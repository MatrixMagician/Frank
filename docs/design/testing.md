# Frank — Test and Verification Design

Design only. No implementation code appears here; every Go block is a type or a
signature. Vocabulary is [CONTEXT.md](../../CONTEXT.md) verbatim: Probe, Target Host,
Transcript, Phase, Recipient, Probe Message, Identity Slot, Identity Triple, Envelope
Sender, HELO Identity, Header From, Domain Pair, Outcome, Acceptance, Rejection,
Deferral, Verdict, Diagnosis, Source Address, Candidate Sending IP, Evaluation Tree,
Matched Mechanism, Lookup Limit, Alignment, Selector Discovery, Matrix, Cell.

Constraints honoured throughout: Go 1.26, standard library only, no CGO in the shipped
binary, no third-party test framework, table-driven tests in standard Go style.

---

## 0. The shape of the proof

Eighty-nine acceptance checkboxes exist across the fourteen issues. Section 9 maps every
one to a named test. Four seams make that mapping possible, and everything else in this
document is downstream of them:

| Seam | Interface | What it makes provable |
|---|---|---|
| Transport | `probe.DialFunc` | that `auth` opens no TCP connection; that a run errors before the first dial |
| Naming | `dnsx.Resolver` | that the suite makes no outbound DNS query; that Verdicts are deterministic |
| Time | `clock.Clock` | that the rate limiter is 6/min, in zero wall-clock seconds |
| Process | `cli.Run(ctx, Env) ExitCode` | that exit codes are asserted without spawning the binary |

Rule for the whole codebase: no package below `cmd/` may call `net.Dial`, `net.Lookup*`,
`time.Now`, `time.Sleep`, `os.Exit`, or read `os.Args` directly. Each of those is
reachable only through a seam carried in `Env`. Three lint-style tests
(`arch.TestNoDirectTransportUse`, `arch.TestNoDirectClockUse`, `arch.TestMainIsThin`)
parse the package ASTs with `go/parser` and fail on a forbidden selector expression, so
the constraint is enforced by the suite rather than by reviewer memory.

### Package layout

```
cmd/frank/            main.go only, ~5 statements
internal/cli          Env, Run, flag parsing, exit codes
internal/config       JSON config, strict decode, pointer fields
internal/transcript   Transcript, Event, Phase, reply parsing, both renderers, redaction
internal/probe        hand-rolled ESMTP client, DialFunc, TLS capture, SMTP AUTH
internal/smtpdouble   the SMTP test double (non-test package; many packages import it)
internal/clock        Clock, System, Fake
internal/ratelimit    Limiter, back-off
internal/dnsx         Resolver interface, DNSError, System, Fixture, Zone
internal/spf          Evaluation Tree, Verdict, Matched Mechanism, Lookup Limit
internal/dkim         key records, Selector Discovery
internal/dmarc        policy, Alignment
internal/matrix       Cell, sweep
internal/explain      Diagnosis, golden rendering
internal/report       combined report
internal/netguard     forbidden dialer + fd accounting for tests
internal/arch         AST-level architecture tests
```

`internal/smtpdouble` is a normal package, not a `_test.go` file, because `cli`,
`probe`, `matrix` and `report` all drive it. It takes a `testing.TB` so it can register
its own cleanup, which keeps its cost at the call site down to one line.

---

## 1. The SMTP test double (issue #3)

### The domain model, not a pile of booleans

A struct of flags (`RejectAtMailFrom bool`, `Greylist bool`, `OfferSTARTTLS bool`) fails
the moment two behaviours must compose: "defer this Triple on its first sighting but
reject a different Triple always, and only after STARTTLS succeeded". The double
therefore models what it actually is: **a rule table keyed by Phase**, evaluated against
a Request that carries the accumulated conversation state. Rules are ordered; the first
rule whose Phase matches and whose predicate holds produces the Reply; if none match, the
Phase's protocol default applies. That is one concept (`Rule`) with two composable
halves (`Predicate`, `Responder`), and every scenario in the issue is a table row.

Advertised extensions, the STARTTLS policy and the AUTH mechanism list are *not* rules.
They are properties of the server's advertised posture, decided before any Phase-keyed
decision runs, so they live in `Options`. Conflating them into the rule table would
require a rule to answer a question the protocol asks before there is anything to match
on.

### Phases and replies

```go
package smtpdouble

// Phase mirrors transcript.Phase exactly; the double never invents a Phase name.
type Phase string

const (
	PhaseBanner    Phase = "banner"
	PhaseEHLO      Phase = "ehlo"
	PhaseHELO      Phase = "helo"
	PhaseSTARTTLS  Phase = "starttls"
	PhaseAUTH      Phase = "auth"
	PhaseMailFrom  Phase = "mail-from"
	PhaseRcptTo    Phase = "rcpt-to"
	PhaseData      Phase = "data"
	PhaseEndOfData Phase = "end-of-data"
	PhaseRSET      Phase = "rset"
	PhaseQuit      Phase = "quit"
)

// Reply is what the double writes. Text is one element per line; multi-element Text
// forces the 250-/250 continuation form, which is what exercises the client's
// multiline parser.
type Reply struct {
	Code     int
	Enhanced string   // "5.7.1"; empty means omit the enhanced status code entirely
	Text     []string
}

func (r Reply) Wire() []byte
```

### The request a rule sees

```go
// Triple is the Identity Triple as the double observed it on the wire, unnormalised.
type Triple struct {
	EnvelopeSender string // raw MAIL FROM argument, "<>" preserved as the null sender
	HELOIdentity   string // raw EHLO/HELO argument
	HeaderFrom     string // parsed from the transmitted Probe Message, empty before DATA
}

// Request is the complete state a Responder may consult. It is a value; a Responder
// cannot mutate the conversation through it.
type Request struct {
	Phase            Phase
	Verb             string // "MAIL", "RCPT", "."
	Arg              string // raw argument bytes after the verb
	Triple           Triple // filled progressively as the conversation advances
	Recipient        string
	TLSActive        bool
	Authenticated    bool
	ConnectionIndex  int // 1-based, ordinal of this connection to this Server
	CommandIndex     int // 1-based within this connection
	TripleSighting   int // 1-based count of connections that have presented this Triple
	Message          []byte // de-stuffed Probe Message, only at PhaseEndOfData
}

type Predicate func(Request) bool
type Responder func(Request) Action
```

### Actions: a Reply is the common case, not the only one

```go
// Action is a closed set. Exactly one field is meaningful, decided by Kind.
type ActionKind int

const (
	ActionReply ActionKind = iota // write Reply and continue
	ActionDrop                    // close the connection without a reply
	ActionStall                   // sleep Delay, then write Reply (governed timeouts)
	ActionTruncate                // write a partial line, then close (parser robustness)
)

type Action struct {
	Kind  ActionKind
	Reply Reply
	Delay time.Duration
	Raw   []byte // ActionTruncate only
}
```

### Rules and the script

```go
type Rule struct {
	Name  string // appears in failure messages and in Server.Trace()
	Phase Phase
	When  Predicate
	Then  Responder
}

// Script is an ordered rule table. Zero value is usable and means "protocol defaults
// everywhere", which is the accept-everything double.
type Script struct{ /* unexported */ }

func NewScript() *Script

// On appends a rule and returns the Script for chaining. Ordering is significant:
// first match wins within a Phase.
func (s *Script) On(name string, phase Phase, when Predicate, then Responder) *Script

// Rules returns the table for inspection; smtpdouble's own tests iterate it.
func (s *Script) Rules() []Rule
```

### Predicate constructors and combinators

```go
func Always() Predicate
func Never() Predicate

func And(...Predicate) Predicate
func Or(...Predicate) Predicate
func Not(Predicate) Predicate

// Identity Slot matchers. Exact, case-sensitive, on the raw wire argument.
func EnvelopeSenderIs(addr string) Predicate       // NullSender matches "<>"
func HELOIdentityIs(name string) Predicate
func HeaderFromIs(addr string) Predicate
func TripleIs(t Triple) Predicate                  // all three slots, exact
func TripleMatches(t Triple) Predicate             // empty field = wildcard

// Domain-level convenience, since most policy keys on domains not addresses.
func EnvelopeDomainIs(domain string) Predicate
func HeaderFromDomainIs(domain string) Predicate
func DomainPairMisaligned() Predicate              // Envelope Sender domain != Header From domain

// Connection-scoped matchers. These are what make greylisting expressible.
func OnConnection(n int) Predicate                 // ConnectionIndex == n
func OnFirstConnection() Predicate                 // OnConnection(1)
func AfterConnection(n int) Predicate              // ConnectionIndex > n
func OnTripleSighting(n int) Predicate             // TripleSighting == n
func OnFirstSightingOfTriple() Predicate           // OnTripleSighting(1)

// Posture matchers.
func TLSActive() Predicate
func Authenticated() Predicate
func MessageContains(needle string) Predicate      // PhaseEndOfData only
```

`OnFirstSightingOfTriple` is the greylisting predicate and it is per-Triple rather than
per-connection on purpose: a real greylister keys on the tuple, and a Matrix visits many
Triples between the first and second sighting of any one of them. Keying on
`ConnectionIndex` would make issue #12's greylisting Cell pass for the wrong reason.

### Responder constructors

```go
// Named after Outcomes in the glossary, so a script reads as the Outcome it produces.
func Accept(code int, enhanced string, text ...string) Responder  // 2xx
func Reject(code int, enhanced string, text ...string) Responder  // 5xx
func Defer(code int, enhanced string, text ...string) Responder   // 4xx
func Respond(r Reply) Responder                                   // any code, no class check

func Drop() Responder
func Stall(d time.Duration, r Reply) Responder
func Truncate(raw []byte) Responder

// Sequence returns each Responder in turn across successive matches of its rule, then
// repeats the last one forever. Greylisting can also be written this way.
func Sequence(...Responder) Responder
```

`Accept`, `Reject` and `Defer` panic at script-construction time if the code class
contradicts the constructor. A `Reject(450, …)` is a bug in the test, and finding it at
`NewScript` time rather than in a confusing assertion failure is worth the panic.
`Respond` is the escape hatch for deliberately malformed replies.

### Server options and lifecycle

```go
type TLSPolicy int

const (
	TLSAbsent      TLSPolicy = iota // STARTTLS never advertised; a client STARTTLS gets 502
	TLSOffered                      // advertised, handshake succeeds with the in-process cert
	TLSRefused                      // advertised, but the STARTTLS verb is answered 454
	TLSHandshakeFails               // advertised, 220 given, then the handshake is aborted
)

type Options struct {
	// Extensions are advertised verbatim in the EHLO response, in order, after the
	// greeting line. "STARTTLS" is added or removed to agree with TLS, so a script
	// cannot advertise a policy it will not honour.
	Extensions []string

	TLS TLSPolicy

	// AuthMechanisms populates the AUTH extension line. Empty means AUTH is not
	// advertised at all, which is distinct from advertising an empty list.
	AuthMechanisms []string

	// Credentials the double accepts. Nil means every credential is accepted, which
	// keeps AUTH-irrelevant tests short.
	Credentials map[string]string

	Script *Script

	// ServerName goes into the self-signed certificate's SAN list. Defaults to
	// "localhost", which is what --tls-verify tests match against.
	ServerName string

	// MaxConnections caps concurrent conversations; exceeding it is a test failure
	// rather than a queue, so a runaway sweep is loud. Zero means 64.
	MaxConnections int

	ReadTimeout time.Duration // per-command; zero means 5s
}

type Server struct{ /* unexported */ }

// Start binds 127.0.0.1:0, serves until the test ends, and registers t.Cleanup to
// close listener and connections. It never reads or writes the filesystem.
func Start(tb testing.TB, opts Options) *Server

func (s *Server) Addr() string          // "127.0.0.1:34517"
func (s *Server) Host() string
func (s *Server) Port() int
func (s *Server) Close()

// Connections returns the number of accepted TCP connections. Issue #12 asserts
// fresh-connection-per-Cell by comparing this against the Cell count.
func (s *Server) Connections() int

// Conversations returns one record per accepted connection, in accept order. Safe to
// call while the server is running; the slice is a copy.
func (s *Server) Conversations() []Conversation

// Trace returns, in order, every rule that fired, as "phase:rulename". A test that
// wants to prove *why* a Cell resolved as it did asserts on this.
func (s *Server) Trace() []string

// Certificate is the in-process self-signed leaf. Generated once per Server with
// crypto/ecdsa P-256 and x509.CreateCertificate; never touches disk.
func (s *Server) Certificate() *x509.Certificate
func (s *Server) CertPool() *x509.CertPool // for the --tls-verify=true happy path
```

### What the double records

```go
type Command struct {
	Index    int
	Phase    Phase
	Verb     string
	Arg      string
	Raw      []byte
	Reply    Reply
	RuleName string // "" when the Phase default answered
	At       time.Time
}

type Conversation struct {
	Index         int // 1-based, matches Request.ConnectionIndex
	RemoteAddr    string
	Commands      []Command
	Triple        Triple
	Recipients    []string // a slice so "exactly one Recipient" is assertable, not assumed
	RawData       []byte   // exactly the bytes between DATA and the terminating dot
	Message       []byte   // RawData with dot-stuffing removed
	TLS           bool
	TLSVersion    uint16
	CipherSuite   uint16
	AuthMechanism string
	AuthCredential string // captured so redaction tests can assert it never reached disk
	ClosedCleanly bool    // true only if the client sent QUIT and read its reply
}
```

`Recipients` being a slice rather than a string is deliberate: issue #4's "exactly one
Recipient per Probe" is proved by asserting `len(c.Recipients) == 1`, which is only
possible if the double is willing to record two.

### Scenario constructors

Six one-line constructors cover the issue's six checkboxes, each built from the
primitives above rather than from special-cased server code:

```go
func ScriptAcceptAll() *Script
func ScriptRejectAtPhase(p Phase, code int, enhanced string, text string) *Script
func ScriptRejectTriple(t Triple, code int, enhanced string, text string) *Script
func ScriptGreylist(deferCode int, deferEnhanced string) *Script // Defer on first sighting
func ScriptRejectMisalignedDomainPair(code int, enhanced string) *Script
func ScriptStallAtPhase(p Phase, d time.Duration) *Script
```

A worked composition, showing that the six compose rather than exclude each other, and
that this is exactly issue #12's greylisting Cell plus issue #4's rejected Triple in one
server:

```go
smtpdouble.NewScript().
	On("greylist-first-sighting", smtpdouble.PhaseRcptTo,
		smtpdouble.OnFirstSightingOfTriple(),
		smtpdouble.Defer(450, "4.7.1", "greylisted, try later")).
	On("reject-spoofed-triple", smtpdouble.PhaseEndOfData,
		smtpdouble.TripleMatches(smtpdouble.Triple{HeaderFrom: "ceo@example.net"}),
		smtpdouble.Reject(550, "5.7.1", "not authorised to send as example.net"))
```

---

## 2. The zone fixture resolver (issue #7)

### The interface

```go
package dnsx

type MX struct {
	Host string
	Pref uint16
}

// Resolver is one method per record type Frank queries. Nothing else.
type Resolver interface {
	// LookupTXT returns one element per TXT RRset record, each element being that
	// record's character-strings ALREADY concatenated, per RFC 7208 §3.3. Callers
	// must not re-join across elements: two records are two records.
	LookupTXT(ctx context.Context, name string) ([]string, error)

	LookupIP(ctx context.Context, name string) ([]netip.Addr, error) // A and AAAA
	LookupMX(ctx context.Context, name string) ([]MX, error)
	LookupAddr(ctx context.Context, addr netip.Addr) ([]string, error) // PTR
	LookupNS(ctx context.Context, name string) ([]string, error)
}

// System wraps net.Resolver with PreferGo and StrictErrors set. It is the only place
// in the tree that constructs a net.Resolver.
func System() Resolver
```

`LookupIP` returns `[]netip.Addr` rather than `[]net.IP` so that ADR-0006's normalization
rule has somewhere to live: `Addr.Unmap()` and `Addr.Zone()` are on `netip.Addr` and
absent from `net.IP`. Every address crossing this boundary is `Unmap`ed by the fixture
and by `System` alike, and an address with a zone is refused with `ErrZonedAddress`
rather than passed on to fail a prefix match silently.

### NXDOMAIN versus NODATA

Distinguishing them from the error text is guesswork, so the resolver returns a typed
error whose `Kind` was decided by the query, not by string shape:

```go
type ErrorKind int

const (
	KindNXDOMAIN  ErrorKind = iota + 1 // the name does not exist
	KindNoData                         // the name exists, no record of this type
	KindTemporary                      // SERVFAIL, timeout: maps to an SPF temperror
	KindInvalidName                    // malformed or over-long label
)

type Error struct {
	Name string
	Type string // "TXT", "A", "MX", "PTR", "NS"
	Kind ErrorKind
	Err  error // wrapped cause, may be nil for fixtures
}

func (e *Error) Error() string
func (e *Error) Unwrap() error

func IsNXDOMAIN(err error) bool
func IsNoData(err error) bool
func IsTemporary(err error) bool
```

The distinction is structural in the fixture, which is the point of modelling it:

- The name **key absent** from the zone map → `KindNXDOMAIN`.
- The name **key present**, that record type empty → `KindNoData`.

So "no SPF record for a domain that exists" and "the domain does not exist" are two
different table rows, not two readings of one. `System` derives the same distinction from
`net.DNSError.IsNotFound` for NXDOMAIN, an empty non-error result for NODATA, and
`IsTemporary || IsTimeout` for `KindTemporary`; `StrictErrors: true` is required for that
mapping to hold, which is why `System` sets it.

For SPF this matters twice. `KindNXDOMAIN` on the subject domain is a `none` Verdict;
`KindNoData` is also `none` but for a different reason the Evaluation Tree states; and
`KindNXDOMAIN` reached through an `include:` is a `permerror` while `KindTemporary` is a
`temperror`. One error type, three Verdicts, no string matching.

### Seeding from a table

```go
// Records is what one name publishes. A nil slice and an empty slice are the same
// thing here; the distinction that matters lives one level up, in Zone's key set.
type Records struct {
	// TXT is unconcatenated at seed time: [][]string is "records, each of
	// character-strings". The Fixture concatenates within a record when serving, so
	// the fixture proves the concatenation contract rather than assuming it.
	TXT  [][]string
	A    []string // dotted quads, parsed and Unmap'ed at seed time
	AAAA []string
	MX   []MX
	NS   []string
	PTR  []string

	// Fail forces a per-type error even when the name exists, keyed by record type.
	// This is how temperror and SERVFAIL cases are seeded.
	Fail map[string]ErrorKind

	// Delay is served before the answer; used only by timeout tests, with a Fake clock.
	Delay time.Duration
}

// Zone is the whole fixture. Keys are lowercase FQDNs without a trailing dot.
// Presence of a key means the name exists. Absence means NXDOMAIN. That is the
// entire NXDOMAIN/NODATA model.
type Zone map[string]Records

type Query struct {
	Name string
	Type string
}

type Fixture struct{ /* unexported */ }

// NewFixture copies the Zone; later mutation of the map cannot affect a running test.
// It parses every address at construction time and panics on a malformed fixture,
// because a typo in test data must not read as a Verdict.
func NewFixture(z Zone) *Fixture

// Fixture satisfies Resolver.
var _ Resolver = (*Fixture)(nil)

// Queries returns every lookup made, in order, including ones that errored. Issue #9's
// "discovery query volume is bounded" is asserted against len(Queries()).
func (f *Fixture) Queries() []Query
func (f *Fixture) QueryCount() int
func (f *Fixture) CountOfType(t string) int
func (f *Fixture) Reset()
```

`Fixture` is safe for concurrent use because the Matrix runner is concurrent and
`-race` is on in CI; the query log is mutex-guarded.

Zone fixtures live in Go source, not on disk, so ADR-0006's "zone fixtures carry a v6
twin for each v4 case" can be enforced by a meta-test rather than by review. Shared
zones sit in `internal/dnsx/zones.go` as named `Zone` values (`ZoneNestedInclude`,
`ZoneOverLimit`, `ZoneRedirect`, `ZoneDKIMDecoys`, `ZoneDMARCSubdomain`, …) and each
consuming table names the zone it wants.

### Proving the suite makes no outbound DNS query

Three independent layers, because any one of them can be defeated by a future edit:

1. **Structural.** `arch.TestOnlyDnsxConstructsNetResolver` parses every package with
   `go/parser` and fails if `net.Resolver`, `net.LookupTXT`, `net.LookupHost`,
   `net.LookupMX`, `net.LookupNS` or `net.LookupAddr` appears outside `internal/dnsx`.
   This catches a new package that reaches for the stdlib directly.

2. **Runtime, process-wide.** `internal/netguard` exposes

   ```go
   func ForbidDNS(tb testing.TB) *Counter
   func ForbidDial(tb testing.TB) *Counter

   type Counter struct{ /* unexported */ }
   func (c *Counter) Count() int
   func (c *Counter) Attempts() []string
   ```

   `ForbidDNS` swaps `net.DefaultResolver` for one with `PreferGo: true` and a `Dial`
   hook that records the attempted address, marks the counter, and returns
   `errForbiddenDNS`; `t.Cleanup` restores the original. Every DNS-touching package's
   `TestMain` installs it for the whole package run, and
   `dnsx.TestSuiteMakesNoOutboundDNSQuery` asserts `Count() == 0` after the package's
   other tests have run. Because the hook returns an error rather than panicking, a
   regression surfaces as a specific "forbidden DNS query to 8.8.8.8:53" failure naming
   the query, rather than as an inscrutable timeout.

3. **Descriptor accounting.** On Linux, `netguard.SocketDelta(tb)` snapshots
   `/proc/self/fd` link targets before and after and asserts no new `socket:` entry
   survives. It skips on other platforms. This catches a package that opened a socket by
   a route neither of the first two layers models.

`TestMain` order matters: layer 2 must be installed before any test in the package runs,
so it goes in `TestMain` and not in individual tests.

**Pure-Go resolver, no CGO.** `dnsx.TestSystemResolverPrefersGo` asserts that the
`*net.Resolver` inside `System()` has `PreferGo` and `StrictErrors` set (checked through
an exported-for-test accessor in the same package). CI adds the real proof: the build job
runs `CGO_ENABLED=0 go build` and then asserts the binary is statically linked via
`go version -m` and a `file` check, and a `TestBuildIsStaticAndCGOFree` e2e test does the
same locally.

---

## 3. Proving `auth` opens no TCP connection (issue #8)

`auth` is the one verb that must never dial. Four layers, cheapest first:

```go
package probe

// DialFunc is the only way anything below cmd/ opens a connection.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)
```

1. **Type-level.** `cli.Env` carries `Dial DialFunc`, and the `auth` command's
   constructor signature simply does not accept one:

   ```go
   package auth

   type Deps struct {
       Resolver dnsx.Resolver
       Clock    clock.Clock
       Out      io.Writer
   }

   func Run(ctx context.Context, opts Options, deps Deps) (Report, ExitCode)
   ```

   There is no field to dial through. This is the primary guarantee; the rest are
   regression detectors for the day someone adds one.

2. **Runtime counter.** `cli.TestAuthOpensNoTCPConnection` builds an `Env` whose `Dial`
   is `netguard.ForbidDial(t)`, runs the full `cli.Run` path for `frank auth …` against a
   zone fixture, and asserts `Count() == 0` and `Attempts()` is empty. Because the whole
   command is exercised, a dial added anywhere in the `auth` path is caught, not just one
   in the `auth` package.

3. **Import graph.** `arch.TestAuthPathDoesNotLinkTransport` runs
   `go list -deps ./internal/auth` in a subtest and fails if `crypto/tls`,
   `internal/probe`, or `internal/smtpdouble` appears. `net` itself is permitted, since
   `net.Resolver` and `netip` legitimately live there; the transport packages are what
   the assertion bans.

4. **Descriptor accounting.** The same test calls `netguard.SocketDelta(t)`, so even a
   dial made through a route the `DialFunc` seam does not cover shows up as a leaked
   socket descriptor.

Layer 2 is the checkbox's named test; layers 1, 3 and 4 are what keep it true.

---

## 4. Proving the rate limiter defaults to 6/min without a slow suite (issue #6)

Six per minute is one Probe every ten seconds. A test that measures it by waiting is both
slow and flaky, so the limiter never reads the wall clock.

### The clock seam

```go
package clock

type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

type Clock interface {
	Now() time.Time
	Since(t time.Time) time.Duration
	NewTimer(d time.Duration) Timer
	After(d time.Duration) <-chan time.Time
	Sleep(d time.Duration)
}

func System() Clock

// Fake is a virtual clock. Time advances only when Advance is called.
type Fake struct{ /* unexported */ }

func NewFake(start time.Time) *Fake

func (f *Fake) Now() time.Time
func (f *Fake) Since(t time.Time) time.Duration
func (f *Fake) NewTimer(d time.Duration) Timer
func (f *Fake) After(d time.Duration) <-chan time.Time
func (f *Fake) Sleep(d time.Duration)

// Advance moves virtual time forward and fires every timer whose deadline is now
// passed, in deadline order, before returning.
func (f *Fake) Advance(d time.Duration)

// WaitForWaiters blocks until n goroutines are parked in Sleep/NewTimer/After, or the
// deadline passes and the test fails. This is what removes the flake: the test never
// advances time before the limiter has actually asked for it.
func (f *Fake) WaitForWaiters(tb testing.TB, n int)

// Waiters reports how many goroutines are currently parked.
func (f *Fake) Waiters() int
```

`WaitForWaiters` is the whole trick. Without it, `Advance` races the limiter's
registration of its timer and the test flakes under `-race` on a loaded CI runner. With
it, the test is deterministic and takes microseconds.

### The limiter

```go
package ratelimit

// DefaultPerMinute is the spec's mandatory default for every mode that opens
// connections. It is a ceiling as well as a default.
const DefaultPerMinute = 6

// ErrRateAboveDefault is returned when a caller asks for more than DefaultPerMinute.
var ErrRateAboveDefault = errors.New("rate cannot be raised above the default")

// Resolve applies the spec's clamp: a request above DefaultPerMinute is refused
// outright rather than silently lowered, because a silent clamp lets a user believe a
// sweep ran faster than it did.
func Resolve(requested int, set bool) (int, error)

type Limiter struct{ /* unexported */ }

func New(perMinute int, c clock.Clock) (*Limiter, error)

// Wait blocks until the next Probe may open a connection, or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error

// Interval is the derived spacing, exported so a test asserts the arithmetic
// independently of the blocking behaviour.
func (l *Limiter) Interval() time.Duration
```

### The test, in zero wall-clock seconds

`ratelimit.TestDefaultRateIsSixPerMinute` proves the default two ways in one test:

- **Arithmetic.** `New(DefaultPerMinute, fake).Interval()` is exactly `10 * time.Second`.
- **Behaviour.** The first `Wait` returns immediately. A second `Wait` runs in a
  goroutine; `fake.WaitForWaiters(t, 1)` confirms it is parked; `fake.Advance(9s)` leaves
  it parked (`fake.Waiters() == 1`); `fake.Advance(1s)` releases it. Six acquisitions
  consume exactly 50s of virtual time and a seventh crosses 60s, which is the definition
  of six per minute. Total real elapsed time is microseconds.

`arch.TestNoDirectClockUse` parses `internal/ratelimit`, `internal/matrix` and
`internal/probe` and fails on any `time.Now`, `time.Sleep`, `time.After`,
`time.NewTimer` or `time.Tick` selector. Without that test, someone reintroduces a real
sleep and the suite gets slow again by increments nobody notices.

The same fake drives `ratelimit.TestDeferralBackoffIsExponentialAndAborts`: the back-off
schedule is asserted as the exact sequence of virtual durations requested
(`Fake.SleepLog() []time.Duration`), so "exponential" is an assertion on the sequence
rather than on elapsed time, and "aborts past a threshold" is an assertion on the error
after the nth Deferral.

---

## 5. Proving a no-TTY run errors before the first dial (issue #6)

The proof must be about **ordering**, not merely about a dial count, because a count of
zero is also what you get if the dial simply failed. So gating is a pure function that
runs before anything capable of dialing is constructed.

```go
package cli

// Console is the terminal seam. The real one wraps os.Stdin and a Stat check.
type Console interface {
	IsTerminal() bool
	Confirm(ctx context.Context, prompt string) (bool, error)
}

type SendMode int

const (
	ModeDryRun    SendMode = iota // walk to RCPT TO, never transmit the Probe Message
	ModeConfirmed                 // --confirm-send named the Recipient
)

// ErrNoTTY is returned when confirmation is required and stdin is not a terminal.
var ErrNoTTY = errors.New("confirmation required but stdin is not a terminal")

// ErrConfirmWithDryRun is the --confirm-send + --dry-run usage error.
var ErrConfirmWithDryRun = errors.New("--confirm-send and --dry-run are mutually exclusive")

// RunPlan is the only type that owns a DialFunc. Building one is the moment a run
// becomes capable of touching the network.
type RunPlan struct {
	Mode      SendMode
	Recipient string
	Target    string
	Rate      int
	Dial      probe.DialFunc
	// ...
}

// Plan validates flags, resolves the send gate and the rate, and returns either a
// RunPlan or an error. It is pure with respect to the network: it holds no DialFunc
// until it returns, and it consults Console before constructing one.
func Plan(ctx context.Context, opts Options, con Console, dial probe.DialFunc) (*RunPlan, ExitCode, error)
```

`cli.TestConfirmationWithoutTTYErrorsBeforeFirstDial` asserts four things at once:

1. `Plan` returns `ErrNoTTY` and `ExitUsage` (3).
2. The returned `*RunPlan` is nil, so no object capable of dialing was ever built.
3. The `netguard.ForbidDial` counter is zero, and `Attempts()` is empty.
4. An ordered event log recorded by the `Env` (`[]string`) contains `gate:no-tty` and no
   entry with the `dial:` prefix. The log is the ordering proof the count alone cannot
   give.

The test is table-driven over the gate's whole truth table, so it also carries the
sibling checkboxes as subtests: `no_tty_needs_confirmation` (error before dial),
`no_tty_dry_run` (proceeds, `ModeDryRun`), `confirm_send_and_dry_run` (usage error),
`confirm_send_without_recipient` (usage error), `tty_available` (prompts).

---

## 6. Golden-file strategy for `explain` (issue #13)

### Layout

```
internal/explain/testdata/
  scenarios/
    alignment-failure/    transcript.json  auth.json  args.txt
    over-limit-spf/       transcript.json  auth.json  args.txt
    tls-refusal/          transcript.json  auth.json  args.txt
    greylisting/          transcript.json  auth.json  args.txt
  golden/
    alignment-failure.txt   alignment-failure.json
    over-limit-spf.txt      over-limit-spf.json
    tls-refusal.txt         tls-refusal.json
    greylisting.txt         greylisting.json
```

Inputs are committed JSON produced by Frank's own writers, not hand-written, so a change
to the Transcript schema breaks the scenario loudly instead of leaving the golden testing
a format that no longer exists. A `-regen` flag on
`transcript.TestGenerateExplainScenarios` re-derives the four `transcript.json` files by
running `probe`/`matrix` against a scripted double, which keeps the inputs honest.

### Determinism

Nothing in a golden may vary between runs:

- Time comes from `clock.NewFake(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))`; both wall
  clock and monotonic offsets are derived from it.
- Message-IDs come from an injected `IDSource` seeded per scenario.
- Ports, temp directories and the output directory path are rewritten by a canonicaliser
  before comparison (`127.0.0.1:\d+` → `127.0.0.1:PORT`, the temp dir → `<OUTDIR>`).
- Map iteration never reaches a renderer; every renderer sorts, and
  `explain.TestRenderIsOrderStable` runs each scenario 100 times asserting byte identity,
  which catches an unsorted map long before `-race` or a golden diff would.
- JSON goldens are compared after `json.Indent` with two-space indentation, so
  insignificant whitespace is not a diff.

### The test

```go
package explain

// -update rewrites goldens. Guarded so a stray -update in CI cannot pass:
// TestGoldenScenarios fails immediately if *update is true and os.Getenv("CI") != "".
var update = flag.Bool("update", false, "rewrite golden files from current output")

type Scenario struct {
	Name    string
	Dir     string
	WantExit cli.ExitCode
}
```

`explain.TestGoldenScenarios` is table-driven over the four `Scenario` values, each a
subtest that loads its inputs, renders both formats, canonicalises, and compares. On
mismatch it prints a hand-rolled unified diff (no third party) of the first differing
region plus the exact command to update: `go test ./internal/explain -run
TestGoldenScenarios/alignment_failure -update`.

Updating is `go test ./... -update`, followed by reading the diff in review. The golden
is evidence only if a human looked at the change, so the CI job runs `go test ./...` and
then `git diff --exit-code testdata/`, which fails if a test rewrote a golden during a CI
run.

### The safety assertion over goldens

`explain.TestNoDiagnosisClaimsDelivery` walks every file under `testdata/golden/` and
fails on any occurrence of "delivered", "sent successfully", "inboxed", or "arrived",
outside a quoted server reply. That single test makes the glossary's Acceptance rule
("not evidence of delivery, and Frank never claims otherwise") enforceable across every
future golden, not just the four that exist today.

---

## 7. Asserting exit codes without spawning the binary (issues #4, #12, #14)

### The seam

```go
package cli

type ExitCode int

const (
	ExitAccepted     ExitCode = 0 // completed with Acceptance
	ExitRejected     ExitCode = 1 // completed with Rejection
	ExitIncomplete   ExitCode = 2 // network, TLS or protocol failure
	ExitUsage        ExitCode = 3 // usage or config error
	ExitInconclusive ExitCode = 4 // completed but Inconclusive
)

// Env is everything Run touches outside its own memory. Every field is a seam.
type Env struct {
	Args      []string // without argv[0]
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	WorkDir   string
	LookupEnv func(key string) (string, bool)
	Console   Console
	Clock     clock.Clock
	Dial      probe.DialFunc
	Resolver  dnsx.Resolver
	Events    *EventLog // ordered trace: "gate:no-tty", "dial:127.0.0.1:2525", ...
}

// OSEnv builds the production Env from the real process.
func OSEnv() Env

// Run is the entire program. It never calls os.Exit and never panics on user input.
func Run(ctx context.Context, env Env) ExitCode
```

`cmd/frank/main.go` is five statements and contains the only `os.Exit` in the tree:

```go
func main() // os.Exit(int(cli.Run(context.Background(), cli.OSEnv())))
```

`arch.TestMainIsThin` parses `cmd/frank/main.go` and fails if `main` has more than five
statements, or if `os.Exit` appears anywhere outside it. That is what keeps the seam from
eroding.

### The tests

Exit-code tests are table-driven over `(args, double script, want ExitCode)` and call
`cli.Run` directly with an in-memory `Env`, a scripted `smtpdouble.Server`, a
`dnsx.Fixture` and a `clock.Fake`. They run in microseconds and in parallel:

- `cli.TestProbeExitCodes` — Acceptance→0, Rejection→1, dial failure→2, bad flag→3,
  Deferral-only→4.
- `cli.TestMatrixExitCodes` — any Cell Rejected→1; else any Inconclusive or Unrun→4;
  else→0. The `Unrun` row is what distinguishes this from a simple pass-through.
- `cli.TestAuthExitCodes` — every Verdict computed→0; DNS failure→2.
- `cli.TestExplainUnreadableInputExitsUsage` — unreadable input→3.

### One real process, once

The seam is only worth as much as the two-line `main` that uses it, so exactly one test
compiles and runs the binary: `cli.TestExitCodeContractE2E` builds with
`CGO_ENABLED=0 go build -trimpath` into `t.TempDir()`, runs `frank probe` against a live
`smtpdouble.Server` with a rejecting script, and asserts `exec.ExitError.ExitCode()` is
1. It skips under `testing.Short()`. That covers "`main` wires `Run`'s return value to
`os.Exit` correctly", which is the only thing the fast tests cannot see, and it doubles
as issue #1's static-binary check.

---

## 8. CI design (issue #1)

Two jobs, because `-race` requires cgo and the shipped binary must not have it. Running
both in one job would either lose the race detector or lose the CGO-free proof.

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: ["**"]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

env:
  GOTOOLCHAIN: local

jobs:
  build:
    name: build (CGO_ENABLED=0)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.26"
          check-latest: true

      - name: gofmt
        run: |
          unformatted="$(gofmt -l .)"
          if [ -n "$unformatted" ]; then
            echo "::error::gofmt needed:"; echo "$unformatted"; exit 1
          fi

      - name: no third-party dependencies
        run: |
          if grep -qE '^\s*require' go.mod; then
            echo "::error::go.mod declares a dependency; Frank is standard library only"
            grep -nE '^\s*require' go.mod
            exit 1
          fi
          test ! -f go.sum || { echo "::error::go.sum exists"; exit 1; }

      - name: go mod tidy is a no-op
        run: |
          go mod tidy
          git diff --exit-code -- go.mod go.sum

      - name: vet
        run: go vet ./...

      - name: build static binary
        env:
          CGO_ENABLED: "0"
        run: go build -trimpath -o frank ./cmd/frank

      - name: binary is static and CGO-free
        run: |
          ./frank --version
          if ldd ./frank 2>&1 | grep -qv 'not a dynamic executable'; then
            echo "::error::frank is dynamically linked"; ldd ./frank; exit 1
          fi
          if go version -m ./frank | grep -q 'CGO_ENABLED=1'; then
            echo "::error::binary built with cgo"; exit 1
          fi

      - name: tests without cgo (proves the pure-Go resolver path)
        env:
          CGO_ENABLED: "0"
          GODEBUG: netdns=go
        run: go test ./...

  race:
    name: test -race
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.26"
          check-latest: true

      - name: vet
        run: go vet ./...

      # -race requires cgo; this job is the only place CGO is enabled, and it never
      # produces a shipped artefact.
      - name: test with the race detector
        env:
          CGO_ENABLED: "1"
        run: go test -race -count=1 -timeout=5m ./...

      - name: no golden file was rewritten by the run
        run: git diff --exit-code -- '**/testdata/**'
```

Two things the workflow asserts that a reader might read as noise. `git diff --exit-code
-- '**/testdata/**'` is what stops a `-update` slipping into CI and making a golden test
tautological. `grep -qE '^\s*require' go.mod` is issue #1's "no third-party
dependencies" checkbox as an executable check rather than a promise; the matching unit
test `cli.TestGoModHasNoRequirements` gives the same failure locally.

`cli.TestCIWorkflowRunsVetAndRace` reads `.github/workflows/ci.yml` as text and asserts
it contains `go vet ./...` and `go test -race`. There is no YAML parser in the standard
library and none is being added, so a regexp over the file is the honest tool. It catches
the realistic failure (someone deletes the race step) without pretending to validate the
schema.

---

## 9. Traceability: every acceptance checkbox to its test

Eighty-nine checkboxes. `Test…/subtest` names a subtest of a table-driven test. A
committed `docs/design/traceability.tsv` carries this table in machine-readable form, and
`arch.TestTraceabilityTableIsComplete` parses it, runs `go test -list '.*'` across the
module, and fails if a named test does not exist or if the row count drifts from 89. The
table is therefore load-bearing, not documentation.

### Issue #1 — Project skeleton and CI

| # | Acceptance checkbox | Test |
|---|---|---|
| 1.1 | `go build` produces a `frank` binary with no CGO | `cli.TestBuildIsStaticAndCGOFree` |
| 1.2 | All four verbs are routed; unimplemented ones exit with the usage/config code | `cli.TestVerbRouting` |
| 1.3 | Global flags parse: `--config`, `--output`, `--json`, `--verbose`, `--dry-run`, `--rate`, `--confirm-send`, `--redact` | `cli.TestGlobalFlagsParse` |
| 1.4 | CI runs vet and `go test -race` on push, and is green | `cli.TestCIWorkflowRunsVetAndRace` |
| 1.5 | No third-party dependencies added | `cli.TestGoModHasNoRequirements` |

### Issue #2 — Transcript spine

| # | Acceptance checkbox | Test |
|---|---|---|
| 2.1 | A hand-constructed Transcript renders to both formats | `transcript.TestRenderBothFormats` |
| 2.2 | Reply parsing covers multiline continuations and enhanced status codes | `transcript.TestParseReplyLines` |
| 2.3 | Every event carries both a monotonic and a wall-clock stamp, and they are monotonic in order | `transcript.TestEventStampsAreMonotonic` |
| 2.4 | `--redact` accepts a repeatable RE2 pattern and masks matches in both renderings | `transcript.TestRedactionMasksInBothRenderings` |
| 2.5 | The redaction code path is exercised by a test even when no pattern is supplied | `transcript.TestRedactionPathRunsWithNoPatterns` |
| 2.6 | The in-memory Transcript is unchanged by rendering | `transcript.TestRenderDoesNotMutateTranscript` |

### Issue #3 — SMTP test double

| # | Acceptance checkbox | Test |
|---|---|---|
| 3.1 | Accepts or rejects at any Phase, with a caller-supplied code, enhanced status and text | `smtpdouble.TestRuleRepliesAtEveryPhase` |
| 3.2 | Advertises a caller-supplied extension list in its EHLO response | `smtpdouble.TestEHLOAdvertisesConfiguredExtensions` |
| 3.3 | Offers or refuses STARTTLS on demand, with a self-signed certificate for the TLS case | `smtpdouble.TestSTARTTLSPolicy` |
| 3.4 | Rejects a specific Identity Triple and accepts the rest | `smtpdouble.TestTriplePredicateRejectsOnlyNamedTriple` |
| 3.5 | Can emit a Deferral first and an Acceptance on a later connection, so greylisting is testable | `smtpdouble.TestGreylistSightingPredicate` |
| 3.6 | Runs in-process on an ephemeral port and needs no fixtures on disk | `smtpdouble.TestStartsOnEphemeralPortWithoutDiskFixtures` |

### Issue #4 — The controlled ESMTP conversation

| # | Acceptance checkbox | Test |
|---|---|---|
| 4.1 | `--envelope-from`, `--helo` and `--header-from` are independent and any may differ from any other | `probe.TestIdentitySlotsAreIndependent` |
| 4.2 | A test asserts all three mismatched values appear verbatim in the Transcript at the correct Phases | `probe.TestMismatchedIdentitiesAppearVerbatim` |
| 4.3 | EHLO falls back to HELO and the fallback is recorded | `probe.TestEHLOFallsBackToHELO` |
| 4.4 | Exactly one Recipient per Probe, so every Phase has exactly one Outcome | `probe.TestExactlyOneRecipientPerProbe` |
| 4.5 | Correct dot-stuffing and CRLF-dot-CRLF termination, covered by a test with a body line starting in a dot | `probe.TestDotStuffingAndTermination` |
| 4.6 | The reply to the DATA verb and the reply to the terminating dot are recorded as separate Phases | `probe.TestDataAndEndOfDataAreSeparatePhases` |
| 4.7 | Per-Phase timings are populated and monotonic | `probe.TestPhaseTimingsPopulatedAndMonotonic` |
| 4.8 | A clean QUIT on every exit path, including error paths | `probe.TestQuitOnEveryExitPath` |
| 4.9 | Exit codes are asserted by tests | `cli.TestProbeExitCodes` |

### Issue #5 — STARTTLS, captured not trusted

| # | Acceptance checkbox | Test |
|---|---|---|
| 5.1 | `require` aborts when STARTTLS is unavailable, `prefer` continues in plaintext, `none` never offers it | `probe.TestTLSModePolicy` |
| 5.2 | The chain, negotiated version and cipher are recorded identically whether verification passes or fails | `probe.TestTLSEvidenceIdenticalUnderBothVerifyModes` |
| 5.3 | A Probe against a self-signed certificate completes with `--tls-verify=false` and records the failure as a finding | `probe.TestSelfSignedCompletesWithVerifyDisabled` |
| 5.4 | The same Probe aborts with `--tls-verify=true`, and the chain is still in the Transcript | `probe.TestSelfSignedAbortsWithVerifyEnabledAndKeepsChain` |
| 5.5 | Session resumption is disabled, with a test proving the certificate is captured on every connection | `probe.TestSessionResumptionDisabledCertCapturedEveryConnection` |
| 5.6 | The server name used for verification is set explicitly and recorded | `probe.TestServerNameIsExplicitAndRecorded` |

### Issue #6 — Send gating and rate limiting

| # | Acceptance checkbox | Test |
|---|---|---|
| 6.1 | Without `--confirm-send`, a run walks to RCPT TO and stops, transmitting no Probe Message | `cli.TestWithoutConfirmSendStopsBeforeData` |
| 6.2 | `--confirm-send` requires a Recipient and the Recipient appears in the Transcript | `cli.TestConfirmSendRecordsRecipient` |
| 6.3 | `--confirm-send` together with `--dry-run` is a usage error | `cli.TestConfirmSendWithDryRunIsUsageError` |
| 6.4 | A run needing confirmation with no TTY errors before the first dial, proven by a test | `cli.TestConfirmationWithoutTTYErrorsBeforeFirstDial` |
| 6.5 | The rate limiter defaults to 6 per minute and is asserted by a timing test | `ratelimit.TestDefaultRateIsSixPerMinute` |
| 6.6 | An attempt to raise the rate above the default is refused | `ratelimit.TestRateAboveDefaultIsRefused` |
| 6.7 | Repeated Deferrals back off exponentially and abort past a threshold | `ratelimit.TestDeferralBackoffIsExponentialAndAborts` |

### Issue #7 — Resolver seam and zone fixtures

| # | Acceptance checkbox | Test |
|---|---|---|
| 7.1 | An interface covering TXT, A/AAAA, MX, PTR and NS that the standard resolver satisfies | `dnsx.TestSystemResolverSatisfiesInterface` |
| 7.2 | A fixture resolver seeded from a table, with no network access | `dnsx.TestFixtureResolverServesSeededZone` |
| 7.3 | Multi-string TXT records arrive as a single concatenated string | `dnsx.TestMultiStringTXTArrivesConcatenated` |
| 7.4 | Non-existent name and no-record-of-this-type are distinguishable to callers | `dnsx.TestNXDOMAINDistinctFromNoData` |
| 7.5 | The real resolver is forced to the pure-Go implementation, with no CGO | `dnsx.TestSystemResolverPrefersGo` |
| 7.6 | A test proves the suite makes no outbound DNS query | `dnsx.TestSuiteMakesNoOutboundDNSQuery` |

### Issue #8 — SPF Evaluation Tree and `frank auth`

| # | Acceptance checkbox | Test |
|---|---|---|
| 8.1 | Table-driven tests over zone fixtures cover nested includes, redirect, and each Verdict class | `spf.TestEvaluate` |
| 8.2 | The Matched Mechanism is reported correctly for each case | `spf.TestMatchedMechanismReported` |
| 8.3 | Over-limit records are detected and reported as a finding | `spf.TestLookupLimitExceededIsAFinding` |
| 8.4 | Addresses are normalised before matching, with a test for the IPv4-mapped case | `spf.TestAddressNormalisedBeforeMatching` |
| 8.5 | Addresses carrying a zone are rejected rather than silently mismatched | `spf.TestZonedAddressRejected` |
| 8.6 | Each `ip4` fixture case has an `ip6` twin | `spf.TestEveryIPv4CaseHasIPv6Twin` |
| 8.7 | Without `--client-ip`, `auth` renders the tree and reports the Verdict as not evaluated | `cli.TestAuthWithoutClientIPReportsNotEvaluated` |
| 8.8 | `auth` opens no TCP connection, proven by a test | `cli.TestAuthOpensNoTCPConnection` |

`spf.TestEveryIPv4CaseHasIPv6Twin` is a meta-test over `spf.TestEvaluate`'s own table: it
groups rows by a `Twin` field and fails on any group of size one. ADR-0006 asks for a v6
twin per v4 case, and a meta-test is the only thing that keeps that true as the table
grows.

### Issue #9 — DKIM Selector Discovery

| # | Acceptance checkbox | Test |
|---|---|---|
| 9.1 | Key records are parsed for version, key type, the public key and flags | `dkim.TestParseKeyRecord` |
| 9.2 | Revoked, empty and test-mode keys are reported as faults | `dkim.TestKeyFaultsReported` |
| 9.3 | Discovery finds a seeded selector among decoys in the fixtures | `dkim.TestDiscoveryFindsSeededSelectorAmongDecoys` |
| 9.4 | `--selector` is repeatable and adds to the built-in list | `cli.TestSelectorFlagExtendsBuiltInList` |
| 9.5 | The effective list probed appears in both renderings | `dkim.TestEffectiveSelectorListAppearsInBothRenderings` |
| 9.6 | Discovery query volume is bounded, and the bound is stated in the output | `dkim.TestDiscoveryQueryVolumeBoundedAndStated` |

9.6 is asserted against `Fixture.CountOfType("TXT")`, which is why the fixture logs
queries rather than merely answering them.

### Issue #10 — DMARC policy and Alignment

| # | Acceptance checkbox | Test |
|---|---|---|
| 10.1 | Policy, subdomain policy, both alignment modes, sampling rate and the reporting addresses are parsed | `dmarc.TestParsePolicyRecord` |
| 10.2 | Alignment is computed for both SPF and DKIM, in relaxed and strict modes | `dmarc.TestAlignment` |
| 10.3 | Fixtures cover strict versus relaxed, subdomain policy, and a missing record resolving to none | `dmarc.TestPolicyResolution` |
| 10.4 | The sampling rate is reported and never applied, with a test proving repeated runs agree | `dmarc.TestSamplingRateReportedNotApplied` |
| 10.5 | A null Envelope Sender moves the SPF subject to the HELO Identity, and the Verdict names which subject it evaluated | `spf.TestNullEnvelopeSenderMovesSubjectToHELO` |

10.4 runs the same input 1000 times and asserts byte-identical output. That is cheap
(pure computation, no clock, no network) and it is the only assertion that actually
excludes a stochastic `pct`.

### Issue #11 — SMTP AUTH

| # | Acceptance checkbox | Test |
|---|---|---|
| 11.1 | PLAIN and LOGIN both work against the test double | `probe.TestAuthMechanisms` |
| 11.2 | Authentication over a non-TLS connection is refused, with a test | `probe.TestAuthRefusedWithoutTLS` |
| 11.3 | Credentials are read from the environment and the config file, and never from a flag | `config.TestCredentialsFromEnvAndConfigNeverFlag` |
| 11.4 | A test asserts the credential appears in neither rendering, in either mechanism | `probe.TestCredentialNeverReachesEitherRendering` |
| 11.5 | The advertised mechanism list is recorded, and an unsupported-mechanism case reports clearly | `probe.TestAdvertisedMechanismsRecordedAndUnsupportedReported` |

11.3's "never from a flag" half is negative and so is proved structurally:
`config.TestCredentialsFromEnvAndConfigNeverFlag` includes a subtest that registers the
full flag set and asserts no flag name matches `(?i)(pass|secret|credential|token)`, and
`arch.TestNoCredentialFlagRegistered` parses the flag registrations. 11.4 asserts the
literal credential bytes, the base64 of the PLAIN triplet, and the base64 of each LOGIN
step are all absent from both renderings, because redacting the plaintext and leaking the
base64 is the realistic bug.

### Issue #12 — The identity matrix

| # | Acceptance checkbox | Test |
|---|---|---|
| 12.1 | Against a test double rejecting one specific Triple, that Cell resolves Rejected and all others Accepted | `matrix.TestRejectedTripleIsolated` |
| 12.2 | A fresh connection per Cell, asserted by counting connections at the test double | `matrix.TestFreshConnectionPerCell` |
| 12.3 | A greylisting host produces an Inconclusive Cell, and a retry that succeeds resolves it to Accepted | `matrix.TestGreylistedCellInconclusiveThenAcceptedOnRetry` |
| 12.4 | An aborted sweep leaves Unrun Cells that render distinctly from Inconclusive ones | `matrix.TestAbortedSweepLeavesUnrunCellsRenderedDistinctly` |
| 12.5 | `--rate` is honoured and cannot be raised above the default | `matrix.TestRateHonouredAndCannotBeRaised` |
| 12.6 | The matrix exits 1 if any Cell is Rejected, otherwise 4 if any is Inconclusive or Unrun, otherwise 0 | `cli.TestMatrixExitCodes` |
| 12.7 | Runs clean under the race detector | `matrix.TestConcurrentSweepIsRaceFree` |

12.2 asserts `Server.Connections() == len(cells)` for a clean sweep and
`== len(cells) + retries` for a greylisted one, and additionally that every
`Conversation` contains at most one `MAIL FROM`, which is what rules out an `RSET` reuse
that happened to reconnect anyway. ADR-0003's correctness argument is that one Cell's
Outcome must not depend on the previous Cell, so the test also runs a script whose rule
fires only on `CommandIndex > 6` and asserts no Cell ever sees it.

### Issue #13 — `frank explain`

| # | Acceptance checkbox | Test |
|---|---|---|
| 13.1 | Golden-file tests cover alignment failure, over-limit SPF, TLS refusal and greylisting | `explain.TestGoldenScenarios` |
| 13.2 | Observed Outcomes and computed Verdicts are distinguishable in the output | `explain.TestObservedAndComputedAreDistinguishable` |
| 13.3 | An ambiguous case says so and names the disambiguating Probe | `explain.TestAmbiguousCaseNamesDisambiguatingProbe` |
| 13.4 | A matrix Transcript produces a run-level Diagnosis plus a per-Cell line | `explain.TestMatrixTranscriptYieldsRunAndPerCellDiagnosis` |
| 13.5 | Unreadable input exits with the usage code | `cli.TestExplainUnreadableInputExitsUsage` |
| 13.6 | No Diagnosis ever claims a message was delivered | `explain.TestNoDiagnosisClaimsDelivery` |

13.1's four subtests are `alignment_failure`, `over_limit_spf`, `tls_refusal`,
`greylisting`. 13.2 asserts on the JSON rendering's structure (every claim carries a
`"source": "observed"` or `"source": "computed"` field, and the text rendering's
observed lines quote a reply code while computed lines name a record), rather than on
prose, so the checkbox survives a rewording of the Diagnosis.

### Issue #14 — Config file and combined report

| # | Acceptance checkbox | Test |
|---|---|---|
| 14.1 | One report combines Transcript, Verdicts, matrix and Diagnosis in both formats | `report.TestCombinedReportContainsAllSections` |
| 14.2 | Both renderings are always written to the output directory, defaulting to a timestamped one | `report.TestBothRenderingsWrittenToDefaultTimestampedDir` |
| 14.3 | The JSON flag changes only what standard output carries | `cli.TestJSONFlagChangesOnlyStdout` |
| 14.4 | A mistyped config key is an error naming the key | `config.TestUnknownConfigKeyIsErrorNamingKey` |
| 14.5 | A key set to zero is distinguishable from an absent key, with tests for the rate and verification cases | `config.TestZeroValueDistinctFromAbsent` |
| 14.6 | Explicit flags beat config values | `config.TestExplicitFlagBeatsConfigValue` |
| 14.7 | An end-to-end run against the test double yields a report that needs no source reading, and exit codes are asserted | `cli.TestEndToEndReportAgainstDouble` |

14.3 is proved by running the same command twice, once with `--json` and once without,
and asserting the two output directories are byte-identical while the two stdout captures
differ, which is exactly what "changes only what standard output carries" means. 14.5
turns on ADR-0005's pointer fields: subtests `rate_absent`, `rate_zero`,
`tls_verify_absent`, `tls_verify_false` assert four distinct resolved configurations.
14.7's "needs no source reading" half is operationalised as a checklist assertion: the
rendered report must contain the Identity Triple, the Phase of the Outcome, the reply
code with its enhanced status, the Candidate Sending IP with its observed-or-supplied
label, the effective selector list, and the Diagnosis. Prose cannot be asserted; presence
of the six facts a reader needs can be.

---

## 10. Conventions

**Naming.** `Test<Subject><AssertedBehaviour>`, in the package under test. No `_test`
package suffix except in `internal/cli`, which uses `cli_test` to prove `Run` is usable
through its exported surface alone. Subtests are snake_case and are the table row names,
so `-run 'TestEvaluate/nested_include_permerror'` addresses one case.

**Table shape.** Standard Go: a `[]struct{...}` literal with a `name` field, `t.Run` per
row, `t.Parallel()` on both the parent and each row where the row owns its fixtures. The
double, the fixture resolver and the fake clock are all per-row values, never package
globals, which is what lets the suite be parallel and race-clean.

**No sleeps.** `arch.TestNoDirectClockUse` forbids `time.Sleep` outside
`internal/clock`. Waiting for a condition uses `clock.Fake.WaitForWaiters` or a channel,
never a poll loop with a sleep.

**Failure messages.** `got`/`want` in that order, with the row name already supplied by
`t.Run`. Byte comparisons print the hand-rolled unified diff rather than two blobs.

**Runtime budget.** The whole suite, race detector on, targets under 30 seconds. The only
tests permitted to exceed 100ms are `cli.TestBuildIsStaticAndCGOFree` and
`cli.TestExitCodeContractE2E`, both of which compile the binary and both of which skip
under `-short`.
