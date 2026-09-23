# Frank — SPEC.md

**Frank** is a command-line SMTP deliverability forensics tool. It conducts a
controlled ESMTP conversation against a smart host (or a domain's MX), captures
a complete timestamped protocol transcript, and independently varies the three
identities that anti-spoofing policies scrutinise — the envelope sender
(`MAIL FROM`), the HELO/EHLO identity, and the header `From:` — so that the exact
combination which trips a rejection can be isolated by experiment rather than
inferred from other systems' logs. Alongside the live conversation it evaluates
the authentication posture of the domains in play: SPF (with `include:`
unrolling), DKIM selector discovery, and DMARC alignment.

The name is deliberate: a *frank* is the mark authorising a piece of mail for
sending, and adjudicating who is authorised to send is precisely what Frank does;
the second sense — candid — fits a tool whose primary artefact is an unvarnished
transcript.

Vocabulary is defined in [CONTEXT.md](./CONTEXT.md) and decisions in
[docs/adr/](./docs/adr/); where this spec and the glossary disagree, the glossary wins.

Frank is a **diagnostic instrument, not a mailer**. Its defaults are cautious,
its output is a report, and every design decision below favours being a safe,
inspectable probe over being a general-purpose sending agent.

---

## Goals

- Reduce a deliverability failure of the "550 anti-spoofing" family to a precise,
  reproducible statement: *which* identity combination is rejected, at *which*
  protocol phase, with the *exact* server response, corroborated by the
  authentication records that explain it.
- Turn a diagnosis that currently requires reading a remote system's logs into a
  local experiment that completes in seconds.
- Produce an artefact — a transcript plus a findings summary — that can be pasted
  into a case or a ticket without further editing.

## Non-goals

- Not a bulk or production mailer. No mailing lists, no templating, no address
  books, no scheduling.
- Not an open relay tester or a spoofing tool. Frank does not exist to *defeat*
  anti-spoofing controls; it exists to *characterise* them. See Safety Posture.
- Not an inbound server. Frank speaks as a client only.
- No coupling to any other tool. Frank is entirely standalone: it reads its own
  inputs, writes its own outputs, and shares no libraries, formats, or runtime
  with anything else.

## Language & runtime

- **Go.** Chosen for a single static binary, first-class `net`, `crypto/tls`,
  and `net/smtp`-adjacent primitives, and fast iteration.
- Target: Linux first (developed on Fedora), but nothing should be
  platform-specific beyond DNS resolution, which uses the standard library.
- Binary name: `frank`.
- No CGO. Pure-Go DNS resolver where practical for deterministic `include:`
  traversal.

## Dependencies (keep minimal)

- Standard library for TCP, TLS, and the SMTP verbs (hand-rolled command/response
  handling rather than `net/smtp`, because Frank needs to send deliberately
  malformed or mismatched identities that the stdlib client is designed to
  prevent).
- A DNS library only if the standard resolver proves insufficient for TXT/SPF
  traversal and DKIM selector queries (`miekg/dns` is the fallback).
- A TUI/colour library is **out of scope** for v1; output is plain text and a
  structured file. Reconsider only after the engine is complete.

---

## Command surface (target)

```
frank probe    — run a controlled ESMTP conversation and capture a transcript
frank auth     — evaluate SPF / DKIM / DMARC for a domain pair, no connection
frank matrix   - sweep Identity Triples, report which are accepted and which rejected
frank explain  — take a captured transcript and annotate it against auth findings
```

`probe` is the core; `auth` is independently useful; `matrix` orchestrates
repeated `probe` runs; `explain` joins the two halves. Each is a milestone.

Global flags: `--config`, `--output <dir>`, `--json`, `--verbose`, `--dry-run`,
`--rate <per-min>`, `--confirm-send <recipient>`, `--redact <regexp>` (repeatable).

---

## Defaults and flag semantics (normative)

Every default below is stated because leaving it implicit produced two readings.

**`--dry-run`** walks the full protocol through `RCPT TO` and stops before issuing the
`DATA` verb. It dials, it negotiates TLS, it sends the real identities, and it produces
a populated Transcript. It never transmits the Probe Message. It means the same thing in
every mode; there is no separate class of "exploratory" modes.

**`--confirm-send <recipient>`** is required before Frank issues `DATA`, and it names the
Recipient explicitly rather than merely asserting intent. The effective Recipient is
recorded in every Transcript. Without it, Frank runs as `--dry-run`. If a run would need
to prompt and stdin is not a terminal, Frank errors before dialing rather than hanging.
`--confirm-send` together with `--dry-run` is a usage error.

**`--rate`** defaults to 6 per minute for every mode that opens connections. `matrix` may
lower it and can never raise it above the default.

**`--tls`** defaults to `prefer`: use STARTTLS where advertised, continue without it where
it is not. **`--tls-verify`** defaults to `false`. Per ADR-0004 the connection is made
identically either way and the certificate chain is always captured and verified; the
flag decides only whether a verification failure aborts the Probe. The verification
finding is recorded in both modes.

**`--candidate-ip`** sets the Candidate Sending IP. Under `probe` and `matrix` it defaults to
the observed Source Address, normalized per ADR-0006. Under `auth` there is no Source
Address to default to, so without `--candidate-ip` Frank reports the SPF Verdict as not
evaluated and still renders the Evaluation Tree, the Lookup Limit finding, DKIM and
DMARC. It never invents a sending IP.

**`--redact`** is a repeatable RE2 regular expression, applied when output is rendered.
The in-memory Transcript stays lossless; what reaches disk is redacted, and the report
states how many spans were masked so a reader knows redaction happened.

**`--output`** is a directory, defaulting to `./frank-<UTC timestamp>/`. Both the
human-readable log and the JSON document are always written there. `--json` changes only
what goes to stdout, which becomes the JSON document instead of the human log.

**`--selector`** is repeatable and adds to the built-in common-selector list. There is no
selector file: `--selector` already expresses any list, and a recurring one belongs in the
config file. The effective list probed is always recorded, so a null Selector Discovery
result reads as "these were checked and none answered" rather than as silence.

**SMTP AUTH** uses PLAIN or LOGIN over an established TLS connection only. Credentials come
from the environment or the config file, never from a command-line argument. See ADR-0007.

**Exit codes.** `0` completed with Acceptance. `1` completed with Rejection. `2` could not
complete, meaning network, TLS or protocol failure. `3` usage or config error. `4`
completed but Inconclusive. `matrix` exits `1` if any Cell resolved Rejected, otherwise `4`
if any Cell is Inconclusive or Unrun, otherwise `0`. `auth` exits `0` when every Verdict was
computed and `2` when DNS failed. `explain` exits `3` on unreadable input.

---

## Milestones

Each milestone is independently shippable and testable. Implement in order; do
not begin a milestone until the previous one's acceptance checks pass.

### Milestone 0 — Skeleton & transcript spine

Establish the project shape and the one data structure everything else hangs off:
the **transcript**.

- Cobra-style (or stdlib `flag`) subcommand routing for the four verbs above;
  only `probe` need do anything yet.
- Define the `Transcript` type: an ordered list of timed events, each tagged as
  `dial`, `tls`, `send` (client→server), `recv` (server→client), `note`, or
  `error`, carrying a monotonic timestamp, wall-clock timestamp, the raw bytes,
  and a parsed view where applicable (SMTP reply code + enhanced status code +
  text).
- A transcript writer that renders to (a) a human-readable annotated log and
  (b) a JSON document. Both are lossless with respect to the raw bytes.
- Redaction hook in the writer: AUTH credentials and any `--redact` patterns are
  masked at render time but the code path is exercised even when empty. The in-memory
  Transcript is never redacted, so "lossless" and "redacted" describe different
  artefacts and both stay true.

**Acceptance:** `frank probe --dry-run` with no reachable target prints a well-formed
Transcript carrying the dial attempt and its error in both formats, not an empty one; unit tests cover reply-line parsing including
multiline replies (`250-` continuations) and enhanced status codes.

### Milestone 1 — The controlled ESMTP conversation

The heart of Frank. A hand-rolled SMTP client that walks the protocol phase by
phase and records everything, and — crucially — lets the three identities be set
independently and to deliberately mismatched values.

- Dial (TCP), optional connect timeout, capture the banner.
- `EHLO <helo-identity>` with fallback to `HELO`; parse and record advertised
  extensions (SIZE, STARTTLS, AUTH mechanisms, PIPELINING, 8BITMIME, etc.).
- STARTTLS negotiation with full control: `--tls=require|prefer|none`, capture
  the negotiated version and cipher, capture and record (never silently trust)
  the presented certificate chain, with `--tls-verify=true|false` explicit and
  logged.
- `MAIL FROM:<envelope-sender>` — set independently of everything else. A null sender
  (`<>`) is a legal value, not an error: it is the bounce path, and under RFC 7208 §2.4
  it moves SPF's subject to the HELO Identity.
- `RCPT TO:<recipient>` — exactly one Recipient per Probe, so every Phase carries
  exactly one Outcome. Several recipients means several Probes. The Recipient is not an
  Identity Slot and is never varied by `matrix`.
- `DATA` with a message whose header `From:` is set **independently** of the
  envelope sender, plus a minimal, valid, clearly-marked diagnostic body
  (`Date`, `Message-ID`, `Subject`, and an X-header identifying the message as a
  Frank probe).
- Correct dot-stuffing and `<CRLF>.<CRLF>` termination.
- Capture the reply to the `DATA` verb and the reply to the terminating dot as
  **separate Phases**, each with its enhanced status code and full text. A refusal of
  `DATA` is policy on the envelope; a refusal of the final dot is policy on the message,
  and it is the latter that usually carries the 550.
- A clean `QUIT`, and a `RSET`-and-reuse path for the matrix runner.
- Phase-level timing recorded for every step (this is what exposes fixed-duration
  stalls and governed timeouts).

The three Identity Slots are the first-class inputs:
`--envelope-from`, `--helo`, `--header-from`. Any may differ from any other; that
is the entire point.

**Acceptance:** against a local fixture SMTP server (a test double, see Testing),
Frank completes a full conversation, and a test asserts that mismatched
`--envelope-from` / `--header-from` / `--helo` values appear verbatim in the
transcript at the correct phases. Timing fields are populated and monotonic.

### Milestone 2 — SPF evaluation with `include:` unrolling

Standalone authentication analysis, beginning with SPF, because SPF is what most
"not allowed to send" policies key on.

- Fetch and parse the SPF TXT record of the Envelope Sender's domain — or of the HELO
  Identity's domain when the Envelope Sender is null. Every Verdict names the subject it
  evaluated.
- Recursively resolve `include:`, `redirect=`, `a`, `mx`, `ptr`, `exists`, and
  `ip4`/`ip6` mechanisms into a flattened, ordered evaluation tree.
- Enforce and *report* the RFC 7208 lookup limit (10 DNS-querying mechanisms):
  Frank should show when a record is over-limit, because an over-limit SPF record
  is itself a common root cause.
- Given a Candidate Sending IP (`--candidate-ip`, defaulting to the observed Source
  Address — see ADR-0002; the default is wrong whenever the Target Host relays onward,
  so the Verdict always states which IP it used and whether it was observed or supplied),
  evaluate to a Verdict: `pass`, `fail`, `softfail`,
  `neutral`, `none`, `permerror`, `temperror`, and show *which* mechanism
  matched.
- Render the unrolled tree so a human can see exactly how the result was reached.

**Acceptance:** table-driven tests over crafted zone fixtures cover nested
includes, redirect, over-limit detection, and each result class; the matched
mechanism is reported correctly.

### Milestone 3 — DKIM selector discovery & DMARC alignment

Complete the authentication picture.

- **DKIM:** given a domain and one or more selectors (`--selector`, repeatable),
  fetch `<selector>._domainkey.<domain>` TXT records, parse the key record
  (`v`, `k`, `p`, flags), and report key presence, algorithm, and any obvious
  faults (revoked/empty `p=`, test mode `t=y`). Include a best-effort
  **selector discovery** pass over a configurable list of common selectors
  (`default`, `google`, `selector1`, `selector2`, `s1`, `k1`, `mail`, …) so the
  user need not know the selector in advance.
- **DMARC:** fetch `_dmarc.<domain>`, parse policy (`p`, `sp`, `adkim`, `aspf`,
  `pct`, `rua`, `ruf`), and compute **alignment**. `pct` is reported, never applied
  stochastically: a Verdict is deterministic, and a `pct` below 100 appears as a caveat
  in the Diagnosis saying receivers apply the policy to a sample. given an SPF result and a DKIM
  d= domain: identifier alignment in both relaxed and strict modes against the
  header `From:` domain. This is the mechanism that ties the envelope/header
  mismatch from Milestone 1 to an actual pass/fail verdict.

**Acceptance:** fixtures exercise strict vs relaxed alignment, subdomain policy,
`pct` handling, and a missing-DMARC (`none`) case; DKIM discovery finds a seeded
selector among decoys.

### Milestone 4 — The identity matrix

Orchestrate Milestone 1 across a grid of identity combinations and report the
boundary between what is accepted and what is rejected.

- Accept sets of values for each Identity Slot and run the Cartesian product of
  Identity Triples (bounded and rate-limited), one Probe per Cell per pass, on a fresh
  connection every time. See ADR-0003: no `RSET` reuse. A Cell is re-probed only by the
  back-off policy, at most twice, and only after a Deferral.
- A Cell holds every Probe run for its Triple, and resolves to **Accepted** if any Probe
  reached Acceptance, **Rejected** if one met a Rejection and none reached Acceptance,
  **Inconclusive** if only Deferrals were seen, and **Unrun** if the sweep aborted before
  reaching it. An Unrun Cell is not evidence of anything and is rendered distinctly from
  an Inconclusive one. Each Probe's Outcome records the
  reply code, enhanced status code, text, and the Phase it occurred at.
- Produce a matrix view: rows and columns are Identity Slot values, Cells are
  Accepted/Rejected/Inconclusive with the response code, so the failing Triple is
  visually obvious. An Inconclusive Cell is never reported as a rejected Triple — a
  greylisting host must not read as a policy rejection.
- Stop-early and back-off behaviour on repeated 4xx/rate responses, so Frank
  never hammers a host.

**Acceptance:** against the test double configured to reject a specific
`(envelope-from, header-from)` pairing, `frank matrix` correctly identifies that
one cell as the failure and all others as passes, and honours `--rate`.

### Milestone 5 — `explain`: joining transcript to authentication

The synthesis step that makes Frank more than the sum of its verbs.

- `frank explain <transcript.json> [--auth <auth.json>]`. Without `--auth`, Frank performs
  the lookups itself. A Transcript from `matrix` yields one Diagnosis for the run, naming
  the boundary between accepted and rejected Triples, plus a one-line Diagnosis per Cell.
- Take a captured Transcript (from `probe` or `matrix`) plus the Verdicts (from `auth`)
  and produce a plain-English Diagnosis: e.g. "rejection
  occurred at DATA with 550 5.7.x; the header From domain is `X`, the envelope
  domain is `Y`, DMARC for `X` is `p=reject` with strict SPF alignment, and the
  envelope domain does not align — this rejection is consistent with a DMARC
  alignment failure, not a connection or TLS fault."
- The Diagnosis is *evidential*, never speculative beyond what the records
  support — it distinguishes what was observed (Outcomes) from what was computed
  (Verdicts); where the cause is ambiguous, it says so and lists what further probe
  would disambiguate.

**Acceptance:** golden-file tests: given a transcript fixture + auth fixture, the
rendered explanation matches the expected diagnosis text for several canonical
scenarios (alignment failure, over-limit SPF, TLS refusal, greylisting 4xx).

### Milestone 6 — Report output & polish

- A single self-contained report combining transcript, authentication tree,
  matrix (if run), and explanation. Plain text and JSON; an HTML rendering is
  optional and only if it is trivially a template over the JSON.
- Config file support (`--config`, TOML or JSON) so recurring targets/smart hosts
  need not be retyped.
- Exit codes that mean something to a script: distinguish "probe completed,
  mail accepted", "probe completed, mail rejected", and "probe could not
  complete" (network/TLS/protocol error).

**Acceptance:** end-to-end run against the test double yields a report a human
can act on without reading the source; exit codes are asserted in tests.

---

## Safety posture (normative — do not weaken)

Frank sends real SMTP. That demands guard rails, and they are part of the spec,
not optional hardening:

- **No sending without intent.** Any run that will transmit `DATA` to a live host
  requires an explicit `--confirm-send` (or an interactive confirmation);
  `--dry-run` performs the full protocol walk up to but not including `DATA`
  transmission by default in exploratory modes.
- **Rate limiting is mandatory and on by default.** A conservative default
  per-minute cap applies to every mode that opens connections; `matrix` cannot
  disable it, only lower it.
- **Back off, don't hammer.** Repeated 4xx/greylist/deferral responses trigger
  exponential back-off and, past a threshold, abort with a clear message.
- **Diagnostic payload only.** The message body is fixed, minimal, and
  self-identifying as a Frank deliverability probe, with a header stating its
  purpose. Frank does not send arbitrary content in its probe modes.
- **Truthful transcripts.** Frank never hides what it did. TLS verification
  status, mismatched identities, and every server response are recorded exactly.
- **Not a bypass tool.** Frank characterises anti-spoofing controls; it does not
  provide, and must not grow, features whose only purpose is to evade them
  against hosts the operator does not control. Keep this line in mind when adding
  anything.

---

## Testing strategy

- **Test double first.** Build a configurable in-process SMTP server test double
  early (during Milestone 1) that can be scripted to accept/reject at any phase,
  advertise arbitrary extensions, offer or refuse STARTTLS, and reject specific
  identity combinations. Almost every acceptance check runs against it — no live
  hosts in the test suite.
- **Zone fixtures** for SPF/DKIM/DMARC: a small in-memory resolver seeded from
  table-driven fixtures, so authentication logic is tested deterministically and
  offline.
- **Golden files** for `explain` output.
- **Race detector** on in the CI test invocation, since the matrix runner is
  concurrent.

---

## Decisions

The four questions this section previously held open are settled. Each is recorded as an
ADR in `docs/adr/` where it shapes the code, and stated here where it only shapes a flag.

- **IPv6 is in scope for v1**, dialing and `ip6:` evaluation both. ADR-0006. Suppressing
  v6 is the extra line, not enabling it, and refusing to parse `ip6:` turns every record
  containing it into a `permerror`.
- **`matrix` opens a fresh connection per Cell.** ADR-0003. Measured: the mandatory rate
  limiter is the binding constraint at every conservative setting, so `RSET` reuse saves
  nothing, and reuse would let one Cell's Outcome depend on the Cell before it.
- **Config is JSON.** ADR-0005. Go's standard library has no TOML parser, and
  `encoding/json` is already linked in for the Transcript.
- **The common-selector list ships built in**, extended by the repeatable `--selector`
  flag, with the effective list always recorded. No selector file.

Two decisions the section never thought to ask for:

- **One TLS path, always capturing, verifying separately.** ADR-0004.
- **SMTP AUTH is in scope, and credentials never touch argv.** ADR-0007.

---

## Milestone summary

| # | Deliverable | Core value |
|---|-------------|------------|
| 0 | Skeleton + transcript spine | The lossless artefact everything hangs off |
| 1 | Controlled ESMTP conversation | Independent control of the three identities |
| 2 | SPF with include unrolling | Root-causes most "not allowed to send" cases |
| 3 | DKIM discovery + DMARC alignment | Ties identity mismatch to a real verdict |
| 4 | Identity matrix | Finds the failing combination by experiment |
| 5 | `explain` | Evidential, human-readable diagnosis |
| 6 | Report + polish | A paste-ready artefact and script-friendly exits |
