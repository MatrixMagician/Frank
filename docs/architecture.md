# Architecture

How Frank is put together, and why. [CONTEXT.md](../CONTEXT.md) defines the vocabulary
and wins over this document; [docs/adr/](./adr/) holds the decisions. This file describes
the shape those decisions produce.

## Package tree

```
main.go                     os.Exit and the real stdout, nothing else
internal/cli                verb routing, global flags, exit codes      #1 #14
internal/version            the version string
internal/transcript         Transcript, Event, Phase, reply parsing,
                            the two renderers, redaction                #2
internal/smtptest           in-process SMTP test double                 #3
internal/smtpconv           the hand-rolled ESMTP conversation          #4 #5 #11
internal/gate               send gating, rate limiting, back-off        #6
internal/resolve            the DNS seam, real and fixture resolvers    #7
internal/spf                Evaluation Tree, Verdict, Lookup Limit      #8
internal/dkim               key records, Selector Discovery             #9
internal/dmarc              policy parsing, Alignment                   #10
internal/matrix             the Cell sweep                              #12
internal/explain            Diagnosis                                   #13
internal/report             combined report, config decoding            #14
```

Dependencies point one way, from the outside in. `cli` may import anything.
`transcript` and `resolve` are leaves and import nothing of Frank's. Nothing imports
`smtptest` outside a test file.

## Names

Package names avoid the glossary's nouns as bare identifiers where that would collide
with the standard library. `internal/smtpconv` rather than `internal/smtp`, so
`smtp.Client` never reads ambiguously against `net/smtp`, which ADR-0001 explains we
deliberately do not use. `internal/resolve` rather than `internal/dns` for the same
reason against `net`.

Everywhere else the glossary's terms are the identifiers, exactly: `Transcript`,
`Phase`, `Outcome`, `Verdict`, `Diagnosis`, `Cell`, `IdentityTriple`, `EnvelopeSender`,
`HeloIdentity`, `HeaderFrom`, `SourceAddress`, `CandidateSendingIP`, `EvaluationTree`,
`MatchedMechanism`, `LookupLimit`, `Alignment`, `SelectorDiscovery`. A reader who knows
the glossary can read the code.

## Two orthogonal axes on an Event

The spec tags each event `dial`, `tls`, `send`, `recv`, `note` or `error`. The glossary
tags each step of the conversation `dial`, `banner`, `EHLO`, `STARTTLS`, `MAIL FROM`,
`RCPT TO`, `DATA`, `end-of-data`, `QUIT`. These are not the same list and collapsing them
loses information: a `recv` during `DATA` and a `recv` during `end-of-data` are the two
events whose difference the whole tool turns on.

So an Event carries both. `Kind` says what sort of record it is, `Phase` says where in
the conversation it happened. Both are closed enumerated types with a `String` method and
explicit JSON marshalling, never bare strings or ints.

`PhaseData` and `PhaseEndOfData` are separate constants. A refusal of the `DATA` verb is
policy on the envelope; a refusal of the terminating dot is policy on the message.

## The typed-identity rule

ADR-0002 turns on Source Address and Candidate Sending IP staying distinct. If both are
`netip.Addr` a future edit will collapse them and reintroduce a confidently wrong Verdict.
They get distinct named types so the compiler refuses the collapse:

```go
type SourceAddress struct{ addr netip.Addr }      // observed, never settable by a flag
type CandidateSendingIP struct {
    addr     netip.Addr
    Observed bool                                  // false when --candidate-ip supplied it
}
```

Every address entering SPF evaluation is normalized with `.Unmap()` at construction, and
an address carrying a zone is rejected there. ADR-0006 requires it, and it is verified
against Go 1.26.2 in `docs/adr/evidence/verify-claims`. Doing it at construction rather
than at each comparison is what stops the next matcher forgetting.

## Illegal states

An `Outcome` is an observation and must always carry the reply that justifies it, so it
is one struct with a closed `OutcomeKind` and a required reply, never a bare enum a caller
can set without evidence. A `Cell` resolves by a pure function over the Probes it holds,
never by a mutable field a caller can set inconsistently with its contents. Verdicts,
mechanisms and policies are closed types with `String` methods.

Where the code would otherwise branch on a shape repeatedly, it holds a table instead:
the SPF mechanism set, the DKIM common-selector list, the test double's rule set, and the
Diagnosis rule set are all tables walked in order, not `switch` chains.

## Exit codes

`cli.Main(args, stdout, stderr) Code` is the seam. It returns a typed `Code` and writes to
injected writers, so tests assert exit codes without spawning a binary. `main.go` is the
only file that mentions `os.Exit`.

`0` Acceptance, `1` Rejection, `2` could not complete, `3` usage or config error,
`4` Inconclusive.

## Time and the network are seams

Anything that would make the suite slow or non-deterministic is an interface with a real
implementation and a fake:

- `gate.Clock` so the 6-per-minute limiter is asserted without a test that sleeps.
- `resolve.Resolver` so no test touches real DNS.
- `smtpconv` dials through a `Dialer` func so the test double is reachable.

The fakes live beside the real ones and the suite uses only the fakes.

## Config

JSON, `DisallowUnknownFields`, pointer fields. ADR-0005. A mistyped key is an error naming
the key, and an absent key is distinguishable from a key set to zero, which is what makes
`--rate 0` and `--tls-verify=false` expressible. Precedence is explicit flag, then config,
then default, decided using the `Explicit` set `cli` already records.
