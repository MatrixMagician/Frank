# Frank

Frank is a command-line SMTP deliverability forensics instrument. It reduces a
"550 not allowed to send" failure to a precise, reproducible statement: which
combination of sending identities a receiving host rejects, at which protocol
phase, with the exact server response, corroborated by the authentication
records that explain it.

It is a diagnostic instrument, not a mailer. Its defaults are cautious, its
output is a report, and it will not transmit a message without being told to.

- [SPEC.md](./SPEC.md) is what it does.
- [CONTEXT.md](./CONTEXT.md) is the vocabulary, and it wins over everything else.
- [docs/architecture.md](./docs/architecture.md) is how the code is arranged.
- [docs/adr/](./docs/adr/) is why the decisions that look surprising are correct.

## Build

```
go build -o frank .
```

Go 1.26, no CGO, no third-party dependencies at all.

## The four verbs

**`frank auth`** evaluates the authentication posture of a domain. It opens no
connection.

```
frank auth --envelope-from noreply@github.com --header-from noreply@github.com --candidate-ip 192.30.252.1
```

It prints the SPF Evaluation Tree with the Matched Mechanism marked, the DKIM
selectors it found and the full list it probed, and the DMARC policy with
alignment computed in both relaxed and strict modes.

Without `--candidate-ip` there is no Candidate Sending IP, so the SPF Verdict is
reported as not evaluated and the tree still renders. Frank never invents a
sending IP.

**`frank probe`** conducts one controlled ESMTP conversation and captures a
complete timestamped Transcript. The three identities are set independently,
and any may differ from any other; that mismatch is the entire point.

```
frank --dry-run probe \
  --target smtp.example.com:587 \
  --envelope-from bounce@sender.example \
  --helo frank.invalid \
  --header-from ceo@victim.example \
  --recipient rcpt@target.example
```

`--dry-run` walks the full protocol through `RCPT TO` and stops before issuing
`DATA`. To actually transmit, name the recipient explicitly with
`--confirm-send rcpt@target.example`.

**`frank matrix`** sweeps the Cartesian product of identity triples and reports
the boundary between what a host accepts and what it rejects.

```
frank --confirm-send rcpt@target.example matrix \
  --target smtp.example.com:587 \
  --recipient rcpt@target.example \
  --envelope-from bounce@sender.example --envelope-from '<>' \
  --helo frank.invalid \
  --header-from ceo@victim.example --header-from author@sender.example
```

```
cells: 2 accepted, 2 rejected, 0 inconclusive, 0 unrun
boundary: 2 of 4 Triples were rejected; every rejection carried header from ceo@victim.example
key: . accepted   X rejected   ? inconclusive (asked, no answer)   - unrun (never asked)

helo identity: frank.invalid
                        1 2
bounce@sender.example   X .
<>                      X .
```

**`frank explain`** takes a captured Transcript and states a Diagnosis, doing
the lookups itself or reading them from `--auth`.

```
frank explain ./frank-20260822T012615Z/transcript.json
```

```
diagnosis: the rejection is consistent with a DMARC alignment failure rather
than a connection or TLS fault: the header From domain is github.com, DMARC for
it is p=quarantine, and neither identifier authenticated and aligned
confidence: supported
evidence:
  - observed: the target replied 550 5.7.1 at end-of-data: ...
  - computed: DMARC for github.com publishes p=quarantine with aspf=relaxed ...
```

Evidence is always tagged: **observed** is something the target did,
**computed** is something the published records say. Where the cause is
ambiguous the Diagnosis says so and names the further Probe that would settle it.

## Safety

These are normative and are not configurable away.

- Nothing is transmitted without `--confirm-send`, which names the recipient
  rather than merely asserting intent. Without it a run walks to `RCPT TO` and
  stops.
- A run that would have to prompt when stdin is not a terminal errors before
  dialing rather than hanging, so Frank is safe in CI.
- Rate limiting is on by default at 6 connections per minute. `matrix` may lower
  it and can never raise it; an attempt to raise is refused, not clamped.
- Repeated deferrals back off exponentially and abort past a threshold.
- The probe message is fixed, minimal and self-identifying as a Frank probe.
- SMTP AUTH runs only over an established TLS connection, and credentials come
  from `FRANK_SMTP_USERNAME` / `FRANK_SMTP_PASSWORD` or the config file, never
  from a flag.

## Output

Every run writes both a human-readable log and a JSON document to the output
directory, which defaults to `./frank-<UTC timestamp>/`. `--json` changes only
what goes to standard output, never what is written to disk.

`--redact <regexp>` is repeatable and masks matches when output is rendered. The
in-memory Transcript stays lossless, and the report states how many spans were
masked so a reader knows redaction happened.

## Config

JSON, decoded strictly. A mistyped key is an error naming the key, and a key set
to zero is distinguishable from an absent one.

```json
{
  "target": "smtp.example.com:587",
  "rate": 4,
  "tls": "require",
  "redact": ["internal\\.example\\.com"],
  "selectors": ["mycompany1"]
}
```

Explicitly-given flags beat config values.

## Exit codes

| code | meaning |
|------|---------|
| 0 | completed with an Acceptance |
| 1 | completed with a Rejection |
| 2 | could not complete: network, TLS or protocol failure |
| 3 | usage or config error |
| 4 | completed but Inconclusive |

`matrix` exits 1 if any Cell was Rejected, otherwise 4 if any is Inconclusive or
Unrun, otherwise 0.

An Acceptance means the target took responsibility for the message. It is not
evidence of delivery, and Frank never claims otherwise.

## Tests

```
CGO_ENABLED=1 go test -race ./...
```

No test touches a live host or real DNS: there is an in-process SMTP test double
and a fixture resolver, and a guard fails any test that tries to reach the
network. `scripts/check.sh` runs the whole predicate, build, vet, race tests and
the acceptance ledger in `docs/acceptance.tsv`.
