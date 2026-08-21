# Frank

Frank is a command-line SMTP deliverability forensics instrument. It isolates, by
controlled experiment, which combination of sending identities a receiving host
rejects, and corroborates that against the authentication records published for
the domains in play.

## Language

### The conversation

**Probe**:
A single controlled ESMTP conversation with one Target Host, from dial to `QUIT`,
using exactly one Identity Triple and exactly one Recipient, so that every Phase has
exactly one Outcome.
_Avoid_: run, attempt, test, send.

**Target Host**:
The SMTP server Frank connects to — a smart host, a relay, or an MX selected for a
recipient domain.
_Avoid_: server, destination, MX (an MX is one way of choosing a Target Host, not a
synonym for it).

**Transcript**:
The complete, ordered, timestamped record of a Probe, lossless with respect to the
bytes on the wire.
_Avoid_: log, output, capture, session.

**Phase**:
A named step of the conversation (dial, banner, EHLO, STARTTLS, MAIL FROM, RCPT TO,
DATA, end-of-data, QUIT) to which an Outcome and a duration can be attributed. DATA
and end-of-data are separate Phases: a refusal of the `DATA` verb is policy on the
envelope, a refusal of the terminating dot is policy on the message.
_Avoid_: step, stage, post-DATA.

**Recipient**:
The single `RCPT TO` address of a Probe. Not an Identity Slot: Frank never varies the
Recipient within a Matrix, so a Matrix result is always about the sending identities.
_Avoid_: to, target, address.

**Probe Message**:
The fixed, minimal, self-identifying diagnostic message Frank transmits during DATA.
Never arbitrary content.
_Avoid_: payload, test email, body.

### The identities

**Identity Slot**:
One of the three roles Frank varies independently: Envelope Sender, HELO Identity,
Header From.
_Avoid_: bare "identity" — it collides with Identity Triple.

**Identity Triple**:
One concrete filling of all three Identity Slots. A Probe uses exactly one.
_Avoid_: combination, pairing, permutation, identity.

**Envelope Sender**:
The address Frank gives in `MAIL FROM`. May be null (`<>`), which is a first-class
Identity Triple value, not an error.
_Avoid_: return-path, bounce address, sender.

**HELO Identity**:
The name Frank presents in `EHLO`/`HELO`.
_Avoid_: hostname, greeting name.

**Header From**:
The address in the Probe Message's `From:` header. In DMARC terms, RFC5322.From.
_Avoid_: display from, author.

**Domain Pair**:
The Envelope Sender's domain and the Header From's domain — what SPF authenticates
and what DMARC aligns against, respectively. When the Envelope Sender is null, SPF's
subject is the HELO Identity's domain instead, and a Verdict always names which
subject it evaluated. The unit `auth` evaluates.
_Avoid_: sender and recipient, the two domains.

### Outcomes

**Outcome**:
What a Target Host did, observed at a Phase of a Probe: an Acceptance, a Rejection or
a Deferral, carrying the reply code, enhanced status code and full text. Always an
observation, never an inference.
_Avoid_: result, finding.

**Acceptance**:
A 2xx reply to end-of-data. The strongest fact a Probe can establish — it is not
evidence of delivery, and Frank never claims otherwise.
_Avoid_: delivered, sent, success, inboxed.

**Rejection**:
A permanent (5xx) refusal at a given Phase.
_Avoid_: failure, bounce, error.

**Deferral**:
A transient (4xx) refusal — greylisting, rate limiting, temporary unavailability. A
Deferral is not a Rejection and proves nothing about the Identity Triple that met it.
_Avoid_: soft bounce, retry, temp fail.

**Verdict**:
What the published records say for a domain — the SPF result and its Matched
Mechanism, the DMARC policy, the Alignment outcome. Computed from DNS, independent of
any Probe.
_Avoid_: result, finding, assessment.

**Diagnosis**:
The evidential synthesis of Outcomes and Verdicts that `explain` produces: a statement
of cause supported by both, explicit about ambiguity and about which further Probe
would resolve it.
_Avoid_: explanation, conclusion, analysis.

### Authentication

**Source Address**:
The address Frank actually dialled the Target Host from. An observed fact, always
recorded in the Transcript.
_Avoid_: local IP, our IP, client IP.

**Candidate Sending IP**:
The IP address an SPF Verdict is computed for — a hypothesis about which host the
receiving system will check. Defaults to the Source Address, which is wrong whenever
the Target Host relays onward, so every Verdict names the Candidate Sending IP it used
and whether it was observed or supplied.
_Avoid_: client IP, sending IP, our IP.

**Evaluation Tree**:
A domain's SPF record flattened into an ordered expansion of every mechanism,
including those reached through `include:` and `redirect=`, showing how a Verdict was
reached.
_Avoid_: SPF chain, flattened record, resolution graph.

**Matched Mechanism**:
The single mechanism in an Evaluation Tree that determined the SPF Verdict.

**Lookup Limit**:
RFC 7208's cap of ten DNS-querying mechanisms. Exceeding it is a root cause in its own
right, not a warning.
_Avoid_: SPF limit, DNS budget.

**Alignment**:
Whether the domain authenticated by SPF or DKIM matches the Header From domain, in
either relaxed or strict mode. Alignment is what turns a Domain Pair mismatch into a
DMARC Verdict.
_Avoid_: match, correspondence.

**Selector Discovery**:
Probing a list of candidate DKIM selectors to find those a domain actually publishes,
when the selector is not known in advance.
_Avoid_: selector scan, key hunt.

### The matrix

**Matrix**:
A bounded, rate-limited sweep of Identity Triples, one Probe per Triple, run to find
the boundary between Triples a Target Host accepts and Triples it rejects.
_Avoid_: grid, sweep, campaign.

**Cell**:
One Identity Triple and every Probe run for it. A Cell resolves to Accepted if any
Probe reached Acceptance, Rejected if one met a Rejection and none reached Acceptance,
and Inconclusive if only Deferrals were seen — an Inconclusive Cell is never reported
as a rejected Triple.
_Avoid_: run, entry, case.
