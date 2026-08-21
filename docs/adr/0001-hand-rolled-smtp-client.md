# Hand-rolled SMTP client rather than `net/smtp`

Frank's entire purpose is to send deliberately mismatched Envelope Sender, HELO
Identity and Header From values and record exactly what a Target Host does about it.
`net/smtp` is built to stop precisely that — it owns the conversation, normalises the
identities, and offers no hook for recording raw bytes or per-Phase timing — so Frank
implements the ESMTP command/response loop itself against `net` and `crypto/tls`.

## Consequences

The correctness of reply parsing (multiline `250-` continuations, enhanced status
codes), dot-stuffing, and `<CRLF>.<CRLF>` termination is ours to get right and ours to
test. That cost is accepted: it buys the lossless Transcript and the independent
Identity Slots, without which Frank has no product.
