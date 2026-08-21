# One TLS path: always capture, verify separately

Frank always dials with `InsecureSkipVerify: true` and captures the presented chain
through `VerifyPeerCertificate`, then runs `x509.Certificate.Verify` itself against a
pool and records the answer as a finding. `--tls-verify=true` decides only whether that
finding aborts the Probe. It does not change how the connection is made.

The obvious alternative is two code paths, one verifying and one not. It loses evidence
exactly when the evidence matters: a verifying handshake that fails aborts before the
Transcript has recorded the chain that caused it, which is the certificate a forensics
user most needs to see. One path means the chain, the negotiated version and the cipher
land in the Transcript identically in both modes, with the verification result recorded
beside them rather than implied by whether the Probe survived.

Verified against Go 1.26.2. Under `InsecureSkipVerify`, `PeerCertificates` is fully
populated, `VerifiedChains` is nil, and `VerifyPeerCertificate` is still invoked with a
nil `verifiedChains`. That nil is the "captured, not trusted" signal.

## Consequences

An unconditional `InsecureSkipVerify: true` in the source reads as a security bug and
someone will try to fix it. It is load-bearing. The verification that matters happens a
few lines later against an explicit pool, and its result is recorded either way.

`ServerName` must be set explicitly or the check has nothing to match against, and
`SessionTicketsDisabled: true` is required because `VerifyPeerCertificate` is not
invoked on a resumed connection. A resumption would produce a Transcript with no
certificate in it at all.
