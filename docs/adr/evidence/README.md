# Evidence for the ADRs

Two programs whose output is quoted in `docs/adr/`. Each is standalone and needs no
module. Rerun either with `go run ./main.go` from its directory.

`reuse-model/` models an 18-Cell matrix under both connection strategies across RTT and
rate-limit settings. Its table is quoted in ADR-0003. It is a model, not a capture, and
its round-trip constants are declared at the top of the file where they can be argued
with.

`verify-claims/` exercises the Go standard library behaviour that ADR-0004 and ADR-0006
depend on. It verifies that `netip.Prefix.Contains` rejects an IPv4-mapped address and
accepts it after `.Unmap()`, that `InsecureSkipVerify` still populates
`PeerCertificates` while leaving `VerifiedChains` nil, that `VerifyPeerCertificate` is
invoked anyway, and that `DisallowUnknownFields` rejects a mistyped key. Sixteen checks,
all passing on Go 1.26.2. A future Go release that changes any of them invalidates the
ADR that rests on it.
