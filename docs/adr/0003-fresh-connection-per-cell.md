# A fresh connection per Cell, no RSET reuse

`matrix` opens a new connection for every Cell and never reuses one via `RSET`. The
spec held this question open pending measurement, so it was measured. Reuse saves the
connection setup, roughly 4.5 round trips per Cell, but every mode that opens
connections is rate-limited by fiat and `matrix` cannot disable that limit. The
rate-limit floor is therefore the binding constraint at every conservative setting,
and reuse saves nothing at all.

Modelled over an 18-Cell matrix, with 5.5 round trips of setup for a fresh connection
against 1.0 for `RSET`:

```
RTT      rate/min          fresh        reuse      saved
80ms     6                  3m0s         3m0s       0.0%
80ms     12                1m30s        1m30s       0.0%
250ms    30               42.75s          36s      15.8%
250ms    600              42.75s        22.5s      47.4%
```

Reuse only pays at 600 probes per minute, a rate the safety posture forbids. The one
non-zero conservative row saves under seven seconds on a three-quarter-minute run.

With the performance case gone, the correctness case decides it and points the other
way. Real MTAs carry per-connection state: error counters, deferred rejection, policy
that tightens after the first refusal. A reused connection lets one Cell's Outcome
depend on the Cell before it, which costs Frank the independence its evidence rests on.
A Cell is one clean Probe, and that has to stay literally true.

## Consequences

Milestone 1's "RSET-and-reuse path for the matrix runner" becomes a QUIT-and-redial
path. Matrix runs cost more TCP and TLS handshakes, which the rate limiter already
paces. Reopening this needs evidence that reconnection rate itself provokes Deferrals
and confounds results, not a throughput argument.
