# Source Address and Candidate Sending IP are separate concepts

An SPF Verdict is computed for some client IP, and Frank's own outbound address is the
right one only when it connects directly to the recipient domain's MX. When the Target
Host is a smart host that relays onward, the receiving system evaluates SPF against the
smart host's egress IP, so defaulting the two to one value yields a confidently wrong
Verdict in exactly the case Frank was built for. Frank therefore models the observed
**Source Address** and the hypothesised **Candidate Sending IP** as distinct, defaulting
the second to the first and stating in every Verdict which was used and whether it was
observed or supplied.

## Consequences

Two IP fields will look redundant to a reader who only pictures the direct-to-MX case;
they are not, and collapsing them reintroduces the bug. `--client-ip` sets the Candidate
Sending IP only — nothing can override the Source Address, which is an observation.
