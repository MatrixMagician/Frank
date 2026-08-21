# SMTP AUTH is in scope, and credentials never touch argv

Frank authenticates with PLAIN and LOGIN, and only over an established TLS connection.
The spec's opening sentence points Frank at a smart host, and most smart hosts require
authentication, so a Frank that cannot authenticate cannot perform its headline
diagnosis. The transcript writer's redaction hook already names AUTH credentials as a
redaction target, which is the spec conceding the feature exists.

Credentials come from an environment variable or the config file. They are never read
from a command-line argument, because argv is world-readable through `/proc` on the
Linux hosts Frank targets and lands verbatim in shell history. Frank refuses to
authenticate over a connection that is not TLS-protected, whatever `--tls` says.

## Consequences

The redaction hook becomes load-bearing rather than decorative, and its tests are the
proof that credentials never reach a Transcript on disk. Refusing plaintext AUTH means
Frank cannot probe a smart host that offers AUTH only in the clear. That host has a
worse problem than the one Frank was called in to diagnose.
