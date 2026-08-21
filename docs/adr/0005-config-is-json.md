# Config files are JSON, not TOML

Frank reads its config with `encoding/json` and `Decoder.DisallowUnknownFields()`. Go's
standard library has no TOML parser and nothing in `golang.org/x/*` provides one, so
TOML costs a third-party module of several thousand lines to hold a file of about eight
keys. `encoding/json` is already linked into the binary because the Transcript and the
report are JSON, so the config decoder is a free rider on a dependency Frank cannot
avoid.

Two decoder details are what make the small answer the correct one rather than merely
the cheap one. `DisallowUnknownFields` turns a mistyped key into an error instead of a
silently ignored default. Pointer fields distinguish "key absent" from "key set to
zero", which matters directly for `--rate 0` and `--tls-verify=false`, where the zero
value and the unset value must not be confused.

## Consequences

No comments and no trailing commas, so a config cannot be annotated. Someone will
propose stripping `//` lines as a pre-pass. Refuse it, because that invents a format
with no parser to inherit. Reopen this when the config grows structure rather than
length, meaning nesting past two levels or named per-target profiles with inherited
defaults. A flat map of scalars is fine as JSON; a document a human hand-edits with
repeated stanzas is not.
