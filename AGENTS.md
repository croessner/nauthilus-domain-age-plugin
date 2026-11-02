# Domain age plugin engineering rules

Work on features. Write concise English comments for every named function and method.
Use focused contract tests before implementation changes. Apply DRY, small responsibilities and composition.
Never add go.mod: this plugin builds inside a clean exact CORE_REF Nauthilus checkout.
Run make guardrails; all Go tests require GOEXPERIMENT=runtimesecret and the exact host toolchain.
Preserve exact host ABI, netgo build tags and vendor mode. Run make build before release.
Never publish imported datasets, credentials or signing keys. Signing is opt-in with an operator-supplied key.
Only Nauthilus Policy decides message disposition. Keep unknown evidence explicit.
Use structured commit subjects and bullet-list bodies as specified in POLICY.md.
License: GPL-3.0-or-later.
