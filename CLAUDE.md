# Examples Repository

## File Structure

- One example per file. NEVER put multiple examples in one file.
- File naming: `<topic>_<action>_example_test.go` — concise but descriptive. e.g., `jws_sign_example_test.go`, `mldsa_sign_verify_example_test.go`.
- Exception: a representative/overview example for a package → `<pkg>_example_test.go`. e.g., `jws_example_test.go`, `jwk_example_test.go`.
- Function naming: `Example_<topic>_<action>()` — matches file name without `_example_test.go`. e.g., `Example_jws_sign()`, `Example_mldsa_sign_verify()`.

### Examples whose behavior depends on the Go version

When the canonical way to do something differs between toolchains, ship one file per toolchain instead of hedging inside a single example:

- `<topic>_<action>_go127_example_test.go` with `//go:build go1.27`.
- `<topic>_<action>_pre_go127_example_test.go` with `//go:build !go1.27`.

Both keep the **same** `Example_<topic>_<action>()` name; the build tags make them exclusive, so godoc shows one per toolchain.

The two files MUST mirror each other line for line, differing only where the toolchain forces it. A reader diffs the pair to learn what actually changed, so any other drift in wording is a defect.

When two packages share a name, prose MUST qualify every type and function with its import path: write `*crypto/mldsa.PrivateKey` or `*filippo.io/mldsa.PrivateKey`, never a bare `*mldsa.PrivateKey`. Code keeps the short form the import gives it, so the comments are the only place a reader can tell the two apart. ML-DSA is the current instance: `crypto/mldsa` from Go 1.27, `filippo.io/mldsa` plus `github.com/jwx-go/mldsa/v4` before that.

## Comments

Examples serve as end-user documentation. Every example function MUST have ample inline comments that:

- Explain **why** code is constructed the way it is, not just what it does.
- Describe how the feature works so readers learn from the example.
- Guide the reader through the flow: what each step accomplishes and why it's needed.

Bad: `// Sign the payload` (states the obvious).
Good: `// Sign the payload using ML-DSA-65. The algorithm must match the key's parameter set — passing an ML-DSA-44 key here would fail.`

## Output

- Every example function MUST end with an `// OUTPUT:` comment block for `go test` to validate output.
- If an example produces no output, use an empty `// OUTPUT:` block.

## Package / Build

- All files use `package examples_test`.
- Build requires `GOEXPERIMENT=jsonv2`.

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly to these branches. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |

- Tags are cut from `v*` branches.
- `v*` branches should never be directly worked on.
- Regular development happens on `develop/v*` and feature branches.
