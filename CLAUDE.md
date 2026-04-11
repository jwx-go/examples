# Examples Repository

## File Structure

- One example per file. NEVER put multiple examples in one file.
- File naming: `<topic>_<action>_example_test.go` — concise but descriptive. e.g., `jws_sign_example_test.go`, `mldsa_sign_verify_example_test.go`.
- Exception: a representative/overview example for a package → `<pkg>_example_test.go`. e.g., `jws_example_test.go`, `jwk_example_test.go`.
- Function naming: `Example_<topic>_<action>()` — matches file name without `_example_test.go`. e.g., `Example_jws_sign()`, `Example_mldsa_sign_verify()`.

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
