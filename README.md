# Examples (and Benchmarks)

Runnable usage patterns for [`github.com/lestrrat-go/jwx/v4`](https://github.com/lestrrat-go/jwx) and its companion modules. Every file in this repo is a single `Example_*` test function with extensive inline comments — read them as documentation, run them with `go test`.

Build/run requires `GOEXPERIMENT=jsonv2` (jwx v4 depends on `encoding/json/v2`).

## Per-package entry points

Start here if you want a representative overview of a package:

- [`github.com/lestrrat-go/jwx/v4`](./jwx_example_test.go) — library-wide operations
- [`github.com/lestrrat-go/jwx/v4/jwt`](./jwt_example_test.go)
- [`github.com/lestrrat-go/jwx/v4/jws`](./jws_example_test.go)
- [`github.com/lestrrat-go/jwx/v4/jwe`](./jwe_example_test.go)
- [`github.com/lestrrat-go/jwx/v4/jwk`](./jwk_example_test.go)

The topical index below lists every example file by purpose. Filenames follow `<package>_<action>_example_test.go`.

## JWT — tokens, claims, validation

### Constructing
- [Builder pattern](./jwt_builder_example_test.go) — `jwt.NewBuilder()` to assemble standard claims
- [Direct construction](./jwt_construct_example_test.go) — `jwt.New()` + `Set()` for full control
- [Get claims](./jwt_get_claims_example_test.go) — typed accessors (`Expiration`, `Audience`, …) and `Field` for private claims
- [Raw struct usage](./jwt_raw_struct_example_test.go) — back-channel between `jwt.Token` and your own Go types

### Parsing / verifying
- [Parse (basic)](./jwt_parse_example_test.go) — minimal verify+validate flow
- [Parse with key](./jwt_parse_with_key_example_test.go) — explicit single-key verification
- [Parse with key set](./jwt_parse_with_keyset_example_test.go) — `kid`-based selection from a JWK Set
- [Parse with key provider](./jwt_parse_with_key_provider_example_test.go) — programmatic key resolution
- [Parse via `jku` header](./jwt_parse_with_jku_example_test.go) — fetch keys from the URL in the JWS header (whitelist required)
- [Parse from `*http.Request`](./jwt_parse_request_example_test.go) — pull token out of the Authorization header / cookie / form
- [Parse from filesystem](./jwt_parsefs_example_test.go) — `jwt.ParseFS` for fs.FS-backed tokens

### Validating
- [Validate (basic)](./jwt_validate_example_test.go) — standalone claim checks on an already-parsed Token
- [Validate issuer](./jwt_validate_issuer_example_test.go) — `jwt.WithIssuer`
- [Custom validator](./jwt_validate_validator_example_test.go) — implement `jwt.Validator` for app-specific checks
- [Pass request context](./jwt_with_context_example_test.go) — `jwt.WithContext` threads a `context.Context` into custom validators
- [Detect error types](./jwt_validate_detect_error_type_example_test.go) — distinguish parse vs. validation failures with `errors.Is`

### Signing / serialization
- [Sign with custom base64](./jwt_sign_with_custom_base64_example_test.go) — swap the base64 backend per call
- [Serialize as JWS](./jwt_serialize_jws_example_test.go) — sign and emit a compact JWS-wrapped JWT
- [Serialize as nested JWE+JWS](./jwt_serialize_jwe_jws_example_test.go) — sign then encrypt
- [Serialize as JSON](./jwt_serialize_json_example_test.go) — raw JSON form (no signature)
- [Flatten `aud`](./jwt_flatten_audience_example_test.go) — single-string vs. array form

### Filtering claims
- [Basic filter](./jwt_filter_basic_example_test.go) — restrict a token to a claim allowlist
- [Advanced filter](./jwt_filter_advanced_example_test.go) — predicate-driven filtering

## JWS — sign and verify arbitrary payloads

### Signing
- [Sign (basic)](./jws_sign_example_test.go) — payload + key + algorithm
- [Sign with headers](./jws_sign_with_headers_example_test.go) — attach `kid`, `typ`, etc. to the protected header
- [Sign as JSON serialization](./jws_sign_json_example_test.go) — multi-signature JSON form
- [Sign detached payload](./jws_sign_detached_payload_example_test.go) — RFC 7797 detached form
- [Sign detached payload (streaming)](./jws_sign_detached_reader_example_test.go) — `jws.WithDetachedPayloadReader` for large payloads from an `io.Reader`
- [Sign with `crypto.Signer`](./jws_sign_crypto_signer_example_test.go) — HSM / KMS-backed signers
- [Sign with ES256K (secp256k1)](./jws_sign_es256k_example_test.go) — extension module required
- [Sign with Ed448](./jws_ed448_example_test.go) — extension module required
- [Sign with custom base64](./jws_sign_with_custom_base64_example_test.go)
- [Custom signer / verifier](./jws_custom_signer_verifier_example_test.go) — plug in a new algorithm

### Verifying / parsing
- [Verify with key](./jws_verify_with_key_example_test.go)
- [Verify with key set](./jws_verify_with_keyset_example_test.go)
- [Verify detached payload](./jws_verify_detached_payload_example_test.go)
- [Verify detached payload (streaming)](./jws_verify_detached_reader_example_test.go) — `jws.WithDetachedPayloadReader` for large payloads from an `io.Reader`
- [Verify with `crit` opt-out](./jws_verify_with_crit_opt_out_example_test.go) — handle unknown critical headers
- [Parse (structure only)](./jws_parse_example_test.go) — does NOT verify
- [Parse from filesystem](./jws_parsefs_example_test.go)
- [Access JWS header on a JWT](./jws_use_jws_header_example_test.go)

### Filtering headers
- [Basic filter](./jws_filter_basic_example_test.go)
- [Advanced filter](./jws_filter_advanced_example_test.go)

## JWE — encrypt and decrypt arbitrary payloads

### Encrypting
- [Encrypt (basic)](./jwe_encrypt_example_test.go) — single recipient, compact form
- [Encrypt with headers](./jwe_encrypt_with_headers_example_test.go) — protected and per-recipient headers
- [Encrypt to multiple recipients (JSON)](./jwe_encrypt_json_example_test.go) — `jwe.WithJSON()` + multiple `jwe.WithKey(...)`
- [Encrypt with ECDH-ES (X25519)](./jwe_ecdh_es_x25519_example_test.go)
- [Encrypt with HPKE](./jwe_hpke_example_test.go) — overview
- [HPKE with X25519](./jwe_hpke_x25519_example_test.go)
- [HPKE-5-KE](./jwe_encrypt_hpke5_example_test.go) — AES-256-GCM mode
- [HPKE-6-KE](./jwe_encrypt_hpke6_example_test.go) — ChaCha20Poly1305 mode

### Decrypting / parsing
- [Decrypt with key](./jwe_decrypt_with_key_example_test.go)
- [Decrypt with key set](./jwe_decrypt_with_keyset_example_test.go)
- [Parse (structure only)](./jwe_parse_example_test.go) — does NOT decrypt
- [Parse from filesystem](./jwe_parsefs_example_test.go)

### Filtering headers
- [Basic filter](./jwe_filter_basic_example_test.go)
- [Advanced filter](./jwe_filter_advanced_example_test.go)

## JWK — keys and key sets

### Parsing
- [Parse a single JWK](./jwk_parse_key_example_test.go) — `jwk.ParseKey[jwk.Key]`
- [Parse a JWK Set](./jwk_parse_jwks_example_test.go) — `jwk.Parse`
- [Parse from PEM](./jwk_parse_with_pem_example_test.go) — convert PEM-encoded crypto.* keys to `jwk.Key`
- [Parse from filesystem](./jwk_parsefs_example_test.go)
- [Parse PEM from filesystem](./jwk_parsefs_with_pem_example_test.go)

### Generating / converting
- [Import from `crypto.*`](./jwk_import_example_test.go) — `jwk.Import[T]` wrapping RSA/EC/OKP keys
- [Key-specific methods](./jwk_key_specific_methods_example_test.go) — typed accessors on `RSAPublicKey`, `ECDSAPrivateKey`, etc.
- [Struct field tagging](./jwk_struct_field_example_test.go) — embed `jwk.Key` in your own types

### Extending (custom key types / formats)
- [Custom x509/PEM encoder & decoder](./jwkbb_x509_custom_example_test.go) — register your own PEM block type via `jwk/jwkbb`, the building-block API used by extension modules

### Fetching
- [`Fetch`](./jwk_fetch_example_test.go) — one-shot HTTP retrieval via the `jwkfetch` companion
- [`Cache`](./jwk_cache_example_test.go) — background-refreshed JWK Set store
- [Cached set as a JWKS](./jwk_cached_set_example_test.go) — pass a cache to `jwt.WithKeySet`
- [URL whitelist](./jwk_whitelist_example_test.go) — restrict which URLs `jwkfetch` will dereference (required for `jku`)

### Comparing / filtering
- [Key comparison](./jwk_comparison_example_test.go) — structural and identity-based comparisons
- [Basic filter](./jwk_filter_basic_example_test.go)
- [Advanced filter](./jwk_filter_advanced_example_test.go)

## Extension modules

Each extension is a separate module under `github.com/jwx-go/*`. Import for side effects.

### Post-quantum signatures (ML-DSA)
- [Sign / verify](./mldsa_sign_verify_example_test.go) — ML-DSA-44/65/87 via `github.com/jwx-go/mldsa/v4`
- [JWK round-trip](./mldsa_jwk_example_test.go) — AKP key type, `"alg"` field requirement
- [Export to raw key](./mldsa_export_example_test.go)

### Post-quantum key encapsulation (ML-KEM)
- [Encrypt / decrypt](./mlkem_encrypt_decrypt_example_test.go) — ML-KEM-768/1024 via `github.com/jwx-go/mlkem/v4`

### Hybrid PQ HPKE
- [Encrypt / decrypt](./pqchpke_encrypt_decrypt_example_test.go) — via `github.com/jwx-go/reddy-pqchpke/v4` (experimental)

### Composite signatures
- [Sign / verify](./compsig_sign_verify_example_test.go) — ML-DSA + classical via `github.com/jwx-go/compsig/v4` (experimental)

### Niche curves
- [ES256K (secp256k1)](./jws_sign_es256k_example_test.go) — see JWS Sign section
- [Ed448](./jws_ed448_example_test.go) — see JWS Sign section

### Tooling / backends
- [ASM-optimized base64](./jwx_asmbase64_example_test.go) — high-throughput base64 backend via `github.com/jwx-go/asmbase64/v4`

## Library-wide

- [Cross-package overview](./jwx_example_test.go)
- [README example](./jwx_readme_example_test.go) — the snippet that appears in the main jwx README
- [Register custom EC curve and key type](./jwx_register_ec_and_key_example_test.go)

## Contributing a new example

1. One example per file. File name: `<topic>_<action>_example_test.go`.
2. Function name: `Example_<topic>_<action>()` — the matching slug without `_example_test.go`.
3. Add a line to the topical index above in the same PR.
4. Include ample inline comments that explain **why** the code is shaped the way it is.
5. End with an `// OUTPUT:` block — even an empty one if the function prints nothing.

See [`CLAUDE.md`](./CLAUDE.md) for the full conventions.
