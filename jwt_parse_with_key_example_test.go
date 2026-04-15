package examples_test

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_parse_with_key() {
	// Parse a symmetric JWK that will be used both to sign and to verify
	// the token. In a real deployment the signing key lives on the issuer
	// and only the verifier side sees the key material — we do both here
	// so the example is self-contained.
	const keysrc = `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`
	key, err := jwk.ParseKey[jwk.Key]([]byte(keysrc))
	if err != nil {
		fmt.Printf("jwk.ParseKey failed: %s\n", err)
		return
	}

	// Build a fresh token with a future `exp` so the example can exercise
	// the full verification + validation path. Using a canned RFC-era
	// fixture here would force us to disable validation, which is exactly
	// the footgun this example is meant to avoid teaching.
	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		fmt.Printf("jwt.NewBuilder failed: %s\n", err)
		return
	}

	// Sign with HS256. `jwt.WithKey` binds the algorithm to the key at
	// sign time — the signed token's protected header will carry `alg:HS256`.
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
	if err != nil {
		fmt.Printf("jwt.Sign failed: %s\n", err)
		return
	}

	// Parse + verify + validate in one call. Passing `jwa.HS256()`
	// explicitly to `jwt.WithKey` is the alg-confusion defense: the
	// verifier will reject the token unless its protected header matches
	// this algorithm, so an attacker cannot swap in a token signed with a
	// different algorithm that happens to accept the same key bytes.
	//
	// `jwt.Parse` runs claim validation (`exp`, `nbf`, `iat`) by default.
	// Do NOT pass `jwt.WithValidate(false)` in production code — doing so
	// accepts expired or not-yet-valid tokens.
	parsed, err := jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key))
	if err != nil {
		fmt.Printf("jwt.Parse failed: %s\n", err)
		return
	}

	iss, _ := parsed.Issuer()
	fmt.Printf("issuer: %s\n", iss)
	// OUTPUT:
	// issuer: github.com/lestrrat-go/jwx
}
