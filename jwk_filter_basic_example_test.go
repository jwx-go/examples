package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/jwx-go/jwxfilter/v4/jwkfilter"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwk_filter_basic_fields() {
	// Generate an RSA key and import it as a JWK.
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate RSA key: %s\n", err)
		return
	}

	key, err := jwk.Import[jwk.Key](rsaPrivateKey)
	if err != nil {
		fmt.Printf("failed to import RSA key: %s\n", err)
		return
	}

	// Mix of RFC 7517 standard fields ...
	key.Set(jwk.KeyIDKey, "my-rsa-key-001")
	key.Set(jwk.KeyUsageKey, "sig")
	key.Set(jwk.AlgorithmKey, "RS256")

	// ... and application-specific custom fields.
	key.Set("keyOwner", "alice@example.com")
	key.Set("environment", "production")
	key.Set("department", "security")
	key.Set("rotationPolicy", "quarterly")

	// JWK filters live in the github.com/jwx-go/jwxfilter/v4/jwkfilter
	// companion package. jwkfilter.ByName matches field names literally;
	// Filter keeps them, Reject drops them.
	customFilter := jwkfilter.ByName("keyOwner", "environment", "department", "rotationPolicy")

	customOnlyKey, err := customFilter.Filter(key)
	if err != nil {
		fmt.Printf("failed to filter custom fields: %s\n", err)
		return
	}

	// jwkfilter.RSAStandard() is the preset for RFC 7517 + RFC 7518 RSA
	// key fields (kty, use, key_ops, alg, kid, x5u, x5c, x5t, x5t#S256,
	// e, n, d, dp, dq, p, q, qi). There are siblings for each key type:
	// ECDSAStandard, OKPStandard, SymmetricStandard, AKPStandard.
	standardOnlyKey, err := jwkfilter.RSAStandard().Filter(key)
	if err != nil {
		fmt.Printf("failed to filter standard fields: %s\n", err)
		return
	}

	// Create a copy for display purposes, replacing long values with "..."
	displayKey, err := standardOnlyKey.Clone()
	if err != nil {
		fmt.Printf("failed to clone standard key: %s\n", err)
		return
	}

	// Validate that the filtering worked correctly

	// Check custom-only key has expected custom fields and no sensitive data
	if !customOnlyKey.Has("keyOwner") || !customOnlyKey.Has("environment") {
		fmt.Printf("custom key missing expected fields\n")
		return
	}
	if customOnlyKey.Has("d") || customOnlyKey.Has("n") {
		fmt.Printf("custom key should not contain cryptographic fields\n")
		return
	}

	// Check that display key has expected standard fields
	if !displayKey.Has("alg") || !displayKey.Has("kty") || !displayKey.Has("use") {
		fmt.Printf("display key missing standard JWK fields\n")
		return
	}

	// Output:
}
