package examples_test

import (
	"encoding/json"
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	_ "github.com/jwx-go/ed448/v4"
)

func Example_jws_ed448() {
	// Generate an Ed448 key pair
	pub, priv, err := ed448.GenerateKey(nil)
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}

	payload := []byte("Hello, Ed448!")

	// Sign and verify with raw keys
	signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd448(), priv))
	if err != nil {
		fmt.Printf("failed to sign: %s\n", err)
		return
	}

	verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd448(), pub))
	if err != nil {
		fmt.Printf("failed to verify: %s\n", err)
		return
	}
	fmt.Printf("%s\n", verified)

	// Import raw keys into JWK
	jwkPriv, err := jwk.Import[jwk.Key](priv)
	if err != nil {
		fmt.Printf("failed to import private key: %s\n", err)
		return
	}

	jwkPub, err := jwk.Import[jwk.Key](pub)
	if err != nil {
		fmt.Printf("failed to import public key: %s\n", err)
		return
	}

	// Sign and verify with JWK keys
	signed, err = jws.Sign(payload, jws.WithKey(jwa.EdDSAEd448(), jwkPriv))
	if err != nil {
		fmt.Printf("failed to sign with JWK key: %s\n", err)
		return
	}

	verified, err = jws.Verify(signed, jws.WithKey(jwa.EdDSAEd448(), jwkPub))
	if err != nil {
		fmt.Printf("failed to verify with JWK key: %s\n", err)
		return
	}
	fmt.Printf("%s\n", verified)

	// JWK JSON round-trip
	buf, err := json.MarshalIndent(jwkPriv, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal JWK: %s\n", err)
		return
	}

	parsed, err := jwk.ParseKey(buf)
	if err != nil {
		fmt.Printf("failed to parse JWK: %s\n", err)
		return
	}
	_ = parsed

	// Output:
	// Hello, Ed448!
	// Hello, Ed448!
}
