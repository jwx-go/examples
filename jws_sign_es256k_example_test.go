package examples_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	jwxes256k "github.com/jwx-go/es256k/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_sign_es256k() {
	// ES256K is the ECDSA signature algorithm using the secp256k1 curve
	// and SHA-256. It is widely used in blockchain ecosystems (Bitcoin,
	// Ethereum) but is not part of the core JWA standard — jwx provides
	// it as an opt-in extension via github.com/jwx-go/es256k/v4.
	//
	// Importing the package for side effects registers:
	//   - The "secp256k1" elliptic curve in jwa
	//   - The "ES256K" signature algorithm in jwa/jws
	//   - The curve-to-ECDSA mapping so jwk can handle secp256k1 keys
	//
	// After registration, secp256k1 keys work like any other ECDSA key
	// (P-256, P-384, etc.) throughout jwx.

	// Generate an ECDSA key on the secp256k1 curve. Because ES256K uses
	// standard ECDSA, key generation uses crypto/ecdsa with the secp256k1
	// curve from the dcrd library — there is no custom key type.
	privkey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader) //nolint:staticcheck
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}

	payload := []byte("Hello, secp256k1!")

	// Sign the payload with ES256K. jws.WithKey takes the algorithm
	// identifier and the raw *ecdsa.PrivateKey — no JWK wrapping needed.
	// The registered signer maps ES256K to the secp256k1+SHA-256 dsig
	// algorithm internally.
	signed, err := jws.Sign(payload, jws.WithKey(jwxes256k.ES256K(), privkey))
	if err != nil {
		fmt.Printf("failed to sign: %s\n", err)
		return
	}

	// Verification can use either a raw *ecdsa.PublicKey or a jwk.Key.
	// Here we demonstrate both approaches.

	// Approach 1: verify with the raw public key directly.
	verified, err := jws.Verify(signed, jws.WithKey(jwxes256k.ES256K(), &privkey.PublicKey))
	if err != nil {
		fmt.Printf("failed to verify with raw key: %s\n", err)
		return
	}
	fmt.Printf("%s\n", verified)

	// Approach 2: import the public key into a JWK first, then verify.
	// This is useful when distributing keys in JWK format — the resulting
	// JWK will have kty="EC" and crv="secp256k1", the same structure as
	// any other EC key.
	pubJWK, err := jwk.Import[jwk.Key](&privkey.PublicKey)
	if err != nil {
		fmt.Printf("failed to import public key: %s\n", err)
		return
	}

	verified, err = jws.Verify(signed, jws.WithKey(jwxes256k.ES256K(), pubJWK))
	if err != nil {
		fmt.Printf("failed to verify with JWK: %s\n", err)
		return
	}
	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// Hello, secp256k1!
	// Hello, secp256k1!
}
