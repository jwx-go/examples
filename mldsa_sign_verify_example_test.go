package examples_test

import (
	"fmt"

	"filippo.io/mldsa"
	jwxmldsa "github.com/jwx-go/mldsa/v4"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_mldsa_sign_verify() {
	// ML-DSA is a post-quantum digital signature scheme (FIPS 204).
	// To use it with jwx, import github.com/jwx-go/mldsa/v4 for its
	// side effects — the init() function registers ML-DSA algorithms,
	// key importers/exporters, and JWS signers/verifiers automatically.

	// Generate an ML-DSA-65 key pair. ML-DSA comes in three parameter sets:
	//   - ML-DSA-44 (NIST Level 2, smallest/fastest)
	//   - ML-DSA-65 (NIST Level 3, balanced)
	//   - ML-DSA-87 (NIST Level 5, highest security)
	// Each parameter set determines the key and signature sizes.
	// mldsa.GenerateKey takes a *mldsa.Parameters to select the variant.
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		fmt.Printf("failed to generate ML-DSA key: %s\n", err)
		return
	}

	payload := []byte("Hello, post-quantum world!")

	// jws.Sign accepts raw *mldsa.PrivateKey directly — the mldsa package's
	// init() registers a JWS signer that handles the conversion internally.
	// The algorithm (jwxmldsa.MLDSA65()) must match the key's parameter set;
	// using a mismatched algorithm (e.g., MLDSA44() with an ML-DSA-65 key)
	// will fail.
	signed, err := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA65(), sk))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}

	// Verification uses the public key extracted from the private key via
	// PublicKey(). Like signing, raw *mldsa.PublicKey is accepted directly.
	// You could also pass the private key itself — the verifier extracts
	// the public key internally.
	verified, err := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA65(), sk.PublicKey()))
	if err != nil {
		fmt.Printf("failed to verify signature: %s\n", err)
		return
	}

	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// Hello, post-quantum world!
}
