//go:build go1.27

package examples_test

import (
	"crypto/mldsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_mldsa_sign_verify() {
	// ML-DSA is a post-quantum digital signature scheme (FIPS 204). On Go
	// 1.27 it comes from the standard library's crypto/mldsa, which jwx
	// supports natively: no extension module, no side-effect import, and
	// nothing to register.

	// Generate an ML-DSA-65 key pair. ML-DSA comes in three parameter sets:
	//   - ML-DSA-44 (NIST Level 2, smallest/fastest)
	//   - ML-DSA-65 (NIST Level 3, balanced)
	//   - ML-DSA-87 (NIST Level 5, highest security)
	// Each parameter set determines the key and signature sizes.
	// GenerateKey takes a crypto/mldsa.Parameters to select the variant.
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		fmt.Printf("failed to generate ML-DSA key: %s\n", err)
		return
	}

	payload := []byte("Hello, post-quantum world!")

	// jws.Sign accepts a raw *crypto/mldsa.PrivateKey directly. The
	// algorithm must match the key's parameter set; a mismatched algorithm,
	// such as MLDSA44() with an ML-DSA-65 key, is rejected.
	signed, err := jws.Sign(payload, jws.WithKey(jwa.MLDSA65(), sk))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}

	// Verification uses the public key extracted from the private key via
	// PublicKey(). Like signing, a raw *crypto/mldsa.PublicKey is accepted
	// directly.
	// You could also pass the private key itself — the verifier extracts
	// the public key internally.
	verified, err := jws.Verify(signed, jws.WithKey(jwa.MLDSA65(), sk.PublicKey()))
	if err != nil {
		fmt.Printf("failed to verify signature: %s\n", err)
		return
	}

	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// Hello, post-quantum world!
}
