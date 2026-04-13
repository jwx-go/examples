package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jws"

	// Importing compsig registers six post-quantum composite signature
	// algorithms with jwx. Each pairs ML-DSA (FIPS 204) with a traditional
	// signature scheme — ECDSA, Ed25519, or Ed448 — and a JWS verifies
	// only when both component signatures verify.
	compsig "github.com/jwx-go/compsig/v4"
)

func Example_compsig_sign_verify() {
	// Composite signatures are defined by draft-ietf-jose-pq-composite-sigs.
	// The motivation is hybrid security: an attacker would need to break
	// BOTH the post-quantum and the traditional component to forge a
	// signature, so the scheme remains secure as long as either family
	// stays unbroken.
	//
	// The six registered algorithms are:
	//   - MLDSA44ES256()    — ML-DSA-44 + ECDSA P-256 / SHA-256
	//   - MLDSA65ES256()    — ML-DSA-65 + ECDSA P-256 / SHA-256
	//   - MLDSA87ES384()    — ML-DSA-87 + ECDSA P-384 / SHA-384
	//   - MLDSA44Ed25519()  — ML-DSA-44 + Ed25519
	//   - MLDSA65Ed25519()  — ML-DSA-65 + Ed25519
	//   - MLDSA87Ed448()    — ML-DSA-87 + Ed448
	//
	// The JWK key type is "AKP" (Algorithm Key Pair), which carries the
	// concatenated component public keys and a 32-byte seed for the
	// private key. The "alg" field is REQUIRED on AKP keys because the
	// key type alone does not determine which composite variant to use.

	alg := compsig.MLDSA65ES256()

	// Generate a composite key pair. compsig.GenerateKey internally
	// generates both the ML-DSA-65 component (via filippo.io/mldsa) and
	// the ECDSA P-256 component (via stdlib crypto/ecdsa) and bundles
	// them into a single PrivateKey.
	sk, err := compsig.GenerateKey(alg)
	if err != nil {
		fmt.Printf("failed to generate composite key: %s\n", err)
		return
	}

	payload := []byte("Hello, hybrid post-quantum world!")

	// Sign with the composite private key. compsig's init() registers a
	// jws.Signer that, for each Sign call:
	//   1. Computes M' = Prefix || Label || 0x00 || PH(M)
	//   2. Signs M' with the ML-DSA component
	//   3. Signs M' with the traditional component (ECDSA-DER, not r||s)
	//   4. Concatenates the two signatures (ML-DSA first, fixed-size).
	signed, err := jws.Sign(payload, jws.WithKey(alg, sk))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}

	// Verify with the public key. Verification splits the composite
	// signature at the known ML-DSA boundary and checks each component
	// against M'. Both must verify; either failure rejects the signature.
	verified, err := jws.Verify(signed, jws.WithKey(alg, sk.Public()))
	if err != nil {
		fmt.Printf("failed to verify signature: %s\n", err)
		return
	}

	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// Hello, hybrid post-quantum world!
}
