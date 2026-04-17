package examples_test

import (
	"encoding/json"
	"fmt"

	"filippo.io/mldsa"
	jwxmldsa "github.com/jwx-go/mldsa/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_mldsa_jwk() {
	// ML-DSA keys can be represented as JWK using the "AKP" (Algorithm Key Pair)
	// key type. Unlike traditional key types (RSA, EC) where the algorithm is
	// optional, AKP keys REQUIRE the "alg" field because the key type alone
	// does not determine the algorithm — the parameter set (ML-DSA-44/65/87)
	// must be specified explicitly.

	// Generate a raw ML-DSA-44 key pair using the filippo.io/mldsa package.
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		fmt.Printf("failed to generate ML-DSA key: %s\n", err)
		return
	}

	// jwk.Import converts the raw *mldsa.PrivateKey into a jwk.Key.
	// The mldsa package registers a key importer during init(), so jwx
	// knows how to handle *mldsa.PrivateKey without any extra setup.
	// The resulting JWK will have kty="AKP", alg="ML-DSA-44", and both
	// "pub" and "priv" fields populated.
	privJWK, err := jwk.Import[jwk.Key](sk)
	if err != nil {
		fmt.Printf("failed to import key to JWK: %s\n", err)
		return
	}

	fmt.Printf("kty: %s\n", privJWK.KeyType())

	alg, ok := privJWK.Algorithm()
	if !ok {
		fmt.Println("missing algorithm")
		return
	}
	fmt.Printf("alg: %s\n", alg)

	// JWK keys can be serialized to JSON for storage or transmission.
	// The JSON representation follows the AKP key format with base64url-encoded
	// "pub" (public key bytes) and "priv" (seed bytes) fields.
	serialized, err := json.Marshal(privJWK)
	if err != nil {
		fmt.Printf("failed to serialize JWK: %s\n", err)
		return
	}

	// Parse back from JSON. Because the mldsa package registered the ML-DSA
	// signature algorithms at init time, jwk.ParseKey can resolve "ML-DSA-44"
	// in the "alg" field and reconstruct the key correctly.
	parsed, err := jwk.ParseKey(serialized)
	if err != nil {
		fmt.Printf("failed to parse JWK: %s\n", err)
		return
	}

	// The parsed JWK key is fully functional — it can be used for signing
	// just like the original. This demonstrates that JWK serialization
	// round-trips correctly for ML-DSA keys.
	payload := []byte("round-trip test")
	signed, err := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA44(), parsed))
	if err != nil {
		fmt.Printf("failed to sign with parsed JWK: %s\n", err)
		return
	}

	// Derive the public JWK from the private JWK for verification.
	// PublicKey() strips the "priv" field, leaving only "pub".
	pubJWK, err := parsed.PublicKey()
	if err != nil {
		fmt.Printf("failed to derive public key: %s\n", err)
		return
	}

	verified, err := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA44(), pubJWK))
	if err != nil {
		fmt.Printf("failed to verify with public JWK: %s\n", err)
		return
	}

	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// kty: AKP
	// alg: ML-DSA-44
	// round-trip test
}
