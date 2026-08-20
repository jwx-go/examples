package examples_test

import (
	"fmt"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_mldsa_export() {
	// jwk.Export converts a jwk.Key back to a raw key type. For ML-DSA keys,
	// this returns *mldsa.PrivateKey or *mldsa.PublicKey depending on whether
	// the JWK contains the "priv" field.
	//
	// This is useful when you receive an ML-DSA key in JWK format (e.g., from
	// a JWKS endpoint or configuration file) and need the raw key for operations
	// outside of jwx.

	// Generate an ML-DSA-87 key pair — the highest security level (NIST Level 5).
	sk, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		fmt.Printf("failed to generate ML-DSA key: %s\n", err)
		return
	}

	// Import the raw key into JWK format.
	privJWK, err := jwk.Import[jwk.Key](sk)
	if err != nil {
		fmt.Printf("failed to import key: %s\n", err)
		return
	}

	// Export back to a raw key, naming the type you want. The exporter
	// reconstructs the key from the stored seed ("priv" field) and verifies
	// that the derived public key matches the "pub" field.
	exportedSK, err := jwk.Export[*mldsa.PrivateKey](privJWK)
	if err != nil {
		fmt.Printf("failed to export key: %s\n", err)
		return
	}

	// The exported key is identical to the original — the import/export
	// cycle is lossless.
	fmt.Printf("key type: %s\n", jwa.AKP())
	fmt.Printf("keys match: %t\n", sk.Equal(exportedSK))
	// OUTPUT:
	// key type: AKP
	// keys match: true
}
