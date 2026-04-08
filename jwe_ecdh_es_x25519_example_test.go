package examples_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwe_ecdh_es_x25519() {
	// X25519 keys work with the standard ECDH-ES family of algorithms
	// (ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW) the
	// same way NIST curves do.
	//
	// Use *ecdh.PublicKey / *ecdh.PrivateKey from crypto/ecdh with the
	// X25519 curve. JWK keys are also accepted.

	const payload = "Hello, X25519 ECDH-ES!"

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}

	// Encrypt with ECDH-ES+A256KW
	encrypted, err := jwe.Encrypt([]byte(payload),
		jwe.WithKey(jwa.ECDH_ES_A256KW(), priv.PublicKey()),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		fmt.Printf("failed to encrypt: %s\n", err)
		return
	}

	decrypted, err := jwe.Decrypt(encrypted,
		jwe.WithKey(jwa.ECDH_ES_A256KW(), priv),
	)
	if err != nil {
		fmt.Printf("failed to decrypt: %s\n", err)
		return
	}
	fmt.Printf("%s\n", decrypted)

	// X25519 keys are represented as OKP keys with crv=X25519 in JWK
	privJWK, err := jwk.Import[jwk.Key](priv)
	if err != nil {
		fmt.Printf("failed to import key: %s\n", err)
		return
	}
	fmt.Printf("kty=%s\n", privJWK.KeyType())

	// OUTPUT:
	// Hello, X25519 ECDH-ES!
	// kty=OKP
}
