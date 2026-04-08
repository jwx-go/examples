package examples_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
)

func Example_jwe_hpke() {
	// HPKE (Hybrid Public Key Encryption) combines KEM, KDF, and AEAD
	// in a single operation. jwx v4 supports six built-in ciphersuites
	// based on draft-ietf-jose-hpke-encrypt.
	//
	// HPKE-0-KE through HPKE-4-KE and HPKE-7-KE are available via
	// jwa.HPKE_0_KE(), jwa.HPKE_1_KE(), etc.
	//
	// The API is identical to any other JWE key encryption algorithm.
	// Pass an *ecdh.PublicKey for encryption, *ecdh.PrivateKey for
	// decryption. *ecdsa.PublicKey / *ecdsa.PrivateKey also work for
	// the NIST curve variants.

	const payload = "Hello, HPKE!"

	// HPKE-0-KE uses DHKEM(P-256), HKDF-SHA256, AES-128-GCM
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}

	encrypted, err := jwe.Encrypt([]byte(payload),
		jwe.WithKey(jwa.HPKE_0_KE(), priv.PublicKey()),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		fmt.Printf("failed to encrypt: %s\n", err)
		return
	}

	decrypted, err := jwe.Decrypt(encrypted,
		jwe.WithKey(jwa.HPKE_0_KE(), priv),
	)
	if err != nil {
		fmt.Printf("failed to decrypt: %s\n", err)
		return
	}
	fmt.Printf("%s\n", decrypted)
	// OUTPUT:
	// Hello, HPKE!
}
