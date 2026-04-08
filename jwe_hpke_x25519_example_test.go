package examples_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
)

func Example_jwe_hpke_x25519() {
	// HPKE-3-KE and HPKE-4-KE use DHKEM(X25519).
	// HPKE-3-KE pairs it with HKDF-SHA256 and AES-128-GCM.
	// HPKE-4-KE pairs it with HKDF-SHA256 and ChaCha20Poly1305.

	const payload = "Hello, X25519 HPKE!"

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}

	encrypted, err := jwe.Encrypt([]byte(payload),
		jwe.WithKey(jwa.HPKE_4_KE(), priv.PublicKey()),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		fmt.Printf("failed to encrypt: %s\n", err)
		return
	}

	decrypted, err := jwe.Decrypt(encrypted,
		jwe.WithKey(jwa.HPKE_4_KE(), priv),
	)
	if err != nil {
		fmt.Printf("failed to decrypt: %s\n", err)
		return
	}
	fmt.Printf("%s\n", decrypted)
	// OUTPUT:
	// Hello, X25519 HPKE!
}
