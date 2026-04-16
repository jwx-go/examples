package examples_test

import (
	"crypto/rand"
	"fmt"

	circlx448 "github.com/cloudflare/circl/dh/x448"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"

	x448mod "github.com/jwx-go/x448/v4"
)

func Example_jwe_encrypt_hpke6() {
	// HPKE-6-KE is the ChaCha20Poly1305 variant of X448 HPKE:
	//   - KEM:  DHKEM(X448, HKDF-SHA512)
	//   - KDF:  HKDF-SHA512
	//   - AEAD: ChaCha20Poly1305
	//
	// Compared to HPKE-5-KE (which uses AES-256-GCM), HPKE-6-KE is
	// preferable on platforms without AES hardware acceleration, where
	// ChaCha20Poly1305 is significantly faster in software. The security
	// level is comparable — both provide 256-bit key strength.

	// Generate an X448 key pair using cloudflare/circl.
	var seed circlx448.Key
	if _, err := rand.Read(seed[:]); err != nil {
		fmt.Printf("failed to generate random seed: %s\n", err)
		return
	}

	var pub circlx448.Key
	circlx448.KeyGen(&pub, &seed)

	// NewPrivateKey derives the public key from the seed, which avoids
	// constructing a JWK whose public and private halves disagree.
	privKey := x448mod.NewPrivateKey(seed)

	privJWK, err := jwk.Import[jwk.Key](privKey)
	if err != nil {
		fmt.Printf("failed to import private key: %s\n", err)
		return
	}

	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		fmt.Printf("failed to derive public key: %s\n", err)
		return
	}

	payload := []byte("Hello, HPKE-6-KE with ChaCha20!")

	// Encrypt using HPKE-6-KE. The only difference from HPKE-5-KE is
	// the AEAD used to encrypt the CEK — ChaCha20Poly1305 instead of
	// AES-256-GCM. The API is identical; the algorithm identifier
	// controls the internal AEAD selection.
	encrypted, err := jwe.Encrypt(payload,
		jwe.WithKey(x448mod.HPKE6(), pubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		fmt.Printf("failed to encrypt: %s\n", err)
		return
	}

	decrypted, err := jwe.Decrypt(encrypted,
		jwe.WithKey(x448mod.HPKE6(), privJWK),
	)
	if err != nil {
		fmt.Printf("failed to decrypt: %s\n", err)
		return
	}

	fmt.Printf("%s\n", decrypted)
	// OUTPUT:
	// Hello, HPKE-6-KE with ChaCha20!
}
