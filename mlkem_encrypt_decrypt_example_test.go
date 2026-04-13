package examples_test

import (
	"crypto/mlkem"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"

	// Importing mlkem registers ML-KEM-768/1024 (with and without AES key
	// wrap) as JWE key encryption algorithms. Without this import, jwx
	// does not know how to dispatch ML-KEM during jwe.Encrypt/Decrypt.
	jwxmlkem "github.com/jwx-go/mlkem/v4"
)

func Example_mlkem_encrypt_decrypt() {
	// ML-KEM is a post-quantum key encapsulation mechanism standardized
	// in FIPS 203. The JOSE binding (draft-ietf-jose-pqc-kem) defines
	// four key encryption algorithms:
	//
	//   - ML-KEM-768          (direct mode, NIST Level 3)
	//   - ML-KEM-1024         (direct mode, NIST Level 5)
	//   - ML-KEM-768+A192KW   (key wrap mode, NIST Level 3)
	//   - ML-KEM-1024+A256KW  (key wrap mode, NIST Level 5)
	//
	// In direct mode, the ML-KEM shared secret is fed through KMAC256 to
	// derive the CEK directly. In key-wrap mode, ML-KEM derives an AES
	// wrap key, which then wraps a freshly-generated CEK. Direct mode
	// is simpler; key-wrap mode allows multi-recipient JWEs.
	//
	// This example uses ML-KEM-768 in direct mode.

	// Generate an ML-KEM-768 decapsulation (private) key. The encapsulation
	// (public) key is derived from it.
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		fmt.Printf("failed to generate ML-KEM key: %s\n", err)
		return
	}
	ek := dk.EncapsulationKey()

	payload := []byte("Hello, post-quantum encryption!")

	// Encrypt with the encapsulation key. The mlkem package registers
	// raw *mlkem.EncapsulationKey768 as a valid jwe.WithKey input via its
	// init(), so no JWK conversion is required for this simple case.
	encrypted, err := jwe.Encrypt(payload,
		jwe.WithKey(jwxmlkem.MLKEM768(), ek),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		fmt.Printf("failed to encrypt: %s\n", err)
		return
	}

	// Decrypt with the decapsulation key. The mlkem package handles
	// extracting the encapsulated KEM ciphertext from the JWE and running
	// the ML-KEM decapsulation + KMAC256 KDF to recover the CEK.
	decrypted, err := jwe.Decrypt(encrypted,
		jwe.WithKey(jwxmlkem.MLKEM768(), dk),
	)
	if err != nil {
		fmt.Printf("failed to decrypt: %s\n", err)
		return
	}

	fmt.Printf("%s\n", decrypted)
	// OUTPUT:
	// Hello, post-quantum encryption!
}
