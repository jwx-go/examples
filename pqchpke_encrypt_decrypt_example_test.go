package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"

	// Importing reddy-pqchpke registers the hybrid PQ HPKE-10-KE and
	// HPKE-11-KE key encryption algorithms with jwx. These pair X25519
	// with ML-KEM-768 via the X-Wing KEM, providing security as long as
	// either component remains unbroken.
	pqchpke "github.com/jwx-go/reddy-pqchpke/v4"
)

func Example_pqchpke_encrypt_decrypt() {
	// HPKE-10-KE and HPKE-11-KE are hybrid post-quantum HPKE ciphersuites
	// from draft-reddy-cose-jose-pqc-hybrid-hpke. They use the X-Wing KEM
	// (X25519 + ML-KEM-768) as the HPKE KEM, SHAKE256 as the HPKE KDF,
	// and either AES-256-GCM (HPKE-10) or ChaCha20-Poly1305 (HPKE-11) as
	// the AEAD inside the HPKE construction. The "-KE" suffix means Key
	// Encryption: HPKE encrypts the CEK, and the CEK then encrypts the
	// payload using the JWE content encryption algorithm.
	//
	// Note: the underlying draft is an individual submission, not yet
	// WG-adopted. Wire formats and algorithm identifiers may change.

	// Generate a hybrid key pair. The 32-byte seed inside the private key
	// deterministically derives both the X25519 component and the
	// ML-KEM-768 component via X-Wing's ExpandDecapsulationKey.
	sk, err := pqchpke.GenerateKey()
	if err != nil {
		fmt.Printf("failed to generate hybrid key: %s\n", err)
		return
	}
	pk := sk.Public()

	payload := []byte("Hello, hybrid post-quantum HPKE!")

	// Encrypt with the hybrid public key. jwe.Encrypt dispatches to
	// HybridPublicKey.EncryptHPKE because pqchpke registers HPKE-10-KE as
	// an HPKE algorithm in its init().
	encrypted, err := jwe.Encrypt(payload,
		jwe.WithKey(pqchpke.HPKE10(), pk),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		fmt.Printf("failed to encrypt: %s\n", err)
		return
	}

	// Decrypt with the hybrid private key. jwe.Decrypt dispatches to
	// HybridPrivateKey.DecryptHPKE, which runs both the X25519 and the
	// ML-KEM-768 decapsulation and combines the shared secrets per the
	// X-Wing construction.
	decrypted, err := jwe.Decrypt(encrypted,
		jwe.WithKey(pqchpke.HPKE10(), sk),
	)
	if err != nil {
		fmt.Printf("failed to decrypt: %s\n", err)
		return
	}

	fmt.Printf("%s\n", decrypted)
	// OUTPUT:
	// Hello, hybrid post-quantum HPKE!
}
