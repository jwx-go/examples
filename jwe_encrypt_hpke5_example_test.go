package examples_test

import (
	"crypto/rand"
	"fmt"

	circlx448 "github.com/cloudflare/circl/dh/x448"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"

	// Importing x448 registers X448 key support, ECDH-ES key agreement,
	// and HPKE algorithms (HPKE-5-KE, HPKE-6-KE) with jwx. Without this
	// import, jwx does not know how to handle OKP keys with curve "X448"
	// or the HPKE key encryption algorithms.
	x448mod "github.com/jwx-go/x448/v4"
)

func Example_jwe_encrypt_hpke5() {
	// HPKE (Hybrid Public Key Encryption) is a modern key encapsulation
	// mechanism defined in RFC 9180, adapted for JOSE in
	// draft-ietf-jose-hpke-encrypt. It replaces traditional key wrapping
	// (e.g., RSA-OAEP, ECDH-ES+A256KW) with a KEM/KDF/AEAD triple.
	//
	// HPKE-5-KE uses:
	//   - KEM:  DHKEM(X448, HKDF-SHA512)
	//   - KDF:  HKDF-SHA512
	//   - AEAD: AES-256-GCM
	//
	// The "-KE" suffix indicates Key Encryption mode, where HPKE encrypts
	// the Content Encryption Key (CEK) rather than the payload directly.
	// The CEK then encrypts the actual payload using the content encryption
	// algorithm (e.g., A256GCM).

	// Generate an X448 key pair. X448 is a Diffie-Hellman function on
	// Curve448 — it provides ~224-bit security, stronger than X25519's
	// ~128-bit level. Key generation uses cloudflare/circl because Go's
	// standard library does not include X448.
	var seed circlx448.Key
	if _, err := rand.Read(seed[:]); err != nil {
		fmt.Printf("failed to generate random seed: %s\n", err)
		return
	}

	var pub circlx448.Key
	circlx448.KeyGen(&pub, &seed)

	// Wrap the raw X448 key pair into the x448mod types that implement
	// jwx's key agreement interfaces. NewPrivateKey takes the seed (private
	// scalar) and the corresponding public key.
	privKey := x448mod.NewPrivateKey(seed, pub)

	// Import to JWK. The resulting key has kty="OKP" and crv="X448".
	// We need a JWK because jwe.Encrypt/Decrypt work with JWK keys
	// to embed the ephemeral public key in the JWE header.
	privJWK, err := jwk.Import[jwk.Key](privKey)
	if err != nil {
		fmt.Printf("failed to import private key: %s\n", err)
		return
	}

	// Derive the public JWK for encryption. In HPKE, the sender only
	// needs the recipient's public key — the KEM generates an ephemeral
	// key pair internally and includes the encapsulated key in the output.
	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		fmt.Printf("failed to derive public key: %s\n", err)
		return
	}

	payload := []byte("Hello, HPKE with X448!")

	// Encrypt using HPKE-5-KE. The key encryption algorithm (HPKE-5-KE)
	// encapsulates the CEK using DHKEM(X448) + AES-256-GCM, while the
	// content encryption algorithm (A256GCM) encrypts the payload with
	// the CEK. These are independent choices — you can pair any HPKE
	// algorithm with any content encryption algorithm.
	encrypted, err := jwe.Encrypt(payload,
		jwe.WithKey(x448mod.HPKE5(), pubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		fmt.Printf("failed to encrypt: %s\n", err)
		return
	}

	// Decrypt using the private JWK. The recipient uses their private key
	// to decapsulate the CEK from the HPKE ciphertext, then decrypts the
	// payload with the recovered CEK.
	decrypted, err := jwe.Decrypt(encrypted,
		jwe.WithKey(x448mod.HPKE5(), privJWK),
	)
	if err != nil {
		fmt.Printf("failed to decrypt: %s\n", err)
		return
	}

	fmt.Printf("%s\n", decrypted)
	// OUTPUT:
	// Hello, HPKE with X448!
}
