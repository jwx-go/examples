package examples_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// ExternalSigner mimics what a cloud KMS crypto.Signer looks like.
// In a real application, this would be replaced by a KMS-backed signer
// such as gcpkms.NewSigner() from github.com/sethvargo/go-gcpkms.
// The key insight is that any object implementing crypto.Signer can be
// passed directly to jws.WithKey().
type ExternalSigner struct {
	privkey *ecdsa.PrivateKey
}

// Public returns the public key corresponding to the opaque private key.
// This method is part of the crypto.Signer interface.
func (s *ExternalSigner) Public() crypto.PublicKey {
	return s.privkey.Public()
}

// Sign signs digest with the private key.
// This method is part of the crypto.Signer interface.
func (s *ExternalSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.privkey.Sign(rand, digest, opts)
}

func Example_jws_sign_crypto_signer() {
	// github.com/lestrrat-go/jwx/v4 supports the standard crypto.Signer
	// interface, which makes it possible to sign JWS messages using cloud
	// KMS services without ever exposing private key material to your
	// application.
	//
	// Cloud KMS libraries that provide crypto.Signer implementations:
	//   - GCP KMS: github.com/sethvargo/go-gcpkms
	//   - AWS KMS: github.com/tprasadtp/cryptokms
	//
	// In production, you would create a signer like:
	//
	//   kmsClient, _ := kms.NewKeyManagementClient(ctx)
	//   signer, _ := gcpkms.NewSigner(ctx, kmsClient,
	//       "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
	//
	// Here we use a local dummy signer to demonstrate the pattern.

	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}
	signer := &ExternalSigner{privkey: privkey}

	payload := []byte("Hello from crypto.Signer!")

	// Pass the crypto.Signer directly to jws.WithKey(). The library
	// inspects signer.Public() to determine the underlying key type and
	// dispatches to the appropriate signing implementation, which in turn
	// calls signer.Sign(). The algorithm (ES256 for P-256, RS256 for RSA,
	// etc.) must match the key type backing the signer.
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), signer))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}

	// For verification, extract the public key via signer.Public().
	// In production, you might distribute this public key separately
	// or fetch it from KMS.
	verified, err := jws.Verify(signed, jws.WithKey(jwa.ES256(), signer.Public()))
	if err != nil {
		fmt.Printf("failed to verify signature: %s\n", err)
		return
	}

	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// Hello from crypto.Signer!
}
