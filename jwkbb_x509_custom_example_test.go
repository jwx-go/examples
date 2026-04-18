package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwk/jwkbb"
)

// MyKey is a stand-in for a custom key type — for example, a PQC
// private key shipped by an extension module. Using a plain wrapper
// around *rsa.PrivateKey keeps the example runnable without pulling in
// a real PQC library; the mechanics of registering a custom decoder
// and encoder are identical regardless of the underlying cryptography.
type MyKey struct {
	Priv *rsa.PrivateKey
}

// The PEM block type string under which MyKey instances travel. In a
// real extension module this would reflect the format you're actually
// serializing — e.g. "ML-DSA-44 PRIVATE KEY" for an ML-DSA extension.
const myKeyBlockType = "MYPKG PRIVATE KEY"

func Example_jwkbb_x509_custom_decoder_and_encoder() {
	// Register an encoder for *MyKey. jwkbb.EncodePEM dispatches by
	// the runtime Go type of each input, so registering for *MyKey
	// means any *MyKey value fed into EncodePEM will be routed here.
	// The block type we emit must match what our decoder expects to
	// see on the way back in.
	if err := jwkbb.RegisterX509Encoder[*MyKey](jwkbb.X509EncodeFunc[*MyKey](func(v *MyKey) (string, []byte, error) {
		// The DER payload format is up to us — here we just reuse
		// PKCS#1 as a convenient stand-in. A real PQC encoder would
		// marshal its own wire format.
		return myKeyBlockType, x509.MarshalPKCS1PrivateKey(v.Priv), nil
	})); err != nil {
		fmt.Printf("failed to register encoder: %s\n", err)
		return
	}

	// Register a decoder for the same block type. jwkbb dispatches by
	// block.Type, so the decoder body never needs to self-check
	// block.Type — it only runs for MYPKG PRIVATE KEY blocks. The
	// decoder's return type (*MyKey here) is captured statically via
	// the type parameter and surfaces through jwkbb.DecodeX509 as the
	// raw value handed to jwk's importer pipeline.
	if err := jwkbb.RegisterX509Decoder[*MyKey](myKeyBlockType, jwkbb.X509DecodeFunc[*MyKey](func(block *pem.Block) (*MyKey, error) {
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &MyKey{Priv: priv}, nil
	})); err != nil {
		fmt.Printf("failed to register decoder: %s\n", err)
		return
	}

	// Teach jwk how to import *MyKey values into the JWK world. Without
	// this, jwk.ParseKey would successfully invoke our decoder but then
	// fail to wrap the raw *MyKey in a jwk.Key. A real extension ships
	// its own importer alongside the X509 registration.
	if err := jwk.RegisterKeyImporter(func(k *MyKey) (jwk.Key, error) {
		return jwk.Import[jwk.Key](k.Priv)
	}); err != nil {
		fmt.Printf("failed to register importer: %s\n", err)
		return
	}

	// Build a fresh MyKey and round-trip it: raw → PEM → jwk.Key.
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}

	pemBytes, err := jwkbb.EncodePEM(&MyKey{Priv: raw})
	if err != nil {
		fmt.Printf("failed to encode PEM: %s\n", err)
		return
	}

	// Confirm the registered encoder actually owned the emission.
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != myKeyBlockType {
		fmt.Printf("unexpected block: %v\n", block)
		return
	}

	// Parse the PEM back through jwk. WithX509(true) tells jwk to
	// treat the input as PEM-framed X.509 and route each block to
	// jwkbb.DecodeX509 — which, for our custom block type, hits the
	// decoder we registered above.
	key, err := jwk.ParseKey(pemBytes, jwk.WithX509(true))
	if err != nil {
		fmt.Printf("failed to parse: %s\n", err)
		return
	}

	fmt.Printf("round-trip: block=%s, key=%T\n", block.Type, key)
	// OUTPUT:
	// round-trip: block=MYPKG PRIVATE KEY, key=*jwk.rsaPrivateKey
}

