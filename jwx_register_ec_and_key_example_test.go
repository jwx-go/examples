package examples_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	ourecdsa "github.com/lestrrat-go/jwx/v4/jwk/ecdsa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// Setup. This is something that you probably should do in your adapter
// library, or in your application's init() function.
//
// I could not readily find what the exact curve notation is for ShangMi SM2
// (either I'm just bad at researching or it's not in an RFC as of this writing)
// so I'm faking it as "SM2".
//
// For demonstration purposes, it could as well be a random string, as long
// as its consistent in your usage.
var SM2 = jwa.NewEllipticCurveAlgorithm("SM2")

func init() {
	// Every jwx Register* function returns error. The current
	// implementations always return nil, but the error return is
	// reserved for future validation (duplicate detection, etc.).
	// Extension init() code should panic on failure — a registration
	// that silently fails would leave the extension half-wired in
	// ways that only surface at call time.
	panicOnRegistrationError := func(err error) {
		if err != nil {
			panic(fmt.Sprintf("sm2 example: registration failed: %s", err))
		}
	}

	// Register the algorithm name so it can be looked up
	panicOnRegistrationError(jwa.RegisterEllipticCurveAlgorithm(SM2))

	// Register the actual ECDSA curve. Notice that we need to tell this
	// to our jwk library, so that the JWK lookup can be done properly
	// when a raw SM2 key is passed to various key operations.
	//
	// jwk/ecdsa.RegisterCurve requires a PointValidator; we use
	// sm2.NewPublicKey as the non-deprecated equivalent of the old
	// elliptic.Curve.IsOnCurve fallback. NewPublicKey takes an
	// uncompressed SEC1 encoding, rejects compressed forms and the
	// point at infinity, and performs on-curve validation via the
	// library's constant-time path.
	sm2PointValidator := ourecdsa.PointValidatorFunc(func(x, y *big.Int) error {
		const coordSize = 32
		buf := make([]byte, 1+2*coordSize)
		buf[0] = 0x04
		x.FillBytes(buf[1 : 1+coordSize])
		y.FillBytes(buf[1+coordSize:])
		if _, err := sm2.NewPublicKey(buf); err != nil {
			return fmt.Errorf("invalid SM2 public key: %w", err)
		}
		return nil
	})
	panicOnRegistrationError(ourecdsa.RegisterCurve(SM2, sm2.P256(), sm2PointValidator))

	// We only need one converter for the private key, because the public key
	// is exactly the same type as *ecdsa.PublicKey
	panicOnRegistrationError(jwk.RegisterKeyImporter(jwk.KeyImportFunc[*sm2.PrivateKey](convertShangMiSm2)))

	panicOnRegistrationError(jwk.RegisterKeyExporter(jwk.KeyKind(jwa.EC().String()), jwk.KeyExportFunc(convertJWKToShangMiSm2)))
}

func convertShangMiSm2(key *sm2.PrivateKey) (jwk.Key, error) {
	return jwk.Import[jwk.Key](key.PrivateKey)
}

func convertJWKToShangMiSm2(key jwk.Key, hint any) (any, error) {
	// If the caller specifically wants *ecdsa.PrivateKey (e.g. JWS signing),
	// let the default ECDSA exporter handle it so the embedded ecdsa key is returned.
	switch hint.(type) {
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return nil, fmt.Errorf(`SM2 exporter: caller wants %T, deferring to default exporter: %w`, hint, jwk.ContinueError())
	}

	ecdsaKey, ok := key.(jwk.ECDSAPrivateKey)
	if !ok {
		return nil, fmt.Errorf(`invalid key type %T: %w`, key, jwk.ContinueError())
	}
	if v, ok := ecdsaKey.Crv(); !ok || v != SM2 {
		return nil, fmt.Errorf(`cannot convert curve of type %s to ShangMi key: %w`, v, jwk.ContinueError())
	}

	d, ok := ecdsaKey.D()
	if !ok {
		return nil, fmt.Errorf(`missing D field in ECDSA private key: %w`, jwk.ContinueError())
	}
	ret, err := sm2.NewPrivateKey(d)
	if err != nil {
		return nil, fmt.Errorf(`failed to create SM2 private key: %w`, err)
	}
	return ret, nil
}

// End setup

func Example_shang_mi_sm2() {
	shangmi2pk, _ := sm2.GenerateKey(rand.Reader)

	// Create a jwk.Key from ShangMi SM2 private key
	shangmi2JWK, err := jwk.Import[jwk.Key](shangmi2pk)
	if err != nil {
		fmt.Printf("failed to create jwk.Key from raw ShangMi private key: %s\n", err)
		return
	}

	{
		// Create a ShangMi SM2 private key back from the jwk.Key
		clone, err := jwk.Export[*sm2.PrivateKey](shangmi2JWK)
		if err != nil {
			fmt.Printf("failed to create ShangMi private key from jwk.Key: %s\n", err)
			return
		}

		// Clone should be equal to the original key
		if !clone.Equal(shangmi2pk) {
			fmt.Println("keys do not match")
			return
		}
	}

	{ // Can do the same thing for any
		clone, err := jwk.Export[any](shangmi2JWK)
		if err != nil {
			fmt.Printf("failed to create ShangMi private key from jwk.Key (via any): %s\n", err)
			return
		}
		_ = clone
	}

	{
		// Of course, ecdsa.PrivateKeys are also supported separately
		ecprivkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Println(err)
			return
		}
		eckjwk, err := jwk.Import[jwk.Key](ecprivkey)
		if err != nil {
			fmt.Printf("failed to create jwk.Key from raw ShangMi public key: %s\n", err)
			return
		}
		cloneV2, err := jwk.Export[any](eckjwk)
		if err != nil {
			fmt.Printf("failed to create ShangMi public key from jwk.Key: %s\n", err)
			return
		}
		_ = cloneV2
	}

	payload := []byte("Lorem ipsum")
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), shangmi2JWK))
	if err != nil {
		fmt.Printf("Failed to sign using ShangMi key: %s\n", err)
		return
	}

	shangmi2PubJWK, err := jwk.PublicKeyOf(shangmi2JWK)
	if err != nil {
		fmt.Printf("Failed to create public JWK using ShangMi key: %s\n", err)
		return
	}

	verified, err := jws.Verify(signed, jws.WithKey(jwa.ES256(), shangmi2PubJWK))
	if err != nil {
		fmt.Printf("Failed to verify using ShangMi key: %s\n", err)
		return
	}

	if !bytes.Equal(payload, verified) {
		fmt.Println("payload does not match")
		return
	}
	//OUTPUT:
}
