package examples_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_ParseFS() {
	f, err := os.CreateTemp(``, `jwt_parsefs-*.jws`)
	if err != nil {
		fmt.Printf("failed to create temporary file: %s\n", err)
		return
	}
	defer os.Remove(f.Name())

	fmt.Fprint(f, exampleJWTSignedHMAC)
	f.Close()

	// This example calls ParseFS with both jwt.WithVerify(false) and
	// jwt.WithValidate(false) only because there is no key context
	// here — it demonstrates the FS-loading mechanics, nothing more.
	// Production code reading a JWT from any source MUST pass
	// jwt.WithKey() / jwt.WithKeySet() and MUST NOT disable
	// jwt.WithValidate. The library exposes jwt.ParseInsecure for the
	// inspect-without-verifying path when consuming raw bytes
	// directly; ParseFS has no corresponding ParseFSInsecure today,
	// so the two-option chant is the explicit way to express the
	// same intent here.
	tok, err := jwt.ParseFS(os.DirFS(filepath.Dir(f.Name())), filepath.Base(f.Name()), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		fmt.Printf("failed to read file %q: %s\n", f.Name(), err)
		return
	}
	_ = tok
	// OUTPUT:
}
