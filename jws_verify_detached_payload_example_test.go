package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_verify_detached_payload() {
	serialized := `eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..lnRw_MSpQjARa5LWqPcu8Qls9p3wYGrC6tz4-nr0rkA`
	payload := `$.02`

	key, err := jwk.Import[jwk.Key]([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}

	// The serialized JWS sets b64=false (RFC 7797) and lists "b64" in
	// the "crit" header. Under v4's default-strict crit validation,
	// passing jws.WithDetachedPayload auto-declares the "b64"
	// extension on the caller's behalf — detached-payload verification
	// is the canonical pairing for b64=false and the jws package
	// implements it natively, so application code does not need to
	// pass jws.WithCritExtension("b64") explicitly.
	verified, err := jws.Verify([]byte(serialized),
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayload([]byte(payload)),
	)
	if err != nil {
		fmt.Printf("failed to verify payload: %s\n", err)
		return
	}

	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// $.02
}
