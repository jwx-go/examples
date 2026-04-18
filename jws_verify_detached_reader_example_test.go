package examples_test

import (
	"bytes"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_verify_detached_reader() {
	// jws.WithDetachedPayloadReader on the verify side is the streaming
	// counterpart to jws.WithDetachedPayload. The JWS itself (compact or
	// flattened JSON) is still passed as []byte since it is small by
	// design; only the detached payload — which may be arbitrarily large
	// — is streamed from an io.Reader.
	//
	// Restrictions mirror the sign path:
	//   - Exactly one jws.WithKey() is required. jws.WithKeySet(),
	//     jws.WithKeyProvider(), and jws.WithVerifyAuto() are rejected
	//     because the reader can only be consumed once.
	//   - Only single-signature JWS messages are accepted.
	//   - EdDSA and "custom"-family algorithms need the full payload up
	//     front and are rejected. HS*/RS*/PS*/ES* work.
	//   - The base64 encoder must implement jws.Base64StreamEncoder.
	//
	// On verification failure the reader cannot be rewound — callers
	// that need retry semantics should either buffer the payload
	// themselves or use jws.Verify with jws.WithDetachedPayload.
	serialized := []byte(`eyJhbGciOiJIUzI1NiJ9..H14oXKwyvAsl0IbBLjw9tLxNIoYisuIyb_oDV4-30Vk`)
	payload := []byte(`$.02`)

	key, err := jwk.Import[jwk.Key]([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}

	if _, err := jws.Verify(serialized,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	); err != nil {
		fmt.Printf("failed to verify: %s\n", err)
		return
	}

	fmt.Println("verified")
	// OUTPUT:
	// verified
}
