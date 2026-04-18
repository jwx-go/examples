package examples_test

import (
	"bytes"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_sign_detached_reader() {
	// jws.WithDetachedPayloadReader is the streaming counterpart to
	// jws.WithDetachedPayload: the detached payload is consumed from an
	// io.Reader and fed directly through the signature algorithm's hash
	// without materializing the payload in memory. Use this when the
	// detached payload is too large to comfortably hold as a []byte
	// (uploads, archives, long-running request bodies, etc.).
	//
	// The streaming path has a few restrictions worth knowing up front:
	//   - Pass nil as the payload to jws.Sign — the option is the source
	//     of bytes, and WithDetachedPayload + WithDetachedPayloadReader
	//     are mutually exclusive.
	//   - Exactly one jws.WithKey() is required. Key sets, key providers,
	//     and multi-signature outputs are out of scope because the reader
	//     can only be consumed once.
	//   - EdDSA and "custom"-family algorithms (e.g. ML-DSA) need the
	//     full payload up front and are rejected. HS*/RS*/PS*/ES* work.
	//   - jws.WithInsecureNoSignature() is rejected — streaming implies
	//     there's a hash to feed, and "none" has none.
	//   - The base64 encoder must implement jws.Base64StreamEncoder. The
	//     default encoder does; a custom encoder installed via
	//     jwx.Settings may not.
	//   - Output is RFC 7515 compact by default; pass jws.WithJSON() for
	//     flattened single-signature JSON. In both forms the payload
	//     segment/member is omitted (RFC 7515 Appendix F).
	key, err := jwk.Import[jwk.Key]([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}

	// In real use this would be an *os.File, an HTTP request body, etc.
	// bytes.Reader is used here just so the example is self-contained.
	payload := []byte(`$.02`)

	serialized, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}

	// The result is a compact JWS with an empty payload segment
	// ("header..signature"). The caller is expected to transmit the
	// detached payload separately.
	fmt.Printf("%s\n", serialized)
	// OUTPUT:
	// eyJhbGciOiJIUzI1NiJ9..H14oXKwyvAsl0IbBLjw9tLxNIoYisuIyb_oDV4-30Vk
}
