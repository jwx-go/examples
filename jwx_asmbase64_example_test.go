package examples_test

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"

	// Importing asmbase64 for its side effects replaces jwx's default
	// encoding/base64 implementation with github.com/segmentio/asm/base64,
	// an assembly-optimized base64 codec. This is a global, one-time swap:
	// the init() function calls jwx.Settings with jwx.WithBase64Encoder
	// and jwx.WithBase64Decoder, so every subsequent jwx operation (JWK
	// serialization, JWS compact encoding, JWT parsing, etc.) automatically
	// uses the faster backend.
	//
	// No code changes are needed beyond this import — the jwx API is
	// identical. This makes it safe to add or remove without touching
	// any other code.
	_ "github.com/jwx-go/asmbase64/v4"
)

func Example_jwx_asmbase64() {
	// With the asm base64 backend active (via the blank import above),
	// all jwx operations that encode/decode base64 benefit automatically.
	// This example demonstrates a JWK JSON round-trip to show that the
	// base64 swap is transparent.

	// Import a known symmetric key. The raw bytes will be base64url-encoded
	// when the JWK is serialized to JSON — this is where the asmbase64
	// backend kicks in, replacing the standard library's base64 encoder
	// with the assembly-optimized one from segmentio/asm.
	key, err := jwk.Import[jwk.Key]([]byte("my-secret-key-for-demo"))
	if err != nil {
		fmt.Printf("failed to import key: %s\n", err)
		return
	}

	// Serialize the JWK to JSON. The "k" field in the output is the
	// base64url-encoded form of the raw key bytes. This encoding step
	// is exactly where the asm base64 backend is used instead of
	// encoding/base64.RawURLEncoding from the standard library.
	serialized, err := json.Marshal(key)
	if err != nil {
		fmt.Printf("failed to marshal JWK: %s\n", err)
		return
	}
	fmt.Printf("serialized: %s\n", serialized)

	// Parse the JSON back into a JWK. The decoder side of asmbase64 is
	// exercised here — it decodes the base64url "k" field back to raw
	// bytes. If the asm decoder produced different output than the
	// standard library, the round-trip would fail.
	parsed, err := jwk.ParseKey[jwk.Key](serialized)
	if err != nil {
		fmt.Printf("failed to parse JWK: %s\n", err)
		return
	}

	// Confirm the decoded key bytes match the original. The "k" field
	// was encoded by the asm encoder and decoded by the asm decoder —
	// both paths must agree for the round-trip to succeed.
	origK, _ := key.Field("k")
	parsedK, _ := parsed.Field("k")
	fmt.Printf("round-trip ok: %t\n", string(origK.([]byte)) == string(parsedK.([]byte)))
	// OUTPUT:
	// serialized: {"k":"bXktc2VjcmV0LWtleS1mb3ItZGVtbw","kty":"oct"}
	// round-trip ok: true
}
