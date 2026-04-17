package examples_test

import (
	"fmt"

	"github.com/jwx-go/jwxfilter/v4/jwsfilter"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_header_filter_basic() {
	key, err := jwk.Import[jwk.Key]([]byte(`my-secret-key`))
	if err != nil {
		fmt.Printf("failed to create key: %s\n", err)
		return
	}

	// Build JWS headers with both RFC 7515 standard fields and custom ones.
	headers := jws.NewHeaders()
	headers.Set(jws.AlgorithmKey, jwa.HS256())
	headers.Set(jws.KeyIDKey, "key-2024")
	headers.Set(jws.TypeKey, "JWT")
	headers.Set("custom-claim", "important-data")
	headers.Set("app-version", "v1.2.3")
	headers.Set("environment", "production")

	payload := []byte(`{"user": "alice", "role": "admin"}`)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		fmt.Printf("failed to sign: %s\n", err)
		return
	}

	msg, err := jws.Parse(signed)
	if err != nil {
		fmt.Printf("failed to parse: %s\n", err)
		return
	}

	originalHeaders := msg.Signatures()[0].ProtectedHeaders()

	// Filters were extracted out of core into github.com/jwx-go/jwxfilter/v4.
	// jwsfilter.ByName builds a filter over jws.Headers for the given
	// field names; Filter keeps the match, Reject removes it. Each call
	// returns a fresh jws.Headers, so the original is left untouched.
	customFilter := jwsfilter.ByName("custom-claim", "app-version", "environment")
	if _, err = customFilter.Filter(originalHeaders); err != nil {
		fmt.Printf("failed to filter custom headers: %s\n", err)
		return
	}

	// jwsfilter.Standard() is the preset for the 11 RFC 7515 headers
	// (alg, cty, crit, jwk, jku, kid, typ, x5c, x5t, x5t#S256, x5u).
	if _, err = jwsfilter.Standard().Filter(originalHeaders); err != nil {
		fmt.Printf("failed to filter standard headers: %s\n", err)
		return
	}

	// Reject removes the named fields and keeps everything else — useful
	// for scrubbing a specific sensitive extension header before logging.
	sensitiveFilter := jwsfilter.ByName("custom-claim")
	if _, err = sensitiveFilter.Reject(originalHeaders); err != nil {
		fmt.Printf("failed to reject sensitive headers: %s\n", err)
		return
	}

	// OUTPUT:
}
