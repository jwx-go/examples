package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// Example_jwk_parse_unsupported demonstrates the three parsing modes for
// a JWK Set containing an entry that this build cannot parse.
func Example_jwk_parse_unsupported() {
	// One entry with a key type this build does not understand, plus a
	// regular EC key (from RFC 7517 Appendix A.1).
	raw := []byte(`{"keys":[
	  {"kty":"PQ-FUTURE","kid":"pq1","alg":"PQ-ALG-1"},
	  {"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"ec1"}
	]}`)

	// Default (retain): the set parses, and the unknown entry is kept as
	// a jwk.UnsupportedKey placeholder alongside the usable EC key.
	set, err := jwk.Parse(raw)
	if err != nil {
		fmt.Println("default: error:", err)
		return
	}
	fmt.Println("default: keys:", set.Len())
	for i, key := range set.All() {
		fmt.Printf("default: key %d unsupported: %t\n", i, jwk.IsUnsupportedKey(key))
	}

	// WithIgnoreParseError(true): the unknown entry is silently dropped.
	dropped, err := jwk.Parse(raw, jwk.WithIgnoreParseError(true))
	if err != nil {
		fmt.Println("ignore: error:", err)
		return
	}
	fmt.Println("ignore: keys:", dropped.Len())

	// WithStrictKeySetParsing(true): the whole set fails to parse. This
	// is the same policy as v3's default behavior — but only the policy:
	// v4 understands more key types than v3 (for example "AKP"), so an
	// entry that fails under v3 may parse successfully under v4, or fail
	// at a different stage with a different error.
	_, err = jwk.Parse(raw, jwk.WithStrictKeySetParsing(true))
	fmt.Println("strict: parse failed:", err != nil)

	// OUTPUT:
	// default: keys: 2
	// default: key 0 unsupported: true
	// default: key 1 unsupported: false
	// ignore: keys: 1
	// strict: parse failed: true
}
