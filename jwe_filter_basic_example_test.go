package examples_test

import (
	"fmt"

	"github.com/jwx-go/jwxfilter/v4/jwefilter"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
)

// Example_jwe_filter_basic demonstrates basic JWE header filtering via the
// jwefilter companion package. Filters were extracted out of jwx core in
// v4 (github.com/jwx-go/jwxfilter/v4/jwefilter).
func Example_jwe_filter_basic() {
	// Construct JWE protected headers with both RFC 7516 standard fields
	// and application-specific custom fields.
	protectedHeaders := jwe.NewHeaders()
	protectedHeaders.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256())
	protectedHeaders.Set(jwe.ContentEncryptionKey, jwa.A256GCM)
	protectedHeaders.Set(jwe.ContentTypeKey, "application/json")
	protectedHeaders.Set(jwe.KeyIDKey, "example-key-1")
	protectedHeaders.Set("custom-header", "custom-value")
	protectedHeaders.Set("app-id", "my-app")
	protectedHeaders.Set("version", "1.0")

	headers := protectedHeaders

	// jwefilter.ByName builds a filter over jwe.Headers for the given
	// field names. Filter returns a fresh copy containing only the
	// matching fields.
	customFilter := jwefilter.ByName("custom-header", "app-id", jwe.KeyIDKey)

	filteredHeaders, err := customFilter.Filter(headers)
	if err != nil {
		fmt.Printf("ByName.Filter failed: %s\n", err)
		return
	}
	if len(filteredHeaders.Keys()) == 0 {
		fmt.Printf("No filtered headers found\n")
		return
	}

	// jwefilter.Standard() is the preset for the 18 RFC 7516 standard
	// headers. Use Filter to keep only them.
	stdFilter := jwefilter.Standard()

	standardHeaders, err := stdFilter.Filter(headers)
	if err != nil {
		fmt.Printf("Standard.Filter failed: %s\n", err)
		return
	}
	if len(standardHeaders.Keys()) == 0 {
		fmt.Printf("No standard headers found\n")
		return
	}

	// Reject keeps everything except the named fields — useful for
	// scrubbing specific custom fields before logging or forwarding.
	rejectFilter := jwefilter.ByName("version", "custom-header")

	rejectedHeaders, err := rejectFilter.Reject(headers)
	if err != nil {
		fmt.Printf("ByName.Reject failed: %s\n", err)
		return
	}
	if len(rejectedHeaders.Keys()) == 0 {
		fmt.Printf("No rejected headers found\n")
		return
	}

	// Reject on the standard filter keeps only custom fields.
	customOnlyHeaders, err := stdFilter.Reject(headers)
	if err != nil {
		fmt.Printf("Standard.Reject failed: %s\n", err)
		return
	}
	if len(customOnlyHeaders.Keys()) == 0 {
		fmt.Printf("No custom only headers found\n")
		return
	}

	// OUTPUT:
}
