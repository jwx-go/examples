package examples_test

import (
	"fmt"
	"time"

	"github.com/jwx-go/jwxfilter/v4/jwtfilter"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_filter_basic_claims() {
	// Create a token with standard and custom claims.
	token, err := jwt.NewBuilder().
		Issuer("github.com/lestrrat-go/jwx").
		Subject("jwt_filter_example").
		Audience([]string{"developers", "users"}).
		IssuedAt(time.Unix(1234567890, 0)).
		Expiration(time.Unix(1234567890+3600, 0)).
		Claim("customClaim", "customValue").
		Claim("applicationRole", "admin").
		Claim("department", "engineering").
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	// Filters live in the companion module github.com/jwx-go/jwxfilter/v4.
	// They were moved out of core in v4 because sign / verify / parse do
	// not depend on them. jwtfilter.ByName builds a filter that matches
	// the specified claim names; the returned jwxfilter.Filter[jwt.Token]
	// has Filter(token) and Reject(token) methods.
	customFilter := jwtfilter.ByName("customClaim", "applicationRole", "department")

	// Filter returns a fresh token containing only the matching claims.
	if _, err := customFilter.Filter(token); err != nil {
		fmt.Printf("failed to filter custom claims: %s\n", err)
		return
	}
	// Reject returns a fresh token with the matching claims removed.
	if _, err := customFilter.Reject(token); err != nil {
		fmt.Printf("failed to reject custom claims: %s\n", err)
		return
	}

	// jwtfilter.Standard() is a preset filter targeting the seven RFC 7519
	// claims (aud, exp, iat, iss, jti, nbf, sub). Filter keeps only them;
	// Reject keeps only non-standard (custom) claims.
	if _, err = jwtfilter.Standard().Filter(token); err != nil {
		fmt.Printf("failed to filter standard claims: %s\n", err)
		return
	}

	if _, err = jwtfilter.Standard().Reject(token); err != nil {
		fmt.Printf("failed to reject standard claims: %s\n", err)
		return
	}

	// OUTPUT:
}
