package examples_test

import (
	"fmt"
	"time"

	"github.com/jwx-go/jwxfilter/v4/jwtfilter"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_filter_advanced_use_cases() {
	// Create a comprehensive token with various types of claims.
	token, err := jwt.NewBuilder().
		Issuer("auth-service.example.com").
		Subject("user-456").
		Audience([]string{"web-app", "mobile-app", "api-gateway"}).
		IssuedAt(time.Unix(1234567890, 0)).
		Expiration(time.Unix(1234567890+7200, 0)).
		NotBefore(time.Unix(1234567890, 0)).
		JwtID("session-xyz789").
		Claim("userRole", "manager").
		Claim("department", "sales").
		Claim("permissions", []string{"read:reports", "write:orders", "approve:discounts"}).
		Claim("profile", map[string]any{
			"name":  "John Doe",
			"email": "john@example.com",
			"phone": "+1-555-0123",
		}).
		Claim("sessionInfo", map[string]any{
			"loginIP":      "10.0.1.100",
			"deviceType":   "desktop",
			"browser":      "Chrome/91.0",
			"lastActivity": "2023-01-01T12:30:00Z",
		}).
		Claim("features", []string{"beta-ui", "advanced-analytics", "mobile-push"}).
		Build()
	if err != nil {
		fmt.Printf("failed to build comprehensive token: %s\n", err)
		return
	}

	// Use case 1: scrub sensitive fields before handing the token to a
	// public-facing API. jwtfilter.ByName builds a filter that matches
	// the specified claim names; Reject returns a copy with those claims
	// removed.
	sensitiveFilter := jwtfilter.ByName("sessionInfo", "profile")
	if _, err := sensitiveFilter.Reject(token); err != nil {
		fmt.Printf("failed to create public API token: %s\n", err)
		return
	}

	// Use case 2: keep only identity-oriented claims. Filter (as opposed
	// to Reject) keeps the matched names.
	identityFilter := jwtfilter.ByName("sub", "iss", "userRole", "department")
	if _, err := identityFilter.Filter(token); err != nil {
		fmt.Printf("failed to create identity token: %s\n", err)
		return
	}

	// Use case 3: keep only the standard security / time claims. Callers
	// who want exactly the RFC 7519 set can use jwtfilter.Standard()
	// instead of enumerating by name; spelling them out here is shown for
	// illustration.
	securityFilter := jwtfilter.ByName("iss", "sub", "aud", "exp", "iat", "nbf", "jti")
	if _, err := securityFilter.Filter(token); err != nil {
		fmt.Printf("failed to create security token: %s\n", err)
		return
	}

	// Use case 4: compose filters. First strip every RFC 7519 claim, then
	// strip two specific custom ones. Each Filter/Reject call returns a
	// fresh jwt.Token, so chaining is just sequential application.
	tempToken, err := jwtfilter.Standard().Reject(token)
	if err != nil {
		fmt.Printf("failed to remove standard claims: %s\n", err)
		return
	}

	customSensitiveFilter := jwtfilter.ByName("sessionInfo", "profile")
	if _, err := customSensitiveFilter.Reject(tempToken); err != nil {
		fmt.Printf("failed to remove custom sensitive claims: %s\n", err)
		return
	}

	// OUTPUT:
}
