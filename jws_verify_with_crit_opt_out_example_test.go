package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_verify_with_crit_opt_out() {
	// This JWS has crit: ["x-custom"] with the "x-custom" header present
	// in the protected header. The producer is asserting that the
	// recipient MUST understand the "x-custom" extension before treating
	// the signature as valid (RFC 7515 §4.1.11).
	const customCrit = `eyJhbGciOiJIUzI1NiIsImNyaXQiOlsieC1jdXN0b20iXSwieC1jdXN0b20iOiJ2YWx1ZSJ9.TG9yZW0gaXBzdW0.JGhCiLa5O8-dJqGHwzjFW_KYRAgMA85v2dlsDs2B2fc`

	key, err := jwk.Import[jwk.Key]([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf("failed to create key: %s\n", err)
		return
	}

	// In v4, jws.Verify enforces the "crit" header by default and rejects
	// any extension the recipient has not declared support for via
	// jws.WithCritExtension. The signature above lists "x-custom" but we
	// did not declare it, so verification fails — exactly the behavior
	// the RFC requires for unknown extensions.
	_, err = jws.Verify([]byte(customCrit), jws.WithKey(jwa.HS256(), key))
	fmt.Printf("default strict: verification error = %t\n", err != nil)

	// Some applications cannot upgrade to declaring every extension they
	// might encounter and need to fall back to the pre-v3.0.14 lax
	// behavior, where jws.Verify ignores the "crit" header entirely. To
	// opt out, pass jws.WithCritValidation(false). The same JWS now
	// verifies successfully because "crit" is no longer enforced.
	//
	// IMPORTANT: opting out also means undeclared extensions silently
	// pass through, which is exactly what RFC 7515 §4.1.11 says
	// recipients MUST NOT do. Use this only when you are certain none of
	// the JWS messages you accept will carry security-relevant crit
	// extensions, or when a higher layer enforces the contract.
	payload, err := jws.Verify([]byte(customCrit),
		jws.WithKey(jwa.HS256(), key),
		jws.WithCritValidation(false),
	)
	if err != nil {
		fmt.Printf("failed to verify: %s\n", err)
		return
	}
	fmt.Printf("opt out: %s\n", payload)
	// OUTPUT:
	// default strict: verification error = true
	// opt out: Lorem ipsum
}
