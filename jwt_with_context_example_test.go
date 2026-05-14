package examples_test

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

// requestIDKey is the context key under which a per-request identifier is
// stored. Real applications should use a dedicated unexported struct type
// (rather than a bare string) to avoid collisions with other packages
// using `context.Value`.
type requestIDKey struct{}

func Example_jwt_with_context() {
	// jwt.WithContext threads a context.Context through jwt.Validate (and
	// through jwt.Parse, since Parse runs validation by default). Custom
	// validators receive that context as their first argument — which is
	// the only sanctioned way for a Validator to see per-request state
	// such as a request ID, a deadline, or a handle to a replay-check
	// store. Without WithContext, a Validator only sees the token.

	// Build a minimal token. The validator below ignores its contents on
	// purpose — the focus here is on what flows through the context.
	tok, err := jwt.NewBuilder().
		Issuer("example.com").
		Subject("user-123").
		Build()
	if err != nil {
		fmt.Printf("build token: %s\n", err)
		return
	}

	// The validator pulls a request ID out of the context. If the caller
	// forgot to attach one, validation fails — demonstrating that the
	// context is the binding between request scope and Validator logic.
	validator := jwt.ValidatorFunc(func(ctx context.Context, _ jwt.Token) error {
		rid, ok := ctx.Value(requestIDKey{}).(string)
		if !ok || rid == "" {
			return fmt.Errorf(`request ID missing from context`)
		}
		fmt.Printf("validating token for request %s\n", rid)
		return nil
	})

	// In real code the context would come from http.Request.Context() with
	// middleware having injected the request ID upstream. Here we build
	// it inline so the example is self-contained.
	ctx := context.WithValue(context.Background(), requestIDKey{}, "req-2025-05-14-abc")

	// Pass the context alongside the validator. WithContext is a
	// ValidateOption, so it also works on jwt.Parse — the signature there
	// would be `jwt.Parse(raw, jwt.WithKey(...), jwt.WithContext(ctx),
	// jwt.WithValidator(validator))`.
	if err := jwt.Validate(tok, jwt.WithContext(ctx), jwt.WithValidator(validator)); err != nil {
		fmt.Printf("validate: %s\n", err)
		return
	}
	// OUTPUT:
	// validating token for request req-2025-05-14-abc
}
