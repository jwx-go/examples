package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/jwx-go/jwkfetch/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_parse_with_jku() {
	set := jwk.NewSet()

	var signingKey jwk.Key

	// for _, alg := range algorithms {
	for i := 0; i < 3; i++ {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("failed to generate private key: %s\n", err)
			return
		}
		// too lazy to write a proper algorithm. just assign every
		// time, and signingKey will end up being the last key generated
		privkey, err := jwk.Import[jwk.Key](pk)
		if err != nil {
			fmt.Printf("failed to create jwk.Key: %s\n", err)
			return
		}
		privkey.Set(jwk.KeyIDKey, fmt.Sprintf(`key-%d`, i))

		// It is important that we are using jwk.Key here instead of
		// rsa.PrivateKey, because this way `kid` is automatically
		// assigned when we sign the token
		signingKey = privkey

		pubkey, err := privkey.PublicKey()
		if err != nil {
			fmt.Printf("failed to create public key: %s\n", err)
			return
		}
		set.AddKey(pubkey)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	// Create a JWT
	token := jwt.New()
	token.Set(`foo`, `bar`)

	hdrs := jws.NewHeaders()
	hdrs.Set(jws.JWKSetURLKey, srv.URL)

	serialized, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), signingKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		fmt.Printf("failed to seign token: %s\n", err)
		return
	}

	// jku verification uses a jwk.Fetcher to retrieve the JWKS
	// referenced in the JWS protected header. Use jwkfetch.Client —
	// it is the canonical implementation and the one this option is
	// designed around.
	//
	// IMPORTANT: the `jku` URL comes from the JWS protected header,
	// which is untrusted input. A real application MUST pass
	// jwkfetch.WithWhitelist with a MapWhitelist / RegexpWhitelist
	// restricted to its known issuer set — otherwise a hostile peer
	// can point the fetcher at any URL it can reach (SSRF) and have
	// its own keys accepted as "the issuer's keys". This example uses
	// srv.URL as a "known issuer" because httptest picks a random
	// port each run.
	client := jwkfetch.NewClient(
		// httptest serves HTTPS with a self-signed cert, so the
		// Client needs srv.Client() to validate it.
		jwkfetch.WithHTTPClient(srv.Client()),
		jwkfetch.WithWhitelist(jwkfetch.NewMapWhitelist().Add(srv.URL)),
	)
	tok, err := jwt.Parse(serialized, jwt.WithVerifyAuto(client))
	if err != nil {
		fmt.Printf("failed to verify token: %s\n", err)
		return
	}
	_ = tok
	// OUTPUT:
}
