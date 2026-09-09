package main

import (
	"encoding/json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNoChallengeOrOptionsBypass(t *testing.T) {
	h := authHandler([]string{"test"}, "test", "session", "", "")
	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		for _, target := range []string{"/auth?token=acme-challenge", "/auth", "/auth?token=acme-challenge&path=/.well-known/acme-challenge/token"} {
			r := httptest.NewRequest(method, target, nil)
			w := httptest.NewRecorder()
			h(w, r)
			if w.Code != 401 {
				t.Fatalf("%s %s allowed: %d", method, target, w.Code)
			}
		}
	}
}

func TestLegitimateSessionAndInvalidClaims(t *testing.T) {
	secret, salt := "local-test-secret", "authjs.session-token"
	key, err := deriveKey("A256GCM", secret, salt)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		payload map[string]any
		want    int
	}{
		{"valid", map[string]any{"sub": "user-a", "teamId": "team-a", "exp": time.Now().Unix() + 600}, 200},
		{"expired", map[string]any{"sub": "user-a", "exp": time.Now().Unix() - 10}, 401},
		{"missing expiry", map[string]any{"sub": "user-a"}, 401},
		{"string expiry", map[string]any{"sub": "user-a", "exp": "forever"}, 401},
		{"missing subject", map[string]any{"exp": time.Now().Unix() + 600}, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, _ := json.Marshal(tc.payload)
			token, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT, key), jwe.WithContentEncryption(jwa.A256GCM))
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", "/auth", nil)
			r.Header.Set("Authorization", "Bearer "+string(token))
			w := httptest.NewRecorder()
			authHandler([]string{secret}, salt, "session", "", "")(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d: %s", w.Code, w.Body.String())
			}
			if w.Code == 200 && w.Header().Get("X-User-Id") != "user-a" {
				t.Fatal("lost session identity")
			}
		})
	}
}
