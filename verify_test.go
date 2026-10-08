package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
)

func TestVerifyConfiguredKeysOnly(t *testing.T) {
	key, err := deriveKey("A256CBC-HS512", "configured-key", "__Secure-authjs.session-token")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"sub": "member-1", "exp": time.Now().Unix() + 600})
	encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT, key), jwe.WithContentEncryption(jwa.A256CBC_HS512))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"token": string(encrypted)})
	handler := verifyHandler([]string{"rotated-key", "configured-key"}, "__Secure-authjs.session-token")
	for _, tc := range []struct {
		name, method, body string
		status             int
	}{
		{"valid", "POST", string(body), 200},
		{"wrong method", "GET", string(body), 405},
		{"reject caller keys", "POST", `{"token":"fake","secret":"attacker","salt":"attacker"}`, 400},
		{"reject trailing JSON", "POST", string(body) + ` {}`, 400},
		{"invalid token", "POST", `{"token":"fake"}`, 401},
		{"empty token", "POST", `{}`, 401},
		{"oversized body", "POST", `{"token":"` + strings.Repeat("a", maxTokenBytes+1) + `"}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequest(tc.method, "/verify", strings.NewReader(tc.body)))
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("verification response permits caching")
			}
			if tc.status == 200 && !strings.Contains(w.Body.String(), `"sub":"member-1"`) {
				t.Fatal("verified identity missing")
			}
		})
	}
}

func TestSessionCookieChunks(t *testing.T) {
	for _, tc := range []struct{ name, cookie, want string }{
		{"plain", "session=abc", "abc"},
		{"out of order", "session.1=def; session.0=abc", "abcdef"},
		{"mixed", "session=abc; session.0=def", ""},
		{"missing first", "session.1=abc", ""},
		{"gap", "session.0=abc; session.2=def", ""},
		{"duplicate", "session=abc; session=def", ""},
		{"duplicate chunk", "session.0=abc; session.0=def", ""},
		{"noncanonical index", "session.00=abc", ""},
		{"large index", "session.32=abc", ""},
		{"unrelated cookie", "other.session=abc", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/auth", nil)
			r.Header.Set("Cookie", tc.cookie)
			got, _ := sessionCookie(r, "session")
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
