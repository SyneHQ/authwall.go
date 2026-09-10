package secrets

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestHydrationBeforeStartupWithoutNetwork(t *testing.T) {
	cfg := map[string]string{}
	get := func(key string) string { return cfg[key] }
	called := false
	fetch := func(context.Context, Config) error { called = true; return nil }
	if err := Hydrate(get, fetch); err != nil || called {
		t.Fatal("disabled hydration contacted provider")
	}
	cfg["INFISICAL_CLIENT_ID"] = "id"
	if Hydrate(get, fetch) == nil || called {
		t.Fatal("partial config did not fail closed")
	}
	cfg["INFISICAL_CLIENT_SECRET"] = "secret-canary"
	cfg["INFISICAL_PROJECT_ID"] = "project"
	cfg["INFISICAL_ENV"] = "production"
	if err := Hydrate(get, fetch); err != nil || !called {
		t.Fatal("valid configuration not loaded")
	}
	err := Hydrate(get, func(context.Context, Config) error { return errors.New("secret-canary") })
	if err == nil || strings.Contains(err.Error(), "secret-canary") {
		t.Fatal("provider errors must fail closed without secret disclosure")
	}
}

func TestPrivateHTTPRequiresExplicitOptIn(t *testing.T) {
	for _, test := range []struct {
		url, allow string
		accepted   bool
	}{
		{"http://infisical-backend:8080", "", false},
		{"http://infisical-backend:8080", "false", false},
		{"http://infisical-backend:8080", "true", true},
		{"https://infisical.synehq.com", "", true},
		{"ftp://infisical-backend:8080", "true", false},
		{"http://user:password@infisical-backend:8080", "true", false},
		{"http://infisical-backend:8080?token=bad", "true", false},
		{"http://infisical-backend:8080#bad", "true", false},
	} {
		t.Run(test.url+test.allow, func(t *testing.T) {
			cfg := map[string]string{"INFISICAL_CLIENT_ID": "test-id", "INFISICAL_CLIENT_SECRET": "test-secret",
				"INFISICAL_PROJECT_ID": "test-project", "INFISICAL_ENV": "prod",
				"INFISICAL_API_URL": test.url, "INFISICAL_ALLOW_INSECURE_HTTP": test.allow}
			called := false
			err := Hydrate(func(k string) string { return cfg[k] }, func(_ context.Context, c Config) error {
				called = true
				if c.URL != test.url {
					t.Fatal("configured URL changed")
				}
				return nil
			})
			if called != test.accepted || (err == nil) != test.accepted {
				t.Fatal("unexpected bootstrap policy result")
			}
		})
	}
}
