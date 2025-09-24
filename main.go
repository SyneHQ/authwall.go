package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"golang.org/x/crypto/hkdf"
)

const (
	defaultCookieName = "authjs.session_token"
	cacheTTL          = 12 * time.Hour
	cleanupInterval   = 1 * time.Hour
)

type cacheEntry struct {
	key []byte
	ts  time.Time
}

var (
	keyCache sync.Map // map[string]cacheEntry
)

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func cacheKey(enc, secret, salt string) string {
	return enc + "|" + salt + "|" + secret
}

func deriveKey(enc, secret, salt string) ([]byte, error) {
	var length int
	switch enc {
	case "A256GCM":
		length = 32
	case "A256CBC-HS512":
		length = 64
	default:
		return nil, fmt.Errorf("unsupported enc: %s", enc)
	}
	// Info must exactly match Auth.js convention.
	info := []byte(fmt.Sprintf("Auth.js Generated Encryption Key (%s)", salt))
	r := hkdf.New(sha256.New, []byte(secret), []byte(salt), info)
	key := make([]byte, length)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func getCachedKey(enc, secret, salt string) ([]byte, error) {
	id := cacheKey(enc, secret, salt)
	if v, ok := keyCache.Load(id); ok {
		e := v.(cacheEntry)
		if time.Since(e.ts) < cacheTTL {
			return e.key, nil
		}
		keyCache.Delete(id)
	}
	k, err := deriveKey(enc, secret, salt)
	if err != nil {
		return nil, err
	}
	keyCache.Store(id, cacheEntry{key: k, ts: time.Now()})
	return k, nil
}

// RFC 7638 thumbprint for symmetric JWK { "k":"...", "kty":"oct" } with canonical order.
func jwkThumbprintOct(key []byte) (string, error) {
	doc := []byte(fmt.Sprintf("{\"k\":\"%s\",\"kty\":\"oct\"}", b64url(key)))
	switch len(key) {
	case 32:
		sum := sha256.Sum256(doc)
		return b64url(sum[:]), nil
	case 64:
		sum := sha512.Sum512(doc)
		return b64url(sum[:]), nil
	default:
		return "", fmt.Errorf("unexpected key length %d", len(key))
	}
}

type authResult struct {
	OK      bool
	Subject string
	Payload map[string]any
}

func decryptAuthJWE(_ context.Context, token string, secrets []string, salt string) (*authResult, error) {
	// Parse headers to learn alg/enc/kid without attempting decryption first.
	msg, err := jwe.ParseString(token)
	if err != nil {
		return nil, fmt.Errorf("parse JWE: %w", err)
	}
	h := msg.ProtectedHeaders()
	alg := string(h.Algorithm())
	enc := string(h.ContentEncryption())
	kid := h.KeyID()

	if alg != "dir" {
		return nil, fmt.Errorf("unexpected alg %s", alg)
	}
	if enc != "A256GCM" && enc != "A256CBC-HS512" {
		return nil, fmt.Errorf("unexpected enc %s", enc)
	}

	// Try secrets; if kid present, match by thumbprint first.
	type cand struct {
		secret string
		key    []byte
	}
	var candidates []cand
	for _, s := range secrets {
		k, err := getCachedKey(enc, s, salt)
		if err != nil {
			continue
		}
		candidates = append(candidates, cand{secret: s, key: k})
	}

	if kid != "" {
		var filtered []cand
		for _, c := range candidates {
			tp, err := jwkThumbprintOct(c.key)
			if err == nil && tp == kid {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) > 0 {
			candidates = filtered
		}
	}

	var plaintext []byte
	var usedKey []byte
	for _, c := range candidates {
		b, err := jwe.Decrypt([]byte(token), jwe.WithKey(jwa.DIRECT, c.key))
		if err == nil {
			plaintext = b
			usedKey = c.key
			break
		}
	}
	if plaintext == nil {
		return nil, fmt.Errorf("decryption failed for all candidates")
	}

	var payload map[string]any
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}

	// Optional exp check if present.
	if v, ok := payload["exp"]; ok {
		switch exp := v.(type) {
		case float64:
			if time.Now().Unix() > int64(exp) {
				return nil, fmt.Errorf("token expired")
			}
		case json.Number:
			if n, _ := exp.Int64(); time.Now().Unix() > n {
				return nil, fmt.Errorf("token expired")
			}
		}
	}

	sub := ""
	if v, ok := payload["sub"].(string); ok {
		sub = v
	}

	_ = usedKey // kept for symmetry/debug; not returned

	return &authResult{
		OK:      true,
		Subject: sub,
		Payload: payload,
	}, nil
}

func startCleanup() {
	t := time.NewTicker(cleanupInterval)
	go func() {
		for range t.C {
			now := time.Now()
			keyCache.Range(func(k, v any) bool {
				e := v.(cacheEntry)
				if now.Sub(e.ts) > cacheTTL {
					keyCache.Delete(k)
				}
				return true
			})
		}
	}()
}

func getTokenFromRequest(r *http.Request, cookieName string, headerName string, queryName string) string {
	// 1) Cookie
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		return c.Value
	}
	// 2) Authorization: Bearer
	if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	// 3) Custom header
	if headerName != "" {
		if v := r.Header.Get(headerName); v != "" {
			return v
		}
	}
	// 4) Fallback query (testing)
	if queryName != "" {
		if v := r.URL.Query().Get(queryName); v != "" {
			return v
		}
	}
	return ""
}

func main() {
	startCleanup()

	// Configuration via env
	secretsEnv := os.Getenv("AUTH_SECRETS") // comma-separated for rotation
	if secretsEnv == "" {
		log.Fatal("missing AUTH_SECRETS (comma-separated)")
	}
	var secrets []string
	for _, s := range strings.Split(secretsEnv, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			secrets = append(secrets, s)
		}
	}

	salt := os.Getenv("AUTH_SALT") // required
	if salt == "" {
		salt = defaultCookieName
		if salt == "" {
			log.Fatal("missing AUTH_SALT")
		}
	}

	cookieName := os.Getenv("AUTH_COOKIE_NAME")
	if cookieName == "" {
		cookieName = defaultCookieName
	}
	headerName := os.Getenv("AUTH_TOKEN_HEADER") // optional
	queryName := os.Getenv("AUTH_TOKEN_QUERY")   // optional

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":80"
	}

	mux := http.NewServeMux()

	// Traefik ForwardAuth endpoint: 2xx allows, otherwise deny.
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {

		// if a OPTIONS request, return 200 or acme challenge
		if r.URL.Query().Get("token") == "acme-challenge" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("acme-challenge"))
			return
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		start := time.Now()
		ctx := r.Context()
		token := getTokenFromRequest(r, cookieName, headerName, queryName)
		if token == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		res, err := decryptAuthJWE(ctx, token, secrets, salt)
		if err != nil || !res.OK {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Optionally pass identity downstream; Traefik can be configured to forward these.
		if res.Subject != "" {
			w.Header().Set("X-User-Id", res.Subject)
		}

		teamId := ""
		if v, ok := res.Payload["teamId"].(string); ok {
			teamId = v
		}

		if teamId != "" {
			w.Header().Set("X-Team-Id", teamId)
		}

		w.WriteHeader(http.StatusOK)

		log.Printf("%s %s %s - %v", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})

	// Testing endpoints mirroring the provided Bun server.
	mux.HandleFunc("/decrypt", func(w http.ResponseWriter, r *http.Request) {
		type Req struct {
			Token  string `json:"token"`
			Secret string `json:"secret"`
			Salt   string `json:"salt"`
		}
		type Resp struct {
			Success bool           `json:"success"`
			Payload map[string]any `json:"payload,omitempty"`
			Error   string         `json:"error,omitempty"`
		}

		var token, secret, lSalt string
		if r.Method == http.MethodPost {
			var req Req
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			token, secret, lSalt = req.Token, req.Secret, req.Salt
		} else {
			q := r.URL.Query()
			token = q.Get("token")
			secret = q.Get("secret")
			lSalt = q.Get("salt")
		}
		if token == "" || secret == "" || lSalt == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(Resp{Error: "missing token/secret/salt"})
			return
		}
		res, err := decryptAuthJWE(r.Context(), token, []string{secret}, lSalt)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(Resp{Error: err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Resp{Success: true, Payload: res.Payload})

	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		type H struct {
			Status    string `json:"status"`
			Timestamp string `json:"timestamp"`
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(H{Status: "ok", Timestamp: time.Now().UTC().Format(time.RFC3339)})
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	log.Printf("auth service listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}
