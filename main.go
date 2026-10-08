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
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	serviceSecrets "github.com/synehq/authwall.go/internal/secrets"
	"golang.org/x/crypto/hkdf"
)

const (
	defaultCookieName = "authjs.session-token"
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
	if len(token) > 64*1024 {
		return nil, fmt.Errorf("token too large")
	}
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

	now := time.Now().Unix()
	exp, ok := payload["exp"].(float64)
	if !ok || math.IsNaN(exp) || math.IsInf(exp, 0) || exp <= float64(now) || exp != math.Trunc(exp) {
		return nil, fmt.Errorf("missing or invalid expiration")
	}
	for _, claim := range []string{"nbf", "iat"} {
		if raw, exists := payload[claim]; exists {
			value, ok := raw.(float64)
			if !ok || math.IsNaN(value) || math.IsInf(value, 0) || value > float64(now+60) {
				return nil, fmt.Errorf("invalid token time")
			}
		}
	}
	sub, ok := payload["sub"].(string)
	if !ok || strings.TrimSpace(sub) == "" {
		return nil, fmt.Errorf("missing subject")
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
	// 1) Cookie, including Auth.js chunks. Reject ambiguous or incomplete cookies.
	if token, present := sessionCookie(r, cookieName); present {
		return token
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
	if err := serviceSecrets.Load(); err != nil {
		log.Fatal(err)
	}
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
	mux.HandleFunc("/auth", authHandler(secrets, salt, cookieName, headerName, queryName))

	mux.HandleFunc("/verify", verifyHandler(secrets, salt))

	// Optional local debugging helper. Never expose secret-bearing query URLs.
	if os.Getenv("AUTHWALL_ENABLE_DEBUG_ENDPOINTS") == "true" {
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

			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", 405)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
			var req Req
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", 400)
				return
			}
			token, secret, lSalt := req.Token, req.Secret, req.Salt

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

	}
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		type H struct {
			Status    string `json:"status"`
			Timestamp string `json:"timestamp"`
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(H{Status: "ok", Timestamp: time.Now().UTC().Format(time.RFC3339)})
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024}
	log.Printf("auth service listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func authHandler(secrets []string, salt, cookieName, headerName, queryName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

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
	}
}
