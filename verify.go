package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const maxTokenBytes = 64 * 1024
const maxCookieChunks = 32

// sessionCookie rejects duplicate names, mixed formats, gaps, and oversized sessions.
func sessionCookie(r *http.Request, name string) (string, bool) {
	chunks := make(map[int]string)
	plain, present, invalid := "", false, false
	for _, c := range r.Cookies() {
		if c.Name == name {
			if present && plain != "" || c.Value == "" {
				invalid = true
			}
			plain, present = c.Value, true
		} else if strings.HasPrefix(c.Name, name+".") {
			present = true
			suffix := strings.TrimPrefix(c.Name, name+".")
			n, err := strconv.Atoi(suffix)
			if err != nil || n < 0 || n >= maxCookieChunks || strconv.Itoa(n) != suffix || c.Value == "" {
				invalid = true
				continue
			}
			if _, found := chunks[n]; found {
				invalid = true
			}
			chunks[n] = c.Value
		}
	}
	if invalid || (plain != "" && len(chunks) != 0) {
		return "", present
	}
	if plain != "" {
		if len(plain) > maxTokenBytes {
			return "", true
		}
		return plain, true
	}
	var token strings.Builder
	for n := 0; n < len(chunks); n++ {
		value, found := chunks[n]
		if !found || token.Len()+len(value) > maxTokenBytes {
			return "", true
		}
		token.WriteString(value)
	}
	return token.String(), present
}

// verifyHandler uses only configured keys. Keep this endpoint on the private service network.
func verifyHandler(secrets []string, salt string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		fail := func(status int, message string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": message})
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			fail(http.StatusMethodNotAllowed, "Use POST for session verification.")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxTokenBytes+1024)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var req struct {
			Token string `json:"token"`
		}
		if err := decoder.Decode(&req); err != nil {
			fail(http.StatusBadRequest, "Request must contain one JSON token field.")
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF || len(req.Token) > maxTokenBytes {
			fail(http.StatusBadRequest, "Request contains invalid or excessive data.")
			return
		}
		res, err := decryptAuthJWE(r.Context(), req.Token, secrets, salt)
		if err != nil {
			fail(http.StatusUnauthorized, "Session verification failed.")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "payload": res.Payload})
	}
}
