/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package vaulttest provides a minimal fake Vault server for tests that only
// need authentication, not secret storage.
package vaulttest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Server fakes Vault's token lookup and Kubernetes login endpoints.
type Server struct {
	*httptest.Server

	mu sync.Mutex
	// Tokens are accepted by lookup-self, mapped to their TTL in seconds.
	tokens map[string]int
	// KubernetesRoles maps "<mount>/<role>" to the JWT it accepts.
	kubernetesRoles map[string]string
	// Logins counts successful Kubernetes logins.
	logins int
}

// NewServer starts a fake Vault server. Close it when done.
func NewServer() *Server {
	s := &Server{tokens: map[string]int{}, kubernetesRoles: map[string]string{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// AddToken makes token valid with the given TTL in seconds (0 = no expiry).
func (s *Server) AddToken(token string, ttl int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = ttl
}

// RevokeToken makes token invalid.
func (s *Server) RevokeToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
}

// AddKubernetesRole accepts jwt for role on the Kubernetes auth mount.
func (s *Server) AddKubernetesRole(mount, role, jwt string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kubernetesRoles[mount+"/"+role] = jwt
}

// Logins returns the number of successful Kubernetes logins.
func (s *Server) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case path == "auth/token/lookup-self":
		ttl, ok := s.tokens[r.Header.Get("X-Vault-Token")]
		if !ok {
			writeJSON(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"ttl": ttl}})

	case strings.HasPrefix(path, "auth/") && strings.HasSuffix(path, "/login") && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		mount := strings.TrimSuffix(strings.TrimPrefix(path, "auth/"), "/login")
		var body struct {
			Role string `json:"role"`
			JWT  string `json:"jwt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []string{err.Error()}})
			return
		}
		want, ok := s.kubernetesRoles[mount+"/"+body.Role]
		if !ok || want != body.JWT {
			writeJSON(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
			return
		}
		s.logins++
		token := "k8s-token-" + body.Role
		s.tokens[token] = 3600
		writeJSON(w, http.StatusOK, map[string]any{
			"auth": map[string]any{"client_token": token, "lease_duration": 3600, "renewable": true},
		})

	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"errors": []string{}})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
