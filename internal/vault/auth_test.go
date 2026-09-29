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

package vault_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warewave/krotos/internal/vault"
	"github.com/warewave/krotos/internal/vault/vaulttest"
)

type staticTokens map[string]string

func (s staticTokens) Token(_ context.Context, audience string) (string, error) {
	return s[audience], nil
}

func TestTokenAuth(t *testing.T) {
	srv := vaulttest.NewServer()
	defer srv.Close()
	srv.AddToken("good", 7200)
	srv.AddToken("root", 0)

	c, err := vault.New(t.Context(), vault.Config{Address: srv.URL, Auth: &vault.TokenAuth{Token: "good\n"}})
	if err != nil {
		t.Fatalf("login with valid token: %v", err)
	}
	if exp := time.Until(c.ExpiresAt()); exp < 119*time.Minute || exp > 2*time.Hour {
		t.Fatalf("ExpiresAt in %v, want ~2h", exp)
	}
	if err := c.LookupSelf(t.Context()); err != nil {
		t.Fatalf("LookupSelf: %v", err)
	}

	c, err = vault.New(t.Context(), vault.Config{Address: srv.URL, Auth: &vault.TokenAuth{Token: "root"}})
	if err != nil {
		t.Fatal(err)
	}
	if !c.ExpiresAt().IsZero() {
		t.Fatalf("non-expiring token has ExpiresAt %v", c.ExpiresAt())
	}

	_, err = vault.New(t.Context(), vault.Config{Address: srv.URL, Auth: &vault.TokenAuth{Token: "bad"}})
	if err == nil || !vault.IsPermissionDenied(err) {
		t.Fatalf("login with invalid token: err = %v, want permission denied", err)
	}

	if _, err := vault.New(t.Context(), vault.Config{Address: srv.URL, Auth: &vault.TokenAuth{Token: " "}}); err == nil {
		t.Fatal("login with empty token succeeded")
	}
}

func TestKubernetesAuth(t *testing.T) {
	srv := vaulttest.NewServer()
	defer srv.Close()
	srv.AddKubernetesRole("k8s-prod", "krotos", "jwt-for-vault")

	auth := &vault.KubernetesAuth{
		Role:      "krotos",
		MountPath: "k8s-prod",
		Audience:  "vault",
		Tokens:    staticTokens{"vault": "jwt-for-vault", "": "mounted-jwt"},
	}
	c, err := vault.New(t.Context(), vault.Config{Address: srv.URL, Auth: auth})
	if err != nil {
		t.Fatalf("kubernetes login: %v", err)
	}
	if err := c.LookupSelf(t.Context()); err != nil {
		t.Fatalf("LookupSelf after kubernetes login: %v", err)
	}
	if c.ExpiresAt().IsZero() {
		t.Fatal("ExpiresAt not set from lease duration")
	}

	// The mounted token (empty audience) is not accepted by this role.
	auth.Audience = ""
	if _, err := vault.New(t.Context(), vault.Config{Address: srv.URL, Auth: auth}); err == nil {
		t.Fatal("login with wrong JWT succeeded")
	}
}

func TestPodServiceAccountTokensReadsMountedToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("mounted-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := &vault.PodServiceAccountTokens{TokenPath: path}
	got, err := src.Token(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "mounted-jwt" {
		t.Fatalf("token = %q, want %q", got, "mounted-jwt")
	}

	if _, err := src.Token(t.Context(), "vault"); err == nil {
		t.Fatal("token request without service account name succeeded")
	}
}

func TestFingerprintsDoNotLeakTokens(t *testing.T) {
	fp := (&vault.TokenAuth{Token: "s.supersecret"}).Fingerprint()
	if fp == "" || strings.Contains(fp, "supersecret") {
		t.Fatalf("fingerprint %q leaks the token", fp)
	}
}
