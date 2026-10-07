//go:build integration

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
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	tcvault "github.com/testcontainers/testcontainers-go/modules/vault"

	"github.com/Warewave-Technology/krotos/internal/vault"
)

const (
	vaultImage = "hashicorp/vault:1.20"
	rootToken  = "root"
)

var vaultAddr string

func TestMain(m *testing.M) {
	ctx := context.Background()
	c, err := tcvault.Run(ctx, vaultImage,
		tcvault.WithToken(rootToken),
		tcvault.WithInitCommand("secrets enable -version=1 -path=kv1 kv"),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start vault: %v\n", err)
		os.Exit(1)
	}
	vaultAddr, err = c.HttpHostAddress(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault address: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = c.Terminate(ctx)
	os.Exit(code)
}

func rootClient(t *testing.T) *vault.Client {
	t.Helper()
	c, err := vault.New(t.Context(), vault.Config{Address: vaultAddr, Auth: &vault.TokenAuth{Token: rootToken}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return c
}

// rawRoot is the plain API client, used to set up fixtures the operator never needs.
func rawRoot(t *testing.T) *vaultapi.Client {
	t.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = vaultAddr
	c, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.SetToken(rootToken)
	return c
}

func TestKVv2(t *testing.T) {
	ctx := t.Context()
	c := rootClient(t)
	ref := vault.SecretRef{Mount: "secret", Path: "apps/orders/db", KVVersion: 2}

	if _, err := c.Read(ctx, ref); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("read missing: err = %v, want ErrNotFound", err)
	}

	v, err := c.Write(ctx, ref, map[string]any{"username": "orders_app", "password": "one", "host": "pg"}, 0)
	if err != nil || v != 1 {
		t.Fatalf("create: version = %d, err = %v", v, err)
	}
	if _, err := c.Write(ctx, ref, map[string]any{"password": "x"}, 0); !errors.Is(err, vault.ErrCASMismatch) {
		t.Fatalf("create over existing: err = %v, want ErrCASMismatch", err)
	}

	s, err := c.Read(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 1 || s.Data["password"] != "one" || s.Data["host"] != "pg" {
		t.Fatalf("read = %+v", s)
	}

	s.Data["password"] = "two"
	if v, err = c.Write(ctx, ref, s.Data, s.Version); err != nil || v != 2 {
		t.Fatalf("update: version = %d, err = %v", v, err)
	}
	if _, err := c.Write(ctx, ref, s.Data, s.Version); !errors.Is(err, vault.ErrCASMismatch) {
		t.Fatalf("stale update: err = %v, want ErrCASMismatch", err)
	}

	s, err = c.Read(ctx, ref)
	if err != nil || s.Version != 2 || s.Data["password"] != "two" || s.Data["username"] != "orders_app" {
		t.Fatalf("read after update = %+v, err = %v", s, err)
	}
}

func TestKVv2DeletedLatestVersion(t *testing.T) {
	ctx := t.Context()
	c := rootClient(t)
	ref := vault.SecretRef{Mount: "secret", Path: "apps/deleted", KVVersion: 2}

	if _, err := c.Write(ctx, ref, map[string]any{"password": "one"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := rawRoot(t).KVv2("secret").Delete(ctx, "apps/deleted"); err != nil {
		t.Fatal(err)
	}

	s, err := c.Read(ctx, ref)
	if err != nil {
		t.Fatalf("read deleted: %v", err)
	}
	if len(s.Data) != 0 || s.Version != 1 {
		t.Fatalf("read deleted = %+v, want empty data at version 1", s)
	}
	if v, err := c.Write(ctx, ref, map[string]any{"password": "two"}, s.Version); err != nil || v != 2 {
		t.Fatalf("write over deleted: version = %d, err = %v", v, err)
	}
}

func TestKVv1(t *testing.T) {
	ctx := t.Context()
	c := rootClient(t)
	ref := vault.SecretRef{Mount: "kv1", Path: "apps/orders/db", KVVersion: 1}

	if _, err := c.Read(ctx, ref); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("read missing: err = %v, want ErrNotFound", err)
	}
	if _, err := c.Write(ctx, ref, map[string]any{"password": "one"}, 12345); err != nil {
		t.Fatalf("write (cas ignored for v1): %v", err)
	}
	s, err := c.Read(ctx, ref)
	if err != nil || s.Version != 0 || s.Data["password"] != "one" {
		t.Fatalf("read = %+v, err = %v", s, err)
	}
}

func TestPermissionDeniedAndTokenTTL(t *testing.T) {
	ctx := t.Context()
	root := rawRoot(t)
	if err := root.Sys().PutPolicyWithContext(ctx, "read-only", `path "secret/data/ro/*" { capabilities = ["read"] }`); err != nil {
		t.Fatal(err)
	}
	tok, err := root.Auth().Token().CreateWithContext(ctx, &vaultapi.TokenCreateRequest{
		Policies: []string{"read-only"},
		TTL:      "1h",
	})
	if err != nil {
		t.Fatal(err)
	}

	c, err := vault.New(ctx, vault.Config{Address: vaultAddr, Auth: &vault.TokenAuth{Token: tok.Auth.ClientToken}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if exp := time.Until(c.ExpiresAt()); exp < 59*time.Minute || exp > time.Hour {
		t.Fatalf("ExpiresAt in %v, want ~1h", exp)
	}

	ref := vault.SecretRef{Mount: "secret", Path: "ro/app", KVVersion: 2}
	_, err = c.Write(ctx, ref, map[string]any{"password": "x"}, 0)
	if !vault.IsPermissionDenied(err) {
		t.Fatalf("write without policy: err = %v, want permission denied", err)
	}
}

func TestDeleteDestroysAllVersions(t *testing.T) {
	ctx := t.Context()
	c := rootClient(t)
	for _, ref := range []vault.SecretRef{
		{Mount: "secret", Path: "krotos/pending/default/x", KVVersion: 2},
		{Mount: "kv1", Path: "krotos/pending/default/x", KVVersion: 1},
	} {
		v, err := c.Write(ctx, ref, map[string]any{"newPassword": "one"}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(ctx, ref, map[string]any{"newPassword": "two"}, v); err != nil {
			t.Fatal(err)
		}
		if err := c.Delete(ctx, ref); err != nil {
			t.Fatalf("%s: delete: %v", ref, err)
		}
		if _, err := c.Read(ctx, ref); !errors.Is(err, vault.ErrNotFound) {
			t.Fatalf("%s: read after delete: err = %v, want ErrNotFound", ref, err)
		}
		if err := c.Delete(ctx, ref); err != nil {
			t.Fatalf("%s: deleting a missing secret: %v", ref, err)
		}
	}
	// No KV v2 version survives, not even as a soft-deleted one.
	if _, err := rawRoot(t).KVv2("secret").GetVersion(ctx, "krotos/pending/default/x", 1); err == nil {
		t.Fatal("version 1 still readable after delete")
	}
}
