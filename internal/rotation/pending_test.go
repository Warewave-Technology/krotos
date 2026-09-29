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

package rotation

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/warewave/krotos/internal/engine"
	"github.com/warewave/krotos/internal/vault"
)

// kvStore is a multi-path KV v2 fake that can be switched off.
type kvStore struct {
	secrets map[string]*vault.Secret
	down    bool
}

var errVaultDown = errors.New("vault unavailable")

func (k *kvStore) Read(_ context.Context, ref vault.SecretRef) (*vault.Secret, error) {
	if k.down {
		return nil, errVaultDown
	}
	s, ok := k.secrets[ref.Path]
	if !ok {
		return nil, vault.ErrNotFound
	}
	return &vault.Secret{Data: maps.Clone(s.Data), Version: s.Version}, nil
}

func (k *kvStore) Write(_ context.Context, ref vault.SecretRef, data map[string]any, cas int) (int, error) {
	if k.down {
		return 0, errVaultDown
	}
	cur := 0
	if s, ok := k.secrets[ref.Path]; ok {
		cur = s.Version
	}
	if cas != cur {
		return 0, vault.ErrCASMismatch
	}
	k.secrets[ref.Path] = &vault.Secret{Data: data, Version: cur + 1}
	return cur + 1, nil
}

func (k *kvStore) Delete(_ context.Context, ref vault.SecretRef) error {
	if k.down {
		return errVaultDown
	}
	delete(k.secrets, ref.Path)
	return nil
}

func TestVaultPendingStore(t *testing.T) {
	ctx := t.Context()
	kv := &kvStore{secrets: map[string]*vault.Secret{}}
	s := &VaultPendingStore{Vault: kv, Ref: vault.SecretRef{Mount: "secret", Path: DefaultPendingPath("ns", "rot"), KVVersion: 2}}

	if p, err := s.Load(ctx); p != nil || err != nil {
		t.Fatalf("empty: %v, %v", p, err)
	}
	want := &Pending{OldPassword: "old", NewPassword: "new"}
	if err := s.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	// Saving again overwrites (check-and-set against the current version).
	want.FailureReason = "boom"
	if err := s.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx)
	if err != nil || *got != *want {
		t.Fatalf("Load = %+v, %v; want %+v", got, err, want)
	}
	if kv.secrets["krotos/pending/ns/rot"] == nil {
		t.Fatalf("stored at %v, want the default path", maps.Keys(kv.secrets))
	}
	if err := s.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Load(ctx); p != nil {
		t.Fatalf("after Delete: %+v", p)
	}
}

func TestVaultPendingStoreTreatsEmptyDataAsMissing(t *testing.T) {
	kv := &kvStore{secrets: map[string]*vault.Secret{"p": {Data: map[string]any{}, Version: 4}}}
	s := &VaultPendingStore{Vault: kv, Ref: vault.SecretRef{Path: "p", KVVersion: 2}}
	if p, err := s.Load(t.Context()); p != nil || err != nil {
		t.Fatalf("Load = %v, %v", p, err)
	}
}

func TestCachedPendingStoreSurvivesVaultOutage(t *testing.T) {
	ctx := t.Context()
	kv := &kvStore{secrets: map[string]*vault.Secret{}}
	cache := &PendingCache{}
	s := &CachedPendingStore{
		Inner: &VaultPendingStore{Vault: kv, Ref: vault.SecretRef{Path: "p", KVVersion: 2}},
		Cache: cache,
		Key:   "uid-1",
	}
	if err := s.Save(ctx, &Pending{OldPassword: "old", NewPassword: "new"}); err != nil {
		t.Fatal(err)
	}

	kv.down = true
	p, err := s.Load(ctx)
	if err != nil || p.OldPassword != "old" {
		t.Fatalf("Load during outage = %+v, %v", p, err)
	}
	// A failed durable write must not change the cache.
	if err := s.Save(ctx, &Pending{OldPassword: "x", NewPassword: "y"}); err == nil {
		t.Fatal("Save during outage succeeded")
	}
	if p, _ := s.Load(ctx); p.NewPassword != "new" {
		t.Fatalf("cache changed by a failed Save: %+v", p)
	}
	if err := s.Delete(ctx); err == nil {
		t.Fatal("Delete during outage succeeded")
	}

	kv.down = false
	if err := s.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Load(ctx); p != nil {
		t.Fatalf("after Delete: %+v", p)
	}
}

func TestCachedPendingStoreLoadsAfterRestart(t *testing.T) {
	ctx := t.Context()
	kv := &kvStore{secrets: map[string]*vault.Secret{}}
	inner := &VaultPendingStore{Vault: kv, Ref: vault.SecretRef{Path: "p", KVVersion: 2}}
	if err := inner.Save(ctx, &Pending{OldPassword: "old", NewPassword: "new"}); err != nil {
		t.Fatal(err)
	}
	// A new process starts with an empty cache.
	s := &CachedPendingStore{Inner: inner, Cache: &PendingCache{}, Key: "uid-1"}
	if p, err := s.Load(ctx); err != nil || p.NewPassword != "new" {
		t.Fatalf("Load = %+v, %v", p, err)
	}
}

// hookDB runs afterSet after each successful SetPassword.
type hookDB struct {
	*fakeDB
	afterSet func(password string)
}

func (h *hookDB) SetPassword(ctx context.Context, ep engine.Endpoint, m engine.Credentials, a engine.Account, pw string) error {
	if err := h.fakeDB.SetPassword(ctx, ep, m, a, pw); err != nil {
		return err
	}
	h.afterSet(pw)
	return nil
}

func TestRollbackWhileVaultIsDown(t *testing.T) {
	f := newFixture()
	kv := &kvStore{secrets: map[string]*vault.Secret{
		"apps/orders": {Data: map[string]any{"password": oldPassword}, Version: 1},
	}}
	f.target.Vault = kv
	f.target.VaultRef = vault.SecretRef{Path: "apps/orders", KVVersion: 2}
	f.target.Pending = &CachedPendingStore{
		Inner: &VaultPendingStore{Vault: kv, Ref: vault.SecretRef{Path: "pending", KVVersion: 2}},
		Cache: &PendingCache{},
		Key:   "uid-1",
	}

	// Vault goes away right after the database was changed.
	f.target.Engine = &hookDB{fakeDB: f.db, afterSet: func(pw string) {
		if pw == newPassword {
			kv.down = true
		}
	}}

	var res Result
	for range maxVaultRetries {
		res = f.run(t)
	}
	if res.Outcome != OutcomeFailed || !res.RolledBack {
		t.Fatalf("outcome = %s rolledBack=%v (%s)", res.Outcome, res.RolledBack, res.Message)
	}
	if f.db.passwords[user] != oldPassword {
		t.Fatalf("database password = %q, want the old one restored", f.db.passwords[user])
	}
}
