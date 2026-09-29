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
	"fmt"
	"sync"

	"github.com/warewave/krotos/internal/vault"
)

const (
	keyOldPassword   = "oldPassword"
	keyNewPassword   = "newPassword"
	keyFailureReason = "failureReason"
)

// DefaultPendingPath is where a rotation's pending passwords live when the spec
// does not say otherwise.
func DefaultPendingPath(namespace, name string) string {
	return fmt.Sprintf("krotos/pending/%s/%s", namespace, name)
}

// VaultPendingStore keeps Pending in Vault, so passwords are never stored in
// Kubernetes. Delete destroys all versions of the secret.
type VaultPendingStore struct {
	Vault SecretStore
	Ref   vault.SecretRef
}

var _ PendingStore = (*VaultPendingStore)(nil)

// Load implements PendingStore.
func (s *VaultPendingStore) Load(ctx context.Context) (*Pending, error) {
	sec, err := s.Vault.Read(ctx, s.Ref)
	if errors.Is(err, vault.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := &Pending{}
	p.OldPassword, _ = sec.Data[keyOldPassword].(string)
	p.NewPassword, _ = sec.Data[keyNewPassword].(string)
	p.FailureReason, _ = sec.Data[keyFailureReason].(string)
	if p.OldPassword == "" || p.NewPassword == "" {
		// A soft-deleted KV v2 secret reads as empty data.
		return nil, nil
	}
	return p, nil
}

// Save implements PendingStore.
func (s *VaultPendingStore) Save(ctx context.Context, p *Pending) error {
	version := 0
	cur, err := s.Vault.Read(ctx, s.Ref)
	switch {
	case err == nil:
		version = cur.Version
	case !errors.Is(err, vault.ErrNotFound):
		return err
	}
	_, err = s.Vault.Write(ctx, s.Ref, map[string]any{
		keyOldPassword:   p.OldPassword,
		keyNewPassword:   p.NewPassword,
		keyFailureReason: p.FailureReason,
	}, version)
	return err
}

// Delete implements PendingStore.
func (s *VaultPendingStore) Delete(ctx context.Context) error {
	return s.Vault.Delete(ctx, s.Ref)
}

// PendingCache keeps pending rotations in memory, keyed by the rotation's UID.
// It lets a rotation roll back while Vault is unreachable, as long as the
// operator has not restarted.
type PendingCache struct {
	m sync.Map
}

// CachedPendingStore reads through a PendingCache and writes to both the cache
// and the durable store. The durable store is authoritative: a Save or Delete
// only takes effect in the cache once it succeeded there.
type CachedPendingStore struct {
	Inner PendingStore
	Cache *PendingCache
	Key   string
}

var _ PendingStore = (*CachedPendingStore)(nil)

// Load implements PendingStore.
func (s *CachedPendingStore) Load(ctx context.Context) (*Pending, error) {
	if v, ok := s.Cache.m.Load(s.Key); ok {
		cp := *v.(*Pending)
		return &cp, nil
	}
	p, err := s.Inner.Load(ctx)
	if err != nil || p == nil {
		return p, err
	}
	cp := *p
	s.Cache.m.Store(s.Key, &cp)
	return p, nil
}

// Save implements PendingStore.
func (s *CachedPendingStore) Save(ctx context.Context, p *Pending) error {
	if err := s.Inner.Save(ctx, p); err != nil {
		return err
	}
	cp := *p
	s.Cache.m.Store(s.Key, &cp)
	return nil
}

// Delete implements PendingStore.
func (s *CachedPendingStore) Delete(ctx context.Context) error {
	if err := s.Inner.Delete(ctx); err != nil {
		return err
	}
	s.Cache.m.Delete(s.Key)
	return nil
}
