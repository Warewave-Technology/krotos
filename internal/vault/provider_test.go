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

package vault

import (
	"context"
	"errors"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

type fakeAuth struct{ fp string }

func (f *fakeAuth) Login(context.Context, *vaultapi.Client) (time.Duration, error) { return 0, nil }
func (f *fakeAuth) Fingerprint() string                                            { return f.fp }

// countingProvider returns a Provider whose clients expire after ttl (0 = never)
// and counts logins.
func countingProvider(now *time.Time, ttl time.Duration) (*Provider, *int) {
	logins := 0
	p := NewProvider()
	p.now = func() time.Time { return *now }
	p.newClient = func(context.Context, Config) (*Client, error) {
		logins++
		c := &Client{}
		if ttl > 0 {
			c.expiresAt = now.Add(ttl)
		}
		return c, nil
	}
	return p, &logins
}

func TestProviderCachesPerConfiguration(t *testing.T) {
	now := time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC)
	p, logins := countingProvider(&now, 0)
	cfgA := Config{Address: "https://a", Auth: &fakeAuth{"token:1"}}
	cfgB := Config{Address: "https://b", Auth: &fakeAuth{"token:1"}}

	c1, _ := p.Get(t.Context(), cfgA)
	c2, _ := p.Get(t.Context(), cfgA)
	if c1 != c2 || *logins != 1 {
		t.Fatalf("same config: logins = %d, same client = %v", *logins, c1 == c2)
	}

	if _, err := p.Get(t.Context(), cfgB); err != nil || *logins != 2 {
		t.Fatalf("other address: logins = %d, err = %v", *logins, err)
	}

	// Rotated credentials produce a new fingerprint and a new login.
	cfgA.Auth = &fakeAuth{"token:2"}
	if _, err := p.Get(t.Context(), cfgA); err != nil || *logins != 3 {
		t.Fatalf("new credentials: logins = %d, err = %v", *logins, err)
	}

	cfgA.CACert = []byte("-----BEGIN CERTIFICATE-----")
	if _, err := p.Get(t.Context(), cfgA); err != nil || *logins != 4 {
		t.Fatalf("new CA: logins = %d, err = %v", *logins, err)
	}
}

func TestProviderRenewsBeforeExpiry(t *testing.T) {
	now := time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC)
	p, logins := countingProvider(&now, time.Hour)
	cfg := Config{Address: "https://a", Auth: &fakeAuth{"k"}}

	_, _ = p.Get(t.Context(), cfg)
	now = now.Add(50 * time.Minute)
	_, _ = p.Get(t.Context(), cfg)
	if *logins != 1 {
		t.Fatalf("logins after 50m = %d, want 1", *logins)
	}
	now = now.Add(6 * time.Minute) // 4m left, below renewBefore
	_, _ = p.Get(t.Context(), cfg)
	if *logins != 2 {
		t.Fatalf("logins close to expiry = %d, want 2", *logins)
	}
}

func TestProviderInvalidate(t *testing.T) {
	now := time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC)
	p, logins := countingProvider(&now, 0)
	cfg := Config{Address: "https://a", Auth: &fakeAuth{"k"}}

	_, _ = p.Get(t.Context(), cfg)
	p.Invalidate(cfg)
	_, _ = p.Get(t.Context(), cfg)
	if *logins != 2 {
		t.Fatalf("logins after Invalidate = %d, want 2", *logins)
	}
}

func TestProviderDoesNotCacheFailures(t *testing.T) {
	p := NewProvider()
	calls := 0
	p.newClient = func(context.Context, Config) (*Client, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("vault down")
		}
		return &Client{}, nil
	}
	cfg := Config{Address: "https://a", Auth: &fakeAuth{"k"}}
	if _, err := p.Get(t.Context(), cfg); err == nil {
		t.Fatal("expected error")
	}
	if _, err := p.Get(t.Context(), cfg); err != nil {
		t.Fatalf("second attempt: %v", err)
	}
}
