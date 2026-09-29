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
	"fmt"
	"sync"
	"time"
)

// renewBefore is how long before token expiry a cached client is replaced.
// Rotations must not run into an expiring token half way.
const renewBefore = 5 * time.Minute

// Provider caches logged-in clients per configuration, so reconciles do not log
// in every time. A client is replaced when the configuration or credentials
// change, or when its token is about to expire.
type Provider struct {
	mu      sync.Mutex
	clients map[string]*Client

	// Overridable for tests.
	now       func() time.Time
	newClient func(context.Context, Config) (*Client, error)
}

// NewProvider returns an empty Provider.
func NewProvider() *Provider {
	return &Provider{
		clients:   map[string]*Client{},
		now:       time.Now,
		newClient: New,
	}
}

// Get returns a logged-in client for cfg.
func (p *Provider) Get(ctx context.Context, cfg Config) (*Client, error) {
	key := fingerprint(cfg)

	p.mu.Lock()
	defer p.mu.Unlock()

	if c, ok := p.clients[key]; ok && p.usable(c) {
		return c, nil
	}
	c, err := p.newClient(ctx, cfg)
	if err != nil {
		delete(p.clients, key)
		return nil, err
	}
	p.evictExpired()
	p.clients[key] = c
	return c, nil
}

// Invalidate drops the cached client for cfg, e.g. after a permission error.
func (p *Provider) Invalidate(cfg Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.clients, fingerprint(cfg))
}

func (p *Provider) usable(c *Client) bool {
	exp := c.ExpiresAt()
	return exp.IsZero() || p.now().Add(renewBefore).Before(exp)
}

func (p *Provider) evictExpired() {
	for k, c := range p.clients {
		if !p.usable(c) {
			delete(p.clients, k)
		}
	}
}

func fingerprint(cfg Config) string {
	auth := ""
	if cfg.Auth != nil {
		auth = cfg.Auth.Fingerprint()
	}
	return hash(fmt.Sprintf("%s\x00%s\x00%s\x00%t\x00%s",
		cfg.Address, cfg.Namespace, hash(string(cfg.CACert)), cfg.InsecureSkipVerify, auth))
}
