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

// Package vault is a small Vault client covering what the operator needs:
// logging in and reading/writing KV v1 and v2 secrets.
package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// ErrNotFound is returned when a secret does not exist.
var ErrNotFound = errors.New("vault secret not found")

// ErrCASMismatch is returned when a KV v2 check-and-set write lost a race.
var ErrCASMismatch = errors.New("vault check-and-set version mismatch")

// Config describes how to reach and authenticate to Vault.
type Config struct {
	Address            string
	Namespace          string
	CACert             []byte
	InsecureSkipVerify bool
	Auth               Authenticator
}

// SecretRef locates a secret in a KV secrets engine.
type SecretRef struct {
	Mount string
	// Path inside the mount, without the KV v2 "data/" prefix.
	Path      string
	KVVersion int
}

func (r SecretRef) String() string {
	return fmt.Sprintf("%s/%s (kv v%d)", r.Mount, r.Path, r.KVVersion)
}

// Secret is the content of a KV secret.
type Secret struct {
	Data map[string]any
	// Version is the KV v2 version, 0 for KV v1. Pass it to Write for check-and-set.
	Version int
}

// Client is an authenticated Vault client.
type Client struct {
	api *vaultapi.Client
	// expiresAt is when the token expires; zero if it does not.
	expiresAt time.Time
}

// New creates a client and logs in.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Auth == nil {
		return nil, errors.New("vault: no authentication method configured")
	}

	apiCfg := vaultapi.DefaultConfig()
	if apiCfg.Error != nil {
		return nil, fmt.Errorf("vault: default config: %w", apiCfg.Error)
	}
	apiCfg.Address = cfg.Address
	apiCfg.Timeout = 30 * time.Second
	// Retries are the controller's job; keep calls predictable.
	apiCfg.MaxRetries = 0
	tlsCfg := &vaultapi.TLSConfig{Insecure: cfg.InsecureSkipVerify}
	if len(cfg.CACert) > 0 {
		tlsCfg.CACertBytes = cfg.CACert
	}
	if err := apiCfg.ConfigureTLS(tlsCfg); err != nil {
		return nil, fmt.Errorf("vault: configure TLS: %w", err)
	}

	api, err := vaultapi.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("vault: new client: %w", err)
	}
	// Never pick up VAULT_TOKEN / VAULT_NAMESPACE from the operator's environment.
	api.ClearToken()
	api.ClearNamespace()
	if cfg.Namespace != "" {
		api.SetNamespace(cfg.Namespace)
	}

	ttl, err := cfg.Auth.Login(ctx, api)
	if err != nil {
		return nil, fmt.Errorf("vault: login: %w", err)
	}
	c := &Client{api: api}
	if ttl > 0 {
		c.expiresAt = time.Now().Add(ttl)
	}
	return c, nil
}

// ExpiresAt is when the client's token expires; zero if it does not.
func (c *Client) ExpiresAt() time.Time {
	return c.expiresAt
}

// LookupSelf verifies that the client's token is valid.
func (c *Client) LookupSelf(ctx context.Context) error {
	if _, err := c.api.Auth().Token().LookupSelfWithContext(ctx); err != nil {
		return fmt.Errorf("vault: token lookup: %w", err)
	}
	return nil
}

// Read returns the secret at ref. It returns ErrNotFound if the secret does not exist.
// For KV v2, a secret whose latest version is deleted is returned with empty data and
// its version, so it can be overwritten with check-and-set.
func (c *Client) Read(ctx context.Context, ref SecretRef) (*Secret, error) {
	switch ref.KVVersion {
	case 1:
		s, err := c.api.KVv1(ref.Mount).Get(ctx, ref.Path)
		if err != nil {
			return nil, wrapErr("read", ref, err)
		}
		return &Secret{Data: nonNil(s.Data)}, nil
	case 2:
		s, err := c.api.KVv2(ref.Mount).Get(ctx, ref.Path)
		if err != nil {
			return nil, wrapErr("read", ref, err)
		}
		out := &Secret{Data: nonNil(s.Data)}
		if s.VersionMetadata != nil {
			out.Version = s.VersionMetadata.Version
		}
		return out, nil
	default:
		return nil, fmt.Errorf("vault: unsupported kv version %d", ref.KVVersion)
	}
}

// Write replaces the secret at ref with data. For KV v2 the write only succeeds if
// the current version equals casVersion (0 means the secret must not exist);
// otherwise ErrCASMismatch is returned. casVersion is ignored for KV v1.
// It returns the new version (0 for KV v1).
func (c *Client) Write(ctx context.Context, ref SecretRef, data map[string]any, casVersion int) (int, error) {
	switch ref.KVVersion {
	case 1:
		if err := c.api.KVv1(ref.Mount).Put(ctx, ref.Path, data); err != nil {
			return 0, wrapErr("write", ref, err)
		}
		return 0, nil
	case 2:
		s, err := c.api.KVv2(ref.Mount).Put(ctx, ref.Path, data, vaultapi.WithCheckAndSet(casVersion))
		if err != nil {
			return 0, wrapErr("write", ref, err)
		}
		if s.VersionMetadata == nil {
			return 0, nil
		}
		return s.VersionMetadata.Version, nil
	default:
		return 0, fmt.Errorf("vault: unsupported kv version %d", ref.KVVersion)
	}
}

// Delete removes the secret at ref. For KV v2 it deletes the metadata, which
// destroys every version; a plain delete would only soft-delete the latest one.
// Deleting a missing secret is not an error.
func (c *Client) Delete(ctx context.Context, ref SecretRef) error {
	var err error
	switch ref.KVVersion {
	case 1:
		err = c.api.KVv1(ref.Mount).Delete(ctx, ref.Path)
	case 2:
		err = c.api.KVv2(ref.Mount).DeleteMetadata(ctx, ref.Path)
	default:
		return fmt.Errorf("vault: unsupported kv version %d", ref.KVVersion)
	}
	if err != nil {
		return wrapErr("delete", ref, err)
	}
	return nil
}

func wrapErr(op string, ref SecretRef, err error) error {
	switch {
	case errors.Is(err, vaultapi.ErrSecretNotFound):
		return fmt.Errorf("vault: %s %s: %w", op, ref, ErrNotFound)
	case isCASMismatch(err):
		return fmt.Errorf("vault: %s %s: %w", op, ref, ErrCASMismatch)
	default:
		return fmt.Errorf("vault: %s %s: %w", op, ref, err)
	}
}

func isCASMismatch(err error) bool {
	var respErr *vaultapi.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	for _, e := range respErr.Errors {
		if strings.Contains(e, "check-and-set") {
			return true
		}
	}
	return false
}

// IsPermissionDenied reports whether err is a Vault 403, e.g. because the token
// was revoked or lacks a policy.
func IsPermissionDenied(err error) bool {
	var respErr *vaultapi.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == 403
}

func nonNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
