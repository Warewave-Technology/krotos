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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	krotosv1alpha1 "github.com/warewave/krotos/api/v1alpha1"
)

// ConfigError means a VaultConnection cannot be turned into a client configuration,
// e.g. because a referenced Secret is missing. Retrying does not help until the
// user fixes the configuration.
type ConfigError struct {
	Err error
}

func (e *ConfigError) Error() string { return e.Err.Error() }
func (e *ConfigError) Unwrap() error { return e.Err }

// IsConfigError reports whether err is a ConfigError.
func IsConfigError(err error) bool {
	var ce *ConfigError
	return errors.As(err, &ce)
}

// Resolver turns VaultConnection resources into logged-in clients.
type Resolver struct {
	// Reader reads referenced Secrets. Use an uncached reader so the operator does
	// not keep every Secret of the namespace in memory.
	Reader   client.Reader
	Tokens   ServiceAccountTokenSource
	Provider *Provider
}

// Config builds the client configuration for conn.
func (r *Resolver) Config(ctx context.Context, conn *krotosv1alpha1.VaultConnection) (Config, error) {
	spec := conn.Spec
	cfg := Config{Address: spec.Address, Namespace: spec.Namespace}

	if spec.TLS != nil {
		cfg.InsecureSkipVerify = spec.TLS.InsecureSkipVerify
		if spec.TLS.CASecretRef != nil {
			ca, err := ReadSecretKey(ctx, r.Reader, conn.Namespace, *spec.TLS.CASecretRef)
			if err != nil {
				return Config{}, err
			}
			cfg.CACert = ca
		}
	}

	switch {
	case spec.Auth.Kubernetes != nil:
		k := spec.Auth.Kubernetes
		mount := k.MountPath
		if mount == "" {
			mount = "kubernetes"
		}
		cfg.Auth = &KubernetesAuth{Role: k.Role, MountPath: mount, Audience: k.Audience, Tokens: r.Tokens}
	case spec.Auth.Token != nil:
		token, err := ReadSecretKey(ctx, r.Reader, conn.Namespace, spec.Auth.Token.SecretRef)
		if err != nil {
			return Config{}, err
		}
		cfg.Auth = &TokenAuth{Token: string(token)}
	default:
		return Config{}, &ConfigError{errors.New("no authentication method configured")}
	}
	return cfg, nil
}

// Client returns a logged-in client for conn.
func (r *Resolver) Client(ctx context.Context, conn *krotosv1alpha1.VaultConnection) (*Client, Config, error) {
	cfg, err := r.Config(ctx, conn)
	if err != nil {
		return nil, Config{}, err
	}
	c, err := r.Provider.Get(ctx, cfg)
	if err != nil {
		return nil, cfg, err
	}
	return c, cfg, nil
}

// ReadSecretKey returns one key of a Secret. Missing Secrets or keys are ConfigErrors.
func ReadSecretKey(ctx context.Context, reader client.Reader, namespace string, ref krotosv1alpha1.SecretKeyReference) ([]byte, error) {
	var s corev1.Secret
	if err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, &s); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, &ConfigError{fmt.Errorf("secret %q not found", ref.Name)}
		}
		return nil, fmt.Errorf("get secret %q: %w", ref.Name, err)
	}
	v, ok := s.Data[ref.Key]
	if !ok || len(v) == 0 {
		return nil, &ConfigError{fmt.Errorf("secret %q has no key %q", ref.Name, ref.Key)}
	}
	return v, nil
}
