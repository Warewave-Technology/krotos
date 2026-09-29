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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	k8sauth "github.com/hashicorp/vault/api/auth/kubernetes"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Authenticator logs a Vault client in.
type Authenticator interface {
	// Login sets a token on c and returns its TTL (0 if it does not expire).
	Login(ctx context.Context, c *vaultapi.Client) (time.Duration, error)
	// Fingerprint identifies the credentials, without revealing them, so cached
	// clients are replaced when the credentials change.
	Fingerprint() string
}

// TokenAuth uses a static Vault token.
type TokenAuth struct {
	Token string
}

// Login implements Authenticator.
func (a *TokenAuth) Login(ctx context.Context, c *vaultapi.Client) (time.Duration, error) {
	token := strings.TrimSpace(a.Token)
	if token == "" {
		return 0, errors.New("empty token")
	}
	c.SetToken(token)
	s, err := c.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("token lookup: %w", err)
	}
	ttl, err := s.TokenTTL()
	if err != nil {
		return 0, fmt.Errorf("token ttl: %w", err)
	}
	return ttl, nil
}

// Fingerprint implements Authenticator.
func (a *TokenAuth) Fingerprint() string {
	return "token:" + hash(strings.TrimSpace(a.Token))
}

// ServiceAccountTokenSource issues Kubernetes ServiceAccount tokens.
type ServiceAccountTokenSource interface {
	// Token returns a token for the given audience; an empty audience means the
	// token mounted into the pod.
	Token(ctx context.Context, audience string) (string, error)
}

// KubernetesAuth uses Vault's Kubernetes auth method with the operator's ServiceAccount.
type KubernetesAuth struct {
	Role      string
	MountPath string
	Audience  string
	Tokens    ServiceAccountTokenSource
}

// Login implements Authenticator.
func (a *KubernetesAuth) Login(ctx context.Context, c *vaultapi.Client) (time.Duration, error) {
	jwt, err := a.Tokens.Token(ctx, a.Audience)
	if err != nil {
		return 0, fmt.Errorf("service account token: %w", err)
	}
	opts := []k8sauth.LoginOption{k8sauth.WithServiceAccountToken(jwt)}
	if a.MountPath != "" {
		opts = append(opts, k8sauth.WithMountPath(a.MountPath))
	}
	method, err := k8sauth.NewKubernetesAuth(a.Role, opts...)
	if err != nil {
		return 0, err
	}
	s, err := c.Auth().Login(ctx, method)
	if err != nil {
		return 0, err
	}
	if s == nil || s.Auth == nil {
		return 0, errors.New("kubernetes login returned no auth info")
	}
	return time.Duration(s.Auth.LeaseDuration) * time.Second, nil
}

// Fingerprint implements Authenticator. The ServiceAccount token itself rotates
// and is not part of the fingerprint; expiry handles re-login.
func (a *KubernetesAuth) Fingerprint() string {
	return fmt.Sprintf("kubernetes:%s:%s:%s", a.MountPath, a.Role, a.Audience)
}

// DefaultServiceAccountTokenPath is where Kubernetes mounts the pod's token.
const DefaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // a path, not a credential

// PodServiceAccountTokens issues tokens for the operator's own ServiceAccount.
// Without an audience it reads the mounted token; with one it uses the TokenRequest API.
type PodServiceAccountTokens struct {
	Client         client.Client
	Namespace      string
	ServiceAccount string
	// TokenPath overrides DefaultServiceAccountTokenPath.
	TokenPath string
}

// Token implements ServiceAccountTokenSource.
func (s *PodServiceAccountTokens) Token(ctx context.Context, audience string) (string, error) {
	if audience == "" {
		path := s.TokenPath
		if path == "" {
			path = DefaultServiceAccountTokenPath
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read mounted token: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}

	if s.ServiceAccount == "" {
		return "", errors.New("operator service account name is unknown; set POD_SERVICE_ACCOUNT")
	}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: s.ServiceAccount, Namespace: s.Namespace}}
	req := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: new(int64(600)),
		},
	}
	if err := s.Client.SubResource("token").Create(ctx, sa, req); err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	return req.Status.Token, nil
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
