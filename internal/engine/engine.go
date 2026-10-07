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

// Package engine defines how the operator talks to a database engine.
package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
)

// ConnectTimeout bounds how long a connection attempt may take.
const ConnectTimeout = 10 * time.Second

// Endpoint is a database server.
type Endpoint struct {
	Host     string
	Port     int32
	Database string
	TLSMode  krotosv1alpha1.TLSMode
	// CACert is a PEM bundle, required for verify-ca and verify-full.
	CACert []byte
	// ClickHouseCluster runs statements ON CLUSTER when set.
	ClickHouseCluster string
	// ClickHouseProtocol is "native" or "http".
	ClickHouseProtocol string
}

// Credentials is a username and password. Its String method hides the password.
type Credentials struct {
	Username string
	Password string
}

func (c Credentials) String() string {
	return fmt.Sprintf("Credentials{Username: %q, Password: <redacted>}", c.Username)
}

// GoString hides the password from %#v.
func (c Credentials) GoString() string { return c.String() }

// Account identifies the database user whose password is rotated.
type Account struct {
	Username string
	// MySQLHost is the host part of a MySQL account.
	MySQLHost string
}

// Engine changes and verifies passwords on one database engine.
// Implementations must never include passwords in returned errors.
type Engine interface {
	// SetPassword changes account's password to password, connecting as master.
	SetPassword(ctx context.Context, ep Endpoint, master Credentials, account Account, password string) error
	// VerifyLogin connects as creds and runs a trivial query.
	VerifyLogin(ctx context.Context, ep Endpoint, creds Credentials) error
}

// TLSConfig builds the client TLS configuration for ep. It returns nil when TLS is disabled.
func TLSConfig(ep Endpoint) (*tls.Config, error) {
	mode := ep.TLSMode
	if mode == "" {
		mode = krotosv1alpha1.TLSModeDisable
	}
	if mode == krotosv1alpha1.TLSModeDisable {
		return nil, nil
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: ep.Host}
	var roots *x509.CertPool
	if len(ep.CACert) > 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ep.CACert) {
			return nil, errors.New("CA bundle contains no PEM certificates")
		}
	}

	switch mode {
	case krotosv1alpha1.TLSModeRequire:
		// Encrypt without verifying, like libpq's sslmode=require.
		cfg.InsecureSkipVerify = true //nolint:gosec // explicit user choice
	case krotosv1alpha1.TLSModeVerifyCA:
		if roots == nil {
			return nil, errors.New("verify-ca requires a CA bundle")
		}
		// Verify the chain but not the host name.
		cfg.InsecureSkipVerify = true //nolint:gosec // chain is verified below
		cfg.VerifyPeerCertificate = verifyChain(roots)
	case krotosv1alpha1.TLSModeVerifyFull:
		if roots == nil {
			return nil, errors.New("verify-full requires a CA bundle")
		}
		cfg.RootCAs = roots
	default:
		return nil, fmt.Errorf("unknown TLS mode %q", mode)
	}
	return cfg, nil
}

func verifyChain(roots *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("server sent no certificate")
		}
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, raw := range rawCerts {
			c, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			certs = append(certs, c)
		}
		opts := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool()}
		for _, c := range certs[1:] {
			opts.Intermediates.AddCert(c)
		}
		_, err := certs[0].Verify(opts)
		return err
	}
}
