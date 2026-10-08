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

// Package nats implements engine.Engine for NATS users in JWT/NKey (operator) mode.
//
// The server keeps no users: it accepts any user JWT signed by a key of the
// account that is neither expired nor revoked. Rotating therefore means issuing a
// new user (new NKey, new JWT with the old one's claims) signed by the account
// signing key held as the master credentials, and nothing is changed on the
// server. The old credentials stop working when they expire, which is why every
// issued JWT carries an expiry.
//
// The secret is a .creds file (user JWT and NKey seed); the master password is
// the account signing key's seed. The master username is not used.
package nats

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/Warewave-Technology/krotos/internal/engine"
)

// Engine is the NATS engine.
type Engine struct {
	// Now is overridable for tests.
	Now func() time.Time
}

var (
	_ engine.Engine      = Engine{}
	_ engine.Issuer      = Engine{}
	_ engine.Expirer     = Engine{}
	_ engine.Preflighter = Engine{}
)

// Preflight implements engine.Preflighter: the master password must be an account seed.
func (Engine) Preflight(_ context.Context, ep engine.Endpoint, master engine.Credentials) error {
	if _, err := accountKey(master); err != nil {
		return err
	}
	if ep.NATSCredentialsTTL <= 0 {
		return errors.New("database.nats.credentialsTTL must be set")
	}
	return nil
}

// Issue implements engine.Issuer. The new user keeps the current user's name,
// permissions, limits and tags, gets a new NKey and expires after the TTL.
func (e Engine) Issue(_ context.Context, ep engine.Endpoint, master engine.Credentials, account engine.Account, current string) (string, error) {
	signer, err := accountKey(master)
	if err != nil {
		return "", err
	}
	old, err := userClaims(current)
	if err != nil {
		return "", fmt.Errorf("current credentials: %w", err)
	}
	if old.Name != account.Username {
		return "", fmt.Errorf("the current credentials belong to user %q, not %q", old.Name, account.Username)
	}
	if ep.NATSCredentialsTTL <= 0 {
		return "", errors.New("database.nats.credentialsTTL must be set")
	}

	user, err := nkeys.CreateUser()
	if err != nil {
		return "", err
	}
	userPub, err := user.PublicKey()
	if err != nil {
		return "", err
	}
	seed, err := user.Seed()
	if err != nil {
		return "", err
	}

	claims := jwt.NewUserClaims(userPub)
	claims.Name = old.Name
	claims.User = old.User
	// The account the user belongs to: set explicitly when the JWT is signed by a
	// signing key rather than by the account's identity key.
	acct := old.IssuerAccount
	if acct == "" {
		acct = old.Issuer
	}
	signerPub, err := signer.PublicKey()
	if err != nil {
		return "", err
	}
	claims.IssuerAccount = ""
	if signerPub != acct {
		claims.IssuerAccount = acct
	}
	claims.Expires = e.now().Add(ep.NATSCredentialsTTL).Unix()

	token, err := claims.Encode(signer)
	if err != nil {
		return "", fmt.Errorf("signing the user JWT: %w", err)
	}
	creds, err := jwt.FormatUserConfig(token, seed)
	if err != nil {
		return "", err
	}
	return string(creds), nil
}

// SetPassword implements engine.Engine. NATS keeps no users on the server, so
// there is nothing to change: the new credentials are valid once issued.
func (Engine) SetPassword(context.Context, engine.Endpoint, engine.Credentials, engine.Account, string) error {
	return nil
}

// VerifyLogin implements engine.Engine: it connects with the .creds file in
// creds.Password. Expired credentials are reported as engine.ErrCredentialsExpired
// without connecting.
func (e Engine) VerifyLogin(ctx context.Context, ep engine.Endpoint, creds engine.Credentials) error {
	token, seed, err := parseCreds(creds.Password)
	if err != nil {
		return err
	}
	claims, err := jwt.DecodeUserClaims(token)
	if err != nil {
		return fmt.Errorf("decoding the user JWT: %w", err)
	}
	if claims.Expires != 0 && !e.now().Before(time.Unix(claims.Expires, 0)) {
		return fmt.Errorf("%w at %s (user %q)", engine.ErrCredentialsExpired,
			time.Unix(claims.Expires, 0).UTC().Format(time.RFC3339), claims.Name)
	}

	opts := []natsgo.Option{
		natsgo.UserJWTAndSeed(token, seed),
		natsgo.Name("krotos"),
		natsgo.Timeout(engine.ConnectTimeout),
		natsgo.NoReconnect(),
	}
	tlsCfg, err := engine.TLSConfig(ep)
	if err != nil {
		return err
	}
	scheme := "nats"
	if tlsCfg != nil {
		scheme = "tls"
		opts = append(opts, natsgo.Secure(tlsCfg))
	}
	url := scheme + "://" + net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port)))
	nc, err := natsgo.Connect(url, opts...)
	if err != nil {
		return fmt.Errorf("connect as %q: %w", claims.Name, err)
	}
	defer nc.Close()
	timeout := engine.ConnectTimeout
	if d, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(d))
	}
	if err := nc.FlushTimeout(timeout); err != nil {
		return fmt.Errorf("connect as %q: %w", claims.Name, err)
	}
	return nil
}

// ExpiresAt implements engine.Expirer.
func (Engine) ExpiresAt(secret string) (time.Time, bool) {
	claims, err := userClaims(secret)
	if err != nil || claims.Expires == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Expires, 0), true
}

func (e Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// accountKey parses the master password as an account seed (SA…).
func accountKey(master engine.Credentials) (nkeys.KeyPair, error) {
	// A seed stored from a file often ends with a newline.
	kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(master.Password)))
	if err != nil {
		// The seed itself must not end up in the error.
		return nil, errors.New("the master password is not an NKey seed; it must be the account signing key's seed (SA…)")
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, err
	}
	if !nkeys.IsValidPublicAccountKey(pub) {
		return nil, errors.New("the master password is an NKey seed, but not an account's (SA…)")
	}
	return kp, nil
}

// parseCreds splits a .creds file into the user JWT and the NKey seed.
func parseCreds(creds string) (token, seed string, err error) {
	token, err = jwt.ParseDecoratedJWT([]byte(creds))
	if err != nil {
		return "", "", errors.New("not a NATS .creds file: no user JWT")
	}
	kp, err := jwt.ParseDecoratedUserNKey([]byte(creds))
	if err != nil {
		return "", "", errors.New("not a NATS .creds file: no user seed")
	}
	s, err := kp.Seed()
	if err != nil {
		return "", "", err
	}
	return token, string(s), nil
}

func userClaims(creds string) (*jwt.UserClaims, error) {
	token, _, err := parseCreds(creds)
	if err != nil {
		return nil, err
	}
	claims, err := jwt.DecodeUserClaims(token)
	if err != nil {
		return nil, fmt.Errorf("decoding the user JWT: %w", err)
	}
	return claims, nil
}
