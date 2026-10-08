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

package nats

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/Warewave-Technology/krotos/internal/engine"
)

const userName = "orders-service"

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func mustKey(t *testing.T, create func() (nkeys.KeyPair, error)) (nkeys.KeyPair, string, string) {
	t.Helper()
	kp, err := create()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	seed, _ := kp.Seed()
	return kp, pub, string(seed)
}

// userCreds issues a .creds file for userName, signed by signer for account acct.
func userCreds(t *testing.T, signer nkeys.KeyPair, acct string, exp time.Time, edit func(*jwt.UserClaims)) string {
	t.Helper()
	_, pub, seed := mustKey(t, nkeys.CreateUser)
	uc := jwt.NewUserClaims(pub)
	uc.Name = userName
	if signerPub, _ := signer.PublicKey(); signerPub != acct {
		uc.IssuerAccount = acct
	}
	if !exp.IsZero() {
		uc.Expires = exp.Unix()
	}
	if edit != nil {
		edit(uc)
	}
	token, err := uc.Encode(signer)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := jwt.FormatUserConfig(token, []byte(seed))
	if err != nil {
		t.Fatal(err)
	}
	return string(creds)
}

func decode(t *testing.T, creds string) *jwt.UserClaims {
	t.Helper()
	uc, err := userClaims(creds)
	if err != nil {
		t.Fatal(err)
	}
	return uc
}

func TestIssueKeepsClaimsAndRenewsKey(t *testing.T) {
	ttl := 60 * 24 * time.Hour
	ep := engine.Endpoint{NATSCredentialsTTL: ttl}
	e := Engine{Now: func() time.Time { return now }}

	acctKP, acctPub, acctSeed := mustKey(t, nkeys.CreateAccount)
	signKP, signPub, signSeed := mustKey(t, nkeys.CreateAccount)

	for name, tc := range map[string]struct {
		oldSigner  nkeys.KeyPair
		masterSeed string
		wantIssuer string
	}{
		"account identity key": {acctKP, acctSeed, acctPub},
		"signing key":          {signKP, signSeed, signPub},
	} {
		t.Run(name, func(t *testing.T) {
			current := userCreds(t, tc.oldSigner, acctPub, now.Add(time.Hour), func(uc *jwt.UserClaims) {
				uc.Pub.Allow.Add("orders.>")
				uc.Sub.Deny.Add("admin.>")
				uc.Tags.Add("team:orders")
			})
			got, err := e.Issue(t.Context(), ep, engine.Credentials{Password: tc.masterSeed},
				engine.Account{Username: userName}, current)
			if err != nil {
				t.Fatal(err)
			}
			old, nu := decode(t, current), decode(t, got)
			if nu.Subject == old.Subject {
				t.Error("the user NKey was not renewed")
			}
			if nu.Name != userName || !nu.Pub.Allow.Contains("orders.>") || !nu.Sub.Deny.Contains("admin.>") || !nu.Tags.Contains("team:orders") {
				t.Errorf("claims not kept: %+v", nu.User)
			}
			if nu.Issuer != tc.wantIssuer {
				t.Errorf("issuer = %s, want %s", nu.Issuer, tc.wantIssuer)
			}
			wantAcct := ""
			if tc.wantIssuer != acctPub {
				wantAcct = acctPub
			}
			if nu.IssuerAccount != wantAcct {
				t.Errorf("issuer_account = %q, want %q", nu.IssuerAccount, wantAcct)
			}
			if exp, ok := e.ExpiresAt(got); !ok || !exp.Equal(now.Add(ttl)) {
				t.Errorf("expires at %v (%v), want %v", exp, ok, now.Add(ttl))
			}
			if strings.Contains(got, tc.masterSeed) {
				t.Error("the master seed is in the issued credentials")
			}
		})
	}
}

func TestIssueRefusals(t *testing.T) {
	ep := engine.Endpoint{NATSCredentialsTTL: time.Hour}
	acctKP, acctPub, acctSeed := mustKey(t, nkeys.CreateAccount)
	_, _, userSeed := mustKey(t, nkeys.CreateUser)
	current := userCreds(t, acctKP, acctPub, time.Time{}, nil)

	cases := map[string]struct {
		master, user, current string
		ep                    engine.Endpoint
		want                  string
	}{
		"master is not a seed":         {"hunter2-secret", userName, current, ep, "not an NKey seed"},
		"master is a user seed":        {userSeed, userName, current, ep, "not an account's"},
		"credentials of another user":  {acctSeed, "billing-service", current, ep, `belong to user "orders-service"`},
		"current secret is not .creds": {acctSeed, userName, "plain-password", ep, "current credentials"},
		"no TTL":                       {acctSeed, userName, current, engine.Endpoint{}, "credentialsTTL"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Engine{}.Issue(t.Context(), tc.ep, engine.Credentials{Password: tc.master},
				engine.Account{Username: tc.user}, tc.current)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), tc.master) {
				t.Error("the master secret is in the error")
			}
		})
	}
}

func TestVerifyLoginReportsExpiryWithoutConnecting(t *testing.T) {
	acctKP, acctPub, _ := mustKey(t, nkeys.CreateAccount)
	creds := userCreds(t, acctKP, acctPub, now.Add(-time.Minute), nil)
	// Nothing listens on port 1: an attempt to connect would fail differently.
	ep := engine.Endpoint{Host: "127.0.0.1", Port: 1}
	err := Engine{Now: func() time.Time { return now }}.VerifyLogin(t.Context(), ep, engine.Credentials{Password: creds})
	if !errors.Is(err, engine.ErrCredentialsExpired) {
		t.Fatalf("err = %v, want ErrCredentialsExpired", err)
	}
}

func TestPreflight(t *testing.T) {
	_, _, acctSeed := mustKey(t, nkeys.CreateAccount)
	ep := engine.Endpoint{NATSCredentialsTTL: time.Hour}
	if err := (Engine{}).Preflight(t.Context(), ep, engine.Credentials{Password: acctSeed}); err != nil {
		t.Errorf("valid account seed: %v", err)
	}
	if err := (Engine{}).Preflight(t.Context(), ep, engine.Credentials{Password: acctSeed + "\n"}); err != nil {
		t.Errorf("seed with a trailing newline: %v", err)
	}
	if err := (Engine{}).Preflight(t.Context(), ep, engine.Credentials{Password: "nope"}); err == nil {
		t.Error("invalid seed accepted")
	}
}

func TestExpiresAtWithoutExpiry(t *testing.T) {
	acctKP, acctPub, _ := mustKey(t, nkeys.CreateAccount)
	if _, ok := (Engine{}).ExpiresAt(userCreds(t, acctKP, acctPub, time.Time{}, nil)); ok {
		t.Error("credentials without expiry reported an expiry")
	}
}
