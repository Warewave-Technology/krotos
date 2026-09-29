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

package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	krotosv1alpha1 "github.com/warewave/krotos/api/v1alpha1"
)

// selfSigned returns a CA certificate as PEM and DER.
func selfSigned(t *testing.T, cn string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		DNSNames:              []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der
}

func TestTLSConfig(t *testing.T) {
	caPEM, caDER := selfSigned(t, "db.example")
	_, otherDER := selfSigned(t, "other.example")

	cfg, err := TLSConfig(Endpoint{Host: "db", TLSMode: krotosv1alpha1.TLSModeDisable})
	if err != nil || cfg != nil {
		t.Fatalf("disable: %v, %v", cfg, err)
	}
	if cfg, _ := TLSConfig(Endpoint{Host: "db"}); cfg != nil {
		t.Fatal("empty mode should mean disable at this layer")
	}

	cfg, err = TLSConfig(Endpoint{Host: "db", TLSMode: krotosv1alpha1.TLSModeRequire})
	if err != nil || !cfg.InsecureSkipVerify {
		t.Fatalf("require: %+v, %v", cfg, err)
	}

	for _, mode := range []krotosv1alpha1.TLSMode{krotosv1alpha1.TLSModeVerifyCA, krotosv1alpha1.TLSModeVerifyFull} {
		if _, err := TLSConfig(Endpoint{Host: "db", TLSMode: mode}); err == nil {
			t.Errorf("%s without CA accepted", mode)
		}
		if _, err := TLSConfig(Endpoint{Host: "db", TLSMode: mode, CACert: []byte("not pem")}); err == nil {
			t.Errorf("%s with invalid CA accepted", mode)
		}
	}

	cfg, err = TLSConfig(Endpoint{Host: "db.example", TLSMode: krotosv1alpha1.TLSModeVerifyFull, CACert: caPEM})
	if err != nil || cfg.InsecureSkipVerify || cfg.RootCAs == nil || cfg.ServerName != "db.example" {
		t.Fatalf("verify-full: %+v, %v", cfg, err)
	}

	cfg, err = TLSConfig(Endpoint{Host: "10.0.0.1", TLSMode: krotosv1alpha1.TLSModeVerifyCA, CACert: caPEM})
	if err != nil || cfg.VerifyPeerCertificate == nil {
		t.Fatalf("verify-ca: %+v, %v", cfg, err)
	}
	// verify-ca checks the chain but not the host name.
	if err := cfg.VerifyPeerCertificate([][]byte{caDER}, nil); err != nil {
		t.Errorf("certificate signed by the CA rejected: %v", err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{otherDER}, nil); err == nil {
		t.Error("certificate from another CA accepted")
	}
	if err := cfg.VerifyPeerCertificate(nil, nil); err == nil {
		t.Error("empty chain accepted")
	}
}

func TestCredentialsDoNotPrintPassword(t *testing.T) {
	c := Credentials{Username: "app", Password: "s3cret"}
	for _, format := range []string{"%v", "%+v", "%s", "%#v"} {
		if s := fmt.Sprintf(format, c); s == "" || strings.Contains(s, "s3cret") {
			t.Errorf("%s prints %q", format, s)
		}
	}
}
