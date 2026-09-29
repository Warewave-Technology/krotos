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

package postgres

import (
	"strings"
	"testing"
)

func TestSCRAMVerifierMatchesReference(t *testing.T) {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	got, err := scramVerifierWithSalt("pencil", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	// Computed independently with Python's hashlib/hmac.
	want := "SCRAM-SHA-256$4096:AAECAwQFBgcICQoLDA0ODw==$zHCdol2044/ZyWzPLi7oxApCkamKw9Z+E4U/QApd/5Y=:dd5peBOitVnLNFu7VmwP+HiDaaw4OUCv396eVCWhYiE="
	if got != want {
		t.Fatalf("verifier = %s\nwant       %s", got, want)
	}
}

func TestSCRAMVerifierIsSaltedAndHidesPassword(t *testing.T) {
	a, _ := scramVerifier("s3cret-password")
	b, _ := scramVerifier("s3cret-password")
	if a == b {
		t.Fatal("two verifiers share a salt")
	}
	if strings.Contains(a, "s3cret") {
		t.Fatal("verifier contains the password")
	}
}

func TestIsSCRAMSafe(t *testing.T) {
	for pw, want := range map[string]bool{
		"":               false,
		"plain-ASCII_1!": true,
		"with space":     true,
		"tab\there":      false,
		"şifre":          false,
	} {
		if got := isSCRAMSafe(pw); got != want {
			t.Errorf("isSCRAMSafe(%q) = %v, want %v", pw, got, want)
		}
	}
}
