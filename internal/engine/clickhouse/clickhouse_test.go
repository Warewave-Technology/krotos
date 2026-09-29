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

package clickhouse

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

var alterRe = regexp.MustCompile(`^ALTER USER (.+?)( ON CLUSTER (.+))? IDENTIFIED WITH sha256_hash BY '([0-9a-f]{64})' SALT '([0-9a-f]{32})'$`)

func TestAlterUserStatement(t *testing.T) {
	stmt, err := alterUserStatement("orders_app", "", "S3cret!")
	if err != nil {
		t.Fatal(err)
	}
	m := alterRe.FindStringSubmatch(stmt)
	if m == nil {
		t.Fatalf("unexpected statement %q", stmt)
	}
	if m[1] != "`orders_app`" || m[2] != "" {
		t.Errorf("user/cluster = %q/%q", m[1], m[2])
	}
	sum := sha256.Sum256([]byte("S3cret!" + m[5]))
	if m[4] != hex.EncodeToString(sum[:]) {
		t.Error("hash is not sha256(password + salt)")
	}
	if strings.Contains(stmt, "S3cret") {
		t.Error("statement contains the password")
	}

	other, _ := alterUserStatement("orders_app", "", "S3cret!")
	if other == stmt {
		t.Error("salt is not random")
	}
}

func TestAlterUserStatementOnCluster(t *testing.T) {
	stmt, err := alterUserStatement("app", "main", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if m := alterRe.FindStringSubmatch(stmt); m == nil || m[3] != "`main`" {
		t.Fatalf("statement %q has no ON CLUSTER `main`", stmt)
	}
}

func TestQuoteIdentifier(t *testing.T) {
	for in, want := range map[string]string{
		"app":        "`app`",
		"we`ird":     "`we\\`ird`",
		`back\slash`: "`back\\\\slash`",
	} {
		if got := quoteIdentifier(in); got != want {
			t.Errorf("quoteIdentifier(%q) = %s, want %s", in, got, want)
		}
	}
}
