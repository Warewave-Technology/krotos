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

package password

import (
	"strings"
	"testing"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
)

func TestGenerate(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		p, err := Generate(32, krotosv1alpha1.DefaultExcludeCharacters)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 32 {
			t.Fatalf("len = %d", len(p))
		}
		if strings.ContainsAny(p, krotosv1alpha1.DefaultExcludeCharacters) {
			t.Fatalf("%q contains an excluded character", p)
		}
		for _, set := range []string{lower, upper, digits} {
			if !strings.ContainsAny(p, set) {
				t.Fatalf("%q has no character from %q", p, set)
			}
		}
		if !strings.ContainsAny(p, strip(symbols, krotosv1alpha1.DefaultExcludeCharacters)) {
			t.Fatalf("%q has no symbol", p)
		}
		for _, r := range p {
			if r < 0x21 || r > 0x7e {
				t.Fatalf("%q contains non-printable or non-ASCII %q", p, r)
			}
		}
		if seen[p] {
			t.Fatalf("duplicate password %q", p)
		}
		seen[p] = true
	}
}

func TestGenerateWithoutSymbols(t *testing.T) {
	p, err := Generate(16, symbols)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(p, symbols) {
		t.Fatalf("%q contains a symbol", p)
	}
}

func TestGenerateRejects(t *testing.T) {
	if _, err := Generate(15, ""); err == nil {
		t.Error("length below minimum accepted")
	}
	if _, err := Generate(32, digits); err == nil {
		t.Error("excluding all digits accepted")
	}
}
