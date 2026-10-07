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

// Package docs checks that the README shows the least-privilege templates the
// integration tests run.
package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestREADMEHoldsLeastPrivilegeTemplates(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("../../docs/least-privilege/*")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no templates found")
	}
	for _, f := range files {
		tpl, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(readme), strings.TrimRight(string(tpl), "\n")+"\n```") {
			t.Errorf("README does not hold %s verbatim; copy it into section 6.2", filepath.Base(f))
		}
	}
}
