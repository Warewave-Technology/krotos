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

// Package enginetest helps engine integration tests use the least-privilege
// templates from docs/least-privilege, so the documented templates are the ones
// that are tested.
package enginetest

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Placeholders used in the templates.
const (
	RotatorUser    = "krotos_rotator"
	TargetUser     = "orders_app"
	PasswordHolder = "change-me"
)

// SQLStatements reads docs/least-privilege/<name>, drops "--" comment lines and
// returns its statements with the target user and the rotator's password replaced.
func SQLStatements(name, targetUser, rotatorPassword string) ([]string, error) {
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "docs", "least-privilege", name))
	if err != nil {
		return nil, err
	}
	var lines []string
	for line := range strings.SplitSeq(string(raw), "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "--") {
			lines = append(lines, line)
		}
	}
	text := strings.Join(lines, "\n")
	text = strings.ReplaceAll(text, TargetUser, targetUser)
	text = strings.ReplaceAll(text, PasswordHolder, rotatorPassword)
	var stmts []string
	for s := range strings.SplitSeq(text, ";") {
		if s = strings.TrimSpace(s); s != "" {
			stmts = append(stmts, s)
		}
	}
	return stmts, nil
}
