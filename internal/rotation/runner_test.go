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

package rotation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
	"github.com/Warewave-Technology/krotos/internal/engine"
	"github.com/Warewave-Technology/krotos/internal/vault"
)

const (
	user        = "orders_app"
	oldPassword = "old-password"
	newPassword = "new-password"
)

// fakeDB is a database with one password per user.
type fakeDB struct {
	passwords map[string]string
	// setFailures/verifyFailures fail that many calls before succeeding; -1 fails forever.
	setFailures    int
	verifyFailures int
	// failOnlyFor limits verify failures to this password.
	failOnlyFor string
}

func consume(n *int) bool {
	if *n == 0 {
		return false
	}
	if *n > 0 {
		*n--
	}
	return true
}

func (d *fakeDB) SetPassword(_ context.Context, _ engine.Endpoint, _ engine.Credentials, a engine.Account, pw string) error {
	if consume(&d.setFailures) {
		return errors.New("connection refused")
	}
	d.passwords[a.Username] = pw
	return nil
}

func (d *fakeDB) VerifyLogin(_ context.Context, _ engine.Endpoint, c engine.Credentials) error {
	if (d.failOnlyFor == "" || d.failOnlyFor == c.Password) && consume(&d.verifyFailures) {
		return errors.New("connection refused")
	}
	if d.passwords[c.Username] != c.Password {
		return errors.New("password authentication failed")
	}
	return nil
}

// fakeVault is a single KV v2 secret.
type fakeVault struct {
	data    map[string]any
	version int
	missing bool

	writeFailures int
	// lostResponses apply the write but return an error, that many times.
	lostResponses int
	// beforeWrite runs before each write, e.g. to simulate a concurrent writer.
	beforeWrite func(v *fakeVault)
}

func (v *fakeVault) Read(context.Context, vault.SecretRef) (*vault.Secret, error) {
	if v.missing {
		return nil, vault.ErrNotFound
	}
	cp := maps.Clone(v.data)
	return &vault.Secret{Data: cp, Version: v.version}, nil
}

func (v *fakeVault) Write(_ context.Context, _ vault.SecretRef, data map[string]any, cas int) (int, error) {
	if v.beforeWrite != nil {
		v.beforeWrite(v)
	}
	if consume(&v.writeFailures) {
		return 0, errors.New("vault unavailable")
	}
	if cas != v.version {
		return 0, vault.ErrCASMismatch
	}
	v.data = data
	v.version++
	if consume(&v.lostResponses) {
		return 0, errors.New("connection reset by peer")
	}
	return v.version, nil
}

func (v *fakeVault) Delete(context.Context, vault.SecretRef) error {
	v.missing = true
	return nil
}

type fakePending struct {
	p *Pending
}

func (f *fakePending) Load(context.Context) (*Pending, error) {
	if f.p == nil {
		return nil, nil
	}
	cp := *f.p
	return &cp, nil
}

func (f *fakePending) Save(_ context.Context, p *Pending) error {
	cp := *p
	f.p = &cp
	return nil
}

func (f *fakePending) Delete(context.Context) error {
	f.p = nil
	return nil
}

type fixture struct {
	db        *fakeDB
	vault     *fakeVault
	pending   *fakePending
	target    *Target
	state     State
	persisted []krotosv1alpha1.RotationStep
	persistFn Persist
}

func newFixture() *fixture {
	f := &fixture{
		db:      &fakeDB{passwords: map[string]string{user: oldPassword}},
		vault:   &fakeVault{data: map[string]any{"password": oldPassword, "host": "pg"}, version: 3},
		pending: &fakePending{},
	}
	f.target = &Target{
		Engine:      f.db,
		Account:     engine.Account{Username: user},
		Vault:       f.vault,
		VaultRef:    vault.SecretRef{Mount: "secret", Path: "apps/orders", KVVersion: 2},
		PasswordKey: "password",
		UsernameKey: "username",
		Pending:     f.pending,
		NewPassword: func() (string, error) { return newPassword, nil },
	}
	f.persistFn = func(_ context.Context, s State) error {
		f.persisted = append(f.persisted, s.Step)
		return nil
	}
	return f
}

func (f *fixture) run(t *testing.T) Result {
	t.Helper()
	return Run(t.Context(), f.target, &f.state, f.persistFn)
}

func (f *fixture) assertConsistent(t *testing.T, want string) {
	t.Helper()
	if got := f.db.passwords[user]; got != want {
		t.Errorf("database password = %q, want %q", got, want)
	}
	if got := f.vault.data["password"]; got != want {
		t.Errorf("vault password = %q, want %q", got, want)
	}
}

func TestRunHappyPath(t *testing.T) {
	f := newFixture()
	res := f.run(t)

	if res.Outcome != OutcomeVaultWritten {
		t.Fatalf("outcome = %s (%s)", res.Outcome, res.Message)
	}
	f.assertConsistent(t, newPassword)
	if f.vault.data["host"] != "pg" || f.vault.data["username"] != user {
		t.Errorf("vault data = %v, other keys must be kept and username written", f.vault.data)
	}
	if f.vault.version != 4 {
		t.Errorf("vault version = %d, want one write", f.vault.version)
	}
	want := []krotosv1alpha1.RotationStep{
		krotosv1alpha1.StepPendingSaved, krotosv1alpha1.StepDbUpdated,
		krotosv1alpha1.StepVerified, krotosv1alpha1.StepVaultWritten,
	}
	if !slices.Equal(f.persisted, want) {
		t.Errorf("persisted steps = %v, want %v", f.persisted, want)
	}
	if f.pending.p == nil || f.pending.p.OldPassword != oldPassword || f.pending.p.NewPassword != newPassword {
		t.Errorf("pending = %+v; it must be kept for the caller's later steps", f.pending.p)
	}
}

func TestRunRefusesToStart(t *testing.T) {
	cases := map[string]func(f *fixture){
		"vault and database disagree": func(f *fixture) { f.db.passwords[user] = "something-else" },
		"vault secret missing":        func(f *fixture) { f.vault.missing = true },
		"password key missing":        func(f *fixture) { delete(f.vault.data, "password") },
		"password key not a string":   func(f *fixture) { f.vault.data["password"] = 42 },
		"password generation fails": func(f *fixture) {
			f.target.NewPassword = func() (string, error) { return "", errors.New("no entropy") }
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			mutate(f)
			dbBefore := f.db.passwords[user]
			res := f.run(t)
			if res.Outcome != OutcomeFailed || res.RolledBack {
				t.Fatalf("outcome = %s rolledBack=%v (%s)", res.Outcome, res.RolledBack, res.Message)
			}
			if f.db.passwords[user] != dbBefore || f.vault.version != 3 {
				t.Error("something was changed")
			}
			if f.pending.p != nil || f.state.Step != krotosv1alpha1.StepNone || len(f.persisted) != 0 {
				t.Errorf("state was touched: pending=%v state=%+v persisted=%v", f.pending.p, f.state, f.persisted)
			}
		})
	}
}

// preflightDB refuses every rotation in its preflight.
type preflightDB struct{ *fakeDB }

func (preflightDB) Preflight(context.Context, engine.Endpoint, engine.Credentials) error {
	return errors.New("server has no aclfile")
}

func TestRunPreflightRefusalChangesNothing(t *testing.T) {
	f := newFixture()
	f.target.Engine = preflightDB{f.db}

	res := f.run(t)
	if res.Outcome != OutcomeFailed || res.RolledBack {
		t.Fatalf("outcome = %s rolledBack=%v (%s)", res.Outcome, res.RolledBack, res.Message)
	}
	if !strings.Contains(res.Message, "no aclfile") {
		t.Errorf("message = %q", res.Message)
	}
	f.assertConsistent(t, oldPassword)
	if f.pending.p != nil || len(f.persisted) != 0 {
		t.Errorf("state was touched: pending=%v persisted=%v", f.pending.p, f.persisted)
	}
}

// issuingDB creates the new secret itself and has expiring credentials, like NATS.
type issuingDB struct {
	*fakeDB
	expired    map[string]bool
	issuedFrom string
}

func (d *issuingDB) Issue(_ context.Context, _ engine.Endpoint, _ engine.Credentials, _ engine.Account, current string) (string, error) {
	d.issuedFrom = current
	return newPassword, nil
}

func (d *issuingDB) VerifyLogin(ctx context.Context, ep engine.Endpoint, c engine.Credentials) error {
	if d.expired[c.Password] {
		return fmt.Errorf("%w at some time", engine.ErrCredentialsExpired)
	}
	return d.fakeDB.VerifyLogin(ctx, ep, c)
}

func TestRunIssuerCreatesTheSecret(t *testing.T) {
	f := newFixture()
	db := &issuingDB{fakeDB: f.db}
	f.target.Engine = db
	f.target.NewPassword = func() (string, error) { return "", errors.New("must not be called") }

	if res := f.run(t); res.Outcome != OutcomeVaultWritten {
		t.Fatalf("outcome = %s (%s)", res.Outcome, res.Message)
	}
	if db.issuedFrom != oldPassword {
		t.Errorf("issued from %q, want the current secret", db.issuedFrom)
	}
	f.assertConsistent(t, newPassword)
}

func TestRunReplacesExpiredCredentials(t *testing.T) {
	f := newFixture()
	f.target.Engine = &issuingDB{fakeDB: f.db, expired: map[string]bool{oldPassword: true}}
	var warnings []string
	f.target.Warn = func(msg string) { warnings = append(warnings, msg) }

	if res := f.run(t); res.Outcome != OutcomeVaultWritten {
		t.Fatalf("outcome = %s (%s)", res.Outcome, res.Message)
	}
	f.assertConsistent(t, newPassword)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "expired") {
		t.Errorf("warnings = %q", warnings)
	}
}

func TestRunRollbackWithExpiredOldCredentials(t *testing.T) {
	// Nothing on the server has to be restored for expiring credentials, so the
	// rollback must not get stuck trying to log in with them.
	f := newFixture()
	f.target.Engine = &issuingDB{fakeDB: f.db, expired: map[string]bool{oldPassword: true}}
	f.db.verifyFailures = -1
	f.db.failOnlyFor = newPassword

	var res Result
	for range maxDBRetries {
		res = f.run(t)
	}
	if res.Outcome != OutcomeFailed || !res.RolledBack {
		t.Fatalf("outcome = %s rolledBack=%v (%s)", res.Outcome, res.RolledBack, res.Message)
	}
	if f.vault.data["password"] != oldPassword {
		t.Errorf("vault password = %q, Vault must keep the old credentials", f.vault.data["password"])
	}
}

func TestRunRetriesTransientDatabaseError(t *testing.T) {
	f := newFixture()
	f.db.setFailures = 1

	res := f.run(t)
	if res.Outcome != OutcomeRetry || res.RequeueAfter != baseBackoff {
		t.Fatalf("first run: outcome = %s after %v (%s)", res.Outcome, res.RequeueAfter, res.Message)
	}
	if !strings.Contains(res.Message, "attempt 1 of 3") {
		t.Errorf("message = %q", res.Message)
	}
	if f.state.Step != krotosv1alpha1.StepPendingSaved || f.state.Retries != 1 {
		t.Fatalf("state = %+v", f.state)
	}

	res = f.run(t)
	if res.Outcome != OutcomeVaultWritten {
		t.Fatalf("second run: outcome = %s (%s)", res.Outcome, res.Message)
	}
	f.assertConsistent(t, newPassword)
}

func TestRunRollsBack(t *testing.T) {
	cases := map[string]struct {
		mutate  func(f *fixture)
		retries int
		reason  string
	}{
		"database change keeps failing": {
			// Fails 3 times for the rotation, then succeeds for the rollback.
			mutate:  func(f *fixture) { f.db.setFailures = maxDBRetries },
			retries: maxDBRetries,
			reason:  "Changing the password in the database",
		},
		"new password does not work": {
			mutate:  func(f *fixture) { f.db.verifyFailures = -1; f.db.failOnlyFor = newPassword },
			retries: maxDBRetries,
			reason:  "Logging in with the new password",
		},
		"vault write keeps failing": {
			mutate:  func(f *fixture) { f.vault.writeFailures = -1 },
			retries: maxVaultRetries,
			reason:  "Writing the new password to Vault",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			tc.mutate(f)

			var res Result
			for i := range tc.retries {
				res = f.run(t)
				if i < tc.retries-1 && res.Outcome != OutcomeRetry {
					t.Fatalf("run %d: outcome = %s (%s)", i+1, res.Outcome, res.Message)
				}
			}
			if res.Outcome != OutcomeFailed || !res.RolledBack {
				t.Fatalf("final outcome = %s rolledBack=%v (%s)", res.Outcome, res.RolledBack, res.Message)
			}
			if !strings.Contains(res.Message, tc.reason) {
				t.Errorf("message %q does not mention %q", res.Message, tc.reason)
			}
			f.assertConsistent(t, oldPassword)
			if f.pending.p != nil || f.state != (State{}) {
				t.Errorf("not cleaned up: pending=%v state=%+v", f.pending.p, f.state)
			}
		})
	}
}

func TestRunDetectsVaultWriteWithLostResponse(t *testing.T) {
	f := newFixture()
	f.vault.lostResponses = 1

	res := f.run(t)
	if res.Outcome != OutcomeRetry {
		t.Fatalf("first run: outcome = %s (%s)", res.Outcome, res.Message)
	}
	res = f.run(t)
	if res.Outcome != OutcomeVaultWritten {
		t.Fatalf("second run: outcome = %s (%s)", res.Outcome, res.Message)
	}
	f.assertConsistent(t, newPassword)
	if f.vault.version != 4 {
		t.Errorf("vault version = %d, the password must not be written twice", f.vault.version)
	}
}

func TestRunDoesNotRollBackWhenVaultAlreadyHasNewPassword(t *testing.T) {
	f := newFixture()
	// Every write lands but reports an error.
	f.vault.lostResponses = -1
	f.vault.writeFailures = 0

	res := f.run(t)
	for res.Outcome == OutcomeRetry {
		res = f.run(t)
	}
	if res.Outcome != OutcomeVaultWritten {
		t.Fatalf("outcome = %s (%s)", res.Outcome, res.Message)
	}
	f.assertConsistent(t, newPassword)
}

func TestRunConcurrentVaultWriterIsMerged(t *testing.T) {
	f := newFixture()
	first := true
	f.vault.beforeWrite = func(v *fakeVault) {
		if first {
			first = false
			v.data = map[string]any{"password": oldPassword, "host": "pg", "port": "5432"}
			v.version++
		}
	}

	res := f.run(t)
	if res.Outcome != OutcomeRetry {
		t.Fatalf("first run: outcome = %s (%s)", res.Outcome, res.Message)
	}
	if !strings.Contains(res.Message, "check-and-set") {
		t.Errorf("message = %q", res.Message)
	}
	res = f.run(t)
	if res.Outcome != OutcomeVaultWritten {
		t.Fatalf("second run: outcome = %s (%s)", res.Outcome, res.Message)
	}
	if f.vault.data["port"] != "5432" || f.vault.data["password"] != newPassword {
		t.Errorf("vault data = %v, concurrent change must be kept", f.vault.data)
	}
}

func TestRunPermanentDatabaseErrorRollsBackWithoutChanges(t *testing.T) {
	// E.g. the master user lacks the privilege: every ALTER fails, including the rollback's.
	f := newFixture()
	f.db.setFailures = -1

	var res Result
	for range maxDBRetries {
		res = f.run(t)
	}
	if res.Outcome != OutcomeFailed || !res.RolledBack {
		t.Fatalf("outcome = %s rolledBack=%v (%s); a database that was never changed must not be stuck",
			res.Outcome, res.RolledBack, res.Message)
	}
	if !strings.Contains(res.Message, "connection refused") {
		t.Errorf("message %q does not carry the original error", res.Message)
	}
	f.assertConsistent(t, oldPassword)
	if f.pending.p != nil || f.state != (State{}) {
		t.Errorf("not cleaned up: pending=%v state=%+v", f.pending.p, f.state)
	}
}

func TestRunRollbackFailureIsStuckUntilItSucceeds(t *testing.T) {
	f := newFixture()
	f.db.verifyFailures = -1
	f.db.failOnlyFor = newPassword
	for range maxDBRetries - 1 {
		f.run(t)
	}
	// The rollback's ALTER fails too.
	f.db.setFailures = 2

	res := f.run(t)
	if res.Outcome != OutcomeStuck || f.state.Step != krotosv1alpha1.StepRollingBack || f.state.Retries != 1 {
		t.Fatalf("outcome = %s state = %+v (%s)", res.Outcome, f.state, res.Message)
	}
	if !strings.Contains(res.Message, "Logging in with the new password") {
		t.Errorf("message %q does not carry the original reason", res.Message)
	}
	res = f.run(t)
	if res.Outcome != OutcomeStuck || f.state.Retries != 2 || res.RequeueAfter != 2*baseBackoff {
		t.Fatalf("second attempt: outcome = %s state = %+v after %v", res.Outcome, f.state, res.RequeueAfter)
	}

	res = f.run(t)
	if res.Outcome != OutcomeFailed || !res.RolledBack {
		t.Fatalf("recovery: outcome = %s (%s)", res.Outcome, res.Message)
	}
	f.assertConsistent(t, oldPassword)
}

func TestRunResumesAfterCrash(t *testing.T) {
	// The operator died after ALTER ROLE but before recording DbUpdated.
	f := newFixture()
	f.state = State{Step: krotosv1alpha1.StepPendingSaved}
	f.pending.p = &Pending{OldPassword: oldPassword, NewPassword: newPassword}
	f.db.passwords[user] = newPassword

	res := f.run(t)
	if res.Outcome != OutcomeVaultWritten {
		t.Fatalf("outcome = %s (%s)", res.Outcome, res.Message)
	}
	f.assertConsistent(t, newPassword)
}

func TestRunWithoutPendingIsStuck(t *testing.T) {
	for _, step := range []krotosv1alpha1.RotationStep{
		krotosv1alpha1.StepPendingSaved, krotosv1alpha1.StepDbUpdated,
		krotosv1alpha1.StepVerified, krotosv1alpha1.StepRollingBack,
	} {
		f := newFixture()
		f.state = State{Step: step}
		if res := f.run(t); res.Outcome != OutcomeStuck {
			t.Errorf("step %s: outcome = %s", step, res.Outcome)
		}
		if f.db.passwords[user] != oldPassword {
			t.Errorf("step %s: database changed", step)
		}
	}
}

func TestRunPersistFailureDoesNotAdvance(t *testing.T) {
	f := newFixture()
	f.persistFn = func(context.Context, State) error { return errors.New("conflict") }

	res := f.run(t)
	if res.Outcome != OutcomeRetry || f.state.Step != krotosv1alpha1.StepNone {
		t.Fatalf("outcome = %s state = %+v", res.Outcome, f.state)
	}
}

func TestBackoff(t *testing.T) {
	want := map[int32]time.Duration{
		1: 15 * time.Second, 2: 30 * time.Second, 3: time.Minute, 5: 4 * time.Minute, 6: 5 * time.Minute, 50: 5 * time.Minute,
	}
	for retries, d := range want {
		if got := backoff(retries); got != d {
			t.Errorf("backoff(%d) = %v, want %v", retries, got, d)
		}
	}
}
