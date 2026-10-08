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

// Package rotation implements the password rotation state machine:
//
//	""  ──> PendingSaved ──> DbUpdated ──> Verified ──> VaultWritten
//	                 │             │            │
//	                 └─────────────┴────────────┴──> RollingBack ──> ""
//
// Every step is idempotent and the current step is persisted after it completes,
// so a crashed or restarted operator resumes where it stopped. The new password is
// kept in a pending store (in Vault) until the rotation finishes.
package rotation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
	"github.com/Warewave-Technology/krotos/internal/engine"
	"github.com/Warewave-Technology/krotos/internal/vault"
)

// Retry policy for steps after the database was changed.
const (
	maxDBRetries    = 3
	maxVaultRetries = 5
	baseBackoff     = 15 * time.Second
	maxBackoff      = 5 * time.Minute
)

// SecretStore reads and writes Vault KV secrets. *vault.Client implements it.
type SecretStore interface {
	Read(ctx context.Context, ref vault.SecretRef) (*vault.Secret, error)
	Write(ctx context.Context, ref vault.SecretRef, data map[string]any, casVersion int) (int, error)
	Delete(ctx context.Context, ref vault.SecretRef) error
}

// Pending is the in-flight rotation's state that must survive restarts.
type Pending struct {
	OldPassword string
	NewPassword string
	// FailureReason is why a rollback was started.
	FailureReason string
}

// PendingStore persists Pending.
type PendingStore interface {
	// Load returns nil, nil if nothing is stored.
	Load(ctx context.Context) (*Pending, error)
	Save(ctx context.Context, p *Pending) error
	Delete(ctx context.Context) error
}

// Target is everything needed to rotate one account.
type Target struct {
	Engine   engine.Engine
	Endpoint engine.Endpoint
	Master   engine.Credentials
	Account  engine.Account

	Vault       SecretStore
	VaultRef    vault.SecretRef
	PasswordKey string
	// UsernameKey, when set, is written together with the password.
	UsernameKey string

	Pending     PendingStore
	NewPassword func() (string, error)
	// Warn reports a problem that does not stop the rotation. Optional.
	Warn func(msg string)
}

// State is the persisted progress of a rotation.
type State struct {
	Step    krotosv1alpha1.RotationStep
	Retries int32
}

// Outcome is how a Run ended.
type Outcome string

const (
	// OutcomeVaultWritten means the database and Vault hold the new password.
	OutcomeVaultWritten Outcome = "VaultWritten"
	// OutcomeFailed means the rotation ended without changing anything, or was
	// rolled back successfully. The state is reset.
	OutcomeFailed Outcome = "Failed"
	// OutcomeRetry means a step failed transiently; run again after RequeueAfter.
	OutcomeRetry Outcome = "Retry"
	// OutcomeStuck means the database and Vault may disagree and the runner cannot
	// fix it on its own yet; it keeps retrying but needs attention.
	OutcomeStuck Outcome = "Stuck"
)

// Result describes the end of a Run.
type Result struct {
	Outcome      Outcome
	RequeueAfter time.Duration
	// Message is human readable and never contains secrets.
	Message string
	// RolledBack is true when OutcomeFailed followed a successful rollback.
	RolledBack bool
}

// Persist stores the state after each completed step.
type Persist func(context.Context, State) error

// Run advances the rotation as far as possible.
func Run(ctx context.Context, t *Target, st *State, persist Persist) Result {
	for {
		var res *Result
		switch st.Step {
		case krotosv1alpha1.StepNone:
			res = start(ctx, t, st, persist)
		case krotosv1alpha1.StepPendingSaved:
			res = updateDatabase(ctx, t, st, persist)
		case krotosv1alpha1.StepDbUpdated:
			res = verifyNewPassword(ctx, t, st, persist)
		case krotosv1alpha1.StepVerified:
			res = writeVault(ctx, t, st, persist)
		case krotosv1alpha1.StepRollingBack:
			res = rollback(ctx, t, st, persist)
		default:
			// VaultWritten and later steps belong to the caller.
			return Result{Outcome: OutcomeVaultWritten, Message: "Database and Vault hold the new password"}
		}
		if res != nil {
			return *res
		}
	}
}

// start checks that Vault and the database agree on the current password, then
// saves the new password before anything is changed.
func start(ctx context.Context, t *Target, st *State, persist Persist) *Result {
	failed := func(format string, args ...any) *Result {
		return &Result{Outcome: OutcomeFailed, Message: fmt.Sprintf(format, args...)}
	}

	current, err := t.Vault.Read(ctx, t.VaultRef)
	if err != nil {
		return failed("Reading current password from Vault: %v", err)
	}
	oldPassword, ok := current.Data[t.PasswordKey].(string)
	if !ok || oldPassword == "" {
		return failed("Vault secret %s has no string key %q", t.VaultRef, t.PasswordKey)
	}
	switch err := t.Engine.VerifyLogin(ctx, t.Endpoint, creds(t, oldPassword)); {
	case errors.Is(err, engine.ErrCredentialsExpired):
		// Applications cannot log in already; new credentials are what fixes that.
		t.warn(fmt.Sprintf("The current credentials of %q in Vault have expired; issuing new ones", t.Account.Username))
	case err != nil:
		return failed("The current password in Vault does not work for %q, not rotating: %v", t.Account.Username, err)
	}
	if pf, ok := t.Engine.(engine.Preflighter); ok {
		if err := pf.Preflight(ctx, t.Endpoint, t.Master); err != nil {
			return failed("Not rotating: %v", err)
		}
	}

	var newPassword string
	if issuer, ok := t.Engine.(engine.Issuer); ok {
		newPassword, err = issuer.Issue(ctx, t.Endpoint, t.Master, t.Account, oldPassword)
	} else {
		newPassword, err = t.NewPassword()
	}
	if err != nil {
		return failed("Generating the new credentials: %v", err)
	}
	if err := t.Pending.Save(ctx, &Pending{OldPassword: oldPassword, NewPassword: newPassword}); err != nil {
		return failed("Saving pending password: %v", err)
	}
	return advance(ctx, st, persist, krotosv1alpha1.StepPendingSaved)
}

func updateDatabase(ctx context.Context, t *Target, st *State, persist Persist) *Result {
	p, res := loadPending(ctx, t)
	if res != nil {
		return res
	}
	if err := t.Engine.SetPassword(ctx, t.Endpoint, t.Master, t.Account, p.NewPassword); err != nil {
		return retryOrRollback(ctx, t, st, persist, p, maxDBRetries, fmt.Sprintf("Changing the password in the database: %v", err))
	}
	return advance(ctx, st, persist, krotosv1alpha1.StepDbUpdated)
}

func verifyNewPassword(ctx context.Context, t *Target, st *State, persist Persist) *Result {
	p, res := loadPending(ctx, t)
	if res != nil {
		return res
	}
	if err := t.Engine.VerifyLogin(ctx, t.Endpoint, creds(t, p.NewPassword)); err != nil {
		return retryOrRollback(ctx, t, st, persist, p, maxDBRetries, fmt.Sprintf("Logging in with the new password: %v", err))
	}
	return advance(ctx, st, persist, krotosv1alpha1.StepVerified)
}

// writeVault writes the new password with check-and-set against the version it
// just read, keeping the secret's other keys. A write that already happened (e.g.
// before a crash) is detected and treated as done.
func writeVault(ctx context.Context, t *Target, st *State, persist Persist) *Result {
	p, res := loadPending(ctx, t)
	if res != nil {
		return res
	}

	err := func() error {
		current, err := t.Vault.Read(ctx, t.VaultRef)
		if err != nil {
			return err
		}
		if current.Data[t.PasswordKey] == p.NewPassword {
			return nil
		}
		data := make(map[string]any, len(current.Data)+2)
		maps.Copy(data, current.Data)
		data[t.PasswordKey] = p.NewPassword
		if t.UsernameKey != "" {
			data[t.UsernameKey] = t.Account.Username
		}
		_, err = t.Vault.Write(ctx, t.VaultRef, data, current.Version)
		return err
	}()
	if err != nil {
		msg := fmt.Sprintf("Writing the new password to Vault: %v", err)
		if st.Retries+1 >= maxVaultRetries && vaultHasPassword(ctx, t, p.NewPassword) {
			// The write went through even though we saw an error.
			return advance(ctx, st, persist, krotosv1alpha1.StepVaultWritten)
		}
		return retryOrRollback(ctx, t, st, persist, p, maxVaultRetries, msg)
	}
	return advance(ctx, st, persist, krotosv1alpha1.StepVaultWritten)
}

// rollback restores the old password in the database. It retries until it succeeds.
func rollback(ctx context.Context, t *Target, st *State, persist Persist) *Result {
	p, res := loadPending(ctx, t)
	if res != nil {
		return res
	}

	// A rollback is done when the old password works. If it still does, the database was
	// never changed (every engine's ALTER replaces the password), so there is nothing to
	// undo; this also keeps a permanent ALTER error (e.g. a missing privilege) from
	// failing the rollback forever.
	err := t.Engine.VerifyLogin(ctx, t.Endpoint, creds(t, p.OldPassword))
	if errors.Is(err, engine.ErrCredentialsExpired) {
		// Expiring credentials are not stored on the server: nothing to restore.
		err = nil
	}
	if err != nil {
		err = t.Engine.SetPassword(ctx, t.Endpoint, t.Master, t.Account, p.OldPassword)
		if err == nil {
			err = t.Engine.VerifyLogin(ctx, t.Endpoint, creds(t, p.OldPassword))
		}
	}
	if err != nil {
		st.Retries++
		msg := fmt.Sprintf("Rollback to the old password failed, the database may not match Vault: %v (rollback started because: %s)", err, p.FailureReason)
		if perr := persist(ctx, *st); perr != nil {
			return &Result{Outcome: OutcomeStuck, RequeueAfter: backoff(st.Retries), Message: msg + "; persisting state: " + perr.Error()}
		}
		return &Result{Outcome: OutcomeStuck, RequeueAfter: backoff(st.Retries), Message: msg}
	}

	reason := p.FailureReason
	if reason == "" {
		reason = "an earlier step kept failing"
	}
	if err := t.Pending.Delete(ctx); err != nil {
		// The rollback is done; a stale pending secret is overwritten by the next rotation.
		reason += fmt.Sprintf(" (deleting pending password failed: %v)", err)
	}
	*st = State{}
	if err := persist(ctx, *st); err != nil {
		return &Result{Outcome: OutcomeRetry, RequeueAfter: baseBackoff, Message: "Persisting state after rollback: " + err.Error()}
	}
	return &Result{Outcome: OutcomeFailed, RolledBack: true, Message: "Rolled back to the old password: " + reason}
}

func retryOrRollback(ctx context.Context, t *Target, st *State, persist Persist, p *Pending, maxRetries int32, msg string) *Result {
	st.Retries++
	if st.Retries < maxRetries {
		if err := persist(ctx, *st); err != nil {
			return &Result{Outcome: OutcomeRetry, RequeueAfter: baseBackoff, Message: msg + "; persisting state: " + err.Error()}
		}
		return &Result{
			Outcome:      OutcomeRetry,
			RequeueAfter: backoff(st.Retries),
			Message:      fmt.Sprintf("%s (attempt %d of %d)", msg, st.Retries, maxRetries),
		}
	}

	// Recording the reason is best effort: when Vault is down it cannot be saved,
	// and that must not block the rollback.
	p.FailureReason = msg
	_ = t.Pending.Save(ctx, p)
	res := advance(ctx, st, persist, krotosv1alpha1.StepRollingBack)
	if res != nil {
		return res
	}
	// Continue with the rollback in the same run.
	return nil
}

func advance(ctx context.Context, st *State, persist Persist, next krotosv1alpha1.RotationStep) *Result {
	prev := *st
	*st = State{Step: next}
	if err := persist(ctx, *st); err != nil {
		// The step's effect is idempotent, so redoing it after a restart is safe.
		*st = prev
		return &Result{Outcome: OutcomeRetry, RequeueAfter: baseBackoff, Message: "Persisting rotation state: " + err.Error()}
	}
	return nil
}

func loadPending(ctx context.Context, t *Target) (*Pending, *Result) {
	p, err := t.Pending.Load(ctx)
	if err != nil {
		return nil, &Result{Outcome: OutcomeRetry, RequeueAfter: baseBackoff, Message: "Loading pending password: " + err.Error()}
	}
	if p == nil {
		return nil, &Result{
			Outcome:      OutcomeStuck,
			RequeueAfter: maxBackoff,
			Message: "The pending passwords are missing from Vault while a rotation is in progress; the " +
				"database password may no longer match Vault. Set the password manually so that the " +
				"database and Vault agree, then clear status.step (see README, Troubleshooting).",
		}
	}
	return p, nil
}

func vaultHasPassword(ctx context.Context, t *Target, password string) bool {
	s, err := t.Vault.Read(ctx, t.VaultRef)
	return err == nil && s.Data[t.PasswordKey] == password
}

func (t *Target) warn(msg string) {
	if t.Warn != nil {
		t.Warn(msg)
	}
}

func creds(t *Target, password string) engine.Credentials {
	return engine.Credentials{Username: t.Account.Username, Password: password}
}

func backoff(retries int32) time.Duration {
	d := baseBackoff
	for i := int32(1); i < retries && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}
