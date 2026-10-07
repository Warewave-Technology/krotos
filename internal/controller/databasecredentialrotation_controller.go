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

package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
	"github.com/Warewave-Technology/krotos/internal/engine"
	"github.com/Warewave-Technology/krotos/internal/metrics"
	"github.com/Warewave-Technology/krotos/internal/restart"
	"github.com/Warewave-Technology/krotos/internal/rotation"
	"github.com/Warewave-Technology/krotos/internal/schedule"
	"github.com/Warewave-Technology/krotos/internal/secretsync"
)

const (
	// maxIdleRequeue bounds how long the controller sleeps before re-evaluating the schedule.
	maxIdleRequeue = time.Hour
	// failureBackoffBase is the wait after the first failed attempt; it doubles per failure.
	failureBackoffBase = 5 * time.Minute
	failureBackoffMax  = 6 * time.Hour
	// resolveRetry is the wait when an in-flight rotation cannot load its dependencies.
	resolveRetry = time.Minute
	// finalizeRetry is the wait when cleaning up after a finished rotation failed.
	finalizeRetry = 15 * time.Second
	// rolloutPoll is how often restarted workloads are checked.
	rolloutPoll = 10 * time.Second
	// defaultRolloutTimeout matches the API default for objects that predate it.
	defaultRolloutTimeout = 10 * time.Minute
	// secretSyncPoll is how often a synced Secret is checked.
	secretSyncPoll = 5 * time.Second
	// defaultSecretSyncTimeout matches the API default for objects that predate it.
	defaultSecretSyncTimeout = 5 * time.Minute
)

// Condition reasons.
const (
	ReasonSpecValid          = "SpecValid"
	ReasonInvalidSpec        = "InvalidSpec"
	ReasonEngineNotSupported = "EngineNotSupported"
	ReasonRotationSucceeded  = "RotationSucceeded"
	ReasonRotationFailed     = "RotationFailed"
	ReasonRolledBack         = "RolledBack"
	ReasonRotationStuck      = "RotationStuck"
	ReasonRolloutIncomplete  = "RolloutIncomplete"
	ReasonAsExpected         = "AsExpected"
)

// DatabaseCredentialRotationReconciler rotates database passwords on schedule.
type DatabaseCredentialRotationReconciler struct {
	client.Client
	// APIReader reads Secrets without caching them.
	APIReader client.Reader
	Scheme    *runtime.Scheme
	Recorder  events.EventRecorder
	Engines   map[krotosv1alpha1.Engine]engine.Engine
	OpenVault VaultStoreFunc
	// PendingCache keeps in-flight rotations' passwords in memory, so a rotation
	// can roll back while Vault is unreachable.
	PendingCache *rotation.PendingCache
	// Now is overridable for tests.
	Now func() time.Time
}

// +kubebuilder:rbac:groups=krotos.warewave.io,resources=databasecredentialrotations,verbs=get;list;watch;create;update;patch;delete,namespace=system
// +kubebuilder:rbac:groups=krotos.warewave.io,resources=databasecredentialrotations/status,verbs=get;update;patch,namespace=system
// +kubebuilder:rbac:groups=krotos.warewave.io,resources=databasecredentialrotations/finalizers,verbs=update,namespace=system
// +kubebuilder:rbac:groups=krotos.warewave.io,resources=vaultconnections,verbs=get;list;watch,namespace=system
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get,namespace=system
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch,namespace=system
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch,namespace=system
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch;patch,namespace=system
// +kubebuilder:rbac:groups=external-secrets.io,resources=externalsecrets,verbs=get;patch,namespace=system
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets,verbs=get;patch,namespace=system

// Reconcile decides whether a rotation is due and inside the change window, and
// drives an in-flight rotation forward.
func (r *DatabaseCredentialRotationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj krotosv1alpha1.DatabaseCredentialRotation
	if err := r.Get(ctx, req.NamespacedName, &obj); err != nil {
		if apierrors.IsNotFound(err) {
			metrics.ForgetRotation(req.Namespace, req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	deleting := !obj.DeletionTimestamp.IsZero()
	switch {
	case deleting && obj.Status.Step == krotosv1alpha1.StepNone:
		// Nothing in flight: let the object go.
		metrics.ForgetRotation(obj.Namespace, obj.Name)
		return ctrl.Result{}, r.updateFinalizer(ctx, &obj, false)
	case !deleting && !controllerutil.ContainsFinalizer(&obj, krotosv1alpha1.FinalizerRotation):
		// Deleting the object mid-rotation must not abandon a changed database password.
		if err := r.updateFinalizer(ctx, &obj, true); err != nil {
			return ctrl.Result{}, err
		}
	}

	sp := &statusPatcher{c: r.Client, obj: &obj, base: obj.DeepCopy()}
	res, err := r.reconcile(ctx, &obj, sp)
	if perr := sp.patch(ctx); perr != nil && err == nil {
		err = perr
	}
	recordStatusMetrics(&obj)
	return res, err
}

// recordStatusMetrics exports the rotation's status as gauges.
func recordStatusMetrics(obj *krotosv1alpha1.DatabaseCredentialRotation) {
	ns, name, st := obj.Namespace, obj.Name, &obj.Status
	if st.LastRotationTime != nil {
		metrics.LastSuccess.WithLabelValues(ns, name).Set(metrics.Timestamp(st.LastRotationTime.Time))
	}
	if st.NextScheduledTime != nil {
		metrics.NextRotation.WithLabelValues(ns, name).Set(metrics.Timestamp(st.NextScheduledTime.Time))
	}
	metrics.Degraded.WithLabelValues(ns, name).Set(metrics.Bool(
		meta.IsStatusConditionTrue(st.Conditions, krotosv1alpha1.ConditionDegraded)))
	metrics.ConsecutiveFailures.WithLabelValues(ns, name).Set(float64(st.ConsecutiveFailures))
}

func (r *DatabaseCredentialRotationReconciler) updateFinalizer(
	ctx context.Context, obj *krotosv1alpha1.DatabaseCredentialRotation, add bool,
) error {
	base := obj.DeepCopy()
	changed := controllerutil.AddFinalizer(obj, krotosv1alpha1.FinalizerRotation)
	if !add {
		changed = controllerutil.RemoveFinalizer(obj, krotosv1alpha1.FinalizerRotation)
	}
	if !changed {
		return nil
	}
	status := obj.Status
	if err := r.Patch(ctx, obj, client.MergeFrom(base)); err != nil {
		return client.IgnoreNotFound(err)
	}
	obj.Status = status
	return nil
}

func (r *DatabaseCredentialRotationReconciler) reconcile(
	ctx context.Context, obj *krotosv1alpha1.DatabaseCredentialRotation, sp *statusPatcher,
) (ctrl.Result, error) {
	now := r.now()
	obj.Status.ObservedGeneration = obj.Generation

	planner, specErr := schedule.NewPlanner(&obj.Spec)
	eng, engineOK := r.Engines[obj.Spec.Engine]
	switch {
	case specErr != nil:
		setCondition(obj, krotosv1alpha1.ConditionReady, false, ReasonInvalidSpec, specErr.Error())
	case !engineOK:
		setCondition(obj, krotosv1alpha1.ConditionReady, false, ReasonEngineNotSupported,
			fmt.Sprintf("Engine %q is not supported yet", obj.Spec.Engine))
	default:
		setCondition(obj, krotosv1alpha1.ConditionReady, true, ReasonSpecValid, "")
	}

	inProgress := obj.Status.Step != krotosv1alpha1.StepNone
	if inProgress && !obj.DeletionTimestamp.IsZero() {
		obj.Status.Message = "Deletion requested; finishing the rotation in progress first"
	}
	if !inProgress {
		if !meta.IsStatusConditionTrue(obj.Status.Conditions, krotosv1alpha1.ConditionReady) {
			// Spec changes trigger a new reconcile.
			return ctrl.Result{}, nil
		}
		start, res := r.decide(obj, planner, now)
		if !start {
			return res, nil
		}
		obj.Status.LastAttemptTime = &metav1.Time{Time: now}
		obj.Status.Phase = krotosv1alpha1.PhaseRotating
		obj.Status.Message = "Rotation started"
		obj.Status.NextWindowStart = nil
		r.event(obj, corev1.EventTypeNormal, "RotationStarted", "Rotating the password of %q", obj.Spec.Target.Username)
		if err := sp.patch(ctx); err != nil {
			return ctrl.Result{}, err
		}
	} else if !engineOK {
		obj.Status.Message = fmt.Sprintf("A rotation is in progress but engine %q is not supported", obj.Spec.Engine)
		return ctrl.Result{RequeueAfter: resolveRetry}, nil
	}

	target, err := r.buildTarget(ctx, obj, eng)
	if err != nil {
		msg := "Preparing rotation: " + err.Error()
		if !inProgress {
			return r.finishFailed(ctx, obj, sp, msg, false)
		}
		obj.Status.Message = msg
		return ctrl.Result{RequeueAfter: resolveRetry}, nil
	}

	state := rotation.State{Step: obj.Status.Step, Retries: obj.Status.Retries}
	persist := func(ctx context.Context, s rotation.State) error {
		obj.Status.Step = s.Step
		obj.Status.Retries = s.Retries
		return sp.patch(ctx)
	}
	res := rotation.Run(ctx, target, &state, persist)
	obj.Status.Step, obj.Status.Retries = state.Step, state.Retries

	switch res.Outcome {
	case rotation.OutcomeVaultWritten:
		return r.afterVaultWritten(ctx, obj, sp, target)
	case rotation.OutcomeFailed:
		return r.finishFailed(ctx, obj, sp, res.Message, res.RolledBack)
	case rotation.OutcomeStuck:
		obj.Status.Message = res.Message
		setCondition(obj, krotosv1alpha1.ConditionDegraded, true, ReasonRotationStuck, res.Message)
		r.event(obj, corev1.EventTypeWarning, ReasonRotationStuck, "%s", res.Message)
		return ctrl.Result{RequeueAfter: res.RequeueAfter}, nil
	default: // OutcomeRetry
		obj.Status.Message = res.Message
		setCondition(obj, krotosv1alpha1.ConditionDegraded, false, ReasonAsExpected, "")
		logf.FromContext(ctx).Info("Rotation step will be retried", "step", obj.Status.Step, "message", res.Message)
		return ctrl.Result{RequeueAfter: res.RequeueAfter}, nil
	}
}

// decide evaluates the schedule and window. It returns true when a rotation should
// start now, and otherwise updates the status and says when to look again.
func (r *DatabaseCredentialRotationReconciler) decide(
	obj *krotosv1alpha1.DatabaseCredentialRotation, planner *schedule.Planner, now time.Time,
) (bool, ctrl.Result) {
	st := &obj.Status
	if obj.Spec.Suspend {
		if st.Phase != krotosv1alpha1.PhaseFailed {
			st.Phase = krotosv1alpha1.PhaseIdle
		}
		st.Message = "Suspended"
		st.NextWindowStart = nil
		return false, ctrl.Result{}
	}

	ignoreWindow := obj.Annotations[krotosv1alpha1.AnnotationIgnoreWindow] == "true"
	in := schedule.Input{
		Now:          now,
		Created:      obj.CreationTimestamp.Time,
		RotateNow:    obj.Annotations[krotosv1alpha1.AnnotationRotateNow] == "true",
		IgnoreWindow: ignoreWindow,
	}
	if st.LastRotationTime != nil {
		in.LastRotation = &st.LastRotationTime.Time
	}
	d := planner.Decide(in)
	nextStart := d.NextStart

	if d.Start && st.ConsecutiveFailures > 0 && st.LastAttemptTime != nil {
		retryAt := st.LastAttemptTime.Add(failureBackoff(st.ConsecutiveFailures))
		if now.Before(retryAt) {
			d.Start = false
			nextStart = retryAt
			if !ignoreWindow {
				nextStart = planner.Window.NextStart(retryAt)
			}
		}
	}

	st.NextScheduledTime = &metav1.Time{Time: d.Due}
	if d.Start {
		return true, ctrl.Result{}
	}
	st.NextWindowStart = &metav1.Time{Time: nextStart}

	switch {
	case st.ConsecutiveFailures > 0:
		// Keep the failure message; it explains the Failed phase.
		st.Phase = krotosv1alpha1.PhaseFailed
	case !d.Due.After(now):
		st.Phase = krotosv1alpha1.PhaseWaiting
		st.Message = fmt.Sprintf("Rotation is due, waiting for the change window at %s", nextStart.Format(time.RFC3339))
	default:
		st.Phase = krotosv1alpha1.PhaseIdle
		st.Message = fmt.Sprintf("Next rotation at %s", nextStart.Format(time.RFC3339))
	}

	wait := min(nextStart.Sub(now), maxIdleRequeue)
	if wait <= 0 {
		wait = time.Second
	}
	return false, ctrl.Result{RequeueAfter: wait}
}

// afterVaultWritten runs once the database and Vault hold the new password: it
// drops the pending passwords, then restarts the workloads and waits for them.
func (r *DatabaseCredentialRotationReconciler) afterVaultWritten(
	ctx context.Context, obj *krotosv1alpha1.DatabaseCredentialRotation, sp *statusPatcher, target *rotation.Target,
) (ctrl.Result, error) {
	st := &obj.Status
	if st.Step == krotosv1alpha1.StepVaultWritten {
		if st.SecretSyncStartTime == nil {
			// No rollback is possible from here on, so the old and new passwords are not needed.
			if err := target.Pending.Delete(ctx); err != nil {
				st.Message = "Removing the pending passwords from Vault: " + err.Error()
				return ctrl.Result{RequeueAfter: finalizeRetry}, nil
			}
		}
		if t := obj.Spec.SecretSync.Type; t != "" && t != krotosv1alpha1.SecretSyncNone {
			res, synced, err := r.syncSecret(ctx, obj, sp, target)
			if !synced {
				return res, err
			}
		}
		st.Step, st.Retries = krotosv1alpha1.StepSecretSynced, 0
		st.SecretSyncStartTime = nil
		st.RolloutStartTime = &metav1.Time{Time: r.now()}
		if n := len(obj.Spec.RestartTargets); n > 0 {
			r.event(obj, corev1.EventTypeNormal, "RestartingWorkloads", "Restarting %d restart target(s)", n)
		}
		if err := sp.patch(ctx); err != nil {
			return ctrl.Result{}, err
		}
	}
	return r.restartWorkloads(ctx, obj, sp)
}

// syncSecret makes the ExternalSecret / VaultStaticSecret copy the new password
// into its Kubernetes Secret and waits until it did. It returns synced=true to go on
// with the restarts. Restarting before the Secret holds the new password would start
// the workloads with the old one, so when the sync does not happen the rotation
// finishes as Degraded without restarting anything.
func (r *DatabaseCredentialRotationReconciler) syncSecret(
	ctx context.Context, obj *krotosv1alpha1.DatabaseCredentialRotation, sp *statusPatcher, target *rotation.Target,
) (ctrl.Result, bool, error) {
	st := &obj.Status
	spec := obj.Spec.SecretSync
	name := secretsync.Describe(spec)
	user := obj.Spec.Target.Username
	// Keep the start time locally: the patch below replaces the status with the
	// server's copy, which would drop it if the installed CRD predates the field.
	started := st.SecretSyncStartTime
	if started == nil {
		started = &metav1.Time{Time: r.now()}
		st.SecretSyncStartTime = started
		r.event(obj, corev1.EventTypeNormal, "SyncingSecret", "Asking %s to sync the new password", name)
		if err := sp.patch(ctx); err != nil {
			return ctrl.Result{}, false, err
		}
	}
	timeout := spec.Timeout.Duration
	if timeout <= 0 {
		timeout = defaultSecretSyncTimeout
	}
	timedOut := r.now().After(started.Add(timeout))
	giveUp := func(problem string) (ctrl.Result, bool, error) {
		res, err := r.finishSucceeded(ctx, obj, sp, fmt.Sprintf("Rotated the password of %q", user),
			problem+"; workloads were not restarted")
		return res, false, err
	}
	wait := func(msg string) (ctrl.Result, bool, error) {
		if timedOut {
			return giveUp(fmt.Sprintf("%s after %s: %s", "Secret sync timed out", timeout, msg))
		}
		st.Phase = krotosv1alpha1.PhaseRotating
		st.Message = msg
		return ctrl.Result{RequeueAfter: secretSyncPoll}, false, nil
	}

	syncer := &secretsync.Syncer{Client: r.Client, Reader: r.APIReader, Namespace: obj.Namespace}
	if err := syncer.Trigger(ctx, spec, rotationToken(st)); err != nil {
		if errors.Is(err, secretsync.ErrNotFound) {
			return giveUp(err.Error())
		}
		return wait("Triggering the secret sync: " + err.Error())
	}

	current, err := target.Vault.Read(ctx, target.VaultRef)
	if err != nil {
		return wait("Reading the new password from Vault: " + err.Error())
	}
	password, _ := current.Data[target.PasswordKey].(string)
	synced, err := syncer.Synced(ctx, spec, password)
	switch {
	case err != nil:
		return wait("Checking the synced Secret: " + err.Error())
	case !synced:
		return wait(fmt.Sprintf("Waiting for %s to sync the new password into its Secret", name))
	}
	return ctrl.Result{}, true, nil
}

// rotationToken identifies the in-flight rotation by its start time, so that each
// rotation triggers a sync and restarts a workload exactly once.
func rotationToken(st *krotosv1alpha1.DatabaseCredentialRotationStatus) string {
	started := st.LastAttemptTime
	if started == nil {
		started = st.RolloutStartTime
	}
	if started == nil {
		started = st.SecretSyncStartTime
	}
	if started == nil {
		// Not expected: the attempt time is set when a rotation starts. A constant
		// token still triggers at most once.
		return "unknown"
	}
	return started.UTC().Format(time.RFC3339)
}

// restartWorkloads restarts the restart targets once per rotation and waits for
// their rollouts. The password is already rotated, so a rollout problem does not
// fail the rotation; it is reported through the Degraded condition.
func (r *DatabaseCredentialRotationReconciler) restartWorkloads(
	ctx context.Context, obj *krotosv1alpha1.DatabaseCredentialRotation, sp *statusPatcher,
) (ctrl.Result, error) {
	st := &obj.Status
	user := obj.Spec.Target.Username
	if len(obj.Spec.RestartTargets) == 0 {
		return r.finishSucceeded(ctx, obj, sp, fmt.Sprintf("Rotated the password of %q; no restart targets configured", user), "")
	}

	token := rotationToken(st)
	timeout := obj.Spec.RolloutTimeout.Duration
	if timeout <= 0 {
		timeout = defaultRolloutTimeout
	}
	timedOut := st.RolloutStartTime != nil && r.now().After(st.RolloutStartTime.Add(timeout))

	restarter := &restart.Restarter{Client: r.Client, Reader: r.APIReader, Namespace: obj.Namespace}
	workloads, warnings, err := restarter.Resolve(ctx, obj.Spec.RestartTargets)
	if err != nil {
		if timedOut {
			return r.finishSucceeded(ctx, obj, sp, fmt.Sprintf("Rotated the password of %q", user), "Resolving restart targets: "+err.Error())
		}
		st.Message = "Resolving restart targets: " + err.Error()
		return ctrl.Result{RequeueAfter: rolloutPoll}, nil
	}

	var pending, failed []string
	for _, w := range workloads {
		s, err := restarter.Ensure(ctx, w, token)
		switch {
		case err != nil:
			pending = append(pending, fmt.Sprintf("%s: %v", w, err))
		case s.Failed:
			failed = append(failed, s.Message)
		case !s.Done:
			pending = append(pending, s.Message)
		}
	}

	problems := slices.Concat(failed, pending, warnings)
	switch {
	case len(pending) == 0 && len(failed) == 0:
		return r.finishSucceeded(ctx, obj, sp,
			fmt.Sprintf("Rotated the password of %q and restarted %d workload(s)", user, len(workloads)), strings.Join(warnings, "; "))
	case len(pending) == 0 || timedOut:
		if timedOut {
			problems = append([]string{"rollout timed out"}, problems...)
		}
		return r.finishSucceeded(ctx, obj, sp, fmt.Sprintf("Rotated the password of %q", user), strings.Join(problems, "; "))
	}

	st.Phase = krotosv1alpha1.PhaseRestarting
	st.Message = "Waiting for rollouts: " + strings.Join(problems, "; ")
	return ctrl.Result{RequeueAfter: rolloutPoll}, nil
}

// finishSucceeded completes a rotation. A non-empty rolloutProblem marks the
// rotation Degraded: the password is rotated but some workloads may still use the old one.
func (r *DatabaseCredentialRotationReconciler) finishSucceeded(
	ctx context.Context, obj *krotosv1alpha1.DatabaseCredentialRotation, sp *statusPatcher, msg, rolloutProblem string,
) (ctrl.Result, error) {
	st := &obj.Status
	now := r.now()
	engineName := string(obj.Spec.Engine)
	metrics.RotationsTotal.WithLabelValues(obj.Namespace, obj.Name, engineName, metrics.ResultSucceeded).Inc()
	if st.LastAttemptTime != nil {
		metrics.RotationDuration.WithLabelValues(engineName).Observe(now.Sub(st.LastAttemptTime.Time).Seconds())
	}
	st.Step, st.Retries = krotosv1alpha1.StepNone, 0
	st.RolloutStartTime, st.SecretSyncStartTime = nil, nil
	st.LastRotationTime = &metav1.Time{Time: now}
	st.ConsecutiveFailures = 0
	st.Phase = krotosv1alpha1.PhaseIdle
	st.Message = msg
	setCondition(obj, krotosv1alpha1.ConditionRotated, true, ReasonRotationSucceeded, msg)
	r.event(obj, corev1.EventTypeNormal, ReasonRotationSucceeded, "%s", msg)
	if rolloutProblem != "" {
		st.Message = msg + "; restarts need attention: " + rolloutProblem
		setCondition(obj, krotosv1alpha1.ConditionDegraded, true, ReasonRolloutIncomplete, rolloutProblem)
		r.event(obj, corev1.EventTypeWarning, ReasonRolloutIncomplete, "%s", rolloutProblem)
	} else {
		setCondition(obj, krotosv1alpha1.ConditionDegraded, false, ReasonAsExpected, "")
	}
	return r.afterAttempt(ctx, obj, sp)
}

func (r *DatabaseCredentialRotationReconciler) finishFailed(
	ctx context.Context, obj *krotosv1alpha1.DatabaseCredentialRotation, sp *statusPatcher, msg string, rolledBack bool,
) (ctrl.Result, error) {
	st := &obj.Status
	st.Step, st.Retries = krotosv1alpha1.StepNone, 0
	st.ConsecutiveFailures++
	st.Phase = krotosv1alpha1.PhaseFailed
	st.Message = msg
	reason, result := ReasonRotationFailed, metrics.ResultFailed
	if rolledBack {
		reason, result = ReasonRolledBack, metrics.ResultRolledBack
	}
	metrics.RotationsTotal.WithLabelValues(obj.Namespace, obj.Name, string(obj.Spec.Engine), result).Inc()
	setCondition(obj, krotosv1alpha1.ConditionRotated, false, reason, msg)
	setCondition(obj, krotosv1alpha1.ConditionDegraded, false, ReasonAsExpected, "")
	r.event(obj, corev1.EventTypeWarning, reason, "%s", msg)
	return r.afterAttempt(ctx, obj, sp)
}

// afterAttempt persists the outcome, consumes one-shot trigger annotations and
// requeues to schedule the next rotation.
func (r *DatabaseCredentialRotationReconciler) afterAttempt(
	ctx context.Context, obj *krotosv1alpha1.DatabaseCredentialRotation, sp *statusPatcher,
) (ctrl.Result, error) {
	if err := sp.patch(ctx); err != nil {
		return ctrl.Result{}, err
	}
	_, rotateNow := obj.Annotations[krotosv1alpha1.AnnotationRotateNow]
	_, ignoreWindow := obj.Annotations[krotosv1alpha1.AnnotationIgnoreWindow]
	if rotateNow || ignoreWindow {
		base := obj.DeepCopy()
		delete(obj.Annotations, krotosv1alpha1.AnnotationRotateNow)
		delete(obj.Annotations, krotosv1alpha1.AnnotationIgnoreWindow)
		status := obj.Status
		if err := r.Patch(ctx, obj, client.MergeFrom(base)); err != nil {
			return ctrl.Result{}, err
		}
		// The patch response carries the server's status; keep ours for the final status patch.
		obj.Status = status
	}
	return ctrl.Result{RequeueAfter: time.Second}, nil
}

func (r *DatabaseCredentialRotationReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *DatabaseCredentialRotationReconciler) event(
	obj *krotosv1alpha1.DatabaseCredentialRotation, eventType, reason, note string, args ...any,
) {
	if r.Recorder != nil {
		r.Recorder.Eventf(obj, nil, eventType, reason, "Rotate", note, args...)
	}
}

func failureBackoff(failures int32) time.Duration {
	d := failureBackoffBase
	for i := int32(1); i < failures && d < failureBackoffMax; i++ {
		d *= 2
	}
	return min(d, failureBackoffMax)
}

func setCondition(obj *krotosv1alpha1.DatabaseCredentialRotation, condType string, status bool, reason, msg string) {
	s := metav1.ConditionFalse
	if status {
		s = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             s,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: obj.Generation,
	})
}

// statusPatcher patches the status subresource with only what changed since the last patch.
type statusPatcher struct {
	c    client.Client
	obj  *krotosv1alpha1.DatabaseCredentialRotation
	base *krotosv1alpha1.DatabaseCredentialRotation
}

func (p *statusPatcher) patch(ctx context.Context) error {
	if equality.Semantic.DeepEqual(p.base.Status, p.obj.Status) {
		return nil
	}
	if err := p.c.Status().Patch(ctx, p.obj, client.MergeFrom(p.base)); err != nil {
		return err
	}
	p.base = p.obj.DeepCopy()
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *DatabaseCredentialRotationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Spec changes and trigger annotations start a reconcile; status updates do not.
		For(&krotosv1alpha1.DatabaseCredentialRotation{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{}),
		)).
		Named("databasecredentialrotation").
		Complete(r)
}
