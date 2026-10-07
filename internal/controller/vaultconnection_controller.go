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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
	"github.com/Warewave-Technology/krotos/internal/metrics"
	"github.com/Warewave-Technology/krotos/internal/vault"
)

const (
	// vaultConnectionRecheckInterval is how often a healthy connection is re-verified.
	vaultConnectionRecheckInterval = 5 * time.Minute
	// vaultConnectionRetryInterval is how often a failing connection is retried.
	vaultConnectionRetryInterval = time.Minute
)

// Reasons for the VaultConnection Ready condition.
const (
	ReasonAuthenticated = "Authenticated"
	ReasonInvalidConfig = "InvalidConfig"
	ReasonLoginFailed   = "LoginFailed"
)

// VaultConnectionReconciler verifies that the operator can log in to Vault.
type VaultConnectionReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Vault  *vault.Resolver
}

// +kubebuilder:rbac:groups=krotos.warewave.io,resources=vaultconnections,verbs=get;list;watch;create;update;patch;delete,namespace=system
// +kubebuilder:rbac:groups=krotos.warewave.io,resources=vaultconnections/status,verbs=get;update;patch,namespace=system
// +kubebuilder:rbac:groups=krotos.warewave.io,resources=vaultconnections/finalizers,verbs=update,namespace=system
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create,namespace=system

// Reconcile logs in to Vault with the connection's settings and reports the result
// in the Ready condition. Healthy connections are re-checked periodically.
func (r *VaultConnectionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var conn krotosv1alpha1.VaultConnection
	if err := r.Get(ctx, req.NamespacedName, &conn); err != nil {
		if apierrors.IsNotFound(err) {
			metrics.ForgetVaultConnection(req.Namespace, req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	cond := metav1.Condition{
		Type:               krotosv1alpha1.ConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             ReasonAuthenticated,
		Message:            "Logged in to Vault",
		ObservedGeneration: conn.Generation,
	}
	requeue := vaultConnectionRecheckInterval

	if err := r.check(ctx, &conn); err != nil {
		log.Info("Vault connection check failed", "error", err.Error())
		cond.Status = metav1.ConditionFalse
		cond.Reason = ReasonLoginFailed
		if vault.IsConfigError(err) {
			cond.Reason = ReasonInvalidConfig
		}
		cond.Message = err.Error()
		requeue = vaultConnectionRetryInterval
	}
	metrics.VaultConnectionReady.WithLabelValues(conn.Namespace, conn.Name).Set(
		metrics.Bool(cond.Status == metav1.ConditionTrue))

	base := conn.DeepCopy()
	now := metav1.Now()
	conn.Status.ObservedGeneration = conn.Generation
	conn.Status.LastCheckedTime = &now
	meta.SetStatusCondition(&conn.Status.Conditions, cond)
	if err := r.Status().Patch(ctx, &conn, client.MergeFrom(base)); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func (r *VaultConnectionReconciler) check(ctx context.Context, conn *krotosv1alpha1.VaultConnection) error {
	c, cfg, err := r.Vault.Client(ctx, conn)
	if err != nil {
		return err
	}
	if err := c.LookupSelf(ctx); err != nil {
		// The cached token may have been revoked; log in again next time.
		r.Vault.Provider.Invalidate(cfg)
		return err
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultConnectionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Status updates must not retrigger reconciles; the periodic requeue covers health.
		For(&krotosv1alpha1.VaultConnection{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("vaultconnection").
		Complete(r)
}
