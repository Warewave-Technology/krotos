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

// Package secretsync makes External Secrets Operator and Vault Secrets Operator
// copy a rotated password from Vault into a Kubernetes Secret right away, and
// tells when they did. The resources are handled as unstructured objects so the
// operator does not depend on either project's Go API.
package secretsync

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
)

// Annotations that make the sync operators reconcile immediately.
const (
	// AnnotationESOForceSync is External Secrets Operator's documented trigger.
	AnnotationESOForceSync = "force-sync"
	// AnnotationSyncRequestedAt is set on VaultStaticSecrets; Vault Secrets Operator
	// reconciles on any annotation change and re-reads Vault when it does.
	AnnotationSyncRequestedAt = "krotos.warewave.io/sync-requested-at"
)

var (
	externalSecretGK    = schema.GroupKind{Group: "external-secrets.io", Kind: "ExternalSecret"}
	vaultStaticSecretGK = schema.GroupKind{Group: "secrets.hashicorp.com", Kind: "VaultStaticSecret"}
)

// ErrNotFound means the sync resource does not exist or its CRD is not installed.
var ErrNotFound = errors.New("sync resource not found")

// Syncer triggers and checks secret syncs in one namespace.
type Syncer struct {
	// Client patches sync resources.
	Client client.Client
	// Reader reads them and the synced Secret; use an uncached reader.
	Reader    client.Reader
	Namespace string
}

// target returns the resource to trigger, its annotation and the synced Secret.
func target(spec krotosv1alpha1.SecretSync) (schema.GroupKind, string, *krotosv1alpha1.SyncedSecretReference, error) {
	switch spec.Type {
	case krotosv1alpha1.SecretSyncExternalSecret:
		if spec.ExternalSecret != nil {
			return externalSecretGK, AnnotationESOForceSync, spec.ExternalSecret, nil
		}
	case krotosv1alpha1.SecretSyncVaultStaticSecret:
		if spec.VaultStaticSecret != nil {
			return vaultStaticSecretGK, AnnotationSyncRequestedAt, spec.VaultStaticSecret, nil
		}
	}
	return schema.GroupKind{}, "", nil, fmt.Errorf("secretSync type %q has no reference", spec.Type)
}

// Describe names the sync resource for messages, e.g. "ExternalSecret/orders-db".
func Describe(spec krotosv1alpha1.SecretSync) string {
	gk, _, ref, err := target(spec)
	if err != nil {
		return string(spec.Type)
	}
	return gk.Kind + "/" + ref.Name
}

// Trigger asks the sync operator to sync now. token identifies the rotation; the
// resource is patched only once per token.
func (s *Syncer) Trigger(ctx context.Context, spec krotosv1alpha1.SecretSync, token string) error {
	gk, annotation, ref, err := target(spec)
	if err != nil {
		return err
	}
	mapping, err := s.Client.RESTMapper().RESTMapping(gk)
	if err != nil {
		if meta.IsNoMatchError(err) {
			return fmt.Errorf("%s: the %s CRD is not installed: %w", Describe(spec), gk, ErrNotFound)
		}
		return err
	}

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(mapping.GroupVersionKind)
	if err := s.Reader.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: ref.Name}, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("%s: %w", Describe(spec), ErrNotFound)
		}
		return err
	}
	if obj.GetAnnotations()[annotation] == token {
		return nil
	}

	base := obj.DeepCopy()
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[annotation] = token
	obj.SetAnnotations(annotations)
	if err := s.Client.Patch(ctx, obj, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("trigger %s: %w", Describe(spec), err)
	}
	return nil
}

// Synced reports whether the synced Secret holds password under the configured key.
func (s *Syncer) Synced(ctx context.Context, spec krotosv1alpha1.SecretSync, password string) (bool, error) {
	_, _, ref, err := target(spec)
	if err != nil {
		return false, err
	}
	key := ref.SecretKey
	if key == "" {
		key = "password"
	}
	var sec corev1.Secret
	if err := s.Reader.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: ref.SecretName}, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			// The sync operator may not have created it yet.
			return false, nil
		}
		return false, err
	}
	return subtle.ConstantTimeCompare(sec.Data[key], []byte(password)) == 1, nil
}
