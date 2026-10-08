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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
	"github.com/Warewave-Technology/krotos/internal/engine"
	"github.com/Warewave-Technology/krotos/internal/password"
	"github.com/Warewave-Technology/krotos/internal/rotation"
	"github.com/Warewave-Technology/krotos/internal/vault"
)

// VaultStoreFunc opens a Vault secret store for a VaultConnection.
type VaultStoreFunc func(ctx context.Context, conn *krotosv1alpha1.VaultConnection) (rotation.SecretStore, error)

// buildTarget resolves everything the rotation runner needs from the spec.
func (r *DatabaseCredentialRotationReconciler) buildTarget(
	ctx context.Context, obj *krotosv1alpha1.DatabaseCredentialRotation, eng engine.Engine,
) (*rotation.Target, error) {
	spec := &obj.Spec

	ep, err := r.endpoint(ctx, obj)
	if err != nil {
		return nil, err
	}
	master, err := r.masterCredentials(ctx, obj)
	if err != nil {
		return nil, err
	}
	store, err := r.vaultStore(ctx, obj.Namespace, spec.Target.Vault.ConnectionRef)
	if err != nil {
		return nil, err
	}

	account := engine.Account{Username: spec.Target.Username}
	if spec.Engine == krotosv1alpha1.EngineMySQL {
		account.MySQLHost = "%"
		if spec.Target.MySQLHost != nil {
			account.MySQLHost = *spec.Target.MySQLHost
		}
	}

	length := int(spec.PasswordPolicy.Length)
	if length == 0 {
		length = 32
	}
	exclude := spec.PasswordPolicy.ExcludeCharacters
	if exclude == "" {
		exclude = krotosv1alpha1.DefaultExcludeCharacters
	}

	return &rotation.Target{
		Engine:      eng,
		Endpoint:    ep,
		Master:      master,
		Account:     account,
		Vault:       store,
		VaultRef:    secretRef(spec.Target.Vault.VaultSecretReference),
		PasswordKey: defaultString(spec.Target.Vault.PasswordKey, "password"),
		UsernameKey: spec.Target.Vault.UsernameKey,
		Pending: &rotation.CachedPendingStore{
			Inner: &rotation.VaultPendingStore{Vault: store, Ref: pendingRef(obj)},
			Cache: r.PendingCache,
			Key:   string(obj.UID),
		},
		NewPassword: func() (string, error) { return password.Generate(length, exclude) },
		Warn: func(msg string) {
			r.event(obj, corev1.EventTypeWarning, ReasonCredentialsExpired, "%s", msg)
		},
	}, nil
}

func (r *DatabaseCredentialRotationReconciler) endpoint(
	ctx context.Context, obj *krotosv1alpha1.DatabaseCredentialRotation,
) (engine.Endpoint, error) {
	db := obj.Spec.Database
	// TLS is on unless disabled explicitly; the API defaults it, this covers older objects.
	ep := engine.Endpoint{Host: db.Host, Port: db.Port, Database: db.Database, TLSMode: krotosv1alpha1.TLSModeRequire}
	if db.TLS != nil {
		ep.TLSMode = db.TLS.Mode
		if ep.TLSMode == "" {
			ep.TLSMode = krotosv1alpha1.TLSModeRequire
		}
		if db.TLS.CASecretRef != nil {
			ca, err := vault.ReadSecretKey(ctx, r.APIReader, obj.Namespace, *db.TLS.CASecretRef)
			if err != nil {
				return engine.Endpoint{}, fmt.Errorf("database CA: %w", err)
			}
			ep.CACert = ca
		}
	}
	if db.ClickHouse != nil {
		ep.ClickHouseCluster = db.ClickHouse.Cluster
		ep.ClickHouseProtocol = db.ClickHouse.Protocol
	}
	if obj.Spec.Engine == krotosv1alpha1.EngineRedis {
		ep.RedisPersistence = string(krotosv1alpha1.RedisPersistenceAuto)
		if db.Redis != nil {
			if db.Redis.Persistence != "" {
				ep.RedisPersistence = string(db.Redis.Persistence)
			}
			ep.RedisNodes = db.Redis.Nodes
		}
	}
	if db.NATS != nil {
		ep.NATSCredentialsTTL = db.NATS.CredentialsTTL.Duration
	}
	return ep, nil
}

func (r *DatabaseCredentialRotationReconciler) masterCredentials(
	ctx context.Context, obj *krotosv1alpha1.DatabaseCredentialRotation,
) (engine.Credentials, error) {
	mc := obj.Spec.MasterCredentials
	// NATS signs with an account key: only the seed (the "password") is needed.
	needUser := obj.Spec.Engine != krotosv1alpha1.EngineNATS
	switch {
	case mc.Vault != nil:
		store, err := r.vaultStore(ctx, obj.Namespace, mc.Vault.ConnectionRef)
		if err != nil {
			return engine.Credentials{}, err
		}
		ref := secretRef(mc.Vault.VaultSecretReference)
		s, err := store.Read(ctx, ref)
		if err != nil {
			return engine.Credentials{}, fmt.Errorf("master credentials: %w", err)
		}
		userKey := defaultString(mc.Vault.UsernameKey, "username")
		passKey := defaultString(mc.Vault.PasswordKey, "password")
		u, _ := s.Data[userKey].(string)
		p, _ := s.Data[passKey].(string)
		if (needUser && u == "") || p == "" {
			if !needUser {
				return engine.Credentials{}, fmt.Errorf("master credentials: Vault secret %s needs string key %q", ref, passKey)
			}
			return engine.Credentials{}, fmt.Errorf("master credentials: Vault secret %s needs string keys %q and %q", ref, userKey, passKey)
		}
		return engine.Credentials{Username: u, Password: p}, nil

	case mc.SecretRef != nil:
		var sec corev1.Secret
		key := types.NamespacedName{Namespace: obj.Namespace, Name: mc.SecretRef.Name}
		if err := r.APIReader.Get(ctx, key, &sec); err != nil {
			if apierrors.IsNotFound(err) {
				return engine.Credentials{}, fmt.Errorf("master credentials: secret %q not found", key.Name)
			}
			return engine.Credentials{}, fmt.Errorf("master credentials: %w", err)
		}
		userKey := defaultString(mc.SecretRef.UsernameKey, "username")
		passKey := defaultString(mc.SecretRef.PasswordKey, "password")
		u, p := string(sec.Data[userKey]), string(sec.Data[passKey])
		if (needUser && u == "") || p == "" {
			if !needUser {
				return engine.Credentials{}, fmt.Errorf("master credentials: secret %q needs key %q", key.Name, passKey)
			}
			return engine.Credentials{}, fmt.Errorf("master credentials: secret %q needs keys %q and %q", key.Name, userKey, passKey)
		}
		return engine.Credentials{Username: u, Password: p}, nil

	default:
		return engine.Credentials{}, fmt.Errorf("no master credentials source configured")
	}
}

func (r *DatabaseCredentialRotationReconciler) vaultStore(ctx context.Context, namespace, name string) (rotation.SecretStore, error) {
	var conn krotosv1alpha1.VaultConnection
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &conn); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("VaultConnection %q not found", name)
		}
		return nil, err
	}
	store, err := r.OpenVault(ctx, &conn)
	if err != nil {
		return nil, fmt.Errorf("VaultConnection %q: %w", name, err)
	}
	return store, nil
}

// pendingRef is where the in-flight rotation's passwords are kept: the target's
// mount and KV version, at spec.target.vault.pendingPath or the default path.
func pendingRef(obj *krotosv1alpha1.DatabaseCredentialRotation) vault.SecretRef {
	ref := secretRef(obj.Spec.Target.Vault.VaultSecretReference)
	ref.Path = defaultString(obj.Spec.Target.Vault.PendingPath, rotation.DefaultPendingPath(obj.Namespace, obj.Name))
	return ref
}

func secretRef(ref krotosv1alpha1.VaultSecretReference) vault.SecretRef {
	kv := int(ref.KVVersion)
	if kv == 0 {
		kv = 2
	}
	return vault.SecretRef{Mount: defaultString(ref.Mount, "secret"), Path: ref.Path, KVVersion: kv}
}

func defaultString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
