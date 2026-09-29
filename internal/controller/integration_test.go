//go:build integration

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

	"github.com/jackc/pgx/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcvault "github.com/testcontainers/testcontainers-go/modules/vault"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	krotosv1alpha1 "github.com/warewave/krotos/api/v1alpha1"
	"github.com/warewave/krotos/internal/engine"
	"github.com/warewave/krotos/internal/engine/postgres"
	"github.com/warewave/krotos/internal/rotation"
	"github.com/warewave/krotos/internal/vault"
)

var _ = Describe("Rotation against real Vault and PostgreSQL", Ordered, func() {
	const (
		rootToken   = "root"
		masterUser  = "master"
		masterPass  = "master-password"
		appUserName = "orders_app"
		appPass     = "initial-app-password"
	)

	var (
		pgEndpoint engine.Endpoint
		vaultAddr  string
		root       *vault.Client
		reconciler *DatabaseCredentialRotationReconciler
	)

	BeforeAll(func() {
		bg := context.Background()

		pg, err := tcpostgres.Run(bg, "postgres:17-alpine",
			tcpostgres.WithDatabase("orders"),
			tcpostgres.WithUsername(masterUser),
			tcpostgres.WithPassword(masterPass),
			tcpostgres.BasicWaitStrategies(),
		)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = pg.Terminate(bg) })
		dsn, err := pg.ConnectionString(bg)
		Expect(err).NotTo(HaveOccurred())
		cfg, err := pgx.ParseConfig(dsn)
		Expect(err).NotTo(HaveOccurred())
		pgEndpoint = engine.Endpoint{Host: cfg.Host, Port: int32(cfg.Port), Database: "orders"}

		conn, err := pgx.ConnectConfig(bg, cfg)
		Expect(err).NotTo(HaveOccurred())
		_, err = conn.Exec(bg, "CREATE ROLE orders_app LOGIN PASSWORD '"+appPass+"'")
		Expect(err).NotTo(HaveOccurred())
		Expect(conn.Close(bg)).To(Succeed())

		vc, err := tcvault.Run(bg, "hashicorp/vault:1.20", tcvault.WithToken(rootToken))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = vc.Terminate(bg) })
		vaultAddr, err = vc.HttpHostAddress(bg)
		Expect(err).NotTo(HaveOccurred())

		root, err = vault.New(bg, vault.Config{Address: vaultAddr, Auth: &vault.TokenAuth{Token: rootToken}})
		Expect(err).NotTo(HaveOccurred())
		_, err = root.Write(bg, vault.SecretRef{Mount: "secret", Path: "db/orders/master", KVVersion: 2},
			map[string]any{"username": masterUser, "password": masterPass}, 0)
		Expect(err).NotTo(HaveOccurred())
		_, err = root.Write(bg, vault.SecretRef{Mount: "secret", Path: "apps/orders/db", KVVersion: 2},
			map[string]any{"password": appPass, "host": cfg.Host}, 0)
		Expect(err).NotTo(HaveOccurred())

		resolver := &vault.Resolver{Reader: k8sClient, Provider: vault.NewProvider()}
		reconciler = &DatabaseCredentialRotationReconciler{
			Client:       k8sClient,
			APIReader:    k8sClient,
			Scheme:       k8sClient.Scheme(),
			Recorder:     events.NewFakeRecorder(100),
			PendingCache: &rotation.PendingCache{},
			Engines:      map[krotosv1alpha1.Engine]engine.Engine{krotosv1alpha1.EnginePostgreSQL: postgres.Engine{}},
			OpenVault: func(ctx context.Context, conn *krotosv1alpha1.VaultConnection) (rotation.SecretStore, error) {
				c, _, err := resolver.Client(ctx, conn)
				return c, err
			},
		}
	})

	It("rotates the password end to end", func() {
		name := "integration"
		ensure(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "real-vault-token", Namespace: testNamespace},
			StringData: map[string]string{"token": rootToken},
		})
		ensure(&krotosv1alpha1.VaultConnection{
			ObjectMeta: metav1.ObjectMeta{Name: "real-vault", Namespace: testNamespace},
			Spec: krotosv1alpha1.VaultConnectionSpec{
				Address: vaultAddr,
				Auth: krotosv1alpha1.VaultAuth{Token: &krotosv1alpha1.VaultTokenAuth{
					SecretRef: krotosv1alpha1.SecretKeyReference{Name: "real-vault-token", Key: "token"},
				}},
			},
		})

		spec := validRotationSpec()
		spec.Database = krotosv1alpha1.DatabaseEndpoint{
			Host: pgEndpoint.Host, Port: pgEndpoint.Port, Database: "orders",
			// The test container has no TLS.
			TLS: &krotosv1alpha1.DatabaseTLS{Mode: krotosv1alpha1.TLSModeDisable},
		}
		spec.MasterCredentials = krotosv1alpha1.MasterCredentials{Vault: &krotosv1alpha1.VaultCredentialsReference{
			VaultSecretReference: krotosv1alpha1.VaultSecretReference{ConnectionRef: "real-vault", Path: "db/orders/master"},
		}}
		spec.Target.Vault.ConnectionRef = "real-vault"
		spec.Target.Vault.UsernameKey = "username"
		// Daily 24h window: the test can run at any time.
		spec.Window = krotosv1alpha1.MaintenanceWindow{Timezone: "UTC", Start: "00:00", Duration: metav1.Duration{Duration: 24 * time.Hour}}
		obj := &krotosv1alpha1.DatabaseCredentialRotation{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec:       spec,
		}
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, obj) })

		// Near the end of the day minRemaining (15m) could defer the start; allow it explicitly.
		obj.Annotations = map[string]string{krotosv1alpha1.AnnotationIgnoreWindow: "true"}
		Expect(k8sClient.Update(ctx, obj)).To(Succeed())

		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: testNamespace}})
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: testNamespace}, obj)).To(Succeed())
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseIdle), obj.Status.Message)
		Expect(obj.Status.LastRotationTime).NotTo(BeNil())

		s, err := root.Read(ctx, vault.SecretRef{Mount: "secret", Path: "apps/orders/db", KVVersion: 2})
		Expect(err).NotTo(HaveOccurred())
		newPass, _ := s.Data["password"].(string)
		Expect(newPass).NotTo(Equal(appPass))
		Expect(s.Data["username"]).To(Equal(appUserName))
		Expect(s.Data["host"]).To(Equal(pgEndpoint.Host))
		Expect(s.Version).To(Equal(2))

		// The pending passwords are gone from Vault, including every KV v2 version.
		_, err = root.Read(ctx, vault.SecretRef{Mount: "secret", Path: rotation.DefaultPendingPath(testNamespace, name), KVVersion: 2})
		Expect(err).To(MatchError(vault.ErrNotFound))

		e := postgres.Engine{}
		Expect(e.VerifyLogin(ctx, pgEndpoint, engine.Credentials{Username: appUserName, Password: newPass})).To(Succeed())
		Expect(e.VerifyLogin(ctx, pgEndpoint, engine.Credentials{Username: appUserName, Password: appPass})).NotTo(Succeed())
	})
})
