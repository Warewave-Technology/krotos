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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
)

var _ = Describe("API validation", func() {
	var counter int
	name := func() string {
		counter++
		return fmt.Sprintf("validation-%d", counter)
	}

	createRotation := func(mutate func(*krotosv1alpha1.DatabaseCredentialRotationSpec)) error {
		spec := validRotationSpec()
		mutate(&spec)
		obj := &krotosv1alpha1.DatabaseCredentialRotation{
			ObjectMeta: metav1.ObjectMeta{Name: name(), Namespace: testNamespace},
			Spec:       spec,
		}
		return k8sClient.Create(ctx, obj)
	}

	createVaultConnection := func(mutate func(*krotosv1alpha1.VaultConnectionSpec)) error {
		spec := validVaultConnectionSpec()
		mutate(&spec)
		obj := &krotosv1alpha1.VaultConnection{
			ObjectMeta: metav1.ObjectMeta{Name: name(), Namespace: testNamespace},
			Spec:       spec,
		}
		return k8sClient.Create(ctx, obj)
	}

	It("applies defaults", func() {
		obj := &krotosv1alpha1.DatabaseCredentialRotation{
			ObjectMeta: metav1.ObjectMeta{Name: name(), Namespace: testNamespace},
			Spec:       validRotationSpec(),
		}
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		Expect(obj.Spec.PasswordPolicy.Length).To(Equal(int32(32)))
		Expect(obj.Spec.SecretSync.Type).To(Equal(krotosv1alpha1.SecretSyncNone))
		Expect(obj.Spec.SecretSync.Timeout.Duration).To(Equal(5 * time.Minute))
		Expect(obj.Spec.RolloutTimeout.Duration).To(Equal(10 * time.Minute))
		Expect(obj.Spec.Window.MinRemaining.Duration).To(Equal(15 * time.Minute))
		Expect(obj.Spec.Database.TLS).NotTo(BeNil())
		Expect(obj.Spec.Database.TLS.Mode).To(Equal(krotosv1alpha1.TLSModeRequire))
		Expect(obj.Spec.Target.Vault.Mount).To(Equal("secret"))
		Expect(obj.Spec.Target.Vault.KVVersion).To(Equal(int32(2)))
		Expect(obj.Spec.Target.Vault.PasswordKey).To(Equal("password"))
	})

	DescribeTable("rejects invalid DatabaseCredentialRotation specs",
		func(mutate func(*krotosv1alpha1.DatabaseCredentialRotationSpec), msg string) {
			err := createRotation(mutate)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(msg))
		},
		Entry("both cron and every", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Schedule.Cron = "0 3 * * 6"
		}, "exactly one of cron or every"),
		Entry("neither cron nor every", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Schedule.Every = ""
		}, "exactly one of cron or every"),
		Entry("bad every format", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Schedule.Every = "30"
		}, "spec.schedule.every"),
		Entry("window longer than 24h", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Window.Duration = metav1.Duration{Duration: 25 * time.Hour}
		}, "at most 24h"),
		Entry("zero window", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Window.Duration = metav1.Duration{}
		}, "greater than 0"),
		Entry("minRemaining not shorter than window", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Window.MinRemaining = metav1.Duration{Duration: 3 * time.Hour}
		}, "minRemaining must be at least 0 and shorter than duration"),
		Entry("bad window start", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Window.Start = "24:00"
		}, "spec.window.start"),
		Entry("both master sources", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.MasterCredentials.Vault = &krotosv1alpha1.VaultCredentialsReference{
				VaultSecretReference: krotosv1alpha1.VaultSecretReference{ConnectionRef: "v", Path: "p"},
			}
		}, "exactly one of vault or secretRef"),
		Entry("no master source", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.MasterCredentials.SecretRef = nil
		}, "exactly one of vault or secretRef"),
		Entry("clickhouse settings on postgresql", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Database.ClickHouse = &krotosv1alpha1.ClickHouseSettings{Cluster: "c"}
		}, "only allowed when engine is clickhouse"),
		Entry("redis settings on postgresql", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Database.Redis = &krotosv1alpha1.RedisSettings{Persistence: krotosv1alpha1.RedisPersistenceNone}
		}, "only allowed when engine is redis"),
		Entry("unknown redis persistence", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Engine = krotosv1alpha1.EngineRedis
			s.Database.Redis = &krotosv1alpha1.RedisSettings{Persistence: "Sometimes"}
		}, "spec.database.redis.persistence"),
		Entry("mysqlHost on postgresql", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Target.MySQLHost = new("%")
		}, "only allowed when engine is mysql"),
		Entry("verify-full without CA", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Database.TLS = &krotosv1alpha1.DatabaseTLS{Mode: krotosv1alpha1.TLSModeVerifyFull}
		}, "caSecretRef is required"),
		Entry("ExternalSecret sync without reference", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.SecretSync.Type = krotosv1alpha1.SecretSyncExternalSecret
		}, "externalSecret is required"),
		Entry("reference not matching sync type", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.SecretSync.Type = krotosv1alpha1.SecretSyncNone
			s.SecretSync.VaultStaticSecret = &krotosv1alpha1.SyncedSecretReference{Name: "a", SecretName: "b"}
		}, "vaultStaticSecret is only allowed"),
		Entry("restart target with name and selector", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.RestartTargets = []krotosv1alpha1.RestartTarget{{
				Kind:     "Deployment",
				Name:     "api",
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			}}
		}, "exactly one of name or selector"),
		Entry("unknown kv version", func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Target.Vault.KVVersion = 3
		}, "kvVersion"),
	)

	It("accepts a valid clickhouse spec with ExternalSecret sync", func() {
		Expect(createRotation(func(s *krotosv1alpha1.DatabaseCredentialRotationSpec) {
			s.Engine = krotosv1alpha1.EngineClickHouse
			s.Database.ClickHouse = &krotosv1alpha1.ClickHouseSettings{Cluster: "main"}
			s.Schedule = krotosv1alpha1.Schedule{Cron: "0 3 * * 6"}
			s.SecretSync = krotosv1alpha1.SecretSync{
				Type:           krotosv1alpha1.SecretSyncExternalSecret,
				ExternalSecret: &krotosv1alpha1.SyncedSecretReference{Name: "orders-db", SecretName: "orders-db"},
			}
			s.RestartTargets = []krotosv1alpha1.RestartTarget{
				{Kind: "Deployment", Name: "api"},
				{Kind: "StatefulSet", Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "w"}}},
			}
		})).To(Succeed())
	})

	DescribeTable("rejects invalid VaultConnection specs",
		func(mutate func(*krotosv1alpha1.VaultConnectionSpec), msg string) {
			err := createVaultConnection(mutate)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(msg))
		},
		Entry("both auth methods", func(s *krotosv1alpha1.VaultConnectionSpec) {
			s.Auth.Token = &krotosv1alpha1.VaultTokenAuth{
				SecretRef: krotosv1alpha1.SecretKeyReference{Name: "t", Key: "token"},
			}
		}, "exactly one of kubernetes or token"),
		Entry("no auth method", func(s *krotosv1alpha1.VaultConnectionSpec) {
			s.Auth.Kubernetes = nil
		}, "exactly one of kubernetes or token"),
		Entry("address without scheme", func(s *krotosv1alpha1.VaultConnectionSpec) {
			s.Address = "vault:8200"
		}, "spec.address"),
	)
})
