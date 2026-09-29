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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	krotosv1alpha1 "github.com/warewave/krotos/api/v1alpha1"
	"github.com/warewave/krotos/internal/metrics"
	"github.com/warewave/krotos/internal/vault"
	"github.com/warewave/krotos/internal/vault/vaulttest"
)

type staticTokens map[string]string

func (s staticTokens) Token(_ context.Context, audience string) (string, error) {
	return s[audience], nil
}

var _ = Describe("VaultConnection Controller", func() {
	var (
		srv        *vaulttest.Server
		reconciler *VaultConnectionReconciler
		key        types.NamespacedName
	)

	BeforeEach(func() {
		srv = vaulttest.NewServer()
		srv.AddToken("good-token", 3600)
		srv.AddKubernetesRole("kubernetes", "krotos", "sa-jwt")

		reconciler = &VaultConnectionReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
			Vault: &vault.Resolver{
				Reader:   k8sClient,
				Tokens:   staticTokens{"": "sa-jwt"},
				Provider: vault.NewProvider(),
			},
		}
		key = types.NamespacedName{Name: "vault-" + rand.String(6), Namespace: testNamespace}
	})

	AfterEach(func() {
		srv.Close()
		_ = k8sClient.Delete(ctx, &krotosv1alpha1.VaultConnection{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}})
	})

	createTokenSecret := func(name, token string) {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Data:       map[string][]byte{"token": []byte(token)},
		}
		Expect(k8sClient.Create(ctx, s)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, s) })
	}

	create := func(auth krotosv1alpha1.VaultAuth) {
		conn := &krotosv1alpha1.VaultConnection{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Spec:       krotosv1alpha1.VaultConnectionSpec{Address: srv.URL, Auth: auth},
		}
		Expect(k8sClient.Create(ctx, conn)).To(Succeed())
	}

	tokenAuth := func(secretName string) krotosv1alpha1.VaultAuth {
		return krotosv1alpha1.VaultAuth{Token: &krotosv1alpha1.VaultTokenAuth{
			SecretRef: krotosv1alpha1.SecretKeyReference{Name: secretName, Key: "token"},
		}}
	}

	reconcileAndGetReady := func() (reconcile.Result, *metav1.Condition) {
		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		var conn krotosv1alpha1.VaultConnection
		Expect(k8sClient.Get(ctx, key, &conn)).To(Succeed())
		Expect(conn.Status.LastCheckedTime).NotTo(BeNil())
		Expect(conn.Status.ObservedGeneration).To(Equal(conn.Generation))
		cond := meta.FindStatusCondition(conn.Status.Conditions, krotosv1alpha1.ConditionReady)
		Expect(cond).NotTo(BeNil())
		return res, cond
	}

	It("becomes Ready with a valid token", func() {
		secretName := key.Name + "-token"
		createTokenSecret(secretName, "good-token")
		create(tokenAuth(secretName))

		res, cond := reconcileAndGetReady()
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		Expect(cond.Reason).To(Equal(ReasonAuthenticated))
		Expect(res.RequeueAfter).To(Equal(vaultConnectionRecheckInterval))
		Expect(testutil.ToFloat64(metrics.VaultConnectionReady.WithLabelValues(testNamespace, key.Name))).To(Equal(1.0))
	})

	It("reports InvalidConfig when the token Secret is missing", func() {
		create(tokenAuth("does-not-exist"))

		res, cond := reconcileAndGetReady()
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal(ReasonInvalidConfig))
		Expect(testutil.ToFloat64(metrics.VaultConnectionReady.WithLabelValues(testNamespace, key.Name))).To(Equal(0.0))
		Expect(cond.Message).To(ContainSubstring(`"does-not-exist" not found`))
		Expect(res.RequeueAfter).To(Equal(vaultConnectionRetryInterval))
	})

	It("reports LoginFailed with a rejected token, without leaking it", func() {
		secretName := key.Name + "-token"
		createTokenSecret(secretName, "wrong-token")
		create(tokenAuth(secretName))

		res, cond := reconcileAndGetReady()
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal(ReasonLoginFailed))
		Expect(cond.Message).NotTo(ContainSubstring("wrong-token"))
		Expect(res.RequeueAfter).To(Equal(vaultConnectionRetryInterval))
	})

	It("notices a revoked token on the next check", func() {
		secretName := key.Name + "-token"
		createTokenSecret(secretName, "good-token")
		create(tokenAuth(secretName))

		_, cond := reconcileAndGetReady()
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))

		srv.RevokeToken("good-token")
		_, cond = reconcileAndGetReady()
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal(ReasonLoginFailed))
	})

	It("logs in with Kubernetes auth and reuses the session", func() {
		create(krotosv1alpha1.VaultAuth{Kubernetes: &krotosv1alpha1.VaultKubernetesAuth{Role: "krotos"}})

		_, cond := reconcileAndGetReady()
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		_, cond = reconcileAndGetReady()
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		Expect(srv.Logins()).To(Equal(1))
	})

	It("ignores deleted resources", func() {
		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(reconcile.Result{}))
	})
})
