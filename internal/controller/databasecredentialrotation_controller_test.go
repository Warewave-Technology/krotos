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
	"maps"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	krotosv1alpha1 "github.com/warewave/krotos/api/v1alpha1"
	"github.com/warewave/krotos/internal/engine"
	"github.com/warewave/krotos/internal/metrics"
	"github.com/warewave/krotos/internal/rotation"
	"github.com/warewave/krotos/internal/secretsync"
	"github.com/warewave/krotos/internal/vault"
)

const (
	appUser     = "orders_app"
	appPassword = "current-app-password"
)

// memDB is a fake database engine.
type memDB struct {
	mu          sync.Mutex
	passwords   map[string]string
	master      engine.Credentials
	setFailures int
	// lastAccount and lastEndpoint are what SetPassword was last called with.
	lastAccount  engine.Account
	lastEndpoint engine.Endpoint
}

func (d *memDB) SetPassword(_ context.Context, ep engine.Endpoint, m engine.Credentials, a engine.Account, pw string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if m != d.master {
		return errors.New("master authentication failed")
	}
	if d.setFailures > 0 {
		d.setFailures--
		return errors.New("connection refused")
	}
	d.lastAccount, d.lastEndpoint = a, ep
	d.passwords[a.Username] = pw
	return nil
}

func (d *memDB) VerifyLogin(_ context.Context, _ engine.Endpoint, c engine.Credentials) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.passwords[c.Username] != c.Password {
		return errors.New("password authentication failed")
	}
	return nil
}

func (d *memDB) appPassword() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.passwords[appUser]
}

// memVault is a fake KV v2 store.
type memVault struct {
	mu      sync.Mutex
	secrets map[string]*vault.Secret
}

func (v *memVault) Read(_ context.Context, ref vault.SecretRef) (*vault.Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	s, ok := v.secrets[ref.Mount+"/"+ref.Path]
	if !ok {
		return nil, vault.ErrNotFound
	}
	return &vault.Secret{Data: maps.Clone(s.Data), Version: s.Version}, nil
}

func (v *memVault) Write(_ context.Context, ref vault.SecretRef, data map[string]any, cas int) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	key := ref.Mount + "/" + ref.Path
	cur := v.secrets[key]
	curVersion := 0
	if cur != nil {
		curVersion = cur.Version
	}
	if cas != curVersion {
		return 0, vault.ErrCASMismatch
	}
	v.secrets[key] = &vault.Secret{Data: data, Version: curVersion + 1}
	return curVersion + 1, nil
}

func (v *memVault) Delete(_ context.Context, ref vault.SecretRef) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.secrets, ref.Mount+"/"+ref.Path)
	return nil
}

func (v *memVault) get(path string) map[string]any {
	v.mu.Lock()
	defer v.mu.Unlock()
	if s, ok := v.secrets["secret/"+path]; ok {
		return maps.Clone(s.Data)
	}
	return nil
}

// appPassword returns the application's password as stored in Vault.
func (v *memVault) appPassword() any {
	return v.get("apps/orders/db")["password"]
}

var _ = Describe("DatabaseCredentialRotation Controller", func() {
	var (
		db         *memDB
		store      *memVault
		recorder   *events.FakeRecorder
		reconciler *DatabaseCredentialRotationReconciler
		key        types.NamespacedName
		now        time.Time
		// insideWindow and outsideWindow are on the day after today, so always
		// after the object's creation time. The fixture window is 02:00-05:00 Istanbul.
		insideWindow, outsideWindow time.Time
	)

	BeforeEach(func() {
		ist, err := time.LoadLocation("Europe/Istanbul")
		Expect(err).NotTo(HaveOccurred())
		tomorrow := time.Now().In(ist).AddDate(0, 0, 1)
		insideWindow = time.Date(tomorrow.Year(), tomorrow.Month(), tomorrow.Day(), 3, 0, 0, 0, ist)
		outsideWindow = time.Date(tomorrow.Year(), tomorrow.Month(), tomorrow.Day(), 12, 0, 0, 0, ist)
		now = insideWindow

		master := engine.Credentials{Username: "postgres", Password: "master-pw"}
		db = &memDB{passwords: map[string]string{appUser: appPassword}, master: master}
		store = &memVault{secrets: map[string]*vault.Secret{
			"secret/apps/orders/db": {Data: map[string]any{"password": appPassword, "host": "pg"}, Version: 1},
		}}
		recorder = events.NewFakeRecorder(100)
		reconciler = &DatabaseCredentialRotationReconciler{
			Client:    k8sClient,
			APIReader: k8sClient,
			Scheme:    k8sClient.Scheme(),
			Recorder:  recorder,
			Engines: map[krotosv1alpha1.Engine]engine.Engine{
				krotosv1alpha1.EnginePostgreSQL: db,
				krotosv1alpha1.EngineMySQL:      db,
				krotosv1alpha1.EngineClickHouse: db,
			},
			OpenVault: func(context.Context, *krotosv1alpha1.VaultConnection) (rotation.SecretStore, error) {
				return store, nil
			},
			Now:          func() time.Time { return now },
			PendingCache: &rotation.PendingCache{},
		}
		key = types.NamespacedName{Name: "rot-" + rand.String(6), Namespace: testNamespace}

		ensure(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "pg-master", Namespace: testNamespace},
			StringData: map[string]string{"username": master.Username, "password": master.Password},
		})
		ensure(&krotosv1alpha1.VaultConnection{
			ObjectMeta: metav1.ObjectMeta{Name: "main-vault", Namespace: testNamespace},
			Spec:       validVaultConnectionSpec(),
		})
	})

	create := func(mutate func(*krotosv1alpha1.DatabaseCredentialRotation)) {
		obj := &krotosv1alpha1.DatabaseCredentialRotation{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Spec:       validRotationSpec(),
		}
		if mutate != nil {
			mutate(obj)
		}
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, obj) })
	}

	reconcileOnce := func() (reconcile.Result, *krotosv1alpha1.DatabaseCredentialRotation) {
		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		var obj krotosv1alpha1.DatabaseCredentialRotation
		Expect(k8sClient.Get(ctx, key, &obj)).To(Succeed())
		return res, &obj
	}

	condition := func(obj *krotosv1alpha1.DatabaseCredentialRotation, t string) *metav1.Condition {
		c := meta.FindStatusCondition(obj.Status.Conditions, t)
		Expect(c).NotTo(BeNil(), "condition %s", t)
		return c
	}

	pendingPath := func() string { return rotation.DefaultPendingPath(testNamespace, key.Name) }
	pendingExists := func() bool { return store.get(pendingPath()) != nil }

	It("rotates a due password inside the window", func() {
		create(nil)

		res, obj := reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseIdle), obj.Status.Message)
		Expect(obj.Status.Step).To(BeEmpty())
		Expect(obj.Status.LastRotationTime).NotTo(BeNil())
		Expect(obj.Status.LastRotationTime.Time).To(BeTemporally("==", now.Truncate(time.Second)))
		Expect(condition(obj, krotosv1alpha1.ConditionRotated).Status).To(Equal(metav1.ConditionTrue))
		Expect(condition(obj, krotosv1alpha1.ConditionReady).Status).To(Equal(metav1.ConditionTrue))
		Expect(res.RequeueAfter).To(Equal(time.Second))

		newPassword := db.appPassword()
		Expect(newPassword).NotTo(Equal(appPassword))
		Expect(newPassword).To(HaveLen(32))
		Expect(store.appPassword()).To(Equal(newPassword))
		Expect(pendingExists()).To(BeFalse())
		Expect(recorder.Events).To(Receive(ContainSubstring("RotationStarted")))
		Expect(recorder.Events).To(Receive(ContainSubstring("RotationSucceeded")))
		Expect(testutil.ToFloat64(metrics.RotationsTotal.WithLabelValues(
			testNamespace, key.Name, "postgresql", metrics.ResultSucceeded))).To(Equal(1.0))
		Expect(testutil.ToFloat64(metrics.LastSuccess.WithLabelValues(testNamespace, key.Name))).
			To(Equal(float64(now.Unix())))

		// The follow-up reconcile schedules the next rotation 30 days out.
		res, obj = reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseIdle))
		Expect(obj.Status.NextScheduledTime.Time).To(BeTemporally("==", now.Add(30*24*time.Hour).Truncate(time.Second)))
		Expect(res.RequeueAfter).To(Equal(maxIdleRequeue))
	})

	It("waits for the window when due outside of it", func() {
		now = outsideWindow
		create(nil)

		res, obj := reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseWaiting))
		Expect(obj.Status.NextWindowStart.Time).To(BeTemporally("==", insideWindow.Add(-time.Hour).AddDate(0, 0, 1)))
		Expect(res.RequeueAfter).To(Equal(maxIdleRequeue))
		Expect(db.appPassword()).To(Equal(appPassword))
	})

	It("rotates immediately with rotate-now and ignore-window, then drops the annotations", func() {
		now = outsideWindow
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) {
			o.Annotations = map[string]string{
				krotosv1alpha1.AnnotationRotateNow:    "true",
				krotosv1alpha1.AnnotationIgnoreWindow: "true",
			}
		})

		_, obj := reconcileOnce()
		Expect(obj.Status.LastRotationTime).NotTo(BeNil())
		Expect(db.appPassword()).NotTo(Equal(appPassword))
		Expect(obj.Annotations).NotTo(HaveKey(krotosv1alpha1.AnnotationRotateNow))
		Expect(obj.Annotations).NotTo(HaveKey(krotosv1alpha1.AnnotationIgnoreWindow))
	})

	It("fails without changing anything when Vault and the database disagree, then backs off", func() {
		db.passwords[appUser] = "drifted"
		create(nil)

		_, obj := reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseFailed))
		Expect(obj.Status.ConsecutiveFailures).To(Equal(int32(1)))
		Expect(obj.Status.Message).To(ContainSubstring("does not work"))
		Expect(testutil.ToFloat64(metrics.RotationsTotal.WithLabelValues(
			testNamespace, key.Name, "postgresql", metrics.ResultFailed))).To(Equal(1.0))
		Expect(testutil.ToFloat64(metrics.ConsecutiveFailures.WithLabelValues(testNamespace, key.Name))).To(Equal(1.0))
		Expect(condition(obj, krotosv1alpha1.ConditionRotated).Reason).To(Equal(ReasonRotationFailed))
		Expect(db.appPassword()).To(Equal("drifted"))
		Expect(pendingExists()).To(BeFalse())

		// Still in the window, but within the failure backoff: no new attempt.
		now = now.Add(time.Minute)
		res, obj := reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseFailed))
		Expect(obj.Status.ConsecutiveFailures).To(Equal(int32(1)))
		Expect(res.RequeueAfter).To(Equal(4 * time.Minute))

		// After the backoff it tries again and, once fixed, succeeds.
		db.passwords[appUser] = appPassword
		now = now.Add(4 * time.Minute)
		_, obj = reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseIdle), obj.Status.Message)
		Expect(obj.Status.ConsecutiveFailures).To(BeZero())
	})

	It("keeps the pending password in Vault across a transient failure and an operator restart", func() {
		db.setFailures = 1
		create(nil)

		res, obj := reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseRotating))
		Expect(obj.Status.Step).To(Equal(krotosv1alpha1.StepPendingSaved))
		Expect(obj.Status.Retries).To(Equal(int32(1)))
		Expect(res.RequeueAfter).To(Equal(15 * time.Second))

		pending := store.get(pendingPath())
		Expect(pending).To(HaveKeyWithValue("oldPassword", appPassword))
		newPassword, _ := pending["newPassword"].(string)
		Expect(newPassword).To(HaveLen(32))
		Expect(obj.Status.Message).NotTo(ContainSubstring(newPassword))

		// No Secret holding passwords exists in the namespace.
		var secrets corev1.SecretList
		Expect(k8sClient.List(ctx, &secrets, client.InNamespace(testNamespace))).To(Succeed())
		for _, sec := range secrets.Items {
			for _, v := range sec.Data {
				Expect(string(v)).NotTo(Equal(newPassword), "secret %s", sec.Name)
			}
		}

		// Simulate an operator restart: the in-memory cache is gone.
		reconciler.PendingCache = &rotation.PendingCache{}
		now = now.Add(15 * time.Second)
		_, obj = reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseIdle), obj.Status.Message)
		Expect(db.appPassword()).To(Equal(newPassword))
		Expect(store.appPassword()).To(Equal(newPassword))
		Expect(pendingExists()).To(BeFalse())
	})

	It("uses a custom pending path", func() {
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) {
			o.Spec.Target.Vault.PendingPath = "ops/krotos/orders"
		})
		db.setFailures = 1

		_, obj := reconcileOnce()
		Expect(obj.Status.Step).To(Equal(krotosv1alpha1.StepPendingSaved))
		Expect(store.get("ops/krotos/orders")).To(HaveKey("newPassword"))
		Expect(pendingExists()).To(BeFalse())
	})

	It("adds a finalizer and releases it when idle", func() {
		now = outsideWindow
		create(nil)

		_, obj := reconcileOnce()
		Expect(obj.Finalizers).To(ContainElement(krotosv1alpha1.FinalizerRotation))

		Expect(testutil.CollectAndCount(metrics.NextRotation)).To(BeNumerically(">", 0))
		before := testutil.CollectAndCount(metrics.NextRotation)

		Expect(k8sClient.Delete(ctx, obj)).To(Succeed())
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, key, obj))).To(BeTrue())
		Expect(testutil.CollectAndCount(metrics.NextRotation)).To(Equal(before - 1))
	})

	It("finishes an in-flight rotation before letting the object be deleted", func() {
		db.setFailures = 1
		create(nil)

		_, obj := reconcileOnce()
		Expect(obj.Status.Step).To(Equal(krotosv1alpha1.StepPendingSaved))

		Expect(k8sClient.Delete(ctx, obj)).To(Succeed())
		_, obj = reconcileOnce()
		Expect(obj.DeletionTimestamp).NotTo(BeNil())
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseIdle), obj.Status.Message)
		Expect(db.appPassword()).NotTo(Equal(appPassword))
		Expect(store.appPassword()).To(Equal(db.appPassword()))

		// The next reconcile, with nothing in flight, lets it go without starting a new rotation.
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, key, obj))).To(BeTrue())
	})

	newDeployment := func(name string, labels map[string]string) {
		d := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace, Labels: labels},
			Spec: appsv1.DeploymentSpec{
				Replicas: new(int32(2)),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:1"}}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, d)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, d) })
	}

	// finishRollout plays the Deployment controller: it reports the current generation as rolled out.
	finishRollout := func(name string) {
		var d appsv1.Deployment
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: testNamespace, Name: name}, &d)).To(Succeed())
		d.Status = appsv1.DeploymentStatus{
			ObservedGeneration: d.Generation, Replicas: 2, UpdatedReplicas: 2, ReadyReplicas: 2, AvailableReplicas: 2,
		}
		Expect(k8sClient.Status().Update(ctx, &d)).To(Succeed())
	}

	restartedAt := func(name string) (string, int64) {
		var d appsv1.Deployment
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: testNamespace, Name: name}, &d)).To(Succeed())
		return d.Spec.Template.Annotations[krotosv1alpha1.AnnotationRestartedAt], d.Generation
	}

	It("restarts the targets after the rotation and waits for their rollouts", func() {
		api := "api-" + rand.String(4)
		worker := "worker-" + rand.String(4)
		newDeployment(api, nil)
		newDeployment(worker, map[string]string{"tier": key.Name})
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) {
			o.Spec.RestartTargets = []krotosv1alpha1.RestartTarget{
				{Kind: "Deployment", Name: api},
				{Kind: "Deployment", Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": key.Name}}},
			}
		})

		res, obj := reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseRestarting), obj.Status.Message)
		Expect(obj.Status.Step).To(Equal(krotosv1alpha1.StepSecretSynced))
		Expect(obj.Status.RolloutStartTime).NotTo(BeNil())
		Expect(res.RequeueAfter).To(Equal(rolloutPoll))
		// The password is already in place and the pending passwords are gone.
		Expect(store.appPassword()).To(Equal(db.appPassword()))
		Expect(pendingExists()).To(BeFalse())

		token, gen := restartedAt(api)
		Expect(token).To(Equal(obj.Status.LastAttemptTime.UTC().Format(time.RFC3339)))
		workerToken, _ := restartedAt(worker)
		Expect(workerToken).To(Equal(token))

		// Waiting does not restart again.
		now = now.Add(rolloutPoll)
		_, obj = reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseRestarting))
		_, gen2 := restartedAt(api)
		Expect(gen2).To(Equal(gen))

		finishRollout(api)
		_, obj = reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseRestarting))
		Expect(obj.Status.Message).To(ContainSubstring(worker))

		finishRollout(worker)
		_, obj = reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseIdle), obj.Status.Message)
		Expect(obj.Status.Step).To(BeEmpty())
		Expect(obj.Status.RolloutStartTime).To(BeNil())
		Expect(obj.Status.Message).To(ContainSubstring("restarted 2 workload(s)"))
		Expect(condition(obj, krotosv1alpha1.ConditionDegraded).Status).To(Equal(metav1.ConditionFalse))
	})

	It("finishes the rotation as Degraded when a rollout times out", func() {
		api := "api-" + rand.String(4)
		newDeployment(api, nil)
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) {
			o.Spec.RestartTargets = []krotosv1alpha1.RestartTarget{{Kind: "Deployment", Name: api}}
			o.Spec.RolloutTimeout = metav1.Duration{Duration: time.Minute}
		})

		_, obj := reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseRestarting))

		now = now.Add(2 * time.Minute)
		_, obj = reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseIdle))
		Expect(obj.Status.LastRotationTime).NotTo(BeNil())
		c := condition(obj, krotosv1alpha1.ConditionDegraded)
		Expect(c.Status).To(Equal(metav1.ConditionTrue))
		Expect(c.Reason).To(Equal(ReasonRolloutIncomplete))
		Expect(c.Message).To(ContainSubstring("rollout timed out"))
		Expect(testutil.ToFloat64(metrics.Degraded.WithLabelValues(testNamespace, key.Name))).To(Equal(1.0))
		Expect(drain(recorder)).To(ContainElement(ContainSubstring("RolloutIncomplete")))
	})

	It("reports a missing restart target without waiting for the timeout", func() {
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) {
			o.Spec.RestartTargets = []krotosv1alpha1.RestartTarget{{Kind: "Deployment", Name: "does-not-exist"}}
		})

		_, obj := reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseIdle))
		Expect(condition(obj, krotosv1alpha1.ConditionRotated).Status).To(Equal(metav1.ConditionTrue))
		c := condition(obj, krotosv1alpha1.ConditionDegraded)
		Expect(c.Status).To(Equal(metav1.ConditionTrue))
		Expect(c.Message).To(ContainSubstring("Deployment/does-not-exist not found"))
	})

	syncResource := func(apiVersion, kind, name string) *unstructured.Unstructured {
		u := &unstructured.Unstructured{}
		u.SetAPIVersion(apiVersion)
		u.SetKind(kind)
		u.SetNamespace(testNamespace)
		u.SetName(name)
		Expect(k8sClient.Create(ctx, u)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, u) })
		return u
	}
	syncedSecret := func(name, password string) {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Data:       map[string][]byte{"password": []byte(password)},
		}
		Expect(k8sClient.Create(ctx, s)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, s) })
	}
	setSyncedSecret := func(name, password string) {
		var s corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: testNamespace, Name: name}, &s)).To(Succeed())
		s.Data["password"] = []byte(password)
		Expect(k8sClient.Update(ctx, &s)).To(Succeed())
	}
	annotation := func(u *unstructured.Unstructured, key string) string {
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(u), u)).To(Succeed())
		return u.GetAnnotations()[key]
	}

	It("triggers an ExternalSecret sync and restarts only after the Secret holds the new password", func() {
		es := "orders-db-" + rand.String(4)
		api := "api-" + rand.String(4)
		newDeployment(api, nil)
		u := syncResource("external-secrets.io/v1", "ExternalSecret", es)
		syncedSecret(es, appPassword)
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) {
			o.Spec.SecretSync = krotosv1alpha1.SecretSync{
				Type:           krotosv1alpha1.SecretSyncExternalSecret,
				ExternalSecret: &krotosv1alpha1.SyncedSecretReference{Name: es, SecretName: es},
			}
			o.Spec.RestartTargets = []krotosv1alpha1.RestartTarget{{Kind: "Deployment", Name: api}}
		})

		res, obj := reconcileOnce()
		Expect(obj.Status.Step).To(Equal(krotosv1alpha1.StepVaultWritten))
		Expect(obj.Status.SecretSyncStartTime).NotTo(BeNil())
		Expect(obj.Status.Message).To(ContainSubstring("Waiting for ExternalSecret/" + es))
		Expect(res.RequeueAfter).To(Equal(secretSyncPoll))
		Expect(annotation(u, secretsync.AnnotationESOForceSync)).To(Equal(obj.Status.LastAttemptTime.UTC().Format(time.RFC3339)))
		Expect(pendingExists()).To(BeFalse())
		token, _ := restartedAt(api)
		Expect(token).To(BeEmpty(), "restarted before the Secret was synced")

		// External Secrets Operator copies the new password.
		setSyncedSecret(es, db.appPassword())
		_, obj = reconcileOnce()
		Expect(obj.Status.Step).To(Equal(krotosv1alpha1.StepSecretSynced))
		Expect(obj.Status.SecretSyncStartTime).To(BeNil())
		token, _ = restartedAt(api)
		Expect(token).NotTo(BeEmpty())
	})

	It("finishes as Degraded without restarting when the VaultStaticSecret does not sync in time", func() {
		vss := "orders-db-" + rand.String(4)
		api := "api-" + rand.String(4)
		newDeployment(api, nil)
		u := syncResource("secrets.hashicorp.com/v1beta1", "VaultStaticSecret", vss)
		syncedSecret(vss, appPassword)
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) {
			o.Spec.SecretSync = krotosv1alpha1.SecretSync{
				Type:              krotosv1alpha1.SecretSyncVaultStaticSecret,
				VaultStaticSecret: &krotosv1alpha1.SyncedSecretReference{Name: vss, SecretName: vss},
				Timeout:           metav1.Duration{Duration: time.Minute},
			}
			o.Spec.RestartTargets = []krotosv1alpha1.RestartTarget{{Kind: "Deployment", Name: api}}
		})

		_, obj := reconcileOnce()
		Expect(obj.Status.Step).To(Equal(krotosv1alpha1.StepVaultWritten))
		Expect(annotation(u, secretsync.AnnotationSyncRequestedAt)).NotTo(BeEmpty())

		now = now.Add(2 * time.Minute)
		_, obj = reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseIdle))
		Expect(obj.Status.LastRotationTime).NotTo(BeNil())
		c := condition(obj, krotosv1alpha1.ConditionDegraded)
		Expect(c.Status).To(Equal(metav1.ConditionTrue))
		Expect(c.Message).To(ContainSubstring("Secret sync timed out"))
		Expect(c.Message).To(ContainSubstring("workloads were not restarted"))
		token, _ := restartedAt(api)
		Expect(token).To(BeEmpty())
	})

	It("finishes as Degraded right away when the sync resource does not exist", func() {
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) {
			o.Spec.SecretSync = krotosv1alpha1.SecretSync{
				Type:           krotosv1alpha1.SecretSyncExternalSecret,
				ExternalSecret: &krotosv1alpha1.SyncedSecretReference{Name: "missing", SecretName: "missing"},
			}
		})

		_, obj := reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseIdle))
		c := condition(obj, krotosv1alpha1.ConditionDegraded)
		Expect(c.Status).To(Equal(metav1.ConditionTrue))
		Expect(c.Message).To(ContainSubstring("ExternalSecret/missing"))
	})

	It("counts a missing VaultConnection as a failed attempt", func() {
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) {
			o.Spec.Target.Vault.ConnectionRef = "nope"
		})

		_, obj := reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseFailed))
		Expect(obj.Status.Message).To(ContainSubstring(`VaultConnection "nope" not found`))
		Expect(obj.Status.ConsecutiveFailures).To(Equal(int32(1)))
	})

	It("does nothing while suspended", func() {
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) { o.Spec.Suspend = true })

		res, obj := reconcileOnce()
		Expect(obj.Status.Phase).To(Equal(krotosv1alpha1.PhaseIdle))
		Expect(obj.Status.Message).To(Equal("Suspended"))
		Expect(res).To(Equal(reconcile.Result{}))
		Expect(db.appPassword()).To(Equal(appPassword))
	})

	It("reports an invalid time zone", func() {
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) { o.Spec.Window.Timezone = "Mars/Olympus" })

		res, obj := reconcileOnce()
		c := condition(obj, krotosv1alpha1.ConditionReady)
		Expect(c.Status).To(Equal(metav1.ConditionFalse))
		Expect(c.Reason).To(Equal(ReasonInvalidSpec))
		Expect(res).To(Equal(reconcile.Result{}))
	})

	It("reports engines that are not supported", func() {
		delete(reconciler.Engines, krotosv1alpha1.EngineMySQL)
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) { o.Spec.Engine = krotosv1alpha1.EngineMySQL })

		_, obj := reconcileOnce()
		Expect(condition(obj, krotosv1alpha1.ConditionReady).Reason).To(Equal(ReasonEngineNotSupported))
	})

	It("passes the MySQL account host, defaulting to %", func() {
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) { o.Spec.Engine = krotosv1alpha1.EngineMySQL })
		reconcileOnce()
		Expect(db.lastAccount).To(Equal(engine.Account{Username: appUser, MySQLHost: "%"}))
	})

	It("passes a custom MySQL account host", func() {
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) {
			o.Spec.Engine = krotosv1alpha1.EngineMySQL
			o.Spec.Target.MySQLHost = new("10.0.%")
		})
		reconcileOnce()
		Expect(db.lastAccount.MySQLHost).To(Equal("10.0.%"))
	})

	It("passes ClickHouse settings", func() {
		create(func(o *krotosv1alpha1.DatabaseCredentialRotation) {
			o.Spec.Engine = krotosv1alpha1.EngineClickHouse
			o.Spec.Database.ClickHouse = &krotosv1alpha1.ClickHouseSettings{Cluster: "main", Protocol: "http"}
		})
		reconcileOnce()
		Expect(db.lastEndpoint.ClickHouseCluster).To(Equal("main"))
		Expect(db.lastEndpoint.ClickHouseProtocol).To(Equal("http"))
		Expect(db.lastEndpoint.TLSMode).To(Equal(krotosv1alpha1.TLSModeRequire))
	})
})

// drain returns the events recorded so far.
func drain(r *events.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-r.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// ensure creates obj unless it already exists.
func ensure(obj client.Object) {
	err := k8sClient.Create(ctx, obj)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		Expect(err).NotTo(HaveOccurred())
	}
}
