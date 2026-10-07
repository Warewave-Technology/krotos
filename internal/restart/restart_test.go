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

package restart

import (
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
)

const ns = "apps"

func deployment(name string, labels map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels}}
}

func newRestarter(objs ...client.Object) (*Restarter, client.Client) {
	c := fake.NewClientBuilder().WithObjects(objs...).Build()
	return &Restarter{Client: c, Reader: c, Namespace: ns}, c
}

func TestResolve(t *testing.T) {
	r, _ := newRestarter(
		deployment("api", map[string]string{"app": "orders"}),
		deployment("worker", map[string]string{"app": "orders"}),
		deployment("other", map[string]string{"app": "billing"}),
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "db-proxy", Namespace: ns, Labels: map[string]string{"app": "orders"}}},
	)
	orders := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "orders"}}

	got, warnings, err := r.Resolve(t.Context(), []krotosv1alpha1.RestartTarget{
		{Kind: KindDeployment, Name: "api"},
		{Kind: KindDeployment, Selector: orders},
		{Kind: KindStatefulSet, Selector: orders},
		{Kind: KindDaemonSet, Selector: orders},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []Workload{
		{KindDeployment, "api"}, {KindDeployment, "worker"}, {KindStatefulSet, "db-proxy"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("workloads = %v, want %v", got, want)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "DaemonSet selector") {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestEnsureRestartsOncePerToken(t *testing.T) {
	r, c := newRestarter(deployment("api", nil))
	w := Workload{KindDeployment, "api"}
	key := types.NamespacedName{Namespace: ns, Name: "api"}

	if _, err := r.Ensure(t.Context(), w, "t1"); err != nil {
		t.Fatal(err)
	}
	var d appsv1.Deployment
	if err := c.Get(t.Context(), key, &d); err != nil {
		t.Fatal(err)
	}
	if d.Spec.Template.Annotations[krotosv1alpha1.AnnotationRestartedAt] != "t1" {
		t.Fatalf("template annotations = %v", d.Spec.Template.Annotations)
	}
	rv := d.ResourceVersion

	if _, err := r.Ensure(t.Context(), w, "t1"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), key, &d); err != nil {
		t.Fatal(err)
	}
	if d.ResourceVersion != rv {
		t.Fatal("same token patched the workload again")
	}

	if _, err := r.Ensure(t.Context(), w, "t2"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), key, &d); err != nil {
		t.Fatal(err)
	}
	if d.Spec.Template.Annotations[krotosv1alpha1.AnnotationRestartedAt] != "t2" {
		t.Fatal("new token did not restart")
	}
}

func TestEnsureReportsWorkloadsItCannotRestart(t *testing.T) {
	paused := deployment("paused", nil)
	paused.Spec.Paused = true
	onDeleteSTS := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "sts", Namespace: ns},
		Spec:       appsv1.StatefulSetSpec{UpdateStrategy: appsv1.StatefulSetUpdateStrategy{Type: appsv1.OnDeleteStatefulSetStrategyType}},
	}
	onDeleteDS := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ds", Namespace: ns},
		Spec:       appsv1.DaemonSetSpec{UpdateStrategy: appsv1.DaemonSetUpdateStrategy{Type: appsv1.OnDeleteDaemonSetStrategyType}},
	}
	r, c := newRestarter(paused, onDeleteSTS, onDeleteDS)

	for _, w := range []Workload{
		{KindDeployment, "paused"}, {KindStatefulSet, "sts"}, {KindDaemonSet, "ds"}, {KindDeployment, "missing"},
	} {
		s, err := r.Ensure(t.Context(), w, "t1")
		if err != nil {
			t.Fatalf("%s: %v", w, err)
		}
		if !s.Failed || s.Message == "" {
			t.Errorf("%s: status = %+v, want failed", w, s)
		}
	}
	var d appsv1.Deployment
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: ns, Name: "paused"}, &d); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Spec.Template.Annotations[krotosv1alpha1.AnnotationRestartedAt]; ok {
		t.Error("paused deployment was patched")
	}
}

func TestDeploymentStatus(t *testing.T) {
	base := func() *appsv1.Deployment {
		d := deployment("api", nil)
		d.Generation = 2
		d.Spec.Replicas = new(int32(3))
		d.Status = appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 3, UpdatedReplicas: 3, AvailableReplicas: 3}
		return d
	}
	cases := []struct {
		name   string
		mutate func(*appsv1.Deployment)
		done   bool
		failed bool
	}{
		{"rolled out", func(*appsv1.Deployment) {}, true, false},
		{"not observed", func(d *appsv1.Deployment) { d.Status.ObservedGeneration = 1 }, false, false},
		{"updating", func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 1 }, false, false},
		{"old replicas", func(d *appsv1.Deployment) { d.Status.Replicas = 4 }, false, false},
		{"not available", func(d *appsv1.Deployment) { d.Status.AvailableReplicas = 2 }, false, false},
		{"deadline exceeded", func(d *appsv1.Deployment) {
			d.Status.UpdatedReplicas = 1
			d.Status.Conditions = []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Reason: "ProgressDeadlineExceeded"}}
		}, false, true},
		{"default replicas", func(d *appsv1.Deployment) {
			d.Spec.Replicas = nil
			d.Status = appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}
		}, true, false},
	}
	for _, tc := range cases {
		d := base()
		tc.mutate(d)
		s := rolloutStatus(d)
		if s.Done != tc.done || s.Failed != tc.failed {
			t.Errorf("%s: status = %+v", tc.name, s)
		}
	}
}

func TestStatefulSetStatus(t *testing.T) {
	base := func() *appsv1.StatefulSet {
		s := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "sts", Generation: 2}}
		s.Spec.Replicas = new(int32(3))
		s.Status = appsv1.StatefulSetStatus{
			ObservedGeneration: 2, ReadyReplicas: 3, UpdatedReplicas: 3, CurrentRevision: "r2", UpdateRevision: "r2",
		}
		return s
	}
	cases := []struct {
		name   string
		mutate func(*appsv1.StatefulSet)
		done   bool
	}{
		{"rolled out", func(*appsv1.StatefulSet) {}, true},
		{"not observed", func(s *appsv1.StatefulSet) { s.Status.ObservedGeneration = 1 }, false},
		{"revisions differ", func(s *appsv1.StatefulSet) { s.Status.CurrentRevision = "r1" }, false},
		{"not ready", func(s *appsv1.StatefulSet) { s.Status.ReadyReplicas = 2 }, false},
		{"partition reached", func(s *appsv1.StatefulSet) {
			s.Spec.UpdateStrategy.RollingUpdate = &appsv1.RollingUpdateStatefulSetStrategy{Partition: new(int32(2))}
			s.Status.CurrentRevision, s.Status.UpdatedReplicas = "r1", 1
		}, true},
		{"partition not reached", func(s *appsv1.StatefulSet) {
			s.Spec.UpdateStrategy.RollingUpdate = &appsv1.RollingUpdateStatefulSetStrategy{Partition: new(int32(1))}
			s.Status.CurrentRevision, s.Status.UpdatedReplicas = "r1", 1
		}, false},
	}
	for _, tc := range cases {
		s := base()
		tc.mutate(s)
		if got := rolloutStatus(s); got.Done != tc.done || got.Failed {
			t.Errorf("%s: status = %+v", tc.name, got)
		}
	}
}

func TestDaemonSetStatus(t *testing.T) {
	base := func() *appsv1.DaemonSet {
		d := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "ds", Generation: 2}}
		d.Status = appsv1.DaemonSetStatus{
			ObservedGeneration: 2, DesiredNumberScheduled: 4, UpdatedNumberScheduled: 4, NumberAvailable: 4,
		}
		return d
	}
	cases := []struct {
		name   string
		mutate func(*appsv1.DaemonSet)
		done   bool
	}{
		{"rolled out", func(*appsv1.DaemonSet) {}, true},
		{"not observed", func(d *appsv1.DaemonSet) { d.Status.ObservedGeneration = 1 }, false},
		{"updating", func(d *appsv1.DaemonSet) { d.Status.UpdatedNumberScheduled = 2 }, false},
		{"not available", func(d *appsv1.DaemonSet) { d.Status.NumberAvailable = 3 }, false},
	}
	for _, tc := range cases {
		d := base()
		tc.mutate(d)
		if got := rolloutStatus(d); got.Done != tc.done || got.Failed {
			t.Errorf("%s: status = %+v", tc.name, got)
		}
	}
}
