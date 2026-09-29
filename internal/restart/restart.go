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

// Package restart restarts workloads the way `kubectl rollout restart` does and
// tracks their rollout the way `kubectl rollout status` does.
package restart

import (
	"context"
	"fmt"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	krotosv1alpha1 "github.com/warewave/krotos/api/v1alpha1"
)

// Supported workload kinds.
const (
	KindDeployment  = "Deployment"
	KindStatefulSet = "StatefulSet"
	KindDaemonSet   = "DaemonSet"
)

// Workload identifies one workload.
type Workload struct {
	Kind string
	Name string
}

func (w Workload) String() string { return w.Kind + "/" + w.Name }

// Status is the rollout state of a workload.
type Status struct {
	Done bool
	// Failed means the rollout cannot finish without intervention.
	Failed  bool
	Message string
}

// Restarter restarts workloads in one namespace.
type Restarter struct {
	// Client patches workloads.
	Client client.Client
	// Reader reads them; an uncached reader avoids watching every workload.
	Reader    client.Reader
	Namespace string
}

// Resolve expands restart targets into workloads, without duplicates. It returns
// the selectors that matched nothing as warnings.
func (r *Restarter) Resolve(ctx context.Context, targets []krotosv1alpha1.RestartTarget) ([]Workload, []string, error) {
	var out []Workload
	var warnings []string
	add := func(w Workload) {
		if !slices.Contains(out, w) {
			out = append(out, w)
		}
	}

	for _, t := range targets {
		if t.Name != "" {
			add(Workload{Kind: t.Kind, Name: t.Name})
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(t.Selector)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid %s selector: %w", t.Kind, err)
		}
		names, err := r.list(ctx, t.Kind, sel)
		if err != nil {
			return nil, nil, err
		}
		if len(names) == 0 {
			warnings = append(warnings, fmt.Sprintf("%s selector %q matches nothing", t.Kind, sel))
		}
		for _, n := range names {
			add(Workload{Kind: t.Kind, Name: n})
		}
	}
	return out, warnings, nil
}

func (r *Restarter) list(ctx context.Context, kind string, sel labels.Selector) ([]string, error) {
	opts := []client.ListOption{client.InNamespace(r.Namespace), client.MatchingLabelsSelector{Selector: sel}}
	var names []string
	switch kind {
	case KindDeployment:
		var l appsv1.DeploymentList
		if err := r.Reader.List(ctx, &l, opts...); err != nil {
			return nil, err
		}
		for _, o := range l.Items {
			names = append(names, o.Name)
		}
	case KindStatefulSet:
		var l appsv1.StatefulSetList
		if err := r.Reader.List(ctx, &l, opts...); err != nil {
			return nil, err
		}
		for _, o := range l.Items {
			names = append(names, o.Name)
		}
	case KindDaemonSet:
		var l appsv1.DaemonSetList
		if err := r.Reader.List(ctx, &l, opts...); err != nil {
			return nil, err
		}
		for _, o := range l.Items {
			names = append(names, o.Name)
		}
	default:
		return nil, fmt.Errorf("unsupported kind %q", kind)
	}
	slices.Sort(names)
	return names, nil
}

// Ensure restarts w unless it was already restarted with token, and reports its
// rollout status. Calling it repeatedly with the same token restarts only once.
func (r *Restarter) Ensure(ctx context.Context, w Workload, token string) (Status, error) {
	obj, err := newObject(w.Kind)
	if err != nil {
		return Status{}, err
	}
	key := types.NamespacedName{Namespace: r.Namespace, Name: w.Name}
	if err := r.Reader.Get(ctx, key, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return Status{Failed: true, Message: w.String() + " not found"}, nil
		}
		return Status{}, err
	}

	tmpl := podTemplateMeta(obj)
	if tmpl.Annotations[krotosv1alpha1.AnnotationRestartedAt] != token {
		if s, ok := cannotRestart(obj); !ok {
			return s, nil
		}
		base := obj.DeepCopyObject().(client.Object)
		if tmpl.Annotations == nil {
			tmpl.Annotations = map[string]string{}
		}
		tmpl.Annotations[krotosv1alpha1.AnnotationRestartedAt] = token
		if err := r.Client.Patch(ctx, obj, client.MergeFrom(base)); err != nil {
			return Status{}, fmt.Errorf("restart %s: %w", w, err)
		}
	}
	return rolloutStatus(obj), nil
}

func newObject(kind string) (client.Object, error) {
	switch kind {
	case KindDeployment:
		return &appsv1.Deployment{}, nil
	case KindStatefulSet:
		return &appsv1.StatefulSet{}, nil
	case KindDaemonSet:
		return &appsv1.DaemonSet{}, nil
	default:
		return nil, fmt.Errorf("unsupported kind %q", kind)
	}
}

func podTemplateMeta(obj client.Object) *metav1.ObjectMeta {
	switch o := obj.(type) {
	case *appsv1.Deployment:
		return &o.Spec.Template.ObjectMeta
	case *appsv1.StatefulSet:
		return &o.Spec.Template.ObjectMeta
	case *appsv1.DaemonSet:
		return &o.Spec.Template.ObjectMeta
	}
	panic(fmt.Sprintf("unsupported object %T", obj))
}

// cannotRestart reports workloads whose pods a template change does not restart.
func cannotRestart(obj client.Object) (Status, bool) {
	switch o := obj.(type) {
	case *appsv1.Deployment:
		if o.Spec.Paused {
			return Status{Failed: true, Message: "Deployment/" + o.Name + " is paused"}, false
		}
	case *appsv1.StatefulSet:
		if o.Spec.UpdateStrategy.Type == appsv1.OnDeleteStatefulSetStrategyType {
			return Status{Failed: true, Message: "StatefulSet/" + o.Name + " uses the OnDelete update strategy; restart its pods manually"}, false
		}
	case *appsv1.DaemonSet:
		if o.Spec.UpdateStrategy.Type == appsv1.OnDeleteDaemonSetStrategyType {
			return Status{Failed: true, Message: "DaemonSet/" + o.Name + " uses the OnDelete update strategy; restart its pods manually"}, false
		}
	}
	return Status{}, true
}

func rolloutStatus(obj client.Object) Status {
	if s, ok := cannotRestart(obj); !ok {
		return s
	}
	switch o := obj.(type) {
	case *appsv1.Deployment:
		return deploymentStatus(o)
	case *appsv1.StatefulSet:
		return statefulSetStatus(o)
	case *appsv1.DaemonSet:
		return daemonSetStatus(o)
	}
	panic(fmt.Sprintf("unsupported object %T", obj))
}

func waiting(format string, args ...any) Status {
	return Status{Message: fmt.Sprintf(format, args...)}
}

func deploymentStatus(d *appsv1.Deployment) Status {
	name := "Deployment/" + d.Name
	if d.Generation > d.Status.ObservedGeneration {
		return waiting("%s: waiting for the rollout to start", name)
	}
	for _, c := range d.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing && c.Reason == "ProgressDeadlineExceeded" {
			return Status{Failed: true, Message: fmt.Sprintf("%s: progress deadline exceeded", name)}
		}
	}
	replicas := int32(1)
	if d.Spec.Replicas != nil {
		replicas = *d.Spec.Replicas
	}
	st := d.Status
	switch {
	case st.UpdatedReplicas < replicas:
		return waiting("%s: %d of %d replicas updated", name, st.UpdatedReplicas, replicas)
	case st.Replicas > st.UpdatedReplicas:
		return waiting("%s: %d old replicas pending termination", name, st.Replicas-st.UpdatedReplicas)
	case st.AvailableReplicas < st.UpdatedReplicas:
		return waiting("%s: %d of %d updated replicas available", name, st.AvailableReplicas, st.UpdatedReplicas)
	}
	return Status{Done: true, Message: name + " rolled out"}
}

func statefulSetStatus(s *appsv1.StatefulSet) Status {
	name := "StatefulSet/" + s.Name
	if s.Generation > s.Status.ObservedGeneration {
		return waiting("%s: waiting for the rollout to start", name)
	}
	replicas := int32(1)
	if s.Spec.Replicas != nil {
		replicas = *s.Spec.Replicas
	}
	st := s.Status
	var partition int32
	if ru := s.Spec.UpdateStrategy.RollingUpdate; ru != nil && ru.Partition != nil {
		partition = *ru.Partition
	}
	if partition > 0 {
		if want := replicas - partition; st.UpdatedReplicas < want {
			return waiting("%s: %d of %d replicas above the partition updated", name, st.UpdatedReplicas, want)
		}
	} else if st.UpdateRevision != st.CurrentRevision {
		return waiting("%s: %d of %d replicas updated", name, st.UpdatedReplicas, replicas)
	}
	if st.ReadyReplicas < replicas {
		return waiting("%s: %d of %d replicas ready", name, st.ReadyReplicas, replicas)
	}
	return Status{Done: true, Message: name + " rolled out"}
}

func daemonSetStatus(d *appsv1.DaemonSet) Status {
	name := "DaemonSet/" + d.Name
	if d.Generation > d.Status.ObservedGeneration {
		return waiting("%s: waiting for the rollout to start", name)
	}
	st := d.Status
	switch {
	case st.UpdatedNumberScheduled < st.DesiredNumberScheduled:
		return waiting("%s: %d of %d pods updated", name, st.UpdatedNumberScheduled, st.DesiredNumberScheduled)
	case st.NumberAvailable < st.DesiredNumberScheduled:
		return waiting("%s: %d of %d pods available", name, st.NumberAvailable, st.DesiredNumberScheduled)
	}
	return Status{Done: true, Message: name + " rolled out"}
}
