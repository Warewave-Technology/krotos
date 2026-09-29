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

// Package metrics defines the operator's Prometheus metrics. They are served by
// the controller-runtime metrics endpoint.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Label names.
const (
	labelNamespace = "namespace"
	labelName      = "name"
	labelEngine    = "engine"
)

// Rotation results.
const (
	ResultSucceeded  = "succeeded"
	ResultFailed     = "failed"
	ResultRolledBack = "rolled_back"
)

var (
	// RotationsTotal counts finished rotation attempts.
	RotationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "krotos_rotations_total",
		Help: "Finished password rotation attempts by result.",
	}, []string{labelNamespace, labelName, labelEngine, "result"})

	// RotationDuration observes how long successful rotations took, from start
	// until the restarted workloads rolled out.
	RotationDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "krotos_rotation_duration_seconds",
		Help:    "Duration of successful rotations including workload rollouts.",
		Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 600, 1200, 1800},
	}, []string{labelEngine})

	// LastSuccess is the time of the last successful rotation.
	LastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "krotos_last_success_timestamp_seconds",
		Help: "Unix time of the last successful rotation.",
	}, []string{labelNamespace, labelName})

	// NextRotation is when the next rotation becomes due.
	NextRotation = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "krotos_next_rotation_timestamp_seconds",
		Help: "Unix time at which the next rotation becomes due.",
	}, []string{labelNamespace, labelName})

	// Degraded is 1 while a rotation needs attention.
	Degraded = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "krotos_rotation_degraded",
		Help: "1 when the rotation needs attention (stuck rollback or incomplete rollout), else 0.",
	}, []string{labelNamespace, labelName})

	// ConsecutiveFailures mirrors status.consecutiveFailures.
	ConsecutiveFailures = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "krotos_rotation_consecutive_failures",
		Help: "Failed rotation attempts since the last success.",
	}, []string{labelNamespace, labelName})

	// VaultConnectionReady is 1 when the operator can log in to Vault.
	VaultConnectionReady = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "krotos_vault_connection_ready",
		Help: "1 when the operator can log in to the VaultConnection's Vault, else 0.",
	}, []string{labelNamespace, labelName})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		RotationsTotal, RotationDuration, LastSuccess, NextRotation, Degraded, ConsecutiveFailures, VaultConnectionReady,
	)
}

// Timestamp converts t for a timestamp gauge.
func Timestamp(t time.Time) float64 {
	return float64(t.UnixNano()) / 1e9
}

// Bool converts b for a 0/1 gauge.
func Bool(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// ForgetRotation drops every series of a deleted rotation.
func ForgetRotation(namespace, name string) {
	labels := prometheus.Labels{labelNamespace: namespace, labelName: name}
	RotationsTotal.DeletePartialMatch(labels)
	LastSuccess.Delete(labels)
	NextRotation.Delete(labels)
	Degraded.Delete(labels)
	ConsecutiveFailures.Delete(labels)
}

// ForgetVaultConnection drops the series of a deleted VaultConnection.
func ForgetVaultConnection(namespace, name string) {
	VaultConnectionReady.Delete(prometheus.Labels{labelNamespace: namespace, labelName: name})
}
