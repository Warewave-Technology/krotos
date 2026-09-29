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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// VaultConnectionSpec defines how the operator connects and authenticates to Vault.
type VaultConnectionSpec struct {
	// address of the Vault server, e.g. https://vault.example.com:8200.
	// +kubebuilder:validation:Pattern=`^https?://.+`
	// +required
	Address string `json:"address"`

	// namespace is the Vault Enterprise namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// tls configures the connection to Vault.
	// +optional
	TLS *VaultTLS `json:"tls,omitempty"`

	// auth selects the authentication method. Exactly one method must be set.
	// +required
	Auth VaultAuth `json:"auth"`
}

// VaultTLS configures TLS towards Vault.
type VaultTLS struct {
	// caSecretRef references a PEM encoded CA bundle.
	// +optional
	CASecretRef *SecretKeyReference `json:"caSecretRef,omitempty"`

	// insecureSkipVerify disables certificate verification. Do not use in production.
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// VaultAuth selects the Vault authentication method.
// +kubebuilder:validation:XValidation:rule="(has(self.kubernetes) ? 1 : 0) + (has(self.token) ? 1 : 0) == 1",message="exactly one of kubernetes or token must be set"
type VaultAuth struct {
	// kubernetes authenticates with the operator's ServiceAccount token.
	// +optional
	Kubernetes *VaultKubernetesAuth `json:"kubernetes,omitempty"`

	// token authenticates with a static token read from a Secret.
	// +optional
	Token *VaultTokenAuth `json:"token,omitempty"`
}

// VaultKubernetesAuth configures the Vault Kubernetes auth method.
type VaultKubernetesAuth struct {
	// role is the Vault role to log in with.
	// +kubebuilder:validation:MinLength=1
	// +required
	Role string `json:"role"`

	// mountPath of the Kubernetes auth method.
	// +kubebuilder:default=kubernetes
	// +optional
	MountPath string `json:"mountPath,omitempty"`

	// audience requested for the ServiceAccount token. Leave empty to use the
	// token mounted into the operator pod.
	// +optional
	Audience string `json:"audience,omitempty"`
}

// VaultTokenAuth configures static token authentication.
type VaultTokenAuth struct {
	// secretRef references the Secret key holding the Vault token.
	// +required
	SecretRef SecretKeyReference `json:"secretRef"`
}

// VaultConnectionStatus defines the observed state of VaultConnection.
type VaultConnectionStatus struct {
	// observedGeneration is the last spec generation that was reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// lastCheckedTime is when the connection was last verified.
	// +optional
	LastCheckedTime *metav1.Time `json:"lastCheckedTime,omitempty"`

	// conditions represent the current state of the connection. The "Ready"
	// condition is true when login to Vault succeeds.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=vconn
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.spec.address`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VaultConnection describes a Vault server and how the operator authenticates to it.
type VaultConnection struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec VaultConnectionSpec `json:"spec"`

	// +optional
	Status VaultConnectionStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// VaultConnectionList contains a list of VaultConnection
type VaultConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []VaultConnection `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &VaultConnection{}, &VaultConnectionList{})
		return nil
	})
}
