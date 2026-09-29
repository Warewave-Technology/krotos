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

// SecretKeyReference points to a key of a Secret in the operator's namespace.
type SecretKeyReference struct {
	// name of the Secret.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`

	// key inside the Secret.
	// +kubebuilder:validation:MinLength=1
	// +required
	Key string `json:"key"`
}

// VaultSecretReference points to a secret stored in a Vault KV engine.
type VaultSecretReference struct {
	// connectionRef is the name of a VaultConnection in the same namespace.
	// +kubebuilder:validation:MinLength=1
	// +required
	ConnectionRef string `json:"connectionRef"`

	// mount is the KV secrets engine mount path, e.g. "secret".
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:default=secret
	// +optional
	Mount string `json:"mount,omitempty"`

	// path of the secret inside the mount, without the "data/" prefix for KV v2,
	// e.g. "apps/orders/db".
	// +kubebuilder:validation:MinLength=1
	// +required
	Path string `json:"path"`

	// kvVersion is the version of the KV secrets engine.
	// +kubebuilder:validation:Enum=1;2
	// +kubebuilder:default=2
	// +optional
	KVVersion int32 `json:"kvVersion,omitempty"`
}
