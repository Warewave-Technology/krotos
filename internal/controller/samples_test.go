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
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
)

// The samples in config/samples are documentation; this keeps them valid against
// the API server's schema and CEL rules.
var _ = Describe("Samples", func() {
	const samplesNS = "samples"
	samplesDir := filepath.Join("..", "..", "config", "samples")

	readSamples := func() []*unstructured.Unstructured {
		raw, err := os.ReadFile(filepath.Join(samplesDir, "kustomization.yaml"))
		Expect(err).NotTo(HaveOccurred())
		var kustomization struct {
			Resources []string `json:"resources"`
		}
		Expect(yaml.Unmarshal(raw, &kustomization)).To(Succeed())
		Expect(kustomization.Resources).NotTo(BeEmpty())

		var objs []*unstructured.Unstructured
		for _, file := range kustomization.Resources {
			data, err := os.ReadFile(filepath.Join(samplesDir, file))
			Expect(err).NotTo(HaveOccurred())
			dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
			for {
				u := &unstructured.Unstructured{}
				if err := dec.Decode(&u.Object); errors.Is(err, io.EOF) {
					break
				} else {
					Expect(err).NotTo(HaveOccurred(), file)
				}
				if len(u.Object) > 0 {
					objs = append(objs, u)
				}
			}
		}
		return objs
	}

	It("are accepted by the API server", func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: samplesNS}}
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, ns))).To(Succeed())

		kinds := map[string]int{}
		for _, u := range readSamples() {
			u.SetNamespace(samplesNS)
			Expect(k8sClient.Create(ctx, u)).To(Succeed(), "%s %s", u.GetKind(), u.GetName())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, u) })
			kinds[u.GetKind()]++
		}
		Expect(kinds).To(HaveKeyWithValue("VaultConnection", 2))
		Expect(kinds).To(HaveKeyWithValue("DatabaseCredentialRotation", 3))

		var list krotosv1alpha1.DatabaseCredentialRotationList
		Expect(k8sClient.List(ctx, &list, client.InNamespace(samplesNS))).To(Succeed())
		engines := map[krotosv1alpha1.Engine]bool{}
		for _, r := range list.Items {
			engines[r.Spec.Engine] = true
			if r.Spec.PasswordPolicy.ExcludeCharacters != "" {
				// The full reference spells out the default; it must really be the default.
				Expect(r.Spec.PasswordPolicy.ExcludeCharacters).To(Equal(krotosv1alpha1.DefaultExcludeCharacters))
			}
		}
		Expect(engines).To(HaveLen(3), "one sample per engine")
	})

	It("cover every secretSync type", func() {
		types := map[string]bool{}
		for _, u := range readSamples() {
			if u.GetKind() != "DatabaseCredentialRotation" {
				continue
			}
			var r krotosv1alpha1.DatabaseCredentialRotation
			Expect(runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &r)).To(Succeed())
			types[string(r.Spec.SecretSync.Type)] = true
		}
		Expect(types).To(Equal(map[string]bool{"None": true, "ExternalSecret": true, "VaultStaticSecret": true}))
	})
})
