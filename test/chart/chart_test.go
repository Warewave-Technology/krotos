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

// Package chart checks that the generated Helm chart is in sync with the API.
package chart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/yaml"
)

// readCRD parses a CRD file, dropping Helm template directives.
func readCRD(t *testing.T, path string) *apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for line := range strings.SplitSeq(string(raw), "\n") {
		if !strings.Contains(line, "{{") {
			lines = append(lines, line)
		}
	}
	crd := &apiextensionsv1.CustomResourceDefinition{}
	if err := yaml.UnmarshalStrict([]byte(strings.Join(lines, "\n")), crd); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return crd
}

// TestChartCRDsMatchAPI fails when the API changed but dist/chart was not
// regenerated. An outdated CRD makes the API server drop new status fields.
func TestChartCRDsMatchAPI(t *testing.T) {
	bases, err := filepath.Glob("../../config/crd/bases/*.yaml")
	if err != nil || len(bases) == 0 {
		t.Fatalf("no CRDs found: %v", err)
	}
	for _, base := range bases {
		want := readCRD(t, base)
		chartPath := filepath.Join("../../dist/chart/templates/crd", want.Name+".yaml")
		got := readCRD(t, chartPath)
		if !equality.Semantic.DeepEqual(got.Spec, want.Spec) {
			t.Errorf("%s differs from %s; run `make helm-chart`", chartPath, base)
		}
	}
}
