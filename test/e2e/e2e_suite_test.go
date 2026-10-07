//go:build e2e

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

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/Warewave-Technology/krotos/test/utils"
)

const (
	// managerImage is the operator image built and loaded into Kind.
	managerImage  = "krotos:e2e"
	postgresImage = "postgres:17-alpine"
	vaultImage    = "hashicorp/vault:1.20"
	curlImage     = "curlimages/curl:8.16.0"
)

// TestE2E runs the e2e suite against a Kind cluster. Run it with `make test-e2e`,
// which creates the cluster with its own kubeconfig.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting krotos e2e test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	By("refusing to run against anything but the e2e Kind cluster")
	cluster := os.Getenv("KIND_CLUSTER")
	Expect(cluster).NotTo(BeEmpty(), "KIND_CLUSTER must be set; run `make test-e2e`")
	Expect(os.Getenv("KUBECONFIG")).NotTo(BeEmpty(), "KUBECONFIG must point at the e2e cluster; run `make test-e2e`")
	out, err := utils.Run(exec.Command("kubectl", "config", "current-context"))
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.TrimSpace(out)).To(Equal("kind-"+cluster), "the current context is not the e2e Kind cluster")

	// kubectl kuberc could change command behavior; keep tests isolated.
	Expect(os.Setenv("KUBECTL_KUBERC", "false")).To(Succeed())

	By("building the manager image")
	_, err = utils.Run(exec.Command("make", "docker-build", "IMG="+managerImage))
	Expect(err).NotTo(HaveOccurred(), "Failed to build the manager image")

	// Only the locally built image is loaded. Third-party images are pulled by the
	// nodes: `kind load` fails for multi-arch images with Docker's containerd store.
	By("loading the manager image into Kind")
	Expect(utils.LoadImageToKindClusterWithName(managerImage)).To(Succeed())
})
