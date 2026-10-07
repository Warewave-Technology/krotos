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
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/warewave/krotos/test/utils"
)

const (
	operatorNS = "krotos-system"
	depsNS     = "krotos-deps"
	release    = "krotos"
	rotation   = "orders-app"
	appUser    = "orders_app"
	appInitial = "initial-app-password"
	masterUser = "master"
	masterPass = "master-password"
)

// depsManifest runs Vault (dev mode) and PostgreSQL next to the operator.
// Vault's ServiceAccount may review tokens, which the Kubernetes auth method needs.
var depsManifest = fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault
  namespace: %[1]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: krotos-e2e-vault-auth-delegator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: vault
  namespace: %[1]s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault
  namespace: %[1]s
spec:
  selector:
    matchLabels: {app: vault}
  template:
    metadata:
      labels: {app: vault}
    spec:
      serviceAccountName: vault
      containers:
      - name: vault
        image: %[2]s
        args: ["server", "-dev", "-dev-root-token-id=root", "-dev-listen-address=0.0.0.0:8200"]
        env:
        - {name: VAULT_ADDR, value: "http://127.0.0.1:8200"}
        - {name: VAULT_TOKEN, value: root}
        ports:
        - containerPort: 8200
        readinessProbe:
          httpGet: {path: /v1/sys/health, port: 8200}
---
apiVersion: v1
kind: Service
metadata:
  name: vault
  namespace: %[1]s
spec:
  selector: {app: vault}
  ports:
  - port: 8200
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: %[1]s
spec:
  selector:
    matchLabels: {app: postgres}
  template:
    metadata:
      labels: {app: postgres}
    spec:
      containers:
      - name: postgres
        image: %[3]s
        env:
        - {name: POSTGRES_USER, value: %[4]s}
        - {name: POSTGRES_PASSWORD, value: %[5]s}
        - {name: POSTGRES_DB, value: orders}
        ports:
        - containerPort: 5432
        readinessProbe:
          exec:
            command: ["pg_isready", "-U", "%[4]s", "-d", "orders"]
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: %[1]s
spec:
  selector: {app: postgres}
  ports:
  - port: 5432
`, depsNS, vaultImage, postgresImage, masterUser, masterPass)

// appManifest is the application that uses the rotated password, and the
// resources telling the operator what to do.
var appManifest = fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: orders-api
  namespace: %[1]s
spec:
  replicas: 2
  selector:
    matchLabels: {app: orders-api}
  template:
    metadata:
      labels: {app: orders-api}
    spec:
      terminationGracePeriodSeconds: 1
      containers:
      - name: app
        image: %[2]s
        command: ["sleep", "infinity"]
---
apiVersion: krotos.warewave.io/v1alpha1
kind: VaultConnection
metadata:
  name: main-vault
  namespace: %[1]s
spec:
  address: http://vault.%[3]s.svc:8200
  auth:
    kubernetes:
      role: krotos
---
apiVersion: krotos.warewave.io/v1alpha1
kind: DatabaseCredentialRotation
metadata:
  name: %[4]s
  namespace: %[1]s
  annotations:
    krotos.warewave.io/rotate-now: "true"
    krotos.warewave.io/ignore-window: "true"
spec:
  engine: postgresql
  database:
    host: postgres.%[3]s.svc
    port: 5432
    database: orders
    tls:
      mode: disable
  masterCredentials:
    vault:
      connectionRef: main-vault
      path: db/orders/master
  target:
    username: %[5]s
    vault:
      connectionRef: main-vault
      path: apps/orders/db
      usernameKey: username
  schedule:
    every: 30d
  window:
    timezone: UTC
    start: "00:00"
    duration: 24h
  restartTargets:
  - kind: Deployment
    name: orders-api
  rolloutTimeout: 5m
`, operatorNS, postgresImage, depsNS, rotation, appUser)

// vaultPolicy lets the operator read the master credentials, rotate the
// application's password and keep its pending passwords.
const vaultPolicy = `
path "secret/data/db/orders/master" { capabilities = ["read"] }
path "secret/data/apps/*"          { capabilities = ["read", "create", "update"] }
path "secret/data/krotos/pending/*"     { capabilities = ["read", "create", "update"] }
path "secret/metadata/krotos/pending/*" { capabilities = ["delete"] }
`

func run(name string, args ...string) (string, error) {
	return utils.Run(exec.Command(name, args...))
}

func kubectl(args ...string) (string, error) {
	return run("kubectl", args...)
}

func mustKubectl(args ...string) string {
	GinkgoHelper()
	out, err := kubectl(args...)
	Expect(err).NotTo(HaveOccurred())
	return strings.TrimSpace(out)
}

func apply(manifest string) {
	GinkgoHelper()
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
}

// vault runs the vault CLI inside the Vault pod as root.
func vault(stdin string, args ...string) (string, error) {
	cmd := exec.Command("kubectl", append([]string{"exec", "-i", "-n", depsNS, "deploy/vault", "--", "vault"}, args...)...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := utils.Run(cmd)
	return strings.TrimSpace(out), err
}

func mustVault(stdin string, args ...string) string {
	GinkgoHelper()
	out, err := vault(stdin, args...)
	Expect(err).NotTo(HaveOccurred())
	return out
}

// pgLogin logs in to PostgreSQL from a separate pod, as an application would.
func pgLogin(user, password string) error {
	name := fmt.Sprintf("pg-check-%d", time.Now().UnixNano())
	_, err := kubectl("run", name, "-n", depsNS, "--rm", "-i", "--restart=Never", "--quiet",
		"--image="+postgresImage, "--env=PGPASSWORD="+password, "--env=PGCONNECT_TIMEOUT=5",
		"--", "psql", "-h", "postgres", "-U", user, "-d", "orders", "-tAc", "SELECT 1")
	return err
}

func jsonpath(kind, name, path string) string {
	GinkgoHelper()
	return mustKubectl("get", kind, name, "-n", operatorNS, "-o", "jsonpath="+path)
}

// syncManifest sets up a rotation whose password reaches the application through
// External Secrets Operator or Vault Secrets Operator. Both refresh only hourly, so
// a quick update proves that krotos triggered the sync.
func syncManifest(name, user, syncType, syncKind string) string {
	return fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s-api
  namespace: %[2]s
spec:
  replicas: 1
  selector:
    matchLabels: {app: %[1]s-api}
  template:
    metadata:
      labels: {app: %[1]s-api}
    spec:
      terminationGracePeriodSeconds: 1
      containers:
      - name: app
        image: %[3]s
        command: ["sleep", "infinity"]
---
apiVersion: krotos.warewave.io/v1alpha1
kind: DatabaseCredentialRotation
metadata:
  name: %[1]s
  namespace: %[2]s
  annotations:
    krotos.warewave.io/rotate-now: "true"
    krotos.warewave.io/ignore-window: "true"
spec:
  engine: postgresql
  database:
    host: postgres.%[4]s.svc
    port: 5432
    database: orders
    tls: {mode: disable}
  masterCredentials:
    vault: {connectionRef: main-vault, path: db/orders/master}
  target:
    username: %[5]s
    vault: {connectionRef: main-vault, path: apps/%[1]s/db}
  schedule: {every: 30d}
  window: {timezone: UTC, start: "00:00", duration: 24h}
  secretSync:
    type: %[6]s
    %[7]s: {name: %[1]s-db, secretName: %[1]s-db}
    timeout: 3m
  restartTargets:
  - {kind: Deployment, name: %[1]s-api}
  rolloutTimeout: 3m
`, name, operatorNS, postgresImage, depsNS, user, syncType, syncKind)
}

// esoManifest syncs apps/<name>/db with External Secrets Operator, authenticating with a token.
func esoManifest(name string) string {
	return fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: eso-vault-token
  namespace: %[2]s
stringData:
  token: root
---
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: vault
  namespace: %[2]s
spec:
  provider:
    vault:
      server: http://vault.%[3]s.svc:8200
      path: secret
      version: v2
      auth:
        tokenSecretRef: {name: eso-vault-token, key: token}
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: %[1]s-db
  namespace: %[2]s
spec:
  refreshInterval: 1h
  secretStoreRef: {kind: SecretStore, name: vault}
  target: {name: %[1]s-db}
  data:
  - secretKey: password
    remoteRef: {key: apps/%[1]s/db, property: password}
`, name, operatorNS, depsNS)
}

// vsoManifest syncs apps/<name>/db with Vault Secrets Operator, using Kubernetes auth.
func vsoManifest(name string) string {
	return fmt.Sprintf(`
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultConnection
metadata:
  name: vso
  namespace: %[2]s
spec:
  address: http://vault.%[3]s.svc:8200
---
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultAuth
metadata:
  name: vso
  namespace: %[2]s
spec:
  vaultConnectionRef: vso
  method: kubernetes
  mount: kubernetes
  kubernetes: {role: vso, serviceAccount: default}
---
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultStaticSecret
metadata:
  name: %[1]s-db
  namespace: %[2]s
spec:
  vaultAuthRef: vso
  type: kv-v2
  mount: secret
  path: apps/%[1]s/db
  refreshAfter: 1h
  destination: {name: %[1]s-db, create: true}
`, name, operatorNS, depsNS)
}

func secretValue(name, key string) string {
	GinkgoHelper()
	out, err := kubectl("get", "secret", name, "-n", operatorNS, "-o", "jsonpath={.data."+key+"}")
	if err != nil || out == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(out)
	Expect(err).NotTo(HaveOccurred())
	return string(decoded)
}

func waitRotated(name string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		out, err := kubectl("get", "dcr", name, "-n", operatorNS, "-o",
			`jsonpath={.status.phase}/{.status.lastRotationTime}/{.status.message}`)
		g.Expect(err).NotTo(HaveOccurred())
		parts := strings.SplitN(out, "/", 3)
		g.Expect(parts).To(HaveLen(3))
		g.Expect(parts[1]).NotTo(BeEmpty(), "phase %s: %s", parts[0], parts[2])
		g.Expect(parts[0]).To(Equal("Idle"))
	}, 5*time.Minute, 3*time.Second).Should(Succeed())
}

var _ = Describe("krotos", Ordered, func() {
	var oldPassword, newPassword string

	BeforeAll(func() {
		By("deploying Vault and PostgreSQL")
		apply(depsManifest)
		for _, d := range []string{"vault", "postgres"} {
			mustKubectl("rollout", "status", "deploy/"+d, "-n", depsNS, "--timeout=3m")
		}

		By("creating the application's database user")
		mustKubectl("exec", "-n", depsNS, "deploy/postgres", "--", "psql", "-U", masterUser, "-d", "orders", "-c",
			fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", appUser, appInitial))

		By("configuring Vault: Kubernetes auth, policy, secrets")
		mustVault("", "auth", "enable", "kubernetes")
		mustVault("", "write", "auth/kubernetes/config", "kubernetes_host=https://kubernetes.default.svc:443")
		mustVault(vaultPolicy, "policy", "write", "krotos", "-")
		mustVault("", "write", "auth/kubernetes/role/krotos",
			"bound_service_account_names="+release+"-controller-manager",
			"bound_service_account_namespaces="+operatorNS,
			"token_policies=krotos", "token_ttl=1h")
		mustVault("", "kv", "put", "secret/db/orders/master", "username="+masterUser, "password="+masterPass)
		mustVault("", "kv", "put", "secret/apps/orders/db", "username="+appUser, "password="+appInitial,
			"host=postgres."+depsNS+".svc")

		By("installing the operator with Helm")
		_, err := run("helm", "upgrade", "--install", release, "dist/chart",
			"--namespace", operatorNS, "--create-namespace",
			"--set", "manager.image.repository=krotos", "--set", "manager.image.tag=e2e",
			"--wait", "--timeout", "3m")
		Expect(err).NotTo(HaveOccurred())

		By("deploying the application and the rotation")
		apply(appManifest)
		mustKubectl("rollout", "status", "deploy/orders-api", "-n", operatorNS, "--timeout=2m")
		oldPassword = appInitial
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		for _, args := range [][]string{
			{"logs", "-n", operatorNS, "deploy/" + release + "-controller-manager", "--tail=200"},
			{"get", "vaultconnections.krotos.warewave.io,databasecredentialrotations", "-n", operatorNS, "-o", "yaml"},
			{"get", "events", "-n", operatorNS, "--sort-by=.lastTimestamp"},
		} {
			out, _ := kubectl(args...)
			_, _ = fmt.Fprintf(GinkgoWriter, "--- kubectl %s\n%s\n", strings.Join(args, " "), out)
		}
	})

	It("logs in to Vault with Kubernetes auth", func() {
		Eventually(func() string {
			return jsonpath("vaultconnections.krotos.warewave.io", "main-vault",
				`{.status.conditions[?(@.type=="Ready")].status}`)
		}, 2*time.Minute, 2*time.Second).Should(Equal("True"))
	})

	It("rotates the password and restarts the application", func() {
		Eventually(func(g Gomega) {
			out, err := kubectl("get", "dcr", rotation, "-n", operatorNS, "-o",
				`jsonpath={.status.phase}/{.status.lastRotationTime}`)
			g.Expect(err).NotTo(HaveOccurred())
			phase, last, _ := strings.Cut(out, "/")
			g.Expect(last).NotTo(BeEmpty(), "phase %s", phase)
			g.Expect(phase).To(Equal("Idle"))
		}, 5*time.Minute, 3*time.Second).Should(Succeed())

		Expect(jsonpath("dcr", rotation, `{.status.conditions[?(@.type=="Rotated")].status}`)).To(Equal("True"))
		Expect(jsonpath("dcr", rotation, `{.status.conditions[?(@.type=="Degraded")].status}`)).To(Equal("False"))
		// The one-shot trigger annotations were consumed.
		Expect(jsonpath("dcr", rotation, `{.metadata.annotations.krotos\.warewave\.io/rotate-now}`)).To(BeEmpty())
		Expect(jsonpath("dcr", rotation, `{.metadata.annotations.krotos\.warewave\.io/ignore-window}`)).To(BeEmpty())

		By("reading the new password from Vault")
		newPassword = mustVault("", "kv", "get", "-field=password", "secret/apps/orders/db")
		Expect(newPassword).To(HaveLen(32))
		Expect(newPassword).NotTo(Equal(oldPassword))
		Expect(mustVault("", "kv", "get", "-field=host", "secret/apps/orders/db")).To(Equal("postgres." + depsNS + ".svc"))

		By("logging in with the new password from another pod")
		Expect(pgLogin(appUser, newPassword)).To(Succeed())
		Expect(pgLogin(appUser, oldPassword)).NotTo(Succeed())

		By("checking that the application was restarted and rolled out")
		token := jsonpath("deploy", "orders-api", `{.spec.template.metadata.annotations.krotos\.warewave\.io/restartedAt}`)
		Expect(token).NotTo(BeEmpty())
		mustKubectl("rollout", "status", "deploy/orders-api", "-n", operatorNS, "--timeout=1m")
		Expect(jsonpath("deploy", "orders-api", "{.status.updatedReplicas}")).To(Equal("2"))

		By("checking that the pending passwords are gone from Vault")
		_, err := vault("", "kv", "metadata", "get", "secret/krotos/pending/"+operatorNS+"/"+rotation)
		Expect(err).To(HaveOccurred())
	})

	It("never logs a password", func() {
		logs := mustKubectl("logs", "-n", operatorNS, "deploy/"+release+"-controller-manager")
		Expect(logs).NotTo(BeEmpty())
		Expect(logs).NotTo(ContainSubstring(newPassword))
		Expect(logs).NotTo(ContainSubstring(oldPassword))
		Expect(logs).NotTo(ContainSubstring(masterPass))
	})

	It("serves Prometheus metrics", func() {
		By("granting a ServiceAccount access to the metrics endpoint")
		mustKubectl("create", "serviceaccount", "metrics-check", "-n", operatorNS)
		mustKubectl("create", "clusterrolebinding", "krotos-e2e-metrics-check",
			"--clusterrole="+release+"-metrics-reader", "--serviceaccount="+operatorNS+":metrics-check")
		token := mustKubectl("create", "token", "metrics-check", "-n", operatorNS)
		svc := mustKubectl("get", "svc", "-n", operatorNS, "-l", "control-plane=controller-manager",
			"-o", "jsonpath={.items[0].metadata.name}")

		// Not `kubectl run -i`: when curl finishes before kubectl attaches, its output is lost.
		mustKubectl("run", "metrics-check", "-n", operatorNS, "--restart=Never",
			"--image="+curlImage, "--", "curl", "-sSfk", "--retry", "10", "--retry-all-errors",
			"-H", "Authorization: Bearer "+token,
			fmt.Sprintf("https://%s.%s.svc:8443/metrics", svc, operatorNS))
		mustKubectl("wait", "pod/metrics-check", "-n", operatorNS,
			"--for=jsonpath={.status.phase}=Succeeded", "--timeout=2m")
		out := mustKubectl("logs", "pod/metrics-check", "-n", operatorNS)
		Expect(out).To(ContainSubstring(fmt.Sprintf(
			`krotos_rotations_total{engine="postgresql",name=%q,namespace=%q,result="succeeded"} 1`, rotation, operatorNS)))
		Expect(out).To(ContainSubstring(fmt.Sprintf(
			`krotos_vault_connection_ready{name="main-vault",namespace=%q} 1`, operatorNS)))
		Expect(out).To(ContainSubstring("krotos_rotation_duration_seconds_count"))
	})

	// testSecretSync rotates a password that reaches the application through a sync
	// operator, and checks that the synced Secret was updated before the restart.
	testSecretSync := func(name, user, syncType, syncKind string, setup func()) {
		GinkgoHelper()
		initial := "initial-" + name
		mustKubectl("exec", "-n", depsNS, "deploy/postgres", "--", "psql", "-U", masterUser, "-d", "orders", "-c",
			fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", user, initial))
		mustVault("", "kv", "put", "secret/apps/"+name+"/db", "username="+user, "password="+initial)

		setup()
		By("waiting for the initial sync")
		Eventually(func() string { return secretValue(name+"-db", "password") }, 3*time.Minute, 2*time.Second).
			Should(Equal(initial))

		By("rotating")
		apply(syncManifest(name, user, syncType, syncKind))
		waitRotated(name)
		Expect(jsonpath("dcr", name, `{.status.conditions[?(@.type=="Degraded")].status}`)).To(Equal("False"),
			jsonpath("dcr", name, `{.status.conditions[?(@.type=="Degraded")].message}`))

		rotated := mustVault("", "kv", "get", "-field=password", "secret/apps/"+name+"/db")
		Expect(rotated).NotTo(Equal(initial))
		Expect(secretValue(name+"-db", "password")).To(Equal(rotated), "the synced Secret was not updated")
		Expect(pgLogin(user, rotated)).To(Succeed())
		Expect(jsonpath("deploy", name+"-api",
			`{.spec.template.metadata.annotations.krotos\.warewave\.io/restartedAt}`)).NotTo(BeEmpty())
	}

	It("triggers an External Secrets Operator sync before restarting", func() {
		By("installing External Secrets Operator")
		_, err := run("helm", "upgrade", "--install", "external-secrets", "external-secrets",
			"--repo", "https://charts.external-secrets.io",
			"--namespace", "external-secrets", "--create-namespace", "--wait", "--timeout", "5m")
		Expect(err).NotTo(HaveOccurred())

		testSecretSync("orders-eso", "orders_eso", "ExternalSecret", "externalSecret", func() {
			Eventually(func() error {
				// The webhook may take a moment after the release is ready.
				cmd := exec.Command("kubectl", "apply", "-f", "-")
				cmd.Stdin = strings.NewReader(esoManifest("orders-eso"))
				_, err := utils.Run(cmd)
				return err
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})

	It("triggers a Vault Secrets Operator sync before restarting", func() {
		By("installing Vault Secrets Operator")
		_, err := run("helm", "upgrade", "--install", "vault-secrets-operator", "vault-secrets-operator",
			"--repo", "https://helm.releases.hashicorp.com",
			"--namespace", "vault-secrets-operator-system", "--create-namespace", "--wait", "--timeout", "5m")
		Expect(err).NotTo(HaveOccurred())
		mustVault(`path "secret/data/apps/*" { capabilities = ["read"] }`, "policy", "write", "vso", "-")
		mustVault("", "write", "auth/kubernetes/role/vso",
			"bound_service_account_names=default", "bound_service_account_namespaces="+operatorNS,
			"token_policies=vso", "token_ttl=1h")

		testSecretSync("orders-vso", "orders_vso", "VaultStaticSecret", "vaultStaticSecret", func() {
			apply(vsoManifest("orders-vso"))
		})
	})
})
