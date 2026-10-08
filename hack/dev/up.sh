#!/usr/bin/env bash
# Creates (or updates) a local Kind cluster "krotos-dev" with Vault, PostgreSQL,
# MySQL, ClickHouse, Redis (primary + replica), NATS (operator mode), External Secrets
# Operator, Vault Secrets Operator, the krotos operator and five demo rotations in the
# namespace team-a.
#
# The cluster's kubeconfig is written to bin/krotos-dev.kubeconfig; the current
# kubectl context is never changed. Safe to run again: existing users and Vault
# secrets are left alone, the operator image is rebuilt and upgraded.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DIR="$ROOT/hack/dev"
CLUSTER="${CLUSTER:-krotos-dev}"
KIND="$ROOT/bin/kind"
export KUBECONFIG="$ROOT/bin/$CLUSTER.kubeconfig"
NS=team-a
DEPS=krotos-deps
IMG_REPO=krotos
IMG_TAG="dev-$(date +%Y%m%d%H%M%S)"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

if [ ! -x "$KIND" ]; then
  make -C "$ROOT" kind >/dev/null
fi

step "Kind cluster $CLUSTER"
if "$KIND" get clusters | grep -qx "$CLUSTER"; then
  "$KIND" export kubeconfig --name "$CLUSTER" --kubeconfig "$KUBECONFIG"
else
  "$KIND" create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG"
fi
# Every command below must hit the dev cluster and nothing else.
[ "$(kubectl config current-context)" = "kind-$CLUSTER" ] || { echo "unexpected context" >&2; exit 1; }

step "Building and loading the operator image $IMG_REPO:$IMG_TAG"
make -C "$ROOT" docker-build IMG="$IMG_REPO:$IMG_TAG" >/dev/null
"$KIND" load docker-image "$IMG_REPO:$IMG_TAG" --name "$CLUSTER"

step "Vault, PostgreSQL, MySQL, ClickHouse, Redis"
kubectl apply -f "$DIR/deps.yaml"
for d in vault postgres mysql clickhouse redis-primary redis-replica nats-box; do
  kubectl rollout status "deploy/$d" -n "$DEPS" --timeout=5m
done

step "Database users"
kubectl exec -n "$DEPS" deploy/postgres -- psql -U postgres -d orders -v ON_ERROR_STOP=1 -c "
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'orders_app') THEN
    CREATE ROLE orders_app LOGIN PASSWORD 'orders-initial-pw';
  END IF;
END \$\$;"
kubectl exec -n "$DEPS" deploy/mysql -- mysql -uroot -pmysql-root-pw -e "
CREATE USER IF NOT EXISTS 'billing_app'@'%' IDENTIFIED BY 'billing-initial-pw';
GRANT SELECT ON billing.* TO 'billing_app'@'%';" 2>&1 | grep -v "Using a password" || true
kubectl exec -n "$DEPS" deploy/clickhouse -- clickhouse-client --user admin --password clickhouse-admin-pw --multiquery --query "
CREATE USER IF NOT EXISTS analytics_reader IDENTIFIED WITH sha256_password BY 'analytics-initial-pw';
GRANT SELECT ON analytics.* TO analytics_reader;"
# ACL users are per server: create them on both, the rotator from the README template.
for d in redis-primary redis-replica; do
  rcli() { kubectl exec -n "$DEPS" "deploy/$d" -- redis-cli --no-auth-warning -a redis-admin-pw "$@"; }
  if [ "$(rcli ACL GETUSER sessions_app | head -1)" = "" ]; then
    rcli ACL SETUSER sessions_app on '>sessions-initial-pw' '~session:*' +@read +@write +ping >/dev/null
  fi
  grep -v '^#' "$ROOT/docs/least-privilege/redis.acl" | sed 's/change-me/redis-rotator-pw/' |
    kubectl exec -i -n "$DEPS" "deploy/$d" -- redis-cli --no-auth-warning -a redis-admin-pw >/dev/null
  rcli ACL SAVE >/dev/null
done

step "NATS: operator, account EVENTS, server"
# nsc runs in the nats-box pod; its store survives on a PVC.
nsc_run() { kubectl exec -i -n "$DEPS" deploy/nats-box -- sh -ec "$1"; }
nsc_run '[ -d /store/nats ] && exit 0
mkdir -p /store/nats /store/demo && nsc env -s /store/nats >/dev/null 2>&1
nsc add operator --generate-signing-key --sys --name krotos-dev
nsc edit operator --account-jwt-server-url nats://nats.krotos-deps.svc:4222
nsc add account EVENTS' </dev/null
nsc_run 'nsc generate config --nats-resolver --sys-account SYS --config-file /tmp/server.conf --force >/dev/null 2>&1
sed "s|dir: .*|dir: \"/data/jwt\"|" /tmp/server.conf' </dev/null |
  kubectl create configmap nats-config -n "$DEPS" --from-file=server.conf=/dev/stdin --dry-run=client -o yaml |
  kubectl apply -f - >/dev/null
kubectl apply -f "$DIR/nats.yaml"
kubectl rollout status deploy/nats -n "$DEPS" --timeout=3m
nsc_run 'for i in $(seq 1 60); do nc -z nats.krotos-deps.svc 4222 2>/dev/null && exit 0; sleep 2; done; exit 1' </dev/null
# The signing key and user from the README template, once (ORDERS becomes EVENTS).
sed 's/ORDERS/EVENTS/g; s/orders/events/g' "$ROOT/docs/least-privilege/nats.sh" |
  nsc_run 'cd /store/demo; [ -f events-service.creds ] && exit 0; cat > template.sh; sh -e template.sh'
# The server keeps pushed accounts in an emptyDir: push them on every run.
nsc_run 'nsc push --all' </dev/null >/dev/null

step "Vault: Kubernetes auth, policies, secrets"
vault() { kubectl exec -i -n "$DEPS" deploy/vault -- vault "$@"; }
vault auth list | grep -q '^kubernetes/' || vault auth enable kubernetes
vault write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc:443 >/dev/null
vault policy write krotos - >/dev/null <<'EOF'
path "secret/data/db/*"                 { capabilities = ["read"] }
path "secret/data/apps/*"               { capabilities = ["read", "create", "update"] }
path "secret/data/krotos/pending/*"     { capabilities = ["read", "create", "update"] }
path "secret/metadata/krotos/pending/*" { capabilities = ["delete"] }
EOF
vault write auth/kubernetes/role/krotos \
  bound_service_account_names=krotos-controller-manager bound_service_account_namespaces="$NS" \
  token_policies=krotos token_ttl=1h >/dev/null
vault policy write vso - >/dev/null <<'EOF'
path "secret/data/apps/*" { capabilities = ["read"] }
EOF
vault write auth/kubernetes/role/vso \
  bound_service_account_names=default bound_service_account_namespaces="$NS" \
  token_policies=vso token_ttl=1h >/dev/null
# Only written when missing: rewriting them after a rotation would break the logins.
put_once() {
  local path=$1; shift
  vault kv get "$path" >/dev/null 2>&1 || vault kv put "$path" "$@" >/dev/null
}
put_once secret/db/postgres/master   username=postgres password=postgres-master-pw
put_once secret/db/mysql/master      username=root     password=mysql-root-pw
put_once secret/db/clickhouse/master username=admin    password=clickhouse-admin-pw
put_once secret/db/redis/rotator     username=krotos_rotator password=redis-rotator-pw
put_once secret/apps/orders/db    username=orders_app       password=orders-initial-pw    host=postgres.$DEPS.svc
put_once secret/apps/billing/db   username=billing_app      password=billing-initial-pw   host=mysql.$DEPS.svc
put_once secret/apps/analytics/db username=analytics_reader password=analytics-initial-pw host=clickhouse.$DEPS.svc
put_once secret/apps/sessions/redis username=sessions_app password=sessions-initial-pw host=redis-primary.$DEPS.svc
# NATS: the scoped signing key's seed and the user's .creds file, from nats-box.
from_box() { kubectl exec -n "$DEPS" deploy/nats-box -- cat "/store/demo/$1"; }
vault kv get secret/db/nats/events-signing-key >/dev/null 2>&1 ||
  from_box krotos-events.seed | vault kv put secret/db/nats/events-signing-key seed=- >/dev/null
vault kv get secret/apps/events/nats >/dev/null 2>&1 ||
  from_box events-service.creds | vault kv put secret/apps/events/nats creds=- url=nats://nats.$DEPS.svc:4222 >/dev/null

step "External Secrets Operator and Vault Secrets Operator"
helm upgrade --install external-secrets external-secrets --repo https://charts.external-secrets.io \
  --namespace external-secrets --create-namespace --wait --timeout 5m >/dev/null
helm upgrade --install vault-secrets-operator vault-secrets-operator --repo https://helm.releases.hashicorp.com \
  --namespace vault-secrets-operator-system --create-namespace --wait --timeout 5m >/dev/null
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# The ESO webhook can need a moment after the release reports ready.
for i in $(seq 1 30); do
  kubectl apply -f "$DIR/sync.yaml" >/dev/null 2>&1 && break
  [ "$i" = 30 ] && kubectl apply -f "$DIR/sync.yaml"
  sleep 5
done
for s in billing-db analytics-db sessions-redis events-nats; do
  until kubectl get secret "$s" -n "$NS" >/dev/null 2>&1; do sleep 2; done
done

step "krotos operator (Helm) in $NS"
helm upgrade --install krotos "$ROOT/dist/chart" --namespace "$NS" \
  --set manager.image.repository="$IMG_REPO" --set manager.image.tag="$IMG_TAG" \
  --wait --timeout 3m >/dev/null

step "Demo applications and rotations"
kubectl apply -f "$DIR/demo.yaml"
kubectl wait --for=condition=Ready vaultconnections.krotos.warewave.io/main-vault -n "$NS" --timeout=2m >/dev/null

cat <<EOF

krotos dev environment is up. Use it with:

  export KUBECONFIG=$KUBECONFIG

  kubectl get vconn,dcr -n $NS
  kubectl get dcr orders -n $NS -o yaml
  kubectl logs -n $NS deploy/krotos-controller-manager -f

Trigger a rotation now:
  kubectl annotate dcr billing -n $NS krotos.warewave.io/rotate-now=true krotos.warewave.io/ignore-window=true

Read a password from Vault:
  kubectl exec -n $DEPS deploy/vault -- vault kv get secret/apps/orders/db

Rotate the NATS user (issues new .creds; the old ones expire after their TTL):
  kubectl annotate dcr events -n $NS krotos.warewave.io/rotate-now=true krotos.warewave.io/ignore-window=true

Rotate the Redis user (primary and replica):
  kubectl annotate dcr sessions -n $NS krotos.warewave.io/rotate-now=true krotos.warewave.io/ignore-window=true

After changing the code:  make dev-up    (rebuilds and upgrades the operator)
Remove everything:        make dev-down
EOF
