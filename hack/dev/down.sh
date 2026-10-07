#!/usr/bin/env bash
# Deletes the krotos-dev Kind cluster and its kubeconfig.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLUSTER="${CLUSTER:-krotos-dev}"
"$ROOT/bin/kind" delete cluster --name "$CLUSTER" --kubeconfig "$ROOT/bin/$CLUSTER.kubeconfig"
rm -f "$ROOT/bin/$CLUSTER.kubeconfig"
