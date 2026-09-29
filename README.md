# krotos

Namespaced Kubernetes operator that rotates database user passwords stored in
HashiCorp Vault and restarts the workloads that use them.

## Description

Supported engines: PostgreSQL, MySQL, MariaDB (`engine: mysql`), ClickHouse.

- `VaultConnection` — Vault address and authentication (Kubernetes auth or static token).
- `DatabaseCredentialRotation` — one database user: where to reach the database, where the
  master credentials live (Vault or a Secret), where the rotated password lives in Vault,
  a schedule (`cron` or `every: 30d`), a **mandatory change window**, how applications
  receive the secret (`secretSync`) and which workloads to restart.

The operator only watches the namespace it is deployed in (`WATCH_NAMESPACE`).

See [docs/PLAN.md](docs/PLAN.md) for the design and the rotation state machine.

### Vault setup

The operator needs to read the master credentials and read/write the rotated
password. Example policy for KV v2 mounted at `secret/`:

```hcl
path "secret/data/db/orders/master" {
  capabilities = ["read"]
}
path "secret/data/apps/orders/db" {
  capabilities = ["read", "create", "update"]
}
# In-flight rotations keep their passwords here until they finish.
path "secret/data/krotos/pending/*" {
  capabilities = ["read", "create", "update"]
}
# Needed to destroy every version of a finished rotation's pending secret.
path "secret/metadata/krotos/pending/*" {
  capabilities = ["delete"]
}
```

The pending path defaults to `krotos/pending/<namespace>/<name>` on the target's mount and
can be changed with `spec.target.vault.pendingPath`. The operator never stores passwords in
Kubernetes; its only Secret permission is `get`.

With Kubernetes auth, bind a role to the operator's ServiceAccount:

```sh
vault write auth/kubernetes/role/krotos \
  bound_service_account_names=krotos-controller-manager \
  bound_service_account_namespaces=krotos-system \
  token_policies=krotos \
  token_ttl=1h
```

If the role requires a specific audience, set `spec.auth.kubernetes.audience` on the
`VaultConnection`; the operator then requests a token for that audience instead of
using its mounted token. Alternatively use `spec.auth.token` with a token stored in a Secret.

`kubectl get vconn` shows whether the operator could log in (`Ready`); the check is
repeated every 5 minutes, and every minute while failing.

### How a rotation runs

1. The current password in Vault must log in to the database; otherwise nothing is changed.
2. A new password is generated and stored, with the old one, at the pending path in Vault
   (also kept in memory, so a rollback works even if Vault becomes unreachable).
3. The password is changed with the master credentials. The plain password never reaches the
   server logs: PostgreSQL receives a SCRAM-SHA-256 verifier, MariaDB a `mysql_native_password`
   hash, ClickHouse a salted `sha256_hash`; MySQL masks `IDENTIFIED BY` itself.
4. Login with the new password is verified.
5. The new password is written to Vault with check-and-set; other keys in the secret are kept.
   The pending passwords are deleted from Vault right after, as no rollback is possible anymore.
6. Every workload in `spec.restartTargets` is restarted like `kubectl rollout restart` (a
   `krotos.warewave.io/restartedAt` pod template annotation) and the operator waits until
   the rollouts complete, up to `spec.rolloutTimeout` (default 10m).

Steps 3–5 are retried; if they keep failing, the old password is restored in the database.
`status.step` records progress, so an operator restart resumes where it stopped.

Trigger a rotation manually with `kubectl annotate dcr <name> krotos.warewave.io/rotate-now=true`.
It still waits for the change window unless `krotos.warewave.io/ignore-window=true` is also set.
Both annotations are removed after the attempt.

A rollout that times out, a missing workload, a paused Deployment or a StatefulSet/DaemonSet
with the `OnDelete` update strategy does not undo the rotation (the password is already
changed everywhere); the rotation completes and the `Degraded` condition, reason
`RolloutIncomplete`, lists the workloads that need attention.

If the `Degraded` condition is true with reason `RotationStuck`, the database and Vault may disagree (e.g. the rollback
keeps failing). The pending path in Vault holds `oldPassword` and `newPassword` for manual recovery.

Deleting a `DatabaseCredentialRotation` while a rotation is in progress waits (via a finalizer)
until that rotation has finished or rolled back; no new rotation is started.

Database connections use TLS (`require`) by default; set `spec.database.tls.mode: disable`
to connect without it.

### Engine notes

| Engine | Statement | Notes |
|---|---|---|
| PostgreSQL | `ALTER ROLE ... PASSWORD 'SCRAM-SHA-256$...'` | Clients must support SCRAM (PostgreSQL 10+ drivers do). |
| MySQL 8+ | `ALTER USER 'u'@'host' IDENTIFIED BY ...` | `spec.target.mysqlHost` selects the account's host part (default `%`). |
| MariaDB | `ALTER USER 'u'@'host' IDENTIFIED BY PASSWORD '*...'` | Only `mysql_native_password` accounts: MariaDB logs `IDENTIFIED BY` passwords in plain text, so other plugins (e.g. `ed25519`) are refused. The master user needs `SELECT` on `mysql.user`. |
| ClickHouse | `ALTER USER u [ON CLUSTER c] IDENTIFIED WITH sha256_hash BY ... SALT ...` | Replaces all of the user's authentication methods. Set `spec.database.clickhouse.cluster` for non-replicated access storage on a cluster. |

### Known limitations

- **ClickHouse:** only users managed by SQL-driven access control can be rotated. Users
  defined in `users.xml` (or other config files) cannot be changed with `ALTER USER`
  and are not supported; ClickHouse rejects them with "storage is readonly".
- **MariaDB:** only `mysql_native_password` accounts (see above).
- The target user must be able to log in to `spec.database.database` from the operator:
  the current and the new password are verified by logging in.
- Rotation is not zero-downtime: new connections using the old password fail until the
  workloads are restarted. This is why a change window is mandatory.

## Installation

Krotos is namespaced: install one release into each namespace whose databases it should
rotate. It only watches that namespace, and only restarts workloads there.

```sh
make docker-build docker-push IMG=<registry>/krotos:<tag>

helm upgrade --install krotos dist/chart \
  --namespace team-a --create-namespace \
  --set manager.image.repository=<registry>/krotos \
  --set manager.image.tag=<tag>
```

CRDs are cluster-wide. The first release installs them (`crd.enabled=true`, kept on
uninstall); install further releases with `--set crd.enabled=false`.

The Vault role must be bound to the release's ServiceAccount, `<release>-controller-manager`
(see [Vault setup](#vault-setup)). Without Helm, `make deploy IMG=...` installs the same
manifests with kustomize into `krotos-system`.

Then create a `VaultConnection` and `DatabaseCredentialRotation`s; see `config/samples/`.

## Metrics

Served on the controller-runtime metrics endpoint (`:8443/metrics`, HTTPS, requires a
token bound to the `<release>-metrics-reader` ClusterRole). Set `prometheus.enabled=true`
to create a ServiceMonitor.

| Metric | Labels | Meaning |
|---|---|---|
| `krotos_rotations_total` | namespace, name, engine, result | Finished attempts; result is `succeeded`, `failed` or `rolled_back`. |
| `krotos_rotation_duration_seconds` | engine | Duration of successful rotations, including rollouts. |
| `krotos_last_success_timestamp_seconds` | namespace, name | Time of the last successful rotation. |
| `krotos_next_rotation_timestamp_seconds` | namespace, name | When the next rotation becomes due. |
| `krotos_rotation_degraded` | namespace, name | 1 while a rotation needs attention. |
| `krotos_rotation_consecutive_failures` | namespace, name | Failed attempts since the last success. |
| `krotos_vault_connection_ready` | namespace, name | 1 when the operator can log in to Vault. |

Useful alerts: `krotos_rotation_degraded == 1`, `krotos_rotation_consecutive_failures >= 3`,
`time() - krotos_last_success_timestamp_seconds > <expected interval + margin>`,
`krotos_vault_connection_ready == 0`.

## Development

```sh
make test              # unit tests and envtest
make test-integration  # also against real Vault, PostgreSQL, MySQL, MariaDB, ClickHouse in Docker
make test-e2e          # Kind cluster: Helm install, Vault Kubernetes auth, full rotation with a restart
make lint
```

`make test-e2e` keeps the Kind cluster's kubeconfig in `bin/krotos-test-e2e.kubeconfig`, so
the current kubectl context is never changed, and refuses to run against any other context.
Set `E2E_KEEP_CLUSTER=true` to keep the cluster afterwards (`make cleanup-test-e2e` removes it).

The Helm chart in `dist/chart` is generated from the kustomize manifests. After changing
the API or RBAC, regenerate it with `kubebuilder edit --plugins=helm/v2-alpha`.

## License

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

