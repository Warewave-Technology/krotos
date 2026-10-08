# Krotos — Veritabanı Credential Rotation Operatörü (Plan v0)

## 1. Amaç

Vault'ta tutulan veritabanı kullanıcı parolalarını planlı ve güvenli şekilde rotate etmek,
ardından bu parolaları kullanan uygulamaları restart etmek.

- İlk hedef engine'ler: **PostgreSQL, MySQL, ClickHouse**
- Kubernetes operatörü, **namespaced** (sadece kendi namespace'ini izler, ClusterRole yok)
- CRD tabanlı, zamanlama: **cron** veya **N günde bir**
- **Değişiklik penceresi (window) zorunlu**; pencere dışında rotation başlamaz
- Master credential: Vault'ta **veya** bir k8s Secret'ta
- Yeni parola Vault'a geri yazılır (yazma yetkili Vault kimliği gerekir)

## 2. Teknoloji

| Konu | Seçim |
|---|---|
| Dil | Go 1.26 |
| Framework | kubebuilder v4 / controller-runtime |
| Vault | `hashicorp/vault/api` (KV v1 + v2) |
| PostgreSQL | `jackc/pgx/v5` |
| MySQL | `go-sql-driver/mysql` |
| ClickHouse | `ClickHouse/clickhouse-go/v2` |
| Cron | `robfig/cron/v3` (parser) |
| Test | envtest + testcontainers-go (postgres, mysql, clickhouse, vault dev) |
| Dağıtım | Helm chart + kustomize (kubebuilder default) |

API group önerisi: `krotos.warewave.io/v1alpha1`

## 3. CRD'ler

İki CRD öneriyorum: Vault bağlantısı ortak olduğu için ayrı tutulur, her rotation tekrar tanımlamaz.

### 3.1 `VaultConnection`

```yaml
apiVersion: krotos.warewave.io/v1alpha1
kind: VaultConnection
metadata:
  name: main-vault
spec:
  address: https://vault.example.com:8200
  namespace: ""                     # Vault Enterprise namespace (opsiyonel)
  caSecretRef: { name: vault-ca, key: ca.crt }   # opsiyonel
  auth:
    # Biri seçilir:
    kubernetes:                     # ÖNERİLEN: operatörün ServiceAccount'u ile login
      role: krotos
      mountPath: kubernetes
    # token:
    #   secretRef: { name: vault-token, key: token }
status:
  conditions: [Ready]               # login + token lookup başarılı mı
```

### 3.2 `DatabaseCredentialRotation`

```yaml
apiVersion: krotos.warewave.io/v1alpha1
kind: DatabaseCredentialRotation
metadata:
  name: orders-db-app-user
spec:
  engine: postgresql                # postgresql | mysql | clickhouse
  suspend: false

  database:
    host: orders-pg.db.svc
    port: 5432
    database: orders                # PG için bağlanılacak DB
    tls:
      mode: require                 # disable | require | verify-full
      caSecretRef: { name: pg-ca, key: ca.crt }
    clickhouse:                     # sadece clickhouse için
      cluster: ""                   # doluysa ALTER USER ... ON CLUSTER
      protocol: native              # native | http

  # Rotation'ı yapacak yetkili kullanıcı
  masterCredentials:
    # Biri seçilir:
    vault:
      connectionRef: main-vault
      mount: secret                 # KV mount
      path: db/orders/master        # KV v2 için "data/" öneki YAZILMAZ
      kvVersion: 2                  # 1 | 2, varsayılan 2
      usernameKey: username
      passwordKey: password
    # secretRef:
    #   name: orders-pg-master
    #   usernameKey: username
    #   passwordKey: password

  # Rotate edilecek kullanıcı ve parolasının Vault'taki yeri
  target:
    username: orders_app
    mysqlHost: "%"                  # sadece mysql için
    vault:
      connectionRef: main-vault     # master'dan farklı (yazma yetkili) bir bağlantı olabilir
      mount: secret
      path: apps/orders/db
      kvVersion: 2
      passwordKey: password
      usernameKey: username         # opsiyonel, yazılırsa username de güncel tutulur

  passwordPolicy:
    length: 32
    excludeCharacters: "'\"\\`$@:/?#"   # connection string'i bozabilecek karakterler

  schedule:
    # Biri seçilir:
    cron: "0 3 * * 6"
    # every: 30d                     # N günde bir (son başarılı rotation'dan itibaren)

  window:                           # ZORUNLU
    timezone: Europe/Istanbul
    days: [Sat, Sun]
    start: "02:00"
    duration: 3h
    minRemaining: 15m               # pencerede en az bu kadar süre kalmışsa başlar (varsayılan 15m)

  # Uygulamaların parolayı nasıl aldığı; restart öncesi ne yapılacağını belirler
  secretSync:
    type: None                      # None (Vault Agent/CSI) | ExternalSecret | VaultStaticSecret
    # externalSecret:
    #   name: orders-db             # force-sync annotation'ı basılır
    #   secretName: orders-db       # senkronlanan k8s Secret; yeni değer görülene kadar beklenir
    #   secretKey: password
    # vaultStaticSecret:
    #   name: orders-db
    #   secretName: orders-db
    #   secretKey: password
    timeout: 5m

  restartTargets:
    - kind: Deployment
      name: orders-api
    - kind: StatefulSet
      selector: { matchLabels: { app: orders-worker } }

  rolloutTimeout: 10m
status:
  phase: Idle                       # Idle | Waiting | Rotating | Restarting | Failed
  step: ""                          # state machine adımı (bkz. 4)
  lastRotationTime: ...
  nextScheduledTime: ...
  nextWindowStart: ...
  consecutiveFailures: 0
  observedGeneration: 1
  conditions: [Ready, Rotated, Degraded]
```

Manuel tetikleme: `krotos.warewave.io/rotate-now: "true"` annotation'ı. Varsayılan olarak
yine pencereye uyar; `krotos.warewave.io/ignore-window: "true"` ile pencere atlanabilir.

## 4. Rotation akışı (state machine)

Asıl risk: DB'de parola değişip Vault'a yazılamazsa veya ortada operatör çökerse uygulamaların
kilitlenmesi. Bu yüzden her adım `status.step`'e yazılır ve adımlar idempotent tasarlanır.

```
Due? ──> InWindow? ──> [1] PendingSaved ──> [2] DbUpdated ──> [3] Verified
                                                                    │
      [6] Done <── [5] SecretSynced <── [4] VaultWritten <──────────┘
```

0. **Ön kontrol** — Vault'taki mevcut parola ile hedef kullanıcı DB'ye giriş yapabiliyor mu?
   Yapamıyorsa (Vault ile DB zaten uyumsuz) hiçbir şey değiştirilmeden deneme başarısız sayılır.
1. **PendingSaved** — Yeni parola üretilir; eski ve yeni parola **Vault'ta** operatöre ait
   `krotos/pending/<namespace>/<name>` path'ine yazılır (ayrıca bellekte tutulur, böylece Vault
   erişilemezken de rollback yapılabilir). Kubernetes'te hiçbir yerde parola tutulmaz.
   Rotation bitince bu secret'ın tüm versiyonları silinir (KV v2'de metadata delete).
2. **DbUpdated** — Master kullanıcıyla `ALTER USER` çalıştırılır.
3. **Verified** — Hedef kullanıcıyla yeni parola ile login denenir (`SELECT 1`).
4. **VaultWritten** — Yeni parola Vault'a yazılır (KV v2'de `cas` ile, eşzamanlı yazmaya karşı).
5. **SecretSynced** — Pending parolalar Vault'tan silinir (artık rollback yok). Hedef workload'ların
   pod template'ine `krotos.warewave.io/restartedAt=<rotation başlangıç zamanı>` basılır
   (`kubectl rollout restart` ile aynı; aynı rotation için tekrar basılmaz) ve rollout'lar
   `kubectl rollout status` kurallarıyla `rolloutTimeout` kadar beklenir. Timeout, bulunamayan
   workload, paused Deployment veya OnDelete strateji rotation'ı geri almaz; rotation tamamlanır,
   `Degraded=True (RolloutIncomplete)` ile raporlanır.
6. **Done** — Vault'taki pending secret tüm versiyonlarıyla silinir, `lastRotationTime` güncellenir, sonraki zaman hesaplanır.

Retry politikası: DB adımları 3, Vault yazma 5 deneme (15s'den 5dk'ya üstel backoff); tükenirse
**RollingBack**. Rollback başarılı olana kadar tekrar edilir (`Degraded`). Başarısız bir denemeden
sonra yeni deneme 5dk'dan başlayıp 6 saate kadar üstel bekler (yine pencere içinde).

Hata durumları:
- 2 başarısız → pending temizlenir, hiçbir şey değişmemiştir, backoff ile tekrar.
- 3 veya 4 başarısız → belirli sayıda retry; sonra **rollback**: eski parola `ALTER USER` ile geri yüklenir.
- 5 başarısız → parola zaten tutarlı (DB = Vault); rollback yapılmaz, `Degraded` (RolloutIncomplete) + Event.
- Pencere, rotation *başlarken* kontrol edilir (en az `minRemaining` kalmış olmalı); başlamış rotation pencere biterse de tamamlanır.

### Engine'e özel SQL

Hiçbir engine'de düz parola sunucu loglarına düşmez (integration testlerinde `log_statement=all`,
general log ve `query_log` üzerinden doğrulanıyor).

| Engine | Komut | Not |
|---|---|---|
| PostgreSQL | `ALTER ROLE "u" WITH PASSWORD 'SCRAM-SHA-256$...'` | Verifier istemcide hesaplanır. |
| MySQL | `ALTER USER 'u'@'host' IDENTIFIED BY '...'` | MySQL parolayı loglarda kendisi maskeler. Host `target.mysqlHost` (varsayılan `%`). |
| MariaDB | `ALTER USER 'u'@'host' IDENTIFIED BY PASSWORD '*...'` | MariaDB `IDENTIFIED BY`'ı general log'a düz yazar; bu yüzden hash gönderilir. Sadece `mysql_native_password` hesaplar; diğer plugin'ler reddedilir. |
| ClickHouse | `ALTER USER u [ON CLUSTER c] IDENTIFIED WITH sha256_hash BY '...' SALT '...'` | Sadece SQL-driven access control kullanıcıları; `users.xml` kullanıcıları "readonly storage" hatası verir. |

## 5. Kesinti meselesi

**Karar:** Parola değişimi ile restart arası kısa kesinti kabul edilir; zorunlu değişiklik
penceresi bunun için var. Kesintisiz yöntemler (MySQL dual password, A/B kullanıcı) kapsam dışı,
ileride gerekirse değerlendirilir.

## 6. Uygulamalar parolayı Vault'tan nasıl alıyor? (kritik)

Restart'ın işe yaraması, uygulamanın restart sonrası **yeni** parolayı görmesine bağlı:

Yöntem CRD'de `spec.secretSync.type` ile seçilir:

- `None` (Vault Agent Injector / CSI) → pod restart'ta doğrudan Vault'tan okur, ek adım yok.
- `ExternalSecret` → ExternalSecret'a ESO'nun belgelenmiş `force-sync` annotation'ı basılır.
- `VaultStaticSecret` → VaultStaticSecret'a `krotos.warewave.io/sync-requested-at` basılır; VSO
  annotation değişikliğinde reconcile edip Vault'u yeniden okur (kaynak kodda doğrulandı).

Her iki durumda da hedef Secret'taki `secretKey`, Vault'taki yeni parolaya eşit olana kadar
beklenir; sonra restart. `secretSync.timeout` içinde olmazsa ya da kaynak yoksa rotation
tamamlanır, `Degraded` olur ve **restart yapılmaz** (eski parolayla açılmasınlar diye).
Kaynaklar `unstructured` olarak ele alınır; ESO/VSO Go modüllerine bağımlılık yoktur.

## 7. Zamanlama mantığı

- `cron`: bir sonraki cron anı hesaplanır; o an geldiğinde "due" olur.
- `every: Nd`: `lastRotationTime + N gün` sonrası "due" olur (ilk kurulumda hemen due).
- Due ama pencere dışındaysa → bir sonraki pencere başlangıcına `RequeueAfter`.
- Controller `RequeueAfter` ile uyur; ayrı bir scheduler goroutine'i yok.
- Aynı DB host'unda eşzamanlı rotation sayısı sınırlanır (varsayılan 1).

## 8. Güvenlik ve RBAC

- Operatör sadece kendi namespace'inde `Role` ile: CRD'ler, Secrets (sadece get),
  Deployments/StatefulSets/DaemonSets (get/list/patch), Events, Leases (leader election).
- Cache `DefaultNamespaces` ile tek namespace'e kısıtlanır (`WATCH_NAMESPACE`).
- Vault policy örneği dokümante edilir: master path'e `read`, target path'e `read`+`create`+`update`,
  pending path'e `read`+`create`+`update` ve metadata'sına `delete`.
- Finalizer: rotation sürerken CR silinirse önce rotation tamamlanır/geri alınır.
- DB bağlantısında TLS varsayılan olarak `require`.
- Parolalar loglara, Event'lere, status'a asla yazılmaz; `String()` redaction'lı tip kullanılır.
- DB bağlantılarında TLS desteği.

## 9. Gözlemlenebilirlik

- Prometheus metrikleri (controller-runtime `/metrics`, HTTPS + token):
  `krotos_rotations_total{namespace,name,engine,result}`, `krotos_rotation_duration_seconds{engine}`,
  `krotos_last_success_timestamp_seconds`, `krotos_next_rotation_timestamp_seconds`,
  `krotos_rotation_degraded`, `krotos_rotation_consecutive_failures`, `krotos_vault_connection_ready`.
  Silinen CR'ların serileri temizlenir. Önerilen alarmlar README'de.
- Her adımda k8s Event.
- `kubectl get dcr` çıktısında: ENGINE, USER, PHASE, LAST ROTATION, NEXT, AGE kolonları.

## 10. Proje yapısı

```
api/v1alpha1/              CRD tipleri + validation (CEL: cron XOR every, auth tek seçenek vb.)
internal/controller/       VaultConnection & DatabaseCredentialRotation reconciler'ları
internal/rotation/         state machine
internal/engine/           Engine interface + postgres/, mysql/, clickhouse/
internal/vault/            client, auth (k8s/token), KV v1/v2 read/write
internal/schedule/         cron/every + window hesaplama (saf fonksiyonlar, bol unit test)
internal/restart/          workload restart + rollout bekleme
internal/password/         üretici
dist/chart/                Helm chart (kubebuilder helm/v2-alpha plugin ile üretilir)
config/                    kubebuilder manifestleri
```

```go
type Engine interface {
    Ping(ctx context.Context, c Conn) error
    SetPassword(ctx context.Context, master Conn, user, newPassword string) error
    VerifyLogin(ctx context.Context, c Conn, user, password string) error
}
```

## 11. Aşamalar

| # | Kapsam |
|---|---|
| M1 ✅ | kubebuilder iskeleti, CRD'ler, CEL validation, namespaced manager |
| M2 ✅ | `internal/schedule` (cron/every/window) + unit testler |
| M3 ✅ | Vault client (k8s + token auth, KV v1/v2), `VaultConnection` controller |
| M4 ✅ | PostgreSQL engine + state machine + Vault pending + rollback + finalizer |
| M5 ✅ | Workload restart + rollout bekleme |
| M6 ✅ | MySQL/MariaDB ve ClickHouse engine'leri |
| M7 ✅ | Metrikler, Event'ler, Helm chart, e2e (kind + testcontainers) |
| M8 ✅ | ESO/VSO sync adımı (`secretSync`) |
| M9 ✅ | Redis/Valkey: ACL kullanıcı parolası rotation'ı (`ACL SETUSER resetpass #sha256`, persistence `Auto`/`ACLFile`/`ConfigRewrite`/`None`, replica'lar için `nodes`); her engine için least-privilege template'leri (`docs/least-privilege/`) |
| M10 ✅ | NATS: JWT/NKey (operator) modunda kullanıcı `.creds` rotation'ı. Sunucuda değişiklik yok: account signing key (tercihen scoped) ile aynı claim'lerle yeni user JWT + NKey üretilir; eski creds `credentialsTTL` dolunca geçersizleşir (TTL ≥ 2 × en uzun rotation aralığı, controller kontrol eder). Süresi dolmuş mevcut creds rotation'ı durdurmaz (`CredentialsExpired` uyarısı). `engine.Issuer`/`engine.Expirer`, `status.credentialsExpireTime`, `secretSync.*.secretKey` varsayılanı artık `target.vault.passwordKey` |
| M12 | NATS revocation (opsiyonel): eski kullanıcıyı account JWT'de hemen revoke et (operator signing key + system account gerekir) |
| M11 | Redis Cluster |

### Secret source yol haritası

Bir kaynak, CI'da gerçek bir sunucuya ya da güvenilir bir emülatöre karşı test edilebildiğinde desteklenir sayılır.

| Sıra | Kaynak | Not |
|---|---|---|
| ✅ | HashiCorp Vault | KV v1/v2, Kubernetes veya token auth |
| S1 | Kasadan bağımsız API | `VaultConnection` yerine provider seçen bir store kaynağı; secret'lara store + key ile referans; her provider CAS/versiyon desteğini ve pending parolaların yerini bildirir |
| S2 | OpenBao | Vault uyumlu API; Docker dev server ile test |
| S3 | AWS Secrets Manager | JSON değer, pending için `AWSPENDING`; IRSA/Pod Identity; LocalStack veya gerçek hesap |
| S4 | Azure Key Vault | JSON değer, CAS yok, silinen ad purge'e kadar kilitli; Workload ID; Lowkey Vault |
| S5 | Google Secret Manager | JSON değer, yazmada CAS yok; Workload Identity Federation; topluluk emülatörü |
| S6 | CyberArk Conjur | CyberArk'ın kendisinin rotate etmediği hesaplar için; Conjur OSS ile test |
| S7 | Sync-and-restart modu | CyberArk CPM / Delinea'nın rotate ettiği hesaplar: parolayı değiştirmeden değişikliği algılayıp restart; iki rotator aynı hesapta çakışır |
| Değerlendirmede | Delinea Secret Server | CI'da test imkânı yok |

## 12. Kararlar

- API group: `krotos.warewave.io/v1alpha1`.
- Secret dağıtım yöntemi CRD'den seçilir (`spec.secretSync`).
- Kesinti kabul, kesintisiz strateji kapsam dışı.
- ClickHouse: sadece SQL-driven access control kullanıcıları desteklenir → README'ye not.
- Vault auth `VaultConnection` CRD'sinde seçilir: `kubernetes` veya `token`.
  KV versiyonu her path referansında `kvVersion` (varsayılan 2).

## 13. Açık sorular

1. Bir rotation CR'ı tek kullanıcı mı rotate etsin? (Şimdilik varsayım: **tek kullanıcı**.)
2. Master parolanın kendisi de rotate edilecek mi (ileride)?
3. Rollout başarısız olursa bildirim (Slack/webhook) isteniyor mu?
