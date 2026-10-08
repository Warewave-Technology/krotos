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

// Engine is a supported database engine.
// +kubebuilder:validation:Enum=postgresql;mysql;clickhouse;redis;nats
type Engine string

const (
	EnginePostgreSQL Engine = "postgresql"
	EngineMySQL      Engine = "mysql"
	EngineClickHouse Engine = "clickhouse"
	// EngineRedis covers Redis 6+ and Valkey (ACL users).
	EngineRedis Engine = "redis"
	// EngineNATS covers NATS users in JWT/NKey (operator) mode; the rotated value is a .creds file.
	EngineNATS Engine = "nats"
)

// DatabaseCredentialRotationSpec defines the desired state of DatabaseCredentialRotation.
// +kubebuilder:validation:XValidation:rule="!has(self.database.clickhouse) || self.engine == 'clickhouse'",message="database.clickhouse is only allowed when engine is clickhouse"
// +kubebuilder:validation:XValidation:rule="!has(self.target.mysqlHost) || self.engine == 'mysql'",message="target.mysqlHost is only allowed when engine is mysql"
// +kubebuilder:validation:XValidation:rule="!has(self.database.redis) || self.engine == 'redis'",message="database.redis is only allowed when engine is redis"
// +kubebuilder:validation:XValidation:rule="has(self.database.nats) == (self.engine == 'nats')",message="database.nats is required when engine is nats, and only allowed then"
type DatabaseCredentialRotationSpec struct {
	// engine of the target database.
	// +required
	Engine Engine `json:"engine"`

	// suspend stops scheduling new rotations. A rotation already in progress is finished.
	// +optional
	Suspend bool `json:"suspend,omitempty"`

	// database describes how to reach the database server.
	// +required
	Database DatabaseEndpoint `json:"database"`

	// masterCredentials are used to change the target user's password.
	// +required
	MasterCredentials MasterCredentials `json:"masterCredentials"`

	// target is the database user whose password is rotated.
	// +required
	Target RotationTarget `json:"target"`

	// passwordPolicy controls generated passwords.
	// +kubebuilder:default={}
	// +optional
	PasswordPolicy PasswordPolicy `json:"passwordPolicy,omitzero"`

	// schedule defines when a rotation becomes due.
	// +required
	Schedule Schedule `json:"schedule"`

	// window is the change window. A due rotation only starts inside the window.
	// +required
	Window MaintenanceWindow `json:"window"`

	// secretSync describes how applications receive the password from Vault, and
	// what has to happen before they are restarted.
	// +kubebuilder:default={type: None}
	// +optional
	SecretSync SecretSync `json:"secretSync,omitzero"`

	// restartTargets are workloads restarted after the new password is in place.
	// +kubebuilder:validation:MaxItems=32
	// +listType=atomic
	// +optional
	RestartTargets []RestartTarget `json:"restartTargets,omitempty"`

	// rolloutTimeout is how long to wait for restarted workloads to become ready.
	// +kubebuilder:default="10m"
	// +optional
	RolloutTimeout metav1.Duration `json:"rolloutTimeout,omitzero"`
}

// DatabaseEndpoint describes a database server.
type DatabaseEndpoint struct {
	// host name or IP address of the database server.
	// +kubebuilder:validation:MinLength=1
	// +required
	Host string `json:"host"`

	// port of the database server.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +required
	Port int32 `json:"port"`

	// database to connect to. Required by PostgreSQL, optional for the others.
	// +optional
	Database string `json:"database,omitempty"`

	// tls configures the connection to the database. Defaults to mode "require";
	// set mode "disable" explicitly for unencrypted connections.
	// +kubebuilder:default={mode: require}
	// +optional
	TLS *DatabaseTLS `json:"tls,omitempty"`

	// clickhouse holds ClickHouse specific settings.
	// +optional
	ClickHouse *ClickHouseSettings `json:"clickhouse,omitempty"`

	// redis holds Redis / Valkey specific settings.
	// +optional
	Redis *RedisSettings `json:"redis,omitempty"`

	// nats holds NATS specific settings. Required when engine is nats.
	// +optional
	NATS *NATSSettings `json:"nats,omitempty"`
}

// NATSSettings configures NATS credentials rotation.
type NATSSettings struct {
	// credentialsTTL is how long issued user credentials stay valid. NATS keeps no
	// users on the server, so expiry is what retires the old credentials. It must be
	// at least twice the longest time between two rotations, so that one failed
	// rotation does not let the credentials in use expire.
	// +required
	CredentialsTTL metav1.Duration `json:"credentialsTTL"`
}

// TLSMode selects how TLS is used towards the database.
// +kubebuilder:validation:Enum=disable;require;verify-ca;verify-full
type TLSMode string

const (
	TLSModeDisable    TLSMode = "disable"
	TLSModeRequire    TLSMode = "require"
	TLSModeVerifyCA   TLSMode = "verify-ca"
	TLSModeVerifyFull TLSMode = "verify-full"
)

// DatabaseTLS configures TLS towards the database.
// +kubebuilder:validation:XValidation:rule="!(self.mode in ['verify-ca', 'verify-full']) || has(self.caSecretRef)",message="caSecretRef is required for verify-ca and verify-full"
type DatabaseTLS struct {
	// mode of TLS usage.
	// +kubebuilder:default=require
	// +optional
	Mode TLSMode `json:"mode,omitempty"`

	// caSecretRef references a PEM encoded CA bundle.
	// +optional
	CASecretRef *SecretKeyReference `json:"caSecretRef,omitempty"`
}

// ClickHouseSettings holds ClickHouse specific settings.
type ClickHouseSettings struct {
	// cluster name. When set, statements are executed with ON CLUSTER.
	// +optional
	Cluster string `json:"cluster,omitempty"`

	// protocol used to connect.
	// +kubebuilder:validation:Enum=native;http
	// +kubebuilder:default=native
	// +optional
	Protocol string `json:"protocol,omitempty"`
}

// RedisPersistence selects how a changed ACL password is made to survive a Redis restart.
// +kubebuilder:validation:Enum=Auto;ACLFile;ConfigRewrite;None
type RedisPersistence string

const (
	// RedisPersistenceAuto uses ACL SAVE when the server has an aclfile and refuses
	// to rotate otherwise.
	RedisPersistenceAuto RedisPersistence = "Auto"
	// RedisPersistenceACLFile runs ACL SAVE.
	RedisPersistenceACLFile RedisPersistence = "ACLFile"
	// RedisPersistenceConfigRewrite runs CONFIG REWRITE, which rewrites the whole
	// config file, including runtime CONFIG SET changes and command-line arguments.
	RedisPersistenceConfigRewrite RedisPersistence = "ConfigRewrite"
	// RedisPersistenceNone keeps the change in memory only; a restarted server
	// comes back with the old password.
	RedisPersistenceNone RedisPersistence = "None"
)

// RedisSettings holds Redis / Valkey specific settings.
type RedisSettings struct {
	// persistence selects how the new password survives a server restart.
	// +kubebuilder:default=Auto
	// +optional
	Persistence RedisPersistence `json:"persistence,omitempty"`

	// nodes are further servers ("host:port") that get the same change, such as
	// replicas: ACL changes are not replicated. The password is changed and
	// verified on database.host and on every node listed here.
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	// +optional
	Nodes []string `json:"nodes,omitempty"`
}

// MasterCredentials locates the privileged credentials. Exactly one source must be set.
// +kubebuilder:validation:XValidation:rule="(has(self.vault) ? 1 : 0) + (has(self.secretRef) ? 1 : 0) == 1",message="exactly one of vault or secretRef must be set"
type MasterCredentials struct {
	// vault reads the master credentials from Vault.
	// +optional
	Vault *VaultCredentialsReference `json:"vault,omitempty"`

	// secretRef reads the master credentials from a Secret.
	// +optional
	SecretRef *SecretCredentialsReference `json:"secretRef,omitempty"`
}

// VaultCredentialsReference locates a username/password pair in Vault.
type VaultCredentialsReference struct {
	VaultSecretReference `json:",inline"`

	// usernameKey is the key holding the username.
	// +kubebuilder:default=username
	// +optional
	UsernameKey string `json:"usernameKey,omitempty"`

	// passwordKey is the key holding the password.
	// +kubebuilder:default=password
	// +optional
	PasswordKey string `json:"passwordKey,omitempty"`
}

// SecretCredentialsReference locates a username/password pair in a Secret.
type SecretCredentialsReference struct {
	// name of the Secret.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`

	// usernameKey is the key holding the username.
	// +kubebuilder:default=username
	// +optional
	UsernameKey string `json:"usernameKey,omitempty"`

	// passwordKey is the key holding the password.
	// +kubebuilder:default=password
	// +optional
	PasswordKey string `json:"passwordKey,omitempty"`
}

// RotationTarget is the user whose password is rotated.
type RotationTarget struct {
	// username of the database user.
	// +kubebuilder:validation:MinLength=1
	// +required
	Username string `json:"username"`

	// mysqlHost is the host part of the MySQL account ('user'@'host'). Defaults to "%".
	// +optional
	MySQLHost *string `json:"mysqlHost,omitempty"`

	// vault is where the password is read from and written back to. The
	// VaultConnection used here needs write access to the path.
	// +required
	Vault VaultTargetReference `json:"vault"`
}

// VaultTargetReference locates the rotated password in Vault.
type VaultTargetReference struct {
	VaultSecretReference `json:",inline"`

	// passwordKey is the key the password is written to.
	// +kubebuilder:default=password
	// +optional
	PasswordKey string `json:"passwordKey,omitempty"`

	// usernameKey, when set, is kept up to date with the username as well.
	// +optional
	UsernameKey string `json:"usernameKey,omitempty"`

	// pendingPath is where the in-flight rotation's old and new passwords are kept
	// (same mount and KV version as the target) until it finishes, so a restarted
	// operator can resume or roll back. All versions are destroyed afterwards.
	// Defaults to "krotos/pending/<namespace>/<name>".
	// +kubebuilder:validation:MinLength=1
	// +optional
	PendingPath string `json:"pendingPath,omitempty"`
}

// DefaultExcludeCharacters are characters that commonly break connection strings,
// shell snippets or SQL quoting.
const DefaultExcludeCharacters = "'\"\\`$@:/?#%&"

// PasswordPolicy controls generated passwords.
type PasswordPolicy struct {
	// length of the generated password.
	// +kubebuilder:validation:Minimum=16
	// +kubebuilder:validation:Maximum=128
	// +kubebuilder:default=32
	// +optional
	Length int32 `json:"length,omitempty"`

	// excludeCharacters are never used in generated passwords. When empty,
	// DefaultExcludeCharacters is used.
	// +optional
	ExcludeCharacters string `json:"excludeCharacters,omitempty"`
}

// Schedule defines when a rotation becomes due. Exactly one of cron or every must be set.
// +kubebuilder:validation:XValidation:rule="(has(self.cron) ? 1 : 0) + (has(self.every) ? 1 : 0) == 1",message="exactly one of cron or every must be set"
type Schedule struct {
	// cron expression (5 fields) evaluated in the window's time zone.
	// +kubebuilder:validation:MinLength=1
	// +optional
	Cron string `json:"cron,omitempty"`

	// every is the interval between successful rotations, in days ("30d") or hours ("12h").
	// +kubebuilder:validation:Pattern=`^[1-9][0-9]*(d|h)$`
	// +optional
	Every string `json:"every,omitempty"`
}

// Weekday is a day of the week.
// +kubebuilder:validation:Enum=Mon;Tue;Wed;Thu;Fri;Sat;Sun
type Weekday string

// MaintenanceWindow is a recurring change window.
// +kubebuilder:validation:XValidation:rule="duration(self.duration) > duration('0s') && duration(self.duration) <= duration('24h')",message="duration must be greater than 0 and at most 24h"
// +kubebuilder:validation:XValidation:rule="!has(self.minRemaining) || (duration(self.minRemaining) >= duration('0s') && duration(self.minRemaining) < duration(self.duration))",message="minRemaining must be at least 0 and shorter than duration"
type MaintenanceWindow struct {
	// timezone is an IANA time zone name, e.g. "Europe/Istanbul".
	// +kubebuilder:default=UTC
	// +optional
	Timezone string `json:"timezone,omitempty"`

	// days the window opens on. Empty means every day.
	// +kubebuilder:validation:MaxItems=7
	// +listType=set
	// +optional
	Days []Weekday `json:"days,omitempty"`

	// start is the local opening time in HH:MM format.
	// +kubebuilder:validation:Pattern=`^([01][0-9]|2[0-3]):[0-5][0-9]$`
	// +required
	Start string `json:"start"`

	// duration of the window, at most 24h.
	// +required
	Duration metav1.Duration `json:"duration"`

	// minRemaining is the minimum time left in the window for a rotation to start.
	// A rotation that already started is always finished, even after the window closes.
	// +kubebuilder:default="15m"
	// +optional
	MinRemaining metav1.Duration `json:"minRemaining,omitzero"`
}

// SecretSyncType is how applications receive the password.
// +kubebuilder:validation:Enum=None;ExternalSecret;VaultStaticSecret
type SecretSyncType string

const (
	// SecretSyncNone means applications read Vault directly (Vault Agent, CSI).
	SecretSyncNone SecretSyncType = "None"
	// SecretSyncExternalSecret means an External Secrets Operator ExternalSecret syncs the password.
	SecretSyncExternalSecret SecretSyncType = "ExternalSecret"
	// SecretSyncVaultStaticSecret means a Vault Secrets Operator VaultStaticSecret syncs the password.
	SecretSyncVaultStaticSecret SecretSyncType = "VaultStaticSecret"
)

// SecretSync describes how the password reaches applications.
// +kubebuilder:validation:XValidation:rule="self.type != 'ExternalSecret' || has(self.externalSecret)",message="externalSecret is required when type is ExternalSecret"
// +kubebuilder:validation:XValidation:rule="self.type != 'VaultStaticSecret' || has(self.vaultStaticSecret)",message="vaultStaticSecret is required when type is VaultStaticSecret"
// +kubebuilder:validation:XValidation:rule="self.type == 'ExternalSecret' || !has(self.externalSecret)",message="externalSecret is only allowed when type is ExternalSecret"
// +kubebuilder:validation:XValidation:rule="self.type == 'VaultStaticSecret' || !has(self.vaultStaticSecret)",message="vaultStaticSecret is only allowed when type is VaultStaticSecret"
type SecretSync struct {
	// type of the sync mechanism.
	// +kubebuilder:default=None
	// +optional
	Type SecretSyncType `json:"type,omitempty"`

	// externalSecret is the ExternalSecret to force-sync.
	// +optional
	ExternalSecret *SyncedSecretReference `json:"externalSecret,omitempty"`

	// vaultStaticSecret is the VaultStaticSecret to refresh.
	// +optional
	VaultStaticSecret *SyncedSecretReference `json:"vaultStaticSecret,omitempty"`

	// timeout for the synced Secret to contain the new password.
	// +kubebuilder:default="5m"
	// +optional
	Timeout metav1.Duration `json:"timeout,omitzero"`
}

// SyncedSecretReference names a sync resource and the Secret it produces.
type SyncedSecretReference struct {
	// name of the ExternalSecret / VaultStaticSecret.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`

	// secretName is the Secret produced by the sync resource.
	// +kubebuilder:validation:MinLength=1
	// +required
	SecretName string `json:"secretName"`

	// secretKey is the key in secretName that holds the password. Defaults to
	// target.vault.passwordKey, the key the sync operators copy from Vault.
	// +optional
	SecretKey string `json:"secretKey,omitempty"`
}

// RestartTarget selects workloads to restart. Exactly one of name or selector must be set.
// +kubebuilder:validation:XValidation:rule="(has(self.name) ? 1 : 0) + (has(self.selector) ? 1 : 0) == 1",message="exactly one of name or selector must be set"
type RestartTarget struct {
	// kind of the workload.
	// +kubebuilder:validation:Enum=Deployment;StatefulSet;DaemonSet
	// +required
	Kind string `json:"kind"`

	// name of a single workload.
	// +optional
	Name string `json:"name,omitempty"`

	// selector matches workloads by label.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// RotationPhase is the coarse state of a rotation.
// +kubebuilder:validation:Enum=Idle;Waiting;Rotating;Restarting;Failed
type RotationPhase string

const (
	PhaseIdle       RotationPhase = "Idle"
	PhaseWaiting    RotationPhase = "Waiting"
	PhaseRotating   RotationPhase = "Rotating"
	PhaseRestarting RotationPhase = "Restarting"
	PhaseFailed     RotationPhase = "Failed"
)

// RotationStep is the last completed step of an in-flight rotation.
// +kubebuilder:validation:Enum="";PendingSaved;DbUpdated;Verified;VaultWritten;SecretSynced;RollingBack
type RotationStep string

const (
	StepNone         RotationStep = ""
	StepPendingSaved RotationStep = "PendingSaved"
	StepDbUpdated    RotationStep = "DbUpdated"
	StepVerified     RotationStep = "Verified"
	StepVaultWritten RotationStep = "VaultWritten"
	// StepSecretSynced means applications can read the new password; workloads
	// are being restarted.
	StepSecretSynced RotationStep = "SecretSynced"
	// StepRollingBack means the old password is being restored in the database.
	StepRollingBack RotationStep = "RollingBack"
)

// Finalizers.
const (
	// FinalizerRotation keeps a rotation from being deleted while it is in progress.
	FinalizerRotation = "krotos.warewave.io/rotation"
)

// Condition types.
const (
	ConditionReady    = "Ready"
	ConditionRotated  = "Rotated"
	ConditionDegraded = "Degraded"
)

// Annotations understood by the operator.
const (
	AnnotationRotateNow    = "krotos.warewave.io/rotate-now"
	AnnotationIgnoreWindow = "krotos.warewave.io/ignore-window"
	AnnotationRestartedAt  = "krotos.warewave.io/restartedAt"
)

// DatabaseCredentialRotationStatus defines the observed state of DatabaseCredentialRotation.
type DatabaseCredentialRotationStatus struct {
	// observedGeneration is the last spec generation that was reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// phase is the coarse state of the rotation.
	// +optional
	Phase RotationPhase `json:"phase,omitempty"`

	// step is the last completed step of the in-flight rotation. Empty when idle.
	// +optional
	Step RotationStep `json:"step,omitempty"`

	// lastRotationTime is when the last rotation completed successfully.
	// +optional
	LastRotationTime *metav1.Time `json:"lastRotationTime,omitempty"`

	// secretSyncStartTime is when the in-flight rotation asked the sync operator
	// (ExternalSecret / VaultStaticSecret) to copy the new password.
	// +optional
	SecretSyncStartTime *metav1.Time `json:"secretSyncStartTime,omitempty"`

	// rolloutStartTime is when the workload restarts of the in-flight rotation began.
	// +optional
	RolloutStartTime *metav1.Time `json:"rolloutStartTime,omitempty"`

	// lastAttemptTime is when the last rotation started.
	// +optional
	LastAttemptTime *metav1.Time `json:"lastAttemptTime,omitempty"`

	// nextScheduledTime is when the next rotation becomes due.
	// +optional
	NextScheduledTime *metav1.Time `json:"nextScheduledTime,omitempty"`

	// nextWindowStart is when the next change window opens.
	// +optional
	NextWindowStart *metav1.Time `json:"nextWindowStart,omitempty"`

	// credentialsExpireTime is when the credentials issued by the last rotation
	// expire. Only set for engines whose credentials expire (nats).
	// +optional
	CredentialsExpireTime *metav1.Time `json:"credentialsExpireTime,omitempty"`

	// retries counts failed attempts of the current step.
	// +optional
	Retries int32 `json:"retries,omitempty"`

	// consecutiveFailures counts failed attempts since the last success.
	// +optional
	ConsecutiveFailures int32 `json:"consecutiveFailures,omitempty"`

	// message is a human readable description of the current state. Never contains secrets.
	// +optional
	Message string `json:"message,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=dcr
// +kubebuilder:printcolumn:name="Engine",type=string,JSONPath=`.spec.engine`
// +kubebuilder:printcolumn:name="User",type=string,JSONPath=`.spec.target.username`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Last Rotation",type=date,JSONPath=`.status.lastRotationTime`
// +kubebuilder:printcolumn:name="Next",type=string,JSONPath=`.status.nextScheduledTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// DatabaseCredentialRotation periodically rotates a database user's password
// stored in Vault and restarts the workloads using it.
type DatabaseCredentialRotation struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec DatabaseCredentialRotationSpec `json:"spec"`

	// +optional
	Status DatabaseCredentialRotationStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// DatabaseCredentialRotationList contains a list of DatabaseCredentialRotation
type DatabaseCredentialRotationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []DatabaseCredentialRotation `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &DatabaseCredentialRotation{}, &DatabaseCredentialRotationList{})
		return nil
	})
}
