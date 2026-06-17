use crate::error::{StorageError, StorageResult};
use crate::ids::ComponentRecordId;
use crate::migration::{
    InMemoryMigrationAuditSink, Migration, MigrationRunReport, MigrationRunner, SchemaMetadata,
};
use crate::privacy_service::PrivacyEngine;
use crate::session::{SessionConfig, SessionDatabaseMode, SessionLifecycle, SessionMode};
use crate::settings::SettingsConfigRepository;
use crate::store::{
    logical_store_migration, GraphStore, LogicalRecord, LogicalStore, SqliteStoreFactory, StoreKind,
};
use rusqlite::{params, Connection, OptionalExtension};
use sentinel_contracts::{
    AuditId, CanonicalGraphEdge, CanonicalGraphNode, EntityId, EntityRef, EntityType, EvidenceId,
    GraphEdgeType, GraphNodeType, PluginId, PrivacyClass, QualityScore, RedactedLabel,
    RedactionStatus, RuntimeProfile, SchemaVersion, Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use uuid::Uuid;

const DATABASE_DIR_NAME: &str = "SentinelGuard";
const DATABASE_FILE_NAME: &str = "sentinel_guard.db";
const DB_PATH_ENV: &str = "SENTINEL_DB_PATH";
const DEMO_DB_PATH_ENV: &str = "SENTINEL_DEMO_DB_PATH";
const DEFAULT_BUSY_TIMEOUT_MS: u64 = 5_000;
const STORAGE_WRITER_LOCK_FILE_NAME: &str = ".sentinel_storage_writer.lock";

const FORBIDDEN_SCHEMA_TOKENS: &[&str] = &[
    "raw_packet",
    "raw_packets",
    "raw_payload",
    "payload_blob",
    "http_body",
    "request_body",
    "response_body",
    "cookie",
    "cookies",
    "authorization",
    "api_key",
    "password",
    "credential",
    "private_key",
    "session_token",
    "access_token",
    "refresh_token",
    "full_query_string",
    "form_content",
];

const SERVICEHOST_DURABLE_ALLOWED_FIELDS: &[&str] = &[
    "ids_refs",
    "categories",
    "buckets",
    "schema_versions",
    "bounded_counters",
    "lifecycle_health",
    "degraded_reasons",
    "provenance_audit_refs",
    "redaction_status",
    "ownership_epoch_metadata",
];

const FORBIDDEN_DURABLE_STATE_MARKERS: &[&str] = &[
    "raw_log",
    "raw_logs",
    "raw_file",
    "raw_files",
    "path",
    "filename",
    "process_name",
    "service_name",
    "pid",
    "ppid",
    "command_line",
    "ip",
    "port",
    "packet",
    "payload",
    "raw_provider",
    "nonce",
    "caller_token",
    "credential",
    "api_key",
    "secret",
    "private_marker",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseMode {
    Normal,
    Demo,
}

impl DatabaseMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Demo => "demo",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DatabaseLocation {
    File(PathBuf),
    InMemory,
}

impl DatabaseLocation {
    pub fn is_in_memory(&self) -> bool {
        matches!(self, Self::InMemory)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageWriterOwnerCategory {
    ServiceHost,
    DesktopPortable,
    TestHarness,
}

impl StorageWriterOwnerCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ServiceHost => "service_host",
            Self::DesktopPortable => "desktop_portable",
            Self::TestHarness => "test_harness",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageWriterState {
    Owned,
    Conflict,
    Released,
}

impl StorageWriterState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owned => "owned",
            Self::Conflict => "conflict",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageOwnershipStatus {
    pub owner_category: StorageWriterOwnerCategory,
    pub writer_state: StorageWriterState,
    pub storage_scope: String,
    pub canonical_writer: bool,
    pub path_exposed: bool,
    pub llm_key_transferred: bool,
    pub degraded_reason: Option<String>,
}

impl StorageOwnershipStatus {
    pub fn owner_category_str(&self) -> &'static str {
        self.owner_category.as_str()
    }

    pub fn writer_state_str(&self) -> &'static str {
        self.writer_state.as_str()
    }

    pub fn redacted_for_conflict(
        owner_category: StorageWriterOwnerCategory,
        storage_scope: impl Into<String>,
    ) -> Self {
        Self {
            owner_category,
            writer_state: StorageWriterState::Conflict,
            storage_scope: storage_scope.into(),
            canonical_writer: false,
            path_exposed: false,
            llm_key_transferred: false,
            degraded_reason: Some("writer_already_owned".to_string()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePersistenceClassification {
    RequiredRuntimeState,
    BoundedTraceability,
    BoundedConfiguration,
    SessionOnly,
    NotPersisted,
    Forbidden,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceHostDurableStatePolicy {
    pub state_name: String,
    pub owner_category: StorageWriterOwnerCategory,
    pub classification: StoragePersistenceClassification,
    pub allowed_fields: Vec<String>,
    pub restored_on_restart: bool,
    pub servicehost_canonical: bool,
    pub redaction_status: RedactionStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitOwnedStatePolicy {
    pub state_name: String,
    pub owner_category: String,
    pub classification: StoragePersistenceClassification,
    pub transferred_to_servicehost: bool,
    pub persisted_by_servicehost: bool,
    pub redaction_status: RedactionStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceHostDurableStorageManifest {
    pub owner_category: StorageWriterOwnerCategory,
    pub canonical_writer_required: bool,
    pub desktop_writer_allowed: bool,
    pub cross_process_sqlite_connection_allowed: bool,
    pub schema_version: SchemaVersion,
    pub durable_state: Vec<ServiceHostDurableStatePolicy>,
    pub split_owned_state: Vec<SplitOwnedStatePolicy>,
    pub forbidden_markers_rejected: Vec<String>,
    pub redaction_status: RedactionStatus,
}

impl ServiceHostDurableStorageManifest {
    pub fn validate(&self) -> StorageResult<()> {
        if self.owner_category != StorageWriterOwnerCategory::ServiceHost
            || !self.canonical_writer_required
            || self.desktop_writer_allowed
            || self.cross_process_sqlite_connection_allowed
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(StorageError::InvalidRecord {
                store_kind: "servicehost_durable_storage_manifest".to_string(),
                reason: "manifest ownership boundary is unsafe".to_string(),
            });
        }
        for policy in &self.durable_state {
            validate_durable_safe_text("state_name", &policy.state_name)?;
            if policy.owner_category != StorageWriterOwnerCategory::ServiceHost
                || policy.classification == StoragePersistenceClassification::Forbidden
                || policy.allowed_fields.is_empty()
                || policy.redaction_status == RedactionStatus::RedactionRequired
            {
                return Err(StorageError::InvalidRecord {
                    store_kind: policy.state_name.clone(),
                    reason: "durable state policy is unsafe".to_string(),
                });
            }
            for field in &policy.allowed_fields {
                validate_durable_safe_text("allowed_field", field)?;
            }
        }
        for policy in &self.split_owned_state {
            validate_durable_safe_text("split_state_name", &policy.state_name)?;
            validate_durable_safe_text("split_owner_category", &policy.owner_category)?;
            if policy.transferred_to_servicehost
                || policy.persisted_by_servicehost
                || policy.redaction_status == RedactionStatus::RedactionRequired
            {
                return Err(StorageError::InvalidRecord {
                    store_kind: policy.state_name.clone(),
                    reason: "split-owned state crossed the ServiceHost boundary".to_string(),
                });
            }
        }
        for marker in &self.forbidden_markers_rejected {
            validate_durable_marker_text("forbidden_marker", marker)?;
        }
        Ok(())
    }

    pub fn policy(&self, state_name: &str) -> Option<&ServiceHostDurableStatePolicy> {
        self.durable_state
            .iter()
            .find(|policy| policy.state_name == state_name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceHostStorageRecoveryReport {
    pub owner_category: StorageWriterOwnerCategory,
    pub writer_state: StorageWriterState,
    pub schema_validated: bool,
    pub ownership_validated: bool,
    pub allowed_state_restored_count: usize,
    pub new_ownership_epoch_established: bool,
    pub canonical_snapshots_rebuilt: bool,
    pub scheduler_activated: bool,
    pub sampler_activated: bool,
    pub provider_executed: bool,
    pub stale_findings_replayed: bool,
    pub llm_invoked: bool,
    pub cross_process_sqlite_connection_shared: bool,
    pub storage_path_exposed: bool,
    pub degraded: bool,
    pub degraded_reason: Option<String>,
    pub redaction_status: RedactionStatus,
}

impl ServiceHostStorageRecoveryReport {
    pub fn from_status(
        status: &StorageOwnershipStatus,
        manifest: &ServiceHostDurableStorageManifest,
        ownership_epoch: u64,
        schema_validated: bool,
        degraded_reason: Option<String>,
    ) -> Self {
        let ownership_validated = status.owner_category == StorageWriterOwnerCategory::ServiceHost
            && status.writer_state == StorageWriterState::Owned
            && status.canonical_writer
            && !status.path_exposed
            && !status.llm_key_transferred
            && manifest.validate().is_ok();
        let degraded =
            !ownership_validated || !schema_validated || degraded_reason.as_ref().is_some();
        Self {
            owner_category: status.owner_category,
            writer_state: status.writer_state,
            schema_validated,
            ownership_validated,
            allowed_state_restored_count: if ownership_validated && schema_validated {
                manifest
                    .durable_state
                    .iter()
                    .filter(|policy| policy.restored_on_restart)
                    .count()
            } else {
                0
            },
            new_ownership_epoch_established: ownership_epoch > 0 && ownership_validated,
            canonical_snapshots_rebuilt: ownership_epoch > 0
                && ownership_validated
                && schema_validated,
            scheduler_activated: false,
            sampler_activated: false,
            provider_executed: false,
            stale_findings_replayed: false,
            llm_invoked: false,
            cross_process_sqlite_connection_shared: false,
            storage_path_exposed: false,
            degraded,
            degraded_reason,
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn degraded(reason: impl Into<String>) -> Self {
        Self {
            owner_category: StorageWriterOwnerCategory::ServiceHost,
            writer_state: StorageWriterState::Conflict,
            schema_validated: false,
            ownership_validated: false,
            allowed_state_restored_count: 0,
            new_ownership_epoch_established: false,
            canonical_snapshots_rebuilt: false,
            scheduler_activated: false,
            sampler_activated: false,
            provider_executed: false,
            stale_findings_replayed: false,
            llm_invoked: false,
            cross_process_sqlite_connection_shared: false,
            storage_path_exposed: false,
            degraded: true,
            degraded_reason: Some(reason.into()),
            redaction_status: RedactionStatus::Redacted,
        }
    }
}

pub fn service_host_durable_storage_manifest() -> ServiceHostDurableStorageManifest {
    let durable_state = vec![
        state_policy(
            "runtime_session_state",
            StoragePersistenceClassification::RequiredRuntimeState,
            true,
            true,
            SERVICEHOST_DURABLE_ALLOWED_FIELDS,
        ),
        state_policy(
            "scheduler_state",
            StoragePersistenceClassification::BoundedConfiguration,
            true,
            true,
            &[
                "ids_refs",
                "schema_versions",
                "lifecycle_health",
                "degraded_reasons",
                "ownership_epoch_metadata",
                "safe_scheduler_settings",
            ],
        ),
        state_policy(
            "sampler_state",
            StoragePersistenceClassification::RequiredRuntimeState,
            true,
            true,
            SERVICEHOST_DURABLE_ALLOWED_FIELDS,
        ),
        state_policy(
            "permission_readiness_state",
            StoragePersistenceClassification::BoundedConfiguration,
            true,
            true,
            SERVICEHOST_DURABLE_ALLOWED_FIELDS,
        ),
        state_policy(
            "baseline_state",
            StoragePersistenceClassification::BoundedTraceability,
            true,
            true,
            SERVICEHOST_DURABLE_ALLOWED_FIELDS,
        ),
        state_policy(
            "incident_linked_state",
            StoragePersistenceClassification::BoundedTraceability,
            true,
            true,
            SERVICEHOST_DURABLE_ALLOWED_FIELDS,
        ),
        state_policy(
            "canonical_read_model_snapshots",
            StoragePersistenceClassification::BoundedTraceability,
            true,
            true,
            SERVICEHOST_DURABLE_ALLOWED_FIELDS,
        ),
        state_policy(
            "report_traceability",
            StoragePersistenceClassification::BoundedTraceability,
            true,
            true,
            SERVICEHOST_DURABLE_ALLOWED_FIELDS,
        ),
        state_policy(
            "export_traceability_history_metadata",
            StoragePersistenceClassification::BoundedTraceability,
            true,
            true,
            SERVICEHOST_DURABLE_ALLOWED_FIELDS,
        ),
        state_policy(
            "portable_reader_cursor_state",
            StoragePersistenceClassification::RequiredRuntimeState,
            true,
            true,
            &[
                "ids_refs",
                "categories",
                "schema_versions",
                "bounded_counters",
                "lifecycle_health",
                "degraded_reasons",
                "provenance_audit_refs",
                "redaction_status",
                "ownership_epoch_metadata",
                "opaque_cursor",
            ],
        ),
    ];
    let split_owned_state = vec![
        split_policy("tauri_window_state", "desktop"),
        split_policy("ui_preferences", "desktop"),
        split_policy("export_destination_picker", "desktop"),
        split_policy("connection_state", "desktop"),
        split_policy("temporary_llm_key", "desktop_memory_only_write_only"),
    ];
    ServiceHostDurableStorageManifest {
        owner_category: StorageWriterOwnerCategory::ServiceHost,
        canonical_writer_required: true,
        desktop_writer_allowed: false,
        cross_process_sqlite_connection_allowed: false,
        schema_version: SchemaVersion::new(1, 0, 0),
        durable_state,
        split_owned_state,
        forbidden_markers_rejected: FORBIDDEN_DURABLE_STATE_MARKERS
            .iter()
            .map(|marker| marker.to_string())
            .collect(),
        redaction_status: RedactionStatus::Redacted,
    }
}

pub fn service_host_storage_recovery_probe(
    config: DatabaseConfig,
    ownership_epoch: u64,
) -> ServiceHostStorageRecoveryReport {
    if config.writer_owner != StorageWriterOwnerCategory::ServiceHost {
        return ServiceHostStorageRecoveryReport::degraded("service_host_writer_required");
    }
    let manifest = service_host_durable_storage_manifest();
    match DatabaseRuntime::bootstrap(config) {
        Ok(runtime) => {
            let health = runtime.health_check();
            let report = match health {
                Ok(health) => ServiceHostStorageRecoveryReport::from_status(
                    &runtime.storage_ownership_status(),
                    &manifest,
                    ownership_epoch,
                    !health.degraded,
                    if health.degraded {
                        Some("schema_or_store_health_degraded".to_string())
                    } else {
                        None
                    },
                ),
                Err(_) => ServiceHostStorageRecoveryReport::from_status(
                    &runtime.storage_ownership_status(),
                    &manifest,
                    ownership_epoch,
                    false,
                    Some("schema_validation_failed".to_string()),
                ),
            };
            drop(runtime);
            report
        }
        Err(_) => ServiceHostStorageRecoveryReport::degraded("storage_open_or_migration_failed"),
    }
}

fn state_policy(
    state_name: &str,
    classification: StoragePersistenceClassification,
    restored_on_restart: bool,
    servicehost_canonical: bool,
    allowed_fields: &[&str],
) -> ServiceHostDurableStatePolicy {
    ServiceHostDurableStatePolicy {
        state_name: state_name.to_string(),
        owner_category: StorageWriterOwnerCategory::ServiceHost,
        classification,
        allowed_fields: allowed_fields
            .iter()
            .map(|field| field.to_string())
            .collect(),
        restored_on_restart,
        servicehost_canonical,
        redaction_status: RedactionStatus::Redacted,
    }
}

fn split_policy(state_name: &str, owner_category: &str) -> SplitOwnedStatePolicy {
    SplitOwnedStatePolicy {
        state_name: state_name.to_string(),
        owner_category: owner_category.to_string(),
        classification: StoragePersistenceClassification::NotPersisted,
        transferred_to_servicehost: false,
        persisted_by_servicehost: false,
        redaction_status: RedactionStatus::Redacted,
    }
}

fn validate_durable_safe_text(field: &'static str, value: &str) -> StorageResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 96 {
        return Err(StorageError::InvalidRecord {
            store_kind: "servicehost_durable_storage_manifest".to_string(),
            reason: format!("{field} is empty or unbounded"),
        });
    }
    let normalized = trimmed.to_ascii_lowercase();
    for marker in FORBIDDEN_DURABLE_STATE_MARKERS {
        if normalized == *marker || normalized.contains(&format!("{marker}_raw")) {
            return Err(StorageError::InvalidRecord {
                store_kind: "servicehost_durable_storage_manifest".to_string(),
                reason: format!("{field} contains forbidden durable marker"),
            });
        }
    }
    Ok(())
}

fn validate_durable_marker_text(field: &'static str, value: &str) -> StorageResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 96 {
        return Err(StorageError::InvalidRecord {
            store_kind: "servicehost_durable_storage_manifest".to_string(),
            reason: format!("{field} is empty or unbounded"),
        });
    }
    Ok(())
}

#[derive(Debug)]
struct StorageWriterLeaseInner {
    key: String,
    lock_path: Option<PathBuf>,
    status: StorageOwnershipStatus,
    released: Mutex<bool>,
}

#[derive(Clone, Debug)]
pub struct StorageWriterLease {
    inner: Arc<StorageWriterLeaseInner>,
}

impl StorageWriterLease {
    pub fn acquire_service_host_runtime(ownership_epoch: u64) -> StorageResult<Self> {
        Self::acquire(
            StorageWriterOwnerCategory::ServiceHost,
            format!("service_host_runtime_epoch_{ownership_epoch}"),
            None,
            "service_owned_runtime_stores",
            true,
        )
    }

    pub fn acquire_for_database(config: &DatabaseConfig) -> StorageResult<Self> {
        let (key, lock_path, scope) = match &config.location {
            DatabaseLocation::InMemory => (
                format!("in_memory_{}", Uuid::new_v4()),
                None,
                "in_memory_session_store".to_string(),
            ),
            DatabaseLocation::File(path) => {
                let key = format!("file_{}", stable_checksum(&path.to_string_lossy()));
                let lock_path = path
                    .parent()
                    .map(|parent| parent.join(STORAGE_WRITER_LOCK_FILE_NAME));
                (key, lock_path, "sqlite_session_store".to_string())
            }
        };
        Self::acquire(config.writer_owner, key, lock_path, scope, true)
    }

    pub fn acquire_for_test_scope(
        owner_category: StorageWriterOwnerCategory,
        scope: impl Into<String>,
    ) -> StorageResult<Self> {
        let scope = scope.into();
        Self::acquire(
            owner_category,
            format!("test_scope_{scope}"),
            None,
            scope,
            true,
        )
    }

    fn acquire(
        owner_category: StorageWriterOwnerCategory,
        key: String,
        lock_path: Option<PathBuf>,
        storage_scope: impl Into<String>,
        canonical_writer: bool,
    ) -> StorageResult<Self> {
        if let Some(path) = &lock_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut file) => {
                    file.write_all(
                        format!(
                            "sentinel_guard_storage_writer\nowner={}\n",
                            owner_category.as_str()
                        )
                        .as_bytes(),
                    )?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(StorageError::StorageOwnershipConflict(
                        "writer_already_owned".to_string(),
                    ));
                }
                Err(error) => return Err(StorageError::Io(error.to_string())),
            }
        }

        let mut registry = storage_writer_registry().lock().map_err(|_| {
            StorageError::StorageOwnershipConflict("writer_registry_unavailable".to_string())
        })?;
        if registry.contains_key(&key) {
            if let Some(path) = &lock_path {
                let _ = fs::remove_file(path);
            }
            return Err(StorageError::StorageOwnershipConflict(
                "writer_already_owned".to_string(),
            ));
        }
        registry.insert(key.clone(), owner_category);
        drop(registry);

        Ok(Self {
            inner: Arc::new(StorageWriterLeaseInner {
                key,
                lock_path,
                status: StorageOwnershipStatus {
                    owner_category,
                    writer_state: StorageWriterState::Owned,
                    storage_scope: storage_scope.into(),
                    canonical_writer,
                    path_exposed: false,
                    llm_key_transferred: false,
                    degraded_reason: None,
                },
                released: Mutex::new(false),
            }),
        })
    }

    pub fn status(&self) -> StorageOwnershipStatus {
        let released = self
            .inner
            .released
            .lock()
            .map(|released| *released)
            .unwrap_or(true);
        let mut status = self.inner.status.clone();
        if released {
            status.writer_state = StorageWriterState::Released;
            status.canonical_writer = false;
        }
        status
    }

    pub fn release(&self) {
        release_storage_writer(&self.inner);
    }

    #[cfg(test)]
    pub fn reset_for_tests() {
        if let Ok(mut registry) = storage_writer_registry().lock() {
            registry.clear();
        }
    }
}

impl Drop for StorageWriterLeaseInner {
    fn drop(&mut self) {
        release_storage_writer_inner(&self.key, self.lock_path.as_ref(), &self.released);
    }
}

fn storage_writer_registry() -> &'static Mutex<BTreeMap<String, StorageWriterOwnerCategory>> {
    static STORAGE_WRITER_REGISTRY: OnceLock<Mutex<BTreeMap<String, StorageWriterOwnerCategory>>> =
        OnceLock::new();
    STORAGE_WRITER_REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn release_storage_writer(inner: &StorageWriterLeaseInner) {
    release_storage_writer_inner(&inner.key, inner.lock_path.as_ref(), &inner.released);
}

fn release_storage_writer_inner(key: &str, lock_path: Option<&PathBuf>, released: &Mutex<bool>) {
    let Ok(mut released_guard) = released.lock() else {
        return;
    };
    if *released_guard {
        return;
    }
    *released_guard = true;
    if let Ok(mut registry) = storage_writer_registry().lock() {
        registry.remove(key);
    }
    if let Some(path) = lock_path {
        let _ = fs::remove_file(path);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabasePragmas {
    pub journal_mode: String,
    pub busy_timeout_ms: u64,
    pub foreign_keys: bool,
    pub secure_delete: bool,
}

impl Default for DatabasePragmas {
    fn default() -> Self {
        Self {
            journal_mode: "WAL".to_string(),
            busy_timeout_ms: DEFAULT_BUSY_TIMEOUT_MS,
            foreign_keys: true,
            secure_delete: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseConfig {
    pub mode: DatabaseMode,
    pub location: DatabaseLocation,
    pub app_version: String,
    pub pragmas: DatabasePragmas,
    pub session_config: Option<SessionConfig>,
    pub writer_owner: StorageWriterOwnerCategory,
}

impl DatabaseConfig {
    pub fn for_startup_mode(app_version: impl Into<String>, demo_mode: bool) -> Self {
        let app_version = app_version.into();

        if demo_mode {
            if let Some(path) = env_path(DEMO_DB_PATH_ENV).or_else(|| env_path(DB_PATH_ENV)) {
                return Self::demo_file(app_version, path);
            }
            return Self::demo_in_memory(app_version);
        }

        let path = env_path(DB_PATH_ENV).unwrap_or_else(default_database_path);
        Self::normal(app_version, path)
    }

    pub fn normal(app_version: impl Into<String>, path: PathBuf) -> Self {
        Self {
            mode: DatabaseMode::Normal,
            location: DatabaseLocation::File(path),
            app_version: app_version.into(),
            pragmas: DatabasePragmas::default(),
            session_config: None,
            writer_owner: StorageWriterOwnerCategory::DesktopPortable,
        }
    }

    pub fn demo_in_memory(app_version: impl Into<String>) -> Self {
        Self {
            mode: DatabaseMode::Demo,
            location: DatabaseLocation::InMemory,
            app_version: app_version.into(),
            pragmas: DatabasePragmas::default(),
            session_config: None,
            writer_owner: StorageWriterOwnerCategory::TestHarness,
        }
    }

    pub fn demo_file(app_version: impl Into<String>, path: PathBuf) -> Self {
        Self {
            mode: DatabaseMode::Demo,
            location: DatabaseLocation::File(path),
            app_version: app_version.into(),
            pragmas: DatabasePragmas::default(),
            session_config: None,
            writer_owner: StorageWriterOwnerCategory::TestHarness,
        }
    }

    pub fn for_session(app_version: impl Into<String>, session_config: SessionConfig) -> Self {
        let location = match session_config.database_mode {
            SessionDatabaseMode::InMemory => DatabaseLocation::InMemory,
            SessionDatabaseMode::TempFile => {
                DatabaseLocation::File(session_config.session_root.join("session.db"))
            }
            SessionDatabaseMode::Persistent => {
                DatabaseLocation::File(session_config.session_root.join(DATABASE_FILE_NAME))
            }
        };
        let mode = if session_config.session_mode == SessionMode::Installed {
            DatabaseMode::Demo
        } else {
            DatabaseMode::Normal
        };

        Self {
            mode,
            location,
            app_version: app_version.into(),
            pragmas: DatabasePragmas::default(),
            session_config: Some(session_config),
            writer_owner: StorageWriterOwnerCategory::DesktopPortable,
        }
    }

    pub fn db_directory_redacted(&self) -> String {
        redacted_database_directory(&self.location)
    }

    pub fn with_writer_owner(mut self, writer_owner: StorageWriterOwnerCategory) -> Self {
        self.writer_owner = writer_owner;
        self
    }
}

#[derive(Clone)]
pub struct DatabaseHandle {
    connection: Arc<Mutex<Connection>>,
}

impl DatabaseHandle {
    pub fn new(connection: Connection) -> Self {
        Self {
            connection: Arc::new(Mutex::new(connection)),
        }
    }

    pub fn with_connection<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> StorageResult<T>,
    ) -> StorageResult<T> {
        let mut connection = self.connection.lock().map_err(|_| {
            StorageError::Sqlite("database connection lock is poisoned".to_string())
        })?;
        operation(&mut connection)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabasePragmaReport {
    pub journal_mode: String,
    pub busy_timeout_ms: u64,
    pub foreign_keys: bool,
    pub secure_delete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseRuntimeHealthReport {
    pub current_pragmas: DatabasePragmaReport,
    pub expected_pragmas: DatabasePragmaReport,
    pub pragmas_match_expected: bool,
    pub migrations_table_accessible: bool,
    pub store_initialization: StoreInitializationReport,
    pub degraded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreInitializationError {
    pub store_kind: StoreKind,
    pub error_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreInitializationReport {
    pub initialized_store_kinds: Vec<StoreKind>,
    pub failed_store_kinds: Vec<StoreInitializationError>,
}

impl StoreInitializationReport {
    pub fn degraded(&self) -> bool {
        !self.failed_store_kinds.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStartedAuditRecord {
    pub audit_id: AuditId,
    pub timestamp: Timestamp,
    pub app_version: String,
    pub startup_mode: DatabaseMode,
    pub session_id: Option<String>,
    pub session_mode: Option<SessionMode>,
    pub profile_mode: Option<String>,
    pub session_root_redacted: Option<String>,
    pub portable_root_redacted: Option<String>,
    pub portable_preferences_loaded: Option<usize>,
    pub db_directory_redacted: String,
    pub migrations_applied: u32,
    pub schema_version: SchemaVersion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseBootstrapReport {
    pub mode: DatabaseMode,
    pub session_id: Option<String>,
    pub session_mode: Option<SessionMode>,
    pub profile_mode: Option<String>,
    pub session_root_redacted: Option<String>,
    pub portable_root_redacted: Option<String>,
    pub portable_preferences_loaded: Option<usize>,
    pub session_database_mode: Option<SessionDatabaseMode>,
    pub location_redacted: String,
    pub in_memory: bool,
    pub pragmas: DatabasePragmaReport,
    pub migrations_applied: u32,
    pub migrations_skipped: u32,
    pub schema_version: SchemaVersion,
    pub store_initialization: StoreInitializationReport,
    pub audit_record: AppStartedAuditRecord,
    pub demo_seeded: bool,
    pub privacy_service_initialized: bool,
    pub schema_privacy_checked: bool,
    pub storage_ownership: StorageOwnershipStatus,
    pub degraded: bool,
}

#[derive(Clone)]
pub struct DatabaseRuntime {
    handle: DatabaseHandle,
    report: DatabaseBootstrapReport,
    privacy_engine: PrivacyEngine,
    session_lifecycle: Option<SessionLifecycle>,
    writer_lease: StorageWriterLease,
}

impl DatabaseRuntime {
    pub fn bootstrap(config: DatabaseConfig) -> StorageResult<Self> {
        Self::bootstrap_inner(config, None)
    }

    pub fn bootstrap_with_session(
        config: DatabaseConfig,
        session_lifecycle: SessionLifecycle,
    ) -> StorageResult<Self> {
        Self::bootstrap_inner(config, Some(session_lifecycle))
    }

    fn bootstrap_inner(
        config: DatabaseConfig,
        session_lifecycle: Option<SessionLifecycle>,
    ) -> StorageResult<Self> {
        let writer_lease = StorageWriterLease::acquire_for_database(&config)?;
        let mut connection = open_connection(&config)?;
        let pragmas = apply_connection_pragmas(&connection, &config.pragmas)?;
        let migrations = storage_migrations()?;
        let migration_report = run_migrations(&mut connection, &migrations)?;
        sync_runtime_migrations_table(&connection, &migrations)?;
        verify_schema_has_no_forbidden_columns(&connection)?;

        let store_initialization = StoreInitializer::initialize(&connection);
        let schema_version = latest_schema_version(&migrations);
        let demo_seeded = if config.mode == DatabaseMode::Demo {
            seed_demo_data(&connection)?
        } else {
            false
        };
        let audit_record = AuditBootstrap::write_app_started(
            &connection,
            AuditBootstrapRequest {
                app_version: config.app_version.clone(),
                startup_mode: config.mode.clone(),
                session_config: config.session_config.clone(),
                db_directory_redacted: config.db_directory_redacted(),
                migrations_applied: migration_report.applied,
                schema_version: schema_version.clone(),
            },
        )?;

        let handle = DatabaseHandle::new(connection);
        let degraded = store_initialization.degraded();
        let report = DatabaseBootstrapReport {
            mode: config.mode.clone(),
            session_id: config
                .session_config
                .as_ref()
                .map(|session| session.session_id.to_string()),
            session_mode: config
                .session_config
                .as_ref()
                .map(|session| session.session_mode),
            profile_mode: config
                .session_config
                .as_ref()
                .map(|session| session.session_mode.profile_mode().to_string()),
            session_root_redacted: config
                .session_config
                .as_ref()
                .map(|session| session.session_root_redacted.clone()),
            portable_root_redacted: config
                .session_config
                .as_ref()
                .and_then(|session| session.portable_root_redacted.clone()),
            portable_preferences_loaded: config
                .session_config
                .as_ref()
                .and_then(|session| session.portable_preferences_loaded),
            session_database_mode: config
                .session_config
                .as_ref()
                .map(|session| session.database_mode),
            location_redacted: config.db_directory_redacted(),
            in_memory: config.location.is_in_memory(),
            pragmas,
            migrations_applied: migration_report.applied,
            migrations_skipped: migration_report.skipped,
            schema_version,
            store_initialization,
            audit_record,
            demo_seeded,
            privacy_service_initialized: true,
            schema_privacy_checked: true,
            storage_ownership: writer_lease.status(),
            degraded,
        };

        Ok(Self {
            handle,
            report,
            privacy_engine: PrivacyEngine::new(),
            session_lifecycle,
            writer_lease,
        })
    }

    pub fn handle(&self) -> &DatabaseHandle {
        &self.handle
    }

    pub fn report(&self) -> &DatabaseBootstrapReport {
        &self.report
    }

    pub fn privacy_engine(&self) -> &PrivacyEngine {
        &self.privacy_engine
    }

    pub fn session_lifecycle(&self) -> Option<&SessionLifecycle> {
        self.session_lifecycle.as_ref()
    }

    pub fn health_check(&self) -> StorageResult<DatabaseRuntimeHealthReport> {
        self.handle.with_connection(|connection| {
            let current_pragmas = read_connection_pragmas(connection)?;
            let migrations_table_accessible = connection
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_migrations' LIMIT 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .is_some();
            let store_initialization = StoreInitializer::initialize(connection);
            let pragmas_match_expected = current_pragmas == self.report.pragmas;
            let degraded = !pragmas_match_expected
                || !migrations_table_accessible
                || store_initialization.degraded();

            Ok(DatabaseRuntimeHealthReport {
                current_pragmas,
                expected_pragmas: self.report.pragmas.clone(),
                pragmas_match_expected,
                migrations_table_accessible,
                store_initialization,
                degraded,
            })
        })
    }

    pub fn storage_ownership_status(&self) -> StorageOwnershipStatus {
        self.writer_lease.status()
    }

    pub fn release_storage_writer(&self) {
        self.writer_lease.release();
    }
}

pub struct StoreInitializer;

impl StoreInitializer {
    pub fn initialize(connection: &Connection) -> StoreInitializationReport {
        let mut initialized_store_kinds = Vec::new();
        let mut failed_store_kinds = Vec::new();

        for store_kind in runtime_store_kinds() {
            match probe_logical_store(connection, &store_kind) {
                Ok(()) => initialized_store_kinds.push(store_kind),
                Err(error) => failed_store_kinds.push(StoreInitializationError {
                    store_kind,
                    error_redacted: error.to_string(),
                }),
            }
        }

        StoreInitializationReport {
            initialized_store_kinds,
            failed_store_kinds,
        }
    }
}

pub struct AuditBootstrap;

pub struct AuditBootstrapRequest {
    pub app_version: String,
    pub startup_mode: DatabaseMode,
    pub session_config: Option<SessionConfig>,
    pub db_directory_redacted: String,
    pub migrations_applied: u32,
    pub schema_version: SchemaVersion,
}

impl AuditBootstrap {
    pub fn write_app_started(
        connection: &Connection,
        request: AuditBootstrapRequest,
    ) -> StorageResult<AppStartedAuditRecord> {
        let audit_id = AuditId::new_v4();
        let timestamp = Timestamp::now();
        let record = AppStartedAuditRecord {
            audit_id: audit_id.clone(),
            timestamp: timestamp.clone(),
            app_version: request.app_version,
            startup_mode: request.startup_mode,
            session_id: request
                .session_config
                .as_ref()
                .map(|session| session.session_id.to_string()),
            session_mode: request
                .session_config
                .as_ref()
                .map(|session| session.session_mode),
            profile_mode: request
                .session_config
                .as_ref()
                .map(|session| session.session_mode.profile_mode().to_string()),
            session_root_redacted: request
                .session_config
                .as_ref()
                .map(|session| session.session_root_redacted.clone()),
            portable_root_redacted: request
                .session_config
                .as_ref()
                .and_then(|session| session.portable_root_redacted.clone()),
            portable_preferences_loaded: request
                .session_config
                .as_ref()
                .and_then(|session| session.portable_preferences_loaded),
            db_directory_redacted: request.db_directory_redacted,
            migrations_applied: request.migrations_applied,
            schema_version: request.schema_version,
        };
        let factory = SqliteStoreFactory::new(connection);
        let audit_store = factory.audit_store();
        audit_store.append(LogicalRecord::metadata_only(
            audit_id,
            SchemaVersion::new(1, 0, 0),
            StoreKind::Audit.default_storage_privacy_class(),
            json!({
                "event_type": "app_started",
                "timestamp": record.timestamp.to_string(),
                "app_version": record.app_version,
                "startup_mode": record.startup_mode.as_str(),
                "session_id": record.session_id.as_deref(),
                "session_mode": record.session_mode.as_ref().map(|mode| mode.as_str()),
                "profile_mode": record.profile_mode.as_deref(),
                "session_root_redacted": record.session_root_redacted.as_deref(),
                "portable_root_redacted": record.portable_root_redacted.as_deref(),
                "portable_preferences_loaded": record.portable_preferences_loaded,
                "db_directory_redacted": record.db_directory_redacted,
                "migrations_applied": record.migrations_applied,
                "schema_version": record.schema_version.to_string()
            }),
        ))?;

        Ok(record)
    }
}

pub fn storage_migrations() -> StorageResult<Vec<Migration>> {
    Ok(vec![logical_store_migration()?])
}

pub fn verify_schema_has_no_forbidden_columns(connection: &Connection) -> StorageResult<()> {
    let mut statement = connection.prepare(
        "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL AND type IN ('table', 'index', 'view', 'trigger')",
    )?;
    let schema_rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for (name, sql) in schema_rows {
        let normalized = format!("{name} {sql}").to_ascii_lowercase();
        for forbidden in FORBIDDEN_SCHEMA_TOKENS {
            if normalized.contains(forbidden) {
                return Err(StorageError::InvalidMigration {
                    migration_key: "runtime_schema_privacy".to_string(),
                    reason: format!("schema contains forbidden storage token `{forbidden}`"),
                });
            }
        }
    }

    Ok(())
}

fn open_connection(config: &DatabaseConfig) -> StorageResult<Connection> {
    match &config.location {
        DatabaseLocation::InMemory => Ok(Connection::open_in_memory()?),
        DatabaseLocation::File(path) => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            Ok(Connection::open(path)?)
        }
    }
}

fn apply_connection_pragmas(
    connection: &Connection,
    pragmas: &DatabasePragmas,
) -> StorageResult<DatabasePragmaReport> {
    connection.busy_timeout(Duration::from_millis(pragmas.busy_timeout_ms))?;
    connection.pragma_update(None, "busy_timeout", pragmas.busy_timeout_ms as i64)?;
    connection.pragma_update(None, "journal_mode", &pragmas.journal_mode)?;
    connection.pragma_update(
        None,
        "foreign_keys",
        if pragmas.foreign_keys { "ON" } else { "OFF" },
    )?;
    connection.pragma_update(
        None,
        "secure_delete",
        if pragmas.secure_delete { "ON" } else { "OFF" },
    )?;

    read_connection_pragmas(connection)
}

fn run_migrations(
    connection: &mut Connection,
    migrations: &[Migration],
) -> StorageResult<MigrationRunReport> {
    let mut runner = MigrationRunner::new(connection);
    runner.initialize(&SchemaMetadata::storage_foundation())?;
    let mut audit_sink = InMemoryMigrationAuditSink::default();
    runner.apply_all(migrations, &mut audit_sink)
}

fn sync_runtime_migrations_table(
    connection: &Connection,
    migrations: &[Migration],
) -> StorageResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS _migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            checksum TEXT NOT NULL
        );
        "#,
    )?;

    for (index, migration) in migrations.iter().enumerate() {
        connection.execute(
            r#"
            INSERT OR IGNORE INTO _migrations (version, name, applied_at, checksum)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                (index + 1) as i64,
                &migration.name,
                Timestamp::now().to_string(),
                migration_checksum(migration),
            ],
        )?;
    }

    Ok(())
}

fn seed_demo_data(connection: &Connection) -> StorageResult<bool> {
    let factory = SqliteStoreFactory::new(connection);
    let plugin_store = factory.plugin_store();
    let component_store = factory.component_store();
    let settings_repository = SettingsConfigRepository::new(factory.settings_store());

    plugin_store.append(LogicalRecord::metadata_only(
        PluginId::new_v4(),
        SchemaVersion::new(1, 0, 0),
        StoreKind::Plugin.default_storage_privacy_class(),
        json!({
            "plugin_name": "demo_metadata_probe",
            "runtime_mode": "static_internal",
            "enabled": true,
            "summary_redacted": "safe demo plugin metadata"
        }),
    ))?;
    component_store.append(LogicalRecord::metadata_only(
        ComponentRecordId::new_v4(),
        SchemaVersion::new(1, 0, 0),
        StoreKind::Component.default_storage_privacy_class(),
        json!({
            "component_name": "demo_local_core",
            "component_type": "local_core",
            "health_status": "healthy",
            "summary_redacted": "safe demo component metadata"
        }),
    ))?;
    settings_repository.save_runtime_profile(RuntimeProfile::safe_default())?;
    seed_demo_graph_data(&factory)?;

    Ok(true)
}

fn seed_demo_graph_data(factory: &SqliteStoreFactory<'_>) -> StorageResult<()> {
    let graph_store = factory.graph_store();
    let evidence_c2 = EvidenceId::new_v4();
    let evidence_exfil = EvidenceId::new_v4();
    let evidence_exposure = EvidenceId::new_v4();
    let producer_plugin = PluginId::new_v4();

    let process = demo_graph_node(
        GraphNodeType::Process,
        EntityType::Process,
        "redacted process",
        &evidence_c2,
        0.82,
    )?;
    let domain = demo_graph_node(
        GraphNodeType::Domain,
        EntityType::Domain,
        "redacted destination",
        &evidence_c2,
        0.78,
    )?;
    let ip = demo_graph_node(
        GraphNodeType::Ip,
        EntityType::Ip,
        "redacted ip destination",
        &evidence_c2,
        0.8,
    )?;
    let cloud = demo_graph_node(
        GraphNodeType::CloudDestination,
        EntityType::CloudResource,
        "redacted cloud destination",
        &evidence_exfil,
        0.76,
    )?;
    let port = demo_graph_node(
        GraphNodeType::LocalPort,
        EntityType::Port,
        "redacted local port",
        &evidence_exposure,
        0.62,
    )?;
    let finding = demo_graph_node(
        GraphNodeType::Finding,
        EntityType::Finding,
        "redacted finding",
        &evidence_c2,
        0.88,
    )?;
    let alert = demo_graph_node(
        GraphNodeType::Alert,
        EntityType::Alert,
        "redacted alert",
        &evidence_c2,
        0.86,
    )?;
    let incident = demo_graph_node(
        GraphNodeType::Incident,
        EntityType::Incident,
        "redacted incident",
        &evidence_c2,
        0.9,
    )?;

    let nodes = vec![
        process.clone(),
        domain.clone(),
        ip.clone(),
        cloud.clone(),
        port.clone(),
        finding.clone(),
        alert.clone(),
        incident.clone(),
    ];
    for node in &nodes {
        graph_store.nodes().append(
            LogicalRecord::metadata_only(
                node.node_id.clone(),
                SchemaVersion::new(1, 0, 0),
                StoreKind::GraphNode.default_storage_privacy_class(),
                serde_json::to_value(node)?,
            )
            .with_entity_refs(node.entity_ref.clone().into_iter().collect())
            .with_record_time(node.last_seen.clone()),
        )?;
    }

    let edges = vec![
        demo_graph_edge(
            GraphEdgeType::ProcessQueriesDomain,
            &process,
            &domain,
            &evidence_c2,
            &producer_plugin,
            0.86,
        )?,
        demo_graph_edge(
            GraphEdgeType::DomainResolvesToIp,
            &domain,
            &ip,
            &evidence_c2,
            &producer_plugin,
            0.82,
        )?,
        demo_graph_edge(
            GraphEdgeType::ProcessConnectsToIp,
            &process,
            &ip,
            &evidence_c2,
            &producer_plugin,
            0.84,
        )?,
        demo_graph_edge(
            GraphEdgeType::ProcessUploadsToCloud,
            &process,
            &cloud,
            &evidence_exfil,
            &producer_plugin,
            0.78,
        )?,
        demo_graph_edge(
            GraphEdgeType::ProcessListensOnPort,
            &process,
            &port,
            &evidence_exposure,
            &producer_plugin,
            0.7,
        )?,
        demo_graph_edge(
            GraphEdgeType::ObservationSupportsFinding,
            &ip,
            &finding,
            &evidence_c2,
            &producer_plugin,
            0.85,
        )?,
        demo_graph_edge(
            GraphEdgeType::ObservationSupportsFinding,
            &cloud,
            &finding,
            &evidence_exfil,
            &producer_plugin,
            0.78,
        )?,
        demo_graph_edge(
            GraphEdgeType::ObservationSupportsFinding,
            &port,
            &finding,
            &evidence_exposure,
            &producer_plugin,
            0.7,
        )?,
        demo_graph_edge(
            GraphEdgeType::FindingSupportsAlert,
            &finding,
            &alert,
            &evidence_c2,
            &producer_plugin,
            0.86,
        )?,
        demo_graph_edge(
            GraphEdgeType::AlertPartOfIncident,
            &alert,
            &incident,
            &evidence_c2,
            &producer_plugin,
            0.88,
        )?,
    ];
    for edge in &edges {
        graph_store.edges().append(
            LogicalRecord::metadata_only(
                edge.edge_id.clone(),
                SchemaVersion::new(1, 0, 0),
                StoreKind::GraphEdge.default_storage_privacy_class(),
                serde_json::to_value(edge)?,
            )
            .with_record_time(edge.last_seen.clone()),
        )?;
    }

    Ok(())
}

fn demo_graph_node(
    node_type: GraphNodeType,
    entity_type: EntityType,
    entity_name: &str,
    evidence_ref: &EvidenceId,
    risk: f32,
) -> StorageResult<CanonicalGraphNode> {
    let now = Timestamp::now();
    let mut entity_ref = EntityRef::new(EntityId::new_v4(), entity_type);
    entity_ref.entity_name = Some(entity_name.to_string());
    entity_ref.confidence = demo_quality(0.86)?;
    entity_ref.first_seen = Some(now.clone());
    entity_ref.last_seen = Some(now.clone());

    let mut node = CanonicalGraphNode::new(
        node_type,
        RedactedLabel::redacted(entity_name, PrivacyClass::Internal).map_err(|error| {
            StorageError::InvalidRecord {
                store_kind: StoreKind::GraphNode.to_string(),
                reason: error.to_string(),
            }
        })?,
    );
    node.entity_ref = Some(entity_ref);
    node.risk_score = demo_quality(risk)?;
    node.confidence = demo_quality(0.86)?;
    node.first_seen = now.clone();
    node.last_seen = now;
    node.privacy_class = PrivacyClass::Sensitive;
    node.source_refs = vec![evidence_ref.clone()];
    Ok(node)
}

fn demo_graph_edge(
    edge_type: GraphEdgeType,
    source: &CanonicalGraphNode,
    target: &CanonicalGraphNode,
    evidence_ref: &EvidenceId,
    producer_plugin: &PluginId,
    confidence: f32,
) -> StorageResult<CanonicalGraphEdge> {
    let now = Timestamp::now();
    let mut edge =
        CanonicalGraphEdge::new(edge_type, source.node_id.clone(), target.node_id.clone());
    edge.confidence = demo_quality(confidence)?;
    edge.weight = demo_quality(confidence)?;
    edge.first_seen = now.clone();
    edge.last_seen = now;
    edge.privacy_class = PrivacyClass::Sensitive;
    edge.evidence_refs = vec![evidence_ref.clone()];
    edge.producer_plugin = Some(producer_plugin.clone());
    Ok(edge)
}

fn demo_quality(value: f32) -> StorageResult<QualityScore> {
    QualityScore::new(value).map_err(|error| StorageError::InvalidRecord {
        store_kind: "demo_graph".to_string(),
        reason: error.to_string(),
    })
}

fn probe_logical_store(connection: &Connection, store_kind: &StoreKind) -> StorageResult<()> {
    connection.query_row(
        "SELECT COUNT(*) FROM sg_logical_records WHERE store_kind = ?1",
        params![store_kind.as_str()],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(())
}

fn runtime_store_kinds() -> Vec<StoreKind> {
    vec![
        StoreKind::Event,
        StoreKind::Plugin,
        StoreKind::Component,
        StoreKind::Flow,
        StoreKind::Session,
        StoreKind::Dns,
        StoreKind::Tls,
        StoreKind::HttpMetadata,
        StoreKind::ProcessContext,
        StoreKind::IntelligenceCache,
        StoreKind::Asset,
        StoreKind::Settings,
        StoreKind::Finding,
        StoreKind::Evidence,
        StoreKind::Risk,
        StoreKind::Alert,
        StoreKind::Incident,
        StoreKind::GraphNode,
        StoreKind::GraphEdge,
        StoreKind::GraphPath,
        StoreKind::ResponsePlan,
        StoreKind::ResponseAction,
        StoreKind::ResponseResult,
        StoreKind::RollbackResult,
        StoreKind::Report,
        StoreKind::Audit,
        StoreKind::ExportHistory,
        StoreKind::ExportPolicyViolation,
        StoreKind::Migration,
    ]
}

fn latest_schema_version(migrations: &[Migration]) -> SchemaVersion {
    migrations
        .last()
        .map(|migration| migration.schema_version.clone())
        .unwrap_or_else(|| SchemaMetadata::storage_foundation().schema_version)
}

fn query_pragma_string(connection: &Connection, name: &str) -> StorageResult<String> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get::<_, String>(0))
        .map_err(StorageError::from)
}

fn query_pragma_i64(connection: &Connection, name: &str) -> StorageResult<i64> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get::<_, i64>(0))
        .map_err(StorageError::from)
}

fn read_connection_pragmas(connection: &Connection) -> StorageResult<DatabasePragmaReport> {
    Ok(DatabasePragmaReport {
        journal_mode: query_pragma_string(connection, "journal_mode")?,
        busy_timeout_ms: query_pragma_i64(connection, "busy_timeout")? as u64,
        foreign_keys: query_pragma_i64(connection, "foreign_keys")? == 1,
        secure_delete: query_pragma_i64(connection, "secure_delete")? == 1,
    })
}

fn migration_checksum(migration: &Migration) -> String {
    let mut input = format!("{}:{}:", migration.migration_key, migration.name);
    for statement in &migration.statements {
        input.push_str(&statement.label);
        input.push(':');
        input.push_str(&statement.sql);
        input.push(';');
    }
    stable_checksum(&input)
}

fn stable_checksum(input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name).and_then(|value| {
        if value.to_string_lossy().trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(value))
        }
    })
}

fn default_database_path() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir)
        .join(DATABASE_DIR_NAME)
        .join(DATABASE_FILE_NAME)
}

fn redacted_database_directory(location: &DatabaseLocation) -> String {
    match location {
        DatabaseLocation::InMemory => ":memory:".to_string(),
        DatabaseLocation::File(path) => path
            .parent()
            .map(redact_directory)
            .unwrap_or_else(|| "[configured-db-dir]".to_string()),
    }
}

fn redact_directory(path: &Path) -> String {
    if let Some(local_app_data) = env::var_os("LOCALAPPDATA").map(PathBuf::from) {
        if path.starts_with(&local_app_data) {
            if path.file_name().and_then(|name| name.to_str()) == Some(DATABASE_DIR_NAME) {
                return format!("%LOCALAPPDATA%/{DATABASE_DIR_NAME}");
            }
            return "%LOCALAPPDATA%/[redacted]".to_string();
        }
    }

    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("[configured-db-dir:{name}]"))
        .unwrap_or_else(|| "[configured-db-dir]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LogicalStore;
    use crate::SessionRootResolver;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn demo_bootstrap_uses_in_memory_database_and_writes_app_started(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = DatabaseRuntime::bootstrap(DatabaseConfig::demo_in_memory("0.1.0"))?;
        let report = runtime.report();

        assert_eq!(report.mode, DatabaseMode::Demo);
        assert!(report.in_memory);
        assert!(report.demo_seeded);
        assert!(report.schema_privacy_checked);
        assert!(report.privacy_service_initialized);
        assert!(report.pragmas.foreign_keys);
        assert!(report.pragmas.secure_delete);
        assert_eq!(report.audit_record.startup_mode, DatabaseMode::Demo);

        let audit_count = runtime.handle().with_connection(|connection| {
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sg_logical_records WHERE store_kind = 'audit'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(StorageError::from)
        })?;
        assert_eq!(audit_count, 1);
        Ok(())
    }

    #[test]
    fn ephemeral_session_bootstrap_uses_in_memory_store_and_audits_session(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = session_test_roots("ephemeral-runtime");
        let lifecycle = SessionLifecycle::start(
            SessionMode::Ephemeral,
            SessionRootResolver::for_roots(roots.join("sessions"), roots.join("local")),
        )?;
        let session_id = lifecycle.config().session_id.to_string();
        let session_root = lifecycle.config().session_root.clone();
        let runtime = DatabaseRuntime::bootstrap_with_session(
            DatabaseConfig::for_session("0.1.0", lifecycle.config().clone()),
            lifecycle,
        )?;
        let report = runtime.report();

        assert_eq!(report.session_id.as_deref(), Some(session_id.as_str()));
        assert_eq!(report.session_mode, Some(SessionMode::Ephemeral));
        assert_eq!(
            report.session_database_mode,
            Some(SessionDatabaseMode::InMemory)
        );
        assert!(report.in_memory);
        assert!(!report.demo_seeded);
        assert_eq!(
            report.audit_record.session_id.as_deref(),
            Some(session_id.as_str())
        );
        assert_eq!(
            report.audit_record.session_mode,
            Some(SessionMode::Ephemeral)
        );
        assert!(runtime.session_lifecycle().is_some());

        drop(runtime);
        assert!(!session_root.exists());
        let _ = fs::remove_dir_all(roots);
        Ok(())
    }

    #[test]
    fn portable_session_bootstrap_marks_no_retention_profile(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = session_test_roots("portable-runtime");
        let portable_root = roots.join("portable");
        let lifecycle = SessionLifecycle::start(
            SessionMode::PortableNoRetention,
            SessionRootResolver::for_portable_root(portable_root.clone()),
        )?;
        let session_root = lifecycle.config().session_root.clone();
        let runtime = DatabaseRuntime::bootstrap_with_session(
            DatabaseConfig::for_session("0.1.0", lifecycle.config().clone()),
            lifecycle,
        )?;
        let report = runtime.report();

        assert_eq!(report.session_mode, Some(SessionMode::PortableNoRetention));
        assert_eq!(
            report.profile_mode.as_deref(),
            Some("portable-no-retention")
        );
        assert_eq!(
            report.session_database_mode,
            Some(SessionDatabaseMode::InMemory)
        );
        assert!(report.in_memory);
        assert_eq!(
            report.audit_record.profile_mode.as_deref(),
            Some("portable-no-retention")
        );
        assert!(report.audit_record.portable_root_redacted.is_some());
        assert!(portable_root.join("data").join("exports").exists());

        drop(runtime);
        assert!(!session_root.exists());
        let _ = fs::remove_dir_all(roots);
        Ok(())
    }

    #[test]
    fn installed_session_bootstrap_uses_persistent_seeded_database(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = session_test_roots("installed-runtime");
        let local_root = roots.join("local");
        let lifecycle = SessionLifecycle::start(
            SessionMode::Installed,
            SessionRootResolver::for_roots(roots.join("sessions"), local_root.clone()),
        )?;
        let database_path = local_root.join(DATABASE_FILE_NAME);
        let runtime = DatabaseRuntime::bootstrap_with_session(
            DatabaseConfig::for_session("0.1.0", lifecycle.config().clone()),
            lifecycle,
        )?;
        let report = runtime.report();

        assert_eq!(report.session_mode, Some(SessionMode::Installed));
        assert_eq!(
            report.session_database_mode,
            Some(SessionDatabaseMode::Persistent)
        );
        assert_eq!(report.mode, DatabaseMode::Demo);
        assert!(report.demo_seeded);
        assert!(database_path.exists());

        drop(runtime);
        let _ = fs::remove_dir_all(roots);
        Ok(())
    }

    #[test]
    fn normal_bootstrap_creates_file_database_and_enables_wal(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_db_path();
        let runtime = DatabaseRuntime::bootstrap(DatabaseConfig::normal("0.1.0", path.clone()))?;
        let report = runtime.report();
        let health = runtime.health_check()?;

        assert_eq!(report.mode, DatabaseMode::Normal);
        assert!(!report.in_memory);
        assert!(path.exists());
        assert_eq!(report.pragmas.journal_mode, "wal");
        assert_eq!(report.pragmas.busy_timeout_ms, DEFAULT_BUSY_TIMEOUT_MS);
        assert!(report.pragmas.foreign_keys);
        assert!(report.pragmas.secure_delete);
        assert_eq!(
            report.audit_record.db_directory_redacted,
            "[configured-db-dir:SentinelGuard]"
        );
        assert_eq!(health.current_pragmas, report.pragmas);
        assert_eq!(health.expected_pragmas, report.pragmas);
        assert!(health.pragmas_match_expected);
        assert!(health.migrations_table_accessible);
        assert!(!health.store_initialization.degraded());
        assert!(!health.degraded);

        cleanup_temp_db(&path);
        Ok(())
    }

    #[test]
    fn health_check_detects_runtime_pragma_drift() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_db_path();
        let runtime = DatabaseRuntime::bootstrap(DatabaseConfig::normal("0.1.0", path.clone()))?;
        runtime.handle().with_connection(|connection| {
            connection.pragma_update(None, "foreign_keys", "OFF")?;
            Ok(())
        })?;

        let health = runtime.health_check()?;

        assert!(!health.current_pragmas.foreign_keys);
        assert!(health.expected_pragmas.foreign_keys);
        assert!(!health.pragmas_match_expected);
        assert!(health.migrations_table_accessible);
        assert!(health.degraded);

        cleanup_temp_db(&path);
        Ok(())
    }

    #[test]
    fn bootstrap_is_idempotent_and_records_skipped_migrations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_db_path();
        let first = DatabaseRuntime::bootstrap(DatabaseConfig::normal("0.1.0", path.clone()))?;
        assert!(matches!(
            first.report().storage_ownership.writer_state,
            StorageWriterState::Owned
        ));
        drop(first);
        let second = DatabaseRuntime::bootstrap(DatabaseConfig::normal("0.1.0", path.clone()))?;

        assert!(second.report().migrations_skipped >= 1);

        let migration_count = second.handle().with_connection(|connection| {
            connection
                .query_row("SELECT COUNT(*) FROM _migrations", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(StorageError::from)
        })?;
        assert_eq!(migration_count, 1);

        cleanup_temp_db(&path);
        Ok(())
    }

    #[test]
    fn ownership_servicehost_acquires_writer_and_rejects_desktop_concurrent_writer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        StorageWriterLease::reset_for_tests();
        let service = StorageWriterLease::acquire_for_test_scope(
            StorageWriterOwnerCategory::ServiceHost,
            "ownership_shared",
        )?;
        let status = service.status();

        assert_eq!(
            status.owner_category,
            StorageWriterOwnerCategory::ServiceHost
        );
        assert_eq!(status.writer_state, StorageWriterState::Owned);
        assert!(status.canonical_writer);
        assert!(!status.path_exposed);
        assert!(!status.llm_key_transferred);

        let desktop = StorageWriterLease::acquire_for_test_scope(
            StorageWriterOwnerCategory::DesktopPortable,
            "ownership_shared",
        );
        assert!(matches!(
            desktop,
            Err(StorageError::StorageOwnershipConflict(_))
        ));

        let serialized = serde_json::to_string(&status)?;
        for marker in ["c:\\", "sid", "token", "api_key", "password", "nonce"] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "storage ownership status leaked marker {marker}"
            );
        }
        service.release();
        StorageWriterLease::reset_for_tests();
        Ok(())
    }

    #[test]
    fn ownership_shutdown_releases_writer_and_allows_safe_reopen(
    ) -> Result<(), Box<dyn std::error::Error>> {
        StorageWriterLease::reset_for_tests();
        let service = StorageWriterLease::acquire_for_test_scope(
            StorageWriterOwnerCategory::ServiceHost,
            "ownership_reopen",
        )?;
        service.release();
        assert_eq!(service.status().writer_state, StorageWriterState::Released);

        let reopened = StorageWriterLease::acquire_for_test_scope(
            StorageWriterOwnerCategory::ServiceHost,
            "ownership_reopen",
        )?;
        assert_eq!(reopened.status().writer_state, StorageWriterState::Owned);
        drop(reopened);
        StorageWriterLease::reset_for_tests();
        Ok(())
    }

    #[test]
    fn ownership_database_runtime_rejects_concurrent_file_writer_and_reopens_after_drop(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_db_path();
        let service = DatabaseRuntime::bootstrap(
            DatabaseConfig::normal("0.1.0", path.clone())
                .with_writer_owner(StorageWriterOwnerCategory::ServiceHost),
        )?;
        assert_eq!(
            service.storage_ownership_status().owner_category,
            StorageWriterOwnerCategory::ServiceHost
        );

        let desktop_attempt = DatabaseRuntime::bootstrap(
            DatabaseConfig::normal("0.1.0", path.clone())
                .with_writer_owner(StorageWriterOwnerCategory::DesktopPortable),
        );
        assert!(matches!(
            desktop_attempt,
            Err(StorageError::StorageOwnershipConflict(_))
        ));

        drop(service);
        let reopened = DatabaseRuntime::bootstrap(
            DatabaseConfig::normal("0.1.0", path.clone())
                .with_writer_owner(StorageWriterOwnerCategory::ServiceHost),
        )?;
        assert_eq!(
            reopened.storage_ownership_status().writer_state,
            StorageWriterState::Owned
        );
        drop(reopened);
        cleanup_temp_db(&path);
        Ok(())
    }

    #[test]
    fn ownership_servicehost_durable_manifest_declares_policy_approved_state_only(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manifest = service_host_durable_storage_manifest();

        manifest.validate()?;
        assert_eq!(
            manifest.owner_category,
            StorageWriterOwnerCategory::ServiceHost
        );
        assert!(manifest.canonical_writer_required);
        assert!(!manifest.desktop_writer_allowed);
        assert!(!manifest.cross_process_sqlite_connection_allowed);
        for required in [
            "runtime_session_state",
            "scheduler_state",
            "sampler_state",
            "permission_readiness_state",
            "baseline_state",
            "incident_linked_state",
            "canonical_read_model_snapshots",
            "report_traceability",
            "export_traceability_history_metadata",
            "portable_reader_cursor_state",
        ] {
            let policy = manifest.policy(required).expect("required policy");
            assert_eq!(
                policy.owner_category,
                StorageWriterOwnerCategory::ServiceHost
            );
            assert_ne!(
                policy.classification,
                StoragePersistenceClassification::Forbidden
            );
            assert!(policy.servicehost_canonical);
            assert_eq!(policy.redaction_status, RedactionStatus::Redacted);
        }
        assert!(manifest.split_owned_state.iter().any(|policy| {
            policy.state_name == "temporary_llm_key"
                && policy.owner_category == "desktop_memory_only_write_only"
                && !policy.transferred_to_servicehost
                && !policy.persisted_by_servicehost
        }));
        let serialized = serde_json::to_string(&manifest)?;
        for forbidden in [
            "c:\\",
            "session_token",
            "api_key_value",
            "raw_payload_column",
            "caller_token_value",
            "process_name_value",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(forbidden),
                "manifest leaked forbidden marker {forbidden}"
            );
        }
        Ok(())
    }

    #[test]
    fn recovery_servicehost_restart_validates_writer_schema_and_rebuilds_snapshots(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_db_path();
        {
            let first = DatabaseRuntime::bootstrap(
                DatabaseConfig::normal("0.1.0", path.clone())
                    .with_writer_owner(StorageWriterOwnerCategory::ServiceHost),
            )?;
            assert_eq!(
                first.storage_ownership_status().owner_category,
                StorageWriterOwnerCategory::ServiceHost
            );
        }

        let report = service_host_storage_recovery_probe(
            DatabaseConfig::normal("0.1.0", path.clone())
                .with_writer_owner(StorageWriterOwnerCategory::ServiceHost),
            42,
        );

        assert!(!report.degraded);
        assert!(report.schema_validated);
        assert!(report.ownership_validated);
        assert!(report.new_ownership_epoch_established);
        assert!(report.canonical_snapshots_rebuilt);
        assert!(report.allowed_state_restored_count >= 10);
        assert!(!report.scheduler_activated);
        assert!(!report.sampler_activated);
        assert!(!report.provider_executed);
        assert!(!report.stale_findings_replayed);
        assert!(!report.llm_invoked);
        assert!(!report.cross_process_sqlite_connection_shared);
        assert!(!report.storage_path_exposed);

        cleanup_temp_db(&path);
        Ok(())
    }

    #[test]
    fn recovery_corrupted_storage_degrades_without_path_or_secret_exposure(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_db_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, b"not a sqlite database")?;

        let report = service_host_storage_recovery_probe(
            DatabaseConfig::normal("0.1.0", path.clone())
                .with_writer_owner(StorageWriterOwnerCategory::ServiceHost),
            43,
        );

        assert!(report.degraded);
        assert!(!report.schema_validated);
        assert!(!report.ownership_validated);
        assert!(!report.storage_path_exposed);
        assert!(!report.llm_invoked);
        assert!(!report.provider_executed);
        let serialized = serde_json::to_string(&report)?;
        assert!(!serialized.contains(path.to_string_lossy().as_ref()));
        for forbidden in ["c:\\", "api_key", "password", "session_token", "nonce"] {
            assert!(
                !serialized.to_ascii_lowercase().contains(forbidden),
                "recovery report leaked forbidden marker {forbidden}"
            );
        }

        cleanup_temp_db(&path);
        Ok(())
    }

    #[test]
    fn store_initializer_covers_task_530_store_facades() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = DatabaseRuntime::bootstrap(DatabaseConfig::demo_in_memory("0.1.0"))?;
        let initialized = &runtime
            .report()
            .store_initialization
            .initialized_store_kinds;

        assert!(initialized.contains(&StoreKind::Plugin));
        assert!(initialized.contains(&StoreKind::Component));
        assert!(initialized.contains(&StoreKind::Settings));
        assert!(initialized.contains(&StoreKind::Finding));
        assert!(initialized.contains(&StoreKind::Alert));
        assert!(initialized.contains(&StoreKind::Incident));
        assert!(initialized.contains(&StoreKind::Flow));
        assert!(initialized.contains(&StoreKind::Dns));
        assert!(initialized.contains(&StoreKind::Tls));
        assert!(initialized.contains(&StoreKind::GraphNode));
        assert!(initialized.contains(&StoreKind::GraphEdge));
        assert!(initialized.contains(&StoreKind::GraphPath));
        assert!(initialized.contains(&StoreKind::ResponsePlan));
        assert!(initialized.contains(&StoreKind::Report));
        assert!(initialized.contains(&StoreKind::Audit));
        assert!(initialized.contains(&StoreKind::ExportHistory));
        assert!(!runtime.report().store_initialization.degraded());
        Ok(())
    }

    #[test]
    fn schema_privacy_check_rejects_forbidden_columns() -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("CREATE TABLE unsafe_capture (raw_payload TEXT)")?;

        assert!(verify_schema_has_no_forbidden_columns(&connection).is_err());
        Ok(())
    }

    #[test]
    fn demo_seed_writes_plugin_component_and_safe_profile() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = DatabaseRuntime::bootstrap(DatabaseConfig::demo_in_memory("0.1.0"))?;
        runtime.handle().with_connection(|connection| {
            let factory = SqliteStoreFactory::new(connection);
            assert_eq!(factory.plugin_store().create_snapshot()?.record_count, 1);
            assert_eq!(factory.component_store().create_snapshot()?.record_count, 1);
            assert_eq!(factory.settings_store().create_snapshot()?.record_count, 1);
            let graph_store = factory.graph_store();
            assert_eq!(graph_store.nodes().create_snapshot()?.record_count, 8);
            assert_eq!(graph_store.edges().create_snapshot()?.record_count, 10);
            Ok(())
        })?;
        Ok(())
    }

    fn temp_db_path() -> PathBuf {
        env::current_dir()
            .unwrap_or_else(|_| env::temp_dir())
            .join("target")
            .join("storage-tests")
            .join(format!("sentinel-runtime-{}", Uuid::new_v4()))
            .join(DATABASE_DIR_NAME)
            .join(DATABASE_FILE_NAME)
    }

    fn cleanup_temp_db(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(path.with_extension("db-wal"));
        let _ = fs::remove_file(path.with_extension("db-shm"));
        if let Some(parent) = path.parent() {
            let _ = fs::remove_file(parent.join(STORAGE_WRITER_LOCK_FILE_NAME));
            let _ = fs::remove_dir(parent);
            if let Some(root) = parent.parent() {
                let _ = fs::remove_dir(root);
            }
        }
    }

    fn session_test_roots(label: &str) -> PathBuf {
        env::current_dir()
            .unwrap_or_else(|_| env::temp_dir())
            .join("target")
            .join("runtime-session-tests")
            .join(format!("{label}-{}", Uuid::new_v4()))
    }
}
