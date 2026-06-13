use crate::error::{StorageError, StorageResult};
use crate::portable_preferences::PortablePreferenceStore;
use chrono::{DateTime, Utc};
use sentinel_contracts::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const APP_DIR_NAME: &str = "SentinelGuard";
const SESSIONS_DIR_NAME: &str = "sessions";
const PREFERENCES_FILE_NAME: &str = "preferences.json";
const PORTABLE_DATA_DIR_NAME: &str = "data";
const PORTABLE_PREFERENCES_DIR_NAME: &str = "preferences";
const PORTABLE_EXPORTS_DIR_NAME: &str = "exports";
const PORTABLE_REPORTS_DIR_NAME: &str = "reports";
const PORTABLE_LOGS_DIR_NAME: &str = "logs";
const PORTABLE_TEMP_DIR_NAME: &str = "temp";
const PORTABLE_UI_PREFERENCES_FILE_NAME: &str = "ui_preferences.json";
const SESSION_AUDIT_FILE_NAME: &str = "session_audit.log";
const CLEANUP_AUDIT_FILE_NAME: &str = "audit.log";
pub const PORTABLE_PROFILE_MARKER_FILE_NAME: &str = "portable.profile.json";
pub const SESSION_MARKER_FILE_NAME: &str = ".sentinel_session";
pub const SESSION_MARKER_VALUE: &str = "SENTINEL_GUARD_SESSION";
pub const SESSION_MARKER_VERSION: u32 = 1;
pub const CAPTURE_IMPORT_PREVIEW_FILE_PREFIX: &str = "capture_import_preview-";
pub const CAPTURE_IMPORT_PREVIEW_FILE_SUFFIX: &str = ".json";

const FORBIDDEN_PREFERENCE_MARKERS: &[&str] = &[
    "session_id",
    "observation",
    "finding",
    "alert",
    "incident",
    "ip_address",
    "hostname",
    "process",
    "raw_packet",
    "payload",
    "http_body",
    "cookie",
    "token",
    "credential",
    "api_key",
    "private_key",
    "command_line",
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    /// Default: live analysis, in-memory, discarded on close unless explicitly saved.
    #[default]
    Ephemeral,
    /// Pre-seeded with installed fixture/mock data for development and demo.
    Installed,
    /// Existing demo flag alias; resolved to Installed before storage opens.
    Demo,
    /// Copied-folder profile; security session data is discarded on close.
    PortableNoRetention,
}

impl SessionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::Installed => "installed",
            Self::Demo => "demo",
            Self::PortableNoRetention => "portable-no-retention",
        }
    }

    pub fn effective(self) -> Self {
        match self {
            Self::Demo => Self::Installed,
            mode => mode,
        }
    }

    pub fn discards_on_shutdown(self) -> bool {
        matches!(
            self.effective(),
            Self::Ephemeral | Self::PortableNoRetention
        )
    }

    pub fn profile_mode(self) -> &'static str {
        self.effective().as_str()
    }

    pub fn for_demo_flag(demo_enabled: bool) -> Self {
        if demo_enabled {
            Self::Installed
        } else {
            Self::Ephemeral
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionDatabaseMode {
    InMemory,
    TempFile,
    Persistent,
}

impl SessionDatabaseMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InMemory => "in_memory",
            Self::TempFile => "temp_file",
            Self::Persistent => "persistent",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionConfig {
    pub session_mode: SessionMode,
    pub session_id: Uuid,
    pub session_root: PathBuf,
    pub session_root_redacted: String,
    pub database_mode: SessionDatabaseMode,
    pub preferences_path: PathBuf,
    pub preferences_path_redacted: String,
    pub portable_root: Option<PathBuf>,
    pub portable_root_redacted: Option<String>,
    pub portable_preferences_loaded: Option<usize>,
    pub cleaned_abandoned_sessions: Vec<Uuid>,
    pub skipped_unknown_entries: Vec<String>,
}

impl SessionConfig {
    pub fn database_mode_str(&self) -> &'static str {
        self.database_mode.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupEntry {
    pub path: PathBuf,
    pub session_id: Uuid,
    pub dry_run: bool,
    pub files_deleted: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedEntry {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupError {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupReport {
    pub cleaned: Vec<CleanupEntry>,
    pub skipped: Vec<SkippedEntry>,
    pub errors: Vec<CleanupError>,
}

pub type SessionCleanupReport = CleanupReport;

impl CleanupReport {
    fn empty() -> Self {
        Self {
            cleaned: Vec::new(),
            skipped: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn cleaned_session_ids(&self) -> Vec<Uuid> {
        self.cleaned.iter().map(|entry| entry.session_id).collect()
    }

    pub fn skipped_entry_names(&self) -> Vec<String> {
        self.skipped
            .iter()
            .map(|entry| {
                entry
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("[unknown]")
                    .to_string()
            })
            .chain(self.errors.iter().map(|entry| {
                entry
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("[unknown]")
                    .to_string()
            }))
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRootResolver {
    sessions_root: PathBuf,
    local_app_root: PathBuf,
    portable_root: Option<PathBuf>,
}

impl SessionRootResolver {
    pub fn platform_default() -> Self {
        let sessions_root = env::temp_dir().join(APP_DIR_NAME).join(SESSIONS_DIR_NAME);
        let local_app_root = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir)
            .join(APP_DIR_NAME);
        Self::for_roots(sessions_root, local_app_root)
    }

    pub fn for_roots(sessions_root: PathBuf, local_app_root: PathBuf) -> Self {
        Self {
            sessions_root,
            local_app_root,
            portable_root: None,
        }
    }

    pub fn for_portable_root(portable_root: PathBuf) -> Self {
        let sessions_root = portable_root
            .join(PORTABLE_TEMP_DIR_NAME)
            .join(SESSIONS_DIR_NAME);
        let local_app_root = portable_root.join(PORTABLE_LOGS_DIR_NAME);
        Self {
            sessions_root,
            local_app_root,
            portable_root: Some(portable_root),
        }
    }

    pub fn sessions_root(&self) -> &Path {
        &self.sessions_root
    }

    pub fn local_app_root(&self) -> &Path {
        &self.local_app_root
    }

    pub fn portable_root(&self) -> Option<&Path> {
        self.portable_root.as_deref()
    }

    pub fn preferences_path(&self) -> PathBuf {
        if let Some(portable_root) = &self.portable_root {
            return portable_root
                .join(PORTABLE_DATA_DIR_NAME)
                .join(PORTABLE_PREFERENCES_DIR_NAME)
                .join(PORTABLE_UI_PREFERENCES_FILE_NAME);
        }
        self.local_app_root.join(PREFERENCES_FILE_NAME)
    }

    pub fn resolve(&self, requested_mode: SessionMode) -> StorageResult<SessionResolution> {
        let mode = requested_mode.effective();
        match mode {
            SessionMode::Ephemeral => {
                fs::create_dir_all(&self.local_app_root)?;
                validate_existing_path_within_root(&self.local_app_root, &self.local_app_root)?;
                self.resolve_ephemeral()
            }
            SessionMode::PortableNoRetention => self.resolve_portable(),
            SessionMode::Installed | SessionMode::Demo => self.resolve_installed(),
        }
    }

    pub fn cleanup_abandoned_sessions(&self) -> StorageResult<SessionCleanupReport> {
        fs::create_dir_all(&self.sessions_root)?;
        validate_existing_path_within_root(&self.sessions_root, &self.sessions_root)?;
        Ok(SessionCleanup::cleanup_abandoned_sessions_with_audit(
            &self.sessions_root,
            &self.local_app_root,
            false,
        ))
    }

    fn resolve_ephemeral(&self) -> StorageResult<SessionResolution> {
        let cleanup_report = self.cleanup_abandoned_sessions()?;
        let session_id = Uuid::new_v4();
        let session_root = self.sessions_root.join(session_id.to_string());
        fs::create_dir_all(&session_root)?;
        validate_existing_path_within_root(&session_root, &self.sessions_root)?;
        SessionMarker::new(session_id, SessionMode::Ephemeral).write_to_dir(&session_root)?;

        Ok(SessionResolution {
            config: SessionConfig {
                session_mode: SessionMode::Ephemeral,
                session_id,
                session_root,
                session_root_redacted: self.redacted_sessions_root(),
                database_mode: SessionDatabaseMode::InMemory,
                preferences_path: self.preferences_path(),
                preferences_path_redacted: self.redacted_preferences_path(),
                portable_root: None,
                portable_root_redacted: None,
                portable_preferences_loaded: None,
                cleaned_abandoned_sessions: cleanup_report.cleaned_session_ids(),
                skipped_unknown_entries: cleanup_report.skipped_entry_names(),
            },
            local_app_root: self.local_app_root.clone(),
        })
    }

    fn resolve_portable(&self) -> StorageResult<SessionResolution> {
        let portable_root =
            self.portable_root
                .as_ref()
                .ok_or_else(|| StorageError::InvalidRecord {
                    store_kind: "portable_root".to_string(),
                    reason: "portable mode requires an executable directory portable root"
                        .to_string(),
                })?;
        self.create_portable_layout(portable_root)?;

        let cleanup_report = self.cleanup_abandoned_sessions()?;
        let session_id = Uuid::new_v4();
        let session_root = self.sessions_root.join(session_id.to_string());
        fs::create_dir_all(&session_root)?;
        validate_existing_path_within_root(&session_root, &self.sessions_root)?;
        SessionMarker::new(session_id, SessionMode::PortableNoRetention)
            .write_to_dir(&session_root)?;
        append_session_audit(
            &session_root,
            json!({
                "event_type": "app_started",
                "timestamp": Timestamp::now().to_string(),
                "profile_mode": SessionMode::PortableNoRetention.profile_mode(),
                "session_id": session_id.to_string(),
                "portable_root_redacted": self.redacted_portable_root()
            }),
        )?;
        let mut preference_store = PortablePreferenceStore::new(portable_root);
        let portable_preferences_loaded = preference_store
            .load()
            .map_err(portable_preference_storage_error)?
            .len();

        Ok(SessionResolution {
            config: SessionConfig {
                session_mode: SessionMode::PortableNoRetention,
                session_id,
                session_root,
                session_root_redacted: self.redacted_sessions_root(),
                database_mode: SessionDatabaseMode::InMemory,
                preferences_path: self.preferences_path(),
                preferences_path_redacted: self.redacted_preferences_path(),
                portable_root: Some(portable_root.clone()),
                portable_root_redacted: Some(self.redacted_portable_root()),
                portable_preferences_loaded: Some(portable_preferences_loaded),
                cleaned_abandoned_sessions: cleanup_report.cleaned_session_ids(),
                skipped_unknown_entries: cleanup_report.skipped_entry_names(),
            },
            local_app_root: self.local_app_root.clone(),
        })
    }

    fn resolve_installed(&self) -> StorageResult<SessionResolution> {
        fs::create_dir_all(&self.local_app_root)?;
        validate_existing_path_within_root(&self.local_app_root, &self.local_app_root)?;

        Ok(SessionResolution {
            config: SessionConfig {
                session_mode: SessionMode::Installed,
                session_id: Uuid::new_v4(),
                session_root: self.local_app_root.clone(),
                session_root_redacted: self.redacted_local_app_root(),
                database_mode: SessionDatabaseMode::Persistent,
                preferences_path: self.preferences_path(),
                preferences_path_redacted: self.redacted_preferences_path(),
                portable_root: None,
                portable_root_redacted: None,
                portable_preferences_loaded: None,
                cleaned_abandoned_sessions: Vec::new(),
                skipped_unknown_entries: Vec::new(),
            },
            local_app_root: self.local_app_root.clone(),
        })
    }

    fn create_portable_layout(&self, portable_root: &Path) -> StorageResult<()> {
        fs::create_dir_all(portable_root)?;
        validate_existing_path_within_root(portable_root, portable_root)?;
        for directory in [
            portable_root
                .join(PORTABLE_DATA_DIR_NAME)
                .join(PORTABLE_PREFERENCES_DIR_NAME),
            portable_root
                .join(PORTABLE_DATA_DIR_NAME)
                .join(PORTABLE_EXPORTS_DIR_NAME),
            portable_root
                .join(PORTABLE_DATA_DIR_NAME)
                .join(PORTABLE_REPORTS_DIR_NAME),
            portable_root.join(PORTABLE_LOGS_DIR_NAME),
            portable_root
                .join(PORTABLE_TEMP_DIR_NAME)
                .join(SESSIONS_DIR_NAME),
        ] {
            fs::create_dir_all(&directory)?;
            validate_existing_path_within_root(&directory, portable_root)?;
        }
        Ok(())
    }

    fn redacted_sessions_root(&self) -> String {
        if self.portable_root.is_some() {
            return format!("{}/temp/{SESSIONS_DIR_NAME}", self.redacted_portable_root());
        }
        let default_sessions_root = env::temp_dir().join(APP_DIR_NAME).join(SESSIONS_DIR_NAME);
        if self.sessions_root == default_sessions_root {
            return format!("%TEMP%/{APP_DIR_NAME}/{SESSIONS_DIR_NAME}");
        }
        redact_configured_path(&self.sessions_root, "sessions-root")
    }

    fn redacted_local_app_root(&self) -> String {
        if let Some(local_app_data) = env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            if self.local_app_root == local_app_data.join(APP_DIR_NAME) {
                return format!("%LOCALAPPDATA%/{APP_DIR_NAME}");
            }
        }
        redact_configured_path(&self.local_app_root, "local-app-root")
    }

    fn redacted_preferences_path(&self) -> String {
        if self.portable_root.is_some() {
            return format!(
                "{}/data/preferences/{PORTABLE_UI_PREFERENCES_FILE_NAME}",
                self.redacted_portable_root()
            );
        }
        if let Some(local_app_data) = env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            if self.preferences_path()
                == local_app_data
                    .join(APP_DIR_NAME)
                    .join(PREFERENCES_FILE_NAME)
            {
                return format!("%LOCALAPPDATA%/{APP_DIR_NAME}/{PREFERENCES_FILE_NAME}");
            }
        }
        format!(
            "{}/{}",
            self.redacted_local_app_root(),
            PREFERENCES_FILE_NAME
        )
    }

    fn redacted_portable_root(&self) -> String {
        self.portable_root
            .as_deref()
            .map(|path| redact_configured_path(path, "portable-root"))
            .unwrap_or_else(|| "[portable-root]".to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionResolution {
    pub config: SessionConfig,
    pub local_app_root: PathBuf,
}

#[derive(Clone)]
pub struct SessionLifecycle {
    inner: Arc<SessionLifecycleInner>,
}

struct SessionLifecycleInner {
    config: SessionConfig,
    local_app_root: PathBuf,
    ended: Mutex<bool>,
}

impl SessionLifecycle {
    pub fn start(mode: SessionMode, resolver: SessionRootResolver) -> StorageResult<Self> {
        let resolution = resolver.resolve(mode)?;
        Ok(Self {
            inner: Arc::new(SessionLifecycleInner {
                config: resolution.config,
                local_app_root: resolution.local_app_root,
                ended: Mutex::new(false),
            }),
        })
    }

    pub fn config(&self) -> &SessionConfig {
        &self.inner.config
    }

    pub fn preferences_store(&self) -> PreferencesStore {
        PreferencesStore::new(self.config().preferences_path.clone())
    }

    pub fn portable_preferences_store(&self) -> Option<PortablePreferenceStore> {
        self.config()
            .portable_root
            .as_deref()
            .map(PortablePreferenceStore::new)
    }

    pub fn append_session_audit_event(&self, event: serde_json::Value) -> StorageResult<()> {
        let audit_root = if self.config().session_mode == SessionMode::PortableNoRetention {
            &self.config().session_root
        } else {
            &self.inner.local_app_root
        };
        append_session_audit(audit_root, event)
    }

    pub fn end(&self) {
        self.inner.finish();
    }
}

impl Drop for SessionLifecycleInner {
    fn drop(&mut self) {
        self.finish();
    }
}

impl SessionLifecycleInner {
    fn finish(&self) {
        let Ok(mut ended) = self.ended.lock() else {
            eprintln!(
                "SESSION_CLEANUP_WARN session_id={} disposition=lock_failed",
                self.config.session_id
            );
            return;
        };
        if *ended {
            return;
        }
        *ended = true;

        if !self.config.session_mode.discards_on_shutdown() {
            return;
        }

        let audit_root = if self.config.session_mode == SessionMode::PortableNoRetention {
            &self.config.session_root
        } else {
            &self.local_app_root
        };
        if let Err(error) = append_session_audit(
            audit_root,
            json!({
                "event_type": "session_ended",
                "timestamp": Timestamp::now().to_string(),
                "session_id": self.config.session_id.to_string(),
                "session_mode": self.config.session_mode.as_str(),
                "profile_mode": self.config.session_mode.profile_mode(),
                "disposition": "discarded"
            }),
        ) {
            eprintln!("SESSION_AUDIT_WARN event=session_ended error={error}");
        }

        if let Err(error) = fs::remove_dir_all(&self.config.session_root) {
            if self.config.session_root.exists() {
                eprintln!(
                    "SESSION_CLEANUP_WARN session_id={} disposition=discard_failed error={}",
                    self.config.session_id, error
                );
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedSessionDirectory {
    marker: SentinelSessionMarker,
    files: Vec<PathBuf>,
    file_names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupAuditEvent {
    pub timestamp: String,
    pub event: String,
    pub session_id: String,
    pub directory_path: String,
    pub files_deleted: Vec<String>,
    pub reason: String,
}

pub trait CleanupAudit {
    fn write_cleanup_event(&self, event: CleanupAuditEvent) -> StorageResult<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonlCleanupAudit {
    audit_root: PathBuf,
}

impl JsonlCleanupAudit {
    pub fn new(audit_root: impl Into<PathBuf>) -> Self {
        Self {
            audit_root: audit_root.into(),
        }
    }
}

impl CleanupAudit for JsonlCleanupAudit {
    fn write_cleanup_event(&self, event: CleanupAuditEvent) -> StorageResult<()> {
        append_cleanup_audit(&self.audit_root, event)
    }
}

pub struct SessionCleanup;

impl SessionCleanup {
    pub fn validate_session_directory(path: &Path) -> Result<SentinelSessionMarker, CleanupError> {
        let session_root = path.parent().unwrap_or(path);
        Self::validate_session_directory_with_root(session_root, path)
            .map(|validated| validated.marker)
    }

    pub fn cleanup_abandoned_sessions(session_root: &Path, dry_run: bool) -> CleanupReport {
        Self::cleanup_abandoned_sessions_impl(session_root, None, dry_run)
    }

    pub fn cleanup_abandoned_sessions_with_audit(
        session_root: &Path,
        audit_root: &Path,
        dry_run: bool,
    ) -> CleanupReport {
        Self::cleanup_abandoned_sessions_impl(session_root, Some(audit_root), dry_run)
    }

    pub fn delete_session_directory(path: &Path) -> Result<(), CleanupError> {
        fs::remove_dir_all(path).map_err(|_error| CleanupError {
            path: path.to_path_buf(),
            reason: "deletion_failed".to_string(),
        })
    }

    fn cleanup_abandoned_sessions_impl(
        session_root: &Path,
        audit_root: Option<&Path>,
        dry_run: bool,
    ) -> CleanupReport {
        let mut report = CleanupReport::empty();
        if !session_root.exists() {
            return report;
        }

        let Ok(entries) = fs::read_dir(session_root) else {
            report.errors.push(CleanupError {
                path: session_root.to_path_buf(),
                reason: "read_dir_failed".to_string(),
            });
            return report;
        };

        for entry in entries {
            let Ok(entry) = entry else {
                report.errors.push(CleanupError {
                    path: session_root.to_path_buf(),
                    reason: "read_dir_entry_failed".to_string(),
                });
                continue;
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    report.errors.push(CleanupError {
                        path,
                        reason: format!("file_type_failed: {error}"),
                    });
                    continue;
                }
            };
            if !file_type.is_dir() {
                report.skipped.push(SkippedEntry {
                    path,
                    reason: "not_a_directory".to_string(),
                });
                continue;
            }

            let validated = match Self::validate_session_directory_with_root(session_root, &path) {
                Ok(validated) => validated,
                Err(error) => {
                    if error.reason == "path_traversal" {
                        report.errors.push(error);
                    } else {
                        report.skipped.push(SkippedEntry {
                            path: error.path,
                            reason: error.reason,
                        });
                    }
                    continue;
                }
            };

            let entry = CleanupEntry {
                path: path.clone(),
                session_id: validated.marker.session_id,
                dry_run,
                files_deleted: validated.file_names.clone(),
            };
            if dry_run {
                report.cleaned.push(entry);
                continue;
            }

            match Self::delete_session_directory(&path) {
                Ok(()) => {
                    if let Some(audit_root) = audit_root {
                        if let Err(error) = JsonlCleanupAudit::new(audit_root)
                            .write_cleanup_event(cleanup_audit_event(&entry))
                        {
                            report.errors.push(CleanupError {
                                path: path.clone(),
                                reason: sanitized_cleanup_error_reason(
                                    "audit_write_failed",
                                    error.to_string().as_str(),
                                ),
                            });
                        }
                    }
                    report.cleaned.push(entry);
                }
                Err(error) => report.errors.push(error),
            }
        }

        report
    }

    fn validate_session_directory_with_root(
        session_root: &Path,
        path: &Path,
    ) -> Result<ValidatedSessionDirectory, CleanupError> {
        let dir_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| cleanup_error(path, "invalid_session_id_format"))?;
        let session_id = parse_uuid_v4(dir_name)
            .map_err(|_| cleanup_error(path, "invalid_session_id_format"))?;
        let marker_path = path.join(SESSION_MARKER_FILE_NAME);
        if !marker_path.exists() {
            return Err(cleanup_error(path, "no_marker_file"));
        }
        let marker = SentinelSessionMarker::read_from_dir(path)
            .map_err(|_| cleanup_error(path, "invalid_marker"))?;
        if marker.session_id != session_id {
            return Err(cleanup_error(path, "session_id_mismatch"));
        }
        if !marker.is_valid_for_dir(path) {
            return Err(cleanup_error(path, "invalid_marker"));
        }

        let mut files = Vec::new();
        let mut file_names = Vec::new();
        for child in fs::read_dir(path).map_err(|_| cleanup_error(path, "read_dir_failed"))? {
            let child = child.map_err(|_| cleanup_error(path, "read_dir_entry_failed"))?;
            let child_path = child.path();
            let child_name = child
                .file_name()
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| cleanup_error(path, "invalid_file_name"))?;
            let metadata = fs::symlink_metadata(&child_path)
                .map_err(|_| cleanup_error(path, "metadata_failed"))?;
            if metadata.file_type().is_dir() {
                return Err(cleanup_error(path, "unknown_file"));
            }
            if !is_known_session_file(&child_name) {
                return Err(cleanup_error(path, "unknown_file"));
            }
            files.push(child_path);
            file_names.push(child_name);
        }

        validate_cleanup_paths(session_root, path, &files)?;
        marker_file_last(&mut files, &mut file_names);
        Ok(ValidatedSessionDirectory {
            marker,
            files,
            file_names,
        })
    }
}

fn cleanup_error(path: &Path, reason: impl Into<String>) -> CleanupError {
    CleanupError {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn parse_uuid_v4(value: &str) -> Result<Uuid, ()> {
    let session_id = Uuid::parse_str(value).map_err(|_| ())?;
    if session_id.get_version_num() == 4 {
        Ok(session_id)
    } else {
        Err(())
    }
}

fn is_known_session_file(name: &str) -> bool {
    matches!(
        name,
        SESSION_MARKER_FILE_NAME
            | "session.db"
            | "session.db-wal"
            | "session.db-shm"
            | "session.db-journal"
            | "audit.log"
            | SESSION_AUDIT_FILE_NAME
    ) || is_known_session_db_sidecar(name)
        || is_known_capture_import_preview_file(name)
}

fn is_known_session_db_sidecar(name: &str) -> bool {
    name.strip_prefix("session.db-mj").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_alphanumeric())
    })
}

fn is_known_capture_import_preview_file(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(CAPTURE_IMPORT_PREVIEW_FILE_PREFIX) else {
        return false;
    };
    let Some(preview_id) = suffix.strip_suffix(CAPTURE_IMPORT_PREVIEW_FILE_SUFFIX) else {
        return false;
    };
    parse_uuid_v4(preview_id).is_ok()
}

fn validate_cleanup_paths(
    session_root: &Path,
    session_dir: &Path,
    files: &[PathBuf],
) -> Result<(), CleanupError> {
    let root =
        fs::canonicalize(session_root).map_err(|_| cleanup_error(session_dir, "path_traversal"))?;
    let session_dir_canonical =
        fs::canonicalize(session_dir).map_err(|_| cleanup_error(session_dir, "path_traversal"))?;
    if !session_dir_canonical.starts_with(&root) {
        return Err(cleanup_error(session_dir, "path_traversal"));
    }
    for file in files {
        let canonical =
            fs::canonicalize(file).map_err(|_| cleanup_error(session_dir, "path_traversal"))?;
        if !canonical.starts_with(&root) {
            return Err(cleanup_error(session_dir, "path_traversal"));
        }
    }
    Ok(())
}

fn marker_file_last(files: &mut [PathBuf], file_names: &mut [String]) {
    let marker_index = file_names
        .iter()
        .position(|name| name == SESSION_MARKER_FILE_NAME);
    if let Some(marker_index) = marker_index {
        let last_index = file_names.len().saturating_sub(1);
        files.swap(marker_index, last_index);
        file_names.swap(marker_index, last_index);
    }
}

fn cleanup_audit_event(entry: &CleanupEntry) -> CleanupAuditEvent {
    CleanupAuditEvent {
        timestamp: Timestamp::now().to_string(),
        event: "abandoned_session_cleaned".to_string(),
        session_id: entry.session_id.to_string(),
        directory_path: redact_configured_path(&entry.path, "session"),
        files_deleted: entry.files_deleted.clone(),
        reason: "found_on_startup".to_string(),
    }
}

fn append_cleanup_audit(audit_root: &Path, event: CleanupAuditEvent) -> StorageResult<()> {
    fs::create_dir_all(audit_root)?;
    let audit_path = audit_root.join(CLEANUP_AUDIT_FILE_NAME);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)?;
    writeln!(file, "{}", serde_json::to_string(&event)?)?;
    Ok(())
}

fn sanitized_cleanup_error_reason(reason: &str, _detail: &str) -> String {
    reason.to_string()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelSessionMarker {
    pub marker: String,
    pub version: u32,
    pub session_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub app_version: String,
    pub session_mode: String,
}

pub type SessionMarker = SentinelSessionMarker;

impl SentinelSessionMarker {
    pub fn new(session_id: Uuid, session_mode: SessionMode) -> Self {
        Self {
            marker: SESSION_MARKER_VALUE.to_string(),
            version: SESSION_MARKER_VERSION,
            session_id,
            created_at: Utc::now(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            session_mode: session_mode.as_str().to_string(),
        }
    }

    pub fn write_to_dir(&self, session_root: &Path) -> StorageResult<()> {
        fs::create_dir_all(session_root)?;
        let marker_path = session_root.join(SESSION_MARKER_FILE_NAME);
        fs::write(marker_path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn read_from_dir(session_root: &Path) -> StorageResult<Self> {
        let marker = fs::read_to_string(session_root.join(SESSION_MARKER_FILE_NAME))?;
        let marker: Self = serde_json::from_str(&marker)?;
        if marker.marker != SESSION_MARKER_VALUE || marker.version != SESSION_MARKER_VERSION {
            return Err(StorageError::InvalidRecord {
                store_kind: "session_marker".to_string(),
                reason: "marker format is not recognized".to_string(),
            });
        }
        Ok(marker)
    }

    pub fn is_valid_for_dir(&self, session_root: &Path) -> bool {
        session_root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == self.session_id.to_string())
            && self.marker == SESSION_MARKER_VALUE
            && self.version == SESSION_MARKER_VERSION
            && matches!(
                self.session_mode.as_str(),
                "ephemeral" | "portable-no-retention"
            )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreferenceRecord {
    pub key: String,
    pub value: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PreferencesDocument {
    schema_version: u16,
    records: BTreeMap<String, PreferenceRecord>,
}

impl Default for PreferencesDocument {
    fn default() -> Self {
        Self {
            schema_version: 1,
            records: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreferencesStore {
    path: PathBuf,
}

impl PreferencesStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn set(&self, key: impl Into<String>, value: impl Into<String>) -> StorageResult<()> {
        let key = key.into();
        let value = value.into();
        validate_preference(&key, &value)?;

        let mut document = self.read_document()?;
        document.records.insert(
            key.clone(),
            PreferenceRecord {
                key,
                value,
                updated_at: Timestamp::now().to_string(),
            },
        );
        self.write_document(&document)
    }

    pub fn get(&self, key: &str) -> StorageResult<Option<String>> {
        validate_preference_key(key)?;
        Ok(self
            .read_document()?
            .records
            .get(key)
            .map(|record| record.value.clone()))
    }

    fn read_document(&self) -> StorageResult<PreferencesDocument> {
        if !self.path.exists() {
            return Ok(PreferencesDocument::default());
        }
        let content = fs::read_to_string(&self.path)?;
        if content.trim().is_empty() {
            return Ok(PreferencesDocument::default());
        }
        Ok(serde_json::from_str(&content)?)
    }

    fn write_document(&self, document: &PreferencesDocument) -> StorageResult<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, serde_json::to_string_pretty(document)?)?;
        Ok(())
    }
}

fn validate_existing_path_within_root(path: &Path, allowed_root: &Path) -> StorageResult<()> {
    let path = fs::canonicalize(path)?;
    let allowed_root = fs::canonicalize(allowed_root)?;
    if path.starts_with(&allowed_root) {
        Ok(())
    } else {
        Err(StorageError::InvalidRecord {
            store_kind: "session_root".to_string(),
            reason: "resolved path escapes the allowed Sentinel Guard root".to_string(),
        })
    }
}

fn append_session_audit(local_app_root: &Path, event: serde_json::Value) -> StorageResult<()> {
    fs::create_dir_all(local_app_root)?;
    let audit_path = local_app_root.join(SESSION_AUDIT_FILE_NAME);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)?;
    writeln!(file, "{}", serde_json::to_string(&event)?)?;
    Ok(())
}

fn redact_configured_path(path: &Path, label: &str) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("[{label}:{name}]"))
        .unwrap_or_else(|| format!("[{label}]"))
}

fn validate_preference(key: &str, value: &str) -> StorageResult<()> {
    validate_preference_key(key)?;
    validate_preference_value(key, value)
}

fn validate_preference_key(key: &str) -> StorageResult<()> {
    if key.trim().is_empty() || key.len() > 128 {
        return Err(invalid_preference("preference key is empty or too long"));
    }

    let allowed = matches!(
        key,
        "theme"
            | "ui.theme"
            | "ui.layout"
            | "ui.font_size"
            | "ui.last_view"
            | "notifications.enabled"
    ) || (key.starts_with("plugin.") && key.ends_with(".enabled"));

    if !allowed || contains_forbidden_preference_marker(key) {
        return Err(invalid_preference(
            "preference key is outside the UI-only allowlist",
        ));
    }

    Ok(())
}

fn validate_preference_value(key: &str, value: &str) -> StorageResult<()> {
    if value.len() > 512 {
        return Err(invalid_preference("preference value is too long"));
    }
    if contains_forbidden_preference_marker(value)
        || looks_like_ipv4(value)
        || looks_like_hostname(value)
    {
        return Err(invalid_preference(format!(
            "preference `{key}` contains security-relevant data"
        )));
    }
    Ok(())
}

fn contains_forbidden_preference_marker(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    FORBIDDEN_PREFERENCE_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
}

fn looks_like_ipv4(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.chars().all(|ch| ch.is_ascii_digit())
                && part.parse::<u8>().is_ok()
        })
}

fn looks_like_hostname(value: &str) -> bool {
    value.contains('.')
        && value.chars().any(|ch| ch.is_ascii_alphabetic())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
}

fn invalid_preference(reason: impl Into<String>) -> StorageError {
    StorageError::InvalidRecord {
        store_kind: "preferences".to_string(),
        reason: reason.into(),
    }
}

fn portable_preference_storage_error(error: impl ToString) -> StorageError {
    StorageError::InvalidRecord {
        store_kind: "portable_preferences".to_string(),
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DatabaseConfig, DatabaseRuntime, LogicalRecord, LogicalStore, SqliteStoreFactory, StoreKind,
    };
    use sentinel_contracts::{FlowId, PageRequest, QueryRequest, QueryScope, SchemaVersion};

    #[test]
    fn two_ephemeral_launches_produce_different_session_ids(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("two-launches")?;
        let first = SessionLifecycle::start(SessionMode::Ephemeral, roots.resolver())?;
        let first_session_id = first.config().session_id;
        assert_eq!(first.config().session_mode, SessionMode::Ephemeral);
        assert_eq!(first.config().database_mode, SessionDatabaseMode::InMemory);
        drop(first);
        let second = SessionLifecycle::start(SessionMode::Ephemeral, roots.resolver())?;

        assert_ne!(first_session_id, second.config().session_id);
        drop(second);
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn ephemeral_session_directory_is_created_with_marker() -> Result<(), Box<dyn std::error::Error>>
    {
        let roots = TestRoots::new("created")?;
        let lifecycle = SessionLifecycle::start(SessionMode::Ephemeral, roots.resolver())?;

        assert!(lifecycle.config().session_root.exists());
        assert!(lifecycle
            .config()
            .session_root
            .join(SESSION_MARKER_FILE_NAME)
            .exists());
        drop(lifecycle);
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn observations_written_to_one_session_are_not_visible_to_next(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("isolation")?;
        let first = SessionLifecycle::start(SessionMode::Ephemeral, roots.resolver())?;
        let first_runtime = DatabaseRuntime::bootstrap_with_session(
            DatabaseConfig::for_session("0.1.0", first.config().clone()),
            first.clone(),
        )?;
        first_runtime.handle().with_connection(|connection| {
            let factory = SqliteStoreFactory::new(connection);
            factory.flow_store().append(LogicalRecord::metadata_only(
                FlowId::new_v4(),
                SchemaVersion::new(1, 0, 0),
                StoreKind::Flow.default_storage_privacy_class(),
                json!({ "summary_redacted": "session A metadata" }),
            ))
        })?;
        drop(first_runtime);
        drop(first);

        let second = SessionLifecycle::start(SessionMode::Ephemeral, roots.resolver())?;
        let second_runtime = DatabaseRuntime::bootstrap_with_session(
            DatabaseConfig::for_session("0.1.0", second.config().clone()),
            second.clone(),
        )?;
        let second_flow_count = second_runtime.handle().with_connection(|connection| {
            let factory = SqliteStoreFactory::new(connection);
            Ok(factory
                .flow_store()
                .query(QueryRequest::new(QueryScope::Global).with_page(PageRequest::default()))?
                .page
                .items
                .len())
        })?;

        assert_eq!(second_flow_count, 0);
        drop(second_runtime);
        drop(second);
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn normal_shutdown_deletes_ephemeral_session_directory(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("shutdown")?;
        let session_root = {
            let lifecycle = SessionLifecycle::start(SessionMode::Ephemeral, roots.resolver())?;
            let session_root = lifecycle.config().session_root.clone();
            assert!(session_root.exists());
            session_root
        };

        assert!(!session_root.exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn portable_session_uses_app_local_temp_layout() -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("portable-layout")?;
        let portable_root = roots.root.join("portable");
        let lifecycle = SessionLifecycle::start(
            SessionMode::PortableNoRetention,
            SessionRootResolver::for_portable_root(portable_root.clone()),
        )?;
        let session_root = lifecycle.config().session_root.clone();

        assert_eq!(
            lifecycle.config().session_mode,
            SessionMode::PortableNoRetention
        );
        assert_eq!(
            lifecycle.config().database_mode,
            SessionDatabaseMode::InMemory
        );
        assert!(session_root.starts_with(portable_root.join("temp").join("sessions")));
        assert_eq!(
            lifecycle.config().preferences_path,
            portable_root
                .join("data")
                .join("preferences")
                .join("ui_preferences.json")
        );
        assert_eq!(
            lifecycle.config().portable_root.as_deref(),
            Some(portable_root.as_path())
        );
        for directory in [
            portable_root.join("data").join("preferences"),
            portable_root.join("data").join("exports"),
            portable_root.join("data").join("reports"),
            portable_root.join("logs"),
            portable_root.join("temp").join("sessions"),
        ] {
            assert!(
                directory.exists(),
                "missing portable directory {directory:?}"
            );
        }

        drop(lifecycle);
        assert!(!session_root.exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn portable_abandoned_session_with_valid_marker_is_cleaned(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("portable-abandoned")?;
        let portable_root = roots.root.join("portable");
        let sessions_root = portable_root.join("temp").join("sessions");
        let abandoned_id = Uuid::new_v4();
        let abandoned_root = sessions_root.join(abandoned_id.to_string());
        SessionMarker::new(abandoned_id, SessionMode::PortableNoRetention)
            .write_to_dir(&abandoned_root)?;

        let lifecycle = SessionLifecycle::start(
            SessionMode::PortableNoRetention,
            SessionRootResolver::for_portable_root(portable_root.clone()),
        )?;

        assert!(!abandoned_root.exists());
        assert_eq!(
            lifecycle.config().cleaned_abandoned_sessions,
            vec![abandoned_id]
        );
        let audit_log =
            fs::read_to_string(portable_root.join("logs").join(CLEANUP_AUDIT_FILE_NAME))?;
        assert!(audit_log.contains("abandoned_session_cleaned"));
        assert!(audit_log.contains(&abandoned_id.to_string()));
        drop(lifecycle);
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn portable_app_started_audit_marker_is_session_scoped(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("portable-audit")?;
        let portable_root = roots.root.join("portable");
        let lifecycle = SessionLifecycle::start(
            SessionMode::PortableNoRetention,
            SessionRootResolver::for_portable_root(portable_root.clone()),
        )?;
        let session_root = lifecycle.config().session_root.clone();
        let session_audit = fs::read_to_string(session_root.join(SESSION_AUDIT_FILE_NAME))?;

        assert!(session_audit.contains("\"event_type\":\"app_started\""));
        assert!(session_audit.contains("\"profile_mode\":\"portable-no-retention\""));
        assert!(session_audit.contains(&lifecycle.config().session_id.to_string()));

        drop(lifecycle);
        assert!(!session_root.exists());
        assert!(!portable_root
            .join("logs")
            .join(SESSION_AUDIT_FILE_NAME)
            .exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn preferences_survive_session_teardown() -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("preferences")?;
        {
            let lifecycle = SessionLifecycle::start(SessionMode::Ephemeral, roots.resolver())?;
            lifecycle.preferences_store().set("theme", "dark")?;
        }

        let next = SessionLifecycle::start(SessionMode::Ephemeral, roots.resolver())?;
        assert_eq!(
            next.preferences_store().get("theme")?,
            Some("dark".to_string())
        );
        assert!(next.config().preferences_path.exists());
        drop(next);
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn preferences_reject_security_relevant_data() -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("preference-privacy")?;
        let lifecycle = SessionLifecycle::start(SessionMode::Ephemeral, roots.resolver())?;

        assert!(lifecycle
            .preferences_store()
            .set("theme", "evil.example.com")
            .is_err());
        assert!(lifecycle
            .preferences_store()
            .set("session_id", "anything")
            .is_err());
        drop(lifecycle);
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn abandoned_session_with_valid_marker_is_cleaned_on_startup(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("abandoned")?;
        let abandoned_id = Uuid::new_v4();
        let abandoned_root = roots.sessions_root.join(abandoned_id.to_string());
        SessionMarker::new(abandoned_id, SessionMode::Ephemeral).write_to_dir(&abandoned_root)?;

        let lifecycle = SessionLifecycle::start(SessionMode::Ephemeral, roots.resolver())?;

        assert!(!abandoned_root.exists());
        assert_eq!(
            lifecycle.config().cleaned_abandoned_sessions,
            vec![abandoned_id]
        );
        drop(lifecycle);
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn dry_run_session_cleanup_identifies_abandoned_sessions_without_deleting(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("cleanup-dry-run")?;
        let abandoned_id = Uuid::new_v4();
        let abandoned_root = roots.sessions_root.join(abandoned_id.to_string());
        SessionMarker::new(abandoned_id, SessionMode::Ephemeral).write_to_dir(&abandoned_root)?;
        fs::write(abandoned_root.join("session.db"), b"metadata only")?;
        fs::write(abandoned_root.join("session.db-wal"), b"metadata only wal")?;

        let report = SessionCleanup::cleanup_abandoned_sessions(&roots.sessions_root, true);

        assert_eq!(report.cleaned.len(), 1);
        assert_eq!(report.cleaned[0].session_id, abandoned_id);
        assert!(report.cleaned[0].dry_run);
        assert!(abandoned_root.exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn non_sentinel_directories_are_skipped_by_session_cleanup(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("cleanup-not-uuid")?;
        let unknown_root = roots.sessions_root.join("not-a-uuid");
        fs::create_dir_all(&unknown_root)?;

        let report = SessionCleanup::cleanup_abandoned_sessions(&roots.sessions_root, false);

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].reason, "invalid_session_id_format");
        assert!(unknown_root.exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn directory_without_marker_is_skipped_by_session_cleanup(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("cleanup-no-marker")?;
        let abandoned_id = Uuid::new_v4();
        let abandoned_root = roots.sessions_root.join(abandoned_id.to_string());
        fs::create_dir_all(&abandoned_root)?;

        let report = SessionCleanup::cleanup_abandoned_sessions(&roots.sessions_root, false);

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].reason, "no_marker_file");
        assert!(abandoned_root.exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn directory_with_invalid_marker_is_skipped_by_session_cleanup(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("cleanup-invalid-marker")?;
        let abandoned_id = Uuid::new_v4();
        let abandoned_root = roots.sessions_root.join(abandoned_id.to_string());
        fs::create_dir_all(&abandoned_root)?;
        fs::write(
            abandoned_root.join(SESSION_MARKER_FILE_NAME),
            r#"{"marker":"NOT_SENTINEL"}"#,
        )?;

        let report = SessionCleanup::cleanup_abandoned_sessions(&roots.sessions_root, false);

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].reason, "invalid_marker");
        assert!(abandoned_root.exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn directory_with_session_id_mismatch_is_skipped_by_session_cleanup(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("cleanup-id-mismatch")?;
        let directory_id = Uuid::new_v4();
        let marker_id = Uuid::new_v4();
        let abandoned_root = roots.sessions_root.join(directory_id.to_string());
        SessionMarker::new(marker_id, SessionMode::Ephemeral).write_to_dir(&abandoned_root)?;

        let report = SessionCleanup::cleanup_abandoned_sessions(&roots.sessions_root, false);

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].reason, "session_id_mismatch");
        assert!(abandoned_root.exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn directory_with_unknown_file_is_skipped_without_partial_delete(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("cleanup-unknown-file")?;
        let abandoned_id = Uuid::new_v4();
        let abandoned_root = roots.sessions_root.join(abandoned_id.to_string());
        SessionMarker::new(abandoned_id, SessionMode::Ephemeral).write_to_dir(&abandoned_root)?;
        fs::write(abandoned_root.join("passwords.txt"), b"do not touch")?;

        let report = SessionCleanup::cleanup_abandoned_sessions(&roots.sessions_root, false);

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].reason, "unknown_file");
        assert!(abandoned_root.join(SESSION_MARKER_FILE_NAME).exists());
        assert!(abandoned_root.join("passwords.txt").exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn session_db_prefixed_unknown_file_is_skipped_without_partial_delete(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("cleanup-session-db-prefix")?;
        let abandoned_id = Uuid::new_v4();
        let abandoned_root = roots.sessions_root.join(abandoned_id.to_string());
        SessionMarker::new(abandoned_id, SessionMode::Ephemeral).write_to_dir(&abandoned_root)?;
        fs::write(
            abandoned_root.join("session.db-passwords.txt"),
            b"do not touch",
        )?;

        let report = SessionCleanup::cleanup_abandoned_sessions(&roots.sessions_root, false);

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].reason, "unknown_file");
        assert!(abandoned_root.join("session.db-passwords.txt").exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn capture_import_preview_files_are_removed_by_session_cleanup(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("cleanup-capture-import-preview")?;
        let abandoned_id = Uuid::new_v4();
        let preview_id = Uuid::new_v4();
        let abandoned_root = roots.sessions_root.join(abandoned_id.to_string());
        SessionMarker::new(abandoned_id, SessionMode::PortableNoRetention)
            .write_to_dir(&abandoned_root)?;
        fs::write(
            abandoned_root.join(format!(
                "{CAPTURE_IMPORT_PREVIEW_FILE_PREFIX}{preview_id}{CAPTURE_IMPORT_PREVIEW_FILE_SUFFIX}"
            )),
            br#"{"preview_id":"redacted"}"#,
        )?;

        let report = SessionCleanup::cleanup_abandoned_sessions(&roots.sessions_root, false);

        assert_eq!(report.cleaned.len(), 1);
        assert_eq!(report.cleaned[0].session_id, abandoned_id);
        assert!(!abandoned_root.exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn non_v4_uuid_directory_is_skipped_by_session_cleanup(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("cleanup-non-v4-uuid")?;
        let unknown_root = roots
            .sessions_root
            .join("123e4567-e89b-12d3-a456-426614174000");
        fs::create_dir_all(&unknown_root)?;

        let report = SessionCleanup::cleanup_abandoned_sessions(&roots.sessions_root, false);

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].reason, "invalid_session_id_format");
        assert!(unknown_root.exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn marker_version_mismatch_is_skipped_by_session_cleanup(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("cleanup-marker-version")?;
        let abandoned_id = Uuid::new_v4();
        let abandoned_root = roots.sessions_root.join(abandoned_id.to_string());
        fs::create_dir_all(&abandoned_root)?;
        let mut marker = SessionMarker::new(abandoned_id, SessionMode::Ephemeral);
        marker.version += 1;
        fs::write(
            abandoned_root.join(SESSION_MARKER_FILE_NAME),
            serde_json::to_string_pretty(&marker)?,
        )?;

        let report = SessionCleanup::cleanup_abandoned_sessions(&roots.sessions_root, false);

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].reason, "invalid_marker");
        assert!(abandoned_root.exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn path_traversal_via_symlink_is_detected_when_symlink_creation_is_available(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("cleanup-symlink")?;
        let abandoned_id = Uuid::new_v4();
        let abandoned_root = roots.sessions_root.join(abandoned_id.to_string());
        let outside_root = roots.root.join("outside");
        fs::create_dir_all(&outside_root)?;
        SessionMarker::new(abandoned_id, SessionMode::Ephemeral).write_to_dir(&abandoned_root)?;
        let symlink_path = abandoned_root.join("session.db-link");
        if create_dir_symlink(&outside_root, &symlink_path).is_err() {
            roots.cleanup();
            return Ok(());
        }

        let report = SessionCleanup::cleanup_abandoned_sessions(&roots.sessions_root, false);

        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].reason, "path_traversal");
        assert!(abandoned_root.exists());
        assert!(outside_root.exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn session_cleanup_handles_deletion_failure_without_panic(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("cleanup-delete-failure")?;
        let abandoned_id = Uuid::new_v4();
        let abandoned_root = roots.sessions_root.join(abandoned_id.to_string());
        SessionMarker::new(abandoned_id, SessionMode::Ephemeral).write_to_dir(&abandoned_root)?;
        let locked_file = abandoned_root.join("session.db");
        fs::write(&locked_file, b"metadata only")?;
        let _handle = fs::OpenOptions::new().read(true).open(&locked_file)?;

        let report = SessionCleanup::cleanup_abandoned_sessions(&roots.sessions_root, false);

        assert!(report.cleaned.len() + report.errors.len() == 1);
        if let Some(error) = report.errors.first() {
            assert_eq!(error.reason, "deletion_failed");
            assert!(abandoned_root.exists());
        }
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn cleanup_dry_run_does_not_write_portable_audit_log() -> Result<(), Box<dyn std::error::Error>>
    {
        let roots = TestRoots::new("cleanup-dry-run-audit")?;
        let portable_root = roots.root.join("portable");
        let sessions_root = portable_root.join("temp").join("sessions");
        let audit_root = portable_root.join("logs");
        fs::create_dir_all(&sessions_root)?;
        let abandoned_id = Uuid::new_v4();
        let abandoned_root = sessions_root.join(abandoned_id.to_string());
        SessionMarker::new(abandoned_id, SessionMode::PortableNoRetention)
            .write_to_dir(&abandoned_root)?;

        let report = SessionCleanup::cleanup_abandoned_sessions_with_audit(
            &sessions_root,
            &audit_root,
            true,
        );

        assert_eq!(report.cleaned.len(), 1);
        assert!(report.cleaned[0].dry_run);
        assert!(abandoned_root.exists());
        assert!(!audit_root.join(CLEANUP_AUDIT_FILE_NAME).exists());
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn portable_restart_cleans_crash_left_session_and_keeps_no_retention(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("portable-restart-cleanup")?;
        let portable_root = roots.root.join("portable");
        let sessions_root = portable_root.join("temp").join("sessions");
        let abandoned_id = Uuid::new_v4();
        let abandoned_root = sessions_root.join(abandoned_id.to_string());
        SessionMarker::new(abandoned_id, SessionMode::PortableNoRetention)
            .write_to_dir(&abandoned_root)?;
        fs::write(abandoned_root.join("session.db-wal"), b"metadata only wal")?;

        let lifecycle = SessionLifecycle::start(
            SessionMode::PortableNoRetention,
            SessionRootResolver::for_portable_root(portable_root.clone()),
        )?;
        let current_root = lifecycle.config().session_root.clone();

        assert_ne!(lifecycle.config().session_id, abandoned_id);
        assert!(!abandoned_root.exists());
        assert!(current_root.exists());
        assert_eq!(
            lifecycle.config().cleaned_abandoned_sessions,
            vec![abandoned_id]
        );

        drop(lifecycle);
        assert!(!current_root.exists());
        let remaining_sessions = fs::read_dir(&sessions_root)?.count();
        assert_eq!(remaining_sessions, 0);
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn unknown_session_directories_are_not_deleted() -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("unknown")?;
        let unknown_root = roots.sessions_root.join("not-a-sentinel-session");
        fs::create_dir_all(&unknown_root)?;

        let lifecycle = SessionLifecycle::start(SessionMode::Ephemeral, roots.resolver())?;

        assert!(unknown_root.exists());
        assert_eq!(
            lifecycle.config().skipped_unknown_entries,
            vec!["not-a-sentinel-session".to_string()]
        );
        drop(lifecycle);
        roots.cleanup();
        Ok(())
    }

    #[test]
    fn demo_flag_resolves_to_installed_mode() -> Result<(), Box<dyn std::error::Error>> {
        let roots = TestRoots::new("installed")?;
        let lifecycle = SessionLifecycle::start(SessionMode::Demo, roots.resolver())?;

        assert_eq!(lifecycle.config().session_mode, SessionMode::Installed);
        assert_eq!(
            lifecycle.config().database_mode,
            SessionDatabaseMode::Persistent
        );
        assert_eq!(lifecycle.config().session_root, roots.local_app_root);
        drop(lifecycle);
        roots.cleanup();
        Ok(())
    }

    struct TestRoots {
        root: PathBuf,
        sessions_root: PathBuf,
        local_app_root: PathBuf,
    }

    #[cfg(windows)]
    fn create_dir_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[cfg(unix)]
    fn create_dir_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(not(any(windows, unix)))]
    fn create_dir_symlink(_target: &Path, _link: &Path) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlinks unsupported",
        ))
    }

    impl TestRoots {
        fn new(label: &str) -> StorageResult<Self> {
            let root = env::current_dir()
                .unwrap_or_else(|_| env::temp_dir())
                .join("target")
                .join("session-tests")
                .join(format!("{label}-{}", Uuid::new_v4()));
            let sessions_root = root.join(APP_DIR_NAME).join(SESSIONS_DIR_NAME);
            let local_app_root = root.join("local").join(APP_DIR_NAME);
            fs::create_dir_all(&sessions_root)?;
            fs::create_dir_all(&local_app_root)?;
            Ok(Self {
                root,
                sessions_root,
                local_app_root,
            })
        }

        fn resolver(&self) -> SessionRootResolver {
            SessionRootResolver::for_roots(self.sessions_root.clone(), self.local_app_root.clone())
        }

        fn cleanup(&self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
