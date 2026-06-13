use crate::error::{StorageError, StorageResult};
use crate::privacy::{DataClass, RetentionClass};
use crate::store::{RetentionDeleteRequest, RetentionDeleteSummary, StoreKind};
use chrono::Duration;
use sentinel_contracts::{
    AuditId, AuditRef, PrivacyClass, RedactedDataCategory, RedactionSummary, ReportExportPolicy,
    RetentionPolicy, Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

const TOKEN_DIGEST_KEY_REF: &str = "local-installation-token-key:v1";
const HASH_DIGEST_KEY_REF: &str = "local-correlation-hash-key:v1";
const DPAPI_MASTER_KEY_REF: &str = "dpapi-current-user-local-master-key:v1";
const SHA256_ALGORITHM: &str = "sha256";
const DPAPI_CURRENT_USER_METHOD: &str = "windows-dpapi-current-user";
#[cfg(windows)]
const DPAPI_STATUS_AVAILABLE: &str = "available";
#[cfg(not(windows))]
const DPAPI_STATUS_UNSUPPORTED: &str = "unsupported_non_windows";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivacyServiceError {
    ExportDenied(String),
    RetentionDenied(String),
}

impl fmt::Display for PrivacyServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExportDenied(reason) => write!(f, "export denied: {reason}"),
            Self::RetentionDenied(reason) => write!(f, "retention denied: {reason}"),
        }
    }
}

impl std::error::Error for PrivacyServiceError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveFieldKind {
    PublicMetadata,
    InternalMetadata,
    Username,
    Sid,
    LocalPath,
    CommandLine,
    Url,
    QueryString,
    Header,
    AuthorizationHeader,
    Cookie,
    Token,
    Credential,
    ApiKey,
    PrivateKey,
    HttpBody,
    Payload,
    RawPacket,
    FormContent,
    FileContent,
    IpAddress,
    HostName,
    AlreadyRedacted,
    AlreadyTokenized,
}

impl SensitiveFieldKind {
    fn redacted_category(&self) -> Option<RedactedDataCategory> {
        match self {
            Self::RawPacket => Some(RedactedDataCategory::RawPacket),
            Self::Payload => Some(RedactedDataCategory::Payload),
            Self::HttpBody => Some(RedactedDataCategory::HttpBody),
            Self::Cookie => Some(RedactedDataCategory::Cookie),
            Self::Token | Self::AuthorizationHeader => Some(RedactedDataCategory::Token),
            Self::Credential => Some(RedactedDataCategory::Credential),
            Self::ApiKey => Some(RedactedDataCategory::ApiKey),
            Self::PrivateKey => Some(RedactedDataCategory::PrivateKey),
            Self::QueryString => Some(RedactedDataCategory::FullQueryString),
            Self::FormContent => Some(RedactedDataCategory::FormContent),
            Self::CommandLine => Some(RedactedDataCategory::CommandLine),
            Self::LocalPath => Some(RedactedDataCategory::LocalPath),
            Self::Username => Some(RedactedDataCategory::Username),
            Self::Sid => Some(RedactedDataCategory::Sid),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyAction {
    Keep,
    Redact,
    Tokenize,
    Hash,
    DenyExport,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensitiveFieldClassification {
    pub field_path: String,
    pub field_kind: SensitiveFieldKind,
    pub privacy_class: PrivacyClass,
    pub action: PrivacyAction,
    pub export_allowed_after_action: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SensitiveFieldClassifier;

impl SensitiveFieldClassifier {
    pub fn classify_privacy_class(
        &self,
        field_path: impl Into<String>,
        privacy_class: PrivacyClass,
    ) -> SensitiveFieldClassification {
        let (field_kind, action, export_allowed_after_action) = match privacy_class {
            PrivacyClass::Public => (
                SensitiveFieldKind::PublicMetadata,
                PrivacyAction::Keep,
                true,
            ),
            PrivacyClass::Internal => (
                SensitiveFieldKind::InternalMetadata,
                PrivacyAction::Keep,
                true,
            ),
            PrivacyClass::Sensitive => (
                SensitiveFieldKind::InternalMetadata,
                PrivacyAction::Redact,
                true,
            ),
            PrivacyClass::Secret => (
                SensitiveFieldKind::Credential,
                PrivacyAction::DenyExport,
                false,
            ),
            PrivacyClass::Redacted => (
                SensitiveFieldKind::AlreadyRedacted,
                PrivacyAction::Keep,
                true,
            ),
            PrivacyClass::Tokenized => (
                SensitiveFieldKind::AlreadyTokenized,
                PrivacyAction::Keep,
                true,
            ),
        };

        SensitiveFieldClassification {
            field_path: field_path.into(),
            field_kind,
            privacy_class,
            action,
            export_allowed_after_action,
        }
    }

    pub fn classify_field(&self, field_path: impl Into<String>) -> SensitiveFieldClassification {
        let field_path = field_path.into();
        let normalized = field_path.to_ascii_lowercase();
        let (field_kind, privacy_class, action, export_allowed_after_action) =
            if contains_any(&normalized, &["raw_packet", "packet_bytes"]) {
                (
                    SensitiveFieldKind::RawPacket,
                    PrivacyClass::Secret,
                    PrivacyAction::DenyExport,
                    false,
                )
            } else if contains_any(&normalized, &["payload", "raw_payload"]) {
                (
                    SensitiveFieldKind::Payload,
                    PrivacyClass::Secret,
                    PrivacyAction::DenyExport,
                    false,
                )
            } else if contains_any(&normalized, &["http_body", "request_body", "response_body"]) {
                (
                    SensitiveFieldKind::HttpBody,
                    PrivacyClass::Secret,
                    PrivacyAction::DenyExport,
                    false,
                )
            } else if contains_any(&normalized, &["authorization", "auth_header"]) {
                (
                    SensitiveFieldKind::AuthorizationHeader,
                    PrivacyClass::Secret,
                    PrivacyAction::DenyExport,
                    false,
                )
            } else if normalized.contains("cookie") {
                (
                    SensitiveFieldKind::Cookie,
                    PrivacyClass::Secret,
                    PrivacyAction::DenyExport,
                    false,
                )
            } else if contains_any(&normalized, &["api_key", "apikey"]) {
                (
                    SensitiveFieldKind::ApiKey,
                    PrivacyClass::Secret,
                    PrivacyAction::DenyExport,
                    false,
                )
            } else if normalized.contains("private_key") {
                (
                    SensitiveFieldKind::PrivateKey,
                    PrivacyClass::Secret,
                    PrivacyAction::DenyExport,
                    false,
                )
            } else if contains_any(&normalized, &["token", "credential", "password", "secret"]) {
                (
                    SensitiveFieldKind::Credential,
                    PrivacyClass::Secret,
                    PrivacyAction::DenyExport,
                    false,
                )
            } else if normalized.contains("query") {
                (
                    SensitiveFieldKind::QueryString,
                    PrivacyClass::Sensitive,
                    PrivacyAction::Redact,
                    true,
                )
            } else if normalized.contains("command") {
                (
                    SensitiveFieldKind::CommandLine,
                    PrivacyClass::Sensitive,
                    PrivacyAction::Redact,
                    true,
                )
            } else if contains_any(&normalized, &["path", "local_file"]) {
                (
                    SensitiveFieldKind::LocalPath,
                    PrivacyClass::Sensitive,
                    PrivacyAction::Redact,
                    true,
                )
            } else if contains_any(&normalized, &["username", "user_name", "account_name"]) {
                (
                    SensitiveFieldKind::Username,
                    PrivacyClass::Sensitive,
                    PrivacyAction::Tokenize,
                    true,
                )
            } else if normalized.contains("sid") {
                (
                    SensitiveFieldKind::Sid,
                    PrivacyClass::Sensitive,
                    PrivacyAction::Tokenize,
                    true,
                )
            } else if normalized.contains("url") {
                (
                    SensitiveFieldKind::Url,
                    PrivacyClass::Sensitive,
                    PrivacyAction::Redact,
                    true,
                )
            } else if normalized.contains("header") {
                (
                    SensitiveFieldKind::Header,
                    PrivacyClass::Sensitive,
                    PrivacyAction::Redact,
                    true,
                )
            } else {
                (
                    SensitiveFieldKind::InternalMetadata,
                    PrivacyClass::Internal,
                    PrivacyAction::Keep,
                    true,
                )
            };

        SensitiveFieldClassification {
            field_path,
            field_kind,
            privacy_class,
            action,
            export_allowed_after_action,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenizationScope {
    LocalInstallation,
    ExportSession,
    RecordScoped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenizedValue {
    pub token: String,
    pub scope: TokenizationScope,
    pub key_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokenizer {
    pub scope: TokenizationScope,
    pub key_ref: String,
}

impl Tokenizer {
    pub fn local_installation() -> Self {
        Self {
            scope: TokenizationScope::LocalInstallation,
            key_ref: TOKEN_DIGEST_KEY_REF.to_string(),
        }
    }

    pub fn tokenize(&self, label: &str, value: &str) -> TokenizedValue {
        let digest = privacy_digest("privacy-token", &self.key_ref, label, value);
        TokenizedValue {
            token: format!("{label}#{digest}"),
            scope: self.scope.clone(),
            key_ref: self.key_ref.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashingPolicy {
    pub algorithm: String,
    pub key_ref: Option<String>,
    pub not_for_production: bool,
}

impl HashingPolicy {
    pub fn local_correlation_sha256() -> Self {
        Self {
            algorithm: SHA256_ALGORITHM.to_string(),
            key_ref: Some(HASH_DIGEST_KEY_REF.to_string()),
            not_for_production: false,
        }
    }

    pub fn hash(&self, label: &str, value: &str) -> String {
        let key_ref = self.key_ref.as_deref().unwrap_or("unkeyed");
        let digest = privacy_digest("privacy-hash", key_ref, label, value);
        format!("{label}#{digest}")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionKeyHook {
    pub key_ref: String,
    pub key_version: u32,
    pub protection_method: String,
    pub status: String,
}

impl EncryptionKeyHook {
    pub fn local_dpapi_current_user() -> Self {
        Self {
            key_ref: DPAPI_MASTER_KEY_REF.to_string(),
            key_version: 1,
            protection_method: DPAPI_CURRENT_USER_METHOD.to_string(),
            status: dpapi_hook_status().to_string(),
        }
    }

    pub fn protect_local_master_key(
        &self,
        plaintext_key: &[u8],
    ) -> StorageResult<ProtectedLocalMasterKey> {
        if plaintext_key.is_empty() {
            return Err(key_protection_error(
                "local master key material must not be empty",
            ));
        }
        let protected_key = dpapi_protect(plaintext_key)?;
        Ok(ProtectedLocalMasterKey {
            key_ref: self.key_ref.clone(),
            key_version: self.key_version,
            protection_method: self.protection_method.clone(),
            protected_key,
            created_at: Timestamp::now(),
        })
    }

    pub fn unprotect_local_master_key(
        &self,
        protected: &ProtectedLocalMasterKey,
    ) -> StorageResult<Vec<u8>> {
        if protected.key_ref != self.key_ref {
            return Err(key_protection_error("protected key reference mismatch"));
        }
        if protected.key_version != self.key_version {
            return Err(key_protection_error("protected key version mismatch"));
        }
        if protected.protection_method != self.protection_method {
            return Err(key_protection_error("protected key method mismatch"));
        }
        if protected.protected_key.is_empty() {
            return Err(key_protection_error("protected key blob must not be empty"));
        }
        dpapi_unprotect(&protected.protected_key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedLocalMasterKey {
    pub key_ref: String,
    pub key_version: u32,
    pub protection_method: String,
    pub protected_key: Vec<u8>,
    pub created_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedactionResult {
    pub value: Value,
    pub redaction_summary: RedactionSummary,
    pub audit_ref: AuditRef,
}

#[derive(Clone, Debug)]
pub struct RedactionEngine {
    classifier: SensitiveFieldClassifier,
    tokenizer: Tokenizer,
    hashing_policy: HashingPolicy,
}

impl Default for RedactionEngine {
    fn default() -> Self {
        Self {
            classifier: SensitiveFieldClassifier,
            tokenizer: Tokenizer::local_installation(),
            hashing_policy: HashingPolicy::local_correlation_sha256(),
        }
    }
}

impl RedactionEngine {
    pub fn redact_json(&self, value: &Value) -> StorageResult<RedactionResult> {
        let mut categories = Vec::new();
        let redacted = self.redact_json_value("$", value, &mut categories);
        Ok(RedactionResult {
            value: redacted,
            redaction_summary: redaction_summary(categories, true),
            audit_ref: AuditRef::new("privacy.redaction")
                .map_err(|error| StorageError::Serialization(error.to_string()))?,
        })
    }

    pub fn redact_text(&self, field_kind: SensitiveFieldKind, value: &str) -> String {
        match field_kind {
            SensitiveFieldKind::Username => self.tokenizer.tokenize("user:local", value).token,
            SensitiveFieldKind::Sid => self.tokenizer.tokenize("sid:local", value).token,
            SensitiveFieldKind::LocalPath => redact_local_path(value),
            SensitiveFieldKind::Url => redact_url(value),
            SensitiveFieldKind::QueryString => "[REDACTED_QUERY_STRING]".to_string(),
            SensitiveFieldKind::Header => "[REDACTED_HEADER_METADATA]".to_string(),
            SensitiveFieldKind::AuthorizationHeader => {
                "[REDACTED_AUTHORIZATION_HEADER]".to_string()
            }
            SensitiveFieldKind::Cookie => "[REDACTED_COOKIE]".to_string(),
            SensitiveFieldKind::Token => "[REDACTED_TOKEN]".to_string(),
            SensitiveFieldKind::Credential => "[REDACTED_CREDENTIAL]".to_string(),
            SensitiveFieldKind::ApiKey => "[REDACTED_API_KEY]".to_string(),
            SensitiveFieldKind::PrivateKey => "[REDACTED_PRIVATE_KEY]".to_string(),
            SensitiveFieldKind::HttpBody => "[REDACTED_HTTP_BODY]".to_string(),
            SensitiveFieldKind::Payload => "[REDACTED_PAYLOAD]".to_string(),
            SensitiveFieldKind::RawPacket => "[REDACTED_RAW_PACKET]".to_string(),
            SensitiveFieldKind::FormContent => "[REDACTED_FORM_CONTENT]".to_string(),
            SensitiveFieldKind::FileContent => "[REDACTED_FILE_CONTENT]".to_string(),
            SensitiveFieldKind::CommandLine => "[REDACTED_COMMAND_LINE]".to_string(),
            SensitiveFieldKind::IpAddress => self.hashing_policy.hash("ip", value),
            SensitiveFieldKind::HostName => self.hashing_policy.hash("host", value),
            SensitiveFieldKind::PublicMetadata
            | SensitiveFieldKind::InternalMetadata
            | SensitiveFieldKind::AlreadyRedacted
            | SensitiveFieldKind::AlreadyTokenized => value.to_string(),
        }
    }

    fn redact_json_value(
        &self,
        path: &str,
        value: &Value,
        categories: &mut Vec<RedactedDataCategory>,
    ) -> Value {
        match value {
            Value::Object(map) => {
                let mut redacted = Map::new();
                for (key, nested) in map {
                    let field_path = format!("{path}.{key}");
                    let classification = self.classifier.classify_field(&field_path);
                    if let Some(category) = classification.field_kind.redacted_category() {
                        push_unique_category(categories, category);
                    }
                    let value = match classification.action {
                        PrivacyAction::Keep => {
                            self.redact_json_value(&field_path, nested, categories)
                        }
                        PrivacyAction::Redact | PrivacyAction::DenyExport => Value::String(
                            self.redact_text(classification.field_kind, value_as_text(nested)),
                        ),
                        PrivacyAction::Tokenize => Value::String(
                            self.tokenizer
                                .tokenize("tokenized", value_as_text(nested))
                                .token,
                        ),
                        PrivacyAction::Hash => {
                            Value::String(self.hashing_policy.hash("hash", value_as_text(nested)))
                        }
                    };
                    redacted.insert(key.clone(), value);
                }
                Value::Object(redacted)
            }
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .enumerate()
                    .map(|(index, nested)| {
                        self.redact_json_value(&format!("{path}[{index}]"), nested, categories)
                    })
                    .collect(),
            ),
            _ => value.clone(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GraphLabelRedactor {
    redaction_engine: RedactionEngine,
}

impl GraphLabelRedactor {
    pub fn redact_label(&self, label: &str) -> String {
        if label.contains("\\Users\\") || label.contains("/Users/") {
            self.redaction_engine
                .redact_text(SensitiveFieldKind::LocalPath, label)
        } else if label.starts_with("http://") || label.starts_with("https://") {
            self.redaction_engine
                .redact_text(SensitiveFieldKind::Url, label)
        } else if label.contains('@') {
            self.redaction_engine
                .redact_text(SensitiveFieldKind::Username, label)
        } else {
            label.to_string()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportPrivacyCheckRequest {
    pub format: sentinel_contracts::report::ExportFormat,
    pub redaction_summary: RedactionSummary,
    pub user_confirmed: bool,
    pub audit_ref: Option<AuditRef>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportPrivacyDecision {
    pub allowed: bool,
    pub denied_reasons: Vec<String>,
    pub audit_ref: Option<AuditRef>,
}

#[derive(Clone, Debug, Default)]
pub struct ExportPrivacyGate;

impl ExportPrivacyGate {
    pub fn evaluate(
        &self,
        policy: &ReportExportPolicy,
        request: ExportPrivacyCheckRequest,
    ) -> StorageResult<ExportPrivacyDecision> {
        let mut denied_reasons = Vec::new();
        policy.validate().map_err(|error| {
            StorageError::Serialization(format!("invalid report export policy: {error}"))
        })?;

        if !policy.allowed_formats.contains(&request.format) {
            denied_reasons.push("export format is not allowed by policy".to_string());
        }
        if policy.require_redaction && !request.redaction_summary.passed {
            denied_reasons.push("redaction summary did not pass".to_string());
        }
        if policy.require_user_confirmation && !request.user_confirmed {
            denied_reasons.push("user confirmation is required".to_string());
        }
        if policy.audit_required && request.audit_ref.is_none() {
            denied_reasons.push("audit reference is required".to_string());
        }

        Ok(ExportPrivacyDecision {
            allowed: denied_reasons.is_empty(),
            denied_reasons,
            audit_ref: request.audit_ref,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPlanStep {
    pub store_kind: StoreKind,
    pub data_class: DataClass,
    pub retention_class: RetentionClass,
    pub privacy_class: PrivacyClass,
    pub older_than: Option<Timestamp>,
    pub preserve_audit_records: bool,
    pub delete_allowed: bool,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPlan {
    pub created_at: Timestamp,
    pub steps: Vec<RetentionPlanStep>,
}

#[derive(Clone, Debug, Default)]
pub struct RetentionPlanner;

impl RetentionPlanner {
    pub fn plan(&self, policy: &RetentionPolicy, now: Timestamp) -> RetentionPlan {
        let steps = vec![
            self.step(StoreKind::Flow, policy.flows_days, false, &now),
            self.step(StoreKind::Session, policy.sessions_days, false, &now),
            self.step(StoreKind::Dns, policy.dns_observations_days, false, &now),
            self.step(StoreKind::Tls, policy.tls_observations_days, false, &now),
            self.step(
                StoreKind::HttpMetadata,
                policy.http_metadata_days,
                false,
                &now,
            ),
            self.step(
                StoreKind::ProcessContext,
                policy.process_context_days,
                false,
                &now,
            ),
            self.step(StoreKind::Asset, policy.asset_exposure_days, false, &now),
            self.step(StoreKind::Finding, policy.findings_days, false, &now),
            self.step(StoreKind::Alert, policy.alerts_days, false, &now),
            self.step(StoreKind::Incident, policy.incidents_days, false, &now),
            self.step(StoreKind::GraphPath, policy.incidents_days, false, &now),
            self.step(
                StoreKind::Audit,
                policy.audit_events_days_minimum,
                true,
                &now,
            ),
            RetentionPlanStep {
                store_kind: StoreKind::Report,
                data_class: DataClass::D1SecurityMetadata,
                retention_class: RetentionClass::UserControlled,
                privacy_class: PrivacyClass::Sensitive,
                older_than: None,
                preserve_audit_records: true,
                delete_allowed: false,
                reason: "reports are user controlled by default".to_string(),
            },
            self.step(
                StoreKind::ExportHistory,
                policy.audit_events_days_minimum,
                true,
                &now,
            ),
            self.step(
                StoreKind::ExportPolicyViolation,
                policy.audit_events_days_minimum,
                true,
                &now,
            ),
        ];

        RetentionPlan {
            created_at: now,
            steps,
        }
    }

    fn step(
        &self,
        store_kind: StoreKind,
        days: u16,
        preserve_audit_records: bool,
        now: &Timestamp,
    ) -> RetentionPlanStep {
        let storage_class = store_kind.default_storage_privacy_class();
        RetentionPlanStep {
            store_kind,
            data_class: storage_class.data_class,
            retention_class: storage_class.retention_class,
            privacy_class: storage_class.privacy_class,
            older_than: Some(subtract_days(now, days)),
            preserve_audit_records,
            delete_allowed: !preserve_audit_records,
            reason: format!("delete records older than {days} days through logical store boundary"),
        }
    }
}

pub trait RetentionStoreAdapter {
    fn store_kind(&self) -> StoreKind;
    fn delete_by_retention(
        &self,
        request: RetentionDeleteRequest,
    ) -> StorageResult<RetentionDeleteSummary>;
}

impl<TId> RetentionStoreAdapter for crate::store::SqliteLogicalStore<'_, TId>
where
    TId: Clone + fmt::Display + Serialize + serde::de::DeserializeOwned,
{
    fn store_kind(&self) -> StoreKind {
        self.store_kind().clone()
    }

    fn delete_by_retention(
        &self,
        request: RetentionDeleteRequest,
    ) -> StorageResult<RetentionDeleteSummary> {
        crate::store::LogicalStore::delete_by_retention(self, request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionDryRun {
    pub plan: RetentionPlan,
    pub summaries: Vec<RetentionDeleteSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionAuditRecord {
    pub audit_id: AuditId,
    pub created_at: Timestamp,
    pub dry_run: bool,
    pub summaries: Vec<RetentionDeleteSummary>,
    pub preserved_store_kinds: Vec<StoreKind>,
    pub total_matched_count: u64,
    pub total_deleted_count: u64,
}

#[derive(Clone, Debug, Default)]
pub struct RetentionJob;

impl RetentionJob {
    pub fn dry_run(
        &self,
        plan: RetentionPlan,
        stores: &[&dyn RetentionStoreAdapter],
    ) -> StorageResult<RetentionDryRun> {
        let summaries = self.execute_steps(&plan.steps, stores, true)?;
        Ok(RetentionDryRun { plan, summaries })
    }

    pub fn apply(
        &self,
        plan: &RetentionPlan,
        stores: &[&dyn RetentionStoreAdapter],
    ) -> StorageResult<RetentionAuditRecord> {
        let summaries = self.execute_steps(&plan.steps, stores, false)?;
        Ok(retention_audit_record(false, summaries))
    }

    fn execute_steps(
        &self,
        steps: &[RetentionPlanStep],
        stores: &[&dyn RetentionStoreAdapter],
        dry_run: bool,
    ) -> StorageResult<Vec<RetentionDeleteSummary>> {
        let mut summaries = Vec::new();

        for step in steps {
            let Some(older_than) = &step.older_than else {
                continue;
            };
            let Some(store) = stores
                .iter()
                .copied()
                .find(|store| store.store_kind() == step.store_kind)
            else {
                continue;
            };

            if !step.delete_allowed && !dry_run {
                return Err(StorageError::InvalidRecord {
                    store_kind: step.store_kind.to_string(),
                    reason: "retention plan does not allow deletion for this store".to_string(),
                });
            }

            summaries.push(store.delete_by_retention(RetentionDeleteRequest {
                older_than: older_than.clone(),
                dry_run,
                preserve_audit_records: step.preserve_audit_records,
            })?);
        }

        Ok(summaries)
    }
}

#[derive(Clone, Debug, Default)]
pub struct PrivacyEngine {
    pub classifier: SensitiveFieldClassifier,
    pub redaction_engine: RedactionEngine,
    pub tokenizer: Tokenizer,
    pub hashing_policy: HashingPolicy,
    pub export_gate: ExportPrivacyGate,
    pub retention_planner: RetentionPlanner,
    pub retention_job: RetentionJob,
    pub graph_label_redactor: GraphLabelRedactor,
    pub encryption_key_hook: EncryptionKeyHook,
}

impl PrivacyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn classify_field(&self, field_path: impl Into<String>) -> SensitiveFieldClassification {
        self.classifier.classify_field(field_path)
    }
}

impl Default for Tokenizer {
    fn default() -> Self {
        Self::local_installation()
    }
}

impl Default for HashingPolicy {
    fn default() -> Self {
        Self::local_correlation_sha256()
    }
}

impl Default for EncryptionKeyHook {
    fn default() -> Self {
        Self::local_dpapi_current_user()
    }
}

fn redaction_summary(categories: Vec<RedactedDataCategory>, passed: bool) -> RedactionSummary {
    RedactionSummary {
        redaction_summary_id: sentinel_contracts::RedactionSummaryId::new_v4(),
        passed,
        redacted_field_count: categories.len() as u32,
        suppressed_section_count: 0,
        reviewer: None,
        completed_at: Some(Timestamp::now()),
        notes_redacted: Vec::new(),
        redacted_categories: categories,
    }
}

fn retention_audit_record(
    dry_run: bool,
    summaries: Vec<RetentionDeleteSummary>,
) -> RetentionAuditRecord {
    let total_matched_count = summaries.iter().map(|summary| summary.matched_count).sum();
    let total_deleted_count = summaries.iter().map(|summary| summary.deleted_count).sum();
    let preserved_store_kinds = summaries
        .iter()
        .filter(|summary| summary.preserve_reason.is_some())
        .map(|summary| summary.store_kind.clone())
        .collect();

    RetentionAuditRecord {
        audit_id: AuditId::new_v4(),
        created_at: Timestamp::now(),
        dry_run,
        summaries,
        preserved_store_kinds,
        total_matched_count,
        total_deleted_count,
    }
}

fn subtract_days(now: &Timestamp, days: u16) -> Timestamp {
    Timestamp::from_datetime(*now.as_datetime() - Duration::days(days as i64))
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn value_as_text(value: &Value) -> &str {
    value.as_str().unwrap_or("[structured_value]")
}

fn push_unique_category(
    categories: &mut Vec<RedactedDataCategory>,
    category: RedactedDataCategory,
) {
    if !categories.contains(&category) {
        categories.push(category);
    }
}

fn redact_local_path(value: &str) -> String {
    if let Some(index) = value.find("\\Users\\") {
        let prefix = &value[..index];
        format!("{prefix}\\Users\\%USERPROFILE%\\...")
    } else if value.contains("/Users/") {
        "/Users/%USERPROFILE%/...".to_string()
    } else {
        "[REDACTED_LOCAL_PATH]".to_string()
    }
}

fn redact_url(value: &str) -> String {
    match value.split_once('?') {
        Some((base, _)) => format!("{base}?[REDACTED_QUERY_STRING]"),
        None => value.to_string(),
    }
}

fn privacy_digest(purpose: &str, key_ref: &str, label: &str, value: &str) -> String {
    sha256_hex(&format!(
        "sentinel-guard:{purpose}:v1:{key_ref}:{label}:{value}"
    ))
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key_protection_error(reason: impl Into<String>) -> StorageError {
    StorageError::InvalidRecord {
        store_kind: "privacy_key".to_string(),
        reason: reason.into(),
    }
}

#[cfg(windows)]
fn dpapi_hook_status() -> &'static str {
    DPAPI_STATUS_AVAILABLE
}

#[cfg(not(windows))]
fn dpapi_hook_status() -> &'static str {
    DPAPI_STATUS_UNSUPPORTED
}

#[cfg(windows)]
fn dpapi_protect(plaintext_key: &[u8]) -> StorageResult<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext_key.len() as u32,
        pbData: plaintext_key.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    // Safety: DPAPI reads `input` during the call only; `plaintext_key` lives for
    // the call, optional pointer parameters are null as allowed by DPAPI, and the
    // returned `output.pbData` is copied before being released with `LocalFree`.
    let ok = unsafe {
        CryptProtectData(
            &input,
            null(),
            null(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        // Safety: `GetLastError` only reads the thread-local Windows error code.
        let code = unsafe { GetLastError() };
        return Err(key_protection_error(format!(
            "DPAPI protect failed with Windows error {code}"
        )));
    }
    copy_and_free_dpapi_blob(output)
}

#[cfg(windows)]
fn dpapi_unprotect(protected_key: &[u8]) -> StorageResult<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: protected_key.len() as u32,
        pbData: protected_key.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    // Safety: DPAPI reads `input` during the call only; `protected_key` lives for
    // the call, optional pointer parameters are null as allowed by DPAPI, and the
    // returned `output.pbData` is copied before being released with `LocalFree`.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            null(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        // Safety: `GetLastError` only reads the thread-local Windows error code.
        let code = unsafe { GetLastError() };
        return Err(key_protection_error(format!(
            "DPAPI unprotect failed with Windows error {code}"
        )));
    }
    copy_and_free_dpapi_blob(output)
}

#[cfg(windows)]
fn copy_and_free_dpapi_blob(
    blob: windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
) -> StorageResult<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;

    if blob.pbData.is_null() || blob.cbData == 0 {
        return Err(key_protection_error("DPAPI returned an empty key blob"));
    }

    // Safety: DPAPI returned `pbData` with `cbData` bytes; the slice is copied
    // immediately, then the original allocation is released with `LocalFree`.
    let bytes = unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec() };
    // Safety: DPAPI allocates the output buffer with a local allocator; `LocalFree`
    // is the documented release function and is called exactly once here.
    unsafe {
        LocalFree(blob.pbData.cast());
    }
    Ok(bytes)
}

#[cfg(not(windows))]
fn dpapi_protect(_plaintext_key: &[u8]) -> StorageResult<Vec<u8>> {
    Err(StorageError::UnsupportedQuery(
        "DPAPI key protection is only available on Windows".to_string(),
    ))
}

#[cfg(not(windows))]
fn dpapi_unprotect(_protected_key: &[u8]) -> StorageResult<Vec<u8>> {
    Err(StorageError::UnsupportedQuery(
        "DPAPI key protection is only available on Windows".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{InMemoryMigrationAuditSink, MigrationRunner, SchemaMetadata};
    use crate::store::{logical_store_migration, LogicalRecord, LogicalStore, SqliteStoreFactory};
    use chrono::Utc;
    use rusqlite::Connection;
    use sentinel_contracts::report::ExportFormat;
    use sentinel_contracts::{FlowId, ReportExportPolicy, SchemaVersion};
    use serde_json::json;

    #[test]
    fn classifier_covers_privacy_classes_and_sensitive_fields() {
        let classifier = SensitiveFieldClassifier;

        assert_eq!(
            classifier
                .classify_privacy_class("field", PrivacyClass::Public)
                .action,
            PrivacyAction::Keep
        );
        assert_eq!(
            classifier
                .classify_privacy_class("field", PrivacyClass::Secret)
                .action,
            PrivacyAction::DenyExport
        );
        assert_eq!(
            classifier
                .classify_field("headers.authorization")
                .field_kind,
            SensitiveFieldKind::AuthorizationHeader
        );
        assert_eq!(
            classifier.classify_field("process.command_line").action,
            PrivacyAction::Redact
        );
    }

    #[test]
    fn redaction_tokenizes_and_redacts_metadata_values() -> Result<(), Box<dyn std::error::Error>> {
        let engine = RedactionEngine::default();
        let input = json!({
            "username": "alice",
            "local_path": "C:\\Users\\Alice\\AppData\\Local\\Temp\\tool.exe",
            "url": "https://example.test/path?token=example",
            "authorization_header": "Bearer example",
            "query_string": "a=b",
            "command_line": "tool.exe --password example"
        });

        let result = engine.redact_json(&input)?;

        assert!(result.redaction_summary.passed);
        assert!(result.redaction_summary.redacted_field_count >= 5);
        assert_ne!(result.value["username"], input["username"]);
        assert_eq!(
            result.value["authorization_header"],
            "[REDACTED_AUTHORIZATION_HEADER]"
        );
        assert_eq!(result.value["query_string"], "[REDACTED_QUERY_STRING]");
        assert_eq!(result.value["command_line"], "[REDACTED_COMMAND_LINE]");
        assert_eq!(result.audit_ref.event_type, "privacy.redaction");
        Ok(())
    }

    #[test]
    fn graph_label_redactor_handles_paths_urls_and_users() {
        let redactor = GraphLabelRedactor::default();

        assert!(redactor
            .redact_label("C:\\Users\\Alice\\AppData\\Local\\Temp\\tool.exe")
            .contains("%USERPROFILE%"));
        assert_eq!(
            redactor.redact_label("https://example.test/path?secret=1"),
            "https://example.test/path?[REDACTED_QUERY_STRING]"
        );
        assert!(redactor
            .redact_label("alice@example.test")
            .starts_with("user:local#"));
    }

    #[test]
    fn export_gate_requires_redaction_confirmation_and_audit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let gate = ExportPrivacyGate;
        let policy = ReportExportPolicy::safe_default();
        let denied = gate.evaluate(
            &policy,
            ExportPrivacyCheckRequest {
                format: ExportFormat::Markdown,
                redaction_summary: redaction_summary(Vec::new(), false),
                user_confirmed: false,
                audit_ref: None,
            },
        )?;

        assert!(!denied.allowed);
        assert_eq!(denied.denied_reasons.len(), 3);

        let allowed = gate.evaluate(
            &policy,
            ExportPrivacyCheckRequest {
                format: ExportFormat::RedactedJson,
                redaction_summary: redaction_summary(Vec::new(), true),
                user_confirmed: true,
                audit_ref: Some(AuditRef::new("report.export.requested")?),
            },
        )?;

        assert!(allowed.allowed);
        Ok(())
    }

    #[test]
    fn retention_job_supports_dry_run_and_audited_delete_counts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let factory = SqliteStoreFactory::new(&connection);
        let flow_store = factory.flow_store();
        let old_time = Timestamp::from_datetime(Utc::now() - Duration::days(45));
        let record = LogicalRecord::metadata_only(
            FlowId::new_v4(),
            SchemaVersion::new(1, 0, 0),
            StoreKind::Flow.default_storage_privacy_class(),
            json!({ "bytes_in": 100, "summary": "metadata only" }),
        )
        .with_record_time(old_time);
        flow_store.append(record)?;

        let planner = RetentionPlanner;
        let plan = planner.plan(&RetentionPolicy::safe_default(), Timestamp::now());
        let job = RetentionJob;
        let dry_run = job.dry_run(plan.clone(), &[&flow_store])?;

        assert_eq!(dry_run.summaries[0].matched_count, 1);
        assert_eq!(dry_run.summaries[0].deleted_count, 0);

        let audit = job.apply(&plan, &[&flow_store])?;
        assert!(!audit.dry_run);
        assert_eq!(audit.total_matched_count, 1);
        assert_eq!(audit.total_deleted_count, 1);
        Ok(())
    }

    #[test]
    fn privacy_engine_exposes_dpapi_key_boundary() {
        let engine = PrivacyEngine::new();

        assert_eq!(
            engine.encryption_key_hook.status,
            dpapi_hook_status().to_string()
        );
        assert_eq!(engine.encryption_key_hook.key_ref, DPAPI_MASTER_KEY_REF);
        assert_eq!(engine.encryption_key_hook.key_version, 1);
        assert_eq!(
            engine.encryption_key_hook.protection_method,
            DPAPI_CURRENT_USER_METHOD
        );
        assert_eq!(engine.tokenizer.scope, TokenizationScope::LocalInstallation);
        assert_eq!(engine.tokenizer.key_ref, TOKEN_DIGEST_KEY_REF);
        assert_eq!(engine.hashing_policy.algorithm, SHA256_ALGORITHM);
        assert_eq!(
            engine.hashing_policy.key_ref.as_deref(),
            Some(HASH_DIGEST_KEY_REF)
        );
        assert!(!engine.hashing_policy.not_for_production);
    }

    #[test]
    fn tokenization_and_hashing_use_stable_sha256_digests() {
        let tokenizer = Tokenizer::local_installation();
        let token = tokenizer.tokenize("user:local", "alice");
        let repeated = tokenizer.tokenize("user:local", "alice");
        let different = tokenizer.tokenize("user:local", "bob");
        let hash = HashingPolicy::local_correlation_sha256().hash("ip", "192.0.2.10");

        assert_eq!(
            token.token,
            "user:local#5c6b7ff5e02aeaa8c4546253421da85d42b394f861cd547e0d6838821260f77c"
        );
        assert_eq!(token.token, repeated.token);
        assert_ne!(token.token, different.token);
        assert_eq!(
            hash,
            "ip#7f09e32c9d2260b1cac6d834f1ed17920e39705661113494395bc8a105af21e8"
        );
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_protects_and_unprotects_local_master_key() -> Result<(), Box<dyn std::error::Error>> {
        let hook = EncryptionKeyHook::local_dpapi_current_user();
        let plaintext_key = b"synthetic-local-master-key-material-for-test";

        let protected = hook.protect_local_master_key(plaintext_key)?;
        let unprotected = hook.unprotect_local_master_key(&protected)?;

        assert_eq!(protected.key_ref, DPAPI_MASTER_KEY_REF);
        assert_eq!(protected.key_version, 1);
        assert_eq!(protected.protection_method, DPAPI_CURRENT_USER_METHOD);
        assert_ne!(protected.protected_key, plaintext_key);
        assert!(protected.protected_key.len() > plaintext_key.len());
        assert_eq!(unprotected, plaintext_key);
        Ok(())
    }

    #[cfg(not(windows))]
    #[test]
    fn dpapi_key_protection_is_explicitly_unavailable_off_windows() {
        let hook = EncryptionKeyHook::local_dpapi_current_user();
        let error = hook
            .protect_local_master_key(b"synthetic-local-master-key-material-for-test")
            .expect_err("DPAPI unavailable off Windows");

        assert_eq!(hook.status, DPAPI_STATUS_UNSUPPORTED);
        assert!(matches!(error, StorageError::UnsupportedQuery(_)));
    }

    fn initialized_connection() -> Result<Connection, Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        {
            let mut runner = MigrationRunner::new(&mut connection);
            runner.initialize(&SchemaMetadata::storage_foundation())?;
            let mut audit = InMemoryMigrationAuditSink::default();
            runner.apply_all(&[logical_store_migration()?], &mut audit)?;
        }
        Ok(connection)
    }
}
