use crate::common::{
    DataSourceId, EvidenceId, FindingId, MetadataSamplingBatchId, MetadataWatchCheckpointId,
    MetadataWatchSourceId, PrivacyClass, RiskEventId, SecurityFactId, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_WATCH_REFS: usize = 64;
pub const MAX_WATCH_LABELS: usize = 32;
const MAX_WATCH_SAFE_TEXT_BYTES: usize = 160;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetadataWatchContractError {
    EmptyField(&'static str),
    UnsafeField(&'static str),
    ExceedsBound(&'static str),
    UnsafeClaim(&'static str),
}

impl fmt::Display for MetadataWatchContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains unsafe metadata"),
            Self::ExceedsBound(field) => write!(formatter, "{field} exceeds bounded limits"),
            Self::UnsafeClaim(reason) => write!(formatter, "unsafe watch claim: {reason}"),
        }
    }
}

impl std::error::Error for MetadataWatchContractError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataWatchSourceKind {
    WatchedHarFolder,
    WatchedJsonlFolder,
    TailedDnsResolverLog,
    TailedApiGatewayLog,
    TailedWafLog,
    TailedCdnEdgeLog,
    TailedSdnControlPlaneLog,
    TailedObjectStorageAuditLog,
    TailedWebLog,
    TailedAuthSecurityLog,
    TailedSaasCloudJsonl,
    TailedDeceptionHoneypotJsonl,
    LocalhostProxyContinuousDrain,
    ManualImport,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataWatchSourceState {
    Preview,
    Enabled,
    Active,
    Paused,
    Disabled,
    Revoked,
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataSamplingMode {
    ManualPreviewConfirm,
    IntervalTick,
    ContinuousDrain,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataSamplingLoopState {
    Disabled,
    Running,
    Paused,
    ShuttingDown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataParserFamily {
    Har,
    JsonlNetwork,
    DnsResolverLog,
    ApiGatewayLog,
    WafLog,
    CdnEdgeLog,
    SdnControlPlaneLog,
    ObjectStorageAuditLog,
    WebAccessLog,
    AuthSecurityLog,
    SaasCloudJsonl,
    DeceptionJsonl,
    LocalProxyMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataSourceHealthState {
    Disabled,
    Enabled,
    Active,
    Idle,
    Paused,
    Degraded,
    Backpressure,
    ParserError,
    SourceUnavailable,
    CursorResetRequired,
    RotationDetected,
    OversizedInputSkipped,
    PermissionRequired,
    Revoked,
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataRetentionMode {
    NoRetention,
    SessionOnlyRedacted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataWatchLifecycleAction {
    Enable,
    Pause,
    Resume,
    Disable,
    Revoke,
    ClearInactive,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataSamplingLoopAction {
    Enable,
    Disable,
    PauseAll,
    ResumeAll,
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataWatchCounters {
    pub sampled_record_count: u64,
    pub sampled_byte_count: u64,
    pub skipped_record_count: u64,
    pub malformed_record_count: u64,
    pub duplicate_record_count: u64,
    pub backpressure_drop_count: u64,
    pub batch_count: u64,
}

impl MetadataWatchCounters {
    pub fn empty() -> Self {
        Self {
            sampled_record_count: 0,
            sampled_byte_count: 0,
            skipped_record_count: 0,
            malformed_record_count: 0,
            duplicate_record_count: 0,
            backpressure_drop_count: 0,
            batch_count: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataWatchCheckpoint {
    pub checkpoint_id: MetadataWatchCheckpointId,
    pub source_id: MetadataWatchSourceId,
    pub source_kind: MetadataWatchSourceKind,
    pub safe_cursor_bucket: String,
    pub safe_generation_hash: String,
    pub sampled_time_bucket: Option<Timestamp>,
    pub handoff_time_bucket: Option<Timestamp>,
    pub parser_schema_version: String,
    pub redaction_schema_version: String,
    pub health_state: MetadataSourceHealthState,
    pub provenance_id: Option<DataSourceId>,
}

impl MetadataWatchCheckpoint {
    pub fn new(
        source_id: MetadataWatchSourceId,
        source_kind: MetadataWatchSourceKind,
        parser_family: &MetadataParserFamily,
    ) -> Result<Self, MetadataWatchContractError> {
        let checkpoint = Self {
            checkpoint_id: MetadataWatchCheckpointId::new_v4(),
            source_id,
            source_kind,
            safe_cursor_bucket: "not_started".to_string(),
            safe_generation_hash: "sha256:pending".to_string(),
            sampled_time_bucket: None,
            handoff_time_bucket: None,
            parser_schema_version: parser_schema_version(parser_family),
            redaction_schema_version: "redaction:v1".to_string(),
            health_state: MetadataSourceHealthState::Enabled,
            provenance_id: None,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn validate(&self) -> Result<(), MetadataWatchContractError> {
        safe_text("safe_cursor_bucket", &self.safe_cursor_bucket)?;
        safe_hash("safe_generation_hash", &self.safe_generation_hash)?;
        safe_text("parser_schema_version", &self.parser_schema_version)?;
        safe_text("redaction_schema_version", &self.redaction_schema_version)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataWatchSourcePreviewRequest {
    pub source_kind: MetadataWatchSourceKind,
    pub parser_family: MetadataParserFamily,
    pub display_label_redacted: String,
    pub sampling_mode: MetadataSamplingMode,
    pub interval_seconds: u32,
    pub max_records_per_tick: u32,
    pub max_bytes_per_tick: u32,
    pub reason_redacted: String,
}

impl MetadataWatchSourcePreviewRequest {
    pub fn validate(&self) -> Result<(), MetadataWatchContractError> {
        safe_text("display_label_redacted", &self.display_label_redacted)?;
        safe_text("reason_redacted", &self.reason_redacted)?;
        validate_limits(
            self.interval_seconds,
            self.max_records_per_tick,
            self.max_bytes_per_tick,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataWatchSourcePreview {
    pub preview_id: MetadataWatchSourceId,
    pub source_kind: MetadataWatchSourceKind,
    pub parser_family: MetadataParserFamily,
    pub display_label_redacted: String,
    pub sampling_mode: MetadataSamplingMode,
    pub interval_seconds: u32,
    pub max_records_per_tick: u32,
    pub max_bytes_per_tick: u32,
    pub retention_mode: MetadataRetentionMode,
    pub redaction_policy: String,
    pub privacy_boundary: String,
    pub portable_default_available: bool,
    pub generated_at: Timestamp,
}

impl MetadataWatchSourcePreview {
    pub fn validate(&self) -> Result<(), MetadataWatchContractError> {
        safe_text("display_label_redacted", &self.display_label_redacted)?;
        safe_text("redaction_policy", &self.redaction_policy)?;
        safe_text("privacy_boundary", &self.privacy_boundary)?;
        validate_limits(
            self.interval_seconds,
            self.max_records_per_tick,
            self.max_bytes_per_tick,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataWatchSourceConfirmation {
    pub preview_id: MetadataWatchSourceId,
    pub user_confirmed: bool,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

impl MetadataWatchSourceConfirmation {
    pub fn validate(&self) -> Result<(), MetadataWatchContractError> {
        safe_text("reason_redacted", &self.reason_redacted)?;
        if let Some(actor) = &self.requested_by_redacted {
            safe_text("requested_by_redacted", actor)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataWatchLifecycleRequest {
    pub source_id: MetadataWatchSourceId,
    pub action: MetadataWatchLifecycleAction,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

impl MetadataWatchLifecycleRequest {
    pub fn validate(&self) -> Result<(), MetadataWatchContractError> {
        safe_text("reason_redacted", &self.reason_redacted)?;
        if let Some(actor) = &self.requested_by_redacted {
            safe_text("requested_by_redacted", actor)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSamplingTickRequest {
    pub source_id: Option<MetadataWatchSourceId>,
    pub max_sources: u32,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

impl MetadataSamplingTickRequest {
    pub fn validate(&self) -> Result<(), MetadataWatchContractError> {
        safe_text("reason_redacted", &self.reason_redacted)?;
        if let Some(actor) = &self.requested_by_redacted {
            safe_text("requested_by_redacted", actor)?;
        }
        if self.max_sources == 0 || self.max_sources > 32 {
            return Err(MetadataWatchContractError::UnsafeClaim(
                "sampling ticks must bound source count",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSamplingLoopControlRequest {
    pub action: MetadataSamplingLoopAction,
    pub max_sources_per_cycle: u32,
    pub max_concurrent_sources: u32,
    pub max_files_per_tick: u32,
    pub per_source_timeout_millis: u32,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

impl MetadataSamplingLoopControlRequest {
    pub fn validate(&self) -> Result<(), MetadataWatchContractError> {
        validate_loop_limits(
            self.max_sources_per_cycle,
            self.max_concurrent_sources,
            self.max_files_per_tick,
            self.per_source_timeout_millis,
        )?;
        safe_text("reason_redacted", &self.reason_redacted)?;
        if let Some(actor) = &self.requested_by_redacted {
            safe_text("requested_by_redacted", actor)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSamplingLoopRunRequest {
    pub max_sources: u32,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

impl MetadataSamplingLoopRunRequest {
    pub fn validate(&self) -> Result<(), MetadataWatchContractError> {
        if self.max_sources == 0 || self.max_sources > 32 {
            return Err(MetadataWatchContractError::UnsafeClaim(
                "sampling loop cycle must bound source count",
            ));
        }
        safe_text("reason_redacted", &self.reason_redacted)?;
        if let Some(actor) = &self.requested_by_redacted {
            safe_text("requested_by_redacted", actor)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataWatchSourceStatus {
    pub source_id: MetadataWatchSourceId,
    pub source_kind: MetadataWatchSourceKind,
    pub state: MetadataWatchSourceState,
    pub health_state: MetadataSourceHealthState,
    pub sampling_mode: MetadataSamplingMode,
    pub interval_seconds: u32,
    pub max_records_per_tick: u32,
    pub max_bytes_per_tick: u32,
    pub parser_family: MetadataParserFamily,
    pub redaction_policy: String,
    pub retention_mode: MetadataRetentionMode,
    pub checkpoint: MetadataWatchCheckpoint,
    pub counters: MetadataWatchCounters,
    pub last_sampled_at: Option<Timestamp>,
    pub last_ingested_at: Option<Timestamp>,
    pub degraded_reason: Option<String>,
    pub error_category: Option<String>,
    pub provenance_id: Option<DataSourceId>,
    pub privacy_boundary: String,
    pub portable_default_available: bool,
    pub sampler_ids: Vec<String>,
    pub fact_count: u32,
    pub hypothesis_count: u32,
    pub finding_count: u32,
    pub evidence_refs: Vec<EvidenceId>,
}

impl MetadataWatchSourceStatus {
    pub fn validate(&self) -> Result<(), MetadataWatchContractError> {
        safe_text("redaction_policy", &self.redaction_policy)?;
        safe_text("privacy_boundary", &self.privacy_boundary)?;
        if let Some(reason) = &self.degraded_reason {
            safe_text("degraded_reason", reason)?;
        }
        if let Some(category) = &self.error_category {
            safe_text("error_category", category)?;
        }
        validate_labels("sampler_ids", &self.sampler_ids)?;
        if self.evidence_refs.len() > MAX_WATCH_REFS {
            return Err(MetadataWatchContractError::ExceedsBound("evidence_refs"));
        }
        self.checkpoint.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSamplingBatchSummary {
    pub batch_id: MetadataSamplingBatchId,
    pub source_id: MetadataWatchSourceId,
    pub source_kind: MetadataWatchSourceKind,
    pub parser_family: MetadataParserFamily,
    pub started_at: Timestamp,
    pub completed_at: Timestamp,
    pub health_state: MetadataSourceHealthState,
    pub sampled_record_count: u64,
    pub sampled_byte_count: u64,
    pub skipped_record_count: u64,
    pub malformed_record_count: u64,
    pub duplicate_record_count: u64,
    pub backpressure_drop_count: u64,
    pub emitted_topics: Vec<String>,
    pub fact_refs: Vec<SecurityFactId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub finding_refs: Vec<FindingId>,
    pub risk_refs: Vec<RiskEventId>,
    pub report_refresh_marker: bool,
    pub attack_refresh_marker: bool,
    pub story_available_marker: bool,
    pub triage_advisory_only: bool,
    pub automatic_llm_calls: bool,
    pub response_execution: bool,
}

impl MetadataSamplingBatchSummary {
    pub fn validate(&self) -> Result<(), MetadataWatchContractError> {
        validate_labels("emitted_topics", &self.emitted_topics)?;
        if self.fact_refs.len() > MAX_WATCH_REFS
            || self.evidence_refs.len() > MAX_WATCH_REFS
            || self.finding_refs.len() > MAX_WATCH_REFS
            || self.risk_refs.len() > MAX_WATCH_REFS
        {
            return Err(MetadataWatchContractError::ExceedsBound("sampling refs"));
        }
        if self.automatic_llm_calls || self.response_execution {
            return Err(MetadataWatchContractError::UnsafeClaim(
                "watch sampling cannot trigger LLM calls or response execution",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataWatchControllerStatus {
    pub generated_at: Timestamp,
    pub scheduler_mode: String,
    pub running: bool,
    pub loop_state: MetadataSamplingLoopState,
    pub loop_enabled: bool,
    pub loop_paused: bool,
    pub scheduled_source_count: u32,
    pub max_sources_per_cycle: u32,
    pub max_concurrent_sources: u32,
    pub max_files_per_tick: u32,
    pub per_source_timeout_millis: u32,
    pub enabled_source_count: u32,
    pub active_source_count: u32,
    pub paused_source_count: u32,
    pub degraded_source_count: u32,
    pub revoked_source_count: u32,
    pub backpressure_source_count: u32,
    pub total_sampled_record_count: u64,
    pub total_duplicate_record_count: u64,
    pub total_malformed_record_count: u64,
    pub total_backpressure_drop_count: u64,
    pub last_tick_at: Option<Timestamp>,
    pub last_scheduled_at: Option<Timestamp>,
    pub graceful_shutdown_requested: bool,
    pub latest_batch_id: Option<MetadataSamplingBatchId>,
    pub latest_checkpoint_id: Option<MetadataWatchCheckpointId>,
    pub latest_provenance_id: Option<DataSourceId>,
    pub fusion_refresh_count: u64,
    pub report_refresh_marker_count: u64,
    pub attack_refresh_marker_count: u64,
    pub triage_advisory_only: bool,
    pub automatic_llm_calls: bool,
    pub response_execution: bool,
    pub privacy_class: PrivacyClass,
}

impl MetadataWatchControllerStatus {
    pub fn empty() -> Self {
        Self {
            generated_at: Timestamp::now(),
            scheduler_mode: "explicit_tick_controller".to_string(),
            running: false,
            loop_state: MetadataSamplingLoopState::Disabled,
            loop_enabled: false,
            loop_paused: false,
            scheduled_source_count: 0,
            max_sources_per_cycle: 8,
            max_concurrent_sources: 1,
            max_files_per_tick: 8,
            per_source_timeout_millis: 5000,
            enabled_source_count: 0,
            active_source_count: 0,
            paused_source_count: 0,
            degraded_source_count: 0,
            revoked_source_count: 0,
            backpressure_source_count: 0,
            total_sampled_record_count: 0,
            total_duplicate_record_count: 0,
            total_malformed_record_count: 0,
            total_backpressure_drop_count: 0,
            last_tick_at: None,
            last_scheduled_at: None,
            graceful_shutdown_requested: false,
            latest_batch_id: None,
            latest_checkpoint_id: None,
            latest_provenance_id: None,
            fusion_refresh_count: 0,
            report_refresh_marker_count: 0,
            attack_refresh_marker_count: 0,
            triage_advisory_only: true,
            automatic_llm_calls: false,
            response_execution: false,
            privacy_class: PrivacyClass::Internal,
        }
    }

    pub fn validate(&self) -> Result<(), MetadataWatchContractError> {
        safe_text("scheduler_mode", &self.scheduler_mode)?;
        validate_loop_limits(
            self.max_sources_per_cycle,
            self.max_concurrent_sources,
            self.max_files_per_tick,
            self.per_source_timeout_millis,
        )?;
        if self.automatic_llm_calls || self.response_execution || !self.triage_advisory_only {
            return Err(MetadataWatchContractError::UnsafeClaim(
                "watch controller must remain advisory and local-only",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSamplingTickResult {
    pub controller_status: MetadataWatchControllerStatus,
    pub batches: Vec<MetadataSamplingBatchSummary>,
    pub source_statuses: Vec<MetadataWatchSourceStatus>,
}

impl MetadataSamplingTickResult {
    pub fn validate(&self) -> Result<(), MetadataWatchContractError> {
        self.controller_status.validate()?;
        if self.batches.len() > MAX_WATCH_REFS || self.source_statuses.len() > MAX_WATCH_REFS {
            return Err(MetadataWatchContractError::ExceedsBound("tick result"));
        }
        for batch in &self.batches {
            batch.validate()?;
        }
        for source in &self.source_statuses {
            source.validate()?;
        }
        Ok(())
    }
}

pub fn parser_schema_version(parser_family: &MetadataParserFamily) -> String {
    match parser_family {
        MetadataParserFamily::Har => "har:v1",
        MetadataParserFamily::JsonlNetwork => "jsonl_network:v1",
        MetadataParserFamily::DnsResolverLog => "dns_resolver_log:v1",
        MetadataParserFamily::ApiGatewayLog => "api_gateway_log:v1",
        MetadataParserFamily::WafLog => "waf_log:v1",
        MetadataParserFamily::CdnEdgeLog => "cdn_edge_log:v1",
        MetadataParserFamily::SdnControlPlaneLog => "sdn_control_plane_log:v1",
        MetadataParserFamily::ObjectStorageAuditLog => "object_storage_audit_log:v1",
        MetadataParserFamily::WebAccessLog => "web_access_log:v1",
        MetadataParserFamily::AuthSecurityLog => "auth_security_log:v1",
        MetadataParserFamily::SaasCloudJsonl => "saas_cloud_jsonl:v1",
        MetadataParserFamily::DeceptionJsonl => "deception_jsonl:v1",
        MetadataParserFamily::LocalProxyMetadata => "local_proxy_metadata:v1",
    }
    .to_string()
}

fn validate_limits(
    interval_seconds: u32,
    max_records_per_tick: u32,
    max_bytes_per_tick: u32,
) -> Result<(), MetadataWatchContractError> {
    if interval_seconds == 0 || interval_seconds > 86_400 {
        return Err(MetadataWatchContractError::UnsafeClaim(
            "interval must be bounded",
        ));
    }
    if max_records_per_tick == 0 || max_records_per_tick > 10_000 {
        return Err(MetadataWatchContractError::UnsafeClaim(
            "record limit must be bounded",
        ));
    }
    if max_bytes_per_tick == 0 || max_bytes_per_tick > 16 * 1024 * 1024 {
        return Err(MetadataWatchContractError::UnsafeClaim(
            "byte limit must be bounded",
        ));
    }
    Ok(())
}

fn validate_loop_limits(
    max_sources_per_cycle: u32,
    max_concurrent_sources: u32,
    max_files_per_tick: u32,
    per_source_timeout_millis: u32,
) -> Result<(), MetadataWatchContractError> {
    if max_sources_per_cycle == 0 || max_sources_per_cycle > 32 {
        return Err(MetadataWatchContractError::UnsafeClaim(
            "sampling loop must bound source count",
        ));
    }
    if max_concurrent_sources == 0 || max_concurrent_sources > 8 {
        return Err(MetadataWatchContractError::UnsafeClaim(
            "sampling loop must bound concurrency",
        ));
    }
    if max_files_per_tick == 0 || max_files_per_tick > 64 {
        return Err(MetadataWatchContractError::UnsafeClaim(
            "sampling loop must bound file discovery",
        ));
    }
    if !(100..=60_000).contains(&per_source_timeout_millis) {
        return Err(MetadataWatchContractError::UnsafeClaim(
            "sampling loop must bound per-source timeout",
        ));
    }
    Ok(())
}

fn validate_labels(
    field: &'static str,
    values: &[String],
) -> Result<(), MetadataWatchContractError> {
    if values.len() > MAX_WATCH_LABELS {
        return Err(MetadataWatchContractError::ExceedsBound(field));
    }
    for value in values {
        safe_text(field, value)?;
    }
    Ok(())
}

fn safe_hash(field: &'static str, value: &str) -> Result<(), MetadataWatchContractError> {
    safe_text(field, value)?;
    let normalized = value.strip_prefix("sha256:").unwrap_or(value);
    if normalized == "pending" {
        return Ok(());
    }
    if normalized.len() != 64
        || !normalized
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(MetadataWatchContractError::UnsafeField(field));
    }
    Ok(())
}

fn safe_text(field: &'static str, value: &str) -> Result<(), MetadataWatchContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(MetadataWatchContractError::EmptyField(field));
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.len() > MAX_WATCH_SAFE_TEXT_BYTES
        || trimmed.contains("://")
        || trimmed.contains('@')
        || trimmed.contains('\\')
        || trimmed.contains('/')
        || trimmed.parse::<std::net::IpAddr>().is_ok()
        || FORBIDDEN_MARKERS
            .iter()
            .any(|marker| lower.contains(marker))
    {
        return Err(MetadataWatchContractError::UnsafeField(field));
    }
    Ok(())
}

const FORBIDDEN_MARKERS: &[&str] = &[
    "password",
    "secret",
    "credential",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "token",
    "bearer",
    "raw_packet",
    "packet_bytes",
    "raw_payload",
    "payload_blob",
    "http_body",
    "query_string",
    "command_line",
    "tenant",
    "account_id",
    "device_id",
    "email",
    "username",
    "filename",
    "filepath",
    "path=",
    "c:",
    "appdata",
    "private_key",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn preview_request() -> MetadataWatchSourcePreviewRequest {
        MetadataWatchSourcePreviewRequest {
            source_kind: MetadataWatchSourceKind::TailedWebLog,
            parser_family: MetadataParserFamily::WebAccessLog,
            display_label_redacted: "web_log_tail".to_string(),
            sampling_mode: MetadataSamplingMode::IntervalTick,
            interval_seconds: 5,
            max_records_per_tick: 100,
            max_bytes_per_tick: 64_000,
            reason_redacted: "local_operator_confirmed".to_string(),
        }
    }

    #[test]
    fn watch_source_request_rejects_paths_and_tokens() {
        let mut request = preview_request();
        request.display_label_redacted = "C:\\Users\\Alice\\access.log".to_string();
        assert!(request.validate().is_err());

        let mut request = preview_request();
        request.reason_redacted = "session_token=secret".to_string();
        assert!(request.validate().is_err());
    }

    #[test]
    fn checkpoint_rejects_revealing_cursor_or_generation_values() {
        let mut checkpoint = MetadataWatchCheckpoint::new(
            MetadataWatchSourceId::new_v4(),
            MetadataWatchSourceKind::WatchedHarFolder,
            &MetadataParserFamily::Har,
        )
        .expect("checkpoint");
        checkpoint.safe_cursor_bucket = "C:/drop/network.har".to_string();
        assert!(checkpoint.validate().is_err());

        checkpoint.safe_cursor_bucket = "bucket_1".to_string();
        checkpoint.safe_generation_hash = "sha256:not-a-real-hash".to_string();
        assert!(checkpoint.validate().is_err());
    }

    #[test]
    fn controller_status_never_allows_llm_or_response_execution() {
        let mut status = MetadataWatchControllerStatus::empty();
        status.automatic_llm_calls = true;
        assert!(status.validate().is_err());

        status.automatic_llm_calls = false;
        status.response_execution = true;
        assert!(status.validate().is_err());
    }
}
