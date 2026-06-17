use crate::{
    CanonicalReadModelCategory, CanonicalReadModelSnapshot, CanonicalReadModelSnapshotItem,
    ReadModelSnapshotFreshness, ReadModelSnapshotId, RedactionStatus, SchemaVersion,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

pub const READ_COMMAND_PROTOCOL_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const READ_COMMAND_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const READ_COMMAND_TIMEOUT_MS: u64 = 250;
pub const READ_COMMAND_MAX_RESPONSE_BYTES: usize = 16 * 1024;
pub const READ_COMMAND_MAX_ITEMS: usize = 8;
pub const READ_COMMAND_MAX_REFS_PER_RECORD: usize = 8;
pub const READ_COMMAND_MAX_NESTED_DEPTH: usize = 8;
pub const READ_COMMAND_MAX_SNAPSHOT_AGE_MS: i64 = 5 * 60 * 1000;
pub const READ_COMMAND_MAX_CONTINUATION_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceReadCommandId {
    GetRuntimeOwnership,
    GetComponentOwnershipSummary,
    GetRuntimeHealth,
    ListCapabilityStatus,
    GetCapabilityHealthSummary,
    GetSchedulerStatus,
    GetSchedulerHostStatus,
    GetNativeSamplerStatus,
    GetNativePermissionStatus,
    GetEndpointThreatSummary,
    GetFusionSummary,
    GetEvidenceQualitySummary,
    GetRiskSummary,
    GetAttackCoverageSummary,
    GetGraphSummary,
    GetBaselineSummary,
    GetIncidentLinkSummary,
    GetReportTraceability,
    GetExportTraceability,
    GetStorageOwnerSummary,
    GetProviderControllerStatus,
    ListNetworkProviderStatus,
    GetNetworkProviderStatus,
    GetNetworkVisibilitySummary,
    GetNetworkFallbackPlan,
}

impl ServiceReadCommandId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetRuntimeOwnership => "get_runtime_ownership",
            Self::GetComponentOwnershipSummary => "get_component_ownership_summary",
            Self::GetRuntimeHealth => "get_runtime_health",
            Self::ListCapabilityStatus => "list_capability_status",
            Self::GetCapabilityHealthSummary => "get_capability_health_summary",
            Self::GetSchedulerStatus => "get_scheduler_status",
            Self::GetSchedulerHostStatus => "get_scheduler_host_status",
            Self::GetNativeSamplerStatus => "get_native_sampler_status",
            Self::GetNativePermissionStatus => "get_native_permission_status",
            Self::GetEndpointThreatSummary => "get_endpoint_threat_summary",
            Self::GetFusionSummary => "get_fusion_summary",
            Self::GetEvidenceQualitySummary => "get_evidence_quality_summary",
            Self::GetRiskSummary => "get_risk_summary",
            Self::GetAttackCoverageSummary => "get_attack_coverage_summary",
            Self::GetGraphSummary => "get_graph_summary",
            Self::GetBaselineSummary => "get_baseline_summary",
            Self::GetIncidentLinkSummary => "get_incident_link_summary",
            Self::GetReportTraceability => "get_report_traceability",
            Self::GetExportTraceability => "get_export_traceability",
            Self::GetStorageOwnerSummary => "get_storage_owner_summary",
            Self::GetProviderControllerStatus => "get_provider_controller_status",
            Self::ListNetworkProviderStatus => "list_network_provider_status",
            Self::GetNetworkProviderStatus => "get_network_provider_status",
            Self::GetNetworkVisibilitySummary => "get_network_visibility_summary",
            Self::GetNetworkFallbackPlan => "get_network_fallback_plan",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ReadCommandContractError> {
        match value {
            "get_runtime_ownership" => Ok(Self::GetRuntimeOwnership),
            "get_component_ownership_summary" => Ok(Self::GetComponentOwnershipSummary),
            "get_runtime_health" => Ok(Self::GetRuntimeHealth),
            "list_capability_status" => Ok(Self::ListCapabilityStatus),
            "get_capability_health_summary" => Ok(Self::GetCapabilityHealthSummary),
            "get_scheduler_status" => Ok(Self::GetSchedulerStatus),
            "get_scheduler_host_status" => Ok(Self::GetSchedulerHostStatus),
            "get_native_sampler_status" => Ok(Self::GetNativeSamplerStatus),
            "get_native_permission_status" => Ok(Self::GetNativePermissionStatus),
            "get_endpoint_threat_summary" => Ok(Self::GetEndpointThreatSummary),
            "get_fusion_summary" => Ok(Self::GetFusionSummary),
            "get_evidence_quality_summary" => Ok(Self::GetEvidenceQualitySummary),
            "get_risk_summary" => Ok(Self::GetRiskSummary),
            "get_attack_coverage_summary" => Ok(Self::GetAttackCoverageSummary),
            "get_graph_summary" => Ok(Self::GetGraphSummary),
            "get_baseline_summary" => Ok(Self::GetBaselineSummary),
            "get_incident_link_summary" => Ok(Self::GetIncidentLinkSummary),
            "get_report_traceability" => Ok(Self::GetReportTraceability),
            "get_export_traceability" => Ok(Self::GetExportTraceability),
            "get_storage_owner_summary" => Ok(Self::GetStorageOwnerSummary),
            "get_provider_controller_status" => Ok(Self::GetProviderControllerStatus),
            "list_network_provider_status" => Ok(Self::ListNetworkProviderStatus),
            "get_network_provider_status" => Ok(Self::GetNetworkProviderStatus),
            "get_network_visibility_summary" => Ok(Self::GetNetworkVisibilitySummary),
            "get_network_fallback_plan" => Ok(Self::GetNetworkFallbackPlan),
            _ => Err(ReadCommandContractError::UnknownCommand),
        }
    }

    pub const fn category(self) -> CanonicalReadModelCategory {
        match self {
            Self::GetRuntimeOwnership => CanonicalReadModelCategory::RuntimeOwnership,
            Self::GetComponentOwnershipSummary => {
                CanonicalReadModelCategory::ComponentLifecycleHealth
            }
            Self::GetRuntimeHealth => CanonicalReadModelCategory::RuntimeHealth,
            Self::ListCapabilityStatus | Self::GetCapabilityHealthSummary => {
                CanonicalReadModelCategory::CapabilityHealth
            }
            Self::GetSchedulerStatus => CanonicalReadModelCategory::Scheduler,
            Self::GetSchedulerHostStatus => CanonicalReadModelCategory::SchedulerHost,
            Self::GetNativeSamplerStatus => CanonicalReadModelCategory::SamplerState,
            Self::GetNativePermissionStatus => {
                CanonicalReadModelCategory::NativePermissionReadiness
            }
            Self::GetEndpointThreatSummary => CanonicalReadModelCategory::EndpointThreat,
            Self::GetFusionSummary => CanonicalReadModelCategory::Fusion,
            Self::GetEvidenceQualitySummary => CanonicalReadModelCategory::EvidenceQuality,
            Self::GetRiskSummary => CanonicalReadModelCategory::Risk,
            Self::GetAttackCoverageSummary => CanonicalReadModelCategory::AttackContext,
            Self::GetGraphSummary => CanonicalReadModelCategory::Graph,
            Self::GetBaselineSummary => CanonicalReadModelCategory::Baseline,
            Self::GetIncidentLinkSummary => CanonicalReadModelCategory::IncidentLinkedGroups,
            Self::GetReportTraceability => CanonicalReadModelCategory::ReportTraceability,
            Self::GetExportTraceability => CanonicalReadModelCategory::ExportTraceabilityHistory,
            Self::GetStorageOwnerSummary => CanonicalReadModelCategory::StorageOwnerSummary,
            Self::GetProviderControllerStatus
            | Self::ListNetworkProviderStatus
            | Self::GetNetworkProviderStatus
            | Self::GetNetworkVisibilitySummary
            | Self::GetNetworkFallbackPlan => CanonicalReadModelCategory::ProviderControllerStatus,
        }
    }

    pub const fn all() -> &'static [Self] {
        &[
            Self::GetRuntimeOwnership,
            Self::GetComponentOwnershipSummary,
            Self::GetRuntimeHealth,
            Self::ListCapabilityStatus,
            Self::GetCapabilityHealthSummary,
            Self::GetSchedulerStatus,
            Self::GetSchedulerHostStatus,
            Self::GetNativeSamplerStatus,
            Self::GetNativePermissionStatus,
            Self::GetEndpointThreatSummary,
            Self::GetFusionSummary,
            Self::GetEvidenceQualitySummary,
            Self::GetRiskSummary,
            Self::GetAttackCoverageSummary,
            Self::GetGraphSummary,
            Self::GetBaselineSummary,
            Self::GetIncidentLinkSummary,
            Self::GetReportTraceability,
            Self::GetExportTraceability,
            Self::GetStorageOwnerSummary,
            Self::GetProviderControllerStatus,
            Self::ListNetworkProviderStatus,
            Self::GetNetworkProviderStatus,
            Self::GetNetworkVisibilitySummary,
            Self::GetNetworkFallbackPlan,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadCommandRequiredRuntimeState {
    ServiceOwned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadCommandTruncationPolicy {
    StablePage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReadCommandDeclaration {
    pub command_id: ServiceReadCommandId,
    pub protocol_version: SchemaVersion,
    pub schema_version: SchemaVersion,
    pub timeout_ms: u64,
    pub maximum_response_size: usize,
    pub maximum_item_count: usize,
    pub maximum_nested_depth: usize,
    pub maximum_refs_per_record: usize,
    pub snapshot_max_age_ms: i64,
    pub required_runtime_state: ReadCommandRequiredRuntimeState,
    pub allowed_freshness_states: Vec<ReadModelSnapshotFreshness>,
    pub truncation_policy: ReadCommandTruncationPolicy,
    pub audit_required: bool,
}

impl ServiceReadCommandDeclaration {
    pub fn validate(&self) -> Result<(), ReadCommandContractError> {
        if self.protocol_version != READ_COMMAND_PROTOCOL_VERSION {
            return Err(ReadCommandContractError::VersionMismatch);
        }
        if self.schema_version != READ_COMMAND_SCHEMA_VERSION {
            return Err(ReadCommandContractError::VersionMismatch);
        }
        if self.timeout_ms == 0
            || self.timeout_ms > 1_000
            || self.maximum_response_size == 0
            || self.maximum_response_size > READ_COMMAND_MAX_RESPONSE_BYTES
            || self.maximum_item_count == 0
            || self.maximum_item_count > READ_COMMAND_MAX_ITEMS
            || self.maximum_nested_depth == 0
            || self.maximum_nested_depth > READ_COMMAND_MAX_NESTED_DEPTH
            || self.maximum_refs_per_record == 0
            || self.maximum_refs_per_record > READ_COMMAND_MAX_REFS_PER_RECORD
            || self.snapshot_max_age_ms <= 0
            || self.allowed_freshness_states.is_empty()
            || !self.audit_required
        {
            return Err(ReadCommandContractError::LimitExceeded("declaration"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReadCommandRequest {
    #[serde(default)]
    pub page_size: Option<usize>,
    #[serde(default)]
    pub continuation_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReadCommandResponse {
    pub command_id: ServiceReadCommandId,
    pub protocol_version: SchemaVersion,
    pub schema_version: SchemaVersion,
    pub snapshot_id: ReadModelSnapshotId,
    pub ownership_ref: String,
    pub ownership_epoch: u64,
    pub generation_bucket: String,
    pub freshness_state: ReadModelSnapshotFreshness,
    pub partial_state: bool,
    pub items: Vec<CanonicalReadModelSnapshotItem>,
    pub total_available: usize,
    pub truncated: bool,
    pub continuation_token: Option<String>,
    pub degraded_reason: Option<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl ServiceReadCommandResponse {
    pub fn validate_with_declaration(
        &self,
        declaration: &ServiceReadCommandDeclaration,
    ) -> Result<(), ReadCommandContractError> {
        declaration.validate()?;
        if self.command_id != declaration.command_id {
            return Err(ReadCommandContractError::UnknownCommand);
        }
        validate_safe_text("ownership_ref", &self.ownership_ref)?;
        validate_safe_text("generation_bucket", &self.generation_bucket)?;
        validate_optional_safe_text("continuation_token", self.continuation_token.as_deref())?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        validate_safe_text("provenance_id", &self.provenance_id)?;
        if self.protocol_version != READ_COMMAND_PROTOCOL_VERSION
            || self.schema_version != READ_COMMAND_SCHEMA_VERSION
        {
            return Err(ReadCommandContractError::VersionMismatch);
        }
        if self.ownership_epoch == 0 {
            return Err(ReadCommandContractError::EpochRequired);
        }
        if self.items.len() > declaration.maximum_item_count {
            return Err(ReadCommandContractError::LimitExceeded("items"));
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ReadCommandContractError::RedactionRequired);
        }
        if !declaration
            .allowed_freshness_states
            .contains(&self.freshness_state)
        {
            return Err(ReadCommandContractError::FreshnessNotAllowed);
        }
        for item in &self.items {
            item.validate()
                .map_err(|_| ReadCommandContractError::UnsafeField("item"))?;
            if item.bounded_refs.len() > declaration.maximum_refs_per_record {
                return Err(ReadCommandContractError::LimitExceeded("bounded_refs"));
            }
        }
        let value = serde_json::to_value(self)
            .map_err(|_| ReadCommandContractError::SerializationFailed)?;
        if json_depth(&value) > declaration.maximum_nested_depth {
            return Err(ReadCommandContractError::LimitExceeded("nested_depth"));
        }
        let size = serde_json::to_vec(self)
            .map_err(|_| ReadCommandContractError::SerializationFailed)?
            .len();
        if size > declaration.maximum_response_size {
            return Err(ReadCommandContractError::LimitExceeded("response_size"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadCommandContractError {
    UnknownCommand,
    VersionMismatch,
    EpochRequired,
    FreshnessNotAllowed,
    LimitExceeded(&'static str),
    UnsafeField(&'static str),
    RedactionRequired,
    SerializationFailed,
}

impl fmt::Display for ReadCommandContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand => write!(f, "read command is not allowlisted"),
            Self::VersionMismatch => write!(f, "read command version mismatch"),
            Self::EpochRequired => write!(f, "read command ownership epoch is required"),
            Self::FreshnessNotAllowed => write!(f, "read command freshness is not allowed"),
            Self::LimitExceeded(field) => write!(f, "read command limit exceeded for {field}"),
            Self::UnsafeField(field) => write!(f, "read command unsafe field {field}"),
            Self::RedactionRequired => write!(f, "read command response must be redacted"),
            Self::SerializationFailed => write!(f, "read command serialization failed"),
        }
    }
}

impl std::error::Error for ReadCommandContractError {}

pub fn service_read_command_declarations() -> Vec<ServiceReadCommandDeclaration> {
    ServiceReadCommandId::all()
        .iter()
        .copied()
        .map(service_read_command_declaration)
        .collect()
}

pub fn service_read_command_declaration(
    command_id: ServiceReadCommandId,
) -> ServiceReadCommandDeclaration {
    ServiceReadCommandDeclaration {
        command_id,
        protocol_version: READ_COMMAND_PROTOCOL_VERSION,
        schema_version: READ_COMMAND_SCHEMA_VERSION,
        timeout_ms: READ_COMMAND_TIMEOUT_MS,
        maximum_response_size: READ_COMMAND_MAX_RESPONSE_BYTES,
        maximum_item_count: READ_COMMAND_MAX_ITEMS,
        maximum_nested_depth: READ_COMMAND_MAX_NESTED_DEPTH,
        maximum_refs_per_record: READ_COMMAND_MAX_REFS_PER_RECORD,
        snapshot_max_age_ms: READ_COMMAND_MAX_SNAPSHOT_AGE_MS,
        required_runtime_state: ReadCommandRequiredRuntimeState::ServiceOwned,
        allowed_freshness_states: vec![
            ReadModelSnapshotFreshness::Fresh,
            ReadModelSnapshotFreshness::Aging,
            ReadModelSnapshotFreshness::Stale,
            ReadModelSnapshotFreshness::Unavailable,
        ],
        truncation_policy: ReadCommandTruncationPolicy::StablePage,
        audit_required: true,
    }
}

pub fn build_service_read_command_response(
    command_id: ServiceReadCommandId,
    snapshot: &CanonicalReadModelSnapshot,
    request: &ServiceReadCommandRequest,
) -> Result<ServiceReadCommandResponse, ReadCommandContractError> {
    let declaration = service_read_command_declaration(command_id);
    declaration.validate()?;
    snapshot
        .validate()
        .map_err(|_| ReadCommandContractError::UnsafeField("snapshot"))?;
    validate_optional_safe_text("continuation_token", request.continuation_token.as_deref())?;
    let start = request
        .continuation_token
        .as_deref()
        .map(parse_continuation_token)
        .transpose()?
        .unwrap_or_default();
    let page_size = request
        .page_size
        .unwrap_or(declaration.maximum_item_count)
        .clamp(1, declaration.maximum_item_count);
    let mut matching = snapshot
        .items
        .iter()
        .filter(|item| item.model_category == command_id.category())
        .cloned()
        .collect::<Vec<_>>();
    matching.sort_by_key(|item| item.model_category);
    let total_available = matching.len();
    let mut truncated = start > 0 || start.saturating_add(page_size) < total_available;
    let items = matching
        .into_iter()
        .skip(start)
        .take(page_size)
        .map(|mut item| {
            if item.bounded_refs.len() > declaration.maximum_refs_per_record {
                item.bounded_refs
                    .truncate(declaration.maximum_refs_per_record);
                truncated = true;
            }
            item
        })
        .collect::<Vec<_>>();
    let continuation_token = if start.saturating_add(items.len()) < total_available {
        Some(format!("read_page_{}", start + items.len()))
    } else {
        None
    };
    let snapshot_age_ms = Utc::now()
        .signed_duration_since(*snapshot.generated_time_bucket.as_datetime())
        .num_milliseconds();
    let mut freshness_state = snapshot.freshness_state;
    let mut partial_state = snapshot.partial_state;
    let mut degraded_reason = snapshot.degraded_reason.clone();
    if snapshot_age_ms > declaration.snapshot_max_age_ms {
        partial_state = true;
        freshness_state = ReadModelSnapshotFreshness::Stale;
        degraded_reason = Some("snapshot_age_limit_exceeded".to_string());
    }
    if !declaration
        .allowed_freshness_states
        .contains(&freshness_state)
    {
        partial_state = true;
        freshness_state = ReadModelSnapshotFreshness::Unavailable;
        degraded_reason = Some("snapshot_freshness_not_allowed".to_string());
    }
    let mut response = ServiceReadCommandResponse {
        command_id,
        protocol_version: READ_COMMAND_PROTOCOL_VERSION,
        schema_version: READ_COMMAND_SCHEMA_VERSION,
        snapshot_id: snapshot.snapshot_id.clone(),
        ownership_ref: snapshot.ownership_ref.clone(),
        ownership_epoch: snapshot.ownership_epoch,
        generation_bucket: snapshot.generation_bucket.clone(),
        freshness_state,
        partial_state,
        items,
        total_available,
        truncated,
        continuation_token,
        degraded_reason,
        provenance_id: snapshot.provenance_id.clone(),
        redaction_status: RedactionStatus::Redacted,
    };
    while serde_json::to_vec(&response)
        .map_err(|_| ReadCommandContractError::SerializationFailed)?
        .len()
        > declaration.maximum_response_size
        && !response.items.is_empty()
    {
        response.items.pop();
        response.truncated = true;
        truncated = true;
    }
    if truncated
        && response.continuation_token.is_none()
        && start + response.items.len() < total_available
    {
        response.continuation_token = Some(format!("read_page_{}", start + response.items.len()));
    }
    response.validate_with_declaration(&declaration)?;
    Ok(response)
}

fn parse_continuation_token(value: &str) -> Result<usize, ReadCommandContractError> {
    validate_safe_text("continuation_token", value)?;
    let Some(offset) = value.strip_prefix("read_page_") else {
        return Err(ReadCommandContractError::UnsafeField("continuation_token"));
    };
    offset
        .parse::<usize>()
        .map_err(|_| ReadCommandContractError::UnsafeField("continuation_token"))
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ReadCommandContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), ReadCommandContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > READ_COMMAND_MAX_CONTINUATION_LEN.max(128) {
        return Err(ReadCommandContractError::UnsafeField(field));
    }
    let normalized = trimmed.to_ascii_lowercase();
    for marker in [
        "raw_db_cursor",
        "select ",
        "sql",
        "runtime_handle",
        "authorization_nonce",
        "nonce",
        "secret",
        "token",
        "password",
        "credential",
        "c:\\",
        "/users/",
        "/home/",
    ] {
        if normalized.contains(marker) {
            return Err(ReadCommandContractError::UnsafeField(field));
        }
    }
    Ok(())
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or_default(),
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or_default(),
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        runtime_ownership::{
            RuntimeComponentLifecycle, RuntimeHealthState, RuntimeMode, RuntimeOwnerCategory,
        },
        Timestamp, READ_MODEL_SNAPSHOT_SCHEMA_VERSION,
    };

    fn snapshot_with_items(
        items: Vec<CanonicalReadModelSnapshotItem>,
    ) -> CanonicalReadModelSnapshot {
        CanonicalReadModelSnapshot {
            snapshot_id: ReadModelSnapshotId::new_v4(),
            ownership_ref: "runtime-owner-ref".to_string(),
            ownership_epoch: 1,
            runtime_owner: RuntimeOwnerCategory::ServiceHost,
            runtime_mode: RuntimeMode::ServiceOwned,
            schema_version: READ_MODEL_SNAPSHOT_SCHEMA_VERSION,
            generation_bucket: "generation_00000001".to_string(),
            generated_time_bucket: Timestamp::now(),
            freshness_state: ReadModelSnapshotFreshness::Fresh,
            partial_state: false,
            items,
            degraded_reason: None,
            missing_visibility_flags: Vec::new(),
            provenance_id: "read_command_contract_test".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn item(category: CanonicalReadModelCategory, idx: usize) -> CanonicalReadModelSnapshotItem {
        CanonicalReadModelSnapshotItem {
            model_category: category,
            lifecycle_state: RuntimeComponentLifecycle::Ready,
            health_state: RuntimeHealthState::Ready,
            bounded_categories: vec!["servicehost_canonical".to_string()],
            bounded_buckets: vec!["count_one".to_string()],
            bounded_refs: vec![format!("bounded_ref_{idx}")],
            degraded_reason: None,
            missing_visibility_flags: Vec::new(),
            provenance_id: "read_command_contract_test".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    #[test]
    fn read_commands_every_command_has_valid_declaration() {
        let declarations = service_read_command_declarations();
        assert_eq!(declarations.len(), ServiceReadCommandId::all().len());
        for command in ServiceReadCommandId::all() {
            let declaration = service_read_command_declaration(*command);
            assert_eq!(declaration.command_id, *command);
            declaration.validate().expect("valid declaration");
            assert_eq!(ServiceReadCommandId::parse(command.as_str()), Ok(*command));
        }
    }

    #[test]
    fn read_commands_unknown_command_is_rejected() {
        assert_eq!(
            ServiceReadCommandId::parse("start_scheduler"),
            Err(ReadCommandContractError::UnknownCommand)
        );
    }

    #[test]
    fn read_commands_build_bounded_category_response() {
        let snapshot = snapshot_with_items(vec![
            item(CanonicalReadModelCategory::RuntimeOwnership, 1),
            item(CanonicalReadModelCategory::Risk, 2),
        ]);
        let response = build_service_read_command_response(
            ServiceReadCommandId::GetRiskSummary,
            &snapshot,
            &ServiceReadCommandRequest::default(),
        )
        .expect("response");

        assert_eq!(response.command_id, ServiceReadCommandId::GetRiskSummary);
        assert_eq!(response.items.len(), 1);
        assert_eq!(
            response.items[0].model_category,
            CanonicalReadModelCategory::Risk
        );
        assert!(!response.truncated);
    }

    #[test]
    fn read_commands_pagination_uses_safe_continuation_tokens() {
        let snapshot = snapshot_with_items(
            (0..3)
                .map(|idx| item(CanonicalReadModelCategory::ComponentLifecycleHealth, idx))
                .collect(),
        );
        let first = build_service_read_command_response(
            ServiceReadCommandId::GetComponentOwnershipSummary,
            &snapshot,
            &ServiceReadCommandRequest {
                page_size: Some(1),
                continuation_token: None,
            },
        )
        .expect("first page");
        assert!(first.truncated);
        assert_eq!(first.continuation_token.as_deref(), Some("read_page_1"));

        let second = build_service_read_command_response(
            ServiceReadCommandId::GetComponentOwnershipSummary,
            &snapshot,
            &ServiceReadCommandRequest {
                page_size: Some(1),
                continuation_token: first.continuation_token,
            },
        )
        .expect("second page");
        assert_eq!(second.items.len(), 1);

        let unsafe_token = build_service_read_command_response(
            ServiceReadCommandId::GetComponentOwnershipSummary,
            &snapshot,
            &ServiceReadCommandRequest {
                page_size: Some(1),
                continuation_token: Some("select * from rows".to_string()),
            },
        );
        assert!(unsafe_token.is_err());
    }

    #[test]
    fn read_commands_reject_version_mismatch() {
        let mut declaration =
            service_read_command_declaration(ServiceReadCommandId::GetRuntimeOwnership);
        declaration.schema_version = SchemaVersion::new(99, 0, 0);
        assert_eq!(
            declaration.validate(),
            Err(ReadCommandContractError::VersionMismatch)
        );
    }
}
