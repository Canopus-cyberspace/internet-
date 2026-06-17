use crate::{
    runtime_ownership::{
        RuntimeComponentLifecycle, RuntimeHealthState, RuntimeMode, RuntimeOwnerCategory,
    },
    ReadModelSnapshotId, RedactionStatus, SchemaVersion, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const READ_MODEL_SNAPSHOT_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_READ_MODEL_SNAPSHOT_ITEMS: usize = 32;
pub const MAX_READ_MODEL_SNAPSHOT_TEXT_LEN: usize = 128;
pub const MAX_READ_MODEL_SNAPSHOT_LIST_ITEMS: usize = 24;
pub const REPORT_EXPORT_TRACEABILITY_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_REPORT_EXPORT_TRACEABILITY_REFS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadModelSnapshotContractError {
    EmptyField(&'static str),
    TooLong {
        field: &'static str,
        max_len: usize,
        actual_len: usize,
    },
    UnsafeField(&'static str),
    UnsupportedSchemaVersion,
    OwnershipEpochRequired,
    TooManyItems(&'static str),
    RedactionRequired(&'static str),
    UnsupportedRuntimeOwner,
}

impl fmt::Display for ReadModelSnapshotContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::TooLong {
                field,
                max_len,
                actual_len,
            } => write!(
                f,
                "{field} length {actual_len} exceeds max {max_len} characters"
            ),
            Self::UnsafeField(field) => write!(f, "{field} contains unsafe read-model metadata"),
            Self::UnsupportedSchemaVersion => write!(f, "read-model snapshot schema unsupported"),
            Self::OwnershipEpochRequired => write!(f, "ownership epoch is required"),
            Self::TooManyItems(field) => write!(f, "{field} contains too many items"),
            Self::RedactionRequired(field) => write!(f, "{field} must be redacted"),
            Self::UnsupportedRuntimeOwner => {
                write!(f, "read-model traceability must be ServiceHost-owned")
            }
        }
    }
}

impl std::error::Error for ReadModelSnapshotContractError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadModelSnapshotFreshness {
    Fresh,
    Aging,
    Stale,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalReadModelCategory {
    RuntimeOwnership,
    ComponentLifecycleHealth,
    RuntimeHealth,
    StorageOwnerSummary,
    CapabilityHealth,
    Scheduler,
    SchedulerHost,
    SamplerState,
    NativePermissionReadiness,
    EndpointThreat,
    Fusion,
    EvidenceQuality,
    Risk,
    AttackContext,
    Graph,
    Baseline,
    IncidentLinkedGroups,
    ReportTraceability,
    ExportTraceabilityHistory,
    ProviderControllerStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalReadModelSnapshotItem {
    pub model_category: CanonicalReadModelCategory,
    pub lifecycle_state: RuntimeComponentLifecycle,
    pub health_state: RuntimeHealthState,
    pub bounded_categories: Vec<String>,
    pub bounded_buckets: Vec<String>,
    pub bounded_refs: Vec<String>,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl CanonicalReadModelSnapshotItem {
    pub fn validate(&self) -> Result<(), ReadModelSnapshotContractError> {
        validate_string_list("bounded_categories", &self.bounded_categories)?;
        validate_string_list("bounded_buckets", &self.bounded_buckets)?;
        validate_string_list("bounded_refs", &self.bounded_refs)?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        validate_string_list("missing_visibility_flags", &self.missing_visibility_flags)?;
        validate_safe_text("provenance_id", &self.provenance_id)?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ReadModelSnapshotContractError::RedactionRequired(
                "snapshot item",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalReadModelSnapshot {
    pub snapshot_id: ReadModelSnapshotId,
    pub ownership_ref: String,
    pub ownership_epoch: u64,
    pub runtime_owner: RuntimeOwnerCategory,
    pub runtime_mode: RuntimeMode,
    pub schema_version: SchemaVersion,
    pub generation_bucket: String,
    pub generated_time_bucket: Timestamp,
    pub freshness_state: ReadModelSnapshotFreshness,
    pub partial_state: bool,
    pub items: Vec<CanonicalReadModelSnapshotItem>,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl CanonicalReadModelSnapshot {
    pub fn validate(&self) -> Result<(), ReadModelSnapshotContractError> {
        validate_safe_text("ownership_ref", &self.ownership_ref)?;
        validate_safe_text("generation_bucket", &self.generation_bucket)?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        validate_string_list("missing_visibility_flags", &self.missing_visibility_flags)?;
        validate_safe_text("provenance_id", &self.provenance_id)?;
        if self.schema_version != READ_MODEL_SNAPSHOT_SCHEMA_VERSION {
            return Err(ReadModelSnapshotContractError::UnsupportedSchemaVersion);
        }
        if self.ownership_epoch == 0 {
            return Err(ReadModelSnapshotContractError::OwnershipEpochRequired);
        }
        if self.items.len() > MAX_READ_MODEL_SNAPSHOT_ITEMS {
            return Err(ReadModelSnapshotContractError::TooManyItems("items"));
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ReadModelSnapshotContractError::RedactionRequired(
                "snapshot",
            ));
        }
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalReportExportTraceabilitySnapshot {
    pub ownership_ref: String,
    pub ownership_epoch: u64,
    pub runtime_owner: RuntimeOwnerCategory,
    pub schema_version: SchemaVersion,
    pub report_refs: Vec<String>,
    pub export_refs: Vec<String>,
    pub finding_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub hypothesis_refs: Vec<String>,
    pub risk_refs: Vec<String>,
    pub attack_refs: Vec<String>,
    pub graph_refs: Vec<String>,
    pub explicit_llm_story_refs: Vec<String>,
    pub snapshot_refs: Vec<String>,
    pub integrity_hash: String,
    pub generated_time_bucket: Timestamp,
    pub redaction_status: RedactionStatus,
}

impl CanonicalReportExportTraceabilitySnapshot {
    pub fn validate(&self) -> Result<(), ReadModelSnapshotContractError> {
        validate_safe_text("traceability ownership_ref", &self.ownership_ref)?;
        validate_safe_text("traceability integrity_hash", &self.integrity_hash)?;
        if self.ownership_epoch == 0 {
            return Err(ReadModelSnapshotContractError::OwnershipEpochRequired);
        }
        if self.runtime_owner != RuntimeOwnerCategory::ServiceHost {
            return Err(ReadModelSnapshotContractError::UnsupportedRuntimeOwner);
        }
        if self.schema_version != REPORT_EXPORT_TRACEABILITY_SCHEMA_VERSION {
            return Err(ReadModelSnapshotContractError::UnsupportedSchemaVersion);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ReadModelSnapshotContractError::RedactionRequired(
                "report export traceability",
            ));
        }
        for (field, refs) in [
            ("report_refs", &self.report_refs),
            ("export_refs", &self.export_refs),
            ("finding_refs", &self.finding_refs),
            ("evidence_refs", &self.evidence_refs),
            ("hypothesis_refs", &self.hypothesis_refs),
            ("risk_refs", &self.risk_refs),
            ("attack_refs", &self.attack_refs),
            ("graph_refs", &self.graph_refs),
            ("explicit_llm_story_refs", &self.explicit_llm_story_refs),
            ("snapshot_refs", &self.snapshot_refs),
        ] {
            validate_traceability_ref_list(field, refs)?;
        }
        Ok(())
    }
}

fn validate_string_list(
    field: &'static str,
    values: &[String],
) -> Result<(), ReadModelSnapshotContractError> {
    if values.len() > MAX_READ_MODEL_SNAPSHOT_LIST_ITEMS {
        return Err(ReadModelSnapshotContractError::TooManyItems(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_traceability_ref_list(
    field: &'static str,
    values: &[String],
) -> Result<(), ReadModelSnapshotContractError> {
    if values.len() > MAX_REPORT_EXPORT_TRACEABILITY_REFS {
        return Err(ReadModelSnapshotContractError::TooManyItems(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ReadModelSnapshotContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(
    field: &'static str,
    value: &str,
) -> Result<(), ReadModelSnapshotContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ReadModelSnapshotContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_READ_MODEL_SNAPSHOT_TEXT_LEN {
        return Err(ReadModelSnapshotContractError::TooLong {
            field,
            max_len: MAX_READ_MODEL_SNAPSHOT_TEXT_LEN,
            actual_len: trimmed.len(),
        });
    }
    let normalized = trimmed.to_ascii_lowercase();
    for marker in [
        "pid",
        "ppid",
        "process_id",
        "process_name",
        "handle",
        "pointer",
        "raw_log",
        "raw_provider",
        "provider_value",
        "username",
        "sid",
        "hostname",
        "host_identifier",
        "credential",
        "secret",
        "token",
        "password",
        "api_key",
        "c:\\",
        "\\users\\",
        "/users/",
        "/home/",
        "http://",
        "https://",
    ] {
        if normalized.contains(marker) {
            return Err(ReadModelSnapshotContractError::UnsafeField(field));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_item() -> CanonicalReadModelSnapshotItem {
        CanonicalReadModelSnapshotItem {
            model_category: CanonicalReadModelCategory::RuntimeOwnership,
            lifecycle_state: RuntimeComponentLifecycle::Ready,
            health_state: RuntimeHealthState::Ready,
            bounded_categories: vec!["service_owned_runtime".to_string()],
            bounded_buckets: vec!["generation_current".to_string()],
            bounded_refs: vec!["runtime_owner_ref".to_string()],
            degraded_reason: None,
            missing_visibility_flags: vec!["provider_execution_deferred".to_string()],
            provenance_id: "canonical_read_model_snapshot_contract".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn valid_snapshot() -> CanonicalReadModelSnapshot {
        CanonicalReadModelSnapshot {
            snapshot_id: ReadModelSnapshotId::new_v4(),
            ownership_ref: "runtime-owner-ref".to_string(),
            ownership_epoch: 7,
            runtime_owner: RuntimeOwnerCategory::ServiceHost,
            runtime_mode: RuntimeMode::ServiceOwned,
            schema_version: READ_MODEL_SNAPSHOT_SCHEMA_VERSION,
            generation_bucket: "generation_current".to_string(),
            generated_time_bucket: Timestamp::now(),
            freshness_state: ReadModelSnapshotFreshness::Fresh,
            partial_state: false,
            items: vec![valid_item()],
            degraded_reason: None,
            missing_visibility_flags: Vec::new(),
            provenance_id: "canonical_read_model_snapshot_contract".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn valid_traceability_snapshot() -> CanonicalReportExportTraceabilitySnapshot {
        CanonicalReportExportTraceabilitySnapshot {
            ownership_ref: "runtime-owner-ref".to_string(),
            ownership_epoch: 7,
            runtime_owner: RuntimeOwnerCategory::ServiceHost,
            schema_version: REPORT_EXPORT_TRACEABILITY_SCHEMA_VERSION,
            report_refs: vec!["report_ref_001".to_string()],
            export_refs: vec!["export_ref_001".to_string()],
            finding_refs: vec!["finding_ref_001".to_string()],
            evidence_refs: vec!["evidence_ref_001".to_string()],
            hypothesis_refs: vec!["hypothesis_ref_001".to_string()],
            risk_refs: vec!["risk_ref_001".to_string()],
            attack_refs: vec!["attack_ref_tactic_bucket".to_string()],
            graph_refs: vec!["graph_ref_001".to_string()],
            explicit_llm_story_refs: vec!["story_ref_001".to_string()],
            snapshot_refs: vec!["snapshot_ref_001".to_string()],
            integrity_hash: "trace_hash_0123456789abcdef".to_string(),
            generated_time_bucket: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    #[test]
    fn read_model_snapshot_contract_accepts_bounded_redacted_snapshot() {
        valid_snapshot().validate().expect("valid snapshot");
    }

    #[test]
    fn read_model_snapshot_contract_rejects_unknown_fields() {
        let value = serde_json::json!({
            "snapshot_id": ReadModelSnapshotId::new_v4(),
            "ownership_ref": "runtime-owner-ref",
            "ownership_epoch": 7,
            "runtime_owner": "service_host",
            "runtime_mode": "service_owned",
            "schema_version": {"major": 1, "minor": 0, "patch": 0},
            "generation_bucket": "generation_current",
            "generated_time_bucket": Timestamp::now(),
            "freshness_state": "fresh",
            "partial_state": false,
            "items": [],
            "degraded_reason": null,
            "missing_visibility_flags": [],
            "provenance_id": "canonical_read_model_snapshot_contract",
            "redaction_status": "redacted",
            "pid": 1234
        });
        assert!(serde_json::from_value::<CanonicalReadModelSnapshot>(value).is_err());
    }

    #[test]
    fn read_model_snapshot_contract_requires_ownership_epoch() {
        let mut snapshot = valid_snapshot();
        snapshot.ownership_epoch = 0;
        assert!(matches!(
            snapshot.validate(),
            Err(ReadModelSnapshotContractError::OwnershipEpochRequired)
        ));
    }

    #[test]
    fn read_model_snapshot_contract_rejects_unsafe_values() {
        let mut snapshot = valid_snapshot();
        snapshot.items[0].bounded_refs = vec!["pid-4242".to_string()];
        assert!(matches!(
            snapshot.validate(),
            Err(ReadModelSnapshotContractError::UnsafeField("bounded_refs"))
        ));
    }

    #[test]
    fn read_model_snapshot_contract_serializes_without_sensitive_keys() {
        let snapshot = valid_snapshot();
        let serialized = serde_json::to_string(&snapshot).expect("serialize snapshot");
        for forbidden in [
            "process_name",
            "pid",
            "ppid",
            "username",
            "sid",
            "hostname",
            "token",
            "credential",
            "secret",
            "handle",
            "provider_value",
            "raw_log",
            "http://",
            "https://",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(forbidden),
                "serialized snapshot leaked forbidden marker {forbidden}"
            );
        }
    }

    #[test]
    fn read_model_snapshot_freshness_state_is_bounded() {
        let states = [
            ReadModelSnapshotFreshness::Fresh,
            ReadModelSnapshotFreshness::Aging,
            ReadModelSnapshotFreshness::Stale,
            ReadModelSnapshotFreshness::Unavailable,
        ];
        assert_eq!(states.len(), 4);
    }

    #[test]
    fn read_models_report_export_traceability_contract_accepts_bounded_refs() {
        let snapshot = valid_traceability_snapshot();

        snapshot.validate().expect("traceability validates");
        let serialized = serde_json::to_string(&snapshot).expect("traceability serializes");
        for marker in [
            "c:\\",
            "pid:",
            "process_name",
            "raw_log",
            "provider_value",
            "username",
            "sid",
            "token",
            "password",
            "api_key",
            "http://",
            "https://",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "traceability leaked marker {marker}"
            );
        }
    }

    #[test]
    fn read_models_report_export_traceability_rejects_unsafe_owner_and_refs() {
        let mut snapshot = valid_traceability_snapshot();
        snapshot.runtime_owner = RuntimeOwnerCategory::DesktopPortable;
        assert_eq!(
            snapshot.validate(),
            Err(ReadModelSnapshotContractError::UnsupportedRuntimeOwner)
        );

        let mut snapshot = valid_traceability_snapshot();
        snapshot.evidence_refs = vec!["evidence_ref_with_api_key_value".to_string()];
        assert!(matches!(
            snapshot.validate(),
            Err(ReadModelSnapshotContractError::UnsafeField("evidence_refs"))
        ));

        let mut snapshot = valid_traceability_snapshot();
        snapshot.report_refs = (0..=MAX_REPORT_EXPORT_TRACEABILITY_REFS)
            .map(|idx| format!("report_ref_{idx:02}"))
            .collect();
        assert_eq!(
            snapshot.validate(),
            Err(ReadModelSnapshotContractError::TooManyItems("report_refs"))
        );
    }
}
