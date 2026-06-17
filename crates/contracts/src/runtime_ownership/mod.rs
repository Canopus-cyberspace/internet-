use crate::{AuditId, RedactionStatus, SchemaVersion, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const RUNTIME_OWNERSHIP_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const RUNTIME_OWNERSHIP_PROTOCOL_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_RUNTIME_OWNERSHIP_COMPONENTS: usize = 32;
pub const MAX_RUNTIME_OWNERSHIP_AUDIT_REFS: usize = 32;
pub const MAX_RUNTIME_SHUTDOWN_STAGES: usize = 24;
pub const MAX_RUNTIME_OWNERSHIP_TEXT_LEN: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeOwnershipContractError {
    EmptyField(&'static str),
    TooLong {
        field: &'static str,
        max_len: usize,
        actual_len: usize,
    },
    UnsafeField(&'static str),
    UnsupportedProtocolVersion,
    UnsupportedSchemaVersion,
    InvalidOwnerModeCombination,
    InvalidLifecycleCombination,
    TooManyItems(&'static str),
    RedactionRequired(&'static str),
}

impl fmt::Display for RuntimeOwnershipContractError {
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
            Self::UnsafeField(field) => write!(f, "{field} contains unsafe runtime metadata"),
            Self::UnsupportedProtocolVersion => {
                write!(f, "runtime ownership protocol version is unsupported")
            }
            Self::UnsupportedSchemaVersion => {
                write!(f, "runtime ownership schema version is unsupported")
            }
            Self::InvalidOwnerModeCombination => {
                write!(f, "runtime owner category does not match runtime mode")
            }
            Self::InvalidLifecycleCombination => {
                write!(f, "runtime lifecycle combination is invalid")
            }
            Self::TooManyItems(field) => write!(f, "{field} contains too many items"),
            Self::RedactionRequired(field) => write!(f, "{field} must be redacted"),
        }
    }
}

impl std::error::Error for RuntimeOwnershipContractError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Unresolved,
    PortableInProcess,
    ServiceOwned,
    ServiceDegraded,
    ServiceUnavailable,
    ProtocolIncompatible,
    OwnershipTransitionPending,
    ShutdownInProgress,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOwnerCategory {
    DesktopPortable,
    ServiceHost,
    TestHarness,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeComponentCategory {
    EventBus,
    TopicCatalog,
    Dag,
    PluginRuntime,
    CapabilityRegistry,
    PortableReaders,
    NativePermissions,
    NativeScheduler,
    NativeSchedulerHost,
    NativeSamplers,
    EndpointThreat,
    Fusion,
    EvidenceQuality,
    Risk,
    AttackContext,
    Graph,
    Baseline,
    IncidentLinking,
    ReadModels,
    ReportTraceability,
    ExportTraceability,
    ProviderController,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeComponentLifecycle {
    NotInitialized,
    Initializing,
    Ready,
    Inactive,
    Running,
    Degraded,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeHealthState {
    Unknown,
    Healthy,
    Ready,
    Inactive,
    Degraded,
    Failed,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTransitionState {
    None,
    OwnershipRequested,
    OwnershipAcquired,
    Initializing,
    Ready,
    ShuttingDown,
    Released,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAuthorizationCategory {
    ServiceHostLocal,
    DesktopPortableFallback,
    TestHarness,
    Unresolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMutationTrustState {
    ImpersonationNotImplemented,
    TrustedLocalService,
    TestOnly,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOwnershipAuditEventKind {
    RuntimeOwnershipRequested,
    RuntimeOwnershipAcquired,
    RuntimeOwnershipRejected,
    RuntimeContainerInitializationStarted,
    RuntimeComponentInitialized,
    RuntimeComponentInitializationFailed,
    RuntimeContainerReady,
    DuplicateRuntimeBlocked,
    DesktopRuntimeCreationBlocked,
    PortableFallbackSelected,
    RuntimeShutdownStarted,
    RuntimeComponentStopped,
    RuntimeShutdownCompleted,
    RuntimeShutdownTimeout,
    StorageOwnerAcquired,
    StorageOwnerConflict,
    StorageOwnerReleased,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeShutdownState {
    NotStarted,
    InProgress,
    Completed,
    Failed,
    TimedOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeShutdownStage {
    RejectMutations,
    ShutdownInProgress,
    InvalidateMutationLeases,
    SignalSchedulerHostCancellation,
    JoinSchedulerHost,
    DisableScheduler,
    StopSamplers,
    StopPortableReaders,
    CancelAnalysisWork,
    DrainEventBus,
    StopPluginRuntime,
    StopDag,
    CloseEventBus,
    FinalizeCanonicalReadModels,
    CloseStorageWriter,
    ClearServiceSessionState,
    ReleaseOwnershipGuard,
    CloseIpc,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeShutdownStageState {
    Pending,
    Completed,
    Skipped,
    Failed,
    TimedOut,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeShutdownStageSummary {
    pub stage: RuntimeShutdownStage,
    pub state: RuntimeShutdownStageState,
    pub timeout_bucket: String,
    pub duration_bucket: String,
    pub reason_category: Option<String>,
    pub audit_refs: Vec<AuditId>,
    pub redaction_status: RedactionStatus,
}

impl RuntimeShutdownStageSummary {
    pub fn validate(&self) -> Result<(), RuntimeOwnershipContractError> {
        validate_safe_text("shutdown timeout_bucket", &self.timeout_bucket)?;
        validate_safe_text("shutdown duration_bucket", &self.duration_bucket)?;
        validate_optional_safe_text("shutdown reason_category", self.reason_category.as_deref())?;
        if self.audit_refs.len() > MAX_RUNTIME_OWNERSHIP_AUDIT_REFS
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(RuntimeOwnershipContractError::InvalidLifecycleCombination);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeShutdownSummary {
    pub state: RuntimeShutdownState,
    pub total_timeout_bucket: String,
    pub mutation_leases_invalidated: bool,
    pub scheduler_host_cancellation_signalled: bool,
    pub scheduler_host_joined: bool,
    pub provider_stop_called: bool,
    pub stages: Vec<RuntimeShutdownStageSummary>,
    pub audit_refs: Vec<AuditId>,
    pub redaction_status: RedactionStatus,
}

impl RuntimeShutdownSummary {
    pub fn validate(&self) -> Result<(), RuntimeOwnershipContractError> {
        validate_safe_text("shutdown total_timeout_bucket", &self.total_timeout_bucket)?;
        if self.stages.len() > MAX_RUNTIME_SHUTDOWN_STAGES
            || self.audit_refs.len() > MAX_RUNTIME_OWNERSHIP_AUDIT_REFS
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(RuntimeOwnershipContractError::InvalidLifecycleCombination);
        }
        for stage in &self.stages {
            stage.validate()?;
        }
        let expected_order = [
            RuntimeShutdownStage::RejectMutations,
            RuntimeShutdownStage::ShutdownInProgress,
            RuntimeShutdownStage::InvalidateMutationLeases,
            RuntimeShutdownStage::SignalSchedulerHostCancellation,
            RuntimeShutdownStage::JoinSchedulerHost,
            RuntimeShutdownStage::DisableScheduler,
            RuntimeShutdownStage::StopSamplers,
            RuntimeShutdownStage::StopPortableReaders,
            RuntimeShutdownStage::CancelAnalysisWork,
            RuntimeShutdownStage::DrainEventBus,
            RuntimeShutdownStage::StopPluginRuntime,
            RuntimeShutdownStage::StopDag,
            RuntimeShutdownStage::CloseEventBus,
            RuntimeShutdownStage::FinalizeCanonicalReadModels,
            RuntimeShutdownStage::CloseStorageWriter,
            RuntimeShutdownStage::ClearServiceSessionState,
            RuntimeShutdownStage::ReleaseOwnershipGuard,
            RuntimeShutdownStage::CloseIpc,
            RuntimeShutdownStage::Stopped,
        ];
        if self
            .stages
            .iter()
            .zip(expected_order.iter())
            .any(|(actual, expected)| actual.stage != *expected)
        {
            return Err(RuntimeOwnershipContractError::InvalidLifecycleCombination);
        }
        if self.state == RuntimeShutdownState::Completed
            && (!self.mutation_leases_invalidated
                || !self.scheduler_host_cancellation_signalled
                || !self.scheduler_host_joined
                || self.stages.len() != expected_order.len()
                || self.stages.last().map(|stage| stage.stage)
                    != Some(RuntimeShutdownStage::Stopped))
        {
            return Err(RuntimeOwnershipContractError::InvalidLifecycleCombination);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProviderZeroSummary {
    pub ip_helper_calls: u32,
    pub etw_calls: u32,
    pub npcap_probes: u32,
    pub capture_broker_launches: u32,
    pub native_network_topics: u32,
    pub process_network_facts: u32,
    pub packet_facts: u32,
}

impl RuntimeProviderZeroSummary {
    pub fn all_zero(&self) -> bool {
        self.ip_helper_calls == 0
            && self.etw_calls == 0
            && self.npcap_probes == 0
            && self.capture_broker_launches == 0
            && self.native_network_topics == 0
            && self.process_network_facts == 0
            && self.packet_facts == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOwnerContext {
    pub owner_category: RuntimeOwnerCategory,
    pub runtime_mode: RuntimeMode,
    pub ownership_ref: String,
    pub ownership_epoch: u64,
    pub service_instance_ref: Option<String>,
    pub policy_profile_ref: String,
    pub protocol_version: SchemaVersion,
    pub schema_version: SchemaVersion,
    pub authorization_category: RuntimeAuthorizationCategory,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl RuntimeOwnerContext {
    pub fn service_host(
        ownership_ref: impl Into<String>,
        ownership_epoch: u64,
        service_instance_ref: impl Into<String>,
    ) -> Self {
        Self {
            owner_category: RuntimeOwnerCategory::ServiceHost,
            runtime_mode: RuntimeMode::ServiceOwned,
            ownership_ref: ownership_ref.into(),
            ownership_epoch,
            service_instance_ref: Some(service_instance_ref.into()),
            policy_profile_ref: "service_host_runtime_profile".to_string(),
            protocol_version: RUNTIME_OWNERSHIP_PROTOCOL_VERSION,
            schema_version: RUNTIME_OWNERSHIP_SCHEMA_VERSION,
            authorization_category: RuntimeAuthorizationCategory::ServiceHostLocal,
            provenance_id: "service_host_runtime_ownership".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn portable_fallback(ownership_ref: impl Into<String>, ownership_epoch: u64) -> Self {
        Self {
            owner_category: RuntimeOwnerCategory::DesktopPortable,
            runtime_mode: RuntimeMode::PortableInProcess,
            ownership_ref: ownership_ref.into(),
            ownership_epoch,
            service_instance_ref: None,
            policy_profile_ref: "portable_default_runtime_profile".to_string(),
            protocol_version: RUNTIME_OWNERSHIP_PROTOCOL_VERSION,
            schema_version: RUNTIME_OWNERSHIP_SCHEMA_VERSION,
            authorization_category: RuntimeAuthorizationCategory::DesktopPortableFallback,
            provenance_id: "desktop_portable_runtime_ownership".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn test_harness(ownership_ref: impl Into<String>, ownership_epoch: u64) -> Self {
        Self {
            owner_category: RuntimeOwnerCategory::TestHarness,
            runtime_mode: RuntimeMode::PortableInProcess,
            ownership_ref: ownership_ref.into(),
            ownership_epoch,
            service_instance_ref: None,
            policy_profile_ref: "test_harness_runtime_profile".to_string(),
            protocol_version: RUNTIME_OWNERSHIP_PROTOCOL_VERSION,
            schema_version: RUNTIME_OWNERSHIP_SCHEMA_VERSION,
            authorization_category: RuntimeAuthorizationCategory::TestHarness,
            provenance_id: "runtime_ownership_test_harness".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn validate(&self) -> Result<(), RuntimeOwnershipContractError> {
        validate_safe_text("ownership_ref", &self.ownership_ref)?;
        validate_optional_safe_text("service_instance_ref", self.service_instance_ref.as_deref())?;
        validate_safe_text("policy_profile_ref", &self.policy_profile_ref)?;
        validate_safe_text("provenance_id", &self.provenance_id)?;
        if self.protocol_version != RUNTIME_OWNERSHIP_PROTOCOL_VERSION {
            return Err(RuntimeOwnershipContractError::UnsupportedProtocolVersion);
        }
        if self.schema_version != RUNTIME_OWNERSHIP_SCHEMA_VERSION {
            return Err(RuntimeOwnershipContractError::UnsupportedSchemaVersion);
        }
        if self.ownership_epoch == 0 {
            return Err(RuntimeOwnershipContractError::InvalidLifecycleCombination);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(RuntimeOwnershipContractError::RedactionRequired(
                "runtime owner context",
            ));
        }
        match (self.runtime_mode, self.owner_category) {
            (RuntimeMode::ServiceOwned, RuntimeOwnerCategory::ServiceHost)
            | (RuntimeMode::PortableInProcess, RuntimeOwnerCategory::DesktopPortable)
            | (RuntimeMode::PortableInProcess, RuntimeOwnerCategory::TestHarness)
            | (RuntimeMode::Unresolved, RuntimeOwnerCategory::None)
            | (RuntimeMode::ServiceUnavailable, RuntimeOwnerCategory::None)
            | (RuntimeMode::ProtocolIncompatible, RuntimeOwnerCategory::None)
            | (RuntimeMode::Failed, RuntimeOwnerCategory::None) => Ok(()),
            _ => Err(RuntimeOwnershipContractError::InvalidOwnerModeCombination),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeComponentOwnershipSummary {
    pub ownership_ref: String,
    pub ownership_epoch: u64,
    pub runtime_mode: RuntimeMode,
    pub owner_category: RuntimeOwnerCategory,
    pub component_category: RuntimeComponentCategory,
    pub component_lifecycle: RuntimeComponentLifecycle,
    pub runtime_health: RuntimeHealthState,
    pub degraded_reason: Option<String>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub time_bucket: Timestamp,
    pub redaction_status: RedactionStatus,
}

impl RuntimeComponentOwnershipSummary {
    pub fn validate(&self) -> Result<(), RuntimeOwnershipContractError> {
        validate_safe_text("component ownership_ref", &self.ownership_ref)?;
        validate_safe_text("component provenance_id", &self.provenance_id)?;
        validate_optional_safe_text("component degraded_reason", self.degraded_reason.as_deref())?;
        if self.ownership_epoch == 0
            || self.audit_refs.len() > MAX_RUNTIME_OWNERSHIP_AUDIT_REFS
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(RuntimeOwnershipContractError::InvalidLifecycleCombination);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOwnershipSummary {
    pub ownership_ref: String,
    pub ownership_epoch: u64,
    pub runtime_mode: RuntimeMode,
    pub owner_category: RuntimeOwnerCategory,
    pub runtime_health: RuntimeHealthState,
    pub transition_state: RuntimeTransitionState,
    pub protocol_version: SchemaVersion,
    pub schema_version: SchemaVersion,
    pub degraded_reason: Option<String>,
    pub mutation_trust_state: RuntimeMutationTrustState,
    pub mutation_commands_enabled: bool,
    pub provider_controller_state: String,
    pub provider_call_count: u32,
    pub provider_zero: RuntimeProviderZeroSummary,
    pub scheduler_state: String,
    pub scheduler_host_state: String,
    pub sampler_state: String,
    pub storage_owner_state: String,
    pub canonical_read_model_owner: String,
    pub snapshot_freshness: String,
    pub shutdown: RuntimeShutdownSummary,
    pub component_summaries: Vec<RuntimeComponentOwnershipSummary>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub time_bucket: Timestamp,
    pub redaction_status: RedactionStatus,
}

impl RuntimeOwnershipSummary {
    pub fn validate(&self) -> Result<(), RuntimeOwnershipContractError> {
        validate_safe_text("summary ownership_ref", &self.ownership_ref)?;
        validate_safe_text("summary provenance_id", &self.provenance_id)?;
        validate_safe_text("provider_controller_state", &self.provider_controller_state)?;
        validate_safe_text("scheduler_state", &self.scheduler_state)?;
        validate_safe_text("scheduler_host_state", &self.scheduler_host_state)?;
        validate_safe_text("sampler_state", &self.sampler_state)?;
        validate_safe_text("storage_owner_state", &self.storage_owner_state)?;
        validate_safe_text(
            "canonical_read_model_owner",
            &self.canonical_read_model_owner,
        )?;
        validate_safe_text("snapshot_freshness", &self.snapshot_freshness)?;
        validate_optional_safe_text("summary degraded_reason", self.degraded_reason.as_deref())?;
        if self.protocol_version != RUNTIME_OWNERSHIP_PROTOCOL_VERSION {
            return Err(RuntimeOwnershipContractError::UnsupportedProtocolVersion);
        }
        if self.schema_version != RUNTIME_OWNERSHIP_SCHEMA_VERSION {
            return Err(RuntimeOwnershipContractError::UnsupportedSchemaVersion);
        }
        if self.ownership_epoch == 0
            || self.component_summaries.len() > MAX_RUNTIME_OWNERSHIP_COMPONENTS
            || self.audit_refs.len() > MAX_RUNTIME_OWNERSHIP_AUDIT_REFS
            || self.redaction_status == RedactionStatus::RedactionRequired
            || self.mutation_commands_enabled
        {
            return Err(RuntimeOwnershipContractError::InvalidLifecycleCombination);
        }
        for component in &self.component_summaries {
            component.validate()?;
        }
        self.shutdown.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOwnershipAuditEvent {
    pub event_id: AuditId,
    pub event_kind: RuntimeOwnershipAuditEventKind,
    pub runtime_mode: RuntimeMode,
    pub owner_category: RuntimeOwnerCategory,
    pub component_category: Option<RuntimeComponentCategory>,
    pub previous_lifecycle: Option<RuntimeComponentLifecycle>,
    pub new_lifecycle: Option<RuntimeComponentLifecycle>,
    pub result_category: String,
    pub reason_category: Option<String>,
    pub time_bucket: Timestamp,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl RuntimeOwnershipAuditEvent {
    pub fn validate(&self) -> Result<(), RuntimeOwnershipContractError> {
        validate_safe_text("audit result_category", &self.result_category)?;
        validate_optional_safe_text("audit reason_category", self.reason_category.as_deref())?;
        validate_safe_text("audit provenance_id", &self.provenance_id)?;
        if self.audit_refs.len() > MAX_RUNTIME_OWNERSHIP_AUDIT_REFS
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(RuntimeOwnershipContractError::InvalidLifecycleCombination);
        }
        Ok(())
    }
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), RuntimeOwnershipContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(
    field: &'static str,
    value: &str,
) -> Result<(), RuntimeOwnershipContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(RuntimeOwnershipContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_RUNTIME_OWNERSHIP_TEXT_LEN {
        return Err(RuntimeOwnershipContractError::TooLong {
            field,
            max_len: MAX_RUNTIME_OWNERSHIP_TEXT_LEN,
            actual_len: trimmed.len(),
        });
    }
    let normalized = trimmed.to_ascii_lowercase();
    for marker in [
        "pid",
        "thread",
        "task_handle",
        "process_handle",
        "raw_pointer",
        "0x",
        "sid",
        "username",
        "hostname",
        "machine_identifier",
        "executable_path",
        "ipc_nonce",
        "nonce",
        "credential",
        "secret",
        "token",
        "password",
        "api_key",
        "c:\\",
        "/users/",
        "/home/",
        "http://",
        "https://",
    ] {
        if normalized.contains(marker) {
            return Err(RuntimeOwnershipContractError::UnsafeField(field));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_ownership_context_accepts_bounded_service_host_owner() {
        RuntimeOwnerContext::service_host("runtime-owner-a", 1, "service-instance-a")
            .validate()
            .expect("valid service host owner");
    }

    #[test]
    fn runtime_ownership_context_rejects_invalid_owner_mode_combination() {
        let mut context = RuntimeOwnerContext::service_host("runtime-owner-a", 1, "service-a");
        context.owner_category = RuntimeOwnerCategory::DesktopPortable;
        assert!(matches!(
            context.validate(),
            Err(RuntimeOwnershipContractError::InvalidOwnerModeCombination)
        ));
    }

    #[test]
    fn runtime_ownership_contract_rejects_unknown_fields_and_forbidden_values() {
        let unknown = serde_json::json!({
            "owner_category": "service_host",
            "runtime_mode": "service_owned",
            "ownership_ref": "runtime-owner-a",
            "ownership_epoch": 1,
            "service_instance_ref": "service-a",
            "policy_profile_ref": "service_host_runtime_profile",
            "protocol_version": {"major": 1, "minor": 0, "patch": 0},
            "schema_version": {"major": 1, "minor": 0, "patch": 0},
            "authorization_category": "service_host_local",
            "provenance_id": "service_host_runtime_ownership",
            "redaction_status": "redacted",
            "pid": 1234
        });
        assert!(serde_json::from_value::<RuntimeOwnerContext>(unknown).is_err());

        let mut unsafe_context =
            RuntimeOwnerContext::service_host("runtime-owner-a", 1, "service-instance-a");
        unsafe_context.provenance_id = "service_host_ipc_nonce".to_string();
        assert!(matches!(
            unsafe_context.validate(),
            Err(RuntimeOwnershipContractError::UnsafeField("provenance_id"))
        ));
    }

    #[test]
    fn runtime_ownership_summary_requires_redacted_side_effect_free_status() {
        let component = RuntimeComponentOwnershipSummary {
            ownership_ref: "runtime-owner-a".to_string(),
            ownership_epoch: 1,
            runtime_mode: RuntimeMode::ServiceOwned,
            owner_category: RuntimeOwnerCategory::ServiceHost,
            component_category: RuntimeComponentCategory::ProviderController,
            component_lifecycle: RuntimeComponentLifecycle::Inactive,
            runtime_health: RuntimeHealthState::Inactive,
            degraded_reason: Some("provider_execution_deferred".to_string()),
            audit_refs: Vec::new(),
            provenance_id: "runtime_container".to_string(),
            time_bucket: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        };
        let summary = RuntimeOwnershipSummary {
            ownership_ref: "runtime-owner-a".to_string(),
            ownership_epoch: 1,
            runtime_mode: RuntimeMode::ServiceOwned,
            owner_category: RuntimeOwnerCategory::ServiceHost,
            runtime_health: RuntimeHealthState::Ready,
            transition_state: RuntimeTransitionState::Ready,
            protocol_version: RUNTIME_OWNERSHIP_PROTOCOL_VERSION,
            schema_version: RUNTIME_OWNERSHIP_SCHEMA_VERSION,
            degraded_reason: None,
            mutation_trust_state: RuntimeMutationTrustState::ImpersonationNotImplemented,
            mutation_commands_enabled: false,
            provider_controller_state: "inactive".to_string(),
            provider_call_count: 0,
            provider_zero: RuntimeProviderZeroSummary::default(),
            scheduler_state: "disabled".to_string(),
            scheduler_host_state: "stopped".to_string(),
            sampler_state: "inactive".to_string(),
            storage_owner_state: "owned".to_string(),
            canonical_read_model_owner: "service_host".to_string(),
            snapshot_freshness: "fresh".to_string(),
            shutdown: RuntimeShutdownSummary {
                state: RuntimeShutdownState::NotStarted,
                total_timeout_bucket: "bounded_total".to_string(),
                mutation_leases_invalidated: false,
                scheduler_host_cancellation_signalled: false,
                scheduler_host_joined: false,
                provider_stop_called: false,
                stages: Vec::new(),
                audit_refs: Vec::new(),
                redaction_status: RedactionStatus::Redacted,
            },
            component_summaries: vec![component],
            audit_refs: Vec::new(),
            provenance_id: "runtime_container".to_string(),
            time_bucket: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        };
        summary.validate().expect("valid summary");

        let mut unsafe_summary = summary;
        unsafe_summary.mutation_commands_enabled = true;
        assert!(unsafe_summary.validate().is_err());
    }
}
