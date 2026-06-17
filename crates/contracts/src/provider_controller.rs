use crate::{
    ip_helper_schedule::IpHelperScheduleStatus, runtime_ownership::RuntimeOwnerCategory,
    EtwFallbackState, EtwLifecycleStatus, RedactionStatus, SchemaVersion, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const NETWORK_PROVIDER_CONTROLLER_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_NETWORK_PROVIDER_RECORDS: usize = 11;
pub const MAX_NETWORK_PROVIDER_REFS: usize = 12;
pub const MAX_NETWORK_PROVIDER_TEXT_LEN: usize = 128;

pub const NETWORK_PROVIDER_CONTROLLER_STATUS_TOPIC: &str = "network.provider_controller.status";
pub const NETWORK_PROVIDER_STATUS_TOPIC: &str = "network.provider.status";
pub const NETWORK_VISIBILITY_STATUS_TOPIC: &str = "network.visibility.status";
pub const AUDIT_NETWORK_PROVIDER_CONTROLLER_TOPIC: &str = "audit.network_provider_controller";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProviderKind {
    PortableMetadata,
    IpHelper,
    EtwNetwork,
    WindowsDns,
    WindowsAuthRemote,
    WindowsRdpOperational,
    WindowsSmbOperational,
    WindowsSshOperational,
    NpcapPacket,
    CaptureBroker,
    None,
}

impl NetworkProviderKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PortableMetadata => "portable_metadata",
            Self::IpHelper => "ip_helper",
            Self::EtwNetwork => "etw_network",
            Self::WindowsDns => "windows_dns",
            Self::WindowsAuthRemote => "windows_auth_remote",
            Self::WindowsRdpOperational => "windows_rdp_operational",
            Self::WindowsSmbOperational => "windows_smb_operational",
            Self::WindowsSshOperational => "windows_ssh_operational",
            Self::NpcapPacket => "npcap_packet",
            Self::CaptureBroker => "capture_broker",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProviderControllerMode {
    PortableOnly,
    IpHelperOnly,
    EtwPlusIpHelper,
    PacketEnhanced,
    Degraded,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProviderControllerState {
    Inactive,
    Probing,
    Ready,
    Activating,
    Active,
    Paused,
    Degraded,
    Stopping,
    Stopped,
    Revoked,
    Failed,
}

impl NetworkProviderControllerState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::Probing => "probing",
            Self::Ready => "ready",
            Self::Activating => "activating",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Degraded => "degraded",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Revoked => "revoked",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProviderImplementationState {
    NotImplemented,
    ImplementedInactive,
    Available,
    Unavailable,
    UnsupportedPlatform,
    PermissionRequired,
    AuthorizationRequired,
    Degraded,
    Revoked,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProviderLifecycleState {
    Inactive,
    Probing,
    Ready,
    Activating,
    Active,
    Paused,
    Degraded,
    Stopping,
    Stopped,
    Revoked,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkVisibilityDimension {
    PortableMetadataVisibility,
    ConnectionTableVisibility,
    ShortLivedNetworkEventVisibility,
    ProcessCategoryVisibility,
    ProcessNetworkCategoryVisibility,
    PacketHeaderVisibility,
    PacketPayloadVisibility,
    SpecificProcessIdentityVisibility,
    SpecificDestinationIdentityVisibility,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkVisibilityState {
    Available,
    Unavailable,
    Degraded,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProviderZeroCounters {
    pub ip_helper_calls: u32,
    pub etw_calls: u32,
    pub dns_sensing_calls: u32,
    pub dns_observation_publications: u32,
    pub dns_detector_invocations: u32,
    pub dns_detector_consumed: u32,
    pub auth_remote_sensing_calls: u32,
    pub auth_remote_publications: u32,
    pub auth_remote_auth_detector_invocations: u32,
    pub auth_remote_auth_consumed: u32,
    pub auth_remote_remote_admin_invocations: u32,
    pub auth_remote_remote_admin_consumed: u32,
    pub auth_remote_lateral_invocations: u32,
    pub auth_remote_lateral_consumed: u32,
    pub auth_remote_downstream_facts: u32,
    pub rdp_operational_sensing_calls: u32,
    pub rdp_operational_publications: u32,
    pub rdp_operational_auth_detector_invocations: u32,
    pub rdp_operational_auth_consumed: u32,
    pub rdp_operational_remote_admin_invocations: u32,
    pub rdp_operational_remote_admin_consumed: u32,
    pub rdp_operational_lateral_invocations: u32,
    pub rdp_operational_lateral_consumed: u32,
    pub rdp_operational_downstream_facts: u32,
    pub smb_operational_sensing_calls: u32,
    pub smb_operational_publications: u32,
    pub smb_operational_auth_detector_invocations: u32,
    pub smb_operational_auth_consumed: u32,
    pub smb_operational_remote_admin_invocations: u32,
    pub smb_operational_remote_admin_consumed: u32,
    pub smb_operational_lateral_invocations: u32,
    pub smb_operational_lateral_consumed: u32,
    pub smb_operational_downstream_facts: u32,
    pub ssh_operational_sensing_calls: u32,
    pub ssh_operational_publications: u32,
    pub ssh_operational_auth_detector_invocations: u32,
    pub ssh_operational_auth_consumed: u32,
    pub ssh_operational_remote_admin_invocations: u32,
    pub ssh_operational_remote_admin_consumed: u32,
    pub ssh_operational_lateral_invocations: u32,
    pub ssh_operational_lateral_consumed: u32,
    pub ssh_operational_downstream_facts: u32,
    pub npcap_probes: u32,
    pub capture_broker_launches: u32,
    pub native_network_topic_publications: u32,
    pub process_network_facts: u32,
    pub packet_facts: u32,
}

impl NetworkProviderZeroCounters {
    pub fn all_zero(&self) -> bool {
        self.ip_helper_calls == 0
            && self.etw_calls == 0
            && self.dns_sensing_calls == 0
            && self.dns_observation_publications == 0
            && self.dns_detector_invocations == 0
            && self.dns_detector_consumed == 0
            && self.auth_remote_sensing_calls == 0
            && self.auth_remote_publications == 0
            && self.auth_remote_auth_detector_invocations == 0
            && self.auth_remote_auth_consumed == 0
            && self.auth_remote_remote_admin_invocations == 0
            && self.auth_remote_remote_admin_consumed == 0
            && self.auth_remote_lateral_invocations == 0
            && self.auth_remote_lateral_consumed == 0
            && self.auth_remote_downstream_facts == 0
            && self.rdp_operational_sensing_calls == 0
            && self.rdp_operational_publications == 0
            && self.rdp_operational_auth_detector_invocations == 0
            && self.rdp_operational_auth_consumed == 0
            && self.rdp_operational_remote_admin_invocations == 0
            && self.rdp_operational_remote_admin_consumed == 0
            && self.rdp_operational_lateral_invocations == 0
            && self.rdp_operational_lateral_consumed == 0
            && self.rdp_operational_downstream_facts == 0
            && self.smb_operational_sensing_calls == 0
            && self.smb_operational_publications == 0
            && self.smb_operational_auth_detector_invocations == 0
            && self.smb_operational_auth_consumed == 0
            && self.smb_operational_remote_admin_invocations == 0
            && self.smb_operational_remote_admin_consumed == 0
            && self.smb_operational_lateral_invocations == 0
            && self.smb_operational_lateral_consumed == 0
            && self.smb_operational_downstream_facts == 0
            && self.ssh_operational_sensing_calls == 0
            && self.ssh_operational_publications == 0
            && self.ssh_operational_auth_detector_invocations == 0
            && self.ssh_operational_auth_consumed == 0
            && self.ssh_operational_remote_admin_invocations == 0
            && self.ssh_operational_remote_admin_consumed == 0
            && self.ssh_operational_lateral_invocations == 0
            && self.ssh_operational_lateral_consumed == 0
            && self.ssh_operational_downstream_facts == 0
            && self.npcap_probes == 0
            && self.capture_broker_launches == 0
            && self.native_network_topic_publications == 0
            && self.process_network_facts == 0
            && self.packet_facts == 0
    }

    pub fn ip_helper_handoff_only(&self) -> bool {
        self.ip_helper_calls > 0
            && self.etw_calls == 0
            && self.npcap_probes == 0
            && self.capture_broker_launches == 0
            && self.native_network_topic_publications > 0
            && self.process_network_facts == 0
            && self.packet_facts == 0
    }

    pub fn etw_lifecycle_only(&self) -> bool {
        self.etw_calls > 0
            && self.npcap_probes == 0
            && self.capture_broker_launches == 0
            && self.process_network_facts == 0
            && self.packet_facts == 0
            && ((self.ip_helper_calls == 0 && self.native_network_topic_publications == 0)
                || (self.ip_helper_calls > 0 && self.native_network_topic_publications > 0))
    }

    pub fn etw_handoff_only(&self) -> bool {
        self.etw_calls > 0
            && self.npcap_probes == 0
            && self.capture_broker_launches == 0
            && self.native_network_topic_publications > 0
            && self.process_network_facts == 0
            && self.packet_facts == 0
    }

    pub fn dns_sensing_only(&self) -> bool {
        self.dns_sensing_calls > 0
            && self.npcap_probes == 0
            && self.capture_broker_launches == 0
            && self.native_network_topic_publications == 0
            && self.process_network_facts == 0
            && self.packet_facts == 0
    }

    pub fn auth_remote_sensing_only(&self) -> bool {
        self.auth_remote_sensing_calls > 0
            && self.npcap_probes == 0
            && self.capture_broker_launches == 0
            && self.native_network_topic_publications == 0
            && self.process_network_facts == 0
            && self.packet_facts == 0
    }

    pub fn rdp_operational_sensing_only(&self) -> bool {
        self.rdp_operational_sensing_calls > 0
            && self.npcap_probes == 0
            && self.capture_broker_launches == 0
            && self.native_network_topic_publications == 0
            && self.process_network_facts == 0
            && self.packet_facts == 0
    }

    pub fn smb_operational_sensing_only(&self) -> bool {
        self.smb_operational_sensing_calls > 0
            && self.npcap_probes == 0
            && self.capture_broker_launches == 0
            && self.native_network_topic_publications == 0
            && self.process_network_facts == 0
            && self.packet_facts == 0
    }

    pub fn ssh_operational_sensing_only(&self) -> bool {
        self.ssh_operational_sensing_calls > 0
            && self.npcap_probes == 0
            && self.capture_broker_launches == 0
            && self.native_network_topic_publications == 0
            && self.process_network_facts == 0
            && self.packet_facts == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProviderStatus {
    pub provider_id: String,
    pub provider_kind: NetworkProviderKind,
    pub adapter_boundary: String,
    pub implementation_state: NetworkProviderImplementationState,
    pub lifecycle_state: NetworkProviderLifecycleState,
    pub activation_allowed: bool,
    pub activation_unavailable_reason: Option<String>,
    pub degraded_reason: Option<String>,
    pub dependency_refs: Vec<String>,
    pub policy_refs: Vec<String>,
    pub provenance_refs: Vec<String>,
    pub bounded_counters: NetworkProviderZeroCounters,
    pub redaction_status: RedactionStatus,
}

impl NetworkProviderStatus {
    fn initial(
        provider_kind: NetworkProviderKind,
        implementation_state: NetworkProviderImplementationState,
    ) -> Self {
        let activation_allowed = matches!(
            provider_kind,
            NetworkProviderKind::IpHelper
                | NetworkProviderKind::EtwNetwork
                | NetworkProviderKind::WindowsDns
                | NetworkProviderKind::WindowsAuthRemote
                | NetworkProviderKind::WindowsRdpOperational
                | NetworkProviderKind::WindowsSmbOperational
                | NetworkProviderKind::WindowsSshOperational
        );
        Self {
            provider_id: format!("network_provider_{}", provider_kind.as_str()),
            provider_kind,
            adapter_boundary: adapter_boundary_for(provider_kind).to_string(),
            implementation_state,
            lifecycle_state: NetworkProviderLifecycleState::Inactive,
            activation_allowed,
            activation_unavailable_reason: if activation_allowed {
                None
            } else {
                Some("provider_execution_deferred".to_string())
            },
            degraded_reason: None,
            dependency_refs: vec![format!("dependency_ref_{}", provider_kind.as_str())],
            policy_refs: vec![format!("policy_ref_{}", provider_kind.as_str())],
            provenance_refs: vec!["provider_controller_foundation".to_string()],
            bounded_counters: NetworkProviderZeroCounters::default(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderControllerContractError> {
        validate_safe_text("provider_id", &self.provider_id)?;
        validate_safe_text("adapter_boundary", &self.adapter_boundary)?;
        validate_optional_safe_text(
            "activation_unavailable_reason",
            self.activation_unavailable_reason.as_deref(),
        )?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        validate_string_list("dependency_refs", &self.dependency_refs)?;
        validate_string_list("policy_refs", &self.policy_refs)?;
        validate_string_list("provenance_refs", &self.provenance_refs)?;
        if self.activation_allowed
            && !matches!(
                self.provider_kind,
                NetworkProviderKind::IpHelper
                    | NetworkProviderKind::EtwNetwork
                    | NetworkProviderKind::WindowsDns
                    | NetworkProviderKind::WindowsAuthRemote
                    | NetworkProviderKind::WindowsRdpOperational
                    | NetworkProviderKind::WindowsSmbOperational
                    | NetworkProviderKind::WindowsSshOperational
            )
        {
            return Err(ProviderControllerContractError::ActivationMustRemainBlocked);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ProviderControllerContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkVisibilityDimensionStatus {
    pub dimension: NetworkVisibilityDimension,
    pub visibility_state: NetworkVisibilityState,
    pub degraded_reason: Option<String>,
}

impl NetworkVisibilityDimensionStatus {
    fn validate(&self) -> Result<(), ProviderControllerContractError> {
        validate_optional_safe_text(
            "visibility degraded_reason",
            self.degraded_reason.as_deref(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkVisibilitySummary {
    pub visibility_ref: String,
    pub dimensions: Vec<NetworkVisibilityDimensionStatus>,
    pub provenance_refs: Vec<String>,
    pub generated_at: Timestamp,
    pub redaction_status: RedactionStatus,
}

impl NetworkVisibilitySummary {
    pub fn validate(&self) -> Result<(), ProviderControllerContractError> {
        validate_safe_text("visibility_ref", &self.visibility_ref)?;
        validate_string_list("visibility provenance_refs", &self.provenance_refs)?;
        if self.dimensions.len() > MAX_NETWORK_PROVIDER_RECORDS + 1 {
            return Err(ProviderControllerContractError::TooManyItems("dimensions"));
        }
        let mut seen = BTreeSet::new();
        for dimension in &self.dimensions {
            if !seen.insert(dimension.dimension) {
                return Err(ProviderControllerContractError::DuplicateProvider);
            }
            dimension.validate()?;
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ProviderControllerContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkFallbackPlan {
    pub fallback_plan_ref: String,
    pub selected_mode: NetworkProviderControllerMode,
    pub selection_order: Vec<NetworkProviderKind>,
    pub fallback_rules: Vec<String>,
    pub degraded_reason: Option<String>,
    pub policy_refs: Vec<String>,
    pub redaction_status: RedactionStatus,
}

impl NetworkFallbackPlan {
    pub fn validate(&self) -> Result<(), ProviderControllerContractError> {
        validate_safe_text("fallback_plan_ref", &self.fallback_plan_ref)?;
        validate_string_list("fallback_rules", &self.fallback_rules)?;
        validate_optional_safe_text("fallback degraded_reason", self.degraded_reason.as_deref())?;
        validate_string_list("fallback policy_refs", &self.policy_refs)?;
        if self.selection_order.is_empty()
            || self.selection_order.len() > MAX_NETWORK_PROVIDER_RECORDS
            || !self
                .selection_order
                .contains(&NetworkProviderKind::PortableMetadata)
        {
            return Err(ProviderControllerContractError::InvalidSelectionPolicy);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ProviderControllerContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProviderPolicySummary {
    pub policy_ref: String,
    pub provider_activation_allowed: bool,
    pub activation_unavailable_reason: String,
    pub ip_helper_execution_available_over_production_ipc: bool,
    pub production_ipc_execution_unavailable_reason: String,
    pub required_gates: Vec<String>,
    pub provider_readiness_creates_evidence: bool,
    pub provider_availability_creates_findings: bool,
    pub production_provider_mutations_enabled: bool,
    pub redaction_status: RedactionStatus,
}

impl NetworkProviderPolicySummary {
    pub fn validate(&self) -> Result<(), ProviderControllerContractError> {
        validate_safe_text("policy_ref", &self.policy_ref)?;
        validate_safe_text(
            "activation_unavailable_reason",
            &self.activation_unavailable_reason,
        )?;
        validate_safe_text(
            "production_ipc_execution_unavailable_reason",
            &self.production_ipc_execution_unavailable_reason,
        )?;
        validate_string_list("required_gates", &self.required_gates)?;
        if self.provider_readiness_creates_evidence || self.provider_availability_creates_findings {
            return Err(ProviderControllerContractError::ActivationMustRemainBlocked);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ProviderControllerContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProviderDependencySummary {
    pub dependency_ref: String,
    pub dependency_refs: Vec<String>,
    pub degraded_reason: Option<String>,
    pub redaction_status: RedactionStatus,
}

impl NetworkProviderDependencySummary {
    pub fn validate(&self) -> Result<(), ProviderControllerContractError> {
        validate_safe_text("dependency_ref", &self.dependency_ref)?;
        validate_string_list("dependency_refs", &self.dependency_refs)?;
        validate_optional_safe_text(
            "dependency degraded_reason",
            self.degraded_reason.as_deref(),
        )?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ProviderControllerContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProviderLifecycleSummary {
    pub lifecycle_ref: String,
    pub controller_state: NetworkProviderControllerState,
    pub selected_mode: NetworkProviderControllerMode,
    pub active_provider_count: u8,
    pub inactive_provider_count: u8,
    pub degraded_provider_count: u8,
    pub redaction_status: RedactionStatus,
}

impl NetworkProviderLifecycleSummary {
    pub fn validate(&self) -> Result<(), ProviderControllerContractError> {
        validate_safe_text("lifecycle_ref", &self.lifecycle_ref)?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ProviderControllerContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProviderAuditSummary {
    pub audit_ref: String,
    pub declared_status_topics: Vec<String>,
    pub audit_refs: Vec<String>,
    pub status_publication_count: u32,
    pub provider_execution_event_count: u32,
    pub redaction_status: RedactionStatus,
}

impl NetworkProviderAuditSummary {
    pub fn validate(&self) -> Result<(), ProviderControllerContractError> {
        validate_safe_text("audit_ref", &self.audit_ref)?;
        validate_string_list("declared_status_topics", &self.declared_status_topics)?;
        validate_string_list("audit_refs", &self.audit_refs)?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ProviderControllerContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProviderControllerStatus {
    pub controller_ref: String,
    pub ownership_ref: String,
    pub ownership_epoch: u64,
    pub runtime_owner: RuntimeOwnerCategory,
    pub schema_version: SchemaVersion,
    pub controller_state: NetworkProviderControllerState,
    pub selected_mode: NetworkProviderControllerMode,
    pub providers: Vec<NetworkProviderStatus>,
    pub visibility_summary: NetworkVisibilitySummary,
    pub fallback_plan: NetworkFallbackPlan,
    pub dependency_summary: NetworkProviderDependencySummary,
    pub policy_summary: NetworkProviderPolicySummary,
    pub lifecycle_summary: NetworkProviderLifecycleSummary,
    pub audit_summary: NetworkProviderAuditSummary,
    pub ip_helper_schedule: IpHelperScheduleStatus,
    pub etw_lifecycle: EtwLifecycleStatus,
    pub provider_zero: NetworkProviderZeroCounters,
    pub generated_at: Timestamp,
    pub redaction_status: RedactionStatus,
}

impl NetworkProviderControllerStatus {
    pub fn inactive_servicehost(
        ownership_ref: impl Into<String>,
        ownership_epoch: u64,
    ) -> Result<Self, ProviderControllerContractError> {
        let ownership_ref = ownership_ref.into();
        let providers = vec![
            NetworkProviderStatus::initial(
                NetworkProviderKind::PortableMetadata,
                NetworkProviderImplementationState::Available,
            ),
            NetworkProviderStatus::initial(
                NetworkProviderKind::IpHelper,
                NetworkProviderImplementationState::ImplementedInactive,
            ),
            NetworkProviderStatus::initial(
                NetworkProviderKind::EtwNetwork,
                NetworkProviderImplementationState::ImplementedInactive,
            ),
            NetworkProviderStatus::initial(
                NetworkProviderKind::WindowsDns,
                NetworkProviderImplementationState::ImplementedInactive,
            ),
            NetworkProviderStatus::initial(
                NetworkProviderKind::WindowsAuthRemote,
                NetworkProviderImplementationState::ImplementedInactive,
            ),
            NetworkProviderStatus::initial(
                NetworkProviderKind::WindowsRdpOperational,
                NetworkProviderImplementationState::ImplementedInactive,
            ),
            NetworkProviderStatus::initial(
                NetworkProviderKind::WindowsSmbOperational,
                NetworkProviderImplementationState::ImplementedInactive,
            ),
            NetworkProviderStatus::initial(
                NetworkProviderKind::WindowsSshOperational,
                NetworkProviderImplementationState::ImplementedInactive,
            ),
            NetworkProviderStatus::initial(
                NetworkProviderKind::NpcapPacket,
                NetworkProviderImplementationState::NotImplemented,
            ),
            NetworkProviderStatus::initial(
                NetworkProviderKind::CaptureBroker,
                NetworkProviderImplementationState::NotImplemented,
            ),
            NetworkProviderStatus::initial(
                NetworkProviderKind::None,
                NetworkProviderImplementationState::Unavailable,
            ),
        ];
        let dimensions = vec![
            NetworkVisibilityDimensionStatus {
                dimension: NetworkVisibilityDimension::PortableMetadataVisibility,
                visibility_state: NetworkVisibilityState::Available,
                degraded_reason: None,
            },
            unavailable_dimension(NetworkVisibilityDimension::ConnectionTableVisibility),
            unavailable_dimension(NetworkVisibilityDimension::ShortLivedNetworkEventVisibility),
            unavailable_dimension(NetworkVisibilityDimension::ProcessCategoryVisibility),
            unavailable_dimension(NetworkVisibilityDimension::ProcessNetworkCategoryVisibility),
            unavailable_dimension(NetworkVisibilityDimension::PacketHeaderVisibility),
            unavailable_dimension(NetworkVisibilityDimension::PacketPayloadVisibility),
            unavailable_dimension(NetworkVisibilityDimension::SpecificProcessIdentityVisibility),
            unavailable_dimension(
                NetworkVisibilityDimension::SpecificDestinationIdentityVisibility,
            ),
        ];
        let status = Self {
            controller_ref: "provider_controller_ref".to_string(),
            ownership_ref: ownership_ref.clone(),
            ownership_epoch,
            runtime_owner: RuntimeOwnerCategory::ServiceHost,
            schema_version: NETWORK_PROVIDER_CONTROLLER_SCHEMA_VERSION,
            controller_state: NetworkProviderControllerState::Inactive,
            selected_mode: NetworkProviderControllerMode::PortableOnly,
            providers,
            visibility_summary: NetworkVisibilitySummary {
                visibility_ref: "network_visibility_ref".to_string(),
                dimensions,
                provenance_refs: vec!["provider_controller_foundation".to_string()],
                generated_at: Timestamp::now(),
                redaction_status: RedactionStatus::Redacted,
            },
            fallback_plan: NetworkFallbackPlan {
                fallback_plan_ref: "network_fallback_plan_ref".to_string(),
                selected_mode: NetworkProviderControllerMode::PortableOnly,
                selection_order: vec![
                    NetworkProviderKind::PortableMetadata,
                    NetworkProviderKind::IpHelper,
                    NetworkProviderKind::EtwNetwork,
                    NetworkProviderKind::WindowsDns,
                    NetworkProviderKind::WindowsAuthRemote,
                    NetworkProviderKind::WindowsRdpOperational,
                    NetworkProviderKind::WindowsSmbOperational,
                    NetworkProviderKind::WindowsSshOperational,
                    NetworkProviderKind::NpcapPacket,
                    NetworkProviderKind::CaptureBroker,
                ],
                fallback_rules: vec![
                    "portable_paths_always_available".to_string(),
                    "ip_helper_requires_explicit_activation".to_string(),
                    "etw_failure_falls_back_to_ip_helper".to_string(),
                    "npcap_failure_falls_back_to_etw_or_ip_helper".to_string(),
                    "packet_enhancement_never_replaces_metadata_fallback".to_string(),
                ],
                degraded_reason: Some("native_network_providers_inactive".to_string()),
                policy_refs: vec!["network_provider_selection_policy_ref".to_string()],
                redaction_status: RedactionStatus::Redacted,
            },
            dependency_summary: NetworkProviderDependencySummary {
                dependency_ref: "network_provider_dependency_ref".to_string(),
                dependency_refs: vec![
                    "servicehost_runtime_ownership_gate".to_string(),
                    "owner_epoch_gate".to_string(),
                    "declared_topic_gate".to_string(),
                    "no_raw_retention_gate".to_string(),
                ],
                degraded_reason: Some("provider_execution_deferred".to_string()),
                redaction_status: RedactionStatus::Redacted,
            },
            policy_summary: NetworkProviderPolicySummary {
                policy_ref: "network_provider_policy_ref".to_string(),
                provider_activation_allowed: true,
                activation_unavailable_reason: "not_applicable".to_string(),
                ip_helper_execution_available_over_production_ipc: true,
                production_ipc_execution_unavailable_reason: "not_applicable".to_string(),
                required_gates: vec![
                    "servicehost_runtime_ownership".to_string(),
                    "current_ownership_epoch".to_string(),
                    "provider_implemented_state".to_string(),
                    "provider_permission_or_authorization".to_string(),
                    "accepted_schema".to_string(),
                    "declared_eventbus_topics".to_string(),
                    "redaction_policy".to_string(),
                    "no_raw_retention_policy".to_string(),
                    "not_shutting_down".to_string(),
                    "bounded_limits".to_string(),
                    "production_caller_trust".to_string(),
                ],
                provider_readiness_creates_evidence: false,
                provider_availability_creates_findings: false,
                production_provider_mutations_enabled: true,
                redaction_status: RedactionStatus::Redacted,
            },
            lifecycle_summary: NetworkProviderLifecycleSummary {
                lifecycle_ref: "network_provider_lifecycle_ref".to_string(),
                controller_state: NetworkProviderControllerState::Inactive,
                selected_mode: NetworkProviderControllerMode::PortableOnly,
                active_provider_count: 0,
                inactive_provider_count: 10,
                degraded_provider_count: 0,
                redaction_status: RedactionStatus::Redacted,
            },
            audit_summary: NetworkProviderAuditSummary {
                audit_ref: "network_provider_audit_ref".to_string(),
                declared_status_topics: vec![
                    NETWORK_PROVIDER_CONTROLLER_STATUS_TOPIC.to_string(),
                    NETWORK_PROVIDER_STATUS_TOPIC.to_string(),
                    NETWORK_VISIBILITY_STATUS_TOPIC.to_string(),
                    AUDIT_NETWORK_PROVIDER_CONTROLLER_TOPIC.to_string(),
                    crate::native_network::AUDIT_NETWORK_PROVIDER_EXECUTION_TOPIC.to_string(),
                ],
                audit_refs: vec!["audit_network_provider_controller_ref".to_string()],
                status_publication_count: 0,
                provider_execution_event_count: 0,
                redaction_status: RedactionStatus::Redacted,
            },
            ip_helper_schedule: IpHelperScheduleStatus::not_configured(ownership_epoch),
            etw_lifecycle: EtwLifecycleStatus::inactive(
                ownership_ref.clone(),
                ownership_epoch,
                EtwFallbackState::IpHelperAvailable,
            ),
            provider_zero: NetworkProviderZeroCounters::default(),
            generated_at: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        };
        status.validate()?;
        Ok(status)
    }

    pub fn validate(&self) -> Result<(), ProviderControllerContractError> {
        validate_safe_text("controller_ref", &self.controller_ref)?;
        validate_safe_text("ownership_ref", &self.ownership_ref)?;
        if self.ownership_epoch == 0 {
            return Err(ProviderControllerContractError::OwnershipEpochRequired);
        }
        if self.runtime_owner != RuntimeOwnerCategory::ServiceHost {
            return Err(ProviderControllerContractError::UnsupportedRuntimeOwner);
        }
        if self.schema_version != NETWORK_PROVIDER_CONTROLLER_SCHEMA_VERSION {
            return Err(ProviderControllerContractError::UnsupportedSchemaVersion);
        }
        if self.providers.len() > MAX_NETWORK_PROVIDER_RECORDS {
            return Err(ProviderControllerContractError::TooManyItems("providers"));
        }
        let mut seen = BTreeSet::new();
        for provider in &self.providers {
            if !seen.insert(provider.provider_kind) {
                return Err(ProviderControllerContractError::DuplicateProvider);
            }
            provider.validate()?;
        }
        validate_network_provider_selection(self.selected_mode, &self.providers)?;
        self.visibility_summary.validate()?;
        self.fallback_plan.validate()?;
        self.dependency_summary.validate()?;
        self.policy_summary.validate()?;
        self.lifecycle_summary.validate()?;
        self.audit_summary.validate()?;
        self.ip_helper_schedule
            .validate()
            .map_err(|_| ProviderControllerContractError::InvalidScheduleState)?;
        if self.ip_helper_schedule.ownership_epoch != self.ownership_epoch {
            return Err(ProviderControllerContractError::InvalidScheduleState);
        }
        self.etw_lifecycle
            .validate()
            .map_err(|_| ProviderControllerContractError::InvalidEtwLifecycleState)?;
        if self.etw_lifecycle.ownership_ref != self.ownership_ref
            || self.etw_lifecycle.ownership_epoch != self.ownership_epoch
        {
            return Err(ProviderControllerContractError::InvalidEtwLifecycleState);
        }
        let inactive_zero = self.controller_state == NetworkProviderControllerState::Inactive
            && self.selected_mode == NetworkProviderControllerMode::PortableOnly
            && self.provider_zero.all_zero();
        let lifecycle_control_zero = matches!(
            self.controller_state,
            NetworkProviderControllerState::Ready
                | NetworkProviderControllerState::Active
                | NetworkProviderControllerState::Stopped
        ) && self.selected_mode
            == NetworkProviderControllerMode::PortableOnly
            && self.provider_zero.all_zero();
        let explicit_ip_helper_handoff = matches!(
            self.controller_state,
            NetworkProviderControllerState::Ready
                | NetworkProviderControllerState::Active
                | NetworkProviderControllerState::Degraded
                | NetworkProviderControllerState::Stopped
        ) && matches!(
            self.selected_mode,
            NetworkProviderControllerMode::IpHelperOnly
                | NetworkProviderControllerMode::Degraded
                | NetworkProviderControllerMode::PortableOnly
        ) && self.provider_zero.ip_helper_handoff_only()
            && self.provider_zero.etw_calls == 0
            && self.provider_zero.npcap_probes == 0
            && self.provider_zero.capture_broker_launches == 0
            && self.provider_zero.process_network_facts == 0
            && self.provider_zero.packet_facts == 0;
        let explicit_etw_lifecycle = matches!(
            self.controller_state,
            NetworkProviderControllerState::Active
                | NetworkProviderControllerState::Paused
                | NetworkProviderControllerState::Degraded
                | NetworkProviderControllerState::Stopped
        ) && matches!(
            self.selected_mode,
            NetworkProviderControllerMode::EtwPlusIpHelper
                | NetworkProviderControllerMode::IpHelperOnly
                | NetworkProviderControllerMode::Degraded
                | NetworkProviderControllerMode::PortableOnly
        ) && self.provider_zero.etw_lifecycle_only();
        let explicit_etw_handoff = matches!(
            self.controller_state,
            NetworkProviderControllerState::Active
                | NetworkProviderControllerState::Degraded
                | NetworkProviderControllerState::Stopped
        ) && matches!(
            self.selected_mode,
            NetworkProviderControllerMode::EtwPlusIpHelper
                | NetworkProviderControllerMode::IpHelperOnly
                | NetworkProviderControllerMode::Degraded
                | NetworkProviderControllerMode::PortableOnly
        ) && self.provider_zero.etw_handoff_only();
        let explicit_dns_sensing = matches!(
            self.controller_state,
            NetworkProviderControllerState::Active
                | NetworkProviderControllerState::Paused
                | NetworkProviderControllerState::Degraded
                | NetworkProviderControllerState::Stopped
        ) && matches!(
            self.selected_mode,
            NetworkProviderControllerMode::PortableOnly
                | NetworkProviderControllerMode::IpHelperOnly
                | NetworkProviderControllerMode::EtwPlusIpHelper
                | NetworkProviderControllerMode::Degraded
        ) && self.provider_zero.dns_sensing_only();
        let explicit_auth_remote_sensing = matches!(
            self.controller_state,
            NetworkProviderControllerState::Active
                | NetworkProviderControllerState::Paused
                | NetworkProviderControllerState::Degraded
                | NetworkProviderControllerState::Stopped
        ) && matches!(
            self.selected_mode,
            NetworkProviderControllerMode::PortableOnly
                | NetworkProviderControllerMode::IpHelperOnly
                | NetworkProviderControllerMode::EtwPlusIpHelper
                | NetworkProviderControllerMode::Degraded
        ) && self.provider_zero.auth_remote_sensing_only();
        let explicit_rdp_operational_sensing =
            matches!(
                self.controller_state,
                NetworkProviderControllerState::Active
                    | NetworkProviderControllerState::Paused
                    | NetworkProviderControllerState::Degraded
                    | NetworkProviderControllerState::Stopped
            ) && matches!(
                self.selected_mode,
                NetworkProviderControllerMode::PortableOnly
                    | NetworkProviderControllerMode::IpHelperOnly
                    | NetworkProviderControllerMode::EtwPlusIpHelper
                    | NetworkProviderControllerMode::Degraded
            ) && self.provider_zero.rdp_operational_sensing_only();
        let explicit_smb_operational_sensing =
            matches!(
                self.controller_state,
                NetworkProviderControllerState::Active
                    | NetworkProviderControllerState::Paused
                    | NetworkProviderControllerState::Degraded
                    | NetworkProviderControllerState::Stopped
            ) && matches!(
                self.selected_mode,
                NetworkProviderControllerMode::PortableOnly
                    | NetworkProviderControllerMode::IpHelperOnly
                    | NetworkProviderControllerMode::EtwPlusIpHelper
                    | NetworkProviderControllerMode::Degraded
            ) && self.provider_zero.smb_operational_sensing_only();
        let explicit_ssh_operational_sensing =
            matches!(
                self.controller_state,
                NetworkProviderControllerState::Active
                    | NetworkProviderControllerState::Paused
                    | NetworkProviderControllerState::Degraded
                    | NetworkProviderControllerState::Stopped
            ) && matches!(
                self.selected_mode,
                NetworkProviderControllerMode::PortableOnly
                    | NetworkProviderControllerMode::IpHelperOnly
                    | NetworkProviderControllerMode::EtwPlusIpHelper
                    | NetworkProviderControllerMode::Degraded
            ) && self.provider_zero.ssh_operational_sensing_only();
        if !(inactive_zero
            || lifecycle_control_zero
            || explicit_ip_helper_handoff
            || explicit_etw_lifecycle
            || explicit_etw_handoff
            || explicit_dns_sensing
            || explicit_auth_remote_sensing
            || explicit_rdp_operational_sensing
            || explicit_smb_operational_sensing
            || explicit_ssh_operational_sensing)
        {
            return Err(ProviderControllerContractError::ProviderExecutionNotAllowed);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ProviderControllerContractError::RedactionRequired);
        }
        Ok(())
    }

    pub fn provider(&self, kind: NetworkProviderKind) -> Option<&NetworkProviderStatus> {
        self.providers
            .iter()
            .find(|provider| provider.provider_kind == kind)
    }
}

pub fn validate_network_provider_selection(
    selected_mode: NetworkProviderControllerMode,
    providers: &[NetworkProviderStatus],
) -> Result<(), ProviderControllerContractError> {
    let state_for = |kind| {
        providers
            .iter()
            .find(|provider| provider.provider_kind == kind)
            .map(|provider| provider.implementation_state)
    };
    if state_for(NetworkProviderKind::PortableMetadata)
        != Some(NetworkProviderImplementationState::Available)
    {
        return Err(ProviderControllerContractError::InvalidSelectionPolicy);
    }
    let native_supported = |kind| {
        matches!(
            state_for(kind),
            Some(
                NetworkProviderImplementationState::ImplementedInactive
                    | NetworkProviderImplementationState::Available
                    | NetworkProviderImplementationState::PermissionRequired
                    | NetworkProviderImplementationState::AuthorizationRequired
                    | NetworkProviderImplementationState::Degraded
            )
        )
    };
    match selected_mode {
        NetworkProviderControllerMode::PortableOnly
        | NetworkProviderControllerMode::Degraded
        | NetworkProviderControllerMode::Unavailable => Ok(()),
        NetworkProviderControllerMode::IpHelperOnly => {
            if native_supported(NetworkProviderKind::IpHelper) {
                Ok(())
            } else {
                Err(ProviderControllerContractError::InvalidSelectionPolicy)
            }
        }
        NetworkProviderControllerMode::EtwPlusIpHelper => {
            if native_supported(NetworkProviderKind::IpHelper)
                && native_supported(NetworkProviderKind::EtwNetwork)
            {
                Ok(())
            } else {
                Err(ProviderControllerContractError::InvalidSelectionPolicy)
            }
        }
        NetworkProviderControllerMode::PacketEnhanced => {
            if native_supported(NetworkProviderKind::NpcapPacket)
                && native_supported(NetworkProviderKind::CaptureBroker)
            {
                Ok(())
            } else {
                Err(ProviderControllerContractError::InvalidSelectionPolicy)
            }
        }
    }
}

fn unavailable_dimension(
    dimension: NetworkVisibilityDimension,
) -> NetworkVisibilityDimensionStatus {
    NetworkVisibilityDimensionStatus {
        dimension,
        visibility_state: NetworkVisibilityState::Unavailable,
        degraded_reason: Some("provider_execution_deferred".to_string()),
    }
}

fn adapter_boundary_for(provider_kind: NetworkProviderKind) -> &'static str {
    match provider_kind {
        NetworkProviderKind::PortableMetadata => "portable_default_metadata",
        NetworkProviderKind::IpHelper => "infrastructure",
        NetworkProviderKind::EtwNetwork => "infrastructure",
        NetworkProviderKind::WindowsDns => "infrastructure",
        NetworkProviderKind::WindowsAuthRemote => "infrastructure",
        NetworkProviderKind::WindowsRdpOperational => "infrastructure",
        NetworkProviderKind::WindowsSmbOperational => "infrastructure",
        NetworkProviderKind::WindowsSshOperational => "infrastructure",
        NetworkProviderKind::NpcapPacket | NetworkProviderKind::CaptureBroker => {
            "deferred_infrastructure"
        }
        NetworkProviderKind::None => "none",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderControllerContractError {
    EmptyField(&'static str),
    TooLong(&'static str),
    UnsafeField(&'static str),
    TooManyItems(&'static str),
    OwnershipEpochRequired,
    UnsupportedRuntimeOwner,
    UnsupportedSchemaVersion,
    DuplicateProvider,
    InvalidSelectionPolicy,
    ActivationMustRemainBlocked,
    ProviderExecutionNotAllowed,
    InvalidScheduleState,
    InvalidEtwLifecycleState,
    RedactionRequired,
}

impl fmt::Display for ProviderControllerContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::TooLong(field) => write!(f, "{field} exceeds bounded provider text length"),
            Self::UnsafeField(field) => write!(f, "{field} contains unsafe provider metadata"),
            Self::TooManyItems(field) => write!(f, "{field} contains too many provider items"),
            Self::OwnershipEpochRequired => write!(f, "provider ownership epoch is required"),
            Self::UnsupportedRuntimeOwner => {
                write!(f, "provider controller must be ServiceHost-owned")
            }
            Self::UnsupportedSchemaVersion => {
                write!(f, "provider controller schema is unsupported")
            }
            Self::DuplicateProvider => {
                write!(f, "provider controller contains duplicate providers")
            }
            Self::InvalidSelectionPolicy => write!(f, "provider selection policy is unsupported"),
            Self::ActivationMustRemainBlocked => {
                write!(f, "provider activation must remain blocked")
            }
            Self::ProviderExecutionNotAllowed => {
                write!(f, "provider execution is not allowed in this slice")
            }
            Self::InvalidScheduleState => write!(f, "IP Helper schedule state is invalid"),
            Self::InvalidEtwLifecycleState => write!(f, "ETW lifecycle state is invalid"),
            Self::RedactionRequired => write!(f, "provider controller metadata must be redacted"),
        }
    }
}

impl std::error::Error for ProviderControllerContractError {}

fn validate_string_list(
    field: &'static str,
    values: &[String],
) -> Result<(), ProviderControllerContractError> {
    if values.len() > MAX_NETWORK_PROVIDER_REFS {
        return Err(ProviderControllerContractError::TooManyItems(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ProviderControllerContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(
    field: &'static str,
    value: &str,
) -> Result<(), ProviderControllerContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ProviderControllerContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_NETWORK_PROVIDER_TEXT_LEN {
        return Err(ProviderControllerContractError::TooLong(field));
    }
    let normalized = trimmed.to_ascii_lowercase();
    for marker in [
        "pid",
        "ppid",
        "process_id",
        "process_name",
        "raw_process",
        "path:",
        "c:\\",
        "\\users\\",
        "/users/",
        "/home/",
        "interface_name",
        "device_identifier",
        "packet_data",
        "packet_bytes",
        "provider_handle",
        "npcap_handle",
        "etw_raw_event",
        "credential",
        "secret",
        "token",
        "password",
        "api_key",
        "http://",
        "https://",
    ] {
        if normalized.contains(marker) {
            return Err(ProviderControllerContractError::UnsafeField(field));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_controller_initial_contract_is_bounded_and_inactive() {
        let status = NetworkProviderControllerStatus::inactive_servicehost("owner-ref", 1)
            .expect("initial provider status");

        assert_eq!(
            status.controller_state,
            NetworkProviderControllerState::Inactive
        );
        assert_eq!(
            status.selected_mode,
            NetworkProviderControllerMode::PortableOnly
        );
        assert_eq!(
            status
                .provider(NetworkProviderKind::PortableMetadata)
                .expect("portable")
                .implementation_state,
            NetworkProviderImplementationState::Available
        );
        assert_eq!(
            status
                .provider(NetworkProviderKind::IpHelper)
                .expect("ip helper")
                .implementation_state,
            NetworkProviderImplementationState::ImplementedInactive
        );
        assert_eq!(
            status
                .provider(NetworkProviderKind::IpHelper)
                .expect("ip helper")
                .adapter_boundary,
            "infrastructure"
        );
        assert_eq!(
            status
                .provider(NetworkProviderKind::EtwNetwork)
                .expect("etw")
                .implementation_state,
            NetworkProviderImplementationState::ImplementedInactive
        );
        assert!(status.policy_summary.provider_activation_allowed);
        assert!(
            status
                .policy_summary
                .ip_helper_execution_available_over_production_ipc
        );
        assert!(status.policy_summary.production_provider_mutations_enabled);
        assert!(!status.policy_summary.provider_readiness_creates_evidence);
        assert!(!status.policy_summary.provider_availability_creates_findings);
        assert!(status.provider_zero.all_zero());
    }

    #[test]
    fn provider_controller_rejects_unsupported_modes_and_activation() {
        let mut status = NetworkProviderControllerStatus::inactive_servicehost("owner-ref", 1)
            .expect("initial provider status");
        status.selected_mode = NetworkProviderControllerMode::PacketEnhanced;
        assert_eq!(
            status.validate(),
            Err(ProviderControllerContractError::InvalidSelectionPolicy)
        );

        let mut status = NetworkProviderControllerStatus::inactive_servicehost("owner-ref", 1)
            .expect("initial provider status");
        status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::NpcapPacket)
            .expect("npcap")
            .activation_allowed = true;
        assert_eq!(
            status.validate(),
            Err(ProviderControllerContractError::ActivationMustRemainBlocked)
        );
    }

    #[test]
    fn provider_controller_serializes_without_sensitive_fields() {
        let status = NetworkProviderControllerStatus::inactive_servicehost("owner-ref", 1)
            .expect("initial provider status");
        let serialized = serde_json::to_string(&status).expect("provider status json");
        for marker in [
            "process_name",
            "pid",
            "ppid",
            "interface_name",
            "device_identifier",
            "packet_data",
            "provider_handle",
            "npcap_handle",
            "etw_raw_event",
            "credential",
            "secret",
            "token",
            "api_key",
            "http://",
            "https://",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "provider controller leaked marker {marker}"
            );
        }
    }

    #[test]
    fn provider_controller_visibility_starts_portable_only() {
        let status = NetworkProviderControllerStatus::inactive_servicehost("owner-ref", 1)
            .expect("initial provider status");
        let portable = status
            .visibility_summary
            .dimensions
            .iter()
            .find(|dimension| {
                dimension.dimension == NetworkVisibilityDimension::PortableMetadataVisibility
            })
            .expect("portable dimension");
        assert_eq!(portable.visibility_state, NetworkVisibilityState::Available);
        assert!(status
            .visibility_summary
            .dimensions
            .iter()
            .filter(|dimension| {
                dimension.dimension != NetworkVisibilityDimension::PortableMetadataVisibility
            })
            .all(|dimension| dimension.visibility_state == NetworkVisibilityState::Unavailable));
    }
}
