use crate::{NetworkProviderKind, RedactionStatus, SchemaVersion, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const ETW_PROBE_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const ETW_NETWORK_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_ETW_PROBE_REFS: usize = 16;
const MAX_ETW_PROBE_TEXT_LEN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwCapabilityState {
    Available,
    Degraded,
    Unavailable,
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwApiSurfaceState {
    Complete,
    CoreOnly,
    Missing,
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwSchemaSupportState {
    RuntimeMetadataAvailable,
    DeclaredOnly,
    Unavailable,
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwSessionState {
    NotCreated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwCollectionState {
    Inactive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwArchitectureOwner {
    Contracts,
    Infrastructure,
    ServiceHost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwNetworkEventFamily {
    ConnectionLifecycle,
    DatagramActivity,
    TransferMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwNetworkMetadataField {
    TransportCategory,
    DirectionCategory,
    LocalScopeCategory,
    DestinationScopeCategory,
    LocalEndpointRangeBucket,
    RemoteEndpointRangeBucket,
    ByteCountBucket,
    TimeBucket,
    ProviderHealth,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwMissingVisibilityFlag {
    SpecificProcessIdentityUnavailable,
    ProcessNetworkAttributionUnavailable,
    PacketPayloadUnavailable,
    CommandLineUnavailable,
    FileRegistryUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtwArchitectureInventory {
    pub inventory_ref: String,
    pub contract_owner: EtwArchitectureOwner,
    pub probe_owner: EtwArchitectureOwner,
    pub future_collection_owner: EtwArchitectureOwner,
    pub desktop_execution_allowed: bool,
    pub capability_runtime_ownership_allowed: bool,
    pub probe_only: bool,
    pub event_session_implemented: bool,
    pub collection_implemented: bool,
    pub schema_declaration_implemented: bool,
    pub provenance_refs: Vec<String>,
    pub redaction_status: RedactionStatus,
}

impl EtwArchitectureInventory {
    pub fn probe_only() -> Self {
        Self {
            inventory_ref: "etw_architecture_inventory_ref".to_string(),
            contract_owner: EtwArchitectureOwner::Contracts,
            probe_owner: EtwArchitectureOwner::Infrastructure,
            future_collection_owner: EtwArchitectureOwner::ServiceHost,
            desktop_execution_allowed: false,
            capability_runtime_ownership_allowed: false,
            probe_only: true,
            event_session_implemented: false,
            collection_implemented: false,
            schema_declaration_implemented: true,
            provenance_refs: vec![
                "etw_contracts_owner".to_string(),
                "etw_infrastructure_probe_owner".to_string(),
                "etw_servicehost_future_runtime_owner".to_string(),
            ],
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn validate(&self) -> Result<(), EtwProbeContractError> {
        validate_safe_text("inventory_ref", &self.inventory_ref)?;
        validate_refs("inventory provenance_refs", &self.provenance_refs)?;
        if self.contract_owner != EtwArchitectureOwner::Contracts
            || self.probe_owner != EtwArchitectureOwner::Infrastructure
            || self.future_collection_owner != EtwArchitectureOwner::ServiceHost
            || self.desktop_execution_allowed
            || self.capability_runtime_ownership_allowed
            || !self.probe_only
            || self.event_session_implemented
            || self.collection_implemented
            || !self.schema_declaration_implemented
        {
            return Err(EtwProbeContractError::ArchitectureBoundaryViolation);
        }
        validate_redaction(&self.redaction_status)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtwNetworkSchemaDeclaration {
    pub declaration_ref: String,
    pub schema_version: SchemaVersion,
    pub provider_kind: NetworkProviderKind,
    pub event_families: Vec<EtwNetworkEventFamily>,
    pub metadata_fields: Vec<EtwNetworkMetadataField>,
    pub missing_visibility_flags: Vec<EtwMissingVisibilityFlag>,
    pub runtime_metadata_required: bool,
    pub raw_event_retention_allowed: bool,
    pub payload_collection_allowed: bool,
    pub process_network_attribution_allowed: bool,
    pub response_execution_allowed: bool,
    pub automatic_llm_calls_allowed: bool,
    pub provenance_refs: Vec<String>,
    pub redaction_status: RedactionStatus,
}

impl EtwNetworkSchemaDeclaration {
    pub fn metadata_only_v1() -> Self {
        Self {
            declaration_ref: "etw_network_schema_v1".to_string(),
            schema_version: ETW_NETWORK_SCHEMA_VERSION,
            provider_kind: NetworkProviderKind::EtwNetwork,
            event_families: vec![
                EtwNetworkEventFamily::ConnectionLifecycle,
                EtwNetworkEventFamily::DatagramActivity,
                EtwNetworkEventFamily::TransferMetadata,
            ],
            metadata_fields: vec![
                EtwNetworkMetadataField::TransportCategory,
                EtwNetworkMetadataField::DirectionCategory,
                EtwNetworkMetadataField::LocalScopeCategory,
                EtwNetworkMetadataField::DestinationScopeCategory,
                EtwNetworkMetadataField::LocalEndpointRangeBucket,
                EtwNetworkMetadataField::RemoteEndpointRangeBucket,
                EtwNetworkMetadataField::ByteCountBucket,
                EtwNetworkMetadataField::TimeBucket,
                EtwNetworkMetadataField::ProviderHealth,
            ],
            missing_visibility_flags: vec![
                EtwMissingVisibilityFlag::SpecificProcessIdentityUnavailable,
                EtwMissingVisibilityFlag::ProcessNetworkAttributionUnavailable,
                EtwMissingVisibilityFlag::PacketPayloadUnavailable,
                EtwMissingVisibilityFlag::CommandLineUnavailable,
                EtwMissingVisibilityFlag::FileRegistryUnavailable,
            ],
            runtime_metadata_required: true,
            raw_event_retention_allowed: false,
            payload_collection_allowed: false,
            process_network_attribution_allowed: false,
            response_execution_allowed: false,
            automatic_llm_calls_allowed: false,
            provenance_refs: vec!["etw_network_schema_contract".to_string()],
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn validate(&self) -> Result<(), EtwProbeContractError> {
        validate_safe_text("declaration_ref", &self.declaration_ref)?;
        validate_refs("schema provenance_refs", &self.provenance_refs)?;
        if self.schema_version != ETW_NETWORK_SCHEMA_VERSION {
            return Err(EtwProbeContractError::UnsupportedSchemaVersion);
        }
        if self.provider_kind != NetworkProviderKind::EtwNetwork {
            return Err(EtwProbeContractError::WrongProviderKind);
        }
        if self.event_families.is_empty()
            || self.event_families.len() > MAX_ETW_PROBE_REFS
            || self.metadata_fields.is_empty()
            || self.metadata_fields.len() > MAX_ETW_PROBE_REFS
            || self.missing_visibility_flags.is_empty()
            || self.missing_visibility_flags.len() > MAX_ETW_PROBE_REFS
        {
            return Err(EtwProbeContractError::InvalidSchemaDeclaration);
        }
        if !self.runtime_metadata_required
            || self.raw_event_retention_allowed
            || self.payload_collection_allowed
            || self.process_network_attribution_allowed
            || self.response_execution_allowed
            || self.automatic_llm_calls_allowed
        {
            return Err(EtwProbeContractError::UnsafeClaim);
        }
        validate_redaction(&self.redaction_status)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtwCapabilityProbeSnapshot {
    pub probe_ref: String,
    pub schema_version: SchemaVersion,
    pub provider_kind: NetworkProviderKind,
    pub capability_state: EtwCapabilityState,
    pub api_surface_state: EtwApiSurfaceState,
    pub schema_support_state: EtwSchemaSupportState,
    pub session_state: EtwSessionState,
    pub collection_state: EtwCollectionState,
    pub activation_allowed: bool,
    pub event_session_created: bool,
    pub collection_started: bool,
    pub provider_execution_count: u32,
    pub events_observed_count: u32,
    pub eventbus_publication_count: u32,
    pub finding_count: u32,
    pub degraded_reason: Option<String>,
    pub schema_declaration: EtwNetworkSchemaDeclaration,
    pub audit_refs: Vec<String>,
    pub provenance_refs: Vec<String>,
    pub probed_at: Timestamp,
    pub redaction_status: RedactionStatus,
}

impl EtwCapabilityProbeSnapshot {
    pub fn validate(&self) -> Result<(), EtwProbeContractError> {
        validate_safe_text("probe_ref", &self.probe_ref)?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        validate_refs("probe audit_refs", &self.audit_refs)?;
        validate_refs("probe provenance_refs", &self.provenance_refs)?;
        if self.schema_version != ETW_PROBE_SCHEMA_VERSION {
            return Err(EtwProbeContractError::UnsupportedSchemaVersion);
        }
        if self.provider_kind != NetworkProviderKind::EtwNetwork {
            return Err(EtwProbeContractError::WrongProviderKind);
        }
        self.schema_declaration.validate()?;
        if self.session_state != EtwSessionState::NotCreated
            || self.collection_state != EtwCollectionState::Inactive
            || self.activation_allowed
            || self.event_session_created
            || self.collection_started
            || self.provider_execution_count != 0
            || self.events_observed_count != 0
            || self.eventbus_publication_count != 0
            || self.finding_count != 0
        {
            return Err(EtwProbeContractError::ProbeCreatedRuntimeState);
        }
        validate_capability_combination(
            self.capability_state,
            self.api_surface_state,
            self.schema_support_state,
        )?;
        validate_redaction(&self.redaction_status)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtwProbeAuditRecord {
    pub audit_ref: String,
    pub probe_ref: String,
    pub result_state: EtwCapabilityState,
    pub session_state: EtwSessionState,
    pub collection_state: EtwCollectionState,
    pub provider_execution_count: u32,
    pub eventbus_publication_count: u32,
    pub findings_created_count: u32,
    pub response_execution_allowed: bool,
    pub automatic_llm_calls_allowed: bool,
    pub provenance_refs: Vec<String>,
    pub recorded_at: Timestamp,
    pub redaction_status: RedactionStatus,
}

impl EtwProbeAuditRecord {
    pub fn from_probe(probe: &EtwCapabilityProbeSnapshot) -> Self {
        Self {
            audit_ref: "audit_etw_capability_probe_ref".to_string(),
            probe_ref: probe.probe_ref.clone(),
            result_state: probe.capability_state,
            session_state: probe.session_state,
            collection_state: probe.collection_state,
            provider_execution_count: probe.provider_execution_count,
            eventbus_publication_count: probe.eventbus_publication_count,
            findings_created_count: probe.finding_count,
            response_execution_allowed: false,
            automatic_llm_calls_allowed: false,
            provenance_refs: vec!["etw_read_only_capability_probe".to_string()],
            recorded_at: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn validate(&self) -> Result<(), EtwProbeContractError> {
        validate_safe_text("audit_ref", &self.audit_ref)?;
        validate_safe_text("audit probe_ref", &self.probe_ref)?;
        validate_refs("audit provenance_refs", &self.provenance_refs)?;
        if self.session_state != EtwSessionState::NotCreated
            || self.collection_state != EtwCollectionState::Inactive
            || self.provider_execution_count != 0
            || self.eventbus_publication_count != 0
            || self.findings_created_count != 0
            || self.response_execution_allowed
            || self.automatic_llm_calls_allowed
        {
            return Err(EtwProbeContractError::ProbeCreatedRuntimeState);
        }
        validate_redaction(&self.redaction_status)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtwProbeReadModel {
    pub read_model_ref: String,
    pub architecture: EtwArchitectureInventory,
    pub probe: EtwCapabilityProbeSnapshot,
    pub audit: EtwProbeAuditRecord,
    pub generated_at: Timestamp,
    pub redaction_status: RedactionStatus,
}

impl EtwProbeReadModel {
    pub fn validate(&self) -> Result<(), EtwProbeContractError> {
        validate_safe_text("read_model_ref", &self.read_model_ref)?;
        self.architecture.validate()?;
        self.probe.validate()?;
        self.audit.validate()?;
        if self.audit.probe_ref != self.probe.probe_ref
            || self.audit.result_state != self.probe.capability_state
        {
            return Err(EtwProbeContractError::AuditMismatch);
        }
        validate_redaction(&self.redaction_status)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EtwProbeContractError {
    EmptyField(&'static str),
    TooLong(&'static str),
    UnsafeField(&'static str),
    TooManyItems(&'static str),
    UnsupportedSchemaVersion,
    WrongProviderKind,
    InvalidSchemaDeclaration,
    InvalidCapabilityCombination,
    ArchitectureBoundaryViolation,
    ProbeCreatedRuntimeState,
    AuditMismatch,
    RedactionRequired,
    UnsafeClaim,
}

impl fmt::Display for EtwProbeContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::TooLong(field) => write!(formatter, "{field} exceeds bounded length"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains unsafe metadata"),
            Self::TooManyItems(field) => write!(formatter, "{field} exceeds bounded item count"),
            Self::UnsupportedSchemaVersion => write!(formatter, "ETW probe schema unsupported"),
            Self::WrongProviderKind => write!(formatter, "ETW probe provider kind is invalid"),
            Self::InvalidSchemaDeclaration => {
                write!(formatter, "ETW schema declaration is invalid")
            }
            Self::InvalidCapabilityCombination => {
                write!(formatter, "ETW capability state combination is invalid")
            }
            Self::ArchitectureBoundaryViolation => {
                write!(formatter, "ETW architecture ownership boundary is invalid")
            }
            Self::ProbeCreatedRuntimeState => {
                write!(formatter, "ETW read-only probe created runtime state")
            }
            Self::AuditMismatch => write!(formatter, "ETW probe audit does not match probe"),
            Self::RedactionRequired => write!(formatter, "ETW probe output must be redacted"),
            Self::UnsafeClaim => write!(formatter, "ETW contract made an unsafe claim"),
        }
    }
}

impl std::error::Error for EtwProbeContractError {}

fn validate_capability_combination(
    capability: EtwCapabilityState,
    api_surface: EtwApiSurfaceState,
    schema_support: EtwSchemaSupportState,
) -> Result<(), EtwProbeContractError> {
    let valid = matches!(
        (capability, api_surface, schema_support),
        (
            EtwCapabilityState::Available,
            EtwApiSurfaceState::Complete,
            EtwSchemaSupportState::RuntimeMetadataAvailable
        ) | (
            EtwCapabilityState::Degraded,
            EtwApiSurfaceState::CoreOnly,
            EtwSchemaSupportState::DeclaredOnly
        ) | (
            EtwCapabilityState::Unavailable,
            EtwApiSurfaceState::Missing,
            EtwSchemaSupportState::Unavailable
        ) | (
            EtwCapabilityState::UnsupportedPlatform,
            EtwApiSurfaceState::UnsupportedPlatform,
            EtwSchemaSupportState::UnsupportedPlatform
        )
    );
    if valid {
        Ok(())
    } else {
        Err(EtwProbeContractError::InvalidCapabilityCombination)
    }
}

fn validate_refs(field: &'static str, values: &[String]) -> Result<(), EtwProbeContractError> {
    if values.len() > MAX_ETW_PROBE_REFS {
        return Err(EtwProbeContractError::TooManyItems(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), EtwProbeContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), EtwProbeContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(EtwProbeContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_ETW_PROBE_TEXT_LEN {
        return Err(EtwProbeContractError::TooLong(field));
    }
    let normalized = trimmed.to_ascii_lowercase();
    for marker in [
        "pid=",
        "ppid=",
        "process_name=",
        "command_line=",
        "raw_address=",
        "ip_address=",
        "exact_port=",
        "socket=",
        "handle=",
        "path=",
        "c:\\",
        "\\users\\",
        "/users/",
        "/home/",
        "packet_bytes=",
        "payload=",
        "token=",
        "credential=",
        "secret=",
        "password=",
        "api_key=",
        "http://",
        "https://",
    ] {
        if normalized.contains(marker) {
            return Err(EtwProbeContractError::UnsafeField(field));
        }
    }
    Ok(())
}

fn validate_redaction(status: &RedactionStatus) -> Result<(), EtwProbeContractError> {
    if *status == RedactionStatus::RedactionRequired {
        Err(EtwProbeContractError::RedactionRequired)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn available_probe() -> EtwCapabilityProbeSnapshot {
        EtwCapabilityProbeSnapshot {
            probe_ref: "etw_capability_probe_ref".to_string(),
            schema_version: ETW_PROBE_SCHEMA_VERSION,
            provider_kind: NetworkProviderKind::EtwNetwork,
            capability_state: EtwCapabilityState::Available,
            api_surface_state: EtwApiSurfaceState::Complete,
            schema_support_state: EtwSchemaSupportState::RuntimeMetadataAvailable,
            session_state: EtwSessionState::NotCreated,
            collection_state: EtwCollectionState::Inactive,
            activation_allowed: false,
            event_session_created: false,
            collection_started: false,
            provider_execution_count: 0,
            events_observed_count: 0,
            eventbus_publication_count: 0,
            finding_count: 0,
            degraded_reason: None,
            schema_declaration: EtwNetworkSchemaDeclaration::metadata_only_v1(),
            audit_refs: vec!["audit_etw_capability_probe_ref".to_string()],
            provenance_refs: vec!["etw_infrastructure_capability_probe".to_string()],
            probed_at: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    #[test]
    fn etw_probe_contract_is_probe_only_and_schema_bounded() {
        let probe = available_probe();
        assert!(probe.validate().is_ok());
        assert!(EtwArchitectureInventory::probe_only().validate().is_ok());
    }

    #[test]
    fn etw_probe_contract_rejects_runtime_state_and_unknown_fields() {
        let mut probe = available_probe();
        probe.event_session_created = true;
        assert_eq!(
            probe.validate(),
            Err(EtwProbeContractError::ProbeCreatedRuntimeState)
        );

        let value = serde_json::to_value(available_probe()).expect("serialize");
        let mut object = value.as_object().cloned().expect("object");
        object.insert("raw_process_name".to_string(), serde_json::json!("unsafe"));
        assert!(
            serde_json::from_value::<EtwCapabilityProbeSnapshot>(serde_json::Value::Object(object))
                .is_err()
        );
    }
}
