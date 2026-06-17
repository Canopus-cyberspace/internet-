use crate::{
    EtwMissingVisibilityFlag, EtwNetworkEventFamily, NativeEndpointRangeBucket,
    NativeEndpointScopeCategory, NetworkProviderKind, RedactionStatus, SchemaVersion, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const ETW_NORMALIZATION_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_ETW_NORMALIZED_RECORDS: usize = 256;
pub const MAX_ETW_ALLOWLIST_ENTRIES: usize = 16;
pub const MAX_ETW_NORMALIZATION_REFS: usize = 16;
const MAX_ETW_NORMALIZATION_TEXT_LEN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwAllowedSchemaId {
    TcpConnectionLifecycleV1,
    TcpTransferMetadataV1,
    UdpDatagramActivityV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwTransportCategory {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwNetworkActivityCategory {
    Connect,
    Accept,
    Disconnect,
    Send,
    Receive,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwDirectionCategory {
    Inbound,
    Outbound,
    Local,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwByteCountBucket {
    None,
    Tiny,
    Small,
    Medium,
    Large,
    VeryLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwOwnerPresenceCategory {
    OwnerObservedNotRetained,
    OwnerUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwCountBucket {
    Zero,
    One,
    Low,
    Medium,
    High,
}

impl EtwCountBucket {
    pub fn from_count(value: u32) -> Self {
        match value {
            0 => Self::Zero,
            1 => Self::One,
            2..=10 => Self::Low,
            11..=100 => Self::Medium,
            _ => Self::High,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtwSchemaAllowlistEntry {
    pub schema_id: EtwAllowedSchemaId,
    pub event_family: EtwNetworkEventFamily,
    pub transport_category: EtwTransportCategory,
    pub schema_version: SchemaVersion,
    pub metadata_only: bool,
    pub raw_event_retention_allowed: bool,
    pub payload_collection_allowed: bool,
    pub provenance_refs: Vec<String>,
    pub redaction_status: RedactionStatus,
}

impl EtwSchemaAllowlistEntry {
    pub fn validate(&self) -> Result<(), EtwNetworkContractError> {
        validate_refs("allowlist provenance_refs", &self.provenance_refs)?;
        if self.schema_version != ETW_NORMALIZATION_SCHEMA_VERSION {
            return Err(EtwNetworkContractError::UnsupportedSchemaVersion);
        }
        if !self.metadata_only
            || self.raw_event_retention_allowed
            || self.payload_collection_allowed
        {
            return Err(EtwNetworkContractError::UnsafeClaim);
        }
        if !matches!(
            (self.schema_id, self.event_family, self.transport_category),
            (
                EtwAllowedSchemaId::TcpConnectionLifecycleV1,
                EtwNetworkEventFamily::ConnectionLifecycle,
                EtwTransportCategory::Tcp
            ) | (
                EtwAllowedSchemaId::TcpTransferMetadataV1,
                EtwNetworkEventFamily::TransferMetadata,
                EtwTransportCategory::Tcp
            ) | (
                EtwAllowedSchemaId::UdpDatagramActivityV1,
                EtwNetworkEventFamily::DatagramActivity,
                EtwTransportCategory::Udp
            )
        ) {
            return Err(EtwNetworkContractError::InvalidAllowlist);
        }
        validate_redaction(&self.redaction_status)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtwSchemaAllowlist {
    pub allowlist_ref: String,
    pub schema_version: SchemaVersion,
    pub entries: Vec<EtwSchemaAllowlistEntry>,
    pub reject_unknown_schemas: bool,
    pub reject_unknown_versions: bool,
    pub provenance_refs: Vec<String>,
    pub redaction_status: RedactionStatus,
}

impl EtwSchemaAllowlist {
    pub fn metadata_only_v1() -> Self {
        Self {
            allowlist_ref: "etw_network_schema_allowlist_v1".to_string(),
            schema_version: ETW_NORMALIZATION_SCHEMA_VERSION,
            entries: vec![
                EtwSchemaAllowlistEntry {
                    schema_id: EtwAllowedSchemaId::TcpConnectionLifecycleV1,
                    event_family: EtwNetworkEventFamily::ConnectionLifecycle,
                    transport_category: EtwTransportCategory::Tcp,
                    schema_version: ETW_NORMALIZATION_SCHEMA_VERSION,
                    metadata_only: true,
                    raw_event_retention_allowed: false,
                    payload_collection_allowed: false,
                    provenance_refs: vec!["etw_declared_schema_contract".to_string()],
                    redaction_status: RedactionStatus::Redacted,
                },
                EtwSchemaAllowlistEntry {
                    schema_id: EtwAllowedSchemaId::TcpTransferMetadataV1,
                    event_family: EtwNetworkEventFamily::TransferMetadata,
                    transport_category: EtwTransportCategory::Tcp,
                    schema_version: ETW_NORMALIZATION_SCHEMA_VERSION,
                    metadata_only: true,
                    raw_event_retention_allowed: false,
                    payload_collection_allowed: false,
                    provenance_refs: vec!["etw_declared_schema_contract".to_string()],
                    redaction_status: RedactionStatus::Redacted,
                },
                EtwSchemaAllowlistEntry {
                    schema_id: EtwAllowedSchemaId::UdpDatagramActivityV1,
                    event_family: EtwNetworkEventFamily::DatagramActivity,
                    transport_category: EtwTransportCategory::Udp,
                    schema_version: ETW_NORMALIZATION_SCHEMA_VERSION,
                    metadata_only: true,
                    raw_event_retention_allowed: false,
                    payload_collection_allowed: false,
                    provenance_refs: vec!["etw_declared_schema_contract".to_string()],
                    redaction_status: RedactionStatus::Redacted,
                },
            ],
            reject_unknown_schemas: true,
            reject_unknown_versions: true,
            provenance_refs: vec!["etw_schema_allowlist_contract".to_string()],
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn validate(&self) -> Result<(), EtwNetworkContractError> {
        validate_safe_text("allowlist_ref", &self.allowlist_ref)?;
        validate_refs("allowlist provenance_refs", &self.provenance_refs)?;
        if self.schema_version != ETW_NORMALIZATION_SCHEMA_VERSION {
            return Err(EtwNetworkContractError::UnsupportedSchemaVersion);
        }
        if self.entries.is_empty() || self.entries.len() > MAX_ETW_ALLOWLIST_ENTRIES {
            return Err(EtwNetworkContractError::InvalidAllowlist);
        }
        if !self.reject_unknown_schemas || !self.reject_unknown_versions {
            return Err(EtwNetworkContractError::InvalidAllowlist);
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if self.entries[index + 1..]
                .iter()
                .any(|other| other.schema_id == entry.schema_id)
            {
                return Err(EtwNetworkContractError::InvalidAllowlist);
            }
        }
        validate_redaction(&self.redaction_status)
    }

    pub fn entry(&self, schema_id: EtwAllowedSchemaId) -> Option<&EtwSchemaAllowlistEntry> {
        self.entries
            .iter()
            .find(|entry| entry.schema_id == schema_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtwNormalizedNetworkRecord {
    pub record_ref: String,
    pub schema_id: EtwAllowedSchemaId,
    pub event_family: EtwNetworkEventFamily,
    pub transport_category: EtwTransportCategory,
    pub activity_category: EtwNetworkActivityCategory,
    pub direction_category: EtwDirectionCategory,
    pub local_scope_category: NativeEndpointScopeCategory,
    pub destination_scope_category: NativeEndpointScopeCategory,
    pub local_endpoint_range_bucket: NativeEndpointRangeBucket,
    pub remote_endpoint_range_bucket: NativeEndpointRangeBucket,
    pub byte_count_bucket: EtwByteCountBucket,
    pub owner_presence_category: EtwOwnerPresenceCategory,
    pub count_bucket: EtwCountBucket,
    pub provenance_refs: Vec<String>,
    pub redaction_status: RedactionStatus,
    pub missing_visibility_flags: Vec<EtwMissingVisibilityFlag>,
}

impl EtwNormalizedNetworkRecord {
    pub fn validate(&self) -> Result<(), EtwNetworkContractError> {
        validate_safe_text("record_ref", &self.record_ref)?;
        validate_refs("record provenance_refs", &self.provenance_refs)?;
        if self.missing_visibility_flags.is_empty()
            || self.missing_visibility_flags.len() > MAX_ETW_NORMALIZATION_REFS
        {
            return Err(EtwNetworkContractError::TooManyItems(
                "missing_visibility_flags",
            ));
        }
        validate_redaction(&self.redaction_status)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtwNormalizationPrivacySummary {
    pub raw_event_retention_allowed: bool,
    pub raw_address_retention_allowed: bool,
    pub exact_port_retention_allowed: bool,
    pub process_identity_retention_allowed: bool,
    pub payload_collection_allowed: bool,
    pub dedup_hash_exposed: bool,
    pub category_only_output: bool,
}

impl Default for EtwNormalizationPrivacySummary {
    fn default() -> Self {
        Self {
            raw_event_retention_allowed: false,
            raw_address_retention_allowed: false,
            exact_port_retention_allowed: false,
            process_identity_retention_allowed: false,
            payload_collection_allowed: false,
            dedup_hash_exposed: false,
            category_only_output: true,
        }
    }
}

impl EtwNormalizationPrivacySummary {
    pub fn validate(&self) -> Result<(), EtwNetworkContractError> {
        if self.raw_event_retention_allowed
            || self.raw_address_retention_allowed
            || self.exact_port_retention_allowed
            || self.process_identity_retention_allowed
            || self.payload_collection_allowed
            || self.dedup_hash_exposed
            || !self.category_only_output
        {
            return Err(EtwNetworkContractError::UnsafeClaim);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtwNormalizedNetworkBatch {
    pub batch_ref: String,
    pub schema_version: SchemaVersion,
    pub provider_kind: NetworkProviderKind,
    pub generated_at: Timestamp,
    pub allowlist_ref: String,
    pub events_observed: u32,
    pub events_accepted: u32,
    pub events_deduplicated: u32,
    pub events_rejected: u32,
    pub events_dropped: u32,
    pub records: Vec<EtwNormalizedNetworkRecord>,
    pub privacy: EtwNormalizationPrivacySummary,
    pub event_session_created: bool,
    pub collection_started: bool,
    pub eventbus_publication_count: u32,
    pub security_fact_count: u32,
    pub provenance_refs: Vec<String>,
    pub redaction_status: RedactionStatus,
    pub degraded_reason: Option<String>,
}

impl EtwNormalizedNetworkBatch {
    pub fn validate(&self) -> Result<(), EtwNetworkContractError> {
        validate_safe_text("batch_ref", &self.batch_ref)?;
        validate_safe_text("allowlist_ref", &self.allowlist_ref)?;
        validate_refs("batch provenance_refs", &self.provenance_refs)?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        if self.schema_version != ETW_NORMALIZATION_SCHEMA_VERSION {
            return Err(EtwNetworkContractError::UnsupportedSchemaVersion);
        }
        if self.provider_kind != NetworkProviderKind::EtwNetwork {
            return Err(EtwNetworkContractError::WrongProviderKind);
        }
        if self.records.len() > MAX_ETW_NORMALIZED_RECORDS {
            return Err(EtwNetworkContractError::TooManyItems("records"));
        }
        if self.events_accepted
            > self
                .events_observed
                .saturating_sub(self.events_rejected)
                .saturating_sub(self.events_dropped)
            || self.event_session_created
            || self.collection_started
            || self.eventbus_publication_count != 0
            || self.security_fact_count != 0
        {
            return Err(EtwNetworkContractError::RuntimeBoundaryViolation);
        }
        self.privacy.validate()?;
        for record in &self.records {
            record.validate()?;
        }
        validate_redaction(&self.redaction_status)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EtwNetworkContractError {
    EmptyField(&'static str),
    TooLong(&'static str),
    UnsafeField(&'static str),
    TooManyItems(&'static str),
    UnsupportedSchemaVersion,
    WrongProviderKind,
    InvalidAllowlist,
    RuntimeBoundaryViolation,
    RedactionRequired,
    UnsafeClaim,
}

impl fmt::Display for EtwNetworkContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::TooLong(field) => write!(formatter, "{field} exceeds bounded length"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains unsafe metadata"),
            Self::TooManyItems(field) => write!(formatter, "{field} exceeds bounded item count"),
            Self::UnsupportedSchemaVersion => write!(formatter, "ETW schema version unsupported"),
            Self::WrongProviderKind => write!(formatter, "ETW provider kind is invalid"),
            Self::InvalidAllowlist => write!(formatter, "ETW schema allowlist is invalid"),
            Self::RuntimeBoundaryViolation => {
                write!(formatter, "ETW normalization crossed the runtime boundary")
            }
            Self::RedactionRequired => write!(formatter, "ETW output must be redacted"),
            Self::UnsafeClaim => write!(formatter, "ETW normalization made an unsafe claim"),
        }
    }
}

impl std::error::Error for EtwNetworkContractError {}

fn validate_refs(field: &'static str, values: &[String]) -> Result<(), EtwNetworkContractError> {
    if values.len() > MAX_ETW_NORMALIZATION_REFS {
        return Err(EtwNetworkContractError::TooManyItems(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), EtwNetworkContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), EtwNetworkContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(EtwNetworkContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_ETW_NORMALIZATION_TEXT_LEN {
        return Err(EtwNetworkContractError::TooLong(field));
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
            return Err(EtwNetworkContractError::UnsafeField(field));
        }
    }
    Ok(())
}

fn validate_redaction(status: &RedactionStatus) -> Result<(), EtwNetworkContractError> {
    if *status == RedactionStatus::RedactionRequired {
        Err(EtwNetworkContractError::RedactionRequired)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etw_network_allowlist_is_bounded_and_metadata_only() {
        let allowlist = EtwSchemaAllowlist::metadata_only_v1();
        assert!(allowlist.validate().is_ok());
        assert_eq!(allowlist.entries.len(), 3);
        assert!(allowlist.reject_unknown_schemas);
    }

    #[test]
    fn etw_network_contract_rejects_unknown_fields() {
        let value = serde_json::to_value(EtwSchemaAllowlist::metadata_only_v1())
            .expect("serialize allowlist");
        let mut object = value.as_object().cloned().expect("allowlist object");
        object.insert("raw_provider_guid".to_string(), serde_json::json!("unsafe"));
        assert!(
            serde_json::from_value::<EtwSchemaAllowlist>(serde_json::Value::Object(object))
                .is_err()
        );
    }

    #[test]
    fn etw_network_allowlist_rejects_duplicate_or_mismatched_declarations() {
        let mut duplicate = EtwSchemaAllowlist::metadata_only_v1();
        duplicate.entries.push(duplicate.entries[0].clone());
        assert_eq!(
            duplicate.validate(),
            Err(EtwNetworkContractError::InvalidAllowlist)
        );

        let mut mismatched = EtwSchemaAllowlist::metadata_only_v1();
        mismatched.entries[0].transport_category = EtwTransportCategory::Udp;
        assert_eq!(
            mismatched.validate(),
            Err(EtwNetworkContractError::InvalidAllowlist)
        );
    }
}
