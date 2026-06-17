use crate::{EvidenceId, QualityScore, RedactionStatus, SchemaVersion, SecurityFactId, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const NATIVE_NETWORK_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const NATIVE_IP_HELPER_METADATA_TOPIC: &str = "native.ip_helper.metadata";
pub const NATIVE_ETW_NETWORK_METADATA_TOPIC: &str = "native.etw_network.metadata";
pub const NATIVE_CONNECTION_CATEGORY_FACT_TOPIC: &str = "native.connection.category_fact";
pub const AUDIT_NETWORK_PROVIDER_EXECUTION_TOPIC: &str = "audit.network_provider_execution";
pub const MAX_NATIVE_NETWORK_RECORDS: usize = 128;
pub const MAX_NATIVE_NETWORK_REFS: usize = 32;
const MAX_NATIVE_NETWORK_TEXT_LEN: usize = 160;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeNetworkProviderCategory {
    IpHelper,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeNetworkTransportCategory {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeConnectionStateBucket {
    Listen,
    Established,
    Closing,
    Stateless,
    Other,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeEndpointScopeCategory {
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Public,
    Unspecified,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeEndpointRangeBucket {
    SystemRange,
    RegisteredRange,
    EphemeralRange,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeConnectionServiceBucket {
    Web,
    Dns,
    RemoteAdmin,
    FileSharing,
    Mail,
    Directory,
    Time,
    Other,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeConnectionRelationCategory {
    LocalOnly,
    LocalToPrivate,
    LocalToPublic,
    LocalToMulticast,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeOwnerPresenceCategory {
    OwnerObservedNotRetained,
    OwnerUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeNetworkProviderHealth {
    Available,
    Degraded,
    Unavailable,
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeNetworkFreshness {
    Fresh,
    Aging,
    Stale,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeIpHelperConnectionCategoryRecord {
    pub observation_ref: String,
    pub provider_category: NativeNetworkProviderCategory,
    pub transport_category: NativeNetworkTransportCategory,
    pub connection_state_bucket: NativeConnectionStateBucket,
    pub local_scope_category: NativeEndpointScopeCategory,
    pub destination_scope_category: NativeEndpointScopeCategory,
    pub local_endpoint_range_bucket: NativeEndpointRangeBucket,
    pub remote_endpoint_range_bucket: NativeEndpointRangeBucket,
    pub service_category_bucket: NativeConnectionServiceBucket,
    pub local_remote_relation_category: NativeConnectionRelationCategory,
    pub owner_presence_category: NativeOwnerPresenceCategory,
    pub count_bucket: String,
    pub change_bucket: String,
    pub time_bucket: Timestamp,
    pub confidence_hint: QualityScore,
    pub provider_health: NativeNetworkProviderHealth,
    pub evidence_refs: Vec<EvidenceId>,
    pub provenance_refs: Vec<String>,
    pub redaction_status: RedactionStatus,
    pub missing_visibility_flags: Vec<String>,
}

impl NativeIpHelperConnectionCategoryRecord {
    pub fn validate(&self) -> Result<(), NativeNetworkContractError> {
        validate_safe_text("observation_ref", &self.observation_ref)?;
        validate_safe_text("count_bucket", &self.count_bucket)?;
        validate_safe_text("change_bucket", &self.change_bucket)?;
        validate_safe_text_list("provenance_refs", &self.provenance_refs)?;
        validate_safe_text_list("missing_visibility_flags", &self.missing_visibility_flags)?;
        if self.evidence_refs.len() > MAX_NATIVE_NETWORK_REFS {
            return Err(NativeNetworkContractError::TooManyItems("evidence_refs"));
        }
        if self.provenance_refs.len() > MAX_NATIVE_NETWORK_REFS {
            return Err(NativeNetworkContractError::TooManyItems("provenance_refs"));
        }
        if self.missing_visibility_flags.len() > MAX_NATIVE_NETWORK_REFS {
            return Err(NativeNetworkContractError::TooManyItems(
                "missing_visibility_flags",
            ));
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(NativeNetworkContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeIpHelperMetadataBatch {
    pub batch_ref: String,
    pub provider_ref: String,
    pub provider_category: NativeNetworkProviderCategory,
    pub schema_version: SchemaVersion,
    pub sampled_time_bucket: Timestamp,
    pub provider_health: NativeNetworkProviderHealth,
    pub rows_observed_bucket: String,
    pub rows_processed_bucket: String,
    pub rows_suppressed_bucket: String,
    pub rows_dropped_bucket: String,
    pub tcp_count_bucket: String,
    pub udp_count_bucket: String,
    pub category_count_bucket: String,
    pub categories: Vec<NativeIpHelperConnectionCategoryRecord>,
    pub skipped_count_bucket: String,
    pub rejected_count_bucket: String,
    pub freshness: NativeNetworkFreshness,
    pub provider_status_ref: String,
    pub visibility_ref: String,
    pub fact_refs: Vec<SecurityFactId>,
    pub audit_refs: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub missing_visibility_flags: Vec<String>,
    pub degraded_reason: Option<String>,
    pub response_execution_allowed: bool,
    pub automatic_llm_calls: bool,
}

impl NativeIpHelperMetadataBatch {
    pub fn validate(&self) -> Result<(), NativeNetworkContractError> {
        validate_safe_text("batch_ref", &self.batch_ref)?;
        validate_safe_text("provider_ref", &self.provider_ref)?;
        validate_safe_text("rows_observed_bucket", &self.rows_observed_bucket)?;
        validate_safe_text("rows_processed_bucket", &self.rows_processed_bucket)?;
        validate_safe_text("rows_suppressed_bucket", &self.rows_suppressed_bucket)?;
        validate_safe_text("rows_dropped_bucket", &self.rows_dropped_bucket)?;
        validate_safe_text("tcp_count_bucket", &self.tcp_count_bucket)?;
        validate_safe_text("udp_count_bucket", &self.udp_count_bucket)?;
        validate_safe_text("category_count_bucket", &self.category_count_bucket)?;
        validate_safe_text("skipped_count_bucket", &self.skipped_count_bucket)?;
        validate_safe_text("rejected_count_bucket", &self.rejected_count_bucket)?;
        validate_safe_text("provider_status_ref", &self.provider_status_ref)?;
        validate_safe_text("visibility_ref", &self.visibility_ref)?;
        validate_safe_text("provenance_id", &self.provenance_id)?;
        validate_safe_text_list("audit_refs", &self.audit_refs)?;
        validate_safe_text_list("missing_visibility_flags", &self.missing_visibility_flags)?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        if self.schema_version != NATIVE_NETWORK_SCHEMA_VERSION {
            return Err(NativeNetworkContractError::UnsupportedSchemaVersion);
        }
        if self.categories.len() > MAX_NATIVE_NETWORK_RECORDS {
            return Err(NativeNetworkContractError::TooManyItems("categories"));
        }
        if self.fact_refs.len() > MAX_NATIVE_NETWORK_REFS {
            return Err(NativeNetworkContractError::TooManyItems("fact_refs"));
        }
        if self.audit_refs.len() > MAX_NATIVE_NETWORK_REFS {
            return Err(NativeNetworkContractError::TooManyItems("audit_refs"));
        }
        if self.missing_visibility_flags.len() > MAX_NATIVE_NETWORK_REFS {
            return Err(NativeNetworkContractError::TooManyItems(
                "missing_visibility_flags",
            ));
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(NativeNetworkContractError::RedactionRequired);
        }
        if self.response_execution_allowed || self.automatic_llm_calls {
            return Err(NativeNetworkContractError::UnsafeClaim);
        }
        for category in &self.categories {
            category.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeNetworkContractError {
    EmptyField(&'static str),
    TooLong(&'static str),
    UnsafeField(&'static str),
    TooManyItems(&'static str),
    UnsupportedSchemaVersion,
    RedactionRequired,
    UnsafeClaim,
}

impl fmt::Display for NativeNetworkContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::TooLong(field) => write!(formatter, "{field} exceeds bounded length"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains unsafe metadata"),
            Self::TooManyItems(field) => write!(formatter, "{field} exceeds bounded item count"),
            Self::UnsupportedSchemaVersion => {
                write!(formatter, "native network schema unsupported")
            }
            Self::RedactionRequired => {
                write!(formatter, "native network metadata must be redacted")
            }
            Self::UnsafeClaim => write!(formatter, "native network metadata made an unsafe claim"),
        }
    }
}

impl std::error::Error for NativeNetworkContractError {}

pub fn native_network_count_bucket(value: u32) -> String {
    match value {
        0 => "none",
        1 => "single",
        2..=10 => "low",
        11..=100 => "medium",
        _ => "high",
    }
    .to_string()
}

fn validate_safe_text_list(
    field: &'static str,
    values: &[String],
) -> Result<(), NativeNetworkContractError> {
    if values.len() > MAX_NATIVE_NETWORK_REFS {
        return Err(NativeNetworkContractError::TooManyItems(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), NativeNetworkContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), NativeNetworkContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(NativeNetworkContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_NATIVE_NETWORK_TEXT_LEN {
        return Err(NativeNetworkContractError::TooLong(field));
    }
    let normalized = trimmed.to_ascii_lowercase();
    for marker in [
        "pid",
        "ppid",
        "raw_process_id",
        "process_name",
        "raw_process",
        "executable",
        "command_line",
        "raw_address",
        "ip_address",
        "exact_ip",
        "port:",
        "exact_port",
        "socket",
        "handle",
        "interface_identifier",
        "hostname",
        "domain:",
        "raw_table",
        "packet_bytes",
        "packet_data",
        "payload_blob",
        "raw_payload",
        "payload_bytes",
        "path:",
        "c:\\",
        "\\users\\",
        "/users/",
        "/home/",
        "credential",
        "secret",
        "token",
        "password",
        "api_key",
        "http://",
        "https://",
        "process_attribution",
    ] {
        if normalized.contains(marker) {
            return Err(NativeNetworkContractError::UnsafeField(field));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> NativeIpHelperConnectionCategoryRecord {
        NativeIpHelperConnectionCategoryRecord {
            observation_ref: "ip_helper_observation_ref".to_string(),
            provider_category: NativeNetworkProviderCategory::IpHelper,
            transport_category: NativeNetworkTransportCategory::Tcp,
            connection_state_bucket: NativeConnectionStateBucket::Established,
            local_scope_category: NativeEndpointScopeCategory::Private,
            destination_scope_category: NativeEndpointScopeCategory::Public,
            local_endpoint_range_bucket: NativeEndpointRangeBucket::EphemeralRange,
            remote_endpoint_range_bucket: NativeEndpointRangeBucket::SystemRange,
            service_category_bucket: NativeConnectionServiceBucket::Web,
            local_remote_relation_category: NativeConnectionRelationCategory::LocalToPublic,
            owner_presence_category: NativeOwnerPresenceCategory::OwnerObservedNotRetained,
            count_bucket: "low".to_string(),
            change_bucket: "observed".to_string(),
            time_bucket: Timestamp::now(),
            confidence_hint: QualityScore::new(0.7).expect("quality"),
            provider_health: NativeNetworkProviderHealth::Available,
            evidence_refs: Vec::new(),
            provenance_refs: vec!["ip_helper_handoff_test".to_string()],
            redaction_status: RedactionStatus::Redacted,
            missing_visibility_flags: vec![
                "specific_process_identity_unavailable".to_string(),
                "process_network_attribution_unavailable".to_string(),
            ],
        }
    }

    fn batch() -> NativeIpHelperMetadataBatch {
        NativeIpHelperMetadataBatch {
            batch_ref: "ip_helper_batch_ref".to_string(),
            provider_ref: "ip_helper_provider_ref".to_string(),
            provider_category: NativeNetworkProviderCategory::IpHelper,
            schema_version: NATIVE_NETWORK_SCHEMA_VERSION,
            sampled_time_bucket: Timestamp::now(),
            provider_health: NativeNetworkProviderHealth::Available,
            rows_observed_bucket: "low".to_string(),
            rows_processed_bucket: "low".to_string(),
            rows_suppressed_bucket: "none".to_string(),
            rows_dropped_bucket: "none".to_string(),
            tcp_count_bucket: "low".to_string(),
            udp_count_bucket: "none".to_string(),
            category_count_bucket: "single".to_string(),
            categories: vec![record()],
            skipped_count_bucket: "none".to_string(),
            rejected_count_bucket: "none".to_string(),
            freshness: NativeNetworkFreshness::Fresh,
            provider_status_ref: "network_provider_ip_helper".to_string(),
            visibility_ref: "network_visibility_ref".to_string(),
            fact_refs: Vec::new(),
            audit_refs: vec!["audit_network_provider_execution_ref".to_string()],
            provenance_id: "ip_helper_servicehost_handoff".to_string(),
            redaction_status: RedactionStatus::Redacted,
            missing_visibility_flags: vec![
                "short_lived_network_event_visibility_unavailable".to_string(),
                "packet_visibility_unavailable".to_string(),
            ],
            degraded_reason: None,
            response_execution_allowed: false,
            automatic_llm_calls: false,
        }
    }

    #[test]
    fn native_network_batch_accepts_bounded_category_metadata() {
        batch().validate().expect("bounded native network batch");
    }

    #[test]
    fn native_network_contract_rejects_raw_identifier_markers() {
        let mut unsafe_batch = batch();
        unsafe_batch.degraded_reason = Some("raw_address 203.0.113.10 leaked".to_string());
        assert_eq!(
            unsafe_batch.validate(),
            Err(NativeNetworkContractError::UnsafeField("degraded_reason"))
        );

        let mut unsafe_record = record();
        unsafe_record.observation_ref = "pid_4242".to_string();
        assert_eq!(
            unsafe_record.validate(),
            Err(NativeNetworkContractError::UnsafeField("observation_ref"))
        );
    }

    #[test]
    fn owner_presence_is_not_process_attribution() {
        let serialized = serde_json::to_string(&record()).expect("record json");
        assert!(serialized.contains("owner_observed_not_retained"));
        assert!(!serialized.contains("process_attribution"));
    }

    #[test]
    fn native_network_serialization_excludes_sensitive_values() {
        let serialized = serde_json::to_string(&batch()).expect("batch json");
        for marker in [
            "203.0.113.10",
            "49152",
            "pid",
            "process_name",
            "c:\\",
            "socket",
            "packet_bytes",
            "payload_blob",
            "credential",
            "secret",
            "token",
            "https://",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "native network batch leaked marker {marker}: {serialized}"
            );
        }
    }
}
