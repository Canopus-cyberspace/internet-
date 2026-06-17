use sentinel_contracts::{NetworkProviderKind, RedactionStatus, SchemaVersion};
use serde::{Deserialize, Serialize};

pub const PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
const MAX_PROVIDER_ADAPTER_TEXT_LEN: usize = 128;
const MAX_PROVIDER_ADAPTER_ITEMS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAdapterBoundary {
    Infrastructure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderExecutionOwner {
    FutureServiceHostProviderController,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRuntimeStateOwner {
    ServiceHost,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdapterOwnership {
    pub adapter_boundary: ProviderAdapterBoundary,
    pub execution_owner: ProviderExecutionOwner,
    pub runtime_state_owner: ProviderRuntimeStateOwner,
    pub owns_scheduler: bool,
    pub owns_event_bus: bool,
    pub owns_dag: bool,
    pub owns_plugin_runtime: bool,
    pub owns_read_models: bool,
    pub owns_provider_controller: bool,
    pub owns_fusion: bool,
    pub owns_findings: bool,
    pub owns_storage: bool,
}

impl ProviderAdapterOwnership {
    pub fn infrastructure_adapter() -> Self {
        Self {
            adapter_boundary: ProviderAdapterBoundary::Infrastructure,
            execution_owner: ProviderExecutionOwner::FutureServiceHostProviderController,
            runtime_state_owner: ProviderRuntimeStateOwner::ServiceHost,
            owns_scheduler: false,
            owns_event_bus: false,
            owns_dag: false,
            owns_plugin_runtime: false,
            owns_read_models: false,
            owns_provider_controller: false,
            owns_fusion: false,
            owns_findings: false,
            owns_storage: false,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderAdapterContractError> {
        if self.owns_scheduler
            || self.owns_event_bus
            || self.owns_dag
            || self.owns_plugin_runtime
            || self.owns_read_models
            || self.owns_provider_controller
            || self.owns_fusion
            || self.owns_findings
            || self.owns_storage
        {
            return Err(ProviderAdapterContractError::RuntimeOwnershipForbidden);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdapterMetadata {
    pub adapter_id: String,
    pub provider_kind: NetworkProviderKind,
    pub schema_version: SchemaVersion,
    pub ownership: ProviderAdapterOwnership,
    pub supported_request_refs: Vec<String>,
    pub supported_result_refs: Vec<String>,
    pub privacy_notes: Vec<String>,
    pub redaction_status: RedactionStatus,
}

impl ProviderAdapterMetadata {
    pub fn validate(&self) -> Result<(), ProviderAdapterContractError> {
        validate_safe_text("adapter_id", &self.adapter_id)?;
        self.ownership.validate()?;
        validate_safe_text_list("supported_request_refs", &self.supported_request_refs)?;
        validate_safe_text_list("supported_result_refs", &self.supported_result_refs)?;
        validate_safe_text_list("privacy_notes", &self.privacy_notes)?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ProviderAdapterContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedProviderRequest {
    pub provider_kind: NetworkProviderKind,
    pub schema_version: SchemaVersion,
    pub max_records: usize,
    pub max_bytes: usize,
    pub timeout_ms: u64,
    pub cancellation_ref: Option<String>,
    pub provenance_ref: String,
    pub redaction_status: RedactionStatus,
}

impl BoundedProviderRequest {
    pub fn validate(&self) -> Result<(), ProviderAdapterContractError> {
        validate_optional_safe_text("cancellation_ref", self.cancellation_ref.as_deref())?;
        validate_safe_text("provenance_ref", &self.provenance_ref)?;
        if self.max_records == 0 || self.max_records > 16_384 {
            return Err(ProviderAdapterContractError::BoundsRequired("max_records"));
        }
        if self.max_bytes == 0 || self.max_bytes > 8 * 1024 * 1024 {
            return Err(ProviderAdapterContractError::BoundsRequired("max_bytes"));
        }
        if !(25..=2_000).contains(&self.timeout_ms) {
            return Err(ProviderAdapterContractError::BoundsRequired("timeout_ms"));
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ProviderAdapterContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedProviderResult {
    pub provider_kind: NetworkProviderKind,
    pub schema_version: SchemaVersion,
    pub records_observed: u32,
    pub records_returned: u32,
    pub records_dropped: u32,
    pub degraded_reason: Option<String>,
    pub provenance_ref: String,
    pub redaction_status: RedactionStatus,
}

impl BoundedProviderResult {
    pub fn validate(&self) -> Result<(), ProviderAdapterContractError> {
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        validate_safe_text("provenance_ref", &self.provenance_ref)?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(ProviderAdapterContractError::RedactionRequired);
        }
        Ok(())
    }
}

pub trait ProviderProbe {
    fn adapter_metadata(&self) -> ProviderAdapterMetadata;
}

pub trait NetworkMetadataAdapter: ProviderProbe {
    type Request;
    type Result;
    type Error;

    fn read_bounded(&self, request: Self::Request) -> Result<Self::Result, Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderAdapterContractError {
    EmptyField(&'static str),
    TooLong(&'static str),
    UnsafeField(&'static str),
    TooManyItems(&'static str),
    BoundsRequired(&'static str),
    RuntimeOwnershipForbidden,
    RedactionRequired,
}

impl std::fmt::Display for ProviderAdapterContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::TooLong(field) => write!(f, "{field} exceeds bounded adapter text length"),
            Self::UnsafeField(field) => write!(f, "{field} contains unsafe adapter metadata"),
            Self::TooManyItems(field) => write!(f, "{field} contains too many adapter items"),
            Self::BoundsRequired(field) => write!(f, "{field} must be bounded"),
            Self::RuntimeOwnershipForbidden => {
                write!(f, "provider adapters must not own runtime state")
            }
            Self::RedactionRequired => write!(f, "provider adapter metadata must be redacted"),
        }
    }
}

impl std::error::Error for ProviderAdapterContractError {}

fn validate_safe_text_list(
    field: &'static str,
    values: &[String],
) -> Result<(), ProviderAdapterContractError> {
    if values.len() > MAX_PROVIDER_ADAPTER_ITEMS {
        return Err(ProviderAdapterContractError::TooManyItems(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ProviderAdapterContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(
    field: &'static str,
    value: &str,
) -> Result<(), ProviderAdapterContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ProviderAdapterContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_PROVIDER_ADAPTER_TEXT_LEN {
        return Err(ProviderAdapterContractError::TooLong(field));
    }
    let normalized = trimmed.to_ascii_lowercase();
    for marker in [
        "pid",
        "ppid",
        "process_name",
        "process_id",
        "raw_address",
        "ip_address",
        "port:",
        "path:",
        "c:\\",
        "\\users\\",
        "/users/",
        "/home/",
        "packet_data",
        "packet_bytes",
        "payload",
        "provider_handle",
        "credential",
        "secret",
        "token",
        "password",
        "api_key",
        "http://",
        "https://",
    ] {
        if normalized.contains(marker) {
            return Err(ProviderAdapterContractError::UnsafeField(field));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_adapter_ownership_rejects_runtime_owner_flags() {
        let mut ownership = ProviderAdapterOwnership::infrastructure_adapter();
        assert!(ownership.validate().is_ok());

        ownership.owns_event_bus = true;
        assert_eq!(
            ownership.validate(),
            Err(ProviderAdapterContractError::RuntimeOwnershipForbidden)
        );
    }

    #[test]
    fn provider_adapter_contract_rejects_raw_markers() {
        let metadata = ProviderAdapterMetadata {
            adapter_id: "ip_helper_adapter".to_string(),
            provider_kind: NetworkProviderKind::IpHelper,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            ownership: ProviderAdapterOwnership::infrastructure_adapter(),
            supported_request_refs: vec!["bounded_snapshot_request".to_string()],
            supported_result_refs: vec!["category_summary_result".to_string()],
            privacy_notes: vec!["raw_address must not appear".to_string()],
            redaction_status: RedactionStatus::Redacted,
        };

        assert_eq!(
            metadata.validate(),
            Err(ProviderAdapterContractError::UnsafeField("privacy_notes"))
        );
    }

    #[test]
    fn provider_adapter_request_and_result_are_bounded() {
        let request = BoundedProviderRequest {
            provider_kind: NetworkProviderKind::IpHelper,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            max_records: 1_024,
            max_bytes: 64 * 1024,
            timeout_ms: 250,
            cancellation_ref: Some("cancel_ref".to_string()),
            provenance_ref: "provider_adapter_test".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        assert!(request.validate().is_ok());

        let mut unbounded = request.clone();
        unbounded.max_records = usize::MAX;
        assert_eq!(
            unbounded.validate(),
            Err(ProviderAdapterContractError::BoundsRequired("max_records"))
        );

        let result = BoundedProviderResult {
            provider_kind: NetworkProviderKind::IpHelper,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            records_observed: 4,
            records_returned: 2,
            records_dropped: 2,
            degraded_reason: Some("category_limit_reached".to_string()),
            provenance_ref: "provider_adapter_test".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        assert!(result.validate().is_ok());
    }
}
