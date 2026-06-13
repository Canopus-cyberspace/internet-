use crate::common::{SchemaVersion, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

pub const SERVICE_METADATA_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceMetadataContractError {
    EmptyField(&'static str),
    TooLong {
        field: &'static str,
        max_len: usize,
        actual_len: usize,
    },
    InvalidField(&'static str),
    PrivacyMarker {
        field: &'static str,
    },
    MissingLimitationFlags,
    DuplicateLimitationFlags,
    UnsupportedSchemaVersion,
}

impl fmt::Display for ServiceMetadataContractError {
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
            Self::InvalidField(field) => write!(f, "{field} contains unsupported characters"),
            Self::PrivacyMarker { field } => {
                write!(f, "{field} contains a forbidden private-content marker")
            }
            Self::MissingLimitationFlags => {
                write!(
                    f,
                    "service capability metadata must include limitation flags"
                )
            }
            Self::DuplicateLimitationFlags => {
                write!(
                    f,
                    "service capability metadata must not repeat limitation flags"
                )
            }
            Self::UnsupportedSchemaVersion => {
                write!(
                    f,
                    "service capability metadata schema version is unsupported"
                )
            }
        }
    }
}

impl std::error::Error for ServiceMetadataContractError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceCapabilityStatus {
    Available,
    Degraded,
    Unavailable,
    Disconnected,
    Disabled,
    Unauthorized,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAdapterMode {
    StubOnly,
    MetadataOnly,
    ReadOnly,
    Disabled,
    Disconnected,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceReasonCode {
    StubOnlyMode,
    ServiceUnavailable,
    IpcDisconnected,
    CaptureUnavailable,
    ProcessAttributionLimited,
    ResponseExecutionDisabled,
    AutoContainmentDisabled,
    ReducedVisibility,
    ReadOnlyAllowlist,
    AdapterInactive,
    PermissionDenied,
    ProtocolError,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceLimitationFlag {
    LocalOnly,
    StubOnly,
    MetadataOnly,
    ReadOnlyAllowlist,
    ReducedVisibility,
    NoRawContentRetention,
    NoPrivilegedCapture,
    NoProcessAttribution,
    NoResponseExecution,
    NoOsAction,
    ControlPlaneOwnedByLocalCore,
    NoProductionServiceLifecycle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCapabilityContext {
    pub capability_id: String,
    pub adapter_mode: ServiceAdapterMode,
    pub status: ServiceCapabilityStatus,
    pub reason_code: Option<ServiceReasonCode>,
    pub limitation_flags: Vec<ServiceLimitationFlag>,
    pub observed_at: Timestamp,
    pub source_provenance_id: String,
    pub schema_version: SchemaVersion,
}

impl ServiceCapabilityContext {
    pub fn new(
        capability_id: impl Into<String>,
        adapter_mode: ServiceAdapterMode,
        status: ServiceCapabilityStatus,
        source_provenance_id: impl Into<String>,
    ) -> Result<Self, ServiceMetadataContractError> {
        let context = Self {
            capability_id: capability_id.into(),
            adapter_mode,
            status,
            reason_code: None,
            limitation_flags: Vec::new(),
            observed_at: Timestamp::now(),
            source_provenance_id: source_provenance_id.into(),
            schema_version: SERVICE_METADATA_SCHEMA_VERSION,
        };
        validate_safe_identifier("capability_id", &context.capability_id)?;
        validate_safe_identifier("source_provenance_id", &context.source_provenance_id)?;
        Ok(context)
    }

    pub fn with_reason_code(mut self, reason_code: ServiceReasonCode) -> Self {
        self.reason_code = Some(reason_code);
        self
    }

    pub fn with_limitation_flags(mut self, limitation_flags: Vec<ServiceLimitationFlag>) -> Self {
        self.limitation_flags = limitation_flags;
        self
    }

    pub fn with_observed_at(mut self, observed_at: Timestamp) -> Self {
        self.observed_at = observed_at;
        self
    }

    pub fn validate_boundary(&self) -> Result<(), ServiceMetadataContractError> {
        if self.schema_version != SERVICE_METADATA_SCHEMA_VERSION {
            return Err(ServiceMetadataContractError::UnsupportedSchemaVersion);
        }
        validate_safe_identifier("capability_id", &self.capability_id)?;
        validate_safe_identifier("source_provenance_id", &self.source_provenance_id)?;
        if self.limitation_flags.is_empty() {
            return Err(ServiceMetadataContractError::MissingLimitationFlags);
        }
        let unique_flags = self
            .limitation_flags
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        if unique_flags.len() != self.limitation_flags.len() {
            return Err(ServiceMetadataContractError::DuplicateLimitationFlags);
        }
        Ok(())
    }
}

fn validate_safe_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), ServiceMetadataContractError> {
    const MAX_LEN: usize = 96;

    if value.trim().is_empty() {
        return Err(ServiceMetadataContractError::EmptyField(field));
    }
    if value.len() > MAX_LEN {
        return Err(ServiceMetadataContractError::TooLong {
            field,
            max_len: MAX_LEN,
            actual_len: value.len(),
        });
    }
    if !value.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '_' | '-' | '.')
    }) {
        return Err(ServiceMetadataContractError::InvalidField(field));
    }

    let normalized = value.to_ascii_lowercase();
    for marker in [
        "raw_packet",
        "packet_bytes",
        "raw_payload",
        "payload_blob",
        "http_body",
        "cookie",
        "session_token",
        "authorization",
        "api_key",
        "credential",
        "private_key",
        "password",
        "access_token",
        "bearer",
        "cmdline",
        "commandline",
        "filepath",
        "username",
        "c.users",
    ] {
        if normalized.contains(marker) {
            return Err(ServiceMetadataContractError::PrivacyMarker { field });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_capability_context_accepts_bounded_safe_metadata() {
        let context = ServiceCapabilityContext::new(
            "capture_adapter",
            ServiceAdapterMode::StubOnly,
            ServiceCapabilityStatus::Unavailable,
            "service_ipc.capture_health",
        )
        .expect("context")
        .with_reason_code(ServiceReasonCode::CaptureUnavailable)
        .with_limitation_flags(vec![
            ServiceLimitationFlag::StubOnly,
            ServiceLimitationFlag::MetadataOnly,
            ServiceLimitationFlag::NoRawContentRetention,
            ServiceLimitationFlag::NoPrivilegedCapture,
            ServiceLimitationFlag::ReducedVisibility,
        ]);

        assert!(context.validate_boundary().is_ok());
    }

    #[test]
    fn service_capability_context_rejects_private_markers() {
        let error = ServiceCapabilityContext::new(
            "capture_adapter",
            ServiceAdapterMode::StubOnly,
            ServiceCapabilityStatus::Unavailable,
            "service_ipc.authorization",
        )
        .expect_err("private marker should be rejected");

        assert!(matches!(
            error,
            ServiceMetadataContractError::PrivacyMarker {
                field: "source_provenance_id"
            }
        ));
    }

    #[test]
    fn service_capability_context_requires_unique_limitation_flags() {
        let error = ServiceCapabilityContext::new(
            "service_boundary",
            ServiceAdapterMode::ReadOnly,
            ServiceCapabilityStatus::Disconnected,
            "service_ipc.status",
        )
        .expect("context")
        .with_limitation_flags(vec![
            ServiceLimitationFlag::StubOnly,
            ServiceLimitationFlag::StubOnly,
        ])
        .validate_boundary()
        .expect_err("duplicate flags should fail");

        assert_eq!(
            error,
            ServiceMetadataContractError::DuplicateLimitationFlags
        );
    }
}
