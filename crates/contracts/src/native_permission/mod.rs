use crate::{AuditId, PrivacyClass, RedactionStatus, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_NATIVE_CAPABILITY_REFS: usize = 32;
pub const MAX_NATIVE_AUDIT_REFS: usize = 64;
pub const MAX_NATIVE_STATUS_EVENTS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativePermissionContractError {
    EmptyField(&'static str),
    UnsafeField(&'static str),
    BoundedFieldTooLarge(&'static str),
    UnsafeControlPlaneState(&'static str),
}

impl fmt::Display for NativePermissionContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains an unsafe marker"),
            Self::BoundedFieldTooLarge(field) => {
                write!(formatter, "{field} exceeds its bounded limit")
            }
            Self::UnsafeControlPlaneState(field) => {
                write!(
                    formatter,
                    "{field} is not allowed in the native control plane"
                )
            }
        }
    }
}

impl std::error::Error for NativePermissionContractError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizedNativeCapabilityCategory {
    NativeHostVisibility,
    ProcessMetadataVisibility,
    ProcessNetworkAttributionVisibility,
    ServiceMetadataVisibility,
    AutorunPersistenceVisibility,
    FileActivitySummaryVisibility,
    RegistrySummaryVisibility,
    EndpointNetworkAttributionVisibility,
    NativeHealthProbe,
    NativeResponseCapabilityPlaceholder,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCapabilityLifecycleState {
    Unavailable,
    Available,
    PermissionRequired,
    Requested,
    Granted,
    Denied,
    Revoked,
    Expired,
    Degraded,
    Disabled,
    NotSupported,
    PortableDefaultUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCapabilityAvailabilityState {
    ServiceUnavailable,
    AvailableUnauthorized,
    AuthorizedSamplerInactive,
    Degraded,
    Revoked,
    UnsupportedPlatform,
    MissingServiceBinary,
    HealthUnknown,
    PermissionExpired,
    PortableDefaultActive,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePermissionState {
    NotGranted,
    Requested,
    GrantedSession,
    Denied,
    Revoked,
    Expired,
    Disabled,
    NotSupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAuthorizationMode {
    None,
    ExplicitSessionBound,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCapabilityAccessMode {
    ReadOnlyVisibility,
    ResponseCapabilityPlaceholder,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCapabilityHealthState {
    Healthy,
    Unknown,
    Degraded,
    Unavailable,
    Revoked,
    NotSupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeVisibilityScopeCategory {
    HostSummary,
    ProcessSummary,
    ProcessNetworkSummary,
    ServiceSummary,
    PersistenceSummary,
    FileActivitySummary,
    RegistryActivitySummary,
    EndpointNetworkSummary,
    HealthStatusOnly,
    ResponsePlaceholderOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeCapabilityPrerequisites {
    pub native_service_required: bool,
    pub explicit_authorization_required: bool,
    pub read_only_mode_required: bool,
    pub separate_response_policy_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedNativeCapabilityStatus {
    pub capability_id: String,
    pub category: AuthorizedNativeCapabilityCategory,
    pub lifecycle_state: NativeCapabilityLifecycleState,
    pub availability_state: NativeCapabilityAvailabilityState,
    pub permission_state: NativePermissionState,
    pub authorization_mode: NativeAuthorizationMode,
    pub access_mode: NativeCapabilityAccessMode,
    pub enabled: bool,
    pub revoked: bool,
    pub health_state: NativeCapabilityHealthState,
    pub degraded_reason: Option<String>,
    pub prerequisites: NativeCapabilityPrerequisites,
    pub visibility_scope: NativeVisibilityScopeCategory,
    pub portable_default_available: bool,
    pub last_checked_time_bucket: Option<String>,
    pub provenance_id: String,
    pub audit_refs: Vec<AuditId>,
    pub redaction_status: RedactionStatus,
    pub privacy_class: PrivacyClass,
    pub telemetry_collection_active: bool,
    pub response_execution_allowed: bool,
    pub automatic_llm_calls: bool,
}

impl AuthorizedNativeCapabilityStatus {
    pub fn validate(&self) -> Result<(), NativePermissionContractError> {
        validate_safe_text("native capability id", &self.capability_id)?;
        validate_safe_text("native capability provenance id", &self.provenance_id)?;
        validate_optional_safe_text(
            "native capability degraded reason",
            self.degraded_reason.as_deref(),
        )?;
        validate_optional_safe_text(
            "native capability checked bucket",
            self.last_checked_time_bucket.as_deref(),
        )?;
        if self.audit_refs.len() > MAX_NATIVE_AUDIT_REFS {
            return Err(NativePermissionContractError::BoundedFieldTooLarge(
                "native capability audit refs",
            ));
        }
        if self.portable_default_available
            || self.telemetry_collection_active
            || self.response_execution_allowed
            || self.automatic_llm_calls
        {
            return Err(NativePermissionContractError::UnsafeControlPlaneState(
                "native capability runtime flags",
            ));
        }
        if self.access_mode == NativeCapabilityAccessMode::ResponseCapabilityPlaceholder
            && self.permission_state == NativePermissionState::GrantedSession
        {
            return Err(NativePermissionContractError::UnsafeControlPlaneState(
                "native response placeholder grant",
            ));
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(NativePermissionContractError::UnsafeControlPlaneState(
                "native capability redaction status",
            ));
        }
        Ok(())
    }

    pub fn sampler_policy_allows_collection(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePermissionAction {
    RequestAuthorization,
    GrantAuthorization,
    RevokeAuthorization,
    DisableCapability,
    RecheckStatus,
    ClearInactiveState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativePermissionActionRequest {
    pub capability_id: String,
    pub action: NativePermissionAction,
    pub explicit_user_action: bool,
    pub reason_redacted: String,
}

impl NativePermissionActionRequest {
    pub fn validate(&self) -> Result<(), NativePermissionContractError> {
        validate_safe_text("native permission capability id", &self.capability_id)?;
        validate_safe_text("native permission reason", &self.reason_redacted)?;
        if self.action == NativePermissionAction::GrantAuthorization && !self.explicit_user_action {
            return Err(NativePermissionContractError::UnsafeControlPlaneState(
                "native permission explicit user action",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativePermissionPreview {
    pub capability: AuthorizedNativeCapabilityStatus,
    pub requested_action: NativePermissionAction,
    pub state_change_performed: bool,
    pub telemetry_collection_started: bool,
    pub response_execution_started: bool,
    pub service_installation_started: bool,
    pub driver_loading_started: bool,
    pub automatic_llm_calls: bool,
    pub boundary_summary_redacted: String,
}

impl NativePermissionPreview {
    pub fn validate(&self) -> Result<(), NativePermissionContractError> {
        self.capability.validate()?;
        validate_safe_text(
            "native permission preview boundary",
            &self.boundary_summary_redacted,
        )?;
        if self.state_change_performed
            || self.telemetry_collection_started
            || self.response_execution_started
            || self.service_installation_started
            || self.driver_loading_started
            || self.automatic_llm_calls
        {
            return Err(NativePermissionContractError::UnsafeControlPlaneState(
                "native permission preview side effect",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativePermissionAuditEntry {
    pub audit_id: AuditId,
    pub capability_id: String,
    pub action: NativePermissionAction,
    pub resulting_state: NativeCapabilityLifecycleState,
    pub time_bucket: String,
    pub provenance_id: String,
    pub summary_redacted: String,
}

impl NativePermissionAuditEntry {
    pub fn validate(&self) -> Result<(), NativePermissionContractError> {
        validate_safe_text("native permission audit capability id", &self.capability_id)?;
        validate_safe_text("native permission audit time bucket", &self.time_bucket)?;
        validate_safe_text("native permission audit provenance id", &self.provenance_id)?;
        validate_safe_text("native permission audit summary", &self.summary_redacted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeStatusEvent {
    pub topic: String,
    pub capability_id: String,
    pub category: AuthorizedNativeCapabilityCategory,
    pub permission_state: NativePermissionState,
    pub health_state: NativeCapabilityHealthState,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub time_bucket: String,
    pub redaction_status: RedactionStatus,
}

impl NativeStatusEvent {
    pub fn validate(&self) -> Result<(), NativePermissionContractError> {
        if !matches!(
            self.topic.as_str(),
            "native.capability.status"
                | "native.permission.status"
                | "native.visibility.status"
                | "security.visibility.degraded"
                | "audit.native_permission"
        ) {
            return Err(NativePermissionContractError::UnsafeField(
                "native status event topic",
            ));
        }
        validate_safe_text("native status event capability id", &self.capability_id)?;
        validate_optional_safe_text(
            "native status event degraded reason",
            self.degraded_reason.as_deref(),
        )?;
        validate_safe_text("native status event provenance id", &self.provenance_id)?;
        validate_safe_text("native status event time bucket", &self.time_bucket)?;
        validate_safe_text_list(
            "native status event missing visibility flags",
            &self.missing_visibility_flags,
            MAX_NATIVE_CAPABILITY_REFS,
        )?;
        if self.audit_refs.len() > MAX_NATIVE_AUDIT_REFS
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativePermissionContractError::UnsafeControlPlaneState(
                "native status event refs or redaction",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativePermissionActionResult {
    pub capability: AuthorizedNativeCapabilityStatus,
    pub audit_entry: NativePermissionAuditEntry,
    pub emitted_status_events: Vec<NativeStatusEvent>,
    pub telemetry_collection_started: bool,
    pub response_execution_started: bool,
    pub service_installation_started: bool,
    pub driver_loading_started: bool,
    pub host_mutation_performed: bool,
    pub automatic_llm_calls: bool,
}

impl NativePermissionActionResult {
    pub fn validate(&self) -> Result<(), NativePermissionContractError> {
        self.capability.validate()?;
        self.audit_entry.validate()?;
        if self.emitted_status_events.len() > MAX_NATIVE_STATUS_EVENTS {
            return Err(NativePermissionContractError::BoundedFieldTooLarge(
                "native status events",
            ));
        }
        for event in &self.emitted_status_events {
            event.validate()?;
        }
        if self.telemetry_collection_started
            || self.response_execution_started
            || self.service_installation_started
            || self.driver_loading_started
            || self.host_mutation_performed
            || self.automatic_llm_calls
        {
            return Err(NativePermissionContractError::UnsafeControlPlaneState(
                "native permission action side effect",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativePermissionStatusSummary {
    pub capability_count: u32,
    pub permission_required_count: u32,
    pub requested_count: u32,
    pub granted_inactive_count: u32,
    pub revoked_count: u32,
    pub degraded_count: u32,
    pub unsupported_count: u32,
    pub portable_default_active: bool,
    pub session_bound_authorization: bool,
    pub telemetry_collection_active: bool,
    pub response_execution_allowed: bool,
    pub automatic_llm_calls: bool,
    pub capability_refs: Vec<String>,
    pub audit_refs: Vec<AuditId>,
    pub generated_at: Timestamp,
}

impl NativePermissionStatusSummary {
    pub fn validate(&self) -> Result<(), NativePermissionContractError> {
        validate_safe_text_list(
            "native permission summary capability refs",
            &self.capability_refs,
            MAX_NATIVE_CAPABILITY_REFS,
        )?;
        if self.audit_refs.len() > MAX_NATIVE_AUDIT_REFS
            || self.telemetry_collection_active
            || self.response_execution_allowed
            || self.automatic_llm_calls
            || !self.session_bound_authorization
        {
            return Err(NativePermissionContractError::UnsafeControlPlaneState(
                "native permission summary flags",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeVisibilitySummary {
    pub available_scope_categories: Vec<NativeVisibilityScopeCategory>,
    pub missing_visibility_flags: Vec<String>,
    pub degraded_reasons: Vec<String>,
    pub capability_refs: Vec<String>,
    pub audit_refs: Vec<AuditId>,
    pub granted_permission_creates_evidence: bool,
    pub native_required_attack_coverage_supported: bool,
    pub future_sampler_ready: bool,
    pub portable_default_active: bool,
    pub metadata_only: bool,
    pub generated_at: Timestamp,
}

impl NativeVisibilitySummary {
    pub fn validate(&self) -> Result<(), NativePermissionContractError> {
        validate_safe_text_list(
            "native visibility missing flags",
            &self.missing_visibility_flags,
            MAX_NATIVE_CAPABILITY_REFS,
        )?;
        validate_safe_text_list(
            "native visibility degraded reasons",
            &self.degraded_reasons,
            MAX_NATIVE_CAPABILITY_REFS,
        )?;
        validate_safe_text_list(
            "native visibility capability refs",
            &self.capability_refs,
            MAX_NATIVE_CAPABILITY_REFS,
        )?;
        if self.audit_refs.len() > MAX_NATIVE_AUDIT_REFS
            || self.granted_permission_creates_evidence
            || self.native_required_attack_coverage_supported
            || self.future_sampler_ready
            || !self.metadata_only
        {
            return Err(NativePermissionContractError::UnsafeControlPlaneState(
                "native visibility summary flags",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativePermissionAuditSummary {
    pub entries: Vec<NativePermissionAuditEntry>,
    pub audit_refs: Vec<AuditId>,
    pub revoked_capability_refs: Vec<String>,
    pub generated_at: Timestamp,
}

impl NativePermissionAuditSummary {
    pub fn validate(&self) -> Result<(), NativePermissionContractError> {
        if self.entries.len() > MAX_NATIVE_AUDIT_REFS
            || self.audit_refs.len() > MAX_NATIVE_AUDIT_REFS
        {
            return Err(NativePermissionContractError::BoundedFieldTooLarge(
                "native permission audit summary",
            ));
        }
        validate_safe_text_list(
            "native permission revoked refs",
            &self.revoked_capability_refs,
            MAX_NATIVE_CAPABILITY_REFS,
        )?;
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), NativePermissionContractError> {
    value.map_or(Ok(()), |value| validate_safe_text(field, value))
}

fn validate_safe_text_list(
    field: &'static str,
    values: &[String],
    limit: usize,
) -> Result<(), NativePermissionContractError> {
    if values.len() > limit {
        return Err(NativePermissionContractError::BoundedFieldTooLarge(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(
    field: &'static str,
    value: &str,
) -> Result<(), NativePermissionContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(NativePermissionContractError::EmptyField(field));
    }
    if trimmed.len() > 160 {
        return Err(NativePermissionContractError::BoundedFieldTooLarge(field));
    }
    let normalized = trimmed.to_ascii_lowercase();
    if [
        "c:\\",
        "/home/",
        "/users/",
        "http://",
        "https://",
        "api_key",
        "apikey",
        "authorization:",
        "bearer ",
        "cookie",
        "token",
        "secret",
        "password",
        "username",
        "email",
        "command_line",
        "registry_key",
        "filename",
        "full_path",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
    {
        return Err(NativePermissionContractError::UnsafeField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status() -> AuthorizedNativeCapabilityStatus {
        AuthorizedNativeCapabilityStatus {
            capability_id: "process_metadata_visibility".to_string(),
            category: AuthorizedNativeCapabilityCategory::ProcessMetadataVisibility,
            lifecycle_state: NativeCapabilityLifecycleState::PermissionRequired,
            availability_state: NativeCapabilityAvailabilityState::AvailableUnauthorized,
            permission_state: NativePermissionState::NotGranted,
            authorization_mode: NativeAuthorizationMode::None,
            access_mode: NativeCapabilityAccessMode::ReadOnlyVisibility,
            enabled: false,
            revoked: false,
            health_state: NativeCapabilityHealthState::Unknown,
            degraded_reason: Some("permission_required".to_string()),
            prerequisites: NativeCapabilityPrerequisites {
                native_service_required: true,
                explicit_authorization_required: true,
                read_only_mode_required: true,
                separate_response_policy_required: true,
            },
            visibility_scope: NativeVisibilityScopeCategory::ProcessSummary,
            portable_default_available: false,
            last_checked_time_bucket: Some("current_session".to_string()),
            provenance_id: "native_status_placeholder".to_string(),
            audit_refs: Vec::new(),
            redaction_status: RedactionStatus::Redacted,
            privacy_class: PrivacyClass::Internal,
            telemetry_collection_active: false,
            response_execution_allowed: false,
            automatic_llm_calls: false,
        }
    }

    #[test]
    fn settings_native_status_is_bounded_and_collection_inactive() {
        let status = status();
        status.validate().expect("safe native status");
        assert!(!status.sampler_policy_allows_collection());
        let serialized = serde_json::to_string(&status).expect("status json");
        assert!(!serialized.contains("C:\\"));
        assert!(!serialized.contains("password"));
    }

    #[test]
    fn settings_native_preview_rejects_any_side_effect() {
        let mut preview = NativePermissionPreview {
            capability: status(),
            requested_action: NativePermissionAction::GrantAuthorization,
            state_change_performed: false,
            telemetry_collection_started: false,
            response_execution_started: false,
            service_installation_started: false,
            driver_loading_started: false,
            automatic_llm_calls: false,
            boundary_summary_redacted:
                "Permission preview only; no native sampler or response is started".to_string(),
        };
        preview.validate().expect("safe preview");
        preview.telemetry_collection_started = true;
        assert!(preview.validate().is_err());
    }

    #[test]
    fn settings_native_grant_requires_explicit_user_action() {
        let request = NativePermissionActionRequest {
            capability_id: "native_host_visibility".to_string(),
            action: NativePermissionAction::GrantAuthorization,
            explicit_user_action: false,
            reason_redacted: "authorize read only visibility".to_string(),
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn settings_native_events_accept_declared_status_topics_only() {
        let mut event = NativeStatusEvent {
            topic: "native.permission.status".to_string(),
            capability_id: "native_host_visibility".to_string(),
            category: AuthorizedNativeCapabilityCategory::NativeHostVisibility,
            permission_state: NativePermissionState::Requested,
            health_state: NativeCapabilityHealthState::Unknown,
            degraded_reason: Some("permission_required".to_string()),
            missing_visibility_flags: vec!["native_host_visibility_missing".to_string()],
            audit_refs: Vec::new(),
            provenance_id: "native_status_placeholder".to_string(),
            time_bucket: "current_session".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        event.validate().expect("declared status topic");
        event.topic = "security.finding".to_string();
        assert!(event.validate().is_err());
    }
}
