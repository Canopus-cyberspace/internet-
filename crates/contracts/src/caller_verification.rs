use crate::{RedactionStatus, SchemaVersion};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const CALLER_VERIFICATION_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_CALLER_VERIFICATION_REFS: usize = 16;
pub const MAX_CALLER_VERIFICATION_TEXT_LEN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerVerificationState {
    VerifiedInteractiveUser,
    VerifiedServiceIdentity,
    AdministratorPolicyVerified,
    CallerNotAuthorized,
    CallerIdentityUnavailable,
    RemoteCallerRejected,
    NetworkLogonRejected,
    TokenTypeRejected,
    ImpersonationFailed,
    TokenQueryFailed,
    SessionMismatch,
    UnsupportedPlatform,
    ForegroundDevelopment,
}

impl CallerVerificationState {
    pub fn permits_read_only_commands(self) -> bool {
        matches!(
            self,
            Self::VerifiedInteractiveUser
                | Self::VerifiedServiceIdentity
                | Self::AdministratorPolicyVerified
                | Self::ForegroundDevelopment
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerCategory {
    InteractiveUser,
    ExpectedServiceIdentity,
    AdministratorPolicy,
    ForegroundDevelopment,
    Unauthorized,
    Unavailable,
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalRemoteClassification {
    Local,
    RemoteRejected,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenSuitabilityCategory {
    ImpersonationSuitable,
    IdentificationOnlyRejected,
    UnsupportedTokenType,
    TokenUnavailable,
    QueryFailed,
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElevationCategory {
    Elevated,
    Standard,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionBindingState {
    Bound,
    Failed,
    Mismatch,
    Expired,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFreshnessBucket {
    CurrentConnection,
    Expired,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowedCommandClass {
    ReadStatus,
    ReadCanonicalModels,
    MutationAuthorizationEvaluation,
    ForegroundTestControl,
    FutureUserMutationCandidate,
    FutureAdminMutationCandidate,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerVerificationImplementationState {
    Implemented,
    NotImplemented,
    UnsupportedPlatform,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerVerificationSummary {
    pub schema_version: SchemaVersion,
    pub verification_ref: String,
    pub caller_category: CallerCategory,
    pub verification_state: CallerVerificationState,
    pub local_classification: LocalRemoteClassification,
    pub interactive_marker: bool,
    pub service_marker: bool,
    pub administrator_policy_marker: bool,
    pub token_suitability: TokenSuitabilityCategory,
    pub elevation_category: ElevationCategory,
    pub session_binding_state: SessionBindingState,
    pub freshness_bucket: VerificationFreshnessBucket,
    pub allowed_command_classes: Vec<AllowedCommandClass>,
    pub degraded_reason: Option<String>,
    pub audit_refs: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub production_mutations_enabled: bool,
}

impl CallerVerificationSummary {
    pub fn permits_read_only_commands(&self) -> bool {
        self.permits_command_class(AllowedCommandClass::ReadStatus)
    }

    pub fn permits_command_class(&self, command_class: AllowedCommandClass) -> bool {
        self.verification_state.permits_read_only_commands()
            && self.local_classification == LocalRemoteClassification::Local
            && self.session_binding_state == SessionBindingState::Bound
            && self.freshness_bucket == VerificationFreshnessBucket::CurrentConnection
            && self.allowed_command_classes.contains(&command_class)
            && !self.production_mutations_enabled
    }

    pub fn validate(&self) -> Result<(), CallerVerificationContractError> {
        if self.schema_version != CALLER_VERIFICATION_SCHEMA_VERSION {
            return Err(CallerVerificationContractError::UnsupportedSchemaVersion);
        }
        validate_safe_text("verification_ref", &self.verification_ref)?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        validate_refs("audit_refs", &self.audit_refs)?;
        validate_safe_text("provenance_id", &self.provenance_id)?;
        if self.allowed_command_classes.is_empty()
            || self.allowed_command_classes.len() > MAX_CALLER_VERIFICATION_REFS
        {
            return Err(CallerVerificationContractError::TooManyItems(
                "allowed_command_classes",
            ));
        }
        if self.production_mutations_enabled {
            return Err(CallerVerificationContractError::ProductionMutationForbidden);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(CallerVerificationContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerVerificationReadStatus {
    pub schema_version: SchemaVersion,
    pub caller_impersonation: CallerVerificationImplementationState,
    pub token_classification: CallerVerificationImplementationState,
    pub production_mutation_authorization: CallerVerificationImplementationState,
    pub production_mutations_enabled: bool,
    pub production_service_mode_policy: String,
    pub foreground_development_policy: String,
    pub remote_caller_rejection_enabled: bool,
    pub network_logon_rejection_enabled: bool,
    pub session_binding_enabled: bool,
    pub last_verification: Option<CallerVerificationSummary>,
    pub audit_refs: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl CallerVerificationReadStatus {
    pub fn validate(&self) -> Result<(), CallerVerificationContractError> {
        if self.schema_version != CALLER_VERIFICATION_SCHEMA_VERSION {
            return Err(CallerVerificationContractError::UnsupportedSchemaVersion);
        }
        if self.production_mutations_enabled
            || self.production_mutation_authorization
                == CallerVerificationImplementationState::Implemented
        {
            return Err(CallerVerificationContractError::ProductionMutationForbidden);
        }
        validate_safe_text(
            "production_service_mode_policy",
            &self.production_service_mode_policy,
        )?;
        validate_safe_text(
            "foreground_development_policy",
            &self.foreground_development_policy,
        )?;
        if let Some(summary) = &self.last_verification {
            summary.validate()?;
        }
        validate_refs("audit_refs", &self.audit_refs)?;
        validate_safe_text("provenance_id", &self.provenance_id)?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(CallerVerificationContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallerVerificationContractError {
    EmptyField(&'static str),
    TooLong(&'static str),
    UnsafeField(&'static str),
    TooManyItems(&'static str),
    UnsupportedSchemaVersion,
    ProductionMutationForbidden,
    RedactionRequired,
}

impl fmt::Display for CallerVerificationContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::TooLong(field) => write!(f, "{field} exceeds the bounded text limit"),
            Self::UnsafeField(field) => write!(f, "{field} contains unsafe identity metadata"),
            Self::TooManyItems(field) => write!(f, "{field} contains too many items"),
            Self::UnsupportedSchemaVersion => {
                write!(f, "caller verification schema version is unsupported")
            }
            Self::ProductionMutationForbidden => {
                write!(f, "caller verification cannot enable production mutations")
            }
            Self::RedactionRequired => write!(f, "caller verification status must be redacted"),
        }
    }
}

impl std::error::Error for CallerVerificationContractError {}

fn validate_refs(
    field: &'static str,
    values: &[String],
) -> Result<(), CallerVerificationContractError> {
    if values.len() > MAX_CALLER_VERIFICATION_REFS {
        return Err(CallerVerificationContractError::TooManyItems(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), CallerVerificationContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(
    field: &'static str,
    value: &str,
) -> Result<(), CallerVerificationContractError> {
    if value.trim().is_empty() {
        return Err(CallerVerificationContractError::EmptyField(field));
    }
    if value.len() > MAX_CALLER_VERIFICATION_TEXT_LEN {
        return Err(CallerVerificationContractError::TooLong(field));
    }
    let lowered = value.to_ascii_lowercase();
    for marker in [
        "s-1-",
        "username",
        "account_name",
        "token_handle",
        "token_group",
        "logon_session_identifier",
        "machine_name",
        "process_id",
        "thread_id",
        "raw_access_mask",
        "authentication_package",
        "session_nonce",
        "credential",
        "password",
        "secret",
    ] {
        if lowered.contains(marker) {
            return Err(CallerVerificationContractError::UnsafeField(field));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> CallerVerificationSummary {
        CallerVerificationSummary {
            schema_version: CALLER_VERIFICATION_SCHEMA_VERSION,
            verification_ref: "caller_verification_ref".to_string(),
            caller_category: CallerCategory::InteractiveUser,
            verification_state: CallerVerificationState::VerifiedInteractiveUser,
            local_classification: LocalRemoteClassification::Local,
            interactive_marker: true,
            service_marker: false,
            administrator_policy_marker: false,
            token_suitability: TokenSuitabilityCategory::ImpersonationSuitable,
            elevation_category: ElevationCategory::Standard,
            session_binding_state: SessionBindingState::Bound,
            freshness_bucket: VerificationFreshnessBucket::CurrentConnection,
            allowed_command_classes: vec![
                AllowedCommandClass::ReadStatus,
                AllowedCommandClass::ReadCanonicalModels,
                AllowedCommandClass::MutationAuthorizationEvaluation,
                AllowedCommandClass::FutureUserMutationCandidate,
            ],
            degraded_reason: None,
            audit_refs: vec!["caller_token_classified_audit".to_string()],
            provenance_id: "windows_named_pipe_impersonation".to_string(),
            redaction_status: RedactionStatus::Redacted,
            production_mutations_enabled: false,
        }
    }

    #[test]
    fn caller_verification_summary_is_bounded_and_read_only() {
        let summary = summary();
        summary.validate().expect("valid summary");
        assert!(summary.permits_read_only_commands());
        assert!(!summary.production_mutations_enabled);
    }

    #[test]
    fn caller_verification_rejects_raw_identity_metadata() {
        let mut summary = summary();
        summary.degraded_reason = Some("username_example".to_string());
        assert!(matches!(
            summary.validate(),
            Err(CallerVerificationContractError::UnsafeField(
                "degraded_reason"
            ))
        ));
    }

    #[test]
    fn caller_verification_serialization_has_no_raw_identity_fields() {
        let serialized = serde_json::to_string(&summary()).expect("serialize");
        for forbidden in [
            "sid",
            "username",
            "account_name",
            "token_handle",
            "token_group",
            "session_nonce",
            "process_id",
            "thread_id",
            "credential",
            "secret",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(forbidden),
                "serialized summary leaked {forbidden}"
            );
        }
    }
}
