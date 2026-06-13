use crate::common::{AuditId, TraceId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    PermissionDenied,
    ServiceUnavailable,
    SchemaMismatch,
    PrivacyPolicyViolation,
    PolicyDenial,
    ValidationFailure,
    StorageUnavailable,
    UnsupportedOperation,
    ResponseRequiresApproval,
    ResponseDeniedByPolicy,
    InvalidRequest,
    Timeout,
    RateLimited,
    InternalError,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::PermissionDenied => "permission_denied",
            Self::ServiceUnavailable => "service_unavailable",
            Self::SchemaMismatch => "schema_mismatch",
            Self::PrivacyPolicyViolation => "privacy_policy_violation",
            Self::PolicyDenial => "policy_denial",
            Self::ValidationFailure => "validation_failure",
            Self::StorageUnavailable => "storage_unavailable",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::ResponseRequiresApproval => "response_requires_approval",
            Self::ResponseDeniedByPolicy => "response_denied_by_policy",
            Self::InvalidRequest => "invalid_request",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::InternalError => "internal_error",
        };

        write!(f, "{value}")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSeverity {
    Info,
    Warning,
    #[default]
    Error,
    Critical,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        };

        write!(f, "{value}")
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CoreError {
    pub error_code: ErrorCode,
    pub message: String,
    pub severity: ErrorSeverity,
    pub retryable: bool,
    pub trace_id: Option<TraceId>,
    pub audit_ref: Option<AuditId>,
    pub details_redacted: Option<Value>,
}

impl CoreError {
    pub fn new(error_code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error_code,
            message: message.into(),
            severity: ErrorSeverity::default(),
            retryable: false,
            trace_id: None,
            audit_ref: None,
            details_redacted: None,
        }
    }

    pub fn validation_failure(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ValidationFailure, message)
    }

    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PermissionDenied, message)
    }

    pub fn with_severity(mut self, severity: ErrorSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    pub fn with_trace_id(mut self, trace_id: TraceId) -> Self {
        self.trace_id = Some(trace_id);
        self
    }

    pub fn with_audit_ref(mut self, audit_ref: AuditId) -> Self {
        self.audit_ref = Some(audit_ref);
        self
    }

    pub fn with_redacted_details(mut self, details_redacted: Value) -> Self {
        self.details_redacted = Some(details_redacted);
        self
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_code, self.message)
    }
}

impl std::error::Error for CoreError {}

pub type CommandResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn core_error_uses_redacted_details_field() {
        let error = CoreError::validation_failure("invalid filter")
            .with_redacted_details(json!({ "field": "process_name" }));
        let value = serde_json::to_value(error).expect("serialize error");

        assert_eq!(value["error_code"], "validation_failure");
        assert!(value.get("details_redacted").is_some());
        assert!(value.get("details").is_none());
    }
}
