use crate::observability::health::{HealthStatus, HealthSubject};
use sentinel_contracts::{
    CausalityId, CorrelationId, EventId, PipelineId, PrivacyClass, ReplayId, Timestamp,
    TraceContext, TraceId,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceLink {
    pub trace_id: TraceId,
    pub correlation_id: Option<CorrelationId>,
    pub causality_id: Option<CausalityId>,
    pub parent_trace_id: Option<TraceId>,
    pub source_event_id: Option<EventId>,
    pub pipeline_id: Option<PipelineId>,
    pub replay_id: Option<ReplayId>,
}

impl TraceLink {
    pub fn new(trace_id: TraceId) -> Self {
        Self {
            trace_id,
            correlation_id: None,
            causality_id: None,
            parent_trace_id: None,
            source_event_id: None,
            pipeline_id: None,
            replay_id: None,
        }
    }

    pub fn from_context(context: TraceContext) -> Self {
        Self {
            trace_id: context.trace_id,
            correlation_id: context.correlation_id,
            causality_id: context.causality_id,
            parent_trace_id: None,
            source_event_id: None,
            pipeline_id: context.pipeline_id,
            replay_id: context.replay_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsSummary {
    pub status: HealthStatus,
    pub summary_redacted: String,
    pub trace_links: Vec<TraceLink>,
    pub health_subjects: Vec<HealthSubject>,
    pub metric_names: Vec<String>,
    pub audit_event_count: u64,
    pub audit_failures_redacted: Vec<String>,
    pub warnings_redacted: Vec<String>,
    pub generated_at: Timestamp,
    pub privacy_class: PrivacyClass,
}

impl DiagnosticsSummary {
    pub fn new(
        status: HealthStatus,
        summary_redacted: impl Into<String>,
    ) -> Result<Self, DiagnosticsValidationError> {
        let summary_redacted = require_privacy_safe_text("summary_redacted", summary_redacted)?;

        Ok(Self {
            status,
            summary_redacted,
            trace_links: Vec::new(),
            health_subjects: Vec::new(),
            metric_names: Vec::new(),
            audit_event_count: 0,
            audit_failures_redacted: Vec::new(),
            warnings_redacted: Vec::new(),
            generated_at: Timestamp::now(),
            privacy_class: PrivacyClass::Internal,
        })
    }

    pub fn validate(&self) -> Result<(), DiagnosticsValidationError> {
        validate_privacy_safe_text("summary_redacted", &self.summary_redacted)?;

        for warning in &self.warnings_redacted {
            validate_privacy_safe_text("warnings_redacted", warning)?;
        }

        for failure in &self.audit_failures_redacted {
            validate_privacy_safe_text("audit_failures_redacted", failure)?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiagnosticsValidationError {
    EmptyField(&'static str),
    SensitiveMarker {
        field: &'static str,
        marker: &'static str,
    },
}

impl fmt::Display for DiagnosticsValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::SensitiveMarker { field, marker } => {
                write!(f, "{field} contains forbidden sensitive marker: {marker}")
            }
        }
    }
}

impl std::error::Error for DiagnosticsValidationError {}

pub(crate) fn require_non_empty(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, DiagnosticsValidationError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(DiagnosticsValidationError::EmptyField(field));
    }

    Ok(value)
}

pub(crate) fn require_privacy_safe_text(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, DiagnosticsValidationError> {
    let value = require_non_empty(field, value)?;
    validate_privacy_safe_text(field, &value)?;
    Ok(value)
}

pub(crate) fn validate_privacy_safe_text(
    field: &'static str,
    value: &str,
) -> Result<(), DiagnosticsValidationError> {
    if let Some(marker) = forbidden_sensitive_marker(value) {
        return Err(DiagnosticsValidationError::SensitiveMarker { field, marker });
    }

    Ok(())
}

pub(crate) fn forbidden_sensitive_marker(value: &str) -> Option<&'static str> {
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '/'], "_");

    SENSITIVE_MARKERS
        .iter()
        .copied()
        .find(|marker| normalized.contains(marker))
}

const SENSITIVE_MARKERS: &[&str] = &[
    "raw_packet",
    "payload",
    "http_body",
    "cookie",
    "token",
    "credential",
    "authorization",
    "api_key",
    "secret",
    "private_key",
    "password",
];
