use crate::event_bus::{PriorityLane, TopicName, AUDIT_EVENT};
use crate::observability::diagnostics::{
    require_privacy_safe_text, validate_privacy_safe_text, DiagnosticsValidationError, TraceLink,
};
use sentinel_contracts::{
    report::ExportFormat, AuditId, PrivacyClass, RedactionSummary, SchemaVersion, Timestamp,
    TraceId,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const AUDIT_EVENT_TYPE: &str = "platform.audit.event";

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    Settings,
    Capture,
    Export,
    Report,
    Response,
    Rollback,
    Service,
    PluginLifecycle,
    SecurityCase,
    Migration,
    PrivacyViolation,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum AuditActionType {
    SettingsChanged,
    CaptureStarted,
    CaptureStopped,
    ExportRequested,
    ExportCompleted,
    ExportFailed,
    ResponsePlanCreated,
    ResponsePolicyDecision,
    ResponseApprovalRequested,
    ResponseApprovalApproved,
    ResponseApprovalRejected,
    ResponseActionStarted,
    ResponseActionCompleted,
    ResponseActionFailed,
    ResponseRollbackStarted,
    ResponseRollbackCompleted,
    ResponseRollbackFailed,
    ServiceCommandRequested,
    ServiceCommandCompleted,
    ServiceCommandFailed,
    PluginLifecycleChanged,
    MigrationApplied,
    PrivacyViolation,
    ForensicModeEnabled,
    ForensicModeDisabled,
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allowed,
    Denied,
    NeedsApproval,
    Completed,
    Failed,
    RolledBack,
    NotApplicable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportAuditMetadata {
    pub format: ExportFormat,
    pub destination_metadata_redacted: Option<String>,
    pub file_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub audit_id: AuditId,
    pub category: AuditCategory,
    pub action_type: AuditActionType,
    pub timestamp: Timestamp,
    pub actor_redacted: String,
    pub target_redacted: String,
    pub decision: AuditDecision,
    pub policy_version: Option<String>,
    pub trace_id: Option<TraceId>,
    pub trace_link: Option<TraceLink>,
    pub result_redacted: String,
    pub rollback_ref: Option<String>,
    pub sensitive_data_touched: bool,
    pub reason_codes: Vec<String>,
    pub redaction_summary: Option<RedactionSummary>,
    pub export_metadata: Option<ExportAuditMetadata>,
    pub privacy_class: PrivacyClass,
    pub schema_version: SchemaVersion,
}

impl AuditEvent {
    pub fn new(
        category: AuditCategory,
        action_type: AuditActionType,
        actor_redacted: impl Into<String>,
        target_redacted: impl Into<String>,
        decision: AuditDecision,
        result_redacted: impl Into<String>,
    ) -> Result<Self, AuditValidationError> {
        Ok(Self {
            audit_id: AuditId::new_v4(),
            category,
            action_type,
            timestamp: Timestamp::now(),
            actor_redacted: require_audit_text("actor_redacted", actor_redacted)?,
            target_redacted: require_audit_text("target_redacted", target_redacted)?,
            decision,
            policy_version: None,
            trace_id: None,
            trace_link: None,
            result_redacted: require_audit_text("result_redacted", result_redacted)?,
            rollback_ref: None,
            sensitive_data_touched: false,
            reason_codes: Vec::new(),
            redaction_summary: None,
            export_metadata: None,
            privacy_class: PrivacyClass::Internal,
            schema_version: SchemaVersion::new(1, 0, 0),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn response_event(
        action_type: AuditActionType,
        actor_redacted: impl Into<String>,
        target_redacted: impl Into<String>,
        decision: AuditDecision,
        policy_version: impl Into<String>,
        trace_id: TraceId,
        result_redacted: impl Into<String>,
        rollback_ref: impl Into<String>,
        sensitive_data_touched: bool,
    ) -> Result<Self, AuditValidationError> {
        let category = if matches!(
            action_type,
            AuditActionType::ResponseRollbackStarted
                | AuditActionType::ResponseRollbackCompleted
                | AuditActionType::ResponseRollbackFailed
        ) {
            AuditCategory::Rollback
        } else {
            AuditCategory::Response
        };

        let mut event = Self::new(
            category,
            action_type,
            actor_redacted,
            target_redacted,
            decision,
            result_redacted,
        )?;
        event.policy_version = Some(require_audit_text("policy_version", policy_version)?);
        event.trace_id = Some(trace_id);
        event.rollback_ref = Some(require_audit_text("rollback_ref", rollback_ref)?);
        event.sensitive_data_touched = sensitive_data_touched;
        event.validate()?;
        Ok(event)
    }

    pub fn export_event(
        action_type: AuditActionType,
        actor_redacted: impl Into<String>,
        target_redacted: impl Into<String>,
        decision: AuditDecision,
        result_redacted: impl Into<String>,
        redaction_summary: RedactionSummary,
        export_metadata: ExportAuditMetadata,
    ) -> Result<Self, AuditValidationError> {
        let mut event = Self::new(
            AuditCategory::Export,
            action_type,
            actor_redacted,
            target_redacted,
            decision,
            result_redacted,
        )?;
        event.redaction_summary = Some(redaction_summary);
        event.export_metadata = Some(export_metadata);
        event.sensitive_data_touched = true;
        event.validate()?;
        Ok(event)
    }

    pub fn topic_name() -> TopicName {
        TopicName::new(AUDIT_EVENT).expect("audit event topic is valid")
    }

    pub fn event_type() -> &'static str {
        AUDIT_EVENT_TYPE
    }

    pub fn priority_lane(&self) -> PriorityLane {
        PriorityLane::P0Critical
    }

    pub fn can_drop_under_pressure(&self) -> bool {
        false
    }

    pub fn validate(&self) -> Result<(), AuditValidationError> {
        validate_audit_text("actor_redacted", &self.actor_redacted)?;
        validate_audit_text("target_redacted", &self.target_redacted)?;
        validate_audit_text("result_redacted", &self.result_redacted)?;

        if let Some(policy_version) = &self.policy_version {
            validate_audit_text("policy_version", policy_version)?;
        }
        if let Some(rollback_ref) = &self.rollback_ref {
            validate_audit_text("rollback_ref", rollback_ref)?;
        }
        for reason in &self.reason_codes {
            validate_audit_text("reason_codes", reason)?;
        }
        if let Some(metadata) = &self.export_metadata {
            if let Some(destination) = &metadata.destination_metadata_redacted {
                validate_audit_text("destination_metadata_redacted", destination)?;
            }
        }

        if matches!(
            self.category,
            AuditCategory::Response | AuditCategory::Rollback
        ) {
            if self.policy_version.is_none() {
                return Err(AuditValidationError::MissingResponseField("policy_version"));
            }
            if self.trace_id.is_none() {
                return Err(AuditValidationError::MissingResponseField("trace_id"));
            }
            if self.rollback_ref.is_none() {
                return Err(AuditValidationError::MissingResponseField("rollback_ref"));
            }
        }

        if matches!(self.category, AuditCategory::Export) {
            if self.redaction_summary.is_none() {
                return Err(AuditValidationError::MissingExportField(
                    "redaction_summary",
                ));
            }
            if self.export_metadata.is_none() {
                return Err(AuditValidationError::MissingExportField("export_metadata"));
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReceipt {
    pub audit_id: AuditId,
    pub sequence: u64,
    pub appended_at: Timestamp,
}

pub trait AuditSink {
    fn append(&mut self, event: AuditEvent) -> Result<AuditReceipt, AuditSinkError>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryAuditSink {
    records: Vec<AuditEvent>,
    available: bool,
    next_sequence: u64,
}

impl InMemoryAuditSink {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            available: true,
            next_sequence: 1,
        }
    }

    pub fn unavailable() -> Self {
        Self {
            records: Vec::new(),
            available: false,
            next_sequence: 1,
        }
    }

    pub fn records(&self) -> &[AuditEvent] {
        &self.records
    }
}

impl AuditSink for InMemoryAuditSink {
    fn append(&mut self, event: AuditEvent) -> Result<AuditReceipt, AuditSinkError> {
        if !self.available {
            return Err(AuditSinkError::Unavailable {
                action_type: event.action_type,
            });
        }

        event.validate()?;
        let receipt = AuditReceipt {
            audit_id: event.audit_id.clone(),
            sequence: self.next_sequence,
            appended_at: Timestamp::now(),
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.records.push(event);
        Ok(receipt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditValidationError {
    Diagnostics(DiagnosticsValidationError),
    MissingResponseField(&'static str),
    MissingExportField(&'static str),
}

impl fmt::Display for AuditValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Diagnostics(error) => write!(f, "{error}"),
            Self::MissingResponseField(field) => {
                write!(f, "response audit event is missing required field: {field}")
            }
            Self::MissingExportField(field) => {
                write!(f, "export audit event is missing required field: {field}")
            }
        }
    }
}

impl std::error::Error for AuditValidationError {}

impl From<DiagnosticsValidationError> for AuditValidationError {
    fn from(value: DiagnosticsValidationError) -> Self {
        Self::Diagnostics(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditSinkError {
    Unavailable { action_type: AuditActionType },
    Validation(AuditValidationError),
}

impl fmt::Display for AuditSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { action_type } => {
                write!(f, "audit sink unavailable for action: {action_type:?}")
            }
            Self::Validation(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuditSinkError {}

impl From<AuditValidationError> for AuditSinkError {
    fn from(value: AuditValidationError) -> Self {
        Self::Validation(value)
    }
}

fn require_audit_text(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, AuditValidationError> {
    Ok(require_privacy_safe_text(field, value)?)
}

fn validate_audit_text(field: &'static str, value: &str) -> Result<(), AuditValidationError> {
    Ok(validate_privacy_safe_text(field, value)?)
}
