use crate::common::{
    AlertId, ErrorCode, EvidenceId, EvidenceQualityId, ExportRequestId, ExportResultId, FindingId,
    GraphSnapshotId, IncidentId, LlmAlertStoryId, PrivacyClass, RedactionSummaryId, ReportId,
    ReportSectionId, ResponseResultId, RollbackResultId, Timestamp, TraceId,
};
use crate::evidence_quality::QualityBreakdown;
use crate::response::AuditRef;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    Markdown,
    Html,
    RedactedJson,
    Unsupported(String),
}

impl ExportFormat {
    pub fn parse(value: &str) -> Self {
        match value {
            "markdown" => Self::Markdown,
            "html" => Self::Html,
            "redacted_json" => Self::RedactedJson,
            other => Self::Unsupported(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Markdown => "markdown",
            Self::Html => "html",
            Self::RedactedJson => "redacted_json",
            Self::Unsupported(value) => value.as_str(),
        }
    }

    pub fn is_supported_v1(&self) -> bool {
        matches!(self, Self::Markdown | Self::Html | Self::RedactedJson)
    }

    pub fn deferred_reason(&self) -> Option<&'static str> {
        match self {
            Self::Unsupported(value) if value == "pdf" => {
                Some("PDF is deferred to a later renderer/export adapter")
            }
            Self::Unsupported(_) => Some("format is not supported in V1"),
            _ => None,
        }
    }
}

impl Serialize for ExportFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ExportFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::parse(&value))
    }
}

pub type ReportFormat = ExportFormat;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactedDataCategory {
    RawPacket,
    Payload,
    HttpBody,
    Cookie,
    Token,
    Credential,
    ApiKey,
    PrivateKey,
    FullQueryString,
    FormContent,
    CommandLine,
    LocalPath,
    Username,
    Sid,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedactionSummary {
    pub redaction_summary_id: RedactionSummaryId,
    pub passed: bool,
    pub redacted_categories: Vec<RedactedDataCategory>,
    pub redacted_field_count: u32,
    pub suppressed_section_count: u32,
    pub reviewer: Option<String>,
    pub completed_at: Option<Timestamp>,
    pub notes_redacted: Vec<String>,
}

impl RedactionSummary {
    pub fn passed(redacted_categories: Vec<RedactedDataCategory>) -> Self {
        Self {
            redaction_summary_id: RedactionSummaryId::new_v4(),
            passed: true,
            redacted_categories,
            redacted_field_count: 0,
            suppressed_section_count: 0,
            reviewer: None,
            completed_at: Some(Timestamp::now()),
            notes_redacted: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportType {
    Incident,
    Exposure,
    Threat,
    Behavior,
    WebSecurity,
    Deception,
    Platform,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Draft,
    RedactionRequired,
    ReadyForExport,
    Exported,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSectionType {
    ExecutiveSummary,
    Timeline,
    EvidenceTable,
    AffectedScope,
    GraphSnapshot,
    AttackCoverage,
    FusionSummary,
    BaselineSummary,
    InvestigationDrillDown,
    EvidenceQuality,
    MetadataWatch,
    NativeVisibility,
    NativeSamplerReadiness,
    NativeSamplerRuntime,
    NativeScheduler,
    LlmAlertStory,
    ResponseRecommendation,
    ResponseResult,
    RollbackStatus,
    PrivacyRedactionSummary,
    Recommendations,
    Custom,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportSection {
    pub section_id: ReportSectionId,
    pub section_type: ReportSectionType,
    pub title_redacted: String,
    pub content_redacted: Value,
    pub evidence_refs: Vec<EvidenceId>,
    pub graph_snapshot_refs: Vec<GraphSnapshotId>,
    pub response_result_refs: Vec<ResponseResultId>,
    #[serde(default)]
    pub rollback_result_refs: Vec<RollbackResultId>,
    #[serde(default)]
    pub llm_story_refs: Vec<LlmAlertStoryId>,
    #[serde(default)]
    pub quality_refs: Vec<EvidenceQualityId>,
    #[serde(default)]
    pub quality: QualityBreakdown,
    pub privacy_class: PrivacyClass,
    pub redaction_summary: RedactionSummary,
}

impl ReportSection {
    pub fn new(
        section_type: ReportSectionType,
        title_redacted: impl Into<String>,
        redaction_summary: RedactionSummary,
    ) -> Result<Self, ReportContractError> {
        Ok(Self {
            section_id: ReportSectionId::new_v4(),
            section_type,
            title_redacted: require_non_empty("title_redacted", title_redacted.into())?,
            content_redacted: Value::Object(Default::default()),
            evidence_refs: Vec::new(),
            graph_snapshot_refs: Vec::new(),
            response_result_refs: Vec::new(),
            rollback_result_refs: Vec::new(),
            llm_story_refs: Vec::new(),
            quality_refs: Vec::new(),
            quality: QualityBreakdown::metadata_only(),
            privacy_class: PrivacyClass::Internal,
            redaction_summary,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub report_id: ReportId,
    pub report_type: ReportType,
    pub title_redacted: String,
    pub summary_redacted: String,
    pub status: ReportStatus,
    pub incident_refs: Vec<IncidentId>,
    pub alert_refs: Vec<AlertId>,
    pub finding_refs: Vec<FindingId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub graph_snapshot_refs: Vec<GraphSnapshotId>,
    pub response_result_refs: Vec<ResponseResultId>,
    #[serde(default)]
    pub rollback_result_refs: Vec<RollbackResultId>,
    #[serde(default)]
    pub llm_story_refs: Vec<LlmAlertStoryId>,
    pub sections: Vec<ReportSection>,
    pub redaction_summary: RedactionSummary,
    pub audit_ref: Option<AuditRef>,
    pub privacy_class: PrivacyClass,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl Report {
    pub fn new(
        report_type: ReportType,
        title_redacted: impl Into<String>,
        summary_redacted: impl Into<String>,
        redaction_summary: RedactionSummary,
    ) -> Result<Self, ReportContractError> {
        let now = Timestamp::now();
        Ok(Self {
            report_id: ReportId::new_v4(),
            report_type,
            title_redacted: require_non_empty("title_redacted", title_redacted.into())?,
            summary_redacted: require_non_empty("summary_redacted", summary_redacted.into())?,
            status: if redaction_summary.passed {
                ReportStatus::ReadyForExport
            } else {
                ReportStatus::RedactionRequired
            },
            incident_refs: Vec::new(),
            alert_refs: Vec::new(),
            finding_refs: Vec::new(),
            evidence_refs: Vec::new(),
            graph_snapshot_refs: Vec::new(),
            response_result_refs: Vec::new(),
            rollback_result_refs: Vec::new(),
            llm_story_refs: Vec::new(),
            sections: Vec::new(),
            redaction_summary,
            audit_ref: None,
            privacy_class: PrivacyClass::Internal,
            created_at: now.clone(),
            updated_at: now,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportRequest {
    pub export_request_id: ExportRequestId,
    pub report_id: ReportId,
    pub format: ExportFormat,
    pub requested_by: String,
    pub requested_at: Timestamp,
    pub redaction_summary: RedactionSummary,
    pub audit_ref: AuditRef,
    pub user_confirmation_required: bool,
    pub export_policy_check_required: bool,
}

impl ExportRequest {
    pub fn new(
        report_id: ReportId,
        format: ExportFormat,
        requested_by: impl Into<String>,
        redaction_summary: RedactionSummary,
        audit_ref: AuditRef,
    ) -> Result<Self, ReportContractError> {
        if !format.is_supported_v1() {
            return Err(ReportContractError::UnsupportedExportFormat(
                format.as_str().to_string(),
            ));
        }

        if !redaction_summary.passed {
            return Err(ReportContractError::RedactionNotPassed);
        }

        Ok(Self {
            export_request_id: ExportRequestId::new_v4(),
            report_id,
            format,
            requested_by: require_non_empty("requested_by", requested_by.into())?,
            requested_at: Timestamp::now(),
            redaction_summary,
            audit_ref,
            user_confirmation_required: true,
            export_policy_check_required: true,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportResult {
    pub export_result_id: ExportResultId,
    pub export_request_id: ExportRequestId,
    pub report_id: ReportId,
    pub format: ExportFormat,
    pub success: bool,
    pub destination_metadata_redacted: Option<String>,
    pub file_hash: Option<String>,
    pub redaction_summary: RedactionSummary,
    pub audit_ref: AuditRef,
    pub error_code: Option<ErrorCode>,
    pub error_summary_redacted: Option<String>,
    pub completed_at: Timestamp,
    pub trace_id: Option<TraceId>,
}

impl ExportResult {
    pub fn from_request(request: ExportRequest, success: bool) -> Self {
        Self {
            export_result_id: ExportResultId::new_v4(),
            export_request_id: request.export_request_id,
            report_id: request.report_id,
            format: request.format,
            success,
            destination_metadata_redacted: None,
            file_hash: None,
            redaction_summary: request.redaction_summary,
            audit_ref: request.audit_ref,
            error_code: None,
            error_summary_redacted: None,
            completed_at: Timestamp::now(),
            trace_id: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportContractError {
    EmptyField(&'static str),
    UnsupportedExportFormat(String),
    RedactionNotPassed,
}

impl fmt::Display for ReportContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::UnsupportedExportFormat(format) => {
                write!(f, "unsupported V1 export format: {format}")
            }
            Self::RedactionNotPassed => write!(f, "report export requires passed redaction"),
        }
    }
}

impl std::error::Error for ReportContractError {}

fn require_non_empty(field: &'static str, value: String) -> Result<String, ReportContractError> {
    if value.trim().is_empty() {
        return Err(ReportContractError::EmptyField(field));
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::AuditRef;

    fn redaction_summary() -> RedactionSummary {
        RedactionSummary::passed(vec![
            RedactedDataCategory::RawPacket,
            RedactedDataCategory::Payload,
            RedactedDataCategory::HttpBody,
            RedactedDataCategory::Cookie,
            RedactedDataCategory::Token,
            RedactedDataCategory::Credential,
            RedactedDataCategory::ApiKey,
        ])
    }

    #[test]
    fn export_format_supports_v1_formats_and_defers_pdf() {
        assert!(ExportFormat::Markdown.is_supported_v1());
        assert!(ExportFormat::Html.is_supported_v1());
        assert!(ExportFormat::RedactedJson.is_supported_v1());

        let pdf = ExportFormat::parse("pdf");
        assert!(!pdf.is_supported_v1());
        assert_eq!(
            pdf.deferred_reason(),
            Some("PDF is deferred to a later renderer/export adapter")
        );
    }

    #[test]
    fn export_request_requires_passed_redaction_and_supported_format() {
        let audit = AuditRef::new("report.export.requested").expect("audit");
        let request = ExportRequest::new(
            ReportId::new_v4(),
            ExportFormat::RedactedJson,
            "local_user",
            redaction_summary(),
            audit,
        )
        .expect("export request");

        assert!(request.redaction_summary.passed);
        assert_eq!(request.format, ExportFormat::RedactedJson);
    }

    #[test]
    fn export_result_includes_redaction_summary_and_audit_ref() {
        let audit = AuditRef::new("report.export.requested").expect("audit");
        let request = ExportRequest::new(
            ReportId::new_v4(),
            ExportFormat::Markdown,
            "local_user",
            redaction_summary(),
            audit.clone(),
        )
        .expect("export request");
        let result = ExportResult::from_request(request, true);

        assert!(result.redaction_summary.passed);
        assert_eq!(result.audit_ref.audit_id, audit.audit_id);
    }

    #[test]
    fn export_request_rejects_pdf_for_v1() {
        let audit = AuditRef::new("report.export.requested").expect("audit");
        let result = ExportRequest::new(
            ReportId::new_v4(),
            ExportFormat::parse("pdf"),
            "local_user",
            redaction_summary(),
            audit,
        );

        assert_eq!(
            result,
            Err(ReportContractError::UnsupportedExportFormat(
                "pdf".to_string()
            ))
        );
    }
}
