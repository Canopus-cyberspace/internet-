use crate::common::{
    ExportRequestId, ExportResultId, IncidentId, PrivacyClass, SessionId, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SaveAction {
    SaveSession,
    ExportReport { incident_id: IncidentId },
    ExportGraph,
}

impl SaveAction {
    pub fn export_type(&self) -> &'static str {
        match self {
            Self::SaveSession => "session_save",
            Self::ExportReport { .. } => "report_export",
            Self::ExportGraph => "graph_export",
        }
    }

    pub fn audit_action(&self) -> &'static str {
        match self {
            Self::SaveSession => "session_saved",
            Self::ExportReport { .. } => "report_exported",
            Self::ExportGraph => "graph_exported",
        }
    }

    pub fn expected_format(&self) -> ExportFormat {
        match self {
            Self::SaveSession => ExportFormat::SgSession,
            Self::ExportReport { .. } => ExportFormat::SgReport,
            Self::ExportGraph => ExportFormat::SgGraph,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    SgSession,
    SgReport,
    SgGraph,
}

impl ExportFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            Self::SgSession => "sgsession",
            Self::SgReport => "sgreport",
            Self::SgGraph => "sggraph",
        }
    }

    pub fn dotted_extension(&self) -> &'static str {
        match self {
            Self::SgSession => ".sgsession",
            Self::SgReport => ".sgreport",
            Self::SgGraph => ".sggraph",
        }
    }

    pub fn schema_name(&self) -> &'static str {
        match self {
            Self::SgSession => "SentinelGuardSessionSnapshot",
            Self::SgReport => "ExportedReport",
            Self::SgGraph => "ExportSafeGraphSnapshot",
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            Self::SgSession => "application/vnd.sentinelguard.session+json",
            Self::SgReport => "application/vnd.sentinelguard.report+json",
            Self::SgGraph => "application/vnd.sentinelguard.graph+json",
        }
    }

    pub fn contract(&self) -> ExportFormatContract {
        ExportFormatContract {
            format: self.clone(),
            extension: self.dotted_extension().to_string(),
            schema_name: self.schema_name().to_string(),
            content_type: self.content_type().to_string(),
            redaction_rules: default_redaction_rules(),
            excluded_data_classes: excluded_data_classes(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionOptions {
    pub strict: bool,
    pub include_hostnames: bool,
    pub include_process_names: bool,
}

impl Default for RedactionOptions {
    fn default() -> Self {
        Self {
            strict: true,
            include_hostnames: false,
            include_process_names: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMethod {
    Strip,
    Redact,
    Tokenize,
    Hash,
    Summarize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRedactionRule {
    pub field: String,
    pub privacy_class: PrivacyClass,
    pub method: RedactionMethod,
    pub export_allowed_after_rule: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportFormatContract {
    pub format: ExportFormat,
    pub extension: String,
    pub schema_name: String,
    pub content_type: String,
    pub redaction_rules: Vec<ExportRedactionRule>,
    pub excluded_data_classes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRequestFieldPrivacy {
    pub field: &'static str,
    pub privacy_class: PrivacyClass,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRedactionSummary {
    pub redacted_field_count: u32,
    pub tokenized_field_count: u32,
    pub removed_field_count: u32,
    pub summarized_field_count: u32,
    pub passed: bool,
    pub methods: Vec<RedactionMethod>,
    pub manifest: BTreeMap<String, String>,
}

impl ExportRedactionSummary {
    pub fn strict_default() -> Self {
        let rules = default_redaction_rules();
        let mut manifest = BTreeMap::new();
        let mut redacted_field_count = 0;
        let mut tokenized_field_count = 0;
        let mut removed_field_count = 0;
        let mut summarized_field_count = 0;
        for rule in &rules {
            manifest.insert(
                rule.field.clone(),
                format!("{:?}", rule.method).to_ascii_lowercase(),
            );
            match rule.method {
                RedactionMethod::Strip => removed_field_count += 1,
                RedactionMethod::Redact => redacted_field_count += 1,
                RedactionMethod::Tokenize | RedactionMethod::Hash => tokenized_field_count += 1,
                RedactionMethod::Summarize => summarized_field_count += 1,
            }
        }
        Self {
            redacted_field_count,
            tokenized_field_count,
            removed_field_count,
            summarized_field_count,
            passed: true,
            methods: vec![
                RedactionMethod::Strip,
                RedactionMethod::Redact,
                RedactionMethod::Tokenize,
                RedactionMethod::Hash,
                RedactionMethod::Summarize,
            ],
            manifest,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSummary {
    pub observation_count: u32,
    pub finding_count: u32,
    pub alert_count: u32,
    pub incident_count: u32,
    pub imported_capture_source_count: u32,
    pub graph_node_count: u32,
    pub graph_edge_count: u32,
    pub response_recommendation_count: u32,
    pub report_count: u32,
    pub baseline_summary_count: u32,
    pub baseline_indicator_count: u32,
    pub incident_linked_group_count: u32,
    pub incident_timeline_entry_count: u32,
    pub hypothesis_explanation_count: u32,
    pub baseline_drill_down_count: u32,
    pub incident_group_detail_count: u32,
    pub timeline_drill_down_count: u32,
    pub source_reliability_explanation_count: u32,
    pub quality_record_count: u32,
    pub report_suitable_quality_count: u32,
    pub export_suitable_quality_count: u32,
    pub blocked_quality_count: u32,
    pub native_sampler_contract_count: u32,
    pub native_sampler_ready_count: u32,
    pub native_sampler_blocked_count: u32,
    pub edr_active_sampler_count: u32,
    pub native_sampler_runtime_count: u32,
    pub native_sampler_runtime_active_count: u32,
    pub native_sampler_runtime_batch_count: u32,
    pub native_sampler_runtime_fact_count: u32,
    pub native_service_visibility_available: bool,
    pub native_health_visibility_available: bool,
    pub native_process_visibility_available: bool,
    pub included_sections: Vec<String>,
    pub excluded_sections: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRequest {
    pub export_id: ExportRequestId,
    pub session_id: SessionId,
    pub action: SaveAction,
    pub format: ExportFormat,
    pub destination_path: String,
    pub redaction_options: RedactionOptions,
    pub requested_by_redacted: String,
    pub requested_at: Timestamp,
    pub user_initiated: bool,
}

impl ExportRequest {
    pub fn new(
        session_id: SessionId,
        action: SaveAction,
        destination_path: impl Into<String>,
        requested_by_redacted: impl Into<String>,
    ) -> Result<Self, SessionExportContractError> {
        let format = action.expected_format();
        Self::with_format(
            session_id,
            action,
            format,
            destination_path,
            RedactionOptions::default(),
            requested_by_redacted,
            true,
        )
    }

    pub fn with_format(
        session_id: SessionId,
        action: SaveAction,
        format: ExportFormat,
        destination_path: impl Into<String>,
        redaction_options: RedactionOptions,
        requested_by_redacted: impl Into<String>,
        user_initiated: bool,
    ) -> Result<Self, SessionExportContractError> {
        if format != action.expected_format() {
            return Err(SessionExportContractError::FormatActionMismatch);
        }
        let destination_path = require_non_empty("destination_path", destination_path.into())?;
        let requested_by_redacted =
            require_non_empty("requested_by_redacted", requested_by_redacted.into())?;
        if !user_initiated {
            return Err(SessionExportContractError::UserGestureRequired);
        }
        if !redaction_options.strict {
            return Err(SessionExportContractError::StrictRedactionRequired);
        }
        Ok(Self {
            export_id: ExportRequestId::new_v4(),
            session_id,
            action,
            format,
            destination_path,
            redaction_options,
            requested_by_redacted,
            requested_at: Timestamp::now(),
            user_initiated,
        })
    }

    pub fn field_privacy() -> Vec<ExportRequestFieldPrivacy> {
        vec![
            ExportRequestFieldPrivacy {
                field: "export_id",
                privacy_class: PrivacyClass::Internal,
            },
            ExportRequestFieldPrivacy {
                field: "session_id",
                privacy_class: PrivacyClass::Internal,
            },
            ExportRequestFieldPrivacy {
                field: "action",
                privacy_class: PrivacyClass::Internal,
            },
            ExportRequestFieldPrivacy {
                field: "format",
                privacy_class: PrivacyClass::Public,
            },
            ExportRequestFieldPrivacy {
                field: "destination_path",
                privacy_class: PrivacyClass::Sensitive,
            },
            ExportRequestFieldPrivacy {
                field: "redaction_options",
                privacy_class: PrivacyClass::Internal,
            },
            ExportRequestFieldPrivacy {
                field: "requested_by_redacted",
                privacy_class: PrivacyClass::Redacted,
            },
            ExportRequestFieldPrivacy {
                field: "requested_at",
                privacy_class: PrivacyClass::Internal,
            },
            ExportRequestFieldPrivacy {
                field: "user_initiated",
                privacy_class: PrivacyClass::Internal,
            },
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPreview {
    pub export_id: ExportRequestId,
    pub summary: ExportSummary,
    pub redaction_summary: ExportRedactionSummary,
    pub estimated_size_bytes: u64,
    pub destination_path: String,
    pub format_contract: ExportFormatContract,
    pub generated_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportConfirmation {
    pub export_id: ExportRequestId,
    pub user_confirmed: bool,
    pub confirmed_at: Option<Timestamp>,
}

impl ExportConfirmation {
    pub fn confirmed(export_id: ExportRequestId) -> Self {
        Self {
            export_id,
            user_confirmed: true,
            confirmed_at: Some(Timestamp::now()),
        }
    }

    pub fn cancelled(export_id: ExportRequestId) -> Self {
        Self {
            export_id,
            user_confirmed: false,
            confirmed_at: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportResult {
    pub export_result_id: ExportResultId,
    pub export_id: ExportRequestId,
    pub file_hash: String,
    pub file_size_bytes: u64,
    pub written_at: Timestamp,
    pub redaction_summary_applied: ExportRedactionSummary,
    pub format: ExportFormat,
    pub destination_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportHistoryEntry {
    pub export_id: ExportRequestId,
    pub session_id: SessionId,
    pub export_type: String,
    pub format: ExportFormat,
    pub destination_path: String,
    pub file_hash: String,
    pub file_size_bytes: u64,
    pub redaction_summary: ExportRedactionSummary,
    pub user_confirmed_at: Timestamp,
    pub exported_at: Timestamp,
}

pub trait ExportHistoryStore {
    type Error;

    fn append_entry(&mut self, entry: ExportHistoryEntry) -> Result<(), Self::Error>;
}

pub trait SaveExportPipeline {
    type Error;

    fn preview(&mut self, request: ExportRequest) -> Result<ExportPreview, Self::Error>;
    fn confirm(&mut self, confirmation: ExportConfirmation) -> Result<ExportResult, Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionExportContractError {
    EmptyField(&'static str),
    FormatActionMismatch,
    UserGestureRequired,
    StrictRedactionRequired,
}

impl fmt::Display for SessionExportContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::FormatActionMismatch => {
                write!(f, "save/export action does not match the requested format")
            }
            Self::UserGestureRequired => write!(f, "save/export requires a user gesture"),
            Self::StrictRedactionRequired => {
                write!(f, "strict redaction is required for V1 export")
            }
        }
    }
}

impl std::error::Error for SessionExportContractError {}

fn require_non_empty(
    field: &'static str,
    value: String,
) -> Result<String, SessionExportContractError> {
    if value.trim().is_empty() {
        Err(SessionExportContractError::EmptyField(field))
    } else {
        Ok(value)
    }
}

fn default_redaction_rules() -> Vec<ExportRedactionRule> {
    vec![
        rule(
            "raw_packets",
            PrivacyClass::Secret,
            RedactionMethod::Strip,
            false,
        ),
        rule(
            "payloads",
            PrivacyClass::Secret,
            RedactionMethod::Strip,
            false,
        ),
        rule(
            "http_bodies",
            PrivacyClass::Secret,
            RedactionMethod::Strip,
            false,
        ),
        rule(
            "cookies",
            PrivacyClass::Secret,
            RedactionMethod::Strip,
            false,
        ),
        rule(
            "tokens",
            PrivacyClass::Secret,
            RedactionMethod::Strip,
            false,
        ),
        rule(
            "credentials",
            PrivacyClass::Secret,
            RedactionMethod::Strip,
            false,
        ),
        rule(
            "api_keys",
            PrivacyClass::Secret,
            RedactionMethod::Strip,
            false,
        ),
        rule(
            "imported_raw_files",
            PrivacyClass::Secret,
            RedactionMethod::Strip,
            false,
        ),
        rule(
            "private_keys",
            PrivacyClass::Secret,
            RedactionMethod::Strip,
            false,
        ),
        rule(
            "full_query_strings",
            PrivacyClass::Sensitive,
            RedactionMethod::Redact,
            true,
        ),
        rule(
            "form_content",
            PrivacyClass::Secret,
            RedactionMethod::Strip,
            false,
        ),
        rule(
            "command_lines",
            PrivacyClass::Sensitive,
            RedactionMethod::Summarize,
            true,
        ),
        rule(
            "local_paths",
            PrivacyClass::Sensitive,
            RedactionMethod::Redact,
            true,
        ),
        rule(
            "usernames",
            PrivacyClass::Sensitive,
            RedactionMethod::Tokenize,
            true,
        ),
        rule(
            "sids",
            PrivacyClass::Sensitive,
            RedactionMethod::Tokenize,
            true,
        ),
        rule(
            "entity_identifiers",
            PrivacyClass::Internal,
            RedactionMethod::Strip,
            true,
        ),
        rule(
            "canonical_graph_internals",
            PrivacyClass::Internal,
            RedactionMethod::Strip,
            true,
        ),
        rule(
            "hostnames",
            PrivacyClass::Sensitive,
            RedactionMethod::Tokenize,
            true,
        ),
        rule(
            "ip_addresses",
            PrivacyClass::Sensitive,
            RedactionMethod::Tokenize,
            true,
        ),
        rule(
            "process_names",
            PrivacyClass::Sensitive,
            RedactionMethod::Redact,
            true,
        ),
    ]
}

fn rule(
    field: &str,
    privacy_class: PrivacyClass,
    method: RedactionMethod,
    export_allowed_after_rule: bool,
) -> ExportRedactionRule {
    ExportRedactionRule {
        field: field.to_string(),
        privacy_class,
        method,
        export_allowed_after_rule,
    }
}

fn excluded_data_classes() -> Vec<String> {
    vec![
        "raw_packets",
        "payloads",
        "http_bodies",
        "cookies",
        "tokens",
        "credentials",
        "api_keys",
        "imported_raw_files",
        "private_keys",
        "decrypted_content",
        "form_content",
        "local_paths",
        "usernames",
        "sids",
        "entity_identifiers",
        "canonical_graph_internals",
        "raw_process_memory",
        "file_content",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_export_request_fields_have_privacy_annotations() {
        let fields = ExportRequest::field_privacy()
            .into_iter()
            .map(|field| field.field)
            .collect::<Vec<_>>();

        assert_eq!(
            fields,
            vec![
                "export_id",
                "session_id",
                "action",
                "format",
                "destination_path",
                "redaction_options",
                "requested_by_redacted",
                "requested_at",
                "user_initiated",
            ]
        );
    }

    #[test]
    fn save_export_formats_document_contracts_and_exclusions() {
        for format in [
            ExportFormat::SgSession,
            ExportFormat::SgReport,
            ExportFormat::SgGraph,
        ] {
            let contract = format.contract();
            assert!(contract.extension.starts_with(".sg"));
            assert!(contract.redaction_rules.iter().any(|rule| {
                rule.privacy_class == PrivacyClass::Secret && !rule.export_allowed_after_rule
            }));
            assert!(contract
                .excluded_data_classes
                .iter()
                .any(|value| value == "tokens"));
        }
    }

    #[test]
    fn request_requires_user_initiated_strict_redacted_matching_action() {
        let session_id = SessionId::new_v4();
        let error = ExportRequest::with_format(
            session_id.clone(),
            SaveAction::SaveSession,
            ExportFormat::SgGraph,
            "session.sgsession",
            RedactionOptions::default(),
            "local_user",
            true,
        )
        .expect_err("mismatched format rejected");
        assert_eq!(error, SessionExportContractError::FormatActionMismatch);

        let error = ExportRequest::with_format(
            session_id,
            SaveAction::ExportGraph,
            ExportFormat::SgGraph,
            "graph.sggraph",
            RedactionOptions {
                strict: false,
                ..RedactionOptions::default()
            },
            "local_user",
            true,
        )
        .expect_err("non-strict export rejected");
        assert_eq!(error, SessionExportContractError::StrictRedactionRequired);
    }
}
