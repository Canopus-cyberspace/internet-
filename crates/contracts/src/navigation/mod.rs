use crate::common::{DataSourceId, SessionId, Timestamp};
use crate::graph::RedactionStatus;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_NAVIGATION_REFS: usize = 64;
pub const MAX_NAVIGATION_FLAGS: usize = 16;
const MAX_NAVIGATION_TEXT_BYTES: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NavigationContractError {
    EmptyField(&'static str),
    UnsafeField(&'static str),
    ExceedsBound(&'static str),
    UnsafeClaim(&'static str),
}

impl fmt::Display for NavigationContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains unsafe metadata"),
            Self::ExceedsBound(field) => write!(formatter, "{field} exceeds bounded limits"),
            Self::UnsafeClaim(reason) => write!(formatter, "unsafe navigation claim: {reason}"),
        }
    }
}

impl std::error::Error for NavigationContractError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NavigationTargetKind {
    Hypothesis,
    Baseline,
    BaselineIndicator,
    IncidentLinkedGroup,
    TimelineEntry,
    SourceReliabilitySummary,
    Evidence,
    Finding,
    Risk,
    AttackTechniqueRow,
    GraphHint,
    GraphNodeSummary,
    GraphEdgeSummary,
    GraphPathSummary,
    ReportSection,
    ExportHistoryEntry,
    LlmStoryRecord,
    EvidenceQualityDetail,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NavigationViewKind {
    Investigation,
    Evidence,
    Graph,
    AttackCoverage,
    Timeline,
    Report,
    Export,
    Story,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NavigationResolutionStatus {
    Resolved,
    Degraded,
    Missing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavigationResolveRequest {
    pub session_id: Option<SessionId>,
    pub source_view: NavigationViewKind,
    pub target_kind: NavigationTargetKind,
    pub target_id: String,
}

impl NavigationResolveRequest {
    pub fn validate(&self) -> Result<(), NavigationContractError> {
        safe_id("navigation.target_id", &self.target_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavigationBreadcrumb {
    pub view_kind: NavigationViewKind,
    pub target_kind: NavigationTargetKind,
    pub target_id: String,
    pub display_label_category: String,
    pub time_bucket: Option<Timestamp>,
    pub confidence_bucket: Option<String>,
    pub degraded_reason: Option<String>,
    pub redaction_status: RedactionStatus,
}

impl NavigationBreadcrumb {
    pub fn validate(&self) -> Result<(), NavigationContractError> {
        safe_id("breadcrumb.target_id", &self.target_id)?;
        safe_text(
            "breadcrumb.display_label_category",
            &self.display_label_category,
        )?;
        optional_safe_text(
            "breadcrumb.confidence_bucket",
            self.confidence_bucket.as_deref(),
        )?;
        optional_safe_text(
            "breadcrumb.degraded_reason",
            self.degraded_reason.as_deref(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavigationReference {
    pub ref_id: String,
    pub ref_kind: NavigationTargetKind,
    pub target_kind: NavigationTargetKind,
    pub target_id: String,
    pub source_view: NavigationViewKind,
    pub target_view: NavigationViewKind,
    pub display_label_category: String,
    pub confidence_bucket: Option<String>,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub redacted_summary: String,
    pub created_time_bucket: Option<Timestamp>,
    pub provenance_id: Option<DataSourceId>,
    pub redaction_status: RedactionStatus,
}

impl NavigationReference {
    pub fn validate(&self) -> Result<(), NavigationContractError> {
        safe_id("navigation.ref_id", &self.ref_id)?;
        safe_id("navigation.target_id", &self.target_id)?;
        safe_text(
            "navigation.display_label_category",
            &self.display_label_category,
        )?;
        safe_text("navigation.redacted_summary", &self.redacted_summary)?;
        optional_safe_text(
            "navigation.confidence_bucket",
            self.confidence_bucket.as_deref(),
        )?;
        optional_safe_text(
            "navigation.degraded_reason",
            self.degraded_reason.as_deref(),
        )?;
        validate_flags(&self.missing_visibility_flags)?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(NavigationContractError::UnsafeClaim(
                "unredacted references cannot be navigated",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavigationTargetSummary {
    pub target_kind: NavigationTargetKind,
    pub target_id: String,
    pub status: NavigationResolutionStatus,
    pub category: String,
    pub severity_risk_bucket: Option<String>,
    pub confidence_bucket: Option<String>,
    pub evidence_quality_bucket: Option<String>,
    pub evidence_refs: Vec<String>,
    pub fact_refs: Vec<String>,
    pub hypothesis_refs: Vec<String>,
    pub finding_refs: Vec<String>,
    pub risk_refs: Vec<String>,
    pub baseline_refs: Vec<String>,
    pub incident_group_refs: Vec<String>,
    pub timeline_refs: Vec<String>,
    pub attack_refs: Vec<String>,
    pub graph_refs: Vec<String>,
    pub report_refs: Vec<String>,
    pub export_refs: Vec<String>,
    pub story_refs: Vec<String>,
    pub quality_refs: Vec<String>,
    pub provenance_refs: Vec<String>,
    pub redacted_summary: String,
    pub created_time_bucket: Option<Timestamp>,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub redaction_status: RedactionStatus,
    pub metadata_only: bool,
    pub session_scoped: bool,
    pub automatic_llm_calls: bool,
    pub response_execution: bool,
}

impl NavigationTargetSummary {
    pub fn validate(&self) -> Result<(), NavigationContractError> {
        safe_id("target.target_id", &self.target_id)?;
        safe_text("target.category", &self.category)?;
        safe_text("target.redacted_summary", &self.redacted_summary)?;
        for value in [
            self.severity_risk_bucket.as_deref(),
            self.confidence_bucket.as_deref(),
            self.evidence_quality_bucket.as_deref(),
            self.degraded_reason.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            safe_text("target.bucket", value)?;
        }
        validate_flags(&self.missing_visibility_flags)?;
        for refs in [
            &self.evidence_refs,
            &self.fact_refs,
            &self.hypothesis_refs,
            &self.finding_refs,
            &self.risk_refs,
            &self.baseline_refs,
            &self.incident_group_refs,
            &self.timeline_refs,
            &self.attack_refs,
            &self.graph_refs,
            &self.report_refs,
            &self.export_refs,
            &self.story_refs,
            &self.quality_refs,
            &self.provenance_refs,
        ] {
            validate_refs(refs)?;
        }
        if self.redaction_status == RedactionStatus::RedactionRequired
            || !self.metadata_only
            || !self.session_scoped
            || self.automatic_llm_calls
            || self.response_execution
        {
            return Err(NavigationContractError::UnsafeClaim(
                "navigation summaries must remain redacted, metadata-only, session-scoped, and non-executing",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavigationResolution {
    pub session_id: Option<SessionId>,
    pub status: NavigationResolutionStatus,
    pub breadcrumb: NavigationBreadcrumb,
    pub target: NavigationTargetSummary,
    pub outgoing_refs: Vec<NavigationReference>,
    pub portable_no_retention: bool,
    pub automatic_llm_calls: bool,
    pub response_execution: bool,
}

impl NavigationResolution {
    pub fn validate(&self) -> Result<(), NavigationContractError> {
        self.breadcrumb.validate()?;
        self.target.validate()?;
        if self.outgoing_refs.len() > MAX_NAVIGATION_REFS {
            return Err(NavigationContractError::ExceedsBound("outgoing_refs"));
        }
        for reference in &self.outgoing_refs {
            reference.validate()?;
        }
        if !self.portable_no_retention || self.automatic_llm_calls || self.response_execution {
            return Err(NavigationContractError::UnsafeClaim(
                "navigation resolution cannot retain data, call LLMs, or execute responses",
            ));
        }
        Ok(())
    }
}

fn validate_refs(refs: &[String]) -> Result<(), NavigationContractError> {
    if refs.len() > MAX_NAVIGATION_REFS {
        return Err(NavigationContractError::ExceedsBound("navigation refs"));
    }
    for value in refs {
        safe_id("navigation ref", value)?;
    }
    Ok(())
}

fn validate_flags(flags: &[String]) -> Result<(), NavigationContractError> {
    if flags.len() > MAX_NAVIGATION_FLAGS {
        return Err(NavigationContractError::ExceedsBound(
            "missing_visibility_flags",
        ));
    }
    for flag in flags {
        safe_text("missing_visibility_flag", flag)?;
    }
    Ok(())
}

fn optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), NavigationContractError> {
    if let Some(value) = value {
        safe_text(field, value)?;
    }
    Ok(())
}

fn safe_id(field: &'static str, value: &str) -> Result<(), NavigationContractError> {
    safe_text(field, value)?;
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-_:.".contains(character))
    {
        return Err(NavigationContractError::UnsafeField(field));
    }
    Ok(())
}

fn safe_text(field: &'static str, value: &str) -> Result<(), NavigationContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(NavigationContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_NAVIGATION_TEXT_BYTES {
        return Err(NavigationContractError::ExceedsBound(field));
    }
    let lowered = trimmed.to_ascii_lowercase();
    let forbidden = [
        "://",
        "\\",
        "/",
        "@",
        "?",
        "cookie",
        "authorization",
        "bearer ",
        "password",
        "secret",
        "token=",
        "username",
        "tenant_id",
        "account_id",
        "device_id",
        "command_line",
        "raw_",
        "payload",
        "private marker",
    ];
    if forbidden.iter().any(|marker| lowered.contains(marker)) {
        return Err(NavigationContractError::UnsafeField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_request_accepts_bounded_refs_and_rejects_raw_values() {
        NavigationResolveRequest {
            session_id: None,
            source_view: NavigationViewKind::Investigation,
            target_kind: NavigationTargetKind::AttackTechniqueRow,
            target_id: "TA0010:T1567.002".to_string(),
        }
        .validate()
        .expect("bounded ATT&CK ref");

        let error = NavigationResolveRequest {
            session_id: None,
            source_view: NavigationViewKind::Investigation,
            target_kind: NavigationTargetKind::Evidence,
            target_id: "https://example.test/private?token=secret".to_string(),
        }
        .validate()
        .expect_err("raw URL rejected");
        assert!(matches!(error, NavigationContractError::UnsafeField(_)));
    }
}
