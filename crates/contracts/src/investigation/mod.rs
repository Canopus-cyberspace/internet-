use crate::baseline::{
    BaselineAttackTechniqueRef, BaselineConfidenceTrendBucket, BaselineCountBucket,
    BaselineIndicatorKind, BaselineRarityBucket, BaselineRecurrenceBucket, BaselineScope,
    BaselineTrendBucket, SourceReliabilityBucket,
};
use crate::common::{
    AlertId, AttackHypothesisId, BaselineIndicatorId, BaselineRecordId, DataSourceId, EvidenceId,
    ExportResultId, FindingId, GraphHintId, IncidentId, IncidentLinkedGroupId,
    IncidentTimelineEntryId, LlmAlertStoryId, MetadataWatchSourceId, ReportSectionId, RiskEventId,
    SecurityFactId, Timestamp,
};
use crate::evidence_quality::QualityBreakdown;
use crate::fusion::{FusionConfidenceBucket, SecurityLayer};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_INVESTIGATION_ITEMS: usize = 128;
pub const MAX_INVESTIGATION_REFS: usize = 64;
pub const MAX_INVESTIGATION_LABELS: usize = 32;
pub const MAX_INVESTIGATION_SUGGESTIONS: usize = 8;
const MAX_INVESTIGATION_SAFE_TEXT_BYTES: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvestigationContractError {
    EmptyField(&'static str),
    UnsafeField(&'static str),
    ExceedsBound(&'static str),
    UnsafeClaim(&'static str),
}

impl fmt::Display for InvestigationContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains unsafe metadata"),
            Self::ExceedsBound(field) => write!(formatter, "{field} exceeds bounded limits"),
            Self::UnsafeClaim(reason) => {
                write!(formatter, "unsafe investigation claim: {reason}")
            }
        }
    }
}

impl std::error::Error for InvestigationContractError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationRequirementStatus {
    Matched,
    Missing,
    NotObserved,
    Disqualified,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationSuggestionKind {
    ReviewEvidenceRefs,
    CompareBaselineIndicators,
    VerifySourceHealth,
    InspectAttackCoverage,
    ReviewProviderCategoryContext,
    GenerateStoryManually,
    ExportReportManually,
    ConsiderAuthorizedVisibility,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationSuggestion {
    pub kind: InvestigationSuggestionKind,
    pub summary_redacted: String,
    pub advisory_only: bool,
    pub automatic_action: bool,
}

impl InvestigationSuggestion {
    pub fn validate(&self) -> Result<(), InvestigationContractError> {
        safe_text("suggestion.summary_redacted", &self.summary_redacted)?;
        if !self.advisory_only || self.automatic_action {
            return Err(InvestigationContractError::UnsafeClaim(
                "investigation suggestions must remain advisory only",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactRequirementExplanation {
    pub layer: SecurityLayer,
    pub categories: Vec<String>,
    pub required: bool,
    pub status: InvestigationRequirementStatus,
    pub matched_count_bucket: BaselineCountBucket,
}

impl FactRequirementExplanation {
    pub fn validate(&self) -> Result<(), InvestigationContractError> {
        validate_labels("requirement.categories", &self.categories)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmStoryAvailabilityDetail {
    pub story_refs: Vec<LlmAlertStoryId>,
    pub alert_ref: Option<AlertId>,
    pub incident_ref: Option<IncidentId>,
    pub bounded_input_available: bool,
    pub existing_story_available: bool,
    pub explicit_user_action_required: bool,
    pub automatic_generation: bool,
}

impl LlmStoryAvailabilityDetail {
    pub fn validate(&self) -> Result<(), InvestigationContractError> {
        validate_refs("story_refs", self.story_refs.len())?;
        if self.automatic_generation || !self.explicit_user_action_required {
            return Err(InvestigationContractError::UnsafeClaim(
                "story generation must remain explicit and manual",
            ));
        }
        if self.existing_story_available == self.story_refs.is_empty() {
            return Err(InvestigationContractError::UnsafeClaim(
                "story availability must be backed by explicit story refs",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HypothesisExplanationDetail {
    pub hypothesis_id: AttackHypothesisId,
    pub family: String,
    pub version: String,
    pub confidence_bucket: FusionConfidenceBucket,
    pub confidence_trend: BaselineConfidenceTrendBucket,
    pub supporting_fact_categories: Vec<String>,
    pub required_fact_status: Vec<FactRequirementExplanation>,
    pub optional_fact_status: Vec<FactRequirementExplanation>,
    pub disqualifier_status: InvestigationRequirementStatus,
    pub evidence_count_bucket: BaselineCountBucket,
    pub source_count_bucket: BaselineCountBucket,
    pub correlation_time_bucket: String,
    pub provider_category_relation: String,
    pub route_endpoint_relation: String,
    pub baseline_refs: Vec<BaselineRecordId>,
    pub indicator_refs: Vec<BaselineIndicatorId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub fact_refs: Vec<SecurityFactId>,
    pub finding_refs: Vec<FindingId>,
    pub risk_refs: Vec<RiskEventId>,
    pub attack_refs: Vec<BaselineAttackTechniqueRef>,
    pub graph_refs: Vec<GraphHintId>,
    pub report_refs: Vec<ReportSectionId>,
    pub export_refs: Vec<ExportResultId>,
    pub story_availability: LlmStoryAvailabilityDetail,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub suggested_questions: Vec<String>,
    pub suggestions: Vec<InvestigationSuggestion>,
    pub summary_redacted: String,
    pub quality: QualityBreakdown,
}

impl HypothesisExplanationDetail {
    pub fn validate(&self) -> Result<(), InvestigationContractError> {
        safe_text("hypothesis.family", &self.family)?;
        safe_text("hypothesis.version", &self.version)?;
        safe_text(
            "hypothesis.correlation_time_bucket",
            &self.correlation_time_bucket,
        )?;
        safe_text(
            "hypothesis.provider_category_relation",
            &self.provider_category_relation,
        )?;
        safe_text(
            "hypothesis.route_endpoint_relation",
            &self.route_endpoint_relation,
        )?;
        safe_text("hypothesis.summary_redacted", &self.summary_redacted)?;
        optional_safe_text(
            "hypothesis.degraded_reason",
            self.degraded_reason.as_deref(),
        )?;
        validate_labels(
            "hypothesis.supporting_fact_categories",
            &self.supporting_fact_categories,
        )?;
        validate_labels(
            "hypothesis.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        validate_labels("hypothesis.suggested_questions", &self.suggested_questions)?;
        validate_items(
            "hypothesis.required_fact_status",
            self.required_fact_status.len(),
        )?;
        validate_items(
            "hypothesis.optional_fact_status",
            self.optional_fact_status.len(),
        )?;
        for status in self
            .required_fact_status
            .iter()
            .chain(self.optional_fact_status.iter())
        {
            status.validate()?;
        }
        validate_trace_refs(&[
            self.baseline_refs.len(),
            self.indicator_refs.len(),
            self.evidence_refs.len(),
            self.fact_refs.len(),
            self.finding_refs.len(),
            self.risk_refs.len(),
            self.attack_refs.len(),
            self.graph_refs.len(),
            self.report_refs.len(),
            self.export_refs.len(),
        ])?;
        validate_suggestions(&self.suggestions)?;
        self.story_availability.validate()?;
        self.quality
            .validate()
            .map_err(|_| InvestigationContractError::UnsafeField("hypothesis.quality"))?;
        for attack_ref in &self.attack_refs {
            attack_ref
                .validate()
                .map_err(|_| InvestigationContractError::UnsafeField("hypothesis.attack_refs"))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BaselineDrillDownDetail {
    pub baseline_id: BaselineRecordId,
    pub scope: BaselineScope,
    pub scope_category: String,
    pub indicator_kinds: Vec<BaselineIndicatorKind>,
    pub indicator_refs: Vec<BaselineIndicatorId>,
    pub count_bucket: BaselineCountBucket,
    pub rarity_bucket: BaselineRarityBucket,
    pub recurrence_bucket: BaselineRecurrenceBucket,
    pub first_seen_bucket: Option<Timestamp>,
    pub last_seen_bucket: Option<Timestamp>,
    pub trend_bucket: BaselineTrendBucket,
    pub confidence_trend: BaselineConfidenceTrendBucket,
    pub confidence_bucket: FusionConfidenceBucket,
    pub source_reliability_bucket: SourceReliabilityBucket,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub incident_group_refs: Vec<IncidentLinkedGroupId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub fact_refs: Vec<SecurityFactId>,
    pub finding_refs: Vec<FindingId>,
    pub risk_refs: Vec<RiskEventId>,
    pub provenance_refs: Vec<DataSourceId>,
    pub attack_refs: Vec<BaselineAttackTechniqueRef>,
    pub report_refs: Vec<ReportSectionId>,
    pub export_refs: Vec<ExportResultId>,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub suggestions: Vec<InvestigationSuggestion>,
    pub summary_redacted: String,
    pub quality: QualityBreakdown,
}

impl BaselineDrillDownDetail {
    pub fn validate(&self) -> Result<(), InvestigationContractError> {
        safe_text("baseline.scope_category", &self.scope_category)?;
        safe_text("baseline.summary_redacted", &self.summary_redacted)?;
        optional_safe_text("baseline.degraded_reason", self.degraded_reason.as_deref())?;
        validate_items("baseline.indicator_kinds", self.indicator_kinds.len())?;
        validate_labels(
            "baseline.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        validate_trace_refs(&[
            self.hypothesis_refs.len(),
            self.incident_group_refs.len(),
            self.indicator_refs.len(),
            self.evidence_refs.len(),
            self.fact_refs.len(),
            self.finding_refs.len(),
            self.risk_refs.len(),
            self.provenance_refs.len(),
            self.attack_refs.len(),
            self.report_refs.len() + self.export_refs.len(),
        ])?;
        validate_suggestions(&self.suggestions)?;
        self.quality
            .validate()
            .map_err(|_| InvestigationContractError::UnsafeField("baseline.quality"))?;
        for attack_ref in &self.attack_refs {
            attack_ref
                .validate()
                .map_err(|_| InvestigationContractError::UnsafeField("baseline.attack_refs"))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentGroupInvestigationDetail {
    pub group_id: IncidentLinkedGroupId,
    pub incident_id: Option<IncidentId>,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub baseline_refs: Vec<BaselineRecordId>,
    pub indicator_refs: Vec<BaselineIndicatorId>,
    pub timeline_refs: Vec<IncidentTimelineEntryId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub fact_refs: Vec<SecurityFactId>,
    pub finding_refs: Vec<FindingId>,
    pub risk_refs: Vec<RiskEventId>,
    pub attack_refs: Vec<BaselineAttackTechniqueRef>,
    pub graph_refs: Vec<GraphHintId>,
    pub report_refs: Vec<ReportSectionId>,
    pub export_refs: Vec<ExportResultId>,
    pub source_reliability_refs: Vec<MetadataWatchSourceId>,
    pub source_reliability_buckets: Vec<SourceReliabilityBucket>,
    pub confidence_trend: BaselineConfidenceTrendBucket,
    pub severity_risk_trend: BaselineTrendBucket,
    pub first_seen_bucket: Option<Timestamp>,
    pub last_updated_bucket: Option<Timestamp>,
    pub story_availability: LlmStoryAvailabilityDetail,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub suggestions: Vec<InvestigationSuggestion>,
    pub summary_redacted: String,
    pub quality: QualityBreakdown,
    pub weak_merge_warning: bool,
    pub broad_provider_only_merge_rejected: bool,
}

impl IncidentGroupInvestigationDetail {
    pub fn validate(&self) -> Result<(), InvestigationContractError> {
        safe_text("group.summary_redacted", &self.summary_redacted)?;
        optional_safe_text("group.degraded_reason", self.degraded_reason.as_deref())?;
        validate_items(
            "group.source_reliability_buckets",
            self.source_reliability_buckets.len(),
        )?;
        validate_labels(
            "group.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        validate_trace_refs(&[
            self.hypothesis_refs.len(),
            self.baseline_refs.len(),
            self.indicator_refs.len(),
            self.timeline_refs.len(),
            self.evidence_refs.len(),
            self.fact_refs.len(),
            self.finding_refs.len(),
            self.risk_refs.len(),
            self.attack_refs.len(),
            self.graph_refs.len()
                + self.report_refs.len()
                + self.export_refs.len()
                + self.source_reliability_refs.len(),
        ])?;
        validate_suggestions(&self.suggestions)?;
        self.story_availability.validate()?;
        self.quality
            .validate()
            .map_err(|_| InvestigationContractError::UnsafeField("group.quality"))?;
        for attack_ref in &self.attack_refs {
            attack_ref
                .validate()
                .map_err(|_| InvestigationContractError::UnsafeField("group.attack_refs"))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TimelineDrillDownDetail {
    pub timeline_entry_id: IncidentTimelineEntryId,
    pub incident_id: Option<IncidentId>,
    pub group_id: IncidentLinkedGroupId,
    pub time_bucket: Timestamp,
    pub event_category: String,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub baseline_refs: Vec<BaselineRecordId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub finding_refs: Vec<FindingId>,
    pub risk_refs: Vec<RiskEventId>,
    pub attack_refs: Vec<BaselineAttackTechniqueRef>,
    pub source_health_refs: Vec<MetadataWatchSourceId>,
    pub report_refs: Vec<ReportSectionId>,
    pub confidence_bucket: FusionConfidenceBucket,
    pub degraded_reason: Option<String>,
    pub summary_redacted: String,
    pub quality: QualityBreakdown,
}

impl TimelineDrillDownDetail {
    pub fn validate(&self) -> Result<(), InvestigationContractError> {
        safe_text("timeline.event_category", &self.event_category)?;
        safe_text("timeline.summary_redacted", &self.summary_redacted)?;
        optional_safe_text("timeline.degraded_reason", self.degraded_reason.as_deref())?;
        validate_trace_refs(&[
            self.hypothesis_refs.len(),
            self.baseline_refs.len(),
            self.evidence_refs.len(),
            self.finding_refs.len(),
            self.risk_refs.len(),
            self.attack_refs.len(),
            self.source_health_refs.len(),
            self.report_refs.len(),
            0,
            0,
        ])?;
        for attack_ref in &self.attack_refs {
            attack_ref
                .validate()
                .map_err(|_| InvestigationContractError::UnsafeField("timeline.attack_refs"))?;
        }
        self.quality
            .validate()
            .map_err(|_| InvestigationContractError::UnsafeField("timeline.quality"))?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReliabilityExplanation {
    pub source_id: MetadataWatchSourceId,
    pub source_health_state: String,
    pub reliability_bucket: SourceReliabilityBucket,
    pub sampled_count_bucket: BaselineCountBucket,
    pub malformed_count_bucket: BaselineCountBucket,
    pub backpressure_count_bucket: BaselineCountBucket,
    pub confidence_impact: BaselineConfidenceTrendBucket,
    pub baseline_refs: Vec<BaselineRecordId>,
    pub incident_group_refs: Vec<IncidentLinkedGroupId>,
    pub timeline_refs: Vec<IncidentTimelineEntryId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub suggestions: Vec<InvestigationSuggestion>,
    pub summary_redacted: String,
    pub quality: QualityBreakdown,
}

impl SourceReliabilityExplanation {
    pub fn validate(&self) -> Result<(), InvestigationContractError> {
        safe_text("source.source_health_state", &self.source_health_state)?;
        safe_text("source.summary_redacted", &self.summary_redacted)?;
        optional_safe_text("source.degraded_reason", self.degraded_reason.as_deref())?;
        validate_labels(
            "source.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        validate_refs("source.baseline_refs", self.baseline_refs.len())?;
        validate_refs("source.incident_group_refs", self.incident_group_refs.len())?;
        validate_refs("source.timeline_refs", self.timeline_refs.len())?;
        validate_refs("source.evidence_refs", self.evidence_refs.len())?;
        validate_suggestions(&self.suggestions)?;
        self.quality
            .validate()
            .map_err(|_| InvestigationContractError::UnsafeField("source.quality"))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvestigationDrillDownSummary {
    pub generated_at: Timestamp,
    pub hypothesis_count: u32,
    pub baseline_count: u32,
    pub incident_group_count: u32,
    pub timeline_count: u32,
    pub source_reliability_count: u32,
    pub hypotheses: Vec<HypothesisExplanationDetail>,
    pub baselines: Vec<BaselineDrillDownDetail>,
    pub incident_groups: Vec<IncidentGroupInvestigationDetail>,
    pub timeline: Vec<TimelineDrillDownDetail>,
    pub source_reliability: Vec<SourceReliabilityExplanation>,
    pub report_refs: Vec<ReportSectionId>,
    pub export_refs: Vec<ExportResultId>,
    pub suggestions: Vec<InvestigationSuggestion>,
    pub quality: QualityBreakdown,
    pub portable_no_retention: bool,
    pub metadata_only: bool,
    pub automatic_llm_calls: bool,
    pub response_execution: bool,
}

impl InvestigationDrillDownSummary {
    pub fn validate(&self) -> Result<(), InvestigationContractError> {
        validate_items("hypotheses", self.hypotheses.len())?;
        validate_items("baselines", self.baselines.len())?;
        validate_items("incident_groups", self.incident_groups.len())?;
        validate_items("timeline", self.timeline.len())?;
        validate_items("source_reliability", self.source_reliability.len())?;
        validate_refs("report_refs", self.report_refs.len())?;
        validate_refs("export_refs", self.export_refs.len())?;
        validate_suggestions(&self.suggestions)?;
        self.quality
            .validate()
            .map_err(|_| InvestigationContractError::UnsafeField("summary.quality"))?;
        if !self.portable_no_retention
            || !self.metadata_only
            || self.automatic_llm_calls
            || self.response_execution
        {
            return Err(InvestigationContractError::UnsafeClaim(
                "drill-down must remain metadata-only, no-retention, and non-executing",
            ));
        }
        for hypothesis in &self.hypotheses {
            hypothesis.validate()?;
        }
        for baseline in &self.baselines {
            baseline.validate()?;
        }
        for group in &self.incident_groups {
            group.validate()?;
        }
        for entry in &self.timeline {
            entry.validate()?;
        }
        for source in &self.source_reliability {
            source.validate()?;
        }
        Ok(())
    }
}

fn validate_trace_refs(lengths: &[usize]) -> Result<(), InvestigationContractError> {
    for len in lengths {
        validate_refs("trace_refs", *len)?;
    }
    Ok(())
}

fn validate_items(field: &'static str, len: usize) -> Result<(), InvestigationContractError> {
    if len > MAX_INVESTIGATION_ITEMS {
        return Err(InvestigationContractError::ExceedsBound(field));
    }
    Ok(())
}

fn validate_refs(field: &'static str, len: usize) -> Result<(), InvestigationContractError> {
    if len > MAX_INVESTIGATION_REFS {
        return Err(InvestigationContractError::ExceedsBound(field));
    }
    Ok(())
}

fn validate_labels(
    field: &'static str,
    values: &[String],
) -> Result<(), InvestigationContractError> {
    if values.len() > MAX_INVESTIGATION_LABELS {
        return Err(InvestigationContractError::ExceedsBound(field));
    }
    for value in values {
        safe_text(field, value)?;
    }
    Ok(())
}

fn validate_suggestions(
    suggestions: &[InvestigationSuggestion],
) -> Result<(), InvestigationContractError> {
    if suggestions.len() > MAX_INVESTIGATION_SUGGESTIONS {
        return Err(InvestigationContractError::ExceedsBound("suggestions"));
    }
    for suggestion in suggestions {
        suggestion.validate()?;
    }
    Ok(())
}

fn optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), InvestigationContractError> {
    if let Some(value) = value {
        safe_text(field, value)?;
    }
    Ok(())
}

fn safe_text(field: &'static str, value: &str) -> Result<(), InvestigationContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(InvestigationContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_INVESTIGATION_SAFE_TEXT_BYTES
        || trimmed.contains("://")
        || trimmed.contains('@')
        || trimmed.contains('\\')
        || trimmed.contains('/')
        || trimmed.parse::<std::net::IpAddr>().is_ok()
        || FORBIDDEN_MARKERS
            .iter()
            .any(|marker| trimmed.to_ascii_lowercase().contains(marker))
    {
        return Err(InvestigationContractError::UnsafeField(field));
    }
    Ok(())
}

const FORBIDDEN_MARKERS: &[&str] = &[
    "password",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "token",
    "credential",
    "payload",
    "raw_log",
    "raw_json",
    "raw_packet",
    "packet_bytes",
    "username",
    "email",
    "tenant_id",
    "account_id",
    "device_id",
    "command_line",
    "local_path",
    "filename",
    "private_marker",
    "confirmed_compromise",
    "credential_theft",
    "host_compromise",
    "malware_execution",
    "process_attribution",
    "full_capture",
    "response_execution",
    "active_scan",
    "firewall_change",
    "account_disable",
    "host_isolation",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions_must_remain_advisory_and_safe() {
        let mut suggestion = safe_suggestion();
        suggestion.automatic_action = true;
        assert!(matches!(
            suggestion.validate(),
            Err(InvestigationContractError::UnsafeClaim(_))
        ));
        suggestion.automatic_action = false;
        suggestion.summary_redacted = "perform active_scan now".to_string();
        assert!(matches!(
            suggestion.validate(),
            Err(InvestigationContractError::UnsafeField(_))
        ));
    }

    #[test]
    fn story_availability_never_allows_automatic_generation() {
        let detail = LlmStoryAvailabilityDetail {
            story_refs: Vec::new(),
            alert_ref: None,
            incident_ref: None,
            bounded_input_available: false,
            existing_story_available: false,
            explicit_user_action_required: true,
            automatic_generation: true,
        };
        assert!(matches!(
            detail.validate(),
            Err(InvestigationContractError::UnsafeClaim(_))
        ));
    }

    fn safe_suggestion() -> InvestigationSuggestion {
        InvestigationSuggestion {
            kind: InvestigationSuggestionKind::ReviewEvidenceRefs,
            summary_redacted: "Review linked evidence references".to_string(),
            advisory_only: true,
            automatic_action: false,
        }
    }
}
