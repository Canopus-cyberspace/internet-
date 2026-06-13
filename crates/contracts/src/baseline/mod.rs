use crate::common::{
    AttackHypothesisId, BaselineIndicatorId, BaselineRecordId, DataSourceId, EvidenceId, FindingId,
    GraphHintId, IncidentId, IncidentLinkedGroupId, IncidentTimelineEntryId, MetadataWatchSourceId,
    ReportSectionId, RiskEventId, SecurityFactId, Timestamp,
};
use crate::evidence_quality::QualityBreakdown;
use crate::fusion::FusionConfidenceBucket;
use crate::graph::RedactionStatus;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_BASELINE_ITEMS: usize = 128;
pub const MAX_BASELINE_REFS: usize = 64;
pub const MAX_BASELINE_LABELS: usize = 32;
const MAX_BASELINE_SAFE_TEXT_BYTES: usize = 160;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaselineContractError {
    EmptyField(&'static str),
    UnsafeField(&'static str),
    ExceedsBound(&'static str),
    UnsafeClaim(&'static str),
}

impl fmt::Display for BaselineContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains unsafe metadata"),
            Self::ExceedsBound(field) => write!(formatter, "{field} exceeds bounded limits"),
            Self::UnsafeClaim(reason) => write!(formatter, "unsafe baseline claim: {reason}"),
        }
    }
}

impl std::error::Error for BaselineContractError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineScope {
    CurrentSession,
    SourceId,
    SamplerLayer,
    ProviderCategory,
    DestinationServiceCategory,
    RouteEndpointFingerprint,
    RedactedIdentitySessionCategory,
    SourceSessionLabel,
    DecoySensorRef,
    HypothesisFamily,
    AttackTechniqueRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineCategory {
    SecurityFact,
    Hypothesis,
    Finding,
    RiskHint,
    SourceHealth,
    AttackTechnique,
    GraphHint,
    SamplingBatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineCountBucket {
    None,
    Single,
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineRecurrenceBucket {
    FirstSeen,
    Rare,
    Repeated,
    Frequent,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineRarityBucket {
    FirstSeen,
    Rare,
    Uncommon,
    Common,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineTrendBucket {
    Unknown,
    Flat,
    Rising,
    Falling,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineConfidenceTrendBucket {
    Unknown,
    StableLow,
    StableMedium,
    Rising,
    Degraded,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceReliabilityBucket {
    Unknown,
    Weak,
    Degraded,
    Stable,
    Corroborated,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineIndicatorKind {
    FirstSeenProviderCategory,
    FirstSeenRouteEndpointFingerprint,
    FirstSeenDestinationServiceCategory,
    FirstSeenAuthProviderSessionCategory,
    FirstSeenDecoySensorInteractionCategory,
    RareProviderCategory,
    RareRouteFingerprint,
    RepeatedFailedAuthSessionPattern,
    RepeatedCdnWafApiErrorPattern,
    RepeatedDeceptionInteraction,
    RepeatedSourceHealthDegradation,
    RisingHypothesisConfidenceTrend,
    RisingRiskTrend,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselinePersistenceMode {
    SessionMemoryOnly,
    PortableNoRetention,
    ExplicitExportOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineAttackTechniqueRef {
    pub tactic_id: String,
    pub technique_id: String,
    pub attack_version: String,
    pub confidence_bucket: FusionConfidenceBucket,
    pub required_visibility: String,
}

impl BaselineAttackTechniqueRef {
    pub fn validate(&self) -> Result<(), BaselineContractError> {
        safe_text("tactic_id", &self.tactic_id)?;
        safe_text("technique_id", &self.technique_id)?;
        safe_text("attack_version", &self.attack_version)?;
        safe_text("required_visibility", &self.required_visibility)?;
        if self.confidence_bucket == FusionConfidenceBucket::Medium
            && matches!(
                self.tactic_id.as_str(),
                "TA0002" | "TA0003" | "TA0004" | "TA0006"
            )
        {
            return Err(BaselineContractError::UnsafeClaim(
                "metadata-only baselines cannot claim high-risk host tactics with medium confidence",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BaselineRecord {
    pub baseline_id: BaselineRecordId,
    pub scope: BaselineScope,
    pub category: BaselineCategory,
    pub scope_key_hash: String,
    pub safe_label: String,
    pub count_bucket: BaselineCountBucket,
    pub first_seen_time_bucket: Option<Timestamp>,
    pub last_seen_time_bucket: Option<Timestamp>,
    pub recurrence_bucket: BaselineRecurrenceBucket,
    pub rarity_bucket: BaselineRarityBucket,
    pub trend_bucket: BaselineTrendBucket,
    pub confidence_trend_bucket: BaselineConfidenceTrendBucket,
    pub source_reliability_bucket: SourceReliabilityBucket,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub evidence_refs: Vec<EvidenceId>,
    pub fact_refs: Vec<SecurityFactId>,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub finding_refs: Vec<FindingId>,
    pub risk_refs: Vec<RiskEventId>,
    pub provenance_refs: Vec<DataSourceId>,
    pub attack_refs: Vec<BaselineAttackTechniqueRef>,
    pub redaction_status: RedactionStatus,
    pub quality: QualityBreakdown,
}

impl BaselineRecord {
    pub fn validate(&self) -> Result<(), BaselineContractError> {
        safe_hash("scope_key_hash", &self.scope_key_hash)?;
        safe_text("safe_label", &self.safe_label)?;
        if let Some(reason) = &self.degraded_reason {
            safe_text("degraded_reason", reason)?;
        }
        validate_labels("missing_visibility_flags", &self.missing_visibility_flags)?;
        validate_refs("evidence_refs", self.evidence_refs.len())?;
        validate_refs("fact_refs", self.fact_refs.len())?;
        validate_refs("hypothesis_refs", self.hypothesis_refs.len())?;
        validate_refs("finding_refs", self.finding_refs.len())?;
        validate_refs("risk_refs", self.risk_refs.len())?;
        validate_refs("provenance_refs", self.provenance_refs.len())?;
        validate_refs("attack_refs", self.attack_refs.len())?;
        for attack_ref in &self.attack_refs {
            attack_ref.validate()?;
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(BaselineContractError::UnsafeClaim(
                "baseline records must be redacted before exposure",
            ));
        }
        self.quality
            .validate()
            .map_err(|_| BaselineContractError::UnsafeField("baseline.quality"))?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BaselineIndicator {
    pub indicator_id: BaselineIndicatorId,
    pub kind: BaselineIndicatorKind,
    pub baseline_refs: Vec<BaselineRecordId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub fact_refs: Vec<SecurityFactId>,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub confidence_bucket: FusionConfidenceBucket,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub summary_redacted: String,
    pub quality: QualityBreakdown,
}

impl BaselineIndicator {
    pub fn validate(&self) -> Result<(), BaselineContractError> {
        validate_refs("baseline_refs", self.baseline_refs.len())?;
        validate_refs("evidence_refs", self.evidence_refs.len())?;
        validate_refs("fact_refs", self.fact_refs.len())?;
        validate_refs("hypothesis_refs", self.hypothesis_refs.len())?;
        safe_text("summary_redacted", &self.summary_redacted)?;
        if let Some(reason) = &self.degraded_reason {
            safe_text("degraded_reason", reason)?;
        }
        validate_labels("missing_visibility_flags", &self.missing_visibility_flags)?;
        self.quality
            .validate()
            .map_err(|_| BaselineContractError::UnsafeField("indicator.quality"))?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReliabilitySummary {
    pub source_id: MetadataWatchSourceId,
    pub source_health_state: String,
    pub reliability_bucket: SourceReliabilityBucket,
    pub sampled_count_bucket: BaselineCountBucket,
    pub malformed_count_bucket: BaselineCountBucket,
    pub backpressure_count_bucket: BaselineCountBucket,
    pub degraded_reason: Option<String>,
    pub evidence_refs: Vec<EvidenceId>,
    pub quality: QualityBreakdown,
}

impl SourceReliabilitySummary {
    pub fn validate(&self) -> Result<(), BaselineContractError> {
        safe_text("source_health_state", &self.source_health_state)?;
        if let Some(reason) = &self.degraded_reason {
            safe_text("degraded_reason", reason)?;
        }
        validate_refs("evidence_refs", self.evidence_refs.len())?;
        self.quality
            .validate()
            .map_err(|_| BaselineContractError::UnsafeField("source_reliability.quality"))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentLinkedHypothesisGroup {
    pub group_id: IncidentLinkedGroupId,
    pub incident_id: Option<IncidentId>,
    pub group_key_hash: String,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub fact_refs: Vec<SecurityFactId>,
    pub finding_refs: Vec<FindingId>,
    pub risk_refs: Vec<RiskEventId>,
    pub baseline_refs: Vec<BaselineRecordId>,
    pub attack_refs: Vec<BaselineAttackTechniqueRef>,
    pub graph_refs: Vec<GraphHintId>,
    pub confidence_trend: BaselineConfidenceTrendBucket,
    pub severity_trend: BaselineTrendBucket,
    pub first_seen_bucket: Option<Timestamp>,
    pub last_updated_bucket: Option<Timestamp>,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub report_section_refs: Vec<ReportSectionId>,
    pub quality: QualityBreakdown,
    pub weak_merge_warning: bool,
    pub broad_provider_only_merge_rejected: bool,
}

impl IncidentLinkedHypothesisGroup {
    pub fn validate(&self) -> Result<(), BaselineContractError> {
        safe_hash("group_key_hash", &self.group_key_hash)?;
        validate_refs("hypothesis_refs", self.hypothesis_refs.len())?;
        validate_refs("evidence_refs", self.evidence_refs.len())?;
        validate_refs("fact_refs", self.fact_refs.len())?;
        validate_refs("finding_refs", self.finding_refs.len())?;
        validate_refs("risk_refs", self.risk_refs.len())?;
        validate_refs("baseline_refs", self.baseline_refs.len())?;
        validate_refs("attack_refs", self.attack_refs.len())?;
        validate_refs("graph_refs", self.graph_refs.len())?;
        validate_refs("report_section_refs", self.report_section_refs.len())?;
        if self.hypothesis_refs.is_empty() || self.evidence_refs.is_empty() {
            return Err(BaselineContractError::UnsafeClaim(
                "incident-linked groups must be hypothesis and evidence backed",
            ));
        }
        if let Some(reason) = &self.degraded_reason {
            safe_text("degraded_reason", reason)?;
        }
        validate_labels("missing_visibility_flags", &self.missing_visibility_flags)?;
        for attack_ref in &self.attack_refs {
            attack_ref.validate()?;
        }
        self.quality
            .validate()
            .map_err(|_| BaselineContractError::UnsafeField("group.quality"))?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentTimelineEntry {
    pub timeline_entry_id: IncidentTimelineEntryId,
    pub incident_id: Option<IncidentId>,
    pub group_id: IncidentLinkedGroupId,
    pub time_bucket: Timestamp,
    pub event_category: String,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub fact_refs: Vec<SecurityFactId>,
    pub finding_refs: Vec<FindingId>,
    pub risk_refs: Vec<RiskEventId>,
    pub baseline_refs: Vec<BaselineRecordId>,
    pub attack_refs: Vec<BaselineAttackTechniqueRef>,
    pub source_health_refs: Vec<MetadataWatchSourceId>,
    pub confidence_bucket: FusionConfidenceBucket,
    pub degraded_reason: Option<String>,
    pub summary_redacted: String,
    pub quality: QualityBreakdown,
}

impl IncidentTimelineEntry {
    pub fn validate(&self) -> Result<(), BaselineContractError> {
        safe_text("event_category", &self.event_category)?;
        safe_text("summary_redacted", &self.summary_redacted)?;
        validate_refs("hypothesis_refs", self.hypothesis_refs.len())?;
        validate_refs("evidence_refs", self.evidence_refs.len())?;
        validate_refs("fact_refs", self.fact_refs.len())?;
        validate_refs("finding_refs", self.finding_refs.len())?;
        validate_refs("risk_refs", self.risk_refs.len())?;
        validate_refs("baseline_refs", self.baseline_refs.len())?;
        validate_refs("attack_refs", self.attack_refs.len())?;
        validate_refs("source_health_refs", self.source_health_refs.len())?;
        if self.hypothesis_refs.is_empty() || self.evidence_refs.is_empty() {
            return Err(BaselineContractError::UnsafeClaim(
                "timeline entries must be hypothesis and evidence backed",
            ));
        }
        if let Some(reason) = &self.degraded_reason {
            safe_text("degraded_reason", reason)?;
        }
        for attack_ref in &self.attack_refs {
            attack_ref.validate()?;
        }
        self.quality
            .validate()
            .map_err(|_| BaselineContractError::UnsafeField("timeline.quality"))?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselinePersistenceStatus {
    pub mode: BaselinePersistenceMode,
    pub automatic_durable_persistence: bool,
    pub explicit_export_allowed: bool,
    pub durable_security_history_written: bool,
    pub storage_boundary: String,
    pub degraded_reason: Option<String>,
}

impl BaselinePersistenceStatus {
    pub fn portable_no_retention() -> Self {
        Self {
            mode: BaselinePersistenceMode::PortableNoRetention,
            automatic_durable_persistence: false,
            explicit_export_allowed: true,
            durable_security_history_written: false,
            storage_boundary: "session_memory_with_explicit_export_refs_only".to_string(),
            degraded_reason: Some("portable_no_retention".to_string()),
        }
    }

    pub fn validate(&self) -> Result<(), BaselineContractError> {
        safe_text("storage_boundary", &self.storage_boundary)?;
        if let Some(reason) = &self.degraded_reason {
            safe_text("degraded_reason", reason)?;
        }
        if self.automatic_durable_persistence || self.durable_security_history_written {
            return Err(BaselineContractError::UnsafeClaim(
                "portable baselines cannot be automatically persisted",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DurableBaselineSummary {
    pub generated_at: Timestamp,
    pub scope: BaselineScope,
    pub persistence_status: BaselinePersistenceStatus,
    pub baseline_count: u32,
    pub indicator_count: u32,
    pub incident_group_count: u32,
    pub timeline_entry_count: u32,
    pub source_reliability_count: u32,
    pub records: Vec<BaselineRecord>,
    pub indicators: Vec<BaselineIndicator>,
    pub incident_groups: Vec<IncidentLinkedHypothesisGroup>,
    pub incident_timeline: Vec<IncidentTimelineEntry>,
    pub source_reliability: Vec<SourceReliabilitySummary>,
    pub baseline_refs: Vec<BaselineRecordId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub fact_refs: Vec<SecurityFactId>,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub finding_refs: Vec<FindingId>,
    pub risk_refs: Vec<RiskEventId>,
    pub attack_refs: Vec<BaselineAttackTechniqueRef>,
    pub provenance_refs: Vec<DataSourceId>,
    pub degraded_visibility_context: Vec<String>,
    pub missing_visibility_flags: Vec<String>,
    pub quality: QualityBreakdown,
    pub report_ref_count: u32,
    pub export_ref_count: u32,
    pub automatic_llm_calls: bool,
    pub response_execution: bool,
}

impl DurableBaselineSummary {
    pub fn validate(&self) -> Result<(), BaselineContractError> {
        self.persistence_status.validate()?;
        validate_items("records", self.records.len())?;
        validate_items("indicators", self.indicators.len())?;
        validate_items("incident_groups", self.incident_groups.len())?;
        validate_items("incident_timeline", self.incident_timeline.len())?;
        validate_items("source_reliability", self.source_reliability.len())?;
        validate_refs("baseline_refs", self.baseline_refs.len())?;
        validate_refs("evidence_refs", self.evidence_refs.len())?;
        validate_refs("fact_refs", self.fact_refs.len())?;
        validate_refs("hypothesis_refs", self.hypothesis_refs.len())?;
        validate_refs("finding_refs", self.finding_refs.len())?;
        validate_refs("risk_refs", self.risk_refs.len())?;
        validate_refs("attack_refs", self.attack_refs.len())?;
        validate_refs("provenance_refs", self.provenance_refs.len())?;
        validate_labels(
            "degraded_visibility_context",
            &self.degraded_visibility_context,
        )?;
        validate_labels("missing_visibility_flags", &self.missing_visibility_flags)?;
        self.quality
            .validate()
            .map_err(|_| BaselineContractError::UnsafeField("summary.quality"))?;
        if self.automatic_llm_calls || self.response_execution {
            return Err(BaselineContractError::UnsafeClaim(
                "baseline refresh cannot trigger LLM calls or response execution",
            ));
        }
        for record in &self.records {
            record.validate()?;
        }
        for indicator in &self.indicators {
            indicator.validate()?;
        }
        for group in &self.incident_groups {
            group.validate()?;
        }
        for entry in &self.incident_timeline {
            entry.validate()?;
        }
        for reliability in &self.source_reliability {
            reliability.validate()?;
        }
        for attack_ref in &self.attack_refs {
            attack_ref.validate()?;
        }
        Ok(())
    }
}

fn validate_items(field: &'static str, len: usize) -> Result<(), BaselineContractError> {
    if len > MAX_BASELINE_ITEMS {
        return Err(BaselineContractError::ExceedsBound(field));
    }
    Ok(())
}

fn validate_refs(field: &'static str, len: usize) -> Result<(), BaselineContractError> {
    if len > MAX_BASELINE_REFS {
        return Err(BaselineContractError::ExceedsBound(field));
    }
    Ok(())
}

fn validate_labels(field: &'static str, values: &[String]) -> Result<(), BaselineContractError> {
    if values.len() > MAX_BASELINE_LABELS {
        return Err(BaselineContractError::ExceedsBound(field));
    }
    for value in values {
        safe_text(field, value)?;
    }
    Ok(())
}

fn safe_hash(field: &'static str, value: &str) -> Result<(), BaselineContractError> {
    let rest = value
        .strip_prefix("sha256:")
        .ok_or(BaselineContractError::UnsafeField(field))?;
    if rest.len() < 12
        || rest.len() > 64
        || !rest.chars().all(|character| character.is_ascii_hexdigit())
    {
        return Err(BaselineContractError::UnsafeField(field));
    }
    Ok(())
}

fn safe_text(field: &'static str, value: &str) -> Result<(), BaselineContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(BaselineContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_BASELINE_SAFE_TEXT_BYTES
        || trimmed.contains("://")
        || trimmed.contains('@')
        || trimmed.contains('\\')
        || trimmed.contains('/')
        || looks_like_ip(trimmed)
        || FORBIDDEN_MARKERS
            .iter()
            .any(|marker| trimmed.to_ascii_lowercase().contains(marker))
    {
        return Err(BaselineContractError::UnsafeField(field));
    }
    Ok(())
}

fn looks_like_ip(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
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
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_records_reject_sensitive_values() {
        let mut record = baseline_record();
        record.safe_label = "https://example.test/private".to_string();
        assert!(matches!(
            record.validate(),
            Err(BaselineContractError::UnsafeField(_))
        ));
    }

    #[test]
    fn persistence_status_blocks_automatic_durable_security_history() {
        let mut status = BaselinePersistenceStatus::portable_no_retention();
        status.automatic_durable_persistence = true;
        assert!(matches!(
            status.validate(),
            Err(BaselineContractError::UnsafeClaim(_))
        ));
    }

    #[test]
    fn baseline_summary_blocks_llm_and_response_execution() {
        let mut summary = DurableBaselineSummary {
            generated_at: Timestamp::now(),
            scope: BaselineScope::CurrentSession,
            persistence_status: BaselinePersistenceStatus::portable_no_retention(),
            baseline_count: 1,
            indicator_count: 0,
            incident_group_count: 0,
            timeline_entry_count: 0,
            source_reliability_count: 0,
            records: vec![baseline_record()],
            indicators: Vec::new(),
            incident_groups: Vec::new(),
            incident_timeline: Vec::new(),
            source_reliability: Vec::new(),
            baseline_refs: Vec::new(),
            evidence_refs: Vec::new(),
            fact_refs: Vec::new(),
            hypothesis_refs: Vec::new(),
            finding_refs: Vec::new(),
            risk_refs: Vec::new(),
            attack_refs: Vec::new(),
            provenance_refs: Vec::new(),
            degraded_visibility_context: vec!["metadata_only_visibility".to_string()],
            missing_visibility_flags: vec!["no_process_visibility".to_string()],
            quality: QualityBreakdown::metadata_only(),
            report_ref_count: 0,
            export_ref_count: 0,
            automatic_llm_calls: true,
            response_execution: false,
        };
        assert!(matches!(
            summary.validate(),
            Err(BaselineContractError::UnsafeClaim(_))
        ));
        summary.automatic_llm_calls = false;
        summary.response_execution = true;
        assert!(matches!(
            summary.validate(),
            Err(BaselineContractError::UnsafeClaim(_))
        ));
    }

    fn baseline_record() -> BaselineRecord {
        BaselineRecord {
            baseline_id: BaselineRecordId::new_v4(),
            scope: BaselineScope::ProviderCategory,
            category: BaselineCategory::SecurityFact,
            scope_key_hash: "sha256:0123456789abcdef".to_string(),
            safe_label: "provider_category".to_string(),
            count_bucket: BaselineCountBucket::Single,
            first_seen_time_bucket: Some(Timestamp::now()),
            last_seen_time_bucket: Some(Timestamp::now()),
            recurrence_bucket: BaselineRecurrenceBucket::FirstSeen,
            rarity_bucket: BaselineRarityBucket::FirstSeen,
            trend_bucket: BaselineTrendBucket::Flat,
            confidence_trend_bucket: BaselineConfidenceTrendBucket::StableLow,
            source_reliability_bucket: SourceReliabilityBucket::Weak,
            degraded_reason: Some("metadata_only_visibility".to_string()),
            missing_visibility_flags: vec!["metadata_only_visibility".to_string()],
            evidence_refs: vec![EvidenceId::new_v4()],
            fact_refs: vec![SecurityFactId::new_v4()],
            hypothesis_refs: Vec::new(),
            finding_refs: Vec::new(),
            risk_refs: Vec::new(),
            provenance_refs: Vec::new(),
            attack_refs: Vec::new(),
            redaction_status: RedactionStatus::Redacted,
            quality: QualityBreakdown::metadata_only(),
        }
    }
}
