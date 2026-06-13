use crate::common::{
    AttackHypothesisId, BaselineIndicatorId, BaselineRecordId, DataSourceId, EvidenceId,
    EvidenceQualityId, ExportResultId, FindingId, GraphHintId, IncidentLinkedGroupId,
    ReportSectionId, RiskEventId, SecurityFactId, Timestamp,
};
use crate::graph::RedactionStatus;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_QUALITY_RECORDS: usize = 128;
pub const MAX_QUALITY_REFS: usize = 64;
pub const MAX_QUALITY_LABELS: usize = 32;
const MAX_QUALITY_TEXT_BYTES: usize = 180;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceQualityContractError {
    EmptyField(&'static str),
    UnsafeField(&'static str),
    ExceedsBound(&'static str),
    UnsafeClaim(&'static str),
}

impl fmt::Display for EvidenceQualityContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains unsafe metadata"),
            Self::ExceedsBound(field) => write!(formatter, "{field} exceeds bounded limits"),
            Self::UnsafeClaim(reason) => {
                write!(formatter, "unsafe evidence quality claim: {reason}")
            }
        }
    }
}

impl std::error::Error for EvidenceQualityContractError {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceQualityBucket {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
    Blocked,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceReliabilityQualityBucket {
    #[default]
    Unknown,
    Weak,
    Degraded,
    Stable,
    Corroborated,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionCompletenessBucket {
    #[default]
    Unknown,
    Complete,
    Partial,
    Incomplete,
    UnsafeBlocked,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceQualityBucket {
    #[default]
    Unknown,
    Present,
    ReferenceOnly,
    Missing,
    Degraded,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationQualityBucket {
    #[default]
    None,
    SingleSignal,
    Limited,
    Corroborated,
    Diverse,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityCompletenessBucket {
    #[default]
    Unknown,
    MetadataOnly,
    Partial,
    Degraded,
    RequiresAuthorizedNative,
    Unsupported,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessBucket {
    #[default]
    Unknown,
    CurrentSession,
    Recent,
    Stale,
    DemoStale,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicationStatusBucket {
    #[default]
    Unknown,
    Unique,
    DuplicateSuppressed,
    Repeated,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalInfluenceBucket {
    #[default]
    None,
    MalformedSkipped,
    OversizedSkipped,
    Backpressure,
    SourceUnavailable,
    RevokedOrDisabled,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeVisibilityStateCategory {
    #[default]
    NotApplicable,
    PortableDefaultNoTelemetry,
    PermissionGrantedSamplerInactive,
    Revoked,
    Unavailable,
    FutureTelemetryAbsent,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceFreshnessCategory {
    #[default]
    Unknown,
    Current,
    Stale,
    DemoOnly,
    NotUsed,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrengthBucket {
    #[default]
    None,
    WeakSingleSignal,
    Moderate,
    StrongCorroborated,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncertaintyBucket {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuitabilityBucket {
    #[default]
    Unknown,
    Suitable,
    Degraded,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceQualityTargetKind {
    Evidence,
    Finding,
    Hypothesis,
    Risk,
    AttackMapping,
    BaselineIndicator,
    BaselineRecord,
    IncidentLinkedGroup,
    Graph,
    ReportSection,
    ExportArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityBreakdown {
    pub evidence_quality_bucket: EvidenceQualityBucket,
    pub source_reliability_bucket: SourceReliabilityQualityBucket,
    pub redaction_completeness_bucket: RedactionCompletenessBucket,
    pub provenance_quality_bucket: ProvenanceQualityBucket,
    pub correlation_quality_bucket: CorrelationQualityBucket,
    pub visibility_completeness_bucket: VisibilityCompletenessBucket,
    pub freshness_bucket: FreshnessBucket,
    pub duplication_status_bucket: DuplicationStatusBucket,
    pub operational_influence_bucket: OperationalInfluenceBucket,
    pub native_visibility_state: NativeVisibilityStateCategory,
    pub intelligence_freshness: IntelligenceFreshnessCategory,
    pub evidence_strength_bucket: EvidenceStrengthBucket,
    pub uncertainty_bucket: UncertaintyBucket,
    pub report_suitability_bucket: SuitabilityBucket,
    pub export_suitability_bucket: SuitabilityBucket,
    pub degraded_reasons: Vec<String>,
    pub missing_visibility_flags: Vec<String>,
    pub quality_refs: Vec<EvidenceQualityId>,
}

impl Default for QualityBreakdown {
    fn default() -> Self {
        Self::metadata_only()
    }
}

impl QualityBreakdown {
    pub fn metadata_only() -> Self {
        Self {
            evidence_quality_bucket: EvidenceQualityBucket::Low,
            source_reliability_bucket: SourceReliabilityQualityBucket::Weak,
            redaction_completeness_bucket: RedactionCompletenessBucket::Complete,
            provenance_quality_bucket: ProvenanceQualityBucket::ReferenceOnly,
            correlation_quality_bucket: CorrelationQualityBucket::SingleSignal,
            visibility_completeness_bucket: VisibilityCompletenessBucket::MetadataOnly,
            freshness_bucket: FreshnessBucket::CurrentSession,
            duplication_status_bucket: DuplicationStatusBucket::Unknown,
            operational_influence_bucket: OperationalInfluenceBucket::None,
            native_visibility_state: NativeVisibilityStateCategory::PortableDefaultNoTelemetry,
            intelligence_freshness: IntelligenceFreshnessCategory::NotUsed,
            evidence_strength_bucket: EvidenceStrengthBucket::WeakSingleSignal,
            uncertainty_bucket: UncertaintyBucket::High,
            report_suitability_bucket: SuitabilityBucket::Degraded,
            export_suitability_bucket: SuitabilityBucket::Degraded,
            degraded_reasons: vec!["metadata_only_visibility".to_string()],
            missing_visibility_flags: vec![
                "no_process_visibility".to_string(),
                "no_packet_visibility".to_string(),
            ],
            quality_refs: Vec::new(),
        }
    }

    pub fn corroborated_metadata() -> Self {
        Self {
            evidence_quality_bucket: EvidenceQualityBucket::Medium,
            source_reliability_bucket: SourceReliabilityQualityBucket::Stable,
            correlation_quality_bucket: CorrelationQualityBucket::Corroborated,
            evidence_strength_bucket: EvidenceStrengthBucket::Moderate,
            uncertainty_bucket: UncertaintyBucket::Medium,
            report_suitability_bucket: SuitabilityBucket::Suitable,
            export_suitability_bucket: SuitabilityBucket::Suitable,
            degraded_reasons: vec!["metadata_only_visibility".to_string()],
            missing_visibility_flags: vec![
                "no_process_visibility".to_string(),
                "no_packet_visibility".to_string(),
            ],
            ..Self::metadata_only()
        }
    }

    pub fn blocked_by_redaction() -> Self {
        Self {
            evidence_quality_bucket: EvidenceQualityBucket::Blocked,
            redaction_completeness_bucket: RedactionCompletenessBucket::UnsafeBlocked,
            report_suitability_bucket: SuitabilityBucket::Blocked,
            export_suitability_bucket: SuitabilityBucket::Blocked,
            degraded_reasons: vec!["redaction_incomplete_or_unsafe".to_string()],
            missing_visibility_flags: vec!["safe_redaction_unavailable".to_string()],
            ..Self::metadata_only()
        }
    }

    pub fn with_quality_ref(mut self, quality_ref: EvidenceQualityId) -> Self {
        if !self.quality_refs.contains(&quality_ref) && self.quality_refs.len() < MAX_QUALITY_REFS {
            self.quality_refs.push(quality_ref);
        }
        self
    }

    pub fn validate(&self) -> Result<(), EvidenceQualityContractError> {
        validate_labels("quality.degraded_reasons", &self.degraded_reasons)?;
        validate_labels(
            "quality.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        validate_ref_count("quality.quality_refs", self.quality_refs.len())?;
        if self.redaction_completeness_bucket == RedactionCompletenessBucket::UnsafeBlocked
            && (self.report_suitability_bucket != SuitabilityBucket::Blocked
                || self.export_suitability_bucket != SuitabilityBucket::Blocked)
        {
            return Err(EvidenceQualityContractError::UnsafeClaim(
                "unsafe redaction must block report and export suitability",
            ));
        }
        if self.native_visibility_state
            == NativeVisibilityStateCategory::PermissionGrantedSamplerInactive
            && self.evidence_quality_bucket == EvidenceQualityBucket::High
        {
            return Err(EvidenceQualityContractError::UnsafeClaim(
                "permission status alone cannot produce high evidence quality",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceQualityRecord {
    pub evidence_quality_id: EvidenceQualityId,
    pub target_kind: EvidenceQualityTargetKind,
    pub evidence_ref: Option<EvidenceId>,
    pub finding_ref: Option<FindingId>,
    pub hypothesis_ref: Option<AttackHypothesisId>,
    pub risk_ref: Option<RiskEventId>,
    pub baseline_ref: Option<BaselineRecordId>,
    pub baseline_indicator_ref: Option<BaselineIndicatorId>,
    pub attack_ref: Option<String>,
    pub graph_ref: Option<GraphHintId>,
    pub incident_group_ref: Option<IncidentLinkedGroupId>,
    pub report_section_ref: Option<ReportSectionId>,
    pub export_result_ref: Option<ExportResultId>,
    pub fact_refs: Vec<SecurityFactId>,
    pub source_kind_category: String,
    pub parser_family: String,
    pub detector_id: Option<String>,
    pub detector_confidence_bucket: EvidenceQualityBucket,
    pub unsafe_field_rejection_bucket: EvidenceQualityBucket,
    pub malformed_skipped_backpressure_bucket: OperationalInfluenceBucket,
    pub redaction_status: RedactionStatus,
    pub provenance_id: Option<DataSourceId>,
    pub time_bucket: Timestamp,
    pub quality: QualityBreakdown,
}

impl EvidenceQualityRecord {
    pub fn validate(&self) -> Result<(), EvidenceQualityContractError> {
        safe_text("quality.source_kind_category", &self.source_kind_category)?;
        safe_text("quality.parser_family", &self.parser_family)?;
        optional_safe_text("quality.detector_id", self.detector_id.as_deref())?;
        optional_safe_id("quality.attack_ref", self.attack_ref.as_deref())?;
        validate_ref_count("quality.fact_refs", self.fact_refs.len())?;
        self.quality.validate()?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(EvidenceQualityContractError::UnsafeClaim(
                "quality records cannot expose redaction-required targets",
            ));
        }
        if self.has_no_target_ref() {
            return Err(EvidenceQualityContractError::UnsafeClaim(
                "quality records must reference a bounded target",
            ));
        }
        Ok(())
    }

    fn has_no_target_ref(&self) -> bool {
        self.evidence_ref.is_none()
            && self.finding_ref.is_none()
            && self.hypothesis_ref.is_none()
            && self.risk_ref.is_none()
            && self.baseline_ref.is_none()
            && self.baseline_indicator_ref.is_none()
            && self.attack_ref.is_none()
            && self.graph_ref.is_none()
            && self.incident_group_ref.is_none()
            && self.report_section_ref.is_none()
            && self.export_result_ref.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceQualitySummary {
    pub generated_at: Timestamp,
    pub record_count: u32,
    pub weak_single_signal_count: u32,
    pub corroborated_count: u32,
    pub report_suitable_count: u32,
    pub export_suitable_count: u32,
    pub blocked_count: u32,
    pub records: Vec<EvidenceQualityRecord>,
    pub quality_refs: Vec<EvidenceQualityId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub finding_refs: Vec<FindingId>,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub risk_refs: Vec<RiskEventId>,
    pub baseline_refs: Vec<BaselineRecordId>,
    pub incident_group_refs: Vec<IncidentLinkedGroupId>,
    pub report_section_refs: Vec<ReportSectionId>,
    pub export_result_refs: Vec<ExportResultId>,
    pub degraded_reason_summary: Vec<String>,
    pub missing_visibility_flags: Vec<String>,
    pub portable_no_retention: bool,
    pub metadata_only: bool,
    pub automatic_llm_calls: bool,
    pub response_execution: bool,
}

impl EvidenceQualitySummary {
    pub fn validate(&self) -> Result<(), EvidenceQualityContractError> {
        validate_record_count("quality.records", self.records.len())?;
        validate_ref_count("quality.quality_refs", self.quality_refs.len())?;
        validate_ref_count("quality.evidence_refs", self.evidence_refs.len())?;
        validate_ref_count("quality.finding_refs", self.finding_refs.len())?;
        validate_ref_count("quality.hypothesis_refs", self.hypothesis_refs.len())?;
        validate_ref_count("quality.risk_refs", self.risk_refs.len())?;
        validate_ref_count("quality.baseline_refs", self.baseline_refs.len())?;
        validate_ref_count(
            "quality.incident_group_refs",
            self.incident_group_refs.len(),
        )?;
        validate_ref_count(
            "quality.report_section_refs",
            self.report_section_refs.len(),
        )?;
        validate_ref_count("quality.export_result_refs", self.export_result_refs.len())?;
        validate_labels(
            "quality.degraded_reason_summary",
            &self.degraded_reason_summary,
        )?;
        validate_labels(
            "quality.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        if !self.portable_no_retention
            || !self.metadata_only
            || self.automatic_llm_calls
            || self.response_execution
        {
            return Err(EvidenceQualityContractError::UnsafeClaim(
                "quality refresh must remain metadata-only, no-retention, and non-executing",
            ));
        }
        if self.record_count != self.records.len() as u32 {
            return Err(EvidenceQualityContractError::UnsafeClaim(
                "quality record_count must match bounded records",
            ));
        }
        for record in &self.records {
            record.validate()?;
        }
        Ok(())
    }
}

fn validate_record_count(
    field: &'static str,
    len: usize,
) -> Result<(), EvidenceQualityContractError> {
    if len > MAX_QUALITY_RECORDS {
        return Err(EvidenceQualityContractError::ExceedsBound(field));
    }
    Ok(())
}

fn validate_ref_count(field: &'static str, len: usize) -> Result<(), EvidenceQualityContractError> {
    if len > MAX_QUALITY_REFS {
        return Err(EvidenceQualityContractError::ExceedsBound(field));
    }
    Ok(())
}

fn validate_labels(
    field: &'static str,
    values: &[String],
) -> Result<(), EvidenceQualityContractError> {
    if values.len() > MAX_QUALITY_LABELS {
        return Err(EvidenceQualityContractError::ExceedsBound(field));
    }
    for value in values {
        safe_text(field, value)?;
    }
    Ok(())
}

fn optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), EvidenceQualityContractError> {
    if let Some(value) = value {
        safe_text(field, value)?;
    }
    Ok(())
}

fn optional_safe_id(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), EvidenceQualityContractError> {
    if let Some(value) = value {
        safe_text(field, value)?;
        if !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_:.".contains(character))
        {
            return Err(EvidenceQualityContractError::UnsafeField(field));
        }
    }
    Ok(())
}

fn safe_text(field: &'static str, value: &str) -> Result<(), EvidenceQualityContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(EvidenceQualityContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_QUALITY_TEXT_BYTES
        || trimmed.contains("://")
        || trimmed.contains('@')
        || trimmed.contains('\\')
        || trimmed.contains('/')
        || trimmed.parse::<std::net::IpAddr>().is_ok()
        || FORBIDDEN_MARKERS
            .iter()
            .any(|marker| trimmed.to_ascii_lowercase().contains(marker))
    {
        return Err(EvidenceQualityContractError::UnsafeField(field));
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
    "raw_line",
    "raw_file",
    "raw_json",
    "raw_packet",
    "packet_bytes",
    "http_body",
    "query_param",
    "query_string",
    "header",
    "username",
    "email",
    "tenant_id",
    "account_id",
    "device_id",
    "process_name",
    "process_id",
    "command_line",
    "registry_key",
    "local_path",
    "file_path",
    "filename",
    "certificate",
    "private_marker",
    "confirmed_compromise",
    "credential_theft",
    "host_compromise",
    "malware_execution",
    "full_capture",
    "response_execution",
    "active_scan",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_breakdown_blocks_unsafe_redaction_suitability() {
        let mut quality = QualityBreakdown::metadata_only();
        quality.redaction_completeness_bucket = RedactionCompletenessBucket::UnsafeBlocked;
        quality.report_suitability_bucket = SuitabilityBucket::Suitable;
        assert!(matches!(
            quality.validate(),
            Err(EvidenceQualityContractError::UnsafeClaim(_))
        ));
    }

    #[test]
    fn permission_status_alone_cannot_raise_quality_to_high() {
        let mut quality = QualityBreakdown::metadata_only();
        quality.native_visibility_state =
            NativeVisibilityStateCategory::PermissionGrantedSamplerInactive;
        quality.evidence_quality_bucket = EvidenceQualityBucket::High;
        assert!(matches!(
            quality.validate(),
            Err(EvidenceQualityContractError::UnsafeClaim(_))
        ));
    }

    #[test]
    fn quality_record_rejects_sensitive_values() {
        let mut record = safe_record();
        record.detector_id = Some("https://example.test/path?token=secret".to_string());
        assert!(matches!(
            record.validate(),
            Err(EvidenceQualityContractError::UnsafeField(_))
        ));
    }

    #[test]
    fn quality_summary_is_metadata_only_and_non_executing() {
        let record = safe_record();
        let summary = EvidenceQualitySummary {
            generated_at: Timestamp::now(),
            record_count: 1,
            weak_single_signal_count: 1,
            corroborated_count: 0,
            report_suitable_count: 0,
            export_suitable_count: 0,
            blocked_count: 0,
            quality_refs: vec![record.evidence_quality_id.clone()],
            evidence_refs: vec![record.evidence_ref.clone().expect("evidence")],
            finding_refs: Vec::new(),
            hypothesis_refs: Vec::new(),
            risk_refs: Vec::new(),
            baseline_refs: Vec::new(),
            incident_group_refs: Vec::new(),
            report_section_refs: Vec::new(),
            export_result_refs: Vec::new(),
            degraded_reason_summary: vec!["metadata_only_visibility".to_string()],
            missing_visibility_flags: vec!["no_process_visibility".to_string()],
            records: vec![record],
            portable_no_retention: true,
            metadata_only: true,
            automatic_llm_calls: false,
            response_execution: false,
        };
        summary.validate().expect("safe quality summary");
    }

    fn safe_record() -> EvidenceQualityRecord {
        EvidenceQualityRecord {
            evidence_quality_id: EvidenceQualityId::new_v4(),
            target_kind: EvidenceQualityTargetKind::Evidence,
            evidence_ref: Some(EvidenceId::new_v4()),
            finding_ref: None,
            hypothesis_ref: None,
            risk_ref: None,
            baseline_ref: None,
            baseline_indicator_ref: None,
            attack_ref: None,
            graph_ref: None,
            incident_group_ref: None,
            report_section_ref: None,
            export_result_ref: None,
            fact_refs: Vec::new(),
            source_kind_category: "portable_metadata".to_string(),
            parser_family: "bounded_reader".to_string(),
            detector_id: Some("portable_detector".to_string()),
            detector_confidence_bucket: EvidenceQualityBucket::Low,
            unsafe_field_rejection_bucket: EvidenceQualityBucket::Unknown,
            malformed_skipped_backpressure_bucket: OperationalInfluenceBucket::None,
            redaction_status: RedactionStatus::Redacted,
            provenance_id: Some(DataSourceId::new_v4()),
            time_bucket: Timestamp::now(),
            quality: QualityBreakdown::metadata_only(),
        }
    }
}
