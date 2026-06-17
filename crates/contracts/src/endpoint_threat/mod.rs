use crate::common::{
    AttackHypothesisId, BaselineRecordId, DataSourceId, EndpointAnalysisInputId,
    EndpointRejectedCandidateId, EndpointThreatCandidateId, EndpointThreatEvidenceId,
    EndpointThreatFindingId, EndpointThreatRiskHintId, EndpointVisibilityAdvisoryId, EvidenceId,
    FindingId, RiskEventId, SecurityFactId, SessionId, Timestamp,
};
use crate::graph::RedactionStatus;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_ENDPOINT_THREAT_REFS: usize = 64;
pub const MAX_ENDPOINT_THREAT_ATTACK_REFS: usize = 16;
pub const MAX_ENDPOINT_THREAT_VISIBILITY_FLAGS: usize = 8;
const MAX_ENDPOINT_THREAT_TEXT_BYTES: usize = 180;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointThreatContractError {
    EmptyField(&'static str),
    EmptyEvidenceRefs,
    UnsafeField(&'static str),
    ExceedsBound(&'static str),
    UnsafeClaim(&'static str),
}

impl fmt::Display for EndpointThreatContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::EmptyEvidenceRefs => {
                write!(formatter, "endpoint threat records require evidence")
            }
            Self::UnsafeField(field) => write!(formatter, "{field} contains unsafe endpoint data"),
            Self::ExceedsBound(field) => write!(formatter, "{field} exceeds bounded limits"),
            Self::UnsafeClaim(reason) => {
                write!(formatter, "unsafe endpoint threat claim: {reason}")
            }
        }
    }
}

impl std::error::Error for EndpointThreatContractError {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointThreatConfidenceBucket {
    #[default]
    Informational,
    Low,
    Moderate,
    Elevated,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointThreatSeverityBucket {
    #[default]
    Informational,
    Low,
    Moderate,
    Elevated,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointProcessCategory {
    #[default]
    Unknown,
    Browser,
    Office,
    ScriptInterpreter,
    Shell,
    ServiceHost,
    SecurityTool,
    DeveloperTool,
    SystemUtility,
    UserApplication,
    BackgroundService,
    OtherRedacted,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRelationCategory {
    #[default]
    Unknown,
    ParentChildObserved,
    ServiceHostedProcess,
    SameSessionCorrelation,
    TemporalAssociation,
    ServiceProcessCorrelation,
    Unsupported,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointExecutionContextCategory {
    #[default]
    Unknown,
    Interactive,
    Service,
    ScheduledTask,
    Startup,
    Elevated,
    Background,
    RemoteManagement,
    MetadataOnly,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointServiceCategory {
    #[default]
    Unknown,
    Security,
    Network,
    RemoteAccess,
    Update,
    Database,
    Web,
    Backup,
    Monitoring,
    System,
    ThirdParty,
    OtherRedacted,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointLifecycleBucket {
    #[default]
    Unknown,
    FirstObserved,
    Existing,
    Terminated,
    ShortLived,
    LongRunning,
    Repeated,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointServiceStateBucket {
    #[default]
    Unknown,
    Running,
    Stopped,
    Paused,
    Starting,
    Stopping,
    Disabled,
    Unavailable,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointStartupTypeBucket {
    #[default]
    Unknown,
    Auto,
    Manual,
    Disabled,
    Delayed,
    Triggered,
    NotApplicable,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointTrustSignednessBucket {
    #[default]
    Unknown,
    SignedTrusted,
    SignedUntrusted,
    Unsigned,
    Mixed,
    NotVisible,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointPrivilegeIntegrityCategory {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
    System,
    Elevated,
    Service,
    NotVisible,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointOccurrenceIndicator {
    #[default]
    Unknown,
    FirstSeen,
    Rare,
    Repeated,
    Common,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointCountChangeBucket {
    #[default]
    Unknown,
    None,
    Single,
    Low,
    Medium,
    High,
    Rising,
    Falling,
    Stable,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointFreshnessCategory {
    #[default]
    Unknown,
    Fresh,
    Aging,
    Stale,
    Missing,
    Unavailable,
    Revoked,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointSourceReliabilityBucket {
    #[default]
    Unknown,
    Weak,
    Degraded,
    Stable,
    Corroborated,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointEvidenceQualityBucket {
    #[default]
    Unknown,
    Low,
    Moderate,
    Elevated,
    Blocked,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointCorrelationQualityBucket {
    #[default]
    None,
    SingleSignal,
    Limited,
    Corroborated,
    Degraded,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointMissingVisibilityFlag {
    ProcessNetworkAttributionUnavailable,
    CommandLineVisibilityUnavailable,
    FileRegistryVisibilityUnavailable,
    PacketVisibilityUnavailable,
    SpecificProcessIdentityUnavailable,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointThreatCausalClaim {
    #[default]
    CorrelationOnly,
    TemporalAssociationOnly,
    UnsupportedCausalClaim,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointThreatCandidateCategory {
    ProcessServiceCorrelation,
    NativeHealthCorrelation,
    PortableFindingCorrelation,
    BaselineRarityCorrelation,
    PrivilegeContextCorrelation,
    TrustSignednessCorrelation,
    LifecyclePatternCorrelation,
    VisibilityLimitedSuspicion,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointThreatFindingCategory {
    EvidenceBackedEndpointAnomaly,
    EvidenceBackedServiceAnomaly,
    EvidenceBackedPrivilegeAnomaly,
    EvidenceBackedTrustAnomaly,
    EvidenceBackedLifecycleAnomaly,
    DegradedVisibilityEndpointSuspicion,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointThreatEvidenceCategory {
    ProcessCategoryMetadata,
    ParentRelationMetadata,
    ServiceCategoryMetadata,
    NativeHealthMetadata,
    PortableFindingCorrelation,
    BaselineCorrelation,
    HypothesisCorrelation,
    RiskCorrelation,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointThreatRiskCategory {
    VisibilityLimitedEndpointRisk,
    RepeatedSuspiciousCategory,
    RarePrivilegeContext,
    DegradedNativeHealthContext,
    CorrelatedPortableFindingContext,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointVisibilityAdvisoryCategory {
    ProcessNetworkAttributionUnavailable,
    CommandLineUnavailable,
    FileRegistryUnavailable,
    PacketUnavailable,
    SpecificProcessIdentityUnavailable,
    EvidenceQualityDegraded,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRejectedCandidateReason {
    UnsafeRawIdentifier,
    RedactionRequired,
    MissingEvidence,
    UnsupportedCausalClaim,
    ExceedsBoundedLimits,
    UnsafeField,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointAttackRef {
    pub tactic_id: String,
    pub technique_id: String,
    pub attack_version: String,
    pub confidence_bucket: EndpointThreatConfidenceBucket,
    pub required_visibility: Vec<EndpointMissingVisibilityFlag>,
}

impl EndpointAttackRef {
    pub fn validate(&self) -> Result<(), EndpointThreatContractError> {
        safe_attack_id("endpoint_attack_ref.tactic_id", &self.tactic_id)?;
        safe_attack_id("endpoint_attack_ref.technique_id", &self.technique_id)?;
        safe_text("endpoint_attack_ref.attack_version", &self.attack_version)?;
        validate_visibility_flags(
            "endpoint_attack_ref.required_visibility",
            &self.required_visibility,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointAnalysisInput {
    pub analysis_input_id: EndpointAnalysisInputId,
    pub session_ref: SessionId,
    pub process_fact_refs: Vec<SecurityFactId>,
    pub parent_relation_fact_refs: Vec<SecurityFactId>,
    pub service_fact_refs: Vec<SecurityFactId>,
    pub native_health_fact_refs: Vec<SecurityFactId>,
    pub portable_finding_refs: Vec<FindingId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub baseline_refs: Vec<BaselineRecordId>,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub risk_refs: Vec<RiskEventId>,
    pub attack_refs: Vec<EndpointAttackRef>,
    pub process_category: EndpointProcessCategory,
    pub parent_process_category: EndpointProcessCategory,
    pub relation_category: EndpointRelationCategory,
    pub execution_context_category: EndpointExecutionContextCategory,
    pub service_category: EndpointServiceCategory,
    pub process_lifecycle_bucket: EndpointLifecycleBucket,
    pub service_state_bucket: EndpointServiceStateBucket,
    pub startup_type_bucket: EndpointStartupTypeBucket,
    pub trust_signedness_bucket: EndpointTrustSignednessBucket,
    pub privilege_integrity_category: EndpointPrivilegeIntegrityCategory,
    pub occurrence_indicator: EndpointOccurrenceIndicator,
    pub count_change_bucket: EndpointCountChangeBucket,
    pub time_bucket: Timestamp,
    pub freshness_category: EndpointFreshnessCategory,
    pub source_reliability_bucket: EndpointSourceReliabilityBucket,
    pub evidence_quality_bucket: EndpointEvidenceQualityBucket,
    pub correlation_quality_bucket: EndpointCorrelationQualityBucket,
    pub missing_visibility_flags: Vec<EndpointMissingVisibilityFlag>,
    pub provenance_id: DataSourceId,
    pub redaction_status: RedactionStatus,
}

impl EndpointAnalysisInput {
    pub fn validate(&self) -> Result<(), EndpointThreatContractError> {
        validate_ref_count(
            "endpoint_input.process_fact_refs",
            self.process_fact_refs.len(),
        )?;
        validate_ref_count(
            "endpoint_input.parent_relation_fact_refs",
            self.parent_relation_fact_refs.len(),
        )?;
        validate_ref_count(
            "endpoint_input.service_fact_refs",
            self.service_fact_refs.len(),
        )?;
        validate_ref_count(
            "endpoint_input.native_health_fact_refs",
            self.native_health_fact_refs.len(),
        )?;
        validate_ref_count(
            "endpoint_input.portable_finding_refs",
            self.portable_finding_refs.len(),
        )?;
        require_evidence_refs("endpoint_input.evidence_refs", &self.evidence_refs)?;
        validate_ref_count("endpoint_input.baseline_refs", self.baseline_refs.len())?;
        validate_ref_count("endpoint_input.hypothesis_refs", self.hypothesis_refs.len())?;
        validate_ref_count("endpoint_input.risk_refs", self.risk_refs.len())?;
        validate_attack_refs(&self.attack_refs)?;
        validate_visibility_flags(
            "endpoint_input.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        require_redacted_status("endpoint_input.redaction_status", &self.redaction_status)?;
        if self.has_no_metadata_refs() {
            return Err(EndpointThreatContractError::UnsafeClaim(
                "endpoint analysis input must reference bounded metadata",
            ));
        }
        Ok(())
    }

    fn has_no_metadata_refs(&self) -> bool {
        self.process_fact_refs.is_empty()
            && self.parent_relation_fact_refs.is_empty()
            && self.service_fact_refs.is_empty()
            && self.native_health_fact_refs.is_empty()
            && self.portable_finding_refs.is_empty()
            && self.baseline_refs.is_empty()
            && self.hypothesis_refs.is_empty()
            && self.risk_refs.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointThreatCandidate {
    pub candidate_id: EndpointThreatCandidateId,
    pub analysis_input_ref: EndpointAnalysisInputId,
    pub category: EndpointThreatCandidateCategory,
    pub process_fact_refs: Vec<SecurityFactId>,
    pub service_fact_refs: Vec<SecurityFactId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub baseline_refs: Vec<BaselineRecordId>,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub risk_refs: Vec<RiskEventId>,
    pub attack_refs: Vec<EndpointAttackRef>,
    pub confidence_bucket: EndpointThreatConfidenceBucket,
    pub severity_bucket: EndpointThreatSeverityBucket,
    pub causal_claim: EndpointThreatCausalClaim,
    pub summary_redacted: String,
    pub missing_visibility_flags: Vec<EndpointMissingVisibilityFlag>,
    pub freshness_category: EndpointFreshnessCategory,
    pub source_reliability_bucket: EndpointSourceReliabilityBucket,
    pub evidence_quality_bucket: EndpointEvidenceQualityBucket,
    pub correlation_quality_bucket: EndpointCorrelationQualityBucket,
    pub provenance_id: DataSourceId,
    pub redaction_status: RedactionStatus,
}

impl EndpointThreatCandidate {
    pub fn validate(&self) -> Result<(), EndpointThreatContractError> {
        validate_ref_count(
            "endpoint_candidate.process_fact_refs",
            self.process_fact_refs.len(),
        )?;
        validate_ref_count(
            "endpoint_candidate.service_fact_refs",
            self.service_fact_refs.len(),
        )?;
        require_evidence_refs("endpoint_candidate.evidence_refs", &self.evidence_refs)?;
        validate_ref_count("endpoint_candidate.baseline_refs", self.baseline_refs.len())?;
        validate_ref_count(
            "endpoint_candidate.hypothesis_refs",
            self.hypothesis_refs.len(),
        )?;
        validate_ref_count("endpoint_candidate.risk_refs", self.risk_refs.len())?;
        validate_attack_refs(&self.attack_refs)?;
        validate_visibility_flags(
            "endpoint_candidate.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        validate_causal_claim(&self.causal_claim)?;
        safe_text(
            "endpoint_candidate.summary_redacted",
            &self.summary_redacted,
        )?;
        require_redacted_status(
            "endpoint_candidate.redaction_status",
            &self.redaction_status,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointThreatFinding {
    pub finding_id: EndpointThreatFindingId,
    pub candidate_ref: EndpointThreatCandidateId,
    pub analysis_input_ref: EndpointAnalysisInputId,
    pub category: EndpointThreatFindingCategory,
    pub evidence_refs: Vec<EvidenceId>,
    pub endpoint_evidence_refs: Vec<EndpointThreatEvidenceId>,
    pub risk_hint_refs: Vec<EndpointThreatRiskHintId>,
    pub attack_refs: Vec<EndpointAttackRef>,
    pub confidence_bucket: EndpointThreatConfidenceBucket,
    pub severity_bucket: EndpointThreatSeverityBucket,
    pub causal_claim: EndpointThreatCausalClaim,
    pub summary_redacted: String,
    pub missing_visibility_flags: Vec<EndpointMissingVisibilityFlag>,
    pub evidence_quality_bucket: EndpointEvidenceQualityBucket,
    pub correlation_quality_bucket: EndpointCorrelationQualityBucket,
    pub provenance_id: DataSourceId,
    pub redaction_status: RedactionStatus,
}

impl EndpointThreatFinding {
    pub fn validate(&self) -> Result<(), EndpointThreatContractError> {
        require_evidence_refs("endpoint_finding.evidence_refs", &self.evidence_refs)?;
        validate_ref_count(
            "endpoint_finding.endpoint_evidence_refs",
            self.endpoint_evidence_refs.len(),
        )?;
        validate_ref_count("endpoint_finding.risk_hint_refs", self.risk_hint_refs.len())?;
        validate_attack_refs(&self.attack_refs)?;
        validate_visibility_flags(
            "endpoint_finding.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        validate_causal_claim(&self.causal_claim)?;
        safe_text("endpoint_finding.summary_redacted", &self.summary_redacted)?;
        require_redacted_status("endpoint_finding.redaction_status", &self.redaction_status)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointThreatEvidence {
    pub endpoint_evidence_id: EndpointThreatEvidenceId,
    pub analysis_input_ref: EndpointAnalysisInputId,
    pub source_evidence_ref: EvidenceId,
    pub category: EndpointThreatEvidenceCategory,
    pub process_fact_refs: Vec<SecurityFactId>,
    pub parent_relation_fact_refs: Vec<SecurityFactId>,
    pub service_fact_refs: Vec<SecurityFactId>,
    pub native_health_fact_refs: Vec<SecurityFactId>,
    pub portable_finding_refs: Vec<FindingId>,
    pub baseline_refs: Vec<BaselineRecordId>,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub risk_refs: Vec<RiskEventId>,
    pub summary_redacted: String,
    pub time_bucket: Timestamp,
    pub freshness_category: EndpointFreshnessCategory,
    pub source_reliability_bucket: EndpointSourceReliabilityBucket,
    pub evidence_quality_bucket: EndpointEvidenceQualityBucket,
    pub correlation_quality_bucket: EndpointCorrelationQualityBucket,
    pub missing_visibility_flags: Vec<EndpointMissingVisibilityFlag>,
    pub provenance_id: DataSourceId,
    pub redaction_status: RedactionStatus,
}

impl EndpointThreatEvidence {
    pub fn validate(&self) -> Result<(), EndpointThreatContractError> {
        validate_ref_count(
            "endpoint_evidence.process_fact_refs",
            self.process_fact_refs.len(),
        )?;
        validate_ref_count(
            "endpoint_evidence.parent_relation_fact_refs",
            self.parent_relation_fact_refs.len(),
        )?;
        validate_ref_count(
            "endpoint_evidence.service_fact_refs",
            self.service_fact_refs.len(),
        )?;
        validate_ref_count(
            "endpoint_evidence.native_health_fact_refs",
            self.native_health_fact_refs.len(),
        )?;
        validate_ref_count(
            "endpoint_evidence.portable_finding_refs",
            self.portable_finding_refs.len(),
        )?;
        validate_ref_count("endpoint_evidence.baseline_refs", self.baseline_refs.len())?;
        validate_ref_count(
            "endpoint_evidence.hypothesis_refs",
            self.hypothesis_refs.len(),
        )?;
        validate_ref_count("endpoint_evidence.risk_refs", self.risk_refs.len())?;
        validate_visibility_flags(
            "endpoint_evidence.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        safe_text("endpoint_evidence.summary_redacted", &self.summary_redacted)?;
        require_redacted_status("endpoint_evidence.redaction_status", &self.redaction_status)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointThreatRiskHint {
    pub risk_hint_id: EndpointThreatRiskHintId,
    pub finding_ref: Option<EndpointThreatFindingId>,
    pub candidate_ref: Option<EndpointThreatCandidateId>,
    pub category: EndpointThreatRiskCategory,
    pub risk_bucket: EndpointThreatSeverityBucket,
    pub confidence_bucket: EndpointThreatConfidenceBucket,
    pub evidence_refs: Vec<EvidenceId>,
    pub risk_refs: Vec<RiskEventId>,
    pub summary_redacted: String,
    pub missing_visibility_flags: Vec<EndpointMissingVisibilityFlag>,
    pub provenance_id: DataSourceId,
    pub redaction_status: RedactionStatus,
}

impl EndpointThreatRiskHint {
    pub fn validate(&self) -> Result<(), EndpointThreatContractError> {
        if self.finding_ref.is_none() && self.candidate_ref.is_none() {
            return Err(EndpointThreatContractError::UnsafeClaim(
                "endpoint risk hints must reference a finding or candidate",
            ));
        }
        require_evidence_refs("endpoint_risk_hint.evidence_refs", &self.evidence_refs)?;
        validate_ref_count("endpoint_risk_hint.risk_refs", self.risk_refs.len())?;
        validate_visibility_flags(
            "endpoint_risk_hint.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        safe_text(
            "endpoint_risk_hint.summary_redacted",
            &self.summary_redacted,
        )?;
        require_redacted_status(
            "endpoint_risk_hint.redaction_status",
            &self.redaction_status,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointVisibilityAdvisory {
    pub advisory_id: EndpointVisibilityAdvisoryId,
    pub analysis_input_ref: Option<EndpointAnalysisInputId>,
    pub category: EndpointVisibilityAdvisoryCategory,
    pub missing_visibility_flags: Vec<EndpointMissingVisibilityFlag>,
    pub confidence_cap: EndpointThreatConfidenceBucket,
    pub summary_redacted: String,
    pub evidence_refs: Vec<EvidenceId>,
    pub provenance_id: DataSourceId,
    pub redaction_status: RedactionStatus,
}

impl EndpointVisibilityAdvisory {
    pub fn validate(&self) -> Result<(), EndpointThreatContractError> {
        if self.missing_visibility_flags.is_empty() {
            return Err(EndpointThreatContractError::UnsafeClaim(
                "visibility advisories must declare missing visibility",
            ));
        }
        validate_visibility_flags(
            "endpoint_visibility_advisory.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        require_evidence_refs(
            "endpoint_visibility_advisory.evidence_refs",
            &self.evidence_refs,
        )?;
        safe_text(
            "endpoint_visibility_advisory.summary_redacted",
            &self.summary_redacted,
        )?;
        require_redacted_status(
            "endpoint_visibility_advisory.redaction_status",
            &self.redaction_status,
        )?;
        if self.confidence_cap == EndpointThreatConfidenceBucket::Elevated {
            return Err(EndpointThreatContractError::UnsafeClaim(
                "missing visibility advisories cannot raise confidence to elevated",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRejectedCandidate {
    pub rejected_candidate_id: EndpointRejectedCandidateId,
    pub analysis_input_ref: EndpointAnalysisInputId,
    pub category: EndpointThreatCandidateCategory,
    pub reason: EndpointRejectedCandidateReason,
    pub evidence_refs: Vec<EvidenceId>,
    pub summary_redacted: String,
    pub missing_visibility_flags: Vec<EndpointMissingVisibilityFlag>,
    pub provenance_id: DataSourceId,
    pub redaction_status: RedactionStatus,
}

impl EndpointRejectedCandidate {
    pub fn validate(&self) -> Result<(), EndpointThreatContractError> {
        validate_ref_count(
            "endpoint_rejected_candidate.evidence_refs",
            self.evidence_refs.len(),
        )?;
        validate_visibility_flags(
            "endpoint_rejected_candidate.missing_visibility_flags",
            &self.missing_visibility_flags,
        )?;
        safe_text(
            "endpoint_rejected_candidate.summary_redacted",
            &self.summary_redacted,
        )?;
        require_redacted_status(
            "endpoint_rejected_candidate.redaction_status",
            &self.redaction_status,
        )?;
        Ok(())
    }
}

fn validate_attack_refs(refs: &[EndpointAttackRef]) -> Result<(), EndpointThreatContractError> {
    if refs.len() > MAX_ENDPOINT_THREAT_ATTACK_REFS {
        return Err(EndpointThreatContractError::ExceedsBound(
            "endpoint.attack_refs",
        ));
    }
    for attack_ref in refs {
        attack_ref.validate()?;
    }
    Ok(())
}

fn validate_ref_count(field: &'static str, len: usize) -> Result<(), EndpointThreatContractError> {
    if len > MAX_ENDPOINT_THREAT_REFS {
        return Err(EndpointThreatContractError::ExceedsBound(field));
    }
    Ok(())
}

fn require_evidence_refs(
    field: &'static str,
    refs: &[EvidenceId],
) -> Result<(), EndpointThreatContractError> {
    if refs.is_empty() {
        return Err(EndpointThreatContractError::EmptyEvidenceRefs);
    }
    validate_ref_count(field, refs.len())
}

fn validate_visibility_flags(
    field: &'static str,
    flags: &[EndpointMissingVisibilityFlag],
) -> Result<(), EndpointThreatContractError> {
    if flags.len() > MAX_ENDPOINT_THREAT_VISIBILITY_FLAGS {
        return Err(EndpointThreatContractError::ExceedsBound(field));
    }
    Ok(())
}

fn validate_causal_claim(
    claim: &EndpointThreatCausalClaim,
) -> Result<(), EndpointThreatContractError> {
    if *claim == EndpointThreatCausalClaim::UnsupportedCausalClaim {
        return Err(EndpointThreatContractError::UnsafeClaim(
            "endpoint threat lite supports correlation-only, evidence-backed analysis",
        ));
    }
    Ok(())
}

fn require_redacted_status(
    field: &'static str,
    status: &RedactionStatus,
) -> Result<(), EndpointThreatContractError> {
    match status {
        RedactionStatus::Redacted
        | RedactionStatus::Tokenized
        | RedactionStatus::Hashed
        | RedactionStatus::PartiallyRedacted
        | RedactionStatus::Suppressed => Ok(()),
        RedactionStatus::NotRequired | RedactionStatus::RedactionRequired => {
            Err(EndpointThreatContractError::UnsafeClaim(match status {
                RedactionStatus::NotRequired => {
                    "endpoint analysis contracts must carry explicit redaction status"
                }
                RedactionStatus::RedactionRequired => {
                    "endpoint analysis contracts cannot expose redaction-required data"
                }
                _ => field,
            }))
        }
    }
}

fn safe_attack_id(field: &'static str, value: &str) -> Result<(), EndpointThreatContractError> {
    safe_text(field, value)?;
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '.')
    {
        return Err(EndpointThreatContractError::UnsafeField(field));
    }
    Ok(())
}

fn safe_text(field: &'static str, value: &str) -> Result<(), EndpointThreatContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(EndpointThreatContractError::EmptyField(field));
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.len() > MAX_ENDPOINT_THREAT_TEXT_BYTES
        || trimmed.contains("://")
        || trimmed.contains('@')
        || trimmed.contains('\\')
        || trimmed.contains('/')
        || looks_like_ip(trimmed)
        || looks_like_raw_endpoint_identifier(&lower)
        || FORBIDDEN_MARKERS
            .iter()
            .any(|marker| lower.contains(marker))
    {
        return Err(EndpointThreatContractError::UnsafeField(field));
    }
    Ok(())
}

fn looks_like_ip(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

fn looks_like_raw_endpoint_identifier(lower: &str) -> bool {
    const EXECUTABLE_SUFFIXES: &[&str] = &[
        ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".msi", ".scr",
    ];
    EXECUTABLE_SUFFIXES
        .iter()
        .any(|suffix| lower.contains(suffix))
        || (lower.contains("pid ") && lower.chars().any(|character| character.is_ascii_digit()))
        || (lower.contains("pid:") && lower.chars().any(|character| character.is_ascii_digit()))
        || (lower.contains("pid=") && lower.chars().any(|character| character.is_ascii_digit()))
        || lower.contains("s-1-5-")
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
    "raw_provider_output",
    "raw_process",
    "raw_service",
    "raw_packet",
    "raw_payload",
    "process_name",
    "service_name",
    "parent_pid",
    "command_line",
    "username",
    "hostname",
    "device_id",
    "tenant_id",
    "registry_key",
    "file_path",
    "executable_path",
    "certificate",
    "socket",
    "destination_attribution",
    "plaintext",
    "confirmed",
    "definitive",
    "critical_confidence",
    "credential_theft",
    "host_compromise",
    "malware_execution",
    "response_execution",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_input_accepts_bounded_redacted_metadata() {
        let input = safe_input();

        input.validate().expect("safe endpoint input");
    }

    #[test]
    fn unsafe_unknown_fields_are_rejected_by_contract_shape() {
        let mut value = serde_json::to_value(safe_input()).expect("serialize safe input");
        value
            .as_object_mut()
            .expect("object")
            .insert("pid".to_string(), serde_json::json!(4242));

        let decoded: Result<EndpointAnalysisInput, _> = serde_json::from_value(value);
        assert!(decoded.is_err());
    }

    #[test]
    fn raw_endpoint_identifiers_are_rejected() {
        let mut candidate = safe_candidate();
        candidate.summary_redacted = "redacted powershell.exe pid 4242".to_string();

        assert!(matches!(
            candidate.validate(),
            Err(EndpointThreatContractError::UnsafeField(_))
        ));
    }

    #[test]
    fn unsupported_causal_claims_are_rejected() {
        let mut candidate = safe_candidate();
        candidate.causal_claim = EndpointThreatCausalClaim::UnsupportedCausalClaim;

        assert!(matches!(
            candidate.validate(),
            Err(EndpointThreatContractError::UnsafeClaim(_))
        ));
    }

    #[test]
    fn redaction_requirements_are_enforced() {
        let mut finding = safe_finding();
        finding.redaction_status = RedactionStatus::RedactionRequired;

        assert!(matches!(
            finding.validate(),
            Err(EndpointThreatContractError::UnsafeClaim(_))
        ));

        finding.redaction_status = RedactionStatus::NotRequired;
        assert!(matches!(
            finding.validate(),
            Err(EndpointThreatContractError::UnsafeClaim(_))
        ));
    }

    #[test]
    fn findings_are_evidence_backed() {
        let mut finding = safe_finding();
        finding.evidence_refs.clear();

        assert_eq!(
            finding.validate(),
            Err(EndpointThreatContractError::EmptyEvidenceRefs)
        );
    }

    #[test]
    fn unsupported_confidence_labels_cannot_deserialize() {
        let confidence: Result<EndpointThreatConfidenceBucket, _> =
            serde_json::from_str("\"confirmed\"");
        let severity: Result<EndpointThreatSeverityBucket, _> =
            serde_json::from_str("\"critical\"");

        assert!(confidence.is_err());
        assert!(severity.is_err());
    }

    #[test]
    fn sensitive_values_do_not_appear_in_serialized_safe_contracts() {
        let serialized = serde_json::to_string(&safe_input()).expect("serialize input");
        for forbidden in [
            "powershell.exe",
            "C:\\Users\\Alice",
            "alice@example.com",
            "192.168.1.2",
            "S-1-5-21",
            "token",
            "secret",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "serialized endpoint contract leaked {forbidden}"
            );
        }
    }

    #[test]
    fn visibility_advisory_cannot_raise_confidence() {
        let mut advisory = EndpointVisibilityAdvisory {
            advisory_id: EndpointVisibilityAdvisoryId::new_v4(),
            analysis_input_ref: Some(EndpointAnalysisInputId::new_v4()),
            category: EndpointVisibilityAdvisoryCategory::CommandLineUnavailable,
            missing_visibility_flags: vec![
                EndpointMissingVisibilityFlag::CommandLineVisibilityUnavailable,
            ],
            confidence_cap: EndpointThreatConfidenceBucket::Elevated,
            summary_redacted: "visibility_limited_context".to_string(),
            evidence_refs: vec![EvidenceId::new_v4()],
            provenance_id: DataSourceId::new_v4(),
            redaction_status: RedactionStatus::Redacted,
        };

        assert!(matches!(
            advisory.validate(),
            Err(EndpointThreatContractError::UnsafeClaim(_))
        ));

        advisory.confidence_cap = EndpointThreatConfidenceBucket::Moderate;
        advisory.validate().expect("bounded advisory");
    }

    fn safe_input() -> EndpointAnalysisInput {
        EndpointAnalysisInput {
            analysis_input_id: EndpointAnalysisInputId::new_v4(),
            session_ref: SessionId::new_v4(),
            process_fact_refs: vec![SecurityFactId::new_v4()],
            parent_relation_fact_refs: vec![SecurityFactId::new_v4()],
            service_fact_refs: vec![SecurityFactId::new_v4()],
            native_health_fact_refs: vec![SecurityFactId::new_v4()],
            portable_finding_refs: vec![FindingId::new_v4()],
            evidence_refs: vec![EvidenceId::new_v4()],
            baseline_refs: vec![BaselineRecordId::new_v4()],
            hypothesis_refs: vec![AttackHypothesisId::new_v4()],
            risk_refs: vec![RiskEventId::new_v4()],
            attack_refs: vec![EndpointAttackRef {
                tactic_id: "TA0007".to_string(),
                technique_id: "T1082".to_string(),
                attack_version: "enterprise_2026_metadata_only".to_string(),
                confidence_bucket: EndpointThreatConfidenceBucket::Low,
                required_visibility: vec![
                    EndpointMissingVisibilityFlag::CommandLineVisibilityUnavailable,
                ],
            }],
            process_category: EndpointProcessCategory::ScriptInterpreter,
            parent_process_category: EndpointProcessCategory::Shell,
            relation_category: EndpointRelationCategory::ParentChildObserved,
            execution_context_category: EndpointExecutionContextCategory::Interactive,
            service_category: EndpointServiceCategory::System,
            process_lifecycle_bucket: EndpointLifecycleBucket::FirstObserved,
            service_state_bucket: EndpointServiceStateBucket::Running,
            startup_type_bucket: EndpointStartupTypeBucket::Manual,
            trust_signedness_bucket: EndpointTrustSignednessBucket::SignedTrusted,
            privilege_integrity_category: EndpointPrivilegeIntegrityCategory::Medium,
            occurrence_indicator: EndpointOccurrenceIndicator::Rare,
            count_change_bucket: EndpointCountChangeBucket::Single,
            time_bucket: Timestamp::now(),
            freshness_category: EndpointFreshnessCategory::Fresh,
            source_reliability_bucket: EndpointSourceReliabilityBucket::Stable,
            evidence_quality_bucket: EndpointEvidenceQualityBucket::Moderate,
            correlation_quality_bucket: EndpointCorrelationQualityBucket::Limited,
            missing_visibility_flags: vec![
                EndpointMissingVisibilityFlag::ProcessNetworkAttributionUnavailable,
                EndpointMissingVisibilityFlag::CommandLineVisibilityUnavailable,
                EndpointMissingVisibilityFlag::FileRegistryVisibilityUnavailable,
                EndpointMissingVisibilityFlag::PacketVisibilityUnavailable,
                EndpointMissingVisibilityFlag::SpecificProcessIdentityUnavailable,
            ],
            provenance_id: DataSourceId::new_v4(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn safe_candidate() -> EndpointThreatCandidate {
        let input = safe_input();
        EndpointThreatCandidate {
            candidate_id: EndpointThreatCandidateId::new_v4(),
            analysis_input_ref: input.analysis_input_id,
            category: EndpointThreatCandidateCategory::ProcessServiceCorrelation,
            process_fact_refs: input.process_fact_refs,
            service_fact_refs: input.service_fact_refs,
            evidence_refs: input.evidence_refs,
            baseline_refs: input.baseline_refs,
            hypothesis_refs: input.hypothesis_refs,
            risk_refs: input.risk_refs,
            attack_refs: input.attack_refs,
            confidence_bucket: EndpointThreatConfidenceBucket::Low,
            severity_bucket: EndpointThreatSeverityBucket::Low,
            causal_claim: EndpointThreatCausalClaim::CorrelationOnly,
            summary_redacted: "redacted_endpoint_category_correlation".to_string(),
            missing_visibility_flags: input.missing_visibility_flags,
            freshness_category: EndpointFreshnessCategory::Fresh,
            source_reliability_bucket: EndpointSourceReliabilityBucket::Stable,
            evidence_quality_bucket: EndpointEvidenceQualityBucket::Moderate,
            correlation_quality_bucket: EndpointCorrelationQualityBucket::Limited,
            provenance_id: input.provenance_id,
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn safe_finding() -> EndpointThreatFinding {
        let candidate = safe_candidate();
        EndpointThreatFinding {
            finding_id: EndpointThreatFindingId::new_v4(),
            candidate_ref: candidate.candidate_id,
            analysis_input_ref: candidate.analysis_input_ref,
            category: EndpointThreatFindingCategory::EvidenceBackedEndpointAnomaly,
            evidence_refs: candidate.evidence_refs,
            endpoint_evidence_refs: vec![EndpointThreatEvidenceId::new_v4()],
            risk_hint_refs: vec![EndpointThreatRiskHintId::new_v4()],
            attack_refs: candidate.attack_refs,
            confidence_bucket: EndpointThreatConfidenceBucket::Moderate,
            severity_bucket: EndpointThreatSeverityBucket::Moderate,
            causal_claim: EndpointThreatCausalClaim::CorrelationOnly,
            summary_redacted: "redacted_endpoint_anomaly".to_string(),
            missing_visibility_flags: candidate.missing_visibility_flags,
            evidence_quality_bucket: EndpointEvidenceQualityBucket::Moderate,
            correlation_quality_bucket: EndpointCorrelationQualityBucket::Limited,
            provenance_id: candidate.provenance_id,
            redaction_status: RedactionStatus::Redacted,
        }
    }
}
