use crate::common::{
    AlertCandidateId, AlertId, CapabilityId, CorrelationId, EntityRef, EventId, EvidenceBundleId,
    EvidenceId, FindingId, GraphPathId, IncidentCandidateId, IncidentId, PluginId, PrivacyClass,
    QualityScore, RiskEventId, SecurityObservationId, TimeRange, Timestamp, TraceId,
};
use crate::evidence_quality::{QualityBreakdown, SuitabilityBucket, VisibilityCompletenessBucket};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecurityContractError {
    EmptyField(&'static str),
    EmptyEvidenceRefs,
    EmptyFindingRefs,
    EmptyAlertRefs,
    UnsafeAttackCoverageClaim(&'static str),
}

impl fmt::Display for SecurityContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::EmptyEvidenceRefs => write!(f, "at least one evidence reference is required"),
            Self::EmptyFindingRefs => write!(f, "at least one finding reference is required"),
            Self::EmptyAlertRefs => write!(f, "at least one alert reference is required"),
            Self::UnsafeAttackCoverageClaim(reason) => {
                write!(f, "unsafe ATT&CK coverage claim: {reason}")
            }
        }
    }
}

impl std::error::Error for SecurityContractError {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecuritySeverity {
    #[default]
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackTaxonomy {
    MitreAttackEnterprise,
    Internal,
    Custom,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MappingProvenance {
    pub source: String,
    pub source_version: Option<String>,
    pub mapped_by: Option<String>,
    pub mapped_at: Option<Timestamp>,
}

impl MappingProvenance {
    pub fn new(source: impl Into<String>) -> Result<Self, SecurityContractError> {
        let source = require_non_empty("mapping source", source.into())?;

        Ok(Self {
            source,
            source_version: None,
            mapped_by: None,
            mapped_at: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttackMapping {
    pub taxonomy: AttackTaxonomy,
    pub tactic_id: Option<String>,
    pub tactic_name: Option<String>,
    pub technique_id: Option<String>,
    pub technique_name: Option<String>,
    pub subtechnique_id: Option<String>,
    pub subtechnique_name: Option<String>,
    pub internal_category: Option<String>,
    pub custom_mapping_id: Option<String>,
    pub custom_mapping_name: Option<String>,
    pub mapping_confidence: QualityScore,
    pub provenance: Option<MappingProvenance>,
}

impl AttackMapping {
    pub fn mitre_attack_enterprise(
        tactic_id: impl Into<String>,
        tactic_name: impl Into<String>,
        technique_id: impl Into<String>,
        technique_name: impl Into<String>,
        mapping_confidence: QualityScore,
        provenance: Option<MappingProvenance>,
    ) -> Result<Self, SecurityContractError> {
        Ok(Self {
            taxonomy: AttackTaxonomy::MitreAttackEnterprise,
            tactic_id: Some(require_non_empty("tactic_id", tactic_id.into())?),
            tactic_name: Some(require_non_empty("tactic_name", tactic_name.into())?),
            technique_id: Some(require_non_empty("technique_id", technique_id.into())?),
            technique_name: Some(require_non_empty("technique_name", technique_name.into())?),
            subtechnique_id: None,
            subtechnique_name: None,
            internal_category: None,
            custom_mapping_id: None,
            custom_mapping_name: None,
            mapping_confidence,
            provenance,
        })
    }

    pub fn with_subtechnique(
        mut self,
        subtechnique_id: impl Into<String>,
        subtechnique_name: impl Into<String>,
    ) -> Result<Self, SecurityContractError> {
        self.subtechnique_id = Some(require_non_empty(
            "subtechnique_id",
            subtechnique_id.into(),
        )?);
        self.subtechnique_name = Some(require_non_empty(
            "subtechnique_name",
            subtechnique_name.into(),
        )?);
        Ok(self)
    }

    pub fn internal(
        internal_category: impl Into<String>,
        mapping_confidence: QualityScore,
        provenance: Option<MappingProvenance>,
    ) -> Result<Self, SecurityContractError> {
        Ok(Self {
            taxonomy: AttackTaxonomy::Internal,
            tactic_id: None,
            tactic_name: None,
            technique_id: None,
            technique_name: None,
            subtechnique_id: None,
            subtechnique_name: None,
            internal_category: Some(require_non_empty(
                "internal_category",
                internal_category.into(),
            )?),
            custom_mapping_id: None,
            custom_mapping_name: None,
            mapping_confidence,
            provenance,
        })
    }

    pub fn custom(
        custom_mapping_id: impl Into<String>,
        custom_mapping_name: impl Into<String>,
        mapping_confidence: QualityScore,
        provenance: Option<MappingProvenance>,
    ) -> Result<Self, SecurityContractError> {
        Ok(Self {
            taxonomy: AttackTaxonomy::Custom,
            tactic_id: None,
            tactic_name: None,
            technique_id: None,
            technique_name: None,
            subtechnique_id: None,
            subtechnique_name: None,
            internal_category: None,
            custom_mapping_id: Some(require_non_empty(
                "custom_mapping_id",
                custom_mapping_id.into(),
            )?),
            custom_mapping_name: Some(require_non_empty(
                "custom_mapping_name",
                custom_mapping_name.into(),
            )?),
            mapping_confidence,
            provenance,
        })
    }
}

pub const MAX_ATTACK_COVERAGE_ROWS: usize = 128;
pub const MAX_ATTACK_COVERAGE_RULE_IDS: usize = 32;
pub const MAX_ATTACK_COVERAGE_REFS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackCoverageState {
    Covered,
    Observed,
    EvidenceBacked,
    Degraded,
    Unsupported,
    RequiresAuthorizedNativeExtension,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackCoverageConfidenceBucket {
    Unknown,
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackObservedCountBucket {
    None,
    Single,
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackLastObservedBucket {
    None,
    CurrentSession,
    RecentSession,
    Stale,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackRequiredVisibility {
    PortableNetworkMetadata,
    PortableAuthMetadata,
    PortableProviderMetadata,
    PortableDeceptionMetadata,
    AuthorizedNativeProcessVisibility,
    AuthorizedNativeExtension,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackCoverageCount {
    pub label: String,
    pub count: u32,
}

impl AttackCoverageCount {
    pub fn new(label: impl Into<String>, count: u32) -> Result<Self, SecurityContractError> {
        Ok(Self {
            label: require_bounded_attack_label("attack coverage count label", label.into())?,
            count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttackCoverageTechniqueRow {
    pub tactic_id: String,
    pub technique_id: String,
    pub attack_version: String,
    pub rule_detector_ids: Vec<String>,
    pub finding_refs: Vec<FindingId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub risk_refs: Vec<RiskEventId>,
    pub confidence_bucket: AttackCoverageConfidenceBucket,
    pub degraded_reason: Option<String>,
    pub required_visibility: AttackRequiredVisibility,
    pub package_category: String,
    pub observed_count_bucket: AttackObservedCountBucket,
    pub last_observed_bucket: AttackLastObservedBucket,
    pub states: Vec<AttackCoverageState>,
    pub quality: QualityBreakdown,
    pub native_required: bool,
    pub metadata_only: bool,
}

impl AttackCoverageTechniqueRow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tactic_id: impl Into<String>,
        technique_id: impl Into<String>,
        attack_version: impl Into<String>,
        rule_detector_ids: Vec<String>,
        confidence_bucket: AttackCoverageConfidenceBucket,
        required_visibility: AttackRequiredVisibility,
        package_category: impl Into<String>,
        observed_count_bucket: AttackObservedCountBucket,
        last_observed_bucket: AttackLastObservedBucket,
        states: Vec<AttackCoverageState>,
    ) -> Result<Self, SecurityContractError> {
        let native_required = matches!(
            required_visibility,
            AttackRequiredVisibility::AuthorizedNativeProcessVisibility
                | AttackRequiredVisibility::AuthorizedNativeExtension
        );
        let metadata_only = matches!(
            required_visibility,
            AttackRequiredVisibility::PortableNetworkMetadata
                | AttackRequiredVisibility::PortableAuthMetadata
                | AttackRequiredVisibility::PortableProviderMetadata
                | AttackRequiredVisibility::PortableDeceptionMetadata
        );
        let row = Self {
            tactic_id: require_attack_identifier("tactic_id", tactic_id.into())?,
            technique_id: require_attack_identifier("technique_id", technique_id.into())?,
            attack_version: require_bounded_attack_label("attack_version", attack_version.into())?,
            rule_detector_ids: rule_detector_ids
                .into_iter()
                .map(|value| require_bounded_attack_label("rule_detector_id", value))
                .collect::<Result<Vec<_>, _>>()?,
            finding_refs: Vec::new(),
            evidence_refs: Vec::new(),
            risk_refs: Vec::new(),
            confidence_bucket,
            degraded_reason: None,
            required_visibility,
            package_category: require_bounded_attack_label(
                "package_category",
                package_category.into(),
            )?,
            observed_count_bucket,
            last_observed_bucket,
            states,
            quality: QualityBreakdown::metadata_only(),
            native_required,
            metadata_only,
        };
        row.validate()?;
        Ok(row)
    }

    pub fn validate(&self) -> Result<(), SecurityContractError> {
        require_attack_identifier("tactic_id", self.tactic_id.clone())?;
        require_attack_identifier("technique_id", self.technique_id.clone())?;
        require_bounded_attack_label("attack_version", self.attack_version.clone())?;
        require_bounded_attack_label("package_category", self.package_category.clone())?;

        if self.states.is_empty() {
            return Err(SecurityContractError::UnsafeAttackCoverageClaim(
                "coverage row must declare at least one state",
            ));
        }
        if self.rule_detector_ids.len() > MAX_ATTACK_COVERAGE_RULE_IDS
            || self.finding_refs.len() > MAX_ATTACK_COVERAGE_REFS
            || self.evidence_refs.len() > MAX_ATTACK_COVERAGE_REFS
            || self.risk_refs.len() > MAX_ATTACK_COVERAGE_REFS
        {
            return Err(SecurityContractError::UnsafeAttackCoverageClaim(
                "coverage row exceeds bounded reference limits",
            ));
        }
        if let Some(reason) = &self.degraded_reason {
            require_bounded_attack_label("degraded_reason", reason.clone())?;
        }
        for detector_id in &self.rule_detector_ids {
            require_bounded_attack_label("rule_detector_id", detector_id.clone())?;
        }
        self.quality.validate().map_err(|_| {
            SecurityContractError::UnsafeAttackCoverageClaim(
                "ATT&CK quality context must stay bounded",
            )
        })?;
        if self.claims_high_confidence_without_supported_visibility() {
            return Err(SecurityContractError::UnsafeAttackCoverageClaim(
                "metadata-only or unsupported rows cannot claim high confidence",
            ));
        }
        if self.native_required
            && !matches!(
                self.required_visibility,
                AttackRequiredVisibility::AuthorizedNativeProcessVisibility
                    | AttackRequiredVisibility::AuthorizedNativeExtension
            )
        {
            return Err(SecurityContractError::UnsafeAttackCoverageClaim(
                "native-required marker must match required visibility",
            ));
        }
        if self.metadata_only
            && self.quality.visibility_completeness_bucket
                != VisibilityCompletenessBucket::MetadataOnly
            && self.quality.visibility_completeness_bucket != VisibilityCompletenessBucket::Degraded
        {
            return Err(SecurityContractError::UnsafeAttackCoverageClaim(
                "metadata-only ATT&CK rows must preserve visibility warnings",
            ));
        }
        if self.quality.report_suitability_bucket == SuitabilityBucket::Suitable
            && self.states.contains(&AttackCoverageState::Unsupported)
        {
            return Err(SecurityContractError::UnsafeAttackCoverageClaim(
                "unsupported ATT&CK rows cannot be report-suitable without degradation",
            ));
        }
        if self.claims_high_confidence_for_restricted_tactic() {
            return Err(SecurityContractError::UnsafeAttackCoverageClaim(
                "restricted tactic rows require degraded confidence",
            ));
        }
        Ok(())
    }

    fn claims_high_confidence_without_supported_visibility(&self) -> bool {
        self.confidence_bucket == AttackCoverageConfidenceBucket::High
            && (self.states.contains(&AttackCoverageState::Unsupported)
                || self
                    .states
                    .contains(&AttackCoverageState::RequiresAuthorizedNativeExtension)
                || self.states.contains(&AttackCoverageState::Degraded)
                || matches!(
                    self.required_visibility,
                    AttackRequiredVisibility::AuthorizedNativeProcessVisibility
                        | AttackRequiredVisibility::AuthorizedNativeExtension
                        | AttackRequiredVisibility::Unsupported
                ))
    }

    fn claims_high_confidence_for_restricted_tactic(&self) -> bool {
        self.confidence_bucket == AttackCoverageConfidenceBucket::High
            && matches!(
                self.tactic_id.as_str(),
                "TA0002" | "TA0003" | "TA0004" | "TA0006"
            )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttackCoverageSummary {
    pub attack_version: String,
    pub generated_at: Timestamp,
    pub complete_coverage_claimed: bool,
    pub technique_rows: Vec<AttackCoverageTechniqueRow>,
    pub top_tactics: Vec<AttackCoverageCount>,
    pub package_coverage: Vec<AttackCoverageCount>,
    pub state_counts: Vec<AttackCoverageCount>,
    pub finding_refs: Vec<FindingId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub risk_refs: Vec<RiskEventId>,
    pub degraded_reason: Option<String>,
}

impl AttackCoverageSummary {
    pub fn new(attack_version: impl Into<String>) -> Result<Self, SecurityContractError> {
        Ok(Self {
            attack_version: require_bounded_attack_label("attack_version", attack_version.into())?,
            generated_at: Timestamp::now(),
            complete_coverage_claimed: false,
            technique_rows: Vec::new(),
            top_tactics: Vec::new(),
            package_coverage: Vec::new(),
            state_counts: Vec::new(),
            finding_refs: Vec::new(),
            evidence_refs: Vec::new(),
            risk_refs: Vec::new(),
            degraded_reason: None,
        })
    }

    pub fn validate(&self) -> Result<(), SecurityContractError> {
        require_bounded_attack_label("attack_version", self.attack_version.clone())?;
        if self.complete_coverage_claimed {
            return Err(SecurityContractError::UnsafeAttackCoverageClaim(
                "portable metadata summaries must not claim complete coverage",
            ));
        }
        if self.technique_rows.len() > MAX_ATTACK_COVERAGE_ROWS
            || self.finding_refs.len() > MAX_ATTACK_COVERAGE_REFS
            || self.evidence_refs.len() > MAX_ATTACK_COVERAGE_REFS
            || self.risk_refs.len() > MAX_ATTACK_COVERAGE_REFS
        {
            return Err(SecurityContractError::UnsafeAttackCoverageClaim(
                "coverage summary exceeds bounded limits",
            ));
        }
        if let Some(reason) = &self.degraded_reason {
            require_bounded_attack_label("degraded_reason", reason.clone())?;
        }
        for row in &self.technique_rows {
            row.validate()?;
        }
        for count in self
            .top_tactics
            .iter()
            .chain(self.package_coverage.iter())
            .chain(self.state_counts.iter())
        {
            require_bounded_attack_label("attack coverage count label", count.label.clone())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RiskReason {
    pub reason_type: String,
    pub summary_redacted: String,
    pub confidence: QualityScore,
    pub evidence_refs: Vec<EvidenceId>,
    pub attack_mappings: Vec<AttackMapping>,
}

impl RiskReason {
    pub fn new(
        reason_type: impl Into<String>,
        summary_redacted: impl Into<String>,
    ) -> Result<Self, SecurityContractError> {
        Ok(Self {
            reason_type: require_non_empty("reason_type", reason_type.into())?,
            summary_redacted: require_non_empty("summary_redacted", summary_redacted.into())?,
            confidence: QualityScore::default(),
            evidence_refs: Vec::new(),
            attack_mappings: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FindingExplanation {
    pub summary_redacted: String,
    pub risk_reasons: Vec<RiskReason>,
    pub limitations_redacted: Vec<String>,
}

impl FindingExplanation {
    pub fn new(summary_redacted: impl Into<String>) -> Result<Self, SecurityContractError> {
        Ok(Self {
            summary_redacted: require_non_empty("summary_redacted", summary_redacted.into())?,
            risk_reasons: Vec::new(),
            limitations_redacted: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecurityObservation {
    pub observation_id: SecurityObservationId,
    pub observation_type: String,
    pub source_event_refs: Vec<EventId>,
    pub entity_refs: Vec<EntityRef>,
    pub producer_plugin: Option<PluginId>,
    pub producer_capability: Option<CapabilityId>,
    pub timestamp: Timestamp,
    pub trace_id: Option<TraceId>,
    pub correlation_id: Option<CorrelationId>,
    pub privacy_class: PrivacyClass,
    pub confidence: QualityScore,
    pub summary_redacted: String,
}

impl SecurityObservation {
    pub fn new(
        observation_type: impl Into<String>,
        summary_redacted: impl Into<String>,
    ) -> Result<Self, SecurityContractError> {
        Ok(Self {
            observation_id: SecurityObservationId::new_v4(),
            observation_type: require_non_empty("observation_type", observation_type.into())?,
            source_event_refs: Vec::new(),
            entity_refs: Vec::new(),
            producer_plugin: None,
            producer_capability: None,
            timestamp: Timestamp::now(),
            trace_id: None,
            correlation_id: None,
            privacy_class: PrivacyClass::default(),
            confidence: QualityScore::default(),
            summary_redacted: require_non_empty("summary_redacted", summary_redacted.into())?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub evidence_id: EvidenceId,
    pub evidence_type: String,
    pub source_event_refs: Vec<EventId>,
    pub source_plugin: Option<PluginId>,
    pub entity_refs: Vec<EntityRef>,
    pub timestamp: Timestamp,
    pub value_summary_redacted: String,
    pub weight: QualityScore,
    pub confidence: QualityScore,
    pub privacy_class: PrivacyClass,
    pub description_redacted: Option<String>,
}

impl EvidenceItem {
    pub fn new(
        evidence_type: impl Into<String>,
        value_summary_redacted: impl Into<String>,
    ) -> Result<Self, SecurityContractError> {
        Ok(Self {
            evidence_id: EvidenceId::new_v4(),
            evidence_type: require_non_empty("evidence_type", evidence_type.into())?,
            source_event_refs: Vec::new(),
            source_plugin: None,
            entity_refs: Vec::new(),
            timestamp: Timestamp::now(),
            value_summary_redacted: require_non_empty(
                "value_summary_redacted",
                value_summary_redacted.into(),
            )?,
            weight: QualityScore::default(),
            confidence: QualityScore::default(),
            privacy_class: PrivacyClass::default(),
            description_redacted: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub bundle_id: EvidenceBundleId,
    pub finding_id: Option<FindingId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub total_weight: QualityScore,
    pub confidence: QualityScore,
    pub severity: SecuritySeverity,
    pub explanation: FindingExplanation,
}

impl EvidenceBundle {
    pub fn new(
        evidence_refs: Vec<EvidenceId>,
        explanation: FindingExplanation,
    ) -> Result<Self, SecurityContractError> {
        if evidence_refs.is_empty() {
            return Err(SecurityContractError::EmptyEvidenceRefs);
        }

        Ok(Self {
            bundle_id: EvidenceBundleId::new_v4(),
            finding_id: None,
            evidence_refs,
            total_weight: QualityScore::default(),
            confidence: QualityScore::default(),
            severity: SecuritySeverity::default(),
            explanation,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    New,
    Updated,
    Suppressed,
    Escalated,
    Promoted,
    Dismissed,
    Expired,
    Resolved,
    Duplicate,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    finding_id: FindingId,
    finding_type: String,
    entity_refs: Vec<EntityRef>,
    evidence_refs: Vec<EvidenceId>,
    confidence: QualityScore,
    severity: SecuritySeverity,
    risk_reasons: Vec<RiskReason>,
    attack_mappings: Vec<AttackMapping>,
    explanation: FindingExplanation,
    producer_plugin: PluginId,
    producer_capability: Option<CapabilityId>,
    created_at: Timestamp,
    updated_at: Timestamp,
    state: FindingState,
    trace_id: Option<TraceId>,
    correlation_id: Option<CorrelationId>,
}

impl Finding {
    pub fn new(
        finding_type: impl Into<String>,
        producer_plugin: PluginId,
        evidence_refs: Vec<EvidenceId>,
        explanation: FindingExplanation,
    ) -> Result<Self, SecurityContractError> {
        if evidence_refs.is_empty() {
            return Err(SecurityContractError::EmptyEvidenceRefs);
        }

        let now = Timestamp::now();
        Ok(Self {
            finding_id: FindingId::new_v4(),
            finding_type: require_non_empty("finding_type", finding_type.into())?,
            entity_refs: Vec::new(),
            evidence_refs,
            confidence: QualityScore::default(),
            severity: SecuritySeverity::default(),
            risk_reasons: Vec::new(),
            attack_mappings: Vec::new(),
            explanation,
            producer_plugin,
            producer_capability: None,
            created_at: now.clone(),
            updated_at: now,
            state: FindingState::New,
            trace_id: None,
            correlation_id: None,
        })
    }

    pub fn id(&self) -> &FindingId {
        &self.finding_id
    }

    pub fn finding_type(&self) -> &str {
        &self.finding_type
    }

    pub fn entity_refs(&self) -> &[EntityRef] {
        &self.entity_refs
    }

    pub fn evidence_refs(&self) -> &[EvidenceId] {
        &self.evidence_refs
    }

    pub fn confidence(&self) -> &QualityScore {
        &self.confidence
    }

    pub fn severity(&self) -> &SecuritySeverity {
        &self.severity
    }

    pub fn risk_reasons(&self) -> &[RiskReason] {
        &self.risk_reasons
    }

    pub fn explanation(&self) -> &FindingExplanation {
        &self.explanation
    }

    pub fn producer_plugin(&self) -> &PluginId {
        &self.producer_plugin
    }

    pub fn state(&self) -> &FindingState {
        &self.state
    }

    pub fn attack_mappings(&self) -> &[AttackMapping] {
        &self.attack_mappings
    }

    pub fn with_attack_mappings(mut self, attack_mappings: Vec<AttackMapping>) -> Self {
        self.attack_mappings = attack_mappings;
        self
    }

    pub fn with_entity_refs(mut self, entity_refs: Vec<EntityRef>) -> Self {
        self.entity_refs = entity_refs;
        self
    }

    pub fn with_confidence(mut self, confidence: QualityScore) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_severity(mut self, severity: SecuritySeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_risk_reasons(mut self, risk_reasons: Vec<RiskReason>) -> Self {
        self.risk_reasons = risk_reasons;
        self
    }

    pub fn with_producer_capability(mut self, producer_capability: CapabilityId) -> Self {
        self.producer_capability = Some(producer_capability);
        self
    }

    pub fn with_trace_id(mut self, trace_id: TraceId) -> Self {
        self.trace_id = Some(trace_id);
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: CorrelationId) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    pub fn with_state(mut self, state: FindingState) -> Self {
        self.state = state;
        self.updated_at = Timestamp::now();
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RiskEvent {
    pub risk_event_id: RiskEventId,
    pub entity_ref: EntityRef,
    pub risk_delta: f32,
    pub risk_score: QualityScore,
    pub risk_reasons: Vec<RiskReason>,
    pub contributing_findings: Vec<FindingId>,
    pub time_window: TimeRange,
    pub decay_policy: Option<String>,
    pub created_at: Timestamp,
}

impl RiskEvent {
    pub fn new(entity_ref: EntityRef, risk_score: QualityScore) -> Self {
        Self {
            risk_event_id: RiskEventId::new_v4(),
            entity_ref,
            risk_delta: 0.0,
            risk_score,
            risk_reasons: Vec::new(),
            contributing_findings: Vec::new(),
            time_window: TimeRange::default(),
            decay_policy: None,
            created_at: Timestamp::now(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AlertCandidate {
    pub alert_candidate_id: AlertCandidateId,
    pub finding_refs: Vec<FindingId>,
    pub risk_event_refs: Vec<RiskEventId>,
    pub entity_refs: Vec<EntityRef>,
    pub severity: SecuritySeverity,
    pub confidence: QualityScore,
    pub risk_reasons: Vec<RiskReason>,
    pub created_at: Timestamp,
}

impl AlertCandidate {
    pub fn new(finding_refs: Vec<FindingId>) -> Result<Self, SecurityContractError> {
        if finding_refs.is_empty() {
            return Err(SecurityContractError::EmptyFindingRefs);
        }

        Ok(Self {
            alert_candidate_id: AlertCandidateId::new_v4(),
            finding_refs,
            risk_event_refs: Vec::new(),
            entity_refs: Vec::new(),
            severity: SecuritySeverity::default(),
            confidence: QualityScore::default(),
            risk_reasons: Vec::new(),
            created_at: Timestamp::now(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    New,
    Triaged,
    InProgress,
    EscalatedToIncident,
    Resolved,
    Suppressed,
    Dismissed,
    FalsePositive,
    Expired,
    Duplicate,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    alert_id: AlertId,
    title_redacted: String,
    summary_redacted: String,
    finding_refs: Vec<FindingId>,
    risk_event_refs: Vec<RiskEventId>,
    entity_refs: Vec<EntityRef>,
    severity: SecuritySeverity,
    confidence: QualityScore,
    state: AlertState,
    created_at: Timestamp,
    updated_at: Timestamp,
    trace_id: Option<TraceId>,
    correlation_id: Option<CorrelationId>,
}

impl Alert {
    pub fn new(
        title_redacted: impl Into<String>,
        summary_redacted: impl Into<String>,
        finding_refs: Vec<FindingId>,
    ) -> Result<Self, SecurityContractError> {
        if finding_refs.is_empty() {
            return Err(SecurityContractError::EmptyFindingRefs);
        }

        let now = Timestamp::now();
        Ok(Self {
            alert_id: AlertId::new_v4(),
            title_redacted: require_non_empty("title_redacted", title_redacted.into())?,
            summary_redacted: require_non_empty("summary_redacted", summary_redacted.into())?,
            finding_refs,
            risk_event_refs: Vec::new(),
            entity_refs: Vec::new(),
            severity: SecuritySeverity::default(),
            confidence: QualityScore::default(),
            state: AlertState::New,
            created_at: now.clone(),
            updated_at: now,
            trace_id: None,
            correlation_id: None,
        })
    }

    pub fn id(&self) -> &AlertId {
        &self.alert_id
    }

    pub fn finding_refs(&self) -> &[FindingId] {
        &self.finding_refs
    }

    pub fn risk_event_refs(&self) -> &[RiskEventId] {
        &self.risk_event_refs
    }

    pub fn entity_refs(&self) -> &[EntityRef] {
        &self.entity_refs
    }

    pub fn severity(&self) -> &SecuritySeverity {
        &self.severity
    }

    pub fn confidence(&self) -> &QualityScore {
        &self.confidence
    }

    pub fn title_redacted(&self) -> &str {
        &self.title_redacted
    }

    pub fn summary_redacted(&self) -> &str {
        &self.summary_redacted
    }

    pub fn state(&self) -> &AlertState {
        &self.state
    }

    pub fn with_risk_event_refs(mut self, risk_event_refs: Vec<RiskEventId>) -> Self {
        self.risk_event_refs = risk_event_refs;
        self
    }

    pub fn with_entity_refs(mut self, entity_refs: Vec<EntityRef>) -> Self {
        self.entity_refs = entity_refs;
        self
    }

    pub fn with_severity(mut self, severity: SecuritySeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_confidence(mut self, confidence: QualityScore) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_trace_id(mut self, trace_id: TraceId) -> Self {
        self.trace_id = Some(trace_id);
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: CorrelationId) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    pub fn with_state(mut self, state: AlertState) -> Self {
        self.state = state;
        self.updated_at = Timestamp::now();
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentCandidate {
    pub incident_candidate_id: IncidentCandidateId,
    pub title_redacted: String,
    pub summary_redacted: String,
    pub alert_refs: Vec<AlertId>,
    pub finding_refs: Vec<FindingId>,
    pub graph_path_refs: Vec<GraphPathId>,
    pub severity: SecuritySeverity,
    pub confidence: QualityScore,
    pub created_at: Timestamp,
}

impl IncidentCandidate {
    pub fn new(
        title_redacted: impl Into<String>,
        summary_redacted: impl Into<String>,
        alert_refs: Vec<AlertId>,
    ) -> Result<Self, SecurityContractError> {
        if alert_refs.is_empty() {
            return Err(SecurityContractError::EmptyAlertRefs);
        }

        Ok(Self {
            incident_candidate_id: IncidentCandidateId::new_v4(),
            title_redacted: require_non_empty("title_redacted", title_redacted.into())?,
            summary_redacted: require_non_empty("summary_redacted", summary_redacted.into())?,
            alert_refs,
            finding_refs: Vec::new(),
            graph_path_refs: Vec::new(),
            severity: SecuritySeverity::default(),
            confidence: QualityScore::default(),
            created_at: Timestamp::now(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    Candidate,
    New,
    Triaged,
    InProgress,
    Promoted,
    Contained,
    Resolved,
    Suppressed,
    Dismissed,
    Expired,
    Duplicate,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    incident_id: IncidentId,
    incident_type: String,
    title_redacted: String,
    summary_redacted: String,
    alert_refs: Vec<AlertId>,
    finding_refs: Vec<FindingId>,
    graph_path_refs: Vec<GraphPathId>,
    severity: SecuritySeverity,
    confidence: QualityScore,
    state: IncidentState,
    created_at: Timestamp,
    updated_at: Timestamp,
    resolved_at: Option<Timestamp>,
    trace_id: Option<TraceId>,
    correlation_id: Option<CorrelationId>,
    root_cause_hint_redacted: Option<String>,
    recommended_response_summary_redacted: Option<String>,
}

impl Incident {
    pub fn new(
        incident_type: impl Into<String>,
        title_redacted: impl Into<String>,
        summary_redacted: impl Into<String>,
        alert_refs: Vec<AlertId>,
    ) -> Result<Self, SecurityContractError> {
        if alert_refs.is_empty() {
            return Err(SecurityContractError::EmptyAlertRefs);
        }

        let now = Timestamp::now();
        Ok(Self {
            incident_id: IncidentId::new_v4(),
            incident_type: require_non_empty("incident_type", incident_type.into())?,
            title_redacted: require_non_empty("title_redacted", title_redacted.into())?,
            summary_redacted: require_non_empty("summary_redacted", summary_redacted.into())?,
            alert_refs,
            finding_refs: Vec::new(),
            graph_path_refs: Vec::new(),
            severity: SecuritySeverity::default(),
            confidence: QualityScore::default(),
            state: IncidentState::New,
            created_at: now.clone(),
            updated_at: now,
            resolved_at: None,
            trace_id: None,
            correlation_id: None,
            root_cause_hint_redacted: None,
            recommended_response_summary_redacted: None,
        })
    }

    pub fn id(&self) -> &IncidentId {
        &self.incident_id
    }

    pub fn alert_refs(&self) -> &[AlertId] {
        &self.alert_refs
    }

    pub fn finding_refs(&self) -> &[FindingId] {
        &self.finding_refs
    }

    pub fn graph_path_refs(&self) -> &[GraphPathId] {
        &self.graph_path_refs
    }

    pub fn severity(&self) -> &SecuritySeverity {
        &self.severity
    }

    pub fn confidence(&self) -> &QualityScore {
        &self.confidence
    }

    pub fn incident_type(&self) -> &str {
        &self.incident_type
    }

    pub fn title_redacted(&self) -> &str {
        &self.title_redacted
    }

    pub fn summary_redacted(&self) -> &str {
        &self.summary_redacted
    }

    pub fn state(&self) -> &IncidentState {
        &self.state
    }

    pub fn with_finding_refs(mut self, finding_refs: Vec<FindingId>) -> Self {
        self.finding_refs = finding_refs;
        self
    }

    pub fn with_severity(mut self, severity: SecuritySeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_confidence(mut self, confidence: QualityScore) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_graph_path_refs(mut self, graph_path_refs: Vec<GraphPathId>) -> Self {
        self.graph_path_refs = graph_path_refs;
        self
    }

    pub fn with_trace_id(mut self, trace_id: TraceId) -> Self {
        self.trace_id = Some(trace_id);
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: CorrelationId) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    pub fn with_root_cause_hint_redacted(
        mut self,
        root_cause_hint_redacted: impl Into<String>,
    ) -> Self {
        self.root_cause_hint_redacted = Some(root_cause_hint_redacted.into());
        self
    }

    pub fn with_recommended_response_summary_redacted(
        mut self,
        recommended_response_summary_redacted: impl Into<String>,
    ) -> Self {
        self.recommended_response_summary_redacted =
            Some(recommended_response_summary_redacted.into());
        self
    }

    pub fn with_state(mut self, state: IncidentState) -> Self {
        if state == IncidentState::Resolved {
            self.resolved_at = Some(Timestamp::now());
        }
        self.state = state;
        self.updated_at = Timestamp::now();
        self
    }
}

fn require_non_empty(field: &'static str, value: String) -> Result<String, SecurityContractError> {
    if value.trim().is_empty() {
        return Err(SecurityContractError::EmptyField(field));
    }

    Ok(value)
}

fn require_attack_identifier(
    field: &'static str,
    value: String,
) -> Result<String, SecurityContractError> {
    let value = require_bounded_attack_label(field, value)?;
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '.')
    {
        return Err(SecurityContractError::UnsafeAttackCoverageClaim(
            "ATT&CK identifiers must be bounded alphanumeric identifiers",
        ));
    }
    Ok(value)
}

fn require_bounded_attack_label(
    field: &'static str,
    value: String,
) -> Result<String, SecurityContractError> {
    let value = require_non_empty(field, value)?;
    if value.len() > 128 {
        return Err(SecurityContractError::UnsafeAttackCoverageClaim(
            "ATT&CK coverage labels must be bounded",
        ));
    }
    let lower = value.to_ascii_lowercase();
    const FORBIDDEN_MARKERS: &[&str] = &[
        "raw_packet",
        "packet_bytes",
        "raw_payload",
        "payload",
        "http_body",
        "cookie",
        "authorization",
        "token",
        "credential",
        "password",
        "api_key",
        "apikey",
        "private_key",
        "query_string",
        "full_query",
        "form_content",
        "command_line",
        "local_path",
    ];
    if FORBIDDEN_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return Err(SecurityContractError::UnsafeAttackCoverageClaim(
            "ATT&CK coverage labels must not carry sensitive markers",
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_requires_evidence_refs() {
        let producer = PluginId::new_v4();
        let explanation = FindingExplanation::new("redacted summary").expect("valid explanation");
        let result = Finding::new("c2_signal", producer, Vec::new(), explanation);

        assert_eq!(result, Err(SecurityContractError::EmptyEvidenceRefs));
    }

    #[test]
    fn finding_does_not_require_attack_mapping() {
        let producer = PluginId::new_v4();
        let explanation = FindingExplanation::new("redacted summary").expect("valid explanation");
        let finding = Finding::new(
            "internal_signal",
            producer,
            vec![EvidenceId::new_v4()],
            explanation,
        )
        .expect("finding can be built without attack mapping");

        assert!(finding.attack_mappings().is_empty());
    }

    #[test]
    fn attack_mapping_supports_mitre_and_internal_taxonomies() {
        let provenance = MappingProvenance::new("sentinel-guard-v1").expect("valid source");
        let mitre = AttackMapping::mitre_attack_enterprise(
            "TA0011",
            "Command and Control",
            "T1071",
            "Application Layer Protocol",
            QualityScore::perfect(),
            Some(provenance),
        )
        .expect("valid mitre mapping")
        .with_subtechnique("T1071.001", "Web Protocols")
        .expect("valid subtechnique");
        let internal =
            AttackMapping::internal("local_network_behavior", QualityScore::perfect(), None)
                .expect("valid internal mapping");

        assert_eq!(mitre.taxonomy, AttackTaxonomy::MitreAttackEnterprise);
        assert_eq!(mitre.subtechnique_id.as_deref(), Some("T1071.001"));
        assert_eq!(internal.taxonomy, AttackTaxonomy::Internal);
    }

    #[test]
    fn attack_coverage_summary_is_bounded_and_not_complete() {
        let mut row = AttackCoverageTechniqueRow::new(
            "TA0011",
            "T1071.001",
            "enterprise-verified-2026-06-12",
            vec!["portable_http_analysis_v1".to_string()],
            AttackCoverageConfidenceBucket::Medium,
            AttackRequiredVisibility::PortableNetworkMetadata,
            "http_analysis_v1",
            AttackObservedCountBucket::Single,
            AttackLastObservedBucket::CurrentSession,
            vec![
                AttackCoverageState::Covered,
                AttackCoverageState::Observed,
                AttackCoverageState::EvidenceBacked,
                AttackCoverageState::Degraded,
            ],
        )
        .expect("safe row");
        row.finding_refs.push(FindingId::new_v4());
        row.evidence_refs.push(EvidenceId::new_v4());

        let mut summary =
            AttackCoverageSummary::new("enterprise-verified-2026-06-12").expect("summary");
        summary.technique_rows.push(row);
        summary.top_tactics = vec![AttackCoverageCount::new("TA0011", 1).expect("count")];
        summary.complete_coverage_claimed = false;

        summary.validate().expect("bounded summary is valid");
    }

    #[test]
    fn attack_coverage_rejects_complete_or_high_confidence_native_claims() {
        let native = AttackCoverageTechniqueRow::new(
            "TA0002",
            "T1059",
            "enterprise-verified-2026-06-12",
            vec!["authorized_native_extension".to_string()],
            AttackCoverageConfidenceBucket::High,
            AttackRequiredVisibility::AuthorizedNativeProcessVisibility,
            "authorized_native_extension",
            AttackObservedCountBucket::None,
            AttackLastObservedBucket::None,
            vec![AttackCoverageState::RequiresAuthorizedNativeExtension],
        );
        assert!(matches!(
            native,
            Err(SecurityContractError::UnsafeAttackCoverageClaim(_))
        ));

        let mut summary =
            AttackCoverageSummary::new("enterprise-verified-2026-06-12").expect("summary");
        summary.complete_coverage_claimed = true;
        assert!(matches!(
            summary.validate(),
            Err(SecurityContractError::UnsafeAttackCoverageClaim(_))
        ));
    }

    #[test]
    fn attack_coverage_rejects_sensitive_labels() {
        let sensitive = AttackCoverageTechniqueRow::new(
            "TA0011",
            "T1071.001",
            "enterprise-verified-2026-06-12",
            vec!["session_token_probe".to_string()],
            AttackCoverageConfidenceBucket::Low,
            AttackRequiredVisibility::PortableNetworkMetadata,
            "api_security_lite",
            AttackObservedCountBucket::None,
            AttackLastObservedBucket::None,
            vec![AttackCoverageState::Covered],
        );

        assert!(matches!(
            sensitive,
            Err(SecurityContractError::UnsafeAttackCoverageClaim(_))
        ));
    }

    #[test]
    fn alert_and_incident_require_traceable_sources() {
        let alert = Alert::new(
            "redacted title",
            "redacted summary",
            vec![FindingId::new_v4()],
        )
        .expect("alert has finding trace");
        let incident = Incident::new(
            "c2_communication_incident",
            "redacted incident",
            "redacted summary",
            vec![alert.id().clone()],
        )
        .expect("incident has alert trace")
        .with_graph_path_refs(vec![GraphPathId::new_v4()]);

        assert!(!alert.finding_refs().is_empty());
        assert!(!incident.alert_refs().is_empty());
        assert_eq!(incident.graph_path_refs().len(), 1);
    }

    #[test]
    fn alert_and_incident_can_carry_risk_context() {
        let finding_id = FindingId::new_v4();
        let risk_event_id = RiskEventId::new_v4();
        let entity = EntityRef::new(
            crate::common::EntityId::new_v4(),
            crate::common::EntityType::Process,
        );
        let alert = Alert::new(
            "redacted title",
            "redacted summary",
            vec![finding_id.clone()],
        )
        .expect("alert")
        .with_risk_event_refs(vec![risk_event_id.clone()])
        .with_entity_refs(vec![entity.clone()])
        .with_severity(SecuritySeverity::High)
        .with_confidence(QualityScore::new(0.82).expect("confidence"));

        let incident = Incident::new(
            "c2_communication_incident",
            "redacted incident",
            "redacted summary",
            vec![alert.id().clone()],
        )
        .expect("incident")
        .with_finding_refs(vec![finding_id])
        .with_severity(SecuritySeverity::High)
        .with_confidence(QualityScore::new(0.79).expect("confidence"))
        .with_root_cause_hint_redacted("risk-based aggregation")
        .with_recommended_response_summary_redacted("review recommended containment options");

        assert_eq!(alert.risk_event_refs(), &[risk_event_id]);
        assert_eq!(alert.entity_refs(), &[entity]);
        assert_eq!(alert.severity(), &SecuritySeverity::High);
        assert_eq!(incident.finding_refs().len(), 1);
        assert_eq!(incident.severity(), &SecuritySeverity::High);
    }
}
