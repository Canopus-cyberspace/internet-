use sentinel_contracts::{
    AttackHypothesisDefinition, AttackHypothesisId, BaselineRecordId, DataSourceId,
    EndpointAnalysisInput, EndpointAttackRef, EndpointCorrelationQualityBucket,
    EndpointCountChangeBucket, EndpointEvidenceQualityBucket, EndpointFreshnessCategory,
    EndpointMissingVisibilityFlag, EndpointRejectedCandidate, EndpointRejectedCandidateId,
    EndpointRejectedCandidateReason, EndpointSourceReliabilityBucket, EndpointThreatCandidate,
    EndpointThreatCandidateCategory, EndpointThreatCandidateId, EndpointThreatCausalClaim,
    EndpointThreatConfidenceBucket, EndpointThreatFinding, EndpointThreatFindingCategory,
    EndpointThreatFindingId, EndpointThreatSeverityBucket, EndpointVisibilityAdvisory,
    EndpointVisibilityAdvisoryCategory, EndpointVisibilityAdvisoryId, EntityId, EntityRef,
    EntityType, EvidenceId, FindingId, FusionAttackCandidate, FusionConfidenceBucket, GraphHint,
    GraphHintType, HypothesisFactRequirement, IntelligenceRecordId, PluginId, PrivacyClass,
    QualityScore, RedactionStatus, RiskEventId, RiskHint, SecurityFactId, SecurityLayer,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MAX_ENDPOINT_DETECTOR_REFS: usize = 64;
pub const MAX_ENDPOINT_DETECTOR_LABELS: usize = 32;
pub const MAX_ENDPOINT_DETECTOR_TEXT_BYTES: usize = 180;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointThreatDetectionError {
    EmptyField(&'static str),
    UnsafeField(&'static str),
    ExceedsBound(&'static str),
    InvalidDefinition(&'static str),
    InvalidInput(&'static str),
    DuplicateEvidence,
    CyclicEvidence,
    EvidenceSelfReference,
    GraphRecursion,
    Contract(String),
}

impl fmt::Display for EndpointThreatDetectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains unsafe data"),
            Self::ExceedsBound(field) => write!(formatter, "{field} exceeds bounded limits"),
            Self::InvalidDefinition(reason) => {
                write!(formatter, "invalid detector definition: {reason}")
            }
            Self::InvalidInput(reason) => {
                write!(formatter, "invalid endpoint detector input: {reason}")
            }
            Self::DuplicateEvidence => write!(formatter, "duplicate evidence is not allowed"),
            Self::CyclicEvidence => write!(formatter, "cyclic evidence graph is not allowed"),
            Self::EvidenceSelfReference => write!(formatter, "evidence cannot reference itself"),
            Self::GraphRecursion => write!(formatter, "graph-recursive evidence is not allowed"),
            Self::Contract(reason) => write!(formatter, "endpoint threat contract error: {reason}"),
        }
    }
}

impl std::error::Error for EndpointThreatDetectionError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointDetectorFamily {
    ProcessCategoryAnomaly,
    ServiceCategoryAnomaly,
    TrustSignednessAnomaly,
    PrivilegeContextAnomaly,
    LifecycleAnomaly,
    NativeHealthCorrelation,
    PortableFindingCorrelation,
    VisibilityDegradationAdvisory,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointDetectorEvidenceLayer {
    ProcessCategory,
    ParentRelation,
    ServiceCategory,
    NativeHealth,
    PortableFinding,
    Baseline,
    Hypothesis,
    Risk,
    Attack,
    Scheduler,
    Readiness,
    SamplerHealth,
    Freshness,
    Graph,
    Ui,
    Llm,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointDetectorEvidenceCategory {
    ProcessCategoryFact,
    ParentRelationFact,
    ServiceCategoryFact,
    NativeHealthFact,
    PortableFinding,
    HighQualityFinding,
    BaselineDeviation,
    EvidenceBackedHypothesis,
    RiskReference,
    AttackMapping,
    SchedulerState,
    ReadinessState,
    SamplerHealth,
    FreshnessOnly,
    GraphHint,
    UiState,
    LlmText,
}

impl EndpointDetectorEvidenceCategory {
    fn is_independence_excluded(&self) -> bool {
        matches!(
            self,
            Self::SchedulerState
                | Self::ReadinessState
                | Self::SamplerHealth
                | Self::FreshnessOnly
                | Self::AttackMapping
                | Self::GraphHint
                | Self::UiState
                | Self::LlmText
        )
    }

    fn is_broad_category_context(&self) -> bool {
        matches!(
            self,
            Self::ProcessCategoryFact
                | Self::ParentRelationFact
                | Self::ServiceCategoryFact
                | Self::NativeHealthFact
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointCorrelationWindowBucket {
    CurrentSession,
    Short,
    Medium,
    Long,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointBaselineRequirement {
    NotRequired,
    FreshDeviation,
    RareOrFirstSeen,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointConfidenceFormula {
    IndependentEvidenceWeighted,
    FindingBaselineWeighted,
    HypothesisNativeFactWeighted,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointIndependentEvidencePattern {
    TwoIndependentLayers,
    HighQualityFindingWithFreshBaseline,
    EvidenceBackedHypothesisWithFreshNativeFacts,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointQualityRequirements {
    pub minimum_evidence_quality: EndpointEvidenceQualityBucket,
    pub minimum_source_reliability: EndpointSourceReliabilityBucket,
    pub minimum_correlation_quality: EndpointCorrelationQualityBucket,
    pub require_redacted: bool,
}

impl Default for EndpointQualityRequirements {
    fn default() -> Self {
        Self {
            minimum_evidence_quality: EndpointEvidenceQualityBucket::Low,
            minimum_source_reliability: EndpointSourceReliabilityBucket::Weak,
            minimum_correlation_quality: EndpointCorrelationQualityBucket::SingleSignal,
            require_redacted: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointFreshnessRequirements {
    pub accepted: Vec<EndpointFreshnessCategory>,
}

impl Default for EndpointFreshnessRequirements {
    fn default() -> Self {
        Self {
            accepted: vec![
                EndpointFreshnessCategory::Fresh,
                EndpointFreshnessCategory::Aging,
            ],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointThreatDetectorDefinition {
    pub detector_id: String,
    pub detector_version: String,
    pub detector_family: EndpointDetectorFamily,
    pub required_fact_categories: Vec<String>,
    pub required_independent_evidence_categories: Vec<EndpointDetectorEvidenceCategory>,
    pub optional_supporting_categories: Vec<EndpointDetectorEvidenceCategory>,
    pub disqualifiers: Vec<String>,
    pub minimum_evidence_count: u8,
    pub minimum_independent_source_count: u8,
    pub correlation_window: EndpointCorrelationWindowBucket,
    pub baseline_requirements: Vec<EndpointBaselineRequirement>,
    pub confidence_formula: EndpointConfidenceFormula,
    pub confidence_cap: EndpointThreatConfidenceBucket,
    pub quality_requirements: EndpointQualityRequirements,
    pub freshness_requirements: EndpointFreshnessRequirements,
    pub degradation_rules: Vec<String>,
    pub missing_visibility_flags: Vec<EndpointMissingVisibilityFlag>,
    pub attack_candidates: Vec<EndpointAttackRef>,
    pub safe_wording: String,
    pub report_template: String,
    pub safety_notes: Vec<String>,
}

impl EndpointThreatDetectorDefinition {
    pub fn validate(&self) -> Result<(), EndpointThreatDetectionError> {
        safe_text("detector_id", &self.detector_id)?;
        safe_text("detector_version", &self.detector_version)?;
        validate_labels("required_fact_categories", &self.required_fact_categories)?;
        validate_labels("disqualifiers", &self.disqualifiers)?;
        validate_labels("degradation_rules", &self.degradation_rules)?;
        safe_text("safe_wording", &self.safe_wording)?;
        safe_text("report_template", &self.report_template)?;
        validate_labels("safety_notes", &self.safety_notes)?;
        validate_category_count(
            "required_independent_evidence_categories",
            self.required_independent_evidence_categories.len(),
        )?;
        validate_category_count(
            "optional_supporting_categories",
            self.optional_supporting_categories.len(),
        )?;
        validate_category_count("baseline_requirements", self.baseline_requirements.len())?;
        validate_category_count(
            "missing_visibility_flags",
            self.missing_visibility_flags.len(),
        )?;
        if self.minimum_evidence_count == 0 || self.minimum_independent_source_count == 0 {
            return Err(EndpointThreatDetectionError::InvalidDefinition(
                "detectors must require evidence and independent sources",
            ));
        }
        if self.required_independent_evidence_categories.is_empty() {
            return Err(EndpointThreatDetectionError::InvalidDefinition(
                "detectors must declare independent evidence categories",
            ));
        }
        for attack_ref in &self.attack_candidates {
            attack_ref
                .validate()
                .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
        }
        if self
            .required_independent_evidence_categories
            .iter()
            .any(EndpointDetectorEvidenceCategory::is_independence_excluded)
        {
            return Err(EndpointThreatDetectionError::InvalidDefinition(
                "required evidence categories cannot be excluded independence sources",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointDetectorEvidenceRecord {
    pub evidence_ref: EvidenceId,
    pub layer: EndpointDetectorEvidenceLayer,
    pub category: EndpointDetectorEvidenceCategory,
    pub provenance_id: DataSourceId,
    pub source_key: String,
    pub sample_group_ref: Option<String>,
    pub parent_evidence_refs: Vec<EvidenceId>,
    pub generated_from_candidate_ref: Option<EndpointThreatCandidateId>,
    pub finding_ref: Option<FindingId>,
    pub hypothesis_ref: Option<AttackHypothesisId>,
    pub baseline_ref: Option<BaselineRecordId>,
    pub risk_ref: Option<RiskEventId>,
    pub quality_bucket: EndpointEvidenceQualityBucket,
    pub reliability_bucket: EndpointSourceReliabilityBucket,
    pub freshness_category: EndpointFreshnessCategory,
    pub correlation_quality_bucket: EndpointCorrelationQualityBucket,
    pub redaction_status: RedactionStatus,
}

impl EndpointDetectorEvidenceRecord {
    pub fn validate(&self) -> Result<(), EndpointThreatDetectionError> {
        safe_text("endpoint_evidence.source_key", &self.source_key)?;
        if let Some(sample_group_ref) = &self.sample_group_ref {
            safe_text("endpoint_evidence.sample_group_ref", sample_group_ref)?;
        }
        validate_ref_count(
            "endpoint_evidence.parent_evidence_refs",
            self.parent_evidence_refs.len(),
        )?;
        require_redacted("endpoint_evidence.redaction_status", &self.redaction_status)?;
        if self.parent_evidence_refs.contains(&self.evidence_ref) {
            return Err(EndpointThreatDetectionError::EvidenceSelfReference);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointDetectorFactRecord {
    pub fact_ref: SecurityFactId,
    pub category: String,
    pub layer: EndpointDetectorEvidenceLayer,
    pub provenance_id: DataSourceId,
    pub evidence_refs: Vec<EvidenceId>,
    pub sample_group_ref: Option<String>,
    pub freshness_category: EndpointFreshnessCategory,
    pub redaction_status: RedactionStatus,
}

impl EndpointDetectorFactRecord {
    pub fn validate(&self) -> Result<(), EndpointThreatDetectionError> {
        safe_text("endpoint_fact.category", &self.category)?;
        validate_ref_count("endpoint_fact.evidence_refs", self.evidence_refs.len())?;
        if let Some(sample_group_ref) = &self.sample_group_ref {
            safe_text("endpoint_fact.sample_group_ref", sample_group_ref)?;
        }
        require_redacted("endpoint_fact.redaction_status", &self.redaction_status)
    }

    fn is_fresh_native_category_fact(&self) -> bool {
        matches!(
            self.layer,
            EndpointDetectorEvidenceLayer::ProcessCategory
                | EndpointDetectorEvidenceLayer::ParentRelation
                | EndpointDetectorEvidenceLayer::ServiceCategory
                | EndpointDetectorEvidenceLayer::NativeHealth
        ) && self.freshness_category == EndpointFreshnessCategory::Fresh
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointThreatDetectionInput {
    pub analysis_input: EndpointAnalysisInput,
    pub candidate_ref: Option<EndpointThreatCandidateId>,
    pub evidence: Vec<EndpointDetectorEvidenceRecord>,
    pub facts: Vec<EndpointDetectorFactRecord>,
}

impl EndpointThreatDetectionInput {
    pub fn validate(&self) -> Result<(), EndpointThreatDetectionError> {
        self.analysis_input
            .validate()
            .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
        validate_ref_count("endpoint_detection.evidence", self.evidence.len())?;
        validate_ref_count("endpoint_detection.facts", self.facts.len())?;
        if self.evidence.is_empty() {
            return Err(EndpointThreatDetectionError::InvalidInput(
                "detector input requires evidence records",
            ));
        }
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        for fact in &self.facts {
            fact.validate()?;
        }
        validate_evidence_graph(&self.evidence)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointEvidenceValidationReport {
    pub pattern: Option<EndpointIndependentEvidencePattern>,
    pub independent_source_count: u8,
    pub independent_layer_count: u8,
    pub independent_evidence_refs: Vec<EvidenceId>,
    pub rejected_reason: Option<EndpointRejectedCandidateReason>,
    pub broad_category_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointConfidenceReport {
    pub confidence_bucket: EndpointThreatConfidenceBucket,
    pub severity_bucket: EndpointThreatSeverityBucket,
    pub capped_by: Vec<String>,
    pub score_bucket: EndpointCountChangeBucket,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointThreatDetectionEvaluation {
    pub accepted: bool,
    pub detector_id: String,
    pub detector_version: String,
    pub evidence_validation: EndpointEvidenceValidationReport,
    pub confidence: EndpointConfidenceReport,
    pub candidate: Option<EndpointThreatCandidate>,
    pub rejected_candidate: Option<EndpointRejectedCandidate>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointThreatDetectorPackOutput {
    pub evaluations: Vec<EndpointThreatDetectionEvaluation>,
    pub findings: Vec<EndpointThreatFinding>,
    pub advisories: Vec<EndpointVisibilityAdvisory>,
    pub rejected_candidates: Vec<EndpointRejectedCandidate>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointThreatIntelligenceInput {
    pub findings: Vec<EndpointThreatFinding>,
    pub facts: Vec<EndpointDetectorFactRecord>,
    pub evaluations: Vec<EndpointThreatDetectionEvaluation>,
}

impl EndpointThreatIntelligenceInput {
    pub fn validate(&self) -> Result<(), EndpointThreatDetectionError> {
        validate_ref_count("endpoint_intelligence.findings", self.findings.len())?;
        validate_ref_count("endpoint_intelligence.facts", self.facts.len())?;
        validate_ref_count("endpoint_intelligence.evaluations", self.evaluations.len())?;
        for fact in &self.facts {
            fact.validate()?;
        }
        for evaluation in &self.evaluations {
            safe_text("endpoint_intelligence.detector_id", &evaluation.detector_id)?;
            safe_text(
                "endpoint_intelligence.detector_version",
                &evaluation.detector_version,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointAttackContextAttachment {
    pub finding_ref: EndpointThreatFindingId,
    pub attack_ref: EndpointAttackRef,
    pub evidence_refs: Vec<EvidenceId>,
    pub technique_observed: bool,
    pub confidence_cap: EndpointThreatConfidenceBucket,
    pub unsupported_visibility: Vec<String>,
    pub safe_wording: String,
}

impl EndpointAttackContextAttachment {
    pub fn validate(&self) -> Result<(), EndpointThreatDetectionError> {
        self.attack_ref
            .validate()
            .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
        validate_ref_count(
            "endpoint_attack_context.evidence_refs",
            self.evidence_refs.len(),
        )?;
        validate_labels(
            "endpoint_attack_context.unsupported_visibility",
            &self.unsupported_visibility,
        )?;
        safe_text("endpoint_attack_context.safe_wording", &self.safe_wording)?;
        if self.technique_observed {
            return Err(EndpointThreatDetectionError::InvalidInput(
                "endpoint category context cannot mark ATT&CK techniques observed",
            ));
        }
        if self.evidence_refs.is_empty() {
            return Err(EndpointThreatDetectionError::InvalidInput(
                "ATT&CK context attachment requires evidence refs",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EndpointThreatIntelligenceOutput {
    pub risk_hints: Vec<RiskHint>,
    pub hypothesis_definitions: Vec<AttackHypothesisDefinition>,
    pub attack_attachments: Vec<EndpointAttackContextAttachment>,
    pub graph_hints: Vec<GraphHint>,
    pub rejected_finding_refs: Vec<EndpointThreatFindingId>,
}

impl EndpointThreatIntelligenceOutput {
    pub fn validate(&self) -> Result<(), EndpointThreatDetectionError> {
        validate_ref_count("endpoint_intelligence.risk_hints", self.risk_hints.len())?;
        validate_ref_count(
            "endpoint_intelligence.hypothesis_definitions",
            self.hypothesis_definitions.len(),
        )?;
        validate_ref_count(
            "endpoint_intelligence.attack_attachments",
            self.attack_attachments.len(),
        )?;
        validate_ref_count("endpoint_intelligence.graph_hints", self.graph_hints.len())?;
        validate_ref_count(
            "endpoint_intelligence.rejected_finding_refs",
            self.rejected_finding_refs.len(),
        )?;
        for risk_hint in &self.risk_hints {
            risk_hint
                .validate_boundary()
                .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
        }
        for definition in &self.hypothesis_definitions {
            definition
                .validate()
                .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
        }
        for attachment in &self.attack_attachments {
            attachment.validate()?;
        }
        for hint in &self.graph_hints {
            validate_graph_hint_boundary(hint)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct EndpointThreatDetectorFramework;

impl EndpointThreatDetectorFramework {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(
        &self,
        definition: &EndpointThreatDetectorDefinition,
        input: &EndpointThreatDetectionInput,
    ) -> Result<EndpointThreatDetectionEvaluation, EndpointThreatDetectionError> {
        definition.validate()?;
        input.validate()?;
        reject_disqualified(definition, input)?;

        let evidence_validation = validate_independent_evidence(definition, input)?;
        let confidence = calculate_confidence(definition, input, &evidence_validation);
        let accepted = evidence_validation.rejected_reason.is_none();
        let detector_id = definition.detector_id.clone();
        let detector_version = definition.detector_version.clone();

        if accepted {
            let candidate = build_candidate(definition, input, &evidence_validation, &confidence)?;
            Ok(EndpointThreatDetectionEvaluation {
                accepted,
                detector_id,
                detector_version,
                evidence_validation,
                confidence,
                candidate: Some(candidate),
                rejected_candidate: None,
            })
        } else {
            let rejected_candidate =
                build_rejected_candidate(definition, input, &evidence_validation)?;
            Ok(EndpointThreatDetectionEvaluation {
                accepted,
                detector_id,
                detector_version,
                evidence_validation,
                confidence,
                candidate: None,
                rejected_candidate: Some(rejected_candidate),
            })
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct EndpointThreatDetectorPack {
    framework: EndpointThreatDetectorFramework,
}

impl EndpointThreatDetectorPack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn analyze(
        &self,
        input: &EndpointThreatDetectionInput,
    ) -> Result<EndpointThreatDetectorPackOutput, EndpointThreatDetectionError> {
        input.validate()?;
        let mut output = EndpointThreatDetectorPackOutput::default();

        for definition in endpoint_threat_lite_detector_pack_catalog()? {
            if definition.detector_family == EndpointDetectorFamily::VisibilityDegradationAdvisory {
                if let Some(advisory) = build_visibility_advisory(&definition, input)? {
                    output.advisories.push(advisory);
                }
                continue;
            }

            if !required_fact_categories_match(&definition, input) {
                continue;
            }

            let evaluation = self.framework.evaluate(&definition, input)?;
            if let Some(rejected) = evaluation.rejected_candidate.clone() {
                output.rejected_candidates.push(rejected);
            }
            if let Some(candidate) = evaluation.candidate.clone() {
                let finding = build_endpoint_threat_finding(&definition, &candidate)?;
                output.findings.push(finding);
            }
            output.evaluations.push(evaluation);
        }

        Ok(output)
    }
}

#[derive(Clone, Debug, Default)]
pub struct EndpointThreatIntelligenceIntegrator;

impl EndpointThreatIntelligenceIntegrator {
    pub fn new() -> Self {
        Self
    }

    pub fn integrate(
        &self,
        input: &EndpointThreatIntelligenceInput,
    ) -> Result<EndpointThreatIntelligenceOutput, EndpointThreatDetectionError> {
        input.validate()?;

        let mut output = EndpointThreatIntelligenceOutput {
            hypothesis_definitions: endpoint_threat_intelligence_hypothesis_catalog()?,
            ..EndpointThreatIntelligenceOutput::default()
        };

        for finding in &input.findings {
            if finding.validate().is_err()
                || finding.causal_claim != EndpointThreatCausalClaim::CorrelationOnly
            {
                output
                    .rejected_finding_refs
                    .push(finding.finding_id.clone());
                continue;
            }

            let risk_hint = build_endpoint_risk_hint(finding)?;
            let risk_entity_id = EntityId::from_uuid(risk_hint.risk_hint_id.as_uuid());
            output.risk_hints.push(risk_hint);

            output
                .attack_attachments
                .extend(build_attack_context_attachments(finding)?);
            output.graph_hints.extend(build_endpoint_graph_hints(
                finding,
                input,
                Some(risk_entity_id),
            )?);
            output.graph_hints.truncate(MAX_ENDPOINT_DETECTOR_REFS);
        }

        output.validate()?;
        Ok(output)
    }
}

pub fn endpoint_threat_intelligence_hypothesis_catalog(
) -> Result<Vec<AttackHypothesisDefinition>, EndpointThreatDetectionError> {
    [
        endpoint_hypothesis_definition(EndpointHypothesisDefinitionSpec {
            category: "possible_endpoint_activity_with_auth_pressure",
            required_facts: vec![
                requirement(
                    SecurityLayer::AuthorizedNativeProcess,
                    &["process_category"],
                ),
                requirement(SecurityLayer::AuthIdentity, &["auth_pressure"]),
            ],
            optional_facts: vec![requirement(
                SecurityLayer::AuthorizedNativeHealth,
                &["native_health"],
            )],
            context_labels: vec!["auth_context", "process_category_context"],
            report_template:
                "Endpoint category context aligns with independent auth pressure signals.",
            required_visibility: "auth_pressure",
            tactic_id: "TA0007",
            technique_id: "T1082",
        }),
        endpoint_hypothesis_definition(EndpointHypothesisDefinitionSpec {
            category: "possible_endpoint_context_for_api_abuse",
            required_facts: vec![
                requirement(
                    SecurityLayer::AuthorizedNativeProcess,
                    &["process_category"],
                ),
                requirement(SecurityLayer::Api, &["api_error_pattern"]),
            ],
            optional_facts: vec![requirement(SecurityLayer::Http, &["http_status_pattern"])],
            context_labels: vec!["api_context", "process_category_context"],
            report_template:
                "Endpoint category context aligns with independent API anomaly signals.",
            required_visibility: "api_abuse_context",
            tactic_id: "TA0007",
            technique_id: "T1082",
        }),
        endpoint_hypothesis_definition(EndpointHypothesisDefinitionSpec {
            category: "possible_endpoint_context_for_saas_cloud_abuse",
            required_facts: vec![
                requirement(
                    SecurityLayer::AuthorizedNativeProcess,
                    &["process_category"],
                ),
                requirement(SecurityLayer::SaasCloud, &["saas_cloud_context"]),
            ],
            optional_facts: vec![requirement(SecurityLayer::Api, &["api_error_pattern"])],
            context_labels: vec!["saas_cloud_context", "process_category_context"],
            report_template:
                "Endpoint category context aligns with independent SaaS or cloud provider signals.",
            required_visibility: "saas_cloud_context",
            tactic_id: "TA0007",
            technique_id: "T1082",
        }),
        endpoint_hypothesis_definition(EndpointHypothesisDefinitionSpec {
            category: "possible_deception_correlated_endpoint_probe",
            required_facts: vec![
                requirement(
                    SecurityLayer::AuthorizedNativeProcess,
                    &["process_category"],
                ),
                requirement(SecurityLayer::Deception, &["decoy_interaction"]),
            ],
            optional_facts: vec![requirement(SecurityLayer::AuthIdentity, &["auth_pressure"])],
            context_labels: vec!["deception_context", "process_category_context"],
            report_template:
                "Endpoint category context aligns with independent decoy interaction signals.",
            required_visibility: "deception_probe_context",
            tactic_id: "TA0007",
            technique_id: "T1082",
        }),
        endpoint_hypothesis_definition(EndpointHypothesisDefinitionSpec {
            category: "possible_service_change_with_independent_security_evidence",
            required_facts: vec![
                requirement(
                    SecurityLayer::AuthorizedNativeService,
                    &["service_state_change"],
                ),
                requirement(SecurityLayer::Waf, &["security_finding"]),
            ],
            optional_facts: vec![requirement(SecurityLayer::AuthIdentity, &["auth_pressure"])],
            context_labels: vec!["service_category_context", "security_context"],
            report_template:
                "Service category state context aligns with independent security evidence.",
            required_visibility: "service_security_context",
            tactic_id: "TA0007",
            technique_id: "T1082",
        }),
        endpoint_hypothesis_definition(EndpointHypothesisDefinitionSpec {
            category: "possible_multi_layer_endpoint_attack_chain",
            required_facts: vec![
                requirement(
                    SecurityLayer::AuthorizedNativeProcess,
                    &["process_category"],
                ),
                requirement(SecurityLayer::AuthIdentity, &["auth_pressure"]),
                requirement(SecurityLayer::SaasCloud, &["saas_cloud_context"]),
            ],
            optional_facts: vec![
                requirement(SecurityLayer::Deception, &["decoy_interaction"]),
                requirement(
                    SecurityLayer::AuthorizedNativeService,
                    &["service_state_change"],
                ),
            ],
            context_labels: vec!["multi_layer_context", "process_category_context"],
            report_template:
                "Multiple independent security layers align with endpoint category context.",
            required_visibility: "multi_layer_endpoint_context",
            tactic_id: "TA0007",
            technique_id: "T1082",
        }),
    ]
    .into_iter()
    .collect()
}

pub fn endpoint_threat_detector_catalog(
) -> Result<Vec<EndpointThreatDetectorDefinition>, EndpointThreatDetectionError> {
    let definition = EndpointThreatDetectorDefinition {
        detector_id: "endpoint_threat_lite.category_correlation".to_string(),
        detector_version: "1.0.0".to_string(),
        detector_family: EndpointDetectorFamily::PortableFindingCorrelation,
        required_fact_categories: vec![
            "process_category".to_string(),
            "service_category".to_string(),
        ],
        required_independent_evidence_categories: vec![
            EndpointDetectorEvidenceCategory::PortableFinding,
            EndpointDetectorEvidenceCategory::BaselineDeviation,
        ],
        optional_supporting_categories: vec![
            EndpointDetectorEvidenceCategory::HighQualityFinding,
            EndpointDetectorEvidenceCategory::NativeHealthFact,
            EndpointDetectorEvidenceCategory::EvidenceBackedHypothesis,
        ],
        disqualifiers: vec!["benign_baseline".to_string()],
        minimum_evidence_count: 2,
        minimum_independent_source_count: 2,
        correlation_window: EndpointCorrelationWindowBucket::CurrentSession,
        baseline_requirements: vec![EndpointBaselineRequirement::FreshDeviation],
        confidence_formula: EndpointConfidenceFormula::IndependentEvidenceWeighted,
        confidence_cap: EndpointThreatConfidenceBucket::Moderate,
        quality_requirements: EndpointQualityRequirements::default(),
        freshness_requirements: EndpointFreshnessRequirements::default(),
        degradation_rules: vec![
            "category_only_context_caps_confidence".to_string(),
            "missing_process_network_attribution_caps_confidence".to_string(),
        ],
        missing_visibility_flags: vec![
            EndpointMissingVisibilityFlag::ProcessNetworkAttributionUnavailable,
            EndpointMissingVisibilityFlag::CommandLineVisibilityUnavailable,
            EndpointMissingVisibilityFlag::FileRegistryVisibilityUnavailable,
            EndpointMissingVisibilityFlag::PacketVisibilityUnavailable,
            EndpointMissingVisibilityFlag::SpecificProcessIdentityUnavailable,
        ],
        attack_candidates: vec![EndpointAttackRef {
            tactic_id: "TA0007".to_string(),
            technique_id: "T1082".to_string(),
            attack_version: "enterprise_2026_metadata_only".to_string(),
            confidence_bucket: EndpointThreatConfidenceBucket::Low,
            required_visibility: vec![
                EndpointMissingVisibilityFlag::CommandLineVisibilityUnavailable,
            ],
        }],
        safe_wording: "possible endpoint context supporting an existing security finding"
            .to_string(),
        report_template: "endpoint_threat_lite_correlation_only".to_string(),
        safety_notes: vec![
            "does_not_confirm_compromise".to_string(),
            "does_not_identify_specific_process".to_string(),
            "does_not_claim_process_network_attribution".to_string(),
        ],
    };
    definition.validate()?;
    Ok(vec![definition])
}

pub fn endpoint_threat_lite_detector_pack_catalog(
) -> Result<Vec<EndpointThreatDetectorDefinition>, EndpointThreatDetectionError> {
    let definitions = vec![
        pack_definition(EndpointPackDefinitionSpec {
            detector_id: "possible_unusual_process_category_population_change",
            detector_family: EndpointDetectorFamily::ProcessCategoryAnomaly,
            required_fact_categories: &["process_category", "population_change"],
            required_independent_evidence_categories: &[
                EndpointDetectorEvidenceCategory::PortableFinding,
                EndpointDetectorEvidenceCategory::BaselineDeviation,
            ],
            optional_supporting_categories: &[
                EndpointDetectorEvidenceCategory::HighQualityFinding,
                EndpointDetectorEvidenceCategory::EvidenceBackedHypothesis,
            ],
            confidence_formula: EndpointConfidenceFormula::FindingBaselineWeighted,
            safe_wording: "possible unusual endpoint category activity",
            report_template: "endpoint_population_change_correlation",
        })?,
        pack_definition(EndpointPackDefinitionSpec {
            detector_id: "possible_suspicious_parent_category_transition",
            detector_family: EndpointDetectorFamily::ProcessCategoryAnomaly,
            required_fact_categories: &["parent_category_transition"],
            required_independent_evidence_categories: &[
                EndpointDetectorEvidenceCategory::PortableFinding,
                EndpointDetectorEvidenceCategory::BaselineDeviation,
            ],
            optional_supporting_categories: &[
                EndpointDetectorEvidenceCategory::ParentRelationFact,
                EndpointDetectorEvidenceCategory::HighQualityFinding,
            ],
            confidence_formula: EndpointConfidenceFormula::IndependentEvidenceWeighted,
            safe_wording: "possible unusual endpoint category activity",
            report_template: "endpoint_parent_category_transition",
        })?,
        pack_definition(EndpointPackDefinitionSpec {
            detector_id: "possible_remote_admin_endpoint_activity_with_auth_pressure",
            detector_family: EndpointDetectorFamily::PortableFindingCorrelation,
            required_fact_categories: &["remote_admin_endpoint_activity", "auth_pressure"],
            required_independent_evidence_categories: &[
                EndpointDetectorEvidenceCategory::HighQualityFinding,
                EndpointDetectorEvidenceCategory::RiskReference,
            ],
            optional_supporting_categories: &[
                EndpointDetectorEvidenceCategory::PortableFinding,
                EndpointDetectorEvidenceCategory::BaselineDeviation,
            ],
            confidence_formula: EndpointConfidenceFormula::IndependentEvidenceWeighted,
            safe_wording: "possible remote-admin endpoint activity with authentication pressure",
            report_template: "endpoint_remote_admin_auth_pressure",
        })?,
        pack_definition(EndpointPackDefinitionSpec {
            detector_id: "possible_script_capable_activity_with_independent_security_evidence",
            detector_family: EndpointDetectorFamily::ProcessCategoryAnomaly,
            required_fact_categories: &["script_capable_activity"],
            required_independent_evidence_categories: &[
                EndpointDetectorEvidenceCategory::HighQualityFinding,
                EndpointDetectorEvidenceCategory::BaselineDeviation,
            ],
            optional_supporting_categories: &[
                EndpointDetectorEvidenceCategory::EvidenceBackedHypothesis,
                EndpointDetectorEvidenceCategory::PortableFinding,
            ],
            confidence_formula: EndpointConfidenceFormula::FindingBaselineWeighted,
            safe_wording: "possible endpoint context supporting an existing security finding",
            report_template: "endpoint_script_capable_independent_evidence",
        })?,
        pack_definition(EndpointPackDefinitionSpec {
            detector_id: "possible_service_state_change_with_security_context",
            detector_family: EndpointDetectorFamily::ServiceCategoryAnomaly,
            required_fact_categories: &["service_state_change"],
            required_independent_evidence_categories: &[
                EndpointDetectorEvidenceCategory::PortableFinding,
                EndpointDetectorEvidenceCategory::BaselineDeviation,
            ],
            optional_supporting_categories: &[
                EndpointDetectorEvidenceCategory::ServiceCategoryFact,
                EndpointDetectorEvidenceCategory::HighQualityFinding,
            ],
            confidence_formula: EndpointConfidenceFormula::FindingBaselineWeighted,
            safe_wording: "possible service change with independent security evidence",
            report_template: "endpoint_service_state_security_context",
        })?,
        pack_definition(EndpointPackDefinitionSpec {
            detector_id: "possible_endpoint_context_for_saas_cloud_abuse",
            detector_family: EndpointDetectorFamily::PortableFindingCorrelation,
            required_fact_categories: &["saas_cloud_endpoint_context"],
            required_independent_evidence_categories: &[
                EndpointDetectorEvidenceCategory::PortableFinding,
                EndpointDetectorEvidenceCategory::RiskReference,
            ],
            optional_supporting_categories: &[
                EndpointDetectorEvidenceCategory::BaselineDeviation,
                EndpointDetectorEvidenceCategory::EvidenceBackedHypothesis,
            ],
            confidence_formula: EndpointConfidenceFormula::IndependentEvidenceWeighted,
            safe_wording: "possible endpoint context supporting an existing security finding",
            report_template: "endpoint_context_saas_cloud_abuse",
        })?,
        pack_definition(EndpointPackDefinitionSpec {
            detector_id: "possible_deception_correlated_endpoint_probe",
            detector_family: EndpointDetectorFamily::PortableFindingCorrelation,
            required_fact_categories: &["deception_endpoint_probe"],
            required_independent_evidence_categories: &[
                EndpointDetectorEvidenceCategory::PortableFinding,
                EndpointDetectorEvidenceCategory::EvidenceBackedHypothesis,
            ],
            optional_supporting_categories: &[
                EndpointDetectorEvidenceCategory::NativeHealthFact,
                EndpointDetectorEvidenceCategory::BaselineDeviation,
            ],
            confidence_formula: EndpointConfidenceFormula::HypothesisNativeFactWeighted,
            safe_wording: "possible endpoint context supporting an existing security finding",
            report_template: "endpoint_deception_correlated_probe",
        })?,
        pack_definition(EndpointPackDefinitionSpec {
            detector_id: "endpoint_visibility_degradation_advisory",
            detector_family: EndpointDetectorFamily::VisibilityDegradationAdvisory,
            required_fact_categories: &[],
            required_independent_evidence_categories: &[
                EndpointDetectorEvidenceCategory::PortableFinding,
            ],
            optional_supporting_categories: &[],
            confidence_formula: EndpointConfidenceFormula::IndependentEvidenceWeighted,
            safe_wording: "endpoint visibility degradation advisory",
            report_template: "endpoint_visibility_degradation_advisory",
        })?,
    ];
    Ok(definitions)
}

struct EndpointPackDefinitionSpec<'a> {
    detector_id: &'a str,
    detector_family: EndpointDetectorFamily,
    required_fact_categories: &'a [&'a str],
    required_independent_evidence_categories: &'a [EndpointDetectorEvidenceCategory],
    optional_supporting_categories: &'a [EndpointDetectorEvidenceCategory],
    confidence_formula: EndpointConfidenceFormula,
    safe_wording: &'a str,
    report_template: &'a str,
}

fn pack_definition(
    spec: EndpointPackDefinitionSpec<'_>,
) -> Result<EndpointThreatDetectorDefinition, EndpointThreatDetectionError> {
    let definition = EndpointThreatDetectorDefinition {
        detector_id: spec.detector_id.to_string(),
        detector_version: "1.0.0".to_string(),
        detector_family: spec.detector_family,
        required_fact_categories: spec
            .required_fact_categories
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        required_independent_evidence_categories: spec
            .required_independent_evidence_categories
            .to_vec(),
        optional_supporting_categories: spec.optional_supporting_categories.to_vec(),
        disqualifiers: vec![
            "benign_baseline".to_string(),
            "approved_admin_activity".to_string(),
            "approved_service_change".to_string(),
            "maintenance_window".to_string(),
        ],
        minimum_evidence_count: 2,
        minimum_independent_source_count: 2,
        correlation_window: EndpointCorrelationWindowBucket::CurrentSession,
        baseline_requirements: vec![EndpointBaselineRequirement::FreshDeviation],
        confidence_formula: spec.confidence_formula,
        confidence_cap: EndpointThreatConfidenceBucket::Moderate,
        quality_requirements: EndpointQualityRequirements {
            minimum_evidence_quality: EndpointEvidenceQualityBucket::Low,
            minimum_source_reliability: EndpointSourceReliabilityBucket::Weak,
            minimum_correlation_quality: EndpointCorrelationQualityBucket::SingleSignal,
            require_redacted: true,
        },
        freshness_requirements: EndpointFreshnessRequirements::default(),
        degradation_rules: vec![
            "category_only_context_caps_confidence".to_string(),
            "independent_evidence_required".to_string(),
            "metadata_only_visibility".to_string(),
        ],
        missing_visibility_flags: vec![
            EndpointMissingVisibilityFlag::ProcessNetworkAttributionUnavailable,
            EndpointMissingVisibilityFlag::CommandLineVisibilityUnavailable,
            EndpointMissingVisibilityFlag::FileRegistryVisibilityUnavailable,
            EndpointMissingVisibilityFlag::PacketVisibilityUnavailable,
            EndpointMissingVisibilityFlag::SpecificProcessIdentityUnavailable,
        ],
        attack_candidates: vec![EndpointAttackRef {
            tactic_id: "TA0007".to_string(),
            technique_id: "T1082".to_string(),
            attack_version: "enterprise_2026_metadata_only".to_string(),
            confidence_bucket: EndpointThreatConfidenceBucket::Low,
            required_visibility: vec![
                EndpointMissingVisibilityFlag::CommandLineVisibilityUnavailable,
            ],
        }],
        safe_wording: spec.safe_wording.to_string(),
        report_template: spec.report_template.to_string(),
        safety_notes: vec![
            "correlation_only".to_string(),
            "category_refs_only".to_string(),
            "no_process_causality_claim".to_string(),
            "no_response_action".to_string(),
        ],
    };
    definition.validate()?;
    Ok(definition)
}

fn validate_independent_evidence(
    definition: &EndpointThreatDetectorDefinition,
    input: &EndpointThreatDetectionInput,
) -> Result<EndpointEvidenceValidationReport, EndpointThreatDetectionError> {
    let countable = input
        .evidence
        .iter()
        .filter(|record| is_countable_independent_source(definition, record, input))
        .collect::<Vec<_>>();
    let unique_sources = unique_independent_sources(&countable);
    let unique_layers = countable
        .iter()
        .map(|record| format!("{:?}", record.layer))
        .collect::<BTreeSet<_>>();
    let broad_category_only = !countable.is_empty()
        && countable
            .iter()
            .all(|record| record.category.is_broad_category_context());

    let pattern = if !broad_category_only
        && unique_sources.len() >= definition.minimum_independent_source_count as usize
        && unique_layers.len() >= 2
        && countable.len() >= definition.minimum_evidence_count as usize
    {
        Some(EndpointIndependentEvidencePattern::TwoIndependentLayers)
    } else if has_high_quality_finding_and_fresh_baseline(&countable) {
        Some(EndpointIndependentEvidencePattern::HighQualityFindingWithFreshBaseline)
    } else if has_evidence_backed_hypothesis_and_fresh_native_facts(&countable, &input.facts) {
        Some(EndpointIndependentEvidencePattern::EvidenceBackedHypothesisWithFreshNativeFacts)
    } else {
        None
    };

    let independent_evidence_refs = countable
        .iter()
        .map(|record| record.evidence_ref.clone())
        .take(MAX_ENDPOINT_DETECTOR_REFS)
        .collect::<Vec<_>>();

    let rejected_reason = if pattern.is_some() {
        None
    } else if broad_category_only {
        Some(EndpointRejectedCandidateReason::UnsafeField)
    } else {
        Some(EndpointRejectedCandidateReason::MissingEvidence)
    };

    Ok(EndpointEvidenceValidationReport {
        pattern,
        independent_source_count: unique_sources.len().min(u8::MAX as usize) as u8,
        independent_layer_count: unique_layers.len().min(u8::MAX as usize) as u8,
        independent_evidence_refs,
        rejected_reason,
        broad_category_only,
    })
}

fn is_countable_independent_source(
    definition: &EndpointThreatDetectorDefinition,
    record: &EndpointDetectorEvidenceRecord,
    input: &EndpointThreatDetectionInput,
) -> bool {
    if record.category.is_independence_excluded() {
        return false;
    }
    if record
        .generated_from_candidate_ref
        .as_ref()
        .is_some_and(|candidate_ref| input.candidate_ref.as_ref() == Some(candidate_ref))
    {
        return false;
    }
    if !definition
        .freshness_requirements
        .accepted
        .contains(&record.freshness_category)
    {
        return false;
    }
    if definition.quality_requirements.require_redacted
        && !is_safe_redaction_status(&record.redaction_status)
    {
        return false;
    }
    if !meets_quality_floor(
        &record.quality_bucket,
        &definition.quality_requirements.minimum_evidence_quality,
    ) || !meets_reliability_floor(
        &record.reliability_bucket,
        &definition.quality_requirements.minimum_source_reliability,
    ) || !meets_correlation_floor(
        &record.correlation_quality_bucket,
        &definition.quality_requirements.minimum_correlation_quality,
    ) {
        return false;
    }
    definition
        .required_independent_evidence_categories
        .contains(&record.category)
        || definition
            .optional_supporting_categories
            .contains(&record.category)
}

fn unique_independent_sources(records: &[&EndpointDetectorEvidenceRecord]) -> BTreeSet<String> {
    let mut source_to_sample = BTreeMap::<String, String>::new();
    for record in records {
        let source = format!("{:?}|{}", record.layer, record.source_key);
        let sample = record
            .sample_group_ref
            .clone()
            .unwrap_or_else(|| record.evidence_ref.to_string());
        source_to_sample.entry(source).or_insert(sample);
    }

    let mut accepted = BTreeSet::new();
    let mut used_samples = BTreeSet::new();
    for (source, sample) in source_to_sample {
        if used_samples.insert(sample) {
            accepted.insert(source);
        }
    }
    accepted
}

fn has_high_quality_finding_and_fresh_baseline(
    records: &[&EndpointDetectorEvidenceRecord],
) -> bool {
    let has_finding = records.iter().any(|record| {
        matches!(
            record.category,
            EndpointDetectorEvidenceCategory::HighQualityFinding
                | EndpointDetectorEvidenceCategory::PortableFinding
        ) && record.finding_ref.is_some()
            && matches!(
                record.quality_bucket,
                EndpointEvidenceQualityBucket::Elevated | EndpointEvidenceQualityBucket::Moderate
            )
    });
    let has_fresh_baseline = records.iter().any(|record| {
        record.category == EndpointDetectorEvidenceCategory::BaselineDeviation
            && record.baseline_ref.is_some()
            && record.freshness_category == EndpointFreshnessCategory::Fresh
    });
    has_finding && has_fresh_baseline
}

fn has_evidence_backed_hypothesis_and_fresh_native_facts(
    records: &[&EndpointDetectorEvidenceRecord],
    facts: &[EndpointDetectorFactRecord],
) -> bool {
    let has_hypothesis = records.iter().any(|record| {
        record.category == EndpointDetectorEvidenceCategory::EvidenceBackedHypothesis
            && record.hypothesis_ref.is_some()
            && !record.parent_evidence_refs.is_empty()
    });
    let fresh_native_facts = facts
        .iter()
        .filter(|fact| fact.is_fresh_native_category_fact())
        .map(|fact| {
            fact.sample_group_ref
                .clone()
                .unwrap_or_else(|| fact.fact_ref.to_string())
        })
        .collect::<BTreeSet<_>>();
    has_hypothesis && !fresh_native_facts.is_empty()
}

fn calculate_confidence(
    definition: &EndpointThreatDetectorDefinition,
    input: &EndpointThreatDetectionInput,
    evidence_validation: &EndpointEvidenceValidationReport,
) -> EndpointConfidenceReport {
    let evidence_count = evidence_validation.independent_evidence_refs.len() as f32;
    let layer_count = evidence_validation.independent_layer_count as f32;
    let baseline_bonus = if input
        .evidence
        .iter()
        .any(|record| record.category == EndpointDetectorEvidenceCategory::BaselineDeviation)
    {
        0.1
    } else {
        0.0
    };
    let quality_score = average_quality_score(&input.evidence);
    let reliability_score = average_reliability_score(&input.evidence);
    let freshness_score = average_freshness_score(&input.evidence);
    let correlation_score = average_correlation_score(&input.evidence);
    let redaction_score = if input
        .evidence
        .iter()
        .all(|record| is_safe_redaction_status(&record.redaction_status))
    {
        0.08
    } else {
        -0.2
    };
    let missing_visibility_penalty =
        (definition.missing_visibility_flags.len() as f32 * 0.025).min(0.15);
    let disqualified_penalty = if evidence_validation.rejected_reason.is_some() {
        0.25
    } else {
        0.0
    };
    let raw_score = (0.16 * evidence_count.min(4.0))
        + (0.08 * layer_count.min(4.0))
        + baseline_bonus
        + (0.14 * quality_score)
        + (0.12 * reliability_score)
        + (0.1 * freshness_score)
        + (0.1 * correlation_score)
        + redaction_score
        - missing_visibility_penalty
        - disqualified_penalty;
    let mut bucket = score_to_confidence_bucket(raw_score.clamp(0.0, 1.0));
    let mut capped_by = Vec::new();

    bucket = cap_confidence(
        bucket,
        definition.confidence_cap.clone(),
        "detector_confidence_cap",
        &mut capped_by,
    );
    if evidence_validation.broad_category_only {
        bucket = cap_confidence(
            bucket,
            EndpointThreatConfidenceBucket::Low,
            "category_only_context",
            &mut capped_by,
        );
    }
    for flag in input
        .analysis_input
        .missing_visibility_flags
        .iter()
        .chain(definition.missing_visibility_flags.iter())
    {
        let cap = match flag {
            EndpointMissingVisibilityFlag::ProcessNetworkAttributionUnavailable
            | EndpointMissingVisibilityFlag::CommandLineVisibilityUnavailable
            | EndpointMissingVisibilityFlag::FileRegistryVisibilityUnavailable
            | EndpointMissingVisibilityFlag::PacketVisibilityUnavailable => {
                Some(EndpointThreatConfidenceBucket::Moderate)
            }
            EndpointMissingVisibilityFlag::SpecificProcessIdentityUnavailable => {
                Some(EndpointThreatConfidenceBucket::Low)
            }
        };
        if let Some(cap) = cap {
            bucket = cap_confidence(
                bucket,
                cap,
                &format!("{flag:?}").to_ascii_lowercase(),
                &mut capped_by,
            );
        }
    }
    if evidence_validation.rejected_reason.is_some() {
        bucket = cap_confidence(
            bucket,
            EndpointThreatConfidenceBucket::Informational,
            "rejected_candidate",
            &mut capped_by,
        );
    }
    let severity_bucket = match bucket {
        EndpointThreatConfidenceBucket::Informational => {
            EndpointThreatSeverityBucket::Informational
        }
        EndpointThreatConfidenceBucket::Low => EndpointThreatSeverityBucket::Low,
        EndpointThreatConfidenceBucket::Moderate => EndpointThreatSeverityBucket::Moderate,
        EndpointThreatConfidenceBucket::Elevated => EndpointThreatSeverityBucket::Elevated,
    };
    EndpointConfidenceReport {
        confidence_bucket: bucket,
        severity_bucket,
        capped_by: bounded_unique_strings(capped_by),
        score_bucket: score_to_count_bucket(raw_score),
    }
}

fn build_candidate(
    definition: &EndpointThreatDetectorDefinition,
    input: &EndpointThreatDetectionInput,
    evidence_validation: &EndpointEvidenceValidationReport,
    confidence: &EndpointConfidenceReport,
) -> Result<EndpointThreatCandidate, EndpointThreatDetectionError> {
    let mut candidate = EndpointThreatCandidate {
        candidate_id: EndpointThreatCandidateId::new_v4(),
        analysis_input_ref: input.analysis_input.analysis_input_id.clone(),
        category: category_for_family(&definition.detector_family),
        process_fact_refs: input.analysis_input.process_fact_refs.clone(),
        service_fact_refs: input.analysis_input.service_fact_refs.clone(),
        evidence_refs: evidence_validation.independent_evidence_refs.clone(),
        baseline_refs: input.analysis_input.baseline_refs.clone(),
        hypothesis_refs: input.analysis_input.hypothesis_refs.clone(),
        risk_refs: input.analysis_input.risk_refs.clone(),
        attack_refs: definition.attack_candidates.clone(),
        confidence_bucket: confidence.confidence_bucket.clone(),
        severity_bucket: confidence.severity_bucket.clone(),
        causal_claim: EndpointThreatCausalClaim::CorrelationOnly,
        summary_redacted: definition.safe_wording.clone(),
        missing_visibility_flags: bounded_visibility_flags(
            input
                .analysis_input
                .missing_visibility_flags
                .iter()
                .cloned()
                .chain(definition.missing_visibility_flags.iter().cloned())
                .collect(),
        ),
        freshness_category: input.analysis_input.freshness_category.clone(),
        source_reliability_bucket: input.analysis_input.source_reliability_bucket.clone(),
        evidence_quality_bucket: input.analysis_input.evidence_quality_bucket.clone(),
        correlation_quality_bucket: input.analysis_input.correlation_quality_bucket.clone(),
        provenance_id: input.analysis_input.provenance_id.clone(),
        redaction_status: RedactionStatus::Redacted,
    };
    candidate.evidence_refs.truncate(MAX_ENDPOINT_DETECTOR_REFS);
    candidate
        .validate()
        .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
    Ok(candidate)
}

fn build_rejected_candidate(
    definition: &EndpointThreatDetectorDefinition,
    input: &EndpointThreatDetectionInput,
    evidence_validation: &EndpointEvidenceValidationReport,
) -> Result<EndpointRejectedCandidate, EndpointThreatDetectionError> {
    let rejected = EndpointRejectedCandidate {
        rejected_candidate_id: EndpointRejectedCandidateId::new_v4(),
        analysis_input_ref: input.analysis_input.analysis_input_id.clone(),
        category: category_for_family(&definition.detector_family),
        reason: evidence_validation
            .rejected_reason
            .clone()
            .unwrap_or(EndpointRejectedCandidateReason::MissingEvidence),
        evidence_refs: evidence_validation.independent_evidence_refs.clone(),
        summary_redacted: "endpoint_threat_candidate_rejected".to_string(),
        missing_visibility_flags: bounded_visibility_flags(
            input
                .analysis_input
                .missing_visibility_flags
                .iter()
                .cloned()
                .chain(definition.missing_visibility_flags.iter().cloned())
                .collect(),
        ),
        provenance_id: input.analysis_input.provenance_id.clone(),
        redaction_status: RedactionStatus::Redacted,
    };
    rejected
        .validate()
        .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
    Ok(rejected)
}

fn required_fact_categories_match(
    definition: &EndpointThreatDetectorDefinition,
    input: &EndpointThreatDetectionInput,
) -> bool {
    definition.required_fact_categories.iter().all(|required| {
        input
            .facts
            .iter()
            .any(|fact| fact.category.contains(required))
    })
}

fn build_endpoint_threat_finding(
    definition: &EndpointThreatDetectorDefinition,
    candidate: &EndpointThreatCandidate,
) -> Result<EndpointThreatFinding, EndpointThreatDetectionError> {
    let finding = EndpointThreatFinding {
        finding_id: EndpointThreatFindingId::new_v4(),
        candidate_ref: candidate.candidate_id.clone(),
        analysis_input_ref: candidate.analysis_input_ref.clone(),
        category: finding_category_for_detector(definition),
        evidence_refs: candidate.evidence_refs.clone(),
        endpoint_evidence_refs: Vec::new(),
        risk_hint_refs: Vec::new(),
        attack_refs: candidate.attack_refs.clone(),
        confidence_bucket: candidate.confidence_bucket.clone(),
        severity_bucket: candidate.severity_bucket.clone(),
        causal_claim: EndpointThreatCausalClaim::CorrelationOnly,
        summary_redacted: definition.safe_wording.clone(),
        missing_visibility_flags: candidate.missing_visibility_flags.clone(),
        evidence_quality_bucket: candidate.evidence_quality_bucket.clone(),
        correlation_quality_bucket: candidate.correlation_quality_bucket.clone(),
        provenance_id: candidate.provenance_id.clone(),
        redaction_status: RedactionStatus::Redacted,
    };
    finding
        .validate()
        .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
    Ok(finding)
}

fn build_visibility_advisory(
    definition: &EndpointThreatDetectorDefinition,
    input: &EndpointThreatDetectionInput,
) -> Result<Option<EndpointVisibilityAdvisory>, EndpointThreatDetectionError> {
    if input.analysis_input.missing_visibility_flags.is_empty()
        || input.analysis_input.evidence_refs.is_empty()
    {
        return Ok(None);
    }
    let advisory = EndpointVisibilityAdvisory {
        advisory_id: EndpointVisibilityAdvisoryId::new_v4(),
        analysis_input_ref: Some(input.analysis_input.analysis_input_id.clone()),
        category: visibility_advisory_category(&input.analysis_input.missing_visibility_flags),
        missing_visibility_flags: bounded_visibility_flags(
            input
                .analysis_input
                .missing_visibility_flags
                .iter()
                .cloned()
                .chain(definition.missing_visibility_flags.iter().cloned())
                .collect(),
        ),
        confidence_cap: EndpointThreatConfidenceBucket::Low,
        summary_redacted: definition.safe_wording.clone(),
        evidence_refs: input.analysis_input.evidence_refs.clone(),
        provenance_id: input.analysis_input.provenance_id.clone(),
        redaction_status: RedactionStatus::Redacted,
    };
    advisory
        .validate()
        .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
    Ok(Some(advisory))
}

fn build_endpoint_risk_hint(
    finding: &EndpointThreatFinding,
) -> Result<RiskHint, EndpointThreatDetectionError> {
    let source_record = IntelligenceRecordId::from_uuid(finding.finding_id.as_uuid());
    let mut hint = RiskHint::new(
        risk_hint_type_for_finding(finding),
        "bounded_endpoint_context_from_validated_finding",
        vec![source_record],
    )
    .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?
    .with_risk_delta(risk_delta_for_severity(&finding.severity_bucket))
    .with_confidence(quality_from_endpoint_confidence(
        &finding.confidence_bucket,
    )?);
    hint.entity_ref = Some(entity_ref_from_uuid(
        EntityId::from_uuid(finding.finding_id.as_uuid()),
        EntityType::Finding,
        "endpoint_threat_finding",
    )?);
    hint.privacy_class = PrivacyClass::Internal;
    hint.validate_boundary()
        .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
    Ok(hint)
}

fn build_attack_context_attachments(
    finding: &EndpointThreatFinding,
) -> Result<Vec<EndpointAttackContextAttachment>, EndpointThreatDetectionError> {
    let mut attachments = Vec::new();
    for attack_ref in finding.attack_refs.iter().take(MAX_ENDPOINT_DETECTOR_REFS) {
        attack_ref
            .validate()
            .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
        let attachment = EndpointAttackContextAttachment {
            finding_ref: finding.finding_id.clone(),
            attack_ref: attack_ref.clone(),
            evidence_refs: finding.evidence_refs.clone(),
            technique_observed: false,
            confidence_cap: endpoint_attack_context_confidence_cap(&finding.confidence_bucket),
            unsupported_visibility: vec![
                "process_network_techniques_unsupported".to_string(),
                "command_visibility_techniques_unsupported".to_string(),
                "file_registry_techniques_unsupported".to_string(),
            ],
            safe_wording: "endpoint_context_attached_without_observed_technique".to_string(),
        };
        attachment.validate()?;
        attachments.push(attachment);
    }
    Ok(attachments)
}

fn build_endpoint_graph_hints(
    finding: &EndpointThreatFinding,
    input: &EndpointThreatIntelligenceInput,
    risk_entity_id: Option<EntityId>,
) -> Result<Vec<GraphHint>, EndpointThreatDetectionError> {
    let mut hints = Vec::new();
    let source = entity_ref_from_uuid(
        EntityId::from_uuid(finding.finding_id.as_uuid()),
        EntityType::Finding,
        "endpoint_threat_finding",
    )?;

    for fact in input.facts.iter().take(MAX_ENDPOINT_DETECTOR_REFS) {
        let (edge_type, target_name) = match fact.layer {
            EndpointDetectorEvidenceLayer::ProcessCategory => (
                "endpoint_finding_to_process_category_fact",
                "process_category_fact",
            ),
            EndpointDetectorEvidenceLayer::ParentRelation => (
                "endpoint_finding_to_parent_relation_fact",
                "parent_relation_fact",
            ),
            EndpointDetectorEvidenceLayer::ServiceCategory => (
                "endpoint_finding_to_service_category_fact",
                "service_category_fact",
            ),
            _ => continue,
        };
        hints.push(graph_hint(
            edge_type,
            source.clone(),
            entity_ref_from_uuid(
                EntityId::from_uuid(fact.fact_ref.as_uuid()),
                EntityType::Other,
                target_name,
            )?,
            finding.evidence_refs.clone(),
            &finding.confidence_bucket,
        )?);
    }

    for evidence_ref in finding
        .evidence_refs
        .iter()
        .take(MAX_ENDPOINT_DETECTOR_REFS)
    {
        hints.push(graph_hint(
            "endpoint_finding_to_evidence",
            source.clone(),
            entity_ref_from_uuid(
                EntityId::from_uuid(evidence_ref.as_uuid()),
                EntityType::Other,
                "endpoint_evidence_ref",
            )?,
            vec![evidence_ref.clone()],
            &finding.confidence_bucket,
        )?);
    }

    for hypothesis_ref in accepted_hypothesis_refs(input).into_iter() {
        hints.push(graph_hint(
            "endpoint_finding_to_hypothesis",
            source.clone(),
            entity_ref_from_uuid(
                EntityId::from_uuid(hypothesis_ref.as_uuid()),
                EntityType::Other,
                "endpoint_hypothesis_ref",
            )?,
            finding.evidence_refs.clone(),
            &finding.confidence_bucket,
        )?);
    }

    if let Some(risk_entity_id) = risk_entity_id {
        hints.push(graph_hint(
            "endpoint_finding_to_risk",
            source.clone(),
            entity_ref_from_uuid(risk_entity_id, EntityType::Other, "endpoint_risk_ref")?,
            finding.evidence_refs.clone(),
            &finding.confidence_bucket,
        )?);
    }

    for attack_ref in finding.attack_refs.iter().take(MAX_ENDPOINT_DETECTOR_REFS) {
        attack_ref
            .validate()
            .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
        hints.push(graph_hint(
            "endpoint_finding_to_attack_candidate",
            source.clone(),
            entity_ref_from_uuid(
                EntityId::new_v4(),
                EntityType::Other,
                "attack_candidate_ref",
            )?,
            finding.evidence_refs.clone(),
            &finding.confidence_bucket,
        )?);
    }

    Ok(hints)
}

struct EndpointHypothesisDefinitionSpec<'a> {
    category: &'a str,
    required_facts: Vec<HypothesisFactRequirement>,
    optional_facts: Vec<HypothesisFactRequirement>,
    context_labels: Vec<&'a str>,
    report_template: &'a str,
    required_visibility: &'a str,
    tactic_id: &'a str,
    technique_id: &'a str,
}

fn endpoint_hypothesis_definition(
    spec: EndpointHypothesisDefinitionSpec<'_>,
) -> Result<AttackHypothesisDefinition, EndpointThreatDetectionError> {
    let mut disqualifiers = vec![
        "category_only_context".to_string(),
        "advisory_only".to_string(),
        "unsafe_schema".to_string(),
        "stale_native_context".to_string(),
        "benign_baseline".to_string(),
    ];
    disqualifiers.extend(spec.context_labels.into_iter().map(str::to_string));

    let definition = AttackHypothesisDefinition {
        hypothesis_id: format!("endpoint_threat_lite.{}", spec.category),
        version: "1.0.0".to_string(),
        category: spec.category.to_string(),
        required_facts: spec.required_facts,
        optional_facts: spec.optional_facts,
        disqualifier_categories: bounded_unique_strings(disqualifiers),
        minimum_evidence: 2,
        confidence_cap: FusionConfidenceBucket::Low,
        confidence_formula: "independent_evidence_with_endpoint_context_cap".to_string(),
        degradation_rules: vec![
            "cap_low_when_category_only".to_string(),
            "degrade_without_fresh_native_context".to_string(),
            "do_not_mark_observed_from_category_context".to_string(),
        ],
        missing_visibility_flags: vec![
            "process_network_context_unavailable".to_string(),
            "command_visibility_context_unavailable".to_string(),
            "file_registry_context_unavailable".to_string(),
        ],
        attack_candidates: vec![FusionAttackCandidate {
            tactic_id: spec.tactic_id.to_string(),
            technique_id: spec.technique_id.to_string(),
            attack_version: "v14".to_string(),
            confidence: FusionConfidenceBucket::Low,
            required_visibility: spec.required_visibility.to_string(),
        }],
        report_template: spec.report_template.to_string(),
        safety_notes: vec![
            "metadata_only".to_string(),
            "no_process_causality".to_string(),
            "no_auto_incident".to_string(),
            "no_response_execution".to_string(),
            "no_observed_technique_from_category".to_string(),
        ],
    };
    definition
        .validate()
        .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
    Ok(definition)
}

fn requirement(layer: SecurityLayer, categories: &[&str]) -> HypothesisFactRequirement {
    HypothesisFactRequirement {
        layer,
        categories: categories
            .iter()
            .map(|category| category.to_string())
            .collect(),
    }
}

fn risk_hint_type_for_finding(finding: &EndpointThreatFinding) -> &'static str {
    match finding.category {
        EndpointThreatFindingCategory::EvidenceBackedPrivilegeAnomaly => {
            "endpoint_auth_context_risk_hint"
        }
        EndpointThreatFindingCategory::EvidenceBackedServiceAnomaly => {
            "endpoint_service_category_risk_hint"
        }
        EndpointThreatFindingCategory::EvidenceBackedTrustAnomaly => {
            "endpoint_saas_cloud_context_risk_hint"
        }
        EndpointThreatFindingCategory::DegradedVisibilityEndpointSuspicion => {
            "endpoint_deception_context_risk_hint"
        }
        EndpointThreatFindingCategory::EvidenceBackedEndpointAnomaly
        | EndpointThreatFindingCategory::EvidenceBackedLifecycleAnomaly => {
            "endpoint_process_category_risk_hint"
        }
    }
}

fn risk_delta_for_severity(severity: &EndpointThreatSeverityBucket) -> f32 {
    match severity {
        EndpointThreatSeverityBucket::Informational => 0.5,
        EndpointThreatSeverityBucket::Low => 1.5,
        EndpointThreatSeverityBucket::Moderate => 3.0,
        EndpointThreatSeverityBucket::Elevated => 4.5,
    }
}

fn quality_from_endpoint_confidence(
    confidence: &EndpointThreatConfidenceBucket,
) -> Result<QualityScore, EndpointThreatDetectionError> {
    let value = match confidence {
        EndpointThreatConfidenceBucket::Informational => 0.2,
        EndpointThreatConfidenceBucket::Low => 0.35,
        EndpointThreatConfidenceBucket::Moderate => 0.55,
        EndpointThreatConfidenceBucket::Elevated => 0.7,
    };
    QualityScore::new(value)
        .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))
}

fn endpoint_attack_context_confidence_cap(
    confidence: &EndpointThreatConfidenceBucket,
) -> EndpointThreatConfidenceBucket {
    match confidence {
        EndpointThreatConfidenceBucket::Elevated => EndpointThreatConfidenceBucket::Moderate,
        value => value.clone(),
    }
}

fn accepted_hypothesis_refs(input: &EndpointThreatIntelligenceInput) -> Vec<AttackHypothesisId> {
    let mut seen = BTreeSet::new();
    let mut refs = Vec::new();
    for hypothesis_ref in input
        .evaluations
        .iter()
        .filter(|evaluation| evaluation.accepted)
        .filter_map(|evaluation| evaluation.candidate.as_ref())
        .flat_map(|candidate| candidate.hypothesis_refs.iter())
    {
        if seen.insert(hypothesis_ref.to_string()) {
            refs.push(hypothesis_ref.clone());
        }
        if refs.len() >= MAX_ENDPOINT_DETECTOR_REFS {
            break;
        }
    }
    refs
}

fn entity_ref_from_uuid(
    entity_id: EntityId,
    entity_type: EntityType,
    entity_name: &str,
) -> Result<EntityRef, EndpointThreatDetectionError> {
    safe_text("endpoint_graph.entity_name", entity_name)?;
    let confidence = QualityScore::new(0.5)
        .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
    let mut entity = EntityRef::new(entity_id, entity_type);
    entity.entity_name = Some(entity_name.to_string());
    entity.namespace = Some("endpoint_threat_lite".to_string());
    entity.source = Some("validated_endpoint_finding".to_string());
    entity.confidence = confidence;
    Ok(entity)
}

fn graph_hint(
    edge_type: &str,
    source_entity: EntityRef,
    target_entity: EntityRef,
    evidence_refs: Vec<EvidenceId>,
    confidence: &EndpointThreatConfidenceBucket,
) -> Result<GraphHint, EndpointThreatDetectionError> {
    safe_text("endpoint_graph.edge_type", edge_type)?;
    let mut hint = GraphHint::new(
        GraphHintType::Custom(edge_type.to_string()),
        source_entity,
        target_entity,
        PluginId::new_v4(),
    );
    hint.evidence_refs = evidence_refs
        .into_iter()
        .take(MAX_ENDPOINT_DETECTOR_REFS)
        .collect();
    hint.confidence = quality_from_endpoint_confidence(confidence)?;
    hint.privacy_class = PrivacyClass::Internal;
    validate_graph_hint_boundary(&hint)?;
    Ok(hint)
}

fn validate_graph_hint_boundary(hint: &GraphHint) -> Result<(), EndpointThreatDetectionError> {
    if hint.evidence_refs.is_empty() {
        return Err(EndpointThreatDetectionError::InvalidInput(
            "endpoint graph hints require evidence refs",
        ));
    }
    if hint.source_entity.entity_type != EntityType::Finding {
        return Err(EndpointThreatDetectionError::InvalidInput(
            "endpoint graph hints must start from findings",
        ));
    }
    if matches!(
        hint.target_entity.entity_type,
        EntityType::Ip
            | EntityType::User
            | EntityType::Url
            | EntityType::CloudResource
            | EntityType::Certificate
            | EntityType::Process
    ) {
        return Err(EndpointThreatDetectionError::InvalidInput(
            "endpoint graph hints must remain category-level",
        ));
    }
    let GraphHintType::Custom(edge_type) = &hint.hint_type else {
        return Err(EndpointThreatDetectionError::InvalidInput(
            "endpoint graph hints require allowlisted custom edges",
        ));
    };
    safe_text("endpoint_graph.edge_type", edge_type)?;
    if !ALLOWED_ENDPOINT_GRAPH_EDGES.contains(&edge_type.as_str()) {
        return Err(EndpointThreatDetectionError::InvalidInput(
            "endpoint graph edge is not allowlisted",
        ));
    }
    for entity in [&hint.source_entity, &hint.target_entity] {
        for value in [
            entity.entity_name.as_ref(),
            entity.namespace.as_ref(),
            entity.source.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            safe_text("endpoint_graph.entity_ref", value)?;
        }
    }
    Ok(())
}

const ALLOWED_ENDPOINT_GRAPH_EDGES: &[&str] = &[
    "endpoint_finding_to_process_category_fact",
    "endpoint_finding_to_parent_relation_fact",
    "endpoint_finding_to_service_category_fact",
    "endpoint_finding_to_evidence",
    "endpoint_finding_to_hypothesis",
    "endpoint_finding_to_risk",
    "endpoint_finding_to_attack_candidate",
];

fn finding_category_for_detector(
    definition: &EndpointThreatDetectorDefinition,
) -> EndpointThreatFindingCategory {
    match definition.detector_id.as_str() {
        "possible_service_state_change_with_security_context" => {
            EndpointThreatFindingCategory::EvidenceBackedServiceAnomaly
        }
        "possible_suspicious_parent_category_transition" => {
            EndpointThreatFindingCategory::EvidenceBackedLifecycleAnomaly
        }
        "possible_remote_admin_endpoint_activity_with_auth_pressure" => {
            EndpointThreatFindingCategory::EvidenceBackedPrivilegeAnomaly
        }
        "possible_endpoint_context_for_saas_cloud_abuse" => {
            EndpointThreatFindingCategory::EvidenceBackedTrustAnomaly
        }
        "possible_deception_correlated_endpoint_probe" => {
            EndpointThreatFindingCategory::DegradedVisibilityEndpointSuspicion
        }
        _ => EndpointThreatFindingCategory::EvidenceBackedEndpointAnomaly,
    }
}

fn visibility_advisory_category(
    flags: &[EndpointMissingVisibilityFlag],
) -> EndpointVisibilityAdvisoryCategory {
    if flags.contains(&EndpointMissingVisibilityFlag::ProcessNetworkAttributionUnavailable) {
        EndpointVisibilityAdvisoryCategory::ProcessNetworkAttributionUnavailable
    } else if flags.contains(&EndpointMissingVisibilityFlag::CommandLineVisibilityUnavailable) {
        EndpointVisibilityAdvisoryCategory::CommandLineUnavailable
    } else if flags.contains(&EndpointMissingVisibilityFlag::FileRegistryVisibilityUnavailable) {
        EndpointVisibilityAdvisoryCategory::FileRegistryUnavailable
    } else if flags.contains(&EndpointMissingVisibilityFlag::PacketVisibilityUnavailable) {
        EndpointVisibilityAdvisoryCategory::PacketUnavailable
    } else if flags.contains(&EndpointMissingVisibilityFlag::SpecificProcessIdentityUnavailable) {
        EndpointVisibilityAdvisoryCategory::SpecificProcessIdentityUnavailable
    } else {
        EndpointVisibilityAdvisoryCategory::EvidenceQualityDegraded
    }
}

fn validate_evidence_graph(
    evidence: &[EndpointDetectorEvidenceRecord],
) -> Result<(), EndpointThreatDetectionError> {
    let mut seen = BTreeSet::new();
    let mut graph = BTreeMap::<String, Vec<String>>::new();
    for record in evidence {
        let evidence_ref = record.evidence_ref.to_string();
        if !seen.insert(evidence_ref.clone()) {
            return Err(EndpointThreatDetectionError::DuplicateEvidence);
        }
        if record.category == EndpointDetectorEvidenceCategory::GraphHint
            && !record.parent_evidence_refs.is_empty()
        {
            return Err(EndpointThreatDetectionError::GraphRecursion);
        }
        let parents = record
            .parent_evidence_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if parents.contains(&evidence_ref) {
            return Err(EndpointThreatDetectionError::EvidenceSelfReference);
        }
        graph.insert(evidence_ref, parents);
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for node in graph.keys() {
        detect_cycle(node, &graph, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn detect_cycle(
    node: &str,
    graph: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> Result<(), EndpointThreatDetectionError> {
    if visited.contains(node) {
        return Ok(());
    }
    if !visiting.insert(node.to_string()) {
        return Err(EndpointThreatDetectionError::CyclicEvidence);
    }
    if let Some(parents) = graph.get(node) {
        for parent in parents {
            if graph.contains_key(parent) {
                detect_cycle(parent, graph, visiting, visited)?;
            }
        }
    }
    visiting.remove(node);
    visited.insert(node.to_string());
    Ok(())
}

fn reject_disqualified(
    definition: &EndpointThreatDetectorDefinition,
    input: &EndpointThreatDetectionInput,
) -> Result<(), EndpointThreatDetectionError> {
    let categories = input
        .facts
        .iter()
        .map(|fact| fact.category.as_str())
        .chain(
            input
                .evidence
                .iter()
                .map(|evidence| evidence.source_key.as_str()),
        )
        .collect::<Vec<_>>();
    if definition.disqualifiers.iter().any(|disqualifier| {
        categories
            .iter()
            .any(|category| category.contains(disqualifier))
    }) {
        return Err(EndpointThreatDetectionError::InvalidInput(
            "disqualified benign context present",
        ));
    }
    Ok(())
}

fn category_for_family(family: &EndpointDetectorFamily) -> EndpointThreatCandidateCategory {
    match family {
        EndpointDetectorFamily::ServiceCategoryAnomaly => {
            EndpointThreatCandidateCategory::ProcessServiceCorrelation
        }
        EndpointDetectorFamily::NativeHealthCorrelation => {
            EndpointThreatCandidateCategory::NativeHealthCorrelation
        }
        EndpointDetectorFamily::TrustSignednessAnomaly => {
            EndpointThreatCandidateCategory::TrustSignednessCorrelation
        }
        EndpointDetectorFamily::PrivilegeContextAnomaly => {
            EndpointThreatCandidateCategory::PrivilegeContextCorrelation
        }
        EndpointDetectorFamily::LifecycleAnomaly => {
            EndpointThreatCandidateCategory::LifecyclePatternCorrelation
        }
        EndpointDetectorFamily::VisibilityDegradationAdvisory => {
            EndpointThreatCandidateCategory::VisibilityLimitedSuspicion
        }
        EndpointDetectorFamily::ProcessCategoryAnomaly
        | EndpointDetectorFamily::PortableFindingCorrelation => {
            EndpointThreatCandidateCategory::PortableFindingCorrelation
        }
    }
}

fn cap_confidence(
    current: EndpointThreatConfidenceBucket,
    cap: EndpointThreatConfidenceBucket,
    reason: &str,
    capped_by: &mut Vec<String>,
) -> EndpointThreatConfidenceBucket {
    if confidence_rank(&current) > confidence_rank(&cap) {
        capped_by.push(reason.to_string());
        cap
    } else {
        current
    }
}

fn confidence_rank(bucket: &EndpointThreatConfidenceBucket) -> u8 {
    match bucket {
        EndpointThreatConfidenceBucket::Informational => 0,
        EndpointThreatConfidenceBucket::Low => 1,
        EndpointThreatConfidenceBucket::Moderate => 2,
        EndpointThreatConfidenceBucket::Elevated => 3,
    }
}

fn score_to_confidence_bucket(score: f32) -> EndpointThreatConfidenceBucket {
    if score >= 0.68 {
        EndpointThreatConfidenceBucket::Elevated
    } else if score >= 0.48 {
        EndpointThreatConfidenceBucket::Moderate
    } else if score >= 0.26 {
        EndpointThreatConfidenceBucket::Low
    } else {
        EndpointThreatConfidenceBucket::Informational
    }
}

fn score_to_count_bucket(score: f32) -> EndpointCountChangeBucket {
    if score >= 0.75 {
        EndpointCountChangeBucket::High
    } else if score >= 0.5 {
        EndpointCountChangeBucket::Medium
    } else if score >= 0.25 {
        EndpointCountChangeBucket::Low
    } else {
        EndpointCountChangeBucket::Single
    }
}

fn average_quality_score(records: &[EndpointDetectorEvidenceRecord]) -> f32 {
    average(records.iter().map(|record| match record.quality_bucket {
        EndpointEvidenceQualityBucket::Unknown => 0.2,
        EndpointEvidenceQualityBucket::Low => 0.38,
        EndpointEvidenceQualityBucket::Moderate => 0.68,
        EndpointEvidenceQualityBucket::Elevated => 0.86,
        EndpointEvidenceQualityBucket::Blocked => 0.0,
    }))
}

fn average_reliability_score(records: &[EndpointDetectorEvidenceRecord]) -> f32 {
    average(
        records
            .iter()
            .map(|record| match record.reliability_bucket {
                EndpointSourceReliabilityBucket::Unknown => 0.2,
                EndpointSourceReliabilityBucket::Weak => 0.35,
                EndpointSourceReliabilityBucket::Degraded => 0.42,
                EndpointSourceReliabilityBucket::Stable => 0.68,
                EndpointSourceReliabilityBucket::Corroborated => 0.86,
            }),
    )
}

fn average_freshness_score(records: &[EndpointDetectorEvidenceRecord]) -> f32 {
    average(
        records
            .iter()
            .map(|record| match record.freshness_category {
                EndpointFreshnessCategory::Fresh => 0.9,
                EndpointFreshnessCategory::Aging => 0.58,
                EndpointFreshnessCategory::Stale => 0.25,
                EndpointFreshnessCategory::Missing
                | EndpointFreshnessCategory::Unavailable
                | EndpointFreshnessCategory::Revoked
                | EndpointFreshnessCategory::Unknown => 0.0,
            }),
    )
}

fn average_correlation_score(records: &[EndpointDetectorEvidenceRecord]) -> f32 {
    average(
        records
            .iter()
            .map(|record| match record.correlation_quality_bucket {
                EndpointCorrelationQualityBucket::None => 0.0,
                EndpointCorrelationQualityBucket::SingleSignal => 0.32,
                EndpointCorrelationQualityBucket::Limited => 0.58,
                EndpointCorrelationQualityBucket::Corroborated => 0.82,
                EndpointCorrelationQualityBucket::Degraded => 0.24,
            }),
    )
}

fn average(values: impl Iterator<Item = f32>) -> f32 {
    let mut total = 0.0;
    let mut count = 0.0;
    for value in values {
        total += value;
        count += 1.0;
    }
    if count == 0.0 {
        0.0
    } else {
        total / count
    }
}

fn meets_quality_floor(
    actual: &EndpointEvidenceQualityBucket,
    minimum: &EndpointEvidenceQualityBucket,
) -> bool {
    quality_rank(actual) >= quality_rank(minimum)
}

fn quality_rank(bucket: &EndpointEvidenceQualityBucket) -> u8 {
    match bucket {
        EndpointEvidenceQualityBucket::Blocked => 0,
        EndpointEvidenceQualityBucket::Unknown => 1,
        EndpointEvidenceQualityBucket::Low => 2,
        EndpointEvidenceQualityBucket::Moderate => 3,
        EndpointEvidenceQualityBucket::Elevated => 4,
    }
}

fn meets_reliability_floor(
    actual: &EndpointSourceReliabilityBucket,
    minimum: &EndpointSourceReliabilityBucket,
) -> bool {
    reliability_rank(actual) >= reliability_rank(minimum)
}

fn reliability_rank(bucket: &EndpointSourceReliabilityBucket) -> u8 {
    match bucket {
        EndpointSourceReliabilityBucket::Unknown => 0,
        EndpointSourceReliabilityBucket::Weak => 1,
        EndpointSourceReliabilityBucket::Degraded => 2,
        EndpointSourceReliabilityBucket::Stable => 3,
        EndpointSourceReliabilityBucket::Corroborated => 4,
    }
}

fn meets_correlation_floor(
    actual: &EndpointCorrelationQualityBucket,
    minimum: &EndpointCorrelationQualityBucket,
) -> bool {
    correlation_rank(actual) >= correlation_rank(minimum)
}

fn correlation_rank(bucket: &EndpointCorrelationQualityBucket) -> u8 {
    match bucket {
        EndpointCorrelationQualityBucket::None => 0,
        EndpointCorrelationQualityBucket::Degraded => 1,
        EndpointCorrelationQualityBucket::SingleSignal => 2,
        EndpointCorrelationQualityBucket::Limited => 3,
        EndpointCorrelationQualityBucket::Corroborated => 4,
    }
}

fn validate_labels(
    field: &'static str,
    values: &[String],
) -> Result<(), EndpointThreatDetectionError> {
    validate_category_count(field, values.len())?;
    for value in values {
        safe_text(field, value)?;
    }
    Ok(())
}

fn validate_category_count(
    field: &'static str,
    len: usize,
) -> Result<(), EndpointThreatDetectionError> {
    if len > MAX_ENDPOINT_DETECTOR_LABELS {
        return Err(EndpointThreatDetectionError::ExceedsBound(field));
    }
    Ok(())
}

fn validate_ref_count(field: &'static str, len: usize) -> Result<(), EndpointThreatDetectionError> {
    if len > MAX_ENDPOINT_DETECTOR_REFS {
        return Err(EndpointThreatDetectionError::ExceedsBound(field));
    }
    Ok(())
}

fn require_redacted(
    field: &'static str,
    status: &RedactionStatus,
) -> Result<(), EndpointThreatDetectionError> {
    if is_safe_redaction_status(status) {
        Ok(())
    } else {
        Err(EndpointThreatDetectionError::UnsafeField(field))
    }
}

fn is_safe_redaction_status(status: &RedactionStatus) -> bool {
    matches!(
        status,
        RedactionStatus::Redacted
            | RedactionStatus::Tokenized
            | RedactionStatus::Hashed
            | RedactionStatus::PartiallyRedacted
            | RedactionStatus::Suppressed
    )
}

fn safe_text(field: &'static str, value: &str) -> Result<(), EndpointThreatDetectionError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(EndpointThreatDetectionError::EmptyField(field));
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.len() > MAX_ENDPOINT_DETECTOR_TEXT_BYTES
        || trimmed.contains("://")
        || trimmed.contains('@')
        || trimmed.contains('\\')
        || trimmed.contains('/')
        || trimmed.parse::<std::net::IpAddr>().is_ok()
        || FORBIDDEN_MARKERS
            .iter()
            .any(|marker| lower.contains(marker))
    {
        return Err(EndpointThreatDetectionError::UnsafeField(field));
    }
    Ok(())
}

fn bounded_unique_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .take(MAX_ENDPOINT_DETECTOR_LABELS)
        .collect()
}

fn bounded_visibility_flags(
    values: Vec<EndpointMissingVisibilityFlag>,
) -> Vec<EndpointMissingVisibilityFlag> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(format!("{value:?}")))
        .take(MAX_ENDPOINT_DETECTOR_LABELS)
        .collect()
}

const FORBIDDEN_MARKERS: &[&str] = &[
    "pid=",
    "pid:",
    "parent_pid",
    "process_name",
    "process_identity",
    "user_identity",
    "username",
    "host_identity",
    "hostname",
    "device_id",
    "destination_attribution",
    "socket",
    "port=",
    "port:",
    "local_port",
    "remote_port",
    "ip_address",
    "command_line",
    "file_path",
    "registry_key",
    "raw_provider_output",
    "password",
    "secret",
    "token",
    "credential",
    "certificate",
    ".exe",
    ".dll",
    "s-1-5-",
];

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        EndpointExecutionContextCategory, EndpointLifecycleBucket, EndpointOccurrenceIndicator,
        EndpointPrivilegeIntegrityCategory, EndpointProcessCategory, EndpointRelationCategory,
        EndpointServiceCategory, EndpointServiceStateBucket, EndpointStartupTypeBucket,
        EndpointTrustSignednessBucket, SessionId, Timestamp,
    };

    #[test]
    fn detection_duplicate_evidence_rejected() {
        let definition = definition();
        let evidence = evidence_record(
            EndpointDetectorEvidenceLayer::PortableFinding,
            EndpointDetectorEvidenceCategory::PortableFinding,
            "portable_finding_source",
            Some("sample_a"),
        );
        let mut duplicate = evidence_record(
            EndpointDetectorEvidenceLayer::Baseline,
            EndpointDetectorEvidenceCategory::BaselineDeviation,
            "baseline_source",
            Some("sample_b"),
        );
        duplicate.evidence_ref = evidence.evidence_ref.clone();
        let input = input_with(vec![evidence, duplicate], Vec::new());

        let result = EndpointThreatDetectorFramework::new().evaluate(&definition, &input);

        assert_eq!(result, Err(EndpointThreatDetectionError::DuplicateEvidence));
    }

    #[test]
    fn detection_cyclic_evidence_rejected() {
        let definition = definition();
        let mut first = evidence_record(
            EndpointDetectorEvidenceLayer::PortableFinding,
            EndpointDetectorEvidenceCategory::PortableFinding,
            "portable_finding_source",
            Some("sample_a"),
        );
        let mut second = evidence_record(
            EndpointDetectorEvidenceLayer::Baseline,
            EndpointDetectorEvidenceCategory::BaselineDeviation,
            "baseline_source",
            Some("sample_b"),
        );
        first.parent_evidence_refs = vec![second.evidence_ref.clone()];
        second.parent_evidence_refs = vec![first.evidence_ref.clone()];
        let input = input_with(vec![first, second], Vec::new());

        let result = EndpointThreatDetectorFramework::new().evaluate(&definition, &input);

        assert_eq!(result, Err(EndpointThreatDetectionError::CyclicEvidence));
    }

    #[test]
    fn evidence_same_sample_process_and_parent_facts_not_independent() {
        let mut definition = definition();
        definition.required_independent_evidence_categories = vec![
            EndpointDetectorEvidenceCategory::ProcessCategoryFact,
            EndpointDetectorEvidenceCategory::ParentRelationFact,
        ];
        definition.optional_supporting_categories.clear();
        let first = evidence_record(
            EndpointDetectorEvidenceLayer::ProcessCategory,
            EndpointDetectorEvidenceCategory::ProcessCategoryFact,
            "process_category_source",
            Some("native_sample_1"),
        );
        let second = evidence_record(
            EndpointDetectorEvidenceLayer::ParentRelation,
            EndpointDetectorEvidenceCategory::ParentRelationFact,
            "parent_category_source",
            Some("native_sample_1"),
        );
        let input = input_with(vec![first, second], Vec::new());

        let evaluation = EndpointThreatDetectorFramework::new()
            .evaluate(&definition, &input)
            .expect("bounded evaluation");

        assert!(!evaluation.accepted);
        assert_eq!(evaluation.evidence_validation.independent_source_count, 1);
        assert!(evaluation.rejected_candidate.is_some());
    }

    #[test]
    fn detection_broad_category_coincidence_insufficient() {
        let mut definition = definition();
        definition.required_independent_evidence_categories = vec![
            EndpointDetectorEvidenceCategory::ProcessCategoryFact,
            EndpointDetectorEvidenceCategory::ServiceCategoryFact,
        ];
        definition.optional_supporting_categories.clear();
        let first = evidence_record(
            EndpointDetectorEvidenceLayer::ProcessCategory,
            EndpointDetectorEvidenceCategory::ProcessCategoryFact,
            "process_category_source",
            Some("sample_a"),
        );
        let second = evidence_record(
            EndpointDetectorEvidenceLayer::ServiceCategory,
            EndpointDetectorEvidenceCategory::ServiceCategoryFact,
            "service_category_source",
            Some("sample_b"),
        );
        let input = input_with(vec![first, second], Vec::new());

        let evaluation = EndpointThreatDetectorFramework::new()
            .evaluate(&definition, &input)
            .expect("bounded evaluation");

        assert!(!evaluation.accepted);
        assert!(evaluation.evidence_validation.broad_category_only);
        assert_eq!(
            evaluation.rejected_candidate.expect("rejected").reason,
            EndpointRejectedCandidateReason::UnsafeField
        );
    }

    #[test]
    fn evidence_pattern_two_independent_layers_accepts_candidate() {
        let definition = definition();
        let first = evidence_record(
            EndpointDetectorEvidenceLayer::PortableFinding,
            EndpointDetectorEvidenceCategory::PortableFinding,
            "portable_finding_source",
            Some("sample_a"),
        );
        let second = evidence_record(
            EndpointDetectorEvidenceLayer::Baseline,
            EndpointDetectorEvidenceCategory::BaselineDeviation,
            "baseline_source",
            Some("sample_b"),
        );
        let input = input_with(vec![first, second], Vec::new());

        let evaluation = EndpointThreatDetectorFramework::new()
            .evaluate(&definition, &input)
            .expect("bounded evaluation");

        assert!(evaluation.accepted);
        assert_eq!(
            evaluation.evidence_validation.pattern,
            Some(EndpointIndependentEvidencePattern::TwoIndependentLayers)
        );
        assert!(evaluation.candidate.is_some());
    }

    #[test]
    fn evidence_pattern_hypothesis_with_fresh_native_fact_accepts_candidate() {
        let mut definition = definition();
        definition.required_independent_evidence_categories =
            vec![EndpointDetectorEvidenceCategory::EvidenceBackedHypothesis];
        definition.optional_supporting_categories.clear();
        definition.minimum_independent_source_count = 1;
        definition.minimum_evidence_count = 1;
        let mut hypothesis = evidence_record(
            EndpointDetectorEvidenceLayer::Hypothesis,
            EndpointDetectorEvidenceCategory::EvidenceBackedHypothesis,
            "hypothesis_source",
            Some("sample_h"),
        );
        hypothesis.hypothesis_ref = Some(AttackHypothesisId::new_v4());
        hypothesis.parent_evidence_refs = vec![EvidenceId::new_v4()];
        let input = input_with(
            vec![hypothesis],
            vec![fact_record(
                EndpointDetectorEvidenceLayer::ProcessCategory,
                "process_category",
                Some("native_sample_1"),
            )],
        );

        let evaluation = EndpointThreatDetectorFramework::new()
            .evaluate(&definition, &input)
            .expect("bounded evaluation");

        assert!(evaluation.accepted);
        assert_eq!(
            evaluation.evidence_validation.pattern,
            Some(EndpointIndependentEvidencePattern::EvidenceBackedHypothesisWithFreshNativeFacts)
        );
    }

    #[test]
    fn detection_confidence_caps_enforced_for_missing_visibility() {
        let mut definition = definition();
        definition.confidence_cap = EndpointThreatConfidenceBucket::Elevated;
        let mut first = evidence_record(
            EndpointDetectorEvidenceLayer::PortableFinding,
            EndpointDetectorEvidenceCategory::HighQualityFinding,
            "portable_finding_source",
            Some("sample_a"),
        );
        first.quality_bucket = EndpointEvidenceQualityBucket::Elevated;
        first.reliability_bucket = EndpointSourceReliabilityBucket::Corroborated;
        first.correlation_quality_bucket = EndpointCorrelationQualityBucket::Corroborated;
        let mut second = evidence_record(
            EndpointDetectorEvidenceLayer::Baseline,
            EndpointDetectorEvidenceCategory::BaselineDeviation,
            "baseline_source",
            Some("sample_b"),
        );
        second.quality_bucket = EndpointEvidenceQualityBucket::Elevated;
        second.reliability_bucket = EndpointSourceReliabilityBucket::Corroborated;
        second.correlation_quality_bucket = EndpointCorrelationQualityBucket::Corroborated;
        let input = input_with(vec![first, second], Vec::new());

        let evaluation = EndpointThreatDetectorFramework::new()
            .evaluate(&definition, &input)
            .expect("bounded evaluation");

        assert!(evaluation.accepted);
        assert_ne!(
            evaluation.confidence.confidence_bucket,
            EndpointThreatConfidenceBucket::Elevated
        );
        assert!(evaluation
            .confidence
            .capped_by
            .iter()
            .any(|reason| reason.contains("specificprocessidentityunavailable")));
    }

    #[test]
    fn endpoint_threat_pack_catalog_declares_first_detector_pack() {
        let catalog = endpoint_threat_lite_detector_pack_catalog().expect("catalog");
        let ids = catalog
            .iter()
            .map(|definition| definition.detector_id.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(catalog.len(), 8);
        for expected in [
            "possible_unusual_process_category_population_change",
            "possible_suspicious_parent_category_transition",
            "possible_remote_admin_endpoint_activity_with_auth_pressure",
            "possible_script_capable_activity_with_independent_security_evidence",
            "possible_service_state_change_with_security_context",
            "possible_endpoint_context_for_saas_cloud_abuse",
            "possible_deception_correlated_endpoint_probe",
            "endpoint_visibility_degradation_advisory",
        ] {
            assert!(ids.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn endpoint_threat_category_only_inputs_create_no_findings() {
        let output = EndpointThreatDetectorPack::new()
            .analyze(&input_with(
                vec![
                    evidence_record(
                        EndpointDetectorEvidenceLayer::ProcessCategory,
                        EndpointDetectorEvidenceCategory::ProcessCategoryFact,
                        "process_category_source",
                        Some("native_sample_1"),
                    ),
                    evidence_record(
                        EndpointDetectorEvidenceLayer::ServiceCategory,
                        EndpointDetectorEvidenceCategory::ServiceCategoryFact,
                        "service_category_source",
                        Some("native_sample_2"),
                    ),
                ],
                pack_facts(),
            ))
            .expect("pack output");

        assert!(output.findings.is_empty());
        assert!(output
            .evaluations
            .iter()
            .all(|evaluation| !evaluation.accepted));
    }

    #[test]
    fn endpoint_threat_shell_category_alone_creates_no_finding() {
        let mut input = input_with(
            vec![evidence_record(
                EndpointDetectorEvidenceLayer::ProcessCategory,
                EndpointDetectorEvidenceCategory::ProcessCategoryFact,
                "shell_category_source",
                Some("native_sample_1"),
            )],
            vec![fact_record(
                EndpointDetectorEvidenceLayer::ProcessCategory,
                "script_capable_activity",
                Some("native_sample_1"),
            )],
        );
        input.analysis_input.process_category = EndpointProcessCategory::Shell;

        let output = EndpointThreatDetectorPack::new()
            .analyze(&input)
            .expect("pack output");

        assert!(output.findings.is_empty());
    }

    #[test]
    fn endpoint_threat_service_change_alone_creates_no_finding() {
        let output = EndpointThreatDetectorPack::new()
            .analyze(&input_with(
                vec![evidence_record(
                    EndpointDetectorEvidenceLayer::ServiceCategory,
                    EndpointDetectorEvidenceCategory::ServiceCategoryFact,
                    "service_state_source",
                    Some("service_sample_1"),
                )],
                vec![fact_record(
                    EndpointDetectorEvidenceLayer::ServiceCategory,
                    "service_state_change",
                    Some("service_sample_1"),
                )],
            ))
            .expect("pack output");

        assert!(output.findings.is_empty());
    }

    #[test]
    fn endpoint_threat_first_seen_alone_creates_no_finding() {
        let mut baseline = evidence_record(
            EndpointDetectorEvidenceLayer::Baseline,
            EndpointDetectorEvidenceCategory::BaselineDeviation,
            "fresh_baseline_source",
            Some("baseline_sample_1"),
        );
        baseline.finding_ref = None;
        let mut input = input_with(
            vec![baseline],
            vec![
                fact_record(
                    EndpointDetectorEvidenceLayer::ProcessCategory,
                    "process_category",
                    Some("native_sample_1"),
                ),
                fact_record(
                    EndpointDetectorEvidenceLayer::ProcessCategory,
                    "population_change",
                    Some("native_sample_1"),
                ),
            ],
        );
        input.analysis_input.occurrence_indicator = EndpointOccurrenceIndicator::FirstSeen;

        let output = EndpointThreatDetectorPack::new()
            .analyze(&input)
            .expect("pack output");

        assert!(output.findings.is_empty());
    }

    #[test]
    fn endpoint_threat_visibility_degradation_advisory_remains_advisory() {
        let output = EndpointThreatDetectorPack::new()
            .analyze(&input_with(
                vec![evidence_record(
                    EndpointDetectorEvidenceLayer::Freshness,
                    EndpointDetectorEvidenceCategory::FreshnessOnly,
                    "freshness_source",
                    Some("visibility_sample_1"),
                )],
                Vec::new(),
            ))
            .expect("pack output");

        assert!(output.findings.is_empty());
        assert_eq!(output.advisories.len(), 1);
        assert_eq!(
            output.advisories[0].confidence_cap,
            EndpointThreatConfidenceBucket::Low
        );
    }

    #[test]
    fn endpoint_threat_supported_evidence_combinations_create_bounded_findings() {
        let output = EndpointThreatDetectorPack::new()
            .analyze(&input_with(supported_evidence(), pack_facts()))
            .expect("pack output");

        assert_eq!(output.findings.len(), 7);
        assert_eq!(output.advisories.len(), 1);
        assert!(output.findings.iter().all(|finding| {
            !finding.evidence_refs.is_empty()
                && finding.causal_claim == EndpointThreatCausalClaim::CorrelationOnly
                && finding.confidence_bucket != EndpointThreatConfidenceBucket::Elevated
                && finding.redaction_status == RedactionStatus::Redacted
        }));

        let serialized = serde_json::to_string(&output).expect("serialize output");
        for forbidden in [
            "malware_execution",
            "compromise",
            "persistence",
            "credential_theft",
            "lateral_movement",
            "process causality",
            "process_causality",
        ] {
            assert!(!serialized.contains(forbidden), "leaked {forbidden}");
        }
    }

    #[test]
    fn endpoint_threat_outputs_use_allowed_human_wording_only() {
        let mut definitions = endpoint_threat_detector_catalog().expect("base catalog");
        definitions.extend(endpoint_threat_lite_detector_pack_catalog().expect("pack catalog"));
        for definition in &definitions {
            assert_allowed_endpoint_wording(&definition.safe_wording);
        }

        let output = EndpointThreatDetectorPack::new()
            .analyze(&input_with(supported_evidence(), pack_facts()))
            .expect("pack output");
        for evaluation in &output.evaluations {
            if let Some(candidate) = &evaluation.candidate {
                assert_allowed_endpoint_wording(&candidate.summary_redacted);
            }
            if let Some(rejected) = &evaluation.rejected_candidate {
                assert!(!contains_forbidden_endpoint_claim(
                    &rejected.summary_redacted
                ));
            }
        }
        for finding in &output.findings {
            assert_allowed_endpoint_wording(&finding.summary_redacted);
        }
        for advisory in &output.advisories {
            assert_allowed_endpoint_wording(&advisory.summary_redacted);
        }
    }

    #[test]
    fn endpoint_threat_serialization_avoids_forbidden_claims_and_llm_markers() {
        let (pack_output, intelligence_input) = intelligence_input_from_pack();
        let intelligence_output = EndpointThreatIntelligenceIntegrator::new()
            .integrate(&intelligence_input)
            .expect("intelligence output");
        let serialized = serde_json::to_string(&(pack_output, intelligence_output))
            .expect("serialize endpoint hardening output")
            .to_ascii_lowercase();

        for forbidden in forbidden_endpoint_claims() {
            assert!(
                !serialized.contains(forbidden),
                "endpoint threat output leaked forbidden claim {forbidden}"
            );
        }
        for forbidden in [
            "process names",
            "service names",
            "command line",
            "destination attribution",
            "credentials",
            "secrets",
            "automatic_llm_invocation",
            "llm_provider_request",
            "response_execution_started\":true",
            "executes_response\":true",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "endpoint threat output leaked LLM/response boundary marker {forbidden}"
            );
        }
    }

    #[test]
    fn endpoint_threat_risk_only_from_validated_findings() {
        let (pack_output, mut intelligence_input) = intelligence_input_from_pack();
        let mut invalid = pack_output.findings[0].clone();
        invalid.finding_id = EndpointThreatFindingId::new_v4();
        invalid.evidence_refs.clear();
        let invalid_ref = invalid.finding_id.clone();
        intelligence_input.findings.push(invalid);

        let output = EndpointThreatIntelligenceIntegrator::new()
            .integrate(&intelligence_input)
            .expect("intelligence output");

        assert_eq!(output.risk_hints.len(), pack_output.findings.len());
        assert!(output.rejected_finding_refs.contains(&invalid_ref));
        assert!(output.risk_hints.iter().all(|hint| {
            hint.evidence_input_only
                && !hint.creates_alert
                && !hint.creates_incident
                && !hint.executes_response
                && hint.risk_delta <= 4.5
                && hint.validate_boundary().is_ok()
        }));

        let hint_types = output
            .risk_hints
            .iter()
            .map(|hint| hint.hint_type.as_str())
            .collect::<BTreeSet<_>>();
        for expected in [
            "endpoint_process_category_risk_hint",
            "endpoint_auth_context_risk_hint",
            "endpoint_service_category_risk_hint",
            "endpoint_saas_cloud_context_risk_hint",
            "endpoint_deception_context_risk_hint",
        ] {
            assert!(hint_types.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn endpoint_threat_unrelated_hypotheses_not_merged() {
        let (_, intelligence_input) = intelligence_input_from_pack();
        let output = EndpointThreatIntelligenceIntegrator::new()
            .integrate(&intelligence_input)
            .expect("intelligence output");
        let ids = output
            .hypothesis_definitions
            .iter()
            .map(|definition| definition.category.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(output.hypothesis_definitions.len(), 6);
        for expected in [
            "possible_endpoint_activity_with_auth_pressure",
            "possible_endpoint_context_for_api_abuse",
            "possible_endpoint_context_for_saas_cloud_abuse",
            "possible_deception_correlated_endpoint_probe",
            "possible_service_change_with_independent_security_evidence",
            "possible_multi_layer_endpoint_attack_chain",
        ] {
            assert!(ids.contains(expected), "missing {expected}");
        }
        for unrelated in ["dns", "waf_bypass", "incident", "response_execution"] {
            assert!(
                !ids.iter().any(|id| id.contains(unrelated)),
                "merged unrelated hypothesis {unrelated}"
            );
        }
        assert!(output.hypothesis_definitions.iter().all(|definition| {
            definition.minimum_evidence >= 2
                && definition.confidence_cap == FusionConfidenceBucket::Low
                && definition
                    .disqualifier_categories
                    .iter()
                    .any(|category| category == "category_only_context")
                && definition.validate().is_ok()
        }));
    }

    #[test]
    fn endpoint_threat_attack_mapping_remains_conservative() {
        let (_, intelligence_input) = intelligence_input_from_pack();
        let output = EndpointThreatIntelligenceIntegrator::new()
            .integrate(&intelligence_input)
            .expect("intelligence output");

        assert!(!output.attack_attachments.is_empty());
        assert!(output.attack_attachments.iter().all(|attachment| {
            !attachment.technique_observed
                && attachment.confidence_cap != EndpointThreatConfidenceBucket::Elevated
                && attachment
                    .unsupported_visibility
                    .contains(&"process_network_techniques_unsupported".to_string())
                && attachment
                    .unsupported_visibility
                    .contains(&"command_visibility_techniques_unsupported".to_string())
                && attachment.validate().is_ok()
        }));
        assert!(output
            .hypothesis_definitions
            .iter()
            .flat_map(|definition| definition.attack_candidates.iter())
            .all(|candidate| candidate.confidence == FusionConfidenceBucket::Low));
    }

    #[test]
    fn endpoint_threat_graph_remains_category_level() {
        let (_, intelligence_input) = intelligence_input_from_pack();
        let output = EndpointThreatIntelligenceIntegrator::new()
            .integrate(&intelligence_input)
            .expect("intelligence output");

        assert!(!output.graph_hints.is_empty());
        for hint in &output.graph_hints {
            assert_eq!(hint.source_entity.entity_type, EntityType::Finding);
            assert!(!matches!(
                hint.target_entity.entity_type,
                EntityType::Ip
                    | EntityType::User
                    | EntityType::Url
                    | EntityType::CloudResource
                    | EntityType::Certificate
                    | EntityType::Process
            ));
            let GraphHintType::Custom(edge_type) = &hint.hint_type else {
                panic!("endpoint graph emitted non-custom edge");
            };
            assert!(ALLOWED_ENDPOINT_GRAPH_EDGES.contains(&edge_type.as_str()));
            for forbidden in [
                "destination",
                "credential",
                "user",
                "file",
                "compromise",
                "persistence",
            ] {
                assert!(
                    !edge_type.contains(forbidden),
                    "graph edge leaked forbidden relation {forbidden}"
                );
            }
            assert!(validate_graph_hint_boundary(hint).is_ok());
        }
    }

    #[test]
    fn endpoint_threat_detector_logic_stays_out_of_unrelated_layers() {
        let scheduler = include_str!("../../app_core/src/native_scheduler.rs");
        let scheduler_host = include_str!("../../app_core/src/native_scheduler_host.rs");
        let sampler = include_str!("../../app_core/src/native_sampler_runtime.rs");
        let provider = include_str!("../../app_core/src/portable_proxy_metadata_provider.rs");
        let report_generator = include_str!("report_generation.rs");
        let frontend_panel = include_str!(
            "../../../frontend/src/features/investigation/components/EndpointThreatPanel.tsx"
        );
        for source in [
            scheduler,
            scheduler_host,
            sampler,
            provider,
            report_generator,
            frontend_panel,
        ] {
            assert!(!source.contains("EndpointThreatDetectorPack"));
            assert!(!source.contains("EndpointThreatDetectorFramework"));
            assert!(!source.contains("EndpointThreatIntelligenceIntegrator"));
            assert!(!source.contains("endpoint_threat_lite_detector_pack_catalog"));
        }
    }

    fn definition() -> EndpointThreatDetectorDefinition {
        endpoint_threat_detector_catalog()
            .expect("catalog")
            .pop()
            .expect("definition")
    }

    fn input_with(
        evidence: Vec<EndpointDetectorEvidenceRecord>,
        facts: Vec<EndpointDetectorFactRecord>,
    ) -> EndpointThreatDetectionInput {
        EndpointThreatDetectionInput {
            analysis_input: analysis_input(),
            candidate_ref: Some(EndpointThreatCandidateId::new_v4()),
            evidence,
            facts,
        }
    }

    fn analysis_input() -> EndpointAnalysisInput {
        EndpointAnalysisInput {
            analysis_input_id: sentinel_contracts::EndpointAnalysisInputId::new_v4(),
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
            attack_refs: Vec::new(),
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

    fn evidence_record(
        layer: EndpointDetectorEvidenceLayer,
        category: EndpointDetectorEvidenceCategory,
        source_key: &str,
        sample_group_ref: Option<&str>,
    ) -> EndpointDetectorEvidenceRecord {
        let mut record = EndpointDetectorEvidenceRecord {
            evidence_ref: EvidenceId::new_v4(),
            layer,
            category,
            provenance_id: DataSourceId::new_v4(),
            source_key: source_key.to_string(),
            sample_group_ref: sample_group_ref.map(str::to_string),
            parent_evidence_refs: Vec::new(),
            generated_from_candidate_ref: None,
            finding_ref: Some(FindingId::new_v4()),
            hypothesis_ref: None,
            baseline_ref: Some(BaselineRecordId::new_v4()),
            risk_ref: None,
            quality_bucket: EndpointEvidenceQualityBucket::Moderate,
            reliability_bucket: EndpointSourceReliabilityBucket::Stable,
            freshness_category: EndpointFreshnessCategory::Fresh,
            correlation_quality_bucket: EndpointCorrelationQualityBucket::Limited,
            redaction_status: RedactionStatus::Redacted,
        };
        if record.category == EndpointDetectorEvidenceCategory::BaselineDeviation {
            record.finding_ref = None;
        }
        record
    }

    fn supported_evidence() -> Vec<EndpointDetectorEvidenceRecord> {
        let mut high_quality = evidence_record(
            EndpointDetectorEvidenceLayer::PortableFinding,
            EndpointDetectorEvidenceCategory::HighQualityFinding,
            "high_quality_security_finding",
            Some("finding_sample_1"),
        );
        high_quality.quality_bucket = EndpointEvidenceQualityBucket::Elevated;
        high_quality.reliability_bucket = EndpointSourceReliabilityBucket::Corroborated;
        high_quality.correlation_quality_bucket = EndpointCorrelationQualityBucket::Corroborated;

        let mut portable = evidence_record(
            EndpointDetectorEvidenceLayer::PortableFinding,
            EndpointDetectorEvidenceCategory::PortableFinding,
            "portable_security_finding",
            Some("finding_sample_2"),
        );
        portable.finding_ref = Some(FindingId::new_v4());

        let mut baseline = evidence_record(
            EndpointDetectorEvidenceLayer::Baseline,
            EndpointDetectorEvidenceCategory::BaselineDeviation,
            "fresh_baseline_source",
            Some("baseline_sample_1"),
        );
        baseline.finding_ref = None;
        baseline.baseline_ref = Some(BaselineRecordId::new_v4());

        let mut risk = evidence_record(
            EndpointDetectorEvidenceLayer::Risk,
            EndpointDetectorEvidenceCategory::RiskReference,
            "risk_context_source",
            Some("risk_sample_1"),
        );
        risk.risk_ref = Some(RiskEventId::new_v4());

        let mut hypothesis = evidence_record(
            EndpointDetectorEvidenceLayer::Hypothesis,
            EndpointDetectorEvidenceCategory::EvidenceBackedHypothesis,
            "hypothesis_source",
            Some("hypothesis_sample_1"),
        );
        hypothesis.hypothesis_ref = Some(AttackHypothesisId::new_v4());
        hypothesis.parent_evidence_refs = vec![portable.evidence_ref.clone()];

        vec![high_quality, portable, baseline, risk, hypothesis]
    }

    fn pack_facts() -> Vec<EndpointDetectorFactRecord> {
        [
            (
                EndpointDetectorEvidenceLayer::ProcessCategory,
                "process_category",
            ),
            (
                EndpointDetectorEvidenceLayer::ProcessCategory,
                "population_change",
            ),
            (
                EndpointDetectorEvidenceLayer::ParentRelation,
                "parent_category_transition",
            ),
            (
                EndpointDetectorEvidenceLayer::ProcessCategory,
                "remote_admin_endpoint_activity",
            ),
            (
                EndpointDetectorEvidenceLayer::ProcessCategory,
                "auth_pressure",
            ),
            (
                EndpointDetectorEvidenceLayer::ProcessCategory,
                "script_capable_activity",
            ),
            (
                EndpointDetectorEvidenceLayer::ServiceCategory,
                "service_state_change",
            ),
            (
                EndpointDetectorEvidenceLayer::ProcessCategory,
                "saas_cloud_endpoint_context",
            ),
            (
                EndpointDetectorEvidenceLayer::ProcessCategory,
                "deception_endpoint_probe",
            ),
        ]
        .into_iter()
        .map(|(layer, category)| fact_record(layer, category, Some(category)))
        .collect()
    }

    fn intelligence_input_from_pack() -> (
        EndpointThreatDetectorPackOutput,
        EndpointThreatIntelligenceInput,
    ) {
        let detection_input = input_with(supported_evidence(), pack_facts());
        let pack_output = EndpointThreatDetectorPack::new()
            .analyze(&detection_input)
            .expect("pack output");
        let intelligence_input = EndpointThreatIntelligenceInput {
            findings: pack_output.findings.clone(),
            facts: detection_input.facts.clone(),
            evaluations: pack_output.evaluations.clone(),
        };
        (pack_output, intelligence_input)
    }

    fn fact_record(
        layer: EndpointDetectorEvidenceLayer,
        category: &str,
        sample_group_ref: Option<&str>,
    ) -> EndpointDetectorFactRecord {
        EndpointDetectorFactRecord {
            fact_ref: SecurityFactId::new_v4(),
            category: category.to_string(),
            layer,
            provenance_id: DataSourceId::new_v4(),
            evidence_refs: vec![EvidenceId::new_v4()],
            sample_group_ref: sample_group_ref.map(str::to_string),
            freshness_category: EndpointFreshnessCategory::Fresh,
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn assert_allowed_endpoint_wording(value: &str) {
        assert!(
            allowed_endpoint_wording().contains(&value),
            "endpoint wording is not allowlisted: {value}"
        );
        assert!(
            !contains_forbidden_endpoint_claim(value),
            "endpoint wording leaked forbidden claim: {value}"
        );
    }

    fn contains_forbidden_endpoint_claim(value: &str) -> bool {
        let lower = value.to_ascii_lowercase();
        forbidden_endpoint_claims()
            .iter()
            .any(|claim| lower.contains(claim))
    }

    fn allowed_endpoint_wording() -> BTreeSet<&'static str> {
        [
            "possible unusual endpoint category activity",
            "possible endpoint context supporting an existing security finding",
            "possible remote-admin endpoint activity with authentication pressure",
            "possible service change with independent security evidence",
            "endpoint visibility degradation advisory",
        ]
        .into_iter()
        .collect()
    }

    fn forbidden_endpoint_claims() -> Vec<&'static str> {
        vec![
            "malware executed",
            "malicious script confirmed",
            "host compromised",
            "account compromised",
            "credential stolen",
            "persistence confirmed",
            "privilege escalation confirmed",
            "lateral movement confirmed",
            "exfiltration confirmed",
            "process caused network activity",
            "attacker identity known",
            "complete edr coverage",
        ]
    }
}
