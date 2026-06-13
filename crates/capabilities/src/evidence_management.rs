use sentinel_contracts::{
    AttackMapping, EntityRef, EvidenceBundle, EvidenceItem, Finding, FindingExplanation, FindingId,
    FindingState, GraphHint, GraphHintType, IntelligenceContractError, MappingProvenance, PluginId,
    QualityScore, RiskHint, RiskReason, SchemaVersion, SecurityContractError, SecurityObservation,
    SecuritySeverity, Timestamp, TraceId,
};
use sentinel_platform::observability::audit::AuditValidationError;
use sentinel_platform::{
    AuditActionType, AuditCategory, AuditDecision, AuditEvent, AuditReceipt, AuditSink,
    AuditSinkError,
};
use sentinel_storage::{LogicalRecord, LogicalStore, SqliteStoreFactory, StorageError, StoreKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fmt;

pub const EVIDENCE_MANAGEMENT_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const EVIDENCE_MANAGEMENT_PROVENANCE: &str = "sentinel-guard-evidence-management-v1";

#[derive(Debug)]
pub enum EvidenceManagementError {
    EmptyEvidence,
    EmptyFindingType,
    MissingEvidenceRef(String),
    HighConfidenceRequiresIndependentSources,
    PrivacyMarker { field: &'static str },
    InvalidQualityScore,
    Contract(String),
    Intelligence(String),
    Storage(StorageError),
    Audit(AuditSinkError),
    Serialization(serde_json::Error),
}

impl fmt::Display for EvidenceManagementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEvidence => write!(f, "at least one evidence item is required"),
            Self::EmptyFindingType => write!(f, "finding_type must not be empty"),
            Self::MissingEvidenceRef(ref_id) => {
                write!(f, "finding references missing evidence item: {ref_id}")
            }
            Self::HighConfidenceRequiresIndependentSources => write!(
                f,
                "high confidence requires multiple independent evidence sources"
            ),
            Self::PrivacyMarker { field } => {
                write!(f, "{field} contains a forbidden private-content marker")
            }
            Self::InvalidQualityScore => write!(f, "quality score is outside valid range"),
            Self::Contract(error) => write!(f, "evidence management contract error: {error}"),
            Self::Intelligence(error) => {
                write!(
                    f,
                    "evidence management intelligence boundary error: {error}"
                )
            }
            Self::Storage(error) => write!(f, "evidence management storage error: {error}"),
            Self::Audit(error) => write!(f, "evidence management audit error: {error}"),
            Self::Serialization(error) => {
                write!(f, "evidence management serialization error: {error}")
            }
        }
    }
}

impl std::error::Error for EvidenceManagementError {}

impl From<SecurityContractError> for EvidenceManagementError {
    fn from(value: SecurityContractError) -> Self {
        Self::Contract(value.to_string())
    }
}

impl From<IntelligenceContractError> for EvidenceManagementError {
    fn from(value: IntelligenceContractError) -> Self {
        Self::Intelligence(value.to_string())
    }
}

impl From<StorageError> for EvidenceManagementError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

impl From<AuditSinkError> for EvidenceManagementError {
    fn from(value: AuditSinkError) -> Self {
        Self::Audit(value)
    }
}

impl From<AuditValidationError> for EvidenceManagementError {
    fn from(value: AuditValidationError) -> Self {
        Self::Audit(AuditSinkError::Validation(value))
    }
}

impl From<serde_json::Error> for EvidenceManagementError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceClass {
    Network,
    Dns,
    Tls,
    Http,
    Process,
    Asset,
    Intelligence,
    Graph,
    Manual,
    #[default]
    Unknown,
}

impl EvidenceSourceClass {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Dns => "dns",
            Self::Tls => "tls",
            Self::Http => "http",
            Self::Process => "process",
            Self::Asset => "asset",
            Self::Intelligence => "intelligence",
            Self::Graph => "graph",
            Self::Manual => "manual",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CollectedEvidence {
    pub evidence: EvidenceItem,
    pub source_class: EvidenceSourceClass,
    pub source_key: String,
    pub independence_key: String,
    pub collected_at: Timestamp,
}

impl CollectedEvidence {
    pub fn from_item(
        evidence: EvidenceItem,
        source_class: EvidenceSourceClass,
        source_key: impl Into<String>,
    ) -> Result<Self, EvidenceManagementError> {
        validate_evidence_item(&evidence)?;
        let source_key = require_safe_text("source_key", source_key.into())?;
        let independence_key = independence_key(&source_class, &evidence);
        Ok(Self {
            evidence,
            source_class,
            source_key,
            independence_key,
            collected_at: Timestamp::now(),
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EvidenceCollectionInput {
    pub observations: Vec<SecurityObservation>,
    pub evidence_items: Vec<EvidenceItem>,
    pub risk_hints: Vec<RiskHint>,
    pub graph_hints: Vec<GraphHint>,
    pub producer_plugin: Option<PluginId>,
}

#[derive(Clone, Debug, Default)]
pub struct EvidenceCollector;

impl EvidenceCollector {
    pub fn new() -> Self {
        Self
    }

    pub fn collect(
        &self,
        input: EvidenceCollectionInput,
    ) -> Result<Vec<CollectedEvidence>, EvidenceManagementError> {
        let mut collected = Vec::new();

        for observation in input.observations {
            validate_safe_text("observation_type", &observation.observation_type)?;
            validate_safe_text("observation_summary", &observation.summary_redacted)?;
            let class = classify_observation(&observation);
            let mut evidence = EvidenceItem::new(
                format!("observation.{}", observation.observation_type),
                observation.summary_redacted.clone(),
            )?;
            evidence.source_event_refs = observation.source_event_refs.clone();
            evidence.source_plugin = observation
                .producer_plugin
                .clone()
                .or(input.producer_plugin.clone());
            evidence.entity_refs = observation.entity_refs.clone();
            evidence.timestamp = observation.timestamp.clone();
            evidence.weight = source_weight(&class);
            evidence.confidence = observation.confidence.clone();
            evidence.privacy_class = observation.privacy_class.clone();
            evidence.description_redacted =
                Some("Collected from a security observation summary.".to_string());
            collected.push(CollectedEvidence::from_item(
                evidence,
                class,
                format!("observation:{}", observation.observation_id),
            )?);
        }

        for mut evidence in input.evidence_items {
            if evidence.source_plugin.is_none() {
                evidence.source_plugin = input.producer_plugin.clone();
            }
            let class = classify_evidence_type(&evidence.evidence_type);
            let source_key = format!("evidence:{}", evidence.evidence_id);
            collected.push(CollectedEvidence::from_item(evidence, class, source_key)?);
        }

        for hint in input.risk_hints {
            hint.validate_boundary()?;
            let mut evidence = EvidenceItem::new(
                format!("risk_hint.{}", hint.hint_type),
                hint.summary_redacted.clone(),
            )?;
            evidence.entity_refs = hint.entity_ref.clone().into_iter().collect();
            evidence.timestamp = hint.timestamp.clone();
            evidence.weight = risk_hint_weight(hint.risk_delta)?;
            evidence.confidence = hint.confidence.clone();
            evidence.privacy_class = hint.privacy_class.clone();
            evidence.description_redacted =
                Some("Collected from evidence-input-only local intelligence context.".to_string());
            collected.push(CollectedEvidence::from_item(
                evidence,
                EvidenceSourceClass::Intelligence,
                format!("risk_hint:{}", hint.risk_hint_id),
            )?);
        }

        for hint in input.graph_hints {
            let hint_label = graph_hint_label(&hint.hint_type);
            let mut evidence = EvidenceItem::new(
                format!("graph_hint.{hint_label}"),
                format!(
                    "Graph hint links {} to {}.",
                    entity_label(&hint.source_entity),
                    entity_label(&hint.target_entity)
                ),
            )?;
            evidence.source_plugin = Some(hint.producer_plugin.clone());
            evidence.entity_refs = vec![hint.source_entity.clone(), hint.target_entity.clone()];
            evidence.timestamp = hint.timestamp.clone();
            evidence.weight = quality_score(0.5)?;
            evidence.confidence = hint.confidence.clone();
            evidence.privacy_class = hint.privacy_class.clone();
            evidence.description_redacted =
                Some("Collected from a graph hint; canonical graph remains untouched.".to_string());
            collected.push(CollectedEvidence::from_item(
                evidence,
                EvidenceSourceClass::Graph,
                format!("graph_hint:{}", hint.hint_id),
            )?);
        }

        if collected.is_empty() {
            return Err(EvidenceManagementError::EmptyEvidence);
        }

        Ok(collected)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EvidenceDeduplicationReport {
    pub retained_count: usize,
    pub removed_duplicate_count: usize,
    pub duplicate_keys: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceDeduplicationOutput {
    pub evidence: Vec<CollectedEvidence>,
    pub report: EvidenceDeduplicationReport,
}

#[derive(Clone, Debug, Default)]
pub struct EvidenceDeduplicator;

impl EvidenceDeduplicator {
    pub fn new() -> Self {
        Self
    }

    pub fn deduplicate(
        &self,
        evidence: Vec<CollectedEvidence>,
    ) -> Result<EvidenceDeduplicationOutput, EvidenceManagementError> {
        if evidence.is_empty() {
            return Err(EvidenceManagementError::EmptyEvidence);
        }

        let mut retained = BTreeMap::<String, CollectedEvidence>::new();
        let mut duplicate_keys = Vec::new();
        let mut removed_duplicate_count = 0;

        for item in evidence {
            let key = dedupe_key(&item);
            if let Some(existing) = retained.get(&key) {
                removed_duplicate_count += 1;
                duplicate_keys.push(key.clone());
                if item.evidence.confidence.value() > existing.evidence.confidence.value() {
                    retained.insert(key, item);
                }
            } else {
                retained.insert(key, item);
            }
        }

        let evidence = retained.into_values().collect::<Vec<_>>();
        Ok(EvidenceDeduplicationOutput {
            report: EvidenceDeduplicationReport {
                retained_count: evidence.len(),
                removed_duplicate_count,
                duplicate_keys,
            },
            evidence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceReport {
    pub confidence: QualityScore,
    pub independent_source_count: usize,
    pub high_confidence_allowed: bool,
    pub capped_reason: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ConfidenceCalculator;

impl ConfidenceCalculator {
    pub fn new() -> Self {
        Self
    }

    pub fn calculate(
        &self,
        evidence: &[CollectedEvidence],
        high_confidence_requires_independent_sources: bool,
    ) -> Result<ConfidenceReport, EvidenceManagementError> {
        if evidence.is_empty() {
            return Err(EvidenceManagementError::EmptyEvidence);
        }

        let weighted_sum = evidence.iter().fold(0.0_f32, |accumulator, item| {
            accumulator + (item.evidence.confidence.value() * item.evidence.weight.value())
        });
        let weight_sum = evidence
            .iter()
            .map(|item| item.evidence.weight.value())
            .sum::<f32>()
            .max(0.01);
        let source_count = independent_source_count(evidence);
        let source_bonus = ((source_count.saturating_sub(1)) as f32 * 0.08).min(0.16);
        let mut score = ((weighted_sum / weight_sum) + source_bonus).min(1.0);
        let mut capped_reason = None;

        if high_confidence_requires_independent_sources && source_count < 2 && score >= 0.75 {
            score = 0.69;
            capped_reason = Some(
                "High confidence capped until another independent evidence source supports the finding."
                    .to_string(),
            );
        }

        Ok(ConfidenceReport {
            confidence: quality_score(score)?,
            independent_source_count: source_count,
            high_confidence_allowed: !high_confidence_requires_independent_sources
                || source_count >= 2,
            capped_reason,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct SeverityCalculator;

impl SeverityCalculator {
    pub fn new() -> Self {
        Self
    }

    pub fn calculate(
        &self,
        evidence: &[CollectedEvidence],
        confidence: &QualityScore,
    ) -> Result<SeverityCalculation, EvidenceManagementError> {
        if evidence.is_empty() {
            return Err(EvidenceManagementError::EmptyEvidence);
        }

        let total_weight = total_weight(evidence)?;
        let combined = (confidence.value() * 0.6) + (total_weight.value() * 0.4);
        let severity = if combined >= 0.88 {
            SecuritySeverity::Critical
        } else if combined >= 0.72 {
            SecuritySeverity::High
        } else if combined >= 0.5 {
            SecuritySeverity::Medium
        } else if combined >= 0.25 {
            SecuritySeverity::Low
        } else {
            SecuritySeverity::Informational
        };

        Ok(SeverityCalculation {
            severity,
            total_weight,
            combined_score: quality_score(combined)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SeverityCalculation {
    pub severity: SecuritySeverity,
    pub total_weight: QualityScore,
    pub combined_score: QualityScore,
}

#[derive(Clone, Debug, Default)]
pub struct ExplanationBuilder;

impl ExplanationBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn attack_mappings(
        &self,
        finding_type: &str,
        confidence: &QualityScore,
    ) -> Result<Vec<AttackMapping>, EvidenceManagementError> {
        let mut provenance = MappingProvenance::new(EVIDENCE_MANAGEMENT_PROVENANCE)?;
        provenance.source_version = Some("1.0.0".to_string());

        let mapping = if finding_type.contains("c2") {
            AttackMapping::mitre_attack_enterprise(
                "TA0011",
                "Command and Control",
                "T1071",
                "Application Layer Protocol",
                confidence.clone(),
                Some(provenance),
            )?
        } else if finding_type.contains("exfil") {
            AttackMapping::mitre_attack_enterprise(
                "TA0010",
                "Exfiltration",
                "T1041",
                "Exfiltration Over C2 Channel",
                confidence.clone(),
                Some(provenance),
            )?
        } else if finding_type.contains("lateral") {
            AttackMapping::mitre_attack_enterprise(
                "TA0008",
                "Lateral Movement",
                "T1021",
                "Remote Services",
                confidence.clone(),
                Some(provenance),
            )?
        } else if finding_type.contains("asset") || finding_type.contains("exposure") {
            AttackMapping::internal("asset_exposure", confidence.clone(), Some(provenance))?
        } else {
            AttackMapping::internal("security_signal", confidence.clone(), Some(provenance))?
        };

        Ok(vec![mapping])
    }

    pub fn build(
        &self,
        request: &EvidenceBundleRequest,
        evidence: &[CollectedEvidence],
        confidence: &ConfidenceReport,
        severity: &SeverityCalculation,
        attack_mappings: &[AttackMapping],
    ) -> Result<FindingExplanation, EvidenceManagementError> {
        let summary = format!(
            "{} supported by {} evidence item(s), {} independent source(s), confidence {:.2}, severity {:?}.",
            request.finding_type,
            evidence.len(),
            confidence.independent_source_count,
            confidence.confidence.value(),
            severity.severity
        );
        validate_safe_text("explanation_summary", &summary)?;

        let mut explanation = FindingExplanation::new(summary)?;
        for item in evidence {
            let mut reason = RiskReason::new(
                item.evidence.evidence_type.clone(),
                item.evidence.value_summary_redacted.clone(),
            )?;
            reason.confidence = item.evidence.confidence.clone();
            reason.evidence_refs.push(item.evidence.evidence_id.clone());
            reason.attack_mappings = attack_mappings.to_vec();
            explanation.risk_reasons.push(reason);
        }

        if let Some(reason) = &confidence.capped_reason {
            explanation.limitations_redacted.push(reason.clone());
        }
        if request.high_confidence_requires_independent_sources {
            explanation.limitations_redacted.push(
                "High-confidence promotion requires multiple independent evidence sources."
                    .to_string(),
            );
        }

        Ok(explanation)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundleRequest {
    pub finding_type: String,
    pub producer_plugin: PluginId,
    pub entity_refs: Vec<EntityRef>,
    pub evidence: Vec<CollectedEvidence>,
    pub high_confidence_requires_independent_sources: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundleBuildResult {
    pub bundle: EvidenceBundle,
    pub confidence: ConfidenceReport,
    pub severity: SeverityCalculation,
    pub attack_mappings: Vec<AttackMapping>,
}

#[derive(Clone, Debug, Default)]
pub struct EvidenceBundleBuilder {
    confidence_calculator: ConfidenceCalculator,
    severity_calculator: SeverityCalculator,
    explanation_builder: ExplanationBuilder,
}

impl EvidenceBundleBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(
        &self,
        request: EvidenceBundleRequest,
    ) -> Result<EvidenceBundleBuildResult, EvidenceManagementError> {
        validate_finding_type(&request.finding_type)?;
        if request.evidence.is_empty() {
            return Err(EvidenceManagementError::EmptyEvidence);
        }

        let confidence = self.confidence_calculator.calculate(
            &request.evidence,
            request.high_confidence_requires_independent_sources,
        )?;
        let severity = self
            .severity_calculator
            .calculate(&request.evidence, &confidence.confidence)?;
        let attack_mappings = self
            .explanation_builder
            .attack_mappings(&request.finding_type, &confidence.confidence)?;
        let explanation = self.explanation_builder.build(
            &request,
            &request.evidence,
            &confidence,
            &severity,
            &attack_mappings,
        )?;
        let evidence_refs = request
            .evidence
            .iter()
            .map(|item| item.evidence.evidence_id.clone())
            .collect::<Vec<_>>();
        let mut bundle = EvidenceBundle::new(evidence_refs, explanation)?;
        bundle.total_weight = severity.total_weight.clone();
        bundle.confidence = confidence.confidence.clone();
        bundle.severity = severity.severity.clone();

        Ok(EvidenceBundleBuildResult {
            bundle,
            confidence,
            severity,
            attack_mappings,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingQualityIssueKind {
    MissingEvidence,
    MissingEvidenceRef,
    PrivateContentMarker,
    HighConfidenceWithoutIndependentSources,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingQualityIssue {
    pub kind: FindingQualityIssueKind,
    pub summary_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FindingQualityReport {
    pub passed: bool,
    pub evidence_count: usize,
    pub independent_source_count: usize,
    pub confidence: QualityScore,
    pub severity: SecuritySeverity,
    pub issues: Vec<FindingQualityIssue>,
}

#[derive(Clone, Debug, Default)]
pub struct FindingQualityValidator;

impl FindingQualityValidator {
    pub fn new() -> Self {
        Self
    }

    pub fn validate(
        &self,
        finding: &Finding,
        bundle: &EvidenceBundle,
        evidence: &[CollectedEvidence],
        high_confidence_requires_independent_sources: bool,
    ) -> Result<FindingQualityReport, EvidenceManagementError> {
        let mut issues = Vec::new();

        if evidence.is_empty()
            || finding.evidence_refs().is_empty()
            || bundle.evidence_refs.is_empty()
        {
            issues.push(issue(
                FindingQualityIssueKind::MissingEvidence,
                "Finding quality requires at least one evidence item.",
            ));
        }

        for evidence_ref in finding.evidence_refs() {
            if !has_collected_evidence_ref(evidence, evidence_ref) {
                issues.push(issue(
                    FindingQualityIssueKind::MissingEvidenceRef,
                    format!("Missing evidence item for ref {evidence_ref}."),
                ));
            }
            if !bundle.evidence_refs.iter().any(|item| item == evidence_ref) {
                issues.push(issue(
                    FindingQualityIssueKind::MissingEvidenceRef,
                    format!(
                        "Finding evidence ref {evidence_ref} is absent from the evidence bundle."
                    ),
                ));
            }
        }

        for evidence_ref in &bundle.evidence_refs {
            if !has_collected_evidence_ref(evidence, evidence_ref) {
                issues.push(issue(
                    FindingQualityIssueKind::MissingEvidenceRef,
                    format!("Bundle evidence ref {evidence_ref} has no collected evidence item."),
                ));
            }
        }

        let serialized = serde_json::to_string(&(finding, bundle, evidence))?;
        if contains_private_marker(&serialized) {
            issues.push(issue(
                FindingQualityIssueKind::PrivateContentMarker,
                "Finding quality rejected private-content markers.",
            ));
        }

        let independent_source_count = independent_source_count(evidence);
        if high_confidence_requires_independent_sources
            && bundle.confidence.value() >= 0.75
            && independent_source_count < 2
        {
            issues.push(issue(
                FindingQualityIssueKind::HighConfidenceWithoutIndependentSources,
                "High confidence requires multiple independent evidence sources.",
            ));
        }

        Ok(FindingQualityReport {
            passed: issues.is_empty(),
            evidence_count: evidence.len(),
            independent_source_count,
            confidence: bundle.confidence.clone(),
            severity: bundle.severity.clone(),
            issues,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingLifecycleAction {
    MarkNew,
    MarkUpdated,
    Suppress,
    Escalate,
    Expire,
    Dismiss,
    Promote,
}

impl FindingLifecycleAction {
    fn target_state(&self) -> FindingState {
        match self {
            Self::MarkNew => FindingState::New,
            Self::MarkUpdated => FindingState::Updated,
            Self::Suppress => FindingState::Suppressed,
            Self::Escalate => FindingState::Escalated,
            Self::Expire => FindingState::Expired,
            Self::Dismiss => FindingState::Dismissed,
            Self::Promote => FindingState::Promoted,
        }
    }

    fn reason_code(&self) -> &'static str {
        match self {
            Self::MarkNew => "finding_new",
            Self::MarkUpdated => "finding_updated",
            Self::Suppress => "finding_suppressed",
            Self::Escalate => "finding_escalated",
            Self::Expire => "finding_expired",
            Self::Dismiss => "finding_dismissed",
            Self::Promote => "finding_promoted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FindingLifecycleTransition {
    pub finding_id: FindingId,
    pub previous_state: FindingState,
    pub new_state: FindingState,
    pub action: FindingLifecycleAction,
    pub actor_redacted: String,
    pub reason_redacted: String,
    pub timestamp: Timestamp,
    pub trace_id: Option<TraceId>,
    pub audit_event: AuditEvent,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FindingLifecycleResult {
    pub finding: Finding,
    pub transition: FindingLifecycleTransition,
    pub audit_receipt: Option<AuditReceipt>,
}

#[derive(Clone, Debug, Default)]
pub struct FindingLifecycleManager;

impl FindingLifecycleManager {
    pub fn new() -> Self {
        Self
    }

    pub fn transition(
        &self,
        finding: Finding,
        action: FindingLifecycleAction,
        actor_redacted: impl Into<String>,
        reason_redacted: impl Into<String>,
        trace_id: Option<TraceId>,
    ) -> Result<FindingLifecycleResult, EvidenceManagementError> {
        self.transition_inner(
            finding,
            action,
            actor_redacted,
            reason_redacted,
            trace_id,
            None,
        )
    }

    pub fn transition_with_audit(
        &self,
        finding: Finding,
        action: FindingLifecycleAction,
        actor_redacted: impl Into<String>,
        reason_redacted: impl Into<String>,
        trace_id: Option<TraceId>,
        audit_sink: &mut dyn AuditSink,
    ) -> Result<FindingLifecycleResult, EvidenceManagementError> {
        self.transition_inner(
            finding,
            action,
            actor_redacted,
            reason_redacted,
            trace_id,
            Some(audit_sink),
        )
    }

    fn transition_inner(
        &self,
        finding: Finding,
        action: FindingLifecycleAction,
        actor_redacted: impl Into<String>,
        reason_redacted: impl Into<String>,
        trace_id: Option<TraceId>,
        audit_sink: Option<&mut dyn AuditSink>,
    ) -> Result<FindingLifecycleResult, EvidenceManagementError> {
        let actor_redacted = require_safe_text("actor_redacted", actor_redacted.into())?;
        let reason_redacted = require_safe_text("reason_redacted", reason_redacted.into())?;
        let previous_state = finding.state().clone();
        let new_state = action.target_state();
        let finding_id = finding.id().clone();
        let finding = finding.with_state(new_state.clone());
        let mut audit_event = AuditEvent::new(
            AuditCategory::SecurityCase,
            AuditActionType::Custom("finding_lifecycle_changed".to_string()),
            actor_redacted.clone(),
            format!("finding:{finding_id}"),
            AuditDecision::Completed,
            reason_redacted.clone(),
        )?;
        audit_event.trace_id = trace_id.clone();
        audit_event
            .reason_codes
            .push(action.reason_code().to_string());
        audit_event.validate()?;

        let audit_receipt = match audit_sink {
            Some(sink) => Some(sink.append(audit_event.clone())?),
            None => None,
        };

        Ok(FindingLifecycleResult {
            finding,
            transition: FindingLifecycleTransition {
                finding_id,
                previous_state,
                new_state,
                action,
                actor_redacted,
                reason_redacted,
                timestamp: Timestamp::now(),
                trace_id,
                audit_event,
            },
            audit_receipt,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceManagementInput {
    pub finding_type: String,
    pub producer_plugin: PluginId,
    pub entity_refs: Vec<EntityRef>,
    pub evidence_collection: EvidenceCollectionInput,
    pub high_confidence_requires_independent_sources: bool,
    pub trace_id: Option<TraceId>,
    pub labels: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceManagementOutput {
    pub finding: Finding,
    pub bundle: EvidenceBundle,
    pub evidence: Vec<CollectedEvidence>,
    pub deduplication_report: EvidenceDeduplicationReport,
    pub quality_report: FindingQualityReport,
    pub lifecycle: FindingLifecycleTransition,
    pub attack_mappings: Vec<AttackMapping>,
}

#[derive(Clone, Debug, Default)]
pub struct EvidenceManagementPlugin {
    collector: EvidenceCollector,
    deduplicator: EvidenceDeduplicator,
    bundle_builder: EvidenceBundleBuilder,
    quality_validator: FindingQualityValidator,
    lifecycle_manager: FindingLifecycleManager,
}

impl EvidenceManagementPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn manage(
        &self,
        mut input: EvidenceManagementInput,
    ) -> Result<EvidenceManagementOutput, EvidenceManagementError> {
        validate_finding_type(&input.finding_type)?;
        input.evidence_collection.producer_plugin = Some(input.producer_plugin.clone());

        let collected = self.collector.collect(input.evidence_collection)?;
        let deduplicated = self.deduplicator.deduplicate(collected)?;
        let bundle_result = self.bundle_builder.build(EvidenceBundleRequest {
            finding_type: input.finding_type.clone(),
            producer_plugin: input.producer_plugin.clone(),
            entity_refs: input.entity_refs.clone(),
            evidence: deduplicated.evidence.clone(),
            high_confidence_requires_independent_sources: input
                .high_confidence_requires_independent_sources,
        })?;
        let mut bundle = bundle_result.bundle;
        let risk_reasons = bundle.explanation.risk_reasons.clone();
        let evidence_refs = bundle.evidence_refs.clone();
        let mut finding = Finding::new(
            input.finding_type,
            input.producer_plugin,
            evidence_refs,
            bundle.explanation.clone(),
        )?
        .with_entity_refs(input.entity_refs)
        .with_confidence(bundle.confidence.clone())
        .with_severity(bundle.severity.clone())
        .with_risk_reasons(risk_reasons)
        .with_attack_mappings(bundle_result.attack_mappings.clone());
        if let Some(trace_id) = input.trace_id.clone() {
            finding = finding.with_trace_id(trace_id);
        }
        bundle.finding_id = Some(finding.id().clone());

        let quality_report = self.quality_validator.validate(
            &finding,
            &bundle,
            &deduplicated.evidence,
            input.high_confidence_requires_independent_sources,
        )?;
        if !quality_report.passed {
            return Err(first_quality_error(&quality_report));
        }

        let lifecycle_result = self.lifecycle_manager.transition(
            finding,
            FindingLifecycleAction::MarkNew,
            "evidence_management",
            "Evidence-backed finding created.",
            input.trace_id,
        )?;

        Ok(EvidenceManagementOutput {
            finding: lifecycle_result.finding,
            bundle,
            evidence: deduplicated.evidence,
            deduplication_report: deduplicated.report,
            quality_report,
            lifecycle: lifecycle_result.transition,
            attack_mappings: bundle_result.attack_mappings,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceStoreWriteSummary {
    pub evidence_records: usize,
    pub finding_records: usize,
}

#[derive(Clone, Debug, Default)]
pub struct EvidenceManagementStoreWriter;

impl EvidenceManagementStoreWriter {
    pub fn new() -> Self {
        Self
    }

    pub fn write_output(
        &self,
        stores: &SqliteStoreFactory<'_>,
        output: &EvidenceManagementOutput,
    ) -> Result<EvidenceStoreWriteSummary, EvidenceManagementError> {
        let mut summary = EvidenceStoreWriteSummary::default();

        for evidence in &output.evidence {
            write_record(
                &stores.evidence_store(),
                evidence.evidence.evidence_id.clone(),
                StoreKind::Evidence,
                evidence_metadata("evidence_item", evidence, &[])?,
                evidence.evidence.entity_refs.clone(),
            )?;
            summary.evidence_records += 1;
        }

        write_record(
            &stores.finding_store(),
            output.finding.id().clone(),
            StoreKind::Finding,
            evidence_metadata(
                "managed_finding",
                &json!({
                    "finding": output.finding,
                    "bundle": output.bundle,
                    "quality_report": output.quality_report,
                    "deduplication_report": output.deduplication_report,
                    "lifecycle": output.lifecycle,
                    "attack_mappings": output.attack_mappings
                }),
                &[],
            )?,
            output.finding.entity_refs().to_vec(),
        )?;
        summary.finding_records += 1;

        Ok(summary)
    }
}

fn write_record<TId>(
    store: &impl LogicalStore<TId>,
    id: TId,
    store_kind: StoreKind,
    metadata: Value,
    entity_refs: Vec<EntityRef>,
) -> Result<(), EvidenceManagementError>
where
    TId: Clone + fmt::Display + Serialize + serde::de::DeserializeOwned,
{
    let record = LogicalRecord::metadata_only(
        id,
        EVIDENCE_MANAGEMENT_SCHEMA_VERSION,
        store_kind.default_storage_privacy_class(),
        metadata,
    )
    .with_entity_refs(entity_refs);
    store.append(record)?;
    Ok(())
}

fn evidence_metadata<T: Serialize>(
    record_kind: &str,
    record: &T,
    labels: &[String],
) -> Result<Value, EvidenceManagementError> {
    Ok(json!({
        "record_kind": record_kind,
        "labels": labels,
        "record": serde_json::to_value(record)?
    }))
}

fn total_weight(evidence: &[CollectedEvidence]) -> Result<QualityScore, EvidenceManagementError> {
    let sum = evidence
        .iter()
        .map(|item| item.evidence.weight.value())
        .sum::<f32>();
    quality_score((sum / 2.5).min(1.0))
}

fn risk_hint_weight(risk_delta: f32) -> Result<QualityScore, EvidenceManagementError> {
    quality_score(risk_delta.abs().clamp(0.35, 0.85))
}

fn source_weight(source_class: &EvidenceSourceClass) -> QualityScore {
    let value = match source_class {
        EvidenceSourceClass::Network => 0.58,
        EvidenceSourceClass::Dns => 0.62,
        EvidenceSourceClass::Tls => 0.62,
        EvidenceSourceClass::Http => 0.56,
        EvidenceSourceClass::Process => 0.64,
        EvidenceSourceClass::Asset => 0.6,
        EvidenceSourceClass::Intelligence => 0.55,
        EvidenceSourceClass::Graph => 0.5,
        EvidenceSourceClass::Manual => 0.45,
        EvidenceSourceClass::Unknown => 0.35,
    };
    QualityScore::new(value).expect("static source weights are in range")
}

fn quality_score(value: f32) -> Result<QualityScore, EvidenceManagementError> {
    QualityScore::new(value).map_err(|_| EvidenceManagementError::InvalidQualityScore)
}

fn independent_source_count(evidence: &[CollectedEvidence]) -> usize {
    let mut sources = BTreeMap::<String, ()>::new();
    for item in evidence {
        sources.insert(item.independence_key.clone(), ());
    }
    sources.len()
}

fn has_collected_evidence_ref(
    evidence: &[CollectedEvidence],
    evidence_ref: &sentinel_contracts::EvidenceId,
) -> bool {
    evidence
        .iter()
        .any(|item| item.evidence.evidence_id == *evidence_ref)
}

fn independence_key(source_class: &EvidenceSourceClass, evidence: &EvidenceItem) -> String {
    let plugin = evidence
        .source_plugin
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "no_plugin".to_string());
    format!(
        "{}:{plugin}:{}",
        source_class.as_str(),
        evidence.evidence_type
    )
}

fn dedupe_key(item: &CollectedEvidence) -> String {
    let mut events = item
        .evidence
        .source_event_refs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    events.sort();
    let mut entities = item
        .evidence
        .entity_refs
        .iter()
        .map(|entity| entity.entity_id.to_string())
        .collect::<Vec<_>>();
    entities.sort();
    format!(
        "{}|{}|{}|{}|{}",
        item.source_class.as_str(),
        item.evidence.evidence_type,
        item.evidence.value_summary_redacted,
        events.join(","),
        entities.join(",")
    )
}

fn classify_observation(observation: &SecurityObservation) -> EvidenceSourceClass {
    classify_evidence_type(&observation.observation_type)
}

fn classify_evidence_type(value: &str) -> EvidenceSourceClass {
    let value = value.to_ascii_lowercase();
    if value.contains("dns") {
        EvidenceSourceClass::Dns
    } else if value.contains("tls") {
        EvidenceSourceClass::Tls
    } else if value.contains("http") {
        EvidenceSourceClass::Http
    } else if value.contains("process") {
        EvidenceSourceClass::Process
    } else if value.contains("asset") || value.contains("service") {
        EvidenceSourceClass::Asset
    } else if value.contains("network") || value.contains("flow") || value.contains("session") {
        EvidenceSourceClass::Network
    } else {
        EvidenceSourceClass::Unknown
    }
}

fn graph_hint_label(hint_type: &GraphHintType) -> String {
    match hint_type {
        GraphHintType::ProcessConnectsToIp => "process_connects_to_ip".to_string(),
        GraphHintType::ProcessQueriesDomain => "process_queries_domain".to_string(),
        GraphHintType::DomainResolvesToIp => "domain_resolves_to_ip".to_string(),
        GraphHintType::IpBelongsToAsn => "ip_belongs_to_asn".to_string(),
        GraphHintType::IpBelongsToCloudProvider => "ip_belongs_to_cloud_provider".to_string(),
        GraphHintType::ProcessUsesTlsFingerprint => "process_uses_tls_fingerprint".to_string(),
        GraphHintType::ProcessUploadsToCloud => "process_uploads_to_cloud".to_string(),
        GraphHintType::ObservationSupportsFinding => "observation_supports_finding".to_string(),
        GraphHintType::FindingSupportsAlert => "finding_supports_alert".to_string(),
        GraphHintType::AlertPartOfIncident => "alert_part_of_incident".to_string(),
        GraphHintType::IncidentRecommendsResponse => "incident_recommends_response".to_string(),
        GraphHintType::ResponseActionTargetsEntity => "response_action_targets_entity".to_string(),
        GraphHintType::Custom(value) => value.clone(),
    }
}

fn entity_label(entity: &EntityRef) -> String {
    entity
        .entity_name
        .clone()
        .unwrap_or_else(|| format!("{:?}", entity.entity_type))
}

fn issue(
    kind: FindingQualityIssueKind,
    summary_redacted: impl Into<String>,
) -> FindingQualityIssue {
    FindingQualityIssue {
        kind,
        summary_redacted: summary_redacted.into(),
    }
}

fn first_quality_error(report: &FindingQualityReport) -> EvidenceManagementError {
    if report.issues.iter().any(|issue| {
        matches!(
            issue.kind,
            FindingQualityIssueKind::HighConfidenceWithoutIndependentSources
        )
    }) {
        EvidenceManagementError::HighConfidenceRequiresIndependentSources
    } else if let Some(issue) = report
        .issues
        .iter()
        .find(|issue| matches!(issue.kind, FindingQualityIssueKind::MissingEvidenceRef))
    {
        EvidenceManagementError::MissingEvidenceRef(issue.summary_redacted.clone())
    } else {
        EvidenceManagementError::EmptyEvidence
    }
}

fn validate_finding_type(value: &str) -> Result<(), EvidenceManagementError> {
    if value.trim().is_empty() {
        return Err(EvidenceManagementError::EmptyFindingType);
    }
    validate_safe_text("finding_type", value)
}

fn validate_evidence_item(evidence: &EvidenceItem) -> Result<(), EvidenceManagementError> {
    validate_safe_text("evidence_type", &evidence.evidence_type)?;
    validate_safe_text("value_summary_redacted", &evidence.value_summary_redacted)?;
    if let Some(description) = &evidence.description_redacted {
        validate_safe_text("description_redacted", description)?;
    }
    Ok(())
}

fn require_safe_text(
    field: &'static str,
    value: String,
) -> Result<String, EvidenceManagementError> {
    if value.trim().is_empty() {
        return Err(EvidenceManagementError::EmptyFindingType);
    }
    validate_safe_text(field, &value)?;
    Ok(value)
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), EvidenceManagementError> {
    if contains_private_marker(value) {
        Err(EvidenceManagementError::PrivacyMarker { field })
    } else {
        Ok(())
    }
}

fn contains_private_marker(value: &str) -> bool {
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '/', '=', ':', '?'], "_");
    [
        "raw_packet",
        "packet_bytes",
        "raw_payload",
        "payload",
        "http_body",
        "request_body",
        "response_body",
        "authorization",
        "authorization_header",
        "api_key",
        "cookie",
        "credential",
        "password",
        "private_key",
        "session_token",
        "access_token",
        "refresh_token",
        "token",
        "secret",
        "form_content",
        "query_string",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use sentinel_contracts::{
        EntityId, EntityType, EventId, EvidenceId, IntelligenceRecordId, PageRequest, QueryRequest,
        QueryScope,
    };
    use sentinel_platform::InMemoryAuditSink;
    use sentinel_storage::{
        logical_store_migration, InMemoryMigrationAuditSink, MigrationRunner, SchemaMetadata,
    };

    fn entity() -> EntityRef {
        let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Process);
        entity.entity_name = Some("fixture_process".to_string());
        entity
    }

    fn observation(observation_type: &str, summary: &str, confidence: f32) -> SecurityObservation {
        let mut observation =
            SecurityObservation::new(observation_type, summary).expect("observation");
        observation.entity_refs = vec![entity()];
        observation.confidence = QualityScore::new(confidence).expect("confidence");
        observation.producer_plugin = Some(PluginId::new_v4());
        observation.source_event_refs = vec![EventId::new_v4()];
        observation
    }

    fn evidence_item(
        evidence_type: &str,
        summary: &str,
        weight: f32,
        confidence: f32,
    ) -> EvidenceItem {
        let mut evidence = EvidenceItem::new(evidence_type, summary).expect("evidence");
        evidence.entity_refs = vec![entity()];
        evidence.weight = QualityScore::new(weight).expect("weight");
        evidence.confidence = QualityScore::new(confidence).expect("confidence");
        evidence.source_plugin = Some(PluginId::new_v4());
        evidence
    }

    #[test]
    fn evidence_collector_deduplicates_observation_evidence() {
        let observation = observation("security.observation.dns", "rare domain observed", 0.8);
        let collected = EvidenceCollector::new()
            .collect(EvidenceCollectionInput {
                observations: vec![observation.clone(), observation],
                ..EvidenceCollectionInput::default()
            })
            .expect("collected");
        let output = EvidenceDeduplicator::new()
            .deduplicate(collected)
            .expect("deduped");

        assert_eq!(output.report.retained_count, 1);
        assert_eq!(output.report.removed_duplicate_count, 1);
    }

    #[test]
    fn high_confidence_requires_multiple_independent_sources() {
        let plugin_id = PluginId::new_v4();
        let mut first = evidence_item("dns.rare_domain", "rare domain observed", 0.9, 0.95);
        first.source_plugin = Some(plugin_id.clone());
        let mut second = evidence_item("dns.rare_domain", "rare domain observed again", 0.9, 0.95);
        second.source_plugin = Some(plugin_id);
        let evidence = vec![
            CollectedEvidence::from_item(first, EvidenceSourceClass::Dns, "dns:first")
                .expect("first"),
            CollectedEvidence::from_item(second, EvidenceSourceClass::Dns, "dns:second")
                .expect("second"),
        ];

        let report = ConfidenceCalculator::new()
            .calculate(&evidence, true)
            .expect("confidence");

        assert_eq!(report.independent_source_count, 1);
        assert!(!report.high_confidence_allowed);
        assert!(report.confidence.value() < 0.75);
        assert!(report.capped_reason.is_some());
    }

    #[test]
    fn evidence_bundle_includes_confidence_severity_explanation_and_refs() {
        let evidence = vec![
            CollectedEvidence::from_item(
                evidence_item("dns.rare_domain", "rare domain observed", 0.8, 0.82),
                EvidenceSourceClass::Dns,
                "dns:rare",
            )
            .expect("dns"),
            CollectedEvidence::from_item(
                evidence_item(
                    "tls.rare_fingerprint",
                    "rare TLS fingerprint observed",
                    0.8,
                    0.84,
                ),
                EvidenceSourceClass::Tls,
                "tls:rare",
            )
            .expect("tls"),
        ];
        let result = EvidenceBundleBuilder::new()
            .build(EvidenceBundleRequest {
                finding_type: "security.finding.c2".to_string(),
                producer_plugin: PluginId::new_v4(),
                entity_refs: vec![entity()],
                evidence,
                high_confidence_requires_independent_sources: true,
            })
            .expect("bundle");

        assert_eq!(result.bundle.evidence_refs.len(), 2);
        assert!(result.bundle.confidence.value() >= 0.75);
        assert!(matches!(
            result.bundle.severity,
            SecuritySeverity::Medium | SecuritySeverity::High | SecuritySeverity::Critical
        ));
        assert!(!result.bundle.explanation.risk_reasons.is_empty());
        assert!(!result.attack_mappings.is_empty());
    }

    #[test]
    fn findings_cannot_pass_quality_validation_without_evidence_item() {
        let evidence_ref = EvidenceId::new_v4();
        let explanation = FindingExplanation::new("fixture finding").expect("explanation");
        let finding = Finding::new(
            "security.finding.c2",
            PluginId::new_v4(),
            vec![evidence_ref.clone()],
            explanation.clone(),
        )
        .expect("finding");
        let mut bundle = EvidenceBundle::new(vec![evidence_ref], explanation).expect("bundle");
        bundle.confidence = QualityScore::new(0.8).expect("confidence");
        bundle.severity = SecuritySeverity::High;
        let report = FindingQualityValidator::new()
            .validate(&finding, &bundle, &[], true)
            .expect("quality report");

        assert!(!report.passed);
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.kind == FindingQualityIssueKind::MissingEvidence));
    }

    #[test]
    fn quality_validation_rejects_bundle_refs_without_collected_evidence() {
        let collected = CollectedEvidence::from_item(
            evidence_item("dns.rare_domain", "rare domain observed", 0.8, 0.82),
            EvidenceSourceClass::Dns,
            "dns:rare",
        )
        .expect("collected evidence");
        let missing_ref = EvidenceId::new_v4();
        let explanation = FindingExplanation::new("fixture finding").expect("explanation");
        let finding = Finding::new(
            "security.finding.c2",
            PluginId::new_v4(),
            vec![collected.evidence.evidence_id.clone()],
            explanation.clone(),
        )
        .expect("finding");
        let mut bundle = EvidenceBundle::new(
            vec![collected.evidence.evidence_id.clone(), missing_ref],
            explanation,
        )
        .expect("bundle");
        bundle.confidence = QualityScore::new(0.72).expect("confidence");
        bundle.severity = SecuritySeverity::Medium;

        let report = FindingQualityValidator::new()
            .validate(&finding, &bundle, &[collected], true)
            .expect("quality report");

        assert!(!report.passed);
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.kind == FindingQualityIssueKind::MissingEvidenceRef));
    }

    #[test]
    fn lifecycle_updates_are_traceable_and_auditable() {
        let evidence = evidence_item("dns.rare_domain", "rare domain observed", 0.8, 0.82);
        let explanation = FindingExplanation::new("fixture finding").expect("explanation");
        let finding = Finding::new(
            "security.finding.c2",
            PluginId::new_v4(),
            vec![evidence.evidence_id],
            explanation,
        )
        .expect("finding");
        let mut audit_sink = InMemoryAuditSink::new();
        let result = FindingLifecycleManager::new()
            .transition_with_audit(
                finding,
                FindingLifecycleAction::Escalate,
                "unit_test",
                "Escalated for risk aggregation.",
                Some(TraceId::new_v4()),
                &mut audit_sink,
            )
            .expect("transition");

        assert_eq!(result.finding.state(), &FindingState::Escalated);
        assert!(result.audit_receipt.is_some());
        assert_eq!(audit_sink.records().len(), 1);
        assert_eq!(
            audit_sink.records()[0].category,
            AuditCategory::SecurityCase
        );
    }

    #[test]
    fn evidence_management_plugin_returns_valid_finding_bundle_and_mapping() {
        let output = EvidenceManagementPlugin::new()
            .manage(EvidenceManagementInput {
                finding_type: "security.finding.c2".to_string(),
                producer_plugin: PluginId::new_v4(),
                entity_refs: vec![entity()],
                evidence_collection: EvidenceCollectionInput {
                    observations: vec![observation(
                        "security.observation.dns",
                        "rare domain observed",
                        0.8,
                    )],
                    evidence_items: vec![evidence_item(
                        "tls.rare_fingerprint",
                        "rare TLS fingerprint observed",
                        0.8,
                        0.84,
                    )],
                    ..EvidenceCollectionInput::default()
                },
                high_confidence_requires_independent_sources: true,
                trace_id: Some(TraceId::new_v4()),
                labels: vec!["FIXTURE_ONLY".to_string()],
            })
            .expect("managed finding");

        assert!(output.quality_report.passed);
        assert_eq!(output.bundle.finding_id.as_ref(), Some(output.finding.id()));
        assert!(output.finding.confidence().value() >= 0.75);
        assert!(!output.finding.attack_mappings().is_empty());
        assert_eq!(output.finding.state(), &FindingState::New);
        assert_eq!(output.lifecycle.new_state, FindingState::New);
    }

    #[test]
    fn evidence_management_accepts_risk_and_graph_inputs_without_promotion() {
        let risk_hint = RiskHint::new(
            "domain_reputation_hint",
            "local intelligence risk context",
            vec![IntelligenceRecordId::new_v4()],
        )
        .expect("risk hint")
        .with_risk_delta(0.7)
        .with_confidence(QualityScore::new(0.8).expect("confidence"));
        let graph_hint = GraphHint::new(
            GraphHintType::ProcessQueriesDomain,
            entity(),
            entity(),
            PluginId::new_v4(),
        );

        let output = EvidenceManagementPlugin::new()
            .manage(EvidenceManagementInput {
                finding_type: "security.finding.c2".to_string(),
                producer_plugin: PluginId::new_v4(),
                entity_refs: vec![entity()],
                evidence_collection: EvidenceCollectionInput {
                    risk_hints: vec![risk_hint],
                    graph_hints: vec![graph_hint],
                    ..EvidenceCollectionInput::default()
                },
                high_confidence_requires_independent_sources: true,
                trace_id: None,
                labels: Vec::new(),
            })
            .expect("managed finding");

        assert_eq!(output.evidence.len(), 2);
        assert!(output.quality_report.passed);
        assert!(output
            .evidence
            .iter()
            .any(|item| item.source_class == EvidenceSourceClass::Intelligence));
        assert!(output
            .evidence
            .iter()
            .any(|item| item.source_class == EvidenceSourceClass::Graph));
    }

    #[test]
    fn evidence_store_writer_persists_metadata_only_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let output = EvidenceManagementPlugin::new().manage(EvidenceManagementInput {
            finding_type: "security.finding.c2".to_string(),
            producer_plugin: PluginId::new_v4(),
            entity_refs: vec![entity()],
            evidence_collection: EvidenceCollectionInput {
                observations: vec![observation(
                    "security.observation.dns",
                    "rare domain observed",
                    0.8,
                )],
                evidence_items: vec![evidence_item(
                    "tls.rare_fingerprint",
                    "rare TLS fingerprint observed",
                    0.8,
                    0.84,
                )],
                ..EvidenceCollectionInput::default()
            },
            high_confidence_requires_independent_sources: true,
            trace_id: None,
            labels: Vec::new(),
        })?;
        let summary = EvidenceManagementStoreWriter::new().write_output(&stores, &output)?;

        assert_eq!(summary.evidence_records, 2);
        assert_eq!(summary.finding_records, 1);
        assert_eq!(stores.evidence_store().create_snapshot()?.record_count, 2);
        assert_eq!(stores.finding_store().create_snapshot()?.record_count, 1);

        let queried = stores
            .finding_store()
            .query(QueryRequest::new(QueryScope::Global).with_page(PageRequest::first(10)?))?;
        let serialized = serde_json::to_string(&queried)?;
        assert!(serialized.contains("\"record_kind\":\"managed_finding\""));
        assert!(!serialized.contains("http_body"));
        assert!(!serialized.contains("api_key"));
        assert!(!serialized.contains("credential"));
        Ok(())
    }

    #[test]
    fn evidence_values_reject_private_content_markers() {
        let evidence = evidence_item(
            "dns.rare_domain",
            "raw_payload marker should fail",
            0.8,
            0.82,
        );

        assert!(matches!(
            CollectedEvidence::from_item(evidence, EvidenceSourceClass::Dns, "dns:bad"),
            Err(EvidenceManagementError::PrivacyMarker {
                field: "value_summary_redacted"
            })
        ));
    }

    fn initialized_connection() -> Result<Connection, Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        {
            let mut runner = MigrationRunner::new(&mut connection);
            runner.initialize(&SchemaMetadata::storage_foundation())?;
            let mut audit = InMemoryMigrationAuditSink::default();
            runner.apply_all(&[logical_store_migration()?], &mut audit)?;
        }
        Ok(connection)
    }
}
