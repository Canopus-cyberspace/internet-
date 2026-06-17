use crate::common::{
    AttackHypothesisId, DataSourceId, EvidenceId, FindingId, GraphHintId, PrivacyClass,
    QualityScore, RiskEventId, SecurityFactId, Timestamp,
};
use crate::evidence_quality::QualityBreakdown;
use crate::graph::RedactionStatus;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_FUSION_ITEMS: usize = 128;
pub const MAX_FUSION_REFS: usize = 64;
pub const MAX_FUSION_LABELS: usize = 32;
const MAX_SAFE_TEXT_BYTES: usize = 160;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FusionContractError {
    EmptyField(&'static str),
    UnsafeField(&'static str),
    ExceedsBound(&'static str),
    UnsafeClaim(&'static str),
}

impl fmt::Display for FusionContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains unsafe metadata"),
            Self::ExceedsBound(field) => write!(formatter, "{field} exceeds bounded limits"),
            Self::UnsafeClaim(reason) => write!(formatter, "unsafe fusion claim: {reason}"),
        }
    }
}

impl std::error::Error for FusionContractError {}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLayer {
    Dns,
    CdnEdge,
    Waf,
    Api,
    Http,
    AuthIdentity,
    SaasCloud,
    Deception,
    LocalMetadataProxy,
    SdnControlPlane,
    SdnPlaceholder,
    AuthorizedNativeHostPlaceholder,
    AuthorizedNativeHealth,
    AuthorizedNativeService,
    AuthorizedNativeProcess,
    AuthorizedNativeNetwork,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamplerState {
    Enabled,
    Disabled,
    Degraded,
    Unavailable,
    NotAuthorized,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamplingMode {
    ConfirmedImport,
    ExplicitDrain,
    Periodic,
    Placeholder,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FusionConfidenceBucket {
    Unknown,
    Low,
    Medium,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayeredSamplerDeclaration {
    pub sampler_id: String,
    pub layer: SecurityLayer,
    pub source_kind: String,
    pub state: SamplerState,
    pub sampling_mode: SamplingMode,
    pub interval_seconds: Option<u32>,
    pub record_limit: u32,
    pub byte_limit: u32,
    pub checkpoint_state: String,
    pub health_reason: Option<String>,
    pub output_fact_categories: Vec<String>,
    pub event_bus_topics: Vec<String>,
    pub privacy_boundary: String,
    pub visibility_requirements: Vec<String>,
    pub portable_default_available: bool,
}

impl LayeredSamplerDeclaration {
    pub fn validate(&self) -> Result<(), FusionContractError> {
        safe_text("sampler_id", &self.sampler_id)?;
        safe_text("source_kind", &self.source_kind)?;
        safe_text("checkpoint_state", &self.checkpoint_state)?;
        safe_text("privacy_boundary", &self.privacy_boundary)?;
        if let Some(reason) = &self.health_reason {
            safe_text("health_reason", reason)?;
        }
        validate_labels("output_fact_categories", &self.output_fact_categories)?;
        validate_labels("event_bus_topics", &self.event_bus_topics)?;
        validate_labels("visibility_requirements", &self.visibility_requirements)?;
        if self.record_limit == 0 || self.byte_limit == 0 {
            return Err(FusionContractError::UnsafeClaim(
                "samplers must declare non-zero bounded limits",
            ));
        }
        if matches!(
            self.layer,
            SecurityLayer::SdnPlaceholder | SecurityLayer::AuthorizedNativeHostPlaceholder
        ) && (self.portable_default_available || self.state == SamplerState::Enabled)
        {
            return Err(FusionContractError::UnsafeClaim(
                "native and SDN placeholders cannot be enabled in Portable Default",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecurityFact {
    pub fact_id: SecurityFactId,
    pub layer: SecurityLayer,
    pub category: String,
    pub sampler_id: String,
    pub provider_service_category: Option<String>,
    pub domain_category_ref: Option<String>,
    pub route_fingerprint: Option<String>,
    pub method_category: Option<String>,
    pub status_category: Option<String>,
    pub auth_category: Option<String>,
    pub cache_edge_origin_bucket: Option<String>,
    pub protocol_category: Option<String>,
    pub saas_cloud_category: Option<String>,
    pub deception_category: Option<String>,
    pub identity_session_label_redacted: Option<String>,
    pub process_category: Option<String>,
    pub parent_process_category: Option<String>,
    pub relation_category: Option<String>,
    pub execution_context_category: Option<String>,
    pub trust_category: Option<String>,
    pub signedness_bucket: Option<String>,
    pub privilege_context_category: Option<String>,
    pub lifecycle_bucket: Option<String>,
    pub count_bucket: Option<String>,
    pub time_bucket: Timestamp,
    pub confidence_hint: QualityScore,
    pub evidence_refs: Vec<EvidenceId>,
    pub provenance_id: Option<DataSourceId>,
    pub redaction_status: RedactionStatus,
    pub missing_visibility_flags: Vec<String>,
    pub degraded_reason: Option<String>,
}

impl SecurityFact {
    pub fn new(
        layer: SecurityLayer,
        category: impl Into<String>,
        sampler_id: impl Into<String>,
        time_bucket: Timestamp,
    ) -> Result<Self, FusionContractError> {
        let fact = Self {
            fact_id: SecurityFactId::new_v4(),
            layer,
            category: category.into(),
            sampler_id: sampler_id.into(),
            provider_service_category: None,
            domain_category_ref: None,
            route_fingerprint: None,
            method_category: None,
            status_category: None,
            auth_category: None,
            cache_edge_origin_bucket: None,
            protocol_category: None,
            saas_cloud_category: None,
            deception_category: None,
            identity_session_label_redacted: None,
            process_category: None,
            parent_process_category: None,
            relation_category: None,
            execution_context_category: None,
            trust_category: None,
            signedness_bucket: None,
            privilege_context_category: None,
            lifecycle_bucket: None,
            count_bucket: None,
            time_bucket,
            confidence_hint: QualityScore::default(),
            evidence_refs: Vec::new(),
            provenance_id: None,
            redaction_status: RedactionStatus::Redacted,
            missing_visibility_flags: vec!["metadata_only_visibility".to_string()],
            degraded_reason: Some("metadata_only_visibility".to_string()),
        };
        fact.validate()?;
        Ok(fact)
    }

    pub fn validate(&self) -> Result<(), FusionContractError> {
        safe_text("category", &self.category)?;
        safe_text("sampler_id", &self.sampler_id)?;
        for value in [
            self.provider_service_category.as_ref(),
            self.domain_category_ref.as_ref(),
            self.route_fingerprint.as_ref(),
            self.method_category.as_ref(),
            self.status_category.as_ref(),
            self.auth_category.as_ref(),
            self.cache_edge_origin_bucket.as_ref(),
            self.protocol_category.as_ref(),
            self.saas_cloud_category.as_ref(),
            self.deception_category.as_ref(),
            self.identity_session_label_redacted.as_ref(),
            self.process_category.as_ref(),
            self.parent_process_category.as_ref(),
            self.relation_category.as_ref(),
            self.execution_context_category.as_ref(),
            self.trust_category.as_ref(),
            self.signedness_bucket.as_ref(),
            self.privilege_context_category.as_ref(),
            self.lifecycle_bucket.as_ref(),
            self.count_bucket.as_ref(),
            self.degraded_reason.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            safe_text("fact metadata", value)?;
        }
        validate_labels("missing_visibility_flags", &self.missing_visibility_flags)?;
        if self.evidence_refs.len() > MAX_FUSION_REFS {
            return Err(FusionContractError::ExceedsBound("evidence_refs"));
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(FusionContractError::UnsafeClaim(
                "unredacted facts cannot enter fusion",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HypothesisFactRequirement {
    pub layer: SecurityLayer,
    pub categories: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttackHypothesisDefinition {
    pub hypothesis_id: String,
    pub version: String,
    pub category: String,
    pub required_facts: Vec<HypothesisFactRequirement>,
    pub optional_facts: Vec<HypothesisFactRequirement>,
    pub disqualifier_categories: Vec<String>,
    pub minimum_evidence: u32,
    pub confidence_cap: FusionConfidenceBucket,
    pub confidence_formula: String,
    pub degradation_rules: Vec<String>,
    pub missing_visibility_flags: Vec<String>,
    pub attack_candidates: Vec<FusionAttackCandidate>,
    pub report_template: String,
    pub safety_notes: Vec<String>,
}

impl AttackHypothesisDefinition {
    pub fn validate(&self) -> Result<(), FusionContractError> {
        safe_text("hypothesis_id", &self.hypothesis_id)?;
        safe_text("version", &self.version)?;
        safe_text("category", &self.category)?;
        safe_text("confidence_formula", &self.confidence_formula)?;
        safe_text("report_template", &self.report_template)?;
        if self.required_facts.is_empty() || self.minimum_evidence == 0 {
            return Err(FusionContractError::UnsafeClaim(
                "hypotheses require facts and evidence",
            ));
        }
        if self.required_facts.len() + self.optional_facts.len() > MAX_FUSION_LABELS {
            return Err(FusionContractError::ExceedsBound("fact requirements"));
        }
        for requirement in self.required_facts.iter().chain(self.optional_facts.iter()) {
            validate_labels("requirement categories", &requirement.categories)?;
        }
        validate_labels("disqualifier_categories", &self.disqualifier_categories)?;
        validate_labels("degradation_rules", &self.degradation_rules)?;
        validate_labels("missing_visibility_flags", &self.missing_visibility_flags)?;
        validate_labels("safety_notes", &self.safety_notes)?;
        for candidate in &self.attack_candidates {
            candidate.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionAttackCandidate {
    pub tactic_id: String,
    pub technique_id: String,
    pub attack_version: String,
    pub confidence: FusionConfidenceBucket,
    pub required_visibility: String,
}

impl FusionAttackCandidate {
    pub fn validate(&self) -> Result<(), FusionContractError> {
        safe_text("tactic_id", &self.tactic_id)?;
        safe_text("technique_id", &self.technique_id)?;
        safe_text("attack_version", &self.attack_version)?;
        safe_text("required_visibility", &self.required_visibility)?;
        if self.confidence == FusionConfidenceBucket::Medium
            && matches!(
                self.tactic_id.as_str(),
                "TA0002" | "TA0003" | "TA0004" | "TA0006"
            )
        {
            return Err(FusionContractError::UnsafeClaim(
                "restricted ATT&CK tactics require low metadata-only confidence",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttackHypothesisRecord {
    pub hypothesis_record_id: AttackHypothesisId,
    pub definition_id: String,
    pub version: String,
    pub category: String,
    pub fact_refs: Vec<SecurityFactId>,
    pub correlated_layers: Vec<SecurityLayer>,
    pub correlation_count: u32,
    pub confidence_bucket: FusionConfidenceBucket,
    pub degraded_reason: Option<String>,
    pub missing_visibility_flags: Vec<String>,
    pub evidence_refs: Vec<EvidenceId>,
    pub finding_refs: Vec<FindingId>,
    pub risk_refs: Vec<RiskEventId>,
    pub graph_hint_refs: Vec<GraphHintId>,
    pub attack_candidates: Vec<FusionAttackCandidate>,
    pub negative_evidence_notes: Vec<String>,
    pub benign_baseline_indicators: Vec<String>,
    pub optional_llm_story_marker: bool,
    pub quality: QualityBreakdown,
    pub created_at: Timestamp,
}

impl AttackHypothesisRecord {
    pub fn validate(&self) -> Result<(), FusionContractError> {
        safe_text("definition_id", &self.definition_id)?;
        safe_text("version", &self.version)?;
        safe_text("category", &self.category)?;
        if self.fact_refs.is_empty() || self.evidence_refs.is_empty() {
            return Err(FusionContractError::UnsafeClaim(
                "hypothesis records must be evidence-backed",
            ));
        }
        if self.fact_refs.len() > MAX_FUSION_REFS
            || self.evidence_refs.len() > MAX_FUSION_REFS
            || self.finding_refs.len() > MAX_FUSION_REFS
            || self.risk_refs.len() > MAX_FUSION_REFS
            || self.graph_hint_refs.len() > MAX_FUSION_REFS
        {
            return Err(FusionContractError::ExceedsBound("hypothesis refs"));
        }
        if let Some(reason) = &self.degraded_reason {
            safe_text("degraded_reason", reason)?;
        }
        validate_labels("missing_visibility_flags", &self.missing_visibility_flags)?;
        validate_labels("negative_evidence_notes", &self.negative_evidence_notes)?;
        validate_labels(
            "benign_baseline_indicators",
            &self.benign_baseline_indicators,
        )?;
        self.quality
            .validate()
            .map_err(|_| FusionContractError::UnsafeField("hypothesis.quality"))?;
        for candidate in &self.attack_candidates {
            candidate.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FusionSummary {
    pub generated_at: Timestamp,
    pub sampler_health: Vec<LayeredSamplerDeclaration>,
    pub fact_count: u32,
    pub hypothesis_count: u32,
    pub facts: Vec<SecurityFact>,
    pub hypotheses: Vec<AttackHypothesisRecord>,
    pub top_correlated_layers: Vec<FusionCount>,
    pub top_hypothesis_categories: Vec<FusionCount>,
    pub degraded_visibility_context: Vec<String>,
    pub fact_refs: Vec<SecurityFactId>,
    pub hypothesis_refs: Vec<AttackHypothesisId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub finding_refs: Vec<FindingId>,
    pub graph_hint_refs: Vec<GraphHintId>,
    pub quality: QualityBreakdown,
    pub privacy_class: PrivacyClass,
    pub automatic_llm_calls: bool,
}

impl FusionSummary {
    pub fn validate(&self) -> Result<(), FusionContractError> {
        if self.automatic_llm_calls {
            return Err(FusionContractError::UnsafeClaim(
                "fusion cannot trigger automatic LLM calls",
            ));
        }
        if self.facts.len() > MAX_FUSION_ITEMS
            || self.hypotheses.len() > MAX_FUSION_ITEMS
            || self.sampler_health.len() > MAX_FUSION_ITEMS
        {
            return Err(FusionContractError::ExceedsBound("fusion summary items"));
        }
        for sampler in &self.sampler_health {
            sampler.validate()?;
        }
        for fact in &self.facts {
            fact.validate()?;
        }
        for hypothesis in &self.hypotheses {
            hypothesis.validate()?;
        }
        validate_labels(
            "degraded_visibility_context",
            &self.degraded_visibility_context,
        )?;
        self.quality
            .validate()
            .map_err(|_| FusionContractError::UnsafeField("fusion.quality"))?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionCount {
    pub label: String,
    pub count: u32,
}

fn validate_labels(field: &'static str, values: &[String]) -> Result<(), FusionContractError> {
    if values.len() > MAX_FUSION_LABELS {
        return Err(FusionContractError::ExceedsBound(field));
    }
    for value in values {
        safe_text(field, value)?;
    }
    Ok(())
}

fn safe_text(field: &'static str, value: &str) -> Result<(), FusionContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(FusionContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_SAFE_TEXT_BYTES
        || trimmed.contains("://")
        || trimmed.contains('@')
        || trimmed.contains('\\')
        || trimmed.contains('/')
        || looks_like_ip(trimmed)
        || FORBIDDEN_MARKERS
            .iter()
            .any(|marker| trimmed.to_ascii_lowercase().contains(marker))
    {
        return Err(FusionContractError::UnsafeField(field));
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
    "payload",
    "raw_log",
    "raw_packet",
    "username",
    "email",
    "tenant_id",
    "account_id",
    "device_id",
    "command_line",
    "private_marker",
    "confirmed_compromise",
    "malware_execution",
    "credential_theft",
    "host_compromise",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_fact_rejects_sensitive_values() {
        let mut fact = SecurityFact::new(
            SecurityLayer::Http,
            "status_error",
            "http_sampler",
            Timestamp::now(),
        )
        .expect("safe fact");
        fact.route_fingerprint = Some("https://unsafe.example/private".to_string());
        assert!(matches!(
            fact.validate(),
            Err(FusionContractError::UnsafeField(_))
        ));
    }

    #[test]
    fn placeholders_cannot_claim_portable_availability() {
        let sampler = LayeredSamplerDeclaration {
            sampler_id: "sdn_placeholder".to_string(),
            layer: SecurityLayer::SdnPlaceholder,
            source_kind: "placeholder".to_string(),
            state: SamplerState::Enabled,
            sampling_mode: SamplingMode::Placeholder,
            interval_seconds: None,
            record_limit: 1,
            byte_limit: 1,
            checkpoint_state: "not_available".to_string(),
            health_reason: Some("requires_authorized_integration".to_string()),
            output_fact_categories: vec!["sdn_context".to_string()],
            event_bus_topics: vec!["security.fact".to_string()],
            privacy_boundary: "metadata_only".to_string(),
            visibility_requirements: vec!["authorized_integration".to_string()],
            portable_default_available: true,
        };
        assert!(matches!(
            sampler.validate(),
            Err(FusionContractError::UnsafeClaim(_))
        ));
    }

    #[test]
    fn fusion_summary_blocks_automatic_llm_calls() {
        let summary = FusionSummary {
            generated_at: Timestamp::now(),
            sampler_health: Vec::new(),
            fact_count: 0,
            hypothesis_count: 0,
            facts: Vec::new(),
            hypotheses: Vec::new(),
            top_correlated_layers: Vec::new(),
            top_hypothesis_categories: Vec::new(),
            degraded_visibility_context: vec!["metadata_only_visibility".to_string()],
            fact_refs: Vec::new(),
            hypothesis_refs: Vec::new(),
            evidence_refs: Vec::new(),
            finding_refs: Vec::new(),
            graph_hint_refs: Vec::new(),
            quality: QualityBreakdown::metadata_only(),
            privacy_class: PrivacyClass::Internal,
            automatic_llm_calls: true,
        };
        assert!(matches!(
            summary.validate(),
            Err(FusionContractError::UnsafeClaim(_))
        ));
    }
}
