use sentinel_contracts::{
    Alert, AlertCandidate, AlertId, ContractDescriptor, DataSourceDescriptor, DataSourceKind,
    EntityId, EntityRef, EntityType, EvidenceId, Finding, FindingId, GraphPathId, Incident,
    IncidentCandidate, IntelligenceContractError, ManifestValidationError, MaturityLevel,
    MetricKind, MetricSchema, PermissionCategory, PermissionDescriptor, PermissionKey,
    PermissionRiskLevel, PluginId, PluginManifest, PluginStatefulness, PluginType, PrivacyClass,
    QualityScore, RefreshMode, RendererType, RiskEvent, RiskEventId, RiskHint, RiskReason,
    RuntimeMode, SchemaVersion, SecurityContractError, SecuritySeverity, ServiceCapabilityContext,
    ServiceCapabilityStatus, ServiceLimitationFlag, ServiceReasonCode, SupportLevel, TimeRange,
    Timestamp, UiContribution, UiContributionSlot,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fmt;

pub const RISK_ALERTING_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const RISK_ALERTING_PLUGIN_NAME: &str = "risk_based_alerting";
pub const ALERT_CANDIDATE_CONTRACT: &str = "security.alert_candidate";
pub const INCIDENT_CANDIDATE_CONTRACT: &str = "security.incident_candidate";

#[derive(Clone, Debug, PartialEq)]
pub enum RiskAlertingError {
    EmptyInput,
    EmptyField(&'static str),
    InvalidQualityScore,
    InvalidMultiplier(&'static str),
    PrivacyMarker { field: &'static str },
    Manifest(ManifestValidationError),
    Security(SecurityContractError),
    Intelligence(IntelligenceContractError),
}

impl fmt::Display for RiskAlertingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "risk alerting input requires at least one finding"),
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::InvalidQualityScore => write!(f, "quality score must be between 0.0 and 1.0"),
            Self::InvalidMultiplier(field) => {
                write!(f, "{field} must be a finite value between 0.0 and 1.0")
            }
            Self::PrivacyMarker { field } => {
                write!(f, "{field} contains a forbidden sensitive marker")
            }
            Self::Manifest(error) => write!(f, "{error}"),
            Self::Security(error) => write!(f, "{error}"),
            Self::Intelligence(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for RiskAlertingError {}

impl From<ManifestValidationError> for RiskAlertingError {
    fn from(value: ManifestValidationError) -> Self {
        Self::Manifest(value)
    }
}

impl From<SecurityContractError> for RiskAlertingError {
    fn from(value: SecurityContractError) -> Self {
        Self::Security(value)
    }
}

impl From<IntelligenceContractError> for RiskAlertingError {
    fn from(value: IntelligenceContractError) -> Self {
        Self::Intelligence(value)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RiskBasedAlertingInput {
    pub producer_plugin: PluginId,
    pub findings: Vec<Finding>,
    pub risk_hints: Vec<RiskHint>,
    pub service_contexts: Vec<ServiceCapabilityContext>,
    pub entity_criticalities: Vec<EntityCriticality>,
    pub known_good_reductions: Vec<KnownGoodReduction>,
    pub suppression_rules: Vec<SuppressionRule>,
    pub graph_path_refs: Vec<GraphPathId>,
    pub labels: Vec<String>,
    pub observed_at: Timestamp,
}

impl RiskBasedAlertingInput {
    pub fn new(producer_plugin: PluginId) -> Self {
        Self {
            producer_plugin,
            findings: Vec::new(),
            risk_hints: Vec::new(),
            service_contexts: Vec::new(),
            entity_criticalities: Vec::new(),
            known_good_reductions: Vec::new(),
            suppression_rules: Vec::new(),
            graph_path_refs: Vec::new(),
            labels: Vec::new(),
            observed_at: Timestamp::now(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RiskBasedAlertingOutput {
    pub entity_risk_profiles: Vec<EntityRiskProfile>,
    pub risk_events: Vec<RiskEvent>,
    pub alert_candidates: Vec<AlertCandidate>,
    pub alert_decisions: Vec<AlertPromotionDecision>,
    pub alerts: Vec<Alert>,
    pub incident_candidates: Vec<IncidentCandidate>,
    pub incidents: Vec<Incident>,
    pub attack_stories: Vec<AttackStory>,
    pub timelines: Vec<AttackTimeline>,
    pub scopes: Vec<AttackScope>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntityCriticality {
    pub entity_ref: EntityRef,
    pub multiplier: f32,
    pub summary_redacted: String,
}

impl EntityCriticality {
    pub fn new(
        entity_ref: EntityRef,
        multiplier: f32,
        summary_redacted: impl Into<String>,
    ) -> Result<Self, RiskAlertingError> {
        validate_multiplier("entity_criticality.multiplier", multiplier)?;
        Ok(Self {
            entity_ref,
            multiplier,
            summary_redacted: require_safe_text("entity_criticality.summary", summary_redacted)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KnownGoodReduction {
    pub entity_ref: EntityRef,
    pub multiplier: f32,
    pub summary_redacted: String,
}

impl KnownGoodReduction {
    pub fn new(
        entity_ref: EntityRef,
        multiplier: f32,
        summary_redacted: impl Into<String>,
    ) -> Result<Self, RiskAlertingError> {
        validate_multiplier("known_good.multiplier", multiplier)?;
        Ok(Self {
            entity_ref,
            multiplier,
            summary_redacted: require_safe_text("known_good.summary", summary_redacted)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SuppressionRule {
    pub rule_id: String,
    pub entity_id: Option<EntityId>,
    pub entity_type: Option<EntityType>,
    pub finding_type: Option<String>,
    pub multiplier: f32,
    pub summary_redacted: String,
    pub expires_at: Option<Timestamp>,
}

impl SuppressionRule {
    pub fn new(
        rule_id: impl Into<String>,
        multiplier: f32,
        summary_redacted: impl Into<String>,
    ) -> Result<Self, RiskAlertingError> {
        validate_multiplier("suppression.multiplier", multiplier)?;
        Ok(Self {
            rule_id: require_safe_text("suppression.rule_id", rule_id)?,
            entity_id: None,
            entity_type: None,
            finding_type: None,
            multiplier,
            summary_redacted: require_safe_text("suppression.summary", summary_redacted)?,
            expires_at: None,
        })
    }

    pub fn for_entity(mut self, entity_id: EntityId) -> Self {
        self.entity_id = Some(entity_id);
        self
    }

    pub fn for_entity_type(mut self, entity_type: EntityType) -> Self {
        self.entity_type = Some(entity_type);
        self
    }

    pub fn for_finding_type(
        mut self,
        finding_type: impl Into<String>,
    ) -> Result<Self, RiskAlertingError> {
        self.finding_type = Some(require_safe_text("suppression.finding_type", finding_type)?);
        Ok(self)
    }

    pub fn with_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SuppressionDecision {
    pub suppressed: bool,
    pub multiplier: f32,
    pub summaries_redacted: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntityRiskProfile {
    pub entity_ref: EntityRef,
    pub risk_score: QualityScore,
    pub raw_score: f32,
    pub severity: SecuritySeverity,
    pub confidence: QualityScore,
    pub signal_count: usize,
    pub risk_reasons: Vec<RiskReason>,
    pub contributing_findings: Vec<FindingId>,
    pub risk_event_refs: Vec<RiskEventId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub known_good_reduced: bool,
    pub suppressed: bool,
    pub last_updated: Timestamp,
}

impl EntityRiskProfile {
    fn new(entity_ref: EntityRef) -> Self {
        Self {
            entity_ref,
            risk_score: QualityScore::unknown(),
            raw_score: 0.0,
            severity: SecuritySeverity::Informational,
            confidence: QualityScore::unknown(),
            signal_count: 0,
            risk_reasons: Vec::new(),
            contributing_findings: Vec::new(),
            risk_event_refs: Vec::new(),
            evidence_refs: Vec::new(),
            known_good_reduced: false,
            suppressed: false,
            last_updated: Timestamp::now(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct EntityRiskKey {
    entity_id: EntityId,
    entity_type: EntityType,
}

impl EntityRiskKey {
    fn from_entity(entity_ref: &EntityRef) -> Self {
        Self {
            entity_id: entity_ref.entity_id.clone(),
            entity_type: entity_ref.entity_type.clone(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct EntityRiskStore {
    profiles: HashMap<EntityRiskKey, EntityRiskProfile>,
}

impl EntityRiskStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn profiles(&self) -> Vec<EntityRiskProfile> {
        self.profiles.values().cloned().collect()
    }

    pub fn profiles_for_risk_events(&self, risk_events: &[RiskEvent]) -> Vec<EntityRiskProfile> {
        let updated_entities = risk_events
            .iter()
            .map(|event| EntityRiskKey::from_entity(&event.entity_ref))
            .collect::<HashSet<_>>();
        self.profiles
            .iter()
            .filter(|(key, _)| updated_entities.contains(*key))
            .map(|(_, profile)| profile.clone())
            .collect()
    }

    pub fn get(&self, entity_ref: &EntityRef) -> Option<&EntityRiskProfile> {
        self.profiles.get(&EntityRiskKey::from_entity(entity_ref))
    }

    fn apply_update(&mut self, update: EntityRiskUpdate) {
        let key = EntityRiskKey::from_entity(&update.event.entity_ref);
        let profile = self
            .profiles
            .entry(key)
            .or_insert_with(|| EntityRiskProfile::new(update.event.entity_ref.clone()));

        profile.entity_ref = update.event.entity_ref.clone();
        profile.raw_score = update.raw_score;
        profile.risk_score = update.event.risk_score.clone();
        profile.severity = max_severity(&profile.severity, &update.severity);
        profile.confidence = max_quality(&profile.confidence, &update.confidence);
        profile.known_good_reduced |= update.known_good_reduced;
        profile.suppressed |= update.suppressed;
        profile.last_updated = update.event.created_at.clone();

        push_unique_id(
            &mut profile.risk_event_refs,
            update.event.risk_event_id.clone(),
        );
        for finding_id in update.event.contributing_findings {
            push_unique_id(&mut profile.contributing_findings, finding_id);
        }
        for reason in update.event.risk_reasons {
            for evidence_id in &reason.evidence_refs {
                push_unique_id(&mut profile.evidence_refs, evidence_id.clone());
            }
            profile.risk_reasons.push(reason);
        }
        profile.signal_count = profile.contributing_findings.len();
    }
}

struct EntityRiskUpdate {
    event: RiskEvent,
    raw_score: f32,
    severity: SecuritySeverity,
    confidence: QualityScore,
    known_good_reduced: bool,
    suppressed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RiskAggregationPolicy {
    pub alert_threshold: f32,
    pub multi_signal_threshold: f32,
    pub incident_threshold: f32,
    pub high_confidence_threshold: f32,
    pub minimum_alert_confidence: f32,
    pub low_confidence_single_signal_alerts_allowed: bool,
}

impl Default for RiskAggregationPolicy {
    fn default() -> Self {
        Self {
            alert_threshold: 0.72,
            multi_signal_threshold: 0.58,
            incident_threshold: 0.76,
            high_confidence_threshold: 0.82,
            minimum_alert_confidence: 0.55,
            low_confidence_single_signal_alerts_allowed: false,
        }
    }
}

impl RiskAggregationPolicy {
    pub fn validate(&self) -> Result<(), RiskAlertingError> {
        validate_multiplier("alert_threshold", self.alert_threshold)?;
        validate_multiplier("multi_signal_threshold", self.multi_signal_threshold)?;
        validate_multiplier("incident_threshold", self.incident_threshold)?;
        validate_multiplier("high_confidence_threshold", self.high_confidence_threshold)?;
        validate_multiplier("minimum_alert_confidence", self.minimum_alert_confidence)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RiskDecayPolicy {
    pub half_life_hours: f32,
    pub minimum_factor: f32,
    pub policy_name: String,
}

impl Default for RiskDecayPolicy {
    fn default() -> Self {
        Self {
            half_life_hours: 24.0,
            minimum_factor: 0.2,
            policy_name: "balanced_time_decay".to_string(),
        }
    }
}

impl RiskDecayPolicy {
    pub fn new(half_life_hours: f32, minimum_factor: f32) -> Result<Self, RiskAlertingError> {
        if !half_life_hours.is_finite() || half_life_hours <= 0.0 {
            return Err(RiskAlertingError::InvalidMultiplier("half_life_hours"));
        }
        validate_multiplier("minimum_factor", minimum_factor)?;
        Ok(Self {
            half_life_hours,
            minimum_factor,
            policy_name: "custom_time_decay".to_string(),
        })
    }

    pub fn apply_to_score(&self, score: f32, last_seen: &Timestamp, now: &Timestamp) -> f32 {
        let elapsed_hours = (*now.as_datetime() - *last_seen.as_datetime())
            .num_seconds()
            .max(0) as f32
            / 3_600.0;
        let decay = 0.5_f32.powf(elapsed_hours / self.half_life_hours);
        score * decay.max(self.minimum_factor)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SuppressionEngine {
    rules: Vec<SuppressionRule>,
}

impl SuppressionEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_rules(rules: Vec<SuppressionRule>) -> Self {
        Self { rules }
    }

    pub fn add_rule(&mut self, rule: SuppressionRule) {
        self.rules.push(rule);
    }

    pub fn evaluate(
        &self,
        finding: &Finding,
        entity_ref: &EntityRef,
        now: &Timestamp,
    ) -> Result<SuppressionDecision, RiskAlertingError> {
        let mut multiplier = 1.0;
        let mut summaries = Vec::new();
        for rule in &self.rules {
            validate_safe_text("suppression.rule_id", &rule.rule_id)?;
            validate_safe_text("suppression.summary", &rule.summary_redacted)?;
            validate_multiplier("suppression.multiplier", rule.multiplier)?;
            if rule
                .expires_at
                .as_ref()
                .is_some_and(|expires| expires <= now)
            {
                continue;
            }
            if !suppression_rule_matches(rule, finding, entity_ref) {
                continue;
            }
            multiplier *= rule.multiplier;
            summaries.push(rule.summary_redacted.clone());
        }
        Ok(SuppressionDecision {
            suppressed: multiplier < 1.0,
            multiplier,
            summaries_redacted: summaries,
        })
    }
}

#[derive(Clone, Debug)]
pub struct RiskAggregator {
    policy: RiskAggregationPolicy,
    decay_policy: RiskDecayPolicy,
    suppression_engine: SuppressionEngine,
}

impl Default for RiskAggregator {
    fn default() -> Self {
        Self {
            policy: RiskAggregationPolicy::default(),
            decay_policy: RiskDecayPolicy::default(),
            suppression_engine: SuppressionEngine::new(),
        }
    }
}

impl RiskAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_policy(mut self, policy: RiskAggregationPolicy) -> Result<Self, RiskAlertingError> {
        policy.validate()?;
        self.policy = policy;
        Ok(self)
    }

    pub fn with_decay_policy(mut self, decay_policy: RiskDecayPolicy) -> Self {
        self.decay_policy = decay_policy;
        self
    }

    pub fn with_suppression_engine(mut self, suppression_engine: SuppressionEngine) -> Self {
        self.suppression_engine = suppression_engine;
        self
    }

    pub fn policy(&self) -> &RiskAggregationPolicy {
        &self.policy
    }

    pub fn aggregate(
        &self,
        store: &mut EntityRiskStore,
        input: &RiskBasedAlertingInput,
    ) -> Result<Vec<RiskEvent>, RiskAlertingError> {
        validate_input(input)?;
        self.policy.validate()?;

        let mut risk_events = Vec::new();
        let service_adjustment = service_context_adjustment(&input.service_contexts);
        let risk_hints_by_entity = risk_hints_by_entity(&input.risk_hints)?;
        let criticality_by_entity = criticality_by_entity(&input.entity_criticalities)?;
        let known_good_by_entity = known_good_by_entity(&input.known_good_reductions)?;
        let mut suppression_engine = self.suppression_engine.clone();
        for rule in &input.suppression_rules {
            suppression_engine.add_rule(rule.clone());
        }

        for finding in &input.findings {
            if !finding_is_active(finding) {
                continue;
            }
            let entities = mvp_risk_entities(finding);
            for entity_ref in entities {
                let key = EntityRiskKey::from_entity(&entity_ref);
                let previous_score = store
                    .get(&entity_ref)
                    .map(|profile| {
                        self.decay_policy.apply_to_score(
                            profile.raw_score,
                            &profile.last_updated,
                            &input.observed_at,
                        )
                    })
                    .unwrap_or_default();
                let criticality = criticality_by_entity.get(&key).map_or(1.0, |value| *value);
                let known_good = known_good_by_entity.get(&key);
                let known_good_multiplier = known_good.map_or(1.0, |value| value.multiplier);
                let suppression =
                    suppression_engine.evaluate(finding, &entity_ref, &input.observed_at)?;
                let hints = risk_hints_by_entity
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(Vec::new);
                let finding_delta = finding_risk_delta(finding, criticality, &hints);
                let risk_delta = finding_delta
                    * known_good_multiplier
                    * suppression.multiplier
                    * service_adjustment.score_multiplier;
                let raw_score = (previous_score + risk_delta).clamp(0.0, 1.0);

                let mut reasons = risk_reasons_for_finding(finding)?;
                if let Some(reduction) = known_good {
                    reasons.push(risk_reason(
                        "known_good_reduction",
                        &reduction.summary_redacted,
                        1.0 - reduction.multiplier,
                        finding.evidence_refs(),
                        finding,
                    )?);
                }
                for summary in &suppression.summaries_redacted {
                    reasons.push(risk_reason(
                        "suppression_reduction",
                        summary,
                        1.0 - suppression.multiplier,
                        finding.evidence_refs(),
                        finding,
                    )?);
                }
                for hint in hints {
                    reasons.push(risk_reason(
                        &hint.hint_type,
                        &hint.summary_redacted,
                        hint.confidence.value(),
                        finding.evidence_refs(),
                        finding,
                    )?);
                }
                for reduction in &service_adjustment.reductions {
                    reasons.push(risk_reason(
                        reduction.reason_type,
                        reduction.summary_redacted,
                        reduction.confidence,
                        finding.evidence_refs(),
                        finding,
                    )?);
                }

                let mut event = RiskEvent::new(entity_ref.clone(), bounded_quality(raw_score));
                event.risk_delta = risk_delta;
                event.risk_reasons = reasons;
                event.contributing_findings = vec![finding.id().clone()];
                event.time_window = TimeRange::new(
                    Some(input.observed_at.clone()),
                    Some(input.observed_at.clone()),
                )
                .map_err(|_| RiskAlertingError::InvalidQualityScore)?;
                event.decay_policy = Some(self.decay_policy.policy_name.clone());
                event.created_at = input.observed_at.clone();

                let output_event = event.clone();
                store.apply_update(EntityRiskUpdate {
                    event,
                    raw_score,
                    severity: finding.severity().clone(),
                    confidence: bounded_quality(
                        finding.confidence().value() * service_adjustment.confidence_multiplier,
                    ),
                    known_good_reduced: known_good.is_some(),
                    suppressed: suppression.suppressed,
                });
                risk_events.push(output_event);
            }
        }

        Ok(risk_events)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertPromotionReason {
    BelowThreshold,
    LowConfidenceSingleSignal,
    RiskThreshold,
    MultiSignal,
    HighConfidence,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AlertPromotionDecision {
    pub alert_candidate_id: sentinel_contracts::AlertCandidateId,
    pub promoted: bool,
    pub reason: AlertPromotionReason,
    pub risk_score: QualityScore,
    pub confidence: QualityScore,
    pub severity: SecuritySeverity,
    pub finding_refs: Vec<FindingId>,
}

#[derive(Clone, Debug, Default)]
pub struct AlertPromoter {
    policy: RiskAggregationPolicy,
}

impl AlertPromoter {
    pub fn new(policy: RiskAggregationPolicy) -> Result<Self, RiskAlertingError> {
        policy.validate()?;
        Ok(Self { policy })
    }

    pub fn promote(
        &self,
        profiles: &[EntityRiskProfile],
    ) -> Result<AlertPromotionOutput, RiskAlertingError> {
        let mut candidates = Vec::new();
        let mut decisions = Vec::new();
        let mut alerts = Vec::new();

        for profile in profiles
            .iter()
            .filter(|profile| !profile.contributing_findings.is_empty())
        {
            let mut candidate = AlertCandidate::new(profile.contributing_findings.clone())?;
            candidate.risk_event_refs = profile.risk_event_refs.clone();
            candidate.entity_refs = vec![profile.entity_ref.clone()];
            candidate.severity = profile.severity.clone();
            candidate.confidence = profile.confidence.clone();
            candidate.risk_reasons = profile.risk_reasons.clone();

            let (promoted, reason) = self.should_promote(profile);
            let decision = AlertPromotionDecision {
                alert_candidate_id: candidate.alert_candidate_id.clone(),
                promoted,
                reason,
                risk_score: profile.risk_score.clone(),
                confidence: profile.confidence.clone(),
                severity: profile.severity.clone(),
                finding_refs: profile.contributing_findings.clone(),
            };

            if promoted {
                let alert = Alert::new(
                    alert_title(profile),
                    alert_summary(profile),
                    profile.contributing_findings.clone(),
                )?
                .with_risk_event_refs(profile.risk_event_refs.clone())
                .with_entity_refs(vec![profile.entity_ref.clone()])
                .with_severity(profile.severity.clone())
                .with_confidence(profile.confidence.clone());
                alerts.push(alert);
            }

            candidates.push(candidate);
            decisions.push(decision);
        }

        Ok(AlertPromotionOutput {
            candidates,
            decisions,
            alerts,
        })
    }

    fn should_promote(&self, profile: &EntityRiskProfile) -> (bool, AlertPromotionReason) {
        let single_signal = profile.signal_count <= 1;
        let confidence = profile.confidence.value();
        if single_signal
            && confidence < self.policy.minimum_alert_confidence
            && !self.policy.low_confidence_single_signal_alerts_allowed
        {
            return (false, AlertPromotionReason::LowConfidenceSingleSignal);
        }
        if profile.suppressed && profile.risk_score.value() < self.policy.alert_threshold {
            return (false, AlertPromotionReason::BelowThreshold);
        }
        if profile.risk_score.value() >= self.policy.alert_threshold
            && confidence >= self.policy.minimum_alert_confidence
        {
            return (true, AlertPromotionReason::RiskThreshold);
        }
        if profile.signal_count >= 2
            && profile.risk_score.value() >= self.policy.multi_signal_threshold
        {
            return (true, AlertPromotionReason::MultiSignal);
        }
        if severity_rank(&profile.severity) >= severity_rank(&SecuritySeverity::High)
            && confidence >= self.policy.high_confidence_threshold
        {
            return (true, AlertPromotionReason::HighConfidence);
        }
        (false, AlertPromotionReason::BelowThreshold)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AlertPromotionOutput {
    pub candidates: Vec<AlertCandidate>,
    pub decisions: Vec<AlertPromotionDecision>,
    pub alerts: Vec<Alert>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttackStory {
    pub story_id: String,
    pub incident_type: String,
    pub title_redacted: String,
    pub summary_redacted: String,
    pub alert_refs: Vec<AlertId>,
    pub finding_refs: Vec<FindingId>,
    pub graph_path_refs: Vec<GraphPathId>,
    pub severity: SecuritySeverity,
    pub confidence: QualityScore,
    pub reason_summaries_redacted: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TimelineItem {
    pub timestamp: Timestamp,
    pub event_type: String,
    pub summary_redacted: String,
    pub alert_refs: Vec<AlertId>,
    pub finding_refs: Vec<FindingId>,
    pub risk_event_refs: Vec<RiskEventId>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttackTimeline {
    pub story_id: String,
    pub items: Vec<TimelineItem>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttackScope {
    pub story_id: String,
    pub hosts: Vec<EntityRef>,
    pub processes: Vec<EntityRef>,
    pub domains: Vec<EntityRef>,
    pub destinations: Vec<EntityRef>,
    pub assets: Vec<EntityRef>,
    pub finding_refs: Vec<FindingId>,
    pub alert_refs: Vec<AlertId>,
}

#[derive(Clone, Debug, Default)]
pub struct AttackStoryBuilder;

impl AttackStoryBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        alerts: &[Alert],
        findings: &[Finding],
        graph_path_refs: &[GraphPathId],
    ) -> Vec<AttackStory> {
        let finding_by_id = findings
            .iter()
            .map(|finding| (finding.id().clone(), finding))
            .collect::<HashMap<_, _>>();
        let mut grouped_alerts: HashMap<String, Vec<&Alert>> = HashMap::new();
        for alert in alerts {
            let incident_type = classify_alert(alert, &finding_by_id);
            grouped_alerts.entry(incident_type).or_default().push(alert);
        }

        grouped_alerts
            .into_iter()
            .map(|(incident_type, alerts)| {
                let mut alert_refs = Vec::new();
                let mut finding_refs = Vec::new();
                let mut severity = SecuritySeverity::Informational;
                let mut confidence = QualityScore::unknown();
                for alert in alerts {
                    push_unique_id(&mut alert_refs, alert.id().clone());
                    for finding_id in alert.finding_refs() {
                        push_unique_id(&mut finding_refs, finding_id.clone());
                    }
                    severity = max_severity(&severity, alert.severity());
                    confidence = max_quality(&confidence, alert.confidence());
                }
                let story_id = format!(
                    "risk-story-{}-{}",
                    incident_type,
                    alert_refs
                        .first()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "empty".to_string())
                );
                AttackStory {
                    story_id,
                    title_redacted: incident_title(&incident_type),
                    summary_redacted: format!(
                        "Risk alerting grouped {} alert(s) and {} finding(s) into an attack story.",
                        alert_refs.len(),
                        finding_refs.len()
                    ),
                    incident_type,
                    alert_refs,
                    finding_refs,
                    graph_path_refs: graph_path_refs.to_vec(),
                    severity,
                    confidence,
                    reason_summaries_redacted: Vec::new(),
                }
            })
            .collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct TimelineBuilder;

impl TimelineBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(&self, story: &AttackStory, risk_events: &[RiskEvent]) -> AttackTimeline {
        let story_findings = story.finding_refs.iter().cloned().collect::<HashSet<_>>();
        let mut items = risk_events
            .iter()
            .filter(|event| {
                event
                    .contributing_findings
                    .iter()
                    .any(|finding_id| story_findings.contains(finding_id))
            })
            .map(|event| TimelineItem {
                timestamp: event.created_at.clone(),
                event_type: "security.risk".to_string(),
                summary_redacted: format!(
                    "Entity risk updated with score {:.2}.",
                    event.risk_score.value()
                ),
                alert_refs: Vec::new(),
                finding_refs: event.contributing_findings.clone(),
                risk_event_refs: vec![event.risk_event_id.clone()],
            })
            .collect::<Vec<_>>();

        items.push(TimelineItem {
            timestamp: Timestamp::now(),
            event_type: "security.alert".to_string(),
            summary_redacted: format!(
                "{} alert(s) promoted by risk policy.",
                story.alert_refs.len()
            ),
            alert_refs: story.alert_refs.clone(),
            finding_refs: story.finding_refs.clone(),
            risk_event_refs: Vec::new(),
        });
        items.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));

        AttackTimeline {
            story_id: story.story_id.clone(),
            items,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ScopeBuilder;

impl ScopeBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        story: &AttackStory,
        alerts: &[Alert],
        findings: &[Finding],
    ) -> AttackScope {
        let alert_by_id = alerts
            .iter()
            .map(|alert| (alert.id().clone(), alert))
            .collect::<HashMap<_, _>>();
        let finding_by_id = findings
            .iter()
            .map(|finding| (finding.id().clone(), finding))
            .collect::<HashMap<_, _>>();

        let mut hosts = Vec::new();
        let mut processes = Vec::new();
        let mut domains = Vec::new();
        let mut destinations = Vec::new();
        let mut assets = Vec::new();

        for alert_id in &story.alert_refs {
            if let Some(alert) = alert_by_id.get(alert_id) {
                for entity_ref in alert.entity_refs() {
                    push_scope_entity(
                        entity_ref.clone(),
                        &mut hosts,
                        &mut processes,
                        &mut domains,
                        &mut destinations,
                        &mut assets,
                    );
                }
            }
        }
        for finding_id in &story.finding_refs {
            if let Some(finding) = finding_by_id.get(finding_id) {
                for entity_ref in finding.entity_refs() {
                    push_scope_entity(
                        entity_ref.clone(),
                        &mut hosts,
                        &mut processes,
                        &mut domains,
                        &mut destinations,
                        &mut assets,
                    );
                }
            }
        }

        AttackScope {
            story_id: story.story_id.clone(),
            hosts,
            processes,
            domains,
            destinations,
            assets,
            finding_refs: story.finding_refs.clone(),
            alert_refs: story.alert_refs.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct IncidentCandidateBuilder {
    policy: RiskAggregationPolicy,
    attack_story_builder: AttackStoryBuilder,
    timeline_builder: TimelineBuilder,
    scope_builder: ScopeBuilder,
}

impl Default for IncidentCandidateBuilder {
    fn default() -> Self {
        Self {
            policy: RiskAggregationPolicy::default(),
            attack_story_builder: AttackStoryBuilder::new(),
            timeline_builder: TimelineBuilder::new(),
            scope_builder: ScopeBuilder::new(),
        }
    }
}

impl IncidentCandidateBuilder {
    pub fn new(policy: RiskAggregationPolicy) -> Result<Self, RiskAlertingError> {
        policy.validate()?;
        Ok(Self {
            policy,
            ..Self::default()
        })
    }

    pub fn build(
        &self,
        alerts: &[Alert],
        findings: &[Finding],
        risk_events: &[RiskEvent],
        graph_path_refs: &[GraphPathId],
    ) -> Result<IncidentCandidateOutput, RiskAlertingError> {
        let stories = self
            .attack_story_builder
            .build(alerts, findings, graph_path_refs);
        let mut candidates = Vec::new();
        let mut incidents = Vec::new();
        let mut timelines = Vec::new();
        let mut scopes = Vec::new();

        for story in &stories {
            if !self.should_create_incident_candidate(story) {
                continue;
            }
            let mut candidate = IncidentCandidate::new(
                story.title_redacted.clone(),
                story.summary_redacted.clone(),
                story.alert_refs.clone(),
            )?;
            candidate.finding_refs = story.finding_refs.clone();
            candidate.graph_path_refs = story.graph_path_refs.clone();
            candidate.severity = story.severity.clone();
            candidate.confidence = story.confidence.clone();

            let incident = Incident::new(
                story.incident_type.clone(),
                story.title_redacted.clone(),
                story.summary_redacted.clone(),
                story.alert_refs.clone(),
            )?
            .with_finding_refs(story.finding_refs.clone())
            .with_graph_path_refs(story.graph_path_refs.clone())
            .with_severity(story.severity.clone())
            .with_confidence(story.confidence.clone())
            .with_state(sentinel_contracts::IncidentState::Candidate)
            .with_root_cause_hint_redacted("risk aggregation linked evidence-backed alerts")
            .with_recommended_response_summary_redacted(
                "Review response planning recommendations; no action was executed.",
            );

            timelines.push(self.timeline_builder.build(story, risk_events));
            scopes.push(self.scope_builder.build(story, alerts, findings));
            candidates.push(candidate);
            incidents.push(incident);
        }

        Ok(IncidentCandidateOutput {
            candidates,
            incidents,
            stories,
            timelines,
            scopes,
        })
    }

    fn should_create_incident_candidate(&self, story: &AttackStory) -> bool {
        story.confidence.value() >= self.policy.minimum_alert_confidence
            && (story.alert_refs.len() >= 2
                || story.finding_refs.len() >= 2
                || story.confidence.value() >= self.policy.high_confidence_threshold
                || severity_rank(&story.severity) >= severity_rank(&SecuritySeverity::High))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentCandidateOutput {
    pub candidates: Vec<IncidentCandidate>,
    pub incidents: Vec<Incident>,
    pub stories: Vec<AttackStory>,
    pub timelines: Vec<AttackTimeline>,
    pub scopes: Vec<AttackScope>,
}

#[derive(Clone, Debug)]
pub struct RiskBasedAlertingPlugin {
    entity_risk_store: EntityRiskStore,
    risk_aggregator: RiskAggregator,
    alert_promoter: AlertPromoter,
    incident_candidate_builder: IncidentCandidateBuilder,
}

impl Default for RiskBasedAlertingPlugin {
    fn default() -> Self {
        let policy = RiskAggregationPolicy::default();
        Self {
            entity_risk_store: EntityRiskStore::new(),
            risk_aggregator: RiskAggregator::new(),
            alert_promoter: AlertPromoter::new(policy.clone()).expect("default policy is valid"),
            incident_candidate_builder: IncidentCandidateBuilder::new(policy)
                .expect("default policy is valid"),
        }
    }
}

impl RiskBasedAlertingPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn manifest() -> Result<PluginManifest, RiskAlertingError> {
        let plugin_id = PluginId::new_v4();
        let mut manifest = PluginManifest::new(
            plugin_id.clone(),
            RISK_ALERTING_PLUGIN_NAME,
            "0.1.0",
            "risk_alerting",
            PluginType::PlatformDetection,
            RuntimeMode::Streaming,
        )?;
        manifest.description =
            "Risk-based alerting and incident candidate creation for evidence-backed findings."
                .to_string();
        manifest.enabled_by_default = true;
        manifest.maturity_level = MaturityLevel::L3Modeling;
        manifest.capability_tags = vec![
            "local_first".to_string(),
            "metadata_first".to_string(),
            "risk_based_alerting".to_string(),
            "incident_candidate".to_string(),
        ];
        manifest.input_contracts = [
            "security.finding",
            "security.evidence",
            "security.risk_hint",
            "asset.exposure",
            "identity.process_context",
            "service.capability_status",
        ]
        .into_iter()
        .map(contract)
        .collect::<Result<Vec<_>, _>>()?;
        manifest.output_contracts = [
            "security.risk",
            ALERT_CANDIDATE_CONTRACT,
            "security.alert",
            INCIDENT_CANDIDATE_CONTRACT,
            "security.incident",
        ]
        .into_iter()
        .map(contract)
        .collect::<Result<Vec<_>, _>>()?;
        manifest.required_permissions = vec![
            permission(
                "read.security.finding",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "Read evidence-backed security findings.",
                &["security.finding", "security.evidence"],
            )?,
            permission(
                "read.security.risk_hint",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "Read evidence-input-only risk hints.",
                &["security.risk_hint"],
            )?,
            permission(
                "read.service.capability_status",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "Read bounded machine-local service capability metadata.",
                &["service.capability_status"],
            )?,
            permission(
                "write.security.risk",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Medium,
                "Write entity risk events through the security risk stage.",
                &["security.risk"],
            )?,
            permission(
                "write.security.alert",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Medium,
                "Promote alert candidates to traceable alerts.",
                &["security.alert", "security.alert_candidate"],
            )?,
            permission(
                "write.security.incident",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Medium,
                "Create traceable incident candidates from promoted alerts.",
                &["security.incident", "security.incident_candidate"],
            )?,
        ];
        manifest.metrics_schema = vec![
            metric(
                "risk_alerting.findings_in_total",
                MetricKind::Counter,
                "Evidence-backed findings processed by risk alerting",
            )?,
            metric(
                "risk_alerting.risk_events_out_total",
                MetricKind::Counter,
                "Entity risk events emitted",
            )?,
            metric(
                "risk_alerting.alerts_promoted_total",
                MetricKind::Counter,
                "Alerts promoted by risk policy",
            )?,
            metric(
                "risk_alerting.incident_candidates_total",
                MetricKind::Counter,
                "Incident candidates built from promoted alerts",
            )?,
        ];
        manifest.ui_contributions = vec![
            ui_contribution(
                plugin_id.clone(),
                UiContributionSlot::OverviewRiskMap,
                RendererType::RiskBreakdown,
                "Risk Breakdown",
                "security.risk",
            )?,
            ui_contribution(
                plugin_id,
                UiContributionSlot::InvestigationEvidencePanel,
                RendererType::Timeline,
                "Attack Story Timeline",
                INCIDENT_CANDIDATE_CONTRACT,
            )?,
        ];
        manifest.statefulness = PluginStatefulness::MemoryState;
        manifest.checkpoint_support = SupportLevel::Optional;
        manifest.replay_support = SupportLevel::Required;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn process(
        &mut self,
        input: RiskBasedAlertingInput,
    ) -> Result<RiskBasedAlertingOutput, RiskAlertingError> {
        let risk_events = self
            .risk_aggregator
            .aggregate(&mut self.entity_risk_store, &input)?;
        let profiles = self.entity_risk_store.profiles();
        let updated_profiles = self
            .entity_risk_store
            .profiles_for_risk_events(&risk_events);
        let alert_output = self.alert_promoter.promote(&updated_profiles)?;
        let incident_output = self.incident_candidate_builder.build(
            &alert_output.alerts,
            &input.findings,
            &risk_events,
            &input.graph_path_refs,
        )?;

        Ok(RiskBasedAlertingOutput {
            entity_risk_profiles: profiles,
            risk_events,
            alert_candidates: alert_output.candidates,
            alert_decisions: alert_output.decisions,
            alerts: alert_output.alerts,
            incident_candidates: incident_output.candidates,
            incidents: incident_output.incidents,
            attack_stories: incident_output.stories,
            timelines: incident_output.timelines,
            scopes: incident_output.scopes,
        })
    }
}

fn validate_input(input: &RiskBasedAlertingInput) -> Result<(), RiskAlertingError> {
    if input.findings.is_empty() {
        return Err(RiskAlertingError::EmptyInput);
    }
    for label in &input.labels {
        validate_safe_text("label", label)?;
    }
    for service_context in &input.service_contexts {
        service_context
            .validate_boundary()
            .map_err(|_| RiskAlertingError::PrivacyMarker {
                field: "service.capability_status",
            })?;
    }
    for finding in &input.findings {
        validate_safe_text("finding_type", finding.finding_type())?;
        validate_safe_text(
            "finding.explanation",
            &finding.explanation().summary_redacted,
        )?;
        for reason in finding.risk_reasons() {
            validate_safe_text("risk_reason.type", &reason.reason_type)?;
            validate_safe_text("risk_reason.summary", &reason.summary_redacted)?;
        }
        for entity_ref in finding.entity_refs() {
            validate_entity_ref(entity_ref)?;
        }
    }
    for hint in &input.risk_hints {
        hint.validate_boundary()?;
        validate_safe_text("risk_hint.type", &hint.hint_type)?;
        validate_safe_text("risk_hint.summary", &hint.summary_redacted)?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ServiceAdjustmentReason {
    reason_type: &'static str,
    summary_redacted: &'static str,
    confidence: f32,
    score_multiplier: f32,
    confidence_multiplier: f32,
}

#[derive(Clone, Debug)]
struct ServiceContextAdjustment {
    score_multiplier: f32,
    confidence_multiplier: f32,
    reductions: Vec<ServiceAdjustmentReason>,
}

fn service_context_adjustment(
    service_contexts: &[ServiceCapabilityContext],
) -> ServiceContextAdjustment {
    let mut score_multiplier = 1.0f32;
    let mut confidence_multiplier = 1.0f32;
    let mut seen = HashSet::new();
    let mut reductions = Vec::new();

    for context in service_contexts {
        for reduction in service_context_reductions(context) {
            if seen.insert(reduction.reason_type) {
                score_multiplier = (score_multiplier * reduction.score_multiplier).clamp(0.45, 1.0);
                confidence_multiplier =
                    (confidence_multiplier * reduction.confidence_multiplier).clamp(0.35, 1.0);
                reductions.push(reduction);
            }
        }
    }

    ServiceContextAdjustment {
        score_multiplier,
        confidence_multiplier,
        reductions,
    }
}

fn service_context_reductions(context: &ServiceCapabilityContext) -> Vec<ServiceAdjustmentReason> {
    let mut reductions = Vec::new();
    if matches!(
        context.reason_code,
        Some(ServiceReasonCode::IpcDisconnected | ServiceReasonCode::ServiceUnavailable)
    ) || matches!(context.status, ServiceCapabilityStatus::Disconnected)
    {
        reductions.push(ServiceAdjustmentReason {
            reason_type: "service_ipc_disconnected",
            summary_redacted:
                "Elevated service IPC is unavailable; risk confidence is reduced to preserve degraded-mode honesty.",
            confidence: 0.74,
            score_multiplier: 0.9,
            confidence_multiplier: 0.74,
        });
    }
    if matches!(
        context.reason_code,
        Some(ServiceReasonCode::CaptureUnavailable)
    ) || context
        .limitation_flags
        .contains(&ServiceLimitationFlag::NoPrivilegedCapture)
    {
        reductions.push(ServiceAdjustmentReason {
            reason_type: "service_capture_unavailable",
            summary_redacted:
                "Capture adapter metadata is unavailable; risk confidence is reduced to avoid overstating visibility.",
            confidence: 0.78,
            score_multiplier: 0.92,
            confidence_multiplier: 0.78,
        });
    }
    if matches!(
        context.reason_code,
        Some(ServiceReasonCode::ProcessAttributionLimited)
    ) || context
        .limitation_flags
        .contains(&ServiceLimitationFlag::NoProcessAttribution)
    {
        reductions.push(ServiceAdjustmentReason {
            reason_type: "service_process_visibility_reduced",
            summary_redacted:
                "Process attribution visibility is limited; risk confidence is reduced to preserve metadata-only honesty.",
            confidence: 0.84,
            score_multiplier: 0.95,
            confidence_multiplier: 0.84,
        });
    } else if context
        .limitation_flags
        .contains(&ServiceLimitationFlag::ReducedVisibility)
        || matches!(
            context.reason_code,
            Some(ServiceReasonCode::ReducedVisibility)
        )
    {
        reductions.push(ServiceAdjustmentReason {
            reason_type: "service_reduced_visibility",
            summary_redacted:
                "Machine-local service visibility is reduced; risk confidence is lowered to avoid overstating certainty.",
            confidence: 0.9,
            score_multiplier: 0.97,
            confidence_multiplier: 0.9,
        });
    }
    reductions
}

fn mvp_risk_entities(finding: &Finding) -> Vec<EntityRef> {
    let mut entities = Vec::new();
    for entity_ref in finding.entity_refs() {
        if matches!(
            entity_ref.entity_type,
            EntityType::Host
                | EntityType::Process
                | EntityType::Domain
                | EntityType::Ip
                | EntityType::CloudResource
                | EntityType::Service
                | EntityType::Port
        ) {
            push_unique_entity(&mut entities, entity_ref.clone());
        }
    }
    entities
}

fn finding_is_active(finding: &Finding) -> bool {
    !matches!(
        finding.state(),
        sentinel_contracts::FindingState::Suppressed
            | sentinel_contracts::FindingState::Dismissed
            | sentinel_contracts::FindingState::Expired
            | sentinel_contracts::FindingState::Resolved
            | sentinel_contracts::FindingState::Duplicate
    )
}

fn finding_risk_delta(finding: &Finding, entity_criticality: f32, risk_hints: &[RiskHint]) -> f32 {
    let severity = severity_weight(finding.severity());
    let confidence = finding.confidence().value();
    let evidence_weight = evidence_weight(finding.evidence_refs().len());
    let hint_delta = risk_hints
        .iter()
        .map(|hint| hint.risk_delta.max(0.0) * hint.confidence.value())
        .sum::<f32>();
    (severity * confidence * evidence_weight * entity_criticality + hint_delta).clamp(0.0, 1.0)
}

fn risk_reasons_for_finding(finding: &Finding) -> Result<Vec<RiskReason>, RiskAlertingError> {
    if !finding.risk_reasons().is_empty() {
        return Ok(finding.risk_reasons().to_vec());
    }
    Ok(vec![risk_reason(
        finding.finding_type(),
        &finding.explanation().summary_redacted,
        finding.confidence().value(),
        finding.evidence_refs(),
        finding,
    )?])
}

fn risk_reason(
    reason_type: &str,
    summary_redacted: &str,
    confidence: f32,
    evidence_refs: &[EvidenceId],
    finding: &Finding,
) -> Result<RiskReason, RiskAlertingError> {
    let mut reason = RiskReason::new(reason_type, summary_redacted)?;
    reason.confidence = bounded_quality(confidence);
    reason.evidence_refs = evidence_refs.to_vec();
    reason.attack_mappings = finding.attack_mappings().to_vec();
    Ok(reason)
}

fn risk_hints_by_entity(
    hints: &[RiskHint],
) -> Result<HashMap<EntityRiskKey, Vec<RiskHint>>, RiskAlertingError> {
    let mut by_entity: HashMap<EntityRiskKey, Vec<RiskHint>> = HashMap::new();
    for hint in hints {
        hint.validate_boundary()?;
        if let Some(entity_ref) = &hint.entity_ref {
            by_entity
                .entry(EntityRiskKey::from_entity(entity_ref))
                .or_default()
                .push(hint.clone());
        }
    }
    Ok(by_entity)
}

fn criticality_by_entity(
    criticalities: &[EntityCriticality],
) -> Result<HashMap<EntityRiskKey, f32>, RiskAlertingError> {
    let mut by_entity = HashMap::new();
    for criticality in criticalities {
        validate_multiplier("entity_criticality.multiplier", criticality.multiplier)?;
        validate_safe_text("entity_criticality.summary", &criticality.summary_redacted)?;
        by_entity.insert(
            EntityRiskKey::from_entity(&criticality.entity_ref),
            criticality.multiplier,
        );
    }
    Ok(by_entity)
}

fn known_good_by_entity(
    reductions: &[KnownGoodReduction],
) -> Result<HashMap<EntityRiskKey, KnownGoodReduction>, RiskAlertingError> {
    let mut by_entity = HashMap::new();
    for reduction in reductions {
        validate_multiplier("known_good.multiplier", reduction.multiplier)?;
        validate_safe_text("known_good.summary", &reduction.summary_redacted)?;
        by_entity.insert(
            EntityRiskKey::from_entity(&reduction.entity_ref),
            reduction.clone(),
        );
    }
    Ok(by_entity)
}

fn suppression_rule_matches(
    rule: &SuppressionRule,
    finding: &Finding,
    entity_ref: &EntityRef,
) -> bool {
    if rule
        .entity_id
        .as_ref()
        .is_some_and(|entity_id| entity_id != &entity_ref.entity_id)
    {
        return false;
    }
    if rule
        .entity_type
        .as_ref()
        .is_some_and(|entity_type| entity_type != &entity_ref.entity_type)
    {
        return false;
    }
    if rule
        .finding_type
        .as_ref()
        .is_some_and(|finding_type| finding_type != finding.finding_type())
    {
        return false;
    }
    true
}

fn classify_alert(alert: &Alert, finding_by_id: &HashMap<FindingId, &Finding>) -> String {
    let mut has_c2 = false;
    let mut has_exfil = false;
    let mut has_lateral = false;
    let mut has_asset = false;
    for finding_id in alert.finding_refs() {
        let Some(finding) = finding_by_id.get(finding_id) else {
            continue;
        };
        let finding_type = finding.finding_type().to_ascii_lowercase();
        has_c2 |= finding_type.contains("c2");
        has_exfil |= finding_type.contains("exfil");
        has_lateral |= finding_type.contains("lateral");
        has_asset |= finding_type.contains("asset");
    }
    if [has_c2, has_exfil, has_lateral, has_asset]
        .into_iter()
        .filter(|present| *present)
        .count()
        >= 2
    {
        "multi_stage_security_incident".to_string()
    } else if has_exfil {
        "data_exfiltration_incident".to_string()
    } else if has_lateral {
        "lateral_movement_incident".to_string()
    } else if has_asset {
        "asset_exposure_incident".to_string()
    } else {
        "c2_communication_incident".to_string()
    }
}

fn push_scope_entity(
    entity_ref: EntityRef,
    hosts: &mut Vec<EntityRef>,
    processes: &mut Vec<EntityRef>,
    domains: &mut Vec<EntityRef>,
    destinations: &mut Vec<EntityRef>,
    assets: &mut Vec<EntityRef>,
) {
    match entity_ref.entity_type {
        EntityType::Host => push_unique_entity(hosts, entity_ref),
        EntityType::Process => push_unique_entity(processes, entity_ref),
        EntityType::Domain => push_unique_entity(domains, entity_ref),
        EntityType::Ip | EntityType::CloudResource => push_unique_entity(destinations, entity_ref),
        EntityType::Service | EntityType::Port => push_unique_entity(assets, entity_ref),
        _ => {}
    }
}

fn push_unique_entity(entities: &mut Vec<EntityRef>, entity_ref: EntityRef) {
    if !entities.iter().any(|existing| {
        existing.entity_id == entity_ref.entity_id && existing.entity_type == entity_ref.entity_type
    }) {
        entities.push(entity_ref);
    }
}

fn push_unique_id<T>(values: &mut Vec<T>, value: T)
where
    T: PartialEq,
{
    if !values.contains(&value) {
        values.push(value);
    }
}

fn alert_title(profile: &EntityRiskProfile) -> String {
    format!(
        "Elevated {} risk",
        entity_type_label(&profile.entity_ref.entity_type)
    )
}

fn alert_summary(profile: &EntityRiskProfile) -> String {
    format!(
        "Risk policy promoted {} evidence-backed finding(s) for a {} entity.",
        profile.contributing_findings.len(),
        entity_type_label(&profile.entity_ref.entity_type)
    )
}

fn incident_title(incident_type: &str) -> String {
    match incident_type {
        "data_exfiltration_incident" => "Data exfiltration incident candidate",
        "lateral_movement_incident" => "Lateral movement incident candidate",
        "asset_exposure_incident" => "Asset exposure incident candidate",
        "multi_stage_security_incident" => "Multi-stage security incident candidate",
        _ => "C2 communication incident candidate",
    }
    .to_string()
}

fn entity_type_label(entity_type: &EntityType) -> &'static str {
    match entity_type {
        EntityType::Host => "host",
        EntityType::Process => "process",
        EntityType::Domain => "domain",
        EntityType::Ip => "destination",
        EntityType::CloudResource => "cloud destination",
        EntityType::Service | EntityType::Port => "asset",
        _ => "entity",
    }
}

fn severity_weight(severity: &SecuritySeverity) -> f32 {
    match severity {
        SecuritySeverity::Informational => 0.12,
        SecuritySeverity::Low => 0.25,
        SecuritySeverity::Medium => 0.48,
        SecuritySeverity::High => 0.72,
        SecuritySeverity::Critical => 0.9,
    }
}

fn severity_rank(severity: &SecuritySeverity) -> u8 {
    match severity {
        SecuritySeverity::Informational => 0,
        SecuritySeverity::Low => 1,
        SecuritySeverity::Medium => 2,
        SecuritySeverity::High => 3,
        SecuritySeverity::Critical => 4,
    }
}

fn max_severity(left: &SecuritySeverity, right: &SecuritySeverity) -> SecuritySeverity {
    if severity_rank(left) >= severity_rank(right) {
        left.clone()
    } else {
        right.clone()
    }
}

fn max_quality(left: &QualityScore, right: &QualityScore) -> QualityScore {
    if left.value() >= right.value() {
        left.clone()
    } else {
        right.clone()
    }
}

fn evidence_weight(evidence_count: usize) -> f32 {
    match evidence_count {
        0 => 0.0,
        1 => 0.65,
        2 => 0.82,
        3 => 0.92,
        _ => 1.0,
    }
}

fn bounded_quality(value: f32) -> QualityScore {
    let safe = if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    };
    QualityScore::new(safe).unwrap_or_else(|_| QualityScore::unknown())
}

fn validate_multiplier(field: &'static str, value: f32) -> Result<(), RiskAlertingError> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(RiskAlertingError::InvalidMultiplier(field))
    }
}

fn validate_entity_ref(entity_ref: &EntityRef) -> Result<(), RiskAlertingError> {
    if let Some(name) = &entity_ref.entity_name {
        validate_safe_text("entity_name", name)?;
    }
    if let Some(namespace) = &entity_ref.namespace {
        validate_safe_text("entity_namespace", namespace)?;
    }
    if let Some(source) = &entity_ref.source {
        validate_safe_text("entity_source", source)?;
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), RiskAlertingError> {
    if value.trim().is_empty() {
        return Err(RiskAlertingError::EmptyField(field));
    }
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '/', '=', ':', '?'], "_");
    for marker in [
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
        "raw_command_line",
    ] {
        if normalized.contains(marker) {
            return Err(RiskAlertingError::PrivacyMarker { field });
        }
    }
    Ok(())
}

fn require_safe_text(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, RiskAlertingError> {
    let value = value.into();
    validate_safe_text(field, &value)?;
    Ok(value)
}

fn contract(name: &str) -> Result<ContractDescriptor, ManifestValidationError> {
    ContractDescriptor::new(name, RISK_ALERTING_SCHEMA_VERSION)
}

fn permission(
    key: &str,
    category: PermissionCategory,
    risk_level: PermissionRiskLevel,
    description: &str,
    scopes: &[&str],
) -> Result<PermissionDescriptor, ManifestValidationError> {
    let mut descriptor =
        PermissionDescriptor::new(PermissionKey::new(key)?, category, risk_level, description)?;
    descriptor.scopes = scopes.iter().map(ToString::to_string).collect();
    Ok(descriptor)
}

fn metric(
    name: &str,
    kind: MetricKind,
    description: &str,
) -> Result<MetricSchema, ManifestValidationError> {
    let mut metric = MetricSchema::new(name, kind, description)?;
    metric.privacy_class = PrivacyClass::Internal;
    Ok(metric)
}

fn ui_contribution(
    plugin_id: PluginId,
    slot: UiContributionSlot,
    renderer_type: RendererType,
    title: &str,
    contract_name: &str,
) -> Result<UiContribution, ManifestValidationError> {
    let mut data_source = DataSourceDescriptor::new(DataSourceKind::CapabilityView);
    data_source.contract = Some(contract(contract_name)?);
    let mut contribution = UiContribution::new(plugin_id, slot, renderer_type, title, data_source)?;
    contribution.refresh_mode = RefreshMode::EventDriven;
    contribution.schema = json!({
        "schema_version": RISK_ALERTING_SCHEMA_VERSION,
        "metadata_only": true,
        "risk_based": true
    });
    Ok(contribution)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use sentinel_contracts::{
        FindingExplanation, FindingState, IntelligenceRecordId, ServiceAdapterMode,
        ServiceCapabilityContext, ServiceCapabilityStatus, ServiceLimitationFlag,
        ServiceReasonCode,
    };

    fn q(value: f32) -> QualityScore {
        QualityScore::new(value).expect("quality")
    }

    fn entity(entity_type: EntityType, name: &str) -> EntityRef {
        let mut entity = EntityRef::new(EntityId::new_v4(), entity_type);
        entity.entity_name = Some(name.to_string());
        entity.confidence = q(0.9);
        entity
    }

    fn finding(
        finding_type: &str,
        severity: SecuritySeverity,
        confidence: f32,
        entities: Vec<EntityRef>,
        evidence_count: usize,
    ) -> Finding {
        let evidence_refs = (0..evidence_count)
            .map(|_| EvidenceId::new_v4())
            .collect::<Vec<_>>();
        let mut explanation =
            FindingExplanation::new("metadata-only fixture finding").expect("explanation");
        let mut reason =
            RiskReason::new(finding_type, "metadata-only risk reason").expect("reason");
        reason.confidence = q(confidence);
        reason.evidence_refs = evidence_refs.clone();
        explanation.risk_reasons = vec![reason.clone()];
        Finding::new(finding_type, PluginId::new_v4(), evidence_refs, explanation)
            .expect("finding")
            .with_entity_refs(entities)
            .with_confidence(q(confidence))
            .with_severity(severity)
            .with_risk_reasons(vec![reason])
    }

    fn fixture_input() -> RiskBasedAlertingInput {
        let host = entity(EntityType::Host, "fixture-host");
        let process = entity(EntityType::Process, "fixture-process");
        let domain = entity(EntityType::Domain, "example.test");
        let destination = entity(EntityType::Ip, "198.51.100.24");
        let service = entity(EntityType::Service, "fixture-service");
        let mut input = RiskBasedAlertingInput::new(PluginId::new_v4());
        input.findings = vec![
            finding(
                "security.finding.c2",
                SecuritySeverity::High,
                0.88,
                vec![
                    host.clone(),
                    process.clone(),
                    domain.clone(),
                    destination.clone(),
                ],
                3,
            ),
            finding(
                "security.finding.exfiltration",
                SecuritySeverity::High,
                0.82,
                vec![host.clone(), process.clone(), destination.clone()],
                3,
            ),
            finding(
                "security.finding.asset_risk",
                SecuritySeverity::Medium,
                0.74,
                vec![host.clone(), service.clone()],
                2,
            ),
        ];
        input.entity_criticalities = vec![
            EntityCriticality::new(process.clone(), 1.0, "important local process").expect("crit"),
            EntityCriticality::new(host.clone(), 0.95, "local host criticality").expect("crit"),
            EntityCriticality::new(domain, 0.9, "domain criticality").expect("crit"),
            EntityCriticality::new(destination, 0.9, "destination criticality").expect("crit"),
            EntityCriticality::new(service, 0.7, "asset criticality").expect("crit"),
        ];
        input.risk_hints = vec![RiskHint::new(
            "domain_reputation_hint",
            "local intelligence risk context",
            vec![IntelligenceRecordId::new_v4()],
        )
        .expect("hint")
        .with_risk_delta(0.12)
        .with_confidence(q(0.8))];
        input.labels = vec!["task_430_fixture".to_string()];
        input
    }

    fn service_context(
        capability_id: &str,
        status: ServiceCapabilityStatus,
        reason_code: Option<ServiceReasonCode>,
        limitation_flags: Vec<ServiceLimitationFlag>,
    ) -> ServiceCapabilityContext {
        let mut context = ServiceCapabilityContext::new(
            capability_id,
            ServiceAdapterMode::StubOnly,
            status,
            "service_ipc.fixture",
        )
        .expect("service context");
        context.reason_code = reason_code;
        context.limitation_flags = limitation_flags;
        context
    }

    #[test]
    fn risk_alerting_promotes_multi_signal_story() {
        let output = RiskBasedAlertingPlugin::new()
            .process(fixture_input())
            .expect("risk output");

        assert!(!output.entity_risk_profiles.is_empty());
        assert!(!output.risk_events.is_empty());
        assert!(!output.alert_candidates.is_empty());
        assert!(!output.alerts.is_empty());
        assert!(!output.incident_candidates.is_empty());
        assert!(!output.incidents.is_empty());
        assert!(!output.timelines.is_empty());
        assert!(!output.scopes.is_empty());
        assert!(output
            .entity_risk_profiles
            .iter()
            .any(|profile| profile.entity_ref.entity_type == EntityType::Host));
        assert!(output
            .entity_risk_profiles
            .iter()
            .any(|profile| profile.entity_ref.entity_type == EntityType::Process));
        assert!(output
            .entity_risk_profiles
            .iter()
            .any(|profile| profile.entity_ref.entity_type == EntityType::Domain));
        assert!(output.entity_risk_profiles.iter().any(|profile| matches!(
            profile.entity_ref.entity_type,
            EntityType::Ip | EntityType::CloudResource
        )));
        assert!(output.entity_risk_profiles.iter().any(|profile| matches!(
            profile.entity_ref.entity_type,
            EntityType::Service | EntityType::Port
        )));
        assert!(output
            .alert_decisions
            .iter()
            .any(|decision| decision.promoted));
        assert!(output
            .incidents
            .iter()
            .all(|incident| incident.state() == &sentinel_contracts::IncidentState::Candidate));
    }

    #[test]
    fn low_confidence_single_signal_does_not_alert() {
        let process = entity(EntityType::Process, "quiet-process");
        let mut input = RiskBasedAlertingInput::new(PluginId::new_v4());
        input.findings = vec![finding(
            "security.finding.c2",
            SecuritySeverity::Medium,
            0.36,
            vec![process],
            1,
        )];

        let output = RiskBasedAlertingPlugin::new()
            .process(input)
            .expect("risk output");

        assert!(!output.risk_events.is_empty());
        assert!(!output.alert_candidates.is_empty());
        assert!(output.alerts.is_empty());
        assert!(output.incidents.is_empty());
        assert!(output.alert_decisions.iter().all(|decision| {
            !decision.promoted && decision.reason == AlertPromotionReason::LowConfidenceSingleSignal
        }));
    }

    #[test]
    fn suppression_and_decay_reduce_noise_without_deleting_evidence() {
        let process = entity(EntityType::Process, "known-process");
        let finding = finding(
            "security.finding.c2",
            SecuritySeverity::High,
            0.86,
            vec![process.clone()],
            3,
        );
        let mut input = RiskBasedAlertingInput::new(PluginId::new_v4());
        input.known_good_reductions =
            vec![
                KnownGoodReduction::new(process.clone(), 0.5, "known-good local process context")
                    .expect("known good"),
            ];
        input.suppression_rules = vec![SuppressionRule::new(
            "local_known_process",
            0.35,
            "temporary analyst suppression",
        )
        .expect("rule")
        .for_entity(process.entity_id.clone())];
        input.findings = vec![finding.clone()];

        let output = RiskBasedAlertingPlugin::new()
            .process(input)
            .expect("risk output");

        let profile = output
            .entity_risk_profiles
            .iter()
            .find(|profile| profile.entity_ref.entity_id == process.entity_id)
            .expect("profile");
        assert!(profile.known_good_reduced);
        assert!(profile.suppressed);
        assert!(!profile.evidence_refs.is_empty());
        assert!(output.alerts.is_empty());

        let policy = RiskDecayPolicy::new(1.0, 0.1).expect("policy");
        let old = Timestamp::from_datetime(Utc::now() - Duration::hours(4));
        let now = Timestamp::now();
        assert!(policy.apply_to_score(0.8, &old, &now) < 0.8);
    }

    #[test]
    fn degraded_service_context_reduces_risk_and_confidence_without_blocking_output() {
        let mut baseline_plugin = RiskBasedAlertingPlugin::new();
        let baseline = baseline_plugin
            .process(fixture_input())
            .expect("baseline output");

        let mut degraded_input = fixture_input();
        degraded_input.service_contexts = vec![
            service_context(
                "capture_adapter",
                ServiceCapabilityStatus::Unavailable,
                Some(ServiceReasonCode::CaptureUnavailable),
                vec![
                    ServiceLimitationFlag::StubOnly,
                    ServiceLimitationFlag::MetadataOnly,
                    ServiceLimitationFlag::NoPrivilegedCapture,
                    ServiceLimitationFlag::ReducedVisibility,
                    ServiceLimitationFlag::NoProductionServiceLifecycle,
                ],
            ),
            service_context(
                "process_attribution",
                ServiceCapabilityStatus::Degraded,
                Some(ServiceReasonCode::ProcessAttributionLimited),
                vec![
                    ServiceLimitationFlag::StubOnly,
                    ServiceLimitationFlag::MetadataOnly,
                    ServiceLimitationFlag::NoProcessAttribution,
                    ServiceLimitationFlag::ReducedVisibility,
                    ServiceLimitationFlag::NoProductionServiceLifecycle,
                ],
            ),
        ];
        let mut degraded_plugin = RiskBasedAlertingPlugin::new();
        let degraded = degraded_plugin
            .process(degraded_input)
            .expect("degraded output");

        let baseline_max_score = baseline
            .risk_events
            .iter()
            .map(|event| event.risk_score.value())
            .fold(0.0, f32::max);
        let degraded_max_score = degraded
            .risk_events
            .iter()
            .map(|event| event.risk_score.value())
            .fold(0.0, f32::max);
        let baseline_max_confidence = baseline
            .entity_risk_profiles
            .iter()
            .map(|profile| profile.confidence.value())
            .fold(0.0, f32::max);
        let degraded_max_confidence = degraded
            .entity_risk_profiles
            .iter()
            .map(|profile| profile.confidence.value())
            .fold(0.0, f32::max);
        assert!(degraded_max_score <= baseline_max_score);
        assert!(degraded_max_confidence < baseline_max_confidence);
        assert!(degraded.risk_events.iter().any(|event| {
            event.risk_reasons.iter().any(|reason| {
                reason.reason_type == "service_capture_unavailable"
                    || reason.reason_type == "service_process_visibility_reduced"
            })
        }));
        assert!(!degraded.alert_candidates.is_empty());
    }

    #[test]
    fn service_context_private_marker_is_rejected() {
        let process = entity(EntityType::Process, "fixture-process");
        let mut input = RiskBasedAlertingInput::new(PluginId::new_v4());
        input.findings = vec![finding(
            "security.finding.c2",
            SecuritySeverity::High,
            0.88,
            vec![process],
            1,
        )];
        let mut context = ServiceCapabilityContext::new(
            "capture_adapter",
            ServiceAdapterMode::StubOnly,
            ServiceCapabilityStatus::Unavailable,
            "service_ipc.capture_health",
        )
        .expect("context");
        context.reason_code = Some(ServiceReasonCode::CaptureUnavailable);
        context.limitation_flags = vec![
            ServiceLimitationFlag::StubOnly,
            ServiceLimitationFlag::NoPrivilegedCapture,
        ];
        context.source_provenance_id = "service_ipc.authorization".to_string();
        input.service_contexts = vec![context];

        let error = RiskBasedAlertingPlugin::new()
            .process(input)
            .expect_err("private marker should fail");

        assert!(matches!(
            error,
            RiskAlertingError::PrivacyMarker {
                field: "service.capability_status"
            }
        ));
    }

    #[test]
    fn graph_and_response_boundaries_are_not_crossed() {
        let output = RiskBasedAlertingPlugin::new()
            .process(fixture_input())
            .expect("risk output");
        let serialized = serde_json::to_string(&output).expect("serialize output");

        assert!(!serialized.contains("canonical_graph"));
        assert!(!serialized.contains("graph.update"));
        assert!(!serialized.contains("graph_update"));
        assert!(!serialized.contains("response_action"));
        assert!(!serialized.contains("executes_response"));
    }

    #[test]
    fn plugin_manifest_declares_contracts_permissions_metrics_and_ui() {
        let manifest = RiskBasedAlertingPlugin::manifest().expect("manifest");
        manifest.validate().expect("valid manifest");

        let input_contracts = manifest
            .input_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<HashSet<_>>();
        assert!(input_contracts.contains("security.finding"));
        assert!(input_contracts.contains("security.evidence"));
        assert!(input_contracts.contains("security.risk_hint"));
        assert!(input_contracts.contains("asset.exposure"));
        assert!(input_contracts.contains("identity.process_context"));

        let output_contracts = manifest
            .output_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<HashSet<_>>();
        assert!(output_contracts.contains("security.risk"));
        assert!(output_contracts.contains(ALERT_CANDIDATE_CONTRACT));
        assert!(output_contracts.contains("security.alert"));
        assert!(output_contracts.contains(INCIDENT_CANDIDATE_CONTRACT));
        assert!(output_contracts.contains("security.incident"));
        assert_eq!(manifest.plugin_type, PluginType::PlatformDetection);
        assert_eq!(manifest.statefulness, PluginStatefulness::MemoryState);
        assert!(!manifest.metrics_schema.is_empty());
        assert!(!manifest.ui_contributions.is_empty());
        assert!(manifest.required_permissions.iter().all(|permission| {
            !permission.permission.as_str().contains("response")
                && !permission.permission.as_str().contains("firewall")
                && !permission.permission.as_str().contains("qos")
        }));
        let risk_hint_permission = manifest
            .required_permissions
            .iter()
            .find(|permission| permission.permission.as_str() == "read.security.risk_hint")
            .expect("risk hint read permission");
        assert_eq!(
            risk_hint_permission.scopes,
            vec!["security.risk_hint".to_string()]
        );
        let alert_permission = manifest
            .required_permissions
            .iter()
            .find(|permission| permission.permission.as_str() == "write.security.alert")
            .expect("alert write permission");
        assert!(alert_permission
            .scopes
            .iter()
            .any(|scope| scope == ALERT_CANDIDATE_CONTRACT));
        let incident_permission = manifest
            .required_permissions
            .iter()
            .find(|permission| permission.permission.as_str() == "write.security.incident")
            .expect("incident write permission");
        assert!(incident_permission
            .scopes
            .iter()
            .any(|scope| scope == INCIDENT_CANDIDATE_CONTRACT));
    }

    #[test]
    fn sensitive_metadata_marker_is_rejected() {
        let process = entity(EntityType::Process, "api_key_scanner");
        let mut input = RiskBasedAlertingInput::new(PluginId::new_v4());
        input.findings = vec![finding(
            "security.finding.c2",
            SecuritySeverity::High,
            0.9,
            vec![process],
            2,
        )];

        let error = RiskBasedAlertingPlugin::new()
            .process(input)
            .expect_err("privacy marker rejected");
        assert!(matches!(
            error,
            RiskAlertingError::PrivacyMarker {
                field: "entity_name"
            }
        ));
    }

    #[test]
    fn suppressed_finding_state_does_not_promote() {
        let process = entity(EntityType::Process, "resolved-process");
        let suppressed = finding(
            "security.finding.c2",
            SecuritySeverity::Critical,
            0.95,
            vec![process],
            4,
        )
        .with_state(FindingState::Suppressed);
        let mut input = RiskBasedAlertingInput::new(PluginId::new_v4());
        input.findings = vec![suppressed];

        let output = RiskBasedAlertingPlugin::new()
            .process(input)
            .expect("risk output");

        assert!(output.risk_events.is_empty());
        assert!(output.alert_candidates.is_empty());
        assert!(output.alerts.is_empty());
    }

    #[test]
    fn stale_risk_state_is_not_repromoted_without_active_update() {
        let process = entity(EntityType::Process, "stateful-process");
        let mut plugin = RiskBasedAlertingPlugin::new();
        let mut first_input = RiskBasedAlertingInput::new(PluginId::new_v4());
        first_input.findings = vec![finding(
            "security.finding.c2",
            SecuritySeverity::High,
            0.9,
            vec![process.clone()],
            3,
        )];

        let first_output = plugin.process(first_input).expect("first risk output");
        assert!(!first_output.alerts.is_empty());

        let suppressed = finding(
            "security.finding.c2",
            SecuritySeverity::Critical,
            0.95,
            vec![process],
            4,
        )
        .with_state(FindingState::Suppressed);
        let mut second_input = RiskBasedAlertingInput::new(PluginId::new_v4());
        second_input.findings = vec![suppressed];

        let second_output = plugin.process(second_input).expect("second risk output");

        assert!(second_output.risk_events.is_empty());
        assert!(!second_output.entity_risk_profiles.is_empty());
        assert!(second_output.alert_candidates.is_empty());
        assert!(second_output.alerts.is_empty());
        assert!(second_output.incidents.is_empty());
    }
}
