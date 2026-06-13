use chrono::{Duration, Utc};
use sentinel_contracts::{
    Alert, ContractDescriptor, DataSourceDescriptor, DataSourceKind, EntityRef, EntityType,
    Finding, GraphPath, GraphPathType, Incident, ManifestValidationError, MaturityLevel,
    MetricKind, MetricSchema, PermissionCategory, PermissionDescriptor, PermissionKey,
    PermissionRiskLevel, PluginId, PluginManifest, PluginStatefulness, PluginType, PrivacyClass,
    QualityScore, RecommendedAction, RefreshMode, RendererType, ResponseActionType,
    ResponseContractError, ResponseLevel, ResponsePlan, ResponsePlanSource, ResponsePolicy,
    ResponseRiskLevel, ResponseRuleRef, ResponseScope, ResponseTarget, ResponseTtl, RollbackPlan,
    RollbackStep, RuntimeMode, SchemaVersion, SecuritySeverity, SupportLevel, Timestamp,
    UiContribution, UiContributionSlot, MAX_AUTO_CONTAINMENT_TTL_SECONDS, SETTINGS_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt;

pub const RESPONSE_PLANNING_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const RESPONSE_PLANNING_PLUGIN_NAME: &str = "response_policy_planning";
pub const RESPONSE_PLAN_CONTRACT: &str = "response.plan";
pub const RESPONSE_POLICY_DECISION_CONTRACT: &str = "response.policy.decision";
pub const RESPONSE_POLICY_SETTINGS_CONTRACT: &str = "settings.response_policy";
pub const RESPONSE_POLICY_RULE_CONTRACT: &str = "settings.response_policy_rule";

const DEFAULT_POLICY_VERSION: &str = "response-policy-v1";
const MIN_AUTO_EVIDENCE_COUNT: usize = 2;
const MAX_AUTO_SCOPE_ENTITIES: usize = 1;

#[derive(Clone, Debug, PartialEq)]
pub enum ResponsePlanningError {
    EmptyInput,
    EmptyField(&'static str),
    InvalidTtl(&'static str),
    PrivacyMarker { field: &'static str },
    Manifest(ManifestValidationError),
    Response(ResponseContractError),
}

impl fmt::Display for ResponsePlanningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(
                f,
                "response planning input requires findings, alerts, incidents, or graph paths"
            ),
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::InvalidTtl(field) => write!(f, "{field} must be within V1 TTL limits"),
            Self::PrivacyMarker { field } => {
                write!(f, "{field} contains a forbidden sensitive marker")
            }
            Self::Manifest(error) => write!(f, "{error}"),
            Self::Response(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ResponsePlanningError {}

impl From<ManifestValidationError> for ResponsePlanningError {
    fn from(value: ManifestValidationError) -> Self {
        Self::Manifest(value)
    }
}

impl From<ResponseContractError> for ResponsePlanningError {
    fn from(value: ResponseContractError) -> Self {
        Self::Response(value)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlanningInput {
    pub producer_plugin: PluginId,
    pub response_policy: ResponsePolicy,
    pub findings: Vec<Finding>,
    pub alerts: Vec<Alert>,
    pub incidents: Vec<Incident>,
    pub graph_paths: Vec<GraphPath>,
    pub policy_rules: Vec<ResponsePolicyRule>,
    pub is_replay: bool,
    pub labels: Vec<String>,
    pub observed_at: Timestamp,
}

impl ResponsePlanningInput {
    pub fn new(producer_plugin: PluginId) -> Self {
        Self {
            producer_plugin,
            response_policy: ResponsePolicy::recommend_only(),
            findings: Vec::new(),
            alerts: Vec::new(),
            incidents: Vec::new(),
            graph_paths: Vec::new(),
            policy_rules: Vec::new(),
            is_replay: false,
            labels: Vec::new(),
            observed_at: Timestamp::now(),
        }
    }

    pub fn with_response_policy(mut self, response_policy: ResponsePolicy) -> Self {
        self.response_policy = response_policy;
        self
    }

    pub fn with_replay(mut self) -> Self {
        self.is_replay = true;
        self.response_policy.replay_execution_disabled = true;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlanningOutput {
    pub response_plans: Vec<ResponsePlan>,
    pub policy_decisions: Vec<sentinel_contracts::PolicyDecision>,
    pub business_impacts: Vec<BusinessImpactAssessment>,
    pub risk_reductions: Vec<RiskReductionEstimate>,
    pub approval_requirements: Vec<ApprovalRequirementResolution>,
    pub rollback_plans: Vec<RollbackPlan>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsePolicyRule {
    pub rule_id: String,
    pub action_type: ResponseActionType,
    pub decision: ResponseLevel,
    pub description_redacted: String,
    pub min_evidence_count: usize,
    pub max_scope_entities: usize,
    pub ttl_seconds: Option<u64>,
    pub requires_rollback: bool,
    pub requires_audit: bool,
    pub requires_approval: bool,
    pub high_impact: bool,
    pub enabled: bool,
}

impl ResponsePolicyRule {
    pub fn new(
        rule_id: impl Into<String>,
        action_type: ResponseActionType,
        decision: ResponseLevel,
        description_redacted: impl Into<String>,
    ) -> Result<Self, ResponsePlanningError> {
        Ok(Self {
            rule_id: require_safe_text("response_policy_rule.rule_id", rule_id)?,
            action_type,
            decision,
            description_redacted: require_safe_text(
                "response_policy_rule.description",
                description_redacted,
            )?,
            min_evidence_count: MIN_AUTO_EVIDENCE_COUNT,
            max_scope_entities: MAX_AUTO_SCOPE_ENTITIES,
            ttl_seconds: None,
            requires_rollback: true,
            requires_audit: true,
            requires_approval: false,
            high_impact: false,
            enabled: true,
        })
    }

    pub fn for_action(action_type: ResponseActionType, decision: ResponseLevel) -> Self {
        Self {
            rule_id: format!("v1:{}", action_key(&action_type)),
            action_type,
            decision,
            description_redacted: "V1 response planning rule".to_string(),
            min_evidence_count: MIN_AUTO_EVIDENCE_COUNT,
            max_scope_entities: MAX_AUTO_SCOPE_ENTITIES,
            ttl_seconds: None,
            requires_rollback: true,
            requires_audit: true,
            requires_approval: false,
            high_impact: false,
            enabled: true,
        }
    }

    pub fn with_ttl_seconds(mut self, ttl_seconds: u64) -> Self {
        self.ttl_seconds = Some(ttl_seconds);
        self
    }

    pub fn with_high_impact(mut self) -> Self {
        self.high_impact = true;
        self.requires_approval = true;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseActionCandidate {
    pub action_type: ResponseActionType,
    pub target: ResponseTarget,
    pub scope: ResponseScope,
    pub expected_effect_redacted: String,
    pub preconditions_redacted: Vec<String>,
    pub evidence_count: usize,
    pub scope_entity_count: usize,
    pub severity: SecuritySeverity,
    pub confidence: QualityScore,
    pub ttl_seconds: Option<u64>,
    pub rollback_available: bool,
    pub audit_available: bool,
    pub high_impact: bool,
    pub broad_scope: bool,
    pub permanent: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BusinessImpactAssessment {
    pub action_type: ResponseActionType,
    pub impact_level: ResponseRiskLevel,
    pub summary_redacted: String,
    pub approval_required: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RiskReductionEstimate {
    pub action_type: ResponseActionType,
    pub score: QualityScore,
    pub summary_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequirementResolution {
    pub action_type: ResponseActionType,
    pub approval_required: bool,
    pub reason_redacted: String,
}

#[derive(Clone, Debug)]
pub struct ResponsePlanningPlugin {
    planner: ResponsePlanner,
}

impl Default for ResponsePlanningPlugin {
    fn default() -> Self {
        Self {
            planner: ResponsePlanner::new(),
        }
    }
}

impl ResponsePlanningPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn manifest() -> Result<PluginManifest, ResponsePlanningError> {
        let plugin_id = PluginId::new_v4();
        let mut manifest = PluginManifest::new(
            plugin_id.clone(),
            RESPONSE_PLANNING_PLUGIN_NAME,
            "0.1.0",
            "response_planning",
            PluginType::Response,
            RuntimeMode::OnDemand,
        )?;
        manifest.description =
            "Recommend-first response planning and isolation policy decisions without execution."
                .to_string();
        manifest.enabled_by_default = true;
        manifest.maturity_level = MaturityLevel::L3Modeling;
        manifest.capability_tags = vec![
            "local_first".to_string(),
            "metadata_first".to_string(),
            "recommend_first".to_string(),
            "rollback_required".to_string(),
            "audit_required".to_string(),
        ];
        manifest.input_contracts = [
            "security.finding",
            "security.alert",
            "security.incident",
            "graph.path",
            RESPONSE_POLICY_SETTINGS_CONTRACT,
            RESPONSE_POLICY_RULE_CONTRACT,
        ]
        .into_iter()
        .map(contract)
        .collect::<Result<Vec<_>, _>>()?;
        manifest.output_contracts = [
            RESPONSE_PLAN_CONTRACT,
            RESPONSE_POLICY_DECISION_CONTRACT,
            "response.recommended_action",
        ]
        .into_iter()
        .map(contract)
        .collect::<Result<Vec<_>, _>>()?;
        manifest.required_permissions = vec![
            permission(
                "read.security.finding",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "Read evidence-backed findings for response planning.",
                &["security.finding"],
            )?,
            permission(
                "read.security.alert",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "Read traceable alerts for response planning.",
                &["security.alert"],
            )?,
            permission(
                "read.security.incident",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "Read incidents for response planning.",
                &["security.incident"],
            )?,
            permission(
                "read.graph.path",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "Read redacted graph paths for response planning.",
                &["graph.path"],
            )?,
            permission(
                "read.settings.response_policy",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "Read response policy settings and scoped rule overrides for response planning.",
                &[
                    RESPONSE_POLICY_SETTINGS_CONTRACT,
                    RESPONSE_POLICY_RULE_CONTRACT,
                ],
            )?,
            permission(
                "write.response.plan",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Medium,
                "Write response plans and policy decisions through Local Core.",
                &[RESPONSE_PLAN_CONTRACT, RESPONSE_POLICY_DECISION_CONTRACT],
            )?,
        ];
        manifest.metrics_schema = vec![
            metric(
                "response_planning.sources_in_total",
                MetricKind::Counter,
                "Planning sources processed",
            )?,
            metric(
                "response_planning.plans_out_total",
                MetricKind::Counter,
                "Response plans produced",
            )?,
            metric(
                "response_planning.policy_decisions_total",
                MetricKind::Counter,
                "Policy decisions produced",
            )?,
        ];
        manifest.ui_contributions = vec![ui_contribution(
            plugin_id,
            UiContributionSlot::ResponseActionPanel,
            RendererType::ResponseActionCard,
            "Response Plan",
            RESPONSE_PLAN_CONTRACT,
        )?];
        manifest.statefulness = PluginStatefulness::Stateless;
        manifest.checkpoint_support = SupportLevel::Optional;
        manifest.replay_support = SupportLevel::Required;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn process(
        &self,
        input: ResponsePlanningInput,
    ) -> Result<ResponsePlanningOutput, ResponsePlanningError> {
        self.planner.plan(input)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ResponsePlanner {
    policy_evaluator: IsolationPolicyEvaluator,
    business_impact_evaluator: BusinessImpactEvaluator,
    risk_reduction_estimator: RiskReductionEstimator,
    rollback_planner: RollbackPlanner,
    approval_requirement_resolver: ApprovalRequirementResolver,
}

impl ResponsePlanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn plan(
        &self,
        input: ResponsePlanningInput,
    ) -> Result<ResponsePlanningOutput, ResponsePlanningError> {
        validate_input(&input)?;
        let sources = planning_sources(&input);
        if sources.is_empty() {
            return Err(ResponsePlanningError::EmptyInput);
        }

        let rules = effective_rules(&input.response_policy, &input.policy_rules);
        let mut output = ResponsePlanningOutput {
            response_plans: Vec::new(),
            policy_decisions: Vec::new(),
            business_impacts: Vec::new(),
            risk_reductions: Vec::new(),
            approval_requirements: Vec::new(),
            rollback_plans: Vec::new(),
        };

        for source in sources {
            let mut plan = ResponsePlan::new(
                source.source.clone(),
                format!(
                    "{}:{}",
                    RESPONSE_PLANNING_PLUGIN_NAME, input.producer_plugin
                ),
            )?;
            plan.is_replay = input.is_replay;
            plan.execution_disabled_in_replay =
                input.is_replay || input.response_policy.replay_execution_disabled;
            plan.risk_evaluation_redacted = source.risk_summary_redacted.clone();

            let candidates = self.recommended_candidates(&source, &input.response_policy)?;
            let mut plan_business_summaries = Vec::new();
            for candidate in candidates {
                let business_impact = self.business_impact_evaluator.evaluate(&candidate)?;
                let risk_reduction = self.risk_reduction_estimator.estimate(&candidate)?;
                let mut policy_decision = self.policy_evaluator.evaluate(
                    &candidate,
                    &input.response_policy,
                    &rules,
                    input.is_replay,
                )?;
                policy_decision.plan_id = Some(plan.plan_id.clone());
                policy_decision.confidence = candidate.confidence.clone();
                let approval_requirement = self.approval_requirement_resolver.resolve(
                    &candidate,
                    &policy_decision,
                    &business_impact,
                );
                let rollback_plan =
                    self.rollback_planner
                        .plan_for(&candidate, &policy_decision, &plan.plan_id)?;

                let mut recommended = RecommendedAction::new(
                    candidate.action_type.clone(),
                    candidate.target.clone(),
                    candidate.scope.clone(),
                    candidate.expected_effect_redacted.clone(),
                    business_impact.summary_redacted.clone(),
                    policy_decision.level.clone(),
                )?;
                recommended.risk_reduction = risk_reduction.score.clone();
                recommended.preconditions_redacted = candidate.preconditions_redacted.clone();
                recommended.ttl = policy_decision.ttl.clone();
                recommended.rollback_available =
                    candidate.rollback_available && is_execution_candidate(&candidate.action_type);
                recommended.approval_required = approval_requirement.approval_required;
                recommended.response_level = policy_decision.level.clone();

                plan.approval_required |= approval_requirement.approval_required;
                if policy_decision.ttl.required_for_execution {
                    plan.ttl = policy_decision.ttl.clone();
                }
                plan_business_summaries.push(business_impact.summary_redacted.clone());
                plan.recommended_actions.push(recommended);
                plan.policy_decisions.push(policy_decision.clone());
                plan.rollback_plans.push(rollback_plan.clone());
                output.policy_decisions.push(policy_decision);
                output.business_impacts.push(business_impact);
                output.risk_reductions.push(risk_reduction);
                output.approval_requirements.push(approval_requirement);
                output.rollback_plans.push(rollback_plan);
            }

            plan.business_impact_redacted = summarize_business_impact(&plan_business_summaries);
            plan.audit_requirements = audit_requirements_for_plan(&plan);
            output.response_plans.push(plan);
        }

        Ok(output)
    }

    fn recommended_candidates(
        &self,
        source: &PlanningSourceContext,
        policy: &ResponsePolicy,
    ) -> Result<Vec<ResponseActionCandidate>, ResponsePlanningError> {
        let mut candidates = vec![
            candidate(
                ResponseActionType::RecommendProcessReview,
                source,
                "Review the associated process and provenance metadata.",
                "analyst review, no privileged adapter call",
                None,
                false,
            )?,
            candidate(
                ResponseActionType::RecommendDestinationWatchlist,
                source,
                "Add the destination to the local watchlist for continued monitoring.",
                "local watchlist recommendation, no privileged adapter call",
                None,
                false,
            )?,
        ];

        if source.suggests_c2_or_malicious_destination() {
            candidates.push(candidate(
                ResponseActionType::RecommendFirewallBlock,
                source,
                "Recommend a temporary scoped destination block after review.",
                "manual approval required before any privileged adapter call",
                None,
                true,
            )?);
            candidates.push(candidate(
                ResponseActionType::MaliciousDestinationAutoBlock,
                source,
                "Candidate for temporary scoped destination block.",
                "temporary single-destination containment candidate",
                Some(policy.auto_containment_ttl_seconds),
                false,
            )?);
        }

        if source.suggests_exfiltration_or_upload() {
            candidates.push(candidate(
                ResponseActionType::RecommendQosThrottle,
                source,
                "Recommend a temporary scoped throttle for suspicious upload traffic after review.",
                "manual approval required before any privileged adapter call",
                None,
                true,
            )?);
            candidates.push(candidate(
                ResponseActionType::ExfiltrationAutoThrottle,
                source,
                "Candidate for temporary scoped throttle of suspected exfiltration traffic.",
                "temporary scoped throttle candidate",
                Some(policy.auto_containment_ttl_seconds),
                false,
            )?);
        }

        if candidates.len() == 2 {
            candidates.push(candidate(
                ResponseActionType::RecommendFirewallBlock,
                source,
                "Recommend a scoped destination block only if later evidence confirms need.",
                "manual approval required before any privileged adapter call",
                None,
                true,
            )?);
        }

        Ok(candidates)
    }
}

#[derive(Clone, Debug, Default)]
pub struct IsolationPolicyEvaluator;

impl IsolationPolicyEvaluator {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(
        &self,
        candidate: &ResponseActionCandidate,
        policy: &ResponsePolicy,
        rules: &[ResponsePolicyRule],
        is_replay: bool,
    ) -> Result<sentinel_contracts::PolicyDecision, ResponsePlanningError> {
        let rule = matching_rule(candidate, rules);
        let mut matched_rules = Vec::new();
        let mut allowlist_ids = Vec::new();
        let mut denylist_ids = Vec::new();
        let mut denied_reasons = Vec::new();

        if let Some(rule) = rule {
            matched_rules.push(ResponseRuleRef {
                rule_id: rule.rule_id.clone(),
                description: Some(rule.description_redacted.clone()),
            });
        }

        let action_key = action_key(&candidate.action_type);
        let denylist_hit = denylist_reason(candidate)
            .or_else(|| missing_required_safety_reason(candidate, policy));

        let level = if let Some(reason) = denylist_hit {
            denylist_ids.push(action_key.clone());
            denied_reasons.push(reason);
            ResponseLevel::NotSupportedInV1
        } else if is_replay
            && policy.replay_execution_disabled
            && is_auto_candidate(&candidate.action_type)
        {
            denied_reasons.push("execution disabled in replay mode".to_string());
            ResponseLevel::RecommendOnly
        } else if let Some(rule) = rule {
            decision_from_rule(candidate, policy, rule, &mut denied_reasons)
        } else {
            decision_from_default(candidate, policy, &mut denied_reasons)
        };

        if matches!(level, ResponseLevel::AutoContainmentLite) {
            allowlist_ids.push(action_key.clone());
        }

        let mut decision = sentinel_contracts::PolicyDecision::new(
            level.clone(),
            decision_reason(&level, candidate, policy),
            policy_version(),
        )?;
        decision.matched_rules = matched_rules;
        decision.allowlist_ids = allowlist_ids;
        decision.denylist_ids = denylist_ids;
        decision.risk_level = response_risk_level(&candidate.severity);
        decision.ttl = ttl_for_decision(candidate, policy, &level)?;
        decision.approval_required =
            matches!(level, ResponseLevel::ApprovalRequired) || candidate.high_impact;
        decision.denied_reasons_redacted = denied_reasons;
        Ok(decision)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BusinessImpactEvaluator;

impl BusinessImpactEvaluator {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(
        &self,
        candidate: &ResponseActionCandidate,
    ) -> Result<BusinessImpactAssessment, ResponsePlanningError> {
        let impact_level = if candidate.broad_scope || candidate.high_impact {
            ResponseRiskLevel::High
        } else if matches!(
            candidate.action_type,
            ResponseActionType::MaliciousDestinationAutoBlock
                | ResponseActionType::ExfiltrationAutoThrottle
        ) {
            ResponseRiskLevel::Medium
        } else {
            ResponseRiskLevel::Low
        };
        let summary_redacted = match impact_level {
            ResponseRiskLevel::Low => {
                "low business impact; recommendation or local monitoring only".to_string()
            }
            ResponseRiskLevel::Medium => {
                "medium business impact; scoped temporary containment candidate".to_string()
            }
            ResponseRiskLevel::High | ResponseRiskLevel::Critical => {
                "high business impact; human approval required before action".to_string()
            }
        };

        Ok(BusinessImpactAssessment {
            action_type: candidate.action_type.clone(),
            impact_level,
            approval_required: candidate.high_impact || candidate.broad_scope,
            summary_redacted,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct RiskReductionEstimator;

impl RiskReductionEstimator {
    pub fn new() -> Self {
        Self
    }

    pub fn estimate(
        &self,
        candidate: &ResponseActionCandidate,
    ) -> Result<RiskReductionEstimate, ResponsePlanningError> {
        let base = match candidate.action_type {
            ResponseActionType::RecommendProcessReview => 0.25,
            ResponseActionType::RecommendDestinationWatchlist => 0.3,
            ResponseActionType::RecommendFirewallBlock => 0.55,
            ResponseActionType::RecommendQosThrottle => 0.5,
            ResponseActionType::MaliciousDestinationAutoBlock => 0.75,
            ResponseActionType::ExfiltrationAutoThrottle => 0.7,
            ResponseActionType::DecoyOutboundAutoBlock => 0.65,
            ResponseActionType::ApiPolicyRecommendation
            | ResponseActionType::WafPolicyRecommendation => 0.35,
            ResponseActionType::Custom(_) => 0.2,
        };
        let confidence_adjustment = candidate.confidence.value() * 0.2;
        let evidence_adjustment = (candidate.evidence_count.min(4) as f32) * 0.03;
        let score = q((base + confidence_adjustment + evidence_adjustment).min(1.0))?;
        Ok(RiskReductionEstimate {
            action_type: candidate.action_type.clone(),
            score,
            summary_redacted:
                "estimated from severity, confidence, evidence count, and action scope".to_string(),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct RollbackPlanner;

impl RollbackPlanner {
    pub fn new() -> Self {
        Self
    }

    pub fn plan_for(
        &self,
        candidate: &ResponseActionCandidate,
        decision: &sentinel_contracts::PolicyDecision,
        plan_id: &sentinel_contracts::ResponsePlanId,
    ) -> Result<RollbackPlan, ResponsePlanningError> {
        let mut rollback = RollbackPlan::new(format!(
            "rollback:{}:{}",
            action_key(&candidate.action_type),
            plan_id
        ))?;
        rollback.rollback_deadline = decision.ttl.expires_at.clone();
        rollback.automatic_on_ttl = decision.ttl.required_for_execution
            && matches!(decision.level, ResponseLevel::AutoContainmentLite);
        rollback.audit_required = true;
        rollback.steps = rollback_steps(candidate, decision);
        Ok(rollback)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ApprovalRequirementResolver;

impl ApprovalRequirementResolver {
    pub fn new() -> Self {
        Self
    }

    pub fn resolve(
        &self,
        candidate: &ResponseActionCandidate,
        decision: &sentinel_contracts::PolicyDecision,
        business_impact: &BusinessImpactAssessment,
    ) -> ApprovalRequirementResolution {
        let approval_required = decision.approval_required
            || business_impact.approval_required
            || matches!(decision.level, ResponseLevel::ApprovalRequired);
        let reason_redacted = if approval_required {
            "approval required by response policy, impact, or scope".to_string()
        } else if matches!(decision.level, ResponseLevel::AutoContainmentLite) {
            "auto containment lite candidate satisfies V1 safety requirements".to_string()
        } else {
            "recommendation only; no approval required for planning".to_string()
        };
        ApprovalRequirementResolution {
            action_type: candidate.action_type.clone(),
            approval_required,
            reason_redacted,
        }
    }
}

#[derive(Clone)]
struct PlanningSourceContext {
    source: ResponsePlanSource,
    source_kind: String,
    severity: SecuritySeverity,
    confidence: QualityScore,
    evidence_count: usize,
    entity_refs: Vec<EntityRef>,
    graph_path_type: Option<GraphPathType>,
    risk_summary_redacted: String,
}

impl PlanningSourceContext {
    fn suggests_c2_or_malicious_destination(&self) -> bool {
        let kind = self.source_kind.to_ascii_lowercase();
        kind.contains("c2")
            || kind.contains("malicious")
            || kind.contains("destination")
            || matches!(
                self.graph_path_type,
                Some(GraphPathType::ProcessToC2Path | GraphPathType::ResponseImpactPath)
            )
    }

    fn suggests_exfiltration_or_upload(&self) -> bool {
        let kind = self.source_kind.to_ascii_lowercase();
        kind.contains("exfil")
            || kind.contains("upload")
            || kind.contains("cloud")
            || matches!(
                self.graph_path_type,
                Some(GraphPathType::ProcessToCloudUploadPath)
            )
    }
}

fn validate_input(input: &ResponsePlanningInput) -> Result<(), ResponsePlanningError> {
    input
        .response_policy
        .validate()
        .map_err(|_| ResponsePlanningError::InvalidTtl("response_policy.auto_containment_ttl"))?;
    for label in &input.labels {
        validate_safe_text("response_planning.labels", label)?;
    }
    for rule in &input.policy_rules {
        validate_policy_rule(rule)?;
    }
    Ok(())
}

fn validate_policy_rule(rule: &ResponsePolicyRule) -> Result<(), ResponsePlanningError> {
    validate_safe_text("response_policy_rule.rule_id", &rule.rule_id)?;
    validate_safe_text(
        "response_policy_rule.description",
        &rule.description_redacted,
    )?;
    if rule.min_evidence_count == 0 {
        return Err(ResponsePlanningError::InvalidTtl(
            "response_policy_rule.min_evidence_count",
        ));
    }
    if rule.max_scope_entities == 0 || rule.max_scope_entities > MAX_AUTO_SCOPE_ENTITIES {
        return Err(ResponsePlanningError::InvalidTtl(
            "response_policy_rule.max_scope_entities",
        ));
    }
    if let Some(ttl_seconds) = rule.ttl_seconds {
        if ttl_seconds == 0 || ttl_seconds > MAX_AUTO_CONTAINMENT_TTL_SECONDS {
            return Err(ResponsePlanningError::InvalidTtl(
                "response_policy_rule.ttl_seconds",
            ));
        }
    }
    Ok(())
}

fn planning_sources(input: &ResponsePlanningInput) -> Vec<PlanningSourceContext> {
    let mut sources = Vec::new();
    sources.extend(input.findings.iter().map(|finding| PlanningSourceContext {
        source: ResponsePlanSource::Finding(finding.id().clone()),
        source_kind: finding.finding_type().to_string(),
        severity: finding.severity().clone(),
        confidence: finding.confidence().clone(),
        evidence_count: finding.evidence_refs().len(),
        entity_refs: finding.entity_refs().to_vec(),
        graph_path_type: None,
        risk_summary_redacted: format!(
            "{} severity finding with {} evidence reference(s)",
            severity_label(finding.severity()),
            finding.evidence_refs().len()
        ),
    }));
    sources.extend(input.alerts.iter().map(|alert| PlanningSourceContext {
        source: ResponsePlanSource::Alert(alert.id().clone()),
        source_kind: format!("{} {}", alert.title_redacted(), alert.summary_redacted()),
        severity: alert.severity().clone(),
        confidence: alert.confidence().clone(),
        evidence_count: (alert.finding_refs().len() + alert.risk_event_refs().len()).max(1),
        entity_refs: alert.entity_refs().to_vec(),
        graph_path_type: None,
        risk_summary_redacted: format!(
            "{} severity alert with {} finding reference(s)",
            severity_label(alert.severity()),
            alert.finding_refs().len()
        ),
    }));
    sources.extend(input.incidents.iter().map(|incident| {
        PlanningSourceContext {
            source: ResponsePlanSource::Incident(incident.id().clone()),
            source_kind: incident.incident_type().to_string(),
            severity: incident.severity().clone(),
            confidence: incident.confidence().clone(),
            evidence_count: (incident.alert_refs().len()
                + incident.finding_refs().len()
                + incident.graph_path_refs().len())
            .max(1),
            entity_refs: Vec::new(),
            graph_path_type: None,
            risk_summary_redacted: format!(
                "{} severity incident with traceable alert/finding/graph references",
                severity_label(incident.severity())
            ),
        }
    }));
    sources.extend(input.graph_paths.iter().map(|path| PlanningSourceContext {
        source: ResponsePlanSource::GraphPath(path.path_id.clone()),
        source_kind: format!("{:?}", path.path_type),
        severity: severity_from_quality(&path.risk_score),
        confidence: path.confidence.clone(),
        evidence_count: (path.evidence_refs.len() + path.edge_sequence.len()).max(1),
        entity_refs: Vec::new(),
        graph_path_type: Some(path.path_type.clone()),
        risk_summary_redacted: format!(
            "graph path risk {:.2} with {} evidence reference(s)",
            path.risk_score.value(),
            path.evidence_refs.len()
        ),
    }));
    sources
}

fn candidate(
    action_type: ResponseActionType,
    source: &PlanningSourceContext,
    expected_effect_redacted: &str,
    precondition: &str,
    ttl_seconds: Option<u64>,
    high_impact: bool,
) -> Result<ResponseActionCandidate, ResponsePlanningError> {
    let target_entity = target_entity_for_action(&action_type, &source.entity_refs);
    let target = target_for_action(&action_type, target_entity.clone())?;
    let scope = scope_for_action(&action_type)?;
    Ok(ResponseActionCandidate {
        action_type,
        target,
        scope,
        expected_effect_redacted: require_safe_text(
            "response_action.expected_effect",
            expected_effect_redacted,
        )?,
        preconditions_redacted: vec![require_safe_text(
            "response_action.precondition",
            precondition,
        )?],
        evidence_count: source.evidence_count,
        scope_entity_count: 1,
        severity: source.severity.clone(),
        confidence: source.confidence.clone(),
        ttl_seconds,
        rollback_available: true,
        audit_available: true,
        high_impact,
        broad_scope: false,
        permanent: false,
    })
}

fn target_entity_for_action(
    action_type: &ResponseActionType,
    entities: &[EntityRef],
) -> Option<EntityRef> {
    let preferred = match action_type {
        ResponseActionType::RecommendProcessReview => &[EntityType::Process][..],
        ResponseActionType::RecommendDestinationWatchlist
        | ResponseActionType::RecommendFirewallBlock
        | ResponseActionType::MaliciousDestinationAutoBlock => {
            &[EntityType::Ip, EntityType::Domain, EntityType::Url][..]
        }
        ResponseActionType::RecommendQosThrottle | ResponseActionType::ExfiltrationAutoThrottle => {
            &[
                EntityType::CloudResource,
                EntityType::Ip,
                EntityType::Domain,
                EntityType::Process,
            ][..]
        }
        _ => &[][..],
    };

    entities
        .iter()
        .find(|entity| preferred.contains(&entity.entity_type))
        .or_else(|| entities.first())
        .map(redacted_entity_ref)
}

fn target_for_action(
    action_type: &ResponseActionType,
    entity_ref: Option<EntityRef>,
) -> Result<ResponseTarget, ResponsePlanningError> {
    let summary = match action_type {
        ResponseActionType::RecommendProcessReview => "redacted process target",
        ResponseActionType::RecommendDestinationWatchlist
        | ResponseActionType::RecommendFirewallBlock
        | ResponseActionType::MaliciousDestinationAutoBlock => "redacted destination target",
        ResponseActionType::RecommendQosThrottle | ResponseActionType::ExfiltrationAutoThrottle => {
            "redacted upload path target"
        }
        ResponseActionType::DecoyOutboundAutoBlock => "redacted decoy outbound target",
        ResponseActionType::ApiPolicyRecommendation => "redacted API policy target",
        ResponseActionType::WafPolicyRecommendation => "redacted WAF policy target",
        ResponseActionType::Custom(_) => "redacted response target",
    };
    let mut target = ResponseTarget::new(summary)?;
    target.target_entity = entity_ref;
    Ok(target)
}

fn scope_for_action(
    action_type: &ResponseActionType,
) -> Result<ResponseScope, ResponsePlanningError> {
    match action_type {
        ResponseActionType::RecommendProcessReview => {
            ResponseScope::limited("single process review scope").map_err(Into::into)
        }
        ResponseActionType::RecommendDestinationWatchlist => {
            ResponseScope::limited("single destination watchlist scope").map_err(Into::into)
        }
        ResponseActionType::RecommendFirewallBlock
        | ResponseActionType::MaliciousDestinationAutoBlock => {
            ResponseScope::limited("single destination temporary scope").map_err(Into::into)
        }
        ResponseActionType::RecommendQosThrottle | ResponseActionType::ExfiltrationAutoThrottle => {
            ResponseScope::limited("single upload path temporary scope").map_err(Into::into)
        }
        ResponseActionType::DecoyOutboundAutoBlock => {
            ResponseScope::limited("single decoy outbound temporary scope").map_err(Into::into)
        }
        ResponseActionType::ApiPolicyRecommendation => {
            ResponseScope::limited("single API policy recommendation scope").map_err(Into::into)
        }
        ResponseActionType::WafPolicyRecommendation => {
            ResponseScope::limited("single WAF policy recommendation scope").map_err(Into::into)
        }
        ResponseActionType::Custom(_) => {
            ResponseScope::limited("single custom response planning scope").map_err(Into::into)
        }
    }
}

fn redacted_entity_ref(entity: &EntityRef) -> EntityRef {
    EntityRef {
        entity_id: entity.entity_id.clone(),
        entity_type: entity.entity_type.clone(),
        entity_name: None,
        namespace: None,
        source: None,
        confidence: entity.confidence.clone(),
        first_seen: entity.first_seen.clone(),
        last_seen: entity.last_seen.clone(),
    }
}

fn effective_rules(
    policy: &ResponsePolicy,
    custom_rules: &[ResponsePolicyRule],
) -> Vec<ResponsePolicyRule> {
    let mut rules = default_rules(policy);
    rules.extend(custom_rules.iter().filter(|rule| rule.enabled).cloned());
    rules
}

fn default_rules(policy: &ResponsePolicy) -> Vec<ResponsePolicyRule> {
    vec![
        ResponsePolicyRule::for_action(
            ResponseActionType::RecommendProcessReview,
            ResponseLevel::RecommendOnly,
        ),
        ResponsePolicyRule::for_action(
            ResponseActionType::RecommendDestinationWatchlist,
            ResponseLevel::RecommendOnly,
        ),
        ResponsePolicyRule::for_action(
            ResponseActionType::RecommendFirewallBlock,
            ResponseLevel::ApprovalRequired,
        )
        .with_high_impact(),
        ResponsePolicyRule::for_action(
            ResponseActionType::RecommendQosThrottle,
            ResponseLevel::ApprovalRequired,
        )
        .with_high_impact(),
        ResponsePolicyRule::for_action(
            ResponseActionType::MaliciousDestinationAutoBlock,
            ResponseLevel::AutoContainmentLite,
        )
        .with_ttl_seconds(policy.auto_containment_ttl_seconds),
        ResponsePolicyRule::for_action(
            ResponseActionType::ExfiltrationAutoThrottle,
            ResponseLevel::AutoContainmentLite,
        )
        .with_ttl_seconds(policy.auto_containment_ttl_seconds),
        ResponsePolicyRule::for_action(
            ResponseActionType::ApiPolicyRecommendation,
            ResponseLevel::RecommendOnly,
        ),
        ResponsePolicyRule::for_action(
            ResponseActionType::WafPolicyRecommendation,
            ResponseLevel::RecommendOnly,
        ),
    ]
}

fn matching_rule<'a>(
    candidate: &ResponseActionCandidate,
    rules: &'a [ResponsePolicyRule],
) -> Option<&'a ResponsePolicyRule> {
    rules
        .iter()
        .rev()
        .find(|rule| rule.enabled && same_action(&rule.action_type, &candidate.action_type))
}

fn decision_from_rule(
    candidate: &ResponseActionCandidate,
    policy: &ResponsePolicy,
    rule: &ResponsePolicyRule,
    denied_reasons: &mut Vec<String>,
) -> ResponseLevel {
    if matches!(rule.decision, ResponseLevel::AutoContainmentLite) {
        return auto_decision(candidate, policy, rule, denied_reasons);
    }
    if rule.requires_approval || rule.high_impact || candidate.high_impact || candidate.broad_scope
    {
        return ResponseLevel::ApprovalRequired;
    }
    match policy.mode {
        sentinel_contracts::ResponseMode::RecommendOnly => ResponseLevel::RecommendOnly,
        sentinel_contracts::ResponseMode::ApprovalRequired
            if is_execution_candidate(&candidate.action_type) =>
        {
            ResponseLevel::ApprovalRequired
        }
        _ => rule.decision.clone(),
    }
}

fn decision_from_default(
    candidate: &ResponseActionCandidate,
    policy: &ResponsePolicy,
    denied_reasons: &mut Vec<String>,
) -> ResponseLevel {
    if is_auto_candidate(&candidate.action_type) {
        let rule = ResponsePolicyRule::for_action(
            candidate.action_type.clone(),
            ResponseLevel::AutoContainmentLite,
        )
        .with_ttl_seconds(policy.auto_containment_ttl_seconds);
        return auto_decision(candidate, policy, &rule, denied_reasons);
    }
    if candidate.high_impact || candidate.broad_scope {
        ResponseLevel::ApprovalRequired
    } else {
        ResponseLevel::RecommendOnly
    }
}

fn auto_decision(
    candidate: &ResponseActionCandidate,
    policy: &ResponsePolicy,
    rule: &ResponsePolicyRule,
    denied_reasons: &mut Vec<String>,
) -> ResponseLevel {
    if !is_allowed_auto_action(&candidate.action_type, policy) {
        denied_reasons.push("action is outside auto-containment allowlist".to_string());
        return match policy.mode {
            sentinel_contracts::ResponseMode::RecommendOnly => ResponseLevel::RecommendOnly,
            _ => ResponseLevel::ApprovalRequired,
        };
    }
    if candidate.evidence_count < rule.min_evidence_count {
        denied_reasons.push("auto containment requires at least two evidence sources".to_string());
        return ResponseLevel::ApprovalRequired;
    }
    if candidate.scope_entity_count > rule.max_scope_entities
        || candidate.broad_scope
        || !candidate.scope.limited
        || !candidate.scope.preserves_control_plane
    {
        denied_reasons
            .push("auto containment requires limited control-plane-preserving scope".to_string());
        return ResponseLevel::ApprovalRequired;
    }
    if candidate.ttl_seconds.is_none() || candidate.ttl_seconds.unwrap_or_default() == 0 {
        denied_reasons.push("auto containment requires TTL metadata".to_string());
        return ResponseLevel::NotSupportedInV1;
    }
    if !candidate.rollback_available || !rule.requires_rollback || !policy.rollback_required {
        denied_reasons.push("auto containment requires rollback metadata".to_string());
        return ResponseLevel::NotSupportedInV1;
    }
    if !candidate.audit_available || !rule.requires_audit || !policy.audit_required {
        denied_reasons.push("auto containment requires audit metadata".to_string());
        return ResponseLevel::NotSupportedInV1;
    }
    if candidate.high_impact || candidate.permanent {
        denied_reasons.push("high-impact or permanent action requires approval".to_string());
        return ResponseLevel::ApprovalRequired;
    }

    match policy.mode {
        sentinel_contracts::ResponseMode::AutoContainmentLite => ResponseLevel::AutoContainmentLite,
        sentinel_contracts::ResponseMode::ApprovalRequired => ResponseLevel::ApprovalRequired,
        sentinel_contracts::ResponseMode::RecommendOnly => {
            denied_reasons.push("current response policy is recommend-only".to_string());
            ResponseLevel::RecommendOnly
        }
    }
}

fn denylist_reason(candidate: &ResponseActionCandidate) -> Option<String> {
    let key = action_key(&candidate.action_type);
    let denied = [
        "production_host_full_isolation",
        "segment_isolation",
        "vlan_quarantine",
        "production_port_block",
        "waf_enforcement_block",
        "api_deny_policy",
        "privileged_identity_lockout",
        "database_network_isolation",
        "message_queue_network_isolation",
        "shared_infrastructure_isolation",
        "global_firewall_block",
        "permanent_deny_rule_without_ttl",
        "action_without_rollback",
        "action_without_audit",
        "process_kill",
        "user_account_disable",
        "delete_file",
        "delete_registry_key",
        "host_isolation",
        "process_network_isolation",
    ];
    let key_hit = denied.iter().any(|value| key.contains(value));
    let scope = candidate.scope.description_redacted.to_ascii_lowercase();
    let target = candidate
        .target
        .target_summary_redacted
        .to_ascii_lowercase();
    let broad_target = [
        "0.0.0.0/0",
        "entire local subnet",
        "default gateway",
        "all dns",
        "all https",
        "global",
        "wildcard",
    ]
    .iter()
    .any(|marker| scope.contains(marker) || target.contains(marker));

    if key_hit || broad_target || candidate.permanent {
        Some("action is denylisted or too broad for personal PC V1".to_string())
    } else {
        None
    }
}

fn missing_required_safety_reason(
    candidate: &ResponseActionCandidate,
    policy: &ResponsePolicy,
) -> Option<String> {
    if !is_execution_candidate(&candidate.action_type) {
        return None;
    }
    if !candidate.rollback_available || !policy.rollback_required {
        return Some("action without rollback is not supported in V1".to_string());
    }
    if !candidate.audit_available || !policy.audit_required {
        return Some("action without audit is not supported in V1".to_string());
    }
    None
}

fn ttl_for_decision(
    candidate: &ResponseActionCandidate,
    policy: &ResponsePolicy,
    level: &ResponseLevel,
) -> Result<ResponseTtl, ResponsePlanningError> {
    if !matches!(level, ResponseLevel::AutoContainmentLite) {
        return Ok(ResponseTtl::recommend_only());
    }
    let ttl_seconds = candidate
        .ttl_seconds
        .ok_or(ResponsePlanningError::InvalidTtl("candidate.ttl_seconds"))?;
    if ttl_seconds == 0 || ttl_seconds > policy.auto_containment_max_ttl_seconds {
        return Err(ResponsePlanningError::InvalidTtl("candidate.ttl_seconds"));
    }
    let expires_at = Timestamp::from_datetime(Utc::now() + Duration::seconds(ttl_seconds as i64));
    Ok(ResponseTtl::required(ttl_seconds, expires_at))
}

fn rollback_steps(
    candidate: &ResponseActionCandidate,
    decision: &sentinel_contracts::PolicyDecision,
) -> Vec<RollbackStep> {
    let mut steps = Vec::new();
    if decision.ttl.required_for_execution {
        steps.push(RollbackStep {
            step_key: "ttl_expiry".to_string(),
            description_redacted: "roll back temporary scoped response when TTL expires"
                .to_string(),
        });
    } else {
        steps.push(RollbackStep {
            step_key: "no_state_change".to_string(),
            description_redacted: "no privileged state change is created by this recommendation"
                .to_string(),
        });
    }
    steps.push(RollbackStep {
        step_key: "audit_rollback_result".to_string(),
        description_redacted: format!(
            "record rollback result for {}",
            action_key(&candidate.action_type)
        ),
    });
    steps
}

fn audit_requirements_for_plan(plan: &ResponsePlan) -> Vec<String> {
    let mut requirements = vec![
        "response.plan.created".to_string(),
        "response.policy.decision".to_string(),
        "response.rollback.result".to_string(),
    ];
    if plan.approval_required {
        requirements.push("response.approval.requested".to_string());
    }
    if plan
        .policy_decisions
        .iter()
        .any(|decision| matches!(decision.level, ResponseLevel::AutoContainmentLite))
    {
        requirements.push("response.action.started".to_string());
        requirements.push("response.action.completed_or_failed".to_string());
    }
    requirements.sort();
    requirements.dedup();
    requirements
}

fn summarize_business_impact(summaries: &[String]) -> String {
    if summaries.iter().any(|summary| {
        summary
            .to_ascii_lowercase()
            .contains("high business impact")
    }) {
        "highest proposed impact requires human approval before execution".to_string()
    } else if summaries.iter().any(|summary| {
        summary
            .to_ascii_lowercase()
            .contains("medium business impact")
    }) {
        "highest proposed impact is scoped temporary containment".to_string()
    } else {
        "recommendation-only plan has low business impact".to_string()
    }
}

fn decision_reason(
    level: &ResponseLevel,
    candidate: &ResponseActionCandidate,
    policy: &ResponsePolicy,
) -> String {
    match level {
        ResponseLevel::RecommendOnly => {
            "recommend-first policy selected; no action is performed".to_string()
        }
        ResponseLevel::AutoContainmentLite => format!(
            "{} satisfies allowlist, TTL, evidence, rollback, audit, and scope requirements",
            action_key(&candidate.action_type)
        ),
        ResponseLevel::ApprovalRequired => {
            "approval required by impact, scope, policy mode, or allowlist status".to_string()
        }
        ResponseLevel::NotSupportedInV1 => format!(
            "{} is not supported in V1 policy mode {}",
            action_key(&candidate.action_type),
            response_policy_mode_label(policy)
        ),
    }
}

fn response_policy_mode_label(policy: &ResponsePolicy) -> &'static str {
    match policy.mode {
        sentinel_contracts::ResponseMode::RecommendOnly => "recommend_only",
        sentinel_contracts::ResponseMode::AutoContainmentLite => "auto_containment_lite",
        sentinel_contracts::ResponseMode::ApprovalRequired => "approval_required",
    }
}

fn response_risk_level(severity: &SecuritySeverity) -> ResponseRiskLevel {
    match severity {
        SecuritySeverity::Critical => ResponseRiskLevel::Critical,
        SecuritySeverity::High => ResponseRiskLevel::High,
        SecuritySeverity::Medium => ResponseRiskLevel::Medium,
        SecuritySeverity::Informational | SecuritySeverity::Low => ResponseRiskLevel::Low,
    }
}

fn severity_from_quality(score: &QualityScore) -> SecuritySeverity {
    match score.value() {
        value if value >= 0.9 => SecuritySeverity::Critical,
        value if value >= 0.7 => SecuritySeverity::High,
        value if value >= 0.4 => SecuritySeverity::Medium,
        value if value > 0.0 => SecuritySeverity::Low,
        _ => SecuritySeverity::Informational,
    }
}

fn severity_label(severity: &SecuritySeverity) -> &'static str {
    match severity {
        SecuritySeverity::Informational => "informational",
        SecuritySeverity::Low => "low",
        SecuritySeverity::Medium => "medium",
        SecuritySeverity::High => "high",
        SecuritySeverity::Critical => "critical",
    }
}

fn same_action(left: &ResponseActionType, right: &ResponseActionType) -> bool {
    action_key(left) == action_key(right)
}

fn is_auto_candidate(action_type: &ResponseActionType) -> bool {
    matches!(
        action_type,
        ResponseActionType::MaliciousDestinationAutoBlock
            | ResponseActionType::ExfiltrationAutoThrottle
            | ResponseActionType::DecoyOutboundAutoBlock
    )
}

fn is_execution_candidate(action_type: &ResponseActionType) -> bool {
    is_auto_candidate(action_type)
        || matches!(
            action_type,
            ResponseActionType::RecommendFirewallBlock | ResponseActionType::RecommendQosThrottle
        )
}

fn is_allowed_auto_action(action_type: &ResponseActionType, policy: &ResponsePolicy) -> bool {
    if !matches!(
        policy.mode,
        sentinel_contracts::ResponseMode::AutoContainmentLite
            | sentinel_contracts::ResponseMode::ApprovalRequired
    ) {
        return false;
    }
    let key = action_key(action_type);
    policy
        .allowed_auto_actions
        .iter()
        .any(|value| value == &key)
}

fn action_key(action_type: &ResponseActionType) -> String {
    match action_type {
        ResponseActionType::RecommendProcessReview => "recommend_process_review",
        ResponseActionType::RecommendDestinationWatchlist => "recommend_destination_watchlist",
        ResponseActionType::RecommendFirewallBlock => "recommend_firewall_block",
        ResponseActionType::RecommendQosThrottle => "recommend_qos_throttle",
        ResponseActionType::MaliciousDestinationAutoBlock => "malicious_destination_auto_block",
        ResponseActionType::ExfiltrationAutoThrottle => "exfiltration_auto_throttle",
        ResponseActionType::DecoyOutboundAutoBlock => "decoy_outbound_auto_block",
        ResponseActionType::ApiPolicyRecommendation => "api_policy_recommendation",
        ResponseActionType::WafPolicyRecommendation => "waf_policy_recommendation",
        ResponseActionType::Custom(value) => value.as_str(),
    }
    .to_string()
}

fn policy_version() -> String {
    format!("{DEFAULT_POLICY_VERSION}:{}", SETTINGS_SCHEMA_VERSION)
}

fn q(value: f32) -> Result<QualityScore, ResponsePlanningError> {
    QualityScore::new(value.clamp(0.0, 1.0))
        .map_err(|_| ResponsePlanningError::InvalidTtl("quality_score"))
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), ResponsePlanningError> {
    if value.trim().is_empty() {
        return Err(ResponsePlanningError::EmptyField(field));
    }
    let normalized = value.to_ascii_lowercase();
    for marker in [
        "raw_packet",
        "raw payload",
        "raw_payload",
        "payload body",
        "http_body",
        "cookie",
        "credential",
        "api_key",
        "private_key",
        "authorization",
        "session_token",
        "access_token",
        "refresh_token",
        "secret",
        "form_content",
        "query_string",
        "raw_command_line",
    ] {
        if normalized.contains(marker) {
            return Err(ResponsePlanningError::PrivacyMarker { field });
        }
    }
    Ok(())
}

fn require_safe_text(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, ResponsePlanningError> {
    let value = value.into();
    validate_safe_text(field, &value)?;
    Ok(value)
}

fn contract(name: &str) -> Result<ContractDescriptor, ManifestValidationError> {
    ContractDescriptor::new(name, RESPONSE_PLANNING_SCHEMA_VERSION)
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
        "schema_version": RESPONSE_PLANNING_SCHEMA_VERSION,
        "metadata_only": true,
        "recommend_first": true,
        "execution_disabled_in_replay": true
    });
    Ok(contribution)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        EntityId, EvidenceId, FindingExplanation, GraphNodeId, RedactedLabel, RedactionStatus,
    };
    use std::collections::HashSet;

    fn q_score(value: f32) -> QualityScore {
        QualityScore::new(value).expect("quality")
    }

    fn entity(entity_type: EntityType, name: &str) -> EntityRef {
        let mut entity = EntityRef::new(EntityId::new_v4(), entity_type);
        entity.entity_name = Some(name.to_string());
        entity.confidence = q_score(0.9);
        entity
    }

    fn finding(
        finding_type: &str,
        severity: SecuritySeverity,
        confidence: f32,
        evidence_count: usize,
    ) -> Finding {
        let evidence_refs = (0..evidence_count)
            .map(|_| EvidenceId::new_v4())
            .collect::<Vec<_>>();
        let explanation = FindingExplanation::new("metadata-only fixture finding").unwrap();
        Finding::new(finding_type, PluginId::new_v4(), evidence_refs, explanation)
            .unwrap()
            .with_entity_refs(vec![
                entity(EntityType::Process, "fixture-process"),
                entity(EntityType::Ip, "198.51.100.10"),
            ])
            .with_severity(severity)
            .with_confidence(q_score(confidence))
    }

    fn graph_path(path_type: GraphPathType) -> GraphPath {
        let mut path = GraphPath::new(
            path_type,
            vec![GraphNodeId::new_v4(), GraphNodeId::new_v4()],
            vec![],
            RedactedLabel::new(
                "redacted path",
                RedactionStatus::Redacted,
                PrivacyClass::Internal,
            )
            .unwrap(),
        )
        .unwrap();
        path.risk_score = q_score(0.78);
        path.confidence = q_score(0.84);
        path.evidence_refs = vec![EvidenceId::new_v4(), EvidenceId::new_v4()];
        path
    }

    #[test]
    fn response_planning_builds_recommend_first_plans_from_sources() {
        let plugin = ResponsePlanningPlugin::new();
        let alert_finding = finding("security.finding.c2", SecuritySeverity::High, 0.88, 2);
        let alert = Alert::new(
            "redacted c2 alert",
            "redacted malicious destination",
            vec![alert_finding.id().clone()],
        )
        .unwrap()
        .with_severity(SecuritySeverity::High)
        .with_confidence(q_score(0.86));
        let incident = Incident::new(
            "data_exfiltration_incident",
            "redacted exfil incident",
            "redacted upload path",
            vec![alert.id().clone()],
        )
        .unwrap()
        .with_finding_refs(vec![alert_finding.id().clone()])
        .with_graph_path_refs(vec![
            graph_path(GraphPathType::ProcessToCloudUploadPath).path_id,
        ])
        .with_severity(SecuritySeverity::High)
        .with_confidence(q_score(0.82));
        let mut input = ResponsePlanningInput::new(PluginId::new_v4())
            .with_response_policy(ResponsePolicy::auto_containment_lite());
        input.findings = vec![alert_finding];
        input.alerts = vec![alert];
        input.incidents = vec![incident];
        input.graph_paths = vec![graph_path(GraphPathType::ProcessToCloudUploadPath)];

        let output = plugin.process(input).expect("response plans");

        assert!(output.response_plans.len() >= 4);
        let action_keys = output
            .response_plans
            .iter()
            .flat_map(|plan| plan.recommended_actions.iter())
            .map(|action| action_key(&action.action_type))
            .collect::<HashSet<_>>();
        assert!(action_keys.contains("recommend_process_review"));
        assert!(action_keys.contains("recommend_destination_watchlist"));
        assert!(action_keys.contains("recommend_firewall_block"));
        assert!(action_keys.contains("recommend_qos_throttle"));
        assert!(action_keys.contains("malicious_destination_auto_block"));
        assert!(action_keys.contains("exfiltration_auto_throttle"));
        for plan in &output.response_plans {
            assert!(!plan.policy_decisions.is_empty());
            assert!(!plan.rollback_plans.is_empty());
            assert!(plan
                .audit_requirements
                .iter()
                .any(|event| event == "response.policy.decision"));
        }
    }

    #[test]
    fn policy_evaluator_returns_all_required_decisions() {
        let evaluator = IsolationPolicyEvaluator::new();
        let policy = ResponsePolicy::auto_containment_lite();
        let rules = default_rules(&policy);
        let source = PlanningSourceContext {
            source: ResponsePlanSource::GraphPath(sentinel_contracts::GraphPathId::new_v4()),
            source_kind: "security.finding.c2".to_string(),
            severity: SecuritySeverity::High,
            confidence: q_score(0.9),
            evidence_count: 2,
            entity_refs: vec![entity(EntityType::Ip, "198.51.100.1")],
            graph_path_type: Some(GraphPathType::ProcessToC2Path),
            risk_summary_redacted: "redacted risk".to_string(),
        };
        let recommend = candidate(
            ResponseActionType::RecommendProcessReview,
            &source,
            "Review the associated process and provenance metadata.",
            "analyst review",
            None,
            false,
        )
        .unwrap();
        let auto = candidate(
            ResponseActionType::MaliciousDestinationAutoBlock,
            &source,
            "Candidate temporary block.",
            "temporary scoped candidate",
            Some(policy.auto_containment_ttl_seconds),
            false,
        )
        .unwrap();
        let approval = candidate(
            ResponseActionType::RecommendFirewallBlock,
            &source,
            "Recommend temporary block.",
            "manual approval",
            None,
            true,
        )
        .unwrap();
        let unsupported = ResponseActionCandidate {
            action_type: ResponseActionType::Custom("process_kill".to_string()),
            ..approval.clone()
        };

        assert_eq!(
            evaluator
                .evaluate(&recommend, &policy, &rules, false)
                .unwrap()
                .level,
            ResponseLevel::RecommendOnly
        );
        assert_eq!(
            evaluator
                .evaluate(&auto, &policy, &rules, false)
                .unwrap()
                .level,
            ResponseLevel::AutoContainmentLite
        );
        assert_eq!(
            evaluator
                .evaluate(&approval, &policy, &rules, false)
                .unwrap()
                .level,
            ResponseLevel::ApprovalRequired
        );
        assert_eq!(
            evaluator
                .evaluate(&unsupported, &policy, &rules, false)
                .unwrap()
                .level,
            ResponseLevel::NotSupportedInV1
        );
    }

    #[test]
    fn denylist_actions_are_never_allowed_for_auto_execution() {
        let evaluator = IsolationPolicyEvaluator::new();
        let policy = ResponsePolicy::auto_containment_lite();
        let source = PlanningSourceContext {
            source: ResponsePlanSource::Finding(sentinel_contracts::FindingId::new_v4()),
            source_kind: "security.finding.c2".to_string(),
            severity: SecuritySeverity::Critical,
            confidence: q_score(0.95),
            evidence_count: 3,
            entity_refs: vec![entity(EntityType::Host, "fixture-host")],
            graph_path_type: None,
            risk_summary_redacted: "critical risk".to_string(),
        };

        for action in [
            "production_host_full_isolation",
            "global_firewall_block",
            "permanent_deny_rule_without_ttl",
            "waf_enforcement_block",
            "api_deny_policy",
            "process_kill",
        ] {
            let blocked = ResponseActionCandidate {
                action_type: ResponseActionType::Custom(action.to_string()),
                ..candidate(
                    ResponseActionType::MaliciousDestinationAutoBlock,
                    &source,
                    "Candidate temporary block.",
                    "temporary scoped candidate",
                    Some(policy.auto_containment_ttl_seconds),
                    false,
                )
                .unwrap()
            };
            let decision = evaluator
                .evaluate(&blocked, &policy, &default_rules(&policy), false)
                .unwrap();
            assert_eq!(decision.level, ResponseLevel::NotSupportedInV1);
            assert!(!decision.allowlist_ids.contains(&action.to_string()));
        }
    }

    #[test]
    fn auto_containment_candidates_require_scope_ttl_evidence_rollback_and_audit() {
        let evaluator = IsolationPolicyEvaluator::new();
        let policy = ResponsePolicy::auto_containment_lite();
        let source = PlanningSourceContext {
            source: ResponsePlanSource::Finding(sentinel_contracts::FindingId::new_v4()),
            source_kind: "security.finding.c2".to_string(),
            severity: SecuritySeverity::High,
            confidence: q_score(0.9),
            evidence_count: 1,
            entity_refs: vec![entity(EntityType::Ip, "198.51.100.4")],
            graph_path_type: None,
            risk_summary_redacted: "high risk".to_string(),
        };
        let mut candidate = candidate(
            ResponseActionType::MaliciousDestinationAutoBlock,
            &source,
            "Candidate temporary block.",
            "temporary scoped candidate",
            Some(policy.auto_containment_ttl_seconds),
            false,
        )
        .unwrap();

        let low_evidence = evaluator
            .evaluate(&candidate, &policy, &default_rules(&policy), false)
            .unwrap();
        assert_ne!(low_evidence.level, ResponseLevel::AutoContainmentLite);

        candidate.evidence_count = 2;
        candidate.ttl_seconds = None;
        let missing_ttl = evaluator
            .evaluate(&candidate, &policy, &default_rules(&policy), false)
            .unwrap();
        assert_eq!(missing_ttl.level, ResponseLevel::NotSupportedInV1);

        candidate.ttl_seconds = Some(policy.auto_containment_ttl_seconds);
        candidate.rollback_available = false;
        let missing_rollback = evaluator
            .evaluate(&candidate, &policy, &default_rules(&policy), false)
            .unwrap();
        assert_eq!(missing_rollback.level, ResponseLevel::NotSupportedInV1);

        candidate.rollback_available = true;
        candidate.audit_available = false;
        let missing_audit = evaluator
            .evaluate(&candidate, &policy, &default_rules(&policy), false)
            .unwrap();
        assert_eq!(missing_audit.level, ResponseLevel::NotSupportedInV1);
    }

    #[test]
    fn replay_planning_disables_execution_by_default() {
        let plugin = ResponsePlanningPlugin::new();
        let mut input = ResponsePlanningInput::new(PluginId::new_v4())
            .with_response_policy(ResponsePolicy::auto_containment_lite())
            .with_replay();
        input.findings = vec![finding(
            "security.finding.c2",
            SecuritySeverity::High,
            0.9,
            3,
        )];

        let output = plugin.process(input).expect("replay output");
        assert!(output
            .response_plans
            .iter()
            .all(|plan| plan.is_replay && plan.execution_disabled_in_replay));
        assert!(output
            .policy_decisions
            .iter()
            .filter(|decision| {
                decision
                    .matched_rules
                    .iter()
                    .any(|rule| rule.rule_id.contains("malicious_destination_auto_block"))
            })
            .all(|decision| decision.level != ResponseLevel::AutoContainmentLite));
    }

    #[test]
    fn plugin_manifest_declares_planning_without_execution_permissions() {
        let manifest = ResponsePlanningPlugin::manifest().expect("manifest");

        assert_eq!(manifest.plugin_type, PluginType::Response);
        assert!(manifest
            .output_contracts
            .iter()
            .any(|contract| contract.contract_name == RESPONSE_PLAN_CONTRACT));
        assert!(manifest
            .input_contracts
            .iter()
            .any(|contract| contract.contract_name == RESPONSE_POLICY_RULE_CONTRACT));
        assert!(manifest
            .output_contracts
            .iter()
            .any(|contract| contract.contract_name == RESPONSE_POLICY_DECISION_CONTRACT));
        assert!(manifest
            .required_permissions
            .iter()
            .all(|permission| !permission.permission.as_str().contains("execute")));
        assert!(manifest
            .required_permissions
            .iter()
            .all(|permission| !permission.permission.as_str().contains("firewall.write")));
        assert!(manifest
            .required_permissions
            .iter()
            .all(|permission| !permission.permission.as_str().contains("qos.write")));
        assert!(manifest.replay_support == SupportLevel::Required);
    }
}
