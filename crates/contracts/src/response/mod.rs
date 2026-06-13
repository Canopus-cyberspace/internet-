use crate::common::{
    AlertId, ApprovalRequestId, ApprovalResultId, AuditId, EntityRef, ErrorCode, FindingId,
    GraphPathId, IncidentId, PolicyDecisionId, QualityScore, RecommendedActionId, ResponseActionId,
    ResponsePlanId, ResponseResultId, RollbackPlanId, RollbackResultId, Timestamp, TraceId,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditRef {
    pub audit_id: AuditId,
    pub event_type: String,
    pub trace_id: Option<TraceId>,
    pub timestamp: Timestamp,
}

impl AuditRef {
    pub fn new(event_type: impl Into<String>) -> Result<Self, ResponseContractError> {
        Ok(Self {
            audit_id: AuditId::new_v4(),
            event_type: require_non_empty("event_type", event_type.into())?,
            trace_id: None,
            timestamp: Timestamp::now(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseLevel {
    RecommendOnly,
    AutoContainmentLite,
    ApprovalRequired,
    NotSupportedInV1,
}

impl ResponseLevel {
    pub fn approval_required(&self) -> bool {
        matches!(self, Self::ApprovalRequired)
    }

    pub fn execution_allowed_by_default(&self) -> bool {
        matches!(self, Self::AutoContainmentLite)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionType {
    RecommendProcessReview,
    RecommendDestinationWatchlist,
    RecommendFirewallBlock,
    RecommendQosThrottle,
    MaliciousDestinationAutoBlock,
    ExfiltrationAutoThrottle,
    DecoyOutboundAutoBlock,
    ApiPolicyRecommendation,
    WafPolicyRecommendation,
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseRuleRef {
    pub rule_id: String,
    pub description: Option<String>,
}

impl ResponseRuleRef {
    pub fn new(rule_id: impl Into<String>) -> Result<Self, ResponseContractError> {
        Ok(Self {
            rule_id: require_non_empty("rule_id", rule_id.into())?,
            description: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseTtl {
    pub duration_seconds: Option<u64>,
    pub expires_at: Option<Timestamp>,
    pub required_for_execution: bool,
}

impl ResponseTtl {
    pub fn recommend_only() -> Self {
        Self {
            duration_seconds: None,
            expires_at: None,
            required_for_execution: false,
        }
    }

    pub fn required(duration_seconds: u64, expires_at: Timestamp) -> Self {
        Self {
            duration_seconds: Some(duration_seconds),
            expires_at: Some(expires_at),
            required_for_execution: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision_id: PolicyDecisionId,
    pub plan_id: Option<ResponsePlanId>,
    pub action_id: Option<ResponseActionId>,
    pub level: ResponseLevel,
    pub reason_redacted: String,
    pub policy_version: String,
    pub matched_rules: Vec<ResponseRuleRef>,
    pub allowlist_ids: Vec<String>,
    pub denylist_ids: Vec<String>,
    pub risk_level: ResponseRiskLevel,
    pub confidence: QualityScore,
    pub ttl: ResponseTtl,
    pub approval_required: bool,
    pub denied_reasons_redacted: Vec<String>,
    pub created_at: Timestamp,
}

impl PolicyDecision {
    pub fn new(
        level: ResponseLevel,
        reason_redacted: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Result<Self, ResponseContractError> {
        Ok(Self {
            decision_id: PolicyDecisionId::new_v4(),
            plan_id: None,
            action_id: None,
            approval_required: level.approval_required(),
            level,
            reason_redacted: require_non_empty("reason_redacted", reason_redacted.into())?,
            policy_version: require_non_empty("policy_version", policy_version.into())?,
            matched_rules: Vec::new(),
            allowlist_ids: Vec::new(),
            denylist_ids: Vec::new(),
            risk_level: ResponseRiskLevel::Low,
            confidence: QualityScore::default(),
            ttl: ResponseTtl::recommend_only(),
            denied_reasons_redacted: Vec::new(),
            created_at: Timestamp::now(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseTarget {
    pub target_entity: Option<EntityRef>,
    pub target_summary_redacted: String,
}

impl ResponseTarget {
    pub fn new(target_summary_redacted: impl Into<String>) -> Result<Self, ResponseContractError> {
        Ok(Self {
            target_entity: None,
            target_summary_redacted: require_non_empty(
                "target_summary_redacted",
                target_summary_redacted.into(),
            )?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseScope {
    pub scope_id: Option<String>,
    pub description_redacted: String,
    pub limited: bool,
    pub preserves_control_plane: bool,
}

impl ResponseScope {
    pub fn limited(description_redacted: impl Into<String>) -> Result<Self, ResponseContractError> {
        Ok(Self {
            scope_id: None,
            description_redacted: require_non_empty(
                "scope description",
                description_redacted.into(),
            )?,
            limited: true,
            preserves_control_plane: true,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RollbackStep {
    pub step_key: String,
    pub description_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RollbackPlan {
    pub rollback_plan_id: RollbackPlanId,
    pub action_id: Option<ResponseActionId>,
    pub rollback_token: String,
    pub rollback_deadline: Option<Timestamp>,
    pub automatic_on_ttl: bool,
    pub steps: Vec<RollbackStep>,
    pub audit_required: bool,
}

impl RollbackPlan {
    pub fn new(rollback_token: impl Into<String>) -> Result<Self, ResponseContractError> {
        Ok(Self {
            rollback_plan_id: RollbackPlanId::new_v4(),
            action_id: None,
            rollback_token: require_non_empty("rollback_token", rollback_token.into())?,
            rollback_deadline: None,
            automatic_on_ttl: true,
            steps: Vec::new(),
            audit_required: true,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub recommended_action_id: RecommendedActionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<ResponseActionId>,
    pub action_type: ResponseActionType,
    pub target: ResponseTarget,
    pub scope: ResponseScope,
    pub expected_effect_redacted: String,
    pub risk_reduction: QualityScore,
    pub business_impact_redacted: String,
    pub preconditions_redacted: Vec<String>,
    pub ttl: ResponseTtl,
    pub rollback_available: bool,
    pub approval_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_state: Option<ApprovalState>,
    pub response_level: ResponseLevel,
}

impl RecommendedAction {
    pub fn new(
        action_type: ResponseActionType,
        target: ResponseTarget,
        scope: ResponseScope,
        expected_effect_redacted: impl Into<String>,
        business_impact_redacted: impl Into<String>,
        response_level: ResponseLevel,
    ) -> Result<Self, ResponseContractError> {
        Ok(Self {
            recommended_action_id: RecommendedActionId::new_v4(),
            action_id: None,
            action_type,
            target,
            scope,
            expected_effect_redacted: require_non_empty(
                "expected_effect_redacted",
                expected_effect_redacted.into(),
            )?,
            risk_reduction: QualityScore::default(),
            business_impact_redacted: require_non_empty(
                "business_impact_redacted",
                business_impact_redacted.into(),
            )?,
            preconditions_redacted: Vec::new(),
            ttl: ResponseTtl::recommend_only(),
            rollback_available: false,
            approval_required: response_level.approval_required(),
            approval_state: None,
            response_level,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlan {
    pub plan_id: ResponsePlanId,
    pub source: ResponsePlanSource,
    pub recommended_actions: Vec<RecommendedAction>,
    pub risk_evaluation_redacted: String,
    pub business_impact_redacted: String,
    pub policy_decisions: Vec<PolicyDecision>,
    pub approval_required: bool,
    pub ttl: ResponseTtl,
    pub rollback_plans: Vec<RollbackPlan>,
    pub audit_requirements: Vec<String>,
    pub created_at: Timestamp,
    pub created_by: String,
    pub is_replay: bool,
    pub execution_disabled_in_replay: bool,
}

impl ResponsePlan {
    pub fn new(
        source: ResponsePlanSource,
        created_by: impl Into<String>,
    ) -> Result<Self, ResponseContractError> {
        Ok(Self {
            plan_id: ResponsePlanId::new_v4(),
            source,
            recommended_actions: Vec::new(),
            risk_evaluation_redacted: String::new(),
            business_impact_redacted: String::new(),
            policy_decisions: Vec::new(),
            approval_required: false,
            ttl: ResponseTtl::recommend_only(),
            rollback_plans: Vec::new(),
            audit_requirements: vec!["audit_required".to_string()],
            created_at: Timestamp::now(),
            created_by: require_non_empty("created_by", created_by.into())?,
            is_replay: false,
            execution_disabled_in_replay: false,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ResponsePlanSource {
    Finding(FindingId),
    Alert(AlertId),
    Incident(IncidentId),
    GraphPath(GraphPathId),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    NotRequired,
    Requested,
    Approved,
    Rejected,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseAction {
    pub action_id: ResponseActionId,
    pub plan_id: ResponsePlanId,
    pub recommended_action_id: RecommendedActionId,
    pub action_type: ResponseActionType,
    pub target: ResponseTarget,
    pub scope: ResponseScope,
    pub ttl: ResponseTtl,
    pub policy_decision: PolicyDecision,
    pub approval_state: ApprovalState,
    pub audit_ref: AuditRef,
    pub rollback_plan: RollbackPlan,
    pub replay_safe: bool,
    pub execution_disabled_in_replay: bool,
    pub created_at: Timestamp,
}

impl ResponseAction {
    pub fn new(
        plan_id: ResponsePlanId,
        recommended_action: RecommendedAction,
        policy_decision: PolicyDecision,
        audit_ref: AuditRef,
        rollback_plan: RollbackPlan,
    ) -> Self {
        Self {
            action_id: ResponseActionId::new_v4(),
            plan_id,
            recommended_action_id: recommended_action.recommended_action_id,
            action_type: recommended_action.action_type,
            target: recommended_action.target,
            scope: recommended_action.scope,
            ttl: recommended_action.ttl,
            approval_state: if policy_decision.approval_required {
                ApprovalState::Requested
            } else {
                ApprovalState::NotRequired
            },
            policy_decision,
            audit_ref,
            rollback_plan,
            replay_safe: true,
            execution_disabled_in_replay: true,
            created_at: Timestamp::now(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub approval_request_id: ApprovalRequestId,
    pub plan_id: ResponsePlanId,
    pub action_id: ResponseActionId,
    pub incident_id: Option<IncidentId>,
    pub evidence_count: u32,
    pub risk_score: QualityScore,
    pub affected_scope_redacted: String,
    pub recommended_action_redacted: String,
    pub business_impact_redacted: String,
    pub rollback_available: bool,
    pub policy_decision: PolicyDecision,
    pub audit_ref: AuditRef,
    pub requested_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalResult {
    pub approval_result_id: ApprovalResultId,
    pub approval_request_id: ApprovalRequestId,
    pub plan_id: ResponsePlanId,
    pub action_id: ResponseActionId,
    pub actor: String,
    pub decision: ApprovalDecision,
    pub reason_redacted: Option<String>,
    pub timestamp: Timestamp,
    pub policy_version: String,
    pub audit_ref: AuditRef,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseResult {
    pub result_id: ResponseResultId,
    pub action_id: ResponseActionId,
    pub executor: String,
    pub target: ResponseTarget,
    pub started_at: Timestamp,
    pub ended_at: Option<Timestamp>,
    pub success: bool,
    pub error_code: Option<ErrorCode>,
    pub error_summary_redacted: Option<String>,
    pub rollback_token: String,
    pub rollback_deadline: Option<Timestamp>,
    pub rollback_plan_ref: RollbackPlanId,
    pub audit_ref: AuditRef,
    pub is_replay: bool,
    pub execution_disabled: bool,
}

impl ResponseResult {
    pub fn new(
        action_id: ResponseActionId,
        executor: impl Into<String>,
        target: ResponseTarget,
        rollback_plan: &RollbackPlan,
        audit_ref: AuditRef,
    ) -> Result<Self, ResponseContractError> {
        Ok(Self {
            result_id: ResponseResultId::new_v4(),
            action_id,
            executor: require_non_empty("executor", executor.into())?,
            target,
            started_at: Timestamp::now(),
            ended_at: None,
            success: false,
            error_code: None,
            error_summary_redacted: None,
            rollback_token: rollback_plan.rollback_token.clone(),
            rollback_deadline: rollback_plan.rollback_deadline.clone(),
            rollback_plan_ref: rollback_plan.rollback_plan_id.clone(),
            audit_ref,
            is_replay: false,
            execution_disabled: false,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RollbackResult {
    pub rollback_result_id: RollbackResultId,
    pub action_id: ResponseActionId,
    pub rollback_plan_ref: RollbackPlanId,
    pub rollback_token: String,
    pub started_at: Timestamp,
    pub ended_at: Option<Timestamp>,
    pub success: bool,
    pub error_summary_redacted: Option<String>,
    pub audit_ref: AuditRef,
    pub is_replay: bool,
}

impl RollbackResult {
    pub fn new(
        action_id: ResponseActionId,
        rollback_plan: &RollbackPlan,
        audit_ref: AuditRef,
    ) -> Self {
        Self {
            rollback_result_id: RollbackResultId::new_v4(),
            action_id,
            rollback_plan_ref: rollback_plan.rollback_plan_id.clone(),
            rollback_token: rollback_plan.rollback_token.clone(),
            started_at: Timestamp::now(),
            ended_at: None,
            success: false,
            error_summary_redacted: None,
            audit_ref,
            is_replay: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseContractError {
    EmptyField(&'static str),
}

impl fmt::Display for ResponseContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
        }
    }
}

impl std::error::Error for ResponseContractError {}

fn require_non_empty(field: &'static str, value: String) -> Result<String, ResponseContractError> {
    if value.trim().is_empty() {
        return Err(ResponseContractError::EmptyField(field));
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_action_includes_policy_audit_ttl_and_rollback() {
        let plan_id = ResponsePlanId::new_v4();
        let target = ResponseTarget::new("redacted destination").expect("target");
        let scope = ResponseScope::limited("single destination").expect("scope");
        let recommended = RecommendedAction::new(
            ResponseActionType::RecommendFirewallBlock,
            target.clone(),
            scope,
            "reduce outbound risk",
            "manual review required",
            ResponseLevel::RecommendOnly,
        )
        .expect("recommended action");
        let policy = PolicyDecision::new(ResponseLevel::RecommendOnly, "recommend only", "v1")
            .expect("policy");
        let audit = AuditRef::new("response.action.created").expect("audit");
        let rollback = RollbackPlan::new("rollback-token").expect("rollback");
        let action = ResponseAction::new(plan_id, recommended, policy, audit, rollback);

        assert!(!action.ttl.required_for_execution);
        assert_eq!(action.rollback_plan.rollback_token, "rollback-token");
        assert_eq!(action.audit_ref.event_type, "response.action.created");
        assert_eq!(action.policy_decision.level, ResponseLevel::RecommendOnly);
    }

    #[test]
    fn response_result_carries_audit_rollback_and_replay_flags() {
        let target = ResponseTarget::new("redacted destination").expect("target");
        let rollback = RollbackPlan::new("rollback-token").expect("rollback");
        let audit = AuditRef::new("response.action.completed").expect("audit");
        let mut result = ResponseResult::new(
            ResponseActionId::new_v4(),
            "recommendation_only",
            target,
            &rollback,
            audit,
        )
        .expect("result");
        result.is_replay = true;
        result.execution_disabled = true;

        assert_eq!(result.rollback_plan_ref, rollback.rollback_plan_id);
        assert_eq!(result.rollback_token, "rollback-token");
        assert!(result.is_replay);
        assert!(result.execution_disabled);
    }
}
