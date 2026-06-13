use sentinel_contracts::{
    ApprovalDecision, ApprovalRequest, ApprovalRequestId, ApprovalResult, AuditRef, ErrorCode,
    IncidentId, QualityScore, ResponseAction, ResponseActionId, ResponseActionType,
    ResponseContractError, ResponseLevel, ResponsePlanId, ResponseResult, ResponseScope,
    ResponseTarget, ResponseTtl, RollbackPlan, RollbackResult, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

pub const RESPONSE_EXECUTION_SCHEMA_VERSION: sentinel_contracts::SchemaVersion =
    sentinel_contracts::SchemaVersion::new(1, 0, 0);
pub const RESPONSE_EXECUTION_STUB_LABEL: &str = "STUB_ONLY";
pub const RECOMMENDATION_ONLY_EXECUTOR: &str = "recommendation_only";
pub const FIREWALL_RESPONSE_LITE_EXECUTOR: &str = "firewall_response_lite_stub_only";
pub const QOS_RESPONSE_LITE_EXECUTOR: &str = "qos_response_lite_stub_only";

#[derive(Clone, Debug, PartialEq)]
pub enum ResponseExecutionError {
    EmptyField(&'static str),
    PrivacyMarker { field: &'static str },
    UnsupportedAction(ResponseActionType),
    ExecutorNotFound(ResponseActionType),
    Response(ResponseContractError),
}

impl fmt::Display for ResponseExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::PrivacyMarker { field } => {
                write!(f, "{field} contains a forbidden sensitive marker")
            }
            Self::UnsupportedAction(action_type) => {
                write!(f, "unsupported response action: {action_type:?}")
            }
            Self::ExecutorNotFound(action_type) => {
                write!(f, "no response executor supports action: {action_type:?}")
            }
            Self::Response(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ResponseExecutionError {}

impl From<ResponseContractError> for ResponseExecutionError {
    fn from(value: ResponseContractError) -> Self {
        Self::Response(value)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approval_request_id: ApprovalRequestId,
    pub approval_result_id: Option<sentinel_contracts::ApprovalResultId>,
    pub plan_id: ResponsePlanId,
    pub action_id: ResponseActionId,
    pub actor_redacted: String,
    pub decision: ApprovalDecision,
    pub reason_redacted: String,
    pub timestamp: Timestamp,
    pub policy_version: String,
    pub audit_ref: AuditRef,
    pub request: ApprovalRequest,
    pub result: ApprovalResult,
}

#[derive(Clone, Debug, Default)]
pub struct ApprovalService {
    records: Vec<ApprovalRecord>,
}

impl ApprovalService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request_for_action(
        &self,
        action: &ResponseAction,
        incident_id: Option<IncidentId>,
        evidence_count: u32,
        risk_score: QualityScore,
    ) -> Result<ApprovalRequest, ResponseExecutionError> {
        let mut audit_ref = AuditRef::new("response.approval.requested")?;
        audit_ref.trace_id = action.audit_ref.trace_id.clone();
        Ok(ApprovalRequest {
            approval_request_id: ApprovalRequestId::new_v4(),
            plan_id: action.plan_id.clone(),
            action_id: action.action_id.clone(),
            incident_id,
            evidence_count,
            risk_score,
            affected_scope_redacted: action.scope.description_redacted.clone(),
            recommended_action_redacted: action.target.target_summary_redacted.clone(),
            business_impact_redacted: action.policy_decision.reason_redacted.clone(),
            rollback_available: !action.rollback_plan.rollback_token.trim().is_empty(),
            policy_decision: action.policy_decision.clone(),
            audit_ref,
            requested_at: Timestamp::now(),
        })
    }

    pub fn record_decision(
        &mut self,
        request: ApprovalRequest,
        actor_redacted: impl Into<String>,
        decision: ApprovalDecision,
        reason_redacted: impl Into<String>,
    ) -> Result<ApprovalRecord, ResponseExecutionError> {
        let actor_redacted = require_safe_text("approval.actor", actor_redacted)?;
        let reason_redacted = require_safe_text("approval.reason", reason_redacted)?;
        let event_type = match decision {
            ApprovalDecision::Approved => "response.approval.approved",
            ApprovalDecision::Rejected => "response.approval.rejected",
        };
        let mut audit_ref = AuditRef::new(event_type)?;
        audit_ref.trace_id = request.audit_ref.trace_id.clone();
        let result = ApprovalResult {
            approval_result_id: sentinel_contracts::ApprovalResultId::new_v4(),
            approval_request_id: request.approval_request_id.clone(),
            plan_id: request.plan_id.clone(),
            action_id: request.action_id.clone(),
            actor: actor_redacted.clone(),
            decision: decision.clone(),
            reason_redacted: Some(reason_redacted.clone()),
            timestamp: Timestamp::now(),
            policy_version: request.policy_decision.policy_version.clone(),
            audit_ref: audit_ref.clone(),
        };
        let record = ApprovalRecord {
            approval_request_id: request.approval_request_id.clone(),
            approval_result_id: Some(result.approval_result_id.clone()),
            plan_id: request.plan_id.clone(),
            action_id: request.action_id.clone(),
            actor_redacted,
            decision,
            reason_redacted,
            timestamp: result.timestamp.clone(),
            policy_version: result.policy_version.clone(),
            audit_ref,
            request,
            result,
        };
        self.records.push(record.clone());
        Ok(record)
    }

    pub fn records(&self) -> &[ApprovalRecord] {
        &self.records
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackButtonState {
    Available,
    Disabled,
    NotRequired,
    Expired,
    Completed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveResponseExecutorStatus {
    PendingApproval,
    Ready,
    Active,
    Completed,
    Failed,
    ExecutionDisabled,
    Expired,
    RolledBack,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActiveResponseRecord {
    pub action_id: ResponseActionId,
    pub plan_id: ResponsePlanId,
    pub incident_id: Option<IncidentId>,
    pub action_type: ResponseActionType,
    pub target: ResponseTarget,
    pub scope: ResponseScope,
    pub ttl: ResponseTtl,
    pub ttl_remaining_seconds: Option<i64>,
    pub rollback_button_state: RollbackButtonState,
    pub executor_status: ActiveResponseExecutorStatus,
    pub last_result: Option<ResponseResult>,
    pub rollback_plan: RollbackPlan,
    pub audit_ref: AuditRef,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub stub_only: bool,
}

impl ActiveResponseRecord {
    pub fn from_action(
        action: &ResponseAction,
        incident_id: Option<IncidentId>,
        now: &Timestamp,
    ) -> Self {
        let approval_required = action.policy_decision.approval_required;
        Self {
            action_id: action.action_id.clone(),
            plan_id: action.plan_id.clone(),
            incident_id,
            action_type: action.action_type.clone(),
            target: action.target.clone(),
            scope: action.scope.clone(),
            ttl: action.ttl.clone(),
            ttl_remaining_seconds: ttl_remaining_seconds(&action.ttl, now),
            rollback_button_state: if action.ttl.required_for_execution {
                RollbackButtonState::Available
            } else {
                RollbackButtonState::NotRequired
            },
            executor_status: if approval_required {
                ActiveResponseExecutorStatus::PendingApproval
            } else {
                ActiveResponseExecutorStatus::Ready
            },
            last_result: None,
            rollback_plan: action.rollback_plan.clone(),
            audit_ref: action.audit_ref.clone(),
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
            stub_only: true,
        }
    }

    pub fn with_result(mut self, result: ResponseResult, now: &Timestamp) -> Self {
        self.ttl_remaining_seconds = ttl_remaining_seconds(&self.ttl, now);
        self.rollback_button_state = rollback_button_state_for_result(&result, &self.ttl);
        self.executor_status = executor_status_for_result(&result, &self.ttl);
        self.audit_ref = result.audit_ref.clone();
        self.updated_at = Timestamp::now();
        self.last_result = Some(result);
        self
    }

    pub fn mark_rolled_back(mut self, result: &RollbackResult) -> Self {
        self.executor_status = if result.success {
            ActiveResponseExecutorStatus::RolledBack
        } else {
            ActiveResponseExecutorStatus::Failed
        };
        self.rollback_button_state = if result.success {
            RollbackButtonState::Completed
        } else {
            RollbackButtonState::Disabled
        };
        self.audit_ref = result.audit_ref.clone();
        self.updated_at = Timestamp::now();
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct ActiveResponseService {
    records: HashMap<ResponseActionId, ActiveResponseRecord>,
}

impl ActiveResponseService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn track_action(
        &mut self,
        action: &ResponseAction,
        incident_id: Option<IncidentId>,
    ) -> ActiveResponseRecord {
        let record = ActiveResponseRecord::from_action(action, incident_id, &Timestamp::now());
        self.records
            .insert(action.action_id.clone(), record.clone());
        record
    }

    pub fn record_result(
        &mut self,
        action: &ResponseAction,
        incident_id: Option<IncidentId>,
        result: ResponseResult,
    ) -> ActiveResponseRecord {
        let now = Timestamp::now();
        let base = self
            .records
            .remove(&action.action_id)
            .unwrap_or_else(|| ActiveResponseRecord::from_action(action, incident_id, &now));
        let record = base.with_result(result, &now);
        self.records
            .insert(action.action_id.clone(), record.clone());
        record
    }

    pub fn record_rollback(&mut self, result: &RollbackResult) -> Option<ActiveResponseRecord> {
        let base = self.records.remove(&result.action_id)?;
        let record = base.mark_rolled_back(result);
        self.records
            .insert(result.action_id.clone(), record.clone());
        Some(record)
    }

    pub fn records(&self) -> Vec<ActiveResponseRecord> {
        self.records.values().cloned().collect()
    }

    pub fn active_records(&self) -> Vec<ActiveResponseRecord> {
        self.records
            .values()
            .filter(|record| {
                matches!(
                    record.executor_status,
                    ActiveResponseExecutorStatus::Active | ActiveResponseExecutorStatus::Expired
                )
            })
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseExecutionRequest {
    pub action: ResponseAction,
    pub approval_result: Option<ApprovalResult>,
    pub incident_id: Option<IncidentId>,
    pub actor_redacted: String,
    pub service_healthy: bool,
    pub audit_available: bool,
    pub is_replay: bool,
}

impl ResponseExecutionRequest {
    pub fn new(
        action: ResponseAction,
        actor_redacted: impl Into<String>,
    ) -> Result<Self, ResponseExecutionError> {
        Ok(Self {
            action,
            approval_result: None,
            incident_id: None,
            actor_redacted: require_safe_text("execution.actor", actor_redacted)?,
            service_healthy: true,
            audit_available: true,
            is_replay: false,
        })
    }

    pub fn with_approval(mut self, approval_result: ApprovalResult) -> Self {
        self.approval_result = Some(approval_result);
        self
    }

    pub fn with_replay(mut self) -> Self {
        self.is_replay = true;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RollbackExecutionRequest {
    pub action_id: ResponseActionId,
    pub action_type: ResponseActionType,
    pub target: ResponseTarget,
    pub rollback_plan: RollbackPlan,
    pub actor_redacted: String,
    pub reason_redacted: String,
    pub is_replay: bool,
}

impl RollbackExecutionRequest {
    pub fn from_active_record(
        record: &ActiveResponseRecord,
        actor_redacted: impl Into<String>,
        reason_redacted: impl Into<String>,
    ) -> Result<Self, ResponseExecutionError> {
        Ok(Self {
            action_id: record.action_id.clone(),
            action_type: record.action_type.clone(),
            target: record.target.clone(),
            rollback_plan: record.rollback_plan.clone(),
            actor_redacted: require_safe_text("rollback.actor", actor_redacted)?,
            reason_redacted: require_safe_text("rollback.reason", reason_redacted)?,
            is_replay: false,
        })
    }
}

pub trait ResponseExecutor {
    fn executor_name(&self) -> &'static str;
    fn supports(&self, action_type: &ResponseActionType) -> bool;
    fn execute(
        &self,
        request: ResponseExecutionRequest,
    ) -> Result<ResponseResult, ResponseExecutionError>;
    fn rollback(
        &self,
        request: RollbackExecutionRequest,
    ) -> Result<RollbackResult, ResponseExecutionError>;
}

#[derive(Clone, Debug, Default)]
pub struct RecommendationOnlyExecutor;

impl ResponseExecutor for RecommendationOnlyExecutor {
    fn executor_name(&self) -> &'static str {
        RECOMMENDATION_ONLY_EXECUTOR
    }

    fn supports(&self, action_type: &ResponseActionType) -> bool {
        matches!(
            action_type,
            ResponseActionType::RecommendProcessReview
                | ResponseActionType::RecommendDestinationWatchlist
                | ResponseActionType::RecommendFirewallBlock
                | ResponseActionType::RecommendQosThrottle
                | ResponseActionType::ApiPolicyRecommendation
                | ResponseActionType::WafPolicyRecommendation
        )
    }

    fn execute(
        &self,
        request: ResponseExecutionRequest,
    ) -> Result<ResponseResult, ResponseExecutionError> {
        if !self.supports(&request.action.action_type) {
            return Err(ResponseExecutionError::UnsupportedAction(
                request.action.action_type,
            ));
        }
        let mut result = base_result(
            &request.action,
            self.executor_name(),
            "response.action.completed",
        )?;
        result.ended_at = Some(Timestamp::now());
        result.is_replay = request.is_replay;
        result.execution_disabled = request.is_replay;

        if let Some(error) = approval_failure(&request.action, request.approval_result.as_ref()) {
            result.error_code = Some(error);
            result.error_summary_redacted =
                Some("approval gate did not allow recommendation action".to_string());
            return Ok(result);
        }

        result.success = true;
        result.error_summary_redacted = Some(
            "recommendation-only response recorded; no privileged adapter call performed"
                .to_string(),
        );
        Ok(result)
    }

    fn rollback(
        &self,
        request: RollbackExecutionRequest,
    ) -> Result<RollbackResult, ResponseExecutionError> {
        if !self.supports(&request.action_type) {
            return Err(ResponseExecutionError::UnsupportedAction(
                request.action_type,
            ));
        }
        let mut result = RollbackResult::new(
            request.action_id,
            &request.rollback_plan,
            audit_ref("response.rollback.completed", None)?,
        );
        result.ended_at = Some(Timestamp::now());
        result.success = true;
        result.error_summary_redacted =
            Some("recommendation-only rollback completed; no OS state existed".to_string());
        result.is_replay = request.is_replay;
        Ok(result)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FirewallResponseLiteExecutor;

impl ResponseExecutor for FirewallResponseLiteExecutor {
    fn executor_name(&self) -> &'static str {
        FIREWALL_RESPONSE_LITE_EXECUTOR
    }

    fn supports(&self, action_type: &ResponseActionType) -> bool {
        matches!(
            action_type,
            ResponseActionType::MaliciousDestinationAutoBlock
                | ResponseActionType::DecoyOutboundAutoBlock
        )
    }

    fn execute(
        &self,
        request: ResponseExecutionRequest,
    ) -> Result<ResponseResult, ResponseExecutionError> {
        if !self.supports(&request.action.action_type) {
            return Err(ResponseExecutionError::UnsupportedAction(
                request.action.action_type,
            ));
        }
        stub_sensitive_result(request, self.executor_name())
    }

    fn rollback(
        &self,
        request: RollbackExecutionRequest,
    ) -> Result<RollbackResult, ResponseExecutionError> {
        stub_sensitive_rollback(request, self)
    }
}

#[derive(Clone, Debug, Default)]
pub struct QosResponseLiteExecutor;

impl ResponseExecutor for QosResponseLiteExecutor {
    fn executor_name(&self) -> &'static str {
        QOS_RESPONSE_LITE_EXECUTOR
    }

    fn supports(&self, action_type: &ResponseActionType) -> bool {
        matches!(action_type, ResponseActionType::ExfiltrationAutoThrottle)
    }

    fn execute(
        &self,
        request: ResponseExecutionRequest,
    ) -> Result<ResponseResult, ResponseExecutionError> {
        if !self.supports(&request.action.action_type) {
            return Err(ResponseExecutionError::UnsupportedAction(
                request.action.action_type,
            ));
        }
        stub_sensitive_result(request, self.executor_name())
    }

    fn rollback(
        &self,
        request: RollbackExecutionRequest,
    ) -> Result<RollbackResult, ResponseExecutionError> {
        stub_sensitive_rollback(request, self)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RollbackScheduler;

impl RollbackScheduler {
    pub fn new() -> Self {
        Self
    }

    pub fn due_records(
        &self,
        records: &[ActiveResponseRecord],
        now: &Timestamp,
    ) -> Vec<ActiveResponseRecord> {
        records
            .iter()
            .filter(|record| {
                record.rollback_plan.automatic_on_ttl
                    && matches!(
                        record.executor_status,
                        ActiveResponseExecutorStatus::Active
                            | ActiveResponseExecutorStatus::Expired
                    )
                    && rollback_deadline_due(&record.rollback_plan, now)
            })
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct RollbackManager {
    scheduler: RollbackScheduler,
}

impl RollbackManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scheduler(&self) -> &RollbackScheduler {
        &self.scheduler
    }

    pub fn rollback_expired(
        &self,
        active_service: &mut ActiveResponseService,
        executors: &[&dyn ResponseExecutor],
        now: &Timestamp,
        actor_redacted: impl Into<String>,
    ) -> Result<Vec<RollbackResult>, ResponseExecutionError> {
        let actor_redacted = require_safe_text("rollback.actor", actor_redacted)?;
        let due = self.scheduler.due_records(&active_service.records(), now);
        let mut results = Vec::new();
        for record in due {
            let executor = executor_for(executors, &record.action_type).ok_or_else(|| {
                ResponseExecutionError::ExecutorNotFound(record.action_type.clone())
            })?;
            let request = RollbackExecutionRequest::from_active_record(
                &record,
                actor_redacted.clone(),
                "TTL expired",
            )?;
            let result = executor.rollback(request)?;
            active_service.record_rollback(&result);
            results.push(result);
        }
        Ok(results)
    }
}

pub fn executor_for<'a>(
    executors: &'a [&dyn ResponseExecutor],
    action_type: &ResponseActionType,
) -> Option<&'a dyn ResponseExecutor> {
    executors
        .iter()
        .copied()
        .find(|executor| executor.supports(action_type))
}

fn stub_sensitive_result(
    request: ResponseExecutionRequest,
    executor_name: &'static str,
) -> Result<ResponseResult, ResponseExecutionError> {
    let mut result = base_result(&request.action, executor_name, "response.action.failed")?;
    result.ended_at = Some(Timestamp::now());
    result.is_replay = request.is_replay;
    result.execution_disabled = true;

    if let Some(error) = sensitive_execution_error(&request) {
        result.error_code = Some(error.0);
        result.error_summary_redacted = Some(error.1);
        return Ok(result);
    }

    result.error_code = Some(ErrorCode::UnsupportedOperation);
    result.error_summary_redacted = Some(format!(
        "{RESPONSE_EXECUTION_STUB_LABEL} executor validated bounded request but did not mutate OS policy"
    ));
    Ok(result)
}

fn stub_sensitive_rollback<E: ResponseExecutor>(
    request: RollbackExecutionRequest,
    executor: &E,
) -> Result<RollbackResult, ResponseExecutionError> {
    if !executor.supports(&request.action_type) {
        return Err(ResponseExecutionError::UnsupportedAction(
            request.action_type,
        ));
    }
    let mut result = RollbackResult::new(
        request.action_id,
        &request.rollback_plan,
        audit_ref("response.rollback.failed", None)?,
    );
    result.ended_at = Some(Timestamp::now());
    result.success = false;
    result.error_summary_redacted = Some(format!(
        "{RESPONSE_EXECUTION_STUB_LABEL} rollback validated but no OS rule was changed by this adapter"
    ));
    result.is_replay = request.is_replay;
    Ok(result)
}

fn sensitive_execution_error(request: &ResponseExecutionRequest) -> Option<(ErrorCode, String)> {
    if request.is_replay {
        return Some((
            ErrorCode::ResponseDeniedByPolicy,
            "response execution is disabled in replay or disabled-by-default mode".to_string(),
        ));
    }
    if !request.audit_available {
        return Some((
            ErrorCode::ServiceUnavailable,
            "audit sink unavailable for sensitive response action".to_string(),
        ));
    }
    if !request.service_healthy {
        return Some((
            ErrorCode::ServiceUnavailable,
            "elevated service response executor is unhealthy or unavailable".to_string(),
        ));
    }
    if let Some(error) = approval_failure(&request.action, request.approval_result.as_ref()) {
        return Some((
            error,
            "approval gate did not allow sensitive response action".to_string(),
        ));
    }
    if !request.action.ttl.required_for_execution
        || request.action.ttl.duration_seconds.is_none()
        || request.action.ttl.expires_at.is_none()
    {
        return Some((
            ErrorCode::ResponseDeniedByPolicy,
            "sensitive response action requires TTL metadata".to_string(),
        ));
    }
    if request
        .action
        .rollback_plan
        .rollback_token
        .trim()
        .is_empty()
    {
        return Some((
            ErrorCode::ResponseDeniedByPolicy,
            "sensitive response action requires rollback token".to_string(),
        ));
    }
    if !request.action.scope.limited || !request.action.scope.preserves_control_plane {
        return Some((
            ErrorCode::ResponseDeniedByPolicy,
            "sensitive response action scope is too broad".to_string(),
        ));
    }
    if !matches!(
        request.action.policy_decision.level,
        ResponseLevel::AutoContainmentLite
    ) {
        return Some((
            ErrorCode::ResponseDeniedByPolicy,
            "sensitive response action requires auto-containment-lite policy decision".to_string(),
        ));
    }
    None
}

fn approval_failure(
    action: &ResponseAction,
    approval_result: Option<&ApprovalResult>,
) -> Option<ErrorCode> {
    if !action.policy_decision.approval_required {
        return None;
    }
    let Some(approval) = approval_result else {
        return Some(ErrorCode::ResponseRequiresApproval);
    };
    if approval.plan_id != action.plan_id || approval.action_id != action.action_id {
        return Some(ErrorCode::ResponseRequiresApproval);
    }
    if !matches!(approval.decision, ApprovalDecision::Approved) {
        return Some(ErrorCode::ResponseDeniedByPolicy);
    }
    None
}

fn base_result(
    action: &ResponseAction,
    executor: &'static str,
    audit_event_type: &'static str,
) -> Result<ResponseResult, ResponseExecutionError> {
    let audit_ref = audit_ref(audit_event_type, action.audit_ref.trace_id.clone())?;
    ResponseResult::new(
        action.action_id.clone(),
        executor,
        action.target.clone(),
        &action.rollback_plan,
        audit_ref,
    )
    .map_err(Into::into)
}

fn audit_ref(
    event_type: &'static str,
    trace_id: Option<sentinel_contracts::TraceId>,
) -> Result<AuditRef, ResponseExecutionError> {
    let mut audit = AuditRef::new(event_type)?;
    audit.trace_id = trace_id;
    Ok(audit)
}

fn ttl_remaining_seconds(ttl: &ResponseTtl, now: &Timestamp) -> Option<i64> {
    ttl.expires_at.as_ref().map(|expires_at| {
        expires_at
            .as_datetime()
            .signed_duration_since(*now.as_datetime())
            .num_seconds()
            .max(0)
    })
}

fn rollback_button_state_for_result(
    result: &ResponseResult,
    ttl: &ResponseTtl,
) -> RollbackButtonState {
    if result.execution_disabled {
        RollbackButtonState::Disabled
    } else if !ttl.required_for_execution {
        RollbackButtonState::NotRequired
    } else if result.success {
        RollbackButtonState::Available
    } else {
        RollbackButtonState::Disabled
    }
}

fn executor_status_for_result(
    result: &ResponseResult,
    ttl: &ResponseTtl,
) -> ActiveResponseExecutorStatus {
    if result.execution_disabled {
        ActiveResponseExecutorStatus::ExecutionDisabled
    } else if result.success && ttl.required_for_execution {
        ActiveResponseExecutorStatus::Active
    } else if result.success {
        ActiveResponseExecutorStatus::Completed
    } else {
        ActiveResponseExecutorStatus::Failed
    }
}

fn rollback_deadline_due(rollback_plan: &RollbackPlan, now: &Timestamp) -> bool {
    rollback_plan
        .rollback_deadline
        .as_ref()
        .is_some_and(|deadline| deadline <= now)
}

fn require_safe_text(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, ResponseExecutionError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(ResponseExecutionError::EmptyField(field));
    }
    let normalized = value.to_ascii_lowercase();
    for marker in [
        "raw_packet",
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
            return Err(ResponseExecutionError::PrivacyMarker { field });
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use sentinel_contracts::{
        PolicyDecision, RecommendedAction, ResponseScope, ResponseTarget, ResponseTtl,
    };

    fn auto_action(action_type: ResponseActionType, expires_in_seconds: i64) -> ResponseAction {
        let target = ResponseTarget::new("redacted destination").expect("target");
        let scope = ResponseScope::limited("single destination").expect("scope");
        let expires_at =
            Timestamp::from_datetime(Utc::now() + Duration::seconds(expires_in_seconds));
        let ttl = ResponseTtl::required(600, expires_at.clone());
        let mut recommended = RecommendedAction::new(
            action_type,
            target,
            scope,
            "temporary scoped containment",
            "medium impact",
            ResponseLevel::AutoContainmentLite,
        )
        .expect("recommended");
        recommended.ttl = ttl.clone();
        recommended.rollback_available = true;
        let mut policy = PolicyDecision::new(
            ResponseLevel::AutoContainmentLite,
            "auto containment allowed",
            "v1",
        )
        .expect("policy");
        policy.ttl = ttl.clone();
        let mut rollback = RollbackPlan::new("rollback-token").expect("rollback");
        rollback.rollback_deadline = Some(expires_at);
        rollback.automatic_on_ttl = true;
        let audit = AuditRef::new("response.action.created").expect("audit");
        let mut action = ResponseAction::new(
            ResponsePlanId::new_v4(),
            recommended,
            policy,
            audit,
            rollback,
        );
        action.execution_disabled_in_replay = false;
        action
    }

    fn recommendation_action() -> ResponseAction {
        let target = ResponseTarget::new("redacted process").expect("target");
        let scope = ResponseScope::limited("single process").expect("scope");
        let recommended = RecommendedAction::new(
            ResponseActionType::RecommendProcessReview,
            target,
            scope,
            "review process",
            "low impact",
            ResponseLevel::RecommendOnly,
        )
        .expect("recommended");
        let policy = PolicyDecision::new(ResponseLevel::RecommendOnly, "recommend only", "v1")
            .expect("policy");
        let rollback = RollbackPlan::new("no-state-change").expect("rollback");
        let audit = AuditRef::new("response.action.created").expect("audit");
        ResponseAction::new(
            ResponsePlanId::new_v4(),
            recommended,
            policy,
            audit,
            rollback,
        )
    }

    #[test]
    fn approval_service_records_actor_decision_reason_policy_plan_and_action() {
        let action = auto_action(ResponseActionType::MaliciousDestinationAutoBlock, 600);
        let mut service = ApprovalService::new();
        let request = service
            .request_for_action(
                &action,
                Some(IncidentId::new_v4()),
                2,
                QualityScore::perfect(),
            )
            .expect("request");
        let record = service
            .record_decision(
                request,
                "local analyst",
                ApprovalDecision::Approved,
                "bounded temporary response approved",
            )
            .expect("record");

        assert_eq!(record.plan_id, action.plan_id);
        assert_eq!(record.action_id, action.action_id);
        assert_eq!(record.actor_redacted, "local analyst");
        assert_eq!(record.decision, ApprovalDecision::Approved);
        assert_eq!(
            record.reason_redacted,
            "bounded temporary response approved"
        );
        assert_eq!(record.policy_version, "v1");
        assert_eq!(service.records().len(), 1);
    }

    #[test]
    fn stub_executors_return_results_with_rollback_deadline_and_audit() {
        let action = auto_action(ResponseActionType::MaliciousDestinationAutoBlock, 600);
        let executor = FirewallResponseLiteExecutor;
        let request = ResponseExecutionRequest::new(action.clone(), "local core").expect("request");
        let result = executor.execute(request).expect("result");

        assert_eq!(result.executor, FIREWALL_RESPONSE_LITE_EXECUTOR);
        assert!(!result.success);
        assert_eq!(result.error_code, Some(ErrorCode::UnsupportedOperation));
        assert!(result.execution_disabled);
        assert_eq!(result.rollback_token, "rollback-token");
        assert!(result.rollback_deadline.is_some());
        assert_eq!(result.audit_ref.event_type, "response.action.failed");

        let recommendation = recommendation_action();
        let recommendation_result = RecommendationOnlyExecutor
            .execute(
                ResponseExecutionRequest::new(recommendation, "local core")
                    .expect("recommendation request"),
            )
            .expect("recommendation result");
        assert!(recommendation_result.success);
        assert_eq!(recommendation_result.executor, RECOMMENDATION_ONLY_EXECUTOR);
    }

    #[test]
    fn active_response_record_exposes_dashboard_fields() {
        let action = auto_action(ResponseActionType::ExfiltrationAutoThrottle, 600);
        let mut service = ActiveResponseService::new();
        service.track_action(&action, Some(IncidentId::new_v4()));
        let mut result = ResponseResult::new(
            action.action_id.clone(),
            "future_real_qos_adapter",
            action.target.clone(),
            &action.rollback_plan,
            AuditRef::new("response.action.completed").expect("audit"),
        )
        .expect("result");
        result.success = true;
        result.ended_at = Some(Timestamp::now());
        let record = service.record_result(&action, Some(IncidentId::new_v4()), result);

        assert_eq!(
            record.target.target_summary_redacted,
            "redacted destination"
        );
        assert!(record.scope.limited);
        assert!(record.incident_id.is_some());
        assert!(record.ttl_remaining_seconds.is_some());
        assert_eq!(record.rollback_button_state, RollbackButtonState::Available);
        assert_eq!(record.executor_status, ActiveResponseExecutorStatus::Active);
        assert!(record.last_result.is_some());
        assert_eq!(record.audit_ref.event_type, "response.action.completed");
    }

    #[test]
    fn rollback_scheduler_triggers_ttl_expired_without_ui() {
        let action = auto_action(ResponseActionType::MaliciousDestinationAutoBlock, -1);
        let mut active = ActiveResponseService::new();
        let mut result = ResponseResult::new(
            action.action_id.clone(),
            "future_real_firewall_adapter",
            action.target.clone(),
            &action.rollback_plan,
            AuditRef::new("response.action.completed").expect("audit"),
        )
        .expect("result");
        result.success = true;
        result.ended_at = Some(Timestamp::now());
        active.record_result(&action, Some(IncidentId::new_v4()), result);
        let manager = RollbackManager::new();
        let firewall = FirewallResponseLiteExecutor;
        let executors: [&dyn ResponseExecutor; 1] = [&firewall];

        let results = manager
            .rollback_expired(&mut active, &executors, &Timestamp::now(), "local core")
            .expect("rollback triggered");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rollback_token, "rollback-token");
        assert_eq!(results[0].audit_ref.event_type, "response.rollback.failed");
        assert!(results[0]
            .error_summary_redacted
            .as_ref()
            .is_some_and(|summary| summary.contains(RESPONSE_EXECUTION_STUB_LABEL)));
    }

    #[test]
    fn replay_and_unhealthy_service_do_not_execute_real_actions() {
        let action = auto_action(ResponseActionType::ExfiltrationAutoThrottle, 600);
        let executor = QosResponseLiteExecutor;
        let replay = executor
            .execute(
                ResponseExecutionRequest::new(action.clone(), "local core")
                    .expect("request")
                    .with_replay(),
            )
            .expect("replay result");
        assert!(replay.execution_disabled);
        assert_eq!(replay.error_code, Some(ErrorCode::ResponseDeniedByPolicy));

        let mut unhealthy = ResponseExecutionRequest::new(action, "local core").expect("request");
        unhealthy.service_healthy = false;
        let result = executor.execute(unhealthy).expect("unhealthy result");
        assert!(result.execution_disabled);
        assert_eq!(result.error_code, Some(ErrorCode::ServiceUnavailable));
    }
}
