use sentinel_contracts::runtime_ownership::{
    RuntimeHealthState, RuntimeMode, RuntimeOwnershipSummary, RuntimeTransitionState,
};
use sentinel_contracts::{
    mutation_policy_catalog, policy_for_command, CallerVerificationState,
    CallerVerificationSummary, MutationAuthorizationDecision, MutationAuthorizationFrameworkState,
    MutationAuthorizationResult, MutationAuthorizationStatus, MutationCapabilityCategory,
    MutationCapabilityStateCategory, MutationCommandId, MutationCommandPolicy, MutationCountBucket,
    MutationExecutionRequest, MutationIdempotencyPolicy, MutationIdempotencyState, MutationIntent,
    MutationIntentTimeBucket, MutationPolicyImplementationState, MutationRequiredCallerCategory,
    MutationRequiredTargetState, MutationRuntimeStateCategory, MutationTtlState, RedactionStatus,
    MUTATION_AUTHORIZATION_SCHEMA_VERSION, MUTATION_POLICY_CATALOG_VERSION,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

const MAX_SESSION_AUTHORIZATION_RECORDS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationAuthorizationRuntimeContext {
    pub ipc_session_ref: String,
    pub protocol_schema_valid: bool,
    pub runtime_state: MutationRuntimeStateCategory,
    pub ownership_epoch: u64,
    pub ip_helper_state: MutationCapabilityStateCategory,
    pub etw_state: MutationCapabilityStateCategory,
    pub dns_sensing_state: MutationCapabilityStateCategory,
    pub auth_remote_state: MutationCapabilityStateCategory,
    pub provider_controller_state: MutationCapabilityStateCategory,
    pub sampler_state: MutationCapabilityStateCategory,
    pub scheduler_state: MutationCapabilityStateCategory,
    pub scheduler_host_state: MutationCapabilityStateCategory,
    pub report_state: MutationCapabilityStateCategory,
    pub export_state: MutationCapabilityStateCategory,
    pub llm_state: MutationCapabilityStateCategory,
    pub capture_state: MutationCapabilityStateCategory,
    pub response_state: MutationCapabilityStateCategory,
}

impl MutationAuthorizationRuntimeContext {
    pub fn from_runtime_summary(
        ipc_session_ref: impl Into<String>,
        summary: &RuntimeOwnershipSummary,
    ) -> Self {
        let runtime_state = if summary.runtime_mode == RuntimeMode::ServiceOwned
            && matches!(
                summary.runtime_health,
                RuntimeHealthState::Healthy | RuntimeHealthState::Ready
            )
            && summary.transition_state == RuntimeTransitionState::Ready
        {
            MutationRuntimeStateCategory::ServiceOwnedReady
        } else if summary.transition_state == RuntimeTransitionState::ShuttingDown {
            MutationRuntimeStateCategory::ShuttingDown
        } else {
            MutationRuntimeStateCategory::Degraded
        };
        Self {
            ipc_session_ref: ipc_session_ref.into(),
            protocol_schema_valid: true,
            runtime_state,
            ownership_epoch: summary.ownership_epoch,
            ip_helper_state: map_state(&summary.provider_controller_state),
            etw_state: map_state(&summary.provider_controller_state),
            dns_sensing_state: map_state(&summary.provider_controller_state),
            auth_remote_state: map_state(&summary.provider_controller_state),
            provider_controller_state: map_state(&summary.provider_controller_state),
            sampler_state: map_state(&summary.sampler_state),
            scheduler_state: map_state(&summary.scheduler_state),
            scheduler_host_state: map_state(&summary.scheduler_host_state),
            report_state: MutationCapabilityStateCategory::Available,
            export_state: MutationCapabilityStateCategory::Available,
            llm_state: MutationCapabilityStateCategory::Unavailable,
            capture_state: MutationCapabilityStateCategory::Unavailable,
            response_state: MutationCapabilityStateCategory::Blocked,
        }
    }

    pub fn unavailable(ipc_session_ref: impl Into<String>) -> Self {
        Self {
            ipc_session_ref: ipc_session_ref.into(),
            protocol_schema_valid: true,
            runtime_state: MutationRuntimeStateCategory::Unavailable,
            ownership_epoch: 1,
            ip_helper_state: MutationCapabilityStateCategory::Unavailable,
            etw_state: MutationCapabilityStateCategory::Unavailable,
            dns_sensing_state: MutationCapabilityStateCategory::Unavailable,
            auth_remote_state: MutationCapabilityStateCategory::Unavailable,
            provider_controller_state: MutationCapabilityStateCategory::Unavailable,
            sampler_state: MutationCapabilityStateCategory::Unavailable,
            scheduler_state: MutationCapabilityStateCategory::Unavailable,
            scheduler_host_state: MutationCapabilityStateCategory::Unavailable,
            report_state: MutationCapabilityStateCategory::Unavailable,
            export_state: MutationCapabilityStateCategory::Unavailable,
            llm_state: MutationCapabilityStateCategory::Unavailable,
            capture_state: MutationCapabilityStateCategory::Unavailable,
            response_state: MutationCapabilityStateCategory::Blocked,
        }
    }

    fn capability_state(
        &self,
        capability: MutationCapabilityCategory,
    ) -> MutationCapabilityStateCategory {
        match capability {
            MutationCapabilityCategory::IpHelperProvider => self.ip_helper_state,
            MutationCapabilityCategory::EtwProvider => self.etw_state,
            MutationCapabilityCategory::DnsSensingProvider => self.dns_sensing_state,
            MutationCapabilityCategory::AuthRemoteSensingProvider => self.auth_remote_state,
            MutationCapabilityCategory::NetworkProviderController => self.provider_controller_state,
            MutationCapabilityCategory::NativeSampler => self.sampler_state,
            MutationCapabilityCategory::NativeScheduler => self.scheduler_state,
            MutationCapabilityCategory::NativeSchedulerHost => self.scheduler_host_state,
            MutationCapabilityCategory::CaptureAuthorization => self.capture_state,
            MutationCapabilityCategory::ReportGeneration => self.report_state,
            MutationCapabilityCategory::Export => self.export_state,
            MutationCapabilityCategory::LlmAlertStory => self.llm_state,
            MutationCapabilityCategory::Response => self.response_state,
            MutationCapabilityCategory::ServiceHostLifecycle
            | MutationCapabilityCategory::HostMutation => {
                MutationCapabilityStateCategory::NotApplicable
            }
        }
    }
}

#[derive(Clone, Debug)]
struct IdempotencyRecord {
    request_hash: String,
    decision: MutationAuthorizationDecision,
    expires_at_millis: u64,
}

#[derive(Clone, Debug)]
struct SeenIntentRecord {
    request_hash: String,
    expires_at_millis: u64,
}

#[derive(Clone, Debug)]
struct ExecutionAuthorizationRecord {
    decision: MutationAuthorizationDecision,
    request_hash: String,
    session_ref: String,
    command_id: MutationCommandId,
    policy_ref: String,
    policy_version: sentinel_contracts::SchemaVersion,
    ownership_epoch: u64,
    expires_at_millis: u64,
    consumed: bool,
}

#[derive(Clone, Copy)]
struct DecisionEnvironment<'a> {
    caller: &'a CallerVerificationSummary,
    policy: &'a MutationCommandPolicy,
    runtime: &'a MutationAuthorizationRuntimeContext,
    capability_state: MutationCapabilityStateCategory,
}

#[derive(Clone, Debug)]
pub struct MutationAuthorizationEvaluator {
    policies: HashMap<MutationCommandId, MutationCommandPolicy>,
    idempotency_records: HashMap<String, IdempotencyRecord>,
    seen_intents: HashMap<String, SeenIntentRecord>,
    execution_records: HashMap<String, ExecutionAuthorizationRecord>,
    clock_origin: Instant,
    last_decision: Option<MutationAuthorizationDecision>,
    denied_count: u64,
    expired_count: u64,
    replay_count: u64,
    execution_attempt_count: u64,
}

impl Default for MutationAuthorizationEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl MutationAuthorizationEvaluator {
    pub fn new() -> Self {
        Self {
            policies: mutation_policy_catalog()
                .into_iter()
                .map(|policy| (policy.command_id, policy))
                .collect(),
            idempotency_records: HashMap::new(),
            seen_intents: HashMap::new(),
            execution_records: HashMap::new(),
            clock_origin: Instant::now(),
            last_decision: None,
            denied_count: 0,
            expired_count: 0,
            replay_count: 0,
            execution_attempt_count: 0,
        }
    }

    pub fn evaluate(
        &mut self,
        intent: &MutationIntent,
        caller: &CallerVerificationSummary,
        context: &MutationAuthorizationRuntimeContext,
    ) -> MutationAuthorizationDecision {
        let now_millis = self.clock_origin.elapsed().as_millis() as u64;
        self.evaluate_at(intent, caller, context, now_millis)
    }

    pub fn evaluate_at(
        &mut self,
        intent: &MutationIntent,
        caller: &CallerVerificationSummary,
        context: &MutationAuthorizationRuntimeContext,
        now_millis: u64,
    ) -> MutationAuthorizationDecision {
        let policy = self
            .policies
            .get(&intent.command_id)
            .cloned()
            .unwrap_or_else(|| policy_for_command(intent.command_id));
        let capability_state = context.capability_state(policy.required_capability);
        let request_hash = bounded_request_hash(intent);
        let environment = DecisionEnvironment {
            caller,
            policy: &policy,
            runtime: context,
            capability_state,
        };

        let terminal = |result, reason, ttl_state, idempotency_state| {
            build_decision(
                intent,
                environment,
                result,
                reason,
                ttl_state,
                idempotency_state,
            )
        };

        let decision = if intent.ipc_session_ref != context.ipc_session_ref
            || intent.caller_verification_ref != caller.verification_ref
        {
            terminal(
                MutationAuthorizationResult::SessionMismatch,
                "session_mismatch",
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if !caller.verification_state.permits_read_only_commands()
            || caller.session_binding_state != sentinel_contracts::SessionBindingState::Bound
            || caller.freshness_bucket
                != sentinel_contracts::VerificationFreshnessBucket::CurrentConnection
        {
            terminal(
                MutationAuthorizationResult::CallerNotAuthorized,
                "caller_verification_not_current",
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if !context.protocol_schema_valid {
            terminal(
                MutationAuthorizationResult::Denied,
                "protocol_schema_invalid",
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if intent.policy_ref != policy.policy_ref {
            terminal(
                MutationAuthorizationResult::PolicyNotFound,
                "policy_not_found",
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if intent.policy_version != policy.policy_version {
            terminal(
                MutationAuthorizationResult::PolicyVersionMismatch,
                "policy_version_mismatch",
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if !caller_matches(policy.required_caller_category, caller) {
            terminal(
                if policy.administrator_required {
                    MutationAuthorizationResult::AdministratorPolicyRequired
                } else {
                    MutationAuthorizationResult::CallerNotAuthorized
                },
                if policy.administrator_required {
                    "administrator_policy_required"
                } else {
                    "caller_not_authorized"
                },
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if !caller.permits_command_class(policy.required_command_class) {
            terminal(
                MutationAuthorizationResult::CommandClassNotAllowed,
                "command_class_not_allowed",
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if policy.interactive_session_required && !caller.interactive_marker {
            terminal(
                MutationAuthorizationResult::CallerNotAuthorized,
                "interactive_session_required",
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if !intent.explicit_user_action {
            terminal(
                MutationAuthorizationResult::ExplicitActionRequired,
                "explicit_action_required",
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if intent.ownership_epoch != context.ownership_epoch {
            terminal(
                MutationAuthorizationResult::OwnershipEpochMismatch,
                "ownership_epoch_mismatch",
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if policy.service_host_runtime_required
            && context.runtime_state != MutationRuntimeStateCategory::ServiceOwnedReady
        {
            terminal(
                MutationAuthorizationResult::RuntimeStateInvalid,
                "runtime_state_invalid",
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if intent.target_capability_category != policy.required_capability {
            terminal(
                MutationAuthorizationResult::CapabilityUnavailable,
                "capability_mismatch",
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if !target_state_matches(policy.required_target_state, capability_state) {
            terminal(
                if capability_state == MutationCapabilityStateCategory::Unavailable
                    || capability_state == MutationCapabilityStateCategory::Blocked
                {
                    MutationAuthorizationResult::CapabilityUnavailable
                } else {
                    MutationAuthorizationResult::ProviderStateInvalid
                },
                if capability_state == MutationCapabilityStateCategory::Unavailable
                    || capability_state == MutationCapabilityStateCategory::Blocked
                {
                    "capability_unavailable"
                } else {
                    "target_state_invalid"
                },
                MutationTtlState::Current,
                MutationIdempotencyState::NotRequired,
            )
        } else if intent.created_time_bucket == MutationIntentTimeBucket::Expired
            || intent.expiry_ttl_bucket != policy.request_ttl_bucket
        {
            terminal(
                MutationAuthorizationResult::Expired,
                if intent.created_time_bucket == MutationIntentTimeBucket::Expired {
                    "mutation_intent_expired"
                } else {
                    "mutation_ttl_policy_mismatch"
                },
                MutationTtlState::Expired,
                MutationIdempotencyState::NotRequired,
            )
        } else if let Some(decision) =
            self.evaluate_idempotency(intent, environment, &request_hash, now_millis)
        {
            decision
        } else if policy.response_capable {
            terminal(
                MutationAuthorizationResult::ResponseCapabilityBlocked,
                "response_capability_blocked",
                MutationTtlState::Current,
                MutationIdempotencyState::New,
            )
        } else {
            match policy.implementation_state {
                MutationPolicyImplementationState::AlwaysDenied => terminal(
                    MutationAuthorizationResult::Denied,
                    policy.degraded_reason.as_deref().unwrap_or("policy_denied"),
                    MutationTtlState::Current,
                    MutationIdempotencyState::New,
                ),
                MutationPolicyImplementationState::NotImplemented => terminal(
                    MutationAuthorizationResult::NotImplemented,
                    policy
                        .degraded_reason
                        .as_deref()
                        .unwrap_or("not_implemented"),
                    MutationTtlState::Current,
                    MutationIdempotencyState::New,
                ),
                MutationPolicyImplementationState::FrameworkReviewOnly => terminal(
                    if policy.execution_enabled {
                        MutationAuthorizationResult::ApprovedForExecution
                    } else {
                        MutationAuthorizationResult::ApprovedDryRun
                    },
                    if policy.execution_enabled {
                        "provider_execution_authorized"
                    } else {
                        "mutation_execution_blocked"
                    },
                    MutationTtlState::Current,
                    MutationIdempotencyState::New,
                ),
            }
        };

        self.record_terminal(intent, &policy, request_hash, decision.clone(), now_millis);
        self.observe_decision(&decision);
        decision
    }

    pub fn invalidate_session(&mut self, session_ref: &str) {
        let prefix = format!("{session_ref}|");
        self.idempotency_records
            .retain(|key, _| !key.starts_with(&prefix));
        self.seen_intents.retain(|key, _| !key.starts_with(&prefix));
        self.execution_records
            .retain(|_, record| record.session_ref != session_ref);
    }

    pub fn status(
        &self,
        caller_trust_ready: bool,
        ownership_runtime_ready: bool,
    ) -> MutationAuthorizationStatus {
        let mut degraded_reasons = Vec::new();
        if !caller_trust_ready {
            degraded_reasons.push("caller_trust_unavailable".to_string());
        }
        if !ownership_runtime_ready {
            degraded_reasons.push("ownership_runtime_unavailable".to_string());
        }
        MutationAuthorizationStatus {
            schema_version: MUTATION_AUTHORIZATION_SCHEMA_VERSION,
            framework_state: if caller_trust_ready && ownership_runtime_ready {
                MutationAuthorizationFrameworkState::ImplementedNarrowExecution
            } else {
                MutationAuthorizationFrameworkState::Degraded
            },
            policy_catalog_version: MUTATION_POLICY_CATALOG_VERSION,
            supported_command_count: MutationCommandId::ALL.len() as u32,
            dry_run_only: false,
            production_execution_enabled: true,
            last_decision_category: self.last_decision.as_ref().map(|decision| decision.result),
            denied_count_bucket: MutationCountBucket::from_count(self.denied_count),
            expired_count_bucket: MutationCountBucket::from_count(self.expired_count),
            replay_count_bucket: MutationCountBucket::from_count(self.replay_count),
            caller_trust_ready,
            ownership_runtime_ready,
            degraded_reasons,
            audit_refs: vec!["mutation_authorization_audit".to_string()],
            provenance_id: "servicehost_mutation_authorization".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn execution_attempt_count(&self) -> u64 {
        self.execution_attempt_count
    }

    pub fn execution_authorization_count(&self) -> usize {
        self.execution_records.len()
    }

    pub fn consume_execution_authorization(
        &mut self,
        request: &MutationExecutionRequest,
        session_ref: &str,
        expected_command: MutationCommandId,
        expected_ownership_epoch: u64,
    ) -> Result<MutationAuthorizationDecision, &'static str> {
        let now_millis = self.clock_origin.elapsed().as_millis() as u64;
        self.consume_execution_authorization_at(
            request,
            session_ref,
            expected_command,
            expected_ownership_epoch,
            now_millis,
        )
    }

    pub fn consume_execution_authorization_at(
        &mut self,
        request: &MutationExecutionRequest,
        session_ref: &str,
        expected_command: MutationCommandId,
        expected_ownership_epoch: u64,
        now_millis: u64,
    ) -> Result<MutationAuthorizationDecision, &'static str> {
        request
            .validate()
            .map_err(|_| "execution_request_invalid")?;
        if request.intent.command_id != expected_command {
            self.replay_count = self.replay_count.saturating_add(1);
            return Err("ip_helper_execution_command_rejected");
        }
        if request.intent.ipc_session_ref != session_ref {
            self.replay_count = self.replay_count.saturating_add(1);
            return Err("ip_helper_execution_session_rejected");
        }
        let request_hash = bounded_request_hash(&request.intent);
        let record = self
            .execution_records
            .get_mut(&request.decision_ref)
            .ok_or("ip_helper_execution_decision_unavailable")?;
        if record.consumed {
            self.replay_count = self.replay_count.saturating_add(1);
            return Err("ip_helper_execution_replay_rejected");
        }
        if record.expires_at_millis <= now_millis {
            self.expired_count = self.expired_count.saturating_add(1);
            return Err("ip_helper_execution_timed_out");
        }
        if record.session_ref != session_ref {
            self.replay_count = self.replay_count.saturating_add(1);
            return Err("ip_helper_execution_session_rejected");
        }
        if record.command_id != expected_command
            || record.policy_ref != request.intent.policy_ref
            || record.policy_version != request.intent.policy_version
            || record.ownership_epoch != expected_ownership_epoch
            || record.ownership_epoch != request.intent.ownership_epoch
            || record.request_hash != request_hash
        {
            self.replay_count = self.replay_count.saturating_add(1);
            return Err("ip_helper_execution_epoch_rejected");
        }
        if record.decision.result != MutationAuthorizationResult::ApprovedForExecution
            || record.decision.dry_run
            || !record.decision.execution_enabled
        {
            self.denied_count = self.denied_count.saturating_add(1);
            return Err("ip_helper_execution_not_authorized");
        }
        record.consumed = true;
        self.execution_attempt_count = self.execution_attempt_count.saturating_add(1);
        self.last_decision = Some(record.decision.clone());
        Ok(record.decision.clone())
    }

    fn evaluate_idempotency(
        &mut self,
        intent: &MutationIntent,
        environment: DecisionEnvironment<'_>,
        request_hash: &str,
        now_millis: u64,
    ) -> Option<MutationAuthorizationDecision> {
        let policy = environment.policy;
        let idempotency_ref = intent.idempotency_ref.as_deref();
        match policy.idempotency_policy {
            MutationIdempotencyPolicy::Required | MutationIdempotencyPolicy::SingleUse
                if idempotency_ref.is_none() =>
            {
                return Some(build_decision(
                    intent,
                    environment,
                    MutationAuthorizationResult::Denied,
                    "idempotency_required",
                    MutationTtlState::Current,
                    MutationIdempotencyState::Missing,
                ));
            }
            MutationIdempotencyPolicy::Forbidden if idempotency_ref.is_some() => {
                return Some(build_decision(
                    intent,
                    environment,
                    MutationAuthorizationResult::Denied,
                    "idempotency_forbidden",
                    MutationTtlState::Current,
                    MutationIdempotencyState::Conflict,
                ));
            }
            _ => {}
        }

        if let Some(idempotency_ref) = idempotency_ref {
            let key = idempotency_key(intent, idempotency_ref);
            if let Some(record) = self.idempotency_records.get(&key) {
                if record.expires_at_millis <= now_millis {
                    return Some(build_decision(
                        intent,
                        environment,
                        MutationAuthorizationResult::Expired,
                        "mutation_intent_expired",
                        MutationTtlState::Expired,
                        MutationIdempotencyState::Reused,
                    ));
                }
                if record.request_hash == request_hash {
                    let mut decision = record.decision.clone();
                    decision.idempotency_state = MutationIdempotencyState::Reused;
                    decision.audit_refs = vec!["mutation_idempotency_reused".to_string()];
                    return Some(decision);
                }
                return Some(replay_decision(
                    intent,
                    environment,
                    MutationIdempotencyState::Conflict,
                    "idempotency_payload_conflict",
                ));
            }
        }

        let intent_key = format!("{}|{}", intent.ipc_session_ref, intent.intent_ref);
        if let Some(previous) = self.seen_intents.get(&intent_key) {
            if previous.expires_at_millis <= now_millis {
                return Some(build_decision(
                    intent,
                    environment,
                    MutationAuthorizationResult::Expired,
                    "mutation_intent_expired",
                    MutationTtlState::Expired,
                    MutationIdempotencyState::Reused,
                ));
            }
            return Some(replay_decision(
                intent,
                environment,
                if previous.request_hash == request_hash {
                    MutationIdempotencyState::Reused
                } else {
                    MutationIdempotencyState::Conflict
                },
                "mutation_intent_replay_rejected",
            ));
        }
        None
    }

    fn record_terminal(
        &mut self,
        intent: &MutationIntent,
        policy: &MutationCommandPolicy,
        request_hash: String,
        decision: MutationAuthorizationDecision,
        now_millis: u64,
    ) {
        let expires_at_millis =
            now_millis.saturating_add(policy.request_ttl_bucket.duration_millis());
        let intent_key = format!("{}|{}", intent.ipc_session_ref, intent.intent_ref);
        self.seen_intents
            .entry(intent_key)
            .or_insert_with(|| SeenIntentRecord {
                request_hash: request_hash.clone(),
                expires_at_millis,
            });
        if let Some(idempotency_ref) = intent.idempotency_ref.as_deref() {
            let key = idempotency_key(intent, idempotency_ref);
            self.idempotency_records
                .entry(key)
                .or_insert(IdempotencyRecord {
                    request_hash: request_hash.clone(),
                    decision: decision.clone(),
                    expires_at_millis,
                });
        }
        if decision.result == MutationAuthorizationResult::ApprovedForExecution {
            self.execution_records
                .entry(decision.decision_ref.clone())
                .or_insert(ExecutionAuthorizationRecord {
                    decision,
                    request_hash,
                    session_ref: intent.ipc_session_ref.clone(),
                    command_id: intent.command_id,
                    policy_ref: policy.policy_ref.clone(),
                    policy_version: policy.policy_version.clone(),
                    ownership_epoch: intent.ownership_epoch,
                    expires_at_millis,
                    consumed: false,
                });
        }
        self.enforce_record_bound();
    }

    fn observe_decision(&mut self, decision: &MutationAuthorizationDecision) {
        match decision.result {
            MutationAuthorizationResult::Expired => {
                self.expired_count = self.expired_count.saturating_add(1);
            }
            MutationAuthorizationResult::ReplayRejected => {
                self.replay_count = self.replay_count.saturating_add(1);
            }
            MutationAuthorizationResult::ApprovedDryRun
            | MutationAuthorizationResult::ApprovedForExecution => {}
            _ => {
                self.denied_count = self.denied_count.saturating_add(1);
            }
        }
        self.last_decision = Some(decision.clone());
    }

    fn enforce_record_bound(&mut self) {
        while self.idempotency_records.len() > MAX_SESSION_AUTHORIZATION_RECORDS {
            if let Some(key) = self.idempotency_records.keys().next().cloned() {
                self.idempotency_records.remove(&key);
            }
        }
        while self.seen_intents.len() > MAX_SESSION_AUTHORIZATION_RECORDS {
            if let Some(key) = self.seen_intents.keys().next().cloned() {
                self.seen_intents.remove(&key);
            }
        }
        while self.execution_records.len() > MAX_SESSION_AUTHORIZATION_RECORDS {
            if let Some(key) = self.execution_records.keys().next().cloned() {
                self.execution_records.remove(&key);
            }
        }
    }
}

fn build_decision(
    intent: &MutationIntent,
    environment: DecisionEnvironment<'_>,
    result: MutationAuthorizationResult,
    degraded_reason: &str,
    ttl_state: MutationTtlState,
    idempotency_state: MutationIdempotencyState,
) -> MutationAuthorizationDecision {
    let policy = environment.policy;
    MutationAuthorizationDecision {
        schema_version: MUTATION_AUTHORIZATION_SCHEMA_VERSION,
        decision_ref: format!("mutation_decision_{}", Uuid::new_v4()),
        intent_ref: intent.intent_ref.clone(),
        command_id: intent.command_id,
        policy_ref: policy.policy_ref.clone(),
        policy_version: policy.policy_version.clone(),
        result,
        caller_category: environment.caller.caller_category,
        command_class: policy.required_command_class,
        runtime_state: environment.runtime.runtime_state,
        capability_state: environment.capability_state,
        ownership_epoch: intent.ownership_epoch,
        ttl_state,
        idempotency_state,
        dry_run: result != MutationAuthorizationResult::ApprovedForExecution,
        execution_enabled: result == MutationAuthorizationResult::ApprovedForExecution,
        degraded_reason: Some(degraded_reason.to_string()),
        audit_refs: decision_audit_refs(result),
        provenance_id: "servicehost_mutation_authorization".to_string(),
        redaction_status: RedactionStatus::Redacted,
    }
}

fn replay_decision(
    intent: &MutationIntent,
    environment: DecisionEnvironment<'_>,
    idempotency_state: MutationIdempotencyState,
    reason: &str,
) -> MutationAuthorizationDecision {
    build_decision(
        intent,
        environment,
        MutationAuthorizationResult::ReplayRejected,
        reason,
        MutationTtlState::Current,
        idempotency_state,
    )
}

fn caller_matches(
    required: MutationRequiredCallerCategory,
    caller: &CallerVerificationSummary,
) -> bool {
    match required {
        MutationRequiredCallerCategory::VerifiedInteractiveUser => {
            caller.interactive_marker
                && matches!(
                    caller.verification_state,
                    CallerVerificationState::VerifiedInteractiveUser
                        | CallerVerificationState::AdministratorPolicyVerified
                )
        }
        MutationRequiredCallerCategory::AdministratorPolicyVerified => {
            caller.administrator_policy_marker
                && caller.verification_state == CallerVerificationState::AdministratorPolicyVerified
        }
        MutationRequiredCallerCategory::VerifiedServiceIdentity => {
            caller.verification_state == CallerVerificationState::VerifiedServiceIdentity
        }
        MutationRequiredCallerCategory::ForegroundDevelopment => {
            caller.verification_state == CallerVerificationState::ForegroundDevelopment
        }
        MutationRequiredCallerCategory::AnyVerifiedLocal => {
            caller.verification_state.permits_read_only_commands()
        }
        MutationRequiredCallerCategory::None => false,
    }
}

fn target_state_matches(
    required: MutationRequiredTargetState,
    actual: MutationCapabilityStateCategory,
) -> bool {
    match required {
        MutationRequiredTargetState::AnyDeclared => !matches!(
            actual,
            MutationCapabilityStateCategory::Unavailable | MutationCapabilityStateCategory::Blocked
        ),
        MutationRequiredTargetState::InactiveOrReady => matches!(
            actual,
            MutationCapabilityStateCategory::Inactive
                | MutationCapabilityStateCategory::Ready
                | MutationCapabilityStateCategory::Stopped
        ),
        MutationRequiredTargetState::ActiveOrPaused => matches!(
            actual,
            MutationCapabilityStateCategory::Active | MutationCapabilityStateCategory::Paused
        ),
        MutationRequiredTargetState::StoppedOrPaused => matches!(
            actual,
            MutationCapabilityStateCategory::Stopped
                | MutationCapabilityStateCategory::Paused
                | MutationCapabilityStateCategory::Inactive
        ),
        MutationRequiredTargetState::Available => matches!(
            actual,
            MutationCapabilityStateCategory::Available | MutationCapabilityStateCategory::Ready
        ),
        MutationRequiredTargetState::Unavailable => {
            actual == MutationCapabilityStateCategory::Unavailable
        }
        MutationRequiredTargetState::NotApplicable => {
            actual == MutationCapabilityStateCategory::NotApplicable
        }
    }
}

fn bounded_request_hash(intent: &MutationIntent) -> String {
    let canonical = format!(
        "{}|{}|{:?}|{}|{}|{:?}|{}|{}|{:?}|{}|{}|{}",
        intent.ipc_session_ref,
        intent.caller_verification_ref,
        intent.command_id,
        intent.policy_ref,
        intent.policy_version,
        intent.target_capability_category,
        intent.target_capability_ref,
        intent.requested_operation_category,
        intent.expiry_ttl_bucket,
        intent.ownership_epoch,
        intent.explicit_user_action,
        intent.dry_run
    );
    let digest = Sha256::digest(canonical.as_bytes());
    format!("{digest:x}")
}

fn idempotency_key(intent: &MutationIntent, idempotency_ref: &str) -> String {
    format!(
        "{}|{}|{}|{}",
        intent.ipc_session_ref,
        intent.command_id.as_str(),
        intent.policy_version,
        idempotency_ref
    )
}

fn decision_audit_refs(result: MutationAuthorizationResult) -> Vec<String> {
    let terminal = match result {
        MutationAuthorizationResult::ApprovedDryRun => "mutation_authorization_approved_dry_run",
        MutationAuthorizationResult::ApprovedForExecution => {
            "mutation_authorization_approved_for_execution"
        }
        MutationAuthorizationResult::Expired => "mutation_intent_expired",
        MutationAuthorizationResult::ReplayRejected => "mutation_replay_rejected",
        MutationAuthorizationResult::SessionMismatch => "mutation_session_mismatch",
        MutationAuthorizationResult::OwnershipEpochMismatch => "mutation_ownership_epoch_mismatch",
        _ => "mutation_authorization_denied",
    };
    let mut refs = vec![terminal.to_string()];
    if result == MutationAuthorizationResult::ApprovedDryRun {
        refs.push("mutation_execution_blocked".to_string());
    } else if result == MutationAuthorizationResult::ApprovedForExecution {
        refs.push("ip_helper_execution_authorized".to_string());
    }
    refs
}

fn map_state(value: &str) -> MutationCapabilityStateCategory {
    match value {
        "active" | "running" => MutationCapabilityStateCategory::Active,
        "ready" => MutationCapabilityStateCategory::Ready,
        "paused" => MutationCapabilityStateCategory::Paused,
        "degraded" | "failed" => MutationCapabilityStateCategory::Degraded,
        "stopped" => MutationCapabilityStateCategory::Stopped,
        "inactive" | "disabled" => MutationCapabilityStateCategory::Inactive,
        "blocked" | "revoked" => MutationCapabilityStateCategory::Blocked,
        _ => MutationCapabilityStateCategory::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        AllowedCommandClass, CallerCategory, CallerVerificationImplementationState,
        CallerVerificationReadStatus, ElevationCategory, LocalRemoteClassification,
        MutationIntentTtlBucket, SessionBindingState, TokenSuitabilityCategory,
        VerificationFreshnessBucket, CALLER_VERIFICATION_SCHEMA_VERSION,
    };

    fn caller() -> CallerVerificationSummary {
        CallerVerificationSummary {
            schema_version: CALLER_VERIFICATION_SCHEMA_VERSION,
            verification_ref: "caller_verification_ref".to_string(),
            caller_category: CallerCategory::InteractiveUser,
            verification_state: CallerVerificationState::VerifiedInteractiveUser,
            local_classification: LocalRemoteClassification::Local,
            interactive_marker: true,
            service_marker: false,
            administrator_policy_marker: false,
            token_suitability: TokenSuitabilityCategory::ImpersonationSuitable,
            elevation_category: ElevationCategory::Standard,
            session_binding_state: SessionBindingState::Bound,
            freshness_bucket: VerificationFreshnessBucket::CurrentConnection,
            allowed_command_classes: vec![
                AllowedCommandClass::ReadStatus,
                AllowedCommandClass::MutationAuthorizationEvaluation,
                AllowedCommandClass::FutureUserMutationCandidate,
            ],
            degraded_reason: None,
            audit_refs: vec!["caller_token_classified".to_string()],
            provenance_id: "windows_named_pipe_impersonation".to_string(),
            redaction_status: RedactionStatus::Redacted,
            production_mutations_enabled: false,
        }
    }

    fn context() -> MutationAuthorizationRuntimeContext {
        MutationAuthorizationRuntimeContext {
            ipc_session_ref: "ipc_session_ref".to_string(),
            protocol_schema_valid: true,
            runtime_state: MutationRuntimeStateCategory::ServiceOwnedReady,
            ownership_epoch: 7,
            ip_helper_state: MutationCapabilityStateCategory::Inactive,
            etw_state: MutationCapabilityStateCategory::Inactive,
            dns_sensing_state: MutationCapabilityStateCategory::Inactive,
            auth_remote_state: MutationCapabilityStateCategory::Inactive,
            provider_controller_state: MutationCapabilityStateCategory::Inactive,
            sampler_state: MutationCapabilityStateCategory::Inactive,
            scheduler_state: MutationCapabilityStateCategory::Inactive,
            scheduler_host_state: MutationCapabilityStateCategory::Stopped,
            report_state: MutationCapabilityStateCategory::Available,
            export_state: MutationCapabilityStateCategory::Available,
            llm_state: MutationCapabilityStateCategory::Unavailable,
            capture_state: MutationCapabilityStateCategory::Unavailable,
            response_state: MutationCapabilityStateCategory::Blocked,
        }
    }

    fn active_ip_helper_context() -> MutationAuthorizationRuntimeContext {
        MutationAuthorizationRuntimeContext {
            ip_helper_state: MutationCapabilityStateCategory::Active,
            provider_controller_state: MutationCapabilityStateCategory::Active,
            ..context()
        }
    }

    fn intent(command_id: MutationCommandId) -> MutationIntent {
        let policy = policy_for_command(command_id);
        MutationIntent {
            schema_version: MUTATION_AUTHORIZATION_SCHEMA_VERSION,
            intent_ref: "mutation_intent_ref".to_string(),
            request_ref: "mutation_request_ref".to_string(),
            ipc_session_ref: "ipc_session_ref".to_string(),
            caller_verification_ref: "caller_verification_ref".to_string(),
            command_id,
            policy_ref: policy.policy_ref,
            policy_version: policy.policy_version,
            target_capability_ref: "target_capability_ref".to_string(),
            target_capability_category: policy.required_capability,
            requested_operation_category: "explicit_operation".to_string(),
            created_time_bucket: MutationIntentTimeBucket::CurrentConnection,
            expiry_ttl_bucket: MutationIntentTtlBucket::ThirtySeconds,
            ownership_epoch: 7,
            idempotency_ref: Some("idempotency_ref".to_string()),
            explicit_user_action: true,
            dry_run: true,
            audit_refs: vec!["mutation_intent_received".to_string()],
            provenance_id: "servicehost_mutation_authorization".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    #[test]
    fn mutation_authorization_approves_dry_run_without_execution_attempt() {
        let mut evaluator = MutationAuthorizationEvaluator::new();
        let decision = evaluator.evaluate_at(
            &intent(MutationCommandId::ChangeNetworkProviderMode),
            &caller(),
            &context(),
            10,
        );
        assert_eq!(decision.result, MutationAuthorizationResult::ApprovedDryRun);
        assert!(!decision.execution_enabled);
        assert_eq!(evaluator.execution_attempt_count(), 0);
    }

    #[test]
    fn mutation_authorization_approves_ip_helper_execution_and_consumes_once() {
        let mut evaluator = MutationAuthorizationEvaluator::new();
        let request = intent(MutationCommandId::SampleIpHelperNow);
        let decision = evaluator.evaluate_at(&request, &caller(), &active_ip_helper_context(), 10);
        assert_eq!(
            decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        assert!(decision.execution_enabled);
        assert!(!decision.dry_run);
        assert_eq!(evaluator.execution_authorization_count(), 1);

        let execution = MutationExecutionRequest {
            schema_version: MUTATION_AUTHORIZATION_SCHEMA_VERSION,
            decision_ref: decision.decision_ref.clone(),
            intent: request.clone(),
            explicit_user_action: true,
            provenance_id: "servicehost_ip_helper_production_ipc".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        let consumed = evaluator
            .consume_execution_authorization_at(
                &execution,
                "ipc_session_ref",
                MutationCommandId::SampleIpHelperNow,
                7,
                20,
            )
            .expect("execution decision consumed");
        assert_eq!(consumed.decision_ref, decision.decision_ref);
        assert_eq!(evaluator.execution_attempt_count(), 1);
        assert_eq!(
            evaluator
                .consume_execution_authorization_at(
                    &execution,
                    "ipc_session_ref",
                    MutationCommandId::SampleIpHelperNow,
                    7,
                    30,
                )
                .expect_err("replay rejected"),
            "ip_helper_execution_replay_rejected"
        );
    }

    #[test]
    fn mutation_authorization_requires_explicit_action_session_and_epoch() {
        let mut evaluator = MutationAuthorizationEvaluator::new();
        let mut request = intent(MutationCommandId::ActivateIpHelperProvider);
        request.explicit_user_action = false;
        assert_eq!(
            evaluator
                .evaluate_at(&request, &caller(), &context(), 10)
                .result,
            MutationAuthorizationResult::ExplicitActionRequired
        );

        request.explicit_user_action = true;
        request.ipc_session_ref = "different_session".to_string();
        assert_eq!(
            evaluator
                .evaluate_at(&request, &caller(), &context(), 20)
                .result,
            MutationAuthorizationResult::SessionMismatch
        );

        request.ipc_session_ref = "ipc_session_ref".to_string();
        request.ownership_epoch = 8;
        assert_eq!(
            evaluator
                .evaluate_at(&request, &caller(), &context(), 30)
                .result,
            MutationAuthorizationResult::OwnershipEpochMismatch
        );
    }

    #[test]
    fn mutation_authorization_expiry_replay_and_idempotency_are_bounded() {
        let mut evaluator = MutationAuthorizationEvaluator::new();
        let request = intent(MutationCommandId::ActivateIpHelperProvider);
        let first = evaluator.evaluate_at(&request, &caller(), &context(), 10);
        let duplicate = evaluator.evaluate_at(&request, &caller(), &context(), 20);
        assert_eq!(first.decision_ref, duplicate.decision_ref);
        assert_eq!(
            duplicate.idempotency_state,
            MutationIdempotencyState::Reused
        );

        let mut conflict = request.clone();
        conflict.requested_operation_category = "different_operation".to_string();
        assert_eq!(
            evaluator
                .evaluate_at(&conflict, &caller(), &context(), 30)
                .result,
            MutationAuthorizationResult::ReplayRejected
        );

        let expired = evaluator.evaluate_at(&request, &caller(), &context(), 31_000);
        assert_eq!(expired.result, MutationAuthorizationResult::Expired);
        assert_eq!(expired.ttl_state, MutationTtlState::Expired);
    }

    #[test]
    fn mutation_authorization_denies_response_and_administrator_membership_alone() {
        let mut evaluator = MutationAuthorizationEvaluator::new();
        let response = evaluator.evaluate_at(
            &intent(MutationCommandId::ExecuteResponse),
            &caller(),
            &context(),
            10,
        );
        assert!(matches!(
            response.result,
            MutationAuthorizationResult::CallerNotAuthorized
                | MutationAuthorizationResult::CommandClassNotAllowed
                | MutationAuthorizationResult::ResponseCapabilityBlocked
        ));

        let mut administrator = caller();
        administrator.caller_category = CallerCategory::AdministratorPolicy;
        administrator.verification_state = CallerVerificationState::AdministratorPolicyVerified;
        administrator.administrator_policy_marker = true;
        administrator.allowed_command_classes = vec![
            AllowedCommandClass::MutationAuthorizationEvaluation,
            AllowedCommandClass::FutureAdminMutationCandidate,
        ];
        let user_command = evaluator.evaluate_at(
            &intent(MutationCommandId::SampleIpHelperNow),
            &administrator,
            &context(),
            20,
        );
        assert_ne!(
            user_command.result,
            MutationAuthorizationResult::ApprovedDryRun
        );
    }

    #[test]
    fn mutation_authorization_disconnect_invalidates_session_records() {
        let mut evaluator = MutationAuthorizationEvaluator::new();
        let request = intent(MutationCommandId::ActivateIpHelperProvider);
        let first = evaluator.evaluate_at(&request, &caller(), &context(), 10);
        evaluator.invalidate_session("ipc_session_ref");
        let second = evaluator.evaluate_at(&request, &caller(), &context(), 20);
        assert_ne!(first.decision_ref, second.decision_ref);
        assert_eq!(evaluator.execution_attempt_count(), 0);
    }

    #[test]
    fn mutation_authorization_status_is_separate_from_caller_verification_status() {
        let evaluator = MutationAuthorizationEvaluator::new();
        let status = evaluator.status(true, true);
        status.validate().expect("valid mutation status");
        assert_eq!(
            status.framework_state,
            MutationAuthorizationFrameworkState::ImplementedNarrowExecution
        );
        assert!(status.production_execution_enabled);

        let caller_status = CallerVerificationReadStatus {
            schema_version: CALLER_VERIFICATION_SCHEMA_VERSION,
            caller_impersonation: CallerVerificationImplementationState::Implemented,
            token_classification: CallerVerificationImplementationState::Implemented,
            production_mutation_authorization:
                CallerVerificationImplementationState::NotImplemented,
            production_mutations_enabled: false,
            production_service_mode_policy: "strict_local_verification".to_string(),
            foreground_development_policy: "disabled".to_string(),
            remote_caller_rejection_enabled: true,
            network_logon_rejection_enabled: true,
            session_binding_enabled: true,
            last_verification: None,
            audit_refs: vec!["caller_verification_audit".to_string()],
            provenance_id: "caller_verification".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        caller_status
            .validate()
            .expect("caller status remains valid");
    }
}
