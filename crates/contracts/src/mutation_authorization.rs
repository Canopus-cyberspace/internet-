use crate::{
    caller_verification::{AllowedCommandClass, CallerCategory},
    RedactionStatus, SchemaVersion,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MUTATION_AUTHORIZATION_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MUTATION_POLICY_CATALOG_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_MUTATION_AUTHORIZATION_TEXT_LEN: usize = 128;
pub const MAX_MUTATION_AUTHORIZATION_REFS: usize = 16;
pub const MAX_MUTATION_REQUEST_BYTES: u32 = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationCommandId {
    ActivateIpHelperProvider,
    SampleIpHelperNow,
    PauseIpHelper,
    StopIpHelper,
    ActivateEtwProvider,
    PauseEtwProvider,
    ResumeEtwProvider,
    StopEtwProvider,
    ActivateDnsSensing,
    PauseDnsSensing,
    ResumeDnsSensing,
    StopDnsSensing,
    ActivateAuthRemoteSensing,
    PauseAuthRemoteSensing,
    ResumeAuthRemoteSensing,
    StopAuthRemoteSensing,
    ConfigureIpHelperSchedule,
    EnableIpHelperSchedule,
    PauseIpHelperSchedule,
    ResumeIpHelperSchedule,
    DisableIpHelperSchedule,
    ChangeNetworkProviderMode,
    ActivateNativeSampler,
    SampleNativeSamplerNow,
    PauseNativeSampler,
    ResumeNativeSampler,
    StopNativeSampler,
    UpdateNativeSchedule,
    StartSchedulerHost,
    PauseSchedulerHost,
    ResumeSchedulerHost,
    StopSchedulerHost,
    RequestCaptureAuthorization,
    RevokeCaptureAuthorization,
    GenerateReport,
    ExportArtifact,
    GenerateLlmStory,
    ExecuteResponse,
    RequestServiceHostShutdown,
    KillProcess,
    StopArbitraryService,
    ModifyFirewall,
    BlockNetwork,
    IsolateHost,
    DisableAccount,
    QuarantineFile,
    InjectPacket,
    ExecuteArbitraryCommand,
    CredentialOperation,
    GenericElevatedExecution,
    AutomaticCapture,
    AutomaticLlmGeneration,
}

impl MutationCommandId {
    pub const ALL: [Self; 52] = [
        Self::ActivateIpHelperProvider,
        Self::SampleIpHelperNow,
        Self::PauseIpHelper,
        Self::StopIpHelper,
        Self::ActivateEtwProvider,
        Self::PauseEtwProvider,
        Self::ResumeEtwProvider,
        Self::StopEtwProvider,
        Self::ActivateDnsSensing,
        Self::PauseDnsSensing,
        Self::ResumeDnsSensing,
        Self::StopDnsSensing,
        Self::ActivateAuthRemoteSensing,
        Self::PauseAuthRemoteSensing,
        Self::ResumeAuthRemoteSensing,
        Self::StopAuthRemoteSensing,
        Self::ConfigureIpHelperSchedule,
        Self::EnableIpHelperSchedule,
        Self::PauseIpHelperSchedule,
        Self::ResumeIpHelperSchedule,
        Self::DisableIpHelperSchedule,
        Self::ChangeNetworkProviderMode,
        Self::ActivateNativeSampler,
        Self::SampleNativeSamplerNow,
        Self::PauseNativeSampler,
        Self::ResumeNativeSampler,
        Self::StopNativeSampler,
        Self::UpdateNativeSchedule,
        Self::StartSchedulerHost,
        Self::PauseSchedulerHost,
        Self::ResumeSchedulerHost,
        Self::StopSchedulerHost,
        Self::RequestCaptureAuthorization,
        Self::RevokeCaptureAuthorization,
        Self::GenerateReport,
        Self::ExportArtifact,
        Self::GenerateLlmStory,
        Self::ExecuteResponse,
        Self::RequestServiceHostShutdown,
        Self::KillProcess,
        Self::StopArbitraryService,
        Self::ModifyFirewall,
        Self::BlockNetwork,
        Self::IsolateHost,
        Self::DisableAccount,
        Self::QuarantineFile,
        Self::InjectPacket,
        Self::ExecuteArbitraryCommand,
        Self::CredentialOperation,
        Self::GenericElevatedExecution,
        Self::AutomaticCapture,
        Self::AutomaticLlmGeneration,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActivateIpHelperProvider => "activate_ip_helper",
            Self::SampleIpHelperNow => "sample_ip_helper_once",
            Self::PauseIpHelper => "pause_ip_helper",
            Self::StopIpHelper => "stop_ip_helper",
            Self::ActivateEtwProvider => "activate_etw",
            Self::PauseEtwProvider => "pause_etw",
            Self::ResumeEtwProvider => "resume_etw",
            Self::StopEtwProvider => "stop_etw",
            Self::ActivateDnsSensing => "activate_dns_sensing",
            Self::PauseDnsSensing => "pause_dns_sensing",
            Self::ResumeDnsSensing => "resume_dns_sensing",
            Self::StopDnsSensing => "stop_dns_sensing",
            Self::ActivateAuthRemoteSensing => "activate_auth_remote_sensing",
            Self::PauseAuthRemoteSensing => "pause_auth_remote_sensing",
            Self::ResumeAuthRemoteSensing => "resume_auth_remote_sensing",
            Self::StopAuthRemoteSensing => "stop_auth_remote_sensing",
            Self::ConfigureIpHelperSchedule => "configure_ip_helper_schedule",
            Self::EnableIpHelperSchedule => "enable_ip_helper_schedule",
            Self::PauseIpHelperSchedule => "pause_ip_helper_schedule",
            Self::ResumeIpHelperSchedule => "resume_ip_helper_schedule",
            Self::DisableIpHelperSchedule => "disable_ip_helper_schedule",
            Self::ChangeNetworkProviderMode => "change_network_provider_mode",
            Self::ActivateNativeSampler => "activate_native_sampler",
            Self::SampleNativeSamplerNow => "sample_native_sampler_now",
            Self::PauseNativeSampler => "pause_native_sampler",
            Self::ResumeNativeSampler => "resume_native_sampler",
            Self::StopNativeSampler => "stop_native_sampler",
            Self::UpdateNativeSchedule => "update_native_schedule",
            Self::StartSchedulerHost => "start_scheduler_host",
            Self::PauseSchedulerHost => "pause_scheduler_host",
            Self::ResumeSchedulerHost => "resume_scheduler_host",
            Self::StopSchedulerHost => "stop_scheduler_host",
            Self::RequestCaptureAuthorization => "request_capture_authorization",
            Self::RevokeCaptureAuthorization => "revoke_capture_authorization",
            Self::GenerateReport => "generate_report",
            Self::ExportArtifact => "export_artifact",
            Self::GenerateLlmStory => "generate_llm_story",
            Self::ExecuteResponse => "execute_response",
            Self::RequestServiceHostShutdown => "request_service_host_shutdown",
            Self::KillProcess => "kill_process",
            Self::StopArbitraryService => "stop_arbitrary_service",
            Self::ModifyFirewall => "modify_firewall",
            Self::BlockNetwork => "block_network",
            Self::IsolateHost => "isolate_host",
            Self::DisableAccount => "disable_account",
            Self::QuarantineFile => "quarantine_file",
            Self::InjectPacket => "inject_packet",
            Self::ExecuteArbitraryCommand => "execute_arbitrary_command",
            Self::CredentialOperation => "credential_operation",
            Self::GenericElevatedExecution => "generic_elevated_execution",
            Self::AutomaticCapture => "automatic_capture",
            Self::AutomaticLlmGeneration => "automatic_llm_generation",
        }
    }

    pub fn ip_helper_production_execution_enabled(self) -> bool {
        matches!(
            self,
            Self::ActivateIpHelperProvider
                | Self::SampleIpHelperNow
                | Self::StopIpHelper
                | Self::ConfigureIpHelperSchedule
                | Self::EnableIpHelperSchedule
                | Self::PauseIpHelperSchedule
                | Self::ResumeIpHelperSchedule
                | Self::DisableIpHelperSchedule
        )
    }

    pub fn production_execution_enabled(self) -> bool {
        self.ip_helper_production_execution_enabled()
            || matches!(
                self,
                Self::ActivateEtwProvider
                    | Self::PauseEtwProvider
                    | Self::ResumeEtwProvider
                    | Self::StopEtwProvider
                    | Self::ActivateDnsSensing
                    | Self::PauseDnsSensing
                    | Self::ResumeDnsSensing
                    | Self::StopDnsSensing
                    | Self::ActivateAuthRemoteSensing
                    | Self::PauseAuthRemoteSensing
                    | Self::ResumeAuthRemoteSensing
                    | Self::StopAuthRemoteSensing
            )
    }

    pub fn ip_helper_schedule_execution_enabled(self) -> bool {
        matches!(
            self,
            Self::ConfigureIpHelperSchedule
                | Self::EnableIpHelperSchedule
                | Self::PauseIpHelperSchedule
                | Self::ResumeIpHelperSchedule
                | Self::DisableIpHelperSchedule
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationCommandClassification {
    AllowedForFrameworkReview,
    FutureUserMutation,
    FutureAdminMutation,
    ExplicitActionOnly,
    TestOnly,
    AlwaysDenied,
    NotImplemented,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationRequiredCallerCategory {
    VerifiedInteractiveUser,
    AdministratorPolicyVerified,
    VerifiedServiceIdentity,
    ForegroundDevelopment,
    AnyVerifiedLocal,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationCapabilityCategory {
    IpHelperProvider,
    EtwProvider,
    DnsSensingProvider,
    AuthRemoteSensingProvider,
    NetworkProviderController,
    NativeSampler,
    NativeScheduler,
    NativeSchedulerHost,
    CaptureAuthorization,
    ReportGeneration,
    Export,
    LlmAlertStory,
    Response,
    ServiceHostLifecycle,
    HostMutation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationRequiredTargetState {
    AnyDeclared,
    InactiveOrReady,
    ActiveOrPaused,
    StoppedOrPaused,
    Available,
    Unavailable,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationIntentTtlBucket {
    FiveSeconds,
    ThirtySeconds,
    SixtySeconds,
}

impl MutationIntentTtlBucket {
    pub fn duration_millis(self) -> u64 {
        match self {
            Self::FiveSeconds => 5_000,
            Self::ThirtySeconds => 30_000,
            Self::SixtySeconds => 60_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationIntentTimeBucket {
    CurrentConnection,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationIdempotencyPolicy {
    Required,
    Optional,
    Forbidden,
    SingleUse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationReplayPolicy {
    Reject,
    ReturnExistingDecision,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationCancellationPolicy {
    ConnectionClose,
    ExplicitFutureCancellation,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationExecutionTimeoutBucket {
    OneSecond,
    FiveSeconds,
    ThirtySeconds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationPolicyImplementationState {
    FrameworkReviewOnly,
    NotImplemented,
    AlwaysDenied,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationCommandPolicy {
    pub command_id: MutationCommandId,
    pub policy_ref: String,
    pub policy_version: SchemaVersion,
    pub classifications: Vec<MutationCommandClassification>,
    pub required_caller_category: MutationRequiredCallerCategory,
    pub required_command_class: AllowedCommandClass,
    pub administrator_required: bool,
    pub interactive_session_required: bool,
    pub service_host_runtime_required: bool,
    pub required_capability: MutationCapabilityCategory,
    pub required_target_state: MutationRequiredTargetState,
    pub required_ownership_epoch: bool,
    pub request_ttl_bucket: MutationIntentTtlBucket,
    pub idempotency_policy: MutationIdempotencyPolicy,
    pub one_time_intent_required: bool,
    pub maximum_request_size: u32,
    pub maximum_execution_timeout: MutationExecutionTimeoutBucket,
    pub audit_required: bool,
    pub replay_policy: MutationReplayPolicy,
    pub cancellation_policy: MutationCancellationPolicy,
    pub response_capable: bool,
    pub implementation_state: MutationPolicyImplementationState,
    pub execution_enabled: bool,
    pub degraded_reason: Option<String>,
    pub redaction_status: RedactionStatus,
}

impl MutationCommandPolicy {
    pub fn validate(&self) -> Result<(), MutationAuthorizationContractError> {
        validate_declared_identifier("policy_ref", &self.policy_ref)?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        if self.classifications.is_empty()
            || self.classifications.len() > MAX_MUTATION_AUTHORIZATION_REFS
        {
            return Err(MutationAuthorizationContractError::TooManyItems(
                "classifications",
            ));
        }
        if self.policy_version != MUTATION_POLICY_CATALOG_VERSION {
            return Err(MutationAuthorizationContractError::UnsupportedPolicyVersion);
        }
        if self.maximum_request_size == 0 || self.maximum_request_size > MAX_MUTATION_REQUEST_BYTES
        {
            return Err(MutationAuthorizationContractError::InvalidLimit(
                "maximum_request_size",
            ));
        }
        if self.execution_enabled && !self.command_id.production_execution_enabled() {
            return Err(MutationAuthorizationContractError::ExecutionForbidden);
        }
        if self.execution_enabled {
            if self.idempotency_policy != MutationIdempotencyPolicy::SingleUse {
                return Err(MutationAuthorizationContractError::InvalidExecutionPolicy);
            }
            if !self.one_time_intent_required
                || !self.service_host_runtime_required
                || !self.required_ownership_epoch
                || self.response_capable
                || self.required_caller_category
                    != MutationRequiredCallerCategory::VerifiedInteractiveUser
                || self.required_command_class != AllowedCommandClass::FutureUserMutationCandidate
            {
                return Err(MutationAuthorizationContractError::InvalidExecutionPolicy);
            }
        }
        if !self.audit_required {
            return Err(MutationAuthorizationContractError::AuditRequired);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(MutationAuthorizationContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationIntent {
    pub schema_version: SchemaVersion,
    pub intent_ref: String,
    pub request_ref: String,
    pub ipc_session_ref: String,
    pub caller_verification_ref: String,
    pub command_id: MutationCommandId,
    pub policy_ref: String,
    pub policy_version: SchemaVersion,
    pub target_capability_ref: String,
    pub target_capability_category: MutationCapabilityCategory,
    pub requested_operation_category: String,
    pub created_time_bucket: MutationIntentTimeBucket,
    pub expiry_ttl_bucket: MutationIntentTtlBucket,
    pub ownership_epoch: u64,
    pub idempotency_ref: Option<String>,
    pub explicit_user_action: bool,
    pub dry_run: bool,
    pub audit_refs: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl MutationIntent {
    pub fn validate(&self) -> Result<(), MutationAuthorizationContractError> {
        if self.schema_version != MUTATION_AUTHORIZATION_SCHEMA_VERSION {
            return Err(MutationAuthorizationContractError::UnsupportedSchemaVersion);
        }
        for (field, value) in [
            ("intent_ref", self.intent_ref.as_str()),
            ("request_ref", self.request_ref.as_str()),
            ("ipc_session_ref", self.ipc_session_ref.as_str()),
            (
                "caller_verification_ref",
                self.caller_verification_ref.as_str(),
            ),
            ("target_capability_ref", self.target_capability_ref.as_str()),
            (
                "requested_operation_category",
                self.requested_operation_category.as_str(),
            ),
            ("provenance_id", self.provenance_id.as_str()),
        ] {
            validate_safe_text(field, value)?;
        }
        validate_declared_identifier("policy_ref", &self.policy_ref)?;
        validate_optional_safe_text("idempotency_ref", self.idempotency_ref.as_deref())?;
        validate_refs("audit_refs", &self.audit_refs)?;
        if self.ownership_epoch == 0 {
            return Err(MutationAuthorizationContractError::InvalidOwnershipEpoch);
        }
        if !self.dry_run {
            return Err(MutationAuthorizationContractError::ExecutionForbidden);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(MutationAuthorizationContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationAuthorizationResult {
    ApprovedDryRun,
    ApprovedForExecution,
    Denied,
    Expired,
    ReplayRejected,
    SessionMismatch,
    CallerNotAuthorized,
    CommandClassNotAllowed,
    PolicyNotFound,
    PolicyVersionMismatch,
    RuntimeStateInvalid,
    OwnershipEpochMismatch,
    CapabilityUnavailable,
    ProviderStateInvalid,
    ExplicitActionRequired,
    AdministratorPolicyRequired,
    ResponseCapabilityBlocked,
    NotImplemented,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationExecutionAuthorizationState {
    ApprovedForExecution,
    Consumed,
    ExecutionStarted,
    ExecutionCompleted,
    ExecutionFailed,
    ExecutionCancelled,
    ExecutionTimedOut,
    ExecutionRejected,
    AlreadySatisfied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationExecutionResultCategory {
    Completed,
    Failed,
    Cancelled,
    TimedOut,
    Rejected,
    AlreadySatisfied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLifecycleCategory {
    Inactive,
    Activating,
    Active,
    Paused,
    Sampling,
    Stopping,
    Stopped,
    Degraded,
    Failed,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationRuntimeStateCategory {
    ServiceOwnedReady,
    Degraded,
    ShuttingDown,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationCapabilityStateCategory {
    Available,
    Inactive,
    Ready,
    Active,
    Paused,
    Degraded,
    Stopped,
    Unavailable,
    Blocked,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationTtlState {
    Current,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationIdempotencyState {
    New,
    Reused,
    Conflict,
    NotRequired,
    Missing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationAuthorizationDecision {
    pub schema_version: SchemaVersion,
    pub decision_ref: String,
    pub intent_ref: String,
    pub command_id: MutationCommandId,
    pub policy_ref: String,
    pub policy_version: SchemaVersion,
    pub result: MutationAuthorizationResult,
    pub caller_category: CallerCategory,
    pub command_class: AllowedCommandClass,
    pub runtime_state: MutationRuntimeStateCategory,
    pub capability_state: MutationCapabilityStateCategory,
    pub ownership_epoch: u64,
    pub ttl_state: MutationTtlState,
    pub idempotency_state: MutationIdempotencyState,
    pub dry_run: bool,
    pub execution_enabled: bool,
    pub degraded_reason: Option<String>,
    pub audit_refs: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl MutationAuthorizationDecision {
    pub fn validate(&self) -> Result<(), MutationAuthorizationContractError> {
        if self.schema_version != MUTATION_AUTHORIZATION_SCHEMA_VERSION {
            return Err(MutationAuthorizationContractError::UnsupportedSchemaVersion);
        }
        for (field, value) in [
            ("decision_ref", self.decision_ref.as_str()),
            ("intent_ref", self.intent_ref.as_str()),
            ("provenance_id", self.provenance_id.as_str()),
        ] {
            validate_safe_text(field, value)?;
        }
        validate_declared_identifier("policy_ref", &self.policy_ref)?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        validate_refs("audit_refs", &self.audit_refs)?;
        if self.ownership_epoch == 0 {
            return Err(MutationAuthorizationContractError::InvalidOwnershipEpoch);
        }
        match self.result {
            MutationAuthorizationResult::ApprovedForExecution => {
                if self.dry_run
                    || !self.execution_enabled
                    || !self.command_id.production_execution_enabled()
                {
                    return Err(MutationAuthorizationContractError::ExecutionForbidden);
                }
            }
            _ => {
                if !self.dry_run || self.execution_enabled {
                    return Err(MutationAuthorizationContractError::ExecutionForbidden);
                }
            }
        }
        if self.result == MutationAuthorizationResult::ApprovedDryRun && self.execution_enabled {
            return Err(MutationAuthorizationContractError::ExecutionForbidden);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(MutationAuthorizationContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationExecutionRequest {
    pub schema_version: SchemaVersion,
    pub decision_ref: String,
    pub intent: MutationIntent,
    pub explicit_user_action: bool,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl MutationExecutionRequest {
    pub fn validate(&self) -> Result<(), MutationAuthorizationContractError> {
        if self.schema_version != MUTATION_AUTHORIZATION_SCHEMA_VERSION {
            return Err(MutationAuthorizationContractError::UnsupportedSchemaVersion);
        }
        validate_safe_text("decision_ref", &self.decision_ref)?;
        self.intent.validate()?;
        validate_safe_text("provenance_id", &self.provenance_id)?;
        if !self.explicit_user_action {
            return Err(MutationAuthorizationContractError::ExplicitActionRequired);
        }
        if !self.intent.command_id.production_execution_enabled() {
            return Err(MutationAuthorizationContractError::ExecutionForbidden);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(MutationAuthorizationContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationExecutionCounters {
    pub sampled_count: u32,
    pub skipped_count: u32,
    pub rejected_count: u32,
}

impl MutationExecutionCounters {
    fn validate(&self) -> Result<(), MutationAuthorizationContractError> {
        if self.sampled_count > 16_384
            || self.skipped_count > 16_384
            || self.rejected_count > 16_384
        {
            return Err(MutationAuthorizationContractError::InvalidLimit(
                "execution_counters",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationExecutionReceipt {
    pub schema_version: SchemaVersion,
    pub execution_ref: String,
    pub authorization_decision_ref: String,
    pub intent_ref: String,
    pub request_ref: String,
    pub command_id: MutationCommandId,
    pub policy_ref: String,
    pub policy_version: SchemaVersion,
    pub ownership_epoch: u64,
    pub provider_category: MutationCapabilityCategory,
    pub previous_lifecycle_state: ProviderLifecycleCategory,
    pub resulting_lifecycle_state: ProviderLifecycleCategory,
    pub authorization_state: MutationExecutionAuthorizationState,
    pub result_category: MutationExecutionResultCategory,
    pub started_time_bucket: String,
    pub completed_time_bucket: String,
    pub duration_bucket: String,
    pub counters: MutationExecutionCounters,
    pub batch_refs: Vec<String>,
    pub fact_refs: Vec<String>,
    pub canonical_snapshot_refs: Vec<String>,
    pub audit_refs: Vec<String>,
    pub degraded_reason: Option<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl MutationExecutionReceipt {
    pub fn validate(&self) -> Result<(), MutationAuthorizationContractError> {
        if self.schema_version != MUTATION_AUTHORIZATION_SCHEMA_VERSION {
            return Err(MutationAuthorizationContractError::UnsupportedSchemaVersion);
        }
        for (field, value) in [
            ("execution_ref", self.execution_ref.as_str()),
            (
                "authorization_decision_ref",
                self.authorization_decision_ref.as_str(),
            ),
            ("intent_ref", self.intent_ref.as_str()),
            ("request_ref", self.request_ref.as_str()),
            ("started_time_bucket", self.started_time_bucket.as_str()),
            ("completed_time_bucket", self.completed_time_bucket.as_str()),
            ("duration_bucket", self.duration_bucket.as_str()),
            ("provenance_id", self.provenance_id.as_str()),
        ] {
            validate_safe_text(field, value)?;
        }
        validate_declared_identifier("policy_ref", &self.policy_ref)?;
        validate_refs("batch_refs", &self.batch_refs)?;
        validate_refs("fact_refs", &self.fact_refs)?;
        validate_refs("canonical_snapshot_refs", &self.canonical_snapshot_refs)?;
        validate_refs("audit_refs", &self.audit_refs)?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        self.counters.validate()?;
        if self.ownership_epoch == 0 {
            return Err(MutationAuthorizationContractError::InvalidOwnershipEpoch);
        }
        if !self.command_id.production_execution_enabled() {
            return Err(MutationAuthorizationContractError::ExecutionForbidden);
        }
        let expected_provider = if matches!(
            self.command_id,
            MutationCommandId::ActivateEtwProvider
                | MutationCommandId::PauseEtwProvider
                | MutationCommandId::ResumeEtwProvider
                | MutationCommandId::StopEtwProvider
        ) {
            MutationCapabilityCategory::EtwProvider
        } else if matches!(
            self.command_id,
            MutationCommandId::ActivateDnsSensing
                | MutationCommandId::PauseDnsSensing
                | MutationCommandId::ResumeDnsSensing
                | MutationCommandId::StopDnsSensing
        ) {
            MutationCapabilityCategory::DnsSensingProvider
        } else if matches!(
            self.command_id,
            MutationCommandId::ActivateAuthRemoteSensing
                | MutationCommandId::PauseAuthRemoteSensing
                | MutationCommandId::ResumeAuthRemoteSensing
                | MutationCommandId::StopAuthRemoteSensing
        ) {
            MutationCapabilityCategory::AuthRemoteSensingProvider
        } else {
            MutationCapabilityCategory::IpHelperProvider
        };
        if self.provider_category != expected_provider {
            return Err(MutationAuthorizationContractError::InvalidExecutionPolicy);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(MutationAuthorizationContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationAuthorizationFrameworkState {
    ImplementedDryRun,
    ImplementedNarrowExecution,
    Degraded,
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationCountBucket {
    Zero,
    One,
    Few,
    Many,
}

impl MutationCountBucket {
    pub fn from_count(count: u64) -> Self {
        match count {
            0 => Self::Zero,
            1 => Self::One,
            2..=9 => Self::Few,
            _ => Self::Many,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationAuthorizationStatus {
    pub schema_version: SchemaVersion,
    pub framework_state: MutationAuthorizationFrameworkState,
    pub policy_catalog_version: SchemaVersion,
    pub supported_command_count: u32,
    pub dry_run_only: bool,
    pub production_execution_enabled: bool,
    pub last_decision_category: Option<MutationAuthorizationResult>,
    pub denied_count_bucket: MutationCountBucket,
    pub expired_count_bucket: MutationCountBucket,
    pub replay_count_bucket: MutationCountBucket,
    pub caller_trust_ready: bool,
    pub ownership_runtime_ready: bool,
    pub degraded_reasons: Vec<String>,
    pub audit_refs: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl MutationAuthorizationStatus {
    pub fn validate(&self) -> Result<(), MutationAuthorizationContractError> {
        if self.schema_version != MUTATION_AUTHORIZATION_SCHEMA_VERSION {
            return Err(MutationAuthorizationContractError::UnsupportedSchemaVersion);
        }
        if self.dry_run_only == self.production_execution_enabled {
            return Err(MutationAuthorizationContractError::ExecutionForbidden);
        }
        if self.supported_command_count as usize != MutationCommandId::ALL.len() {
            return Err(MutationAuthorizationContractError::InvalidLimit(
                "supported_command_count",
            ));
        }
        validate_refs("degraded_reasons", &self.degraded_reasons)?;
        validate_refs("audit_refs", &self.audit_refs)?;
        validate_safe_text("provenance_id", &self.provenance_id)?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(MutationAuthorizationContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MutationAuthorizationContractError {
    EmptyField(&'static str),
    TooLong(&'static str),
    UnsafeField(&'static str),
    TooManyItems(&'static str),
    InvalidLimit(&'static str),
    UnsupportedSchemaVersion,
    UnsupportedPolicyVersion,
    InvalidOwnershipEpoch,
    ExecutionForbidden,
    ExplicitActionRequired,
    InvalidExecutionPolicy,
    AuditRequired,
    RedactionRequired,
}

impl fmt::Display for MutationAuthorizationContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::TooLong(field) => write!(f, "{field} exceeds the bounded text limit"),
            Self::UnsafeField(field) => write!(f, "{field} contains unsafe metadata"),
            Self::TooManyItems(field) => write!(f, "{field} contains too many items"),
            Self::InvalidLimit(field) => write!(f, "{field} is outside the bounded limit"),
            Self::UnsupportedSchemaVersion => {
                write!(f, "mutation authorization schema version is unsupported")
            }
            Self::UnsupportedPolicyVersion => {
                write!(f, "mutation policy version is unsupported")
            }
            Self::InvalidOwnershipEpoch => write!(f, "ownership epoch must be non-zero"),
            Self::ExecutionForbidden => {
                write!(
                    f,
                    "production mutation execution is limited to explicit provider policies"
                )
            }
            Self::ExplicitActionRequired => write!(f, "explicit user action is required"),
            Self::InvalidExecutionPolicy => {
                write!(f, "mutation execution policy is not narrowly allowlisted")
            }
            Self::AuditRequired => write!(f, "mutation policy audit is required"),
            Self::RedactionRequired => write!(f, "mutation authorization must be redacted"),
        }
    }
}

impl std::error::Error for MutationAuthorizationContractError {}

pub fn mutation_policy_catalog() -> Vec<MutationCommandPolicy> {
    MutationCommandId::ALL
        .iter()
        .copied()
        .map(policy_for_command)
        .collect()
}

pub fn policy_for_command(command_id: MutationCommandId) -> MutationCommandPolicy {
    use MutationCapabilityCategory as Capability;
    use MutationCommandClassification as Classification;
    use MutationCommandId as Command;
    use MutationPolicyImplementationState as Implementation;
    use MutationRequiredCallerCategory as RequiredCaller;
    use MutationRequiredTargetState as TargetState;

    let (
        classifications,
        required_caller_category,
        required_command_class,
        administrator_required,
        interactive_session_required,
        capability,
        target_state,
        idempotency_policy,
        implementation_state,
        response_capable,
        degraded_reason,
    ) = match command_id {
        Command::ActivateIpHelperProvider | Command::SampleIpHelperNow | Command::StopIpHelper => (
            vec![
                Classification::AllowedForFrameworkReview,
                Classification::FutureUserMutation,
                Classification::ExplicitActionOnly,
            ],
            RequiredCaller::VerifiedInteractiveUser,
            AllowedCommandClass::FutureUserMutationCandidate,
            false,
            true,
            Capability::IpHelperProvider,
            match command_id {
                Command::SampleIpHelperNow => TargetState::ActiveOrPaused,
                Command::StopIpHelper => TargetState::AnyDeclared,
                _ => TargetState::InactiveOrReady,
            },
            MutationIdempotencyPolicy::SingleUse,
            Implementation::FrameworkReviewOnly,
            false,
            Some("ip_helper_production_execution_enabled".to_string()),
        ),
        Command::ActivateEtwProvider
        | Command::PauseEtwProvider
        | Command::ResumeEtwProvider
        | Command::StopEtwProvider => (
            vec![
                Classification::AllowedForFrameworkReview,
                Classification::FutureUserMutation,
                Classification::ExplicitActionOnly,
            ],
            RequiredCaller::VerifiedInteractiveUser,
            AllowedCommandClass::FutureUserMutationCandidate,
            false,
            true,
            Capability::EtwProvider,
            match command_id {
                Command::ActivateEtwProvider => TargetState::InactiveOrReady,
                Command::PauseEtwProvider => TargetState::ActiveOrPaused,
                Command::ResumeEtwProvider => TargetState::StoppedOrPaused,
                Command::StopEtwProvider => TargetState::AnyDeclared,
                _ => TargetState::AnyDeclared,
            },
            MutationIdempotencyPolicy::SingleUse,
            Implementation::FrameworkReviewOnly,
            false,
            Some("etw_lifecycle_execution_enabled".to_string()),
        ),
        Command::ActivateDnsSensing
        | Command::PauseDnsSensing
        | Command::ResumeDnsSensing
        | Command::StopDnsSensing => (
            vec![
                Classification::AllowedForFrameworkReview,
                Classification::FutureUserMutation,
                Classification::ExplicitActionOnly,
            ],
            RequiredCaller::VerifiedInteractiveUser,
            AllowedCommandClass::FutureUserMutationCandidate,
            false,
            true,
            Capability::DnsSensingProvider,
            match command_id {
                Command::ActivateDnsSensing => TargetState::InactiveOrReady,
                Command::PauseDnsSensing => TargetState::ActiveOrPaused,
                Command::ResumeDnsSensing => TargetState::StoppedOrPaused,
                Command::StopDnsSensing => TargetState::AnyDeclared,
                _ => TargetState::AnyDeclared,
            },
            MutationIdempotencyPolicy::SingleUse,
            Implementation::FrameworkReviewOnly,
            false,
            Some("windows_dns_sensing_execution_enabled".to_string()),
        ),
        Command::ActivateAuthRemoteSensing
        | Command::PauseAuthRemoteSensing
        | Command::ResumeAuthRemoteSensing
        | Command::StopAuthRemoteSensing => (
            vec![
                Classification::AllowedForFrameworkReview,
                Classification::FutureUserMutation,
                Classification::ExplicitActionOnly,
            ],
            RequiredCaller::VerifiedInteractiveUser,
            AllowedCommandClass::FutureUserMutationCandidate,
            false,
            true,
            Capability::AuthRemoteSensingProvider,
            match command_id {
                Command::ActivateAuthRemoteSensing => TargetState::InactiveOrReady,
                Command::PauseAuthRemoteSensing => TargetState::ActiveOrPaused,
                Command::ResumeAuthRemoteSensing => TargetState::StoppedOrPaused,
                Command::StopAuthRemoteSensing => TargetState::AnyDeclared,
                _ => TargetState::AnyDeclared,
            },
            MutationIdempotencyPolicy::SingleUse,
            Implementation::FrameworkReviewOnly,
            false,
            Some("windows_auth_remote_sensing_execution_enabled".to_string()),
        ),
        Command::ConfigureIpHelperSchedule
        | Command::EnableIpHelperSchedule
        | Command::PauseIpHelperSchedule
        | Command::ResumeIpHelperSchedule
        | Command::DisableIpHelperSchedule => (
            vec![
                Classification::AllowedForFrameworkReview,
                Classification::FutureUserMutation,
                Classification::ExplicitActionOnly,
            ],
            RequiredCaller::VerifiedInteractiveUser,
            AllowedCommandClass::FutureUserMutationCandidate,
            false,
            true,
            Capability::IpHelperProvider,
            match command_id {
                Command::EnableIpHelperSchedule | Command::ResumeIpHelperSchedule => {
                    TargetState::ActiveOrPaused
                }
                _ => TargetState::AnyDeclared,
            },
            MutationIdempotencyPolicy::SingleUse,
            Implementation::FrameworkReviewOnly,
            false,
            Some("ip_helper_schedule_control_plane_enabled".to_string()),
        ),
        Command::PauseIpHelper | Command::ChangeNetworkProviderMode => (
            vec![
                Classification::AllowedForFrameworkReview,
                Classification::FutureUserMutation,
                Classification::ExplicitActionOnly,
                Classification::NotImplemented,
            ],
            RequiredCaller::VerifiedInteractiveUser,
            AllowedCommandClass::FutureUserMutationCandidate,
            false,
            true,
            if command_id == Command::ChangeNetworkProviderMode {
                Capability::NetworkProviderController
            } else {
                Capability::IpHelperProvider
            },
            match command_id {
                Command::PauseIpHelper => TargetState::ActiveOrPaused,
                _ => TargetState::InactiveOrReady,
            },
            MutationIdempotencyPolicy::Required,
            Implementation::FrameworkReviewOnly,
            false,
            Some("production_ip_helper_command_deferred".to_string()),
        ),
        Command::ActivateNativeSampler
        | Command::SampleNativeSamplerNow
        | Command::PauseNativeSampler
        | Command::ResumeNativeSampler
        | Command::StopNativeSampler => (
            vec![
                Classification::AllowedForFrameworkReview,
                Classification::FutureUserMutation,
                Classification::ExplicitActionOnly,
                Classification::NotImplemented,
            ],
            RequiredCaller::VerifiedInteractiveUser,
            AllowedCommandClass::FutureUserMutationCandidate,
            false,
            true,
            Capability::NativeSampler,
            match command_id {
                Command::PauseNativeSampler | Command::StopNativeSampler => {
                    TargetState::ActiveOrPaused
                }
                _ => TargetState::InactiveOrReady,
            },
            MutationIdempotencyPolicy::Required,
            Implementation::FrameworkReviewOnly,
            false,
            Some("native_sampler_execution_deferred".to_string()),
        ),
        Command::UpdateNativeSchedule => (
            vec![
                Classification::AllowedForFrameworkReview,
                Classification::FutureUserMutation,
                Classification::ExplicitActionOnly,
                Classification::NotImplemented,
            ],
            RequiredCaller::VerifiedInteractiveUser,
            AllowedCommandClass::FutureUserMutationCandidate,
            false,
            true,
            Capability::NativeScheduler,
            TargetState::AnyDeclared,
            MutationIdempotencyPolicy::Required,
            Implementation::FrameworkReviewOnly,
            false,
            Some("native_schedule_mutation_deferred".to_string()),
        ),
        Command::StartSchedulerHost
        | Command::PauseSchedulerHost
        | Command::ResumeSchedulerHost
        | Command::StopSchedulerHost => (
            vec![
                Classification::AllowedForFrameworkReview,
                Classification::FutureUserMutation,
                Classification::ExplicitActionOnly,
                Classification::NotImplemented,
            ],
            RequiredCaller::VerifiedInteractiveUser,
            AllowedCommandClass::FutureUserMutationCandidate,
            false,
            true,
            Capability::NativeSchedulerHost,
            match command_id {
                Command::PauseSchedulerHost | Command::StopSchedulerHost => {
                    TargetState::ActiveOrPaused
                }
                _ => TargetState::StoppedOrPaused,
            },
            MutationIdempotencyPolicy::Required,
            Implementation::FrameworkReviewOnly,
            false,
            Some("scheduler_host_execution_deferred".to_string()),
        ),
        Command::RequestCaptureAuthorization => (
            vec![
                Classification::AllowedForFrameworkReview,
                Classification::FutureAdminMutation,
                Classification::ExplicitActionOnly,
                Classification::NotImplemented,
            ],
            RequiredCaller::AdministratorPolicyVerified,
            AllowedCommandClass::FutureAdminMutationCandidate,
            true,
            true,
            Capability::CaptureAuthorization,
            TargetState::Unavailable,
            MutationIdempotencyPolicy::SingleUse,
            Implementation::NotImplemented,
            false,
            Some("capture_broker_not_implemented".to_string()),
        ),
        Command::RevokeCaptureAuthorization => (
            vec![
                Classification::AllowedForFrameworkReview,
                Classification::FutureUserMutation,
                Classification::ExplicitActionOnly,
                Classification::NotImplemented,
            ],
            RequiredCaller::VerifiedInteractiveUser,
            AllowedCommandClass::FutureUserMutationCandidate,
            false,
            true,
            Capability::CaptureAuthorization,
            TargetState::Unavailable,
            MutationIdempotencyPolicy::SingleUse,
            Implementation::NotImplemented,
            false,
            Some("capture_authorization_not_implemented".to_string()),
        ),
        Command::GenerateReport | Command::ExportArtifact | Command::GenerateLlmStory => (
            vec![
                Classification::AllowedForFrameworkReview,
                Classification::FutureUserMutation,
                Classification::ExplicitActionOnly,
                Classification::NotImplemented,
            ],
            RequiredCaller::VerifiedInteractiveUser,
            AllowedCommandClass::FutureUserMutationCandidate,
            false,
            true,
            match command_id {
                Command::GenerateReport => Capability::ReportGeneration,
                Command::ExportArtifact => Capability::Export,
                _ => Capability::LlmAlertStory,
            },
            TargetState::Available,
            MutationIdempotencyPolicy::Required,
            Implementation::FrameworkReviewOnly,
            false,
            Some("servicehost_execution_deferred".to_string()),
        ),
        Command::ExecuteResponse => (
            vec![Classification::AlwaysDenied, Classification::NotImplemented],
            RequiredCaller::None,
            AllowedCommandClass::None,
            false,
            true,
            Capability::Response,
            TargetState::Unavailable,
            MutationIdempotencyPolicy::Forbidden,
            Implementation::AlwaysDenied,
            true,
            Some("response_execution_unavailable".to_string()),
        ),
        Command::RequestServiceHostShutdown => (
            vec![Classification::AlwaysDenied, Classification::NotImplemented],
            RequiredCaller::None,
            AllowedCommandClass::None,
            false,
            true,
            Capability::ServiceHostLifecycle,
            TargetState::NotApplicable,
            MutationIdempotencyPolicy::Forbidden,
            Implementation::AlwaysDenied,
            false,
            Some("production_shutdown_not_authorized".to_string()),
        ),
        Command::KillProcess
        | Command::StopArbitraryService
        | Command::ModifyFirewall
        | Command::BlockNetwork
        | Command::IsolateHost
        | Command::DisableAccount
        | Command::QuarantineFile
        | Command::InjectPacket
        | Command::ExecuteArbitraryCommand
        | Command::CredentialOperation
        | Command::GenericElevatedExecution
        | Command::AutomaticCapture
        | Command::AutomaticLlmGeneration => (
            vec![Classification::AlwaysDenied, Classification::NotImplemented],
            RequiredCaller::None,
            AllowedCommandClass::None,
            false,
            false,
            Capability::HostMutation,
            TargetState::NotApplicable,
            MutationIdempotencyPolicy::Forbidden,
            Implementation::AlwaysDenied,
            command_id != Command::AutomaticLlmGeneration,
            Some("high_risk_command_always_denied".to_string()),
        ),
    };

    MutationCommandPolicy {
        command_id,
        policy_ref: format!("mutation_policy_{}", command_id.as_str()),
        policy_version: MUTATION_POLICY_CATALOG_VERSION,
        classifications,
        required_caller_category,
        required_command_class,
        administrator_required,
        interactive_session_required,
        service_host_runtime_required: true,
        required_capability: capability,
        required_target_state: target_state,
        required_ownership_epoch: true,
        request_ttl_bucket: MutationIntentTtlBucket::ThirtySeconds,
        idempotency_policy,
        one_time_intent_required: true,
        maximum_request_size: MAX_MUTATION_REQUEST_BYTES,
        maximum_execution_timeout: MutationExecutionTimeoutBucket::FiveSeconds,
        audit_required: true,
        replay_policy: MutationReplayPolicy::ReturnExistingDecision,
        cancellation_policy: MutationCancellationPolicy::ConnectionClose,
        response_capable,
        implementation_state,
        execution_enabled: command_id.production_execution_enabled(),
        degraded_reason,
        redaction_status: RedactionStatus::Redacted,
    }
}

fn validate_refs(
    field: &'static str,
    values: &[String],
) -> Result<(), MutationAuthorizationContractError> {
    if values.len() > MAX_MUTATION_AUTHORIZATION_REFS {
        return Err(MutationAuthorizationContractError::TooManyItems(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), MutationAuthorizationContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(
    field: &'static str,
    value: &str,
) -> Result<(), MutationAuthorizationContractError> {
    if value.trim().is_empty() {
        return Err(MutationAuthorizationContractError::EmptyField(field));
    }
    if value.len() > MAX_MUTATION_AUTHORIZATION_TEXT_LEN {
        return Err(MutationAuthorizationContractError::TooLong(field));
    }
    let lowered = value.to_ascii_lowercase();
    for marker in [
        "s-1-",
        "username",
        "account_name",
        "token",
        "nonce",
        "process_id",
        "thread_id",
        "pid",
        "ppid",
        "command_line",
        "path",
        "ip_address",
        "port_number",
        "provider_handle",
        "credential",
        "password",
        "secret",
        "api_key",
    ] {
        if lowered.contains(marker) {
            return Err(MutationAuthorizationContractError::UnsafeField(field));
        }
    }
    Ok(())
}

fn validate_declared_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), MutationAuthorizationContractError> {
    if value.trim().is_empty() {
        return Err(MutationAuthorizationContractError::EmptyField(field));
    }
    if value.len() > MAX_MUTATION_AUTHORIZATION_TEXT_LEN {
        return Err(MutationAuthorizationContractError::TooLong(field));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(MutationAuthorizationContractError::UnsafeField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_intent() -> MutationIntent {
        let policy = policy_for_command(MutationCommandId::SampleIpHelperNow);
        MutationIntent {
            schema_version: MUTATION_AUTHORIZATION_SCHEMA_VERSION,
            intent_ref: "mutation_intent_ref".to_string(),
            request_ref: "mutation_request_ref".to_string(),
            ipc_session_ref: "ipc_session_ref".to_string(),
            caller_verification_ref: "caller_verification_ref".to_string(),
            command_id: MutationCommandId::SampleIpHelperNow,
            policy_ref: policy.policy_ref,
            policy_version: policy.policy_version,
            target_capability_ref: "ip_helper_provider_ref".to_string(),
            target_capability_category: MutationCapabilityCategory::IpHelperProvider,
            requested_operation_category: "sample_now".to_string(),
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
    fn mutation_authorization_catalog_covers_every_command_once() {
        let catalog = mutation_policy_catalog();
        assert_eq!(catalog.len(), MutationCommandId::ALL.len());
        for command in MutationCommandId::ALL {
            let matches = catalog
                .iter()
                .filter(|policy| policy.command_id == command)
                .count();
            assert_eq!(matches, 1, "missing or duplicate policy for {command:?}");
        }
        assert!(catalog.iter().all(|policy| policy.validate().is_ok()));
        let executable = catalog
            .iter()
            .filter(|policy| policy.execution_enabled)
            .map(|policy| policy.command_id)
            .collect::<Vec<_>>();
        assert_eq!(
            executable,
            vec![
                MutationCommandId::ActivateIpHelperProvider,
                MutationCommandId::SampleIpHelperNow,
                MutationCommandId::StopIpHelper,
                MutationCommandId::ActivateEtwProvider,
                MutationCommandId::PauseEtwProvider,
                MutationCommandId::ResumeEtwProvider,
                MutationCommandId::StopEtwProvider,
                MutationCommandId::ActivateDnsSensing,
                MutationCommandId::PauseDnsSensing,
                MutationCommandId::ResumeDnsSensing,
                MutationCommandId::StopDnsSensing,
                MutationCommandId::ActivateAuthRemoteSensing,
                MutationCommandId::PauseAuthRemoteSensing,
                MutationCommandId::ResumeAuthRemoteSensing,
                MutationCommandId::StopAuthRemoteSensing,
                MutationCommandId::ConfigureIpHelperSchedule,
                MutationCommandId::EnableIpHelperSchedule,
                MutationCommandId::PauseIpHelperSchedule,
                MutationCommandId::ResumeIpHelperSchedule,
                MutationCommandId::DisableIpHelperSchedule,
            ]
        );
        assert!(catalog.iter().all(|policy| {
            policy.command_id.production_execution_enabled() == policy.execution_enabled
        }));
    }

    #[test]
    fn mutation_authorization_contracts_reject_unknown_and_sensitive_fields() {
        let mut value = serde_json::to_value(valid_intent()).expect("intent value");
        value
            .as_object_mut()
            .expect("intent object")
            .insert("username".to_string(), serde_json::json!("example"));
        assert!(serde_json::from_value::<MutationIntent>(value).is_err());

        let mut intent = valid_intent();
        intent.target_capability_ref = "credential_secret".to_string();
        assert!(matches!(
            intent.validate(),
            Err(MutationAuthorizationContractError::UnsafeField(
                "target_capability_ref"
            ))
        ));
    }

    #[test]
    fn mutation_authorization_intent_is_bounded_dry_run_only() {
        let intent = valid_intent();
        intent.validate().expect("valid intent");
        let serialized = serde_json::to_string(&intent).expect("serialize intent");
        for forbidden in [
            "s-1-",
            "username",
            "token_handle",
            "session_nonce",
            "command_line",
            "provider_handle",
            "credential",
            "secret",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn provider_execution_receipt_is_bounded_and_rejects_sensitive_refs() {
        let policy = policy_for_command(MutationCommandId::SampleIpHelperNow);
        let receipt = MutationExecutionReceipt {
            schema_version: MUTATION_AUTHORIZATION_SCHEMA_VERSION,
            execution_ref: "ip_helper_execution_ref".to_string(),
            authorization_decision_ref: "mutation_decision_ref".to_string(),
            intent_ref: "mutation_intent_ref".to_string(),
            request_ref: "mutation_request_ref".to_string(),
            command_id: MutationCommandId::SampleIpHelperNow,
            policy_ref: policy.policy_ref,
            policy_version: policy.policy_version,
            ownership_epoch: 7,
            provider_category: MutationCapabilityCategory::IpHelperProvider,
            previous_lifecycle_state: ProviderLifecycleCategory::Active,
            resulting_lifecycle_state: ProviderLifecycleCategory::Active,
            authorization_state: MutationExecutionAuthorizationState::ExecutionCompleted,
            result_category: MutationExecutionResultCategory::Completed,
            started_time_bucket: "current_connection".to_string(),
            completed_time_bucket: "current_connection".to_string(),
            duration_bucket: "bounded_under_timeout".to_string(),
            counters: MutationExecutionCounters {
                sampled_count: 1,
                skipped_count: 0,
                rejected_count: 0,
            },
            batch_refs: vec!["ip_helper_batch_ref".to_string()],
            fact_refs: vec!["security_fact_ref".to_string()],
            canonical_snapshot_refs: vec!["canonical_snapshot_ref".to_string()],
            audit_refs: vec!["ip_helper_sample_completed".to_string()],
            degraded_reason: None,
            provenance_id: "servicehost_ip_helper_production_ipc".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        receipt.validate().expect("receipt validates");
        let mut unsafe_receipt = receipt;
        unsafe_receipt.batch_refs = vec!["pid_1234".to_string()];
        assert!(matches!(
            unsafe_receipt.validate(),
            Err(MutationAuthorizationContractError::UnsafeField(
                "batch_refs"
            ))
        ));
    }
}
