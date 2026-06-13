use crate::{
    AuditId, EvidenceQualityId, NativePermissionState, NativeSamplerBatchId, NativeSamplerCategory,
    NativeSamplerContractError, NativeSamplerRetentionModeCategory, NativeSamplerRuntimeState,
    NativeSchedulerCycleId, RedactionStatus, SecurityFactId, Timestamp,
};
use serde::{Deserialize, Serialize};

pub const MAX_NATIVE_SCHEDULES: usize = 8;
pub const MAX_NATIVE_SCHEDULER_REFS: usize = 32;
pub const MAX_NATIVE_SCHEDULER_CYCLES: usize = 32;
pub const MAX_NATIVE_SCHEDULER_BACKLOG_SIGNAL: u32 = 10_000;
pub const MAX_NATIVE_SAMPLERS_PER_TICK: u32 = 3;
pub const MIN_NATIVE_SCHEDULER_TICK_MILLIS: u64 = 250;
pub const MIN_NATIVE_SCHEDULER_EXECUTION_TIMEOUT_MILLIS: u32 = 10;
pub const MIN_NATIVE_SCHEDULER_RETRY_DELAY_MILLIS: u64 = 250;
pub const NATIVE_SCHEDULER_ALLOWED_TOPICS: &[&str] = &[
    "native.scheduler.status",
    "native.scheduler.cycle_started",
    "native.scheduler.cycle_completed",
    "native.scheduler.cycle_skipped",
    "native.scheduler.execution_control",
    "native.scheduler.backpressure",
    "native.scheduler.freshness",
    "native.scheduler.missed_sample",
    "native.scheduler.host_status",
    "native.scheduler.host_started",
    "native.scheduler.host_wake",
    "native.scheduler.host_paused",
    "native.scheduler.host_resumed",
    "native.scheduler.host_stopped",
    "native.scheduler.host_failed",
    "audit.native_scheduler",
    "audit.native_scheduler_host",
];

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerControllerState {
    Disabled,
    Ready,
    Running,
    Paused,
    Degraded,
    Stopping,
    Stopped,
    Revoked,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeScheduleIntervalBucket {
    OneMinute,
    FiveMinutes,
    FifteenMinutes,
    Hourly,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeScheduleTimeoutBucket {
    OneSecond,
    FiveSeconds,
    FifteenSeconds,
    ThirtySeconds,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeScheduleRetryBudgetBucket {
    None,
    One,
    Two,
    Three,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerAction {
    PreviewEnableSampler,
    EnableSampler,
    DisableSampler,
    DisableScheduler,
    Pause,
    Resume,
    BeginStop,
    CompleteStop,
    RefreshStatus,
    RunTick,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerCycleState {
    Started,
    Completed,
    Skipped,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerBackpressureState {
    None,
    Low,
    Moderate,
    High,
    Saturated,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeTelemetryFreshnessState {
    Fresh,
    Aging,
    Stale,
    Missing,
    Unavailable,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeTelemetryDimension {
    Health,
    Service,
    Process,
    ParentCategory,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeMissedSampleState {
    OnTime,
    Delayed,
    MissedOnce,
    RepeatedlyMissed,
    Paused,
    Blocked,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerHealthState {
    Healthy,
    Idle,
    Paused,
    Degraded,
    Backpressure,
    Stopped,
    Revoked,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerHostLifecycleState {
    Disabled,
    Ready,
    Starting,
    Running,
    Paused,
    Degraded,
    Stopping,
    Stopped,
    Revoked,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerHostHealthState {
    Healthy,
    Idle,
    Paused,
    Delayed,
    Degraded,
    Unresponsive,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerHostWakeState {
    Idle,
    Waiting,
    Due,
    Woken,
    Cancelled,
    NoEligibleSamplers,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerHostWakeReason {
    SamplerDue,
    ScheduleChanged,
    PermissionChanged,
    SamplerStateChanged,
    RetryDue,
    ManualWake,
    ControllerResumed,
    StatusReconciliation,
    StopRequested,
    ShutdownRequested,
    Revoked,
    Cancellation,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerCycleOrigin {
    Manual,
    Autonomous,
    Recovery,
    TestFixture,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerHostWatchdogState {
    Healthy,
    Idle,
    Paused,
    Delayed,
    Degraded,
    Unresponsive,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerHostShutdownState {
    None,
    Requested,
    Cancelling,
    Completed,
    TimedOut,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSchedulerHostAction {
    PreviewStart,
    Start,
    Pause,
    Resume,
    WakeNow,
    Stop,
    RefreshStatus,
    ClearInactiveState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerSamplerCycleResult {
    pub sampler_id: String,
    pub cycle_state: NativeSchedulerCycleState,
    pub skip_reason: Option<String>,
    pub batch_ref: Option<NativeSamplerBatchId>,
    pub fact_refs: Vec<SecurityFactId>,
    pub audit_refs: Vec<AuditId>,
    pub runtime_validation_passed: bool,
    pub event_bus_dispatched: bool,
    pub dag_dispatched: bool,
    pub plugin_runtime_dispatched: bool,
    pub execution_control_applied: bool,
    pub overlap_prevented: bool,
    pub timeout_enforced: bool,
    pub cancellation_requested: bool,
    pub retryable: bool,
    pub retry_scheduled: bool,
    pub retry_exhausted: bool,
    pub retry_attempt: u32,
    pub retry_budget: u32,
    pub retry_delay_millis: u64,
}

impl NativeSchedulerSamplerCycleResult {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native scheduler cycle sampler id", &self.sampler_id)?;
        if let Some(reason) = &self.skip_reason {
            validate_safe_text("native scheduler cycle skip reason", reason)?;
        }
        if self.fact_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || self.audit_refs.len() > MAX_NATIVE_SCHEDULER_REFS
        {
            return Err(NativeSamplerContractError::BoundedFieldTooLarge(
                "native scheduler cycle refs",
            ));
        }
        let completed = self.cycle_state == NativeSchedulerCycleState::Completed;
        if completed
            != (self.runtime_validation_passed
                && self.event_bus_dispatched
                && self.dag_dispatched
                && self.plugin_runtime_dispatched)
            || completed && self.skip_reason.is_some()
            || !completed && self.skip_reason.is_none()
            || self.retry_attempt > self.retry_budget
            || self.retry_delay_millis > 60_000
            || self.retry_scheduled && (!self.retryable || self.retry_delay_millis == 0)
            || self.retry_exhausted && !self.retryable
            || self.retry_scheduled && self.retry_exhausted
            || self.overlap_prevented && self.cycle_state != NativeSchedulerCycleState::Skipped
            || self.timeout_enforced && !self.retryable
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler cycle dispatch boundary",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerExecutionControlSummary {
    pub cycle_id: NativeSchedulerCycleId,
    pub global_concurrency_limit: u32,
    pub per_category_concurrency_limit: u32,
    pub active_execution_count: u32,
    pub selected_sampler_ids: Vec<String>,
    pub overlap_prevented_count: u32,
    pub timeout_enforced_count: u32,
    pub cancellation_requested: bool,
    pub retry_scheduled_count: u32,
    pub retry_exhausted_count: u32,
    pub provider_timeout_millis: u32,
    pub execution_timeout_millis: u32,
    pub global_cycle_timeout_millis: u32,
    pub retry_delay_millis: u64,
    pub emitted_topics: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
}

impl NativeSchedulerExecutionControlSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native scheduler execution provenance", &self.provenance_id)?;
        validate_safe_text_list(
            "native scheduler execution selected samplers",
            &self.selected_sampler_ids,
            MAX_NATIVE_SAMPLERS_PER_TICK as usize,
        )?;
        validate_topics(&self.emitted_topics)?;
        if self.global_concurrency_limit == 0
            || self.global_concurrency_limit > MAX_NATIVE_SAMPLERS_PER_TICK
            || self.per_category_concurrency_limit == 0
            || self.per_category_concurrency_limit > MAX_NATIVE_SAMPLERS_PER_TICK
            || self.active_execution_count > MAX_NATIVE_SAMPLERS_PER_TICK
            || self.provider_timeout_millis == 0
            || self.provider_timeout_millis > 30_000
            || self.execution_timeout_millis == 0
            || self.execution_timeout_millis > 30_000
            || self.global_cycle_timeout_millis == 0
            || self.global_cycle_timeout_millis > 120_000
            || self.retry_delay_millis < MIN_NATIVE_SCHEDULER_RETRY_DELAY_MILLIS
            || self.retry_delay_millis > 60_000
            || self.redaction_status == RedactionStatus::RedactionRequired
            || self.automatic_llm_calls
            || self.response_execution_started
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler execution control bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerBackpressureSummary {
    pub cycle_id: NativeSchedulerCycleId,
    pub state: NativeSchedulerBackpressureState,
    pub active_task_count: u32,
    pub pending_due_task_count: u32,
    pub event_bus_backlog_count: u32,
    pub dag_backlog_count: u32,
    pub timeout_rate_bucket: String,
    pub overlap_skip_rate_bucket: String,
    pub defer_low_priority_samplers: bool,
    pub skip_cycle: bool,
    pub pause_degraded_samplers: bool,
    pub deferred_sampler_ids: Vec<String>,
    pub paused_sampler_ids: Vec<String>,
    pub emitted_topics: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
}

impl NativeSchedulerBackpressureSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text(
            "native scheduler backpressure provenance",
            &self.provenance_id,
        )?;
        validate_safe_text(
            "native scheduler backpressure timeout rate",
            &self.timeout_rate_bucket,
        )?;
        validate_safe_text(
            "native scheduler backpressure overlap rate",
            &self.overlap_skip_rate_bucket,
        )?;
        validate_safe_text_list(
            "native scheduler backpressure deferred samplers",
            &self.deferred_sampler_ids,
            MAX_NATIVE_SAMPLERS_PER_TICK as usize,
        )?;
        validate_safe_text_list(
            "native scheduler backpressure paused samplers",
            &self.paused_sampler_ids,
            MAX_NATIVE_SAMPLERS_PER_TICK as usize,
        )?;
        validate_topics(&self.emitted_topics)?;
        if self.active_task_count > MAX_NATIVE_SAMPLERS_PER_TICK
            || self.pending_due_task_count > MAX_NATIVE_SCHEDULES as u32
            || self.event_bus_backlog_count > MAX_NATIVE_SCHEDULER_BACKLOG_SIGNAL
            || self.dag_backlog_count > MAX_NATIVE_SCHEDULER_BACKLOG_SIGNAL
            || !matches!(
                self.timeout_rate_bucket.as_str(),
                "none" | "low" | "moderate" | "high" | "saturated"
            )
            || !matches!(
                self.overlap_skip_rate_bucket.as_str(),
                "none" | "low" | "moderate" | "high" | "saturated"
            )
            || self.redaction_status == RedactionStatus::RedactionRequired
            || self.automatic_llm_calls
            || self.response_execution_started
            || (self.state == NativeSchedulerBackpressureState::None
                && (self.defer_low_priority_samplers
                    || self.skip_cycle
                    || self.pause_degraded_samplers
                    || !self.deferred_sampler_ids.is_empty()
                    || !self.paused_sampler_ids.is_empty()))
            || (self.state == NativeSchedulerBackpressureState::Saturated && !self.skip_cycle)
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler backpressure bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeTelemetryFreshnessDimensionSummary {
    pub dimension: NativeTelemetryDimension,
    pub sampler_id: String,
    pub freshness_state: NativeTelemetryFreshnessState,
    pub last_success_monotonic_millis: Option<u64>,
    pub age_bucket: String,
    pub interval_bucket: NativeScheduleIntervalBucket,
    pub source_reliability_bucket: String,
    pub visibility_completeness_bucket: String,
    pub evidence_quality_bucket: String,
    pub degraded_reason: Option<String>,
    pub batch_refs: Vec<NativeSamplerBatchId>,
    pub fact_refs: Vec<SecurityFactId>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl NativeTelemetryFreshnessDimensionSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native freshness sampler id", &self.sampler_id)?;
        validate_safe_text("native freshness age bucket", &self.age_bucket)?;
        validate_safe_text(
            "native freshness source reliability",
            &self.source_reliability_bucket,
        )?;
        validate_safe_text(
            "native freshness visibility completeness",
            &self.visibility_completeness_bucket,
        )?;
        validate_safe_text(
            "native freshness evidence quality",
            &self.evidence_quality_bucket,
        )?;
        validate_optional_safe_text(
            "native freshness degraded reason",
            self.degraded_reason.as_deref(),
        )?;
        validate_safe_text("native freshness provenance", &self.provenance_id)?;
        if self.batch_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || self.fact_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || self.audit_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native freshness dimension bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerFreshnessSummary {
    pub cycle_id: NativeSchedulerCycleId,
    pub monotonic_elapsed_millis: u64,
    pub dimensions: Vec<NativeTelemetryFreshnessDimensionSummary>,
    pub fresh_dimension_count: u32,
    pub aging_dimension_count: u32,
    pub stale_dimension_count: u32,
    pub missing_dimension_count: u32,
    pub unavailable_dimension_count: u32,
    pub revoked_dimension_count: u32,
    pub worst_freshness_state: NativeTelemetryFreshnessState,
    pub emitted_topics: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub attack_finding_generation_started: bool,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
}

impl NativeSchedulerFreshnessSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native freshness provenance", &self.provenance_id)?;
        validate_topics(&self.emitted_topics)?;
        if self.dimensions.len() != 4
            || self.fresh_dimension_count
                + self.aging_dimension_count
                + self.stale_dimension_count
                + self.missing_dimension_count
                + self.unavailable_dimension_count
                + self.revoked_dimension_count
                != self.dimensions.len() as u32
            || self.redaction_status == RedactionStatus::RedactionRequired
            || self.attack_finding_generation_started
            || self.automatic_llm_calls
            || self.response_execution_started
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native freshness summary bounds",
            ));
        }
        for dimension in &self.dimensions {
            dimension.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeMissedSampleDimensionSummary {
    pub dimension: NativeTelemetryDimension,
    pub sampler_id: String,
    pub missed_sample_state: NativeMissedSampleState,
    pub expected_interval_bucket: NativeScheduleIntervalBucket,
    pub last_success_monotonic_millis: Option<u64>,
    pub missed_expected_count_bucket: String,
    pub blocked_reason: Option<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl NativeMissedSampleDimensionSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native missed sampler id", &self.sampler_id)?;
        validate_safe_text(
            "native missed count bucket",
            &self.missed_expected_count_bucket,
        )?;
        validate_optional_safe_text(
            "native missed blocked reason",
            self.blocked_reason.as_deref(),
        )?;
        validate_safe_text("native missed provenance", &self.provenance_id)?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native missed sample redaction",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerMissedSampleSummary {
    pub cycle_id: NativeSchedulerCycleId,
    pub monotonic_elapsed_millis: u64,
    pub dimensions: Vec<NativeMissedSampleDimensionSummary>,
    pub delayed_dimension_count: u32,
    pub missed_once_dimension_count: u32,
    pub repeatedly_missed_dimension_count: u32,
    pub paused_dimension_count: u32,
    pub blocked_dimension_count: u32,
    pub revoked_dimension_count: u32,
    pub emitted_topics: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub attack_finding_generation_started: bool,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
}

impl NativeSchedulerMissedSampleSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native missed summary provenance", &self.provenance_id)?;
        validate_topics(&self.emitted_topics)?;
        if self.dimensions.len() != 4
            || self.redaction_status == RedactionStatus::RedactionRequired
            || self.attack_finding_generation_started
            || self.automatic_llm_calls
            || self.response_execution_started
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native missed sample summary bounds",
            ));
        }
        for dimension in &self.dimensions {
            dimension.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerCycleSummary {
    pub cycle_id: NativeSchedulerCycleId,
    pub cycle_state: NativeSchedulerCycleState,
    pub monotonic_elapsed_millis: u64,
    pub selected_sampler_ids: Vec<String>,
    pub sampler_results: Vec<NativeSchedulerSamplerCycleResult>,
    pub skip_reason: Option<String>,
    pub completed_sampler_count: u32,
    pub skipped_sampler_count: u32,
    pub execution_control: Option<NativeSchedulerExecutionControlSummary>,
    pub backpressure: Option<NativeSchedulerBackpressureSummary>,
    pub freshness: Option<NativeSchedulerFreshnessSummary>,
    pub missed_sample: Option<NativeSchedulerMissedSampleSummary>,
    pub emitted_topics: Vec<String>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub graceful_shutdown_requested: bool,
    pub retry_execution_started: bool,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
}

impl NativeSchedulerCycleSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native scheduler cycle provenance", &self.provenance_id)?;
        validate_safe_text_list(
            "native scheduler selected samplers",
            &self.selected_sampler_ids,
            MAX_NATIVE_SAMPLERS_PER_TICK as usize,
        )?;
        validate_topics(&self.emitted_topics)?;
        if let Some(reason) = &self.skip_reason {
            validate_safe_text("native scheduler cycle skip reason", reason)?;
        }
        if let Some(control) = &self.execution_control {
            control.validate()?;
            if control.cycle_id != self.cycle_id {
                return Err(NativeSamplerContractError::UnsafeSamplerState(
                    "native scheduler execution control cycle ref",
                ));
            }
        }
        if let Some(backpressure) = &self.backpressure {
            backpressure.validate()?;
            if backpressure.cycle_id != self.cycle_id
                || (backpressure.skip_cycle
                    && self.cycle_state != NativeSchedulerCycleState::Skipped)
            {
                return Err(NativeSamplerContractError::UnsafeSamplerState(
                    "native scheduler backpressure cycle ref",
                ));
            }
        }
        if let Some(freshness) = &self.freshness {
            freshness.validate()?;
            if freshness.cycle_id != self.cycle_id {
                return Err(NativeSamplerContractError::UnsafeSamplerState(
                    "native scheduler freshness cycle ref",
                ));
            }
        }
        if let Some(missed_sample) = &self.missed_sample {
            missed_sample.validate()?;
            if missed_sample.cycle_id != self.cycle_id {
                return Err(NativeSamplerContractError::UnsafeSamplerState(
                    "native scheduler missed sample cycle ref",
                ));
            }
        }
        if self.sampler_results.len() > MAX_NATIVE_SAMPLERS_PER_TICK as usize
            || self.audit_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || self.completed_sampler_count
                != self
                    .sampler_results
                    .iter()
                    .filter(|result| result.cycle_state == NativeSchedulerCycleState::Completed)
                    .count() as u32
            || self.skipped_sampler_count
                != self
                    .sampler_results
                    .iter()
                    .filter(|result| result.cycle_state == NativeSchedulerCycleState::Skipped)
                    .count() as u32
            || self.retry_execution_started
            || self.automatic_llm_calls
            || self.response_execution_started
            || self.redaction_status == RedactionStatus::RedactionRequired
            || (self.cycle_state == NativeSchedulerCycleState::Skipped)
                != self.skip_reason.is_some()
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler cycle boundary",
            ));
        }
        for result in &self.sampler_results {
            result.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerTickRequest {
    pub monotonic_elapsed_millis: u64,
    pub max_samplers_per_tick: u32,
    pub global_concurrency_limit: u32,
    pub per_category_concurrency_limit: u32,
    pub provider_timeout_millis: u32,
    pub execution_timeout_millis: u32,
    pub global_cycle_timeout_millis: u32,
    pub retry_delay_millis: u64,
    pub event_bus_backlog_count: u32,
    pub dag_backlog_count: u32,
    pub cancellation_requested: bool,
    pub reason_redacted: String,
}

impl NativeSchedulerTickRequest {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native scheduler tick reason", &self.reason_redacted)?;
        if self.max_samplers_per_tick == 0
            || self.max_samplers_per_tick > MAX_NATIVE_SAMPLERS_PER_TICK
            || self.global_concurrency_limit == 0
            || self.global_concurrency_limit > MAX_NATIVE_SAMPLERS_PER_TICK
            || self.per_category_concurrency_limit == 0
            || self.per_category_concurrency_limit > MAX_NATIVE_SAMPLERS_PER_TICK
            || self.provider_timeout_millis == 0
            || self.provider_timeout_millis > 30_000
            || self.execution_timeout_millis == 0
            || self.execution_timeout_millis > 30_000
            || self.global_cycle_timeout_millis == 0
            || self.global_cycle_timeout_millis > 120_000
            || self.retry_delay_millis < MIN_NATIVE_SCHEDULER_RETRY_DELAY_MILLIS
            || self.retry_delay_millis > 60_000
            || self.event_bus_backlog_count > MAX_NATIVE_SCHEDULER_BACKLOG_SIGNAL
            || self.dag_backlog_count > MAX_NATIVE_SCHEDULER_BACKLOG_SIGNAL
        {
            return Err(NativeSamplerContractError::BoundedFieldTooLarge(
                "native scheduler execution control bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerScheduleContract {
    pub sampler_id: String,
    pub sampler_category: NativeSamplerCategory,
    pub schedule_enabled: bool,
    pub interval_bucket: NativeScheduleIntervalBucket,
    pub timeout_bucket: NativeScheduleTimeoutBucket,
    pub retry_budget_bucket: NativeScheduleRetryBudgetBucket,
    pub max_records: u32,
    pub max_bytes: u32,
    pub declared_topics: Vec<String>,
    pub retention_mode: NativeSamplerRetentionModeCategory,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl NativeSamplerScheduleContract {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native schedule sampler id", &self.sampler_id)?;
        validate_safe_text("native schedule provenance", &self.provenance_id)?;
        validate_topics(&self.declared_topics)?;
        if self.max_records == 0
            || self.max_records > 512
            || self.max_bytes == 0
            || self.max_bytes > 1_048_576
        {
            return Err(NativeSamplerContractError::BoundedFieldTooLarge(
                "native schedule bounds",
            ));
        }
        if self.retention_mode != NativeSamplerRetentionModeCategory::NoRawRetention
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native schedule retention policy",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerScheduleStatus {
    pub contract: NativeSamplerScheduleContract,
    pub permission_state: NativePermissionState,
    pub runtime_state: NativeSamplerRuntimeState,
    pub authorized: bool,
    pub activated: bool,
    pub schedule_eligible: bool,
    pub blocked_reason: Option<String>,
    pub audit_refs: Vec<AuditId>,
}

impl NativeSamplerScheduleStatus {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        self.contract.validate()?;
        if let Some(reason) = &self.blocked_reason {
            validate_safe_text("native schedule blocked reason", reason)?;
        }
        if self.audit_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || self.contract.schedule_enabled && !self.schedule_eligible
            || self.authorized != (self.permission_state == NativePermissionState::GrantedSession)
            || self.activated
                != matches!(
                    self.runtime_state,
                    NativeSamplerRuntimeState::Active
                        | NativeSamplerRuntimeState::Idle
                        | NativeSamplerRuntimeState::Paused
                )
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native schedule eligibility",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerStatus {
    pub controller_state: NativeSchedulerControllerState,
    pub periodic_sampling_enabled: bool,
    pub enabled_schedule_count: u32,
    pub eligible_schedule_count: u32,
    pub revoked_schedule_count: u32,
    pub scheduling_loop_implemented: bool,
    pub scheduling_loop_active: bool,
    pub backpressure_state: NativeSchedulerBackpressureState,
    pub backpressure_cycle_count: u32,
    pub latest_backpressure_cycle_id: Option<NativeSchedulerCycleId>,
    pub freshness_stale_dimension_count: u32,
    pub freshness_missing_dimension_count: u32,
    pub missed_sample_dimension_count: u32,
    pub latest_freshness_cycle_id: Option<NativeSchedulerCycleId>,
    pub latest_missed_sample_cycle_id: Option<NativeSchedulerCycleId>,
    pub periodic_execution_started: bool,
    pub sample_requested: bool,
    pub retry_execution_started: bool,
    pub graceful_shutdown_requested: bool,
    pub cycle_count: u32,
    pub completed_cycle_count: u32,
    pub skipped_cycle_count: u32,
    pub latest_cycle_id: Option<NativeSchedulerCycleId>,
    pub last_tick_monotonic_millis: Option<u64>,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
    pub emitted_topics: Vec<String>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub generated_at: Timestamp,
}

impl NativeSchedulerStatus {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native scheduler provenance", &self.provenance_id)?;
        validate_topics(&self.emitted_topics)?;
        if self.audit_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || !self.scheduling_loop_implemented
            || self.periodic_execution_started
            || self.sample_requested
            || self.retry_execution_started
            || self.automatic_llm_calls
            || self.response_execution_started
            || self.redaction_status == RedactionStatus::RedactionRequired
            || self.periodic_sampling_enabled != (self.enabled_schedule_count > 0)
            || self.backpressure_cycle_count > self.cycle_count
            || (self.backpressure_cycle_count == 0 && self.latest_backpressure_cycle_id.is_some())
            || (self.backpressure_cycle_count > 0 && self.latest_backpressure_cycle_id.is_none())
            || self.freshness_stale_dimension_count > 4
            || self.freshness_missing_dimension_count > 4
            || self.missed_sample_dimension_count > 4
            || self.scheduling_loop_active
                != (self.controller_state == NativeSchedulerControllerState::Running
                    && self.periodic_sampling_enabled)
            || self
                .completed_cycle_count
                .saturating_add(self.skipped_cycle_count)
                != self.cycle_count
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler execution boundary",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerSummary {
    pub status: NativeSchedulerStatus,
    pub schedules: Vec<NativeSamplerScheduleStatus>,
    pub authorization_independent: bool,
    pub activation_independent: bool,
    pub enablement_independent: bool,
    pub startup_auto_enablement: bool,
    pub latest_cycle: Option<NativeSchedulerCycleSummary>,
    pub generated_at: Timestamp,
}

impl NativeSchedulerSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        self.status.validate()?;
        if self.schedules.len() > MAX_NATIVE_SCHEDULES
            || !self.authorization_independent
            || !self.activation_independent
            || !self.enablement_independent
            || self.startup_auto_enablement
            || self.status.latest_cycle_id
                != self
                    .latest_cycle
                    .as_ref()
                    .map(|cycle| cycle.cycle_id.clone())
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler independence boundary",
            ));
        }
        for schedule in &self.schedules {
            schedule.validate()?;
        }
        if let Some(cycle) = &self.latest_cycle {
            cycle.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerSafePersistedSchedule {
    pub sampler_id: String,
    pub sampler_category: NativeSamplerCategory,
    pub schedule_enabled: bool,
    pub interval_bucket: NativeScheduleIntervalBucket,
    pub timeout_bucket: NativeScheduleTimeoutBucket,
    pub retry_budget_bucket: NativeScheduleRetryBudgetBucket,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl NativeSchedulerSafePersistedSchedule {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native scheduler persisted sampler id", &self.sampler_id)?;
        validate_safe_text("native scheduler persisted provenance", &self.provenance_id)?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler persisted schedule redaction",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerRetrySummary {
    pub retry_scheduled_count: u32,
    pub retry_exhausted_count: u32,
    pub retry_pending_sampler_count: u32,
    pub latest_execution_control_cycle_id: Option<NativeSchedulerCycleId>,
    pub retrying_sampler_ids: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
}

impl NativeSchedulerRetrySummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native scheduler retry provenance", &self.provenance_id)?;
        validate_safe_text_list(
            "native scheduler retrying samplers",
            &self.retrying_sampler_ids,
            MAX_NATIVE_SCHEDULES,
        )?;
        if self.retry_pending_sampler_count as usize != self.retrying_sampler_ids.len()
            || self.redaction_status == RedactionStatus::RedactionRequired
            || self.automatic_llm_calls
            || self.response_execution_started
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler retry summary boundary",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerOperationalSummary {
    pub status: NativeSchedulerStatus,
    pub scheduler_health: NativeSchedulerHealthState,
    pub safe_persisted_schedules: Vec<NativeSchedulerSafePersistedSchedule>,
    pub freshness_summary: Option<NativeSchedulerFreshnessSummary>,
    pub missed_sample_summary: Option<NativeSchedulerMissedSampleSummary>,
    pub retry_summary: NativeSchedulerRetrySummary,
    pub backpressure_summary: Option<NativeSchedulerBackpressureSummary>,
    pub scheduler_refs: Vec<NativeSchedulerCycleId>,
    pub freshness_refs: Vec<NativeSchedulerCycleId>,
    pub missed_sample_refs: Vec<NativeSchedulerCycleId>,
    pub quality_refs: Vec<EvidenceQualityId>,
    pub safe_persistence_only: bool,
    pub raw_native_data_persisted: bool,
    pub runtime_subject_persisted: bool,
    pub source_location_persisted: bool,
    pub launch_text_persisted: bool,
    pub machine_identifier_persisted: bool,
    pub scheduler_enablement_started: bool,
    pub provider_refresh_started: bool,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
    pub generated_at: Timestamp,
}

impl NativeSchedulerOperationalSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        self.status.validate()?;
        self.retry_summary.validate()?;
        if let Some(freshness) = &self.freshness_summary {
            freshness.validate()?;
        }
        if let Some(missed_sample) = &self.missed_sample_summary {
            missed_sample.validate()?;
        }
        if let Some(backpressure) = &self.backpressure_summary {
            backpressure.validate()?;
        }
        if self.safe_persisted_schedules.len() > MAX_NATIVE_SCHEDULES
            || self.scheduler_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || self.freshness_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || self.missed_sample_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || self.quality_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || !self.safe_persistence_only
            || self.raw_native_data_persisted
            || self.runtime_subject_persisted
            || self.source_location_persisted
            || self.launch_text_persisted
            || self.machine_identifier_persisted
            || self.scheduler_enablement_started
            || self.provider_refresh_started
            || self.automatic_llm_calls
            || self.response_execution_started
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler operational boundary",
            ));
        }
        for schedule in &self.safe_persisted_schedules {
            schedule.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerEnablementPreview {
    pub sampler_id: String,
    pub controller_state: NativeSchedulerControllerState,
    pub permission_state: NativePermissionState,
    pub runtime_state: NativeSamplerRuntimeState,
    pub schedule_eligible: bool,
    pub blocked_reason: Option<String>,
    pub state_change_performed: bool,
    pub periodic_execution_started: bool,
    pub sample_requested: bool,
    pub boundary_summary_redacted: String,
}

impl NativeSchedulerEnablementPreview {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native schedule preview sampler id", &self.sampler_id)?;
        validate_safe_text(
            "native schedule preview boundary",
            &self.boundary_summary_redacted,
        )?;
        if let Some(reason) = &self.blocked_reason {
            validate_safe_text("native schedule preview blocked reason", reason)?;
        }
        if self.state_change_performed || self.periodic_execution_started || self.sample_requested {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native schedule preview side effects",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerActionRequest {
    pub sampler_id: Option<String>,
    pub action: NativeSchedulerAction,
    pub explicit_user_action: bool,
    pub interval_bucket: NativeScheduleIntervalBucket,
    pub timeout_bucket: NativeScheduleTimeoutBucket,
    pub retry_budget_bucket: NativeScheduleRetryBudgetBucket,
    pub max_records: u32,
    pub max_bytes: u32,
    pub reason_redacted: String,
}

impl NativeSchedulerActionRequest {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        if let Some(sampler_id) = &self.sampler_id {
            validate_safe_text("native scheduler action sampler id", sampler_id)?;
        }
        validate_safe_text("native scheduler action reason", &self.reason_redacted)?;
        if !self.explicit_user_action {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler explicit user action",
            ));
        }
        if matches!(
            self.action,
            NativeSchedulerAction::EnableSampler | NativeSchedulerAction::DisableSampler
        ) && self.sampler_id.is_none()
        {
            return Err(NativeSamplerContractError::EmptyField(
                "native scheduler action sampler id",
            ));
        }
        if self.action == NativeSchedulerAction::RunTick {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler tick requires tick contract",
            ));
        }
        if self.max_records == 0
            || self.max_records > 512
            || self.max_bytes == 0
            || self.max_bytes > 1_048_576
        {
            return Err(NativeSamplerContractError::BoundedFieldTooLarge(
                "native scheduler action bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerAuditEntry {
    pub audit_id: AuditId,
    pub sampler_id: Option<String>,
    pub action: NativeSchedulerAction,
    pub resulting_controller_state: NativeSchedulerControllerState,
    pub time_bucket: String,
    pub provenance_id: String,
    pub summary_redacted: String,
}

impl NativeSchedulerAuditEntry {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        if let Some(sampler_id) = &self.sampler_id {
            validate_safe_text("native scheduler audit sampler id", sampler_id)?;
        }
        validate_safe_text("native scheduler audit time bucket", &self.time_bucket)?;
        validate_safe_text("native scheduler audit provenance", &self.provenance_id)?;
        validate_safe_text("native scheduler audit summary", &self.summary_redacted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerActionResult {
    pub status: NativeSchedulerStatus,
    pub sampler_status: Option<NativeSamplerScheduleStatus>,
    pub audit_entry: NativeSchedulerAuditEntry,
    pub emitted_topics: Vec<String>,
    pub preview_only: bool,
    pub periodic_execution_started: bool,
    pub sample_requested: bool,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
}

impl NativeSchedulerActionResult {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        self.status.validate()?;
        if let Some(status) = &self.sampler_status {
            status.validate()?;
        }
        self.audit_entry.validate()?;
        validate_topics(&self.emitted_topics)?;
        if self.preview_only
            || self.periodic_execution_started
            || self.sample_requested
            || self.automatic_llm_calls
            || self.response_execution_started
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler action execution boundary",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerHostStatus {
    pub orchestrator_id: String,
    pub controller_id: String,
    pub lifecycle_state: NativeSchedulerHostLifecycleState,
    pub health_state: NativeSchedulerHostHealthState,
    pub wake_state: NativeSchedulerHostWakeState,
    pub latest_wake_reason: Option<NativeSchedulerHostWakeReason>,
    pub enabled_sampler_count_bucket: String,
    pub eligible_sampler_count_bucket: String,
    pub next_wake_bucket: String,
    pub last_wake_bucket: Option<String>,
    pub last_tick_ref: Option<NativeSchedulerCycleId>,
    pub latest_cycle_ref: Option<NativeSchedulerCycleId>,
    pub successful_wake_count_bucket: String,
    pub no_op_wake_count_bucket: String,
    pub degraded_wake_count_bucket: String,
    pub cancelled_wake_count_bucket: String,
    pub restart_count_bucket: String,
    pub manual_cycle_count_bucket: String,
    pub autonomous_cycle_count_bucket: String,
    pub watchdog_state: NativeSchedulerHostWatchdogState,
    pub shutdown_state: NativeSchedulerHostShutdownState,
    pub degraded_reason: Option<String>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub host_task_owned: bool,
    pub singleton_owner: bool,
    pub startup_auto_started: bool,
    pub os_service_started: bool,
    pub provider_direct_calls: bool,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
    pub generated_at: Timestamp,
}

impl NativeSchedulerHostStatus {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native scheduler host orchestrator id", &self.orchestrator_id)?;
        validate_safe_text("native scheduler host controller id", &self.controller_id)?;
        validate_safe_text(
            "native scheduler host enabled sampler count",
            &self.enabled_sampler_count_bucket,
        )?;
        validate_safe_text(
            "native scheduler host eligible sampler count",
            &self.eligible_sampler_count_bucket,
        )?;
        validate_safe_text("native scheduler host next wake", &self.next_wake_bucket)?;
        validate_optional_safe_text(
            "native scheduler host last wake",
            self.last_wake_bucket.as_deref(),
        )?;
        validate_safe_text(
            "native scheduler host successful wake count",
            &self.successful_wake_count_bucket,
        )?;
        validate_safe_text(
            "native scheduler host no op wake count",
            &self.no_op_wake_count_bucket,
        )?;
        validate_safe_text(
            "native scheduler host degraded wake count",
            &self.degraded_wake_count_bucket,
        )?;
        validate_safe_text(
            "native scheduler host cancelled wake count",
            &self.cancelled_wake_count_bucket,
        )?;
        validate_safe_text(
            "native scheduler host restart count",
            &self.restart_count_bucket,
        )?;
        validate_safe_text(
            "native scheduler host manual cycle count",
            &self.manual_cycle_count_bucket,
        )?;
        validate_safe_text(
            "native scheduler host autonomous cycle count",
            &self.autonomous_cycle_count_bucket,
        )?;
        validate_optional_safe_text(
            "native scheduler host degraded reason",
            self.degraded_reason.as_deref(),
        )?;
        validate_safe_text("native scheduler host provenance", &self.provenance_id)?;
        if self.audit_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || self.redaction_status == RedactionStatus::RedactionRequired
            || self.startup_auto_started
            || self.os_service_started
            || self.provider_direct_calls
            || self.automatic_llm_calls
            || self.response_execution_started
            || (self.lifecycle_state == NativeSchedulerHostLifecycleState::Running
                && (!self.host_task_owned || !self.singleton_owner))
            || (self.host_task_owned && !self.singleton_owner)
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler host status boundary",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerHostCycleSummary {
    pub host_cycle_id: NativeSchedulerCycleId,
    pub orchestrator_id: String,
    pub controller_id: String,
    pub cycle_origin: NativeSchedulerCycleOrigin,
    pub wake_reason: NativeSchedulerHostWakeReason,
    pub lifecycle_state: NativeSchedulerHostLifecycleState,
    pub health_state: NativeSchedulerHostHealthState,
    pub wake_state: NativeSchedulerHostWakeState,
    pub scheduler_cycle_ref: Option<NativeSchedulerCycleId>,
    pub tick_invoked: bool,
    pub no_due_work: bool,
    pub degraded: bool,
    pub cancelled: bool,
    pub cycle_gate_busy: bool,
    pub emitted_topics: Vec<String>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub provider_direct_calls: bool,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
    pub generated_at: Timestamp,
}

impl NativeSchedulerHostCycleSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text(
            "native scheduler host cycle orchestrator id",
            &self.orchestrator_id,
        )?;
        validate_safe_text(
            "native scheduler host cycle controller id",
            &self.controller_id,
        )?;
        validate_topics(&self.emitted_topics)?;
        validate_safe_text("native scheduler host cycle provenance", &self.provenance_id)?;
        if self.cycle_origin == NativeSchedulerCycleOrigin::TestFixture && !cfg!(test) {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler host cycle origin",
            ));
        }
        if self.audit_refs.len() > MAX_NATIVE_SCHEDULER_REFS
            || self.redaction_status == RedactionStatus::RedactionRequired
            || self.provider_direct_calls
            || self.automatic_llm_calls
            || self.response_execution_started
            || (self.scheduler_cycle_ref.is_none() && self.tick_invoked && !self.no_due_work)
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler host cycle boundary",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerHostAuditEntry {
    pub audit_id: AuditId,
    pub action: NativeSchedulerHostAction,
    pub resulting_lifecycle_state: NativeSchedulerHostLifecycleState,
    pub wake_reason: Option<NativeSchedulerHostWakeReason>,
    pub time_bucket: String,
    pub provenance_id: String,
    pub summary_redacted: String,
}

impl NativeSchedulerHostAuditEntry {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native scheduler host audit time bucket", &self.time_bucket)?;
        validate_safe_text("native scheduler host audit provenance", &self.provenance_id)?;
        validate_safe_text("native scheduler host audit summary", &self.summary_redacted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerHostStartPreview {
    pub status: NativeSchedulerHostStatus,
    pub start_allowed: bool,
    pub blocked_reason: Option<String>,
    pub task_created: bool,
    pub tick_invoked: bool,
    pub provider_direct_calls: bool,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
    pub boundary_summary_redacted: String,
}

impl NativeSchedulerHostStartPreview {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        self.status.validate()?;
        validate_optional_safe_text(
            "native scheduler host preview blocked reason",
            self.blocked_reason.as_deref(),
        )?;
        validate_safe_text(
            "native scheduler host preview boundary",
            &self.boundary_summary_redacted,
        )?;
        if self.task_created
            || self.tick_invoked
            || self.provider_direct_calls
            || self.automatic_llm_calls
            || self.response_execution_started
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler host preview side effects",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerHostActionRequest {
    pub action: NativeSchedulerHostAction,
    pub explicit_user_action: bool,
    pub wake_reason: NativeSchedulerHostWakeReason,
    pub reason_redacted: String,
}

impl NativeSchedulerHostActionRequest {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native scheduler host action reason", &self.reason_redacted)?;
        if matches!(
            self.action,
            NativeSchedulerHostAction::Start
                | NativeSchedulerHostAction::Pause
                | NativeSchedulerHostAction::Resume
                | NativeSchedulerHostAction::WakeNow
                | NativeSchedulerHostAction::Stop
                | NativeSchedulerHostAction::ClearInactiveState
        ) && !self.explicit_user_action
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler host explicit user action",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerHostActionResult {
    pub status: NativeSchedulerHostStatus,
    pub latest_host_cycle: Option<NativeSchedulerHostCycleSummary>,
    pub audit_entry: NativeSchedulerHostAuditEntry,
    pub emitted_topics: Vec<String>,
    pub preview_only: bool,
    pub task_created: bool,
    pub tick_invoked: bool,
    pub provider_direct_calls: bool,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
}

impl NativeSchedulerHostActionResult {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        self.status.validate()?;
        if let Some(cycle) = &self.latest_host_cycle {
            cycle.validate()?;
        }
        self.audit_entry.validate()?;
        validate_topics(&self.emitted_topics)?;
        if self.preview_only
            || self.provider_direct_calls
            || self.automatic_llm_calls
            || self.response_execution_started
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler host action boundary",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSchedulerHostHealthSummary {
    pub status: NativeSchedulerHostStatus,
    pub latest_cycle: Option<NativeSchedulerHostCycleSummary>,
    pub latest_wake_reason: Option<NativeSchedulerHostWakeReason>,
    pub watchdog_state: NativeSchedulerHostWatchdogState,
    pub shutdown_state: NativeSchedulerHostShutdownState,
    pub delayed_wake_count_bucket: String,
    pub no_op_wake_count_bucket: String,
    pub degraded_wake_count_bucket: String,
    pub successful_wake_count_bucket: String,
    pub session_bound: bool,
    pub startup_auto_run: bool,
    pub os_service: bool,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
    pub generated_at: Timestamp,
}

impl NativeSchedulerHostHealthSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        self.status.validate()?;
        if let Some(cycle) = &self.latest_cycle {
            cycle.validate()?;
        }
        validate_safe_text(
            "native scheduler host health delayed wake count",
            &self.delayed_wake_count_bucket,
        )?;
        validate_safe_text(
            "native scheduler host health no op wake count",
            &self.no_op_wake_count_bucket,
        )?;
        validate_safe_text(
            "native scheduler host health degraded wake count",
            &self.degraded_wake_count_bucket,
        )?;
        validate_safe_text(
            "native scheduler host health successful wake count",
            &self.successful_wake_count_bucket,
        )?;
        if !self.session_bound
            || self.startup_auto_run
            || self.os_service
            || self.automatic_llm_calls
            || self.response_execution_started
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduler host health boundary",
            ));
        }
        Ok(())
    }
}

fn validate_topics(values: &[String]) -> Result<(), NativeSamplerContractError> {
    if values.is_empty() || values.len() > NATIVE_SCHEDULER_ALLOWED_TOPICS.len() {
        return Err(NativeSamplerContractError::BoundedFieldTooLarge(
            "native scheduler topics",
        ));
    }
    for value in values {
        validate_safe_text("native scheduler topic", value)?;
        if !NATIVE_SCHEDULER_ALLOWED_TOPICS.contains(&value.as_str()) {
            return Err(NativeSamplerContractError::UnsafeField(
                "native scheduler topic",
            ));
        }
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), NativeSamplerContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(NativeSamplerContractError::EmptyField(field));
    }
    if trimmed.len() > 160 {
        return Err(NativeSamplerContractError::BoundedFieldTooLarge(field));
    }
    let normalized = trimmed.to_ascii_lowercase();
    if [
        "c:\\",
        "/home/",
        "/users/",
        "http://",
        "https://",
        "process_name",
        "process_id",
        "command_line",
        "full_path",
        "filename",
        "username",
        "email",
        "ip_address",
        "token",
        "cookie",
        "credential",
        "payload",
        "secret",
        "password",
        "api_key",
        "tenant_id",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
    {
        return Err(NativeSamplerContractError::UnsafeField(field));
    }
    Ok(())
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), NativeSamplerContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text_list(
    field: &'static str,
    values: &[String],
    max_len: usize,
) -> Result<(), NativeSamplerContractError> {
    if values.len() > max_len {
        return Err(NativeSamplerContractError::BoundedFieldTooLarge(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> NativeSamplerScheduleContract {
        NativeSamplerScheduleContract {
            sampler_id: "process_metadata_sampler".to_string(),
            sampler_category: NativeSamplerCategory::ProcessMetadataSampler,
            schedule_enabled: false,
            interval_bucket: NativeScheduleIntervalBucket::FiveMinutes,
            timeout_bucket: NativeScheduleTimeoutBucket::FiveSeconds,
            retry_budget_bucket: NativeScheduleRetryBudgetBucket::One,
            max_records: 128,
            max_bytes: 65_536,
            declared_topics: NATIVE_SCHEDULER_ALLOWED_TOPICS
                .iter()
                .map(|topic| (*topic).to_string())
                .collect(),
            retention_mode: NativeSamplerRetentionModeCategory::NoRawRetention,
            provenance_id: "native_scheduler_controller".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    #[test]
    fn schedule_contract_is_bounded_and_no_retention() {
        contract().validate().expect("valid");
    }

    #[test]
    fn schedule_contract_rejects_undeclared_topic_and_unsafe_retention() {
        let mut unsafe_topic = contract();
        unsafe_topic.declared_topics = vec!["native.process.metadata".to_string()];
        assert!(unsafe_topic.validate().is_err());

        let mut unsafe_retention = contract();
        unsafe_retention.retention_mode =
            NativeSamplerRetentionModeCategory::RawEndpointRetentionRejected;
        assert!(unsafe_retention.validate().is_err());
    }

    #[test]
    fn schedule_buckets_reject_unbounded_and_unlimited_values() {
        assert!(serde_json::from_str::<NativeScheduleIntervalBucket>("\"unbounded\"").is_err());
        assert!(serde_json::from_str::<NativeScheduleRetryBudgetBucket>("\"unlimited\"").is_err());
    }
}
