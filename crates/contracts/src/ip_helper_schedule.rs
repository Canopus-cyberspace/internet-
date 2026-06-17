use crate::{
    mutation_authorization::MutationExecutionRequest, provider_controller::NetworkProviderKind,
    RedactionStatus, SchemaVersion, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const IP_HELPER_SCHEDULE_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_IP_HELPER_SCHEDULE_REFS: usize = 12;
pub const MAX_IP_HELPER_SCHEDULE_TEXT_LEN: usize = 128;
pub const MAX_IP_HELPER_SCHEDULE_RECORDS: u32 = 16_384;
pub const MAX_IP_HELPER_SCHEDULE_BYTES: u32 = 8 * 1024 * 1024;

pub const IP_HELPER_SCHEDULE_CONFIGURED: &str = "ip_helper_schedule_configured";
pub const IP_HELPER_SCHEDULE_ENABLED: &str = "ip_helper_schedule_enabled";
pub const IP_HELPER_SCHEDULE_PAUSED: &str = "ip_helper_schedule_paused";
pub const IP_HELPER_SCHEDULE_RESUMED: &str = "ip_helper_schedule_resumed";
pub const IP_HELPER_SCHEDULE_DISABLED: &str = "ip_helper_schedule_disabled";
pub const IP_HELPER_SCHEDULE_INVALIDATED: &str = "ip_helper_schedule_invalidated";
pub const IP_HELPER_SCHEDULE_LEASE_CREATED: &str = "ip_helper_schedule_lease_created";
pub const IP_HELPER_SCHEDULE_LEASE_EXPIRED: &str = "ip_helper_schedule_lease_expired";
pub const IP_HELPER_SCHEDULE_SESSION_INVALIDATED: &str = "ip_helper_schedule_session_invalidated";
pub const IP_HELPER_SCHEDULE_EPOCH_REJECTED: &str = "ip_helper_schedule_epoch_rejected";
pub const IP_HELPER_SCHEDULE_PROVIDER_STOPPED: &str = "ip_helper_schedule_provider_stopped";
pub const IP_HELPER_SCHEDULE_PERMISSION_REVOKED: &str = "ip_helper_schedule_permission_revoked";
pub const IP_HELPER_SCHEDULER_HOST_STARTED: &str = "ip_helper_scheduler_host_started";
pub const IP_HELPER_SCHEDULER_HOST_STOPPED: &str = "ip_helper_scheduler_host_stopped";
pub const IP_HELPER_SCHEDULED_CYCLE_DUE: &str = "ip_helper_scheduled_cycle_due";
pub const IP_HELPER_SCHEDULED_CYCLE_STARTED: &str = "ip_helper_scheduled_cycle_started";
pub const IP_HELPER_SCHEDULED_CYCLE_COMPLETED: &str = "ip_helper_scheduled_cycle_completed";
pub const IP_HELPER_SCHEDULED_CYCLE_SKIPPED: &str = "ip_helper_scheduled_cycle_skipped";
pub const IP_HELPER_SCHEDULED_CYCLE_FAILED: &str = "ip_helper_scheduled_cycle_failed";
pub const IP_HELPER_SCHEDULED_CYCLE_TIMED_OUT: &str = "ip_helper_scheduled_cycle_timed_out";
pub const IP_HELPER_SCHEDULED_CYCLE_RETRY_SCHEDULED: &str =
    "ip_helper_scheduled_cycle_retry_scheduled";
pub const IP_HELPER_SCHEDULED_CYCLE_BACKPRESSURE_SKIPPED: &str =
    "ip_helper_scheduled_cycle_backpressure_skipped";
pub const IP_HELPER_SCHEDULE_LEASE_INVALIDATED: &str = "ip_helper_schedule_lease_invalidated";
pub const IP_HELPER_SCHEDULER_DISCONNECT_STOP: &str = "ip_helper_scheduler_disconnect_stop";
pub const IP_HELPER_SCHEDULER_SHUTDOWN_JOINED: &str = "ip_helper_scheduler_shutdown_joined";
pub const IP_HELPER_SCHEDULER_SHUTDOWN_TIMEOUT: &str = "ip_helper_scheduler_shutdown_timeout";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduleState {
    NotConfigured,
    ConfiguredDisabled,
    ConfiguredEnabled,
    Paused,
    Invalidated,
    Revoked,
    Degraded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduleIntervalBucket {
    FifteenSeconds,
    ThirtySeconds,
    OneMinute,
    FiveMinutes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduleTimeoutBucket {
    TwoHundredFiftyMillis,
    OneSecond,
    FiveSeconds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduleRetryBudgetBucket {
    None,
    One,
    Three,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduleRetryDelayBucket {
    None,
    FiveSeconds,
    ThirtySeconds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduleLeaseState {
    NoLease,
    Active,
    Paused,
    Invalidated,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduleNextDueCategory {
    NotRunning,
    Ineligible,
    Deferred,
    DueSoon,
    DueNow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperSchedulerRegistrationState {
    Configured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduleCountBucket {
    Zero,
    One,
    Few,
    Many,
}

impl IpHelperScheduleCountBucket {
    pub fn from_count(count: u32) -> Self {
        match count {
            0 => Self::Zero,
            1 => Self::One,
            2..=9 => Self::Few,
            _ => Self::Many,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduledCycleType {
    Scheduled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduledDueState {
    NotDue,
    Due,
    Deferred,
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduledAuthorizationState {
    Valid,
    Invalid,
    Revoked,
    StaleEpoch,
    PolicyMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduledExecutionResult {
    NotStarted,
    Completed,
    Skipped,
    Failed,
    TimedOut,
    Busy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduledRetryState {
    None,
    Scheduled,
    Exhausted,
    Cleared,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduledBackpressureState {
    None,
    Low,
    Moderate,
    High,
    Saturated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduledFreshnessState {
    Fresh,
    Aging,
    Stale,
    Missing,
    Unavailable,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperScheduledMissedSampleState {
    OnTime,
    Delayed,
    MissedOnce,
    RepeatedlyMissed,
    Paused,
    Blocked,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpHelperScheduledCycleRecord {
    pub cycle_ref: String,
    pub scheduler_item_ref: String,
    pub schedule_ref: String,
    pub cycle_type: IpHelperScheduledCycleType,
    pub due_state: IpHelperScheduledDueState,
    pub authorization_state: IpHelperScheduledAuthorizationState,
    pub execution_result: IpHelperScheduledExecutionResult,
    pub retry_state: IpHelperScheduledRetryState,
    pub backpressure_state: IpHelperScheduledBackpressureState,
    pub freshness_result: IpHelperScheduledFreshnessState,
    pub missed_sample_result: IpHelperScheduledMissedSampleState,
    pub started_time_bucket: Option<Timestamp>,
    pub completed_time_bucket: Option<Timestamp>,
    pub duration_bucket: String,
    pub provider_call_count_bucket: IpHelperScheduleCountBucket,
    pub batch_refs: Vec<String>,
    pub fact_refs: Vec<String>,
    pub snapshot_refs: Vec<String>,
    pub audit_refs: Vec<String>,
    pub degraded_reason: Option<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl IpHelperScheduledCycleRecord {
    pub fn validate(&self) -> Result<(), IpHelperScheduleContractError> {
        validate_safe_text("cycle_ref", &self.cycle_ref)?;
        validate_safe_text("scheduler_item_ref", &self.scheduler_item_ref)?;
        validate_safe_text("schedule_ref", &self.schedule_ref)?;
        validate_safe_text("duration_bucket", &self.duration_bucket)?;
        validate_refs("batch_refs", &self.batch_refs)?;
        validate_refs("fact_refs", &self.fact_refs)?;
        validate_refs("snapshot_refs", &self.snapshot_refs)?;
        validate_refs("audit_refs", &self.audit_refs)?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        validate_safe_text("provenance_id", &self.provenance_id)?;
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(IpHelperScheduleContractError::RedactionRequired);
        }
        if self.cycle_type != IpHelperScheduledCycleType::Scheduled {
            return Err(IpHelperScheduleContractError::InvalidState("cycle_type"));
        }
        let completed = self.execution_result == IpHelperScheduledExecutionResult::Completed;
        if completed
            != (self.provider_call_count_bucket != IpHelperScheduleCountBucket::Zero
                && self.completed_time_bucket.is_some()
                && self.degraded_reason.is_none())
        {
            return Err(IpHelperScheduleContractError::InvalidState(
                "scheduled_cycle_completion",
            ));
        }
        if !completed
            && self.execution_result != IpHelperScheduledExecutionResult::NotStarted
            && self.degraded_reason.is_none()
        {
            return Err(IpHelperScheduleContractError::InvalidState(
                "scheduled_cycle_degraded_reason",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpHelperScheduleConfig {
    pub interval_bucket: IpHelperScheduleIntervalBucket,
    pub provider_timeout_bucket: IpHelperScheduleTimeoutBucket,
    pub execution_timeout_bucket: IpHelperScheduleTimeoutBucket,
    pub retry_budget_bucket: IpHelperScheduleRetryBudgetBucket,
    pub retry_delay_bucket: IpHelperScheduleRetryDelayBucket,
    pub maximum_records: u32,
    pub maximum_bytes: u32,
    pub no_overlap_marker: bool,
    pub no_catch_up_marker: bool,
}

impl Default for IpHelperScheduleConfig {
    fn default() -> Self {
        Self {
            interval_bucket: IpHelperScheduleIntervalBucket::OneMinute,
            provider_timeout_bucket: IpHelperScheduleTimeoutBucket::TwoHundredFiftyMillis,
            execution_timeout_bucket: IpHelperScheduleTimeoutBucket::OneSecond,
            retry_budget_bucket: IpHelperScheduleRetryBudgetBucket::One,
            retry_delay_bucket: IpHelperScheduleRetryDelayBucket::FiveSeconds,
            maximum_records: 128,
            maximum_bytes: 128 * 1024,
            no_overlap_marker: true,
            no_catch_up_marker: true,
        }
    }
}

impl IpHelperScheduleConfig {
    pub fn validate(&self) -> Result<(), IpHelperScheduleContractError> {
        if self.maximum_records == 0 || self.maximum_records > MAX_IP_HELPER_SCHEDULE_RECORDS {
            return Err(IpHelperScheduleContractError::InvalidLimit(
                "maximum_records",
            ));
        }
        if self.maximum_bytes == 0 || self.maximum_bytes > MAX_IP_HELPER_SCHEDULE_BYTES {
            return Err(IpHelperScheduleContractError::InvalidLimit("maximum_bytes"));
        }
        if !self.no_overlap_marker {
            return Err(IpHelperScheduleContractError::UnsafePolicy(
                "overlapping_execution_policy",
            ));
        }
        if !self.no_catch_up_marker {
            return Err(IpHelperScheduleContractError::UnsafePolicy(
                "catch_up_queue_policy",
            ));
        }
        if self.retry_budget_bucket == IpHelperScheduleRetryBudgetBucket::None
            && self.retry_delay_bucket != IpHelperScheduleRetryDelayBucket::None
        {
            return Err(IpHelperScheduleContractError::InvalidLimit(
                "retry_delay_bucket",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpHelperScheduleStatus {
    pub schema_version: SchemaVersion,
    pub schedule_ref: String,
    pub provider_category: NetworkProviderKind,
    pub scheduler_owner_ref: String,
    pub ownership_epoch: u64,
    pub schedule_state: IpHelperScheduleState,
    pub enabled_marker: bool,
    pub paused_marker: bool,
    pub config: IpHelperScheduleConfig,
    pub session_bound_marker: bool,
    pub restart_disabled_marker: bool,
    pub policy_id: String,
    pub policy_version: SchemaVersion,
    pub authorization_refs: Vec<String>,
    pub lease_state: IpHelperScheduleLeaseState,
    pub schedule_lease_ref: Option<String>,
    pub scheduler_registration: IpHelperSchedulerRegistrationState,
    pub timer_runtime_active: bool,
    pub next_due_category: IpHelperScheduleNextDueCategory,
    pub execution_count_bucket: IpHelperScheduleCountBucket,
    pub skipped_count_bucket: IpHelperScheduleCountBucket,
    pub automatic_provider_calls: u32,
    pub scheduler_triggered_provider_calls: u32,
    pub latest_manual_sample_ref: Option<String>,
    pub latest_scheduled_cycle_ref: Option<String>,
    pub latest_scheduled_execution_result: IpHelperScheduledExecutionResult,
    pub latest_scheduled_cycle: Option<IpHelperScheduledCycleRecord>,
    pub manual_sample_count_bucket: IpHelperScheduleCountBucket,
    pub scheduled_sample_count_bucket: IpHelperScheduleCountBucket,
    pub retry_count_bucket: IpHelperScheduleCountBucket,
    pub timeout_count_bucket: IpHelperScheduleCountBucket,
    pub overlap_skip_count_bucket: IpHelperScheduleCountBucket,
    pub backpressure_state: IpHelperScheduledBackpressureState,
    pub freshness_state: IpHelperScheduledFreshnessState,
    pub missed_sample_state: IpHelperScheduledMissedSampleState,
    pub schedule_lease_valid: bool,
    pub created_time_bucket: Timestamp,
    pub updated_time_bucket: Timestamp,
    pub audit_refs: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub degraded_reason: Option<String>,
}

impl IpHelperScheduleStatus {
    pub fn not_configured(ownership_epoch: u64) -> Self {
        let now = Timestamp::now();
        Self {
            schema_version: IP_HELPER_SCHEDULE_SCHEMA_VERSION,
            schedule_ref: "ip_helper_schedule_ref".to_string(),
            provider_category: NetworkProviderKind::IpHelper,
            scheduler_owner_ref: "servicehost_scheduler_controller".to_string(),
            ownership_epoch,
            schedule_state: IpHelperScheduleState::NotConfigured,
            enabled_marker: false,
            paused_marker: false,
            config: IpHelperScheduleConfig::default(),
            session_bound_marker: true,
            restart_disabled_marker: true,
            policy_id: "mutation_policy_configure_ip_helper_schedule".to_string(),
            policy_version: crate::MUTATION_POLICY_CATALOG_VERSION,
            authorization_refs: Vec::new(),
            lease_state: IpHelperScheduleLeaseState::NoLease,
            schedule_lease_ref: None,
            scheduler_registration: IpHelperSchedulerRegistrationState::Configured,
            timer_runtime_active: false,
            next_due_category: IpHelperScheduleNextDueCategory::NotRunning,
            execution_count_bucket: IpHelperScheduleCountBucket::Zero,
            skipped_count_bucket: IpHelperScheduleCountBucket::Zero,
            automatic_provider_calls: 0,
            scheduler_triggered_provider_calls: 0,
            latest_manual_sample_ref: None,
            latest_scheduled_cycle_ref: None,
            latest_scheduled_execution_result: IpHelperScheduledExecutionResult::NotStarted,
            latest_scheduled_cycle: None,
            manual_sample_count_bucket: IpHelperScheduleCountBucket::Zero,
            scheduled_sample_count_bucket: IpHelperScheduleCountBucket::Zero,
            retry_count_bucket: IpHelperScheduleCountBucket::Zero,
            timeout_count_bucket: IpHelperScheduleCountBucket::Zero,
            overlap_skip_count_bucket: IpHelperScheduleCountBucket::Zero,
            backpressure_state: IpHelperScheduledBackpressureState::None,
            freshness_state: IpHelperScheduledFreshnessState::Unavailable,
            missed_sample_state: IpHelperScheduledMissedSampleState::Blocked,
            schedule_lease_valid: false,
            created_time_bucket: now.clone(),
            updated_time_bucket: now,
            audit_refs: vec!["ip_helper_schedule_not_configured".to_string()],
            provenance_id: "servicehost_ip_helper_schedule_control_plane".to_string(),
            redaction_status: RedactionStatus::Redacted,
            degraded_reason: Some("schedule_not_configured".to_string()),
        }
    }

    pub fn validate(&self) -> Result<(), IpHelperScheduleContractError> {
        if self.schema_version != IP_HELPER_SCHEDULE_SCHEMA_VERSION {
            return Err(IpHelperScheduleContractError::UnsupportedSchemaVersion);
        }
        validate_safe_text("schedule_ref", &self.schedule_ref)?;
        validate_safe_text("scheduler_owner_ref", &self.scheduler_owner_ref)?;
        validate_declared_identifier("policy_id", &self.policy_id)?;
        validate_optional_safe_text("schedule_lease_ref", self.schedule_lease_ref.as_deref())?;
        validate_optional_safe_text(
            "latest_manual_sample_ref",
            self.latest_manual_sample_ref.as_deref(),
        )?;
        validate_optional_safe_text(
            "latest_scheduled_cycle_ref",
            self.latest_scheduled_cycle_ref.as_deref(),
        )?;
        validate_refs("authorization_refs", &self.authorization_refs)?;
        validate_refs("audit_refs", &self.audit_refs)?;
        validate_safe_text("provenance_id", &self.provenance_id)?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        self.config.validate()?;
        if self.provider_category != NetworkProviderKind::IpHelper {
            return Err(IpHelperScheduleContractError::InvalidProvider);
        }
        if self.ownership_epoch == 0 {
            return Err(IpHelperScheduleContractError::OwnershipEpochRequired);
        }
        if !self.session_bound_marker || !self.restart_disabled_marker {
            return Err(IpHelperScheduleContractError::UnsafePolicy(
                "schedule_must_be_session_bound_and_restart_disabled",
            ));
        }
        if self.enabled_marker != (self.schedule_state == IpHelperScheduleState::ConfiguredEnabled)
        {
            return Err(IpHelperScheduleContractError::InvalidState(
                "enabled_marker",
            ));
        }
        if self.paused_marker != (self.schedule_state == IpHelperScheduleState::Paused) {
            return Err(IpHelperScheduleContractError::InvalidState("paused_marker"));
        }
        if self.automatic_provider_calls != 0 {
            return Err(IpHelperScheduleContractError::ProviderCallsForbidden);
        }
        if self.timer_runtime_active
            && (self.schedule_state != IpHelperScheduleState::ConfiguredEnabled
                || self.lease_state != IpHelperScheduleLeaseState::Active
                || !self.schedule_lease_valid)
        {
            return Err(IpHelperScheduleContractError::InvalidState(
                "timer_runtime_requires_active_lease",
            ));
        }
        if self.next_due_category != IpHelperScheduleNextDueCategory::NotRunning
            && !matches!(
                self.schedule_state,
                IpHelperScheduleState::ConfiguredEnabled | IpHelperScheduleState::Paused
            )
        {
            return Err(IpHelperScheduleContractError::InvalidState(
                "next_due_category",
            ));
        }
        match self.schedule_state {
            IpHelperScheduleState::ConfiguredEnabled => {
                if self.lease_state != IpHelperScheduleLeaseState::Active
                    || self.schedule_lease_ref.is_none()
                    || !self.schedule_lease_valid
                {
                    return Err(IpHelperScheduleContractError::InvalidState("enabled_lease"));
                }
            }
            IpHelperScheduleState::Paused
                if self.lease_state != IpHelperScheduleLeaseState::Paused
                    || self.schedule_lease_valid =>
            {
                return Err(IpHelperScheduleContractError::InvalidState("paused_lease"));
            }
            _ => {}
        }
        if let Some(cycle) = &self.latest_scheduled_cycle {
            cycle.validate()?;
            if self.latest_scheduled_cycle_ref.as_deref() != Some(cycle.cycle_ref.as_str())
                || cycle.schedule_ref != self.schedule_ref
                || self.latest_scheduled_execution_result != cycle.execution_result
            {
                return Err(IpHelperScheduleContractError::InvalidState(
                    "latest_scheduled_cycle_ref",
                ));
            }
        } else if self.latest_scheduled_cycle_ref.is_some() {
            return Err(IpHelperScheduleContractError::InvalidState(
                "latest_scheduled_cycle_ref",
            ));
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(IpHelperScheduleContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpHelperScheduleMutationRequest {
    pub execution_request: MutationExecutionRequest,
    pub schedule_config: Option<IpHelperScheduleConfig>,
    pub explicit_user_action: bool,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
}

impl IpHelperScheduleMutationRequest {
    pub fn validate(&self) -> Result<(), IpHelperScheduleContractError> {
        self.execution_request
            .validate()
            .map_err(|_| IpHelperScheduleContractError::InvalidExecutionRequest)?;
        validate_safe_text("provenance_id", &self.provenance_id)?;
        if !self.explicit_user_action {
            return Err(IpHelperScheduleContractError::ExplicitActionRequired);
        }
        if let Some(config) = &self.schedule_config {
            config.validate()?;
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(IpHelperScheduleContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpHelperScheduleContractError {
    UnsupportedSchemaVersion,
    EmptyField(&'static str),
    TooLong(&'static str),
    UnsafeField(&'static str),
    TooManyItems(&'static str),
    InvalidLimit(&'static str),
    UnsafePolicy(&'static str),
    InvalidProvider,
    InvalidState(&'static str),
    OwnershipEpochRequired,
    ProviderCallsForbidden,
    ExplicitActionRequired,
    InvalidExecutionRequest,
    RedactionRequired,
}

impl fmt::Display for IpHelperScheduleContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion => write!(f, "IP Helper schedule schema is unsupported"),
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::TooLong(field) => write!(f, "{field} exceeds bounded schedule text length"),
            Self::UnsafeField(field) => write!(f, "{field} contains unsafe schedule metadata"),
            Self::TooManyItems(field) => write!(f, "{field} contains too many schedule items"),
            Self::InvalidLimit(field) => write!(f, "{field} has an unsafe schedule limit"),
            Self::UnsafePolicy(field) => write!(f, "{field} is not allowed for schedule policy"),
            Self::InvalidProvider => write!(f, "IP Helper schedule must target IP Helper"),
            Self::InvalidState(field) => write!(f, "{field} is inconsistent for schedule state"),
            Self::OwnershipEpochRequired => write!(f, "schedule ownership epoch is required"),
            Self::ProviderCallsForbidden => {
                write!(f, "schedule control plane must not call providers")
            }
            Self::ExplicitActionRequired => write!(f, "schedule mutation requires explicit action"),
            Self::InvalidExecutionRequest => write!(f, "schedule execution request is invalid"),
            Self::RedactionRequired => write!(f, "schedule metadata must be redacted"),
        }
    }
}

impl std::error::Error for IpHelperScheduleContractError {}

fn validate_refs(
    field: &'static str,
    values: &[String],
) -> Result<(), IpHelperScheduleContractError> {
    if values.len() > MAX_IP_HELPER_SCHEDULE_REFS {
        return Err(IpHelperScheduleContractError::TooManyItems(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), IpHelperScheduleContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(
    field: &'static str,
    value: &str,
) -> Result<(), IpHelperScheduleContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(IpHelperScheduleContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_IP_HELPER_SCHEDULE_TEXT_LEN {
        return Err(IpHelperScheduleContractError::TooLong(field));
    }
    let normalized = trimmed.to_ascii_lowercase();
    for marker in [
        "s-1-",
        "sid",
        "username",
        "account_name",
        "token",
        "nonce",
        "pid",
        "process_id",
        "ip_address",
        "port",
        "path",
        "c:\\",
        "/users/",
        "/home/",
        "credential",
        "secret",
        "password",
        "api_key",
    ] {
        if normalized.contains(marker) {
            return Err(IpHelperScheduleContractError::UnsafeField(field));
        }
    }
    Ok(())
}

fn validate_declared_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), IpHelperScheduleContractError> {
    validate_safe_text(field, value)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(IpHelperScheduleContractError::UnsafeField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        policy_for_command, MutationCommandId, MutationIntent, MutationIntentTimeBucket,
        MutationIntentTtlBucket, MUTATION_AUTHORIZATION_SCHEMA_VERSION,
    };

    #[test]
    fn ip_helper_schedule_contract_accepts_bounded_session_only_state() {
        let status = IpHelperScheduleStatus::not_configured(7);
        status.validate().expect("default schedule status");
        assert!(status.session_bound_marker);
        assert!(status.restart_disabled_marker);
        assert!(!status.timer_runtime_active);
        assert_eq!(status.scheduler_triggered_provider_calls, 0);
    }

    #[test]
    fn ip_helper_schedule_contract_rejects_unsafe_limits_and_fields() {
        let mut status = IpHelperScheduleStatus::not_configured(7);
        status.config.maximum_records = 0;
        assert!(matches!(
            status.validate(),
            Err(IpHelperScheduleContractError::InvalidLimit(
                "maximum_records"
            ))
        ));

        let mut status = IpHelperScheduleStatus::not_configured(7);
        status.audit_refs = vec!["token_value".to_string()];
        assert!(matches!(
            status.validate(),
            Err(IpHelperScheduleContractError::UnsafeField("audit_refs"))
        ));
    }

    #[test]
    fn ip_helper_schedule_contract_accepts_session_bound_scheduled_runtime() {
        let mut status = IpHelperScheduleStatus::not_configured(7);
        status.schedule_state = IpHelperScheduleState::ConfiguredEnabled;
        status.enabled_marker = true;
        status.lease_state = IpHelperScheduleLeaseState::Active;
        status.schedule_lease_ref = Some("ip_helper_schedule_lease_ref".to_string());
        status.schedule_lease_valid = true;
        status.timer_runtime_active = true;
        status.next_due_category = IpHelperScheduleNextDueCategory::Deferred;
        status.scheduler_triggered_provider_calls = 1;
        status.execution_count_bucket = IpHelperScheduleCountBucket::One;
        status.scheduled_sample_count_bucket = IpHelperScheduleCountBucket::One;
        status.latest_scheduled_cycle_ref = Some("ip_helper_scheduled_cycle_ref".to_string());
        status.latest_scheduled_execution_result = IpHelperScheduledExecutionResult::Completed;
        status.latest_scheduled_cycle = Some(IpHelperScheduledCycleRecord {
            cycle_ref: "ip_helper_scheduled_cycle_ref".to_string(),
            scheduler_item_ref: "ip_helper_scheduler_item_ref".to_string(),
            schedule_ref: status.schedule_ref.clone(),
            cycle_type: IpHelperScheduledCycleType::Scheduled,
            due_state: IpHelperScheduledDueState::Due,
            authorization_state: IpHelperScheduledAuthorizationState::Valid,
            execution_result: IpHelperScheduledExecutionResult::Completed,
            retry_state: IpHelperScheduledRetryState::None,
            backpressure_state: IpHelperScheduledBackpressureState::None,
            freshness_result: IpHelperScheduledFreshnessState::Fresh,
            missed_sample_result: IpHelperScheduledMissedSampleState::OnTime,
            started_time_bucket: Some(Timestamp::now()),
            completed_time_bucket: Some(Timestamp::now()),
            duration_bucket: "bounded_under_timeout".to_string(),
            provider_call_count_bucket: IpHelperScheduleCountBucket::One,
            batch_refs: vec!["ip_helper_batch_ref".to_string()],
            fact_refs: vec!["security_fact_ref".to_string()],
            snapshot_refs: vec!["canonical_snapshot_ref".to_string()],
            audit_refs: vec![IP_HELPER_SCHEDULED_CYCLE_COMPLETED.to_string()],
            degraded_reason: None,
            provenance_id: "servicehost_ip_helper_scheduler_runtime".to_string(),
            redaction_status: RedactionStatus::Redacted,
        });
        status
            .validate()
            .expect("scheduled runtime status is bounded");

        let mut status = IpHelperScheduleStatus::not_configured(7);
        status.automatic_provider_calls = 1;
        assert_eq!(
            status.validate(),
            Err(IpHelperScheduleContractError::ProviderCallsForbidden)
        );
    }

    #[test]
    fn ip_helper_scheduler_cycle_rejects_sensitive_values() {
        let mut cycle = IpHelperScheduledCycleRecord {
            cycle_ref: "ip_helper_scheduled_cycle_ref".to_string(),
            scheduler_item_ref: "ip_helper_scheduler_item_ref".to_string(),
            schedule_ref: "ip_helper_schedule_ref".to_string(),
            cycle_type: IpHelperScheduledCycleType::Scheduled,
            due_state: IpHelperScheduledDueState::Due,
            authorization_state: IpHelperScheduledAuthorizationState::Valid,
            execution_result: IpHelperScheduledExecutionResult::Skipped,
            retry_state: IpHelperScheduledRetryState::None,
            backpressure_state: IpHelperScheduledBackpressureState::None,
            freshness_result: IpHelperScheduledFreshnessState::Unavailable,
            missed_sample_result: IpHelperScheduledMissedSampleState::Blocked,
            started_time_bucket: Some(Timestamp::now()),
            completed_time_bucket: Some(Timestamp::now()),
            duration_bucket: "no_provider_call".to_string(),
            provider_call_count_bucket: IpHelperScheduleCountBucket::Zero,
            batch_refs: Vec::new(),
            fact_refs: Vec::new(),
            snapshot_refs: Vec::new(),
            audit_refs: vec![IP_HELPER_SCHEDULED_CYCLE_SKIPPED.to_string()],
            degraded_reason: Some("schedule_lease_invalid".to_string()),
            provenance_id: "servicehost_ip_helper_scheduler_runtime".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        cycle.validate().expect("safe skipped cycle");
        cycle.audit_refs = vec!["token=secret".to_string()];
        assert!(matches!(
            cycle.validate(),
            Err(IpHelperScheduleContractError::UnsafeField("audit_refs"))
        ));
    }

    #[test]
    fn ip_helper_schedule_mutation_request_is_strict_and_redacted() {
        let policy = policy_for_command(MutationCommandId::ConfigureIpHelperSchedule);
        let intent = MutationIntent {
            schema_version: MUTATION_AUTHORIZATION_SCHEMA_VERSION,
            intent_ref: "schedule_intent_ref".to_string(),
            request_ref: "schedule_request_ref".to_string(),
            ipc_session_ref: "ipc_session_ref".to_string(),
            caller_verification_ref: "caller_verification_ref".to_string(),
            command_id: MutationCommandId::ConfigureIpHelperSchedule,
            policy_ref: policy.policy_ref,
            policy_version: policy.policy_version,
            target_capability_ref: "ip_helper_provider_ref".to_string(),
            target_capability_category: policy.required_capability,
            requested_operation_category: "configure_schedule".to_string(),
            created_time_bucket: MutationIntentTimeBucket::CurrentConnection,
            expiry_ttl_bucket: MutationIntentTtlBucket::ThirtySeconds,
            ownership_epoch: 7,
            idempotency_ref: Some("schedule_idempotency_ref".to_string()),
            explicit_user_action: true,
            dry_run: true,
            audit_refs: vec!["mutation_intent_received".to_string()],
            provenance_id: "servicehost_mutation_authorization".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        let request = IpHelperScheduleMutationRequest {
            execution_request: MutationExecutionRequest {
                schema_version: MUTATION_AUTHORIZATION_SCHEMA_VERSION,
                decision_ref: "mutation_decision_ref".to_string(),
                intent,
                explicit_user_action: true,
                provenance_id: "servicehost_ip_helper_schedule_control_plane".to_string(),
                redaction_status: RedactionStatus::Redacted,
            },
            schedule_config: Some(IpHelperScheduleConfig::default()),
            explicit_user_action: true,
            provenance_id: "servicehost_ip_helper_schedule_control_plane".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        request.validate().expect("valid schedule mutation request");
        let mut value = serde_json::to_value(&request).expect("json");
        value
            .as_object_mut()
            .expect("object")
            .insert("path".to_string(), serde_json::json!("C:\\secret"));
        assert!(serde_json::from_value::<IpHelperScheduleMutationRequest>(value).is_err());
    }
}
