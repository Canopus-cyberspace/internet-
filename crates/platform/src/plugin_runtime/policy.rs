use crate::pipeline::{CheckpointHandle, ReplayContext};
use sentinel_contracts::{RuntimeMode, SupportLevel};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceQuota {
    pub max_memory_mb: u64,
    pub max_queue_depth: usize,
    pub max_events_per_batch: usize,
    pub max_concurrency: usize,
    pub allow_online_lookup: bool,
    pub allow_external_upload: bool,
    pub allow_raw_filesystem: bool,
    pub allow_elevated_service: bool,
    pub allow_response_execution: bool,
}

impl ResourceQuota {
    pub fn static_internal_default(runtime_mode: &RuntimeMode) -> Self {
        Self {
            max_memory_mb: 256,
            max_queue_depth: 1024,
            max_events_per_batch: if matches!(
                runtime_mode,
                RuntimeMode::Batch | RuntimeMode::Hybrid
            ) {
                256
            } else {
                1
            },
            max_concurrency: 1,
            allow_online_lookup: false,
            allow_external_upload: false,
            allow_raw_filesystem: false,
            allow_elevated_service: false,
            allow_response_execution: false,
        }
    }

    pub fn replay_safe(mut self) -> Self {
        self.allow_online_lookup = false;
        self.allow_external_upload = false;
        self.allow_response_execution = false;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutPolicy {
    pub initialize_timeout_ms: u64,
    pub start_timeout_ms: u64,
    pub event_timeout_ms: u64,
    pub batch_timeout_ms: u64,
    pub checkpoint_timeout_ms: u64,
    pub stop_timeout_ms: u64,
    pub health_timeout_ms: u64,
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        Self {
            initialize_timeout_ms: 5_000,
            start_timeout_ms: 5_000,
            event_timeout_ms: 2_000,
            batch_timeout_ms: 10_000,
            checkpoint_timeout_ms: 3_000,
            stop_timeout_ms: 5_000,
            health_timeout_ms: 1_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailurePolicy {
    pub mode: FailureMode,
    pub max_failures_before_disable: u32,
    pub restart_backoff_ms: u64,
    pub degrade_on_error: bool,
}

impl FailurePolicy {
    pub fn degrade() -> Self {
        Self {
            mode: FailureMode::MarkDegraded,
            max_failures_before_disable: 3,
            restart_backoff_ms: 1_000,
            degrade_on_error: true,
        }
    }
}

impl Default for FailurePolicy {
    fn default() -> Self {
        Self::degrade()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    MarkDegraded,
    DisablePlugin,
    RestartWithinLimit,
    MarkFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointSupport {
    pub support_level: SupportLevel,
    pub handle: Option<CheckpointHandle>,
    pub interval_seconds: Option<u64>,
    pub before_shutdown: bool,
    pub before_upgrade: bool,
    pub before_replay: bool,
}

impl CheckpointSupport {
    pub fn none() -> Self {
        Self {
            support_level: SupportLevel::None,
            handle: None,
            interval_seconds: None,
            before_shutdown: false,
            before_upgrade: false,
            before_replay: false,
        }
    }

    pub fn from_manifest_level(support_level: SupportLevel) -> Self {
        Self {
            before_shutdown: !matches!(support_level, SupportLevel::None),
            before_upgrade: !matches!(support_level, SupportLevel::None),
            before_replay: !matches!(support_level, SupportLevel::None),
            support_level,
            handle: None,
            interval_seconds: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySupport {
    pub support_level: SupportLevel,
    pub context: Option<ReplayContext>,
    pub response_execution_disabled_by_default: bool,
    pub online_lookup_disabled_by_default: bool,
    pub firewall_qos_isolation_disabled_by_default: bool,
    pub external_upload_disabled_by_default: bool,
}

impl ReplaySupport {
    pub fn from_manifest_level(support_level: SupportLevel) -> Self {
        Self {
            support_level,
            context: None,
            response_execution_disabled_by_default: true,
            online_lookup_disabled_by_default: true,
            firewall_qos_isolation_disabled_by_default: true,
            external_upload_disabled_by_default: true,
        }
    }

    pub fn with_context(mut self, context: ReplayContext) -> Self {
        self.context = Some(context);
        self.response_execution_disabled_by_default = true;
        self.online_lookup_disabled_by_default = true;
        self.firewall_qos_isolation_disabled_by_default = true;
        self.external_upload_disabled_by_default = true;
        self
    }

    pub fn real_response_forbidden(&self) -> bool {
        self.response_execution_disabled_by_default
            || self.firewall_qos_isolation_disabled_by_default
            || self
                .context
                .as_ref()
                .is_some_and(ReplayContext::real_response_forbidden)
    }

    pub fn online_lookup_forbidden(&self) -> bool {
        self.online_lookup_disabled_by_default
            || self
                .context
                .as_ref()
                .is_some_and(|context| context.online_lookup_disabled)
    }
}
