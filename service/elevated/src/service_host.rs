//! Product ServiceHost lifecycle wrapper.
//!
//! This phase owns the ServiceHost runtime container shell and bounded IPC
//! runtime. It does not start capture, execute responses, or persist raw source
//! data; IP Helper execution remains narrow, explicit, and ServiceHost-owned.

use crate::{
    run_one_pipe_connection_until_stop, wake_local_pipe, CallerVerificationPolicy,
    ServiceAuditLogger, ServiceCommandDispatcher, ServiceRuntimeError, ServiceSchedulerWakeSignal,
    DEFAULT_PIPE_NAME, SERVICE_DISPLAY_NAME, SERVICE_NAME, SERVICE_VERSION,
};
#[cfg(test)]
use sentinel_app_core::IpHelperHandoffRequest;
use sentinel_app_core::{RuntimeContainer, RuntimeContainerBuilder};
use sentinel_contracts::runtime_ownership::{
    RuntimeMode, RuntimeMutationTrustState, RuntimeOwnershipSummary, RuntimeShutdownState,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;
use uuid::Uuid;

const IP_HELPER_SCHEDULER_MIN_WAIT: Duration = Duration::from_millis(50);
const IP_HELPER_SCHEDULER_IDLE_WAIT: Duration = Duration::from_millis(500);
const IP_HELPER_SCHEDULER_MAX_WAIT: Duration = Duration::from_millis(1_000);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceHostRunMode {
    Service,
    Foreground,
}

impl ServiceHostRunMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Foreground => "foreground",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceHostLifecycleState {
    Created,
    Initializing,
    Starting,
    Running,
    Degraded,
    Stopping,
    Stopped,
    Failed,
    UnsupportedPlatform,
}

impl ServiceHostLifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Initializing => "initializing",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Degraded => "degraded",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::UnsupportedPlatform => "unsupported_platform",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceHostRuntimeStatus {
    pub service_name: String,
    pub display_name: String,
    pub version: String,
    pub run_mode: ServiceHostRunMode,
    pub lifecycle_state: ServiceHostLifecycleState,
    pub ipc_state: String,
    pub runtime_ownership: RuntimeMode,
    pub runtime_ownership_status: Option<RuntimeOwnershipSummary>,
    pub storage_owner_state: String,
    pub storage_owner_category: String,
    pub canonical_storage_writer: bool,
    pub storage_recovery_state: String,
    pub service_owned_cursor_state: String,
    pub split_owned_state_declared: bool,
    pub storage_path_exposed: bool,
    pub canonical_read_model_owner: String,
    pub llm_key_transferred_to_service: bool,
    pub mutation_trust_state: String,
    pub mutation_commands_enabled: bool,
    pub caller_impersonation: String,
    pub token_classification: String,
    pub production_mutation_authorization: String,
    pub foreground_development_policy: String,
    pub remote_caller_rejection_enabled: bool,
    pub network_logon_rejection_enabled: bool,
    pub session_binding_enabled: bool,
    pub provider_controller_state: String,
    pub provider_call_count: u32,
    pub shutdown_state: String,
    pub snapshot_freshness: String,
    pub local_only: bool,
    pub service_identity_requirement: String,
    pub temporary_runtime_directory: bool,
    pub scheduler_joined: bool,
    pub session_cleanup_completed: bool,
}

impl ServiceHostRuntimeStatus {
    pub fn new(run_mode: ServiceHostRunMode, lifecycle_state: ServiceHostLifecycleState) -> Self {
        Self {
            service_name: SERVICE_NAME.to_string(),
            display_name: SERVICE_DISPLAY_NAME.to_string(),
            version: SERVICE_VERSION.to_string(),
            run_mode,
            lifecycle_state,
            ipc_state: "not_started".to_string(),
            runtime_ownership: RuntimeMode::ServiceUnavailable,
            runtime_ownership_status: None,
            storage_owner_state: "unknown".to_string(),
            storage_owner_category: "none".to_string(),
            canonical_storage_writer: false,
            storage_recovery_state: "unavailable".to_string(),
            service_owned_cursor_state: "unavailable".to_string(),
            split_owned_state_declared: false,
            storage_path_exposed: false,
            canonical_read_model_owner: "none".to_string(),
            llm_key_transferred_to_service: false,
            mutation_trust_state: "impersonation_not_implemented".to_string(),
            mutation_commands_enabled: false,
            caller_impersonation: if cfg!(windows) {
                "implemented".to_string()
            } else {
                "unsupported_platform".to_string()
            },
            token_classification: if cfg!(windows) {
                "implemented".to_string()
            } else {
                "unsupported_platform".to_string()
            },
            production_mutation_authorization: "not_implemented".to_string(),
            foreground_development_policy: "disabled_by_default".to_string(),
            remote_caller_rejection_enabled: true,
            network_logon_rejection_enabled: true,
            session_binding_enabled: true,
            provider_controller_state: "inactive".to_string(),
            provider_call_count: 0,
            shutdown_state: "not_started".to_string(),
            snapshot_freshness: "unavailable".to_string(),
            local_only: true,
            service_identity_requirement: "local_service".to_string(),
            temporary_runtime_directory: matches!(run_mode, ServiceHostRunMode::Foreground),
            scheduler_joined: false,
            session_cleanup_completed: false,
        }
    }

    pub fn unsupported_platform(run_mode: ServiceHostRunMode) -> Self {
        let mut status = Self::new(run_mode, ServiceHostLifecycleState::UnsupportedPlatform);
        status.ipc_state = "unsupported_platform".to_string();
        status
    }
}

#[derive(Clone, Debug)]
pub struct ServiceHostShutdown {
    stop_requested: Arc<AtomicBool>,
}

impl ServiceHostShutdown {
    pub fn new() -> Self {
        Self {
            stop_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn request(&self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        wake_local_pipe(DEFAULT_PIPE_NAME);
    }

    pub fn is_requested(&self) -> bool {
        self.stop_requested.load(Ordering::SeqCst)
    }

    pub(crate) fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_requested)
    }
}

impl Default for ServiceHostShutdown {
    fn default() -> Self {
        Self::new()
    }
}

struct ServiceHostIpHelperSchedulerRuntime {
    stop_requested: Arc<AtomicBool>,
    wake_signal: Arc<ServiceSchedulerWakeSignal>,
    handle: Option<JoinHandle<()>>,
}

impl ServiceHostIpHelperSchedulerRuntime {
    fn start(
        container: Arc<Mutex<RuntimeContainer>>,
        shutdown: ServiceHostShutdown,
        wake_signal: Arc<ServiceSchedulerWakeSignal>,
        audit_logger: ServiceAuditLogger,
    ) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop_requested);
        let thread_wake = Arc::clone(&wake_signal);
        let handle = thread::spawn(move || {
            let _ = audit_logger.log(
                "ip_helper_scheduler_servicehost_timer_created",
                None,
                "created",
                Some("dormant_until_schedule_enabled"),
            );
            while !thread_stop.load(Ordering::SeqCst) && !shutdown.is_requested() {
                let elapsed_millis = thread_wake.elapsed_millis();
                let wait_millis = match container.lock() {
                    Ok(mut container) => {
                        let etw_wait = match container.pump_etw_live_batches() {
                            Ok(result) if result.published_batches > 0 => {
                                let reason = format!(
                                    "published_batches={},downstream_facts={}",
                                    result.published_batches, result.downstream_facts
                                );
                                let _ = audit_logger.log(
                                    "etw_live_network_pump",
                                    None,
                                    "completed",
                                    Some(reason.as_str()),
                                );
                                container.etw_live_pump_wait_millis()
                            }
                            Ok(_) => container.etw_live_pump_wait_millis(),
                            Err(error) => {
                                let _ = audit_logger.log(
                                    "etw_live_network_pump",
                                    None,
                                    "failed",
                                    Some(error.message.as_str()),
                                );
                                container.etw_live_pump_wait_millis()
                            }
                        };
                        let dns_wait = match container.pump_dns_sensing_live_batches() {
                            Ok(result) if result.published_batches > 0 => {
                                let reason = format!(
                                    "published_batches={},detector_consumed={}",
                                    result.published_batches, result.detector_consumed
                                );
                                let _ = audit_logger.log(
                                    "windows_dns_sensing_pump",
                                    None,
                                    "completed",
                                    Some(reason.as_str()),
                                );
                                container.dns_sensing_live_pump_wait_millis()
                            }
                            Ok(_) => container.dns_sensing_live_pump_wait_millis(),
                            Err(error) => {
                                let _ = audit_logger.log(
                                    "windows_dns_sensing_pump",
                                    None,
                                    "failed",
                                    Some(error.message.as_str()),
                                );
                                container.dns_sensing_live_pump_wait_millis()
                            }
                        };
                        let auth_remote_wait =
                            match container.pump_auth_remote_sensing_live_batches() {
                                Ok(result) if result.published_batches > 0 => {
                                    let reason = format!(
                                        "published_batches={},downstream_facts={}",
                                        result.published_batches, result.downstream_facts
                                    );
                                    let _ = audit_logger.log(
                                        "windows_auth_remote_sensing_pump",
                                        None,
                                        "completed",
                                        Some(reason.as_str()),
                                    );
                                    container.auth_remote_sensing_live_pump_wait_millis()
                                }
                                Ok(_) => container.auth_remote_sensing_live_pump_wait_millis(),
                                Err(error) => {
                                    let _ = audit_logger.log(
                                        "windows_auth_remote_sensing_pump",
                                        None,
                                        "failed",
                                        Some(error.message.as_str()),
                                    );
                                    container.auth_remote_sensing_live_pump_wait_millis()
                                }
                            };
                        let provider_wait = [etw_wait, dns_wait, auth_remote_wait]
                            .into_iter()
                            .flatten()
                            .min();
                        match container.ip_helper_scheduler_wait_millis(elapsed_millis) {
                            Some(0) => {
                                let owner_context = container.owner_context().clone();
                                let result = container
                                    .run_due_ip_helper_schedule_cycle(
                                        &owner_context,
                                        elapsed_millis,
                                    )
                                    .map(|cycle| cycle.execution_result);
                                let (outcome, reason) = match result {
                                    Ok(execution_result) => {
                                        ("completed", format!("{execution_result:?}"))
                                    }
                                    Err(error) => ("failed", error.message),
                                };
                                let _ = audit_logger.log(
                                    "ip_helper_scheduler_servicehost_timer_cycle",
                                    None,
                                    outcome,
                                    Some(reason.as_str()),
                                );
                                let ip_helper_wait = container
                                    .ip_helper_scheduler_wait_millis(elapsed_millis)
                                    .unwrap_or_else(|| {
                                        IP_HELPER_SCHEDULER_IDLE_WAIT.as_millis() as u64
                                    });
                                provider_wait
                                    .map_or(ip_helper_wait, |wait| wait.min(ip_helper_wait))
                            }
                            Some(wait) => provider_wait.map_or(wait, |provider| provider.min(wait)),
                            None => provider_wait.unwrap_or_else(|| {
                                IP_HELPER_SCHEDULER_IDLE_WAIT.as_millis() as u64
                            }),
                        }
                    }
                    Err(_) => IP_HELPER_SCHEDULER_IDLE_WAIT.as_millis() as u64,
                };
                let bounded_wait = Duration::from_millis(wait_millis)
                    .max(IP_HELPER_SCHEDULER_MIN_WAIT)
                    .min(IP_HELPER_SCHEDULER_MAX_WAIT);
                thread_wake.wait(bounded_wait);
            }
            let _ = audit_logger.log(
                "ip_helper_scheduler_servicehost_timer_joining",
                None,
                "joining",
                Some("shutdown_or_stop_requested"),
            );
        });
        Self {
            stop_requested,
            wake_signal,
            handle: Some(handle),
        }
    }

    fn stop_and_join(&mut self) -> bool {
        self.stop_requested.store(true, Ordering::SeqCst);
        self.wake_signal.notify();
        self.handle
            .take()
            .is_none_or(|handle| handle.join().is_ok())
    }
}

impl Drop for ServiceHostIpHelperSchedulerRuntime {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

pub struct ServiceHostRuntime {
    run_mode: ServiceHostRunMode,
    shutdown: ServiceHostShutdown,
    audit_logger: ServiceAuditLogger,
    temporary_runtime_dir: Option<PathBuf>,
    status: ServiceHostRuntimeStatus,
    runtime_container: Option<RuntimeContainer>,
    scheduler_runtime: Option<ServiceHostIpHelperSchedulerRuntime>,
}

impl ServiceHostRuntime {
    pub fn new(run_mode: ServiceHostRunMode, shutdown: ServiceHostShutdown) -> Self {
        let (audit_logger, temporary_runtime_dir) = match run_mode {
            ServiceHostRunMode::Service => (ServiceAuditLogger::program_data_default(), None),
            ServiceHostRunMode::Foreground => {
                let dir = foreground_runtime_dir().join(Uuid::new_v4().to_string());
                (
                    ServiceAuditLogger::with_path(dir.join("service-ipc.jsonl")),
                    Some(dir),
                )
            }
        };
        Self {
            run_mode,
            shutdown,
            audit_logger,
            temporary_runtime_dir,
            status: ServiceHostRuntimeStatus::new(run_mode, ServiceHostLifecycleState::Created),
            runtime_container: None,
            scheduler_runtime: None,
        }
    }

    pub fn status(&self) -> &ServiceHostRuntimeStatus {
        &self.status
    }

    #[cfg(not(windows))]
    pub fn run(&mut self) -> Result<ServiceHostRuntimeStatus, ServiceRuntimeError> {
        self.status = ServiceHostRuntimeStatus::unsupported_platform(self.run_mode);
        let _ = self.audit_logger.log(
            "service_host_unsupported_platform",
            None,
            "unsupported_platform",
            Some(self.run_mode.as_str()),
        );
        Ok(self.status.clone())
    }

    #[cfg(windows)]
    pub fn run(&mut self) -> Result<ServiceHostRuntimeStatus, ServiceRuntimeError> {
        self.transition(ServiceHostLifecycleState::Initializing, "initializing");
        self.prepare_runtime_directory()?;
        self.initialize_runtime_container()?;
        self.transition(ServiceHostLifecycleState::Starting, "starting");

        let verification_policy = match self.run_mode {
            ServiceHostRunMode::Service => CallerVerificationPolicy::service_mode(),
            ServiceHostRunMode::Foreground => CallerVerificationPolicy::foreground_mode(),
        };
        let mut dispatcher = ServiceCommandDispatcher::new(self.audit_logger.clone())
            .with_caller_verification_policy(verification_policy);
        if let Some(container) = self.runtime_container.take() {
            let shared_container = Arc::new(Mutex::new(container));
            let scheduler_wake_signal = Arc::new(ServiceSchedulerWakeSignal::new());
            self.scheduler_runtime = Some(ServiceHostIpHelperSchedulerRuntime::start(
                Arc::clone(&shared_container),
                self.shutdown.clone(),
                Arc::clone(&scheduler_wake_signal),
                self.audit_logger.clone(),
            ));
            dispatcher = dispatcher
                .with_shared_runtime_container(shared_container)
                .with_scheduler_wake_signal(scheduler_wake_signal);
        } else {
            if let Some(summary) = self.status.runtime_ownership_status.clone() {
                dispatcher = dispatcher.with_runtime_ownership_status(summary);
            }
            if let Some(snapshot) = self
                .runtime_container
                .as_ref()
                .and_then(|container| container.canonical_read_model_snapshot().ok())
            {
                dispatcher = dispatcher.with_canonical_read_model_snapshot(snapshot);
            }
        }
        self.status.ipc_state = "listening".to_string();
        self.transition(ServiceHostLifecycleState::Running, "running");

        while !self.shutdown.is_requested() {
            run_one_pipe_connection_until_stop(
                DEFAULT_PIPE_NAME,
                &mut dispatcher,
                &self.shutdown.flag(),
            )?;
        }

        if let Some(runtime) = self.scheduler_runtime.as_mut() {
            if !runtime.stop_and_join() {
                let _ = self.audit_logger.log(
                    "ip_helper_scheduler_servicehost_timer_join_failed",
                    None,
                    "failed",
                    Some("scheduler_timer_join_failed"),
                );
            }
        }
        self.scheduler_runtime = None;
        self.runtime_container = dispatcher.take_runtime_container();
        let shared_shutdown_summary = if self.runtime_container.is_none() {
            Some(
                dispatcher
                    .shutdown_runtime_container_in_place()
                    .map_err(ServiceRuntimeError::runtime)?,
            )
        } else {
            None
        };
        if let Some(summary) = self
            .runtime_container
            .as_ref()
            .map(RuntimeContainer::summary)
        {
            self.apply_runtime_summary(summary);
        }
        self.transition(ServiceHostLifecycleState::Stopping, "stopping");
        let shutdown_completed = match shared_shutdown_summary {
            Some(Some(summary)) => {
                self.status.runtime_ownership = RuntimeMode::ShutdownInProgress;
                self.status.scheduler_joined = summary.shutdown.scheduler_host_joined;
                self.status.storage_owner_state = "released".to_string();
                self.status.canonical_storage_writer = false;
                self.status.ipc_state = "shutdown".to_string();
                let completed = summary.shutdown.state
                    == sentinel_contracts::runtime_ownership::RuntimeShutdownState::Completed;
                self.apply_runtime_summary(summary);
                completed
            }
            Some(None) => false,
            None => self.perform_shutdown_ordering(),
        };
        if !shutdown_completed {
            self.transition(ServiceHostLifecycleState::Failed, "shutdown_failed");
            return Err(ServiceRuntimeError::runtime(
                "service host shutdown did not complete",
            ));
        }
        self.transition(ServiceHostLifecycleState::Stopped, "stopped");
        self.cleanup_runtime_directory();
        Ok(self.status.clone())
    }

    fn transition(&mut self, state: ServiceHostLifecycleState, outcome: &'static str) {
        self.status.lifecycle_state = state;
        let _ = self.audit_logger.log(
            "service_host_lifecycle",
            None,
            outcome,
            Some(state.as_str()),
        );
    }

    fn prepare_runtime_directory(&mut self) -> Result<(), ServiceRuntimeError> {
        if self.run_mode != ServiceHostRunMode::Foreground {
            return Ok(());
        }
        let dir = self
            .temporary_runtime_dir
            .clone()
            .unwrap_or_else(|| foreground_runtime_dir().join(Uuid::new_v4().to_string()));
        std::fs::create_dir_all(&dir)?;
        self.temporary_runtime_dir = Some(dir);
        self.status.temporary_runtime_directory = true;
        Ok(())
    }

    fn initialize_runtime_container(&mut self) -> Result<(), ServiceRuntimeError> {
        let _ = self.audit_logger.log(
            "runtime_container_initialization_started",
            None,
            "started",
            Some("service_host_runtime_container"),
        );
        let container = RuntimeContainerBuilder::for_service_host()
            .build()
            .map_err(|error| ServiceRuntimeError::runtime(error.message))?;
        let summary = container.summary();
        if let Some(storage_status) = container.storage_ownership_status() {
            self.status.storage_owner_state = storage_status.writer_state_str().to_string();
            self.status.storage_owner_category = storage_status.owner_category_str().to_string();
            self.status.canonical_storage_writer = storage_status.canonical_writer;
            self.status.llm_key_transferred_to_service = storage_status.llm_key_transferred;
        }
        if let Some(recovery) = container.storage_recovery_report() {
            self.status.storage_recovery_state = if recovery.degraded {
                "degraded".to_string()
            } else {
                "ready".to_string()
            };
            self.status.storage_path_exposed = recovery.storage_path_exposed;
        }
        let manifest = container.durable_storage_manifest();
        self.status.service_owned_cursor_state =
            if manifest.policy("portable_reader_cursor_state").is_some() {
                "service_owned".to_string()
            } else {
                "unavailable".to_string()
            };
        self.status.split_owned_state_declared = manifest.split_owned_state.iter().any(|policy| {
            policy.state_name == "temporary_llm_key"
                && policy.owner_category == "desktop_memory_only_write_only"
                && !policy.transferred_to_servicehost
                && !policy.persisted_by_servicehost
        });
        self.status.runtime_ownership = RuntimeMode::ServiceOwned;
        self.apply_runtime_summary(summary);
        self.runtime_container = Some(container);
        let _ = self.audit_logger.log(
            "runtime_container_ready",
            None,
            "ready",
            Some("provider_controller_inactive"),
        );
        Ok(())
    }

    fn cleanup_runtime_directory(&mut self) {
        self.status.session_cleanup_completed = true;
        let _ = self.audit_logger.log(
            "service_host_session_cleanup",
            None,
            "completed",
            Some("bounded_runtime_cleanup"),
        );
        if let Some(dir) = self.temporary_runtime_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    fn perform_shutdown_ordering(&mut self) -> bool {
        if self
            .status
            .runtime_ownership_status
            .as_ref()
            .is_some_and(|summary| {
                summary.shutdown.state
                    == sentinel_contracts::runtime_ownership::RuntimeShutdownState::Completed
            })
        {
            return true;
        }
        if let Some(mut container) = self.runtime_container.take() {
            match container.shutdown_before_ipc_close() {
                Ok(summary) => {
                    self.status.runtime_ownership = RuntimeMode::ShutdownInProgress;
                    self.status.scheduler_joined = summary.shutdown.scheduler_host_joined;
                    self.apply_runtime_summary(summary);
                    self.status.storage_owner_state = "released".to_string();
                    self.status.canonical_storage_writer = false;
                }
                Err(error) => {
                    self.status.runtime_ownership = RuntimeMode::Failed;
                    let _ = self.audit_logger.log(
                        "runtime_shutdown_completed",
                        None,
                        "failed",
                        Some(error.message.as_str()),
                    );
                    return false;
                }
            }

            self.status.ipc_state = "shutdown".to_string();
            let _ = self.audit_logger.log(
                "service_host_ipc_shutdown",
                None,
                "completed",
                Some("local_ipc_stopped"),
            );

            match container.complete_shutdown_after_ipc_close() {
                Ok(summary) => {
                    self.status.scheduler_joined = summary.shutdown.scheduler_host_joined;
                    let completed = summary.shutdown.state
                        == sentinel_contracts::runtime_ownership::RuntimeShutdownState::Completed;
                    self.apply_runtime_summary(summary);
                    if !completed {
                        return false;
                    }
                }
                Err(error) => {
                    self.status.runtime_ownership = RuntimeMode::Failed;
                    let _ = self.audit_logger.log(
                        "runtime_shutdown_completed",
                        None,
                        "failed",
                        Some(error.message.as_str()),
                    );
                    return false;
                }
            }
        } else {
            return false;
        }
        let _ = self.audit_logger.log(
            "service_host_scheduler_join",
            None,
            "completed",
            Some("service_scheduler_host_stopped"),
        );
        true
    }

    fn apply_runtime_summary(&mut self, summary: RuntimeOwnershipSummary) {
        self.status.mutation_trust_state =
            mutation_trust_state_label(summary.mutation_trust_state).to_string();
        self.status.mutation_commands_enabled = summary.mutation_commands_enabled;
        self.status.provider_controller_state = summary.provider_controller_state.clone();
        self.status.provider_call_count = summary.provider_call_count;
        self.status.shutdown_state = shutdown_state_label(summary.shutdown.state).to_string();
        self.status.snapshot_freshness = summary.snapshot_freshness.clone();
        self.status.canonical_read_model_owner = summary.canonical_read_model_owner.clone();
        self.status.runtime_ownership_status = Some(summary);
    }
}

impl Drop for ServiceHostRuntime {
    fn drop(&mut self) {
        if let Some(dir) = self.temporary_runtime_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn mutation_trust_state_label(state: RuntimeMutationTrustState) -> &'static str {
    match state {
        RuntimeMutationTrustState::ImpersonationNotImplemented => "impersonation_not_implemented",
        RuntimeMutationTrustState::TrustedLocalService => "trusted_local_service",
        RuntimeMutationTrustState::TestOnly => "test_only",
        RuntimeMutationTrustState::Disabled => "disabled",
    }
}

fn shutdown_state_label(state: RuntimeShutdownState) -> &'static str {
    match state {
        RuntimeShutdownState::NotStarted => "not_started",
        RuntimeShutdownState::InProgress => "in_progress",
        RuntimeShutdownState::Completed => "completed",
        RuntimeShutdownState::Failed => "failed",
        RuntimeShutdownState::TimedOut => "timed_out",
    }
}

fn foreground_runtime_dir() -> PathBuf {
    std::env::temp_dir()
        .join("SentinelGuard")
        .join("service-host")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SERVICE_HOST_RUNTIME_TEST_LOCK;

    fn wait_for_provider_call_count(
        shared_container: &Arc<Mutex<RuntimeContainer>>,
        expected_count: u32,
        timeout: Duration,
    ) {
        let deadline = Instant::now() + timeout;
        loop {
            let provider_call_count = shared_container
                .lock()
                .expect("container lock")
                .provider_call_count();
            if provider_call_count == expected_count || Instant::now() >= deadline {
                assert_eq!(provider_call_count, expected_count);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn service_host_status_uses_bounded_lifecycle_and_no_paths() {
        let status = ServiceHostRuntimeStatus::new(
            ServiceHostRunMode::Foreground,
            ServiceHostLifecycleState::Created,
        );

        assert_eq!(status.lifecycle_state, ServiceHostLifecycleState::Created);
        assert_eq!(status.service_identity_requirement, "local_service");
        assert!(status.temporary_runtime_directory);
        assert_eq!(status.storage_owner_state, "unknown");
        assert_eq!(status.storage_owner_category, "none");
        assert!(!status.canonical_storage_writer);
        assert_eq!(status.storage_recovery_state, "unavailable");
        assert_eq!(status.service_owned_cursor_state, "unavailable");
        assert!(!status.split_owned_state_declared);
        assert!(!status.storage_path_exposed);
        assert_eq!(status.canonical_read_model_owner, "none");
        assert!(!status.llm_key_transferred_to_service);
        assert_eq!(status.mutation_trust_state, "impersonation_not_implemented");
        assert!(!status.mutation_commands_enabled);
        assert_eq!(status.provider_controller_state, "inactive");
        assert_eq!(status.provider_call_count, 0);
        assert_eq!(status.shutdown_state, "not_started");
        let serialized = serde_json::to_string(&status).expect("status serializes");
        let lowered = serialized.to_ascii_lowercase();
        assert!(!lowered.contains("c:\\"));
        assert!(!lowered.contains("s-1-"));
        assert!(!lowered.contains("token_handle"));
        assert!(!lowered.contains("caller_token_value"));
    }

    #[test]
    fn runtime_container_initialization_reports_service_owned_and_provider_inactive() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .as_ref()
            .expect("service-owned runtime container");
        assert_eq!(container.event_bus_count(), 1);
        assert_eq!(container.dag_count(), 1);
        assert_eq!(container.plugin_runtime_count(), 1);
        assert_eq!(container.scheduler_controller_count(), 1);
        assert_eq!(container.scheduler_host_owner_count(), 1);
        assert_eq!(container.sampler_runtime_count(), 1);
        assert_eq!(container.endpoint_threat_runtime_count(), 1);
        assert_eq!(container.fusion_runtime_engine_count(), 1);
        assert!(container.evidence_quality_record_count() > 0);
        assert_eq!(container.provider_call_count(), 0);
        assert_eq!(container.startup_side_effect_count(), 0);
        assert!(container.scheduler_starts_disabled());
        assert!(container.scheduler_host_starts_stopped());
        assert!(container.samplers_start_inactive());
        assert_eq!(container.storage_writer_count(), 1);
        assert!(container.storage_canonical_writer());
        let status = runtime.status().clone();
        assert_eq!(status.runtime_ownership, RuntimeMode::ServiceOwned);
        assert_eq!(status.storage_owner_state, "owned");
        assert_eq!(status.storage_owner_category, "service_host");
        assert!(status.canonical_storage_writer);
        assert_eq!(status.storage_recovery_state, "ready");
        assert_eq!(status.service_owned_cursor_state, "service_owned");
        assert!(status.split_owned_state_declared);
        assert!(!status.storage_path_exposed);
        assert!(!status.llm_key_transferred_to_service);
        let ownership = status
            .runtime_ownership_status
            .as_ref()
            .expect("ownership status");
        assert_eq!(ownership.runtime_mode, RuntimeMode::ServiceOwned);
        assert_eq!(ownership.provider_controller_state, "inactive");
        assert_eq!(ownership.provider_call_count, 0);
        assert!(ownership.provider_zero.all_zero());
        assert!(!ownership.mutation_commands_enabled);
        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn scheduler_host_service_owned_startup_stays_stopped_until_ip_helper_schedule_enable() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .as_mut()
            .expect("service-owned runtime container");
        assert!(container.scheduler_host_starts_stopped());
        assert_eq!(container.provider_call_count(), 0);
        let owner_context = container.owner_context().clone();
        container
            .activate_ip_helper_provider(&owner_context)
            .expect("activate ip helper");
        let configure_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::ConfigureIpHelperSchedule,
        );
        container
            .configure_ip_helper_schedule(
                &owner_context,
                sentinel_contracts::IpHelperScheduleConfig::default(),
                vec!["ip_helper_schedule_configure_authorized".to_string()],
                configure_policy.policy_ref,
                configure_policy.policy_version,
            )
            .expect("configure ip helper schedule");
        assert_eq!(container.provider_call_count(), 0);
        let enable_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::EnableIpHelperSchedule,
        );
        let status = container
            .enable_ip_helper_schedule(
                &owner_context,
                "ip_helper_schedule_lease_servicehost_test".to_string(),
                vec!["ip_helper_schedule_enable_authorized".to_string()],
                enable_policy.policy_ref,
                enable_policy.policy_version,
            )
            .expect("enable ip helper schedule");
        assert!(status.ip_helper_schedule.timer_runtime_active);
        assert!(status.ip_helper_schedule.schedule_lease_valid);
        assert_eq!(container.provider_call_count(), 0);
        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn ip_helper_scheduler_servicehost_due_cycle_executes_once_and_preserves_boundaries() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .as_mut()
            .expect("service-owned runtime container");
        let owner_context = container.owner_context().clone();
        container
            .activate_ip_helper_provider(&owner_context)
            .expect("activate ip helper");
        let configure_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::ConfigureIpHelperSchedule,
        );
        container
            .configure_ip_helper_schedule(
                &owner_context,
                sentinel_contracts::IpHelperScheduleConfig::default(),
                vec!["ip_helper_schedule_configure_authorized".to_string()],
                configure_policy.policy_ref,
                configure_policy.policy_version,
            )
            .expect("configure ip helper schedule");
        let enable_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::EnableIpHelperSchedule,
        );
        container
            .enable_ip_helper_schedule(
                &owner_context,
                "ip_helper_schedule_lease_servicehost_cycle".to_string(),
                vec!["ip_helper_schedule_enable_authorized".to_string()],
                enable_policy.policy_ref,
                enable_policy.policy_version,
            )
            .expect("enable ip helper schedule");
        let cycle = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_servicehost_test".to_string(),
                1_000,
            )
            .expect("scheduled ip helper cycle");
        assert_eq!(
            cycle.execution_result,
            sentinel_contracts::IpHelperScheduledExecutionResult::Completed
        );
        assert_eq!(container.provider_call_count(), 1);
        let provider_zero = container.summary().provider_zero;
        assert_eq!(provider_zero.ip_helper_calls, 1);
        assert_eq!(provider_zero.etw_calls, 0);
        assert_eq!(provider_zero.npcap_probes, 0);
        assert_eq!(provider_zero.capture_broker_launches, 0);
        assert_eq!(provider_zero.process_network_facts, 0);
        assert_eq!(provider_zero.packet_facts, 0);
        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn servicehost_owned_timer_executes_due_ip_helper_cycle_and_joins() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .take()
            .expect("service-owned runtime container");
        let shared_container = Arc::new(Mutex::new(container));
        let wake_signal = Arc::new(ServiceSchedulerWakeSignal::new());
        let mut scheduler_runtime = ServiceHostIpHelperSchedulerRuntime::start(
            Arc::clone(&shared_container),
            runtime.shutdown.clone(),
            Arc::clone(&wake_signal),
            runtime.audit_logger.clone(),
        );

        {
            let mut container = shared_container.lock().expect("container lock");
            let owner_context = container.owner_context().clone();
            container
                .activate_ip_helper_provider(&owner_context)
                .expect("activate ip helper");
            container
                .configure_ip_helper_schedule(
                    &owner_context,
                    sentinel_contracts::IpHelperScheduleConfig::default(),
                    vec!["timer_schedule_authorization_ref".to_string()],
                    "mutation_policy_catalog".to_string(),
                    sentinel_contracts::MUTATION_POLICY_CATALOG_VERSION,
                )
                .expect("configure schedule");
            container
                .enable_ip_helper_schedule(
                    &owner_context,
                    "timer_schedule_lease_ref".to_string(),
                    vec!["timer_schedule_enable_ref".to_string()],
                    "mutation_policy_catalog".to_string(),
                    sentinel_contracts::MUTATION_POLICY_CATALOG_VERSION,
                )
                .expect("enable schedule");
            assert_eq!(container.provider_call_count(), 0);
        }
        wake_signal.notify();

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let provider_call_count = shared_container
                .lock()
                .expect("container lock")
                .provider_call_count();
            if provider_call_count == 1 || Instant::now() >= deadline {
                assert_eq!(provider_call_count, 1);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        assert!(scheduler_runtime.stop_and_join());
        drop(scheduler_runtime);
        let container = match Arc::try_unwrap(shared_container) {
            Ok(container) => container.into_inner().expect("container mutex"),
            Err(_) => panic!("single container owner after timer join"),
        };
        runtime.runtime_container = Some(container);
        let summary = runtime
            .runtime_container
            .as_ref()
            .expect("container restored")
            .summary();
        assert_eq!(summary.provider_call_count, 1);
        assert_eq!(summary.provider_zero.etw_calls, 0);
        assert_eq!(summary.provider_zero.npcap_probes, 0);
        assert_eq!(summary.provider_zero.capture_broker_launches, 0);
        assert_eq!(summary.provider_zero.packet_facts, 0);
        assert_eq!(summary.provider_zero.process_network_facts, 0);
        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn servicehost_owned_timer_resumes_after_pause_with_new_due_cycle() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .take()
            .expect("service-owned runtime container");
        let shared_container = Arc::new(Mutex::new(container));
        let wake_signal = Arc::new(ServiceSchedulerWakeSignal::new());
        let mut scheduler_runtime = ServiceHostIpHelperSchedulerRuntime::start(
            Arc::clone(&shared_container),
            runtime.shutdown.clone(),
            Arc::clone(&wake_signal),
            runtime.audit_logger.clone(),
        );

        {
            let mut container = shared_container.lock().expect("container lock");
            let owner_context = container.owner_context().clone();
            container
                .activate_ip_helper_provider(&owner_context)
                .expect("activate ip helper");
            container
                .configure_ip_helper_schedule(
                    &owner_context,
                    sentinel_contracts::IpHelperScheduleConfig::default(),
                    vec!["timer_resume_schedule_authorization_ref".to_string()],
                    "mutation_policy_catalog".to_string(),
                    sentinel_contracts::MUTATION_POLICY_CATALOG_VERSION,
                )
                .expect("configure schedule");
            container
                .enable_ip_helper_schedule(
                    &owner_context,
                    "timer_resume_schedule_lease_ref".to_string(),
                    vec!["timer_resume_schedule_enable_ref".to_string()],
                    "mutation_policy_catalog".to_string(),
                    sentinel_contracts::MUTATION_POLICY_CATALOG_VERSION,
                )
                .expect("enable schedule");
        }
        wake_signal.notify();
        wait_for_provider_call_count(&shared_container, 1, Duration::from_secs(5));

        {
            let mut container = shared_container.lock().expect("container lock");
            let owner_context = container.owner_context().clone();
            container
                .pause_ip_helper_schedule(
                    &owner_context,
                    vec!["timer_resume_schedule_pause_ref".to_string()],
                    "mutation_policy_catalog".to_string(),
                    sentinel_contracts::MUTATION_POLICY_CATALOG_VERSION,
                )
                .expect("pause schedule");
        }
        wake_signal.notify();
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(
            shared_container
                .lock()
                .expect("container lock")
                .provider_call_count(),
            1
        );

        {
            let mut container = shared_container.lock().expect("container lock");
            let owner_context = container.owner_context().clone();
            container
                .resume_ip_helper_schedule(
                    &owner_context,
                    "timer_resume_schedule_lease_ref_second".to_string(),
                    vec!["timer_resume_schedule_resume_ref".to_string()],
                    "mutation_policy_catalog".to_string(),
                    sentinel_contracts::MUTATION_POLICY_CATALOG_VERSION,
                )
                .expect("resume schedule");
        }
        wake_signal.notify();
        wait_for_provider_call_count(&shared_container, 2, Duration::from_secs(5));

        assert!(scheduler_runtime.stop_and_join());
        drop(scheduler_runtime);
        let container = match Arc::try_unwrap(shared_container) {
            Ok(container) => container.into_inner().expect("container mutex"),
            Err(_) => panic!("single container owner after timer join"),
        };
        runtime.runtime_container = Some(container);
        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn scheduler_shutdown_invalidates_ip_helper_schedule_and_joins_host() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        {
            let container = runtime
                .runtime_container
                .as_mut()
                .expect("service-owned runtime container");
            let owner_context = container.owner_context().clone();
            container
                .activate_ip_helper_provider(&owner_context)
                .expect("activate ip helper");
            let configure_policy = sentinel_contracts::policy_for_command(
                sentinel_contracts::MutationCommandId::ConfigureIpHelperSchedule,
            );
            container
                .configure_ip_helper_schedule(
                    &owner_context,
                    sentinel_contracts::IpHelperScheduleConfig::default(),
                    vec!["ip_helper_schedule_configure_authorized".to_string()],
                    configure_policy.policy_ref,
                    configure_policy.policy_version,
                )
                .expect("configure ip helper schedule");
            let enable_policy = sentinel_contracts::policy_for_command(
                sentinel_contracts::MutationCommandId::EnableIpHelperSchedule,
            );
            container
                .enable_ip_helper_schedule(
                    &owner_context,
                    "ip_helper_schedule_lease_shutdown_test".to_string(),
                    vec!["ip_helper_schedule_enable_authorized".to_string()],
                    enable_policy.policy_ref,
                    enable_policy.policy_version,
                )
                .expect("enable ip helper schedule");
        }
        assert!(runtime.perform_shutdown_ordering());
        assert!(runtime.status.scheduler_joined);
        assert_eq!(runtime.status.shutdown_state, "completed");
    }

    #[test]
    fn ip_helper_handoff_runs_only_through_servicehost_container() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .as_mut()
            .expect("service-owned runtime container");
        let owner_context = container.owner_context().clone();

        let result = container
            .execute_ip_helper_servicehost_handoff(
                &owner_context,
                IpHelperHandoffRequest::foreground_development_test(),
            )
            .expect("ip helper handoff");

        assert_eq!(container.provider_call_count(), 1);
        assert!(result.fact_count >= 2);
        assert!(result
            .emitted_topics
            .iter()
            .any(|topic| topic == "native.ip_helper.metadata"));
        assert!(result
            .emitted_topics
            .iter()
            .any(|topic| topic == "native.connection.category_fact"));
        assert_eq!(result.provider_status.provider_zero.etw_calls, 0);
        assert_eq!(result.provider_status.provider_zero.npcap_probes, 0);
        assert_eq!(
            result.provider_status.provider_zero.capture_broker_launches,
            0
        );
        assert_eq!(
            result.provider_status.provider_zero.process_network_facts,
            0
        );
        assert_eq!(result.provider_status.provider_zero.packet_facts, 0);
        assert!(
            result
                .provider_status
                .policy_summary
                .ip_helper_execution_available_over_production_ipc
        );

        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn provider_execution_gate_rejects_production_ipc_sample_until_activation() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .as_mut()
            .expect("service-owned runtime container");
        let owner_context = container.owner_context().clone();

        let error = container
            .execute_ip_helper_servicehost_handoff(
                &owner_context,
                IpHelperHandoffRequest::production_ipc(),
            )
            .expect_err("production ipc sample rejected");

        assert_eq!(
            error.details_redacted,
            Some(serde_json::json!({
                "reason_category": "ip_helper_not_active"
            }))
        );
        assert_eq!(container.provider_call_count(), 0);

        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn restart_recovery_servicehost_reacquires_storage_without_provider_or_llm_side_effects() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut first = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        first
            .initialize_runtime_container()
            .expect("first runtime container");
        assert_eq!(first.status.storage_owner_state, "owned");
        assert_eq!(first.status.storage_recovery_state, "ready");
        assert_eq!(first.status.service_owned_cursor_state, "service_owned");
        assert!(first.status.split_owned_state_declared);
        assert!(!first.status.storage_path_exposed);
        assert!(!first.status.llm_key_transferred_to_service);
        assert_eq!(first.status.provider_call_count, 0);
        let first_recovery = first
            .runtime_container
            .as_ref()
            .and_then(RuntimeContainer::storage_recovery_report)
            .expect("first recovery report");
        assert!(first_recovery.new_ownership_epoch_established);
        assert!(first_recovery.canonical_snapshots_rebuilt);
        assert!(!first_recovery.provider_executed);
        assert!(!first_recovery.llm_invoked);
        assert!(first.perform_shutdown_ordering());
        assert_eq!(first.status.storage_owner_state, "released");

        let shutdown = ServiceHostShutdown::new();
        let mut second = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        second
            .initialize_runtime_container()
            .expect("second runtime container");
        assert_eq!(second.status.storage_owner_state, "owned");
        assert_eq!(second.status.storage_recovery_state, "ready");
        assert_eq!(second.status.service_owned_cursor_state, "service_owned");
        assert!(second.status.split_owned_state_declared);
        assert!(!second.status.storage_path_exposed);
        assert!(!second.status.llm_key_transferred_to_service);
        assert_eq!(second.status.provider_call_count, 0);
        let second_recovery = second
            .runtime_container
            .as_ref()
            .and_then(RuntimeContainer::storage_recovery_report)
            .expect("second recovery report");
        assert!(second_recovery.ownership_validated);
        assert!(second_recovery.schema_validated);
        assert!(!second_recovery.scheduler_activated);
        assert!(!second_recovery.sampler_activated);
        assert!(!second_recovery.provider_executed);
        assert!(!second_recovery.stale_findings_replayed);
        assert!(!second_recovery.llm_invoked);
        assert!(second.perform_shutdown_ordering());
    }

    #[test]
    fn canonical_read_store_servicehost_initializes_one_bounded_snapshot() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .as_ref()
            .expect("service-owned runtime container");
        let snapshot = container
            .canonical_read_model_snapshot()
            .expect("canonical read-model snapshot");

        assert_eq!(container.read_model_store_count(), 1);
        assert_eq!(container.canonical_read_model_generation_count(), 1);
        assert!(!snapshot.partial_state);
        assert_eq!(
            snapshot.ownership_epoch,
            container.owner_context().ownership_epoch
        );
        assert!(snapshot.items.iter().any(|item| {
            item.model_category
                == sentinel_contracts::read_model_snapshot::CanonicalReadModelCategory::RuntimeOwnership
        }));
        assert!(snapshot.items.iter().any(|item| {
            item.model_category
                == sentinel_contracts::read_model_snapshot::CanonicalReadModelCategory::ProviderControllerStatus
        }));
        assert_eq!(container.provider_call_count(), 0);
        assert!(runtime
            .status
            .runtime_ownership_status
            .as_ref()
            .expect("runtime ownership status")
            .provider_zero
            .all_zero());
        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn canonical_read_store_servicehost_status_reads_do_not_publish_new_generations() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .as_ref()
            .expect("service-owned runtime container");
        let first = container
            .canonical_read_model_snapshot()
            .expect("first snapshot");
        let first_generation_count = container.canonical_read_model_generation_count();

        let _status = runtime.status().clone();
        let second = runtime
            .runtime_container
            .as_ref()
            .expect("service-owned runtime container")
            .canonical_read_model_snapshot()
            .expect("second snapshot");

        assert_eq!(first.snapshot_id, second.snapshot_id);
        assert_eq!(
            runtime
                .runtime_container
                .as_ref()
                .expect("service-owned runtime container")
                .canonical_read_model_generation_count(),
            first_generation_count
        );
        assert_eq!(
            runtime
                .runtime_container
                .as_ref()
                .expect("service-owned runtime container")
                .provider_call_count(),
            0
        );
        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn read_commands_servicehost_dispatch_is_side_effect_free_and_provider_zero() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .as_ref()
            .expect("service-owned runtime container");
        let snapshot = container
            .canonical_read_model_snapshot()
            .expect("canonical read-model snapshot");
        let generation_count = container.canonical_read_model_generation_count();
        let mut dispatcher = ServiceCommandDispatcher::new(runtime.audit_logger.clone())
            .with_canonical_read_model_snapshot(snapshot);

        let response = dispatcher.dispatch(crate::runtime_ipc::IpcRequest::new(
            crate::runtime_ipc::ServiceCommand::Read(
                sentinel_contracts::ServiceReadCommandId::GetProviderControllerStatus,
            ),
            serde_json::json!({ "page_size": 1 }),
        ));

        assert!(response.error.is_none());
        let container = runtime
            .runtime_container
            .as_ref()
            .expect("service-owned runtime container");
        assert_eq!(
            container.canonical_read_model_generation_count(),
            generation_count
        );
        assert_eq!(container.provider_call_count(), 0);
        assert!(runtime
            .status
            .runtime_ownership_status
            .as_ref()
            .expect("ownership status")
            .provider_zero
            .all_zero());
        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn provider_controller_read_commands_are_side_effect_free_and_provider_zero() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .as_ref()
            .expect("service-owned runtime container");
        let generation_count = container.canonical_read_model_generation_count();
        let snapshot = container
            .canonical_read_model_snapshot()
            .expect("canonical read-model snapshot");
        let mut dispatcher = ServiceCommandDispatcher::new(runtime.audit_logger.clone())
            .with_canonical_read_model_snapshot(snapshot);

        for command in [
            sentinel_contracts::ServiceReadCommandId::GetProviderControllerStatus,
            sentinel_contracts::ServiceReadCommandId::ListNetworkProviderStatus,
            sentinel_contracts::ServiceReadCommandId::GetNetworkProviderStatus,
            sentinel_contracts::ServiceReadCommandId::GetNetworkVisibilitySummary,
            sentinel_contracts::ServiceReadCommandId::GetNetworkFallbackPlan,
        ] {
            let response = dispatcher.dispatch(crate::runtime_ipc::IpcRequest::new(
                crate::runtime_ipc::ServiceCommand::Read(command),
                serde_json::json!({ "page_size": 1 }),
            ));
            assert!(response.error.is_none(), "read command failed: {command:?}");
            let serialized = serde_json::to_string(&response).expect("response json");
            assert!(serialized.contains("provider_controller_ref"));
            assert!(!serialized.contains("provider_handle"));
            assert!(!serialized.contains("packet_data"));
        }

        let container = runtime
            .runtime_container
            .as_ref()
            .expect("service-owned runtime container");
        assert_eq!(
            container.canonical_read_model_generation_count(),
            generation_count
        );
        assert_eq!(container.provider_call_count(), 0);
        assert!(container.summary().provider_zero.all_zero());
        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn read_models_report_export_traceability_reads_are_side_effect_free() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .as_ref()
            .expect("service-owned runtime container");
        let generation_count = container.canonical_read_model_generation_count();
        let traceability = container
            .canonical_report_export_traceability()
            .expect("traceability");
        traceability.validate().expect("traceability validates");
        let integrity_hash = traceability.integrity_hash.clone();
        let snapshot = container
            .canonical_read_model_snapshot()
            .expect("canonical read-model snapshot");
        let mut dispatcher = ServiceCommandDispatcher::new(runtime.audit_logger.clone())
            .with_runtime_ownership_status(container.summary())
            .with_canonical_read_model_snapshot(snapshot);

        for command in [
            sentinel_contracts::ServiceReadCommandId::GetReportTraceability,
            sentinel_contracts::ServiceReadCommandId::GetExportTraceability,
        ] {
            let response = dispatcher.dispatch(crate::runtime_ipc::IpcRequest::new(
                crate::runtime_ipc::ServiceCommand::Read(command),
                serde_json::json!({ "page_size": 1 }),
            ));
            assert!(response.error.is_none());
            let value = response.result.expect("read response");
            let serialized = serde_json::to_string(&value).expect("read json");
            assert!(serialized.contains(&integrity_hash));
            for marker in [
                "provider_value",
                "automatic_llm_calls\":true",
                "response_execution\":true",
                "raw_log",
                "api_key_value",
                "c:\\",
            ] {
                assert!(
                    !serialized.to_ascii_lowercase().contains(marker),
                    "ServiceHost read leaked marker {marker}"
                );
            }
        }

        let container = runtime
            .runtime_container
            .as_ref()
            .expect("service-owned runtime container");
        assert_eq!(
            container.canonical_read_model_generation_count(),
            generation_count
        );
        assert_eq!(container.provider_call_count(), 0);
        assert!(container.phase_0b_closure_summary().complete());
        assert!(runtime
            .status
            .runtime_ownership_status
            .as_ref()
            .expect("ownership status")
            .provider_zero
            .all_zero());
        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn runtime_container_shutdown_is_ordered_and_idempotent() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        assert!(runtime.perform_shutdown_ordering());
        assert!(runtime.perform_shutdown_ordering());
        assert!(runtime.status.scheduler_joined);
        assert_eq!(runtime.status.storage_owner_state, "released");
        assert!(!runtime.status.canonical_storage_writer);
        assert_eq!(runtime.status.canonical_read_model_owner, "released");
        assert_eq!(runtime.status.shutdown_state, "completed");
        assert_eq!(runtime.status.snapshot_freshness, "finalized");
        assert_eq!(runtime.status.provider_call_count, 0);
        assert_eq!(runtime.status.provider_controller_state, "inactive");
        assert_eq!(runtime.status.ipc_state, "shutdown");
        assert_eq!(
            runtime.status.runtime_ownership,
            RuntimeMode::ShutdownInProgress
        );
        let summary = runtime
            .status
            .runtime_ownership_status
            .as_ref()
            .expect("completed runtime ownership summary");
        assert_eq!(
            summary.shutdown.state,
            sentinel_contracts::runtime_ownership::RuntimeShutdownState::Completed
        );
        assert_eq!(
            summary.shutdown.stages.last().map(|stage| stage.stage),
            Some(sentinel_contracts::runtime_ownership::RuntimeShutdownStage::Stopped)
        );
        assert!(!summary.shutdown.provider_stop_called);
        assert!(summary.provider_zero.all_zero());
    }

    #[test]
    fn storage_ownership_shutdown_releases_writer_and_stopped_servicehost_reopens() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut first = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        first
            .initialize_runtime_container()
            .expect("first runtime container");
        assert_eq!(first.status.storage_owner_state, "owned");
        assert_eq!(first.status.storage_owner_category, "service_host");
        assert!(first.perform_shutdown_ordering());
        assert_eq!(first.status.storage_owner_state, "released");

        let shutdown = ServiceHostShutdown::new();
        let mut second = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        second
            .initialize_runtime_container()
            .expect("second runtime container after first stopped");
        assert_eq!(second.status.storage_owner_state, "owned");
        assert!(second.status.canonical_storage_writer);
        assert!(second.perform_shutdown_ordering());
    }

    #[test]
    fn startup_runtime_assembly_builds_actual_instances_without_side_effects() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime
            .initialize_runtime_container()
            .expect("runtime container");
        let container = runtime
            .runtime_container
            .as_ref()
            .expect("service-owned runtime container");

        assert_eq!(container.event_bus_count(), 1);
        assert_eq!(container.dag_count(), 1);
        assert_eq!(container.plugin_runtime_count(), 1);
        assert_eq!(container.scheduler_controller_count(), 1);
        assert_eq!(container.scheduler_host_owner_count(), 1);
        assert_eq!(container.sampler_runtime_count(), 1);
        assert_eq!(container.endpoint_threat_runtime_count(), 1);
        assert_eq!(container.fusion_state_count(), 1);
        assert_eq!(container.evidence_quality_state_count(), 1);
        assert_eq!(container.provider_call_count(), 0);
        assert_eq!(container.startup_side_effect_count(), 0);
        assert!(container.scheduler_starts_disabled());
        assert!(container.scheduler_host_starts_stopped());
        assert!(container.samplers_start_inactive());
        assert!(runtime.perform_shutdown_ordering());
    }

    #[test]
    fn shutdown_without_owned_container_never_reports_stopped() {
        let shutdown = ServiceHostShutdown::new();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
        runtime.transition(ServiceHostLifecycleState::Stopping, "stopping");

        assert!(!runtime.perform_shutdown_ordering());
        assert_ne!(
            runtime.status.lifecycle_state,
            ServiceHostLifecycleState::Stopped
        );
        assert!(!runtime.status.scheduler_joined);
        assert_ne!(runtime.status.shutdown_state, "completed");
    }

    #[cfg(windows)]
    #[test]
    fn bounded_foreground_smoke_constructs_and_closes_service_owned_runtime() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shutdown = ServiceHostShutdown::new();
        shutdown.request();
        let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);

        let status = runtime.run().expect("bounded foreground runtime");

        assert_eq!(status.lifecycle_state, ServiceHostLifecycleState::Stopped);
        assert_eq!(status.ipc_state, "shutdown");
        assert_eq!(status.shutdown_state, "completed");
        assert!(status.scheduler_joined);
        assert!(status.session_cleanup_completed);
        assert_eq!(status.storage_owner_state, "released");
        assert_eq!(status.canonical_read_model_owner, "released");
        assert!(!status.canonical_storage_writer);
        assert_eq!(status.provider_controller_state, "inactive");
        assert_eq!(status.provider_call_count, 0);
        assert!(!status.mutation_commands_enabled);
        let summary = status
            .runtime_ownership_status
            .expect("runtime ownership summary");
        assert!(summary.provider_zero.all_zero());
        assert_eq!(
            summary.shutdown.state,
            sentinel_contracts::runtime_ownership::RuntimeShutdownState::Completed
        );
    }

    #[test]
    fn non_windows_status_is_explicitly_unsupported() {
        let status = ServiceHostRuntimeStatus::unsupported_platform(ServiceHostRunMode::Service);
        assert_eq!(
            status.lifecycle_state,
            ServiceHostLifecycleState::UnsupportedPlatform
        );
        assert_eq!(status.ipc_state, "unsupported_platform");
    }
}
