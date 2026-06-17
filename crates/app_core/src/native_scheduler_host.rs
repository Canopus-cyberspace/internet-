use crate::native_sampler_runtime::NativeSamplerRuntime;
use crate::native_scheduler::NativeSchedulerController;
use crate::read_commands::ReadOnlyCommandState;
use crate::runtime_container::RuntimeEventBusHandle;
use sentinel_contracts::{
    AuditId, CommandResult, CoreError, ErrorCode, ErrorSeverity, EventEnvelope, EventType,
    NativePermissionState, NativeSamplerRuntimeState, NativeSchedulerControllerState,
    NativeSchedulerCycleId, NativeSchedulerCycleOrigin, NativeSchedulerCycleState,
    NativeSchedulerHostAction, NativeSchedulerHostActionRequest, NativeSchedulerHostActionResult,
    NativeSchedulerHostAuditEntry, NativeSchedulerHostCycleSummary, NativeSchedulerHostHealthState,
    NativeSchedulerHostHealthSummary, NativeSchedulerHostLifecycleState,
    NativeSchedulerHostShutdownState, NativeSchedulerHostStartPreview, NativeSchedulerHostStatus,
    NativeSchedulerHostWakeReason, NativeSchedulerHostWakeState, NativeSchedulerHostWatchdogState,
    NativeSchedulerTickRequest, PluginId, PrivacyClass, QualityScore, RedactionStatus,
    SchemaVersion, Timestamp, TraceContext, MAX_NATIVE_SAMPLERS_PER_TICK,
    MAX_NATIVE_SCHEDULER_CYCLES, MAX_NATIVE_SCHEDULER_REFS,
    MIN_NATIVE_SCHEDULER_RETRY_DELAY_MILLIS, MIN_NATIVE_SCHEDULER_TICK_MILLIS,
};
use sentinel_platform::{
    PublishOptions, TopicName, AUDIT_NATIVE_SCHEDULER_HOST, NATIVE_SCHEDULER_HOST_FAILED,
    NATIVE_SCHEDULER_HOST_PAUSED, NATIVE_SCHEDULER_HOST_RESUMED, NATIVE_SCHEDULER_HOST_STARTED,
    NATIVE_SCHEDULER_HOST_STATUS, NATIVE_SCHEDULER_HOST_STOPPED, NATIVE_SCHEDULER_HOST_TASK_FAILED,
    NATIVE_SCHEDULER_HOST_TASK_JOINED, NATIVE_SCHEDULER_HOST_TASK_PAUSED,
    NATIVE_SCHEDULER_HOST_TASK_RESUMED, NATIVE_SCHEDULER_HOST_TASK_STARTED,
    NATIVE_SCHEDULER_HOST_TASK_STOPPED, NATIVE_SCHEDULER_HOST_TASK_WAKE,
    NATIVE_SCHEDULER_HOST_WAKE,
};
use serde_json::json;

const HOST_PROVENANCE_ID: &str = "native_scheduler_host_orchestrator";
const HOST_ORCHESTRATOR_ID: &str = "session_native_scheduler_host";
const CONTROLLER_ID: &str = "native_scheduler_controller";
const CURRENT_SESSION_BUCKET: &str = "current_session";
const MAX_IDLE_WAKE_BUCKET: &str = "status_reconcile_later";
pub const NATIVE_SCHEDULER_HOST_MAX_RECONCILE_SLEEP_MILLIS: u64 = 30_000;
pub const NATIVE_SCHEDULER_HOST_JOIN_TIMEOUT_MILLIS: u64 = 2_000;

#[derive(Clone, Debug)]
pub struct NativeSchedulerHostController {
    status: NativeSchedulerHostStatus,
    cycles: Vec<NativeSchedulerHostCycleSummary>,
    audit_entries: Vec<NativeSchedulerHostAuditEntry>,
    event_bus: RuntimeEventBusHandle,
    producer_plugin: PluginId,
}

#[derive(Clone, Debug)]
struct HostCycleDraft {
    host_cycle_id: NativeSchedulerCycleId,
    cycle_origin: NativeSchedulerCycleOrigin,
    wake_reason: NativeSchedulerHostWakeReason,
    scheduler_cycle_ref: Option<NativeSchedulerCycleId>,
    tick_invoked: bool,
    no_due_work: bool,
    degraded: bool,
    cancelled: bool,
    cycle_gate_busy: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSchedulerHostWaitPlan {
    pub wait_millis: u64,
    pub wake_reason: NativeSchedulerHostWakeReason,
    pub wait_state: String,
    pub eligible_sampler_count: u32,
    pub due_now: bool,
}

#[derive(Clone, Debug)]
pub struct NativeSchedulerHostTimerRuntimeUpdate {
    pub lifecycle_state: Option<NativeSchedulerHostLifecycleState>,
    pub timer_task_active: bool,
    pub task_ownership_state: String,
    pub current_wait_state: String,
    pub pending_wake: bool,
    pub cancellation_state: String,
    pub join_state: String,
    pub join_timeout_category: Option<String>,
    pub shutdown_cleanup_status: String,
    pub wake_state: Option<NativeSchedulerHostWakeState>,
    pub health_state: Option<NativeSchedulerHostHealthState>,
    pub watchdog_state: Option<NativeSchedulerHostWatchdogState>,
    pub shutdown_state: Option<NativeSchedulerHostShutdownState>,
    pub latest_wake_reason: Option<NativeSchedulerHostWakeReason>,
    pub degraded_reason: Option<String>,
}

impl NativeSchedulerHostController {
    #[cfg(test)]
    pub fn from_read_state(read: &ReadOnlyCommandState) -> Self {
        Self::from_read_state_with_event_bus(read, RuntimeEventBusHandle::new_legacy_core_topics())
    }

    pub(crate) fn from_read_state_with_event_bus(
        read: &ReadOnlyCommandState,
        event_bus: RuntimeEventBusHandle,
    ) -> Self {
        Self {
            status: read.native_scheduler_host_status.clone(),
            cycles: read.native_scheduler_host_cycles.clone(),
            audit_entries: read.native_scheduler_host_audit_entries.clone(),
            event_bus,
            producer_plugin: PluginId::new_v4(),
        }
    }

    pub fn sync_read_state(&self, read: &mut ReadOnlyCommandState) {
        read.native_scheduler_host_status = self.status.clone();
        read.native_scheduler_host_cycles = self.cycles.clone();
        read.native_scheduler_host_audit_entries = self.audit_entries.clone();
    }

    pub fn status(&self, read: &ReadOnlyCommandState) -> CommandResult<NativeSchedulerHostStatus> {
        let mut status = self.status.clone();
        refresh_status_from_read(read, &self.cycles, &self.audit_entries, &mut status);
        status.validate().map_err(contract_error)?;
        Ok(status)
    }

    pub(crate) fn status_from_read_state(
        read: &ReadOnlyCommandState,
    ) -> CommandResult<NativeSchedulerHostStatus> {
        let mut status = read.native_scheduler_host_status.clone();
        refresh_status_from_read(
            read,
            &read.native_scheduler_host_cycles,
            &read.native_scheduler_host_audit_entries,
            &mut status,
        );
        status.validate().map_err(contract_error)?;
        Ok(status)
    }

    pub(crate) fn health_from_read_state(
        read: &ReadOnlyCommandState,
    ) -> CommandResult<NativeSchedulerHostHealthSummary> {
        let status = Self::status_from_read_state(read)?;
        let health = NativeSchedulerHostHealthSummary {
            latest_wake_reason: status.latest_wake_reason.clone(),
            watchdog_state: status.watchdog_state.clone(),
            shutdown_state: status.shutdown_state.clone(),
            delayed_wake_count_bucket: status.degraded_wake_count_bucket.clone(),
            no_op_wake_count_bucket: status.no_op_wake_count_bucket.clone(),
            degraded_wake_count_bucket: status.degraded_wake_count_bucket.clone(),
            successful_wake_count_bucket: status.successful_wake_count_bucket.clone(),
            status,
            latest_cycle: read.native_scheduler_host_cycles.last().cloned(),
            session_bound: true,
            startup_auto_run: false,
            os_service: false,
            automatic_llm_calls: false,
            response_execution_started: false,
            generated_at: Timestamp::now(),
        };
        health.validate().map_err(contract_error)?;
        Ok(health)
    }

    pub fn health(
        &self,
        read: &ReadOnlyCommandState,
    ) -> CommandResult<NativeSchedulerHostHealthSummary> {
        let status = self.status(read)?;
        let latest_cycle = self.cycles.last().cloned();
        let health = NativeSchedulerHostHealthSummary {
            latest_wake_reason: status.latest_wake_reason.clone(),
            watchdog_state: status.watchdog_state.clone(),
            shutdown_state: status.shutdown_state.clone(),
            delayed_wake_count_bucket: status.degraded_wake_count_bucket.clone(),
            no_op_wake_count_bucket: status.no_op_wake_count_bucket.clone(),
            degraded_wake_count_bucket: status.degraded_wake_count_bucket.clone(),
            successful_wake_count_bucket: status.successful_wake_count_bucket.clone(),
            status,
            latest_cycle,
            session_bound: true,
            startup_auto_run: false,
            os_service: false,
            automatic_llm_calls: false,
            response_execution_started: false,
            generated_at: Timestamp::now(),
        };
        health.validate().map_err(contract_error)?;
        Ok(health)
    }

    pub fn wait_plan(
        &self,
        read: &ReadOnlyCommandState,
        current_elapsed_millis: u64,
    ) -> CommandResult<NativeSchedulerHostWaitPlan> {
        native_scheduler_host_wait_plan(read, &self.status(read)?, current_elapsed_millis)
    }

    pub fn record_timer_runtime_update(
        &mut self,
        read: &mut ReadOnlyCommandState,
        update: NativeSchedulerHostTimerRuntimeUpdate,
    ) -> CommandResult<()> {
        refresh_status_from_read(read, &self.cycles, &self.audit_entries, &mut self.status);
        if let Some(lifecycle_state) = update.lifecycle_state {
            self.status.lifecycle_state = lifecycle_state;
        }
        self.status.timer_task_active = update.timer_task_active;
        self.status.task_ownership_state = update.task_ownership_state;
        self.status.current_wait_state = update.current_wait_state;
        self.status.pending_wake = update.pending_wake;
        self.status.cancellation_state = update.cancellation_state;
        self.status.join_state = update.join_state;
        self.status.join_timeout_category = update.join_timeout_category;
        self.status.shutdown_cleanup_status = update.shutdown_cleanup_status;
        if let Some(wake_state) = update.wake_state {
            self.status.wake_state = wake_state;
        }
        if let Some(health_state) = update.health_state {
            self.status.health_state = health_state;
        }
        if let Some(watchdog_state) = update.watchdog_state {
            self.status.watchdog_state = watchdog_state;
        }
        if let Some(shutdown_state) = update.shutdown_state {
            self.status.shutdown_state = shutdown_state;
        }
        if update.latest_wake_reason.is_some() {
            self.status.latest_wake_reason = update.latest_wake_reason;
        }
        if update.degraded_reason.is_some() {
            self.status.degraded_reason = update.degraded_reason;
        }
        if !self.status.timer_task_active
            && !matches!(
                self.status.lifecycle_state,
                NativeSchedulerHostLifecycleState::Running
                    | NativeSchedulerHostLifecycleState::Paused
            )
        {
            self.status.host_task_owned = false;
        }
        self.status.generated_at = Timestamp::now();
        self.status.validate().map_err(contract_error)?;
        self.publish_status()?;
        self.sync_read_state(read);
        Ok(())
    }

    pub fn preview_start(
        &self,
        read: &ReadOnlyCommandState,
    ) -> CommandResult<NativeSchedulerHostStartPreview> {
        let scheduler_summary = NativeSchedulerController::summary_from_read_state(read)?;
        let (start_allowed, blocked_reason) = start_eligibility(&scheduler_summary.status);
        let preview = NativeSchedulerHostStartPreview {
            status: self.status(read)?,
            start_allowed,
            blocked_reason,
            task_created: false,
            tick_invoked: false,
            provider_direct_calls: false,
            automatic_llm_calls: false,
            response_execution_started: false,
            boundary_summary_redacted:
                "preview_only_explicit_start_required_session_bound_no_startup_auto_run".to_string(),
        };
        preview.validate().map_err(contract_error)?;
        Ok(preview)
    }

    pub fn apply_action(
        &mut self,
        read: &mut ReadOnlyCommandState,
        scheduler: &mut NativeSchedulerController,
        runtime: &mut NativeSamplerRuntime,
        request: NativeSchedulerHostActionRequest,
    ) -> CommandResult<NativeSchedulerHostActionResult> {
        request.validate().map_err(contract_error)?;
        scheduler.reconcile(read)?;
        scheduler.sync_read_state(read);

        if request.action == NativeSchedulerHostAction::PreviewStart {
            return Err(CoreError::validation_failure(
                "use the native scheduler host preview command for preview-only actions",
            ));
        }

        refresh_status_from_read(read, &self.cycles, &self.audit_entries, &mut self.status);
        let mut task_created = false;
        let mut tick_invoked = false;
        let mut latest_host_cycle = None;
        let mut emitted_topics = vec![NATIVE_SCHEDULER_HOST_STATUS.to_string()];

        match request.action {
            NativeSchedulerHostAction::Start => {
                if self.status.lifecycle_state == NativeSchedulerHostLifecycleState::Running {
                    self.status.latest_wake_reason = Some(request.wake_reason.clone());
                } else {
                    let summary = scheduler.summary(read)?;
                    let (allowed, blocked) = start_eligibility(&summary.status);
                    if !allowed {
                        return Err(CoreError::new(
                            ErrorCode::InvalidRequest,
                            "native scheduler host start requirements are not met",
                        )
                        .with_severity(ErrorSeverity::Warning)
                        .with_redacted_details(json!({
                            "blocked_reason": blocked.unwrap_or_else(|| "not_eligible".to_string())
                        })));
                    }
                    self.status.lifecycle_state = NativeSchedulerHostLifecycleState::Running;
                    self.status.health_state = NativeSchedulerHostHealthState::Idle;
                    self.status.wake_state = NativeSchedulerHostWakeState::Waiting;
                    self.status.watchdog_state = NativeSchedulerHostWatchdogState::Idle;
                    self.status.shutdown_state = NativeSchedulerHostShutdownState::None;
                    self.status.degraded_reason = None;
                    self.status.host_task_owned = true;
                    self.status.singleton_owner = true;
                    self.status.timer_task_active = true;
                    self.status.task_ownership_state = "owned".to_string();
                    self.status.current_wait_state = "starting".to_string();
                    self.status.pending_wake = true;
                    self.status.cancellation_state = "none".to_string();
                    self.status.join_state = "not_joining".to_string();
                    self.status.join_timeout_category = None;
                    self.status.shutdown_cleanup_status = "not_requested".to_string();
                    self.status.latest_wake_reason = Some(request.wake_reason.clone());
                    self.status.restart_count_bucket = "none".to_string();
                    task_created = true;
                    emitted_topics.push(NATIVE_SCHEDULER_HOST_STARTED.to_string());
                    emitted_topics.push(NATIVE_SCHEDULER_HOST_TASK_STARTED.to_string());
                }
            }
            NativeSchedulerHostAction::Pause => {
                ensure_running_or_paused("pause", &self.status.lifecycle_state)?;
                self.status.lifecycle_state = NativeSchedulerHostLifecycleState::Paused;
                self.status.health_state = NativeSchedulerHostHealthState::Paused;
                self.status.wake_state = NativeSchedulerHostWakeState::Cancelled;
                self.status.watchdog_state = NativeSchedulerHostWatchdogState::Paused;
                self.status.current_wait_state = "paused".to_string();
                self.status.pending_wake = true;
                self.status.latest_wake_reason = Some(request.wake_reason.clone());
                emitted_topics.push(NATIVE_SCHEDULER_HOST_PAUSED.to_string());
                emitted_topics.push(NATIVE_SCHEDULER_HOST_TASK_PAUSED.to_string());
            }
            NativeSchedulerHostAction::Resume => {
                if self.status.lifecycle_state != NativeSchedulerHostLifecycleState::Paused {
                    return Err(invalid_host_transition(
                        "resume",
                        &self.status.lifecycle_state,
                    ));
                }
                self.status.lifecycle_state = NativeSchedulerHostLifecycleState::Running;
                self.status.health_state = NativeSchedulerHostHealthState::Idle;
                self.status.wake_state = NativeSchedulerHostWakeState::Waiting;
                self.status.watchdog_state = NativeSchedulerHostWatchdogState::Idle;
                self.status.current_wait_state = "waiting".to_string();
                self.status.pending_wake = true;
                self.status.latest_wake_reason = Some(request.wake_reason.clone());
                emitted_topics.push(NATIVE_SCHEDULER_HOST_RESUMED.to_string());
                emitted_topics.push(NATIVE_SCHEDULER_HOST_TASK_RESUMED.to_string());
            }
            NativeSchedulerHostAction::WakeNow => {
                ensure_running("wake_now", &self.status.lifecycle_state)?;
                let cycle = self.invoke_one_scheduler_tick(
                    read,
                    scheduler,
                    runtime,
                    request.wake_reason.clone(),
                )?;
                tick_invoked = cycle.tick_invoked;
                latest_host_cycle = Some(cycle);
                emitted_topics.push(NATIVE_SCHEDULER_HOST_WAKE.to_string());
                emitted_topics.push(NATIVE_SCHEDULER_HOST_TASK_WAKE.to_string());
            }
            NativeSchedulerHostAction::Stop => {
                if matches!(
                    self.status.lifecycle_state,
                    NativeSchedulerHostLifecycleState::Stopped
                        | NativeSchedulerHostLifecycleState::Disabled
                ) {
                    self.status.lifecycle_state = NativeSchedulerHostLifecycleState::Stopped;
                } else {
                    self.status.lifecycle_state = NativeSchedulerHostLifecycleState::Stopped;
                    self.status.health_state = NativeSchedulerHostHealthState::Stopped;
                    self.status.wake_state = NativeSchedulerHostWakeState::Cancelled;
                    self.status.watchdog_state = NativeSchedulerHostWatchdogState::Stopped;
                    self.status.shutdown_state = NativeSchedulerHostShutdownState::Completed;
                    self.status.host_task_owned = false;
                    self.status.timer_task_active = false;
                    self.status.task_ownership_state = "released".to_string();
                    self.status.current_wait_state = "stopped".to_string();
                    self.status.pending_wake = false;
                    self.status.cancellation_state = "cancelled".to_string();
                    self.status.join_state = "joined".to_string();
                    self.status.join_timeout_category = None;
                    self.status.shutdown_cleanup_status = "completed".to_string();
                    self.status.latest_wake_reason = Some(request.wake_reason.clone());
                }
                emitted_topics.push(NATIVE_SCHEDULER_HOST_STOPPED.to_string());
                emitted_topics.push(NATIVE_SCHEDULER_HOST_TASK_STOPPED.to_string());
                emitted_topics.push(NATIVE_SCHEDULER_HOST_TASK_JOINED.to_string());
            }
            NativeSchedulerHostAction::RefreshStatus => {
                self.status.latest_wake_reason = Some(request.wake_reason.clone());
            }
            NativeSchedulerHostAction::ClearInactiveState => {
                if self.status.lifecycle_state == NativeSchedulerHostLifecycleState::Running {
                    return Err(invalid_host_transition(
                        "clear_inactive_state",
                        &self.status.lifecycle_state,
                    ));
                }
                self.cycles.clear();
                self.audit_entries.clear();
                self.status = default_native_scheduler_host_status();
                self.status.lifecycle_state = NativeSchedulerHostLifecycleState::Ready;
                self.status.latest_wake_reason = Some(request.wake_reason.clone());
            }
            NativeSchedulerHostAction::PreviewStart => unreachable!(),
        }

        refresh_status_from_read(read, &self.cycles, &self.audit_entries, &mut self.status);
        if self.status.lifecycle_state == NativeSchedulerHostLifecycleState::Running {
            self.status.host_task_owned = true;
            self.status.singleton_owner = true;
        }
        if self.status.lifecycle_state == NativeSchedulerHostLifecycleState::Stopped {
            self.status.host_task_owned = false;
            self.status.timer_task_active = false;
        }
        let audit_entry = host_audit_entry(&request, &self.status.lifecycle_state);
        self.audit_entries.push(audit_entry.clone());
        bound_host_audits(&mut self.audit_entries);
        self.status.audit_refs = self
            .audit_entries
            .iter()
            .rev()
            .take(MAX_NATIVE_SCHEDULER_REFS)
            .map(|entry| entry.audit_id.clone())
            .collect();
        self.status.generated_at = Timestamp::now();
        self.status.validate().map_err(contract_error)?;
        audit_entry.validate().map_err(contract_error)?;

        if self.status.lifecycle_state == NativeSchedulerHostLifecycleState::Failed
            || self.status.lifecycle_state == NativeSchedulerHostLifecycleState::Degraded
        {
            emitted_topics.push(NATIVE_SCHEDULER_HOST_FAILED.to_string());
            emitted_topics.push(NATIVE_SCHEDULER_HOST_TASK_FAILED.to_string());
        }
        emitted_topics.push(AUDIT_NATIVE_SCHEDULER_HOST.to_string());
        publish_unique_topics(&mut emitted_topics);
        self.publish_status()?;
        self.publish_action_topic(&request.action)?;
        self.publish_audit(&audit_entry)?;
        self.sync_read_state(read);

        let result = NativeSchedulerHostActionResult {
            status: self.status.clone(),
            latest_host_cycle,
            audit_entry,
            emitted_topics,
            preview_only: false,
            task_created,
            tick_invoked,
            provider_direct_calls: false,
            automatic_llm_calls: false,
            response_execution_started: false,
        };
        result.validate().map_err(contract_error)?;
        Ok(result)
    }

    fn invoke_one_scheduler_tick(
        &mut self,
        read: &mut ReadOnlyCommandState,
        scheduler: &mut NativeSchedulerController,
        runtime: &mut NativeSamplerRuntime,
        wake_reason: NativeSchedulerHostWakeReason,
    ) -> CommandResult<NativeSchedulerHostCycleSummary> {
        let host_cycle_id = NativeSchedulerCycleId::new_v4();
        if read.native_scheduler_cycle_gate_active {
            let cycle = self.host_cycle(HostCycleDraft {
                host_cycle_id,
                cycle_origin: NativeSchedulerCycleOrigin::Autonomous,
                wake_reason,
                scheduler_cycle_ref: None,
                tick_invoked: false,
                no_due_work: true,
                degraded: true,
                cancelled: false,
                cycle_gate_busy: true,
            })?;
            self.store_cycle(cycle.clone());
            self.status.health_state = NativeSchedulerHostHealthState::Delayed;
            self.status.watchdog_state = NativeSchedulerHostWatchdogState::Delayed;
            self.status.wake_state = NativeSchedulerHostWakeState::Waiting;
            self.status.degraded_reason = Some("cycle_gate_busy".to_string());
            return Ok(cycle);
        }

        read.native_scheduler_cycle_gate_active = true;
        let request = host_tick_request(read, &wake_reason);
        let tick_result = scheduler.tick(read, runtime, request);
        read.native_scheduler_cycle_gate_active = false;
        runtime.sync_read_state(read);
        scheduler.sync_read_state(read);

        let (scheduler_cycle_ref, no_due_work, degraded, cancelled) = match tick_result {
            Ok(cycle) => {
                let no_due = cycle.cycle_state == NativeSchedulerCycleState::Skipped
                    && cycle.skip_reason.as_deref() == Some("no_due_samplers");
                let cancelled = cycle.cycle_state == NativeSchedulerCycleState::Skipped
                    && cycle.skip_reason.as_deref() == Some("cancellation_requested");
                (Some(cycle.cycle_id), no_due, false, cancelled)
            }
            Err(_) => {
                self.status.lifecycle_state = NativeSchedulerHostLifecycleState::Degraded;
                self.status.health_state = NativeSchedulerHostHealthState::Degraded;
                self.status.watchdog_state = NativeSchedulerHostWatchdogState::Degraded;
                self.status.degraded_reason = Some("scheduler_tick_failed".to_string());
                (None, false, true, false)
            }
        };

        self.status.latest_wake_reason = Some(wake_reason.clone());
        self.status.wake_state = if cancelled {
            NativeSchedulerHostWakeState::Cancelled
        } else {
            NativeSchedulerHostWakeState::Woken
        };
        self.status.last_wake_bucket = Some("current_session".to_string());
        self.status.last_tick_ref = scheduler_cycle_ref.clone();
        self.status.latest_cycle_ref = scheduler_cycle_ref.clone();
        if !degraded && !cancelled {
            self.status.health_state = if no_due_work {
                NativeSchedulerHostHealthState::Idle
            } else {
                NativeSchedulerHostHealthState::Healthy
            };
            self.status.watchdog_state = if no_due_work {
                NativeSchedulerHostWatchdogState::Idle
            } else {
                NativeSchedulerHostWatchdogState::Healthy
            };
            self.status.degraded_reason = None;
        }

        let cycle = self.host_cycle(HostCycleDraft {
            host_cycle_id,
            cycle_origin: NativeSchedulerCycleOrigin::Autonomous,
            wake_reason,
            scheduler_cycle_ref,
            tick_invoked: true,
            no_due_work,
            degraded,
            cancelled,
            cycle_gate_busy: false,
        })?;
        self.store_cycle(cycle.clone());
        Ok(cycle)
    }

    fn host_cycle(&self, draft: HostCycleDraft) -> CommandResult<NativeSchedulerHostCycleSummary> {
        let cycle = NativeSchedulerHostCycleSummary {
            host_cycle_id: draft.host_cycle_id,
            orchestrator_id: HOST_ORCHESTRATOR_ID.to_string(),
            controller_id: CONTROLLER_ID.to_string(),
            cycle_origin: draft.cycle_origin,
            wake_reason: draft.wake_reason,
            lifecycle_state: self.status.lifecycle_state.clone(),
            health_state: self.status.health_state.clone(),
            wake_state: self.status.wake_state.clone(),
            scheduler_cycle_ref: draft.scheduler_cycle_ref,
            tick_invoked: draft.tick_invoked,
            no_due_work: draft.no_due_work,
            degraded: draft.degraded,
            cancelled: draft.cancelled,
            cycle_gate_busy: draft.cycle_gate_busy,
            emitted_topics: vec![NATIVE_SCHEDULER_HOST_WAKE.to_string()],
            audit_refs: self
                .audit_entries
                .iter()
                .rev()
                .take(MAX_NATIVE_SCHEDULER_REFS)
                .map(|entry| entry.audit_id.clone())
                .collect(),
            provenance_id: HOST_PROVENANCE_ID.to_string(),
            redaction_status: RedactionStatus::Redacted,
            provider_direct_calls: false,
            automatic_llm_calls: false,
            response_execution_started: false,
            generated_at: Timestamp::now(),
        };
        cycle.validate().map_err(contract_error)?;
        Ok(cycle)
    }

    fn store_cycle(&mut self, cycle: NativeSchedulerHostCycleSummary) {
        self.cycles.push(cycle);
        if self.cycles.len() > MAX_NATIVE_SCHEDULER_CYCLES {
            self.cycles
                .drain(0..self.cycles.len() - MAX_NATIVE_SCHEDULER_CYCLES);
        }
    }

    fn publish_status(&mut self) -> CommandResult<()> {
        let status = self.status.clone();
        self.publish(
            NATIVE_SCHEDULER_HOST_STATUS,
            &status,
            "bounded native scheduler host status",
        )
    }

    fn publish_audit(&mut self, audit: &NativeSchedulerHostAuditEntry) -> CommandResult<()> {
        self.publish(
            AUDIT_NATIVE_SCHEDULER_HOST,
            audit,
            "bounded native scheduler host audit",
        )
    }

    fn publish_action_topic(&mut self, action: &NativeSchedulerHostAction) -> CommandResult<()> {
        let topics = match action {
            NativeSchedulerHostAction::Start => vec![
                NATIVE_SCHEDULER_HOST_STARTED,
                NATIVE_SCHEDULER_HOST_TASK_STARTED,
            ],
            NativeSchedulerHostAction::Pause => {
                vec![
                    NATIVE_SCHEDULER_HOST_PAUSED,
                    NATIVE_SCHEDULER_HOST_TASK_PAUSED,
                ]
            }
            NativeSchedulerHostAction::Resume => vec![
                NATIVE_SCHEDULER_HOST_RESUMED,
                NATIVE_SCHEDULER_HOST_TASK_RESUMED,
            ],
            NativeSchedulerHostAction::WakeNow => {
                vec![NATIVE_SCHEDULER_HOST_WAKE, NATIVE_SCHEDULER_HOST_TASK_WAKE]
            }
            NativeSchedulerHostAction::Stop => vec![
                NATIVE_SCHEDULER_HOST_STOPPED,
                NATIVE_SCHEDULER_HOST_TASK_STOPPED,
                NATIVE_SCHEDULER_HOST_TASK_JOINED,
            ],
            NativeSchedulerHostAction::RefreshStatus
            | NativeSchedulerHostAction::ClearInactiveState => Vec::new(),
            NativeSchedulerHostAction::PreviewStart => Vec::new(),
        };
        for topic in topics {
            let status = self.status.clone();
            self.publish(topic, &status, "bounded native scheduler host lifecycle")?;
        }
        Ok(())
    }

    fn publish<T: serde::Serialize>(
        &mut self,
        topic: &str,
        payload: &T,
        summary: &str,
    ) -> CommandResult<()> {
        let mut event = EventEnvelope::new(
            EventType::new(topic).map_err(contract_error)?,
            SchemaVersion::new(1, 0, 0),
            self.producer_plugin.clone(),
            TraceContext::new_root(),
        );
        event.privacy_class = PrivacyClass::Internal;
        event.quality_score = QualityScore::new(0.7).map_err(contract_error)?;
        event.payload = serde_json::to_value(payload).map_err(internal_error)?;
        self.event_bus
            .publish(
                TopicName::new(topic).map_err(contract_error)?,
                event,
                PublishOptions::new(summary),
            )
            .map_err(internal_error)?;
        Ok(())
    }
}

pub fn default_native_scheduler_host_status() -> NativeSchedulerHostStatus {
    NativeSchedulerHostStatus {
        orchestrator_id: HOST_ORCHESTRATOR_ID.to_string(),
        controller_id: CONTROLLER_ID.to_string(),
        lifecycle_state: NativeSchedulerHostLifecycleState::Disabled,
        health_state: NativeSchedulerHostHealthState::Stopped,
        wake_state: NativeSchedulerHostWakeState::Idle,
        latest_wake_reason: None,
        enabled_sampler_count_bucket: "none".to_string(),
        eligible_sampler_count_bucket: "none".to_string(),
        next_wake_bucket: "not_enabled".to_string(),
        last_wake_bucket: None,
        last_tick_ref: None,
        latest_cycle_ref: None,
        successful_wake_count_bucket: "none".to_string(),
        no_op_wake_count_bucket: "none".to_string(),
        degraded_wake_count_bucket: "none".to_string(),
        cancelled_wake_count_bucket: "none".to_string(),
        restart_count_bucket: "none".to_string(),
        manual_cycle_count_bucket: "none".to_string(),
        autonomous_cycle_count_bucket: "none".to_string(),
        watchdog_state: NativeSchedulerHostWatchdogState::Stopped,
        shutdown_state: NativeSchedulerHostShutdownState::Completed,
        degraded_reason: None,
        timer_task_active: false,
        task_ownership_state: "released".to_string(),
        current_wait_state: "inactive".to_string(),
        pending_wake: false,
        cancellation_state: "none".to_string(),
        join_state: "joined".to_string(),
        join_timeout_category: None,
        shutdown_cleanup_status: "completed".to_string(),
        audit_refs: Vec::new(),
        provenance_id: HOST_PROVENANCE_ID.to_string(),
        redaction_status: RedactionStatus::Redacted,
        host_task_owned: false,
        singleton_owner: true,
        startup_auto_started: false,
        os_service_started: false,
        provider_direct_calls: false,
        automatic_llm_calls: false,
        response_execution_started: false,
        generated_at: Timestamp::now(),
    }
}

fn refresh_status_from_read(
    read: &ReadOnlyCommandState,
    cycles: &[NativeSchedulerHostCycleSummary],
    audits: &[NativeSchedulerHostAuditEntry],
    status: &mut NativeSchedulerHostStatus,
) {
    let enabled = read
        .native_sampler_schedule_statuses
        .iter()
        .filter(|schedule| schedule.contract.schedule_enabled)
        .count() as u32;
    let eligible = read
        .native_sampler_schedule_statuses
        .iter()
        .filter(|schedule| schedule.schedule_eligible && schedule.contract.schedule_enabled)
        .count() as u32;
    status.enabled_sampler_count_bucket = count_bucket(enabled);
    status.eligible_sampler_count_bucket = count_bucket(eligible);
    status.next_wake_bucket = next_wake_bucket(read, status);
    status.latest_cycle_ref = cycles
        .iter()
        .rev()
        .find_map(|cycle| cycle.scheduler_cycle_ref.clone())
        .or_else(|| {
            read.native_scheduler_cycles
                .last()
                .map(|cycle| cycle.cycle_id.clone())
        });
    status.last_tick_ref = status.latest_cycle_ref.clone();
    status.successful_wake_count_bucket = count_bucket(
        cycles
            .iter()
            .filter(|cycle| cycle.tick_invoked && !cycle.degraded && !cycle.cancelled)
            .count() as u32,
    );
    status.no_op_wake_count_bucket =
        count_bucket(cycles.iter().filter(|cycle| cycle.no_due_work).count() as u32);
    status.degraded_wake_count_bucket =
        count_bucket(cycles.iter().filter(|cycle| cycle.degraded).count() as u32);
    status.cancelled_wake_count_bucket =
        count_bucket(cycles.iter().filter(|cycle| cycle.cancelled).count() as u32);
    let autonomous_count = cycles
        .iter()
        .filter(|cycle| cycle.cycle_origin == NativeSchedulerCycleOrigin::Autonomous)
        .count() as u32;
    status.autonomous_cycle_count_bucket = count_bucket(autonomous_count);
    status.manual_cycle_count_bucket =
        count_bucket((read.native_scheduler_cycles.len() as u32).saturating_sub(autonomous_count));
    status.audit_refs = audits
        .iter()
        .rev()
        .take(MAX_NATIVE_SCHEDULER_REFS)
        .map(|entry| entry.audit_id.clone())
        .collect();
    status.generated_at = Timestamp::now();

    if read
        .native_sampler_schedule_statuses
        .iter()
        .any(|schedule| schedule.permission_state == NativePermissionState::Revoked)
        && eligible == 0
        && status.host_task_owned
    {
        status.lifecycle_state = NativeSchedulerHostLifecycleState::Revoked;
        status.health_state = NativeSchedulerHostHealthState::Degraded;
        status.watchdog_state = NativeSchedulerHostWatchdogState::Degraded;
        status.wake_state = NativeSchedulerHostWakeState::Cancelled;
        status.degraded_reason = Some("authorization_revoked".to_string());
        status.host_task_owned = false;
        status.timer_task_active = false;
        status.task_ownership_state = "revoked".to_string();
        status.current_wait_state = "revoked".to_string();
        status.pending_wake = false;
        status.cancellation_state = "revoked".to_string();
        status.join_state = "joined".to_string();
        status.shutdown_cleanup_status = "completed".to_string();
    }
}

fn start_eligibility(status: &sentinel_contracts::NativeSchedulerStatus) -> (bool, Option<String>) {
    if !status.scheduling_loop_active {
        return (false, Some("scheduler_controller_not_running".to_string()));
    }
    if status.enabled_schedule_count == 0 {
        return (false, Some("periodic_intent_required".to_string()));
    }
    if status.eligible_schedule_count == 0 {
        return (false, Some("eligible_sampler_required".to_string()));
    }
    (true, None)
}

fn host_tick_request(
    read: &ReadOnlyCommandState,
    wake_reason: &NativeSchedulerHostWakeReason,
) -> NativeSchedulerTickRequest {
    let next_due = read
        .native_scheduler_next_due_monotonic_millis
        .values()
        .copied()
        .min();
    let minimum_next = read
        .native_scheduler_last_tick_monotonic_millis
        .map(|last| last.saturating_add(MIN_NATIVE_SCHEDULER_TICK_MILLIS))
        .unwrap_or(0);
    let monotonic_elapsed_millis = next_due
        .map(|due| due.max(minimum_next))
        .unwrap_or(minimum_next);
    NativeSchedulerTickRequest {
        monotonic_elapsed_millis,
        max_samplers_per_tick: MAX_NATIVE_SAMPLERS_PER_TICK,
        global_concurrency_limit: MAX_NATIVE_SAMPLERS_PER_TICK,
        per_category_concurrency_limit: 1,
        provider_timeout_millis: 5_000,
        execution_timeout_millis: 5_000,
        global_cycle_timeout_millis: 30_000,
        retry_delay_millis: MIN_NATIVE_SCHEDULER_RETRY_DELAY_MILLIS,
        event_bus_backlog_count: 0,
        dag_backlog_count: 0,
        cancellation_requested: matches!(
            wake_reason,
            NativeSchedulerHostWakeReason::Cancellation
                | NativeSchedulerHostWakeReason::StopRequested
                | NativeSchedulerHostWakeReason::ShutdownRequested
                | NativeSchedulerHostWakeReason::Revoked
        ),
        reason_redacted: "native_scheduler_host_wake".to_string(),
    }
}

fn next_wake_bucket(read: &ReadOnlyCommandState, status: &NativeSchedulerHostStatus) -> String {
    if status.lifecycle_state != NativeSchedulerHostLifecycleState::Running {
        return "not_running".to_string();
    }
    let enabled_schedules = read
        .native_sampler_schedule_statuses
        .iter()
        .filter(|schedule| schedule.contract.schedule_enabled && schedule.schedule_eligible)
        .collect::<Vec<_>>();
    if enabled_schedules.is_empty() {
        return "no_eligible".to_string();
    }
    if enabled_schedules.iter().any(|schedule| {
        !read
            .native_scheduler_next_due_monotonic_millis
            .contains_key(&schedule.contract.sampler_id)
    }) {
        return "due_now".to_string();
    }
    let Some(min_due) = enabled_schedules
        .iter()
        .filter_map(|schedule| {
            read.native_scheduler_next_due_monotonic_millis
                .get(&schedule.contract.sampler_id)
                .copied()
        })
        .min()
    else {
        return MAX_IDLE_WAKE_BUCKET.to_string();
    };
    let minimum_next = read
        .native_scheduler_last_tick_monotonic_millis
        .map(|last| last.saturating_add(MIN_NATIVE_SCHEDULER_TICK_MILLIS))
        .unwrap_or(0);
    if min_due <= minimum_next {
        "due_soon".to_string()
    } else {
        MAX_IDLE_WAKE_BUCKET.to_string()
    }
}

pub fn native_scheduler_host_wait_plan(
    read: &ReadOnlyCommandState,
    status: &NativeSchedulerHostStatus,
    current_elapsed_millis: u64,
) -> CommandResult<NativeSchedulerHostWaitPlan> {
    let idle = |wait_state: &str| NativeSchedulerHostWaitPlan {
        wait_millis: NATIVE_SCHEDULER_HOST_MAX_RECONCILE_SLEEP_MILLIS,
        wake_reason: NativeSchedulerHostWakeReason::StatusReconciliation,
        wait_state: wait_state.to_string(),
        eligible_sampler_count: 0,
        due_now: false,
    };

    if status.lifecycle_state == NativeSchedulerHostLifecycleState::Paused {
        let plan = idle("paused");
        plan.validate()?;
        return Ok(plan);
    }
    if status.lifecycle_state != NativeSchedulerHostLifecycleState::Running
        || read.native_scheduler_controller_state != NativeSchedulerControllerState::Running
        || read.native_scheduler_graceful_shutdown_requested
        || read.native_scheduler_cycle_gate_active
    {
        let plan = idle("reconciliation_wait");
        plan.validate()?;
        return Ok(plan);
    }

    let eligible_schedules = read
        .native_sampler_schedule_statuses
        .iter()
        .filter(|schedule| schedule.contract.schedule_enabled)
        .filter(|schedule| schedule.schedule_eligible)
        .filter(|schedule| schedule.permission_state == NativePermissionState::GrantedSession)
        .filter(|schedule| {
            matches!(
                schedule.runtime_state,
                NativeSamplerRuntimeState::Active | NativeSamplerRuntimeState::Idle
            )
        })
        .collect::<Vec<_>>();
    if eligible_schedules.is_empty() {
        let plan = idle("idle_no_eligible");
        plan.validate()?;
        return Ok(plan);
    }

    let earliest_due = eligible_schedules
        .iter()
        .map(|schedule| {
            read.native_scheduler_next_due_monotonic_millis
                .get(&schedule.contract.sampler_id)
                .copied()
                .unwrap_or(0)
        })
        .min()
        .unwrap_or(0);
    let minimum_next = read
        .native_scheduler_last_tick_monotonic_millis
        .map(|last| last.saturating_add(MIN_NATIVE_SCHEDULER_TICK_MILLIS))
        .unwrap_or(0);
    let next_due = earliest_due.max(minimum_next);
    let (wait_millis, due_now) = if next_due <= current_elapsed_millis {
        (0, true)
    } else {
        let wait = next_due.saturating_sub(current_elapsed_millis);
        (wait.max(MIN_NATIVE_SCHEDULER_TICK_MILLIS), false)
    };
    let plan = NativeSchedulerHostWaitPlan {
        wait_millis,
        wake_reason: if due_now {
            NativeSchedulerHostWakeReason::SamplerDue
        } else {
            NativeSchedulerHostWakeReason::StatusReconciliation
        },
        wait_state: if due_now {
            "due_now".to_string()
        } else {
            "timer_sleep_until_due".to_string()
        },
        eligible_sampler_count: eligible_schedules.len() as u32,
        due_now,
    };
    plan.validate()?;
    Ok(plan)
}

impl NativeSchedulerHostWaitPlan {
    fn validate(&self) -> CommandResult<()> {
        if self.wait_millis > 3_600_000
            || self.eligible_sampler_count > MAX_NATIVE_SAMPLERS_PER_TICK
        {
            return Err(CoreError::validation_failure(
                "native scheduler host wait plan exceeded bounds",
            ));
        }
        if self.wait_state.trim().is_empty() || self.wait_state.len() > 80 {
            return Err(CoreError::validation_failure(
                "native scheduler host wait plan state is unsafe",
            ));
        }
        Ok(())
    }
}

fn count_bucket(value: u32) -> String {
    match value {
        0 => "none",
        1 => "one",
        2..=3 => "few",
        4..=10 => "several",
        _ => "many",
    }
    .to_string()
}

fn host_audit_entry(
    request: &NativeSchedulerHostActionRequest,
    lifecycle_state: &NativeSchedulerHostLifecycleState,
) -> NativeSchedulerHostAuditEntry {
    NativeSchedulerHostAuditEntry {
        audit_id: AuditId::new_v4(),
        action: request.action.clone(),
        resulting_lifecycle_state: lifecycle_state.clone(),
        wake_reason: Some(request.wake_reason.clone()),
        time_bucket: CURRENT_SESSION_BUCKET.to_string(),
        provenance_id: HOST_PROVENANCE_ID.to_string(),
        summary_redacted: format!("native_scheduler_host_action_{:?}", request.action)
            .to_ascii_lowercase(),
    }
}

fn bound_host_audits(values: &mut Vec<NativeSchedulerHostAuditEntry>) {
    if values.len() > MAX_NATIVE_SCHEDULER_REFS {
        values.drain(0..values.len() - MAX_NATIVE_SCHEDULER_REFS);
    }
}

fn publish_unique_topics(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn ensure_running(action: &str, state: &NativeSchedulerHostLifecycleState) -> CommandResult<()> {
    if *state == NativeSchedulerHostLifecycleState::Running {
        return Ok(());
    }
    Err(invalid_host_transition(action, state))
}

fn ensure_running_or_paused(
    action: &str,
    state: &NativeSchedulerHostLifecycleState,
) -> CommandResult<()> {
    if matches!(
        state,
        NativeSchedulerHostLifecycleState::Running | NativeSchedulerHostLifecycleState::Paused
    ) {
        return Ok(());
    }
    Err(invalid_host_transition(action, state))
}

fn invalid_host_transition(action: &str, state: &NativeSchedulerHostLifecycleState) -> CoreError {
    CoreError::new(
        ErrorCode::InvalidRequest,
        "native scheduler host state transition is not allowed",
    )
    .with_severity(ErrorSeverity::Warning)
    .with_redacted_details(json!({ "action": action, "host_state": state }))
}

fn contract_error(error: impl std::fmt::Display) -> CoreError {
    CoreError::validation_failure("native scheduler host contract validation failed")
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn internal_error(error: impl std::fmt::Display) -> CoreError {
    CoreError::new(
        ErrorCode::InternalError,
        "native scheduler host operation failed",
    )
    .with_severity(ErrorSeverity::Error)
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorized_native_permissions::AuthorizedNativePermissionRuntime;
    use sentinel_contracts::{
        NativePermissionAction, NativePermissionActionRequest, NativeSamplerRuntimeAction,
        NativeSamplerRuntimeActionRequest, NativeScheduleIntervalBucket,
        NativeScheduleRetryBudgetBucket, NativeScheduleTimeoutBucket, NativeSchedulerAction,
        NativeSchedulerActionRequest,
    };

    fn grant(read: &mut ReadOnlyCommandState, capability_id: &str) {
        let mut permissions = AuthorizedNativePermissionRuntime::from_read_state(read);
        permissions
            .apply_action(NativePermissionActionRequest {
                capability_id: capability_id.to_string(),
                action: NativePermissionAction::GrantAuthorization,
                explicit_user_action: true,
                reason_redacted: "authorize native scheduler host test".to_string(),
            })
            .expect("grant");
        permissions.sync_read_state(read);
    }

    fn activate(read: &mut ReadOnlyCommandState, sampler_id: &str) {
        let mut runtime = NativeSamplerRuntime::from_read_state(read);
        runtime
            .apply_action(
                read,
                NativeSamplerRuntimeActionRequest {
                    sampler_id: sampler_id.to_string(),
                    action: NativeSamplerRuntimeAction::Activate,
                    explicit_user_action: true,
                    enable_interval_sampling: false,
                    max_records_per_sample: 128,
                    max_bytes_per_sample: 65_536,
                    timeout_millis: 5_000,
                    reason_redacted: "activate native scheduler host test".to_string(),
                },
            )
            .expect("activate");
        runtime.sync_read_state(read);
    }

    fn enable_schedule(read: &mut ReadOnlyCommandState, sampler_id: &str) {
        let mut scheduler = NativeSchedulerController::from_read_state(read);
        scheduler
            .apply_action(
                read,
                NativeSchedulerActionRequest {
                    sampler_id: Some(sampler_id.to_string()),
                    action: NativeSchedulerAction::EnableSampler,
                    explicit_user_action: true,
                    interval_bucket: NativeScheduleIntervalBucket::FiveMinutes,
                    timeout_bucket: NativeScheduleTimeoutBucket::FiveSeconds,
                    retry_budget_bucket: NativeScheduleRetryBudgetBucket::One,
                    max_records: 128,
                    max_bytes: 65_536,
                    reason_redacted: "enable native scheduler host test".to_string(),
                },
            )
            .expect("enable schedule");
        scheduler.sync_read_state(read);
    }

    fn host_request(action: NativeSchedulerHostAction) -> NativeSchedulerHostActionRequest {
        NativeSchedulerHostActionRequest {
            action,
            explicit_user_action: true,
            wake_reason: NativeSchedulerHostWakeReason::ManualWake,
            reason_redacted: "native scheduler host test action".to_string(),
        }
    }

    fn prepared_state() -> (
        ReadOnlyCommandState,
        NativeSchedulerController,
        NativeSamplerRuntime,
    ) {
        let mut read = ReadOnlyCommandState::bootstrap().expect("bootstrap");
        grant(&mut read, "native_health_probe");
        activate(&mut read, "native_health_probe_sampler");
        enable_schedule(&mut read, "native_health_probe_sampler");
        let scheduler = NativeSchedulerController::from_read_state(&read);
        let runtime = NativeSamplerRuntime::from_read_state(&read);
        (read, scheduler, runtime)
    }

    #[test]
    fn native_scheduler_host_start_is_explicit_singleton_and_not_startup() {
        let (mut read, mut scheduler, mut runtime) = prepared_state();
        let mut host = NativeSchedulerHostController::from_read_state(&read);
        assert_eq!(
            host.status(&read).expect("status").lifecycle_state,
            NativeSchedulerHostLifecycleState::Disabled
        );
        let preview = host.preview_start(&read).expect("preview");
        assert!(preview.start_allowed);
        assert!(!preview.task_created);

        let started = host
            .apply_action(
                &mut read,
                &mut scheduler,
                &mut runtime,
                host_request(NativeSchedulerHostAction::Start),
            )
            .expect("start");
        assert!(started.task_created);
        assert_eq!(
            started.status.lifecycle_state,
            NativeSchedulerHostLifecycleState::Running
        );
        assert!(started.status.host_task_owned);

        let duplicate = host
            .apply_action(
                &mut read,
                &mut scheduler,
                &mut runtime,
                host_request(NativeSchedulerHostAction::Start),
            )
            .expect("duplicate start");
        assert!(!duplicate.task_created);
        assert_eq!(
            duplicate.status.lifecycle_state,
            NativeSchedulerHostLifecycleState::Running
        );
    }

    #[test]
    fn native_scheduler_host_wake_uses_existing_tick_and_records_origin() {
        let (mut read, mut scheduler, mut runtime) = prepared_state();
        let mut host = NativeSchedulerHostController::from_read_state(&read);
        host.apply_action(
            &mut read,
            &mut scheduler,
            &mut runtime,
            host_request(NativeSchedulerHostAction::Start),
        )
        .expect("start");
        let result = host
            .apply_action(
                &mut read,
                &mut scheduler,
                &mut runtime,
                host_request(NativeSchedulerHostAction::WakeNow),
            )
            .expect("wake");
        assert!(result.tick_invoked);
        let cycle = result.latest_host_cycle.expect("host cycle");
        assert_eq!(cycle.cycle_origin, NativeSchedulerCycleOrigin::Autonomous);
        assert!(cycle.scheduler_cycle_ref.is_some());
        assert_eq!(read.native_scheduler_cycles.len(), 1);
        assert!(!result.provider_direct_calls);
        assert!(!result.automatic_llm_calls);
        assert!(!result.response_execution_started);
    }

    #[test]
    fn native_scheduler_host_cycle_gate_prevents_overlap() {
        let (mut read, mut scheduler, mut runtime) = prepared_state();
        let mut host = NativeSchedulerHostController::from_read_state(&read);
        host.apply_action(
            &mut read,
            &mut scheduler,
            &mut runtime,
            host_request(NativeSchedulerHostAction::Start),
        )
        .expect("start");
        read.native_scheduler_cycle_gate_active = true;
        let result = host
            .apply_action(
                &mut read,
                &mut scheduler,
                &mut runtime,
                host_request(NativeSchedulerHostAction::WakeNow),
            )
            .expect("wake busy");
        let cycle = result.latest_host_cycle.expect("host cycle");
        assert!(cycle.cycle_gate_busy);
        assert!(!cycle.tick_invoked);
        assert!(read.native_scheduler_cycles.is_empty());
        read.native_scheduler_cycle_gate_active = false;
    }

    #[test]
    fn native_scheduler_host_pause_resume_stop_and_health_are_bounded() {
        let (mut read, mut scheduler, mut runtime) = prepared_state();
        let mut host = NativeSchedulerHostController::from_read_state(&read);
        host.apply_action(
            &mut read,
            &mut scheduler,
            &mut runtime,
            host_request(NativeSchedulerHostAction::Start),
        )
        .expect("start");
        let paused = host
            .apply_action(
                &mut read,
                &mut scheduler,
                &mut runtime,
                host_request(NativeSchedulerHostAction::Pause),
            )
            .expect("pause");
        assert_eq!(
            paused.status.lifecycle_state,
            NativeSchedulerHostLifecycleState::Paused
        );
        let resumed = host
            .apply_action(
                &mut read,
                &mut scheduler,
                &mut runtime,
                host_request(NativeSchedulerHostAction::Resume),
            )
            .expect("resume");
        assert_eq!(
            resumed.status.lifecycle_state,
            NativeSchedulerHostLifecycleState::Running
        );
        let stopped = host
            .apply_action(
                &mut read,
                &mut scheduler,
                &mut runtime,
                host_request(NativeSchedulerHostAction::Stop),
            )
            .expect("stop");
        assert_eq!(
            stopped.status.lifecycle_state,
            NativeSchedulerHostLifecycleState::Stopped
        );
        assert!(!stopped.status.host_task_owned);
        let health = host.health(&read).expect("health");
        assert!(health.session_bound);
        assert!(!health.startup_auto_run);
        assert!(!health.os_service);
    }
}
