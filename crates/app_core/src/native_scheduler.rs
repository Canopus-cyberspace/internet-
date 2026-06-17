use crate::native_sampler_readiness::get_native_sampler_readiness_detail;
use crate::native_sampler_runtime::NativeSamplerRuntime;
use crate::read_commands::ReadOnlyCommandState;
use crate::runtime_container::RuntimeEventBusHandle;
use sentinel_contracts::{
    AuditId, CommandResult, CoreError, ErrorCode, ErrorSeverity, EventEnvelope, EventType,
    NativeMissedSampleDimensionSummary, NativeMissedSampleState, NativePermissionState,
    NativeProcessCategory, NativeProviderAvailabilityState, NativeSamplerBatchId,
    NativeSamplerCategory, NativeSamplerRetentionModeCategory, NativeSamplerRuntimeAction,
    NativeSamplerRuntimeActionRequest, NativeSamplerRuntimeActionResult, NativeSamplerRuntimeBatch,
    NativeSamplerRuntimeState, NativeSamplerScheduleContract, NativeSamplerScheduleStatus,
    NativeScheduleIntervalBucket, NativeScheduleRetryBudgetBucket, NativeScheduleTimeoutBucket,
    NativeSchedulerAction, NativeSchedulerActionRequest, NativeSchedulerActionResult,
    NativeSchedulerAuditEntry, NativeSchedulerBackpressureState,
    NativeSchedulerBackpressureSummary, NativeSchedulerControllerState, NativeSchedulerCycleId,
    NativeSchedulerCycleState, NativeSchedulerCycleSummary, NativeSchedulerEnablementPreview,
    NativeSchedulerExecutionControlSummary, NativeSchedulerFreshnessSummary,
    NativeSchedulerHealthState, NativeSchedulerMissedSampleSummary,
    NativeSchedulerOperationalSummary, NativeSchedulerRetrySummary,
    NativeSchedulerSafePersistedSchedule, NativeSchedulerSamplerCycleResult, NativeSchedulerStatus,
    NativeSchedulerSummary, NativeSchedulerTickRequest, NativeTelemetryDimension,
    NativeTelemetryFreshnessDimensionSummary, NativeTelemetryFreshnessState, PluginId,
    PrivacyClass, QualityScore, RedactionStatus, SchemaVersion, Timestamp, TraceContext,
    MAX_NATIVE_SCHEDULER_CYCLES, MAX_NATIVE_SCHEDULES,
    MIN_NATIVE_SCHEDULER_EXECUTION_TIMEOUT_MILLIS, MIN_NATIVE_SCHEDULER_TICK_MILLIS,
    NATIVE_SCHEDULER_ALLOWED_TOPICS,
};
use sentinel_platform::{
    PublishOptions, TopicName, AUDIT_NATIVE_SCHEDULER, NATIVE_SCHEDULER_BACKPRESSURE,
    NATIVE_SCHEDULER_CYCLE_COMPLETED, NATIVE_SCHEDULER_CYCLE_SKIPPED,
    NATIVE_SCHEDULER_CYCLE_STARTED, NATIVE_SCHEDULER_EXECUTION_CONTROL, NATIVE_SCHEDULER_FRESHNESS,
    NATIVE_SCHEDULER_MISSED_SAMPLE, NATIVE_SCHEDULER_STATUS,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

const PROVENANCE_ID: &str = "native_scheduler_controller";
const CURRENT_SESSION_BUCKET: &str = "current_session";
const DEFAULT_MAX_RECORDS: u32 = 128;
const DEFAULT_MAX_BYTES: u32 = 65_536;
const SUPPORTED_SAMPLERS: &[&str] = &[
    "native_health_probe_sampler",
    "service_metadata_sampler",
    "process_metadata_sampler",
];

#[derive(Clone, Debug)]
pub struct NativeSchedulerController {
    controller_state: NativeSchedulerControllerState,
    schedules: Vec<NativeSamplerScheduleStatus>,
    audit_entries: Vec<NativeSchedulerAuditEntry>,
    cycles: Vec<NativeSchedulerCycleSummary>,
    last_tick_monotonic_millis: Option<u64>,
    next_due_monotonic_millis: BTreeMap<String, u64>,
    retry_attempts: BTreeMap<String, u32>,
    active_sampler_executions: BTreeSet<String>,
    active_category_executions: BTreeMap<String, u32>,
    graceful_shutdown_requested: bool,
    event_bus: RuntimeEventBusHandle,
    producer_plugin: PluginId,
}

impl NativeSchedulerController {
    #[cfg(test)]
    pub fn from_read_state(read: &ReadOnlyCommandState) -> Self {
        Self::from_read_state_with_event_bus(read, RuntimeEventBusHandle::new_legacy_core_topics())
    }

    pub(crate) fn from_read_state_with_event_bus(
        read: &ReadOnlyCommandState,
        event_bus: RuntimeEventBusHandle,
    ) -> Self {
        Self {
            controller_state: read.native_scheduler_controller_state.clone(),
            schedules: read.native_sampler_schedule_statuses.clone(),
            audit_entries: read.native_scheduler_audit_entries.clone(),
            cycles: read.native_scheduler_cycles.clone(),
            last_tick_monotonic_millis: read.native_scheduler_last_tick_monotonic_millis,
            next_due_monotonic_millis: read.native_scheduler_next_due_monotonic_millis.clone(),
            retry_attempts: read.native_scheduler_retry_attempts.clone(),
            active_sampler_executions: BTreeSet::new(),
            active_category_executions: BTreeMap::new(),
            graceful_shutdown_requested: read.native_scheduler_graceful_shutdown_requested,
            event_bus,
            producer_plugin: PluginId::new_v4(),
        }
    }

    pub(crate) fn schedule_status_from_read_state(
        read: &ReadOnlyCommandState,
        sampler_id: &str,
    ) -> CommandResult<NativeSamplerScheduleStatus> {
        schedule_status_from_parts(read, &read.native_sampler_schedule_statuses, sampler_id)
    }

    pub(crate) fn summary_from_read_state(
        read: &ReadOnlyCommandState,
    ) -> CommandResult<NativeSchedulerSummary> {
        let schedules = SUPPORTED_SAMPLERS
            .iter()
            .map(|sampler_id| Self::schedule_status_from_read_state(read, sampler_id))
            .collect::<CommandResult<Vec<_>>>()?;
        let status = scheduler_status_from_parts(
            &read.native_scheduler_controller_state,
            &schedules,
            &read.native_scheduler_cycles,
            read.native_scheduler_last_tick_monotonic_millis,
            read.native_scheduler_graceful_shutdown_requested,
            &read.native_scheduler_audit_entries,
        );
        let summary = NativeSchedulerSummary {
            status,
            schedules,
            authorization_independent: true,
            activation_independent: true,
            enablement_independent: true,
            startup_auto_enablement: false,
            latest_cycle: read.native_scheduler_cycles.last().cloned(),
            generated_at: Timestamp::now(),
        };
        summary.validate().map_err(contract_error)?;
        Ok(summary)
    }

    pub(crate) fn operational_summary_from_read_state(
        read: &ReadOnlyCommandState,
    ) -> CommandResult<NativeSchedulerOperationalSummary> {
        let summary = Self::summary_from_read_state(read)?;
        operational_summary_from_parts(
            summary,
            &read.native_scheduler_cycles,
            &read.native_scheduler_retry_attempts,
        )
    }

    pub fn sync_read_state(&self, read: &mut ReadOnlyCommandState) {
        read.native_scheduler_controller_state = self.controller_state.clone();
        read.native_sampler_schedule_statuses = self.schedules.clone();
        read.native_scheduler_audit_entries = self.audit_entries.clone();
        read.native_scheduler_cycles = self.cycles.clone();
        read.native_scheduler_last_tick_monotonic_millis = self.last_tick_monotonic_millis;
        read.native_scheduler_next_due_monotonic_millis = self.next_due_monotonic_millis.clone();
        read.native_scheduler_retry_attempts = self.retry_attempts.clone();
        read.native_scheduler_graceful_shutdown_requested = self.graceful_shutdown_requested;
    }

    #[cfg(test)]
    fn mark_sampler_execution_active_for_test(
        &mut self,
        sampler_id: &str,
        category: NativeSamplerCategory,
    ) {
        self.active_sampler_executions
            .insert(sampler_id.to_string());
        *self
            .active_category_executions
            .entry(sampler_category_key(&category))
            .or_insert(0) += 1;
    }

    pub fn preview_enablement(
        &self,
        read: &ReadOnlyCommandState,
        sampler_id: &str,
    ) -> CommandResult<NativeSchedulerEnablementPreview> {
        let schedule = self.schedule_status(read, sampler_id)?;
        let preview = NativeSchedulerEnablementPreview {
            sampler_id: sampler_id.to_string(),
            controller_state: self.controller_state.clone(),
            permission_state: schedule.permission_state,
            runtime_state: schedule.runtime_state,
            schedule_eligible: schedule.schedule_eligible,
            blocked_reason: schedule.blocked_reason,
            state_change_performed: false,
            periodic_execution_started: false,
            sample_requested: false,
            boundary_summary_redacted:
                "Preview only; authorization, activation, and periodic enablement remain independent"
                    .to_string(),
        };
        preview.validate().map_err(contract_error)?;
        Ok(preview)
    }

    pub fn apply_action(
        &mut self,
        read: &mut ReadOnlyCommandState,
        request: NativeSchedulerActionRequest,
    ) -> CommandResult<NativeSchedulerActionResult> {
        request.validate().map_err(contract_error)?;
        if request.action == NativeSchedulerAction::PreviewEnableSampler {
            return Err(CoreError::validation_failure(
                "use the native scheduler preview command for preview-only actions",
            ));
        }
        self.reconcile(read)?;

        let sampler_status = match request.action {
            NativeSchedulerAction::EnableSampler => {
                let sampler_id = required_sampler_id(&request)?;
                let mut status = self.schedule_status(read, sampler_id)?;
                if !status.schedule_eligible {
                    return Err(CoreError::new(
                        ErrorCode::PermissionDenied,
                        "native periodic scheduling requires separate authorization and activation",
                    )
                    .with_severity(ErrorSeverity::Warning)
                    .with_redacted_details(json!({
                        "sampler_id": sampler_id,
                        "reason": status.blocked_reason
                    })));
                }
                status.contract.schedule_enabled = true;
                status.contract.interval_bucket = request.interval_bucket.clone();
                status.contract.timeout_bucket = request.timeout_bucket.clone();
                status.contract.retry_budget_bucket = request.retry_budget_bucket.clone();
                status.contract.max_records = request.max_records;
                status.contract.max_bytes = request.max_bytes;
                self.next_due_monotonic_millis.remove(sampler_id);
                self.retry_attempts.remove(sampler_id);
                self.upsert_schedule(status.clone());
                self.controller_state = NativeSchedulerControllerState::Running;
                self.graceful_shutdown_requested = false;
                Some(status)
            }
            NativeSchedulerAction::DisableSampler => {
                let sampler_id = required_sampler_id(&request)?;
                let mut status = self.schedule_status(read, sampler_id)?;
                status.contract.schedule_enabled = false;
                self.next_due_monotonic_millis.remove(sampler_id);
                self.retry_attempts.remove(sampler_id);
                self.upsert_schedule(status.clone());
                self.controller_state = state_after_schedule_change(&self.schedules);
                Some(status)
            }
            NativeSchedulerAction::DisableScheduler => {
                for schedule in &mut self.schedules {
                    schedule.contract.schedule_enabled = false;
                }
                self.next_due_monotonic_millis.clear();
                self.retry_attempts.clear();
                self.controller_state = NativeSchedulerControllerState::Disabled;
                self.graceful_shutdown_requested = false;
                None
            }
            NativeSchedulerAction::Pause => {
                if self.controller_state != NativeSchedulerControllerState::Running {
                    return Err(invalid_transition("pause", &self.controller_state));
                }
                self.controller_state = NativeSchedulerControllerState::Paused;
                None
            }
            NativeSchedulerAction::Resume => {
                if self.controller_state != NativeSchedulerControllerState::Paused {
                    return Err(invalid_transition("resume", &self.controller_state));
                }
                self.controller_state = if self
                    .schedules
                    .iter()
                    .any(|schedule| schedule.contract.schedule_enabled)
                {
                    NativeSchedulerControllerState::Running
                } else {
                    NativeSchedulerControllerState::Ready
                };
                self.graceful_shutdown_requested = false;
                None
            }
            NativeSchedulerAction::BeginStop => {
                if matches!(
                    self.controller_state,
                    NativeSchedulerControllerState::Stopped
                        | NativeSchedulerControllerState::Revoked
                ) {
                    return Err(invalid_transition("begin_stop", &self.controller_state));
                }
                for schedule in &mut self.schedules {
                    schedule.contract.schedule_enabled = false;
                }
                self.next_due_monotonic_millis.clear();
                self.retry_attempts.clear();
                self.controller_state = NativeSchedulerControllerState::Stopping;
                self.graceful_shutdown_requested = true;
                None
            }
            NativeSchedulerAction::CompleteStop => {
                if self.controller_state != NativeSchedulerControllerState::Stopping {
                    return Err(invalid_transition("complete_stop", &self.controller_state));
                }
                self.controller_state = NativeSchedulerControllerState::Stopped;
                self.graceful_shutdown_requested = true;
                None
            }
            NativeSchedulerAction::RefreshStatus => {
                self.reconcile(read)?;
                request
                    .sampler_id
                    .as_deref()
                    .map(|sampler_id| self.schedule_status(read, sampler_id))
                    .transpose()?
            }
            NativeSchedulerAction::PreviewEnableSampler => unreachable!(),
            NativeSchedulerAction::RunTick => {
                return Err(CoreError::validation_failure(
                    "use the native scheduler tick command for periodic cycles",
                ));
            }
        };

        let audit_entry = scheduler_audit_entry(&request, &self.controller_state);
        if let Some(status) = &sampler_status {
            let mut status = status.clone();
            status.audit_refs.push(audit_entry.audit_id.clone());
            status
                .audit_refs
                .truncate(sentinel_contracts::MAX_NATIVE_SCHEDULER_REFS);
            self.upsert_schedule(status);
        }
        self.audit_entries.push(audit_entry.clone());
        bound_audits(&mut self.audit_entries);
        let status = self.status_snapshot();
        self.publish_status(&status)?;
        self.publish_audit(&audit_entry)?;
        self.sync_read_state(read);

        let result = NativeSchedulerActionResult {
            status,
            sampler_status: sampler_status.map(|status| {
                self.schedules
                    .iter()
                    .find(|current| current.contract.sampler_id == status.contract.sampler_id)
                    .cloned()
                    .unwrap_or(status)
            }),
            audit_entry,
            emitted_topics: vec![
                NATIVE_SCHEDULER_STATUS.to_string(),
                AUDIT_NATIVE_SCHEDULER.to_string(),
            ],
            preview_only: false,
            periodic_execution_started: false,
            sample_requested: false,
            automatic_llm_calls: false,
            response_execution_started: false,
        };
        result.validate().map_err(contract_error)?;
        Ok(result)
    }

    pub fn tick(
        &mut self,
        read: &mut ReadOnlyCommandState,
        runtime: &mut NativeSamplerRuntime,
        request: NativeSchedulerTickRequest,
    ) -> CommandResult<NativeSchedulerCycleSummary> {
        request.validate().map_err(contract_error)?;
        self.reconcile(read)?;

        if let Some(last_tick) = self.last_tick_monotonic_millis {
            if request.monotonic_elapsed_millis < last_tick {
                return self.finish_skipped_cycle(read, &request, "monotonic_clock_regressed");
            }
            if request.monotonic_elapsed_millis.saturating_sub(last_tick)
                < MIN_NATIVE_SCHEDULER_TICK_MILLIS
            {
                return self.finish_skipped_cycle(read, &request, "tick_frequency_bounded");
            }
        }
        self.last_tick_monotonic_millis = Some(request.monotonic_elapsed_millis);

        if request.cancellation_requested {
            return self.finish_skipped_cycle(read, &request, "cancellation_requested");
        }

        if self.controller_state != NativeSchedulerControllerState::Running
            || self.graceful_shutdown_requested
        {
            return self.finish_skipped_cycle(read, &request, "scheduler_not_running");
        }

        let mut due_sampler_ids = self
            .schedules
            .iter()
            .filter(|schedule| schedule.contract.schedule_enabled)
            .filter(|schedule| {
                self.next_due_monotonic_millis
                    .get(&schedule.contract.sampler_id)
                    .is_none_or(|due| *due <= request.monotonic_elapsed_millis)
            })
            .map(|schedule| schedule.contract.sampler_id.clone())
            .collect::<Vec<_>>();
        due_sampler_ids.sort();
        if due_sampler_ids.is_empty() {
            return self.finish_skipped_cycle(read, &request, "no_due_samplers");
        }

        let cycle_id = NativeSchedulerCycleId::new_v4();
        let backpressure =
            self.backpressure_summary(cycle_id.clone(), &request, &due_sampler_ids)?;
        if backpressure.skip_cycle {
            self.advance_due_without_catch_up(&request, &due_sampler_ids);
            return self.finish_skipped_cycle_with_selected(
                read,
                &request,
                due_sampler_ids,
                "backpressure_saturated",
            );
        }
        if backpressure.pause_degraded_samplers {
            self.pause_degraded_schedules(&backpressure.paused_sampler_ids);
        }
        let deferred_sampler_ids = backpressure
            .deferred_sampler_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let started = cycle_summary(
            cycle_id.clone(),
            NativeSchedulerCycleState::Started,
            request.monotonic_elapsed_millis,
            due_sampler_ids.clone(),
            Vec::new(),
            None,
            None,
            None,
            None,
            None,
            vec![NATIVE_SCHEDULER_CYCLE_STARTED.to_string()],
            Vec::new(),
            self.graceful_shutdown_requested,
        )?;
        self.publish(
            NATIVE_SCHEDULER_CYCLE_STARTED,
            &started,
            "bounded native scheduler cycle started",
        )?;
        self.publish(
            NATIVE_SCHEDULER_BACKPRESSURE,
            &backpressure,
            "bounded native scheduler backpressure",
        )?;

        let mut results = Vec::new();
        let mut admitted_count = 0usize;
        let mut category_admitted_counts = BTreeMap::<String, u32>::new();
        let cycle_started = Instant::now();
        let active_execution_count_at_start = self.active_sampler_executions.len() as u32;
        for sampler_id in &due_sampler_ids {
            let schedule = self
                .schedules
                .iter()
                .find(|schedule| schedule.contract.sampler_id == *sampler_id)
                .cloned()
                .ok_or_else(|| {
                    CoreError::validation_failure("selected native schedule is missing")
                })?;
            let interval_millis = interval_millis(&schedule.contract.interval_bucket);
            self.next_due_monotonic_millis.insert(
                sampler_id.clone(),
                request
                    .monotonic_elapsed_millis
                    .saturating_add(interval_millis),
            );
            let retry_budget = retry_budget(&schedule.contract.retry_budget_bucket);

            if deferred_sampler_ids.contains(sampler_id) {
                results.push(skipped_sampler_result(
                    sampler_id,
                    "backpressure_deferred",
                    ExecutionControlDecision::none(retry_budget),
                )?);
                continue;
            }

            if admitted_count >= request.max_samplers_per_tick as usize
                || admitted_count >= request.global_concurrency_limit as usize
            {
                let control = self.retry_control_for(
                    sampler_id,
                    &schedule,
                    &request,
                    "global_concurrency_limit",
                );
                results.push(skipped_sampler_result(
                    sampler_id,
                    "global_concurrency_limit",
                    control.with_overlap_prevented(),
                )?);
                continue;
            }

            if self.active_sampler_executions.contains(sampler_id) {
                let control =
                    self.retry_control_for(sampler_id, &schedule, &request, "transient_busy_state");
                results.push(skipped_sampler_result(
                    sampler_id,
                    "transient_busy_state",
                    control.with_overlap_prevented(),
                )?);
                continue;
            }

            let category_key = sampler_category_key(&schedule.contract.sampler_category);
            let active_category_count = self
                .active_category_executions
                .get(&category_key)
                .copied()
                .unwrap_or(0);
            let admitted_category_count = category_admitted_counts
                .get(&category_key)
                .copied()
                .unwrap_or(0);
            if active_category_count.saturating_add(admitted_category_count)
                >= request.per_category_concurrency_limit
            {
                let control = self.retry_control_for(
                    sampler_id,
                    &schedule,
                    &request,
                    "per_category_concurrency_limit",
                );
                results.push(skipped_sampler_result(
                    sampler_id,
                    "per_category_concurrency_limit",
                    control.with_overlap_prevented(),
                )?);
                continue;
            }

            if request.global_cycle_timeout_millis < MIN_NATIVE_SCHEDULER_EXECUTION_TIMEOUT_MILLIS
                || cycle_started.elapsed().as_millis()
                    >= u128::from(request.global_cycle_timeout_millis)
            {
                let control = self
                    .retry_control_for(sampler_id, &schedule, &request, "global_cycle_timeout")
                    .with_timeout_enforced();
                results.push(skipped_sampler_result(
                    sampler_id,
                    "global_cycle_timeout",
                    control,
                )?);
                continue;
            }

            if request.execution_timeout_millis < MIN_NATIVE_SCHEDULER_EXECUTION_TIMEOUT_MILLIS {
                let control = self
                    .retry_control_for(sampler_id, &schedule, &request, "execution_timeout")
                    .with_timeout_enforced();
                results.push(skipped_sampler_result(
                    sampler_id,
                    "execution_timeout",
                    control,
                )?);
                continue;
            }

            if request.provider_timeout_millis < MIN_NATIVE_SCHEDULER_EXECUTION_TIMEOUT_MILLIS {
                let control = self
                    .retry_control_for(sampler_id, &schedule, &request, "provider_timeout")
                    .with_timeout_enforced();
                results.push(skipped_sampler_result(
                    sampler_id,
                    "provider_timeout",
                    control,
                )?);
                continue;
            }

            let revalidated = self.schedule_status(read, sampler_id).and_then(|status| {
                status.validate().map_err(contract_error)?;
                if !status.contract.schedule_enabled || !status.schedule_eligible {
                    return Err(CoreError::new(
                        ErrorCode::PermissionDenied,
                        "native scheduler authorization revalidation failed",
                    )
                    .with_severity(ErrorSeverity::Warning));
                }
                let detail = get_native_sampler_readiness_detail(read, sampler_id)?;
                detail.validate().map_err(contract_error)?;
                if !detail.review.allowed || !detail.contract.sampler_implemented {
                    return Err(CoreError::new(
                        ErrorCode::PermissionDenied,
                        "native scheduler readiness revalidation failed",
                    )
                    .with_severity(ErrorSeverity::Warning));
                }
                Ok(())
            });

            if revalidated.is_err() {
                self.retry_attempts.remove(sampler_id);
                results.push(skipped_sampler_result(
                    sampler_id,
                    "authorization_revalidation_failed",
                    ExecutionControlDecision::none(retry_budget),
                )?);
                continue;
            }

            self.active_sampler_executions.insert(sampler_id.clone());
            *self
                .active_category_executions
                .entry(category_key.clone())
                .or_insert(0) += 1;
            admitted_count += 1;
            *category_admitted_counts
                .entry(category_key.clone())
                .or_insert(0) += 1;

            let effective_timeout_millis = timeout_millis(&schedule.contract.timeout_bucket)
                .min(request.provider_timeout_millis)
                .min(request.execution_timeout_millis);
            let runtime_result = runtime.apply_action(
                read,
                NativeSamplerRuntimeActionRequest {
                    sampler_id: sampler_id.clone(),
                    action: NativeSamplerRuntimeAction::ScheduledSample,
                    explicit_user_action: false,
                    enable_interval_sampling: false,
                    max_records_per_sample: schedule.contract.max_records,
                    max_bytes_per_sample: schedule.contract.max_bytes,
                    timeout_millis: effective_timeout_millis,
                    reason_redacted: "authorized native scheduler cycle".to_string(),
                },
            );
            self.active_sampler_executions.remove(sampler_id);
            if let Some(count) = self.active_category_executions.get_mut(&category_key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.active_category_executions.remove(&category_key);
                }
            }
            match runtime_result {
                Ok(result) => {
                    let control = if runtime_result_is_temporarily_unavailable(&result) {
                        self.retry_control_for(
                            sampler_id,
                            &schedule,
                            &request,
                            "temporary_unavailability",
                        )
                    } else {
                        self.retry_attempts.remove(sampler_id);
                        ExecutionControlDecision::none(retry_budget)
                    };
                    results.push(completed_sampler_result(sampler_id, &result, control)?);
                }
                Err(_) => {
                    let control = self.retry_control_for(
                        sampler_id,
                        &schedule,
                        &request,
                        "transient_busy_state",
                    );
                    results.push(skipped_sampler_result(
                        sampler_id,
                        "transient_busy_state",
                        control,
                    )?);
                }
            }
        }

        runtime.sync_read_state(read);
        self.reconcile(read)?;
        let freshness = self.freshness_summary(cycle_id.clone(), read, &request, Some(&results))?;
        let missed_sample = self.missed_sample_summary(cycle_id.clone(), &request, &freshness)?;
        self.publish(
            NATIVE_SCHEDULER_FRESHNESS,
            &freshness,
            "bounded native scheduler freshness",
        )?;
        self.publish(
            NATIVE_SCHEDULER_MISSED_SAMPLE,
            &missed_sample,
            "bounded native scheduler missed sample",
        )?;
        let cycle_state = if results
            .iter()
            .any(|result| result.cycle_state == NativeSchedulerCycleState::Completed)
        {
            NativeSchedulerCycleState::Completed
        } else {
            NativeSchedulerCycleState::Skipped
        };
        let topic = if cycle_state == NativeSchedulerCycleState::Completed {
            NATIVE_SCHEDULER_CYCLE_COMPLETED
        } else {
            NATIVE_SCHEDULER_CYCLE_SKIPPED
        };
        let audit = scheduler_tick_audit(&self.controller_state, None);
        self.publish_audit(&audit)?;
        self.audit_entries.push(audit.clone());
        bound_audits(&mut self.audit_entries);
        let execution_control = execution_control_summary(
            cycle_id.clone(),
            &request,
            due_sampler_ids.clone(),
            &results,
            active_execution_count_at_start,
        )?;
        self.publish(
            NATIVE_SCHEDULER_EXECUTION_CONTROL,
            &execution_control,
            "bounded native scheduler execution control",
        )?;
        let cycle = cycle_summary(
            cycle_id,
            cycle_state.clone(),
            request.monotonic_elapsed_millis,
            due_sampler_ids,
            results,
            (cycle_state == NativeSchedulerCycleState::Skipped)
                .then_some("all_due_samplers_skipped"),
            Some(execution_control),
            Some(backpressure),
            Some(freshness),
            Some(missed_sample),
            vec![
                NATIVE_SCHEDULER_CYCLE_STARTED.to_string(),
                NATIVE_SCHEDULER_BACKPRESSURE.to_string(),
                NATIVE_SCHEDULER_FRESHNESS.to_string(),
                NATIVE_SCHEDULER_MISSED_SAMPLE.to_string(),
                NATIVE_SCHEDULER_EXECUTION_CONTROL.to_string(),
                topic.to_string(),
            ],
            vec![audit.audit_id],
            self.graceful_shutdown_requested,
        )?;
        self.publish(topic, &cycle, "bounded native scheduler cycle result")?;
        self.store_cycle(cycle.clone());
        self.publish_status(&self.status_snapshot())?;
        self.sync_read_state(read);
        Ok(cycle)
    }

    fn finish_skipped_cycle(
        &mut self,
        read: &mut ReadOnlyCommandState,
        request: &NativeSchedulerTickRequest,
        reason: &str,
    ) -> CommandResult<NativeSchedulerCycleSummary> {
        self.finish_skipped_cycle_with_selected(read, request, Vec::new(), reason)
    }

    fn finish_skipped_cycle_with_selected(
        &mut self,
        read: &mut ReadOnlyCommandState,
        request: &NativeSchedulerTickRequest,
        selected_sampler_ids: Vec<String>,
        reason: &str,
    ) -> CommandResult<NativeSchedulerCycleSummary> {
        let audit = scheduler_tick_audit(&self.controller_state, Some(reason));
        self.publish_audit(&audit)?;
        self.audit_entries.push(audit.clone());
        bound_audits(&mut self.audit_entries);
        let cycle_id = NativeSchedulerCycleId::new_v4();
        let backpressure =
            self.backpressure_summary(cycle_id.clone(), request, &selected_sampler_ids)?;
        if backpressure.pause_degraded_samplers {
            self.pause_degraded_schedules(&backpressure.paused_sampler_ids);
        }
        self.publish(
            NATIVE_SCHEDULER_BACKPRESSURE,
            &backpressure,
            "bounded native scheduler backpressure",
        )?;
        let freshness = self.freshness_summary(cycle_id.clone(), read, request, None)?;
        let missed_sample = self.missed_sample_summary(cycle_id.clone(), request, &freshness)?;
        self.publish(
            NATIVE_SCHEDULER_FRESHNESS,
            &freshness,
            "bounded native scheduler freshness",
        )?;
        self.publish(
            NATIVE_SCHEDULER_MISSED_SAMPLE,
            &missed_sample,
            "bounded native scheduler missed sample",
        )?;
        let control = execution_control_summary(
            cycle_id,
            request,
            selected_sampler_ids.clone(),
            &[],
            self.active_sampler_executions.len() as u32,
        )?;
        self.publish(
            NATIVE_SCHEDULER_EXECUTION_CONTROL,
            &control,
            "bounded native scheduler execution control",
        )?;
        let cycle = cycle_summary(
            control.cycle_id.clone(),
            NativeSchedulerCycleState::Skipped,
            request.monotonic_elapsed_millis,
            selected_sampler_ids,
            Vec::new(),
            Some(reason),
            Some(control),
            Some(backpressure),
            Some(freshness),
            Some(missed_sample),
            vec![
                NATIVE_SCHEDULER_BACKPRESSURE.to_string(),
                NATIVE_SCHEDULER_FRESHNESS.to_string(),
                NATIVE_SCHEDULER_MISSED_SAMPLE.to_string(),
                NATIVE_SCHEDULER_EXECUTION_CONTROL.to_string(),
                NATIVE_SCHEDULER_CYCLE_SKIPPED.to_string(),
            ],
            vec![audit.audit_id],
            self.graceful_shutdown_requested,
        )?;
        self.publish(
            NATIVE_SCHEDULER_CYCLE_SKIPPED,
            &cycle,
            "bounded native scheduler cycle skipped",
        )?;
        self.store_cycle(cycle.clone());
        self.publish_status(&self.status_snapshot())?;
        self.sync_read_state(read);
        Ok(cycle)
    }

    fn backpressure_summary(
        &self,
        cycle_id: NativeSchedulerCycleId,
        request: &NativeSchedulerTickRequest,
        due_sampler_ids: &[String],
    ) -> CommandResult<NativeSchedulerBackpressureSummary> {
        let active_task_count = self.active_sampler_executions.len() as u32;
        let pending_due_task_count = due_sampler_ids.len() as u32;
        let timeout_rate_bucket =
            scheduler_rate_bucket(&self.cycles, |result| result.timeout_enforced);
        let overlap_skip_rate_bucket =
            scheduler_rate_bucket(&self.cycles, |result| result.overlap_prevented);
        let state = classify_backpressure(
            request,
            active_task_count,
            pending_due_task_count,
            &timeout_rate_bucket,
            &overlap_skip_rate_bucket,
        );
        let skip_cycle = state == NativeSchedulerBackpressureState::Saturated;
        let deferred_sampler_ids = if skip_cycle {
            Vec::new()
        } else {
            self.deferred_sampler_ids(due_sampler_ids, &state)
        };
        let paused_sampler_ids = if matches!(
            state,
            NativeSchedulerBackpressureState::High | NativeSchedulerBackpressureState::Saturated
        ) {
            self.schedules
                .iter()
                .filter(|schedule| schedule.contract.schedule_enabled)
                .filter(|schedule| schedule.runtime_state == NativeSamplerRuntimeState::Degraded)
                .map(|schedule| schedule.contract.sampler_id.clone())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let summary = NativeSchedulerBackpressureSummary {
            cycle_id,
            state,
            active_task_count,
            pending_due_task_count,
            event_bus_backlog_count: request.event_bus_backlog_count,
            dag_backlog_count: request.dag_backlog_count,
            timeout_rate_bucket,
            overlap_skip_rate_bucket,
            defer_low_priority_samplers: !deferred_sampler_ids.is_empty(),
            skip_cycle,
            pause_degraded_samplers: !paused_sampler_ids.is_empty(),
            deferred_sampler_ids,
            paused_sampler_ids,
            emitted_topics: vec![NATIVE_SCHEDULER_BACKPRESSURE.to_string()],
            provenance_id: PROVENANCE_ID.to_string(),
            redaction_status: RedactionStatus::Redacted,
            automatic_llm_calls: false,
            response_execution_started: false,
        };
        summary.validate().map_err(contract_error)?;
        Ok(summary)
    }

    fn deferred_sampler_ids(
        &self,
        due_sampler_ids: &[String],
        state: &NativeSchedulerBackpressureState,
    ) -> Vec<String> {
        let defer_priority_at_or_above = match state {
            NativeSchedulerBackpressureState::Moderate => Some(2),
            NativeSchedulerBackpressureState::High => Some(1),
            _ => None,
        };
        let Some(min_priority) = defer_priority_at_or_above else {
            return Vec::new();
        };
        due_sampler_ids
            .iter()
            .filter_map(|sampler_id| {
                self.schedules
                    .iter()
                    .find(|schedule| schedule.contract.sampler_id == *sampler_id)
                    .filter(|schedule| {
                        sampler_pressure_priority(&schedule.contract.sampler_category)
                            >= min_priority
                    })
                    .map(|_| sampler_id.clone())
            })
            .collect()
    }

    fn pause_degraded_schedules(&mut self, paused_sampler_ids: &[String]) {
        for sampler_id in paused_sampler_ids {
            if let Some(schedule) = self
                .schedules
                .iter_mut()
                .find(|schedule| schedule.contract.sampler_id == *sampler_id)
            {
                schedule.contract.schedule_enabled = false;
                self.next_due_monotonic_millis.remove(sampler_id);
                self.retry_attempts.remove(sampler_id);
            }
        }
    }

    fn advance_due_without_catch_up(
        &mut self,
        request: &NativeSchedulerTickRequest,
        due_sampler_ids: &[String],
    ) {
        for sampler_id in due_sampler_ids {
            if let Some(schedule) = self
                .schedules
                .iter()
                .find(|schedule| schedule.contract.sampler_id == *sampler_id)
            {
                self.next_due_monotonic_millis.insert(
                    sampler_id.clone(),
                    request
                        .monotonic_elapsed_millis
                        .saturating_add(interval_millis(&schedule.contract.interval_bucket)),
                );
                self.retry_attempts.remove(sampler_id);
            }
        }
    }

    fn freshness_summary(
        &self,
        cycle_id: NativeSchedulerCycleId,
        read: &ReadOnlyCommandState,
        request: &NativeSchedulerTickRequest,
        current_results: Option<&[NativeSchedulerSamplerCycleResult]>,
    ) -> CommandResult<NativeSchedulerFreshnessSummary> {
        let dimensions = freshness_dimensions()
            .into_iter()
            .map(|dimension| {
                self.freshness_dimension_summary(read, request, current_results, dimension)
            })
            .collect::<CommandResult<Vec<_>>>()?;
        let fresh_dimension_count = dimensions
            .iter()
            .filter(|dimension| dimension.freshness_state == NativeTelemetryFreshnessState::Fresh)
            .count() as u32;
        let aging_dimension_count = dimensions
            .iter()
            .filter(|dimension| dimension.freshness_state == NativeTelemetryFreshnessState::Aging)
            .count() as u32;
        let stale_dimension_count = dimensions
            .iter()
            .filter(|dimension| dimension.freshness_state == NativeTelemetryFreshnessState::Stale)
            .count() as u32;
        let missing_dimension_count = dimensions
            .iter()
            .filter(|dimension| dimension.freshness_state == NativeTelemetryFreshnessState::Missing)
            .count() as u32;
        let unavailable_dimension_count = dimensions
            .iter()
            .filter(|dimension| {
                dimension.freshness_state == NativeTelemetryFreshnessState::Unavailable
            })
            .count() as u32;
        let revoked_dimension_count = dimensions
            .iter()
            .filter(|dimension| dimension.freshness_state == NativeTelemetryFreshnessState::Revoked)
            .count() as u32;
        let summary = NativeSchedulerFreshnessSummary {
            cycle_id,
            monotonic_elapsed_millis: request.monotonic_elapsed_millis,
            worst_freshness_state: worst_freshness_state(&dimensions),
            dimensions,
            fresh_dimension_count,
            aging_dimension_count,
            stale_dimension_count,
            missing_dimension_count,
            unavailable_dimension_count,
            revoked_dimension_count,
            emitted_topics: vec![NATIVE_SCHEDULER_FRESHNESS.to_string()],
            provenance_id: PROVENANCE_ID.to_string(),
            redaction_status: RedactionStatus::Redacted,
            attack_finding_generation_started: false,
            automatic_llm_calls: false,
            response_execution_started: false,
        };
        summary.validate().map_err(contract_error)?;
        Ok(summary)
    }

    fn freshness_dimension_summary(
        &self,
        read: &ReadOnlyCommandState,
        request: &NativeSchedulerTickRequest,
        current_results: Option<&[NativeSchedulerSamplerCycleResult]>,
        dimension: NativeTelemetryDimension,
    ) -> CommandResult<NativeTelemetryFreshnessDimensionSummary> {
        let sampler_id = sampler_id_for_dimension(&dimension);
        let schedule = self.schedule_for_dimension(read, &dimension)?;
        let interval = schedule
            .as_ref()
            .map(|schedule| schedule.contract.interval_bucket.clone())
            .unwrap_or(NativeScheduleIntervalBucket::FiveMinutes);
        let last_success = self.last_success_for_dimension(
            read,
            current_results,
            request.monotonic_elapsed_millis,
            &dimension,
        );
        let freshness_state = freshness_state_for_dimension(
            schedule.as_ref(),
            last_success.as_ref(),
            request.monotonic_elapsed_millis,
            interval_millis(&interval),
            &dimension,
        );
        let batch_refs = last_success
            .as_ref()
            .map(|success| vec![success.batch.batch_id.clone()])
            .unwrap_or_default();
        let fact_refs = last_success
            .as_ref()
            .map(|success| success.batch.fact_refs.clone())
            .unwrap_or_default();
        let audit_refs = last_success
            .as_ref()
            .map(|success| success.batch.audit_refs.clone())
            .unwrap_or_default();
        let summary = NativeTelemetryFreshnessDimensionSummary {
            dimension,
            sampler_id: sampler_id.to_string(),
            freshness_state: freshness_state.clone(),
            last_success_monotonic_millis: last_success
                .as_ref()
                .map(|success| success.monotonic_elapsed_millis),
            age_bucket: age_bucket_for(
                request.monotonic_elapsed_millis,
                last_success
                    .as_ref()
                    .map(|success| success.monotonic_elapsed_millis),
                interval_millis(&interval),
            ),
            interval_bucket: interval,
            source_reliability_bucket: source_reliability_bucket_for(&freshness_state).to_string(),
            visibility_completeness_bucket: visibility_completeness_bucket_for(&freshness_state)
                .to_string(),
            evidence_quality_bucket: evidence_quality_bucket_for(&freshness_state).to_string(),
            degraded_reason: degraded_reason_for_freshness(&freshness_state),
            batch_refs,
            fact_refs,
            audit_refs,
            provenance_id: PROVENANCE_ID.to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        summary.validate().map_err(contract_error)?;
        Ok(summary)
    }

    fn missed_sample_summary(
        &self,
        cycle_id: NativeSchedulerCycleId,
        request: &NativeSchedulerTickRequest,
        freshness: &NativeSchedulerFreshnessSummary,
    ) -> CommandResult<NativeSchedulerMissedSampleSummary> {
        let dimensions = freshness
            .dimensions
            .iter()
            .map(|dimension| self.missed_sample_dimension_summary(request, dimension))
            .collect::<CommandResult<Vec<_>>>()?;
        let summary = NativeSchedulerMissedSampleSummary {
            cycle_id,
            monotonic_elapsed_millis: request.monotonic_elapsed_millis,
            delayed_dimension_count: dimensions
                .iter()
                .filter(|dimension| {
                    dimension.missed_sample_state == NativeMissedSampleState::Delayed
                })
                .count() as u32,
            missed_once_dimension_count: dimensions
                .iter()
                .filter(|dimension| {
                    dimension.missed_sample_state == NativeMissedSampleState::MissedOnce
                })
                .count() as u32,
            repeatedly_missed_dimension_count: dimensions
                .iter()
                .filter(|dimension| {
                    dimension.missed_sample_state == NativeMissedSampleState::RepeatedlyMissed
                })
                .count() as u32,
            paused_dimension_count: dimensions
                .iter()
                .filter(|dimension| {
                    dimension.missed_sample_state == NativeMissedSampleState::Paused
                })
                .count() as u32,
            blocked_dimension_count: dimensions
                .iter()
                .filter(|dimension| {
                    dimension.missed_sample_state == NativeMissedSampleState::Blocked
                })
                .count() as u32,
            revoked_dimension_count: dimensions
                .iter()
                .filter(|dimension| {
                    dimension.missed_sample_state == NativeMissedSampleState::Revoked
                })
                .count() as u32,
            dimensions,
            emitted_topics: vec![NATIVE_SCHEDULER_MISSED_SAMPLE.to_string()],
            provenance_id: PROVENANCE_ID.to_string(),
            redaction_status: RedactionStatus::Redacted,
            attack_finding_generation_started: false,
            automatic_llm_calls: false,
            response_execution_started: false,
        };
        summary.validate().map_err(contract_error)?;
        Ok(summary)
    }

    fn missed_sample_dimension_summary(
        &self,
        request: &NativeSchedulerTickRequest,
        dimension: &NativeTelemetryFreshnessDimensionSummary,
    ) -> CommandResult<NativeMissedSampleDimensionSummary> {
        let state = missed_sample_state_for(
            self.controller_state.clone(),
            dimension,
            request.monotonic_elapsed_millis,
            interval_millis(&dimension.interval_bucket),
        );
        let summary = NativeMissedSampleDimensionSummary {
            dimension: dimension.dimension.clone(),
            sampler_id: dimension.sampler_id.clone(),
            missed_sample_state: state,
            expected_interval_bucket: dimension.interval_bucket.clone(),
            last_success_monotonic_millis: dimension.last_success_monotonic_millis,
            missed_expected_count_bucket: missed_expected_count_bucket(
                request.monotonic_elapsed_millis,
                dimension.last_success_monotonic_millis,
                interval_millis(&dimension.interval_bucket),
            ),
            blocked_reason: dimension.degraded_reason.clone(),
            provenance_id: PROVENANCE_ID.to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        summary.validate().map_err(contract_error)?;
        Ok(summary)
    }

    fn schedule_for_dimension(
        &self,
        read: &ReadOnlyCommandState,
        dimension: &NativeTelemetryDimension,
    ) -> CommandResult<Option<NativeSamplerScheduleStatus>> {
        let sampler_id = sampler_id_for_dimension(dimension);
        if self
            .schedules
            .iter()
            .any(|schedule| schedule.contract.sampler_id == sampler_id)
        {
            return self.schedule_status(read, sampler_id).map(Some);
        }
        Ok(None)
    }

    fn last_success_for_dimension(
        &self,
        read: &ReadOnlyCommandState,
        current_results: Option<&[NativeSchedulerSamplerCycleResult]>,
        current_monotonic_elapsed_millis: u64,
        dimension: &NativeTelemetryDimension,
    ) -> Option<DimensionSuccess> {
        let sampler_id = sampler_id_for_dimension(dimension);
        if let Some(results) = current_results {
            for result in results.iter().rev() {
                if result.sampler_id == sampler_id
                    && result.cycle_state == NativeSchedulerCycleState::Completed
                    && result.batch_ref.as_ref().is_some_and(|batch_ref| {
                        batch_supports_dimension(read, batch_ref, dimension)
                    })
                {
                    let batch_ref = result.batch_ref.as_ref()?;
                    let batch = read
                        .native_sampler_runtime_batches
                        .iter()
                        .find(|batch| &batch.batch_id == batch_ref)?
                        .clone();
                    return Some(DimensionSuccess {
                        monotonic_elapsed_millis: current_monotonic_elapsed_millis,
                        batch,
                    });
                }
            }
        }
        for cycle in self.cycles.iter().rev() {
            for result in cycle.sampler_results.iter().rev() {
                if result.sampler_id == sampler_id
                    && result.cycle_state == NativeSchedulerCycleState::Completed
                    && result.batch_ref.as_ref().is_some_and(|batch_ref| {
                        batch_supports_dimension(read, batch_ref, dimension)
                    })
                {
                    let batch_ref = result.batch_ref.as_ref()?;
                    let batch = read
                        .native_sampler_runtime_batches
                        .iter()
                        .find(|batch| &batch.batch_id == batch_ref)?
                        .clone();
                    return Some(DimensionSuccess {
                        monotonic_elapsed_millis: cycle.monotonic_elapsed_millis,
                        batch,
                    });
                }
            }
        }
        None
    }

    fn retry_control_for(
        &mut self,
        sampler_id: &str,
        schedule: &NativeSamplerScheduleStatus,
        request: &NativeSchedulerTickRequest,
        reason: &str,
    ) -> ExecutionControlDecision {
        let budget = retry_budget(&schedule.contract.retry_budget_bucket);
        if !retryable_skip_reason(reason) {
            self.retry_attempts.remove(sampler_id);
            return ExecutionControlDecision::none(budget);
        }
        let current_attempt = self.retry_attempts.get(sampler_id).copied().unwrap_or(0);
        let next_attempt = current_attempt.saturating_add(1);
        if next_attempt <= budget {
            self.retry_attempts
                .insert(sampler_id.to_string(), next_attempt);
            self.next_due_monotonic_millis.insert(
                sampler_id.to_string(),
                request
                    .monotonic_elapsed_millis
                    .saturating_add(request.retry_delay_millis),
            );
            ExecutionControlDecision::retryable(
                next_attempt,
                budget,
                request.retry_delay_millis,
                true,
            )
        } else {
            self.retry_attempts.remove(sampler_id);
            self.next_due_monotonic_millis.insert(
                sampler_id.to_string(),
                request
                    .monotonic_elapsed_millis
                    .saturating_add(interval_millis(&schedule.contract.interval_bucket)),
            );
            ExecutionControlDecision::retryable(budget, budget, request.retry_delay_millis, false)
        }
    }

    fn store_cycle(&mut self, cycle: NativeSchedulerCycleSummary) {
        self.cycles.push(cycle);
        if self.cycles.len() > MAX_NATIVE_SCHEDULER_CYCLES {
            self.cycles
                .drain(0..self.cycles.len() - MAX_NATIVE_SCHEDULER_CYCLES);
        }
    }

    pub fn reconcile(&mut self, read: &ReadOnlyCommandState) -> CommandResult<()> {
        let previously_enabled = self
            .schedules
            .iter()
            .any(|schedule| schedule.contract.schedule_enabled);
        let schedules = SUPPORTED_SAMPLERS
            .iter()
            .map(|sampler_id| self.schedule_status(read, sampler_id))
            .collect::<CommandResult<Vec<_>>>()?;
        let lost_enabled_eligibility = previously_enabled
            && schedules
                .iter()
                .all(|schedule| !schedule.contract.schedule_enabled);
        self.schedules = schedules;

        if self
            .schedules
            .iter()
            .all(|schedule| schedule.permission_state == NativePermissionState::Revoked)
        {
            self.controller_state = NativeSchedulerControllerState::Revoked;
        } else if lost_enabled_eligibility {
            self.controller_state = NativeSchedulerControllerState::Degraded;
        } else if !matches!(
            self.controller_state,
            NativeSchedulerControllerState::Disabled
                | NativeSchedulerControllerState::Paused
                | NativeSchedulerControllerState::Stopping
                | NativeSchedulerControllerState::Stopped
                | NativeSchedulerControllerState::Failed
        ) {
            self.controller_state = state_after_schedule_change(&self.schedules);
        } else if self.controller_state == NativeSchedulerControllerState::Disabled
            && self
                .schedules
                .iter()
                .any(|schedule| schedule.schedule_eligible)
        {
            self.controller_state = NativeSchedulerControllerState::Ready;
        }
        Ok(())
    }

    pub fn schedule_status(
        &self,
        read: &ReadOnlyCommandState,
        sampler_id: &str,
    ) -> CommandResult<NativeSamplerScheduleStatus> {
        if !SUPPORTED_SAMPLERS.contains(&sampler_id) {
            return Err(CoreError::new(
                ErrorCode::InvalidRequest,
                "native scheduler sampler was not found",
            )
            .with_severity(ErrorSeverity::Info)
            .with_redacted_details(json!({ "sampler_id": sampler_id })));
        }
        schedule_status_from_parts(read, &self.schedules, sampler_id)
    }

    pub fn summary(&self, read: &ReadOnlyCommandState) -> CommandResult<NativeSchedulerSummary> {
        let schedules = SUPPORTED_SAMPLERS
            .iter()
            .map(|sampler_id| self.schedule_status(read, sampler_id))
            .collect::<CommandResult<Vec<_>>>()?;
        let mut status = self.status_snapshot_for(&schedules);
        status.audit_refs = self
            .audit_entries
            .iter()
            .rev()
            .take(sentinel_contracts::MAX_NATIVE_SCHEDULER_REFS)
            .map(|entry| entry.audit_id.clone())
            .collect();
        let summary = NativeSchedulerSummary {
            status,
            schedules,
            authorization_independent: true,
            activation_independent: true,
            enablement_independent: true,
            startup_auto_enablement: false,
            latest_cycle: self.cycles.last().cloned(),
            generated_at: Timestamp::now(),
        };
        summary.validate().map_err(contract_error)?;
        Ok(summary)
    }

    pub fn operational_summary(
        &self,
        read: &ReadOnlyCommandState,
    ) -> CommandResult<NativeSchedulerOperationalSummary> {
        let summary = self.summary(read)?;
        let latest_cycle = summary.latest_cycle.clone();
        let safe_persisted_schedules = summary
            .schedules
            .iter()
            .map(|schedule| {
                let persisted = NativeSchedulerSafePersistedSchedule {
                    sampler_id: schedule.contract.sampler_id.clone(),
                    sampler_category: schedule.contract.sampler_category.clone(),
                    schedule_enabled: schedule.contract.schedule_enabled,
                    interval_bucket: schedule.contract.interval_bucket.clone(),
                    timeout_bucket: schedule.contract.timeout_bucket.clone(),
                    retry_budget_bucket: schedule.contract.retry_budget_bucket.clone(),
                    provenance_id: PROVENANCE_ID.to_string(),
                    redaction_status: RedactionStatus::Redacted,
                };
                persisted.validate().map_err(contract_error)?;
                Ok(persisted)
            })
            .collect::<CommandResult<Vec<_>>>()?;
        let scheduler_refs = self
            .cycles
            .iter()
            .rev()
            .take(MAX_NATIVE_SCHEDULER_CYCLES)
            .map(|cycle| cycle.cycle_id.clone())
            .collect::<Vec<_>>();
        let freshness_refs = self
            .cycles
            .iter()
            .rev()
            .filter(|cycle| cycle.freshness.is_some())
            .take(MAX_NATIVE_SCHEDULER_CYCLES)
            .map(|cycle| cycle.cycle_id.clone())
            .collect::<Vec<_>>();
        let missed_sample_refs = self
            .cycles
            .iter()
            .rev()
            .filter(|cycle| cycle.missed_sample.is_some())
            .take(MAX_NATIVE_SCHEDULER_CYCLES)
            .map(|cycle| cycle.cycle_id.clone())
            .collect::<Vec<_>>();
        let retry_summary = scheduler_retry_summary(&self.cycles, &self.retry_attempts)?;
        let operational = NativeSchedulerOperationalSummary {
            scheduler_health: scheduler_health_state(&summary.status),
            status: summary.status,
            safe_persisted_schedules,
            freshness_summary: latest_cycle
                .as_ref()
                .and_then(|cycle| cycle.freshness.clone()),
            missed_sample_summary: latest_cycle
                .as_ref()
                .and_then(|cycle| cycle.missed_sample.clone()),
            retry_summary,
            backpressure_summary: latest_cycle
                .as_ref()
                .and_then(|cycle| cycle.backpressure.clone()),
            scheduler_refs,
            freshness_refs,
            missed_sample_refs,
            quality_refs: Vec::new(),
            safe_persistence_only: true,
            raw_native_data_persisted: false,
            runtime_subject_persisted: false,
            source_location_persisted: false,
            launch_text_persisted: false,
            machine_identifier_persisted: false,
            scheduler_enablement_started: false,
            provider_refresh_started: false,
            automatic_llm_calls: false,
            response_execution_started: false,
            generated_at: Timestamp::now(),
        };
        operational.validate().map_err(contract_error)?;
        Ok(operational)
    }

    fn status_snapshot(&self) -> NativeSchedulerStatus {
        self.status_snapshot_for(&self.schedules)
    }

    fn status_snapshot_for(
        &self,
        schedules: &[NativeSamplerScheduleStatus],
    ) -> NativeSchedulerStatus {
        scheduler_status_from_parts(
            &self.controller_state,
            schedules,
            &self.cycles,
            self.last_tick_monotonic_millis,
            self.graceful_shutdown_requested,
            &self.audit_entries,
        )
    }

    fn upsert_schedule(&mut self, status: NativeSamplerScheduleStatus) {
        if let Some(existing) = self
            .schedules
            .iter_mut()
            .find(|existing| existing.contract.sampler_id == status.contract.sampler_id)
        {
            *existing = status;
        } else {
            self.schedules.push(status);
        }
        self.schedules
            .sort_by(|left, right| left.contract.sampler_id.cmp(&right.contract.sampler_id));
    }

    fn publish_status(&mut self, status: &NativeSchedulerStatus) -> CommandResult<()> {
        self.publish(
            NATIVE_SCHEDULER_STATUS,
            status,
            "bounded native scheduler status",
        )
    }

    fn publish_audit(&mut self, audit: &NativeSchedulerAuditEntry) -> CommandResult<()> {
        self.publish(
            AUDIT_NATIVE_SCHEDULER,
            audit,
            "bounded native scheduler audit",
        )
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

fn schedule_status_from_parts(
    read: &ReadOnlyCommandState,
    schedules: &[NativeSamplerScheduleStatus],
    sampler_id: &str,
) -> CommandResult<NativeSamplerScheduleStatus> {
    if !SUPPORTED_SAMPLERS.contains(&sampler_id) {
        return Err(CoreError::new(
            ErrorCode::InvalidRequest,
            "native scheduler sampler was not found",
        )
        .with_severity(ErrorSeverity::Info)
        .with_redacted_details(json!({ "sampler_id": sampler_id })));
    }
    let runtime = NativeSamplerRuntime::status_from_read_state(read, sampler_id)?;
    let existing = schedules
        .iter()
        .find(|status| status.contract.sampler_id == sampler_id);
    let authorized = runtime.permission_state == NativePermissionState::GrantedSession;
    let activated = matches!(
        runtime.runtime_state,
        NativeSamplerRuntimeState::Active
            | NativeSamplerRuntimeState::Idle
            | NativeSamplerRuntimeState::Paused
    );
    let schedule_eligible = authorized
        && matches!(
            runtime.runtime_state,
            NativeSamplerRuntimeState::Active | NativeSamplerRuntimeState::Idle
        );
    let blocked_reason = if !authorized {
        Some("authorization_required".to_string())
    } else if runtime.runtime_state == NativeSamplerRuntimeState::Revoked {
        Some("authorization_revoked".to_string())
    } else if runtime.runtime_state == NativeSamplerRuntimeState::Paused {
        Some("sampler_runtime_paused".to_string())
    } else if !activated {
        Some("explicit_sampler_activation_required".to_string())
    } else {
        None
    };
    let mut contract = existing
        .map(|status| status.contract.clone())
        .unwrap_or_else(|| default_schedule_contract(sampler_id, runtime.category.clone()));
    if !schedule_eligible {
        contract.schedule_enabled = false;
    }
    let status = NativeSamplerScheduleStatus {
        contract,
        permission_state: runtime.permission_state,
        runtime_state: runtime.runtime_state,
        authorized,
        activated,
        schedule_eligible,
        blocked_reason,
        audit_refs: existing
            .map(|status| status.audit_refs.clone())
            .unwrap_or_default(),
    };
    status.validate().map_err(contract_error)?;
    Ok(status)
}

fn scheduler_status_from_parts(
    controller_state: &NativeSchedulerControllerState,
    schedules: &[NativeSamplerScheduleStatus],
    cycles: &[NativeSchedulerCycleSummary],
    last_tick_monotonic_millis: Option<u64>,
    graceful_shutdown_requested: bool,
    audit_entries: &[NativeSchedulerAuditEntry],
) -> NativeSchedulerStatus {
    let enabled_schedule_count = schedules
        .iter()
        .filter(|schedule| schedule.contract.schedule_enabled)
        .count() as u32;
    let latest_backpressure = cycles
        .iter()
        .rev()
        .filter_map(|cycle| cycle.backpressure.as_ref())
        .find(|summary| summary.state != NativeSchedulerBackpressureState::None);
    let latest_freshness = cycles
        .iter()
        .rev()
        .find_map(|cycle| cycle.freshness.as_ref());
    let latest_missed_sample = cycles
        .iter()
        .rev()
        .find_map(|cycle| cycle.missed_sample.as_ref());
    NativeSchedulerStatus {
        controller_state: controller_state.clone(),
        periodic_sampling_enabled: enabled_schedule_count > 0,
        enabled_schedule_count,
        eligible_schedule_count: schedules
            .iter()
            .filter(|schedule| schedule.schedule_eligible)
            .count() as u32,
        revoked_schedule_count: schedules
            .iter()
            .filter(|schedule| schedule.permission_state == NativePermissionState::Revoked)
            .count() as u32,
        scheduling_loop_implemented: true,
        scheduling_loop_active: *controller_state == NativeSchedulerControllerState::Running
            && enabled_schedule_count > 0,
        backpressure_state: latest_backpressure
            .map(|summary| summary.state.clone())
            .unwrap_or(NativeSchedulerBackpressureState::None),
        backpressure_cycle_count: cycles
            .iter()
            .filter_map(|cycle| cycle.backpressure.as_ref())
            .filter(|summary| summary.state != NativeSchedulerBackpressureState::None)
            .count() as u32,
        latest_backpressure_cycle_id: latest_backpressure.map(|summary| summary.cycle_id.clone()),
        freshness_stale_dimension_count: latest_freshness
            .map(|summary| summary.stale_dimension_count)
            .unwrap_or(0),
        freshness_missing_dimension_count: latest_freshness
            .map(|summary| {
                summary
                    .missing_dimension_count
                    .saturating_add(summary.unavailable_dimension_count)
                    .saturating_add(summary.revoked_dimension_count)
            })
            .unwrap_or(0),
        missed_sample_dimension_count: latest_missed_sample
            .map(|summary| {
                summary
                    .delayed_dimension_count
                    .saturating_add(summary.missed_once_dimension_count)
                    .saturating_add(summary.repeatedly_missed_dimension_count)
                    .saturating_add(summary.paused_dimension_count)
                    .saturating_add(summary.blocked_dimension_count)
                    .saturating_add(summary.revoked_dimension_count)
            })
            .unwrap_or(0),
        latest_freshness_cycle_id: latest_freshness.map(|summary| summary.cycle_id.clone()),
        latest_missed_sample_cycle_id: latest_missed_sample.map(|summary| summary.cycle_id.clone()),
        periodic_execution_started: false,
        sample_requested: false,
        retry_execution_started: false,
        graceful_shutdown_requested,
        cycle_count: cycles.len() as u32,
        completed_cycle_count: cycles
            .iter()
            .filter(|cycle| cycle.cycle_state == NativeSchedulerCycleState::Completed)
            .count() as u32,
        skipped_cycle_count: cycles
            .iter()
            .filter(|cycle| cycle.cycle_state == NativeSchedulerCycleState::Skipped)
            .count() as u32,
        latest_cycle_id: cycles.last().map(|cycle| cycle.cycle_id.clone()),
        last_tick_monotonic_millis,
        automatic_llm_calls: false,
        response_execution_started: false,
        emitted_topics: vec![NATIVE_SCHEDULER_STATUS.to_string()],
        audit_refs: audit_entries
            .iter()
            .rev()
            .take(sentinel_contracts::MAX_NATIVE_SCHEDULER_REFS)
            .map(|entry| entry.audit_id.clone())
            .collect(),
        provenance_id: PROVENANCE_ID.to_string(),
        redaction_status: RedactionStatus::Redacted,
        generated_at: Timestamp::now(),
    }
}

fn operational_summary_from_parts(
    summary: NativeSchedulerSummary,
    cycles: &[NativeSchedulerCycleSummary],
    retry_attempts: &BTreeMap<String, u32>,
) -> CommandResult<NativeSchedulerOperationalSummary> {
    let latest_cycle = summary.latest_cycle.clone();
    let safe_persisted_schedules = summary
        .schedules
        .iter()
        .map(|schedule| {
            let persisted = NativeSchedulerSafePersistedSchedule {
                sampler_id: schedule.contract.sampler_id.clone(),
                sampler_category: schedule.contract.sampler_category.clone(),
                schedule_enabled: schedule.contract.schedule_enabled,
                interval_bucket: schedule.contract.interval_bucket.clone(),
                timeout_bucket: schedule.contract.timeout_bucket.clone(),
                retry_budget_bucket: schedule.contract.retry_budget_bucket.clone(),
                provenance_id: PROVENANCE_ID.to_string(),
                redaction_status: RedactionStatus::Redacted,
            };
            persisted.validate().map_err(contract_error)?;
            Ok(persisted)
        })
        .collect::<CommandResult<Vec<_>>>()?;
    let operational = NativeSchedulerOperationalSummary {
        scheduler_health: scheduler_health_state(&summary.status),
        status: summary.status,
        safe_persisted_schedules,
        freshness_summary: latest_cycle
            .as_ref()
            .and_then(|cycle| cycle.freshness.clone()),
        missed_sample_summary: latest_cycle
            .as_ref()
            .and_then(|cycle| cycle.missed_sample.clone()),
        retry_summary: scheduler_retry_summary(cycles, retry_attempts)?,
        backpressure_summary: latest_cycle
            .as_ref()
            .and_then(|cycle| cycle.backpressure.clone()),
        scheduler_refs: cycles
            .iter()
            .rev()
            .take(MAX_NATIVE_SCHEDULER_CYCLES)
            .map(|cycle| cycle.cycle_id.clone())
            .collect(),
        freshness_refs: cycles
            .iter()
            .rev()
            .filter(|cycle| cycle.freshness.is_some())
            .take(MAX_NATIVE_SCHEDULER_CYCLES)
            .map(|cycle| cycle.cycle_id.clone())
            .collect(),
        missed_sample_refs: cycles
            .iter()
            .rev()
            .filter(|cycle| cycle.missed_sample.is_some())
            .take(MAX_NATIVE_SCHEDULER_CYCLES)
            .map(|cycle| cycle.cycle_id.clone())
            .collect(),
        quality_refs: Vec::new(),
        safe_persistence_only: true,
        raw_native_data_persisted: false,
        runtime_subject_persisted: false,
        source_location_persisted: false,
        launch_text_persisted: false,
        machine_identifier_persisted: false,
        scheduler_enablement_started: false,
        provider_refresh_started: false,
        automatic_llm_calls: false,
        response_execution_started: false,
        generated_at: Timestamp::now(),
    };
    operational.validate().map_err(contract_error)?;
    Ok(operational)
}

fn default_schedule_contract(
    sampler_id: &str,
    sampler_category: NativeSamplerCategory,
) -> NativeSamplerScheduleContract {
    NativeSamplerScheduleContract {
        sampler_id: sampler_id.to_string(),
        sampler_category,
        schedule_enabled: false,
        interval_bucket: NativeScheduleIntervalBucket::FiveMinutes,
        timeout_bucket: NativeScheduleTimeoutBucket::FiveSeconds,
        retry_budget_bucket: NativeScheduleRetryBudgetBucket::One,
        max_records: DEFAULT_MAX_RECORDS,
        max_bytes: DEFAULT_MAX_BYTES,
        declared_topics: NATIVE_SCHEDULER_ALLOWED_TOPICS
            .iter()
            .map(|topic| (*topic).to_string())
            .collect(),
        retention_mode: NativeSamplerRetentionModeCategory::NoRawRetention,
        provenance_id: PROVENANCE_ID.to_string(),
        redaction_status: RedactionStatus::Redacted,
    }
}

fn required_sampler_id(request: &NativeSchedulerActionRequest) -> CommandResult<&str> {
    request
        .sampler_id
        .as_deref()
        .ok_or_else(|| CoreError::validation_failure("native scheduler action requires sampler id"))
}

fn state_after_schedule_change(
    schedules: &[NativeSamplerScheduleStatus],
) -> NativeSchedulerControllerState {
    if schedules
        .iter()
        .any(|schedule| schedule.contract.schedule_enabled)
    {
        NativeSchedulerControllerState::Running
    } else if schedules.iter().any(|schedule| schedule.schedule_eligible) {
        NativeSchedulerControllerState::Ready
    } else {
        NativeSchedulerControllerState::Disabled
    }
}

fn scheduler_audit_entry(
    request: &NativeSchedulerActionRequest,
    state: &NativeSchedulerControllerState,
) -> NativeSchedulerAuditEntry {
    NativeSchedulerAuditEntry {
        audit_id: AuditId::new_v4(),
        sampler_id: request.sampler_id.clone(),
        action: request.action.clone(),
        resulting_controller_state: state.clone(),
        time_bucket: CURRENT_SESSION_BUCKET.to_string(),
        provenance_id: PROVENANCE_ID.to_string(),
        summary_redacted: format!("native_scheduler_action_{:?}", request.action)
            .to_ascii_lowercase(),
    }
}

fn scheduler_tick_audit(
    state: &NativeSchedulerControllerState,
    skip_reason: Option<&str>,
) -> NativeSchedulerAuditEntry {
    NativeSchedulerAuditEntry {
        audit_id: AuditId::new_v4(),
        sampler_id: None,
        action: NativeSchedulerAction::RunTick,
        resulting_controller_state: state.clone(),
        time_bucket: CURRENT_SESSION_BUCKET.to_string(),
        provenance_id: PROVENANCE_ID.to_string(),
        summary_redacted: skip_reason
            .map(|reason| format!("native_scheduler_cycle_skipped_{reason}"))
            .unwrap_or_else(|| "native_scheduler_cycle_completed".to_string()),
    }
}

fn interval_millis(bucket: &NativeScheduleIntervalBucket) -> u64 {
    match bucket {
        NativeScheduleIntervalBucket::OneMinute => 60_000,
        NativeScheduleIntervalBucket::FiveMinutes => 300_000,
        NativeScheduleIntervalBucket::FifteenMinutes => 900_000,
        NativeScheduleIntervalBucket::Hourly => 3_600_000,
    }
}

fn timeout_millis(bucket: &NativeScheduleTimeoutBucket) -> u32 {
    match bucket {
        NativeScheduleTimeoutBucket::OneSecond => 1_000,
        NativeScheduleTimeoutBucket::FiveSeconds => 5_000,
        NativeScheduleTimeoutBucket::FifteenSeconds => 15_000,
        NativeScheduleTimeoutBucket::ThirtySeconds => 30_000,
    }
}

#[derive(Clone, Debug)]
struct ExecutionControlDecision {
    retryable: bool,
    retry_scheduled: bool,
    retry_exhausted: bool,
    retry_attempt: u32,
    retry_budget: u32,
    retry_delay_millis: u64,
    overlap_prevented: bool,
    timeout_enforced: bool,
    cancellation_requested: bool,
}

impl ExecutionControlDecision {
    fn none(retry_budget: u32) -> Self {
        Self {
            retryable: false,
            retry_scheduled: false,
            retry_exhausted: false,
            retry_attempt: 0,
            retry_budget,
            retry_delay_millis: 0,
            overlap_prevented: false,
            timeout_enforced: false,
            cancellation_requested: false,
        }
    }

    fn retryable(
        retry_attempt: u32,
        retry_budget: u32,
        retry_delay_millis: u64,
        retry_scheduled: bool,
    ) -> Self {
        Self {
            retryable: true,
            retry_scheduled,
            retry_exhausted: !retry_scheduled,
            retry_attempt,
            retry_budget,
            retry_delay_millis: if retry_scheduled {
                retry_delay_millis
            } else {
                0
            },
            overlap_prevented: false,
            timeout_enforced: false,
            cancellation_requested: false,
        }
    }

    fn with_overlap_prevented(mut self) -> Self {
        self.overlap_prevented = true;
        self
    }

    fn with_timeout_enforced(mut self) -> Self {
        self.timeout_enforced = true;
        self
    }
}

fn completed_sampler_result(
    sampler_id: &str,
    result: &NativeSamplerRuntimeActionResult,
    control: ExecutionControlDecision,
) -> CommandResult<NativeSchedulerSamplerCycleResult> {
    let cycle_result = NativeSchedulerSamplerCycleResult {
        sampler_id: sampler_id.to_string(),
        cycle_state: NativeSchedulerCycleState::Completed,
        skip_reason: None,
        batch_ref: result
            .latest_batch
            .as_ref()
            .map(|batch| batch.batch_id.clone()),
        fact_refs: result.status.fact_refs.clone(),
        audit_refs: vec![result.audit_entry.audit_id.clone()],
        runtime_validation_passed: true,
        event_bus_dispatched: true,
        dag_dispatched: true,
        plugin_runtime_dispatched: true,
        execution_control_applied: true,
        overlap_prevented: control.overlap_prevented,
        timeout_enforced: control.timeout_enforced,
        cancellation_requested: control.cancellation_requested,
        retryable: control.retryable,
        retry_scheduled: control.retry_scheduled,
        retry_exhausted: control.retry_exhausted,
        retry_attempt: control.retry_attempt,
        retry_budget: control.retry_budget,
        retry_delay_millis: control.retry_delay_millis,
    };
    cycle_result.validate().map_err(contract_error)?;
    Ok(cycle_result)
}

fn skipped_sampler_result(
    sampler_id: &str,
    reason: &str,
    control: ExecutionControlDecision,
) -> CommandResult<NativeSchedulerSamplerCycleResult> {
    let cycle_result = NativeSchedulerSamplerCycleResult {
        sampler_id: sampler_id.to_string(),
        cycle_state: NativeSchedulerCycleState::Skipped,
        skip_reason: Some(reason.to_string()),
        batch_ref: None,
        fact_refs: Vec::new(),
        audit_refs: Vec::new(),
        runtime_validation_passed: false,
        event_bus_dispatched: false,
        dag_dispatched: false,
        plugin_runtime_dispatched: false,
        execution_control_applied: true,
        overlap_prevented: control.overlap_prevented,
        timeout_enforced: control.timeout_enforced,
        cancellation_requested: control.cancellation_requested,
        retryable: control.retryable,
        retry_scheduled: control.retry_scheduled,
        retry_exhausted: control.retry_exhausted,
        retry_attempt: control.retry_attempt,
        retry_budget: control.retry_budget,
        retry_delay_millis: control.retry_delay_millis,
    };
    cycle_result.validate().map_err(contract_error)?;
    Ok(cycle_result)
}

#[allow(clippy::too_many_arguments)]
fn cycle_summary(
    cycle_id: NativeSchedulerCycleId,
    cycle_state: NativeSchedulerCycleState,
    monotonic_elapsed_millis: u64,
    selected_sampler_ids: Vec<String>,
    sampler_results: Vec<NativeSchedulerSamplerCycleResult>,
    skip_reason: Option<&str>,
    execution_control: Option<NativeSchedulerExecutionControlSummary>,
    backpressure: Option<NativeSchedulerBackpressureSummary>,
    freshness: Option<NativeSchedulerFreshnessSummary>,
    missed_sample: Option<NativeSchedulerMissedSampleSummary>,
    emitted_topics: Vec<String>,
    audit_refs: Vec<AuditId>,
    graceful_shutdown_requested: bool,
) -> CommandResult<NativeSchedulerCycleSummary> {
    let summary = NativeSchedulerCycleSummary {
        cycle_id,
        cycle_state,
        monotonic_elapsed_millis,
        selected_sampler_ids,
        completed_sampler_count: sampler_results
            .iter()
            .filter(|result| result.cycle_state == NativeSchedulerCycleState::Completed)
            .count() as u32,
        skipped_sampler_count: sampler_results
            .iter()
            .filter(|result| result.cycle_state == NativeSchedulerCycleState::Skipped)
            .count() as u32,
        sampler_results,
        skip_reason: skip_reason.map(str::to_string),
        execution_control,
        backpressure,
        freshness,
        missed_sample,
        emitted_topics,
        audit_refs,
        provenance_id: PROVENANCE_ID.to_string(),
        redaction_status: RedactionStatus::Redacted,
        graceful_shutdown_requested,
        retry_execution_started: false,
        automatic_llm_calls: false,
        response_execution_started: false,
    };
    summary.validate().map_err(contract_error)?;
    Ok(summary)
}

#[allow(clippy::too_many_arguments)]
fn execution_control_summary(
    cycle_id: NativeSchedulerCycleId,
    request: &NativeSchedulerTickRequest,
    selected_sampler_ids: Vec<String>,
    sampler_results: &[NativeSchedulerSamplerCycleResult],
    active_execution_count: u32,
) -> CommandResult<NativeSchedulerExecutionControlSummary> {
    let summary = NativeSchedulerExecutionControlSummary {
        cycle_id,
        global_concurrency_limit: request.global_concurrency_limit,
        per_category_concurrency_limit: request.per_category_concurrency_limit,
        active_execution_count,
        selected_sampler_ids,
        overlap_prevented_count: sampler_results
            .iter()
            .filter(|result| result.overlap_prevented)
            .count() as u32,
        timeout_enforced_count: sampler_results
            .iter()
            .filter(|result| result.timeout_enforced)
            .count() as u32,
        cancellation_requested: request.cancellation_requested
            || sampler_results
                .iter()
                .any(|result| result.cancellation_requested),
        retry_scheduled_count: sampler_results
            .iter()
            .filter(|result| result.retry_scheduled)
            .count() as u32,
        retry_exhausted_count: sampler_results
            .iter()
            .filter(|result| result.retry_exhausted)
            .count() as u32,
        provider_timeout_millis: request.provider_timeout_millis,
        execution_timeout_millis: request.execution_timeout_millis,
        global_cycle_timeout_millis: request.global_cycle_timeout_millis,
        retry_delay_millis: request.retry_delay_millis,
        emitted_topics: vec![NATIVE_SCHEDULER_EXECUTION_CONTROL.to_string()],
        provenance_id: PROVENANCE_ID.to_string(),
        redaction_status: RedactionStatus::Redacted,
        automatic_llm_calls: false,
        response_execution_started: false,
    };
    summary.validate().map_err(contract_error)?;
    Ok(summary)
}

#[derive(Clone, Debug)]
struct DimensionSuccess {
    monotonic_elapsed_millis: u64,
    batch: NativeSamplerRuntimeBatch,
}

fn freshness_dimensions() -> Vec<NativeTelemetryDimension> {
    vec![
        NativeTelemetryDimension::Health,
        NativeTelemetryDimension::Service,
        NativeTelemetryDimension::Process,
        NativeTelemetryDimension::ParentCategory,
    ]
}

fn sampler_id_for_dimension(dimension: &NativeTelemetryDimension) -> &'static str {
    match dimension {
        NativeTelemetryDimension::Health => "native_health_probe_sampler",
        NativeTelemetryDimension::Service => "service_metadata_sampler",
        NativeTelemetryDimension::Process | NativeTelemetryDimension::ParentCategory => {
            "process_metadata_sampler"
        }
    }
}

fn batch_supports_dimension(
    read: &ReadOnlyCommandState,
    batch_ref: &NativeSamplerBatchId,
    dimension: &NativeTelemetryDimension,
) -> bool {
    read.native_sampler_runtime_batches
        .iter()
        .find(|batch| &batch.batch_id == batch_ref)
        .is_some_and(|batch| match dimension {
            NativeTelemetryDimension::Health => batch.health_record.is_some(),
            NativeTelemetryDimension::Service => !batch.service_records.is_empty(),
            NativeTelemetryDimension::Process => !batch.process_records.is_empty(),
            NativeTelemetryDimension::ParentCategory => batch
                .process_records
                .iter()
                .any(|record| record.parent_process_category != NativeProcessCategory::Unknown),
        })
}

fn freshness_state_for_dimension(
    schedule: Option<&NativeSamplerScheduleStatus>,
    last_success: Option<&DimensionSuccess>,
    monotonic_elapsed_millis: u64,
    interval_millis: u64,
    dimension: &NativeTelemetryDimension,
) -> NativeTelemetryFreshnessState {
    if schedule.is_some_and(|schedule| {
        schedule.permission_state == NativePermissionState::Revoked
            || schedule.runtime_state == NativeSamplerRuntimeState::Revoked
    }) {
        return NativeTelemetryFreshnessState::Revoked;
    }
    if schedule.is_some_and(|schedule| {
        matches!(
            schedule.runtime_state,
            NativeSamplerRuntimeState::Failed
                | NativeSamplerRuntimeState::NotImplemented
                | NativeSamplerRuntimeState::ReadinessBlocked
        )
    }) {
        return NativeTelemetryFreshnessState::Unavailable;
    }
    let Some(success) = last_success else {
        return match dimension {
            NativeTelemetryDimension::ParentCategory => NativeTelemetryFreshnessState::Missing,
            _ => NativeTelemetryFreshnessState::Missing,
        };
    };
    let age = monotonic_elapsed_millis.saturating_sub(success.monotonic_elapsed_millis);
    if age <= interval_millis {
        NativeTelemetryFreshnessState::Fresh
    } else if age <= interval_millis.saturating_mul(2) {
        NativeTelemetryFreshnessState::Aging
    } else {
        NativeTelemetryFreshnessState::Stale
    }
}

fn age_bucket_for(
    monotonic_elapsed_millis: u64,
    last_success_monotonic_millis: Option<u64>,
    interval_millis: u64,
) -> String {
    let Some(last_success) = last_success_monotonic_millis else {
        return "missing".to_string();
    };
    let age = monotonic_elapsed_millis.saturating_sub(last_success);
    if age <= interval_millis {
        "fresh_window"
    } else if age <= interval_millis.saturating_mul(2) {
        "aging_window"
    } else if age <= interval_millis.saturating_mul(4) {
        "stale_window"
    } else {
        "long_stale_window"
    }
    .to_string()
}

fn source_reliability_bucket_for(state: &NativeTelemetryFreshnessState) -> &'static str {
    match state {
        NativeTelemetryFreshnessState::Fresh => "stable",
        NativeTelemetryFreshnessState::Aging => "degraded",
        NativeTelemetryFreshnessState::Stale
        | NativeTelemetryFreshnessState::Missing
        | NativeTelemetryFreshnessState::Unavailable => "weak",
        NativeTelemetryFreshnessState::Revoked => "blocked",
    }
}

fn visibility_completeness_bucket_for(state: &NativeTelemetryFreshnessState) -> &'static str {
    match state {
        NativeTelemetryFreshnessState::Fresh | NativeTelemetryFreshnessState::Aging => "partial",
        NativeTelemetryFreshnessState::Stale => "degraded",
        NativeTelemetryFreshnessState::Missing => "metadata_only",
        NativeTelemetryFreshnessState::Unavailable => "unsupported",
        NativeTelemetryFreshnessState::Revoked => "blocked",
    }
}

fn evidence_quality_bucket_for(state: &NativeTelemetryFreshnessState) -> &'static str {
    match state {
        NativeTelemetryFreshnessState::Fresh => "medium",
        NativeTelemetryFreshnessState::Aging | NativeTelemetryFreshnessState::Stale => "low",
        NativeTelemetryFreshnessState::Missing | NativeTelemetryFreshnessState::Unavailable => {
            "unknown"
        }
        NativeTelemetryFreshnessState::Revoked => "blocked",
    }
}

fn degraded_reason_for_freshness(state: &NativeTelemetryFreshnessState) -> Option<String> {
    match state {
        NativeTelemetryFreshnessState::Fresh => None,
        NativeTelemetryFreshnessState::Aging => Some("native_visibility_aging".to_string()),
        NativeTelemetryFreshnessState::Stale => Some("native_visibility_stale".to_string()),
        NativeTelemetryFreshnessState::Missing => Some("native_visibility_missing".to_string()),
        NativeTelemetryFreshnessState::Unavailable => {
            Some("native_visibility_unavailable".to_string())
        }
        NativeTelemetryFreshnessState::Revoked => Some("native_visibility_revoked".to_string()),
    }
}

fn worst_freshness_state(
    dimensions: &[NativeTelemetryFreshnessDimensionSummary],
) -> NativeTelemetryFreshnessState {
    dimensions
        .iter()
        .map(|dimension| dimension.freshness_state.clone())
        .max_by_key(freshness_severity_rank)
        .unwrap_or(NativeTelemetryFreshnessState::Missing)
}

fn freshness_severity_rank(state: &NativeTelemetryFreshnessState) -> u8 {
    match state {
        NativeTelemetryFreshnessState::Fresh => 0,
        NativeTelemetryFreshnessState::Aging => 1,
        NativeTelemetryFreshnessState::Stale => 2,
        NativeTelemetryFreshnessState::Missing => 3,
        NativeTelemetryFreshnessState::Unavailable => 4,
        NativeTelemetryFreshnessState::Revoked => 5,
    }
}

fn missed_sample_state_for(
    controller_state: NativeSchedulerControllerState,
    dimension: &NativeTelemetryFreshnessDimensionSummary,
    monotonic_elapsed_millis: u64,
    interval_millis: u64,
) -> NativeMissedSampleState {
    if dimension.freshness_state == NativeTelemetryFreshnessState::Revoked {
        return NativeMissedSampleState::Revoked;
    }
    if matches!(
        controller_state,
        NativeSchedulerControllerState::Paused
            | NativeSchedulerControllerState::Stopping
            | NativeSchedulerControllerState::Stopped
            | NativeSchedulerControllerState::Disabled
    ) {
        return NativeMissedSampleState::Paused;
    }
    if matches!(
        dimension.freshness_state,
        NativeTelemetryFreshnessState::Missing | NativeTelemetryFreshnessState::Unavailable
    ) {
        return NativeMissedSampleState::Blocked;
    }
    let missed_intervals = missed_interval_count(
        monotonic_elapsed_millis,
        dimension.last_success_monotonic_millis,
        interval_millis,
    );
    match missed_intervals {
        0 | 1 => NativeMissedSampleState::OnTime,
        2 => NativeMissedSampleState::Delayed,
        3 => NativeMissedSampleState::MissedOnce,
        _ => NativeMissedSampleState::RepeatedlyMissed,
    }
}

fn missed_expected_count_bucket(
    monotonic_elapsed_millis: u64,
    last_success_monotonic_millis: Option<u64>,
    interval_millis: u64,
) -> String {
    match missed_interval_count(
        monotonic_elapsed_millis,
        last_success_monotonic_millis,
        interval_millis,
    ) {
        0 | 1 => "none",
        2 => "single",
        3 => "low",
        4..=8 => "medium",
        _ => "high",
    }
    .to_string()
}

fn missed_interval_count(
    monotonic_elapsed_millis: u64,
    last_success_monotonic_millis: Option<u64>,
    interval_millis: u64,
) -> u64 {
    let Some(last_success) = last_success_monotonic_millis else {
        return 0;
    };
    let bounded_interval = interval_millis.max(1);
    monotonic_elapsed_millis
        .saturating_sub(last_success)
        .saturating_add(bounded_interval - 1)
        / bounded_interval
}

fn classify_backpressure(
    request: &NativeSchedulerTickRequest,
    active_task_count: u32,
    pending_due_task_count: u32,
    timeout_rate_bucket: &str,
    overlap_skip_rate_bucket: &str,
) -> NativeSchedulerBackpressureState {
    let backlog_count = request
        .event_bus_backlog_count
        .max(request.dag_backlog_count);
    let allowed_due_count = request
        .max_samplers_per_tick
        .min(request.global_concurrency_limit)
        .max(1);
    let excess_due_count = pending_due_task_count.saturating_sub(allowed_due_count);
    let timeout_rank = pressure_bucket_rank(timeout_rate_bucket);
    let overlap_rank = pressure_bucket_rank(overlap_skip_rate_bucket);

    if backlog_count >= 96
        || timeout_rank >= 4
        || overlap_rank >= 4
        || (active_task_count >= request.global_concurrency_limit && pending_due_task_count > 0)
    {
        NativeSchedulerBackpressureState::Saturated
    } else if backlog_count >= 48 || timeout_rank >= 3 || overlap_rank >= 3 {
        NativeSchedulerBackpressureState::High
    } else if backlog_count >= 16 || active_task_count > 0 || timeout_rank >= 2 || overlap_rank >= 2
    {
        NativeSchedulerBackpressureState::Moderate
    } else if backlog_count > 0 || excess_due_count > 0 || timeout_rank >= 1 || overlap_rank >= 1 {
        NativeSchedulerBackpressureState::Low
    } else {
        NativeSchedulerBackpressureState::None
    }
}

fn scheduler_rate_bucket<F>(cycles: &[NativeSchedulerCycleSummary], predicate: F) -> String
where
    F: Fn(&NativeSchedulerSamplerCycleResult) -> bool,
{
    let mut total = 0u32;
    let mut matched = 0u32;
    for cycle in cycles.iter().rev().take(8) {
        for result in &cycle.sampler_results {
            total = total.saturating_add(1);
            if predicate(result) {
                matched = matched.saturating_add(1);
            }
        }
    }
    if total == 0 || matched == 0 {
        return "none".to_string();
    }
    if total < 4 {
        return "low".to_string();
    }
    match matched.saturating_mul(100) / total {
        0..=20 => "low",
        21..=45 => "moderate",
        46..=75 => "high",
        _ => "saturated",
    }
    .to_string()
}

fn scheduler_retry_summary(
    cycles: &[NativeSchedulerCycleSummary],
    retry_attempts: &BTreeMap<String, u32>,
) -> CommandResult<NativeSchedulerRetrySummary> {
    let retry_scheduled_count = cycles
        .iter()
        .flat_map(|cycle| cycle.sampler_results.iter())
        .filter(|result| result.retry_scheduled)
        .count() as u32;
    let retry_exhausted_count = cycles
        .iter()
        .flat_map(|cycle| cycle.sampler_results.iter())
        .filter(|result| result.retry_exhausted)
        .count() as u32;
    let retrying_sampler_ids = retry_attempts
        .keys()
        .take(MAX_NATIVE_SCHEDULES)
        .cloned()
        .collect::<Vec<_>>();
    let summary = NativeSchedulerRetrySummary {
        retry_scheduled_count,
        retry_exhausted_count,
        retry_pending_sampler_count: retrying_sampler_ids.len() as u32,
        latest_execution_control_cycle_id: cycles
            .iter()
            .rev()
            .find(|cycle| cycle.execution_control.is_some())
            .map(|cycle| cycle.cycle_id.clone()),
        retrying_sampler_ids,
        provenance_id: PROVENANCE_ID.to_string(),
        redaction_status: RedactionStatus::Redacted,
        automatic_llm_calls: false,
        response_execution_started: false,
    };
    summary.validate().map_err(contract_error)?;
    Ok(summary)
}

fn scheduler_health_state(status: &NativeSchedulerStatus) -> NativeSchedulerHealthState {
    match &status.controller_state {
        NativeSchedulerControllerState::Revoked => NativeSchedulerHealthState::Revoked,
        NativeSchedulerControllerState::Failed => NativeSchedulerHealthState::Failed,
        NativeSchedulerControllerState::Degraded => NativeSchedulerHealthState::Degraded,
        NativeSchedulerControllerState::Paused => NativeSchedulerHealthState::Paused,
        NativeSchedulerControllerState::Stopping
        | NativeSchedulerControllerState::Stopped
        | NativeSchedulerControllerState::Disabled => NativeSchedulerHealthState::Stopped,
        _ if matches!(
            status.backpressure_state,
            NativeSchedulerBackpressureState::High | NativeSchedulerBackpressureState::Saturated
        ) =>
        {
            NativeSchedulerHealthState::Backpressure
        }
        _ if status.scheduling_loop_active
            && status.freshness_stale_dimension_count == 0
            && status.freshness_missing_dimension_count == 0
            && status.missed_sample_dimension_count == 0 =>
        {
            NativeSchedulerHealthState::Healthy
        }
        _ => NativeSchedulerHealthState::Idle,
    }
}

fn pressure_bucket_rank(bucket: &str) -> u8 {
    match bucket {
        "low" => 1,
        "moderate" => 2,
        "high" => 3,
        "saturated" => 4,
        _ => 0,
    }
}

fn sampler_pressure_priority(category: &NativeSamplerCategory) -> u8 {
    match category {
        NativeSamplerCategory::NativeHealthProbeSampler => 0,
        NativeSamplerCategory::ServiceMetadataSampler => 1,
        NativeSamplerCategory::ProcessMetadataSampler => 2,
        _ => 2,
    }
}

fn retry_budget(bucket: &NativeScheduleRetryBudgetBucket) -> u32 {
    match bucket {
        NativeScheduleRetryBudgetBucket::None => 0,
        NativeScheduleRetryBudgetBucket::One => 1,
        NativeScheduleRetryBudgetBucket::Two => 2,
        NativeScheduleRetryBudgetBucket::Three => 3,
    }
}

fn retryable_skip_reason(reason: &str) -> bool {
    matches!(
        reason,
        "temporary_unavailability"
            | "provider_timeout"
            | "execution_timeout"
            | "global_cycle_timeout"
            | "transient_busy_state"
            | "global_concurrency_limit"
            | "per_category_concurrency_limit"
    )
}

fn sampler_category_key(category: &NativeSamplerCategory) -> String {
    format!("{category:?}").to_ascii_lowercase()
}

fn runtime_result_is_temporarily_unavailable(result: &NativeSamplerRuntimeActionResult) -> bool {
    result.status.provider_availability_state != NativeProviderAvailabilityState::Available
        || result
            .latest_batch
            .as_ref()
            .is_some_and(|batch| batch.counters.timeout_count > 0)
}

fn bound_audits(values: &mut Vec<NativeSchedulerAuditEntry>) {
    if values.len() > sentinel_contracts::MAX_NATIVE_SCHEDULER_REFS {
        values.drain(0..values.len() - sentinel_contracts::MAX_NATIVE_SCHEDULER_REFS);
    }
}

fn invalid_transition(action: &str, state: &NativeSchedulerControllerState) -> CoreError {
    CoreError::new(
        ErrorCode::InvalidRequest,
        "native scheduler state transition is not allowed",
    )
    .with_severity(ErrorSeverity::Warning)
    .with_redacted_details(json!({ "action": action, "controller_state": state }))
}

fn contract_error(error: impl std::fmt::Display) -> CoreError {
    CoreError::validation_failure("native scheduler contract validation failed")
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn internal_error(error: impl std::fmt::Display) -> CoreError {
    CoreError::new(
        ErrorCode::InternalError,
        "native scheduler control-plane operation failed",
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
        NativeSamplerRuntimeActionRequest,
    };

    fn grant(read: &mut ReadOnlyCommandState, capability_id: &str) {
        let mut permissions = AuthorizedNativePermissionRuntime::from_read_state(read);
        permissions
            .apply_action(NativePermissionActionRequest {
                capability_id: capability_id.to_string(),
                action: NativePermissionAction::GrantAuthorization,
                explicit_user_action: true,
                reason_redacted: "authorize native scheduler test".to_string(),
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
                    reason_redacted: "activate native scheduler test".to_string(),
                },
            )
            .expect("activate");
    }

    fn request(
        sampler_id: Option<&str>,
        action: NativeSchedulerAction,
    ) -> NativeSchedulerActionRequest {
        NativeSchedulerActionRequest {
            sampler_id: sampler_id.map(str::to_string),
            action,
            explicit_user_action: true,
            interval_bucket: NativeScheduleIntervalBucket::FiveMinutes,
            timeout_bucket: NativeScheduleTimeoutBucket::FiveSeconds,
            retry_budget_bucket: NativeScheduleRetryBudgetBucket::One,
            max_records: 128,
            max_bytes: 65_536,
            reason_redacted: "native scheduler control action".to_string(),
        }
    }

    fn tick_request(monotonic_elapsed_millis: u64) -> NativeSchedulerTickRequest {
        NativeSchedulerTickRequest {
            monotonic_elapsed_millis,
            max_samplers_per_tick: 3,
            global_concurrency_limit: 3,
            per_category_concurrency_limit: 1,
            provider_timeout_millis: 5_000,
            execution_timeout_millis: 5_000,
            global_cycle_timeout_millis: 30_000,
            retry_delay_millis: 1_000,
            event_bus_backlog_count: 0,
            dag_backlog_count: 0,
            cancellation_requested: false,
            reason_redacted: "bounded native scheduler test tick".to_string(),
        }
    }

    fn freshness_state_for_test(
        cycle: &NativeSchedulerCycleSummary,
        dimension: NativeTelemetryDimension,
    ) -> NativeTelemetryFreshnessState {
        cycle
            .freshness
            .as_ref()
            .expect("freshness")
            .dimensions
            .iter()
            .find(|entry| entry.dimension == dimension)
            .expect("freshness dimension")
            .freshness_state
            .clone()
    }

    fn missed_state_for_test(
        cycle: &NativeSchedulerCycleSummary,
        dimension: NativeTelemetryDimension,
    ) -> NativeMissedSampleState {
        cycle
            .missed_sample
            .as_ref()
            .expect("missed sample")
            .dimensions
            .iter()
            .find(|entry| entry.dimension == dimension)
            .expect("missed dimension")
            .missed_sample_state
            .clone()
    }

    #[test]
    fn authorization_activation_and_enablement_are_independent() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        let scheduler = NativeSchedulerController::from_read_state(&read);
        assert!(
            !scheduler
                .schedule_status(&read, "process_metadata_sampler")
                .expect("status")
                .authorized
        );

        grant(&mut read, "process_metadata_visibility");
        let scheduler = NativeSchedulerController::from_read_state(&read);
        let authorized = scheduler
            .schedule_status(&read, "process_metadata_sampler")
            .expect("authorized");
        assert!(authorized.authorized);
        assert!(!authorized.activated);
        assert!(!authorized.contract.schedule_enabled);

        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let combined_activation = runtime.apply_action(
            &mut read,
            NativeSamplerRuntimeActionRequest {
                sampler_id: "process_metadata_sampler".to_string(),
                action: NativeSamplerRuntimeAction::Activate,
                explicit_user_action: true,
                enable_interval_sampling: true,
                max_records_per_sample: 128,
                max_bytes_per_sample: 65_536,
                timeout_millis: 5_000,
                reason_redacted: "combined activation is prohibited".to_string(),
            },
        );
        assert!(combined_activation.is_err());

        activate(&mut read, "process_metadata_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        scheduler.reconcile(&read).expect("reconcile activation");
        assert_eq!(
            scheduler.controller_state,
            NativeSchedulerControllerState::Ready
        );
        let activated = scheduler
            .schedule_status(&read, "process_metadata_sampler")
            .expect("activated");
        assert!(activated.activated);
        assert!(activated.schedule_eligible);
        assert!(!activated.contract.schedule_enabled);

        let enabled = scheduler
            .apply_action(
                &mut read,
                request(
                    Some("process_metadata_sampler"),
                    NativeSchedulerAction::EnableSampler,
                ),
            )
            .expect("enable");
        assert!(enabled.status.periodic_sampling_enabled);
        assert!(!enabled.periodic_execution_started);
        assert!(!enabled.sample_requested);
    }

    #[test]
    fn preview_and_startup_create_no_scheduler_runtime_state() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        activate(&mut read, "native_health_probe_sampler");
        let scheduler = NativeSchedulerController::from_read_state(&read);
        let preview = scheduler
            .preview_enablement(&read, "native_health_probe_sampler")
            .expect("preview");
        assert!(preview.schedule_eligible);
        assert!(read.native_sampler_schedule_statuses.is_empty());
        assert_eq!(
            read.native_scheduler_controller_state,
            NativeSchedulerControllerState::Disabled
        );
        assert!(
            !scheduler
                .summary(&read)
                .expect("summary")
                .status
                .periodic_sampling_enabled
        );
    }

    #[test]
    fn revoke_removes_schedule_eligibility_without_sampling() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "service_metadata_visibility");
        activate(&mut read, "service_metadata_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        scheduler
            .apply_action(
                &mut read,
                request(
                    Some("service_metadata_sampler"),
                    NativeSchedulerAction::EnableSampler,
                ),
            )
            .expect("enable");

        let mut permissions = AuthorizedNativePermissionRuntime::from_read_state(&read);
        permissions
            .apply_action(NativePermissionActionRequest {
                capability_id: "service_metadata_visibility".to_string(),
                action: NativePermissionAction::RevokeAuthorization,
                explicit_user_action: true,
                reason_redacted: "revoke native scheduler test".to_string(),
            })
            .expect("revoke");
        permissions.sync_read_state(&mut read);
        for runtime in &mut read.native_sampler_runtime_statuses {
            if runtime.sampler_id == "service_metadata_sampler" {
                runtime.permission_state = NativePermissionState::Revoked;
                runtime.runtime_state = NativeSamplerRuntimeState::Revoked;
            }
        }

        scheduler.reconcile(&read).expect("reconcile");
        assert_eq!(
            scheduler.controller_state,
            NativeSchedulerControllerState::Degraded
        );
        let status = scheduler
            .schedule_status(&read, "service_metadata_sampler")
            .expect("status");
        assert!(!status.schedule_eligible);
        assert!(!status.contract.schedule_enabled);
        assert!(read.native_sampler_runtime_batches.is_empty());

        for capability_id in ["native_health_probe", "process_metadata_visibility"] {
            let mut permissions = AuthorizedNativePermissionRuntime::from_read_state(&read);
            permissions
                .apply_action(NativePermissionActionRequest {
                    capability_id: capability_id.to_string(),
                    action: NativePermissionAction::RevokeAuthorization,
                    explicit_user_action: true,
                    reason_redacted: "revoke remaining native scheduler test".to_string(),
                })
                .expect("revoke remaining");
            permissions.sync_read_state(&mut read);
        }
        scheduler.reconcile(&read).expect("reconcile all revoked");
        assert_eq!(
            scheduler.controller_state,
            NativeSchedulerControllerState::Revoked
        );
    }

    #[test]
    fn scheduler_state_machine_is_control_plane_only() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        activate(&mut read, "native_health_probe_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        let enabled = scheduler
            .apply_action(
                &mut read,
                request(
                    Some("native_health_probe_sampler"),
                    NativeSchedulerAction::EnableSampler,
                ),
            )
            .expect("enable");
        assert!(enabled.emitted_topics.iter().all(|topic| {
            sentinel_contracts::NATIVE_SCHEDULER_ALLOWED_TOPICS.contains(&topic.as_str())
        }));
        assert_eq!(
            scheduler.controller_state,
            NativeSchedulerControllerState::Running
        );
        scheduler
            .apply_action(&mut read, request(None, NativeSchedulerAction::Pause))
            .expect("pause");
        assert_eq!(
            scheduler.controller_state,
            NativeSchedulerControllerState::Paused
        );
        scheduler
            .apply_action(&mut read, request(None, NativeSchedulerAction::Resume))
            .expect("resume");
        scheduler
            .apply_action(&mut read, request(None, NativeSchedulerAction::BeginStop))
            .expect("begin stop");
        assert_eq!(
            scheduler.controller_state,
            NativeSchedulerControllerState::Stopping
        );
        scheduler
            .apply_action(
                &mut read,
                request(None, NativeSchedulerAction::CompleteStop),
            )
            .expect("complete stop");
        assert_eq!(
            scheduler.controller_state,
            NativeSchedulerControllerState::Stopped
        );
        assert!(read.native_sampler_runtime_batches.is_empty());
        let serialized = serde_json::to_string(&(
            read.native_sampler_schedule_statuses,
            read.native_scheduler_audit_entries,
        ))
        .expect("serialize");
        for forbidden in [
            "process_name",
            "command_line",
            "file_path",
            "username",
            "ip_address",
            "password",
            "token",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[test]
    fn due_cycles_execute_through_runtime_and_respect_intervals() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        activate(&mut read, "native_health_probe_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        let mut enable = request(
            Some("native_health_probe_sampler"),
            NativeSchedulerAction::EnableSampler,
        );
        enable.interval_bucket = NativeScheduleIntervalBucket::OneMinute;
        scheduler
            .apply_action(&mut read, enable)
            .expect("enable schedule");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);

        let first = scheduler
            .tick(&mut read, &mut runtime, tick_request(0))
            .expect("first due tick");
        assert_eq!(first.cycle_state, NativeSchedulerCycleState::Completed);
        assert_eq!(first.completed_sampler_count, 1);
        assert!(first.sampler_results[0].runtime_validation_passed);
        assert!(first.sampler_results[0].event_bus_dispatched);
        assert!(first.sampler_results[0].dag_dispatched);
        assert!(first.sampler_results[0].plugin_runtime_dispatched);
        assert!(first.emitted_topics.iter().all(|topic| {
            sentinel_contracts::NATIVE_SCHEDULER_ALLOWED_TOPICS.contains(&topic.as_str())
        }));
        let first_batch_count = read.native_sampler_runtime_batches.len();
        assert_eq!(first_batch_count, 1);

        let bounded = scheduler
            .tick(&mut read, &mut runtime, tick_request(100))
            .expect("bounded frequency tick");
        assert_eq!(
            bounded.skip_reason.as_deref(),
            Some("tick_frequency_bounded")
        );
        let early = scheduler
            .tick(&mut read, &mut runtime, tick_request(250))
            .expect("bounded early tick");
        assert_eq!(early.cycle_state, NativeSchedulerCycleState::Skipped);
        assert_eq!(early.skip_reason.as_deref(), Some("no_due_samplers"));
        assert_eq!(read.native_sampler_runtime_batches.len(), first_batch_count);

        let second = scheduler
            .tick(&mut read, &mut runtime, tick_request(60_000))
            .expect("second due tick");
        assert_eq!(second.cycle_state, NativeSchedulerCycleState::Completed);
        assert_eq!(
            read.native_sampler_runtime_batches.len(),
            first_batch_count + 1
        );
        let regressed = scheduler
            .tick(&mut read, &mut runtime, tick_request(59_000))
            .expect("regressed monotonic tick");
        assert_eq!(
            regressed.skip_reason.as_deref(),
            Some("monotonic_clock_regressed")
        );
        assert_eq!(
            read.native_sampler_runtime_batches.len(),
            first_batch_count + 1
        );

        let serialized = serde_json::to_string(&read.native_scheduler_cycles).expect("serialize");
        for forbidden in [
            "C:\\",
            "/home/",
            "full_path",
            "filename",
            "username",
            "email",
            "ip_address",
            "cookie",
            "credential",
            "password",
            "api_key",
            "tenant_id",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[test]
    fn revoke_and_stop_block_periodic_provider_calls() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "service_metadata_visibility");
        activate(&mut read, "service_metadata_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        scheduler
            .apply_action(
                &mut read,
                request(
                    Some("service_metadata_sampler"),
                    NativeSchedulerAction::EnableSampler,
                ),
            )
            .expect("enable schedule");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let first = scheduler
            .tick(&mut read, &mut runtime, tick_request(0))
            .expect("first tick");
        assert_eq!(first.cycle_state, NativeSchedulerCycleState::Completed);
        let batch_count = read.native_sampler_runtime_batches.len();

        runtime
            .apply_action(
                &mut read,
                NativeSamplerRuntimeActionRequest {
                    sampler_id: "service_metadata_sampler".to_string(),
                    action: NativeSamplerRuntimeAction::Revoke,
                    explicit_user_action: true,
                    enable_interval_sampling: false,
                    max_records_per_sample: 128,
                    max_bytes_per_sample: 65_536,
                    timeout_millis: 5_000,
                    reason_redacted: "revoke before periodic cycle".to_string(),
                },
            )
            .expect("revoke");
        let revoked = scheduler
            .tick(&mut read, &mut runtime, tick_request(300_000))
            .expect("revoked tick");
        assert_eq!(revoked.cycle_state, NativeSchedulerCycleState::Skipped);
        assert_eq!(read.native_sampler_runtime_batches.len(), batch_count);

        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "process_metadata_visibility");
        activate(&mut read, "process_metadata_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        scheduler
            .apply_action(
                &mut read,
                request(
                    Some("process_metadata_sampler"),
                    NativeSchedulerAction::EnableSampler,
                ),
            )
            .expect("enable schedule");
        scheduler
            .apply_action(&mut read, request(None, NativeSchedulerAction::BeginStop))
            .expect("begin stop");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let stopped = scheduler
            .tick(&mut read, &mut runtime, tick_request(0))
            .expect("stopped tick");
        assert_eq!(stopped.cycle_state, NativeSchedulerCycleState::Skipped);
        assert_eq!(
            stopped.skip_reason.as_deref(),
            Some("scheduler_not_running")
        );
        assert!(read.native_sampler_runtime_batches.is_empty());
    }

    #[test]
    fn scheduler_never_bypasses_runtime_gate_failures() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        activate(&mut read, "native_health_probe_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        scheduler
            .apply_action(
                &mut read,
                request(
                    Some("native_health_probe_sampler"),
                    NativeSchedulerAction::EnableSampler,
                ),
            )
            .expect("enable schedule");
        for status in &mut read.native_sampler_runtime_statuses {
            if status.sampler_id == "native_health_probe_sampler" {
                status.runtime_state = NativeSamplerRuntimeState::Paused;
            }
        }
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let cycle = scheduler
            .tick(&mut read, &mut runtime, tick_request(0))
            .expect("gate failure becomes skipped cycle");
        assert_eq!(cycle.cycle_state, NativeSchedulerCycleState::Skipped);
        assert!(read.native_sampler_runtime_batches.is_empty());
        assert!(cycle.sampler_results.iter().all(|result| {
            !result.runtime_validation_passed
                && !result.event_bus_dispatched
                && !result.dag_dispatched
                && !result.plugin_runtime_dispatched
        }));
    }

    #[test]
    fn scheduler_concurrency_prevents_duplicate_and_overlapping_execution() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        grant(&mut read, "service_metadata_visibility");
        grant(&mut read, "process_metadata_visibility");
        for sampler_id in [
            "native_health_probe_sampler",
            "service_metadata_sampler",
            "process_metadata_sampler",
        ] {
            activate(&mut read, sampler_id);
        }
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        for sampler_id in [
            "native_health_probe_sampler",
            "service_metadata_sampler",
            "process_metadata_sampler",
        ] {
            scheduler
                .apply_action(
                    &mut read,
                    request(Some(sampler_id), NativeSchedulerAction::EnableSampler),
                )
                .expect("enable schedule");
        }
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let mut limited = tick_request(0);
        limited.global_concurrency_limit = 1;
        let cycle = scheduler
            .tick(&mut read, &mut runtime, limited)
            .expect("limited concurrency tick");
        assert_eq!(cycle.completed_sampler_count, 1);
        assert_eq!(cycle.skipped_sampler_count, 2);
        assert_eq!(
            cycle
                .execution_control
                .as_ref()
                .expect("execution control")
                .retry_scheduled_count,
            2
        );
        assert!(
            cycle
                .sampler_results
                .iter()
                .filter(|result| {
                    result.skip_reason.as_deref() == Some("global_concurrency_limit")
                        && result.overlap_prevented
                        && result.retry_scheduled
                })
                .count()
                >= 2
        );

        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        activate(&mut read, "native_health_probe_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        scheduler
            .apply_action(
                &mut read,
                request(
                    Some("native_health_probe_sampler"),
                    NativeSchedulerAction::EnableSampler,
                ),
            )
            .expect("enable schedule");
        scheduler.mark_sampler_execution_active_for_test(
            "native_health_probe_sampler",
            NativeSamplerCategory::NativeHealthProbeSampler,
        );
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let busy = scheduler
            .tick(&mut read, &mut runtime, tick_request(0))
            .expect("busy tick");
        assert_eq!(busy.cycle_state, NativeSchedulerCycleState::Skipped);
        assert!(busy.sampler_results.iter().all(|result| {
            result.skip_reason.as_deref() == Some("transient_busy_state")
                && result.overlap_prevented
                && result.retry_scheduled
        }));
        assert!(read.native_sampler_runtime_batches.is_empty());
    }

    #[test]
    fn backlog_triggers_backpressure_and_defers_low_priority_samplers() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        grant(&mut read, "process_metadata_visibility");
        activate(&mut read, "native_health_probe_sampler");
        activate(&mut read, "process_metadata_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        for sampler_id in ["native_health_probe_sampler", "process_metadata_sampler"] {
            let mut enable = request(Some(sampler_id), NativeSchedulerAction::EnableSampler);
            enable.interval_bucket = NativeScheduleIntervalBucket::OneMinute;
            scheduler
                .apply_action(&mut read, enable)
                .expect("enable schedule");
        }
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let mut pressured = tick_request(0);
        pressured.event_bus_backlog_count = 24;
        let cycle = scheduler
            .tick(&mut read, &mut runtime, pressured)
            .expect("pressured tick");
        let backpressure = cycle.backpressure.as_ref().expect("backpressure summary");
        assert_eq!(
            backpressure.state,
            NativeSchedulerBackpressureState::Moderate
        );
        assert!(backpressure.defer_low_priority_samplers);
        assert_eq!(
            backpressure.deferred_sampler_ids,
            vec!["process_metadata_sampler".to_string()]
        );
        assert_eq!(cycle.completed_sampler_count, 1);
        let deferred = cycle
            .sampler_results
            .iter()
            .find(|result| result.sampler_id == "process_metadata_sampler")
            .expect("deferred result");
        assert_eq!(
            deferred.skip_reason.as_deref(),
            Some("backpressure_deferred")
        );
        assert!(!deferred.retry_scheduled);
        assert!(cycle.emitted_topics.iter().all(|topic| {
            sentinel_contracts::NATIVE_SCHEDULER_ALLOWED_TOPICS.contains(&topic.as_str())
        }));
        assert!(!cycle.automatic_llm_calls);
        assert!(!cycle.response_execution_started);
    }

    #[test]
    fn saturated_backpressure_skips_without_accumulating_catch_up_work() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        activate(&mut read, "native_health_probe_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        let mut enable = request(
            Some("native_health_probe_sampler"),
            NativeSchedulerAction::EnableSampler,
        );
        enable.interval_bucket = NativeScheduleIntervalBucket::OneMinute;
        scheduler
            .apply_action(&mut read, enable)
            .expect("enable schedule");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let mut saturated = tick_request(0);
        saturated.event_bus_backlog_count = 128;
        let skipped = scheduler
            .tick(&mut read, &mut runtime, saturated)
            .expect("saturated tick");
        assert_eq!(skipped.cycle_state, NativeSchedulerCycleState::Skipped);
        assert_eq!(
            skipped.skip_reason.as_deref(),
            Some("backpressure_saturated")
        );
        let backpressure = skipped.backpressure.as_ref().expect("backpressure summary");
        assert_eq!(
            backpressure.state,
            NativeSchedulerBackpressureState::Saturated
        );
        assert!(backpressure.skip_cycle);
        assert!(read.native_sampler_runtime_batches.is_empty());
        assert_eq!(
            scheduler
                .next_due_monotonic_millis
                .get("native_health_probe_sampler")
                .copied(),
            Some(60_000)
        );

        let no_catch_up = scheduler
            .tick(&mut read, &mut runtime, tick_request(250))
            .expect("post-pressure tick");
        assert_eq!(no_catch_up.skip_reason.as_deref(), Some("no_due_samplers"));
        assert!(read.native_sampler_runtime_batches.is_empty());
    }

    #[test]
    fn native_freshness_transitions_from_fresh_to_aging_to_stale() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        activate(&mut read, "native_health_probe_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        let mut enable = request(
            Some("native_health_probe_sampler"),
            NativeSchedulerAction::EnableSampler,
        );
        enable.interval_bucket = NativeScheduleIntervalBucket::OneMinute;
        scheduler
            .apply_action(&mut read, enable)
            .expect("enable schedule");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);

        let fresh = scheduler
            .tick(&mut read, &mut runtime, tick_request(0))
            .expect("fresh tick");
        assert_eq!(
            freshness_state_for_test(&fresh, NativeTelemetryDimension::Health),
            NativeTelemetryFreshnessState::Fresh
        );

        scheduler
            .apply_action(&mut read, request(None, NativeSchedulerAction::Pause))
            .expect("pause scheduler");
        let aging = scheduler
            .tick(&mut read, &mut runtime, tick_request(90_000))
            .expect("aging tick");
        assert_eq!(
            freshness_state_for_test(&aging, NativeTelemetryDimension::Health),
            NativeTelemetryFreshnessState::Aging
        );
        assert_eq!(
            missed_state_for_test(&aging, NativeTelemetryDimension::Health),
            NativeMissedSampleState::Paused
        );
        let stale = scheduler
            .tick(&mut read, &mut runtime, tick_request(180_000))
            .expect("stale tick");
        assert_eq!(
            freshness_state_for_test(&stale, NativeTelemetryDimension::Health),
            NativeTelemetryFreshnessState::Stale
        );
        assert!(
            !stale
                .freshness
                .as_ref()
                .expect("freshness")
                .attack_finding_generation_started
        );
        assert!(read.findings.items.is_empty());
    }

    #[test]
    fn stale_native_visibility_degrades_quality_without_attack_findings() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        activate(&mut read, "native_health_probe_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        let mut enable = request(
            Some("native_health_probe_sampler"),
            NativeSchedulerAction::EnableSampler,
        );
        enable.interval_bucket = NativeScheduleIntervalBucket::OneMinute;
        scheduler
            .apply_action(&mut read, enable)
            .expect("enable schedule");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        scheduler
            .tick(&mut read, &mut runtime, tick_request(0))
            .expect("fresh tick");
        scheduler
            .apply_action(&mut read, request(None, NativeSchedulerAction::Pause))
            .expect("pause scheduler");
        scheduler
            .tick(&mut read, &mut runtime, tick_request(180_000))
            .expect("stale tick");

        let quality = crate::evidence_quality::build_evidence_quality_summary(&read)
            .expect("quality summary");
        assert!(quality
            .degraded_reason_summary
            .iter()
            .any(|reason| reason == "native_health_native_visibility_stale"));
        assert!(quality
            .missing_visibility_flags
            .iter()
            .any(|flag| flag == "native_health_visibility_stale"));
        assert!(read.findings.items.is_empty());
    }

    #[test]
    fn missed_sample_tracking_progresses_without_generating_findings() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        activate(&mut read, "native_health_probe_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        let mut enable = request(
            Some("native_health_probe_sampler"),
            NativeSchedulerAction::EnableSampler,
        );
        enable.interval_bucket = NativeScheduleIntervalBucket::OneMinute;
        enable.retry_budget_bucket = NativeScheduleRetryBudgetBucket::Three;
        scheduler
            .apply_action(&mut read, enable)
            .expect("enable schedule");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        scheduler
            .tick(&mut read, &mut runtime, tick_request(0))
            .expect("fresh tick");
        let batch_count = read.native_sampler_runtime_batches.len();
        for monotonic in [60_000, 120_000, 180_000, 240_000] {
            let mut timeout = tick_request(monotonic);
            timeout.execution_timeout_millis = 1;
            scheduler
                .tick(&mut read, &mut runtime, timeout)
                .expect("timeout tick");
        }
        let latest = read
            .native_scheduler_cycles
            .last()
            .expect("latest cycle")
            .clone();
        assert_eq!(
            missed_state_for_test(&latest, NativeTelemetryDimension::Health),
            NativeMissedSampleState::RepeatedlyMissed
        );
        assert!(
            latest
                .missed_sample
                .as_ref()
                .expect("missed sample")
                .repeatedly_missed_dimension_count
                >= 1
        );
        assert_eq!(read.native_sampler_runtime_batches.len(), batch_count);
        assert!(read.findings.items.is_empty());
    }

    #[test]
    fn operational_summary_persists_only_safe_schedule_settings() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "service_metadata_visibility");
        activate(&mut read, "service_metadata_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        let mut enable = request(
            Some("service_metadata_sampler"),
            NativeSchedulerAction::EnableSampler,
        );
        enable.interval_bucket = NativeScheduleIntervalBucket::FifteenMinutes;
        enable.timeout_bucket = NativeScheduleTimeoutBucket::FifteenSeconds;
        enable.retry_budget_bucket = NativeScheduleRetryBudgetBucket::Two;
        scheduler
            .apply_action(&mut read, enable)
            .expect("enable schedule");

        let operational = scheduler
            .operational_summary(&read)
            .expect("operational summary");
        assert!(operational.safe_persistence_only);
        assert!(!operational.raw_native_data_persisted);
        assert!(!operational.runtime_subject_persisted);
        assert!(!operational.source_location_persisted);
        assert!(!operational.launch_text_persisted);
        assert!(!operational.machine_identifier_persisted);
        assert_eq!(operational.safe_persisted_schedules.len(), 3);
        let service_schedule = operational
            .safe_persisted_schedules
            .iter()
            .find(|schedule| schedule.sampler_id == "service_metadata_sampler")
            .expect("service schedule");
        assert!(service_schedule.schedule_enabled);
        assert_eq!(
            service_schedule.interval_bucket,
            NativeScheduleIntervalBucket::FifteenMinutes
        );
        assert_eq!(
            service_schedule.timeout_bucket,
            NativeScheduleTimeoutBucket::FifteenSeconds
        );
        assert_eq!(
            service_schedule.retry_budget_bucket,
            NativeScheduleRetryBudgetBucket::Two
        );
        let serialized =
            serde_json::to_string(&operational).expect("operational summary serializes");
        for marker in [
            "C:\\",
            "/users/",
            "process_id",
            "command_line",
            "api_key",
            "tenant_id",
        ] {
            assert!(
                !serialized.contains(marker),
                "operational summary leaked marker {marker}"
            );
        }
    }

    #[test]
    fn timeout_and_retry_budget_controls_are_enforced_without_tight_loops() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        activate(&mut read, "native_health_probe_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        let mut enable = request(
            Some("native_health_probe_sampler"),
            NativeSchedulerAction::EnableSampler,
        );
        enable.retry_budget_bucket = NativeScheduleRetryBudgetBucket::One;
        scheduler
            .apply_action(&mut read, enable)
            .expect("enable schedule");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let mut timeout = tick_request(0);
        timeout.execution_timeout_millis = 1;
        timeout.retry_delay_millis = 1_000;
        let first = scheduler
            .tick(&mut read, &mut runtime, timeout.clone())
            .expect("timeout tick");
        let first_result = first.sampler_results.first().expect("result");
        assert_eq!(
            first_result.skip_reason.as_deref(),
            Some("execution_timeout")
        );
        assert!(first_result.timeout_enforced);
        assert!(first_result.retry_scheduled);
        assert_eq!(first_result.retry_attempt, 1);
        assert_eq!(
            scheduler
                .next_due_monotonic_millis
                .get("native_health_probe_sampler")
                .copied(),
            Some(1_000)
        );
        assert!(read.native_sampler_runtime_batches.is_empty());

        timeout.monotonic_elapsed_millis = 1_000;
        let second = scheduler
            .tick(&mut read, &mut runtime, timeout)
            .expect("retry budget exhausted");
        let second_result = second.sampler_results.first().expect("result");
        assert!(second_result.timeout_enforced);
        assert!(second_result.retry_exhausted);
        assert!(!second_result.retry_scheduled);
        assert_eq!(second_result.retry_attempt, 1);
        assert!(read.native_sampler_runtime_batches.is_empty());
    }

    #[test]
    fn revoked_samplers_are_not_retried() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "service_metadata_visibility");
        activate(&mut read, "service_metadata_sampler");
        let mut scheduler = NativeSchedulerController::from_read_state(&read);
        scheduler
            .apply_action(
                &mut read,
                request(
                    Some("service_metadata_sampler"),
                    NativeSchedulerAction::EnableSampler,
                ),
            )
            .expect("enable schedule");
        for status in &mut read.native_sampler_runtime_statuses {
            if status.sampler_id == "service_metadata_sampler" {
                status.permission_state = NativePermissionState::Revoked;
                status.runtime_state = NativeSamplerRuntimeState::Revoked;
            }
        }
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let cycle = scheduler
            .tick(&mut read, &mut runtime, tick_request(0))
            .expect("revoked tick");
        assert_eq!(cycle.cycle_state, NativeSchedulerCycleState::Skipped);
        assert_eq!(
            cycle
                .execution_control
                .as_ref()
                .expect("execution control")
                .retry_scheduled_count,
            0
        );
        assert!(scheduler.retry_attempts.is_empty());
        assert!(read.native_sampler_runtime_batches.is_empty());
    }
}
