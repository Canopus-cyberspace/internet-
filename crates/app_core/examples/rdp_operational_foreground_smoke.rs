use sentinel_app_core::RuntimeContainerBuilder;
use sentinel_contracts::runtime_ownership::RuntimeShutdownState;
use sentinel_contracts::{
    EtwAuthorizationState, EtwLifecycleState, NetworkProviderControllerStatus, NetworkProviderKind,
    NetworkProviderLifecycleState, RedactionStatus,
};
use serde::Serialize;
use std::time::{Duration, Instant};

const SMOKE_WAIT: Duration = Duration::from_secs(12);

#[derive(Serialize)]
struct RdpOperationalSmokeReport {
    profile: &'static str,
    result: &'static str,
    honest_status: &'static str,
    blocked_reason: Option<String>,
    execution_context: &'static str,
    disabled_by_default: bool,
    activation_result: String,
    stop_result: String,
    lifecycle_state: String,
    authorization_state: String,
    provider_lifecycle_state: String,
    provider_implementation_state: String,
    provider_enabled: u32,
    channels_ready: u32,
    channels_unavailable: u32,
    raw_events: u32,
    schema_accepted: u32,
    schema_rejected: u32,
    malformed: u32,
    rate_limited: u32,
    queue_dropped: u32,
    duplicate_suppressed: u32,
    normalized_auth_observations: u32,
    normalized_remote_access_observations: u32,
    normalized_batches: u32,
    published_batches: u32,
    eventbus_publications: u32,
    dag_dispatches: u32,
    auth_detector_invocations: u32,
    auth_consumed: u32,
    remote_admin_invocations: u32,
    remote_admin_consumed: u32,
    lateral_invocations: u32,
    lateral_consumed: u32,
    outputs: u32,
    downstream_facts: u32,
    security_facts_refreshed: usize,
    evidence_quality_records: usize,
    latest_batch_cached: bool,
    latest_batch_observations: usize,
    provider_zero_rdp_only: bool,
    canonical_generation_updates: u64,
    read_only_side_effects: u32,
    process_network_attribution_available: bool,
    packet_visibility_available: bool,
    response_execution_allowed: bool,
    privacy_boundary_holds: bool,
    raw_value_exposure_detected: bool,
    provider_degraded_reason: Option<String>,
    clean_shutdown: bool,
    unjoined_workers: u32,
}

impl RdpOperationalSmokeReport {
    fn new() -> Self {
        Self {
            profile: "windows_rdp_operational_foreground",
            result: "blocked",
            honest_status: "blocked_by_env",
            blocked_reason: None,
            execution_context: "foreground_servicehost_owned_runtime",
            disabled_by_default: false,
            activation_result: "not_run".to_string(),
            stop_result: "not_run".to_string(),
            lifecycle_state: "unknown".to_string(),
            authorization_state: "unknown".to_string(),
            provider_lifecycle_state: "unknown".to_string(),
            provider_implementation_state: "unknown".to_string(),
            provider_enabled: 0,
            channels_ready: 0,
            channels_unavailable: 0,
            raw_events: 0,
            schema_accepted: 0,
            schema_rejected: 0,
            malformed: 0,
            rate_limited: 0,
            queue_dropped: 0,
            duplicate_suppressed: 0,
            normalized_auth_observations: 0,
            normalized_remote_access_observations: 0,
            normalized_batches: 0,
            published_batches: 0,
            eventbus_publications: 0,
            dag_dispatches: 0,
            auth_detector_invocations: 0,
            auth_consumed: 0,
            remote_admin_invocations: 0,
            remote_admin_consumed: 0,
            lateral_invocations: 0,
            lateral_consumed: 0,
            outputs: 0,
            downstream_facts: 0,
            security_facts_refreshed: 0,
            evidence_quality_records: 0,
            latest_batch_cached: false,
            latest_batch_observations: 0,
            provider_zero_rdp_only: false,
            canonical_generation_updates: 0,
            read_only_side_effects: 0,
            process_network_attribution_available: false,
            packet_visibility_available: false,
            response_execution_allowed: false,
            privacy_boundary_holds: true,
            raw_value_exposure_detected: false,
            provider_degraded_reason: None,
            clean_shutdown: false,
            unjoined_workers: 1,
        }
    }

    fn record_lifecycle(&mut self, status: &sentinel_contracts::EtwLifecycleStatus) {
        self.lifecycle_state = format!("{:?}", status.lifecycle_state).to_ascii_lowercase();
        self.authorization_state = format!("{:?}", status.authorization_state).to_ascii_lowercase();
        self.provider_enabled = self
            .provider_enabled
            .max(u32::from(status.provider_enabled));
        self.raw_events = self.raw_events.max(status.raw_event_count);
        self.normalized_auth_observations = self
            .normalized_auth_observations
            .max(status.normalized_event_count);
        self.normalized_remote_access_observations = self
            .normalized_remote_access_observations
            .max(status.normalized_event_count);
        self.schema_rejected = self.schema_rejected.max(status.schema_rejected_event_count);
        self.rate_limited = self.rate_limited.max(status.rate_limited_event_count);
        self.queue_dropped = self.queue_dropped.max(status.dropped_event_count);
        self.published_batches = self.published_batches.max(status.published_batch_count);
        self.eventbus_publications = self
            .eventbus_publications
            .max(status.eventbus_publication_count);
        self.downstream_facts = self.downstream_facts.max(status.security_fact_count);
        self.provider_degraded_reason = status.degraded_reason.clone();
        self.privacy_boundary_holds &= status.redaction_status == RedactionStatus::Redacted;
    }

    fn record_provider_status(&mut self, status: &NetworkProviderControllerStatus) {
        if let Some(provider) = status.provider(NetworkProviderKind::WindowsRdpOperational) {
            self.provider_lifecycle_state =
                format!("{:?}", provider.lifecycle_state).to_ascii_lowercase();
            self.provider_implementation_state =
                format!("{:?}", provider.implementation_state).to_ascii_lowercase();
            self.provider_degraded_reason = provider
                .degraded_reason
                .clone()
                .or_else(|| self.provider_degraded_reason.clone());
            self.privacy_boundary_holds &= provider.redaction_status == RedactionStatus::Redacted;
        }
        self.auth_detector_invocations = self.auth_detector_invocations.max(
            status
                .provider_zero
                .rdp_operational_auth_detector_invocations,
        );
        self.auth_consumed = self
            .auth_consumed
            .max(status.provider_zero.rdp_operational_auth_consumed);
        self.remote_admin_invocations = self.remote_admin_invocations.max(
            status
                .provider_zero
                .rdp_operational_remote_admin_invocations,
        );
        self.remote_admin_consumed = self
            .remote_admin_consumed
            .max(status.provider_zero.rdp_operational_remote_admin_consumed);
        self.lateral_invocations = self
            .lateral_invocations
            .max(status.provider_zero.rdp_operational_lateral_invocations);
        self.lateral_consumed = self
            .lateral_consumed
            .max(status.provider_zero.rdp_operational_lateral_consumed);
        self.downstream_facts = self
            .downstream_facts
            .max(status.provider_zero.rdp_operational_downstream_facts);
        self.provider_zero_rdp_only = status.provider_zero.rdp_operational_sensing_only();
    }

    fn record_latest_batch(
        &mut self,
        batch: &sentinel_contracts::WindowsAuthRemoteObservationBatch,
    ) {
        self.latest_batch_cached = true;
        self.latest_batch_observations =
            self.latest_batch_observations.max(batch.observations.len());
        self.channels_ready = self.channels_ready.max(batch.counters.channels_ready);
        self.channels_unavailable = self
            .channels_unavailable
            .max(batch.counters.channels_unavailable);
        self.raw_events = self.raw_events.max(batch.counters.raw_events_observed);
        self.schema_accepted = self.schema_accepted.max(batch.counters.schema_accepted);
        self.schema_rejected = self.schema_rejected.max(batch.counters.schema_rejected);
        self.malformed = self.malformed.max(batch.counters.malformed);
        self.rate_limited = self.rate_limited.max(batch.counters.rate_limited);
        self.queue_dropped = self.queue_dropped.max(batch.counters.queue_dropped);
        self.duplicate_suppressed = self
            .duplicate_suppressed
            .max(batch.counters.duplicate_suppressed);
        self.normalized_auth_observations = self
            .normalized_auth_observations
            .max(batch.counters.normalized_auth_observations);
        self.normalized_remote_access_observations = self
            .normalized_remote_access_observations
            .max(batch.counters.normalized_remote_access_observations);
        self.published_batches = self.published_batches.max(batch.counters.published_batches);
        self.eventbus_publications = self
            .eventbus_publications
            .max(batch.counters.eventbus_publications);
        self.dag_dispatches = self.dag_dispatches.max(batch.counters.dag_dispatches);
        self.auth_detector_invocations = self
            .auth_detector_invocations
            .max(batch.counters.auth_detector_invocations);
        self.auth_consumed = self.auth_consumed.max(batch.counters.auth_consumed);
        self.remote_admin_invocations = self
            .remote_admin_invocations
            .max(batch.counters.remote_admin_invocations);
        self.remote_admin_consumed = self
            .remote_admin_consumed
            .max(batch.counters.remote_admin_consumed);
        self.lateral_invocations = self
            .lateral_invocations
            .max(batch.counters.lateral_invocations);
        self.lateral_consumed = self.lateral_consumed.max(batch.counters.lateral_consumed);
        self.outputs = self.outputs.max(batch.counters.outputs);
        self.downstream_facts = self.downstream_facts.max(batch.counters.downstream_facts);
        self.provider_degraded_reason = batch
            .degraded_reason
            .clone()
            .or_else(|| self.provider_degraded_reason.clone());
        self.privacy_boundary_holds &= batch.redaction_status == RedactionStatus::Redacted
            && batch
                .observations
                .iter()
                .all(|observation| observation.redaction_status == RedactionStatus::Redacted);
    }

    fn mark_final_status(&mut self) {
        let real = self.disabled_by_default
            && self.provider_enabled > 0
            && self.raw_events > 0
            && self.schema_accepted > 0
            && self.normalized_auth_observations > 0
            && self.normalized_remote_access_observations > 0
            && self.normalized_batches > 0
            && self.published_batches > 0
            && self.eventbus_publications > 0
            && self.dag_dispatches > 0
            && self.auth_detector_invocations > 0
            && self.auth_consumed > 0
            && self.remote_admin_invocations > 0
            && self.remote_admin_consumed > 0
            && self.downstream_facts > 0
            && self.security_facts_refreshed > 0
            && self.provider_zero_rdp_only
            && self.canonical_generation_updates > 0
            && self.privacy_boundary_holds
            && self.clean_shutdown
            && self.unjoined_workers == 0
            && !self.response_execution_allowed
            && !self.process_network_attribution_available
            && !self.packet_visibility_available;

        if real {
            self.result = "pass";
            self.honest_status = "real";
            self.blocked_reason = None;
            return;
        }

        self.result = "blocked";
        self.honest_status = "blocked_by_env";
        self.blocked_reason = Some(if self.provider_enabled == 0 {
            self.provider_degraded_reason
                .clone()
                .unwrap_or_else(|| "rdp_operational_channels_unavailable_or_not_ready".to_string())
        } else if self.raw_events == 0 || self.normalized_batches == 0 {
            "rdp_operational_no_recent_terminal_services_events".to_string()
        } else if self.downstream_facts == 0 {
            "rdp_operational_downstream_consumption_not_observed".to_string()
        } else if !self.clean_shutdown || self.unjoined_workers != 0 {
            "rdp_operational_shutdown_join_not_observed".to_string()
        } else {
            "rdp_operational_live_realization_incomplete".to_string()
        });
    }
}

fn safe_reason(error: impl ToString) -> String {
    error
        .to_string()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_ascii_lowercase()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut report = RdpOperationalSmokeReport::new();
    let mut container = RuntimeContainerBuilder::for_service_host().build()?;
    let owner = container.owner_context().clone();
    let initial_generation = container
        .canonical_read_model_current_generation()
        .unwrap_or_default();

    if let Some(initial) = container.rdp_operational_sensing_lifecycle_status() {
        report.disabled_by_default = initial.lifecycle_state == EtwLifecycleState::Inactive
            && initial.authorization_state == EtwAuthorizationState::Required
            && !initial.provider_enabled;
        report.record_lifecycle(initial);
    }
    if let Some(status) = container.provider_controller_status() {
        report.record_provider_status(status);
    }

    match container.activate_rdp_operational_sensing(
        &owner,
        vec!["rdp_operational_foreground_smoke_authorization".to_string()],
    ) {
        Ok(status) => {
            report.record_provider_status(&status);
            if let Some(lifecycle) = container.rdp_operational_sensing_lifecycle_status() {
                report.record_lifecycle(lifecycle);
                report.activation_result =
                    format!("{:?}", lifecycle.lifecycle_state).to_ascii_lowercase();
            } else {
                report.activation_result = "status_unavailable".to_string();
            }
        }
        Err(error) => {
            report.activation_result = "error".to_string();
            report.blocked_reason = Some(safe_reason(error));
        }
    }

    let deadline = Instant::now() + SMOKE_WAIT;
    while Instant::now() < deadline {
        if container
            .rdp_operational_sensing_lifecycle_status()
            .is_some_and(|status| status.lifecycle_state == EtwLifecycleState::Active)
        {
            match container.pump_rdp_operational_sensing_live_batches() {
                Ok(pump) => {
                    report.normalized_batches = report
                        .normalized_batches
                        .saturating_add(pump.normalized_batches);
                    report.published_batches = report
                        .published_batches
                        .saturating_add(pump.published_batches);
                    report.eventbus_publications = report
                        .eventbus_publications
                        .saturating_add(pump.eventbus_publications);
                    report.dag_dispatches =
                        report.dag_dispatches.saturating_add(pump.dag_dispatches);
                    report.auth_detector_invocations = report
                        .auth_detector_invocations
                        .saturating_add(pump.auth_detector_invocations);
                    report.auth_consumed = report.auth_consumed.saturating_add(pump.auth_consumed);
                    report.remote_admin_invocations = report
                        .remote_admin_invocations
                        .saturating_add(pump.remote_admin_invocations);
                    report.remote_admin_consumed = report
                        .remote_admin_consumed
                        .saturating_add(pump.remote_admin_consumed);
                    report.lateral_invocations = report
                        .lateral_invocations
                        .saturating_add(pump.lateral_invocations);
                    report.lateral_consumed = report
                        .lateral_consumed
                        .saturating_add(pump.lateral_consumed);
                    report.outputs = report.outputs.saturating_add(pump.outputs);
                    report.downstream_facts = report
                        .downstream_facts
                        .saturating_add(pump.downstream_facts);
                    report.raw_events = report.raw_events.max(pump.raw_events);
                    report.normalized_auth_observations = report
                        .normalized_auth_observations
                        .max(pump.normalized_events);
                    report.normalized_remote_access_observations = report
                        .normalized_remote_access_observations
                        .max(pump.normalized_events);
                    report.queue_dropped = report.queue_dropped.max(pump.dropped_events);
                }
                Err(error) => {
                    report.blocked_reason = Some(safe_reason(error));
                    break;
                }
            }
        }
        if let Some(lifecycle) = container.rdp_operational_sensing_lifecycle_status() {
            report.record_lifecycle(lifecycle);
        }
        if let Some(status) = container.provider_controller_status() {
            report.record_provider_status(status);
        }
        if let Some(batch) = container.latest_rdp_operational_batch() {
            report.record_latest_batch(batch);
        }
        if report.normalized_batches > 0
            && report.eventbus_publications > 0
            && report.downstream_facts > 0
        {
            break;
        }
        let wait = container
            .rdp_operational_sensing_live_pump_wait_millis()
            .unwrap_or(250);
        std::thread::sleep(Duration::from_millis(wait));
    }

    if let Some(batch) = container.latest_rdp_operational_batch() {
        report.record_latest_batch(batch);
    }
    report.security_facts_refreshed = container.security_fact_count();
    report.evidence_quality_records = container.evidence_quality_record_count();

    match container.stop_rdp_operational_sensing(
        &owner,
        vec!["rdp_operational_foreground_smoke_stop".to_string()],
    ) {
        Ok(status) => {
            report.stop_result = "stopped".to_string();
            report.record_provider_status(&status);
            if let Some(lifecycle) = container.rdp_operational_sensing_lifecycle_status() {
                report.record_lifecycle(lifecycle);
            }
        }
        Err(error) => {
            report.stop_result = safe_reason(error);
        }
    }

    let final_generation = container
        .canonical_read_model_current_generation()
        .unwrap_or_default();
    report.canonical_generation_updates = final_generation.saturating_sub(initial_generation);

    match container.shutdown() {
        Ok(shutdown) => {
            report.clean_shutdown = shutdown.shutdown.state == RuntimeShutdownState::Completed;
            report.unjoined_workers = u32::from(!shutdown.shutdown.scheduler_host_joined);
        }
        Err(error) => {
            report.clean_shutdown = false;
            report.unjoined_workers = 1;
            report.blocked_reason = Some(safe_reason(error));
        }
    }

    if report.provider_lifecycle_state.is_empty() {
        report.provider_lifecycle_state =
            format!("{:?}", NetworkProviderLifecycleState::Inactive).to_ascii_lowercase();
    }
    report.mark_final_status();
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
