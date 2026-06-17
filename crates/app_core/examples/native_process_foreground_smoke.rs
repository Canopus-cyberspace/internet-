use sentinel_app_core::RuntimeContainerBuilder;
use sentinel_contracts::runtime_ownership::RuntimeShutdownState;
use sentinel_contracts::{
    NativePermissionState, NativeProcessCategory, NativeSamplerRuntimeAction,
};
use serde::Serialize;

#[derive(Serialize)]
struct NativeProcessSmokeReport {
    execution_context: &'static str,
    authorization_granted: bool,
    authorization_revoked: bool,
    provider_enabled: u32,
    raw_process_observations: u32,
    schema_accepted: u32,
    schema_rejected: u32,
    malformed: u32,
    rate_limited: u32,
    queue_dropped: u32,
    duplicate_suppressed: u32,
    normalized_observations: u32,
    process_category_aggregates: usize,
    parent_process_category_aggregates: usize,
    published_batches: u32,
    eventbus_publications: u32,
    dag_executions: u32,
    plugin_runtime_invocations: u32,
    native_fact_observations_consumed: u32,
    native_facts_produced: u32,
    security_facts_refreshed: usize,
    endpoint_threat_invocations: u32,
    endpoint_threat_observations_consumed: u32,
    endpoint_threat_outputs: u32,
    fusion_outputs: u32,
    evidence_quality_records: usize,
    risk_outputs: u32,
    settings_read_model_updates: u32,
    canonical_generation_updates: u64,
    provider_availability: String,
    provider_health: String,
    process_network_attribution_available: bool,
    packet_visibility_available: bool,
    response_execution_allowed: bool,
    clean_shutdown: bool,
    unjoined_workers: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut container = RuntimeContainerBuilder::for_service_host().build()?;
    let owner = container.owner_context().clone();
    let initial_generation = container
        .canonical_read_model_current_generation()
        .unwrap_or_default();

    let authorization = container.authorize_native_process_sampler(
        &owner,
        "foreground native process smoke authorization",
    )?;
    container.apply_native_process_sampler_action(
        &owner,
        NativeSamplerRuntimeAction::Activate,
        "foreground native process smoke activation",
    )?;
    let sampled = container.apply_native_process_sampler_action(
        &owner,
        NativeSamplerRuntimeAction::SampleNow,
        "foreground native process smoke sample",
    )?;
    let batch = sampled
        .latest_batch
        .ok_or("native process smoke produced no batch")?;
    let status = container
        .native_sampler_runtime_status("process_metadata_sampler")
        .ok_or("native process smoke produced no runtime status")?;
    let settings_read_model_updates = u32::from(
        status.latest_batch_id.as_ref() == Some(&batch.batch_id)
            && status.counters == batch.counters,
    );
    let security_facts_refreshed = container.security_fact_count();
    let evidence_quality_records = container.evidence_quality_record_count();
    let parent_process_category_aggregates = batch
        .process_records
        .iter()
        .filter(|record| record.parent_process_category != NativeProcessCategory::Unknown)
        .count();

    container.apply_native_process_sampler_action(
        &owner,
        NativeSamplerRuntimeAction::Stop,
        "foreground native process smoke stop",
    )?;
    let revoked = container.apply_native_process_sampler_action(
        &owner,
        NativeSamplerRuntimeAction::Revoke,
        "foreground native process smoke revoke",
    )?;
    let final_generation = container
        .canonical_read_model_current_generation()
        .unwrap_or_default();
    let shutdown = container.shutdown()?;

    let report = NativeProcessSmokeReport {
        execution_context: "foreground_servicehost_owned_runtime",
        authorization_granted: authorization.capability.permission_state
            == NativePermissionState::GrantedSession,
        authorization_revoked: revoked.status.permission_state == NativePermissionState::Revoked,
        provider_enabled: batch.counters.provider_enabled_count,
        raw_process_observations: batch.counters.raw_record_count,
        schema_accepted: batch.counters.schema_accepted_count,
        schema_rejected: batch.counters.schema_rejected_count,
        malformed: batch.counters.malformed_record_count,
        rate_limited: batch.counters.rate_limited_count,
        queue_dropped: batch.counters.queue_dropped_count,
        duplicate_suppressed: batch.counters.duplicate_suppressed_count,
        normalized_observations: batch.counters.normalized_record_count,
        process_category_aggregates: batch.process_records.len(),
        parent_process_category_aggregates,
        published_batches: batch.counters.published_batch_count,
        eventbus_publications: batch.counters.eventbus_publication_count,
        dag_executions: batch.counters.dag_dispatch_count,
        plugin_runtime_invocations: batch.counters.plugin_runtime_invocation_count,
        native_fact_observations_consumed: batch.counters.observations_consumed_count,
        native_facts_produced: batch.counters.facts_emitted_count,
        security_facts_refreshed,
        endpoint_threat_invocations: batch.counters.detector_consumer_invocation_count,
        endpoint_threat_observations_consumed: batch.counters.detector_observations_consumed_count,
        endpoint_threat_outputs: batch.counters.detector_output_count,
        fusion_outputs: 0,
        evidence_quality_records,
        risk_outputs: 0,
        settings_read_model_updates,
        canonical_generation_updates: final_generation.saturating_sub(initial_generation),
        provider_availability: format!("{:?}", status.provider_availability_state)
            .to_ascii_lowercase(),
        provider_health: format!("{:?}", status.health_state).to_ascii_lowercase(),
        process_network_attribution_available: false,
        packet_visibility_available: false,
        response_execution_allowed: false,
        clean_shutdown: shutdown.shutdown.state == RuntimeShutdownState::Completed,
        unjoined_workers: u32::from(!shutdown.shutdown.scheduler_host_joined),
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
