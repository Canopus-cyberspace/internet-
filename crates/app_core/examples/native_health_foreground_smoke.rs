use sentinel_app_core::RuntimeContainerBuilder;
use sentinel_contracts::runtime_ownership::RuntimeShutdownState;
use sentinel_contracts::{NativePermissionState, NativeSamplerRuntimeAction};
use serde::Serialize;

#[derive(Serialize)]
struct NativeHealthSmokeReport {
    execution_context: &'static str,
    authorization_granted: bool,
    provider_enabled: u32,
    raw_records: u32,
    schema_accepted: u32,
    schema_rejected: u32,
    malformed: u32,
    rate_limited: u32,
    queue_dropped: u32,
    duplicate_suppressed: u32,
    normalized_records: u32,
    published_batches: u32,
    eventbus_publications: u32,
    dag_dispatches: u32,
    plugin_runtime_invocations: u32,
    observations_consumed: u32,
    downstream_facts: u32,
    endpoint_consumer_invocations: u32,
    endpoint_observations_consumed: u32,
    endpoint_outputs: u32,
    fusion_facts_consumed: u32,
    evidence_quality_records: usize,
    risk_outputs: u32,
    read_model_generation_updates: u64,
    provider_availability: String,
    resource_pressure: String,
    freshness: String,
    clean_shutdown: bool,
    unjoined_workers: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut container = RuntimeContainerBuilder::for_service_host().build()?;
    let owner = container.owner_context().clone();
    let initial_generation = container
        .canonical_read_model_current_generation()
        .unwrap_or_default();

    let authorization = container
        .authorize_native_health_sampler(&owner, "foreground native health smoke authorization")?;
    container.apply_native_health_sampler_action(
        &owner,
        NativeSamplerRuntimeAction::Activate,
        "foreground native health smoke activation",
    )?;
    let sampled = container.apply_native_health_sampler_action(
        &owner,
        NativeSamplerRuntimeAction::SampleNow,
        "foreground native health smoke sample",
    )?;
    let batch = sampled
        .latest_batch
        .ok_or("native health smoke produced no batch")?;
    let health = batch
        .health_record
        .as_ref()
        .ok_or("native health smoke produced no health record")?;
    let evidence_quality_records = container.evidence_quality_record_count();
    let final_generation = container
        .canonical_read_model_current_generation()
        .unwrap_or_default();

    container.apply_native_health_sampler_action(
        &owner,
        NativeSamplerRuntimeAction::Stop,
        "foreground native health smoke stop",
    )?;
    let shutdown = container.shutdown()?;

    let report = NativeHealthSmokeReport {
        execution_context: "foreground_servicehost_owned_runtime",
        authorization_granted: authorization.capability.permission_state
            == NativePermissionState::GrantedSession,
        provider_enabled: batch.counters.provider_enabled_count,
        raw_records: batch.counters.raw_record_count,
        schema_accepted: batch.counters.schema_accepted_count,
        schema_rejected: batch.counters.schema_rejected_count,
        malformed: batch.counters.malformed_record_count,
        rate_limited: batch.counters.rate_limited_count,
        queue_dropped: batch.counters.queue_dropped_count,
        duplicate_suppressed: batch.counters.duplicate_suppressed_count,
        normalized_records: batch.counters.normalized_record_count,
        published_batches: batch.counters.published_batch_count,
        eventbus_publications: batch.counters.eventbus_publication_count,
        dag_dispatches: batch.counters.dag_dispatch_count,
        plugin_runtime_invocations: batch.counters.plugin_runtime_invocation_count,
        observations_consumed: batch.counters.observations_consumed_count,
        downstream_facts: batch.counters.facts_emitted_count,
        endpoint_consumer_invocations: batch.counters.detector_consumer_invocation_count,
        endpoint_observations_consumed: batch.counters.detector_observations_consumed_count,
        endpoint_outputs: batch.counters.detector_output_count,
        fusion_facts_consumed: 0,
        evidence_quality_records,
        risk_outputs: 0,
        read_model_generation_updates: final_generation.saturating_sub(initial_generation),
        provider_availability: format!("{:?}", health.provider_availability_state)
            .to_ascii_lowercase(),
        resource_pressure: format!("{:?}", health.resource_pressure_bucket).to_ascii_lowercase(),
        freshness: format!("{:?}", health.freshness_bucket).to_ascii_lowercase(),
        clean_shutdown: shutdown.shutdown.state == RuntimeShutdownState::Completed,
        unjoined_workers: u32::from(!shutdown.shutdown.scheduler_host_joined),
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
