use crate::native_sampler_readiness::get_native_sampler_readiness_detail;
use crate::read_commands::ReadOnlyCommandState;
use crate::run_endpoint_threat_analysis_runtime_with_services;
use crate::runtime_container::{RuntimeEventBusHandle, RuntimeServices};
use sentinel_capabilities::{
    NATIVE_SAMPLER_FACT_STATIC_PLUGIN_ID, NATIVE_SAMPLER_RUNTIME_SCHEMA_VERSION,
};
use sentinel_contracts::{
    AuditId, CommandResult, ContractDescriptor, CoreError, DataSourceId, ErrorCode, ErrorSeverity,
    EventEnvelope, EventType, EvidenceId, NativeHealthMetadataRecord, NativeHealthObservationId,
    NativeHostCriticalityCategory, NativeIntegrityContextBucket, NativePermissionAction,
    NativePermissionActionRequest, NativePermissionState, NativePrivilegeContextCategory,
    NativeProcessBucketCount, NativeProcessCategory, NativeProcessCategoryCount,
    NativeProcessExecutionContextCategory, NativeProcessLifecycleStateBucket,
    NativeProcessMetadataRecord, NativeProcessObservationId, NativeProcessParentRelationCategory,
    NativeProcessTrustCategory, NativeProviderAvailabilityState, NativeProviderCategory,
    NativeRuntimeHealthState, NativeRuntimePlatformCategory, NativeSampleFreshnessBucket,
    NativeSamplerActivationPreview, NativeSamplerBatchId, NativeSamplerCategory,
    NativeSamplerCounterSummary, NativeSamplerReadinessState, NativeSamplerRuntimeAction,
    NativeSamplerRuntimeActionRequest, NativeSamplerRuntimeActionResult,
    NativeSamplerRuntimeAuditEntry, NativeSamplerRuntimeBatch, NativeSamplerRuntimeState,
    NativeSamplerRuntimeStatus, NativeSamplerRuntimeSummary, NativeServiceBucketCount,
    NativeServiceCategory, NativeServiceCategoryCount, NativeServiceMetadataRecord,
    NativeServiceObservationId, NativeSessionContextCategory, NativeSignednessBucket, PluginId,
    PluginManifest, PrivacyClass, QualityScore, RedactionStatus, SchemaVersion, SecurityFact,
    SecurityFactId, Timestamp, TraceContext,
};
use sentinel_infrastructure::{
    WindowsNativeHealthAdapter, WindowsNativeHealthSample, WindowsNativeServiceAdapter,
    WindowsNativeServiceBounds,
};
use sentinel_platform::{
    CheckpointSupport, ContractRegistry, PermissionResolver, PluginContext, PluginEventBatch,
    PolicyScope, PublishOptions, ReplaySupport, TopicName, AUDIT_ENDPOINT_THREAT_ANALYSIS,
    AUDIT_NATIVE_SAMPLER_RUNTIME, ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT,
    ENDPOINT_PROCESS_CATEGORY_FACT, ENDPOINT_PROCESS_PARENT_CATEGORY_FACT,
    ENDPOINT_SERVICE_CATEGORY_FACT, ENDPOINT_THREAT_CANDIDATE, ENDPOINT_THREAT_EVIDENCE,
    ENDPOINT_THREAT_FINDING, ENDPOINT_THREAT_REJECTED, ENDPOINT_THREAT_RISK_HINT,
    ENDPOINT_VISIBILITY_ADVISORY, GRAPH_HINT, NATIVE_HEALTH_METADATA, NATIVE_PROCESS_METADATA,
    NATIVE_PROCESS_PARENT_METADATA, NATIVE_SAMPLER_RUNTIME_STATUS, NATIVE_SERVICE_METADATA,
    SECURITY_VISIBILITY_STATUS,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

const PROVENANCE_ID: &str = "native_sampler_runtime";
const CURRENT_SESSION_BUCKET: &str = "current_session";
const DEFAULT_MAX_RECORDS: u32 = 128;
const DEFAULT_MAX_BYTES: u32 = 65_536;
const DEFAULT_TIMEOUT_MS: u32 = 5_000;
const QUEUE_SIZE_BOUND: u32 = 64;

#[derive(Clone, Debug)]
pub struct NativeSamplerRuntime {
    statuses: Vec<NativeSamplerRuntimeStatus>,
    batches: Vec<NativeSamplerRuntimeBatch>,
    audit_entries: Vec<NativeSamplerRuntimeAuditEntry>,
    seen_generation_keys: BTreeSet<String>,
    previous_process_population: BTreeMap<ProcessAggregateKey, u32>,
    sampling_in_progress: BTreeSet<String>,
    event_bus: RuntimeEventBusHandle,
    runtime_services: RuntimeServices,
    producer_plugin: PluginId,
}

impl NativeSamplerRuntime {
    #[cfg(test)]
    pub fn from_read_state(read: &ReadOnlyCommandState) -> Self {
        Self::from_read_state_with_services(
            read,
            RuntimeServices::for_test("native-sampler").expect("test runtime services"),
        )
    }

    pub(crate) fn from_read_state_with_services(
        read: &ReadOnlyCommandState,
        runtime_services: RuntimeServices,
    ) -> Self {
        Self {
            statuses: read.native_sampler_runtime_statuses.clone(),
            batches: read.native_sampler_runtime_batches.clone(),
            audit_entries: read.native_sampler_runtime_audit_entries.clone(),
            seen_generation_keys: read
                .native_sampler_runtime_batches
                .iter()
                .flat_map(batch_generation_keys)
                .collect(),
            previous_process_population: BTreeMap::new(),
            sampling_in_progress: BTreeSet::new(),
            event_bus: runtime_services.event_bus(),
            runtime_services,
            producer_plugin: PluginId::new_v4(),
        }
    }

    pub fn sync_read_state(&self, read: &mut ReadOnlyCommandState) {
        read.native_sampler_runtime_statuses = self.statuses.clone();
        read.native_sampler_runtime_batches = self.batches.clone();
        read.native_sampler_runtime_audit_entries = self.audit_entries.clone();
    }

    pub fn preview_activation(
        &self,
        read: &ReadOnlyCommandState,
        sampler_id: &str,
    ) -> CommandResult<NativeSamplerActivationPreview> {
        let detail = get_native_sampler_readiness_detail(read, sampler_id)?;
        let current = self.status_for_detail(read, sampler_id)?;
        let blocked_reason = activation_blocked_reason(&detail, &current);
        let preview = NativeSamplerActivationPreview {
            sampler_id: detail.contract.sampler_id,
            category: detail.contract.category,
            readiness_state: detail.review.readiness_state,
            current_runtime_state: current.runtime_state,
            activation_allowed: blocked_reason.is_none(),
            blocked_reason,
            state_change_performed: false,
            telemetry_collection_started: false,
            response_execution_started: false,
            service_installation_started: false,
            driver_loading_started: false,
            host_mutation_performed: false,
            automatic_llm_calls: false,
            boundary_summary_redacted:
                "Preview only; activation requires explicit action and starts no sampling"
                    .to_string(),
        };
        preview.validate().map_err(contract_error)?;
        Ok(preview)
    }

    pub fn apply_action(
        &mut self,
        read: &mut ReadOnlyCommandState,
        request: NativeSamplerRuntimeActionRequest,
    ) -> CommandResult<NativeSamplerRuntimeActionResult> {
        request.validate().map_err(contract_error)?;
        if request.action == NativeSamplerRuntimeAction::PreviewActivation {
            return Err(CoreError::validation_failure(
                "use the activation preview command for preview-only native sampler actions",
            ));
        }
        let detail = get_native_sampler_readiness_detail(read, &request.sampler_id)?;
        let mut status = self.status_for_detail(read, &request.sampler_id)?;
        let mut latest_batch = None;
        let mut emitted_topics = vec![NATIVE_SAMPLER_RUNTIME_STATUS.to_string()];
        let mut telemetry_collection_started = false;

        match request.action {
            NativeSamplerRuntimeAction::Activate => {
                ensure_activation_allowed(&detail, &status)?;
                status.runtime_state = NativeSamplerRuntimeState::Active;
                status.health_state = NativeRuntimeHealthState::Idle;
                status.interval_sampling_enabled = false;
                status.max_records_per_sample = request.max_records_per_sample;
                status.max_bytes_per_sample = request.max_bytes_per_sample;
                status.timeout_millis = request.timeout_millis;
                status.degraded_reason = None;
                status.missing_prerequisite_flags = missing_visibility_flags_for(&detail);
            }
            NativeSamplerRuntimeAction::SampleNow | NativeSamplerRuntimeAction::ScheduledSample => {
                ensure_sampling_allowed(&detail, &status)?;
                let sampled = self.sample_now(&detail.contract.category, &status, &request)?;
                emitted_topics.extend(sampled.emitted_topics.iter().cloned());
                telemetry_collection_started =
                    sampled.counters.sampled_record_count > 0 || sampled.health_record.is_some();
                status = status_after_batch(status, &sampled, telemetry_collection_started);
                latest_batch = Some(sampled);
            }
            NativeSamplerRuntimeAction::Pause => {
                ensure_runtime_mutable(&status)?;
                status.runtime_state = NativeSamplerRuntimeState::Paused;
                status.health_state = NativeRuntimeHealthState::Paused;
                status.telemetry_collection_active = false;
            }
            NativeSamplerRuntimeAction::Resume => {
                ensure_activation_allowed(&detail, &status)?;
                status.runtime_state = NativeSamplerRuntimeState::Active;
                status.health_state = NativeRuntimeHealthState::Idle;
                status.telemetry_collection_active = false;
            }
            NativeSamplerRuntimeAction::Stop => {
                status.runtime_state = NativeSamplerRuntimeState::Stopped;
                status.health_state = NativeRuntimeHealthState::Idle;
                status.telemetry_collection_active = false;
                status.interval_sampling_enabled = false;
            }
            NativeSamplerRuntimeAction::Revoke => {
                status.runtime_state = NativeSamplerRuntimeState::Revoked;
                status.health_state = NativeRuntimeHealthState::Revoked;
                status.permission_state = NativePermissionState::Revoked;
                status.telemetry_collection_active = false;
                status.interval_sampling_enabled = false;
                status.degraded_reason = Some("authorization_revoked".to_string());
                status.missing_prerequisite_flags = vec!["authorization_revoked".to_string()];
            }
            NativeSamplerRuntimeAction::RefreshStatus => {
                status = self.status_for_detail(read, &request.sampler_id)?;
            }
            NativeSamplerRuntimeAction::ReadLatestBoundedBatch => {
                latest_batch = self
                    .batches
                    .iter()
                    .rev()
                    .find(|batch| batch.sampler_id == request.sampler_id)
                    .cloned();
            }
            NativeSamplerRuntimeAction::ClearInactiveRuntimeState => {
                if !matches!(
                    status.runtime_state,
                    NativeSamplerRuntimeState::Active | NativeSamplerRuntimeState::Paused
                ) {
                    self.statuses
                        .retain(|existing| existing.sampler_id != request.sampler_id);
                    status = self.status_for_detail(read, &request.sampler_id)?;
                }
            }
            NativeSamplerRuntimeAction::PreviewActivation => unreachable!(),
        }

        let audit_entry = runtime_audit_entry(&request, &status);
        status.audit_refs.push(audit_entry.audit_id.clone());
        status
            .audit_refs
            .truncate(sentinel_contracts::MAX_NATIVE_SAMPLER_REFS);
        status.emitted_topics = bounded_unique_strings(emitted_topics.clone());
        status.validate().map_err(contract_error)?;
        self.upsert_status(status.clone());

        if let Some(batch) = &mut latest_batch {
            batch.audit_refs.push(audit_entry.audit_id.clone());
            self.publish_batch_and_facts(read, batch)?;
            emitted_topics.extend(batch.emitted_topics.iter().cloned());
            status.fact_refs = bounded_fact_refs(batch.fact_refs.clone());
            status.evidence_refs = bounded_evidence_refs(batch.evidence_refs.clone());
            status.latest_batch_id = Some(batch.batch_id.clone());
            status.counters = batch.counters.clone();
            status.validate().map_err(contract_error)?;
            self.upsert_status(status.clone());
            self.store_batch(batch.clone());
        }

        self.publish_status(&status)?;
        self.publish_audit(&audit_entry)?;
        self.audit_entries.push(audit_entry.clone());
        bound_runtime_audit(&mut self.audit_entries);
        self.sync_read_state(read);

        let result = NativeSamplerRuntimeActionResult {
            status,
            latest_batch,
            audit_entry,
            emitted_topics: bounded_unique_strings(emitted_topics),
            preview_only: false,
            telemetry_collection_started,
            response_execution_started: false,
            service_installation_started: false,
            driver_loading_started: false,
            host_mutation_performed: false,
            automatic_llm_calls: false,
        };
        result.validate().map_err(contract_error)?;
        Ok(result)
    }

    pub fn status_for_detail(
        &self,
        read: &ReadOnlyCommandState,
        sampler_id: &str,
    ) -> CommandResult<NativeSamplerRuntimeStatus> {
        status_for_detail_from_statuses(read, &self.statuses, sampler_id)
    }

    pub(crate) fn status_from_read_state(
        read: &ReadOnlyCommandState,
        sampler_id: &str,
    ) -> CommandResult<NativeSamplerRuntimeStatus> {
        status_for_detail_from_statuses(read, &read.native_sampler_runtime_statuses, sampler_id)
    }

    pub fn summary(
        &self,
        read: &ReadOnlyCommandState,
    ) -> CommandResult<NativeSamplerRuntimeSummary> {
        let mut statuses = self.statuses.clone();
        for sampler_id in [
            "native_health_probe_sampler",
            "service_metadata_sampler",
            "process_metadata_sampler",
        ] {
            if !statuses
                .iter()
                .any(|status| status.sampler_id == sampler_id)
            {
                statuses.push(self.status_for_detail(read, sampler_id)?);
            }
        }
        native_sampler_summary_from_parts(statuses, &self.batches, &self.audit_entries)
    }

    pub(crate) fn summary_from_read_state(
        read: &ReadOnlyCommandState,
    ) -> CommandResult<NativeSamplerRuntimeSummary> {
        let mut statuses = read.native_sampler_runtime_statuses.clone();
        for sampler_id in [
            "native_health_probe_sampler",
            "service_metadata_sampler",
            "process_metadata_sampler",
        ] {
            if !statuses
                .iter()
                .any(|status| status.sampler_id == sampler_id)
            {
                statuses.push(Self::status_from_read_state(read, sampler_id)?);
            }
        }
        native_sampler_summary_from_parts(
            statuses,
            &read.native_sampler_runtime_batches,
            &read.native_sampler_runtime_audit_entries,
        )
    }

    pub fn latest_batch(
        &self,
        sampler_id: &str,
    ) -> CommandResult<Option<NativeSamplerRuntimeBatch>> {
        latest_native_sampler_batch(&self.batches, sampler_id)
    }

    pub(crate) fn latest_batch_from_read_state(
        read: &ReadOnlyCommandState,
        sampler_id: &str,
    ) -> CommandResult<Option<NativeSamplerRuntimeBatch>> {
        latest_native_sampler_batch(&read.native_sampler_runtime_batches, sampler_id)
    }

    pub fn revoke_matching_capability(
        sampler_id: &str,
    ) -> CommandResult<Option<NativePermissionActionRequest>> {
        let capability_id = match sampler_id {
            "native_health_probe_sampler" => "native_health_probe",
            "service_metadata_sampler" => "service_metadata_visibility",
            "process_metadata_sampler" => "process_metadata_visibility",
            _ => return Ok(None),
        };
        Ok(Some(NativePermissionActionRequest {
            capability_id: capability_id.to_string(),
            action: NativePermissionAction::RevokeAuthorization,
            explicit_user_action: true,
            reason_redacted: "revoke native sampler runtime authorization".to_string(),
        }))
    }

    fn sample_now(
        &mut self,
        category: &NativeSamplerCategory,
        status: &NativeSamplerRuntimeStatus,
        request: &NativeSamplerRuntimeActionRequest,
    ) -> CommandResult<NativeSamplerRuntimeBatch> {
        if !self.sampling_in_progress.insert(status.sampler_id.clone()) {
            return Err(CoreError::new(
                ErrorCode::InvalidRequest,
                "native sampler sample already in progress",
            )
            .with_severity(ErrorSeverity::Warning)
            .with_redacted_details(json!({ "sampler_id": status.sampler_id })));
        }
        let result = self.sample_now_inner(category, status, request);
        self.sampling_in_progress.remove(&status.sampler_id);
        result
    }

    fn sample_now_inner(
        &mut self,
        category: &NativeSamplerCategory,
        status: &NativeSamplerRuntimeStatus,
        request: &NativeSamplerRuntimeActionRequest,
    ) -> CommandResult<NativeSamplerRuntimeBatch> {
        let started = Instant::now();
        let batch_id = NativeSamplerBatchId::new_v4();
        let mut provider = provider_status_for(category);
        let mut counters = NativeSamplerCounterSummary::empty();
        let mut health_record = None;
        let mut service_records = Vec::new();
        let mut process_records = Vec::new();
        let mut emitted_topics = vec![NATIVE_SAMPLER_RUNTIME_STATUS.to_string()];
        match category {
            NativeSamplerCategory::NativeHealthProbeSampler => {
                let sample = WindowsNativeHealthAdapter.sample();
                provider = ProviderStatus {
                    provider_category: sample.provider_category.clone(),
                    platform_category: sample.platform_category.clone(),
                    availability_state: sample.availability_state.clone(),
                    degraded_reason: sample.degraded_reason.clone(),
                };
                counters.provider_enabled_count = sample.provider_enabled_count;
                counters.raw_record_count = sample.raw_record_count;
                counters.schema_accepted_count = sample.schema_accepted_count;
                counters.schema_rejected_count = sample.schema_rejected_count;
                counters.normalized_record_count = sample.normalized_record_count;
                counters.sampled_record_count = sample.normalized_record_count;
                counters.sampled_record_count_bucket =
                    counter_bucket(sample.normalized_record_count);
                counters.rejected_record_count = sample.schema_rejected_count;
                if sample.normalized_record_count == 0 {
                    counters.skipped_record_count = 1;
                    counters.skipped_record_count_bucket = "single".to_string();
                }
                counters.duration_bucket = duration_bucket(started.elapsed().as_millis() as u64);
                counters.bytes_processed_bucket = "metadata_only_low".to_string();
                health_record = Some(native_health_record(status, &sample, &counters));
                emitted_topics.push(NATIVE_HEALTH_METADATA.to_string());
                emitted_topics.push(ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT.to_string());
            }
            NativeSamplerCategory::ServiceMetadataSampler => {
                let sampled = sample_service_metadata(
                    batch_id.clone(),
                    request,
                    &mut self.seen_generation_keys,
                );
                provider = sampled.provider;
                counters = sampled.counters;
                counters.duration_bucket = duration_bucket(started.elapsed().as_millis() as u64);
                service_records = sampled.records;
                if service_records.is_empty()
                    && provider.availability_state != NativeProviderAvailabilityState::Available
                {
                    counters.skipped_record_count = counters.skipped_record_count.saturating_add(1);
                    counters.skipped_record_count_bucket = "single".to_string();
                }
                emitted_topics.push(NATIVE_SERVICE_METADATA.to_string());
                if !service_records.is_empty() {
                    emitted_topics.push(ENDPOINT_SERVICE_CATEGORY_FACT.to_string());
                }
            }
            NativeSamplerCategory::ProcessMetadataSampler => {
                let sampled = sample_process_metadata(
                    batch_id.clone(),
                    request,
                    &mut self.seen_generation_keys,
                    &mut self.previous_process_population,
                );
                counters = sampled.counters;
                counters.duration_bucket = duration_bucket(started.elapsed().as_millis() as u64);
                process_records = sampled.records;
                if process_records.is_empty()
                    && provider.availability_state != NativeProviderAvailabilityState::Available
                {
                    counters.skipped_record_count = counters.skipped_record_count.saturating_add(1);
                    counters.skipped_record_count_bucket =
                        counter_bucket(counters.skipped_record_count);
                }
                emitted_topics.push(NATIVE_PROCESS_METADATA.to_string());
                emitted_topics.push(NATIVE_PROCESS_PARENT_METADATA.to_string());
                if !process_records.is_empty() {
                    emitted_topics.push(ENDPOINT_PROCESS_CATEGORY_FACT.to_string());
                    emitted_topics.push(ENDPOINT_PROCESS_PARENT_CATEGORY_FACT.to_string());
                }
            }
            _ => {
                return Err(CoreError::validation_failure(
                    "native sampler runtime supports only authorized bounded native metadata categories",
                ));
            }
        }
        if self.batches.len() >= sentinel_contracts::MAX_NATIVE_RUNTIME_BATCHES {
            counters.backpressure_event_count = counters.backpressure_event_count.saturating_add(1);
        }
        let batch = NativeSamplerRuntimeBatch {
            batch_id,
            sampler_id: status.sampler_id.clone(),
            category: category.clone(),
            runtime_state: NativeSamplerRuntimeState::Active,
            provider_category: provider.provider_category,
            platform_category: provider.platform_category,
            health_record,
            service_records,
            process_records,
            counters,
            emitted_topics: bounded_unique_strings(emitted_topics),
            fact_refs: Vec::new(),
            evidence_refs: Vec::new(),
            audit_refs: Vec::new(),
            provenance_id: DataSourceId::new_v4().to_string(),
            time_bucket: CURRENT_SESSION_BUCKET.to_string(),
            redaction_status: RedactionStatus::Redacted,
            response_execution_allowed: false,
            host_mutation_performed: false,
            automatic_llm_calls: false,
        };
        batch.validate().map_err(contract_error)?;
        Ok(batch)
    }

    fn publish_batch_and_facts(
        &mut self,
        read: &mut ReadOnlyCommandState,
        batch: &mut NativeSamplerRuntimeBatch,
    ) -> CommandResult<()> {
        let topic = match batch.category {
            NativeSamplerCategory::NativeHealthProbeSampler => NATIVE_HEALTH_METADATA,
            NativeSamplerCategory::ServiceMetadataSampler => NATIVE_SERVICE_METADATA,
            NativeSamplerCategory::ProcessMetadataSampler => NATIVE_PROCESS_METADATA,
            _ => {
                return Err(CoreError::validation_failure(
                    "native sampler batch category is not publishable in this slice",
                ));
            }
        };
        self.publish_payload(topic, batch, "bounded native sampler metadata")?;
        batch.counters.published_batch_count = 1;
        batch.counters.eventbus_publication_count = 1;
        if batch.category == NativeSamplerCategory::ProcessMetadataSampler {
            self.publish_payload(
                NATIVE_PROCESS_PARENT_METADATA,
                batch,
                "bounded native process parent-category metadata",
            )?;
            batch.counters.eventbus_publication_count =
                batch.counters.eventbus_publication_count.saturating_add(1);
        }
        let fact_topics = fact_topics_for(&batch.category);
        validate_native_fact_dag(&self.runtime_services, topic, fact_topics.clone())?;
        batch.counters.dag_dispatch_count = 1;
        let facts = self.run_fact_runtime(batch)?;
        batch.counters.plugin_runtime_invocation_count = 1;
        batch.counters.observations_consumed_count = 1;
        batch.counters.facts_emitted_count = facts.len().min(u32::MAX as usize) as u32;
        for fact in facts {
            let topic = match fact.layer {
                sentinel_contracts::SecurityLayer::AuthorizedNativeHealth => {
                    ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT
                }
                sentinel_contracts::SecurityLayer::AuthorizedNativeService => {
                    ENDPOINT_SERVICE_CATEGORY_FACT
                }
                sentinel_contracts::SecurityLayer::AuthorizedNativeProcess => {
                    if fact.category == ENDPOINT_PROCESS_PARENT_CATEGORY_FACT {
                        ENDPOINT_PROCESS_PARENT_CATEGORY_FACT
                    } else {
                        ENDPOINT_PROCESS_CATEGORY_FACT
                    }
                }
                _ => {
                    return Err(CoreError::validation_failure(
                        "native sampler fact runtime produced a forbidden fact layer",
                    ));
                }
            };
            self.publish_payload(topic, &fact, "bounded native sampler fact")?;
            batch.counters.eventbus_publication_count =
                batch.counters.eventbus_publication_count.saturating_add(1);
            batch.fact_refs.push(fact.fact_id.clone());
            read.security_facts.items.push(fact);
        }
        for fact_topic in &fact_topics {
            self.runtime_services
                .validate_dag_route(fact_topic, endpoint_threat_output_topics())?;
        }
        batch.counters.dag_dispatch_count = batch.counters.dag_dispatch_count.saturating_add(1);
        let endpoint_receipt = run_endpoint_threat_analysis_runtime_with_services(
            read,
            self.runtime_services.clone(),
        )?;
        batch.counters.detector_consumer_invocation_count = endpoint_receipt.consumer_invocations;
        batch.counters.detector_observations_consumed_count =
            endpoint_receipt.observations_consumed;
        batch.counters.detector_output_count =
            endpoint_receipt.emitted_topics.len().min(u32::MAX as usize) as u32;
        batch.counters.eventbus_publication_count = batch
            .counters
            .eventbus_publication_count
            .saturating_add(batch.counters.detector_output_count);
        batch.fact_refs = bounded_fact_refs(batch.fact_refs.clone());
        batch.validate().map_err(contract_error)?;
        Ok(())
    }

    fn run_fact_runtime(
        &self,
        batch: &NativeSamplerRuntimeBatch,
    ) -> CommandResult<Vec<SecurityFact>> {
        self.runtime_services.with_plugin_runtime(|runtime| {
            let plugin_id = PluginId::parse_str(NATIVE_SAMPLER_FACT_STATIC_PLUGIN_ID)
                .map_err(native_runtime_error)?;
            let manifest = runtime
                .manifest(&plugin_id)
                .ok_or_else(|| native_runtime_error("native sampler fact manifest missing"))?
                .clone();
            let contracts = contract_registry_for_manifest(&manifest)?;
            let mut permissions = PermissionResolver::new();
            permissions.register_plugin_manifest_permissions(&manifest);
            let validation = runtime
                .registry()
                .validate_startup(&plugin_id, &contracts, &permissions)
                .map_err(native_runtime_error)?;
            let trace_context = TraceContext::new_root();
            let mut context = plugin_context_for_manifest(&manifest, trace_context.clone())?;
            context.policy_scope = PolicyScope::Plugin;
            runtime
                .start_plugin(&plugin_id, &validation, &mut context)
                .map_err(native_runtime_error)?;
            let mut plugin_batch = PluginEventBatch::new(plugin_id.clone(), 1);
            plugin_batch
                .push(native_runtime_event(
                    &self.producer_plugin,
                    match batch.category {
                        NativeSamplerCategory::NativeHealthProbeSampler => NATIVE_HEALTH_METADATA,
                        NativeSamplerCategory::ServiceMetadataSampler => NATIVE_SERVICE_METADATA,
                        NativeSamplerCategory::ProcessMetadataSampler => NATIVE_PROCESS_METADATA,
                        _ => {
                            return Err(CoreError::validation_failure(
                                "native sampler batch category is not fact-runtime publishable",
                            ));
                        }
                    },
                    batch,
                    &trace_context,
                )?)
                .map_err(native_runtime_error)?;
            let output = runtime
                .process_batch(&plugin_id, &mut context, &plugin_batch)
                .map_err(native_runtime_error)?;
            let mut facts = Vec::new();
            for event in output.events {
                match event.event_type.as_str() {
                    ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT
                    | ENDPOINT_SERVICE_CATEGORY_FACT
                    | ENDPOINT_PROCESS_CATEGORY_FACT
                    | ENDPOINT_PROCESS_PARENT_CATEGORY_FACT => {
                        facts.push(
                            serde_json::from_value::<SecurityFact>(event.payload)
                                .map_err(native_runtime_error)?,
                        );
                    }
                    other => {
                        return Err(CoreError::validation_failure(
                            "native sampler fact runtime emitted undeclared output",
                        )
                        .with_redacted_details(json!({ "topic": other })));
                    }
                }
            }
            Ok(facts)
        })
    }

    fn publish_status(&mut self, status: &NativeSamplerRuntimeStatus) -> CommandResult<()> {
        self.publish_payload(
            NATIVE_SAMPLER_RUNTIME_STATUS,
            status,
            "bounded native sampler runtime status",
        )?;
        self.publish_payload(
            SECURITY_VISIBILITY_STATUS,
            status,
            "bounded native sampler visibility status",
        )
    }

    fn publish_audit(&mut self, audit: &NativeSamplerRuntimeAuditEntry) -> CommandResult<()> {
        self.publish_payload(
            AUDIT_NATIVE_SAMPLER_RUNTIME,
            audit,
            "bounded native sampler runtime audit",
        )
    }

    fn publish_payload<T: serde::Serialize>(
        &mut self,
        topic: &str,
        payload: &T,
        summary: &str,
    ) -> CommandResult<()> {
        let envelope = native_runtime_event(
            &self.producer_plugin,
            topic,
            payload,
            &TraceContext::new_root(),
        )?;
        self.event_bus
            .publish(
                TopicName::new(topic).map_err(contract_error)?,
                envelope,
                PublishOptions::new(summary),
            )
            .map_err(native_runtime_error)?;
        Ok(())
    }

    fn upsert_status(&mut self, status: NativeSamplerRuntimeStatus) {
        if let Some(existing) = self
            .statuses
            .iter_mut()
            .find(|existing| existing.sampler_id == status.sampler_id)
        {
            *existing = status;
        } else {
            self.statuses.push(status);
        }
        self.statuses
            .sort_by(|left, right| left.sampler_id.cmp(&right.sampler_id));
    }

    fn store_batch(&mut self, batch: NativeSamplerRuntimeBatch) {
        self.batches.push(batch);
        if self.batches.len() > sentinel_contracts::MAX_NATIVE_RUNTIME_BATCHES {
            self.batches
                .drain(0..self.batches.len() - sentinel_contracts::MAX_NATIVE_RUNTIME_BATCHES);
        }
    }
}

fn fact_topics_for(category: &NativeSamplerCategory) -> Vec<&'static str> {
    match category {
        NativeSamplerCategory::NativeHealthProbeSampler => {
            vec![ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT]
        }
        NativeSamplerCategory::ServiceMetadataSampler => vec![ENDPOINT_SERVICE_CATEGORY_FACT],
        NativeSamplerCategory::ProcessMetadataSampler => vec![
            ENDPOINT_PROCESS_CATEGORY_FACT,
            ENDPOINT_PROCESS_PARENT_CATEGORY_FACT,
        ],
        _ => Vec::new(),
    }
}

fn endpoint_threat_output_topics() -> &'static [&'static str] {
    &[
        ENDPOINT_THREAT_CANDIDATE,
        ENDPOINT_THREAT_FINDING,
        ENDPOINT_THREAT_EVIDENCE,
        ENDPOINT_THREAT_RISK_HINT,
        ENDPOINT_VISIBILITY_ADVISORY,
        ENDPOINT_THREAT_REJECTED,
        GRAPH_HINT,
        AUDIT_ENDPOINT_THREAT_ANALYSIS,
    ]
}

fn status_for_detail_from_statuses(
    read: &ReadOnlyCommandState,
    statuses: &[NativeSamplerRuntimeStatus],
    sampler_id: &str,
) -> CommandResult<NativeSamplerRuntimeStatus> {
    if let Some(status) = statuses
        .iter()
        .find(|status| status.sampler_id == sampler_id)
        .cloned()
    {
        return Ok(status);
    }
    let detail = get_native_sampler_readiness_detail(read, sampler_id)?;
    let runtime_state = if !detail.contract.sampler_implemented {
        NativeSamplerRuntimeState::NotImplemented
    } else if detail.review.readiness_state.is_blocked() {
        NativeSamplerRuntimeState::ReadinessBlocked
    } else if detail.review.permission_state == NativePermissionState::Revoked {
        NativeSamplerRuntimeState::Revoked
    } else if detail.review.allowed {
        NativeSamplerRuntimeState::ReadyInactive
    } else {
        NativeSamplerRuntimeState::ReadinessBlocked
    };
    let provider = provider_status_for(&detail.contract.category);
    let degraded_reason = match runtime_state {
        NativeSamplerRuntimeState::NotImplemented => Some("sampler_not_implemented".to_string()),
        NativeSamplerRuntimeState::ReadinessBlocked => {
            Some("sampler_readiness_blocked".to_string())
        }
        NativeSamplerRuntimeState::Revoked => Some("authorization_revoked".to_string()),
        _ => None,
    }
    .or(provider.degraded_reason);
    let health_state = match runtime_state {
        NativeSamplerRuntimeState::NotImplemented => NativeRuntimeHealthState::Unsupported,
        NativeSamplerRuntimeState::ReadinessBlocked => NativeRuntimeHealthState::Degraded,
        NativeSamplerRuntimeState::Revoked => NativeRuntimeHealthState::Revoked,
        _ => NativeRuntimeHealthState::Idle,
    };
    let status = NativeSamplerRuntimeStatus {
        sampler_id: detail.contract.sampler_id.clone(),
        category: detail.contract.category.clone(),
        capability_id: detail.contract.required_capability_id.clone(),
        readiness_state: detail.review.readiness_state.clone(),
        runtime_state,
        permission_state: detail.review.permission_state.clone(),
        provider_category: provider.provider_category,
        platform_category: provider.platform_category,
        provider_availability_state: provider.availability_state,
        health_state,
        degraded_reason,
        missing_prerequisite_flags: missing_visibility_flags_for(&detail),
        interval_sampling_enabled: false,
        max_records_per_sample: DEFAULT_MAX_RECORDS,
        max_bytes_per_sample: DEFAULT_MAX_BYTES,
        timeout_millis: DEFAULT_TIMEOUT_MS,
        queue_size_bound: QUEUE_SIZE_BOUND,
        latest_batch_id: None,
        latest_sample_time_bucket: None,
        counters: NativeSamplerCounterSummary::empty(),
        emitted_topics: vec![NATIVE_SAMPLER_RUNTIME_STATUS.to_string()],
        fact_refs: Vec::new(),
        evidence_refs: Vec::new(),
        audit_refs: detail.review.audit_refs,
        provenance_id: PROVENANCE_ID.to_string(),
        redaction_status: RedactionStatus::Redacted,
        telemetry_collection_active: false,
        response_execution_allowed: false,
        service_installation_started: false,
        driver_loading_started: false,
        host_mutation_performed: false,
        automatic_llm_calls: false,
    };
    status.validate().map_err(contract_error)?;
    Ok(status)
}

fn native_sampler_summary_from_parts(
    statuses: Vec<NativeSamplerRuntimeStatus>,
    batches: &[NativeSamplerRuntimeBatch],
    audit_entries: &[NativeSamplerRuntimeAuditEntry],
) -> CommandResult<NativeSamplerRuntimeSummary> {
    let latest_batch_refs = batches
        .iter()
        .rev()
        .take(sentinel_contracts::MAX_NATIVE_RUNTIME_BATCHES)
        .map(|batch| batch.batch_id.clone())
        .collect::<Vec<_>>();
    let fact_refs = bounded_fact_refs(
        batches
            .iter()
            .flat_map(|batch| batch.fact_refs.iter().cloned())
            .collect(),
    );
    let evidence_refs = bounded_evidence_refs(
        batches
            .iter()
            .flat_map(|batch| batch.evidence_refs.iter().cloned())
            .collect(),
    );
    let audit_refs = audit_entries
        .iter()
        .rev()
        .take(sentinel_contracts::MAX_NATIVE_SAMPLER_REFS)
        .map(|entry| entry.audit_id.clone())
        .collect::<Vec<_>>();
    let service_records = batches
        .iter()
        .flat_map(|batch| batch.service_records.iter())
        .collect::<Vec<_>>();
    let process_records = batches
        .iter()
        .flat_map(|batch| batch.process_records.iter())
        .collect::<Vec<_>>();
    let summary = NativeSamplerRuntimeSummary {
        runtime_count: statuses.len() as u32,
        active_count: count_runtime(&statuses, NativeSamplerRuntimeState::Active),
        paused_count: count_runtime(&statuses, NativeSamplerRuntimeState::Paused),
        degraded_count: statuses
            .iter()
            .filter(|status| {
                matches!(
                    status.runtime_state,
                    NativeSamplerRuntimeState::Degraded
                        | NativeSamplerRuntimeState::ReadinessBlocked
                        | NativeSamplerRuntimeState::Failed
                )
            })
            .count() as u32,
        stopped_count: count_runtime(&statuses, NativeSamplerRuntimeState::Stopped),
        revoked_count: count_runtime(&statuses, NativeSamplerRuntimeState::Revoked),
        latest_batch_refs,
        fact_refs,
        evidence_refs,
        audit_refs,
        service_category_counts: service_category_counts(&service_records),
        service_state_counts: service_bucket_counts(
            service_records
                .iter()
                .map(|record| format!("{:?}", record.service_state_bucket).to_ascii_lowercase()),
        ),
        startup_type_counts: service_bucket_counts(
            service_records
                .iter()
                .map(|record| format!("{:?}", record.startup_type_bucket).to_ascii_lowercase()),
        ),
        process_category_counts: process_category_counts(process_records.iter().copied(), false),
        parent_process_category_counts: process_category_counts(
            process_records.iter().copied(),
            true,
        ),
        process_relation_counts: process_bucket_counts(
            process_records
                .iter()
                .map(|record| format!("{:?}", record.relation_category).to_ascii_lowercase()),
        ),
        execution_context_counts: process_bucket_counts(
            process_records.iter().map(|record| {
                format!("{:?}", record.execution_context_category).to_ascii_lowercase()
            }),
        ),
        process_trust_counts: process_bucket_counts(
            process_records
                .iter()
                .map(|record| format!("{:?}", record.trust_category).to_ascii_lowercase()),
        ),
        process_signedness_counts: process_bucket_counts(
            process_records
                .iter()
                .map(|record| format!("{:?}", record.signedness_bucket).to_ascii_lowercase()),
        ),
        process_privilege_counts: process_bucket_counts(
            process_records.iter().map(|record| {
                format!("{:?}", record.privilege_context_category).to_ascii_lowercase()
            }),
        ),
        process_lifecycle_counts: process_bucket_counts(
            process_records
                .iter()
                .map(|record| format!("{:?}", record.lifecycle_state_bucket).to_ascii_lowercase()),
        ),
        quality_bucket: quality_bucket_for(&statuses, batches),
        service_visibility_available: batches
            .iter()
            .any(|batch| !batch.service_records.is_empty()),
        native_health_visibility_available: batches
            .iter()
            .any(|batch| batch.health_record.is_some()),
        process_visibility_available: batches
            .iter()
            .any(|batch| !batch.process_records.is_empty()),
        parent_process_visibility_available: batches.iter().any(|batch| {
            batch
                .process_records
                .iter()
                .any(|record| record.parent_process_category != NativeProcessCategory::Unknown)
        }),
        process_network_attribution_available: false,
        packet_visibility_available: false,
        response_execution_allowed: false,
        edr_coverage_claimed: false,
        automatic_llm_calls: false,
        statuses,
        generated_at: Timestamp::now(),
    };
    summary.validate().map_err(contract_error)?;
    Ok(summary)
}

fn latest_native_sampler_batch(
    batches: &[NativeSamplerRuntimeBatch],
    sampler_id: &str,
) -> CommandResult<Option<NativeSamplerRuntimeBatch>> {
    validate_safe_request_id("native sampler id", sampler_id)?;
    Ok(batches
        .iter()
        .rev()
        .find(|batch| batch.sampler_id == sampler_id)
        .cloned())
}

fn validate_native_fact_dag(
    runtime_services: &RuntimeServices,
    input_topic: &str,
    output_topics: Vec<&str>,
) -> CommandResult<()> {
    if output_topics.is_empty() {
        return Err(CoreError::validation_failure(
            "native sampler DAG requires declared fact outputs",
        ));
    }
    TopicName::new(input_topic).map_err(contract_error)?;
    let outputs = output_topics
        .iter()
        .map(|topic| TopicName::new(*topic))
        .collect::<Result<Vec<_>, _>>()
        .map_err(contract_error)?;
    if outputs
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>()
        .len()
        != outputs.len()
    {
        return Err(CoreError::validation_failure(
            "native sampler runtime requires unique declared fact outputs",
        ));
    }
    runtime_services.validate_dag_route(input_topic, &output_topics)?;
    Ok(())
}

#[derive(Clone, Debug)]
struct ProviderStatus {
    provider_category: NativeProviderCategory,
    platform_category: NativeRuntimePlatformCategory,
    availability_state: NativeProviderAvailabilityState,
    degraded_reason: Option<String>,
}

#[derive(Clone, Debug)]
struct ServiceSample {
    provider: ProviderStatus,
    records: Vec<NativeServiceMetadataRecord>,
    counters: NativeSamplerCounterSummary,
}

#[derive(Clone, Debug)]
struct ProcessSample {
    records: Vec<NativeProcessMetadataRecord>,
    counters: NativeSamplerCounterSummary,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProcessAggregateKey {
    process_category: NativeProcessCategory,
    parent_process_category: NativeProcessCategory,
    relation_category: NativeProcessParentRelationCategory,
    execution_context_category: NativeProcessExecutionContextCategory,
    trust_category: NativeProcessTrustCategory,
    signedness_bucket: NativeSignednessBucket,
    privilege_context_category: NativePrivilegeContextCategory,
    integrity_context_bucket: NativeIntegrityContextBucket,
    session_context_category: NativeSessionContextCategory,
}

#[derive(Clone, Debug)]
struct ProcessProviderBounds {
    max_records: u32,
    max_bytes: u32,
    timeout: Duration,
    cancellation_requested: bool,
}

#[derive(Clone, Debug)]
struct ProcessProviderSample {
    aggregates: BTreeMap<ProcessAggregateKey, u32>,
    counters: NativeSamplerCounterSummary,
}

#[derive(Clone, Debug)]
struct ProcessTransitionSummary {
    lifecycle_state_bucket: NativeProcessLifecycleStateBucket,
    first_seen_in_session: bool,
    population_count: u32,
    start_count: u32,
    stop_count: u32,
    changed_category: bool,
}

trait NativeProcessCategoryProvider {
    fn sample_categories(&self, bounds: &ProcessProviderBounds) -> ProcessProviderSample;
}

#[cfg(windows)]
fn provider_status_for(category: &NativeSamplerCategory) -> ProviderStatus {
    match category {
        NativeSamplerCategory::NativeHealthProbeSampler => ProviderStatus {
            provider_category: NativeProviderCategory::WindowsSystemHealthSnapshot,
            platform_category: NativeRuntimePlatformCategory::Windows,
            availability_state: NativeProviderAvailabilityState::Available,
            degraded_reason: None,
        },
        NativeSamplerCategory::ProcessMetadataSampler => ProviderStatus {
            provider_category: NativeProviderCategory::WindowsToolhelpProcessSnapshot,
            platform_category: NativeRuntimePlatformCategory::Windows,
            availability_state: NativeProviderAvailabilityState::Available,
            degraded_reason: None,
        },
        _ => ProviderStatus {
            provider_category: NativeProviderCategory::WindowsServiceControlManager,
            platform_category: NativeRuntimePlatformCategory::Windows,
            availability_state: NativeProviderAvailabilityState::Available,
            degraded_reason: None,
        },
    }
}

#[cfg(not(windows))]
fn provider_status_for(_category: &NativeSamplerCategory) -> ProviderStatus {
    ProviderStatus {
        provider_category: NativeProviderCategory::UnsupportedPlatform,
        platform_category: NativeRuntimePlatformCategory::Unsupported,
        availability_state: NativeProviderAvailabilityState::UnsupportedPlatform,
        degraded_reason: Some("unsupported_platform".to_string()),
    }
}

fn native_health_record(
    status: &NativeSamplerRuntimeStatus,
    sample: &WindowsNativeHealthSample,
    counters: &NativeSamplerCounterSummary,
) -> NativeHealthMetadataRecord {
    NativeHealthMetadataRecord {
        health_observation_id: NativeHealthObservationId::new_v4(),
        sampler_id: status.sampler_id.clone(),
        provider_category: sample.provider_category.clone(),
        platform_category: sample.platform_category.clone(),
        provider_availability_state: sample.availability_state.clone(),
        authorization_state: status.permission_state.clone(),
        runtime_state: status.runtime_state.clone(),
        health_state: sample.health_state.clone(),
        resource_pressure_bucket: sample.resource_pressure_bucket.clone(),
        uptime_bucket: sample.uptime_bucket.clone(),
        freshness_bucket: sample.freshness_bucket.clone(),
        degraded_reason: sample.degraded_reason.clone(),
        missing_prerequisite_flags: status.missing_prerequisite_flags.clone(),
        sample_duration_bucket: counters.duration_bucket.clone(),
        sampled_record_count_bucket: counters.sampled_record_count_bucket.clone(),
        skipped_record_count_bucket: counters.skipped_record_count_bucket.clone(),
        malformed_record_count_bucket: counter_bucket(counters.malformed_record_count),
        rejected_record_count_bucket: counter_bucket(counters.rejected_record_count),
        timeout_bucket: counter_bucket(counters.timeout_count),
        last_sample_time_bucket: CURRENT_SESSION_BUCKET.to_string(),
        schema_version: SchemaVersion::new(1, 0, 0),
        provenance_id: DataSourceId::new_v4().to_string(),
        audit_refs: status.audit_refs.clone(),
        redaction_status: RedactionStatus::Redacted,
        quality_score: match (
            &sample.availability_state,
            &sample.health_state,
            &sample.freshness_bucket,
        ) {
            (
                NativeProviderAvailabilityState::Available,
                NativeRuntimeHealthState::Healthy,
                NativeSampleFreshnessBucket::Current,
            ) => quality(0.86),
            (NativeProviderAvailabilityState::Available, _, _) => quality(0.68),
            _ => quality(0.35),
        },
    }
}

fn sample_service_metadata(
    batch_id: NativeSamplerBatchId,
    request: &NativeSamplerRuntimeActionRequest,
    seen_generation_keys: &mut BTreeSet<String>,
) -> ServiceSample {
    let sample = WindowsNativeServiceAdapter.sample(WindowsNativeServiceBounds {
        max_records: request.max_records_per_sample,
        max_bytes: request.max_bytes_per_sample,
        timeout_millis: request.timeout_millis,
        cancellation_requested: false,
    });
    let provider = ProviderStatus {
        provider_category: sample.provider_category.clone(),
        platform_category: sample.platform_category.clone(),
        availability_state: sample.availability_state.clone(),
        degraded_reason: sample.degraded_reason.clone(),
    };
    let mut counters = NativeSamplerCounterSummary::empty();
    counters.provider_enabled_count = sample.provider_enabled_count;
    counters.raw_record_count = sample.raw_record_count;
    counters.schema_accepted_count = sample.schema_accepted_count;
    counters.schema_rejected_count = sample.schema_rejected_count;
    counters.rate_limited_count = sample.rate_limited_count;
    counters.queue_dropped_count = sample.queue_dropped_count;
    counters.normalized_record_count = sample.normalized_record_count;
    counters.sampled_record_count = sample.schema_accepted_count;
    counters.skipped_record_count = sample.skipped_record_count;
    counters.malformed_record_count = sample.malformed_record_count;
    counters.rejected_record_count = sample.rejected_record_count;
    counters.timeout_count = sample.timeout_count;
    counters.sampled_record_count_bucket = counter_bucket(counters.sampled_record_count);
    counters.skipped_record_count_bucket = counter_bucket(counters.skipped_record_count);
    counters.bytes_processed_bucket = sample.bytes_processed_bucket;
    counters.unknown_category_ratio_bucket = sample.unknown_category_ratio_bucket;
    let records = sample
        .aggregates
        .into_iter()
        .map(|aggregate| {
            let generation_key = format!(
                "service_metadata_sampler:{:?}:{:?}:{:?}:{:?}:{}",
                aggregate.service_category,
                aggregate.service_state_bucket,
                aggregate.startup_type_bucket,
                aggregate.trust_category,
                CURRENT_SESSION_BUCKET
            );
            let first_seen = seen_generation_keys.insert(generation_key);
            let host_criticality_category = host_criticality(&aggregate.service_category);
            let category_unknown = aggregate.service_category == NativeServiceCategory::Unknown;
            NativeServiceMetadataRecord {
                service_observation_id: NativeServiceObservationId::new_v4(),
                service_category: aggregate.service_category,
                service_state_bucket: aggregate.service_state_bucket,
                startup_type_bucket: aggregate.startup_type_bucket,
                trust_category: aggregate.trust_category,
                signedness_bucket: NativeSignednessBucket::NotChecked,
                privilege_context_category: NativePrivilegeContextCategory::Unknown,
                host_criticality_category,
                first_seen_in_session: first_seen,
                count_bucket: counter_bucket(aggregate.observation_count),
                changed_state: false,
                sampler_id: "service_metadata_sampler".to_string(),
                sample_batch_id: batch_id.clone(),
                time_bucket: CURRENT_SESSION_BUCKET.to_string(),
                confidence_hint: if category_unknown {
                    quality(0.42)
                } else {
                    quality(0.68)
                },
                evidence_refs: Vec::new(),
                provenance_id: DataSourceId::new_v4().to_string(),
                redaction_status: RedactionStatus::Redacted,
                missing_visibility_flags: vec![
                    "process_visibility_unavailable".to_string(),
                    "packet_visibility_unavailable".to_string(),
                ],
            }
        })
        .collect::<Vec<_>>();
    ServiceSample {
        provider,
        records,
        counters,
    }
}

fn sample_process_metadata(
    batch_id: NativeSamplerBatchId,
    request: &NativeSamplerRuntimeActionRequest,
    seen_generation_keys: &mut BTreeSet<String>,
    previous_population: &mut BTreeMap<ProcessAggregateKey, u32>,
) -> ProcessSample {
    let provider_sample = platform_process_provider_sample(&ProcessProviderBounds {
        max_records: request.max_records_per_sample,
        max_bytes: request.max_bytes_per_sample,
        timeout: Duration::from_millis(request.timeout_millis as u64),
        cancellation_requested: false,
    });
    let mut counters = provider_sample.counters;
    let current_population = provider_sample.aggregates;
    let mut records = Vec::new();

    for (key, count) in &current_population {
        if records.len() >= sentinel_contracts::MAX_NATIVE_RUNTIME_RECORDS {
            counters.skipped_record_count = counters.skipped_record_count.saturating_add(1);
            continue;
        }
        let previous = previous_population.get(key).copied();
        let lifecycle_state_bucket = match previous {
            None => NativeProcessLifecycleStateBucket::NewlyObserved,
            Some(previous_count) if previous_count != *count => {
                NativeProcessLifecycleStateBucket::PopulationChanged
            }
            Some(_) => NativeProcessLifecycleStateBucket::ObservedRunning,
        };
        let start_count = previous.map_or(*count, |value| count.saturating_sub(value));
        let stop_count = previous.map_or(0, |value| value.saturating_sub(*count));
        let generation_key = process_generation_key(key);
        let first_seen_in_session = seen_generation_keys.insert(generation_key);
        if previous == Some(*count) {
            counters.duplicate_suppressed_count =
                counters.duplicate_suppressed_count.saturating_add(1);
        }
        records.push(process_metadata_record(
            key,
            batch_id.clone(),
            &ProcessTransitionSummary {
                lifecycle_state_bucket,
                first_seen_in_session,
                population_count: *count,
                start_count,
                stop_count,
                changed_category: previous.is_some_and(|value| value != *count),
            },
        ));
    }

    for (key, previous_count) in previous_population.iter() {
        if current_population.contains_key(key)
            || records.len() >= sentinel_contracts::MAX_NATIVE_RUNTIME_RECORDS
        {
            continue;
        }
        records.push(process_metadata_record(
            key,
            batch_id.clone(),
            &ProcessTransitionSummary {
                lifecycle_state_bucket: NativeProcessLifecycleStateBucket::NoLongerObserved,
                first_seen_in_session: false,
                population_count: 0,
                start_count: 0,
                stop_count: *previous_count,
                changed_category: true,
            },
        ));
    }

    if counters.provider_enabled_count == 0 && !records.is_empty() {
        counters.provider_enabled_count = 1;
    }
    if counters.raw_record_count == 0 {
        counters.raw_record_count = counters.sampled_record_count;
    }
    if counters.schema_accepted_count == 0 {
        counters.schema_accepted_count = counters.sampled_record_count;
    }
    counters.normalized_record_count = records.len().min(u32::MAX as usize) as u32;
    counters.sampled_record_count_bucket = counter_bucket(counters.sampled_record_count);
    counters.skipped_record_count_bucket = counter_bucket(counters.skipped_record_count);
    *previous_population = current_population;
    ProcessSample { records, counters }
}

fn process_metadata_record(
    key: &ProcessAggregateKey,
    batch_id: NativeSamplerBatchId,
    transition: &ProcessTransitionSummary,
) -> NativeProcessMetadataRecord {
    let mut missing_visibility_flags = vec![
        "process_network_attribution_unavailable".to_string(),
        "packet_visibility_unavailable".to_string(),
        "file_visibility_unavailable".to_string(),
        "registry_visibility_unavailable".to_string(),
    ];
    if key.parent_process_category == NativeProcessCategory::Unknown {
        missing_visibility_flags.push("parent_category_visibility_degraded".to_string());
    }
    let confidence_hint = if key.process_category == NativeProcessCategory::Unknown {
        quality(0.35)
    } else if key.parent_process_category == NativeProcessCategory::Unknown {
        quality(0.52)
    } else {
        quality(0.7)
    };
    NativeProcessMetadataRecord {
        process_observation_id: NativeProcessObservationId::new_v4(),
        process_category: key.process_category.clone(),
        parent_process_category: key.parent_process_category.clone(),
        relation_category: key.relation_category.clone(),
        execution_context_category: key.execution_context_category.clone(),
        trust_category: key.trust_category.clone(),
        signedness_bucket: key.signedness_bucket.clone(),
        privilege_context_category: key.privilege_context_category.clone(),
        integrity_context_bucket: key.integrity_context_bucket.clone(),
        session_context_category: key.session_context_category.clone(),
        lifecycle_state_bucket: transition.lifecycle_state_bucket.clone(),
        first_seen_in_session: transition.first_seen_in_session,
        population_count_bucket: counter_bucket(transition.population_count),
        start_count_bucket: counter_bucket(transition.start_count),
        stop_count_bucket: counter_bucket(transition.stop_count),
        changed_category: transition.changed_category,
        sampler_id: "process_metadata_sampler".to_string(),
        sample_batch_id: batch_id,
        time_bucket: CURRENT_SESSION_BUCKET.to_string(),
        confidence_hint,
        evidence_refs: Vec::new(),
        provenance_id: DataSourceId::new_v4().to_string(),
        redaction_status: RedactionStatus::Redacted,
        missing_visibility_flags,
    }
}

fn process_generation_key(key: &ProcessAggregateKey) -> String {
    format!(
        "process_metadata_sampler:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{}",
        key.process_category,
        key.parent_process_category,
        key.relation_category,
        key.execution_context_category,
        key.trust_category,
        key.signedness_bucket,
        key.privilege_context_category,
        CURRENT_SESSION_BUCKET
    )
}

#[cfg(windows)]
fn platform_process_provider_sample(bounds: &ProcessProviderBounds) -> ProcessProviderSample {
    WindowsToolhelpProcessCategoryProvider.sample_categories(bounds)
}

#[cfg(not(windows))]
fn platform_process_provider_sample(bounds: &ProcessProviderBounds) -> ProcessProviderSample {
    UnsupportedProcessCategoryProvider.sample_categories(bounds)
}

#[cfg(windows)]
#[derive(Clone, Debug, Default)]
struct WindowsToolhelpProcessCategoryProvider;

#[cfg(windows)]
impl NativeProcessCategoryProvider for WindowsToolhelpProcessCategoryProvider {
    fn sample_categories(&self, bounds: &ProcessProviderBounds) -> ProcessProviderSample {
        use std::mem::size_of;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let mut counters = NativeSamplerCounterSummary::empty();
        counters.bytes_processed_bucket = "metadata_only_low".to_string();
        if bounds.cancellation_requested {
            counters.skipped_record_count = 1;
            counters.skipped_record_count_bucket = "single".to_string();
            return ProcessProviderSample {
                aggregates: BTreeMap::new(),
                counters,
            };
        }
        let started = Instant::now();
        let mut classified = Vec::<(u32, u32, NativeProcessCategory)>::new();
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                counters.rejected_record_count = 1;
                return ProcessProviderSample {
                    aggregates: BTreeMap::new(),
                    counters,
                };
            }
            counters.provider_enabled_count = 1;
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            let mut has_entry = Process32FirstW(snapshot, &mut entry) != 0;
            while has_entry {
                if started.elapsed() >= bounds.timeout {
                    counters.timeout_count = counters.timeout_count.saturating_add(1);
                    break;
                }
                let projected_bytes = (classified.len() + 1) * size_of::<PROCESSENTRY32W>();
                if classified.len() >= bounds.max_records as usize
                    || projected_bytes > bounds.max_bytes as usize
                {
                    counters.skipped_record_count = counters.skipped_record_count.saturating_add(1);
                    counters.backpressure_event_count =
                        counters.backpressure_event_count.saturating_add(1);
                    break;
                }
                let category = classify_process(&wide_array_to_string(&entry.szExeFile));
                counters.raw_record_count = counters.raw_record_count.saturating_add(1);
                counters.schema_accepted_count = counters.schema_accepted_count.saturating_add(1);
                classified.push((entry.th32ProcessID, entry.th32ParentProcessID, category));
                entry.szExeFile.fill(0);
                has_entry = Process32NextW(snapshot, &mut entry) != 0;
            }
            CloseHandle(snapshot);
        }
        let category_by_ephemeral_id = classified
            .iter()
            .map(|(ephemeral_id, _, category)| (*ephemeral_id, category.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut aggregates = BTreeMap::<ProcessAggregateKey, u32>::new();
        let mut unknown_count = 0u32;
        for (_, parent_ephemeral_id, process_category) in classified {
            let parent_process_category = category_by_ephemeral_id
                .get(&parent_ephemeral_id)
                .cloned()
                .unwrap_or(NativeProcessCategory::Unknown);
            if process_category == NativeProcessCategory::Unknown {
                unknown_count = unknown_count.saturating_add(1);
            }
            let key = process_aggregate_key(process_category, parent_process_category);
            *aggregates.entry(key).or_insert(0) += 1;
            counters.sampled_record_count = counters.sampled_record_count.saturating_add(1);
        }
        counters.sampled_record_count_bucket = counter_bucket(counters.sampled_record_count);
        counters.skipped_record_count_bucket = counter_bucket(counters.skipped_record_count);
        counters.normalized_record_count = aggregates.len().min(u32::MAX as usize) as u32;
        counters.unknown_category_ratio_bucket =
            ratio_bucket(unknown_count, counters.sampled_record_count);
        counters.duration_bucket = duration_bucket(started.elapsed().as_millis() as u64);
        ProcessProviderSample {
            aggregates,
            counters,
        }
    }
}

#[cfg(not(windows))]
#[derive(Clone, Debug, Default)]
struct UnsupportedProcessCategoryProvider;

#[cfg(not(windows))]
impl NativeProcessCategoryProvider for UnsupportedProcessCategoryProvider {
    fn sample_categories(&self, _bounds: &ProcessProviderBounds) -> ProcessProviderSample {
        let mut counters = NativeSamplerCounterSummary::empty();
        counters.rejected_record_count = 1;
        counters.skipped_record_count = 1;
        counters.skipped_record_count_bucket = "single".to_string();
        counters.unknown_category_ratio_bucket = "unknown".to_string();
        ProcessProviderSample {
            aggregates: BTreeMap::new(),
            counters,
        }
    }
}

#[cfg(windows)]
fn wide_array_to_string<const N: usize>(value: &[u16; N]) -> String {
    let len = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(N);
    String::from_utf16_lossy(&value[..len])
}

fn process_aggregate_key(
    process_category: NativeProcessCategory,
    parent_process_category: NativeProcessCategory,
) -> ProcessAggregateKey {
    ProcessAggregateKey {
        relation_category: process_relation_category(&parent_process_category, &process_category),
        execution_context_category: process_execution_context(&process_category),
        trust_category: process_trust_category(&process_category),
        signedness_bucket: NativeSignednessBucket::NotChecked,
        privilege_context_category: process_privilege_context(&process_category),
        integrity_context_bucket: process_integrity_context(&process_category),
        session_context_category: process_session_context(&process_category),
        process_category,
        parent_process_category,
    }
}

#[cfg(windows)]
fn classify_process(raw_name: &str) -> NativeProcessCategory {
    let value = raw_name
        .trim()
        .trim_end_matches(".exe")
        .to_ascii_lowercase();
    if matches_any(
        &value,
        &[
            "system", "registry", "smss", "csrss", "wininit", "winlogon", "services", "lsass",
        ],
    ) {
        NativeProcessCategory::OperatingSystemCore
    } else if matches_any(&value, &["svchost", "taskhostw", "dllhost", "fontdrvhost"]) {
        NativeProcessCategory::ServiceHost
    } else if matches_any(
        &value,
        &["msmpeng", "sense", "securityhealthservice", "nissrv"],
    ) {
        NativeProcessCategory::Security
    } else if matches_any(
        &value,
        &["chrome", "msedge", "firefox", "brave", "opera", "iexplore"],
    ) {
        NativeProcessCategory::Browser
    } else if matches_any(
        &value,
        &["winword", "excel", "powerpnt", "outlook", "onenote"],
    ) {
        NativeProcessCategory::OfficeProductivity
    } else if matches_any(
        &value,
        &["powershell", "pwsh", "wscript", "cscript", "python", "node"],
    ) {
        NativeProcessCategory::ScriptingRuntime
    } else if matches_any(&value, &["cmd", "conhost", "windowsterminal"]) {
        NativeProcessCategory::CommandShell
    } else if matches_any(
        &value,
        &["devenv", "code", "rustc", "cargo", "msbuild", "git"],
    ) {
        NativeProcessCategory::DevelopmentTool
    } else if matches_any(
        &value,
        &["taskmgr", "mmc", "regedit", "procexp", "procmon", "wmic"],
    ) {
        NativeProcessCategory::AdministrativeTool
    } else if matches_any(&value, &["mstsc", "ssh", "winrs", "psexec"]) {
        NativeProcessCategory::RemoteManagement
    } else if matches_any(
        &value,
        &[
            "curl", "wget", "ping", "tracert", "nslookup", "netstat", "tcpview",
        ],
    ) {
        NativeProcessCategory::NetworkingTool
    } else if contains_any(&value, &["update", "installer", "setup", "msiexec"]) {
        NativeProcessCategory::UpdaterInstaller
    } else if contains_any(
        &value,
        &[
            "helper",
            "broker",
            "runtimebroker",
            "searchhost",
            "shellhost",
            "crashpad",
        ],
    ) {
        NativeProcessCategory::ApplicationSupport
    } else if matches_any(&value, &["explorer", "notepad", "mspaint", "calc"]) {
        NativeProcessCategory::UserApplication
    } else {
        NativeProcessCategory::Unknown
    }
}

#[cfg(windows)]
fn matches_any(value: &str, allowlist: &[&str]) -> bool {
    allowlist.contains(&value)
}

#[cfg(windows)]
fn contains_any(value: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| value.contains(marker))
}

fn process_relation_category(
    parent: &NativeProcessCategory,
    child: &NativeProcessCategory,
) -> NativeProcessParentRelationCategory {
    match (parent, child) {
        (NativeProcessCategory::OperatingSystemCore, NativeProcessCategory::ServiceHost) => {
            NativeProcessParentRelationCategory::SystemToService
        }
        (NativeProcessCategory::ServiceHost, _) => {
            NativeProcessParentRelationCategory::ServiceToWorker
        }
        (NativeProcessCategory::CommandShell, NativeProcessCategory::ScriptingRuntime) => {
            NativeProcessParentRelationCategory::ShellToScript
        }
        (NativeProcessCategory::Browser, NativeProcessCategory::ApplicationSupport) => {
            NativeProcessParentRelationCategory::BrowserToHelper
        }
        (NativeProcessCategory::OfficeProductivity, NativeProcessCategory::ApplicationSupport) => {
            NativeProcessParentRelationCategory::OfficeToHelper
        }
        (NativeProcessCategory::UpdaterInstaller, _) => {
            NativeProcessParentRelationCategory::UpdaterToInstaller
        }
        (NativeProcessCategory::AdministrativeTool, _) => {
            NativeProcessParentRelationCategory::AdministrativeToolToChild
        }
        (NativeProcessCategory::Unknown, NativeProcessCategory::Unknown) => {
            NativeProcessParentRelationCategory::UnknownToUnknown
        }
        (NativeProcessCategory::UserApplication, _)
        | (NativeProcessCategory::Browser, _)
        | (NativeProcessCategory::OfficeProductivity, _)
        | (NativeProcessCategory::DevelopmentTool, _) => {
            NativeProcessParentRelationCategory::ApplicationToChild
        }
        _ => NativeProcessParentRelationCategory::Unknown,
    }
}

fn process_execution_context(
    category: &NativeProcessCategory,
) -> NativeProcessExecutionContextCategory {
    match category {
        NativeProcessCategory::OperatingSystemCore => NativeProcessExecutionContextCategory::System,
        NativeProcessCategory::ServiceHost | NativeProcessCategory::Security => {
            NativeProcessExecutionContextCategory::Service
        }
        NativeProcessCategory::Browser
        | NativeProcessCategory::OfficeProductivity
        | NativeProcessCategory::ScriptingRuntime
        | NativeProcessCategory::CommandShell
        | NativeProcessCategory::DevelopmentTool
        | NativeProcessCategory::AdministrativeTool
        | NativeProcessCategory::RemoteManagement
        | NativeProcessCategory::NetworkingTool
        | NativeProcessCategory::UserApplication => {
            NativeProcessExecutionContextCategory::Interactive
        }
        NativeProcessCategory::UpdaterInstaller | NativeProcessCategory::ApplicationSupport => {
            NativeProcessExecutionContextCategory::Background
        }
        NativeProcessCategory::Unknown => NativeProcessExecutionContextCategory::Unknown,
    }
}

fn process_trust_category(category: &NativeProcessCategory) -> NativeProcessTrustCategory {
    match category {
        NativeProcessCategory::OperatingSystemCore | NativeProcessCategory::ServiceHost => {
            NativeProcessTrustCategory::OperatingSystemOwned
        }
        NativeProcessCategory::Security => NativeProcessTrustCategory::SecurityRelevant,
        NativeProcessCategory::Unknown => NativeProcessTrustCategory::Unknown,
        _ => NativeProcessTrustCategory::AllowlistedCategory,
    }
}

fn process_privilege_context(category: &NativeProcessCategory) -> NativePrivilegeContextCategory {
    match category {
        NativeProcessCategory::OperatingSystemCore
        | NativeProcessCategory::ServiceHost
        | NativeProcessCategory::Security => NativePrivilegeContextCategory::LocalSystemLike,
        NativeProcessCategory::Unknown => NativePrivilegeContextCategory::Unknown,
        _ => NativePrivilegeContextCategory::UserContextUnknown,
    }
}

fn process_integrity_context(category: &NativeProcessCategory) -> NativeIntegrityContextBucket {
    match category {
        NativeProcessCategory::OperatingSystemCore | NativeProcessCategory::ServiceHost => {
            NativeIntegrityContextBucket::SystemLike
        }
        _ => NativeIntegrityContextBucket::Unknown,
    }
}

fn process_session_context(category: &NativeProcessCategory) -> NativeSessionContextCategory {
    match category {
        NativeProcessCategory::OperatingSystemCore => NativeSessionContextCategory::SystemLike,
        NativeProcessCategory::ServiceHost | NativeProcessCategory::Security => {
            NativeSessionContextCategory::ServiceLike
        }
        NativeProcessCategory::UpdaterInstaller | NativeProcessCategory::ApplicationSupport => {
            NativeSessionContextCategory::BackgroundUnknown
        }
        NativeProcessCategory::Unknown => NativeSessionContextCategory::Unknown,
        _ => NativeSessionContextCategory::InteractiveUnknown,
    }
}

fn host_criticality(category: &NativeServiceCategory) -> NativeHostCriticalityCategory {
    match category {
        NativeServiceCategory::OperatingSystemCore | NativeServiceCategory::Security => {
            NativeHostCriticalityCategory::Critical
        }
        NativeServiceCategory::Network
        | NativeServiceCategory::RemoteManagement
        | NativeServiceCategory::Update
        | NativeServiceCategory::Storage => NativeHostCriticalityCategory::Important,
        NativeServiceCategory::Unknown => NativeHostCriticalityCategory::Unknown,
        _ => NativeHostCriticalityCategory::Standard,
    }
}

fn activation_blocked_reason(
    detail: &sentinel_contracts::NativeSamplerReadinessDetail,
    status: &NativeSamplerRuntimeStatus,
) -> Option<String> {
    if !detail.contract.sampler_implemented {
        return Some("sampler_not_implemented".to_string());
    }
    if detail.review.readiness_state != NativeSamplerReadinessState::ReadyWhenSamplerImplemented
        || !detail.review.allowed
    {
        return Some("readiness_review_blocked".to_string());
    }
    if detail.review.permission_state != NativePermissionState::GrantedSession {
        return Some("permission_not_granted".to_string());
    }
    if status.runtime_state == NativeSamplerRuntimeState::Revoked {
        return Some("runtime_revoked".to_string());
    }
    None
}

fn ensure_activation_allowed(
    detail: &sentinel_contracts::NativeSamplerReadinessDetail,
    status: &NativeSamplerRuntimeStatus,
) -> CommandResult<()> {
    if let Some(reason) = activation_blocked_reason(detail, status) {
        return Err(CoreError::new(
            ErrorCode::PermissionDenied,
            "native sampler activation is blocked",
        )
        .with_severity(ErrorSeverity::Warning)
        .with_redacted_details(json!({ "reason": reason, "sampler_id": status.sampler_id })));
    }
    Ok(())
}

fn ensure_sampling_allowed(
    detail: &sentinel_contracts::NativeSamplerReadinessDetail,
    status: &NativeSamplerRuntimeStatus,
) -> CommandResult<()> {
    ensure_activation_allowed(detail, status)?;
    if !matches!(
        status.runtime_state,
        NativeSamplerRuntimeState::Active | NativeSamplerRuntimeState::Idle
    ) {
        return Err(CoreError::new(
            ErrorCode::InvalidRequest,
            "native sampler must be active before sample-now",
        )
        .with_severity(ErrorSeverity::Warning)
        .with_redacted_details(json!({ "sampler_id": status.sampler_id })));
    }
    Ok(())
}

fn ensure_runtime_mutable(status: &NativeSamplerRuntimeStatus) -> CommandResult<()> {
    if matches!(
        status.runtime_state,
        NativeSamplerRuntimeState::Revoked | NativeSamplerRuntimeState::NotImplemented
    ) {
        return Err(CoreError::new(
            ErrorCode::InvalidRequest,
            "native sampler runtime state cannot be mutated",
        )
        .with_severity(ErrorSeverity::Warning)
        .with_redacted_details(json!({ "sampler_id": status.sampler_id })));
    }
    Ok(())
}

fn status_after_batch(
    mut status: NativeSamplerRuntimeStatus,
    batch: &NativeSamplerRuntimeBatch,
    telemetry_collection_started: bool,
) -> NativeSamplerRuntimeStatus {
    let provider_degraded = batch.counters.rejected_record_count > 0
        && (batch.counters.normalized_record_count == 0 || !batch_has_metadata_records(batch));
    status.runtime_state = if provider_degraded {
        NativeSamplerRuntimeState::Degraded
    } else {
        NativeSamplerRuntimeState::Idle
    };
    status.health_state = batch
        .health_record
        .as_ref()
        .map(|record| record.health_state.clone())
        .unwrap_or_else(|| {
            if provider_degraded {
                NativeRuntimeHealthState::Degraded
            } else {
                NativeRuntimeHealthState::Healthy
            }
        });
    status.provider_category = batch.provider_category.clone();
    status.platform_category = batch.platform_category.clone();
    status.provider_availability_state = batch
        .health_record
        .as_ref()
        .map(|record| record.provider_availability_state.clone())
        .unwrap_or_else(|| provider_status_for(&batch.category).availability_state);
    status.latest_batch_id = Some(batch.batch_id.clone());
    status.latest_sample_time_bucket = Some(CURRENT_SESSION_BUCKET.to_string());
    status.counters = batch.counters.clone();
    status.telemetry_collection_active = telemetry_collection_started;
    status.degraded_reason = batch
        .health_record
        .as_ref()
        .and_then(|record| record.degraded_reason.clone())
        .or_else(|| {
            (status.health_state != NativeRuntimeHealthState::Healthy)
                .then(|| "provider_degraded_or_unavailable".to_string())
        });
    status
}

fn batch_has_metadata_records(batch: &NativeSamplerRuntimeBatch) -> bool {
    batch.health_record.is_some()
        || !batch.service_records.is_empty()
        || !batch.process_records.is_empty()
}

fn missing_visibility_flags_for(
    detail: &sentinel_contracts::NativeSamplerReadinessDetail,
) -> Vec<String> {
    let mut flags = detail.review.missing_prerequisite_flags.clone();
    if detail.contract.category != NativeSamplerCategory::ProcessMetadataSampler {
        push_unique(&mut flags, "process_visibility_unavailable");
    } else {
        push_unique(&mut flags, "process_visibility_requires_fresh_sample");
        push_unique(&mut flags, "process_network_attribution_unavailable");
        push_unique(&mut flags, "file_visibility_unavailable");
        push_unique(&mut flags, "registry_visibility_unavailable");
    }
    push_unique(&mut flags, "packet_visibility_unavailable");
    if detail.contract.category == NativeSamplerCategory::ServiceMetadataSampler {
        push_unique(&mut flags, "service_visibility_requires_fresh_sample");
    }
    flags
}

fn runtime_audit_entry(
    request: &NativeSamplerRuntimeActionRequest,
    status: &NativeSamplerRuntimeStatus,
) -> NativeSamplerRuntimeAuditEntry {
    NativeSamplerRuntimeAuditEntry {
        audit_id: AuditId::new_v4(),
        sampler_id: request.sampler_id.clone(),
        action: request.action.clone(),
        resulting_runtime_state: status.runtime_state.clone(),
        time_bucket: CURRENT_SESSION_BUCKET.to_string(),
        provenance_id: PROVENANCE_ID.to_string(),
        summary_redacted: format!("native_sampler_runtime_action_{:?}", request.action)
            .to_ascii_lowercase(),
    }
}

fn native_runtime_event<T: serde::Serialize>(
    producer_plugin: &PluginId,
    topic: &str,
    payload: &T,
    trace_context: &TraceContext,
) -> CommandResult<EventEnvelope> {
    let mut event = EventEnvelope::new(
        EventType::new(topic).map_err(contract_error)?,
        NATIVE_SAMPLER_RUNTIME_SCHEMA_VERSION,
        producer_plugin.clone(),
        trace_context.clone(),
    );
    event.privacy_class = PrivacyClass::Internal;
    event.quality_score = quality(0.7);
    event.payload = serde_json::to_value(payload).map_err(native_runtime_error)?;
    Ok(event)
}

fn contract_registry_for_manifest(manifest: &PluginManifest) -> CommandResult<ContractRegistry> {
    let mut registry = ContractRegistry::new();
    for contract in manifest
        .input_contracts
        .iter()
        .chain(manifest.output_contracts.iter())
    {
        registry
            .register(contract.clone())
            .map_err(native_runtime_error)?;
    }
    Ok(registry)
}

fn plugin_context_for_manifest(
    manifest: &PluginManifest,
    trace_context: TraceContext,
) -> CommandResult<PluginContext<'static>> {
    let mut context = PluginContext::new(
        manifest.plugin_id.clone(),
        manifest.runtime_mode.clone(),
        trace_context,
    );
    for contract in &manifest.input_contracts {
        context
            .topic_scope
            .subscribe_topics
            .insert(topic_for_contract(contract)?);
    }
    for contract in &manifest.output_contracts {
        context
            .topic_scope
            .publish_topics
            .insert(topic_for_contract(contract)?);
    }
    for permission in &manifest.required_permissions {
        context
            .permission_scope
            .required_permissions
            .insert(permission.permission.clone());
        context
            .permission_scope
            .granted_permissions
            .insert(permission.permission.clone());
    }
    context.checkpoint =
        CheckpointSupport::from_manifest_level(manifest.checkpoint_support.clone());
    context.replay = ReplaySupport::from_manifest_level(manifest.replay_support.clone());
    Ok(context)
}

fn topic_for_contract(contract: &ContractDescriptor) -> CommandResult<TopicName> {
    TopicName::new(
        contract
            .topic
            .as_deref()
            .unwrap_or(contract.contract_name.as_str()),
    )
    .map_err(contract_error)
}

fn batch_generation_keys(batch: &NativeSamplerRuntimeBatch) -> Vec<String> {
    let mut keys = batch
        .service_records
        .iter()
        .map(|record| {
            format!(
                "{}:{:?}:{:?}:{:?}:{:?}:{}",
                record.sampler_id,
                record.service_category,
                record.service_state_bucket,
                record.startup_type_bucket,
                record.trust_category,
                record.time_bucket
            )
        })
        .collect::<Vec<_>>();
    keys.extend(batch.process_records.iter().map(|record| {
        format!(
            "{}:{:?}:{:?}:{:?}:{:?}:{}",
            record.sampler_id,
            record.process_category,
            record.parent_process_category,
            record.relation_category,
            record.execution_context_category,
            record.time_bucket
        )
    }));
    keys
}

fn service_category_counts(
    records: &[&NativeServiceMetadataRecord],
) -> Vec<NativeServiceCategoryCount> {
    let mut counts = BTreeMap::<NativeServiceCategory, u32>::new();
    for record in records {
        *counts.entry(record.service_category.clone()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(
            |(service_category, observation_count)| NativeServiceCategoryCount {
                service_category,
                count_bucket: counter_bucket(observation_count),
                observation_count,
            },
        )
        .collect()
}

fn service_bucket_counts(labels: impl Iterator<Item = String>) -> Vec<NativeServiceBucketCount> {
    let mut counts = BTreeMap::<String, u32>::new();
    for label in labels {
        *counts.entry(label).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(label, observation_count)| NativeServiceBucketCount {
            label,
            count_bucket: counter_bucket(observation_count),
            observation_count,
        })
        .collect()
}

fn process_category_counts<'a>(
    records: impl Iterator<Item = &'a NativeProcessMetadataRecord>,
    parent: bool,
) -> Vec<NativeProcessCategoryCount> {
    let mut counts = BTreeMap::<NativeProcessCategory, u32>::new();
    for record in records {
        let category = if parent {
            record.parent_process_category.clone()
        } else {
            record.process_category.clone()
        };
        *counts.entry(category).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(
            |(process_category, observation_count)| NativeProcessCategoryCount {
                process_category,
                count_bucket: counter_bucket(observation_count),
                observation_count,
            },
        )
        .collect()
}

fn process_bucket_counts(labels: impl Iterator<Item = String>) -> Vec<NativeProcessBucketCount> {
    let mut counts = BTreeMap::<String, u32>::new();
    for label in labels {
        *counts.entry(label).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(label, observation_count)| NativeProcessBucketCount {
            label,
            count_bucket: counter_bucket(observation_count),
            observation_count,
        })
        .collect()
}

fn quality_bucket_for(
    statuses: &[NativeSamplerRuntimeStatus],
    batches: &[NativeSamplerRuntimeBatch],
) -> String {
    if batches
        .iter()
        .any(|batch| !batch.process_records.is_empty())
    {
        let unknown = batches
            .iter()
            .flat_map(|batch| batch.process_records.iter())
            .filter(|record| record.process_category == NativeProcessCategory::Unknown)
            .count();
        let total = batches
            .iter()
            .map(|batch| batch.process_records.len())
            .sum::<usize>();
        if total > 0 && unknown * 2 >= total {
            "degraded_high_unknown_process_category_ratio".to_string()
        } else {
            "medium_process_category_visibility_context".to_string()
        }
    } else if batches
        .iter()
        .any(|batch| !batch.service_records.is_empty() || batch.health_record.is_some())
    {
        "medium_service_visibility_context".to_string()
    } else if statuses.iter().any(|status| {
        matches!(
            status.runtime_state,
            NativeSamplerRuntimeState::Degraded | NativeSamplerRuntimeState::ReadinessBlocked
        )
    }) {
        "degraded_no_fresh_sample".to_string()
    } else {
        "unknown_no_sample".to_string()
    }
}

fn count_runtime(statuses: &[NativeSamplerRuntimeStatus], state: NativeSamplerRuntimeState) -> u32 {
    statuses
        .iter()
        .filter(|status| status.runtime_state == state)
        .count() as u32
}

fn counter_bucket(value: u32) -> String {
    match value {
        0 => "none",
        1 => "single",
        2..=10 => "low",
        11..=100 => "medium",
        _ => "high",
    }
    .to_string()
}

fn duration_bucket(millis: u64) -> String {
    match millis {
        0..=50 => "sub_50ms",
        51..=250 => "sub_250ms",
        251..=1_000 => "sub_1s",
        _ => "over_1s",
    }
    .to_string()
}

fn ratio_bucket(part: u32, total: u32) -> String {
    if total == 0 {
        return "none".to_string();
    }
    let ratio = part as f32 / total as f32;
    if ratio == 0.0 {
        "none"
    } else if ratio < 0.25 {
        "low"
    } else if ratio < 0.75 {
        "medium"
    } else {
        "high"
    }
    .to_string()
}

fn quality(value: f32) -> QualityScore {
    QualityScore::new(value).unwrap_or_else(|_| QualityScore::unknown())
}

fn bounded_unique_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            output.push(value);
        }
        if output.len() >= sentinel_contracts::MAX_NATIVE_SAMPLER_REFS {
            break;
        }
    }
    output
}

fn bounded_fact_refs(values: Vec<SecurityFactId>) -> Vec<SecurityFactId> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for value in values {
        if seen.insert(value.to_string()) {
            output.push(value);
        }
        if output.len() >= sentinel_contracts::MAX_NATIVE_SAMPLER_REFS {
            break;
        }
    }
    output
}

fn bounded_evidence_refs(values: Vec<EvidenceId>) -> Vec<EvidenceId> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for value in values {
        if seen.insert(value.to_string()) {
            output.push(value);
        }
        if output.len() >= sentinel_contracts::MAX_NATIVE_SAMPLER_REFS {
            break;
        }
    }
    output
}

fn bound_runtime_audit(values: &mut Vec<NativeSamplerRuntimeAuditEntry>) {
    if values.len() > sentinel_contracts::MAX_NATIVE_SAMPLER_REFS {
        values.drain(0..values.len() - sentinel_contracts::MAX_NATIVE_SAMPLER_REFS);
    }
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn validate_safe_request_id(field: &'static str, value: &str) -> CommandResult<()> {
    if value.trim().is_empty()
        || value.len() > 160
        || value.contains('\\')
        || value.contains('/')
        || value.contains('@')
        || value.contains(':')
    {
        return Err(
            CoreError::validation_failure("unsafe native sampler request id")
                .with_redacted_details(json!({ "field": field })),
        );
    }
    Ok(())
}

fn native_runtime_error(error: impl ToString) -> CoreError {
    CoreError::new(ErrorCode::InternalError, "native sampler runtime failed")
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn contract_error(error: impl ToString) -> CoreError {
    CoreError::validation_failure("native sampler runtime contract validation failed")
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorized_native_permissions::AuthorizedNativePermissionRuntime;

    fn grant(read: &mut ReadOnlyCommandState, capability_id: &str) {
        let mut permission_runtime = AuthorizedNativePermissionRuntime::from_read_state(read);
        permission_runtime
            .apply_action(NativePermissionActionRequest {
                capability_id: capability_id.to_string(),
                action: NativePermissionAction::GrantAuthorization,
                explicit_user_action: true,
                reason_redacted: "authorize native sampler".to_string(),
            })
            .expect("grant");
        permission_runtime.sync_read_state(read);
    }

    fn runtime_request(
        sampler_id: &str,
        action: NativeSamplerRuntimeAction,
    ) -> NativeSamplerRuntimeActionRequest {
        NativeSamplerRuntimeActionRequest {
            sampler_id: sampler_id.to_string(),
            action,
            explicit_user_action: true,
            enable_interval_sampling: false,
            max_records_per_sample: 128,
            max_bytes_per_sample: 65_536,
            timeout_millis: 5_000,
            reason_redacted: "authorized bounded native sampler action".to_string(),
        }
    }

    #[test]
    fn native_sampler_preview_creates_no_runtime_state() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "service_metadata_visibility");
        let runtime = NativeSamplerRuntime::from_read_state(&read);
        let preview = runtime
            .preview_activation(&read, "service_metadata_sampler")
            .expect("preview");
        assert!(preview.activation_allowed);
        assert!(runtime.statuses.is_empty());
        assert!(read.native_sampler_runtime_statuses.is_empty());
    }

    #[test]
    fn native_sampler_activation_requires_permission_and_explicit_action() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let denied = runtime.apply_action(
            &mut read,
            NativeSamplerRuntimeActionRequest {
                sampler_id: "service_metadata_sampler".to_string(),
                action: NativeSamplerRuntimeAction::Activate,
                explicit_user_action: true,
                enable_interval_sampling: false,
                max_records_per_sample: 32,
                max_bytes_per_sample: 32_768,
                timeout_millis: 1_000,
                reason_redacted: "activate".to_string(),
            },
        );
        assert!(denied.is_err());

        grant(&mut read, "service_metadata_visibility");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let implicit = runtime.apply_action(
            &mut read,
            NativeSamplerRuntimeActionRequest {
                sampler_id: "service_metadata_sampler".to_string(),
                action: NativeSamplerRuntimeAction::Activate,
                explicit_user_action: false,
                enable_interval_sampling: false,
                max_records_per_sample: 32,
                max_bytes_per_sample: 32_768,
                timeout_millis: 1_000,
                reason_redacted: "activate".to_string(),
            },
        );
        assert!(implicit.is_err());
    }

    #[test]
    fn service_sampler_lifecycle_emits_only_bounded_category_facts() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "service_metadata_visibility");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);

        runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "service_metadata_sampler",
                    NativeSamplerRuntimeAction::Activate,
                ),
            )
            .expect("activate");
        runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "service_metadata_sampler",
                    NativeSamplerRuntimeAction::Pause,
                ),
            )
            .expect("pause");
        runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "service_metadata_sampler",
                    NativeSamplerRuntimeAction::Resume,
                ),
            )
            .expect("resume");
        let sampled = runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "service_metadata_sampler",
                    NativeSamplerRuntimeAction::SampleNow,
                ),
            )
            .expect("sample");

        #[cfg(windows)]
        {
            let batch = sampled.latest_batch.as_ref().expect("service batch");
            assert!(batch.counters.provider_enabled_count > 0);
            assert!(batch.counters.raw_record_count > 0);
            assert!(batch.counters.schema_accepted_count > 0);
            assert!(batch.counters.normalized_record_count > 0);
            assert!(!batch.service_records.is_empty());
            assert!(batch.process_records.is_empty());
            assert!(batch.health_record.is_none());
            assert!(batch.counters.published_batch_count > 0);
            assert!(batch.counters.eventbus_publication_count > 0);
            assert!(batch.counters.dag_dispatch_count > 0);
            assert!(batch.counters.plugin_runtime_invocation_count > 0);
            assert!(batch.counters.facts_emitted_count > 0);
            assert!(batch.counters.detector_consumer_invocation_count > 0);
            assert!(batch.counters.detector_observations_consumed_count > 0);
        }
        assert!(read.security_facts.items.iter().all(|fact| {
            fact.layer == sentinel_contracts::SecurityLayer::AuthorizedNativeService
        }));
        assert!(read.findings.items.is_empty());

        let serialized = serde_json::to_string(&(
            &read.native_sampler_runtime_statuses,
            &read.native_sampler_runtime_batches,
            &read.security_facts.items,
        ))
        .expect("serialize service runtime");
        for forbidden in [
            "service_name",
            "display_name",
            "executable_path",
            "command_line",
            "account_name",
            "username",
            "\"sid\"",
            "\"pid\"",
            "registry_path",
            "credential",
            "secret",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }

        runtime
            .apply_action(
                &mut read,
                runtime_request("service_metadata_sampler", NativeSamplerRuntimeAction::Stop),
            )
            .expect("stop");
        runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "service_metadata_sampler",
                    NativeSamplerRuntimeAction::Revoke,
                ),
            )
            .expect("revoke");
        assert!(runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "service_metadata_sampler",
                    NativeSamplerRuntimeAction::SampleNow,
                ),
            )
            .is_err());
    }

    #[test]
    fn service_sampler_no_overlap_guard_rejects_concurrent_sample() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "service_metadata_visibility");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "service_metadata_sampler",
                    NativeSamplerRuntimeAction::Activate,
                ),
            )
            .expect("activate");
        runtime
            .sampling_in_progress
            .insert("service_metadata_sampler".to_string());

        let overlapping = runtime.apply_action(
            &mut read,
            runtime_request(
                "service_metadata_sampler",
                NativeSamplerRuntimeAction::SampleNow,
            ),
        );
        assert!(overlapping.is_err());
    }

    #[test]
    fn native_sampler_sample_emits_bounded_facts_without_response_or_llm() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "native_health_probe");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        runtime
            .apply_action(
                &mut read,
                NativeSamplerRuntimeActionRequest {
                    sampler_id: "native_health_probe_sampler".to_string(),
                    action: NativeSamplerRuntimeAction::Activate,
                    explicit_user_action: true,
                    enable_interval_sampling: false,
                    max_records_per_sample: 8,
                    max_bytes_per_sample: 8_192,
                    timeout_millis: 1_000,
                    reason_redacted: "activate health sampler".to_string(),
                },
            )
            .expect("activate");
        let result = runtime
            .apply_action(
                &mut read,
                NativeSamplerRuntimeActionRequest {
                    sampler_id: "native_health_probe_sampler".to_string(),
                    action: NativeSamplerRuntimeAction::SampleNow,
                    explicit_user_action: true,
                    enable_interval_sampling: false,
                    max_records_per_sample: 8,
                    max_bytes_per_sample: 8_192,
                    timeout_millis: 1_000,
                    reason_redacted: "sample health".to_string(),
                },
            )
            .expect("sample");
        assert!(!result.response_execution_started);
        assert!(!result.automatic_llm_calls);
        assert!(result.emitted_topics.iter().all(|topic| {
            sentinel_contracts::NATIVE_SAMPLER_ALLOWED_TOPICS.contains(&topic.as_str())
        }));
        assert!(read.security_facts.items.iter().all(|fact| matches!(
            fact.layer,
            sentinel_contracts::SecurityLayer::AuthorizedNativeHealth
        )));
        let serialized = serde_json::to_string(&(
            read.native_sampler_runtime_statuses,
            read.native_sampler_runtime_batches,
            read.security_facts.items,
        ))
        .expect("serialize");
        for forbidden in [
            "service_name",
            "display_name",
            "executable_path",
            "command_line",
            "account",
            "pid",
            "C:\\",
            "password",
            "token",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn process_sampler_lifecycle_emits_category_only_facts_and_revocation_blocks_sampling() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "process_metadata_visibility");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        let preview = runtime
            .preview_activation(&read, "process_metadata_sampler")
            .expect("preview");
        assert!(preview.activation_allowed);
        assert!(runtime.statuses.is_empty());

        runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "process_metadata_sampler",
                    NativeSamplerRuntimeAction::Activate,
                ),
            )
            .expect("activate");
        runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "process_metadata_sampler",
                    NativeSamplerRuntimeAction::Pause,
                ),
            )
            .expect("pause");
        runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "process_metadata_sampler",
                    NativeSamplerRuntimeAction::Resume,
                ),
            )
            .expect("resume");
        let sampled = runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "process_metadata_sampler",
                    NativeSamplerRuntimeAction::SampleNow,
                ),
            )
            .expect("sample");

        #[cfg(windows)]
        assert!(sampled
            .latest_batch
            .as_ref()
            .is_some_and(|batch| !batch.process_records.is_empty()));
        assert!(read.findings.items.is_empty());
        let process_facts = read
            .security_facts
            .items
            .iter()
            .filter(|fact| fact.layer == sentinel_contracts::SecurityLayer::AuthorizedNativeProcess)
            .collect::<Vec<_>>();
        #[cfg(windows)]
        assert!(!process_facts.is_empty());
        assert!(
            process_facts.iter().all(|fact| matches!(
                fact.category.as_str(),
                "endpoint.process.category_fact" | "endpoint.process_parent.category_fact"
            )),
            "unexpected process fact categories: {:?}",
            process_facts
                .iter()
                .map(|fact| fact.category.as_str())
                .collect::<Vec<_>>()
        );
        let summary = runtime.summary(&read).expect("summary");
        #[cfg(windows)]
        assert!(summary.process_visibility_available);
        assert!(!summary.process_network_attribution_available);
        assert!(!summary.packet_visibility_available);
        assert!(!summary.edr_coverage_claimed);
        let quality_summary =
            crate::evidence_quality::build_evidence_quality_summary(&read).expect("quality");
        #[cfg(windows)]
        assert!(!quality_summary
            .missing_visibility_flags
            .iter()
            .any(|flag| flag == "missing_process_category_visibility"));
        assert!(quality_summary
            .missing_visibility_flags
            .iter()
            .any(|flag| flag == "process_network_attribution_unavailable"));

        runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "process_metadata_sampler",
                    NativeSamplerRuntimeAction::Revoke,
                ),
            )
            .expect("revoke");
        assert!(runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "process_metadata_sampler",
                    NativeSamplerRuntimeAction::SampleNow,
                ),
            )
            .is_err());

        let serialized = serde_json::to_string(&(
            read.native_sampler_runtime_statuses,
            read.native_sampler_runtime_batches,
            read.security_facts.items,
        ))
        .expect("serialize");
        for forbidden in [
            "process_name",
            "parent_pid",
            "command_line",
            "executable_path",
            "working_directory",
            "username",
            "account_name",
            "socket",
            "ip_address",
            "C:\\",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn process_provider_bounds_cancel_and_no_overlap_degrade_safely() {
        let cancelled = platform_process_provider_sample(&ProcessProviderBounds {
            max_records: 8,
            max_bytes: 8_192,
            timeout: Duration::from_millis(100),
            cancellation_requested: true,
        });
        assert!(cancelled.aggregates.is_empty());
        assert_eq!(cancelled.counters.skipped_record_count, 1);

        let mut read = ReadOnlyCommandState::bootstrap().expect("read");
        grant(&mut read, "process_metadata_visibility");
        let mut runtime = NativeSamplerRuntime::from_read_state(&read);
        runtime
            .apply_action(
                &mut read,
                runtime_request(
                    "process_metadata_sampler",
                    NativeSamplerRuntimeAction::Activate,
                ),
            )
            .expect("activate");
        runtime
            .sampling_in_progress
            .insert("process_metadata_sampler".to_string());
        let overlapping = runtime.apply_action(
            &mut read,
            runtime_request(
                "process_metadata_sampler",
                NativeSamplerRuntimeAction::SampleNow,
            ),
        );
        assert!(overlapping.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn unknown_process_classification_never_echoes_raw_value() {
        assert_eq!(
            classify_process("sensitive-raw-provider-value.exe"),
            NativeProcessCategory::Unknown
        );
    }
}
