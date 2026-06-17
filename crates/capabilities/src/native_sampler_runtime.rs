use sentinel_contracts::{
    FusionContractError, NativeHealthMetadataRecord, NativeProcessCategory,
    NativeProcessMetadataRecord, NativeSamplerRuntimeBatch, NativeServiceCategory,
    NativeServiceMetadataRecord, SecurityFact, SecurityLayer,
};

pub const NATIVE_SAMPLER_RUNTIME_SCHEMA_VERSION: sentinel_contracts::SchemaVersion =
    sentinel_contracts::SchemaVersion::new(1, 0, 0);
pub const ENDPOINT_NATIVE_HEALTH_FACT_CONTRACT: &str = "endpoint.native_health.category_fact";
pub const ENDPOINT_SERVICE_CATEGORY_FACT_CONTRACT: &str = "endpoint.service.category_fact";
pub const ENDPOINT_PROCESS_CATEGORY_FACT_CONTRACT: &str = "endpoint.process.category_fact";
pub const ENDPOINT_PROCESS_PARENT_CATEGORY_FACT_CONTRACT: &str =
    "endpoint.process_parent.category_fact";

#[derive(Clone, Debug, Default)]
pub struct NativeSamplerFactPlugin;

impl NativeSamplerFactPlugin {
    pub fn process_batch(
        &self,
        batch: &NativeSamplerRuntimeBatch,
    ) -> Result<Vec<SecurityFact>, FusionContractError> {
        batch
            .validate()
            .map_err(|_| FusionContractError::UnsafeField("native_sampler_batch"))?;
        let mut facts = Vec::new();
        if let Some(health) = &batch.health_record {
            facts.push(native_health_fact(health)?);
        }
        for service in &batch.service_records {
            facts.push(service_category_fact(service)?);
        }
        for process in &batch.process_records {
            facts.push(process_category_fact(process)?);
            facts.push(process_parent_category_fact(process)?);
        }
        Ok(facts)
    }
}

pub fn native_health_fact(
    health: &NativeHealthMetadataRecord,
) -> Result<SecurityFact, FusionContractError> {
    health
        .validate()
        .map_err(|_| FusionContractError::UnsafeField("native_health_metadata"))?;
    let mut fact = SecurityFact::new(
        SecurityLayer::AuthorizedNativeHealth,
        ENDPOINT_NATIVE_HEALTH_FACT_CONTRACT,
        health.sampler_id.clone(),
        health_time(),
    )?;
    fact.provider_service_category = Some("native_health".to_string());
    fact.status_category = Some(
        format!("resource_pressure_{:?}", health.resource_pressure_bucket).to_ascii_lowercase(),
    );
    fact.lifecycle_bucket = Some(format!("{:?}", health.uptime_bucket).to_ascii_lowercase());
    fact.count_bucket = Some(format!("{:?}", health.freshness_bucket).to_ascii_lowercase());
    fact.confidence_hint = health.quality_score.clone();
    fact.provenance_id = sentinel_contracts::DataSourceId::parse_str(&health.provenance_id).ok();
    fact.redaction_status = health.redaction_status.clone();
    fact.missing_visibility_flags = health.missing_prerequisite_flags.clone();
    fact.degraded_reason = health.degraded_reason.clone();
    fact.validate()?;
    Ok(fact)
}

pub fn service_category_fact(
    service: &NativeServiceMetadataRecord,
) -> Result<SecurityFact, FusionContractError> {
    service
        .validate()
        .map_err(|_| FusionContractError::UnsafeField("native_service_metadata"))?;
    let mut fact = SecurityFact::new(
        SecurityLayer::AuthorizedNativeService,
        ENDPOINT_SERVICE_CATEGORY_FACT_CONTRACT,
        service.sampler_id.clone(),
        health_time(),
    )?;
    fact.provider_service_category = Some(service_category_label(&service.service_category));
    fact.status_category = Some(format!("{:?}", service.service_state_bucket).to_ascii_lowercase());
    fact.auth_category = Some(format!("{:?}", service.startup_type_bucket).to_ascii_lowercase());
    fact.confidence_hint = service.confidence_hint.clone();
    fact.evidence_refs = service.evidence_refs.clone();
    fact.provenance_id = sentinel_contracts::DataSourceId::parse_str(&service.provenance_id).ok();
    fact.redaction_status = service.redaction_status.clone();
    fact.missing_visibility_flags = service.missing_visibility_flags.clone();
    if service.service_category == NativeServiceCategory::Unknown {
        fact.degraded_reason = Some("unknown_service_category".to_string());
    } else {
        fact.degraded_reason = Some("service_visibility_context_only".to_string());
    }
    fact.validate()?;
    Ok(fact)
}

pub fn process_category_fact(
    process: &NativeProcessMetadataRecord,
) -> Result<SecurityFact, FusionContractError> {
    process
        .validate()
        .map_err(|_| FusionContractError::UnsafeField("native_process_metadata"))?;
    process_fact(process, ENDPOINT_PROCESS_CATEGORY_FACT_CONTRACT)
}

pub fn process_parent_category_fact(
    process: &NativeProcessMetadataRecord,
) -> Result<SecurityFact, FusionContractError> {
    process
        .validate()
        .map_err(|_| FusionContractError::UnsafeField("native_process_parent_metadata"))?;
    process_fact(process, ENDPOINT_PROCESS_PARENT_CATEGORY_FACT_CONTRACT)
}

fn process_fact(
    process: &NativeProcessMetadataRecord,
    category: &str,
) -> Result<SecurityFact, FusionContractError> {
    let mut fact = SecurityFact::new(
        SecurityLayer::AuthorizedNativeProcess,
        category,
        process.sampler_id.clone(),
        health_time(),
    )?;
    fact.process_category = Some(process_category_label(&process.process_category));
    fact.parent_process_category = Some(process_category_label(&process.parent_process_category));
    fact.relation_category = Some(format!("{:?}", process.relation_category).to_ascii_lowercase());
    fact.execution_context_category =
        Some(format!("{:?}", process.execution_context_category).to_ascii_lowercase());
    fact.trust_category = Some(format!("{:?}", process.trust_category).to_ascii_lowercase());
    fact.signedness_bucket = Some(format!("{:?}", process.signedness_bucket).to_ascii_lowercase());
    fact.privilege_context_category =
        Some(format!("{:?}", process.privilege_context_category).to_ascii_lowercase());
    fact.lifecycle_bucket =
        Some(format!("{:?}", process.lifecycle_state_bucket).to_ascii_lowercase());
    fact.count_bucket = Some(process.population_count_bucket.clone());
    fact.confidence_hint = process.confidence_hint.clone();
    fact.evidence_refs = process.evidence_refs.clone();
    fact.provenance_id = sentinel_contracts::DataSourceId::parse_str(&process.provenance_id).ok();
    fact.redaction_status = process.redaction_status.clone();
    fact.missing_visibility_flags = process.missing_visibility_flags.clone();
    fact.degraded_reason = Some(
        if process.process_category == NativeProcessCategory::Unknown
            || process.parent_process_category == NativeProcessCategory::Unknown
        {
            "unknown_process_category_context"
        } else {
            "process_category_visibility_context_only"
        }
        .to_string(),
    );
    fact.validate()?;
    Ok(fact)
}

fn service_category_label(category: &NativeServiceCategory) -> String {
    format!("{category:?}").to_ascii_lowercase()
}

fn process_category_label(category: &NativeProcessCategory) -> String {
    format!("{category:?}").to_ascii_lowercase()
}

fn health_time() -> sentinel_contracts::Timestamp {
    sentinel_contracts::Timestamp::now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        NativeHostCriticalityCategory, NativeIntegrityContextBucket,
        NativePrivilegeContextCategory, NativeProcessExecutionContextCategory,
        NativeProcessLifecycleStateBucket, NativeProcessMetadataRecord, NativeProcessObservationId,
        NativeProcessParentRelationCategory, NativeProcessTrustCategory, NativeProviderCategory,
        NativeRuntimePlatformCategory, NativeSamplerBatchId, NativeSamplerCategory,
        NativeSamplerCounterSummary, NativeSamplerRuntimeState, NativeServiceObservationId,
        NativeServiceStartupTypeBucket, NativeServiceStateBucket, NativeServiceTrustCategory,
        NativeSessionContextCategory, NativeSignednessBucket, QualityScore, RedactionStatus,
    };

    #[test]
    fn native_sampler_fact_builder_emits_only_allowed_fact_families() {
        let batch_id = NativeSamplerBatchId::new_v4();
        let service = NativeServiceMetadataRecord {
            service_observation_id: NativeServiceObservationId::new_v4(),
            service_category: NativeServiceCategory::Security,
            service_state_bucket: NativeServiceStateBucket::Running,
            startup_type_bucket: NativeServiceStartupTypeBucket::Automatic,
            trust_category: NativeServiceTrustCategory::SecurityRelevant,
            signedness_bucket: NativeSignednessBucket::NotChecked,
            privilege_context_category: NativePrivilegeContextCategory::Unknown,
            host_criticality_category: NativeHostCriticalityCategory::Important,
            first_seen_in_session: true,
            count_bucket: "low".to_string(),
            changed_state: false,
            sampler_id: "service_metadata_sampler".to_string(),
            sample_batch_id: batch_id.clone(),
            time_bucket: "current_session".to_string(),
            confidence_hint: QualityScore::new(0.72).expect("quality"),
            evidence_refs: Vec::new(),
            provenance_id: sentinel_contracts::DataSourceId::new_v4().to_string(),
            redaction_status: RedactionStatus::Redacted,
            missing_visibility_flags: vec!["missing_process_visibility".to_string()],
        };
        let batch = NativeSamplerRuntimeBatch {
            batch_id,
            sampler_id: "service_metadata_sampler".to_string(),
            category: NativeSamplerCategory::ServiceMetadataSampler,
            runtime_state: NativeSamplerRuntimeState::Active,
            provider_category: NativeProviderCategory::WindowsServiceControlManager,
            platform_category: NativeRuntimePlatformCategory::Windows,
            health_record: None,
            service_records: vec![service],
            process_records: Vec::new(),
            counters: NativeSamplerCounterSummary::empty(),
            emitted_topics: vec![
                "native.service.metadata".to_string(),
                "endpoint.service.category_fact".to_string(),
                "native.sampler.runtime_status".to_string(),
            ],
            fact_refs: Vec::new(),
            evidence_refs: Vec::new(),
            audit_refs: Vec::new(),
            provenance_id: sentinel_contracts::DataSourceId::new_v4().to_string(),
            time_bucket: "current_session".to_string(),
            redaction_status: RedactionStatus::Redacted,
            response_execution_allowed: false,
            host_mutation_performed: false,
            automatic_llm_calls: false,
        };

        let facts = NativeSamplerFactPlugin
            .process_batch(&batch)
            .expect("native facts");
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].layer, SecurityLayer::AuthorizedNativeService);
        assert_eq!(facts[0].category, ENDPOINT_SERVICE_CATEGORY_FACT_CONTRACT);
        let serialized = serde_json::to_string(&facts).expect("serialize");
        for forbidden in ["pid", "command_line", "C:\\", "service_name", "password"] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn process_category_fact_builder_emits_category_context_only() {
        let batch_id = NativeSamplerBatchId::new_v4();
        let process = NativeProcessMetadataRecord {
            process_observation_id: NativeProcessObservationId::new_v4(),
            process_category: NativeProcessCategory::CommandShell,
            parent_process_category: NativeProcessCategory::AdministrativeTool,
            relation_category: NativeProcessParentRelationCategory::AdministrativeToolToChild,
            execution_context_category: NativeProcessExecutionContextCategory::Interactive,
            trust_category: NativeProcessTrustCategory::AllowlistedCategory,
            signedness_bucket: NativeSignednessBucket::NotChecked,
            privilege_context_category: NativePrivilegeContextCategory::UserContextUnknown,
            integrity_context_bucket: NativeIntegrityContextBucket::Unknown,
            session_context_category: NativeSessionContextCategory::InteractiveUnknown,
            lifecycle_state_bucket: NativeProcessLifecycleStateBucket::NewlyObserved,
            first_seen_in_session: true,
            population_count_bucket: "single".to_string(),
            start_count_bucket: "single".to_string(),
            stop_count_bucket: "none".to_string(),
            changed_category: false,
            sampler_id: "process_metadata_sampler".to_string(),
            sample_batch_id: batch_id.clone(),
            time_bucket: "current_session".to_string(),
            confidence_hint: QualityScore::new(0.7).expect("quality"),
            evidence_refs: Vec::new(),
            provenance_id: sentinel_contracts::DataSourceId::new_v4().to_string(),
            redaction_status: RedactionStatus::Redacted,
            missing_visibility_flags: vec![
                "process_network_attribution_unavailable".to_string(),
                "packet_visibility_unavailable".to_string(),
            ],
        };
        let batch = NativeSamplerRuntimeBatch {
            batch_id,
            sampler_id: "process_metadata_sampler".to_string(),
            category: NativeSamplerCategory::ProcessMetadataSampler,
            runtime_state: NativeSamplerRuntimeState::Active,
            provider_category: NativeProviderCategory::WindowsToolhelpProcessSnapshot,
            platform_category: NativeRuntimePlatformCategory::Windows,
            health_record: None,
            service_records: Vec::new(),
            process_records: vec![process],
            counters: NativeSamplerCounterSummary::empty(),
            emitted_topics: vec![
                "native.process.metadata".to_string(),
                "native.process_parent.metadata".to_string(),
                "endpoint.process.category_fact".to_string(),
                "endpoint.process_parent.category_fact".to_string(),
            ],
            fact_refs: Vec::new(),
            evidence_refs: Vec::new(),
            audit_refs: Vec::new(),
            provenance_id: sentinel_contracts::DataSourceId::new_v4().to_string(),
            time_bucket: "current_session".to_string(),
            redaction_status: RedactionStatus::Redacted,
            response_execution_allowed: false,
            host_mutation_performed: false,
            automatic_llm_calls: false,
        };
        let facts = NativeSamplerFactPlugin
            .process_batch(&batch)
            .expect("process facts");
        assert_eq!(facts.len(), 2);
        assert!(facts
            .iter()
            .all(|fact| fact.layer == SecurityLayer::AuthorizedNativeProcess));
        assert!(facts.iter().all(|fact| {
            matches!(
                fact.category.as_str(),
                ENDPOINT_PROCESS_CATEGORY_FACT_CONTRACT
                    | ENDPOINT_PROCESS_PARENT_CATEGORY_FACT_CONTRACT
            )
        }));
        let serialized = serde_json::to_string(&facts).expect("serialize");
        for forbidden in [
            "process_name",
            "parent_pid",
            "command_line",
            "executable_path",
            "socket",
            "ip_address",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }
    }
}
