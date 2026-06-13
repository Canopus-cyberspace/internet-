use crate::authorized_native_permissions::default_capability_catalog;
use crate::read_commands::ReadOnlyCommandState;
use sentinel_contracts::{
    AuditId, AuthorizedNativeCapabilityStatus, CommandResult, CoreError, EdrReadinessSummary,
    FutureEndpointSecurityFactCategory, FutureNativeFieldCategory,
    FutureSecurityFactMappingDeclaration, FutureSecurityFactMappingId,
    FutureSecurityFactMappingSummary, MissingEndpointVisibilitySummary,
    NativeCapabilityAvailabilityState, NativePermissionState, NativeSamplerAuthorizationMode,
    NativeSamplerAuthorizationReview, NativeSamplerBlockedSummary, NativeSamplerCategory,
    NativeSamplerContract, NativeSamplerId, NativeSamplerPlatformCategory,
    NativeSamplerPrivacyBoundaryCategory, NativeSamplerQualityEffect, NativeSamplerReadinessDetail,
    NativeSamplerReadinessState, NativeSamplerReadinessSummary,
    NativeSamplerRequiredUserActionCategory, NativeSamplerRetentionModeCategory,
    NativeSamplerSamplingModeDeclaration, NativeSamplerSchemaDeclaration, NativeSamplerSchemaId,
    NativeSamplerSchemaSafetyState, NativeSamplerStatusEvent, NativeVisibilityScopeCategory,
    PrivacyClass, RedactionStatus, SchemaVersion, Timestamp,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

const PROVENANCE_ID: &str = "native_sampler_readiness_catalog";
const TIME_BUCKET: &str = "current_session";
const REDACTION_POLICY_ID: &str = "native_sampler_redacted_categories_only";
const MAX_RECORDS_PER_TICK: u32 = 128;
const MAX_BYTES_PER_TICK: u32 = 65_536;

pub fn list_native_sampler_contracts(
    state: &ReadOnlyCommandState,
) -> CommandResult<Vec<NativeSamplerContract>> {
    Ok(native_sampler_details_for_state(state)?
        .into_iter()
        .map(|detail| detail.contract)
        .collect())
}

pub fn get_native_sampler_contract(
    state: &ReadOnlyCommandState,
    sampler_id: &str,
) -> CommandResult<NativeSamplerContract> {
    let detail = get_native_sampler_readiness_detail(state, sampler_id)?;
    Ok(detail.contract)
}

pub fn get_native_sampler_readiness_detail(
    state: &ReadOnlyCommandState,
    sampler_id: &str,
) -> CommandResult<NativeSamplerReadinessDetail> {
    native_sampler_details_for_state(state)?
        .into_iter()
        .find(|detail| detail.contract.sampler_id == sampler_id)
        .ok_or_else(|| {
            CoreError::validation_failure("native sampler contract was not found")
                .with_redacted_details(serde_json::json!({ "sampler_id": sampler_id }))
        })
}

pub fn get_native_sampler_authorization_review(
    state: &ReadOnlyCommandState,
    sampler_id: &str,
) -> CommandResult<NativeSamplerAuthorizationReview> {
    Ok(get_native_sampler_readiness_detail(state, sampler_id)?.review)
}

pub fn get_native_sampler_readiness_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativeSamplerReadinessSummary> {
    let details = native_sampler_details_for_state(state)?;
    readiness_summary_for_details(&details)
}

pub fn get_future_security_fact_mapping_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<FutureSecurityFactMappingSummary> {
    let details = native_sampler_details_for_state(state)?;
    let mappings = details
        .iter()
        .flat_map(|detail| detail.future_mappings.iter().cloned())
        .collect::<Vec<_>>();
    let sampler_refs = details
        .iter()
        .map(|detail| detail.contract.sampler_id.clone())
        .collect::<Vec<_>>();
    let summary = FutureSecurityFactMappingSummary {
        mapping_count: mappings.len() as u32,
        emitted_security_fact_count: 0,
        mappings,
        sampler_refs,
        generated_at: Timestamp::now(),
    };
    summary.validate().map_err(native_sampler_error)?;
    Ok(summary)
}

pub fn get_native_sampler_blocked_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativeSamplerBlockedSummary> {
    let details = native_sampler_details_for_state(state)?;
    let mut blocked_sampler_refs = Vec::new();
    let mut blocked_reasons = Vec::new();
    let mut revoked_sampler_refs = Vec::new();
    let mut disabled_sampler_refs = Vec::new();
    let mut unsafe_schema_sampler_refs = Vec::new();
    let mut response_capable_sampler_refs = Vec::new();

    for detail in &details {
        if let Some(reason) = &detail.review.blocked_reason {
            blocked_sampler_refs.push(detail.contract.sampler_id.clone());
            blocked_reasons.push(readiness_state_label(reason));
            match reason {
                NativeSamplerReadinessState::BlockedPermissionRevoked => {
                    revoked_sampler_refs.push(detail.contract.sampler_id.clone());
                }
                NativeSamplerReadinessState::BlockedPermissionDisabled => {
                    disabled_sampler_refs.push(detail.contract.sampler_id.clone());
                }
                NativeSamplerReadinessState::BlockedSchemaUnsafe => {
                    unsafe_schema_sampler_refs.push(detail.contract.sampler_id.clone());
                }
                NativeSamplerReadinessState::BlockedResponseCapable => {
                    response_capable_sampler_refs.push(detail.contract.sampler_id.clone());
                }
                _ => {}
            }
        }
    }

    let summary = NativeSamplerBlockedSummary {
        blocked_count: blocked_sampler_refs.len() as u32,
        blocked_sampler_refs,
        blocked_reasons,
        revoked_sampler_refs,
        disabled_sampler_refs,
        unsafe_schema_sampler_refs,
        response_capable_sampler_refs,
        generated_at: Timestamp::now(),
    };
    summary.validate().map_err(native_sampler_error)?;
    Ok(summary)
}

pub fn get_missing_endpoint_visibility_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<MissingEndpointVisibilitySummary> {
    let details = native_sampler_details_for_state(state)?;
    let summary = missing_endpoint_visibility_for_state(&details, state);
    summary.validate().map_err(native_sampler_error)?;
    Ok(summary)
}

pub fn get_edr_readiness_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<EdrReadinessSummary> {
    let details = native_sampler_details_for_state(state)?;
    let readiness = readiness_summary_for_details(&details)?;
    let missing_endpoint_visibility = missing_endpoint_visibility_for_state(&details, state);
    let implemented_sampler_count = details
        .iter()
        .filter(|detail| detail.contract.sampler_implemented)
        .count() as u32;
    let active_sampler_count = state
        .native_sampler_runtime_statuses
        .iter()
        .filter(|status| {
            matches!(
                status.runtime_state,
                sentinel_contracts::NativeSamplerRuntimeState::Active
                    | sentinel_contracts::NativeSamplerRuntimeState::Idle
                    | sentinel_contracts::NativeSamplerRuntimeState::Paused
            )
        })
        .count() as u32;
    let telemetry_collection_active = state
        .native_sampler_runtime_statuses
        .iter()
        .any(|status| status.telemetry_collection_active);
    let endpoint_security_facts_emitted = state
        .native_sampler_runtime_batches
        .iter()
        .any(|batch| !batch.fact_refs.is_empty());
    let summary = EdrReadinessSummary {
        contract_ready_count: readiness.contract_count,
        readiness_approved_count: readiness.ready_when_implemented_count,
        implemented_sampler_count,
        active_sampler_count,
        blocked_sampler_count: readiness.blocked_count,
        telemetry_collection_active,
        response_execution_allowed: false,
        endpoint_security_facts_emitted,
        edr_coverage_claimed: false,
        portable_default_active: true,
        no_telemetry_collected: !telemetry_collection_active && !endpoint_security_facts_emitted,
        sampler_refs: readiness.contract_refs,
        audit_refs: readiness.audit_refs,
        missing_endpoint_visibility,
        generated_at: Timestamp::now(),
    };
    summary.validate().map_err(native_sampler_error)?;
    Ok(summary)
}

pub fn native_sampler_details_for_state(
    state: &ReadOnlyCommandState,
) -> CommandResult<Vec<NativeSamplerReadinessDetail>> {
    let capabilities = if state.authorized_native_capabilities.is_empty() {
        default_capability_catalog()
    } else {
        state.authorized_native_capabilities.clone()
    };
    let mut details = Vec::new();
    for contract in native_sampler_contract_catalog()? {
        let status = capabilities
            .iter()
            .find(|status| status.capability_id == contract.required_capability_id);
        let detail = review_contract(contract, status)?;
        details.push(detail);
    }
    Ok(details)
}

fn readiness_summary_for_details(
    details: &[NativeSamplerReadinessDetail],
) -> CommandResult<NativeSamplerReadinessSummary> {
    let mut missing_endpoint_visibility_flags = BTreeSet::new();
    let mut degraded_reasons = BTreeSet::new();
    let mut audit_refs = Vec::<AuditId>::new();
    for detail in details {
        for flag in &detail.review.missing_prerequisite_flags {
            missing_endpoint_visibility_flags.insert(flag.clone());
        }
        if let Some(reason) = &detail.review.degraded_reason {
            degraded_reasons.insert(reason.clone());
        }
        audit_refs.extend(detail.review.audit_refs.iter().cloned());
    }
    let summary = NativeSamplerReadinessSummary {
        contract_count: details.len() as u32,
        review_count: details.len() as u32,
        ready_when_implemented_count: details
            .iter()
            .filter(|detail| {
                detail.review.readiness_state
                    == NativeSamplerReadinessState::ReadyWhenSamplerImplemented
            })
            .count() as u32,
        blocked_count: details
            .iter()
            .filter(|detail| detail.review.readiness_state.is_blocked())
            .count() as u32,
        degraded_count: details
            .iter()
            .filter(|detail| {
                detail.review.readiness_state
                    == NativeSamplerReadinessState::DegradedMissingVisibility
            })
            .count() as u32,
        not_implemented_count: details
            .iter()
            .filter(|detail| !detail.contract.sampler_implemented)
            .count() as u32,
        active_sampler_count: 0,
        future_collection_allowed_count: details
            .iter()
            .filter(|detail| detail.review.future_collection_allowed)
            .count() as u32,
        future_response_allowed_count: 0,
        endpoint_security_facts_emitted: false,
        telemetry_collection_active: false,
        response_execution_allowed: false,
        automatic_llm_calls: false,
        portable_default_active: true,
        no_telemetry_collected: true,
        contract_refs: details
            .iter()
            .map(|detail| detail.contract.sampler_id.clone())
            .collect(),
        review_refs: details
            .iter()
            .map(|detail| detail.review.review_id.clone())
            .collect(),
        audit_refs,
        missing_endpoint_visibility_flags: missing_endpoint_visibility_flags.into_iter().collect(),
        degraded_reasons: degraded_reasons.into_iter().collect(),
        generated_at: Timestamp::now(),
    };
    summary.validate().map_err(native_sampler_error)?;
    Ok(summary)
}

fn missing_endpoint_visibility_for_details(
    details: &[NativeSamplerReadinessDetail],
) -> MissingEndpointVisibilitySummary {
    let mut flags = BTreeSet::new();
    let mut reasons = BTreeSet::new();
    for detail in details {
        for flag in &detail.review.missing_prerequisite_flags {
            flags.insert(flag.clone());
        }
        if let Some(reason) = &detail.review.degraded_reason {
            reasons.insert(reason.clone());
        }
    }
    MissingEndpointVisibilitySummary {
        missing_visibility_flags: {
            flags.insert("missing_process_category_visibility".to_string());
            flags.insert("process_network_attribution_unavailable".to_string());
            flags.insert("packet_visibility_unavailable".to_string());
            flags.insert("file_visibility_unavailable".to_string());
            flags.insert("registry_visibility_unavailable".to_string());
            flags.into_iter().collect()
        },
        sampler_refs: details
            .iter()
            .map(|detail| detail.contract.sampler_id.clone())
            .collect(),
        degraded_reasons: reasons.into_iter().collect(),
        endpoint_required_hypotheses_degraded: true,
        native_attack_rows_supported: false,
        edr_coverage_claimed: false,
        generated_at: Timestamp::now(),
    }
}

fn missing_endpoint_visibility_for_state(
    details: &[NativeSamplerReadinessDetail],
    state: &ReadOnlyCommandState,
) -> MissingEndpointVisibilitySummary {
    let mut summary = missing_endpoint_visibility_for_details(details);
    let process_visibility_available = state.native_sampler_runtime_batches.iter().any(|batch| {
        batch.category == NativeSamplerCategory::ProcessMetadataSampler
            && !batch.process_records.is_empty()
    });
    if process_visibility_available {
        summary
            .missing_visibility_flags
            .retain(|flag| flag != "missing_process_category_visibility");
        summary
            .degraded_reasons
            .retain(|reason| reason != "process_category_visibility_requires_fresh_sample");
    }
    summary
}

fn review_contract(
    mut contract: NativeSamplerContract,
    status: Option<&AuthorizedNativeCapabilityStatus>,
) -> CommandResult<NativeSamplerReadinessDetail> {
    let (permission_state, audit_refs) = status
        .map(|status| (status.permission_state.clone(), status.audit_refs.clone()))
        .unwrap_or((NativePermissionState::NotGranted, Vec::new()));
    let readiness_state;
    let required_user_action;
    let degraded_reason;
    let missing_flags;
    let mut schema_safety_state = NativeSamplerSchemaSafetyState::SafeDeclarationOnly;

    if contract.response_capable {
        readiness_state = NativeSamplerReadinessState::BlockedResponseCapable;
        required_user_action =
            NativeSamplerRequiredUserActionCategory::SeparateResponsePolicyRequired;
        degraded_reason = Some("response_capable_placeholder_blocked".to_string());
        missing_flags = vec!["separate_response_policy_required".to_string()];
        schema_safety_state = NativeSamplerSchemaSafetyState::ResponseCapableBlocked;
    } else if contract.retention_mode != NativeSamplerRetentionModeCategory::NoRawRetention {
        readiness_state = NativeSamplerReadinessState::BlockedRetentionPolicy;
        required_user_action = NativeSamplerRequiredUserActionCategory::FixSchemaDeclaration;
        degraded_reason = Some("raw_endpoint_retention_rejected".to_string());
        missing_flags = vec!["no_raw_retention_policy_required".to_string()];
        schema_safety_state = NativeSamplerSchemaSafetyState::UnsafeRetentionPolicy;
        sanitize_contract_for_blocked_review(&mut contract);
    } else if contract.schema.validate().is_err() {
        readiness_state = NativeSamplerReadinessState::BlockedSchemaUnsafe;
        required_user_action = NativeSamplerRequiredUserActionCategory::FixSchemaDeclaration;
        degraded_reason = Some("schema_declaration_unsafe".to_string());
        missing_flags = vec!["schema_safety_review_required".to_string()];
        schema_safety_state = NativeSamplerSchemaSafetyState::UnsafeForbiddenField;
        sanitize_contract_for_blocked_review(&mut contract);
    } else if !declared_topics_are_safe(&contract.declared_event_topics) {
        readiness_state = NativeSamplerReadinessState::BlockedTopicNotDeclared;
        required_user_action = NativeSamplerRequiredUserActionCategory::DeclareEventTopics;
        degraded_reason = Some("event_topic_not_declared".to_string());
        missing_flags = vec!["declared_topic_required".to_string()];
        schema_safety_state = NativeSamplerSchemaSafetyState::UnsafeTopicDeclaration;
        contract.declared_event_topics = review_topics();
    } else if contract.validate().is_err() {
        readiness_state = NativeSamplerReadinessState::BlockedSchemaUnsafe;
        required_user_action = NativeSamplerRequiredUserActionCategory::FixSchemaDeclaration;
        degraded_reason = Some("schema_declaration_unsafe".to_string());
        missing_flags = vec!["schema_safety_review_required".to_string()];
        schema_safety_state = NativeSamplerSchemaSafetyState::UnsafeForbiddenField;
        sanitize_contract_for_blocked_review(&mut contract);
    } else {
        match status {
            None => {
                readiness_state = NativeSamplerReadinessState::BlockedPermissionRequired;
                required_user_action =
                    NativeSamplerRequiredUserActionCategory::GrantNativePermission;
                degraded_reason = Some("native_permission_required".to_string());
                missing_flags = vec![format!("{}_permission_missing", contract.sampler_id)];
            }
            Some(status)
                if status.availability_state
                    == NativeCapabilityAvailabilityState::UnsupportedPlatform =>
            {
                readiness_state = NativeSamplerReadinessState::BlockedUnsupportedPlatform;
                required_user_action =
                    NativeSamplerRequiredUserActionCategory::FutureNativeServiceRequired;
                degraded_reason = Some("unsupported_platform".to_string());
                missing_flags = vec!["supported_platform_missing".to_string()];
            }
            Some(status) if status.permission_state == NativePermissionState::Revoked => {
                readiness_state = NativeSamplerReadinessState::BlockedPermissionRevoked;
                required_user_action =
                    NativeSamplerRequiredUserActionCategory::ReauthorizeAfterRevocation;
                degraded_reason = Some("native_permission_revoked".to_string());
                missing_flags = vec![format!("{}_permission_revoked", contract.sampler_id)];
            }
            Some(status) if status.permission_state == NativePermissionState::Disabled => {
                readiness_state = NativeSamplerReadinessState::BlockedPermissionDisabled;
                required_user_action = NativeSamplerRequiredUserActionCategory::EnableCapability;
                degraded_reason = Some("native_permission_disabled".to_string());
                missing_flags = vec![format!("{}_permission_disabled", contract.sampler_id)];
            }
            Some(status) if status.permission_state != NativePermissionState::GrantedSession => {
                if status.availability_state
                    == NativeCapabilityAvailabilityState::PortableDefaultActive
                {
                    readiness_state = NativeSamplerReadinessState::BlockedPortableDefault;
                    required_user_action =
                        NativeSamplerRequiredUserActionCategory::GrantNativePermission;
                    degraded_reason = Some("portable_default_native_unavailable".to_string());
                    missing_flags =
                        vec![format!("{}_portable_default_blocked", contract.sampler_id)];
                } else {
                    readiness_state = NativeSamplerReadinessState::BlockedPermissionRequired;
                    required_user_action =
                        NativeSamplerRequiredUserActionCategory::GrantNativePermission;
                    degraded_reason = Some("native_permission_required".to_string());
                    missing_flags = vec![format!("{}_permission_missing", contract.sampler_id)];
                }
            }
            Some(status)
                if status.availability_state
                    == NativeCapabilityAvailabilityState::MissingServiceBinary
                    || status.availability_state
                        == NativeCapabilityAvailabilityState::ServiceUnavailable =>
            {
                readiness_state = NativeSamplerReadinessState::BlockedMissingNativeService;
                required_user_action =
                    NativeSamplerRequiredUserActionCategory::FutureNativeServiceRequired;
                degraded_reason = Some("native_service_missing".to_string());
                missing_flags = vec!["native_service_missing".to_string()];
            }
            Some(_) => {
                readiness_state = NativeSamplerReadinessState::ReadyWhenSamplerImplemented;
                required_user_action = NativeSamplerRequiredUserActionCategory::None;
                degraded_reason = if contract.sampler_implemented {
                    Some("ready_but_sampler_inactive".to_string())
                } else {
                    Some("ready_but_sampler_not_implemented".to_string())
                };
                missing_flags = if contract.sampler_implemented {
                    vec!["sampler_runtime_inactive".to_string()]
                } else {
                    vec!["sampler_runtime_not_implemented".to_string()]
                };
            }
        }
    }

    contract.readiness_state = readiness_state.clone();
    contract.degraded_reason = degraded_reason.clone();
    contract.missing_prerequisite_flags = missing_flags.clone();
    contract.audit_refs = audit_refs.clone();
    contract.last_reviewed_time_bucket = Some(TIME_BUCKET.to_string());
    contract.validate().map_err(native_sampler_error)?;

    let blocked_reason = readiness_state
        .is_blocked()
        .then_some(readiness_state.clone());
    let future_collection_allowed =
        readiness_state == NativeSamplerReadinessState::ReadyWhenSamplerImplemented;
    let review = NativeSamplerAuthorizationReview {
        review_id: review_id_for(&contract.sampler_id),
        sampler_id: contract.sampler_id.clone(),
        category: contract.category.clone(),
        capability_id: contract.required_capability_id.clone(),
        permission_state,
        readiness_state: readiness_state.clone(),
        allowed: future_collection_allowed,
        blocked_reason,
        degraded_reason,
        missing_prerequisite_flags: missing_flags,
        required_user_action,
        future_collection_allowed,
        future_response_allowed: false,
        sampler_active: false,
        telemetry_collection_started: false,
        response_execution_started: false,
        service_installation_started: false,
        driver_loading_started: false,
        host_mutation_performed: false,
        automatic_llm_calls: false,
        schema_safety_state,
        evidence_quality_effect: if future_collection_allowed {
            NativeSamplerQualityEffect::ReadinessOnlyNoEvidence
        } else {
            NativeSamplerQualityEffect::DegradesMissingEndpointVisibility
        },
        report_export_suitable: true,
        declared_event_topics: review_topics(),
        output_fact_categories: contract.output_fact_categories.clone(),
        audit_refs: audit_refs.clone(),
        provenance_id: PROVENANCE_ID.to_string(),
        time_bucket: TIME_BUCKET.to_string(),
        redaction_status: RedactionStatus::Redacted,
    };
    review.validate().map_err(native_sampler_error)?;

    let future_mappings = mapping_declarations_for(&contract)?;
    let status_events = status_events_for(&contract, &review);
    for event in &status_events {
        event.validate().map_err(native_sampler_error)?;
    }
    let detail = NativeSamplerReadinessDetail {
        contract,
        review,
        status_events,
        future_mappings,
    };
    detail.validate().map_err(native_sampler_error)?;
    Ok(detail)
}

fn sanitize_contract_for_blocked_review(contract: &mut NativeSamplerContract) {
    contract.schema.declared_field_labels = vec!["unsafe_schema_field_redacted".to_string()];
    contract.schema.raw_fields_allowed = false;
    contract.schema.declared_only = true;
    contract.schema.redaction_status = RedactionStatus::Redacted;
    contract.retention_mode = NativeSamplerRetentionModeCategory::NoRawRetention;
    contract.read_only = true;
    contract.portable_default_available = false;
    contract.sampler_implemented = false;
    contract.sampler_active = false;
    contract.telemetry_collection_active = false;
    contract.response_execution_allowed = false;
    contract.automatic_llm_calls = false;
}

fn native_sampler_contract_catalog() -> CommandResult<Vec<NativeSamplerContract>> {
    let entries = [
        (
            "native_host_visibility_sampler",
            NativeSamplerCategory::NativeHostVisibilitySampler,
            "native_host_visibility",
            NativeVisibilityScopeCategory::HostSummary,
            NativeSamplerSamplingModeDeclaration::ReadOnlySnapshotMetadata,
            vec![
                FutureNativeFieldCategory::ExecutionContextCategory,
                FutureNativeFieldCategory::TimestampBucket,
                FutureNativeFieldCategory::ProvenanceId,
            ],
            vec![
                "execution_context_category",
                "timestamp_bucket",
                "provenance_id",
            ],
            vec![FutureEndpointSecurityFactCategory::EndpointNativeHealthCategoryFact],
        ),
        (
            "process_metadata_sampler",
            NativeSamplerCategory::ProcessMetadataSampler,
            "process_metadata_visibility",
            NativeVisibilityScopeCategory::ProcessSummary,
            NativeSamplerSamplingModeDeclaration::ReadOnlySnapshotMetadata,
            vec![
                FutureNativeFieldCategory::ProcessCategory,
                FutureNativeFieldCategory::ParentProcessCategory,
                FutureNativeFieldCategory::ParentChildRelationCategory,
                FutureNativeFieldCategory::ExecutionContextCategory,
                FutureNativeFieldCategory::SignednessBucket,
                FutureNativeFieldCategory::BinaryTrustBucket,
                FutureNativeFieldCategory::PrivilegeContextCategory,
                FutureNativeFieldCategory::IntegrityContextBucket,
                FutureNativeFieldCategory::SessionContextCategory,
                FutureNativeFieldCategory::LifecycleStateBucket,
                FutureNativeFieldCategory::PopulationCountBucket,
                FutureNativeFieldCategory::StartCountBucket,
                FutureNativeFieldCategory::StopCountBucket,
                FutureNativeFieldCategory::ChangedCategoryFlag,
            ],
            vec![
                "process_category",
                "parent_process_category",
                "parent_child_relation_category",
                "execution_context_category",
                "signedness_bucket",
                "binary_trust_bucket",
                "privilege_context_category",
                "integrity_context_bucket",
                "session_context_category",
                "lifecycle_state_bucket",
                "population_count_bucket",
                "start_count_bucket",
                "stop_count_bucket",
                "changed_category_flag",
            ],
            vec![
                FutureEndpointSecurityFactCategory::EndpointProcessCategoryFact,
                FutureEndpointSecurityFactCategory::EndpointProcessParentCategoryFact,
            ],
        ),
        (
            "process_network_attribution_sampler",
            NativeSamplerCategory::ProcessNetworkAttributionSampler,
            "process_network_attribution_visibility",
            NativeVisibilityScopeCategory::ProcessNetworkSummary,
            NativeSamplerSamplingModeDeclaration::ReadOnlySnapshotMetadata,
            vec![
                FutureNativeFieldCategory::ProcessCategory,
                FutureNativeFieldCategory::EndpointNetworkRelationCategory,
                FutureNativeFieldCategory::DestinationServiceCategory,
            ],
            vec![
                "process_category",
                "endpoint_network_relation_category",
                "destination_service_category",
            ],
            vec![FutureEndpointSecurityFactCategory::EndpointProcessNetworkRelationCategoryFact],
        ),
        (
            "service_metadata_sampler",
            NativeSamplerCategory::ServiceMetadataSampler,
            "service_metadata_visibility",
            NativeVisibilityScopeCategory::ServiceSummary,
            NativeSamplerSamplingModeDeclaration::ReadOnlySnapshotMetadata,
            vec![
                FutureNativeFieldCategory::ServiceCategory,
                FutureNativeFieldCategory::SignednessBucket,
                FutureNativeFieldCategory::BinaryTrustBucket,
            ],
            vec![
                "service_category",
                "signedness_bucket",
                "binary_trust_bucket",
            ],
            vec![FutureEndpointSecurityFactCategory::EndpointServiceCategoryFact],
        ),
        (
            "autorun_persistence_metadata_sampler",
            NativeSamplerCategory::AutorunPersistenceMetadataSampler,
            "autorun_persistence_visibility",
            NativeVisibilityScopeCategory::PersistenceSummary,
            NativeSamplerSamplingModeDeclaration::ReadOnlySnapshotMetadata,
            vec![
                FutureNativeFieldCategory::AutorunCategory,
                FutureNativeFieldCategory::ExecutionContextCategory,
                FutureNativeFieldCategory::ConfidenceHint,
            ],
            vec![
                "autorun_category",
                "execution_context_category",
                "confidence_hint",
            ],
            vec![
                FutureEndpointSecurityFactCategory::EndpointAutorunCategoryFact,
                FutureEndpointSecurityFactCategory::EndpointPersistenceCategoryFact,
            ],
        ),
        (
            "file_activity_summary_sampler",
            NativeSamplerCategory::FileActivitySummarySampler,
            "file_activity_summary_visibility",
            NativeVisibilityScopeCategory::FileActivitySummary,
            NativeSamplerSamplingModeDeclaration::ReadOnlyAppendSummary,
            vec![
                FutureNativeFieldCategory::FileActivityCategory,
                FutureNativeFieldCategory::PathCategory,
                FutureNativeFieldCategory::CountBucket,
            ],
            vec!["file_activity_category", "path_category", "count_bucket"],
            vec![FutureEndpointSecurityFactCategory::EndpointFileActivityCategoryFact],
        ),
        (
            "registry_summary_sampler",
            NativeSamplerCategory::RegistrySummarySampler,
            "registry_summary_visibility",
            NativeVisibilityScopeCategory::RegistryActivitySummary,
            NativeSamplerSamplingModeDeclaration::ReadOnlyAppendSummary,
            vec![
                FutureNativeFieldCategory::RegistryActivityCategory,
                FutureNativeFieldCategory::CountBucket,
                FutureNativeFieldCategory::ConfidenceHint,
            ],
            vec![
                "registry_activity_category",
                "count_bucket",
                "confidence_hint",
            ],
            vec![FutureEndpointSecurityFactCategory::EndpointRegistryActivityCategoryFact],
        ),
        (
            "endpoint_network_attribution_sampler",
            NativeSamplerCategory::EndpointNetworkAttributionSampler,
            "endpoint_network_attribution_visibility",
            NativeVisibilityScopeCategory::EndpointNetworkSummary,
            NativeSamplerSamplingModeDeclaration::ReadOnlySnapshotMetadata,
            vec![
                FutureNativeFieldCategory::EndpointNetworkRelationCategory,
                FutureNativeFieldCategory::DestinationServiceCategory,
                FutureNativeFieldCategory::CountBucket,
            ],
            vec![
                "endpoint_network_relation_category",
                "destination_service_category",
                "count_bucket",
            ],
            vec![FutureEndpointSecurityFactCategory::EndpointProcessNetworkRelationCategoryFact],
        ),
        (
            "native_health_probe_sampler",
            NativeSamplerCategory::NativeHealthProbeSampler,
            "native_health_probe",
            NativeVisibilityScopeCategory::HealthStatusOnly,
            NativeSamplerSamplingModeDeclaration::HealthStatusOnly,
            vec![
                FutureNativeFieldCategory::TimestampBucket,
                FutureNativeFieldCategory::ConfidenceHint,
                FutureNativeFieldCategory::MissingVisibilityFlags,
            ],
            vec![
                "timestamp_bucket",
                "confidence_hint",
                "missing_visibility_flags",
            ],
            vec![FutureEndpointSecurityFactCategory::EndpointNativeHealthCategoryFact],
        ),
        (
            "native_response_capability_placeholder_sampler",
            NativeSamplerCategory::NativeResponseCapabilityPlaceholder,
            "native_response_capability_placeholder",
            NativeVisibilityScopeCategory::ResponsePlaceholderOnly,
            NativeSamplerSamplingModeDeclaration::ResponsePlaceholderNoTelemetry,
            vec![
                FutureNativeFieldCategory::ConfidenceHint,
                FutureNativeFieldCategory::MissingVisibilityFlags,
                FutureNativeFieldCategory::RedactionStatus,
            ],
            vec![
                "confidence_hint",
                "missing_visibility_flags",
                "redaction_status",
            ],
            vec![FutureEndpointSecurityFactCategory::EndpointNativeHealthCategoryFact],
        ),
    ];

    entries
        .into_iter()
        .map(
            |(
                sampler_id,
                category,
                capability_id,
                visibility_scope,
                sampling_mode,
                fields,
                field_labels,
                output_fact_categories,
            )| {
                let response_capable =
                    category == NativeSamplerCategory::NativeResponseCapabilityPlaceholder;
                let implemented = matches!(
                    category,
                    NativeSamplerCategory::NativeHealthProbeSampler
                        | NativeSamplerCategory::ServiceMetadataSampler
                        | NativeSamplerCategory::ProcessMetadataSampler
                );
                let schema = NativeSamplerSchemaDeclaration {
                    schema_id: schema_id_for(sampler_id),
                    schema_version: SchemaVersion::new(1, 0, 0),
                    field_categories: fields,
                    declared_field_labels: field_labels
                        .into_iter()
                        .map(str::to_string)
                        .collect::<Vec<_>>(),
                    output_fact_categories: output_fact_categories.clone(),
                    declared_only: true,
                    raw_fields_allowed: false,
                    redaction_status: RedactionStatus::Redacted,
                };
                let contract = NativeSamplerContract {
                    contract_id: sampler_id_for(sampler_id),
                    sampler_id: sampler_id.to_string(),
                    category: category.clone(),
                    required_capability_id: capability_id.to_string(),
                    required_permission_state: NativePermissionState::GrantedSession,
                    authorization_mode: if response_capable {
                        NativeSamplerAuthorizationMode::NotGrantableResponsePlaceholder
                    } else {
                        NativeSamplerAuthorizationMode::ExplicitSessionBoundFutureActivation
                    },
                    read_only: true,
                    response_capable,
                    readiness_state: NativeSamplerReadinessState::NotImplemented,
                    supported_platform: NativeSamplerPlatformCategory::WindowsNativeExtensionFuture,
                    portable_default_available: false,
                    sampling_mode,
                    max_records_per_tick: MAX_RECORDS_PER_TICK,
                    max_bytes_per_tick: MAX_BYTES_PER_TICK,
                    output_fact_categories,
                    declared_event_topics: contract_topics(&category),
                    redaction_policy_id: REDACTION_POLICY_ID.to_string(),
                    privacy_boundary: if response_capable {
                        NativeSamplerPrivacyBoundaryCategory::ResponsePlaceholderOnly
                    } else {
                        NativeSamplerPrivacyBoundaryCategory::BoundedEndpointMetadataFuture
                    },
                    retention_mode: NativeSamplerRetentionModeCategory::NoRawRetention,
                    visibility_scope,
                    schema,
                    degraded_reason: if implemented {
                        Some("sampler_runtime_inactive".to_string())
                    } else {
                        Some("sampler_runtime_not_implemented".to_string())
                    },
                    missing_prerequisite_flags: if implemented {
                        vec!["sampler_runtime_inactive".to_string()]
                    } else {
                        vec!["sampler_runtime_not_implemented".to_string()]
                    },
                    audit_refs: Vec::new(),
                    provenance_id: PROVENANCE_ID.to_string(),
                    redaction_status: RedactionStatus::Redacted,
                    privacy_class: PrivacyClass::Internal,
                    last_reviewed_time_bucket: Some(TIME_BUCKET.to_string()),
                    sampler_implemented: implemented,
                    sampler_active: false,
                    telemetry_collection_active: false,
                    response_execution_allowed: false,
                    automatic_llm_calls: false,
                };
                contract.validate().map_err(native_sampler_error)?;
                Ok(contract)
            },
        )
        .collect()
}

fn mapping_declarations_for(
    contract: &NativeSamplerContract,
) -> CommandResult<Vec<FutureSecurityFactMappingDeclaration>> {
    contract
        .output_fact_categories
        .iter()
        .map(|category| {
            let mapping = FutureSecurityFactMappingDeclaration {
                mapping_id: mapping_id_for(&contract.sampler_id, category),
                sampler_id: contract.sampler_id.clone(),
                sampler_category: contract.category.clone(),
                output_fact_category: category.clone(),
                declared_field_categories: contract.schema.field_categories.clone(),
                declared_only: true,
                emits_security_facts_now: false,
                quality_gate_required: true,
                visibility_gate_required: true,
                report_export_suitability_gate: true,
                forbidden_raw_fields_rejected: true,
                provenance_id: PROVENANCE_ID.to_string(),
                schema_version: SchemaVersion::new(1, 0, 0),
                redaction_status: RedactionStatus::Redacted,
            };
            mapping.validate().map_err(native_sampler_error)?;
            Ok(mapping)
        })
        .collect()
}

fn status_events_for(
    contract: &NativeSamplerContract,
    review: &NativeSamplerAuthorizationReview,
) -> Vec<NativeSamplerStatusEvent> {
    [
        "native.sampler.contract",
        "native.sampler.readiness",
        "native.sampler.review",
        "native.visibility.status",
        "security.visibility.degraded",
        "audit.native_sampler_review",
    ]
    .into_iter()
    .map(|topic| NativeSamplerStatusEvent {
        topic: topic.to_string(),
        sampler_id: contract.sampler_id.clone(),
        category: contract.category.clone(),
        capability_id: contract.required_capability_id.clone(),
        readiness_state: review.readiness_state.clone(),
        permission_state: review.permission_state.clone(),
        health_state: "readiness_review_only".to_string(),
        degraded_reason: review.degraded_reason.clone(),
        missing_prerequisite_flags: review.missing_prerequisite_flags.clone(),
        schema_version: SchemaVersion::new(1, 0, 0),
        declared_output_categories: contract.output_fact_categories.clone(),
        audit_refs: review.audit_refs.clone(),
        provenance_id: PROVENANCE_ID.to_string(),
        time_bucket: TIME_BUCKET.to_string(),
        redaction_status: RedactionStatus::Redacted,
    })
    .collect()
}

fn contract_topics(category: &NativeSamplerCategory) -> Vec<String> {
    match category {
        NativeSamplerCategory::NativeHealthProbeSampler => vec![
            "native.sampler.contract".to_string(),
            "native.sampler.readiness".to_string(),
            "native.sampler.runtime_status".to_string(),
            "native.health.metadata".to_string(),
            "endpoint.native_health.category_fact".to_string(),
            "security.visibility.status".to_string(),
            "security.visibility.degraded".to_string(),
            "audit.native_sampler_runtime".to_string(),
        ],
        NativeSamplerCategory::ServiceMetadataSampler => vec![
            "native.sampler.contract".to_string(),
            "native.sampler.readiness".to_string(),
            "native.sampler.runtime_status".to_string(),
            "native.service.metadata".to_string(),
            "endpoint.service.category_fact".to_string(),
            "security.visibility.status".to_string(),
            "security.visibility.degraded".to_string(),
            "audit.native_sampler_runtime".to_string(),
        ],
        NativeSamplerCategory::ProcessMetadataSampler => vec![
            "native.sampler.contract".to_string(),
            "native.sampler.readiness".to_string(),
            "native.sampler.runtime_status".to_string(),
            "native.process.metadata".to_string(),
            "native.process_parent.metadata".to_string(),
            "endpoint.process.category_fact".to_string(),
            "endpoint.process_parent.category_fact".to_string(),
            "security.visibility.status".to_string(),
            "security.visibility.degraded".to_string(),
            "audit.native_sampler_runtime".to_string(),
        ],
        _ => vec![
            "native.sampler.contract".to_string(),
            "native.sampler.readiness".to_string(),
            "native.sampler.review".to_string(),
            "native.visibility.status".to_string(),
            "security.visibility.degraded".to_string(),
            "audit.native_sampler_review".to_string(),
        ],
    }
}

fn review_topics() -> Vec<String> {
    vec![
        "native.sampler.readiness".to_string(),
        "native.sampler.review".to_string(),
        "audit.native_sampler_review".to_string(),
    ]
}

fn declared_topics_are_safe(topics: &[String]) -> bool {
    !topics.is_empty()
        && topics.iter().all(|topic| {
            sentinel_contracts::NATIVE_SAMPLER_ALLOWED_TOPICS.contains(&topic.as_str())
        })
}

fn readiness_state_label(state: &NativeSamplerReadinessState) -> String {
    match state {
        NativeSamplerReadinessState::ReadyWhenSamplerImplemented => {
            "ready_when_sampler_implemented"
        }
        NativeSamplerReadinessState::BlockedPortableDefault => "blocked_portable_default",
        NativeSamplerReadinessState::BlockedPermissionRequired => "blocked_permission_required",
        NativeSamplerReadinessState::BlockedPermissionRevoked => "blocked_permission_revoked",
        NativeSamplerReadinessState::BlockedPermissionDisabled => "blocked_permission_disabled",
        NativeSamplerReadinessState::BlockedUnsupportedPlatform => "blocked_unsupported_platform",
        NativeSamplerReadinessState::BlockedMissingNativeService => {
            "blocked_missing_native_service"
        }
        NativeSamplerReadinessState::BlockedSchemaUnsafe => "blocked_schema_unsafe",
        NativeSamplerReadinessState::BlockedResponseCapable => "blocked_response_capable",
        NativeSamplerReadinessState::BlockedRetentionPolicy => "blocked_retention_policy",
        NativeSamplerReadinessState::BlockedRedactionPolicy => "blocked_redaction_policy",
        NativeSamplerReadinessState::BlockedTopicNotDeclared => "blocked_topic_not_declared",
        NativeSamplerReadinessState::DegradedMissingVisibility => "degraded_missing_visibility",
        NativeSamplerReadinessState::NotImplemented => "not_implemented",
    }
    .to_string()
}

fn sampler_id_for(value: &str) -> NativeSamplerId {
    NativeSamplerId::from_uuid(uuid_from_hash(&format!("native_sampler:{value}")))
}

fn schema_id_for(value: &str) -> NativeSamplerSchemaId {
    NativeSamplerSchemaId::from_uuid(uuid_from_hash(&format!("native_sampler_schema:{value}")))
}

fn review_id_for(value: &str) -> sentinel_contracts::NativeSamplerReviewId {
    sentinel_contracts::NativeSamplerReviewId::from_uuid(uuid_from_hash(&format!(
        "native_sampler_review:{value}"
    )))
}

fn mapping_id_for(
    sampler_id: &str,
    category: &FutureEndpointSecurityFactCategory,
) -> FutureSecurityFactMappingId {
    FutureSecurityFactMappingId::from_uuid(uuid_from_hash(&format!(
        "native_sampler_mapping:{sampler_id}:{category:?}"
    )))
}

fn uuid_from_hash(key: &str) -> Uuid {
    let digest = Sha256::digest(key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

fn native_sampler_error(error: impl ToString) -> CoreError {
    CoreError::validation_failure("native sampler readiness validation failed")
        .with_redacted_details(serde_json::json!({ "error_redacted": error.to_string() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        NativeCapabilityAccessMode, NativeCapabilityHealthState, NativeCapabilityLifecycleState,
        NativeCapabilityPrerequisites,
    };

    #[test]
    fn portable_default_blocks_future_sampler_without_telemetry() {
        let state = ReadOnlyCommandState::bootstrap().expect("state");
        let summary = get_native_sampler_readiness_summary(&state).expect("summary");
        assert_eq!(summary.contract_count, 10);
        assert_eq!(summary.active_sampler_count, 0);
        assert_eq!(summary.future_response_allowed_count, 0);
        assert!(!summary.telemetry_collection_active);
        assert!(!summary.endpoint_security_facts_emitted);
        assert!(summary.blocked_count >= 1);
    }

    #[test]
    fn granted_permission_improves_readiness_only_not_activation() {
        let mut capabilities = default_capability_catalog();
        let capability = capabilities
            .iter_mut()
            .find(|status| status.capability_id == "process_metadata_visibility")
            .expect("capability");
        capability.permission_state = NativePermissionState::GrantedSession;
        capability.availability_state =
            NativeCapabilityAvailabilityState::AuthorizedSamplerInactive;
        capability.lifecycle_state = NativeCapabilityLifecycleState::Granted;
        capability.enabled = true;
        capability.degraded_reason = Some("authorized_but_no_sampler_enabled".to_string());
        capability.validate().expect("capability");

        let state = ReadOnlyCommandState::bootstrap()
            .expect("state")
            .with_authorized_native_capabilities(capabilities);
        let detail = get_native_sampler_readiness_detail(&state, "process_metadata_sampler")
            .expect("detail");
        assert_eq!(
            detail.review.readiness_state,
            NativeSamplerReadinessState::ReadyWhenSamplerImplemented
        );
        assert!(detail.review.future_collection_allowed);
        assert!(!detail.review.sampler_active);
        assert!(!detail.review.telemetry_collection_started);
        assert_eq!(
            detail.review.evidence_quality_effect,
            NativeSamplerQualityEffect::ReadinessOnlyNoEvidence
        );
    }

    #[test]
    fn revoked_and_response_capable_samplers_are_blocked() {
        let mut capabilities = default_capability_catalog();
        let capability = capabilities
            .iter_mut()
            .find(|status| status.capability_id == "process_metadata_visibility")
            .expect("capability");
        capability.permission_state = NativePermissionState::Revoked;
        capability.availability_state = NativeCapabilityAvailabilityState::Revoked;
        capability.lifecycle_state = NativeCapabilityLifecycleState::Revoked;
        capability.revoked = true;
        capability.enabled = false;
        capability.health_state = NativeCapabilityHealthState::Revoked;
        capability.degraded_reason = Some("authorization_revoked".to_string());
        capability.validate().expect("capability");

        let state = ReadOnlyCommandState::bootstrap()
            .expect("state")
            .with_authorized_native_capabilities(capabilities);
        let detail = get_native_sampler_readiness_detail(&state, "process_metadata_sampler")
            .expect("detail");
        assert_eq!(
            detail.review.blocked_reason,
            Some(NativeSamplerReadinessState::BlockedPermissionRevoked)
        );

        let response = get_native_sampler_readiness_detail(
            &state,
            "native_response_capability_placeholder_sampler",
        )
        .expect("response placeholder");
        assert_eq!(
            response.review.blocked_reason,
            Some(NativeSamplerReadinessState::BlockedResponseCapable)
        );
        assert!(!response.review.future_response_allowed);
    }

    #[test]
    fn future_mapping_summary_declares_only_and_emits_no_security_facts() {
        let state = ReadOnlyCommandState::bootstrap().expect("state");
        let summary = get_future_security_fact_mapping_summary(&state).expect("summary");
        assert_eq!(summary.emitted_security_fact_count, 0);
        assert!(!summary.mappings.is_empty());
        assert!(summary.mappings.iter().all(|mapping| {
            mapping.declared_only
                && !mapping.emits_security_facts_now
                && mapping.forbidden_raw_fields_rejected
        }));
    }

    #[test]
    fn readiness_events_are_allowed_topics_only() {
        let state = ReadOnlyCommandState::bootstrap().expect("state");
        let detail = get_native_sampler_readiness_detail(&state, "process_metadata_sampler")
            .expect("detail");
        assert!(!detail.status_events.is_empty());
        assert!(detail.status_events.iter().all(|event| {
            matches!(
                event.topic.as_str(),
                "native.sampler.contract"
                    | "native.sampler.readiness"
                    | "native.sampler.review"
                    | "native.visibility.status"
                    | "security.visibility.degraded"
                    | "audit.native_sampler_review"
            )
        }));
    }

    #[test]
    fn unsafe_contract_shape_fails_review_before_collection() {
        let mut contract = native_sampler_contract_catalog()
            .expect("catalog")
            .into_iter()
            .find(|contract| contract.sampler_id == "process_metadata_sampler")
            .expect("contract");
        contract
            .schema
            .declared_field_labels
            .push("command_line".to_string());
        let status = AuthorizedNativeCapabilityStatus {
            capability_id: "process_metadata_visibility".to_string(),
            category: contract.category.capability_category(),
            lifecycle_state: NativeCapabilityLifecycleState::Granted,
            availability_state: NativeCapabilityAvailabilityState::AuthorizedSamplerInactive,
            permission_state: NativePermissionState::GrantedSession,
            authorization_mode: sentinel_contracts::NativeAuthorizationMode::ExplicitSessionBound,
            access_mode: NativeCapabilityAccessMode::ReadOnlyVisibility,
            enabled: true,
            revoked: false,
            health_state: NativeCapabilityHealthState::Unknown,
            degraded_reason: Some("authorized_but_no_sampler_enabled".to_string()),
            prerequisites: NativeCapabilityPrerequisites {
                native_service_required: true,
                explicit_authorization_required: true,
                read_only_mode_required: true,
                separate_response_policy_required: true,
            },
            visibility_scope: NativeVisibilityScopeCategory::ProcessSummary,
            portable_default_available: false,
            last_checked_time_bucket: Some(TIME_BUCKET.to_string()),
            provenance_id: "test_native_status".to_string(),
            audit_refs: Vec::new(),
            redaction_status: RedactionStatus::Redacted,
            privacy_class: PrivacyClass::Internal,
            telemetry_collection_active: false,
            response_execution_allowed: false,
            automatic_llm_calls: false,
        };
        let detail = review_contract(contract, Some(&status)).expect("review");
        assert_eq!(
            detail.review.blocked_reason,
            Some(NativeSamplerReadinessState::BlockedSchemaUnsafe)
        );
        assert!(!detail.review.telemetry_collection_started);
    }
}
