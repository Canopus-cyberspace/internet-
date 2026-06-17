use crate::read_commands::ReadOnlyCommandState;
use crate::runtime_container::RuntimeEventBusHandle;
use sentinel_contracts::{
    AuthorizedNativeCapabilityCategory, AuthorizedNativeCapabilityStatus, CommandResult, CoreError,
    ErrorCode, ErrorSeverity, EventEnvelope, EventType, NativeAuthorizationMode,
    NativeCapabilityAccessMode, NativeCapabilityAvailabilityState, NativeCapabilityHealthState,
    NativeCapabilityLifecycleState, NativeCapabilityPrerequisites, NativePermissionAction,
    NativePermissionActionRequest, NativePermissionActionResult, NativePermissionAuditEntry,
    NativePermissionAuditSummary, NativePermissionPreview, NativePermissionState,
    NativePermissionStatusSummary, NativeStatusEvent, NativeVisibilityScopeCategory,
    NativeVisibilitySummary, PluginId, PrivacyClass, QualityScore, RedactionStatus, SchemaVersion,
    Timestamp, TraceContext, MAX_NATIVE_AUDIT_REFS,
};
use sentinel_platform::{
    PublishOptions, TopicName, AUDIT_NATIVE_PERMISSION, NATIVE_CAPABILITY_STATUS,
    NATIVE_PERMISSION_STATUS, NATIVE_VISIBILITY_STATUS, SECURITY_VISIBILITY_DEGRADED,
};
use serde_json::json;

const PROVENANCE_ID: &str = "authorized_native_control_plane";
const CURRENT_SESSION_BUCKET: &str = "current_session";

#[derive(Clone, Debug)]
pub struct AuthorizedNativePermissionRuntime {
    capabilities: Vec<AuthorizedNativeCapabilityStatus>,
    audit_entries: Vec<NativePermissionAuditEntry>,
    status_events: Vec<NativeStatusEvent>,
    event_bus: RuntimeEventBusHandle,
    producer_plugin: PluginId,
}

impl AuthorizedNativePermissionRuntime {
    #[cfg(test)]
    pub fn from_read_state(read: &ReadOnlyCommandState) -> Self {
        Self::from_read_state_with_event_bus(read, RuntimeEventBusHandle::new_legacy_core_topics())
    }

    pub(crate) fn from_read_state_with_event_bus(
        read: &ReadOnlyCommandState,
        event_bus: RuntimeEventBusHandle,
    ) -> Self {
        let capabilities = if read.authorized_native_capabilities.is_empty() {
            default_capability_catalog()
        } else {
            read.authorized_native_capabilities.clone()
        };
        Self {
            capabilities,
            audit_entries: read.native_permission_audit_entries.clone(),
            status_events: read.native_status_events.clone(),
            event_bus,
            producer_plugin: PluginId::new_v4(),
        }
    }

    pub fn preview_permission_request(
        &self,
        capability_id: &str,
    ) -> CommandResult<NativePermissionPreview> {
        let capability = self.capability(capability_id)?.clone();
        let preview = NativePermissionPreview {
            capability,
            requested_action: NativePermissionAction::RequestAuthorization,
            state_change_performed: false,
            telemetry_collection_started: false,
            response_execution_started: false,
            service_installation_started: false,
            driver_loading_started: false,
            automatic_llm_calls: false,
            boundary_summary_redacted:
                "Preview only; authorization remains session bound and no native sampler starts"
                    .to_string(),
        };
        preview.validate().map_err(contract_error)?;
        Ok(preview)
    }

    pub fn apply_action(
        &mut self,
        request: NativePermissionActionRequest,
    ) -> CommandResult<NativePermissionActionResult> {
        request.validate().map_err(contract_error)?;
        let index = self
            .capabilities
            .iter()
            .position(|status| status.capability_id == request.capability_id)
            .ok_or_else(|| native_not_found(&request.capability_id))?;
        let capability = &mut self.capabilities[index];

        match request.action {
            NativePermissionAction::RequestAuthorization => {
                capability.lifecycle_state = NativeCapabilityLifecycleState::Requested;
                capability.permission_state = NativePermissionState::Requested;
                capability.authorization_mode = NativeAuthorizationMode::None;
                capability.enabled = false;
                capability.revoked = false;
                capability.degraded_reason = Some("authorization_requested".to_string());
            }
            NativePermissionAction::GrantAuthorization => {
                if capability.access_mode
                    == NativeCapabilityAccessMode::ResponseCapabilityPlaceholder
                {
                    capability.lifecycle_state = NativeCapabilityLifecycleState::Denied;
                    capability.permission_state = NativePermissionState::Denied;
                    capability.authorization_mode = NativeAuthorizationMode::None;
                    capability.enabled = false;
                    capability.revoked = false;
                    capability.degraded_reason =
                        Some("separate_response_policy_required".to_string());
                } else {
                    capability.lifecycle_state = NativeCapabilityLifecycleState::Granted;
                    capability.availability_state =
                        NativeCapabilityAvailabilityState::AuthorizedSamplerInactive;
                    capability.permission_state = NativePermissionState::GrantedSession;
                    capability.authorization_mode = NativeAuthorizationMode::ExplicitSessionBound;
                    capability.enabled = true;
                    capability.revoked = false;
                    capability.health_state = NativeCapabilityHealthState::Unknown;
                    capability.degraded_reason =
                        Some("authorized_but_no_sampler_enabled".to_string());
                }
            }
            NativePermissionAction::RevokeAuthorization => {
                capability.lifecycle_state = NativeCapabilityLifecycleState::Revoked;
                capability.availability_state = NativeCapabilityAvailabilityState::Revoked;
                capability.permission_state = NativePermissionState::Revoked;
                capability.authorization_mode = NativeAuthorizationMode::None;
                capability.enabled = false;
                capability.revoked = true;
                capability.health_state = NativeCapabilityHealthState::Revoked;
                capability.degraded_reason = Some("authorization_revoked".to_string());
            }
            NativePermissionAction::DisableCapability => {
                capability.lifecycle_state = NativeCapabilityLifecycleState::Disabled;
                capability.permission_state = NativePermissionState::Disabled;
                capability.authorization_mode = NativeAuthorizationMode::None;
                capability.enabled = false;
                capability.degraded_reason = Some("capability_disabled".to_string());
            }
            NativePermissionAction::RecheckStatus => {
                capability.last_checked_time_bucket = Some(CURRENT_SESSION_BUCKET.to_string());
                if capability.revoked {
                    capability.lifecycle_state = NativeCapabilityLifecycleState::Revoked;
                    capability.availability_state = NativeCapabilityAvailabilityState::Revoked;
                    capability.health_state = NativeCapabilityHealthState::Revoked;
                    capability.degraded_reason = Some("authorization_revoked".to_string());
                } else if capability.permission_state == NativePermissionState::GrantedSession {
                    capability.lifecycle_state = NativeCapabilityLifecycleState::Granted;
                    capability.availability_state =
                        NativeCapabilityAvailabilityState::AuthorizedSamplerInactive;
                    capability.health_state = NativeCapabilityHealthState::Unknown;
                    capability.degraded_reason =
                        Some("authorized_but_no_sampler_enabled".to_string());
                } else {
                    apply_portable_default_status(capability);
                }
            }
            NativePermissionAction::ClearInactiveState => {
                if !capability.revoked
                    && capability.permission_state != NativePermissionState::GrantedSession
                {
                    apply_portable_default_status(capability);
                }
            }
        }

        capability.last_checked_time_bucket = Some(CURRENT_SESSION_BUCKET.to_string());
        capability.validate().map_err(contract_error)?;
        let audit_entry = NativePermissionAuditEntry {
            audit_id: sentinel_contracts::AuditId::new_v4(),
            capability_id: capability.capability_id.clone(),
            action: request.action,
            resulting_state: capability.lifecycle_state.clone(),
            time_bucket: CURRENT_SESSION_BUCKET.to_string(),
            provenance_id: PROVENANCE_ID.to_string(),
            summary_redacted: audit_summary_for(capability),
        };
        audit_entry.validate().map_err(contract_error)?;
        capability.audit_refs.push(audit_entry.audit_id.clone());
        capability.audit_refs.truncate(MAX_NATIVE_AUDIT_REFS);
        let capability_snapshot = capability.clone();
        self.audit_entries.push(audit_entry.clone());
        if self.audit_entries.len() > MAX_NATIVE_AUDIT_REFS {
            self.audit_entries
                .drain(0..self.audit_entries.len() - MAX_NATIVE_AUDIT_REFS);
        }

        let emitted_status_events = status_events_for(&capability_snapshot, &audit_entry);
        for event in &emitted_status_events {
            self.publish_status_event(event)?;
            self.status_events.push(event.clone());
        }
        if self.status_events.len() > MAX_NATIVE_AUDIT_REFS {
            self.status_events
                .drain(0..self.status_events.len() - MAX_NATIVE_AUDIT_REFS);
        }

        let result = NativePermissionActionResult {
            capability: capability_snapshot,
            audit_entry,
            emitted_status_events,
            telemetry_collection_started: false,
            response_execution_started: false,
            service_installation_started: false,
            driver_loading_started: false,
            host_mutation_performed: false,
            automatic_llm_calls: false,
        };
        result.validate().map_err(contract_error)?;
        Ok(result)
    }

    pub fn sync_read_state(&self, read: &mut ReadOnlyCommandState) {
        read.authorized_native_capabilities = self.capabilities.clone();
        read.native_permission_audit_entries = self.audit_entries.clone();
        read.native_status_events = self.status_events.clone();
    }

    fn capability(&self, capability_id: &str) -> CommandResult<&AuthorizedNativeCapabilityStatus> {
        self.capabilities
            .iter()
            .find(|status| status.capability_id == capability_id)
            .ok_or_else(|| native_not_found(capability_id))
    }

    fn publish_status_event(&mut self, event: &NativeStatusEvent) -> CommandResult<()> {
        event.validate().map_err(contract_error)?;
        let mut envelope = EventEnvelope::new(
            EventType::new(event.topic.clone()).map_err(contract_error)?,
            SchemaVersion::new(1, 0, 0),
            self.producer_plugin.clone(),
            TraceContext::new_root(),
        );
        envelope.privacy_class = PrivacyClass::Internal;
        envelope.quality_score = QualityScore::unknown();
        envelope.payload = serde_json::to_value(event).map_err(|error| {
            CoreError::new(
                ErrorCode::InternalError,
                "native status event serialization failed",
            )
            .with_redacted_details(json!({ "error_redacted": error.to_string() }))
        })?;
        self.event_bus
            .publish(
                TopicName::new(&event.topic).map_err(contract_error)?,
                envelope,
                PublishOptions::new("bounded native permission status"),
            )
            .map_err(|error| {
                CoreError::new(
                    ErrorCode::InternalError,
                    "native status EventBus publish failed",
                )
                .with_redacted_details(json!({ "error_redacted": error.to_string() }))
            })?;
        Ok(())
    }
}

pub fn native_permission_status_summary(
    capabilities: &[AuthorizedNativeCapabilityStatus],
) -> CommandResult<NativePermissionStatusSummary> {
    let audit_refs = capabilities
        .iter()
        .flat_map(|status| status.audit_refs.iter().cloned())
        .take(MAX_NATIVE_AUDIT_REFS)
        .collect();
    let summary = NativePermissionStatusSummary {
        capability_count: capabilities.len() as u32,
        permission_required_count: count_lifecycle(
            capabilities,
            NativeCapabilityLifecycleState::PermissionRequired,
        ),
        requested_count: count_lifecycle(capabilities, NativeCapabilityLifecycleState::Requested),
        granted_inactive_count: capabilities
            .iter()
            .filter(|status| {
                status.permission_state == NativePermissionState::GrantedSession
                    && !status.telemetry_collection_active
            })
            .count() as u32,
        revoked_count: count_lifecycle(capabilities, NativeCapabilityLifecycleState::Revoked),
        degraded_count: count_lifecycle(capabilities, NativeCapabilityLifecycleState::Degraded),
        unsupported_count: count_lifecycle(
            capabilities,
            NativeCapabilityLifecycleState::NotSupported,
        ),
        portable_default_active: true,
        session_bound_authorization: true,
        telemetry_collection_active: false,
        response_execution_allowed: false,
        automatic_llm_calls: false,
        capability_refs: capabilities
            .iter()
            .map(|status| status.capability_id.clone())
            .collect(),
        audit_refs,
        generated_at: Timestamp::now(),
    };
    summary.validate().map_err(contract_error)?;
    Ok(summary)
}

pub fn native_visibility_summary(
    capabilities: &[AuthorizedNativeCapabilityStatus],
) -> CommandResult<NativeVisibilitySummary> {
    let available_scope_categories = capabilities
        .iter()
        .filter(|status| status.permission_state == NativePermissionState::GrantedSession)
        .map(|status| status.visibility_scope.clone())
        .collect::<Vec<_>>();
    let missing_visibility_flags = capabilities
        .iter()
        .filter(|status| status.permission_state != NativePermissionState::GrantedSession)
        .map(|status| format!("{}_missing", status.capability_id))
        .collect::<Vec<_>>();
    let degraded_reasons = capabilities
        .iter()
        .filter_map(|status| status.degraded_reason.clone())
        .collect::<Vec<_>>();
    let summary = NativeVisibilitySummary {
        available_scope_categories,
        missing_visibility_flags,
        degraded_reasons,
        capability_refs: capabilities
            .iter()
            .map(|status| status.capability_id.clone())
            .collect(),
        audit_refs: capabilities
            .iter()
            .flat_map(|status| status.audit_refs.iter().cloned())
            .take(MAX_NATIVE_AUDIT_REFS)
            .collect(),
        granted_permission_creates_evidence: false,
        native_required_attack_coverage_supported: false,
        future_sampler_ready: false,
        portable_default_active: true,
        metadata_only: true,
        generated_at: Timestamp::now(),
    };
    summary.validate().map_err(contract_error)?;
    Ok(summary)
}

pub fn native_permission_audit_summary(
    entries: &[NativePermissionAuditEntry],
) -> CommandResult<NativePermissionAuditSummary> {
    let bounded_entries = entries
        .iter()
        .rev()
        .take(MAX_NATIVE_AUDIT_REFS)
        .cloned()
        .collect::<Vec<_>>();
    let summary = NativePermissionAuditSummary {
        audit_refs: bounded_entries
            .iter()
            .map(|entry| entry.audit_id.clone())
            .collect(),
        revoked_capability_refs: bounded_entries
            .iter()
            .filter(|entry| entry.resulting_state == NativeCapabilityLifecycleState::Revoked)
            .map(|entry| entry.capability_id.clone())
            .collect(),
        entries: bounded_entries,
        generated_at: Timestamp::now(),
    };
    summary.validate().map_err(contract_error)?;
    Ok(summary)
}

pub(crate) fn default_capability_catalog() -> Vec<AuthorizedNativeCapabilityStatus> {
    [
        (
            "native_host_visibility",
            AuthorizedNativeCapabilityCategory::NativeHostVisibility,
            NativeVisibilityScopeCategory::HostSummary,
            NativeCapabilityAccessMode::ReadOnlyVisibility,
        ),
        (
            "process_metadata_visibility",
            AuthorizedNativeCapabilityCategory::ProcessMetadataVisibility,
            NativeVisibilityScopeCategory::ProcessSummary,
            NativeCapabilityAccessMode::ReadOnlyVisibility,
        ),
        (
            "process_network_attribution_visibility",
            AuthorizedNativeCapabilityCategory::ProcessNetworkAttributionVisibility,
            NativeVisibilityScopeCategory::ProcessNetworkSummary,
            NativeCapabilityAccessMode::ReadOnlyVisibility,
        ),
        (
            "service_metadata_visibility",
            AuthorizedNativeCapabilityCategory::ServiceMetadataVisibility,
            NativeVisibilityScopeCategory::ServiceSummary,
            NativeCapabilityAccessMode::ReadOnlyVisibility,
        ),
        (
            "autorun_persistence_visibility",
            AuthorizedNativeCapabilityCategory::AutorunPersistenceVisibility,
            NativeVisibilityScopeCategory::PersistenceSummary,
            NativeCapabilityAccessMode::ReadOnlyVisibility,
        ),
        (
            "file_activity_summary_visibility",
            AuthorizedNativeCapabilityCategory::FileActivitySummaryVisibility,
            NativeVisibilityScopeCategory::FileActivitySummary,
            NativeCapabilityAccessMode::ReadOnlyVisibility,
        ),
        (
            "registry_summary_visibility",
            AuthorizedNativeCapabilityCategory::RegistrySummaryVisibility,
            NativeVisibilityScopeCategory::RegistryActivitySummary,
            NativeCapabilityAccessMode::ReadOnlyVisibility,
        ),
        (
            "endpoint_network_attribution_visibility",
            AuthorizedNativeCapabilityCategory::EndpointNetworkAttributionVisibility,
            NativeVisibilityScopeCategory::EndpointNetworkSummary,
            NativeCapabilityAccessMode::ReadOnlyVisibility,
        ),
        (
            "native_health_probe",
            AuthorizedNativeCapabilityCategory::NativeHealthProbe,
            NativeVisibilityScopeCategory::HealthStatusOnly,
            NativeCapabilityAccessMode::ReadOnlyVisibility,
        ),
        (
            "native_response_capability_placeholder",
            AuthorizedNativeCapabilityCategory::NativeResponseCapabilityPlaceholder,
            NativeVisibilityScopeCategory::ResponsePlaceholderOnly,
            NativeCapabilityAccessMode::ResponseCapabilityPlaceholder,
        ),
    ]
    .into_iter()
    .map(|(capability_id, category, visibility_scope, access_mode)| {
        let mut status = AuthorizedNativeCapabilityStatus {
            capability_id: capability_id.to_string(),
            category,
            lifecycle_state: NativeCapabilityLifecycleState::PortableDefaultUnavailable,
            availability_state: NativeCapabilityAvailabilityState::PortableDefaultActive,
            permission_state: NativePermissionState::NotGranted,
            authorization_mode: NativeAuthorizationMode::None,
            access_mode,
            enabled: false,
            revoked: false,
            health_state: NativeCapabilityHealthState::Unknown,
            degraded_reason: Some("portable_default_native_unavailable".to_string()),
            prerequisites: NativeCapabilityPrerequisites {
                native_service_required: true,
                explicit_authorization_required: true,
                read_only_mode_required: true,
                separate_response_policy_required: true,
            },
            visibility_scope,
            portable_default_available: false,
            last_checked_time_bucket: None,
            provenance_id: PROVENANCE_ID.to_string(),
            audit_refs: Vec::new(),
            redaction_status: RedactionStatus::Redacted,
            privacy_class: PrivacyClass::Internal,
            telemetry_collection_active: false,
            response_execution_allowed: false,
            automatic_llm_calls: false,
        };
        if status.access_mode == NativeCapabilityAccessMode::ResponseCapabilityPlaceholder {
            status.lifecycle_state = NativeCapabilityLifecycleState::NotSupported;
            status.availability_state = NativeCapabilityAvailabilityState::UnsupportedPlatform;
            status.permission_state = NativePermissionState::NotSupported;
            status.health_state = NativeCapabilityHealthState::NotSupported;
            status.degraded_reason = Some("future_response_capability_placeholder".to_string());
        }
        status
            .validate()
            .expect("static authorized native capability catalog is safe");
        status
    })
    .collect()
}

fn apply_portable_default_status(capability: &mut AuthorizedNativeCapabilityStatus) {
    capability.lifecycle_state = NativeCapabilityLifecycleState::PortableDefaultUnavailable;
    capability.availability_state = NativeCapabilityAvailabilityState::PortableDefaultActive;
    capability.permission_state = NativePermissionState::NotGranted;
    capability.authorization_mode = NativeAuthorizationMode::None;
    capability.enabled = false;
    capability.health_state = NativeCapabilityHealthState::Unknown;
    capability.degraded_reason = Some("portable_default_native_unavailable".to_string());
}

fn status_events_for(
    capability: &AuthorizedNativeCapabilityStatus,
    audit_entry: &NativePermissionAuditEntry,
) -> Vec<NativeStatusEvent> {
    let missing = if capability.permission_state == NativePermissionState::GrantedSession {
        vec!["native_sampler_inactive".to_string()]
    } else {
        vec![format!("{}_missing", capability.capability_id)]
    };
    let topics = [
        NATIVE_CAPABILITY_STATUS,
        NATIVE_PERMISSION_STATUS,
        NATIVE_VISIBILITY_STATUS,
        AUDIT_NATIVE_PERMISSION,
    ];
    let mut events = topics
        .into_iter()
        .map(|topic| NativeStatusEvent {
            topic: topic.to_string(),
            capability_id: capability.capability_id.clone(),
            category: capability.category.clone(),
            permission_state: capability.permission_state.clone(),
            health_state: capability.health_state.clone(),
            degraded_reason: capability.degraded_reason.clone(),
            missing_visibility_flags: missing.clone(),
            audit_refs: vec![audit_entry.audit_id.clone()],
            provenance_id: PROVENANCE_ID.to_string(),
            time_bucket: CURRENT_SESSION_BUCKET.to_string(),
            redaction_status: RedactionStatus::Redacted,
        })
        .collect::<Vec<_>>();
    if capability.permission_state != NativePermissionState::GrantedSession
        || capability.revoked
        || capability.health_state != NativeCapabilityHealthState::Healthy
    {
        events.push(NativeStatusEvent {
            topic: SECURITY_VISIBILITY_DEGRADED.to_string(),
            capability_id: capability.capability_id.clone(),
            category: capability.category.clone(),
            permission_state: capability.permission_state.clone(),
            health_state: capability.health_state.clone(),
            degraded_reason: capability.degraded_reason.clone(),
            missing_visibility_flags: missing,
            audit_refs: vec![audit_entry.audit_id.clone()],
            provenance_id: PROVENANCE_ID.to_string(),
            time_bucket: CURRENT_SESSION_BUCKET.to_string(),
            redaction_status: RedactionStatus::Redacted,
        });
    }
    events
}

fn audit_summary_for(capability: &AuthorizedNativeCapabilityStatus) -> String {
    match capability.lifecycle_state {
        NativeCapabilityLifecycleState::Requested => {
            "Session authorization requested; native sampler remains inactive".to_string()
        }
        NativeCapabilityLifecycleState::Granted => {
            "Session authorization granted; native sampler remains inactive".to_string()
        }
        NativeCapabilityLifecycleState::Revoked => {
            "Session authorization revoked; future native collection blocked".to_string()
        }
        NativeCapabilityLifecycleState::Disabled => {
            "Native capability disabled; bounded status retained".to_string()
        }
        NativeCapabilityLifecycleState::Denied => {
            "Native capability denied by the read only control plane".to_string()
        }
        _ => "Native capability status checked without host access".to_string(),
    }
}

fn count_lifecycle(
    capabilities: &[AuthorizedNativeCapabilityStatus],
    state: NativeCapabilityLifecycleState,
) -> u32 {
    capabilities
        .iter()
        .filter(|status| status.lifecycle_state == state)
        .count() as u32
}

fn native_not_found(capability_id: &str) -> CoreError {
    CoreError::new(
        ErrorCode::InvalidRequest,
        "authorized native capability was not found",
    )
    .with_severity(ErrorSeverity::Warning)
    .with_redacted_details(json!({ "capability_id": capability_id }))
}

fn contract_error(error: impl ToString) -> CoreError {
    CoreError::validation_failure("authorized native permission contract validation failed")
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{AttackCoverageState, AttackRequiredVisibility};

    #[test]
    fn portable_native_control_plane_starts_unavailable_without_collection() {
        let read = ReadOnlyCommandState::bootstrap().expect("read state");
        let runtime = AuthorizedNativePermissionRuntime::from_read_state(&read);
        assert_eq!(runtime.capabilities.len(), 10);
        assert!(runtime
            .capabilities
            .iter()
            .all(|status| !status.telemetry_collection_active
                && !status.response_execution_allowed
                && !status.automatic_llm_calls
                && !status.sampler_policy_allows_collection()));
    }

    #[test]
    fn preview_and_grant_never_start_native_collection_or_create_findings() {
        let mut read = ReadOnlyCommandState::bootstrap().expect("read state");
        let mut runtime = AuthorizedNativePermissionRuntime::from_read_state(&read);
        let finding_count = read.findings.items.len();
        let preview = runtime
            .preview_permission_request("process_metadata_visibility")
            .expect("preview");
        assert!(!preview.state_change_performed);
        let result = runtime
            .apply_action(NativePermissionActionRequest {
                capability_id: "process_metadata_visibility".to_string(),
                action: NativePermissionAction::GrantAuthorization,
                explicit_user_action: true,
                reason_redacted: "authorize read only visibility".to_string(),
            })
            .expect("grant");
        runtime.sync_read_state(&mut read);
        assert_eq!(read.findings.items.len(), finding_count);
        assert_eq!(
            result.capability.availability_state,
            NativeCapabilityAvailabilityState::AuthorizedSamplerInactive
        );
        assert!(!result.telemetry_collection_started);
        assert!(!result.capability.sampler_policy_allows_collection());
    }

    #[test]
    fn revocation_blocks_future_collection_and_emits_declared_topics_only() {
        let read = ReadOnlyCommandState::bootstrap().expect("read state");
        let mut runtime = AuthorizedNativePermissionRuntime::from_read_state(&read);
        runtime
            .apply_action(NativePermissionActionRequest {
                capability_id: "native_host_visibility".to_string(),
                action: NativePermissionAction::GrantAuthorization,
                explicit_user_action: true,
                reason_redacted: "authorize read only visibility".to_string(),
            })
            .expect("grant");
        let revoked = runtime
            .apply_action(NativePermissionActionRequest {
                capability_id: "native_host_visibility".to_string(),
                action: NativePermissionAction::RevokeAuthorization,
                explicit_user_action: true,
                reason_redacted: "revoke native authorization".to_string(),
            })
            .expect("revoke");
        assert!(revoked.capability.revoked);
        assert!(!revoked.capability.sampler_policy_allows_collection());
        assert!(revoked.emitted_status_events.iter().all(|event| matches!(
            event.topic.as_str(),
            NATIVE_CAPABILITY_STATUS
                | NATIVE_PERMISSION_STATUS
                | NATIVE_VISIBILITY_STATUS
                | SECURITY_VISIBILITY_DEGRADED
                | AUDIT_NATIVE_PERMISSION
        )));
    }

    #[test]
    fn native_required_attack_rows_remain_unsupported_after_grant() {
        let read = ReadOnlyCommandState::bootstrap().expect("read state");
        let summary = crate::read_commands::build_attack_coverage_summary(&read).expect("coverage");
        let native_rows = summary
            .technique_rows
            .iter()
            .filter(|row| {
                matches!(
                    row.required_visibility,
                    AttackRequiredVisibility::AuthorizedNativeProcessVisibility
                        | AttackRequiredVisibility::AuthorizedNativeExtension
                )
            })
            .collect::<Vec<_>>();
        assert!(!native_rows.is_empty());
        assert!(native_rows.iter().all(|row| {
            row.states.contains(&AttackCoverageState::Unsupported)
                && row
                    .states
                    .contains(&AttackCoverageState::RequiresAuthorizedNativeExtension)
                && row.evidence_refs.is_empty()
                && row.finding_refs.is_empty()
        }));
    }

    #[test]
    fn read_commands_expose_bounded_native_status_without_endpoint_values() {
        let read = ReadOnlyCommandState::bootstrap().expect("read state");
        let capabilities =
            crate::read_commands::list_authorized_native_capabilities(&read).expect("capabilities");
        let permission =
            crate::read_commands::get_native_permission_status_summary(&read).expect("permission");
        let visibility =
            crate::read_commands::get_native_visibility_summary(&read).expect("visibility");
        let audit =
            crate::read_commands::get_native_permission_audit_summary(&read).expect("audit");
        assert_eq!(capabilities.len(), 10);
        assert_eq!(permission.capability_count, 10);
        assert!(!visibility.future_sampler_ready);
        assert!(audit.entries.is_empty());
        let serialized = serde_json::to_string(&(capabilities, permission, visibility, audit))
            .expect("bounded native read models");
        for forbidden in [
            "C:\\Users",
            "https://",
            "command_line",
            "password",
            "session_token",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }
}
