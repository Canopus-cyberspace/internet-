//! STUB_ONLY service-side command safety boundary.
//!
//! NOT_FOR_PRODUCTION: this module validates command metadata, local-core
//! permission hooks, audit prerequisites, and degraded-state behavior before a
//! future privileged adapter can run. It never performs Windows OS actions.

use crate::ipc::{
    command_spec, default_ipc_command_allowlist, IpcCommand, IpcCommandLevel, IpcCommandSpec,
    IpcProtocolError, IpcRequestEnvelope, IPC_SCHEMA_VERSION,
};
use crate::{ServiceHealthSnapshot, ServiceStatus, NOT_FOR_PRODUCTION_LABEL, STUB_ONLY_LABEL};
use sentinel_contracts::{
    AttributionConfidence, AuditId, ErrorCode, PermissionKey, SchemaVersion, ServiceAdapterMode,
    ServiceCapabilityContext, ServiceCapabilityStatus, ServiceLimitationFlag, ServiceReasonCode,
    Timestamp, TraceId,
};
use sentinel_platform::{
    AuditActionType, AuditCategory, AuditDecision, AuditEvent, ObservabilityHealthStatus,
    PermissionScope, PermissionSubject,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SERVICE_SECURITY_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
const SERVICE_CONTEXT_SOURCE_PRECHECK: &str = "service_stub.security_precheck";
const SERVICE_CONTEXT_SOURCE_CAPTURE: &str = "service_stub.capture_status";
const SERVICE_CONTEXT_SOURCE_PROCESS: &str = "service_stub.process_attribution";
const SERVICE_CONTEXT_SOURCE_RESPONSE: &str = "service_stub.response_executor";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceCommandAllowlist {
    pub specs: Vec<IpcCommandSpec>,
    pub schema_version: SchemaVersion,
    pub stub_only: bool,
    pub not_for_production: bool,
}

impl ServiceCommandAllowlist {
    pub fn v1_default() -> Result<Self, IpcProtocolError> {
        let allowlist = Self {
            specs: default_ipc_command_allowlist()?,
            schema_version: SERVICE_SECURITY_SCHEMA_VERSION,
            stub_only: true,
            not_for_production: true,
        };
        allowlist.validate()?;
        Ok(allowlist)
    }

    pub fn deny_all() -> Self {
        Self {
            specs: Vec::new(),
            schema_version: SERVICE_SECURITY_SCHEMA_VERSION,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn without_command(mut self, command: &IpcCommand) -> Self {
        self.specs.retain(|spec| &spec.command != command);
        self
    }

    pub fn validate(&self) -> Result<(), IpcProtocolError> {
        if self.schema_version != SERVICE_SECURITY_SCHEMA_VERSION {
            return Err(IpcProtocolError::schema_mismatch(
                "service command allowlist schema version is unsupported",
            ));
        }
        if !self.stub_only || !self.not_for_production {
            return Err(IpcProtocolError::invalid(
                "labels",
                "service command allowlist must be STUB_ONLY and NOT_FOR_PRODUCTION",
            ));
        }
        for spec in &self.specs {
            spec.validate()?;
        }
        Ok(())
    }

    pub fn spec_for(&self, command: &IpcCommand) -> Option<&IpcCommandSpec> {
        self.specs.iter().find(|spec| &spec.command == command)
    }

    pub fn enabled_spec_for(
        &self,
        command: &IpcCommand,
    ) -> Result<&IpcCommandSpec, ServiceRejectionReason> {
        let Some(spec) = self.spec_for(command) else {
            return Err(ServiceRejectionReason::CommandNotInAllowlist);
        };
        if !spec.enabled_in_v1 {
            return Err(ServiceRejectionReason::CommandNotInAllowlist);
        }
        Ok(spec)
    }

    pub fn commands_for_level(&self, level: IpcCommandLevel) -> Vec<IpcCommand> {
        self.specs
            .iter()
            .filter(|spec| spec.level == level)
            .map(|spec| spec.command.clone())
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServicePermissionCheck {
    pub subject: PermissionSubject,
    pub permission: PermissionKey,
    pub scope: PermissionScope,
    pub permission_granted: bool,
    pub policy_evaluated: bool,
    pub policy_allowed: bool,
    pub approval_granted: bool,
    pub policy_version: Option<String>,
    pub reason_redacted: String,
    pub checked_at: Timestamp,
}

impl ServicePermissionCheck {
    pub fn granted_for_spec(spec: &IpcCommandSpec) -> Self {
        Self {
            subject: PermissionSubject::LocalCore,
            permission: spec.permission.clone(),
            scope: spec.permission_scope.clone(),
            permission_granted: true,
            policy_evaluated: spec.approval_required,
            policy_allowed: true,
            approval_granted: spec.approval_required,
            policy_version: Some("service-policy-v1".to_string()),
            reason_redacted: "Local Core service IPC permission granted".to_string(),
            checked_at: Timestamp::now(),
        }
    }

    pub fn missing_for_spec(spec: &IpcCommandSpec) -> Self {
        Self {
            subject: PermissionSubject::LocalCore,
            permission: spec.permission.clone(),
            scope: spec.permission_scope.clone(),
            permission_granted: false,
            policy_evaluated: false,
            policy_allowed: false,
            approval_granted: false,
            policy_version: None,
            reason_redacted: "Local Core service IPC permission missing".to_string(),
            checked_at: Timestamp::now(),
        }
    }

    pub fn denied_by_policy_for_spec(spec: &IpcCommandSpec) -> Self {
        Self {
            subject: PermissionSubject::LocalCore,
            permission: spec.permission.clone(),
            scope: spec.permission_scope.clone(),
            permission_granted: true,
            policy_evaluated: true,
            policy_allowed: false,
            approval_granted: false,
            policy_version: Some("service-policy-v1".to_string()),
            reason_redacted: "Local Core service IPC policy denied command".to_string(),
            checked_at: Timestamp::now(),
        }
    }

    pub fn unavailable_for_command(command: &IpcCommand) -> Self {
        let spec = command_spec(command).ok();
        let permission = spec
            .as_ref()
            .map(|spec| spec.permission.clone())
            .unwrap_or_else(service_ipc_unavailable_permission);
        let scope = spec
            .as_ref()
            .map(|spec| spec.permission_scope.clone())
            .unwrap_or_else(|| PermissionScope::System {
                command: command.as_str().to_string(),
                elevated_service_required: true,
            });
        Self {
            subject: PermissionSubject::LocalCore,
            permission,
            scope,
            permission_granted: false,
            policy_evaluated: false,
            policy_allowed: false,
            approval_granted: false,
            policy_version: None,
            reason_redacted: "service IPC command permission unavailable".to_string(),
            checked_at: Timestamp::now(),
        }
    }

    pub fn validate_for_spec(&self, spec: &IpcCommandSpec) -> Result<(), ServiceRejectionReason> {
        if self.permission != spec.permission
            || self.scope.domain() != spec.permission_scope.domain()
        {
            return Err(ServiceRejectionReason::MissingPermission);
        }
        if !self.permission_granted {
            return Err(ServiceRejectionReason::MissingPermission);
        }
        if spec.approval_required && (!self.policy_evaluated || !self.policy_allowed) {
            return Err(ServiceRejectionReason::PolicyDenied);
        }
        if spec.approval_required && !self.approval_granted {
            return Err(ServiceRejectionReason::MissingApproval);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensitiveCommandAudit {
    pub audit_id: AuditId,
    pub action_type: AuditActionType,
    pub actor_redacted: String,
    pub target_redacted: String,
    pub decision: AuditDecision,
    pub policy_version: String,
    pub trace_id: TraceId,
    pub rollback_ref: Option<String>,
    pub sensitive_data_touched: bool,
    pub audit_sink_available: bool,
    pub schema_version: SchemaVersion,
    pub labels: Vec<String>,
}

impl SensitiveCommandAudit {
    pub fn for_request(
        request: &IpcRequestEnvelope,
        target_redacted: impl Into<String>,
        rollback_ref: Option<String>,
    ) -> Self {
        Self {
            audit_id: AuditId::new_v4(),
            action_type: AuditActionType::ServiceCommandRequested,
            actor_redacted: request.caller.actor_redacted.clone(),
            target_redacted: target_redacted.into(),
            decision: AuditDecision::Allowed,
            policy_version: "service-policy-v1".to_string(),
            trace_id: request.trace_id.clone(),
            rollback_ref,
            sensitive_data_touched: false,
            audit_sink_available: true,
            schema_version: SERVICE_SECURITY_SCHEMA_VERSION,
            labels: vec![
                STUB_ONLY_LABEL.to_string(),
                NOT_FOR_PRODUCTION_LABEL.to_string(),
            ],
        }
    }

    pub fn validate_for_spec(&self, spec: &IpcCommandSpec) -> Result<(), ServiceRejectionReason> {
        if self.schema_version != SERVICE_SECURITY_SCHEMA_VERSION {
            return Err(ServiceRejectionReason::InvalidSchema);
        }
        if !self.audit_sink_available {
            return Err(ServiceRejectionReason::MissingAuditSink);
        }
        if self.actor_redacted.trim().is_empty()
            || self.target_redacted.trim().is_empty()
            || self.policy_version.trim().is_empty()
        {
            return Err(ServiceRejectionReason::SensitiveCommandAuditMissing);
        }
        if crate::validate_safe_text("actor_redacted", &self.actor_redacted).is_err()
            || crate::validate_safe_text("target_redacted", &self.target_redacted).is_err()
            || crate::validate_safe_text("policy_version", &self.policy_version).is_err()
        {
            return Err(ServiceRejectionReason::PrivacyViolation);
        }
        if let Some(rollback_ref) = &self.rollback_ref {
            if crate::validate_safe_text("rollback_ref", rollback_ref).is_err() {
                return Err(ServiceRejectionReason::PrivacyViolation);
            }
        }
        if spec.rollback_required && self.rollback_ref.as_deref().unwrap_or("").trim().is_empty() {
            return Err(ServiceRejectionReason::MissingRollback);
        }
        Ok(())
    }

    pub fn validate_for_request(
        &self,
        request: &IpcRequestEnvelope,
        spec: &IpcCommandSpec,
    ) -> Result<(), ServiceRejectionReason> {
        self.validate_for_spec(spec)?;
        if self.action_type != AuditActionType::ServiceCommandRequested
            || self.trace_id != request.trace_id
            || self.actor_redacted != request.caller.actor_redacted
        {
            return Err(ServiceRejectionReason::SensitiveCommandAuditMissing);
        }
        Ok(())
    }

    pub fn to_audit_event(
        &self,
        result_redacted: impl Into<String>,
    ) -> Result<AuditEvent, IpcProtocolError> {
        let mut event = AuditEvent::new(
            AuditCategory::Service,
            self.action_type.clone(),
            self.actor_redacted.clone(),
            self.target_redacted.clone(),
            self.decision.clone(),
            result_redacted,
        )
        .map_err(|error| IpcProtocolError::invalid("audit", error.to_string()))?;
        event.audit_id = self.audit_id.clone();
        event.policy_version = Some(self.policy_version.clone());
        event.trace_id = Some(self.trace_id.clone());
        event.rollback_ref = self.rollback_ref.clone();
        event.sensitive_data_touched = self.sensitive_data_touched;
        event
            .validate()
            .map_err(|error| IpcProtocolError::invalid("audit", error.to_string()))?;
        Ok(event)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDegradedState {
    pub service_unavailable: bool,
    pub ipc_disconnected: bool,
    pub capture_unavailable: bool,
    pub process_attribution_low_or_unknown: bool,
    pub response_executor_disabled: bool,
    pub auto_containment_disabled: bool,
    pub reduced_visibility: bool,
    pub reason_codes: Vec<ServiceRejectionReason>,
    pub message_redacted: String,
}

impl ServiceDegradedState {
    pub fn healthy() -> Self {
        Self {
            service_unavailable: false,
            ipc_disconnected: false,
            capture_unavailable: false,
            process_attribution_low_or_unknown: false,
            response_executor_disabled: false,
            auto_containment_disabled: false,
            reduced_visibility: false,
            reason_codes: Vec::new(),
            message_redacted: "Elevated service safety boundary is healthy".to_string(),
        }
    }

    pub fn stub_only() -> Self {
        Self {
            service_unavailable: true,
            ipc_disconnected: true,
            capture_unavailable: true,
            process_attribution_low_or_unknown: true,
            response_executor_disabled: true,
            auto_containment_disabled: true,
            reduced_visibility: true,
            reason_codes: vec![
                ServiceRejectionReason::UnhealthyService,
                ServiceRejectionReason::CaptureUnavailable,
                ServiceRejectionReason::ResponseExecutorDisabled,
            ],
            message_redacted: "STUB_ONLY service unavailable; privileged adapters are disabled"
                .to_string(),
        }
    }

    pub fn capture_unavailable() -> Self {
        Self {
            capture_unavailable: true,
            reduced_visibility: true,
            reason_codes: vec![ServiceRejectionReason::CaptureUnavailable],
            message_redacted: "Capture adapter unavailable; imported metadata remains usable"
                .to_string(),
            ..Self::healthy()
        }
    }

    pub fn response_executor_disabled() -> Self {
        Self {
            response_executor_disabled: true,
            auto_containment_disabled: true,
            reduced_visibility: true,
            reason_codes: vec![ServiceRejectionReason::ResponseExecutorDisabled],
            message_redacted: "Response executor disabled; recommendations remain available"
                .to_string(),
            ..Self::healthy()
        }
    }

    pub fn privileged_actions_available(&self) -> bool {
        !self.service_unavailable
            && !self.ipc_disconnected
            && !self.response_executor_disabled
            && !self.auto_containment_disabled
    }

    pub fn rejection_for_command(&self, command: &IpcCommand) -> Option<ServiceRejectionReason> {
        if self.service_unavailable && !matches!(command, IpcCommand::GetServiceStatus) {
            return Some(ServiceRejectionReason::UnhealthyService);
        }
        if self.ipc_disconnected && is_privileged_command(command) {
            return Some(ServiceRejectionReason::UnhealthyService);
        }
        if self.capture_unavailable && is_capture_mutation_command(command) {
            return Some(ServiceRejectionReason::CaptureUnavailable);
        }
        if self.process_attribution_low_or_unknown && is_process_attribution_command(command) {
            return Some(ServiceRejectionReason::ProcessAttributionLowOrUnknown);
        }
        if self.response_executor_disabled && is_response_command(command) {
            return Some(ServiceRejectionReason::ResponseExecutorDisabled);
        }
        None
    }
}

pub fn safe_service_capability_contexts(
    degraded: &ServiceDegradedState,
    observed_at: Timestamp,
) -> Result<Vec<ServiceCapabilityContext>, IpcProtocolError> {
    let contexts = vec![
        service_capability_context(
            "service_boundary",
            if degraded.service_unavailable && degraded.ipc_disconnected {
                ServiceCapabilityStatus::Disconnected
            } else if degraded.service_unavailable {
                ServiceCapabilityStatus::Unavailable
            } else if degraded.reduced_visibility {
                ServiceCapabilityStatus::Degraded
            } else {
                ServiceCapabilityStatus::Available
            },
            if degraded.ipc_disconnected {
                Some(ServiceReasonCode::IpcDisconnected)
            } else if degraded.service_unavailable {
                Some(ServiceReasonCode::ServiceUnavailable)
            } else if degraded.reduced_visibility {
                Some(ServiceReasonCode::ReducedVisibility)
            } else {
                Some(ServiceReasonCode::StubOnlyMode)
            },
            vec![
                ServiceLimitationFlag::LocalOnly,
                ServiceLimitationFlag::StubOnly,
                ServiceLimitationFlag::ReadOnlyAllowlist,
                ServiceLimitationFlag::NoRawContentRetention,
                ServiceLimitationFlag::ControlPlaneOwnedByLocalCore,
                ServiceLimitationFlag::NoProductionServiceLifecycle,
            ],
            SERVICE_CONTEXT_SOURCE_PRECHECK,
            observed_at.clone(),
        )?,
        service_capability_context(
            "capture_adapter",
            if degraded.ipc_disconnected {
                ServiceCapabilityStatus::Disconnected
            } else if degraded.capture_unavailable || degraded.service_unavailable {
                ServiceCapabilityStatus::Unavailable
            } else {
                ServiceCapabilityStatus::Degraded
            },
            Some(ServiceReasonCode::CaptureUnavailable),
            vec![
                ServiceLimitationFlag::StubOnly,
                ServiceLimitationFlag::MetadataOnly,
                ServiceLimitationFlag::NoRawContentRetention,
                ServiceLimitationFlag::NoPrivilegedCapture,
                ServiceLimitationFlag::ReducedVisibility,
                ServiceLimitationFlag::NoProductionServiceLifecycle,
            ],
            SERVICE_CONTEXT_SOURCE_CAPTURE,
            observed_at.clone(),
        )?,
        service_capability_context(
            "process_attribution",
            if degraded.ipc_disconnected {
                ServiceCapabilityStatus::Disconnected
            } else if degraded.service_unavailable {
                ServiceCapabilityStatus::Unavailable
            } else {
                ServiceCapabilityStatus::Degraded
            },
            Some(ServiceReasonCode::ProcessAttributionLimited),
            vec![
                ServiceLimitationFlag::StubOnly,
                ServiceLimitationFlag::MetadataOnly,
                ServiceLimitationFlag::NoProcessAttribution,
                ServiceLimitationFlag::ReducedVisibility,
                ServiceLimitationFlag::NoProductionServiceLifecycle,
            ],
            SERVICE_CONTEXT_SOURCE_PROCESS,
            observed_at.clone(),
        )?,
        service_capability_context(
            "response_executor",
            ServiceCapabilityStatus::Disabled,
            Some(ServiceReasonCode::ResponseExecutionDisabled),
            vec![
                ServiceLimitationFlag::StubOnly,
                ServiceLimitationFlag::ReadOnlyAllowlist,
                ServiceLimitationFlag::NoResponseExecution,
                ServiceLimitationFlag::NoOsAction,
                ServiceLimitationFlag::NoProductionServiceLifecycle,
            ],
            SERVICE_CONTEXT_SOURCE_RESPONSE,
            observed_at,
        )?,
    ];
    Ok(contexts)
}

fn service_capability_context(
    capability_id: &str,
    status: ServiceCapabilityStatus,
    reason_code: Option<ServiceReasonCode>,
    limitation_flags: Vec<ServiceLimitationFlag>,
    source_provenance_id: &str,
    observed_at: Timestamp,
) -> Result<ServiceCapabilityContext, IpcProtocolError> {
    let mut context = ServiceCapabilityContext::new(
        capability_id,
        match status {
            ServiceCapabilityStatus::Disconnected => ServiceAdapterMode::Disconnected,
            ServiceCapabilityStatus::Disabled => ServiceAdapterMode::Disabled,
            ServiceCapabilityStatus::Available
            | ServiceCapabilityStatus::Degraded
            | ServiceCapabilityStatus::Unavailable
            | ServiceCapabilityStatus::Unauthorized => ServiceAdapterMode::StubOnly,
        },
        status,
        source_provenance_id,
    )
    .map_err(|error| IpcProtocolError::invalid("service_context", error.to_string()))?;
    if let Some(reason_code) = reason_code {
        context.reason_code = Some(reason_code);
    }
    context.limitation_flags = limitation_flags;
    context.observed_at = observed_at;
    context
        .validate_boundary()
        .map_err(|error| IpcProtocolError::invalid("service_context", error.to_string()))?;
    Ok(context)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceMappedHealth {
    pub local_core_status: ObservabilityHealthStatus,
    pub elevated_service_status: ObservabilityHealthStatus,
    pub ipc_status: ObservabilityHealthStatus,
    pub capture_status: ObservabilityHealthStatus,
    pub process_attribution_status: ObservabilityHealthStatus,
    pub response_executor_status: ObservabilityHealthStatus,
    pub reduced_visibility: bool,
    pub privileged_actions_available: bool,
    pub capture_available: bool,
    pub message_redacted: String,
    pub generated_at: Timestamp,
}

#[derive(Clone, Debug, Default)]
pub struct ServiceHealthMapper;

impl ServiceHealthMapper {
    pub fn map(
        snapshot: &ServiceHealthSnapshot,
        degraded: &ServiceDegradedState,
    ) -> ServiceMappedHealth {
        let elevated = if degraded.service_unavailable {
            match snapshot.status {
                ServiceStatus::Disconnected => ObservabilityHealthStatus::Disconnected,
                ServiceStatus::Unauthorized => ObservabilityHealthStatus::Unauthorized,
                _ => ObservabilityHealthStatus::Unavailable,
            }
        } else {
            snapshot.status.as_observability_status()
        };

        ServiceMappedHealth {
            local_core_status: ObservabilityHealthStatus::Healthy,
            elevated_service_status: elevated,
            ipc_status: if degraded.ipc_disconnected {
                ObservabilityHealthStatus::Disconnected
            } else {
                ObservabilityHealthStatus::Healthy
            },
            capture_status: if degraded.capture_unavailable {
                ObservabilityHealthStatus::Unavailable
            } else {
                ObservabilityHealthStatus::Healthy
            },
            process_attribution_status: if degraded.process_attribution_low_or_unknown {
                ObservabilityHealthStatus::Degraded
            } else {
                ObservabilityHealthStatus::Healthy
            },
            response_executor_status: if degraded.response_executor_disabled {
                ObservabilityHealthStatus::Unavailable
            } else {
                ObservabilityHealthStatus::Healthy
            },
            reduced_visibility: degraded.reduced_visibility,
            privileged_actions_available: degraded.privileged_actions_available(),
            capture_available: !degraded.capture_unavailable && !degraded.service_unavailable,
            message_redacted: degraded.message_redacted.clone(),
            generated_at: Timestamp::now(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRejectionReason {
    InvalidSchema,
    CommandNotInAllowlist,
    MissingPermission,
    PolicyDenied,
    MissingApproval,
    BroadTargetScope,
    MissingTtl,
    MissingRollback,
    MissingAuditSink,
    SensitiveCommandAuditMissing,
    UnhealthyService,
    UnauthenticatedClient,
    CaptureUnavailable,
    ProcessAttributionLowOrUnknown,
    ResponseExecutorDisabled,
    PrivacyViolation,
}

impl ServiceRejectionReason {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidSchema => ErrorCode::SchemaMismatch,
            Self::CommandNotInAllowlist => ErrorCode::UnsupportedOperation,
            Self::MissingPermission | Self::UnauthenticatedClient => ErrorCode::PermissionDenied,
            Self::PolicyDenied
            | Self::MissingApproval
            | Self::BroadTargetScope
            | Self::MissingTtl
            | Self::MissingRollback
            | Self::SensitiveCommandAuditMissing => ErrorCode::ResponseDeniedByPolicy,
            Self::MissingAuditSink
            | Self::UnhealthyService
            | Self::CaptureUnavailable
            | Self::ProcessAttributionLowOrUnknown
            | Self::ResponseExecutorDisabled => ErrorCode::ServiceUnavailable,
            Self::PrivacyViolation => ErrorCode::PrivacyPolicyViolation,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSchema => "invalid_schema",
            Self::CommandNotInAllowlist => "command_not_in_allowlist",
            Self::MissingPermission => "missing_permission",
            Self::PolicyDenied => "policy_denied",
            Self::MissingApproval => "missing_approval",
            Self::BroadTargetScope => "broad_target_scope",
            Self::MissingTtl => "missing_ttl",
            Self::MissingRollback => "missing_rollback",
            Self::MissingAuditSink => "missing_audit_sink",
            Self::SensitiveCommandAuditMissing => "sensitive_command_audit_missing",
            Self::UnhealthyService => "unhealthy_service",
            Self::UnauthenticatedClient => "unauthenticated_client",
            Self::CaptureUnavailable => "capture_unavailable",
            Self::ProcessAttributionLowOrUnknown => "process_attribution_low_or_unknown",
            Self::ResponseExecutorDisabled => "response_executor_disabled",
            Self::PrivacyViolation => "privacy_violation",
        }
    }

    pub fn message_redacted(&self) -> &'static str {
        match self {
            Self::InvalidSchema => "service command request schema is invalid",
            Self::CommandNotInAllowlist => "service command is not enabled in the V1 allowlist",
            Self::MissingPermission => "Local Core permission check did not grant command",
            Self::PolicyDenied => "Local Core policy denied command",
            Self::MissingApproval => "Local Core approval was required but not granted",
            Self::BroadTargetScope => "response target scope is too broad",
            Self::MissingTtl => "temporary response command is missing TTL metadata",
            Self::MissingRollback => "response command is missing rollback metadata",
            Self::MissingAuditSink => "audit sink is unavailable for sensitive command",
            Self::SensitiveCommandAuditMissing => "sensitive command audit metadata is incomplete",
            Self::UnhealthyService => "elevated service is not healthy enough for command",
            Self::UnauthenticatedClient => "IPC client is not authenticated",
            Self::CaptureUnavailable => "capture adapter is unavailable",
            Self::ProcessAttributionLowOrUnknown => {
                "process attribution confidence is low or unknown"
            }
            Self::ResponseExecutorDisabled => "response executor is disabled",
            Self::PrivacyViolation => "service command contains disallowed private content marker",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceCommandDecision {
    pub command: IpcCommand,
    pub level: IpcCommandLevel,
    pub allowed: bool,
    pub rejection_reason: Option<ServiceRejectionReason>,
    pub error_code: Option<ErrorCode>,
    pub audit_required: bool,
    pub policy_required: bool,
    pub ttl_required: bool,
    pub rollback_required: bool,
    pub permission_check: ServicePermissionCheck,
    pub degraded_state: ServiceDegradedState,
    pub audit: Option<SensitiveCommandAudit>,
    pub message_redacted: String,
    pub decided_at: Timestamp,
}

impl ServiceCommandDecision {
    fn allowed(
        spec: &IpcCommandSpec,
        permission_check: ServicePermissionCheck,
        degraded_state: ServiceDegradedState,
        audit: Option<SensitiveCommandAudit>,
    ) -> Self {
        Self {
            command: spec.command.clone(),
            level: spec.level.clone(),
            allowed: true,
            rejection_reason: None,
            error_code: None,
            audit_required: spec.audit_required,
            policy_required: spec.approval_required,
            ttl_required: spec.ttl_required,
            rollback_required: spec.rollback_required,
            permission_check,
            degraded_state,
            audit,
            message_redacted: "service command passed safety precheck".to_string(),
            decided_at: Timestamp::now(),
        }
    }

    fn denied(
        command: IpcCommand,
        level: IpcCommandLevel,
        reason: ServiceRejectionReason,
        spec: Option<&IpcCommandSpec>,
        permission_check: ServicePermissionCheck,
        degraded_state: ServiceDegradedState,
        audit: Option<SensitiveCommandAudit>,
    ) -> Self {
        Self {
            command,
            level,
            allowed: false,
            error_code: Some(reason.error_code()),
            message_redacted: reason.message_redacted().to_string(),
            rejection_reason: Some(reason),
            audit_required: spec.is_some_and(|spec| spec.audit_required),
            policy_required: spec.is_some_and(|spec| spec.approval_required),
            ttl_required: spec.is_some_and(|spec| spec.ttl_required),
            rollback_required: spec.is_some_and(|spec| spec.rollback_required),
            permission_check,
            degraded_state,
            audit,
            decided_at: Timestamp::now(),
        }
    }

    pub fn to_ipc_error(&self) -> IpcProtocolError {
        let reason = self
            .rejection_reason
            .clone()
            .unwrap_or(ServiceRejectionReason::CommandNotInAllowlist);
        IpcProtocolError {
            error_code: reason.error_code(),
            message_redacted: self.message_redacted.clone(),
            field: Some(reason.as_str().to_string()),
            retryable: matches!(
                reason,
                ServiceRejectionReason::MissingAuditSink
                    | ServiceRejectionReason::UnhealthyService
                    | ServiceRejectionReason::CaptureUnavailable
                    | ServiceRejectionReason::ResponseExecutorDisabled
            ),
            audit_ref: self.audit.as_ref().map(|audit| audit.audit_id.clone()),
            stub_only: true,
            not_for_production: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivilegedCommandPrecheck {
    pub allowlist: ServiceCommandAllowlist,
    pub degraded_state: ServiceDegradedState,
    pub schema_version: SchemaVersion,
}

impl PrivilegedCommandPrecheck {
    pub fn new(allowlist: ServiceCommandAllowlist, degraded_state: ServiceDegradedState) -> Self {
        Self {
            allowlist,
            degraded_state,
            schema_version: SERVICE_SECURITY_SCHEMA_VERSION,
        }
    }

    pub fn stub_only() -> Self {
        Self {
            allowlist: ServiceCommandAllowlist::v1_default()
                .unwrap_or_else(|_| ServiceCommandAllowlist::deny_all()),
            degraded_state: ServiceDegradedState::stub_only(),
            schema_version: SERVICE_SECURITY_SCHEMA_VERSION,
        }
    }

    pub fn healthy_for_tests() -> Self {
        Self {
            allowlist: ServiceCommandAllowlist::v1_default()
                .expect("Task 320 default allowlist should be valid"),
            degraded_state: ServiceDegradedState::healthy(),
            schema_version: SERVICE_SECURITY_SCHEMA_VERSION,
        }
    }

    pub fn trusted_local_core_permission_check(
        &self,
        command: &IpcCommand,
    ) -> ServicePermissionCheck {
        self.allowlist
            .spec_for(command)
            .map(ServicePermissionCheck::granted_for_spec)
            .unwrap_or_else(|| ServicePermissionCheck::unavailable_for_command(command))
    }

    pub fn evaluate_request(
        &self,
        request: &IpcRequestEnvelope,
        permission_check: &ServicePermissionCheck,
        audit: Option<&SensitiveCommandAudit>,
    ) -> ServiceCommandDecision {
        let command = request.command.clone();
        let level = command.level();
        let spec = self.allowlist.spec_for(&command);
        let audit = audit.cloned();

        if self.schema_version != SERVICE_SECURITY_SCHEMA_VERSION
            || request.schema_version != IPC_SCHEMA_VERSION
        {
            return ServiceCommandDecision::denied(
                command,
                level,
                ServiceRejectionReason::InvalidSchema,
                spec,
                permission_check.clone(),
                self.degraded_state.clone(),
                audit,
            );
        }

        if request.auth_context.validate().is_err() || request.caller.validate().is_err() {
            return ServiceCommandDecision::denied(
                command,
                level,
                ServiceRejectionReason::UnauthenticatedClient,
                spec,
                permission_check.clone(),
                self.degraded_state.clone(),
                audit,
            );
        }

        let spec = match self.allowlist.enabled_spec_for(&command) {
            Ok(spec) => spec,
            Err(reason) => {
                return ServiceCommandDecision::denied(
                    command,
                    level,
                    reason,
                    spec,
                    permission_check.clone(),
                    self.degraded_state.clone(),
                    audit,
                );
            }
        };

        if let Err(error) = request.validate() {
            return ServiceCommandDecision::denied(
                command,
                level,
                rejection_from_ipc_error(&error),
                Some(spec),
                permission_check.clone(),
                self.degraded_state.clone(),
                audit,
            );
        }

        if let Some(reason) = self.degraded_state.rejection_for_command(&command) {
            return ServiceCommandDecision::denied(
                command,
                level,
                reason,
                Some(spec),
                permission_check.clone(),
                self.degraded_state.clone(),
                audit,
            );
        }

        if let Err(reason) = permission_check.validate_for_spec(spec) {
            return ServiceCommandDecision::denied(
                command,
                level,
                reason,
                Some(spec),
                permission_check.clone(),
                self.degraded_state.clone(),
                audit,
            );
        }

        if spec.approval_required && target_scope_too_broad(&request.payload) {
            return ServiceCommandDecision::denied(
                command,
                level,
                ServiceRejectionReason::BroadTargetScope,
                Some(spec),
                permission_check.clone(),
                self.degraded_state.clone(),
                audit,
            );
        }

        if spec.ttl_required && !payload_has_positive_ttl(&request.payload) {
            return ServiceCommandDecision::denied(
                command,
                level,
                ServiceRejectionReason::MissingTtl,
                Some(spec),
                permission_check.clone(),
                self.degraded_state.clone(),
                audit,
            );
        }

        if spec.rollback_required
            && !payload_has_rollback_ref(&request.payload)
            && audit
                .as_ref()
                .and_then(|metadata| metadata.rollback_ref.as_ref())
                .is_none()
        {
            return ServiceCommandDecision::denied(
                command,
                level,
                ServiceRejectionReason::MissingRollback,
                Some(spec),
                permission_check.clone(),
                self.degraded_state.clone(),
                audit,
            );
        }

        if spec.audit_required {
            let Some(audit_metadata) = audit.as_ref() else {
                return ServiceCommandDecision::denied(
                    command,
                    level,
                    ServiceRejectionReason::SensitiveCommandAuditMissing,
                    Some(spec),
                    permission_check.clone(),
                    self.degraded_state.clone(),
                    None,
                );
            };
            if let Err(reason) = audit_metadata.validate_for_request(request, spec) {
                return ServiceCommandDecision::denied(
                    command,
                    level,
                    reason,
                    Some(spec),
                    permission_check.clone(),
                    self.degraded_state.clone(),
                    audit,
                );
            }
        }

        ServiceCommandDecision::allowed(
            spec,
            permission_check.clone(),
            self.degraded_state.clone(),
            audit,
        )
    }
}

fn service_ipc_unavailable_permission() -> PermissionKey {
    PermissionKey::new("service.ipc.unavailable").expect("static permission key is valid")
}

fn is_privileged_command(command: &IpcCommand) -> bool {
    !matches!(
        command,
        IpcCommand::GetServiceStatus
            | IpcCommand::GetCaptureHealth
            | IpcCommand::ListInterfaces
            | IpcCommand::ListProcessSnapshot
            | IpcCommand::ListConnectionSnapshot
            | IpcCommand::ListFirewallRules
    )
}

fn is_capture_mutation_command(command: &IpcCommand) -> bool {
    matches!(
        command,
        IpcCommand::StartCapture
            | IpcCommand::StopCapture
            | IpcCommand::PauseCapture
            | IpcCommand::ResumeCapture
            | IpcCommand::UpdateCaptureFilter
    )
}

fn is_process_attribution_command(command: &IpcCommand) -> bool {
    matches!(command, IpcCommand::RefreshProcessInventory)
}

fn is_response_command(command: &IpcCommand) -> bool {
    matches!(
        command,
        IpcCommand::TemporaryBlockDestination
            | IpcCommand::TemporaryThrottleFlow
            | IpcCommand::RollbackFirewallRule
            | IpcCommand::RollbackQosPolicy
            | IpcCommand::FullHostIsolation
            | IpcCommand::SegmentIsolation
            | IpcCommand::PermanentFirewallDeny
            | IpcCommand::ProcessKill
            | IpcCommand::PrivilegedUserLockout
            | IpcCommand::WafApiEnforcement
    )
}

fn rejection_from_ipc_error(error: &IpcProtocolError) -> ServiceRejectionReason {
    match error.error_code {
        ErrorCode::SchemaMismatch => ServiceRejectionReason::InvalidSchema,
        ErrorCode::PrivacyPolicyViolation => ServiceRejectionReason::PrivacyViolation,
        ErrorCode::PermissionDenied => ServiceRejectionReason::UnauthenticatedClient,
        ErrorCode::UnsupportedOperation => ServiceRejectionReason::CommandNotInAllowlist,
        _ => ServiceRejectionReason::InvalidSchema,
    }
}

fn payload_has_positive_ttl(payload: &Value) -> bool {
    payload_u64(payload, "ttl_seconds").is_some_and(|ttl| ttl > 0)
        || payload_u64(payload, "ttl_ms").is_some_and(|ttl| ttl > 0)
}

fn payload_has_rollback_ref(payload: &Value) -> bool {
    payload_non_empty_string(payload, "rollback_ref")
        || payload_non_empty_string(payload, "rollback_id")
        || payload_non_empty_string(payload, "rollback_plan_ref")
}

fn target_scope_too_broad(payload: &Value) -> bool {
    if payload_bool(payload, "broad_target_scope") == Some(true) {
        return true;
    }
    let Some(scope) = payload_string(payload, "target_scope") else {
        return true;
    };
    let normalized = scope.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "global" | "broad" | "wildcard" | "any" | "all" | "0.0.0.0/0" | "::/0"
    )
}

fn payload_u64(payload: &Value, key: &str) -> Option<u64> {
    match payload {
        Value::Object(map) => map.get(key).and_then(Value::as_u64),
        _ => None,
    }
}

fn payload_bool(payload: &Value, key: &str) -> Option<bool> {
    match payload {
        Value::Object(map) => map.get(key).and_then(Value::as_bool),
        _ => None,
    }
}

fn payload_string<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    match payload {
        Value::Object(map) => map.get(key).and_then(Value::as_str),
        _ => None,
    }
}

fn payload_non_empty_string(payload: &Value, key: &str) -> bool {
    payload_string(payload, key).is_some_and(|value| !value.trim().is_empty())
}

pub fn degraded_state_from_attribution_confidence(
    confidence: AttributionConfidence,
) -> ServiceDegradedState {
    let mut state = ServiceDegradedState::healthy();
    if matches!(
        confidence,
        AttributionConfidence::Low | AttributionConfidence::Unknown
    ) {
        state.process_attribution_low_or_unknown = true;
        state.reduced_visibility = true;
        state
            .reason_codes
            .push(ServiceRejectionReason::ProcessAttributionLowOrUnknown);
        state.message_redacted =
            "Process attribution confidence is low or unknown; visibility is reduced".to_string();
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{stub_control_request, IpcAuthContext};
    use sentinel_contracts::PrivacyClass;
    use serde_json::json;

    fn l2_request() -> IpcRequestEnvelope {
        let spec = command_spec(&IpcCommand::TemporaryBlockDestination).expect("spec");
        IpcRequestEnvelope::new(
            crate::ipc::IpcCaller::local_core("local operator").expect("caller"),
            IpcCommand::TemporaryBlockDestination,
            spec.permission_scope,
            json!({
                "target_scope": "single_destination",
                "ttl_seconds": 600,
                "rollback_ref": "rollback_ref_1"
            }),
            PrivacyClass::Internal,
            IpcAuthContext::local_core_stub(),
        )
    }

    #[test]
    fn allowlist_separates_command_levels_and_disables_l3() {
        let allowlist = ServiceCommandAllowlist::v1_default().expect("allowlist");

        assert!(allowlist
            .commands_for_level(IpcCommandLevel::L0ReadOnly)
            .contains(&IpcCommand::GetServiceStatus));
        assert!(allowlist
            .commands_for_level(IpcCommandLevel::L1ControlledOperation)
            .contains(&IpcCommand::StartCapture));
        assert!(allowlist
            .commands_for_level(IpcCommandLevel::L2SensitiveResponse)
            .contains(&IpcCommand::TemporaryBlockDestination));
        assert!(allowlist
            .commands_for_level(IpcCommandLevel::L3NotV1ApprovalRequired)
            .contains(&IpcCommand::FullHostIsolation));

        assert_eq!(
            allowlist
                .enabled_spec_for(&IpcCommand::FullHostIsolation)
                .expect_err("l3 disabled"),
            ServiceRejectionReason::CommandNotInAllowlist
        );
    }

    #[test]
    fn precheck_rejects_missing_permission_policy_denial_and_bad_auth() {
        let precheck = PrivilegedCommandPrecheck::healthy_for_tests();
        let request = stub_control_request(IpcCommand::GetServiceStatus).expect("request");
        let spec = precheck.allowlist.spec_for(&request.command).expect("spec");
        let missing = ServicePermissionCheck::missing_for_spec(spec);

        let decision = precheck.evaluate_request(&request, &missing, None);
        assert!(!decision.allowed);
        assert_eq!(
            decision.rejection_reason,
            Some(ServiceRejectionReason::MissingPermission)
        );

        let l2 = l2_request();
        let l2_spec = precheck.allowlist.spec_for(&l2.command).expect("l2 spec");
        let denied = ServicePermissionCheck::denied_by_policy_for_spec(l2_spec);
        let audit = SensitiveCommandAudit::for_request(
            &l2,
            "single external destination",
            Some("rollback_ref_1".to_string()),
        );
        let decision = precheck.evaluate_request(&l2, &denied, Some(&audit));
        assert_eq!(
            decision.rejection_reason,
            Some(ServiceRejectionReason::PolicyDenied)
        );

        let mut missing_approval = ServicePermissionCheck::granted_for_spec(l2_spec);
        missing_approval.approval_granted = false;
        let decision = precheck.evaluate_request(&l2, &missing_approval, Some(&audit));
        assert_eq!(
            decision.rejection_reason,
            Some(ServiceRejectionReason::MissingApproval)
        );

        let mut bad_auth = request;
        bad_auth.auth_context.authenticated = false;
        let granted = ServicePermissionCheck::granted_for_spec(spec);
        let decision = precheck.evaluate_request(&bad_auth, &granted, None);
        assert_eq!(
            decision.rejection_reason,
            Some(ServiceRejectionReason::UnauthenticatedClient)
        );
    }

    #[test]
    fn l2_sensitive_commands_require_audit_ttl_rollback_and_limited_scope() {
        let precheck = PrivilegedCommandPrecheck::healthy_for_tests();
        let request = l2_request();
        let spec = precheck.allowlist.spec_for(&request.command).expect("spec");
        let permission = ServicePermissionCheck::granted_for_spec(spec);

        let decision = precheck.evaluate_request(&request, &permission, None);
        assert_eq!(
            decision.rejection_reason,
            Some(ServiceRejectionReason::SensitiveCommandAuditMissing)
        );

        let mut audit = SensitiveCommandAudit::for_request(
            &request,
            "single external destination",
            Some("rollback_ref_1".to_string()),
        );
        audit.trace_id = TraceId::new_v4();
        let decision = precheck.evaluate_request(&request, &permission, Some(&audit));
        assert_eq!(
            decision.rejection_reason,
            Some(ServiceRejectionReason::SensitiveCommandAuditMissing)
        );

        let mut audit = SensitiveCommandAudit::for_request(
            &request,
            "single external destination",
            Some("rollback_ref_1".to_string()),
        );
        audit.audit_sink_available = false;
        let decision = precheck.evaluate_request(&request, &permission, Some(&audit));
        assert_eq!(
            decision.rejection_reason,
            Some(ServiceRejectionReason::MissingAuditSink)
        );

        let mut no_ttl = request.clone();
        no_ttl.payload = json!({
            "target_scope": "single_destination",
            "rollback_ref": "rollback_ref_1"
        });
        let audit = SensitiveCommandAudit::for_request(
            &no_ttl,
            "single external destination",
            Some("rollback_ref_1".to_string()),
        );
        let decision = precheck.evaluate_request(&no_ttl, &permission, Some(&audit));
        assert_eq!(
            decision.rejection_reason,
            Some(ServiceRejectionReason::MissingTtl)
        );

        let mut no_rollback = request.clone();
        no_rollback.payload = json!({
            "target_scope": "single_destination",
            "ttl_seconds": 600
        });
        let audit =
            SensitiveCommandAudit::for_request(&no_rollback, "single external destination", None);
        let decision = precheck.evaluate_request(&no_rollback, &permission, Some(&audit));
        assert_eq!(
            decision.rejection_reason,
            Some(ServiceRejectionReason::MissingRollback)
        );

        let mut broad = request.clone();
        broad.payload = json!({
            "target_scope": "global",
            "ttl_seconds": 600,
            "rollback_ref": "rollback_ref_1"
        });
        let audit = SensitiveCommandAudit::for_request(
            &broad,
            "global destination scope",
            Some("rollback_ref_1".to_string()),
        );
        let decision = precheck.evaluate_request(&broad, &permission, Some(&audit));
        assert_eq!(
            decision.rejection_reason,
            Some(ServiceRejectionReason::BroadTargetScope)
        );

        let audit = SensitiveCommandAudit::for_request(
            &request,
            "single external destination",
            Some("rollback_ref_1".to_string()),
        );
        let decision = precheck.evaluate_request(&request, &permission, Some(&audit));
        assert!(decision.allowed);
        assert!(decision.audit_required);
        assert!(decision.ttl_required);
        assert!(decision.rollback_required);
    }

    #[test]
    fn sensitive_audit_metadata_is_request_bound_and_privacy_safe() {
        let precheck = PrivilegedCommandPrecheck::healthy_for_tests();
        let request = l2_request();
        let spec = precheck.allowlist.spec_for(&request.command).expect("spec");
        let permission = ServicePermissionCheck::granted_for_spec(spec);

        let mut wrong_actor = SensitiveCommandAudit::for_request(
            &request,
            "single external destination",
            Some("rollback_ref_1".to_string()),
        );
        wrong_actor.actor_redacted = "different local operator".to_string();
        let decision = precheck.evaluate_request(&request, &permission, Some(&wrong_actor));
        assert_eq!(
            decision.rejection_reason,
            Some(ServiceRejectionReason::SensitiveCommandAuditMissing)
        );

        let mut private_target = SensitiveCommandAudit::for_request(
            &request,
            "authorization_header target should never appear",
            Some("rollback_ref_1".to_string()),
        );
        assert_eq!(
            private_target
                .validate_for_request(&request, spec)
                .expect_err("private audit metadata rejected"),
            ServiceRejectionReason::PrivacyViolation
        );

        private_target.target_redacted = "single external destination".to_string();
        assert!(private_target.validate_for_request(&request, spec).is_ok());
    }

    #[test]
    fn degraded_state_disables_high_risk_commands_and_maps_service_health() {
        let capture_state = ServiceDegradedState::capture_unavailable();
        assert_eq!(
            capture_state.rejection_for_command(&IpcCommand::StartCapture),
            Some(ServiceRejectionReason::CaptureUnavailable)
        );

        let response_state = ServiceDegradedState::response_executor_disabled();
        assert_eq!(
            response_state.rejection_for_command(&IpcCommand::TemporaryThrottleFlow),
            Some(ServiceRejectionReason::ResponseExecutorDisabled)
        );

        let config = crate::ServiceStartupConfig::stub_only_local();
        let snapshot =
            ServiceHealthSnapshot::stub_only(&config, ServiceStatus::Stopped).expect("snapshot");
        let mapped = ServiceHealthMapper::map(&snapshot, &ServiceDegradedState::stub_only());

        assert_eq!(
            mapped.elevated_service_status,
            ObservabilityHealthStatus::Unavailable
        );
        assert_eq!(
            mapped.response_executor_status,
            ObservabilityHealthStatus::Unavailable
        );
        assert!(mapped.reduced_visibility);
        assert!(!mapped.privileged_actions_available);
        assert!(!mapped.capture_available);
    }

    #[test]
    fn sensitive_audit_metadata_builds_platform_audit_event() {
        let request = l2_request();
        let audit = SensitiveCommandAudit::for_request(
            &request,
            "single external destination",
            Some("rollback_ref_1".to_string()),
        );
        let event = audit
            .to_audit_event("service command denied before adapter execution")
            .expect("audit event");

        assert_eq!(event.category, AuditCategory::Service);
        assert_eq!(event.action_type, AuditActionType::ServiceCommandRequested);
        assert_eq!(event.trace_id, Some(request.trace_id));
        assert_eq!(event.rollback_ref, Some("rollback_ref_1".to_string()));
        assert!(event.validate().is_ok());
    }

    #[test]
    fn attribution_low_or_unknown_sets_reduced_visibility_flag() {
        let state = degraded_state_from_attribution_confidence(AttributionConfidence::Unknown);

        assert!(state.process_attribution_low_or_unknown);
        assert!(state.reduced_visibility);
        assert!(state
            .reason_codes
            .contains(&ServiceRejectionReason::ProcessAttributionLowOrUnknown));
    }

    #[test]
    fn safe_service_capability_contexts_stay_bounded_and_stub_honest() {
        let contexts =
            safe_service_capability_contexts(&ServiceDegradedState::stub_only(), Timestamp::now())
                .expect("contexts");

        assert_eq!(contexts.len(), 4);
        assert!(contexts
            .iter()
            .all(|context| context.validate_boundary().is_ok()));
        assert!(contexts
            .iter()
            .all(|context| !matches!(context.status, ServiceCapabilityStatus::Available)));
        assert!(contexts.iter().any(|context| {
            context.capability_id == "capture_adapter"
                && context.reason_code == Some(ServiceReasonCode::CaptureUnavailable)
        }));
        assert!(contexts.iter().all(|context| {
            context
                .limitation_flags
                .contains(&ServiceLimitationFlag::NoProductionServiceLifecycle)
        }));
    }
}
