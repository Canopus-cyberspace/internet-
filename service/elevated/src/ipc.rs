//! STUB_ONLY Named Pipe IPC protocol contracts.
//!
//! NOT_FOR_PRODUCTION: this module defines local authenticated IPC schemas,
//! command metadata, and client/server/channel traits only. It does not bind a
//! named pipe, accept remote clients, stream private content, or execute
//! privileged OS actions.

use crate::security::PrivilegedCommandPrecheck;
use crate::{validate_safe_text, NOT_FOR_PRODUCTION_LABEL, SERVICE_STUB_NAME, STUB_ONLY_LABEL};
use sentinel_contracts::{
    AuditId, ErrorCode, PermissionCategory, PermissionDescriptor, PermissionKey,
    PermissionRiskLevel, PrivacyClass, ResponseActionType, SchemaVersion, Timestamp, TraceId,
};
use sentinel_platform::permissions::{PermissionScope, PermissionSubject};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;
use uuid::Uuid;

pub const IPC_PROTOCOL_NAME: &str = "sentinel_guard_named_pipe_ipc";
pub const IPC_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const DEFAULT_CONTROL_TIMEOUT_MS: u64 = 2_000;
pub const DEFAULT_EVENT_TIMEOUT_MS: u64 = 1_000;
pub const DEFAULT_BULK_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_BULK_MAX_BYTES: usize = 64 * 1024;
pub const DEFAULT_RATE_LIMIT_WINDOW_MS: u64 = 1_000;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IpcRequestId(Uuid);

impl IpcRequestId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for IpcRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcCommandLevel {
    L0ReadOnly,
    L1ControlledOperation,
    L2SensitiveResponse,
    L3NotV1ApprovalRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcCommand {
    GetServiceStatus,
    GetCaptureHealth,
    ListInterfaces,
    ListProcessSnapshot,
    ListConnectionSnapshot,
    ListFirewallRules,
    StartCapture,
    StopCapture,
    PauseCapture,
    ResumeCapture,
    UpdateCaptureFilter,
    RefreshProcessInventory,
    TemporaryBlockDestination,
    TemporaryThrottleFlow,
    RollbackFirewallRule,
    RollbackQosPolicy,
    FullHostIsolation,
    SegmentIsolation,
    PermanentFirewallDeny,
    ProcessKill,
    PrivilegedUserLockout,
    WafApiEnforcement,
}

impl IpcCommand {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GetServiceStatus => "get_service_status",
            Self::GetCaptureHealth => "get_capture_health",
            Self::ListInterfaces => "list_interfaces",
            Self::ListProcessSnapshot => "list_process_snapshot",
            Self::ListConnectionSnapshot => "list_connection_snapshot",
            Self::ListFirewallRules => "list_firewall_rules",
            Self::StartCapture => "start_capture",
            Self::StopCapture => "stop_capture",
            Self::PauseCapture => "pause_capture",
            Self::ResumeCapture => "resume_capture",
            Self::UpdateCaptureFilter => "update_capture_filter",
            Self::RefreshProcessInventory => "refresh_process_inventory",
            Self::TemporaryBlockDestination => "temporary_block_destination",
            Self::TemporaryThrottleFlow => "temporary_throttle_flow",
            Self::RollbackFirewallRule => "rollback_firewall_rule",
            Self::RollbackQosPolicy => "rollback_qos_policy",
            Self::FullHostIsolation => "full_host_isolation",
            Self::SegmentIsolation => "segment_isolation",
            Self::PermanentFirewallDeny => "permanent_firewall_deny",
            Self::ProcessKill => "process_kill",
            Self::PrivilegedUserLockout => "privileged_user_lockout",
            Self::WafApiEnforcement => "waf_api_enforcement",
        }
    }

    pub fn level(&self) -> IpcCommandLevel {
        match self {
            Self::GetServiceStatus
            | Self::GetCaptureHealth
            | Self::ListInterfaces
            | Self::ListProcessSnapshot
            | Self::ListConnectionSnapshot
            | Self::ListFirewallRules => IpcCommandLevel::L0ReadOnly,
            Self::StartCapture
            | Self::StopCapture
            | Self::PauseCapture
            | Self::ResumeCapture
            | Self::UpdateCaptureFilter
            | Self::RefreshProcessInventory => IpcCommandLevel::L1ControlledOperation,
            Self::TemporaryBlockDestination
            | Self::TemporaryThrottleFlow
            | Self::RollbackFirewallRule
            | Self::RollbackQosPolicy => IpcCommandLevel::L2SensitiveResponse,
            Self::FullHostIsolation
            | Self::SegmentIsolation
            | Self::PermanentFirewallDeny
            | Self::ProcessKill
            | Self::PrivilegedUserLockout
            | Self::WafApiEnforcement => IpcCommandLevel::L3NotV1ApprovalRequired,
        }
    }

    pub fn is_v1_allowed(&self) -> bool {
        !matches!(self.level(), IpcCommandLevel::L3NotV1ApprovalRequired)
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::GetServiceStatus,
            Self::GetCaptureHealth,
            Self::ListInterfaces,
            Self::ListProcessSnapshot,
            Self::ListConnectionSnapshot,
            Self::ListFirewallRules,
            Self::StartCapture,
            Self::StopCapture,
            Self::PauseCapture,
            Self::ResumeCapture,
            Self::UpdateCaptureFilter,
            Self::RefreshProcessInventory,
            Self::TemporaryBlockDestination,
            Self::TemporaryThrottleFlow,
            Self::RollbackFirewallRule,
            Self::RollbackQosPolicy,
            Self::FullHostIsolation,
            Self::SegmentIsolation,
            Self::PermanentFirewallDeny,
            Self::ProcessKill,
            Self::PrivilegedUserLockout,
            Self::WafApiEnforcement,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcTimeout {
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub idle_timeout_ms: u64,
}

impl IpcTimeout {
    pub fn control_default() -> Self {
        Self {
            connect_timeout_ms: 500,
            request_timeout_ms: DEFAULT_CONTROL_TIMEOUT_MS,
            idle_timeout_ms: 10_000,
        }
    }

    pub fn event_default() -> Self {
        Self {
            connect_timeout_ms: 500,
            request_timeout_ms: DEFAULT_EVENT_TIMEOUT_MS,
            idle_timeout_ms: 30_000,
        }
    }

    pub fn bulk_default() -> Self {
        Self {
            connect_timeout_ms: 500,
            request_timeout_ms: DEFAULT_BULK_TIMEOUT_MS,
            idle_timeout_ms: 5_000,
        }
    }

    pub fn validate(&self) -> Result<(), IpcProtocolError> {
        if self.connect_timeout_ms == 0 || self.request_timeout_ms == 0 {
            return Err(IpcProtocolError::invalid(
                "timeout",
                "IPC timeouts must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcRateLimit {
    pub max_requests: u32,
    pub window_ms: u64,
    pub burst: u32,
}

impl IpcRateLimit {
    pub fn for_level(level: &IpcCommandLevel) -> Self {
        match level {
            IpcCommandLevel::L0ReadOnly => Self {
                max_requests: 120,
                window_ms: DEFAULT_RATE_LIMIT_WINDOW_MS,
                burst: 20,
            },
            IpcCommandLevel::L1ControlledOperation => Self {
                max_requests: 20,
                window_ms: DEFAULT_RATE_LIMIT_WINDOW_MS,
                burst: 5,
            },
            IpcCommandLevel::L2SensitiveResponse => Self {
                max_requests: 6,
                window_ms: DEFAULT_RATE_LIMIT_WINDOW_MS,
                burst: 2,
            },
            IpcCommandLevel::L3NotV1ApprovalRequired => Self {
                max_requests: 0,
                window_ms: DEFAULT_RATE_LIMIT_WINDOW_MS,
                burst: 0,
            },
        }
    }

    pub fn validate(&self, command_level: &IpcCommandLevel) -> Result<(), IpcProtocolError> {
        if matches!(command_level, IpcCommandLevel::L3NotV1ApprovalRequired) {
            return Ok(());
        }
        if self.max_requests == 0 || self.window_ms == 0 {
            return Err(IpcProtocolError::invalid(
                "rate_limit",
                "V1 IPC commands require positive rate limits",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcChannelKind {
    Control,
    Event,
    Bulk,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcTransportKind {
    NamedPipe,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcEndpointConfig {
    pub protocol_name: String,
    pub transport: IpcTransportKind,
    pub channel: IpcChannelKind,
    pub pipe_name_redacted: String,
    pub local_machine_only: bool,
    pub remote_bind_enabled: bool,
    pub unauthenticated_tcp_enabled: bool,
    pub require_authenticated_client: bool,
    pub timeout: IpcTimeout,
    pub default_rate_limit: IpcRateLimit,
    pub max_bulk_bytes: usize,
    pub labels: Vec<String>,
}

impl IpcEndpointConfig {
    pub fn named_pipe_stub(channel: IpcChannelKind) -> Self {
        let timeout = match channel {
            IpcChannelKind::Control => IpcTimeout::control_default(),
            IpcChannelKind::Event => IpcTimeout::event_default(),
            IpcChannelKind::Bulk => IpcTimeout::bulk_default(),
        };
        Self {
            protocol_name: IPC_PROTOCOL_NAME.to_string(),
            transport: IpcTransportKind::NamedPipe,
            channel: channel.clone(),
            pipe_name_redacted: format!(r"\\.\pipe\{SERVICE_STUB_NAME}"),
            local_machine_only: true,
            remote_bind_enabled: false,
            unauthenticated_tcp_enabled: false,
            require_authenticated_client: true,
            timeout,
            default_rate_limit: IpcRateLimit::for_level(&IpcCommandLevel::L0ReadOnly),
            max_bulk_bytes: if matches!(channel, IpcChannelKind::Bulk) {
                DEFAULT_BULK_MAX_BYTES
            } else {
                0
            },
            labels: vec![
                STUB_ONLY_LABEL.to_string(),
                NOT_FOR_PRODUCTION_LABEL.to_string(),
            ],
        }
    }

    pub fn validate(&self) -> Result<(), IpcProtocolError> {
        validate_ipc_text("protocol_name", &self.protocol_name)?;
        validate_ipc_text("pipe_name_redacted", &self.pipe_name_redacted)?;
        if self.protocol_name != IPC_PROTOCOL_NAME {
            return Err(IpcProtocolError::invalid(
                "protocol_name",
                "IPC endpoint protocol name is unsupported",
            ));
        }
        if !matches!(self.transport, IpcTransportKind::NamedPipe) {
            return Err(IpcProtocolError::invalid(
                "transport",
                "Windows V1 IPC endpoint must use a local Named Pipe transport",
            ));
        }
        if self.pipe_name_redacted.trim().is_empty() {
            return Err(IpcProtocolError::invalid(
                "pipe_name_redacted",
                "IPC Named Pipe endpoint must be identified with redacted metadata",
            ));
        }
        if !self.local_machine_only || self.remote_bind_enabled {
            return Err(IpcProtocolError::permission_denied(
                "IPC endpoint must not bind for remote clients",
            ));
        }
        if self.unauthenticated_tcp_enabled {
            return Err(IpcProtocolError::permission_denied(
                "IPC endpoint must not expose unauthenticated TCP",
            ));
        }
        if !self.require_authenticated_client {
            return Err(IpcProtocolError::permission_denied(
                "IPC endpoint requires authenticated Local Core clients",
            ));
        }
        self.timeout.validate()?;
        self.default_rate_limit
            .validate(&IpcCommandLevel::L0ReadOnly)?;
        if matches!(self.channel, IpcChannelKind::Bulk) {
            if self.max_bulk_bytes == 0 || self.max_bulk_bytes > DEFAULT_BULK_MAX_BYTES {
                return Err(IpcProtocolError::invalid(
                    "max_bulk_bytes",
                    "bulk IPC endpoint must stay within the bounded transfer limit",
                ));
            }
        } else if self.max_bulk_bytes != 0 {
            return Err(IpcProtocolError::invalid(
                "max_bulk_bytes",
                "non-bulk IPC endpoints must not declare a bulk byte window",
            ));
        }
        require_ipc_label(&self.labels, STUB_ONLY_LABEL)?;
        require_ipc_label(&self.labels, NOT_FOR_PRODUCTION_LABEL)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcAuthMethod {
    WindowsLocalProcessToken,
    NamedPipeClientImpersonation,
    StubOnly,
    Unauthenticated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcAuthContext {
    pub caller_process_redacted: String,
    pub caller_sid_redacted: Option<String>,
    pub local_machine_only: bool,
    pub authenticated: bool,
    pub auth_method: IpcAuthMethod,
    pub remote_endpoint_redacted: Option<String>,
    pub authorized_by_local_core: bool,
    pub labels: Vec<String>,
}

impl IpcAuthContext {
    pub fn local_core_stub() -> Self {
        Self {
            caller_process_redacted: "sentinel-local-core".to_string(),
            caller_sid_redacted: None,
            local_machine_only: true,
            authenticated: true,
            auth_method: IpcAuthMethod::StubOnly,
            remote_endpoint_redacted: None,
            authorized_by_local_core: true,
            labels: vec![
                STUB_ONLY_LABEL.to_string(),
                NOT_FOR_PRODUCTION_LABEL.to_string(),
            ],
        }
    }

    pub fn validate(&self) -> Result<(), IpcProtocolError> {
        validate_ipc_text("caller_process_redacted", &self.caller_process_redacted)?;
        if let Some(sid) = &self.caller_sid_redacted {
            validate_ipc_text("caller_sid_redacted", sid)?;
        }
        if let Some(endpoint) = &self.remote_endpoint_redacted {
            validate_ipc_text("remote_endpoint_redacted", endpoint)?;
        }
        if !self.local_machine_only || self.remote_endpoint_redacted.is_some() {
            return Err(IpcProtocolError::permission_denied(
                "IPC permits local named-pipe clients only",
            ));
        }
        if !self.authenticated || matches!(self.auth_method, IpcAuthMethod::Unauthenticated) {
            return Err(IpcProtocolError::permission_denied(
                "IPC client is not authenticated",
            ));
        }
        if !self.authorized_by_local_core {
            return Err(IpcProtocolError::permission_denied(
                "Local Core authorization hook was not satisfied",
            ));
        }
        require_ipc_label(&self.labels, STUB_ONLY_LABEL)?;
        require_ipc_label(&self.labels, NOT_FOR_PRODUCTION_LABEL)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcCaller {
    pub subject: PermissionSubject,
    pub actor_redacted: String,
    pub local_core_instance_redacted: String,
}

impl IpcCaller {
    pub fn local_core(actor_redacted: impl Into<String>) -> Result<Self, IpcProtocolError> {
        let actor_redacted = actor_redacted.into();
        validate_ipc_text("actor_redacted", &actor_redacted)?;
        Ok(Self {
            subject: PermissionSubject::LocalCore,
            actor_redacted,
            local_core_instance_redacted: "local-core".to_string(),
        })
    }

    pub fn validate(&self) -> Result<(), IpcProtocolError> {
        validate_ipc_text("actor_redacted", &self.actor_redacted)?;
        validate_ipc_text(
            "local_core_instance_redacted",
            &self.local_core_instance_redacted,
        )?;
        if !matches!(self.subject, PermissionSubject::LocalCore) {
            return Err(IpcProtocolError::permission_denied(
                "service IPC caller must be Rust Local Core",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IpcCommandSpec {
    pub command: IpcCommand,
    pub level: IpcCommandLevel,
    pub channel: IpcChannelKind,
    pub permission: PermissionKey,
    pub permission_scope: PermissionScope,
    pub timeout: IpcTimeout,
    pub rate_limit: IpcRateLimit,
    pub audit_required: bool,
    pub approval_required: bool,
    pub rollback_required: bool,
    pub ttl_required: bool,
    pub enabled_in_v1: bool,
    pub stub_only: bool,
    pub not_for_production: bool,
    pub description_redacted: String,
}

impl IpcCommandSpec {
    pub fn validate(&self) -> Result<(), IpcProtocolError> {
        if self.level != self.command.level() {
            return Err(IpcProtocolError::invalid(
                "command_level",
                "command metadata level does not match command",
            ));
        }
        if self.enabled_in_v1 != self.command.is_v1_allowed() {
            return Err(IpcProtocolError::invalid(
                "enabled_in_v1",
                "command V1 enablement does not match its level",
            ));
        }
        if matches!(self.level, IpcCommandLevel::L2SensitiveResponse)
            && (!self.audit_required
                || !self.approval_required
                || !self.rollback_required
                || !self.ttl_required)
        {
            return Err(IpcProtocolError::invalid(
                "sensitive_response_metadata",
                "L2 response commands require audit, approval, rollback, and TTL",
            ));
        }
        if matches!(self.level, IpcCommandLevel::L3NotV1ApprovalRequired) && self.enabled_in_v1 {
            return Err(IpcProtocolError::invalid(
                "l3_enabled",
                "L3 commands are not supported in V1",
            ));
        }
        self.timeout.validate()?;
        self.rate_limit.validate(&self.level)?;
        validate_ipc_text("description_redacted", &self.description_redacted)?;
        Ok(())
    }

    pub fn descriptor(&self) -> Result<PermissionDescriptor, IpcProtocolError> {
        PermissionDescriptor::new(
            self.permission.clone(),
            permission_category_for_scope(&self.permission_scope),
            permission_risk_for_level(&self.level),
            self.description_redacted.clone(),
        )
        .map_err(|error| IpcProtocolError::invalid("permission_descriptor", error.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IpcRequestEnvelope {
    pub request_id: IpcRequestId,
    pub trace_id: TraceId,
    pub caller: IpcCaller,
    pub command: IpcCommand,
    pub schema_version: SchemaVersion,
    pub timestamp: Timestamp,
    pub permission_scope: PermissionScope,
    pub payload: Value,
    pub privacy_level: PrivacyClass,
    pub auth_context: IpcAuthContext,
    pub timeout: IpcTimeout,
    pub rate_limit: IpcRateLimit,
    pub channel: IpcChannelKind,
    pub transport: IpcTransportKind,
}

impl IpcRequestEnvelope {
    pub fn new(
        caller: IpcCaller,
        command: IpcCommand,
        permission_scope: PermissionScope,
        payload: Value,
        privacy_level: PrivacyClass,
        auth_context: IpcAuthContext,
    ) -> Self {
        let level = command.level();
        Self {
            request_id: IpcRequestId::new_v4(),
            trace_id: TraceId::new_v4(),
            caller,
            command,
            schema_version: IPC_SCHEMA_VERSION,
            timestamp: Timestamp::now(),
            permission_scope,
            payload,
            privacy_level,
            auth_context,
            timeout: timeout_for_command_level(&level),
            rate_limit: IpcRateLimit::for_level(&level),
            channel: IpcChannelKind::Control,
            transport: IpcTransportKind::NamedPipe,
        }
    }

    pub fn validate(&self) -> Result<(), IpcProtocolError> {
        if self.schema_version != IPC_SCHEMA_VERSION {
            return Err(IpcProtocolError::schema_mismatch(
                "IPC request schema version is unsupported",
            ));
        }
        self.caller.validate()?;
        self.auth_context.validate()?;
        self.timeout.validate()?;
        self.rate_limit.validate(&self.command.level())?;
        validate_payload(&self.payload)?;

        let spec = command_spec(&self.command)?;
        if !spec.enabled_in_v1 {
            return Err(IpcProtocolError::unsupported(
                "command is not supported in V1",
            ));
        }
        if self.channel != spec.channel {
            return Err(IpcProtocolError::invalid(
                "channel",
                "IPC request channel does not match command metadata",
            ));
        }
        if !matches!(self.transport, IpcTransportKind::NamedPipe) {
            return Err(IpcProtocolError::invalid(
                "transport",
                "IPC request must use the Windows V1 Named Pipe transport",
            ));
        }
        if self.timeout != spec.timeout {
            return Err(IpcProtocolError::invalid(
                "timeout",
                "IPC request timeout must match command allowlist metadata",
            ));
        }
        if self.rate_limit != spec.rate_limit {
            return Err(IpcProtocolError::invalid(
                "rate_limit",
                "IPC request rate limit must match command allowlist metadata",
            ));
        }
        if spec.permission_scope.domain() != self.permission_scope.domain() {
            return Err(IpcProtocolError::permission_denied(
                "IPC request permission scope does not match command domain",
            ));
        }
        if matches!(
            self.privacy_level,
            PrivacyClass::Secret | PrivacyClass::Redacted | PrivacyClass::Tokenized
        ) {
            return Err(IpcProtocolError::privacy_violation(
                "IPC request payload must carry metadata, not private content",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IpcResponseEnvelope {
    pub request_id: IpcRequestId,
    pub trace_id: TraceId,
    pub success: bool,
    pub error_code: Option<ErrorCode>,
    pub error_message_redacted: Option<String>,
    pub result: Option<Value>,
    pub audit_ref: Option<AuditId>,
    pub latency_ms: u64,
    pub schema_version: SchemaVersion,
    pub timestamp: Timestamp,
}

impl IpcResponseEnvelope {
    pub fn ok(request: &IpcRequestEnvelope, result: Value, latency_ms: u64) -> Self {
        Self {
            request_id: request.request_id.clone(),
            trace_id: request.trace_id.clone(),
            success: true,
            error_code: None,
            error_message_redacted: None,
            result: Some(result),
            audit_ref: None,
            latency_ms,
            schema_version: IPC_SCHEMA_VERSION,
            timestamp: Timestamp::now(),
        }
    }

    pub fn error(
        request_id: IpcRequestId,
        trace_id: TraceId,
        error: IpcProtocolError,
        latency_ms: u64,
    ) -> Self {
        Self {
            request_id,
            trace_id,
            success: false,
            error_code: Some(error.error_code),
            error_message_redacted: Some(error.message_redacted),
            result: None,
            audit_ref: error.audit_ref,
            latency_ms,
            schema_version: IPC_SCHEMA_VERSION,
            timestamp: Timestamp::now(),
        }
    }

    pub fn validate(&self) -> Result<(), IpcProtocolError> {
        if self.schema_version != IPC_SCHEMA_VERSION {
            return Err(IpcProtocolError::schema_mismatch(
                "IPC response schema version is unsupported",
            ));
        }
        if self.success {
            if self.error_code.is_some() || self.error_message_redacted.is_some() {
                return Err(IpcProtocolError::invalid(
                    "response",
                    "successful IPC response must not carry an error",
                ));
            }
            if let Some(result) = &self.result {
                validate_payload(result)?;
            }
        } else if self.error_code.is_none() || self.error_message_redacted.is_none() {
            return Err(IpcProtocolError::invalid(
                "response",
                "failed IPC response requires structured error fields",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceEventEnvelope {
    pub event_id: IpcRequestId,
    pub trace_id: TraceId,
    pub event_type: String,
    pub channel: IpcChannelKind,
    pub transport: IpcTransportKind,
    pub payload: Value,
    pub privacy_level: PrivacyClass,
    pub timestamp: Timestamp,
    pub schema_version: SchemaVersion,
}

impl ServiceEventEnvelope {
    pub fn new(event_type: impl Into<String>, payload: Value) -> Result<Self, IpcProtocolError> {
        let event_type = event_type.into();
        validate_ipc_text("event_type", &event_type)?;
        validate_payload(&payload)?;
        Ok(Self {
            event_id: IpcRequestId::new_v4(),
            trace_id: TraceId::new_v4(),
            event_type,
            channel: IpcChannelKind::Event,
            transport: IpcTransportKind::NamedPipe,
            payload,
            privacy_level: PrivacyClass::Internal,
            timestamp: Timestamp::now(),
            schema_version: IPC_SCHEMA_VERSION,
        })
    }

    pub fn validate(&self) -> Result<(), IpcProtocolError> {
        if self.schema_version != IPC_SCHEMA_VERSION {
            return Err(IpcProtocolError::schema_mismatch(
                "service event schema version is unsupported",
            ));
        }
        validate_ipc_text("event_type", &self.event_type)?;
        validate_payload(&self.payload)?;
        if !matches!(self.channel, IpcChannelKind::Event) {
            return Err(IpcProtocolError::invalid(
                "channel",
                "service events must use the event channel",
            ));
        }
        if !matches!(self.transport, IpcTransportKind::NamedPipe) {
            return Err(IpcProtocolError::invalid(
                "transport",
                "service events must use the Windows V1 Named Pipe transport",
            ));
        }
        if matches!(
            self.privacy_level,
            PrivacyClass::Secret | PrivacyClass::Redacted | PrivacyClass::Tokenized
        ) {
            return Err(IpcProtocolError::privacy_violation(
                "service events must carry metadata, not private content",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BulkTransferRequest {
    pub batch_id: IpcRequestId,
    pub trace_id: TraceId,
    pub command: IpcCommand,
    pub channel: IpcChannelKind,
    pub transport: IpcTransportKind,
    pub items: Vec<Value>,
    pub max_bytes: usize,
    pub raw_streaming_enabled: bool,
    pub privacy_level: PrivacyClass,
    pub timeout: IpcTimeout,
    pub schema_version: SchemaVersion,
}

impl BulkTransferRequest {
    pub fn bounded(command: IpcCommand, items: Vec<Value>) -> Self {
        Self {
            batch_id: IpcRequestId::new_v4(),
            trace_id: TraceId::new_v4(),
            command,
            channel: IpcChannelKind::Bulk,
            transport: IpcTransportKind::NamedPipe,
            items,
            max_bytes: DEFAULT_BULK_MAX_BYTES,
            raw_streaming_enabled: false,
            privacy_level: PrivacyClass::Internal,
            timeout: IpcTimeout::bulk_default(),
            schema_version: IPC_SCHEMA_VERSION,
        }
    }

    pub fn validate(&self) -> Result<(), IpcProtocolError> {
        if self.schema_version != IPC_SCHEMA_VERSION {
            return Err(IpcProtocolError::schema_mismatch(
                "bulk transfer schema version is unsupported",
            ));
        }
        if !matches!(self.channel, IpcChannelKind::Bulk) {
            return Err(IpcProtocolError::invalid(
                "channel",
                "bulk transfer requests must use the bulk channel",
            ));
        }
        if !matches!(self.transport, IpcTransportKind::NamedPipe) {
            return Err(IpcProtocolError::invalid(
                "transport",
                "bulk transfer requests must use the Windows V1 Named Pipe transport",
            ));
        }
        if self.raw_streaming_enabled {
            return Err(IpcProtocolError::privacy_violation(
                "bulk IPC must not stream raw content by default",
            ));
        }
        if matches!(
            self.privacy_level,
            PrivacyClass::Secret | PrivacyClass::Redacted | PrivacyClass::Tokenized
        ) {
            return Err(IpcProtocolError::privacy_violation(
                "bulk IPC must carry metadata batches, not private content",
            ));
        }
        let spec = command_spec(&self.command)?;
        if !spec.enabled_in_v1 {
            return Err(IpcProtocolError::unsupported(
                "bulk IPC command is not supported in V1",
            ));
        }
        if !matches!(spec.level, IpcCommandLevel::L0ReadOnly) {
            return Err(IpcProtocolError::invalid(
                "command",
                "bulk IPC is limited to read-only metadata commands",
            ));
        }
        if self.max_bytes == 0 || self.max_bytes > DEFAULT_BULK_MAX_BYTES {
            return Err(IpcProtocolError::invalid(
                "max_bytes",
                "bulk IPC must stay within the bounded transfer limit",
            ));
        }
        self.timeout.validate()?;
        for item in &self.items {
            validate_payload(item)?;
        }
        let serialized = serde_json::to_vec(&self.items).map_err(|error| {
            IpcProtocolError::invalid("items", format!("bulk item serialization failed: {error}"))
        })?;
        if serialized.len() > self.max_bytes {
            return Err(IpcProtocolError::rate_limited(
                "bulk IPC batch exceeds configured byte bound",
            ));
        }
        Ok(())
    }
}

pub trait IpcClient {
    fn endpoint(&self) -> &IpcEndpointConfig;
    fn auth_context(&self) -> &IpcAuthContext;
    fn send_control(
        &mut self,
        request: IpcRequestEnvelope,
    ) -> Result<IpcResponseEnvelope, IpcProtocolError>;
}

pub trait IpcServer {
    fn endpoint(&self) -> &IpcEndpointConfig;
    fn authenticate(&self, auth_context: &IpcAuthContext) -> Result<(), IpcProtocolError>;
    fn handle_control(
        &mut self,
        request: IpcRequestEnvelope,
    ) -> Result<IpcResponseEnvelope, IpcProtocolError>;
}

pub trait ControlChannel {
    fn endpoint(&self) -> &IpcEndpointConfig;
    fn send_request(
        &mut self,
        request: IpcRequestEnvelope,
    ) -> Result<IpcResponseEnvelope, IpcProtocolError>;
}

pub trait ServiceEventChannel {
    fn endpoint(&self) -> &IpcEndpointConfig;
    fn publish_event(&mut self, event: ServiceEventEnvelope) -> Result<(), IpcProtocolError>;
    fn poll_event(&mut self) -> Result<Option<ServiceEventEnvelope>, IpcProtocolError>;
}

pub trait BulkChannel {
    fn endpoint(&self) -> &IpcEndpointConfig;
    fn send_bulk(&mut self, request: BulkTransferRequest) -> Result<(), IpcProtocolError>;
    fn max_batch_bytes(&self) -> usize;
}

#[derive(Clone, Debug)]
pub struct StubOnlyIpcServer {
    pub endpoint: IpcEndpointConfig,
    pub auth_context: IpcAuthContext,
    pub precheck: PrivilegedCommandPrecheck,
}

impl StubOnlyIpcServer {
    pub fn new(auth_context: IpcAuthContext) -> Self {
        Self {
            endpoint: IpcEndpointConfig::named_pipe_stub(IpcChannelKind::Control),
            auth_context,
            precheck: PrivilegedCommandPrecheck::stub_only(),
        }
    }

    pub fn with_precheck(
        auth_context: IpcAuthContext,
        precheck: PrivilegedCommandPrecheck,
    ) -> Self {
        Self {
            endpoint: IpcEndpointConfig::named_pipe_stub(IpcChannelKind::Control),
            auth_context,
            precheck,
        }
    }
}

impl IpcServer for StubOnlyIpcServer {
    fn endpoint(&self) -> &IpcEndpointConfig {
        &self.endpoint
    }

    fn authenticate(&self, auth_context: &IpcAuthContext) -> Result<(), IpcProtocolError> {
        self.endpoint.validate()?;
        self.auth_context.validate()?;
        auth_context.validate()
    }

    fn handle_control(
        &mut self,
        request: IpcRequestEnvelope,
    ) -> Result<IpcResponseEnvelope, IpcProtocolError> {
        self.authenticate(&request.auth_context)?;
        let permission_check = self
            .precheck
            .trusted_local_core_permission_check(&request.command);
        let decision = self
            .precheck
            .evaluate_request(&request, &permission_check, None);
        if !decision.allowed {
            return Ok(IpcResponseEnvelope::error(
                request.request_id.clone(),
                request.trace_id.clone(),
                decision.to_ipc_error(),
                0,
            ));
        }
        request.validate()?;
        Ok(IpcResponseEnvelope::error(
            request.request_id,
            request.trace_id,
            IpcProtocolError::unsupported(
                "STUB_ONLY IPC server validates protocol but does not execute OS actions",
            ),
            0,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct StubOnlyIpcClient<S: IpcServer> {
    pub endpoint: IpcEndpointConfig,
    pub auth_context: IpcAuthContext,
    pub server: S,
}

impl<S: IpcServer> StubOnlyIpcClient<S> {
    pub fn new(auth_context: IpcAuthContext, server: S) -> Self {
        Self {
            endpoint: IpcEndpointConfig::named_pipe_stub(IpcChannelKind::Control),
            auth_context,
            server,
        }
    }
}

impl<S: IpcServer> IpcClient for StubOnlyIpcClient<S> {
    fn endpoint(&self) -> &IpcEndpointConfig {
        &self.endpoint
    }

    fn auth_context(&self) -> &IpcAuthContext {
        &self.auth_context
    }

    fn send_control(
        &mut self,
        mut request: IpcRequestEnvelope,
    ) -> Result<IpcResponseEnvelope, IpcProtocolError> {
        self.endpoint.validate()?;
        self.server.endpoint().validate()?;
        self.auth_context.validate()?;
        request.auth_context = self.auth_context.clone();
        request.transport = self.endpoint.transport.clone();
        request.validate()?;
        self.server.handle_control(request)
    }
}

impl<S: IpcServer> ControlChannel for StubOnlyIpcClient<S> {
    fn endpoint(&self) -> &IpcEndpointConfig {
        &self.endpoint
    }

    fn send_request(
        &mut self,
        request: IpcRequestEnvelope,
    ) -> Result<IpcResponseEnvelope, IpcProtocolError> {
        self.send_control(request)
    }
}

#[derive(Clone, Debug)]
pub struct StubOnlyEventChannel {
    endpoint: IpcEndpointConfig,
    events: Vec<ServiceEventEnvelope>,
}

impl Default for StubOnlyEventChannel {
    fn default() -> Self {
        Self {
            endpoint: IpcEndpointConfig::named_pipe_stub(IpcChannelKind::Event),
            events: Vec::new(),
        }
    }
}

impl ServiceEventChannel for StubOnlyEventChannel {
    fn endpoint(&self) -> &IpcEndpointConfig {
        &self.endpoint
    }

    fn publish_event(&mut self, event: ServiceEventEnvelope) -> Result<(), IpcProtocolError> {
        self.endpoint.validate()?;
        event.validate()?;
        self.events.push(event);
        Ok(())
    }

    fn poll_event(&mut self) -> Result<Option<ServiceEventEnvelope>, IpcProtocolError> {
        Ok(self.events.pop())
    }
}

#[derive(Clone, Debug)]
pub struct StubOnlyBulkChannel {
    pub endpoint: IpcEndpointConfig,
    pub max_batch_bytes: usize,
}

impl Default for StubOnlyBulkChannel {
    fn default() -> Self {
        Self {
            endpoint: IpcEndpointConfig::named_pipe_stub(IpcChannelKind::Bulk),
            max_batch_bytes: DEFAULT_BULK_MAX_BYTES,
        }
    }
}

impl BulkChannel for StubOnlyBulkChannel {
    fn endpoint(&self) -> &IpcEndpointConfig {
        &self.endpoint
    }

    fn send_bulk(&mut self, mut request: BulkTransferRequest) -> Result<(), IpcProtocolError> {
        self.endpoint.validate()?;
        request.max_bytes = request.max_bytes.min(self.max_batch_bytes);
        request.validate()?;
        Err(IpcProtocolError::unsupported(
            "STUB_ONLY bulk channel validates bounded batches but does not transfer data",
        ))
    }

    fn max_batch_bytes(&self) -> usize {
        self.max_batch_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcProtocolError {
    pub error_code: ErrorCode,
    pub message_redacted: String,
    pub field: Option<String>,
    pub retryable: bool,
    pub audit_ref: Option<AuditId>,
    pub stub_only: bool,
    pub not_for_production: bool,
}

impl IpcProtocolError {
    pub fn invalid(field: impl Into<String>, message_redacted: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::InvalidRequest,
            message_redacted: message_redacted.into(),
            field: Some(field.into()),
            retryable: false,
            audit_ref: None,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn schema_mismatch(message_redacted: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::SchemaMismatch,
            message_redacted: message_redacted.into(),
            field: Some("schema_version".to_string()),
            retryable: false,
            audit_ref: None,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn permission_denied(message_redacted: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::PermissionDenied,
            message_redacted: message_redacted.into(),
            field: Some("auth_context".to_string()),
            retryable: false,
            audit_ref: None,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn privacy_violation(message_redacted: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::PrivacyPolicyViolation,
            message_redacted: message_redacted.into(),
            field: Some("payload".to_string()),
            retryable: false,
            audit_ref: None,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn unsupported(message_redacted: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::UnsupportedOperation,
            message_redacted: message_redacted.into(),
            field: Some("command".to_string()),
            retryable: false,
            audit_ref: None,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn rate_limited(message_redacted: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::RateLimited,
            message_redacted: message_redacted.into(),
            field: Some("rate_limit".to_string()),
            retryable: true,
            audit_ref: None,
            stub_only: true,
            not_for_production: true,
        }
    }
}

impl fmt::Display for IpcProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_code, self.message_redacted)
    }
}

impl std::error::Error for IpcProtocolError {}

pub fn default_ipc_command_allowlist() -> Result<Vec<IpcCommandSpec>, IpcProtocolError> {
    IpcCommand::all()
        .into_iter()
        .map(|command| command_spec(&command))
        .collect()
}

pub fn command_spec(command: &IpcCommand) -> Result<IpcCommandSpec, IpcProtocolError> {
    let level = command.level();
    let permission_scope = permission_scope_for_command(command);
    let permission = PermissionKey::new(permission_key_for_command(command))
        .map_err(|error| IpcProtocolError::invalid("permission", error.to_string()))?;
    let timeout = timeout_for_command_level(&level);
    let spec = IpcCommandSpec {
        command: command.clone(),
        level: level.clone(),
        channel: IpcChannelKind::Control,
        permission,
        permission_scope,
        timeout,
        rate_limit: IpcRateLimit::for_level(&level),
        audit_required: !matches!(level, IpcCommandLevel::L0ReadOnly),
        approval_required: matches!(
            level,
            IpcCommandLevel::L2SensitiveResponse | IpcCommandLevel::L3NotV1ApprovalRequired
        ),
        rollback_required: matches!(level, IpcCommandLevel::L2SensitiveResponse),
        ttl_required: matches!(level, IpcCommandLevel::L2SensitiveResponse),
        enabled_in_v1: command.is_v1_allowed(),
        stub_only: true,
        not_for_production: true,
        description_redacted: format!(
            "{STUB_ONLY_LABEL} {NOT_FOR_PRODUCTION_LABEL} IPC command metadata for {}",
            command.as_str()
        ),
    };
    spec.validate()?;
    Ok(spec)
}

fn permission_key_for_command(command: &IpcCommand) -> &'static str {
    match command.level() {
        IpcCommandLevel::L0ReadOnly => "service.ipc.read",
        IpcCommandLevel::L1ControlledOperation => "service.ipc.control",
        IpcCommandLevel::L2SensitiveResponse => "service.ipc.response",
        IpcCommandLevel::L3NotV1ApprovalRequired => "service.ipc.not_v1",
    }
}

fn timeout_for_command_level(level: &IpcCommandLevel) -> IpcTimeout {
    match level {
        IpcCommandLevel::L0ReadOnly | IpcCommandLevel::L1ControlledOperation => {
            IpcTimeout::control_default()
        }
        IpcCommandLevel::L2SensitiveResponse | IpcCommandLevel::L3NotV1ApprovalRequired => {
            IpcTimeout {
                request_timeout_ms: 3_000,
                ..IpcTimeout::control_default()
            }
        }
    }
}

fn permission_scope_for_command(command: &IpcCommand) -> PermissionScope {
    match command {
        IpcCommand::TemporaryBlockDestination
        | IpcCommand::RollbackFirewallRule
        | IpcCommand::PermanentFirewallDeny => PermissionScope::Response {
            action_type: ResponseActionType::RecommendFirewallBlock,
            execute: false,
        },
        IpcCommand::TemporaryThrottleFlow | IpcCommand::RollbackQosPolicy => {
            PermissionScope::Response {
                action_type: ResponseActionType::RecommendQosThrottle,
                execute: false,
            }
        }
        IpcCommand::FullHostIsolation
        | IpcCommand::SegmentIsolation
        | IpcCommand::ProcessKill
        | IpcCommand::PrivilegedUserLockout
        | IpcCommand::WafApiEnforcement => PermissionScope::System {
            command: command.as_str().to_string(),
            elevated_service_required: true,
        },
        _ => PermissionScope::System {
            command: command.as_str().to_string(),
            elevated_service_required: true,
        },
    }
}

fn permission_category_for_scope(scope: &PermissionScope) -> PermissionCategory {
    match scope {
        PermissionScope::Data { .. } => PermissionCategory::DataAccess,
        PermissionScope::System { .. } => PermissionCategory::SystemAccess,
        PermissionScope::Response { .. } => PermissionCategory::ResponseAccess,
        PermissionScope::Export { .. } => PermissionCategory::ExportAccess,
        PermissionScope::Desktop { .. } => PermissionCategory::DesktopAccess,
        PermissionScope::Policy { .. } => PermissionCategory::PolicyAccess,
    }
}

fn permission_risk_for_level(level: &IpcCommandLevel) -> PermissionRiskLevel {
    match level {
        IpcCommandLevel::L0ReadOnly => PermissionRiskLevel::Low,
        IpcCommandLevel::L1ControlledOperation => PermissionRiskLevel::Medium,
        IpcCommandLevel::L2SensitiveResponse => PermissionRiskLevel::High,
        IpcCommandLevel::L3NotV1ApprovalRequired => PermissionRiskLevel::Critical,
    }
}

fn require_ipc_label(labels: &[String], label: &str) -> Result<(), IpcProtocolError> {
    if labels.iter().any(|value| value == label) {
        return Ok(());
    }
    Err(IpcProtocolError::invalid(
        "labels",
        format!("missing required label: {label}"),
    ))
}

fn validate_ipc_text(field: &'static str, value: &str) -> Result<(), IpcProtocolError> {
    validate_safe_text(field, value)
        .map_err(|error| IpcProtocolError::invalid(field, error.message_redacted))
}

fn validate_payload(payload: &Value) -> Result<(), IpcProtocolError> {
    find_sensitive_marker(payload).map_or(Ok(()), |marker| {
        Err(IpcProtocolError::privacy_violation(format!(
            "IPC payload contains forbidden marker: {marker}"
        )))
    })
}

fn find_sensitive_marker(value: &Value) -> Option<&'static str> {
    const MARKERS: &[&str] = &[
        "raw_packet",
        "packet_bytes",
        "raw_payload",
        "payload_blob",
        "http_body",
        "cookie",
        "session_token",
        "authorization",
        "api_key",
        "credential",
        "private_key",
        "password",
        "secret",
    ];

    match value {
        Value::String(text) => {
            let normalized = text.to_ascii_lowercase();
            MARKERS
                .iter()
                .copied()
                .find(|marker| normalized.contains(marker))
        }
        Value::Array(items) => items.iter().find_map(find_sensitive_marker),
        Value::Object(map) => map.iter().find_map(|(key, nested)| {
            let normalized = key.to_ascii_lowercase();
            MARKERS
                .iter()
                .copied()
                .find(|marker| normalized.contains(marker))
                .or_else(|| find_sensitive_marker(nested))
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

pub fn stub_control_request(command: IpcCommand) -> Result<IpcRequestEnvelope, IpcProtocolError> {
    let spec = command_spec(&command)?;
    Ok(IpcRequestEnvelope::new(
        IpcCaller::local_core("local operator")?,
        command,
        spec.permission_scope,
        json!({
            "source": "STUB_ONLY",
            "service": SERVICE_STUB_NAME,
        }),
        PrivacyClass::Internal,
        IpcAuthContext::local_core_stub(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_envelope_contains_required_versioned_fields() {
        let request = stub_control_request(IpcCommand::GetServiceStatus).expect("request");

        assert_eq!(request.schema_version, IPC_SCHEMA_VERSION);
        assert_eq!(request.command, IpcCommand::GetServiceStatus);
        assert_eq!(request.caller.subject, PermissionSubject::LocalCore);
        assert_eq!(request.privacy_level, PrivacyClass::Internal);
        assert_eq!(request.channel, IpcChannelKind::Control);
        assert_eq!(
            request.rate_limit,
            IpcRateLimit::for_level(&IpcCommandLevel::L0ReadOnly)
        );
        assert!(request.validate().is_ok());
    }

    #[test]
    fn endpoint_config_requires_local_authenticated_named_pipe_binding() {
        let endpoint = IpcEndpointConfig::named_pipe_stub(IpcChannelKind::Control);

        assert_eq!(endpoint.protocol_name, IPC_PROTOCOL_NAME);
        assert_eq!(endpoint.transport, IpcTransportKind::NamedPipe);
        assert!(endpoint.local_machine_only);
        assert!(!endpoint.remote_bind_enabled);
        assert!(!endpoint.unauthenticated_tcp_enabled);
        assert!(endpoint.require_authenticated_client);
        assert!(endpoint.validate().is_ok());

        let mut remote = endpoint.clone();
        remote.remote_bind_enabled = true;
        assert!(matches!(
            remote
                .validate()
                .expect_err("remote bind rejected")
                .error_code,
            ErrorCode::PermissionDenied
        ));

        let mut tcp = endpoint.clone();
        tcp.unauthenticated_tcp_enabled = true;
        assert!(matches!(
            tcp.validate()
                .expect_err("unauthenticated tcp rejected")
                .error_code,
            ErrorCode::PermissionDenied
        ));

        let mut unauthenticated = endpoint;
        unauthenticated.require_authenticated_client = false;
        assert!(matches!(
            unauthenticated
                .validate()
                .expect_err("unauthenticated client rejected")
                .error_code,
            ErrorCode::PermissionDenied
        ));
    }

    #[test]
    fn request_validation_requires_allowlist_timeout_and_rate_metadata() {
        let mut timeout = stub_control_request(IpcCommand::GetServiceStatus).expect("request");
        timeout.timeout.request_timeout_ms += 1;
        assert_eq!(
            timeout
                .validate()
                .expect_err("timeout override rejected")
                .field,
            Some("timeout".to_string())
        );

        let mut rate_limit = stub_control_request(IpcCommand::GetServiceStatus).expect("request");
        rate_limit.rate_limit.max_requests += 1;
        assert_eq!(
            rate_limit
                .validate()
                .expect_err("rate override rejected")
                .field,
            Some("rate_limit".to_string())
        );
    }

    #[test]
    fn command_levels_cover_read_control_sensitive_and_not_v1() {
        let allowlist = default_ipc_command_allowlist().expect("allowlist");

        assert!(allowlist
            .iter()
            .any(|spec| spec.level == IpcCommandLevel::L0ReadOnly));
        assert!(allowlist
            .iter()
            .any(|spec| spec.level == IpcCommandLevel::L1ControlledOperation));
        assert!(allowlist
            .iter()
            .any(|spec| spec.level == IpcCommandLevel::L2SensitiveResponse));
        assert!(allowlist
            .iter()
            .any(|spec| spec.level == IpcCommandLevel::L3NotV1ApprovalRequired));

        let l2 = allowlist
            .iter()
            .find(|spec| spec.command == IpcCommand::TemporaryBlockDestination)
            .expect("l2 command");
        assert!(l2.audit_required);
        assert!(l2.approval_required);
        assert!(l2.rollback_required);
        assert!(l2.ttl_required);
        assert!(l2.enabled_in_v1);

        let l3 = allowlist
            .iter()
            .find(|spec| spec.command == IpcCommand::FullHostIsolation)
            .expect("l3 command");
        assert!(!l3.enabled_in_v1);
        assert_eq!(l3.rate_limit.max_requests, 0);
    }

    #[test]
    fn unauthenticated_or_remote_clients_are_rejected() {
        let mut auth = IpcAuthContext::local_core_stub();
        auth.authenticated = false;
        assert!(matches!(
            auth.validate()
                .expect_err("unauthenticated rejected")
                .error_code,
            ErrorCode::PermissionDenied
        ));

        let mut remote = IpcAuthContext::local_core_stub();
        remote.remote_endpoint_redacted = Some("remote host".to_string());
        assert!(matches!(
            remote.validate().expect_err("remote rejected").error_code,
            ErrorCode::PermissionDenied
        ));
    }

    #[test]
    fn request_validation_rejects_l3_and_sensitive_payload_markers() {
        let l3 = stub_control_request(IpcCommand::FullHostIsolation).expect("l3 request");
        assert!(matches!(
            l3.validate().expect_err("l3 rejected").error_code,
            ErrorCode::UnsupportedOperation
        ));

        let mut request = stub_control_request(IpcCommand::GetServiceStatus).expect("request");
        request.payload = json!({ "raw_payload": "not allowed" });
        assert!(matches!(
            request
                .validate()
                .expect_err("sensitive payload rejected")
                .error_code,
            ErrorCode::PrivacyPolicyViolation
        ));
    }

    #[test]
    fn stub_client_and_server_validate_but_do_not_execute() {
        let auth = IpcAuthContext::local_core_stub();
        let server = StubOnlyIpcServer::new(auth.clone());
        let mut client = StubOnlyIpcClient::new(auth, server);
        let request = stub_control_request(IpcCommand::GetServiceStatus).expect("request");
        let response = client.send_control(request).expect("stub response");

        assert!(!response.success);
        assert_eq!(response.error_code, Some(ErrorCode::UnsupportedOperation));
        assert!(response.validate().is_ok());
    }

    #[test]
    fn event_and_bulk_channels_reject_raw_payload_streaming() {
        let event = ServiceEventEnvelope::new("capture.health", json!({ "status": "degraded" }))
            .expect("event");
        let mut event_channel = StubOnlyEventChannel::default();
        assert_eq!(event_channel.endpoint().channel, IpcChannelKind::Event);
        event_channel.publish_event(event).expect("publish");
        assert!(event_channel.poll_event().expect("poll").is_some());

        let mut private_event =
            ServiceEventEnvelope::new("capture.health", json!({ "status": "degraded" }))
                .expect("event");
        private_event.privacy_level = PrivacyClass::Secret;
        assert!(matches!(
            private_event
                .validate()
                .expect_err("private event rejected")
                .error_code,
            ErrorCode::PrivacyPolicyViolation
        ));

        let mut bulk = BulkTransferRequest::bounded(
            IpcCommand::ListConnectionSnapshot,
            vec![json!({ "flow": "metadata" })],
        );
        bulk.raw_streaming_enabled = true;
        assert!(matches!(
            bulk.validate()
                .expect_err("raw streaming rejected")
                .error_code,
            ErrorCode::PrivacyPolicyViolation
        ));

        let response_bulk = BulkTransferRequest::bounded(
            IpcCommand::TemporaryBlockDestination,
            vec![json!({ "target": "metadata only" })],
        );
        assert_eq!(
            response_bulk
                .validate()
                .expect_err("response bulk rejected")
                .field,
            Some("command".to_string())
        );

        let mut channel = StubOnlyBulkChannel::default();
        assert_eq!(channel.endpoint().channel, IpcChannelKind::Bulk);
        let err = channel
            .send_bulk(BulkTransferRequest::bounded(
                IpcCommand::ListConnectionSnapshot,
                vec![json!({ "flow": "metadata" })],
            ))
            .expect_err("stub bulk does not transfer");
        assert_eq!(err.error_code, ErrorCode::UnsupportedOperation);
    }

    #[test]
    fn response_envelope_requires_structured_error_fields() {
        let request = stub_control_request(IpcCommand::GetServiceStatus).expect("request");
        let mut response = IpcResponseEnvelope::error(
            request.request_id,
            request.trace_id,
            IpcProtocolError::unsupported("stub"),
            1,
        );
        assert!(response.validate().is_ok());

        response.error_message_redacted = None;
        assert!(response.validate().is_err());
    }
}
