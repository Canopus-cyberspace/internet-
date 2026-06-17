//! Local Core client for the Sentinel Guard elevated service IPC stub.
//!
//! This adapter performs only local Named Pipe request/response calls. It does
//! not execute privileged actions and does not expose raw packet or payload
//! content to callers.

use sentinel_contracts::{
    caller_verification::{
        AllowedCommandClass, CallerVerificationReadStatus, CallerVerificationSummary,
    },
    provider_controller::NetworkProviderControllerStatus,
    runtime_ownership::{RuntimeMode, RuntimeOwnershipSummary},
    MutationAuthorizationDecision, MutationAuthorizationStatus, MutationExecutionReceipt,
    MutationExecutionRequest, MutationIntent, SchemaVersion, ServiceAdapterMode,
    ServiceCapabilityContext, ServiceCapabilityStatus, ServiceLimitationFlag, ServiceReadCommandId,
    ServiceReadCommandRequest, ServiceReadCommandResponse, ServiceReasonCode, Timestamp,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::thread;
use std::time::Duration;
use uuid::Uuid;

pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\SentinelGuardIpc";
pub const IPC_PROTOCOL_VERSION: u16 = 1;
pub const RUNTIME_IPC_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_PAYLOAD_BYTES: usize = 48 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServiceCommand {
    Ping,
    Status,
    CaptureHealth,
    ProcessSnapshot,
    EvaluateMutationIntent,
    ActivateIpHelper,
    SampleIpHelperOnce,
    StopIpHelper,
    Read(ServiceReadCommandId),
}

impl ServiceCommand {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Status => "status",
            Self::CaptureHealth => "capture_health",
            Self::ProcessSnapshot => "process_snapshot",
            Self::EvaluateMutationIntent => "evaluate_mutation_intent",
            Self::ActivateIpHelper => "activate_ip_helper",
            Self::SampleIpHelperOnce => "sample_ip_helper_once",
            Self::StopIpHelper => "stop_ip_helper",
            Self::Read(command) => command.as_str(),
        }
    }

    pub fn parse(value: &str) -> Result<Self, IpcError> {
        match value {
            "ping" => Ok(Self::Ping),
            "status" => Ok(Self::Status),
            "capture_health" => Ok(Self::CaptureHealth),
            "process_snapshot" => Ok(Self::ProcessSnapshot),
            "evaluate_mutation_intent" => Ok(Self::EvaluateMutationIntent),
            "activate_ip_helper" => Ok(Self::ActivateIpHelper),
            "sample_ip_helper_once" => Ok(Self::SampleIpHelperOnce),
            "stop_ip_helper" => Ok(Self::StopIpHelper),
            _ => ServiceReadCommandId::parse(value)
                .map(Self::Read)
                .map_err(|_| IpcError {
                    code: "COMMAND_NOT_ALLOWED".to_string(),
                    message: "command is not allowlisted".to_string(),
                    retryable: false,
                }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcRequest<T = Value> {
    pub id: String,
    pub command: String,
    pub params: T,
    pub timestamp: Timestamp,
}

impl IpcRequest<Value> {
    pub fn new(command: ServiceCommand, params: Value) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            command: command.as_str().to_string(),
            params,
            timestamp: Timestamp::now(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcClientHello {
    pub message_type: String,
    pub supported_protocol_versions: Vec<u16>,
    pub schema_version: SchemaVersion,
    pub client_nonce: String,
    pub requested_capabilities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcServerHello {
    pub message_type: String,
    pub protocol_version: u16,
    pub schema_version: SchemaVersion,
    pub challenge_nonce: String,
    pub server_nonce: String,
    pub session_reference: String,
    pub accepted_capabilities: Vec<String>,
    pub max_frame_bytes: usize,
    pub max_payload_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcClientVerify {
    pub message_type: String,
    pub protocol_version: u16,
    pub schema_version: SchemaVersion,
    pub session_reference: String,
    pub client_nonce: String,
    pub server_nonce: String,
    pub challenge_nonce: String,
    pub sequence_number: u64,
    pub caller_kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcServerVerify {
    pub message_type: String,
    pub protocol_version: u16,
    pub schema_version: SchemaVersion,
    pub session_reference: String,
    pub response_status: String,
    pub caller_verification: CallerVerificationSummary,
    pub session_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcEnvelope<T = Value> {
    pub protocol_version: u16,
    pub schema_version: SchemaVersion,
    pub request_id: String,
    pub session_reference: String,
    pub client_nonce: String,
    pub server_nonce: String,
    pub sequence_number: u64,
    pub command_id: String,
    pub response_status: String,
    pub payload: T,
}

impl IpcEnvelope<Value> {
    pub fn request(session: &IpcSessionState, command: ServiceCommand, payload: Value) -> Self {
        Self::request_with_sequence(session, command, payload, 1)
    }

    pub fn request_with_sequence(
        session: &IpcSessionState,
        command: ServiceCommand,
        payload: Value,
        sequence_number: u64,
    ) -> Self {
        Self {
            protocol_version: IPC_PROTOCOL_VERSION,
            schema_version: RUNTIME_IPC_SCHEMA_VERSION,
            request_id: Uuid::new_v4().to_string(),
            session_reference: session.session_reference.clone(),
            client_nonce: session.client_nonce.clone(),
            server_nonce: session.server_nonce.clone(),
            sequence_number,
            command_id: command.as_str().to_string(),
            response_status: "request".to_string(),
            payload,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpcSessionState {
    pub session_reference: String,
    pub client_nonce: String,
    pub server_nonce: String,
    pub challenge_nonce: String,
    pub caller_verification: CallerVerificationSummary,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PingResult {
    pub nonce: String,
    pub service_uptime_ms: u64,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResult {
    pub service_status: String,
    pub connected_clients: u32,
    pub memory_usage_mb: f64,
    pub pid: u32,
    #[serde(default)]
    pub runtime_ownership: Option<RuntimeMode>,
    #[serde(default)]
    pub runtime_ownership_status: Option<RuntimeOwnershipSummary>,
    #[serde(default)]
    pub runtime_protocol_version: Option<SchemaVersion>,
    #[serde(default)]
    pub runtime_schema_version: Option<SchemaVersion>,
    #[serde(default)]
    pub caller_verification_status: Option<CallerVerificationReadStatus>,
    #[serde(default)]
    pub mutation_authorization_status: Option<MutationAuthorizationStatus>,
    #[serde(default)]
    pub provider_controller_status: Option<NetworkProviderControllerStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureHealthResult {
    pub capture_active: bool,
    pub packets_observed: u64,
    pub last_packet_at: Option<String>,
    pub adapter_state: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSnapshotResult {
    pub processes: Vec<ProcessSnapshotEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSnapshotEntry {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub connections: Vec<ProcessConnectionEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessConnectionEntry {
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub state: String,
}

#[derive(Debug)]
pub enum IpcFrameError {
    Io(io::Error),
    FrameTooLarge { len: usize, max: usize },
    Json(serde_json::Error),
}

impl fmt::Display for IpcFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "IPC frame IO failed: {error}"),
            Self::FrameTooLarge { len, max } => {
                write!(f, "IPC frame is too large: {len} > {max}")
            }
            Self::Json(error) => write!(f, "IPC frame JSON failed: {error}"),
        }
    }
}

impl std::error::Error for IpcFrameError {}

impl From<io::Error> for IpcFrameError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for IpcFrameError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub fn write_json_frame<W, T>(writer: &mut W, value: &T) -> Result<(), IpcFrameError>
where
    W: Write,
    T: Serialize,
{
    let payload = serde_json::to_vec(value)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(IpcFrameError::FrameTooLarge {
            len: payload.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    writer.write_all(&(payload.len() as u32).to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_json_frame<R, T>(reader: &mut R) -> Result<T, IpcFrameError>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut len_bytes = [0_u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(IpcFrameError::FrameTooLarge {
            len,
            max: MAX_FRAME_BYTES,
        });
    }
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceIpcClientErrorKind {
    Unreachable,
    Timeout,
    PermissionDenied,
    Protocol,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceIpcClientError {
    pub kind: ServiceIpcClientErrorKind,
    pub code: String,
    pub message_redacted: String,
    pub retryable: bool,
}

impl ServiceIpcClientError {
    fn unreachable(error: impl ToString) -> Self {
        Self {
            kind: ServiceIpcClientErrorKind::Unreachable,
            code: "service_unreachable".to_string(),
            message_redacted: error.to_string(),
            retryable: true,
        }
    }

    fn protocol(error: impl ToString) -> Self {
        Self {
            kind: ServiceIpcClientErrorKind::Protocol,
            code: "service_ipc_protocol_error".to_string(),
            message_redacted: error.to_string(),
            retryable: false,
        }
    }

    fn rejected(error: IpcError) -> Self {
        Self {
            kind: ServiceIpcClientErrorKind::Rejected,
            code: error.code,
            message_redacted: error.message,
            retryable: error.retryable,
        }
    }
}

impl fmt::Display for ServiceIpcClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message_redacted)
    }
}

impl std::error::Error for ServiceIpcClientError {}

const SERVICE_IPC_STATUS_SOURCE: &str = "service_ipc.status";
const SERVICE_IPC_CAPTURE_SOURCE: &str = "service_ipc.capture_health";
const SERVICE_IPC_PROCESS_SOURCE: &str = "service_ipc.process_stub";
const SERVICE_IPC_RESPONSE_SOURCE: &str = "service_ipc.response_stub";

#[derive(Clone, Debug, PartialEq)]
pub struct ServiceIpcCapabilityContextSnapshot {
    pub contexts: Vec<ServiceCapabilityContext>,
    pub degraded: bool,
    pub message_redacted: String,
    pub observed_at: Timestamp,
}

impl ServiceIpcCapabilityContextSnapshot {
    pub fn from_status_and_capture(
        status: &StatusResult,
        capture: &CaptureHealthResult,
    ) -> Result<Self, ServiceIpcClientError> {
        let observed_at = Timestamp::now();
        let boundary_status = match status.service_status.as_str() {
            "running" => ServiceCapabilityStatus::Available,
            "stopped" | "degraded" => ServiceCapabilityStatus::Degraded,
            "unauthorized" => ServiceCapabilityStatus::Unauthorized,
            other => {
                if other.trim().is_empty() {
                    return Err(ServiceIpcClientError::protocol(
                        "service status probe returned an empty state",
                    ));
                }
                ServiceCapabilityStatus::Degraded
            }
        };
        let boundary_reason = if status.service_status == "running" {
            Some(ServiceReasonCode::StubOnlyMode)
        } else {
            Some(ServiceReasonCode::AdapterInactive)
        };
        let capture_status = if capture.capture_active {
            ServiceCapabilityStatus::Degraded
        } else if capture.adapter_state == "stub_inactive" {
            ServiceCapabilityStatus::Unavailable
        } else {
            ServiceCapabilityStatus::Degraded
        };
        let capture_reason = if capture.capture_active {
            Some(ServiceReasonCode::StubOnlyMode)
        } else {
            Some(ServiceReasonCode::CaptureUnavailable)
        };
        let contexts = vec![
            service_capability_context(
                "service_boundary",
                ServiceAdapterMode::StubOnly,
                boundary_status,
                boundary_reason,
                vec![
                    ServiceLimitationFlag::LocalOnly,
                    ServiceLimitationFlag::StubOnly,
                    ServiceLimitationFlag::ReadOnlyAllowlist,
                    ServiceLimitationFlag::NoRawContentRetention,
                    ServiceLimitationFlag::ControlPlaneOwnedByLocalCore,
                    ServiceLimitationFlag::NoProductionServiceLifecycle,
                ],
                SERVICE_IPC_STATUS_SOURCE,
                observed_at.clone(),
            )?,
            service_capability_context(
                "capture_adapter",
                ServiceAdapterMode::StubOnly,
                capture_status,
                capture_reason,
                vec![
                    ServiceLimitationFlag::StubOnly,
                    ServiceLimitationFlag::MetadataOnly,
                    ServiceLimitationFlag::NoRawContentRetention,
                    ServiceLimitationFlag::NoPrivilegedCapture,
                    ServiceLimitationFlag::ReducedVisibility,
                    ServiceLimitationFlag::NoProductionServiceLifecycle,
                ],
                SERVICE_IPC_CAPTURE_SOURCE,
                observed_at.clone(),
            )?,
            service_capability_context(
                "process_attribution",
                ServiceAdapterMode::StubOnly,
                ServiceCapabilityStatus::Degraded,
                Some(ServiceReasonCode::ProcessAttributionLimited),
                vec![
                    ServiceLimitationFlag::StubOnly,
                    ServiceLimitationFlag::MetadataOnly,
                    ServiceLimitationFlag::NoProcessAttribution,
                    ServiceLimitationFlag::ReducedVisibility,
                    ServiceLimitationFlag::NoProductionServiceLifecycle,
                ],
                SERVICE_IPC_PROCESS_SOURCE,
                observed_at.clone(),
            )?,
            service_capability_context(
                "response_executor",
                ServiceAdapterMode::Disabled,
                ServiceCapabilityStatus::Disabled,
                Some(ServiceReasonCode::ResponseExecutionDisabled),
                vec![
                    ServiceLimitationFlag::StubOnly,
                    ServiceLimitationFlag::ReadOnlyAllowlist,
                    ServiceLimitationFlag::NoResponseExecution,
                    ServiceLimitationFlag::NoOsAction,
                    ServiceLimitationFlag::NoProductionServiceLifecycle,
                ],
                SERVICE_IPC_RESPONSE_SOURCE,
                observed_at.clone(),
            )?,
        ];

        Ok(Self {
            degraded: contexts
                .iter()
                .any(|context| !matches!(context.status, ServiceCapabilityStatus::Available)),
            message_redacted: "Service IPC metadata context captured bounded stub capability state"
                .to_string(),
            contexts,
            observed_at,
        })
    }

    pub fn from_status_error(error: &ServiceIpcClientError) -> Result<Self, ServiceIpcClientError> {
        let observed_at = Timestamp::now();
        let boundary_status = match error.kind {
            ServiceIpcClientErrorKind::PermissionDenied => ServiceCapabilityStatus::Unauthorized,
            ServiceIpcClientErrorKind::Protocol => ServiceCapabilityStatus::Unavailable,
            ServiceIpcClientErrorKind::Rejected => ServiceCapabilityStatus::Unavailable,
            ServiceIpcClientErrorKind::Timeout | ServiceIpcClientErrorKind::Unreachable => {
                ServiceCapabilityStatus::Disconnected
            }
        };
        let boundary_reason = match error.kind {
            ServiceIpcClientErrorKind::PermissionDenied => ServiceReasonCode::PermissionDenied,
            ServiceIpcClientErrorKind::Protocol => ServiceReasonCode::ProtocolError,
            ServiceIpcClientErrorKind::Rejected => ServiceReasonCode::ServiceUnavailable,
            ServiceIpcClientErrorKind::Timeout | ServiceIpcClientErrorKind::Unreachable => {
                ServiceReasonCode::IpcDisconnected
            }
        };
        let contexts = vec![
            service_capability_context(
                "service_boundary",
                ServiceAdapterMode::Disconnected,
                boundary_status,
                Some(boundary_reason),
                vec![
                    ServiceLimitationFlag::LocalOnly,
                    ServiceLimitationFlag::StubOnly,
                    ServiceLimitationFlag::ReadOnlyAllowlist,
                    ServiceLimitationFlag::NoRawContentRetention,
                    ServiceLimitationFlag::ControlPlaneOwnedByLocalCore,
                    ServiceLimitationFlag::NoProductionServiceLifecycle,
                ],
                SERVICE_IPC_STATUS_SOURCE,
                observed_at.clone(),
            )?,
            service_capability_context(
                "capture_adapter",
                ServiceAdapterMode::Disconnected,
                ServiceCapabilityStatus::Disconnected,
                Some(ServiceReasonCode::IpcDisconnected),
                vec![
                    ServiceLimitationFlag::StubOnly,
                    ServiceLimitationFlag::MetadataOnly,
                    ServiceLimitationFlag::NoRawContentRetention,
                    ServiceLimitationFlag::NoPrivilegedCapture,
                    ServiceLimitationFlag::ReducedVisibility,
                    ServiceLimitationFlag::NoProductionServiceLifecycle,
                ],
                SERVICE_IPC_CAPTURE_SOURCE,
                observed_at.clone(),
            )?,
            service_capability_context(
                "process_attribution",
                ServiceAdapterMode::Disconnected,
                ServiceCapabilityStatus::Disconnected,
                Some(ServiceReasonCode::IpcDisconnected),
                vec![
                    ServiceLimitationFlag::StubOnly,
                    ServiceLimitationFlag::MetadataOnly,
                    ServiceLimitationFlag::NoProcessAttribution,
                    ServiceLimitationFlag::ReducedVisibility,
                    ServiceLimitationFlag::NoProductionServiceLifecycle,
                ],
                SERVICE_IPC_PROCESS_SOURCE,
                observed_at.clone(),
            )?,
            service_capability_context(
                "response_executor",
                ServiceAdapterMode::Disabled,
                ServiceCapabilityStatus::Disabled,
                Some(ServiceReasonCode::ResponseExecutionDisabled),
                vec![
                    ServiceLimitationFlag::StubOnly,
                    ServiceLimitationFlag::ReadOnlyAllowlist,
                    ServiceLimitationFlag::NoResponseExecution,
                    ServiceLimitationFlag::NoOsAction,
                    ServiceLimitationFlag::NoProductionServiceLifecycle,
                ],
                SERVICE_IPC_RESPONSE_SOURCE,
                observed_at.clone(),
            )?,
        ];

        Ok(Self {
            contexts,
            degraded: true,
            message_redacted: error.message_redacted.clone(),
            observed_at,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ElevatedServiceIpcClient {
    pipe_name: String,
    max_retries: u8,
    backoff_ms: Vec<u64>,
}

impl Default for ElevatedServiceIpcClient {
    fn default() -> Self {
        Self {
            pipe_name: DEFAULT_PIPE_NAME.to_string(),
            max_retries: 2,
            backoff_ms: vec![100, 200],
        }
    }
}

impl ElevatedServiceIpcClient {
    pub fn with_pipe_name(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            ..Self::default()
        }
    }

    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    pub fn ping(&self, nonce: impl Into<String>) -> Result<PingResult, ServiceIpcClientError> {
        self.send_request(ServiceCommand::Ping, json!({ "nonce": nonce.into() }))
    }

    pub fn status(&self) -> Result<StatusResult, ServiceIpcClientError> {
        self.send_request(ServiceCommand::Status, json!({}))
    }

    pub fn capture_health(&self) -> Result<CaptureHealthResult, ServiceIpcClientError> {
        self.send_request(ServiceCommand::CaptureHealth, json!({}))
    }

    pub fn process_snapshot(
        &self,
        pid: Option<u32>,
    ) -> Result<ProcessSnapshotResult, ServiceIpcClientError> {
        let params = match pid {
            Some(pid) => json!({ "pid": pid }),
            None => json!({}),
        };
        self.send_request(ServiceCommand::ProcessSnapshot, params)
    }

    pub fn read_command(
        &self,
        command_id: ServiceReadCommandId,
        request: ServiceReadCommandRequest,
    ) -> Result<ServiceReadCommandResponse, ServiceIpcClientError> {
        let params = serde_json::to_value(request).map_err(ServiceIpcClientError::protocol)?;
        self.send_request(ServiceCommand::Read(command_id), params)
    }

    pub fn evaluate_mutation_intent(
        &self,
        intent: MutationIntent,
    ) -> Result<MutationAuthorizationDecision, ServiceIpcClientError> {
        let params = serde_json::to_value(intent).map_err(ServiceIpcClientError::protocol)?;
        self.send_request(ServiceCommand::EvaluateMutationIntent, params)
    }

    pub fn activate_ip_helper(
        &self,
        request: MutationExecutionRequest,
    ) -> Result<MutationExecutionReceipt, ServiceIpcClientError> {
        let params = serde_json::to_value(request).map_err(ServiceIpcClientError::protocol)?;
        self.send_request(ServiceCommand::ActivateIpHelper, params)
    }

    pub fn sample_ip_helper_once(
        &self,
        request: MutationExecutionRequest,
    ) -> Result<MutationExecutionReceipt, ServiceIpcClientError> {
        let params = serde_json::to_value(request).map_err(ServiceIpcClientError::protocol)?;
        self.send_request(ServiceCommand::SampleIpHelperOnce, params)
    }

    pub fn stop_ip_helper(
        &self,
        request: MutationExecutionRequest,
    ) -> Result<MutationExecutionReceipt, ServiceIpcClientError> {
        let params = serde_json::to_value(request).map_err(ServiceIpcClientError::protocol)?;
        self.send_request(ServiceCommand::StopIpHelper, params)
    }

    pub fn safe_capability_contexts(
        &self,
    ) -> Result<ServiceIpcCapabilityContextSnapshot, ServiceIpcClientError> {
        match self.status() {
            Ok(status) => match self.capture_health() {
                Ok(capture) => {
                    ServiceIpcCapabilityContextSnapshot::from_status_and_capture(&status, &capture)
                }
                Err(error) => ServiceIpcCapabilityContextSnapshot::from_status_error(&error),
            },
            Err(error) => ServiceIpcCapabilityContextSnapshot::from_status_error(&error),
        }
    }

    pub fn send_request<T>(
        &self,
        command: ServiceCommand,
        params: Value,
    ) -> Result<T, ServiceIpcClientError>
    where
        T: DeserializeOwned,
    {
        let request = IpcRequest::new(command, params);
        let mut last_error = None;
        for attempt in 0..=self.max_retries {
            match self.send_once::<T>(&request) {
                Ok(result) => return Ok(result),
                Err(error) => {
                    let retryable = matches!(
                        error.kind,
                        ServiceIpcClientErrorKind::Unreachable | ServiceIpcClientErrorKind::Timeout
                    ) || error.retryable;
                    last_error = Some(error);
                    if !retryable || attempt == self.max_retries {
                        break;
                    }
                    let delay = self
                        .backoff_ms
                        .get(attempt as usize)
                        .copied()
                        .unwrap_or(200);
                    thread::sleep(Duration::from_millis(delay));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| ServiceIpcClientError::unreachable("pipe unavailable")))
    }

    fn send_once<T>(&self, request: &IpcRequest<Value>) -> Result<T, ServiceIpcClientError>
    where
        T: DeserializeOwned,
    {
        let mut pipe = open_pipe(&self.pipe_name)?;
        let session = negotiate_ipc_session(&mut pipe)?;
        let command =
            ServiceCommand::parse(&request.command).map_err(ServiceIpcClientError::rejected)?;
        let envelope = IpcEnvelope::request(&session, command, request.params.clone());
        write_json_frame(&mut pipe, &envelope).map_err(ServiceIpcClientError::protocol)?;
        let response: IpcEnvelope<Value> =
            read_json_frame(&mut pipe).map_err(ServiceIpcClientError::protocol)?;
        validate_response_envelope(&session, &envelope, &response)?;
        if response.response_status == "error" {
            let error: IpcError = serde_json::from_value(response.payload)
                .map_err(ServiceIpcClientError::protocol)?;
            return Err(ServiceIpcClientError::rejected(error));
        }
        serde_json::from_value(response.payload).map_err(ServiceIpcClientError::protocol)
    }
}

fn negotiate_ipc_session(
    pipe: &mut std::fs::File,
) -> Result<IpcSessionState, ServiceIpcClientError> {
    let client_nonce = Uuid::new_v4().to_string();
    let hello = IpcClientHello {
        message_type: "client_hello".to_string(),
        supported_protocol_versions: vec![IPC_PROTOCOL_VERSION],
        schema_version: RUNTIME_IPC_SCHEMA_VERSION,
        client_nonce: client_nonce.clone(),
        requested_capabilities: vec![
            "read_only_status".to_string(),
            "read_only_canonical_snapshots".to_string(),
        ],
    };
    write_json_frame(pipe, &hello).map_err(ServiceIpcClientError::protocol)?;
    let server_hello: IpcServerHello =
        read_json_frame(pipe).map_err(ServiceIpcClientError::protocol)?;
    if server_hello.message_type != "server_hello"
        || server_hello.protocol_version != IPC_PROTOCOL_VERSION
        || server_hello.schema_version != RUNTIME_IPC_SCHEMA_VERSION
    {
        return Err(ServiceIpcClientError::protocol(
            "service IPC protocol negotiation failed",
        ));
    }
    if server_hello.max_frame_bytes > MAX_FRAME_BYTES
        || server_hello.max_payload_bytes > MAX_PAYLOAD_BYTES
    {
        return Err(ServiceIpcClientError::protocol(
            "service IPC negotiated unsafe size limits",
        ));
    }
    let verify = IpcClientVerify {
        message_type: "client_verify".to_string(),
        protocol_version: IPC_PROTOCOL_VERSION,
        schema_version: RUNTIME_IPC_SCHEMA_VERSION,
        session_reference: server_hello.session_reference.clone(),
        client_nonce: client_nonce.clone(),
        server_nonce: server_hello.server_nonce.clone(),
        challenge_nonce: server_hello.challenge_nonce.clone(),
        sequence_number: 0,
        caller_kind: "local_desktop".to_string(),
    };
    write_json_frame(pipe, &verify).map_err(ServiceIpcClientError::protocol)?;
    let server_verify: IpcServerVerify =
        read_json_frame(pipe).map_err(ServiceIpcClientError::protocol)?;
    if server_verify.message_type != "server_verify"
        || server_verify.response_status != "ok"
        || server_verify.protocol_version != IPC_PROTOCOL_VERSION
        || server_verify.schema_version != RUNTIME_IPC_SCHEMA_VERSION
        || server_verify.session_reference != server_hello.session_reference
    {
        return Err(ServiceIpcClientError::protocol(
            "service IPC caller verification failed",
        ));
    }
    server_verify
        .caller_verification
        .validate()
        .map_err(ServiceIpcClientError::protocol)?;
    if !server_verify
        .caller_verification
        .permits_command_class(AllowedCommandClass::ReadStatus)
    {
        return Err(ServiceIpcClientError::protocol(
            "service IPC caller verification did not permit read-only commands",
        ));
    }
    Ok(IpcSessionState {
        session_reference: server_hello.session_reference,
        client_nonce,
        server_nonce: server_hello.server_nonce,
        challenge_nonce: server_hello.challenge_nonce,
        caller_verification: server_verify.caller_verification,
    })
}

fn validate_response_envelope(
    session: &IpcSessionState,
    request: &IpcEnvelope<Value>,
    response: &IpcEnvelope<Value>,
) -> Result<(), ServiceIpcClientError> {
    if response.protocol_version != IPC_PROTOCOL_VERSION
        || response.schema_version != RUNTIME_IPC_SCHEMA_VERSION
        || response.request_id != request.request_id
        || response.session_reference != session.session_reference
        || response.client_nonce != session.client_nonce
        || response.server_nonce != session.server_nonce
        || response.sequence_number != request.sequence_number
        || response.command_id != request.command_id
    {
        return Err(ServiceIpcClientError::protocol(
            "service IPC response envelope validation failed",
        ));
    }
    if !matches!(response.response_status.as_str(), "ok" | "error") {
        return Err(ServiceIpcClientError::protocol(
            "service IPC response status was invalid",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn open_pipe(pipe_name: &str) -> Result<std::fs::File, ServiceIpcClientError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe_name)
        .map_err(classify_open_error)
}

#[cfg(not(windows))]
fn open_pipe(_pipe_name: &str) -> Result<std::fs::File, ServiceIpcClientError> {
    Err(ServiceIpcClientError::unreachable(
        "Sentinel Guard service IPC is Windows-only",
    ))
}

fn classify_open_error(error: io::Error) -> ServiceIpcClientError {
    match error.kind() {
        io::ErrorKind::TimedOut => ServiceIpcClientError {
            kind: ServiceIpcClientErrorKind::Timeout,
            code: "service_timeout".to_string(),
            message_redacted: error.to_string(),
            retryable: true,
        },
        io::ErrorKind::PermissionDenied => ServiceIpcClientError {
            kind: ServiceIpcClientErrorKind::PermissionDenied,
            code: "service_permission_denied".to_string(),
            message_redacted: "service IPC access was denied".to_string(),
            retryable: false,
        },
        _ => ServiceIpcClientError::unreachable(error),
    }
}

fn service_capability_context(
    capability_id: &str,
    adapter_mode: ServiceAdapterMode,
    status: ServiceCapabilityStatus,
    reason_code: Option<ServiceReasonCode>,
    limitation_flags: Vec<ServiceLimitationFlag>,
    source_provenance_id: &str,
    observed_at: Timestamp,
) -> Result<ServiceCapabilityContext, ServiceIpcClientError> {
    let mut context =
        ServiceCapabilityContext::new(capability_id, adapter_mode, status, source_provenance_id)
            .map_err(ServiceIpcClientError::protocol)?;
    context.reason_code = reason_code;
    context.limitation_flags = limitation_flags;
    context.observed_at = observed_at;
    context
        .validate_boundary()
        .map_err(ServiceIpcClientError::protocol)?;
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        caller_verification::{
            CallerCategory, CallerVerificationState, ElevationCategory, LocalRemoteClassification,
            SessionBindingState, TokenSuitabilityCategory, VerificationFreshnessBucket,
            CALLER_VERIFICATION_SCHEMA_VERSION,
        },
        RedactionStatus,
    };

    fn verified_test_summary() -> CallerVerificationSummary {
        CallerVerificationSummary {
            schema_version: CALLER_VERIFICATION_SCHEMA_VERSION,
            verification_ref: "caller_verification_test_ref".to_string(),
            caller_category: CallerCategory::InteractiveUser,
            verification_state: CallerVerificationState::VerifiedInteractiveUser,
            local_classification: LocalRemoteClassification::Local,
            interactive_marker: true,
            service_marker: false,
            administrator_policy_marker: false,
            token_suitability: TokenSuitabilityCategory::ImpersonationSuitable,
            elevation_category: ElevationCategory::Standard,
            session_binding_state: SessionBindingState::Bound,
            freshness_bucket: VerificationFreshnessBucket::CurrentConnection,
            allowed_command_classes: vec![
                AllowedCommandClass::ReadStatus,
                AllowedCommandClass::ReadCanonicalModels,
            ],
            degraded_reason: None,
            audit_refs: vec!["caller_token_classified".to_string()],
            provenance_id: "windows_named_pipe_impersonation".to_string(),
            redaction_status: RedactionStatus::Redacted,
            production_mutations_enabled: false,
        }
    }

    #[test]
    fn client_error_for_unreachable_service_is_retryable_and_degraded_safe() {
        let client = ElevatedServiceIpcClient::with_pipe_name(
            r"\\.\pipe\SentinelGuardDefinitelyMissingForTest",
        );
        let error = client.status().expect_err("missing pipe");

        assert_eq!(error.kind, ServiceIpcClientErrorKind::Unreachable);
        assert_eq!(error.code, "service_unreachable");
        assert!(error.retryable);
    }

    #[test]
    fn service_wire_status_response_deserializes_for_client_contract() {
        let status: StatusResult = serde_json::from_value(json!({
            "service_status": "running",
            "connected_clients": 1,
            "memory_usage_mb": 0.0,
            "pid": std::process::id()
        }))
        .expect("decode");

        assert_eq!(status.service_status, "running");
        assert_eq!(status.pid, std::process::id());
        assert!(status.runtime_ownership.is_none());
    }

    #[test]
    fn service_ipc_status_accepts_runtime_ownership_negotiation_metadata() {
        let status: StatusResult = serde_json::from_value(json!({
            "service_status": "running",
            "connected_clients": 1,
            "memory_usage_mb": 0.0,
            "pid": 0,
            "runtime_ownership": "service_owned",
            "runtime_protocol_version": { "major": 1, "minor": 0, "patch": 0 },
            "runtime_schema_version": { "major": 1, "minor": 0, "patch": 0 }
        }))
        .expect("decode");

        assert_eq!(status.runtime_ownership, Some(RuntimeMode::ServiceOwned));
        assert_eq!(
            status.runtime_protocol_version,
            Some(RUNTIME_IPC_SCHEMA_VERSION)
        );
        assert_eq!(
            status.runtime_schema_version,
            Some(RUNTIME_IPC_SCHEMA_VERSION)
        );
    }

    #[test]
    fn service_ipc_read_commands_are_allowlisted_for_client_envelopes() {
        let session = IpcSessionState {
            session_reference: "session-ref".to_string(),
            client_nonce: "client-nonce".to_string(),
            server_nonce: "server-nonce".to_string(),
            challenge_nonce: "challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };

        for command_id in ServiceReadCommandId::all() {
            let command = ServiceCommand::Read(*command_id);
            assert_eq!(
                ServiceCommand::parse(command.as_str()).expect("read command parses"),
                command
            );
            let envelope = IpcEnvelope::request(&session, command, json!({ "page_size": 1 }));
            assert_eq!(envelope.command_id, command_id.as_str());
            assert_eq!(envelope.response_status, "request");
        }
    }

    #[test]
    fn provider_controller_read_commands_are_read_only_ipc_only() {
        for command_id in [
            ServiceReadCommandId::GetProviderControllerStatus,
            ServiceReadCommandId::ListNetworkProviderStatus,
            ServiceReadCommandId::GetNetworkProviderStatus,
            ServiceReadCommandId::GetNetworkVisibilitySummary,
            ServiceReadCommandId::GetNetworkFallbackPlan,
        ] {
            let command = ServiceCommand::Read(command_id);
            assert_eq!(
                ServiceCommand::parse(command.as_str()).expect("provider read command parses"),
                command
            );
            let request = IpcRequest::new(command, json!({ "page_size": 1 }));
            assert_eq!(request.command, command_id.as_str());
        }

        for forbidden in [
            "activate_provider",
            "stop_provider",
            "sample_provider",
            "probe_npcap",
            "start_capture_broker",
            "change_provider_mode",
        ] {
            assert!(ServiceCommand::parse(forbidden).is_err());
        }
    }

    #[test]
    fn service_ipc_read_command_request_serializes_without_raw_cursor_or_secret_values() {
        let request = ServiceReadCommandRequest {
            page_size: Some(1),
            continuation_token: Some("read_page_1".to_string()),
        };
        let params = serde_json::to_value(request).expect("serialize read request");
        let serialized = serde_json::to_string(&params).expect("request json");
        let lowered = serialized.to_ascii_lowercase();

        assert!(lowered.contains("read_page_1"));
        assert!(!lowered.contains("raw_db_cursor"));
        assert!(!lowered.contains("select "));
        assert!(!lowered.contains("runtime_handle"));
        assert!(!lowered.contains("authorization_nonce"));
        assert!(!lowered.contains("secret"));
    }

    #[test]
    fn bounded_service_ipc_context_snapshot_admits_only_safe_fields() {
        let snapshot = ServiceIpcCapabilityContextSnapshot::from_status_and_capture(
            &StatusResult {
                service_status: "running".to_string(),
                connected_clients: 1,
                memory_usage_mb: 0.0,
                pid: 4242,
                runtime_ownership: None,
                runtime_ownership_status: None,
                runtime_protocol_version: None,
                runtime_schema_version: None,
                caller_verification_status: None,
                mutation_authorization_status: None,
                provider_controller_status: None,
            },
            &CaptureHealthResult {
                capture_active: false,
                packets_observed: 0,
                last_packet_at: None,
                adapter_state: "stub_inactive".to_string(),
            },
        )
        .expect("snapshot");

        assert_eq!(snapshot.contexts.len(), 4);
        assert!(snapshot
            .contexts
            .iter()
            .all(|context| context.validate_boundary().is_ok()));
        let serialized = serde_json::to_string(&snapshot.contexts).expect("serialize");
        for forbidden in [
            "pid",
            "processes",
            "connections",
            "path",
            "authorization",
            "cookie",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(forbidden),
                "snapshot leaked forbidden field {forbidden}"
            );
        }
    }

    #[test]
    fn service_ipc_context_snapshot_from_error_stays_degraded_and_redacted() {
        let snapshot =
            ServiceIpcCapabilityContextSnapshot::from_status_error(&ServiceIpcClientError {
                kind: ServiceIpcClientErrorKind::Unreachable,
                code: "service_unreachable".to_string(),
                message_redacted: "service pipe unavailable".to_string(),
                retryable: true,
            })
            .expect("snapshot");

        assert!(snapshot.degraded);
        assert!(snapshot.contexts.iter().all(|context| {
            matches!(
                context.status,
                ServiceCapabilityStatus::Disconnected | ServiceCapabilityStatus::Disabled
            )
        }));
        assert!(snapshot
            .contexts
            .iter()
            .all(|context| context.validate_boundary().is_ok()));
    }
}
