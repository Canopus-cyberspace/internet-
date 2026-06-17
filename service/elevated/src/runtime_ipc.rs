//! Runtime Named Pipe IPC stub for Task 550.
//!
//! This module is still metadata-only and STUB_ONLY: it exposes a local
//! request/response server for ping, service status, capture health, and a
//! process snapshot stub. It does not start capture, inspect packets, execute
//! response actions, render UI, or host plugins.

use sentinel_app_core::{
    IpHelperHandoffRequest, MutationAuthorizationEvaluator, MutationAuthorizationRuntimeContext,
    RuntimeContainer,
};
use sentinel_contracts::provider_controller::{
    NetworkProviderControllerStatus, NetworkProviderKind, NetworkProviderLifecycleState,
};
use sentinel_contracts::{
    build_service_read_command_response,
    caller_verification::{
        AllowedCommandClass, CallerCategory, CallerVerificationImplementationState,
        CallerVerificationReadStatus, CallerVerificationState, CallerVerificationSummary,
        ElevationCategory, LocalRemoteClassification, SessionBindingState,
        TokenSuitabilityCategory, VerificationFreshnessBucket, CALLER_VERIFICATION_SCHEMA_VERSION,
    },
    read_model_snapshot::CanonicalReadModelSnapshot,
    runtime_ownership::{RuntimeMode, RuntimeOwnershipSummary},
    EtwLifecycleStatus, IpHelperScheduleMutationRequest, MutationAuthorizationDecision,
    MutationAuthorizationStatus, MutationCapabilityCategory, MutationCommandId,
    MutationExecutionAuthorizationState, MutationExecutionCounters, MutationExecutionReceipt,
    MutationExecutionRequest, MutationExecutionResultCategory, MutationIntent,
    ProviderLifecycleCategory, RedactionStatus, SchemaVersion, ServiceReadCommandId,
    ServiceReadCommandRequest, Timestamp, IP_HELPER_SCHEDULE_SESSION_INVALIDATED,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashSet, VecDeque};
use std::env;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const SERVICE_NAME: &str = "SentinelGuardElevated";
pub const SERVICE_DISPLAY_NAME: &str = "Sentinel Guard Elevated Service";
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\SentinelGuardIpc";
pub const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const IPC_PROTOCOL_VERSION: u16 = 1;
pub const RUNTIME_IPC_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_PAYLOAD_BYTES: usize = 48 * 1024;
pub const PRODUCTION_MUTATION_COMMANDS_ENABLED: bool = true;
pub const IMPERSONATION_REVERT_FAILED_AUDIT_EVENT: &str = "impersonation_revert_failed";
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);
const READ_COMMAND_RATE_LIMIT: u32 = 120;
const REPLAY_CACHE_LIMIT: usize = 256;
const MAX_REQUESTS_PER_SESSION: u64 = 64;

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
    ActivateEtw,
    PauseEtw,
    ResumeEtw,
    StopEtw,
    ActivateDnsSensing,
    PauseDnsSensing,
    ResumeDnsSensing,
    StopDnsSensing,
    ActivateAuthRemoteSensing,
    PauseAuthRemoteSensing,
    ResumeAuthRemoteSensing,
    StopAuthRemoteSensing,
    ConfigureIpHelperSchedule,
    EnableIpHelperSchedule,
    PauseIpHelperSchedule,
    ResumeIpHelperSchedule,
    DisableIpHelperSchedule,
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
            Self::ActivateEtw => "activate_etw",
            Self::PauseEtw => "pause_etw",
            Self::ResumeEtw => "resume_etw",
            Self::StopEtw => "stop_etw",
            Self::ActivateDnsSensing => "activate_dns_sensing",
            Self::PauseDnsSensing => "pause_dns_sensing",
            Self::ResumeDnsSensing => "resume_dns_sensing",
            Self::StopDnsSensing => "stop_dns_sensing",
            Self::ActivateAuthRemoteSensing => "activate_auth_remote_sensing",
            Self::PauseAuthRemoteSensing => "pause_auth_remote_sensing",
            Self::ResumeAuthRemoteSensing => "resume_auth_remote_sensing",
            Self::StopAuthRemoteSensing => "stop_auth_remote_sensing",
            Self::ConfigureIpHelperSchedule => "configure_ip_helper_schedule",
            Self::EnableIpHelperSchedule => "enable_ip_helper_schedule",
            Self::PauseIpHelperSchedule => "pause_ip_helper_schedule",
            Self::ResumeIpHelperSchedule => "resume_ip_helper_schedule",
            Self::DisableIpHelperSchedule => "disable_ip_helper_schedule",
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
            "activate_etw" => Ok(Self::ActivateEtw),
            "pause_etw" => Ok(Self::PauseEtw),
            "resume_etw" => Ok(Self::ResumeEtw),
            "stop_etw" => Ok(Self::StopEtw),
            "activate_dns_sensing" => Ok(Self::ActivateDnsSensing),
            "pause_dns_sensing" => Ok(Self::PauseDnsSensing),
            "resume_dns_sensing" => Ok(Self::ResumeDnsSensing),
            "stop_dns_sensing" => Ok(Self::StopDnsSensing),
            "activate_auth_remote_sensing" => Ok(Self::ActivateAuthRemoteSensing),
            "pause_auth_remote_sensing" => Ok(Self::PauseAuthRemoteSensing),
            "resume_auth_remote_sensing" => Ok(Self::ResumeAuthRemoteSensing),
            "stop_auth_remote_sensing" => Ok(Self::StopAuthRemoteSensing),
            "configure_ip_helper_schedule" => Ok(Self::ConfigureIpHelperSchedule),
            "enable_ip_helper_schedule" => Ok(Self::EnableIpHelperSchedule),
            "pause_ip_helper_schedule" => Ok(Self::PauseIpHelperSchedule),
            "resume_ip_helper_schedule" => Ok(Self::ResumeIpHelperSchedule),
            "disable_ip_helper_schedule" => Ok(Self::DisableIpHelperSchedule),
            _ => ServiceReadCommandId::parse(value)
                .map(Self::Read)
                .map_err(|_| IpcError::command_not_allowed("command is not allowlisted")),
        }
    }

    fn allowed_command_class(self) -> AllowedCommandClass {
        match self {
            Self::Ping | Self::Status | Self::CaptureHealth | Self::ProcessSnapshot => {
                AllowedCommandClass::ReadStatus
            }
            Self::EvaluateMutationIntent => AllowedCommandClass::MutationAuthorizationEvaluation,
            Self::ActivateIpHelper
            | Self::SampleIpHelperOnce
            | Self::StopIpHelper
            | Self::ActivateEtw
            | Self::PauseEtw
            | Self::ResumeEtw
            | Self::StopEtw
            | Self::ActivateDnsSensing
            | Self::PauseDnsSensing
            | Self::ResumeDnsSensing
            | Self::StopDnsSensing
            | Self::ActivateAuthRemoteSensing
            | Self::PauseAuthRemoteSensing
            | Self::ResumeAuthRemoteSensing
            | Self::StopAuthRemoteSensing
            | Self::ConfigureIpHelperSchedule
            | Self::EnableIpHelperSchedule
            | Self::PauseIpHelperSchedule
            | Self::ResumeIpHelperSchedule
            | Self::DisableIpHelperSchedule => AllowedCommandClass::FutureUserMutationCandidate,
            Self::Read(_) => AllowedCommandClass::ReadCanonicalModels,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcAccessLevel {
    None,
    Read,
}

impl IpcAccessLevel {
    fn permits(self, required: Self) -> bool {
        matches!((self, required), (Self::Read, Self::Read))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcResponse<T = Value> {
    pub id: String,
    pub command: String,
    pub result: Option<T>,
    pub error: Option<IpcError>,
    pub timestamp: Timestamp,
}

impl IpcResponse<Value> {
    pub fn ok(request: &IpcRequest<Value>, result: Value) -> Self {
        Self {
            id: request.id.clone(),
            command: request.command.clone(),
            result: Some(result),
            error: None,
            timestamp: Timestamp::now(),
        }
    }

    pub fn error(request: &IpcRequest<Value>, error: IpcError) -> Self {
        Self {
            id: request.id.clone(),
            command: request.command.clone(),
            result: None,
            error: Some(error),
            timestamp: Timestamp::now(),
        }
    }

    pub fn malformed(error: IpcError) -> Self {
        Self {
            id: "malformed".to_string(),
            command: "unknown".to_string(),
            result: None,
            error: Some(error),
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

impl IpcError {
    pub fn schema(message: impl Into<String>) -> Self {
        Self {
            code: "SCHEMA_VALIDATION_ERROR".to_string(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn command_not_allowed(message: impl Into<String>) -> Self {
        Self {
            code: "COMMAND_NOT_ALLOWED".to_string(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn insufficient_level(message: impl Into<String>) -> Self {
        Self {
            code: "INSUFFICIENT_LEVEL".to_string(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self {
            code: "RATE_LIMITED".to_string(),
            message: message.into(),
            retryable: true,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: "SERVICE_ERROR".to_string(),
            message: message.into(),
            retryable: true,
        }
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self {
            code: "PROTOCOL_ERROR".to_string(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn replay(message: impl Into<String>) -> Self {
        Self {
            code: "REPLAY_REJECTED".to_string(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn invalid_sequence(message: impl Into<String>) -> Self {
        Self {
            code: "INVALID_SEQUENCE".to_string(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn caller_rejected(message: impl Into<String>) -> Self {
        Self {
            code: "CALLER_REJECTED".to_string(),
            message: message.into(),
            retryable: false,
        }
    }
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
        Self {
            protocol_version: IPC_PROTOCOL_VERSION,
            schema_version: RUNTIME_IPC_SCHEMA_VERSION,
            request_id: Uuid::new_v4().to_string(),
            session_reference: session.session_reference.clone(),
            client_nonce: session.client_nonce.clone(),
            server_nonce: session.server_nonce.clone(),
            sequence_number: 1,
            command_id: command.as_str().to_string(),
            response_status: "request".to_string(),
            payload,
        }
    }

    fn ok(request: &Self, payload: Value) -> Self {
        Self {
            protocol_version: IPC_PROTOCOL_VERSION,
            schema_version: RUNTIME_IPC_SCHEMA_VERSION,
            request_id: request.request_id.clone(),
            session_reference: request.session_reference.clone(),
            client_nonce: request.client_nonce.clone(),
            server_nonce: request.server_nonce.clone(),
            sequence_number: request.sequence_number,
            command_id: request.command_id.clone(),
            response_status: "ok".to_string(),
            payload,
        }
    }

    fn error(request: &Self, error: IpcError) -> Self {
        Self {
            protocol_version: IPC_PROTOCOL_VERSION,
            schema_version: RUNTIME_IPC_SCHEMA_VERSION,
            request_id: request.request_id.clone(),
            session_reference: request.session_reference.clone(),
            client_nonce: request.client_nonce.clone(),
            server_nonce: request.server_nonce.clone(),
            sequence_number: request.sequence_number,
            command_id: request.command_id.clone(),
            response_status: "error".to_string(),
            payload: serde_json::to_value(error).unwrap_or_else(|_| {
                json!({
                    "code": "SERVICE_ERROR",
                    "message": "failed to serialize bounded IPC error",
                    "retryable": true
                })
            }),
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
pub struct PingParams {
    pub nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyParams {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSnapshotParams {
    pub pid: Option<u32>,
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
    #[serde(default)]
    pub dns_sensing_lifecycle_status: Option<EtwLifecycleStatus>,
    #[serde(default)]
    pub auth_remote_sensing_lifecycle_status: Option<EtwLifecycleStatus>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandAllowlist {
    entries: Vec<(ServiceCommand, IpcAccessLevel)>,
}

impl CommandAllowlist {
    pub fn read_only_v1() -> Self {
        Self {
            entries: vec![
                (ServiceCommand::Ping, IpcAccessLevel::Read),
                (ServiceCommand::Status, IpcAccessLevel::Read),
                (ServiceCommand::CaptureHealth, IpcAccessLevel::Read),
                (ServiceCommand::ProcessSnapshot, IpcAccessLevel::Read),
                (ServiceCommand::EvaluateMutationIntent, IpcAccessLevel::Read),
                (ServiceCommand::ActivateIpHelper, IpcAccessLevel::Read),
                (ServiceCommand::SampleIpHelperOnce, IpcAccessLevel::Read),
                (ServiceCommand::StopIpHelper, IpcAccessLevel::Read),
                (ServiceCommand::ActivateEtw, IpcAccessLevel::Read),
                (ServiceCommand::PauseEtw, IpcAccessLevel::Read),
                (ServiceCommand::ResumeEtw, IpcAccessLevel::Read),
                (ServiceCommand::StopEtw, IpcAccessLevel::Read),
                (ServiceCommand::ActivateDnsSensing, IpcAccessLevel::Read),
                (ServiceCommand::PauseDnsSensing, IpcAccessLevel::Read),
                (ServiceCommand::ResumeDnsSensing, IpcAccessLevel::Read),
                (ServiceCommand::StopDnsSensing, IpcAccessLevel::Read),
                (
                    ServiceCommand::ActivateAuthRemoteSensing,
                    IpcAccessLevel::Read,
                ),
                (ServiceCommand::PauseAuthRemoteSensing, IpcAccessLevel::Read),
                (
                    ServiceCommand::ResumeAuthRemoteSensing,
                    IpcAccessLevel::Read,
                ),
                (ServiceCommand::StopAuthRemoteSensing, IpcAccessLevel::Read),
                (
                    ServiceCommand::ConfigureIpHelperSchedule,
                    IpcAccessLevel::Read,
                ),
                (ServiceCommand::EnableIpHelperSchedule, IpcAccessLevel::Read),
                (ServiceCommand::PauseIpHelperSchedule, IpcAccessLevel::Read),
                (ServiceCommand::ResumeIpHelperSchedule, IpcAccessLevel::Read),
                (
                    ServiceCommand::DisableIpHelperSchedule,
                    IpcAccessLevel::Read,
                ),
            ]
            .into_iter()
            .chain(
                ServiceReadCommandId::all()
                    .iter()
                    .copied()
                    .map(|command| (ServiceCommand::Read(command), IpcAccessLevel::Read)),
            )
            .collect(),
        }
    }

    pub fn ensure_allowed(
        &self,
        command: ServiceCommand,
        caller_level: IpcAccessLevel,
    ) -> Result<(), IpcError> {
        let Some((_, required)) = self.entries.iter().find(|(entry, _)| *entry == command) else {
            return Err(IpcError::command_not_allowed(format!(
                "command is not allowlisted: {}",
                command.as_str()
            )));
        };
        if !caller_level.permits(*required) {
            return Err(IpcError::insufficient_level(format!(
                "command requires {:?} access",
                required
            )));
        }
        Ok(())
    }
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

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceAuditRecord {
    timestamp: Timestamp,
    event_type: String,
    command: Option<String>,
    outcome: String,
    reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ServiceAuditLogger {
    path: PathBuf,
}

impl ServiceAuditLogger {
    pub fn program_data_default() -> Self {
        let mut root = env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        root.push("SentinelGuard");
        root.push("audit");
        root.push("service-ipc.jsonl");
        Self { path: root }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn log(
        &self,
        event_type: impl Into<String>,
        command: Option<&str>,
        outcome: impl Into<String>,
        reason: Option<&str>,
    ) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let record = ServiceAuditRecord {
            timestamp: Timestamp::now(),
            event_type: event_type.into(),
            command: command.map(ToOwned::to_owned),
            outcome: outcome.into(),
            reason: reason.map(ToOwned::to_owned),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, &record)?;
        file.write_all(b"\n")?;
        Ok(())
    }
}

#[derive(Debug)]
struct RateLimiter {
    window_started_at: Instant,
    recent: VecDeque<Instant>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            window_started_at: Instant::now(),
            recent: VecDeque::new(),
        }
    }

    fn check(&mut self, now: Instant) -> Result<(), IpcError> {
        if now.duration_since(self.window_started_at) > RATE_LIMIT_WINDOW {
            self.window_started_at = now;
            self.recent.clear();
        }
        while self
            .recent
            .front()
            .is_some_and(|seen| now.duration_since(*seen) > RATE_LIMIT_WINDOW)
        {
            self.recent.pop_front();
        }
        if self.recent.len() as u32 >= READ_COMMAND_RATE_LIMIT {
            return Err(IpcError::rate_limited("read command rate limit exceeded"));
        }
        self.recent.push_back(now);
        Ok(())
    }
}

#[derive(Debug)]
struct ReplayProtector {
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl ReplayProtector {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    fn remember_nonce(&mut self, field: &str, nonce: &str) -> Result<(), IpcError> {
        validate_safe_ipc_text(field, nonce)?;
        if !self.seen.insert(nonce.to_string()) {
            return Err(IpcError::replay("IPC nonce was already used"));
        }
        self.order.push_back(nonce.to_string());
        while self.order.len() > REPLAY_CACHE_LIMIT {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerVerificationPolicy {
    pub production_service_mode: bool,
    pub allow_administrators_for_read: bool,
    pub allow_foreground_development: bool,
}

impl CallerVerificationPolicy {
    pub fn service_mode() -> Self {
        Self {
            production_service_mode: true,
            allow_administrators_for_read: true,
            allow_foreground_development: false,
        }
    }

    pub fn foreground_mode() -> Self {
        Self {
            production_service_mode: false,
            allow_administrators_for_read: true,
            allow_foreground_development: false,
        }
    }

    #[cfg(test)]
    fn foreground_development_test() -> Self {
        Self {
            production_service_mode: false,
            allow_administrators_for_read: false,
            allow_foreground_development: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingIpcSessionState {
    session_reference: String,
    client_nonce: String,
    server_nonce: String,
    challenge_nonce: String,
}

#[derive(Debug)]
pub struct ServiceSchedulerWakeSignal {
    started_at: Instant,
    pending: Mutex<bool>,
    wake: Condvar,
}

impl ServiceSchedulerWakeSignal {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            pending: Mutex::new(false),
            wake: Condvar::new(),
        }
    }

    pub fn elapsed_millis(&self) -> u64 {
        self.started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64
    }

    pub fn notify(&self) {
        if let Ok(mut pending) = self.pending.lock() {
            *pending = true;
            self.wake.notify_all();
        }
    }

    pub fn wait(&self, timeout: Duration) {
        let Ok(mut pending) = self.pending.lock() else {
            std::thread::sleep(timeout);
            return;
        };
        if *pending {
            *pending = false;
            return;
        }
        let Ok((mut pending, _)) = self.wake.wait_timeout(pending, timeout) else {
            std::thread::sleep(timeout);
            return;
        };
        *pending = false;
    }
}

impl Default for ServiceSchedulerWakeSignal {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ServiceCommandDispatcher {
    started_at: Instant,
    connected_clients: u32,
    allowlist: CommandAllowlist,
    caller_level: IpcAccessLevel,
    audit_logger: ServiceAuditLogger,
    rate_limiter: RateLimiter,
    replay: ReplayProtector,
    runtime_ownership_status: Option<RuntimeOwnershipSummary>,
    canonical_read_model_snapshot: Option<CanonicalReadModelSnapshot>,
    runtime_container: Option<Arc<Mutex<RuntimeContainer>>>,
    scheduler_wake_signal: Option<Arc<ServiceSchedulerWakeSignal>>,
    caller_verification_policy: CallerVerificationPolicy,
    last_caller_verification: Option<CallerVerificationSummary>,
    active_session_reference: Option<String>,
    active_verification_ref: Option<String>,
    active_next_sequence_number: u64,
    mutation_authorization: MutationAuthorizationEvaluator,
}

impl ServiceCommandDispatcher {
    pub fn new(audit_logger: ServiceAuditLogger) -> Self {
        Self {
            started_at: Instant::now(),
            connected_clients: 0,
            allowlist: CommandAllowlist::read_only_v1(),
            caller_level: IpcAccessLevel::Read,
            audit_logger,
            rate_limiter: RateLimiter::new(),
            replay: ReplayProtector::new(),
            runtime_ownership_status: None,
            canonical_read_model_snapshot: None,
            runtime_container: None,
            scheduler_wake_signal: None,
            caller_verification_policy: CallerVerificationPolicy::service_mode(),
            last_caller_verification: None,
            active_session_reference: None,
            active_verification_ref: None,
            active_next_sequence_number: 1,
            mutation_authorization: MutationAuthorizationEvaluator::new(),
        }
    }

    pub fn with_caller_verification_policy(mut self, policy: CallerVerificationPolicy) -> Self {
        self.caller_verification_policy = policy;
        self
    }

    pub fn with_runtime_ownership_status(
        mut self,
        runtime_ownership_status: RuntimeOwnershipSummary,
    ) -> Self {
        self.runtime_ownership_status = Some(runtime_ownership_status);
        self
    }

    pub fn with_canonical_read_model_snapshot(
        mut self,
        snapshot: CanonicalReadModelSnapshot,
    ) -> Self {
        self.canonical_read_model_snapshot = Some(snapshot);
        self
    }

    pub fn with_runtime_container(mut self, container: RuntimeContainer) -> Self {
        self.runtime_ownership_status = Some(container.summary());
        if let Ok(snapshot) = container.canonical_read_model_snapshot() {
            self.canonical_read_model_snapshot = Some(snapshot);
        }
        self.runtime_container = Some(Arc::new(Mutex::new(container)));
        self
    }

    pub fn with_shared_runtime_container(
        mut self,
        container: Arc<Mutex<RuntimeContainer>>,
    ) -> Self {
        if let Ok(container_guard) = container.lock() {
            self.runtime_ownership_status = Some(container_guard.summary());
            if let Ok(snapshot) = container_guard.canonical_read_model_snapshot() {
                self.canonical_read_model_snapshot = Some(snapshot);
            }
        }
        self.runtime_container = Some(container);
        self
    }

    pub fn with_scheduler_wake_signal(mut self, signal: Arc<ServiceSchedulerWakeSignal>) -> Self {
        self.scheduler_wake_signal = Some(signal);
        self
    }

    pub fn take_runtime_container(&mut self) -> Option<RuntimeContainer> {
        let container = self.runtime_container.take()?;
        match Arc::try_unwrap(container) {
            Ok(mutex) => mutex.into_inner().ok(),
            Err(shared) => {
                self.runtime_container = Some(shared);
                None
            }
        }
    }

    pub fn shutdown_runtime_container_in_place(
        &mut self,
    ) -> Result<Option<RuntimeOwnershipSummary>, String> {
        let Some(container_handle) = self.runtime_container.as_ref().cloned() else {
            return Ok(None);
        };
        let mut container = container_handle
            .lock()
            .map_err(|_| "servicehost runtime container lock unavailable".to_string())?;
        container
            .shutdown_before_ipc_close()
            .map_err(|error| error.message)?;
        let summary = container
            .complete_shutdown_after_ipc_close()
            .map_err(|error| error.message)?;
        self.runtime_ownership_status = Some(summary.clone());
        Ok(Some(summary))
    }

    fn kick_due_ip_helper_scheduler_cycle(&self) -> String {
        let (Some(container_handle), Some(signal)) = (
            self.runtime_container.as_ref().cloned(),
            self.scheduler_wake_signal.as_ref().cloned(),
        ) else {
            return "ip_helper_scheduler_wake_assist_unavailable".to_string();
        };
        let elapsed_millis = signal.elapsed_millis();
        let Ok(mut container) = container_handle.lock() else {
            return "ip_helper_scheduler_wake_assist_lock_unavailable".to_string();
        };
        if container.ip_helper_scheduler_wait_millis(elapsed_millis) == Some(0) {
            let owner_context = container.owner_context().clone();
            return match container.run_due_ip_helper_schedule_cycle(&owner_context, elapsed_millis)
            {
                Ok(cycle)
                    if cycle.execution_result
                        == sentinel_contracts::IpHelperScheduledExecutionResult::Completed =>
                {
                    "ip_helper_scheduler_wake_assist_completed".to_string()
                }
                Ok(_) => "ip_helper_scheduler_wake_assist_skipped".to_string(),
                Err(error) => {
                    let reason = error
                        .details_redacted
                        .as_ref()
                        .and_then(|details| details.get("reason_category"))
                        .and_then(Value::as_str)
                        .map(safe_wake_assist_reason)
                        .unwrap_or_else(|| safe_wake_assist_reason(&error.message));
                    format!(
                        "ip_helper_scheduler_wake_assist_failed_{}_{}",
                        error.error_code.to_string().to_ascii_lowercase(),
                        reason
                    )
                }
            };
        }
        "ip_helper_scheduler_wake_assist_not_due".to_string()
    }

    fn begin_session<RW>(&mut self, stream: &mut RW) -> Result<PendingIpcSessionState, IpcError>
    where
        RW: Read + Write,
    {
        let hello: IpcClientHello = read_json_frame(stream)
            .map_err(|error| IpcError::protocol(format!("client hello failed: {error}")))?;
        if hello.message_type != "client_hello" {
            return Err(IpcError::protocol("expected client_hello"));
        }
        if !hello
            .supported_protocol_versions
            .contains(&IPC_PROTOCOL_VERSION)
        {
            return Err(IpcError::protocol("unsupported IPC protocol version"));
        }
        if hello.schema_version != RUNTIME_IPC_SCHEMA_VERSION {
            return Err(IpcError::protocol("unsupported IPC schema version"));
        }
        self.replay
            .remember_nonce("client_nonce", &hello.client_nonce)?;
        for capability in &hello.requested_capabilities {
            validate_safe_ipc_text("requested_capability", capability)?;
        }

        let session = PendingIpcSessionState {
            session_reference: Uuid::new_v4().to_string(),
            client_nonce: hello.client_nonce,
            server_nonce: Uuid::new_v4().to_string(),
            challenge_nonce: Uuid::new_v4().to_string(),
        };
        self.replay
            .remember_nonce("server_nonce", &session.server_nonce)?;
        self.replay
            .remember_nonce("challenge_nonce", &session.challenge_nonce)?;

        let server_hello = IpcServerHello {
            message_type: "server_hello".to_string(),
            protocol_version: IPC_PROTOCOL_VERSION,
            schema_version: RUNTIME_IPC_SCHEMA_VERSION,
            challenge_nonce: session.challenge_nonce.clone(),
            server_nonce: session.server_nonce.clone(),
            session_reference: session.session_reference.clone(),
            accepted_capabilities: vec![
                "read_only_status".to_string(),
                "read_only_canonical_snapshots".to_string(),
                "mutation_authorization_dry_run".to_string(),
            ],
            max_frame_bytes: MAX_FRAME_BYTES,
            max_payload_bytes: MAX_PAYLOAD_BYTES,
        };
        write_json_frame(stream, &server_hello)
            .map_err(|error| IpcError::protocol(format!("server hello failed: {error}")))?;

        Ok(session)
    }

    fn complete_session<RW>(
        &mut self,
        stream: &mut RW,
        pending: PendingIpcSessionState,
        caller_verification: CallerVerificationSummary,
    ) -> Result<IpcSessionState, IpcError>
    where
        RW: Read + Write,
    {
        caller_verification
            .validate()
            .map_err(|error| IpcError::caller_rejected(error.to_string()))?;
        if caller_verification.session_binding_state != SessionBindingState::Bound
            || caller_verification.freshness_bucket
                != VerificationFreshnessBucket::CurrentConnection
        {
            return Err(IpcError::caller_rejected("session_binding_failed"));
        }
        let session = IpcSessionState {
            session_reference: pending.session_reference,
            client_nonce: pending.client_nonce,
            server_nonce: pending.server_nonce,
            challenge_nonce: pending.challenge_nonce,
            caller_verification,
        };
        let verify: IpcClientVerify = read_json_frame(stream)
            .map_err(|error| IpcError::protocol(format!("client verify failed: {error}")))?;
        validate_client_verify(&session, &verify)?;
        if !session.caller_verification.permits_read_only_commands() {
            return Err(IpcError::caller_rejected(format!(
                "caller verification state: {:?}",
                session.caller_verification.verification_state
            )));
        }

        let server_verify = IpcServerVerify {
            message_type: "server_verify".to_string(),
            protocol_version: IPC_PROTOCOL_VERSION,
            schema_version: RUNTIME_IPC_SCHEMA_VERSION,
            session_reference: session.session_reference.clone(),
            response_status: "ok".to_string(),
            caller_verification: session.caller_verification.clone(),
            session_nonce: Uuid::new_v4().to_string(),
        };
        write_json_frame(stream, &server_verify)
            .map_err(|error| IpcError::protocol(format!("server verify failed: {error}")))?;
        self.active_session_reference = Some(session.session_reference.clone());
        self.active_verification_ref = Some(session.caller_verification.verification_ref.clone());
        self.active_next_sequence_number = 1;
        self.last_caller_verification = Some(session.caller_verification.clone());

        Ok(session)
    }

    pub fn dispatch_envelope(
        &mut self,
        session: &IpcSessionState,
        envelope: IpcEnvelope<Value>,
    ) -> IpcEnvelope<Value> {
        if self.active_session_reference.as_deref() != Some(session.session_reference.as_str())
            || self.active_verification_ref.as_deref()
                != Some(session.caller_verification.verification_ref.as_str())
        {
            return IpcEnvelope::error(
                &envelope,
                IpcError::caller_rejected("caller verification is not active for this connection"),
            );
        }
        if !session.caller_verification.permits_read_only_commands() {
            return IpcEnvelope::error(
                &envelope,
                IpcError::caller_rejected("caller verification is not valid for this session"),
            );
        }
        if let Err(error) =
            validate_request_envelope(session, &envelope, self.active_next_sequence_number)
        {
            return IpcEnvelope::error(&envelope, error);
        }
        self.active_next_sequence_number = self.active_next_sequence_number.saturating_add(1);
        if let Err(error) = self
            .replay
            .remember_nonce("request_id", &envelope.request_id)
        {
            return IpcEnvelope::error(&envelope, error);
        }
        let command = match ServiceCommand::parse(&envelope.command_id) {
            Ok(command) => command,
            Err(error) => return IpcEnvelope::error(&envelope, error),
        };
        if !session
            .caller_verification
            .permits_command_class(command.allowed_command_class())
        {
            return IpcEnvelope::error(
                &envelope,
                IpcError::caller_rejected("caller is not authorized for the command class"),
            );
        }
        if command == ServiceCommand::EvaluateMutationIntent {
            return self.evaluate_mutation_intent(session, &envelope);
        }
        if matches!(
            command,
            ServiceCommand::ActivateIpHelper
                | ServiceCommand::SampleIpHelperOnce
                | ServiceCommand::StopIpHelper
        ) {
            return self.execute_ip_helper_mutation(session, &envelope, command);
        }
        if matches!(
            command,
            ServiceCommand::ActivateEtw
                | ServiceCommand::PauseEtw
                | ServiceCommand::ResumeEtw
                | ServiceCommand::StopEtw
        ) {
            return self.execute_etw_mutation(session, &envelope, command);
        }
        if matches!(
            command,
            ServiceCommand::ActivateDnsSensing
                | ServiceCommand::PauseDnsSensing
                | ServiceCommand::ResumeDnsSensing
                | ServiceCommand::StopDnsSensing
                | ServiceCommand::ActivateAuthRemoteSensing
                | ServiceCommand::PauseAuthRemoteSensing
                | ServiceCommand::ResumeAuthRemoteSensing
                | ServiceCommand::StopAuthRemoteSensing
        ) {
            return self.execute_etw_mutation(session, &envelope, command);
        }
        if matches!(
            command,
            ServiceCommand::ConfigureIpHelperSchedule
                | ServiceCommand::EnableIpHelperSchedule
                | ServiceCommand::PauseIpHelperSchedule
                | ServiceCommand::ResumeIpHelperSchedule
                | ServiceCommand::DisableIpHelperSchedule
        ) {
            return self.execute_ip_helper_schedule_mutation(session, &envelope, command);
        }
        if matches!(command, ServiceCommand::Status | ServiceCommand::Read(_)) {
            self.refresh_runtime_snapshots_from_container();
        }
        let request = IpcRequest {
            id: envelope.request_id.clone(),
            command: command.as_str().to_string(),
            params: envelope.payload.clone(),
            timestamp: Timestamp::now(),
        };
        let response = self.dispatch(request);
        match response.error {
            Some(error) => IpcEnvelope::error(&envelope, error),
            None => {
                let payload = response.result.unwrap_or_else(|| json!({}));
                if let Err(error) = enforce_payload_size_limit(&payload) {
                    return IpcEnvelope::error(&envelope, error);
                }
                IpcEnvelope::ok(&envelope, payload)
            }
        }
    }

    pub fn dispatch(&mut self, request: IpcRequest<Value>) -> IpcResponse<Value> {
        let command = match ServiceCommand::parse(&request.command) {
            Ok(command) => command,
            Err(error) => {
                let _ = self.audit_logger.log(
                    "command_rejected",
                    None,
                    "rejected",
                    Some(error.code.as_str()),
                );
                return IpcResponse::error(&request, error);
            }
        };
        let command_name = command.as_str();
        let _ = self
            .audit_logger
            .log("command_received", Some(command_name), "received", None);

        if let Err(error) = self.allowlist.ensure_allowed(command, self.caller_level) {
            let _ = self.audit_logger.log(
                "command_rejected",
                Some(command_name),
                "rejected",
                Some(error.code.as_str()),
            );
            return IpcResponse::error(&request, error);
        }
        if let Err(error) = self.rate_limiter.check(Instant::now()) {
            let _ = self.audit_logger.log(
                "command_rejected",
                Some(command_name),
                "rejected",
                Some(error.code.as_str()),
            );
            return IpcResponse::error(&request, error);
        }

        let result = match command {
            ServiceCommand::Ping => self.handle_ping(&request.params),
            ServiceCommand::Status => self.handle_status(&request.params),
            ServiceCommand::CaptureHealth => self.handle_capture_health(&request.params),
            ServiceCommand::ProcessSnapshot => self.handle_process_snapshot(&request.params),
            ServiceCommand::EvaluateMutationIntent => Err(IpcError::caller_rejected(
                "mutation authorization evaluation requires a verified IPC session",
            )),
            ServiceCommand::ActivateIpHelper
            | ServiceCommand::SampleIpHelperOnce
            | ServiceCommand::StopIpHelper
            | ServiceCommand::ActivateEtw
            | ServiceCommand::PauseEtw
            | ServiceCommand::ResumeEtw
            | ServiceCommand::StopEtw
            | ServiceCommand::ActivateDnsSensing
            | ServiceCommand::PauseDnsSensing
            | ServiceCommand::ResumeDnsSensing
            | ServiceCommand::StopDnsSensing
            | ServiceCommand::ActivateAuthRemoteSensing
            | ServiceCommand::PauseAuthRemoteSensing
            | ServiceCommand::ResumeAuthRemoteSensing
            | ServiceCommand::StopAuthRemoteSensing => Err(IpcError::caller_rejected(
                "provider execution requires a verified IPC session and execution authorization",
            )),
            ServiceCommand::ConfigureIpHelperSchedule
            | ServiceCommand::EnableIpHelperSchedule
            | ServiceCommand::PauseIpHelperSchedule
            | ServiceCommand::ResumeIpHelperSchedule
            | ServiceCommand::DisableIpHelperSchedule => Err(IpcError::caller_rejected(
                "schedule mutation requires a verified IPC session and execution authorization",
            )),
            ServiceCommand::Read(command_id) => {
                self.handle_read_command(command_id, &request.params)
            }
        };

        match result {
            Ok(result) => {
                let _ = self
                    .audit_logger
                    .log("command_completed", Some(command_name), "ok", None);
                IpcResponse::ok(&request, result)
            }
            Err(error) => {
                let _ = self.audit_logger.log(
                    "command_rejected",
                    Some(command_name),
                    "rejected",
                    Some(error.code.as_str()),
                );
                IpcResponse::error(&request, error)
            }
        }
    }

    pub fn connection_accepted(&mut self) {
        self.connected_clients = self.connected_clients.saturating_add(1);
        let _ = self
            .audit_logger
            .log("ipc_connection_accepted", None, "accepted", None);
    }

    pub fn connection_closed(&mut self) {
        self.connected_clients = self.connected_clients.saturating_sub(1);
        if let Some(session_ref) = self.active_session_reference.as_deref() {
            self.mutation_authorization.invalidate_session(session_ref);
        }
        if let Some(container_handle) = self.runtime_container.as_ref().cloned() {
            if let Ok(mut container) = container_handle.lock() {
                let owner_context = container.owner_context().clone();
                match container.invalidate_ip_helper_schedule_for_session_end(
                    &owner_context,
                    IP_HELPER_SCHEDULE_SESSION_INVALIDATED,
                    "ipc_session_closed",
                ) {
                    Ok(Some(_status)) => {
                        self.runtime_ownership_status = Some(container.summary());
                        if let Ok(snapshot) = container.canonical_read_model_snapshot() {
                            self.canonical_read_model_snapshot = Some(snapshot);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let _ = self.audit_logger.log(
                            "ip_helper_schedule_session_invalidation_failed",
                            None,
                            "rejected",
                            Some(error.message.as_str()),
                        );
                    }
                }
            } else {
                let _ = self.audit_logger.log(
                    "ip_helper_schedule_session_invalidation_failed",
                    None,
                    "rejected",
                    Some("runtime_container_lock_unavailable"),
                );
            }
        }
        if let Some(signal) = &self.scheduler_wake_signal {
            signal.notify();
        }
        self.active_session_reference = None;
        self.active_verification_ref = None;
        self.active_next_sequence_number = 1;
        if let Some(summary) = &mut self.last_caller_verification {
            summary.session_binding_state = SessionBindingState::Expired;
            summary.freshness_bucket = VerificationFreshnessBucket::Expired;
            summary.allowed_command_classes = vec![AllowedCommandClass::None];
        }
        let _ = self.audit_logger.log(
            "caller_verification_expired",
            None,
            "expired",
            Some("connection_closed"),
        );
    }

    pub fn caller_verification_read_status(&self) -> CallerVerificationReadStatus {
        let implementation = if cfg!(windows) {
            CallerVerificationImplementationState::Implemented
        } else {
            CallerVerificationImplementationState::UnsupportedPlatform
        };
        CallerVerificationReadStatus {
            schema_version: CALLER_VERIFICATION_SCHEMA_VERSION,
            caller_impersonation: implementation,
            token_classification: implementation,
            production_mutation_authorization: implementation,
            production_mutations_enabled: PRODUCTION_MUTATION_COMMANDS_ENABLED,
            production_service_mode_policy: if self
                .caller_verification_policy
                .production_service_mode
            {
                "strict_local_token_verification".to_string()
            } else {
                "not_production_service_mode".to_string()
            },
            foreground_development_policy: if self
                .caller_verification_policy
                .allow_foreground_development
            {
                "explicit_test_only".to_string()
            } else {
                "disabled_by_default".to_string()
            },
            remote_caller_rejection_enabled: true,
            network_logon_rejection_enabled: true,
            session_binding_enabled: true,
            last_verification: self.last_caller_verification.clone(),
            audit_refs: vec!["caller_verification_audit".to_string()],
            provenance_id: "servicehost_named_pipe_caller_verification".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn mutation_authorization_status(&self) -> MutationAuthorizationStatus {
        let caller_trust_ready = self
            .last_caller_verification
            .as_ref()
            .is_some_and(|summary| {
                summary.session_binding_state == SessionBindingState::Bound
                    && summary.freshness_bucket == VerificationFreshnessBucket::CurrentConnection
            });
        let ownership_runtime_ready =
            self.runtime_ownership_status
                .as_ref()
                .is_some_and(|status| {
                    status.runtime_mode == RuntimeMode::ServiceOwned && status.ownership_epoch > 0
                });
        self.mutation_authorization
            .status(caller_trust_ready, ownership_runtime_ready)
    }

    fn evaluate_mutation_intent(
        &mut self,
        session: &IpcSessionState,
        envelope: &IpcEnvelope<Value>,
    ) -> IpcEnvelope<Value> {
        if let Err(error) = self.audit_logger.log(
            "mutation_intent_received",
            Some(ServiceCommand::EvaluateMutationIntent.as_str()),
            "received",
            None,
        ) {
            return IpcEnvelope::error(envelope, IpcError::internal(error.to_string()));
        }
        let intent: MutationIntent = match serde_json::from_value(envelope.payload.clone()) {
            Ok(intent) => intent,
            Err(_) => {
                let _ = self.audit_logger.log(
                    "mutation_intent_rejected",
                    Some(ServiceCommand::EvaluateMutationIntent.as_str()),
                    "rejected",
                    Some("invalid_intent_contract"),
                );
                return IpcEnvelope::error(
                    envelope,
                    IpcError::schema("mutation intent contract is invalid"),
                );
            }
        };
        if let Err(error) = intent.validate() {
            let _ = self.audit_logger.log(
                "mutation_intent_rejected",
                Some(ServiceCommand::EvaluateMutationIntent.as_str()),
                "rejected",
                Some("intent_validation_failed"),
            );
            return IpcEnvelope::error(envelope, IpcError::schema(error.to_string()));
        }
        if self
            .audit_logger
            .log(
                "mutation_policy_loaded",
                Some(intent.command_id.as_str()),
                "loaded",
                None,
            )
            .is_err()
        {
            return IpcEnvelope::error(
                envelope,
                IpcError::internal("mutation authorization audit unavailable"),
            );
        }
        let mut context = self
            .runtime_ownership_status
            .as_ref()
            .map(|summary| {
                MutationAuthorizationRuntimeContext::from_runtime_summary(
                    session.session_reference.clone(),
                    summary,
                )
            })
            .unwrap_or_else(|| {
                MutationAuthorizationRuntimeContext::unavailable(session.session_reference.clone())
            });
        if let Some(container_handle) = self.runtime_container.as_ref() {
            if let Ok(container) = container_handle.lock() {
                context.etw_state = container.etw_mutation_capability_state();
                context.auth_remote_state = container.auth_remote_mutation_capability_state();
            }
        }
        let decision =
            self.mutation_authorization
                .evaluate(&intent, &session.caller_verification, &context);
        let terminal_event = match decision.result {
            sentinel_contracts::MutationAuthorizationResult::ApprovedDryRun => {
                "mutation_authorization_approved_dry_run"
            }
            sentinel_contracts::MutationAuthorizationResult::ApprovedForExecution => {
                "mutation_authorization_approved_for_execution"
            }
            sentinel_contracts::MutationAuthorizationResult::Expired => "mutation_intent_expired",
            sentinel_contracts::MutationAuthorizationResult::ReplayRejected => {
                "mutation_replay_rejected"
            }
            sentinel_contracts::MutationAuthorizationResult::SessionMismatch => {
                "mutation_session_mismatch"
            }
            sentinel_contracts::MutationAuthorizationResult::OwnershipEpochMismatch => {
                "mutation_ownership_epoch_mismatch"
            }
            _ => "mutation_authorization_denied",
        };
        if self
            .audit_logger
            .log(
                terminal_event,
                Some(intent.command_id.as_str()),
                "evaluated",
                decision.degraded_reason.as_deref(),
            )
            .is_err()
        {
            return IpcEnvelope::error(
                envelope,
                IpcError::internal("mutation authorization audit unavailable"),
            );
        }
        if decision.result == sentinel_contracts::MutationAuthorizationResult::ApprovedDryRun {
            let _ = self.audit_logger.log(
                "mutation_execution_blocked",
                Some(intent.command_id.as_str()),
                "blocked",
                Some("dry_run_terminal_gate"),
            );
        } else if decision.result
            == sentinel_contracts::MutationAuthorizationResult::ApprovedForExecution
        {
            let event = provider_authorized_event(intent.command_id);
            let _ = self.audit_logger.log(
                event,
                Some(intent.command_id.as_str()),
                "authorized",
                Some("single_use_execution_authorization"),
            );
        }
        match serde_json::to_value::<MutationAuthorizationDecision>(decision) {
            Ok(payload) => IpcEnvelope::ok(envelope, payload),
            Err(error) => IpcEnvelope::error(envelope, IpcError::internal(error.to_string())),
        }
    }

    fn execute_ip_helper_mutation(
        &mut self,
        session: &IpcSessionState,
        envelope: &IpcEnvelope<Value>,
        service_command: ServiceCommand,
    ) -> IpcEnvelope<Value> {
        let expected_command = match ip_helper_mutation_command_id(service_command) {
            Some(command) => command,
            None => {
                return IpcEnvelope::error(
                    envelope,
                    IpcError::command_not_allowed("provider command is not execution-enabled"),
                )
            }
        };
        let execution_request: MutationExecutionRequest =
            match serde_json::from_value(envelope.payload.clone()) {
                Ok(request) => request,
                Err(_) => {
                    let _ = self.audit_logger.log(
                        "ip_helper_execution_rejected",
                        Some(service_command.as_str()),
                        "rejected",
                        Some("invalid_execution_request_contract"),
                    );
                    return IpcEnvelope::error(
                        envelope,
                        IpcError::schema("mutation execution request contract is invalid"),
                    );
                }
            };
        if let Err(error) = execution_request.validate() {
            let _ = self.audit_logger.log(
                "ip_helper_execution_rejected",
                Some(service_command.as_str()),
                "rejected",
                Some("execution_request_validation_failed"),
            );
            return IpcEnvelope::error(envelope, IpcError::schema(error.to_string()));
        }
        let current_epoch = self
            .runtime_ownership_status
            .as_ref()
            .map(|summary| summary.ownership_epoch)
            .unwrap_or_default();
        let decision = match self.mutation_authorization.consume_execution_authorization(
            &execution_request,
            &session.session_reference,
            expected_command,
            current_epoch,
        ) {
            Ok(decision) => decision,
            Err(reason) => {
                let _ = self.audit_logger.log(
                    reason,
                    Some(expected_command.as_str()),
                    "rejected",
                    Some(reason),
                );
                return IpcEnvelope::error(envelope, IpcError::caller_rejected(reason));
            }
        };
        let _ = self.audit_logger.log(
            ip_helper_started_event(expected_command),
            Some(expected_command.as_str()),
            "started",
            Some("single_use_execution_authorization_consumed"),
        );

        let previous_lifecycle = self.ip_helper_lifecycle_category();
        let execution_ref = format!("ip_helper_execution_{}", Uuid::new_v4());
        let mut batch_refs = Vec::new();
        let mut fact_refs = Vec::new();
        let mut counters = MutationExecutionCounters::default();
        let mut degraded_reason = None;
        let (result_category, resulting_lifecycle) = {
            let Some(container_handle) = self.runtime_container.as_ref().cloned() else {
                return IpcEnvelope::error(
                    envelope,
                    IpcError::internal("servicehost runtime container unavailable"),
                );
            };
            let Ok(mut container) = container_handle.lock() else {
                return IpcEnvelope::error(
                    envelope,
                    IpcError::internal("servicehost runtime container lock unavailable"),
                );
            };
            let owner_context = container.owner_context().clone();
            if owner_context.ownership_epoch != decision.ownership_epoch {
                let _ = self.audit_logger.log(
                    "ip_helper_execution_epoch_rejected",
                    Some(expected_command.as_str()),
                    "rejected",
                    Some("ownership_epoch_changed"),
                );
                return IpcEnvelope::error(
                    envelope,
                    IpcError::caller_rejected("ip_helper_execution_epoch_rejected"),
                );
            }
            let execution = match expected_command {
                MutationCommandId::ActivateIpHelperProvider => container
                    .activate_ip_helper_provider(&owner_context)
                    .map(|status| ProviderExecutionOutcome::Status(Box::new(status))),
                MutationCommandId::SampleIpHelperNow => container
                    .execute_ip_helper_servicehost_handoff(
                        &owner_context,
                        IpHelperHandoffRequest::production_ipc(),
                    )
                    .map(|result| ProviderExecutionOutcome::Sample(Box::new(result))),
                MutationCommandId::StopIpHelper => container
                    .stop_ip_helper_provider(&owner_context)
                    .map(|status| ProviderExecutionOutcome::Status(Box::new(status))),
                _ => Err(sentinel_contracts::CoreError::new(
                    sentinel_contracts::ErrorCode::UnsupportedOperation,
                    "unsupported ip helper command",
                )),
            };
            match execution {
                Ok(ProviderExecutionOutcome::Status(status)) => {
                    let resulting = lifecycle_from_status(&status);
                    (
                        if previous_lifecycle == resulting
                            && matches!(
                                expected_command,
                                MutationCommandId::ActivateIpHelperProvider
                                    | MutationCommandId::StopIpHelper
                            )
                        {
                            MutationExecutionResultCategory::AlreadySatisfied
                        } else {
                            MutationExecutionResultCategory::Completed
                        },
                        resulting,
                    )
                }
                Ok(ProviderExecutionOutcome::Sample(result)) => {
                    batch_refs.push(result.batch.batch_ref.clone());
                    fact_refs.extend(
                        result
                            .batch
                            .fact_refs
                            .iter()
                            .take(sentinel_contracts::MAX_MUTATION_AUTHORIZATION_REFS)
                            .map(ToString::to_string),
                    );
                    counters.sampled_count = 1;
                    (
                        MutationExecutionResultCategory::Completed,
                        ProviderLifecycleCategory::Active,
                    )
                }
                Err(_) => {
                    counters.rejected_count = 1;
                    degraded_reason = Some("provider_execution_failed".to_string());
                    (
                        MutationExecutionResultCategory::Failed,
                        self.ip_helper_lifecycle_category(),
                    )
                }
            }
        };
        self.refresh_runtime_snapshots_from_container();

        let canonical_snapshot_refs = self
            .canonical_read_model_snapshot
            .as_ref()
            .map(|snapshot| vec![snapshot.snapshot_id.to_string()])
            .unwrap_or_default();
        let audit_event = match result_category {
            MutationExecutionResultCategory::Completed
            | MutationExecutionResultCategory::AlreadySatisfied => {
                ip_helper_completed_event(expected_command)
            }
            MutationExecutionResultCategory::TimedOut => "ip_helper_sample_timed_out",
            MutationExecutionResultCategory::Cancelled => "ip_helper_sample_cancelled",
            _ => ip_helper_failed_event(expected_command),
        };
        let _ = self.audit_logger.log(
            audit_event,
            Some(expected_command.as_str()),
            "completed",
            degraded_reason.as_deref(),
        );
        if let Some(signal) = &self.scheduler_wake_signal {
            signal.notify();
        }
        let receipt = MutationExecutionReceipt {
            schema_version: sentinel_contracts::MUTATION_AUTHORIZATION_SCHEMA_VERSION,
            execution_ref,
            authorization_decision_ref: decision.decision_ref,
            intent_ref: execution_request.intent.intent_ref,
            request_ref: execution_request.intent.request_ref,
            command_id: expected_command,
            policy_ref: execution_request.intent.policy_ref,
            policy_version: execution_request.intent.policy_version,
            ownership_epoch: decision.ownership_epoch,
            provider_category: MutationCapabilityCategory::IpHelperProvider,
            previous_lifecycle_state: previous_lifecycle,
            resulting_lifecycle_state: resulting_lifecycle,
            authorization_state: match result_category {
                MutationExecutionResultCategory::Completed => {
                    MutationExecutionAuthorizationState::ExecutionCompleted
                }
                MutationExecutionResultCategory::AlreadySatisfied => {
                    MutationExecutionAuthorizationState::AlreadySatisfied
                }
                MutationExecutionResultCategory::TimedOut => {
                    MutationExecutionAuthorizationState::ExecutionTimedOut
                }
                MutationExecutionResultCategory::Cancelled => {
                    MutationExecutionAuthorizationState::ExecutionCancelled
                }
                MutationExecutionResultCategory::Rejected => {
                    MutationExecutionAuthorizationState::ExecutionRejected
                }
                MutationExecutionResultCategory::Failed => {
                    MutationExecutionAuthorizationState::ExecutionFailed
                }
            },
            result_category,
            started_time_bucket: "current_connection".to_string(),
            completed_time_bucket: "current_connection".to_string(),
            duration_bucket: "bounded_under_timeout".to_string(),
            counters,
            batch_refs,
            fact_refs,
            canonical_snapshot_refs,
            audit_refs: vec![
                provider_authorized_event(expected_command).to_string(),
                ip_helper_started_event(expected_command).to_string(),
                audit_event.to_string(),
            ],
            degraded_reason,
            provenance_id: "servicehost_ip_helper_production_ipc".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        if let Err(error) = receipt.validate() {
            return IpcEnvelope::error(envelope, IpcError::schema(error.to_string()));
        }
        match serde_json::to_value(receipt) {
            Ok(payload) => IpcEnvelope::ok(envelope, payload),
            Err(error) => IpcEnvelope::error(envelope, IpcError::internal(error.to_string())),
        }
    }

    fn execute_etw_mutation(
        &mut self,
        session: &IpcSessionState,
        envelope: &IpcEnvelope<Value>,
        service_command: ServiceCommand,
    ) -> IpcEnvelope<Value> {
        let expected_command = match etw_mutation_command_id(service_command) {
            Some(command) => command,
            None => {
                return IpcEnvelope::error(
                    envelope,
                    IpcError::command_not_allowed("ETW command is not execution-enabled"),
                )
            }
        };
        let execution_request: MutationExecutionRequest =
            match serde_json::from_value(envelope.payload.clone()) {
                Ok(request) => request,
                Err(_) => {
                    let _ = self.audit_logger.log(
                        "etw_execution_rejected",
                        Some(service_command.as_str()),
                        "rejected",
                        Some("invalid_execution_request_contract"),
                    );
                    return IpcEnvelope::error(
                        envelope,
                        IpcError::schema("mutation execution request contract is invalid"),
                    );
                }
            };
        if let Err(error) = execution_request.validate() {
            let _ = self.audit_logger.log(
                "etw_execution_rejected",
                Some(service_command.as_str()),
                "rejected",
                Some("execution_request_validation_failed"),
            );
            return IpcEnvelope::error(envelope, IpcError::schema(error.to_string()));
        }
        let current_epoch = self
            .runtime_ownership_status
            .as_ref()
            .map(|summary| summary.ownership_epoch)
            .unwrap_or_default();
        let decision = match self.mutation_authorization.consume_execution_authorization(
            &execution_request,
            &session.session_reference,
            expected_command,
            current_epoch,
        ) {
            Ok(decision) => decision,
            Err(reason) => {
                let _ = self.audit_logger.log(
                    reason,
                    Some(expected_command.as_str()),
                    "rejected",
                    Some(reason),
                );
                return IpcEnvelope::error(envelope, IpcError::caller_rejected(reason));
            }
        };
        let started_event = etw_started_event(expected_command);
        let _ = self.audit_logger.log(
            started_event,
            Some(expected_command.as_str()),
            "started",
            Some("single_use_execution_authorization_consumed"),
        );

        let dns_sensing_command = matches!(
            expected_command,
            MutationCommandId::ActivateDnsSensing
                | MutationCommandId::PauseDnsSensing
                | MutationCommandId::ResumeDnsSensing
                | MutationCommandId::StopDnsSensing
        );
        let auth_remote_sensing_command = matches!(
            expected_command,
            MutationCommandId::ActivateAuthRemoteSensing
                | MutationCommandId::PauseAuthRemoteSensing
                | MutationCommandId::ResumeAuthRemoteSensing
                | MutationCommandId::StopAuthRemoteSensing
        );
        let previous_lifecycle = if auth_remote_sensing_command {
            self.auth_remote_sensing_lifecycle_category()
        } else if dns_sensing_command {
            self.dns_sensing_lifecycle_category()
        } else {
            self.etw_lifecycle_category()
        };
        let execution_ref = format!("provider_execution_{}", Uuid::new_v4());
        let authorization_refs = vec![
            decision.decision_ref.clone(),
            execution_request.intent.intent_ref.clone(),
        ];
        let mut counters = MutationExecutionCounters::default();
        let mut degraded_reason = None;
        let (result_category, resulting_lifecycle) = {
            let Some(container_handle) = self.runtime_container.as_ref().cloned() else {
                return IpcEnvelope::error(
                    envelope,
                    IpcError::internal("servicehost runtime container unavailable"),
                );
            };
            let Ok(mut container) = container_handle.lock() else {
                return IpcEnvelope::error(
                    envelope,
                    IpcError::internal("servicehost runtime container lock unavailable"),
                );
            };
            let owner_context = container.owner_context().clone();
            if owner_context.ownership_epoch != decision.ownership_epoch {
                let _ = self.audit_logger.log(
                    "etw_execution_epoch_rejected",
                    Some(expected_command.as_str()),
                    "rejected",
                    Some("ownership_epoch_changed"),
                );
                return IpcEnvelope::error(
                    envelope,
                    IpcError::caller_rejected("etw_execution_epoch_rejected"),
                );
            }
            let execution = match expected_command {
                MutationCommandId::ActivateEtwProvider => {
                    container.activate_etw_provider(&owner_context, authorization_refs)
                }
                MutationCommandId::PauseEtwProvider => {
                    container.pause_etw_provider(&owner_context, authorization_refs)
                }
                MutationCommandId::ResumeEtwProvider => {
                    container.resume_etw_provider(&owner_context, authorization_refs)
                }
                MutationCommandId::StopEtwProvider => {
                    container.stop_etw_provider(&owner_context, authorization_refs)
                }
                MutationCommandId::ActivateDnsSensing => {
                    container.activate_dns_sensing(&owner_context, authorization_refs)
                }
                MutationCommandId::PauseDnsSensing => {
                    container.pause_dns_sensing(&owner_context, authorization_refs)
                }
                MutationCommandId::ResumeDnsSensing => {
                    container.resume_dns_sensing(&owner_context, authorization_refs)
                }
                MutationCommandId::StopDnsSensing => {
                    container.stop_dns_sensing(&owner_context, authorization_refs)
                }
                MutationCommandId::ActivateAuthRemoteSensing => {
                    container.activate_auth_remote_sensing(&owner_context, authorization_refs)
                }
                MutationCommandId::PauseAuthRemoteSensing => {
                    container.pause_auth_remote_sensing(&owner_context, authorization_refs)
                }
                MutationCommandId::ResumeAuthRemoteSensing => {
                    container.resume_auth_remote_sensing(&owner_context, authorization_refs)
                }
                MutationCommandId::StopAuthRemoteSensing => {
                    container.stop_auth_remote_sensing(&owner_context, authorization_refs)
                }
                _ => Err(sentinel_contracts::CoreError::new(
                    sentinel_contracts::ErrorCode::UnsupportedOperation,
                    "unsupported ETW command",
                )),
            };
            match execution {
                Ok(status) => {
                    let resulting = lifecycle_from_provider_status(
                        &status,
                        if auth_remote_sensing_command {
                            NetworkProviderKind::WindowsAuthRemote
                        } else if dns_sensing_command {
                            NetworkProviderKind::WindowsDns
                        } else {
                            NetworkProviderKind::EtwNetwork
                        },
                    );
                    (
                        if previous_lifecycle == resulting {
                            MutationExecutionResultCategory::AlreadySatisfied
                        } else {
                            MutationExecutionResultCategory::Completed
                        },
                        resulting,
                    )
                }
                Err(_) => {
                    counters.rejected_count = 1;
                    degraded_reason = Some("etw_lifecycle_execution_failed".to_string());
                    (
                        MutationExecutionResultCategory::Failed,
                        if dns_sensing_command {
                            self.dns_sensing_lifecycle_category()
                        } else if auth_remote_sensing_command {
                            self.auth_remote_sensing_lifecycle_category()
                        } else {
                            self.etw_lifecycle_category()
                        },
                    )
                }
            }
        };
        self.refresh_runtime_snapshots_from_container();

        let canonical_snapshot_refs = self
            .canonical_read_model_snapshot
            .as_ref()
            .map(|snapshot| vec![snapshot.snapshot_id.to_string()])
            .unwrap_or_default();
        let audit_event = match result_category {
            MutationExecutionResultCategory::Completed
            | MutationExecutionResultCategory::AlreadySatisfied => {
                etw_completed_event(expected_command)
            }
            _ => etw_failed_event(expected_command),
        };
        let _ = self.audit_logger.log(
            audit_event,
            Some(expected_command.as_str()),
            "completed",
            degraded_reason.as_deref(),
        );
        let receipt = MutationExecutionReceipt {
            schema_version: sentinel_contracts::MUTATION_AUTHORIZATION_SCHEMA_VERSION,
            execution_ref,
            authorization_decision_ref: decision.decision_ref,
            intent_ref: execution_request.intent.intent_ref,
            request_ref: execution_request.intent.request_ref,
            command_id: expected_command,
            policy_ref: execution_request.intent.policy_ref,
            policy_version: execution_request.intent.policy_version,
            ownership_epoch: decision.ownership_epoch,
            provider_category: if auth_remote_sensing_command {
                MutationCapabilityCategory::AuthRemoteSensingProvider
            } else if dns_sensing_command {
                MutationCapabilityCategory::DnsSensingProvider
            } else {
                MutationCapabilityCategory::EtwProvider
            },
            previous_lifecycle_state: previous_lifecycle,
            resulting_lifecycle_state: resulting_lifecycle,
            authorization_state: match result_category {
                MutationExecutionResultCategory::Completed => {
                    MutationExecutionAuthorizationState::ExecutionCompleted
                }
                MutationExecutionResultCategory::AlreadySatisfied => {
                    MutationExecutionAuthorizationState::AlreadySatisfied
                }
                MutationExecutionResultCategory::TimedOut => {
                    MutationExecutionAuthorizationState::ExecutionTimedOut
                }
                MutationExecutionResultCategory::Cancelled => {
                    MutationExecutionAuthorizationState::ExecutionCancelled
                }
                MutationExecutionResultCategory::Rejected => {
                    MutationExecutionAuthorizationState::ExecutionRejected
                }
                MutationExecutionResultCategory::Failed => {
                    MutationExecutionAuthorizationState::ExecutionFailed
                }
            },
            result_category,
            started_time_bucket: "current_connection".to_string(),
            completed_time_bucket: "current_connection".to_string(),
            duration_bucket: "bounded_under_timeout".to_string(),
            counters,
            batch_refs: Vec::new(),
            fact_refs: Vec::new(),
            canonical_snapshot_refs,
            audit_refs: vec![
                provider_authorized_event(expected_command).to_string(),
                started_event.to_string(),
                audit_event.to_string(),
            ],
            degraded_reason,
            provenance_id: if dns_sensing_command {
                "servicehost_windows_dns_sensing_ipc".to_string()
            } else {
                "servicehost_etw_lifecycle_ipc".to_string()
            },
            redaction_status: RedactionStatus::Redacted,
        };
        if let Err(error) = receipt.validate() {
            return IpcEnvelope::error(envelope, IpcError::schema(error.to_string()));
        }
        match serde_json::to_value(receipt) {
            Ok(payload) => IpcEnvelope::ok(envelope, payload),
            Err(error) => IpcEnvelope::error(envelope, IpcError::internal(error.to_string())),
        }
    }

    fn execute_ip_helper_schedule_mutation(
        &mut self,
        session: &IpcSessionState,
        envelope: &IpcEnvelope<Value>,
        service_command: ServiceCommand,
    ) -> IpcEnvelope<Value> {
        let expected_command = match ip_helper_schedule_command_id(service_command) {
            Some(command) => command,
            None => {
                return IpcEnvelope::error(
                    envelope,
                    IpcError::command_not_allowed("schedule command is not execution-enabled"),
                )
            }
        };
        let schedule_request: IpHelperScheduleMutationRequest =
            match serde_json::from_value(envelope.payload.clone()) {
                Ok(request) => request,
                Err(_) => {
                    let _ = self.audit_logger.log(
                        "ip_helper_schedule_invalidated",
                        Some(service_command.as_str()),
                        "rejected",
                        Some("invalid_schedule_request_contract"),
                    );
                    return IpcEnvelope::error(
                        envelope,
                        IpcError::schema("schedule mutation request contract is invalid"),
                    );
                }
            };
        if let Err(error) = schedule_request.validate() {
            let _ = self.audit_logger.log(
                "ip_helper_schedule_invalidated",
                Some(service_command.as_str()),
                "rejected",
                Some("schedule_request_validation_failed"),
            );
            return IpcEnvelope::error(envelope, IpcError::schema(error.to_string()));
        }
        if expected_command == MutationCommandId::ConfigureIpHelperSchedule
            && schedule_request.schedule_config.is_none()
        {
            return IpcEnvelope::error(
                envelope,
                IpcError::schema("configure_ip_helper_schedule requires bounded configuration"),
            );
        }
        if expected_command != MutationCommandId::ConfigureIpHelperSchedule
            && schedule_request.schedule_config.is_some()
        {
            return IpcEnvelope::error(
                envelope,
                IpcError::schema("only configure_ip_helper_schedule accepts schedule_config"),
            );
        }

        let execution_request = schedule_request.execution_request;
        let current_epoch = self
            .runtime_ownership_status
            .as_ref()
            .map(|summary| summary.ownership_epoch)
            .unwrap_or_default();
        let decision = match self.mutation_authorization.consume_execution_authorization(
            &execution_request,
            &session.session_reference,
            expected_command,
            current_epoch,
        ) {
            Ok(decision) => decision,
            Err(reason) => {
                let audit_event = if reason.contains("epoch") {
                    "ip_helper_schedule_epoch_rejected"
                } else {
                    "ip_helper_schedule_invalidated"
                };
                let _ = self.audit_logger.log(
                    audit_event,
                    Some(expected_command.as_str()),
                    "rejected",
                    Some(reason),
                );
                return IpcEnvelope::error(envelope, IpcError::caller_rejected(reason));
            }
        };

        let previous_lifecycle = self.ip_helper_lifecycle_category();
        let execution_ref = format!("ip_helper_schedule_execution_{}", Uuid::new_v4());
        let schedule_event = ip_helper_schedule_completed_event(expected_command);
        let mut degraded_reason = None;
        let mut result_category = MutationExecutionResultCategory::Completed;
        let resulting_lifecycle = {
            let Some(container_handle) = self.runtime_container.as_ref().cloned() else {
                return IpcEnvelope::error(
                    envelope,
                    IpcError::internal("servicehost runtime container unavailable"),
                );
            };
            let Ok(mut container) = container_handle.lock() else {
                return IpcEnvelope::error(
                    envelope,
                    IpcError::internal("servicehost runtime container lock unavailable"),
                );
            };
            let owner_context = container.owner_context().clone();
            if owner_context.ownership_epoch != decision.ownership_epoch {
                let _ = self.audit_logger.log(
                    "ip_helper_schedule_epoch_rejected",
                    Some(expected_command.as_str()),
                    "rejected",
                    Some("ownership_epoch_changed"),
                );
                return IpcEnvelope::error(
                    envelope,
                    IpcError::caller_rejected("ip_helper_schedule_epoch_rejected"),
                );
            }
            let authorization_refs = vec![
                decision.decision_ref.clone(),
                execution_request.intent.intent_ref.clone(),
            ];
            let execution = match expected_command {
                MutationCommandId::ConfigureIpHelperSchedule => container
                    .configure_ip_helper_schedule(
                        &owner_context,
                        schedule_request.schedule_config.unwrap_or_default(),
                        authorization_refs,
                        execution_request.intent.policy_ref.clone(),
                        execution_request.intent.policy_version.clone(),
                    )
                    .map(Box::new),
                MutationCommandId::EnableIpHelperSchedule => container
                    .enable_ip_helper_schedule(
                        &owner_context,
                        format!("ip_helper_schedule_lease_{}", Uuid::new_v4()),
                        authorization_refs,
                        execution_request.intent.policy_ref.clone(),
                        execution_request.intent.policy_version.clone(),
                    )
                    .map(Box::new),
                MutationCommandId::PauseIpHelperSchedule => container
                    .pause_ip_helper_schedule(
                        &owner_context,
                        authorization_refs,
                        execution_request.intent.policy_ref.clone(),
                        execution_request.intent.policy_version.clone(),
                    )
                    .map(Box::new),
                MutationCommandId::ResumeIpHelperSchedule => container
                    .resume_ip_helper_schedule(
                        &owner_context,
                        format!("ip_helper_schedule_lease_{}", Uuid::new_v4()),
                        authorization_refs,
                        execution_request.intent.policy_ref.clone(),
                        execution_request.intent.policy_version.clone(),
                    )
                    .map(Box::new),
                MutationCommandId::DisableIpHelperSchedule => container
                    .disable_ip_helper_schedule(
                        &owner_context,
                        authorization_refs,
                        execution_request.intent.policy_ref.clone(),
                        execution_request.intent.policy_version.clone(),
                    )
                    .map(Box::new),
                _ => Err(sentinel_contracts::CoreError::new(
                    sentinel_contracts::ErrorCode::UnsupportedOperation,
                    "unsupported ip helper schedule command",
                )),
            };
            match execution {
                Ok(status) => lifecycle_from_status(&status),
                Err(_) => {
                    result_category = MutationExecutionResultCategory::Failed;
                    degraded_reason = Some("schedule_mutation_failed".to_string());
                    self.ip_helper_lifecycle_category()
                }
            }
        };
        self.refresh_runtime_snapshots_from_container();

        let canonical_snapshot_refs = self
            .canonical_read_model_snapshot
            .as_ref()
            .map(|snapshot| vec![snapshot.snapshot_id.to_string()])
            .unwrap_or_default();
        let _ = self.audit_logger.log(
            schedule_event,
            Some(expected_command.as_str()),
            "completed",
            degraded_reason.as_deref(),
        );
        if let Some(signal) = &self.scheduler_wake_signal {
            signal.notify();
        }
        let wake_assist_ref = if matches!(
            expected_command,
            MutationCommandId::EnableIpHelperSchedule | MutationCommandId::ResumeIpHelperSchedule
        ) {
            Some(self.kick_due_ip_helper_scheduler_cycle())
        } else {
            None
        };
        let mut audit_refs = vec![schedule_event.to_string()];
        if matches!(
            expected_command,
            MutationCommandId::EnableIpHelperSchedule | MutationCommandId::ResumeIpHelperSchedule
        ) {
            audit_refs.push("ip_helper_schedule_lease_created".to_string());
        }
        if let Some(wake_assist_ref) = wake_assist_ref {
            audit_refs.push(wake_assist_ref);
        }
        let receipt = MutationExecutionReceipt {
            schema_version: sentinel_contracts::MUTATION_AUTHORIZATION_SCHEMA_VERSION,
            execution_ref,
            authorization_decision_ref: decision.decision_ref,
            intent_ref: execution_request.intent.intent_ref,
            request_ref: execution_request.intent.request_ref,
            command_id: expected_command,
            policy_ref: execution_request.intent.policy_ref,
            policy_version: execution_request.intent.policy_version,
            ownership_epoch: decision.ownership_epoch,
            provider_category: MutationCapabilityCategory::IpHelperProvider,
            previous_lifecycle_state: previous_lifecycle,
            resulting_lifecycle_state: resulting_lifecycle,
            authorization_state: match result_category {
                MutationExecutionResultCategory::Completed => {
                    MutationExecutionAuthorizationState::ExecutionCompleted
                }
                MutationExecutionResultCategory::AlreadySatisfied => {
                    MutationExecutionAuthorizationState::AlreadySatisfied
                }
                MutationExecutionResultCategory::TimedOut => {
                    MutationExecutionAuthorizationState::ExecutionTimedOut
                }
                MutationExecutionResultCategory::Cancelled => {
                    MutationExecutionAuthorizationState::ExecutionCancelled
                }
                MutationExecutionResultCategory::Rejected => {
                    MutationExecutionAuthorizationState::ExecutionRejected
                }
                MutationExecutionResultCategory::Failed => {
                    MutationExecutionAuthorizationState::ExecutionFailed
                }
            },
            result_category,
            started_time_bucket: "current_connection".to_string(),
            completed_time_bucket: "current_connection".to_string(),
            duration_bucket: "bounded_under_timeout".to_string(),
            counters: MutationExecutionCounters::default(),
            batch_refs: Vec::new(),
            fact_refs: Vec::new(),
            canonical_snapshot_refs,
            audit_refs,
            degraded_reason,
            provenance_id: "servicehost_ip_helper_schedule_control_plane".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        if let Err(error) = receipt.validate() {
            return IpcEnvelope::error(envelope, IpcError::schema(error.to_string()));
        }
        match serde_json::to_value(receipt) {
            Ok(payload) => IpcEnvelope::ok(envelope, payload),
            Err(error) => IpcEnvelope::error(envelope, IpcError::internal(error.to_string())),
        }
    }

    fn refresh_runtime_snapshots_from_container(&mut self) {
        if let Some(container_handle) = self.runtime_container.as_ref() {
            let Ok(container) = container_handle.lock() else {
                return;
            };
            self.runtime_ownership_status = Some(container.summary());
            if let Ok(snapshot) = container.canonical_read_model_snapshot() {
                self.canonical_read_model_snapshot = Some(snapshot);
            }
        }
    }

    fn ip_helper_lifecycle_category(&self) -> ProviderLifecycleCategory {
        self.runtime_container
            .as_ref()
            .and_then(|container| {
                container.lock().ok().and_then(|container| {
                    container
                        .network_provider_status(NetworkProviderKind::IpHelper)
                        .map(|provider| lifecycle_category(provider.lifecycle_state))
                })
            })
            .unwrap_or(ProviderLifecycleCategory::Unavailable)
    }

    fn etw_lifecycle_category(&self) -> ProviderLifecycleCategory {
        self.runtime_container
            .as_ref()
            .and_then(|container| {
                container.lock().ok().and_then(|container| {
                    container
                        .network_provider_status(NetworkProviderKind::EtwNetwork)
                        .map(|provider| lifecycle_category(provider.lifecycle_state))
                })
            })
            .unwrap_or(ProviderLifecycleCategory::Unavailable)
    }

    fn dns_sensing_lifecycle_category(&self) -> ProviderLifecycleCategory {
        self.runtime_container
            .as_ref()
            .and_then(|container| {
                container.lock().ok().and_then(|container| {
                    container
                        .network_provider_status(NetworkProviderKind::WindowsDns)
                        .map(|provider| lifecycle_category(provider.lifecycle_state))
                })
            })
            .unwrap_or(ProviderLifecycleCategory::Unavailable)
    }

    fn auth_remote_sensing_lifecycle_category(&self) -> ProviderLifecycleCategory {
        self.runtime_container
            .as_ref()
            .and_then(|container| {
                container.lock().ok().and_then(|container| {
                    container
                        .network_provider_status(NetworkProviderKind::WindowsAuthRemote)
                        .map(|provider| lifecycle_category(provider.lifecycle_state))
                })
            })
            .unwrap_or(ProviderLifecycleCategory::Unavailable)
    }

    fn handle_ping(&self, params: &Value) -> Result<Value, IpcError> {
        let params: PingParams = decode_params(params)?;
        validate_safe_ipc_text("nonce", &params.nonce)?;
        let result = PingResult {
            nonce: params.nonce,
            service_uptime_ms: self.started_at.elapsed().as_millis() as u64,
            version: SERVICE_VERSION.to_string(),
        };
        serde_json::to_value(result).map_err(|error| IpcError::internal(error.to_string()))
    }

    fn handle_status(&self, params: &Value) -> Result<Value, IpcError> {
        let _: EmptyParams = decode_params(params)?;
        let provider_controller_status = self.runtime_container.as_ref().and_then(|container| {
            container
                .lock()
                .ok()
                .and_then(|container| container.provider_controller_status().cloned())
        });
        let dns_sensing_lifecycle_status = self.runtime_container.as_ref().and_then(|container| {
            container
                .lock()
                .ok()
                .and_then(|container| container.dns_sensing_lifecycle_status().cloned())
        });
        let auth_remote_sensing_lifecycle_status =
            self.runtime_container.as_ref().and_then(|container| {
                container
                    .lock()
                    .ok()
                    .and_then(|container| container.auth_remote_sensing_lifecycle_status().cloned())
            });
        let result = StatusResult {
            service_status: "running".to_string(),
            connected_clients: self.connected_clients,
            memory_usage_mb: 0.0,
            runtime_ownership: self
                .runtime_ownership_status
                .as_ref()
                .map(|status| status.runtime_mode),
            runtime_ownership_status: self.runtime_ownership_status.clone(),
            runtime_protocol_version: self
                .runtime_ownership_status
                .as_ref()
                .map(|status| status.protocol_version.clone()),
            runtime_schema_version: self
                .runtime_ownership_status
                .as_ref()
                .map(|status| status.schema_version.clone()),
            caller_verification_status: Some(self.caller_verification_read_status()),
            mutation_authorization_status: Some(self.mutation_authorization_status()),
            provider_controller_status,
            dns_sensing_lifecycle_status,
            auth_remote_sensing_lifecycle_status,
        };
        serde_json::to_value(result).map_err(|error| IpcError::internal(error.to_string()))
    }

    fn handle_capture_health(&self, params: &Value) -> Result<Value, IpcError> {
        let _: EmptyParams = decode_params(params)?;
        let result = CaptureHealthResult {
            capture_active: false,
            packets_observed: 0,
            last_packet_at: None,
            adapter_state: "stub_inactive".to_string(),
        };
        serde_json::to_value(result).map_err(|error| IpcError::internal(error.to_string()))
    }

    fn handle_process_snapshot(&self, params: &Value) -> Result<Value, IpcError> {
        let params: ProcessSnapshotParams = decode_params(params)?;
        let own_pid = std::process::id();
        let processes = if params.pid.is_none_or(|pid| pid == own_pid) {
            vec![ProcessSnapshotEntry {
                pid: own_pid,
                name: service_process_name(),
                path: "redacted:sentinel-guard-elevated".to_string(),
                connections: Vec::new(),
            }]
        } else {
            Vec::new()
        };
        let result = ProcessSnapshotResult { processes };
        serde_json::to_value(result).map_err(|error| IpcError::internal(error.to_string()))
    }

    fn handle_read_command(
        &self,
        command_id: ServiceReadCommandId,
        params: &Value,
    ) -> Result<Value, IpcError> {
        let params: ServiceReadCommandRequest = decode_params(params)?;
        let snapshot = self
            .canonical_read_model_snapshot
            .as_ref()
            .ok_or_else(|| IpcError::internal("canonical read-model snapshot unavailable"))?;
        let response = build_service_read_command_response(command_id, snapshot, &params)
            .map_err(|error| IpcError::schema(error.to_string()))?;
        let value = serde_json::to_value(response)
            .map_err(|error| IpcError::internal(error.to_string()))?;
        enforce_payload_size_limit(&value)?;
        Ok(value)
    }
}

fn safe_wake_assist_reason(value: &str) -> String {
    let mut safe = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    while safe.contains("__") {
        safe = safe.replace("__", "_");
    }
    let safe = safe.trim_matches('_').chars().take(48).collect::<String>();
    if safe.is_empty() {
        "unknown".to_string()
    } else {
        safe
    }
}

enum ProviderExecutionOutcome {
    Status(Box<sentinel_contracts::provider_controller::NetworkProviderControllerStatus>),
    Sample(Box<sentinel_app_core::IpHelperHandoffResult>),
}

fn ip_helper_mutation_command_id(command: ServiceCommand) -> Option<MutationCommandId> {
    match command {
        ServiceCommand::ActivateIpHelper => Some(MutationCommandId::ActivateIpHelperProvider),
        ServiceCommand::SampleIpHelperOnce => Some(MutationCommandId::SampleIpHelperNow),
        ServiceCommand::StopIpHelper => Some(MutationCommandId::StopIpHelper),
        _ => None,
    }
}

fn etw_mutation_command_id(command: ServiceCommand) -> Option<MutationCommandId> {
    match command {
        ServiceCommand::ActivateEtw => Some(MutationCommandId::ActivateEtwProvider),
        ServiceCommand::PauseEtw => Some(MutationCommandId::PauseEtwProvider),
        ServiceCommand::ResumeEtw => Some(MutationCommandId::ResumeEtwProvider),
        ServiceCommand::StopEtw => Some(MutationCommandId::StopEtwProvider),
        ServiceCommand::ActivateDnsSensing => Some(MutationCommandId::ActivateDnsSensing),
        ServiceCommand::PauseDnsSensing => Some(MutationCommandId::PauseDnsSensing),
        ServiceCommand::ResumeDnsSensing => Some(MutationCommandId::ResumeDnsSensing),
        ServiceCommand::StopDnsSensing => Some(MutationCommandId::StopDnsSensing),
        ServiceCommand::ActivateAuthRemoteSensing => {
            Some(MutationCommandId::ActivateAuthRemoteSensing)
        }
        ServiceCommand::PauseAuthRemoteSensing => Some(MutationCommandId::PauseAuthRemoteSensing),
        ServiceCommand::ResumeAuthRemoteSensing => Some(MutationCommandId::ResumeAuthRemoteSensing),
        ServiceCommand::StopAuthRemoteSensing => Some(MutationCommandId::StopAuthRemoteSensing),
        _ => None,
    }
}

fn ip_helper_schedule_command_id(command: ServiceCommand) -> Option<MutationCommandId> {
    match command {
        ServiceCommand::ConfigureIpHelperSchedule => {
            Some(MutationCommandId::ConfigureIpHelperSchedule)
        }
        ServiceCommand::EnableIpHelperSchedule => Some(MutationCommandId::EnableIpHelperSchedule),
        ServiceCommand::PauseIpHelperSchedule => Some(MutationCommandId::PauseIpHelperSchedule),
        ServiceCommand::ResumeIpHelperSchedule => Some(MutationCommandId::ResumeIpHelperSchedule),
        ServiceCommand::DisableIpHelperSchedule => Some(MutationCommandId::DisableIpHelperSchedule),
        _ => None,
    }
}

fn lifecycle_from_status(
    status: &sentinel_contracts::provider_controller::NetworkProviderControllerStatus,
) -> ProviderLifecycleCategory {
    lifecycle_from_provider_status(status, NetworkProviderKind::IpHelper)
}

fn lifecycle_from_provider_status(
    status: &sentinel_contracts::provider_controller::NetworkProviderControllerStatus,
    provider_kind: NetworkProviderKind,
) -> ProviderLifecycleCategory {
    status
        .provider(provider_kind)
        .map(|provider| lifecycle_category(provider.lifecycle_state))
        .unwrap_or(ProviderLifecycleCategory::Unavailable)
}

fn lifecycle_category(lifecycle: NetworkProviderLifecycleState) -> ProviderLifecycleCategory {
    match lifecycle {
        NetworkProviderLifecycleState::Inactive => ProviderLifecycleCategory::Inactive,
        NetworkProviderLifecycleState::Activating => ProviderLifecycleCategory::Activating,
        NetworkProviderLifecycleState::Ready => ProviderLifecycleCategory::Active,
        NetworkProviderLifecycleState::Active => ProviderLifecycleCategory::Active,
        NetworkProviderLifecycleState::Probing => ProviderLifecycleCategory::Sampling,
        NetworkProviderLifecycleState::Paused => ProviderLifecycleCategory::Paused,
        NetworkProviderLifecycleState::Degraded => ProviderLifecycleCategory::Degraded,
        NetworkProviderLifecycleState::Stopping => ProviderLifecycleCategory::Stopping,
        NetworkProviderLifecycleState::Stopped => ProviderLifecycleCategory::Stopped,
        NetworkProviderLifecycleState::Revoked | NetworkProviderLifecycleState::Failed => {
            ProviderLifecycleCategory::Failed
        }
    }
}

fn provider_authorized_event(command: MutationCommandId) -> &'static str {
    match command {
        MutationCommandId::ActivateIpHelperProvider => "ip_helper_activation_authorized",
        MutationCommandId::SampleIpHelperNow => "ip_helper_sample_authorized",
        MutationCommandId::StopIpHelper => "ip_helper_stop_authorized",
        MutationCommandId::ActivateEtwProvider => "etw_activation_authorized",
        MutationCommandId::PauseEtwProvider => "etw_pause_authorized",
        MutationCommandId::ResumeEtwProvider => "etw_resume_authorized",
        MutationCommandId::StopEtwProvider => "etw_stop_authorized",
        MutationCommandId::ActivateDnsSensing => "dns_sensing_activation_authorized",
        MutationCommandId::PauseDnsSensing => "dns_sensing_pause_authorized",
        MutationCommandId::ResumeDnsSensing => "dns_sensing_resume_authorized",
        MutationCommandId::StopDnsSensing => "dns_sensing_stop_authorized",
        MutationCommandId::ActivateAuthRemoteSensing => "auth_remote_sensing_activation_authorized",
        MutationCommandId::PauseAuthRemoteSensing => "auth_remote_sensing_pause_authorized",
        MutationCommandId::ResumeAuthRemoteSensing => "auth_remote_sensing_resume_authorized",
        MutationCommandId::StopAuthRemoteSensing => "auth_remote_sensing_stop_authorized",
        MutationCommandId::ConfigureIpHelperSchedule => "ip_helper_schedule_configure_authorized",
        MutationCommandId::EnableIpHelperSchedule => "ip_helper_schedule_enable_authorized",
        MutationCommandId::PauseIpHelperSchedule => "ip_helper_schedule_pause_authorized",
        MutationCommandId::ResumeIpHelperSchedule => "ip_helper_schedule_resume_authorized",
        MutationCommandId::DisableIpHelperSchedule => "ip_helper_schedule_disable_authorized",
        _ => "provider_execution_rejected",
    }
}

fn etw_started_event(command: MutationCommandId) -> &'static str {
    match command {
        MutationCommandId::ActivateEtwProvider => "etw_activation_started",
        MutationCommandId::PauseEtwProvider => "etw_pause_started",
        MutationCommandId::ResumeEtwProvider => "etw_resume_started",
        MutationCommandId::StopEtwProvider => "etw_stop_started",
        MutationCommandId::ActivateDnsSensing => "dns_sensing_activation_started",
        MutationCommandId::PauseDnsSensing => "dns_sensing_pause_started",
        MutationCommandId::ResumeDnsSensing => "dns_sensing_resume_started",
        MutationCommandId::StopDnsSensing => "dns_sensing_stop_started",
        MutationCommandId::ActivateAuthRemoteSensing => "auth_remote_sensing_activation_started",
        MutationCommandId::PauseAuthRemoteSensing => "auth_remote_sensing_pause_started",
        MutationCommandId::ResumeAuthRemoteSensing => "auth_remote_sensing_resume_started",
        MutationCommandId::StopAuthRemoteSensing => "auth_remote_sensing_stop_started",
        _ => "etw_execution_rejected",
    }
}

fn etw_completed_event(command: MutationCommandId) -> &'static str {
    match command {
        MutationCommandId::ActivateEtwProvider => "etw_activation_completed",
        MutationCommandId::PauseEtwProvider => "etw_pause_completed",
        MutationCommandId::ResumeEtwProvider => "etw_resume_completed",
        MutationCommandId::StopEtwProvider => "etw_stop_completed",
        MutationCommandId::ActivateDnsSensing => "dns_sensing_activation_completed",
        MutationCommandId::PauseDnsSensing => "dns_sensing_pause_completed",
        MutationCommandId::ResumeDnsSensing => "dns_sensing_resume_completed",
        MutationCommandId::StopDnsSensing => "dns_sensing_stop_completed",
        MutationCommandId::ActivateAuthRemoteSensing => "auth_remote_sensing_activation_completed",
        MutationCommandId::PauseAuthRemoteSensing => "auth_remote_sensing_pause_completed",
        MutationCommandId::ResumeAuthRemoteSensing => "auth_remote_sensing_resume_completed",
        MutationCommandId::StopAuthRemoteSensing => "auth_remote_sensing_stop_completed",
        _ => "etw_execution_rejected",
    }
}

fn etw_failed_event(command: MutationCommandId) -> &'static str {
    match command {
        MutationCommandId::ActivateEtwProvider => "etw_activation_failed",
        MutationCommandId::PauseEtwProvider => "etw_pause_failed",
        MutationCommandId::ResumeEtwProvider => "etw_resume_failed",
        MutationCommandId::StopEtwProvider => "etw_stop_failed",
        MutationCommandId::ActivateDnsSensing => "dns_sensing_activation_failed",
        MutationCommandId::PauseDnsSensing => "dns_sensing_pause_failed",
        MutationCommandId::ResumeDnsSensing => "dns_sensing_resume_failed",
        MutationCommandId::StopDnsSensing => "dns_sensing_stop_failed",
        MutationCommandId::ActivateAuthRemoteSensing => "auth_remote_sensing_activation_failed",
        MutationCommandId::PauseAuthRemoteSensing => "auth_remote_sensing_pause_failed",
        MutationCommandId::ResumeAuthRemoteSensing => "auth_remote_sensing_resume_failed",
        MutationCommandId::StopAuthRemoteSensing => "auth_remote_sensing_stop_failed",
        _ => "etw_execution_rejected",
    }
}

fn ip_helper_started_event(command: MutationCommandId) -> &'static str {
    match command {
        MutationCommandId::ActivateIpHelperProvider => "ip_helper_activation_started",
        MutationCommandId::SampleIpHelperNow => "ip_helper_sample_started",
        MutationCommandId::StopIpHelper => "ip_helper_stop_started",
        _ => "ip_helper_execution_rejected",
    }
}

fn ip_helper_completed_event(command: MutationCommandId) -> &'static str {
    match command {
        MutationCommandId::ActivateIpHelperProvider => "ip_helper_activation_completed",
        MutationCommandId::SampleIpHelperNow => "ip_helper_sample_completed",
        MutationCommandId::StopIpHelper => "ip_helper_stop_completed",
        _ => "ip_helper_execution_rejected",
    }
}

fn ip_helper_failed_event(command: MutationCommandId) -> &'static str {
    match command {
        MutationCommandId::ActivateIpHelperProvider => "ip_helper_activation_failed",
        MutationCommandId::SampleIpHelperNow => "ip_helper_sample_failed",
        MutationCommandId::StopIpHelper => "ip_helper_execution_rejected",
        _ => "ip_helper_execution_rejected",
    }
}

fn ip_helper_schedule_completed_event(command: MutationCommandId) -> &'static str {
    match command {
        MutationCommandId::ConfigureIpHelperSchedule => "ip_helper_schedule_configured",
        MutationCommandId::EnableIpHelperSchedule => "ip_helper_schedule_enabled",
        MutationCommandId::PauseIpHelperSchedule => "ip_helper_schedule_paused",
        MutationCommandId::ResumeIpHelperSchedule => "ip_helper_schedule_resumed",
        MutationCommandId::DisableIpHelperSchedule => "ip_helper_schedule_disabled",
        _ => "ip_helper_schedule_invalidated",
    }
}

fn decode_params<T>(params: &Value) -> Result<T, IpcError>
where
    T: DeserializeOwned,
{
    serde_json::from_value(params.clone()).map_err(|error| {
        IpcError::schema(format!(
            "request params failed strict schema validation: {error}"
        ))
    })
}

fn enforce_payload_size_limit(value: &Value) -> Result<(), IpcError> {
    let payload_len = serde_json::to_vec(value)
        .map_err(|error| IpcError::schema(error.to_string()))?
        .len();
    if payload_len > MAX_PAYLOAD_BYTES {
        return Err(IpcError::schema(format!(
            "IPC response payload exceeds bounded limit: {payload_len} > {MAX_PAYLOAD_BYTES}"
        )));
    }
    Ok(())
}

fn validate_client_verify(
    session: &IpcSessionState,
    verify: &IpcClientVerify,
) -> Result<(), IpcError> {
    if verify.message_type != "client_verify" {
        return Err(IpcError::protocol("expected client_verify"));
    }
    if verify.protocol_version != IPC_PROTOCOL_VERSION
        || verify.schema_version != RUNTIME_IPC_SCHEMA_VERSION
    {
        return Err(IpcError::protocol("IPC verify version mismatch"));
    }
    if verify.session_reference != session.session_reference
        || verify.client_nonce != session.client_nonce
        || verify.server_nonce != session.server_nonce
        || verify.challenge_nonce != session.challenge_nonce
    {
        return Err(IpcError::protocol("IPC verify session mismatch"));
    }
    if verify.sequence_number != 0 {
        return Err(IpcError::invalid_sequence(
            "IPC verify sequence must start at zero",
        ));
    }
    validate_safe_ipc_text("caller_kind", &verify.caller_kind)?;
    Ok(())
}

fn validate_request_envelope(
    session: &IpcSessionState,
    envelope: &IpcEnvelope<Value>,
    expected_sequence_number: u64,
) -> Result<(), IpcError> {
    if envelope.protocol_version != IPC_PROTOCOL_VERSION
        || envelope.schema_version != RUNTIME_IPC_SCHEMA_VERSION
    {
        return Err(IpcError::protocol("IPC envelope version mismatch"));
    }
    if envelope.session_reference != session.session_reference
        || envelope.client_nonce != session.client_nonce
        || envelope.server_nonce != session.server_nonce
    {
        return Err(IpcError::protocol("IPC envelope session mismatch"));
    }
    if envelope.sequence_number != expected_sequence_number
        || envelope.sequence_number == 0
        || envelope.sequence_number > MAX_REQUESTS_PER_SESSION
    {
        return Err(IpcError::invalid_sequence(
            "IPC request sequence is outside the bounded monotonic session",
        ));
    }
    if envelope.response_status != "request" {
        return Err(IpcError::protocol(
            "IPC request envelope status must be request",
        ));
    }
    validate_safe_ipc_text("request_id", &envelope.request_id)?;
    validate_safe_ipc_text("command_id", &envelope.command_id)?;
    let payload_len = serde_json::to_vec(&envelope.payload)
        .map_err(|error| IpcError::schema(error.to_string()))?
        .len();
    if payload_len > MAX_PAYLOAD_BYTES {
        return Err(IpcError::schema(format!(
            "IPC payload exceeds bounded limit: {payload_len} > {MAX_PAYLOAD_BYTES}"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BoundedTokenClassificationInput {
    local_connection: bool,
    token_available: bool,
    impersonation_token: bool,
    impersonation_level_suitable: bool,
    network_logon: bool,
    anonymous: bool,
    interactive: bool,
    expected_service_identity: bool,
    administrator_member: bool,
    elevated: bool,
    session_binding_valid: bool,
}

fn classify_bounded_token(
    input: BoundedTokenClassificationInput,
    policy: CallerVerificationPolicy,
) -> CallerVerificationSummary {
    let (caller_category, verification_state, token_suitability, degraded_reason) =
        if !input.local_connection {
            (
                CallerCategory::Unauthorized,
                CallerVerificationState::RemoteCallerRejected,
                TokenSuitabilityCategory::TokenUnavailable,
                Some("remote_transport_rejected".to_string()),
            )
        } else if !input.token_available {
            (
                CallerCategory::Unavailable,
                CallerVerificationState::CallerIdentityUnavailable,
                TokenSuitabilityCategory::TokenUnavailable,
                Some("token_unavailable".to_string()),
            )
        } else if !input.impersonation_token {
            (
                CallerCategory::Unauthorized,
                CallerVerificationState::TokenTypeRejected,
                TokenSuitabilityCategory::UnsupportedTokenType,
                Some("unsupported_token_type".to_string()),
            )
        } else if !input.impersonation_level_suitable {
            (
                CallerCategory::Unauthorized,
                CallerVerificationState::TokenTypeRejected,
                TokenSuitabilityCategory::IdentificationOnlyRejected,
                Some("unsupported_impersonation_level".to_string()),
            )
        } else if !input.session_binding_valid {
            (
                CallerCategory::Unauthorized,
                CallerVerificationState::SessionMismatch,
                TokenSuitabilityCategory::ImpersonationSuitable,
                Some("session_binding_failed".to_string()),
            )
        } else if input.network_logon {
            (
                CallerCategory::Unauthorized,
                CallerVerificationState::NetworkLogonRejected,
                TokenSuitabilityCategory::ImpersonationSuitable,
                Some("network_logon_rejected".to_string()),
            )
        } else if input.anonymous {
            (
                CallerCategory::Unauthorized,
                CallerVerificationState::CallerNotAuthorized,
                TokenSuitabilityCategory::ImpersonationSuitable,
                Some("anonymous_rejected".to_string()),
            )
        } else if input.expected_service_identity {
            (
                CallerCategory::ExpectedServiceIdentity,
                CallerVerificationState::VerifiedServiceIdentity,
                TokenSuitabilityCategory::ImpersonationSuitable,
                None,
            )
        } else if input.administrator_member && policy.allow_administrators_for_read {
            (
                CallerCategory::AdministratorPolicy,
                CallerVerificationState::AdministratorPolicyVerified,
                TokenSuitabilityCategory::ImpersonationSuitable,
                None,
            )
        } else if input.interactive
            && !policy.production_service_mode
            && policy.allow_foreground_development
        {
            (
                CallerCategory::ForegroundDevelopment,
                CallerVerificationState::ForegroundDevelopment,
                TokenSuitabilityCategory::ImpersonationSuitable,
                None,
            )
        } else if input.interactive {
            (
                CallerCategory::InteractiveUser,
                CallerVerificationState::VerifiedInteractiveUser,
                TokenSuitabilityCategory::ImpersonationSuitable,
                None,
            )
        } else {
            (
                CallerCategory::Unauthorized,
                CallerVerificationState::CallerNotAuthorized,
                TokenSuitabilityCategory::ImpersonationSuitable,
                Some("policy_rejected".to_string()),
            )
        };

    let allowed_command_classes = match verification_state {
        CallerVerificationState::VerifiedInteractiveUser => vec![
            AllowedCommandClass::ReadStatus,
            AllowedCommandClass::ReadCanonicalModels,
            AllowedCommandClass::MutationAuthorizationEvaluation,
            AllowedCommandClass::FutureUserMutationCandidate,
        ],
        CallerVerificationState::VerifiedServiceIdentity => vec![
            AllowedCommandClass::ReadStatus,
            AllowedCommandClass::ReadCanonicalModels,
            AllowedCommandClass::MutationAuthorizationEvaluation,
        ],
        CallerVerificationState::AdministratorPolicyVerified => vec![
            AllowedCommandClass::ReadStatus,
            AllowedCommandClass::ReadCanonicalModels,
            AllowedCommandClass::MutationAuthorizationEvaluation,
            AllowedCommandClass::FutureUserMutationCandidate,
            AllowedCommandClass::FutureAdminMutationCandidate,
        ],
        CallerVerificationState::ForegroundDevelopment => vec![
            AllowedCommandClass::ReadStatus,
            AllowedCommandClass::ReadCanonicalModels,
            AllowedCommandClass::MutationAuthorizationEvaluation,
            AllowedCommandClass::ForegroundTestControl,
        ],
        _ => vec![AllowedCommandClass::None],
    };

    CallerVerificationSummary {
        schema_version: CALLER_VERIFICATION_SCHEMA_VERSION,
        verification_ref: format!("caller_verification_{}", Uuid::new_v4()),
        caller_category,
        verification_state,
        local_classification: if input.local_connection {
            LocalRemoteClassification::Local
        } else {
            LocalRemoteClassification::RemoteRejected
        },
        interactive_marker: input.interactive,
        service_marker: input.expected_service_identity,
        administrator_policy_marker: input.administrator_member
            && policy.allow_administrators_for_read,
        token_suitability,
        elevation_category: if input.token_available {
            if input.elevated {
                ElevationCategory::Elevated
            } else {
                ElevationCategory::Standard
            }
        } else {
            ElevationCategory::Unavailable
        },
        session_binding_state: if input.session_binding_valid {
            SessionBindingState::Bound
        } else {
            SessionBindingState::Mismatch
        },
        freshness_bucket: VerificationFreshnessBucket::CurrentConnection,
        allowed_command_classes,
        degraded_reason,
        audit_refs: vec!["caller_token_classified".to_string()],
        provenance_id: "windows_named_pipe_impersonation".to_string(),
        redaction_status: RedactionStatus::Redacted,
        production_mutations_enabled: false,
    }
}

#[cfg(not(windows))]
fn verification_failure_summary(
    state: CallerVerificationState,
    reason: &'static str,
) -> CallerVerificationSummary {
    CallerVerificationSummary {
        schema_version: CALLER_VERIFICATION_SCHEMA_VERSION,
        verification_ref: format!("caller_verification_{}", Uuid::new_v4()),
        caller_category: if state == CallerVerificationState::UnsupportedPlatform {
            CallerCategory::UnsupportedPlatform
        } else {
            CallerCategory::Unavailable
        },
        verification_state: state,
        local_classification: LocalRemoteClassification::Unavailable,
        interactive_marker: false,
        service_marker: false,
        administrator_policy_marker: false,
        token_suitability: TokenSuitabilityCategory::QueryFailed,
        elevation_category: ElevationCategory::Unavailable,
        session_binding_state: SessionBindingState::Failed,
        freshness_bucket: VerificationFreshnessBucket::Unavailable,
        allowed_command_classes: vec![AllowedCommandClass::None],
        degraded_reason: Some(reason.to_string()),
        audit_refs: vec!["caller_verification_failed".to_string()],
        provenance_id: "windows_named_pipe_impersonation".to_string(),
        redaction_status: RedactionStatus::Redacted,
        production_mutations_enabled: false,
    }
}

#[cfg(windows)]
fn verify_connected_pipe_caller(
    pipe_handle: windows_sys::Win32::Foundation::HANDLE,
    policy: CallerVerificationPolicy,
    audit_logger: &ServiceAuditLogger,
) -> Result<CallerVerificationSummary, IpcError> {
    use std::mem::{size_of, MaybeUninit};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, IsWellKnownSid,
        RevertToSelf, SecurityImpersonation, TokenElevation, TokenImpersonation,
        TokenImpersonationLevel, TokenSessionId, TokenType, TokenUser, WinAnonymousSid,
        WinBuiltinAdministratorsSid, WinInteractiveSid, WinLocalServiceSid, WinNetworkSid,
        SECURITY_IMPERSONATION_LEVEL, SECURITY_MAX_SID_SIZE, TOKEN_ELEVATION, TOKEN_QUERY,
        TOKEN_TYPE, TOKEN_USER, WELL_KNOWN_SID_TYPE,
    };
    use windows_sys::Win32::System::Pipes::{
        GetNamedPipeClientSessionId, ImpersonateNamedPipeClient,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    struct ImpersonationGuard {
        active: bool,
    }
    impl ImpersonationGuard {
        fn finish(mut self) {
            let reverted = unsafe { RevertToSelf() };
            if reverted == 0 {
                std::process::abort();
            }
            self.active = false;
        }
    }
    impl Drop for ImpersonationGuard {
        fn drop(&mut self) {
            if self.active && unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }

    unsafe fn query_scalar<T: Copy>(token: HANDLE, information_class: i32) -> Result<T, IpcError> {
        let mut value = MaybeUninit::<T>::uninit();
        let mut returned = 0_u32;
        let ok = GetTokenInformation(
            token,
            information_class,
            value.as_mut_ptr().cast(),
            size_of::<T>() as u32,
            &mut returned,
        );
        if ok == 0 || returned < size_of::<T>() as u32 {
            return Err(IpcError::caller_rejected("token_query_failed"));
        }
        Ok(value.assume_init())
    }

    unsafe fn token_is_member(
        token: HANDLE,
        sid_type: WELL_KNOWN_SID_TYPE,
    ) -> Result<bool, IpcError> {
        let mut sid = [0_u8; SECURITY_MAX_SID_SIZE as usize];
        let mut sid_len = sid.len() as u32;
        if CreateWellKnownSid(sid_type, null_mut(), sid.as_mut_ptr().cast(), &mut sid_len) == 0 {
            return Err(IpcError::caller_rejected("token_query_failed"));
        }
        let mut member = 0;
        if CheckTokenMembership(token, sid.as_mut_ptr().cast(), &mut member) == 0 {
            return Err(IpcError::caller_rejected("token_query_failed"));
        }
        Ok(member != 0)
    }

    unsafe fn token_user_is_well_known(
        token: HANDLE,
        sid_type: WELL_KNOWN_SID_TYPE,
    ) -> Result<bool, IpcError> {
        let mut required = 0_u32;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut required);
        if required < size_of::<TOKEN_USER>() as u32 {
            return Err(IpcError::caller_rejected("token_query_failed"));
        }
        let word_count = (required as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; word_count];
        let mut returned = 0_u32;
        if GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut returned,
        ) == 0
            || returned < size_of::<TOKEN_USER>() as u32
        {
            return Err(IpcError::caller_rejected("token_query_failed"));
        }
        let token_user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        Ok(IsWellKnownSid(token_user.User.Sid, sid_type) != 0)
    }

    let _ = audit_logger.log(
        "pipe_client_impersonation_started",
        None,
        "started",
        Some("local_pipe_connection"),
    );
    if unsafe { ImpersonateNamedPipeClient(pipe_handle) } == 0 {
        let _ = audit_logger.log(
            "pipe_client_impersonation_failed",
            None,
            "rejected",
            Some("impersonation_failed"),
        );
        return Err(IpcError::caller_rejected("impersonation_failed"));
    }
    let guard = ImpersonationGuard { active: true };

    let classification = (|| -> Result<(CallerVerificationSummary, bool), IpcError> {
        let mut pipe_session_id = 0_u32;
        if unsafe { GetNamedPipeClientSessionId(pipe_handle, &mut pipe_session_id) } == 0 {
            return Err(IpcError::caller_rejected("session_binding_failed"));
        }
        let mut token = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            return Err(IpcError::caller_rejected("token_unavailable"));
        }
        let token = OwnedHandle(token);

        let token_type: TOKEN_TYPE = unsafe { query_scalar(token.0, TokenType)? };
        let impersonation_level: SECURITY_IMPERSONATION_LEVEL =
            unsafe { query_scalar(token.0, TokenImpersonationLevel)? };
        let elevation: TOKEN_ELEVATION = unsafe { query_scalar(token.0, TokenElevation)? };
        let token_session_id: u32 = unsafe { query_scalar(token.0, TokenSessionId)? };
        let input = BoundedTokenClassificationInput {
            local_connection: true,
            token_available: true,
            impersonation_token: token_type == TokenImpersonation,
            impersonation_level_suitable: impersonation_level >= SecurityImpersonation,
            network_logon: unsafe { token_is_member(token.0, WinNetworkSid)? },
            anonymous: unsafe { token_is_member(token.0, WinAnonymousSid)? },
            interactive: unsafe { token_is_member(token.0, WinInteractiveSid)? },
            expected_service_identity: unsafe {
                token_user_is_well_known(token.0, WinLocalServiceSid)?
            },
            administrator_member: unsafe { token_is_member(token.0, WinBuiltinAdministratorsSid)? },
            elevated: elevation.TokenIsElevated != 0,
            session_binding_valid: pipe_session_id == token_session_id,
        };
        Ok((classify_bounded_token(input, policy), input.anonymous))
    })();

    guard.finish();
    let (summary, anonymous) = classification.inspect_err(|error| {
        let _ = audit_logger.log(
            "pipe_client_impersonation_failed",
            None,
            "rejected",
            Some(error.message.as_str()),
        );
    })?;

    let accepted = summary.verification_state.permits_read_only_commands();
    let _ = audit_logger.log(
        if accepted {
            "pipe_client_impersonation_succeeded"
        } else {
            "caller_token_rejected"
        },
        None,
        if accepted { "verified" } else { "rejected" },
        summary.degraded_reason.as_deref(),
    );
    let _ = audit_logger.log(
        "caller_token_classified",
        None,
        if accepted { "verified" } else { "rejected" },
        Some(caller_verification_state_label(summary.verification_state)),
    );
    match summary.verification_state {
        CallerVerificationState::RemoteCallerRejected => {
            let _ = audit_logger.log(
                "remote_caller_rejected",
                None,
                "rejected",
                Some("remote_transport_rejected"),
            );
        }
        CallerVerificationState::NetworkLogonRejected => {
            let _ = audit_logger.log(
                "network_logon_rejected",
                None,
                "rejected",
                Some("network_logon_rejected"),
            );
        }
        CallerVerificationState::TokenTypeRejected => {
            let _ = audit_logger.log(
                "token_type_rejected",
                None,
                "rejected",
                summary.degraded_reason.as_deref(),
            );
        }
        CallerVerificationState::SessionMismatch => {
            let _ = audit_logger.log(
                "session_binding_failed",
                None,
                "rejected",
                Some("session_binding_failed"),
            );
        }
        CallerVerificationState::CallerNotAuthorized if anonymous => {
            let _ = audit_logger.log(
                "anonymous_caller_rejected",
                None,
                "rejected",
                Some("anonymous_rejected"),
            );
        }
        _ => {}
    }
    Ok(summary)
}

#[cfg(not(windows))]
fn verify_connected_pipe_caller(
    _pipe_handle: (),
    _policy: CallerVerificationPolicy,
    _audit_logger: &ServiceAuditLogger,
) -> Result<CallerVerificationSummary, IpcError> {
    Ok(verification_failure_summary(
        CallerVerificationState::UnsupportedPlatform,
        "unsupported_platform",
    ))
}

fn caller_verification_state_label(state: CallerVerificationState) -> &'static str {
    match state {
        CallerVerificationState::VerifiedInteractiveUser => "verified_interactive_user",
        CallerVerificationState::VerifiedServiceIdentity => "verified_service_identity",
        CallerVerificationState::AdministratorPolicyVerified => "administrator_policy_verified",
        CallerVerificationState::CallerNotAuthorized => "caller_not_authorized",
        CallerVerificationState::CallerIdentityUnavailable => "caller_identity_unavailable",
        CallerVerificationState::RemoteCallerRejected => "remote_caller_rejected",
        CallerVerificationState::NetworkLogonRejected => "network_logon_rejected",
        CallerVerificationState::TokenTypeRejected => "token_type_rejected",
        CallerVerificationState::ImpersonationFailed => "impersonation_failed",
        CallerVerificationState::TokenQueryFailed => "token_query_failed",
        CallerVerificationState::SessionMismatch => "session_mismatch",
        CallerVerificationState::UnsupportedPlatform => "unsupported_platform",
        CallerVerificationState::ForegroundDevelopment => "foreground_development",
    }
}

fn service_process_name() -> String {
    env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "sentinel-guard-elevated.exe".to_string())
}

fn validate_safe_ipc_text(field: &str, value: &str) -> Result<(), IpcError> {
    if value.trim().is_empty() || value.len() > 128 {
        return Err(IpcError::schema(format!(
            "{field} must be non-empty and bounded"
        )));
    }
    let normalized = value.to_ascii_lowercase();
    for marker in [
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
    ] {
        if normalized.contains(marker) {
            return Err(IpcError::schema(format!(
                "{field} contains a forbidden sensitive marker"
            )));
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum ServiceRuntimeError {
    Io(io::Error),
    Frame(IpcFrameError),
    Runtime(String),
}

impl fmt::Display for ServiceRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "service runtime IO failed: {error}"),
            Self::Frame(error) => write!(f, "service runtime frame failed: {error}"),
            Self::Runtime(error) => write!(f, "service runtime initialization failed: {error}"),
        }
    }
}

impl std::error::Error for ServiceRuntimeError {}

impl From<io::Error> for ServiceRuntimeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<IpcFrameError> for ServiceRuntimeError {
    fn from(value: IpcFrameError) -> Self {
        Self::Frame(value)
    }
}

impl ServiceRuntimeError {
    pub fn runtime(reason: impl Into<String>) -> Self {
        Self::Runtime(reason.into())
    }
}

pub fn run_standalone_named_pipe_server(pipe_name: &str) -> Result<(), ServiceRuntimeError> {
    let audit_logger = ServiceAuditLogger::program_data_default();
    let _ = audit_logger.log("service_start", None, "started", Some("standalone"));
    let mut dispatcher = ServiceCommandDispatcher::new(audit_logger.clone());
    loop {
        run_one_pipe_connection(pipe_name, &mut dispatcher)?;
    }
}

pub fn dispatch_json_request_for_tests(
    dispatcher: &mut ServiceCommandDispatcher,
    value: Value,
) -> IpcResponse<Value> {
    match serde_json::from_value::<IpcRequest<Value>>(value) {
        Ok(request) => dispatcher.dispatch(request),
        Err(error) => IpcResponse::malformed(IpcError::schema(format!(
            "request envelope failed strict schema validation: {error}"
        ))),
    }
}

#[cfg(windows)]
pub fn run_one_pipe_connection(
    pipe_name: &str,
    dispatcher: &mut ServiceCommandDispatcher,
) -> Result<(), ServiceRuntimeError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    struct PipeSecurity {
        descriptor: *mut core::ffi::c_void,
        attributes: SECURITY_ATTRIBUTES,
    }

    impl PipeSecurity {
        fn local_service_and_interactive_users() -> io::Result<Self> {
            let sddl = wide(&pipe_acl_sddl(true));
            let mut descriptor = null_mut();
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                descriptor,
                attributes: SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: descriptor,
                    bInheritHandle: 0,
                },
            })
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            if !self.descriptor.is_null() {
                unsafe {
                    LocalFree(self.descriptor as _);
                }
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    let security = PipeSecurity::local_service_and_interactive_users()?;
    let pipe = wide(pipe_name);
    let handle = unsafe {
        CreateNamedPipeW(
            pipe.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_FRAME_BYTES as u32,
            MAX_FRAME_BYTES as u32,
            5_000,
            &security.attributes,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }

    let connected = unsafe { ConnectNamedPipe(handle, null_mut()) };
    if connected == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_PIPE_CONNECTED {
            unsafe {
                CloseHandle(handle);
            }
            return Err(io::Error::from_raw_os_error(error as i32).into());
        }
    }

    dispatcher.connection_accepted();
    let mut file = unsafe { File::from_raw_handle(handle as _) };
    let session_result = handle_pipe_session(&mut file, dispatcher, None);
    unsafe {
        DisconnectNamedPipe(file.as_raw_handle() as HANDLE);
    }
    dispatcher.connection_closed();
    session_result
}

#[cfg(windows)]
pub fn run_one_pipe_connection_until_stop(
    pipe_name: &str,
    dispatcher: &mut ServiceCommandDispatcher,
    stop_requested: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), ServiceRuntimeError> {
    if stop_requested.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    struct PipeSecurity {
        descriptor: *mut core::ffi::c_void,
        attributes: SECURITY_ATTRIBUTES,
    }

    impl PipeSecurity {
        fn local_service_and_interactive_users(allow_administrators: bool) -> io::Result<Self> {
            let sddl = pipe_acl_sddl(allow_administrators);
            let sddl = wide(&sddl);
            let mut descriptor = null_mut();
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                descriptor,
                attributes: SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: descriptor,
                    bInheritHandle: 0,
                },
            })
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            if !self.descriptor.is_null() {
                unsafe {
                    LocalFree(self.descriptor as _);
                }
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    let security = PipeSecurity::local_service_and_interactive_users(true)?;
    let pipe = wide(pipe_name);
    let handle = unsafe {
        CreateNamedPipeW(
            pipe.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_FRAME_BYTES as u32,
            MAX_FRAME_BYTES as u32,
            1_000,
            &security.attributes,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }

    let connected = unsafe { ConnectNamedPipe(handle, null_mut()) };
    if connected == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_PIPE_CONNECTED {
            unsafe {
                CloseHandle(handle);
            }
            return Err(io::Error::from_raw_os_error(error as i32).into());
        }
    }

    dispatcher.connection_accepted();
    let mut file = unsafe { File::from_raw_handle(handle as _) };
    let stop = stop_requested.load(std::sync::atomic::Ordering::SeqCst);
    let session_result = handle_pipe_session(&mut file, dispatcher, Some(stop_requested));
    unsafe {
        DisconnectNamedPipe(file.as_raw_handle() as HANDLE);
    }
    dispatcher.connection_closed();
    session_result?;
    if stop {
        return Ok(());
    }
    Ok(())
}

#[cfg(windows)]
fn handle_pipe_session(
    file: &mut File,
    dispatcher: &mut ServiceCommandDispatcher,
    stop_requested: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<(), ServiceRuntimeError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;

    match dispatcher.begin_session(file) {
        Ok(pending) => {
            let caller_verification = match verify_connected_pipe_caller(
                file.as_raw_handle() as HANDLE,
                dispatcher.caller_verification_policy,
                &dispatcher.audit_logger,
            ) {
                Ok(summary) => summary,
                Err(error) => {
                    let response = IpcResponse::malformed(error);
                    write_json_frame_or_closed(file, &response)?;
                    return Ok(());
                }
            };
            let session = match dispatcher.complete_session(file, pending, caller_verification) {
                Ok(session) => session,
                Err(error) => {
                    let _ = dispatcher.audit_logger.log(
                        "session_binding_failed",
                        None,
                        "rejected",
                        Some(error.code.as_str()),
                    );
                    let response = IpcResponse::malformed(error);
                    write_json_frame_or_closed(file, &response)?;
                    return Ok(());
                }
            };
            let _ = dispatcher.audit_logger.log(
                "session_binding_succeeded",
                None,
                "verified",
                Some("current_connection"),
            );
            for _ in 0..MAX_REQUESTS_PER_SESSION {
                let envelope = match read_json_frame::<_, IpcEnvelope<Value>>(file) {
                    Ok(envelope) => envelope,
                    Err(IpcFrameError::Io(error))
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::BrokenPipe
                                | io::ErrorKind::ConnectionReset
                        ) =>
                    {
                        return Ok(());
                    }
                    Err(error) => {
                        if stop_requested
                            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst))
                        {
                            return Ok(());
                        }
                        let response = IpcResponse::malformed(IpcError::schema(error.to_string()));
                        write_json_frame_or_closed(file, &response)?;
                        return Ok(());
                    }
                };
                let response = dispatcher.dispatch_envelope(&session, envelope);
                write_json_frame_or_closed(file, &response)?;
            }
        }
        Err(error) => {
            let _ = dispatcher.audit_logger.log(
                "ipc_handshake_failed",
                None,
                "rejected",
                Some(error.message.as_str()),
            );
            if stop_requested.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst)) {
                return Ok(());
            }
            let response = IpcResponse::malformed(error);
            write_json_frame_or_closed(file, &response)?;
        }
    }
    Ok(())
}

fn write_json_frame_or_closed<W, T>(writer: &mut W, value: &T) -> Result<(), ServiceRuntimeError>
where
    W: Write,
    T: Serialize,
{
    match write_json_frame(writer, value) {
        Ok(()) => Ok(()),
        Err(error) if ipc_frame_is_closed_pipe(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn ipc_frame_is_closed_pipe(error: &IpcFrameError) -> bool {
    match error {
        IpcFrameError::Io(error) => {
            matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) || error.raw_os_error() == Some(232)
        }
        _ => false,
    }
}

#[cfg(windows)]
pub fn wake_local_pipe(pipe_name: &str) {
    let _ = OpenOptions::new().read(true).write(true).open(pipe_name);
}

#[cfg(windows)]
pub fn pipe_acl_sddl(allow_administrators: bool) -> String {
    if allow_administrators {
        "D:P(A;;GA;;;SY)(A;;GA;;;LS)(A;;0x0012019B;;;IU)(A;;0x0012019B;;;BA)".to_string()
    } else {
        "D:P(A;;GA;;;SY)(A;;GA;;;LS)(A;;0x0012019B;;;IU)".to_string()
    }
}

#[cfg(not(windows))]
pub fn run_one_pipe_connection(
    _pipe_name: &str,
    _dispatcher: &mut ServiceCommandDispatcher,
) -> Result<(), ServiceRuntimeError> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Sentinel Guard elevated service IPC is Windows-only",
    )
    .into())
}

#[cfg(not(windows))]
pub fn run_one_pipe_connection_until_stop(
    _pipe_name: &str,
    _dispatcher: &mut ServiceCommandDispatcher,
    _stop_requested: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), ServiceRuntimeError> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Sentinel Guard service host IPC is Windows-only",
    )
    .into())
}

#[cfg(not(windows))]
pub fn wake_local_pipe(_pipe_name: &str) {}

#[cfg(not(windows))]
pub fn pipe_acl_sddl(_allow_administrators: bool) -> String {
    "unsupported_platform".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SERVICE_HOST_RUNTIME_TEST_LOCK;
    use sentinel_app_core::RuntimeContainerBuilder;
    use sentinel_contracts::read_model_snapshot::{
        CanonicalReadModelCategory, CanonicalReadModelSnapshot, CanonicalReadModelSnapshotItem,
        ReadModelSnapshotFreshness, READ_MODEL_SNAPSHOT_SCHEMA_VERSION,
    };
    use sentinel_contracts::runtime_ownership::{
        RuntimeComponentLifecycle, RuntimeHealthState, RuntimeMode, RuntimeMutationTrustState,
        RuntimeOwnerCategory, RuntimeOwnershipSummary, RuntimeProviderZeroSummary,
        RuntimeShutdownState, RuntimeShutdownSummary, RuntimeTransitionState,
        RUNTIME_OWNERSHIP_PROTOCOL_VERSION, RUNTIME_OWNERSHIP_SCHEMA_VERSION,
    };
    use sentinel_contracts::{
        policy_for_command, IpHelperScheduleConfig, IpHelperScheduleLeaseState,
        IpHelperScheduleState, MutationAuthorizationResult, MutationCapabilityCategory,
        MutationCommandId, MutationExecutionReceipt, MutationExecutionRequest,
        MutationExecutionResultCategory, MutationIdempotencyState, MutationIntentTimeBucket,
        MutationIntentTtlBucket, ProviderLifecycleCategory, ReadModelSnapshotId, RedactionStatus,
        ServiceReadCommandResponse, MUTATION_AUTHORIZATION_SCHEMA_VERSION,
    };
    use serde_json::json;

    fn dispatcher() -> ServiceCommandDispatcher {
        ServiceCommandDispatcher::new(ServiceAuditLogger::with_path(env::temp_dir().join(
            format!("sentinel-guard-service-test-audit-{}.jsonl", Uuid::new_v4()),
        )))
    }

    fn verified_test_summary() -> CallerVerificationSummary {
        let mut summary = classify_bounded_token(
            BoundedTokenClassificationInput {
                local_connection: true,
                token_available: true,
                impersonation_token: true,
                impersonation_level_suitable: true,
                interactive: true,
                session_binding_valid: true,
                ..BoundedTokenClassificationInput::default()
            },
            CallerVerificationPolicy::service_mode(),
        );
        summary.session_binding_state = SessionBindingState::Bound;
        summary
    }

    fn activate_test_session(dispatcher: &mut ServiceCommandDispatcher, session: &IpcSessionState) {
        dispatcher.active_session_reference = Some(session.session_reference.clone());
        dispatcher.active_verification_ref =
            Some(session.caller_verification.verification_ref.clone());
        dispatcher.last_caller_verification = Some(session.caller_verification.clone());
        dispatcher.active_next_sequence_number = 1;
    }

    fn service_owned_runtime_summary() -> RuntimeOwnershipSummary {
        RuntimeOwnershipSummary {
            ownership_ref: "servicehost_owner_ref".to_string(),
            ownership_epoch: 7,
            runtime_mode: RuntimeMode::ServiceOwned,
            owner_category: RuntimeOwnerCategory::ServiceHost,
            runtime_health: RuntimeHealthState::Ready,
            transition_state: RuntimeTransitionState::Ready,
            protocol_version: RUNTIME_OWNERSHIP_PROTOCOL_VERSION,
            schema_version: RUNTIME_OWNERSHIP_SCHEMA_VERSION,
            degraded_reason: None,
            mutation_trust_state: RuntimeMutationTrustState::ImpersonationNotImplemented,
            mutation_commands_enabled: false,
            provider_controller_state: "inactive".to_string(),
            provider_call_count: 0,
            provider_zero: RuntimeProviderZeroSummary::default(),
            scheduler_state: "disabled".to_string(),
            scheduler_host_state: "stopped".to_string(),
            sampler_state: "inactive".to_string(),
            storage_owner_state: "service_owned".to_string(),
            canonical_read_model_owner: "service_host".to_string(),
            snapshot_freshness: "fresh".to_string(),
            shutdown: RuntimeShutdownSummary {
                state: RuntimeShutdownState::NotStarted,
                total_timeout_bucket: "bounded".to_string(),
                mutation_leases_invalidated: false,
                scheduler_host_cancellation_signalled: false,
                scheduler_host_joined: false,
                provider_stop_called: false,
                stages: Vec::new(),
                audit_refs: Vec::new(),
                redaction_status: RedactionStatus::Redacted,
            },
            component_summaries: Vec::new(),
            audit_refs: Vec::new(),
            provenance_id: "servicehost_mutation_authorization_test".to_string(),
            time_bucket: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn mutation_intent(session: &IpcSessionState) -> MutationIntent {
        mutation_intent_for(
            session,
            MutationCommandId::ActivateIpHelperProvider,
            7,
            "mutation_intent_ref",
            "idempotency_ref",
        )
    }

    fn mutation_intent_for(
        session: &IpcSessionState,
        command_id: MutationCommandId,
        ownership_epoch: u64,
        intent_ref: &str,
        idempotency_ref: &str,
    ) -> MutationIntent {
        let policy = policy_for_command(command_id);
        let (target_capability_ref, target_capability_category) = if matches!(
            command_id,
            MutationCommandId::ActivateEtwProvider
                | MutationCommandId::PauseEtwProvider
                | MutationCommandId::ResumeEtwProvider
                | MutationCommandId::StopEtwProvider
        ) {
            ("etw_provider_ref", MutationCapabilityCategory::EtwProvider)
        } else if matches!(
            command_id,
            MutationCommandId::ActivateAuthRemoteSensing
                | MutationCommandId::PauseAuthRemoteSensing
                | MutationCommandId::ResumeAuthRemoteSensing
                | MutationCommandId::StopAuthRemoteSensing
        ) {
            (
                "auth_remote_sensing_provider_ref",
                MutationCapabilityCategory::AuthRemoteSensingProvider,
            )
        } else {
            (
                "ip_helper_provider_ref",
                MutationCapabilityCategory::IpHelperProvider,
            )
        };
        MutationIntent {
            schema_version: MUTATION_AUTHORIZATION_SCHEMA_VERSION,
            intent_ref: intent_ref.to_string(),
            request_ref: format!("{intent_ref}_request_ref"),
            ipc_session_ref: session.session_reference.clone(),
            caller_verification_ref: session.caller_verification.verification_ref.clone(),
            command_id,
            policy_ref: policy.policy_ref,
            policy_version: policy.policy_version,
            target_capability_ref: target_capability_ref.to_string(),
            target_capability_category,
            requested_operation_category: command_id.as_str().to_string(),
            created_time_bucket: MutationIntentTimeBucket::CurrentConnection,
            expiry_ttl_bucket: MutationIntentTtlBucket::ThirtySeconds,
            ownership_epoch,
            idempotency_ref: Some(idempotency_ref.to_string()),
            explicit_user_action: true,
            dry_run: true,
            audit_refs: vec!["mutation_intent_received".to_string()],
            provenance_id: "servicehost_mutation_authorization".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn activate_execution_request(
        decision_ref: String,
        intent: MutationIntent,
    ) -> MutationExecutionRequest {
        MutationExecutionRequest {
            schema_version: MUTATION_AUTHORIZATION_SCHEMA_VERSION,
            decision_ref,
            intent,
            explicit_user_action: true,
            provenance_id: "servicehost_ip_helper_production_ipc".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn schedule_execution_request(
        decision_ref: String,
        intent: MutationIntent,
        schedule_config: Option<IpHelperScheduleConfig>,
    ) -> IpHelperScheduleMutationRequest {
        IpHelperScheduleMutationRequest {
            execution_request: MutationExecutionRequest {
                schema_version: MUTATION_AUTHORIZATION_SCHEMA_VERSION,
                decision_ref,
                intent,
                explicit_user_action: true,
                provenance_id: "servicehost_ip_helper_schedule_control_plane".to_string(),
                redaction_status: RedactionStatus::Redacted,
            },
            schedule_config,
            explicit_user_action: true,
            provenance_id: "servicehost_ip_helper_schedule_control_plane".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn dispatch_decision(
        dispatcher: &mut ServiceCommandDispatcher,
        session: &IpcSessionState,
        sequence_number: u64,
        request_id: &str,
        intent: MutationIntent,
    ) -> MutationAuthorizationDecision {
        let envelope = IpcEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            schema_version: RUNTIME_IPC_SCHEMA_VERSION,
            request_id: request_id.to_string(),
            session_reference: session.session_reference.clone(),
            client_nonce: session.client_nonce.clone(),
            server_nonce: session.server_nonce.clone(),
            sequence_number,
            command_id: ServiceCommand::EvaluateMutationIntent.as_str().to_string(),
            response_status: "request".to_string(),
            payload: serde_json::to_value(intent).expect("intent payload"),
        };
        let response = dispatcher.dispatch_envelope(session, envelope);
        assert_eq!(response.response_status, "ok", "{:?}", response.payload);
        serde_json::from_value(response.payload).expect("authorization decision")
    }

    fn dispatch_execution_receipt(
        dispatcher: &mut ServiceCommandDispatcher,
        session: &IpcSessionState,
        sequence_number: u64,
        command: ServiceCommand,
        request_id: &str,
        request: MutationExecutionRequest,
    ) -> MutationExecutionReceipt {
        let envelope = IpcEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            schema_version: RUNTIME_IPC_SCHEMA_VERSION,
            request_id: request_id.to_string(),
            session_reference: session.session_reference.clone(),
            client_nonce: session.client_nonce.clone(),
            server_nonce: session.server_nonce.clone(),
            sequence_number,
            command_id: command.as_str().to_string(),
            response_status: "request".to_string(),
            payload: serde_json::to_value(request).expect("execution payload"),
        };
        let response = dispatcher.dispatch_envelope(session, envelope);
        assert_eq!(response.response_status, "ok", "{:?}", response.payload);
        serde_json::from_value(response.payload).expect("execution receipt")
    }

    fn dispatch_schedule_execution_receipt(
        dispatcher: &mut ServiceCommandDispatcher,
        session: &IpcSessionState,
        sequence_number: u64,
        command: ServiceCommand,
        request_id: &str,
        request: IpHelperScheduleMutationRequest,
    ) -> MutationExecutionReceipt {
        let envelope = IpcEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            schema_version: RUNTIME_IPC_SCHEMA_VERSION,
            request_id: request_id.to_string(),
            session_reference: session.session_reference.clone(),
            client_nonce: session.client_nonce.clone(),
            server_nonce: session.server_nonce.clone(),
            sequence_number,
            command_id: command.as_str().to_string(),
            response_status: "request".to_string(),
            payload: serde_json::to_value(request).expect("schedule execution payload"),
        };
        let response = dispatcher.dispatch_envelope(session, envelope);
        assert_eq!(response.response_status, "ok", "{:?}", response.payload);
        serde_json::from_value(response.payload).expect("schedule execution receipt")
    }

    fn read_command_snapshot() -> CanonicalReadModelSnapshot {
        CanonicalReadModelSnapshot {
            snapshot_id: ReadModelSnapshotId::new_v4(),
            ownership_ref: "runtime_owner_ref".to_string(),
            ownership_epoch: 7,
            runtime_owner: RuntimeOwnerCategory::ServiceHost,
            runtime_mode: RuntimeMode::ServiceOwned,
            schema_version: READ_MODEL_SNAPSHOT_SCHEMA_VERSION,
            generation_bucket: "generation_current".to_string(),
            generated_time_bucket: Timestamp::now(),
            freshness_state: ReadModelSnapshotFreshness::Fresh,
            partial_state: false,
            items: vec![
                CanonicalReadModelSnapshotItem {
                    model_category: CanonicalReadModelCategory::RuntimeOwnership,
                    lifecycle_state: RuntimeComponentLifecycle::Ready,
                    health_state: RuntimeHealthState::Ready,
                    bounded_categories: vec!["service_owned_runtime".to_string()],
                    bounded_buckets: vec!["generation_current".to_string()],
                    bounded_refs: vec!["runtime_owner_ref".to_string()],
                    degraded_reason: None,
                    missing_visibility_flags: vec!["provider_execution_deferred".to_string()],
                    provenance_id: "service_ipc_read_commands".to_string(),
                    redaction_status: RedactionStatus::Redacted,
                },
                CanonicalReadModelSnapshotItem {
                    model_category: CanonicalReadModelCategory::Risk,
                    lifecycle_state: RuntimeComponentLifecycle::Ready,
                    health_state: RuntimeHealthState::Ready,
                    bounded_categories: vec!["risk_summary".to_string()],
                    bounded_buckets: vec!["risk_low".to_string()],
                    bounded_refs: vec!["risk_summary_ref".to_string()],
                    degraded_reason: None,
                    missing_visibility_flags: vec!["provider_execution_deferred".to_string()],
                    provenance_id: "service_ipc_read_commands".to_string(),
                    redaction_status: RedactionStatus::Redacted,
                },
            ],
            degraded_reason: None,
            missing_visibility_flags: vec!["provider_execution_deferred".to_string()],
            provenance_id: "service_ipc_read_commands".to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    #[test]
    fn ping_status_capture_and_process_snapshot_follow_strict_schema() {
        let mut dispatcher = dispatcher();
        let ping = dispatcher.dispatch(IpcRequest::new(
            ServiceCommand::Ping,
            json!({ "nonce": "abc-123" }),
        ));
        let status = dispatcher.dispatch(IpcRequest::new(ServiceCommand::Status, json!({})));
        let capture =
            dispatcher.dispatch(IpcRequest::new(ServiceCommand::CaptureHealth, json!({})));
        let processes =
            dispatcher.dispatch(IpcRequest::new(ServiceCommand::ProcessSnapshot, json!({})));

        assert!(ping.error.is_none());
        assert_eq!(
            ping.result
                .as_ref()
                .and_then(|value| value.get("nonce"))
                .and_then(Value::as_str),
            Some("abc-123")
        );
        assert_eq!(
            status
                .result
                .as_ref()
                .and_then(|value| value.get("service_status"))
                .and_then(Value::as_str),
            Some("running")
        );
        assert_eq!(
            capture
                .result
                .as_ref()
                .and_then(|value| value.get("capture_active"))
                .and_then(Value::as_bool),
            Some(false)
        );
        assert!(processes
            .result
            .as_ref()
            .and_then(|value| value.get("processes"))
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty()));
    }

    #[test]
    fn unknown_commands_and_malformed_params_are_rejected() {
        let mut dispatcher = dispatcher();
        let unknown = dispatcher.dispatch(IpcRequest {
            id: "request-1".to_string(),
            command: "start_capture".to_string(),
            params: json!({}),
            timestamp: Timestamp::now(),
        });
        let malformed = dispatcher.dispatch(IpcRequest::new(
            ServiceCommand::Ping,
            json!({ "nonce": "abc", "extra": true }),
        ));

        assert_eq!(
            unknown.error.as_ref().map(|error| error.code.as_str()),
            Some("COMMAND_NOT_ALLOWED")
        );
        let unknown_error = unknown.error.as_ref().expect("unknown command error");
        assert!(!unknown_error.message.contains("start_capture"));
        assert_eq!(
            malformed.error.as_ref().map(|error| error.code.as_str()),
            Some("SCHEMA_VALIDATION_ERROR")
        );
    }

    #[test]
    fn read_commands_are_allowlisted_and_return_bounded_snapshots() {
        let mut dispatcher =
            dispatcher().with_canonical_read_model_snapshot(read_command_snapshot());

        for command_id in ServiceReadCommandId::all() {
            dispatcher
                .allowlist
                .ensure_allowed(ServiceCommand::Read(*command_id), IpcAccessLevel::Read)
                .expect("read command is allowlisted");
        }

        let response = dispatcher.dispatch(IpcRequest::new(
            ServiceCommand::Read(ServiceReadCommandId::GetRuntimeOwnership),
            json!({ "page_size": 1 }),
        ));
        assert!(response.error.is_none());
        let response: ServiceReadCommandResponse =
            serde_json::from_value(response.result.expect("read command response"))
                .expect("bounded read command response");
        assert_eq!(
            response.command_id,
            ServiceReadCommandId::GetRuntimeOwnership
        );
        assert_eq!(response.ownership_epoch, 7);
        assert_eq!(response.items.len(), 1);
        assert!(!response.truncated);
        let serialized = serde_json::to_string(&response).expect("serialize read response");
        let lowered = serialized.to_ascii_lowercase();
        assert!(!lowered.contains("c:\\"));
        assert!(!lowered.contains("raw_db_cursor"));
        assert!(!lowered.contains("authorization_nonce"));
        assert!(!lowered.contains("secret"));
    }

    #[test]
    fn read_commands_reject_version_mismatch_and_remain_bounded() {
        let mut dispatcher =
            dispatcher().with_canonical_read_model_snapshot(read_command_snapshot());
        let session = IpcSessionState {
            session_reference: "session-ref".to_string(),
            client_nonce: "client-nonce".to_string(),
            server_nonce: "server-nonce".to_string(),
            challenge_nonce: "challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };
        activate_test_session(&mut dispatcher, &session);

        let mut request = IpcEnvelope::request(
            &session,
            ServiceCommand::Read(ServiceReadCommandId::GetRuntimeOwnership),
            json!({}),
        );
        request.schema_version = SchemaVersion::new(9, 9, 9);
        let mismatch = dispatcher.dispatch_envelope(&session, request);

        assert_eq!(mismatch.response_status, "error");
        assert_eq!(
            mismatch.payload.get("code").and_then(Value::as_str),
            Some("PROTOCOL_ERROR")
        );
    }

    #[test]
    fn length_prefixed_json_frame_round_trips() {
        let request = IpcRequest::new(ServiceCommand::Status, json!({}));
        let mut bytes = Vec::new();
        write_json_frame(&mut bytes, &request).expect("write frame");
        let decoded: IpcRequest<Value> =
            read_json_frame(&mut bytes.as_slice()).expect("read frame");

        assert_eq!(decoded.command, "status");
        assert_eq!(decoded.id, request.id);
    }

    #[test]
    fn versioned_envelope_requires_valid_sequence_and_rejects_replay() {
        let mut dispatcher = dispatcher();
        let session = IpcSessionState {
            session_reference: "session-ref".to_string(),
            client_nonce: "client-nonce".to_string(),
            server_nonce: "server-nonce".to_string(),
            challenge_nonce: "challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };
        activate_test_session(&mut dispatcher, &session);

        let mut request = IpcEnvelope::request(&session, ServiceCommand::Status, json!({}));
        let invalid_sequence = {
            request.sequence_number = 2;
            dispatcher.dispatch_envelope(&session, request.clone())
        };
        assert_eq!(invalid_sequence.response_status, "error");
        assert_eq!(
            invalid_sequence.payload.get("code").and_then(Value::as_str),
            Some("INVALID_SEQUENCE")
        );

        request.sequence_number = 1;
        let ok = dispatcher.dispatch_envelope(&session, request.clone());
        assert_eq!(ok.response_status, "ok");
        request.sequence_number = 2;
        let replay = dispatcher.dispatch_envelope(&session, request);
        assert_eq!(replay.response_status, "error");
        assert_eq!(
            replay.payload.get("code").and_then(Value::as_str),
            Some("REPLAY_REJECTED")
        );
    }

    #[test]
    fn pipe_acl_metadata_is_local_only_without_raw_identity_output() {
        let sddl = pipe_acl_sddl(true);
        assert!(sddl.contains("LS"));
        assert!(sddl.contains("IU"));
        assert!(sddl.contains("BA"));
        assert!(sddl.contains("0x0012019B"));
        assert!(!sddl.contains("GRGW"));
        let lowered = sddl.to_ascii_lowercase();
        assert!(!lowered.contains("sid"));
        assert!(!lowered.contains("token"));
        assert!(!lowered.contains("anonymous"));
    }

    fn accepted_token_input() -> BoundedTokenClassificationInput {
        BoundedTokenClassificationInput {
            local_connection: true,
            token_available: true,
            impersonation_token: true,
            impersonation_level_suitable: true,
            interactive: true,
            session_binding_valid: true,
            ..BoundedTokenClassificationInput::default()
        }
    }

    #[test]
    fn bounded_token_classification_accepts_only_policy_supported_local_categories() {
        let interactive = classify_bounded_token(
            accepted_token_input(),
            CallerVerificationPolicy::service_mode(),
        );
        assert_eq!(
            interactive.verification_state,
            CallerVerificationState::VerifiedInteractiveUser
        );
        assert!(interactive.permits_command_class(AllowedCommandClass::ReadStatus));
        assert!(interactive.permits_command_class(AllowedCommandClass::ReadCanonicalModels));

        let service = classify_bounded_token(
            BoundedTokenClassificationInput {
                expected_service_identity: true,
                interactive: false,
                ..accepted_token_input()
            },
            CallerVerificationPolicy::service_mode(),
        );
        assert_eq!(
            service.verification_state,
            CallerVerificationState::VerifiedServiceIdentity
        );

        let administrator = classify_bounded_token(
            BoundedTokenClassificationInput {
                administrator_member: true,
                ..accepted_token_input()
            },
            CallerVerificationPolicy::service_mode(),
        );
        assert_eq!(
            administrator.verification_state,
            CallerVerificationState::AdministratorPolicyVerified
        );

        let administrator_without_policy = classify_bounded_token(
            BoundedTokenClassificationInput {
                administrator_member: true,
                interactive: false,
                ..accepted_token_input()
            },
            CallerVerificationPolicy {
                production_service_mode: true,
                allow_administrators_for_read: false,
                allow_foreground_development: false,
            },
        );
        assert_eq!(
            administrator_without_policy.verification_state,
            CallerVerificationState::CallerNotAuthorized
        );
    }

    #[test]
    fn bounded_token_classification_rejects_remote_network_anonymous_and_unsafe_tokens() {
        let cases = [
            (
                BoundedTokenClassificationInput {
                    local_connection: false,
                    ..accepted_token_input()
                },
                CallerVerificationState::RemoteCallerRejected,
            ),
            (
                BoundedTokenClassificationInput {
                    network_logon: true,
                    ..accepted_token_input()
                },
                CallerVerificationState::NetworkLogonRejected,
            ),
            (
                BoundedTokenClassificationInput {
                    anonymous: true,
                    ..accepted_token_input()
                },
                CallerVerificationState::CallerNotAuthorized,
            ),
            (
                BoundedTokenClassificationInput {
                    impersonation_token: false,
                    ..accepted_token_input()
                },
                CallerVerificationState::TokenTypeRejected,
            ),
            (
                BoundedTokenClassificationInput {
                    token_available: false,
                    ..accepted_token_input()
                },
                CallerVerificationState::CallerIdentityUnavailable,
            ),
            (
                BoundedTokenClassificationInput {
                    session_binding_valid: false,
                    ..accepted_token_input()
                },
                CallerVerificationState::SessionMismatch,
            ),
        ];

        for (input, expected_state) in cases {
            let summary = classify_bounded_token(input, CallerVerificationPolicy::service_mode());
            assert_eq!(summary.verification_state, expected_state);
            assert!(!summary.permits_read_only_commands());
            assert_eq!(
                summary.allowed_command_classes,
                vec![AllowedCommandClass::None]
            );
        }
    }

    #[test]
    fn foreground_development_is_explicit_and_never_available_in_service_mode() {
        let development = classify_bounded_token(
            accepted_token_input(),
            CallerVerificationPolicy::foreground_development_test(),
        );
        assert_eq!(
            development.verification_state,
            CallerVerificationState::ForegroundDevelopment
        );
        assert!(!development.production_mutations_enabled);

        let production = classify_bounded_token(
            accepted_token_input(),
            CallerVerificationPolicy {
                production_service_mode: true,
                allow_administrators_for_read: false,
                allow_foreground_development: true,
            },
        );
        assert_eq!(
            production.verification_state,
            CallerVerificationState::VerifiedInteractiveUser
        );
    }

    #[test]
    fn caller_trust_is_session_bound_and_command_class_specific() {
        let mut dispatcher = dispatcher();
        let mut session = IpcSessionState {
            session_reference: "session-ref".to_string(),
            client_nonce: "client-nonce".to_string(),
            server_nonce: "server-nonce".to_string(),
            challenge_nonce: "challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };

        session.caller_verification.allowed_command_classes = vec![AllowedCommandClass::ReadStatus];
        activate_test_session(&mut dispatcher, &session);
        let canonical_read = IpcEnvelope::request(
            &session,
            ServiceCommand::Read(ServiceReadCommandId::GetRuntimeOwnership),
            json!({}),
        );
        let rejected = dispatcher.dispatch_envelope(&session, canonical_read);
        assert_eq!(rejected.response_status, "error");
        assert_eq!(
            rejected.payload.get("code").and_then(Value::as_str),
            Some("CALLER_REJECTED")
        );

        session.caller_verification.session_binding_state = SessionBindingState::Expired;
        session.caller_verification.freshness_bucket = VerificationFreshnessBucket::Expired;
        let status = IpcEnvelope::request(&session, ServiceCommand::Status, json!({}));
        let stale = dispatcher.dispatch_envelope(&session, status);
        assert_eq!(stale.response_status, "error");
        assert_eq!(
            stale.payload.get("code").and_then(Value::as_str),
            Some("CALLER_REJECTED")
        );
    }

    #[test]
    fn disconnect_expires_server_side_caller_trust_and_reconnect_requires_reverification() {
        let mut dispatcher = dispatcher();
        let session = IpcSessionState {
            session_reference: "session-ref".to_string(),
            client_nonce: "client-nonce".to_string(),
            server_nonce: "server-nonce".to_string(),
            challenge_nonce: "challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };
        dispatcher.connection_accepted();
        activate_test_session(&mut dispatcher, &session);
        dispatcher.connection_closed();

        let stale_request = IpcEnvelope::request(&session, ServiceCommand::Status, json!({}));
        let stale = dispatcher.dispatch_envelope(&session, stale_request);
        assert_eq!(stale.response_status, "error");
        assert_eq!(
            stale.payload.get("code").and_then(Value::as_str),
            Some("CALLER_REJECTED")
        );
        assert!(dispatcher.active_session_reference.is_none());
        assert!(dispatcher.active_verification_ref.is_none());
        assert_eq!(
            dispatcher
                .last_caller_verification
                .as_ref()
                .map(|summary| summary.session_binding_state),
            Some(SessionBindingState::Expired)
        );
    }

    #[test]
    fn production_mutation_commands_remain_disabled_for_every_verified_caller_category() {
        for caller in [
            classify_bounded_token(
                accepted_token_input(),
                CallerVerificationPolicy::service_mode(),
            ),
            classify_bounded_token(
                BoundedTokenClassificationInput {
                    expected_service_identity: true,
                    interactive: false,
                    ..accepted_token_input()
                },
                CallerVerificationPolicy::service_mode(),
            ),
            classify_bounded_token(
                BoundedTokenClassificationInput {
                    administrator_member: true,
                    ..accepted_token_input()
                },
                CallerVerificationPolicy::service_mode(),
            ),
        ] {
            assert!(!caller.production_mutations_enabled);
            for command in [
                "activate_provider",
                "sample_ip_helper",
                "enable_scheduler",
                "activate_sampler",
                "authorize_capture",
                "generate_report",
                "generate_export",
                "generate_llm_story",
                "execute_response",
                "shutdown_service_host",
            ] {
                assert!(ServiceCommand::parse(command).is_err());
            }
        }
    }

    #[test]
    fn caller_verification_status_contains_only_bounded_redacted_categories() {
        let mut dispatcher = dispatcher();
        dispatcher.last_caller_verification = Some(verified_test_summary());
        let serialized = serde_json::to_string(&dispatcher.caller_verification_read_status())
            .expect("caller verification status serializes");
        let lowered = serialized.to_ascii_lowercase();

        for forbidden in [
            "s-1-",
            "username",
            "account_name",
            "token_handle",
            "token_group",
            "logon_session_identifier",
            "machine_name",
            "process_id",
            "thread_id",
            "raw_access_mask",
            "authentication_package",
            "session_nonce",
            "credential",
            "secret",
        ] {
            assert!(!lowered.contains(forbidden), "status leaked {forbidden}");
        }
    }

    #[test]
    fn mutation_authorization_is_verified_session_bound_and_execution_enabled_for_ip_helper() {
        let mut dispatcher =
            dispatcher().with_runtime_ownership_status(service_owned_runtime_summary());
        let session = IpcSessionState {
            session_reference: "session-ref".to_string(),
            client_nonce: "client-nonce".to_string(),
            server_nonce: "server-nonce".to_string(),
            challenge_nonce: "challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };
        dispatcher.connection_accepted();
        activate_test_session(&mut dispatcher, &session);
        let request = IpcEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            schema_version: RUNTIME_IPC_SCHEMA_VERSION,
            request_id: "mutation-request-one".to_string(),
            session_reference: session.session_reference.clone(),
            client_nonce: session.client_nonce.clone(),
            server_nonce: session.server_nonce.clone(),
            sequence_number: 1,
            command_id: ServiceCommand::EvaluateMutationIntent.as_str().to_string(),
            response_status: "request".to_string(),
            payload: serde_json::to_value(mutation_intent(&session)).expect("intent payload"),
        };
        let response = dispatcher.dispatch_envelope(&session, request);
        let decision: MutationAuthorizationDecision =
            serde_json::from_value(response.payload).expect("authorization decision");
        assert_eq!(
            decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        assert!(decision.execution_enabled);
        assert_eq!(
            dispatcher.mutation_authorization.execution_attempt_count(),
            0
        );
        assert_eq!(
            dispatcher
                .runtime_ownership_status
                .as_ref()
                .expect("runtime summary")
                .provider_call_count,
            0
        );
    }

    #[test]
    fn mutation_authorization_reuses_idempotent_decision_without_dispatching_target() {
        let mut dispatcher =
            dispatcher().with_runtime_ownership_status(service_owned_runtime_summary());
        let session = IpcSessionState {
            session_reference: "session-ref".to_string(),
            client_nonce: "client-nonce".to_string(),
            server_nonce: "server-nonce".to_string(),
            challenge_nonce: "challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };
        dispatcher.connection_accepted();
        activate_test_session(&mut dispatcher, &session);
        let payload = serde_json::to_value(mutation_intent(&session)).expect("intent payload");
        let envelope = |request_id: &str, sequence_number: u64| IpcEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            schema_version: RUNTIME_IPC_SCHEMA_VERSION,
            request_id: request_id.to_string(),
            session_reference: session.session_reference.clone(),
            client_nonce: session.client_nonce.clone(),
            server_nonce: session.server_nonce.clone(),
            sequence_number,
            command_id: ServiceCommand::EvaluateMutationIntent.as_str().to_string(),
            response_status: "request".to_string(),
            payload: payload.clone(),
        };
        let first = dispatcher.dispatch_envelope(&session, envelope("mutation-request-one", 1));
        let second = dispatcher.dispatch_envelope(&session, envelope("mutation-request-two", 2));
        let first: MutationAuthorizationDecision =
            serde_json::from_value(first.payload).expect("first decision");
        let second: MutationAuthorizationDecision =
            serde_json::from_value(second.payload).expect("second decision");
        assert_eq!(first.decision_ref, second.decision_ref);
        assert_eq!(second.idempotency_state, MutationIdempotencyState::Reused);
        assert_eq!(
            dispatcher.mutation_authorization.execution_attempt_count(),
            0
        );
    }

    #[test]
    fn mutation_dispatch_gate_rejects_unverified_direct_dispatch() {
        let mut dispatcher = dispatcher();
        let session = IpcSessionState {
            session_reference: "session-ref".to_string(),
            client_nonce: "client-nonce".to_string(),
            server_nonce: "server-nonce".to_string(),
            challenge_nonce: "challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };
        let request = IpcRequest::new(
            ServiceCommand::EvaluateMutationIntent,
            serde_json::to_value(mutation_intent(&session)).expect("intent payload"),
        );
        let response = dispatcher.dispatch(request);
        assert_eq!(
            response.error.expect("direct dispatch rejected").code,
            "CALLER_REJECTED"
        );
        assert_eq!(
            dispatcher.mutation_authorization.execution_attempt_count(),
            0
        );

        let execute = dispatcher.dispatch(IpcRequest::new(
            ServiceCommand::ActivateIpHelper,
            json!({ "decision_ref": "mutation_decision_ref" }),
        ));
        assert_eq!(
            execute.error.expect("direct execution rejected").code,
            "CALLER_REJECTED"
        );
    }

    #[test]
    fn etw_lifecycle_commands_are_allowlisted_and_versioned() {
        let allowlist = CommandAllowlist::read_only_v1();
        for (command, expected_id) in [
            (
                ServiceCommand::ActivateEtw,
                MutationCommandId::ActivateEtwProvider,
            ),
            (
                ServiceCommand::PauseEtw,
                MutationCommandId::PauseEtwProvider,
            ),
            (
                ServiceCommand::ResumeEtw,
                MutationCommandId::ResumeEtwProvider,
            ),
            (ServiceCommand::StopEtw, MutationCommandId::StopEtwProvider),
            (
                ServiceCommand::ActivateAuthRemoteSensing,
                MutationCommandId::ActivateAuthRemoteSensing,
            ),
            (
                ServiceCommand::PauseAuthRemoteSensing,
                MutationCommandId::PauseAuthRemoteSensing,
            ),
            (
                ServiceCommand::ResumeAuthRemoteSensing,
                MutationCommandId::ResumeAuthRemoteSensing,
            ),
            (
                ServiceCommand::StopAuthRemoteSensing,
                MutationCommandId::StopAuthRemoteSensing,
            ),
        ] {
            assert_eq!(
                ServiceCommand::parse(command.as_str()).expect("allowlisted provider command"),
                command
            );
            assert_eq!(etw_mutation_command_id(command), Some(expected_id));
            allowlist
                .ensure_allowed(command, IpcAccessLevel::Read)
                .expect("provider lifecycle command allowlisted");
        }
    }

    #[test]
    fn etw_lifecycle_ipc_requires_authorization_and_preserves_collection_boundary() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("runtime container");
        let ownership_epoch = container.owner_context().ownership_epoch;
        let mut dispatcher = dispatcher().with_runtime_container(container);
        let session = IpcSessionState {
            session_reference: "etw-session-ref".to_string(),
            client_nonce: "etw-client-nonce".to_string(),
            server_nonce: "etw-server-nonce".to_string(),
            challenge_nonce: "etw-challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };
        dispatcher.connection_accepted();
        activate_test_session(&mut dispatcher, &session);

        let activate_intent = mutation_intent_for(
            &session,
            MutationCommandId::ActivateEtwProvider,
            ownership_epoch,
            "activate_etw_intent",
            "activate_etw_idempotency",
        );
        let activate_decision = dispatch_decision(
            &mut dispatcher,
            &session,
            1,
            "activate-etw-evaluate",
            activate_intent.clone(),
        );
        assert_eq!(
            activate_decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        let activate_receipt = dispatch_execution_receipt(
            &mut dispatcher,
            &session,
            2,
            ServiceCommand::ActivateEtw,
            "activate-etw-execute",
            activate_execution_request(activate_decision.decision_ref, activate_intent),
        );
        assert_eq!(
            activate_receipt.provider_category,
            MutationCapabilityCategory::EtwProvider
        );
        assert!(matches!(
            activate_receipt.result_category,
            MutationExecutionResultCategory::Completed
                | MutationExecutionResultCategory::AlreadySatisfied
        ));
        assert!(activate_receipt.batch_refs.is_empty());
        assert!(activate_receipt.fact_refs.is_empty());

        let status = dispatcher
            .runtime_container
            .as_ref()
            .expect("runtime container")
            .lock()
            .expect("runtime lock")
            .provider_controller_status()
            .cloned()
            .expect("provider status");
        assert_eq!(status.provider_zero.etw_calls, 1);
        assert_eq!(status.provider_zero.native_network_topic_publications, 0);
        assert_eq!(status.provider_zero.process_network_facts, 0);
        assert_eq!(status.provider_zero.packet_facts, 0);
        assert!(matches!(
            status.etw_lifecycle.lifecycle_state,
            sentinel_contracts::EtwLifecycleState::Active
                | sentinel_contracts::EtwLifecycleState::Degraded
        ));
        assert!(matches!(
            status.etw_lifecycle.fallback_state,
            sentinel_contracts::EtwFallbackState::IpHelperAvailable
                | sentinel_contracts::EtwFallbackState::IpHelperActive
                | sentinel_contracts::EtwFallbackState::PortableMetadataOnly
        ));

        let mut sequence = 3;
        if status.etw_lifecycle.lifecycle_state == sentinel_contracts::EtwLifecycleState::Active {
            for (command_id, command, expected_lifecycle, label) in [
                (
                    MutationCommandId::PauseEtwProvider,
                    ServiceCommand::PauseEtw,
                    ProviderLifecycleCategory::Paused,
                    "pause",
                ),
                (
                    MutationCommandId::ResumeEtwProvider,
                    ServiceCommand::ResumeEtw,
                    ProviderLifecycleCategory::Active,
                    "resume",
                ),
            ] {
                let intent = mutation_intent_for(
                    &session,
                    command_id,
                    ownership_epoch,
                    &format!("{label}_etw_intent"),
                    &format!("{label}_etw_idempotency"),
                );
                let decision = dispatch_decision(
                    &mut dispatcher,
                    &session,
                    sequence,
                    &format!("{label}-etw-evaluate"),
                    intent.clone(),
                );
                assert_eq!(
                    decision.result,
                    MutationAuthorizationResult::ApprovedForExecution
                );
                sequence += 1;
                let receipt = dispatch_execution_receipt(
                    &mut dispatcher,
                    &session,
                    sequence,
                    command,
                    &format!("{label}-etw-execute"),
                    activate_execution_request(decision.decision_ref, intent),
                );
                assert_eq!(receipt.resulting_lifecycle_state, expected_lifecycle);
                assert!(receipt.batch_refs.is_empty());
                assert!(receipt.fact_refs.is_empty());
                sequence += 1;
            }
        }

        let stop_intent = mutation_intent_for(
            &session,
            MutationCommandId::StopEtwProvider,
            ownership_epoch,
            "stop_etw_intent",
            "stop_etw_idempotency",
        );
        let stop_decision = dispatch_decision(
            &mut dispatcher,
            &session,
            sequence,
            "stop-etw-evaluate",
            stop_intent.clone(),
        );
        assert_eq!(
            stop_decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        let stop_receipt = dispatch_execution_receipt(
            &mut dispatcher,
            &session,
            sequence + 1,
            ServiceCommand::StopEtw,
            "stop-etw-execute",
            activate_execution_request(stop_decision.decision_ref, stop_intent),
        );
        assert_eq!(
            stop_receipt.resulting_lifecycle_state,
            ProviderLifecycleCategory::Stopped
        );
        assert!(stop_receipt.batch_refs.is_empty());
        assert!(stop_receipt.fact_refs.is_empty());
    }

    #[test]
    fn etw_network_production_hardening_preserves_privacy_fallback_and_shutdown_boundary() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("runtime container");
        let ownership_epoch = container.owner_context().ownership_epoch;
        let mut dispatcher = dispatcher().with_runtime_container(container);
        let session = IpcSessionState {
            session_reference: "etw-network-session-ref".to_string(),
            client_nonce: "etw-network-client-nonce".to_string(),
            server_nonce: "etw-network-server-nonce".to_string(),
            challenge_nonce: "etw-network-challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };
        dispatcher.connection_accepted();
        activate_test_session(&mut dispatcher, &session);

        let initial_status = dispatcher
            .runtime_container
            .as_ref()
            .expect("runtime container")
            .lock()
            .expect("runtime lock")
            .provider_controller_status()
            .cloned()
            .expect("provider status");
        assert_eq!(
            initial_status.etw_lifecycle.lifecycle_state,
            sentinel_contracts::EtwLifecycleState::Inactive
        );
        assert_eq!(initial_status.provider_zero.etw_calls, 0);
        assert_eq!(
            initial_status
                .provider_zero
                .native_network_topic_publications,
            0
        );
        assert_eq!(
            initial_status.provider_zero.npcap_probes
                + initial_status.provider_zero.capture_broker_launches
                + initial_status.provider_zero.process_network_facts
                + initial_status.provider_zero.packet_facts,
            0
        );

        let mut sequence = 1;
        let execute_etw = |dispatcher: &mut ServiceCommandDispatcher,
                           command_id: MutationCommandId,
                           command: ServiceCommand,
                           label: &str,
                           sequence: &mut u64| {
            let intent = mutation_intent_for(
                &session,
                command_id,
                ownership_epoch,
                &format!("{label}_intent"),
                &format!("{label}_idempotency"),
            );
            let decision = dispatch_decision(
                dispatcher,
                &session,
                *sequence,
                &format!("{label}-evaluate"),
                intent.clone(),
            );
            assert_eq!(
                decision.result,
                MutationAuthorizationResult::ApprovedForExecution
            );
            *sequence += 1;
            let receipt = dispatch_execution_receipt(
                dispatcher,
                &session,
                *sequence,
                command,
                &format!("{label}-execute"),
                activate_execution_request(decision.decision_ref, intent),
            );
            *sequence += 1;
            receipt
        };

        let activate_receipt = execute_etw(
            &mut dispatcher,
            MutationCommandId::ActivateEtwProvider,
            ServiceCommand::ActivateEtw,
            "activate_etw_network",
            &mut sequence,
        );
        assert_eq!(
            activate_receipt.provider_category,
            MutationCapabilityCategory::EtwProvider
        );
        assert!(matches!(
            activate_receipt.result_category,
            MutationExecutionResultCategory::Completed
                | MutationExecutionResultCategory::AlreadySatisfied
        ));
        assert!(activate_receipt.batch_refs.is_empty());
        assert!(activate_receipt.fact_refs.is_empty());

        let after_activate = dispatcher
            .runtime_container
            .as_ref()
            .expect("runtime container")
            .lock()
            .expect("runtime lock")
            .provider_controller_status()
            .cloned()
            .expect("provider status");
        assert!(!after_activate.etw_lifecycle.provider_enabled);
        assert!(!after_activate.etw_lifecycle.collection_started);
        assert!(!after_activate.etw_lifecycle.consumer_started);
        assert_eq!(after_activate.etw_lifecycle.eventbus_publication_count, 0);
        assert_eq!(after_activate.etw_lifecycle.security_fact_count, 0);
        assert_eq!(
            after_activate
                .provider_zero
                .native_network_topic_publications,
            0
        );
        assert_eq!(after_activate.provider_zero.process_network_facts, 0);
        assert_eq!(after_activate.provider_zero.packet_facts, 0);
        assert!(matches!(
            after_activate.etw_lifecycle.fallback_state,
            sentinel_contracts::EtwFallbackState::IpHelperAvailable
                | sentinel_contracts::EtwFallbackState::IpHelperActive
                | sentinel_contracts::EtwFallbackState::PortableMetadataOnly
        ));

        if after_activate.etw_lifecycle.lifecycle_state
            == sentinel_contracts::EtwLifecycleState::Active
        {
            let pause_receipt = execute_etw(
                &mut dispatcher,
                MutationCommandId::PauseEtwProvider,
                ServiceCommand::PauseEtw,
                "pause_etw_network",
                &mut sequence,
            );
            assert_eq!(
                pause_receipt.resulting_lifecycle_state,
                ProviderLifecycleCategory::Paused
            );
            assert!(pause_receipt.batch_refs.is_empty());
            assert!(pause_receipt.fact_refs.is_empty());

            let resume_receipt = execute_etw(
                &mut dispatcher,
                MutationCommandId::ResumeEtwProvider,
                ServiceCommand::ResumeEtw,
                "resume_etw_network",
                &mut sequence,
            );
            assert_eq!(
                resume_receipt.resulting_lifecycle_state,
                ProviderLifecycleCategory::Active
            );
            assert!(resume_receipt.batch_refs.is_empty());
            assert!(resume_receipt.fact_refs.is_empty());
        } else {
            assert_eq!(
                after_activate.etw_lifecycle.lifecycle_state,
                sentinel_contracts::EtwLifecycleState::Degraded
            );
        }

        let stop_receipt = execute_etw(
            &mut dispatcher,
            MutationCommandId::StopEtwProvider,
            ServiceCommand::StopEtw,
            "stop_etw_network",
            &mut sequence,
        );
        assert!(matches!(
            stop_receipt.resulting_lifecycle_state,
            ProviderLifecycleCategory::Stopped | ProviderLifecycleCategory::Degraded
        ));
        assert!(stop_receipt.batch_refs.is_empty());
        assert!(stop_receipt.fact_refs.is_empty());
        dispatcher.refresh_runtime_snapshots_from_container();

        let final_status = dispatcher
            .runtime_container
            .as_ref()
            .expect("runtime container")
            .lock()
            .expect("runtime lock")
            .provider_controller_status()
            .cloned()
            .expect("provider status");
        assert!(!final_status.etw_lifecycle.provider_enabled);
        assert!(!final_status.etw_lifecycle.collection_started);
        assert!(!final_status.etw_lifecycle.consumer_started);
        assert_eq!(final_status.etw_lifecycle.eventbus_publication_count, 0);
        assert_eq!(final_status.etw_lifecycle.security_fact_count, 0);
        assert_eq!(
            final_status.provider_zero.native_network_topic_publications,
            0
        );
        assert_eq!(final_status.provider_zero.process_network_facts, 0);
        assert_eq!(final_status.provider_zero.packet_facts, 0);
        assert_eq!(final_status.provider_zero.npcap_probes, 0);
        assert_eq!(final_status.provider_zero.capture_broker_launches, 0);

        let serialized =
            serde_json::to_string(&(final_status, stop_receipt)).expect("serialize ETW status");
        for marker in [
            "provider_guid=",
            "session_name=",
            "handle=",
            "pid=",
            "process_name=",
            "raw_address=",
            "exact_port=",
            "packet_bytes",
            "payload_bytes",
            "credential=",
            "secret=",
            "token=",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "ETW hardening output leaked marker {marker}: {serialized}"
            );
        }
    }

    #[test]
    fn ip_helper_production_ipc_authorizes_executes_once_and_rejects_stopped_sample() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("runtime container");
        let ownership_epoch = container.owner_context().ownership_epoch;
        let mut dispatcher = dispatcher().with_runtime_container(container);
        let session = IpcSessionState {
            session_reference: "session-ref".to_string(),
            client_nonce: "client-nonce".to_string(),
            server_nonce: "server-nonce".to_string(),
            challenge_nonce: "challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };
        dispatcher.connection_accepted();
        activate_test_session(&mut dispatcher, &session);

        let activate_intent = mutation_intent_for(
            &session,
            MutationCommandId::ActivateIpHelperProvider,
            ownership_epoch,
            "activate_ip_helper_intent",
            "activate_ip_helper_idempotency",
        );
        let activate_decision = dispatch_decision(
            &mut dispatcher,
            &session,
            1,
            "activate-evaluate",
            activate_intent.clone(),
        );
        assert_eq!(
            activate_decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        let activate_receipt = dispatch_execution_receipt(
            &mut dispatcher,
            &session,
            2,
            ServiceCommand::ActivateIpHelper,
            "activate-execute",
            activate_execution_request(
                activate_decision.decision_ref.clone(),
                activate_intent.clone(),
            ),
        );
        assert_eq!(
            activate_receipt.result_category,
            MutationExecutionResultCategory::Completed
        );
        assert_eq!(
            activate_receipt.resulting_lifecycle_state,
            ProviderLifecycleCategory::Active
        );
        assert_eq!(
            dispatcher
                .runtime_ownership_status
                .as_ref()
                .expect("runtime summary")
                .provider_call_count,
            0
        );

        let replay = IpcEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            schema_version: RUNTIME_IPC_SCHEMA_VERSION,
            request_id: "activate-replay".to_string(),
            session_reference: session.session_reference.clone(),
            client_nonce: session.client_nonce.clone(),
            server_nonce: session.server_nonce.clone(),
            sequence_number: 3,
            command_id: ServiceCommand::ActivateIpHelper.as_str().to_string(),
            response_status: "request".to_string(),
            payload: serde_json::to_value(activate_execution_request(
                activate_decision.decision_ref,
                activate_intent,
            ))
            .expect("execution payload"),
        };
        let replay = dispatcher.dispatch_envelope(&session, replay);
        assert_eq!(replay.response_status, "error");
        assert_eq!(
            dispatcher
                .runtime_ownership_status
                .as_ref()
                .expect("runtime summary")
                .provider_call_count,
            0
        );

        let sample_intent = mutation_intent_for(
            &session,
            MutationCommandId::SampleIpHelperNow,
            ownership_epoch,
            "sample_ip_helper_intent",
            "sample_ip_helper_idempotency",
        );
        let sample_decision = dispatch_decision(
            &mut dispatcher,
            &session,
            4,
            "sample-evaluate",
            sample_intent.clone(),
        );
        assert_eq!(
            sample_decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        let sample_receipt = dispatch_execution_receipt(
            &mut dispatcher,
            &session,
            5,
            ServiceCommand::SampleIpHelperOnce,
            "sample-execute",
            activate_execution_request(sample_decision.decision_ref, sample_intent),
        );
        assert_eq!(
            sample_receipt.result_category,
            MutationExecutionResultCategory::Completed
        );
        assert_eq!(sample_receipt.counters.sampled_count, 1);
        assert!(!sample_receipt.batch_refs.is_empty());
        assert_eq!(
            dispatcher
                .runtime_ownership_status
                .as_ref()
                .expect("runtime summary")
                .provider_call_count,
            1
        );

        let stop_intent = mutation_intent_for(
            &session,
            MutationCommandId::StopIpHelper,
            ownership_epoch,
            "stop_ip_helper_intent",
            "stop_ip_helper_idempotency",
        );
        let stop_decision = dispatch_decision(
            &mut dispatcher,
            &session,
            6,
            "stop-evaluate",
            stop_intent.clone(),
        );
        assert_eq!(
            stop_decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        let stop_receipt = dispatch_execution_receipt(
            &mut dispatcher,
            &session,
            7,
            ServiceCommand::StopIpHelper,
            "stop-execute",
            activate_execution_request(stop_decision.decision_ref, stop_intent),
        );
        assert_eq!(
            stop_receipt.resulting_lifecycle_state,
            ProviderLifecycleCategory::Stopped
        );

        let stopped_sample = mutation_intent_for(
            &session,
            MutationCommandId::SampleIpHelperNow,
            ownership_epoch,
            "sample_after_stop_intent",
            "sample_after_stop_idempotency",
        );
        let rejected = dispatch_decision(
            &mut dispatcher,
            &session,
            8,
            "sample-after-stop-evaluate",
            stopped_sample,
        );
        assert_eq!(
            rejected.result,
            MutationAuthorizationResult::ProviderStateInvalid
        );
        assert_eq!(
            dispatcher
                .runtime_ownership_status
                .as_ref()
                .expect("runtime summary")
                .provider_call_count,
            1
        );
        dispatcher.connection_closed();
        let mut container = dispatcher
            .take_runtime_container()
            .expect("runtime container returned");
        container.shutdown().expect("shutdown");
    }

    #[test]
    fn ip_helper_schedule_ipc_controls_are_authorized_and_never_sample_provider() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("runtime container");
        let owner_context = container.owner_context().clone();
        let ownership_epoch = owner_context.ownership_epoch;
        container
            .activate_ip_helper_provider(&owner_context)
            .expect("activate ip helper for schedule controls");
        assert_eq!(container.provider_call_count(), 0);
        let mut dispatcher = dispatcher().with_runtime_container(container);
        let session = IpcSessionState {
            session_reference: "schedule-session-ref".to_string(),
            client_nonce: "schedule-client-nonce".to_string(),
            server_nonce: "schedule-server-nonce".to_string(),
            challenge_nonce: "schedule-challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };
        dispatcher.connection_accepted();
        activate_test_session(&mut dispatcher, &session);

        let configure_intent = mutation_intent_for(
            &session,
            MutationCommandId::ConfigureIpHelperSchedule,
            ownership_epoch,
            "configure_ip_helper_schedule_intent",
            "configure_ip_helper_schedule_idempotency",
        );
        let configure_decision = dispatch_decision(
            &mut dispatcher,
            &session,
            1,
            "configure-schedule-evaluate",
            configure_intent.clone(),
        );
        assert_eq!(
            configure_decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        let configure_receipt = dispatch_schedule_execution_receipt(
            &mut dispatcher,
            &session,
            2,
            ServiceCommand::ConfigureIpHelperSchedule,
            "configure-schedule-execute",
            schedule_execution_request(
                configure_decision.decision_ref,
                configure_intent,
                Some(IpHelperScheduleConfig::default()),
            ),
        );
        assert_eq!(
            configure_receipt.result_category,
            MutationExecutionResultCategory::Completed
        );
        assert_eq!(configure_receipt.counters.sampled_count, 0);

        let enable_intent = mutation_intent_for(
            &session,
            MutationCommandId::EnableIpHelperSchedule,
            ownership_epoch,
            "enable_ip_helper_schedule_intent",
            "enable_ip_helper_schedule_idempotency",
        );
        let enable_decision = dispatch_decision(
            &mut dispatcher,
            &session,
            3,
            "enable-schedule-evaluate",
            enable_intent.clone(),
        );
        assert_eq!(
            enable_decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        let enable_receipt = dispatch_schedule_execution_receipt(
            &mut dispatcher,
            &session,
            4,
            ServiceCommand::EnableIpHelperSchedule,
            "enable-schedule-execute",
            schedule_execution_request(enable_decision.decision_ref, enable_intent, None),
        );
        assert_eq!(
            enable_receipt.result_category,
            MutationExecutionResultCategory::Completed
        );
        assert_eq!(enable_receipt.counters.sampled_count, 0);

        let pause_intent = mutation_intent_for(
            &session,
            MutationCommandId::PauseIpHelperSchedule,
            ownership_epoch,
            "pause_ip_helper_schedule_intent",
            "pause_ip_helper_schedule_idempotency",
        );
        let pause_decision = dispatch_decision(
            &mut dispatcher,
            &session,
            5,
            "pause-schedule-evaluate",
            pause_intent.clone(),
        );
        assert_eq!(
            pause_decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        let pause_receipt = dispatch_schedule_execution_receipt(
            &mut dispatcher,
            &session,
            6,
            ServiceCommand::PauseIpHelperSchedule,
            "pause-schedule-execute",
            schedule_execution_request(pause_decision.decision_ref, pause_intent, None),
        );
        assert_eq!(
            pause_receipt.result_category,
            MutationExecutionResultCategory::Completed
        );

        let resume_intent = mutation_intent_for(
            &session,
            MutationCommandId::ResumeIpHelperSchedule,
            ownership_epoch,
            "resume_ip_helper_schedule_intent",
            "resume_ip_helper_schedule_idempotency",
        );
        let resume_decision = dispatch_decision(
            &mut dispatcher,
            &session,
            7,
            "resume-schedule-evaluate",
            resume_intent.clone(),
        );
        assert_eq!(
            resume_decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        let resume_receipt = dispatch_schedule_execution_receipt(
            &mut dispatcher,
            &session,
            8,
            ServiceCommand::ResumeIpHelperSchedule,
            "resume-schedule-execute",
            schedule_execution_request(resume_decision.decision_ref, resume_intent, None),
        );
        assert_eq!(
            resume_receipt.result_category,
            MutationExecutionResultCategory::Completed
        );

        let disable_intent = mutation_intent_for(
            &session,
            MutationCommandId::DisableIpHelperSchedule,
            ownership_epoch,
            "disable_ip_helper_schedule_intent",
            "disable_ip_helper_schedule_idempotency",
        );
        let disable_decision = dispatch_decision(
            &mut dispatcher,
            &session,
            9,
            "disable-schedule-evaluate",
            disable_intent.clone(),
        );
        assert_eq!(
            disable_decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        let disable_receipt = dispatch_schedule_execution_receipt(
            &mut dispatcher,
            &session,
            10,
            ServiceCommand::DisableIpHelperSchedule,
            "disable-schedule-execute",
            schedule_execution_request(disable_decision.decision_ref, disable_intent, None),
        );
        assert_eq!(
            disable_receipt.result_category,
            MutationExecutionResultCategory::Completed
        );

        assert_eq!(
            dispatcher
                .runtime_ownership_status
                .as_ref()
                .expect("runtime summary")
                .provider_call_count,
            0
        );
        dispatcher.connection_closed();
        let mut container = dispatcher
            .take_runtime_container()
            .expect("runtime container returned");
        let status = container
            .provider_controller_status()
            .expect("provider status");
        let schedule = &status.ip_helper_schedule;
        assert_eq!(
            schedule.schedule_state,
            IpHelperScheduleState::ConfiguredDisabled
        );
        assert_eq!(
            schedule.lease_state,
            IpHelperScheduleLeaseState::Invalidated
        );
        assert!(!schedule.timer_runtime_active);
        assert_eq!(schedule.scheduler_triggered_provider_calls, 0);
        assert_eq!(container.provider_call_count(), 0);
        container.shutdown().expect("shutdown");
    }

    #[test]
    fn ip_helper_schedule_disconnect_invalidates_active_session_bound_lease() {
        let _lock = SERVICE_HOST_RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("runtime container");
        let owner_context = container.owner_context().clone();
        let ownership_epoch = owner_context.ownership_epoch;
        container
            .activate_ip_helper_provider(&owner_context)
            .expect("activate ip helper for schedule controls");
        let mut dispatcher = dispatcher().with_runtime_container(container);
        let session = IpcSessionState {
            session_reference: "schedule-disconnect-session-ref".to_string(),
            client_nonce: "schedule-disconnect-client-nonce".to_string(),
            server_nonce: "schedule-disconnect-server-nonce".to_string(),
            challenge_nonce: "schedule-disconnect-challenge-nonce".to_string(),
            caller_verification: verified_test_summary(),
        };
        dispatcher.connection_accepted();
        activate_test_session(&mut dispatcher, &session);

        let configure_intent = mutation_intent_for(
            &session,
            MutationCommandId::ConfigureIpHelperSchedule,
            ownership_epoch,
            "disconnect_configure_schedule_intent",
            "disconnect_configure_schedule_idempotency",
        );
        let configure_decision = dispatch_decision(
            &mut dispatcher,
            &session,
            1,
            "disconnect-configure-evaluate",
            configure_intent.clone(),
        );
        dispatch_schedule_execution_receipt(
            &mut dispatcher,
            &session,
            2,
            ServiceCommand::ConfigureIpHelperSchedule,
            "disconnect-configure-execute",
            schedule_execution_request(
                configure_decision.decision_ref,
                configure_intent,
                Some(IpHelperScheduleConfig::default()),
            ),
        );

        let enable_intent = mutation_intent_for(
            &session,
            MutationCommandId::EnableIpHelperSchedule,
            ownership_epoch,
            "disconnect_enable_schedule_intent",
            "disconnect_enable_schedule_idempotency",
        );
        let enable_decision = dispatch_decision(
            &mut dispatcher,
            &session,
            3,
            "disconnect-enable-evaluate",
            enable_intent.clone(),
        );
        dispatch_schedule_execution_receipt(
            &mut dispatcher,
            &session,
            4,
            ServiceCommand::EnableIpHelperSchedule,
            "disconnect-enable-execute",
            schedule_execution_request(enable_decision.decision_ref, enable_intent, None),
        );

        dispatcher.connection_closed();
        let mut container = dispatcher
            .take_runtime_container()
            .expect("runtime container returned");
        let status = container
            .provider_controller_status()
            .expect("provider status");
        let schedule = &status.ip_helper_schedule;
        assert_eq!(schedule.schedule_state, IpHelperScheduleState::Invalidated);
        assert_eq!(
            schedule.lease_state,
            IpHelperScheduleLeaseState::Invalidated
        );
        assert_eq!(
            schedule.degraded_reason.as_deref(),
            Some("ipc_session_closed")
        );
        assert!(schedule
            .audit_refs
            .iter()
            .any(|audit| audit == IP_HELPER_SCHEDULE_SESSION_INVALIDATED));
        assert_eq!(container.provider_call_count(), 0);
        container.shutdown().expect("shutdown");
    }

    #[cfg(windows)]
    #[test]
    fn windows_named_pipe_smoke_verifies_caller_before_read_dispatch() {
        use std::thread;

        let pipe_name = format!(
            r"\\.\pipe\SentinelGuardCallerVerificationTest-{}",
            Uuid::new_v4()
        );
        let server_pipe_name = pipe_name.clone();
        let server = thread::spawn(move || {
            let mut dispatcher =
                dispatcher().with_runtime_ownership_status(service_owned_runtime_summary());
            run_one_pipe_connection(&server_pipe_name, &mut dispatcher)
        });

        let mut pipe = (0..100)
            .find_map(
                |_| match OpenOptions::new().read(true).write(true).open(&pipe_name) {
                    Ok(pipe) => Some(pipe),
                    Err(_) => {
                        thread::sleep(Duration::from_millis(20));
                        None
                    }
                },
            )
            .expect("connect to local caller-verification pipe");

        let client_nonce = Uuid::new_v4().to_string();
        write_json_frame(
            &mut pipe,
            &IpcClientHello {
                message_type: "client_hello".to_string(),
                supported_protocol_versions: vec![IPC_PROTOCOL_VERSION],
                schema_version: RUNTIME_IPC_SCHEMA_VERSION,
                client_nonce: client_nonce.clone(),
                requested_capabilities: vec!["read_only_status".to_string()],
            },
        )
        .expect("write client hello");
        let hello: IpcServerHello = read_json_frame(&mut pipe).expect("read server hello");
        write_json_frame(
            &mut pipe,
            &IpcClientVerify {
                message_type: "client_verify".to_string(),
                protocol_version: IPC_PROTOCOL_VERSION,
                schema_version: RUNTIME_IPC_SCHEMA_VERSION,
                session_reference: hello.session_reference.clone(),
                client_nonce: client_nonce.clone(),
                server_nonce: hello.server_nonce.clone(),
                challenge_nonce: hello.challenge_nonce.clone(),
                sequence_number: 0,
                caller_kind: "local_desktop".to_string(),
            },
        )
        .expect("write client verification");
        let verified: IpcServerVerify =
            read_json_frame(&mut pipe).expect("read caller verification");
        assert!(verified.caller_verification.permits_read_only_commands());
        assert!(matches!(
            verified.caller_verification.verification_state,
            CallerVerificationState::VerifiedInteractiveUser
                | CallerVerificationState::AdministratorPolicyVerified
                | CallerVerificationState::VerifiedServiceIdentity
        ));

        let session = IpcSessionState {
            session_reference: hello.session_reference,
            client_nonce,
            server_nonce: hello.server_nonce,
            challenge_nonce: hello.challenge_nonce,
            caller_verification: verified.caller_verification,
        };
        let request = IpcEnvelope::request(&session, ServiceCommand::Status, json!({}));
        write_json_frame(&mut pipe, &request).expect("write read-only status request");
        let response: IpcEnvelope<Value> =
            read_json_frame(&mut pipe).expect("read status response");
        assert_eq!(response.response_status, "ok");
        assert!(response.payload.get("caller_verification_status").is_some());
        assert_eq!(
            response.payload["runtime_ownership_status"]["provider_call_count"],
            json!(0)
        );

        let intent_payload =
            serde_json::to_value(mutation_intent(&session)).expect("mutation intent payload");
        let mut evaluate = IpcEnvelope::request(
            &session,
            ServiceCommand::EvaluateMutationIntent,
            intent_payload.clone(),
        );
        evaluate.sequence_number = 2;
        write_json_frame(&mut pipe, &evaluate).expect("write mutation evaluation");
        let first: IpcEnvelope<Value> = read_json_frame(&mut pipe).expect("read mutation decision");
        let first_decision: MutationAuthorizationDecision =
            serde_json::from_value(first.payload).expect("decode mutation decision");
        assert_eq!(
            first_decision.result,
            MutationAuthorizationResult::ApprovedForExecution
        );
        assert!(first_decision.execution_enabled);

        let mut replay = IpcEnvelope::request(
            &session,
            ServiceCommand::EvaluateMutationIntent,
            intent_payload,
        );
        replay.sequence_number = 3;
        write_json_frame(&mut pipe, &replay).expect("write idempotent replay");
        let replay: IpcEnvelope<Value> =
            read_json_frame(&mut pipe).expect("read idempotent replay decision");
        let replay_decision: MutationAuthorizationDecision =
            serde_json::from_value(replay.payload).expect("decode replay decision");
        assert_eq!(first_decision.decision_ref, replay_decision.decision_ref);
        assert_eq!(
            replay_decision.idempotency_state,
            MutationIdempotencyState::Reused
        );

        drop(pipe);
        server
            .join()
            .expect("server thread joins")
            .expect("server completes one verified connection");
    }
}
