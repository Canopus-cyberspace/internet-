//! Runtime Named Pipe IPC stub for Task 550.
//!
//! This module is still metadata-only and STUB_ONLY: it exposes a local
//! request/response server for ping, service status, capture health, and a
//! process snapshot stub. It does not start capture, inspect packets, execute
//! response actions, render UI, or host plugins.

use sentinel_contracts::Timestamp;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::VecDeque;
use std::env;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const SERVICE_NAME: &str = "SentinelGuardElevated";
pub const SERVICE_DISPLAY_NAME: &str = "Sentinel Guard Elevated Service";
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\SentinelGuardIpc";
pub const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);
const READ_COMMAND_RATE_LIMIT: u32 = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServiceCommand {
    Ping,
    Status,
    CaptureHealth,
    ProcessSnapshot,
}

impl ServiceCommand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Status => "status",
            Self::CaptureHealth => "capture_health",
            Self::ProcessSnapshot => "process_snapshot",
        }
    }

    pub fn parse(value: &str) -> Result<Self, IpcError> {
        match value {
            "ping" => Ok(Self::Ping),
            "status" => Ok(Self::Status),
            "capture_health" => Ok(Self::CaptureHealth),
            "process_snapshot" => Ok(Self::ProcessSnapshot),
            _ => Err(IpcError::command_not_allowed(format!(
                "command is not allowlisted: {value}"
            ))),
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
    pub pid: u32,
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
            ],
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
pub struct ServiceCommandDispatcher {
    started_at: Instant,
    connected_clients: u32,
    allowlist: CommandAllowlist,
    caller_level: IpcAccessLevel,
    audit_logger: ServiceAuditLogger,
    rate_limiter: RateLimiter,
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
        }
    }

    pub fn dispatch(&mut self, request: IpcRequest<Value>) -> IpcResponse<Value> {
        let command = match ServiceCommand::parse(&request.command) {
            Ok(command) => command,
            Err(error) => {
                let _ = self.audit_logger.log(
                    "command_rejected",
                    Some(&request.command),
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
        let result = StatusResult {
            service_status: "running".to_string(),
            connected_clients: self.connected_clients,
            memory_usage_mb: 0.0,
            pid: std::process::id(),
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
}

impl fmt::Display for ServiceRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "service runtime IO failed: {error}"),
            Self::Frame(error) => write!(f, "service runtime frame failed: {error}"),
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
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    struct PipeSecurity {
        descriptor: *mut core::ffi::c_void,
        attributes: SECURITY_ATTRIBUTES,
    }

    impl PipeSecurity {
        fn admins_and_system_only() -> io::Result<Self> {
            let sddl = wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
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

    let security = PipeSecurity::admins_and_system_only()?;
    let pipe = wide(pipe_name);
    let handle = unsafe {
        CreateNamedPipeW(
            pipe.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
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
    let request = match read_json_frame::<_, IpcRequest<Value>>(&mut file) {
        Ok(request) => request,
        Err(error) => {
            let response = IpcResponse::malformed(IpcError::schema(error.to_string()));
            write_json_frame(&mut file, &response)?;
            unsafe {
                DisconnectNamedPipe(file.as_raw_handle() as HANDLE);
            }
            dispatcher.connection_closed();
            return Ok(());
        }
    };
    let response = dispatcher.dispatch(request);
    write_json_frame(&mut file, &response)?;
    unsafe {
        DisconnectNamedPipe(file.as_raw_handle() as HANDLE);
    }
    dispatcher.connection_closed();
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dispatcher() -> ServiceCommandDispatcher {
        ServiceCommandDispatcher::new(ServiceAuditLogger::with_path(
            env::temp_dir().join("sentinel-guard-service-test-audit.jsonl"),
        ))
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
        assert_eq!(
            malformed.error.as_ref().map(|error| error.code.as_str()),
            Some("SCHEMA_VALIDATION_ERROR")
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
}
