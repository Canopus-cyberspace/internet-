//! Local Core client for the Sentinel Guard elevated service IPC stub.
//!
//! This adapter performs only local Named Pipe request/response calls. It does
//! not execute privileged actions and does not expose raw packet or payload
//! content to callers.

use sentinel_contracts::{
    ServiceAdapterMode, ServiceCapabilityContext, ServiceCapabilityStatus, ServiceLimitationFlag,
    ServiceReasonCode, Timestamp,
};
use sentinel_elevated_service::{
    read_json_frame, write_json_frame, CaptureHealthResult, IpcError, IpcRequest, IpcResponse,
    PingResult, ProcessSnapshotResult, ServiceCommand, StatusResult, DEFAULT_PIPE_NAME,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::fmt;
use std::fs::OpenOptions;
use std::io;
use std::thread;
use std::time::Duration;

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
        write_json_frame(&mut pipe, request).map_err(ServiceIpcClientError::protocol)?;
        let response: IpcResponse<Value> =
            read_json_frame(&mut pipe).map_err(ServiceIpcClientError::protocol)?;
        if let Some(error) = response.error {
            return Err(ServiceIpcClientError::rejected(error));
        }
        let result = response.result.ok_or_else(|| {
            ServiceIpcClientError::protocol("IPC response did not include result")
        })?;
        serde_json::from_value(result).map_err(ServiceIpcClientError::protocol)
    }
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
    use sentinel_elevated_service::{
        dispatch_json_request_for_tests, ServiceAuditLogger, ServiceCommandDispatcher,
    };

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
        let mut dispatcher = ServiceCommandDispatcher::new(ServiceAuditLogger::with_path(
            std::env::temp_dir().join("sentinel-guard-infra-service-test-audit.jsonl"),
        ));
        let response = dispatch_json_request_for_tests(
            &mut dispatcher,
            json!({
                "id": "request-1",
                "command": "status",
                "params": {},
                "timestamp": "2026-06-04T00:00:00Z"
            }),
        );
        let status: StatusResult =
            serde_json::from_value(response.result.expect("status result")).expect("decode");

        assert_eq!(status.service_status, "running");
        assert_eq!(status.pid, std::process::id());
    }

    #[test]
    fn bounded_service_ipc_context_snapshot_admits_only_safe_fields() {
        let snapshot = ServiceIpcCapabilityContextSnapshot::from_status_and_capture(
            &StatusResult {
                service_status: "running".to_string(),
                connected_clients: 1,
                memory_usage_mb: 0.0,
                pid: 4242,
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
