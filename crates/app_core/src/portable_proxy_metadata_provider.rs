use crate::portable_capture_import::apply_portable_capture_run;
use crate::read_commands::ReadOnlyCommandState;
use sentinel_capabilities::{
    LocalProxyMetadataProvider, LocalProxyMetadataProviderError,
    LocalProxyMetadataProviderStateKind, LocalProxyMetadataProviderStatus,
    LocalProxyMetadataStartRequest, PortableCaptureLiteRunResult,
};
use sentinel_contracts::{CommandResult, CoreError, ErrorCode, ErrorSeverity, TraceId};
use serde_json::json;
#[cfg(test)]
use std::net::TcpStream;
#[cfg(test)]
use std::thread;
#[cfg(test)]
use std::time::Duration;

#[derive(Debug, Default)]
pub struct PortableProxyMetadataRuntime {
    provider: LocalProxyMetadataProvider,
}

impl PortableProxyMetadataRuntime {
    pub fn start(
        &mut self,
        state: &mut ReadOnlyCommandState,
        request: LocalProxyMetadataStartRequest,
    ) -> CommandResult<LocalProxyMetadataProviderStatus> {
        let status = self.provider.start(request).map_err(proxy_error)?;
        update_capture_availability(state, &status);
        Ok(status)
    }

    pub fn status_snapshot(&mut self) -> LocalProxyMetadataProviderStatus {
        self.provider.status()
    }

    pub fn drain(
        &mut self,
        state: &mut ReadOnlyCommandState,
    ) -> CommandResult<LocalProxyMetadataProviderStatus> {
        let _ = drain_proxy_runs(state, &mut self.provider);
        let status = self.provider.status();
        update_capture_availability(state, &status);
        Ok(status)
    }

    pub fn drain_with_runs(
        &mut self,
        state: &mut ReadOnlyCommandState,
    ) -> CommandResult<(
        LocalProxyMetadataProviderStatus,
        Vec<PortableCaptureLiteRunResult>,
    )> {
        let runs = drain_proxy_runs(state, &mut self.provider);
        let status = self.provider.status();
        update_capture_availability(state, &status);
        Ok((status, runs))
    }

    pub fn stop(
        &mut self,
        state: &mut ReadOnlyCommandState,
    ) -> CommandResult<LocalProxyMetadataProviderStatus> {
        self.provider.stop().map_err(proxy_error)?;
        let _ = drain_proxy_runs(state, &mut self.provider);
        let status = self.provider.status();
        update_capture_availability(state, &status);
        Ok(status)
    }
}

fn drain_proxy_runs(
    state: &mut ReadOnlyCommandState,
    provider: &mut LocalProxyMetadataProvider,
) -> Vec<PortableCaptureLiteRunResult> {
    let runs = provider.take_completed_runs();
    for run in &runs {
        apply_portable_capture_run(state, run);
    }
    runs
}

fn update_capture_availability(
    state: &mut ReadOnlyCommandState,
    status: &LocalProxyMetadataProviderStatus,
) {
    state.service_status.capture_available = matches!(
        status.state,
        LocalProxyMetadataProviderStateKind::Running
            | LocalProxyMetadataProviderStateKind::Degraded
    );
}

fn proxy_error(error: LocalProxyMetadataProviderError) -> CoreError {
    let code = match error {
        LocalProxyMetadataProviderError::AlreadyRunning => ErrorCode::InvalidRequest,
        LocalProxyMetadataProviderError::BindFailed => ErrorCode::ServiceUnavailable,
        LocalProxyMetadataProviderError::WorkerThreadPanicked => ErrorCode::InternalError,
    };

    CoreError::new(code, "portable localhost metadata proxy operation failed")
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read_commands::get_service_status;

    fn wait_for_capture(
        runtime: &mut PortableProxyMetadataRuntime,
    ) -> LocalProxyMetadataProviderStatus {
        for _ in 0..40 {
            let status = runtime.status_snapshot();
            if status.requests_captured > 0 {
                return status;
            }
            thread::sleep(Duration::from_millis(25));
        }
        runtime.status_snapshot()
    }

    fn send_proxy_request(port: u16, request: &str) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect proxy");
        use std::io::{Read, Write};

        stream
            .write_all(request.as_bytes())
            .expect("write proxy request");
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
    }

    #[test]
    fn portable_proxy_runtime_drains_metadata_into_existing_read_models() {
        let mut runtime = PortableProxyMetadataRuntime::default();
        let mut state = ReadOnlyCommandState::bootstrap().expect("bootstrap state");

        let start = runtime
            .start(&mut state, LocalProxyMetadataStartRequest::default())
            .expect("start runtime");
        let port = start.listen_port.expect("listen port");
        send_proxy_request(
            port,
            "POST http://upload.example.test/api/v1/export/42?session_token=secret HTTP/1.1\r\nHost: upload.example.test\r\nUser-Agent: curl/8.8.0\r\nContent-Length: 2048\r\n\r\n",
        );

        let status = wait_for_capture(&mut runtime);
        assert_eq!(status.requests_captured, 1);
        assert!(status.pending_event_count > 0);
        assert_eq!(status.drained_event_count, 0);
        assert_eq!(state.flows.items.len(), 0);

        let drained = runtime.drain(&mut state).expect("drain runtime");
        assert_eq!(drained.pending_event_count, 0);
        assert!(drained.drained_event_count > 0);
        assert_eq!(state.flows.items.len(), 1);
        assert_eq!(state.http_metadata.items.len(), 1);
        assert_eq!(state.findings.items.len(), 1);
        assert_eq!(state.portable_capture_sources.len(), 1);
        assert_eq!(
            state.portable_capture_sources[0].source_type,
            sentinel_contracts::PortableCaptureInputSourceType::LocalProxyMetadata
        );

        let service_status = get_service_status(&state).expect("service status");
        assert!(service_status.capture_available);

        let stopped = runtime.stop(&mut state).expect("stop runtime");
        assert!(matches!(
            stopped.state,
            LocalProxyMetadataProviderStateKind::Stopped
        ));
        let service_status = get_service_status(&state).expect("service status");
        assert!(!service_status.capture_available);
    }

    #[test]
    fn portable_proxy_runtime_stop_drains_pending_batches() {
        let mut runtime = PortableProxyMetadataRuntime::default();
        let mut state = ReadOnlyCommandState::bootstrap().expect("bootstrap state");

        let start = runtime
            .start(&mut state, LocalProxyMetadataStartRequest::default())
            .expect("start runtime");
        let port = start.listen_port.expect("listen port");
        send_proxy_request(
            port,
            "CONNECT secure.example.test:443 HTTP/1.1\r\nHost: secure.example.test:443\r\nUser-Agent: powershell/7.5\r\n\r\n",
        );

        thread::sleep(Duration::from_millis(100));
        let stopped = runtime.stop(&mut state).expect("stop runtime");

        assert!(matches!(
            stopped.state,
            LocalProxyMetadataProviderStateKind::Stopped
        ));
        assert_eq!(stopped.pending_event_count, 0);
        assert!(stopped.drained_event_count > 0);
        assert_eq!(state.flows.items.len(), 1);
        assert_eq!(state.http_metadata.items.len(), 1);
        assert_eq!(
            state.http_metadata.items[0].method,
            sentinel_contracts::HttpMethod::Connect
        );
    }

    #[test]
    fn portable_proxy_runtime_drain_is_idempotent() {
        let mut runtime = PortableProxyMetadataRuntime::default();
        let mut state = ReadOnlyCommandState::bootstrap().expect("bootstrap state");

        let start = runtime
            .start(&mut state, LocalProxyMetadataStartRequest::default())
            .expect("start runtime");
        let port = start.listen_port.expect("listen port");
        send_proxy_request(
            port,
            "POST http://upload.example.test/api/v1/export/88 HTTP/1.1\r\nHost: upload.example.test\r\nContent-Length: 2048\r\n\r\n",
        );

        let _ = wait_for_capture(&mut runtime);
        let first = runtime.drain(&mut state).expect("first drain");
        assert_eq!(first.pending_event_count, 0);
        assert_eq!(state.flows.items.len(), 1);

        let second = runtime.drain(&mut state).expect("second drain");
        assert_eq!(second.pending_event_count, 0);
        assert_eq!(state.flows.items.len(), 1);
        assert_eq!(state.http_metadata.items.len(), 1);

        runtime.stop(&mut state).expect("stop runtime");
    }
}
