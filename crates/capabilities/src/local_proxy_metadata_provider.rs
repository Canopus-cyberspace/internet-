use crate::network_observations::{
    HttpMetadataExtractor, HttpMetadataInput, NetworkObservationError,
};
use crate::portable_capture_lite::{
    build_portable_capture_prepared_batch, run_portable_capture_lite, ParsedPortableCaptureInput,
    PortableCaptureLiteError, PortableCaptureLiteRunResult,
};
use chrono::Duration as ChronoDuration;
#[cfg(test)]
use sentinel_contracts::PluginId;
use sentinel_contracts::{
    FlowRecord, HttpMethod, IpAddress, PortableCaptureInputSourceType, QualityScore,
    RedactionStatus, SessionRecord, Timestamp, TransportProtocol,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const LOCAL_PROXY_LISTEN_HOST: &str = "127.0.0.1";
pub const MAX_LOCAL_PROXY_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_LOCAL_PROXY_PENDING_BATCHES: usize = 64;

const ACCEPT_POLL_INTERVAL_MILLIS: u64 = 25;
const STREAM_TIMEOUT_MILLIS: u64 = 750;
const MAX_LOCAL_PROXY_REPORTED_BODY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LOCAL_PROXY_SCHEME_CHARS: usize = 16;
const MAX_LOCAL_PROXY_CONTENT_TYPE_CHARS: usize = 64;
const MAX_LOCAL_PROXY_PATH_CHARS: usize = 256;
const LOCAL_PROXY_CAPTURED_RESULT_LABEL: &str = "captured_metadata_only_not_forwarded";
const LOCAL_PROXY_CONNECT_RESULT_LABEL: &str = "captured_connect_metadata_only_not_forwarded";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalProxyMetadataStartRequest {
    pub listen_port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalProxyMetadataProviderStateKind {
    Stopped,
    Running,
    Degraded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalProxyMetadataProviderStatus {
    pub state: LocalProxyMetadataProviderStateKind,
    pub listen_host: String,
    pub listen_port: Option<u16>,
    pub requests_captured: u64,
    pub requests_rejected: u64,
    pub dropped_batches: u64,
    pub pending_batches: usize,
    pub pending_event_count: u64,
    pub drained_event_count: u64,
    pub last_capture_at: Option<Timestamp>,
    pub last_error_code: Option<String>,
    pub localhost_only: bool,
    pub metadata_only: bool,
    pub message_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalProxyMetadataProviderError {
    AlreadyRunning,
    BindFailed,
    WorkerThreadPanicked,
}

impl fmt::Display for LocalProxyMetadataProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning => write!(f, "localhost metadata proxy is already running"),
            Self::BindFailed => write!(f, "localhost metadata proxy could not bind to 127.0.0.1"),
            Self::WorkerThreadPanicked => {
                write!(f, "localhost metadata proxy worker terminated unexpectedly")
            }
        }
    }
}

impl std::error::Error for LocalProxyMetadataProviderError {}

#[derive(Debug)]
pub struct LocalProxyMetadataProvider {
    runtime: Option<LocalProxyMetadataProviderRuntime>,
    stopped_runs: Vec<PortableCaptureLiteRunResult>,
    last_status: LocalProxyMetadataProviderStatus,
}

impl Default for LocalProxyMetadataProvider {
    fn default() -> Self {
        Self {
            runtime: None,
            stopped_runs: Vec::new(),
            last_status: stopped_status(None, LocalProxyMetadataProviderStats::default()),
        }
    }
}

impl LocalProxyMetadataProvider {
    pub fn start(
        &mut self,
        request: LocalProxyMetadataStartRequest,
    ) -> Result<LocalProxyMetadataProviderStatus, LocalProxyMetadataProviderError> {
        self.start_with_queue_capacity(request, MAX_LOCAL_PROXY_PENDING_BATCHES)
    }

    fn start_with_queue_capacity(
        &mut self,
        request: LocalProxyMetadataStartRequest,
        queue_capacity: usize,
    ) -> Result<LocalProxyMetadataProviderStatus, LocalProxyMetadataProviderError> {
        if self.runtime.is_some() {
            return Err(LocalProxyMetadataProviderError::AlreadyRunning);
        }

        let listener =
            TcpListener::bind((LOCAL_PROXY_LISTEN_HOST, request.listen_port.unwrap_or(0)))
                .map_err(|_| LocalProxyMetadataProviderError::BindFailed)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| LocalProxyMetadataProviderError::BindFailed)?;
        let listen_port = listener
            .local_addr()
            .map_err(|_| LocalProxyMetadataProviderError::BindFailed)?
            .port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let carryover_stats = if self.stopped_runs.is_empty() {
            LocalProxyMetadataProviderStats {
                drained_event_count: self.last_status.drained_event_count,
                ..LocalProxyMetadataProviderStats::default()
            }
        } else {
            LocalProxyMetadataProviderStats {
                requests_captured: self.last_status.requests_captured,
                requests_rejected: self.last_status.requests_rejected,
                dropped_batches: self.last_status.dropped_batches,
                pending_batches: self.stopped_runs.len(),
                pending_event_count: self.last_status.pending_event_count,
                drained_event_count: self.last_status.drained_event_count,
                last_capture_at: self.last_status.last_capture_at.clone(),
                last_error_code: self.last_status.last_error_code.clone(),
            }
        };
        let stats = Arc::new(Mutex::new(carryover_stats));
        let (completed_tx, completed_rx) =
            mpsc::sync_channel::<PortableCaptureLiteRunResult>(queue_capacity);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_stats = Arc::clone(&stats);
        let worker = thread::spawn(move || {
            run_local_proxy_listener(listener, thread_shutdown, thread_stats, completed_tx);
        });

        self.runtime = Some(LocalProxyMetadataProviderRuntime {
            listen_port,
            shutdown,
            stats,
            completed_rx,
            worker,
        });
        Ok(self.status())
    }

    pub fn status(&mut self) -> LocalProxyMetadataProviderStatus {
        let Some(runtime) = &self.runtime else {
            return self.last_status.clone();
        };

        let worker_finished = runtime.worker.is_finished();
        let status = running_status(
            runtime.listen_port,
            runtime.stats_snapshot(),
            worker_finished,
        );
        self.last_status = status.clone();
        status
    }

    pub fn drain_completed_runs(&mut self) -> Vec<PortableCaptureLiteRunResult> {
        let mut drained = std::mem::take(&mut self.stopped_runs);
        let Some(runtime) = &mut self.runtime else {
            finish_stopped_drain(&mut self.last_status, &drained);
            return drained;
        };

        let runtime_drained = runtime.completed_rx.try_iter().collect::<Vec<_>>();
        if !runtime_drained.is_empty() {
            runtime.finish_drained_runs(&runtime_drained);
        }
        drained.extend(runtime_drained);
        if !drained.is_empty() {
            self.last_status = running_status(
                runtime.listen_port,
                runtime.stats_snapshot(),
                runtime.worker.is_finished(),
            );
        }
        drained
    }

    pub fn take_completed_runs(&mut self) -> Vec<PortableCaptureLiteRunResult> {
        self.drain_completed_runs()
    }

    pub fn stop(
        &mut self,
    ) -> Result<LocalProxyMetadataProviderStatus, LocalProxyMetadataProviderError> {
        let Some(runtime) = self.runtime.take() else {
            return Ok(self.status());
        };

        runtime.shutdown.store(true, Ordering::Relaxed);
        let listen_port = runtime.listen_port;
        let snapshot = runtime.stats_snapshot();
        if runtime.worker.join().is_err() {
            self.last_status = stopped_status(Some(listen_port), snapshot);
            self.last_status.last_error_code = Some("worker_thread_panicked".to_string());
            return Err(LocalProxyMetadataProviderError::WorkerThreadPanicked);
        }
        let drained_after_stop = runtime.completed_rx.try_iter().collect::<Vec<_>>();
        if !drained_after_stop.is_empty() {
            self.stopped_runs.extend(drained_after_stop);
        }
        self.last_status = stopped_status(
            Some(listen_port),
            LocalProxyMetadataProviderStats {
                pending_batches: self.stopped_runs.len(),
                ..snapshot
            },
        );
        Ok(self.last_status.clone())
    }
}

impl Drop for LocalProxyMetadataProvider {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Debug)]
struct LocalProxyMetadataProviderRuntime {
    listen_port: u16,
    shutdown: Arc<AtomicBool>,
    stats: Arc<Mutex<LocalProxyMetadataProviderStats>>,
    completed_rx: Receiver<PortableCaptureLiteRunResult>,
    worker: JoinHandle<()>,
}

impl LocalProxyMetadataProviderRuntime {
    fn finish_drained_runs(&self, drained: &[PortableCaptureLiteRunResult]) {
        if drained.is_empty() {
            return;
        }
        if let Ok(mut stats) = self.stats.lock() {
            let drained_event_count = drained.iter().map(proxy_event_count).sum::<u64>();
            stats.pending_batches = stats.pending_batches.saturating_sub(drained.len());
            stats.pending_event_count = stats
                .pending_event_count
                .saturating_sub(drained_event_count);
            stats.drained_event_count = stats
                .drained_event_count
                .saturating_add(drained_event_count);
        }
    }

    fn stats_snapshot(&self) -> LocalProxyMetadataProviderStats {
        self.stats
            .lock()
            .map(|stats| stats.clone())
            .unwrap_or_else(|_| LocalProxyMetadataProviderStats {
                last_error_code: Some("stats_unavailable".to_string()),
                ..LocalProxyMetadataProviderStats::default()
            })
    }
}

#[derive(Clone, Debug, Default)]
struct LocalProxyMetadataProviderStats {
    requests_captured: u64,
    requests_rejected: u64,
    dropped_batches: u64,
    pending_batches: usize,
    pending_event_count: u64,
    drained_event_count: u64,
    last_capture_at: Option<Timestamp>,
    last_error_code: Option<String>,
}

#[derive(Clone, Debug)]
struct ParsedProxyRequest {
    method: HttpMethod,
    scheme: String,
    host: String,
    port: u16,
    path_visible: Option<String>,
    header_bytes: usize,
    declared_content_length: u64,
    content_type: Option<String>,
    user_agent_family: Option<String>,
    result_label: &'static str,
    status_code: u16,
    redaction_applied: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalProxyConnectionError {
    HeaderTooLarge,
    IncompleteHeader,
    MalformedRequest,
    UnsupportedTarget,
    MetadataPipelineFailed,
    QueueBackpressure,
}

impl LocalProxyConnectionError {
    fn code(self) -> &'static str {
        match self {
            Self::HeaderTooLarge => "header_too_large",
            Self::IncompleteHeader => "incomplete_header",
            Self::MalformedRequest => "malformed_request",
            Self::UnsupportedTarget => "unsupported_target",
            Self::MetadataPipelineFailed => "metadata_pipeline_failed",
            Self::QueueBackpressure => "queue_backpressure",
        }
    }
}

fn run_local_proxy_listener(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    stats: Arc<Mutex<LocalProxyMetadataProviderStats>>,
    completed_tx: SyncSender<PortableCaptureLiteRunResult>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, peer_addr)) => {
                handle_local_proxy_connection(&mut stream, peer_addr, &stats, &completed_tx);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(ACCEPT_POLL_INTERVAL_MILLIS));
            }
            Err(_) => {
                record_rejection(&stats, LocalProxyConnectionError::MalformedRequest);
                thread::sleep(Duration::from_millis(ACCEPT_POLL_INTERVAL_MILLIS));
            }
        }
    }
}

fn handle_local_proxy_connection(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    stats: &Arc<Mutex<LocalProxyMetadataProviderStats>>,
    completed_tx: &SyncSender<PortableCaptureLiteRunResult>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(STREAM_TIMEOUT_MILLIS)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(STREAM_TIMEOUT_MILLIS)));
    let started_at = Timestamp::now();
    let started = Instant::now();

    let parsed = match read_and_parse_proxy_request(stream) {
        Ok(parsed) => parsed,
        Err(error) => {
            record_rejection(stats, error);
            let _ = write_response(stream, error_response(error));
            return;
        }
    };

    let duration_millis = cap_duration_millis(started.elapsed());
    let run_result = match build_and_run_proxy_metadata(
        peer_addr,
        &parsed,
        started_at,
        duration_millis,
    ) {
        Ok(result) => result,
        Err(_) => {
            record_rejection(stats, LocalProxyConnectionError::MetadataPipelineFailed);
            let _ = write_response(stream, b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\nX-Sentinel-Guard-Metadata-Only: true\r\n\r\n");
            return;
        }
    };

    let queued_event_count = proxy_event_count(&run_result);
    match completed_tx.try_send(run_result) {
        Ok(()) => {
            record_capture(stats, queued_event_count);
            let _ = write_response(stream, success_response(&parsed.method));
        }
        Err(TrySendError::Full(_)) => {
            record_drop(stats);
            let _ = write_response(stream, b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\nX-Sentinel-Guard-Metadata-Only: true\r\n\r\n");
        }
        Err(TrySendError::Disconnected(_)) => {
            record_rejection(stats, LocalProxyConnectionError::MetadataPipelineFailed);
            let _ = write_response(stream, b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\nX-Sentinel-Guard-Metadata-Only: true\r\n\r\n");
        }
    }
}

fn read_and_parse_proxy_request(
    stream: &mut TcpStream,
) -> Result<ParsedProxyRequest, LocalProxyConnectionError> {
    let header = read_request_head(stream)?;
    parse_proxy_request(&header)
}

fn read_request_head(stream: &mut TcpStream) -> Result<Vec<u8>, LocalProxyConnectionError> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 512];

    loop {
        let read_count = stream
            .read(&mut chunk)
            .map_err(|_| LocalProxyConnectionError::IncompleteHeader)?;
        if read_count == 0 {
            return Err(LocalProxyConnectionError::IncompleteHeader);
        }
        buffer.extend_from_slice(&chunk[..read_count]);
        if buffer.len() > MAX_LOCAL_PROXY_HEADER_BYTES {
            return Err(LocalProxyConnectionError::HeaderTooLarge);
        }
        if find_header_terminator(&buffer).is_some() {
            return Ok(buffer);
        }
    }
}

fn parse_proxy_request(header: &[u8]) -> Result<ParsedProxyRequest, LocalProxyConnectionError> {
    let text = String::from_utf8_lossy(header);
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(LocalProxyConnectionError::MalformedRequest)?;
    let mut request_parts = request_line.split_whitespace();
    let method_raw = request_parts
        .next()
        .ok_or(LocalProxyConnectionError::MalformedRequest)?;
    let target = request_parts
        .next()
        .ok_or(LocalProxyConnectionError::MalformedRequest)?;
    let _version = request_parts
        .next()
        .ok_or(LocalProxyConnectionError::MalformedRequest)?;
    if request_parts.next().is_some() {
        return Err(LocalProxyConnectionError::MalformedRequest);
    }

    let method = parse_http_method(method_raw);
    let mut host_header = None::<String>;
    let mut declared_content_length = 0_u64;
    let mut content_type = None::<String>;
    let mut user_agent_family = None::<String>;
    let mut redaction_applied = false;

    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(LocalProxyConnectionError::MalformedRequest);
        };
        let header_name = name.trim();
        let header_value = value.trim();
        if header_name.eq_ignore_ascii_case("host") {
            host_header = Some(header_value.to_string());
        } else if header_name.eq_ignore_ascii_case("content-length") {
            declared_content_length = header_value
                .parse::<u64>()
                .map(cap_reported_body_bytes)
                .unwrap_or(0);
        } else if header_name.eq_ignore_ascii_case("content-type") {
            content_type = normalize_bounded_text(header_value, MAX_LOCAL_PROXY_CONTENT_TYPE_CHARS);
        } else if header_name.eq_ignore_ascii_case("user-agent") {
            user_agent_family = user_agent_family_for_value(Some(header_value));
        }
        if is_sensitive_header(header_name)
            || contains_local_path(header_value)
            || contains_private_marker(header_value)
        {
            redaction_applied = true;
        }
    }

    let parsed_target = parse_proxy_target(&method, target, host_header.as_deref())?;
    let result_label = result_label_for_method(&method);
    let status_code = status_code_for_method(&method);
    Ok(ParsedProxyRequest {
        method,
        scheme: parsed_target.scheme,
        host: parsed_target.host,
        port: parsed_target.port,
        path_visible: parsed_target.path_visible,
        header_bytes: header.len(),
        declared_content_length,
        content_type,
        user_agent_family,
        result_label,
        status_code,
        redaction_applied: redaction_applied || parsed_target.redaction_applied,
    })
}

fn build_and_run_proxy_metadata(
    peer_addr: SocketAddr,
    parsed: &ParsedProxyRequest,
    started_at: Timestamp,
    duration_millis: u64,
) -> Result<PortableCaptureLiteRunResult, LocalProxyConnectionError> {
    let src_ip = IpAddress::from(peer_addr.ip());
    let dst_ip = destination_ip_for_host(&parsed.host);
    let ended_at = Timestamp::from_datetime(
        started_at.as_datetime().to_owned() + ChronoDuration::milliseconds(duration_millis as i64),
    );
    let mut flow = FlowRecord::new(
        src_ip,
        peer_addr.port(),
        dst_ip,
        parsed.port,
        TransportProtocol::Tcp,
        sentinel_contracts::NetworkDirection::Outbound,
    );
    flow.start_time = started_at.clone();
    flow.end_time = Some(ended_at.clone());
    flow.duration_millis = Some(duration_millis);
    flow.bytes_out = cap_reported_body_bytes(parsed.declared_content_length)
        .saturating_add(parsed.header_bytes as u64);
    flow.bytes_in = 0;
    flow.packets_out = 1;
    flow.packets_in = 0;
    flow.quality_score =
        QualityScore::new(0.74).map_err(|_| LocalProxyConnectionError::MetadataPipelineFailed)?;

    let mut session = SessionRecord::new(
        src_ip,
        peer_addr.port(),
        dst_ip,
        parsed.port,
        TransportProtocol::Tcp,
        sentinel_contracts::NetworkDirection::Outbound,
    );
    session.flow_refs.push(flow.flow_id.clone());
    session.start_time = flow.start_time.clone();
    session.end_time = flow.end_time.clone();
    session.duration_millis = flow.duration_millis;
    session.bytes_out = flow.bytes_out;
    session.bytes_in = flow.bytes_in;
    session.packets_out = flow.packets_out;
    session.packets_in = flow.packets_in;
    session.quality_score =
        QualityScore::new(0.74).map_err(|_| LocalProxyConnectionError::MetadataPipelineFailed)?;
    flow.session_ref = Some(session.session_id.clone());

    let (host_protected, host_redaction) = redact_host(&parsed.host);
    let (path_visible, path_redaction) = sanitize_path_input(parsed.path_visible.as_deref());
    let http = HttpMetadataExtractor
        .extract(HttpMetadataInput {
            flow_ref: Some(flow.flow_id.clone()),
            timestamp: ended_at,
            method: parsed.method.clone(),
            scheme: Some(parsed.scheme.clone()),
            host_protected: Some(host_protected),
            path_visible,
            status_code: Some(parsed.status_code),
            result_label: Some(parsed.result_label.to_string()),
            request_size_bytes: Some(flow.bytes_out),
            response_size_bytes: Some(flow.bytes_in),
            request_content_length_bytes: Some(parsed.declared_content_length),
            response_content_length_bytes: Some(0),
            content_type: parsed.content_type.clone(),
            user_agent_family: parsed.user_agent_family.clone(),
            waf_action: None,
            waf_rule_id: None,
            waf_attack_class: None,
            visible_plaintext: true,
            process_ref: None,
        })
        .map_err(map_network_observation_error)?
        .ok_or(LocalProxyConnectionError::MetadataPipelineFailed)?;

    let prepared = build_portable_capture_prepared_batch(
        PortableCaptureInputSourceType::LocalProxyMetadata,
        ParsedPortableCaptureInput {
            flow_records: vec![flow],
            session_records: vec![session],
            dns_observations: Vec::new(),
            tls_observations: Vec::new(),
            http_metadata: vec![http],
            auth_metadata: Vec::new(),
            saas_cloud_metadata: Vec::new(),
            deception_events: Vec::new(),
            redaction_status: if parsed.redaction_applied || host_redaction || path_redaction {
                RedactionStatus::Redacted
            } else {
                RedactionStatus::NotRequired
            },
        },
    )
    .map_err(map_portable_capture_error)?;

    run_portable_capture_lite(&prepared).map_err(map_portable_capture_error)
}

fn find_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn write_response(stream: &mut TcpStream, response: &[u8]) -> std::io::Result<()> {
    stream.write_all(response)?;
    stream.flush()
}

fn success_response(method: &HttpMethod) -> &'static [u8] {
    if matches!(method, HttpMethod::Connect) {
        b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\nX-Sentinel-Guard-Metadata-Only: true\r\n\r\n"
    } else {
        b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\nX-Sentinel-Guard-Metadata-Only: true\r\n\r\n"
    }
}

fn error_response(error: LocalProxyConnectionError) -> &'static [u8] {
    match error {
        LocalProxyConnectionError::HeaderTooLarge => {
            b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\nX-Sentinel-Guard-Metadata-Only: true\r\n\r\n"
        }
        LocalProxyConnectionError::UnsupportedTarget => {
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\nX-Sentinel-Guard-Metadata-Only: true\r\n\r\n"
        }
        _ => {
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\nX-Sentinel-Guard-Metadata-Only: true\r\n\r\n"
        }
    }
}

fn record_capture(stats: &Arc<Mutex<LocalProxyMetadataProviderStats>>, event_count: u64) {
    if let Ok(mut stats) = stats.lock() {
        stats.requests_captured = stats.requests_captured.saturating_add(1);
        stats.pending_batches = stats.pending_batches.saturating_add(1);
        stats.pending_event_count = stats.pending_event_count.saturating_add(event_count);
        stats.last_capture_at = Some(Timestamp::now());
    }
}

fn record_rejection(
    stats: &Arc<Mutex<LocalProxyMetadataProviderStats>>,
    error: LocalProxyConnectionError,
) {
    if let Ok(mut stats) = stats.lock() {
        stats.requests_rejected = stats.requests_rejected.saturating_add(1);
        stats.last_error_code = Some(error.code().to_string());
    }
}

fn record_drop(stats: &Arc<Mutex<LocalProxyMetadataProviderStats>>) {
    if let Ok(mut stats) = stats.lock() {
        stats.dropped_batches = stats.dropped_batches.saturating_add(1);
        stats.last_error_code = Some(
            LocalProxyConnectionError::QueueBackpressure
                .code()
                .to_string(),
        );
    }
}

fn finish_stopped_drain(
    status: &mut LocalProxyMetadataProviderStatus,
    drained: &[PortableCaptureLiteRunResult],
) {
    if drained.is_empty() {
        return;
    }

    let drained_event_count = drained.iter().map(proxy_event_count).sum::<u64>();
    status.pending_batches = status.pending_batches.saturating_sub(drained.len());
    status.pending_event_count = status
        .pending_event_count
        .saturating_sub(drained_event_count);
    status.drained_event_count = status
        .drained_event_count
        .saturating_add(drained_event_count);
    status.message_redacted = stopped_message(status.pending_event_count);
}

fn running_status(
    listen_port: u16,
    snapshot: LocalProxyMetadataProviderStats,
    worker_finished: bool,
) -> LocalProxyMetadataProviderStatus {
    let state = if worker_finished
        || snapshot.requests_rejected > 0
        || snapshot.dropped_batches > 0
        || snapshot.last_error_code.is_some()
    {
        LocalProxyMetadataProviderStateKind::Degraded
    } else {
        LocalProxyMetadataProviderStateKind::Running
    };
    let message_redacted = match state {
        LocalProxyMetadataProviderStateKind::Running => format!(
            "Localhost metadata proxy is running on {}:{} in metadata-only mode; requests are not forwarded or retained",
            LOCAL_PROXY_LISTEN_HOST, listen_port
        ),
        LocalProxyMetadataProviderStateKind::Degraded => format!(
            "Localhost metadata proxy is running on {}:{} with reduced fidelity or worker instability; metadata-only mode remains active",
            LOCAL_PROXY_LISTEN_HOST, listen_port
        ),
        LocalProxyMetadataProviderStateKind::Stopped => stopped_message(snapshot.pending_event_count),
    };

    LocalProxyMetadataProviderStatus {
        state,
        listen_host: LOCAL_PROXY_LISTEN_HOST.to_string(),
        listen_port: Some(listen_port),
        requests_captured: snapshot.requests_captured,
        requests_rejected: snapshot.requests_rejected,
        dropped_batches: snapshot.dropped_batches,
        pending_batches: snapshot.pending_batches,
        pending_event_count: snapshot.pending_event_count,
        drained_event_count: snapshot.drained_event_count,
        last_capture_at: snapshot.last_capture_at,
        last_error_code: snapshot.last_error_code,
        localhost_only: true,
        metadata_only: true,
        message_redacted,
    }
}

fn stopped_status(
    listen_port: Option<u16>,
    snapshot: LocalProxyMetadataProviderStats,
) -> LocalProxyMetadataProviderStatus {
    LocalProxyMetadataProviderStatus {
        state: LocalProxyMetadataProviderStateKind::Stopped,
        listen_host: LOCAL_PROXY_LISTEN_HOST.to_string(),
        listen_port,
        requests_captured: snapshot.requests_captured,
        requests_rejected: snapshot.requests_rejected,
        dropped_batches: snapshot.dropped_batches,
        pending_batches: snapshot.pending_batches,
        pending_event_count: snapshot.pending_event_count,
        drained_event_count: snapshot.drained_event_count,
        last_capture_at: snapshot.last_capture_at,
        last_error_code: snapshot.last_error_code,
        localhost_only: true,
        metadata_only: true,
        message_redacted: stopped_message(snapshot.pending_event_count),
    }
}

fn stopped_message(pending_event_count: u64) -> String {
    if pending_event_count > 0 {
        "Localhost metadata proxy is stopped; queued metadata is waiting for explicit drain"
            .to_string()
    } else {
        "Localhost metadata proxy is stopped".to_string()
    }
}

fn proxy_event_count(run_result: &PortableCaptureLiteRunResult) -> u64 {
    (run_result.flow_records.len()
        + run_result.session_records.len()
        + run_result.dns_observations.len()
        + run_result.tls_observations.len()
        + run_result.http_metadata.len()
        + run_result.service_capability_contexts.len()
        + run_result.findings.len()
        + run_result.evidence.len()
        + run_result.graph_hints.len()
        + run_result.risk_events.len()
        + run_result.alerts.len()
        + run_result.incidents.len()) as u64
}

#[derive(Clone, Debug)]
struct ParsedProxyTarget {
    scheme: String,
    host: String,
    port: u16,
    path_visible: Option<String>,
    redaction_applied: bool,
}

fn parse_proxy_target(
    method: &HttpMethod,
    target: &str,
    host_header: Option<&str>,
) -> Result<ParsedProxyTarget, LocalProxyConnectionError> {
    match method {
        HttpMethod::Connect => parse_connect_target(target),
        _ if target.contains("://") => parse_absolute_target(target),
        _ => parse_origin_target(target, host_header),
    }
}

fn parse_connect_target(target: &str) -> Result<ParsedProxyTarget, LocalProxyConnectionError> {
    let (authority, had_userinfo) = split_authority_userinfo(target);
    let (host, port) = parse_authority(authority, "https")?;
    Ok(ParsedProxyTarget {
        scheme: "https".to_string(),
        host,
        port,
        path_visible: None,
        redaction_applied: had_userinfo,
    })
}

fn parse_absolute_target(target: &str) -> Result<ParsedProxyTarget, LocalProxyConnectionError> {
    let (scheme, remainder) = target
        .split_once("://")
        .ok_or(LocalProxyConnectionError::UnsupportedTarget)?;
    let scheme = normalize_scheme(scheme)?;
    let (authority_with_userinfo, path_visible) = match remainder.find('/') {
        Some(index) => (&remainder[..index], Some(remainder[index..].to_string())),
        None => (remainder, None),
    };
    let (authority, had_userinfo) = split_authority_userinfo(authority_with_userinfo);
    let (host, port) = parse_authority(authority, &scheme)?;
    Ok(ParsedProxyTarget {
        scheme,
        host,
        port,
        path_visible,
        redaction_applied: had_userinfo,
    })
}

fn parse_origin_target(
    target: &str,
    host_header: Option<&str>,
) -> Result<ParsedProxyTarget, LocalProxyConnectionError> {
    let host_header = host_header.ok_or(LocalProxyConnectionError::UnsupportedTarget)?;
    let (authority, had_userinfo) = split_authority_userinfo(host_header);
    let (host, port) = parse_authority(authority, "http")?;
    Ok(ParsedProxyTarget {
        scheme: "http".to_string(),
        host,
        port,
        path_visible: Some(target.to_string()),
        redaction_applied: had_userinfo,
    })
}

fn split_authority_userinfo(authority: &str) -> (&str, bool) {
    authority
        .rsplit_once('@')
        .map(|(_, value)| (value, true))
        .unwrap_or((authority, false))
}

fn parse_authority(
    authority: &str,
    scheme: &str,
) -> Result<(String, u16), LocalProxyConnectionError> {
    if authority.is_empty() {
        return Err(LocalProxyConnectionError::UnsupportedTarget);
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or(LocalProxyConnectionError::UnsupportedTarget)?;
        let port = suffix
            .strip_prefix(':')
            .map(|value| {
                value
                    .parse::<u16>()
                    .map_err(|_| LocalProxyConnectionError::UnsupportedTarget)
            })
            .transpose()?
            .unwrap_or_else(|| default_port(scheme));
        return normalize_authority_host(host, port);
    }

    if let Some((host, port)) = authority.rsplit_once(':') {
        if authority.matches(':').count() == 1 {
            return normalize_authority_host(
                host.trim(),
                port.parse::<u16>()
                    .map_err(|_| LocalProxyConnectionError::UnsupportedTarget)?,
            );
        }
    }

    if authority.contains(':') {
        return Err(LocalProxyConnectionError::UnsupportedTarget);
    }

    normalize_authority_host(authority.trim(), default_port(scheme))
}

fn parse_http_method(value: &str) -> HttpMethod {
    match value.trim().to_ascii_uppercase().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        "TRACE" => HttpMethod::Trace,
        "CONNECT" => HttpMethod::Connect,
        _ => HttpMethod::Other,
    }
}

fn default_port(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("http") {
        80
    } else {
        443
    }
}

fn normalize_scheme(value: &str) -> Result<String, LocalProxyConnectionError> {
    let trimmed = value.trim().to_ascii_lowercase();
    if trimmed.is_empty()
        || trimmed.len() > MAX_LOCAL_PROXY_SCHEME_CHARS
        || !trimmed.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
    {
        return Err(LocalProxyConnectionError::UnsupportedTarget);
    }
    Ok(trimmed)
}

fn normalize_authority_host(
    host: &str,
    port: u16,
) -> Result<(String, u16), LocalProxyConnectionError> {
    let normalized = host.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 255
        || normalized.contains('/')
        || normalized.contains('\\')
        || normalized.contains(' ')
    {
        return Err(LocalProxyConnectionError::UnsupportedTarget);
    }
    Ok((normalized, port))
}

fn normalize_bounded_text(value: &str, max_chars: usize) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(max_chars).collect::<String>())
}

fn cap_reported_body_bytes(value: u64) -> u64 {
    value.min(MAX_LOCAL_PROXY_REPORTED_BODY_BYTES)
}

fn cap_duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(STREAM_TIMEOUT_MILLIS as u128) as u64
}

fn status_code_for_method(method: &HttpMethod) -> u16 {
    if matches!(method, HttpMethod::Connect) {
        501
    } else {
        204
    }
}

fn result_label_for_method(method: &HttpMethod) -> &'static str {
    if matches!(method, HttpMethod::Connect) {
        LOCAL_PROXY_CONNECT_RESULT_LABEL
    } else {
        LOCAL_PROXY_CAPTURED_RESULT_LABEL
    }
}

fn destination_ip_for_host(host: &str) -> IpAddress {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return IpAddress::from(ip);
    }
    let digest = stable_hash(host);
    IpAddress::from(IpAddr::V4(Ipv4Addr::new(
        198,
        51,
        100,
        20 + (digest[0] % 200),
    )))
}

fn redact_host(host: &str) -> (String, bool) {
    if host.parse::<IpAddr>().is_ok() {
        (host.to_ascii_lowercase(), false)
    } else {
        (format!("host#{}", stable_hash_hex(host, 12)), true)
    }
}

fn sanitize_path_input(path_and_query: Option<&str>) -> (Option<String>, bool) {
    let Some(path_and_query) = path_and_query else {
        return (None, false);
    };
    let path = path_and_query.split('#').next().unwrap_or_default();
    let had_query = path.contains('?');
    let stripped = path.split('?').next().unwrap_or_default();
    let templated = if contains_local_path(stripped) || contains_private_marker(stripped) {
        "/redacted/{id}".to_string()
    } else {
        stripped
            .split('/')
            .map(|segment| {
                if segment.parse::<u64>().is_ok()
                    || looks_like_hex_identifier(segment)
                    || looks_like_secret_token(segment)
                {
                    "{id}".to_string()
                } else {
                    segment.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    };
    let bounded = templated
        .chars()
        .take(MAX_LOCAL_PROXY_PATH_CHARS)
        .collect::<String>();
    (
        Some(bounded),
        had_query || contains_local_path(stripped) || contains_private_marker(stripped),
    )
}

fn user_agent_family_for_value(value: Option<&str>) -> Option<String> {
    let value = value?.to_ascii_lowercase();
    if value.contains("curl") {
        Some("curl".to_string())
    } else if value.contains("python-requests") {
        Some("python_requests".to_string())
    } else if value.contains("powershell") {
        Some("powershell".to_string())
    } else if value.contains("firefox") {
        Some("firefox".to_string())
    } else if value.contains("chrome") || value.contains("chromium") {
        Some("chromium".to_string())
    } else if value.contains("edge") {
        Some("edge".to_string())
    } else if value.trim().is_empty() {
        None
    } else {
        Some("other".to_string())
    }
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "set-cookie" | "proxy-authorization" | "x-api-key"
    )
}

fn map_network_observation_error(_: NetworkObservationError) -> LocalProxyConnectionError {
    LocalProxyConnectionError::MetadataPipelineFailed
}

fn map_portable_capture_error(_: PortableCaptureLiteError) -> LocalProxyConnectionError {
    LocalProxyConnectionError::MetadataPipelineFailed
}

fn contains_private_marker(value: &str) -> bool {
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '/', '=', ':', '\\'], "_");
    [
        "authorization",
        "api_key",
        "cookie",
        "credential",
        "password",
        "private_key",
        "session_token",
        "access_token",
        "refresh_token",
        "token",
        "secret",
        "form_content",
    ]
    .into_iter()
    .any(|marker| normalized.contains(marker))
}

fn contains_local_path(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("file:///")
        || normalized.contains(":\\")
        || normalized.contains("\\users\\")
        || normalized.contains("/users/")
        || normalized.contains("/home/")
        || normalized.contains("/var/")
        || normalized.contains("%appdata%")
        || normalized.contains("%localappdata%")
}

fn looks_like_hex_identifier(value: &str) -> bool {
    value.len() >= 12 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn looks_like_secret_token(value: &str) -> bool {
    let trimmed = value.trim_matches(|character: char| {
        character == '"' || character == '\'' || character == ';' || character == ','
    });
    trimmed.len() > 24
        && trimmed.chars().any(|ch| ch.is_ascii_lowercase())
        && trimmed.chars().any(|ch| ch.is_ascii_uppercase())
        && trimmed.chars().any(|ch| ch.is_ascii_digit())
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '='))
}

fn stable_hash(value: &str) -> [u8; 32] {
    let digest = Sha256::digest(value.as_bytes());
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn stable_hash_hex(value: &str, limit: usize) -> String {
    let digest = stable_hash(value);
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .chars()
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_stage::{GraphStageInput, GraphStagePlugin};
    use std::io::{Read, Write};
    use std::net::Shutdown;

    fn wait_for_status(
        provider: &mut LocalProxyMetadataProvider,
        predicate: impl Fn(&LocalProxyMetadataProviderStatus) -> bool,
    ) -> LocalProxyMetadataProviderStatus {
        for _ in 0..40 {
            let status = provider.status();
            if predicate(&status) {
                return status;
            }
            thread::sleep(Duration::from_millis(25));
        }
        provider.status()
    }

    fn send_proxy_request(port: u16, request: &str) -> String {
        let mut stream =
            TcpStream::connect((LOCAL_PROXY_LISTEN_HOST, port)).expect("connect proxy");
        stream
            .write_all(request.as_bytes())
            .expect("write proxy request");
        let _ = stream.shutdown(Shutdown::Write);
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        String::from_utf8_lossy(&response).to_string()
    }

    fn response_status_line(response: &str) -> &str {
        response.lines().next().unwrap_or_default()
    }

    fn run_graph_stage_for_proxy(
        run: &PortableCaptureLiteRunResult,
    ) -> crate::graph_stage::GraphStageOutput {
        let mut input = GraphStageInput::new(PluginId::new_v4());
        input.graph_hints = run.graph_hints.clone();
        input.findings = run.findings.clone();
        GraphStagePlugin::new()
            .process(
                input,
                Option::<&sentinel_storage::SqliteGraphStore<'_>>::None,
            )
            .expect("graph stage output")
    }

    #[test]
    fn portable_local_proxy_provider_captures_connect_metadata_without_payload_leakage() {
        let mut provider = LocalProxyMetadataProvider::default();
        let start = provider
            .start(LocalProxyMetadataStartRequest::default())
            .expect("start proxy");
        let port = start.listen_port.expect("listen port");

        let response = send_proxy_request(
            port,
            "CONNECT secret.example.test:443 HTTP/1.1\r\nHost: secret.example.test:443\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\nUser-Agent: curl/8.8.0\r\n\r\n",
        );
        assert_eq!(
            response_status_line(&response),
            "HTTP/1.1 501 Not Implemented"
        );

        let status = wait_for_status(&mut provider, |status| status.requests_captured == 1);
        assert!(matches!(
            status.state,
            LocalProxyMetadataProviderStateKind::Degraded
                | LocalProxyMetadataProviderStateKind::Running
        ));
        assert!(status.pending_event_count > 0);
        let completed = provider.drain_completed_runs();
        assert_eq!(completed.len(), 1);
        assert_eq!(
            completed[0].provenance.source_type,
            PortableCaptureInputSourceType::LocalProxyMetadata
        );
        assert_eq!(completed[0].flow_records.len(), 1);
        assert_eq!(completed[0].session_records.len(), 1);
        assert_eq!(completed[0].http_metadata.len(), 1);
        assert_eq!(completed[0].http_metadata[0].method, HttpMethod::Connect);
        assert_eq!(
            completed[0].http_metadata[0].scheme.as_deref(),
            Some("https")
        );
        assert_eq!(completed[0].http_metadata[0].status_code, Some(501));
        assert_eq!(
            completed[0].http_metadata[0].result_label.as_deref(),
            Some(LOCAL_PROXY_CONNECT_RESULT_LABEL)
        );
        assert!(completed[0].graph_hints.is_empty());
        assert!(completed[0].flow_records[0].duration_millis.is_some());

        let serialized = serde_json::json!({
            "provenance": &completed[0].provenance,
            "emitted_topics": &completed[0].emitted_topics,
            "flow_records": &completed[0].flow_records,
            "session_records": &completed[0].session_records,
            "http_metadata": &completed[0].http_metadata,
            "findings": &completed[0].findings,
            "evidence": &completed[0].evidence,
            "graph_hints": &completed[0].graph_hints,
            "alerts": &completed[0].alerts,
            "incidents": &completed[0].incidents,
        })
        .to_string();
        for marker in ["Proxy-Authorization", "Zm9vOmJhcg==", "cookie", "payload"] {
            assert!(
                !serialized
                    .to_ascii_lowercase()
                    .contains(&marker.to_ascii_lowercase()),
                "serialized runtime leaked forbidden marker {marker}"
            );
        }

        provider.stop().expect("stop proxy");
    }

    #[test]
    fn portable_local_proxy_provider_emits_evidence_backed_graph_hints_for_http_uploads() {
        let mut provider = LocalProxyMetadataProvider::default();
        let start = provider
            .start(LocalProxyMetadataStartRequest::default())
            .expect("start proxy");
        let port = start.listen_port.expect("listen port");

        let response = send_proxy_request(
            port,
            "POST http://upload.example.test/api/v1/items/42?access_token=secret HTTP/1.1\r\nHost: upload.example.test\r\nUser-Agent: python-requests/2.32.0\r\nContent-Type: application/json\r\nContent-Length: 8192\r\n\r\n",
        );
        assert_eq!(response_status_line(&response), "HTTP/1.1 204 No Content");

        let _status = wait_for_status(&mut provider, |status| status.requests_captured == 1);
        let completed = provider.drain_completed_runs();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].http_metadata[0].method, HttpMethod::Post);
        assert_eq!(
            completed[0].http_metadata[0].scheme.as_deref(),
            Some("http")
        );
        assert_eq!(completed[0].http_metadata[0].status_code, Some(204));
        assert_eq!(
            completed[0].http_metadata[0].result_label.as_deref(),
            Some(LOCAL_PROXY_CAPTURED_RESULT_LABEL)
        );
        assert_eq!(
            completed[0].http_metadata[0].user_agent_family.as_deref(),
            Some("python_requests")
        );
        assert_eq!(
            completed[0].provenance.redaction_status,
            RedactionStatus::Redacted
        );
        assert!(!completed[0].findings.is_empty());
        assert!(!completed[0].evidence.is_empty());
        assert!(completed[0]
            .emitted_topics
            .iter()
            .any(|topic| topic == "graph.hint"));
        assert!(!completed[0].graph_hints.is_empty());
        assert!(completed[0]
            .graph_hints
            .iter()
            .all(|hint| !hint.evidence_refs.is_empty()));

        let graph_output = run_graph_stage_for_proxy(&completed[0]);
        assert!(graph_output.dead_letters.is_empty());
        assert!(graph_output.accepted_hint_count >= completed[0].graph_hints.len());

        let serialized = serde_json::json!({
            "provenance": &completed[0].provenance,
            "emitted_topics": &completed[0].emitted_topics,
            "flow_records": &completed[0].flow_records,
            "session_records": &completed[0].session_records,
            "http_metadata": &completed[0].http_metadata,
            "findings": &completed[0].findings,
            "evidence": &completed[0].evidence,
            "graph_hints": &completed[0].graph_hints,
            "risk_events": &completed[0].risk_events,
            "alerts": &completed[0].alerts,
            "incidents": &completed[0].incidents,
        })
        .to_string();
        for marker in ["access_token", "secret", "cookie", "payload"] {
            assert!(
                !serialized.contains(marker),
                "serialized runtime leaked forbidden marker {marker}"
            );
        }

        provider.stop().expect("stop proxy");
    }

    #[test]
    fn portable_local_proxy_provider_rejects_oversized_headers_and_unsupported_targets() {
        let mut provider = LocalProxyMetadataProvider::default();
        let start = provider
            .start(LocalProxyMetadataStartRequest::default())
            .expect("start proxy");
        let port = start.listen_port.expect("listen port");

        let oversized_response = send_proxy_request(
            port,
            &format!(
                "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nX-Fill: {}\r\n\r\n",
                "A".repeat(MAX_LOCAL_PROXY_HEADER_BYTES)
            ),
        );
        assert_eq!(
            response_status_line(&oversized_response),
            "HTTP/1.1 431 Request Header Fields Too Large"
        );

        let unsupported_response = send_proxy_request(
            port,
            "GET /relative/path HTTP/1.1\r\nUser-Agent: curl/8.8.0\r\n\r\n",
        );
        assert_eq!(
            response_status_line(&unsupported_response),
            "HTTP/1.1 400 Bad Request"
        );

        let status = wait_for_status(&mut provider, |status| status.requests_rejected >= 2);
        assert_eq!(status.requests_captured, 0);
        assert_eq!(status.requests_rejected, 2);
        assert_eq!(
            status.last_error_code.as_deref(),
            Some(LocalProxyConnectionError::UnsupportedTarget.code())
        );
        assert_eq!(provider.drain_completed_runs().len(), 0);
        provider.stop().expect("stop proxy");
    }

    #[test]
    fn portable_local_proxy_provider_queue_bound_and_backpressure_are_bounded() {
        let mut provider = LocalProxyMetadataProvider::default();
        let start = provider
            .start_with_queue_capacity(LocalProxyMetadataStartRequest::default(), 1)
            .expect("start proxy");
        let port = start.listen_port.expect("listen port");

        let first = send_proxy_request(
            port,
            "POST http://upload.example.test/api/v1/items/42 HTTP/1.1\r\nHost: upload.example.test\r\nContent-Length: 256\r\n\r\n",
        );
        let second = send_proxy_request(
            port,
            "POST http://upload.example.test/api/v1/items/43 HTTP/1.1\r\nHost: upload.example.test\r\nContent-Length: 256\r\n\r\n",
        );

        assert_eq!(response_status_line(&first), "HTTP/1.1 204 No Content");
        assert_eq!(
            response_status_line(&second),
            "HTTP/1.1 503 Service Unavailable"
        );

        let status = wait_for_status(&mut provider, |status| status.dropped_batches == 1);
        assert_eq!(status.requests_captured, 1);
        assert_eq!(status.dropped_batches, 1);
        assert_eq!(status.pending_batches, 1);
        assert!(status.pending_event_count > 0);

        provider.stop().expect("stop proxy");
        assert_eq!(provider.drain_completed_runs().len(), 1);
    }

    #[test]
    fn portable_local_proxy_provider_stop_and_drain_are_idempotent_and_cleanup_port() {
        let mut provider = LocalProxyMetadataProvider::default();
        let start = provider
            .start(LocalProxyMetadataStartRequest::default())
            .expect("start proxy");
        let port = start.listen_port.expect("listen port");

        let response = send_proxy_request(
            port,
            "POST http://upload.example.test/api/v1/items/7 HTTP/1.1\r\nHost: upload.example.test\r\nContent-Length: 128\r\n\r\n",
        );
        assert_eq!(response_status_line(&response), "HTTP/1.1 204 No Content");
        let _ = wait_for_status(&mut provider, |status| status.requests_captured == 1);

        let first_stop = provider.stop().expect("first stop");
        assert!(matches!(
            first_stop.state,
            LocalProxyMetadataProviderStateKind::Stopped
        ));
        assert!(first_stop.pending_event_count > 0);

        let second_stop = provider.stop().expect("second stop");
        assert!(matches!(
            second_stop.state,
            LocalProxyMetadataProviderStateKind::Stopped
        ));
        assert_eq!(
            second_stop.pending_event_count,
            first_stop.pending_event_count
        );

        let drained_once = provider.drain_completed_runs();
        assert_eq!(drained_once.len(), 1);
        let drained_twice = provider.drain_completed_runs();
        assert!(drained_twice.is_empty());
        assert_eq!(provider.status().pending_event_count, 0);

        assert!(TcpStream::connect((LOCAL_PROXY_LISTEN_HOST, port)).is_err());

        let mut restarted = LocalProxyMetadataProvider::default();
        let restart_status = restarted
            .start(LocalProxyMetadataStartRequest {
                listen_port: Some(port),
            })
            .expect("restart on cleaned port");
        assert_eq!(restart_status.listen_port, Some(port));
        restarted.stop().expect("stop restarted proxy");
    }

    #[test]
    fn portable_local_proxy_provider_reports_bind_failures() {
        let listener = TcpListener::bind((LOCAL_PROXY_LISTEN_HOST, 0)).expect("reserve port");
        let occupied_port = listener.local_addr().expect("listener addr").port();
        let mut provider = LocalProxyMetadataProvider::default();

        let error = provider
            .start(LocalProxyMetadataStartRequest {
                listen_port: Some(occupied_port),
            })
            .expect_err("occupied port should fail");

        assert_eq!(error, LocalProxyMetadataProviderError::BindFailed);
        drop(listener);
    }

    #[test]
    fn local_proxy_connection_reports_metadata_pipeline_failure_when_queue_disconnects() {
        let listener = TcpListener::bind((LOCAL_PROXY_LISTEN_HOST, 0)).expect("listener");
        let addr = listener.local_addr().expect("listener addr");
        let client = thread::spawn(move || {
            send_proxy_request(
                addr.port(),
                "POST http://upload.example.test/api/v1/items/99 HTTP/1.1\r\nHost: upload.example.test\r\nContent-Length: 128\r\n\r\n",
            )
        });
        let (mut server_stream, peer_addr) = listener.accept().expect("accept");
        let stats = Arc::new(Mutex::new(LocalProxyMetadataProviderStats::default()));
        let (tx, rx) = mpsc::sync_channel(1);
        drop(rx);

        handle_local_proxy_connection(&mut server_stream, peer_addr, &stats, &tx);

        let response = client.join().expect("client join");
        assert_eq!(
            response_status_line(&response),
            "HTTP/1.1 503 Service Unavailable"
        );
        let snapshot = stats.lock().expect("stats").clone();
        assert_eq!(snapshot.requests_rejected, 1);
        assert_eq!(
            snapshot.last_error_code.as_deref(),
            Some(LocalProxyConnectionError::MetadataPipelineFailed.code())
        );
    }
}
