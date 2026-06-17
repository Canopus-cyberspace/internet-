//! Bounded Windows Event Log authentication and remote-access source adapter.
//!
//! The adapter owns only Windows Event Log handles, bounded queues, counters,
//! cursors, and privacy-safe normalization. It does not own EventBus, DAG,
//! PluginRuntime, RuntimeContainer, read models, or detectors.

use crate::provider_adapter::{
    ProviderAdapterMetadata, ProviderAdapterOwnership, ProviderProbe,
    PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
};
use sentinel_contracts::{
    NetworkProviderKind, PortableAuthAttemptCountBucket, QualityScore, RedactionStatus, Timestamp,
    WindowsAuthAccountCategory, WindowsAuthFailureCategory, WindowsAuthFreshnessCategory,
    WindowsAuthMechanismCategory, WindowsAuthObservedBucket, WindowsAuthPrivilegeBucket,
    WindowsAuthRemoteCounters, WindowsAuthRemoteEventId, WindowsAuthRemoteObservation,
    WindowsAuthRemoteObservationBatch, WindowsAuthResultCategory, WindowsAuthSchemaCategory,
    WindowsAuthSourceReliability, WindowsRemoteProtocolCategory,
    WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const WINDOWS_AUTH_REMOTE_EVENT_LOG_ADAPTER_ID: &str = "windows_auth_remote_event_log_adapter";
pub const WINDOWS_AUTH_REMOTE_ALLOWLIST_REF: &str = "windows_security_auth_event_allowlist_v1";
pub const WINDOWS_AUTH_REMOTE_RAW_QUEUE_CAPACITY: usize = 512;
pub const WINDOWS_AUTH_REMOTE_BATCH_QUEUE_CAPACITY: usize = 16;
pub const WINDOWS_AUTH_REMOTE_MAX_EVENTS_PER_SECOND: u32 = 512;
pub const WINDOWS_AUTH_REMOTE_MAX_DRAIN_BATCHES: usize = 16;
pub const WINDOWS_AUTH_REMOTE_BATCH_SIZE: usize = 64;
const WINDOWS_AUTH_REMOTE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const WINDOWS_AUTH_REMOTE_EVENTLOG_TIMEOUT_MS: u32 = 100;
const WINDOWS_AUTH_REMOTE_QUERY_LIMIT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsAuthRemoteControlState {
    Inactive,
    Active,
    Paused,
    Stopped,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WindowsAuthRemoteEventLogOutcome {
    pub state: WindowsAuthRemoteControlState,
    pub provider_enabled: bool,
    pub channels_ready: u32,
    pub channels_unavailable: u32,
    pub collection_started: bool,
    pub consumer_started: bool,
    pub consumer_worker_active: bool,
    pub consumer_worker_joined: bool,
    pub raw_events_observed: u32,
    pub schema_accepted: u32,
    pub schema_rejected: u32,
    pub malformed_events: u32,
    pub rate_limited_events: u32,
    pub queue_dropped_events: u32,
    pub duplicate_suppressed_events: u32,
    pub normalized_auth_observations: u32,
    pub normalized_remote_access_observations: u32,
    pub bookmark_updates: u32,
    pub record_gaps: u32,
    pub normalized_batches: Vec<WindowsAuthRemoteObservationBatch>,
    pub cursor_ref: Option<String>,
    pub degraded_reason: Option<String>,
}

pub trait WindowsAuthRemoteEventLogControl: Send {
    fn start(&mut self)
        -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError>;
    fn pause(&mut self)
        -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError>;
    fn resume(
        &mut self,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError>;
    fn stop(&mut self) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError>;
    fn drain_normalized_batches(
        &mut self,
        max_batches: usize,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError>;
}

pub struct WindowsAuthRemoteEventLogAdapter {
    state: WindowsAuthRemoteControlState,
    #[cfg(windows)]
    active_session: Option<WindowsAuthRemoteEventLogSession>,
}

impl WindowsAuthRemoteEventLogAdapter {
    pub fn new() -> Self {
        Self {
            state: WindowsAuthRemoteControlState::Inactive,
            #[cfg(windows)]
            active_session: None,
        }
    }

    fn inactive_outcome(state: WindowsAuthRemoteControlState) -> WindowsAuthRemoteEventLogOutcome {
        WindowsAuthRemoteEventLogOutcome {
            state,
            provider_enabled: false,
            channels_ready: 0,
            channels_unavailable: 0,
            collection_started: false,
            consumer_started: false,
            consumer_worker_active: false,
            consumer_worker_joined: matches!(
                state,
                WindowsAuthRemoteControlState::Paused | WindowsAuthRemoteControlState::Stopped
            ),
            raw_events_observed: 0,
            schema_accepted: 0,
            schema_rejected: 0,
            malformed_events: 0,
            rate_limited_events: 0,
            queue_dropped_events: 0,
            duplicate_suppressed_events: 0,
            normalized_auth_observations: 0,
            normalized_remote_access_observations: 0,
            bookmark_updates: 0,
            record_gaps: 0,
            normalized_batches: Vec::new(),
            cursor_ref: None,
            degraded_reason: None,
        }
    }
}

impl Default for WindowsAuthRemoteEventLogAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderProbe for WindowsAuthRemoteEventLogAdapter {
    fn adapter_metadata(&self) -> ProviderAdapterMetadata {
        ProviderAdapterMetadata {
            adapter_id: WINDOWS_AUTH_REMOTE_EVENT_LOG_ADAPTER_ID.to_string(),
            provider_kind: NetworkProviderKind::WindowsAuthRemote,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            ownership: ProviderAdapterOwnership::infrastructure_adapter(),
            supported_request_refs: vec![
                "explicit_windows_auth_remote_lifecycle_request".to_string()
            ],
            supported_result_refs: vec!["bounded_windows_auth_remote_batch_result".to_string()],
            privacy_notes: vec![
                "security_channel_allowlist_only".to_string(),
                "event_xml_transient".to_string(),
                "bounded_polling_cursor_no_overlap".to_string(),
                "subject_source_target_values_hashed_or_bucketed".to_string(),
                "no_sensitive_host_identity_retention".to_string(),
            ],
            redaction_status: RedactionStatus::Redacted,
        }
    }
}

impl WindowsAuthRemoteEventLogControl for WindowsAuthRemoteEventLogAdapter {
    fn start(
        &mut self,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
        if self.state == WindowsAuthRemoteControlState::Active {
            #[cfg(windows)]
            return self
                .active_session
                .as_mut()
                .map(WindowsAuthRemoteEventLogSession::outcome)
                .unwrap_or_else(|| Ok(Self::inactive_outcome(self.state)));
            #[cfg(not(windows))]
            return Ok(Self::inactive_outcome(self.state));
        }
        #[cfg(windows)]
        {
            let mut session = WindowsAuthRemoteEventLogSession::start()?;
            let outcome = session.outcome()?;
            self.active_session = Some(session);
            self.state = WindowsAuthRemoteControlState::Active;
            Ok(outcome)
        }
        #[cfg(not(windows))]
        {
            self.state = WindowsAuthRemoteControlState::Unavailable;
            Err(WindowsAuthRemoteEventLogError::new(
                "windows_event_log_auth_remote_unsupported_platform",
            ))
        }
    }

    fn pause(
        &mut self,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
        #[cfg(windows)]
        if let Some(session) = self.active_session.as_mut() {
            session.set_paused(true);
            self.state = WindowsAuthRemoteControlState::Paused;
            return session.outcome_for_state(self.state);
        }
        self.state = WindowsAuthRemoteControlState::Paused;
        Ok(Self::inactive_outcome(self.state))
    }

    fn resume(
        &mut self,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
        #[cfg(windows)]
        if let Some(session) = self.active_session.as_mut() {
            session.set_paused(false);
            self.state = WindowsAuthRemoteControlState::Active;
            return session.outcome_for_state(self.state);
        }
        self.start()
    }

    fn stop(&mut self) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
        if self.state == WindowsAuthRemoteControlState::Stopped {
            return Ok(Self::inactive_outcome(self.state));
        }
        #[cfg(windows)]
        if let Some(mut session) = self.active_session.take() {
            let outcome = session.stop()?;
            self.state = WindowsAuthRemoteControlState::Stopped;
            return Ok(outcome);
        }
        self.state = WindowsAuthRemoteControlState::Stopped;
        Ok(Self::inactive_outcome(self.state))
    }

    fn drain_normalized_batches(
        &mut self,
        max_batches: usize,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
        #[cfg(windows)]
        if let Some(session) = self.active_session.as_mut() {
            return session.drain_normalized_batches(max_batches);
        }
        Ok(Self::inactive_outcome(self.state))
    }
}

impl Drop for WindowsAuthRemoteEventLogAdapter {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsAuthRemoteEventLogError {
    pub reason_redacted: String,
}

impl WindowsAuthRemoteEventLogError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason_redacted: sanitize_reason(reason.into()),
        }
    }
}

impl std::fmt::Display for WindowsAuthRemoteEventLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason_redacted)
    }
}

impl std::error::Error for WindowsAuthRemoteEventLogError {}

#[derive(Clone, Debug)]
struct AuthRemoteTransientEvent {
    record_id: u64,
    event_id: u16,
    version: u8,
    logon_type: Option<u32>,
    auth_package: Option<String>,
    status_code: Option<String>,
    target_user: Option<String>,
    target_domain: Option<String>,
    source_value: Option<String>,
    system_time: Option<String>,
}

#[derive(Default)]
struct AuthRemoteMetrics {
    raw_events_observed: AtomicU32,
    schema_accepted: AtomicU32,
    schema_rejected: AtomicU32,
    malformed_events: AtomicU32,
    rate_limited_events: AtomicU32,
    queue_dropped_events: AtomicU32,
    duplicate_suppressed_events: AtomicU32,
    normalized_auth_observations: AtomicU32,
    normalized_remote_access_observations: AtomicU32,
    bookmark_updates: AtomicU32,
    record_gaps: AtomicU32,
    rate_window_second: AtomicU64,
    rate_window_count: AtomicU32,
    last_record_id: AtomicU64,
    worker_active: AtomicBool,
    normalizer_active: AtomicBool,
    channels_ready: AtomicU32,
    channels_unavailable: AtomicU32,
}

impl AuthRemoteMetrics {
    fn workers_active(&self) -> bool {
        self.worker_active.load(Ordering::SeqCst) || self.normalizer_active.load(Ordering::SeqCst)
    }
}

#[cfg(windows)]
struct WindowsAuthRemoteEventLogSession {
    batch_receiver: Receiver<WindowsAuthRemoteObservationBatch>,
    metrics: Arc<AuthRemoteMetrics>,
    cancellation: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    reader_thread: Option<JoinHandle<()>>,
    normalizer_thread: Option<JoinHandle<()>>,
    stopped: bool,
}

#[cfg(windows)]
impl WindowsAuthRemoteEventLogSession {
    fn start() -> Result<Self, WindowsAuthRemoteEventLogError> {
        let metrics = Arc::new(AuthRemoteMetrics::default());
        let cancellation = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let (raw_sender, raw_receiver) = mpsc::sync_channel(WINDOWS_AUTH_REMOTE_RAW_QUEUE_CAPACITY);
        let (batch_sender, batch_receiver) =
            mpsc::sync_channel(WINDOWS_AUTH_REMOTE_BATCH_QUEUE_CAPACITY);

        let reader_metrics = Arc::clone(&metrics);
        let reader_cancel = Arc::clone(&cancellation);
        let reader_paused = Arc::clone(&paused);
        let reader_thread = thread::spawn(move || {
            reader_metrics.worker_active.store(true, Ordering::SeqCst);
            run_event_log_reader(raw_sender, reader_metrics, reader_cancel, reader_paused);
        });

        let normalizer_metrics = Arc::clone(&metrics);
        let normalizer_cancel = Arc::clone(&cancellation);
        let normalizer_thread = thread::spawn(move || {
            normalizer_metrics
                .normalizer_active
                .store(true, Ordering::SeqCst);
            run_event_log_normalizer(
                raw_receiver,
                batch_sender,
                normalizer_metrics,
                normalizer_cancel,
            );
        });

        let session = Self {
            batch_receiver,
            metrics,
            cancellation,
            paused,
            reader_thread: Some(reader_thread),
            normalizer_thread: Some(normalizer_thread),
            stopped: false,
        };
        Ok(session)
    }

    fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
    }

    fn outcome(
        &mut self,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
        self.outcome_for_state(WindowsAuthRemoteControlState::Active)
    }

    fn outcome_for_state(
        &mut self,
        state: WindowsAuthRemoteControlState,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
        let mut batches = Vec::new();
        while let Ok(batch) = self.batch_receiver.try_recv() {
            batches.push(batch);
            if batches.len() >= WINDOWS_AUTH_REMOTE_MAX_DRAIN_BATCHES {
                break;
            }
        }
        Ok(outcome_from_metrics(
            state,
            &self.metrics,
            batches,
            self.stopped,
        ))
    }

    fn drain_normalized_batches(
        &mut self,
        max_batches: usize,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
        let mut batches = Vec::new();
        for _ in 0..max_batches.min(WINDOWS_AUTH_REMOTE_MAX_DRAIN_BATCHES) {
            match self.batch_receiver.try_recv() {
                Ok(batch) => batches.push(batch),
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
        Ok(outcome_from_metrics(
            WindowsAuthRemoteControlState::Active,
            &self.metrics,
            batches,
            self.stopped,
        ))
    }

    fn stop(&mut self) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
        self.cancellation.store(true, Ordering::SeqCst);
        self.paused.store(false, Ordering::SeqCst);
        let reader_joined = self
            .reader_thread
            .take()
            .is_none_or(|handle| handle.join().is_ok());
        let normalizer_joined = self
            .normalizer_thread
            .take()
            .is_none_or(|handle| handle.join().is_ok());
        self.stopped = true;
        let mut outcome = outcome_from_metrics(
            WindowsAuthRemoteControlState::Stopped,
            &self.metrics,
            Vec::new(),
            true,
        );
        outcome.consumer_worker_joined =
            reader_joined && normalizer_joined && !self.metrics.workers_active();
        outcome.consumer_worker_active = false;
        outcome.collection_started = false;
        outcome.consumer_started = false;
        outcome.provider_enabled = false;
        outcome.degraded_reason = if outcome.consumer_worker_joined {
            Some("windows_auth_remote_event_log_stopped".to_string())
        } else {
            Some("windows_auth_remote_event_log_join_failed".to_string())
        };
        if !outcome.consumer_worker_joined {
            return Err(WindowsAuthRemoteEventLogError::new(
                "windows_auth_remote_event_log_join_failed",
            ));
        }
        Ok(outcome)
    }
}

#[cfg(windows)]
impl Drop for WindowsAuthRemoteEventLogSession {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.stop();
        }
    }
}

#[cfg(windows)]
fn run_event_log_reader(
    sender: SyncSender<AuthRemoteTransientEvent>,
    metrics: Arc<AuthRemoteMetrics>,
    cancellation: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) {
    while !cancellation.load(Ordering::SeqCst) {
        if paused.load(Ordering::SeqCst) {
            thread::sleep(WINDOWS_AUTH_REMOTE_POLL_INTERVAL);
            continue;
        }
        let result = poll_security_events_once(&sender, &metrics);
        if let Err(error) = result {
            metrics.channels_unavailable.fetch_add(1, Ordering::Relaxed);
            let _ = error;
            thread::sleep(WINDOWS_AUTH_REMOTE_POLL_INTERVAL);
        }
        thread::sleep(WINDOWS_AUTH_REMOTE_POLL_INTERVAL);
    }
    metrics.worker_active.store(false, Ordering::SeqCst);
}

#[cfg(windows)]
fn run_event_log_normalizer(
    receiver: Receiver<AuthRemoteTransientEvent>,
    sender: SyncSender<WindowsAuthRemoteObservationBatch>,
    metrics: Arc<AuthRemoteMetrics>,
    cancellation: Arc<AtomicBool>,
) {
    let mut pending = Vec::with_capacity(WINDOWS_AUTH_REMOTE_BATCH_SIZE);
    let mut cohort_counts = BTreeMap::<String, u32>::new();
    while !cancellation.load(Ordering::SeqCst) {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(transient) => {
                if let Some(observation) =
                    normalize_transient_auth_event(transient, &mut cohort_counts)
                {
                    if matches!(
                        observation.remote_protocol_category,
                        Some(
                            WindowsRemoteProtocolCategory::Rdp
                                | WindowsRemoteProtocolCategory::Smb
                                | WindowsRemoteProtocolCategory::Ssh
                                | WindowsRemoteProtocolCategory::Network
                        )
                    ) {
                        metrics
                            .normalized_remote_access_observations
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    metrics
                        .normalized_auth_observations
                        .fetch_add(1, Ordering::Relaxed);
                    pending.push(observation);
                } else {
                    metrics.schema_rejected.fetch_add(1, Ordering::Relaxed);
                }
                if pending.len() >= WINDOWS_AUTH_REMOTE_BATCH_SIZE {
                    flush_auth_remote_batch(&mut pending, &sender, &metrics);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !pending.is_empty() {
                    flush_auth_remote_batch(&mut pending, &sender, &metrics);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if !pending.is_empty() {
        flush_auth_remote_batch(&mut pending, &sender, &metrics);
    }
    metrics.normalizer_active.store(false, Ordering::SeqCst);
}

#[cfg(windows)]
fn flush_auth_remote_batch(
    pending: &mut Vec<WindowsAuthRemoteObservation>,
    sender: &SyncSender<WindowsAuthRemoteObservationBatch>,
    metrics: &AuthRemoteMetrics,
) {
    let observations = std::mem::take(pending);
    let counters = counters_from_metrics(metrics, false);
    let batch = WindowsAuthRemoteObservationBatch {
        batch_ref: format!(
            "windows_auth_remote_batch_{}",
            hashed_ref("batch", &format!("{:?}", Timestamp::now()))
        ),
        provider_ref: "windows_auth_remote_event_log".to_string(),
        schema_version: WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
        observations,
        counters,
        cursor_ref: Some(cursor_ref(metrics.last_record_id.load(Ordering::Relaxed))),
        channel_refs: vec!["security_log".to_string()],
        degraded_reason: Some("existing_host_events_or_live_security_log".to_string()),
        generated_at: Timestamp::now(),
        redaction_status: RedactionStatus::Redacted,
    };
    if batch.validate().is_err() {
        metrics.malformed_events.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if sender.try_send(batch).is_err() {
        metrics.queue_dropped_events.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(windows)]
fn poll_security_events_once(
    sender: &SyncSender<AuthRemoteTransientEvent>,
    metrics: &AuthRemoteMetrics,
) -> Result<(), WindowsAuthRemoteEventLogError> {
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS,
    };
    use windows_sys::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtRender,
        EvtRenderEventXml, EVT_HANDLE,
    };

    let channel = wide_null("Security");
    let query_text = security_query(metrics.last_record_id.load(Ordering::Relaxed));
    let query_wide = wide_null(&query_text);
    let query = unsafe {
        EvtQuery(
            0,
            channel.as_ptr(),
            query_wide.as_ptr(),
            EvtQueryChannelPath | EvtQueryForwardDirection,
        )
    };
    if query == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsAuthRemoteEventLogError::new(format!(
            "windows_event_log_query_error_{code}"
        )));
    }
    metrics.channels_ready.store(1, Ordering::Relaxed);
    let mut read_count = 0_usize;
    loop {
        let mut events: [EVT_HANDLE; 8] = [0; 8];
        let mut returned = 0_u32;
        let ok = unsafe {
            EvtNext(
                query,
                events.len() as u32,
                events.as_mut_ptr(),
                WINDOWS_AUTH_REMOTE_EVENTLOG_TIMEOUT_MS,
                0,
                &mut returned,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_ITEMS {
                break;
            }
            unsafe {
                EvtClose(query);
            }
            return Err(WindowsAuthRemoteEventLogError::new(format!(
                "windows_event_log_next_error_{code}"
            )));
        }
        for handle in events.iter().take(returned as usize).copied() {
            if handle == 0 {
                continue;
            }
            let rendered = render_event_xml(
                handle,
                EvtRender,
                EvtRenderEventXml,
                ERROR_INSUFFICIENT_BUFFER,
            );
            unsafe {
                EvtClose(handle);
            }
            match rendered {
                Ok(xml) => {
                    metrics.raw_events_observed.fetch_add(1, Ordering::Relaxed);
                    if !rate_limit_allows(metrics) {
                        metrics.rate_limited_events.fetch_add(1, Ordering::Relaxed);
                        metrics.queue_dropped_events.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    match parse_transient_auth_event_xml(&xml) {
                        Some(transient)
                            if schema_allowed(transient.event_id, transient.version) =>
                        {
                            let previous = metrics.last_record_id.load(Ordering::Relaxed);
                            if transient.record_id <= previous && previous != 0 {
                                metrics
                                    .duplicate_suppressed_events
                                    .fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            if previous != 0
                                && transient.record_id > previous.saturating_add(10_000)
                            {
                                metrics.record_gaps.fetch_add(1, Ordering::Relaxed);
                            }
                            metrics
                                .last_record_id
                                .store(transient.record_id, Ordering::Relaxed);
                            metrics.bookmark_updates.fetch_add(1, Ordering::Relaxed);
                            metrics.schema_accepted.fetch_add(1, Ordering::Relaxed);
                            if matches!(sender.try_send(transient), Err(TrySendError::Full(_))) {
                                metrics.queue_dropped_events.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Some(_) => {
                            metrics.schema_rejected.fetch_add(1, Ordering::Relaxed);
                        }
                        None => {
                            metrics.malformed_events.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(_) => {
                    metrics.malformed_events.fetch_add(1, Ordering::Relaxed);
                }
            }
            read_count += 1;
            if read_count >= WINDOWS_AUTH_REMOTE_QUERY_LIMIT {
                unsafe {
                    EvtClose(query);
                }
                return Ok(());
            }
        }
    }
    unsafe {
        EvtClose(query);
    }
    Ok(())
}

#[cfg(windows)]
fn render_event_xml(
    handle: isize,
    render_fn: unsafe extern "system" fn(
        isize,
        isize,
        u32,
        u32,
        *mut core::ffi::c_void,
        *mut u32,
        *mut u32,
    ) -> i32,
    render_flag: u32,
    insufficient_buffer: u32,
) -> Result<String, WindowsAuthRemoteEventLogError> {
    use windows_sys::Win32::Foundation::GetLastError;

    let mut buffer_used = 0_u32;
    let mut property_count = 0_u32;
    let first = unsafe {
        render_fn(
            0,
            handle,
            render_flag,
            0,
            std::ptr::null_mut(),
            &mut buffer_used,
            &mut property_count,
        )
    };
    if first == 0 {
        let code = unsafe { GetLastError() };
        if code != insufficient_buffer {
            return Err(WindowsAuthRemoteEventLogError::new(format!(
                "windows_event_log_render_probe_error_{code}"
            )));
        }
    }
    if buffer_used == 0 || buffer_used > 256 * 1024 {
        return Err(WindowsAuthRemoteEventLogError::new(
            "windows_event_log_render_size_invalid",
        ));
    }
    let mut buffer = vec![0_u8; buffer_used as usize];
    let ok = unsafe {
        render_fn(
            0,
            handle,
            render_flag,
            buffer_used,
            buffer.as_mut_ptr().cast(),
            &mut buffer_used,
            &mut property_count,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsAuthRemoteEventLogError::new(format!(
            "windows_event_log_render_error_{code}"
        )));
    }
    let units = buffer
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    Ok(String::from_utf16_lossy(&units))
}

fn security_query(last_record_id: u64) -> String {
    let event_filter =
        "(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4740 or EventID=4768 or EventID=4769 or EventID=4771 or EventID=4776 or EventID=4634)";
    if last_record_id > 0 {
        format!("*[System[{event_filter} and EventRecordID>{last_record_id}]]")
    } else {
        format!("*[System[{event_filter} and TimeCreated[timediff(@SystemTime) <= 90000]]]")
    }
}

fn parse_transient_auth_event_xml(xml: &str) -> Option<AuthRemoteTransientEvent> {
    let event_id = tag_text(xml, "EventID")?.parse::<u16>().ok()?;
    let version = tag_text(xml, "Version")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0);
    let record_id = tag_text(xml, "EventRecordID")?.parse::<u64>().ok()?;
    let logon_type = data_name(xml, "LogonType").and_then(|value| value.parse::<u32>().ok());
    let auth_package = first_data_name(xml, &["AuthenticationPackageName", "PackageName"]);
    let status_code = first_data_name(xml, &["Status", "SubStatus"]);
    let target_user = first_data_name(xml, &["TargetUserName", "AccountName"]);
    let target_domain = first_data_name(xml, &["TargetDomainName", "AccountDomain"]);
    let source_value = first_data_name(xml, &["IpAddress", "WorkstationName", "Workstation"]);
    let system_time = attribute_value(xml, "TimeCreated", "SystemTime");
    Some(AuthRemoteTransientEvent {
        record_id,
        event_id,
        version,
        logon_type,
        auth_package,
        status_code,
        target_user,
        target_domain,
        source_value,
        system_time,
    })
}

fn normalize_transient_auth_event(
    transient: AuthRemoteTransientEvent,
    cohort_counts: &mut BTreeMap<String, u32>,
) -> Option<WindowsAuthRemoteObservation> {
    let schema_category = schema_category(transient.event_id, transient.version)?;
    let event_category = event_category(transient.event_id);
    let auth_result = auth_result_category(transient.event_id);
    let auth_mechanism = auth_mechanism(transient.auth_package.as_deref(), transient.event_id);
    let account_category = account_category(
        transient.target_user.as_deref(),
        transient.target_domain.as_deref(),
    );
    let remote_protocol_category = remote_protocol_category(transient.logon_type);
    let failure_category = failure_category(transient.status_code.as_deref(), transient.event_id);
    let identity_ref = transient.target_user.as_deref().map(|user| {
        hashed_ref(
            "acct",
            &format!(
                "{}|{}",
                transient.target_domain.as_deref().unwrap_or(""),
                user
            ),
        )
    });
    let source_ref = transient
        .source_value
        .as_deref()
        .filter(|value| !value.trim().is_empty() && *value != "-")
        .map(|value| hashed_ref("source", value));
    let target_ref = Some("target_scope_local_system".to_string());
    let cohort_key = format!(
        "{}|{}|{}",
        identity_ref.as_deref().unwrap_or("identity_unknown"),
        source_ref.as_deref().unwrap_or("source_unknown"),
        remote_protocol_category
            .map(|category| format!("{category:?}"))
            .unwrap_or_else(|| "protocol_unknown".to_string())
    );
    let count = cohort_counts.entry(cohort_key).or_insert(0);
    *count = count.saturating_add(1);
    let repeated_failure_bucket = if auth_result == WindowsAuthResultCategory::Failure {
        Some(match *count {
            0 | 1 => PortableAuthAttemptCountBucket::One,
            2..=4 => PortableAuthAttemptCountBucket::Few,
            5..=12 => PortableAuthAttemptCountBucket::Burst,
            _ => PortableAuthAttemptCountBucket::Many,
        })
    } else {
        None
    };
    let observation = WindowsAuthRemoteObservation {
        observation_ref: hashed_ref("auth_obs", &format!("{}", transient.record_id)),
        event_category,
        schema_category,
        event_version: transient.version,
        auth_result,
        auth_mechanism,
        account_category,
        privilege_bucket: privilege_bucket(transient.event_id, account_category),
        remote_protocol_category,
        failure_category,
        repeated_failure_bucket,
        success_after_failure: auth_result == WindowsAuthResultCategory::Success && *count > 1,
        identity_ref,
        source_ref,
        target_ref,
        observed_bucket: WindowsAuthObservedBucket::ExistingHostEvents,
        source_reliability: WindowsAuthSourceReliability::SecurityLogVerified,
        freshness: freshness(transient.system_time.as_deref()),
        provenance_ref: "windows_event_log_security".to_string(),
        missing_visibility: vec!["raw_subject_source_target_discarded".to_string()],
        time_bucket_start: Timestamp::now(),
        redaction_status: RedactionStatus::Hashed,
        quality_score: QualityScore::new(0.72).ok()?,
    };
    observation.validate().ok()?;
    Some(observation)
}

fn schema_allowed(event_id: u16, version: u8) -> bool {
    schema_category(event_id, version).is_some()
}

fn schema_category(event_id: u16, version: u8) -> Option<WindowsAuthSchemaCategory> {
    match (event_id, version) {
        (4624, 0) => Some(WindowsAuthSchemaCategory::Security4624V0),
        (4624, 1) => Some(WindowsAuthSchemaCategory::Security4624V1),
        (4624, 2) => Some(WindowsAuthSchemaCategory::Security4624V2),
        (4625, 0) => Some(WindowsAuthSchemaCategory::Security4625V0),
        (4625, 1) => Some(WindowsAuthSchemaCategory::Security4625V1),
        (4648, 0) => Some(WindowsAuthSchemaCategory::Security4648V0),
        (4672, 0) => Some(WindowsAuthSchemaCategory::Security4672V0),
        (4740, 0) => Some(WindowsAuthSchemaCategory::Security4740V0),
        (4768, 0) => Some(WindowsAuthSchemaCategory::Security4768V0),
        (4769, 0) => Some(WindowsAuthSchemaCategory::Security4769V0),
        (4771, 0) => Some(WindowsAuthSchemaCategory::Security4771V0),
        (4776, 0) => Some(WindowsAuthSchemaCategory::Security4776V0),
        (4634, 0) => Some(WindowsAuthSchemaCategory::Security4634V0),
        _ => None,
    }
}

fn event_category(event_id: u16) -> WindowsAuthRemoteEventId {
    match event_id {
        4624 => WindowsAuthRemoteEventId::SuccessfulLogon,
        4625 => WindowsAuthRemoteEventId::FailedLogon,
        4648 => WindowsAuthRemoteEventId::ExplicitCredentialUse,
        4672 => WindowsAuthRemoteEventId::SpecialPrivilegesAssigned,
        4740 => WindowsAuthRemoteEventId::AccountLockout,
        4768 => WindowsAuthRemoteEventId::KerberosPreauthFailure,
        4769 => WindowsAuthRemoteEventId::KerberosServiceTicket,
        4771 => WindowsAuthRemoteEventId::KerberosPreauthFailure,
        4776 => WindowsAuthRemoteEventId::NtlmFailure,
        4634 => WindowsAuthRemoteEventId::Logoff,
        _ => WindowsAuthRemoteEventId::Unknown,
    }
}

fn auth_result_category(event_id: u16) -> WindowsAuthResultCategory {
    match event_id {
        4624 | 4648 => WindowsAuthResultCategory::Success,
        4672 => WindowsAuthResultCategory::PrivilegedSuccess,
        4740 => WindowsAuthResultCategory::Lockout,
        4634 => WindowsAuthResultCategory::Logoff,
        4625 | 4771 | 4776 => WindowsAuthResultCategory::Failure,
        4768 | 4769 => WindowsAuthResultCategory::Unknown,
        _ => WindowsAuthResultCategory::Unknown,
    }
}

fn auth_mechanism(package: Option<&str>, event_id: u16) -> WindowsAuthMechanismCategory {
    if matches!(event_id, 4768 | 4769 | 4771) {
        return WindowsAuthMechanismCategory::Kerberos;
    }
    if event_id == 4776 {
        return WindowsAuthMechanismCategory::Ntlm;
    }
    let package = package.unwrap_or_default().to_ascii_lowercase();
    if package.contains("kerberos") {
        WindowsAuthMechanismCategory::Kerberos
    } else if package.contains("ntlm") {
        WindowsAuthMechanismCategory::Ntlm
    } else if package.contains("negotiate") {
        WindowsAuthMechanismCategory::Negotiate
    } else if package.contains("explicit") {
        WindowsAuthMechanismCategory::ExplicitCredential
    } else {
        WindowsAuthMechanismCategory::Unknown
    }
}

fn account_category(user: Option<&str>, domain: Option<&str>) -> WindowsAuthAccountCategory {
    let user = user.unwrap_or_default().to_ascii_lowercase();
    let domain = domain.unwrap_or_default().to_ascii_lowercase();
    if user.contains("anonymous") {
        WindowsAuthAccountCategory::Anonymous
    } else if user.ends_with('$') {
        WindowsAuthAccountCategory::Machine
    } else if user.contains("admin") {
        WindowsAuthAccountCategory::AdminLike
    } else if domain == "nt authority" || domain == "window manager" {
        WindowsAuthAccountCategory::Service
    } else if domain.is_empty() || domain == "." {
        WindowsAuthAccountCategory::LocalUser
    } else {
        WindowsAuthAccountCategory::DomainUser
    }
}

fn privilege_bucket(
    event_id: u16,
    account_category: WindowsAuthAccountCategory,
) -> WindowsAuthPrivilegeBucket {
    if event_id == 4672 {
        WindowsAuthPrivilegeBucket::SpecialPrivileges
    } else if account_category == WindowsAuthAccountCategory::AdminLike {
        WindowsAuthPrivilegeBucket::Elevated
    } else {
        WindowsAuthPrivilegeBucket::Standard
    }
}

fn remote_protocol_category(logon_type: Option<u32>) -> Option<WindowsRemoteProtocolCategory> {
    match logon_type {
        Some(2) | Some(7) | Some(11) => Some(WindowsRemoteProtocolCategory::LocalInteractive),
        Some(3) => Some(WindowsRemoteProtocolCategory::Network),
        Some(4) => Some(WindowsRemoteProtocolCategory::ScheduledTask),
        Some(5) => Some(WindowsRemoteProtocolCategory::Service),
        Some(10) => Some(WindowsRemoteProtocolCategory::Rdp),
        _ => None,
    }
}

fn failure_category(status: Option<&str>, event_id: u16) -> Option<WindowsAuthFailureCategory> {
    if !matches!(event_id, 4625 | 4740 | 4771 | 4776) {
        return None;
    }
    let status = status.unwrap_or_default().to_ascii_lowercase();
    Some(match status.as_str() {
        "0xc000006a" | "0xc000006d" | "0xc000006f" => WindowsAuthFailureCategory::BadSecret,
        "0xc0000064" => WindowsAuthFailureCategory::UnknownIdentity,
        "0xc0000234" | "0xc0000072" => WindowsAuthFailureCategory::LockedOut,
        "0xc0000071" => WindowsAuthFailureCategory::Expired,
        "0xc000015b" | "0xc0000413" => WindowsAuthFailureCategory::NotAllowed,
        "0x18" | "0x19" => WindowsAuthFailureCategory::TimeSkew,
        "" => WindowsAuthFailureCategory::MissingVisibility,
        _ => WindowsAuthFailureCategory::Unknown,
    })
}

fn freshness(system_time: Option<&str>) -> WindowsAuthFreshnessCategory {
    let Some(value) = system_time else {
        return WindowsAuthFreshnessCategory::Unknown;
    };
    if value.is_empty() {
        WindowsAuthFreshnessCategory::Unknown
    } else {
        WindowsAuthFreshnessCategory::Recent
    }
}

fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let start = format!("<{tag}>");
    let end = format!("</{tag}>");
    let start_index = xml.find(&start)? + start.len();
    let end_index = xml[start_index..].find(&end)? + start_index;
    Some(xml[start_index..end_index].trim().to_string())
}

fn data_name(xml: &str, name: &str) -> Option<String> {
    let marker1 = format!("Name='{name}'");
    let marker2 = format!("Name=\"{name}\"");
    let marker_index = xml.find(&marker1).or_else(|| xml.find(&marker2))?;
    let close = xml[marker_index..].find('>')? + marker_index + 1;
    let end = xml[close..].find("</Data>")? + close;
    Some(unescape_xml(&xml[close..end]))
}

fn first_data_name(xml: &str, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| data_name(xml, name))
}

fn attribute_value(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_index = xml.find(&format!("<{tag}"))?;
    let tag_end = xml[tag_index..].find('>')? + tag_index;
    let slice = &xml[tag_index..tag_end];
    let marker1 = format!("{attr}='");
    let marker2 = format!("{attr}=\"");
    let marker = if slice.contains(&marker1) {
        marker1
    } else {
        marker2
    };
    let start = slice.find(&marker)? + marker.len();
    let quote = if marker.ends_with('\'') { '\'' } else { '"' };
    let end = slice[start..].find(quote)? + start;
    Some(slice[start..end].to_string())
}

fn unescape_xml(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .trim()
        .to_string()
}

fn counters_from_metrics(
    metrics: &AuthRemoteMetrics,
    worker_joined: bool,
) -> WindowsAuthRemoteCounters {
    WindowsAuthRemoteCounters {
        provider_enabled: if metrics.channels_ready.load(Ordering::Relaxed) > 0 {
            1
        } else {
            0
        },
        channels_ready: metrics.channels_ready.load(Ordering::Relaxed),
        channels_unavailable: metrics.channels_unavailable.load(Ordering::Relaxed),
        raw_events_observed: metrics.raw_events_observed.load(Ordering::Relaxed),
        schema_accepted: metrics.schema_accepted.load(Ordering::Relaxed),
        schema_rejected: metrics.schema_rejected.load(Ordering::Relaxed),
        malformed: metrics.malformed_events.load(Ordering::Relaxed),
        rate_limited: metrics.rate_limited_events.load(Ordering::Relaxed),
        queue_dropped: metrics.queue_dropped_events.load(Ordering::Relaxed),
        duplicate_suppressed: metrics.duplicate_suppressed_events.load(Ordering::Relaxed),
        normalized_auth_observations: metrics.normalized_auth_observations.load(Ordering::Relaxed),
        normalized_remote_access_observations: metrics
            .normalized_remote_access_observations
            .load(Ordering::Relaxed),
        bookmark_updates: metrics.bookmark_updates.load(Ordering::Relaxed),
        record_gaps: metrics.record_gaps.load(Ordering::Relaxed),
        worker_active: metrics.workers_active(),
        worker_joined,
        ..WindowsAuthRemoteCounters::default()
    }
}

fn outcome_from_metrics(
    state: WindowsAuthRemoteControlState,
    metrics: &AuthRemoteMetrics,
    normalized_batches: Vec<WindowsAuthRemoteObservationBatch>,
    stopped: bool,
) -> WindowsAuthRemoteEventLogOutcome {
    let counters = counters_from_metrics(metrics, stopped);
    let provider_enabled =
        counters.provider_enabled > 0 && state == WindowsAuthRemoteControlState::Active;
    WindowsAuthRemoteEventLogOutcome {
        state,
        provider_enabled,
        channels_ready: counters.channels_ready,
        channels_unavailable: counters.channels_unavailable,
        collection_started: provider_enabled,
        consumer_started: provider_enabled,
        consumer_worker_active: metrics.workers_active(),
        consumer_worker_joined: stopped && !metrics.workers_active(),
        raw_events_observed: counters.raw_events_observed,
        schema_accepted: counters.schema_accepted,
        schema_rejected: counters.schema_rejected,
        malformed_events: counters.malformed,
        rate_limited_events: counters.rate_limited,
        queue_dropped_events: counters.queue_dropped,
        duplicate_suppressed_events: counters.duplicate_suppressed,
        normalized_auth_observations: counters.normalized_auth_observations,
        normalized_remote_access_observations: counters.normalized_remote_access_observations,
        bookmark_updates: counters.bookmark_updates,
        record_gaps: counters.record_gaps,
        normalized_batches,
        cursor_ref: Some(cursor_ref(metrics.last_record_id.load(Ordering::Relaxed))),
        degraded_reason: if provider_enabled {
            None
        } else {
            Some("windows_auth_remote_event_log_not_yet_ready".to_string())
        },
    }
}

fn rate_limit_allows(metrics: &AuthRemoteMetrics) -> bool {
    let current_second = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let observed = metrics.rate_window_second.load(Ordering::Relaxed);
    if observed == current_second {
        metrics.rate_window_count.fetch_add(1, Ordering::Relaxed)
            < WINDOWS_AUTH_REMOTE_MAX_EVENTS_PER_SECOND
    } else {
        metrics
            .rate_window_second
            .store(current_second, Ordering::Relaxed);
        metrics.rate_window_count.store(1, Ordering::Relaxed);
        true
    }
}

fn hashed_ref(prefix: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(WINDOWS_AUTH_REMOTE_ALLOWLIST_REF.as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    format!(
        "{prefix}_ref_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]
    )
}

fn cursor_ref(record_id: u64) -> String {
    if record_id == 0 {
        "event_log_cursor_not_observed".to_string()
    } else {
        hashed_ref("event_log_cursor", &record_id.to_string())
    }
}

fn sanitize_reason(reason: String) -> String {
    let lowered = reason.to_ascii_lowercase();
    for marker in [
        "s-1-",
        "username",
        "password",
        "token",
        "credential",
        "c:\\",
        "\\users\\",
        "command",
        "powershell",
    ] {
        if lowered.contains(marker) {
            return "windows_auth_remote_event_log_error_redacted".to_string();
        }
    }
    reason
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_declares_infrastructure_only_privacy_boundary() {
        let metadata = WindowsAuthRemoteEventLogAdapter::new().adapter_metadata();
        assert!(metadata.validate().is_ok());
        assert_eq!(
            metadata.provider_kind,
            NetworkProviderKind::WindowsAuthRemote
        );
        assert!(!metadata.ownership.owns_event_bus);
        assert!(!metadata.ownership.owns_dag);
        assert!(!metadata.ownership.owns_plugin_runtime);
        assert!(metadata
            .privacy_notes
            .iter()
            .any(|note| note == "subject_source_target_values_hashed_or_bucketed"));
    }

    #[test]
    fn schema_allowlist_is_exact_and_bounded() {
        assert!(schema_allowed(4624, 2));
        assert!(schema_allowed(4625, 0));
        assert!(!schema_allowed(4624, 9));
        assert!(!schema_allowed(9999, 0));
    }

    #[test]
    fn parser_extracts_transient_fields_without_outputting_raw_values() {
        let xml = r#"
        <Event>
          <System><EventID>4625</EventID><Version>0</Version><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-06-15T00:00:00.000Z"/></System>
          <EventData>
            <Data Name="TargetUserName">alice</Data>
            <Data Name="TargetDomainName">EXAMPLE</Data>
            <Data Name="LogonType">3</Data>
            <Data Name="AuthenticationPackageName">NTLM</Data>
            <Data Name="IpAddress">192.0.2.10</Data>
            <Data Name="Status">0xc000006a</Data>
          </EventData>
        </Event>
        "#;
        let transient = parse_transient_auth_event_xml(xml).expect("transient");
        let mut cohorts = BTreeMap::new();
        let observation =
            normalize_transient_auth_event(transient, &mut cohorts).expect("normalized");
        assert_eq!(observation.auth_result, WindowsAuthResultCategory::Failure);
        assert_eq!(
            observation.auth_mechanism,
            WindowsAuthMechanismCategory::Ntlm
        );
        assert_eq!(
            observation.remote_protocol_category,
            Some(WindowsRemoteProtocolCategory::Network)
        );
        let json = serde_json::to_string(&observation).expect("json");
        assert!(!json.contains("alice"));
        assert!(!json.contains("EXAMPLE"));
        assert!(!json.contains("192.0.2.10"));
        assert!(!json.to_ascii_lowercase().contains("password"));
        observation.validate().expect("safe observation");
    }

    #[test]
    fn rate_limit_counts_are_bounded() {
        let metrics = AuthRemoteMetrics::default();
        let current_second = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        metrics
            .rate_window_second
            .store(current_second, Ordering::Relaxed);
        metrics
            .rate_window_count
            .store(WINDOWS_AUTH_REMOTE_MAX_EVENTS_PER_SECOND, Ordering::Relaxed);
        assert!(!rate_limit_allows(&metrics));
    }

    #[test]
    fn batch_queue_overflow_counts_drop_without_unbounded_growth() {
        let metrics = AuthRemoteMetrics::default();
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut pending = vec![WindowsAuthRemoteObservation {
            observation_ref: "auth_obs_ref".to_string(),
            event_category: WindowsAuthRemoteEventId::FailedLogon,
            schema_category: WindowsAuthSchemaCategory::Security4625V0,
            event_version: 0,
            auth_result: WindowsAuthResultCategory::Failure,
            auth_mechanism: WindowsAuthMechanismCategory::Ntlm,
            account_category: WindowsAuthAccountCategory::DomainUser,
            privilege_bucket: WindowsAuthPrivilegeBucket::Standard,
            remote_protocol_category: Some(WindowsRemoteProtocolCategory::Network),
            failure_category: Some(WindowsAuthFailureCategory::BadSecret),
            repeated_failure_bucket: Some(PortableAuthAttemptCountBucket::One),
            success_after_failure: false,
            identity_ref: Some("acct_ref_test".to_string()),
            source_ref: Some("source_ref_test".to_string()),
            target_ref: Some("target_scope_local_system".to_string()),
            observed_bucket: WindowsAuthObservedBucket::ExistingHostEvents,
            source_reliability: WindowsAuthSourceReliability::SecurityLogVerified,
            freshness: WindowsAuthFreshnessCategory::Recent,
            provenance_ref: "windows_event_log_security".to_string(),
            missing_visibility: vec!["raw_subject_source_target_discarded".to_string()],
            time_bucket_start: Timestamp::now(),
            redaction_status: RedactionStatus::Hashed,
            quality_score: QualityScore::new(0.7).expect("quality"),
        }];
        flush_auth_remote_batch(&mut pending, &sender, &metrics);
        let mut second = vec![WindowsAuthRemoteObservation {
            observation_ref: "auth_obs_ref_second".to_string(),
            ..receiver.try_recv().expect("first").observations[0].clone()
        }];
        let first = second[0].clone();
        sender
            .try_send(WindowsAuthRemoteObservationBatch {
                batch_ref: "auth_remote_test_full_batch".to_string(),
                provider_ref: "windows_event_log_security".to_string(),
                schema_version: WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
                observations: vec![first],
                counters: WindowsAuthRemoteCounters::default(),
                channel_refs: vec!["security".to_string()],
                cursor_ref: Some("event_log_cursor_test".to_string()),
                degraded_reason: None,
                generated_at: Timestamp::now(),
                redaction_status: RedactionStatus::Redacted,
            })
            .expect("queue primed");
        flush_auth_remote_batch(&mut second, &sender, &metrics);
        assert_eq!(metrics.queue_dropped_events.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn windows_auth_remote_contract_error_display_is_safe() {
        let error = sentinel_contracts::WindowsAuthRemoteContractError::UnsafeField("identity_ref")
            .to_string();
        assert!(!error.to_ascii_lowercase().contains("token"));
    }
}
