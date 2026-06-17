//! Bounded Windows Terminal Services RDP operational source adapter.
//!
//! The adapter owns only Windows Event Log handles, bounded queues, cursors,
//! counters, and privacy-safe normalization. It reuses the auth/remote batch
//! contract for downstream product handoff and does not own EventBus, DAG,
//! PluginRuntime, RuntimeContainer, read models, or detectors.

use super::event_log_auth_remote::{
    WindowsAuthRemoteControlState, WindowsAuthRemoteEventLogControl,
    WindowsAuthRemoteEventLogError, WindowsAuthRemoteEventLogOutcome,
};
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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const WINDOWS_RDP_OPERATIONAL_EVENT_LOG_ADAPTER_ID: &str =
    "windows_rdp_operational_event_log_adapter";
pub const WINDOWS_RDP_OPERATIONAL_ALLOWLIST_REF: &str =
    "windows_terminal_services_rdp_operational_allowlist_v1";
pub const WINDOWS_RDP_OPERATIONAL_RAW_QUEUE_CAPACITY: usize = 512;
pub const WINDOWS_RDP_OPERATIONAL_BATCH_QUEUE_CAPACITY: usize = 16;
pub const WINDOWS_RDP_OPERATIONAL_MAX_EVENTS_PER_SECOND: u32 = 512;
pub const WINDOWS_RDP_OPERATIONAL_MAX_DRAIN_BATCHES: usize = 16;
pub const WINDOWS_RDP_OPERATIONAL_BATCH_SIZE: usize = 64;
const WINDOWS_RDP_OPERATIONAL_POLL_INTERVAL: Duration = Duration::from_millis(250);
#[cfg(windows)]
const WINDOWS_RDP_OPERATIONAL_EVENTLOG_TIMEOUT_MS: u32 = 100;
#[cfg(windows)]
const WINDOWS_RDP_OPERATIONAL_QUERY_LIMIT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RdpOperationalChannel {
    RemoteConnectionManager,
    LocalSessionManager,
}

impl RdpOperationalChannel {
    const fn channel_path(self) -> &'static str {
        match self {
            Self::RemoteConnectionManager => {
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
            }
            Self::LocalSessionManager => {
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
            }
        }
    }

    const fn channel_ref(self) -> &'static str {
        match self {
            Self::RemoteConnectionManager => {
                "terminal_services_remoteconnectionmanager_operational"
            }
            Self::LocalSessionManager => "terminal_services_localsessionmanager_operational",
        }
    }
}

pub struct WindowsRdpOperationalEventLogAdapter {
    state: WindowsAuthRemoteControlState,
    #[cfg(windows)]
    active_session: Option<WindowsRdpOperationalEventLogSession>,
}

impl WindowsRdpOperationalEventLogAdapter {
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

impl Default for WindowsRdpOperationalEventLogAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderProbe for WindowsRdpOperationalEventLogAdapter {
    fn adapter_metadata(&self) -> ProviderAdapterMetadata {
        ProviderAdapterMetadata {
            adapter_id: WINDOWS_RDP_OPERATIONAL_EVENT_LOG_ADAPTER_ID.to_string(),
            provider_kind: NetworkProviderKind::WindowsRdpOperational,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            ownership: ProviderAdapterOwnership::infrastructure_adapter(),
            supported_request_refs: vec![
                "explicit_windows_rdp_operational_lifecycle_request".to_string()
            ],
            supported_result_refs: vec!["bounded_windows_rdp_operational_batch_result".to_string()],
            privacy_notes: vec![
                "terminal_services_channel_allowlist_only".to_string(),
                "event_xml_transient".to_string(),
                "bounded_polling_cursor_no_overlap".to_string(),
                "user_domain_client_session_values_hashed_or_bucketed".to_string(),
                "no_sensitive_remote_session_identity_retention".to_string(),
            ],
            redaction_status: RedactionStatus::Redacted,
        }
    }
}

impl WindowsAuthRemoteEventLogControl for WindowsRdpOperationalEventLogAdapter {
    fn start(
        &mut self,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
        if self.state == WindowsAuthRemoteControlState::Active {
            #[cfg(windows)]
            return self
                .active_session
                .as_mut()
                .map(WindowsRdpOperationalEventLogSession::outcome)
                .unwrap_or_else(|| Ok(Self::inactive_outcome(self.state)));
            #[cfg(not(windows))]
            return Ok(Self::inactive_outcome(self.state));
        }
        #[cfg(windows)]
        {
            let mut session = WindowsRdpOperationalEventLogSession::start()?;
            let outcome = session.outcome()?;
            self.active_session = Some(session);
            self.state = WindowsAuthRemoteControlState::Active;
            Ok(outcome)
        }
        #[cfg(not(windows))]
        {
            self.state = WindowsAuthRemoteControlState::Unavailable;
            Err(rdp_error(
                "windows_rdp_operational_event_log_unsupported_platform",
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

impl Drop for WindowsRdpOperationalEventLogAdapter {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Clone, Debug)]
struct RdpOperationalTransientEvent {
    channel: RdpOperationalChannel,
    record_id: u64,
    event_id: u16,
    version: u8,
    user: Option<String>,
    domain: Option<String>,
    client_address: Option<String>,
    system_time: Option<String>,
}

#[derive(Default)]
struct RdpOperationalMetrics {
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
    rcm_last_record_id: AtomicU64,
    lsm_last_record_id: AtomicU64,
    worker_active: AtomicBool,
    normalizer_active: AtomicBool,
    channels_ready: AtomicU32,
    channels_unavailable: AtomicU32,
}

impl RdpOperationalMetrics {
    fn workers_active(&self) -> bool {
        self.worker_active.load(Ordering::SeqCst) || self.normalizer_active.load(Ordering::SeqCst)
    }

    fn last_record_id(&self, channel: RdpOperationalChannel) -> u64 {
        match channel {
            RdpOperationalChannel::RemoteConnectionManager => {
                self.rcm_last_record_id.load(Ordering::Relaxed)
            }
            RdpOperationalChannel::LocalSessionManager => {
                self.lsm_last_record_id.load(Ordering::Relaxed)
            }
        }
    }

    fn store_last_record_id(&self, channel: RdpOperationalChannel, record_id: u64) {
        match channel {
            RdpOperationalChannel::RemoteConnectionManager => {
                self.rcm_last_record_id.store(record_id, Ordering::Relaxed)
            }
            RdpOperationalChannel::LocalSessionManager => {
                self.lsm_last_record_id.store(record_id, Ordering::Relaxed)
            }
        }
    }
}

#[cfg(windows)]
struct WindowsRdpOperationalEventLogSession {
    batch_receiver: Receiver<WindowsAuthRemoteObservationBatch>,
    metrics: Arc<RdpOperationalMetrics>,
    cancellation: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    reader_thread: Option<JoinHandle<()>>,
    normalizer_thread: Option<JoinHandle<()>>,
    stopped: bool,
}

#[cfg(windows)]
impl WindowsRdpOperationalEventLogSession {
    fn start() -> Result<Self, WindowsAuthRemoteEventLogError> {
        let metrics = Arc::new(RdpOperationalMetrics::default());
        let cancellation = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let (raw_sender, raw_receiver) =
            mpsc::sync_channel(WINDOWS_RDP_OPERATIONAL_RAW_QUEUE_CAPACITY);
        let (batch_sender, batch_receiver) =
            mpsc::sync_channel(WINDOWS_RDP_OPERATIONAL_BATCH_QUEUE_CAPACITY);

        poll_terminal_services_events_once(&raw_sender, &metrics)?;

        let reader_metrics = Arc::clone(&metrics);
        let reader_cancel = Arc::clone(&cancellation);
        let reader_paused = Arc::clone(&paused);
        let reader_thread = thread::spawn(move || {
            reader_metrics.worker_active.store(true, Ordering::SeqCst);
            run_rdp_event_log_reader(raw_sender, reader_metrics, reader_cancel, reader_paused);
        });

        let normalizer_metrics = Arc::clone(&metrics);
        let normalizer_cancel = Arc::clone(&cancellation);
        let normalizer_thread = thread::spawn(move || {
            normalizer_metrics
                .normalizer_active
                .store(true, Ordering::SeqCst);
            run_rdp_event_log_normalizer(
                raw_receiver,
                batch_sender,
                normalizer_metrics,
                normalizer_cancel,
            );
        });

        let startup_deadline = Instant::now() + Duration::from_millis(250);
        while !metrics.workers_active() && Instant::now() < startup_deadline {
            thread::sleep(Duration::from_millis(10));
        }

        Ok(Self {
            batch_receiver,
            metrics,
            cancellation,
            paused,
            reader_thread: Some(reader_thread),
            normalizer_thread: Some(normalizer_thread),
            stopped: false,
        })
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
            if batches.len() >= WINDOWS_RDP_OPERATIONAL_MAX_DRAIN_BATCHES {
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
        for _ in 0..max_batches.min(WINDOWS_RDP_OPERATIONAL_MAX_DRAIN_BATCHES) {
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
            Some("windows_rdp_operational_event_log_stopped".to_string())
        } else {
            Some("windows_rdp_operational_event_log_join_failed".to_string())
        };
        if !outcome.consumer_worker_joined {
            return Err(rdp_error("windows_rdp_operational_event_log_join_failed"));
        }
        Ok(outcome)
    }
}

#[cfg(windows)]
impl Drop for WindowsRdpOperationalEventLogSession {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.stop();
        }
    }
}

#[cfg(windows)]
fn run_rdp_event_log_reader(
    sender: SyncSender<RdpOperationalTransientEvent>,
    metrics: Arc<RdpOperationalMetrics>,
    cancellation: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) {
    while !cancellation.load(Ordering::SeqCst) {
        if paused.load(Ordering::SeqCst) {
            thread::sleep(WINDOWS_RDP_OPERATIONAL_POLL_INTERVAL);
            continue;
        }
        if poll_terminal_services_events_once(&sender, &metrics).is_err() {
            thread::sleep(WINDOWS_RDP_OPERATIONAL_POLL_INTERVAL);
        }
        thread::sleep(WINDOWS_RDP_OPERATIONAL_POLL_INTERVAL);
    }
    metrics.worker_active.store(false, Ordering::SeqCst);
}

#[cfg(windows)]
fn run_rdp_event_log_normalizer(
    receiver: Receiver<RdpOperationalTransientEvent>,
    sender: SyncSender<WindowsAuthRemoteObservationBatch>,
    metrics: Arc<RdpOperationalMetrics>,
    cancellation: Arc<AtomicBool>,
) {
    let mut pending = Vec::with_capacity(WINDOWS_RDP_OPERATIONAL_BATCH_SIZE);
    while !cancellation.load(Ordering::SeqCst) {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(transient) => {
                if let Some(observation) = normalize_transient_rdp_event(transient) {
                    metrics
                        .normalized_auth_observations
                        .fetch_add(1, Ordering::Relaxed);
                    metrics
                        .normalized_remote_access_observations
                        .fetch_add(1, Ordering::Relaxed);
                    pending.push(observation);
                } else {
                    metrics.schema_rejected.fetch_add(1, Ordering::Relaxed);
                }
                if pending.len() >= WINDOWS_RDP_OPERATIONAL_BATCH_SIZE {
                    flush_rdp_operational_batch(&mut pending, &sender, &metrics);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !pending.is_empty() {
                    flush_rdp_operational_batch(&mut pending, &sender, &metrics);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if !pending.is_empty() {
        flush_rdp_operational_batch(&mut pending, &sender, &metrics);
    }
    metrics.normalizer_active.store(false, Ordering::SeqCst);
}

fn flush_rdp_operational_batch(
    pending: &mut Vec<WindowsAuthRemoteObservation>,
    sender: &SyncSender<WindowsAuthRemoteObservationBatch>,
    metrics: &RdpOperationalMetrics,
) {
    let observations = std::mem::take(pending);
    let counters = counters_from_metrics(metrics, false);
    let batch = WindowsAuthRemoteObservationBatch {
        batch_ref: format!(
            "windows_rdp_operational_batch_{}",
            hashed_ref("batch", &format!("{:?}", Timestamp::now()))
        ),
        provider_ref: "windows_rdp_operational_event_log".to_string(),
        schema_version: WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
        observations,
        counters,
        cursor_ref: Some(cursor_ref(metrics)),
        channel_refs: vec![
            RdpOperationalChannel::RemoteConnectionManager
                .channel_ref()
                .to_string(),
            RdpOperationalChannel::LocalSessionManager
                .channel_ref()
                .to_string(),
        ],
        degraded_reason: Some("existing_host_events_or_live_terminal_services_log".to_string()),
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
fn poll_terminal_services_events_once(
    sender: &SyncSender<RdpOperationalTransientEvent>,
    metrics: &RdpOperationalMetrics,
) -> Result<(), WindowsAuthRemoteEventLogError> {
    let channels = [
        RdpOperationalChannel::RemoteConnectionManager,
        RdpOperationalChannel::LocalSessionManager,
    ];
    let mut ready = 0_u32;
    let mut unavailable = 0_u32;
    for channel in channels {
        match poll_terminal_services_channel_once(channel, sender, metrics) {
            Ok(()) => ready = ready.saturating_add(1),
            Err(_) => unavailable = unavailable.saturating_add(1),
        }
    }
    metrics.channels_ready.store(ready, Ordering::Relaxed);
    metrics
        .channels_unavailable
        .store(unavailable, Ordering::Relaxed);
    if ready == 0 && unavailable > 0 {
        Err(rdp_error("windows_rdp_operational_channels_unavailable"))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn poll_terminal_services_channel_once(
    channel: RdpOperationalChannel,
    sender: &SyncSender<RdpOperationalTransientEvent>,
    metrics: &RdpOperationalMetrics,
) -> Result<(), WindowsAuthRemoteEventLogError> {
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS,
    };
    use windows_sys::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtRender,
        EvtRenderEventXml, EVT_HANDLE,
    };

    let channel_wide = wide_null(channel.channel_path());
    let query_text = terminal_services_query(channel, metrics.last_record_id(channel));
    let query_wide = wide_null(&query_text);
    let query = unsafe {
        EvtQuery(
            0,
            channel_wide.as_ptr(),
            query_wide.as_ptr(),
            EvtQueryChannelPath | EvtQueryForwardDirection,
        )
    };
    if query == 0 {
        let code = unsafe { GetLastError() };
        return Err(rdp_error(format!(
            "windows_rdp_event_log_query_error_{code}"
        )));
    }
    let mut read_count = 0_usize;
    loop {
        let mut events: [EVT_HANDLE; 8] = [0; 8];
        let mut returned = 0_u32;
        let ok = unsafe {
            EvtNext(
                query,
                events.len() as u32,
                events.as_mut_ptr(),
                WINDOWS_RDP_OPERATIONAL_EVENTLOG_TIMEOUT_MS,
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
            return Err(rdp_error(format!(
                "windows_rdp_event_log_next_error_{code}"
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
                    match parse_transient_rdp_event_xml(&xml, channel) {
                        Some(transient)
                            if schema_allowed(
                                transient.channel,
                                transient.event_id,
                                transient.version,
                            ) =>
                        {
                            let previous = metrics.last_record_id(channel);
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
                            metrics.store_last_record_id(channel, transient.record_id);
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
            if read_count >= WINDOWS_RDP_OPERATIONAL_QUERY_LIMIT {
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
            return Err(rdp_error(format!(
                "windows_rdp_event_log_render_probe_error_{code}"
            )));
        }
    }
    if buffer_used == 0 || buffer_used > 256 * 1024 {
        return Err(rdp_error("windows_rdp_event_log_render_size_invalid"));
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
        return Err(rdp_error(format!(
            "windows_rdp_event_log_render_error_{code}"
        )));
    }
    let units = buffer
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    Ok(String::from_utf16_lossy(&units))
}

#[cfg(windows)]
fn terminal_services_query(channel: RdpOperationalChannel, last_record_id: u64) -> String {
    let event_filter = match channel {
        RdpOperationalChannel::RemoteConnectionManager => "(EventID=1149)",
        RdpOperationalChannel::LocalSessionManager => {
            "(EventID=21 or EventID=23 or EventID=24 or EventID=25 or EventID=39 or EventID=40)"
        }
    };
    if last_record_id > 0 {
        format!("*[System[{event_filter} and EventRecordID>{last_record_id}]]")
    } else {
        format!("*[System[{event_filter} and TimeCreated[timediff(@SystemTime) <= 90000]]]")
    }
}

fn parse_transient_rdp_event_xml(
    xml: &str,
    channel: RdpOperationalChannel,
) -> Option<RdpOperationalTransientEvent> {
    let event_id = tag_text(xml, "EventID")?.parse::<u16>().ok()?;
    let version = tag_text(xml, "Version")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0);
    let record_id = tag_text(xml, "EventRecordID")?.parse::<u64>().ok()?;
    let user = first_data_name(
        xml,
        &[
            "Param1",
            "User",
            "UserName",
            "AccountName",
            "TargetUserName",
        ],
    );
    let domain = first_data_name(xml, &["Param2", "Domain", "DomainName", "TargetDomainName"]);
    let client_address = first_data_name(
        xml,
        &[
            "Param3",
            "ClientAddress",
            "Address",
            "SourceNetworkAddress",
            "IpAddress",
        ],
    );
    let system_time = attribute_value(xml, "TimeCreated", "SystemTime");
    Some(RdpOperationalTransientEvent {
        channel,
        record_id,
        event_id,
        version,
        user,
        domain,
        client_address,
        system_time,
    })
}

fn normalize_transient_rdp_event(
    transient: RdpOperationalTransientEvent,
) -> Option<WindowsAuthRemoteObservation> {
    let schema_category =
        schema_category(transient.channel, transient.event_id, transient.version)?;
    let event_category = rdp_event_category(transient.event_id);
    let auth_result = rdp_auth_result(transient.event_id);
    let account_category = account_category(transient.user.as_deref(), transient.domain.as_deref());
    let identity_ref = transient.user.as_deref().map(|user| {
        hashed_ref(
            "acct",
            &format!("{}|{}", transient.domain.as_deref().unwrap_or(""), user),
        )
    });
    let source_ref = transient
        .client_address
        .as_deref()
        .filter(|value| !value.trim().is_empty() && *value != "-")
        .map(|value| hashed_ref("source", value));
    let observation = WindowsAuthRemoteObservation {
        observation_ref: hashed_ref(
            "rdp_obs",
            &format!(
                "{}|{}|{}",
                transient.channel.channel_ref(),
                transient.event_id,
                transient.record_id
            ),
        ),
        event_category,
        schema_category,
        event_version: transient.version,
        auth_result,
        auth_mechanism: WindowsAuthMechanismCategory::Unknown,
        account_category,
        privilege_bucket: privilege_bucket(account_category),
        remote_protocol_category: Some(WindowsRemoteProtocolCategory::Rdp),
        failure_category: if auth_result == WindowsAuthResultCategory::Failure {
            Some(WindowsAuthFailureCategory::ProtocolFailure)
        } else {
            None
        },
        repeated_failure_bucket: if auth_result == WindowsAuthResultCategory::Failure {
            Some(PortableAuthAttemptCountBucket::One)
        } else {
            None
        },
        success_after_failure: false,
        identity_ref,
        source_ref,
        target_ref: Some("target_scope_local_terminal_services".to_string()),
        observed_bucket: WindowsAuthObservedBucket::ExistingHostEvents,
        source_reliability: WindowsAuthSourceReliability::OptionalChannelVerified,
        freshness: freshness(transient.system_time.as_deref()),
        provenance_ref: "windows_terminal_services_operational".to_string(),
        missing_visibility: vec![
            "raw_user_domain_client_session_discarded".to_string(),
            "security_log_correlation_not_required_for_rdp_source".to_string(),
        ],
        time_bucket_start: Timestamp::now(),
        redaction_status: RedactionStatus::Hashed,
        quality_score: QualityScore::new(0.68).ok()?,
    };
    observation.validate().ok()?;
    Some(observation)
}

fn schema_allowed(channel: RdpOperationalChannel, event_id: u16, version: u8) -> bool {
    schema_category(channel, event_id, version).is_some()
}

fn schema_category(
    channel: RdpOperationalChannel,
    event_id: u16,
    version: u8,
) -> Option<WindowsAuthSchemaCategory> {
    match (channel, event_id, version) {
        (RdpOperationalChannel::RemoteConnectionManager, 1149, 0) => {
            Some(WindowsAuthSchemaCategory::TerminalServicesRemoteConnectionManager1149V0)
        }
        (RdpOperationalChannel::LocalSessionManager, 21, 0) => {
            Some(WindowsAuthSchemaCategory::TerminalServicesLocalSessionManager21V0)
        }
        (RdpOperationalChannel::LocalSessionManager, 23, 0) => {
            Some(WindowsAuthSchemaCategory::TerminalServicesLocalSessionManager23V0)
        }
        (RdpOperationalChannel::LocalSessionManager, 24, 0) => {
            Some(WindowsAuthSchemaCategory::TerminalServicesLocalSessionManager24V0)
        }
        (RdpOperationalChannel::LocalSessionManager, 25, 0) => {
            Some(WindowsAuthSchemaCategory::TerminalServicesLocalSessionManager25V0)
        }
        (RdpOperationalChannel::LocalSessionManager, 39, 0) => {
            Some(WindowsAuthSchemaCategory::TerminalServicesLocalSessionManager39V0)
        }
        (RdpOperationalChannel::LocalSessionManager, 40, 0) => {
            Some(WindowsAuthSchemaCategory::TerminalServicesLocalSessionManager40V0)
        }
        _ => None,
    }
}

fn rdp_event_category(event_id: u16) -> WindowsAuthRemoteEventId {
    match event_id {
        1149 | 21 | 25 => WindowsAuthRemoteEventId::SuccessfulLogon,
        23 | 24 | 39 | 40 => WindowsAuthRemoteEventId::Logoff,
        _ => WindowsAuthRemoteEventId::Unknown,
    }
}

fn rdp_auth_result(event_id: u16) -> WindowsAuthResultCategory {
    match event_id {
        1149 | 21 | 25 => WindowsAuthResultCategory::Success,
        23 | 24 | 39 | 40 => WindowsAuthResultCategory::Logoff,
        _ => WindowsAuthResultCategory::Unknown,
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

fn privilege_bucket(account_category: WindowsAuthAccountCategory) -> WindowsAuthPrivilegeBucket {
    if account_category == WindowsAuthAccountCategory::AdminLike {
        WindowsAuthPrivilegeBucket::Elevated
    } else {
        WindowsAuthPrivilegeBucket::Standard
    }
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
    metrics: &RdpOperationalMetrics,
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
    metrics: &RdpOperationalMetrics,
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
        cursor_ref: Some(cursor_ref(metrics)),
        degraded_reason: if provider_enabled {
            None
        } else {
            Some("windows_rdp_operational_event_log_not_yet_ready".to_string())
        },
    }
}

fn rate_limit_allows(metrics: &RdpOperationalMetrics) -> bool {
    let current_second = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let observed = metrics.rate_window_second.load(Ordering::Relaxed);
    if observed == current_second {
        metrics.rate_window_count.fetch_add(1, Ordering::Relaxed)
            < WINDOWS_RDP_OPERATIONAL_MAX_EVENTS_PER_SECOND
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
    hasher.update(WINDOWS_RDP_OPERATIONAL_ALLOWLIST_REF.as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    format!(
        "{prefix}_ref_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]
    )
}

fn cursor_ref(metrics: &RdpOperationalMetrics) -> String {
    let rcm = metrics
        .rcm_last_record_id
        .load(Ordering::Relaxed)
        .to_string();
    let lsm = metrics
        .lsm_last_record_id
        .load(Ordering::Relaxed)
        .to_string();
    if rcm == "0" && lsm == "0" {
        "rdp_event_log_cursor_not_observed".to_string()
    } else {
        hashed_ref("rdp_event_log_cursor", &format!("{rcm}|{lsm}"))
    }
}

fn rdp_error(reason: impl Into<String>) -> WindowsAuthRemoteEventLogError {
    WindowsAuthRemoteEventLogError {
        reason_redacted: sanitize_reason(reason.into()),
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
        "clientaddress",
        "ipaddress",
        "sessionid",
    ] {
        if lowered.contains(marker) {
            return "windows_rdp_operational_event_log_error_redacted".to_string();
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
        let metadata = WindowsRdpOperationalEventLogAdapter::new().adapter_metadata();
        assert!(metadata.validate().is_ok());
        assert_eq!(
            metadata.provider_kind,
            NetworkProviderKind::WindowsRdpOperational
        );
        assert!(!metadata.ownership.owns_event_bus);
        assert!(!metadata.ownership.owns_dag);
        assert!(!metadata.ownership.owns_plugin_runtime);
        assert!(metadata
            .privacy_notes
            .iter()
            .any(|note| note == "terminal_services_channel_allowlist_only"));
    }

    #[test]
    fn schema_allowlist_is_exact_and_bounded() {
        assert!(schema_allowed(
            RdpOperationalChannel::RemoteConnectionManager,
            1149,
            0
        ));
        assert!(schema_allowed(
            RdpOperationalChannel::LocalSessionManager,
            21,
            0
        ));
        assert!(!schema_allowed(
            RdpOperationalChannel::RemoteConnectionManager,
            1149,
            9
        ));
        assert!(!schema_allowed(
            RdpOperationalChannel::LocalSessionManager,
            4624,
            0
        ));
    }

    #[test]
    fn parser_extracts_transient_fields_without_outputting_raw_values() {
        let xml = r#"
        <Event>
          <System><EventID>1149</EventID><Version>0</Version><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-06-15T00:00:00.000Z"/></System>
          <EventData>
            <Data Name="Param1">alice</Data>
            <Data Name="Param2">EXAMPLE</Data>
            <Data Name="Param3">192.0.2.10</Data>
          </EventData>
        </Event>
        "#;
        let transient =
            parse_transient_rdp_event_xml(xml, RdpOperationalChannel::RemoteConnectionManager)
                .expect("transient");
        let observation = normalize_transient_rdp_event(transient).expect("normalized");
        assert_eq!(observation.auth_result, WindowsAuthResultCategory::Success);
        assert_eq!(
            observation.remote_protocol_category,
            Some(WindowsRemoteProtocolCategory::Rdp)
        );
        let json = serde_json::to_string(&observation).expect("json");
        assert!(!json.contains("alice"));
        assert!(!json.contains("EXAMPLE"));
        assert!(!json.contains("192.0.2.10"));
        assert!(!json.to_ascii_lowercase().contains("sessionid"));
        observation.validate().expect("safe observation");
    }

    #[test]
    fn rate_limit_counts_are_bounded() {
        let metrics = RdpOperationalMetrics::default();
        let current_second = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        metrics
            .rate_window_second
            .store(current_second, Ordering::Relaxed);
        metrics.rate_window_count.store(
            WINDOWS_RDP_OPERATIONAL_MAX_EVENTS_PER_SECOND,
            Ordering::Relaxed,
        );
        assert!(!rate_limit_allows(&metrics));
    }

    #[test]
    fn batch_queue_overflow_counts_drop_without_unbounded_growth() {
        let metrics = RdpOperationalMetrics::default();
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut pending = vec![WindowsAuthRemoteObservation {
            observation_ref: "rdp_obs_ref_test".to_string(),
            event_category: WindowsAuthRemoteEventId::SuccessfulLogon,
            schema_category:
                WindowsAuthSchemaCategory::TerminalServicesRemoteConnectionManager1149V0,
            event_version: 0,
            auth_result: WindowsAuthResultCategory::Success,
            auth_mechanism: WindowsAuthMechanismCategory::Unknown,
            account_category: WindowsAuthAccountCategory::DomainUser,
            privilege_bucket: WindowsAuthPrivilegeBucket::Standard,
            remote_protocol_category: Some(WindowsRemoteProtocolCategory::Rdp),
            failure_category: None,
            repeated_failure_bucket: None,
            success_after_failure: false,
            identity_ref: Some("acct_ref_test".to_string()),
            source_ref: Some("source_ref_test".to_string()),
            target_ref: Some("target_scope_local_terminal_services".to_string()),
            observed_bucket: WindowsAuthObservedBucket::ExistingHostEvents,
            source_reliability: WindowsAuthSourceReliability::OptionalChannelVerified,
            freshness: WindowsAuthFreshnessCategory::Recent,
            provenance_ref: "windows_terminal_services_operational".to_string(),
            missing_visibility: vec!["raw_user_domain_client_session_discarded".to_string()],
            time_bucket_start: Timestamp::now(),
            redaction_status: RedactionStatus::Hashed,
            quality_score: QualityScore::new(0.68).expect("quality"),
        }];
        flush_rdp_operational_batch(&mut pending, &sender, &metrics);
        let mut second = vec![WindowsAuthRemoteObservation {
            observation_ref: "rdp_obs_ref_second".to_string(),
            ..receiver.try_recv().expect("first").observations[0].clone()
        }];
        let first = second[0].clone();
        sender
            .try_send(WindowsAuthRemoteObservationBatch {
                batch_ref: "rdp_operational_test_full_batch".to_string(),
                provider_ref: "windows_rdp_operational_event_log".to_string(),
                schema_version: WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
                observations: vec![first],
                counters: WindowsAuthRemoteCounters::default(),
                channel_refs: vec![RdpOperationalChannel::RemoteConnectionManager
                    .channel_ref()
                    .to_string()],
                cursor_ref: Some("rdp_event_log_cursor_test".to_string()),
                degraded_reason: None,
                generated_at: Timestamp::now(),
                redaction_status: RedactionStatus::Redacted,
            })
            .expect("queue primed");
        flush_rdp_operational_batch(&mut second, &sender, &metrics);
        assert_eq!(metrics.queue_dropped_events.load(Ordering::Relaxed), 1);
    }
}
