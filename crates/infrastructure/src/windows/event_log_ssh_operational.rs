//! Bounded Windows OpenSSH Operational Event Log source adapter.
//!
//! The adapter owns only Windows Event Log handles, bounded queues, cursors,
//! counters, and privacy-safe normalization. It accepts only the OpenSSH
//! Operational provider/channel/event schema plus fixed OpenSSH message
//! structures. It does not own EventBus, DAG, PluginRuntime, RuntimeContainer,
//! read models, storage, schedulers, or detectors.

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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const WINDOWS_SSH_OPERATIONAL_EVENT_LOG_ADAPTER_ID: &str =
    "windows_ssh_operational_event_log_adapter";
pub const WINDOWS_SSH_OPERATIONAL_ALLOWLIST_REF: &str =
    "windows_openssh_operational_event_log_allowlist_v1";
pub const WINDOWS_SSH_OPERATIONAL_RAW_QUEUE_CAPACITY: usize = 512;
pub const WINDOWS_SSH_OPERATIONAL_BATCH_QUEUE_CAPACITY: usize = 16;
pub const WINDOWS_SSH_OPERATIONAL_MAX_EVENTS_PER_SECOND: u32 = 512;
pub const WINDOWS_SSH_OPERATIONAL_MAX_DRAIN_BATCHES: usize = 16;
pub const WINDOWS_SSH_OPERATIONAL_BATCH_SIZE: usize = 64;
pub const WINDOWS_SSH_OPERATIONAL_MAX_RENDERED_XML_BYTES: usize = 256 * 1024;
pub const WINDOWS_SSH_OPERATIONAL_MAX_MESSAGE_BYTES: usize = 2048;
const WINDOWS_SSH_OPERATIONAL_POLL_INTERVAL: Duration = Duration::from_millis(250);
#[cfg(windows)]
const WINDOWS_SSH_OPERATIONAL_EVENTLOG_TIMEOUT_MS: u32 = 100;
#[cfg(windows)]
const WINDOWS_SSH_OPERATIONAL_QUERY_LIMIT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SshOperationalChannel {
    OpenSshOperational,
}

impl SshOperationalChannel {
    const fn channel_path(self) -> &'static str {
        match self {
            Self::OpenSshOperational => "OpenSSH/Operational",
        }
    }

    const fn channel_ref(self) -> &'static str {
        match self {
            Self::OpenSshOperational => "openssh_operational",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SshOperationalMessageSchema {
    AuthSuccessPublicKey,
    AuthSuccessPassword,
    AuthFailurePublicKey,
    AuthFailurePassword,
    InvalidUser,
    ConnectionOpened,
    SessionOpened,
    SessionClosed,
    SubsystemRequested,
    Disconnect,
    PolicyRejection,
    ProtocolError,
    KeyExchangeFailure,
}

#[derive(Clone, Debug)]
struct SshOperationalMessageMatch {
    schema: SshOperationalMessageSchema,
    identity_seed: Option<String>,
    source_seed: Option<String>,
}

pub struct WindowsSshOperationalEventLogAdapter {
    state: WindowsAuthRemoteControlState,
    #[cfg(windows)]
    active_session: Option<WindowsSshOperationalEventLogSession>,
}

impl WindowsSshOperationalEventLogAdapter {
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

impl Default for WindowsSshOperationalEventLogAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderProbe for WindowsSshOperationalEventLogAdapter {
    fn adapter_metadata(&self) -> ProviderAdapterMetadata {
        ProviderAdapterMetadata {
            adapter_id: WINDOWS_SSH_OPERATIONAL_EVENT_LOG_ADAPTER_ID.to_string(),
            provider_kind: NetworkProviderKind::WindowsSshOperational,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            ownership: ProviderAdapterOwnership::infrastructure_adapter(),
            supported_request_refs: vec![
                "explicit_windows_ssh_operational_lifecycle_request".to_string()
            ],
            supported_result_refs: vec!["bounded_windows_ssh_operational_batch_result".to_string()],
            privacy_notes: vec![
                "openssh_operational_channel_allowlist_only".to_string(),
                "event_xml_and_insertion_strings_transient".to_string(),
                "bounded_polling_cursor_no_overlap".to_string(),
                "ssh_actor_peer_crypto_exec_values_not_retained".to_string(),
                "no_sshd_configuration_or_connection_side_effects".to_string(),
            ],
            redaction_status: RedactionStatus::Redacted,
        }
    }
}

impl WindowsAuthRemoteEventLogControl for WindowsSshOperationalEventLogAdapter {
    fn start(
        &mut self,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
        if self.state == WindowsAuthRemoteControlState::Active {
            #[cfg(windows)]
            return self
                .active_session
                .as_mut()
                .map(WindowsSshOperationalEventLogSession::outcome)
                .unwrap_or_else(|| Ok(Self::inactive_outcome(self.state)));
            #[cfg(not(windows))]
            return Ok(Self::inactive_outcome(self.state));
        }
        #[cfg(windows)]
        {
            let mut session = WindowsSshOperationalEventLogSession::start()?;
            let outcome = session.outcome()?;
            self.active_session = Some(session);
            self.state = WindowsAuthRemoteControlState::Active;
            Ok(outcome)
        }
        #[cfg(not(windows))]
        {
            self.state = WindowsAuthRemoteControlState::Unavailable;
            Err(ssh_error(
                "windows_ssh_operational_event_log_unsupported_platform",
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

impl Drop for WindowsSshOperationalEventLogAdapter {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Clone, Debug)]
struct SshOperationalTransientEvent {
    channel: SshOperationalChannel,
    record_id: u64,
    event_id: u16,
    version: u8,
    system_time: Option<String>,
    message_match: Option<SshOperationalMessageMatch>,
}

#[derive(Default)]
struct SshOperationalMetrics {
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

impl SshOperationalMetrics {
    fn workers_active(&self) -> bool {
        self.worker_active.load(Ordering::SeqCst) || self.normalizer_active.load(Ordering::SeqCst)
    }

    fn last_record_id(&self) -> u64 {
        self.last_record_id.load(Ordering::Relaxed)
    }

    fn store_last_record_id(&self, record_id: u64) {
        self.last_record_id.store(record_id, Ordering::Relaxed);
    }
}

#[cfg(windows)]
struct WindowsSshOperationalEventLogSession {
    batch_receiver: Receiver<WindowsAuthRemoteObservationBatch>,
    metrics: Arc<SshOperationalMetrics>,
    cancellation: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    reader_thread: Option<JoinHandle<()>>,
    normalizer_thread: Option<JoinHandle<()>>,
    stopped: bool,
}

#[cfg(windows)]
impl WindowsSshOperationalEventLogSession {
    fn start() -> Result<Self, WindowsAuthRemoteEventLogError> {
        let metrics = Arc::new(SshOperationalMetrics::default());
        let cancellation = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let (raw_sender, raw_receiver) =
            mpsc::sync_channel(WINDOWS_SSH_OPERATIONAL_RAW_QUEUE_CAPACITY);
        let (batch_sender, batch_receiver) =
            mpsc::sync_channel(WINDOWS_SSH_OPERATIONAL_BATCH_QUEUE_CAPACITY);

        let reader_metrics = Arc::clone(&metrics);
        let reader_cancel = Arc::clone(&cancellation);
        let reader_paused = Arc::clone(&paused);
        let reader_thread = thread::spawn(move || {
            reader_metrics.worker_active.store(true, Ordering::SeqCst);
            run_ssh_event_log_reader(raw_sender, reader_metrics, reader_cancel, reader_paused);
        });

        let normalizer_metrics = Arc::clone(&metrics);
        let normalizer_cancel = Arc::clone(&cancellation);
        let normalizer_thread = thread::spawn(move || {
            normalizer_metrics
                .normalizer_active
                .store(true, Ordering::SeqCst);
            run_ssh_event_log_normalizer(
                raw_receiver,
                batch_sender,
                normalizer_metrics,
                normalizer_cancel,
            );
        });

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
            if batches.len() >= WINDOWS_SSH_OPERATIONAL_MAX_DRAIN_BATCHES {
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
        for _ in 0..max_batches.min(WINDOWS_SSH_OPERATIONAL_MAX_DRAIN_BATCHES) {
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
            Some("windows_ssh_operational_event_log_stopped".to_string())
        } else {
            Some("windows_ssh_operational_event_log_join_failed".to_string())
        };
        if !outcome.consumer_worker_joined {
            return Err(ssh_error("windows_ssh_operational_event_log_join_failed"));
        }
        Ok(outcome)
    }
}

#[cfg(windows)]
impl Drop for WindowsSshOperationalEventLogSession {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.stop();
        }
    }
}

#[cfg(windows)]
fn run_ssh_event_log_reader(
    sender: SyncSender<SshOperationalTransientEvent>,
    metrics: Arc<SshOperationalMetrics>,
    cancellation: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) {
    while !cancellation.load(Ordering::SeqCst) {
        if paused.load(Ordering::SeqCst) {
            thread::sleep(WINDOWS_SSH_OPERATIONAL_POLL_INTERVAL);
            continue;
        }
        if poll_ssh_events_once(&sender, &metrics).is_err() {
            thread::sleep(WINDOWS_SSH_OPERATIONAL_POLL_INTERVAL);
        }
        thread::sleep(WINDOWS_SSH_OPERATIONAL_POLL_INTERVAL);
    }
    metrics.worker_active.store(false, Ordering::SeqCst);
}

#[cfg(windows)]
fn run_ssh_event_log_normalizer(
    receiver: Receiver<SshOperationalTransientEvent>,
    sender: SyncSender<WindowsAuthRemoteObservationBatch>,
    metrics: Arc<SshOperationalMetrics>,
    cancellation: Arc<AtomicBool>,
) {
    let mut pending = Vec::with_capacity(WINDOWS_SSH_OPERATIONAL_BATCH_SIZE);
    while !cancellation.load(Ordering::SeqCst) {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(transient) => {
                if let Some(observation) = normalize_transient_ssh_event(transient) {
                    metrics
                        .normalized_remote_access_observations
                        .fetch_add(1, Ordering::Relaxed);
                    if ssh_schema_has_auth_context(observation.schema_category) {
                        metrics
                            .normalized_auth_observations
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    pending.push(observation);
                } else {
                    metrics.schema_rejected.fetch_add(1, Ordering::Relaxed);
                }
                if pending.len() >= WINDOWS_SSH_OPERATIONAL_BATCH_SIZE {
                    flush_ssh_operational_batch(&mut pending, &sender, &metrics);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !pending.is_empty() {
                    flush_ssh_operational_batch(&mut pending, &sender, &metrics);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if !pending.is_empty() {
        flush_ssh_operational_batch(&mut pending, &sender, &metrics);
    }
    metrics.normalizer_active.store(false, Ordering::SeqCst);
}

fn flush_ssh_operational_batch(
    pending: &mut Vec<WindowsAuthRemoteObservation>,
    sender: &SyncSender<WindowsAuthRemoteObservationBatch>,
    metrics: &SshOperationalMetrics,
) {
    let observations = std::mem::take(pending);
    let counters = counters_from_metrics(metrics, false);
    let batch = WindowsAuthRemoteObservationBatch {
        batch_ref: format!(
            "windows_ssh_operational_batch_{}",
            hashed_ref("batch", &format!("{:?}", Timestamp::now()))
        ),
        provider_ref: "windows_openssh_operational_event_log".to_string(),
        schema_version: WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
        observations,
        counters,
        cursor_ref: Some(cursor_ref(metrics)),
        channel_refs: allowlisted_channels()
            .iter()
            .map(|channel| channel.channel_ref().to_string())
            .collect(),
        degraded_reason: Some("existing_host_events_or_live_openssh_operational_log".to_string()),
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
fn poll_ssh_events_once(
    sender: &SyncSender<SshOperationalTransientEvent>,
    metrics: &SshOperationalMetrics,
) -> Result<(), WindowsAuthRemoteEventLogError> {
    let mut ready = 0_u32;
    let mut unavailable = 0_u32;
    for channel in allowlisted_channels() {
        match poll_ssh_channel_once(channel, sender, metrics) {
            Ok(()) => ready = ready.saturating_add(1),
            Err(_) => unavailable = unavailable.saturating_add(1),
        }
    }
    metrics.channels_ready.store(ready, Ordering::Relaxed);
    metrics
        .channels_unavailable
        .store(unavailable, Ordering::Relaxed);
    if ready == 0 && unavailable > 0 {
        Err(ssh_error("windows_ssh_operational_channel_unavailable"))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn poll_ssh_channel_once(
    channel: SshOperationalChannel,
    sender: &SyncSender<SshOperationalTransientEvent>,
    metrics: &SshOperationalMetrics,
) -> Result<(), WindowsAuthRemoteEventLogError> {
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS,
    };
    use windows_sys::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtRender,
        EvtRenderEventXml, EVT_HANDLE,
    };

    let channel_wide = wide_null(channel.channel_path());
    let query_text = ssh_channel_query(metrics.last_record_id());
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
        return Err(ssh_error(format!(
            "windows_ssh_event_log_query_error_{code}"
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
                WINDOWS_SSH_OPERATIONAL_EVENTLOG_TIMEOUT_MS,
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
            return Err(ssh_error(format!(
                "windows_ssh_event_log_next_error_{code}"
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
                    match parse_transient_ssh_event_xml(&xml, channel) {
                        Some(transient) if schema_allowed(&transient) => {
                            let previous = metrics.last_record_id();
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
                            metrics.store_last_record_id(transient.record_id);
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
            if read_count >= WINDOWS_SSH_OPERATIONAL_QUERY_LIMIT {
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
            return Err(ssh_error(format!(
                "windows_ssh_event_log_render_probe_error_{code}"
            )));
        }
    }
    if buffer_used == 0 || buffer_used as usize > WINDOWS_SSH_OPERATIONAL_MAX_RENDERED_XML_BYTES {
        return Err(ssh_error("windows_ssh_event_log_render_size_invalid"));
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
        return Err(ssh_error(format!(
            "windows_ssh_event_log_render_error_{code}"
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
fn ssh_channel_query(last_record_id: u64) -> String {
    let event_filter = "(EventID=3 or EventID=4)";
    if last_record_id > 0 {
        format!("*[System[{event_filter} and EventRecordID>{last_record_id}]]")
    } else {
        format!("*[System[{event_filter} and TimeCreated[timediff(@SystemTime) <= 90000]]]")
    }
}

fn parse_transient_ssh_event_xml(
    xml: &str,
    channel: SshOperationalChannel,
) -> Option<SshOperationalTransientEvent> {
    if xml.len() > WINDOWS_SSH_OPERATIONAL_MAX_RENDERED_XML_BYTES {
        return None;
    }
    let provider = attribute_value(xml, "Provider", "Name")?;
    if provider != "OpenSSH" {
        return None;
    }
    let channel_name = tag_text(xml, "Channel")?;
    if channel_name != channel.channel_path() {
        return None;
    }
    let event_id = tag_text(xml, "EventID")?.parse::<u16>().ok()?;
    let version = tag_text(xml, "Version")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0);
    let record_id = tag_text(xml, "EventRecordID")?.parse::<u64>().ok()?;
    let system_time = attribute_value(xml, "TimeCreated", "SystemTime");
    let data = data_texts(xml);
    let message = data.get(1).or_else(|| data.first())?;
    if message.len() > WINDOWS_SSH_OPERATIONAL_MAX_MESSAGE_BYTES {
        return None;
    }
    Some(SshOperationalTransientEvent {
        channel,
        record_id,
        event_id,
        version,
        system_time,
        message_match: classify_ssh_message(event_id, version, message),
    })
}

fn normalize_transient_ssh_event(
    transient: SshOperationalTransientEvent,
) -> Option<WindowsAuthRemoteObservation> {
    let message_match = transient.message_match?;
    let schema_category = schema_category(message_match.schema);
    let auth_result = ssh_auth_result(message_match.schema);
    let event_category = ssh_event_category(message_match.schema);
    let identity_ref = message_match
        .identity_seed
        .as_deref()
        .map(|seed| hashed_ref("ssh_actor", seed));
    let source_ref = message_match
        .source_seed
        .as_deref()
        .map(|seed| hashed_ref("ssh_source", seed))
        .or_else(|| Some("ssh_source_scope_unavailable".to_string()));
    let observation = WindowsAuthRemoteObservation {
        observation_ref: hashed_ref(
            "ssh_obs",
            &format!(
                "{}|{}|{}|{:?}",
                transient.channel.channel_ref(),
                transient.event_id,
                transient.record_id,
                message_match.schema
            ),
        ),
        event_category,
        schema_category,
        event_version: transient.version,
        auth_result,
        auth_mechanism: ssh_auth_mechanism(message_match.schema),
        account_category: ssh_account_category(message_match.schema),
        privilege_bucket: WindowsAuthPrivilegeBucket::Unknown,
        remote_protocol_category: Some(WindowsRemoteProtocolCategory::Ssh),
        failure_category: ssh_failure_category(message_match.schema),
        repeated_failure_bucket: (auth_result == WindowsAuthResultCategory::Failure)
            .then_some(PortableAuthAttemptCountBucket::One),
        success_after_failure: false,
        identity_ref,
        source_ref,
        target_ref: Some("ssh_service_scope".to_string()),
        observed_bucket: WindowsAuthObservedBucket::ExistingHostEvents,
        source_reliability: WindowsAuthSourceReliability::OptionalChannelVerified,
        freshness: freshness(transient.system_time.as_deref()),
        provenance_ref: "windows_openssh_operational_event_log".to_string(),
        missing_visibility: ssh_missing_visibility(message_match.schema),
        time_bucket_start: Timestamp::now(),
        redaction_status: if ssh_schema_has_auth_context(schema_category) {
            RedactionStatus::Hashed
        } else {
            RedactionStatus::Redacted
        },
        quality_score: QualityScore::new(0.63).ok()?,
    };
    observation.validate().ok()?;
    Some(observation)
}

fn allowlisted_channels() -> [SshOperationalChannel; 1] {
    [SshOperationalChannel::OpenSshOperational]
}

fn schema_allowed(transient: &SshOperationalTransientEvent) -> bool {
    transient.channel == SshOperationalChannel::OpenSshOperational
        && transient.version == 0
        && matches!(transient.event_id, 3 | 4)
        && transient.message_match.is_some()
}

fn classify_ssh_message(
    event_id: u16,
    version: u8,
    message: &str,
) -> Option<SshOperationalMessageMatch> {
    if version != 0 {
        return None;
    }
    let tokens = message.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return None;
    }
    match event_id {
        4 => classify_ssh_info_message(message, &tokens),
        3 => classify_ssh_warning_message(message, &tokens),
        _ => None,
    }
}

fn classify_ssh_info_message(
    _message: &str,
    tokens: &[&str],
) -> Option<SshOperationalMessageMatch> {
    if let Some(matched) = parse_accepted_or_failed_auth(tokens) {
        return Some(matched);
    }
    if tokens.len() >= 7
        && tokens[0] == "Invalid"
        && tokens[1] == "user"
        && tokens[3] == "from"
        && tokens[5] == "port"
    {
        return Some(SshOperationalMessageMatch {
            schema: SshOperationalMessageSchema::InvalidUser,
            identity_seed: Some(tokens[2].to_string()),
            source_seed: Some(format!("{}:{}", tokens[4], tokens[6])),
        });
    }
    if tokens.len() >= 9
        && tokens[0] == "Connection"
        && tokens[1] == "from"
        && tokens[3] == "port"
        && tokens[5] == "on"
        && tokens[7] == "port"
    {
        return Some(SshOperationalMessageMatch {
            schema: SshOperationalMessageSchema::ConnectionOpened,
            identity_seed: None,
            source_seed: Some(format!("{}:{}", tokens[2], tokens[4])),
        });
    }
    if tokens.len() >= 6
        && tokens[0] == "pam_unix(sshd:session):"
        && tokens[1] == "session"
        && matches!(tokens[2], "opened" | "closed")
        && tokens[3] == "for"
        && tokens[4] == "user"
    {
        let schema = if tokens[2] == "opened" {
            SshOperationalMessageSchema::SessionOpened
        } else {
            SshOperationalMessageSchema::SessionClosed
        };
        return Some(SshOperationalMessageMatch {
            schema,
            identity_seed: Some(tokens[5].to_string()),
            source_seed: None,
        });
    }
    if tokens.len() >= 7
        && tokens[0] == "subsystem"
        && tokens[1] == "request"
        && tokens[2] == "for"
        && tokens[4] == "by"
        && tokens[5] == "user"
    {
        return Some(SshOperationalMessageMatch {
            schema: SshOperationalMessageSchema::SubsystemRequested,
            identity_seed: Some(tokens[6].to_string()),
            source_seed: None,
        });
    }
    if tokens.len() >= 6
        && tokens[0] == "Received"
        && tokens[1] == "disconnect"
        && tokens[2] == "from"
        && tokens[4] == "port"
    {
        return Some(SshOperationalMessageMatch {
            schema: SshOperationalMessageSchema::Disconnect,
            identity_seed: None,
            source_seed: Some(format!("{}:{}", tokens[3], tokens[5].trim_end_matches(':'))),
        });
    }
    None
}

fn parse_accepted_or_failed_auth(tokens: &[&str]) -> Option<SshOperationalMessageMatch> {
    let result = *tokens.first()?;
    if !matches!(result, "Accepted" | "Failed") {
        return None;
    }
    let mechanism = *tokens.get(1)?;
    if !matches!(mechanism, "publickey" | "password") {
        return None;
    }
    if tokens.get(2).copied()? != "for" {
        return None;
    }
    let (identity_index, from_index) =
        if tokens.get(3) == Some(&"invalid") && tokens.get(4) == Some(&"user") {
            (5, 6)
        } else {
            (3, 4)
        };
    let ssh2_token = tokens.get(from_index + 4).copied()?;
    if tokens.get(from_index).copied()? != "from"
        || tokens.get(from_index + 2).copied()? != "port"
        || ssh2_token.trim_end_matches(':') != "ssh2"
    {
        return None;
    }
    let schema = match (result, mechanism) {
        ("Accepted", "publickey") => SshOperationalMessageSchema::AuthSuccessPublicKey,
        ("Accepted", "password") => SshOperationalMessageSchema::AuthSuccessPassword,
        ("Failed", "publickey") => SshOperationalMessageSchema::AuthFailurePublicKey,
        ("Failed", "password") => SshOperationalMessageSchema::AuthFailurePassword,
        _ => return None,
    };
    Some(SshOperationalMessageMatch {
        schema,
        identity_seed: tokens.get(identity_index).map(|value| (*value).to_string()),
        source_seed: Some(format!(
            "{}:{}",
            tokens.get(from_index + 1)?,
            tokens.get(from_index + 3)?
        )),
    })
}

fn classify_ssh_warning_message(
    message: &str,
    tokens: &[&str],
) -> Option<SshOperationalMessageMatch> {
    if tokens.first() == Some(&"userauth_pubkey:")
        && message.ends_with("[preauth]")
        && message.contains("not in PubkeyAcceptedAlgorithms")
    {
        return Some(SshOperationalMessageMatch {
            schema: SshOperationalMessageSchema::PolicyRejection,
            identity_seed: None,
            source_seed: None,
        });
    }
    if message.starts_with("Authentication refused: bad ownership or modes") {
        return Some(SshOperationalMessageMatch {
            schema: SshOperationalMessageSchema::PolicyRejection,
            identity_seed: None,
            source_seed: None,
        });
    }
    if tokens.len() >= 7
        && tokens[0] == "Unable"
        && tokens[1] == "to"
        && tokens[2] == "negotiate"
        && tokens[3] == "with"
        && tokens[5] == "port"
        && message.contains("no matching key exchange method found")
    {
        return Some(SshOperationalMessageMatch {
            schema: SshOperationalMessageSchema::KeyExchangeFailure,
            identity_seed: None,
            source_seed: Some(format!("{}:{}", tokens[4], tokens[6].trim_end_matches(':'))),
        });
    }
    if message.starts_with("kex_exchange_identification:")
        || message.starts_with("Bad protocol version identification")
    {
        return Some(SshOperationalMessageMatch {
            schema: SshOperationalMessageSchema::ProtocolError,
            identity_seed: None,
            source_seed: None,
        });
    }
    None
}

fn schema_category(schema: SshOperationalMessageSchema) -> WindowsAuthSchemaCategory {
    match schema {
        SshOperationalMessageSchema::AuthSuccessPublicKey => {
            WindowsAuthSchemaCategory::OpenSshOperational4AuthSuccessPublicKeyV0
        }
        SshOperationalMessageSchema::AuthSuccessPassword => {
            WindowsAuthSchemaCategory::OpenSshOperational4AuthSuccessPasswordV0
        }
        SshOperationalMessageSchema::AuthFailurePublicKey => {
            WindowsAuthSchemaCategory::OpenSshOperational4AuthFailurePublicKeyV0
        }
        SshOperationalMessageSchema::AuthFailurePassword => {
            WindowsAuthSchemaCategory::OpenSshOperational4AuthFailurePasswordV0
        }
        SshOperationalMessageSchema::InvalidUser => {
            WindowsAuthSchemaCategory::OpenSshOperational4InvalidUserV0
        }
        SshOperationalMessageSchema::ConnectionOpened => {
            WindowsAuthSchemaCategory::OpenSshOperational4ConnectionOpenedV0
        }
        SshOperationalMessageSchema::SessionOpened => {
            WindowsAuthSchemaCategory::OpenSshOperational4SessionOpenedV0
        }
        SshOperationalMessageSchema::SessionClosed => {
            WindowsAuthSchemaCategory::OpenSshOperational4SessionClosedV0
        }
        SshOperationalMessageSchema::SubsystemRequested => {
            WindowsAuthSchemaCategory::OpenSshOperational4SubsystemRequestedV0
        }
        SshOperationalMessageSchema::Disconnect => {
            WindowsAuthSchemaCategory::OpenSshOperational4DisconnectV0
        }
        SshOperationalMessageSchema::PolicyRejection => {
            WindowsAuthSchemaCategory::OpenSshOperational3PolicyRejectionV0
        }
        SshOperationalMessageSchema::ProtocolError => {
            WindowsAuthSchemaCategory::OpenSshOperational3ProtocolErrorV0
        }
        SshOperationalMessageSchema::KeyExchangeFailure => {
            WindowsAuthSchemaCategory::OpenSshOperational3KeyExchangeFailureV0
        }
    }
}

pub fn ssh_schema_has_auth_context(schema: WindowsAuthSchemaCategory) -> bool {
    matches!(
        schema,
        WindowsAuthSchemaCategory::OpenSshOperational4AuthSuccessPublicKeyV0
            | WindowsAuthSchemaCategory::OpenSshOperational4AuthSuccessPasswordV0
            | WindowsAuthSchemaCategory::OpenSshOperational4AuthFailurePublicKeyV0
            | WindowsAuthSchemaCategory::OpenSshOperational4AuthFailurePasswordV0
            | WindowsAuthSchemaCategory::OpenSshOperational4InvalidUserV0
            | WindowsAuthSchemaCategory::OpenSshOperational3PolicyRejectionV0
    )
}

fn ssh_event_category(schema: SshOperationalMessageSchema) -> WindowsAuthRemoteEventId {
    match schema {
        SshOperationalMessageSchema::AuthSuccessPublicKey
        | SshOperationalMessageSchema::AuthSuccessPassword => {
            WindowsAuthRemoteEventId::SuccessfulLogon
        }
        SshOperationalMessageSchema::AuthFailurePublicKey
        | SshOperationalMessageSchema::AuthFailurePassword
        | SshOperationalMessageSchema::InvalidUser
        | SshOperationalMessageSchema::PolicyRejection => WindowsAuthRemoteEventId::FailedLogon,
        SshOperationalMessageSchema::SessionClosed => WindowsAuthRemoteEventId::Logoff,
        _ => WindowsAuthRemoteEventId::Unknown,
    }
}

fn ssh_auth_result(schema: SshOperationalMessageSchema) -> WindowsAuthResultCategory {
    match schema {
        SshOperationalMessageSchema::AuthSuccessPublicKey
        | SshOperationalMessageSchema::AuthSuccessPassword => WindowsAuthResultCategory::Success,
        SshOperationalMessageSchema::AuthFailurePublicKey
        | SshOperationalMessageSchema::AuthFailurePassword
        | SshOperationalMessageSchema::InvalidUser
        | SshOperationalMessageSchema::PolicyRejection => WindowsAuthResultCategory::Failure,
        SshOperationalMessageSchema::SessionClosed => WindowsAuthResultCategory::Logoff,
        _ => WindowsAuthResultCategory::Unknown,
    }
}

fn ssh_auth_mechanism(schema: SshOperationalMessageSchema) -> WindowsAuthMechanismCategory {
    match schema {
        SshOperationalMessageSchema::AuthSuccessPublicKey
        | SshOperationalMessageSchema::AuthFailurePublicKey
        | SshOperationalMessageSchema::PolicyRejection => WindowsAuthMechanismCategory::Unknown,
        SshOperationalMessageSchema::AuthSuccessPassword
        | SshOperationalMessageSchema::AuthFailurePassword => {
            WindowsAuthMechanismCategory::ExplicitCredential
        }
        _ => WindowsAuthMechanismCategory::Unknown,
    }
}

fn ssh_account_category(_schema: SshOperationalMessageSchema) -> WindowsAuthAccountCategory {
    WindowsAuthAccountCategory::Unknown
}

fn ssh_failure_category(schema: SshOperationalMessageSchema) -> Option<WindowsAuthFailureCategory> {
    match schema {
        SshOperationalMessageSchema::AuthFailurePassword => {
            Some(WindowsAuthFailureCategory::BadSecret)
        }
        SshOperationalMessageSchema::InvalidUser => {
            Some(WindowsAuthFailureCategory::UnknownIdentity)
        }
        SshOperationalMessageSchema::AuthFailurePublicKey
        | SshOperationalMessageSchema::PolicyRejection => {
            Some(WindowsAuthFailureCategory::NotAllowed)
        }
        SshOperationalMessageSchema::ProtocolError
        | SshOperationalMessageSchema::KeyExchangeFailure => {
            Some(WindowsAuthFailureCategory::ProtocolFailure)
        }
        _ => None,
    }
}

fn ssh_missing_visibility(schema: SshOperationalMessageSchema) -> Vec<String> {
    let mut flags = vec![
        "ssh_actor_ref_bucketed".to_string(),
        "ssh_peer_ref_bucketed".to_string(),
        "ssh_crypto_detail_absent".to_string(),
        "flow_session_visibility_unavailable".to_string(),
        "runtime_relation_unavailable".to_string(),
        "exec_detail_not_collected".to_string(),
    ];
    if !matches!(
        schema,
        SshOperationalMessageSchema::AuthSuccessPublicKey
            | SshOperationalMessageSchema::AuthSuccessPassword
            | SshOperationalMessageSchema::AuthFailurePublicKey
            | SshOperationalMessageSchema::AuthFailurePassword
            | SshOperationalMessageSchema::InvalidUser
            | SshOperationalMessageSchema::PolicyRejection
    ) {
        flags.push("non_auth_schema_auth_dispatch_skipped".to_string());
    }
    flags
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

fn data_texts(xml: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut offset = 0_usize;
    while let Some(start) = xml[offset..].find("<Data") {
        let tag_start = offset + start;
        let Some(tag_end_rel) = xml[tag_start..].find('>') else {
            break;
        };
        let value_start = tag_start + tag_end_rel + 1;
        let Some(value_end_rel) = xml[value_start..].find("</Data>") else {
            break;
        };
        let value_end = value_start + value_end_rel;
        values.push(xml[value_start..value_end].trim().to_string());
        offset = value_end + "</Data>".len();
    }
    values
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

fn counters_from_metrics(
    metrics: &SshOperationalMetrics,
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
    metrics: &SshOperationalMetrics,
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
            Some("windows_ssh_operational_event_log_not_yet_ready".to_string())
        },
    }
}

fn rate_limit_allows(metrics: &SshOperationalMetrics) -> bool {
    let current_second = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let observed = metrics.rate_window_second.load(Ordering::Relaxed);
    if observed == current_second {
        metrics.rate_window_count.fetch_add(1, Ordering::Relaxed)
            < WINDOWS_SSH_OPERATIONAL_MAX_EVENTS_PER_SECOND
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
    hasher.update(WINDOWS_SSH_OPERATIONAL_ALLOWLIST_REF.as_bytes());
    hasher.update(b":session-scoped:");
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    format!(
        "{prefix}_ref_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]
    )
}

fn cursor_ref(metrics: &SshOperationalMetrics) -> String {
    let record_id = metrics.last_record_id.load(Ordering::Relaxed);
    if record_id == 0 {
        "ssh_event_log_cursor_not_observed".to_string()
    } else {
        hashed_ref("ssh_event_log_cursor", &record_id.to_string())
    }
}

fn ssh_error(reason: impl Into<String>) -> WindowsAuthRemoteEventLogError {
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
        "ticket",
        "c:\\",
        "\\users\\",
        "authorized_keys",
        "fingerprint",
        "command",
        "subsystem",
        "ipaddress",
        "hostname",
        "eventrecordid",
        "pid",
        "port",
        "nonce",
        "secret",
    ] {
        if lowered.contains(marker) {
            return "windows_ssh_operational_event_log_error_redacted".to_string();
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

    fn ssh_xml(event_id: u16, message: &str) -> String {
        format!(
            r#"
        <Event>
          <System>
            <Provider Name="OpenSSH"/>
            <EventID>{event_id}</EventID>
            <Version>0</Version>
            <Channel>OpenSSH/Operational</Channel>
            <EventRecordID>77</EventRecordID>
            <TimeCreated SystemTime="2026-06-16T00:00:00.000Z"/>
          </System>
          <EventData>
            <Data>sshd</Data>
            <Data>{message}</Data>
          </EventData>
        </Event>
        "#
        )
    }

    #[test]
    fn adapter_declares_infrastructure_only_privacy_boundary() {
        let metadata = WindowsSshOperationalEventLogAdapter::new().adapter_metadata();
        assert!(metadata.validate().is_ok());
        assert_eq!(
            metadata.provider_kind,
            NetworkProviderKind::WindowsSshOperational
        );
        assert!(!metadata.ownership.owns_event_bus);
        assert!(!metadata.ownership.owns_dag);
        assert!(!metadata.ownership.owns_plugin_runtime);
        assert!(metadata
            .privacy_notes
            .iter()
            .any(|note| note == "openssh_operational_channel_allowlist_only"));
    }

    #[test]
    fn channel_and_schema_allowlists_are_exact_and_bounded() {
        let channels = allowlisted_channels();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].channel_path(), "OpenSSH/Operational");
        let accepted = parse_transient_ssh_event_xml(
            &ssh_xml(
                4,
                "Accepted publickey for alice from 192.0.2.44 port 55222 ssh2: RSA SHA256:abc",
            ),
            SshOperationalChannel::OpenSshOperational,
        )
        .expect("accepted transient");
        assert!(schema_allowed(&accepted));
        let wrong_version = r#"
        <Event><System><Provider Name="OpenSSH"/><EventID>4</EventID><Version>9</Version><Channel>OpenSSH/Operational</Channel><EventRecordID>1</EventRecordID></System><EventData><Data>sshd</Data><Data>Accepted password for alice from 192.0.2.1 port 555 ssh2</Data></EventData></Event>
        "#;
        let rejected =
            parse_transient_ssh_event_xml(wrong_version, SshOperationalChannel::OpenSshOperational)
                .expect("transient");
        assert!(!schema_allowed(&rejected));
    }

    #[test]
    fn parser_extracts_transient_fields_without_outputting_raw_values() {
        let xml = ssh_xml(
            4,
            "Accepted publickey for alice from 192.0.2.44 port 55222 ssh2: RSA SHA256:rawfingerprint",
        );
        let transient =
            parse_transient_ssh_event_xml(&xml, SshOperationalChannel::OpenSshOperational)
                .expect("transient ssh event");
        let observation = normalize_transient_ssh_event(transient).expect("observation");
        assert_eq!(
            observation.remote_protocol_category,
            Some(WindowsRemoteProtocolCategory::Ssh)
        );
        assert_eq!(
            observation.schema_category,
            WindowsAuthSchemaCategory::OpenSshOperational4AuthSuccessPublicKeyV0
        );
        let serialized = serde_json::to_string(&observation).expect("json");
        for forbidden in [
            "alice",
            "192.0.2.44",
            "55222",
            "rawfingerprint",
            "RSA",
            "SHA256",
            "publickey for",
        ] {
            assert!(
                !serialized
                    .to_ascii_lowercase()
                    .contains(&forbidden.to_ascii_lowercase()),
                "SSH observation leaked raw value {forbidden}: {serialized}"
            );
        }
    }

    #[test]
    fn unknown_message_schema_is_rejected_without_auth_context() {
        let xml = ssh_xml(4, "Server listening on 0.0.0.0 port 22.");
        let transient =
            parse_transient_ssh_event_xml(&xml, SshOperationalChannel::OpenSshOperational)
                .expect("transient ssh event");
        assert!(!schema_allowed(&transient));
        assert!(normalize_transient_ssh_event(transient).is_none());
    }

    #[test]
    fn auth_capable_schema_is_distinct_from_non_auth_operational_schema() {
        assert!(ssh_schema_has_auth_context(
            WindowsAuthSchemaCategory::OpenSshOperational4AuthFailurePasswordV0
        ));
        assert!(ssh_schema_has_auth_context(
            WindowsAuthSchemaCategory::OpenSshOperational3PolicyRejectionV0
        ));
        assert!(!ssh_schema_has_auth_context(
            WindowsAuthSchemaCategory::OpenSshOperational4SessionClosedV0
        ));
        assert!(!ssh_schema_has_auth_context(
            WindowsAuthSchemaCategory::OpenSshOperational3KeyExchangeFailureV0
        ));
    }

    #[test]
    fn rate_limit_counts_are_bounded() {
        let metrics = SshOperationalMetrics::default();
        for _ in 0..WINDOWS_SSH_OPERATIONAL_MAX_EVENTS_PER_SECOND {
            assert!(rate_limit_allows(&metrics));
        }
        assert!(!rate_limit_allows(&metrics));
    }

    #[test]
    fn batch_queue_overflow_counts_drop_without_unbounded_growth() {
        let metrics = SshOperationalMetrics::default();
        let (sender, _receiver) = mpsc::sync_channel(0);
        let mut pending = vec![WindowsAuthRemoteObservation {
            observation_ref: "ssh_obs_ref_test".to_string(),
            event_category: WindowsAuthRemoteEventId::FailedLogon,
            schema_category: WindowsAuthSchemaCategory::OpenSshOperational4AuthFailurePasswordV0,
            event_version: 0,
            auth_result: WindowsAuthResultCategory::Failure,
            auth_mechanism: WindowsAuthMechanismCategory::ExplicitCredential,
            account_category: WindowsAuthAccountCategory::Unknown,
            privilege_bucket: WindowsAuthPrivilegeBucket::Unknown,
            remote_protocol_category: Some(WindowsRemoteProtocolCategory::Ssh),
            failure_category: Some(WindowsAuthFailureCategory::BadSecret),
            repeated_failure_bucket: Some(PortableAuthAttemptCountBucket::One),
            success_after_failure: false,
            identity_ref: Some("ssh_actor_ref_test".to_string()),
            source_ref: Some("ssh_source_ref_test".to_string()),
            target_ref: Some("ssh_service_scope".to_string()),
            observed_bucket: WindowsAuthObservedBucket::ExistingHostEvents,
            source_reliability: WindowsAuthSourceReliability::OptionalChannelVerified,
            freshness: WindowsAuthFreshnessCategory::Recent,
            provenance_ref: "windows_openssh_operational_event_log".to_string(),
            missing_visibility: vec!["ssh_actor_ref_bucketed".to_string()],
            time_bucket_start: Timestamp::now(),
            redaction_status: RedactionStatus::Hashed,
            quality_score: QualityScore::new(0.63).expect("quality"),
        }];
        flush_ssh_operational_batch(&mut pending, &sender, &metrics);
        assert_eq!(pending.len(), 0);
        assert_eq!(metrics.queue_dropped_events.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cursor_ref_is_bounded_and_not_raw_event_record_id() {
        let metrics = SshOperationalMetrics::default();
        assert_eq!(cursor_ref(&metrics), "ssh_event_log_cursor_not_observed");
        metrics.store_last_record_id(77);
        let cursor = cursor_ref(&metrics);
        assert!(cursor.starts_with("ssh_event_log_cursor_ref_"));
        assert!(!cursor.contains("77"));
    }
}
