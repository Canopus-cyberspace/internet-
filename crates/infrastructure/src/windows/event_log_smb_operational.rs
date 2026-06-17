//! Bounded Windows SMB operational/security Event Log source adapter.
//!
//! The adapter owns only Windows Event Log handles, bounded queues, cursors,
//! counters, and privacy-safe normalization. It reuses the bounded
//! auth/remote observation batch for downstream product handoff and does not
//! own EventBus, DAG, PluginRuntime, RuntimeContainer, read models, storage,
//! schedulers, or detectors.

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

pub const WINDOWS_SMB_OPERATIONAL_EVENT_LOG_ADAPTER_ID: &str =
    "windows_smb_operational_event_log_adapter";
pub const WINDOWS_SMB_OPERATIONAL_ALLOWLIST_REF: &str =
    "windows_smb_operational_event_log_allowlist_v1";
pub const WINDOWS_SMB_OPERATIONAL_RAW_QUEUE_CAPACITY: usize = 512;
pub const WINDOWS_SMB_OPERATIONAL_BATCH_QUEUE_CAPACITY: usize = 16;
pub const WINDOWS_SMB_OPERATIONAL_MAX_EVENTS_PER_SECOND: u32 = 512;
pub const WINDOWS_SMB_OPERATIONAL_MAX_DRAIN_BATCHES: usize = 16;
pub const WINDOWS_SMB_OPERATIONAL_BATCH_SIZE: usize = 64;
const WINDOWS_SMB_OPERATIONAL_POLL_INTERVAL: Duration = Duration::from_millis(250);
#[cfg(windows)]
const WINDOWS_SMB_OPERATIONAL_EVENTLOG_TIMEOUT_MS: u32 = 100;
#[cfg(windows)]
const WINDOWS_SMB_OPERATIONAL_QUERY_LIMIT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmbOperationalChannel {
    ClientConnectivity,
    ClientSecurity,
    ServerOperational,
    ServerSecurity,
}

impl SmbOperationalChannel {
    const fn channel_path(self) -> &'static str {
        match self {
            Self::ClientConnectivity => "Microsoft-Windows-SmbClient/Connectivity",
            Self::ClientSecurity => "Microsoft-Windows-SmbClient/Security",
            Self::ServerOperational => "Microsoft-Windows-SMBServer/Operational",
            Self::ServerSecurity => "Microsoft-Windows-SMBServer/Security",
        }
    }

    const fn channel_ref(self) -> &'static str {
        match self {
            Self::ClientConnectivity => "smbclient_connectivity",
            Self::ClientSecurity => "smbclient_security",
            Self::ServerOperational => "smbserver_operational",
            Self::ServerSecurity => "smbserver_security",
        }
    }

    const fn role_ref(self) -> &'static str {
        match self {
            Self::ClientConnectivity | Self::ClientSecurity => "smb_client_role",
            Self::ServerOperational | Self::ServerSecurity => "smb_server_role",
        }
    }
}

pub struct WindowsSmbOperationalEventLogAdapter {
    state: WindowsAuthRemoteControlState,
    #[cfg(windows)]
    active_session: Option<WindowsSmbOperationalEventLogSession>,
}

impl WindowsSmbOperationalEventLogAdapter {
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

impl Default for WindowsSmbOperationalEventLogAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderProbe for WindowsSmbOperationalEventLogAdapter {
    fn adapter_metadata(&self) -> ProviderAdapterMetadata {
        ProviderAdapterMetadata {
            adapter_id: WINDOWS_SMB_OPERATIONAL_EVENT_LOG_ADAPTER_ID.to_string(),
            provider_kind: NetworkProviderKind::WindowsSmbOperational,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            ownership: ProviderAdapterOwnership::infrastructure_adapter(),
            supported_request_refs: vec![
                "explicit_windows_smb_operational_lifecycle_request".to_string()
            ],
            supported_result_refs: vec!["bounded_windows_smb_operational_batch_result".to_string()],
            privacy_notes: vec![
                "smb_channel_allowlist_only".to_string(),
                "event_xml_transient".to_string(),
                "bounded_polling_cursor_no_overlap".to_string(),
                "share_unc_identity_network_values_discarded".to_string(),
                "no_smb_configuration_or_connection_side_effects".to_string(),
            ],
            redaction_status: RedactionStatus::Redacted,
        }
    }
}

impl WindowsAuthRemoteEventLogControl for WindowsSmbOperationalEventLogAdapter {
    fn start(
        &mut self,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
        if self.state == WindowsAuthRemoteControlState::Active {
            #[cfg(windows)]
            return self
                .active_session
                .as_mut()
                .map(WindowsSmbOperationalEventLogSession::outcome)
                .unwrap_or_else(|| Ok(Self::inactive_outcome(self.state)));
            #[cfg(not(windows))]
            return Ok(Self::inactive_outcome(self.state));
        }
        #[cfg(windows)]
        {
            let mut session = WindowsSmbOperationalEventLogSession::start()?;
            let outcome = session.outcome()?;
            self.active_session = Some(session);
            self.state = WindowsAuthRemoteControlState::Active;
            Ok(outcome)
        }
        #[cfg(not(windows))]
        {
            self.state = WindowsAuthRemoteControlState::Unavailable;
            Err(smb_error(
                "windows_smb_operational_event_log_unsupported_platform",
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

impl Drop for WindowsSmbOperationalEventLogAdapter {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Clone, Debug)]
struct SmbOperationalTransientEvent {
    channel: SmbOperationalChannel,
    record_id: u64,
    event_id: u16,
    version: u8,
    system_time: Option<String>,
}

#[derive(Default)]
struct SmbOperationalMetrics {
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
    client_connectivity_last_record_id: AtomicU64,
    client_security_last_record_id: AtomicU64,
    server_operational_last_record_id: AtomicU64,
    server_security_last_record_id: AtomicU64,
    worker_active: AtomicBool,
    normalizer_active: AtomicBool,
    channels_ready: AtomicU32,
    channels_unavailable: AtomicU32,
}

impl SmbOperationalMetrics {
    fn workers_active(&self) -> bool {
        self.worker_active.load(Ordering::SeqCst) || self.normalizer_active.load(Ordering::SeqCst)
    }

    fn last_record_id(&self, channel: SmbOperationalChannel) -> u64 {
        match channel {
            SmbOperationalChannel::ClientConnectivity => self
                .client_connectivity_last_record_id
                .load(Ordering::Relaxed),
            SmbOperationalChannel::ClientSecurity => {
                self.client_security_last_record_id.load(Ordering::Relaxed)
            }
            SmbOperationalChannel::ServerOperational => self
                .server_operational_last_record_id
                .load(Ordering::Relaxed),
            SmbOperationalChannel::ServerSecurity => {
                self.server_security_last_record_id.load(Ordering::Relaxed)
            }
        }
    }

    fn store_last_record_id(&self, channel: SmbOperationalChannel, record_id: u64) {
        match channel {
            SmbOperationalChannel::ClientConnectivity => self
                .client_connectivity_last_record_id
                .store(record_id, Ordering::Relaxed),
            SmbOperationalChannel::ClientSecurity => self
                .client_security_last_record_id
                .store(record_id, Ordering::Relaxed),
            SmbOperationalChannel::ServerOperational => self
                .server_operational_last_record_id
                .store(record_id, Ordering::Relaxed),
            SmbOperationalChannel::ServerSecurity => self
                .server_security_last_record_id
                .store(record_id, Ordering::Relaxed),
        }
    }
}

#[cfg(windows)]
struct WindowsSmbOperationalEventLogSession {
    batch_receiver: Receiver<WindowsAuthRemoteObservationBatch>,
    metrics: Arc<SmbOperationalMetrics>,
    cancellation: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    reader_thread: Option<JoinHandle<()>>,
    normalizer_thread: Option<JoinHandle<()>>,
    stopped: bool,
}

#[cfg(windows)]
impl WindowsSmbOperationalEventLogSession {
    fn start() -> Result<Self, WindowsAuthRemoteEventLogError> {
        let metrics = Arc::new(SmbOperationalMetrics::default());
        let cancellation = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let (raw_sender, raw_receiver) =
            mpsc::sync_channel(WINDOWS_SMB_OPERATIONAL_RAW_QUEUE_CAPACITY);
        let (batch_sender, batch_receiver) =
            mpsc::sync_channel(WINDOWS_SMB_OPERATIONAL_BATCH_QUEUE_CAPACITY);

        poll_smb_events_once(&raw_sender, &metrics)?;

        let reader_metrics = Arc::clone(&metrics);
        let reader_cancel = Arc::clone(&cancellation);
        let reader_paused = Arc::clone(&paused);
        let reader_thread = thread::spawn(move || {
            reader_metrics.worker_active.store(true, Ordering::SeqCst);
            run_smb_event_log_reader(raw_sender, reader_metrics, reader_cancel, reader_paused);
        });

        let normalizer_metrics = Arc::clone(&metrics);
        let normalizer_cancel = Arc::clone(&cancellation);
        let normalizer_thread = thread::spawn(move || {
            normalizer_metrics
                .normalizer_active
                .store(true, Ordering::SeqCst);
            run_smb_event_log_normalizer(
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
            if batches.len() >= WINDOWS_SMB_OPERATIONAL_MAX_DRAIN_BATCHES {
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
        for _ in 0..max_batches.min(WINDOWS_SMB_OPERATIONAL_MAX_DRAIN_BATCHES) {
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
            Some("windows_smb_operational_event_log_stopped".to_string())
        } else {
            Some("windows_smb_operational_event_log_join_failed".to_string())
        };
        if !outcome.consumer_worker_joined {
            return Err(smb_error("windows_smb_operational_event_log_join_failed"));
        }
        Ok(outcome)
    }
}

#[cfg(windows)]
impl Drop for WindowsSmbOperationalEventLogSession {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.stop();
        }
    }
}

#[cfg(windows)]
fn run_smb_event_log_reader(
    sender: SyncSender<SmbOperationalTransientEvent>,
    metrics: Arc<SmbOperationalMetrics>,
    cancellation: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) {
    while !cancellation.load(Ordering::SeqCst) {
        if paused.load(Ordering::SeqCst) {
            thread::sleep(WINDOWS_SMB_OPERATIONAL_POLL_INTERVAL);
            continue;
        }
        if poll_smb_events_once(&sender, &metrics).is_err() {
            thread::sleep(WINDOWS_SMB_OPERATIONAL_POLL_INTERVAL);
        }
        thread::sleep(WINDOWS_SMB_OPERATIONAL_POLL_INTERVAL);
    }
    metrics.worker_active.store(false, Ordering::SeqCst);
}

#[cfg(windows)]
fn run_smb_event_log_normalizer(
    receiver: Receiver<SmbOperationalTransientEvent>,
    sender: SyncSender<WindowsAuthRemoteObservationBatch>,
    metrics: Arc<SmbOperationalMetrics>,
    cancellation: Arc<AtomicBool>,
) {
    let mut pending = Vec::with_capacity(WINDOWS_SMB_OPERATIONAL_BATCH_SIZE);
    while !cancellation.load(Ordering::SeqCst) {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(transient) => {
                if let Some(observation) = normalize_transient_smb_event(transient) {
                    metrics
                        .normalized_remote_access_observations
                        .fetch_add(1, Ordering::Relaxed);
                    if smb_schema_has_auth_context(observation.schema_category) {
                        metrics
                            .normalized_auth_observations
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    pending.push(observation);
                } else {
                    metrics.schema_rejected.fetch_add(1, Ordering::Relaxed);
                }
                if pending.len() >= WINDOWS_SMB_OPERATIONAL_BATCH_SIZE {
                    flush_smb_operational_batch(&mut pending, &sender, &metrics);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !pending.is_empty() {
                    flush_smb_operational_batch(&mut pending, &sender, &metrics);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if !pending.is_empty() {
        flush_smb_operational_batch(&mut pending, &sender, &metrics);
    }
    metrics.normalizer_active.store(false, Ordering::SeqCst);
}

fn flush_smb_operational_batch(
    pending: &mut Vec<WindowsAuthRemoteObservation>,
    sender: &SyncSender<WindowsAuthRemoteObservationBatch>,
    metrics: &SmbOperationalMetrics,
) {
    let observations = std::mem::take(pending);
    let counters = counters_from_metrics(metrics, false);
    let batch = WindowsAuthRemoteObservationBatch {
        batch_ref: format!(
            "windows_smb_operational_batch_{}",
            hashed_ref("batch", &format!("{:?}", Timestamp::now()))
        ),
        provider_ref: "windows_smb_operational_event_log".to_string(),
        schema_version: WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
        observations,
        counters,
        cursor_ref: Some(cursor_ref(metrics)),
        channel_refs: allowlisted_channels()
            .iter()
            .map(|channel| channel.channel_ref().to_string())
            .collect(),
        degraded_reason: Some("existing_host_events_or_live_smb_operational_log".to_string()),
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
fn poll_smb_events_once(
    sender: &SyncSender<SmbOperationalTransientEvent>,
    metrics: &SmbOperationalMetrics,
) -> Result<(), WindowsAuthRemoteEventLogError> {
    let mut ready = 0_u32;
    let mut unavailable = 0_u32;
    for channel in allowlisted_channels() {
        match poll_smb_channel_once(channel, sender, metrics) {
            Ok(()) => ready = ready.saturating_add(1),
            Err(_) => unavailable = unavailable.saturating_add(1),
        }
    }
    metrics.channels_ready.store(ready, Ordering::Relaxed);
    metrics
        .channels_unavailable
        .store(unavailable, Ordering::Relaxed);
    if ready == 0 && unavailable > 0 {
        Err(smb_error("windows_smb_operational_channels_unavailable"))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn poll_smb_channel_once(
    channel: SmbOperationalChannel,
    sender: &SyncSender<SmbOperationalTransientEvent>,
    metrics: &SmbOperationalMetrics,
) -> Result<(), WindowsAuthRemoteEventLogError> {
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS,
    };
    use windows_sys::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtRender,
        EvtRenderEventXml, EVT_HANDLE,
    };

    let channel_wide = wide_null(channel.channel_path());
    let query_text = smb_channel_query(channel, metrics.last_record_id(channel));
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
        return Err(smb_error(format!(
            "windows_smb_event_log_query_error_{code}"
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
                WINDOWS_SMB_OPERATIONAL_EVENTLOG_TIMEOUT_MS,
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
            return Err(smb_error(format!(
                "windows_smb_event_log_next_error_{code}"
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
                    match parse_transient_smb_event_xml(&xml, channel) {
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
            if read_count >= WINDOWS_SMB_OPERATIONAL_QUERY_LIMIT {
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
            return Err(smb_error(format!(
                "windows_smb_event_log_render_probe_error_{code}"
            )));
        }
    }
    if buffer_used == 0 || buffer_used > 256 * 1024 {
        return Err(smb_error("windows_smb_event_log_render_size_invalid"));
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
        return Err(smb_error(format!(
            "windows_smb_event_log_render_error_{code}"
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
fn smb_channel_query(channel: SmbOperationalChannel, last_record_id: u64) -> String {
    let event_filter = match channel {
        SmbOperationalChannel::ClientConnectivity => {
            "(EventID=30803 or EventID=30806 or EventID=30808 or EventID=30832 or EventID=30834 or EventID=30835)"
        }
        SmbOperationalChannel::ClientSecurity => {
            "(EventID=31017 or EventID=31019 or EventID=31020 or EventID=31023)"
        }
        SmbOperationalChannel::ServerOperational => {
            "(EventID=1001 or EventID=1003 or EventID=1004 or EventID=1005)"
        }
        SmbOperationalChannel::ServerSecurity => "(EventID=551)",
    };
    if last_record_id > 0 {
        format!("*[System[{event_filter} and EventRecordID>{last_record_id}]]")
    } else {
        format!("*[System[{event_filter} and TimeCreated[timediff(@SystemTime) <= 90000]]]")
    }
}

fn parse_transient_smb_event_xml(
    xml: &str,
    channel: SmbOperationalChannel,
) -> Option<SmbOperationalTransientEvent> {
    let event_id = tag_text(xml, "EventID")?.parse::<u16>().ok()?;
    let version = tag_text(xml, "Version")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0);
    let record_id = tag_text(xml, "EventRecordID")?.parse::<u64>().ok()?;
    let system_time = attribute_value(xml, "TimeCreated", "SystemTime");
    Some(SmbOperationalTransientEvent {
        channel,
        record_id,
        event_id,
        version,
        system_time,
    })
}

fn normalize_transient_smb_event(
    transient: SmbOperationalTransientEvent,
) -> Option<WindowsAuthRemoteObservation> {
    let schema_category =
        schema_category(transient.channel, transient.event_id, transient.version)?;
    let auth_result = smb_auth_result(schema_category);
    let event_category = smb_event_category(schema_category);
    let observation = WindowsAuthRemoteObservation {
        observation_ref: hashed_ref(
            "smb_obs",
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
        auth_mechanism: smb_auth_mechanism(schema_category),
        account_category: WindowsAuthAccountCategory::Unknown,
        privilege_bucket: WindowsAuthPrivilegeBucket::Unknown,
        remote_protocol_category: Some(WindowsRemoteProtocolCategory::Smb),
        failure_category: smb_failure_category(schema_category),
        repeated_failure_bucket: (auth_result == WindowsAuthResultCategory::Failure)
            .then_some(PortableAuthAttemptCountBucket::One),
        success_after_failure: false,
        identity_ref: None,
        source_ref: Some(transient.channel.role_ref().to_string()),
        target_ref: Some("smb_service_scope".to_string()),
        observed_bucket: WindowsAuthObservedBucket::ExistingHostEvents,
        source_reliability: WindowsAuthSourceReliability::OptionalChannelVerified,
        freshness: freshness(transient.system_time.as_deref()),
        provenance_ref: "windows_smb_operational_event_log".to_string(),
        missing_visibility: vec![
            "raw_smb_identity_discarded".to_string(),
            "raw_smb_network_endpoint_discarded".to_string(),
            "raw_smb_share_or_unc_discarded".to_string(),
            "flow_session_visibility_unavailable".to_string(),
        ],
        time_bucket_start: Timestamp::now(),
        redaction_status: RedactionStatus::Redacted,
        quality_score: QualityScore::new(0.64).ok()?,
    };
    observation.validate().ok()?;
    Some(observation)
}

fn allowlisted_channels() -> [SmbOperationalChannel; 4] {
    [
        SmbOperationalChannel::ClientConnectivity,
        SmbOperationalChannel::ClientSecurity,
        SmbOperationalChannel::ServerOperational,
        SmbOperationalChannel::ServerSecurity,
    ]
}

fn schema_allowed(channel: SmbOperationalChannel, event_id: u16, version: u8) -> bool {
    schema_category(channel, event_id, version).is_some()
}

fn schema_category(
    channel: SmbOperationalChannel,
    event_id: u16,
    version: u8,
) -> Option<WindowsAuthSchemaCategory> {
    match (channel, event_id, version) {
        (SmbOperationalChannel::ClientConnectivity, 30803, 0) => {
            Some(WindowsAuthSchemaCategory::SmbClientConnectivity30803V0)
        }
        (SmbOperationalChannel::ClientConnectivity, 30806, 2) => {
            Some(WindowsAuthSchemaCategory::SmbClientConnectivity30806V2)
        }
        (SmbOperationalChannel::ClientConnectivity, 30808, 2) => {
            Some(WindowsAuthSchemaCategory::SmbClientConnectivity30808V2)
        }
        (SmbOperationalChannel::ClientConnectivity, 30832, 0) => {
            Some(WindowsAuthSchemaCategory::SmbClientConnectivity30832V0)
        }
        (SmbOperationalChannel::ClientConnectivity, 30834, 0) => {
            Some(WindowsAuthSchemaCategory::SmbClientConnectivity30834V0)
        }
        (SmbOperationalChannel::ClientConnectivity, 30835, 0) => {
            Some(WindowsAuthSchemaCategory::SmbClientConnectivity30835V0)
        }
        (SmbOperationalChannel::ClientSecurity, 31017, 0) => {
            Some(WindowsAuthSchemaCategory::SmbClientSecurity31017V0)
        }
        (SmbOperationalChannel::ClientSecurity, 31019, 0) => {
            Some(WindowsAuthSchemaCategory::SmbClientSecurity31019V0)
        }
        (SmbOperationalChannel::ClientSecurity, 31020, 0) => {
            Some(WindowsAuthSchemaCategory::SmbClientSecurity31020V0)
        }
        (SmbOperationalChannel::ClientSecurity, 31023, 0) => {
            Some(WindowsAuthSchemaCategory::SmbClientSecurity31023V0)
        }
        (SmbOperationalChannel::ServerOperational, 1001, 1) => {
            Some(WindowsAuthSchemaCategory::SmbServerOperational1001V1)
        }
        (SmbOperationalChannel::ServerOperational, 1003, 1) => {
            Some(WindowsAuthSchemaCategory::SmbServerOperational1003V1)
        }
        (SmbOperationalChannel::ServerOperational, 1004, 1) => {
            Some(WindowsAuthSchemaCategory::SmbServerOperational1004V1)
        }
        (SmbOperationalChannel::ServerOperational, 1005, 2) => {
            Some(WindowsAuthSchemaCategory::SmbServerOperational1005V2)
        }
        (SmbOperationalChannel::ServerSecurity, 551, 1) => {
            Some(WindowsAuthSchemaCategory::SmbServerSecurity551V1)
        }
        _ => None,
    }
}

pub fn smb_schema_has_auth_context(schema: WindowsAuthSchemaCategory) -> bool {
    matches!(
        schema,
        WindowsAuthSchemaCategory::SmbClientConnectivity30832V0
            | WindowsAuthSchemaCategory::SmbClientConnectivity30834V0
            | WindowsAuthSchemaCategory::SmbClientConnectivity30835V0
            | WindowsAuthSchemaCategory::SmbClientSecurity31017V0
            | WindowsAuthSchemaCategory::SmbClientSecurity31019V0
            | WindowsAuthSchemaCategory::SmbClientSecurity31020V0
            | WindowsAuthSchemaCategory::SmbClientSecurity31023V0
            | WindowsAuthSchemaCategory::SmbServerOperational1003V1
            | WindowsAuthSchemaCategory::SmbServerOperational1004V1
            | WindowsAuthSchemaCategory::SmbServerOperational1005V2
            | WindowsAuthSchemaCategory::SmbServerSecurity551V1
    )
}

fn smb_event_category(schema: WindowsAuthSchemaCategory) -> WindowsAuthRemoteEventId {
    match schema {
        WindowsAuthSchemaCategory::SmbClientConnectivity30832V0 => {
            WindowsAuthRemoteEventId::SuccessfulLogon
        }
        schema if smb_schema_has_auth_context(schema) => WindowsAuthRemoteEventId::FailedLogon,
        _ => WindowsAuthRemoteEventId::Unknown,
    }
}

fn smb_auth_result(schema: WindowsAuthSchemaCategory) -> WindowsAuthResultCategory {
    match schema {
        WindowsAuthSchemaCategory::SmbClientConnectivity30806V2
        | WindowsAuthSchemaCategory::SmbClientConnectivity30808V2
        | WindowsAuthSchemaCategory::SmbClientConnectivity30832V0 => {
            WindowsAuthResultCategory::Success
        }
        schema if smb_schema_has_auth_context(schema) => WindowsAuthResultCategory::Failure,
        _ => WindowsAuthResultCategory::Unknown,
    }
}

fn smb_auth_mechanism(schema: WindowsAuthSchemaCategory) -> WindowsAuthMechanismCategory {
    match schema {
        WindowsAuthSchemaCategory::SmbClientSecurity31023V0 => WindowsAuthMechanismCategory::Ntlm,
        WindowsAuthSchemaCategory::SmbClientConnectivity30832V0
        | WindowsAuthSchemaCategory::SmbClientConnectivity30834V0
        | WindowsAuthSchemaCategory::SmbClientConnectivity30835V0 => {
            WindowsAuthMechanismCategory::Negotiate
        }
        _ => WindowsAuthMechanismCategory::Unknown,
    }
}

fn smb_failure_category(schema: WindowsAuthSchemaCategory) -> Option<WindowsAuthFailureCategory> {
    match schema {
        WindowsAuthSchemaCategory::SmbClientSecurity31017V0
        | WindowsAuthSchemaCategory::SmbClientSecurity31020V0
        | WindowsAuthSchemaCategory::SmbClientSecurity31023V0
        | WindowsAuthSchemaCategory::SmbServerOperational1001V1
        | WindowsAuthSchemaCategory::SmbServerOperational1003V1
        | WindowsAuthSchemaCategory::SmbServerOperational1004V1
        | WindowsAuthSchemaCategory::SmbServerOperational1005V2 => {
            Some(WindowsAuthFailureCategory::NotAllowed)
        }
        WindowsAuthSchemaCategory::SmbClientConnectivity30803V0
        | WindowsAuthSchemaCategory::SmbClientConnectivity30834V0
        | WindowsAuthSchemaCategory::SmbClientConnectivity30835V0
        | WindowsAuthSchemaCategory::SmbClientSecurity31019V0
        | WindowsAuthSchemaCategory::SmbServerSecurity551V1 => {
            Some(WindowsAuthFailureCategory::ProtocolFailure)
        }
        _ => None,
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
    metrics: &SmbOperationalMetrics,
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
    metrics: &SmbOperationalMetrics,
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
            Some("windows_smb_operational_event_log_not_yet_ready".to_string())
        },
    }
}

fn rate_limit_allows(metrics: &SmbOperationalMetrics) -> bool {
    let current_second = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let observed = metrics.rate_window_second.load(Ordering::Relaxed);
    if observed == current_second {
        metrics.rate_window_count.fetch_add(1, Ordering::Relaxed)
            < WINDOWS_SMB_OPERATIONAL_MAX_EVENTS_PER_SECOND
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
    hasher.update(WINDOWS_SMB_OPERATIONAL_ALLOWLIST_REF.as_bytes());
    hasher.update(b":session-scoped:");
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    format!(
        "{prefix}_ref_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]
    )
}

fn cursor_ref(metrics: &SmbOperationalMetrics) -> String {
    let parts = [
        metrics
            .client_connectivity_last_record_id
            .load(Ordering::Relaxed),
        metrics
            .client_security_last_record_id
            .load(Ordering::Relaxed),
        metrics
            .server_operational_last_record_id
            .load(Ordering::Relaxed),
        metrics
            .server_security_last_record_id
            .load(Ordering::Relaxed),
    ];
    if parts.iter().all(|part| *part == 0) {
        "smb_event_log_cursor_not_observed".to_string()
    } else {
        hashed_ref(
            "smb_event_log_cursor",
            &format!("{}|{}|{}|{}", parts[0], parts[1], parts[2], parts[3]),
        )
    }
}

fn smb_error(reason: impl Into<String>) -> WindowsAuthRemoteEventLogError {
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
        "\\\\",
        "unc",
        "share",
        "filename",
        "filepath",
        "clientaddress",
        "ipaddress",
        "hostname",
        "workstation",
        "sessionid",
        "logonid",
    ] {
        if lowered.contains(marker) {
            return "windows_smb_operational_event_log_error_redacted".to_string();
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
        let metadata = WindowsSmbOperationalEventLogAdapter::new().adapter_metadata();
        assert!(metadata.validate().is_ok());
        assert_eq!(
            metadata.provider_kind,
            NetworkProviderKind::WindowsSmbOperational
        );
        assert!(!metadata.ownership.owns_event_bus);
        assert!(!metadata.ownership.owns_dag);
        assert!(!metadata.ownership.owns_plugin_runtime);
        assert!(metadata
            .privacy_notes
            .iter()
            .any(|note| note == "smb_channel_allowlist_only"));
    }

    #[test]
    fn channel_and_schema_allowlists_are_exact_and_bounded() {
        let channels = allowlisted_channels();
        assert_eq!(channels.len(), 4);
        assert!(channels
            .iter()
            .any(|channel| channel.channel_path() == "Microsoft-Windows-SmbClient/Connectivity"));
        assert!(schema_allowed(
            SmbOperationalChannel::ClientConnectivity,
            30803,
            0
        ));
        assert!(schema_allowed(
            SmbOperationalChannel::ClientSecurity,
            31017,
            0
        ));
        assert!(schema_allowed(
            SmbOperationalChannel::ServerSecurity,
            551,
            1
        ));
        assert!(!schema_allowed(
            SmbOperationalChannel::ClientConnectivity,
            30803,
            9
        ));
        assert!(!schema_allowed(
            SmbOperationalChannel::ServerSecurity,
            4624,
            0
        ));
    }

    #[test]
    fn parser_extracts_transient_fields_without_outputting_raw_values() {
        let xml = r#"
        <Event>
          <System><EventID>31017</EventID><Version>0</Version><EventRecordID>77</EventRecordID><TimeCreated SystemTime="2026-06-15T00:00:00.000Z"/></System>
          <EventData>
            <Data Name="UserName">alice</Data>
            <Data Name="ServerName">fileserver01</Data>
            <Data Name="Path">\\fileserver01\secret\payroll.xlsx</Data>
            <Data Name="ClientAddress">192.0.2.55</Data>
          </EventData>
        </Event>
        "#;
        let transient = parse_transient_smb_event_xml(xml, SmbOperationalChannel::ClientSecurity)
            .expect("transient smb event");
        let observation = normalize_transient_smb_event(transient).expect("observation");
        assert_eq!(
            observation.remote_protocol_category,
            Some(WindowsRemoteProtocolCategory::Smb)
        );
        assert_eq!(
            observation.schema_category,
            WindowsAuthSchemaCategory::SmbClientSecurity31017V0
        );
        let serialized = serde_json::to_string(&observation).expect("json");
        for forbidden in [
            "alice",
            "fileserver01",
            "192.0.2.55",
            "payroll",
            "\\\\",
            "secret",
        ] {
            assert!(
                !serialized
                    .to_ascii_lowercase()
                    .contains(&forbidden.to_ascii_lowercase()),
                "SMB observation leaked raw value {forbidden}"
            );
        }
    }

    #[test]
    fn unknown_versions_are_schema_rejected() {
        let xml = r#"
        <Event>
          <System><EventID>551</EventID><Version>3</Version><EventRecordID>7</EventRecordID></System>
          <EventData><Data Name="UserName">alice</Data></EventData>
        </Event>
        "#;
        let transient = parse_transient_smb_event_xml(xml, SmbOperationalChannel::ServerSecurity)
            .expect("transient smb event");
        assert!(!schema_allowed(
            transient.channel,
            transient.event_id,
            transient.version
        ));
        assert!(normalize_transient_smb_event(transient).is_none());
    }

    #[test]
    fn rate_limit_counts_are_bounded() {
        let metrics = SmbOperationalMetrics::default();
        for _ in 0..WINDOWS_SMB_OPERATIONAL_MAX_EVENTS_PER_SECOND {
            assert!(rate_limit_allows(&metrics));
        }
        assert!(!rate_limit_allows(&metrics));
    }

    #[test]
    fn batch_queue_overflow_counts_drop_without_unbounded_growth() {
        let metrics = SmbOperationalMetrics::default();
        let (sender, _receiver) = mpsc::sync_channel(0);
        let mut pending = vec![WindowsAuthRemoteObservation {
            observation_ref: "smb_obs_ref_test".to_string(),
            event_category: WindowsAuthRemoteEventId::FailedLogon,
            schema_category: WindowsAuthSchemaCategory::SmbClientSecurity31017V0,
            event_version: 0,
            auth_result: WindowsAuthResultCategory::Failure,
            auth_mechanism: WindowsAuthMechanismCategory::Unknown,
            account_category: WindowsAuthAccountCategory::Unknown,
            privilege_bucket: WindowsAuthPrivilegeBucket::Unknown,
            remote_protocol_category: Some(WindowsRemoteProtocolCategory::Smb),
            failure_category: Some(WindowsAuthFailureCategory::NotAllowed),
            repeated_failure_bucket: Some(PortableAuthAttemptCountBucket::One),
            success_after_failure: false,
            identity_ref: None,
            source_ref: Some("smb_client_role".to_string()),
            target_ref: Some("smb_service_scope".to_string()),
            observed_bucket: WindowsAuthObservedBucket::ExistingHostEvents,
            source_reliability: WindowsAuthSourceReliability::OptionalChannelVerified,
            freshness: WindowsAuthFreshnessCategory::Recent,
            provenance_ref: "windows_smb_operational_event_log".to_string(),
            missing_visibility: vec!["raw_smb_identity_discarded".to_string()],
            time_bucket_start: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
            quality_score: QualityScore::new(0.64).expect("quality"),
        }];
        flush_smb_operational_batch(&mut pending, &sender, &metrics);
        assert_eq!(pending.len(), 0);
        assert_eq!(metrics.queue_dropped_events.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn record_gap_and_cursor_refs_are_bounded() {
        let metrics = SmbOperationalMetrics::default();
        assert_eq!(cursor_ref(&metrics), "smb_event_log_cursor_not_observed");
        metrics.store_last_record_id(SmbOperationalChannel::ClientConnectivity, 12);
        let cursor = cursor_ref(&metrics);
        assert!(cursor.starts_with("smb_event_log_cursor_ref_"));
        assert!(!cursor.contains("12"));
    }
}
