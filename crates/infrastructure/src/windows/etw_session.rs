//! Bounded live ETW network session adapter.
//!
//! This adapter creates one bounded product-owned real-time trace session,
//! enables one fixed allowlisted Windows network provider, and opens one consumer. The
//! callback never copies payloads or raw endpoint/process values and only uses
//! non-blocking bounded queue insertion.

use crate::provider_adapter::{
    ProviderAdapterMetadata, ProviderAdapterOwnership, ProviderProbe,
    PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
};
use crate::windows::etw_network::{
    EtwNetworkEventNormalizer, EtwNetworkNormalizerConfig, EtwTransientNetworkEvent,
};
use sentinel_contracts::{
    EtwAllowedSchemaId, EtwNetworkActivityCategory, EtwNormalizedNetworkBatch, NetworkProviderKind,
    RedactionStatus, Timestamp, WindowsDnsAnswerCountBucket, WindowsDnsDepthBucket,
    WindowsDnsEntropyBucket, WindowsDnsLengthBucket, WindowsDnsObservation,
    WindowsDnsObservationBatch, WindowsDnsQueryTypeCategory, WindowsDnsRecurrenceBucket,
    WindowsDnsResultCategory, WINDOWS_DNS_SENSING_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const ETW_SESSION_CONTROL_ADAPTER_ID: &str = "etw_control_session_adapter";
pub const ETW_NETWORK_PROVIDER_ALLOWLIST_REF: &str =
    "microsoft_windows_kernel_network_provider_allowlist_v1";
pub const ETW_RAW_QUEUE_CAPACITY: usize = 1_024;
pub const ETW_BATCH_QUEUE_CAPACITY: usize = 16;
pub const ETW_MAX_EVENTS_PER_SECOND: u32 = 4_096;
pub const ETW_MAX_DRAIN_BATCHES: usize = 16;
const ETW_NORMALIZER_BATCH_SIZE: usize = 128;
const ETW_NORMALIZER_FLUSH_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtwSessionControlState {
    Inactive,
    Active,
    Paused,
    Stopped,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtwSessionControlOutcome {
    pub state: EtwSessionControlState,
    pub trace_session_created: bool,
    pub provider_enabled: bool,
    pub collection_started: bool,
    pub consumer_started: bool,
    pub consumer_worker_active: bool,
    pub consumer_worker_joined: bool,
    pub raw_events_observed: u32,
    pub normalized_events: u32,
    pub dropped_events: u32,
    pub rate_limited_events: u32,
    pub schema_rejected_events: u32,
    pub normalized_batches: Vec<EtwNormalizedNetworkBatch>,
    pub degraded_reason: Option<String>,
}

pub trait EtwSessionControl: Send {
    fn start(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError>;
    fn pause(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError>;
    fn resume(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError>;
    fn stop(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError>;
    fn drain_normalized_batches(
        &mut self,
        max_batches: usize,
    ) -> Result<EtwSessionControlOutcome, EtwSessionControlError>;
}

pub struct EtwControlSessionAdapter {
    state: EtwSessionControlState,
    #[cfg(windows)]
    active_session: Option<WindowsEtwControlSession>,
}

impl Default for EtwControlSessionAdapter {
    fn default() -> Self {
        Self {
            state: EtwSessionControlState::Inactive,
            #[cfg(windows)]
            active_session: None,
        }
    }
}

impl EtwControlSessionAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    fn inactive_outcome(state: EtwSessionControlState) -> EtwSessionControlOutcome {
        EtwSessionControlOutcome {
            state,
            trace_session_created: false,
            provider_enabled: false,
            collection_started: false,
            consumer_started: false,
            consumer_worker_active: false,
            consumer_worker_joined: matches!(
                state,
                EtwSessionControlState::Paused | EtwSessionControlState::Stopped
            ),
            raw_events_observed: 0,
            normalized_events: 0,
            dropped_events: 0,
            rate_limited_events: 0,
            schema_rejected_events: 0,
            normalized_batches: Vec::new(),
            degraded_reason: None,
        }
    }
}

impl ProviderProbe for EtwControlSessionAdapter {
    fn adapter_metadata(&self) -> ProviderAdapterMetadata {
        ProviderAdapterMetadata {
            adapter_id: ETW_SESSION_CONTROL_ADAPTER_ID.to_string(),
            provider_kind: NetworkProviderKind::EtwNetwork,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            ownership: ProviderAdapterOwnership::infrastructure_adapter(),
            supported_request_refs: vec!["explicit_etw_session_lifecycle_request".to_string()],
            supported_result_refs: vec!["bounded_etw_session_lifecycle_result".to_string()],
            privacy_notes: vec![
                "single_allowlisted_provider_only".to_string(),
                "callback_user_data_not_read".to_string(),
                "bounded_nonblocking_callback_queue".to_string(),
                "category_only_normalized_batches".to_string(),
            ],
            redaction_status: RedactionStatus::Redacted,
        }
    }
}

impl EtwSessionControl for EtwControlSessionAdapter {
    fn start(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError> {
        if self.state == EtwSessionControlState::Active {
            #[cfg(windows)]
            return self
                .active_session
                .as_mut()
                .map(WindowsEtwControlSession::outcome)
                .unwrap_or_else(|| Ok(Self::inactive_outcome(self.state)));
            #[cfg(not(windows))]
            return Ok(Self::inactive_outcome(self.state));
        }
        #[cfg(windows)]
        {
            let mut session = WindowsEtwControlSession::start()?;
            let outcome = session.outcome()?;
            self.active_session = Some(session);
            self.state = EtwSessionControlState::Active;
            Ok(outcome)
        }
        #[cfg(not(windows))]
        {
            self.state = EtwSessionControlState::Unavailable;
            Err(EtwSessionControlError::new("unsupported_platform"))
        }
    }

    fn pause(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError> {
        if self.state == EtwSessionControlState::Paused {
            return Ok(Self::inactive_outcome(self.state));
        }
        #[cfg(windows)]
        if let Some(mut session) = self.active_session.take() {
            session.stop()?;
            self.state = EtwSessionControlState::Paused;
            return Ok(session.stopped_outcome(self.state));
        }
        self.state = EtwSessionControlState::Paused;
        Ok(Self::inactive_outcome(self.state))
    }

    fn resume(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError> {
        self.start()
    }

    fn stop(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError> {
        if self.state == EtwSessionControlState::Stopped {
            return Ok(Self::inactive_outcome(self.state));
        }
        #[cfg(windows)]
        if let Some(mut session) = self.active_session.take() {
            session.stop()?;
            self.state = EtwSessionControlState::Stopped;
            return Ok(session.stopped_outcome(self.state));
        }
        self.state = EtwSessionControlState::Stopped;
        Ok(Self::inactive_outcome(self.state))
    }

    fn drain_normalized_batches(
        &mut self,
        max_batches: usize,
    ) -> Result<EtwSessionControlOutcome, EtwSessionControlError> {
        #[cfg(windows)]
        if let Some(session) = self.active_session.as_mut() {
            return session.drain_normalized_batches(max_batches);
        }
        Ok(Self::inactive_outcome(self.state))
    }
}

impl Drop for EtwControlSessionAdapter {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtwSessionControlError {
    pub reason_redacted: String,
}

impl EtwSessionControlError {
    fn new(reason_redacted: impl Into<String>) -> Self {
        Self {
            reason_redacted: reason_redacted.into(),
        }
    }
}

impl std::fmt::Display for EtwSessionControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "ETW control session unavailable: {}",
            self.reason_redacted
        )
    }
}

impl std::error::Error for EtwSessionControlError {}

#[cfg(windows)]
const ETW_LOGGER_NAME_CAPACITY: usize = 96;

#[cfg(windows)]
const MICROSOFT_WINDOWS_KERNEL_NETWORK_PROVIDER: windows_sys::core::GUID =
    windows_sys::core::GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
#[cfg(windows)]
const SENTINEL_GUARD_ETW_NETWORK_SESSION_GUID: windows_sys::core::GUID =
    windows_sys::core::GUID::from_u128(0xb13656a2_9f39_4c35_b7f5_63350f45223a);
#[cfg(windows)]
const SENTINEL_GUARD_ETW_NETWORK_SESSION_NAME: &str = "SentinelGuardEtwNetworkLive";
#[cfg(windows)]
const KERNEL_NETWORK_IPV4_KEYWORD: u64 = 0x10;
#[cfg(windows)]
const KERNEL_NETWORK_IPV6_KEYWORD: u64 = 0x20;
#[cfg(windows)]
const KERNEL_NETWORK_ANALYTIC_KEYWORD: u64 = 0x8000_0000_0000_0000;
#[cfg(windows)]
const KERNEL_NETWORK_KEYWORD_MASK: u64 =
    KERNEL_NETWORK_ANALYTIC_KEYWORD | KERNEL_NETWORK_IPV4_KEYWORD | KERNEL_NETWORK_IPV6_KEYWORD;
#[cfg(windows)]
const ETW_LOG_FILE_MODE: u32 =
    windows_sys::Win32::System::Diagnostics::Etw::EVENT_TRACE_REAL_TIME_MODE
        | windows_sys::Win32::System::Diagnostics::Etw::EVENT_TRACE_SYSTEM_LOGGER_MODE;

#[cfg(windows)]
#[repr(C)]
struct EtwPropertiesBuffer {
    properties: windows_sys::Win32::System::Diagnostics::Etw::EVENT_TRACE_PROPERTIES,
    logger_name: [u16; ETW_LOGGER_NAME_CAPACITY],
}

#[cfg(windows)]
struct WindowsEtwControlSession {
    handle: windows_sys::Win32::System::Diagnostics::Etw::CONTROLTRACE_HANDLE,
    provider_enabled: bool,
    processing_handle: windows_sys::Win32::System::Diagnostics::Etw::PROCESSTRACE_HANDLE,
    batch_receiver: Receiver<EtwNormalizedNetworkBatch>,
    metrics: Arc<EtwLiveMetrics>,
    cancellation: Arc<AtomicBool>,
    consumer_thread: Option<JoinHandle<()>>,
    normalizer_thread: Option<JoinHandle<()>>,
    stopped: bool,
}

#[derive(Default)]
struct EtwLiveMetrics {
    raw_events_observed: AtomicU32,
    normalized_events: AtomicU32,
    dropped_events: AtomicU32,
    rate_limited_events: AtomicU32,
    schema_rejected_events: AtomicU32,
    callback_sequence: AtomicU64,
    rate_window_second: AtomicU64,
    rate_window_count: AtomicU32,
    consumer_worker_active: AtomicBool,
    normalizer_worker_active: AtomicBool,
}

impl EtwLiveMetrics {
    fn worker_active(&self) -> bool {
        self.consumer_worker_active.load(Ordering::SeqCst)
            || self.normalizer_worker_active.load(Ordering::SeqCst)
    }

    fn workers_joined(&self) -> bool {
        !self.worker_active()
    }
}

struct EtwCallbackContext {
    sender: SyncSender<EtwTransientNetworkEvent>,
    metrics: Arc<EtwLiveMetrics>,
}

#[cfg(windows)]
impl WindowsEtwControlSession {
    fn start() -> Result<Self, EtwSessionControlError> {
        use std::mem::{size_of, zeroed};
        use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, NO_ERROR};
        use windows_sys::Win32::System::Diagnostics::Etw::{
            ControlTraceW, EnableTraceEx2, StartTraceW, CONTROLTRACE_HANDLE,
            ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_TRACE_CONTROL_STOP, TRACE_LEVEL_INFORMATION,
            WNODE_FLAG_TRACED_GUID,
        };

        let encoded = SENTINEL_GUARD_ETW_NETWORK_SESSION_NAME
            .encode_utf16()
            .chain([0])
            .take(ETW_LOGGER_NAME_CAPACITY)
            .collect::<Vec<_>>();
        if encoded.last().copied() != Some(0) {
            return Err(EtwSessionControlError::new("bounded_session_name_rejected"));
        }

        let mut buffer: EtwPropertiesBuffer = unsafe { zeroed() };
        buffer.properties.Wnode.BufferSize = size_of::<EtwPropertiesBuffer>() as u32;
        buffer.properties.Wnode.Guid = SENTINEL_GUARD_ETW_NETWORK_SESSION_GUID;
        buffer.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        buffer.properties.Wnode.ClientContext = 1;
        buffer.properties.BufferSize = 64;
        buffer.properties.MinimumBuffers = 2;
        buffer.properties.MaximumBuffers = 4;
        buffer.properties.FlushTimer = 1;
        // ETW private-logger mode cannot consume an external provider in real time.
        // Product privacy is enforced by no file output and the descriptor-only callback.
        buffer.properties.LogFileMode = ETW_LOG_FILE_MODE;
        buffer.properties.LoggerNameOffset = size_of::<
            windows_sys::Win32::System::Diagnostics::Etw::EVENT_TRACE_PROPERTIES,
        >() as u32;
        buffer.logger_name[..encoded.len()].copy_from_slice(&encoded);

        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let mut result = unsafe {
            StartTraceW(
                &mut handle,
                buffer.logger_name.as_ptr(),
                &mut buffer.properties,
            )
        };
        if result == ERROR_ALREADY_EXISTS {
            let mut stale_buffer: EtwPropertiesBuffer = unsafe { zeroed() };
            stale_buffer.properties.Wnode.BufferSize = size_of::<EtwPropertiesBuffer>() as u32;
            unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE { Value: 0 },
                    buffer.logger_name.as_ptr(),
                    &mut stale_buffer.properties,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            handle.Value = 0;
            result = unsafe {
                StartTraceW(
                    &mut handle,
                    buffer.logger_name.as_ptr(),
                    &mut buffer.properties,
                )
            };
        }
        if result != NO_ERROR {
            return Err(EtwSessionControlError::new(classify_start_error(result)));
        }

        let mut enable_parameters: ENABLE_TRACE_PARAMETERS = unsafe { zeroed() };
        enable_parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        let provider_result = unsafe {
            EnableTraceEx2(
                handle,
                &MICROSOFT_WINDOWS_KERNEL_NETWORK_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_INFORMATION as u8,
                KERNEL_NETWORK_KEYWORD_MASK,
                0,
                0,
                &enable_parameters,
            )
        };
        if provider_result != NO_ERROR {
            let mut failed = Self::control_only_failed(handle);
            let _ = failed.stop();
            return Err(EtwSessionControlError::new(classify_provider_error(
                provider_result,
            )));
        }

        let metrics = Arc::new(EtwLiveMetrics::default());
        let cancellation = Arc::new(AtomicBool::new(false));
        let (raw_sender, raw_receiver) = mpsc::sync_channel(ETW_RAW_QUEUE_CAPACITY);
        let (batch_sender, batch_receiver) = mpsc::sync_channel(ETW_BATCH_QUEUE_CAPACITY);
        let normalizer_thread = start_normalizer_thread(
            raw_receiver,
            batch_sender,
            Arc::clone(&metrics),
            Arc::clone(&cancellation),
        );
        let consumer_result = start_consumer_thread(
            encoded,
            raw_sender,
            Arc::clone(&metrics),
            Arc::clone(&cancellation),
        );
        let (processing_handle, consumer_thread) = match consumer_result {
            Ok(result) => result,
            Err(error) => {
                let mut failed = Self {
                    handle,
                    provider_enabled: true,
                    processing_handle:
                        windows_sys::Win32::System::Diagnostics::Etw::PROCESSTRACE_HANDLE {
                            Value: u64::MAX,
                        },
                    batch_receiver,
                    metrics,
                    cancellation,
                    consumer_thread: None,
                    normalizer_thread: Some(normalizer_thread),
                    stopped: false,
                };
                let _ = failed.stop();
                return Err(error);
            }
        };

        Ok(Self {
            handle,
            provider_enabled: true,
            processing_handle,
            batch_receiver,
            metrics,
            cancellation,
            consumer_thread: Some(consumer_thread),
            normalizer_thread: Some(normalizer_thread),
            stopped: false,
        })
    }

    fn control_only_failed(
        handle: windows_sys::Win32::System::Diagnostics::Etw::CONTROLTRACE_HANDLE,
    ) -> Self {
        Self {
            handle,
            provider_enabled: false,
            processing_handle: windows_sys::Win32::System::Diagnostics::Etw::PROCESSTRACE_HANDLE {
                Value: u64::MAX,
            },
            batch_receiver: mpsc::sync_channel(1).1,
            metrics: Arc::new(EtwLiveMetrics::default()),
            cancellation: Arc::new(AtomicBool::new(true)),
            consumer_thread: None,
            normalizer_thread: None,
            stopped: false,
        }
    }

    fn outcome(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError> {
        self.drain_normalized_batches(0)
    }

    fn drain_normalized_batches(
        &mut self,
        max_batches: usize,
    ) -> Result<EtwSessionControlOutcome, EtwSessionControlError> {
        let mut batches = Vec::new();
        for _ in 0..max_batches.min(ETW_MAX_DRAIN_BATCHES) {
            match self.batch_receiver.try_recv() {
                Ok(batch) => batches.push(batch),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        Ok(self.live_outcome(batches))
    }

    fn live_outcome(
        &self,
        normalized_batches: Vec<EtwNormalizedNetworkBatch>,
    ) -> EtwSessionControlOutcome {
        EtwSessionControlOutcome {
            state: if self.stopped {
                EtwSessionControlState::Stopped
            } else {
                EtwSessionControlState::Active
            },
            trace_session_created: !self.stopped,
            provider_enabled: self.provider_enabled && !self.stopped,
            collection_started: self.provider_enabled && !self.stopped,
            consumer_started: self.consumer_thread.is_some() && !self.stopped,
            consumer_worker_active: self.metrics.worker_active(),
            consumer_worker_joined: self.metrics.workers_joined(),
            raw_events_observed: self.metrics.raw_events_observed.load(Ordering::Relaxed),
            normalized_events: self.metrics.normalized_events.load(Ordering::Relaxed),
            dropped_events: self.metrics.dropped_events.load(Ordering::Relaxed),
            rate_limited_events: self.metrics.rate_limited_events.load(Ordering::Relaxed),
            schema_rejected_events: self.metrics.schema_rejected_events.load(Ordering::Relaxed),
            normalized_batches,
            degraded_reason: None,
        }
    }

    fn stopped_outcome(&self, state: EtwSessionControlState) -> EtwSessionControlOutcome {
        let mut outcome = self.live_outcome(Vec::new());
        outcome.state = state;
        outcome.trace_session_created = false;
        outcome.provider_enabled = false;
        outcome.collection_started = false;
        outcome.consumer_started = false;
        outcome.consumer_worker_active = false;
        outcome.consumer_worker_joined = true;
        outcome
    }

    fn stop(&mut self) -> Result<(), EtwSessionControlError> {
        use std::mem::zeroed;
        use windows_sys::Win32::Foundation::NO_ERROR;
        use windows_sys::Win32::System::Diagnostics::Etw::{
            CloseTrace, ControlTraceW, EnableTraceEx2, ENABLE_TRACE_PARAMETERS,
            ENABLE_TRACE_PARAMETERS_VERSION_2, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
            EVENT_TRACE_CONTROL_STOP,
        };

        if self.stopped {
            return Ok(());
        }
        self.cancellation.store(true, Ordering::SeqCst);
        if self.provider_enabled {
            let mut disable_parameters: ENABLE_TRACE_PARAMETERS = unsafe { zeroed() };
            disable_parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
            let _ = unsafe {
                EnableTraceEx2(
                    self.handle,
                    &MICROSOFT_WINDOWS_KERNEL_NETWORK_PROVIDER,
                    EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                    0,
                    0,
                    0,
                    0,
                    &disable_parameters,
                )
            };
            self.provider_enabled = false;
        }
        if self.processing_handle.Value != u64::MAX {
            unsafe {
                CloseTrace(self.processing_handle);
            }
            self.processing_handle.Value = u64::MAX;
        }
        let mut buffer: EtwPropertiesBuffer = unsafe { zeroed() };
        buffer.properties.Wnode.BufferSize = std::mem::size_of::<EtwPropertiesBuffer>() as u32;
        let stop_result = unsafe {
            ControlTraceW(
                self.handle,
                std::ptr::null(),
                &mut buffer.properties,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        let consumer_joined = self
            .consumer_thread
            .take()
            .is_none_or(|handle| handle.join().is_ok());
        let normalizer_joined = self
            .normalizer_thread
            .take()
            .is_none_or(|handle| handle.join().is_ok());
        if !consumer_joined || !normalizer_joined {
            return Err(EtwSessionControlError::new(
                "etw_consumer_worker_join_failed",
            ));
        }
        self.stopped = true;
        if stop_result != NO_ERROR {
            return Err(EtwSessionControlError::new("control_session_stop_failed"));
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsEtwControlSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(windows)]
fn classify_start_error(error: u32) -> &'static str {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS};
    match error {
        ERROR_ACCESS_DENIED => "authorization_or_privilege_unavailable",
        ERROR_ALREADY_EXISTS => "control_session_name_conflict",
        _ => "control_session_start_failed",
    }
}

#[cfg(windows)]
fn classify_provider_error(error: u32) -> &'static str {
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
    if error == ERROR_ACCESS_DENIED {
        "authorization_or_privilege_unavailable"
    } else {
        "allowlisted_provider_enable_failed"
    }
}

#[cfg(windows)]
fn classify_open_trace_error(error: u32) -> &'static str {
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
    if error == ERROR_ACCESS_DENIED {
        "authorization_or_privilege_unavailable"
    } else {
        "open_trace_failed"
    }
}

#[cfg(windows)]
fn start_consumer_thread(
    logger_name: Vec<u16>,
    sender: SyncSender<EtwTransientNetworkEvent>,
    metrics: Arc<EtwLiveMetrics>,
    cancellation: Arc<AtomicBool>,
) -> Result<
    (
        windows_sys::Win32::System::Diagnostics::Etw::PROCESSTRACE_HANDLE,
        JoinHandle<()>,
    ),
    EtwSessionControlError,
> {
    use windows_sys::Win32::System::Diagnostics::Etw::PROCESSTRACE_HANDLE;

    let (ready_sender, ready_receiver) =
        mpsc::sync_channel::<Result<PROCESSTRACE_HANDLE, EtwSessionControlError>>(1);
    let handle = thread::spawn(move || {
        use std::mem::zeroed;
        use windows_sys::Win32::System::Diagnostics::Etw::{
            OpenTraceW, ProcessTrace, EVENT_TRACE_LOGFILEW, PROCESS_TRACE_MODE_EVENT_RECORD,
            PROCESS_TRACE_MODE_REAL_TIME,
        };

        let mut logger_name = logger_name;
        let context = Box::new(EtwCallbackContext { sender, metrics });
        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { zeroed() };
        logfile.LoggerName = logger_name.as_mut_ptr();
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(etw_event_record_callback);
        logfile.Context = (&*context as *const EtwCallbackContext).cast_mut().cast();

        let processing_handle = unsafe { OpenTraceW(&mut logfile) };
        if processing_handle.Value == u64::MAX {
            let error = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_default() as u32;
            let _ = ready_sender.send(Err(EtwSessionControlError::new(classify_open_trace_error(
                error,
            ))));
            return;
        }
        context
            .metrics
            .consumer_worker_active
            .store(true, Ordering::SeqCst);
        if ready_sender.send(Ok(processing_handle)).is_ok() && !cancellation.load(Ordering::SeqCst)
        {
            unsafe {
                ProcessTrace(&processing_handle, 1, std::ptr::null(), std::ptr::null());
            }
        }
        context
            .metrics
            .consumer_worker_active
            .store(false, Ordering::SeqCst);
    });
    match ready_receiver.recv() {
        Ok(Ok(processing_handle)) => Ok((processing_handle, handle)),
        Ok(Err(error)) => {
            let _ = handle.join();
            Err(error)
        }
        Err(_) => {
            let _ = handle.join();
            Err(EtwSessionControlError::new(
                "etw_consumer_thread_start_failed",
            ))
        }
    }
}

#[cfg(windows)]
fn start_normalizer_thread(
    receiver: Receiver<EtwTransientNetworkEvent>,
    batch_sender: SyncSender<EtwNormalizedNetworkBatch>,
    metrics: Arc<EtwLiveMetrics>,
    cancellation: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        use std::sync::mpsc::RecvTimeoutError;

        metrics
            .normalizer_worker_active
            .store(true, Ordering::SeqCst);
        let normalizer = EtwNetworkEventNormalizer::new();
        let mut pending = Vec::with_capacity(ETW_NORMALIZER_BATCH_SIZE);
        loop {
            match receiver.recv_timeout(ETW_NORMALIZER_FLUSH_INTERVAL) {
                Ok(event) => {
                    pending.push(event);
                    if pending.len() >= ETW_NORMALIZER_BATCH_SIZE {
                        flush_normalized_batch(&normalizer, &batch_sender, &metrics, &mut pending);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    flush_normalized_batch(&normalizer, &batch_sender, &metrics, &mut pending);
                    if cancellation.load(Ordering::SeqCst) {
                        break;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    flush_normalized_batch(&normalizer, &batch_sender, &metrics, &mut pending);
                    break;
                }
            }
        }
        metrics
            .normalizer_worker_active
            .store(false, Ordering::SeqCst);
    })
}

#[cfg(windows)]
fn flush_normalized_batch(
    normalizer: &EtwNetworkEventNormalizer,
    batch_sender: &SyncSender<EtwNormalizedNetworkBatch>,
    metrics: &EtwLiveMetrics,
    pending: &mut Vec<EtwTransientNetworkEvent>,
) {
    if pending.is_empty() {
        return;
    }
    let batch = normalizer.normalize_bounded(
        std::mem::take(pending),
        EtwNetworkNormalizerConfig {
            max_events: ETW_NORMALIZER_BATCH_SIZE,
            max_records: ETW_NORMALIZER_BATCH_SIZE,
            max_dedup_entries: ETW_NORMALIZER_BATCH_SIZE,
        },
    );
    metrics
        .normalized_events
        .fetch_add(batch.events_accepted, Ordering::Relaxed);
    if let Err(TrySendError::Full(batch) | TrySendError::Disconnected(batch)) =
        batch_sender.try_send(batch)
    {
        metrics
            .dropped_events
            .fetch_add(batch.events_accepted, Ordering::Relaxed);
    }
}

#[cfg(windows)]
unsafe extern "system" fn etw_event_record_callback(
    event_record: *mut windows_sys::Win32::System::Diagnostics::Etw::EVENT_RECORD,
) {
    if event_record.is_null() {
        return;
    }
    let event = unsafe { &*event_record };
    if event.UserContext.is_null() {
        return;
    }
    let context = unsafe { &*(event.UserContext as *const EtwCallbackContext) };
    if !guid_matches(
        &event.EventHeader.ProviderId,
        &MICROSOFT_WINDOWS_KERNEL_NETWORK_PROVIDER,
    ) {
        context
            .metrics
            .schema_rejected_events
            .fetch_add(1, Ordering::Relaxed);
        context
            .metrics
            .dropped_events
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    context
        .metrics
        .raw_events_observed
        .fetch_add(1, Ordering::Relaxed);
    if !rate_limit_allows(&context.metrics) {
        context
            .metrics
            .rate_limited_events
            .fetch_add(1, Ordering::Relaxed);
        context
            .metrics
            .dropped_events
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    let descriptor = event.EventHeader.EventDescriptor;
    let Some((schema_id, activity)) = classify_provider_descriptor(
        descriptor.Id,
        descriptor.Version,
        descriptor.Task,
        descriptor.Opcode,
    ) else {
        context
            .metrics
            .schema_rejected_events
            .fetch_add(1, Ordering::Relaxed);
        context
            .metrics
            .dropped_events
            .fetch_add(1, Ordering::Relaxed);
        return;
    };
    let sequence = context
        .metrics
        .callback_sequence
        .fetch_add(1, Ordering::Relaxed);
    let event = EtwTransientNetworkEvent::new_provider_metadata(schema_id, activity, sequence);
    if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
        context.sender.try_send(event)
    {
        context
            .metrics
            .dropped_events
            .fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(windows)]
fn guid_matches(left: &windows_sys::core::GUID, right: &windows_sys::core::GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

#[cfg(windows)]
fn rate_limit_allows(metrics: &EtwLiveMetrics) -> bool {
    let second = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let observed_window = metrics.rate_window_second.load(Ordering::Relaxed);
    if observed_window != second {
        metrics.rate_window_second.store(second, Ordering::Relaxed);
        metrics.rate_window_count.store(1, Ordering::Relaxed);
        return true;
    }
    metrics.rate_window_count.fetch_add(1, Ordering::Relaxed) < ETW_MAX_EVENTS_PER_SECOND
}

#[cfg(windows)]
fn classify_provider_descriptor(
    event_id: u16,
    version: u8,
    task: u16,
    opcode: u8,
) -> Option<(EtwAllowedSchemaId, EtwNetworkActivityCategory)> {
    if version != 0 {
        return None;
    }
    use EtwAllowedSchemaId::{
        TcpConnectionLifecycleV1, TcpTransferMetadataV1, UdpDatagramActivityV1,
    };
    use EtwNetworkActivityCategory::{Accept, Connect, Disconnect, Other, Receive, Send};
    match (task, event_id, opcode) {
        (10, 10 | 26, 10 | 26) => Some((TcpTransferMetadataV1, Send)),
        (10, 11 | 27, 11 | 27) => Some((TcpTransferMetadataV1, Receive)),
        (10, 12 | 28 | 16 | 32 | 17 | 33, 12 | 28 | 16 | 32 | 17 | 33) => {
            Some((TcpConnectionLifecycleV1, Connect))
        }
        (10, 13 | 29, 13 | 29) => Some((TcpConnectionLifecycleV1, Disconnect)),
        (10, 15 | 31, 15 | 31) => Some((TcpConnectionLifecycleV1, Accept)),
        (10, 14 | 30 | 18 | 34, 14 | 30 | 18 | 34) => Some((TcpTransferMetadataV1, Other)),
        (11, 42 | 58, 42 | 58) => Some((UdpDatagramActivityV1, Send)),
        (11, 43 | 59, 43 | 59) => Some((UdpDatagramActivityV1, Receive)),
        (11, 49, 49) => Some((UdpDatagramActivityV1, Other)),
        _ => None,
    }
}

pub const WINDOWS_DNS_SESSION_ADAPTER_ID: &str = "windows_dns_etw_session_adapter";
pub const WINDOWS_DNS_PROVIDER_ALLOWLIST_REF: &str =
    "microsoft_windows_dns_client_provider_allowlist_v1";
pub const WINDOWS_DNS_RAW_QUEUE_CAPACITY: usize = 512;
pub const WINDOWS_DNS_BATCH_QUEUE_CAPACITY: usize = 16;
pub const WINDOWS_DNS_MAX_EVENTS_PER_SECOND: u32 = 2_048;
pub const WINDOWS_DNS_MAX_DRAIN_BATCHES: usize = 16;
const WINDOWS_DNS_BATCH_SIZE: usize = 64;
const WINDOWS_DNS_FLUSH_INTERVAL: Duration = Duration::from_millis(200);
const WINDOWS_DNS_MAX_QUERY_UTF16_UNITS: usize = 253;
const WINDOWS_DNS_MAX_DEDUP_ENTRIES: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsDnsSessionOutcome {
    pub state: EtwSessionControlState,
    pub trace_session_created: bool,
    pub provider_enabled: bool,
    pub collection_started: bool,
    pub consumer_started: bool,
    pub consumer_worker_active: bool,
    pub consumer_worker_joined: bool,
    pub raw_events_observed: u32,
    pub normalized_events: u32,
    pub dropped_events: u32,
    pub overflow_events: u32,
    pub rate_limited_events: u32,
    pub schema_rejected_events: u32,
    pub duplicate_events: u32,
    pub normalized_batches: Vec<WindowsDnsObservationBatch>,
    pub degraded_reason: Option<String>,
}

pub trait WindowsDnsSessionControl: Send {
    fn start(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError>;
    fn pause(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError>;
    fn resume(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError>;
    fn stop(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError>;
    fn drain_normalized_batches(
        &mut self,
        max_batches: usize,
    ) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError>;
}

pub struct WindowsDnsEtwSessionAdapter {
    state: EtwSessionControlState,
    #[cfg(windows)]
    active_session: Option<WindowsDnsControlSession>,
}

impl Default for WindowsDnsEtwSessionAdapter {
    fn default() -> Self {
        Self {
            state: EtwSessionControlState::Inactive,
            #[cfg(windows)]
            active_session: None,
        }
    }
}

impl WindowsDnsEtwSessionAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    fn inactive_outcome(state: EtwSessionControlState) -> WindowsDnsSessionOutcome {
        WindowsDnsSessionOutcome {
            state,
            trace_session_created: false,
            provider_enabled: false,
            collection_started: false,
            consumer_started: false,
            consumer_worker_active: false,
            consumer_worker_joined: matches!(
                state,
                EtwSessionControlState::Paused | EtwSessionControlState::Stopped
            ),
            raw_events_observed: 0,
            normalized_events: 0,
            dropped_events: 0,
            overflow_events: 0,
            rate_limited_events: 0,
            schema_rejected_events: 0,
            duplicate_events: 0,
            normalized_batches: Vec::new(),
            degraded_reason: None,
        }
    }
}

impl ProviderProbe for WindowsDnsEtwSessionAdapter {
    fn adapter_metadata(&self) -> ProviderAdapterMetadata {
        ProviderAdapterMetadata {
            adapter_id: WINDOWS_DNS_SESSION_ADAPTER_ID.to_string(),
            provider_kind: NetworkProviderKind::WindowsDns,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            ownership: ProviderAdapterOwnership::infrastructure_adapter(),
            supported_request_refs: vec!["explicit_windows_dns_sensing_lifecycle".to_string()],
            supported_result_refs: vec!["bounded_windows_dns_observation_batch".to_string()],
            privacy_notes: vec![
                "single_allowlisted_dns_provider_only".to_string(),
                "raw_query_transient_in_infrastructure".to_string(),
                "bounded_nonblocking_callback_queue".to_string(),
                "query_ref_and_category_only_publication".to_string(),
            ],
            redaction_status: RedactionStatus::Redacted,
        }
    }
}

impl WindowsDnsSessionControl for WindowsDnsEtwSessionAdapter {
    fn start(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
        if self.state == EtwSessionControlState::Active {
            #[cfg(windows)]
            return self
                .active_session
                .as_mut()
                .map(WindowsDnsControlSession::outcome)
                .unwrap_or_else(|| Ok(Self::inactive_outcome(self.state)));
            #[cfg(not(windows))]
            return Ok(Self::inactive_outcome(self.state));
        }
        #[cfg(windows)]
        {
            let mut session = WindowsDnsControlSession::start()?;
            let outcome = session.outcome()?;
            self.active_session = Some(session);
            self.state = EtwSessionControlState::Active;
            Ok(outcome)
        }
        #[cfg(not(windows))]
        {
            self.state = EtwSessionControlState::Unavailable;
            Err(EtwSessionControlError::new("unsupported_platform"))
        }
    }

    fn pause(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
        if self.state == EtwSessionControlState::Paused {
            return Ok(Self::inactive_outcome(self.state));
        }
        #[cfg(windows)]
        if let Some(mut session) = self.active_session.take() {
            session.stop()?;
            self.state = EtwSessionControlState::Paused;
            return Ok(session.stopped_outcome(self.state));
        }
        self.state = EtwSessionControlState::Paused;
        Ok(Self::inactive_outcome(self.state))
    }

    fn resume(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
        self.start()
    }

    fn stop(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
        if self.state == EtwSessionControlState::Stopped {
            return Ok(Self::inactive_outcome(self.state));
        }
        #[cfg(windows)]
        if let Some(mut session) = self.active_session.take() {
            session.stop()?;
            self.state = EtwSessionControlState::Stopped;
            return Ok(session.stopped_outcome(self.state));
        }
        self.state = EtwSessionControlState::Stopped;
        Ok(Self::inactive_outcome(self.state))
    }

    fn drain_normalized_batches(
        &mut self,
        max_batches: usize,
    ) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
        #[cfg(windows)]
        if let Some(session) = self.active_session.as_mut() {
            return session.drain_normalized_batches(max_batches);
        }
        Ok(Self::inactive_outcome(self.state))
    }
}

impl Drop for WindowsDnsEtwSessionAdapter {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(windows)]
const WINDOWS_DNS_PROVIDER: windows_sys::core::GUID =
    windows_sys::core::GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
#[cfg(windows)]
const WINDOWS_DNS_SESSION_GUID: windows_sys::core::GUID =
    windows_sys::core::GUID::from_u128(0x913b9d95_a3f9_41bb_90a2_e424c23ff08c);
#[cfg(windows)]
const WINDOWS_DNS_SESSION_NAME: &str = "SentinelGuardWindowsDnsLive";
#[cfg(windows)]
const WINDOWS_DNS_OPERATIONAL_KEYWORD: u64 = 0x8000_0000_0000_0000;
#[cfg(windows)]
const WINDOWS_DNS_LOG_FILE_MODE: u32 =
    windows_sys::Win32::System::Diagnostics::Etw::EVENT_TRACE_REAL_TIME_MODE;

#[cfg(windows)]
#[derive(Clone)]
struct WindowsDnsTransientEvent {
    query_name: String,
    query_type: u32,
    status: Option<u32>,
    sequence: u64,
}

#[cfg(windows)]
#[derive(Default)]
struct WindowsDnsLiveMetrics {
    raw_events_observed: AtomicU32,
    normalized_events: AtomicU32,
    dropped_events: AtomicU32,
    overflow_events: AtomicU32,
    rate_limited_events: AtomicU32,
    schema_rejected_events: AtomicU32,
    duplicate_events: AtomicU32,
    callback_sequence: AtomicU64,
    rate_window_second: AtomicU64,
    rate_window_count: AtomicU32,
    consumer_worker_active: AtomicBool,
    normalizer_worker_active: AtomicBool,
}

#[cfg(windows)]
impl WindowsDnsLiveMetrics {
    fn worker_active(&self) -> bool {
        self.consumer_worker_active.load(Ordering::SeqCst)
            || self.normalizer_worker_active.load(Ordering::SeqCst)
    }
}

#[cfg(windows)]
struct WindowsDnsCallbackContext {
    sender: SyncSender<WindowsDnsTransientEvent>,
    metrics: Arc<WindowsDnsLiveMetrics>,
}

#[cfg(windows)]
struct WindowsDnsControlSession {
    handle: windows_sys::Win32::System::Diagnostics::Etw::CONTROLTRACE_HANDLE,
    provider_enabled: bool,
    processing_handle: windows_sys::Win32::System::Diagnostics::Etw::PROCESSTRACE_HANDLE,
    batch_receiver: Receiver<WindowsDnsObservationBatch>,
    metrics: Arc<WindowsDnsLiveMetrics>,
    cancellation: Arc<AtomicBool>,
    consumer_thread: Option<JoinHandle<()>>,
    normalizer_thread: Option<JoinHandle<()>>,
    stopped: bool,
}

#[cfg(windows)]
impl WindowsDnsControlSession {
    fn start() -> Result<Self, EtwSessionControlError> {
        use std::mem::{size_of, zeroed};
        use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, NO_ERROR};
        use windows_sys::Win32::System::Diagnostics::Etw::{
            ControlTraceW, EnableTraceEx2, StartTraceW, CONTROLTRACE_HANDLE,
            ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_TRACE_CONTROL_STOP, TRACE_LEVEL_INFORMATION,
            WNODE_FLAG_TRACED_GUID,
        };

        let encoded = WINDOWS_DNS_SESSION_NAME
            .encode_utf16()
            .chain([0])
            .take(ETW_LOGGER_NAME_CAPACITY)
            .collect::<Vec<_>>();
        if encoded.last().copied() != Some(0) {
            return Err(EtwSessionControlError::new("bounded_session_name_rejected"));
        }
        let mut buffer: EtwPropertiesBuffer = unsafe { zeroed() };
        buffer.properties.Wnode.BufferSize = size_of::<EtwPropertiesBuffer>() as u32;
        buffer.properties.Wnode.Guid = WINDOWS_DNS_SESSION_GUID;
        buffer.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        buffer.properties.Wnode.ClientContext = 1;
        buffer.properties.BufferSize = 64;
        buffer.properties.MinimumBuffers = 2;
        buffer.properties.MaximumBuffers = 4;
        buffer.properties.FlushTimer = 1;
        buffer.properties.LogFileMode = WINDOWS_DNS_LOG_FILE_MODE;
        buffer.properties.LoggerNameOffset = size_of::<
            windows_sys::Win32::System::Diagnostics::Etw::EVENT_TRACE_PROPERTIES,
        >() as u32;
        buffer.logger_name[..encoded.len()].copy_from_slice(&encoded);

        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let mut result = unsafe {
            StartTraceW(
                &mut handle,
                buffer.logger_name.as_ptr(),
                &mut buffer.properties,
            )
        };
        if result == ERROR_ALREADY_EXISTS {
            let mut stale_buffer: EtwPropertiesBuffer = unsafe { zeroed() };
            stale_buffer.properties.Wnode.BufferSize = size_of::<EtwPropertiesBuffer>() as u32;
            unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE { Value: 0 },
                    buffer.logger_name.as_ptr(),
                    &mut stale_buffer.properties,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            handle.Value = 0;
            result = unsafe {
                StartTraceW(
                    &mut handle,
                    buffer.logger_name.as_ptr(),
                    &mut buffer.properties,
                )
            };
        }
        if result != NO_ERROR {
            return Err(EtwSessionControlError::new(classify_start_error(result)));
        }

        let mut enable_parameters: ENABLE_TRACE_PARAMETERS = unsafe { zeroed() };
        enable_parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        let provider_result = unsafe {
            EnableTraceEx2(
                handle,
                &WINDOWS_DNS_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_INFORMATION as u8,
                WINDOWS_DNS_OPERATIONAL_KEYWORD,
                0,
                0,
                &enable_parameters,
            )
        };
        if provider_result != NO_ERROR {
            let mut failed = Self::control_only_failed(handle);
            let _ = failed.stop();
            return Err(EtwSessionControlError::new(classify_provider_error(
                provider_result,
            )));
        }

        let metrics = Arc::new(WindowsDnsLiveMetrics::default());
        let cancellation = Arc::new(AtomicBool::new(false));
        let (raw_sender, raw_receiver) = mpsc::sync_channel(WINDOWS_DNS_RAW_QUEUE_CAPACITY);
        let (batch_sender, batch_receiver) = mpsc::sync_channel(WINDOWS_DNS_BATCH_QUEUE_CAPACITY);
        let normalizer_thread = start_windows_dns_normalizer_thread(
            raw_receiver,
            batch_sender,
            Arc::clone(&metrics),
            Arc::clone(&cancellation),
        );
        let (processing_handle, consumer_thread) = match start_windows_dns_consumer_thread(
            encoded,
            raw_sender,
            Arc::clone(&metrics),
            Arc::clone(&cancellation),
        ) {
            Ok(result) => result,
            Err(error) => {
                let mut failed = Self {
                    handle,
                    provider_enabled: true,
                    processing_handle:
                        windows_sys::Win32::System::Diagnostics::Etw::PROCESSTRACE_HANDLE {
                            Value: u64::MAX,
                        },
                    batch_receiver,
                    metrics,
                    cancellation,
                    consumer_thread: None,
                    normalizer_thread: Some(normalizer_thread),
                    stopped: false,
                };
                let _ = failed.stop();
                return Err(error);
            }
        };
        Ok(Self {
            handle,
            provider_enabled: true,
            processing_handle,
            batch_receiver,
            metrics,
            cancellation,
            consumer_thread: Some(consumer_thread),
            normalizer_thread: Some(normalizer_thread),
            stopped: false,
        })
    }

    fn control_only_failed(
        handle: windows_sys::Win32::System::Diagnostics::Etw::CONTROLTRACE_HANDLE,
    ) -> Self {
        Self {
            handle,
            provider_enabled: false,
            processing_handle: windows_sys::Win32::System::Diagnostics::Etw::PROCESSTRACE_HANDLE {
                Value: u64::MAX,
            },
            batch_receiver: mpsc::sync_channel(1).1,
            metrics: Arc::new(WindowsDnsLiveMetrics::default()),
            cancellation: Arc::new(AtomicBool::new(true)),
            consumer_thread: None,
            normalizer_thread: None,
            stopped: false,
        }
    }

    fn outcome(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
        self.drain_normalized_batches(0)
    }

    fn drain_normalized_batches(
        &mut self,
        max_batches: usize,
    ) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
        let mut batches = Vec::new();
        for _ in 0..max_batches.min(WINDOWS_DNS_MAX_DRAIN_BATCHES) {
            match self.batch_receiver.try_recv() {
                Ok(batch) => batches.push(batch),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        Ok(self.live_outcome(batches))
    }

    fn live_outcome(
        &self,
        normalized_batches: Vec<WindowsDnsObservationBatch>,
    ) -> WindowsDnsSessionOutcome {
        WindowsDnsSessionOutcome {
            state: if self.stopped {
                EtwSessionControlState::Stopped
            } else {
                EtwSessionControlState::Active
            },
            trace_session_created: !self.stopped,
            provider_enabled: self.provider_enabled && !self.stopped,
            collection_started: self.provider_enabled && !self.stopped,
            consumer_started: self.consumer_thread.is_some() && !self.stopped,
            consumer_worker_active: self.metrics.worker_active(),
            consumer_worker_joined: !self.metrics.worker_active(),
            raw_events_observed: self.metrics.raw_events_observed.load(Ordering::Relaxed),
            normalized_events: self.metrics.normalized_events.load(Ordering::Relaxed),
            dropped_events: self.metrics.dropped_events.load(Ordering::Relaxed),
            overflow_events: self.metrics.overflow_events.load(Ordering::Relaxed),
            rate_limited_events: self.metrics.rate_limited_events.load(Ordering::Relaxed),
            schema_rejected_events: self.metrics.schema_rejected_events.load(Ordering::Relaxed),
            duplicate_events: self.metrics.duplicate_events.load(Ordering::Relaxed),
            normalized_batches,
            degraded_reason: None,
        }
    }

    fn stopped_outcome(&self, state: EtwSessionControlState) -> WindowsDnsSessionOutcome {
        let mut outcome = self.live_outcome(Vec::new());
        outcome.state = state;
        outcome.trace_session_created = false;
        outcome.provider_enabled = false;
        outcome.collection_started = false;
        outcome.consumer_started = false;
        outcome.consumer_worker_active = false;
        outcome.consumer_worker_joined = true;
        outcome
    }

    fn stop(&mut self) -> Result<(), EtwSessionControlError> {
        use std::mem::zeroed;
        use windows_sys::Win32::Foundation::NO_ERROR;
        use windows_sys::Win32::System::Diagnostics::Etw::{
            CloseTrace, ControlTraceW, EnableTraceEx2, ENABLE_TRACE_PARAMETERS,
            ENABLE_TRACE_PARAMETERS_VERSION_2, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
            EVENT_TRACE_CONTROL_STOP,
        };
        if self.stopped {
            return Ok(());
        }
        self.cancellation.store(true, Ordering::SeqCst);
        if self.provider_enabled {
            let mut parameters: ENABLE_TRACE_PARAMETERS = unsafe { zeroed() };
            parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
            unsafe {
                EnableTraceEx2(
                    self.handle,
                    &WINDOWS_DNS_PROVIDER,
                    EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                    0,
                    0,
                    0,
                    0,
                    &parameters,
                );
            }
            self.provider_enabled = false;
        }
        if self.processing_handle.Value != u64::MAX {
            unsafe {
                CloseTrace(self.processing_handle);
            }
            self.processing_handle.Value = u64::MAX;
        }
        let mut buffer: EtwPropertiesBuffer = unsafe { zeroed() };
        buffer.properties.Wnode.BufferSize = std::mem::size_of::<EtwPropertiesBuffer>() as u32;
        let stop_result = unsafe {
            ControlTraceW(
                self.handle,
                std::ptr::null(),
                &mut buffer.properties,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        let consumer_joined = self
            .consumer_thread
            .take()
            .is_none_or(|handle| handle.join().is_ok());
        let normalizer_joined = self
            .normalizer_thread
            .take()
            .is_none_or(|handle| handle.join().is_ok());
        if !consumer_joined || !normalizer_joined {
            return Err(EtwSessionControlError::new(
                "windows_dns_consumer_worker_join_failed",
            ));
        }
        self.stopped = true;
        if stop_result != NO_ERROR {
            return Err(EtwSessionControlError::new(
                "windows_dns_control_session_stop_failed",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsDnsControlSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(windows)]
fn start_windows_dns_consumer_thread(
    logger_name: Vec<u16>,
    sender: SyncSender<WindowsDnsTransientEvent>,
    metrics: Arc<WindowsDnsLiveMetrics>,
    cancellation: Arc<AtomicBool>,
) -> Result<
    (
        windows_sys::Win32::System::Diagnostics::Etw::PROCESSTRACE_HANDLE,
        JoinHandle<()>,
    ),
    EtwSessionControlError,
> {
    use windows_sys::Win32::System::Diagnostics::Etw::PROCESSTRACE_HANDLE;
    let (ready_sender, ready_receiver) =
        mpsc::sync_channel::<Result<PROCESSTRACE_HANDLE, EtwSessionControlError>>(1);
    let handle = thread::spawn(move || {
        use std::mem::zeroed;
        use windows_sys::Win32::System::Diagnostics::Etw::{
            OpenTraceW, ProcessTrace, EVENT_TRACE_LOGFILEW, PROCESS_TRACE_MODE_EVENT_RECORD,
            PROCESS_TRACE_MODE_REAL_TIME,
        };
        let mut logger_name = logger_name;
        let context = Box::new(WindowsDnsCallbackContext { sender, metrics });
        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { zeroed() };
        logfile.LoggerName = logger_name.as_mut_ptr();
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(windows_dns_event_record_callback);
        logfile.Context = (&*context as *const WindowsDnsCallbackContext)
            .cast_mut()
            .cast();
        let processing_handle = unsafe { OpenTraceW(&mut logfile) };
        if processing_handle.Value == u64::MAX {
            let error = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_default() as u32;
            let _ = ready_sender.send(Err(EtwSessionControlError::new(classify_open_trace_error(
                error,
            ))));
            return;
        }
        context
            .metrics
            .consumer_worker_active
            .store(true, Ordering::SeqCst);
        if ready_sender.send(Ok(processing_handle)).is_ok() && !cancellation.load(Ordering::SeqCst)
        {
            unsafe {
                ProcessTrace(&processing_handle, 1, std::ptr::null(), std::ptr::null());
            }
        }
        context
            .metrics
            .consumer_worker_active
            .store(false, Ordering::SeqCst);
    });
    match ready_receiver.recv() {
        Ok(Ok(processing_handle)) => Ok((processing_handle, handle)),
        Ok(Err(error)) => {
            let _ = handle.join();
            Err(error)
        }
        Err(_) => {
            let _ = handle.join();
            Err(EtwSessionControlError::new(
                "windows_dns_consumer_thread_start_failed",
            ))
        }
    }
}

#[cfg(windows)]
fn start_windows_dns_normalizer_thread(
    receiver: Receiver<WindowsDnsTransientEvent>,
    batch_sender: SyncSender<WindowsDnsObservationBatch>,
    metrics: Arc<WindowsDnsLiveMetrics>,
    cancellation: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        use std::sync::mpsc::RecvTimeoutError;
        metrics
            .normalizer_worker_active
            .store(true, Ordering::SeqCst);
        let salt = uuid::Uuid::new_v4().to_string();
        let mut pending = Vec::with_capacity(WINDOWS_DNS_BATCH_SIZE);
        let mut recurrence = HashMap::<String, u32>::new();
        let mut dedup_order = VecDeque::<String>::new();
        loop {
            match receiver.recv_timeout(WINDOWS_DNS_FLUSH_INTERVAL) {
                Ok(event) => {
                    pending.push(event);
                    if pending.len() >= WINDOWS_DNS_BATCH_SIZE {
                        flush_windows_dns_batch(
                            &salt,
                            &batch_sender,
                            &metrics,
                            &mut pending,
                            &mut recurrence,
                            &mut dedup_order,
                        );
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    flush_windows_dns_batch(
                        &salt,
                        &batch_sender,
                        &metrics,
                        &mut pending,
                        &mut recurrence,
                        &mut dedup_order,
                    );
                    if cancellation.load(Ordering::SeqCst) {
                        break;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    flush_windows_dns_batch(
                        &salt,
                        &batch_sender,
                        &metrics,
                        &mut pending,
                        &mut recurrence,
                        &mut dedup_order,
                    );
                    break;
                }
            }
        }
        metrics
            .normalizer_worker_active
            .store(false, Ordering::SeqCst);
    })
}

#[cfg(windows)]
fn flush_windows_dns_batch(
    salt: &str,
    sender: &SyncSender<WindowsDnsObservationBatch>,
    metrics: &WindowsDnsLiveMetrics,
    pending: &mut Vec<WindowsDnsTransientEvent>,
    recurrence: &mut HashMap<String, u32>,
    dedup_order: &mut VecDeque<String>,
) {
    if pending.is_empty() {
        return;
    }
    let mut records = Vec::with_capacity(pending.len());
    for event in std::mem::take(pending) {
        let query_ref = dns_query_ref(salt, &event.query_name);
        let dedup_ref = format!(
            "{}_{}_{}",
            query_ref,
            event.query_type,
            event.status.unwrap_or_default()
        );
        if recurrence.contains_key(&dedup_ref) {
            metrics.duplicate_events.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        recurrence.insert(dedup_ref.clone(), 1);
        dedup_order.push_back(dedup_ref);
        while dedup_order.len() > WINDOWS_DNS_MAX_DEDUP_ENTRIES {
            if let Some(expired) = dedup_order.pop_front() {
                recurrence.remove(&expired);
            }
        }
        let query_count = recurrence
            .entry(query_ref.clone())
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        records.push(normalize_windows_dns_event(event, query_ref, *query_count));
    }
    if records.is_empty() {
        return;
    }
    metrics
        .normalized_events
        .fetch_add(records.len() as u32, Ordering::Relaxed);
    let batch = WindowsDnsObservationBatch {
        schema_version: WINDOWS_DNS_SENSING_SCHEMA_VERSION,
        batch_ref: format!("dns_batch_{}", uuid::Uuid::new_v4().simple()),
        allowlist_ref: WINDOWS_DNS_PROVIDER_ALLOWLIST_REF.to_string(),
        records,
        raw_events_observed: metrics.raw_events_observed.load(Ordering::Relaxed),
        normalized_events: metrics.normalized_events.load(Ordering::Relaxed),
        dropped_events: metrics.dropped_events.load(Ordering::Relaxed),
        overflow_events: metrics.overflow_events.load(Ordering::Relaxed),
        rate_limited_events: metrics.rate_limited_events.load(Ordering::Relaxed),
        schema_rejected_events: metrics.schema_rejected_events.load(Ordering::Relaxed),
        duplicate_events: metrics.duplicate_events.load(Ordering::Relaxed),
        provenance_refs: vec![
            "windows_dns_client_etw".to_string(),
            "windows_dns_privacy_normalizer".to_string(),
        ],
        generated_at: Timestamp::now(),
        redaction_status: RedactionStatus::Redacted,
    };
    if let Err(TrySendError::Full(batch) | TrySendError::Disconnected(batch)) =
        sender.try_send(batch)
    {
        let dropped = batch.records.len().min(u32::MAX as usize) as u32;
        metrics.dropped_events.fetch_add(dropped, Ordering::Relaxed);
        metrics
            .overflow_events
            .fetch_add(dropped, Ordering::Relaxed);
    }
}

#[cfg(windows)]
fn normalize_windows_dns_event(
    event: WindowsDnsTransientEvent,
    query_ref: String,
    recurrence: u32,
) -> WindowsDnsObservation {
    let query = event.query_name.trim_end_matches('.');
    let labels = query.split('.').filter(|label| !label.is_empty()).count();
    let entropy = dns_character_entropy(query);
    WindowsDnsObservation {
        schema_version: WINDOWS_DNS_SENSING_SCHEMA_VERSION,
        observation_ref: format!("dns_observation_{:016x}", event.sequence),
        query_ref,
        query_type_category: match event.query_type {
            1 | 28 => WindowsDnsQueryTypeCategory::Address,
            5 => WindowsDnsQueryTypeCategory::Alias,
            12 => WindowsDnsQueryTypeCategory::Reverse,
            15 => WindowsDnsQueryTypeCategory::Mail,
            16 => WindowsDnsQueryTypeCategory::Text,
            33 | 64 | 65 => WindowsDnsQueryTypeCategory::Service,
            _ => WindowsDnsQueryTypeCategory::Other,
        },
        result_category: match event.status {
            None => WindowsDnsResultCategory::Pending,
            Some(0) => WindowsDnsResultCategory::Success,
            Some(9003) => WindowsDnsResultCategory::NameError,
            Some(1460) => WindowsDnsResultCategory::Timeout,
            Some(9005) => WindowsDnsResultCategory::Refused,
            Some(9002) => WindowsDnsResultCategory::ServerFailure,
            Some(995) => WindowsDnsResultCategory::Cancelled,
            Some(_) => WindowsDnsResultCategory::OtherFailure,
        },
        query_length_bucket: match query.len() {
            0..=19 => WindowsDnsLengthBucket::Short,
            20..=63 => WindowsDnsLengthBucket::Medium,
            _ => WindowsDnsLengthBucket::Long,
        },
        subdomain_depth_bucket: match labels.saturating_sub(2) {
            0..=1 => WindowsDnsDepthBucket::Shallow,
            2..=3 => WindowsDnsDepthBucket::Moderate,
            _ => WindowsDnsDepthBucket::Deep,
        },
        entropy_bucket: if entropy >= 3.9 {
            WindowsDnsEntropyBucket::High
        } else if entropy >= 3.0 {
            WindowsDnsEntropyBucket::Medium
        } else {
            WindowsDnsEntropyBucket::Low
        },
        answer_count_bucket: WindowsDnsAnswerCountBucket::Unknown,
        recurrence_bucket: match recurrence {
            0 | 1 => WindowsDnsRecurrenceBucket::One,
            2..=9 => WindowsDnsRecurrenceBucket::Few,
            _ => WindowsDnsRecurrenceBucket::Many,
        },
        observed_at: Timestamp::now(),
        provenance_refs: vec![
            "windows_dns_client_etw".to_string(),
            "dns_query_session_hash".to_string(),
        ],
        redaction_status: RedactionStatus::Redacted,
    }
}

#[cfg(windows)]
fn dns_query_ref(salt: &str, query_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update([0]);
    hasher.update(query_name.to_ascii_lowercase().as_bytes());
    let digest = hasher.finalize();
    format!("dns_query_{}", hex_prefix(&digest, 16))
}

#[cfg(windows)]
fn hex_prefix(bytes: &[u8], count: usize) -> String {
    bytes
        .iter()
        .take(count)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(windows)]
fn dns_character_entropy(value: &str) -> f32 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = HashMap::<u8, usize>::new();
    for byte in value.to_ascii_lowercase().bytes() {
        *counts.entry(byte).or_default() += 1;
    }
    let length = value.len() as f32;
    counts
        .values()
        .map(|count| {
            let probability = *count as f32 / length;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(windows)]
fn windows_dns_rate_limit_allows(metrics: &WindowsDnsLiveMetrics) -> bool {
    let second = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let observed = metrics.rate_window_second.load(Ordering::Relaxed);
    if observed != second {
        metrics.rate_window_second.store(second, Ordering::Relaxed);
        metrics.rate_window_count.store(1, Ordering::Relaxed);
        return true;
    }
    metrics.rate_window_count.fetch_add(1, Ordering::Relaxed) < WINDOWS_DNS_MAX_EVENTS_PER_SECOND
}

#[cfg(windows)]
fn classify_windows_dns_descriptor(event_id: u16, version: u8, task: u16, opcode: u8) -> bool {
    version == 0 && task == 0 && opcode == 0 && matches!(event_id, 3006 | 3008)
}

#[cfg(windows)]
unsafe extern "system" fn windows_dns_event_record_callback(
    event_record: *mut windows_sys::Win32::System::Diagnostics::Etw::EVENT_RECORD,
) {
    if event_record.is_null() {
        return;
    }
    let event = unsafe { &*event_record };
    if event.UserContext.is_null() {
        return;
    }
    let context = unsafe { &*(event.UserContext as *const WindowsDnsCallbackContext) };
    if !guid_matches(&event.EventHeader.ProviderId, &WINDOWS_DNS_PROVIDER) {
        context
            .metrics
            .schema_rejected_events
            .fetch_add(1, Ordering::Relaxed);
        context
            .metrics
            .dropped_events
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    context
        .metrics
        .raw_events_observed
        .fetch_add(1, Ordering::Relaxed);
    let descriptor = event.EventHeader.EventDescriptor;
    if !classify_windows_dns_descriptor(
        descriptor.Id,
        descriptor.Version,
        descriptor.Task,
        descriptor.Opcode,
    ) {
        context
            .metrics
            .schema_rejected_events
            .fetch_add(1, Ordering::Relaxed);
        context
            .metrics
            .dropped_events
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    if !windows_dns_rate_limit_allows(&context.metrics) {
        context
            .metrics
            .rate_limited_events
            .fetch_add(1, Ordering::Relaxed);
        context
            .metrics
            .dropped_events
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Some((query_name, query_type, status)) = (unsafe {
        parse_windows_dns_user_data(
            event.UserData.cast(),
            event.UserDataLength as usize,
            descriptor.Id,
        )
    }) else {
        context
            .metrics
            .schema_rejected_events
            .fetch_add(1, Ordering::Relaxed);
        context
            .metrics
            .dropped_events
            .fetch_add(1, Ordering::Relaxed);
        return;
    };
    let transient = WindowsDnsTransientEvent {
        query_name,
        query_type,
        status,
        sequence: context
            .metrics
            .callback_sequence
            .fetch_add(1, Ordering::Relaxed),
    };
    if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
        context.sender.try_send(transient)
    {
        context
            .metrics
            .dropped_events
            .fetch_add(1, Ordering::Relaxed);
        context
            .metrics
            .overflow_events
            .fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(windows)]
unsafe fn parse_windows_dns_user_data(
    data: *const u8,
    length: usize,
    event_id: u16,
) -> Option<(String, u32, Option<u32>)> {
    if data.is_null() || !(6..=4_096).contains(&length) {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, length) };
    let mut utf16 = Vec::new();
    let mut offset = 0usize;
    while offset + 1 < bytes.len() && utf16.len() <= WINDOWS_DNS_MAX_QUERY_UTF16_UNITS {
        let unit = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;
        if unit == 0 {
            break;
        }
        utf16.push(unit);
    }
    if utf16.is_empty()
        || utf16.len() > WINDOWS_DNS_MAX_QUERY_UTF16_UNITS
        || offset + 4 > bytes.len()
    {
        return None;
    }
    let query_name = String::from_utf16(&utf16).ok()?;
    if query_name.chars().any(char::is_control) {
        return None;
    }
    let query_type = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?);
    let status = if event_id == 3008 {
        let status_offset = offset.checked_add(12)?;
        if status_offset + 4 > bytes.len() {
            return None;
        }
        Some(u32::from_le_bytes(
            bytes[status_offset..status_offset + 4].try_into().ok()?,
        ))
    } else {
        None
    };
    Some((query_name, query_type, status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etw_session_adapter_declares_bounded_collection_without_runtime_ownership() {
        let metadata = EtwControlSessionAdapter::new().adapter_metadata();
        assert!(metadata.validate().is_ok());
        assert!(!metadata.ownership.owns_event_bus);
        assert!(!metadata.ownership.owns_dag);
        assert!(!metadata.ownership.owns_plugin_runtime);
        assert!(metadata
            .privacy_notes
            .iter()
            .any(|note| note == "bounded_nonblocking_callback_queue"));
    }

    #[cfg(windows)]
    #[test]
    fn provider_descriptor_allowlist_rejects_unknown_or_wrong_version() {
        assert_eq!(
            classify_provider_descriptor(12, 0, 10, 12),
            Some((
                EtwAllowedSchemaId::TcpConnectionLifecycleV1,
                EtwNetworkActivityCategory::Connect
            ))
        );
        assert_eq!(classify_provider_descriptor(12, 1, 10, 12), None);
        assert_eq!(classify_provider_descriptor(1, 0, 10, 1), None);
    }

    #[cfg(windows)]
    #[test]
    fn system_provider_session_mode_and_keywords_match_verified_windows_metadata() {
        use windows_sys::Win32::System::Diagnostics::Etw::{
            EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_SYSTEM_LOGGER_MODE,
            EVENT_TRACE_USE_PAGED_MEMORY,
        };

        assert_ne!(ETW_LOG_FILE_MODE & EVENT_TRACE_REAL_TIME_MODE, 0);
        assert_ne!(ETW_LOG_FILE_MODE & EVENT_TRACE_SYSTEM_LOGGER_MODE, 0);
        assert_eq!(ETW_LOG_FILE_MODE & EVENT_TRACE_USE_PAGED_MEMORY, 0);
        assert_eq!(KERNEL_NETWORK_KEYWORD_MASK, 0x8000_0000_0000_0030);
    }

    #[cfg(windows)]
    #[test]
    fn callback_uses_nonblocking_bounded_queue_and_counts_overflow() {
        use std::mem::zeroed;
        use windows_sys::Win32::System::Diagnostics::Etw::EVENT_RECORD;

        let metrics = Arc::new(EtwLiveMetrics::default());
        let (sender, receiver) = mpsc::sync_channel(1);
        let context = EtwCallbackContext {
            sender,
            metrics: Arc::clone(&metrics),
        };
        let mut event: EVENT_RECORD = unsafe { zeroed() };
        event.UserContext = (&context as *const EtwCallbackContext).cast_mut().cast();
        event.EventHeader.ProviderId = MICROSOFT_WINDOWS_KERNEL_NETWORK_PROVIDER;
        event.EventHeader.EventDescriptor.Id = 12;
        event.EventHeader.EventDescriptor.Version = 0;
        event.EventHeader.EventDescriptor.Task = 10;
        event.EventHeader.EventDescriptor.Opcode = 12;

        unsafe {
            etw_event_record_callback(&mut event);
            etw_event_record_callback(&mut event);
        }

        assert!(receiver.try_recv().is_ok());
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(metrics.raw_events_observed.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.dropped_events.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.schema_rejected_events.load(Ordering::Relaxed), 0);
    }

    #[cfg(windows)]
    #[test]
    fn rate_limit_is_bounded_per_second() {
        let metrics = EtwLiveMetrics::default();
        let current_second = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        metrics
            .rate_window_second
            .store(current_second, Ordering::Relaxed);
        metrics
            .rate_window_count
            .store(ETW_MAX_EVENTS_PER_SECOND, Ordering::Relaxed);
        assert!(!rate_limit_allows(&metrics));
    }

    #[test]
    fn windows_dns_adapter_declares_one_allowlisted_metadata_only_source() {
        let metadata = WindowsDnsEtwSessionAdapter::new().adapter_metadata();
        assert!(metadata.validate().is_ok());
        assert_eq!(metadata.provider_kind, NetworkProviderKind::WindowsDns);
        assert!(!metadata.ownership.owns_event_bus);
        assert!(!metadata.ownership.owns_dag);
        assert!(!metadata.ownership.owns_plugin_runtime);
        assert!(metadata
            .privacy_notes
            .iter()
            .any(|note| note == "raw_query_transient_in_infrastructure"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_dns_descriptor_allowlist_is_exact() {
        assert!(classify_windows_dns_descriptor(3006, 0, 0, 0));
        assert!(classify_windows_dns_descriptor(3008, 0, 0, 0));
        assert!(!classify_windows_dns_descriptor(3009, 0, 0, 0));
        assert!(!classify_windows_dns_descriptor(3008, 1, 0, 0));
        assert!(!classify_windows_dns_descriptor(3008, 0, 1, 0));
    }

    #[cfg(windows)]
    #[test]
    fn windows_dns_parser_extracts_only_bounded_transient_fields() {
        let mut payload = "sentinel-dns-smoke.test"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        payload.extend_from_slice(&0_u16.to_le_bytes());
        payload.extend_from_slice(&1_u32.to_le_bytes());
        payload.extend_from_slice(&0_u64.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes());
        let parsed = unsafe { parse_windows_dns_user_data(payload.as_ptr(), payload.len(), 3008) }
            .expect("allowlisted payload");
        assert_eq!(parsed.0, "sentinel-dns-smoke.test");
        assert_eq!(parsed.1, 1);
        assert_eq!(parsed.2, Some(0));
    }

    #[cfg(windows)]
    #[test]
    fn windows_dns_callback_is_nonblocking_and_counts_overflow() {
        use std::mem::zeroed;
        use windows_sys::Win32::System::Diagnostics::Etw::EVENT_RECORD;

        let metrics = Arc::new(WindowsDnsLiveMetrics::default());
        let (sender, receiver) = mpsc::sync_channel(1);
        let context = WindowsDnsCallbackContext {
            sender,
            metrics: Arc::clone(&metrics),
        };
        let mut payload = "sentinel-overflow.test"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        payload.extend_from_slice(&0_u16.to_le_bytes());
        payload.extend_from_slice(&1_u32.to_le_bytes());
        payload.extend_from_slice(&0_u64.to_le_bytes());
        let mut event: EVENT_RECORD = unsafe { zeroed() };
        event.UserContext = (&context as *const WindowsDnsCallbackContext)
            .cast_mut()
            .cast();
        event.UserData = payload.as_mut_ptr().cast();
        event.UserDataLength = payload.len() as u16;
        event.EventHeader.ProviderId = WINDOWS_DNS_PROVIDER;
        event.EventHeader.EventDescriptor.Id = 3006;
        unsafe {
            windows_dns_event_record_callback(&mut event);
            windows_dns_event_record_callback(&mut event);
        }
        assert!(receiver.try_recv().is_ok());
        assert_eq!(metrics.raw_events_observed.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.overflow_events.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.dropped_events.load(Ordering::Relaxed), 1);
    }

    #[cfg(windows)]
    #[test]
    fn windows_dns_rate_limit_is_bounded() {
        let metrics = WindowsDnsLiveMetrics::default();
        let current_second = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        metrics
            .rate_window_second
            .store(current_second, Ordering::Relaxed);
        metrics
            .rate_window_count
            .store(WINDOWS_DNS_MAX_EVENTS_PER_SECOND, Ordering::Relaxed);
        assert!(!windows_dns_rate_limit_allows(&metrics));
    }

    #[cfg(windows)]
    #[test]
    fn windows_dns_normalized_contract_does_not_serialize_raw_query() {
        let record = normalize_windows_dns_event(
            WindowsDnsTransientEvent {
                query_name: "sentinel-private-query.test".to_string(),
                query_type: 1,
                status: Some(0),
                sequence: 7,
            },
            dns_query_ref("session-salt", "sentinel-private-query.test"),
            1,
        );
        record.validate().expect("safe native DNS record");
        let serialized = serde_json::to_string(&record).expect("serialize");
        assert!(!serialized.contains("sentinel-private-query"));
        assert!(!serialized.contains(".test"));
        assert!(!serialized.contains("pid"));
        assert!(!serialized.contains("port"));
        assert!(!serialized.contains("payload"));
    }
}
