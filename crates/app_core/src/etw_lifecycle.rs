use sentinel_contracts::runtime_ownership::{
    RuntimeMode, RuntimeOwnerCategory, RuntimeOwnerContext,
};
use sentinel_contracts::{
    EtwAuthorizationState, EtwFallbackState, EtwLifecycleState, EtwLifecycleStatus,
    EtwNormalizedNetworkBatch, EtwRuntimeSessionState, Timestamp, MAX_ETW_LIFECYCLE_REFS,
};
use sentinel_infrastructure::{
    EtwControlSessionAdapter, EtwSessionControl, EtwSessionControlOutcome, EtwSessionControlState,
    WindowsAuthRemoteControlState, WindowsAuthRemoteEventLogAdapter,
    WindowsAuthRemoteEventLogControl, WindowsAuthRemoteEventLogOutcome,
    WindowsDnsEtwSessionAdapter, WindowsDnsSessionControl, WindowsDnsSessionOutcome,
    WindowsRdpOperationalEventLogAdapter, WindowsSmbOperationalEventLogAdapter,
    WindowsSshOperationalEventLogAdapter,
};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

type EtwControlFactory = Arc<dyn Fn() -> Box<dyn EtwSessionControl> + Send + Sync>;

enum EtwControlCommand {
    Pause,
    Resume,
    Stop,
    Drain(usize),
}

struct EtwControlRequest {
    command: EtwControlCommand,
    response: SyncSender<Result<EtwSessionControlOutcome, String>>,
}

pub struct ServiceOwnedEtwLifecycleRuntime {
    owner_context: RuntimeOwnerContext,
    status: EtwLifecycleStatus,
    control_factory: EtwControlFactory,
    sender: Option<Sender<EtwControlRequest>>,
    handle: Option<JoinHandle<()>>,
}

impl ServiceOwnedEtwLifecycleRuntime {
    pub fn new(owner_context: &RuntimeOwnerContext, fallback_state: EtwFallbackState) -> Self {
        Self::with_factory(
            owner_context,
            fallback_state,
            Arc::new(|| Box::new(EtwControlSessionAdapter::new())),
        )
    }

    fn with_factory(
        owner_context: &RuntimeOwnerContext,
        fallback_state: EtwFallbackState,
        control_factory: EtwControlFactory,
    ) -> Self {
        Self {
            owner_context: owner_context.clone(),
            status: EtwLifecycleStatus::inactive(
                owner_context.ownership_ref.clone(),
                owner_context.ownership_epoch,
                fallback_state,
            ),
            control_factory,
            sender: None,
            handle: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        owner_context: &RuntimeOwnerContext,
        fallback_state: EtwFallbackState,
        control_factory: EtwControlFactory,
    ) -> Self {
        Self::with_factory(owner_context, fallback_state, control_factory)
    }

    pub fn status(&self) -> &EtwLifecycleStatus {
        &self.status
    }

    pub fn activate(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
        fallback_state: EtwFallbackState,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        if self.handle.is_some()
            && matches!(
                self.status.lifecycle_state,
                EtwLifecycleState::Active | EtwLifecycleState::Degraded
            )
        {
            return Ok(self.status.clone());
        }

        self.status.lifecycle_state = EtwLifecycleState::Activating;
        self.status.authorization_state = EtwAuthorizationState::Authorized;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        self.status.fallback_state = fallback_state;
        self.status.control_thread_joined = false;
        self.status.updated_at = Timestamp::now();

        let (command_tx, command_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let mut control = (self.control_factory)();
        let handle = thread::spawn(move || run_control_thread(&mut *control, command_rx, ready_tx));
        let start_result = ready_rx
            .recv()
            .map_err(|_| "etw_control_thread_start_failed".to_string())?;
        self.sender = Some(command_tx);
        self.handle = Some(handle);
        self.status.control_thread_active = true;
        self.apply_outcome(start_result, EtwLifecycleState::Active, true)?;
        self.status.activation_count = self.status.activation_count.saturating_add(1);
        self.status.audit_refs = bounded_refs(
            self.status
                .audit_refs
                .clone()
                .into_iter()
                .chain(["etw_activation_authorized".to_string()]),
        );
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    pub fn pause(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
        fallback_state: EtwFallbackState,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        if self.status.lifecycle_state == EtwLifecycleState::Paused {
            return Ok(self.status.clone());
        }
        self.status.lifecycle_state = EtwLifecycleState::Pausing;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        self.status.fallback_state = fallback_state;
        let outcome = self.send_command(EtwControlCommand::Pause)?;
        self.apply_outcome(Ok(outcome), EtwLifecycleState::Paused, false)?;
        self.status.pause_count = self.status.pause_count.saturating_add(1);
        self.status.audit_refs = bounded_refs(
            self.status
                .audit_refs
                .clone()
                .into_iter()
                .chain(["etw_pause_completed".to_string()]),
        );
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    pub fn resume(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
        fallback_state: EtwFallbackState,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        if self.status.lifecycle_state == EtwLifecycleState::Active {
            return Ok(self.status.clone());
        }
        self.status.lifecycle_state = EtwLifecycleState::Resuming;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        self.status.fallback_state = fallback_state;
        let outcome = self.send_command(EtwControlCommand::Resume)?;
        self.apply_outcome(Ok(outcome), EtwLifecycleState::Active, true)?;
        self.status.resume_count = self.status.resume_count.saturating_add(1);
        self.status.audit_refs = bounded_refs(
            self.status
                .audit_refs
                .clone()
                .into_iter()
                .chain(["etw_resume_completed".to_string()]),
        );
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    pub fn stop(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
        fallback_state: EtwFallbackState,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        self.stop_internal(authorization_refs, fallback_state)
    }

    pub fn shutdown_join(
        &mut self,
        fallback_state: EtwFallbackState,
    ) -> Result<EtwLifecycleStatus, String> {
        self.stop_internal(vec!["servicehost_shutdown".to_string()], fallback_state)
    }

    pub fn drain_live_batches(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        max_batches: usize,
    ) -> Result<Vec<EtwNormalizedNetworkBatch>, String> {
        self.validate_owner(owner_context)?;
        if self.status.lifecycle_state != EtwLifecycleState::Active {
            return Ok(Vec::new());
        }
        let outcome = self.send_command(EtwControlCommand::Drain(max_batches))?;
        let batches = outcome.normalized_batches.clone();
        self.apply_outcome(Ok(outcome), EtwLifecycleState::Active, false)?;
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(batches)
    }

    pub fn record_live_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        published_batches: u32,
        eventbus_publications: u32,
        security_facts: u32,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        self.status.published_batch_count = self
            .status
            .published_batch_count
            .saturating_add(published_batches);
        self.status.eventbus_publication_count = self
            .status
            .eventbus_publication_count
            .saturating_add(eventbus_publications);
        self.status.security_fact_count = self
            .status
            .security_fact_count
            .saturating_add(security_facts);
        self.status.updated_at = Timestamp::now();
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    fn stop_internal(
        &mut self,
        authorization_refs: Vec<String>,
        fallback_state: EtwFallbackState,
    ) -> Result<EtwLifecycleStatus, String> {
        if self.handle.is_none() {
            self.status.lifecycle_state = EtwLifecycleState::Stopped;
            self.status.session_state = EtwRuntimeSessionState::ControlSessionStopped;
            self.status.authorization_state = EtwAuthorizationState::Invalidated;
            self.status.control_thread_active = false;
            self.status.control_thread_joined = true;
            self.status.trace_session_created = false;
            self.status.provider_enabled = false;
            self.status.collection_started = false;
            self.status.consumer_started = false;
            self.status.consumer_worker_active = false;
            self.status.consumer_worker_joined = true;
            self.status.fallback_state = fallback_state;
            self.status.authorization_refs = bounded_refs(authorization_refs);
            self.status.updated_at = Timestamp::now();
            self.status.validate().map_err(|error| error.to_string())?;
            return Ok(self.status.clone());
        }

        self.status.lifecycle_state = EtwLifecycleState::Stopping;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        self.status.fallback_state = fallback_state;
        let outcome = self.send_command(EtwControlCommand::Stop)?;
        self.apply_runtime_outcome(&outcome);
        self.sender = None;
        let joined = self
            .handle
            .take()
            .is_none_or(|handle| handle.join().is_ok());
        if !joined {
            self.status.lifecycle_state = EtwLifecycleState::Failed;
            self.status.session_state = EtwRuntimeSessionState::Unavailable;
            self.status.control_thread_active = false;
            self.status.control_thread_joined = false;
            self.status.trace_session_created = false;
            self.status.consumer_worker_active = false;
            self.status.degraded_reason = Some("etw_control_thread_join_failed".to_string());
            self.status.updated_at = Timestamp::now();
            return Err("etw_control_thread_join_failed".to_string());
        }
        self.status.lifecycle_state = EtwLifecycleState::Stopped;
        self.status.session_state = EtwRuntimeSessionState::ControlSessionStopped;
        self.status.authorization_state = EtwAuthorizationState::Invalidated;
        self.status.control_thread_active = false;
        self.status.control_thread_joined = true;
        self.status.trace_session_created = false;
        self.status.provider_enabled = false;
        self.status.collection_started = false;
        self.status.consumer_started = false;
        self.status.consumer_worker_active = false;
        self.status.consumer_worker_joined = true;
        self.status.stop_count = self.status.stop_count.saturating_add(1);
        self.status.degraded_reason = Some("etw_control_session_stopped".to_string());
        self.status.audit_refs = bounded_refs(
            self.status
                .audit_refs
                .clone()
                .into_iter()
                .chain(["etw_stop_completed".to_string()]),
        );
        self.status.updated_at = Timestamp::now();
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    fn send_command(&self, command: EtwControlCommand) -> Result<EtwSessionControlOutcome, String> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| "etw_control_thread_unavailable".to_string())?;
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        sender
            .send(EtwControlRequest {
                command,
                response: response_tx,
            })
            .map_err(|_| "etw_control_command_rejected".to_string())?;
        response_rx
            .recv()
            .map_err(|_| "etw_control_response_unavailable".to_string())?
    }

    fn apply_outcome(
        &mut self,
        outcome: Result<EtwSessionControlOutcome, String>,
        success_state: EtwLifecycleState,
        increment_generation: bool,
    ) -> Result<(), String> {
        match outcome {
            Ok(outcome) => {
                self.status.lifecycle_state = success_state;
                self.status.session_state = match outcome.state {
                    EtwSessionControlState::Active => EtwRuntimeSessionState::ControlSessionActive,
                    EtwSessionControlState::Paused => EtwRuntimeSessionState::ControlSessionPaused,
                    EtwSessionControlState::Stopped => {
                        EtwRuntimeSessionState::ControlSessionStopped
                    }
                    EtwSessionControlState::Inactive => EtwRuntimeSessionState::NotCreated,
                    EtwSessionControlState::Unavailable => EtwRuntimeSessionState::Unavailable,
                };
                self.apply_runtime_outcome(&outcome);
                if increment_generation && outcome.trace_session_created {
                    self.status.session_generation =
                        self.status.session_generation.saturating_add(1);
                }
            }
            Err(reason) => {
                self.status.lifecycle_state = EtwLifecycleState::Degraded;
                self.status.session_state = EtwRuntimeSessionState::Unavailable;
                self.status.trace_session_created = false;
                self.status.provider_enabled = false;
                self.status.collection_started = false;
                self.status.consumer_started = false;
                self.status.consumer_worker_active = false;
                self.status.consumer_worker_joined = true;
                self.status.degraded_reason = Some(reason);
            }
        }
        self.status.updated_at = Timestamp::now();
        Ok(())
    }

    fn apply_runtime_outcome(&mut self, outcome: &EtwSessionControlOutcome) {
        self.status.trace_session_created = outcome.trace_session_created;
        self.status.provider_enabled = outcome.provider_enabled;
        self.status.collection_started = outcome.collection_started;
        self.status.consumer_started = outcome.consumer_started;
        self.status.consumer_worker_active = outcome.consumer_worker_active;
        self.status.consumer_worker_joined = outcome.consumer_worker_joined;
        self.status.raw_event_count = outcome.raw_events_observed;
        self.status.normalized_event_count = outcome.normalized_events;
        self.status.dropped_event_count = outcome.dropped_events;
        self.status.rate_limited_event_count = outcome.rate_limited_events;
        self.status.schema_rejected_event_count = outcome.schema_rejected_events;
        self.status.degraded_reason = outcome.degraded_reason.clone();
    }

    fn validate_owner(&self, owner_context: &RuntimeOwnerContext) -> Result<(), String> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || owner_context.ownership_ref != self.owner_context.ownership_ref
        {
            return Err("etw_runtime_owner_mismatch".to_string());
        }
        if owner_context.ownership_epoch != self.owner_context.ownership_epoch {
            return Err("etw_runtime_stale_ownership_epoch".to_string());
        }
        Ok(())
    }
}

impl Drop for ServiceOwnedEtwLifecycleRuntime {
    fn drop(&mut self) {
        let _ = self.stop_internal(
            vec!["etw_runtime_drop".to_string()],
            self.status.fallback_state,
        );
    }
}

fn run_control_thread(
    control: &mut dyn EtwSessionControl,
    receiver: Receiver<EtwControlRequest>,
    ready: SyncSender<Result<EtwSessionControlOutcome, String>>,
) {
    let initial = control
        .start()
        .map_err(|error| error.reason_redacted.clone());
    let _ = ready.send(initial);
    while let Ok(request) = receiver.recv() {
        let is_stop = matches!(request.command, EtwControlCommand::Stop);
        let outcome = match request.command {
            EtwControlCommand::Pause => control.pause(),
            EtwControlCommand::Resume => control.resume(),
            EtwControlCommand::Stop => control.stop(),
            EtwControlCommand::Drain(max_batches) => control.drain_normalized_batches(max_batches),
        }
        .map_err(|error| error.reason_redacted);
        let _ = request.response.send(outcome);
        if is_stop {
            break;
        }
    }
    let _ = control.stop();
}

fn bounded_refs(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut refs = values
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .take(MAX_ETW_LIFECYCLE_REFS)
        .collect::<Vec<_>>();
    refs.sort();
    refs.dedup();
    refs
}

type DnsControlFactory = Arc<dyn Fn() -> Box<dyn WindowsDnsSessionControl> + Send + Sync>;

enum DnsControlCommand {
    Pause,
    Resume,
    Stop,
    Drain(usize),
}

struct DnsControlRequest {
    command: DnsControlCommand,
    response: SyncSender<Result<WindowsDnsSessionOutcome, String>>,
}

pub struct ServiceOwnedDnsSensingLifecycleRuntime {
    owner_context: RuntimeOwnerContext,
    status: EtwLifecycleStatus,
    control_factory: DnsControlFactory,
    sender: Option<Sender<DnsControlRequest>>,
    handle: Option<JoinHandle<()>>,
}

impl ServiceOwnedDnsSensingLifecycleRuntime {
    pub fn new(owner_context: &RuntimeOwnerContext) -> Self {
        Self::with_factory(
            owner_context,
            Arc::new(|| Box::new(WindowsDnsEtwSessionAdapter::new())),
        )
    }

    fn with_factory(
        owner_context: &RuntimeOwnerContext,
        control_factory: DnsControlFactory,
    ) -> Self {
        let mut status = EtwLifecycleStatus::inactive(
            owner_context.ownership_ref.clone(),
            owner_context.ownership_epoch,
            EtwFallbackState::PortableMetadataOnly,
        );
        status.lifecycle_ref = "windows_dns_sensing_lifecycle_ref".to_string();
        status.audit_refs = vec!["windows_dns_sensing_initialized".to_string()];
        status.provenance_refs = vec!["servicehost_windows_dns_sensing_runtime".to_string()];
        Self {
            owner_context: owner_context.clone(),
            status,
            control_factory,
            sender: None,
            handle: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        owner_context: &RuntimeOwnerContext,
        control_factory: DnsControlFactory,
    ) -> Self {
        Self::with_factory(owner_context, control_factory)
    }

    pub fn status(&self) -> &EtwLifecycleStatus {
        &self.status
    }

    pub fn activate(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        if self.handle.is_some()
            && matches!(
                self.status.lifecycle_state,
                EtwLifecycleState::Active | EtwLifecycleState::Degraded
            )
        {
            return Ok(self.status.clone());
        }
        self.status.lifecycle_state = EtwLifecycleState::Activating;
        self.status.authorization_state = EtwAuthorizationState::Authorized;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        self.status.control_thread_joined = false;
        self.status.updated_at = Timestamp::now();
        let (command_tx, command_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let mut control = (self.control_factory)();
        let handle =
            thread::spawn(move || run_dns_control_thread(&mut *control, command_rx, ready_tx));
        let start_result = ready_rx
            .recv()
            .map_err(|_| "windows_dns_control_thread_start_failed".to_string())?;
        self.sender = Some(command_tx);
        self.handle = Some(handle);
        self.status.control_thread_active = true;
        self.apply_outcome(start_result, EtwLifecycleState::Active, true)?;
        self.status.activation_count = self.status.activation_count.saturating_add(1);
        self.status.audit_refs = bounded_refs(
            self.status
                .audit_refs
                .clone()
                .into_iter()
                .chain(["windows_dns_activation_authorized".to_string()]),
        );
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    pub fn pause(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        if self.status.lifecycle_state == EtwLifecycleState::Paused {
            return Ok(self.status.clone());
        }
        self.status.lifecycle_state = EtwLifecycleState::Pausing;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        let outcome = self.send_command(DnsControlCommand::Pause)?;
        self.apply_outcome(Ok(outcome), EtwLifecycleState::Paused, false)?;
        self.status.pause_count = self.status.pause_count.saturating_add(1);
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    pub fn resume(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        if self.status.lifecycle_state == EtwLifecycleState::Active {
            return Ok(self.status.clone());
        }
        self.status.lifecycle_state = EtwLifecycleState::Resuming;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        let outcome = self.send_command(DnsControlCommand::Resume)?;
        self.apply_outcome(Ok(outcome), EtwLifecycleState::Active, true)?;
        self.status.resume_count = self.status.resume_count.saturating_add(1);
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    pub fn stop(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        self.stop_internal(authorization_refs)
    }

    pub fn shutdown_join(&mut self) -> Result<EtwLifecycleStatus, String> {
        self.stop_internal(vec!["servicehost_shutdown".to_string()])
    }

    pub fn drain_live_batches(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        max_batches: usize,
    ) -> Result<Vec<sentinel_contracts::WindowsDnsObservationBatch>, String> {
        self.validate_owner(owner_context)?;
        if self.status.lifecycle_state != EtwLifecycleState::Active {
            return Ok(Vec::new());
        }
        let outcome = self.send_command(DnsControlCommand::Drain(max_batches))?;
        let batches = outcome.normalized_batches.clone();
        self.apply_outcome(Ok(outcome), EtwLifecycleState::Active, false)?;
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(batches)
    }

    pub fn record_live_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        published_batches: u32,
        eventbus_publications: u32,
        downstream_outputs: u32,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        self.status.published_batch_count = self
            .status
            .published_batch_count
            .saturating_add(published_batches);
        self.status.eventbus_publication_count = self
            .status
            .eventbus_publication_count
            .saturating_add(eventbus_publications);
        self.status.security_fact_count = self
            .status
            .security_fact_count
            .saturating_add(downstream_outputs);
        self.status.updated_at = Timestamp::now();
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    fn stop_internal(
        &mut self,
        authorization_refs: Vec<String>,
    ) -> Result<EtwLifecycleStatus, String> {
        if self.handle.is_none() {
            self.mark_stopped(authorization_refs);
            self.status.validate().map_err(|error| error.to_string())?;
            return Ok(self.status.clone());
        }
        self.status.lifecycle_state = EtwLifecycleState::Stopping;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        let outcome = self.send_command(DnsControlCommand::Stop)?;
        self.apply_runtime_outcome(&outcome);
        self.sender = None;
        let joined = self
            .handle
            .take()
            .is_none_or(|handle| handle.join().is_ok());
        if !joined {
            self.status.lifecycle_state = EtwLifecycleState::Failed;
            self.status.session_state = EtwRuntimeSessionState::Unavailable;
            self.status.control_thread_active = false;
            self.status.control_thread_joined = false;
            self.status.degraded_reason =
                Some("windows_dns_control_thread_join_failed".to_string());
            return Err("windows_dns_control_thread_join_failed".to_string());
        }
        self.mark_stopped(self.status.authorization_refs.clone());
        self.status.stop_count = self.status.stop_count.saturating_add(1);
        self.status.audit_refs = bounded_refs(
            self.status
                .audit_refs
                .clone()
                .into_iter()
                .chain(["windows_dns_stop_completed".to_string()]),
        );
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    fn mark_stopped(&mut self, authorization_refs: Vec<String>) {
        self.status.lifecycle_state = EtwLifecycleState::Stopped;
        self.status.session_state = EtwRuntimeSessionState::ControlSessionStopped;
        self.status.authorization_state = EtwAuthorizationState::Invalidated;
        self.status.control_thread_active = false;
        self.status.control_thread_joined = true;
        self.status.trace_session_created = false;
        self.status.provider_enabled = false;
        self.status.collection_started = false;
        self.status.consumer_started = false;
        self.status.consumer_worker_active = false;
        self.status.consumer_worker_joined = true;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        self.status.degraded_reason = Some("windows_dns_control_session_stopped".to_string());
        self.status.updated_at = Timestamp::now();
    }

    fn send_command(&self, command: DnsControlCommand) -> Result<WindowsDnsSessionOutcome, String> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| "windows_dns_control_thread_unavailable".to_string())?;
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        sender
            .send(DnsControlRequest {
                command,
                response: response_tx,
            })
            .map_err(|_| "windows_dns_control_command_rejected".to_string())?;
        response_rx
            .recv()
            .map_err(|_| "windows_dns_control_response_unavailable".to_string())?
    }

    fn apply_outcome(
        &mut self,
        outcome: Result<WindowsDnsSessionOutcome, String>,
        success_state: EtwLifecycleState,
        increment_generation: bool,
    ) -> Result<(), String> {
        match outcome {
            Ok(outcome) => {
                self.status.lifecycle_state = success_state;
                self.status.session_state = match outcome.state {
                    EtwSessionControlState::Active => EtwRuntimeSessionState::ControlSessionActive,
                    EtwSessionControlState::Paused => EtwRuntimeSessionState::ControlSessionPaused,
                    EtwSessionControlState::Stopped => {
                        EtwRuntimeSessionState::ControlSessionStopped
                    }
                    EtwSessionControlState::Inactive => EtwRuntimeSessionState::NotCreated,
                    EtwSessionControlState::Unavailable => EtwRuntimeSessionState::Unavailable,
                };
                self.apply_runtime_outcome(&outcome);
                if increment_generation && outcome.trace_session_created {
                    self.status.session_generation =
                        self.status.session_generation.saturating_add(1);
                }
            }
            Err(reason) => {
                self.status.lifecycle_state = EtwLifecycleState::Degraded;
                self.status.session_state = EtwRuntimeSessionState::Unavailable;
                self.status.trace_session_created = false;
                self.status.provider_enabled = false;
                self.status.collection_started = false;
                self.status.consumer_started = false;
                self.status.consumer_worker_active = false;
                self.status.consumer_worker_joined = true;
                self.status.degraded_reason = Some(reason);
            }
        }
        self.status.updated_at = Timestamp::now();
        Ok(())
    }

    fn apply_runtime_outcome(&mut self, outcome: &WindowsDnsSessionOutcome) {
        self.status.trace_session_created = outcome.trace_session_created;
        self.status.provider_enabled = outcome.provider_enabled;
        self.status.collection_started = outcome.collection_started;
        self.status.consumer_started = outcome.consumer_started;
        self.status.consumer_worker_active = outcome.consumer_worker_active;
        self.status.consumer_worker_joined = outcome.consumer_worker_joined;
        self.status.raw_event_count = outcome.raw_events_observed;
        self.status.normalized_event_count = outcome.normalized_events;
        self.status.dropped_event_count = outcome.dropped_events;
        self.status.rate_limited_event_count = outcome.rate_limited_events;
        self.status.schema_rejected_event_count = outcome.schema_rejected_events;
        self.status.degraded_reason = outcome.degraded_reason.clone();
    }

    fn validate_owner(&self, owner_context: &RuntimeOwnerContext) -> Result<(), String> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || owner_context.ownership_ref != self.owner_context.ownership_ref
        {
            return Err("windows_dns_runtime_owner_mismatch".to_string());
        }
        if owner_context.ownership_epoch != self.owner_context.ownership_epoch {
            return Err("windows_dns_runtime_stale_ownership_epoch".to_string());
        }
        Ok(())
    }
}

impl Drop for ServiceOwnedDnsSensingLifecycleRuntime {
    fn drop(&mut self) {
        let _ = self.stop_internal(vec!["windows_dns_runtime_drop".to_string()]);
    }
}

fn run_dns_control_thread(
    control: &mut dyn WindowsDnsSessionControl,
    receiver: Receiver<DnsControlRequest>,
    ready: SyncSender<Result<WindowsDnsSessionOutcome, String>>,
) {
    let initial = control
        .start()
        .map_err(|error| error.reason_redacted.clone());
    let _ = ready.send(initial);
    while let Ok(request) = receiver.recv() {
        let is_stop = matches!(request.command, DnsControlCommand::Stop);
        let outcome = match request.command {
            DnsControlCommand::Pause => control.pause(),
            DnsControlCommand::Resume => control.resume(),
            DnsControlCommand::Stop => control.stop(),
            DnsControlCommand::Drain(max_batches) => control.drain_normalized_batches(max_batches),
        }
        .map_err(|error| error.reason_redacted);
        let _ = request.response.send(outcome);
        if is_stop {
            break;
        }
    }
    let _ = control.stop();
}

type AuthRemoteControlFactory =
    Arc<dyn Fn() -> Box<dyn WindowsAuthRemoteEventLogControl> + Send + Sync>;

enum AuthRemoteControlCommand {
    Pause,
    Resume,
    Stop,
    Drain(usize),
}

struct AuthRemoteControlRequest {
    command: AuthRemoteControlCommand,
    response: SyncSender<Result<WindowsAuthRemoteEventLogOutcome, String>>,
}

pub struct ServiceOwnedAuthRemoteSensingLifecycleRuntime {
    owner_context: RuntimeOwnerContext,
    status: EtwLifecycleStatus,
    control_factory: AuthRemoteControlFactory,
    sender: Option<Sender<AuthRemoteControlRequest>>,
    handle: Option<JoinHandle<()>>,
}

impl ServiceOwnedAuthRemoteSensingLifecycleRuntime {
    pub fn new(owner_context: &RuntimeOwnerContext) -> Self {
        Self::with_factory(
            owner_context,
            Arc::new(|| Box::new(WindowsAuthRemoteEventLogAdapter::new())),
        )
    }

    pub fn rdp_operational(owner_context: &RuntimeOwnerContext) -> Self {
        let mut runtime = Self::with_factory(
            owner_context,
            Arc::new(|| Box::new(WindowsRdpOperationalEventLogAdapter::new())),
        );
        runtime.status.lifecycle_ref = "windows_rdp_operational_sensing_lifecycle_ref".to_string();
        runtime.status.audit_refs = vec!["windows_rdp_operational_sensing_initialized".to_string()];
        runtime.status.provenance_refs =
            vec!["servicehost_windows_rdp_operational_sensing_runtime".to_string()];
        runtime
    }

    pub fn smb_operational(owner_context: &RuntimeOwnerContext) -> Self {
        let mut runtime = Self::with_factory(
            owner_context,
            Arc::new(|| Box::new(WindowsSmbOperationalEventLogAdapter::new())),
        );
        runtime.status.lifecycle_ref = "windows_smb_operational_sensing_lifecycle_ref".to_string();
        runtime.status.audit_refs = vec!["windows_smb_operational_sensing_initialized".to_string()];
        runtime.status.provenance_refs =
            vec!["servicehost_windows_smb_operational_sensing_runtime".to_string()];
        runtime
    }

    pub fn ssh_operational(owner_context: &RuntimeOwnerContext) -> Self {
        let mut runtime = Self::with_factory(
            owner_context,
            Arc::new(|| Box::new(WindowsSshOperationalEventLogAdapter::new())),
        );
        runtime.status.lifecycle_ref = "windows_ssh_operational_sensing_lifecycle_ref".to_string();
        runtime.status.audit_refs = vec!["windows_ssh_operational_sensing_initialized".to_string()];
        runtime.status.provenance_refs =
            vec!["servicehost_windows_ssh_operational_sensing_runtime".to_string()];
        runtime
    }

    fn with_factory(
        owner_context: &RuntimeOwnerContext,
        control_factory: AuthRemoteControlFactory,
    ) -> Self {
        let mut status = EtwLifecycleStatus::inactive(
            owner_context.ownership_ref.clone(),
            owner_context.ownership_epoch,
            EtwFallbackState::PortableMetadataOnly,
        );
        status.lifecycle_ref = "windows_auth_remote_sensing_lifecycle_ref".to_string();
        status.audit_refs = vec!["windows_auth_remote_sensing_initialized".to_string()];
        status.provenance_refs =
            vec!["servicehost_windows_auth_remote_sensing_runtime".to_string()];
        Self {
            owner_context: owner_context.clone(),
            status,
            control_factory,
            sender: None,
            handle: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        owner_context: &RuntimeOwnerContext,
        control_factory: AuthRemoteControlFactory,
    ) -> Self {
        Self::with_factory(owner_context, control_factory)
    }

    pub fn status(&self) -> &EtwLifecycleStatus {
        &self.status
    }

    pub fn activate(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        if self.handle.is_some()
            && matches!(
                self.status.lifecycle_state,
                EtwLifecycleState::Active | EtwLifecycleState::Degraded
            )
        {
            return Ok(self.status.clone());
        }
        self.status.lifecycle_state = EtwLifecycleState::Activating;
        self.status.authorization_state = EtwAuthorizationState::Authorized;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        self.status.control_thread_joined = false;
        self.status.updated_at = Timestamp::now();

        let (command_tx, command_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let mut control = (self.control_factory)();
        let handle = thread::spawn(move || {
            run_auth_remote_control_thread(&mut *control, command_rx, ready_tx)
        });
        let start_result = ready_rx
            .recv()
            .map_err(|_| "windows_auth_remote_control_thread_start_failed".to_string())?;
        self.sender = Some(command_tx);
        self.handle = Some(handle);
        self.status.control_thread_active = true;
        self.apply_outcome(start_result, EtwLifecycleState::Active, true)?;
        self.status.activation_count = self.status.activation_count.saturating_add(1);
        self.status.audit_refs = bounded_refs(
            self.status
                .audit_refs
                .clone()
                .into_iter()
                .chain(["windows_auth_remote_activation_authorized".to_string()]),
        );
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    pub fn pause(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        if self.status.lifecycle_state == EtwLifecycleState::Paused {
            return Ok(self.status.clone());
        }
        self.status.lifecycle_state = EtwLifecycleState::Pausing;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        let outcome = self.send_command(AuthRemoteControlCommand::Pause)?;
        self.apply_outcome(Ok(outcome), EtwLifecycleState::Paused, false)?;
        self.status.pause_count = self.status.pause_count.saturating_add(1);
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    pub fn resume(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        if self.status.lifecycle_state == EtwLifecycleState::Active {
            return Ok(self.status.clone());
        }
        self.status.lifecycle_state = EtwLifecycleState::Resuming;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        let outcome = self.send_command(AuthRemoteControlCommand::Resume)?;
        self.apply_outcome(Ok(outcome), EtwLifecycleState::Active, true)?;
        self.status.resume_count = self.status.resume_count.saturating_add(1);
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    pub fn stop(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        self.stop_internal(authorization_refs)
    }

    pub fn shutdown_join(&mut self) -> Result<EtwLifecycleStatus, String> {
        self.stop_internal(vec!["servicehost_shutdown".to_string()])
    }

    pub fn drain_live_batches(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        max_batches: usize,
    ) -> Result<Vec<sentinel_contracts::WindowsAuthRemoteObservationBatch>, String> {
        self.validate_owner(owner_context)?;
        if self.status.lifecycle_state != EtwLifecycleState::Active {
            return Ok(Vec::new());
        }
        let outcome = self.send_command(AuthRemoteControlCommand::Drain(max_batches))?;
        let batches = outcome.normalized_batches.clone();
        self.apply_outcome(Ok(outcome), EtwLifecycleState::Active, false)?;
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(batches)
    }

    pub fn record_live_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        published_batches: u32,
        eventbus_publications: u32,
        downstream_facts: u32,
    ) -> Result<EtwLifecycleStatus, String> {
        self.validate_owner(owner_context)?;
        self.status.published_batch_count = self
            .status
            .published_batch_count
            .saturating_add(published_batches);
        self.status.eventbus_publication_count = self
            .status
            .eventbus_publication_count
            .saturating_add(eventbus_publications);
        self.status.security_fact_count = self
            .status
            .security_fact_count
            .saturating_add(downstream_facts);
        self.status.updated_at = Timestamp::now();
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    fn stop_internal(
        &mut self,
        authorization_refs: Vec<String>,
    ) -> Result<EtwLifecycleStatus, String> {
        if self.handle.is_none() {
            self.mark_stopped(authorization_refs);
            self.status.validate().map_err(|error| error.to_string())?;
            return Ok(self.status.clone());
        }
        self.status.lifecycle_state = EtwLifecycleState::Stopping;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        let outcome = self.send_command(AuthRemoteControlCommand::Stop)?;
        self.apply_runtime_outcome(&outcome);
        self.sender = None;
        let joined = self
            .handle
            .take()
            .is_none_or(|handle| handle.join().is_ok());
        if !joined {
            self.status.lifecycle_state = EtwLifecycleState::Failed;
            self.status.session_state = EtwRuntimeSessionState::Unavailable;
            self.status.control_thread_active = false;
            self.status.control_thread_joined = false;
            self.status.degraded_reason =
                Some("windows_auth_remote_control_thread_join_failed".to_string());
            return Err("windows_auth_remote_control_thread_join_failed".to_string());
        }
        self.mark_stopped(self.status.authorization_refs.clone());
        self.status.stop_count = self.status.stop_count.saturating_add(1);
        self.status.audit_refs = bounded_refs(
            self.status
                .audit_refs
                .clone()
                .into_iter()
                .chain(["windows_auth_remote_stop_completed".to_string()]),
        );
        self.status.validate().map_err(|error| error.to_string())?;
        Ok(self.status.clone())
    }

    fn mark_stopped(&mut self, authorization_refs: Vec<String>) {
        self.status.lifecycle_state = EtwLifecycleState::Stopped;
        self.status.session_state = EtwRuntimeSessionState::ControlSessionStopped;
        self.status.authorization_state = EtwAuthorizationState::Invalidated;
        self.status.control_thread_active = false;
        self.status.control_thread_joined = true;
        self.status.trace_session_created = false;
        self.status.provider_enabled = false;
        self.status.collection_started = false;
        self.status.consumer_started = false;
        self.status.consumer_worker_active = false;
        self.status.consumer_worker_joined = true;
        self.status.authorization_refs = bounded_refs(authorization_refs);
        self.status.degraded_reason =
            Some("windows_auth_remote_event_log_session_stopped".to_string());
        self.status.updated_at = Timestamp::now();
    }

    fn send_command(
        &self,
        command: AuthRemoteControlCommand,
    ) -> Result<WindowsAuthRemoteEventLogOutcome, String> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| "windows_auth_remote_control_thread_unavailable".to_string())?;
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        sender
            .send(AuthRemoteControlRequest {
                command,
                response: response_tx,
            })
            .map_err(|_| "windows_auth_remote_control_command_rejected".to_string())?;
        response_rx
            .recv()
            .map_err(|_| "windows_auth_remote_control_response_unavailable".to_string())?
    }

    fn apply_outcome(
        &mut self,
        outcome: Result<WindowsAuthRemoteEventLogOutcome, String>,
        success_state: EtwLifecycleState,
        increment_generation: bool,
    ) -> Result<(), String> {
        match outcome {
            Ok(outcome) => {
                self.status.lifecycle_state = success_state;
                self.status.session_state = match outcome.state {
                    WindowsAuthRemoteControlState::Active => {
                        EtwRuntimeSessionState::ControlSessionActive
                    }
                    WindowsAuthRemoteControlState::Paused => {
                        EtwRuntimeSessionState::ControlSessionPaused
                    }
                    WindowsAuthRemoteControlState::Stopped => {
                        EtwRuntimeSessionState::ControlSessionStopped
                    }
                    WindowsAuthRemoteControlState::Inactive => EtwRuntimeSessionState::NotCreated,
                    WindowsAuthRemoteControlState::Unavailable => {
                        EtwRuntimeSessionState::Unavailable
                    }
                };
                self.apply_runtime_outcome(&outcome);
                if increment_generation && outcome.provider_enabled {
                    self.status.session_generation =
                        self.status.session_generation.saturating_add(1);
                }
            }
            Err(reason) => {
                self.status.lifecycle_state = EtwLifecycleState::Degraded;
                self.status.session_state = EtwRuntimeSessionState::Unavailable;
                self.status.trace_session_created = false;
                self.status.provider_enabled = false;
                self.status.collection_started = false;
                self.status.consumer_started = false;
                self.status.consumer_worker_active = false;
                self.status.consumer_worker_joined = true;
                self.status.degraded_reason = Some(reason);
            }
        }
        self.status.updated_at = Timestamp::now();
        Ok(())
    }

    fn apply_runtime_outcome(&mut self, outcome: &WindowsAuthRemoteEventLogOutcome) {
        self.status.trace_session_created = outcome.provider_enabled;
        self.status.provider_enabled = outcome.provider_enabled;
        self.status.collection_started = outcome.collection_started;
        self.status.consumer_started = outcome.consumer_started;
        self.status.consumer_worker_active = outcome.consumer_worker_active;
        self.status.consumer_worker_joined = outcome.consumer_worker_joined;
        self.status.raw_event_count = outcome.raw_events_observed;
        self.status.normalized_event_count = outcome
            .normalized_auth_observations
            .max(outcome.normalized_remote_access_observations);
        self.status.dropped_event_count = outcome.queue_dropped_events;
        self.status.rate_limited_event_count = outcome.rate_limited_events;
        self.status.schema_rejected_event_count = outcome.schema_rejected;
        self.status.degraded_reason = outcome.degraded_reason.clone();
    }

    fn validate_owner(&self, owner_context: &RuntimeOwnerContext) -> Result<(), String> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || owner_context.ownership_ref != self.owner_context.ownership_ref
        {
            return Err("windows_auth_remote_runtime_owner_mismatch".to_string());
        }
        if owner_context.ownership_epoch != self.owner_context.ownership_epoch {
            return Err("windows_auth_remote_runtime_stale_ownership_epoch".to_string());
        }
        Ok(())
    }
}

impl Drop for ServiceOwnedAuthRemoteSensingLifecycleRuntime {
    fn drop(&mut self) {
        let _ = self.stop_internal(vec!["windows_auth_remote_runtime_drop".to_string()]);
    }
}

fn run_auth_remote_control_thread(
    control: &mut dyn WindowsAuthRemoteEventLogControl,
    receiver: Receiver<AuthRemoteControlRequest>,
    ready: SyncSender<Result<WindowsAuthRemoteEventLogOutcome, String>>,
) {
    let initial = control
        .start()
        .map_err(|error| error.reason_redacted.clone());
    let _ = ready.send(initial);
    while let Ok(request) = receiver.recv() {
        let is_stop = matches!(request.command, AuthRemoteControlCommand::Stop);
        let outcome = match request.command {
            AuthRemoteControlCommand::Pause => control.pause(),
            AuthRemoteControlCommand::Resume => control.resume(),
            AuthRemoteControlCommand::Stop => control.stop(),
            AuthRemoteControlCommand::Drain(max_batches) => {
                control.drain_normalized_batches(max_batches)
            }
        }
        .map_err(|error| error.reason_redacted);
        let _ = request.response.send(outcome);
        if is_stop {
            break;
        }
    }
    let _ = control.stop();
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_infrastructure::EtwSessionControlError;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct FakeControl {
        calls: Arc<AtomicU32>,
        fail_start: bool,
    }

    impl EtwSessionControl for FakeControl {
        fn start(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_start {
                return Err(EtwSessionControlError {
                    reason_redacted: "etw_unavailable".to_string(),
                });
            }
            Ok(fake_outcome(EtwSessionControlState::Active))
        }

        fn pause(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError> {
            Ok(fake_outcome(EtwSessionControlState::Paused))
        }

        fn resume(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError> {
            self.start()
        }

        fn stop(&mut self) -> Result<EtwSessionControlOutcome, EtwSessionControlError> {
            Ok(fake_outcome(EtwSessionControlState::Stopped))
        }

        fn drain_normalized_batches(
            &mut self,
            _max_batches: usize,
        ) -> Result<EtwSessionControlOutcome, EtwSessionControlError> {
            Ok(fake_outcome(EtwSessionControlState::Active))
        }
    }

    fn fake_outcome(state: EtwSessionControlState) -> EtwSessionControlOutcome {
        let active = state == EtwSessionControlState::Active;
        EtwSessionControlOutcome {
            state,
            trace_session_created: active,
            provider_enabled: active,
            collection_started: active,
            consumer_started: active,
            consumer_worker_active: active,
            consumer_worker_joined: !active,
            raw_events_observed: 0,
            normalized_events: 0,
            dropped_events: 0,
            rate_limited_events: 0,
            schema_rejected_events: 0,
            normalized_batches: Vec::new(),
            degraded_reason: None,
        }
    }

    fn owner() -> RuntimeOwnerContext {
        RuntimeOwnerContext::service_host("etw_owner_ref", 7, "service_instance_ref")
    }

    #[test]
    fn etw_lifecycle_activate_pause_resume_stop_and_join() {
        let owner = owner();
        let calls = Arc::new(AtomicU32::new(0));
        let factory_calls = Arc::clone(&calls);
        let factory: EtwControlFactory = Arc::new(move || {
            Box::new(FakeControl {
                calls: Arc::clone(&factory_calls),
                fail_start: false,
            })
        });
        let mut runtime = ServiceOwnedEtwLifecycleRuntime::for_test(
            &owner,
            EtwFallbackState::IpHelperAvailable,
            factory,
        );

        let active = runtime
            .activate(
                &owner,
                vec!["authorization_ref".to_string()],
                EtwFallbackState::IpHelperAvailable,
            )
            .expect("activate");
        assert_eq!(active.lifecycle_state, EtwLifecycleState::Active);
        assert!(active.trace_session_created);
        assert!(active.collection_started);

        let paused = runtime
            .pause(
                &owner,
                vec!["pause_authorization_ref".to_string()],
                EtwFallbackState::IpHelperAvailable,
            )
            .expect("pause");
        assert_eq!(paused.lifecycle_state, EtwLifecycleState::Paused);
        assert!(!paused.trace_session_created);

        let resumed = runtime
            .resume(
                &owner,
                vec!["resume_authorization_ref".to_string()],
                EtwFallbackState::IpHelperAvailable,
            )
            .expect("resume");
        assert_eq!(resumed.lifecycle_state, EtwLifecycleState::Active);
        assert_eq!(resumed.session_generation, 2);

        let stopped = runtime
            .stop(
                &owner,
                vec!["stop_authorization_ref".to_string()],
                EtwFallbackState::IpHelperAvailable,
            )
            .expect("stop");
        assert_eq!(stopped.lifecycle_state, EtwLifecycleState::Stopped);
        assert!(stopped.control_thread_joined);
        assert_eq!(stopped.eventbus_publication_count, 0);
        assert_eq!(stopped.security_fact_count, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn etw_lifecycle_unavailable_degrades_to_ip_helper_without_collection() {
        let owner = owner();
        let factory: EtwControlFactory = Arc::new(|| {
            Box::new(FakeControl {
                calls: Arc::new(AtomicU32::new(0)),
                fail_start: true,
            })
        });
        let mut runtime = ServiceOwnedEtwLifecycleRuntime::for_test(
            &owner,
            EtwFallbackState::IpHelperAvailable,
            factory,
        );
        let degraded = runtime
            .activate(
                &owner,
                vec!["authorization_ref".to_string()],
                EtwFallbackState::IpHelperAvailable,
            )
            .expect("bounded degraded status");
        assert_eq!(degraded.lifecycle_state, EtwLifecycleState::Degraded);
        assert_eq!(degraded.fallback_state, EtwFallbackState::IpHelperAvailable);
        assert!(!degraded.trace_session_created);
        assert_eq!(degraded.eventbus_publication_count, 0);
        runtime
            .shutdown_join(EtwFallbackState::IpHelperAvailable)
            .expect("join degraded thread");
    }

    #[test]
    fn etw_lifecycle_rejects_stale_owner_epoch() {
        let owner = owner();
        let mut runtime =
            ServiceOwnedEtwLifecycleRuntime::new(&owner, EtwFallbackState::IpHelperAvailable);
        let stale = RuntimeOwnerContext::service_host(
            owner.ownership_ref.clone(),
            owner.ownership_epoch + 1,
            "service_instance_ref",
        );
        assert_eq!(
            runtime.activate(
                &stale,
                vec!["authorization_ref".to_string()],
                EtwFallbackState::IpHelperAvailable,
            ),
            Err("etw_runtime_stale_ownership_epoch".to_string())
        );
    }

    struct FakeDnsControl;

    impl WindowsDnsSessionControl for FakeDnsControl {
        fn start(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
            Ok(fake_dns_outcome(EtwSessionControlState::Active))
        }

        fn pause(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
            Ok(fake_dns_outcome(EtwSessionControlState::Paused))
        }

        fn resume(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
            self.start()
        }

        fn stop(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
            Ok(fake_dns_outcome(EtwSessionControlState::Stopped))
        }

        fn drain_normalized_batches(
            &mut self,
            _max_batches: usize,
        ) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
            self.start()
        }
    }

    fn fake_dns_outcome(state: EtwSessionControlState) -> WindowsDnsSessionOutcome {
        let active = state == EtwSessionControlState::Active;
        WindowsDnsSessionOutcome {
            state,
            trace_session_created: active,
            provider_enabled: active,
            collection_started: active,
            consumer_started: active,
            consumer_worker_active: active,
            consumer_worker_joined: !active,
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

    #[test]
    fn windows_dns_lifecycle_requires_activation_and_joins_cleanly() {
        let owner = owner();
        let factory: DnsControlFactory = Arc::new(|| Box::new(FakeDnsControl));
        let mut runtime = ServiceOwnedDnsSensingLifecycleRuntime::for_test(&owner, factory);
        assert_eq!(
            runtime.status().authorization_state,
            EtwAuthorizationState::Required
        );
        let active = runtime
            .activate(&owner, vec!["dns_authorization_ref".to_string()])
            .expect("activate");
        assert_eq!(active.lifecycle_state, EtwLifecycleState::Active);
        let paused = runtime
            .pause(&owner, vec!["dns_pause_ref".to_string()])
            .expect("pause");
        assert_eq!(paused.lifecycle_state, EtwLifecycleState::Paused);
        let resumed = runtime
            .resume(&owner, vec!["dns_resume_ref".to_string()])
            .expect("resume");
        assert_eq!(resumed.lifecycle_state, EtwLifecycleState::Active);
        let stopped = runtime
            .stop(&owner, vec!["dns_stop_ref".to_string()])
            .expect("stop");
        assert_eq!(stopped.lifecycle_state, EtwLifecycleState::Stopped);
        assert!(stopped.control_thread_joined);
        assert!(stopped.consumer_worker_joined);
    }
}
