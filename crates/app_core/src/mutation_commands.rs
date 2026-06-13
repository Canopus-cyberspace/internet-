use crate::authorized_native_permissions::AuthorizedNativePermissionRuntime;
use crate::native_sampler_runtime::NativeSamplerRuntime;
use crate::native_scheduler::NativeSchedulerController;
use crate::portable_capture_import::{
    ingest_portable_capture_import, prepare_portable_capture_import,
    PortableCaptureImportConfirmation, PortableCaptureImportResult, PreparedPortableCaptureImport,
};
use crate::portable_proxy_metadata_provider::PortableProxyMetadataRuntime;
use crate::portable_source_readers::{
    PortableReaderSourcePreviewRequest, PortableSourceReaderError, PortableSourceReaderRuntime,
};
use crate::read_commands::{
    build_attack_coverage_summary, get_durable_baseline_summary, get_evidence_quality_summary,
    get_investigation_drill_down_summary, get_native_permission_status_summary,
    get_native_sampler_readiness_summary, get_native_sampler_runtime_summary,
    get_native_scheduler_operational_summary, get_native_visibility_summary, ReadOnlyCommandState,
};
use sentinel_capabilities::{
    build_export_safe_graph_snapshot_from_view as capability_export_safe_graph_snapshot_from_view,
    register_static_response_planning_plugin, ContinuousMetadataWatchController,
    ContinuousMetadataWatchError, ExportAuditService, ExportAuditSuccessInput,
    ExportDestinationMetadata, ExportFileHash, ExportHistoryError, ExportHistoryRecord,
    ExportHistoryStorageAdapter, ExportPolicyViolation, ExportPolicyViolationInput,
    GraphAnalyticsError, IncidentReportGenerator, IncidentReportInput,
    LocalProxyMetadataProviderStateKind, LocalProxyMetadataProviderStatus,
    LocalProxyMetadataStartRequest, MetadataSamplingObservation, PortableCaptureLiteRunResult,
    ReportExportGate, ReportExportGateRequest, ReportGenerationError, ResponsePlanningError,
    ResponsePlanningInput, ResponsePlanningPlugin, RESPONSE_POLICY_RULE_CONTRACT,
    RESPONSE_POLICY_SETTINGS_CONTRACT,
};
use sentinel_contracts::{
    report::{ExportFormat, ExportResult},
    Alert, AlertId, AlertState, ApprovalDecision, ApprovalRequestId, ApprovalResult,
    ApprovalResultId, ApprovalState, AuditRef, CommandResult, ContractDescriptor, CoreError,
    ErrorCode, ErrorSeverity, EventEnvelope, EventType, EvidenceId, Finding, FindingId,
    FindingState, ForensicModeSettings, ForensicScope, GraphPath, GraphPathId, GraphScope,
    GraphSnapshot, GraphSnapshotId, GraphViewModel, Incident, IncidentId, IncidentState,
    LlmAlertStoryRecord, MetadataParserFamily, MetadataSamplingBatchSummary,
    MetadataSamplingLoopAction, MetadataSamplingLoopControlRequest, MetadataSamplingLoopRunRequest,
    MetadataSamplingLoopState, MetadataSamplingMode, MetadataSamplingTickRequest,
    MetadataSamplingTickResult, MetadataSourceHealthState, MetadataWatchControllerStatus,
    MetadataWatchLifecycleRequest, MetadataWatchSourceConfirmation, MetadataWatchSourceKind,
    MetadataWatchSourcePreview, MetadataWatchSourcePreviewRequest, MetadataWatchSourceState,
    NativePermissionActionRequest, NativePermissionActionResult, NativePermissionPreview,
    NativeSamplerActivationPreview, NativeSamplerRuntimeAction, NativeSamplerRuntimeActionRequest,
    NativeSamplerRuntimeActionResult, NativeSchedulerActionRequest, NativeSchedulerActionResult,
    NativeSchedulerCycleSummary, NativeSchedulerEnablementPreview, NativeSchedulerTickRequest,
    PermissionCategory, PermissionDescriptor, PermissionKey, PermissionRiskLevel, PluginId,
    PluginManifest, PolicyDecision as ResponsePolicyDecision, PortableCaptureInputSourceType,
    PrivacyClass, PrivacyPolicy, RedactionStatus, RedactionSummary, Report, ReportId,
    ResponseAction, ResponseActionId, ResponseActionType, ResponseLevel, ResponsePlan,
    ResponsePlanSource, ResponsePolicy, ResponseResult, RollbackPlan, RollbackResult,
    RuntimeProfile, SchemaVersion, SettingsChangeKind, SettingsChangeRequest,
    SettingsImpactAnalysis, Timestamp, TraceContext, TraceId,
};
use sentinel_platform::{
    AuditActionType, AuditCategory, AuditDecision, AuditEvent, AuditReceipt, AuditSink,
    CheckpointSupport, ContractRegistry, ExportAuditMetadata, InMemoryAuditSink,
    PermissionDecision, PermissionDecisionKind, PermissionRequest, PermissionResolver,
    PermissionScope, PermissionSubject, PluginContext, PluginEventBatch, PluginRuntime,
    PolicyEvaluationContext, PolicyScope, ReplaySupport, TopicName, GRAPH_PATH, RESPONSE_PLAN,
    RESPONSE_RESULT, RESPONSE_ROLLBACK_RESULT, SECURITY_ALERT, SECURITY_FINDING, SECURITY_INCIDENT,
};
use sentinel_storage::SqliteStoreFactory;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, time::Instant};

const ACTOR_LOCAL_USER: &str = "local_user";

const ENABLE_PLUGIN: &str = "enable_plugin";
const DISABLE_PLUGIN: &str = "disable_plugin";
const RESTART_PLUGIN: &str = "restart_plugin";
const SUPPRESS_FINDING: &str = "suppress_finding";
const DISMISS_FINDING: &str = "dismiss_finding";
const ESCALATE_ALERT: &str = "escalate_alert";
const UPDATE_INCIDENT_STATUS: &str = "update_incident_status";
const CREATE_RESPONSE_PLAN: &str = "create_response_plan";
const APPROVE_RESPONSE_ACTION: &str = "approve_response_action";
const REJECT_RESPONSE_ACTION: &str = "reject_response_action";
const ROLLBACK_RESPONSE_ACTION: &str = "rollback_response_action";
const GENERATE_INCIDENT_REPORT: &str = "generate_incident_report";
const EXPORT_REPORT: &str = "export_report";
const CONFIRM_PORTABLE_CAPTURE_IMPORT: &str = "confirm_portable_capture_import";
const CONFIRM_METADATA_WATCH_SOURCE: &str = "confirm_metadata_watch_source";
const UPDATE_METADATA_WATCH_SOURCE: &str = "update_metadata_watch_source";
const TICK_METADATA_WATCH_CONTROLLER: &str = "tick_metadata_watch_controller";
const UPDATE_METADATA_SAMPLING_LOOP: &str = "update_metadata_sampling_loop";
const RUN_METADATA_SAMPLING_LOOP: &str = "run_metadata_sampling_loop";
const APPLY_RUNTIME_PROFILE: &str = "apply_runtime_profile";
const UPDATE_PRIVACY_POLICY: &str = "update_privacy_policy";
const UPDATE_RESPONSE_POLICY: &str = "update_response_policy";
const ENABLE_FORENSIC_MODE: &str = "enable_forensic_mode";
const DISABLE_FORENSIC_MODE: &str = "disable_forensic_mode";
const PREVIEW_NATIVE_SAMPLER_ACTIVATION: &str = "preview_native_sampler_activation";
const APPLY_NATIVE_SAMPLER_RUNTIME_ACTION: &str = "apply_native_sampler_runtime_action";

pub struct MutationCommandState {
    read: ReadOnlyCommandState,
    permission_resolver: PermissionResolver,
    audit_sink: InMemoryAuditSink,
    actor_redacted: String,
    plugin_lifecycle: HashMap<sentinel_contracts::PluginId, PluginLifecycleMutationState>,
    response_actions: Vec<ResponseAction>,
    approval_results: Vec<ApprovalResult>,
    response_results: Vec<ResponseResult>,
    rollback_results: Vec<RollbackResult>,
    export_results: Vec<ExportResult>,
    settings_rollbacks: HashMap<String, RuntimeProfile>,
    portable_proxy_runtime: PortableProxyMetadataRuntime,
    metadata_watch_controller: ContinuousMetadataWatchController,
    metadata_reader_runtime: PortableSourceReaderRuntime,
    metadata_sampling_loop: MetadataSamplingLoopRuntime,
    authorized_native_permission_runtime: AuthorizedNativePermissionRuntime,
    native_sampler_runtime: NativeSamplerRuntime,
    native_scheduler_controller: NativeSchedulerController,
}

#[derive(Clone, Debug)]
struct MetadataSamplingLoopRuntime {
    state: MetadataSamplingLoopState,
    max_sources_per_cycle: u32,
    max_concurrent_sources: u32,
    max_files_per_tick: u32,
    per_source_timeout_millis: u32,
    last_scheduled_at: Option<Timestamp>,
    graceful_shutdown_requested: bool,
    scheduled_source_count: u32,
}

impl Default for MetadataSamplingLoopRuntime {
    fn default() -> Self {
        Self {
            state: MetadataSamplingLoopState::Disabled,
            max_sources_per_cycle: 8,
            max_concurrent_sources: 1,
            max_files_per_tick: 8,
            per_source_timeout_millis: 5_000,
            last_scheduled_at: None,
            graceful_shutdown_requested: false,
            scheduled_source_count: 0,
        }
    }
}

impl MetadataSamplingLoopRuntime {
    fn apply_control(&mut self, request: &MetadataSamplingLoopControlRequest) {
        self.max_sources_per_cycle = request.max_sources_per_cycle;
        self.max_concurrent_sources = request.max_concurrent_sources;
        self.max_files_per_tick = request.max_files_per_tick;
        self.per_source_timeout_millis = request.per_source_timeout_millis;
        match request.action {
            MetadataSamplingLoopAction::Enable | MetadataSamplingLoopAction::ResumeAll => {
                self.state = MetadataSamplingLoopState::Running;
                self.graceful_shutdown_requested = false;
            }
            MetadataSamplingLoopAction::Disable => {
                self.state = MetadataSamplingLoopState::Disabled;
                self.graceful_shutdown_requested = false;
                self.scheduled_source_count = 0;
            }
            MetadataSamplingLoopAction::PauseAll => {
                self.state = MetadataSamplingLoopState::Paused;
            }
            MetadataSamplingLoopAction::Shutdown => {
                self.state = MetadataSamplingLoopState::ShuttingDown;
                self.graceful_shutdown_requested = true;
                self.scheduled_source_count = 0;
            }
        }
    }

    fn is_running(&self) -> bool {
        self.state == MetadataSamplingLoopState::Running
    }

    fn is_enabled(&self) -> bool {
        matches!(
            self.state,
            MetadataSamplingLoopState::Running | MetadataSamplingLoopState::Paused
        )
    }

    fn source_limit(&self, requested_max_sources: u32) -> usize {
        requested_max_sources
            .min(self.max_sources_per_cycle)
            .min(self.max_concurrent_sources)
            .max(1) as usize
    }

    fn record_cycle(&mut self, selected_source_count: usize) {
        self.last_scheduled_at = Some(Timestamp::now());
        self.scheduled_source_count = u32::try_from(selected_source_count).unwrap_or(u32::MAX);
    }

    fn record_idle_cycle(&mut self) {
        self.scheduled_source_count = 0;
    }

    fn apply_to_status(&self, status: &mut MetadataWatchControllerStatus) {
        status.loop_state = self.state.clone();
        status.loop_enabled = self.is_enabled();
        status.loop_paused = self.state == MetadataSamplingLoopState::Paused;
        status.scheduled_source_count = self.scheduled_source_count;
        status.max_sources_per_cycle = self.max_sources_per_cycle;
        status.max_concurrent_sources = self.max_concurrent_sources;
        status.max_files_per_tick = self.max_files_per_tick;
        status.per_source_timeout_millis = self.per_source_timeout_millis;
        status.last_scheduled_at = self.last_scheduled_at.clone();
        status.graceful_shutdown_requested = self.graceful_shutdown_requested;
        if self.is_enabled() {
            status.scheduler_mode = "background_sampling_loop".to_string();
        }
        if self.is_running() {
            status.running = true;
        }
    }
}

impl MutationCommandState {
    pub fn bootstrap() -> CommandResult<Self> {
        Self::from_read_state(ReadOnlyCommandState::bootstrap()?)
    }

    pub fn from_read_state(read: ReadOnlyCommandState) -> CommandResult<Self> {
        let mut permission_resolver = PermissionResolver::new();
        register_tauri_mutation_permissions(&mut permission_resolver)?;
        let metadata_watch_controller = ContinuousMetadataWatchController::from_read_models(
            read.metadata_watch_sources.items.clone(),
            read.metadata_sampling_batches.items.clone(),
        )
        .map_err(metadata_watch_error)?;
        let authorized_native_permission_runtime =
            AuthorizedNativePermissionRuntime::from_read_state(&read);
        let native_sampler_runtime = NativeSamplerRuntime::from_read_state(&read);
        let native_scheduler_controller = NativeSchedulerController::from_read_state(&read);
        let mut state = Self {
            read,
            permission_resolver,
            audit_sink: InMemoryAuditSink::new(),
            actor_redacted: ACTOR_LOCAL_USER.to_string(),
            plugin_lifecycle: HashMap::new(),
            response_actions: Vec::new(),
            approval_results: Vec::new(),
            response_results: Vec::new(),
            rollback_results: Vec::new(),
            export_results: Vec::new(),
            settings_rollbacks: HashMap::new(),
            portable_proxy_runtime: PortableProxyMetadataRuntime::default(),
            metadata_watch_controller,
            metadata_reader_runtime: PortableSourceReaderRuntime::default(),
            metadata_sampling_loop: MetadataSamplingLoopRuntime::default(),
            authorized_native_permission_runtime,
            native_sampler_runtime,
            native_scheduler_controller,
        };
        sync_metadata_watch_read_state(&mut state)?;
        Ok(state)
    }

    pub fn read_state(&self) -> &ReadOnlyCommandState {
        &self.read
    }

    pub fn audit_records(&self) -> &[AuditEvent] {
        self.audit_sink.records()
    }

    pub fn response_actions(&self) -> &[ResponseAction] {
        &self.response_actions
    }

    pub fn approval_results(&self) -> &[ApprovalResult] {
        &self.approval_results
    }

    pub fn response_results(&self) -> &[ResponseResult] {
        &self.response_results
    }

    pub fn rollback_results(&self) -> &[RollbackResult] {
        &self.rollback_results
    }

    pub fn export_results(&self) -> &[ExportResult] {
        &self.export_results
    }

    pub fn record_llm_alert_story(&mut self, story: LlmAlertStoryRecord) -> CommandResult<()> {
        story.validate().map_err(contract_error)?;
        self.read.llm_alert_stories.items.push(story);
        Ok(())
    }

    pub fn preview_native_permission_request(
        &mut self,
        capability_id: String,
    ) -> CommandResult<NativePermissionPreview> {
        self.authorized_native_permission_runtime
            .preview_permission_request(&capability_id)
    }

    pub fn update_native_permission(
        &mut self,
        request: NativePermissionActionRequest,
    ) -> CommandResult<NativePermissionActionResult> {
        let result = self
            .authorized_native_permission_runtime
            .apply_action(request)?;
        self.authorized_native_permission_runtime
            .sync_read_state(&mut self.read);
        if result.capability.permission_state == sentinel_contracts::NativePermissionState::Revoked
        {
            for status in &mut self.read.native_sampler_runtime_statuses {
                if status.capability_id == result.capability.capability_id {
                    status.runtime_state = sentinel_contracts::NativeSamplerRuntimeState::Revoked;
                    status.health_state = sentinel_contracts::NativeRuntimeHealthState::Revoked;
                    status.permission_state = sentinel_contracts::NativePermissionState::Revoked;
                    status.telemetry_collection_active = false;
                    status.interval_sampling_enabled = false;
                    status.degraded_reason = Some("authorization_revoked".to_string());
                    status.missing_prerequisite_flags = vec!["authorization_revoked".to_string()];
                }
            }
        }
        self.native_sampler_runtime = NativeSamplerRuntime::from_read_state(&self.read);
        self.native_scheduler_controller.reconcile(&self.read)?;
        self.native_scheduler_controller
            .sync_read_state(&mut self.read);
        Ok(result)
    }

    pub fn preview_native_sampler_activation(
        &mut self,
        sampler_id: String,
    ) -> CommandResult<NativeSamplerActivationPreview> {
        self.native_sampler_runtime
            .preview_activation(&self.read, &sampler_id)
    }

    pub fn apply_native_sampler_runtime_action(
        &mut self,
        request: NativeSamplerRuntimeActionRequest,
    ) -> CommandResult<NativeSamplerRuntimeActionResult> {
        if request.action == NativeSamplerRuntimeAction::ScheduledSample {
            return Err(CoreError::validation_failure(
                "scheduled native samples require the scheduler tick runtime",
            ));
        }
        if request.action == NativeSamplerRuntimeAction::Revoke {
            if let Some(permission_request) =
                NativeSamplerRuntime::revoke_matching_capability(&request.sampler_id)?
            {
                self.authorized_native_permission_runtime
                    .apply_action(permission_request)?;
                self.authorized_native_permission_runtime
                    .sync_read_state(&mut self.read);
            }
        }
        let result = self
            .native_sampler_runtime
            .apply_action(&mut self.read, request)?;
        self.native_sampler_runtime.sync_read_state(&mut self.read);
        self.native_scheduler_controller.reconcile(&self.read)?;
        self.native_scheduler_controller
            .sync_read_state(&mut self.read);
        Ok(result)
    }

    pub fn preview_native_scheduler_enablement(
        &mut self,
        sampler_id: String,
    ) -> CommandResult<NativeSchedulerEnablementPreview> {
        self.native_scheduler_controller
            .preview_enablement(&self.read, &sampler_id)
    }

    pub fn apply_native_scheduler_action(
        &mut self,
        request: NativeSchedulerActionRequest,
    ) -> CommandResult<NativeSchedulerActionResult> {
        let result = self
            .native_scheduler_controller
            .apply_action(&mut self.read, request)?;
        self.native_scheduler_controller
            .sync_read_state(&mut self.read);
        Ok(result)
    }

    pub fn tick_native_scheduler(
        &mut self,
        request: NativeSchedulerTickRequest,
    ) -> CommandResult<NativeSchedulerCycleSummary> {
        let result = self.native_scheduler_controller.tick(
            &mut self.read,
            &mut self.native_sampler_runtime,
            request,
        )?;
        self.native_sampler_runtime.sync_read_state(&mut self.read);
        self.native_scheduler_controller
            .sync_read_state(&mut self.read);
        Ok(result)
    }

    pub fn get_local_metadata_proxy_status(&mut self) -> LocalProxyMetadataProviderStatus {
        self.portable_proxy_runtime.status_snapshot()
    }

    pub fn start_local_metadata_proxy(
        &mut self,
        request: LocalProxyMetadataStartRequest,
    ) -> CommandResult<LocalProxyMetadataProviderStatus> {
        self.portable_proxy_runtime.start(&mut self.read, request)
    }

    pub fn stop_local_metadata_proxy(&mut self) -> CommandResult<LocalProxyMetadataProviderStatus> {
        let status = self.portable_proxy_runtime.stop(&mut self.read)?;
        mark_proxy_watch_sources_after_stop(self)?;
        sync_metadata_watch_read_state(self)?;
        Ok(status)
    }

    pub fn drain_local_metadata_proxy(
        &mut self,
    ) -> CommandResult<LocalProxyMetadataProviderStatus> {
        self.portable_proxy_runtime.drain(&mut self.read)
    }

    pub fn preview_metadata_watch_source(
        &mut self,
        request: MetadataWatchSourcePreviewRequest,
    ) -> CommandResult<MetadataWatchSourcePreview> {
        request.validate().map_err(contract_error)?;
        self.metadata_watch_controller
            .preview_source(request)
            .map_err(metadata_watch_error)
    }

    pub fn preview_portable_reader_source(
        &mut self,
        request: PortableReaderSourcePreviewRequest,
    ) -> CommandResult<MetadataWatchSourcePreview> {
        preview_portable_reader_source(self, request)
    }

    pub fn confirm_metadata_watch_source(
        &mut self,
        confirmation: MetadataWatchSourceConfirmation,
    ) -> CommandResult<MutationReceipt<MetadataWatchControllerStatus>> {
        confirm_metadata_watch_source(self, confirmation)
    }

    pub fn update_metadata_watch_source(
        &mut self,
        request: MetadataWatchLifecycleRequest,
    ) -> CommandResult<MutationReceipt<MetadataWatchControllerStatus>> {
        update_metadata_watch_source(self, request)
    }

    pub fn tick_metadata_watch_controller(
        &mut self,
        request: MetadataSamplingTickRequest,
    ) -> CommandResult<MutationReceipt<MetadataSamplingTickResult>> {
        tick_metadata_watch_controller(self, request)
    }

    pub fn update_metadata_sampling_loop(
        &mut self,
        request: MetadataSamplingLoopControlRequest,
    ) -> CommandResult<MutationReceipt<MetadataWatchControllerStatus>> {
        update_metadata_sampling_loop(self, request)
    }

    pub fn run_metadata_sampling_loop(
        &mut self,
        request: MetadataSamplingLoopRunRequest,
    ) -> CommandResult<MutationReceipt<MetadataSamplingTickResult>> {
        run_metadata_sampling_loop(self, request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationReceipt<T> {
    pub command: String,
    pub result: T,
    pub permission_decision: PermissionDecision,
    pub audit_receipt: AuditReceipt,
    pub trace_id: TraceId,
    pub rollback: Option<MutationRollbackMetadata>,
    pub generated_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationRollbackMetadata {
    pub rollback_ref: String,
    pub rollback_kind: String,
    pub rollback_available: bool,
    pub audit_required: bool,
    pub expires_at: Option<Timestamp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginLifecycleMutationState {
    Enabled,
    Disabled,
    RestartRequested,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginLifecycleRequest {
    pub plugin_id: sentinel_contracts::PluginId,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginLifecycleMutationResult {
    pub plugin_id: sentinel_contracts::PluginId,
    pub plugin_name: String,
    pub state: PluginLifecycleMutationState,
    pub applied_to_runtime: bool,
    pub reason_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FindingStateMutationRequest {
    pub finding_id: FindingId,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FindingStateMutationResult {
    pub finding: Finding,
    pub applied_state: FindingState,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EscalateAlertRequest {
    pub alert_id: AlertId,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AlertEscalationResult {
    pub alert: Alert,
    pub routed_to_incident_stage: bool,
    pub incident_created: Option<Incident>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentStatusMutationRequest {
    pub incident_id: IncidentId,
    pub state: IncidentState,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentStatusMutationResult {
    pub incident: Incident,
    pub applied_state: IncidentState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateResponsePlanRequest {
    pub source: ResponsePlanSource,
    pub reason_redacted: String,
    pub created_by_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlanMutationResult {
    pub plan: ResponsePlan,
    pub actions: Vec<ResponseAction>,
    pub execution_started: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseApprovalMutationRequest {
    pub action_id: ResponseActionId,
    pub actor_redacted: Option<String>,
    pub reason_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseApprovalMutationResult {
    pub action: ResponseAction,
    pub approval_result: ApprovalResult,
    pub execution_started: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RollbackResponseActionRequest {
    pub action_id: ResponseActionId,
    pub actor_redacted: Option<String>,
    pub reason_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RollbackResponseActionResult {
    pub rollback_result: RollbackResult,
    pub execution_performed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerateIncidentReportRequest {
    pub incident_id: IncidentId,
    pub requested_by_redacted: Option<String>,
    pub reason_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportGenerationResult {
    pub report: Report,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportReportRequest {
    pub report_id: ReportId,
    pub format: ExportFormat,
    pub destination_metadata_redacted: Option<String>,
    pub requested_by_redacted: Option<String>,
    pub user_confirmed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportReportMutationResult {
    pub export_result: ExportResult,
    pub export_performed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApplyRuntimeProfileRequest {
    pub profile: RuntimeProfile,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePrivacyPolicyRequest {
    pub policy: PrivacyPolicy,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateResponsePolicyRequest {
    pub policy: ResponsePolicy,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnableForensicModeRequest {
    pub reason_redacted: String,
    pub scope: ForensicScope,
    pub requested_by_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisableForensicModeRequest {
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SettingsMutationResult {
    pub runtime_profile: RuntimeProfile,
    pub change_request: SettingsChangeRequest,
    pub impact_analysis: SettingsImpactAnalysis,
}

pub fn enable_plugin(
    state: &mut MutationCommandState,
    request: PluginLifecycleRequest,
) -> CommandResult<MutationReceipt<PluginLifecycleMutationResult>> {
    plugin_lifecycle_mutation(
        state,
        ENABLE_PLUGIN,
        request,
        PluginLifecycleMutationState::Enabled,
    )
}

pub fn disable_plugin(
    state: &mut MutationCommandState,
    request: PluginLifecycleRequest,
) -> CommandResult<MutationReceipt<PluginLifecycleMutationResult>> {
    plugin_lifecycle_mutation(
        state,
        DISABLE_PLUGIN,
        request,
        PluginLifecycleMutationState::Disabled,
    )
}

pub fn restart_plugin(
    state: &mut MutationCommandState,
    request: PluginLifecycleRequest,
) -> CommandResult<MutationReceipt<PluginLifecycleMutationResult>> {
    plugin_lifecycle_mutation(
        state,
        RESTART_PLUGIN,
        request,
        PluginLifecycleMutationState::RestartRequested,
    )
}

pub fn suppress_finding(
    state: &mut MutationCommandState,
    request: FindingStateMutationRequest,
) -> CommandResult<MutationReceipt<FindingStateMutationResult>> {
    finding_state_mutation(state, SUPPRESS_FINDING, request, FindingState::Suppressed)
}

pub fn dismiss_finding(
    state: &mut MutationCommandState,
    request: FindingStateMutationRequest,
) -> CommandResult<MutationReceipt<FindingStateMutationResult>> {
    finding_state_mutation(state, DISMISS_FINDING, request, FindingState::Dismissed)
}

pub fn escalate_alert(
    state: &mut MutationCommandState,
    request: EscalateAlertRequest,
) -> CommandResult<MutationReceipt<AlertEscalationResult>> {
    require_reason(&request.reason_redacted)?;
    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.requested_by_redacted.as_deref());
    let target = format!("alert:{}", request.alert_id);
    let audit = AuditDraft::generic(
        AuditCategory::SecurityCase,
        AuditActionType::Custom("security.alert.escalated".to_string()),
        actor,
        target,
    );
    let permission = authorize(
        state,
        &trace_id,
        ESCALATE_ALERT,
        "data.security_case.write",
        PermissionScope::Data {
            resource: "security.alert".to_string(),
            operation: "escalate".to_string(),
            metadata_only: true,
        },
        PolicyScope::TauriMutationCommand,
        &request.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;
    let alert = mutate_alert(state, &request.alert_id, |alert| {
        alert.with_state(AlertState::EscalatedToIncident)
    })?;
    let result = AlertEscalationResult {
        alert,
        routed_to_incident_stage: true,
        incident_created: None,
    };
    finish_mutation(
        state,
        ESCALATE_ALERT,
        result,
        permission,
        &trace_id,
        audit.with_result("alert escalation request recorded"),
        None,
    )
}

pub fn update_incident_status(
    state: &mut MutationCommandState,
    request: IncidentStatusMutationRequest,
) -> CommandResult<MutationReceipt<IncidentStatusMutationResult>> {
    require_reason(&request.reason_redacted)?;
    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.requested_by_redacted.as_deref());
    let target = format!("incident:{}", request.incident_id);
    let audit = AuditDraft::generic(
        AuditCategory::SecurityCase,
        AuditActionType::Custom("security.incident.status_changed".to_string()),
        actor,
        target,
    );
    let permission = authorize(
        state,
        &trace_id,
        UPDATE_INCIDENT_STATUS,
        "data.security_case.write",
        PermissionScope::Data {
            resource: "security.incident".to_string(),
            operation: "update_status".to_string(),
            metadata_only: true,
        },
        PolicyScope::TauriMutationCommand,
        &request.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;
    let incident = mutate_incident(state, &request.incident_id, |incident| {
        incident.with_state(request.state.clone())
    })?;
    let result = IncidentStatusMutationResult {
        incident,
        applied_state: request.state,
    };
    finish_mutation(
        state,
        UPDATE_INCIDENT_STATUS,
        result,
        permission,
        &trace_id,
        audit.with_result("incident status updated"),
        None,
    )
}

pub fn create_response_plan(
    state: &mut MutationCommandState,
    request: CreateResponsePlanRequest,
) -> CommandResult<MutationReceipt<ResponsePlanMutationResult>> {
    require_reason(&request.reason_redacted)?;
    validate_response_plan_source(state, &request.source)?;
    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.created_by_redacted.as_deref());
    let target = response_source_target(&request.source);
    let audit = AuditDraft::response(
        AuditActionType::ResponsePlanCreated,
        actor.clone(),
        target,
        "not_applicable".to_string(),
    );
    let permission = authorize(
        state,
        &trace_id,
        CREATE_RESPONSE_PLAN,
        "response.plan.write",
        PermissionScope::Response {
            action_type: ResponseActionType::RecommendProcessReview,
            execute: false,
        },
        PolicyScope::ResponsePlanning,
        &request.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;

    let planning_output = response_planning_output_for_source(state, &request.source, &trace_id)?;
    let mut plan = response_plan_for_source(planning_output.response_plans, &request.source)?;
    plan.created_by = actor;
    plan.execution_disabled_in_replay = true;
    if planning_output.used_static_runtime {
        push_unique_string(
            &mut plan.audit_requirements,
            "response.runtime.static_internal.process_batch".to_string(),
        );
    }
    push_unique_string(
        &mut plan.audit_requirements,
        "response.execution.deferred".to_string(),
    );
    prepare_response_plan_metadata(&mut plan)?;

    let actions = response_actions_for_plan(&mut plan, &trace_id);
    state.read.response_plans.items.push(plan.clone());
    state.response_actions.extend(actions.clone());
    for action in actions
        .iter()
        .filter(|action| action.approval_state == ApprovalState::Approved)
    {
        record_non_executing_response_result(state, action, &trace_id)?;
    }

    let rollback = actions.first().map(|action| MutationRollbackMetadata {
        rollback_ref: action.rollback_plan.rollback_plan_id.to_string(),
        rollback_kind: "response_action".to_string(),
        rollback_available: true,
        audit_required: true,
        expires_at: action.rollback_plan.rollback_deadline.clone(),
    });
    let result = ResponsePlanMutationResult {
        plan,
        actions,
        execution_started: false,
    };
    finish_mutation(
        state,
        CREATE_RESPONSE_PLAN,
        result,
        permission,
        &trace_id,
        audit.with_result(
            "response plan created from incident, graph context, policy, approval, and rollback metadata without execution",
        ),
        rollback,
    )
}

pub fn approve_response_action(
    state: &mut MutationCommandState,
    request: ResponseApprovalMutationRequest,
) -> CommandResult<MutationReceipt<ResponseApprovalMutationResult>> {
    response_approval_mutation(
        state,
        APPROVE_RESPONSE_ACTION,
        request,
        ApprovalDecision::Approved,
    )
}

pub fn reject_response_action(
    state: &mut MutationCommandState,
    request: ResponseApprovalMutationRequest,
) -> CommandResult<MutationReceipt<ResponseApprovalMutationResult>> {
    response_approval_mutation(
        state,
        REJECT_RESPONSE_ACTION,
        request,
        ApprovalDecision::Rejected,
    )
}

pub fn rollback_response_action(
    state: &mut MutationCommandState,
    request: RollbackResponseActionRequest,
) -> CommandResult<MutationReceipt<RollbackResponseActionResult>> {
    require_reason(&request.reason_redacted)?;
    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.actor_redacted.as_deref());
    let action = get_response_action(state, &request.action_id)?.clone();
    let rollback_ref = action.rollback_plan.rollback_plan_id.to_string();
    let audit = AuditDraft::response(
        AuditActionType::ResponseRollbackStarted,
        actor.clone(),
        format!("response_action:{}", request.action_id),
        rollback_ref.clone(),
    );
    let permission = authorize(
        state,
        &trace_id,
        ROLLBACK_RESPONSE_ACTION,
        "response.rollback.write",
        PermissionScope::Response {
            action_type: action.action_type.clone(),
            execute: false,
        },
        PolicyScope::TauriMutationCommand,
        &request.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;
    let audit_ref = AuditRef {
        audit_id: sentinel_contracts::AuditId::new_v4(),
        event_type: "response.rollback.disabled".to_string(),
        trace_id: Some(trace_id.clone()),
        timestamp: Timestamp::now(),
    };
    let mut rollback_result =
        RollbackResult::new(request.action_id, &action.rollback_plan, audit_ref);
    rollback_result.ended_at = Some(Timestamp::now());
    rollback_result.error_summary_redacted =
        Some("no privileged executor has run; rollback request recorded only".to_string());
    state.rollback_results.push(rollback_result.clone());
    let result = RollbackResponseActionResult {
        rollback_result,
        execution_performed: false,
    };
    finish_mutation(
        state,
        ROLLBACK_RESPONSE_ACTION,
        result,
        permission,
        &trace_id,
        audit.with_result("rollback request recorded without OS action"),
        None,
    )
}

pub fn generate_incident_report(
    state: &mut MutationCommandState,
    request: GenerateIncidentReportRequest,
) -> CommandResult<MutationReceipt<ReportGenerationResult>> {
    require_reason(&request.reason_redacted)?;
    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.requested_by_redacted.as_deref());
    let incident = find_incident(state, &request.incident_id)?.clone();
    let audit = AuditDraft::generic(
        AuditCategory::Report,
        AuditActionType::Custom("report.incident.generated".to_string()),
        actor,
        format!("incident:{}", request.incident_id),
    );
    let permission = authorize(
        state,
        &trace_id,
        GENERATE_INCIDENT_REPORT,
        "report.generate.write",
        PermissionScope::Data {
            resource: "report.incident".to_string(),
            operation: "generate".to_string(),
            metadata_only: true,
        },
        PolicyScope::TauriMutationCommand,
        &request.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;

    let related_alerts = state
        .read
        .alerts
        .items
        .iter()
        .filter(|alert| incident.alert_refs().contains(alert.id()))
        .cloned()
        .collect::<Vec<_>>();
    let related_finding_ids = related_alerts
        .iter()
        .flat_map(|alert| alert.finding_refs().iter().cloned())
        .chain(incident.finding_refs().iter().cloned())
        .collect::<Vec<_>>();
    let related_findings = state
        .read
        .findings
        .items
        .iter()
        .filter(|finding| related_finding_ids.contains(finding.id()))
        .cloned()
        .collect::<Vec<_>>();
    let response_plans = state
        .read
        .response_plans
        .items
        .iter()
        .filter(
            |plan| matches!(&plan.source, ResponsePlanSource::Incident(id) if id == incident.id()),
        )
        .cloned()
        .collect::<Vec<_>>();
    let response_plan_ids = response_plans
        .iter()
        .map(|plan| plan.plan_id.clone())
        .collect::<Vec<_>>();
    let related_action_ids = state
        .response_actions
        .iter()
        .filter(|action| response_plan_ids.contains(&action.plan_id))
        .map(|action| action.action_id.clone())
        .collect::<Vec<_>>();
    let rollback_results = state
        .rollback_results
        .iter()
        .filter(|result| related_action_ids.contains(&result.action_id))
        .cloned()
        .collect::<Vec<_>>();
    let response_results = state
        .response_results
        .iter()
        .filter(|result| related_action_ids.contains(&result.action_id))
        .cloned()
        .collect::<Vec<_>>();
    let mut input = IncidentReportInput::new(incident);
    input.alerts = related_alerts;
    input.findings = related_findings;
    input.graph_snapshots =
        graph_snapshots_for_incident(state, &request.incident_id, &input.findings)?;
    let coverage_read = state
        .read
        .clone()
        .with_findings(input.findings.clone())
        .with_alerts(input.alerts.clone());
    input.attack_coverage = Some(build_attack_coverage_summary(&coverage_read)?);
    input.fusion_summary = state
        .read
        .fusion_summaries
        .last()
        .filter(|summary| {
            summary.finding_refs.iter().any(|finding_ref| {
                input
                    .findings
                    .iter()
                    .any(|finding| finding.id() == finding_ref)
            })
        })
        .cloned();
    input.baseline_summary = Some(get_durable_baseline_summary(&state.read)?);
    input.investigation_drill_down = Some(get_investigation_drill_down_summary(&state.read)?);
    input.evidence_quality_summary = Some(get_evidence_quality_summary(&state.read)?);
    input.metadata_watch_status = Some(state.read.metadata_watch_controller_status.clone());
    input.metadata_sampling_batches = state
        .read
        .metadata_sampling_batches
        .items
        .iter()
        .rev()
        .take(64)
        .cloned()
        .collect();
    input.metadata_sampling_batches.reverse();
    input.native_permission_status = Some(get_native_permission_status_summary(&state.read)?);
    input.native_visibility_summary = Some(get_native_visibility_summary(&state.read)?);
    input.native_sampler_readiness = Some(get_native_sampler_readiness_summary(&state.read)?);
    input.native_sampler_runtime = Some(get_native_sampler_runtime_summary(&state.read)?);
    input.native_scheduler_operational =
        Some(get_native_scheduler_operational_summary(&state.read)?);
    input.llm_alert_stories = state
        .read
        .llm_alert_stories
        .items
        .iter()
        .filter(|story| {
            story.incident_ref.as_ref() == Some(&request.incident_id)
                || input
                    .alerts
                    .iter()
                    .any(|alert| alert.id() == &story.alert_ref)
        })
        .cloned()
        .collect();
    input.response_plans = response_plans;
    input.response_results = response_results;
    input.rollback_results = rollback_results;
    let output = IncidentReportGenerator::new()
        .generate(input)
        .map_err(report_generation_error)?;
    let report = output.report;
    state.read.reports.items.push(report.clone());

    finish_mutation(
        state,
        GENERATE_INCIDENT_REPORT,
        ReportGenerationResult { report },
        permission,
        &trace_id,
        audit.with_result("incident report generated from redacted metadata"),
        None,
    )
}

pub fn export_report(
    state: &mut MutationCommandState,
    request: ExportReportRequest,
) -> CommandResult<MutationReceipt<ExportReportMutationResult>> {
    export_report_impl(state, request, None)
}

pub fn preview_metadata_watch_source(
    state: &mut MutationCommandState,
    request: MetadataWatchSourcePreviewRequest,
) -> CommandResult<MetadataWatchSourcePreview> {
    request.validate().map_err(contract_error)?;
    state
        .metadata_watch_controller
        .preview_source(request)
        .map_err(metadata_watch_error)
}

pub fn preview_portable_reader_source(
    state: &mut MutationCommandState,
    request: PortableReaderSourcePreviewRequest,
) -> CommandResult<MetadataWatchSourcePreview> {
    request.watch_request.validate().map_err(contract_error)?;
    let preview = state
        .metadata_watch_controller
        .preview_source(request.watch_request.clone())
        .map_err(metadata_watch_error)?;
    state
        .metadata_reader_runtime
        .preview_source(&preview, &request)
        .map_err(portable_reader_error)?;
    Ok(preview)
}

pub fn confirm_metadata_watch_source(
    state: &mut MutationCommandState,
    confirmation: MetadataWatchSourceConfirmation,
) -> CommandResult<MutationReceipt<MetadataWatchControllerStatus>> {
    confirmation.validate().map_err(contract_error)?;
    require_reason(&confirmation.reason_redacted)?;
    if !confirmation.user_confirmed {
        return Err(CoreError::new(
            ErrorCode::PolicyDenial,
            "metadata watch source confirmation was cancelled",
        )
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({
            "preview_id": confirmation.preview_id.to_string(),
            "stage": "confirmation",
        })));
    }

    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, confirmation.requested_by_redacted.as_deref());
    let audit = AuditDraft::generic(
        AuditCategory::Capture,
        AuditActionType::Custom("capture.metadata_watch.confirmed".to_string()),
        actor,
        format!("metadata_watch_source:{}", confirmation.preview_id),
    );
    let permission = authorize(
        state,
        &trace_id,
        CONFIRM_METADATA_WATCH_SOURCE,
        "data.metadata_watch.write",
        PermissionScope::Data {
            resource: "metadata.watch".to_string(),
            operation: "confirm".to_string(),
            metadata_only: true,
        },
        PolicyScope::TauriMutationCommand,
        &confirmation.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;

    let source_status = state
        .metadata_watch_controller
        .confirm_source(confirmation)
        .map_err(metadata_watch_error)?;
    state.metadata_reader_runtime.confirm_source(&source_status);
    sync_metadata_watch_read_state(state)?;
    let status = validated_metadata_watch_status(state)?;

    finish_mutation(
        state,
        CONFIRM_METADATA_WATCH_SOURCE,
        status,
        permission,
        &trace_id,
        audit.with_result("metadata watch source confirmed with bounded state"),
        None,
    )
}

pub fn update_metadata_watch_source(
    state: &mut MutationCommandState,
    request: MetadataWatchLifecycleRequest,
) -> CommandResult<MutationReceipt<MetadataWatchControllerStatus>> {
    request.validate().map_err(contract_error)?;
    require_reason(&request.reason_redacted)?;

    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.requested_by_redacted.as_deref());
    let audit = AuditDraft::generic(
        AuditCategory::Capture,
        AuditActionType::Custom("capture.metadata_watch.lifecycle".to_string()),
        actor,
        format!("metadata_watch_source:{}", request.source_id),
    );
    let permission = authorize(
        state,
        &trace_id,
        UPDATE_METADATA_WATCH_SOURCE,
        "data.metadata_watch.write",
        PermissionScope::Data {
            resource: "metadata.watch".to_string(),
            operation: "lifecycle".to_string(),
            metadata_only: true,
        },
        PolicyScope::TauriMutationCommand,
        &request.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;

    let action = request.action.clone();
    state
        .metadata_watch_controller
        .transition_source(&request.source_id, request.action)
        .map_err(metadata_watch_error)?;
    if matches!(
        action,
        sentinel_contracts::MetadataWatchLifecycleAction::Revoke
            | sentinel_contracts::MetadataWatchLifecycleAction::ClearInactive
    ) {
        state
            .metadata_reader_runtime
            .revoke_source(&request.source_id);
    }
    sync_metadata_watch_read_state(state)?;
    let status = validated_metadata_watch_status(state)?;

    finish_mutation(
        state,
        UPDATE_METADATA_WATCH_SOURCE,
        status,
        permission,
        &trace_id,
        audit.with_result("metadata watch source lifecycle updated"),
        None,
    )
}

pub fn tick_metadata_watch_controller(
    state: &mut MutationCommandState,
    request: MetadataSamplingTickRequest,
) -> CommandResult<MutationReceipt<MetadataSamplingTickResult>> {
    request.validate().map_err(contract_error)?;
    require_reason(&request.reason_redacted)?;

    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.requested_by_redacted.as_deref());
    let audit = AuditDraft::generic(
        AuditCategory::Capture,
        AuditActionType::Custom("capture.metadata_watch.tick".to_string()),
        actor,
        "metadata_watch_controller".to_string(),
    );
    let permission = authorize(
        state,
        &trace_id,
        TICK_METADATA_WATCH_CONTROLLER,
        "data.metadata_watch.write",
        PermissionScope::Data {
            resource: "metadata.watch".to_string(),
            operation: "sample".to_string(),
            metadata_only: true,
        },
        PolicyScope::TauriMutationCommand,
        &request.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;

    let batches = run_metadata_watch_tick(state, &request)?;
    sync_metadata_watch_read_state(state)?;
    let result = metadata_sampling_tick_result(state, batches);
    result.validate().map_err(contract_error)?;

    finish_mutation(
        state,
        TICK_METADATA_WATCH_CONTROLLER,
        result,
        permission,
        &trace_id,
        audit.with_result("metadata watch controller tick completed through bounded sources"),
        None,
    )
}

pub fn update_metadata_sampling_loop(
    state: &mut MutationCommandState,
    request: MetadataSamplingLoopControlRequest,
) -> CommandResult<MutationReceipt<MetadataWatchControllerStatus>> {
    request.validate().map_err(contract_error)?;
    require_reason(&request.reason_redacted)?;

    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.requested_by_redacted.as_deref());
    let audit = AuditDraft::generic(
        AuditCategory::Capture,
        AuditActionType::Custom("capture.metadata_sampling_loop.control".to_string()),
        actor,
        "metadata_sampling_loop".to_string(),
    );
    let permission = authorize(
        state,
        &trace_id,
        UPDATE_METADATA_SAMPLING_LOOP,
        "data.metadata_watch.write",
        PermissionScope::Data {
            resource: "metadata.watch".to_string(),
            operation: "schedule".to_string(),
            metadata_only: true,
        },
        PolicyScope::TauriMutationCommand,
        &request.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;

    state.metadata_sampling_loop.apply_control(&request);
    sync_metadata_watch_read_state(state)?;
    let status = validated_metadata_watch_status(state)?;

    finish_mutation(
        state,
        UPDATE_METADATA_SAMPLING_LOOP,
        status,
        permission,
        &trace_id,
        audit.with_result("metadata sampling loop control updated"),
        None,
    )
}

pub fn run_metadata_sampling_loop(
    state: &mut MutationCommandState,
    request: MetadataSamplingLoopRunRequest,
) -> CommandResult<MutationReceipt<MetadataSamplingTickResult>> {
    request.validate().map_err(contract_error)?;
    require_reason(&request.reason_redacted)?;

    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.requested_by_redacted.as_deref());
    let audit = AuditDraft::generic(
        AuditCategory::Capture,
        AuditActionType::Custom("capture.metadata_sampling_loop.tick".to_string()),
        actor,
        "metadata_sampling_loop".to_string(),
    );
    let permission = authorize(
        state,
        &trace_id,
        RUN_METADATA_SAMPLING_LOOP,
        "data.metadata_watch.write",
        PermissionScope::Data {
            resource: "metadata.watch".to_string(),
            operation: "schedule_cycle".to_string(),
            metadata_only: true,
        },
        PolicyScope::TauriMutationCommand,
        &request.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;

    let batches = run_metadata_sampling_loop_cycle(state, request.max_sources)?;
    sync_metadata_watch_read_state(state)?;
    let result = metadata_sampling_tick_result(state, batches);
    result.validate().map_err(contract_error)?;

    finish_mutation(
        state,
        RUN_METADATA_SAMPLING_LOOP,
        result,
        permission,
        &trace_id,
        audit.with_result("metadata sampling loop cycle completed through bounded readers"),
        None,
    )
}

pub fn confirm_portable_capture_import(
    state: &mut MutationCommandState,
    prepared: &PreparedPortableCaptureImport,
    confirmation: PortableCaptureImportConfirmation,
) -> CommandResult<MutationReceipt<PortableCaptureImportResult>> {
    require_reason(&confirmation.reason_redacted)?;
    if prepared.preview.preview_id != confirmation.preview_id {
        return Err(CoreError::new(
            ErrorCode::InvalidRequest,
            "portable capture preview does not match the pending import",
        )
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({
            "expected_preview_id": prepared.preview.preview_id.to_string(),
            "received_preview_id": confirmation.preview_id.to_string(),
        })));
    }
    if !confirmation.user_confirmed {
        return Err(CoreError::new(
            ErrorCode::PolicyDenial,
            "portable capture import cancelled before runtime ingest",
        )
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({
            "preview_id": confirmation.preview_id.to_string(),
            "stage": "confirmation",
        })));
    }

    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, confirmation.requested_by_redacted.as_deref());
    let audit = AuditDraft::generic(
        AuditCategory::Capture,
        AuditActionType::Custom("capture.portable_import.confirmed".to_string()),
        actor,
        format!("portable_capture_import:{}", confirmation.preview_id),
    );
    let permission = authorize(
        state,
        &trace_id,
        CONFIRM_PORTABLE_CAPTURE_IMPORT,
        "data.network_metadata.import",
        PermissionScope::Data {
            resource: "network.metadata.import".to_string(),
            operation: "ingest".to_string(),
            metadata_only: true,
        },
        PolicyScope::TauriMutationCommand,
        &confirmation.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;
    let result = ingest_portable_capture_import(&mut state.read, prepared)?;
    record_manual_import_watch_sampling(state, &result)?;

    finish_mutation(
        state,
        CONFIRM_PORTABLE_CAPTURE_IMPORT,
        result,
        permission,
        &trace_id,
        audit.with_result("portable capture metadata imported from confirmed preview"),
        None,
    )
}

fn run_metadata_watch_tick(
    state: &mut MutationCommandState,
    request: &MetadataSamplingTickRequest,
) -> CommandResult<Vec<MetadataSamplingBatchSummary>> {
    let selected_sources = state
        .metadata_watch_controller
        .sources()
        .into_iter()
        .filter(|source| {
            request
                .source_id
                .as_ref()
                .map(|requested| requested == &source.source_id)
                .unwrap_or(true)
        })
        .filter(|source| {
            matches!(
                source.state,
                MetadataWatchSourceState::Enabled | MetadataWatchSourceState::Active
            )
        })
        .take(request.max_sources as usize)
        .collect::<Vec<_>>();

    let mut batches = Vec::new();
    for source in selected_sources {
        if let Some(batch) = run_source_watch_tick(state, &source, None, false)? {
            batches.push(batch);
        }
    }
    Ok(batches)
}

fn run_metadata_sampling_loop_cycle(
    state: &mut MutationCommandState,
    requested_max_sources: u32,
) -> CommandResult<Vec<MetadataSamplingBatchSummary>> {
    if !state.metadata_sampling_loop.is_running() {
        state.metadata_sampling_loop.record_idle_cycle();
        return Ok(Vec::new());
    }

    let now = Timestamp::now();
    let mut due_sources = state
        .metadata_watch_controller
        .sources()
        .into_iter()
        .filter(|source| {
            matches!(
                source.state,
                MetadataWatchSourceState::Enabled | MetadataWatchSourceState::Active
            )
        })
        .filter(|source| source_due_for_loop(source, &now))
        .collect::<Vec<_>>();
    due_sources.sort_by_key(|source| source.source_id.to_string());

    let limit = state
        .metadata_sampling_loop
        .source_limit(requested_max_sources);
    let overflow = if due_sources.len() > limit {
        due_sources.split_off(limit)
    } else {
        Vec::new()
    };
    for source in overflow {
        state
            .metadata_watch_controller
            .mark_source_health(
                &source.source_id,
                MetadataSourceHealthState::Backpressure,
                Some("scheduler_backpressure".to_string()),
                Some("backpressure".to_string()),
            )
            .map_err(metadata_watch_error)?;
    }

    let max_files_per_tick = Some(state.metadata_sampling_loop.max_files_per_tick);
    let per_source_timeout_millis =
        u128::from(state.metadata_sampling_loop.per_source_timeout_millis);
    let selected_source_count = due_sources.len();
    let mut batches = Vec::new();
    for source in due_sources {
        let started = Instant::now();
        if let Some(batch) = run_source_watch_tick(state, &source, max_files_per_tick, true)? {
            batches.push(batch);
        }
        if started.elapsed().as_millis() > per_source_timeout_millis {
            state
                .metadata_watch_controller
                .mark_source_health(
                    &source.source_id,
                    MetadataSourceHealthState::Backpressure,
                    Some("source_timeout".to_string()),
                    Some("timeout".to_string()),
                )
                .map_err(metadata_watch_error)?;
        }
    }
    state
        .metadata_sampling_loop
        .record_cycle(selected_source_count);
    Ok(batches)
}

fn source_due_for_loop(
    source: &sentinel_contracts::MetadataWatchSourceStatus,
    now: &Timestamp,
) -> bool {
    if source.source_kind == MetadataWatchSourceKind::ManualImport
        || source.sampling_mode == MetadataSamplingMode::ManualPreviewConfirm
    {
        return false;
    }
    let Some(last_sampled_at) = &source.last_sampled_at else {
        return true;
    };
    now.as_datetime()
        .signed_duration_since(*last_sampled_at.as_datetime())
        .num_seconds()
        >= i64::from(source.interval_seconds.max(1))
}

fn run_source_watch_tick(
    state: &mut MutationCommandState,
    source: &sentinel_contracts::MetadataWatchSourceStatus,
    max_files_per_tick: Option<u32>,
    scheduled: bool,
) -> CommandResult<Option<MetadataSamplingBatchSummary>> {
    if source.source_kind == MetadataWatchSourceKind::LocalhostProxyContinuousDrain {
        if scheduled {
            let proxy_status = state.portable_proxy_runtime.status_snapshot();
            if proxy_status.state != LocalProxyMetadataProviderStateKind::Running {
                state
                    .metadata_watch_controller
                    .mark_source_health(
                        &source.source_id,
                        MetadataSourceHealthState::Degraded,
                        Some("local_proxy_unavailable_for_scheduled_drain".to_string()),
                        Some("source_unavailable".to_string()),
                    )
                    .map_err(metadata_watch_error)?;
                return Ok(None);
            }
        }
        return run_proxy_watch_tick(state, source);
    }

    if state.metadata_reader_runtime.has_source(&source.source_id) {
        return run_reader_watch_tick(state, source, max_files_per_tick);
    }

    state
        .metadata_watch_controller
        .mark_source_health(
            &source.source_id,
            MetadataSourceHealthState::SourceUnavailable,
            Some("portable_watcher_not_connected".to_string()),
            Some("source_unavailable".to_string()),
        )
        .map_err(metadata_watch_error)?;
    Ok(None)
}

fn run_reader_watch_tick(
    state: &mut MutationCommandState,
    source: &sentinel_contracts::MetadataWatchSourceStatus,
    max_files_per_tick: Option<u32>,
) -> CommandResult<Option<MetadataSamplingBatchSummary>> {
    let read_result = match state
        .metadata_reader_runtime
        .read_source(source, max_files_per_tick)
    {
        Ok(result) => result,
        Err(error) => {
            let failures = state.metadata_reader_runtime.record_source_failure(source);
            let (health, reason, category) = portable_reader_failure_health(error, failures);
            state
                .metadata_watch_controller
                .mark_source_health(&source.source_id, health, reason, category)
                .map_err(metadata_watch_error)?;
            return Ok(None);
        }
    };

    if read_result.candidates.is_empty()
        && read_result.skipped_record_count == 0
        && read_result.malformed_record_count == 0
        && read_result.backpressure_drop_count == 0
        && read_result.health_state == MetadataSourceHealthState::Idle
    {
        state
            .metadata_watch_controller
            .mark_source_health(
                &source.source_id,
                MetadataSourceHealthState::Idle,
                None,
                None,
            )
            .map_err(metadata_watch_error)?;
        return Ok(None);
    }

    let mut emitted_topics = Vec::new();
    let mut fact_refs = Vec::new();
    let mut evidence_refs = Vec::new();
    let mut finding_refs = Vec::new();
    let mut risk_refs = Vec::new();
    let mut hypothesis_count = 0usize;
    let mut provenance_id = read_result.provenance_id_hint.clone();
    let mut sampled_record_count = read_result.sampled_record_count;
    let mut sampled_byte_count = read_result.sampled_byte_count;
    let mut handoff_malformed_count = 0u64;

    for candidate in &read_result.candidates {
        let prepared = match prepare_portable_capture_import(
            candidate.source_type.clone(),
            &candidate.content,
            candidate.content_len,
        ) {
            Ok(prepared) => prepared,
            Err(_) => {
                handoff_malformed_count =
                    handoff_malformed_count.saturating_add(candidate.record_count_hint.max(1));
                continue;
            }
        };
        let before_facts = state.read.security_facts.items.len();
        let before_findings = state.read.findings.items.len();
        let before_fusion = state.read.fusion_summaries.len();
        let result = ingest_portable_capture_import(&mut state.read, &prepared)?;
        emitted_topics.extend(result.emitted_topics.clone());
        sampled_record_count = sampled_record_count.max(portable_import_record_count(&result));
        sampled_byte_count = sampled_byte_count.saturating_add(candidate.content_len as u64);
        provenance_id = Some(result.provenance.provenance_id.clone());
        fact_refs.extend(
            state
                .read
                .security_facts
                .items
                .iter()
                .skip(before_facts)
                .map(|fact| fact.fact_id.clone()),
        );
        finding_refs.extend(
            state
                .read
                .findings
                .items
                .iter()
                .skip(before_findings)
                .map(|finding| finding.id().clone()),
        );
        for summary in state.read.fusion_summaries.iter().skip(before_fusion) {
            evidence_refs.extend(summary.evidence_refs.clone());
            risk_refs.extend(
                summary
                    .hypotheses
                    .iter()
                    .flat_map(|hypothesis| hypothesis.risk_refs.iter().cloned()),
            );
            hypothesis_count = hypothesis_count.saturating_add(summary.hypotheses.len());
        }
    }
    let health_state = if handoff_malformed_count > 0 {
        MetadataSourceHealthState::ParserError
    } else {
        read_result.health_state.clone()
    };
    let degraded_reason = if handoff_malformed_count > 0 && read_result.degraded_reason.is_none() {
        Some("parser_error".to_string())
    } else {
        read_result.degraded_reason.clone()
    };
    let error_category = if handoff_malformed_count > 0 && read_result.error_category.is_none() {
        Some("parser_error".to_string())
    } else {
        read_result.error_category.clone()
    };

    let observation = MetadataSamplingObservation {
        source_id: source.source_id.clone(),
        source_generation_ref: read_result.generation_ref.clone(),
        sampled_record_count,
        sampled_byte_count,
        skipped_record_count: read_result.skipped_record_count,
        malformed_record_count: read_result
            .malformed_record_count
            .saturating_add(handoff_malformed_count),
        backpressure_drop_count: read_result.backpressure_drop_count,
        emitted_topics: unique_strings(emitted_topics),
        fact_refs,
        evidence_refs,
        finding_refs,
        risk_refs,
        hypothesis_count: bounded_u32(hypothesis_count),
        provenance_id: provenance_id.clone(),
        health_state_override: Some(health_state),
        degraded_reason,
        error_category,
    };
    let batch = state
        .metadata_watch_controller
        .record_sampling_observation(observation)
        .map_err(metadata_watch_error)?;
    state
        .metadata_reader_runtime
        .commit_source(source, read_result.commit, provenance_id);
    Ok(Some(batch))
}

fn portable_reader_failure_health(
    error: PortableSourceReaderError,
    failure_count: u32,
) -> (MetadataSourceHealthState, Option<String>, Option<String>) {
    if failure_count >= 3 {
        return (
            MetadataSourceHealthState::Degraded,
            Some("repeated_reader_failures".to_string()),
            Some("reader_failure".to_string()),
        );
    }
    match error {
        PortableSourceReaderError::UnauthorizedSourceRef => (
            MetadataSourceHealthState::PermissionRequired,
            Some("reader_source_ref_unauthorized".to_string()),
            Some("permission_required".to_string()),
        ),
        PortableSourceReaderError::ParserFamilyMismatch
        | PortableSourceReaderError::UnsupportedSourceFamily => (
            MetadataSourceHealthState::ParserError,
            Some("reader_source_family_mismatch".to_string()),
            Some("parser_error".to_string()),
        ),
        _ => (
            MetadataSourceHealthState::SourceUnavailable,
            Some("source_unavailable".to_string()),
            Some("source_unavailable".to_string()),
        ),
    }
}

fn run_proxy_watch_tick(
    state: &mut MutationCommandState,
    source: &sentinel_contracts::MetadataWatchSourceStatus,
) -> CommandResult<Option<MetadataSamplingBatchSummary>> {
    let (status, runs) = state
        .portable_proxy_runtime
        .drain_with_runs(&mut state.read)?;
    let malformed_delta = status
        .requests_rejected
        .saturating_sub(source.counters.malformed_record_count);
    let backpressure_delta = status
        .dropped_batches
        .saturating_sub(source.counters.backpressure_drop_count);

    if runs.is_empty() && malformed_delta == 0 && backpressure_delta == 0 {
        let (health, reason, category) = proxy_health_without_batch(&status);
        state
            .metadata_watch_controller
            .mark_source_health(&source.source_id, health, reason, category)
            .map_err(metadata_watch_error)?;
        return Ok(None);
    }

    let observation = MetadataSamplingObservation {
        source_id: source.source_id.clone(),
        source_generation_ref: format!(
            "local_proxy_drain:{}:{}:{}:{}",
            status.drained_event_count,
            status.requests_rejected,
            status.dropped_batches,
            runs.len()
        ),
        sampled_record_count: runs.iter().map(run_record_count).sum(),
        sampled_byte_count: 0,
        skipped_record_count: 0,
        malformed_record_count: malformed_delta,
        backpressure_drop_count: backpressure_delta,
        emitted_topics: unique_emitted_topics(&runs),
        fact_refs: runs
            .iter()
            .flat_map(|run| run.security_facts.iter().map(|fact| fact.fact_id.clone()))
            .collect(),
        evidence_refs: runs
            .iter()
            .flat_map(|run| {
                run.evidence
                    .iter()
                    .map(|evidence| evidence.evidence_id.clone())
            })
            .collect(),
        finding_refs: runs
            .iter()
            .flat_map(|run| run.findings.iter().map(|finding| finding.id().clone()))
            .collect(),
        risk_refs: runs
            .iter()
            .flat_map(|run| {
                run.risk_events
                    .iter()
                    .map(|risk| risk.risk_event_id.clone())
            })
            .collect(),
        hypothesis_count: bounded_u32(runs.iter().map(|run| run.attack_hypotheses.len()).sum()),
        provenance_id: runs.last().map(|run| run.provenance.provenance_id.clone()),
        health_state_override: None,
        degraded_reason: None,
        error_category: None,
    };
    state
        .metadata_watch_controller
        .record_sampling_observation(observation)
        .map(Some)
        .map_err(metadata_watch_error)
}

fn proxy_health_without_batch(
    status: &LocalProxyMetadataProviderStatus,
) -> (MetadataSourceHealthState, Option<String>, Option<String>) {
    match status.state {
        LocalProxyMetadataProviderStateKind::Running => {
            (MetadataSourceHealthState::Active, None, None)
        }
        LocalProxyMetadataProviderStateKind::Degraded => (
            MetadataSourceHealthState::Degraded,
            Some("local_proxy_degraded".to_string()),
            status
                .last_error_code
                .clone()
                .or_else(|| Some("proxy_degraded".to_string())),
        ),
        LocalProxyMetadataProviderStateKind::Stopped => (
            MetadataSourceHealthState::Stopped,
            Some("local_proxy_not_running".to_string()),
            Some("source_unavailable".to_string()),
        ),
    }
}

fn mark_proxy_watch_sources_after_stop(state: &mut MutationCommandState) -> CommandResult<()> {
    let sources = state.metadata_watch_controller.sources();
    for source in sources {
        if source.source_kind == MetadataWatchSourceKind::LocalhostProxyContinuousDrain
            && matches!(
                source.state,
                MetadataWatchSourceState::Enabled | MetadataWatchSourceState::Active
            )
        {
            state
                .metadata_watch_controller
                .mark_source_health(
                    &source.source_id,
                    MetadataSourceHealthState::Stopped,
                    Some("local_proxy_stopped".to_string()),
                    Some("source_unavailable".to_string()),
                )
                .map_err(metadata_watch_error)?;
        }
    }
    Ok(())
}

fn record_manual_import_watch_sampling(
    state: &mut MutationCommandState,
    result: &PortableCaptureImportResult,
) -> CommandResult<()> {
    let parser_family = metadata_parser_family_for_source_type(&result.provenance.source_type);
    let preview = state
        .metadata_watch_controller
        .preview_source(MetadataWatchSourcePreviewRequest {
            source_kind: MetadataWatchSourceKind::ManualImport,
            parser_family,
            display_label_redacted: "manual_import".to_string(),
            sampling_mode: MetadataSamplingMode::ManualPreviewConfirm,
            interval_seconds: 1,
            max_records_per_tick: 10_000,
            max_bytes_per_tick: 16 * 1024 * 1024,
            reason_redacted: "confirmed_preview_import".to_string(),
        })
        .map_err(metadata_watch_error)?;
    state
        .metadata_watch_controller
        .confirm_source(MetadataWatchSourceConfirmation {
            preview_id: preview.preview_id.clone(),
            user_confirmed: true,
            reason_redacted: "confirmed_preview_import".to_string(),
            requested_by_redacted: None,
        })
        .map_err(metadata_watch_error)?;

    let observation = MetadataSamplingObservation {
        source_id: preview.preview_id,
        source_generation_ref: result.preview_id.to_string(),
        sampled_record_count: portable_import_record_count(result),
        sampled_byte_count: 0,
        skipped_record_count: 0,
        malformed_record_count: 0,
        backpressure_drop_count: 0,
        emitted_topics: result.emitted_topics.clone(),
        fact_refs: latest_fusion_summary(state)
            .map(|summary| summary.fact_refs.clone())
            .unwrap_or_default(),
        evidence_refs: latest_fusion_summary(state)
            .map(|summary| summary.evidence_refs.clone())
            .unwrap_or_default(),
        finding_refs: latest_fusion_summary(state)
            .map(|summary| summary.finding_refs.clone())
            .unwrap_or_default(),
        risk_refs: latest_fusion_summary(state)
            .map(|summary| {
                summary
                    .hypotheses
                    .iter()
                    .flat_map(|hypothesis| hypothesis.risk_refs.iter().cloned())
                    .collect()
            })
            .unwrap_or_default(),
        hypothesis_count: bounded_u32(result.attack_hypothesis_count),
        provenance_id: Some(result.provenance.provenance_id.clone()),
        health_state_override: None,
        degraded_reason: None,
        error_category: None,
    };
    state
        .metadata_watch_controller
        .record_sampling_observation(observation)
        .map_err(metadata_watch_error)?;
    sync_metadata_watch_read_state(state)
}

fn sync_metadata_watch_read_state(state: &mut MutationCommandState) -> CommandResult<()> {
    let sources = state.metadata_watch_controller.sources();
    let batches = state.metadata_watch_controller.batches();
    let mut status = state.metadata_watch_controller.status();
    state.metadata_sampling_loop.apply_to_status(&mut status);
    for source in &sources {
        source.validate().map_err(contract_error)?;
    }
    for batch in &batches {
        batch.validate().map_err(contract_error)?;
    }
    status.validate().map_err(contract_error)?;
    state.read.metadata_watch_sources.items = sources;
    state.read.metadata_sampling_batches.items = batches;
    state.read.metadata_watch_controller_status = status;
    Ok(())
}

fn validated_metadata_watch_status(
    state: &MutationCommandState,
) -> CommandResult<MetadataWatchControllerStatus> {
    let mut status = state.metadata_watch_controller.status();
    state.metadata_sampling_loop.apply_to_status(&mut status);
    status.validate().map_err(contract_error)?;
    Ok(status)
}

fn metadata_sampling_tick_result(
    state: &MutationCommandState,
    batches: Vec<MetadataSamplingBatchSummary>,
) -> MetadataSamplingTickResult {
    let mut result = state.metadata_watch_controller.tick_result(batches);
    state
        .metadata_sampling_loop
        .apply_to_status(&mut result.controller_status);
    result
}

fn metadata_parser_family_for_source_type(
    source_type: &PortableCaptureInputSourceType,
) -> MetadataParserFamily {
    match source_type {
        PortableCaptureInputSourceType::ImportedHar => MetadataParserFamily::Har,
        PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata => {
            MetadataParserFamily::JsonlNetwork
        }
        PortableCaptureInputSourceType::ImportedWebAccessLog => MetadataParserFamily::WebAccessLog,
        PortableCaptureInputSourceType::ImportedAuthSecurityLog => {
            MetadataParserFamily::AuthSecurityLog
        }
        PortableCaptureInputSourceType::ImportedSaasCloudMetadata => {
            MetadataParserFamily::SaasCloudJsonl
        }
        PortableCaptureInputSourceType::ImportedDeceptionEventLog => {
            MetadataParserFamily::DeceptionJsonl
        }
        PortableCaptureInputSourceType::LocalProxyMetadata => {
            MetadataParserFamily::LocalProxyMetadata
        }
    }
}

fn run_record_count(run: &PortableCaptureLiteRunResult) -> u64 {
    let counts = &run.provenance.record_counts;
    u64::from(counts.flow_records)
        + u64::from(counts.session_records)
        + u64::from(counts.dns_records)
        + u64::from(counts.tls_records)
        + u64::from(counts.http_metadata_records)
        + u64::from(counts.auth_metadata_records)
        + u64::from(counts.saas_cloud_metadata_records)
        + u64::from(counts.deception_event_records)
}

fn portable_import_record_count(result: &PortableCaptureImportResult) -> u64 {
    u64::try_from(
        result.flow_count
            + result.session_count
            + result.dns_count
            + result.tls_count
            + result.http_metadata_count
            + result.auth_metadata_count
            + result.saas_cloud_metadata_count
            + result.deception_event_count,
    )
    .unwrap_or(u64::MAX)
}

fn unique_emitted_topics(runs: &[PortableCaptureLiteRunResult]) -> Vec<String> {
    unique_strings(
        runs.iter()
            .flat_map(|run| run.emitted_topics.iter().cloned())
            .collect(),
    )
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::<String>::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

fn latest_fusion_summary(
    state: &MutationCommandState,
) -> Option<&sentinel_contracts::FusionSummary> {
    state.read.fusion_summaries.last()
}

fn bounded_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

pub fn export_report_with_export_history_storage(
    state: &mut MutationCommandState,
    request: ExportReportRequest,
    stores: &SqliteStoreFactory<'_>,
) -> CommandResult<MutationReceipt<ExportReportMutationResult>> {
    export_report_impl(state, request, Some(stores))
}

fn export_report_impl(
    state: &mut MutationCommandState,
    request: ExportReportRequest,
    export_history_stores: Option<&SqliteStoreFactory<'_>>,
) -> CommandResult<MutationReceipt<ExportReportMutationResult>> {
    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.requested_by_redacted.as_deref());
    let report = find_report(state, &request.report_id)?.clone();
    let export_metadata = ExportAuditMetadata {
        format: request.format.clone(),
        destination_metadata_redacted: request.destination_metadata_redacted.clone(),
        file_hash: None,
    };
    let permission = authorize_export(
        state,
        &trace_id,
        &request,
        &report.redaction_summary,
        export_metadata.clone(),
        &actor,
        export_history_stores,
    )?;

    let audit_ref = AuditRef {
        audit_id: sentinel_contracts::AuditId::new_v4(),
        event_type: "report.export.requested".to_string(),
        trace_id: Some(trace_id.clone()),
        timestamp: Timestamp::now(),
    };
    let export_package = match ReportExportGate::new().prepare_export(ReportExportGateRequest {
        report: report.clone(),
        format: request.format.clone(),
        policy: state.read.runtime_profile.report_export_policy.clone(),
        requested_by_redacted: actor.clone(),
        user_confirmed: request.user_confirmed,
        audit_ref,
        destination_metadata_redacted: request.destination_metadata_redacted.clone(),
        file_hash: None,
    }) {
        Ok(package) => package,
        Err(error) => {
            let export_audit_receipt = append_export_audit(
                state,
                &trace_id,
                AuditActionType::ExportFailed,
                &actor,
                "report.export",
                AuditDecision::Denied,
                "report export denied by redaction or export gate",
                report.redaction_summary.clone(),
                export_metadata,
            )?;
            let violation_receipt = append_export_policy_violation_audit(
                state,
                &trace_id,
                &actor,
                "report.export",
                "report export denied by redaction or export gate",
            )?;
            let violation = record_export_policy_violation(
                state,
                &request,
                &actor,
                report.redaction_summary,
                "report export denied by redaction or export gate",
                &trace_id,
                violation_receipt.clone(),
                Some(export_audit_receipt.audit_id),
            )?;
            persist_export_policy_violation(export_history_stores, &violation, &trace_id)?;
            return Err(report_generation_error(error).with_audit_ref(violation_receipt.audit_id));
        }
    };
    let rendered_artifact_bytes = export_package
        .rendered_report
        .content_redacted
        .as_bytes()
        .to_vec();
    let file_hash = ExportFileHash::from_bytes(&rendered_artifact_bytes);
    let mut export_result = export_package.export_result;
    export_result.file_hash = Some(file_hash.value.clone());
    export_result.trace_id = Some(trace_id.clone());
    let export_metadata = ExportAuditMetadata {
        format: request.format.clone(),
        destination_metadata_redacted: request.destination_metadata_redacted.clone(),
        file_hash: export_result.file_hash.clone(),
    };
    let audit_receipt = append_export_audit(
        state,
        &trace_id,
        AuditActionType::ExportCompleted,
        &actor,
        "report.export",
        AuditDecision::Completed,
        "report export recorded after redaction and confirmation",
        report.redaction_summary,
        export_metadata,
    )?;
    export_result.audit_ref.audit_id = audit_receipt.audit_id.clone();
    export_result.audit_ref.trace_id = Some(trace_id.clone());
    let history_record = record_successful_export_history(
        state,
        SuccessfulExportHistoryInput {
            export_result: export_result.clone(),
            actor_redacted: actor.clone(),
            destination_metadata_redacted: request.destination_metadata_redacted.clone(),
            audit_receipt: audit_receipt.clone(),
            artifact_bytes: Some(rendered_artifact_bytes),
            graph_snapshot_refs: report.graph_snapshot_refs.clone(),
            evidence_refs: report.evidence_refs.clone(),
            response_result_refs: report.response_result_refs.clone(),
            rollback_result_refs: report.rollback_result_refs.clone(),
            llm_story_refs: report.llm_story_refs.clone(),
        },
    )?;
    persist_export_history_record(export_history_stores, &history_record, &trace_id)?;
    state.export_results.push(export_result.clone());
    Ok(MutationReceipt {
        command: EXPORT_REPORT.to_string(),
        result: ExportReportMutationResult {
            export_result,
            export_performed: true,
        },
        permission_decision: permission,
        audit_receipt,
        trace_id,
        rollback: None,
        generated_at: Timestamp::now(),
    })
}

pub fn apply_runtime_profile(
    state: &mut MutationCommandState,
    request: ApplyRuntimeProfileRequest,
) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
    apply_profile_change(
        state,
        APPLY_RUNTIME_PROFILE,
        SettingsChangeKind::RuntimeProfile,
        request.profile,
        request.reason_redacted,
        request.requested_by_redacted,
        AuditActionType::SettingsChanged,
    )
}

pub fn update_privacy_policy(
    state: &mut MutationCommandState,
    request: UpdatePrivacyPolicyRequest,
) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
    let mut profile = state.read.runtime_profile.clone();
    profile.privacy_policy = request.policy;
    profile.updated_at = Timestamp::now();
    apply_profile_change(
        state,
        UPDATE_PRIVACY_POLICY,
        SettingsChangeKind::PrivacyPolicy,
        profile,
        request.reason_redacted,
        request.requested_by_redacted,
        AuditActionType::SettingsChanged,
    )
}

pub fn update_response_policy(
    state: &mut MutationCommandState,
    request: UpdateResponsePolicyRequest,
) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
    let mut profile = state.read.runtime_profile.clone();
    profile.response_policy = request.policy;
    profile.updated_at = Timestamp::now();
    apply_profile_change(
        state,
        UPDATE_RESPONSE_POLICY,
        SettingsChangeKind::ResponsePolicy,
        profile,
        request.reason_redacted,
        request.requested_by_redacted,
        AuditActionType::SettingsChanged,
    )
}

pub fn enable_forensic_mode(
    state: &mut MutationCommandState,
    request: EnableForensicModeRequest,
) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
    let mut profile = state.read.runtime_profile.clone();
    profile.privacy_policy.forensic_mode = ForensicModeSettings::manual_schema_reserved(
        request.reason_redacted.clone(),
        request.scope,
    )
    .map_err(contract_error)?;
    profile.updated_at = Timestamp::now();
    apply_profile_change(
        state,
        ENABLE_FORENSIC_MODE,
        SettingsChangeKind::PrivacyPolicy,
        profile,
        request.reason_redacted,
        request.requested_by_redacted,
        AuditActionType::ForensicModeEnabled,
    )
}

pub fn disable_forensic_mode(
    state: &mut MutationCommandState,
    request: DisableForensicModeRequest,
) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
    let mut profile = state.read.runtime_profile.clone();
    profile.privacy_policy.forensic_mode = ForensicModeSettings::disabled();
    profile.updated_at = Timestamp::now();
    apply_profile_change(
        state,
        DISABLE_FORENSIC_MODE,
        SettingsChangeKind::PrivacyPolicy,
        profile,
        request.reason_redacted,
        request.requested_by_redacted,
        AuditActionType::ForensicModeDisabled,
    )
}

fn plugin_lifecycle_mutation(
    state: &mut MutationCommandState,
    command: &'static str,
    request: PluginLifecycleRequest,
    lifecycle_state: PluginLifecycleMutationState,
) -> CommandResult<MutationReceipt<PluginLifecycleMutationResult>> {
    require_reason(&request.reason_redacted)?;
    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.requested_by_redacted.as_deref());
    let manifest = state
        .read
        .plugin_registry
        .get(&request.plugin_id)
        .cloned()
        .ok_or_else(|| {
            not_found_error(
                "plugin",
                json!({ "plugin_id": request.plugin_id.to_string() }),
                &trace_id,
            )
        })?;
    let audit = AuditDraft::generic(
        AuditCategory::PluginLifecycle,
        AuditActionType::PluginLifecycleChanged,
        actor,
        format!("plugin:{}", request.plugin_id),
    );
    let permission = authorize(
        state,
        &trace_id,
        command,
        "system.plugin_lifecycle",
        PermissionScope::System {
            command: command.to_string(),
            elevated_service_required: false,
        },
        PolicyScope::TauriMutationCommand,
        &request.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;
    state
        .plugin_lifecycle
        .insert(request.plugin_id.clone(), lifecycle_state.clone());
    let result = PluginLifecycleMutationResult {
        plugin_id: request.plugin_id,
        plugin_name: manifest.plugin_name,
        state: lifecycle_state,
        applied_to_runtime: false,
        reason_redacted: request.reason_redacted,
    };
    finish_mutation(
        state,
        command,
        result,
        permission,
        &trace_id,
        audit.with_result("plugin lifecycle request recorded"),
        None,
    )
}

fn finding_state_mutation(
    state: &mut MutationCommandState,
    command: &'static str,
    request: FindingStateMutationRequest,
    finding_state: FindingState,
) -> CommandResult<MutationReceipt<FindingStateMutationResult>> {
    require_reason(&request.reason_redacted)?;
    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.requested_by_redacted.as_deref());
    let audit = AuditDraft::generic(
        AuditCategory::SecurityCase,
        AuditActionType::Custom("security.finding.state_changed".to_string()),
        actor,
        format!("finding:{}", request.finding_id),
    );
    let permission = authorize(
        state,
        &trace_id,
        command,
        "data.security_case.write",
        PermissionScope::Data {
            resource: "security.finding".to_string(),
            operation: "update_state".to_string(),
            metadata_only: true,
        },
        PolicyScope::TauriMutationCommand,
        &request.reason_redacted,
        PolicyOptions::default(),
        audit.clone(),
    )?;
    let finding = mutate_finding(state, &request.finding_id, |finding| {
        finding.with_state(finding_state.clone())
    })?;
    let result = FindingStateMutationResult {
        finding,
        applied_state: finding_state,
    };
    finish_mutation(
        state,
        command,
        result,
        permission,
        &trace_id,
        audit.with_result("finding state updated"),
        None,
    )
}

fn response_approval_mutation(
    state: &mut MutationCommandState,
    command: &'static str,
    request: ResponseApprovalMutationRequest,
    decision: ApprovalDecision,
) -> CommandResult<MutationReceipt<ResponseApprovalMutationResult>> {
    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, request.actor_redacted.as_deref());
    let action = get_response_action(state, &request.action_id)?.clone();
    let action_type = match decision {
        ApprovalDecision::Approved => AuditActionType::ResponseApprovalApproved,
        ApprovalDecision::Rejected => AuditActionType::ResponseApprovalRejected,
    };
    let audit = AuditDraft::response(
        action_type,
        actor.clone(),
        format!("response_action:{}", request.action_id),
        action.rollback_plan.rollback_plan_id.to_string(),
    );
    let permission = authorize(
        state,
        &trace_id,
        command,
        "response.approval.write",
        PermissionScope::Response {
            action_type: action.action_type.clone(),
            execute: false,
        },
        PolicyScope::TauriMutationCommand,
        request
            .reason_redacted
            .as_deref()
            .unwrap_or("approval decision"),
        PolicyOptions::default(),
        audit.clone(),
    )?;
    let audit_receipt = audit_success(
        state,
        &trace_id,
        audit.with_result(match decision {
            ApprovalDecision::Approved => "response action approval recorded without execution",
            ApprovalDecision::Rejected => "response action rejection recorded",
        }),
        &permission,
    )?;
    let audit_ref = AuditRef {
        audit_id: audit_receipt.audit_id.clone(),
        event_type: match decision {
            ApprovalDecision::Approved => "response.approval.approved",
            ApprovalDecision::Rejected => "response.approval.rejected",
        }
        .to_string(),
        trace_id: Some(trace_id.clone()),
        timestamp: Timestamp::now(),
    };
    let approval_result = ApprovalResult {
        approval_result_id: ApprovalResultId::new_v4(),
        approval_request_id: ApprovalRequestId::new_v4(),
        plan_id: action.plan_id.clone(),
        action_id: action.action_id.clone(),
        actor,
        decision: decision.clone(),
        reason_redacted: request.reason_redacted,
        timestamp: Timestamp::now(),
        policy_version: action.policy_decision.policy_version.clone(),
        audit_ref,
    };
    let updated_action = mutate_response_action(state, &action.action_id, |mut action| {
        action.approval_state = match decision {
            ApprovalDecision::Approved => sentinel_contracts::ApprovalState::Approved,
            ApprovalDecision::Rejected => sentinel_contracts::ApprovalState::Rejected,
        };
        action
    })?;
    if matches!(decision, ApprovalDecision::Approved) {
        record_non_executing_response_result(state, &updated_action, &trace_id)?;
    }
    state.approval_results.push(approval_result.clone());
    Ok(MutationReceipt {
        command: command.to_string(),
        result: ResponseApprovalMutationResult {
            action: updated_action,
            approval_result,
            execution_started: false,
        },
        permission_decision: permission,
        audit_receipt,
        trace_id,
        rollback: None,
        generated_at: Timestamp::now(),
    })
}

fn apply_profile_change(
    state: &mut MutationCommandState,
    command: &'static str,
    change_kind: SettingsChangeKind,
    profile: RuntimeProfile,
    reason_redacted: String,
    requested_by_redacted: Option<String>,
    action_type: AuditActionType,
) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
    require_reason(&reason_redacted)?;
    let trace_id = TraceId::new_v4();
    let actor = actor_for_request(state, requested_by_redacted.as_deref());
    let audit = AuditDraft::generic(
        AuditCategory::Settings,
        action_type,
        actor.clone(),
        format!("settings:{change_kind:?}"),
    );
    let permission = authorize(
        state,
        &trace_id,
        command,
        settings_permission_key(command, &change_kind),
        PermissionScope::Policy {
            policy_key: format!("{change_kind:?}"),
            mutation: true,
        },
        PolicyScope::SettingsMutation,
        &reason_redacted,
        PolicyOptions {
            runtime_profile: Some(profile.clone()),
            ..PolicyOptions::default()
        },
        audit.clone(),
    )?;
    let mut change_request =
        SettingsChangeRequest::new(change_kind, profile.clone(), reason_redacted)
            .map_err(contract_error)?;
    change_request.requested_by = Some(actor);
    let impact_analysis = SettingsImpactAnalysis::from_request(&change_request);
    if !impact_analysis.forbidden_changes.is_empty() {
        return Err(policy_error(
            "settings change violates policy",
            json!({ "forbidden_changes": impact_analysis.forbidden_changes }),
            &trace_id,
        ));
    }

    let previous_profile = state.read.runtime_profile.clone();
    let rollback_ref = format!("settings.rollback:{}", change_request.request_id);
    state
        .settings_rollbacks
        .insert(rollback_ref.clone(), previous_profile);
    state.read.runtime_profile = profile.clone();

    let rollback = MutationRollbackMetadata {
        rollback_ref,
        rollback_kind: "runtime_profile".to_string(),
        rollback_available: true,
        audit_required: true,
        expires_at: None,
    };
    let result = SettingsMutationResult {
        runtime_profile: profile,
        change_request,
        impact_analysis,
    };
    finish_mutation(
        state,
        command,
        result,
        permission,
        &trace_id,
        audit.with_result("settings profile updated after validation and impact analysis"),
        Some(rollback),
    )
}

fn authorize_export(
    state: &mut MutationCommandState,
    trace_id: &TraceId,
    request: &ExportReportRequest,
    redaction_summary: &RedactionSummary,
    export_metadata: ExportAuditMetadata,
    actor: &str,
    export_history_stores: Option<&SqliteStoreFactory<'_>>,
) -> CommandResult<PermissionDecision> {
    let permission = permission_key("export.report.write")?;
    let subject = PermissionSubject::TauriCommand(EXPORT_REPORT.to_string());
    let scope = PermissionScope::Export {
        export_kind: request.format.as_str().to_string(),
        redaction_required: true,
    };
    let mut context = PolicyEvaluationContext::new(
        PolicyScope::Export,
        subject.clone(),
        permission.clone(),
        scope.clone(),
        state.read.runtime_profile.clone(),
    );
    context.redaction_confirmed = request.user_confirmed && redaction_summary.passed;
    let policy_result = state.permission_resolver.evaluate_policy(context);
    let decision = state.permission_resolver.evaluate_permission(
        PermissionRequest::new(
            subject,
            permission,
            scope,
            PolicyScope::Export,
            "export redacted report",
        ),
        Some(&policy_result),
    );

    if !matches!(decision.decision, PermissionDecisionKind::Allow) {
        let audit_decision = audit_decision_for_permission(&decision);
        let receipt = append_export_audit(
            state,
            trace_id,
            AuditActionType::ExportFailed,
            actor,
            "report.export",
            audit_decision,
            "report export denied by permission or policy",
            redaction_summary.clone(),
            export_metadata,
        )?;
        let violation_receipt = append_export_policy_violation_audit(
            state,
            trace_id,
            actor,
            "report.export",
            "report export denied by permission or policy",
        )?;
        let violation = record_export_policy_violation(
            state,
            request,
            actor,
            redaction_summary.clone(),
            "report export denied by permission or policy",
            trace_id,
            violation_receipt.clone(),
            Some(receipt.audit_id),
        )?;
        persist_export_policy_violation(export_history_stores, &violation, trace_id)?;
        return Err(permission_error(decision, trace_id).with_audit_ref(violation_receipt.audit_id));
    }

    Ok(decision)
}

#[allow(clippy::too_many_arguments)]
fn authorize(
    state: &mut MutationCommandState,
    trace_id: &TraceId,
    command: &'static str,
    permission: &'static str,
    scope: PermissionScope,
    policy_scope: PolicyScope,
    reason_redacted: &str,
    options: PolicyOptions,
    audit: AuditDraft,
) -> CommandResult<PermissionDecision> {
    let permission = permission_key(permission)?;
    let subject = PermissionSubject::TauriCommand(command.to_string());
    let request = PermissionRequest::new(
        subject.clone(),
        permission.clone(),
        scope.clone(),
        policy_scope.clone(),
        reason_redacted,
    );
    let policy_result = if request.policy_evaluation_required {
        let mut context = PolicyEvaluationContext::new(
            policy_scope,
            subject,
            permission,
            scope,
            options
                .runtime_profile
                .unwrap_or_else(|| state.read.runtime_profile.clone()),
        );
        context.service_available = options.service_available;
        context.rollback_available = options.rollback_available;
        context.redaction_confirmed = options.redaction_confirmed;
        context.approval_already_granted = options.approval_already_granted;
        context.is_replay = options.is_replay;
        context.detail_redacted = options.detail_redacted;
        Some(state.permission_resolver.evaluate_policy(context))
    } else {
        None
    };
    let decision = state
        .permission_resolver
        .evaluate_permission(request, policy_result.as_ref());

    if !matches!(decision.decision, PermissionDecisionKind::Allow) {
        let receipt = audit_success(
            state,
            trace_id,
            audit
                .with_decision(audit_decision_for_permission(&decision))
                .with_result("mutation denied by permission or policy"),
            &decision,
        )?;
        return Err(permission_error(decision, trace_id).with_audit_ref(receipt.audit_id));
    }

    Ok(decision)
}

fn finish_mutation<T>(
    state: &mut MutationCommandState,
    command: &'static str,
    result: T,
    permission: PermissionDecision,
    trace_id: &TraceId,
    audit: AuditDraft,
    rollback: Option<MutationRollbackMetadata>,
) -> CommandResult<MutationReceipt<T>> {
    let audit_receipt = audit_success(state, trace_id, audit, &permission)?;
    Ok(MutationReceipt {
        command: command.to_string(),
        result,
        permission_decision: permission,
        audit_receipt,
        trace_id: trace_id.clone(),
        rollback,
        generated_at: Timestamp::now(),
    })
}

fn audit_success(
    state: &mut MutationCommandState,
    trace_id: &TraceId,
    audit: AuditDraft,
    permission: &PermissionDecision,
) -> CommandResult<AuditReceipt> {
    let reason_codes = permission
        .reasons
        .iter()
        .map(|reason| format!("{:?}", reason.code))
        .collect::<Vec<_>>();
    let mut event = match audit.category {
        AuditCategory::Response | AuditCategory::Rollback => AuditEvent::response_event(
            audit.action_type,
            audit.actor_redacted,
            audit.target_redacted,
            audit.decision,
            audit.policy_version.unwrap_or_else(|| "v1".to_string()),
            trace_id.clone(),
            audit.result_redacted,
            audit
                .rollback_ref
                .unwrap_or_else(|| "not_applicable".to_string()),
            audit.sensitive_data_touched,
        )
        .map_err(contract_error)?,
        _ => {
            let mut event = AuditEvent::new(
                audit.category,
                audit.action_type,
                audit.actor_redacted,
                audit.target_redacted,
                audit.decision,
                audit.result_redacted,
            )
            .map_err(contract_error)?;
            event.trace_id = Some(trace_id.clone());
            event.policy_version = audit.policy_version;
            event.rollback_ref = audit.rollback_ref;
            event.sensitive_data_touched = audit.sensitive_data_touched;
            event
        }
    };
    event.reason_codes = reason_codes;
    append_audit(state, event, trace_id)
}

#[allow(clippy::too_many_arguments)]
fn append_export_audit(
    state: &mut MutationCommandState,
    trace_id: &TraceId,
    action_type: AuditActionType,
    actor_redacted: &str,
    target_redacted: &str,
    decision: AuditDecision,
    result_redacted: &str,
    redaction_summary: RedactionSummary,
    export_metadata: ExportAuditMetadata,
) -> CommandResult<AuditReceipt> {
    let mut event = AuditEvent::export_event(
        action_type,
        actor_redacted,
        target_redacted,
        decision,
        result_redacted,
        redaction_summary,
        export_metadata,
    )
    .map_err(contract_error)?;
    event.trace_id = Some(trace_id.clone());
    append_audit(state, event, trace_id)
}

fn append_export_policy_violation_audit(
    state: &mut MutationCommandState,
    trace_id: &TraceId,
    actor_redacted: &str,
    target_redacted: &str,
    result_redacted: &str,
) -> CommandResult<AuditReceipt> {
    let mut event = AuditEvent::new(
        AuditCategory::PrivacyViolation,
        AuditActionType::PrivacyViolation,
        actor_redacted,
        target_redacted,
        AuditDecision::Denied,
        result_redacted,
    )
    .map_err(contract_error)?;
    event.trace_id = Some(trace_id.clone());
    event.sensitive_data_touched = true;
    append_audit(state, event, trace_id)
}

struct SuccessfulExportHistoryInput {
    export_result: ExportResult,
    actor_redacted: String,
    destination_metadata_redacted: Option<String>,
    audit_receipt: AuditReceipt,
    artifact_bytes: Option<Vec<u8>>,
    graph_snapshot_refs: Vec<GraphSnapshotId>,
    evidence_refs: Vec<EvidenceId>,
    response_result_refs: Vec<sentinel_contracts::ResponseResultId>,
    rollback_result_refs: Vec<sentinel_contracts::RollbackResultId>,
    llm_story_refs: Vec<sentinel_contracts::LlmAlertStoryId>,
}

fn record_successful_export_history(
    state: &mut MutationCommandState,
    input: SuccessfulExportHistoryInput,
) -> CommandResult<ExportHistoryRecord> {
    let destination = ExportDestinationMetadata::local(input.destination_metadata_redacted)
        .map_err(export_history_error)?;
    ExportAuditService::new()
        .record_success(
            &mut state.read.export_history,
            ExportAuditSuccessInput {
                export_result: input.export_result,
                actor_redacted: input.actor_redacted,
                destination,
                audit_receipt: input.audit_receipt,
                artifact_bytes: input.artifact_bytes,
                graph_snapshot_refs: input.graph_snapshot_refs,
                evidence_refs: input.evidence_refs,
                response_result_refs: input.response_result_refs,
                rollback_result_refs: input.rollback_result_refs,
                llm_story_refs: input.llm_story_refs,
            },
        )
        .map_err(export_history_error)
}

#[allow(clippy::too_many_arguments)]
fn record_export_policy_violation(
    state: &mut MutationCommandState,
    request: &ExportReportRequest,
    actor_redacted: &str,
    redaction_summary: RedactionSummary,
    reason_redacted: &str,
    trace_id: &TraceId,
    violation_audit_receipt: AuditReceipt,
    export_audit_id: Option<sentinel_contracts::AuditId>,
) -> CommandResult<ExportPolicyViolation> {
    let destination =
        ExportDestinationMetadata::local(request.destination_metadata_redacted.clone())
            .map_err(export_history_error)?;
    ExportAuditService::new()
        .record_violation(
            &mut state.read.export_history,
            ExportPolicyViolationInput {
                report_id: request.report_id.clone(),
                format: request.format.clone(),
                actor_redacted: actor_redacted.to_string(),
                destination,
                reason_redacted: reason_redacted.to_string(),
                redaction_summary,
                trace_id: Some(trace_id.clone()),
                violation_audit_receipt,
                export_audit_id,
            },
        )
        .map_err(export_history_error)
}

fn persist_export_history_record(
    stores: Option<&SqliteStoreFactory<'_>>,
    record: &ExportHistoryRecord,
    trace_id: &TraceId,
) -> CommandResult<()> {
    if let Some(stores) = stores {
        ExportHistoryStorageAdapter::new()
            .persist_record(stores, record)
            .map_err(|error| export_history_storage_error(error, trace_id))?;
    }
    Ok(())
}

fn persist_export_policy_violation(
    stores: Option<&SqliteStoreFactory<'_>>,
    violation: &ExportPolicyViolation,
    trace_id: &TraceId,
) -> CommandResult<()> {
    if let Some(stores) = stores {
        ExportHistoryStorageAdapter::new()
            .persist_violation(stores, violation)
            .map_err(|error| export_history_storage_error(error, trace_id))?;
    }
    Ok(())
}

fn append_audit(
    state: &mut MutationCommandState,
    event: AuditEvent,
    trace_id: &TraceId,
) -> CommandResult<AuditReceipt> {
    state.audit_sink.append(event).map_err(|error| {
        CoreError::new(
            ErrorCode::InternalError,
            "audit sink rejected mutation event",
        )
        .with_trace_id(trace_id.clone())
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
    })
}

#[derive(Clone, Debug)]
struct AuditDraft {
    category: AuditCategory,
    action_type: AuditActionType,
    actor_redacted: String,
    target_redacted: String,
    decision: AuditDecision,
    result_redacted: String,
    policy_version: Option<String>,
    rollback_ref: Option<String>,
    sensitive_data_touched: bool,
}

impl AuditDraft {
    fn generic(
        category: AuditCategory,
        action_type: AuditActionType,
        actor_redacted: String,
        target_redacted: String,
    ) -> Self {
        Self {
            category,
            action_type,
            actor_redacted,
            target_redacted,
            decision: AuditDecision::Completed,
            result_redacted: "mutation completed".to_string(),
            policy_version: Some("v1".to_string()),
            rollback_ref: None,
            sensitive_data_touched: false,
        }
    }

    fn response(
        action_type: AuditActionType,
        actor_redacted: String,
        target_redacted: String,
        rollback_ref: String,
    ) -> Self {
        Self {
            category: if matches!(
                action_type,
                AuditActionType::ResponseRollbackStarted
                    | AuditActionType::ResponseRollbackCompleted
                    | AuditActionType::ResponseRollbackFailed
            ) {
                AuditCategory::Rollback
            } else {
                AuditCategory::Response
            },
            action_type,
            actor_redacted,
            target_redacted,
            decision: AuditDecision::Completed,
            result_redacted: "response mutation completed".to_string(),
            policy_version: Some("v1".to_string()),
            rollback_ref: Some(rollback_ref),
            sensitive_data_touched: false,
        }
    }

    fn with_result(mut self, result_redacted: impl Into<String>) -> Self {
        self.result_redacted = result_redacted.into();
        self
    }

    fn with_decision(mut self, decision: AuditDecision) -> Self {
        self.decision = decision;
        self
    }
}

#[derive(Clone, Debug, Default)]
struct PolicyOptions {
    runtime_profile: Option<RuntimeProfile>,
    service_available: bool,
    rollback_available: bool,
    redaction_confirmed: bool,
    approval_already_granted: bool,
    is_replay: bool,
    detail_redacted: Option<String>,
}

fn mutate_finding(
    state: &mut MutationCommandState,
    finding_id: &FindingId,
    update: impl FnOnce(Finding) -> Finding,
) -> CommandResult<Finding> {
    let index = state
        .read
        .findings
        .items
        .iter()
        .position(|finding| finding.id() == finding_id)
        .ok_or_else(|| {
            not_found_error(
                "finding",
                json!({ "finding_id": finding_id.to_string() }),
                &TraceId::new_v4(),
            )
        })?;
    let updated = update(state.read.findings.items[index].clone());
    state.read.findings.items[index] = updated.clone();
    Ok(updated)
}

fn mutate_alert(
    state: &mut MutationCommandState,
    alert_id: &AlertId,
    update: impl FnOnce(Alert) -> Alert,
) -> CommandResult<Alert> {
    let index = state
        .read
        .alerts
        .items
        .iter()
        .position(|alert| alert.id() == alert_id)
        .ok_or_else(|| {
            not_found_error(
                "alert",
                json!({ "alert_id": alert_id.to_string() }),
                &TraceId::new_v4(),
            )
        })?;
    let updated = update(state.read.alerts.items[index].clone());
    state.read.alerts.items[index] = updated.clone();
    Ok(updated)
}

fn mutate_incident(
    state: &mut MutationCommandState,
    incident_id: &IncidentId,
    update: impl FnOnce(Incident) -> Incident,
) -> CommandResult<Incident> {
    let index = state
        .read
        .incidents
        .items
        .iter()
        .position(|incident| incident.id() == incident_id)
        .ok_or_else(|| {
            not_found_error(
                "incident",
                json!({ "incident_id": incident_id.to_string() }),
                &TraceId::new_v4(),
            )
        })?;
    let updated = update(state.read.incidents.items[index].clone());
    state.read.incidents.items[index] = updated.clone();
    Ok(updated)
}

fn mutate_response_action(
    state: &mut MutationCommandState,
    action_id: &ResponseActionId,
    update: impl FnOnce(ResponseAction) -> ResponseAction,
) -> CommandResult<ResponseAction> {
    let index = state
        .response_actions
        .iter()
        .position(|action| &action.action_id == action_id)
        .ok_or_else(|| {
            not_found_error(
                "response_action",
                json!({ "action_id": action_id.to_string() }),
                &TraceId::new_v4(),
            )
        })?;
    let updated = update(state.response_actions[index].clone());
    state.response_actions[index] = updated.clone();
    update_recommended_action_approval_state(state, &updated);
    Ok(updated)
}

fn update_recommended_action_approval_state(
    state: &mut MutationCommandState,
    action: &ResponseAction,
) {
    for plan in &mut state.read.response_plans.items {
        if plan.plan_id != action.plan_id {
            continue;
        }
        for recommended in &mut plan.recommended_actions {
            if recommended.action_id.as_ref() == Some(&action.action_id) {
                recommended.approval_state = Some(action.approval_state.clone());
                break;
            }
        }
        for decision in &mut plan.policy_decisions {
            if decision.action_id.as_ref() == Some(&action.action_id) {
                *decision = action.policy_decision.clone();
                break;
            }
        }
    }
}

fn find_incident<'a>(
    state: &'a MutationCommandState,
    incident_id: &IncidentId,
) -> CommandResult<&'a Incident> {
    state
        .read
        .incidents
        .items
        .iter()
        .find(|incident| incident.id() == incident_id)
        .ok_or_else(|| {
            not_found_error(
                "incident",
                json!({ "incident_id": incident_id.to_string() }),
                &TraceId::new_v4(),
            )
        })
}

fn find_report<'a>(
    state: &'a MutationCommandState,
    report_id: &ReportId,
) -> CommandResult<&'a Report> {
    state
        .read
        .reports
        .items
        .iter()
        .find(|report| &report.report_id == report_id)
        .ok_or_else(|| {
            not_found_error(
                "report",
                json!({ "report_id": report_id.to_string() }),
                &TraceId::new_v4(),
            )
        })
}

fn get_response_action<'a>(
    state: &'a MutationCommandState,
    action_id: &ResponseActionId,
) -> CommandResult<&'a ResponseAction> {
    state
        .response_actions
        .iter()
        .find(|action| &action.action_id == action_id)
        .ok_or_else(|| {
            not_found_error(
                "response_action",
                json!({ "action_id": action_id.to_string() }),
                &TraceId::new_v4(),
            )
        })
}

fn response_planning_input_for_source(
    state: &MutationCommandState,
    source: &ResponsePlanSource,
) -> CommandResult<ResponsePlanningInput> {
    let mut input = ResponsePlanningInput::new(PluginId::new_v4())
        .with_response_policy(state.read.runtime_profile.response_policy.clone());
    input.labels = vec!["task_580_response_report_demo".to_string()];

    match source {
        ResponsePlanSource::Finding(id) => {
            let finding = state
                .read
                .findings
                .items
                .iter()
                .find(|finding| finding.id() == id)
                .cloned()
                .ok_or_else(|| {
                    not_found_error(
                        "finding",
                        json!({ "finding_id": id.to_string() }),
                        &TraceId::new_v4(),
                    )
                })?;
            input.findings.push(finding);
        }
        ResponsePlanSource::Alert(id) => {
            let alert = state
                .read
                .alerts
                .items
                .iter()
                .find(|alert| alert.id() == id)
                .cloned()
                .ok_or_else(|| {
                    not_found_error(
                        "alert",
                        json!({ "alert_id": id.to_string() }),
                        &TraceId::new_v4(),
                    )
                })?;
            input.findings = findings_for_ids(state, alert.finding_refs());
            input.alerts.push(alert);
        }
        ResponsePlanSource::Incident(id) => {
            let incident = find_incident(state, id)?.clone();
            let related_alerts = alerts_for_incident(state, &incident);
            let related_finding_ids = finding_ids_for_incident(&incident, &related_alerts);
            input.findings = findings_for_ids(state, &related_finding_ids);
            input.alerts = related_alerts;
            input.incidents.push(incident);
        }
        ResponsePlanSource::GraphPath(_) => {}
    }

    input.graph_paths = graph_paths_for_response_source(state, source)?;
    Ok(input)
}

#[derive(Clone, Debug)]
pub(crate) struct ResponsePlanningCommandOutput {
    pub(crate) response_plans: Vec<ResponsePlan>,
    pub(crate) used_static_runtime: bool,
}

fn response_planning_output_for_source(
    state: &MutationCommandState,
    source: &ResponsePlanSource,
    trace_id: &TraceId,
) -> CommandResult<ResponsePlanningCommandOutput> {
    let input = response_planning_input_for_source(state, source)?;
    if response_source_can_use_static_runtime(source) {
        return static_response_planning_output(input, trace_id);
    }

    let output = ResponsePlanningPlugin::new()
        .process(input)
        .map_err(response_planning_error)?;
    Ok(ResponsePlanningCommandOutput {
        response_plans: output.response_plans,
        used_static_runtime: false,
    })
}

fn response_source_can_use_static_runtime(source: &ResponsePlanSource) -> bool {
    matches!(
        source,
        ResponsePlanSource::Finding(_)
            | ResponsePlanSource::Alert(_)
            | ResponsePlanSource::Incident(_)
            | ResponsePlanSource::GraphPath(_)
    )
}

pub(crate) fn static_response_planning_output(
    input: ResponsePlanningInput,
    trace_id: &TraceId,
) -> CommandResult<ResponsePlanningCommandOutput> {
    let staged_event_producer = input.producer_plugin.clone();
    let mut runtime = PluginRuntime::new();
    let plugin_id = register_static_response_planning_plugin(&mut runtime)
        .map_err(|error| response_planning_runtime_error(error, trace_id))?;
    let manifest = runtime
        .manifest(&plugin_id)
        .ok_or_else(|| {
            response_planning_runtime_error(
                "static response planning manifest was not registered",
                trace_id,
            )
        })?
        .clone();
    let contracts = contract_registry_for_manifest(&manifest, trace_id)?;
    let mut permissions = PermissionResolver::new();
    permissions.register_plugin_manifest_permissions(&manifest);
    let validation = runtime
        .registry()
        .validate_startup(&plugin_id, &contracts, &permissions)
        .map_err(|error| response_planning_runtime_error(error, trace_id))?;
    let trace_context = TraceContext::new(trace_id.clone());
    let mut context = plugin_context_for_manifest(&manifest, trace_context.clone(), trace_id)?;
    context.policy_scope = PolicyScope::ResponsePlanning;
    context.current_permission_scope = Some(PermissionScope::Response {
        action_type: ResponseActionType::RecommendProcessReview,
        execute: false,
    });
    runtime
        .start_plugin(&plugin_id, &validation, &mut context)
        .map_err(|error| response_planning_runtime_error(error, trace_id))?;

    let mut batch = PluginEventBatch::new(
        plugin_id.clone(),
        input.findings.len()
            + input.alerts.len()
            + input.incidents.len()
            + input.graph_paths.len()
            + input.policy_rules.len()
            + 1,
    );
    batch
        .push(response_planning_event(
            &staged_event_producer,
            RESPONSE_POLICY_SETTINGS_CONTRACT,
            input.response_policy.clone(),
            &trace_context,
            trace_id,
        )?)
        .map_err(|error| response_planning_runtime_error(error, trace_id))?;
    for policy_rule in input.policy_rules {
        batch
            .push(response_planning_event(
                &staged_event_producer,
                RESPONSE_POLICY_RULE_CONTRACT,
                policy_rule,
                &trace_context,
                trace_id,
            )?)
            .map_err(|error| response_planning_runtime_error(error, trace_id))?;
    }
    for finding in input.findings {
        batch
            .push(response_planning_event(
                &staged_event_producer,
                SECURITY_FINDING,
                finding,
                &trace_context,
                trace_id,
            )?)
            .map_err(|error| response_planning_runtime_error(error, trace_id))?;
    }
    for alert in input.alerts {
        batch
            .push(response_planning_event(
                &staged_event_producer,
                SECURITY_ALERT,
                alert,
                &trace_context,
                trace_id,
            )?)
            .map_err(|error| response_planning_runtime_error(error, trace_id))?;
    }
    for incident in input.incidents {
        batch
            .push(response_planning_event(
                &staged_event_producer,
                SECURITY_INCIDENT,
                incident,
                &trace_context,
                trace_id,
            )?)
            .map_err(|error| response_planning_runtime_error(error, trace_id))?;
    }
    for graph_path in input.graph_paths {
        batch
            .push(response_planning_event(
                &staged_event_producer,
                GRAPH_PATH,
                graph_path,
                &trace_context,
                trace_id,
            )?)
            .map_err(|error| response_planning_runtime_error(error, trace_id))?;
    }

    let output = runtime
        .process_batch(&plugin_id, &mut context, &batch)
        .map_err(|error| response_planning_runtime_error(error, trace_id))?;
    let mut response_plans = Vec::new();
    for event in output.events {
        match event.event_type.as_str() {
            RESPONSE_PLAN => response_plans.push(
                serde_json::from_value::<ResponsePlan>(event.payload)
                    .map_err(|error| response_planning_runtime_error(error, trace_id))?,
            ),
            RESPONSE_RESULT | RESPONSE_ROLLBACK_RESULT => {
                return Err(response_planning_runtime_error(
                    "response planning runtime emitted an execution output topic",
                    trace_id,
                ));
            }
            _ => {}
        }
    }
    for plan in &mut response_plans {
        push_unique_string(
            &mut plan.audit_requirements,
            "response.runtime.static_internal.process_batch".to_string(),
        );
    }

    Ok(ResponsePlanningCommandOutput {
        response_plans,
        used_static_runtime: true,
    })
}

fn contract_registry_for_manifest(
    manifest: &PluginManifest,
    trace_id: &TraceId,
) -> CommandResult<ContractRegistry> {
    let mut registry = ContractRegistry::new();
    for contract in manifest
        .input_contracts
        .iter()
        .chain(manifest.output_contracts.iter())
    {
        registry
            .register(contract.clone())
            .map_err(|error| response_planning_runtime_error(error, trace_id))?;
    }
    Ok(registry)
}

fn plugin_context_for_manifest(
    manifest: &PluginManifest,
    trace_context: TraceContext,
    trace_id: &TraceId,
) -> CommandResult<PluginContext<'static>> {
    let mut context = PluginContext::new(
        manifest.plugin_id.clone(),
        manifest.runtime_mode.clone(),
        trace_context,
    );
    for contract in &manifest.input_contracts {
        context
            .topic_scope
            .subscribe_topics
            .insert(topic_for_contract(contract, trace_id)?);
    }
    for contract in &manifest.output_contracts {
        context
            .topic_scope
            .publish_topics
            .insert(topic_for_contract(contract, trace_id)?);
    }
    for permission in &manifest.required_permissions {
        context
            .permission_scope
            .required_permissions
            .insert(permission.permission.clone());
        context
            .permission_scope
            .granted_permissions
            .insert(permission.permission.clone());
    }
    context.checkpoint =
        CheckpointSupport::from_manifest_level(manifest.checkpoint_support.clone());
    context.replay = ReplaySupport::from_manifest_level(manifest.replay_support.clone());
    Ok(context)
}

fn topic_for_contract(
    contract: &ContractDescriptor,
    trace_id: &TraceId,
) -> CommandResult<TopicName> {
    TopicName::new(
        contract
            .topic
            .as_deref()
            .unwrap_or(contract.contract_name.as_str()),
    )
    .map_err(|error| response_planning_runtime_error(error, trace_id))
}

fn response_planning_event(
    producer_plugin: &PluginId,
    topic: &str,
    payload: impl Serialize,
    trace_context: &TraceContext,
    trace_id: &TraceId,
) -> CommandResult<EventEnvelope> {
    let mut event = EventEnvelope::new(
        EventType::new(topic).map_err(contract_error)?,
        SchemaVersion::new(1, 0, 0),
        producer_plugin.clone(),
        trace_context.clone(),
    );
    event.privacy_class = PrivacyClass::Internal;
    event.payload = serde_json::to_value(payload)
        .map_err(|error| response_planning_runtime_error(error, trace_id))?;
    Ok(event)
}

fn response_plan_for_source(
    mut plans: Vec<ResponsePlan>,
    source: &ResponsePlanSource,
) -> CommandResult<ResponsePlan> {
    if plans.is_empty() {
        return Err(CoreError::new(
            ErrorCode::ValidationFailure,
            "response planner produced no response plans",
        )
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({ "source": response_source_target(source) })));
    }

    let selected_index = plans
        .iter()
        .position(|plan| &plan.source == source)
        .unwrap_or(0);
    let mut primary = plans.remove(selected_index);
    for extra in plans {
        merge_response_plan_context(&mut primary, extra)?;
    }

    if primary.recommended_actions.is_empty() {
        return Err(CoreError::new(
            ErrorCode::ValidationFailure,
            "response planner produced an empty recommendation set",
        )
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({ "source": response_source_target(source) })));
    }

    Ok(primary)
}

fn merge_response_plan_context(
    primary: &mut ResponsePlan,
    extra: ResponsePlan,
) -> CommandResult<()> {
    for (index, action) in extra.recommended_actions.into_iter().enumerate() {
        if primary
            .recommended_actions
            .iter()
            .any(|existing| existing.action_type == action.action_type)
        {
            continue;
        }

        let mut policy = if let Some(policy) = extra.policy_decisions.get(index) {
            policy.clone()
        } else {
            ResponsePolicyDecision::new(
                action.response_level.clone(),
                "policy decision synthesized for merged response context",
                "response-policy-v1",
            )
            .map_err(contract_error)?
        };
        policy.plan_id = Some(primary.plan_id.clone());

        let mut rollback = if let Some(rollback) = extra.rollback_plans.get(index) {
            rollback.clone()
        } else {
            RollbackPlan::new(format!(
                "rollback:{}:{}",
                action_key_for_audit(&action.action_type),
                primary.plan_id
            ))
            .map_err(contract_error)?
        };
        rollback.action_id = None;

        primary.recommended_actions.push(action);
        primary.policy_decisions.push(policy);
        primary.rollback_plans.push(rollback);
    }

    primary.approval_required |= extra.approval_required;
    for requirement in extra.audit_requirements {
        push_unique_string(&mut primary.audit_requirements, requirement);
    }
    if primary.business_impact_redacted.trim().is_empty() {
        primary.business_impact_redacted = extra.business_impact_redacted;
    }
    Ok(())
}

fn prepare_response_plan_metadata(plan: &mut ResponsePlan) -> CommandResult<()> {
    while plan.policy_decisions.len() < plan.recommended_actions.len() {
        let action = &plan.recommended_actions[plan.policy_decisions.len()];
        let mut policy = ResponsePolicyDecision::new(
            action.response_level.clone(),
            "policy decision synthesized for response recommendation",
            "response-policy-v1",
        )
        .map_err(contract_error)?;
        policy.approval_required = action.approval_required;
        plan.policy_decisions.push(policy);
    }

    while plan.rollback_plans.len() < plan.recommended_actions.len() {
        let action = &plan.recommended_actions[plan.rollback_plans.len()];
        plan.rollback_plans.push(
            RollbackPlan::new(format!(
                "rollback:{}:{}",
                action_key_for_audit(&action.action_type),
                plan.plan_id
            ))
            .map_err(contract_error)?,
        );
    }

    plan.approval_required = false;
    for (index, action) in plan.recommended_actions.iter_mut().enumerate() {
        let policy = &mut plan.policy_decisions[index];
        policy.plan_id = Some(plan.plan_id.clone());
        action.response_level = policy.level.clone();
        action.approval_required = policy.approval_required;
        action.ttl = policy.ttl.clone();
        action.rollback_available = true;
        plan.approval_required |= policy.approval_required;
    }

    Ok(())
}

fn response_actions_for_plan(plan: &mut ResponsePlan, trace_id: &TraceId) -> Vec<ResponseAction> {
    let mut actions = Vec::new();
    for index in 0..plan.recommended_actions.len() {
        let recommended = plan.recommended_actions[index].clone();
        let policy = plan.policy_decisions[index].clone();
        let rollback = plan.rollback_plans[index].clone();
        let audit_ref = AuditRef {
            audit_id: sentinel_contracts::AuditId::new_v4(),
            event_type: audit_event_type_for_response_level(&policy.level).to_string(),
            trace_id: Some(trace_id.clone()),
            timestamp: Timestamp::now(),
        };
        let mut action = ResponseAction::new(
            plan.plan_id.clone(),
            recommended,
            policy,
            audit_ref,
            rollback,
        );
        if matches!(
            action.policy_decision.level,
            ResponseLevel::AutoContainmentLite
        ) {
            action.approval_state = ApprovalState::Approved;
        }
        action.policy_decision.action_id = Some(action.action_id.clone());
        action.rollback_plan.action_id = Some(action.action_id.clone());

        plan.recommended_actions[index].action_id = Some(action.action_id.clone());
        plan.recommended_actions[index].approval_state = Some(action.approval_state.clone());
        plan.policy_decisions[index] = action.policy_decision.clone();
        plan.rollback_plans[index] = action.rollback_plan.clone();
        actions.push(action);
    }
    actions
}

fn record_non_executing_response_result(
    state: &mut MutationCommandState,
    action: &ResponseAction,
    trace_id: &TraceId,
) -> CommandResult<()> {
    if state
        .response_results
        .iter()
        .any(|result| result.action_id == action.action_id)
    {
        return Ok(());
    }

    let audit_ref = AuditRef {
        audit_id: sentinel_contracts::AuditId::new_v4(),
        event_type: "response.execution.disabled".to_string(),
        trace_id: Some(trace_id.clone()),
        timestamp: Timestamp::now(),
    };
    let mut result = ResponseResult::new(
        action.action_id.clone(),
        "execution_disabled_recommendation_only",
        action.target.clone(),
        &action.rollback_plan,
        audit_ref,
    )
    .map_err(contract_error)?;
    result.ended_at = Some(Timestamp::now());
    result.success = false;
    result.error_summary_redacted = Some(
        "no OS action was performed; response execution is disabled for this recommendation"
            .to_string(),
    );
    result.rollback_token.clear();
    result.rollback_deadline = None;
    result.is_replay = true;
    result.execution_disabled = true;
    state.response_results.push(result);
    Ok(())
}

fn audit_event_type_for_response_level(level: &ResponseLevel) -> &'static str {
    match level {
        ResponseLevel::AutoContainmentLite => "response.action.auto_approved",
        ResponseLevel::ApprovalRequired => "response.approval.requested",
        ResponseLevel::NotSupportedInV1 => "response.policy.denied",
        ResponseLevel::RecommendOnly => "response.recommendation.recorded",
    }
}

fn action_key_for_audit(action_type: &ResponseActionType) -> String {
    format!("{action_type:?}").to_ascii_lowercase()
}

fn alerts_for_incident(state: &MutationCommandState, incident: &Incident) -> Vec<Alert> {
    state
        .read
        .alerts
        .items
        .iter()
        .filter(|alert| incident.alert_refs().contains(alert.id()))
        .cloned()
        .collect()
}

fn finding_ids_for_incident(incident: &Incident, alerts: &[Alert]) -> Vec<FindingId> {
    let mut ids = Vec::new();
    for alert in alerts {
        for finding_id in alert.finding_refs() {
            push_unique_finding_id(&mut ids, finding_id.clone());
        }
    }
    for finding_id in incident.finding_refs() {
        push_unique_finding_id(&mut ids, finding_id.clone());
    }
    ids
}

fn findings_for_ids(state: &MutationCommandState, finding_ids: &[FindingId]) -> Vec<Finding> {
    state
        .read
        .findings
        .items
        .iter()
        .filter(|finding| finding_ids.contains(finding.id()))
        .cloned()
        .collect()
}

fn graph_paths_for_response_source(
    state: &MutationCommandState,
    source: &ResponsePlanSource,
) -> CommandResult<Vec<GraphPath>> {
    let incident_path_refs = match source {
        ResponsePlanSource::Incident(id) => find_incident(state, id)?.graph_path_refs().to_vec(),
        _ => Vec::new(),
    };
    let mut paths = Vec::new();
    for view in &state.read.graph_views {
        if !graph_view_matches_response_source(view, source, &incident_path_refs) {
            continue;
        }
        for summary in &view.paths {
            if !graph_path_summary_matches_source(&summary.path_id, source, &incident_path_refs) {
                continue;
            }
            let path = graph_path_from_view_summary(view, summary)?;
            if !paths
                .iter()
                .any(|existing: &GraphPath| existing.path_id == path.path_id)
            {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

fn graph_view_matches_response_source(
    view: &GraphViewModel,
    source: &ResponsePlanSource,
    incident_path_refs: &[GraphPathId],
) -> bool {
    match source {
        ResponsePlanSource::Incident(id) => {
            matches!(&view.filters.scope, GraphScope::Incident(scope_id) if scope_id == id)
                || view
                    .paths
                    .iter()
                    .any(|summary| incident_path_refs.contains(&summary.path_id))
        }
        ResponsePlanSource::Alert(id) => {
            matches!(&view.filters.scope, GraphScope::Alert(scope_id) if scope_id == id)
        }
        ResponsePlanSource::Finding(id) => {
            matches!(&view.filters.scope, GraphScope::Finding(scope_id) if scope_id == id)
        }
        ResponsePlanSource::GraphPath(id) => {
            view.paths.iter().any(|summary| &summary.path_id == id)
        }
    }
}

fn graph_path_summary_matches_source(
    path_id: &GraphPathId,
    source: &ResponsePlanSource,
    incident_path_refs: &[GraphPathId],
) -> bool {
    match source {
        ResponsePlanSource::GraphPath(id) => path_id == id,
        ResponsePlanSource::Incident(_) if !incident_path_refs.is_empty() => {
            incident_path_refs.contains(path_id)
        }
        _ => true,
    }
}

fn graph_path_from_view_summary(
    view: &GraphViewModel,
    summary: &sentinel_contracts::GraphPathSummary,
) -> CommandResult<GraphPath> {
    let node_sequence = view
        .nodes
        .iter()
        .map(|node| node.node_id.clone())
        .collect::<Vec<_>>();
    let edge_sequence = view
        .edges
        .iter()
        .map(|edge| edge.edge_id.clone())
        .collect::<Vec<_>>();
    let mut path = GraphPath::new(
        summary.path_type.clone(),
        node_sequence,
        edge_sequence,
        summary.label.clone(),
    )
    .map_err(contract_error)?;
    path.path_id = summary.path_id.clone();
    path.risk_score = summary.risk_score.clone();
    path.confidence = summary.confidence.clone();
    path.evidence_refs = graph_path_evidence_refs(view, summary);
    path.redaction_status = RedactionStatus::Redacted;
    Ok(path)
}

fn graph_path_evidence_refs(
    view: &GraphViewModel,
    summary: &sentinel_contracts::GraphPathSummary,
) -> Vec<EvidenceId> {
    let mut refs = Vec::new();
    for evidence_id in &summary.evidence_refs {
        push_unique_evidence_id(&mut refs, evidence_id.clone());
    }
    for edge in &view.edges {
        for evidence_id in &edge.evidence_refs {
            push_unique_evidence_id(&mut refs, evidence_id.clone());
        }
    }
    refs
}

fn graph_path_exists_in_read_state(
    state: &MutationCommandState,
    graph_path_id: &GraphPathId,
) -> bool {
    state
        .read
        .graph_views
        .iter()
        .any(|view| view.paths.iter().any(|path| &path.path_id == graph_path_id))
}

fn graph_snapshots_for_incident(
    state: &MutationCommandState,
    incident_id: &IncidentId,
    findings: &[Finding],
) -> CommandResult<Vec<GraphSnapshot>> {
    let incident = find_incident(state, incident_id)?;
    let fallback_evidence_refs = findings
        .iter()
        .flat_map(|finding| finding.evidence_refs().iter().cloned())
        .collect::<Vec<_>>();
    let mut views = state
        .read
        .graph_views
        .iter()
        .filter(|view| {
            matches!(&view.filters.scope, GraphScope::Incident(scope_id) if scope_id == incident_id)
        })
        .collect::<Vec<_>>();

    if views.is_empty() && !incident.graph_path_refs().is_empty() {
        views = state
            .read
            .graph_views
            .iter()
            .filter(|view| {
                view.paths
                    .iter()
                    .any(|path| incident.graph_path_refs().contains(&path.path_id))
            })
            .collect::<Vec<_>>();
    }

    let mut snapshots = Vec::new();
    for view in views.into_iter().take(3) {
        if let Some(snapshot) =
            graph_snapshot_from_view(view, incident_id, &fallback_evidence_refs)?
        {
            snapshots.push(snapshot);
        }
    }
    Ok(snapshots)
}

fn graph_snapshot_from_view(
    view: &GraphViewModel,
    incident_id: &IncidentId,
    fallback_evidence_refs: &[EvidenceId],
) -> CommandResult<Option<GraphSnapshot>> {
    export_safe_graph_snapshot_from_view(
        view,
        GraphScope::Incident(incident_id.clone()),
        fallback_evidence_refs,
        "report snapshot uses redacted GraphViewModel data only",
    )
}

pub(crate) fn export_safe_graph_snapshot_from_view(
    view: &GraphViewModel,
    scope: GraphScope,
    fallback_evidence_refs: &[EvidenceId],
    default_note: &str,
) -> CommandResult<Option<GraphSnapshot>> {
    capability_export_safe_graph_snapshot_from_view(
        view,
        scope,
        fallback_evidence_refs,
        default_note,
    )
    .map_err(graph_snapshot_contract_error)
}

fn push_unique_string(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn push_unique_finding_id(values: &mut Vec<FindingId>, value: FindingId) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn push_unique_evidence_id(values: &mut Vec<EvidenceId>, value: EvidenceId) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn validate_response_plan_source(
    state: &MutationCommandState,
    source: &ResponsePlanSource,
) -> CommandResult<()> {
    match source {
        ResponsePlanSource::Finding(id) => {
            if state
                .read
                .findings
                .items
                .iter()
                .any(|finding| finding.id() == id)
            {
                Ok(())
            } else {
                Err(not_found_error(
                    "finding",
                    json!({ "finding_id": id.to_string() }),
                    &TraceId::new_v4(),
                ))
            }
        }
        ResponsePlanSource::Alert(id) => {
            if state.read.alerts.items.iter().any(|alert| alert.id() == id) {
                Ok(())
            } else {
                Err(not_found_error(
                    "alert",
                    json!({ "alert_id": id.to_string() }),
                    &TraceId::new_v4(),
                ))
            }
        }
        ResponsePlanSource::Incident(id) => {
            if state
                .read
                .incidents
                .items
                .iter()
                .any(|incident| incident.id() == id)
            {
                Ok(())
            } else {
                Err(not_found_error(
                    "incident",
                    json!({ "incident_id": id.to_string() }),
                    &TraceId::new_v4(),
                ))
            }
        }
        ResponsePlanSource::GraphPath(id) => {
            if graph_path_exists_in_read_state(state, id) {
                Ok(())
            } else {
                Err(not_found_error(
                    "graph_path",
                    json!({ "graph_path_id": id.to_string() }),
                    &TraceId::new_v4(),
                ))
            }
        }
    }
}

fn response_source_target(source: &ResponsePlanSource) -> String {
    match source {
        ResponsePlanSource::Finding(id) => format!("finding:{id}"),
        ResponsePlanSource::Alert(id) => format!("alert:{id}"),
        ResponsePlanSource::Incident(id) => format!("incident:{id}"),
        ResponsePlanSource::GraphPath(id) => format!("graph_path:{id}"),
    }
}

fn register_tauri_mutation_permissions(resolver: &mut PermissionResolver) -> CommandResult<()> {
    for (command, key, category, risk) in [
        (
            ENABLE_PLUGIN,
            "system.plugin_lifecycle",
            PermissionCategory::SystemAccess,
            PermissionRiskLevel::Low,
        ),
        (
            DISABLE_PLUGIN,
            "system.plugin_lifecycle",
            PermissionCategory::SystemAccess,
            PermissionRiskLevel::Low,
        ),
        (
            RESTART_PLUGIN,
            "system.plugin_lifecycle",
            PermissionCategory::SystemAccess,
            PermissionRiskLevel::Low,
        ),
        (
            SUPPRESS_FINDING,
            "data.security_case.write",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            DISMISS_FINDING,
            "data.security_case.write",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            ESCALATE_ALERT,
            "data.security_case.write",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            UPDATE_INCIDENT_STATUS,
            "data.security_case.write",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            CREATE_RESPONSE_PLAN,
            "response.plan.write",
            PermissionCategory::ResponseAccess,
            PermissionRiskLevel::Low,
        ),
        (
            APPROVE_RESPONSE_ACTION,
            "response.approval.write",
            PermissionCategory::ResponseAccess,
            PermissionRiskLevel::Medium,
        ),
        (
            REJECT_RESPONSE_ACTION,
            "response.approval.write",
            PermissionCategory::ResponseAccess,
            PermissionRiskLevel::Medium,
        ),
        (
            ROLLBACK_RESPONSE_ACTION,
            "response.rollback.write",
            PermissionCategory::ResponseAccess,
            PermissionRiskLevel::Medium,
        ),
        (
            GENERATE_INCIDENT_REPORT,
            "report.generate.write",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            EXPORT_REPORT,
            "export.report.write",
            PermissionCategory::ExportAccess,
            PermissionRiskLevel::High,
        ),
        (
            CONFIRM_PORTABLE_CAPTURE_IMPORT,
            "data.network_metadata.import",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            CONFIRM_METADATA_WATCH_SOURCE,
            "data.metadata_watch.write",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            UPDATE_METADATA_WATCH_SOURCE,
            "data.metadata_watch.write",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            TICK_METADATA_WATCH_CONTROLLER,
            "data.metadata_watch.write",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            UPDATE_METADATA_SAMPLING_LOOP,
            "data.metadata_watch.write",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            RUN_METADATA_SAMPLING_LOOP,
            "data.metadata_watch.write",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            PREVIEW_NATIVE_SAMPLER_ACTIVATION,
            "data.native_sampler.runtime",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            APPLY_NATIVE_SAMPLER_RUNTIME_ACTION,
            "data.native_sampler.runtime",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        ),
        (
            APPLY_RUNTIME_PROFILE,
            "settings.runtime.write",
            PermissionCategory::PolicyAccess,
            PermissionRiskLevel::Medium,
        ),
        (
            UPDATE_PRIVACY_POLICY,
            "settings.privacy.write",
            PermissionCategory::PolicyAccess,
            PermissionRiskLevel::High,
        ),
        (
            UPDATE_RESPONSE_POLICY,
            "settings.response.write",
            PermissionCategory::PolicyAccess,
            PermissionRiskLevel::High,
        ),
        (
            ENABLE_FORENSIC_MODE,
            "settings.forensic.write",
            PermissionCategory::PolicyAccess,
            PermissionRiskLevel::High,
        ),
        (
            DISABLE_FORENSIC_MODE,
            "settings.forensic.write",
            PermissionCategory::PolicyAccess,
            PermissionRiskLevel::High,
        ),
    ] {
        let descriptor = PermissionDescriptor::new(
            permission_key(key)?,
            category,
            risk,
            format!("allow Tauri mutation command {command}"),
        )
        .map_err(contract_error)?;
        resolver.register_descriptor(&descriptor);
        resolver.grant(
            PermissionSubject::TauriCommand(command.to_string()),
            descriptor.permission,
        );
    }
    Ok(())
}

fn settings_permission_key(command: &str, change_kind: &SettingsChangeKind) -> &'static str {
    if matches!(command, ENABLE_FORENSIC_MODE | DISABLE_FORENSIC_MODE) {
        return "settings.forensic.write";
    }

    match change_kind {
        SettingsChangeKind::RuntimeProfile => "settings.runtime.write",
        SettingsChangeKind::PrivacyPolicy => "settings.privacy.write",
        SettingsChangeKind::ResponsePolicy => "settings.response.write",
        SettingsChangeKind::CaptureSettings
        | SettingsChangeKind::AttributionSettings
        | SettingsChangeKind::IntelligenceSettings
        | SettingsChangeKind::ApiSecuritySettings
        | SettingsChangeKind::WafIntegrationSettings
        | SettingsChangeKind::ReportExportPolicy
        | SettingsChangeKind::RetentionPolicy
        | SettingsChangeKind::ServiceStatusSettings => "settings.runtime.write",
    }
}

fn permission_key(value: &str) -> CommandResult<PermissionKey> {
    PermissionKey::new(value).map_err(contract_error)
}

fn actor_for_request(state: &MutationCommandState, requested: Option<&str>) -> String {
    requested
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&state.actor_redacted)
        .to_string()
}

fn require_reason(reason_redacted: &str) -> CommandResult<()> {
    if reason_redacted.trim().is_empty() {
        return Err(CoreError::validation_failure("mutation reason is required")
            .with_trace_id(TraceId::new_v4())
            .with_redacted_details(json!({ "field": "reason_redacted" })));
    }
    Ok(())
}

fn audit_decision_for_permission(decision: &PermissionDecision) -> AuditDecision {
    match decision.decision {
        PermissionDecisionKind::Allow => AuditDecision::Allowed,
        PermissionDecisionKind::NeedsApproval => AuditDecision::NeedsApproval,
        PermissionDecisionKind::Deny | PermissionDecisionKind::Unavailable => AuditDecision::Denied,
        PermissionDecisionKind::NotApplicable => AuditDecision::NotApplicable,
    }
}

fn permission_error(decision: PermissionDecision, trace_id: &TraceId) -> CoreError {
    let code = match decision.decision {
        PermissionDecisionKind::NeedsApproval => ErrorCode::ResponseRequiresApproval,
        PermissionDecisionKind::Unavailable => ErrorCode::ServiceUnavailable,
        PermissionDecisionKind::Deny | PermissionDecisionKind::NotApplicable => {
            if decision.policy_evaluated {
                ErrorCode::PolicyDenial
            } else {
                ErrorCode::PermissionDenied
            }
        }
        PermissionDecisionKind::Allow => ErrorCode::InternalError,
    };

    CoreError::new(code, "mutation denied by permission or policy")
        .with_trace_id(trace_id.clone())
        .with_redacted_details(json!({
            "decision": decision.decision,
            "reasons": decision.reasons,
            "audit_required": decision.audit_requirement.audit_required,
            "approval_required": decision.audit_requirement.approval_required,
            "rollback_required": decision.audit_requirement.rollback_required
        }))
}

fn policy_error(message: impl Into<String>, details: Value, trace_id: &TraceId) -> CoreError {
    CoreError::new(ErrorCode::PolicyDenial, message)
        .with_trace_id(trace_id.clone())
        .with_redacted_details(details)
}

fn not_found_error(resource: &'static str, details: Value, trace_id: &TraceId) -> CoreError {
    CoreError::new(
        ErrorCode::InvalidRequest,
        format!("{resource} was not found"),
    )
    .with_trace_id(trace_id.clone())
    .with_redacted_details(json!({ "resource": resource, "lookup": details }))
}

fn contract_error(error: impl ToString) -> CoreError {
    CoreError::new(ErrorCode::ValidationFailure, "contract validation failed")
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn metadata_watch_error(error: ContinuousMetadataWatchError) -> CoreError {
    CoreError::new(
        ErrorCode::ValidationFailure,
        "metadata watch controller operation failed safety validation",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn portable_reader_error(error: PortableSourceReaderError) -> CoreError {
    CoreError::new(
        ErrorCode::ValidationFailure,
        "portable metadata reader operation failed safety validation",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn graph_snapshot_contract_error(error: GraphAnalyticsError) -> CoreError {
    let error_code = match &error {
        GraphAnalyticsError::PrivacyMarker { .. } => ErrorCode::PrivacyPolicyViolation,
        GraphAnalyticsError::InvalidRequest(reason)
            if reason.contains("redaction") || reason.contains("detail references") =>
        {
            ErrorCode::PrivacyPolicyViolation
        }
        _ => ErrorCode::ValidationFailure,
    };
    CoreError::new(error_code, "graph snapshot export validation failed")
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn report_generation_error(error: ReportGenerationError) -> CoreError {
    let error_code = if error.is_policy_or_privacy_denial() {
        ErrorCode::PrivacyPolicyViolation
    } else {
        ErrorCode::ValidationFailure
    };
    CoreError::new(error_code, "report generation or export validation failed")
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn response_planning_error(error: ResponsePlanningError) -> CoreError {
    CoreError::new(ErrorCode::ValidationFailure, "response planning failed")
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn response_planning_runtime_error(error: impl ToString, trace_id: &TraceId) -> CoreError {
    CoreError::new(
        ErrorCode::ValidationFailure,
        "response planning runtime dispatch failed",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(trace_id.clone())
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn export_history_error(error: ExportHistoryError) -> CoreError {
    CoreError::new(
        ErrorCode::PrivacyPolicyViolation,
        "export history validation failed",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn export_history_storage_error(error: ExportHistoryError, trace_id: &TraceId) -> CoreError {
    CoreError::new(
        ErrorCode::InternalError,
        "export history storage write failed",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(trace_id.clone())
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use sentinel_capabilities::ResponsePolicyRule;
    use sentinel_contracts::{
        Alert, EntityId, EntityRef, EntityType, EvidenceId, FindingExplanation, ForensicScopeKind,
        GraphEdgeType, GraphEdgeViewModel, GraphNodeType, GraphNodeViewModel,
        GraphRedactionSummary, GraphType, LlmAlertStoryDraft, LlmAlertStoryId,
        LlmAlertStoryProvider, LlmAlertStoryRecord, LlmAttackTechniqueRef, PrivacyClass,
        QualityScore, RedactedLabel, ReportSectionType, ResponseMode, RiskEventId,
        SecuritySeverity,
    };
    use sentinel_storage::{
        logical_store_migration, InMemoryMigrationAuditSink, MigrationRunner, SchemaMetadata,
    };
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn public_native_runtime_command_rejects_scheduler_only_samples() {
        let mut state = MutationCommandState::bootstrap().expect("state");
        let result = state.apply_native_sampler_runtime_action(NativeSamplerRuntimeActionRequest {
            sampler_id: "native_health_probe_sampler".to_string(),
            action: NativeSamplerRuntimeAction::ScheduledSample,
            explicit_user_action: false,
            enable_interval_sampling: false,
            max_records_per_sample: 8,
            max_bytes_per_sample: 8_192,
            timeout_millis: 1_000,
            reason_redacted: "scheduler only sample".to_string(),
        });
        assert!(result.is_err());
        assert!(state.read.native_sampler_runtime_batches.is_empty());
    }

    #[test]
    fn plugin_lifecycle_mutations_are_permissioned_and_audited() {
        let mut state = MutationCommandState::bootstrap().expect("state");
        let plugin_id = state.read.plugin_registry.list()[0].plugin_id.clone();

        let result = disable_plugin(
            &mut state,
            PluginLifecycleRequest {
                plugin_id: plugin_id.clone(),
                reason_redacted: "local troubleshooting".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("disable plugin");

        assert_eq!(result.result.plugin_id, plugin_id);
        assert_eq!(result.result.state, PluginLifecycleMutationState::Disabled);
        assert!(!result.result.applied_to_runtime);
        assert_eq!(state.audit_records().len(), 1);
        assert_eq!(
            state.audit_records()[0].category,
            AuditCategory::PluginLifecycle
        );
        assert_eq!(
            result.permission_decision.decision,
            PermissionDecisionKind::Allow
        );
    }

    #[test]
    fn metadata_watch_preview_confirm_and_lifecycle_are_bounded() {
        let mut state = MutationCommandState::bootstrap().expect("state");

        let preview = preview_metadata_watch_source(
            &mut state,
            metadata_watch_preview_request(
                MetadataWatchSourceKind::LocalhostProxyContinuousDrain,
                MetadataParserFamily::LocalProxyMetadata,
                MetadataSamplingMode::ContinuousDrain,
            ),
        )
        .expect("preview metadata watch source");
        assert!(state.read.metadata_watch_sources.items.is_empty());

        let confirmed = confirm_metadata_watch_source(
            &mut state,
            MetadataWatchSourceConfirmation {
                preview_id: preview.preview_id.clone(),
                user_confirmed: true,
                reason_redacted: "operator_confirmed".to_string(),
                requested_by_redacted: Some("local_user".to_string()),
            },
        )
        .expect("confirm metadata watch source");
        let source_id = state.read.metadata_watch_sources.items[0].source_id.clone();

        assert_eq!(confirmed.result.enabled_source_count, 1);
        assert_eq!(state.read.metadata_watch_sources.items.len(), 1);
        assert_eq!(
            state.read.metadata_watch_sources.items[0].source_kind,
            MetadataWatchSourceKind::LocalhostProxyContinuousDrain
        );

        let paused = update_metadata_watch_source(
            &mut state,
            MetadataWatchLifecycleRequest {
                source_id: source_id.clone(),
                action: sentinel_contracts::MetadataWatchLifecycleAction::Pause,
                reason_redacted: "operator_pause".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("pause watch source");
        assert_eq!(paused.result.paused_source_count, 1);

        let revoked = update_metadata_watch_source(
            &mut state,
            MetadataWatchLifecycleRequest {
                source_id,
                action: sentinel_contracts::MetadataWatchLifecycleAction::Revoke,
                reason_redacted: "operator_revoke".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("revoke watch source");
        assert_eq!(revoked.result.revoked_source_count, 1);

        let serialized = serde_json::to_string(&state.read.metadata_watch_sources.items)
            .expect("serialize watch sources");
        for forbidden in ["C:\\Users", "https://", "session_token", "alice@example"] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[test]
    fn metadata_watch_tick_degrades_unavailable_portable_tailers_without_sampling() {
        let mut state = MutationCommandState::bootstrap().expect("state");
        let preview = preview_metadata_watch_source(
            &mut state,
            metadata_watch_preview_request(
                MetadataWatchSourceKind::TailedWebLog,
                MetadataParserFamily::WebAccessLog,
                MetadataSamplingMode::IntervalTick,
            ),
        )
        .expect("preview tailer");
        confirm_metadata_watch_source(
            &mut state,
            MetadataWatchSourceConfirmation {
                preview_id: preview.preview_id.clone(),
                user_confirmed: true,
                reason_redacted: "operator_confirmed".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("confirm tailer");

        let receipt = tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: Some(preview.preview_id),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("tick watch controller");

        assert!(receipt.result.batches.is_empty());
        assert!(receipt.result.controller_status.triage_advisory_only);
        assert!(!receipt.result.controller_status.automatic_llm_calls);
        assert!(!receipt.result.controller_status.response_execution);
        assert_eq!(
            receipt.result.source_statuses[0].health_state,
            MetadataSourceHealthState::SourceUnavailable
        );
        assert_eq!(state.read.metadata_sampling_batches.items.len(), 0);
    }

    #[test]
    fn metadata_sampling_loop_master_toggle_pause_resume_and_scheduling_work() {
        let temp = TestTempDir::new("sampling_loop_toggle");
        std::fs::write(temp.path().join("loop.har"), har_reader_fixture()).expect("write loop har");
        let mut state = MutationCommandState::bootstrap().expect("state");
        confirm_reader_source(
            &mut state,
            MetadataWatchSourceKind::WatchedHarFolder,
            MetadataParserFamily::Har,
            MetadataSamplingMode::IntervalTick,
            temp.path(),
        );

        let disabled = run_metadata_sampling_loop(
            &mut state,
            MetadataSamplingLoopRunRequest {
                max_sources: 8,
                reason_redacted: "operator_cycle".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("disabled loop run");
        assert!(disabled.result.batches.is_empty());
        assert!(!disabled.result.controller_status.loop_enabled);

        let enabled = update_metadata_sampling_loop(
            &mut state,
            loop_control_request(MetadataSamplingLoopAction::Enable),
        )
        .expect("enable sampling loop");
        assert_eq!(
            enabled.result.loop_state,
            MetadataSamplingLoopState::Running
        );
        assert!(enabled.result.loop_enabled);

        let scheduled = run_metadata_sampling_loop(
            &mut state,
            MetadataSamplingLoopRunRequest {
                max_sources: 8,
                reason_redacted: "operator_cycle".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("scheduled loop run");
        assert_eq!(scheduled.result.batches.len(), 1);
        assert_eq!(scheduled.result.controller_status.scheduled_source_count, 1);
        assert!(scheduled.result.controller_status.latest_batch_id.is_some());
        assert!(scheduled
            .result
            .batches
            .iter()
            .all(|batch| !batch.automatic_llm_calls && !batch.response_execution));
        assert!(state.read.llm_alert_stories.items.is_empty());
        assert!(state.response_actions().is_empty());

        let paused = update_metadata_sampling_loop(
            &mut state,
            loop_control_request(MetadataSamplingLoopAction::PauseAll),
        )
        .expect("pause sampling loop");
        assert_eq!(paused.result.loop_state, MetadataSamplingLoopState::Paused);
        let paused_run = run_metadata_sampling_loop(
            &mut state,
            MetadataSamplingLoopRunRequest {
                max_sources: 8,
                reason_redacted: "operator_cycle".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("paused loop run");
        assert!(paused_run.result.batches.is_empty());
        assert_eq!(
            paused_run.result.controller_status.scheduled_source_count,
            0
        );

        let resumed = update_metadata_sampling_loop(
            &mut state,
            loop_control_request(MetadataSamplingLoopAction::ResumeAll),
        )
        .expect("resume sampling loop");
        assert_eq!(
            resumed.result.loop_state,
            MetadataSamplingLoopState::Running
        );
        let disabled = update_metadata_sampling_loop(
            &mut state,
            loop_control_request(MetadataSamplingLoopAction::Disable),
        )
        .expect("disable sampling loop");
        assert_eq!(
            disabled.result.loop_state,
            MetadataSamplingLoopState::Disabled
        );
        assert!(!disabled.result.loop_enabled);
        assert_reader_surfaces_redacted(&state, &["loop.har", "token=secret", "https://"]);
    }

    #[test]
    fn metadata_sampling_loop_bounds_sources_and_marks_backpressure() {
        let temp_a = TestTempDir::new("sampling_loop_backpressure_a");
        let temp_b = TestTempDir::new("sampling_loop_backpressure_b");
        std::fs::write(temp_a.path().join("a.har"), har_reader_fixture()).expect("write a");
        std::fs::write(temp_b.path().join("b.har"), har_reader_fixture()).expect("write b");
        let mut state = MutationCommandState::bootstrap().expect("state");
        confirm_reader_source(
            &mut state,
            MetadataWatchSourceKind::WatchedHarFolder,
            MetadataParserFamily::Har,
            MetadataSamplingMode::IntervalTick,
            temp_a.path(),
        );
        confirm_reader_source(
            &mut state,
            MetadataWatchSourceKind::WatchedHarFolder,
            MetadataParserFamily::Har,
            MetadataSamplingMode::IntervalTick,
            temp_b.path(),
        );

        update_metadata_sampling_loop(
            &mut state,
            MetadataSamplingLoopControlRequest {
                max_sources_per_cycle: 2,
                max_concurrent_sources: 1,
                ..loop_control_request(MetadataSamplingLoopAction::Enable)
            },
        )
        .expect("enable bounded loop");
        let receipt = run_metadata_sampling_loop(
            &mut state,
            MetadataSamplingLoopRunRequest {
                max_sources: 2,
                reason_redacted: "operator_cycle".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("bounded loop cycle");

        assert_eq!(receipt.result.batches.len(), 1);
        assert_eq!(receipt.result.controller_status.scheduled_source_count, 1);
        assert!(receipt.result.source_statuses.iter().any(|source| {
            source.health_state == MetadataSourceHealthState::Backpressure
                && source.error_category.as_deref() == Some("backpressure")
        }));
        assert!(!receipt.result.controller_status.automatic_llm_calls);
        assert!(!receipt.result.controller_status.response_execution);
        assert_reader_surfaces_redacted(&state, &["a.har", "b.har", "token=secret"]);
    }

    #[test]
    fn metadata_sampling_loop_proxy_unavailable_degrades_without_auto_drain() {
        let mut state = MutationCommandState::bootstrap().expect("state");
        let preview = preview_metadata_watch_source(
            &mut state,
            metadata_watch_preview_request(
                MetadataWatchSourceKind::LocalhostProxyContinuousDrain,
                MetadataParserFamily::LocalProxyMetadata,
                MetadataSamplingMode::ContinuousDrain,
            ),
        )
        .expect("preview proxy source");
        confirm_metadata_watch_source(
            &mut state,
            MetadataWatchSourceConfirmation {
                preview_id: preview.preview_id.clone(),
                user_confirmed: true,
                reason_redacted: "operator_confirmed".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("confirm proxy source");
        update_metadata_sampling_loop(
            &mut state,
            loop_control_request(MetadataSamplingLoopAction::Enable),
        )
        .expect("enable loop");

        let receipt = run_metadata_sampling_loop(
            &mut state,
            MetadataSamplingLoopRunRequest {
                max_sources: 1,
                reason_redacted: "operator_cycle".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("proxy unavailable loop cycle");
        assert!(receipt.result.batches.is_empty());
        let proxy_source = receipt
            .result
            .source_statuses
            .iter()
            .find(|source| source.source_id == preview.preview_id)
            .expect("proxy source status");
        assert_eq!(
            proxy_source.health_state,
            MetadataSourceHealthState::Degraded
        );
        assert_eq!(
            proxy_source.error_category.as_deref(),
            Some("source_unavailable")
        );

        let manual = state
            .drain_local_metadata_proxy()
            .expect("manual drain still works");
        assert_eq!(manual.state, LocalProxyMetadataProviderStateKind::Stopped);
        assert!(state.read.llm_alert_stories.items.is_empty());
        assert!(state.response_actions().is_empty());
        assert_reader_surfaces_redacted(&state, &["session_token", "authorization", "https://"]);
    }

    #[test]
    fn portable_watch_folder_reader_processes_har_and_jsonl_without_path_exposure() {
        let temp = TestTempDir::new("watch_folder");
        let har_path = temp.path().join("watch.har");
        let jsonl_path = temp.path().join("network.jsonl");
        std::fs::write(&har_path, har_reader_fixture()).expect("write har fixture");
        std::fs::write(&jsonl_path, network_jsonl_reader_fixture()).expect("write jsonl fixture");
        let mut state = MutationCommandState::bootstrap().expect("state");
        confirm_reader_source(
            &mut state,
            MetadataWatchSourceKind::WatchedHarFolder,
            MetadataParserFamily::Har,
            MetadataSamplingMode::IntervalTick,
            temp.path(),
        );
        confirm_reader_source(
            &mut state,
            MetadataWatchSourceKind::WatchedJsonlFolder,
            MetadataParserFamily::JsonlNetwork,
            MetadataSamplingMode::IntervalTick,
            temp.path(),
        );

        let receipt = tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: None,
                max_sources: 2,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("tick readers");

        assert_eq!(receipt.result.batches.len(), 2);
        assert!(state.read.flows.items.len() >= 2);
        assert!(state.read.http_metadata.items.len() >= 2);
        assert!(!state.read.fusion_summaries.is_empty());
        assert!(receipt
            .result
            .batches
            .iter()
            .all(|batch| !batch.automatic_llm_calls && !batch.response_execution));
        assert!(state.read.llm_alert_stories.items.is_empty());
        assert!(state.response_actions().is_empty());
        assert_reader_surfaces_redacted(&state, &["watch.har", "network.jsonl", "token=secret"]);
    }

    #[test]
    fn portable_watch_folder_reader_rejects_oversized_candidates() {
        let temp = TestTempDir::new("watch_oversized");
        std::fs::write(temp.path().join("oversized.har"), "x".repeat(70_000))
            .expect("write oversized fixture");
        let mut state = MutationCommandState::bootstrap().expect("state");
        let source_id = confirm_reader_source(
            &mut state,
            MetadataWatchSourceKind::WatchedHarFolder,
            MetadataParserFamily::Har,
            MetadataSamplingMode::IntervalTick,
            temp.path(),
        );

        let receipt = tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: Some(source_id),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("tick oversized reader");

        assert_eq!(receipt.result.batches.len(), 1);
        assert_eq!(
            receipt.result.source_statuses[0].health_state,
            MetadataSourceHealthState::OversizedInputSkipped
        );
        assert!(state.read.flows.items.is_empty());
        let temp_path = temp.path_string();
        assert_reader_surfaces_redacted(&state, &["oversized.har", temp_path.as_str()]);
    }

    #[test]
    fn portable_log_tail_reader_reads_complete_appended_lines_only() {
        let temp = TestTempDir::new("log_tail");
        let log_path = temp.path().join("access.log");
        std::fs::write(&log_path, web_access_line("/initial?token=secret"))
            .expect("write initial log");
        let mut state = MutationCommandState::bootstrap().expect("state");
        let source_id = confirm_reader_source(
            &mut state,
            MetadataWatchSourceKind::TailedWebLog,
            MetadataParserFamily::WebAccessLog,
            MetadataSamplingMode::IntervalTick,
            &log_path,
        );

        tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: Some(source_id.clone()),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("first tail tick");
        let first_flow_count = state.read.flows.items.len();
        assert_eq!(first_flow_count, 1);

        append_to_file(
            &log_path,
            "192.0.2.55 - - [12/Jun/2026:08:01:00 +0000] \"GET https://web.example.test/partial",
        );
        tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: Some(source_id.clone()),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("partial tail tick");
        assert_eq!(state.read.flows.items.len(), first_flow_count);

        append_to_file(
            &log_path,
            "?token=secret HTTP/1.1\" 404 321 \"-\" \"curl/8\"\n",
        );
        tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: Some(source_id),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("complete appended tail tick");
        assert_eq!(state.read.flows.items.len(), first_flow_count + 1);
        assert_reader_surfaces_redacted(&state, &["access.log", "token=secret", "192.0.2.55"]);
    }

    #[test]
    fn portable_log_tail_reader_handles_rotation_and_truncation() {
        let temp = TestTempDir::new("log_rotation");
        let log_path = temp.path().join("rotating.log");
        std::fs::write(&log_path, web_access_line("/before-rotation")).expect("write initial log");
        let mut state = MutationCommandState::bootstrap().expect("state");
        let source_id = confirm_reader_source(
            &mut state,
            MetadataWatchSourceKind::TailedWebLog,
            MetadataParserFamily::WebAccessLog,
            MetadataSamplingMode::IntervalTick,
            &log_path,
        );
        tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: Some(source_id.clone()),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("first tick");

        std::fs::write(&log_path, web_access_line("/after-rotation")).expect("rotate log");
        let rotated = tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: Some(source_id.clone()),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("rotation tick");
        assert_eq!(
            rotated.result.source_statuses[0].health_state,
            MetadataSourceHealthState::RotationDetected
        );

        std::fs::write(&log_path, "").expect("truncate log");
        let truncated = tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: Some(source_id),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("truncation tick");
        assert_eq!(
            truncated.result.source_statuses[0].health_state,
            MetadataSourceHealthState::CursorResetRequired
        );
    }

    #[test]
    fn portable_jsonl_append_reader_rejects_malformed_and_high_risk_entries() {
        let temp = TestTempDir::new("jsonl_append");
        let jsonl_path = temp.path().join("saas.jsonl");
        std::fs::write(&jsonl_path, "{not-json}\n").expect("write malformed jsonl");
        let mut state = MutationCommandState::bootstrap().expect("state");
        let source_id = confirm_reader_source(
            &mut state,
            MetadataWatchSourceKind::TailedSaasCloudJsonl,
            MetadataParserFamily::SaasCloudJsonl,
            MetadataSamplingMode::IntervalTick,
            &jsonl_path,
        );

        let malformed = tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: Some(source_id.clone()),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("malformed tick");
        assert_eq!(
            malformed.result.source_statuses[0].health_state,
            MetadataSourceHealthState::ParserError
        );
        assert!(state.read.portable_capture_sources.is_empty());

        append_to_file(
            &jsonl_path,
            "{\"timestamp\":\"2026-06-12T07:00:00Z\",\"provider_category\":\"object_storage\",\"headers\":{\"authorization\":\"Bearer secret\"}}\n",
        );
        let high_risk = tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: Some(source_id.clone()),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("high risk tick");
        assert_eq!(
            high_risk.result.source_statuses[0].health_state,
            MetadataSourceHealthState::OversizedInputSkipped
        );

        append_to_file(&jsonl_path, &saas_jsonl_reader_line());
        let accepted = tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: Some(source_id),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("accepted jsonl tick");
        assert_eq!(
            accepted.result.source_statuses[0].health_state,
            MetadataSourceHealthState::Active
        );
        assert_eq!(state.read.portable_capture_sources.len(), 1);
        assert_reader_surfaces_redacted(&state, &["saas.jsonl", "authorization", "Bearer secret"]);
    }

    #[test]
    fn portable_reader_cursor_store_prevents_duplicate_ingest_after_restart() {
        let temp = TestTempDir::new("restart_resume");
        std::fs::write(
            temp.path().join("network.jsonl"),
            network_jsonl_reader_fixture(),
        )
        .expect("write jsonl fixture");
        let mut state = MutationCommandState::bootstrap().expect("state");
        let source_id = confirm_reader_source(
            &mut state,
            MetadataWatchSourceKind::WatchedJsonlFolder,
            MetadataParserFamily::JsonlNetwork,
            MetadataSamplingMode::IntervalTick,
            temp.path(),
        );
        tick_metadata_watch_controller(
            &mut state,
            MetadataSamplingTickRequest {
                source_id: Some(source_id.clone()),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("first tick");
        let flow_count = state.read.flows.items.len();
        let cursor_records = state.metadata_reader_runtime.cursor_records();
        let serialized_cursors = serde_json::to_string(&cursor_records).expect("serialize cursors");
        let temp_path = temp.path_string();
        for forbidden in ["network.jsonl", temp_path.as_str(), "token=secret"] {
            assert!(!serialized_cursors.contains(forbidden));
        }

        let read = state.read.clone();
        let mut restarted = MutationCommandState::from_read_state(read).expect("restart state");
        restarted.metadata_reader_runtime =
            PortableSourceReaderRuntime::from_cursor_records(cursor_records);
        let source = restarted
            .read
            .metadata_watch_sources
            .items
            .iter()
            .find(|source| source.source_id == source_id)
            .cloned()
            .expect("source after restart");
        restarted
            .metadata_reader_runtime
            .attach_existing_source(&source, temp.path_string())
            .expect("reattach reader after restart");

        let receipt = tick_metadata_watch_controller(
            &mut restarted,
            MetadataSamplingTickRequest {
                source_id: Some(source_id),
                max_sources: 1,
                reason_redacted: "operator_tick".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("restart tick");
        assert!(receipt.result.batches.is_empty());
        assert_eq!(restarted.read.flows.items.len(), flow_count);
    }

    #[test]
    fn finding_alert_and_incident_mutations_update_logical_models() {
        let read = sample_read_state();
        let finding_id = read.findings.items[0].id().clone();
        let alert_id = read.alerts.items[0].id().clone();
        let incident_id = read.incidents.items[0].id().clone();
        let mut state = MutationCommandState::from_read_state(read).expect("state");

        let finding = suppress_finding(
            &mut state,
            FindingStateMutationRequest {
                finding_id,
                reason_redacted: "known maintenance signal".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("suppress finding");
        let alert = escalate_alert(
            &mut state,
            EscalateAlertRequest {
                alert_id,
                reason_redacted: "human escalation".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("escalate alert");
        let incident = update_incident_status(
            &mut state,
            IncidentStatusMutationRequest {
                incident_id,
                state: IncidentState::InProgress,
                reason_redacted: "active investigation".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("update incident");

        assert_eq!(finding.result.applied_state, FindingState::Suppressed);
        assert_eq!(alert.result.alert.state(), &AlertState::EscalatedToIncident);
        assert!(alert.result.routed_to_incident_stage);
        assert_eq!(incident.result.applied_state, IncidentState::InProgress);
        assert_eq!(state.audit_records().len(), 3);
    }

    #[test]
    fn response_plan_creation_requires_policy_and_does_not_execute() {
        let read = sample_read_state();
        let incident_id = read.incidents.items[0].id().clone();
        let mut state = MutationCommandState::from_read_state(read).expect("state");

        let receipt = create_response_plan(
            &mut state,
            CreateResponsePlanRequest {
                source: ResponsePlanSource::Incident(incident_id),
                reason_redacted: "recommend containment options".to_string(),
                created_by_redacted: None,
            },
        )
        .expect("response plan");

        assert!(receipt.result.plan.recommended_actions.len() >= 3);
        assert_eq!(
            receipt.result.actions.len(),
            receipt.result.plan.recommended_actions.len()
        );
        assert_eq!(
            receipt.result.plan.policy_decisions.len(),
            receipt.result.plan.recommended_actions.len()
        );
        assert!(receipt.result.plan.approval_required);
        assert!(receipt
            .result
            .plan
            .audit_requirements
            .iter()
            .any(|requirement| requirement == "response.runtime.static_internal.process_batch"));
        assert!(receipt
            .result
            .plan
            .policy_decisions
            .iter()
            .any(|decision| matches!(decision.level, ResponseLevel::ApprovalRequired)));
        assert!(receipt
            .result
            .plan
            .recommended_actions
            .iter()
            .all(|action| {
                action.action_id.is_some()
                    && action.rollback_available
                    && action.approval_state.is_some()
            }));
        assert!(!receipt.result.execution_started);
        assert!(receipt
            .result
            .actions
            .iter()
            .all(|action| action.execution_disabled_in_replay));
        assert!(receipt.rollback.is_some());
        assert_eq!(
            state.response_actions().len(),
            receipt.result.plan.recommended_actions.len()
        );
        assert!(state.audit_records().iter().any(|event| {
            event.action_type == AuditActionType::ResponsePlanCreated
                && event.rollback_ref.is_some()
        }));
    }

    #[test]
    fn finding_response_plan_uses_static_runtime_path() {
        let read = sample_read_state();
        let finding_id = read.findings.items[0].id().clone();
        let mut state = MutationCommandState::from_read_state(read).expect("state");

        let receipt = create_response_plan(
            &mut state,
            CreateResponsePlanRequest {
                source: ResponsePlanSource::Finding(finding_id.clone()),
                reason_redacted: "recommend finding triage".to_string(),
                created_by_redacted: None,
            },
        )
        .expect("response plan");

        assert!(matches!(
            &receipt.result.plan.source,
            ResponsePlanSource::Finding(id) if id == &finding_id
        ));
        assert!(receipt
            .result
            .plan
            .audit_requirements
            .iter()
            .any(|requirement| requirement == "response.runtime.static_internal.process_batch"));
        assert!(!receipt.result.execution_started);
        assert!(receipt
            .result
            .actions
            .iter()
            .all(|action| action.execution_disabled_in_replay));
    }

    #[test]
    fn custom_response_policy_is_staged_for_static_runtime_path() {
        let mut read = auto_eligible_finding_read_state();
        read.runtime_profile.response_policy = ResponsePolicy::auto_containment_lite();
        let finding_id = read.findings.items[0].id().clone();
        let mut state = MutationCommandState::from_read_state(read).expect("state");

        let receipt = create_response_plan(
            &mut state,
            CreateResponsePlanRequest {
                source: ResponsePlanSource::Finding(finding_id.clone()),
                reason_redacted: "allow scoped auto containment candidate".to_string(),
                created_by_redacted: None,
            },
        )
        .expect("response plan");

        assert!(matches!(
            &receipt.result.plan.source,
            ResponsePlanSource::Finding(id) if id == &finding_id
        ));
        assert!(receipt
            .result
            .plan
            .audit_requirements
            .iter()
            .any(|requirement| requirement == "response.runtime.static_internal.process_batch"));
        assert!(receipt
            .result
            .plan
            .policy_decisions
            .iter()
            .any(|decision| decision.level == ResponseLevel::AutoContainmentLite));
        assert!(!receipt.result.execution_started);
        assert!(receipt
            .result
            .actions
            .iter()
            .all(|action| action.execution_disabled_in_replay));
    }

    #[test]
    fn custom_response_policy_rules_use_static_runtime_path() {
        let mut read = auto_eligible_finding_read_state();
        read.runtime_profile.response_policy = ResponsePolicy::auto_containment_lite();
        let finding_id = read.findings.items[0].id().clone();
        let state = MutationCommandState::from_read_state(read).expect("state");
        let source = ResponsePlanSource::Finding(finding_id.clone());
        let mut input = response_planning_input_for_source(&state, &source).expect("input");
        input.policy_rules.push(
            ResponsePolicyRule::new(
                "custom:c2:recommend-only",
                ResponseActionType::MaliciousDestinationAutoBlock,
                ResponseLevel::RecommendOnly,
                "Force destination auto-block candidates to recommendation-only.",
            )
            .expect("policy rule"),
        );

        let output =
            static_response_planning_output(input, &TraceId::new_v4()).expect("static output");

        assert!(output.used_static_runtime);
        assert!(output.response_plans.iter().any(|plan| {
            plan.audit_requirements
                .iter()
                .any(|requirement| requirement == "response.runtime.static_internal.process_batch")
        }));
        let overridden_decisions = output
            .response_plans
            .iter()
            .flat_map(|plan| plan.policy_decisions.iter())
            .filter(|decision| {
                decision
                    .matched_rules
                    .iter()
                    .any(|rule| rule.rule_id == "custom:c2:recommend-only")
            })
            .collect::<Vec<_>>();
        assert!(!overridden_decisions.is_empty());
        assert!(overridden_decisions
            .iter()
            .all(|decision| decision.level == ResponseLevel::RecommendOnly));
    }

    #[test]
    fn approval_and_rejection_do_not_start_execution() {
        let mut state = state_with_response_action();
        let action_id = state.response_actions()[0].action_id.clone();

        let approval = approve_response_action(
            &mut state,
            ResponseApprovalMutationRequest {
                action_id: action_id.clone(),
                actor_redacted: None,
                reason_redacted: Some("approve recommendation only".to_string()),
            },
        )
        .expect("approve action");

        assert!(!approval.result.execution_started);
        assert_eq!(
            approval.result.action.approval_state,
            sentinel_contracts::ApprovalState::Approved
        );
        assert!(state
            .response_results()
            .iter()
            .any(|result| result.action_id == action_id));

        let rejection = reject_response_action(
            &mut state,
            ResponseApprovalMutationRequest {
                action_id,
                actor_redacted: None,
                reason_redacted: Some("reject after review".to_string()),
            },
        )
        .expect("reject action");
        assert!(!rejection.result.execution_started);
        assert_eq!(
            rejection.result.action.approval_state,
            sentinel_contracts::ApprovalState::Rejected
        );
    }

    #[test]
    fn response_approval_records_safe_non_executing_result_evidence() {
        let mut state = state_with_response_action();
        let action_id = state
            .response_actions()
            .iter()
            .find(|action| action.approval_state == sentinel_contracts::ApprovalState::Requested)
            .expect("approval-required response action")
            .action_id
            .clone();
        let before = state.response_results().len();

        let approval = approve_response_action(
            &mut state,
            ResponseApprovalMutationRequest {
                action_id: action_id.clone(),
                actor_redacted: Some("local_operator".to_string()),
                reason_redacted: Some("record disabled execution evidence".to_string()),
            },
        )
        .expect("approve action");

        assert!(!approval.result.execution_started);
        assert_eq!(state.response_results().len(), before + 1);
        let response_result = state
            .response_results()
            .iter()
            .find(|result| result.action_id == action_id)
            .expect("response result");
        assert_safe_disabled_response_result(response_result);
    }

    #[test]
    fn report_export_history_preserves_safe_response_result_refs() {
        let mut state = state_with_response_action();
        let incident_id = state.read_state().incidents.items[0].id().clone();
        let action_id = state
            .response_actions()
            .iter()
            .find(|action| action.approval_state == sentinel_contracts::ApprovalState::Requested)
            .expect("approval-required response action")
            .action_id
            .clone();

        approve_response_action(
            &mut state,
            ResponseApprovalMutationRequest {
                action_id: action_id.clone(),
                actor_redacted: Some("local_operator".to_string()),
                reason_redacted: Some("approve recommendation evidence only".to_string()),
            },
        )
        .expect("approve action");
        let response_result = state
            .response_results()
            .iter()
            .find(|result| result.action_id == action_id)
            .expect("response result")
            .clone();
        assert_safe_disabled_response_result(&response_result);

        let report = generate_incident_report(
            &mut state,
            GenerateIncidentReportRequest {
                incident_id,
                requested_by_redacted: Some("local_operator".to_string()),
                reason_redacted: "prepare response result trace report".to_string(),
            },
        )
        .expect("report")
        .result
        .report;

        assert!(report
            .response_result_refs
            .contains(&response_result.result_id));
        let response_section = report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::ResponseResult)
            .expect("response result section");
        assert!(response_section
            .response_result_refs
            .contains(&response_result.result_id));
        let response_result_id = response_result.result_id.to_string();
        let results = response_section
            .content_redacted
            .get("results")
            .and_then(Value::as_array)
            .expect("response result summaries");
        let summary = results
            .iter()
            .find(|summary| {
                summary.get("response_result_id").and_then(Value::as_str)
                    == Some(response_result_id.as_str())
            })
            .expect("response result summary");
        assert_eq!(
            summary.get("executor").and_then(Value::as_str),
            Some("execution_disabled_recommendation_only")
        );
        assert_eq!(
            summary.get("execution_disabled").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(summary.get("success").and_then(Value::as_bool), Some(false));
        assert_eq!(
            summary.get("rollback_available").and_then(Value::as_bool),
            Some(false)
        );

        let expected_response_result_refs = report.response_result_refs.clone();
        let exported = export_report(
            &mut state,
            ExportReportRequest {
                report_id: report.report_id,
                format: ExportFormat::RedactedJson,
                destination_metadata_redacted: Some(
                    "local response result trace export".to_string(),
                ),
                requested_by_redacted: Some("local_operator".to_string()),
                user_confirmed: true,
            },
        )
        .expect("export");
        assert!(exported.result.export_performed);
        let history = &state.read_state().export_history.records()[0];
        assert_eq!(history.response_result_refs, expected_response_result_refs);
    }

    #[test]
    fn rollback_request_records_result_without_privileged_execution() {
        let mut state = state_with_response_action();
        let action_id = state.response_actions()[0].action_id.clone();

        let rollback = rollback_response_action(
            &mut state,
            RollbackResponseActionRequest {
                action_id,
                actor_redacted: None,
                reason_redacted: "operator requested rollback".to_string(),
            },
        )
        .expect("rollback");

        assert!(!rollback.result.execution_performed);
        assert!(!rollback.result.rollback_result.success);
        assert_eq!(state.rollback_results().len(), 1);
    }

    #[test]
    fn report_export_history_preserves_safe_rollback_result_refs() {
        let mut state = state_with_response_action();
        let incident_id = state.read_state().incidents.items[0].id().clone();
        let action_id = state.response_actions()[0].action_id.clone();

        let rollback = rollback_response_action(
            &mut state,
            RollbackResponseActionRequest {
                action_id,
                actor_redacted: Some("local_operator".to_string()),
                reason_redacted: "record report rollback evidence".to_string(),
            },
        )
        .expect("rollback");
        assert!(!rollback.result.execution_performed);

        let report = generate_incident_report(
            &mut state,
            GenerateIncidentReportRequest {
                incident_id,
                requested_by_redacted: Some("local_operator".to_string()),
                reason_redacted: "prepare rollback trace report".to_string(),
            },
        )
        .expect("report");
        let report = report.result.report;
        assert_eq!(
            report.rollback_result_refs,
            vec![rollback.result.rollback_result.rollback_result_id.clone()]
        );
        let rollback_section = report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::RollbackStatus)
            .expect("rollback section");
        assert_eq!(
            rollback_section.rollback_result_refs,
            report.rollback_result_refs
        );
        assert!(rollback_section.response_result_refs.is_empty());

        let expected_response_result_refs = report.response_result_refs.clone();
        let exported = export_report(
            &mut state,
            ExportReportRequest {
                report_id: report.report_id,
                format: ExportFormat::RedactedJson,
                destination_metadata_redacted: Some("local rollback trace export".to_string()),
                requested_by_redacted: Some("local_operator".to_string()),
                user_confirmed: true,
            },
        )
        .expect("export");
        assert!(exported.result.export_performed);
        let history = &state.read_state().export_history.records()[0];
        assert_eq!(
            history.rollback_result_refs,
            vec![rollback.result.rollback_result.rollback_result_id]
        );
        assert_eq!(history.response_result_refs, expected_response_result_refs);
    }

    fn assert_safe_disabled_response_result(result: &ResponseResult) {
        assert_eq!(result.executor, "execution_disabled_recommendation_only");
        assert!(result.execution_disabled);
        assert!(result.is_replay);
        assert!(!result.success);
        assert!(result.ended_at.is_some());
        assert!(result.rollback_token.is_empty());
        assert!(result.rollback_deadline.is_none());
        let summary = result
            .error_summary_redacted
            .as_deref()
            .expect("redacted disabled-execution summary");
        assert!(summary.contains("no OS action"));
        assert!(!summary.contains("raw_payload"));
        assert!(!summary.contains("http_body"));
        assert!(!summary.contains("api_key"));
    }

    #[test]
    fn report_generation_and_export_require_redaction_confirmation() {
        let read = sample_read_state();
        let incident_id = read.incidents.items[0].id().clone();
        let mut state = MutationCommandState::from_read_state(read).expect("state");
        let report = generate_incident_report(
            &mut state,
            GenerateIncidentReportRequest {
                incident_id,
                requested_by_redacted: None,
                reason_redacted: "prepare local report".to_string(),
            },
        )
        .expect("report");
        let generated_report = report.result.report.clone();

        let denied = export_report(
            &mut state,
            ExportReportRequest {
                report_id: report.result.report.report_id.clone(),
                format: ExportFormat::RedactedJson,
                destination_metadata_redacted: Some("local file".to_string()),
                requested_by_redacted: None,
                user_confirmed: false,
            },
        )
        .expect_err("export without confirmation denied");
        assert_eq!(denied.error_code, ErrorCode::PolicyDenial);
        assert!(denied.audit_ref.is_some());
        assert!(state.read_state().export_history.records().is_empty());
        assert_eq!(state.read_state().export_history.violations().len(), 1);
        assert!(state
            .audit_records()
            .iter()
            .any(|event| event.category == AuditCategory::PrivacyViolation));

        let exported = export_report(
            &mut state,
            ExportReportRequest {
                report_id: report.result.report.report_id,
                format: ExportFormat::RedactedJson,
                destination_metadata_redacted: Some("local file".to_string()),
                requested_by_redacted: None,
                user_confirmed: true,
            },
        )
        .expect("export");
        assert!(exported.result.export_result.success);
        assert!(exported.result.export_result.file_hash.is_some());
        assert_eq!(
            exported.result.export_result.audit_ref.audit_id,
            exported.audit_receipt.audit_id
        );
        let expected_export_package = ReportExportGate::new()
            .prepare_export(ReportExportGateRequest {
                report: generated_report,
                format: ExportFormat::RedactedJson,
                policy: state
                    .read_state()
                    .runtime_profile
                    .report_export_policy
                    .clone(),
                requested_by_redacted: ACTOR_LOCAL_USER.to_string(),
                user_confirmed: true,
                audit_ref: AuditRef::new("report.export.requested").expect("audit ref"),
                destination_metadata_redacted: Some("local file".to_string()),
                file_hash: None,
            })
            .expect("expected export package");
        let expected_hash = ExportFileHash::from_bytes(
            expected_export_package
                .rendered_report
                .content_redacted
                .as_bytes(),
        );
        assert_eq!(
            exported.result.export_result.file_hash.as_deref(),
            Some(expected_hash.value.as_str())
        );
        assert_eq!(state.export_results().len(), 1);
        assert_eq!(state.read_state().export_history.records().len(), 1);
        let history_record = &state.read_state().export_history.records()[0];
        assert!(history_record.file_hash.is_some());
        assert!(history_record.redaction_summary.passed);
        assert_eq!(history_record.audit_id, exported.audit_receipt.audit_id);
        assert_eq!(
            history_record
                .file_hash
                .as_ref()
                .map(|hash| hash.value.as_str()),
            Some(expected_hash.value.as_str())
        );
    }

    #[test]
    fn scheduler_report_traceability_has_no_operational_side_effects() {
        let read = sample_read_state();
        let incident_id = read.incidents.items[0].id().clone();
        let mut state = MutationCommandState::from_read_state(read).expect("state");
        let before_controller_state = state.read_state().native_scheduler_controller_state.clone();
        let before_cycle_count = state.read_state().native_scheduler_cycles.len();
        let before_llm_story_count = state.read_state().llm_alert_stories.items.len();
        let before_response_action_count = state.response_actions().len();

        let report = generate_incident_report(
            &mut state,
            GenerateIncidentReportRequest {
                incident_id,
                requested_by_redacted: Some("local_operator".to_string()),
                reason_redacted: "prepare scheduler traceability report".to_string(),
            },
        )
        .expect("report")
        .result
        .report;

        assert_eq!(
            state.read_state().native_scheduler_controller_state,
            before_controller_state
        );
        assert_eq!(
            state.read_state().native_scheduler_cycles.len(),
            before_cycle_count
        );
        assert_eq!(
            state.read_state().llm_alert_stories.items.len(),
            before_llm_story_count
        );
        assert_eq!(state.response_actions().len(), before_response_action_count);
        let scheduler_section = report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::NativeScheduler)
            .expect("native scheduler section");
        assert_eq!(
            scheduler_section.content_redacted["scheduler_enablement_on_report"],
            Value::Bool(false)
        );
        assert_eq!(
            scheduler_section.content_redacted["provider_refresh_on_report"],
            Value::Bool(false)
        );
        assert_eq!(
            scheduler_section.content_redacted["automatic_llm_calls"],
            Value::Bool(false)
        );
        assert_eq!(
            scheduler_section.content_redacted["response_execution"],
            Value::Bool(false)
        );
        let section_text =
            serde_json::to_string(&scheduler_section.content_redacted).expect("section json");
        for marker in [
            "C:\\",
            "command_line",
            "api_key",
            "session_token",
            "access_token",
            "token=secret",
            "tenant_id",
        ] {
            assert!(
                !section_text.contains(marker),
                "scheduler section leaked marker {marker}"
            );
        }

        export_report(
            &mut state,
            ExportReportRequest {
                report_id: report.report_id,
                format: ExportFormat::RedactedJson,
                destination_metadata_redacted: Some("local scheduler trace export".to_string()),
                requested_by_redacted: Some("local_operator".to_string()),
                user_confirmed: true,
            },
        )
        .expect("export");

        assert_eq!(
            state.read_state().native_scheduler_controller_state,
            before_controller_state
        );
        assert_eq!(
            state.read_state().native_scheduler_cycles.len(),
            before_cycle_count
        );
        assert_eq!(
            state.read_state().llm_alert_stories.items.len(),
            before_llm_story_count
        );
        assert_eq!(state.response_actions().len(), before_response_action_count);
    }

    #[test]
    fn unsafe_export_destination_does_not_append_history_and_redacts_error_details() {
        let read = sample_read_state();
        let incident_id = read.incidents.items[0].id().clone();
        let mut state = MutationCommandState::from_read_state(read).expect("state");
        let report = generate_incident_report(
            &mut state,
            GenerateIncidentReportRequest {
                incident_id,
                requested_by_redacted: Some("local_operator".to_string()),
                reason_redacted: "prepare local report".to_string(),
            },
        )
        .expect("report");
        let unsafe_destination = "C:\\Users\\Lenovo\\Desktop\\incident_report.sgreport";

        let error = export_report(
            &mut state,
            ExportReportRequest {
                report_id: report.result.report.report_id,
                format: ExportFormat::RedactedJson,
                destination_metadata_redacted: Some(unsafe_destination.to_string()),
                requested_by_redacted: Some("local_operator".to_string()),
                user_confirmed: true,
            },
        )
        .expect_err("unsafe destination should be rejected");

        assert_eq!(error.error_code, ErrorCode::PrivacyPolicyViolation);
        let details = error.details_redacted.expect("redacted details");
        let error_text = details["error_redacted"].as_str().expect("error text");
        assert!(error_text.contains("destination_metadata_redacted"));
        assert!(!error_text.contains(unsafe_destination));
        assert!(state.read_state().export_history.records().is_empty());
    }

    #[test]
    fn demo_story_report_consumes_graph_snapshot_and_response_plan() {
        let replay = crate::demo_story::FixtureRunner::from_default_fixture()
            .expect("fixture runner")
            .run()
            .expect("fixture run");
        let read = replay
            .read_model
            .into_read_state(ReadOnlyCommandState::bootstrap().expect("read state"));
        let incident_id = read.incidents.items[0].id().clone();
        let mut state = MutationCommandState::from_read_state(read).expect("state");
        create_response_plan(
            &mut state,
            CreateResponsePlanRequest {
                source: ResponsePlanSource::Incident(incident_id.clone()),
                reason_redacted: "generate live demo response plan".to_string(),
                created_by_redacted: Some("local_operator".to_string()),
            },
        )
        .expect("response plan");

        let report = generate_incident_report(
            &mut state,
            GenerateIncidentReportRequest {
                incident_id,
                requested_by_redacted: Some("local_operator".to_string()),
                reason_redacted: "prepare redacted demo report".to_string(),
            },
        )
        .expect("report");

        let report = report.result.report;
        assert!(!report.graph_snapshot_refs.is_empty());
        assert!(report
            .sections
            .iter()
            .any(|section| section.section_type == ReportSectionType::Recommendations));
        let graph_section = report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::GraphSnapshot)
            .expect("graph section");
        assert_eq!(
            graph_section.content_redacted["evidence_backed"],
            Value::Bool(true)
        );
        assert!(report.redaction_summary.passed);
    }

    #[test]
    fn llm_alert_story_report_and_export_preserve_only_validated_story_refs() {
        let read = sample_read_state();
        let incident_id = read.incidents.items[0].id().clone();
        let alert_id = read.alerts.items[0].id().clone();
        let evidence_id = read.findings.items[0].evidence_refs()[0].clone();
        let story_id = LlmAlertStoryId::new_v4();
        let mut state = MutationCommandState::from_read_state(read).expect("state");
        state
            .record_llm_alert_story(LlmAlertStoryRecord {
                story_id: story_id.clone(),
                alert_ref: alert_id,
                incident_ref: Some(incident_id.clone()),
                provider: LlmAlertStoryProvider::OpenAiCompatible,
                model: "safe-model".to_string(),
                request_hash: "a".repeat(64),
                response_hash: "b".repeat(64),
                generated_at: Timestamp::now(),
                ai_generated: true,
                redaction_passed: true,
                degraded: true,
                story: LlmAlertStoryDraft {
                    alert_narrative_redacted: "Bounded metadata forms an alert sequence."
                        .to_string(),
                    likely_attack_summary_redacted: "Linked degraded techniques may apply."
                        .to_string(),
                    confidence_uncertainty_redacted:
                        "Confidence is limited by metadata-only visibility.".to_string(),
                    evidence_summary_redacted: "Linked evidence refs support review.".to_string(),
                    affected_entities_redacted: vec!["entity:redacted".to_string()],
                    investigation_suggestions_redacted: vec![
                        "Review linked evidence refs.".to_string()
                    ],
                    report_text_redacted: "AI-generated story for analyst review.".to_string(),
                },
                evidence_refs: vec![evidence_id],
                risk_refs: vec![RiskEventId::new_v4()],
                attack_refs: vec![LlmAttackTechniqueRef {
                    tactic_id: "TA0011".to_string(),
                    technique_id: "T1071".to_string(),
                }],
            })
            .expect("record story");

        let report = generate_incident_report(
            &mut state,
            GenerateIncidentReportRequest {
                incident_id,
                requested_by_redacted: Some("local_operator".to_string()),
                reason_redacted: "prepare story-linked report".to_string(),
            },
        )
        .expect("report")
        .result
        .report;
        assert_eq!(report.llm_story_refs, vec![story_id.clone()]);
        assert!(report
            .sections
            .iter()
            .any(|section| section.section_type == ReportSectionType::LlmAlertStory));

        let report_id = report.report_id.clone();
        export_report(
            &mut state,
            ExportReportRequest {
                report_id,
                format: ExportFormat::RedactedJson,
                destination_metadata_redacted: Some("local report file".to_string()),
                requested_by_redacted: Some("local_operator".to_string()),
                user_confirmed: true,
            },
        )
        .expect("export");
        assert_eq!(
            state.read_state().export_history.records()[0].llm_story_refs,
            vec![story_id]
        );
        let serialized =
            serde_json::to_string(state.read_state().export_history.records()).expect("serialize");
        for forbidden in ["provider_payload", "raw_prompt", "session-secret"] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[test]
    fn export_report_with_history_storage_persists_success_and_denial() {
        let connection = initialized_connection().expect("sqlite");
        let stores = SqliteStoreFactory::new(&connection);
        let read = sample_read_state();
        let incident_id = read.incidents.items[0].id().clone();
        let mut state = MutationCommandState::from_read_state(read).expect("state");
        let report = generate_incident_report(
            &mut state,
            GenerateIncidentReportRequest {
                incident_id,
                requested_by_redacted: None,
                reason_redacted: "prepare local report".to_string(),
            },
        )
        .expect("report");
        let report_id = report.result.report.report_id.clone();
        let graph_snapshot_refs = report.result.report.graph_snapshot_refs.clone();
        let evidence_refs = report.result.report.evidence_refs.clone();
        let graph_section = report
            .result
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::GraphSnapshot)
            .expect("graph section");
        assert_eq!(
            graph_section.content_redacted["evidence_backed"],
            Value::Bool(true)
        );
        assert!(graph_section
            .content_redacted
            .get("export_safe_snapshots")
            .and_then(Value::as_array)
            .is_some_and(|snapshots| !snapshots.is_empty()));

        let denied = export_report_with_export_history_storage(
            &mut state,
            ExportReportRequest {
                report_id: report_id.clone(),
                format: ExportFormat::RedactedJson,
                destination_metadata_redacted: Some("local file".to_string()),
                requested_by_redacted: None,
                user_confirmed: false,
            },
            &stores,
        )
        .expect_err("export without confirmation denied");
        assert_eq!(denied.error_code, ErrorCode::PolicyDenial);
        let empty_history = ReadOnlyCommandState::bootstrap()
            .expect("read state")
            .with_export_history_from_storage(&stores)
            .expect("load empty export history");
        let empty_page = crate::read_commands::list_export_history(
            &empty_history,
            sentinel_capabilities::ReportExportHistoryQuery::for_report(report_id.clone()),
        )
        .expect("empty export history");
        assert!(empty_page.items.is_empty());

        let exported = export_report_with_export_history_storage(
            &mut state,
            ExportReportRequest {
                report_id: report_id.clone(),
                format: ExportFormat::RedactedJson,
                destination_metadata_redacted: Some("local file".to_string()),
                requested_by_redacted: None,
                user_confirmed: true,
            },
            &stores,
        )
        .expect("export");

        let loaded = ReadOnlyCommandState::bootstrap()
            .expect("read state")
            .with_export_history_from_storage(&stores)
            .expect("load export history");
        let history = crate::read_commands::list_export_history(
            &loaded,
            sentinel_capabilities::ReportExportHistoryQuery::for_report(report_id),
        )
        .expect("stored export history");
        let violations =
            crate::read_commands::list_export_policy_violations(&loaded).expect("violations");

        assert_eq!(history.items.len(), 1);
        assert_eq!(
            history.items[0].export_result_id,
            exported.result.export_result.export_result_id
        );
        assert!(history.items[0].file_hash.is_some());
        assert_eq!(history.items[0].audit_id, exported.audit_receipt.audit_id);
        assert_eq!(history.items[0].graph_snapshot_refs, graph_snapshot_refs);
        assert_eq!(history.items[0].evidence_refs, evidence_refs);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].export_audit_id.is_some());
    }

    #[test]
    fn repeated_successful_exports_append_multiple_history_records() {
        let connection = initialized_connection().expect("sqlite");
        let stores = SqliteStoreFactory::new(&connection);
        let read = sample_read_state();
        let incident_id = read.incidents.items[0].id().clone();
        let mut state = MutationCommandState::from_read_state(read).expect("state");
        let report = generate_incident_report(
            &mut state,
            GenerateIncidentReportRequest {
                incident_id,
                requested_by_redacted: Some("local_operator".to_string()),
                reason_redacted: "prepare local report".to_string(),
            },
        )
        .expect("report");
        let report_id = report.result.report.report_id.clone();

        for destination in ["local file one", "local file two"] {
            let exported = export_report_with_export_history_storage(
                &mut state,
                ExportReportRequest {
                    report_id: report_id.clone(),
                    format: ExportFormat::RedactedJson,
                    destination_metadata_redacted: Some(destination.to_string()),
                    requested_by_redacted: Some("local_operator".to_string()),
                    user_confirmed: true,
                },
                &stores,
            )
            .expect("export");
            assert!(exported.result.export_performed);
        }

        assert_eq!(state.read_state().export_history.records().len(), 2);
        let loaded = ReadOnlyCommandState::bootstrap()
            .expect("read state")
            .with_export_history_from_storage(&stores)
            .expect("load export history");
        let history = crate::read_commands::list_export_history(
            &loaded,
            sentinel_capabilities::ReportExportHistoryQuery::for_report(report_id),
        )
        .expect("stored export history");

        assert_eq!(history.items.len(), 2);
        assert_ne!(
            history.items[0].export_result_id,
            history.items[1].export_result_id
        );
        assert!(history.items.iter().all(|item| item.file_hash.is_some()));
    }

    #[test]
    fn settings_mutations_validate_impact_and_expose_rollback() {
        let mut state = MutationCommandState::bootstrap().expect("state");
        let mut profile = RuntimeProfile::low_resource();
        profile.response_policy = ResponsePolicy::approval_required();

        let applied = apply_runtime_profile(
            &mut state,
            ApplyRuntimeProfileRequest {
                profile,
                reason_redacted: "switch profile".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("apply profile");
        assert!(applied.rollback.is_some());
        assert_eq!(
            state.read_state().runtime_profile.response_policy.mode,
            ResponseMode::ApprovalRequired
        );

        let mut unsafe_policy = state.read_state().runtime_profile.privacy_policy.clone();
        unsafe_policy.raw_packet_storage_enabled = true;
        let denied = update_privacy_policy(
            &mut state,
            UpdatePrivacyPolicyRequest {
                policy: unsafe_policy,
                reason_redacted: "unsafe test".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect_err("unsafe privacy denied");
        assert_eq!(denied.error_code, ErrorCode::PolicyDenial);
    }

    #[test]
    fn forensic_mode_is_explicit_time_limited_and_audited() {
        let mut state = MutationCommandState::bootstrap().expect("state");
        let scope =
            ForensicScope::new(ForensicScopeKind::SelectedFlow, "flow-redacted").expect("scope");

        let enabled = enable_forensic_mode(
            &mut state,
            EnableForensicModeRequest {
                reason_redacted: "manual incident investigation".to_string(),
                scope,
                requested_by_redacted: None,
            },
        )
        .expect("enable forensic");

        assert!(
            enabled
                .result
                .runtime_profile
                .privacy_policy
                .forensic_mode
                .enabled
        );
        assert!(enabled
            .result
            .runtime_profile
            .privacy_policy
            .forensic_mode
            .ttl_seconds
            .is_some());
        assert!(state
            .audit_records()
            .iter()
            .any(|event| { event.action_type == AuditActionType::ForensicModeEnabled }));

        let disabled = disable_forensic_mode(
            &mut state,
            DisableForensicModeRequest {
                reason_redacted: "investigation complete".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("disable forensic");
        assert!(
            !disabled
                .result
                .runtime_profile
                .privacy_policy
                .forensic_mode
                .enabled
        );
    }

    fn state_with_response_action() -> MutationCommandState {
        let read = sample_read_state();
        let incident_id = read.incidents.items[0].id().clone();
        let mut state = MutationCommandState::from_read_state(read).expect("state");
        create_response_plan(
            &mut state,
            CreateResponsePlanRequest {
                source: ResponsePlanSource::Incident(incident_id),
                reason_redacted: "recommend containment options".to_string(),
                created_by_redacted: None,
            },
        )
        .expect("plan");
        state
    }

    fn initialized_connection() -> Result<Connection, Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        {
            let mut runner = MigrationRunner::new(&mut connection);
            runner.initialize(&SchemaMetadata::storage_foundation())?;
            let mut audit = InMemoryMigrationAuditSink::default();
            runner.apply_all(&[logical_store_migration()?], &mut audit)?;
        }
        Ok(connection)
    }

    fn auto_eligible_finding_read_state() -> ReadOnlyCommandState {
        let state = ReadOnlyCommandState::bootstrap().expect("read state");
        let producer = state.read_plugin_for_tests();
        let mut destination = EntityRef::new(EntityId::new_v4(), EntityType::Ip);
        destination.entity_name = Some("redacted destination".to_string());
        destination.confidence = QualityScore::new(0.93).expect("entity confidence");
        let finding = Finding::new(
            "security.finding.c2",
            producer,
            vec![EvidenceId::new_v4(), EvidenceId::new_v4()],
            FindingExplanation::new("redacted C2 destination with independent evidence")
                .expect("explanation"),
        )
        .expect("finding")
        .with_entity_refs(vec![destination])
        .with_severity(SecuritySeverity::High)
        .with_confidence(QualityScore::new(0.91).expect("finding confidence"));

        state.with_findings(vec![finding])
    }

    fn sample_read_state() -> ReadOnlyCommandState {
        let state = ReadOnlyCommandState::bootstrap().expect("read state");
        let producer = state.read_plugin_for_tests();
        let evidence_id = EvidenceId::new_v4();
        let finding = Finding::new(
            "c2_signal",
            producer,
            vec![evidence_id.clone()],
            FindingExplanation::new("redacted C2-like cadence").expect("explanation"),
        )
        .expect("finding")
        .with_risk_reasons(vec![sentinel_contracts::RiskReason {
            reason_type: "cadence".to_string(),
            summary_redacted: "regular beacon-like cadence".to_string(),
            confidence: QualityScore::perfect(),
            evidence_refs: Vec::new(),
            attack_mappings: Vec::new(),
        }]);
        let alert = Alert::new(
            "redacted C2 alert",
            "redacted alert summary",
            vec![finding.id().clone()],
        )
        .expect("alert");
        let incident = Incident::new(
            "c2_incident",
            "redacted incident",
            "redacted incident summary",
            vec![alert.id().clone()],
        )
        .expect("incident");
        let graph_view = sample_incident_graph_view(incident.id().clone(), evidence_id);

        state
            .with_findings(vec![finding])
            .with_alerts(vec![alert])
            .with_incidents(vec![incident])
            .with_graph_views(vec![graph_view])
    }

    fn metadata_watch_preview_request(
        source_kind: MetadataWatchSourceKind,
        parser_family: MetadataParserFamily,
        sampling_mode: MetadataSamplingMode,
    ) -> MetadataWatchSourcePreviewRequest {
        MetadataWatchSourcePreviewRequest {
            source_kind,
            parser_family,
            display_label_redacted: "watch_source_redacted".to_string(),
            sampling_mode,
            interval_seconds: 5,
            max_records_per_tick: 100,
            max_bytes_per_tick: 64_000,
            reason_redacted: "operator_confirmed".to_string(),
        }
    }

    fn loop_control_request(
        action: MetadataSamplingLoopAction,
    ) -> MetadataSamplingLoopControlRequest {
        MetadataSamplingLoopControlRequest {
            action,
            max_sources_per_cycle: 8,
            max_concurrent_sources: 1,
            max_files_per_tick: 8,
            per_source_timeout_millis: 5_000,
            reason_redacted: "operator_loop_control".to_string(),
            requested_by_redacted: None,
        }
    }

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "sentinel_portable_reader_{label}_{}_{}",
                std::process::id(),
                nanos
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &PathBuf {
            &self.path
        }

        fn path_string(&self) -> String {
            self.path.to_string_lossy().to_string()
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn confirm_reader_source(
        state: &mut MutationCommandState,
        source_kind: MetadataWatchSourceKind,
        parser_family: MetadataParserFamily,
        sampling_mode: MetadataSamplingMode,
        source_path: &Path,
    ) -> sentinel_contracts::MetadataWatchSourceId {
        let preview = preview_portable_reader_source(
            state,
            PortableReaderSourcePreviewRequest {
                watch_request: metadata_watch_preview_request(
                    source_kind,
                    parser_family,
                    sampling_mode,
                ),
                source_path: source_path.to_string_lossy().to_string(),
            },
        )
        .expect("preview reader source");
        confirm_metadata_watch_source(
            state,
            MetadataWatchSourceConfirmation {
                preview_id: preview.preview_id.clone(),
                user_confirmed: true,
                reason_redacted: "operator_confirmed".to_string(),
                requested_by_redacted: None,
            },
        )
        .expect("confirm reader source");
        preview.preview_id
    }

    fn append_to_file(path: &PathBuf, content: &str) {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open append file");
        file.write_all(content.as_bytes()).expect("append file");
    }

    fn assert_reader_surfaces_redacted(state: &MutationCommandState, forbidden: &[&str]) {
        let serialized = serde_json::to_string(&serde_json::json!({
            "sources": state.read.metadata_watch_sources.items,
            "batches": state.read.metadata_sampling_batches.items,
            "controller": state.read.metadata_watch_controller_status,
            "llm": state.read.llm_alert_stories.items,
            "reports": state.read.reports.items,
            "exports": state.export_results,
        }))
        .expect("serialize safe reader surfaces");
        for marker in forbidden {
            assert!(
                !serialized.contains(marker),
                "reader surface leaked forbidden marker {marker}"
            );
        }
    }

    fn har_reader_fixture() -> String {
        serde_json::json!({
            "log": {
                "entries": [
                    {
                        "startedDateTime": "2026-06-12T08:00:00Z",
                        "time": 42,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://reader.example.test/upload/1?token=secret",
                            "headersSize": 120,
                            "bodySize": 4096,
                            "headers": []
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 80,
                            "bodySize": 128,
                            "content": { "mimeType": "application/json", "size": 128 }
                        }
                    }
                ]
            }
        })
        .to_string()
    }

    fn network_jsonl_reader_fixture() -> String {
        serde_json::json!({
            "timestamp": "2026-06-12T08:00:01Z",
            "src_ip": "192.0.2.15",
            "src_port": 51515,
            "dst_ip": "203.0.113.22",
            "dst_port": 443,
            "protocol": "tcp",
            "direction": "outbound",
            "bytes_out": 72000,
            "bytes_in": 2200,
            "http": {
                "method": "POST",
                "url": "https://jsonl.example.test/upload/9?token=secret",
                "status_code": 200,
                "request_size_bytes": 72000,
                "response_size_bytes": 2200,
                "content_type": "application/json",
                "user_agent": "python-requests/2.32.0"
            },
            "dns": {
                "query_name": "api.jsonl.example.test",
                "query_type": "A",
                "resolver_ip": "192.0.2.53",
                "client_ip": "192.0.2.15",
                "answers": [{ "answer_type": "ip", "value": "203.0.113.22", "ttl_seconds": 60 }]
            }
        })
        .to_string()
            + "\n"
    }

    fn web_access_line(target: &str) -> String {
        format!(
            "192.0.2.55 - - [12/Jun/2026:08:00:00 +0000] \"GET https://web.example.test{target} HTTP/1.1\" 200 123 \"-\" \"curl/8\"\n"
        )
    }

    fn saas_jsonl_reader_line() -> String {
        serde_json::json!({
            "timestamp": "2026-06-12T07:00:00Z",
            "provider_category": "object_storage",
            "service_category": "object_storage",
            "provider_confidence": "high",
            "endpoint_fingerprint": "endpoint#object-storage",
            "api_method_category": "write",
            "status_bucket": "success",
            "upload_download_ratio_bucket": "upload_burst",
            "identity_hash": "identity-cloud-a",
            "session": "session-cloud-a"
        })
        .to_string()
            + "\n"
    }

    fn sample_incident_graph_view(
        incident_id: IncidentId,
        evidence_id: EvidenceId,
    ) -> GraphViewModel {
        let mut process = GraphNodeViewModel::new(
            GraphNodeType::Process,
            RedactedLabel::redacted("redacted process", PrivacyClass::Internal)
                .expect("process label"),
        );
        process.detail_ref.evidence_refs = vec![evidence_id.clone()];
        let destination = GraphNodeViewModel::new(
            GraphNodeType::Domain,
            RedactedLabel::redacted("redacted destination", PrivacyClass::Internal)
                .expect("destination label"),
        );
        let mut edge = GraphEdgeViewModel::new(
            GraphEdgeType::ProcessQueriesDomain,
            process.node_id.clone(),
            destination.node_id.clone(),
        );
        edge.evidence_refs = vec![evidence_id];
        edge.label = Some(
            RedactedLabel::redacted("redacted metadata edge", PrivacyClass::Internal)
                .expect("edge label"),
        );
        edge.confidence = QualityScore::new(0.82).expect("edge confidence");

        let mut view = GraphViewModel::new(
            GraphType::IncidentGraph,
            RedactedLabel::redacted("redacted incident graph", PrivacyClass::Internal)
                .expect("graph title"),
            GraphScope::Incident(incident_id),
        );
        view.nodes = vec![process, destination];
        view.edges = vec![edge];
        view.redaction_status = RedactionStatus::Redacted;
        view.redaction_summary = GraphRedactionSummary {
            status: RedactionStatus::Redacted,
            redacted_node_count: 2,
            redacted_edge_count: 1,
            hidden_label_count: 0,
            notes: vec!["test GraphViewModel is redacted and evidence-backed".to_string()],
        };
        view.original_node_count = view.nodes.len() as u32;
        view.original_edge_count = view.edges.len() as u32;
        view
    }

    trait ReadStateTestExt {
        fn read_plugin_for_tests(&self) -> sentinel_contracts::PluginId;
    }

    impl ReadStateTestExt for ReadOnlyCommandState {
        fn read_plugin_for_tests(&self) -> sentinel_contracts::PluginId {
            self.plugin_registry
                .list()
                .into_iter()
                .find(|plugin| !plugin.finding_types.is_empty())
                .expect("finding producer")
                .plugin_id
                .clone()
        }
    }
}
