//! Tauri desktop command surface for Sentinel Guard.
//!
//! This crate is the desktop shell boundary. Read handlers delegate into
//! `sentinel-app-core` and return the same structured, redacted contracts used
//! by the frontend bridge.

mod llm_alert_story;

use crate::llm_alert_story::{
    ClearLlmAlertStoryApiKeyRequest, DesktopLlmAlertStoryState, SaveLlmAlertStoryApiKeyRequest,
    TestLlmAlertStoryConnectionRequest, UpdateLlmAlertStorySettingsRequest,
};
use sentinel_app_core::{
    self as core, AlertEscalationResult, AlertStreamUpdate, ApplyRuntimeProfileRequest,
    CapabilityOverview, CaptureStatusUpdate, ComponentDetail, ComponentSummary,
    CreateResponsePlanRequest, DisableForensicModeRequest, EnableForensicModeRequest,
    EscalateAlertRequest, ExportHistoryRecord, ExportPolicyViolation, ExportReportMutationResult,
    ExportReportRequest, FindingStateMutationRequest, FindingStateMutationResult, FixtureRunner,
    GenerateIncidentReportRequest, GenerateLlmAlertStoryRequest, GraphUpdateStreamUpdate,
    GraphViewRequest, HealthStreamUpdate, IncidentDetailView, IncidentStatusMutationRequest,
    IncidentStatusMutationResult, IncidentStreamUpdate, LocalProxyMetadataProviderStatus,
    LocalProxyMetadataStartRequest, MetricStreamUpdate, MutationCommandState, MutationReceipt,
    PluginCatalogView, PluginLifecycleMutationResult, PluginLifecycleRequest,
    PortableCaptureImportConfirmation, PortableCaptureImportFileRequest,
    PortableCaptureImportPreview, PortableCaptureImportResult, PreparedPortableCaptureImport,
    PrivacyWarningUpdate, ReadOnlyCommandState, ReportExportHistoryQuery, ReportGenerationResult,
    ReportProgressUpdate, ResponseApprovalMutationRequest, ResponseApprovalMutationResult,
    ResponsePlanMutationResult, ResponseStatusUpdate, RollbackResponseActionRequest,
    RollbackResponseActionResult, ServiceStatusUpdate, ServiceStatusView, SettingsMutationResult,
    StreamEventEnvelope, TauriEventDispatcher, UpdatePrivacyPolicyRequest,
    UpdateResponsePolicyRequest,
};
use sentinel_contracts::{
    session_export::{
        ExportConfirmation as ExplicitExportConfirmation,
        ExportHistoryEntry as ExplicitExportHistoryEntry, ExportPreview as ExplicitExportPreview,
        ExportRequest as ExplicitExportRequest, ExportResult as ExplicitExportResult,
    },
    Alert, AttackCoverageSummary, AttackHypothesisId, AttackHypothesisRecord,
    AuthorizedNativeCapabilityStatus, BaselineDrillDownDetail, BaselineIndicator,
    BaselineIndicatorId, BaselineRecord, BaselineRecordId, CommandResult, CoreError,
    DnsObservation, DurableBaselineSummary, EdrReadinessSummary, ErrorCode, ErrorSeverity,
    EvidenceQualityId, EvidenceQualityRecord, EvidenceQualitySummary, ExportResultId, Finding,
    FlowRecord, FusionSummary, FutureSecurityFactMappingSummary, GraphViewModel,
    HypothesisExplanationDetail, Incident, IncidentGroupInvestigationDetail, IncidentId,
    IncidentLinkedGroupId, IncidentLinkedHypothesisGroup, IncidentTimelineEntry,
    IncidentTimelineEntryId, InvestigationDrillDownSummary, LlmAlertStoryId, LlmAlertStoryRecord,
    LlmAlertStoryStatusView, MetadataSamplingBatchId, MetadataSamplingBatchSummary,
    MetadataSamplingLoopControlRequest, MetadataSamplingLoopRunRequest,
    MetadataSamplingTickRequest, MetadataSamplingTickResult, MetadataWatchControllerStatus,
    MetadataWatchLifecycleRequest, MetadataWatchSourceConfirmation, MetadataWatchSourceId,
    MetadataWatchSourcePreview, MetadataWatchSourcePreviewRequest, MetadataWatchSourceStatus,
    MissingEndpointVisibilitySummary, NativePermissionActionRequest, NativePermissionActionResult,
    NativePermissionAuditSummary, NativePermissionPreview, NativePermissionStatusSummary,
    NativeSamplerActivationPreview, NativeSamplerAuthorizationReview, NativeSamplerBlockedSummary,
    NativeSamplerContract, NativeSamplerReadinessDetail, NativeSamplerReadinessSummary,
    NativeSamplerRuntimeActionRequest, NativeSamplerRuntimeActionResult, NativeSamplerRuntimeBatch,
    NativeSamplerRuntimeStatus, NativeSamplerRuntimeSummary, NativeSamplerScheduleStatus,
    NativeSchedulerActionRequest, NativeSchedulerActionResult, NativeSchedulerCycleSummary,
    NativeSchedulerEnablementPreview, NativeSchedulerOperationalSummary, NativeSchedulerStatus,
    NativeSchedulerSummary, NativeSchedulerTickRequest, NativeVisibilitySummary,
    NavigationResolution, NavigationResolveRequest, PageRequest, PageResponse, PluginId,
    PluginManifest, PortableCaptureInputSourceType, QueryRequest, Report, ReportId, ResponsePlan,
    RuntimeProfile, SecurityFact, SessionId, SourceReliabilityExplanation,
    SourceReliabilitySummary, TimelineDrillDownDetail, Timestamp, TlsObservation, TraceId,
};
use sentinel_platform::{component::ComponentId, ObservabilityHealthStatus};
use sentinel_storage::{
    DatabaseConfig, DatabaseRuntime, PreferenceError, SessionLifecycle, SessionMode,
    SessionRootResolver, SqliteStoreFactory, StorageError, CAPTURE_IMPORT_PREVIEW_FILE_PREFIX,
    CAPTURE_IMPORT_PREVIEW_FILE_SUFFIX, PORTABLE_PROFILE_MARKER_FILE_NAME,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process,
    sync::Mutex,
};
use tauri::{Emitter, Manager, State};

pub const READ_ONLY_COMMAND_NAMES: &[&str] = &[
    "list_components",
    "get_component_detail",
    "search_components",
    "get_plugin_catalog",
    "get_plugin_manifest",
    "search_plugins",
    "get_capability_overview",
    "search_capabilities",
    "search_findings",
    "search_alerts",
    "search_incidents",
    "get_incident_detail",
    "search_flows",
    "search_dns",
    "search_tls",
    "get_graph_view",
    "list_active_responses",
    "search_response_plans",
    "list_reports",
    "search_reports",
    "get_report",
    "get_attack_coverage_summary",
    "get_fusion_summary",
    "list_security_facts",
    "list_attack_hypotheses",
    "get_attack_hypothesis",
    "get_durable_baseline_summary",
    "get_evidence_quality_summary",
    "list_evidence_quality_records",
    "get_evidence_quality_record",
    "get_investigation_drill_down_summary",
    "resolve_navigation_reference",
    "get_hypothesis_explanation_detail",
    "get_baseline_drill_down_detail",
    "get_incident_group_investigation_detail",
    "get_timeline_drill_down_detail",
    "get_source_reliability_explanation",
    "list_baseline_records",
    "get_baseline_record",
    "list_baseline_indicators",
    "get_baseline_indicator",
    "list_incident_linked_hypothesis_groups",
    "get_incident_linked_hypothesis_group",
    "list_incident_timeline_entries",
    "get_incident_timeline_entry",
    "list_source_reliability_summaries",
    "get_metadata_watch_controller_status",
    "list_metadata_watch_sources",
    "get_metadata_watch_source",
    "list_metadata_sampling_batches",
    "get_metadata_sampling_batch",
    "list_export_history",
    "search_export_history",
    "get_export_history_record",
    "list_export_policy_violations",
    "get_runtime_profile",
    "search_runtime_profiles",
    "get_llm_alert_story_status",
    "list_llm_alert_stories",
    "get_llm_alert_story",
    "get_service_status",
    "search_service_status",
    "list_authorized_native_capabilities",
    "get_authorized_native_capability",
    "get_native_permission_status_summary",
    "get_native_visibility_summary",
    "get_native_permission_audit_summary",
    "list_native_sampler_contracts",
    "get_native_sampler_contract",
    "get_native_sampler_readiness_summary",
    "get_native_sampler_readiness_detail",
    "get_native_sampler_authorization_review",
    "get_future_security_fact_mapping_summary",
    "get_native_sampler_blocked_summary",
    "get_missing_endpoint_visibility_summary",
    "get_edr_readiness_summary",
    "get_native_sampler_runtime_summary",
    "get_native_sampler_runtime_status",
    "get_latest_native_sampler_runtime_batch",
    "get_native_scheduler_status",
    "list_native_sampler_schedule_statuses",
    "get_native_sampler_schedule_status",
    "get_native_scheduler_summary",
    "get_native_scheduler_operational_summary",
    "list_native_scheduler_cycles",
    "get_latest_native_scheduler_cycle",
    "get_portable_preferences",
];

pub const MUTATION_COMMAND_NAMES: &[&str] = &[
    "enable_plugin",
    "disable_plugin",
    "restart_plugin",
    "suppress_finding",
    "dismiss_finding",
    "escalate_alert",
    "update_incident_status",
    "create_response_plan",
    "approve_response_action",
    "reject_response_action",
    "rollback_response_action",
    "generate_incident_report",
    "export_report",
    "get_local_metadata_proxy_status",
    "start_local_metadata_proxy",
    "stop_local_metadata_proxy",
    "drain_local_metadata_proxy",
    "preview_portable_capture_import",
    "confirm_portable_capture_import",
    "preview_metadata_watch_source",
    "confirm_metadata_watch_source",
    "update_metadata_watch_source",
    "tick_metadata_watch_controller",
    "update_metadata_sampling_loop",
    "run_metadata_sampling_loop",
    "preview_explicit_export",
    "confirm_explicit_export",
    "apply_runtime_profile",
    "update_privacy_policy",
    "update_response_policy",
    "enable_forensic_mode",
    "disable_forensic_mode",
    "update_llm_alert_story_settings",
    "save_llm_alert_story_api_key",
    "clear_llm_alert_story_api_key",
    "test_llm_alert_story_connection",
    "generate_llm_alert_story",
    "preview_native_permission_request",
    "update_native_permission",
    "preview_native_sampler_activation",
    "apply_native_sampler_runtime_action",
    "preview_native_scheduler_enablement",
    "apply_native_scheduler_action",
    "tick_native_scheduler",
    "run_demo_story",
    "save_portable_preferences",
    "shutdown_app",
];

pub const STREAM_EVENT_NAMES: &[&str] = &[
    "health_stream",
    "metric_stream",
    "capture_status_stream",
    "service_status_stream",
    "alert_stream",
    "incident_stream",
    "graph_update_stream",
    "response_status_stream",
    "report_progress_stream",
    "privacy_warning_stream",
];

const MAIN_WINDOW_LABEL: &str = "main";
const DETACHED_PANE_CLOSED_EVENT: &str = "detached_pane_closed";

#[derive(Clone, Copy, Debug, PartialEq)]
struct DetachedPaneConfig {
    pane_id: &'static str,
    label: &'static str,
}

const DETACHED_PANES: &[DetachedPaneConfig] = &[
    DetachedPaneConfig {
        pane_id: "graph",
        label: "detached-graph",
    },
    DetachedPaneConfig {
        pane_id: "inspector",
        label: "detached-inspector",
    },
    DetachedPaneConfig {
        pane_id: "evidence",
        label: "detached-evidence",
    },
    DetachedPaneConfig {
        pane_id: "timeline",
        label: "detached-timeline",
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupMode {
    Demo,
    Normal,
    PortableNoRetention,
}

impl StartupMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Demo => "demo",
            Self::Normal => "normal",
            Self::PortableNoRetention => "portable-no-retention",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupModeSource {
    CommandLine,
    Environment,
    MarkerFile,
    Default,
}

impl StartupModeSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommandLine => "command_line",
            Self::Environment => "environment",
            Self::MarkerFile => "marker_file",
            Self::Default => "default",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DemoStartupConfig {
    pub mode: StartupMode,
    pub source: StartupModeSource,
    pub portable_root: Option<PathBuf>,
}

impl DemoStartupConfig {
    pub fn detect() -> Self {
        let executable_dir = env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf));
        Self::from_args_env_and_executable_dir(
            env::args(),
            env::var("SENTINEL_DEMO").ok(),
            env::var("SENTINEL_PROFILE").ok(),
            executable_dir,
        )
    }

    pub fn from_args_and_env<I, S>(args: I, sentinel_demo: Option<String>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::from_args_env_and_executable_dir(args, sentinel_demo, None, None)
    }

    pub fn from_args_env_and_executable_dir<I, S>(
        args: I,
        sentinel_demo: Option<String>,
        sentinel_profile: Option<String>,
        executable_dir: Option<PathBuf>,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let args = args
            .into_iter()
            .map(|arg| arg.as_ref().to_string())
            .collect::<Vec<_>>();

        if cli_profile_is_portable(&args) {
            return Self::portable(StartupModeSource::CommandLine, executable_dir);
        }

        if sentinel_profile
            .as_deref()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("portable"))
        {
            return Self::portable(StartupModeSource::Environment, executable_dir);
        }

        if portable_marker_exists(executable_dir.as_deref()) {
            return Self::portable(StartupModeSource::MarkerFile, executable_dir);
        }

        if args.iter().any(|arg| arg == "--demo") {
            return Self {
                mode: StartupMode::Demo,
                source: StartupModeSource::CommandLine,
                portable_root: None,
            };
        }

        if sentinel_demo.as_deref().is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        }) {
            return Self {
                mode: StartupMode::Demo,
                source: StartupModeSource::Environment,
                portable_root: None,
            };
        }

        Self {
            mode: StartupMode::Normal,
            source: StartupModeSource::Default,
            portable_root: None,
        }
    }

    pub fn is_demo(&self) -> bool {
        self.mode == StartupMode::Demo
    }

    pub fn is_portable(&self) -> bool {
        self.mode == StartupMode::PortableNoRetention
    }

    pub fn session_mode(&self) -> SessionMode {
        if self.is_portable() {
            SessionMode::PortableNoRetention
        } else {
            SessionMode::for_demo_flag(self.is_demo())
        }
    }

    fn portable(source: StartupModeSource, executable_dir: Option<PathBuf>) -> Self {
        let portable_root = executable_dir.or_else(|| env::current_dir().ok());
        Self {
            mode: StartupMode::PortableNoRetention,
            source,
            portable_root,
        }
    }
}

fn cli_profile_is_portable(args: &[String]) -> bool {
    args.iter().enumerate().any(|(index, arg)| {
        arg == "--profile=portable"
            || (arg == "--profile"
                && args
                    .get(index + 1)
                    .is_some_and(|value| value.eq_ignore_ascii_case("portable")))
    })
}

fn portable_marker_exists(executable_dir: Option<&Path>) -> bool {
    let Some(executable_dir) = executable_dir else {
        return false;
    };
    executable_dir
        .join(PORTABLE_PROFILE_MARKER_FILE_NAME)
        .is_file()
        || executable_dir
            .join("resources")
            .join(PORTABLE_PROFILE_MARKER_FILE_NAME)
            .is_file()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupAuditRecord {
    pub startup_mode: StartupMode,
    pub source: StartupModeSource,
    pub demo_data_enabled: bool,
    pub portable_mode_enabled: bool,
    pub capture_attempted: bool,
    pub elevated_service_connection_attempted: bool,
    pub privileged_actions_enabled: bool,
    pub persistence_attempted: bool,
}

impl StartupAuditRecord {
    pub fn from_config(config: &DemoStartupConfig) -> Self {
        Self {
            startup_mode: config.mode,
            source: config.source,
            demo_data_enabled: config.is_demo(),
            portable_mode_enabled: config.is_portable(),
            capture_attempted: false,
            elevated_service_connection_attempted: false,
            privileged_actions_enabled: false,
            persistence_attempted: config.is_demo(),
        }
    }

    pub fn log_to_console(&self) {
        println!("STARTUP_MODE={}", self.startup_mode.as_str());
        println!(
            "STARTUP_AUDIT mode={} source={} demo_data_enabled={} portable_mode_enabled={} capture_attempted={} elevated_service_connection_attempted={} privileged_actions_enabled={} persistence_attempted={}",
            self.startup_mode.as_str(),
            self.source.as_str(),
            self.demo_data_enabled,
            self.portable_mode_enabled,
            self.capture_attempted,
            self.elevated_service_connection_attempted,
            self.privileged_actions_enabled,
            self.persistence_attempted,
        );

        match self.startup_mode {
            StartupMode::Demo => {
                println!(
                    "STARTUP_DEMO_SAFE_DEFAULTS real_capture=disabled elevated_service=disabled raw_payload_persistence=disabled"
                );
            }
            StartupMode::PortableNoRetention => {
                println!(
                    "STARTUP_PORTABLE_NO_RETENTION raw_payload_persistence=disabled security_history_persistence=disabled explicit_export_only=true"
                );
            }
            StartupMode::Normal => {
                eprintln!(
                    "STARTUP_DEGRADED elevated service IPC is not initialized in Task 520; read-only Local Core remains available"
                );
            }
        }
    }
}

pub fn read_only_invoke_handler<R: tauri::Runtime>(
) -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        list_components,
        get_component_detail,
        get_plugin_catalog,
        get_plugin_manifest,
        get_capability_overview,
        search_findings,
        search_alerts,
        search_incidents,
        get_incident_detail,
        search_flows,
        search_dns,
        search_tls,
        get_graph_view,
        list_active_responses,
        search_response_plans,
        list_reports,
        search_reports,
        get_report,
        get_attack_coverage_summary,
        get_fusion_summary,
        list_security_facts,
        list_attack_hypotheses,
        get_attack_hypothesis,
        get_durable_baseline_summary,
        get_evidence_quality_summary,
        list_evidence_quality_records,
        get_evidence_quality_record,
        get_investigation_drill_down_summary,
        resolve_navigation_reference,
        get_hypothesis_explanation_detail,
        get_baseline_drill_down_detail,
        get_incident_group_investigation_detail,
        get_timeline_drill_down_detail,
        get_source_reliability_explanation,
        list_baseline_records,
        get_baseline_record,
        list_baseline_indicators,
        get_baseline_indicator,
        list_incident_linked_hypothesis_groups,
        get_incident_linked_hypothesis_group,
        list_incident_timeline_entries,
        get_incident_timeline_entry,
        list_source_reliability_summaries,
        get_metadata_watch_controller_status,
        list_metadata_watch_sources,
        get_metadata_watch_source,
        list_metadata_sampling_batches,
        get_metadata_sampling_batch,
        list_export_history,
        get_export_history_record,
        list_export_policy_violations,
        get_runtime_profile,
        get_llm_alert_story_status,
        list_llm_alert_stories,
        get_llm_alert_story,
        get_service_status,
        list_authorized_native_capabilities,
        get_authorized_native_capability,
        get_native_permission_status_summary,
        get_native_visibility_summary,
        get_native_permission_audit_summary,
        list_native_sampler_contracts,
        get_native_sampler_contract,
        get_native_sampler_readiness_summary,
        get_native_sampler_readiness_detail,
        get_native_sampler_authorization_review,
        get_future_security_fact_mapping_summary,
        get_native_sampler_blocked_summary,
        get_missing_endpoint_visibility_summary,
        get_edr_readiness_summary,
        get_native_sampler_runtime_summary,
        get_native_sampler_runtime_status,
        get_latest_native_sampler_runtime_batch,
        get_native_scheduler_status,
        list_native_sampler_schedule_statuses,
        get_native_sampler_schedule_status,
        get_native_scheduler_summary,
        get_native_scheduler_operational_summary,
        list_native_scheduler_cycles,
        get_latest_native_scheduler_cycle,
        get_portable_preferences
    ]
}

pub fn mutation_invoke_handler<R: tauri::Runtime>(
) -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        enable_plugin,
        disable_plugin,
        restart_plugin,
        suppress_finding,
        dismiss_finding,
        escalate_alert,
        update_incident_status,
        create_response_plan,
        approve_response_action,
        reject_response_action,
        rollback_response_action,
        generate_incident_report,
        export_report,
        get_local_metadata_proxy_status,
        start_local_metadata_proxy,
        stop_local_metadata_proxy,
        drain_local_metadata_proxy,
        preview_portable_capture_import,
        confirm_portable_capture_import,
        preview_metadata_watch_source,
        confirm_metadata_watch_source,
        update_metadata_watch_source,
        tick_metadata_watch_controller,
        update_metadata_sampling_loop,
        run_metadata_sampling_loop,
        preview_explicit_export,
        confirm_explicit_export,
        apply_runtime_profile,
        update_privacy_policy,
        update_response_policy,
        enable_forensic_mode,
        disable_forensic_mode,
        update_llm_alert_story_settings,
        save_llm_alert_story_api_key,
        clear_llm_alert_story_api_key,
        test_llm_alert_story_connection,
        generate_llm_alert_story,
        preview_native_permission_request,
        update_native_permission,
        preview_native_sampler_activation,
        apply_native_sampler_runtime_action,
        preview_native_scheduler_enablement,
        apply_native_scheduler_action,
        tick_native_scheduler,
        run_demo_story,
        save_portable_preferences,
        shutdown_app
    ]
}

#[derive(Debug)]
pub struct DesktopReadState {
    core: Mutex<ReadOnlyCommandState>,
}

impl DesktopReadState {
    pub fn bootstrap() -> CommandResult<Self> {
        Ok(Self {
            core: Mutex::new(ReadOnlyCommandState::bootstrap()?),
        })
    }

    pub fn bootstrap_with_service_status(service_status: ServiceStatusView) -> CommandResult<Self> {
        Ok(Self {
            core: Mutex::new(
                ReadOnlyCommandState::bootstrap()?.with_service_status(service_status),
            ),
        })
    }

    pub fn from_core(core: ReadOnlyCommandState) -> Self {
        Self {
            core: Mutex::new(core),
        }
    }

    pub fn with_core<T>(
        &self,
        read: impl FnOnce(&ReadOnlyCommandState) -> CommandResult<T>,
    ) -> CommandResult<T> {
        let core = self.core.lock().map_err(|_| read_state_lock_error())?;
        read(&core)
    }

    pub fn snapshot_core(&self) -> CommandResult<ReadOnlyCommandState> {
        let core = self.core.lock().map_err(|_| read_state_lock_error())?;
        Ok(core.clone())
    }

    pub fn replace_core(&self, read_state: ReadOnlyCommandState) -> CommandResult<()> {
        let mut core = self.core.lock().map_err(|_| read_state_lock_error())?;
        *core = read_state;
        Ok(())
    }

    pub fn install_demo_read_model(
        &self,
        read_model: core::DemoStoryReadModel,
    ) -> CommandResult<ReadOnlyCommandState> {
        let mut core = self.core.lock().map_err(|_| read_state_lock_error())?;
        let updated = read_model.into_read_state(core.clone());
        *core = updated.clone();
        Ok(updated)
    }

    pub fn list_components(&self) -> CommandResult<Vec<ComponentSummary>> {
        self.with_core(core::list_components)
    }

    pub fn get_component_detail(
        &self,
        component_id: ComponentId,
    ) -> CommandResult<ComponentDetail> {
        self.with_core(|core| core::get_component_detail(core, component_id))
    }

    pub fn search_components(
        &self,
        request: QueryRequest,
    ) -> CommandResult<PageResponse<ComponentSummary>> {
        self.with_core(|core| core::search_components(core, request))
    }

    pub fn get_plugin_catalog(&self) -> CommandResult<PluginCatalogView> {
        self.with_core(core::get_plugin_catalog)
    }

    pub fn get_plugin_manifest(&self, plugin_id: PluginId) -> CommandResult<PluginManifest> {
        self.with_core(|core| core::get_plugin_manifest(core, plugin_id))
    }

    pub fn search_plugins(
        &self,
        request: QueryRequest,
    ) -> CommandResult<PageResponse<PluginManifest>> {
        self.with_core(|core| core::search_plugins(core, request))
    }

    pub fn get_capability_overview(&self) -> CommandResult<Vec<CapabilityOverview>> {
        self.with_core(core::get_capability_overview)
    }

    pub fn search_capabilities(
        &self,
        request: QueryRequest,
    ) -> CommandResult<PageResponse<CapabilityOverview>> {
        self.with_core(|core| core::search_capabilities(core, request))
    }

    pub fn search_findings(&self, request: QueryRequest) -> CommandResult<PageResponse<Finding>> {
        self.with_core(|core| core::search_findings(core, request))
    }

    pub fn search_alerts(&self, request: QueryRequest) -> CommandResult<PageResponse<Alert>> {
        self.with_core(|core| core::search_alerts(core, request))
    }

    pub fn search_incidents(&self, request: QueryRequest) -> CommandResult<PageResponse<Incident>> {
        self.with_core(|core| core::search_incidents(core, request))
    }

    pub fn get_incident_detail(
        &self,
        incident_id: IncidentId,
    ) -> CommandResult<IncidentDetailView> {
        self.with_core(|core| core::get_incident_detail(core, incident_id))
    }

    pub fn search_flows(&self, request: QueryRequest) -> CommandResult<PageResponse<FlowRecord>> {
        self.with_core(|core| core::search_flows(core, request))
    }

    pub fn search_dns(&self, request: QueryRequest) -> CommandResult<PageResponse<DnsObservation>> {
        self.with_core(|core| core::search_dns(core, request))
    }

    pub fn search_tls(&self, request: QueryRequest) -> CommandResult<PageResponse<TlsObservation>> {
        self.with_core(|core| core::search_tls(core, request))
    }

    pub fn get_graph_view(&self, request: GraphViewRequest) -> CommandResult<GraphViewModel> {
        self.with_core(|core| core::get_graph_view(core, request))
    }

    pub fn list_active_responses(
        &self,
        page: PageRequest,
    ) -> CommandResult<PageResponse<ResponsePlan>> {
        self.with_core(|core| core::list_active_responses(core, page))
    }

    pub fn search_response_plans(
        &self,
        request: QueryRequest,
    ) -> CommandResult<PageResponse<ResponsePlan>> {
        self.with_core(|core| core::search_response_plans(core, request))
    }

    pub fn list_reports(&self, page: PageRequest) -> CommandResult<PageResponse<Report>> {
        self.with_core(|core| core::list_reports(core, page))
    }

    pub fn search_reports(&self, request: QueryRequest) -> CommandResult<PageResponse<Report>> {
        self.with_core(|core| core::search_reports(core, request))
    }

    pub fn get_report(&self, report_id: ReportId) -> CommandResult<Report> {
        self.with_core(|core| core::get_report(core, report_id))
    }

    pub fn get_attack_coverage_summary(&self) -> CommandResult<AttackCoverageSummary> {
        self.with_core(core::get_attack_coverage_summary)
    }

    pub fn get_fusion_summary(&self) -> CommandResult<FusionSummary> {
        self.with_core(core::get_fusion_summary)
    }

    pub fn list_security_facts(
        &self,
        page: PageRequest,
    ) -> CommandResult<PageResponse<SecurityFact>> {
        self.with_core(|core| core::list_security_facts(core, page))
    }

    pub fn list_attack_hypotheses(
        &self,
        page: PageRequest,
    ) -> CommandResult<PageResponse<AttackHypothesisRecord>> {
        self.with_core(|core| core::list_attack_hypotheses(core, page))
    }

    pub fn get_attack_hypothesis(
        &self,
        hypothesis_id: AttackHypothesisId,
    ) -> CommandResult<AttackHypothesisRecord> {
        self.with_core(|core| core::get_attack_hypothesis(core, hypothesis_id))
    }

    pub fn get_durable_baseline_summary(&self) -> CommandResult<DurableBaselineSummary> {
        self.with_core(core::get_durable_baseline_summary)
    }

    pub fn get_evidence_quality_summary(&self) -> CommandResult<EvidenceQualitySummary> {
        self.with_core(core::get_evidence_quality_summary)
    }

    pub fn list_evidence_quality_records(
        &self,
        page: PageRequest,
    ) -> CommandResult<PageResponse<EvidenceQualityRecord>> {
        self.with_core(|core| core::list_evidence_quality_records(core, page))
    }

    pub fn get_evidence_quality_record(
        &self,
        evidence_quality_id: EvidenceQualityId,
    ) -> CommandResult<EvidenceQualityRecord> {
        self.with_core(|core| core::get_evidence_quality_record(core, evidence_quality_id))
    }

    pub fn get_investigation_drill_down_summary(
        &self,
    ) -> CommandResult<InvestigationDrillDownSummary> {
        self.with_core(core::get_investigation_drill_down_summary)
    }

    pub fn resolve_navigation_reference(
        &self,
        request: NavigationResolveRequest,
    ) -> CommandResult<NavigationResolution> {
        self.with_core(|core| core::resolve_navigation_reference(core, request))
    }

    pub fn get_hypothesis_explanation_detail(
        &self,
        hypothesis_id: AttackHypothesisId,
    ) -> CommandResult<HypothesisExplanationDetail> {
        self.with_core(|core| core::get_hypothesis_explanation_detail(core, hypothesis_id))
    }

    pub fn get_baseline_drill_down_detail(
        &self,
        baseline_id: BaselineRecordId,
    ) -> CommandResult<BaselineDrillDownDetail> {
        self.with_core(|core| core::get_baseline_drill_down_detail(core, baseline_id))
    }

    pub fn get_incident_group_investigation_detail(
        &self,
        group_id: IncidentLinkedGroupId,
    ) -> CommandResult<IncidentGroupInvestigationDetail> {
        self.with_core(|core| core::get_incident_group_investigation_detail(core, group_id))
    }

    pub fn get_timeline_drill_down_detail(
        &self,
        timeline_entry_id: IncidentTimelineEntryId,
    ) -> CommandResult<TimelineDrillDownDetail> {
        self.with_core(|core| core::get_timeline_drill_down_detail(core, timeline_entry_id))
    }

    pub fn get_source_reliability_explanation(
        &self,
        source_id: MetadataWatchSourceId,
    ) -> CommandResult<SourceReliabilityExplanation> {
        self.with_core(|core| core::get_source_reliability_explanation(core, source_id))
    }

    pub fn list_baseline_records(
        &self,
        page: PageRequest,
    ) -> CommandResult<PageResponse<BaselineRecord>> {
        self.with_core(|core| core::list_baseline_records(core, page))
    }

    pub fn get_baseline_record(
        &self,
        baseline_id: BaselineRecordId,
    ) -> CommandResult<BaselineRecord> {
        self.with_core(|core| core::get_baseline_record(core, baseline_id))
    }

    pub fn list_baseline_indicators(
        &self,
        page: PageRequest,
    ) -> CommandResult<PageResponse<BaselineIndicator>> {
        self.with_core(|core| core::list_baseline_indicators(core, page))
    }

    pub fn get_baseline_indicator(
        &self,
        indicator_id: BaselineIndicatorId,
    ) -> CommandResult<BaselineIndicator> {
        self.with_core(|core| core::get_baseline_indicator(core, indicator_id))
    }

    pub fn list_incident_linked_hypothesis_groups(
        &self,
        page: PageRequest,
    ) -> CommandResult<PageResponse<IncidentLinkedHypothesisGroup>> {
        self.with_core(|core| core::list_incident_linked_hypothesis_groups(core, page))
    }

    pub fn get_incident_linked_hypothesis_group(
        &self,
        group_id: IncidentLinkedGroupId,
    ) -> CommandResult<IncidentLinkedHypothesisGroup> {
        self.with_core(|core| core::get_incident_linked_hypothesis_group(core, group_id))
    }

    pub fn list_incident_timeline_entries(
        &self,
        page: PageRequest,
    ) -> CommandResult<PageResponse<IncidentTimelineEntry>> {
        self.with_core(|core| core::list_incident_timeline_entries(core, page))
    }

    pub fn get_incident_timeline_entry(
        &self,
        timeline_entry_id: IncidentTimelineEntryId,
    ) -> CommandResult<IncidentTimelineEntry> {
        self.with_core(|core| core::get_incident_timeline_entry(core, timeline_entry_id))
    }

    pub fn list_source_reliability_summaries(
        &self,
        page: PageRequest,
    ) -> CommandResult<PageResponse<SourceReliabilitySummary>> {
        self.with_core(|core| core::list_source_reliability_summaries(core, page))
    }

    pub fn get_metadata_watch_controller_status(
        &self,
    ) -> CommandResult<MetadataWatchControllerStatus> {
        self.with_core(core::get_metadata_watch_controller_status)
    }

    pub fn list_metadata_watch_sources(
        &self,
        page: PageRequest,
    ) -> CommandResult<PageResponse<MetadataWatchSourceStatus>> {
        self.with_core(|core| core::list_metadata_watch_sources(core, page))
    }

    pub fn get_metadata_watch_source(
        &self,
        source_id: MetadataWatchSourceId,
    ) -> CommandResult<MetadataWatchSourceStatus> {
        self.with_core(|core| core::get_metadata_watch_source(core, source_id))
    }

    pub fn list_metadata_sampling_batches(
        &self,
        page: PageRequest,
    ) -> CommandResult<PageResponse<MetadataSamplingBatchSummary>> {
        self.with_core(|core| core::list_metadata_sampling_batches(core, page))
    }

    pub fn get_metadata_sampling_batch(
        &self,
        batch_id: MetadataSamplingBatchId,
    ) -> CommandResult<MetadataSamplingBatchSummary> {
        self.with_core(|core| core::get_metadata_sampling_batch(core, batch_id))
    }

    pub fn list_llm_alert_stories(
        &self,
        page: PageRequest,
    ) -> CommandResult<PageResponse<LlmAlertStoryRecord>> {
        self.with_core(|core| core::list_llm_alert_stories(core, page))
    }

    pub fn get_llm_alert_story(
        &self,
        story_id: LlmAlertStoryId,
    ) -> CommandResult<LlmAlertStoryRecord> {
        self.with_core(|core| core::get_llm_alert_story(core, story_id))
    }

    pub fn list_export_history(
        &self,
        query: ReportExportHistoryQuery,
    ) -> CommandResult<PageResponse<ExportHistoryRecord>> {
        self.with_core(|core| core::list_export_history(core, query))
    }

    pub fn search_export_history(
        &self,
        request: QueryRequest,
    ) -> CommandResult<PageResponse<ExportHistoryRecord>> {
        self.with_core(|core| core::search_export_history(core, request))
    }

    pub fn get_export_history_record(
        &self,
        export_result_id: ExportResultId,
    ) -> CommandResult<ExportHistoryRecord> {
        self.with_core(|core| core::get_export_history_record(core, export_result_id))
    }

    pub fn list_export_policy_violations(&self) -> CommandResult<Vec<ExportPolicyViolation>> {
        self.with_core(core::list_export_policy_violations)
    }

    pub fn get_runtime_profile(&self) -> CommandResult<RuntimeProfile> {
        self.with_core(core::get_runtime_profile)
    }

    pub fn search_runtime_profiles(
        &self,
        request: QueryRequest,
    ) -> CommandResult<PageResponse<RuntimeProfile>> {
        self.with_core(|core| core::search_runtime_profiles(core, request))
    }

    pub fn get_service_status(&self) -> CommandResult<ServiceStatusView> {
        self.with_core(core::get_service_status)
    }

    pub fn search_service_status(
        &self,
        request: QueryRequest,
    ) -> CommandResult<PageResponse<ServiceStatusView>> {
        self.with_core(|core| core::search_service_status(core, request))
    }

    pub fn list_authorized_native_capabilities(
        &self,
    ) -> CommandResult<Vec<AuthorizedNativeCapabilityStatus>> {
        self.with_core(core::list_authorized_native_capabilities)
    }

    pub fn get_authorized_native_capability(
        &self,
        capability_id: String,
    ) -> CommandResult<AuthorizedNativeCapabilityStatus> {
        self.with_core(|core| core::get_authorized_native_capability(core, capability_id))
    }

    pub fn get_native_permission_status_summary(
        &self,
    ) -> CommandResult<NativePermissionStatusSummary> {
        self.with_core(core::get_native_permission_status_summary)
    }

    pub fn get_native_visibility_summary(&self) -> CommandResult<NativeVisibilitySummary> {
        self.with_core(core::get_native_visibility_summary)
    }

    pub fn get_native_permission_audit_summary(
        &self,
    ) -> CommandResult<NativePermissionAuditSummary> {
        self.with_core(core::get_native_permission_audit_summary)
    }

    pub fn list_native_sampler_contracts(&self) -> CommandResult<Vec<NativeSamplerContract>> {
        self.with_core(core::list_native_sampler_contracts)
    }

    pub fn get_native_sampler_contract(
        &self,
        sampler_id: String,
    ) -> CommandResult<NativeSamplerContract> {
        self.with_core(|core| core::get_native_sampler_contract(core, sampler_id))
    }

    pub fn get_native_sampler_readiness_summary(
        &self,
    ) -> CommandResult<NativeSamplerReadinessSummary> {
        self.with_core(core::get_native_sampler_readiness_summary)
    }

    pub fn get_native_sampler_readiness_detail(
        &self,
        sampler_id: String,
    ) -> CommandResult<NativeSamplerReadinessDetail> {
        self.with_core(|core| core::get_native_sampler_readiness_detail(core, sampler_id))
    }

    pub fn get_native_sampler_authorization_review(
        &self,
        sampler_id: String,
    ) -> CommandResult<NativeSamplerAuthorizationReview> {
        self.with_core(|core| core::get_native_sampler_authorization_review(core, sampler_id))
    }

    pub fn get_future_security_fact_mapping_summary(
        &self,
    ) -> CommandResult<FutureSecurityFactMappingSummary> {
        self.with_core(core::get_future_security_fact_mapping_summary)
    }

    pub fn get_native_sampler_blocked_summary(&self) -> CommandResult<NativeSamplerBlockedSummary> {
        self.with_core(core::get_native_sampler_blocked_summary)
    }

    pub fn get_missing_endpoint_visibility_summary(
        &self,
    ) -> CommandResult<MissingEndpointVisibilitySummary> {
        self.with_core(core::get_missing_endpoint_visibility_summary)
    }

    pub fn get_edr_readiness_summary(&self) -> CommandResult<EdrReadinessSummary> {
        self.with_core(core::get_edr_readiness_summary)
    }

    pub fn get_native_sampler_runtime_summary(&self) -> CommandResult<NativeSamplerRuntimeSummary> {
        self.with_core(core::get_native_sampler_runtime_summary)
    }

    pub fn get_native_sampler_runtime_status(
        &self,
        sampler_id: String,
    ) -> CommandResult<NativeSamplerRuntimeStatus> {
        self.with_core(|core| core::get_native_sampler_runtime_status(core, sampler_id))
    }

    pub fn get_latest_native_sampler_runtime_batch(
        &self,
        sampler_id: String,
    ) -> CommandResult<Option<NativeSamplerRuntimeBatch>> {
        self.with_core(|core| core::get_latest_native_sampler_runtime_batch(core, sampler_id))
    }

    pub fn get_native_scheduler_status(&self) -> CommandResult<NativeSchedulerStatus> {
        self.with_core(core::get_native_scheduler_status)
    }

    pub fn list_native_sampler_schedule_statuses(
        &self,
    ) -> CommandResult<Vec<NativeSamplerScheduleStatus>> {
        self.with_core(core::list_native_sampler_schedule_statuses)
    }

    pub fn get_native_sampler_schedule_status(
        &self,
        sampler_id: String,
    ) -> CommandResult<NativeSamplerScheduleStatus> {
        self.with_core(|core| core::get_native_sampler_schedule_status(core, sampler_id))
    }

    pub fn get_native_scheduler_summary(&self) -> CommandResult<NativeSchedulerSummary> {
        self.with_core(core::get_native_scheduler_summary)
    }

    pub fn get_native_scheduler_operational_summary(
        &self,
    ) -> CommandResult<NativeSchedulerOperationalSummary> {
        self.with_core(core::get_native_scheduler_operational_summary)
    }

    pub fn list_native_scheduler_cycles(&self) -> CommandResult<Vec<NativeSchedulerCycleSummary>> {
        self.with_core(core::list_native_scheduler_cycles)
    }

    pub fn get_latest_native_scheduler_cycle(
        &self,
    ) -> CommandResult<Option<NativeSchedulerCycleSummary>> {
        self.with_core(core::get_latest_native_scheduler_cycle)
    }
}

pub struct DesktopMutationState {
    core: Mutex<MutationCommandState>,
}

impl DesktopMutationState {
    pub fn bootstrap() -> CommandResult<Self> {
        Ok(Self {
            core: Mutex::new(MutationCommandState::bootstrap()?),
        })
    }

    pub fn from_core(core: MutationCommandState) -> Self {
        Self {
            core: Mutex::new(core),
        }
    }

    pub fn with_core<T>(
        &self,
        mutation: impl FnOnce(&mut MutationCommandState) -> CommandResult<T>,
    ) -> CommandResult<T> {
        let mut core = self.core.lock().map_err(|_| mutation_state_lock_error())?;
        mutation(&mut core)
    }

    pub fn replace_from_read_state(&self, read_state: ReadOnlyCommandState) -> CommandResult<()> {
        let mut core = self.core.lock().map_err(|_| mutation_state_lock_error())?;
        *core = MutationCommandState::from_read_state(read_state)?;
        Ok(())
    }

    pub fn snapshot_read_state(&self) -> CommandResult<ReadOnlyCommandState> {
        self.with_core(|state| Ok(state.read_state().clone()))
    }

    pub fn enable_plugin(
        &self,
        request: PluginLifecycleRequest,
    ) -> CommandResult<MutationReceipt<PluginLifecycleMutationResult>> {
        self.with_core(|state| core::enable_plugin(state, request))
    }

    pub fn disable_plugin(
        &self,
        request: PluginLifecycleRequest,
    ) -> CommandResult<MutationReceipt<PluginLifecycleMutationResult>> {
        self.with_core(|state| core::disable_plugin(state, request))
    }

    pub fn restart_plugin(
        &self,
        request: PluginLifecycleRequest,
    ) -> CommandResult<MutationReceipt<PluginLifecycleMutationResult>> {
        self.with_core(|state| core::restart_plugin(state, request))
    }

    pub fn suppress_finding(
        &self,
        request: FindingStateMutationRequest,
    ) -> CommandResult<MutationReceipt<FindingStateMutationResult>> {
        self.with_core(|state| core::suppress_finding(state, request))
    }

    pub fn dismiss_finding(
        &self,
        request: FindingStateMutationRequest,
    ) -> CommandResult<MutationReceipt<FindingStateMutationResult>> {
        self.with_core(|state| core::dismiss_finding(state, request))
    }

    pub fn escalate_alert(
        &self,
        request: EscalateAlertRequest,
    ) -> CommandResult<MutationReceipt<AlertEscalationResult>> {
        self.with_core(|state| core::escalate_alert(state, request))
    }

    pub fn update_incident_status(
        &self,
        request: IncidentStatusMutationRequest,
    ) -> CommandResult<MutationReceipt<IncidentStatusMutationResult>> {
        self.with_core(|state| core::update_incident_status(state, request))
    }

    pub fn create_response_plan(
        &self,
        request: CreateResponsePlanRequest,
    ) -> CommandResult<MutationReceipt<ResponsePlanMutationResult>> {
        self.with_core(|state| core::create_response_plan(state, request))
    }

    pub fn approve_response_action(
        &self,
        request: ResponseApprovalMutationRequest,
    ) -> CommandResult<MutationReceipt<ResponseApprovalMutationResult>> {
        self.with_core(|state| core::approve_response_action(state, request))
    }

    pub fn reject_response_action(
        &self,
        request: ResponseApprovalMutationRequest,
    ) -> CommandResult<MutationReceipt<ResponseApprovalMutationResult>> {
        self.with_core(|state| core::reject_response_action(state, request))
    }

    pub fn rollback_response_action(
        &self,
        request: RollbackResponseActionRequest,
    ) -> CommandResult<MutationReceipt<RollbackResponseActionResult>> {
        self.with_core(|state| core::rollback_response_action(state, request))
    }

    pub fn generate_incident_report(
        &self,
        request: GenerateIncidentReportRequest,
    ) -> CommandResult<MutationReceipt<ReportGenerationResult>> {
        self.with_core(|state| core::generate_incident_report(state, request))
    }

    pub fn export_report(
        &self,
        request: ExportReportRequest,
    ) -> CommandResult<MutationReceipt<ExportReportMutationResult>> {
        self.with_core(|state| core::export_report(state, request))
    }

    pub fn record_llm_alert_story(&self, story: LlmAlertStoryRecord) -> CommandResult<()> {
        self.with_core(|state| state.record_llm_alert_story(story))
    }

    pub fn preview_native_permission_request(
        &self,
        capability_id: String,
    ) -> CommandResult<NativePermissionPreview> {
        self.with_core(|state| state.preview_native_permission_request(capability_id))
    }

    pub fn update_native_permission(
        &self,
        request: NativePermissionActionRequest,
    ) -> CommandResult<NativePermissionActionResult> {
        self.with_core(|state| state.update_native_permission(request))
    }

    pub fn preview_native_sampler_activation(
        &self,
        sampler_id: String,
    ) -> CommandResult<NativeSamplerActivationPreview> {
        self.with_core(|state| state.preview_native_sampler_activation(sampler_id))
    }

    pub fn apply_native_sampler_runtime_action(
        &self,
        request: NativeSamplerRuntimeActionRequest,
    ) -> CommandResult<NativeSamplerRuntimeActionResult> {
        self.with_core(|state| state.apply_native_sampler_runtime_action(request))
    }

    pub fn preview_native_scheduler_enablement(
        &self,
        sampler_id: String,
    ) -> CommandResult<NativeSchedulerEnablementPreview> {
        self.with_core(|state| state.preview_native_scheduler_enablement(sampler_id))
    }

    pub fn apply_native_scheduler_action(
        &self,
        request: NativeSchedulerActionRequest,
    ) -> CommandResult<NativeSchedulerActionResult> {
        self.with_core(|state| state.apply_native_scheduler_action(request))
    }

    pub fn tick_native_scheduler(
        &self,
        request: NativeSchedulerTickRequest,
    ) -> CommandResult<NativeSchedulerCycleSummary> {
        self.with_core(|state| state.tick_native_scheduler(request))
    }

    pub fn get_local_metadata_proxy_status(
        &self,
    ) -> CommandResult<LocalProxyMetadataProviderStatus> {
        self.with_core(|state| Ok(state.get_local_metadata_proxy_status()))
    }

    pub fn start_local_metadata_proxy(
        &self,
        request: LocalProxyMetadataStartRequest,
    ) -> CommandResult<LocalProxyMetadataProviderStatus> {
        self.with_core(|state| state.start_local_metadata_proxy(request))
    }

    pub fn stop_local_metadata_proxy(&self) -> CommandResult<LocalProxyMetadataProviderStatus> {
        self.with_core(|state| state.stop_local_metadata_proxy())
    }

    pub fn drain_local_metadata_proxy(&self) -> CommandResult<LocalProxyMetadataProviderStatus> {
        self.with_core(|state| state.drain_local_metadata_proxy())
    }

    pub fn confirm_portable_capture_import(
        &self,
        prepared: &PreparedPortableCaptureImport,
        confirmation: PortableCaptureImportConfirmation,
    ) -> CommandResult<MutationReceipt<PortableCaptureImportResult>> {
        self.with_core(|state| core::confirm_portable_capture_import(state, prepared, confirmation))
    }

    pub fn preview_metadata_watch_source(
        &self,
        request: MetadataWatchSourcePreviewRequest,
    ) -> CommandResult<MetadataWatchSourcePreview> {
        self.with_core(|state| core::preview_metadata_watch_source(state, request))
    }

    pub fn confirm_metadata_watch_source(
        &self,
        confirmation: MetadataWatchSourceConfirmation,
    ) -> CommandResult<MutationReceipt<MetadataWatchControllerStatus>> {
        self.with_core(|state| core::confirm_metadata_watch_source(state, confirmation))
    }

    pub fn update_metadata_watch_source(
        &self,
        request: MetadataWatchLifecycleRequest,
    ) -> CommandResult<MutationReceipt<MetadataWatchControllerStatus>> {
        self.with_core(|state| core::update_metadata_watch_source(state, request))
    }

    pub fn tick_metadata_watch_controller(
        &self,
        request: MetadataSamplingTickRequest,
    ) -> CommandResult<MutationReceipt<MetadataSamplingTickResult>> {
        self.with_core(|state| core::tick_metadata_watch_controller(state, request))
    }

    pub fn update_metadata_sampling_loop(
        &self,
        request: MetadataSamplingLoopControlRequest,
    ) -> CommandResult<MutationReceipt<MetadataWatchControllerStatus>> {
        self.with_core(|state| core::update_metadata_sampling_loop(state, request))
    }

    pub fn run_metadata_sampling_loop(
        &self,
        request: MetadataSamplingLoopRunRequest,
    ) -> CommandResult<MutationReceipt<MetadataSamplingTickResult>> {
        self.with_core(|state| core::run_metadata_sampling_loop(state, request))
    }

    pub fn apply_runtime_profile(
        &self,
        request: ApplyRuntimeProfileRequest,
    ) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
        self.with_core(|state| core::apply_runtime_profile(state, request))
    }

    pub fn update_privacy_policy(
        &self,
        request: UpdatePrivacyPolicyRequest,
    ) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
        self.with_core(|state| core::update_privacy_policy(state, request))
    }

    pub fn update_response_policy(
        &self,
        request: UpdateResponsePolicyRequest,
    ) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
        self.with_core(|state| core::update_response_policy(state, request))
    }

    pub fn enable_forensic_mode(
        &self,
        request: EnableForensicModeRequest,
    ) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
        self.with_core(|state| core::enable_forensic_mode(state, request))
    }

    pub fn disable_forensic_mode(
        &self,
        request: DisableForensicModeRequest,
    ) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
        self.with_core(|state| core::disable_forensic_mode(state, request))
    }
}

#[derive(Debug)]
pub struct DesktopEventState {
    dispatcher: Mutex<TauriEventDispatcher>,
}

impl DesktopEventState {
    pub fn bootstrap() -> CommandResult<Self> {
        Ok(Self::from_dispatcher(TauriEventDispatcher::default()))
    }

    pub fn with_capacity(max_events: usize) -> CommandResult<Self> {
        Ok(Self::from_dispatcher(TauriEventDispatcher::new(
            max_events,
        )?))
    }

    pub fn from_dispatcher(dispatcher: TauriEventDispatcher) -> Self {
        Self {
            dispatcher: Mutex::new(dispatcher),
        }
    }

    pub fn with_dispatcher<T>(
        &self,
        dispatch: impl FnOnce(&mut TauriEventDispatcher) -> CommandResult<T>,
    ) -> CommandResult<T> {
        let mut dispatcher = self
            .dispatcher
            .lock()
            .map_err(|_| event_state_lock_error())?;
        dispatch(&mut dispatcher)
    }

    pub fn pending_events(&self) -> CommandResult<Vec<StreamEventEnvelope>> {
        self.with_dispatcher(|dispatcher| Ok(dispatcher.pending_events().to_vec()))
    }

    pub fn drain_pending_events(&self) -> CommandResult<Vec<StreamEventEnvelope>> {
        self.with_dispatcher(|dispatcher| Ok(dispatcher.drain()))
    }

    pub fn dropped_count(&self) -> CommandResult<usize> {
        self.with_dispatcher(|dispatcher| Ok(dispatcher.dropped_count()))
    }

    pub fn health_stream(&self, update: HealthStreamUpdate) -> CommandResult<StreamEventEnvelope> {
        self.with_dispatcher(|dispatcher| core::health_stream(dispatcher, update))
    }

    pub fn metric_stream(&self, update: MetricStreamUpdate) -> CommandResult<StreamEventEnvelope> {
        self.with_dispatcher(|dispatcher| core::metric_stream(dispatcher, update))
    }

    pub fn capture_status_stream(
        &self,
        update: CaptureStatusUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        self.with_dispatcher(|dispatcher| core::capture_status_stream(dispatcher, update))
    }

    pub fn service_status_stream(
        &self,
        update: ServiceStatusUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        self.with_dispatcher(|dispatcher| core::service_status_stream(dispatcher, update))
    }

    pub fn alert_stream(&self, update: AlertStreamUpdate) -> CommandResult<StreamEventEnvelope> {
        self.with_dispatcher(|dispatcher| core::alert_stream(dispatcher, update))
    }

    pub fn incident_stream(
        &self,
        update: IncidentStreamUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        self.with_dispatcher(|dispatcher| core::incident_stream(dispatcher, update))
    }

    pub fn graph_update_stream(
        &self,
        update: GraphUpdateStreamUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        self.with_dispatcher(|dispatcher| core::graph_update_stream(dispatcher, update))
    }

    pub fn response_status_stream(
        &self,
        update: ResponseStatusUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        self.with_dispatcher(|dispatcher| core::response_status_stream(dispatcher, update))
    }

    pub fn report_progress_stream(
        &self,
        update: ReportProgressUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        self.with_dispatcher(|dispatcher| core::report_progress_stream(dispatcher, update))
    }

    pub fn privacy_warning_stream(
        &self,
        update: PrivacyWarningUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        self.with_dispatcher(|dispatcher| core::privacy_warning_stream(dispatcher, update))
    }

    pub fn emit_health_stream<R: tauri::Runtime, E: Emitter<R>>(
        &self,
        emitter: &E,
        update: HealthStreamUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        let envelope = self.health_stream(update)?;
        emit_tauri_stream_event(emitter, &envelope)?;
        Ok(envelope)
    }

    pub fn emit_metric_stream<R: tauri::Runtime, E: Emitter<R>>(
        &self,
        emitter: &E,
        update: MetricStreamUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        let envelope = self.metric_stream(update)?;
        emit_tauri_stream_event(emitter, &envelope)?;
        Ok(envelope)
    }

    pub fn emit_capture_status_stream<R: tauri::Runtime, E: Emitter<R>>(
        &self,
        emitter: &E,
        update: CaptureStatusUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        let envelope = self.capture_status_stream(update)?;
        emit_tauri_stream_event(emitter, &envelope)?;
        Ok(envelope)
    }

    pub fn emit_service_status_stream<R: tauri::Runtime, E: Emitter<R>>(
        &self,
        emitter: &E,
        update: ServiceStatusUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        let envelope = self.service_status_stream(update)?;
        emit_tauri_stream_event(emitter, &envelope)?;
        Ok(envelope)
    }

    pub fn emit_alert_stream<R: tauri::Runtime, E: Emitter<R>>(
        &self,
        emitter: &E,
        update: AlertStreamUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        let envelope = self.alert_stream(update)?;
        emit_tauri_stream_event(emitter, &envelope)?;
        Ok(envelope)
    }

    pub fn emit_incident_stream<R: tauri::Runtime, E: Emitter<R>>(
        &self,
        emitter: &E,
        update: IncidentStreamUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        let envelope = self.incident_stream(update)?;
        emit_tauri_stream_event(emitter, &envelope)?;
        Ok(envelope)
    }

    pub fn emit_graph_update_stream<R: tauri::Runtime, E: Emitter<R>>(
        &self,
        emitter: &E,
        update: GraphUpdateStreamUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        let envelope = self.graph_update_stream(update)?;
        emit_tauri_stream_event(emitter, &envelope)?;
        Ok(envelope)
    }

    pub fn emit_response_status_stream<R: tauri::Runtime, E: Emitter<R>>(
        &self,
        emitter: &E,
        update: ResponseStatusUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        let envelope = self.response_status_stream(update)?;
        emit_tauri_stream_event(emitter, &envelope)?;
        Ok(envelope)
    }

    pub fn emit_report_progress_stream<R: tauri::Runtime, E: Emitter<R>>(
        &self,
        emitter: &E,
        update: ReportProgressUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        let envelope = self.report_progress_stream(update)?;
        emit_tauri_stream_event(emitter, &envelope)?;
        Ok(envelope)
    }

    pub fn emit_privacy_warning_stream<R: tauri::Runtime, E: Emitter<R>>(
        &self,
        emitter: &E,
        update: PrivacyWarningUpdate,
    ) -> CommandResult<StreamEventEnvelope> {
        let envelope = self.privacy_warning_stream(update)?;
        emit_tauri_stream_event(emitter, &envelope)?;
        Ok(envelope)
    }
}

pub struct DesktopStorageState {
    runtime: Option<DatabaseRuntime>,
    degraded_reason_redacted: Option<String>,
    profile_mode: String,
    machine_local_capability_status: Option<core::CapabilityStatusSummary>,
}

impl DesktopStorageState {
    pub fn healthy(runtime: DatabaseRuntime) -> Self {
        let profile_mode = runtime
            .report()
            .profile_mode
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        Self {
            runtime: Some(runtime),
            degraded_reason_redacted: None,
            profile_mode,
            machine_local_capability_status: None,
        }
    }

    pub fn degraded(reason: impl Into<String>) -> Self {
        Self::degraded_with_profile_mode(reason, "unknown")
    }

    pub fn degraded_with_profile_mode(
        reason: impl Into<String>,
        profile_mode: impl Into<String>,
    ) -> Self {
        Self {
            runtime: None,
            degraded_reason_redacted: Some(reason.into()),
            profile_mode: profile_mode.into(),
            machine_local_capability_status: None,
        }
    }

    pub fn with_machine_local_capability_status(
        mut self,
        summary: core::CapabilityStatusSummary,
    ) -> Self {
        self.machine_local_capability_status = Some(summary);
        self
    }

    pub fn machine_local_capability_status(&self) -> Option<&core::CapabilityStatusSummary> {
        self.machine_local_capability_status.as_ref()
    }

    pub fn is_healthy(&self) -> bool {
        self.runtime
            .as_ref()
            .is_some_and(|runtime| !runtime.report().degraded)
    }

    pub fn runtime(&self) -> Option<&DatabaseRuntime> {
        self.runtime.as_ref()
    }

    pub fn get_graph_view(
        &self,
        request: GraphViewRequest,
    ) -> CommandResult<Option<GraphViewModel>> {
        let Some(runtime) = self.runtime() else {
            return Ok(None);
        };
        runtime
            .handle()
            .with_connection(|connection| {
                let stores = SqliteStoreFactory::new(connection);
                core::try_get_graph_view_from_storage(&stores, request).map_err(|error| {
                    StorageError::UnsupportedQuery(format!(
                        "graph view storage read failed: {}",
                        error.message
                    ))
                })
            })
            .map_err(|error| storage_read_error("graph_view", error))
    }

    pub fn persist_demo_read_model(
        &self,
        read_model: &core::DemoStoryReadModel,
    ) -> CommandResult<Option<core::DemoStoryPersistenceSummary>> {
        let Some(runtime) = self.runtime() else {
            return Ok(None);
        };
        runtime
            .handle()
            .with_connection(|connection| {
                let stores = SqliteStoreFactory::new(connection);
                read_model.persist_to_storage(&stores).map_err(|error| {
                    StorageError::UnsupportedQuery(format!(
                        "demo story persistence failed: {}",
                        error.message
                    ))
                })
            })
            .map(Some)
            .map_err(|error| storage_write_error("demo_story", error))
    }

    pub fn load_portable_preferences(&self) -> CommandResult<BTreeMap<String, serde_json::Value>> {
        let Some(runtime) = self.runtime() else {
            return Ok(BTreeMap::new());
        };
        let Some(lifecycle) = runtime.session_lifecycle() else {
            return Ok(BTreeMap::new());
        };
        let Some(mut store) = lifecycle.portable_preferences_store() else {
            return Ok(BTreeMap::new());
        };
        store.load().map_err(portable_preference_error)
    }

    pub fn save_portable_preferences(
        &self,
        preferences: BTreeMap<String, serde_json::Value>,
    ) -> CommandResult<BTreeMap<String, serde_json::Value>> {
        let Some(runtime) = self.runtime() else {
            return Ok(BTreeMap::new());
        };
        let Some(lifecycle) = runtime.session_lifecycle() else {
            return Ok(BTreeMap::new());
        };
        let Some(mut store) = lifecycle.portable_preferences_store() else {
            return Ok(BTreeMap::new());
        };
        for (key, value) in preferences {
            store.set(&key, value).map_err(portable_preference_error)?;
        }
        store.save().map_err(portable_preference_error)?;
        Ok(store.preferences().clone())
    }

    pub fn degraded_reason_redacted(&self) -> Option<&str> {
        self.degraded_reason_redacted.as_deref()
    }

    pub fn profile_mode(&self) -> &str {
        &self.profile_mode
    }

    pub fn end_session(&self) {
        if let Some(runtime) = self.runtime() {
            if let Some(lifecycle) = runtime.session_lifecycle() {
                lifecycle.end();
            }
        }
    }
}

#[derive(Default)]
pub struct DesktopExplicitExportState {
    pending: Mutex<BTreeMap<String, core::PreparedExplicitExport>>,
    active_writes: Mutex<usize>,
}

impl DesktopExplicitExportState {
    pub fn store_pending(
        &self,
        prepared: core::PreparedExplicitExport,
    ) -> CommandResult<ExplicitExportPreview> {
        let preview = prepared.preview.clone();
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| explicit_export_lock_error("pending_exports"))?;
        pending.insert(prepared.request.export_id.to_string(), prepared);
        Ok(preview)
    }

    pub fn take_pending(
        &self,
        export_id: &sentinel_contracts::ExportRequestId,
    ) -> CommandResult<Option<core::PreparedExplicitExport>> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| explicit_export_lock_error("pending_exports"))?;
        Ok(pending.remove(&export_id.to_string()))
    }

    pub fn pending_count(&self) -> CommandResult<usize> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| explicit_export_lock_error("pending_exports"))?;
        Ok(pending.len())
    }

    pub fn has_pending_or_active(&self) -> CommandResult<bool> {
        let pending_count = self.pending_count()?;
        let active_writes = self
            .active_writes
            .lock()
            .map_err(|_| explicit_export_lock_error("active_exports"))?;
        Ok(pending_count > 0 || *active_writes > 0)
    }

    pub fn begin_write(&self) -> CommandResult<ActiveExplicitExportWrite<'_>> {
        let mut active_writes = self
            .active_writes
            .lock()
            .map_err(|_| explicit_export_lock_error("active_exports"))?;
        *active_writes += 1;
        Ok(ActiveExplicitExportWrite { state: self })
    }
}

pub struct ActiveExplicitExportWrite<'state> {
    state: &'state DesktopExplicitExportState,
}

impl Drop for ActiveExplicitExportWrite<'_> {
    fn drop(&mut self) {
        if let Ok(mut active_writes) = self.state.active_writes.lock() {
            *active_writes = active_writes.saturating_sub(1);
        }
    }
}

struct PendingPortableCaptureImport {
    prepared: PreparedPortableCaptureImport,
    preview_artifact_path: PathBuf,
}

#[derive(Default)]
pub struct DesktopPortableCaptureImportState {
    pending: Mutex<BTreeMap<String, PendingPortableCaptureImport>>,
}

impl DesktopPortableCaptureImportState {
    pub fn store_pending(
        &self,
        prepared: PreparedPortableCaptureImport,
        preview_artifact_path: PathBuf,
    ) -> CommandResult<PortableCaptureImportPreview> {
        let preview = prepared.preview.clone();
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| portable_capture_import_lock_error("pending_imports"))?;
        pending.insert(
            preview.preview_id.to_string(),
            PendingPortableCaptureImport {
                prepared,
                preview_artifact_path,
            },
        );
        Ok(preview)
    }

    fn take_pending(
        &self,
        preview_id: &sentinel_contracts::DataSourceId,
    ) -> CommandResult<Option<PendingPortableCaptureImport>> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| portable_capture_import_lock_error("pending_imports"))?;
        Ok(pending.remove(&preview_id.to_string()))
    }

    pub fn discard_all_pending(&self) -> CommandResult<()> {
        let drained = {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| portable_capture_import_lock_error("pending_imports"))?;
            std::mem::take(&mut *pending)
                .into_values()
                .collect::<Vec<_>>()
        };

        for pending in drained {
            remove_portable_capture_preview_artifact(&pending.preview_artifact_path)?;
        }

        Ok(())
    }
}

pub fn emit_tauri_stream_event<R: tauri::Runtime, E: Emitter<R>>(
    emitter: &E,
    envelope: &StreamEventEnvelope,
) -> CommandResult<()> {
    envelope.validate()?;
    emitter
        .emit(envelope.stream.as_str(), envelope.clone())
        .map_err(|error| tauri_emit_error(error, envelope))
}

fn mutation_state_lock_error() -> CoreError {
    CoreError::new(
        ErrorCode::InternalError,
        "desktop mutation state is unavailable",
    )
    .with_severity(ErrorSeverity::Critical)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({
        "context": "desktop_mutation_state",
        "reason_redacted": "mutation state lock poisoned"
    }))
}

fn read_state_lock_error() -> CoreError {
    CoreError::new(
        ErrorCode::InternalError,
        "desktop read state is unavailable",
    )
    .with_severity(ErrorSeverity::Critical)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({
        "context": "desktop_read_state",
        "reason_redacted": "read state lock poisoned"
    }))
}

fn storage_read_error(context: &'static str, error: StorageError) -> CoreError {
    CoreError::new(
        ErrorCode::StorageUnavailable,
        "desktop storage read is unavailable",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({
        "context": context,
        "error_redacted": error.to_string()
    }))
}

fn storage_write_error(context: &'static str, error: StorageError) -> CoreError {
    CoreError::new(
        ErrorCode::StorageUnavailable,
        "desktop storage write is unavailable",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({
    "context": context,
    "error_redacted": error.to_string()
    }))
}

fn explicit_export_lock_error(context: &'static str) -> CoreError {
    CoreError::new(
        ErrorCode::InternalError,
        "explicit export state is unavailable",
    )
    .with_severity(ErrorSeverity::Critical)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({
        "context": context,
        "reason_redacted": "explicit export state lock poisoned"
    }))
}

fn explicit_export_error(
    code: ErrorCode,
    message: impl Into<String>,
    context: &'static str,
    details: serde_json::Value,
) -> CoreError {
    CoreError::new(code, message)
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({
            "context": context,
            "details": details
        }))
}

fn explicit_export_io_error(context: &'static str, error: std::io::Error) -> CoreError {
    explicit_export_error(
        ErrorCode::StorageUnavailable,
        "explicit export file operation failed",
        context,
        json!({ "error_redacted": error.to_string() }),
    )
}

fn portable_capture_import_lock_error(context: &'static str) -> CoreError {
    CoreError::new(
        ErrorCode::InternalError,
        "portable capture import state is unavailable",
    )
    .with_severity(ErrorSeverity::Critical)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({
        "context": context,
        "reason_redacted": "portable capture import state lock poisoned"
    }))
}

fn portable_capture_import_error(
    code: ErrorCode,
    message: impl Into<String>,
    context: &'static str,
    details: serde_json::Value,
) -> CoreError {
    CoreError::new(code, message)
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({
            "context": context,
            "details": details
        }))
}

fn portable_capture_import_io_error(context: &'static str, error: std::io::Error) -> CoreError {
    portable_capture_import_error(
        ErrorCode::StorageUnavailable,
        "portable capture import file operation failed",
        context,
        json!({ "error_redacted": error.to_string() }),
    )
}

fn portable_preference_error(error: PreferenceError) -> CoreError {
    let code = match &error {
        PreferenceError::PreferenceRejected { .. } => ErrorCode::PrivacyPolicyViolation,
        PreferenceError::Io(_) | PreferenceError::Serialization(_) => ErrorCode::StorageUnavailable,
    };
    CoreError::new(code, "portable preference operation failed")
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({
            "context": "portable_preferences",
            "error_redacted": error.to_string()
        }))
}

fn event_state_lock_error() -> CoreError {
    CoreError::new(
        ErrorCode::InternalError,
        "desktop event state is unavailable",
    )
    .with_severity(ErrorSeverity::Critical)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({
        "context": "desktop_event_state",
        "reason_redacted": "event dispatcher lock poisoned"
    }))
}

fn tauri_emit_error(error: tauri::Error, envelope: &StreamEventEnvelope) -> CoreError {
    CoreError::new(
        ErrorCode::InternalError,
        "failed to emit Tauri stream event",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(envelope.trace_id.clone())
    .with_redacted_details(json!({
        "stream": envelope.stream.as_str(),
        "event_type": envelope.event_type,
        "error_redacted": error.to_string()
    }))
}

fn service_status_join_error(error: impl ToString) -> CoreError {
    CoreError::new(ErrorCode::InternalError, "service status probe task failed")
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({
            "context": "service_status_ipc_probe",
            "error_redacted": error.to_string()
        }))
}

fn detached_pane_id_from_label(label: &str) -> Option<&'static str> {
    DETACHED_PANES
        .iter()
        .find(|pane| pane.label == label)
        .map(|pane| pane.pane_id)
}

fn emit_detached_pane_event<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    event_name: &'static str,
    pane_id: &str,
    label: &str,
) {
    let _ = app.emit_to(
        MAIN_WINDOW_LABEL,
        event_name,
        json!({
            "pane_id": pane_id,
            "label": label
        }),
    );
}

#[tauri::command]
fn list_components(state: State<'_, DesktopReadState>) -> CommandResult<Vec<ComponentSummary>> {
    state.list_components()
}

#[tauri::command]
fn get_component_detail(
    state: State<'_, DesktopReadState>,
    component_id: ComponentId,
) -> CommandResult<ComponentDetail> {
    state.get_component_detail(component_id)
}

#[tauri::command]
fn search_components(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<ComponentSummary>> {
    state.search_components(request)
}

#[tauri::command]
fn get_plugin_catalog(state: State<'_, DesktopReadState>) -> CommandResult<PluginCatalogView> {
    state.get_plugin_catalog()
}

#[tauri::command]
fn get_plugin_manifest(
    state: State<'_, DesktopReadState>,
    plugin_id: PluginId,
) -> CommandResult<PluginManifest> {
    state.get_plugin_manifest(plugin_id)
}

#[tauri::command]
fn search_plugins(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<PluginManifest>> {
    state.search_plugins(request)
}

#[tauri::command]
fn get_capability_overview(
    state: State<'_, DesktopReadState>,
) -> CommandResult<Vec<CapabilityOverview>> {
    state.get_capability_overview()
}

#[tauri::command]
fn search_capabilities(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<CapabilityOverview>> {
    state.search_capabilities(request)
}

#[tauri::command]
fn search_findings(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<Finding>> {
    state.search_findings(request)
}

#[tauri::command]
fn search_alerts(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<Alert>> {
    state.search_alerts(request)
}

#[tauri::command]
fn search_incidents(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<Incident>> {
    state.search_incidents(request)
}

#[tauri::command]
fn get_incident_detail(
    state: State<'_, DesktopReadState>,
    incident_id: IncidentId,
) -> CommandResult<IncidentDetailView> {
    state.get_incident_detail(incident_id)
}

#[tauri::command]
fn search_flows(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<FlowRecord>> {
    state.search_flows(request)
}

#[tauri::command]
fn search_dns(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<DnsObservation>> {
    state.search_dns(request)
}

#[tauri::command]
fn search_tls(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<TlsObservation>> {
    state.search_tls(request)
}

#[tauri::command]
fn get_graph_view(
    state: State<'_, DesktopReadState>,
    storage: State<'_, DesktopStorageState>,
    request: GraphViewRequest,
) -> CommandResult<GraphViewModel> {
    match storage.get_graph_view(request.clone())? {
        Some(view) => Ok(view),
        None => state.get_graph_view(request),
    }
}

#[tauri::command]
fn list_active_responses(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<ResponsePlan>> {
    state.list_active_responses(page)
}

#[tauri::command]
fn search_response_plans(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<ResponsePlan>> {
    state.search_response_plans(request)
}

#[tauri::command]
fn list_reports(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<Report>> {
    state.list_reports(page)
}

#[tauri::command]
fn search_reports(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<Report>> {
    state.search_reports(request)
}

#[tauri::command]
fn get_report(state: State<'_, DesktopReadState>, report_id: ReportId) -> CommandResult<Report> {
    state.get_report(report_id)
}

#[tauri::command]
fn get_attack_coverage_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<AttackCoverageSummary> {
    state.get_attack_coverage_summary()
}

#[tauri::command]
fn get_fusion_summary(state: State<'_, DesktopReadState>) -> CommandResult<FusionSummary> {
    state.get_fusion_summary()
}

#[tauri::command]
fn list_security_facts(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<SecurityFact>> {
    state.list_security_facts(page)
}

#[tauri::command]
fn list_attack_hypotheses(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<AttackHypothesisRecord>> {
    state.list_attack_hypotheses(page)
}

#[tauri::command]
fn get_attack_hypothesis(
    state: State<'_, DesktopReadState>,
    hypothesis_id: AttackHypothesisId,
) -> CommandResult<AttackHypothesisRecord> {
    state.get_attack_hypothesis(hypothesis_id)
}

#[tauri::command]
fn get_durable_baseline_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<DurableBaselineSummary> {
    state.get_durable_baseline_summary()
}

#[tauri::command]
fn get_evidence_quality_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<EvidenceQualitySummary> {
    state.get_evidence_quality_summary()
}

#[tauri::command]
fn list_evidence_quality_records(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<EvidenceQualityRecord>> {
    state.list_evidence_quality_records(page)
}

#[tauri::command]
fn get_evidence_quality_record(
    state: State<'_, DesktopReadState>,
    evidence_quality_id: EvidenceQualityId,
) -> CommandResult<EvidenceQualityRecord> {
    state.get_evidence_quality_record(evidence_quality_id)
}

#[tauri::command]
fn get_investigation_drill_down_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<InvestigationDrillDownSummary> {
    state.get_investigation_drill_down_summary()
}

#[tauri::command]
fn resolve_navigation_reference(
    state: State<'_, DesktopReadState>,
    request: NavigationResolveRequest,
) -> CommandResult<NavigationResolution> {
    state.resolve_navigation_reference(request)
}

#[tauri::command]
fn get_hypothesis_explanation_detail(
    state: State<'_, DesktopReadState>,
    hypothesis_id: AttackHypothesisId,
) -> CommandResult<HypothesisExplanationDetail> {
    state.get_hypothesis_explanation_detail(hypothesis_id)
}

#[tauri::command]
fn get_baseline_drill_down_detail(
    state: State<'_, DesktopReadState>,
    baseline_id: BaselineRecordId,
) -> CommandResult<BaselineDrillDownDetail> {
    state.get_baseline_drill_down_detail(baseline_id)
}

#[tauri::command]
fn get_incident_group_investigation_detail(
    state: State<'_, DesktopReadState>,
    group_id: IncidentLinkedGroupId,
) -> CommandResult<IncidentGroupInvestigationDetail> {
    state.get_incident_group_investigation_detail(group_id)
}

#[tauri::command]
fn get_timeline_drill_down_detail(
    state: State<'_, DesktopReadState>,
    timeline_entry_id: IncidentTimelineEntryId,
) -> CommandResult<TimelineDrillDownDetail> {
    state.get_timeline_drill_down_detail(timeline_entry_id)
}

#[tauri::command]
fn get_source_reliability_explanation(
    state: State<'_, DesktopReadState>,
    source_id: MetadataWatchSourceId,
) -> CommandResult<SourceReliabilityExplanation> {
    state.get_source_reliability_explanation(source_id)
}

#[tauri::command]
fn list_baseline_records(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<BaselineRecord>> {
    state.list_baseline_records(page)
}

#[tauri::command]
fn get_baseline_record(
    state: State<'_, DesktopReadState>,
    baseline_id: BaselineRecordId,
) -> CommandResult<BaselineRecord> {
    state.get_baseline_record(baseline_id)
}

#[tauri::command]
fn list_baseline_indicators(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<BaselineIndicator>> {
    state.list_baseline_indicators(page)
}

#[tauri::command]
fn get_baseline_indicator(
    state: State<'_, DesktopReadState>,
    indicator_id: BaselineIndicatorId,
) -> CommandResult<BaselineIndicator> {
    state.get_baseline_indicator(indicator_id)
}

#[tauri::command]
fn list_incident_linked_hypothesis_groups(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<IncidentLinkedHypothesisGroup>> {
    state.list_incident_linked_hypothesis_groups(page)
}

#[tauri::command]
fn get_incident_linked_hypothesis_group(
    state: State<'_, DesktopReadState>,
    group_id: IncidentLinkedGroupId,
) -> CommandResult<IncidentLinkedHypothesisGroup> {
    state.get_incident_linked_hypothesis_group(group_id)
}

#[tauri::command]
fn list_incident_timeline_entries(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<IncidentTimelineEntry>> {
    state.list_incident_timeline_entries(page)
}

#[tauri::command]
fn get_incident_timeline_entry(
    state: State<'_, DesktopReadState>,
    timeline_entry_id: IncidentTimelineEntryId,
) -> CommandResult<IncidentTimelineEntry> {
    state.get_incident_timeline_entry(timeline_entry_id)
}

#[tauri::command]
fn list_source_reliability_summaries(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<SourceReliabilitySummary>> {
    state.list_source_reliability_summaries(page)
}

#[tauri::command]
fn get_metadata_watch_controller_status(
    state: State<'_, DesktopReadState>,
) -> CommandResult<MetadataWatchControllerStatus> {
    state.get_metadata_watch_controller_status()
}

#[tauri::command]
fn list_metadata_watch_sources(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<MetadataWatchSourceStatus>> {
    state.list_metadata_watch_sources(page)
}

#[tauri::command]
fn get_metadata_watch_source(
    state: State<'_, DesktopReadState>,
    source_id: MetadataWatchSourceId,
) -> CommandResult<MetadataWatchSourceStatus> {
    state.get_metadata_watch_source(source_id)
}

#[tauri::command]
fn list_metadata_sampling_batches(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<MetadataSamplingBatchSummary>> {
    state.list_metadata_sampling_batches(page)
}

#[tauri::command]
fn get_metadata_sampling_batch(
    state: State<'_, DesktopReadState>,
    batch_id: MetadataSamplingBatchId,
) -> CommandResult<MetadataSamplingBatchSummary> {
    state.get_metadata_sampling_batch(batch_id)
}

#[tauri::command]
fn list_export_history(
    state: State<'_, DesktopReadState>,
    query: ReportExportHistoryQuery,
) -> CommandResult<PageResponse<ExportHistoryRecord>> {
    state.list_export_history(query)
}

#[tauri::command]
fn search_export_history(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<ExportHistoryRecord>> {
    state.search_export_history(request)
}

#[tauri::command]
fn get_export_history_record(
    state: State<'_, DesktopReadState>,
    export_result_id: ExportResultId,
) -> CommandResult<ExportHistoryRecord> {
    state.get_export_history_record(export_result_id)
}

#[tauri::command]
fn list_export_policy_violations(
    state: State<'_, DesktopReadState>,
) -> CommandResult<Vec<ExportPolicyViolation>> {
    state.list_export_policy_violations()
}

#[tauri::command]
fn get_runtime_profile(state: State<'_, DesktopReadState>) -> CommandResult<RuntimeProfile> {
    state.get_runtime_profile()
}

#[tauri::command]
fn get_llm_alert_story_status(
    state: State<'_, DesktopLlmAlertStoryState>,
) -> CommandResult<LlmAlertStoryStatusView> {
    state.get_status()
}

#[tauri::command]
fn list_llm_alert_stories(
    state: State<'_, DesktopReadState>,
    page: PageRequest,
) -> CommandResult<PageResponse<LlmAlertStoryRecord>> {
    state.list_llm_alert_stories(page)
}

#[tauri::command]
fn get_llm_alert_story(
    state: State<'_, DesktopReadState>,
    story_id: LlmAlertStoryId,
) -> CommandResult<LlmAlertStoryRecord> {
    state.get_llm_alert_story(story_id)
}

#[tauri::command]
fn search_runtime_profiles(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<RuntimeProfile>> {
    state.search_runtime_profiles(request)
}

#[tauri::command]
async fn get_service_status(
    state: State<'_, DesktopReadState>,
) -> CommandResult<ServiceStatusView> {
    let core_snapshot = state.snapshot_core()?;
    tauri::async_runtime::spawn_blocking(move || core::get_service_status(&core_snapshot))
        .await
        .map_err(service_status_join_error)?
}

#[tauri::command]
fn search_service_status(
    state: State<'_, DesktopReadState>,
    request: QueryRequest,
) -> CommandResult<PageResponse<ServiceStatusView>> {
    state.search_service_status(request)
}

#[tauri::command]
fn list_authorized_native_capabilities(
    state: State<'_, DesktopReadState>,
) -> CommandResult<Vec<AuthorizedNativeCapabilityStatus>> {
    state.list_authorized_native_capabilities()
}

#[tauri::command]
fn get_authorized_native_capability(
    state: State<'_, DesktopReadState>,
    capability_id: String,
) -> CommandResult<AuthorizedNativeCapabilityStatus> {
    state.get_authorized_native_capability(capability_id)
}

#[tauri::command]
fn get_native_permission_status_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<NativePermissionStatusSummary> {
    state.get_native_permission_status_summary()
}

#[tauri::command]
fn get_native_visibility_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<NativeVisibilitySummary> {
    state.get_native_visibility_summary()
}

#[tauri::command]
fn get_native_permission_audit_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<NativePermissionAuditSummary> {
    state.get_native_permission_audit_summary()
}

#[tauri::command]
fn list_native_sampler_contracts(
    state: State<'_, DesktopReadState>,
) -> CommandResult<Vec<NativeSamplerContract>> {
    state.list_native_sampler_contracts()
}

#[tauri::command]
fn get_native_sampler_contract(
    state: State<'_, DesktopReadState>,
    sampler_id: String,
) -> CommandResult<NativeSamplerContract> {
    state.get_native_sampler_contract(sampler_id)
}

#[tauri::command]
fn get_native_sampler_readiness_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<NativeSamplerReadinessSummary> {
    state.get_native_sampler_readiness_summary()
}

#[tauri::command]
fn get_native_sampler_readiness_detail(
    state: State<'_, DesktopReadState>,
    sampler_id: String,
) -> CommandResult<NativeSamplerReadinessDetail> {
    state.get_native_sampler_readiness_detail(sampler_id)
}

#[tauri::command]
fn get_native_sampler_authorization_review(
    state: State<'_, DesktopReadState>,
    sampler_id: String,
) -> CommandResult<NativeSamplerAuthorizationReview> {
    state.get_native_sampler_authorization_review(sampler_id)
}

#[tauri::command]
fn get_future_security_fact_mapping_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<FutureSecurityFactMappingSummary> {
    state.get_future_security_fact_mapping_summary()
}

#[tauri::command]
fn get_native_sampler_blocked_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<NativeSamplerBlockedSummary> {
    state.get_native_sampler_blocked_summary()
}

#[tauri::command]
fn get_missing_endpoint_visibility_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<MissingEndpointVisibilitySummary> {
    state.get_missing_endpoint_visibility_summary()
}

#[tauri::command]
fn get_edr_readiness_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<EdrReadinessSummary> {
    state.get_edr_readiness_summary()
}

#[tauri::command]
fn get_native_sampler_runtime_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<NativeSamplerRuntimeSummary> {
    state.get_native_sampler_runtime_summary()
}

#[tauri::command]
fn get_native_sampler_runtime_status(
    state: State<'_, DesktopReadState>,
    sampler_id: String,
) -> CommandResult<NativeSamplerRuntimeStatus> {
    state.get_native_sampler_runtime_status(sampler_id)
}

#[tauri::command]
fn get_latest_native_sampler_runtime_batch(
    state: State<'_, DesktopReadState>,
    sampler_id: String,
) -> CommandResult<Option<NativeSamplerRuntimeBatch>> {
    state.get_latest_native_sampler_runtime_batch(sampler_id)
}

#[tauri::command]
fn get_native_scheduler_status(
    state: State<'_, DesktopReadState>,
) -> CommandResult<NativeSchedulerStatus> {
    state.get_native_scheduler_status()
}

#[tauri::command]
fn list_native_sampler_schedule_statuses(
    state: State<'_, DesktopReadState>,
) -> CommandResult<Vec<NativeSamplerScheduleStatus>> {
    state.list_native_sampler_schedule_statuses()
}

#[tauri::command]
fn get_native_sampler_schedule_status(
    state: State<'_, DesktopReadState>,
    sampler_id: String,
) -> CommandResult<NativeSamplerScheduleStatus> {
    state.get_native_sampler_schedule_status(sampler_id)
}

#[tauri::command]
fn get_native_scheduler_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<NativeSchedulerSummary> {
    state.get_native_scheduler_summary()
}

#[tauri::command]
fn get_native_scheduler_operational_summary(
    state: State<'_, DesktopReadState>,
) -> CommandResult<NativeSchedulerOperationalSummary> {
    state.get_native_scheduler_operational_summary()
}

#[tauri::command]
fn list_native_scheduler_cycles(
    state: State<'_, DesktopReadState>,
) -> CommandResult<Vec<NativeSchedulerCycleSummary>> {
    state.list_native_scheduler_cycles()
}

#[tauri::command]
fn get_latest_native_scheduler_cycle(
    state: State<'_, DesktopReadState>,
) -> CommandResult<Option<NativeSchedulerCycleSummary>> {
    state.get_latest_native_scheduler_cycle()
}

#[tauri::command]
fn get_portable_preferences(
    storage: State<'_, DesktopStorageState>,
) -> CommandResult<BTreeMap<String, serde_json::Value>> {
    storage.load_portable_preferences()
}

#[tauri::command]
fn enable_plugin(
    state: State<'_, DesktopMutationState>,
    request: PluginLifecycleRequest,
) -> CommandResult<MutationReceipt<PluginLifecycleMutationResult>> {
    state.enable_plugin(request)
}

#[tauri::command]
fn preview_native_permission_request(
    state: State<'_, DesktopMutationState>,
    capability_id: String,
) -> CommandResult<NativePermissionPreview> {
    state.preview_native_permission_request(capability_id)
}

#[tauri::command]
fn update_native_permission(
    read_state: State<'_, DesktopReadState>,
    mutation_state: State<'_, DesktopMutationState>,
    request: NativePermissionActionRequest,
) -> CommandResult<NativePermissionActionResult> {
    let result = mutation_state.update_native_permission(request)?;
    sync_read_state_from_mutation(&read_state, &mutation_state)?;
    Ok(result)
}

#[tauri::command]
fn preview_native_sampler_activation(
    state: State<'_, DesktopMutationState>,
    sampler_id: String,
) -> CommandResult<NativeSamplerActivationPreview> {
    state.preview_native_sampler_activation(sampler_id)
}

#[tauri::command]
fn apply_native_sampler_runtime_action(
    read_state: State<'_, DesktopReadState>,
    mutation_state: State<'_, DesktopMutationState>,
    request: NativeSamplerRuntimeActionRequest,
) -> CommandResult<NativeSamplerRuntimeActionResult> {
    let result = mutation_state.apply_native_sampler_runtime_action(request)?;
    sync_read_state_from_mutation(&read_state, &mutation_state)?;
    Ok(result)
}

#[tauri::command]
fn preview_native_scheduler_enablement(
    state: State<'_, DesktopMutationState>,
    sampler_id: String,
) -> CommandResult<NativeSchedulerEnablementPreview> {
    state.preview_native_scheduler_enablement(sampler_id)
}

#[tauri::command]
fn apply_native_scheduler_action(
    read_state: State<'_, DesktopReadState>,
    mutation_state: State<'_, DesktopMutationState>,
    request: NativeSchedulerActionRequest,
) -> CommandResult<NativeSchedulerActionResult> {
    let result = mutation_state.apply_native_scheduler_action(request)?;
    sync_read_state_from_mutation(&read_state, &mutation_state)?;
    Ok(result)
}

#[tauri::command]
fn tick_native_scheduler(
    read_state: State<'_, DesktopReadState>,
    mutation_state: State<'_, DesktopMutationState>,
    request: NativeSchedulerTickRequest,
) -> CommandResult<NativeSchedulerCycleSummary> {
    let result = mutation_state.tick_native_scheduler(request)?;
    sync_read_state_from_mutation(&read_state, &mutation_state)?;
    Ok(result)
}

#[tauri::command]
fn disable_plugin(
    state: State<'_, DesktopMutationState>,
    request: PluginLifecycleRequest,
) -> CommandResult<MutationReceipt<PluginLifecycleMutationResult>> {
    state.disable_plugin(request)
}

#[tauri::command]
fn restart_plugin(
    state: State<'_, DesktopMutationState>,
    request: PluginLifecycleRequest,
) -> CommandResult<MutationReceipt<PluginLifecycleMutationResult>> {
    state.restart_plugin(request)
}

#[tauri::command]
fn suppress_finding(
    state: State<'_, DesktopMutationState>,
    request: FindingStateMutationRequest,
) -> CommandResult<MutationReceipt<FindingStateMutationResult>> {
    state.suppress_finding(request)
}

#[tauri::command]
fn dismiss_finding(
    state: State<'_, DesktopMutationState>,
    request: FindingStateMutationRequest,
) -> CommandResult<MutationReceipt<FindingStateMutationResult>> {
    state.dismiss_finding(request)
}

#[tauri::command]
fn escalate_alert(
    state: State<'_, DesktopMutationState>,
    request: EscalateAlertRequest,
) -> CommandResult<MutationReceipt<AlertEscalationResult>> {
    state.escalate_alert(request)
}

#[tauri::command]
fn update_incident_status(
    state: State<'_, DesktopMutationState>,
    request: IncidentStatusMutationRequest,
) -> CommandResult<MutationReceipt<IncidentStatusMutationResult>> {
    state.update_incident_status(request)
}

fn sync_read_state_from_mutation(
    read_state: &DesktopReadState,
    mutation_state: &DesktopMutationState,
) -> CommandResult<()> {
    read_state.replace_core(mutation_state.snapshot_read_state()?)
}

fn preview_portable_capture_import_from_path(
    storage: &DesktopStorageState,
    import_state: &DesktopPortableCaptureImportState,
    request: PortableCaptureImportFileRequest,
) -> CommandResult<PortableCaptureImportPreview> {
    let source_type = portable_capture_import_source_type(&request)?;
    let source_path = PathBuf::from(&request.source_path);
    let metadata = fs::metadata(&source_path).map_err(|error| {
        portable_capture_import_io_error("portable_capture_import_metadata", error)
    })?;
    if !metadata.is_file() {
        return Err(portable_capture_import_error(
            ErrorCode::InvalidRequest,
            "portable capture import source must be a file",
            "portable_capture_import_metadata",
            json!({ "source_path_redacted": "[local-file]" }),
        ));
    }
    let file_size_bytes = usize::try_from(metadata.len()).map_err(|_| {
        portable_capture_import_error(
            ErrorCode::ValidationFailure,
            "portable capture import source exceeds the bounded size limit",
            "portable_capture_import_metadata",
            json!({ "size_bytes_redacted": metadata.len() }),
        )
    })?;
    let content = fs::read_to_string(&source_path)
        .map_err(|error| portable_capture_import_io_error("portable_capture_import_read", error))?;
    let prepared = core::prepare_portable_capture_import(source_type, &content, file_size_bytes)?;
    let preview_artifact_path =
        write_portable_capture_preview_artifact(storage, &prepared.preview)?;
    import_state.store_pending(prepared, preview_artifact_path)
}

fn confirm_portable_capture_import_preview(
    read_state: &DesktopReadState,
    mutation_state: &DesktopMutationState,
    import_state: &DesktopPortableCaptureImportState,
    confirmation: PortableCaptureImportConfirmation,
) -> CommandResult<MutationReceipt<PortableCaptureImportResult>> {
    let Some(pending) = import_state.take_pending(&confirmation.preview_id)? else {
        return Err(portable_capture_import_error(
            ErrorCode::InvalidRequest,
            "portable capture import preview was not found",
            "confirm_portable_capture_import",
            json!({ "preview_id": confirmation.preview_id.to_string() }),
        ));
    };
    remove_portable_capture_preview_artifact(&pending.preview_artifact_path)?;
    if !confirmation.user_confirmed {
        return Err(portable_capture_import_error(
            ErrorCode::PolicyDenial,
            "portable capture import cancelled before runtime ingest",
            "confirm_portable_capture_import",
            json!({
                "preview_id": confirmation.preview_id.to_string(),
                "stage": "confirmation"
            }),
        ));
    }

    let receipt =
        mutation_state.confirm_portable_capture_import(&pending.prepared, confirmation)?;
    sync_read_state_from_mutation(read_state, mutation_state)?;
    Ok(receipt)
}

fn portable_capture_import_source_type(
    request: &PortableCaptureImportFileRequest,
) -> CommandResult<PortableCaptureInputSourceType> {
    if let Some(source_type) = request.source_type.clone() {
        return Ok(source_type);
    }

    let deception_source_hint = portable_deception_source_hint(&request.source_path);
    let auth_source_hint = portable_auth_source_hint(&request.source_path);
    let saas_cloud_source_hint = portable_saas_cloud_source_hint(&request.source_path);
    let extension = Path::new(&request.source_path)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());
    match extension.as_deref() {
        Some("har") => Ok(PortableCaptureInputSourceType::ImportedHar),
        Some("jsonl") if deception_source_hint => {
            Ok(PortableCaptureInputSourceType::ImportedDeceptionEventLog)
        }
        Some("jsonl") if auth_source_hint => {
            Ok(PortableCaptureInputSourceType::ImportedAuthSecurityLog)
        }
        Some("jsonl") if saas_cloud_source_hint => {
            Ok(PortableCaptureInputSourceType::ImportedSaasCloudMetadata)
        }
        Some("jsonl") => Ok(PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata),
        Some("log") if deception_source_hint => {
            Ok(PortableCaptureInputSourceType::ImportedDeceptionEventLog)
        }
        Some("log") if auth_source_hint => {
            Ok(PortableCaptureInputSourceType::ImportedAuthSecurityLog)
        }
        Some("log") if saas_cloud_source_hint => {
            Ok(PortableCaptureInputSourceType::ImportedSaasCloudMetadata)
        }
        Some("log") => Ok(PortableCaptureInputSourceType::ImportedWebAccessLog),
        Some("pcap") | Some("pcapng") => Err(portable_capture_import_error(
            ErrorCode::UnsupportedOperation,
            "portable pcapng metadata preview is unavailable without an existing safe parser",
            "portable_capture_import_source_type",
            json!({ "extension_redacted": extension }),
        )),
        _ => Err(portable_capture_import_error(
            ErrorCode::UnsupportedOperation,
            "portable capture import source type is unsupported",
            "portable_capture_import_source_type",
            json!({ "extension_redacted": extension }),
        )),
    }
}

fn portable_deception_source_hint(source_path: &str) -> bool {
    let file_name = Path::new(source_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    file_name
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|token| {
            matches!(
                token,
                "deception" | "decoy" | "honeypot" | "honey" | "sensor" | "canary" | "trap"
            )
        })
}

fn portable_auth_source_hint(source_path: &str) -> bool {
    let file_name = Path::new(source_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    file_name
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|token| {
            matches!(
                token,
                "auth" | "identity" | "idp" | "login" | "mfa" | "vpn" | "sshd" | "rdp"
            )
        })
}

fn portable_saas_cloud_source_hint(source_path: &str) -> bool {
    let file_name = Path::new(source_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    file_name
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|token| {
            matches!(
                token,
                "saas"
                    | "cloud"
                    | "cdn"
                    | "provider"
                    | "object"
                    | "storage"
                    | "bucket"
                    | "proxy"
                    | "tunnel"
            )
        })
}

fn write_portable_capture_preview_artifact(
    storage: &DesktopStorageState,
    preview: &PortableCaptureImportPreview,
) -> CommandResult<PathBuf> {
    let session_root = portable_capture_session_root(storage)?;
    let artifact_path = session_root.join(format!(
        "{CAPTURE_IMPORT_PREVIEW_FILE_PREFIX}{}{CAPTURE_IMPORT_PREVIEW_FILE_SUFFIX}",
        preview.preview_id
    ));
    let artifact = serde_json::to_string_pretty(preview).map_err(|error| {
        portable_capture_import_error(
            ErrorCode::InternalError,
            "portable capture preview serialization failed",
            "portable_capture_import_preview",
            json!({ "error_redacted": error.to_string() }),
        )
    })?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&artifact_path)
        .and_then(|mut file| {
            file.write_all(artifact.as_bytes())?;
            file.flush()
        })
        .map_err(|error| {
            portable_capture_import_io_error("portable_capture_import_preview", error)
        })?;
    Ok(artifact_path)
}

fn remove_portable_capture_preview_artifact(path: &Path) -> CommandResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(portable_capture_import_io_error(
            "portable_capture_import_preview_cleanup",
            error,
        )),
    }
}

fn portable_capture_session_root(storage: &DesktopStorageState) -> CommandResult<PathBuf> {
    let Some(runtime) = storage.runtime() else {
        return Err(portable_capture_import_error(
            ErrorCode::StorageUnavailable,
            "portable capture import requires an active session root",
            "portable_capture_import_session_root",
            json!({ "profile_mode": storage.profile_mode() }),
        ));
    };
    let Some(lifecycle) = runtime.session_lifecycle() else {
        return Err(portable_capture_import_error(
            ErrorCode::StorageUnavailable,
            "portable capture import requires session lifecycle state",
            "portable_capture_import_session_root",
            json!({ "profile_mode": storage.profile_mode() }),
        ));
    };
    Ok(lifecycle.config().session_root.clone())
}

#[tauri::command]
fn create_response_plan(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    request: CreateResponsePlanRequest,
) -> CommandResult<MutationReceipt<ResponsePlanMutationResult>> {
    let receipt = state.create_response_plan(request)?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(receipt)
}

#[tauri::command]
fn approve_response_action(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    request: ResponseApprovalMutationRequest,
) -> CommandResult<MutationReceipt<ResponseApprovalMutationResult>> {
    let receipt = state.approve_response_action(request)?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(receipt)
}

#[tauri::command]
fn reject_response_action(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    request: ResponseApprovalMutationRequest,
) -> CommandResult<MutationReceipt<ResponseApprovalMutationResult>> {
    let receipt = state.reject_response_action(request)?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(receipt)
}

#[tauri::command]
fn rollback_response_action(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    request: RollbackResponseActionRequest,
) -> CommandResult<MutationReceipt<RollbackResponseActionResult>> {
    let receipt = state.rollback_response_action(request)?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(receipt)
}

#[tauri::command]
fn generate_incident_report(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    request: GenerateIncidentReportRequest,
) -> CommandResult<MutationReceipt<ReportGenerationResult>> {
    let receipt = state.generate_incident_report(request)?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(receipt)
}

#[tauri::command]
fn export_report(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    request: ExportReportRequest,
) -> CommandResult<MutationReceipt<ExportReportMutationResult>> {
    let receipt = state.export_report(request)?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(receipt)
}

#[tauri::command]
fn get_local_metadata_proxy_status(
    state: State<'_, DesktopMutationState>,
) -> CommandResult<LocalProxyMetadataProviderStatus> {
    state.get_local_metadata_proxy_status()
}

#[tauri::command]
fn start_local_metadata_proxy(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    request: LocalProxyMetadataStartRequest,
) -> CommandResult<LocalProxyMetadataProviderStatus> {
    let status = state.start_local_metadata_proxy(request)?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(status)
}

#[tauri::command]
fn stop_local_metadata_proxy(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
) -> CommandResult<LocalProxyMetadataProviderStatus> {
    let status = state.stop_local_metadata_proxy()?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(status)
}

#[tauri::command]
fn drain_local_metadata_proxy(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
) -> CommandResult<LocalProxyMetadataProviderStatus> {
    let status = state.drain_local_metadata_proxy()?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(status)
}

#[tauri::command]
fn preview_portable_capture_import(
    storage: State<'_, DesktopStorageState>,
    import_state: State<'_, DesktopPortableCaptureImportState>,
    request: PortableCaptureImportFileRequest,
) -> CommandResult<PortableCaptureImportPreview> {
    preview_portable_capture_import_from_path(&storage, &import_state, request)
}

#[tauri::command]
fn confirm_portable_capture_import(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    import_state: State<'_, DesktopPortableCaptureImportState>,
    confirmation: PortableCaptureImportConfirmation,
) -> CommandResult<MutationReceipt<PortableCaptureImportResult>> {
    confirm_portable_capture_import_preview(&read_state, &state, &import_state, confirmation)
}

#[tauri::command]
fn preview_metadata_watch_source(
    state: State<'_, DesktopMutationState>,
    request: MetadataWatchSourcePreviewRequest,
) -> CommandResult<MetadataWatchSourcePreview> {
    state.preview_metadata_watch_source(request)
}

#[tauri::command]
fn confirm_metadata_watch_source(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    confirmation: MetadataWatchSourceConfirmation,
) -> CommandResult<MutationReceipt<MetadataWatchControllerStatus>> {
    let receipt = state.confirm_metadata_watch_source(confirmation)?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(receipt)
}

#[tauri::command]
fn update_metadata_watch_source(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    request: MetadataWatchLifecycleRequest,
) -> CommandResult<MutationReceipt<MetadataWatchControllerStatus>> {
    let receipt = state.update_metadata_watch_source(request)?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(receipt)
}

#[tauri::command]
fn tick_metadata_watch_controller(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    request: MetadataSamplingTickRequest,
) -> CommandResult<MutationReceipt<MetadataSamplingTickResult>> {
    let receipt = state.tick_metadata_watch_controller(request)?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(receipt)
}

#[tauri::command]
fn update_metadata_sampling_loop(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    request: MetadataSamplingLoopControlRequest,
) -> CommandResult<MutationReceipt<MetadataWatchControllerStatus>> {
    let receipt = state.update_metadata_sampling_loop(request)?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(receipt)
}

#[tauri::command]
fn run_metadata_sampling_loop(
    read_state: State<'_, DesktopReadState>,
    state: State<'_, DesktopMutationState>,
    request: MetadataSamplingLoopRunRequest,
) -> CommandResult<MutationReceipt<MetadataSamplingTickResult>> {
    let receipt = state.run_metadata_sampling_loop(request)?;
    sync_read_state_from_mutation(&read_state, &state)?;
    Ok(receipt)
}

#[tauri::command]
fn preview_explicit_export(
    read_state: State<'_, DesktopReadState>,
    export_state: State<'_, DesktopExplicitExportState>,
    request: ExplicitExportRequest,
) -> CommandResult<ExplicitExportPreview> {
    let prepared = read_state.with_core(|core| core::prepare_explicit_export(core, request))?;
    export_state.store_pending(prepared)
}

#[tauri::command]
fn confirm_explicit_export(
    storage: State<'_, DesktopStorageState>,
    export_state: State<'_, DesktopExplicitExportState>,
    confirmation: ExplicitExportConfirmation,
) -> CommandResult<ExplicitExportResult> {
    let Some(prepared) = export_state.take_pending(&confirmation.export_id)? else {
        return Err(explicit_export_error(
            ErrorCode::InvalidRequest,
            "explicit export preview was not found",
            "confirm_explicit_export",
            json!({ "export_id": confirmation.export_id.to_string() }),
        ));
    };

    if !confirmation.user_confirmed {
        append_explicit_export_session_audit(
            &storage,
            core::explicit_export_cancelled_audit_event(&prepared, "confirmation"),
        )?;
        return Err(explicit_export_error(
            ErrorCode::PolicyDenial,
            "explicit export cancelled before file write",
            "confirm_explicit_export",
            json!({
                "export_id": confirmation.export_id.to_string(),
                "stage": "confirmation"
            }),
        ));
    }

    let _write_guard = export_state.begin_write()?;
    let destination_path = resolve_explicit_export_destination(&storage, &prepared)?;
    let destination_path_redacted = redacted_destination_directory(&destination_path);
    write_explicit_export_file(&destination_path, &prepared.content_redacted)?;
    let artifact_integrity = explicit_export_artifact_integrity(&destination_path)?;
    let completion = core::finalize_explicit_export(
        &prepared,
        confirmation,
        destination_path_redacted,
        artifact_integrity,
    )?;
    append_explicit_export_session_audit(&storage, completion.audit_event)?;
    append_explicit_export_history(&storage, &completion.history_entry)?;
    Ok(completion.result)
}

#[tauri::command]
fn apply_runtime_profile(
    state: State<'_, DesktopMutationState>,
    request: ApplyRuntimeProfileRequest,
) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
    state.apply_runtime_profile(request)
}

#[tauri::command]
fn update_privacy_policy(
    state: State<'_, DesktopMutationState>,
    request: UpdatePrivacyPolicyRequest,
) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
    state.update_privacy_policy(request)
}

#[tauri::command]
fn update_response_policy(
    state: State<'_, DesktopMutationState>,
    request: UpdateResponsePolicyRequest,
) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
    state.update_response_policy(request)
}

#[tauri::command]
fn enable_forensic_mode(
    state: State<'_, DesktopMutationState>,
    request: EnableForensicModeRequest,
) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
    state.enable_forensic_mode(request)
}

#[tauri::command]
fn disable_forensic_mode(
    state: State<'_, DesktopMutationState>,
    request: DisableForensicModeRequest,
) -> CommandResult<MutationReceipt<SettingsMutationResult>> {
    state.disable_forensic_mode(request)
}

#[tauri::command]
fn update_llm_alert_story_settings(
    state: State<'_, DesktopLlmAlertStoryState>,
    request: UpdateLlmAlertStorySettingsRequest,
) -> CommandResult<LlmAlertStoryStatusView> {
    state.update_settings(request)
}

#[tauri::command]
fn save_llm_alert_story_api_key(
    state: State<'_, DesktopLlmAlertStoryState>,
    request: SaveLlmAlertStoryApiKeyRequest,
) -> CommandResult<LlmAlertStoryStatusView> {
    state.save_api_key(request)
}

#[tauri::command]
fn clear_llm_alert_story_api_key(
    state: State<'_, DesktopLlmAlertStoryState>,
    request: ClearLlmAlertStoryApiKeyRequest,
) -> CommandResult<LlmAlertStoryStatusView> {
    state.clear_api_key(request)
}

#[tauri::command]
fn test_llm_alert_story_connection(
    state: State<'_, DesktopLlmAlertStoryState>,
    request: TestLlmAlertStoryConnectionRequest,
) -> CommandResult<LlmAlertStoryStatusView> {
    state.test_connection(request)
}

#[tauri::command]
fn generate_llm_alert_story(
    read_state: State<'_, DesktopReadState>,
    mutation_state: State<'_, DesktopMutationState>,
    llm_state: State<'_, DesktopLlmAlertStoryState>,
    request: GenerateLlmAlertStoryRequest,
) -> CommandResult<LlmAlertStoryRecord> {
    let read = read_state.snapshot_core()?;
    let story = llm_state.generate(&read, request)?;
    mutation_state.record_llm_alert_story(story.clone())?;
    sync_read_state_from_mutation(&read_state, &mutation_state)?;
    Ok(story)
}

#[tauri::command]
fn run_demo_story(
    read_state: State<'_, DesktopReadState>,
    mutation_state: State<'_, DesktopMutationState>,
    storage_state: State<'_, DesktopStorageState>,
) -> CommandResult<core::DemoStoryResult> {
    install_demo_story(&read_state, &mutation_state, &storage_state)
}

fn install_demo_story(
    read_state: &DesktopReadState,
    mutation_state: &DesktopMutationState,
    storage_state: &DesktopStorageState,
) -> CommandResult<core::DemoStoryResult> {
    let replay = FixtureRunner::from_default_fixture()?.run()?;
    let persistence_summary = storage_state.persist_demo_read_model(&replay.read_model)?;
    let updated_read_state = read_state.install_demo_read_model(replay.read_model)?;
    mutation_state.replace_from_read_state(updated_read_state)?;
    log_demo_story_replay(&replay.result, persistence_summary.as_ref());
    Ok(replay.result)
}

#[tauri::command]
fn save_portable_preferences(
    storage: State<'_, DesktopStorageState>,
    preferences: BTreeMap<String, serde_json::Value>,
) -> CommandResult<BTreeMap<String, serde_json::Value>> {
    storage.save_portable_preferences(preferences)
}

fn log_demo_story_replay(
    result: &core::DemoStoryResult,
    persistence_summary: Option<&core::DemoStoryPersistenceSummary>,
) {
    println!(
        "DEMO_STORY_REPLAY story_id={} stage_count={} flows={} dns={} tls={} findings={} alerts={} incidents={} graph_nodes={} graph_edges={} graph_paths={} responses={} reports={} export_history={} storage_persisted={} storage_graph_nodes={} storage_graph_edges={}",
        result.story_id,
        result.stage_count,
        result.flow_count,
        result.dns_observation_count,
        result.tls_observation_count,
        result.finding_count,
        result.alert_count,
        result.incident_count,
        result.graph_node_count,
        result.graph_edge_count,
        result.graph_path_count,
        result.response_plan_count,
        result.report_count,
        result.export_history_count,
        persistence_summary.is_some(),
        persistence_summary.map_or(0, |summary| summary.canonical_graph_node_count),
        persistence_summary.map_or(0, |summary| summary.canonical_graph_edge_count)
    );
}

fn resolve_explicit_export_destination(
    storage: &DesktopStorageState,
    prepared: &core::PreparedExplicitExport,
) -> CommandResult<PathBuf> {
    let requested = PathBuf::from(prepared.request.destination_path.trim());
    if requested.as_os_str().is_empty() {
        return Err(explicit_export_error(
            ErrorCode::ValidationFailure,
            "explicit export destination is required",
            "explicit_export_destination",
            json!({ "export_id": prepared.request.export_id.to_string() }),
        ));
    }

    let path = if requested.is_absolute() {
        requested
    } else {
        default_explicit_export_directory(storage, prepared)?.join(requested)
    };
    validate_explicit_export_extension(&path, prepared)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| explicit_export_io_error("explicit_export_create_dir", error))?;
    }
    validate_portable_explicit_export_path(storage, &path)?;
    Ok(path)
}

fn default_explicit_export_directory(
    storage: &DesktopStorageState,
    prepared: &core::PreparedExplicitExport,
) -> CommandResult<PathBuf> {
    if let Some(portable_root) = portable_root_for_storage(storage) {
        let data_root = portable_root.join("data");
        return Ok(match &prepared.request.format {
            sentinel_contracts::session_export::ExportFormat::SgReport => data_root.join("reports"),
            sentinel_contracts::session_export::ExportFormat::SgSession
            | sentinel_contracts::session_export::ExportFormat::SgGraph => {
                data_root.join("exports")
            }
        });
    }

    let Some(runtime) = storage.runtime() else {
        return env::current_dir()
            .map_err(|error| explicit_export_io_error("explicit_export_current_dir", error));
    };
    let Some(lifecycle) = runtime.session_lifecycle() else {
        return env::current_dir()
            .map_err(|error| explicit_export_io_error("explicit_export_current_dir", error));
    };
    let preferences_parent = lifecycle
        .config()
        .preferences_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(env::temp_dir);
    Ok(preferences_parent.join("exports"))
}

fn validate_explicit_export_extension(
    path: &Path,
    prepared: &core::PreparedExplicitExport,
) -> CommandResult<()> {
    let extension = path.extension().and_then(|value| value.to_str());
    if extension != Some(prepared.request.format.extension()) {
        return Err(explicit_export_error(
            ErrorCode::ValidationFailure,
            "explicit export destination extension does not match format",
            "explicit_export_extension",
            json!({
                "expected_extension": prepared.request.format.dotted_extension(),
                "export_id": prepared.request.export_id.to_string()
            }),
        ));
    }
    Ok(())
}

fn validate_portable_explicit_export_path(
    storage: &DesktopStorageState,
    path: &Path,
) -> CommandResult<()> {
    let Some(portable_root) = portable_root_for_storage(storage) else {
        return Ok(());
    };
    let Some(parent) = path.parent() else {
        return Err(explicit_export_error(
            ErrorCode::ValidationFailure,
            "explicit export destination must have a parent directory",
            "explicit_export_destination",
            json!({ "profile_mode": storage.profile_mode() }),
        ));
    };
    let portable_root = fs::canonicalize(portable_root)
        .map_err(|error| explicit_export_io_error("explicit_export_portable_root", error))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| explicit_export_io_error("explicit_export_destination", error))?;
    if !parent.starts_with(&portable_root) {
        return Err(explicit_export_error(
            ErrorCode::PolicyDenial,
            "portable explicit export must stay under the portable root",
            "explicit_export_portable_root",
            json!({ "profile_mode": storage.profile_mode() }),
        ));
    }
    Ok(())
}

fn portable_root_for_storage(storage: &DesktopStorageState) -> Option<PathBuf> {
    storage
        .runtime()
        .and_then(DatabaseRuntime::session_lifecycle)
        .and_then(|lifecycle| lifecycle.config().portable_root.clone())
}

fn write_explicit_export_file(path: &Path, content_redacted: &str) -> CommandResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| explicit_export_io_error("explicit_export_file_write", error))?;
    file.write_all(content_redacted.as_bytes())
        .map_err(|error| explicit_export_io_error("explicit_export_file_write", error))?;
    file.flush()
        .map_err(|error| explicit_export_io_error("explicit_export_file_flush", error))?;
    Ok(())
}

fn explicit_export_artifact_integrity(
    path: &Path,
) -> CommandResult<core::ExplicitExportArtifactIntegrity> {
    let artifact_bytes = fs::read(path)
        .map_err(|error| explicit_export_io_error("explicit_export_file_read", error))?;
    Ok(core::explicit_export_artifact_integrity_from_bytes(
        &artifact_bytes,
    ))
}

fn append_explicit_export_session_audit(
    storage: &DesktopStorageState,
    event: serde_json::Value,
) -> CommandResult<()> {
    let Some(runtime) = storage.runtime() else {
        return Ok(());
    };
    let Some(lifecycle) = runtime.session_lifecycle() else {
        return Ok(());
    };
    lifecycle
        .append_session_audit_event(event)
        .map_err(|error| storage_write_error("explicit_export_session_audit", error))
}

fn append_explicit_export_history(
    storage: &DesktopStorageState,
    entry: &ExplicitExportHistoryEntry,
) -> CommandResult<()> {
    let history_path = explicit_export_history_path(storage)?;
    if let Some(parent) = history_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| explicit_export_io_error("explicit_export_history_dir", error))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&history_path)
        .map_err(|error| explicit_export_io_error("explicit_export_history", error))?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(entry).map_err(|error| explicit_export_error(
            ErrorCode::ValidationFailure,
            "explicit export history serialization failed",
            "explicit_export_history",
            json!({ "error_redacted": error.to_string() }),
        ))?
    )
    .map_err(|error| explicit_export_io_error("explicit_export_history", error))?;
    Ok(())
}

fn explicit_export_history_path(storage: &DesktopStorageState) -> CommandResult<PathBuf> {
    if let Some(portable_root) = portable_root_for_storage(storage) {
        return Ok(portable_root
            .join("data")
            .join("exports")
            .join("export_history.jsonl"));
    }
    let Some(runtime) = storage.runtime() else {
        return env::current_dir()
            .map(|path| path.join("export_history.jsonl"))
            .map_err(|error| explicit_export_io_error("explicit_export_history_path", error));
    };
    let Some(lifecycle) = runtime.session_lifecycle() else {
        return env::current_dir()
            .map(|path| path.join("export_history.jsonl"))
            .map_err(|error| explicit_export_io_error("explicit_export_history_path", error));
    };
    let history_root = lifecycle
        .config()
        .preferences_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(env::temp_dir);
    Ok(history_root.join("export_history.jsonl"))
}

fn redacted_destination_directory(path: &Path) -> String {
    path.parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .map(|name| format!("[export-dir:{name}]"))
        .unwrap_or_else(|| "[export-dir]".to_string())
}

#[tauri::command]
fn shutdown_app(
    storage: State<'_, DesktopStorageState>,
    export_state: State<'_, DesktopExplicitExportState>,
    import_state: State<'_, DesktopPortableCaptureImportState>,
    llm_state: State<'_, DesktopLlmAlertStoryState>,
) -> CommandResult<()> {
    if export_state.has_pending_or_active()? {
        return Err(explicit_export_error(
            ErrorCode::PolicyDenial,
            "explicit export is pending; confirm or cancel before shutdown",
            "shutdown_app",
            json!({ "export_pending": true }),
        ));
    }
    import_state.discard_all_pending()?;
    llm_state.clear_session()?;
    storage.end_session();
    process::exit(0);
}

/// Launch the Sentinel Guard Tauri desktop application.
///
/// Bootstraps read, mutation, and event state, then starts the Tauri runtime
/// with all registered commands and event streams.
pub fn run() {
    let startup_config = DemoStartupConfig::detect();
    StartupAuditRecord::from_config(&startup_config).log_to_console();
    let storage_state = bootstrap_storage_state(startup_config.clone());
    let service_status = service_status_for_storage(&storage_state);

    let read_state = bootstrap_state_or_exit(
        "read state",
        DesktopReadState::bootstrap_with_service_status(service_status),
    );
    let mutation_state =
        bootstrap_state_or_exit("mutation state", DesktopMutationState::bootstrap());
    let event_state = bootstrap_state_or_exit("event state", DesktopEventState::bootstrap());
    let llm_alert_story_state = bootstrap_state_or_exit(
        "llm alert story state",
        DesktopLlmAlertStoryState::bootstrap(&storage_state),
    );

    if startup_config.is_demo() {
        bootstrap_state_or_exit(
            "demo story replay",
            install_demo_story(&read_state, &mutation_state, &storage_state),
        );
    }

    let app = tauri::Builder::default()
        .manage(read_state)
        .manage(mutation_state)
        .manage(event_state)
        .manage(storage_state)
        .manage(llm_alert_story_state)
        .manage(DesktopExplicitExportState::default())
        .manage(DesktopPortableCaptureImportState::default())
        .setup(|app| {
            let storage_state = app.state::<DesktopStorageState>();
            if storage_state.machine_local_capability_status().is_some() {
                let status = service_status_for_storage(&storage_state);
                if let Err(error) = app
                    .state::<DesktopEventState>()
                    .emit_service_status_stream(app.handle(), ServiceStatusUpdate::from(&status))
                {
                    eprintln!(
                        "STARTUP_WARN component=capability_status_stream error_code={:?} message={}",
                        error.error_code, error.message
                    );
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            let label = window.label();
            if label == MAIN_WINDOW_LABEL {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    match window
                        .app_handle()
                        .state::<DesktopExplicitExportState>()
                        .has_pending_or_active()
                    {
                        Ok(true) => {
                            api.prevent_close();
                            eprintln!(
                                "EXPORT_CLOSE_WARN pending_explicit_export=true action=prevent_close"
                            );
                            return;
                        }
                        Ok(false) => {
                            if let Err(error) = window
                                .app_handle()
                                .state::<DesktopPortableCaptureImportState>()
                                .discard_all_pending()
                            {
                                api.prevent_close();
                                eprintln!(
                                    "IMPORT_CLOSE_WARN pending_state_error=true error_code={:?} message={}",
                                    error.error_code, error.message
                                );
                                return;
                            }
                            window
                                .app_handle()
                                .state::<DesktopLlmAlertStoryState>()
                                .clear_session()
                                .ok();
                            window
                                .app_handle()
                                .state::<DesktopStorageState>()
                                .end_session();
                            window.app_handle().exit(0);
                        }
                        Err(error) => {
                            api.prevent_close();
                            eprintln!(
                                "EXPORT_CLOSE_WARN pending_state_error=true error_code={:?} message={}",
                                error.error_code, error.message
                            );
                            return;
                        }
                    }
                }
            }
            if matches!(event, tauri::WindowEvent::Destroyed) {
                if let Some(pane_id) = detached_pane_id_from_label(label) {
                    emit_detached_pane_event(
                        window.app_handle(),
                        DETACHED_PANE_CLOSED_EVENT,
                        pane_id,
                        label,
                    );
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            // ── read-only commands (Task 200) ──
            list_components,
            get_component_detail,
            search_components,
            get_plugin_catalog,
            get_plugin_manifest,
            search_plugins,
            get_capability_overview,
            search_capabilities,
            search_findings,
            search_alerts,
            search_incidents,
            get_incident_detail,
            search_flows,
            search_dns,
            search_tls,
            get_graph_view,
            list_active_responses,
            search_response_plans,
            list_reports,
            search_reports,
            get_report,
            get_attack_coverage_summary,
        get_fusion_summary,
        list_security_facts,
        list_attack_hypotheses,
        get_attack_hypothesis,
        get_durable_baseline_summary,
        get_evidence_quality_summary,
        list_evidence_quality_records,
        get_evidence_quality_record,
        get_investigation_drill_down_summary,
        resolve_navigation_reference,
        get_hypothesis_explanation_detail,
        get_baseline_drill_down_detail,
        get_incident_group_investigation_detail,
        get_timeline_drill_down_detail,
        get_source_reliability_explanation,
        list_baseline_records,
        get_baseline_record,
        list_baseline_indicators,
        get_baseline_indicator,
        list_incident_linked_hypothesis_groups,
        get_incident_linked_hypothesis_group,
        list_incident_timeline_entries,
        get_incident_timeline_entry,
        list_source_reliability_summaries,
        get_metadata_watch_controller_status,
        list_metadata_watch_sources,
        get_metadata_watch_source,
        list_metadata_sampling_batches,
        get_metadata_sampling_batch,
        list_export_history,
            search_export_history,
            get_export_history_record,
            list_export_policy_violations,
            get_runtime_profile,
            search_runtime_profiles,
            get_llm_alert_story_status,
            list_llm_alert_stories,
            get_llm_alert_story,
            get_service_status,
            search_service_status,
            list_authorized_native_capabilities,
            get_authorized_native_capability,
            get_native_permission_status_summary,
            get_native_visibility_summary,
            get_native_permission_audit_summary,
            list_native_sampler_contracts,
            get_native_sampler_contract,
            get_native_sampler_readiness_summary,
            get_native_sampler_readiness_detail,
            get_native_sampler_authorization_review,
            get_future_security_fact_mapping_summary,
        get_native_sampler_blocked_summary,
        get_missing_endpoint_visibility_summary,
        get_edr_readiness_summary,
        get_native_sampler_runtime_summary,
        get_native_sampler_runtime_status,
        get_latest_native_sampler_runtime_batch,
        get_native_scheduler_status,
        list_native_sampler_schedule_statuses,
        get_native_sampler_schedule_status,
        get_native_scheduler_summary,
        get_native_scheduler_operational_summary,
        list_native_scheduler_cycles,
        get_latest_native_scheduler_cycle,
        get_portable_preferences,
            // ── mutation commands (Task 210) ──
            enable_plugin,
            disable_plugin,
            restart_plugin,
            suppress_finding,
            dismiss_finding,
            escalate_alert,
            update_incident_status,
            create_response_plan,
            approve_response_action,
            reject_response_action,
            rollback_response_action,
            generate_incident_report,
            export_report,
            get_local_metadata_proxy_status,
            start_local_metadata_proxy,
            stop_local_metadata_proxy,
        drain_local_metadata_proxy,
        preview_portable_capture_import,
        confirm_portable_capture_import,
        preview_metadata_watch_source,
        confirm_metadata_watch_source,
        update_metadata_watch_source,
        tick_metadata_watch_controller,
        update_metadata_sampling_loop,
        run_metadata_sampling_loop,
        preview_explicit_export,
            confirm_explicit_export,
            apply_runtime_profile,
            update_privacy_policy,
            update_response_policy,
            enable_forensic_mode,
            disable_forensic_mode,
            update_llm_alert_story_settings,
            save_llm_alert_story_api_key,
            clear_llm_alert_story_api_key,
            test_llm_alert_story_connection,
            generate_llm_alert_story,
        preview_native_permission_request,
        update_native_permission,
        preview_native_sampler_activation,
        apply_native_sampler_runtime_action,
        preview_native_scheduler_enablement,
        apply_native_scheduler_action,
        tick_native_scheduler,
            run_demo_story,
            save_portable_preferences,
            shutdown_app,
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|error| {
            eprintln!("STARTUP_FATAL component=tauri_runtime message={}", error);
            process::exit(1);
        });

    let exit_code = app.run_return(|app_handle, event| {
        if matches!(
            event,
            tauri::RunEvent::WindowEvent {
                ref label,
                event: tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed,
                ..
            } if label == MAIN_WINDOW_LABEL
        ) {
            if app_handle
                .state::<DesktopExplicitExportState>()
                .has_pending_or_active()
                .unwrap_or(true)
            {
                eprintln!("EXPORT_CLOSE_WARN pending_explicit_export=true action=skip_exit");
                return;
            }
            if let Err(error) = app_handle
                .state::<DesktopPortableCaptureImportState>()
                .discard_all_pending()
            {
                eprintln!(
                    "IMPORT_CLOSE_WARN pending_state_error=true error_code={:?} message={}",
                    error.error_code, error.message
                );
                return;
            }
            app_handle.state::<DesktopStorageState>().end_session();
            app_handle
                .state::<DesktopLlmAlertStoryState>()
                .clear_session()
                .ok();
            app_handle.exit(0);
        }
    });
    process::exit(exit_code);
}

fn bootstrap_storage_state(startup_config: DemoStartupConfig) -> DesktopStorageState {
    let session_mode = startup_config.session_mode();
    let profile_mode = session_mode.profile_mode().to_string();
    let resolver = if startup_config.is_portable() {
        match startup_config.portable_root.clone() {
            Some(portable_root) => SessionRootResolver::for_portable_root(portable_root),
            None => {
                let reason = "portable startup failed: executable directory could not be resolved"
                    .to_string();
                eprintln!(
                    "SESSION_DEGRADED requested_mode={} reason={}",
                    session_mode.as_str(),
                    reason
                );
                return DesktopStorageState::degraded_with_profile_mode(reason, profile_mode);
            }
        }
    } else {
        SessionRootResolver::platform_default()
    };
    let session_lifecycle = match SessionLifecycle::start(session_mode, resolver) {
        Ok(lifecycle) => lifecycle,
        Err(error) => {
            let reason = format!("session startup failed: {error}");
            eprintln!(
                "SESSION_DEGRADED requested_mode={} reason={}",
                session_mode.as_str(),
                reason
            );
            return DesktopStorageState::degraded_with_profile_mode(reason, profile_mode);
        }
    };
    let session_config = session_lifecycle.config().clone();
    println!(
        "SESSION_START mode={} session_id={} root={} database_mode={} preferences={} portable_preferences_loaded={} cleaned_abandoned={} skipped_unknown={}",
        session_config.session_mode.as_str(),
        session_config.session_id,
        session_config.session_root_redacted,
        session_config.database_mode_str(),
        session_config.preferences_path_redacted,
        session_config
            .portable_preferences_loaded
            .map_or(0, |count| count),
        session_config.cleaned_abandoned_sessions.len(),
        session_config.skipped_unknown_entries.len()
    );
    for skipped in &session_config.skipped_unknown_entries {
        eprintln!(
            "SESSION_CLEANUP_WARN entry_redacted={} reason=missing_or_invalid_marker",
            skipped
        );
    }

    let config = DatabaseConfig::for_session(env!("CARGO_PKG_VERSION"), session_config);
    let location_redacted = config.db_directory_redacted();

    match DatabaseRuntime::bootstrap_with_session(config, session_lifecycle) {
        Ok(runtime) => {
            let report = runtime.report();
            let initialized_count = report.store_initialization.initialized_store_kinds.len();
            let failed_count = report.store_initialization.failed_store_kinds.len();
            if report.degraded {
                eprintln!(
                    "STORAGE_BOOTSTRAP status=degraded mode={} session_mode={} session_id={} session_root={} location={} in_memory={} portable_preferences_loaded={} migrations_applied={} migrations_skipped={} schema_version={} stores_initialized={} stores_failed={} app_started_audit_id={}",
                    report.mode.as_str(),
                    report
                        .session_mode
                        .as_ref()
                        .map(|mode| mode.as_str())
                        .unwrap_or("none"),
                    report.session_id.as_deref().unwrap_or("none"),
                    report.session_root_redacted.as_deref().unwrap_or("none"),
                    report.location_redacted,
                    report.in_memory,
                    report.portable_preferences_loaded.unwrap_or(0),
                    report.migrations_applied,
                    report.migrations_skipped,
                    report.schema_version,
                    initialized_count,
                    failed_count,
                    report.audit_record.audit_id
                );
            } else {
                println!(
                    "STORAGE_BOOTSTRAP status=healthy mode={} session_mode={} session_id={} session_root={} location={} in_memory={} portable_preferences_loaded={} migrations_applied={} migrations_skipped={} schema_version={} stores_initialized={} app_started_audit_id={}",
                    report.mode.as_str(),
                    report
                        .session_mode
                        .as_ref()
                        .map(|mode| mode.as_str())
                        .unwrap_or("none"),
                    report.session_id.as_deref().unwrap_or("none"),
                    report.session_root_redacted.as_deref().unwrap_or("none"),
                    report.location_redacted,
                    report.in_memory,
                    report.portable_preferences_loaded.unwrap_or(0),
                    report.migrations_applied,
                    report.migrations_skipped,
                    report.schema_version,
                    initialized_count,
                    report.audit_record.audit_id
                );
            }
            let storage_state = DesktopStorageState::healthy(runtime);
            if startup_config.is_portable() {
                attach_machine_local_capability_status(storage_state)
            } else {
                storage_state
            }
        }
        Err(error) => {
            let reason = format!("storage bootstrap failed: {error}");
            eprintln!(
                "STORAGE_DEGRADED mode={} location={} reason={}",
                session_mode.as_str(),
                location_redacted,
                reason
            );
            DesktopStorageState::degraded_with_profile_mode(reason, profile_mode)
        }
    }
}

fn attach_machine_local_capability_status(
    storage_state: DesktopStorageState,
) -> DesktopStorageState {
    let mut detector = core::MachineLocalCapabilityDetector::new();
    detector.detect_all();
    let summary = detector.summary();
    if let Some(runtime) = storage_state.runtime() {
        if let Some(lifecycle) = runtime.session_lifecycle() {
            if let Err(error) = lifecycle.append_session_audit_event(json!({
                "event_type": "machine_local_capability_detection",
                "timestamp": Timestamp::now().to_string(),
                "profile_mode": storage_state.profile_mode(),
                "all_available": summary.all_available,
                "degraded_count": summary.degraded_count,
                "unavailable_count": summary.unavailable_count,
                "requires_setup_count": summary.requires_setup_count,
                "capabilities": summary.capabilities.clone()
            })) {
                eprintln!(
                    "SESSION_AUDIT_WARN event=machine_local_capability_detection error={}",
                    error
                );
            }
        }
    }
    println!(
        "MACHINE_LOCAL_CAPABILITY_STATUS profile_mode={} all_available={} degraded={} unavailable={} requires_setup={}",
        storage_state.profile_mode(),
        summary.all_available,
        summary.degraded_count,
        summary.unavailable_count,
        summary.requires_setup_count
    );
    storage_state.with_machine_local_capability_status(summary)
}

fn service_status_for_storage(storage_state: &DesktopStorageState) -> ServiceStatusView {
    let mut status = ServiceStatusView::reduced_visibility();
    status.profile_mode = storage_state.profile_mode().to_string();
    status.storage_status = if storage_state.is_healthy() {
        ObservabilityHealthStatus::Healthy
    } else {
        ObservabilityHealthStatus::Degraded
    };
    status.active_session_id = storage_state
        .runtime()
        .and_then(DatabaseRuntime::session_lifecycle)
        .map(|lifecycle| SessionId::from_uuid(lifecycle.config().session_id));
    status.message_redacted = if storage_state.is_healthy() {
        "Storage is operational; elevated Windows service is not connected; read-only local metadata is available"
            .to_string()
    } else {
        storage_state
            .degraded_reason_redacted()
            .unwrap_or("Storage startup is degraded; read-only fixture metadata is available")
            .to_string()
    };
    status.machine_local_capability_status =
        storage_state.machine_local_capability_status().cloned();
    status.generated_at = Timestamp::now();
    status
}

fn bootstrap_state_or_exit<T>(label: &str, result: CommandResult<T>) -> T {
    match result {
        Ok(state) => state,
        Err(error) => {
            eprintln!(
                "STARTUP_FATAL component={} error_code={:?} message={}",
                label, error.error_code, error.message
            );
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_app_core::{
        CaptureStatusKind, HealthSubjectRef, MetricValueSummary, PluginLifecycleMutationState,
        PrivacyWarningKind, ReportProgressPhase, ResponseStatusKind,
    };
    use sentinel_contracts::session_export::{
        ExportConfirmation as ExplicitExportConfirmation, ExportRequest as ExplicitExportRequest,
        SaveAction as ExplicitSaveAction,
    };
    use sentinel_contracts::{
        AlertId, AlertState, EvidenceId, GraphEdgeType, GraphEdgeViewModel, GraphNodeType,
        GraphNodeViewModel, GraphPathId, GraphPathSummary, GraphPathType, GraphRedactionSummary,
        GraphScope, GraphType, GraphViewId, IncidentId, IncidentState, PrivacyClass, QualityScore,
        QueryRequest, RedactedLabel, RedactionStatus, ReportId, ReportStatus, ResponseActionId,
        ResponsePlanId, SecuritySeverity, SessionId, Timestamp,
    };
    use sentinel_contracts::{ErrorCode, QueryScope};
    use sentinel_platform::{ObservabilityHealthStatus, PriorityLane};
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn exposes_task_200_read_command_names() {
        assert_eq!(READ_ONLY_COMMAND_NAMES.len(), 87);
        assert_eq!(READ_ONLY_COMMAND_NAMES[0], "list_components");
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_export_history"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"search_response_plans"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"search_reports"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_attack_coverage_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_fusion_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_security_facts"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_attack_hypotheses"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_attack_hypothesis"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_durable_baseline_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_evidence_quality_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_evidence_quality_records"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_evidence_quality_record"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_investigation_drill_down_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"resolve_navigation_reference"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_hypothesis_explanation_detail"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_baseline_drill_down_detail"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_incident_group_investigation_detail"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_timeline_drill_down_detail"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_source_reliability_explanation"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_baseline_records"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_baseline_record"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_baseline_indicators"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_baseline_indicator"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_incident_linked_hypothesis_groups"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_incident_linked_hypothesis_group"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_incident_timeline_entries"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_incident_timeline_entry"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_source_reliability_summaries"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_llm_alert_story_status"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_llm_alert_stories"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_llm_alert_story"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_metadata_watch_controller_status"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_metadata_watch_sources"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_metadata_watch_source"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_metadata_sampling_batches"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_metadata_sampling_batch"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_service_status"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_authorized_native_capabilities"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_authorized_native_capability"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_permission_status_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_visibility_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_permission_audit_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_native_sampler_contracts"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_sampler_contract"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_sampler_readiness_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_sampler_readiness_detail"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_sampler_authorization_review"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_future_security_fact_mapping_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_sampler_blocked_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_missing_endpoint_visibility_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_edr_readiness_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_sampler_runtime_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_sampler_runtime_status"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_latest_native_sampler_runtime_batch"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_scheduler_status"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_native_sampler_schedule_statuses"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_sampler_schedule_status"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_scheduler_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_native_scheduler_operational_summary"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"list_native_scheduler_cycles"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_latest_native_scheduler_cycle"));
        assert!(READ_ONLY_COMMAND_NAMES.contains(&"get_portable_preferences"));
        assert!(!READ_ONLY_COMMAND_NAMES.contains(&"export_report"));
    }

    #[test]
    fn exposes_task_210_mutation_command_names() {
        assert_eq!(MUTATION_COMMAND_NAMES.len(), 47);
        assert_eq!(MUTATION_COMMAND_NAMES[0], "enable_plugin");
        assert!(MUTATION_COMMAND_NAMES.contains(&"export_report"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"get_local_metadata_proxy_status"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"start_local_metadata_proxy"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"stop_local_metadata_proxy"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"drain_local_metadata_proxy"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"preview_portable_capture_import"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"confirm_portable_capture_import"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"preview_metadata_watch_source"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"confirm_metadata_watch_source"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"update_metadata_watch_source"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"tick_metadata_watch_controller"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"update_metadata_sampling_loop"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"run_metadata_sampling_loop"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"preview_explicit_export"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"confirm_explicit_export"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"disable_forensic_mode"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"update_llm_alert_story_settings"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"save_llm_alert_story_api_key"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"clear_llm_alert_story_api_key"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"test_llm_alert_story_connection"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"generate_llm_alert_story"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"preview_native_permission_request"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"update_native_permission"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"preview_native_sampler_activation"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"apply_native_sampler_runtime_action"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"preview_native_scheduler_enablement"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"apply_native_scheduler_action"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"tick_native_scheduler"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"run_demo_story"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"save_portable_preferences"));
        assert!(MUTATION_COMMAND_NAMES.contains(&"shutdown_app"));
        assert!(!MUTATION_COMMAND_NAMES.contains(&"execute_response_action"));
        assert!(!MUTATION_COMMAND_NAMES.contains(&"firewall_write_rule"));
    }

    fn portable_capture_har_fixture() -> String {
        serde_json::json!({
            "log": {
                "entries": [
                    {
                        "startedDateTime": "2026-06-11T02:00:00Z",
                        "time": 150,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://uploader.example.test/upload/42?access_token=secret",
                            "headersSize": 240,
                            "bodySize": 64000,
                            "headers": [
                                { "name": "User-Agent", "value": "curl/8.8.0" }
                            ]
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 180,
                            "bodySize": 1024,
                            "headers": [],
                            "content": { "mimeType": "application/json", "size": 1024 }
                        }
                    },
                    {
                        "startedDateTime": "2026-06-11T02:00:10Z",
                        "time": 80,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://uploader.example.test/upload/43?user=alice",
                            "headersSize": 220,
                            "bodySize": 1024,
                            "headers": [
                                { "name": "User-Agent", "value": "curl/8.8.0" }
                            ]
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 180,
                            "bodySize": 120,
                            "headers": [],
                            "content": { "mimeType": "application/json", "size": 120 }
                        }
                    },
                    {
                        "startedDateTime": "2026-06-11T02:00:20Z",
                        "time": 75,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://uploader.example.test/upload/44?session_token=shh",
                            "headersSize": 220,
                            "bodySize": 1100,
                            "headers": [
                                { "name": "User-Agent", "value": "curl/8.8.0" }
                            ]
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 180,
                            "bodySize": 110,
                            "headers": [],
                            "content": { "mimeType": "application/json", "size": 110 }
                        }
                    },
                    {
                        "startedDateTime": "2026-06-11T02:00:30Z",
                        "time": 70,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://uploader.example.test/upload/45?path=C:/Users/Alice/Desktop",
                            "headersSize": 220,
                            "bodySize": 1200,
                            "headers": [
                                { "name": "User-Agent", "value": "curl/8.8.0" }
                            ]
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 180,
                            "bodySize": 100,
                            "headers": [],
                            "content": { "mimeType": "application/json", "size": 100 }
                        }
                    }
                ]
            }
        })
        .to_string()
    }

    fn portable_capture_jsonl_fixture() -> String {
        [
            serde_json::json!({
                "timestamp": "2026-06-11T10:05:00Z",
                "src_ip": "192.0.2.15",
                "src_port": 51515,
                "dst_ip": "203.0.113.22",
                "dst_port": 443,
                "protocol": "tcp",
                "direction": "outbound",
                "bytes_out": 72000,
                "bytes_in": 2200,
                "packets_out": 5,
                "packets_in": 3,
                "http": {
                    "method": "POST",
                    "url": "https://jsonl.example.test/upload/9?token=abcdef1234567890",
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
                },
                "tls": {
                    "sni": "api.jsonl.example.test",
                    "alpn": ["h2"],
                    "tls_version": "TLS1.3",
                    "cipher_suite": "TLS_AES_256_GCM_SHA384"
                }
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-11T10:05:30Z",
                "src_ip": "192.0.2.15",
                "src_port": 51516,
                "dst_ip": "203.0.113.22",
                "dst_port": 443,
                "protocol": "tcp",
                "direction": "outbound",
                "bytes_out": 76000,
                "bytes_in": 1800,
                "packets_out": 5,
                "packets_in": 2,
                "http": {
                    "method": "POST",
                    "url": "https://jsonl.example.test/upload/10?path=C:/Users/Alice/Desktop",
                    "status_code": 200,
                    "request_size_bytes": 76000,
                    "response_size_bytes": 1800,
                    "content_type": "application/json",
                    "user_agent": "python-requests/2.32.0"
                }
            })
            .to_string(),
        ]
        .join("\n")
    }

    fn send_local_metadata_proxy_request(port: u16, request: &str) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect proxy");
        stream
            .write_all(request.as_bytes())
            .expect("write proxy request");
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
    }

    #[test]
    fn exposes_task_220_stream_event_names() {
        assert_eq!(STREAM_EVENT_NAMES.len(), 10);
        assert_eq!(STREAM_EVENT_NAMES[0], "health_stream");
        assert!(STREAM_EVENT_NAMES.contains(&"graph_update_stream"));
        assert!(STREAM_EVENT_NAMES.contains(&"privacy_warning_stream"));
        assert!(!STREAM_EVENT_NAMES.contains(&"raw_packet_stream"));
        assert!(!STREAM_EVENT_NAMES.contains(&"payload_stream"));
    }

    #[test]
    fn detached_panes_use_stable_allowlisted_labels() {
        assert_eq!(DETACHED_PANES.len(), 4);
        assert_eq!(
            DETACHED_PANES,
            &[
                DetachedPaneConfig {
                    pane_id: "graph",
                    label: "detached-graph"
                },
                DetachedPaneConfig {
                    pane_id: "inspector",
                    label: "detached-inspector"
                },
                DetachedPaneConfig {
                    pane_id: "evidence",
                    label: "detached-evidence"
                },
                DetachedPaneConfig {
                    pane_id: "timeline",
                    label: "detached-timeline"
                }
            ]
        );
        assert_eq!(detached_pane_id_from_label("detached-graph"), Some("graph"));
        assert_eq!(
            detached_pane_id_from_label("detached-inspector"),
            Some("inspector")
        );
        assert_eq!(
            detached_pane_id_from_label("detached-evidence"),
            Some("evidence")
        );
        assert_eq!(
            detached_pane_id_from_label("detached-timeline"),
            Some("timeline")
        );
        assert_eq!(detached_pane_id_from_label("detached-settings"), None);
    }

    #[test]
    fn startup_config_enables_demo_from_cli_flag() {
        let config = DemoStartupConfig::from_args_and_env(
            ["sentinel-guard-desktop", "--demo"],
            Some("false".to_string()),
        );

        assert_eq!(config.mode, StartupMode::Demo);
        assert_eq!(config.source, StartupModeSource::CommandLine);
        assert!(config.is_demo());
    }

    #[test]
    fn startup_config_enables_demo_from_environment() {
        let config = DemoStartupConfig::from_args_and_env(
            ["sentinel-guard-desktop"],
            Some("true".to_string()),
        );

        assert_eq!(config.mode, StartupMode::Demo);
        assert_eq!(config.source, StartupModeSource::Environment);
        assert!(config.is_demo());
    }

    #[test]
    fn startup_config_enables_portable_from_cli_profile_flag() {
        let portable_root = temp_startup_root("portable-cli");
        let config = DemoStartupConfig::from_args_env_and_executable_dir(
            ["sentinel-guard-desktop", "--profile", "portable", "--demo"],
            Some("true".to_string()),
            Some("installed".to_string()),
            Some(portable_root.clone()),
        );

        assert_eq!(config.mode, StartupMode::PortableNoRetention);
        assert_eq!(config.source, StartupModeSource::CommandLine);
        assert_eq!(
            config.portable_root.as_deref(),
            Some(portable_root.as_path())
        );
        assert_eq!(config.session_mode(), SessionMode::PortableNoRetention);
        let _ = std::fs::remove_dir_all(portable_root);
    }

    #[test]
    fn startup_config_enables_portable_from_environment_profile() {
        let portable_root = temp_startup_root("portable-env");
        let config = DemoStartupConfig::from_args_env_and_executable_dir(
            ["sentinel-guard-desktop"],
            Some("true".to_string()),
            Some("portable".to_string()),
            Some(portable_root.clone()),
        );

        assert_eq!(config.mode, StartupMode::PortableNoRetention);
        assert_eq!(config.source, StartupModeSource::Environment);
        assert_eq!(
            config.portable_root.as_deref(),
            Some(portable_root.as_path())
        );
        let _ = std::fs::remove_dir_all(portable_root);
    }

    #[test]
    fn startup_config_enables_portable_from_marker_file() {
        let portable_root = temp_startup_root("portable-marker");
        std::fs::create_dir_all(&portable_root).expect("portable root");
        std::fs::write(
            portable_root.join(PORTABLE_PROFILE_MARKER_FILE_NAME),
            r#"{"profile":"portable-no-retention","version":1}"#,
        )
        .expect("portable marker");

        let config = DemoStartupConfig::from_args_env_and_executable_dir(
            ["sentinel-guard-desktop"],
            None,
            None,
            Some(portable_root.clone()),
        );

        assert_eq!(config.mode, StartupMode::PortableNoRetention);
        assert_eq!(config.source, StartupModeSource::MarkerFile);
        assert_eq!(
            config.portable_root.as_deref(),
            Some(portable_root.as_path())
        );
        let _ = std::fs::remove_dir_all(portable_root);
    }

    #[test]
    fn startup_default_maps_to_ephemeral_session_mode() {
        let config = DemoStartupConfig::from_args_and_env(["sentinel-guard-desktop"], None);

        assert_eq!(config.session_mode(), SessionMode::Ephemeral);
    }

    #[test]
    fn startup_demo_maps_to_installed_session_mode() {
        let config =
            DemoStartupConfig::from_args_and_env(["sentinel-guard-desktop", "--demo"], None);

        assert_eq!(config.session_mode(), SessionMode::Installed);
    }

    #[test]
    fn startup_audit_keeps_demo_boot_safe_and_local_only() {
        let config = DemoStartupConfig {
            mode: StartupMode::Demo,
            source: StartupModeSource::CommandLine,
            portable_root: None,
        };
        let audit = StartupAuditRecord::from_config(&config);

        assert!(audit.demo_data_enabled);
        assert!(!audit.portable_mode_enabled);
        assert!(!audit.capture_attempted);
        assert!(!audit.elevated_service_connection_attempted);
        assert!(!audit.privileged_actions_enabled);
        assert!(audit.persistence_attempted);
    }

    #[test]
    fn desktop_read_state_delegates_to_core_read_models() {
        let state = DesktopReadState::bootstrap().expect("desktop read state");

        let components = state.list_components().expect("components");
        let catalog = state.get_plugin_catalog().expect("plugin catalog");
        let capabilities = state
            .get_capability_overview()
            .expect("capability overview");
        let service_status = state.get_service_status().expect("service status");

        assert_eq!(components.len(), catalog.plugins.len());
        assert!(capabilities
            .iter()
            .all(|capability| capability.plugin_count > 0));
        assert!(!catalog.mock_only);
        assert!(!catalog.production_ready);
        assert!(catalog.plugins.iter().all(|plugin| plugin
            .capability_tags
            .iter()
            .any(|tag| tag == "STATIC_INTERNAL")));
        assert!(service_status.reduced_visibility);
    }

    #[test]
    fn desktop_read_state_preserves_structured_errors() {
        let state = DesktopReadState::bootstrap().expect("desktop read state");
        let error = state
            .get_plugin_manifest(PluginId::new_v4())
            .expect_err("missing plugin");

        assert_eq!(error.error_code, ErrorCode::InvalidRequest);
        assert!(error.trace_id.is_some());
        assert!(error.details_redacted.is_some());
    }

    #[test]
    fn desktop_demo_story_replay_installs_read_models_and_refreshes_mutation_state() {
        let read_state = DesktopReadState::bootstrap().expect("desktop read state");
        let mutation_state = DesktopMutationState::bootstrap().expect("desktop mutation state");
        let storage_state = DesktopStorageState::healthy(
            DatabaseRuntime::bootstrap(DatabaseConfig::demo_in_memory("task-540-desktop-test"))
                .expect("demo database runtime"),
        );
        let result = install_demo_story(&read_state, &mutation_state, &storage_state)
            .expect("install demo story");

        let incidents = read_state
            .search_incidents(QueryRequest::new(QueryScope::Global))
            .expect("incidents");
        let reports = read_state
            .list_reports(PageRequest::default())
            .expect("reports");
        let history = read_state
            .list_export_history(ReportExportHistoryQuery::for_report(
                reports.items[0].report_id.clone(),
            ))
            .expect("export history");
        let exported = mutation_state
            .export_report(ExportReportRequest {
                report_id: reports.items[0].report_id.clone(),
                format: sentinel_contracts::report::ExportFormat::RedactedJson,
                destination_metadata_redacted: Some("DEMO_ONLY local export".to_string()),
                requested_by_redacted: Some("local_operator".to_string()),
                user_confirmed: true,
            })
            .expect("export report after demo replay");

        assert_eq!(result.stage_count, 8);
        assert_eq!(incidents.items.len(), 1);
        assert_eq!(reports.items.len(), 1);
        assert_eq!(history.items.len(), 1);
        assert!(exported.result.export_result.success);
        assert_eq!(
            exported.result.export_result.report_id,
            reports.items[0].report_id
        );

        let graph = storage_state
            .get_graph_view(GraphViewRequest {
                graph_type: GraphType::IncidentGraph,
                scope: GraphScope::Overview,
                title_redacted: Some("DEMO_ONLY desktop storage graph".to_string()),
                node_limit: Some(100),
                edge_limit: Some(200),
            })
            .expect("storage graph command")
            .expect("storage graph view");
        assert_eq!(graph.original_node_count, result.graph_node_count);
        assert_eq!(graph.original_edge_count, result.graph_edge_count);
    }

    #[test]
    fn desktop_portable_preferences_round_trip_without_session_retention() {
        let portable_root = temp_startup_root("desktop-portable-preferences");
        let lifecycle = SessionLifecycle::start(
            SessionMode::PortableNoRetention,
            SessionRootResolver::for_portable_root(portable_root.clone()),
        )
        .expect("portable lifecycle");
        let session_root = lifecycle.config().session_root.clone();
        let preferences_path = lifecycle.config().preferences_path.clone();
        let runtime = DatabaseRuntime::bootstrap_with_session(
            DatabaseConfig::for_session("desktop-portable-preferences", lifecycle.config().clone()),
            lifecycle,
        )
        .expect("portable runtime");
        let storage_state = DesktopStorageState::healthy(runtime);
        let mut preferences = BTreeMap::new();
        preferences.insert("theme".to_string(), json!("dark"));
        preferences.insert(
            "layout".to_string(),
            json!({
                "bottom_graph_open": true,
                "detail_drawer_open": true,
                "sidebar_collapsed": false
            }),
        );

        let saved = storage_state
            .save_portable_preferences(preferences)
            .expect("save portable preferences");
        let loaded = storage_state
            .load_portable_preferences()
            .expect("load portable preferences");

        assert_eq!(saved.get("theme"), Some(&json!("dark")));
        assert_eq!(loaded.get("theme"), Some(&json!("dark")));
        assert!(preferences_path.exists());
        storage_state.end_session();
        assert!(!session_root.exists());
        assert!(preferences_path.exists());
        let _ = std::fs::remove_dir_all(portable_root);
    }

    #[test]
    fn desktop_portable_preferences_reject_forbidden_security_keys() {
        let portable_root = temp_startup_root("desktop-portable-preferences-reject");
        let lifecycle = SessionLifecycle::start(
            SessionMode::PortableNoRetention,
            SessionRootResolver::for_portable_root(portable_root.clone()),
        )
        .expect("portable lifecycle");
        let runtime = DatabaseRuntime::bootstrap_with_session(
            DatabaseConfig::for_session(
                "desktop-portable-preferences-reject",
                lifecycle.config().clone(),
            ),
            lifecycle,
        )
        .expect("portable runtime");
        let storage_state = DesktopStorageState::healthy(runtime);
        let mut preferences = BTreeMap::new();
        preferences.insert("findings".to_string(), json!([]));

        let error = storage_state
            .save_portable_preferences(preferences)
            .expect_err("forbidden portable preference should fail");

        assert_eq!(error.error_code, ErrorCode::PrivacyPolicyViolation);
        storage_state.end_session();
        let _ = std::fs::remove_dir_all(portable_root);
    }

    #[test]
    fn desktop_portable_startup_attaches_machine_local_capability_summary() {
        let portable_root = temp_startup_root("desktop-portable-capabilities");
        let lifecycle = SessionLifecycle::start(
            SessionMode::PortableNoRetention,
            SessionRootResolver::for_portable_root(portable_root.clone()),
        )
        .expect("portable lifecycle");
        let session_root = lifecycle.config().session_root.clone();
        let runtime = DatabaseRuntime::bootstrap_with_session(
            DatabaseConfig::for_session(
                "desktop-portable-capabilities",
                lifecycle.config().clone(),
            ),
            lifecycle,
        )
        .expect("portable runtime");
        let storage_state =
            attach_machine_local_capability_status(DesktopStorageState::healthy(runtime));
        let status = service_status_for_storage(&storage_state);
        let summary = status
            .machine_local_capability_status
            .expect("machine-local capability summary");
        let audit =
            std::fs::read_to_string(session_root.join("session_audit.log")).expect("session audit");

        assert_eq!(status.profile_mode, "portable-no-retention");
        assert_eq!(summary.capabilities.len(), 9);
        assert!(audit.contains("\"event_type\":\"machine_local_capability_detection\""));
        assert!(!audit.contains("raw_packet"));
        assert!(!audit.contains("payload"));
        storage_state.end_session();
        let _ = std::fs::remove_dir_all(portable_root);
    }

    #[test]
    fn desktop_portable_explicit_export_requires_preview_confirmation_and_writes_app_local_artifact(
    ) {
        let portable_root = temp_startup_root("desktop-portable-explicit-export");
        let lifecycle = SessionLifecycle::start(
            SessionMode::PortableNoRetention,
            SessionRootResolver::for_portable_root(portable_root.clone()),
        )
        .expect("portable lifecycle");
        let session_root = lifecycle.config().session_root.clone();
        let runtime = DatabaseRuntime::bootstrap_with_session(
            DatabaseConfig::for_session(
                "desktop-portable-explicit-export",
                lifecycle.config().clone(),
            ),
            lifecycle,
        )
        .expect("portable runtime");
        let storage_state = DesktopStorageState::healthy(runtime);
        let read_state = ReadOnlyCommandState::bootstrap()
            .expect("read state")
            .with_graph_views(vec![test_export_graph_view()]);
        let export_state = DesktopExplicitExportState::default();
        let destination = portable_root
            .join("data")
            .join("exports")
            .join("graph_task620.sggraph");
        let request = ExplicitExportRequest::new(
            SessionId::new_v4(),
            ExplicitSaveAction::ExportGraph,
            destination.to_string_lossy().to_string(),
            "local_user",
        )
        .expect("explicit export request");
        let prepared = core::prepare_explicit_export(&read_state, request).expect("export preview");

        assert!(!destination.exists());
        let preview = export_state
            .store_pending(prepared.clone())
            .expect("store pending preview");
        assert_eq!(preview.format_contract.extension, ".sggraph");
        assert!(export_state
            .has_pending_or_active()
            .expect("pending export state"));
        assert!(!destination.exists());
        assert!(!portable_root
            .join("data")
            .join("exports")
            .join("export_history.jsonl")
            .exists());

        let prepared = export_state
            .take_pending(&prepared.request.export_id)
            .expect("take pending")
            .expect("pending export");
        let _write_guard = export_state.begin_write().expect("begin write");
        let destination_path =
            resolve_explicit_export_destination(&storage_state, &prepared).expect("destination");
        write_explicit_export_file(&destination_path, &prepared.content_redacted)
            .expect("write export");
        let artifact_integrity =
            explicit_export_artifact_integrity(&destination_path).expect("artifact integrity");
        let completion = core::finalize_explicit_export(
            &prepared,
            ExplicitExportConfirmation::confirmed(prepared.request.export_id.clone()),
            redacted_destination_directory(&destination_path),
            artifact_integrity.clone(),
        )
        .expect("finalize export");
        append_explicit_export_session_audit(&storage_state, completion.audit_event)
            .expect("session audit");
        append_explicit_export_history(&storage_state, &completion.history_entry).expect("history");
        drop(_write_guard);

        let artifact_bytes = std::fs::read(&destination).expect("artifact bytes");
        let artifact = String::from_utf8(artifact_bytes.clone()).expect("artifact text");
        let audit = std::fs::read_to_string(session_root.join("session_audit.log")).expect("audit");
        let history = std::fs::read_to_string(
            portable_root
                .join("data")
                .join("exports")
                .join("export_history.jsonl"),
        )
        .expect("history");

        assert!(destination.exists());
        assert!(artifact.contains("export_safe_graph_snapshot"));
        assert!(!artifact.contains("session_token destination"));
        assert!(!artifact.contains("authorization:"));
        assert_eq!(completion.result.file_hash, artifact_integrity.file_hash);
        assert_eq!(
            completion.result.file_size_bytes,
            artifact_integrity.file_size_bytes
        );
        assert_eq!(
            completion.result.file_hash,
            core::explicit_export_artifact_integrity_from_bytes(&artifact_bytes).file_hash
        );
        assert!(audit.contains("\"event_type\":\"export_performed\""));
        assert!(audit.contains("\"user_confirmed\":true"));
        assert!(history.contains("\"graph_export\""));
        assert!(history.contains("[export-dir:exports]"));
        assert!(!history.contains("graph_task620.sggraph"));

        storage_state.end_session();
        assert!(!session_root.exists());
        assert!(destination.exists());
        let _ = std::fs::remove_dir_all(portable_root);
    }

    #[test]
    fn desktop_portable_capture_import_preview_is_sanitized_confirmed_and_cleans_temp_artifact() {
        let portable_root = temp_startup_root("desktop-portable-capture-import");
        let lifecycle = SessionLifecycle::start(
            SessionMode::PortableNoRetention,
            SessionRootResolver::for_portable_root(portable_root.clone()),
        )
        .expect("portable lifecycle");
        let session_root = lifecycle.config().session_root.clone();
        let runtime = DatabaseRuntime::bootstrap_with_session(
            DatabaseConfig::for_session(
                "desktop-portable-capture-import",
                lifecycle.config().clone(),
            ),
            lifecycle,
        )
        .expect("portable runtime");
        let storage_state = DesktopStorageState::healthy(runtime);
        let read_state = DesktopReadState::bootstrap_with_service_status(
            service_status_for_storage(&storage_state),
        )
        .expect("desktop read state");
        let mutation_state = DesktopMutationState::bootstrap().expect("desktop mutation state");
        let import_state = DesktopPortableCaptureImportState::default();
        let source_path = portable_root.join("incoming").join("capture.har");
        std::fs::create_dir_all(source_path.parent().expect("source parent")).expect("source dir");
        std::fs::write(&source_path, portable_capture_har_fixture()).expect("source fixture");

        let preview = preview_portable_capture_import_from_path(
            &storage_state,
            &import_state,
            PortableCaptureImportFileRequest {
                source_path: source_path.to_string_lossy().to_string(),
                source_type: None,
            },
        )
        .expect("preview import");
        let preview_artifact_path = session_root.join(format!(
            "{CAPTURE_IMPORT_PREVIEW_FILE_PREFIX}{}{CAPTURE_IMPORT_PREVIEW_FILE_SUFFIX}",
            preview.preview_id
        ));
        let artifact = std::fs::read_to_string(&preview_artifact_path).expect("preview artifact");

        assert!(preview_artifact_path.exists());
        assert_eq!(preview.provenance.record_counts.flow_records, 4);
        assert!(!artifact.contains("access_token=secret"));
        assert!(!artifact.contains("C:/Users/Alice/Desktop"));
        assert!(!artifact.contains("uploader.example.test/upload/42"));

        let receipt = confirm_portable_capture_import_preview(
            &read_state,
            &mutation_state,
            &import_state,
            PortableCaptureImportConfirmation {
                preview_id: preview.preview_id.clone(),
                user_confirmed: true,
                reason_redacted: "portable import confirmed".to_string(),
                requested_by_redacted: Some("local_user".to_string()),
            },
        )
        .expect("confirm import");
        let flows = read_state
            .search_flows(QueryRequest::new(QueryScope::Global))
            .expect("flows");

        assert_eq!(receipt.result.flow_count, 4);
        assert!(receipt.result.alert_count > 0 || receipt.result.alert_candidate_count > 0);
        assert!(!preview_artifact_path.exists());
        assert_eq!(flows.items.len(), 4);

        storage_state.end_session();
        assert!(!session_root.exists());
        let _ = std::fs::remove_dir_all(portable_root);
    }

    #[test]
    fn desktop_portable_local_metadata_proxy_commands_refresh_read_models() {
        let read_state = DesktopReadState::bootstrap().expect("desktop read state");
        let mutation_state = DesktopMutationState::bootstrap().expect("desktop mutation state");

        let initial = mutation_state
            .get_local_metadata_proxy_status()
            .expect("initial proxy status");
        assert_eq!(initial.listen_host, "127.0.0.1");
        assert!(matches!(
            initial.state,
            core::LocalProxyMetadataProviderStateKind::Stopped
        ));

        let started = mutation_state
            .start_local_metadata_proxy(LocalProxyMetadataStartRequest::default())
            .expect("start local metadata proxy");
        sync_read_state_from_mutation(&read_state, &mutation_state).expect("sync after start");
        let port = started.listen_port.expect("listen port");

        send_local_metadata_proxy_request(
            port,
            "POST http://upload.example.test/api/v1/export/42?session_token=secret HTTP/1.1\r\nHost: upload.example.test\r\nUser-Agent: curl/8.8.0\r\nContent-Length: 2048\r\n\r\n",
        );

        let queued_status = (0..40)
            .find_map(|_| {
                let status = mutation_state
                    .get_local_metadata_proxy_status()
                    .expect("queued proxy status");
                if status.pending_event_count > 0 {
                    Some(status)
                } else {
                    thread::sleep(Duration::from_millis(25));
                    None
                }
            })
            .expect("queued metadata");
        assert!(queued_status.pending_event_count > 0);

        let drained = mutation_state
            .drain_local_metadata_proxy()
            .expect("drain local metadata proxy");
        sync_read_state_from_mutation(&read_state, &mutation_state).expect("sync after drain");
        let flows = read_state
            .search_flows(QueryRequest::new(QueryScope::Global))
            .expect("flows");

        assert_eq!(drained.pending_event_count, 0);
        assert!(drained.drained_event_count > 0);
        assert_eq!(flows.items.len(), 1);

        let stopped = mutation_state
            .stop_local_metadata_proxy()
            .expect("stop local metadata proxy");
        sync_read_state_from_mutation(&read_state, &mutation_state).expect("sync after stop");

        assert!(matches!(
            stopped.state,
            core::LocalProxyMetadataProviderStateKind::Stopped
        ));
        assert_eq!(stopped.listen_host, "127.0.0.1");
    }

    #[test]
    fn desktop_portable_capture_import_smoke_covers_har_jsonl_traceability_and_cleanup() {
        for (
            label,
            extension,
            content,
            expected_flow_count,
            expected_dns_count,
            expected_tls_count,
        ) in [
            (
                "har",
                "har",
                portable_capture_har_fixture(),
                4usize,
                0usize,
                4usize,
            ),
            (
                "jsonl",
                "jsonl",
                portable_capture_jsonl_fixture(),
                2usize,
                1usize,
                1usize,
            ),
        ] {
            let test_label = format!("desktop-portable-import-smoke-{label}");
            let portable_root = temp_startup_root(&test_label);
            let lifecycle = SessionLifecycle::start(
                SessionMode::PortableNoRetention,
                SessionRootResolver::for_portable_root(portable_root.clone()),
            )
            .expect("portable lifecycle");
            let session_root = lifecycle.config().session_root.clone();
            let runtime = DatabaseRuntime::bootstrap_with_session(
                DatabaseConfig::for_session(test_label.clone(), lifecycle.config().clone()),
                lifecycle,
            )
            .expect("portable runtime");
            let storage_state = DesktopStorageState::healthy(runtime);
            let read_state = DesktopReadState::bootstrap_with_service_status(
                service_status_for_storage(&storage_state),
            )
            .expect("desktop read state");
            let mutation_state = DesktopMutationState::bootstrap().expect("desktop mutation state");
            let import_state = DesktopPortableCaptureImportState::default();
            let export_state = DesktopExplicitExportState::default();
            let source_path = portable_root
                .join("incoming")
                .join(format!("capture.{extension}"));
            std::fs::create_dir_all(source_path.parent().expect("source parent"))
                .expect("source dir");
            std::fs::write(&source_path, &content).expect("source fixture");

            let preview = preview_portable_capture_import_from_path(
                &storage_state,
                &import_state,
                PortableCaptureImportFileRequest {
                    source_path: source_path.to_string_lossy().to_string(),
                    source_type: None,
                },
            )
            .expect("preview import");
            let preview_artifact_path = session_root.join(format!(
                "{CAPTURE_IMPORT_PREVIEW_FILE_PREFIX}{}{CAPTURE_IMPORT_PREVIEW_FILE_SUFFIX}",
                preview.preview_id
            ));
            let preview_artifact =
                std::fs::read_to_string(&preview_artifact_path).expect("preview artifact");

            assert!(preview_artifact_path.exists());
            assert_eq!(
                preview.provenance.record_counts.flow_records as usize,
                expected_flow_count
            );
            assert!(preview
                .declared_topics
                .iter()
                .any(|topic| topic == "service.capability_status"));
            for marker in [
                "access_token=secret",
                "token=abcdef1234567890",
                "C:/Users/Alice/Desktop",
                "uploader.example.test/upload/42",
                "jsonl.example.test/upload/9",
            ] {
                assert!(
                    !preview_artifact.contains(marker),
                    "preview artifact leaked forbidden marker {marker}"
                );
            }

            let import_receipt = confirm_portable_capture_import_preview(
                &read_state,
                &mutation_state,
                &import_state,
                PortableCaptureImportConfirmation {
                    preview_id: preview.preview_id.clone(),
                    user_confirmed: true,
                    reason_redacted: format!("portable import confirmed for {label}"),
                    requested_by_redacted: Some("local_user".to_string()),
                },
            )
            .expect("confirm import");
            let flows = read_state
                .search_flows(QueryRequest::new(QueryScope::Global))
                .expect("flows");
            let findings = read_state
                .search_findings(QueryRequest::new(QueryScope::Global))
                .expect("findings");
            let alerts = read_state
                .search_alerts(QueryRequest::new(QueryScope::Global))
                .expect("alerts");
            let dns = read_state
                .search_dns(QueryRequest::new(QueryScope::Global))
                .expect("dns");
            let tls = read_state
                .search_tls(QueryRequest::new(QueryScope::Global))
                .expect("tls");

            assert_eq!(import_receipt.result.flow_count, expected_flow_count);
            assert_eq!(import_receipt.result.dns_count, expected_dns_count);
            assert_eq!(import_receipt.result.tls_count, expected_tls_count);
            assert!(import_receipt.result.report_traceability_ready);
            assert!(!preview_artifact_path.exists());
            assert_eq!(flows.items.len(), expected_flow_count);
            assert!(!findings.items.is_empty());
            assert!(import_receipt.result.alert_candidate_count > 0 || !alerts.items.is_empty());
            assert_eq!(dns.items.len(), expected_dns_count);
            assert_eq!(tls.items.len(), expected_tls_count);

            let active_session_id = storage_state
                .runtime()
                .and_then(DatabaseRuntime::session_lifecycle)
                .map(|session| SessionId::from_uuid(session.config().session_id))
                .expect("active session id");
            let session_export_destination = portable_root
                .join("data")
                .join("exports")
                .join(format!("{label}-portable-import.sgsession"));
            let source_path_redacted = source_path.to_string_lossy().to_string();
            let export_request = ExplicitExportRequest::new(
                active_session_id,
                ExplicitSaveAction::SaveSession,
                session_export_destination.to_string_lossy().to_string(),
                "local_user",
            )
            .expect("session export request");
            let prepared_export = read_state
                .with_core(|core| core::prepare_explicit_export(core, export_request))
                .expect("preview explicit export");

            assert!(prepared_export
                .content_redacted
                .contains("\"imported_capture_sources\": 1"));
            assert!(prepared_export
                .content_redacted
                .contains("\"portable_capture_sources\""));
            for marker in [
                "access_token=secret",
                "token=abcdef1234567890",
                "C:/Users/Alice/Desktop",
                "uploader.example.test/upload/42",
                "jsonl.example.test/upload/9",
                source_path_redacted.as_str(),
            ] {
                assert!(
                    !prepared_export.content_redacted.contains(marker),
                    "explicit export preview leaked forbidden marker {marker}"
                );
            }

            export_state
                .store_pending(prepared_export.clone())
                .expect("store pending export");
            let prepared_export = export_state
                .take_pending(&prepared_export.request.export_id)
                .expect("take pending export")
                .expect("stored pending export");
            let _write_guard = export_state.begin_write().expect("begin write");
            let destination_path =
                resolve_explicit_export_destination(&storage_state, &prepared_export)
                    .expect("explicit export destination");
            write_explicit_export_file(&destination_path, &prepared_export.content_redacted)
                .expect("write explicit export");
            let artifact_integrity =
                explicit_export_artifact_integrity(&destination_path).expect("artifact integrity");
            let completion = core::finalize_explicit_export(
                &prepared_export,
                ExplicitExportConfirmation::confirmed(prepared_export.request.export_id.clone()),
                redacted_destination_directory(&destination_path),
                artifact_integrity.clone(),
            )
            .expect("finalize explicit export");
            append_explicit_export_session_audit(&storage_state, completion.audit_event)
                .expect("explicit export audit");
            append_explicit_export_history(&storage_state, &completion.history_entry)
                .expect("explicit export history");
            drop(_write_guard);

            let artifact =
                std::fs::read_to_string(&session_export_destination).expect("session export");
            let session_audit =
                std::fs::read_to_string(session_root.join("session_audit.log")).expect("audit");
            let explicit_history = std::fs::read_to_string(
                portable_root
                    .join("data")
                    .join("exports")
                    .join("export_history.jsonl"),
            )
            .expect("explicit export history");

            assert!(artifact.contains("\"portable_capture_sources\""));
            assert!(artifact.contains("\"imported_capture_sources\": 1"));
            assert!(session_audit.contains("\"event_type\":\"export_performed\""));
            assert!(explicit_history.contains("\"session_save\""));
            assert!(!session_root.join(format!("capture.{extension}")).exists());
            assert!(!portable_root
                .join("data")
                .join("exports")
                .join(format!("capture.{extension}"))
                .exists());

            storage_state.end_session();
            assert!(!session_root.exists());
            let remaining_sessions = if portable_root.join("temp").join("sessions").exists() {
                std::fs::read_dir(portable_root.join("temp").join("sessions"))
                    .expect("sessions root")
                    .filter_map(Result::ok)
                    .filter(|entry| entry.path().is_dir())
                    .count()
            } else {
                0
            };
            assert_eq!(remaining_sessions, 0);
            assert!(session_export_destination.exists());

            let _ = std::fs::remove_dir_all(portable_root);
        }
    }

    #[test]
    fn desktop_mutation_state_delegates_to_core_permissions_and_audit() {
        let read = ReadOnlyCommandState::bootstrap().expect("read state");
        let plugin_id = core::get_plugin_catalog(&read).expect("catalog").plugins[0]
            .plugin_id
            .clone();
        let state = DesktopMutationState::from_core(
            MutationCommandState::from_read_state(read).expect("mutation state"),
        );
        let request: PluginLifecycleRequest = serde_json::from_value(json!({
            "plugin_id": plugin_id.to_string(),
            "reason_redacted": "operator requested component validation",
            "requested_by_redacted": "local_user"
        }))
        .expect("deserialize mutation request");

        let receipt = state.enable_plugin(request).expect("enable plugin");
        let audit_count = state
            .with_core(|core| Ok(core.audit_records().len()))
            .expect("audit count");

        assert_eq!(receipt.command, "enable_plugin");
        assert_eq!(receipt.result.state, PluginLifecycleMutationState::Enabled);
        assert!(!receipt.result.applied_to_runtime);
        assert!(receipt.permission_decision.is_ready());
        assert_eq!(audit_count, 1);
        assert_eq!(receipt.audit_receipt.sequence, 1);
        assert!(receipt.rollback.is_none());
    }

    #[test]
    fn desktop_mutation_state_preserves_structured_errors() {
        let state = DesktopMutationState::bootstrap().expect("desktop mutation state");
        let error = state
            .enable_plugin(PluginLifecycleRequest {
                plugin_id: PluginId::new_v4(),
                reason_redacted: "missing plugin validation".to_string(),
                requested_by_redacted: Some("local_user".to_string()),
            })
            .expect_err("missing plugin");

        assert_eq!(error.error_code, ErrorCode::InvalidRequest);
        assert!(error.trace_id.is_some());
        assert!(error.details_redacted.is_some());
    }

    #[test]
    fn desktop_event_state_dispatches_all_named_streams_with_hints() {
        let state = DesktopEventState::bootstrap().expect("event state");

        state.health_stream(health_update()).expect("health");
        state.metric_stream(metric_update()).expect("metric");
        state
            .capture_status_stream(capture_update(CaptureStatusKind::Running))
            .expect("capture");
        state
            .service_status_stream(service_update(false))
            .expect("service");
        state.alert_stream(alert_update()).expect("alert");
        state
            .incident_stream(incident_update(SecuritySeverity::High))
            .expect("incident");
        state.graph_update_stream(graph_update()).expect("graph");
        state
            .response_status_stream(response_update(ResponseStatusKind::PlanCreated))
            .expect("response");
        state
            .report_progress_stream(report_update(ReportProgressPhase::Generated))
            .expect("report");
        state
            .privacy_warning_stream(privacy_update(PrivacyWarningKind::SensitiveDataSuppressed))
            .expect("privacy");

        let events = state.pending_events().expect("pending events");
        assert_eq!(events.len(), 10);
        assert_eq!(
            events
                .iter()
                .map(|event| event.stream.as_str())
                .collect::<Vec<_>>(),
            STREAM_EVENT_NAMES
        );
        assert!(events
            .iter()
            .all(|event| !event.invalidation_hints.is_empty()));
        assert!(events
            .iter()
            .all(|event| serde_json::to_string(event).expect("json").len() < 4096));
        assert!(state.drain_pending_events().expect("drain").len() == 10);
        assert!(state.pending_events().expect("pending").is_empty());
    }

    #[test]
    fn desktop_event_state_preserves_p0_priority_mapping() {
        let state = DesktopEventState::bootstrap().expect("event state");
        let service = state
            .service_status_stream(service_update(true))
            .expect("service disconnected");
        let response_failed = state
            .response_status_stream(response_update(ResponseStatusKind::ActionFailed))
            .expect("response failed");
        let rollback_failed = state
            .response_status_stream(response_update(ResponseStatusKind::RollbackFailed))
            .expect("rollback failed");
        let incident = state
            .incident_stream(incident_update(SecuritySeverity::Critical))
            .expect("critical incident");
        let forensic = state
            .privacy_warning_stream(privacy_update(PrivacyWarningKind::ForensicModeEnabled))
            .expect("forensic");

        for event in [
            service,
            response_failed,
            rollback_failed,
            incident,
            forensic,
        ] {
            assert_eq!(event.priority, PriorityLane::P0Critical);
            assert!(!event.priority.can_drop_under_pressure());
        }
    }

    #[test]
    fn desktop_event_state_rejects_sensitive_stream_markers() {
        let state = DesktopEventState::bootstrap().expect("event state");
        let mut update = privacy_update(PrivacyWarningKind::SensitiveDataSuppressed);
        update.summary_redacted = "raw_payload marker must not stream".to_string();

        let error = state
            .privacy_warning_stream(update)
            .expect_err("privacy marker rejected");

        assert_eq!(error.error_code, ErrorCode::PrivacyPolicyViolation);
        assert!(error.trace_id.is_some());
        assert!(error.details_redacted.is_some());
    }

    #[test]
    fn graph_command_accepts_frontend_wire_shape_and_returns_view_model() {
        let state = DesktopReadState::bootstrap().expect("desktop read state");
        let request: GraphViewRequest = serde_json::from_value(json!({
            "graph_type": "c2_graph",
            "scope": { "type": "overview" },
            "title_redacted": "C2 graph",
            "node_limit": 25,
            "edge_limit": 50
        }))
        .expect("deserialize graph request");

        let view = state.get_graph_view(request).expect("graph view");
        let serialized = serde_json::to_string(&view).expect("serialize graph view");

        assert_eq!(view.graph_type, GraphType::C2Graph);
        assert_eq!(view.filters.scope, GraphScope::Overview);
        assert_eq!(view.node_limit, 25);
        assert_eq!(view.edge_limit, 50);
        assert!(!serialized.contains("canonical_node"));
        assert!(!serialized.contains("canonical_edge"));
    }

    #[test]
    fn unsupported_query_shape_keeps_core_error_contract() {
        let state = DesktopReadState::bootstrap().expect("desktop read state");
        let request = QueryRequest::new(QueryScope::LocalHost);
        let error = state
            .search_flows(request)
            .expect_err("unsupported non-global scope");

        assert_eq!(error.error_code, ErrorCode::UnsupportedOperation);
        assert!(error.trace_id.is_some());
        assert!(error.details_redacted.is_some());
    }

    fn health_update() -> HealthStreamUpdate {
        HealthStreamUpdate {
            subject: HealthSubjectRef::Plugin {
                plugin_id: PluginId::new_v4(),
            },
            status: ObservabilityHealthStatus::Healthy,
            liveness: ObservabilityHealthStatus::Healthy,
            readiness: ObservabilityHealthStatus::Healthy,
            message_redacted: Some("plugin health changed".to_string()),
            observed_at: Timestamp::now(),
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn metric_update() -> MetricStreamUpdate {
        MetricStreamUpdate {
            plugin_id: Some(PluginId::new_v4()),
            metric_name: "events_out_total".to_string(),
            value: MetricValueSummary::Counter(3),
            label_count: 1,
            observed_at: Timestamp::now(),
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn capture_update(status: CaptureStatusKind) -> CaptureStatusUpdate {
        CaptureStatusUpdate {
            status,
            adapter_name: "metadata_capture".to_string(),
            packet_rate_per_second: Some(12.0),
            drop_rate: Some(0.0),
            reduced_visibility: false,
            message_redacted: "capture status changed".to_string(),
        }
    }

    fn service_update(disconnected: bool) -> ServiceStatusUpdate {
        ServiceStatusUpdate {
            profile_mode: "ephemeral".to_string(),
            local_core_status: ObservabilityHealthStatus::Healthy,
            elevated_service_status: if disconnected {
                ObservabilityHealthStatus::Disconnected
            } else {
                ObservabilityHealthStatus::Healthy
            },
            ipc_status: if disconnected {
                ObservabilityHealthStatus::Disconnected
            } else {
                ObservabilityHealthStatus::Healthy
            },
            storage_status: ObservabilityHealthStatus::Healthy,
            reduced_visibility: disconnected,
            privileged_actions_available: false,
            capture_available: false,
            machine_local_capability_status: None,
            message_redacted: if disconnected {
                "elevated service disconnected".to_string()
            } else {
                "service status changed".to_string()
            },
        }
    }

    fn alert_update() -> AlertStreamUpdate {
        AlertStreamUpdate {
            alert_id: AlertId::new_v4(),
            state: AlertState::New,
            severity: SecuritySeverity::High,
            finding_count: 1,
            summary_redacted: "new alert".to_string(),
        }
    }

    fn incident_update(severity: SecuritySeverity) -> IncidentStreamUpdate {
        IncidentStreamUpdate {
            incident_id: IncidentId::new_v4(),
            state: IncidentState::New,
            severity,
            alert_count: 1,
            graph_path_count: 0,
            summary_redacted: "incident changed".to_string(),
        }
    }

    fn graph_update() -> GraphUpdateStreamUpdate {
        GraphUpdateStreamUpdate {
            graph_type: GraphType::IncidentGraph,
            scope: GraphScope::Overview,
            graph_view_id: Some(GraphViewId::new_v4()),
            changed_node_count: 2,
            changed_edge_count: 1,
            changed_path_count: 0,
            summary_redacted: "graph view changed".to_string(),
        }
    }

    #[test]
    fn desktop_authorized_native_control_plane_grants_inactive_and_revokes() {
        let state = DesktopMutationState::bootstrap().expect("mutation state");
        let preview = state
            .preview_native_permission_request("native_host_visibility".to_string())
            .expect("preview");
        assert!(!preview.state_change_performed);
        assert!(!preview.telemetry_collection_started);

        let granted = state
            .update_native_permission(NativePermissionActionRequest {
                capability_id: "native_host_visibility".to_string(),
                action: sentinel_contracts::NativePermissionAction::GrantAuthorization,
                explicit_user_action: true,
                reason_redacted: "authorize read only visibility".to_string(),
            })
            .expect("grant");
        assert!(!granted.telemetry_collection_started);
        assert_eq!(
            granted.capability.availability_state,
            sentinel_contracts::NativeCapabilityAvailabilityState::AuthorizedSamplerInactive
        );

        let revoked = state
            .update_native_permission(NativePermissionActionRequest {
                capability_id: "native_host_visibility".to_string(),
                action: sentinel_contracts::NativePermissionAction::RevokeAuthorization,
                explicit_user_action: true,
                reason_redacted: "revoke native authorization".to_string(),
            })
            .expect("revoke");
        assert!(revoked.capability.revoked);
        assert!(!revoked.capability.sampler_policy_allows_collection());
    }

    fn response_update(status: ResponseStatusKind) -> ResponseStatusUpdate {
        ResponseStatusUpdate {
            plan_id: Some(ResponsePlanId::new_v4()),
            action_id: Some(ResponseActionId::new_v4()),
            status,
            rollback_available: true,
            approval_required: true,
            summary_redacted: "response status changed".to_string(),
        }
    }

    fn report_update(phase: ReportProgressPhase) -> ReportProgressUpdate {
        ReportProgressUpdate {
            report_id: Some(ReportId::new_v4()),
            phase,
            status: Some(ReportStatus::ReadyForExport),
            progress_percent: Some(100),
            summary_redacted: "report progress changed".to_string(),
        }
    }

    fn privacy_update(warning_kind: PrivacyWarningKind) -> PrivacyWarningUpdate {
        PrivacyWarningUpdate {
            warning_kind,
            active: true,
            user_visible: true,
            summary_redacted: "privacy warning changed".to_string(),
        }
    }

    fn temp_startup_root(label: &str) -> PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        env::current_dir()
            .unwrap_or_else(|_| env::temp_dir())
            .join("target")
            .join("desktop-startup-tests")
            .join(format!("{label}-{suffix}"))
    }

    fn test_export_graph_view() -> GraphViewModel {
        let evidence_id = EvidenceId::new_v4();
        let mut process = GraphNodeViewModel::new(
            GraphNodeType::Process,
            RedactedLabel::redacted("process", PrivacyClass::Internal).expect("label"),
        );
        process.risk_score = QualityScore::new(0.74).expect("quality");
        process.detail_ref.evidence_refs = vec![evidence_id.clone()];

        let mut incident = GraphNodeViewModel::new(
            GraphNodeType::Incident,
            RedactedLabel::redacted("incident", PrivacyClass::Internal).expect("label"),
        );
        incident.risk_score = QualityScore::new(0.88).expect("quality");
        incident.detail_ref.evidence_refs = vec![evidence_id.clone()];

        let mut edge = GraphEdgeViewModel::new(
            GraphEdgeType::ObservationSupportsFinding,
            process.node_id.clone(),
            incident.node_id.clone(),
        );
        edge.label = Some(
            RedactedLabel::redacted("evidence-backed link", PrivacyClass::Internal).expect("label"),
        );
        edge.confidence = QualityScore::new(0.86).expect("quality");
        edge.evidence_refs = vec![evidence_id.clone()];

        let mut view = GraphViewModel::new(
            GraphType::IncidentGraph,
            RedactedLabel::redacted("incident graph", PrivacyClass::Internal).expect("title"),
            GraphScope::Overview,
        );
        view.nodes = vec![process, incident];
        view.edges = vec![edge];
        view.paths = vec![GraphPathSummary {
            path_id: GraphPathId::new_v4(),
            path_type: GraphPathType::IncidentSummaryPath,
            label: RedactedLabel::redacted("incident summary path", PrivacyClass::Internal)
                .expect("path label"),
            risk_score: QualityScore::new(0.88).expect("quality"),
            confidence: QualityScore::new(0.86).expect("quality"),
            evidence_refs: vec![evidence_id],
        }];
        view.redaction_status = RedactionStatus::Redacted;
        view.redaction_summary = GraphRedactionSummary {
            status: RedactionStatus::Redacted,
            redacted_node_count: view.nodes.len() as u32,
            redacted_edge_count: view.edges.len() as u32,
            hidden_label_count: (view.nodes.len() + view.edges.len()) as u32,
            notes: vec!["desktop graph export test uses redacted view data".to_string()],
        };
        view.original_node_count = view.nodes.len() as u32;
        view.original_edge_count = view.edges.len() as u32;
        view
    }
}
