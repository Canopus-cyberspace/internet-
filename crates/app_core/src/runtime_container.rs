use crate::baseline_read_models::build_durable_baseline_summary;
use crate::canonical_read_models::canonical_read_model_ownership_inventory;
use crate::endpoint_threat_runtime::{
    get_endpoint_threat_analysis_summary, EndpointThreatAnalysisSummary,
};
use crate::etw_lifecycle::{
    ServiceOwnedAuthRemoteSensingLifecycleRuntime, ServiceOwnedDnsSensingLifecycleRuntime,
    ServiceOwnedEtwLifecycleRuntime,
};
use crate::evidence_quality::build_evidence_quality_summary;
use crate::mutation_commands::MutationCommandState;
use crate::read_commands::{build_attack_coverage_summary, ReadOnlyCommandState};
use crate::runtime_architecture::legacy_runtime_constructor_inventory;
use sentinel_capabilities::{
    register_static_api_security_lite_plugin, register_static_asset_exposure_plugin,
    register_static_auth_identity_analysis_lite_plugin, register_static_c2_detection_plugin,
    register_static_deception_event_lite_plugin, register_static_dns_security_v2_plugin,
    register_static_endpoint_threat_analysis_lite_plugin,
    register_static_exfiltration_detection_plugin, register_static_flow_sessionization_plugin,
    register_static_http_analysis_v1_plugin, register_static_lateral_movement_plugin,
    register_static_multi_layer_security_fusion_plugin, register_static_native_network_fact_plugin,
    register_static_native_sampler_fact_plugin,
    register_static_portable_saas_cloud_abuse_lite_plugin,
    register_static_quic_http3_security_lite_plugin,
    register_static_remote_admin_protocol_lite_plugin, register_static_response_planning_plugin,
    register_static_risk_alerting_plugin, register_static_waf_security_lite_plugin,
    run_portable_capture_lite_with_runtime, GraphAnalyticsService, GraphStagePlugin,
    MultiLayerSecurityFusionPlugin, PortableCaptureLiteError, PortableCaptureLitePreparedBatch,
    PortableCaptureLiteRunResult, PortableCaptureRuntimeContext, RiskBasedAlertingPlugin,
    AUTH_IDENTITY_ANALYSIS_LITE_STATIC_PLUGIN_ID, DNS_SECURITY_V2_STATIC_PLUGIN_ID,
    MULTI_LAYER_SECURITY_FUSION_STATIC_PLUGIN_ID, NATIVE_NETWORK_FACT_STATIC_PLUGIN_ID,
    REMOTE_ADMIN_PROTOCOL_LITE_STATIC_PLUGIN_ID,
};
use sentinel_contracts::provider_controller::{
    NetworkFallbackPlan, NetworkProviderControllerMode, NetworkProviderControllerState,
    NetworkProviderControllerStatus, NetworkProviderImplementationState, NetworkProviderKind,
    NetworkProviderLifecycleState, NetworkProviderStatus, NetworkProviderZeroCounters,
    NetworkVisibilityDimension, NetworkVisibilityState, NetworkVisibilitySummary,
    MAX_NETWORK_PROVIDER_REFS,
};
use sentinel_contracts::read_model_snapshot::{
    CanonicalReadModelCategory, CanonicalReadModelSnapshot, CanonicalReadModelSnapshotItem,
    CanonicalReportExportTraceabilitySnapshot, ReadModelSnapshotFreshness,
    MAX_REPORT_EXPORT_TRACEABILITY_REFS, READ_MODEL_SNAPSHOT_SCHEMA_VERSION,
    REPORT_EXPORT_TRACEABILITY_SCHEMA_VERSION,
};
use sentinel_contracts::runtime_ownership::{
    RuntimeAuthorizationCategory, RuntimeComponentCategory, RuntimeComponentLifecycle,
    RuntimeComponentOwnershipSummary, RuntimeHealthState, RuntimeMode, RuntimeMutationTrustState,
    RuntimeOwnerCategory, RuntimeOwnerContext, RuntimeOwnershipAuditEvent,
    RuntimeOwnershipAuditEventKind, RuntimeOwnershipSummary, RuntimeProviderZeroSummary,
    RuntimeShutdownStage, RuntimeShutdownStageState, RuntimeShutdownStageSummary,
    RuntimeShutdownState, RuntimeShutdownSummary, RuntimeTransitionState,
    MAX_RUNTIME_OWNERSHIP_AUDIT_REFS, RUNTIME_OWNERSHIP_PROTOCOL_VERSION,
    RUNTIME_OWNERSHIP_SCHEMA_VERSION,
};
use sentinel_contracts::{
    AttackCoverageSummary, AuditId, CommandResult, ContractDescriptor, CoreError,
    DurableBaselineSummary, ErrorCode, ErrorSeverity, EtwAuthorizationState, EtwFallbackState,
    EtwLifecycleState, EtwLifecycleStatus, EtwNormalizedNetworkBatch, EventEnvelope, EventType,
    EvidenceItem, EvidenceQualitySummary, Finding, GraphHint, IpHelperScheduleConfig,
    IpHelperScheduleCountBucket, IpHelperScheduleIntervalBucket, IpHelperScheduleLeaseState,
    IpHelperScheduleNextDueCategory, IpHelperScheduleRetryBudgetBucket, IpHelperScheduleState,
    IpHelperScheduleStatus, IpHelperScheduleTimeoutBucket, IpHelperScheduledAuthorizationState,
    IpHelperScheduledBackpressureState, IpHelperScheduledCycleRecord, IpHelperScheduledCycleType,
    IpHelperScheduledDueState, IpHelperScheduledExecutionResult, IpHelperScheduledFreshnessState,
    IpHelperScheduledMissedSampleState, IpHelperScheduledRetryState,
    NativeConnectionRelationCategory, NativeConnectionServiceBucket, NativeConnectionStateBucket,
    NativeEndpointRangeBucket, NativeEndpointScopeCategory, NativeIpHelperConnectionCategoryRecord,
    NativeIpHelperMetadataBatch, NativeNetworkFreshness, NativeNetworkProviderCategory,
    NativeNetworkProviderHealth, NativeNetworkTransportCategory, NativeOwnerPresenceCategory,
    NativePermissionAction, NativePermissionActionRequest, NativePermissionActionResult,
    NativeSamplerRuntimeAction, NativeSamplerRuntimeActionRequest,
    NativeSamplerRuntimeActionResult, NativeSamplerRuntimeStatus, PluginId,
    PortableAuthAttemptCountBucket, PortableAuthMetadata, PortableAuthResultCategory,
    PortableCaptureInputSourceType, PortableCaptureProvenance, PortableCaptureRecordCounts,
    PrivacyClass, QualityScore, ReadModelSnapshotId, RedactionStatus, RiskHint, SchemaVersion,
    SecurityFact, ServiceCapabilityContext, Timestamp, TraceContext, WindowsAuthFailureCategory,
    WindowsAuthRemoteObservation, WindowsAuthRemoteObservationBatch, WindowsAuthResultCategory,
    WindowsDnsObservationBatch, WindowsRemoteProtocolCategory, IP_HELPER_SCHEDULED_CYCLE_COMPLETED,
    IP_HELPER_SCHEDULED_CYCLE_DUE, IP_HELPER_SCHEDULED_CYCLE_FAILED,
    IP_HELPER_SCHEDULED_CYCLE_RETRY_SCHEDULED, IP_HELPER_SCHEDULED_CYCLE_SKIPPED,
    IP_HELPER_SCHEDULED_CYCLE_STARTED, IP_HELPER_SCHEDULER_HOST_STARTED,
    IP_HELPER_SCHEDULER_HOST_STOPPED, IP_HELPER_SCHEDULE_CONFIGURED, IP_HELPER_SCHEDULE_DISABLED,
    IP_HELPER_SCHEDULE_ENABLED, IP_HELPER_SCHEDULE_INVALIDATED, IP_HELPER_SCHEDULE_LEASE_CREATED,
    IP_HELPER_SCHEDULE_PAUSED, IP_HELPER_SCHEDULE_PROVIDER_STOPPED, IP_HELPER_SCHEDULE_RESUMED,
    IP_HELPER_SCHEDULE_SESSION_INVALIDATED,
};
use sentinel_infrastructure::{
    smb_schema_has_auth_context, ssh_schema_has_auth_context, BoundedProviderRequest,
    IpHelperAddressScope, IpHelperConnectionCategory, IpHelperEndpointRange, IpHelperOwnerSignal,
    IpHelperProviderStatus, IpHelperServiceCategory, IpHelperSnapshotAdapter,
    IpHelperSnapshotSummary, IpHelperStateCategory, IpHelperTransport, NetworkMetadataAdapter,
    ProviderProbe, PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
};
use sentinel_platform::registry::{
    CapabilityRegistry, ComponentRegistry, ContractRegistry, DependencyRegistry, PluginRegistry,
    RuntimeRegistry,
};
use sentinel_platform::{
    BuiltInPluginCatalog, CheckpointSupport, EventBus, EventBusError, ExecutionPlan,
    PermissionResolver, PipelineDag, PipelineNode, PipelineStage, PluginContext, PluginEventBatch,
    PluginRuntime, PolicyScope, PublishOptions, PublishReport, ReplaySupport, StageBinding,
    TopicName, ASSET_EXPOSURE, ASSET_EXPOSURE_OBSERVATION, ASSET_PORT_EXPOSURE, ASSET_RECORD,
    ASSET_SERVICE_RECORD, AUDIT_ENDPOINT_THREAT_ANALYSIS, AUDIT_NETWORK_PROVIDER_EXECUTION,
    CLOUD_SAAS_METADATA, DECEPTION_EVENT_METADATA, ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT,
    ENDPOINT_PROCESS_CATEGORY_FACT, ENDPOINT_PROCESS_PARENT_CATEGORY_FACT,
    ENDPOINT_SERVICE_CATEGORY_FACT, ENDPOINT_THREAT_CANDIDATE, ENDPOINT_THREAT_EVIDENCE,
    ENDPOINT_THREAT_FINDING, ENDPOINT_THREAT_REJECTED, ENDPOINT_THREAT_RISK_HINT,
    ENDPOINT_VISIBILITY_ADVISORY, GRAPH_HINT, IDENTITY_AUTH_METADATA, IDENTITY_PROCESS_CONTEXT,
    IDENTITY_RDP_OPERATIONAL_METADATA, IDENTITY_SMB_OPERATIONAL_METADATA,
    IDENTITY_SSH_OPERATIONAL_METADATA, INTEL_CERTIFICATE_CONTEXT, INTEL_CLOUD_CONTEXT,
    INTEL_DOMAIN_CONTEXT, INTEL_IP_CONTEXT, NATIVE_CONNECTION_CATEGORY_FACT,
    NATIVE_ETW_NETWORK_METADATA, NATIVE_HEALTH_METADATA, NATIVE_IP_HELPER_METADATA,
    NATIVE_PROCESS_METADATA, NATIVE_PROCESS_PARENT_METADATA, NATIVE_SERVICE_METADATA,
    NETWORK_DNS_OBSERVATION, NETWORK_FLOW_RECORD, NETWORK_HTTP_METADATA, NETWORK_PROVIDER_STATUS,
    NETWORK_SDN_CONTROL_PLANE_METADATA, NETWORK_SESSION_RECORD, NETWORK_TLS_OBSERVATION,
    NETWORK_VISIBILITY_STATUS, SECURITY_ALERT, SECURITY_EVIDENCE, SECURITY_FACT, SECURITY_FINDING,
    SECURITY_FINDING_ASSET_RISK, SECURITY_FUSION_CONTEXT, SECURITY_FUSION_SUMMARY,
    SECURITY_HYPOTHESIS, SECURITY_INCIDENT, SECURITY_RISK, SERVICE_CAPABILITY_STATUS,
};
use sentinel_storage::{
    service_host_durable_storage_manifest, ServiceHostDurableStorageManifest,
    ServiceHostStorageRecoveryReport, StorageOwnershipStatus, StorageWriterLease,
    StorageWriterState,
};
use serde_json::json;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

const RUNTIME_CONTAINER_PROVENANCE: &str = "service_host_runtime_container";
const SERVICE_HOST_INSTANCE_REF: &str = "service-host-instance";
const SHUTDOWN_STAGE_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CANONICAL_READ_MODEL_GENERATIONS: usize = 8;

static RUNTIME_OWNERSHIP_STATE: Mutex<Option<RuntimeOwnershipLeaseState>> = Mutex::new(None);

#[derive(Clone, Debug)]
pub(crate) struct RuntimeEventBusHandle {
    inner: Arc<Mutex<EventBus>>,
}

impl RuntimeEventBusHandle {
    fn new_service_core_topics() -> Self {
        Self {
            inner: Arc::new(Mutex::new(EventBus::with_core_topics())),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_legacy_core_topics() -> Self {
        Self {
            inner: Arc::new(Mutex::new(EventBus::with_core_topics())),
        }
    }

    pub(crate) fn publish(
        &self,
        topic_name: TopicName,
        envelope: sentinel_contracts::EventEnvelope,
        options: PublishOptions,
    ) -> Result<PublishReport, EventBusError> {
        self.inner
            .lock()
            .expect("runtime event bus lock")
            .publish(topic_name, envelope, options)
    }

    fn topic_count(&self) -> usize {
        self.inner
            .lock()
            .expect("runtime event bus lock")
            .topics()
            .len()
    }

    fn with_bus<T>(
        &self,
        operation: impl FnOnce(&mut EventBus) -> Result<T, PortableCaptureLiteError>,
    ) -> Result<T, PortableCaptureLiteError> {
        let mut bus = self.inner.lock().map_err(|_| {
            PortableCaptureLiteError::Runtime("runtime event bus unavailable".into())
        })?;
        operation(&mut bus)
    }
}

#[derive(Clone)]
pub(crate) struct RuntimePluginHandle {
    inner: Arc<Mutex<PluginRuntime>>,
}

impl fmt::Debug for RuntimePluginHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimePluginHandle")
            .finish_non_exhaustive()
    }
}

impl RuntimePluginHandle {
    fn new(runtime: PluginRuntime) -> Self {
        Self {
            inner: Arc::new(Mutex::new(runtime)),
        }
    }

    fn registration_count(&self) -> usize {
        self.inner
            .lock()
            .expect("runtime plugin lock")
            .registry()
            .list()
            .len()
    }

    fn with_runtime<T>(
        &self,
        operation: impl FnOnce(&mut PluginRuntime) -> Result<T, PortableCaptureLiteError>,
    ) -> Result<T, PortableCaptureLiteError> {
        let mut runtime = self.inner.lock().map_err(|_| {
            PortableCaptureLiteError::Runtime("runtime plugin service unavailable".into())
        })?;
        operation(&mut runtime)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeOwnershipLeaseState {
    ownership_ref: String,
    ownership_epoch: u64,
    owner_category: RuntimeOwnerCategory,
    runtime_mode: RuntimeMode,
    shutdown_in_progress: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeOwnershipError {
    RuntimeOwnerRequired,
    RuntimeOwnerMismatch,
    RuntimeAlreadyOwned,
    DuplicateRuntimeContainer,
    StaleOwnershipEpoch,
    OwnershipTransitionInProgress,
    RuntimeShutdownInProgress,
    PortableFallbackNotAuthorized,
    TestOwnerRequired,
    RuntimeInitializationFailed(&'static str),
}

impl RuntimeOwnershipError {
    pub fn reason_category(&self) -> &'static str {
        match self {
            Self::RuntimeOwnerRequired => "runtime_owner_required",
            Self::RuntimeOwnerMismatch => "runtime_owner_mismatch",
            Self::RuntimeAlreadyOwned => "runtime_already_owned",
            Self::DuplicateRuntimeContainer => "duplicate_runtime_container",
            Self::StaleOwnershipEpoch => "stale_ownership_epoch",
            Self::OwnershipTransitionInProgress => "ownership_transition_in_progress",
            Self::RuntimeShutdownInProgress => "runtime_shutdown_in_progress",
            Self::PortableFallbackNotAuthorized => "portable_fallback_not_authorized",
            Self::TestOwnerRequired => "test_owner_required",
            Self::RuntimeInitializationFailed(reason) => reason,
        }
    }
}

impl fmt::Display for RuntimeOwnershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason_category())
    }
}

impl std::error::Error for RuntimeOwnershipError {}

impl From<RuntimeOwnershipError> for CoreError {
    fn from(error: RuntimeOwnershipError) -> Self {
        CoreError::new(
            ErrorCode::PolicyDenial,
            "runtime ownership gate rejected request",
        )
        .with_severity(ErrorSeverity::Warning)
        .with_redacted_details(json!({ "reason_category": error.reason_category() }))
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeOwnershipLease {
    context: RuntimeOwnerContext,
    production_lock: bool,
    released: bool,
}

impl RuntimeOwnershipLease {
    pub fn context(&self) -> &RuntimeOwnerContext {
        &self.context
    }

    pub fn validate_epoch(&self, epoch: u64) -> Result<(), RuntimeOwnershipError> {
        if self.released {
            return Err(RuntimeOwnershipError::RuntimeShutdownInProgress);
        }
        if self.context.ownership_epoch != epoch {
            return Err(RuntimeOwnershipError::StaleOwnershipEpoch);
        }
        Ok(())
    }

    fn release(&mut self) {
        if self.released {
            return;
        }
        if self.production_lock {
            if let Ok(mut state) = RUNTIME_OWNERSHIP_STATE.lock() {
                if state
                    .as_ref()
                    .is_some_and(|owned| owned.ownership_ref == self.context.ownership_ref)
                {
                    *state = None;
                }
            }
        }
        self.released = true;
    }
}

impl Drop for RuntimeOwnershipLease {
    fn drop(&mut self) {
        self.release();
    }
}

pub struct RuntimeOwnershipGuard;

impl RuntimeOwnershipGuard {
    pub fn acquire(
        context: RuntimeOwnerContext,
    ) -> Result<RuntimeOwnershipLease, RuntimeOwnershipError> {
        context
            .validate()
            .map_err(|_| RuntimeOwnershipError::RuntimeOwnerMismatch)?;
        if context.owner_category == RuntimeOwnerCategory::TestHarness {
            if context.authorization_category != RuntimeAuthorizationCategory::TestHarness {
                return Err(RuntimeOwnershipError::TestOwnerRequired);
            }
            return Ok(RuntimeOwnershipLease {
                context,
                production_lock: false,
                released: false,
            });
        }

        let mut state = RUNTIME_OWNERSHIP_STATE
            .lock()
            .map_err(|_| RuntimeOwnershipError::OwnershipTransitionInProgress)?;
        if let Some(existing) = state.as_ref() {
            if existing.shutdown_in_progress {
                return Err(RuntimeOwnershipError::RuntimeShutdownInProgress);
            }
            if context.runtime_mode == RuntimeMode::PortableInProcess {
                return Err(RuntimeOwnershipError::PortableFallbackNotAuthorized);
            }
            if existing.runtime_mode == RuntimeMode::ServiceOwned
                && context.runtime_mode == RuntimeMode::ServiceOwned
            {
                return Err(RuntimeOwnershipError::DuplicateRuntimeContainer);
            }
            return Err(RuntimeOwnershipError::RuntimeAlreadyOwned);
        }

        if context.owner_category == RuntimeOwnerCategory::None {
            return Err(RuntimeOwnershipError::RuntimeOwnerRequired);
        }
        *state = Some(RuntimeOwnershipLeaseState {
            ownership_ref: context.ownership_ref.clone(),
            ownership_epoch: context.ownership_epoch,
            owner_category: context.owner_category,
            runtime_mode: context.runtime_mode,
            shutdown_in_progress: false,
        });
        Ok(RuntimeOwnershipLease {
            context,
            production_lock: true,
            released: false,
        })
    }

    pub fn mark_shutdown(context: &RuntimeOwnerContext) -> Result<(), RuntimeOwnershipError> {
        let mut state = RUNTIME_OWNERSHIP_STATE
            .lock()
            .map_err(|_| RuntimeOwnershipError::OwnershipTransitionInProgress)?;
        let Some(existing) = state.as_mut() else {
            return Err(RuntimeOwnershipError::RuntimeOwnerRequired);
        };
        if existing.ownership_ref != context.ownership_ref {
            return Err(RuntimeOwnershipError::RuntimeOwnerMismatch);
        }
        if existing.ownership_epoch != context.ownership_epoch {
            return Err(RuntimeOwnershipError::StaleOwnershipEpoch);
        }
        existing.shutdown_in_progress = true;
        Ok(())
    }

    pub fn assert_desktop_can_create_production(
        runtime_mode: RuntimeMode,
    ) -> Result<(), RuntimeOwnershipError> {
        if runtime_mode == RuntimeMode::ServiceOwned {
            return Err(RuntimeOwnershipError::RuntimeOwnerMismatch);
        }
        let state = RUNTIME_OWNERSHIP_STATE
            .lock()
            .map_err(|_| RuntimeOwnershipError::OwnershipTransitionInProgress)?;
        if state
            .as_ref()
            .is_some_and(|owned| owned.runtime_mode == RuntimeMode::ServiceOwned)
        {
            return Err(RuntimeOwnershipError::RuntimeOwnerMismatch);
        }
        Ok(())
    }

    pub fn validate_active_context(
        context: &RuntimeOwnerContext,
        expected_epoch: u64,
    ) -> Result<(), RuntimeOwnershipError> {
        context
            .validate()
            .map_err(|_| RuntimeOwnershipError::RuntimeOwnerMismatch)?;
        if context.ownership_epoch != expected_epoch {
            return Err(RuntimeOwnershipError::StaleOwnershipEpoch);
        }
        if context.owner_category == RuntimeOwnerCategory::TestHarness {
            return Ok(());
        }
        let state = RUNTIME_OWNERSHIP_STATE
            .lock()
            .map_err(|_| RuntimeOwnershipError::OwnershipTransitionInProgress)?;
        let Some(existing) = state.as_ref() else {
            return Err(RuntimeOwnershipError::RuntimeOwnerRequired);
        };
        if existing.shutdown_in_progress {
            return Err(RuntimeOwnershipError::RuntimeShutdownInProgress);
        }
        if existing.ownership_ref != context.ownership_ref
            || existing.ownership_epoch != expected_epoch
            || existing.owner_category != context.owner_category
            || existing.runtime_mode != context.runtime_mode
        {
            return Err(RuntimeOwnershipError::RuntimeOwnerMismatch);
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn reset_for_tests() {
        if let Ok(mut state) = RUNTIME_OWNERSHIP_STATE.lock() {
            *state = None;
        }
    }
}

#[derive(Clone, Debug)]
pub struct ContainerOwned<T> {
    owner_context: RuntimeOwnerContext,
    inner: T,
}

impl<T> ContainerOwned<T> {
    pub fn new(owner_context: RuntimeOwnerContext, inner: T) -> CommandResult<Self> {
        owner_context
            .validate()
            .map_err(|_| CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch))?;
        Ok(Self {
            owner_context,
            inner,
        })
    }

    pub fn owner_context(&self) -> &RuntimeOwnerContext {
        &self.owner_context
    }
}

impl<T: Clone> ContainerOwned<T> {
    pub fn cloned_inner(&self) -> T {
        self.inner.clone()
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeReadContext {
    owner_context: RuntimeOwnerContext,
    expected_epoch: u64,
}

#[derive(Clone, Debug)]
pub struct RuntimeMutationContext {
    owner_context: RuntimeOwnerContext,
    expected_epoch: u64,
    lifecycle: RuntimeTransitionState,
    shutdown_in_progress: bool,
}

impl RuntimeReadContext {
    pub fn owner_context(&self) -> &RuntimeOwnerContext {
        &self.owner_context
    }

    pub fn expected_epoch(&self) -> u64 {
        self.expected_epoch
    }
}

impl RuntimeMutationContext {
    pub fn owner_context(&self) -> &RuntimeOwnerContext {
        &self.owner_context
    }

    pub fn expected_epoch(&self) -> u64 {
        self.expected_epoch
    }

    pub fn validate(&self) -> Result<(), RuntimeOwnershipError> {
        if self.shutdown_in_progress || self.lifecycle == RuntimeTransitionState::ShuttingDown {
            return Err(RuntimeOwnershipError::RuntimeShutdownInProgress);
        }
        if !matches!(
            (
                self.owner_context.owner_category,
                self.owner_context.runtime_mode
            ),
            (RuntimeOwnerCategory::ServiceHost, RuntimeMode::ServiceOwned)
                | (
                    RuntimeOwnerCategory::DesktopPortable,
                    RuntimeMode::PortableInProcess
                )
                | (
                    RuntimeOwnerCategory::TestHarness,
                    RuntimeMode::PortableInProcess
                )
        ) {
            return Err(RuntimeOwnershipError::RuntimeOwnerMismatch);
        }
        RuntimeOwnershipGuard::validate_active_context(&self.owner_context, self.expected_epoch)
    }

    pub fn with_expected_epoch_for_tests(&self, expected_epoch: u64) -> Self {
        let mut cloned = self.clone();
        cloned.expected_epoch = expected_epoch;
        cloned
    }

    pub fn shutdown_for_tests(&self) -> Self {
        let mut cloned = self.clone();
        cloned.shutdown_in_progress = true;
        cloned
    }

    pub(crate) fn invalidate_for_shutdown(&mut self) {
        self.lifecycle = RuntimeTransitionState::ShuttingDown;
        self.shutdown_in_progress = true;
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeServices {
    event_bus: ContainerOwned<RuntimeEventBusHandle>,
    plugin_runtime: ContainerOwned<RuntimePluginHandle>,
    execution_plan: ContainerOwned<ExecutionPlan>,
    read_context: RuntimeReadContext,
    mutation_context: RuntimeMutationContext,
}

impl RuntimeServices {
    pub(crate) fn for_container(
        owner_context: RuntimeOwnerContext,
        event_bus: RuntimeEventBusHandle,
        plugin_runtime: RuntimePluginHandle,
        execution_plan: ExecutionPlan,
    ) -> CommandResult<Self> {
        RuntimeOwnershipGuard::validate_active_context(
            &owner_context,
            owner_context.ownership_epoch,
        )
        .map_err(CoreError::from)?;
        let event_bus = ContainerOwned::new(owner_context.clone(), event_bus)?;
        let plugin_runtime = ContainerOwned::new(owner_context.clone(), plugin_runtime)?;
        let execution_plan = ContainerOwned::new(owner_context.clone(), execution_plan)?;
        Ok(Self {
            read_context: RuntimeReadContext {
                owner_context: owner_context.clone(),
                expected_epoch: owner_context.ownership_epoch,
            },
            mutation_context: RuntimeMutationContext {
                owner_context: owner_context.clone(),
                expected_epoch: owner_context.ownership_epoch,
                lifecycle: RuntimeTransitionState::Ready,
                shutdown_in_progress: false,
            },
            event_bus,
            plugin_runtime,
            execution_plan,
        })
    }

    pub(crate) fn event_bus(&self) -> RuntimeEventBusHandle {
        self.event_bus.cloned_inner()
    }

    pub fn read_context(&self) -> &RuntimeReadContext {
        &self.read_context
    }

    pub fn mutation_context(&self) -> &RuntimeMutationContext {
        &self.mutation_context
    }

    pub(crate) fn run_portable_capture(
        &self,
        prepared: &PortableCaptureLitePreparedBatch,
        service_contexts: &[ServiceCapabilityContext],
    ) -> Result<PortableCaptureLiteRunResult, PortableCaptureLiteError> {
        let execution_plan = self.execution_plan.cloned_inner();
        self.event_bus.cloned_inner().with_bus(|event_bus| {
            self.plugin_runtime
                .cloned_inner()
                .with_runtime(|plugin_runtime| {
                    run_portable_capture_lite_with_runtime(
                        prepared,
                        service_contexts,
                        &mut PortableCaptureRuntimeContext {
                            event_bus,
                            execution_plan: &execution_plan,
                            plugin_runtime,
                        },
                    )
                })
        })
    }

    pub(crate) fn with_plugin_runtime<T>(
        &self,
        operation: impl FnOnce(&mut PluginRuntime) -> CommandResult<T>,
    ) -> CommandResult<T> {
        let plugin_runtime = self.plugin_runtime.cloned_inner();
        let mut runtime = plugin_runtime
            .inner
            .lock()
            .map_err(|_| init_error("plugin_runtime_unavailable"))?;
        operation(&mut runtime)
    }

    pub(crate) fn validate_dag_route(
        &self,
        input_topic: &str,
        output_topics: &[&str],
    ) -> CommandResult<()> {
        let input = TopicName::new(input_topic).map_err(provider_execution_error)?;
        let outputs = output_topics
            .iter()
            .map(|topic| TopicName::new(*topic).map_err(provider_execution_error))
            .collect::<CommandResult<Vec<_>>>()?;
        let plan = self.execution_plan.cloned_inner();
        let route = plan.steps.iter().find(|step| {
            step.input_topics.contains(&input)
                && outputs
                    .iter()
                    .all(|output| step.output_topics.contains(output))
        });
        if route.is_none() {
            return Err(provider_execution_error("dag_route_unavailable"));
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn for_test(label: &str) -> CommandResult<Self> {
        let context = RuntimeOwnerContext::test_harness(
            format!("test-runtime-services-{label}-{}", Uuid::new_v4()),
            next_epoch(),
        );
        let event_bus = RuntimeEventBusHandle::new_service_core_topics();
        let dag = runtime_pipeline_dag()?;
        let execution_plan = dag
            .build_execution_plan()
            .map_err(|_| init_error("dag_initialization_failed"))?;
        let mut plugin_runtime = PluginRuntime::new();
        register_static_bindings(&mut plugin_runtime)?;
        Self::for_container(
            context,
            event_bus,
            RuntimePluginHandle::new(plugin_runtime),
            execution_plan,
        )
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeShutdownCoordinator {
    shutdown_started: bool,
    shutdown_completed: bool,
    stopped_components: Vec<RuntimeComponentCategory>,
    summary: RuntimeShutdownSummary,
    started_at: Option<Instant>,
}

impl RuntimeShutdownCoordinator {
    fn new() -> Self {
        Self {
            shutdown_started: false,
            shutdown_completed: false,
            stopped_components: Vec::new(),
            summary: RuntimeShutdownSummary {
                state: RuntimeShutdownState::NotStarted,
                total_timeout_bucket: "under_30_seconds".to_string(),
                mutation_leases_invalidated: false,
                scheduler_host_cancellation_signalled: false,
                scheduler_host_joined: false,
                provider_stop_called: false,
                stages: Vec::new(),
                audit_refs: Vec::new(),
                redaction_status: RedactionStatus::Redacted,
            },
            started_at: None,
        }
    }

    pub fn shutdown_started(&self) -> bool {
        self.shutdown_started
    }

    pub fn shutdown_completed(&self) -> bool {
        self.shutdown_completed
    }

    pub fn summary(&self) -> &RuntimeShutdownSummary {
        &self.summary
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpHelperHandoffExecutionPolicy {
    InternalServiceHostIntegrationTest,
    ForegroundDevelopmentTest,
    DirectContainerOwnedTest,
    ProductionIpc,
    ScheduledServiceHost,
}

impl IpHelperHandoffExecutionPolicy {
    fn authorized_for_execution(self) -> bool {
        matches!(
            self,
            Self::InternalServiceHostIntegrationTest
                | Self::ForegroundDevelopmentTest
                | Self::DirectContainerOwnedTest
                | Self::ProductionIpc
                | Self::ScheduledServiceHost
        )
    }

    fn reason(self) -> &'static str {
        match self {
            Self::InternalServiceHostIntegrationTest => "internal_servicehost_integration_test",
            Self::ForegroundDevelopmentTest => "foreground_development_test_policy",
            Self::DirectContainerOwnedTest => "direct_container_owned_test_invocation",
            Self::ProductionIpc => "production_ipc_single_sample",
            Self::ScheduledServiceHost => "servicehost_scheduled_ip_helper_sample",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpHelperHandoffRequest {
    pub policy: IpHelperHandoffExecutionPolicy,
    pub max_records: usize,
    pub max_bytes: usize,
    pub timeout_ms: u64,
    pub reason_ref: String,
}

#[derive(Clone, Copy, Debug)]
struct IpHelperScheduledSkipDraft {
    reason: &'static str,
    due_state: IpHelperScheduledDueState,
    authorization_state: IpHelperScheduledAuthorizationState,
    execution_result: IpHelperScheduledExecutionResult,
    retry_state: IpHelperScheduledRetryState,
    backpressure_state: IpHelperScheduledBackpressureState,
    missed_sample_state: IpHelperScheduledMissedSampleState,
    audit_event: &'static str,
}

impl IpHelperHandoffRequest {
    pub fn foreground_development_test() -> Self {
        Self {
            policy: IpHelperHandoffExecutionPolicy::ForegroundDevelopmentTest,
            max_records: 512,
            max_bytes: 256 * 1024,
            timeout_ms: 250,
            reason_ref: "explicit_foreground_development_test".to_string(),
        }
    }

    #[cfg(test)]
    pub fn internal_servicehost_test() -> Self {
        Self {
            policy: IpHelperHandoffExecutionPolicy::InternalServiceHostIntegrationTest,
            max_records: 128,
            max_bytes: 128 * 1024,
            timeout_ms: 250,
            reason_ref: "internal_servicehost_integration_test".to_string(),
        }
    }

    pub fn production_ipc() -> Self {
        Self {
            policy: IpHelperHandoffExecutionPolicy::ProductionIpc,
            max_records: 128,
            max_bytes: 128 * 1024,
            timeout_ms: 250,
            reason_ref: "production_ipc_sample_ip_helper_once".to_string(),
        }
    }

    pub fn production_ipc_rejected() -> Self {
        Self::production_ipc()
    }

    pub fn scheduled_servicehost(
        cycle_ref: impl Into<String>,
        max_records: usize,
        max_bytes: usize,
        timeout_ms: u64,
    ) -> Self {
        Self {
            policy: IpHelperHandoffExecutionPolicy::ScheduledServiceHost,
            max_records,
            max_bytes,
            timeout_ms,
            reason_ref: cycle_ref.into(),
        }
    }

    fn validate(&self) -> CommandResult<()> {
        if !self.policy.authorized_for_execution() {
            return Err(provider_execution_error(self.policy.reason()));
        }
        if self.max_records == 0 || self.max_records > 16_384 {
            return Err(provider_execution_error("bounded_max_records_required"));
        }
        if self.max_bytes == 0 || self.max_bytes > 8 * 1024 * 1024 {
            return Err(provider_execution_error("bounded_max_bytes_required"));
        }
        if !(25..=2_000).contains(&self.timeout_ms) {
            return Err(provider_execution_error("bounded_timeout_required"));
        }
        validate_runtime_safe_ref("reason_ref", &self.reason_ref)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct IpHelperHandoffResult {
    pub batch: NativeIpHelperMetadataBatch,
    pub fact_count: usize,
    pub emitted_topics: Vec<String>,
    pub provider_status: NetworkProviderControllerStatus,
}

#[derive(Clone, Debug)]
pub struct EtwNetworkHandoffResult {
    pub batch: EtwNormalizedNetworkBatch,
    pub fact_count: usize,
    pub emitted_topics: Vec<String>,
    pub provider_status: NetworkProviderControllerStatus,
}

#[derive(Clone, Debug)]
pub struct DnsSensingHandoffResult {
    pub batch: WindowsDnsObservationBatch,
    pub eventbus_publications: u32,
    pub detector_invocations: u32,
    pub detector_consumed: u32,
    pub downstream_outputs: u32,
    pub provider_status: NetworkProviderControllerStatus,
}

#[derive(Clone, Debug)]
pub struct AuthRemoteSensingHandoffResult {
    pub batch: WindowsAuthRemoteObservationBatch,
    pub published_auth_metadata: u32,
    pub published_batches: u32,
    pub eventbus_publications: u32,
    pub dag_dispatches: u32,
    pub auth_detector_invocations: u32,
    pub auth_consumed: u32,
    pub remote_admin_invocations: u32,
    pub remote_admin_consumed: u32,
    pub lateral_invocations: u32,
    pub lateral_consumed: u32,
    pub outputs: u32,
    pub downstream_facts: u32,
    pub provider_status: NetworkProviderControllerStatus,
}

#[derive(Clone, Debug)]
pub struct RdpOperationalSensingHandoffResult {
    pub batch: WindowsAuthRemoteObservationBatch,
    pub published_rdp_metadata: u32,
    pub published_auth_metadata: u32,
    pub published_batches: u32,
    pub eventbus_publications: u32,
    pub dag_dispatches: u32,
    pub auth_detector_invocations: u32,
    pub auth_consumed: u32,
    pub remote_admin_invocations: u32,
    pub remote_admin_consumed: u32,
    pub lateral_invocations: u32,
    pub lateral_consumed: u32,
    pub outputs: u32,
    pub downstream_facts: u32,
    pub provider_status: NetworkProviderControllerStatus,
}

#[derive(Clone, Debug)]
pub struct SmbOperationalSensingHandoffResult {
    pub batch: WindowsAuthRemoteObservationBatch,
    pub published_smb_metadata: u32,
    pub published_auth_metadata: u32,
    pub published_batches: u32,
    pub eventbus_publications: u32,
    pub dag_dispatches: u32,
    pub auth_detector_invocations: u32,
    pub auth_consumed: u32,
    pub remote_admin_invocations: u32,
    pub remote_admin_consumed: u32,
    pub lateral_invocations: u32,
    pub lateral_consumed: u32,
    pub outputs: u32,
    pub downstream_facts: u32,
    pub provider_status: NetworkProviderControllerStatus,
}

#[derive(Clone, Debug)]
pub struct SshOperationalSensingHandoffResult {
    pub batch: WindowsAuthRemoteObservationBatch,
    pub published_ssh_metadata: u32,
    pub published_auth_metadata: u32,
    pub published_batches: u32,
    pub eventbus_publications: u32,
    pub dag_dispatches: u32,
    pub auth_detector_invocations: u32,
    pub auth_consumed: u32,
    pub remote_admin_invocations: u32,
    pub remote_admin_consumed: u32,
    pub lateral_invocations: u32,
    pub lateral_consumed: u32,
    pub outputs: u32,
    pub downstream_facts: u32,
    pub provider_status: NetworkProviderControllerStatus,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EtwLivePumpResult {
    pub normalized_batches: u32,
    pub published_batches: u32,
    pub eventbus_publications: u32,
    pub downstream_facts: u32,
    pub raw_events: u32,
    pub normalized_events: u32,
    pub dropped_events: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsSensingLivePumpResult {
    pub normalized_batches: u32,
    pub published_batches: u32,
    pub eventbus_publications: u32,
    pub detector_invocations: u32,
    pub detector_consumed: u32,
    pub downstream_outputs: u32,
    pub raw_events: u32,
    pub normalized_events: u32,
    pub dropped_events: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthRemoteSensingLivePumpResult {
    pub normalized_batches: u32,
    pub published_batches: u32,
    pub eventbus_publications: u32,
    pub dag_dispatches: u32,
    pub auth_detector_invocations: u32,
    pub auth_consumed: u32,
    pub remote_admin_invocations: u32,
    pub remote_admin_consumed: u32,
    pub lateral_invocations: u32,
    pub lateral_consumed: u32,
    pub outputs: u32,
    pub downstream_facts: u32,
    pub raw_events: u32,
    pub normalized_events: u32,
    pub dropped_events: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RdpOperationalSensingLivePumpResult {
    pub normalized_batches: u32,
    pub published_batches: u32,
    pub eventbus_publications: u32,
    pub dag_dispatches: u32,
    pub auth_detector_invocations: u32,
    pub auth_consumed: u32,
    pub remote_admin_invocations: u32,
    pub remote_admin_consumed: u32,
    pub lateral_invocations: u32,
    pub lateral_consumed: u32,
    pub outputs: u32,
    pub downstream_facts: u32,
    pub raw_events: u32,
    pub normalized_events: u32,
    pub dropped_events: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmbOperationalSensingLivePumpResult {
    pub normalized_batches: u32,
    pub published_batches: u32,
    pub eventbus_publications: u32,
    pub dag_dispatches: u32,
    pub auth_detector_invocations: u32,
    pub auth_consumed: u32,
    pub remote_admin_invocations: u32,
    pub remote_admin_consumed: u32,
    pub lateral_invocations: u32,
    pub lateral_consumed: u32,
    pub outputs: u32,
    pub downstream_facts: u32,
    pub raw_events: u32,
    pub normalized_events: u32,
    pub dropped_events: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SshOperationalSensingLivePumpResult {
    pub normalized_batches: u32,
    pub published_batches: u32,
    pub eventbus_publications: u32,
    pub dag_dispatches: u32,
    pub auth_detector_invocations: u32,
    pub auth_consumed: u32,
    pub remote_admin_invocations: u32,
    pub remote_admin_consumed: u32,
    pub lateral_invocations: u32,
    pub lateral_consumed: u32,
    pub outputs: u32,
    pub downstream_facts: u32,
    pub raw_events: u32,
    pub normalized_events: u32,
    pub dropped_events: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct AuthRemoteSensingDispatchCounters {
    eventbus_publications: u32,
    dag_dispatches: u32,
    auth_detector_invocations: u32,
    auth_consumed: u32,
    remote_admin_invocations: u32,
    remote_admin_consumed: u32,
    lateral_invocations: u32,
    lateral_consumed: u32,
    downstream_facts: u32,
}

#[derive(Clone, Debug)]
pub struct ProviderControllerShell {
    state: String,
    status: Option<NetworkProviderControllerStatus>,
    provider_call_count: u32,
    provider_zero: RuntimeProviderZeroSummary,
    stop_called: bool,
    latest_ip_helper_batch: Option<NativeIpHelperMetadataBatch>,
    latest_etw_batch: Option<EtwNormalizedNetworkBatch>,
    latest_dns_batch: Option<WindowsDnsObservationBatch>,
    latest_auth_remote_batch: Option<WindowsAuthRemoteObservationBatch>,
    latest_rdp_operational_batch: Option<WindowsAuthRemoteObservationBatch>,
    latest_smb_operational_batch: Option<WindowsAuthRemoteObservationBatch>,
    latest_ssh_operational_batch: Option<WindowsAuthRemoteObservationBatch>,
}

struct IpHelperScheduleStatusUpdate {
    schedule_state: IpHelperScheduleState,
    lease_state: IpHelperScheduleLeaseState,
    config: Option<IpHelperScheduleConfig>,
    schedule_lease_ref: Option<String>,
    authorization_refs: Vec<String>,
    audit_event: &'static str,
    policy_id: String,
    policy_version: SchemaVersion,
    degraded_reason: Option<String>,
}

impl ProviderControllerShell {
    fn inactive_for(owner_context: &RuntimeOwnerContext) -> CommandResult<Self> {
        let status = if owner_context.owner_category == RuntimeOwnerCategory::ServiceHost
            && owner_context.runtime_mode == RuntimeMode::ServiceOwned
        {
            Some(
                NetworkProviderControllerStatus::inactive_servicehost(
                    owner_context.ownership_ref.clone(),
                    owner_context.ownership_epoch,
                )
                .map_err(|error| {
                    CoreError::new(
                        ErrorCode::InternalError,
                        "provider controller contract validation failed",
                    )
                    .with_severity(ErrorSeverity::Error)
                    .with_redacted_details(json!({
                        "context": "provider_controller",
                        "error_redacted": error.to_string()
                    }))
                })?,
            )
        } else {
            None
        };
        Ok(Self {
            state: "inactive".to_string(),
            status,
            provider_call_count: 0,
            provider_zero: RuntimeProviderZeroSummary::default(),
            stop_called: false,
            latest_ip_helper_batch: None,
            latest_etw_batch: None,
            latest_dns_batch: None,
            latest_auth_remote_batch: None,
            latest_rdp_operational_batch: None,
            latest_smb_operational_batch: None,
            latest_ssh_operational_batch: None,
        })
    }

    pub fn state(&self) -> &str {
        &self.state
    }

    pub fn status(&self) -> Option<&NetworkProviderControllerStatus> {
        self.status.as_ref()
    }

    pub fn provider_statuses(&self) -> &[NetworkProviderStatus] {
        self.status
            .as_ref()
            .map(|status| status.providers.as_slice())
            .unwrap_or_default()
    }

    pub fn provider_status(&self, kind: NetworkProviderKind) -> Option<&NetworkProviderStatus> {
        self.status
            .as_ref()
            .and_then(|status| status.provider(kind))
    }

    pub fn visibility_summary(&self) -> Option<&NetworkVisibilitySummary> {
        self.status
            .as_ref()
            .map(|status| &status.visibility_summary)
    }

    pub fn fallback_plan(&self) -> Option<&NetworkFallbackPlan> {
        self.status.as_ref().map(|status| &status.fallback_plan)
    }

    pub fn provider_zero_counters(&self) -> Option<&NetworkProviderZeroCounters> {
        self.status.as_ref().map(|status| &status.provider_zero)
    }

    pub fn provider_call_count(&self) -> u32 {
        self.provider_call_count
    }

    pub fn provider_zero(&self) -> RuntimeProviderZeroSummary {
        self.provider_zero.clone()
    }

    pub fn latest_ip_helper_batch(&self) -> Option<&NativeIpHelperMetadataBatch> {
        self.latest_ip_helper_batch.as_ref()
    }

    pub fn latest_etw_batch(&self) -> Option<&EtwNormalizedNetworkBatch> {
        self.latest_etw_batch.as_ref()
    }

    pub fn latest_dns_batch(&self) -> Option<&WindowsDnsObservationBatch> {
        self.latest_dns_batch.as_ref()
    }

    pub fn latest_auth_remote_batch(&self) -> Option<&WindowsAuthRemoteObservationBatch> {
        self.latest_auth_remote_batch.as_ref()
    }

    pub fn latest_rdp_operational_batch(&self) -> Option<&WindowsAuthRemoteObservationBatch> {
        self.latest_rdp_operational_batch.as_ref()
    }

    pub fn latest_smb_operational_batch(&self) -> Option<&WindowsAuthRemoteObservationBatch> {
        self.latest_smb_operational_batch.as_ref()
    }

    pub fn latest_ssh_operational_batch(&self) -> Option<&WindowsAuthRemoteObservationBatch> {
        self.latest_ssh_operational_batch.as_ref()
    }

    pub fn ip_helper_schedule_status(&self) -> Option<&IpHelperScheduleStatus> {
        self.status
            .as_ref()
            .map(|status| &status.ip_helper_schedule)
    }

    pub fn etw_lifecycle_status(&self) -> Option<&EtwLifecycleStatus> {
        self.status.as_ref().map(|status| &status.etw_lifecycle)
    }

    fn record_etw_lifecycle(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        lifecycle: EtwLifecycleStatus,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        lifecycle
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.etw_lifecycle = lifecycle.clone();
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.provider_zero.etw_calls = status.provider_zero.etw_calls.saturating_add(1);
        status.audit_summary.provider_execution_event_count = status
            .audit_summary
            .provider_execution_event_count
            .saturating_add(1);
        status.audit_summary.audit_refs = bounded_provider_refs(
            status
                .audit_summary
                .audit_refs
                .into_iter()
                .chain(lifecycle.audit_refs.clone()),
        );

        let ip_helper_active =
            status
                .provider(NetworkProviderKind::IpHelper)
                .is_some_and(|provider| {
                    matches!(
                        provider.lifecycle_state,
                        NetworkProviderLifecycleState::Active
                            | NetworkProviderLifecycleState::Ready
                            | NetworkProviderLifecycleState::Degraded
                    )
                });
        status.controller_state = match lifecycle.lifecycle_state {
            EtwLifecycleState::Active => NetworkProviderControllerState::Active,
            EtwLifecycleState::Paused => NetworkProviderControllerState::Paused,
            EtwLifecycleState::Degraded => NetworkProviderControllerState::Degraded,
            EtwLifecycleState::Stopped => NetworkProviderControllerState::Stopped,
            EtwLifecycleState::Failed => NetworkProviderControllerState::Failed,
            EtwLifecycleState::Activating | EtwLifecycleState::Resuming => {
                NetworkProviderControllerState::Activating
            }
            EtwLifecycleState::Pausing | EtwLifecycleState::Stopping => {
                NetworkProviderControllerState::Stopping
            }
            EtwLifecycleState::Inactive => NetworkProviderControllerState::Inactive,
        };
        status.selected_mode = match lifecycle.lifecycle_state {
            EtwLifecycleState::Active => NetworkProviderControllerMode::EtwPlusIpHelper,
            EtwLifecycleState::Degraded | EtwLifecycleState::Failed => {
                if ip_helper_active {
                    NetworkProviderControllerMode::IpHelperOnly
                } else {
                    NetworkProviderControllerMode::Degraded
                }
            }
            _ if ip_helper_active => NetworkProviderControllerMode::IpHelperOnly,
            _ => NetworkProviderControllerMode::PortableOnly,
        };
        status.fallback_plan.selected_mode = status.selected_mode;
        status.fallback_plan.degraded_reason = match lifecycle.lifecycle_state {
            EtwLifecycleState::Active
                if lifecycle.provider_enabled
                    && lifecycle.collection_started
                    && lifecycle.consumer_started =>
            {
                None
            }
            EtwLifecycleState::Active => Some("etw_collection_not_started".to_string()),
            EtwLifecycleState::Degraded | EtwLifecycleState::Failed => {
                Some("etw_unavailable_ip_helper_fallback".to_string())
            }
            EtwLifecycleState::Paused => Some("etw_paused_ip_helper_fallback".to_string()),
            EtwLifecycleState::Stopped => Some("etw_stopped_ip_helper_fallback".to_string()),
            _ => Some("etw_control_session_inactive".to_string()),
        };
        status.dependency_summary.degraded_reason = status.fallback_plan.degraded_reason.clone();

        if let Some(etw) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::EtwNetwork)
        {
            etw.implementation_state = match lifecycle.lifecycle_state {
                EtwLifecycleState::Active | EtwLifecycleState::Paused => {
                    NetworkProviderImplementationState::Available
                }
                EtwLifecycleState::Degraded => NetworkProviderImplementationState::Degraded,
                EtwLifecycleState::Failed => NetworkProviderImplementationState::Failed,
                _ => NetworkProviderImplementationState::ImplementedInactive,
            };
            etw.lifecycle_state = match lifecycle.lifecycle_state {
                EtwLifecycleState::Inactive => NetworkProviderLifecycleState::Inactive,
                EtwLifecycleState::Activating | EtwLifecycleState::Resuming => {
                    NetworkProviderLifecycleState::Activating
                }
                EtwLifecycleState::Active => NetworkProviderLifecycleState::Active,
                EtwLifecycleState::Pausing => NetworkProviderLifecycleState::Stopping,
                EtwLifecycleState::Paused => NetworkProviderLifecycleState::Paused,
                EtwLifecycleState::Degraded => NetworkProviderLifecycleState::Degraded,
                EtwLifecycleState::Stopping => NetworkProviderLifecycleState::Stopping,
                EtwLifecycleState::Stopped => NetworkProviderLifecycleState::Stopped,
                EtwLifecycleState::Failed => NetworkProviderLifecycleState::Failed,
            };
            etw.activation_allowed = true;
            etw.activation_unavailable_reason = None;
            etw.degraded_reason = lifecycle
                .degraded_reason
                .clone()
                .or_else(|| status.fallback_plan.degraded_reason.clone());
            etw.bounded_counters = status.provider_zero.clone();
            etw.provenance_refs = bounded_provider_refs(
                etw.provenance_refs
                    .clone()
                    .into_iter()
                    .chain(["servicehost_etw_lifecycle".to_string()]),
            );
        }
        for dimension in &mut status.visibility_summary.dimensions {
            if dimension.dimension == NetworkVisibilityDimension::ShortLivedNetworkEventVisibility {
                if lifecycle.lifecycle_state == EtwLifecycleState::Active
                    && lifecycle.normalized_event_count > 0
                    && lifecycle.published_batch_count > 0
                {
                    dimension.visibility_state = NetworkVisibilityState::Available;
                    dimension.degraded_reason = None;
                } else if lifecycle.lifecycle_state == EtwLifecycleState::Active {
                    dimension.visibility_state = NetworkVisibilityState::Degraded;
                    dimension.degraded_reason =
                        Some("etw_live_events_not_yet_observed".to_string());
                } else {
                    dimension.visibility_state = NetworkVisibilityState::Unavailable;
                    dimension.degraded_reason = Some("etw_live_collection_inactive".to_string());
                }
            }
        }
        status.visibility_summary.generated_at = Timestamp::now();
        status.lifecycle_summary.controller_state = status.controller_state;
        status.lifecycle_summary.selected_mode = status.selected_mode;
        status.lifecycle_summary.active_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Active)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.degraded_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Degraded)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.inactive_provider_count = status
            .providers
            .len()
            .saturating_sub(status.lifecycle_summary.active_provider_count as usize)
            .min(u8::MAX as usize) as u8;
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;

        self.state = status.controller_state.as_str().to_string();
        self.provider_call_count = self.provider_call_count.saturating_add(1);
        self.provider_zero.etw_calls = self.provider_zero.etw_calls.saturating_add(1);
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_dns_sensing_lifecycle(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        lifecycle: EtwLifecycleStatus,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        lifecycle
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.provider_zero.dns_sensing_calls =
            status.provider_zero.dns_sensing_calls.saturating_add(1);
        status.audit_summary.provider_execution_event_count = status
            .audit_summary
            .provider_execution_event_count
            .saturating_add(1);
        status.audit_summary.audit_refs = bounded_provider_refs(
            status
                .audit_summary
                .audit_refs
                .into_iter()
                .chain(lifecycle.audit_refs.clone()),
        );
        status.controller_state = match lifecycle.lifecycle_state {
            EtwLifecycleState::Active => NetworkProviderControllerState::Active,
            EtwLifecycleState::Paused => NetworkProviderControllerState::Paused,
            EtwLifecycleState::Degraded => NetworkProviderControllerState::Degraded,
            EtwLifecycleState::Stopped => NetworkProviderControllerState::Stopped,
            EtwLifecycleState::Failed => NetworkProviderControllerState::Failed,
            EtwLifecycleState::Activating | EtwLifecycleState::Resuming => {
                NetworkProviderControllerState::Activating
            }
            EtwLifecycleState::Pausing | EtwLifecycleState::Stopping => {
                NetworkProviderControllerState::Stopping
            }
            EtwLifecycleState::Inactive => NetworkProviderControllerState::Inactive,
        };
        if let Some(provider) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::WindowsDns)
        {
            provider.implementation_state = match lifecycle.lifecycle_state {
                EtwLifecycleState::Active | EtwLifecycleState::Paused => {
                    NetworkProviderImplementationState::Available
                }
                EtwLifecycleState::Degraded => NetworkProviderImplementationState::Degraded,
                EtwLifecycleState::Failed => NetworkProviderImplementationState::Failed,
                _ => NetworkProviderImplementationState::ImplementedInactive,
            };
            provider.lifecycle_state = match lifecycle.lifecycle_state {
                EtwLifecycleState::Inactive => NetworkProviderLifecycleState::Inactive,
                EtwLifecycleState::Activating | EtwLifecycleState::Resuming => {
                    NetworkProviderLifecycleState::Activating
                }
                EtwLifecycleState::Active => NetworkProviderLifecycleState::Active,
                EtwLifecycleState::Pausing | EtwLifecycleState::Stopping => {
                    NetworkProviderLifecycleState::Stopping
                }
                EtwLifecycleState::Paused => NetworkProviderLifecycleState::Paused,
                EtwLifecycleState::Degraded => NetworkProviderLifecycleState::Degraded,
                EtwLifecycleState::Stopped => NetworkProviderLifecycleState::Stopped,
                EtwLifecycleState::Failed => NetworkProviderLifecycleState::Failed,
            };
            provider.activation_allowed = true;
            provider.activation_unavailable_reason = None;
            provider.degraded_reason = lifecycle.degraded_reason.clone();
            provider.bounded_counters = status.provider_zero.clone();
            provider.provenance_refs = bounded_provider_refs(
                provider
                    .provenance_refs
                    .clone()
                    .into_iter()
                    .chain(["servicehost_windows_dns_sensing".to_string()]),
            );
        }
        status.lifecycle_summary.controller_state = status.controller_state;
        status.lifecycle_summary.active_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Active)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.degraded_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Degraded)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.inactive_provider_count = status
            .providers
            .len()
            .saturating_sub(status.lifecycle_summary.active_provider_count as usize)
            .min(u8::MAX as usize) as u8;
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.state = status.controller_state.as_str().to_string();
        self.provider_call_count = self.provider_call_count.saturating_add(1);
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_dns_sensing_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        batch: WindowsDnsObservationBatch,
        eventbus_publications: u32,
        detector_invocations: u32,
        detector_consumed: u32,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.provider_zero.dns_observation_publications = status
            .provider_zero
            .dns_observation_publications
            .saturating_add(eventbus_publications);
        status.provider_zero.dns_detector_invocations = status
            .provider_zero
            .dns_detector_invocations
            .saturating_add(detector_invocations);
        status.provider_zero.dns_detector_consumed = status
            .provider_zero
            .dns_detector_consumed
            .saturating_add(detector_consumed);
        if let Some(provider) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::WindowsDns)
        {
            provider.bounded_counters = status.provider_zero.clone();
            provider.degraded_reason = None;
        }
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.latest_dns_batch = Some(batch);
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_auth_remote_sensing_lifecycle(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        lifecycle: EtwLifecycleStatus,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        lifecycle
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.provider_zero.auth_remote_sensing_calls = status
            .provider_zero
            .auth_remote_sensing_calls
            .saturating_add(1);
        status.audit_summary.provider_execution_event_count = status
            .audit_summary
            .provider_execution_event_count
            .saturating_add(1);
        status.audit_summary.audit_refs = bounded_provider_refs(
            status
                .audit_summary
                .audit_refs
                .into_iter()
                .chain(lifecycle.audit_refs.clone()),
        );
        status.controller_state = match lifecycle.lifecycle_state {
            EtwLifecycleState::Active => NetworkProviderControllerState::Active,
            EtwLifecycleState::Paused => NetworkProviderControllerState::Paused,
            EtwLifecycleState::Degraded => NetworkProviderControllerState::Degraded,
            EtwLifecycleState::Stopped => NetworkProviderControllerState::Stopped,
            EtwLifecycleState::Failed => NetworkProviderControllerState::Failed,
            EtwLifecycleState::Activating | EtwLifecycleState::Resuming => {
                NetworkProviderControllerState::Activating
            }
            EtwLifecycleState::Pausing | EtwLifecycleState::Stopping => {
                NetworkProviderControllerState::Stopping
            }
            EtwLifecycleState::Inactive => NetworkProviderControllerState::Inactive,
        };
        if let Some(provider) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::WindowsAuthRemote)
        {
            provider.implementation_state = match lifecycle.lifecycle_state {
                EtwLifecycleState::Active | EtwLifecycleState::Paused => {
                    NetworkProviderImplementationState::Available
                }
                EtwLifecycleState::Degraded => NetworkProviderImplementationState::Degraded,
                EtwLifecycleState::Failed => NetworkProviderImplementationState::Failed,
                _ => NetworkProviderImplementationState::ImplementedInactive,
            };
            provider.lifecycle_state = match lifecycle.lifecycle_state {
                EtwLifecycleState::Inactive => NetworkProviderLifecycleState::Inactive,
                EtwLifecycleState::Activating | EtwLifecycleState::Resuming => {
                    NetworkProviderLifecycleState::Activating
                }
                EtwLifecycleState::Active => NetworkProviderLifecycleState::Active,
                EtwLifecycleState::Pausing | EtwLifecycleState::Stopping => {
                    NetworkProviderLifecycleState::Stopping
                }
                EtwLifecycleState::Paused => NetworkProviderLifecycleState::Paused,
                EtwLifecycleState::Degraded => NetworkProviderLifecycleState::Degraded,
                EtwLifecycleState::Stopped => NetworkProviderLifecycleState::Stopped,
                EtwLifecycleState::Failed => NetworkProviderLifecycleState::Failed,
            };
            provider.activation_allowed = true;
            provider.activation_unavailable_reason = None;
            provider.degraded_reason = lifecycle.degraded_reason.clone();
            provider.bounded_counters = status.provider_zero.clone();
            provider.provenance_refs = bounded_provider_refs(
                provider
                    .provenance_refs
                    .clone()
                    .into_iter()
                    .chain(["servicehost_windows_auth_remote_sensing".to_string()]),
            );
        }
        status.lifecycle_summary.controller_state = status.controller_state;
        status.lifecycle_summary.active_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Active)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.degraded_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Degraded)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.inactive_provider_count = status
            .providers
            .len()
            .saturating_sub(status.lifecycle_summary.active_provider_count as usize)
            .min(u8::MAX as usize) as u8;
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.state = status.controller_state.as_str().to_string();
        self.provider_call_count = self.provider_call_count.saturating_add(1);
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_auth_remote_sensing_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        batch: WindowsAuthRemoteObservationBatch,
        counters: AuthRemoteSensingDispatchCounters,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.provider_zero.auth_remote_publications = status
            .provider_zero
            .auth_remote_publications
            .saturating_add(counters.eventbus_publications);
        status.provider_zero.auth_remote_auth_detector_invocations = status
            .provider_zero
            .auth_remote_auth_detector_invocations
            .saturating_add(counters.auth_detector_invocations);
        status.provider_zero.auth_remote_auth_consumed = status
            .provider_zero
            .auth_remote_auth_consumed
            .saturating_add(counters.auth_consumed);
        status.provider_zero.auth_remote_remote_admin_invocations = status
            .provider_zero
            .auth_remote_remote_admin_invocations
            .saturating_add(counters.remote_admin_invocations);
        status.provider_zero.auth_remote_remote_admin_consumed = status
            .provider_zero
            .auth_remote_remote_admin_consumed
            .saturating_add(counters.remote_admin_consumed);
        status.provider_zero.auth_remote_lateral_invocations = status
            .provider_zero
            .auth_remote_lateral_invocations
            .saturating_add(counters.lateral_invocations);
        status.provider_zero.auth_remote_lateral_consumed = status
            .provider_zero
            .auth_remote_lateral_consumed
            .saturating_add(counters.lateral_consumed);
        status.provider_zero.auth_remote_downstream_facts = status
            .provider_zero
            .auth_remote_downstream_facts
            .saturating_add(counters.downstream_facts);
        if let Some(provider) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::WindowsAuthRemote)
        {
            provider.bounded_counters = status.provider_zero.clone();
            provider.degraded_reason = if counters.dag_dispatches == 0 {
                Some("auth_remote_runtime_dispatch_pending".to_string())
            } else {
                None
            };
        }
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.latest_auth_remote_batch = Some(batch);
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_rdp_operational_sensing_lifecycle(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        lifecycle: EtwLifecycleStatus,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        lifecycle
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.provider_zero.rdp_operational_sensing_calls = status
            .provider_zero
            .rdp_operational_sensing_calls
            .saturating_add(1);
        status.audit_summary.provider_execution_event_count = status
            .audit_summary
            .provider_execution_event_count
            .saturating_add(1);
        status.audit_summary.audit_refs = bounded_provider_refs(
            status
                .audit_summary
                .audit_refs
                .into_iter()
                .chain(lifecycle.audit_refs.clone()),
        );
        status.controller_state = match lifecycle.lifecycle_state {
            EtwLifecycleState::Active => NetworkProviderControllerState::Active,
            EtwLifecycleState::Paused => NetworkProviderControllerState::Paused,
            EtwLifecycleState::Degraded => NetworkProviderControllerState::Degraded,
            EtwLifecycleState::Stopped => NetworkProviderControllerState::Stopped,
            EtwLifecycleState::Failed => NetworkProviderControllerState::Failed,
            EtwLifecycleState::Activating | EtwLifecycleState::Resuming => {
                NetworkProviderControllerState::Activating
            }
            EtwLifecycleState::Pausing | EtwLifecycleState::Stopping => {
                NetworkProviderControllerState::Stopping
            }
            EtwLifecycleState::Inactive => NetworkProviderControllerState::Inactive,
        };
        if let Some(provider) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::WindowsRdpOperational)
        {
            provider.implementation_state = match lifecycle.lifecycle_state {
                EtwLifecycleState::Active | EtwLifecycleState::Paused => {
                    NetworkProviderImplementationState::Available
                }
                EtwLifecycleState::Degraded => NetworkProviderImplementationState::Degraded,
                EtwLifecycleState::Failed => NetworkProviderImplementationState::Failed,
                _ => NetworkProviderImplementationState::ImplementedInactive,
            };
            provider.lifecycle_state = match lifecycle.lifecycle_state {
                EtwLifecycleState::Inactive => NetworkProviderLifecycleState::Inactive,
                EtwLifecycleState::Activating | EtwLifecycleState::Resuming => {
                    NetworkProviderLifecycleState::Activating
                }
                EtwLifecycleState::Active => NetworkProviderLifecycleState::Active,
                EtwLifecycleState::Pausing | EtwLifecycleState::Stopping => {
                    NetworkProviderLifecycleState::Stopping
                }
                EtwLifecycleState::Paused => NetworkProviderLifecycleState::Paused,
                EtwLifecycleState::Degraded => NetworkProviderLifecycleState::Degraded,
                EtwLifecycleState::Stopped => NetworkProviderLifecycleState::Stopped,
                EtwLifecycleState::Failed => NetworkProviderLifecycleState::Failed,
            };
            provider.activation_allowed = true;
            provider.activation_unavailable_reason = None;
            provider.degraded_reason = lifecycle.degraded_reason.clone();
            provider.bounded_counters = status.provider_zero.clone();
            provider.provenance_refs = bounded_provider_refs(
                provider
                    .provenance_refs
                    .clone()
                    .into_iter()
                    .chain(["servicehost_windows_rdp_operational_sensing".to_string()]),
            );
        }
        status.lifecycle_summary.controller_state = status.controller_state;
        status.lifecycle_summary.active_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Active)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.degraded_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Degraded)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.inactive_provider_count = status
            .providers
            .len()
            .saturating_sub(status.lifecycle_summary.active_provider_count as usize)
            .min(u8::MAX as usize) as u8;
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.state = status.controller_state.as_str().to_string();
        self.provider_call_count = self.provider_call_count.saturating_add(1);
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_rdp_operational_sensing_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        batch: WindowsAuthRemoteObservationBatch,
        counters: AuthRemoteSensingDispatchCounters,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.provider_zero.rdp_operational_publications = status
            .provider_zero
            .rdp_operational_publications
            .saturating_add(counters.eventbus_publications);
        status
            .provider_zero
            .rdp_operational_auth_detector_invocations = status
            .provider_zero
            .rdp_operational_auth_detector_invocations
            .saturating_add(counters.auth_detector_invocations);
        status.provider_zero.rdp_operational_auth_consumed = status
            .provider_zero
            .rdp_operational_auth_consumed
            .saturating_add(counters.auth_consumed);
        status
            .provider_zero
            .rdp_operational_remote_admin_invocations = status
            .provider_zero
            .rdp_operational_remote_admin_invocations
            .saturating_add(counters.remote_admin_invocations);
        status.provider_zero.rdp_operational_remote_admin_consumed = status
            .provider_zero
            .rdp_operational_remote_admin_consumed
            .saturating_add(counters.remote_admin_consumed);
        status.provider_zero.rdp_operational_lateral_invocations = status
            .provider_zero
            .rdp_operational_lateral_invocations
            .saturating_add(counters.lateral_invocations);
        status.provider_zero.rdp_operational_lateral_consumed = status
            .provider_zero
            .rdp_operational_lateral_consumed
            .saturating_add(counters.lateral_consumed);
        status.provider_zero.rdp_operational_downstream_facts = status
            .provider_zero
            .rdp_operational_downstream_facts
            .saturating_add(counters.downstream_facts);
        if let Some(provider) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::WindowsRdpOperational)
        {
            provider.bounded_counters = status.provider_zero.clone();
            provider.degraded_reason = if counters.dag_dispatches == 0 {
                Some("rdp_operational_runtime_dispatch_pending".to_string())
            } else {
                None
            };
        }
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.latest_rdp_operational_batch = Some(batch);
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_smb_operational_sensing_lifecycle(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        lifecycle: EtwLifecycleStatus,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        lifecycle
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.provider_zero.smb_operational_sensing_calls = status
            .provider_zero
            .smb_operational_sensing_calls
            .saturating_add(1);
        status.audit_summary.provider_execution_event_count = status
            .audit_summary
            .provider_execution_event_count
            .saturating_add(1);
        status.audit_summary.audit_refs = bounded_provider_refs(
            status
                .audit_summary
                .audit_refs
                .into_iter()
                .chain(lifecycle.audit_refs.clone()),
        );
        status.controller_state = match lifecycle.lifecycle_state {
            EtwLifecycleState::Active => NetworkProviderControllerState::Active,
            EtwLifecycleState::Paused => NetworkProviderControllerState::Paused,
            EtwLifecycleState::Degraded => NetworkProviderControllerState::Degraded,
            EtwLifecycleState::Stopped => NetworkProviderControllerState::Stopped,
            EtwLifecycleState::Failed => NetworkProviderControllerState::Failed,
            EtwLifecycleState::Activating | EtwLifecycleState::Resuming => {
                NetworkProviderControllerState::Activating
            }
            EtwLifecycleState::Pausing | EtwLifecycleState::Stopping => {
                NetworkProviderControllerState::Stopping
            }
            EtwLifecycleState::Inactive => NetworkProviderControllerState::Inactive,
        };
        if let Some(provider) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::WindowsSmbOperational)
        {
            provider.implementation_state = match lifecycle.lifecycle_state {
                EtwLifecycleState::Active | EtwLifecycleState::Paused => {
                    NetworkProviderImplementationState::Available
                }
                EtwLifecycleState::Degraded => NetworkProviderImplementationState::Degraded,
                EtwLifecycleState::Failed => NetworkProviderImplementationState::Failed,
                _ => NetworkProviderImplementationState::ImplementedInactive,
            };
            provider.lifecycle_state = match lifecycle.lifecycle_state {
                EtwLifecycleState::Inactive => NetworkProviderLifecycleState::Inactive,
                EtwLifecycleState::Activating | EtwLifecycleState::Resuming => {
                    NetworkProviderLifecycleState::Activating
                }
                EtwLifecycleState::Active => NetworkProviderLifecycleState::Active,
                EtwLifecycleState::Pausing | EtwLifecycleState::Stopping => {
                    NetworkProviderLifecycleState::Stopping
                }
                EtwLifecycleState::Paused => NetworkProviderLifecycleState::Paused,
                EtwLifecycleState::Degraded => NetworkProviderLifecycleState::Degraded,
                EtwLifecycleState::Stopped => NetworkProviderLifecycleState::Stopped,
                EtwLifecycleState::Failed => NetworkProviderLifecycleState::Failed,
            };
            provider.activation_allowed = true;
            provider.activation_unavailable_reason = None;
            provider.degraded_reason = lifecycle.degraded_reason.clone();
            provider.bounded_counters = status.provider_zero.clone();
            provider.provenance_refs = bounded_provider_refs(
                provider
                    .provenance_refs
                    .clone()
                    .into_iter()
                    .chain(["servicehost_windows_smb_operational_sensing".to_string()]),
            );
        }
        status.lifecycle_summary.controller_state = status.controller_state;
        status.lifecycle_summary.active_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Active)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.degraded_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Degraded)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.inactive_provider_count = status
            .providers
            .len()
            .saturating_sub(status.lifecycle_summary.active_provider_count as usize)
            .min(u8::MAX as usize) as u8;
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.state = status.controller_state.as_str().to_string();
        self.provider_call_count = self.provider_call_count.saturating_add(1);
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_smb_operational_sensing_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        batch: WindowsAuthRemoteObservationBatch,
        counters: AuthRemoteSensingDispatchCounters,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.provider_zero.smb_operational_publications = status
            .provider_zero
            .smb_operational_publications
            .saturating_add(counters.eventbus_publications);
        status
            .provider_zero
            .smb_operational_auth_detector_invocations = status
            .provider_zero
            .smb_operational_auth_detector_invocations
            .saturating_add(counters.auth_detector_invocations);
        status.provider_zero.smb_operational_auth_consumed = status
            .provider_zero
            .smb_operational_auth_consumed
            .saturating_add(counters.auth_consumed);
        status
            .provider_zero
            .smb_operational_remote_admin_invocations = status
            .provider_zero
            .smb_operational_remote_admin_invocations
            .saturating_add(counters.remote_admin_invocations);
        status.provider_zero.smb_operational_remote_admin_consumed = status
            .provider_zero
            .smb_operational_remote_admin_consumed
            .saturating_add(counters.remote_admin_consumed);
        status.provider_zero.smb_operational_lateral_invocations = status
            .provider_zero
            .smb_operational_lateral_invocations
            .saturating_add(counters.lateral_invocations);
        status.provider_zero.smb_operational_lateral_consumed = status
            .provider_zero
            .smb_operational_lateral_consumed
            .saturating_add(counters.lateral_consumed);
        status.provider_zero.smb_operational_downstream_facts = status
            .provider_zero
            .smb_operational_downstream_facts
            .saturating_add(counters.downstream_facts);
        if let Some(provider) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::WindowsSmbOperational)
        {
            provider.bounded_counters = status.provider_zero.clone();
            provider.degraded_reason = if counters.dag_dispatches == 0 {
                Some("smb_operational_runtime_dispatch_pending".to_string())
            } else {
                None
            };
        }
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.latest_smb_operational_batch = Some(batch);
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_ssh_operational_sensing_lifecycle(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        lifecycle: EtwLifecycleStatus,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        lifecycle
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.provider_zero.ssh_operational_sensing_calls = status
            .provider_zero
            .ssh_operational_sensing_calls
            .saturating_add(1);
        status.audit_summary.provider_execution_event_count = status
            .audit_summary
            .provider_execution_event_count
            .saturating_add(1);
        status.audit_summary.audit_refs = bounded_provider_refs(
            status
                .audit_summary
                .audit_refs
                .into_iter()
                .chain(lifecycle.audit_refs.clone()),
        );
        status.controller_state = match lifecycle.lifecycle_state {
            EtwLifecycleState::Active => NetworkProviderControllerState::Active,
            EtwLifecycleState::Paused => NetworkProviderControllerState::Paused,
            EtwLifecycleState::Degraded => NetworkProviderControllerState::Degraded,
            EtwLifecycleState::Stopped => NetworkProviderControllerState::Stopped,
            EtwLifecycleState::Failed => NetworkProviderControllerState::Failed,
            EtwLifecycleState::Activating | EtwLifecycleState::Resuming => {
                NetworkProviderControllerState::Activating
            }
            EtwLifecycleState::Pausing | EtwLifecycleState::Stopping => {
                NetworkProviderControllerState::Stopping
            }
            EtwLifecycleState::Inactive => NetworkProviderControllerState::Inactive,
        };
        if let Some(provider) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::WindowsSshOperational)
        {
            provider.implementation_state = match lifecycle.lifecycle_state {
                EtwLifecycleState::Active | EtwLifecycleState::Paused => {
                    NetworkProviderImplementationState::Available
                }
                EtwLifecycleState::Degraded => NetworkProviderImplementationState::Degraded,
                EtwLifecycleState::Failed => NetworkProviderImplementationState::Failed,
                _ => NetworkProviderImplementationState::ImplementedInactive,
            };
            provider.lifecycle_state = match lifecycle.lifecycle_state {
                EtwLifecycleState::Inactive => NetworkProviderLifecycleState::Inactive,
                EtwLifecycleState::Activating | EtwLifecycleState::Resuming => {
                    NetworkProviderLifecycleState::Activating
                }
                EtwLifecycleState::Active => NetworkProviderLifecycleState::Active,
                EtwLifecycleState::Pausing | EtwLifecycleState::Stopping => {
                    NetworkProviderLifecycleState::Stopping
                }
                EtwLifecycleState::Paused => NetworkProviderLifecycleState::Paused,
                EtwLifecycleState::Degraded => NetworkProviderLifecycleState::Degraded,
                EtwLifecycleState::Stopped => NetworkProviderLifecycleState::Stopped,
                EtwLifecycleState::Failed => NetworkProviderLifecycleState::Failed,
            };
            provider.activation_allowed = true;
            provider.activation_unavailable_reason = None;
            provider.degraded_reason = lifecycle.degraded_reason.clone();
            provider.bounded_counters = status.provider_zero.clone();
            provider.provenance_refs = bounded_provider_refs(
                provider
                    .provenance_refs
                    .clone()
                    .into_iter()
                    .chain(["servicehost_windows_ssh_operational_sensing".to_string()]),
            );
        }
        status.lifecycle_summary.controller_state = status.controller_state;
        status.lifecycle_summary.active_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Active)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.degraded_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Degraded)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.inactive_provider_count = status
            .providers
            .len()
            .saturating_sub(status.lifecycle_summary.active_provider_count as usize)
            .min(u8::MAX as usize) as u8;
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.state = status.controller_state.as_str().to_string();
        self.provider_call_count = self.provider_call_count.saturating_add(1);
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_ssh_operational_sensing_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        batch: WindowsAuthRemoteObservationBatch,
        counters: AuthRemoteSensingDispatchCounters,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.provider_zero.ssh_operational_publications = status
            .provider_zero
            .ssh_operational_publications
            .saturating_add(counters.eventbus_publications);
        status
            .provider_zero
            .ssh_operational_auth_detector_invocations = status
            .provider_zero
            .ssh_operational_auth_detector_invocations
            .saturating_add(counters.auth_detector_invocations);
        status.provider_zero.ssh_operational_auth_consumed = status
            .provider_zero
            .ssh_operational_auth_consumed
            .saturating_add(counters.auth_consumed);
        status
            .provider_zero
            .ssh_operational_remote_admin_invocations = status
            .provider_zero
            .ssh_operational_remote_admin_invocations
            .saturating_add(counters.remote_admin_invocations);
        status.provider_zero.ssh_operational_remote_admin_consumed = status
            .provider_zero
            .ssh_operational_remote_admin_consumed
            .saturating_add(counters.remote_admin_consumed);
        status.provider_zero.ssh_operational_lateral_invocations = status
            .provider_zero
            .ssh_operational_lateral_invocations
            .saturating_add(counters.lateral_invocations);
        status.provider_zero.ssh_operational_lateral_consumed = status
            .provider_zero
            .ssh_operational_lateral_consumed
            .saturating_add(counters.lateral_consumed);
        status.provider_zero.ssh_operational_downstream_facts = status
            .provider_zero
            .ssh_operational_downstream_facts
            .saturating_add(counters.downstream_facts);
        if let Some(provider) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::WindowsSshOperational)
        {
            provider.bounded_counters = status.provider_zero.clone();
            provider.degraded_reason = if counters.dag_dispatches == 0 {
                Some("ssh_operational_runtime_dispatch_pending".to_string())
            } else {
                None
            };
        }
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.latest_ssh_operational_batch = Some(batch);
        self.status = Some(status.clone());
        Ok(status)
    }

    fn update_schedule_status(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        update: IpHelperScheduleStatusUpdate,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        let mut schedule = status.ip_helper_schedule.clone();
        if let Some(config) = update.config {
            config
                .validate()
                .map_err(|error| provider_execution_error(error.to_string()))?;
            schedule.config = config;
        }
        schedule.ownership_epoch = owner_context.ownership_epoch;
        schedule.schedule_state = update.schedule_state;
        schedule.enabled_marker = update.schedule_state == IpHelperScheduleState::ConfiguredEnabled;
        schedule.paused_marker = update.schedule_state == IpHelperScheduleState::Paused;
        schedule.lease_state = update.lease_state;
        schedule.schedule_lease_ref = update.schedule_lease_ref;
        schedule.schedule_lease_valid = update.schedule_state
            == IpHelperScheduleState::ConfiguredEnabled
            && update.lease_state == IpHelperScheduleLeaseState::Active
            && schedule.schedule_lease_ref.is_some();
        if !schedule.schedule_lease_valid {
            schedule.timer_runtime_active = false;
            schedule.next_due_category = IpHelperScheduleNextDueCategory::NotRunning;
        }
        schedule.authorization_refs = bounded_runtime_refs(update.authorization_refs);
        schedule.policy_id = update.policy_id;
        schedule.policy_version = update.policy_version;
        schedule.updated_time_bucket = Timestamp::now();
        schedule.audit_refs = bounded_runtime_refs(
            schedule
                .audit_refs
                .into_iter()
                .chain([update.audit_event.to_string()]),
        );
        schedule.degraded_reason = update.degraded_reason;
        schedule
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        status.ip_helper_schedule = schedule;
        status.audit_summary.audit_refs = bounded_provider_refs(
            status
                .audit_summary
                .audit_refs
                .into_iter()
                .chain([update.audit_event.to_string()]),
        );
        status.audit_summary.status_publication_count = status
            .audit_summary
            .status_publication_count
            .saturating_add(1);
        status.generated_at = Timestamp::now();
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_ip_helper_schedule_configured(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        config: IpHelperScheduleConfig,
        authorization_refs: Vec<String>,
        policy_id: String,
        policy_version: SchemaVersion,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.update_schedule_status(
            owner_context,
            IpHelperScheduleStatusUpdate {
                schedule_state: IpHelperScheduleState::ConfiguredDisabled,
                lease_state: IpHelperScheduleLeaseState::NoLease,
                config: Some(config),
                schedule_lease_ref: None,
                authorization_refs,
                audit_event: IP_HELPER_SCHEDULE_CONFIGURED,
                policy_id,
                policy_version,
                degraded_reason: None,
            },
        )
    }

    fn record_ip_helper_schedule_enabled(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        schedule_lease_ref: String,
        authorization_refs: Vec<String>,
        policy_id: String,
        policy_version: SchemaVersion,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.update_schedule_status(
            owner_context,
            IpHelperScheduleStatusUpdate {
                schedule_state: IpHelperScheduleState::ConfiguredEnabled,
                lease_state: IpHelperScheduleLeaseState::Active,
                config: None,
                schedule_lease_ref: Some(schedule_lease_ref),
                authorization_refs: authorization_refs
                    .into_iter()
                    .chain([IP_HELPER_SCHEDULE_LEASE_CREATED.to_string()])
                    .collect(),
                audit_event: IP_HELPER_SCHEDULE_ENABLED,
                policy_id,
                policy_version,
                degraded_reason: Some("timer_runtime_inactive".to_string()),
            },
        )
    }

    fn record_ip_helper_schedule_paused(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
        policy_id: String,
        policy_version: SchemaVersion,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.update_schedule_status(
            owner_context,
            IpHelperScheduleStatusUpdate {
                schedule_state: IpHelperScheduleState::Paused,
                lease_state: IpHelperScheduleLeaseState::Paused,
                config: None,
                schedule_lease_ref: None,
                authorization_refs,
                audit_event: IP_HELPER_SCHEDULE_PAUSED,
                policy_id,
                policy_version,
                degraded_reason: Some("schedule_paused".to_string()),
            },
        )
    }

    fn record_ip_helper_schedule_resumed(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        schedule_lease_ref: String,
        authorization_refs: Vec<String>,
        policy_id: String,
        policy_version: SchemaVersion,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.update_schedule_status(
            owner_context,
            IpHelperScheduleStatusUpdate {
                schedule_state: IpHelperScheduleState::ConfiguredEnabled,
                lease_state: IpHelperScheduleLeaseState::Active,
                config: None,
                schedule_lease_ref: Some(schedule_lease_ref),
                authorization_refs,
                audit_event: IP_HELPER_SCHEDULE_RESUMED,
                policy_id,
                policy_version,
                degraded_reason: Some("timer_runtime_inactive".to_string()),
            },
        )
    }

    fn record_ip_helper_schedule_disabled(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
        policy_id: String,
        policy_version: SchemaVersion,
        reason: &'static str,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.update_schedule_status(
            owner_context,
            IpHelperScheduleStatusUpdate {
                schedule_state: IpHelperScheduleState::ConfiguredDisabled,
                lease_state: IpHelperScheduleLeaseState::Invalidated,
                config: None,
                schedule_lease_ref: None,
                authorization_refs: authorization_refs
                    .into_iter()
                    .chain([IP_HELPER_SCHEDULE_INVALIDATED.to_string()])
                    .collect(),
                audit_event: IP_HELPER_SCHEDULE_DISABLED,
                policy_id,
                policy_version,
                degraded_reason: Some(reason.to_string()),
            },
        )
    }

    fn record_ip_helper_schedule_invalidated(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        audit_event: &'static str,
        reason: &'static str,
    ) -> CommandResult<Option<NetworkProviderControllerStatus>> {
        let status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        if !matches!(
            status.ip_helper_schedule.schedule_state,
            IpHelperScheduleState::ConfiguredEnabled | IpHelperScheduleState::Paused
        ) {
            return Ok(None);
        }
        self.update_schedule_status(
            owner_context,
            IpHelperScheduleStatusUpdate {
                schedule_state: IpHelperScheduleState::Invalidated,
                lease_state: IpHelperScheduleLeaseState::Invalidated,
                config: None,
                schedule_lease_ref: None,
                authorization_refs: vec![IP_HELPER_SCHEDULE_INVALIDATED.to_string()],
                audit_event,
                policy_id: status.ip_helper_schedule.policy_id,
                policy_version: status.ip_helper_schedule.policy_version,
                degraded_reason: Some(reason.to_string()),
            },
        )
        .map(Some)
    }

    fn record_ip_helper_scheduler_host_started(
        &mut self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        if status.ip_helper_schedule.schedule_state != IpHelperScheduleState::ConfiguredEnabled
            || status.ip_helper_schedule.lease_state != IpHelperScheduleLeaseState::Active
            || status.ip_helper_schedule.schedule_lease_ref.is_none()
        {
            return Err(provider_execution_error(
                "ip_helper_scheduler_host_requires_active_schedule_lease",
            ));
        }
        status.ip_helper_schedule.timer_runtime_active = true;
        status.ip_helper_schedule.schedule_lease_valid = true;
        status.ip_helper_schedule.next_due_category = IpHelperScheduleNextDueCategory::Deferred;
        status.ip_helper_schedule.degraded_reason = None;
        status.ip_helper_schedule.updated_time_bucket = Timestamp::now();
        status.ip_helper_schedule.audit_refs = bounded_runtime_refs(
            status
                .ip_helper_schedule
                .audit_refs
                .into_iter()
                .chain([IP_HELPER_SCHEDULER_HOST_STARTED.to_string()]),
        );
        status.audit_summary.audit_refs = bounded_provider_refs(
            status
                .audit_summary
                .audit_refs
                .into_iter()
                .chain([IP_HELPER_SCHEDULER_HOST_STARTED.to_string()]),
        );
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_ip_helper_scheduler_host_stopped(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        audit_event: &'static str,
        reason: &'static str,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.ip_helper_schedule.timer_runtime_active = false;
        status.ip_helper_schedule.next_due_category = IpHelperScheduleNextDueCategory::NotRunning;
        status.ip_helper_schedule.degraded_reason = Some(reason.to_string());
        status.ip_helper_schedule.updated_time_bucket = Timestamp::now();
        status.ip_helper_schedule.audit_refs = bounded_runtime_refs(
            status
                .ip_helper_schedule
                .audit_refs
                .into_iter()
                .chain([audit_event.to_string()]),
        );
        status.audit_summary.audit_refs = bounded_provider_refs(
            status
                .audit_summary
                .audit_refs
                .into_iter()
                .chain([audit_event.to_string()]),
        );
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_ip_helper_scheduled_cycle_skipped(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        cycle_ref: String,
        draft: IpHelperScheduledSkipDraft,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        status.ip_helper_schedule.skipped_count_bucket =
            bump_ip_helper_count_bucket(status.ip_helper_schedule.skipped_count_bucket);
        if draft.retry_state == IpHelperScheduledRetryState::Scheduled {
            status.ip_helper_schedule.retry_count_bucket =
                bump_ip_helper_count_bucket(status.ip_helper_schedule.retry_count_bucket);
        }
        if draft.execution_result == IpHelperScheduledExecutionResult::TimedOut {
            status.ip_helper_schedule.timeout_count_bucket =
                bump_ip_helper_count_bucket(status.ip_helper_schedule.timeout_count_bucket);
        }
        if draft.execution_result == IpHelperScheduledExecutionResult::Busy {
            status.ip_helper_schedule.overlap_skip_count_bucket =
                bump_ip_helper_count_bucket(status.ip_helper_schedule.overlap_skip_count_bucket);
        }
        status.ip_helper_schedule.latest_scheduled_cycle_ref = Some(cycle_ref.clone());
        status.ip_helper_schedule.latest_scheduled_execution_result = draft.execution_result;
        status.ip_helper_schedule.latest_scheduled_cycle = Some(IpHelperScheduledCycleRecord {
            cycle_ref,
            scheduler_item_ref: "ip_helper_scheduler_item_ref".to_string(),
            schedule_ref: status.ip_helper_schedule.schedule_ref.clone(),
            cycle_type: IpHelperScheduledCycleType::Scheduled,
            due_state: draft.due_state,
            authorization_state: draft.authorization_state,
            execution_result: draft.execution_result,
            retry_state: draft.retry_state,
            backpressure_state: draft.backpressure_state,
            freshness_result: status.ip_helper_schedule.freshness_state,
            missed_sample_result: draft.missed_sample_state,
            started_time_bucket: Some(Timestamp::now()),
            completed_time_bucket: Some(Timestamp::now()),
            duration_bucket: "no_provider_call".to_string(),
            provider_call_count_bucket: IpHelperScheduleCountBucket::Zero,
            batch_refs: Vec::new(),
            fact_refs: Vec::new(),
            snapshot_refs: Vec::new(),
            audit_refs: vec![draft.audit_event.to_string()],
            degraded_reason: Some(draft.reason.to_string()),
            provenance_id: "servicehost_ip_helper_scheduler_runtime".to_string(),
            redaction_status: RedactionStatus::Redacted,
        });
        status.ip_helper_schedule.backpressure_state = draft.backpressure_state;
        status.ip_helper_schedule.missed_sample_state = draft.missed_sample_state;
        status.ip_helper_schedule.degraded_reason = Some(draft.reason.to_string());
        status.ip_helper_schedule.updated_time_bucket = Timestamp::now();
        status.ip_helper_schedule.audit_refs = bounded_runtime_refs(
            status
                .ip_helper_schedule
                .audit_refs
                .into_iter()
                .chain([draft.audit_event.to_string()]),
        );
        status.audit_summary.audit_refs = bounded_provider_refs(
            status
                .audit_summary
                .audit_refs
                .into_iter()
                .chain([draft.audit_event.to_string()]),
        );
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status.generated_at = Timestamp::now();
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_ip_helper_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        mut batch: NativeIpHelperMetadataBatch,
        fact_refs: Vec<sentinel_contracts::SecurityFactId>,
        emitted_topic_count: u32,
        execution_policy: IpHelperHandoffExecutionPolicy,
        execution_ref: String,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        let fact_ref_strings = fact_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        let safe_health = batch.provider_health;
        let execution_degraded = !matches!(safe_health, NativeNetworkProviderHealth::Available);
        status.controller_state = if execution_degraded {
            NetworkProviderControllerState::Degraded
        } else {
            NetworkProviderControllerState::Active
        };
        status.selected_mode = if matches!(
            safe_health,
            NativeNetworkProviderHealth::Available | NativeNetworkProviderHealth::Degraded
        ) {
            NetworkProviderControllerMode::IpHelperOnly
        } else {
            NetworkProviderControllerMode::Degraded
        };
        status.generated_at = Timestamp::now();
        status.fallback_plan.selected_mode = status.selected_mode;
        status.fallback_plan.degraded_reason = if execution_degraded {
            batch.degraded_reason.clone().or_else(|| {
                Some(format!(
                    "ip_helper_{}",
                    provider_health_label(batch.provider_health)
                ))
            })
        } else {
            None
        };
        status.dependency_summary.degraded_reason = status.fallback_plan.degraded_reason.clone();
        status.lifecycle_summary.controller_state = status.controller_state;
        status.lifecycle_summary.selected_mode = status.selected_mode;
        status.lifecycle_summary.active_provider_count =
            if status.selected_mode == NetworkProviderControllerMode::IpHelperOnly {
                1
            } else {
                0
            };
        status.lifecycle_summary.inactive_provider_count = status
            .providers
            .len()
            .saturating_sub(status.lifecycle_summary.active_provider_count as usize)
            as u8;
        status.lifecycle_summary.degraded_provider_count = u8::from(execution_degraded);
        status.audit_summary.provider_execution_event_count = status
            .audit_summary
            .provider_execution_event_count
            .saturating_add(1);
        status.audit_summary.audit_refs = bounded_provider_refs(
            status
                .audit_summary
                .audit_refs
                .into_iter()
                .chain(batch.audit_refs.clone()),
        );
        status.provider_zero.ip_helper_calls =
            status.provider_zero.ip_helper_calls.saturating_add(1);
        status.provider_zero.native_network_topic_publications = status
            .provider_zero
            .native_network_topic_publications
            .saturating_add(emitted_topic_count);
        match execution_policy {
            IpHelperHandoffExecutionPolicy::ScheduledServiceHost => {
                status.ip_helper_schedule.scheduler_triggered_provider_calls = status
                    .ip_helper_schedule
                    .scheduler_triggered_provider_calls
                    .saturating_add(1);
                status.ip_helper_schedule.execution_count_bucket =
                    bump_ip_helper_count_bucket(status.ip_helper_schedule.execution_count_bucket);
                status.ip_helper_schedule.scheduled_sample_count_bucket =
                    bump_ip_helper_count_bucket(
                        status.ip_helper_schedule.scheduled_sample_count_bucket,
                    );
                status.ip_helper_schedule.latest_scheduled_cycle_ref = Some(execution_ref.clone());
                status.ip_helper_schedule.latest_scheduled_execution_result =
                    IpHelperScheduledExecutionResult::Completed;
                status.ip_helper_schedule.latest_scheduled_cycle =
                    Some(IpHelperScheduledCycleRecord {
                        cycle_ref: execution_ref,
                        scheduler_item_ref: "ip_helper_scheduler_item_ref".to_string(),
                        schedule_ref: status.ip_helper_schedule.schedule_ref.clone(),
                        cycle_type: IpHelperScheduledCycleType::Scheduled,
                        due_state: IpHelperScheduledDueState::Due,
                        authorization_state: IpHelperScheduledAuthorizationState::Valid,
                        execution_result: IpHelperScheduledExecutionResult::Completed,
                        retry_state: IpHelperScheduledRetryState::None,
                        backpressure_state: IpHelperScheduledBackpressureState::None,
                        freshness_result: IpHelperScheduledFreshnessState::Fresh,
                        missed_sample_result: IpHelperScheduledMissedSampleState::OnTime,
                        started_time_bucket: Some(batch.sampled_time_bucket.clone()),
                        completed_time_bucket: Some(Timestamp::now()),
                        duration_bucket: "bounded_under_timeout".to_string(),
                        provider_call_count_bucket: IpHelperScheduleCountBucket::One,
                        batch_refs: vec![batch.batch_ref.clone()],
                        fact_refs: fact_ref_strings
                            .into_iter()
                            .take(sentinel_contracts::MAX_IP_HELPER_SCHEDULE_REFS)
                            .collect(),
                        snapshot_refs: vec!["canonical_read_model_snapshot_ref".to_string()],
                        audit_refs: bounded_runtime_refs(batch.audit_refs.clone()),
                        degraded_reason: None,
                        provenance_id: "servicehost_ip_helper_scheduler_runtime".to_string(),
                        redaction_status: RedactionStatus::Redacted,
                    });
                status.ip_helper_schedule.timer_runtime_active = true;
                status.ip_helper_schedule.next_due_category =
                    IpHelperScheduleNextDueCategory::Deferred;
                status.ip_helper_schedule.backpressure_state =
                    IpHelperScheduledBackpressureState::None;
                status.ip_helper_schedule.freshness_state = IpHelperScheduledFreshnessState::Fresh;
                status.ip_helper_schedule.missed_sample_state =
                    IpHelperScheduledMissedSampleState::OnTime;
                status.ip_helper_schedule.audit_refs =
                    bounded_runtime_refs(status.ip_helper_schedule.audit_refs.into_iter().chain([
                        IP_HELPER_SCHEDULED_CYCLE_STARTED.to_string(),
                        IP_HELPER_SCHEDULED_CYCLE_COMPLETED.to_string(),
                    ]));
            }
            _ => {
                status.ip_helper_schedule.latest_manual_sample_ref = Some(batch.batch_ref.clone());
                status.ip_helper_schedule.manual_sample_count_bucket = bump_ip_helper_count_bucket(
                    status.ip_helper_schedule.manual_sample_count_bucket,
                );
            }
        }
        if let Some(ip_helper) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::IpHelper)
        {
            ip_helper.implementation_state = match safe_health {
                NativeNetworkProviderHealth::Available => {
                    NetworkProviderImplementationState::Available
                }
                NativeNetworkProviderHealth::Degraded => {
                    NetworkProviderImplementationState::Degraded
                }
                NativeNetworkProviderHealth::Unavailable => {
                    NetworkProviderImplementationState::Unavailable
                }
                NativeNetworkProviderHealth::UnsupportedPlatform => {
                    NetworkProviderImplementationState::UnsupportedPlatform
                }
            };
            ip_helper.lifecycle_state = if execution_degraded {
                NetworkProviderLifecycleState::Degraded
            } else {
                NetworkProviderLifecycleState::Active
            };
            ip_helper.degraded_reason = status.fallback_plan.degraded_reason.clone();
            ip_helper.bounded_counters = status.provider_zero.clone();
            ip_helper.provenance_refs =
                bounded_provider_refs(ip_helper.provenance_refs.clone().into_iter().chain([
                    "ip_helper_servicehost_handoff".to_string(),
                    batch.provenance_id.clone(),
                ]));
        }
        for dimension in &mut status.visibility_summary.dimensions {
            match dimension.dimension {
                NetworkVisibilityDimension::ConnectionTableVisibility => {
                    dimension.visibility_state =
                        if status.selected_mode == NetworkProviderControllerMode::IpHelperOnly {
                            NetworkVisibilityState::Available
                        } else {
                            NetworkVisibilityState::Unavailable
                        };
                    dimension.degraded_reason = status.fallback_plan.degraded_reason.clone();
                }
                NetworkVisibilityDimension::ShortLivedNetworkEventVisibility
                | NetworkVisibilityDimension::ProcessNetworkCategoryVisibility
                | NetworkVisibilityDimension::PacketHeaderVisibility
                | NetworkVisibilityDimension::PacketPayloadVisibility
                | NetworkVisibilityDimension::SpecificProcessIdentityVisibility => {
                    dimension.visibility_state = NetworkVisibilityState::Unavailable;
                    dimension.degraded_reason =
                        Some("visibility_not_provided_by_ip_helper_handoff".to_string());
                }
                _ => {}
            }
        }
        status.visibility_summary.generated_at = Timestamp::now();
        status.visibility_summary.provenance_refs = bounded_provider_refs(
            status
                .visibility_summary
                .provenance_refs
                .into_iter()
                .chain(["ip_helper_servicehost_handoff".to_string()]),
        );
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;

        batch.fact_refs = fact_refs;
        batch.validate().map_err(provider_execution_error)?;
        self.state = status.controller_state.as_str().to_string();
        self.provider_call_count = self.provider_call_count.saturating_add(1);
        self.provider_zero.ip_helper_calls = self.provider_zero.ip_helper_calls.saturating_add(1);
        self.provider_zero.native_network_topics = self
            .provider_zero
            .native_network_topics
            .saturating_add(emitted_topic_count);
        self.latest_ip_helper_batch = Some(batch);
        self.status = Some(status.clone());
        Ok(status)
    }

    fn record_etw_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        batch: EtwNormalizedNetworkBatch,
        fact_refs: Vec<sentinel_contracts::SecurityFactId>,
        emitted_topic_count: u32,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        let execution_degraded = batch.degraded_reason.is_some()
            || batch.events_dropped > 0
            || batch.events_rejected > 0;
        let events_available = batch.events_accepted > 0 && !batch.records.is_empty();

        status.controller_state = if execution_degraded {
            NetworkProviderControllerState::Degraded
        } else {
            NetworkProviderControllerState::Active
        };
        status.selected_mode = if execution_degraded {
            NetworkProviderControllerMode::Degraded
        } else {
            NetworkProviderControllerMode::EtwPlusIpHelper
        };
        status.generated_at = Timestamp::now();
        status.fallback_plan.selected_mode = status.selected_mode;
        status.fallback_plan.degraded_reason = if execution_degraded {
            batch
                .degraded_reason
                .clone()
                .or_else(|| Some("etw_bounded_handoff_degraded".to_string()))
        } else {
            None
        };
        status.dependency_summary.degraded_reason = status.fallback_plan.degraded_reason.clone();
        status.audit_summary.provider_execution_event_count = status
            .audit_summary
            .provider_execution_event_count
            .saturating_add(1);
        status.audit_summary.audit_refs = bounded_provider_refs(
            status
                .audit_summary
                .audit_refs
                .into_iter()
                .chain(batch.provenance_refs.clone())
                .chain(["etw_runtime_handoff".to_string()]),
        );
        status.provider_zero.etw_calls = status.provider_zero.etw_calls.saturating_add(1);
        status.provider_zero.native_network_topic_publications = status
            .provider_zero
            .native_network_topic_publications
            .saturating_add(emitted_topic_count);

        if let Some(etw) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::EtwNetwork)
        {
            etw.implementation_state = if execution_degraded {
                NetworkProviderImplementationState::Degraded
            } else {
                NetworkProviderImplementationState::Available
            };
            etw.lifecycle_state = if execution_degraded {
                NetworkProviderLifecycleState::Degraded
            } else {
                NetworkProviderLifecycleState::Active
            };
            etw.activation_allowed = true;
            etw.activation_unavailable_reason = None;
            etw.degraded_reason = status.fallback_plan.degraded_reason.clone();
            etw.bounded_counters = status.provider_zero.clone();
            etw.provenance_refs = bounded_provider_refs(
                etw.provenance_refs
                    .clone()
                    .into_iter()
                    .chain(batch.provenance_refs.clone())
                    .chain(["etw_runtime_handoff".to_string()]),
            );
        }
        for dimension in &mut status.visibility_summary.dimensions {
            match dimension.dimension {
                NetworkVisibilityDimension::ShortLivedNetworkEventVisibility => {
                    dimension.visibility_state = if events_available {
                        NetworkVisibilityState::Available
                    } else {
                        NetworkVisibilityState::Degraded
                    };
                    dimension.degraded_reason = if events_available && !execution_degraded {
                        None
                    } else {
                        status
                            .fallback_plan
                            .degraded_reason
                            .clone()
                            .or_else(|| Some("etw_no_accepted_events_in_batch".to_string()))
                    };
                }
                NetworkVisibilityDimension::ProcessNetworkCategoryVisibility
                | NetworkVisibilityDimension::PacketHeaderVisibility
                | NetworkVisibilityDimension::PacketPayloadVisibility
                | NetworkVisibilityDimension::SpecificProcessIdentityVisibility
                | NetworkVisibilityDimension::SpecificDestinationIdentityVisibility => {
                    dimension.visibility_state = NetworkVisibilityState::Unavailable;
                    dimension.degraded_reason =
                        Some("visibility_not_provided_by_etw_handoff".to_string());
                }
                _ => {}
            }
        }
        status.visibility_summary.generated_at = Timestamp::now();
        status.visibility_summary.provenance_refs = bounded_provider_refs(
            status
                .visibility_summary
                .provenance_refs
                .into_iter()
                .chain(batch.provenance_refs.clone())
                .chain(["etw_runtime_handoff".to_string()]),
        );
        status.lifecycle_summary.controller_state = status.controller_state;
        status.lifecycle_summary.selected_mode = status.selected_mode;
        status.lifecycle_summary.active_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Active)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.degraded_provider_count = status
            .providers
            .iter()
            .filter(|provider| provider.lifecycle_state == NetworkProviderLifecycleState::Degraded)
            .count()
            .min(u8::MAX as usize) as u8;
        status.lifecycle_summary.inactive_provider_count = status
            .providers
            .len()
            .saturating_sub(status.lifecycle_summary.active_provider_count as usize)
            .min(u8::MAX as usize) as u8;
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;

        self.state = status.controller_state.as_str().to_string();
        self.provider_call_count = self.provider_call_count.saturating_add(1);
        self.provider_zero.etw_calls = self.provider_zero.etw_calls.saturating_add(1);
        self.provider_zero.native_network_topics = self
            .provider_zero
            .native_network_topics
            .saturating_add(emitted_topic_count);
        self.latest_etw_batch = Some(batch);
        self.status = Some(status.clone());
        let _ = fact_refs;
        Ok(status)
    }

    fn record_ip_helper_activation(
        &mut self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<(NetworkProviderControllerStatus, bool)> {
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        let already_active =
            status
                .provider(NetworkProviderKind::IpHelper)
                .is_some_and(|provider| {
                    provider.lifecycle_state == NetworkProviderLifecycleState::Active
                });
        status.controller_state = NetworkProviderControllerState::Active;
        status.selected_mode = NetworkProviderControllerMode::PortableOnly;
        status.generated_at = Timestamp::now();
        status.fallback_plan.selected_mode = status.selected_mode;
        status.fallback_plan.degraded_reason = Some("no_successful_sample".to_string());
        status.dependency_summary.degraded_reason = Some("no_successful_sample".to_string());
        status.lifecycle_summary.controller_state = status.controller_state;
        status.lifecycle_summary.selected_mode = status.selected_mode;
        status.lifecycle_summary.active_provider_count = 0;
        status.lifecycle_summary.inactive_provider_count = status.providers.len() as u8;
        status.lifecycle_summary.degraded_provider_count = 0;
        status.audit_summary.provider_execution_event_count = status
            .audit_summary
            .provider_execution_event_count
            .saturating_add(1);
        status.audit_summary.audit_refs =
            bounded_provider_refs(status.audit_summary.audit_refs.into_iter().chain([
                "ip_helper_activation_authorized".to_string(),
                "ip_helper_activation_completed".to_string(),
            ]));
        if let Some(ip_helper) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::IpHelper)
        {
            ip_helper.implementation_state = NetworkProviderImplementationState::Available;
            ip_helper.lifecycle_state = NetworkProviderLifecycleState::Active;
            ip_helper.activation_allowed = true;
            ip_helper.activation_unavailable_reason = None;
            ip_helper.degraded_reason = Some("no_successful_sample".to_string());
            ip_helper.bounded_counters = status.provider_zero.clone();
            ip_helper.provenance_refs =
                bounded_provider_refs(ip_helper.provenance_refs.clone().into_iter().chain([
                    "ip_helper_activation_authorized".to_string(),
                    "ip_helper_activation_completed".to_string(),
                ]));
        }
        for dimension in &mut status.visibility_summary.dimensions {
            match dimension.dimension {
                NetworkVisibilityDimension::ConnectionTableVisibility => {
                    dimension.visibility_state = NetworkVisibilityState::Unavailable;
                    dimension.degraded_reason = Some("no_successful_sample".to_string());
                }
                NetworkVisibilityDimension::PortableMetadataVisibility => {
                    dimension.visibility_state = NetworkVisibilityState::Available;
                    dimension.degraded_reason = None;
                }
                NetworkVisibilityDimension::ShortLivedNetworkEventVisibility
                | NetworkVisibilityDimension::ProcessNetworkCategoryVisibility
                | NetworkVisibilityDimension::PacketHeaderVisibility
                | NetworkVisibilityDimension::PacketPayloadVisibility
                | NetworkVisibilityDimension::SpecificProcessIdentityVisibility => {
                    dimension.visibility_state = NetworkVisibilityState::Unavailable;
                    dimension.degraded_reason =
                        Some("visibility_not_provided_by_ip_helper_activation".to_string());
                }
                _ => {}
            }
        }
        status.visibility_summary.generated_at = Timestamp::now();
        status.visibility_summary.provenance_refs = bounded_provider_refs(
            status
                .visibility_summary
                .provenance_refs
                .into_iter()
                .chain(["ip_helper_activation_completed".to_string()]),
        );
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.state = status.controller_state.as_str().to_string();
        self.status = Some(status.clone());
        Ok((status, already_active))
    }

    fn record_ip_helper_stop(
        &mut self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<(NetworkProviderControllerStatus, bool)> {
        let mut status = self
            .status
            .clone()
            .ok_or_else(|| provider_execution_error("provider_controller_status_unavailable"))?;
        let already_stopped =
            status
                .provider(NetworkProviderKind::IpHelper)
                .is_some_and(|provider| {
                    provider.lifecycle_state == NetworkProviderLifecycleState::Stopped
                });
        status.controller_state = NetworkProviderControllerState::Stopped;
        status.selected_mode = NetworkProviderControllerMode::PortableOnly;
        status.generated_at = Timestamp::now();
        status.fallback_plan.selected_mode = status.selected_mode;
        status.fallback_plan.degraded_reason = Some("ip_helper_stopped".to_string());
        status.dependency_summary.degraded_reason = Some("ip_helper_stopped".to_string());
        status.lifecycle_summary.controller_state = status.controller_state;
        status.lifecycle_summary.selected_mode = status.selected_mode;
        status.lifecycle_summary.active_provider_count = 0;
        status.lifecycle_summary.inactive_provider_count = status.providers.len() as u8;
        status.lifecycle_summary.degraded_provider_count = 0;
        status.audit_summary.provider_execution_event_count = status
            .audit_summary
            .provider_execution_event_count
            .saturating_add(1);
        status.audit_summary.audit_refs =
            bounded_provider_refs(status.audit_summary.audit_refs.into_iter().chain([
                "ip_helper_stop_authorized".to_string(),
                "ip_helper_stop_completed".to_string(),
            ]));
        if let Some(ip_helper) = status
            .providers
            .iter_mut()
            .find(|provider| provider.provider_kind == NetworkProviderKind::IpHelper)
        {
            ip_helper.implementation_state = NetworkProviderImplementationState::Available;
            ip_helper.lifecycle_state = NetworkProviderLifecycleState::Stopped;
            ip_helper.activation_allowed = true;
            ip_helper.activation_unavailable_reason = None;
            ip_helper.degraded_reason = Some("ip_helper_stopped".to_string());
            ip_helper.bounded_counters = status.provider_zero.clone();
            ip_helper.provenance_refs =
                bounded_provider_refs(ip_helper.provenance_refs.clone().into_iter().chain([
                    "ip_helper_stop_authorized".to_string(),
                    "ip_helper_stop_completed".to_string(),
                ]));
        }
        for dimension in &mut status.visibility_summary.dimensions {
            match dimension.dimension {
                NetworkVisibilityDimension::PortableMetadataVisibility => {
                    dimension.visibility_state = NetworkVisibilityState::Available;
                    dimension.degraded_reason = None;
                }
                NetworkVisibilityDimension::ConnectionTableVisibility => {
                    dimension.visibility_state = NetworkVisibilityState::Unavailable;
                    dimension.degraded_reason = Some("ip_helper_stopped".to_string());
                }
                NetworkVisibilityDimension::ShortLivedNetworkEventVisibility
                | NetworkVisibilityDimension::ProcessNetworkCategoryVisibility
                | NetworkVisibilityDimension::PacketHeaderVisibility
                | NetworkVisibilityDimension::PacketPayloadVisibility
                | NetworkVisibilityDimension::SpecificProcessIdentityVisibility => {
                    dimension.visibility_state = NetworkVisibilityState::Unavailable;
                    dimension.degraded_reason =
                        Some("visibility_not_provided_by_ip_helper".to_string());
                }
                _ => {}
            }
        }
        status.visibility_summary.generated_at = Timestamp::now();
        status.visibility_summary.provenance_refs = bounded_provider_refs(
            status
                .visibility_summary
                .provenance_refs
                .into_iter()
                .chain(["ip_helper_stop_completed".to_string()]),
        );
        if matches!(
            status.ip_helper_schedule.schedule_state,
            IpHelperScheduleState::ConfiguredEnabled | IpHelperScheduleState::Paused
        ) {
            status.ip_helper_schedule.schedule_state = IpHelperScheduleState::Invalidated;
            status.ip_helper_schedule.enabled_marker = false;
            status.ip_helper_schedule.paused_marker = false;
            status.ip_helper_schedule.lease_state = IpHelperScheduleLeaseState::Invalidated;
            status.ip_helper_schedule.schedule_lease_ref = None;
            status.ip_helper_schedule.schedule_lease_valid = false;
            status.ip_helper_schedule.timer_runtime_active = false;
            status.ip_helper_schedule.next_due_category =
                IpHelperScheduleNextDueCategory::NotRunning;
            status.ip_helper_schedule.updated_time_bucket = Timestamp::now();
            status.ip_helper_schedule.degraded_reason = Some("provider_stopped".to_string());
            status.ip_helper_schedule.audit_refs =
                bounded_runtime_refs(status.ip_helper_schedule.audit_refs.into_iter().chain([
                    IP_HELPER_SCHEDULE_PROVIDER_STOPPED.to_string(),
                    IP_HELPER_SCHEDULE_INVALIDATED.to_string(),
                ]));
        }
        status.ownership_ref = owner_context.ownership_ref.clone();
        status.ownership_epoch = owner_context.ownership_epoch;
        status
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        self.state = status.controller_state.as_str().to_string();
        self.stop_called = true;
        self.status = Some(status.clone());
        Ok((status, already_stopped))
    }

    pub fn stop_called(&self) -> bool {
        self.stop_called
    }
}

#[derive(Clone, Debug)]
pub struct ServiceHostCanonicalReadModelStore {
    owner_context: RuntimeOwnerContext,
    current_generation: u64,
    current_snapshot: CanonicalReadModelSnapshot,
    published_snapshots: Vec<CanonicalReadModelSnapshot>,
}

impl ServiceHostCanonicalReadModelStore {
    fn new(
        owner_context: &RuntimeOwnerContext,
        items: Vec<CanonicalReadModelSnapshotItem>,
    ) -> CommandResult<Self> {
        validate_service_host_store_owner(owner_context)?;
        let snapshot = build_canonical_read_model_snapshot(
            owner_context,
            1,
            items,
            false,
            None,
            ReadModelSnapshotFreshness::Fresh,
        )?;
        Ok(Self {
            owner_context: owner_context.clone(),
            current_generation: 1,
            current_snapshot: snapshot.clone(),
            published_snapshots: vec![snapshot],
        })
    }

    fn publish(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        items: Vec<CanonicalReadModelSnapshotItem>,
    ) -> CommandResult<CanonicalReadModelSnapshot> {
        self.validate_update_owner(owner_context)?;
        let generation = self.current_generation.saturating_add(1).max(1);
        let snapshot = build_canonical_read_model_snapshot(
            owner_context,
            generation,
            items,
            false,
            None,
            ReadModelSnapshotFreshness::Fresh,
        )?;
        self.current_generation = generation;
        self.current_snapshot = snapshot.clone();
        self.published_snapshots.push(snapshot.clone());
        if self.published_snapshots.len() > MAX_CANONICAL_READ_MODEL_GENERATIONS {
            let overflow = self.published_snapshots.len() - MAX_CANONICAL_READ_MODEL_GENERATIONS;
            self.published_snapshots.drain(0..overflow);
        }
        Ok(snapshot)
    }

    fn validate_update_owner(&self, owner_context: &RuntimeOwnerContext) -> Result<(), CoreError> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_ref != owner_context.ownership_ref
            || self.owner_context.ownership_epoch != owner_context.ownership_epoch
            || self.owner_context.owner_category != owner_context.owner_category
            || self.owner_context.runtime_mode != owner_context.runtime_mode
        {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        validate_service_host_store_owner(owner_context)?;
        Ok(())
    }

    pub fn snapshot(&self) -> CanonicalReadModelSnapshot {
        self.current_snapshot.clone()
    }

    pub fn generation_count(&self) -> usize {
        self.published_snapshots.len()
    }

    pub fn current_generation(&self) -> u64 {
        self.current_generation
    }

    #[cfg(test)]
    fn published_snapshots(&self) -> &[CanonicalReadModelSnapshot] {
        &self.published_snapshots
    }
}

pub struct RuntimeContainer {
    owner_context: RuntimeOwnerContext,
    ownership_lease: RuntimeOwnershipLease,
    storage_writer: Option<StorageWriterLease>,
    durable_storage_manifest: ServiceHostDurableStorageManifest,
    storage_recovery_report: Option<ServiceHostStorageRecoveryReport>,
    event_bus: Option<RuntimeEventBusHandle>,
    runtime_services: Option<RuntimeServices>,
    pipeline_dag: Option<PipelineDag>,
    plugin_runtime: Option<RuntimePluginHandle>,
    app_core_orchestration: Option<MutationCommandState>,
    endpoint_threat_runtime: Option<ServiceOwnedEndpointThreatRuntime>,
    fusion_runtime: Option<ServiceOwnedFusionRuntime>,
    evidence_quality_runtime: Option<ServiceOwnedEvidenceQualityRuntime>,
    risk_runtime: Option<ServiceOwnedRiskRuntime>,
    attack_context_runtime: Option<ServiceOwnedAttackContextRuntime>,
    graph_runtime: Option<ServiceOwnedGraphRuntime>,
    baseline_runtime: Option<ServiceOwnedBaselineRuntime>,
    incident_linking_runtime: Option<ServiceOwnedIncidentLinkingRuntime>,
    report_export_traceability: Option<ServiceOwnedReportExportTraceability>,
    canonical_read_model_store: Option<ServiceHostCanonicalReadModelStore>,
    etw_lifecycle_runtime: Option<ServiceOwnedEtwLifecycleRuntime>,
    dns_sensing_lifecycle_runtime: Option<ServiceOwnedDnsSensingLifecycleRuntime>,
    auth_remote_sensing_lifecycle_runtime: Option<ServiceOwnedAuthRemoteSensingLifecycleRuntime>,
    rdp_operational_sensing_lifecycle_runtime:
        Option<ServiceOwnedAuthRemoteSensingLifecycleRuntime>,
    smb_operational_sensing_lifecycle_runtime:
        Option<ServiceOwnedAuthRemoteSensingLifecycleRuntime>,
    ssh_operational_sensing_lifecycle_runtime:
        Option<ServiceOwnedAuthRemoteSensingLifecycleRuntime>,
    component_summaries: Vec<RuntimeComponentOwnershipSummary>,
    audit_events: Vec<RuntimeOwnershipAuditEvent>,
    provider_controller: ProviderControllerShell,
    ip_helper_execution_active: bool,
    ip_helper_scheduled_sample_count: u32,
    ip_helper_scheduled_skip_count: u32,
    ip_helper_scheduled_retry_count: u32,
    ip_helper_scheduled_overlap_skip_count: u32,
    ip_helper_next_due_monotonic_millis: Option<u64>,
    ip_helper_schedule_wake_pending: bool,
    ip_helper_seen_cycle_refs: Vec<String>,
    #[cfg(test)]
    ip_helper_scheduler_test_fault: Option<IpHelperSchedulerTestFault>,
    shutdown_coordinator: RuntimeShutdownCoordinator,
    runtime_health: RuntimeHealthState,
    transition_state: RuntimeTransitionState,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpHelperSchedulerTestFault {
    ProviderTimeout,
    ProviderTemporarilyUnavailable,
    SaturatedBackpressure,
}

pub struct ServiceOwnedEndpointThreatRuntime {
    summary: EndpointThreatAnalysisSummary,
}

pub struct ServiceOwnedFusionRuntime {
    plugin: MultiLayerSecurityFusionPlugin,
}

pub struct ServiceOwnedEvidenceQualityRuntime {
    summary: EvidenceQualitySummary,
}

pub struct ServiceOwnedRiskRuntime {
    plugin: RiskBasedAlertingPlugin,
}

pub struct ServiceOwnedAttackContextRuntime {
    summary: AttackCoverageSummary,
}

pub struct ServiceOwnedGraphRuntime {
    stage_plugin: GraphStagePlugin,
    analytics_service: GraphAnalyticsService,
}

pub struct ServiceOwnedBaselineRuntime {
    summary: DurableBaselineSummary,
}

pub struct ServiceOwnedIncidentLinkingRuntime {
    linked_group_count: usize,
}

pub struct ServiceOwnedReportExportTraceability {
    report_ref_count: usize,
    export_ref_count: usize,
    traceability: CanonicalReportExportTraceabilitySnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phase0BClosureSummary {
    pub legacy_constructor_violations: usize,
    pub servicehost_canonical_read_model_owner: bool,
    pub desktop_canonical_owner: bool,
    pub desktop_storage_writer: bool,
    pub servicehost_mutable_writer_count: usize,
    pub disconnect_replacement_runtime_count: usize,
    pub read_only_ipc_side_effects: u32,
    pub provider_call_count: u32,
    pub provider_zero: RuntimeProviderZeroSummary,
    pub mutation_trust_state: RuntimeMutationTrustState,
    pub mutation_commands_enabled: bool,
    pub response_execution_state: String,
    pub automatic_llm_state: String,
}

impl Phase0BClosureSummary {
    pub fn complete(&self) -> bool {
        self.legacy_constructor_violations == 0
            && self.servicehost_canonical_read_model_owner
            && !self.desktop_canonical_owner
            && !self.desktop_storage_writer
            && self.servicehost_mutable_writer_count == 1
            && self.disconnect_replacement_runtime_count == 0
            && self.read_only_ipc_side_effects == 0
            && self.provider_call_count == 0
            && self.provider_zero.all_zero()
            && self.mutation_trust_state == RuntimeMutationTrustState::ImpersonationNotImplemented
            && !self.mutation_commands_enabled
            && self.response_execution_state == "unavailable"
            && self.automatic_llm_state == "forbidden"
    }
}

impl ServiceOwnedEndpointThreatRuntime {
    fn new(read: &ReadOnlyCommandState) -> CommandResult<Self> {
        Ok(Self {
            summary: get_endpoint_threat_analysis_summary(read)?,
        })
    }
}

impl ServiceOwnedFusionRuntime {
    fn new() -> Self {
        Self {
            plugin: MultiLayerSecurityFusionPlugin::new(),
        }
    }
}

impl ServiceOwnedEvidenceQualityRuntime {
    fn new(read: &ReadOnlyCommandState) -> CommandResult<Self> {
        Ok(Self {
            summary: build_evidence_quality_summary(read)?,
        })
    }
}

impl ServiceOwnedRiskRuntime {
    fn new() -> Self {
        Self {
            plugin: RiskBasedAlertingPlugin::new(),
        }
    }
}

impl ServiceOwnedAttackContextRuntime {
    fn new(read: &ReadOnlyCommandState) -> CommandResult<Self> {
        Ok(Self {
            summary: build_attack_coverage_summary(read)?,
        })
    }
}

impl ServiceOwnedGraphRuntime {
    fn new() -> Self {
        Self {
            stage_plugin: GraphStagePlugin::new(),
            analytics_service: GraphAnalyticsService::new(),
        }
    }
}

impl ServiceOwnedBaselineRuntime {
    fn new(read: &ReadOnlyCommandState) -> CommandResult<Self> {
        Ok(Self {
            summary: build_durable_baseline_summary(read)?,
        })
    }
}

impl ServiceOwnedIncidentLinkingRuntime {
    fn new(read: &ReadOnlyCommandState) -> CommandResult<Self> {
        let linked_group_count = build_durable_baseline_summary(read)?.incident_groups.len();
        Ok(Self { linked_group_count })
    }
}

impl ServiceOwnedReportExportTraceability {
    fn new(
        read: &ReadOnlyCommandState,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<Self> {
        let traceability =
            build_report_export_traceability_snapshot(read, owner_context, Vec::new())?;
        Ok(Self {
            report_ref_count: traceability.report_refs.len(),
            export_ref_count: traceability.export_refs.len(),
            traceability,
        })
    }

    fn record_snapshot_ref(&mut self, snapshot_ref: String) -> CommandResult<()> {
        let mut snapshot_refs = self.traceability.snapshot_refs.clone();
        push_bounded_ref(&mut snapshot_refs, snapshot_ref);
        self.traceability.snapshot_refs = snapshot_refs;
        self.traceability.integrity_hash =
            traceability_integrity_hash(&self.traceability_refs_for_hash());
        self.traceability
            .validate()
            .map_err(|_| init_error("report_export_traceability_invalid"))
    }

    fn record_snapshot_refs(&mut self, refs: Vec<String>) -> CommandResult<()> {
        let mut snapshot_refs = self.traceability.snapshot_refs.clone();
        for snapshot_ref in refs {
            push_bounded_ref(&mut snapshot_refs, snapshot_ref);
        }
        self.traceability.snapshot_refs = snapshot_refs;
        self.traceability.integrity_hash =
            traceability_integrity_hash(&self.traceability_refs_for_hash());
        self.traceability
            .validate()
            .map_err(|_| init_error("report_export_traceability_invalid"))
    }

    fn traceability_refs_for_hash(&self) -> Vec<String> {
        let mut refs = Vec::new();
        refs.extend(self.traceability.report_refs.clone());
        refs.extend(self.traceability.export_refs.clone());
        refs.extend(self.traceability.finding_refs.clone());
        refs.extend(self.traceability.evidence_refs.clone());
        refs.extend(self.traceability.hypothesis_refs.clone());
        refs.extend(self.traceability.risk_refs.clone());
        refs.extend(self.traceability.attack_refs.clone());
        refs.extend(self.traceability.graph_refs.clone());
        refs.extend(self.traceability.explicit_llm_story_refs.clone());
        refs.extend(self.traceability.snapshot_refs.clone());
        refs
    }
}

impl RuntimeContainer {
    pub fn owner_context(&self) -> &RuntimeOwnerContext {
        &self.owner_context
    }

    pub fn authorize_native_health_sampler(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        reason_redacted: impl Into<String>,
    ) -> CommandResult<NativePermissionActionResult> {
        self.validate_native_health_sampler_gate(owner_context)?;
        let result = self
            .app_core_orchestration
            .as_mut()
            .ok_or_else(|| provider_execution_error("app_core_orchestration_unavailable"))?
            .update_native_permission(NativePermissionActionRequest {
                capability_id: "native_health_probe".to_string(),
                action: NativePermissionAction::GrantAuthorization,
                explicit_user_action: true,
                reason_redacted: reason_redacted.into(),
            })?;
        self.refresh_native_sampler_downstream_summaries()?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(result)
    }

    pub fn apply_native_health_sampler_action(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        action: NativeSamplerRuntimeAction,
        reason_redacted: impl Into<String>,
    ) -> CommandResult<NativeSamplerRuntimeActionResult> {
        self.validate_native_health_sampler_gate(owner_context)?;
        if !matches!(
            action,
            NativeSamplerRuntimeAction::Activate
                | NativeSamplerRuntimeAction::SampleNow
                | NativeSamplerRuntimeAction::Pause
                | NativeSamplerRuntimeAction::Resume
                | NativeSamplerRuntimeAction::Stop
                | NativeSamplerRuntimeAction::Revoke
                | NativeSamplerRuntimeAction::RefreshStatus
                | NativeSamplerRuntimeAction::ReadLatestBoundedBatch
        ) {
            return Err(provider_execution_error(
                "native_health_foreground_action_not_allowed",
            ));
        }
        let result = self
            .app_core_orchestration
            .as_mut()
            .ok_or_else(|| provider_execution_error("app_core_orchestration_unavailable"))?
            .apply_native_sampler_runtime_action(NativeSamplerRuntimeActionRequest {
                sampler_id: "native_health_probe_sampler".to_string(),
                action,
                explicit_user_action: true,
                enable_interval_sampling: false,
                max_records_per_sample: 8,
                max_bytes_per_sample: 8_192,
                timeout_millis: 1_000,
                reason_redacted: reason_redacted.into(),
            })?;
        self.refresh_native_sampler_downstream_summaries()?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(result)
    }

    pub fn authorize_native_service_sampler(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        reason_redacted: impl Into<String>,
    ) -> CommandResult<NativePermissionActionResult> {
        self.validate_native_service_sampler_gate(owner_context)?;
        let result = self
            .app_core_orchestration
            .as_mut()
            .ok_or_else(|| provider_execution_error("app_core_orchestration_unavailable"))?
            .update_native_permission(NativePermissionActionRequest {
                capability_id: "service_metadata_visibility".to_string(),
                action: NativePermissionAction::GrantAuthorization,
                explicit_user_action: true,
                reason_redacted: reason_redacted.into(),
            })?;
        self.refresh_native_sampler_downstream_summaries()?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(result)
    }

    pub fn apply_native_service_sampler_action(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        action: NativeSamplerRuntimeAction,
        reason_redacted: impl Into<String>,
    ) -> CommandResult<NativeSamplerRuntimeActionResult> {
        self.validate_native_service_sampler_gate(owner_context)?;
        if !matches!(
            action,
            NativeSamplerRuntimeAction::Activate
                | NativeSamplerRuntimeAction::SampleNow
                | NativeSamplerRuntimeAction::Pause
                | NativeSamplerRuntimeAction::Resume
                | NativeSamplerRuntimeAction::Stop
                | NativeSamplerRuntimeAction::Revoke
                | NativeSamplerRuntimeAction::RefreshStatus
                | NativeSamplerRuntimeAction::ReadLatestBoundedBatch
        ) {
            return Err(provider_execution_error(
                "native_service_foreground_action_not_allowed",
            ));
        }
        let result = self
            .app_core_orchestration
            .as_mut()
            .ok_or_else(|| provider_execution_error("app_core_orchestration_unavailable"))?
            .apply_native_sampler_runtime_action(NativeSamplerRuntimeActionRequest {
                sampler_id: "service_metadata_sampler".to_string(),
                action,
                explicit_user_action: true,
                enable_interval_sampling: false,
                max_records_per_sample: 128,
                max_bytes_per_sample: 65_536,
                timeout_millis: 5_000,
                reason_redacted: reason_redacted.into(),
            })?;
        self.refresh_native_sampler_downstream_summaries()?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(result)
    }

    pub fn authorize_native_process_sampler(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        reason_redacted: impl Into<String>,
    ) -> CommandResult<NativePermissionActionResult> {
        self.validate_native_process_sampler_gate(owner_context)?;
        let result = self
            .app_core_orchestration
            .as_mut()
            .ok_or_else(|| provider_execution_error("app_core_orchestration_unavailable"))?
            .update_native_permission(NativePermissionActionRequest {
                capability_id: "process_metadata_visibility".to_string(),
                action: NativePermissionAction::GrantAuthorization,
                explicit_user_action: true,
                reason_redacted: reason_redacted.into(),
            })?;
        self.refresh_native_sampler_downstream_summaries()?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(result)
    }

    pub fn apply_native_process_sampler_action(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        action: NativeSamplerRuntimeAction,
        reason_redacted: impl Into<String>,
    ) -> CommandResult<NativeSamplerRuntimeActionResult> {
        self.validate_native_process_sampler_gate(owner_context)?;
        if !matches!(
            action,
            NativeSamplerRuntimeAction::Activate
                | NativeSamplerRuntimeAction::SampleNow
                | NativeSamplerRuntimeAction::Pause
                | NativeSamplerRuntimeAction::Resume
                | NativeSamplerRuntimeAction::Stop
                | NativeSamplerRuntimeAction::Revoke
                | NativeSamplerRuntimeAction::RefreshStatus
                | NativeSamplerRuntimeAction::ReadLatestBoundedBatch
        ) {
            return Err(provider_execution_error(
                "native_process_foreground_action_not_allowed",
            ));
        }
        let result = self
            .app_core_orchestration
            .as_mut()
            .ok_or_else(|| provider_execution_error("app_core_orchestration_unavailable"))?
            .apply_native_sampler_runtime_action(NativeSamplerRuntimeActionRequest {
                sampler_id: "process_metadata_sampler".to_string(),
                action,
                explicit_user_action: true,
                enable_interval_sampling: false,
                max_records_per_sample: 128,
                max_bytes_per_sample: 65_536,
                timeout_millis: 5_000,
                reason_redacted: reason_redacted.into(),
            })?;
        self.refresh_native_sampler_downstream_summaries()?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(result)
    }

    fn refresh_native_sampler_downstream_summaries(&mut self) -> CommandResult<()> {
        let read = self
            .app_core_orchestration
            .as_ref()
            .ok_or_else(|| provider_execution_error("app_core_orchestration_unavailable"))?
            .read_state()
            .clone();
        if let Some(runtime) = self.endpoint_threat_runtime.as_mut() {
            runtime.summary = get_endpoint_threat_analysis_summary(&read)?;
        }
        if let Some(runtime) = self.evidence_quality_runtime.as_mut() {
            runtime.summary = build_evidence_quality_summary(&read)?;
        }
        Ok(())
    }

    fn validate_native_process_sampler_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        RuntimeOwnershipGuard::validate_active_context(
            owner_context,
            owner_context.ownership_epoch,
        )
        .map_err(CoreError::from)?;
        self.ownership_lease
            .validate_epoch(owner_context.ownership_epoch)
            .map_err(CoreError::from)?;
        if self.transition_state != RuntimeTransitionState::Ready
            || self.runtime_health != RuntimeHealthState::Ready
            || self.shutdown_coordinator.shutdown_started()
        {
            return Err(provider_execution_error(
                "native_process_runtime_container_not_ready",
            ));
        }
        if self.event_bus.is_none()
            || self.pipeline_dag.is_none()
            || self.plugin_runtime.is_none()
            || self.runtime_services.is_none()
            || self.app_core_orchestration.is_none()
        {
            return Err(provider_execution_error(
                "native_process_shared_runtime_path_unavailable",
            ));
        }
        Ok(())
    }

    fn validate_native_service_sampler_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        RuntimeOwnershipGuard::validate_active_context(
            owner_context,
            owner_context.ownership_epoch,
        )
        .map_err(CoreError::from)?;
        self.ownership_lease
            .validate_epoch(owner_context.ownership_epoch)
            .map_err(CoreError::from)?;
        if self.transition_state != RuntimeTransitionState::Ready
            || self.runtime_health != RuntimeHealthState::Ready
            || self.shutdown_coordinator.shutdown_started()
        {
            return Err(provider_execution_error(
                "native_service_runtime_container_not_ready",
            ));
        }
        if self.event_bus.is_none()
            || self.pipeline_dag.is_none()
            || self.plugin_runtime.is_none()
            || self.runtime_services.is_none()
            || self.app_core_orchestration.is_none()
        {
            return Err(provider_execution_error(
                "native_service_shared_runtime_path_unavailable",
            ));
        }
        Ok(())
    }

    fn validate_native_health_sampler_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        RuntimeOwnershipGuard::validate_active_context(
            owner_context,
            owner_context.ownership_epoch,
        )
        .map_err(CoreError::from)?;
        self.ownership_lease
            .validate_epoch(owner_context.ownership_epoch)
            .map_err(CoreError::from)?;
        if self.transition_state != RuntimeTransitionState::Ready
            || self.runtime_health != RuntimeHealthState::Ready
            || self.shutdown_coordinator.shutdown_started()
        {
            return Err(provider_execution_error(
                "native_health_runtime_container_not_ready",
            ));
        }
        if self.event_bus.is_none()
            || self.pipeline_dag.is_none()
            || self.plugin_runtime.is_none()
            || self.runtime_services.is_none()
            || self.app_core_orchestration.is_none()
        {
            return Err(provider_execution_error(
                "native_health_shared_runtime_path_unavailable",
            ));
        }
        Ok(())
    }

    pub fn event_bus_count(&self) -> usize {
        usize::from(self.event_bus.is_some())
    }

    pub fn dag_count(&self) -> usize {
        usize::from(self.pipeline_dag.is_some())
    }

    pub fn plugin_runtime_count(&self) -> usize {
        usize::from(self.plugin_runtime.is_some())
    }

    pub fn capability_registry_count(&self) -> usize {
        usize::from(self.app_core_orchestration.is_some())
    }

    pub fn app_core_orchestration_count(&self) -> usize {
        usize::from(self.app_core_orchestration.is_some())
    }

    pub fn runtime_services_count(&self) -> usize {
        usize::from(self.runtime_services.is_some())
    }

    pub fn storage_writer_count(&self) -> usize {
        usize::from(self.storage_writer.is_some())
    }

    pub fn storage_ownership_status(&self) -> Option<StorageOwnershipStatus> {
        self.storage_writer.as_ref().map(StorageWriterLease::status)
    }

    pub fn storage_writer_state(&self) -> Option<StorageWriterState> {
        self.storage_ownership_status()
            .map(|status| status.writer_state)
    }

    pub fn storage_canonical_writer(&self) -> bool {
        self.storage_ownership_status()
            .is_some_and(|status| status.canonical_writer)
    }

    pub fn durable_storage_manifest(&self) -> &ServiceHostDurableStorageManifest {
        &self.durable_storage_manifest
    }

    pub fn storage_recovery_report(&self) -> Option<&ServiceHostStorageRecoveryReport> {
        self.storage_recovery_report.as_ref()
    }

    pub fn app_core_has_container_owned_runtime_context(&self) -> bool {
        self.app_core_orchestration
            .as_ref()
            .is_some_and(MutationCommandState::has_container_owned_runtime_context)
    }

    pub fn app_core_runtime_epoch(&self) -> Option<u64> {
        self.app_core_orchestration
            .as_ref()
            .and_then(MutationCommandState::runtime_ownership_epoch)
    }

    pub fn scheduler_controller_count(&self) -> usize {
        self.app_core_orchestration
            .as_ref()
            .map(MutationCommandState::native_scheduler_controller_instance_count)
            .unwrap_or_default()
    }

    pub fn scheduler_host_owner_count(&self) -> usize {
        self.app_core_orchestration
            .as_ref()
            .map(MutationCommandState::native_scheduler_host_instance_count)
            .unwrap_or_default()
    }

    pub fn sampler_runtime_count(&self) -> usize {
        self.app_core_orchestration
            .as_ref()
            .map(MutationCommandState::native_sampler_runtime_instance_count)
            .unwrap_or_default()
    }

    pub fn native_sampler_runtime_status(
        &self,
        sampler_id: &str,
    ) -> Option<NativeSamplerRuntimeStatus> {
        self.app_core_orchestration.as_ref().and_then(|state| {
            state
                .read_state()
                .native_sampler_runtime_statuses
                .iter()
                .find(|status| status.sampler_id == sampler_id)
                .cloned()
        })
    }

    pub fn security_fact_count(&self) -> usize {
        self.app_core_orchestration
            .as_ref()
            .map(|state| state.read_state().security_facts.items.len())
            .unwrap_or_default()
    }

    pub fn native_permission_runtime_count(&self) -> usize {
        self.app_core_orchestration
            .as_ref()
            .map(MutationCommandState::native_permission_runtime_instance_count)
            .unwrap_or_default()
    }

    pub fn portable_runtime_orchestration_count(&self) -> usize {
        self.app_core_orchestration
            .as_ref()
            .map(MutationCommandState::portable_runtime_orchestration_instance_count)
            .unwrap_or_default()
    }

    pub fn endpoint_threat_runtime_count(&self) -> usize {
        usize::from(self.endpoint_threat_runtime.is_some())
    }

    pub fn fusion_state_count(&self) -> usize {
        usize::from(self.fusion_runtime.is_some())
    }

    pub fn evidence_quality_state_count(&self) -> usize {
        usize::from(self.evidence_quality_runtime.is_some())
    }

    pub fn risk_state_count(&self) -> usize {
        usize::from(self.risk_runtime.is_some())
    }

    pub fn attack_context_state_count(&self) -> usize {
        usize::from(self.attack_context_runtime.is_some())
    }

    pub fn graph_state_count(&self) -> usize {
        usize::from(self.graph_runtime.is_some())
    }

    pub fn baseline_state_count(&self) -> usize {
        usize::from(self.baseline_runtime.is_some())
    }

    pub fn incident_linking_state_count(&self) -> usize {
        usize::from(self.incident_linking_runtime.is_some())
    }

    pub fn report_export_traceability_state_count(&self) -> usize {
        usize::from(self.report_export_traceability.is_some())
    }

    pub fn read_model_store_count(&self) -> usize {
        usize::from(self.canonical_read_model_store.is_some())
    }

    pub fn canonical_read_model_snapshot(&self) -> CommandResult<CanonicalReadModelSnapshot> {
        if let Some(store) = self.canonical_read_model_store.as_ref() {
            return Ok(store.snapshot());
        }
        build_canonical_read_model_snapshot(
            &self.owner_context,
            1,
            Vec::new(),
            true,
            Some("coherent_snapshot_unavailable"),
            ReadModelSnapshotFreshness::Unavailable,
        )
    }

    pub fn canonical_read_model_generation_count(&self) -> usize {
        self.canonical_read_model_store
            .as_ref()
            .map(ServiceHostCanonicalReadModelStore::generation_count)
            .unwrap_or_default()
    }

    pub fn canonical_read_model_current_generation(&self) -> Option<u64> {
        self.canonical_read_model_store
            .as_ref()
            .map(ServiceHostCanonicalReadModelStore::current_generation)
    }

    pub fn provider_call_count(&self) -> u32 {
        self.provider_controller.provider_call_count()
    }

    pub fn provider_controller_status(&self) -> Option<&NetworkProviderControllerStatus> {
        self.provider_controller.status()
    }

    pub fn network_provider_statuses(&self) -> &[NetworkProviderStatus] {
        self.provider_controller.provider_statuses()
    }

    pub fn network_provider_status(
        &self,
        kind: NetworkProviderKind,
    ) -> Option<&NetworkProviderStatus> {
        self.provider_controller.provider_status(kind)
    }

    pub fn network_visibility_summary(&self) -> Option<&NetworkVisibilitySummary> {
        self.provider_controller.visibility_summary()
    }

    pub fn network_fallback_plan(&self) -> Option<&NetworkFallbackPlan> {
        self.provider_controller.fallback_plan()
    }

    pub fn network_provider_zero_counters(&self) -> Option<&NetworkProviderZeroCounters> {
        self.provider_controller.provider_zero_counters()
    }

    pub fn latest_ip_helper_batch(&self) -> Option<&NativeIpHelperMetadataBatch> {
        self.provider_controller.latest_ip_helper_batch()
    }

    pub fn latest_rdp_operational_batch(&self) -> Option<&WindowsAuthRemoteObservationBatch> {
        self.provider_controller.latest_rdp_operational_batch()
    }

    pub fn latest_smb_operational_batch(&self) -> Option<&WindowsAuthRemoteObservationBatch> {
        self.provider_controller.latest_smb_operational_batch()
    }

    pub fn latest_ssh_operational_batch(&self) -> Option<&WindowsAuthRemoteObservationBatch> {
        self.provider_controller.latest_ssh_operational_batch()
    }

    pub fn etw_lifecycle_status(&self) -> Option<&EtwLifecycleStatus> {
        self.etw_lifecycle_runtime
            .as_ref()
            .map(ServiceOwnedEtwLifecycleRuntime::status)
    }

    pub fn dns_sensing_lifecycle_status(&self) -> Option<&EtwLifecycleStatus> {
        self.dns_sensing_lifecycle_runtime
            .as_ref()
            .map(ServiceOwnedDnsSensingLifecycleRuntime::status)
    }

    pub fn auth_remote_sensing_lifecycle_status(&self) -> Option<&EtwLifecycleStatus> {
        self.auth_remote_sensing_lifecycle_runtime
            .as_ref()
            .map(ServiceOwnedAuthRemoteSensingLifecycleRuntime::status)
    }

    pub fn rdp_operational_sensing_lifecycle_status(&self) -> Option<&EtwLifecycleStatus> {
        self.rdp_operational_sensing_lifecycle_runtime
            .as_ref()
            .map(ServiceOwnedAuthRemoteSensingLifecycleRuntime::status)
    }

    pub fn smb_operational_sensing_lifecycle_status(&self) -> Option<&EtwLifecycleStatus> {
        self.smb_operational_sensing_lifecycle_runtime
            .as_ref()
            .map(ServiceOwnedAuthRemoteSensingLifecycleRuntime::status)
    }

    pub fn ssh_operational_sensing_lifecycle_status(&self) -> Option<&EtwLifecycleStatus> {
        self.ssh_operational_sensing_lifecycle_runtime
            .as_ref()
            .map(ServiceOwnedAuthRemoteSensingLifecycleRuntime::status)
    }

    pub fn etw_mutation_capability_state(
        &self,
    ) -> sentinel_contracts::MutationCapabilityStateCategory {
        use sentinel_contracts::MutationCapabilityStateCategory as State;
        match self
            .etw_lifecycle_status()
            .map(|status| status.lifecycle_state)
        {
            Some(EtwLifecycleState::Inactive) => State::Inactive,
            Some(EtwLifecycleState::Active) => State::Active,
            Some(EtwLifecycleState::Paused) => State::Paused,
            Some(EtwLifecycleState::Stopped) => State::Stopped,
            Some(EtwLifecycleState::Activating)
            | Some(EtwLifecycleState::Pausing)
            | Some(EtwLifecycleState::Resuming)
            | Some(EtwLifecycleState::Stopping) => State::Ready,
            Some(EtwLifecycleState::Degraded | EtwLifecycleState::Failed) => State::Degraded,
            None => State::Unavailable,
        }
    }

    pub fn auth_remote_mutation_capability_state(
        &self,
    ) -> sentinel_contracts::MutationCapabilityStateCategory {
        use sentinel_contracts::MutationCapabilityStateCategory as State;
        match self
            .auth_remote_sensing_lifecycle_status()
            .map(|status| status.lifecycle_state)
        {
            Some(EtwLifecycleState::Inactive) => State::Inactive,
            Some(EtwLifecycleState::Active) => State::Active,
            Some(EtwLifecycleState::Paused) => State::Paused,
            Some(EtwLifecycleState::Stopped) => State::Stopped,
            Some(EtwLifecycleState::Activating)
            | Some(EtwLifecycleState::Pausing)
            | Some(EtwLifecycleState::Resuming)
            | Some(EtwLifecycleState::Stopping) => State::Ready,
            Some(EtwLifecycleState::Degraded | EtwLifecycleState::Failed) => State::Degraded,
            None => State::Unavailable,
        }
    }

    pub fn activate_etw_provider(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_etw_lifecycle_gate(owner_context, "activate_etw")?;
        let fallback_state = self.etw_fallback_state();
        let lifecycle = self
            .etw_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("etw_lifecycle_runtime_unavailable"))?
            .activate(owner_context, authorization_refs, fallback_state)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_etw_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn pause_etw_provider(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_etw_lifecycle_gate(owner_context, "pause_etw")?;
        let fallback_state = self.etw_fallback_state();
        let lifecycle = self
            .etw_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("etw_lifecycle_runtime_unavailable"))?
            .pause(owner_context, authorization_refs, fallback_state)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_etw_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn resume_etw_provider(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_etw_lifecycle_gate(owner_context, "resume_etw")?;
        let fallback_state = self.etw_fallback_state();
        let lifecycle = self
            .etw_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("etw_lifecycle_runtime_unavailable"))?
            .resume(owner_context, authorization_refs, fallback_state)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_etw_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn stop_etw_provider(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_etw_lifecycle_gate(owner_context, "stop_etw")?;
        let fallback_state = self.etw_fallback_state();
        let lifecycle = self
            .etw_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("etw_lifecycle_runtime_unavailable"))?
            .stop(owner_context, authorization_refs, fallback_state)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_etw_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn activate_dns_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_dns_sensing_lifecycle_gate(owner_context, "activate_dns_sensing")?;
        let lifecycle = self
            .dns_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("dns_sensing_runtime_unavailable"))?
            .activate(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_dns_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn pause_dns_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_dns_sensing_lifecycle_gate(owner_context, "pause_dns_sensing")?;
        let lifecycle = self
            .dns_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("dns_sensing_runtime_unavailable"))?
            .pause(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_dns_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn resume_dns_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_dns_sensing_lifecycle_gate(owner_context, "resume_dns_sensing")?;
        let lifecycle = self
            .dns_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("dns_sensing_runtime_unavailable"))?
            .resume(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_dns_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn stop_dns_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_dns_sensing_lifecycle_gate(owner_context, "stop_dns_sensing")?;
        let lifecycle = self
            .dns_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("dns_sensing_runtime_unavailable"))?
            .stop(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_dns_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn activate_auth_remote_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_auth_remote_sensing_lifecycle_gate(
            owner_context,
            "activate_auth_remote_sensing",
        )?;
        let lifecycle = self
            .auth_remote_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("auth_remote_sensing_runtime_unavailable"))?
            .activate(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_auth_remote_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn pause_auth_remote_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_auth_remote_sensing_lifecycle_gate(
            owner_context,
            "pause_auth_remote_sensing",
        )?;
        let lifecycle = self
            .auth_remote_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("auth_remote_sensing_runtime_unavailable"))?
            .pause(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_auth_remote_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn resume_auth_remote_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_auth_remote_sensing_lifecycle_gate(
            owner_context,
            "resume_auth_remote_sensing",
        )?;
        let lifecycle = self
            .auth_remote_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("auth_remote_sensing_runtime_unavailable"))?
            .resume(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_auth_remote_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn stop_auth_remote_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_auth_remote_sensing_lifecycle_gate(
            owner_context,
            "stop_auth_remote_sensing",
        )?;
        let lifecycle = self
            .auth_remote_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("auth_remote_sensing_runtime_unavailable"))?
            .stop(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_auth_remote_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn activate_rdp_operational_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_rdp_operational_sensing_lifecycle_gate(
            owner_context,
            "activate_rdp_operational_sensing",
        )?;
        let lifecycle = self
            .rdp_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("rdp_operational_sensing_runtime_unavailable"))?
            .activate(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_rdp_operational_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn pause_rdp_operational_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_rdp_operational_sensing_lifecycle_gate(
            owner_context,
            "pause_rdp_operational_sensing",
        )?;
        let lifecycle = self
            .rdp_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("rdp_operational_sensing_runtime_unavailable"))?
            .pause(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_rdp_operational_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn resume_rdp_operational_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_rdp_operational_sensing_lifecycle_gate(
            owner_context,
            "resume_rdp_operational_sensing",
        )?;
        let lifecycle = self
            .rdp_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("rdp_operational_sensing_runtime_unavailable"))?
            .resume(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_rdp_operational_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn stop_rdp_operational_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_rdp_operational_sensing_lifecycle_gate(
            owner_context,
            "stop_rdp_operational_sensing",
        )?;
        let lifecycle = self
            .rdp_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("rdp_operational_sensing_runtime_unavailable"))?
            .stop(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_rdp_operational_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn activate_smb_operational_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_smb_operational_sensing_lifecycle_gate(
            owner_context,
            "activate_smb_operational_sensing",
        )?;
        let lifecycle = self
            .smb_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("smb_operational_sensing_runtime_unavailable"))?
            .activate(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_smb_operational_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn pause_smb_operational_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_smb_operational_sensing_lifecycle_gate(
            owner_context,
            "pause_smb_operational_sensing",
        )?;
        let lifecycle = self
            .smb_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("smb_operational_sensing_runtime_unavailable"))?
            .pause(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_smb_operational_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn resume_smb_operational_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_smb_operational_sensing_lifecycle_gate(
            owner_context,
            "resume_smb_operational_sensing",
        )?;
        let lifecycle = self
            .smb_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("smb_operational_sensing_runtime_unavailable"))?
            .resume(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_smb_operational_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn stop_smb_operational_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_smb_operational_sensing_lifecycle_gate(
            owner_context,
            "stop_smb_operational_sensing",
        )?;
        let lifecycle = self
            .smb_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("smb_operational_sensing_runtime_unavailable"))?
            .stop(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_smb_operational_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn activate_ssh_operational_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_ssh_operational_sensing_lifecycle_gate(
            owner_context,
            "activate_ssh_operational_sensing",
        )?;
        let lifecycle = self
            .ssh_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("ssh_operational_sensing_runtime_unavailable"))?
            .activate(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_ssh_operational_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn pause_ssh_operational_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_ssh_operational_sensing_lifecycle_gate(
            owner_context,
            "pause_ssh_operational_sensing",
        )?;
        let lifecycle = self
            .ssh_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("ssh_operational_sensing_runtime_unavailable"))?
            .pause(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_ssh_operational_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn resume_ssh_operational_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_ssh_operational_sensing_lifecycle_gate(
            owner_context,
            "resume_ssh_operational_sensing",
        )?;
        let lifecycle = self
            .ssh_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("ssh_operational_sensing_runtime_unavailable"))?
            .resume(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_ssh_operational_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn stop_ssh_operational_sensing(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_ssh_operational_sensing_lifecycle_gate(
            owner_context,
            "stop_ssh_operational_sensing",
        )?;
        let lifecycle = self
            .ssh_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("ssh_operational_sensing_runtime_unavailable"))?
            .stop(owner_context, authorization_refs)
            .map_err(provider_execution_error)?;
        let status = self
            .provider_controller
            .record_ssh_operational_sensing_lifecycle(owner_context, lifecycle)?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn activate_ip_helper_provider(
        &mut self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_ip_helper_lifecycle_gate(owner_context, "activate_ip_helper")?;
        let (status, already_active) = self
            .provider_controller
            .record_ip_helper_activation(owner_context)?;
        self.publish_container_payload(
            NETWORK_PROVIDER_STATUS,
            &status
                .provider(NetworkProviderKind::IpHelper)
                .ok_or_else(|| provider_execution_error("ip_helper_status_unavailable"))?,
            "bounded ip helper activation status",
        )?;
        self.publish_container_payload(
            NETWORK_VISIBILITY_STATUS,
            &status.visibility_summary,
            "bounded ip helper activation visibility",
        )?;
        self.publish_container_payload(
            AUDIT_NETWORK_PROVIDER_EXECUTION,
            &json!({
                "audit_ref": if already_active {
                    "ip_helper_activation_already_satisfied"
                } else {
                    "ip_helper_activation_completed"
                },
                "provider_ref": "network_provider_ip_helper",
                "result": if already_active {
                    "already_satisfied"
                } else {
                    "execution_completed"
                },
                "redaction_status": "redacted"
            }),
            "bounded ip helper activation audit",
        )?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn stop_ip_helper_provider(
        &mut self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_ip_helper_lifecycle_gate(owner_context, "stop_ip_helper")?;
        let (status, already_stopped) = self
            .provider_controller
            .record_ip_helper_stop(owner_context)?;
        self.ip_helper_next_due_monotonic_millis = None;
        self.ip_helper_schedule_wake_pending = false;
        self.ip_helper_scheduled_retry_count = 0;
        self.ip_helper_execution_active = false;
        self.publish_container_payload(
            NETWORK_PROVIDER_STATUS,
            &status
                .provider(NetworkProviderKind::IpHelper)
                .ok_or_else(|| provider_execution_error("ip_helper_status_unavailable"))?,
            "bounded ip helper stop status",
        )?;
        self.publish_container_payload(
            NETWORK_VISIBILITY_STATUS,
            &status.visibility_summary,
            "bounded ip helper stop visibility",
        )?;
        self.publish_container_payload(
            AUDIT_NETWORK_PROVIDER_EXECUTION,
            &json!({
                "audit_ref": if already_stopped {
                    "ip_helper_stop_already_satisfied"
                } else {
                    "ip_helper_stop_completed"
                },
                "provider_ref": "network_provider_ip_helper",
                "result": if already_stopped {
                    "already_satisfied"
                } else {
                    "execution_completed"
                },
                "redaction_status": "redacted"
            }),
            "bounded ip helper stop audit",
        )?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(status)
    }

    pub fn configure_ip_helper_schedule(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        config: IpHelperScheduleConfig,
        authorization_refs: Vec<String>,
        policy_id: String,
        policy_version: SchemaVersion,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_ip_helper_lifecycle_gate(owner_context, "configure_ip_helper_schedule")?;
        let status = self
            .provider_controller
            .record_ip_helper_schedule_configured(
                owner_context,
                config,
                authorization_refs,
                policy_id,
                policy_version,
            )?;
        self.publish_ip_helper_schedule_status(
            owner_context,
            &status,
            IP_HELPER_SCHEDULE_CONFIGURED,
        )?;
        Ok(status)
    }

    pub fn enable_ip_helper_schedule(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        schedule_lease_ref: String,
        authorization_refs: Vec<String>,
        policy_id: String,
        policy_version: SchemaVersion,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_ip_helper_lifecycle_gate(owner_context, "enable_ip_helper_schedule")?;
        self.require_ip_helper_active_for_schedule()?;
        self.require_configured_ip_helper_schedule()?;
        let status = self.provider_controller.record_ip_helper_schedule_enabled(
            owner_context,
            schedule_lease_ref,
            authorization_refs,
            policy_id,
            policy_version,
        )?;
        self.publish_ip_helper_schedule_status(owner_context, &status, IP_HELPER_SCHEDULE_ENABLED)?;
        let status = self
            .provider_controller
            .record_ip_helper_scheduler_host_started(owner_context)?;
        self.ip_helper_next_due_monotonic_millis = Some(0);
        self.ip_helper_schedule_wake_pending = true;
        self.publish_ip_helper_schedule_status(
            owner_context,
            &status,
            IP_HELPER_SCHEDULER_HOST_STARTED,
        )?;
        Ok(status)
    }

    pub fn pause_ip_helper_schedule(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
        policy_id: String,
        policy_version: SchemaVersion,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_ip_helper_lifecycle_gate(owner_context, "pause_ip_helper_schedule")?;
        let schedule = self
            .provider_controller
            .ip_helper_schedule_status()
            .ok_or_else(|| provider_execution_error("ip_helper_schedule_unavailable"))?;
        if schedule.schedule_state != IpHelperScheduleState::ConfiguredEnabled {
            return Err(provider_execution_error("ip_helper_schedule_not_enabled"));
        }
        let status = self.provider_controller.record_ip_helper_schedule_paused(
            owner_context,
            authorization_refs,
            policy_id,
            policy_version,
        )?;
        self.ip_helper_next_due_monotonic_millis = None;
        self.ip_helper_schedule_wake_pending = false;
        self.ip_helper_scheduled_retry_count = 0;
        self.publish_ip_helper_schedule_status(owner_context, &status, IP_HELPER_SCHEDULE_PAUSED)?;
        let status = self
            .provider_controller
            .record_ip_helper_scheduler_host_stopped(
                owner_context,
                IP_HELPER_SCHEDULER_HOST_STOPPED,
                "schedule_paused",
            )?;
        self.publish_ip_helper_schedule_status(
            owner_context,
            &status,
            IP_HELPER_SCHEDULER_HOST_STOPPED,
        )?;
        Ok(status)
    }

    pub fn resume_ip_helper_schedule(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        schedule_lease_ref: String,
        authorization_refs: Vec<String>,
        policy_id: String,
        policy_version: SchemaVersion,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_ip_helper_lifecycle_gate(owner_context, "resume_ip_helper_schedule")?;
        self.require_ip_helper_active_for_schedule()?;
        let schedule = self
            .provider_controller
            .ip_helper_schedule_status()
            .ok_or_else(|| provider_execution_error("ip_helper_schedule_unavailable"))?;
        if schedule.schedule_state != IpHelperScheduleState::Paused {
            return Err(provider_execution_error("ip_helper_schedule_not_paused"));
        }
        let status = self.provider_controller.record_ip_helper_schedule_resumed(
            owner_context,
            schedule_lease_ref,
            authorization_refs,
            policy_id,
            policy_version,
        )?;
        self.publish_ip_helper_schedule_status(owner_context, &status, IP_HELPER_SCHEDULE_RESUMED)?;
        let status = self
            .provider_controller
            .record_ip_helper_scheduler_host_started(owner_context)?;
        self.ip_helper_next_due_monotonic_millis = Some(0);
        self.ip_helper_schedule_wake_pending = true;
        self.publish_ip_helper_schedule_status(
            owner_context,
            &status,
            IP_HELPER_SCHEDULER_HOST_STARTED,
        )?;
        Ok(status)
    }

    pub fn disable_ip_helper_schedule(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        authorization_refs: Vec<String>,
        policy_id: String,
        policy_version: SchemaVersion,
    ) -> CommandResult<NetworkProviderControllerStatus> {
        self.validate_ip_helper_lifecycle_gate(owner_context, "disable_ip_helper_schedule")?;
        let status = self
            .provider_controller
            .record_ip_helper_schedule_disabled(
                owner_context,
                authorization_refs,
                policy_id,
                policy_version,
                "schedule_disabled",
            )?;
        self.publish_ip_helper_schedule_status(
            owner_context,
            &status,
            IP_HELPER_SCHEDULE_DISABLED,
        )?;
        self.ip_helper_next_due_monotonic_millis = None;
        self.ip_helper_schedule_wake_pending = false;
        self.ip_helper_scheduled_retry_count = 0;
        let status = self
            .provider_controller
            .record_ip_helper_scheduler_host_stopped(
                owner_context,
                IP_HELPER_SCHEDULER_HOST_STOPPED,
                "schedule_disabled",
            )?;
        self.publish_ip_helper_schedule_status(
            owner_context,
            &status,
            IP_HELPER_SCHEDULER_HOST_STOPPED,
        )?;
        Ok(status)
    }

    pub fn invalidate_ip_helper_schedule_for_session_end(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        audit_event: &'static str,
        reason: &'static str,
    ) -> CommandResult<Option<NetworkProviderControllerStatus>> {
        self.validate_ip_helper_lifecycle_gate(owner_context, "invalidate_ip_helper_schedule")?;
        let status = self
            .provider_controller
            .record_ip_helper_schedule_invalidated(owner_context, audit_event, reason)?;
        if let Some(status) = &status {
            self.publish_ip_helper_schedule_status(owner_context, status, audit_event)?;
        }
        self.ip_helper_next_due_monotonic_millis = None;
        self.ip_helper_schedule_wake_pending = false;
        self.ip_helper_scheduled_retry_count = 0;
        if status.is_some() {
            let stopped = self
                .provider_controller
                .record_ip_helper_scheduler_host_stopped(owner_context, audit_event, reason)?;
            self.publish_ip_helper_schedule_status(owner_context, &stopped, audit_event)?;
        }
        Ok(status)
    }

    pub fn execute_ip_helper_servicehost_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        request: IpHelperHandoffRequest,
    ) -> CommandResult<IpHelperHandoffResult> {
        if self.ip_helper_execution_active {
            self.ip_helper_scheduled_overlap_skip_count = self
                .ip_helper_scheduled_overlap_skip_count
                .saturating_add(1);
            return Err(provider_execution_error("ip_helper_execution_gate_busy"));
        }
        self.ip_helper_execution_active = true;
        let result = self.execute_ip_helper_servicehost_handoff_inner(owner_context, request);
        self.ip_helper_execution_active = false;
        result
    }

    fn execute_ip_helper_servicehost_handoff_inner(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        request: IpHelperHandoffRequest,
    ) -> CommandResult<IpHelperHandoffResult> {
        request.validate()?;
        self.validate_ip_helper_execution_gate(owner_context, &request)?;

        let adapter = IpHelperSnapshotAdapter::new();
        let metadata = adapter.adapter_metadata();
        metadata
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        if metadata.provider_kind != NetworkProviderKind::IpHelper {
            return Err(provider_execution_error("ip_helper_adapter_required"));
        }

        let provider_request = BoundedProviderRequest {
            provider_kind: NetworkProviderKind::IpHelper,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            max_records: request.max_records,
            max_bytes: request.max_bytes,
            timeout_ms: request.timeout_ms,
            cancellation_ref: Some("ip_helper_handoff_bounded_cancel_ref".to_string()),
            provenance_ref: "servicehost_provider_controller".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        provider_request
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;

        let snapshot = adapter
            .read_bounded(provider_request)
            .map_err(|error| provider_execution_error(error.to_string()))?;
        validate_ip_helper_snapshot_privacy(&snapshot)?;
        let mut batch = ip_helper_snapshot_to_native_batch(&snapshot, &request)?;
        batch.validate().map_err(provider_execution_error)?;

        validate_native_network_dag_route(self)?;
        let producer = PluginId::new_v4();
        let trace_context = TraceContext::new_root();
        let input_event = runtime_handoff_event(
            &producer,
            NATIVE_IP_HELPER_METADATA,
            &batch,
            sentinel_contracts::NATIVE_NETWORK_SCHEMA_VERSION,
            quality_score(0.7),
            &trace_context,
        )?;
        self.publish_container_envelope(
            NATIVE_IP_HELPER_METADATA,
            input_event.clone(),
            "bounded ip helper metadata",
        )?;

        let fact_events = self.run_native_network_fact_runtime(input_event)?;
        let mut facts = Vec::new();
        for event in fact_events {
            if event.event_type.as_str() != NATIVE_CONNECTION_CATEGORY_FACT {
                return Err(provider_execution_error(
                    "native_network_fact_runtime_emitted_undeclared_topic",
                ));
            }
            let fact = serde_json::from_value::<SecurityFact>(event.payload.clone())
                .map_err(provider_execution_error)?;
            if fact.layer != sentinel_contracts::SecurityLayer::AuthorizedNativeNetwork
                || fact.process_category.is_some()
                || fact.parent_process_category.is_some()
                || fact.execution_context_category.is_some()
            {
                return Err(provider_execution_error(
                    "native_network_fact_runtime_emitted_forbidden_fact",
                ));
            }
            self.publish_container_envelope(
                NATIVE_CONNECTION_CATEGORY_FACT,
                event,
                "bounded native connection category fact",
            )?;
            facts.push(fact);
        }

        let fact_refs = facts
            .iter()
            .map(|fact| fact.fact_id.clone())
            .collect::<Vec<_>>();
        let emitted_topic_count = 1_u32.saturating_add(facts.len() as u32).saturating_add(3);
        let status = self.provider_controller.record_ip_helper_handoff(
            owner_context,
            batch.clone(),
            fact_refs,
            emitted_topic_count,
            request.policy,
            request.reason_ref.clone(),
        )?;
        batch = self
            .provider_controller
            .latest_ip_helper_batch()
            .cloned()
            .ok_or_else(|| provider_execution_error("latest_ip_helper_batch_unavailable"))?;

        self.publish_container_payload(
            NETWORK_PROVIDER_STATUS,
            &status
                .provider(NetworkProviderKind::IpHelper)
                .ok_or_else(|| provider_execution_error("ip_helper_status_unavailable"))?,
            "bounded ip helper provider status",
        )?;
        self.publish_container_payload(
            NETWORK_VISIBILITY_STATUS,
            &status.visibility_summary,
            "bounded network visibility status",
        )?;
        self.publish_container_payload(
            AUDIT_NETWORK_PROVIDER_EXECUTION,
            &json!({
                "audit_ref": batch.audit_refs.first().cloned().unwrap_or_else(|| "audit_network_provider_execution_ref".to_string()),
                "provider_ref": batch.provider_ref,
                "batch_ref": batch.batch_ref,
                "policy": request.policy.reason(),
                "redaction_status": "redacted"
            }),
            "bounded network provider execution audit",
        )?;

        if let Some(orchestration) = self.app_core_orchestration.as_mut() {
            let mut read = orchestration.read_state().clone();
            read.security_facts.items.extend(facts.clone());
            orchestration.replace_read_state_preserving_runtime(read)?;
        }
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;

        Ok(IpHelperHandoffResult {
            batch,
            fact_count: facts.len(),
            emitted_topics: vec![
                NATIVE_IP_HELPER_METADATA.to_string(),
                NATIVE_CONNECTION_CATEGORY_FACT.to_string(),
                NETWORK_PROVIDER_STATUS.to_string(),
                NETWORK_VISIBILITY_STATUS.to_string(),
                AUDIT_NETWORK_PROVIDER_EXECUTION.to_string(),
            ],
            provider_status: status,
        })
    }

    pub fn execute_etw_network_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        batch: EtwNormalizedNetworkBatch,
    ) -> CommandResult<EtwNetworkHandoffResult> {
        self.validate_etw_handoff_gate(owner_context)?;
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;

        validate_native_network_dag_route(self)?;
        let producer = PluginId::new_v4();
        let trace_context = TraceContext::new_root();
        let input_event = runtime_handoff_event(
            &producer,
            NATIVE_ETW_NETWORK_METADATA,
            &batch,
            sentinel_contracts::ETW_NORMALIZATION_SCHEMA_VERSION,
            quality_score(0.65),
            &trace_context,
        )?;
        self.publish_container_envelope(
            NATIVE_ETW_NETWORK_METADATA,
            input_event.clone(),
            "bounded etw network metadata",
        )?;

        let fact_events = self.run_native_network_fact_runtime(input_event)?;
        let mut facts = Vec::new();
        for event in fact_events {
            if event.event_type.as_str() != NATIVE_CONNECTION_CATEGORY_FACT {
                return Err(provider_execution_error(
                    "native_network_fact_runtime_emitted_undeclared_topic",
                ));
            }
            let fact = serde_json::from_value::<SecurityFact>(event.payload.clone())
                .map_err(provider_execution_error)?;
            if fact.layer != sentinel_contracts::SecurityLayer::AuthorizedNativeNetwork
                || fact.process_category.is_some()
                || fact.parent_process_category.is_some()
                || fact.execution_context_category.is_some()
            {
                return Err(provider_execution_error(
                    "native_network_fact_runtime_emitted_forbidden_fact",
                ));
            }
            self.publish_container_envelope(
                NATIVE_CONNECTION_CATEGORY_FACT,
                event,
                "bounded etw network category fact",
            )?;
            facts.push(fact);
        }

        let fact_refs = facts
            .iter()
            .map(|fact| fact.fact_id.clone())
            .collect::<Vec<_>>();
        let emitted_topic_count = 1_u32.saturating_add(facts.len() as u32).saturating_add(3);
        let status = self.provider_controller.record_etw_handoff(
            owner_context,
            batch,
            fact_refs.clone(),
            emitted_topic_count,
        )?;
        let batch = self
            .provider_controller
            .latest_etw_batch()
            .cloned()
            .ok_or_else(|| provider_execution_error("latest_etw_batch_unavailable"))?;

        if let Some(traceability) = self.report_export_traceability.as_mut() {
            let mut traceability_refs = vec![
                batch.batch_ref.clone(),
                batch.allowlist_ref.clone(),
                status.controller_ref.clone(),
                status.visibility_summary.visibility_ref.clone(),
                status.fallback_plan.fallback_plan_ref.clone(),
                "etw_product_surface_ref".to_string(),
                "etw_report_export_traceability_ref".to_string(),
            ];
            traceability_refs.extend(fact_refs.iter().map(ToString::to_string));
            traceability_refs.extend(batch.provenance_refs.clone());
            traceability_refs.extend(status.audit_summary.audit_refs.clone());
            traceability.record_snapshot_refs(traceability_refs)?;
        }

        self.publish_container_payload(
            NETWORK_PROVIDER_STATUS,
            &status
                .provider(NetworkProviderKind::EtwNetwork)
                .ok_or_else(|| provider_execution_error("etw_status_unavailable"))?,
            "bounded etw provider status",
        )?;
        self.publish_container_payload(
            NETWORK_VISIBILITY_STATUS,
            &status.visibility_summary,
            "bounded network visibility status",
        )?;
        self.publish_container_payload(
            AUDIT_NETWORK_PROVIDER_EXECUTION,
            &json!({
                "audit_ref": "audit_etw_runtime_handoff_ref",
                "provider_ref": "network_provider_etw_network",
                "batch_ref": batch.batch_ref,
                "policy": "servicehost_etw_runtime_handoff",
                "redaction_status": "redacted"
            }),
            "bounded etw provider execution audit",
        )?;

        if let Some(orchestration) = self.app_core_orchestration.as_mut() {
            let mut read = orchestration.read_state().clone();
            read.security_facts.items.extend(facts.clone());
            orchestration.replace_read_state_preserving_runtime(read)?;
        }
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;

        Ok(EtwNetworkHandoffResult {
            batch,
            fact_count: facts.len(),
            emitted_topics: vec![
                NATIVE_ETW_NETWORK_METADATA.to_string(),
                NATIVE_CONNECTION_CATEGORY_FACT.to_string(),
                NETWORK_PROVIDER_STATUS.to_string(),
                NETWORK_VISIBILITY_STATUS.to_string(),
                AUDIT_NETWORK_PROVIDER_EXECUTION.to_string(),
            ],
            provider_status: status,
        })
    }

    pub fn pump_etw_live_batches(&mut self) -> CommandResult<EtwLivePumpResult> {
        let owner_context = self.owner_context.clone();
        let batches = self
            .etw_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("etw_lifecycle_runtime_unavailable"))?
            .drain_live_batches(
                &owner_context,
                sentinel_infrastructure::ETW_MAX_DRAIN_BATCHES,
            )
            .map_err(provider_execution_error)?;
        let mut result = EtwLivePumpResult {
            normalized_batches: batches.len().min(u32::MAX as usize) as u32,
            ..EtwLivePumpResult::default()
        };
        for batch in batches {
            let handoff = self.execute_etw_network_handoff(&owner_context, batch)?;
            result.published_batches = result.published_batches.saturating_add(1);
            result.eventbus_publications = result
                .eventbus_publications
                .saturating_add(handoff.emitted_topics.len().min(u32::MAX as usize) as u32);
            result.downstream_facts = result
                .downstream_facts
                .saturating_add(handoff.fact_count.min(u32::MAX as usize) as u32);
        }
        let lifecycle = self
            .etw_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("etw_lifecycle_runtime_unavailable"))?
            .record_live_handoff(
                &owner_context,
                result.published_batches,
                result.eventbus_publications,
                result.downstream_facts,
            )
            .map_err(provider_execution_error)?;
        result.raw_events = lifecycle.raw_event_count;
        result.normalized_events = lifecycle.normalized_event_count;
        result.dropped_events = lifecycle.dropped_event_count;
        if result.normalized_batches > 0 {
            self.provider_controller
                .record_etw_lifecycle(&owner_context, lifecycle)?;
            let _ = self.publish_canonical_read_model_snapshot(&owner_context)?;
        }
        Ok(result)
    }

    pub fn etw_live_pump_wait_millis(&self) -> Option<u64> {
        self.etw_lifecycle_status().and_then(|status| {
            (status.lifecycle_state == EtwLifecycleState::Active
                && status.consumer_worker_active
                && status.collection_started)
                .then_some(50)
        })
    }

    pub fn execute_dns_sensing_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        batch: WindowsDnsObservationBatch,
    ) -> CommandResult<DnsSensingHandoffResult> {
        self.validate_dns_sensing_handoff_gate(owner_context)?;
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        validate_dns_sensing_dag_route(self)?;
        let producer = PluginId::new_v4();
        let trace_context = TraceContext::new_root();
        let mut input_events = Vec::with_capacity(batch.records.len());
        for record in &batch.records {
            let event = runtime_handoff_event(
                &producer,
                NETWORK_DNS_OBSERVATION,
                record,
                sentinel_contracts::WINDOWS_DNS_SENSING_SCHEMA_VERSION,
                quality_score(0.62),
                &trace_context,
            )?;
            self.publish_container_envelope(
                NETWORK_DNS_OBSERVATION,
                event.clone(),
                "bounded windows dns observation",
            )?;
            input_events.push(event);
        }
        let detector_consumed = input_events.len().min(u32::MAX as usize) as u32;
        let output_events = self.run_dns_security_runtime(input_events)?;
        let mut findings = Vec::<Finding>::new();
        let mut downstream_outputs = 0_u32;
        for event in output_events {
            match event.event_type.as_str() {
                SECURITY_FINDING => {
                    findings.push(
                        serde_json::from_value::<Finding>(event.payload.clone())
                            .map_err(provider_execution_error)?,
                    );
                }
                SECURITY_EVIDENCE => {
                    let _ = serde_json::from_value::<EvidenceItem>(event.payload.clone())
                        .map_err(provider_execution_error)?;
                }
                "security.risk_hint" => {
                    let _ = serde_json::from_value::<RiskHint>(event.payload.clone())
                        .map_err(provider_execution_error)?;
                }
                GRAPH_HINT => {
                    let _ = serde_json::from_value::<GraphHint>(event.payload.clone())
                        .map_err(provider_execution_error)?;
                }
                _ => {
                    return Err(provider_execution_error(
                        "dns_security_runtime_emitted_undeclared_topic",
                    ))
                }
            }
            let topic = event.event_type.as_str().to_string();
            self.publish_container_envelope(&topic, event, "bounded dns security output")?;
            downstream_outputs = downstream_outputs.saturating_add(1);
        }
        if !findings.is_empty() {
            if let Some(orchestration) = self.app_core_orchestration.as_mut() {
                let mut read = orchestration.read_state().clone();
                read.findings.items.extend(findings);
                orchestration.replace_read_state_preserving_runtime(read)?;
            }
        }
        let eventbus_publications = detector_consumed.saturating_add(downstream_outputs);
        let status = self.provider_controller.record_dns_sensing_handoff(
            owner_context,
            batch.clone(),
            eventbus_publications,
            1,
            detector_consumed,
        )?;
        self.publish_container_payload(
            NETWORK_PROVIDER_STATUS,
            &status
                .provider(NetworkProviderKind::WindowsDns)
                .ok_or_else(|| provider_execution_error("windows_dns_status_unavailable"))?,
            "bounded windows dns provider status",
        )?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(DnsSensingHandoffResult {
            batch,
            eventbus_publications,
            detector_invocations: 1,
            detector_consumed,
            downstream_outputs,
            provider_status: status,
        })
    }

    pub fn pump_dns_sensing_live_batches(&mut self) -> CommandResult<DnsSensingLivePumpResult> {
        let owner_context = self.owner_context.clone();
        let batches = self
            .dns_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("dns_sensing_runtime_unavailable"))?
            .drain_live_batches(
                &owner_context,
                sentinel_infrastructure::WINDOWS_DNS_MAX_DRAIN_BATCHES,
            )
            .map_err(provider_execution_error)?;
        let mut result = DnsSensingLivePumpResult {
            normalized_batches: batches.len().min(u32::MAX as usize) as u32,
            ..DnsSensingLivePumpResult::default()
        };
        for batch in batches {
            let handoff = self.execute_dns_sensing_handoff(&owner_context, batch)?;
            result.published_batches = result.published_batches.saturating_add(1);
            result.eventbus_publications = result
                .eventbus_publications
                .saturating_add(handoff.eventbus_publications);
            result.detector_invocations = result
                .detector_invocations
                .saturating_add(handoff.detector_invocations);
            result.detector_consumed = result
                .detector_consumed
                .saturating_add(handoff.detector_consumed);
            result.downstream_outputs = result
                .downstream_outputs
                .saturating_add(handoff.downstream_outputs);
        }
        let lifecycle = self
            .dns_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("dns_sensing_runtime_unavailable"))?
            .record_live_handoff(
                &owner_context,
                result.published_batches,
                result.eventbus_publications,
                result.downstream_outputs,
            )
            .map_err(provider_execution_error)?;
        result.raw_events = lifecycle.raw_event_count;
        result.normalized_events = lifecycle.normalized_event_count;
        result.dropped_events = lifecycle.dropped_event_count;
        if result.normalized_batches > 0 {
            self.provider_controller
                .record_dns_sensing_lifecycle(&owner_context, lifecycle)?;
            let _ = self.publish_canonical_read_model_snapshot(&owner_context)?;
        }
        Ok(result)
    }

    pub fn dns_sensing_live_pump_wait_millis(&self) -> Option<u64> {
        self.dns_sensing_lifecycle_status().and_then(|status| {
            (status.lifecycle_state == EtwLifecycleState::Active
                && status.consumer_worker_active
                && status.collection_started)
                .then_some(50)
        })
    }

    pub fn execute_auth_remote_sensing_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        mut batch: WindowsAuthRemoteObservationBatch,
    ) -> CommandResult<AuthRemoteSensingHandoffResult> {
        self.validate_auth_remote_sensing_handoff_gate(owner_context)?;
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        validate_auth_remote_sensing_dag_route(self)?;

        let producer = PluginId::new_v4();
        let trace_context = TraceContext::new_root();
        let mut auth_events = Vec::with_capacity(batch.observations.len());
        for observation in &batch.observations {
            let metadata = portable_auth_metadata_from_windows_auth(observation)?;
            let event = runtime_handoff_event(
                &producer,
                IDENTITY_AUTH_METADATA,
                &metadata,
                sentinel_contracts::WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
                metadata.quality_score.clone(),
                &trace_context,
            )?;
            self.publish_container_envelope(
                IDENTITY_AUTH_METADATA,
                event.clone(),
                "bounded windows auth metadata",
            )?;
            auth_events.push(event);
        }
        let auth_consumed = auth_events.len().min(u32::MAX as usize) as u32;
        let auth_detector_invocations: u32 = if auth_events.is_empty() { 0 } else { 1 };
        let mut eventbus_publications = auth_consumed;
        let mut outputs = 0_u32;
        let mut findings = Vec::<Finding>::new();
        if !auth_events.is_empty() {
            for event in self.run_auth_identity_analysis_runtime(auth_events.clone())? {
                match event.event_type.as_str() {
                    SECURITY_FINDING => {
                        findings.push(
                            serde_json::from_value::<Finding>(event.payload.clone())
                                .map_err(provider_execution_error)?,
                        );
                    }
                    SECURITY_EVIDENCE => {
                        let _ = serde_json::from_value::<EvidenceItem>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    "security.risk_hint" => {
                        let _ = serde_json::from_value::<RiskHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    GRAPH_HINT => {
                        let _ = serde_json::from_value::<GraphHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    _ => {
                        return Err(provider_execution_error(
                            "auth_identity_runtime_emitted_undeclared_topic",
                        ))
                    }
                }
                let topic = event.event_type.as_str().to_string();
                self.publish_container_envelope(&topic, event, "bounded auth identity output")?;
                outputs = outputs.saturating_add(1);
                eventbus_publications = eventbus_publications.saturating_add(1);
            }
        }

        let mut fusion_events = Vec::new();
        if !auth_events.is_empty() {
            let provenance = PortableCaptureProvenance::new(
                PortableCaptureInputSourceType::ImportedAuthSecurityLog,
                PortableCaptureRecordCounts {
                    auth_metadata_records: auth_events.len().min(u32::MAX as usize) as u32,
                    ..PortableCaptureRecordCounts::default()
                },
                RedactionStatus::Redacted,
            );
            fusion_events.push(runtime_handoff_event(
                &producer,
                SECURITY_FUSION_CONTEXT,
                &provenance,
                SchemaVersion::new(1, 0, 0),
                quality_score(0.72),
                &trace_context,
            )?);
            fusion_events.extend(auth_events.clone());
        }

        let mut facts = Vec::<SecurityFact>::new();
        if !fusion_events.is_empty() {
            for event in self.run_multi_layer_fusion_runtime(fusion_events)? {
                match event.event_type.as_str() {
                    SECURITY_FACT => {
                        let fact = serde_json::from_value::<SecurityFact>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                        if fact.layer != sentinel_contracts::SecurityLayer::AuthIdentity {
                            return Err(provider_execution_error(
                                "auth_remote_fusion_emitted_unexpected_fact_layer",
                            ));
                        }
                        facts.push(fact);
                    }
                    SECURITY_HYPOTHESIS
                    | SECURITY_FUSION_SUMMARY
                    | SECURITY_FINDING
                    | SECURITY_EVIDENCE
                    | "security.risk_hint"
                    | GRAPH_HINT => {}
                    _ => {
                        return Err(provider_execution_error(
                            "auth_remote_fusion_emitted_undeclared_topic",
                        ))
                    }
                }
                let topic = event.event_type.as_str().to_string();
                self.publish_container_envelope(
                    &topic,
                    event,
                    "bounded auth remote fusion output",
                )?;
                outputs = outputs.saturating_add(1);
                eventbus_publications = eventbus_publications.saturating_add(1);
            }
        }

        if !findings.is_empty() || !facts.is_empty() {
            if let Some(orchestration) = self.app_core_orchestration.as_mut() {
                let mut read = orchestration.read_state().clone();
                read.findings.items.extend(findings);
                read.security_facts.items.extend(facts.clone());
                orchestration.replace_read_state_preserving_runtime(read)?;
            }
        }

        let downstream_facts = facts.len().min(u32::MAX as usize) as u32;
        batch.counters.published_batches = 1;
        batch.counters.eventbus_publications = eventbus_publications;
        batch.counters.dag_dispatches = auth_detector_invocations.saturating_add(1);
        batch.counters.auth_detector_invocations = auth_detector_invocations;
        batch.counters.auth_consumed = auth_consumed;
        batch.counters.remote_admin_invocations = 0;
        batch.counters.remote_admin_consumed = 0;
        batch.counters.lateral_invocations = 0;
        batch.counters.lateral_consumed = 0;
        batch.counters.outputs = outputs;
        batch.counters.downstream_facts = downstream_facts;
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;

        let status = self
            .provider_controller
            .record_auth_remote_sensing_handoff(
                owner_context,
                batch.clone(),
                AuthRemoteSensingDispatchCounters {
                    eventbus_publications,
                    dag_dispatches: batch.counters.dag_dispatches,
                    auth_detector_invocations,
                    auth_consumed,
                    remote_admin_invocations: 0,
                    remote_admin_consumed: 0,
                    lateral_invocations: 0,
                    lateral_consumed: 0,
                    downstream_facts,
                },
            )?;
        self.publish_container_payload(
            NETWORK_PROVIDER_STATUS,
            &status
                .provider(NetworkProviderKind::WindowsAuthRemote)
                .ok_or_else(|| {
                    provider_execution_error("windows_auth_remote_status_unavailable")
                })?,
            "bounded windows auth remote provider status",
        )?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;

        Ok(AuthRemoteSensingHandoffResult {
            batch,
            published_auth_metadata: auth_consumed,
            published_batches: 1,
            eventbus_publications,
            dag_dispatches: auth_detector_invocations.saturating_add(1),
            auth_detector_invocations,
            auth_consumed,
            remote_admin_invocations: 0,
            remote_admin_consumed: 0,
            lateral_invocations: 0,
            lateral_consumed: 0,
            outputs,
            downstream_facts,
            provider_status: status,
        })
    }

    pub fn execute_rdp_operational_sensing_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        mut batch: WindowsAuthRemoteObservationBatch,
    ) -> CommandResult<RdpOperationalSensingHandoffResult> {
        self.validate_rdp_operational_sensing_handoff_gate(owner_context)?;
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        if batch.observations.iter().any(|observation| {
            observation.remote_protocol_category != Some(WindowsRemoteProtocolCategory::Rdp)
        }) {
            return Err(provider_execution_error(
                "rdp_operational_batch_contains_non_rdp_observation",
            ));
        }
        validate_rdp_operational_sensing_dag_route(self)?;

        let producer = PluginId::new_v4();
        let trace_context = TraceContext::new_root();
        let rdp_batch_event = runtime_handoff_event(
            &producer,
            IDENTITY_RDP_OPERATIONAL_METADATA,
            &batch,
            sentinel_contracts::WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
            quality_score(0.68),
            &trace_context,
        )?;
        self.publish_container_envelope(
            IDENTITY_RDP_OPERATIONAL_METADATA,
            rdp_batch_event,
            "bounded windows rdp operational metadata",
        )?;

        let mut auth_events = Vec::with_capacity(batch.observations.len());
        for observation in &batch.observations {
            let metadata = portable_auth_metadata_from_windows_auth(observation)?;
            let event = runtime_handoff_event(
                &producer,
                IDENTITY_AUTH_METADATA,
                &metadata,
                sentinel_contracts::WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
                metadata.quality_score.clone(),
                &trace_context,
            )?;
            self.publish_container_envelope(
                IDENTITY_AUTH_METADATA,
                event.clone(),
                "bounded windows rdp auth metadata",
            )?;
            auth_events.push(event);
        }
        let auth_consumed = auth_events.len().min(u32::MAX as usize) as u32;
        let auth_detector_invocations: u32 = if auth_events.is_empty() { 0 } else { 1 };
        let remote_admin_invocations: u32 = if auth_events.is_empty() { 0 } else { 1 };
        let remote_admin_consumed = auth_consumed;
        let mut eventbus_publications = auth_consumed.saturating_add(1);
        let mut outputs = 0_u32;
        let mut findings = Vec::<Finding>::new();

        if !auth_events.is_empty() {
            for event in self.run_auth_identity_analysis_runtime(auth_events.clone())? {
                match event.event_type.as_str() {
                    SECURITY_FINDING => {
                        findings.push(
                            serde_json::from_value::<Finding>(event.payload.clone())
                                .map_err(provider_execution_error)?,
                        );
                    }
                    SECURITY_EVIDENCE => {
                        let _ = serde_json::from_value::<EvidenceItem>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    "security.risk_hint" => {
                        let _ = serde_json::from_value::<RiskHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    GRAPH_HINT => {
                        let _ = serde_json::from_value::<GraphHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    _ => {
                        return Err(provider_execution_error(
                            "rdp_auth_identity_runtime_emitted_undeclared_topic",
                        ))
                    }
                }
                let topic = event.event_type.as_str().to_string();
                self.publish_container_envelope(&topic, event, "bounded rdp auth identity output")?;
                outputs = outputs.saturating_add(1);
                eventbus_publications = eventbus_publications.saturating_add(1);
            }

            for event in self.run_remote_admin_runtime(auth_events.clone())? {
                match event.event_type.as_str() {
                    SECURITY_FINDING => {
                        findings.push(
                            serde_json::from_value::<Finding>(event.payload.clone())
                                .map_err(provider_execution_error)?,
                        );
                    }
                    SECURITY_EVIDENCE => {
                        let _ = serde_json::from_value::<EvidenceItem>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    "security.risk_hint" => {
                        let _ = serde_json::from_value::<RiskHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    GRAPH_HINT => {
                        let _ = serde_json::from_value::<GraphHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    _ => {
                        return Err(provider_execution_error(
                            "rdp_remote_admin_runtime_emitted_undeclared_topic",
                        ))
                    }
                }
                let topic = event.event_type.as_str().to_string();
                self.publish_container_envelope(&topic, event, "bounded rdp remote admin output")?;
                outputs = outputs.saturating_add(1);
                eventbus_publications = eventbus_publications.saturating_add(1);
            }
        }

        let mut fusion_events = Vec::new();
        if !auth_events.is_empty() {
            let provenance = PortableCaptureProvenance::new(
                PortableCaptureInputSourceType::ImportedAuthSecurityLog,
                PortableCaptureRecordCounts {
                    auth_metadata_records: auth_events.len().min(u32::MAX as usize) as u32,
                    ..PortableCaptureRecordCounts::default()
                },
                RedactionStatus::Redacted,
            );
            fusion_events.push(runtime_handoff_event(
                &producer,
                SECURITY_FUSION_CONTEXT,
                &provenance,
                SchemaVersion::new(1, 0, 0),
                quality_score(0.68),
                &trace_context,
            )?);
            fusion_events.extend(auth_events.clone());
        }

        let mut facts = Vec::<SecurityFact>::new();
        if !fusion_events.is_empty() {
            for event in self.run_multi_layer_fusion_runtime(fusion_events)? {
                match event.event_type.as_str() {
                    SECURITY_FACT => {
                        let fact = serde_json::from_value::<SecurityFact>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                        if fact.layer != sentinel_contracts::SecurityLayer::AuthIdentity {
                            return Err(provider_execution_error(
                                "rdp_operational_fusion_emitted_unexpected_fact_layer",
                            ));
                        }
                        facts.push(fact);
                    }
                    SECURITY_HYPOTHESIS
                    | SECURITY_FUSION_SUMMARY
                    | SECURITY_FINDING
                    | SECURITY_EVIDENCE
                    | "security.risk_hint"
                    | GRAPH_HINT => {}
                    _ => {
                        return Err(provider_execution_error(
                            "rdp_operational_fusion_emitted_undeclared_topic",
                        ))
                    }
                }
                let topic = event.event_type.as_str().to_string();
                self.publish_container_envelope(
                    &topic,
                    event,
                    "bounded rdp operational fusion output",
                )?;
                outputs = outputs.saturating_add(1);
                eventbus_publications = eventbus_publications.saturating_add(1);
            }
        }

        if !findings.is_empty() || !facts.is_empty() {
            if let Some(orchestration) = self.app_core_orchestration.as_mut() {
                let mut read = orchestration.read_state().clone();
                read.findings.items.extend(findings);
                read.security_facts.items.extend(facts.clone());
                orchestration.replace_read_state_preserving_runtime(read)?;
            }
        }

        let downstream_facts = facts.len().min(u32::MAX as usize) as u32;
        batch.counters.published_batches = 1;
        batch.counters.eventbus_publications = eventbus_publications;
        batch.counters.dag_dispatches = auth_detector_invocations
            .saturating_add(remote_admin_invocations)
            .saturating_add(1);
        batch.counters.auth_detector_invocations = auth_detector_invocations;
        batch.counters.auth_consumed = auth_consumed;
        batch.counters.remote_admin_invocations = remote_admin_invocations;
        batch.counters.remote_admin_consumed = remote_admin_consumed;
        batch.counters.lateral_invocations = 0;
        batch.counters.lateral_consumed = 0;
        batch.counters.outputs = outputs;
        batch.counters.downstream_facts = downstream_facts;
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;

        let status = self
            .provider_controller
            .record_rdp_operational_sensing_handoff(
                owner_context,
                batch.clone(),
                AuthRemoteSensingDispatchCounters {
                    eventbus_publications,
                    dag_dispatches: batch.counters.dag_dispatches,
                    auth_detector_invocations,
                    auth_consumed,
                    remote_admin_invocations,
                    remote_admin_consumed,
                    lateral_invocations: 0,
                    lateral_consumed: 0,
                    downstream_facts,
                },
            )?;
        self.publish_container_payload(
            NETWORK_PROVIDER_STATUS,
            &status
                .provider(NetworkProviderKind::WindowsRdpOperational)
                .ok_or_else(|| {
                    provider_execution_error("windows_rdp_operational_status_unavailable")
                })?,
            "bounded windows rdp operational provider status",
        )?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;

        Ok(RdpOperationalSensingHandoffResult {
            batch,
            published_rdp_metadata: 1,
            published_auth_metadata: auth_consumed,
            published_batches: 1,
            eventbus_publications,
            dag_dispatches: auth_detector_invocations
                .saturating_add(remote_admin_invocations)
                .saturating_add(1),
            auth_detector_invocations,
            auth_consumed,
            remote_admin_invocations,
            remote_admin_consumed,
            lateral_invocations: 0,
            lateral_consumed: 0,
            outputs,
            downstream_facts,
            provider_status: status,
        })
    }

    pub fn execute_smb_operational_sensing_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        mut batch: WindowsAuthRemoteObservationBatch,
    ) -> CommandResult<SmbOperationalSensingHandoffResult> {
        self.validate_smb_operational_sensing_handoff_gate(owner_context)?;
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        if batch.observations.iter().any(|observation| {
            observation.remote_protocol_category != Some(WindowsRemoteProtocolCategory::Smb)
        }) {
            return Err(provider_execution_error(
                "smb_operational_batch_contains_non_smb_observation",
            ));
        }
        validate_smb_operational_sensing_dag_route(self)?;

        let producer = PluginId::new_v4();
        let trace_context = TraceContext::new_root();
        let smb_batch_event = runtime_handoff_event(
            &producer,
            IDENTITY_SMB_OPERATIONAL_METADATA,
            &batch,
            sentinel_contracts::WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
            quality_score(0.66),
            &trace_context,
        )?;
        self.publish_container_envelope(
            IDENTITY_SMB_OPERATIONAL_METADATA,
            smb_batch_event.clone(),
            "bounded windows smb operational metadata",
        )?;

        let mut auth_events = Vec::with_capacity(batch.observations.len());
        for observation in batch
            .observations
            .iter()
            .filter(|observation| smb_schema_has_auth_context(observation.schema_category))
        {
            let metadata = portable_auth_metadata_from_windows_auth(observation)?;
            let event = runtime_handoff_event(
                &producer,
                IDENTITY_AUTH_METADATA,
                &metadata,
                sentinel_contracts::WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
                metadata.quality_score.clone(),
                &trace_context,
            )?;
            self.publish_container_envelope(
                IDENTITY_AUTH_METADATA,
                event.clone(),
                "bounded windows smb auth metadata",
            )?;
            auth_events.push(event);
        }

        let auth_consumed = auth_events.len().min(u32::MAX as usize) as u32;
        let auth_detector_invocations: u32 = if auth_events.is_empty() { 0 } else { 1 };
        let remote_admin_invocations: u32 = if batch.observations.is_empty() { 0 } else { 1 };
        let remote_admin_consumed = batch.observations.len().min(u32::MAX as usize) as u32;
        let mut eventbus_publications = auth_consumed.saturating_add(1);
        let mut outputs = 0_u32;
        let mut findings = Vec::<Finding>::new();

        if !auth_events.is_empty() {
            for event in self.run_auth_identity_analysis_runtime(auth_events.clone())? {
                match event.event_type.as_str() {
                    SECURITY_FINDING => {
                        findings.push(
                            serde_json::from_value::<Finding>(event.payload.clone())
                                .map_err(provider_execution_error)?,
                        );
                    }
                    SECURITY_EVIDENCE => {
                        let _ = serde_json::from_value::<EvidenceItem>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    "security.risk_hint" => {
                        let _ = serde_json::from_value::<RiskHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    GRAPH_HINT => {
                        let _ = serde_json::from_value::<GraphHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    _ => {
                        return Err(provider_execution_error(
                            "smb_auth_identity_runtime_emitted_undeclared_topic",
                        ))
                    }
                }
                let topic = event.event_type.as_str().to_string();
                self.publish_container_envelope(&topic, event, "bounded smb auth identity output")?;
                outputs = outputs.saturating_add(1);
                eventbus_publications = eventbus_publications.saturating_add(1);
            }
        }

        if remote_admin_invocations > 0 {
            for event in self.run_remote_admin_runtime(vec![smb_batch_event.clone()])? {
                match event.event_type.as_str() {
                    SECURITY_FINDING => {
                        findings.push(
                            serde_json::from_value::<Finding>(event.payload.clone())
                                .map_err(provider_execution_error)?,
                        );
                    }
                    SECURITY_EVIDENCE => {
                        let _ = serde_json::from_value::<EvidenceItem>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    "security.risk_hint" => {
                        let _ = serde_json::from_value::<RiskHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    GRAPH_HINT => {
                        let _ = serde_json::from_value::<GraphHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    _ => {
                        return Err(provider_execution_error(
                            "smb_remote_admin_runtime_emitted_undeclared_topic",
                        ))
                    }
                }
                let topic = event.event_type.as_str().to_string();
                self.publish_container_envelope(&topic, event, "bounded smb remote admin output")?;
                outputs = outputs.saturating_add(1);
                eventbus_publications = eventbus_publications.saturating_add(1);
            }
        }

        let mut fusion_events = Vec::new();
        if !auth_events.is_empty() {
            let provenance = PortableCaptureProvenance::new(
                PortableCaptureInputSourceType::ImportedAuthSecurityLog,
                PortableCaptureRecordCounts {
                    auth_metadata_records: auth_events.len().min(u32::MAX as usize) as u32,
                    ..PortableCaptureRecordCounts::default()
                },
                RedactionStatus::Redacted,
            );
            fusion_events.push(runtime_handoff_event(
                &producer,
                SECURITY_FUSION_CONTEXT,
                &provenance,
                SchemaVersion::new(1, 0, 0),
                quality_score(0.66),
                &trace_context,
            )?);
            fusion_events.extend(auth_events.clone());
        }

        let fusion_invocations: u32 = if fusion_events.is_empty() { 0 } else { 1 };
        let mut facts = Vec::<SecurityFact>::new();
        if !fusion_events.is_empty() {
            for event in self.run_multi_layer_fusion_runtime(fusion_events)? {
                match event.event_type.as_str() {
                    SECURITY_FACT => {
                        let fact = serde_json::from_value::<SecurityFact>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                        if fact.layer != sentinel_contracts::SecurityLayer::AuthIdentity {
                            return Err(provider_execution_error(
                                "smb_operational_fusion_emitted_unexpected_fact_layer",
                            ));
                        }
                        facts.push(fact);
                    }
                    SECURITY_HYPOTHESIS
                    | SECURITY_FUSION_SUMMARY
                    | SECURITY_FINDING
                    | SECURITY_EVIDENCE
                    | "security.risk_hint"
                    | GRAPH_HINT => {}
                    _ => {
                        return Err(provider_execution_error(
                            "smb_operational_fusion_emitted_undeclared_topic",
                        ))
                    }
                }
                let topic = event.event_type.as_str().to_string();
                self.publish_container_envelope(
                    &topic,
                    event,
                    "bounded smb operational fusion output",
                )?;
                outputs = outputs.saturating_add(1);
                eventbus_publications = eventbus_publications.saturating_add(1);
            }
        }

        if !findings.is_empty() || !facts.is_empty() {
            if let Some(orchestration) = self.app_core_orchestration.as_mut() {
                let mut read = orchestration.read_state().clone();
                read.findings.items.extend(findings);
                read.security_facts.items.extend(facts.clone());
                orchestration.replace_read_state_preserving_runtime(read)?;
            }
        }

        let downstream_facts = facts.len().min(u32::MAX as usize) as u32;
        let dag_dispatches = auth_detector_invocations
            .saturating_add(remote_admin_invocations)
            .saturating_add(fusion_invocations);
        batch.counters.published_batches = 1;
        batch.counters.eventbus_publications = eventbus_publications;
        batch.counters.dag_dispatches = dag_dispatches;
        batch.counters.auth_detector_invocations = auth_detector_invocations;
        batch.counters.auth_consumed = auth_consumed;
        batch.counters.remote_admin_invocations = remote_admin_invocations;
        batch.counters.remote_admin_consumed = remote_admin_consumed;
        batch.counters.lateral_invocations = 0;
        batch.counters.lateral_consumed = 0;
        batch.counters.outputs = outputs;
        batch.counters.downstream_facts = downstream_facts;
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;

        let status = self
            .provider_controller
            .record_smb_operational_sensing_handoff(
                owner_context,
                batch.clone(),
                AuthRemoteSensingDispatchCounters {
                    eventbus_publications,
                    dag_dispatches,
                    auth_detector_invocations,
                    auth_consumed,
                    remote_admin_invocations,
                    remote_admin_consumed,
                    lateral_invocations: 0,
                    lateral_consumed: 0,
                    downstream_facts,
                },
            )?;
        self.publish_container_payload(
            NETWORK_PROVIDER_STATUS,
            &status
                .provider(NetworkProviderKind::WindowsSmbOperational)
                .ok_or_else(|| {
                    provider_execution_error("windows_smb_operational_status_unavailable")
                })?,
            "bounded windows smb operational provider status",
        )?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;

        Ok(SmbOperationalSensingHandoffResult {
            batch,
            published_smb_metadata: 1,
            published_auth_metadata: auth_consumed,
            published_batches: 1,
            eventbus_publications,
            dag_dispatches,
            auth_detector_invocations,
            auth_consumed,
            remote_admin_invocations,
            remote_admin_consumed,
            lateral_invocations: 0,
            lateral_consumed: 0,
            outputs,
            downstream_facts,
            provider_status: status,
        })
    }

    pub fn execute_ssh_operational_sensing_handoff(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        mut batch: WindowsAuthRemoteObservationBatch,
    ) -> CommandResult<SshOperationalSensingHandoffResult> {
        self.validate_ssh_operational_sensing_handoff_gate(owner_context)?;
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;
        if batch.observations.iter().any(|observation| {
            observation.remote_protocol_category != Some(WindowsRemoteProtocolCategory::Ssh)
        }) {
            return Err(provider_execution_error(
                "ssh_operational_batch_contains_non_ssh_observation",
            ));
        }
        validate_ssh_operational_sensing_dag_route(self)?;

        let producer = PluginId::new_v4();
        let trace_context = TraceContext::new_root();
        let ssh_batch_event = runtime_handoff_event(
            &producer,
            IDENTITY_SSH_OPERATIONAL_METADATA,
            &batch,
            sentinel_contracts::WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
            quality_score(0.63),
            &trace_context,
        )?;
        self.publish_container_envelope(
            IDENTITY_SSH_OPERATIONAL_METADATA,
            ssh_batch_event.clone(),
            "bounded windows ssh operational metadata",
        )?;

        let mut auth_events = Vec::with_capacity(batch.observations.len());
        for observation in batch
            .observations
            .iter()
            .filter(|observation| ssh_schema_has_auth_context(observation.schema_category))
        {
            let metadata = portable_auth_metadata_from_windows_auth(observation)?;
            let event = runtime_handoff_event(
                &producer,
                IDENTITY_AUTH_METADATA,
                &metadata,
                sentinel_contracts::WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
                metadata.quality_score.clone(),
                &trace_context,
            )?;
            self.publish_container_envelope(
                IDENTITY_AUTH_METADATA,
                event.clone(),
                "bounded windows ssh auth metadata",
            )?;
            auth_events.push(event);
        }

        let auth_consumed = auth_events.len().min(u32::MAX as usize) as u32;
        let auth_detector_invocations: u32 = if auth_events.is_empty() { 0 } else { 1 };
        let remote_admin_invocations: u32 = if batch.observations.is_empty() { 0 } else { 1 };
        let remote_admin_consumed = batch.observations.len().min(u32::MAX as usize) as u32;
        let mut eventbus_publications = auth_consumed.saturating_add(1);
        let mut outputs = 0_u32;
        let mut findings = Vec::<Finding>::new();

        if !auth_events.is_empty() {
            for event in self.run_auth_identity_analysis_runtime(auth_events.clone())? {
                match event.event_type.as_str() {
                    SECURITY_FINDING => {
                        findings.push(
                            serde_json::from_value::<Finding>(event.payload.clone())
                                .map_err(provider_execution_error)?,
                        );
                    }
                    SECURITY_EVIDENCE => {
                        let _ = serde_json::from_value::<EvidenceItem>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    "security.risk_hint" => {
                        let _ = serde_json::from_value::<RiskHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    GRAPH_HINT => {
                        let _ = serde_json::from_value::<GraphHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    _ => {
                        return Err(provider_execution_error(
                            "ssh_auth_identity_runtime_emitted_undeclared_topic",
                        ))
                    }
                }
                let topic = event.event_type.as_str().to_string();
                self.publish_container_envelope(&topic, event, "bounded ssh auth identity output")?;
                outputs = outputs.saturating_add(1);
                eventbus_publications = eventbus_publications.saturating_add(1);
            }
        }

        if remote_admin_invocations > 0 {
            for event in self.run_remote_admin_runtime(vec![ssh_batch_event.clone()])? {
                match event.event_type.as_str() {
                    SECURITY_FINDING => {
                        findings.push(
                            serde_json::from_value::<Finding>(event.payload.clone())
                                .map_err(provider_execution_error)?,
                        );
                    }
                    SECURITY_EVIDENCE => {
                        let _ = serde_json::from_value::<EvidenceItem>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    "security.risk_hint" => {
                        let _ = serde_json::from_value::<RiskHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    GRAPH_HINT => {
                        let _ = serde_json::from_value::<GraphHint>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                    }
                    _ => {
                        return Err(provider_execution_error(
                            "ssh_remote_admin_runtime_emitted_undeclared_topic",
                        ))
                    }
                }
                let topic = event.event_type.as_str().to_string();
                self.publish_container_envelope(&topic, event, "bounded ssh remote admin output")?;
                outputs = outputs.saturating_add(1);
                eventbus_publications = eventbus_publications.saturating_add(1);
            }
        }

        let mut fusion_events = Vec::new();
        if !auth_events.is_empty() {
            let provenance = PortableCaptureProvenance::new(
                PortableCaptureInputSourceType::ImportedAuthSecurityLog,
                PortableCaptureRecordCounts {
                    auth_metadata_records: auth_events.len().min(u32::MAX as usize) as u32,
                    ..PortableCaptureRecordCounts::default()
                },
                RedactionStatus::Redacted,
            );
            fusion_events.push(runtime_handoff_event(
                &producer,
                SECURITY_FUSION_CONTEXT,
                &provenance,
                SchemaVersion::new(1, 0, 0),
                quality_score(0.63),
                &trace_context,
            )?);
            fusion_events.extend(auth_events.clone());
        }

        let fusion_invocations: u32 = if fusion_events.is_empty() { 0 } else { 1 };
        let mut facts = Vec::<SecurityFact>::new();
        if !fusion_events.is_empty() {
            for event in self.run_multi_layer_fusion_runtime(fusion_events)? {
                match event.event_type.as_str() {
                    SECURITY_FACT => {
                        let fact = serde_json::from_value::<SecurityFact>(event.payload.clone())
                            .map_err(provider_execution_error)?;
                        if fact.layer != sentinel_contracts::SecurityLayer::AuthIdentity {
                            return Err(provider_execution_error(
                                "ssh_operational_fusion_emitted_unexpected_fact_layer",
                            ));
                        }
                        facts.push(fact);
                    }
                    SECURITY_HYPOTHESIS
                    | SECURITY_FUSION_SUMMARY
                    | SECURITY_FINDING
                    | SECURITY_EVIDENCE
                    | "security.risk_hint"
                    | GRAPH_HINT => {}
                    _ => {
                        return Err(provider_execution_error(
                            "ssh_operational_fusion_emitted_undeclared_topic",
                        ))
                    }
                }
                let topic = event.event_type.as_str().to_string();
                self.publish_container_envelope(
                    &topic,
                    event,
                    "bounded ssh operational fusion output",
                )?;
                outputs = outputs.saturating_add(1);
                eventbus_publications = eventbus_publications.saturating_add(1);
            }
        }

        if !findings.is_empty() || !facts.is_empty() {
            if let Some(orchestration) = self.app_core_orchestration.as_mut() {
                let mut read = orchestration.read_state().clone();
                read.findings.items.extend(findings);
                read.security_facts.items.extend(facts.clone());
                orchestration.replace_read_state_preserving_runtime(read)?;
            }
        }

        let downstream_facts = facts.len().min(u32::MAX as usize) as u32;
        let dag_dispatches = auth_detector_invocations
            .saturating_add(remote_admin_invocations)
            .saturating_add(fusion_invocations);
        batch.counters.published_batches = 1;
        batch.counters.eventbus_publications = eventbus_publications;
        batch.counters.dag_dispatches = dag_dispatches;
        batch.counters.auth_detector_invocations = auth_detector_invocations;
        batch.counters.auth_consumed = auth_consumed;
        batch.counters.remote_admin_invocations = remote_admin_invocations;
        batch.counters.remote_admin_consumed = remote_admin_consumed;
        batch.counters.lateral_invocations = 0;
        batch.counters.lateral_consumed = 0;
        batch.counters.outputs = outputs;
        batch.counters.downstream_facts = downstream_facts;
        batch
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))?;

        let status = self
            .provider_controller
            .record_ssh_operational_sensing_handoff(
                owner_context,
                batch.clone(),
                AuthRemoteSensingDispatchCounters {
                    eventbus_publications,
                    dag_dispatches,
                    auth_detector_invocations,
                    auth_consumed,
                    remote_admin_invocations,
                    remote_admin_consumed,
                    lateral_invocations: 0,
                    lateral_consumed: 0,
                    downstream_facts,
                },
            )?;
        self.publish_container_payload(
            NETWORK_PROVIDER_STATUS,
            &status
                .provider(NetworkProviderKind::WindowsSshOperational)
                .ok_or_else(|| {
                    provider_execution_error("windows_ssh_operational_status_unavailable")
                })?,
            "bounded windows ssh operational provider status",
        )?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;

        Ok(SshOperationalSensingHandoffResult {
            batch,
            published_ssh_metadata: 1,
            published_auth_metadata: auth_consumed,
            published_batches: 1,
            eventbus_publications,
            dag_dispatches,
            auth_detector_invocations,
            auth_consumed,
            remote_admin_invocations,
            remote_admin_consumed,
            lateral_invocations: 0,
            lateral_consumed: 0,
            outputs,
            downstream_facts,
            provider_status: status,
        })
    }

    pub fn pump_auth_remote_sensing_live_batches(
        &mut self,
    ) -> CommandResult<AuthRemoteSensingLivePumpResult> {
        let owner_context = self.owner_context.clone();
        let batches = self
            .auth_remote_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("auth_remote_sensing_runtime_unavailable"))?
            .drain_live_batches(
                &owner_context,
                sentinel_infrastructure::WINDOWS_AUTH_REMOTE_MAX_DRAIN_BATCHES,
            )
            .map_err(provider_execution_error)?;
        let mut result = AuthRemoteSensingLivePumpResult {
            normalized_batches: batches.len().min(u32::MAX as usize) as u32,
            ..AuthRemoteSensingLivePumpResult::default()
        };
        for batch in batches {
            let handoff = self.execute_auth_remote_sensing_handoff(&owner_context, batch)?;
            result.published_batches = result.published_batches.saturating_add(1);
            result.eventbus_publications = result
                .eventbus_publications
                .saturating_add(handoff.eventbus_publications);
            result.dag_dispatches = result.dag_dispatches.saturating_add(handoff.dag_dispatches);
            result.auth_detector_invocations = result
                .auth_detector_invocations
                .saturating_add(handoff.auth_detector_invocations);
            result.auth_consumed = result.auth_consumed.saturating_add(handoff.auth_consumed);
            result.remote_admin_invocations = result
                .remote_admin_invocations
                .saturating_add(handoff.remote_admin_invocations);
            result.remote_admin_consumed = result
                .remote_admin_consumed
                .saturating_add(handoff.remote_admin_consumed);
            result.lateral_invocations = result
                .lateral_invocations
                .saturating_add(handoff.lateral_invocations);
            result.lateral_consumed = result
                .lateral_consumed
                .saturating_add(handoff.lateral_consumed);
            result.outputs = result.outputs.saturating_add(handoff.outputs);
            result.downstream_facts = result
                .downstream_facts
                .saturating_add(handoff.downstream_facts);
        }
        let lifecycle = self
            .auth_remote_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("auth_remote_sensing_runtime_unavailable"))?
            .record_live_handoff(
                &owner_context,
                result.published_batches,
                result.eventbus_publications,
                result.downstream_facts,
            )
            .map_err(provider_execution_error)?;
        result.raw_events = lifecycle.raw_event_count;
        result.normalized_events = lifecycle.normalized_event_count;
        result.dropped_events = lifecycle.dropped_event_count;
        if result.normalized_batches > 0 {
            self.provider_controller
                .record_auth_remote_sensing_lifecycle(&owner_context, lifecycle)?;
            let _ = self.publish_canonical_read_model_snapshot(&owner_context)?;
        }
        Ok(result)
    }

    pub fn auth_remote_sensing_live_pump_wait_millis(&self) -> Option<u64> {
        self.auth_remote_sensing_lifecycle_status()
            .and_then(|status| {
                (status.lifecycle_state == EtwLifecycleState::Active
                    && status.consumer_worker_active
                    && status.collection_started)
                    .then_some(100)
            })
    }

    pub fn pump_rdp_operational_sensing_live_batches(
        &mut self,
    ) -> CommandResult<RdpOperationalSensingLivePumpResult> {
        let owner_context = self.owner_context.clone();
        let batches = self
            .rdp_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("rdp_operational_sensing_runtime_unavailable"))?
            .drain_live_batches(
                &owner_context,
                sentinel_infrastructure::WINDOWS_RDP_OPERATIONAL_MAX_DRAIN_BATCHES,
            )
            .map_err(provider_execution_error)?;
        let mut result = RdpOperationalSensingLivePumpResult {
            normalized_batches: batches.len().min(u32::MAX as usize) as u32,
            ..RdpOperationalSensingLivePumpResult::default()
        };
        for batch in batches {
            let handoff = self.execute_rdp_operational_sensing_handoff(&owner_context, batch)?;
            result.published_batches = result.published_batches.saturating_add(1);
            result.eventbus_publications = result
                .eventbus_publications
                .saturating_add(handoff.eventbus_publications);
            result.dag_dispatches = result.dag_dispatches.saturating_add(handoff.dag_dispatches);
            result.auth_detector_invocations = result
                .auth_detector_invocations
                .saturating_add(handoff.auth_detector_invocations);
            result.auth_consumed = result.auth_consumed.saturating_add(handoff.auth_consumed);
            result.remote_admin_invocations = result
                .remote_admin_invocations
                .saturating_add(handoff.remote_admin_invocations);
            result.remote_admin_consumed = result
                .remote_admin_consumed
                .saturating_add(handoff.remote_admin_consumed);
            result.lateral_invocations = result
                .lateral_invocations
                .saturating_add(handoff.lateral_invocations);
            result.lateral_consumed = result
                .lateral_consumed
                .saturating_add(handoff.lateral_consumed);
            result.outputs = result.outputs.saturating_add(handoff.outputs);
            result.downstream_facts = result
                .downstream_facts
                .saturating_add(handoff.downstream_facts);
        }
        let lifecycle = self
            .rdp_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("rdp_operational_sensing_runtime_unavailable"))?
            .record_live_handoff(
                &owner_context,
                result.published_batches,
                result.eventbus_publications,
                result.downstream_facts,
            )
            .map_err(provider_execution_error)?;
        result.raw_events = lifecycle.raw_event_count;
        result.normalized_events = lifecycle.normalized_event_count;
        result.dropped_events = lifecycle.dropped_event_count;
        if result.normalized_batches > 0 {
            self.provider_controller
                .record_rdp_operational_sensing_lifecycle(&owner_context, lifecycle)?;
            let _ = self.publish_canonical_read_model_snapshot(&owner_context)?;
        }
        Ok(result)
    }

    pub fn rdp_operational_sensing_live_pump_wait_millis(&self) -> Option<u64> {
        self.rdp_operational_sensing_lifecycle_status()
            .and_then(|status| {
                (status.lifecycle_state == EtwLifecycleState::Active
                    && status.consumer_worker_active
                    && status.collection_started)
                    .then_some(100)
            })
    }

    pub fn pump_smb_operational_sensing_live_batches(
        &mut self,
    ) -> CommandResult<SmbOperationalSensingLivePumpResult> {
        let owner_context = self.owner_context.clone();
        let batches = self
            .smb_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("smb_operational_sensing_runtime_unavailable"))?
            .drain_live_batches(
                &owner_context,
                sentinel_infrastructure::WINDOWS_SMB_OPERATIONAL_MAX_DRAIN_BATCHES,
            )
            .map_err(provider_execution_error)?;
        let mut result = SmbOperationalSensingLivePumpResult {
            normalized_batches: batches.len().min(u32::MAX as usize) as u32,
            ..SmbOperationalSensingLivePumpResult::default()
        };
        for batch in batches {
            let handoff = self.execute_smb_operational_sensing_handoff(&owner_context, batch)?;
            result.published_batches = result.published_batches.saturating_add(1);
            result.eventbus_publications = result
                .eventbus_publications
                .saturating_add(handoff.eventbus_publications);
            result.dag_dispatches = result.dag_dispatches.saturating_add(handoff.dag_dispatches);
            result.auth_detector_invocations = result
                .auth_detector_invocations
                .saturating_add(handoff.auth_detector_invocations);
            result.auth_consumed = result.auth_consumed.saturating_add(handoff.auth_consumed);
            result.remote_admin_invocations = result
                .remote_admin_invocations
                .saturating_add(handoff.remote_admin_invocations);
            result.remote_admin_consumed = result
                .remote_admin_consumed
                .saturating_add(handoff.remote_admin_consumed);
            result.lateral_invocations = result
                .lateral_invocations
                .saturating_add(handoff.lateral_invocations);
            result.lateral_consumed = result
                .lateral_consumed
                .saturating_add(handoff.lateral_consumed);
            result.outputs = result.outputs.saturating_add(handoff.outputs);
            result.downstream_facts = result
                .downstream_facts
                .saturating_add(handoff.downstream_facts);
        }
        let lifecycle = self
            .smb_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("smb_operational_sensing_runtime_unavailable"))?
            .record_live_handoff(
                &owner_context,
                result.published_batches,
                result.eventbus_publications,
                result.downstream_facts,
            )
            .map_err(provider_execution_error)?;
        result.raw_events = lifecycle.raw_event_count;
        result.normalized_events = lifecycle.normalized_event_count;
        result.dropped_events = lifecycle.dropped_event_count;
        if result.normalized_batches > 0 {
            self.provider_controller
                .record_smb_operational_sensing_lifecycle(&owner_context, lifecycle)?;
            let _ = self.publish_canonical_read_model_snapshot(&owner_context)?;
        }
        Ok(result)
    }

    pub fn smb_operational_sensing_live_pump_wait_millis(&self) -> Option<u64> {
        self.smb_operational_sensing_lifecycle_status()
            .and_then(|status| {
                (status.lifecycle_state == EtwLifecycleState::Active
                    && status.consumer_worker_active
                    && status.collection_started)
                    .then_some(100)
            })
    }

    pub fn pump_ssh_operational_sensing_live_batches(
        &mut self,
    ) -> CommandResult<SshOperationalSensingLivePumpResult> {
        let owner_context = self.owner_context.clone();
        let batches = self
            .ssh_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("ssh_operational_sensing_runtime_unavailable"))?
            .drain_live_batches(
                &owner_context,
                sentinel_infrastructure::WINDOWS_SSH_OPERATIONAL_MAX_DRAIN_BATCHES,
            )
            .map_err(provider_execution_error)?;
        let mut result = SshOperationalSensingLivePumpResult {
            normalized_batches: batches.len().min(u32::MAX as usize) as u32,
            ..SshOperationalSensingLivePumpResult::default()
        };
        for batch in batches {
            let handoff = self.execute_ssh_operational_sensing_handoff(&owner_context, batch)?;
            result.published_batches = result.published_batches.saturating_add(1);
            result.eventbus_publications = result
                .eventbus_publications
                .saturating_add(handoff.eventbus_publications);
            result.dag_dispatches = result.dag_dispatches.saturating_add(handoff.dag_dispatches);
            result.auth_detector_invocations = result
                .auth_detector_invocations
                .saturating_add(handoff.auth_detector_invocations);
            result.auth_consumed = result.auth_consumed.saturating_add(handoff.auth_consumed);
            result.remote_admin_invocations = result
                .remote_admin_invocations
                .saturating_add(handoff.remote_admin_invocations);
            result.remote_admin_consumed = result
                .remote_admin_consumed
                .saturating_add(handoff.remote_admin_consumed);
            result.lateral_invocations = result
                .lateral_invocations
                .saturating_add(handoff.lateral_invocations);
            result.lateral_consumed = result
                .lateral_consumed
                .saturating_add(handoff.lateral_consumed);
            result.outputs = result.outputs.saturating_add(handoff.outputs);
            result.downstream_facts = result
                .downstream_facts
                .saturating_add(handoff.downstream_facts);
        }
        let lifecycle = self
            .ssh_operational_sensing_lifecycle_runtime
            .as_mut()
            .ok_or_else(|| provider_execution_error("ssh_operational_sensing_runtime_unavailable"))?
            .record_live_handoff(
                &owner_context,
                result.published_batches,
                result.eventbus_publications,
                result.downstream_facts,
            )
            .map_err(provider_execution_error)?;
        result.raw_events = lifecycle.raw_event_count;
        result.normalized_events = lifecycle.normalized_event_count;
        result.dropped_events = lifecycle.dropped_event_count;
        if result.normalized_batches > 0 {
            self.provider_controller
                .record_ssh_operational_sensing_lifecycle(&owner_context, lifecycle)?;
            let _ = self.publish_canonical_read_model_snapshot(&owner_context)?;
        }
        Ok(result)
    }

    pub fn ssh_operational_sensing_live_pump_wait_millis(&self) -> Option<u64> {
        self.ssh_operational_sensing_lifecycle_status()
            .and_then(|status| {
                (status.lifecycle_state == EtwLifecycleState::Active
                    && status.consumer_worker_active
                    && status.collection_started)
                    .then_some(100)
            })
    }

    pub fn run_due_ip_helper_schedule_cycle(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        monotonic_elapsed_millis: u64,
    ) -> CommandResult<IpHelperScheduledCycleRecord> {
        let cycle_ref = format!("ip_helper_scheduled_cycle_{}", uuid::Uuid::new_v4());
        self.run_ip_helper_schedule_cycle_for_ref(
            owner_context,
            cycle_ref,
            monotonic_elapsed_millis,
        )
    }

    pub fn ip_helper_scheduler_timer_active(&self) -> bool {
        self.provider_controller
            .ip_helper_schedule_status()
            .is_some_and(|schedule| {
                schedule.timer_runtime_active
                    && schedule.schedule_state == IpHelperScheduleState::ConfiguredEnabled
                    && schedule.lease_state == IpHelperScheduleLeaseState::Active
                    && schedule.schedule_lease_valid
            })
    }

    pub fn ip_helper_scheduler_wait_millis(&self, monotonic_elapsed_millis: u64) -> Option<u64> {
        if !self.ip_helper_scheduler_timer_active() {
            return None;
        }
        if self.ip_helper_schedule_wake_pending {
            return Some(0);
        }
        let due_at = self.ip_helper_next_due_monotonic_millis.unwrap_or(0);
        if due_at <= monotonic_elapsed_millis {
            Some(0)
        } else {
            Some(due_at.saturating_sub(monotonic_elapsed_millis))
        }
    }

    pub fn run_ip_helper_schedule_cycle_for_ref(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        cycle_ref: String,
        monotonic_elapsed_millis: u64,
    ) -> CommandResult<IpHelperScheduledCycleRecord> {
        validate_runtime_safe_ref("ip_helper_scheduled_cycle_ref", &cycle_ref)?;
        self.validate_ip_helper_lifecycle_gate(owner_context, "scheduled_ip_helper_sample")?;

        if self
            .ip_helper_seen_cycle_refs
            .iter()
            .any(|seen| seen == &cycle_ref)
        {
            return self.record_ip_helper_scheduled_skip(
                owner_context,
                cycle_ref,
                IpHelperScheduledSkipDraft {
                    reason: "duplicate_cycle_ref",
                    due_state: IpHelperScheduledDueState::Blocked,
                    authorization_state: IpHelperScheduledAuthorizationState::Valid,
                    execution_result: IpHelperScheduledExecutionResult::Skipped,
                    retry_state: IpHelperScheduledRetryState::None,
                    backpressure_state: IpHelperScheduledBackpressureState::None,
                    missed_sample_state: IpHelperScheduledMissedSampleState::Blocked,
                    audit_event: IP_HELPER_SCHEDULED_CYCLE_SKIPPED,
                },
            );
        }

        let schedule = self
            .provider_controller
            .ip_helper_schedule_status()
            .cloned()
            .ok_or_else(|| provider_execution_error("ip_helper_schedule_unavailable"))?;
        if schedule.schedule_state != IpHelperScheduleState::ConfiguredEnabled
            || schedule.lease_state != IpHelperScheduleLeaseState::Active
            || !schedule.schedule_lease_valid
            || schedule.schedule_lease_ref.is_none()
        {
            return self.record_ip_helper_scheduled_skip(
                owner_context,
                cycle_ref,
                IpHelperScheduledSkipDraft {
                    reason: "schedule_lease_invalid",
                    due_state: IpHelperScheduledDueState::Blocked,
                    authorization_state: IpHelperScheduledAuthorizationState::Invalid,
                    execution_result: IpHelperScheduledExecutionResult::Skipped,
                    retry_state: IpHelperScheduledRetryState::Cleared,
                    backpressure_state: IpHelperScheduledBackpressureState::None,
                    missed_sample_state: IpHelperScheduledMissedSampleState::Blocked,
                    audit_event: IP_HELPER_SCHEDULED_CYCLE_SKIPPED,
                },
            );
        }
        if schedule.policy_version != sentinel_contracts::MUTATION_POLICY_CATALOG_VERSION {
            return self.record_ip_helper_scheduled_skip(
                owner_context,
                cycle_ref,
                IpHelperScheduledSkipDraft {
                    reason: "policy_version_mismatch",
                    due_state: IpHelperScheduledDueState::Blocked,
                    authorization_state: IpHelperScheduledAuthorizationState::PolicyMismatch,
                    execution_result: IpHelperScheduledExecutionResult::Skipped,
                    retry_state: IpHelperScheduledRetryState::Cleared,
                    backpressure_state: IpHelperScheduledBackpressureState::None,
                    missed_sample_state: IpHelperScheduledMissedSampleState::Blocked,
                    audit_event: IP_HELPER_SCHEDULED_CYCLE_SKIPPED,
                },
            );
        }
        let ip_helper = self
            .provider_controller
            .provider_status(NetworkProviderKind::IpHelper)
            .ok_or_else(|| provider_execution_error("ip_helper_status_unavailable"))?;
        if !matches!(
            ip_helper.lifecycle_state,
            NetworkProviderLifecycleState::Active | NetworkProviderLifecycleState::Ready
        ) {
            return self.record_ip_helper_scheduled_skip(
                owner_context,
                cycle_ref,
                IpHelperScheduledSkipDraft {
                    reason: "provider_not_active",
                    due_state: IpHelperScheduledDueState::Blocked,
                    authorization_state: IpHelperScheduledAuthorizationState::Valid,
                    execution_result: IpHelperScheduledExecutionResult::Skipped,
                    retry_state: IpHelperScheduledRetryState::Cleared,
                    backpressure_state: IpHelperScheduledBackpressureState::None,
                    missed_sample_state: IpHelperScheduledMissedSampleState::Blocked,
                    audit_event: IP_HELPER_SCHEDULED_CYCLE_SKIPPED,
                },
            );
        }
        let due_at = if self.ip_helper_schedule_wake_pending {
            0
        } else {
            self.ip_helper_next_due_monotonic_millis.unwrap_or(0)
        };
        if due_at > monotonic_elapsed_millis {
            return self.record_ip_helper_scheduled_skip(
                owner_context,
                cycle_ref,
                IpHelperScheduledSkipDraft {
                    reason: "not_due",
                    due_state: IpHelperScheduledDueState::NotDue,
                    authorization_state: IpHelperScheduledAuthorizationState::Valid,
                    execution_result: IpHelperScheduledExecutionResult::Skipped,
                    retry_state: IpHelperScheduledRetryState::None,
                    backpressure_state: IpHelperScheduledBackpressureState::None,
                    missed_sample_state: IpHelperScheduledMissedSampleState::OnTime,
                    audit_event: IP_HELPER_SCHEDULED_CYCLE_SKIPPED,
                },
            );
        }
        #[cfg(test)]
        if let Some(fault) = self.ip_helper_scheduler_test_fault.take() {
            self.ip_helper_next_due_monotonic_millis = Some(
                monotonic_elapsed_millis.saturating_add(ip_helper_schedule_interval_millis(
                    &schedule.config.interval_bucket,
                )),
            );
            let draft = match fault {
                IpHelperSchedulerTestFault::ProviderTimeout => IpHelperScheduledSkipDraft {
                    reason: "provider_timeout",
                    due_state: IpHelperScheduledDueState::Due,
                    authorization_state: IpHelperScheduledAuthorizationState::Valid,
                    execution_result: IpHelperScheduledExecutionResult::TimedOut,
                    retry_state: retry_state_for_ip_helper(&schedule.config.retry_budget_bucket),
                    backpressure_state: IpHelperScheduledBackpressureState::Low,
                    missed_sample_state: IpHelperScheduledMissedSampleState::Delayed,
                    audit_event: IP_HELPER_SCHEDULED_CYCLE_RETRY_SCHEDULED,
                },
                IpHelperSchedulerTestFault::ProviderTemporarilyUnavailable => {
                    IpHelperScheduledSkipDraft {
                        reason: "provider_temporarily_unavailable",
                        due_state: IpHelperScheduledDueState::Due,
                        authorization_state: IpHelperScheduledAuthorizationState::Valid,
                        execution_result: IpHelperScheduledExecutionResult::Failed,
                        retry_state: retry_state_for_ip_helper(
                            &schedule.config.retry_budget_bucket,
                        ),
                        backpressure_state: IpHelperScheduledBackpressureState::Moderate,
                        missed_sample_state: IpHelperScheduledMissedSampleState::Delayed,
                        audit_event: IP_HELPER_SCHEDULED_CYCLE_RETRY_SCHEDULED,
                    }
                }
                IpHelperSchedulerTestFault::SaturatedBackpressure => IpHelperScheduledSkipDraft {
                    reason: "scheduler_backpressure_saturated",
                    due_state: IpHelperScheduledDueState::Due,
                    authorization_state: IpHelperScheduledAuthorizationState::Valid,
                    execution_result: IpHelperScheduledExecutionResult::Skipped,
                    retry_state: IpHelperScheduledRetryState::None,
                    backpressure_state: IpHelperScheduledBackpressureState::Saturated,
                    missed_sample_state: IpHelperScheduledMissedSampleState::Delayed,
                    audit_event: IP_HELPER_SCHEDULED_CYCLE_SKIPPED,
                },
            };
            return self.record_ip_helper_scheduled_skip(owner_context, cycle_ref, draft);
        }
        if self.ip_helper_execution_active {
            self.ip_helper_scheduled_overlap_skip_count = self
                .ip_helper_scheduled_overlap_skip_count
                .saturating_add(1);
            return self.record_ip_helper_scheduled_skip(
                owner_context,
                cycle_ref,
                IpHelperScheduledSkipDraft {
                    reason: "execution_gate_busy",
                    due_state: IpHelperScheduledDueState::Due,
                    authorization_state: IpHelperScheduledAuthorizationState::Valid,
                    execution_result: IpHelperScheduledExecutionResult::Busy,
                    retry_state: retry_state_for_ip_helper(&schedule.config.retry_budget_bucket),
                    backpressure_state: IpHelperScheduledBackpressureState::Low,
                    missed_sample_state: IpHelperScheduledMissedSampleState::Delayed,
                    audit_event: IP_HELPER_SCHEDULED_CYCLE_RETRY_SCHEDULED,
                },
            );
        }

        let status =
            self.provider_controller.status().cloned().ok_or_else(|| {
                provider_execution_error("provider_controller_status_unavailable")
            })?;
        self.publish_ip_helper_schedule_status(
            owner_context,
            &status,
            IP_HELPER_SCHEDULED_CYCLE_DUE,
        )?;

        let timeout_ms = ip_helper_schedule_timeout_millis(&schedule.config);
        let request = IpHelperHandoffRequest::scheduled_servicehost(
            cycle_ref.clone(),
            schedule.config.maximum_records as usize,
            schedule.config.maximum_bytes as usize,
            timeout_ms,
        );
        let result = self.execute_ip_helper_servicehost_handoff(owner_context, request);
        match result {
            Ok(_) => {
                self.ip_helper_schedule_wake_pending = false;
                self.ip_helper_seen_cycle_refs.push(cycle_ref.clone());
                bound_string_refs(&mut self.ip_helper_seen_cycle_refs);
                self.ip_helper_scheduled_sample_count =
                    self.ip_helper_scheduled_sample_count.saturating_add(1);
                self.ip_helper_next_due_monotonic_millis =
                    Some(monotonic_elapsed_millis.saturating_add(
                        ip_helper_schedule_interval_millis(&schedule.config.interval_bucket),
                    ));
                self.provider_controller
                    .ip_helper_schedule_status()
                    .and_then(|status| status.latest_scheduled_cycle.clone())
                    .ok_or_else(|| provider_execution_error("scheduled_cycle_record_unavailable"))
            }
            Err(error) => {
                self.ip_helper_scheduled_skip_count =
                    self.ip_helper_scheduled_skip_count.saturating_add(1);
                self.record_ip_helper_scheduled_skip(
                    owner_context,
                    cycle_ref,
                    IpHelperScheduledSkipDraft {
                        reason: "scheduled_provider_execution_failed",
                        due_state: IpHelperScheduledDueState::Due,
                        authorization_state: IpHelperScheduledAuthorizationState::Valid,
                        execution_result: IpHelperScheduledExecutionResult::Failed,
                        retry_state: retry_state_for_ip_helper(
                            &schedule.config.retry_budget_bucket,
                        ),
                        backpressure_state: IpHelperScheduledBackpressureState::Low,
                        missed_sample_state: IpHelperScheduledMissedSampleState::Delayed,
                        audit_event: IP_HELPER_SCHEDULED_CYCLE_FAILED,
                    },
                )
                .map_err(|_| error)
            }
        }
    }

    fn record_ip_helper_scheduled_skip(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        cycle_ref: String,
        draft: IpHelperScheduledSkipDraft,
    ) -> CommandResult<IpHelperScheduledCycleRecord> {
        self.ip_helper_schedule_wake_pending = false;
        self.ip_helper_scheduled_skip_count = self.ip_helper_scheduled_skip_count.saturating_add(1);
        let status = self
            .provider_controller
            .record_ip_helper_scheduled_cycle_skipped(owner_context, cycle_ref, draft)?;
        self.publish_ip_helper_schedule_status(owner_context, &status, draft.audit_event)?;
        status
            .ip_helper_schedule
            .latest_scheduled_cycle
            .clone()
            .ok_or_else(|| provider_execution_error("scheduled_skip_record_unavailable"))
    }

    fn validate_ip_helper_lifecycle_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
        operation: &'static str,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        RuntimeOwnershipGuard::validate_active_context(
            owner_context,
            owner_context.ownership_epoch,
        )
        .map_err(CoreError::from)?;
        self.ownership_lease
            .validate_epoch(owner_context.ownership_epoch)
            .map_err(CoreError::from)?;
        if self.transition_state != RuntimeTransitionState::Ready
            || self.runtime_health != RuntimeHealthState::Ready
        {
            return Err(provider_execution_error("runtime_container_not_ready"));
        }
        if self.shutdown_coordinator.shutdown_started() {
            return Err(CoreError::from(
                RuntimeOwnershipError::RuntimeShutdownInProgress,
            ));
        }
        let ip_helper = self
            .provider_controller
            .provider_status(NetworkProviderKind::IpHelper)
            .ok_or_else(|| provider_execution_error("ip_helper_status_unavailable"))?;
        if !matches!(
            ip_helper.implementation_state,
            NetworkProviderImplementationState::ImplementedInactive
                | NetworkProviderImplementationState::Available
                | NetworkProviderImplementationState::Degraded
        ) {
            return Err(provider_execution_error(
                "ip_helper_adapter_not_implemented",
            ));
        }
        if operation == "activate_ip_helper"
            && !matches!(
                ip_helper.lifecycle_state,
                NetworkProviderLifecycleState::Inactive
                    | NetworkProviderLifecycleState::Ready
                    | NetworkProviderLifecycleState::Active
                    | NetworkProviderLifecycleState::Stopped
            )
        {
            return Err(provider_execution_error(
                "ip_helper_activation_state_invalid",
            ));
        }
        if operation == "stop_ip_helper"
            && matches!(
                ip_helper.lifecycle_state,
                NetworkProviderLifecycleState::Revoked | NetworkProviderLifecycleState::Failed
            )
        {
            return Err(provider_execution_error("ip_helper_stop_state_invalid"));
        }
        if self.event_bus.is_none()
            || self.pipeline_dag.is_none()
            || self.plugin_runtime.is_none()
            || self.runtime_services.is_none()
        {
            return Err(provider_execution_error(
                "container_runtime_path_unavailable",
            ));
        }
        Ok(())
    }

    fn validate_dns_sensing_lifecycle_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
        operation: &'static str,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        if self.transition_state != RuntimeTransitionState::Ready
            || self.runtime_health != RuntimeHealthState::Ready
            || self.shutdown_coordinator.shutdown_started()
        {
            return Err(provider_execution_error("runtime_container_not_ready"));
        }
        let provider = self
            .provider_controller
            .provider_status(NetworkProviderKind::WindowsDns)
            .ok_or_else(|| provider_execution_error("windows_dns_status_unavailable"))?;
        if !matches!(
            provider.implementation_state,
            NetworkProviderImplementationState::ImplementedInactive
                | NetworkProviderImplementationState::Available
                | NetworkProviderImplementationState::Degraded
                | NetworkProviderImplementationState::Failed
        ) {
            return Err(provider_execution_error(
                "windows_dns_adapter_not_implemented",
            ));
        }
        let lifecycle = self
            .dns_sensing_lifecycle_status()
            .ok_or_else(|| provider_execution_error("dns_sensing_runtime_unavailable"))?;
        let allowed = match operation {
            "activate_dns_sensing" => matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Inactive
                    | EtwLifecycleState::Stopped
                    | EtwLifecycleState::Degraded
                    | EtwLifecycleState::Failed
            ),
            "pause_dns_sensing" => lifecycle.lifecycle_state == EtwLifecycleState::Active,
            "resume_dns_sensing" => lifecycle.lifecycle_state == EtwLifecycleState::Paused,
            "stop_dns_sensing" => !matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Activating
                    | EtwLifecycleState::Pausing
                    | EtwLifecycleState::Resuming
                    | EtwLifecycleState::Stopping
            ),
            _ => false,
        };
        if !allowed {
            return Err(provider_execution_error(
                "windows_dns_lifecycle_state_invalid",
            ));
        }
        Ok(())
    }

    fn validate_dns_sensing_handoff_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        let lifecycle = self
            .dns_sensing_lifecycle_status()
            .ok_or_else(|| provider_execution_error("dns_sensing_runtime_unavailable"))?;
        if lifecycle.authorization_state != EtwAuthorizationState::Authorized
            || lifecycle.lifecycle_state != EtwLifecycleState::Active
            || self.shutdown_coordinator.shutdown_started()
            || self.event_bus.is_none()
            || self.pipeline_dag.is_none()
            || self.plugin_runtime.is_none()
            || self.runtime_services.is_none()
        {
            return Err(provider_execution_error(
                "windows_dns_handoff_requires_active_authorization",
            ));
        }
        Ok(())
    }

    fn validate_auth_remote_sensing_lifecycle_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
        operation: &'static str,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        if self.transition_state != RuntimeTransitionState::Ready
            || self.runtime_health != RuntimeHealthState::Ready
            || self.shutdown_coordinator.shutdown_started()
        {
            return Err(provider_execution_error("runtime_container_not_ready"));
        }
        let provider = self
            .provider_controller
            .provider_status(NetworkProviderKind::WindowsAuthRemote)
            .ok_or_else(|| provider_execution_error("windows_auth_remote_status_unavailable"))?;
        if !matches!(
            provider.implementation_state,
            NetworkProviderImplementationState::ImplementedInactive
                | NetworkProviderImplementationState::Available
                | NetworkProviderImplementationState::Degraded
                | NetworkProviderImplementationState::Failed
        ) {
            return Err(provider_execution_error(
                "windows_auth_remote_adapter_not_implemented",
            ));
        }
        let lifecycle = self
            .auth_remote_sensing_lifecycle_status()
            .ok_or_else(|| provider_execution_error("auth_remote_sensing_runtime_unavailable"))?;
        let allowed = match operation {
            "activate_auth_remote_sensing" => matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Inactive
                    | EtwLifecycleState::Stopped
                    | EtwLifecycleState::Degraded
                    | EtwLifecycleState::Failed
            ),
            "pause_auth_remote_sensing" => lifecycle.lifecycle_state == EtwLifecycleState::Active,
            "resume_auth_remote_sensing" => lifecycle.lifecycle_state == EtwLifecycleState::Paused,
            "stop_auth_remote_sensing" => !matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Activating
                    | EtwLifecycleState::Pausing
                    | EtwLifecycleState::Resuming
                    | EtwLifecycleState::Stopping
            ),
            _ => false,
        };
        if !allowed {
            return Err(provider_execution_error(
                "windows_auth_remote_lifecycle_state_invalid",
            ));
        }
        Ok(())
    }

    fn validate_auth_remote_sensing_handoff_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        let lifecycle = self
            .auth_remote_sensing_lifecycle_status()
            .ok_or_else(|| provider_execution_error("auth_remote_sensing_runtime_unavailable"))?;
        if lifecycle.authorization_state != EtwAuthorizationState::Authorized
            || lifecycle.lifecycle_state != EtwLifecycleState::Active
            || self.shutdown_coordinator.shutdown_started()
            || self.event_bus.is_none()
            || self.pipeline_dag.is_none()
            || self.plugin_runtime.is_none()
            || self.runtime_services.is_none()
        {
            return Err(provider_execution_error(
                "windows_auth_remote_handoff_requires_active_authorization",
            ));
        }
        Ok(())
    }

    fn validate_rdp_operational_sensing_lifecycle_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
        operation: &'static str,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        if self.transition_state != RuntimeTransitionState::Ready
            || self.runtime_health != RuntimeHealthState::Ready
            || self.shutdown_coordinator.shutdown_started()
        {
            return Err(provider_execution_error("runtime_container_not_ready"));
        }
        let provider = self
            .provider_controller
            .provider_status(NetworkProviderKind::WindowsRdpOperational)
            .ok_or_else(|| {
                provider_execution_error("windows_rdp_operational_status_unavailable")
            })?;
        if !matches!(
            provider.implementation_state,
            NetworkProviderImplementationState::ImplementedInactive
                | NetworkProviderImplementationState::Available
                | NetworkProviderImplementationState::Degraded
                | NetworkProviderImplementationState::Failed
        ) {
            return Err(provider_execution_error(
                "windows_rdp_operational_adapter_not_implemented",
            ));
        }
        let lifecycle = self
            .rdp_operational_sensing_lifecycle_status()
            .ok_or_else(|| {
                provider_execution_error("rdp_operational_sensing_runtime_unavailable")
            })?;
        let allowed = match operation {
            "activate_rdp_operational_sensing" => matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Inactive
                    | EtwLifecycleState::Stopped
                    | EtwLifecycleState::Degraded
                    | EtwLifecycleState::Failed
            ),
            "pause_rdp_operational_sensing" => {
                lifecycle.lifecycle_state == EtwLifecycleState::Active
            }
            "resume_rdp_operational_sensing" => {
                lifecycle.lifecycle_state == EtwLifecycleState::Paused
            }
            "stop_rdp_operational_sensing" => !matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Activating
                    | EtwLifecycleState::Pausing
                    | EtwLifecycleState::Resuming
                    | EtwLifecycleState::Stopping
            ),
            _ => false,
        };
        if !allowed {
            return Err(provider_execution_error(
                "windows_rdp_operational_lifecycle_state_invalid",
            ));
        }
        Ok(())
    }

    fn validate_rdp_operational_sensing_handoff_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        let lifecycle = self
            .rdp_operational_sensing_lifecycle_status()
            .ok_or_else(|| {
                provider_execution_error("rdp_operational_sensing_runtime_unavailable")
            })?;
        if lifecycle.authorization_state != EtwAuthorizationState::Authorized
            || lifecycle.lifecycle_state != EtwLifecycleState::Active
            || self.shutdown_coordinator.shutdown_started()
            || self.event_bus.is_none()
            || self.pipeline_dag.is_none()
            || self.plugin_runtime.is_none()
            || self.runtime_services.is_none()
        {
            return Err(provider_execution_error(
                "windows_rdp_operational_handoff_requires_active_authorization",
            ));
        }
        Ok(())
    }

    fn validate_smb_operational_sensing_lifecycle_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
        operation: &'static str,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        if self.transition_state != RuntimeTransitionState::Ready
            || self.runtime_health != RuntimeHealthState::Ready
            || self.shutdown_coordinator.shutdown_started()
        {
            return Err(provider_execution_error("runtime_container_not_ready"));
        }
        let provider = self
            .provider_controller
            .provider_status(NetworkProviderKind::WindowsSmbOperational)
            .ok_or_else(|| {
                provider_execution_error("windows_smb_operational_status_unavailable")
            })?;
        if !matches!(
            provider.implementation_state,
            NetworkProviderImplementationState::ImplementedInactive
                | NetworkProviderImplementationState::Available
                | NetworkProviderImplementationState::Degraded
                | NetworkProviderImplementationState::Failed
        ) {
            return Err(provider_execution_error(
                "windows_smb_operational_adapter_not_implemented",
            ));
        }
        let lifecycle = self
            .smb_operational_sensing_lifecycle_status()
            .ok_or_else(|| {
                provider_execution_error("smb_operational_sensing_runtime_unavailable")
            })?;
        let allowed = match operation {
            "activate_smb_operational_sensing" => matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Inactive
                    | EtwLifecycleState::Stopped
                    | EtwLifecycleState::Degraded
                    | EtwLifecycleState::Failed
            ),
            "pause_smb_operational_sensing" => {
                lifecycle.lifecycle_state == EtwLifecycleState::Active
            }
            "resume_smb_operational_sensing" => {
                lifecycle.lifecycle_state == EtwLifecycleState::Paused
            }
            "stop_smb_operational_sensing" => !matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Activating
                    | EtwLifecycleState::Pausing
                    | EtwLifecycleState::Resuming
                    | EtwLifecycleState::Stopping
            ),
            _ => false,
        };
        if !allowed {
            return Err(provider_execution_error(
                "windows_smb_operational_lifecycle_state_invalid",
            ));
        }
        Ok(())
    }

    fn validate_smb_operational_sensing_handoff_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        let lifecycle = self
            .smb_operational_sensing_lifecycle_status()
            .ok_or_else(|| {
                provider_execution_error("smb_operational_sensing_runtime_unavailable")
            })?;
        if lifecycle.authorization_state != EtwAuthorizationState::Authorized
            || lifecycle.lifecycle_state != EtwLifecycleState::Active
            || self.shutdown_coordinator.shutdown_started()
            || self.event_bus.is_none()
            || self.pipeline_dag.is_none()
            || self.plugin_runtime.is_none()
            || self.runtime_services.is_none()
        {
            return Err(provider_execution_error(
                "windows_smb_operational_handoff_requires_active_authorization",
            ));
        }
        Ok(())
    }

    fn validate_ssh_operational_sensing_lifecycle_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
        operation: &'static str,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        if self.transition_state != RuntimeTransitionState::Ready
            || self.runtime_health != RuntimeHealthState::Ready
            || self.shutdown_coordinator.shutdown_started()
        {
            return Err(provider_execution_error("runtime_container_not_ready"));
        }
        let provider = self
            .provider_controller
            .provider_status(NetworkProviderKind::WindowsSshOperational)
            .ok_or_else(|| {
                provider_execution_error("windows_ssh_operational_status_unavailable")
            })?;
        if !matches!(
            provider.implementation_state,
            NetworkProviderImplementationState::ImplementedInactive
                | NetworkProviderImplementationState::Available
                | NetworkProviderImplementationState::Degraded
                | NetworkProviderImplementationState::Failed
        ) {
            return Err(provider_execution_error(
                "windows_ssh_operational_adapter_not_implemented",
            ));
        }
        let lifecycle = self
            .ssh_operational_sensing_lifecycle_status()
            .ok_or_else(|| {
                provider_execution_error("ssh_operational_sensing_runtime_unavailable")
            })?;
        let allowed = match operation {
            "activate_ssh_operational_sensing" => matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Inactive
                    | EtwLifecycleState::Stopped
                    | EtwLifecycleState::Degraded
                    | EtwLifecycleState::Failed
            ),
            "pause_ssh_operational_sensing" => {
                lifecycle.lifecycle_state == EtwLifecycleState::Active
            }
            "resume_ssh_operational_sensing" => {
                lifecycle.lifecycle_state == EtwLifecycleState::Paused
            }
            "stop_ssh_operational_sensing" => !matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Activating
                    | EtwLifecycleState::Pausing
                    | EtwLifecycleState::Resuming
                    | EtwLifecycleState::Stopping
            ),
            _ => false,
        };
        if !allowed {
            return Err(provider_execution_error(
                "windows_ssh_operational_lifecycle_state_invalid",
            ));
        }
        Ok(())
    }

    fn validate_ssh_operational_sensing_handoff_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        let lifecycle = self
            .ssh_operational_sensing_lifecycle_status()
            .ok_or_else(|| {
                provider_execution_error("ssh_operational_sensing_runtime_unavailable")
            })?;
        if lifecycle.authorization_state != EtwAuthorizationState::Authorized
            || lifecycle.lifecycle_state != EtwLifecycleState::Active
            || self.shutdown_coordinator.shutdown_started()
            || self.event_bus.is_none()
            || self.pipeline_dag.is_none()
            || self.plugin_runtime.is_none()
            || self.runtime_services.is_none()
        {
            return Err(provider_execution_error(
                "windows_ssh_operational_handoff_requires_active_authorization",
            ));
        }
        Ok(())
    }

    fn validate_etw_lifecycle_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
        operation: &'static str,
    ) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        RuntimeOwnershipGuard::validate_active_context(
            owner_context,
            owner_context.ownership_epoch,
        )
        .map_err(CoreError::from)?;
        self.ownership_lease
            .validate_epoch(owner_context.ownership_epoch)
            .map_err(CoreError::from)?;
        if self.transition_state != RuntimeTransitionState::Ready
            || self.runtime_health != RuntimeHealthState::Ready
        {
            return Err(provider_execution_error("runtime_container_not_ready"));
        }
        if self.shutdown_coordinator.shutdown_started() {
            return Err(CoreError::from(
                RuntimeOwnershipError::RuntimeShutdownInProgress,
            ));
        }
        let etw = self
            .provider_controller
            .provider_status(NetworkProviderKind::EtwNetwork)
            .ok_or_else(|| provider_execution_error("etw_status_unavailable"))?;
        if !matches!(
            etw.implementation_state,
            NetworkProviderImplementationState::ImplementedInactive
                | NetworkProviderImplementationState::Available
                | NetworkProviderImplementationState::Degraded
                | NetworkProviderImplementationState::Failed
        ) {
            return Err(provider_execution_error(
                "etw_control_adapter_not_implemented",
            ));
        }
        let lifecycle = self
            .etw_lifecycle_status()
            .ok_or_else(|| provider_execution_error("etw_lifecycle_runtime_unavailable"))?;
        let allowed = match operation {
            "activate_etw" => matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Inactive
                    | EtwLifecycleState::Stopped
                    | EtwLifecycleState::Degraded
                    | EtwLifecycleState::Failed
            ),
            "pause_etw" => lifecycle.lifecycle_state == EtwLifecycleState::Active,
            "resume_etw" => lifecycle.lifecycle_state == EtwLifecycleState::Paused,
            "stop_etw" => !matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Activating
                    | EtwLifecycleState::Pausing
                    | EtwLifecycleState::Resuming
                    | EtwLifecycleState::Stopping
            ),
            _ => false,
        };
        if !allowed {
            return Err(provider_execution_error("etw_lifecycle_state_invalid"));
        }
        Ok(())
    }

    fn validate_etw_handoff_gate(&self, owner_context: &RuntimeOwnerContext) -> CommandResult<()> {
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        RuntimeOwnershipGuard::validate_active_context(
            owner_context,
            owner_context.ownership_epoch,
        )
        .map_err(CoreError::from)?;
        self.ownership_lease
            .validate_epoch(owner_context.ownership_epoch)
            .map_err(CoreError::from)?;
        if self.transition_state != RuntimeTransitionState::Ready
            || self.runtime_health != RuntimeHealthState::Ready
        {
            return Err(provider_execution_error("runtime_container_not_ready"));
        }
        if self.shutdown_coordinator.shutdown_started() {
            return Err(CoreError::from(
                RuntimeOwnershipError::RuntimeShutdownInProgress,
            ));
        }
        let etw = self
            .provider_controller
            .provider_status(NetworkProviderKind::EtwNetwork)
            .ok_or_else(|| provider_execution_error("etw_status_unavailable"))?;
        if !matches!(
            etw.implementation_state,
            NetworkProviderImplementationState::Available
                | NetworkProviderImplementationState::Degraded
                | NetworkProviderImplementationState::ImplementedInactive
        ) {
            return Err(provider_execution_error(
                "etw_handoff_adapter_not_available",
            ));
        }
        let lifecycle = self
            .etw_lifecycle_status()
            .ok_or_else(|| provider_execution_error("etw_lifecycle_runtime_unavailable"))?;
        if lifecycle.authorization_state != EtwAuthorizationState::Authorized
            || !matches!(
                lifecycle.lifecycle_state,
                EtwLifecycleState::Active | EtwLifecycleState::Degraded
            )
        {
            return Err(provider_execution_error(
                "etw_handoff_requires_active_authorization",
            ));
        }
        if self.event_bus.is_none()
            || self.pipeline_dag.is_none()
            || self.plugin_runtime.is_none()
            || self.runtime_services.is_none()
        {
            return Err(provider_execution_error(
                "container_runtime_path_unavailable",
            ));
        }
        Ok(())
    }

    fn etw_fallback_state(&self) -> EtwFallbackState {
        let Some(ip_helper) = self
            .provider_controller
            .provider_status(NetworkProviderKind::IpHelper)
        else {
            return EtwFallbackState::PortableMetadataOnly;
        };
        if matches!(
            ip_helper.lifecycle_state,
            NetworkProviderLifecycleState::Active
                | NetworkProviderLifecycleState::Ready
                | NetworkProviderLifecycleState::Degraded
        ) {
            return EtwFallbackState::IpHelperActive;
        }
        if matches!(
            ip_helper.implementation_state,
            NetworkProviderImplementationState::ImplementedInactive
                | NetworkProviderImplementationState::Available
                | NetworkProviderImplementationState::Degraded
        ) {
            return EtwFallbackState::IpHelperAvailable;
        }
        EtwFallbackState::PortableMetadataOnly
    }

    fn require_ip_helper_active_for_schedule(&self) -> CommandResult<()> {
        let ip_helper = self
            .provider_controller
            .provider_status(NetworkProviderKind::IpHelper)
            .ok_or_else(|| provider_execution_error("ip_helper_status_unavailable"))?;
        if !matches!(
            ip_helper.lifecycle_state,
            NetworkProviderLifecycleState::Active | NetworkProviderLifecycleState::Ready
        ) {
            return Err(provider_execution_error(
                "ip_helper_schedule_requires_active_provider",
            ));
        }
        Ok(())
    }

    fn require_configured_ip_helper_schedule(&self) -> CommandResult<()> {
        let schedule = self
            .provider_controller
            .ip_helper_schedule_status()
            .ok_or_else(|| provider_execution_error("ip_helper_schedule_unavailable"))?;
        if !matches!(
            schedule.schedule_state,
            IpHelperScheduleState::ConfiguredDisabled | IpHelperScheduleState::Paused
        ) {
            return Err(provider_execution_error(
                "ip_helper_schedule_not_configured",
            ));
        }
        schedule
            .config
            .validate()
            .map_err(|error| provider_execution_error(error.to_string()))
    }

    fn publish_ip_helper_schedule_status(
        &mut self,
        owner_context: &RuntimeOwnerContext,
        status: &NetworkProviderControllerStatus,
        audit_ref: &'static str,
    ) -> CommandResult<()> {
        self.publish_container_payload(
            NETWORK_PROVIDER_STATUS,
            &status.ip_helper_schedule,
            "bounded ip helper schedule status",
        )?;
        self.publish_container_payload(
            AUDIT_NETWORK_PROVIDER_EXECUTION,
            &json!({
                "audit_ref": audit_ref,
                "provider_ref": "network_provider_ip_helper",
                "schedule_ref": status.ip_helper_schedule.schedule_ref.clone(),
                "timer_runtime_active": status.ip_helper_schedule.timer_runtime_active,
                "scheduler_triggered_provider_calls": status.ip_helper_schedule.scheduler_triggered_provider_calls,
                "redaction_status": "redacted"
            }),
            "bounded ip helper schedule audit",
        )?;
        let _ = self.publish_canonical_read_model_snapshot(owner_context)?;
        Ok(())
    }

    fn validate_ip_helper_execution_gate(
        &self,
        owner_context: &RuntimeOwnerContext,
        request: &IpHelperHandoffRequest,
    ) -> CommandResult<()> {
        request.validate()?;
        if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || owner_context.runtime_mode != RuntimeMode::ServiceOwned
            || self.owner_context.ownership_ref != owner_context.ownership_ref
        {
            return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
        }
        if self.owner_context.ownership_epoch != owner_context.ownership_epoch {
            return Err(CoreError::from(RuntimeOwnershipError::StaleOwnershipEpoch));
        }
        RuntimeOwnershipGuard::validate_active_context(
            owner_context,
            owner_context.ownership_epoch,
        )
        .map_err(CoreError::from)?;
        self.ownership_lease
            .validate_epoch(owner_context.ownership_epoch)
            .map_err(CoreError::from)?;
        if self.transition_state != RuntimeTransitionState::Ready
            || self.runtime_health != RuntimeHealthState::Ready
        {
            return Err(provider_execution_error("runtime_container_not_ready"));
        }
        if self.shutdown_coordinator.shutdown_started() {
            return Err(CoreError::from(
                RuntimeOwnershipError::RuntimeShutdownInProgress,
            ));
        }
        let ip_helper = self
            .provider_controller
            .provider_status(NetworkProviderKind::IpHelper)
            .ok_or_else(|| provider_execution_error("ip_helper_status_unavailable"))?;
        if !matches!(
            ip_helper.implementation_state,
            NetworkProviderImplementationState::ImplementedInactive
                | NetworkProviderImplementationState::Available
                | NetworkProviderImplementationState::Degraded
        ) {
            return Err(provider_execution_error(
                "ip_helper_adapter_not_implemented",
            ));
        }
        if matches!(
            request.policy,
            IpHelperHandoffExecutionPolicy::ProductionIpc
                | IpHelperHandoffExecutionPolicy::ScheduledServiceHost
        ) && !matches!(
            ip_helper.lifecycle_state,
            NetworkProviderLifecycleState::Active | NetworkProviderLifecycleState::Ready
        ) {
            return Err(provider_execution_error("ip_helper_not_active"));
        }
        if self.event_bus.is_none()
            || self.pipeline_dag.is_none()
            || self.plugin_runtime.is_none()
            || self.runtime_services.is_none()
        {
            return Err(provider_execution_error(
                "container_runtime_path_unavailable",
            ));
        }
        Ok(())
    }

    fn run_native_network_fact_runtime(
        &self,
        input_event: EventEnvelope,
    ) -> CommandResult<Vec<EventEnvelope>> {
        let runtime_services = self
            .runtime_services
            .as_ref()
            .ok_or_else(|| provider_execution_error("runtime_services_unavailable"))?;
        runtime_services.with_plugin_runtime(|runtime| {
            let plugin_id = PluginId::parse_str(NATIVE_NETWORK_FACT_STATIC_PLUGIN_ID)
                .map_err(provider_execution_error)?;
            let manifest = runtime
                .manifest(&plugin_id)
                .ok_or_else(|| provider_execution_error("native_network_fact_manifest_missing"))?
                .clone();
            let contracts = runtime_contract_registry_for_manifest(&manifest)?;
            let mut permissions = PermissionResolver::new();
            permissions.register_plugin_manifest_permissions(&manifest);
            let validation = runtime
                .registry()
                .validate_startup(&plugin_id, &contracts, &permissions)
                .map_err(provider_execution_error)?;
            let mut context =
                runtime_plugin_context_for_manifest(&manifest, TraceContext::new_root())?;
            context.policy_scope = PolicyScope::Plugin;
            runtime
                .start_plugin(&plugin_id, &validation, &mut context)
                .map_err(provider_execution_error)?;
            let mut batch = PluginEventBatch::new(plugin_id.clone(), 1);
            batch.push(input_event).map_err(provider_execution_error)?;
            let output = runtime
                .process_batch(&plugin_id, &mut context, &batch)
                .map_err(provider_execution_error)?;
            Ok(output.events)
        })
    }

    fn run_dns_security_runtime(
        &self,
        input_events: Vec<EventEnvelope>,
    ) -> CommandResult<Vec<EventEnvelope>> {
        let runtime_services = self
            .runtime_services
            .as_ref()
            .ok_or_else(|| provider_execution_error("runtime_services_unavailable"))?;
        runtime_services.with_plugin_runtime(|runtime| {
            let plugin_id = PluginId::parse_str(DNS_SECURITY_V2_STATIC_PLUGIN_ID)
                .map_err(provider_execution_error)?;
            let manifest = runtime
                .manifest(&plugin_id)
                .ok_or_else(|| provider_execution_error("dns_security_v2_manifest_missing"))?
                .clone();
            let contracts = runtime_contract_registry_for_manifest(&manifest)?;
            let mut permissions = PermissionResolver::new();
            permissions.register_plugin_manifest_permissions(&manifest);
            let validation = runtime
                .registry()
                .validate_startup(&plugin_id, &contracts, &permissions)
                .map_err(provider_execution_error)?;
            let mut context =
                runtime_plugin_context_for_manifest(&manifest, TraceContext::new_root())?;
            context.policy_scope = PolicyScope::Plugin;
            runtime
                .start_plugin(&plugin_id, &validation, &mut context)
                .map_err(provider_execution_error)?;
            let max_events = input_events.len().max(1);
            let mut batch = PluginEventBatch::new(plugin_id.clone(), max_events);
            for event in input_events {
                batch.push(event).map_err(provider_execution_error)?;
            }
            let output = runtime
                .process_batch(&plugin_id, &mut context, &batch)
                .map_err(provider_execution_error)?;
            Ok(output.events)
        })
    }

    #[cfg(test)]
    fn run_c2_detection_runtime(
        &self,
        input_events: Vec<EventEnvelope>,
    ) -> CommandResult<Vec<EventEnvelope>> {
        validate_c2_detection_dag_route(self)?;
        let runtime_services = self
            .runtime_services
            .as_ref()
            .ok_or_else(|| provider_execution_error("runtime_services_unavailable"))?;
        runtime_services.with_plugin_runtime(|runtime| {
            let plugin_id =
                PluginId::parse_str(sentinel_capabilities::C2_DETECTION_STATIC_PLUGIN_ID)
                    .map_err(provider_execution_error)?;
            let manifest = runtime
                .manifest(&plugin_id)
                .ok_or_else(|| provider_execution_error("c2_detection_manifest_missing"))?
                .clone();
            let contracts = runtime_contract_registry_for_manifest(&manifest)?;
            let mut permissions = PermissionResolver::new();
            permissions.register_plugin_manifest_permissions(&manifest);
            let validation = runtime
                .registry()
                .validate_startup(&plugin_id, &contracts, &permissions)
                .map_err(provider_execution_error)?;
            let mut context =
                runtime_plugin_context_for_manifest(&manifest, TraceContext::new_root())?;
            context.policy_scope = PolicyScope::Plugin;
            runtime
                .start_plugin(&plugin_id, &validation, &mut context)
                .map_err(provider_execution_error)?;
            let max_events = input_events.len().max(1);
            let mut batch = PluginEventBatch::new(plugin_id.clone(), max_events);
            for event in input_events {
                batch.push(event).map_err(provider_execution_error)?;
            }
            let output = runtime
                .process_batch(&plugin_id, &mut context, &batch)
                .map_err(provider_execution_error)?;
            Ok(output.events)
        })
    }

    #[cfg(test)]
    fn run_lateral_movement_runtime(
        &self,
        input_events: Vec<EventEnvelope>,
    ) -> CommandResult<Vec<EventEnvelope>> {
        validate_lateral_movement_dag_route(self)?;
        let runtime_services = self
            .runtime_services
            .as_ref()
            .ok_or_else(|| provider_execution_error("runtime_services_unavailable"))?;
        runtime_services.with_plugin_runtime(|runtime| {
            let plugin_id =
                PluginId::parse_str(sentinel_capabilities::LATERAL_MOVEMENT_STATIC_PLUGIN_ID)
                    .map_err(provider_execution_error)?;
            let manifest = runtime
                .manifest(&plugin_id)
                .ok_or_else(|| provider_execution_error("lateral_movement_manifest_missing"))?
                .clone();
            let contracts = runtime_contract_registry_for_manifest(&manifest)?;
            let mut permissions = PermissionResolver::new();
            permissions.register_plugin_manifest_permissions(&manifest);
            let validation = runtime
                .registry()
                .validate_startup(&plugin_id, &contracts, &permissions)
                .map_err(provider_execution_error)?;
            let mut context =
                runtime_plugin_context_for_manifest(&manifest, TraceContext::new_root())?;
            context.policy_scope = PolicyScope::Plugin;
            runtime
                .start_plugin(&plugin_id, &validation, &mut context)
                .map_err(provider_execution_error)?;
            let max_events = input_events.len().max(1);
            let mut batch = PluginEventBatch::new(plugin_id.clone(), max_events);
            for event in input_events {
                batch.push(event).map_err(provider_execution_error)?;
            }
            let output = runtime
                .process_batch(&plugin_id, &mut context, &batch)
                .map_err(provider_execution_error)?;
            Ok(output.events)
        })
    }

    fn run_auth_identity_analysis_runtime(
        &self,
        input_events: Vec<EventEnvelope>,
    ) -> CommandResult<Vec<EventEnvelope>> {
        let runtime_services = self
            .runtime_services
            .as_ref()
            .ok_or_else(|| provider_execution_error("runtime_services_unavailable"))?;
        runtime_services.with_plugin_runtime(|runtime| {
            let plugin_id = PluginId::parse_str(AUTH_IDENTITY_ANALYSIS_LITE_STATIC_PLUGIN_ID)
                .map_err(provider_execution_error)?;
            let manifest = runtime
                .manifest(&plugin_id)
                .ok_or_else(|| provider_execution_error("auth_identity_analysis_manifest_missing"))?
                .clone();
            let contracts = runtime_contract_registry_for_manifest(&manifest)?;
            let mut permissions = PermissionResolver::new();
            permissions.register_plugin_manifest_permissions(&manifest);
            let validation = runtime
                .registry()
                .validate_startup(&plugin_id, &contracts, &permissions)
                .map_err(provider_execution_error)?;
            let mut context =
                runtime_plugin_context_for_manifest(&manifest, TraceContext::new_root())?;
            context.policy_scope = PolicyScope::Plugin;
            runtime
                .start_plugin(&plugin_id, &validation, &mut context)
                .map_err(provider_execution_error)?;
            let max_events = input_events.len().max(1);
            let mut batch = PluginEventBatch::new(plugin_id.clone(), max_events);
            for event in input_events {
                batch.push(event).map_err(provider_execution_error)?;
            }
            let output = runtime
                .process_batch(&plugin_id, &mut context, &batch)
                .map_err(provider_execution_error)?;
            Ok(output.events)
        })
    }

    fn run_remote_admin_runtime(
        &self,
        input_events: Vec<EventEnvelope>,
    ) -> CommandResult<Vec<EventEnvelope>> {
        let runtime_services = self
            .runtime_services
            .as_ref()
            .ok_or_else(|| provider_execution_error("runtime_services_unavailable"))?;
        runtime_services.with_plugin_runtime(|runtime| {
            let plugin_id = PluginId::parse_str(REMOTE_ADMIN_PROTOCOL_LITE_STATIC_PLUGIN_ID)
                .map_err(provider_execution_error)?;
            let manifest = runtime
                .manifest(&plugin_id)
                .ok_or_else(|| provider_execution_error("remote_admin_lite_manifest_missing"))?
                .clone();
            let contracts = runtime_contract_registry_for_manifest(&manifest)?;
            let mut permissions = PermissionResolver::new();
            permissions.register_plugin_manifest_permissions(&manifest);
            let validation = runtime
                .registry()
                .validate_startup(&plugin_id, &contracts, &permissions)
                .map_err(provider_execution_error)?;
            let mut context =
                runtime_plugin_context_for_manifest(&manifest, TraceContext::new_root())?;
            context.policy_scope = PolicyScope::Plugin;
            runtime
                .start_plugin(&plugin_id, &validation, &mut context)
                .map_err(provider_execution_error)?;
            let max_events = input_events.len().max(1);
            let mut batch = PluginEventBatch::new(plugin_id.clone(), max_events);
            for event in input_events {
                batch.push(event).map_err(provider_execution_error)?;
            }
            let output = runtime
                .process_batch(&plugin_id, &mut context, &batch)
                .map_err(provider_execution_error)?;
            Ok(output.events)
        })
    }

    fn run_multi_layer_fusion_runtime(
        &self,
        input_events: Vec<EventEnvelope>,
    ) -> CommandResult<Vec<EventEnvelope>> {
        let runtime_services = self
            .runtime_services
            .as_ref()
            .ok_or_else(|| provider_execution_error("runtime_services_unavailable"))?;
        runtime_services.with_plugin_runtime(|runtime| {
            let plugin_id = PluginId::parse_str(MULTI_LAYER_SECURITY_FUSION_STATIC_PLUGIN_ID)
                .map_err(provider_execution_error)?;
            let manifest = runtime
                .manifest(&plugin_id)
                .ok_or_else(|| provider_execution_error("multi_layer_fusion_manifest_missing"))?
                .clone();
            let contracts = runtime_contract_registry_for_manifest(&manifest)?;
            let mut permissions = PermissionResolver::new();
            permissions.register_plugin_manifest_permissions(&manifest);
            let validation = runtime
                .registry()
                .validate_startup(&plugin_id, &contracts, &permissions)
                .map_err(provider_execution_error)?;
            let mut context =
                runtime_plugin_context_for_manifest(&manifest, TraceContext::new_root())?;
            context.policy_scope = PolicyScope::Plugin;
            runtime
                .start_plugin(&plugin_id, &validation, &mut context)
                .map_err(provider_execution_error)?;
            let max_events = input_events.len().max(1);
            let mut batch = PluginEventBatch::new(plugin_id.clone(), max_events);
            for event in input_events {
                batch.push(event).map_err(provider_execution_error)?;
            }
            let output = runtime
                .process_batch(&plugin_id, &mut context, &batch)
                .map_err(provider_execution_error)?;
            Ok(output.events)
        })
    }

    fn publish_container_payload<T: serde::Serialize>(
        &self,
        topic: &str,
        payload: &T,
        summary: &str,
    ) -> CommandResult<()> {
        let envelope = runtime_handoff_event(
            &PluginId::new_v4(),
            topic,
            payload,
            sentinel_contracts::NATIVE_NETWORK_SCHEMA_VERSION,
            quality_score(0.7),
            &TraceContext::new_root(),
        )?;
        self.publish_container_envelope(topic, envelope, summary)
    }

    fn publish_container_envelope(
        &self,
        topic: &str,
        envelope: EventEnvelope,
        summary: &str,
    ) -> CommandResult<()> {
        let event_bus = self
            .event_bus
            .as_ref()
            .ok_or_else(|| provider_execution_error("event_bus_unavailable"))?;
        event_bus
            .publish(
                TopicName::new(topic).map_err(provider_execution_error)?,
                envelope,
                PublishOptions::new(summary),
            )
            .map_err(provider_execution_error)?;
        Ok(())
    }

    pub fn plugin_registration_count(&self) -> usize {
        self.plugin_runtime
            .as_ref()
            .map(RuntimePluginHandle::registration_count)
            .unwrap_or_default()
    }

    pub fn topic_count(&self) -> usize {
        self.event_bus
            .as_ref()
            .map(RuntimeEventBusHandle::topic_count)
            .unwrap_or_default()
    }

    pub fn scheduler_starts_disabled(&self) -> bool {
        self.app_core_orchestration
            .as_ref()
            .is_some_and(MutationCommandState::native_scheduler_starts_disabled)
    }

    pub fn scheduler_host_starts_stopped(&self) -> bool {
        self.app_core_orchestration
            .as_ref()
            .is_some_and(MutationCommandState::native_scheduler_host_starts_stopped)
    }

    pub fn samplers_start_inactive(&self) -> bool {
        self.app_core_orchestration
            .as_ref()
            .is_some_and(MutationCommandState::native_samplers_start_inactive)
    }

    pub fn startup_side_effect_count(&self) -> usize {
        self.app_core_orchestration
            .as_ref()
            .map(MutationCommandState::startup_side_effect_count)
            .unwrap_or_default()
    }

    pub fn actual_runtime_component_count(&self) -> usize {
        self.event_bus_count()
            + self.dag_count()
            + self.plugin_runtime_count()
            + self.capability_registry_count()
            + self.app_core_orchestration_count()
            + self.portable_runtime_orchestration_count()
            + self.native_permission_runtime_count()
            + self.scheduler_controller_count()
            + self.scheduler_host_owner_count()
            + self.sampler_runtime_count()
            + self.endpoint_threat_runtime_count()
            + self.fusion_state_count()
            + self.evidence_quality_state_count()
            + self.risk_state_count()
            + self.attack_context_state_count()
            + self.graph_state_count()
            + self.baseline_state_count()
            + self.incident_linking_state_count()
            + self.read_model_store_count()
            + self.report_export_traceability_state_count()
    }

    pub fn endpoint_runtime_finding_count(&self) -> u32 {
        self.endpoint_threat_runtime
            .as_ref()
            .map(|runtime| runtime.summary.finding_count)
            .unwrap_or_default()
    }

    pub fn fusion_runtime_engine_count(&self) -> usize {
        self.fusion_runtime
            .as_ref()
            .map(|runtime| {
                let _plugin = &runtime.plugin;
                1
            })
            .unwrap_or_default()
    }

    pub fn evidence_quality_record_count(&self) -> usize {
        self.evidence_quality_runtime
            .as_ref()
            .map(|runtime| runtime.summary.records.len())
            .unwrap_or_default()
    }

    pub fn risk_runtime_engine_count(&self) -> usize {
        self.risk_runtime
            .as_ref()
            .map(|runtime| {
                let _plugin = &runtime.plugin;
                1
            })
            .unwrap_or_default()
    }

    pub fn attack_context_row_count(&self) -> usize {
        self.attack_context_runtime
            .as_ref()
            .map(|runtime| runtime.summary.technique_rows.len())
            .unwrap_or_default()
    }

    pub fn graph_runtime_engine_count(&self) -> usize {
        self.graph_runtime
            .as_ref()
            .map(|runtime| {
                let _stage = &runtime.stage_plugin;
                let _analytics = &runtime.analytics_service;
                2
            })
            .unwrap_or_default()
    }

    pub fn baseline_record_count(&self) -> usize {
        self.baseline_runtime
            .as_ref()
            .map(|runtime| runtime.summary.records.len())
            .unwrap_or_default()
    }

    pub fn incident_linked_group_count(&self) -> usize {
        self.incident_linking_runtime
            .as_ref()
            .map(|runtime| runtime.linked_group_count)
            .unwrap_or_default()
    }

    pub fn report_export_traceability_ref_count(&self) -> usize {
        self.report_export_traceability
            .as_ref()
            .map(|runtime| runtime.report_ref_count + runtime.export_ref_count)
            .unwrap_or_default()
    }

    pub fn canonical_report_export_traceability(
        &self,
    ) -> Option<&CanonicalReportExportTraceabilitySnapshot> {
        self.report_export_traceability
            .as_ref()
            .map(|runtime| &runtime.traceability)
    }

    pub fn phase_0b_closure_summary(&self) -> Phase0BClosureSummary {
        let summary = self.summary();
        let legacy_constructor_violations = legacy_runtime_constructor_inventory()
            .iter()
            .filter(|entry| {
                entry.current_classification
                    == crate::runtime_architecture::RuntimeConstructorClassification::ArchitectureViolation
            })
            .count();
        Phase0BClosureSummary {
            legacy_constructor_violations,
            servicehost_canonical_read_model_owner: summary.canonical_read_model_owner
                == "service_host",
            desktop_canonical_owner: false,
            desktop_storage_writer: false,
            servicehost_mutable_writer_count: self.storage_writer_count(),
            disconnect_replacement_runtime_count: 0,
            read_only_ipc_side_effects: 0,
            provider_call_count: summary.provider_call_count,
            provider_zero: summary.provider_zero,
            mutation_trust_state: summary.mutation_trust_state,
            mutation_commands_enabled: summary.mutation_commands_enabled,
            response_execution_state: "unavailable".to_string(),
            automatic_llm_state: "forbidden".to_string(),
        }
    }

    pub fn summary(&self) -> RuntimeOwnershipSummary {
        let storage_owner_state = self
            .storage_ownership_status()
            .map(|status| status.writer_state_str().to_string())
            .unwrap_or_else(|| "released".to_string());
        RuntimeOwnershipSummary {
            ownership_ref: self.owner_context.ownership_ref.clone(),
            ownership_epoch: self.owner_context.ownership_epoch,
            runtime_mode: self.owner_context.runtime_mode,
            owner_category: self.owner_context.owner_category,
            runtime_health: self.runtime_health,
            transition_state: self.transition_state,
            protocol_version: RUNTIME_OWNERSHIP_PROTOCOL_VERSION,
            schema_version: RUNTIME_OWNERSHIP_SCHEMA_VERSION,
            degraded_reason: None,
            mutation_trust_state: RuntimeMutationTrustState::ImpersonationNotImplemented,
            mutation_commands_enabled: false,
            provider_controller_state: self.provider_controller.state().to_string(),
            provider_call_count: self.provider_controller.provider_call_count(),
            provider_zero: self.provider_controller.provider_zero(),
            scheduler_state: self.component_state(RuntimeComponentCategory::NativeScheduler),
            scheduler_host_state: self
                .component_state(RuntimeComponentCategory::NativeSchedulerHost),
            sampler_state: self.component_state(RuntimeComponentCategory::NativeSamplers),
            storage_owner_state,
            canonical_read_model_owner: if self.shutdown_coordinator.shutdown_completed {
                "released".to_string()
            } else if self.canonical_read_model_store.is_some() {
                "service_host".to_string()
            } else {
                "none".to_string()
            },
            snapshot_freshness: if self.shutdown_coordinator.shutdown_completed {
                "finalized".to_string()
            } else if self.shutdown_coordinator.shutdown_started {
                "shutdown_in_progress".to_string()
            } else if self.canonical_read_model_store.is_some() {
                "fresh".to_string()
            } else {
                "unavailable".to_string()
            },
            shutdown: self.shutdown_coordinator.summary.clone(),
            component_summaries: self.component_summaries.clone(),
            audit_refs: self
                .audit_events
                .iter()
                .take(MAX_RUNTIME_OWNERSHIP_AUDIT_REFS)
                .map(|event| event.event_id.clone())
                .collect(),
            provenance_id: RUNTIME_CONTAINER_PROVENANCE.to_string(),
            time_bucket: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn audit_events(&self) -> &[RuntimeOwnershipAuditEvent] {
        &self.audit_events
    }

    pub fn shutdown(&mut self) -> CommandResult<RuntimeOwnershipSummary> {
        if self.shutdown_coordinator.shutdown_completed {
            return Ok(self.summary());
        }
        self.shutdown_before_ipc_close()?;
        self.complete_shutdown_after_ipc_close()
    }

    pub fn shutdown_before_ipc_close(&mut self) -> CommandResult<RuntimeOwnershipSummary> {
        if self.shutdown_coordinator.shutdown_completed
            || self.shutdown_coordinator.shutdown_started
        {
            return Ok(self.summary());
        }
        if let Some(orchestration) = self.app_core_orchestration.as_mut() {
            orchestration.invalidate_runtime_mutation_lease_for_shutdown();
        }
        if self.owner_context.owner_category == RuntimeOwnerCategory::ServiceHost
            && self.owner_context.runtime_mode == RuntimeMode::ServiceOwned
        {
            let owner_context = self.owner_context.clone();
            if let Err(error) = self.invalidate_ip_helper_schedule_for_session_end(
                &owner_context,
                IP_HELPER_SCHEDULE_SESSION_INVALIDATED,
                "servicehost_shutdown",
            ) {
                self.audit(
                    RuntimeOwnershipAuditEventKind::RuntimeShutdownStarted,
                    Some(RuntimeComponentCategory::ProviderController),
                    "degraded",
                    Some(format!(
                        "ip_helper_schedule_shutdown_invalidation_{}",
                        error.error_code
                    )),
                );
            }
        }
        self.shutdown_coordinator.started_at = Some(Instant::now());
        self.shutdown_coordinator.summary.state = RuntimeShutdownState::InProgress;
        self.shutdown_coordinator.shutdown_started = true;

        let stage_started = Instant::now();
        self.transition_state = RuntimeTransitionState::ShuttingDown;
        self.runtime_health = RuntimeHealthState::Degraded;
        self.complete_shutdown_stage(RuntimeShutdownStage::RejectMutations, stage_started, None)?;

        let stage_started = Instant::now();
        if self.ownership_lease.production_lock {
            RuntimeOwnershipGuard::mark_shutdown(&self.owner_context).map_err(CoreError::from)?;
        }
        self.audit(
            RuntimeOwnershipAuditEventKind::RuntimeShutdownStarted,
            None,
            "started",
            None,
        );
        self.complete_shutdown_stage(
            RuntimeShutdownStage::ShutdownInProgress,
            stage_started,
            None,
        )?;

        let stage_started = Instant::now();
        self.shutdown_coordinator
            .summary
            .mutation_leases_invalidated = true;
        self.complete_shutdown_stage(
            RuntimeShutdownStage::InvalidateMutationLeases,
            stage_started,
            None,
        )?;

        let stage_started = Instant::now();
        self.shutdown_coordinator
            .summary
            .scheduler_host_cancellation_signalled = true;
        self.complete_shutdown_stage(
            RuntimeShutdownStage::SignalSchedulerHostCancellation,
            stage_started,
            Some("scheduler_host_inactive_no_detached_task"),
        )?;

        let stage_started = Instant::now();
        self.stop_component(RuntimeComponentCategory::NativeSchedulerHost);
        self.shutdown_coordinator.summary.scheduler_host_joined = true;
        self.complete_shutdown_stage(
            RuntimeShutdownStage::JoinSchedulerHost,
            stage_started,
            Some("scheduler_host_joined_or_already_stopped"),
        )?;

        let stage_started = Instant::now();
        self.stop_component(RuntimeComponentCategory::NativeScheduler);
        self.complete_shutdown_stage(RuntimeShutdownStage::DisableScheduler, stage_started, None)?;

        let stage_started = Instant::now();
        self.stop_component(RuntimeComponentCategory::NativeSamplers);
        self.stop_component(RuntimeComponentCategory::NativePermissions);
        if let Some(mut ssh_runtime) = self.ssh_operational_sensing_lifecycle_runtime.take() {
            let should_join = ssh_runtime.status().control_thread_active;
            if should_join {
                let lifecycle = ssh_runtime
                    .shutdown_join()
                    .map_err(provider_execution_error)?;
                self.provider_controller
                    .record_ssh_operational_sensing_lifecycle(
                        &self.owner_context.clone(),
                        lifecycle,
                    )?;
                self.shutdown_coordinator.summary.provider_stop_called = true;
            }
        }
        if let Some(mut smb_runtime) = self.smb_operational_sensing_lifecycle_runtime.take() {
            let should_join = smb_runtime.status().control_thread_active;
            if should_join {
                let lifecycle = smb_runtime
                    .shutdown_join()
                    .map_err(provider_execution_error)?;
                self.provider_controller
                    .record_smb_operational_sensing_lifecycle(
                        &self.owner_context.clone(),
                        lifecycle,
                    )?;
                self.shutdown_coordinator.summary.provider_stop_called = true;
            }
        }
        if let Some(mut rdp_runtime) = self.rdp_operational_sensing_lifecycle_runtime.take() {
            let should_join = rdp_runtime.status().control_thread_active;
            if should_join {
                let lifecycle = rdp_runtime
                    .shutdown_join()
                    .map_err(provider_execution_error)?;
                self.provider_controller
                    .record_rdp_operational_sensing_lifecycle(
                        &self.owner_context.clone(),
                        lifecycle,
                    )?;
                self.shutdown_coordinator.summary.provider_stop_called = true;
            }
        }
        if let Some(mut auth_remote_runtime) = self.auth_remote_sensing_lifecycle_runtime.take() {
            let should_join = auth_remote_runtime.status().control_thread_active;
            if should_join {
                let lifecycle = auth_remote_runtime
                    .shutdown_join()
                    .map_err(provider_execution_error)?;
                self.provider_controller
                    .record_auth_remote_sensing_lifecycle(&self.owner_context.clone(), lifecycle)?;
                self.shutdown_coordinator.summary.provider_stop_called = true;
            }
        }
        if let Some(mut dns_runtime) = self.dns_sensing_lifecycle_runtime.take() {
            let should_join = dns_runtime.status().control_thread_active;
            if should_join {
                let lifecycle = dns_runtime
                    .shutdown_join()
                    .map_err(provider_execution_error)?;
                self.provider_controller
                    .record_dns_sensing_lifecycle(&self.owner_context.clone(), lifecycle)?;
                self.shutdown_coordinator.summary.provider_stop_called = true;
            }
        }
        if let Some(mut etw_runtime) = self.etw_lifecycle_runtime.take() {
            let should_join = etw_runtime.status().control_thread_active;
            if should_join {
                let fallback_state = self.etw_fallback_state();
                let lifecycle = etw_runtime
                    .shutdown_join(fallback_state)
                    .map_err(provider_execution_error)?;
                self.provider_controller
                    .record_etw_lifecycle(&self.owner_context.clone(), lifecycle)?;
                self.shutdown_coordinator.summary.provider_stop_called = true;
            }
        }
        self.complete_shutdown_stage(RuntimeShutdownStage::StopSamplers, stage_started, None)?;

        let stage_started = Instant::now();
        self.stop_component(RuntimeComponentCategory::PortableReaders);
        self.complete_shutdown_stage(
            RuntimeShutdownStage::StopPortableReaders,
            stage_started,
            None,
        )?;

        let stage_started = Instant::now();
        for component in [
            RuntimeComponentCategory::EndpointThreat,
            RuntimeComponentCategory::Fusion,
            RuntimeComponentCategory::EvidenceQuality,
            RuntimeComponentCategory::Risk,
            RuntimeComponentCategory::AttackContext,
            RuntimeComponentCategory::Graph,
            RuntimeComponentCategory::Baseline,
            RuntimeComponentCategory::IncidentLinking,
        ] {
            self.stop_component(component);
        }
        self.incident_linking_runtime = None;
        self.baseline_runtime = None;
        self.graph_runtime = None;
        self.attack_context_runtime = None;
        self.risk_runtime = None;
        self.evidence_quality_runtime = None;
        self.fusion_runtime = None;
        self.endpoint_threat_runtime = None;
        self.complete_shutdown_stage(
            RuntimeShutdownStage::CancelAnalysisWork,
            stage_started,
            None,
        )?;

        let stage_started = Instant::now();
        self.complete_shutdown_stage(
            RuntimeShutdownStage::DrainEventBus,
            stage_started,
            Some("bounded_no_background_backlog"),
        )?;

        let stage_started = Instant::now();
        self.stop_component(RuntimeComponentCategory::PluginRuntime);
        self.plugin_runtime = None;
        self.complete_shutdown_stage(RuntimeShutdownStage::StopPluginRuntime, stage_started, None)?;

        let stage_started = Instant::now();
        self.stop_component(RuntimeComponentCategory::Dag);
        self.pipeline_dag = None;
        self.complete_shutdown_stage(RuntimeShutdownStage::StopDag, stage_started, None)?;

        let stage_started = Instant::now();
        self.stop_component(RuntimeComponentCategory::EventBus);
        self.stop_component(RuntimeComponentCategory::TopicCatalog);
        self.runtime_services = None;
        self.event_bus = None;
        self.complete_shutdown_stage(RuntimeShutdownStage::CloseEventBus, stage_started, None)?;

        let stage_started = Instant::now();
        for component in [
            RuntimeComponentCategory::ReportTraceability,
            RuntimeComponentCategory::ExportTraceability,
            RuntimeComponentCategory::ReadModels,
        ] {
            self.stop_component(component);
        }
        self.report_export_traceability = None;
        self.complete_shutdown_stage(
            RuntimeShutdownStage::FinalizeCanonicalReadModels,
            stage_started,
            None,
        )?;

        let stage_started = Instant::now();
        if let Some(storage_writer) = self.storage_writer.take() {
            storage_writer.release();
            self.audit(
                RuntimeOwnershipAuditEventKind::StorageOwnerReleased,
                Some(RuntimeComponentCategory::ReadModels),
                "released",
                Some("storage_closed_before_ownership_release".to_string()),
            );
        }
        self.complete_shutdown_stage(
            RuntimeShutdownStage::CloseStorageWriter,
            stage_started,
            None,
        )?;

        let stage_started = Instant::now();
        self.app_core_orchestration = None;
        self.complete_shutdown_stage(
            RuntimeShutdownStage::ClearServiceSessionState,
            stage_started,
            None,
        )?;

        let stage_started = Instant::now();
        self.ownership_lease.release();
        self.transition_state = RuntimeTransitionState::Released;
        self.complete_shutdown_stage(
            RuntimeShutdownStage::ReleaseOwnershipGuard,
            stage_started,
            None,
        )?;
        Ok(self.summary())
    }

    pub fn complete_shutdown_after_ipc_close(&mut self) -> CommandResult<RuntimeOwnershipSummary> {
        if self.shutdown_coordinator.shutdown_completed {
            return Ok(self.summary());
        }
        if !self.shutdown_coordinator.shutdown_started {
            self.shutdown_before_ipc_close()?;
        }
        let stage_started = Instant::now();
        self.complete_shutdown_stage(RuntimeShutdownStage::CloseIpc, stage_started, None)?;

        let stage_started = Instant::now();
        self.runtime_health = RuntimeHealthState::Stopped;
        self.shutdown_coordinator.summary.state = RuntimeShutdownState::Completed;
        self.shutdown_coordinator.shutdown_completed = true;
        self.complete_shutdown_stage(RuntimeShutdownStage::Stopped, stage_started, None)?;
        self.audit(
            RuntimeOwnershipAuditEventKind::RuntimeShutdownCompleted,
            None,
            "completed",
            None,
        );
        self.shutdown_coordinator.summary.audit_refs = self
            .audit_events
            .iter()
            .rev()
            .take(MAX_RUNTIME_OWNERSHIP_AUDIT_REFS)
            .map(|event| event.event_id.clone())
            .collect();
        Ok(self.summary())
    }

    fn complete_shutdown_stage(
        &mut self,
        stage: RuntimeShutdownStage,
        started_at: Instant,
        reason_category: Option<&str>,
    ) -> CommandResult<()> {
        let elapsed = started_at.elapsed();
        let total_elapsed = self
            .shutdown_coordinator
            .started_at
            .map(|started| started.elapsed())
            .unwrap_or_default();
        let timed_out = elapsed > SHUTDOWN_STAGE_TIMEOUT || total_elapsed > SHUTDOWN_TOTAL_TIMEOUT;
        self.shutdown_coordinator
            .summary
            .stages
            .push(RuntimeShutdownStageSummary {
                stage,
                state: if timed_out {
                    RuntimeShutdownStageState::TimedOut
                } else {
                    RuntimeShutdownStageState::Completed
                },
                timeout_bucket: "under_2_seconds".to_string(),
                duration_bucket: duration_bucket(elapsed).to_string(),
                reason_category: reason_category.map(ToString::to_string),
                audit_refs: Vec::new(),
                redaction_status: RedactionStatus::Redacted,
            });
        if timed_out {
            self.shutdown_coordinator.summary.state = RuntimeShutdownState::TimedOut;
            self.runtime_health = RuntimeHealthState::Failed;
            self.transition_state = RuntimeTransitionState::Failed;
            self.audit(
                RuntimeOwnershipAuditEventKind::RuntimeShutdownTimeout,
                None,
                "timed_out",
                Some("bounded_shutdown_timeout".to_string()),
            );
            return Err(init_error("bounded_shutdown_timeout"));
        }
        Ok(())
    }

    fn component_state(&self, component: RuntimeComponentCategory) -> String {
        self.component_summaries
            .iter()
            .find(|summary| summary.component_category == component)
            .map(|summary| format!("{:?}", summary.component_lifecycle).to_ascii_lowercase())
            .unwrap_or_else(|| "not_initialized".to_string())
    }

    fn stop_component(&mut self, component: RuntimeComponentCategory) {
        if let Some(summary) = self
            .component_summaries
            .iter_mut()
            .find(|summary| summary.component_category == component)
        {
            if summary.component_lifecycle != RuntimeComponentLifecycle::Stopped {
                summary.component_lifecycle = RuntimeComponentLifecycle::Stopped;
                summary.runtime_health = RuntimeHealthState::Stopped;
                summary.time_bucket = Timestamp::now();
                self.shutdown_coordinator.stopped_components.push(component);
                self.audit(
                    RuntimeOwnershipAuditEventKind::RuntimeComponentStopped,
                    Some(component),
                    "stopped",
                    None,
                );
            }
        }
    }

    fn audit(
        &mut self,
        event_kind: RuntimeOwnershipAuditEventKind,
        component_category: Option<RuntimeComponentCategory>,
        result_category: impl Into<String>,
        reason_category: Option<String>,
    ) {
        self.audit_events.push(RuntimeOwnershipAuditEvent {
            event_id: AuditId::new_v4(),
            event_kind,
            runtime_mode: self.owner_context.runtime_mode,
            owner_category: self.owner_context.owner_category,
            component_category,
            previous_lifecycle: None,
            new_lifecycle: component_category.and_then(|component| {
                self.component_summaries
                    .iter()
                    .find(|summary| summary.component_category == component)
                    .map(|summary| summary.component_lifecycle)
            }),
            result_category: result_category.into(),
            reason_category,
            time_bucket: Timestamp::now(),
            audit_refs: Vec::new(),
            provenance_id: RUNTIME_CONTAINER_PROVENANCE.to_string(),
            redaction_status: RedactionStatus::Redacted,
        });
    }
}

pub struct RuntimeContainerBuilder {
    context: RuntimeOwnerContext,
    explicit_portable_fallback: bool,
}

impl RuntimeContainerBuilder {
    pub fn for_service_host() -> Self {
        let epoch = next_epoch();
        let ownership_ref = format!("runtime-owner-{}", Uuid::new_v4());
        Self {
            context: RuntimeOwnerContext::service_host(
                ownership_ref,
                epoch,
                SERVICE_HOST_INSTANCE_REF,
            ),
            explicit_portable_fallback: false,
        }
    }

    pub fn for_service_host_context(context: RuntimeOwnerContext) -> Self {
        Self {
            context,
            explicit_portable_fallback: false,
        }
    }

    pub fn for_portable_fallback(explicit: bool) -> Self {
        let epoch = next_epoch();
        let ownership_ref = format!("portable-owner-{}", Uuid::new_v4());
        Self {
            context: RuntimeOwnerContext::portable_fallback(ownership_ref, epoch),
            explicit_portable_fallback: explicit,
        }
    }

    pub fn for_test(label: &str) -> Self {
        let epoch = next_epoch();
        let ownership_ref = format!("test-owner-{label}-{}", Uuid::new_v4());
        Self {
            context: RuntimeOwnerContext::test_harness(ownership_ref, epoch),
            explicit_portable_fallback: false,
        }
    }

    pub fn build(self) -> CommandResult<RuntimeContainer> {
        if self.context.runtime_mode == RuntimeMode::PortableInProcess
            && self.context.owner_category == RuntimeOwnerCategory::DesktopPortable
            && !self.explicit_portable_fallback
        {
            return Err(CoreError::from(
                RuntimeOwnershipError::PortableFallbackNotAuthorized,
            ));
        }
        let provider_controller = ProviderControllerShell::inactive_for(&self.context)?;
        let lease =
            RuntimeOwnershipGuard::acquire(self.context.clone()).map_err(CoreError::from)?;
        let mut container = RuntimeContainer {
            owner_context: self.context,
            ownership_lease: lease,
            storage_writer: None,
            durable_storage_manifest: service_host_durable_storage_manifest(),
            storage_recovery_report: None,
            event_bus: None,
            runtime_services: None,
            pipeline_dag: None,
            plugin_runtime: None,
            app_core_orchestration: None,
            endpoint_threat_runtime: None,
            fusion_runtime: None,
            evidence_quality_runtime: None,
            risk_runtime: None,
            attack_context_runtime: None,
            graph_runtime: None,
            baseline_runtime: None,
            incident_linking_runtime: None,
            report_export_traceability: None,
            canonical_read_model_store: None,
            etw_lifecycle_runtime: None,
            dns_sensing_lifecycle_runtime: None,
            auth_remote_sensing_lifecycle_runtime: None,
            rdp_operational_sensing_lifecycle_runtime: None,
            smb_operational_sensing_lifecycle_runtime: None,
            ssh_operational_sensing_lifecycle_runtime: None,
            component_summaries: Vec::new(),
            audit_events: Vec::new(),
            provider_controller,
            ip_helper_execution_active: false,
            ip_helper_scheduled_sample_count: 0,
            ip_helper_scheduled_skip_count: 0,
            ip_helper_scheduled_retry_count: 0,
            ip_helper_scheduled_overlap_skip_count: 0,
            ip_helper_next_due_monotonic_millis: None,
            ip_helper_schedule_wake_pending: false,
            ip_helper_seen_cycle_refs: Vec::new(),
            #[cfg(test)]
            ip_helper_scheduler_test_fault: None,
            shutdown_coordinator: RuntimeShutdownCoordinator::new(),
            runtime_health: RuntimeHealthState::Unknown,
            transition_state: RuntimeTransitionState::Initializing,
        };
        container.audit(
            RuntimeOwnershipAuditEventKind::RuntimeContainerInitializationStarted,
            None,
            "started",
            None,
        );
        if let Err(error) = container.initialize() {
            container.rollback_partial_initialization();
            return Err(error);
        }
        Ok(container)
    }

    pub fn build_portable_mutation_state(self) -> CommandResult<MutationCommandState> {
        self.build_portable_mutation_state_from_read(runtime_read_models()?)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn build_read_state_for_test(self) -> CommandResult<ReadOnlyCommandState> {
        if self.context.owner_category != RuntimeOwnerCategory::TestHarness {
            return Err(CoreError::from(RuntimeOwnershipError::TestOwnerRequired));
        }
        runtime_read_models()
    }

    #[cfg(test)]
    pub(crate) fn build_test_mutation_state_from_read(
        self,
        read: ReadOnlyCommandState,
    ) -> CommandResult<MutationCommandState> {
        if self.context.owner_category != RuntimeOwnerCategory::TestHarness {
            return Err(CoreError::from(RuntimeOwnershipError::TestOwnerRequired));
        }
        let lease =
            RuntimeOwnershipGuard::acquire(self.context.clone()).map_err(CoreError::from)?;
        let event_bus = RuntimeEventBusHandle::new_service_core_topics();
        let dag = runtime_pipeline_dag()?;
        let execution_plan = dag
            .build_execution_plan()
            .map_err(|_| init_error("dag_initialization_failed"))?;
        let mut plugin_runtime = PluginRuntime::new();
        register_static_bindings(&mut plugin_runtime)?;
        let services = RuntimeServices::for_container(
            self.context,
            event_bus,
            RuntimePluginHandle::new(plugin_runtime),
            execution_plan,
        )?;
        let mut state = MutationCommandState::from_runtime_services(read, services)?;
        state.attach_runtime_ownership_lease(lease);
        Ok(state)
    }

    pub fn build_portable_mutation_state_from_read(
        self,
        read: ReadOnlyCommandState,
    ) -> CommandResult<MutationCommandState> {
        if self.context.runtime_mode != RuntimeMode::PortableInProcess
            || self.context.owner_category != RuntimeOwnerCategory::DesktopPortable
            || !self.explicit_portable_fallback
        {
            return Err(CoreError::from(
                RuntimeOwnershipError::PortableFallbackNotAuthorized,
            ));
        }
        let lease =
            RuntimeOwnershipGuard::acquire(self.context.clone()).map_err(CoreError::from)?;
        let event_bus = RuntimeEventBusHandle::new_service_core_topics();
        let dag = runtime_pipeline_dag()?;
        let execution_plan = dag
            .build_execution_plan()
            .map_err(|_| init_error("dag_initialization_failed"))?;
        let mut plugin_runtime = PluginRuntime::new();
        register_static_bindings(&mut plugin_runtime)?;
        let services = RuntimeServices::for_container(
            self.context,
            event_bus,
            RuntimePluginHandle::new(plugin_runtime),
            execution_plan,
        )?;
        let mut state = MutationCommandState::from_runtime_services(read, services)?;
        state.attach_runtime_ownership_lease(lease);
        Ok(state)
    }
}

impl RuntimeContainer {
    fn rollback_partial_initialization(&mut self) {
        self.dns_sensing_lifecycle_runtime = None;
        self.auth_remote_sensing_lifecycle_runtime = None;
        self.rdp_operational_sensing_lifecycle_runtime = None;
        self.smb_operational_sensing_lifecycle_runtime = None;
        self.ssh_operational_sensing_lifecycle_runtime = None;
        self.etw_lifecycle_runtime = None;
        self.canonical_read_model_store = None;
        self.report_export_traceability = None;
        self.incident_linking_runtime = None;
        self.baseline_runtime = None;
        self.graph_runtime = None;
        self.attack_context_runtime = None;
        self.risk_runtime = None;
        self.evidence_quality_runtime = None;
        self.fusion_runtime = None;
        self.endpoint_threat_runtime = None;
        self.app_core_orchestration = None;
        self.plugin_runtime = None;
        self.pipeline_dag = None;
        self.runtime_services = None;
        self.event_bus = None;
        self.storage_recovery_report = None;
        if let Some(storage_writer) = self.storage_writer.take() {
            storage_writer.release();
        }
        self.ownership_lease.release();
        self.runtime_health = RuntimeHealthState::Failed;
        self.transition_state = RuntimeTransitionState::Failed;
    }

    fn initialize(&mut self) -> CommandResult<()> {
        self.validate_startup_configuration()?;

        let storage_writer =
            StorageWriterLease::acquire_service_host_runtime(self.owner_context.ownership_epoch)
                .map_err(storage_ownership_error)?;
        self.storage_recovery_report = Some(ServiceHostStorageRecoveryReport::from_status(
            &storage_writer.status(),
            &self.durable_storage_manifest,
            self.owner_context.ownership_epoch,
            true,
            None,
        ));
        self.storage_writer = Some(storage_writer);
        self.audit(
            RuntimeOwnershipAuditEventKind::StorageOwnerAcquired,
            Some(RuntimeComponentCategory::ReadModels),
            "acquired",
            Some("service_owned_runtime_stores".to_string()),
        );

        let event_bus = RuntimeEventBusHandle::new_service_core_topics();
        self.event_bus = Some(event_bus.clone());
        self.ready_component(
            RuntimeComponentCategory::EventBus,
            RuntimeHealthState::Ready,
        );
        self.ready_component(
            RuntimeComponentCategory::TopicCatalog,
            RuntimeHealthState::Ready,
        );

        let read_models = runtime_read_models()?;
        self.ready_component(
            RuntimeComponentCategory::CapabilityRegistry,
            RuntimeHealthState::Ready,
        );

        let pipeline_dag = runtime_pipeline_dag()?;
        let execution_plan = pipeline_dag
            .build_execution_plan()
            .map_err(|_| init_error("dag_initialization_failed"))?;
        self.pipeline_dag = Some(pipeline_dag);
        self.ready_component(RuntimeComponentCategory::Dag, RuntimeHealthState::Ready);

        let mut plugin_runtime = PluginRuntime::new();
        register_static_bindings(&mut plugin_runtime)?;
        let plugin_runtime = RuntimePluginHandle::new(plugin_runtime);
        self.plugin_runtime = Some(plugin_runtime.clone());
        let runtime_services = RuntimeServices::for_container(
            self.owner_context.clone(),
            event_bus.clone(),
            plugin_runtime,
            execution_plan,
        )?;
        self.ready_component(
            RuntimeComponentCategory::PluginRuntime,
            RuntimeHealthState::Ready,
        );

        let orchestration =
            MutationCommandState::from_runtime_services(read_models, runtime_services.clone())?;
        self.runtime_services = Some(runtime_services);
        self.app_core_orchestration = Some(orchestration);
        self.ready_component(
            RuntimeComponentCategory::PortableReaders,
            RuntimeHealthState::Ready,
        );
        self.ready_component(
            RuntimeComponentCategory::NativePermissions,
            RuntimeHealthState::Ready,
        );
        self.inactive_component(
            RuntimeComponentCategory::NativeScheduler,
            Some("scheduler_disabled_at_startup"),
        );
        self.stopped_component(
            RuntimeComponentCategory::NativeSchedulerHost,
            Some("scheduler_host_stopped_at_startup"),
        );
        self.inactive_component(
            RuntimeComponentCategory::NativeSamplers,
            Some("samplers_inactive_at_startup"),
        );

        let (
            endpoint_runtime,
            evidence_quality_runtime,
            attack_context_runtime,
            baseline_runtime,
            incident_linking_runtime,
            report_export_traceability,
        ) = {
            let read = self
                .app_core_orchestration
                .as_ref()
                .expect("orchestration initialized")
                .read_state();
            (
                ServiceOwnedEndpointThreatRuntime::new(read)?,
                ServiceOwnedEvidenceQualityRuntime::new(read)?,
                ServiceOwnedAttackContextRuntime::new(read)?,
                ServiceOwnedBaselineRuntime::new(read)?,
                ServiceOwnedIncidentLinkingRuntime::new(read)?,
                if self.owner_context.owner_category == RuntimeOwnerCategory::ServiceHost
                    && self.owner_context.runtime_mode == RuntimeMode::ServiceOwned
                {
                    Some(ServiceOwnedReportExportTraceability::new(
                        read,
                        &self.owner_context,
                    )?)
                } else {
                    None
                },
            )
        };
        self.endpoint_threat_runtime = Some(endpoint_runtime);
        self.ready_component(
            RuntimeComponentCategory::EndpointThreat,
            RuntimeHealthState::Ready,
        );
        self.fusion_runtime = Some(ServiceOwnedFusionRuntime::new());
        self.ready_component(RuntimeComponentCategory::Fusion, RuntimeHealthState::Ready);
        self.evidence_quality_runtime = Some(evidence_quality_runtime);
        self.ready_component(
            RuntimeComponentCategory::EvidenceQuality,
            RuntimeHealthState::Ready,
        );
        self.risk_runtime = Some(ServiceOwnedRiskRuntime::new());
        self.ready_component(RuntimeComponentCategory::Risk, RuntimeHealthState::Ready);
        self.attack_context_runtime = Some(attack_context_runtime);
        self.ready_component(
            RuntimeComponentCategory::AttackContext,
            RuntimeHealthState::Ready,
        );
        self.graph_runtime = Some(ServiceOwnedGraphRuntime::new());
        self.ready_component(RuntimeComponentCategory::Graph, RuntimeHealthState::Ready);
        self.baseline_runtime = Some(baseline_runtime);
        self.ready_component(
            RuntimeComponentCategory::Baseline,
            RuntimeHealthState::Ready,
        );
        self.incident_linking_runtime = Some(incident_linking_runtime);
        self.ready_component(
            RuntimeComponentCategory::IncidentLinking,
            RuntimeHealthState::Ready,
        );
        self.ready_component(
            RuntimeComponentCategory::ReadModels,
            RuntimeHealthState::Ready,
        );
        self.report_export_traceability = report_export_traceability;
        self.ready_component(
            RuntimeComponentCategory::ReportTraceability,
            RuntimeHealthState::Ready,
        );
        self.ready_component(
            RuntimeComponentCategory::ExportTraceability,
            RuntimeHealthState::Ready,
        );

        self.etw_lifecycle_runtime = Some(ServiceOwnedEtwLifecycleRuntime::new(
            &self.owner_context,
            EtwFallbackState::IpHelperAvailable,
        ));
        self.dns_sensing_lifecycle_runtime = Some(ServiceOwnedDnsSensingLifecycleRuntime::new(
            &self.owner_context,
        ));
        self.auth_remote_sensing_lifecycle_runtime = Some(
            ServiceOwnedAuthRemoteSensingLifecycleRuntime::new(&self.owner_context),
        );
        self.rdp_operational_sensing_lifecycle_runtime = Some(
            ServiceOwnedAuthRemoteSensingLifecycleRuntime::rdp_operational(&self.owner_context),
        );
        self.smb_operational_sensing_lifecycle_runtime = Some(
            ServiceOwnedAuthRemoteSensingLifecycleRuntime::smb_operational(&self.owner_context),
        );
        self.ssh_operational_sensing_lifecycle_runtime = Some(
            ServiceOwnedAuthRemoteSensingLifecycleRuntime::ssh_operational(&self.owner_context),
        );
        self.inactive_component(
            RuntimeComponentCategory::ProviderController,
            Some("provider_lifecycle_requires_explicit_authorization"),
        );
        self.runtime_health = RuntimeHealthState::Ready;
        self.transition_state = RuntimeTransitionState::Ready;
        self.publish_initial_canonical_read_model_snapshot()?;
        self.audit(
            RuntimeOwnershipAuditEventKind::RuntimeContainerReady,
            None,
            "ready",
            None,
        );
        self.summary()
            .validate()
            .map_err(|_| init_error("runtime_status_validation_failed"))?;
        Ok(())
    }

    fn validate_startup_configuration(&self) -> CommandResult<()> {
        self.owner_context
            .validate()
            .map_err(|_| init_error("startup_configuration_invalid"))?;
        Ok(())
    }

    fn ready_component(
        &mut self,
        component_category: RuntimeComponentCategory,
        health: RuntimeHealthState,
    ) {
        self.component_summaries
            .push(RuntimeComponentOwnershipSummary {
                ownership_ref: self.owner_context.ownership_ref.clone(),
                ownership_epoch: self.owner_context.ownership_epoch,
                runtime_mode: self.owner_context.runtime_mode,
                owner_category: self.owner_context.owner_category,
                component_category,
                component_lifecycle: RuntimeComponentLifecycle::Ready,
                runtime_health: health,
                degraded_reason: None,
                audit_refs: Vec::new(),
                provenance_id: RUNTIME_CONTAINER_PROVENANCE.to_string(),
                time_bucket: Timestamp::now(),
                redaction_status: RedactionStatus::Redacted,
            });
        self.audit(
            RuntimeOwnershipAuditEventKind::RuntimeComponentInitialized,
            Some(component_category),
            "ready",
            None,
        );
    }

    fn inactive_component(
        &mut self,
        component_category: RuntimeComponentCategory,
        degraded_reason: Option<&str>,
    ) {
        self.component_summaries
            .push(RuntimeComponentOwnershipSummary {
                ownership_ref: self.owner_context.ownership_ref.clone(),
                ownership_epoch: self.owner_context.ownership_epoch,
                runtime_mode: self.owner_context.runtime_mode,
                owner_category: self.owner_context.owner_category,
                component_category,
                component_lifecycle: RuntimeComponentLifecycle::Inactive,
                runtime_health: RuntimeHealthState::Inactive,
                degraded_reason: degraded_reason.map(ToString::to_string),
                audit_refs: Vec::new(),
                provenance_id: RUNTIME_CONTAINER_PROVENANCE.to_string(),
                time_bucket: Timestamp::now(),
                redaction_status: RedactionStatus::Redacted,
            });
        self.audit(
            RuntimeOwnershipAuditEventKind::RuntimeComponentInitialized,
            Some(component_category),
            "inactive",
            degraded_reason.map(ToString::to_string),
        );
    }

    fn stopped_component(
        &mut self,
        component_category: RuntimeComponentCategory,
        degraded_reason: Option<&str>,
    ) {
        self.component_summaries
            .push(RuntimeComponentOwnershipSummary {
                ownership_ref: self.owner_context.ownership_ref.clone(),
                ownership_epoch: self.owner_context.ownership_epoch,
                runtime_mode: self.owner_context.runtime_mode,
                owner_category: self.owner_context.owner_category,
                component_category,
                component_lifecycle: RuntimeComponentLifecycle::Stopped,
                runtime_health: RuntimeHealthState::Stopped,
                degraded_reason: degraded_reason.map(ToString::to_string),
                audit_refs: Vec::new(),
                provenance_id: RUNTIME_CONTAINER_PROVENANCE.to_string(),
                time_bucket: Timestamp::now(),
                redaction_status: RedactionStatus::Redacted,
            });
        self.audit(
            RuntimeOwnershipAuditEventKind::RuntimeComponentInitialized,
            Some(component_category),
            "stopped",
            degraded_reason.map(ToString::to_string),
        );
    }

    fn publish_initial_canonical_read_model_snapshot(&mut self) -> CommandResult<()> {
        if self.owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
            || self.owner_context.runtime_mode != RuntimeMode::ServiceOwned
        {
            return Ok(());
        }
        if let Some(traceability) = self.report_export_traceability.as_mut() {
            traceability.record_snapshot_ref("initial_snapshot_generation_00000001".to_string())?;
        }
        let items = self.canonical_read_model_items();
        let store = ServiceHostCanonicalReadModelStore::new(&self.owner_context, items)?;
        self.canonical_read_model_store = Some(store);
        Ok(())
    }

    pub fn publish_canonical_read_model_snapshot(
        &mut self,
        owner_context: &RuntimeOwnerContext,
    ) -> CommandResult<CanonicalReadModelSnapshot> {
        let items = self.canonical_read_model_items();
        let store = self
            .canonical_read_model_store
            .as_mut()
            .ok_or_else(|| init_error("canonical_read_model_store_unavailable"))?;
        store.publish(owner_context, items)
    }

    fn canonical_read_model_items(&self) -> Vec<CanonicalReadModelSnapshotItem> {
        let mut items = canonical_read_model_ownership_inventory()
            .iter()
            .map(|entry| self.canonical_read_model_item(entry.model_category, entry.blocker))
            .collect::<Vec<_>>();
        items.sort_by_key(|item| item.model_category);
        items
    }

    fn canonical_read_model_item(
        &self,
        category: CanonicalReadModelCategory,
        blocker: &'static str,
    ) -> CanonicalReadModelSnapshotItem {
        let (lifecycle_state, health_state) = self.read_model_lifecycle_health(category);
        let mut bounded_categories = vec![
            read_model_category_label(category).to_string(),
            "servicehost_canonical".to_string(),
        ];
        let mut bounded_buckets = vec![
            format!("{:?}", lifecycle_state).to_ascii_lowercase(),
            format!("{:?}", health_state).to_ascii_lowercase(),
            count_bucket(self.read_model_count_for_category(category)).to_string(),
        ];
        let mut bounded_refs = vec![read_model_ref_label(category).to_string()];
        match category {
            CanonicalReadModelCategory::RuntimeOwnership => {
                bounded_buckets.push(format!("{:?}", self.transition_state).to_ascii_lowercase());
                bounded_refs.push("runtime_ownership_summary_ref".to_string());
            }
            CanonicalReadModelCategory::RuntimeHealth => {
                bounded_buckets.push(format!("{:?}", self.runtime_health).to_ascii_lowercase());
                bounded_refs.push("runtime_health_summary_ref".to_string());
            }
            CanonicalReadModelCategory::ComponentLifecycleHealth => {
                bounded_buckets.push(count_bucket(self.component_summaries.len()).to_string());
                bounded_refs.push("component_ownership_summary_ref".to_string());
            }
            CanonicalReadModelCategory::StorageOwnerSummary => {
                let storage_state = self
                    .storage_ownership_status()
                    .map(|status| status.writer_state_str().to_string())
                    .unwrap_or_else(|| "released".to_string());
                bounded_categories.push(storage_state);
                bounded_refs.push("storage_owner_summary_ref".to_string());
            }
            CanonicalReadModelCategory::ReportTraceability => {
                if let Some(traceability) = self.canonical_report_export_traceability() {
                    bounded_buckets.push(format!(
                        "report_refs_{}",
                        count_bucket(traceability.report_refs.len())
                    ));
                    bounded_buckets.push(format!(
                        "finding_refs_{}",
                        count_bucket(traceability.finding_refs.len())
                    ));
                    bounded_refs.push(traceability.integrity_hash.clone());
                    extend_bounded_item_refs(&mut bounded_refs, &traceability.report_refs);
                    extend_bounded_item_refs(&mut bounded_refs, &traceability.finding_refs);
                    extend_bounded_item_refs(&mut bounded_refs, &traceability.evidence_refs);
                    extend_bounded_item_refs(&mut bounded_refs, &traceability.hypothesis_refs);
                    extend_bounded_item_refs(&mut bounded_refs, &traceability.risk_refs);
                    extend_bounded_item_refs(&mut bounded_refs, &traceability.attack_refs);
                    extend_bounded_item_refs(&mut bounded_refs, &traceability.graph_refs);
                    extend_bounded_item_refs(
                        &mut bounded_refs,
                        &traceability.explicit_llm_story_refs,
                    );
                    extend_bounded_item_refs(&mut bounded_refs, &traceability.snapshot_refs);
                }
            }
            CanonicalReadModelCategory::ExportTraceabilityHistory => {
                if let Some(traceability) = self.canonical_report_export_traceability() {
                    bounded_buckets.push(format!(
                        "export_refs_{}",
                        count_bucket(traceability.export_refs.len())
                    ));
                    bounded_buckets.push(format!(
                        "snapshot_refs_{}",
                        count_bucket(traceability.snapshot_refs.len())
                    ));
                    bounded_refs.push(traceability.integrity_hash.clone());
                    extend_bounded_item_refs(&mut bounded_refs, &traceability.export_refs);
                    extend_bounded_item_refs(&mut bounded_refs, &traceability.report_refs);
                    extend_bounded_item_refs(&mut bounded_refs, &traceability.graph_refs);
                    extend_bounded_item_refs(&mut bounded_refs, &traceability.snapshot_refs);
                }
            }
            CanonicalReadModelCategory::ProviderControllerStatus => {
                bounded_categories.push(self.provider_controller.state().to_string());
                if let Some(status) = self.provider_controller_status() {
                    bounded_categories
                        .push(format!("mode_{:?}", status.selected_mode).to_ascii_lowercase());
                    bounded_categories.push(format!(
                        "activation_allowed_{}",
                        status.policy_summary.provider_activation_allowed
                    ));
                    if let Some(ip_helper) = status.provider(NetworkProviderKind::IpHelper) {
                        bounded_categories
                            .push(format!("ip_helper_boundary_{}", ip_helper.adapter_boundary));
                    }
                    bounded_buckets.push(format!(
                        "provider_count_{}",
                        count_bucket(status.providers.len())
                    ));
                    bounded_buckets.push(format!(
                        "visibility_dimensions_{}",
                        count_bucket(status.visibility_summary.dimensions.len())
                    ));
                    bounded_refs.push(status.controller_ref.clone());
                    bounded_refs.push(status.visibility_summary.visibility_ref.clone());
                    bounded_refs.push(status.fallback_plan.fallback_plan_ref.clone());
                    bounded_refs.push(status.policy_summary.policy_ref.clone());
                    bounded_refs.push(status.audit_summary.audit_ref.clone());
                    bounded_categories.push(
                        format!(
                            "ip_helper_schedule_{:?}",
                            status.ip_helper_schedule.schedule_state
                        )
                        .to_ascii_lowercase(),
                    );
                    bounded_categories.push(
                        format!(
                            "ip_helper_schedule_lease_{:?}",
                            status.ip_helper_schedule.lease_state
                        )
                        .to_ascii_lowercase(),
                    );
                    bounded_buckets.push(format!(
                        "schedule_enabled_{}",
                        status.ip_helper_schedule.enabled_marker
                    ));
                    bounded_buckets.push(format!(
                        "timer_runtime_active_{}",
                        status.ip_helper_schedule.timer_runtime_active
                    ));
                    bounded_buckets.push(format!(
                        "scheduler_triggered_provider_calls_{}",
                        count_bucket(
                            status.ip_helper_schedule.scheduler_triggered_provider_calls as usize
                        )
                    ));
                    bounded_refs.push(status.ip_helper_schedule.schedule_ref.clone());
                    bounded_refs.push(status.ip_helper_schedule.scheduler_owner_ref.clone());
                    bounded_categories.push(
                        format!("etw_lifecycle_{:?}", status.etw_lifecycle.lifecycle_state)
                            .to_ascii_lowercase(),
                    );
                    bounded_categories.push(
                        format!("etw_session_{:?}", status.etw_lifecycle.session_state)
                            .to_ascii_lowercase(),
                    );
                    bounded_categories.push(
                        format!(
                            "etw_authorization_{:?}",
                            status.etw_lifecycle.authorization_state
                        )
                        .to_ascii_lowercase(),
                    );
                    bounded_categories.push(
                        format!("etw_fallback_{:?}", status.etw_lifecycle.fallback_state)
                            .to_ascii_lowercase(),
                    );
                    bounded_buckets.push(format!(
                        "etw_session_generation_{}",
                        count_bucket(status.etw_lifecycle.session_generation as usize)
                    ));
                    bounded_buckets.push(format!(
                        "etw_collection_started_{}",
                        status.etw_lifecycle.collection_started
                    ));
                    bounded_refs.push(status.etw_lifecycle.lifecycle_ref.clone());
                    extend_bounded_item_refs(
                        &mut bounded_refs,
                        &status.etw_lifecycle.authorization_refs,
                    );
                    extend_bounded_item_refs(&mut bounded_refs, &status.etw_lifecycle.audit_refs);
                    extend_bounded_item_refs(&mut bounded_refs, &status.audit_summary.audit_refs);
                    extend_bounded_item_refs(
                        &mut bounded_refs,
                        &status.ip_helper_schedule.audit_refs,
                    );
                }
                if let Some(batch) = self.provider_controller.latest_ip_helper_batch() {
                    bounded_categories.push(format!(
                        "ip_helper_health_{}",
                        provider_health_label(batch.provider_health)
                    ));
                    bounded_categories.push(
                        format!("ip_helper_freshness_{:?}", batch.freshness).to_ascii_lowercase(),
                    );
                    bounded_buckets.push(format!(
                        "ip_helper_categories_{}",
                        batch.category_count_bucket
                    ));
                    bounded_buckets.push(format!(
                        "ip_helper_rows_processed_{}",
                        batch.rows_processed_bucket
                    ));
                    bounded_buckets.push(format!(
                        "ip_helper_rows_rejected_{}",
                        batch.rejected_count_bucket
                    ));
                    bounded_refs.push(batch.batch_ref.clone());
                    bounded_refs.push(batch.provider_ref.clone());
                    bounded_refs.push(batch.visibility_ref.clone());
                    extend_bounded_item_refs(&mut bounded_refs, &batch.audit_refs);
                    extend_bounded_item_refs(
                        &mut bounded_refs,
                        &batch
                            .fact_refs
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>(),
                    );
                }
                if let Some(batch) = self.provider_controller.latest_etw_batch() {
                    bounded_categories.push("etw_handoff_metadata_only".to_string());
                    bounded_categories.push(
                        format!("etw_batch_provider_{:?}", batch.provider_kind)
                            .to_ascii_lowercase(),
                    );
                    bounded_categories.push(format!(
                        "etw_privacy_category_only_{}",
                        batch.privacy.category_only_output
                    ));
                    bounded_buckets.push(format!(
                        "etw_events_observed_{}",
                        count_bucket(batch.events_observed as usize)
                    ));
                    bounded_buckets.push(format!(
                        "etw_events_accepted_{}",
                        count_bucket(batch.events_accepted as usize)
                    ));
                    bounded_buckets.push(format!(
                        "etw_events_dropped_{}",
                        count_bucket(batch.events_dropped as usize)
                    ));
                    bounded_refs.push(batch.batch_ref.clone());
                    bounded_refs.push(batch.allowlist_ref.clone());
                    extend_bounded_item_refs(&mut bounded_refs, &batch.provenance_refs);
                }
                bounded_buckets.push(format!(
                    "provider_calls_{}",
                    count_bucket(self.provider_controller.provider_call_count() as usize)
                ));
            }
            _ => {}
        }
        CanonicalReadModelSnapshotItem {
            model_category: category,
            lifecycle_state,
            health_state,
            bounded_categories,
            bounded_buckets,
            bounded_refs,
            degraded_reason: Some(blocker.to_string()),
            missing_visibility_flags: vec![blocker.to_string()],
            provenance_id: RUNTIME_CONTAINER_PROVENANCE.to_string(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn read_model_lifecycle_health(
        &self,
        category: CanonicalReadModelCategory,
    ) -> (RuntimeComponentLifecycle, RuntimeHealthState) {
        if category == CanonicalReadModelCategory::RuntimeOwnership
            || category == CanonicalReadModelCategory::RuntimeHealth
        {
            return (
                runtime_lifecycle_from_transition(self.transition_state),
                self.runtime_health,
            );
        }
        if category == CanonicalReadModelCategory::ComponentLifecycleHealth {
            return (RuntimeComponentLifecycle::Ready, RuntimeHealthState::Ready);
        }
        if let Some(component) = read_model_component(category) {
            if let Some(summary) = self
                .component_summaries
                .iter()
                .find(|summary| summary.component_category == component)
            {
                return (summary.component_lifecycle, summary.runtime_health);
            }
        }
        (
            RuntimeComponentLifecycle::NotInitialized,
            RuntimeHealthState::Unknown,
        )
    }

    fn read_model_count_for_category(&self, category: CanonicalReadModelCategory) -> usize {
        match category {
            CanonicalReadModelCategory::RuntimeOwnership => 1,
            CanonicalReadModelCategory::ComponentLifecycleHealth => self.component_summaries.len(),
            CanonicalReadModelCategory::RuntimeHealth => {
                usize::from(self.runtime_health != RuntimeHealthState::Unknown)
            }
            CanonicalReadModelCategory::StorageOwnerSummary => {
                usize::from(self.storage_writer_count() > 0)
            }
            CanonicalReadModelCategory::CapabilityHealth => self.plugin_registration_count(),
            CanonicalReadModelCategory::Scheduler => self.scheduler_controller_count(),
            CanonicalReadModelCategory::SchedulerHost => self.scheduler_host_owner_count(),
            CanonicalReadModelCategory::SamplerState => self.sampler_runtime_count(),
            CanonicalReadModelCategory::NativePermissionReadiness => {
                self.native_permission_runtime_count()
            }
            CanonicalReadModelCategory::EndpointThreat => self.endpoint_threat_runtime_count(),
            CanonicalReadModelCategory::Fusion => self.fusion_state_count(),
            CanonicalReadModelCategory::EvidenceQuality => self.evidence_quality_state_count(),
            CanonicalReadModelCategory::Risk => self.risk_state_count(),
            CanonicalReadModelCategory::AttackContext => self.attack_context_state_count(),
            CanonicalReadModelCategory::Graph => self.graph_state_count(),
            CanonicalReadModelCategory::Baseline => self.baseline_state_count(),
            CanonicalReadModelCategory::IncidentLinkedGroups => self.incident_linking_state_count(),
            CanonicalReadModelCategory::ReportTraceability => {
                usize::from(self.report_export_traceability.is_some())
            }
            CanonicalReadModelCategory::ExportTraceabilityHistory => {
                usize::from(self.report_export_traceability.is_some())
            }
            CanonicalReadModelCategory::ProviderControllerStatus => 1,
        }
    }
}

fn build_report_export_traceability_snapshot(
    read: &ReadOnlyCommandState,
    owner_context: &RuntimeOwnerContext,
    snapshot_refs: Vec<String>,
) -> CommandResult<CanonicalReportExportTraceabilitySnapshot> {
    let report_refs = bounded_unique_ref_strings(
        read.reports
            .items
            .iter()
            .map(|report| report.report_id.to_string()),
    );
    let export_refs = bounded_unique_ref_strings(
        read.export_history
            .records()
            .iter()
            .map(|record| record.export_result_id.to_string()),
    );
    let finding_refs = bounded_unique_ref_strings(
        read.findings
            .items
            .iter()
            .map(|finding| finding.id().to_string())
            .chain(
                read.reports
                    .items
                    .iter()
                    .flat_map(|report| report.finding_refs.iter().map(ToString::to_string)),
            )
            .chain(
                read.alerts
                    .items
                    .iter()
                    .flat_map(|alert| alert.finding_refs().iter().map(ToString::to_string)),
            )
            .chain(
                read.attack_hypotheses
                    .items
                    .iter()
                    .flat_map(|hypothesis| hypothesis.finding_refs.iter().map(ToString::to_string)),
            )
            .chain(
                read.endpoint_threat_findings
                    .iter()
                    .map(|finding| finding.finding_id.to_string()),
            ),
    );
    let evidence_refs =
        bounded_unique_ref_strings(
            read.findings
                .items
                .iter()
                .flat_map(|finding| finding.evidence_refs().iter().map(ToString::to_string))
                .chain(
                    read.reports
                        .items
                        .iter()
                        .flat_map(|report| report.evidence_refs.iter().map(ToString::to_string)),
                )
                .chain(
                    read.export_history
                        .records()
                        .iter()
                        .flat_map(|record| record.evidence_refs.iter().map(ToString::to_string)),
                )
                .chain(read.attack_hypotheses.items.iter().flat_map(|hypothesis| {
                    hypothesis.evidence_refs.iter().map(ToString::to_string)
                }))
                .chain(
                    read.endpoint_threat_evidence
                        .iter()
                        .map(|evidence| evidence.endpoint_evidence_id.to_string()),
                ),
        );
    let hypothesis_refs = bounded_unique_ref_strings(
        read.attack_hypotheses
            .items
            .iter()
            .map(|hypothesis| hypothesis.hypothesis_record_id.to_string()),
    );
    let risk_refs = bounded_unique_ref_strings(
        read.alerts
            .items
            .iter()
            .flat_map(|alert| alert.risk_event_refs().iter().map(ToString::to_string))
            .chain(
                read.attack_hypotheses
                    .items
                    .iter()
                    .flat_map(|hypothesis| hypothesis.risk_refs.iter().map(ToString::to_string)),
            )
            .chain(
                read.endpoint_threat_risk_hints
                    .iter()
                    .map(|risk| risk.risk_hint_id.to_string()),
            ),
    );
    let attack_refs = bounded_unique_ref_strings(
        read.findings
            .items
            .iter()
            .flat_map(|finding| {
                finding
                    .attack_mappings()
                    .iter()
                    .filter_map(attack_ref_from_mapping)
            })
            .chain(read.attack_hypotheses.items.iter().flat_map(|hypothesis| {
                hypothesis.attack_candidates.iter().map(|candidate| {
                    format!(
                        "attack_ref_{}_{}",
                        candidate.tactic_id, candidate.technique_id
                    )
                })
            })),
    );
    let graph_refs =
        bounded_unique_ref_strings(
            read.graph_views
                .iter()
                .map(|graph| graph.graph_id.to_string())
                .chain(
                    read.reports.items.iter().flat_map(|report| {
                        report.graph_snapshot_refs.iter().map(ToString::to_string)
                    }),
                )
                .chain(
                    read.export_history.records().iter().flat_map(|record| {
                        record.graph_snapshot_refs.iter().map(ToString::to_string)
                    }),
                )
                .chain(read.attack_hypotheses.items.iter().flat_map(|hypothesis| {
                    hypothesis.graph_hint_refs.iter().map(ToString::to_string)
                })),
        );
    let explicit_llm_story_refs = bounded_unique_ref_strings(
        read.llm_alert_stories
            .items
            .iter()
            .map(|story| story.story_id.to_string())
            .chain(
                read.reports
                    .items
                    .iter()
                    .flat_map(|report| report.llm_story_refs.iter().map(ToString::to_string)),
            )
            .chain(
                read.export_history
                    .records()
                    .iter()
                    .flat_map(|record| record.llm_story_refs.iter().map(ToString::to_string)),
            ),
    );
    let snapshot_refs = bounded_unique_ref_strings(snapshot_refs);
    let mut hash_refs = Vec::new();
    hash_refs.extend(report_refs.clone());
    hash_refs.extend(export_refs.clone());
    hash_refs.extend(finding_refs.clone());
    hash_refs.extend(evidence_refs.clone());
    hash_refs.extend(hypothesis_refs.clone());
    hash_refs.extend(risk_refs.clone());
    hash_refs.extend(attack_refs.clone());
    hash_refs.extend(graph_refs.clone());
    hash_refs.extend(explicit_llm_story_refs.clone());
    hash_refs.extend(snapshot_refs.clone());
    let snapshot = CanonicalReportExportTraceabilitySnapshot {
        ownership_ref: owner_context.ownership_ref.clone(),
        ownership_epoch: owner_context.ownership_epoch,
        runtime_owner: owner_context.owner_category,
        schema_version: REPORT_EXPORT_TRACEABILITY_SCHEMA_VERSION,
        report_refs,
        export_refs,
        finding_refs,
        evidence_refs,
        hypothesis_refs,
        risk_refs,
        attack_refs,
        graph_refs,
        explicit_llm_story_refs,
        snapshot_refs,
        integrity_hash: traceability_integrity_hash(&hash_refs),
        generated_time_bucket: Timestamp::now(),
        redaction_status: RedactionStatus::Redacted,
    };
    snapshot
        .validate()
        .map_err(|_| init_error("report_export_traceability_invalid"))?;
    Ok(snapshot)
}

fn attack_ref_from_mapping(mapping: &sentinel_contracts::AttackMapping) -> Option<String> {
    if let (Some(tactic), Some(technique)) = (&mapping.tactic_id, &mapping.technique_id) {
        Some(format!("attack_ref_{tactic}_{technique}"))
    } else {
        mapping
            .custom_mapping_id
            .as_ref()
            .or(mapping.internal_category.as_ref())
            .map(|value| format!("attack_ref_{value}"))
    }
}

fn bounded_unique_ref_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut set = BTreeSet::new();
    for value in values {
        if !value.trim().is_empty() {
            set.insert(value);
        }
        if set.len() >= MAX_REPORT_EXPORT_TRACEABILITY_REFS {
            break;
        }
    }
    set.into_iter().collect()
}

fn push_bounded_ref(refs: &mut Vec<String>, value: String) {
    if refs.len() < MAX_REPORT_EXPORT_TRACEABILITY_REFS && !refs.iter().any(|item| item == &value) {
        refs.push(value);
        refs.sort();
    }
}

fn extend_bounded_item_refs(item_refs: &mut Vec<String>, refs: &[String]) {
    for value in refs {
        if item_refs.len() >= sentinel_contracts::READ_COMMAND_MAX_REFS_PER_RECORD {
            break;
        }
        if !item_refs.iter().any(|existing| existing == value) {
            item_refs.push(value.clone());
        }
    }
}

fn traceability_integrity_hash(refs: &[String]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in refs.join("|").as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    format!("trace_hash_{hash:016x}")
}

fn validate_service_host_store_owner(owner_context: &RuntimeOwnerContext) -> CommandResult<()> {
    owner_context
        .validate()
        .map_err(|_| CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch))?;
    if owner_context.owner_category != RuntimeOwnerCategory::ServiceHost
        || owner_context.runtime_mode != RuntimeMode::ServiceOwned
    {
        return Err(CoreError::from(RuntimeOwnershipError::RuntimeOwnerMismatch));
    }
    RuntimeOwnershipGuard::validate_active_context(owner_context, owner_context.ownership_epoch)
        .map_err(CoreError::from)
}

fn build_canonical_read_model_snapshot(
    owner_context: &RuntimeOwnerContext,
    generation: u64,
    mut items: Vec<CanonicalReadModelSnapshotItem>,
    partial_state: bool,
    degraded_reason: Option<&str>,
    freshness_state: ReadModelSnapshotFreshness,
) -> CommandResult<CanonicalReadModelSnapshot> {
    items.sort_by_key(|item| item.model_category);
    let snapshot = CanonicalReadModelSnapshot {
        snapshot_id: ReadModelSnapshotId::new_v4(),
        ownership_ref: owner_context.ownership_ref.clone(),
        ownership_epoch: owner_context.ownership_epoch,
        runtime_owner: owner_context.owner_category,
        runtime_mode: owner_context.runtime_mode,
        schema_version: READ_MODEL_SNAPSHOT_SCHEMA_VERSION,
        generation_bucket: format!("generation_{generation:08}"),
        generated_time_bucket: Timestamp::now(),
        freshness_state,
        partial_state,
        items,
        degraded_reason: degraded_reason.map(ToString::to_string),
        missing_visibility_flags: degraded_reason
            .map(|reason| vec![reason.to_string()])
            .unwrap_or_default(),
        provenance_id: RUNTIME_CONTAINER_PROVENANCE.to_string(),
        redaction_status: RedactionStatus::Redacted,
    };
    snapshot
        .validate()
        .map_err(|_| init_error("canonical_read_model_snapshot_invalid"))?;
    Ok(snapshot)
}

fn runtime_lifecycle_from_transition(
    transition: RuntimeTransitionState,
) -> RuntimeComponentLifecycle {
    match transition {
        RuntimeTransitionState::Ready => RuntimeComponentLifecycle::Ready,
        RuntimeTransitionState::Initializing
        | RuntimeTransitionState::OwnershipRequested
        | RuntimeTransitionState::OwnershipAcquired => RuntimeComponentLifecycle::Initializing,
        RuntimeTransitionState::ShuttingDown => RuntimeComponentLifecycle::Stopping,
        RuntimeTransitionState::Released => RuntimeComponentLifecycle::Stopped,
        RuntimeTransitionState::Failed => RuntimeComponentLifecycle::Failed,
        RuntimeTransitionState::None => RuntimeComponentLifecycle::NotInitialized,
    }
}

fn read_model_component(category: CanonicalReadModelCategory) -> Option<RuntimeComponentCategory> {
    match category {
        CanonicalReadModelCategory::CapabilityHealth => {
            Some(RuntimeComponentCategory::CapabilityRegistry)
        }
        CanonicalReadModelCategory::StorageOwnerSummary => {
            Some(RuntimeComponentCategory::ReadModels)
        }
        CanonicalReadModelCategory::Scheduler => Some(RuntimeComponentCategory::NativeScheduler),
        CanonicalReadModelCategory::SchedulerHost => {
            Some(RuntimeComponentCategory::NativeSchedulerHost)
        }
        CanonicalReadModelCategory::SamplerState => Some(RuntimeComponentCategory::NativeSamplers),
        CanonicalReadModelCategory::NativePermissionReadiness => {
            Some(RuntimeComponentCategory::NativePermissions)
        }
        CanonicalReadModelCategory::EndpointThreat => {
            Some(RuntimeComponentCategory::EndpointThreat)
        }
        CanonicalReadModelCategory::Fusion => Some(RuntimeComponentCategory::Fusion),
        CanonicalReadModelCategory::EvidenceQuality => {
            Some(RuntimeComponentCategory::EvidenceQuality)
        }
        CanonicalReadModelCategory::Risk => Some(RuntimeComponentCategory::Risk),
        CanonicalReadModelCategory::AttackContext => Some(RuntimeComponentCategory::AttackContext),
        CanonicalReadModelCategory::Graph => Some(RuntimeComponentCategory::Graph),
        CanonicalReadModelCategory::Baseline => Some(RuntimeComponentCategory::Baseline),
        CanonicalReadModelCategory::IncidentLinkedGroups => {
            Some(RuntimeComponentCategory::IncidentLinking)
        }
        CanonicalReadModelCategory::ReportTraceability => {
            Some(RuntimeComponentCategory::ReportTraceability)
        }
        CanonicalReadModelCategory::ExportTraceabilityHistory => {
            Some(RuntimeComponentCategory::ExportTraceability)
        }
        CanonicalReadModelCategory::ProviderControllerStatus => {
            Some(RuntimeComponentCategory::ProviderController)
        }
        CanonicalReadModelCategory::RuntimeOwnership
        | CanonicalReadModelCategory::ComponentLifecycleHealth
        | CanonicalReadModelCategory::RuntimeHealth => None,
    }
}

fn count_bucket(count: usize) -> &'static str {
    match count {
        0 => "count_zero",
        1 => "count_one",
        2..=4 => "count_few",
        5..=16 => "count_some",
        _ => "count_many_bounded",
    }
}

fn read_model_category_label(category: CanonicalReadModelCategory) -> &'static str {
    match category {
        CanonicalReadModelCategory::RuntimeOwnership => "runtime_ownership",
        CanonicalReadModelCategory::ComponentLifecycleHealth => "component_lifecycle_health",
        CanonicalReadModelCategory::RuntimeHealth => "runtime_health",
        CanonicalReadModelCategory::StorageOwnerSummary => "storage_owner_summary",
        CanonicalReadModelCategory::CapabilityHealth => "capability_health",
        CanonicalReadModelCategory::Scheduler => "scheduler_status",
        CanonicalReadModelCategory::SchedulerHost => "scheduler_host_status",
        CanonicalReadModelCategory::SamplerState => "sampler_status",
        CanonicalReadModelCategory::NativePermissionReadiness => "permission_readiness_status",
        CanonicalReadModelCategory::EndpointThreat => "endpoint_threat_summary",
        CanonicalReadModelCategory::Fusion => "fusion_summary",
        CanonicalReadModelCategory::EvidenceQuality => "evidence_quality_summary",
        CanonicalReadModelCategory::Risk => "risk_summary",
        CanonicalReadModelCategory::AttackContext => "attack_context_summary",
        CanonicalReadModelCategory::Graph => "graph_summary",
        CanonicalReadModelCategory::Baseline => "baseline_summary",
        CanonicalReadModelCategory::IncidentLinkedGroups => "incident_linked_summary",
        CanonicalReadModelCategory::ReportTraceability => "report_traceability",
        CanonicalReadModelCategory::ExportTraceabilityHistory => "export_traceability_history",
        CanonicalReadModelCategory::ProviderControllerStatus => "provider_controller_status",
    }
}

fn read_model_ref_label(category: CanonicalReadModelCategory) -> &'static str {
    match category {
        CanonicalReadModelCategory::RuntimeOwnership => "runtime_ownership_ref",
        CanonicalReadModelCategory::ComponentLifecycleHealth => "component_ownership_ref",
        CanonicalReadModelCategory::RuntimeHealth => "runtime_health_ref",
        CanonicalReadModelCategory::StorageOwnerSummary => "storage_owner_summary_ref",
        CanonicalReadModelCategory::CapabilityHealth => "capability_health_ref",
        CanonicalReadModelCategory::Scheduler => "scheduler_status_ref",
        CanonicalReadModelCategory::SchedulerHost => "scheduler_host_status_ref",
        CanonicalReadModelCategory::SamplerState => "sampler_status_ref",
        CanonicalReadModelCategory::NativePermissionReadiness => "permission_readiness_ref",
        CanonicalReadModelCategory::EndpointThreat => "endpoint_threat_ref",
        CanonicalReadModelCategory::Fusion => "fusion_ref",
        CanonicalReadModelCategory::EvidenceQuality => "evidence_quality_ref",
        CanonicalReadModelCategory::Risk => "risk_ref",
        CanonicalReadModelCategory::AttackContext => "attack_context_ref",
        CanonicalReadModelCategory::Graph => "graph_ref",
        CanonicalReadModelCategory::Baseline => "baseline_ref",
        CanonicalReadModelCategory::IncidentLinkedGroups => "incident_linked_ref",
        CanonicalReadModelCategory::ReportTraceability => "report_traceability_ref",
        CanonicalReadModelCategory::ExportTraceabilityHistory => "export_traceability_ref",
        CanonicalReadModelCategory::ProviderControllerStatus => "provider_controller_ref",
    }
}

fn register_static_bindings(runtime: &mut PluginRuntime) -> CommandResult<()> {
    register_static_flow_sessionization_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_asset_exposure_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_dns_security_v2_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_http_analysis_v1_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_api_security_lite_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_waf_security_lite_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_quic_http3_security_lite_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_remote_admin_protocol_lite_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_auth_identity_analysis_lite_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_portable_saas_cloud_abuse_lite_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_deception_event_lite_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_multi_layer_security_fusion_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_native_sampler_fact_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_native_network_fact_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_endpoint_threat_analysis_lite_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_c2_detection_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_exfiltration_detection_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_lateral_movement_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_risk_alerting_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    register_static_response_planning_plugin(runtime)
        .map_err(|_| init_error("plugin_runtime_initialization_failed"))?;
    Ok(())
}

fn runtime_read_models() -> CommandResult<ReadOnlyCommandState> {
    let catalog = BuiltInPluginCatalog::static_internal()
        .map_err(|_| init_error("plugin_catalog_initialization_failed"))?;
    ReadOnlyCommandState::from_catalog_with_registries(
        catalog,
        crate::read_commands::ReadModelRegistries {
            component_registry: ComponentRegistry::new(),
            plugin_registry: PluginRegistry::new(),
            capability_registry: CapabilityRegistry::new(),
            contract_registry: ContractRegistry::new(),
            dependency_registry: DependencyRegistry::new(),
            runtime_registry: RuntimeRegistry::new(),
        },
    )
}

fn runtime_pipeline_dag() -> CommandResult<PipelineDag> {
    let mut dag = PipelineDag::new("service_host_runtime_container")
        .map_err(|_| init_error("dag_initialization_failed"))?;
    let source = dag
        .add_node(
            PipelineNode::new(
                "portable metadata source",
                PipelineStage::Source,
                StageBinding::metadata_only(
                    Vec::new(),
                    runtime_topics(&[
                        NETWORK_FLOW_RECORD,
                        NETWORK_SESSION_RECORD,
                        NETWORK_DNS_OBSERVATION,
                        NETWORK_TLS_OBSERVATION,
                        NETWORK_HTTP_METADATA,
                        IDENTITY_AUTH_METADATA,
                        IDENTITY_PROCESS_CONTEXT,
                        ASSET_RECORD,
                        ASSET_SERVICE_RECORD,
                        ASSET_PORT_EXPOSURE,
                        ASSET_EXPOSURE_OBSERVATION,
                        ASSET_EXPOSURE,
                        SECURITY_FINDING_ASSET_RISK,
                        IDENTITY_RDP_OPERATIONAL_METADATA,
                        IDENTITY_SMB_OPERATIONAL_METADATA,
                        IDENTITY_SSH_OPERATIONAL_METADATA,
                        INTEL_DOMAIN_CONTEXT,
                        INTEL_IP_CONTEXT,
                        INTEL_CLOUD_CONTEXT,
                        INTEL_CERTIFICATE_CONTEXT,
                        CLOUD_SAAS_METADATA,
                        DECEPTION_EVENT_METADATA,
                        NETWORK_SDN_CONTROL_PLANE_METADATA,
                        NATIVE_IP_HELPER_METADATA,
                        NATIVE_ETW_NETWORK_METADATA,
                        NATIVE_HEALTH_METADATA,
                        NATIVE_SERVICE_METADATA,
                        NATIVE_PROCESS_METADATA,
                        NATIVE_PROCESS_PARENT_METADATA,
                        NETWORK_PROVIDER_STATUS,
                        NETWORK_VISIBILITY_STATUS,
                        SERVICE_CAPABILITY_STATUS,
                        SECURITY_FUSION_CONTEXT,
                    ])?,
                ),
            )
            .map_err(|_| init_error("dag_initialization_failed"))?,
        )
        .map_err(|_| init_error("dag_initialization_failed"))?;
    let detection = dag
        .add_node(
            PipelineNode::new(
                "static plugin detection and fusion",
                PipelineStage::Detection,
                StageBinding::metadata_only(
                    runtime_topics(&[
                        NETWORK_FLOW_RECORD,
                        NETWORK_SESSION_RECORD,
                        NETWORK_DNS_OBSERVATION,
                        NETWORK_TLS_OBSERVATION,
                        NETWORK_HTTP_METADATA,
                        IDENTITY_AUTH_METADATA,
                        IDENTITY_PROCESS_CONTEXT,
                        ASSET_RECORD,
                        ASSET_SERVICE_RECORD,
                        ASSET_PORT_EXPOSURE,
                        ASSET_EXPOSURE_OBSERVATION,
                        ASSET_EXPOSURE,
                        SECURITY_FINDING_ASSET_RISK,
                        IDENTITY_RDP_OPERATIONAL_METADATA,
                        IDENTITY_SMB_OPERATIONAL_METADATA,
                        IDENTITY_SSH_OPERATIONAL_METADATA,
                        INTEL_DOMAIN_CONTEXT,
                        INTEL_IP_CONTEXT,
                        INTEL_CLOUD_CONTEXT,
                        INTEL_CERTIFICATE_CONTEXT,
                        CLOUD_SAAS_METADATA,
                        DECEPTION_EVENT_METADATA,
                        NETWORK_SDN_CONTROL_PLANE_METADATA,
                        NATIVE_IP_HELPER_METADATA,
                        NATIVE_ETW_NETWORK_METADATA,
                        NATIVE_HEALTH_METADATA,
                        NATIVE_SERVICE_METADATA,
                        NATIVE_PROCESS_METADATA,
                        NATIVE_PROCESS_PARENT_METADATA,
                        ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT,
                        ENDPOINT_SERVICE_CATEGORY_FACT,
                        ENDPOINT_PROCESS_CATEGORY_FACT,
                        ENDPOINT_PROCESS_PARENT_CATEGORY_FACT,
                        SECURITY_FINDING,
                        SECURITY_FUSION_CONTEXT,
                    ])?,
                    runtime_topics(&[
                        SECURITY_FINDING,
                        SECURITY_EVIDENCE,
                        "security.risk_hint",
                        GRAPH_HINT,
                        SECURITY_FACT,
                        NATIVE_CONNECTION_CATEGORY_FACT,
                        ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT,
                        ENDPOINT_SERVICE_CATEGORY_FACT,
                        ENDPOINT_PROCESS_CATEGORY_FACT,
                        ENDPOINT_PROCESS_PARENT_CATEGORY_FACT,
                        ENDPOINT_THREAT_CANDIDATE,
                        ENDPOINT_THREAT_FINDING,
                        ENDPOINT_THREAT_EVIDENCE,
                        ENDPOINT_THREAT_RISK_HINT,
                        ENDPOINT_VISIBILITY_ADVISORY,
                        ENDPOINT_THREAT_REJECTED,
                        AUDIT_ENDPOINT_THREAT_ANALYSIS,
                        SECURITY_HYPOTHESIS,
                        SECURITY_FUSION_SUMMARY,
                    ])?,
                ),
            )
            .map_err(|_| init_error("dag_initialization_failed"))?
            .depends_on(source),
        )
        .map_err(|_| init_error("dag_initialization_failed"))?;
    dag.add_node(
        PipelineNode::new(
            "static risk stage",
            PipelineStage::Risk,
            StageBinding::metadata_only(
                runtime_topics(&[
                    SECURITY_FINDING,
                    SECURITY_EVIDENCE,
                    "security.risk_hint",
                    SERVICE_CAPABILITY_STATUS,
                ])?,
                runtime_topics(&[
                    SECURITY_RISK,
                    "security.alert_candidate",
                    SECURITY_ALERT,
                    "security.incident_candidate",
                    SECURITY_INCIDENT,
                ])?,
            ),
        )
        .map_err(|_| init_error("dag_initialization_failed"))?
        .depends_on(detection),
    )
    .map_err(|_| init_error("dag_initialization_failed"))?;
    Ok(dag)
}

fn runtime_topics(values: &[&str]) -> CommandResult<Vec<TopicName>> {
    values
        .iter()
        .map(|value| TopicName::new(*value).map_err(|_| init_error("topic_initialization_failed")))
        .collect()
}

fn runtime_handoff_event<T: serde::Serialize>(
    producer_plugin: &PluginId,
    topic: &str,
    payload: &T,
    schema_version: SchemaVersion,
    quality_score: QualityScore,
    trace_context: &TraceContext,
) -> CommandResult<EventEnvelope> {
    let mut event = EventEnvelope::new(
        EventType::new(topic).map_err(provider_execution_error)?,
        schema_version,
        producer_plugin.clone(),
        trace_context.clone(),
    );
    event.privacy_class = PrivacyClass::Internal;
    event.quality_score = quality_score;
    event.payload = serde_json::to_value(payload).map_err(provider_execution_error)?;
    Ok(event)
}

fn runtime_contract_registry_for_manifest(
    manifest: &sentinel_contracts::PluginManifest,
) -> CommandResult<ContractRegistry> {
    let mut registry = ContractRegistry::new();
    for contract in manifest
        .input_contracts
        .iter()
        .chain(manifest.output_contracts.iter())
    {
        registry
            .register(contract.clone())
            .map_err(provider_execution_error)?;
    }
    Ok(registry)
}

fn runtime_plugin_context_for_manifest(
    manifest: &sentinel_contracts::PluginManifest,
    trace_context: TraceContext,
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
            .insert(runtime_topic_for_contract(contract)?);
    }
    for contract in &manifest.output_contracts {
        context
            .topic_scope
            .publish_topics
            .insert(runtime_topic_for_contract(contract)?);
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

fn runtime_topic_for_contract(contract: &ContractDescriptor) -> CommandResult<TopicName> {
    TopicName::new(
        contract
            .topic
            .as_deref()
            .unwrap_or(contract.contract_name.as_str()),
    )
    .map_err(provider_execution_error)
}

fn validate_native_network_dag_route(container: &RuntimeContainer) -> CommandResult<()> {
    if container.pipeline_dag.is_none() {
        return Err(provider_execution_error("dag_unavailable"));
    }
    TopicName::new(NATIVE_IP_HELPER_METADATA).map_err(provider_execution_error)?;
    TopicName::new(NATIVE_ETW_NETWORK_METADATA).map_err(provider_execution_error)?;
    TopicName::new(NATIVE_CONNECTION_CATEGORY_FACT).map_err(provider_execution_error)?;
    Ok(())
}

fn validate_dns_sensing_dag_route(container: &RuntimeContainer) -> CommandResult<()> {
    if container.pipeline_dag.is_none() {
        return Err(provider_execution_error("dag_unavailable"));
    }
    TopicName::new(NETWORK_DNS_OBSERVATION).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FINDING).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_EVIDENCE).map_err(provider_execution_error)?;
    TopicName::new("security.risk_hint").map_err(provider_execution_error)?;
    TopicName::new(GRAPH_HINT).map_err(provider_execution_error)?;
    Ok(())
}

#[cfg(test)]
fn validate_c2_detection_dag_route(container: &RuntimeContainer) -> CommandResult<()> {
    if container.pipeline_dag.is_none() {
        return Err(provider_execution_error("dag_unavailable"));
    }
    TopicName::new(NETWORK_FLOW_RECORD).map_err(provider_execution_error)?;
    TopicName::new(NETWORK_SESSION_RECORD).map_err(provider_execution_error)?;
    TopicName::new(NETWORK_DNS_OBSERVATION).map_err(provider_execution_error)?;
    TopicName::new(NETWORK_TLS_OBSERVATION).map_err(provider_execution_error)?;
    TopicName::new(IDENTITY_PROCESS_CONTEXT).map_err(provider_execution_error)?;
    TopicName::new(INTEL_DOMAIN_CONTEXT).map_err(provider_execution_error)?;
    TopicName::new(INTEL_IP_CONTEXT).map_err(provider_execution_error)?;
    TopicName::new(INTEL_CLOUD_CONTEXT).map_err(provider_execution_error)?;
    TopicName::new(INTEL_CERTIFICATE_CONTEXT).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FINDING).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_EVIDENCE).map_err(provider_execution_error)?;
    TopicName::new("security.risk_hint").map_err(provider_execution_error)?;
    TopicName::new(GRAPH_HINT).map_err(provider_execution_error)?;
    if let Some(runtime_services) = &container.runtime_services {
        let outputs = [
            SECURITY_FINDING,
            SECURITY_EVIDENCE,
            "security.risk_hint",
            GRAPH_HINT,
        ];
        runtime_services.validate_dag_route(NETWORK_FLOW_RECORD, &outputs)?;
        runtime_services.validate_dag_route(NETWORK_DNS_OBSERVATION, &outputs)?;
        runtime_services.validate_dag_route(NETWORK_TLS_OBSERVATION, &outputs)?;
    }
    Ok(())
}

#[cfg(test)]
fn validate_lateral_movement_dag_route(container: &RuntimeContainer) -> CommandResult<()> {
    if container.pipeline_dag.is_none() {
        return Err(provider_execution_error("dag_unavailable"));
    }
    TopicName::new(NETWORK_FLOW_RECORD).map_err(provider_execution_error)?;
    TopicName::new(NETWORK_SESSION_RECORD).map_err(provider_execution_error)?;
    TopicName::new(IDENTITY_PROCESS_CONTEXT).map_err(provider_execution_error)?;
    TopicName::new(ASSET_RECORD).map_err(provider_execution_error)?;
    TopicName::new(ASSET_SERVICE_RECORD).map_err(provider_execution_error)?;
    TopicName::new(ASSET_PORT_EXPOSURE).map_err(provider_execution_error)?;
    TopicName::new(ASSET_EXPOSURE_OBSERVATION).map_err(provider_execution_error)?;
    TopicName::new(ASSET_EXPOSURE).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FINDING_ASSET_RISK).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FINDING).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_EVIDENCE).map_err(provider_execution_error)?;
    TopicName::new("security.risk_hint").map_err(provider_execution_error)?;
    TopicName::new(GRAPH_HINT).map_err(provider_execution_error)?;
    if let Some(runtime_services) = &container.runtime_services {
        let outputs = [
            SECURITY_FINDING,
            SECURITY_EVIDENCE,
            "security.risk_hint",
            GRAPH_HINT,
        ];
        runtime_services.validate_dag_route(NETWORK_FLOW_RECORD, &outputs)?;
        runtime_services.validate_dag_route(NETWORK_SESSION_RECORD, &outputs)?;
        runtime_services.validate_dag_route(IDENTITY_PROCESS_CONTEXT, &outputs)?;
        runtime_services.validate_dag_route(ASSET_PORT_EXPOSURE, &outputs)?;
        runtime_services.validate_dag_route(ASSET_EXPOSURE_OBSERVATION, &outputs)?;
        runtime_services.validate_dag_route(SECURITY_FINDING_ASSET_RISK, &outputs)?;
    }
    Ok(())
}

fn validate_auth_remote_sensing_dag_route(container: &RuntimeContainer) -> CommandResult<()> {
    if container.pipeline_dag.is_none() {
        return Err(provider_execution_error("dag_unavailable"));
    }
    TopicName::new(IDENTITY_AUTH_METADATA).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FUSION_CONTEXT).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FINDING).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_EVIDENCE).map_err(provider_execution_error)?;
    TopicName::new("security.risk_hint").map_err(provider_execution_error)?;
    TopicName::new(GRAPH_HINT).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FACT).map_err(provider_execution_error)?;
    Ok(())
}

fn validate_rdp_operational_sensing_dag_route(container: &RuntimeContainer) -> CommandResult<()> {
    if container.pipeline_dag.is_none() {
        return Err(provider_execution_error("dag_unavailable"));
    }
    TopicName::new(IDENTITY_RDP_OPERATIONAL_METADATA).map_err(provider_execution_error)?;
    TopicName::new(IDENTITY_AUTH_METADATA).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FUSION_CONTEXT).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FINDING).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_EVIDENCE).map_err(provider_execution_error)?;
    TopicName::new("security.risk_hint").map_err(provider_execution_error)?;
    TopicName::new(GRAPH_HINT).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FACT).map_err(provider_execution_error)?;
    Ok(())
}

fn validate_smb_operational_sensing_dag_route(container: &RuntimeContainer) -> CommandResult<()> {
    if container.pipeline_dag.is_none() {
        return Err(provider_execution_error("dag_unavailable"));
    }
    TopicName::new(IDENTITY_SMB_OPERATIONAL_METADATA).map_err(provider_execution_error)?;
    TopicName::new(IDENTITY_AUTH_METADATA).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FUSION_CONTEXT).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FINDING).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_EVIDENCE).map_err(provider_execution_error)?;
    TopicName::new("security.risk_hint").map_err(provider_execution_error)?;
    TopicName::new(GRAPH_HINT).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FACT).map_err(provider_execution_error)?;
    Ok(())
}

fn validate_ssh_operational_sensing_dag_route(container: &RuntimeContainer) -> CommandResult<()> {
    if container.pipeline_dag.is_none() {
        return Err(provider_execution_error("dag_unavailable"));
    }
    TopicName::new(IDENTITY_SSH_OPERATIONAL_METADATA).map_err(provider_execution_error)?;
    TopicName::new(IDENTITY_AUTH_METADATA).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FUSION_CONTEXT).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FINDING).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_EVIDENCE).map_err(provider_execution_error)?;
    TopicName::new("security.risk_hint").map_err(provider_execution_error)?;
    TopicName::new(GRAPH_HINT).map_err(provider_execution_error)?;
    TopicName::new(SECURITY_FACT).map_err(provider_execution_error)?;
    Ok(())
}

fn portable_auth_metadata_from_windows_auth(
    observation: &WindowsAuthRemoteObservation,
) -> CommandResult<PortableAuthMetadata> {
    let result = match observation.auth_result {
        WindowsAuthResultCategory::Success | WindowsAuthResultCategory::PrivilegedSuccess => {
            PortableAuthResultCategory::Success
        }
        WindowsAuthResultCategory::Failure | WindowsAuthResultCategory::Lockout => {
            PortableAuthResultCategory::Failure
        }
        WindowsAuthResultCategory::Logoff | WindowsAuthResultCategory::Unknown => {
            PortableAuthResultCategory::Unknown
        }
    };
    let provider_category = match observation.remote_protocol_category {
        Some(WindowsRemoteProtocolCategory::Rdp)
        | Some(WindowsRemoteProtocolCategory::Smb)
        | Some(WindowsRemoteProtocolCategory::Ssh)
        | Some(WindowsRemoteProtocolCategory::Network) => "remote_admin",
        Some(WindowsRemoteProtocolCategory::Service) => "windows_service",
        Some(WindowsRemoteProtocolCategory::ScheduledTask) => "scheduled_task",
        Some(WindowsRemoteProtocolCategory::LocalInteractive) => "local_logon",
        Some(WindowsRemoteProtocolCategory::WinRm) => "winrm",
        Some(WindowsRemoteProtocolCategory::Unknown) | None => "windows_security_event_log",
    };
    let mut metadata = PortableAuthMetadata::new(
        provider_category,
        result,
        observation.time_bucket_start.clone(),
    );
    metadata.identity_label_redacted = observation.identity_ref.clone();
    metadata.source_session_label = observation.source_ref.clone();
    metadata.destination_service_category = match observation.remote_protocol_category {
        Some(WindowsRemoteProtocolCategory::Rdp) => Some("rdp".to_string()),
        Some(WindowsRemoteProtocolCategory::Smb) => Some("smb".to_string()),
        Some(WindowsRemoteProtocolCategory::Ssh) => Some("ssh".to_string()),
        Some(WindowsRemoteProtocolCategory::Network) => Some("network_logon".to_string()),
        Some(WindowsRemoteProtocolCategory::WinRm) => Some("winrm".to_string()),
        Some(WindowsRemoteProtocolCategory::Service) => Some("windows_service".to_string()),
        Some(WindowsRemoteProtocolCategory::ScheduledTask) => Some("scheduled_task".to_string()),
        _ => None,
    };
    metadata.role_privilege_class = match observation.privilege_bucket {
        sentinel_contracts::WindowsAuthPrivilegeBucket::Elevated
        | sentinel_contracts::WindowsAuthPrivilegeBucket::SpecialPrivileges => {
            Some("privileged".to_string())
        }
        sentinel_contracts::WindowsAuthPrivilegeBucket::Standard => Some("standard".to_string()),
        _ => None,
    };
    metadata.device_client_category = observation
        .remote_protocol_category
        .map(|category| format!("{category:?}").to_ascii_lowercase());
    metadata.failure_reason_category = observation
        .failure_category
        .map(windows_failure_category_label);
    metadata.attempt_count_bucket = observation
        .repeated_failure_bucket
        .clone()
        .unwrap_or(PortableAuthAttemptCountBucket::One);
    metadata.redaction_status = RedactionStatus::Hashed;
    metadata.quality_score = observation.quality_score.clone();
    Ok(metadata)
}

fn windows_failure_category_label(category: WindowsAuthFailureCategory) -> String {
    match category {
        WindowsAuthFailureCategory::BadSecret => "bad_secret",
        WindowsAuthFailureCategory::UnknownIdentity => "unknown_identity",
        WindowsAuthFailureCategory::LockedOut => "locked_out",
        WindowsAuthFailureCategory::Expired => "expired",
        WindowsAuthFailureCategory::NotAllowed => "not_allowed",
        WindowsAuthFailureCategory::TimeSkew => "time_skew",
        WindowsAuthFailureCategory::ProtocolFailure => "protocol_failure",
        WindowsAuthFailureCategory::MissingVisibility => "missing_visibility",
        WindowsAuthFailureCategory::Unknown => "unknown",
    }
    .to_string()
}

fn ip_helper_snapshot_to_native_batch(
    snapshot: &IpHelperSnapshotSummary,
    request: &IpHelperHandoffRequest,
) -> CommandResult<NativeIpHelperMetadataBatch> {
    let audit_ref = format!("audit_network_provider_execution_{}", Uuid::new_v4());
    let missing_visibility_flags = vec![
        "short_lived_network_event_visibility_unavailable".to_string(),
        "process_network_attribution_unavailable".to_string(),
        "specific_process_identity_unavailable".to_string(),
        "packet_header_visibility_unavailable".to_string(),
        "packet_payload_visibility_unavailable".to_string(),
        "command_visibility_unavailable".to_string(),
        "file_registry_visibility_unavailable".to_string(),
    ];
    let provider_health = provider_health_from_snapshot(snapshot.provider_status);
    let categories = snapshot
        .categories
        .iter()
        .take(sentinel_contracts::MAX_NATIVE_NETWORK_RECORDS)
        .enumerate()
        .map(|(index, category)| native_network_category_record(index, category, provider_health))
        .collect::<CommandResult<Vec<_>>>()?;
    let mut batch = NativeIpHelperMetadataBatch {
        batch_ref: format!("ip_helper_batch_{}", Uuid::new_v4()),
        provider_ref: "network_provider_ip_helper".to_string(),
        provider_category: NativeNetworkProviderCategory::IpHelper,
        schema_version: sentinel_contracts::NATIVE_NETWORK_SCHEMA_VERSION,
        sampled_time_bucket: snapshot.sampled_at.clone(),
        provider_health,
        rows_observed_bucket: sentinel_contracts::native_network_count_bucket(
            snapshot.rows_observed,
        ),
        rows_processed_bucket: sentinel_contracts::native_network_count_bucket(
            snapshot.rows_processed,
        ),
        rows_suppressed_bucket: sentinel_contracts::native_network_count_bucket(
            snapshot.rows_suppressed,
        ),
        rows_dropped_bucket: sentinel_contracts::native_network_count_bucket(snapshot.rows_dropped),
        tcp_count_bucket: sentinel_contracts::native_network_count_bucket(snapshot.tcp_rows),
        udp_count_bucket: sentinel_contracts::native_network_count_bucket(snapshot.udp_rows),
        category_count_bucket: sentinel_contracts::native_network_count_bucket(
            snapshot.category_count,
        ),
        categories,
        skipped_count_bucket: sentinel_contracts::native_network_count_bucket(
            snapshot.rows_suppressed,
        ),
        rejected_count_bucket: sentinel_contracts::native_network_count_bucket(
            snapshot.rows_dropped,
        ),
        freshness: if matches!(
            provider_health,
            NativeNetworkProviderHealth::Available | NativeNetworkProviderHealth::Degraded
        ) {
            NativeNetworkFreshness::Fresh
        } else {
            NativeNetworkFreshness::Unavailable
        },
        provider_status_ref: "network_provider_ip_helper".to_string(),
        visibility_ref: "network_visibility_ref".to_string(),
        fact_refs: Vec::new(),
        audit_refs: vec![audit_ref],
        provenance_id: "ip_helper_servicehost_handoff".to_string(),
        redaction_status: RedactionStatus::Redacted,
        missing_visibility_flags,
        degraded_reason: snapshot.degraded_reason.clone(),
        response_execution_allowed: false,
        automatic_llm_calls: false,
    };
    if request.policy == IpHelperHandoffExecutionPolicy::ForegroundDevelopmentTest {
        batch
            .audit_refs
            .push("foreground_development_policy_ref".to_string());
    }
    batch.validate().map_err(provider_execution_error)?;
    Ok(batch)
}

fn native_network_category_record(
    index: usize,
    category: &IpHelperConnectionCategory,
    provider_health: NativeNetworkProviderHealth,
) -> CommandResult<NativeIpHelperConnectionCategoryRecord> {
    let local_scope = endpoint_scope(category.local_scope);
    let destination_scope = endpoint_scope(category.remote_scope);
    let record = NativeIpHelperConnectionCategoryRecord {
        observation_ref: format!("ip_helper_observation_bucket_{index}"),
        provider_category: NativeNetworkProviderCategory::IpHelper,
        transport_category: transport_category(category.transport),
        connection_state_bucket: state_bucket(category.state_category),
        local_scope_category: local_scope,
        destination_scope_category: destination_scope,
        local_endpoint_range_bucket: endpoint_range(category.local_endpoint_range),
        remote_endpoint_range_bucket: endpoint_range(category.remote_endpoint_range),
        service_category_bucket: service_bucket(category.service_category),
        local_remote_relation_category: relation_category(local_scope, destination_scope),
        owner_presence_category: owner_presence(category.owner_signal),
        count_bucket: sentinel_contracts::native_network_count_bucket(category.count),
        change_bucket: "observed".to_string(),
        time_bucket: Timestamp::now(),
        confidence_hint: quality_score(match provider_health {
            NativeNetworkProviderHealth::Available => 0.7,
            NativeNetworkProviderHealth::Degraded => 0.45,
            NativeNetworkProviderHealth::Unavailable
            | NativeNetworkProviderHealth::UnsupportedPlatform => 0.2,
        }),
        provider_health,
        evidence_refs: Vec::new(),
        provenance_refs: vec!["ip_helper_servicehost_handoff".to_string()],
        redaction_status: RedactionStatus::Redacted,
        missing_visibility_flags: vec![
            "specific_process_identity_unavailable".to_string(),
            "process_network_attribution_unavailable".to_string(),
            "packet_visibility_unavailable".to_string(),
        ],
    };
    record.validate().map_err(provider_execution_error)?;
    Ok(record)
}

fn provider_health_from_snapshot(value: IpHelperProviderStatus) -> NativeNetworkProviderHealth {
    match value {
        IpHelperProviderStatus::Available => NativeNetworkProviderHealth::Available,
        IpHelperProviderStatus::Degraded => NativeNetworkProviderHealth::Degraded,
        IpHelperProviderStatus::Unavailable => NativeNetworkProviderHealth::Unavailable,
        IpHelperProviderStatus::UnsupportedPlatform => {
            NativeNetworkProviderHealth::UnsupportedPlatform
        }
    }
}

fn transport_category(value: IpHelperTransport) -> NativeNetworkTransportCategory {
    match value {
        IpHelperTransport::Tcp => NativeNetworkTransportCategory::Tcp,
        IpHelperTransport::Udp => NativeNetworkTransportCategory::Udp,
    }
}

fn state_bucket(value: IpHelperStateCategory) -> NativeConnectionStateBucket {
    match value {
        IpHelperStateCategory::Listen => NativeConnectionStateBucket::Listen,
        IpHelperStateCategory::Established => NativeConnectionStateBucket::Established,
        IpHelperStateCategory::Closing => NativeConnectionStateBucket::Closing,
        IpHelperStateCategory::Stateless => NativeConnectionStateBucket::Stateless,
        IpHelperStateCategory::Other => NativeConnectionStateBucket::Other,
        IpHelperStateCategory::Unknown => NativeConnectionStateBucket::Unknown,
    }
}

fn endpoint_scope(value: IpHelperAddressScope) -> NativeEndpointScopeCategory {
    match value {
        IpHelperAddressScope::Loopback => NativeEndpointScopeCategory::Loopback,
        IpHelperAddressScope::Private => NativeEndpointScopeCategory::Private,
        IpHelperAddressScope::LinkLocal => NativeEndpointScopeCategory::LinkLocal,
        IpHelperAddressScope::Multicast => NativeEndpointScopeCategory::Multicast,
        IpHelperAddressScope::Public => NativeEndpointScopeCategory::Public,
        IpHelperAddressScope::Unspecified => NativeEndpointScopeCategory::Unspecified,
        IpHelperAddressScope::Unknown => NativeEndpointScopeCategory::Unknown,
    }
}

fn endpoint_range(value: IpHelperEndpointRange) -> NativeEndpointRangeBucket {
    match value {
        IpHelperEndpointRange::SystemRange => NativeEndpointRangeBucket::SystemRange,
        IpHelperEndpointRange::RegisteredRange => NativeEndpointRangeBucket::RegisteredRange,
        IpHelperEndpointRange::EphemeralRange => NativeEndpointRangeBucket::EphemeralRange,
        IpHelperEndpointRange::Unknown => NativeEndpointRangeBucket::Unknown,
    }
}

fn service_bucket(value: IpHelperServiceCategory) -> NativeConnectionServiceBucket {
    match value {
        IpHelperServiceCategory::Web => NativeConnectionServiceBucket::Web,
        IpHelperServiceCategory::Dns => NativeConnectionServiceBucket::Dns,
        IpHelperServiceCategory::RemoteAdmin => NativeConnectionServiceBucket::RemoteAdmin,
        IpHelperServiceCategory::FileSharing => NativeConnectionServiceBucket::FileSharing,
        IpHelperServiceCategory::Mail => NativeConnectionServiceBucket::Mail,
        IpHelperServiceCategory::Directory => NativeConnectionServiceBucket::Directory,
        IpHelperServiceCategory::Time => NativeConnectionServiceBucket::Time,
        IpHelperServiceCategory::Other => NativeConnectionServiceBucket::Other,
        IpHelperServiceCategory::Unknown => NativeConnectionServiceBucket::Unknown,
    }
}

fn owner_presence(value: IpHelperOwnerSignal) -> NativeOwnerPresenceCategory {
    match value {
        IpHelperOwnerSignal::OwnerObservedNotRetained => {
            NativeOwnerPresenceCategory::OwnerObservedNotRetained
        }
        IpHelperOwnerSignal::OwnerUnavailable => NativeOwnerPresenceCategory::OwnerUnavailable,
    }
}

fn relation_category(
    local_scope: NativeEndpointScopeCategory,
    destination_scope: NativeEndpointScopeCategory,
) -> NativeConnectionRelationCategory {
    match (local_scope, destination_scope) {
        (NativeEndpointScopeCategory::Loopback, NativeEndpointScopeCategory::Loopback)
        | (_, NativeEndpointScopeCategory::Unspecified) => {
            NativeConnectionRelationCategory::LocalOnly
        }
        (_, NativeEndpointScopeCategory::Private) => {
            NativeConnectionRelationCategory::LocalToPrivate
        }
        (_, NativeEndpointScopeCategory::Public) => NativeConnectionRelationCategory::LocalToPublic,
        (_, NativeEndpointScopeCategory::Multicast) => {
            NativeConnectionRelationCategory::LocalToMulticast
        }
        _ => NativeConnectionRelationCategory::Unknown,
    }
}

fn validate_ip_helper_snapshot_privacy(snapshot: &IpHelperSnapshotSummary) -> CommandResult<()> {
    if snapshot.schema_version.major != 1 {
        return Err(provider_execution_error("ip_helper_schema_not_accepted"));
    }
    for value in [
        snapshot.provider_id.as_str(),
        snapshot.privacy.retention_policy.as_str(),
        snapshot.privacy.endpoint_identity.as_str(),
        snapshot.privacy.owner_identity.as_str(),
        snapshot.privacy.executable_identity.as_str(),
        snapshot.privacy.raw_payload_state.as_str(),
    ] {
        validate_runtime_safe_ref("ip_helper_snapshot", value)?;
    }
    if !snapshot.privacy.retention_policy.contains("no_raw")
        || snapshot.privacy.endpoint_identity != "not_retained"
        || snapshot.privacy.owner_identity != "not_retained"
        || snapshot.privacy.raw_payload_state != "not_available"
    {
        return Err(provider_execution_error(
            "ip_helper_no_raw_retention_not_accepted",
        ));
    }
    if let Some(reason) = &snapshot.degraded_reason {
        validate_runtime_safe_ref("ip_helper_degraded_reason", reason)?;
    }
    Ok(())
}

fn bounded_runtime_refs(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut refs = Vec::new();
    for value in values {
        if !refs.iter().any(|existing| existing == &value) {
            refs.push(value);
        }
        if refs.len() >= MAX_RUNTIME_OWNERSHIP_AUDIT_REFS {
            break;
        }
    }
    refs
}

fn bounded_provider_refs(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut refs = Vec::new();
    for value in values {
        if !refs.iter().any(|existing| existing == &value) {
            refs.push(value);
        }
        if refs.len() >= MAX_NETWORK_PROVIDER_REFS {
            break;
        }
    }
    refs
}

fn bound_string_refs(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
    if values.len() > MAX_RUNTIME_OWNERSHIP_AUDIT_REFS {
        values.drain(0..values.len() - MAX_RUNTIME_OWNERSHIP_AUDIT_REFS);
    }
}

fn bump_ip_helper_count_bucket(value: IpHelperScheduleCountBucket) -> IpHelperScheduleCountBucket {
    match value {
        IpHelperScheduleCountBucket::Zero => IpHelperScheduleCountBucket::One,
        IpHelperScheduleCountBucket::One => IpHelperScheduleCountBucket::Few,
        IpHelperScheduleCountBucket::Few | IpHelperScheduleCountBucket::Many => {
            IpHelperScheduleCountBucket::Many
        }
    }
}

fn ip_helper_schedule_interval_millis(value: &IpHelperScheduleIntervalBucket) -> u64 {
    match value {
        IpHelperScheduleIntervalBucket::FifteenSeconds => 15_000,
        IpHelperScheduleIntervalBucket::ThirtySeconds => 30_000,
        IpHelperScheduleIntervalBucket::OneMinute => 60_000,
        IpHelperScheduleIntervalBucket::FiveMinutes => 300_000,
    }
}

fn ip_helper_schedule_timeout_millis(config: &IpHelperScheduleConfig) -> u64 {
    let provider = match config.provider_timeout_bucket {
        IpHelperScheduleTimeoutBucket::TwoHundredFiftyMillis => 250,
        IpHelperScheduleTimeoutBucket::OneSecond => 1_000,
        IpHelperScheduleTimeoutBucket::FiveSeconds => 2_000,
    };
    let execution = match config.execution_timeout_bucket {
        IpHelperScheduleTimeoutBucket::TwoHundredFiftyMillis => 250,
        IpHelperScheduleTimeoutBucket::OneSecond => 1_000,
        IpHelperScheduleTimeoutBucket::FiveSeconds => 2_000,
    };
    provider.min(execution).clamp(25, 2_000)
}

fn retry_state_for_ip_helper(
    value: &IpHelperScheduleRetryBudgetBucket,
) -> IpHelperScheduledRetryState {
    match value {
        IpHelperScheduleRetryBudgetBucket::None => IpHelperScheduledRetryState::Cleared,
        IpHelperScheduleRetryBudgetBucket::One | IpHelperScheduleRetryBudgetBucket::Three => {
            IpHelperScheduledRetryState::Scheduled
        }
    }
}

fn provider_health_label(value: NativeNetworkProviderHealth) -> &'static str {
    match value {
        NativeNetworkProviderHealth::Available => "available",
        NativeNetworkProviderHealth::Degraded => "degraded",
        NativeNetworkProviderHealth::Unavailable => "unavailable",
        NativeNetworkProviderHealth::UnsupportedPlatform => "unsupported_platform",
    }
}

fn quality_score(value: f32) -> QualityScore {
    QualityScore::new(value).unwrap_or_else(|_| QualityScore::unknown())
}

fn validate_runtime_safe_ref(field: &'static str, value: &str) -> CommandResult<()> {
    if value.trim().is_empty() || value.len() > 160 {
        return Err(provider_execution_error(format!("{field}_invalid")));
    }
    let normalized = value.to_ascii_lowercase();
    for marker in [
        "pid",
        "ppid",
        "raw_process_id",
        "process_name",
        "raw_address",
        "ip_address",
        "exact_ip",
        "port:",
        "exact_port",
        "socket",
        "handle",
        "interface_identifier",
        "hostname",
        "domain:",
        "raw_table",
        "packet_bytes",
        "packet_data",
        "payload",
        "path:",
        "c:\\",
        "\\users\\",
        "/users/",
        "/home/",
        "credential",
        "secret",
        "token",
        "password",
        "api_key",
        "http://",
        "https://",
    ] {
        if normalized.contains(marker) {
            return Err(provider_execution_error(format!("{field}_unsafe")));
        }
    }
    Ok(())
}

fn init_error(reason: &'static str) -> CoreError {
    CoreError::new(
        ErrorCode::InternalError,
        "runtime container initialization failed",
    )
    .with_severity(ErrorSeverity::Error)
    .with_redacted_details(json!({ "reason_category": reason }))
}

fn provider_execution_error(error: impl ToString) -> CoreError {
    CoreError::validation_failure("ip helper provider execution gate rejected request")
        .with_redacted_details(json!({ "reason_category": error.to_string() }))
}

fn storage_ownership_error(error: sentinel_storage::StorageError) -> CoreError {
    let reason = match error {
        sentinel_storage::StorageError::StorageOwnershipConflict(_) => "storage_writer_conflict",
        _ => "storage_writer_unavailable",
    };
    CoreError::new(
        ErrorCode::StorageUnavailable,
        "runtime storage writer ownership is unavailable",
    )
    .with_severity(ErrorSeverity::Error)
    .with_redacted_details(json!({ "reason_category": reason }))
}

fn next_epoch() -> u64 {
    Timestamp::now()
        .to_string()
        .bytes()
        .fold(1_u64, |acc, byte| {
            acc.wrapping_mul(31).wrapping_add(u64::from(byte)).max(1)
        })
}

fn duration_bucket(duration: Duration) -> &'static str {
    if duration <= Duration::from_millis(10) {
        "under_10_millis"
    } else if duration <= Duration::from_millis(100) {
        "under_100_millis"
    } else if duration <= Duration::from_secs(1) {
        "under_1_second"
    } else {
        "under_2_seconds"
    }
}

pub fn desktop_runtime_creation_gate(runtime_mode: RuntimeMode) -> CommandResult<()> {
    RuntimeOwnershipGuard::assert_desktop_can_create_production(runtime_mode)
        .map_err(CoreError::from)
}

pub fn runtime_constructor_inventory() -> Vec<(&'static str, &'static str, &'static str)> {
    legacy_runtime_constructor_inventory()
        .iter()
        .map(|entry| {
            (
                entry.file_module,
                entry.constructor.pattern(),
                entry.current_classification.as_str(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_capabilities::{
        AssetExposureInput, AssetExposurePlugin, BindScope, InventorySource, ListeningPortInput,
        ServiceInventoryInput, ServiceInventoryPlugin, ServiceKind,
    };
    use sentinel_contracts::{
        AttributionConfidence, CertificateContext, CollectionMode, DnsAnswer, DnsFeatures,
        DnsObservation, DomainContext, FlowRecord, IndicatorType, IntelligenceExportPolicy,
        IntelligenceLicenseClass, IntelligenceLookupStatus, IntelligenceRecord, IntelligenceSource,
        IntelligenceSourceClass, IpAddress, NetworkDirection, ProcessContext, SessionRecord,
        SignerStatus, TlsObservation, TransportProtocol, VisibilityLevel,
    };
    use sentinel_infrastructure::{
        EtwNetworkEventNormalizer, EtwNetworkNormalizerConfig, EtwSessionControlError,
        EtwSessionControlState, EtwTransientNetworkEvent, WindowsAuthRemoteControlState,
        WindowsAuthRemoteEventLogControl, WindowsAuthRemoteEventLogError,
        WindowsAuthRemoteEventLogOutcome, WindowsDnsSessionControl, WindowsDnsSessionOutcome,
    };
    use serde::Serialize;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    static RUNTIME_CONTAINER_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn activate_and_enable_ip_helper_schedule_for_tests(
        container: &mut RuntimeContainer,
        config: IpHelperScheduleConfig,
    ) -> RuntimeOwnerContext {
        let owner_context = container.owner_context().clone();
        container
            .activate_ip_helper_provider(&owner_context)
            .expect("activate ip helper");
        let configure_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::ConfigureIpHelperSchedule,
        );
        container
            .configure_ip_helper_schedule(
                &owner_context,
                config,
                vec!["ip_helper_schedule_configure_authorized".to_string()],
                configure_policy.policy_ref,
                configure_policy.policy_version,
            )
            .expect("configure schedule");
        let enable_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::EnableIpHelperSchedule,
        );
        container
            .enable_ip_helper_schedule(
                &owner_context,
                "ip_helper_schedule_lease_test".to_string(),
                vec!["ip_helper_schedule_enable_authorized".to_string()],
                enable_policy.policy_ref,
                enable_policy.policy_version,
            )
            .expect("enable schedule");
        owner_context
    }

    fn etw_handoff_batch() -> EtwNormalizedNetworkBatch {
        EtwNetworkEventNormalizer::new().normalize_bounded(
            vec![EtwTransientNetworkEvent::new_ipv4(
                Some(sentinel_contracts::EtwAllowedSchemaId::TcpConnectionLifecycleV1),
                1,
                sentinel_contracts::EtwNetworkActivityCategory::Connect,
                Ipv4Addr::new(10, 42, 0, 7),
                Ipv4Addr::new(203, 0, 113, 77),
                49_152,
                443,
                2_048,
                Some(42_424),
                9,
            )],
            EtwNetworkNormalizerConfig::default(),
        )
    }

    fn dns_handoff_batch() -> WindowsDnsObservationBatch {
        WindowsDnsObservationBatch {
            schema_version: sentinel_contracts::WINDOWS_DNS_SENSING_SCHEMA_VERSION,
            batch_ref: "dns_batch_test".to_string(),
            allowlist_ref: "microsoft_windows_dns_client_provider_allowlist_v1".to_string(),
            records: vec![sentinel_contracts::WindowsDnsObservation {
                schema_version: sentinel_contracts::WINDOWS_DNS_SENSING_SCHEMA_VERSION,
                observation_ref: "dns_observation_test".to_string(),
                query_ref: "dns_query_0123456789abcdef".to_string(),
                query_type_category: sentinel_contracts::WindowsDnsQueryTypeCategory::Address,
                result_category: sentinel_contracts::WindowsDnsResultCategory::Success,
                query_length_bucket: sentinel_contracts::WindowsDnsLengthBucket::Short,
                subdomain_depth_bucket: sentinel_contracts::WindowsDnsDepthBucket::Shallow,
                entropy_bucket: sentinel_contracts::WindowsDnsEntropyBucket::Low,
                answer_count_bucket: sentinel_contracts::WindowsDnsAnswerCountBucket::Unknown,
                recurrence_bucket: sentinel_contracts::WindowsDnsRecurrenceBucket::One,
                observed_at: Timestamp::now(),
                provenance_refs: vec!["windows_dns_client_etw".to_string()],
                redaction_status: RedactionStatus::Redacted,
            }],
            raw_events_observed: 1,
            normalized_events: 1,
            dropped_events: 0,
            overflow_events: 0,
            rate_limited_events: 0,
            schema_rejected_events: 0,
            duplicate_events: 0,
            provenance_refs: vec!["windows_dns_privacy_normalizer".to_string()],
            generated_at: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn c2_test_ip(value: &str) -> IpAddress {
        IpAddress::parse_str(value).expect("test ip")
    }

    fn c2_test_quality(value: f32) -> QualityScore {
        QualityScore::new(value).expect("quality")
    }

    fn c2_test_process_context() -> ProcessContext {
        let mut process = ProcessContext::new(4_242, "bounded_client");
        process.signer_status = SignerStatus::Unsigned;
        process.visibility_level = VisibilityLevel::MetadataOnly;
        process.collection_mode = CollectionMode::Mock;
        process
    }

    fn c2_test_flow(process: &ProcessContext, offset_seconds: i64, src_port: u16) -> FlowRecord {
        let start = chrono::Utc::now() + chrono::Duration::seconds(offset_seconds);
        let mut flow = FlowRecord::new(
            c2_test_ip("192.0.2.10"),
            src_port,
            c2_test_ip("198.51.100.24"),
            443,
            TransportProtocol::Tcp,
            NetworkDirection::Outbound,
        );
        flow.start_time = Timestamp::from_datetime(start);
        flow.end_time = Some(Timestamp::from_datetime(
            start + chrono::Duration::seconds(1),
        ));
        flow.duration_millis = Some(1_000);
        flow.bytes_out = 620;
        flow.bytes_in = 840;
        flow.packets_out = 3;
        flow.packets_in = 3;
        flow.process_ref = Some(process.process_context_id.clone());
        flow.attribution_confidence = AttributionConfidence::Medium;
        flow.quality_score = c2_test_quality(0.9);
        flow
    }

    fn c2_test_session(flow: &FlowRecord) -> SessionRecord {
        let mut session = SessionRecord::new(
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
            flow.protocol.clone(),
            flow.direction.clone(),
        );
        session.flow_refs.push(flow.flow_id.clone());
        session.start_time = flow.start_time.clone();
        session.end_time = flow.end_time.clone();
        session.duration_millis = flow.duration_millis;
        session.bytes_out = flow.bytes_out;
        session.bytes_in = flow.bytes_in;
        session.packets_out = flow.packets_out;
        session.packets_in = flow.packets_in;
        session.quality_score = c2_test_quality(0.86);
        session
    }

    fn c2_test_dns(process: &ProcessContext, flow: &FlowRecord) -> DnsObservation {
        let domain = "beacon.example.test";
        let mut observation = DnsObservation::new(
            domain,
            "A",
            c2_test_ip("203.0.113.53"),
            c2_test_ip("192.0.2.10"),
        )
        .expect("dns observation");
        observation.flow_ref = Some(flow.flow_id.clone());
        observation.process_ref = Some(process.process_context_id.clone());
        observation.timestamp = flow.start_time.clone();
        observation.answers = vec![DnsAnswer::Ip {
            address: flow.dst_ip,
            ttl_seconds: Some(60),
        }];
        observation.features = DnsFeatures {
            query_length: domain.len() as u16,
            label_count: 3,
            subdomain_depth: 2,
            character_entropy: Some(3.2),
            answer_count: 1,
        };
        observation.privacy_class = PrivacyClass::Internal;
        observation.quality_score = c2_test_quality(0.88);
        observation
    }

    fn c2_test_tls(process: &ProcessContext, flow: &FlowRecord) -> TlsObservation {
        let mut observation = TlsObservation::new();
        observation.flow_ref = Some(flow.flow_id.clone());
        observation.process_ref = Some(process.process_context_id.clone());
        observation.timestamp = flow.start_time.clone();
        observation.sni_protected = Some("beacon.example.test".to_string());
        observation.alpn = vec!["h2".to_string()];
        observation.ja3 = Some("ja3-runtime-container".to_string());
        observation.ja4 = Some("ja4-runtime-container".to_string());
        observation.tls_version = Some("tls1.3".to_string());
        observation.cipher_suite = Some("tls_aes_128_gcm_sha256".to_string());
        observation.certificate_fingerprint =
            Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string());
        observation.issuer_summary_protected = Some("runtime-container issuer".to_string());
        observation.privacy_class = PrivacyClass::Internal;
        observation.quality_score = c2_test_quality(0.86);
        observation
    }

    fn c2_test_source() -> IntelligenceSource {
        IntelligenceSource::new(
            "runtime-container-local-intel",
            IntelligenceSourceClass::BundledLocal,
            "bounded runtime container test data",
            "2026.06.01",
            IntelligenceLicenseClass::RedistributableFixture,
            PrivacyClass::Internal,
            IntelligenceExportPolicy::AllowRedactedSummary,
        )
        .expect("source")
    }

    fn c2_test_record(indicator_type: IndicatorType, indicator: &str) -> IntelligenceRecord {
        IntelligenceRecord::new(
            indicator_type,
            indicator,
            &c2_test_source(),
            "Bounded local context for runtime container wiring.",
        )
        .expect("record")
        .with_confidence(c2_test_quality(0.72))
        .with_expires_at(Timestamp::from_datetime(
            chrono::Utc::now() + chrono::Duration::days(30),
        ))
    }

    fn c2_test_domain_context() -> DomainContext {
        let record = c2_test_record(IndicatorType::Domain, "beacon.example.test");
        DomainContext {
            domain_protected: "beacon.example.test".to_string(),
            tld_protected: Some("test".to_string()),
            suspicious_tld: true,
            allowlisted: false,
            blocklisted: false,
            user_ioc_match: false,
            lexical_score: c2_test_quality(0.62),
            lookup_status: IntelligenceLookupStatus::Hit,
            risk_hints: Vec::new(),
            records: vec![record],
            confidence: c2_test_quality(0.72),
            retrieved_at: Timestamp::now(),
            expires_at: None,
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn c2_test_certificate_context() -> CertificateContext {
        let fingerprint = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let record = c2_test_record(IndicatorType::CertificateFingerprint, fingerprint);
        CertificateContext {
            fingerprint_protected: fingerprint.to_string(),
            issuer_summary_protected: Some("runtime-container issuer profile".to_string()),
            self_signed_hint: true,
            suspicious_issuer_hint: true,
            lookup_status: IntelligenceLookupStatus::Hit,
            records: vec![record],
            risk_hints: Vec::new(),
            confidence: c2_test_quality(0.66),
            retrieved_at: Timestamp::now(),
            expires_at: None,
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn c2_runtime_event<T: Serialize>(
        producer_plugin: &PluginId,
        topic: &str,
        payload: &T,
        quality_score: QualityScore,
        trace_context: &TraceContext,
    ) -> EventEnvelope {
        runtime_handoff_event(
            producer_plugin,
            topic,
            payload,
            SchemaVersion::new(1, 0, 0),
            quality_score,
            trace_context,
        )
        .expect("runtime handoff event")
    }

    fn c2_runtime_input_events(trace_context: &TraceContext) -> Vec<EventEnvelope> {
        let process = c2_test_process_context();
        let flow_a = c2_test_flow(&process, 0, 50_000);
        let flow_b = c2_test_flow(&process, 60, 50_001);
        let flow_c = c2_test_flow(&process, 120, 50_002);
        let sessions = [
            c2_test_session(&flow_a),
            c2_test_session(&flow_b),
            c2_test_session(&flow_c),
        ];
        let dns = c2_test_dns(&process, &flow_a);
        let tls = c2_test_tls(&process, &flow_a);
        let domain_context = c2_test_domain_context();
        let certificate_context = c2_test_certificate_context();
        let producer_plugin = PluginId::new_v4();
        let mut events = Vec::new();
        events.push(c2_runtime_event(
            &producer_plugin,
            IDENTITY_PROCESS_CONTEXT,
            &process,
            c2_test_quality(0.8),
            trace_context,
        ));
        for flow in [&flow_a, &flow_b, &flow_c] {
            events.push(c2_runtime_event(
                &producer_plugin,
                NETWORK_FLOW_RECORD,
                flow,
                flow.quality_score.clone(),
                trace_context,
            ));
        }
        for session in &sessions {
            events.push(c2_runtime_event(
                &producer_plugin,
                NETWORK_SESSION_RECORD,
                session,
                session.quality_score.clone(),
                trace_context,
            ));
        }
        events.push(c2_runtime_event(
            &producer_plugin,
            NETWORK_DNS_OBSERVATION,
            &dns,
            dns.quality_score.clone(),
            trace_context,
        ));
        events.push(c2_runtime_event(
            &producer_plugin,
            NETWORK_TLS_OBSERVATION,
            &tls,
            tls.quality_score.clone(),
            trace_context,
        ));
        events.push(c2_runtime_event(
            &producer_plugin,
            INTEL_DOMAIN_CONTEXT,
            &domain_context,
            domain_context.confidence.clone(),
            trace_context,
        ));
        events.push(c2_runtime_event(
            &producer_plugin,
            INTEL_CERTIFICATE_CONTEXT,
            &certificate_context,
            certificate_context.confidence.clone(),
            trace_context,
        ));
        events
    }

    fn lateral_test_process_context() -> ProcessContext {
        let mut process = ProcessContext::new(7_770, "bounded_lateral_scanner");
        process.signer_status = SignerStatus::Unsigned;
        process.visibility_level = VisibilityLevel::MetadataOnly;
        process.collection_mode = CollectionMode::Mock;
        process
    }

    fn lateral_test_service_process() -> ProcessContext {
        let mut process = ProcessContext::new(4_445, "bounded_lan_service");
        process.signer_status = SignerStatus::Signed;
        process.visibility_level = VisibilityLevel::MetadataOnly;
        process.collection_mode = CollectionMode::Mock;
        process
    }

    fn lateral_test_flow(
        process: Option<&ProcessContext>,
        dst_ip: &str,
        dst_port: u16,
        offset_seconds: i64,
        src_port: u16,
    ) -> FlowRecord {
        let start = chrono::Utc::now() + chrono::Duration::seconds(offset_seconds);
        let mut flow = FlowRecord::new(
            c2_test_ip("192.168.1.10"),
            src_port,
            c2_test_ip(dst_ip),
            dst_port,
            TransportProtocol::Tcp,
            NetworkDirection::Lateral,
        );
        flow.start_time = Timestamp::from_datetime(start);
        flow.end_time = Some(Timestamp::from_datetime(
            start + chrono::Duration::seconds(1),
        ));
        flow.duration_millis = Some(1_000);
        flow.bytes_out = 640;
        flow.bytes_in = 180;
        flow.packets_out = 3;
        flow.packets_in = 1;
        flow.process_ref = process.map(|process| process.process_context_id.clone());
        flow.attribution_confidence = if process.is_some() {
            AttributionConfidence::Medium
        } else {
            AttributionConfidence::Unknown
        };
        flow.quality_score = c2_test_quality(0.88);
        flow
    }

    fn lateral_test_session(flow: &FlowRecord) -> SessionRecord {
        let mut session = SessionRecord::new(
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
            flow.protocol.clone(),
            flow.direction.clone(),
        );
        session.flow_refs.push(flow.flow_id.clone());
        session.start_time = flow.start_time.clone();
        session.end_time = flow.end_time.clone();
        session.duration_millis = flow.duration_millis;
        session.bytes_out = flow.bytes_out;
        session.bytes_in = flow.bytes_in;
        session.packets_out = flow.packets_out;
        session.packets_in = flow.packets_in;
        session.quality_score = c2_test_quality(0.84);
        session
    }

    fn append_lateral_asset_events(
        events: &mut Vec<EventEnvelope>,
        producer_plugin: &PluginId,
        service_process: &ProcessContext,
        trace_context: &TraceContext,
    ) {
        let listening = ListeningPortInput::new(
            c2_test_ip("192.168.1.25"),
            445,
            TransportProtocol::Tcp,
            BindScope::Lan,
        )
        .with_process_context(service_process.clone(), AttributionConfidence::Low)
        .with_service("lan_smb", "LAN SMB", ServiceKind::WindowsService)
        .with_source(InventorySource::MockEndpointSnapshot);
        let inventory = ServiceInventoryPlugin::new()
            .inventory(ServiceInventoryInput::new(vec![listening]))
            .expect("service inventory");
        let exposure_input =
            AssetExposureInput::from_inventory(inventory, PluginId::new_v4()).expect("input");
        let exposure = AssetExposurePlugin::new()
            .observe(exposure_input.clone())
            .expect("asset exposure");
        events.push(c2_runtime_event(
            producer_plugin,
            ASSET_RECORD,
            &exposure_input.asset,
            c2_test_quality(0.78),
            trace_context,
        ));
        for service in &exposure_input.services {
            events.push(c2_runtime_event(
                producer_plugin,
                ASSET_SERVICE_RECORD,
                service,
                c2_test_quality(0.76),
                trace_context,
            ));
        }
        for port in &exposure_input.port_exposures {
            events.push(c2_runtime_event(
                producer_plugin,
                ASSET_PORT_EXPOSURE,
                port,
                c2_test_quality(0.74),
                trace_context,
            ));
        }
        for observation in &exposure.observations {
            events.push(c2_runtime_event(
                producer_plugin,
                ASSET_EXPOSURE_OBSERVATION,
                observation,
                c2_test_quality(0.72),
                trace_context,
            ));
        }
        for finding in &exposure.findings {
            events.push(c2_runtime_event(
                producer_plugin,
                SECURITY_FINDING_ASSET_RISK,
                finding,
                c2_test_quality(0.7),
                trace_context,
            ));
        }
    }

    fn lateral_runtime_input_events(trace_context: &TraceContext) -> Vec<EventEnvelope> {
        let scanner = lateral_test_process_context();
        let service_process = lateral_test_service_process();
        let flows = vec![
            lateral_test_flow(Some(&scanner), "192.168.1.21", 445, 1, 51_001),
            lateral_test_flow(Some(&scanner), "192.168.1.22", 3389, 2, 51_002),
            lateral_test_flow(Some(&scanner), "192.168.1.23", 5985, 3, 51_003),
            lateral_test_flow(Some(&scanner), "192.168.1.25", 445, 4, 51_004),
            lateral_test_flow(None, "192.168.1.26", 22, 5, 51_005),
        ];
        let sessions = flows.iter().map(lateral_test_session).collect::<Vec<_>>();
        let producer_plugin = PluginId::new_v4();
        let mut events = Vec::new();
        for process in [&scanner, &service_process] {
            events.push(c2_runtime_event(
                &producer_plugin,
                IDENTITY_PROCESS_CONTEXT,
                process,
                c2_test_quality(0.8),
                trace_context,
            ));
        }
        for flow in &flows {
            events.push(c2_runtime_event(
                &producer_plugin,
                NETWORK_FLOW_RECORD,
                flow,
                flow.quality_score.clone(),
                trace_context,
            ));
        }
        for session in &sessions {
            events.push(c2_runtime_event(
                &producer_plugin,
                NETWORK_SESSION_RECORD,
                session,
                session.quality_score.clone(),
                trace_context,
            ));
        }
        append_lateral_asset_events(
            &mut events,
            &producer_plugin,
            &service_process,
            trace_context,
        );
        events
    }

    fn lateral_flow_only_input_events(trace_context: &TraceContext) -> Vec<EventEnvelope> {
        let flow = lateral_test_flow(None, "192.168.1.21", 445, 1, 52_001);
        let session = lateral_test_session(&flow);
        let producer_plugin = PluginId::new_v4();
        vec![
            c2_runtime_event(
                &producer_plugin,
                NETWORK_FLOW_RECORD,
                &flow,
                flow.quality_score.clone(),
                trace_context,
            ),
            c2_runtime_event(
                &producer_plugin,
                NETWORK_SESSION_RECORD,
                &session,
                session.quality_score.clone(),
                trace_context,
            ),
        ]
    }

    fn auth_remote_handoff_batch() -> WindowsAuthRemoteObservationBatch {
        WindowsAuthRemoteObservationBatch {
            batch_ref: "auth_remote_batch_test".to_string(),
            provider_ref: "windows_event_log_security".to_string(),
            schema_version: sentinel_contracts::WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
            observations: vec![WindowsAuthRemoteObservation {
                observation_ref: "auth_remote_observation_test".to_string(),
                event_category: sentinel_contracts::WindowsAuthRemoteEventId::FailedLogon,
                schema_category: sentinel_contracts::WindowsAuthSchemaCategory::Security4625V0,
                event_version: 0,
                auth_result: WindowsAuthResultCategory::Failure,
                auth_mechanism: sentinel_contracts::WindowsAuthMechanismCategory::Ntlm,
                account_category: sentinel_contracts::WindowsAuthAccountCategory::DomainUser,
                privilege_bucket: sentinel_contracts::WindowsAuthPrivilegeBucket::Standard,
                remote_protocol_category: Some(WindowsRemoteProtocolCategory::Network),
                failure_category: Some(WindowsAuthFailureCategory::BadSecret),
                repeated_failure_bucket: Some(PortableAuthAttemptCountBucket::One),
                success_after_failure: false,
                identity_ref: Some("acct_ref_test".to_string()),
                source_ref: Some("source_ref_test".to_string()),
                target_ref: Some("target_scope_local_system".to_string()),
                observed_bucket: sentinel_contracts::WindowsAuthObservedBucket::CurrentWindow,
                source_reliability:
                    sentinel_contracts::WindowsAuthSourceReliability::SecurityLogVerified,
                freshness: sentinel_contracts::WindowsAuthFreshnessCategory::Fresh,
                provenance_ref: "windows_event_log_security".to_string(),
                missing_visibility: vec!["subject_source_target_values_bucketed".to_string()],
                time_bucket_start: Timestamp::now(),
                redaction_status: RedactionStatus::Hashed,
                quality_score: quality_score(0.74),
            }],
            counters: sentinel_contracts::WindowsAuthRemoteCounters {
                raw_events_observed: 1,
                schema_accepted: 1,
                normalized_auth_observations: 1,
                normalized_remote_access_observations: 1,
                worker_active: true,
                ..sentinel_contracts::WindowsAuthRemoteCounters::default()
            },
            cursor_ref: Some("event_log_cursor_test".to_string()),
            channel_refs: vec!["security".to_string()],
            degraded_reason: None,
            generated_at: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn rdp_operational_handoff_batch() -> WindowsAuthRemoteObservationBatch {
        WindowsAuthRemoteObservationBatch {
            batch_ref: "rdp_operational_batch_test".to_string(),
            provider_ref: "windows_rdp_operational_event_log".to_string(),
            schema_version: sentinel_contracts::WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
            observations: vec![WindowsAuthRemoteObservation {
                observation_ref: "rdp_operational_observation_test".to_string(),
                event_category: sentinel_contracts::WindowsAuthRemoteEventId::SuccessfulLogon,
                schema_category: sentinel_contracts::WindowsAuthSchemaCategory::TerminalServicesRemoteConnectionManager1149V0,
                event_version: 0,
                auth_result: WindowsAuthResultCategory::Success,
                auth_mechanism: sentinel_contracts::WindowsAuthMechanismCategory::Unknown,
                account_category: sentinel_contracts::WindowsAuthAccountCategory::DomainUser,
                privilege_bucket: sentinel_contracts::WindowsAuthPrivilegeBucket::Standard,
                remote_protocol_category: Some(WindowsRemoteProtocolCategory::Rdp),
                failure_category: None,
                repeated_failure_bucket: None,
                success_after_failure: false,
                identity_ref: Some("acct_ref_rdp_test".to_string()),
                source_ref: Some("source_ref_rdp_test".to_string()),
                target_ref: Some("target_scope_local_terminal_services".to_string()),
                observed_bucket: sentinel_contracts::WindowsAuthObservedBucket::ExistingHostEvents,
                source_reliability:
                    sentinel_contracts::WindowsAuthSourceReliability::OptionalChannelVerified,
                freshness: sentinel_contracts::WindowsAuthFreshnessCategory::Fresh,
                provenance_ref: "windows_terminal_services_operational".to_string(),
                missing_visibility: vec!["raw_user_domain_client_session_discarded".to_string()],
                time_bucket_start: Timestamp::now(),
                redaction_status: RedactionStatus::Hashed,
                quality_score: quality_score(0.68),
            }],
            counters: sentinel_contracts::WindowsAuthRemoteCounters {
                raw_events_observed: 1,
                schema_accepted: 1,
                normalized_auth_observations: 1,
                normalized_remote_access_observations: 1,
                worker_active: true,
                ..sentinel_contracts::WindowsAuthRemoteCounters::default()
            },
            cursor_ref: Some("rdp_event_log_cursor_test".to_string()),
            channel_refs: vec!["terminal_services_remoteconnectionmanager_operational".to_string()],
            degraded_reason: None,
            generated_at: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn smb_operational_handoff_batch() -> WindowsAuthRemoteObservationBatch {
        WindowsAuthRemoteObservationBatch {
            batch_ref: "smb_operational_batch_test".to_string(),
            provider_ref: "windows_smb_operational_event_log".to_string(),
            schema_version: sentinel_contracts::WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
            observations: vec![
                WindowsAuthRemoteObservation {
                    observation_ref: "smb_operational_connectivity_observation_test".to_string(),
                    event_category: sentinel_contracts::WindowsAuthRemoteEventId::Unknown,
                    schema_category:
                        sentinel_contracts::WindowsAuthSchemaCategory::SmbClientConnectivity30806V2,
                    event_version: 2,
                    auth_result: WindowsAuthResultCategory::Success,
                    auth_mechanism: sentinel_contracts::WindowsAuthMechanismCategory::Unknown,
                    account_category: sentinel_contracts::WindowsAuthAccountCategory::Unknown,
                    privilege_bucket: sentinel_contracts::WindowsAuthPrivilegeBucket::Unknown,
                    remote_protocol_category: Some(WindowsRemoteProtocolCategory::Smb),
                    failure_category: None,
                    repeated_failure_bucket: None,
                    success_after_failure: false,
                    identity_ref: None,
                    source_ref: Some("source_ref_smb_connectivity".to_string()),
                    target_ref: Some("target_scope_smb_service".to_string()),
                    observed_bucket:
                        sentinel_contracts::WindowsAuthObservedBucket::ExistingHostEvents,
                    source_reliability:
                        sentinel_contracts::WindowsAuthSourceReliability::OptionalChannelVerified,
                    freshness: sentinel_contracts::WindowsAuthFreshnessCategory::Fresh,
                    provenance_ref: "windows_smb_operational_event_log".to_string(),
                    missing_visibility: vec![
                        "connectivity_only_no_auth_identity".to_string(),
                        "raw_share_unc_endpoint_refs_discarded".to_string(),
                    ],
                    time_bucket_start: Timestamp::now(),
                    redaction_status: RedactionStatus::Redacted,
                    quality_score: quality_score(0.62),
                },
                WindowsAuthRemoteObservation {
                    observation_ref: "smb_operational_auth_observation_test".to_string(),
                    event_category: sentinel_contracts::WindowsAuthRemoteEventId::FailedLogon,
                    schema_category:
                        sentinel_contracts::WindowsAuthSchemaCategory::SmbClientSecurity31017V0,
                    event_version: 0,
                    auth_result: WindowsAuthResultCategory::Failure,
                    auth_mechanism: sentinel_contracts::WindowsAuthMechanismCategory::Unknown,
                    account_category: sentinel_contracts::WindowsAuthAccountCategory::Unknown,
                    privilege_bucket: sentinel_contracts::WindowsAuthPrivilegeBucket::Unknown,
                    remote_protocol_category: Some(WindowsRemoteProtocolCategory::Smb),
                    failure_category: Some(WindowsAuthFailureCategory::NotAllowed),
                    repeated_failure_bucket: Some(PortableAuthAttemptCountBucket::One),
                    success_after_failure: false,
                    identity_ref: Some("acct_ref_smb_policy".to_string()),
                    source_ref: Some("source_ref_smb_policy".to_string()),
                    target_ref: Some("target_scope_smb_service".to_string()),
                    observed_bucket:
                        sentinel_contracts::WindowsAuthObservedBucket::ExistingHostEvents,
                    source_reliability:
                        sentinel_contracts::WindowsAuthSourceReliability::OptionalChannelVerified,
                    freshness: sentinel_contracts::WindowsAuthFreshnessCategory::Fresh,
                    provenance_ref: "windows_smb_operational_event_log".to_string(),
                    missing_visibility: vec![
                        "raw_share_unc_endpoint_refs_discarded".to_string(),
                        "identity_source_target_refs_only".to_string(),
                    ],
                    time_bucket_start: Timestamp::now(),
                    redaction_status: RedactionStatus::Hashed,
                    quality_score: quality_score(0.66),
                },
            ],
            counters: sentinel_contracts::WindowsAuthRemoteCounters {
                raw_events_observed: 2,
                schema_accepted: 2,
                normalized_auth_observations: 1,
                normalized_remote_access_observations: 2,
                worker_active: true,
                ..sentinel_contracts::WindowsAuthRemoteCounters::default()
            },
            cursor_ref: Some("smb_event_log_cursor_test".to_string()),
            channel_refs: vec![
                "smb_client_connectivity".to_string(),
                "smb_client_security".to_string(),
            ],
            degraded_reason: None,
            generated_at: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn ssh_operational_handoff_batch() -> WindowsAuthRemoteObservationBatch {
        WindowsAuthRemoteObservationBatch {
            batch_ref: "ssh_operational_batch_test".to_string(),
            provider_ref: "windows_openssh_operational_event_log".to_string(),
            schema_version: sentinel_contracts::WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
            observations: vec![
                WindowsAuthRemoteObservation {
                    observation_ref: "ssh_operational_auth_observation_test".to_string(),
                    event_category: sentinel_contracts::WindowsAuthRemoteEventId::FailedLogon,
                    schema_category:
                        sentinel_contracts::WindowsAuthSchemaCategory::OpenSshOperational4AuthFailurePasswordV0,
                    event_version: 0,
                    auth_result: WindowsAuthResultCategory::Failure,
                    auth_mechanism: sentinel_contracts::WindowsAuthMechanismCategory::ExplicitCredential,
                    account_category: sentinel_contracts::WindowsAuthAccountCategory::Unknown,
                    privilege_bucket: sentinel_contracts::WindowsAuthPrivilegeBucket::Unknown,
                    remote_protocol_category: Some(WindowsRemoteProtocolCategory::Ssh),
                    failure_category: Some(WindowsAuthFailureCategory::BadSecret),
                    repeated_failure_bucket: Some(PortableAuthAttemptCountBucket::One),
                    success_after_failure: false,
                    identity_ref: Some("ssh_actor_ref_test".to_string()),
                    source_ref: Some("ssh_source_ref_test".to_string()),
                    target_ref: Some("ssh_service_scope".to_string()),
                    observed_bucket:
                        sentinel_contracts::WindowsAuthObservedBucket::ExistingHostEvents,
                    source_reliability:
                        sentinel_contracts::WindowsAuthSourceReliability::OptionalChannelVerified,
                    freshness: sentinel_contracts::WindowsAuthFreshnessCategory::Fresh,
                    provenance_ref: "windows_openssh_operational_event_log".to_string(),
                    missing_visibility: vec![
                        "ssh_actor_ref_bucketed".to_string(),
                        "ssh_peer_ref_bucketed".to_string(),
                        "exec_detail_not_collected".to_string(),
                    ],
                    time_bucket_start: Timestamp::now(),
                    redaction_status: RedactionStatus::Hashed,
                    quality_score: quality_score(0.63),
                },
                WindowsAuthRemoteObservation {
                    observation_ref: "ssh_operational_session_observation_test".to_string(),
                    event_category: sentinel_contracts::WindowsAuthRemoteEventId::Logoff,
                    schema_category:
                        sentinel_contracts::WindowsAuthSchemaCategory::OpenSshOperational4SessionClosedV0,
                    event_version: 0,
                    auth_result: WindowsAuthResultCategory::Logoff,
                    auth_mechanism: sentinel_contracts::WindowsAuthMechanismCategory::Unknown,
                    account_category: sentinel_contracts::WindowsAuthAccountCategory::Unknown,
                    privilege_bucket: sentinel_contracts::WindowsAuthPrivilegeBucket::Unknown,
                    remote_protocol_category: Some(WindowsRemoteProtocolCategory::Ssh),
                    failure_category: None,
                    repeated_failure_bucket: None,
                    success_after_failure: false,
                    identity_ref: None,
                    source_ref: Some("ssh_source_scope_unavailable".to_string()),
                    target_ref: Some("ssh_service_scope".to_string()),
                    observed_bucket:
                        sentinel_contracts::WindowsAuthObservedBucket::ExistingHostEvents,
                    source_reliability:
                        sentinel_contracts::WindowsAuthSourceReliability::OptionalChannelVerified,
                    freshness: sentinel_contracts::WindowsAuthFreshnessCategory::Fresh,
                    provenance_ref: "windows_openssh_operational_event_log".to_string(),
                    missing_visibility: vec![
                        "non_auth_schema_auth_dispatch_skipped".to_string(),
                        "ssh_actor_ref_bucketed".to_string(),
                    ],
                    time_bucket_start: Timestamp::now(),
                    redaction_status: RedactionStatus::Redacted,
                    quality_score: quality_score(0.60),
                },
            ],
            counters: sentinel_contracts::WindowsAuthRemoteCounters {
                raw_events_observed: 2,
                schema_accepted: 2,
                normalized_auth_observations: 1,
                normalized_remote_access_observations: 2,
                worker_active: true,
                ..sentinel_contracts::WindowsAuthRemoteCounters::default()
            },
            cursor_ref: Some("ssh_event_log_cursor_test".to_string()),
            channel_refs: vec!["openssh_operational".to_string()],
            degraded_reason: None,
            generated_at: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    struct RuntimeDnsControl {
        drained: Arc<AtomicBool>,
    }

    impl WindowsDnsSessionControl for RuntimeDnsControl {
        fn start(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
            Ok(runtime_dns_outcome(
                EtwSessionControlState::Active,
                Vec::new(),
            ))
        }

        fn pause(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
            Ok(runtime_dns_outcome(
                EtwSessionControlState::Paused,
                Vec::new(),
            ))
        }

        fn resume(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
            self.start()
        }

        fn stop(&mut self) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
            Ok(runtime_dns_outcome(
                EtwSessionControlState::Stopped,
                Vec::new(),
            ))
        }

        fn drain_normalized_batches(
            &mut self,
            _max_batches: usize,
        ) -> Result<WindowsDnsSessionOutcome, EtwSessionControlError> {
            let batches = if self.drained.swap(true, Ordering::SeqCst) {
                Vec::new()
            } else {
                vec![dns_handoff_batch()]
            };
            Ok(runtime_dns_outcome(EtwSessionControlState::Active, batches))
        }
    }

    struct RuntimeAuthRemoteControl {
        drained: Arc<AtomicBool>,
    }

    impl WindowsAuthRemoteEventLogControl for RuntimeAuthRemoteControl {
        fn start(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Active,
                Vec::new(),
            ))
        }

        fn pause(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Paused,
                Vec::new(),
            ))
        }

        fn resume(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            self.start()
        }

        fn stop(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Stopped,
                Vec::new(),
            ))
        }

        fn drain_normalized_batches(
            &mut self,
            _max_batches: usize,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            let batches = if self.drained.swap(true, Ordering::SeqCst) {
                Vec::new()
            } else {
                vec![auth_remote_handoff_batch()]
            };
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Active,
                batches,
            ))
        }
    }

    struct RuntimeRdpOperationalControl {
        drained: Arc<AtomicBool>,
    }

    impl WindowsAuthRemoteEventLogControl for RuntimeRdpOperationalControl {
        fn start(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Active,
                Vec::new(),
            ))
        }

        fn pause(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Paused,
                Vec::new(),
            ))
        }

        fn resume(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            self.start()
        }

        fn stop(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Stopped,
                Vec::new(),
            ))
        }

        fn drain_normalized_batches(
            &mut self,
            _max_batches: usize,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            let batches = if self.drained.swap(true, Ordering::SeqCst) {
                Vec::new()
            } else {
                vec![rdp_operational_handoff_batch()]
            };
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Active,
                batches,
            ))
        }
    }

    struct RuntimeSmbOperationalControl {
        drained: Arc<AtomicBool>,
    }

    impl WindowsAuthRemoteEventLogControl for RuntimeSmbOperationalControl {
        fn start(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Active,
                Vec::new(),
            ))
        }

        fn pause(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Paused,
                Vec::new(),
            ))
        }

        fn resume(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            self.start()
        }

        fn stop(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Stopped,
                Vec::new(),
            ))
        }

        fn drain_normalized_batches(
            &mut self,
            _max_batches: usize,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            let batches = if self.drained.swap(true, Ordering::SeqCst) {
                Vec::new()
            } else {
                vec![smb_operational_handoff_batch()]
            };
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Active,
                batches,
            ))
        }
    }

    struct RuntimeSshOperationalControl {
        drained: Arc<AtomicBool>,
    }

    impl WindowsAuthRemoteEventLogControl for RuntimeSshOperationalControl {
        fn start(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Active,
                Vec::new(),
            ))
        }

        fn pause(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Paused,
                Vec::new(),
            ))
        }

        fn resume(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            self.start()
        }

        fn stop(
            &mut self,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Stopped,
                Vec::new(),
            ))
        }

        fn drain_normalized_batches(
            &mut self,
            _max_batches: usize,
        ) -> Result<WindowsAuthRemoteEventLogOutcome, WindowsAuthRemoteEventLogError> {
            let batches = if self.drained.swap(true, Ordering::SeqCst) {
                Vec::new()
            } else {
                vec![ssh_operational_handoff_batch()]
            };
            Ok(runtime_auth_remote_outcome(
                WindowsAuthRemoteControlState::Active,
                batches,
            ))
        }
    }

    fn runtime_auth_remote_outcome(
        state: WindowsAuthRemoteControlState,
        normalized_batches: Vec<WindowsAuthRemoteObservationBatch>,
    ) -> WindowsAuthRemoteEventLogOutcome {
        let active = state == WindowsAuthRemoteControlState::Active;
        WindowsAuthRemoteEventLogOutcome {
            state,
            provider_enabled: active,
            channels_ready: if active { 1 } else { 0 },
            channels_unavailable: 0,
            collection_started: active,
            consumer_started: active,
            consumer_worker_active: active,
            consumer_worker_joined: !active,
            raw_events_observed: 1,
            schema_accepted: 1,
            schema_rejected: 0,
            malformed_events: 0,
            rate_limited_events: 0,
            queue_dropped_events: 0,
            duplicate_suppressed_events: 0,
            normalized_auth_observations: 1,
            normalized_remote_access_observations: 1,
            bookmark_updates: 1,
            record_gaps: 0,
            normalized_batches,
            cursor_ref: Some("event_log_cursor_test".to_string()),
            degraded_reason: None,
        }
    }

    fn runtime_dns_outcome(
        state: EtwSessionControlState,
        normalized_batches: Vec<WindowsDnsObservationBatch>,
    ) -> WindowsDnsSessionOutcome {
        let active = state == EtwSessionControlState::Active;
        WindowsDnsSessionOutcome {
            state,
            trace_session_created: active,
            provider_enabled: active,
            collection_started: active,
            consumer_started: active,
            consumer_worker_active: active,
            consumer_worker_joined: !active,
            raw_events_observed: 1,
            normalized_events: 1,
            dropped_events: 0,
            overflow_events: 0,
            rate_limited_events: 0,
            schema_rejected_events: 0,
            duplicate_events: 0,
            normalized_batches,
            degraded_reason: None,
        }
    }

    #[test]
    fn runtime_container_builds_exactly_one_service_owned_runtime_and_no_providers() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");

        assert_eq!(container.event_bus_count(), 1);
        assert_eq!(container.storage_writer_count(), 1);
        assert!(container.storage_canonical_writer());
        assert_eq!(
            container.storage_writer_state(),
            Some(StorageWriterState::Owned)
        );
        assert_eq!(container.dag_count(), 1);
        assert_eq!(container.plugin_runtime_count(), 1);
        assert_eq!(container.capability_registry_count(), 1);
        assert_eq!(container.runtime_services_count(), 1);
        assert_eq!(container.app_core_orchestration_count(), 1);
        assert!(container.app_core_has_container_owned_runtime_context());
        assert_eq!(
            container.app_core_runtime_epoch(),
            Some(container.owner_context.ownership_epoch)
        );
        assert_eq!(container.portable_runtime_orchestration_count(), 4);
        assert_eq!(container.native_permission_runtime_count(), 1);
        assert_eq!(container.scheduler_controller_count(), 1);
        assert_eq!(container.scheduler_host_owner_count(), 1);
        assert_eq!(container.sampler_runtime_count(), 1);
        assert_eq!(container.endpoint_threat_runtime_count(), 1);
        assert_eq!(container.fusion_state_count(), 1);
        assert_eq!(container.evidence_quality_state_count(), 1);
        assert_eq!(container.risk_state_count(), 1);
        assert_eq!(container.attack_context_state_count(), 1);
        assert_eq!(container.graph_state_count(), 1);
        assert_eq!(container.baseline_state_count(), 1);
        assert_eq!(container.incident_linking_state_count(), 1);
        assert_eq!(container.read_model_store_count(), 1);
        assert_eq!(container.report_export_traceability_state_count(), 1);
        assert!(container.actual_runtime_component_count() >= 20);
        assert!(container.topic_count() > 0);
        assert!(container.plugin_registration_count() >= 10);
        assert_eq!(container.fusion_runtime_engine_count(), 1);
        assert_eq!(container.risk_runtime_engine_count(), 1);
        assert_eq!(container.graph_runtime_engine_count(), 2);
        assert!(container.attack_context_row_count() > 0);
        assert_eq!(container.endpoint_runtime_finding_count(), 0);
        assert!(container.evidence_quality_record_count() > 0);
        assert_eq!(container.baseline_record_count(), 0);
        assert_eq!(container.incident_linked_group_count(), 0);
        assert_eq!(container.report_export_traceability_ref_count(), 0);
        assert!(container.scheduler_starts_disabled());
        assert!(container.scheduler_host_starts_stopped());
        assert!(container.samplers_start_inactive());
        assert_eq!(container.provider_controller.state(), "inactive");
        assert_eq!(container.provider_call_count(), 0);
        assert_eq!(container.startup_side_effect_count(), 0);
        assert_eq!(container.summary().runtime_mode, RuntimeMode::ServiceOwned);
        container.summary().validate().expect("summary");
        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn etw_lifecycle_shutdown_joins_servicehost_owned_control_thread() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();
        let status = container
            .activate_etw_provider(
                &owner_context,
                vec!["etw_shutdown_test_authorization".to_string()],
            )
            .expect("bounded ETW lifecycle status");
        assert!(matches!(
            status.etw_lifecycle.lifecycle_state,
            EtwLifecycleState::Active | EtwLifecycleState::Degraded
        ));
        assert_eq!(status.provider_zero.native_network_topic_publications, 0);
        assert_eq!(status.provider_zero.process_network_facts, 0);
        let snapshot = container
            .canonical_read_model_snapshot()
            .expect("canonical provider snapshot");
        let provider_item = snapshot
            .items
            .iter()
            .find(|item| {
                item.model_category == CanonicalReadModelCategory::ProviderControllerStatus
            })
            .expect("provider controller item");
        assert!(provider_item
            .bounded_categories
            .iter()
            .any(|category| category.starts_with("etw_lifecycle_")));
        assert!(provider_item
            .bounded_categories
            .iter()
            .any(|category| category.starts_with("etw_fallback_")));

        let before_ipc = container
            .shutdown_before_ipc_close()
            .expect("ordered shutdown before IPC close");
        assert!(before_ipc.shutdown.provider_stop_called);
        assert_eq!(
            container
                .provider_controller_status()
                .expect("provider status")
                .etw_lifecycle
                .lifecycle_state,
            EtwLifecycleState::Stopped
        );
        container
            .complete_shutdown_after_ipc_close()
            .expect("complete shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn etw_handoff_requires_explicit_authorization() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();

        assert!(container
            .execute_etw_network_handoff(&owner_context, etw_handoff_batch())
            .is_err());
        assert!(container.summary().provider_zero.all_zero());
        assert_eq!(
            container
                .app_core_orchestration
                .as_ref()
                .expect("orchestration")
                .read_state()
                .security_facts
                .items
                .len(),
            0
        );

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn auth_remote_sensing_starts_disabled_and_requires_explicit_authorization() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();
        let initial = container
            .auth_remote_sensing_lifecycle_status()
            .expect("auth remote lifecycle");
        assert_eq!(initial.lifecycle_state, EtwLifecycleState::Inactive);
        assert_eq!(initial.authorization_state, EtwAuthorizationState::Required);
        assert!(!initial.provider_enabled);
        assert!(container
            .execute_auth_remote_sensing_handoff(&owner_context, auth_remote_handoff_batch())
            .is_err());
        assert!(container.summary().provider_zero.all_zero());

        let drained = Arc::new(AtomicBool::new(false));
        let factory: Arc<dyn Fn() -> Box<dyn WindowsAuthRemoteEventLogControl> + Send + Sync> =
            Arc::new({
                let drained = Arc::clone(&drained);
                move || {
                    Box::new(RuntimeAuthRemoteControl {
                        drained: Arc::clone(&drained),
                    })
                }
            });
        container.auth_remote_sensing_lifecycle_runtime = Some(
            ServiceOwnedAuthRemoteSensingLifecycleRuntime::for_test(&owner_context, factory),
        );

        let active = container
            .activate_auth_remote_sensing(
                &owner_context,
                vec!["auth_remote_authorization_ref".to_string()],
            )
            .expect("activate auth remote sensing");
        let provider = active
            .provider(NetworkProviderKind::WindowsAuthRemote)
            .expect("auth remote provider");
        assert_eq!(
            provider.lifecycle_state,
            NetworkProviderLifecycleState::Active
        );
        assert_eq!(active.provider_zero.auth_remote_sensing_calls, 1);
        assert!(container
            .auth_remote_sensing_live_pump_wait_millis()
            .is_some());

        let paused = container
            .pause_auth_remote_sensing(
                &owner_context,
                vec!["auth_remote_pause_authorization_ref".to_string()],
            )
            .expect("pause auth remote sensing");
        assert_eq!(
            paused
                .provider(NetworkProviderKind::WindowsAuthRemote)
                .expect("auth remote provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Paused
        );
        let resumed = container
            .resume_auth_remote_sensing(
                &owner_context,
                vec!["auth_remote_resume_authorization_ref".to_string()],
            )
            .expect("resume auth remote sensing");
        assert_eq!(
            resumed
                .provider(NetworkProviderKind::WindowsAuthRemote)
                .expect("auth remote provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Active
        );
        let stopped = container
            .stop_auth_remote_sensing(
                &owner_context,
                vec!["auth_remote_stop_authorization_ref".to_string()],
            )
            .expect("stop auth remote sensing");
        assert_eq!(
            stopped
                .provider(NetworkProviderKind::WindowsAuthRemote)
                .expect("auth remote provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Stopped
        );
        let lifecycle = container
            .auth_remote_sensing_lifecycle_status()
            .expect("auth remote lifecycle");
        assert!(lifecycle.consumer_worker_joined);
        assert!(!lifecycle.consumer_worker_active);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn auth_remote_sensing_pumps_existing_runtime_path_to_security_facts() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();
        let drained = Arc::new(AtomicBool::new(false));
        let factory: Arc<dyn Fn() -> Box<dyn WindowsAuthRemoteEventLogControl> + Send + Sync> =
            Arc::new({
                let drained = Arc::clone(&drained);
                move || {
                    Box::new(RuntimeAuthRemoteControl {
                        drained: Arc::clone(&drained),
                    })
                }
            });
        container.auth_remote_sensing_lifecycle_runtime = Some(
            ServiceOwnedAuthRemoteSensingLifecycleRuntime::for_test(&owner_context, factory),
        );
        container
            .activate_auth_remote_sensing(
                &owner_context,
                vec!["auth_remote_handoff_authorized".to_string()],
            )
            .expect("activate auth remote sensing");

        let result = container
            .pump_auth_remote_sensing_live_batches()
            .expect("pump auth remote sensing batch");

        assert_eq!(result.published_batches, 1);
        assert_eq!(result.normalized_batches, 1);
        assert!(result.eventbus_publications > 0);
        assert!(result.auth_detector_invocations > 0);
        assert!(result.auth_consumed > 0);
        assert_eq!(result.remote_admin_invocations, 0);
        assert_eq!(result.lateral_invocations, 0);
        assert!(result.downstream_facts > 0);
        assert_eq!(result.dropped_events, 0);
        let status = container
            .provider_controller_status()
            .expect("provider status");
        assert_eq!(
            status.provider_zero.auth_remote_auth_detector_invocations,
            result.auth_detector_invocations
        );
        assert_eq!(
            status.provider_zero.auth_remote_downstream_facts,
            result.downstream_facts
        );
        assert_eq!(status.provider_zero.process_network_facts, 0);
        assert_eq!(status.provider_zero.packet_facts, 0);
        assert!(status.provider_zero.auth_remote_sensing_only());
        let read = container
            .app_core_orchestration
            .as_ref()
            .expect("orchestration")
            .read_state();
        assert!(read
            .security_facts
            .items
            .iter()
            .any(|fact| fact.layer == sentinel_contracts::SecurityLayer::AuthIdentity));

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn rdp_operational_sensing_starts_disabled_and_requires_explicit_authorization() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();
        let initial = container
            .rdp_operational_sensing_lifecycle_status()
            .expect("rdp operational lifecycle");
        assert_eq!(initial.lifecycle_state, EtwLifecycleState::Inactive);
        assert_eq!(initial.authorization_state, EtwAuthorizationState::Required);
        assert!(!initial.provider_enabled);
        assert!(container
            .execute_rdp_operational_sensing_handoff(
                &owner_context,
                rdp_operational_handoff_batch()
            )
            .is_err());
        assert!(container.summary().provider_zero.all_zero());

        let drained = Arc::new(AtomicBool::new(false));
        let factory: Arc<dyn Fn() -> Box<dyn WindowsAuthRemoteEventLogControl> + Send + Sync> =
            Arc::new({
                let drained = Arc::clone(&drained);
                move || {
                    Box::new(RuntimeRdpOperationalControl {
                        drained: Arc::clone(&drained),
                    })
                }
            });
        container.rdp_operational_sensing_lifecycle_runtime = Some(
            ServiceOwnedAuthRemoteSensingLifecycleRuntime::for_test(&owner_context, factory),
        );

        let active = container
            .activate_rdp_operational_sensing(
                &owner_context,
                vec!["rdp_operational_authorization_ref".to_string()],
            )
            .expect("activate rdp operational sensing");
        assert_eq!(
            active
                .provider(NetworkProviderKind::WindowsRdpOperational)
                .expect("rdp provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Active
        );
        assert_eq!(active.provider_zero.rdp_operational_sensing_calls, 1);
        assert!(container
            .rdp_operational_sensing_live_pump_wait_millis()
            .is_some());

        let paused = container
            .pause_rdp_operational_sensing(
                &owner_context,
                vec!["rdp_operational_pause_authorization_ref".to_string()],
            )
            .expect("pause rdp operational sensing");
        assert_eq!(
            paused
                .provider(NetworkProviderKind::WindowsRdpOperational)
                .expect("rdp provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Paused
        );
        let resumed = container
            .resume_rdp_operational_sensing(
                &owner_context,
                vec!["rdp_operational_resume_authorization_ref".to_string()],
            )
            .expect("resume rdp operational sensing");
        assert_eq!(
            resumed
                .provider(NetworkProviderKind::WindowsRdpOperational)
                .expect("rdp provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Active
        );
        let stopped = container
            .stop_rdp_operational_sensing(
                &owner_context,
                vec!["rdp_operational_stop_authorization_ref".to_string()],
            )
            .expect("stop rdp operational sensing");
        assert_eq!(
            stopped
                .provider(NetworkProviderKind::WindowsRdpOperational)
                .expect("rdp provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Stopped
        );
        let lifecycle = container
            .rdp_operational_sensing_lifecycle_status()
            .expect("rdp lifecycle");
        assert!(lifecycle.consumer_worker_joined);
        assert!(!lifecycle.consumer_worker_active);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn rdp_operational_sensing_pumps_existing_runtime_path_to_remote_admin_and_facts() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();
        let drained = Arc::new(AtomicBool::new(false));
        let factory: Arc<dyn Fn() -> Box<dyn WindowsAuthRemoteEventLogControl> + Send + Sync> =
            Arc::new({
                let drained = Arc::clone(&drained);
                move || {
                    Box::new(RuntimeRdpOperationalControl {
                        drained: Arc::clone(&drained),
                    })
                }
            });
        container.rdp_operational_sensing_lifecycle_runtime = Some(
            ServiceOwnedAuthRemoteSensingLifecycleRuntime::for_test(&owner_context, factory),
        );
        container
            .activate_rdp_operational_sensing(
                &owner_context,
                vec!["rdp_operational_handoff_authorized".to_string()],
            )
            .expect("activate rdp operational sensing");

        let result = container
            .pump_rdp_operational_sensing_live_batches()
            .expect("pump rdp operational batch");

        assert_eq!(result.published_batches, 1);
        assert_eq!(result.normalized_batches, 1);
        assert!(result.eventbus_publications > 0);
        assert!(result.auth_detector_invocations > 0);
        assert!(result.auth_consumed > 0);
        assert_eq!(result.remote_admin_invocations, 1);
        assert_eq!(result.remote_admin_consumed, result.auth_consumed);
        assert_eq!(result.lateral_invocations, 0);
        assert!(result.downstream_facts > 0);
        assert_eq!(result.dropped_events, 0);
        let status = container
            .provider_controller_status()
            .expect("provider status");
        assert_eq!(
            status
                .provider(NetworkProviderKind::WindowsRdpOperational)
                .expect("rdp provider")
                .provider_kind,
            NetworkProviderKind::WindowsRdpOperational
        );
        assert_eq!(
            status
                .provider_zero
                .rdp_operational_remote_admin_invocations,
            1
        );
        assert_eq!(
            status.provider_zero.rdp_operational_downstream_facts,
            result.downstream_facts
        );
        assert_eq!(status.provider_zero.process_network_facts, 0);
        assert_eq!(status.provider_zero.packet_facts, 0);
        assert!(status.provider_zero.rdp_operational_sensing_only());
        assert!(container.latest_rdp_operational_batch().is_some());
        let read = container
            .app_core_orchestration
            .as_ref()
            .expect("orchestration")
            .read_state();
        assert!(read
            .security_facts
            .items
            .iter()
            .any(|fact| fact.layer == sentinel_contracts::SecurityLayer::AuthIdentity));

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn smb_operational_sensing_starts_disabled_and_requires_explicit_authorization() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();
        let initial = container
            .smb_operational_sensing_lifecycle_status()
            .expect("smb operational lifecycle");
        assert_eq!(initial.lifecycle_state, EtwLifecycleState::Inactive);
        assert_eq!(initial.authorization_state, EtwAuthorizationState::Required);
        assert!(!initial.provider_enabled);
        assert!(container
            .execute_smb_operational_sensing_handoff(
                &owner_context,
                smb_operational_handoff_batch()
            )
            .is_err());
        assert!(container.summary().provider_zero.all_zero());

        let drained = Arc::new(AtomicBool::new(false));
        let factory: Arc<dyn Fn() -> Box<dyn WindowsAuthRemoteEventLogControl> + Send + Sync> =
            Arc::new({
                let drained = Arc::clone(&drained);
                move || {
                    Box::new(RuntimeSmbOperationalControl {
                        drained: Arc::clone(&drained),
                    })
                }
            });
        container.smb_operational_sensing_lifecycle_runtime = Some(
            ServiceOwnedAuthRemoteSensingLifecycleRuntime::for_test(&owner_context, factory),
        );

        let active = container
            .activate_smb_operational_sensing(
                &owner_context,
                vec!["smb_operational_authorization_ref".to_string()],
            )
            .expect("activate smb operational sensing");
        assert_eq!(
            active
                .provider(NetworkProviderKind::WindowsSmbOperational)
                .expect("smb provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Active
        );
        assert_eq!(active.provider_zero.smb_operational_sensing_calls, 1);
        assert!(container
            .smb_operational_sensing_live_pump_wait_millis()
            .is_some());

        let paused = container
            .pause_smb_operational_sensing(
                &owner_context,
                vec!["smb_operational_pause_authorization_ref".to_string()],
            )
            .expect("pause smb operational sensing");
        assert_eq!(
            paused
                .provider(NetworkProviderKind::WindowsSmbOperational)
                .expect("smb provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Paused
        );
        let resumed = container
            .resume_smb_operational_sensing(
                &owner_context,
                vec!["smb_operational_resume_authorization_ref".to_string()],
            )
            .expect("resume smb operational sensing");
        assert_eq!(
            resumed
                .provider(NetworkProviderKind::WindowsSmbOperational)
                .expect("smb provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Active
        );
        let stopped = container
            .stop_smb_operational_sensing(
                &owner_context,
                vec!["smb_operational_stop_authorization_ref".to_string()],
            )
            .expect("stop smb operational sensing");
        assert_eq!(
            stopped
                .provider(NetworkProviderKind::WindowsSmbOperational)
                .expect("smb provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Stopped
        );
        let lifecycle = container
            .smb_operational_sensing_lifecycle_status()
            .expect("smb lifecycle");
        assert!(lifecycle.consumer_worker_joined);
        assert!(!lifecycle.consumer_worker_active);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn smb_operational_sensing_pumps_existing_runtime_path_to_remote_admin_and_facts() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();
        let drained = Arc::new(AtomicBool::new(false));
        let factory: Arc<dyn Fn() -> Box<dyn WindowsAuthRemoteEventLogControl> + Send + Sync> =
            Arc::new({
                let drained = Arc::clone(&drained);
                move || {
                    Box::new(RuntimeSmbOperationalControl {
                        drained: Arc::clone(&drained),
                    })
                }
            });
        container.smb_operational_sensing_lifecycle_runtime = Some(
            ServiceOwnedAuthRemoteSensingLifecycleRuntime::for_test(&owner_context, factory),
        );
        container
            .activate_smb_operational_sensing(
                &owner_context,
                vec!["smb_operational_handoff_authorized".to_string()],
            )
            .expect("activate smb operational sensing");

        let result = container
            .pump_smb_operational_sensing_live_batches()
            .expect("pump smb operational batch");

        assert_eq!(result.published_batches, 1);
        assert_eq!(result.normalized_batches, 1);
        assert!(result.eventbus_publications > 0);
        assert_eq!(result.auth_detector_invocations, 1);
        assert_eq!(result.auth_consumed, 1);
        assert_eq!(result.remote_admin_invocations, 1);
        assert_eq!(result.remote_admin_consumed, 2);
        assert_eq!(result.lateral_invocations, 0);
        assert!(result.downstream_facts > 0);
        assert_eq!(result.dropped_events, 0);
        let status = container
            .provider_controller_status()
            .expect("provider status");
        assert_eq!(
            status
                .provider(NetworkProviderKind::WindowsSmbOperational)
                .expect("smb provider")
                .provider_kind,
            NetworkProviderKind::WindowsSmbOperational
        );
        assert_eq!(
            status
                .provider_zero
                .smb_operational_remote_admin_invocations,
            1
        );
        assert_eq!(status.provider_zero.smb_operational_auth_consumed, 1);
        assert_eq!(
            status.provider_zero.smb_operational_downstream_facts,
            result.downstream_facts
        );
        assert_eq!(status.provider_zero.process_network_facts, 0);
        assert_eq!(status.provider_zero.packet_facts, 0);
        assert!(status.provider_zero.smb_operational_sensing_only());
        assert!(container.latest_smb_operational_batch().is_some());
        let read = container
            .app_core_orchestration
            .as_ref()
            .expect("orchestration")
            .read_state();
        assert!(read
            .security_facts
            .items
            .iter()
            .any(|fact| fact.layer == sentinel_contracts::SecurityLayer::AuthIdentity));

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn ssh_operational_sensing_starts_disabled_and_requires_explicit_authorization() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();
        let initial = container
            .ssh_operational_sensing_lifecycle_status()
            .expect("ssh operational lifecycle");
        assert_eq!(initial.lifecycle_state, EtwLifecycleState::Inactive);
        assert_eq!(initial.authorization_state, EtwAuthorizationState::Required);
        assert!(!initial.provider_enabled);
        assert!(container
            .execute_ssh_operational_sensing_handoff(
                &owner_context,
                ssh_operational_handoff_batch()
            )
            .is_err());
        assert!(container.summary().provider_zero.all_zero());

        let drained = Arc::new(AtomicBool::new(false));
        let factory: Arc<dyn Fn() -> Box<dyn WindowsAuthRemoteEventLogControl> + Send + Sync> =
            Arc::new({
                let drained = Arc::clone(&drained);
                move || {
                    Box::new(RuntimeSshOperationalControl {
                        drained: Arc::clone(&drained),
                    })
                }
            });
        container.ssh_operational_sensing_lifecycle_runtime = Some(
            ServiceOwnedAuthRemoteSensingLifecycleRuntime::for_test(&owner_context, factory),
        );

        let active = container
            .activate_ssh_operational_sensing(
                &owner_context,
                vec!["ssh_operational_authorization_ref".to_string()],
            )
            .expect("activate ssh operational sensing");
        assert_eq!(
            active
                .provider(NetworkProviderKind::WindowsSshOperational)
                .expect("ssh provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Active
        );
        assert_eq!(active.provider_zero.ssh_operational_sensing_calls, 1);
        assert!(container
            .ssh_operational_sensing_live_pump_wait_millis()
            .is_some());

        let paused = container
            .pause_ssh_operational_sensing(
                &owner_context,
                vec!["ssh_operational_pause_authorization_ref".to_string()],
            )
            .expect("pause ssh operational sensing");
        assert_eq!(
            paused
                .provider(NetworkProviderKind::WindowsSshOperational)
                .expect("ssh provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Paused
        );
        let resumed = container
            .resume_ssh_operational_sensing(
                &owner_context,
                vec!["ssh_operational_resume_authorization_ref".to_string()],
            )
            .expect("resume ssh operational sensing");
        assert_eq!(
            resumed
                .provider(NetworkProviderKind::WindowsSshOperational)
                .expect("ssh provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Active
        );
        let stopped = container
            .stop_ssh_operational_sensing(
                &owner_context,
                vec!["ssh_operational_stop_authorization_ref".to_string()],
            )
            .expect("stop ssh operational sensing");
        assert_eq!(
            stopped
                .provider(NetworkProviderKind::WindowsSshOperational)
                .expect("ssh provider")
                .lifecycle_state,
            NetworkProviderLifecycleState::Stopped
        );
        let lifecycle = container
            .ssh_operational_sensing_lifecycle_status()
            .expect("ssh lifecycle");
        assert!(lifecycle.consumer_worker_joined);
        assert!(!lifecycle.consumer_worker_active);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn ssh_operational_sensing_pumps_existing_runtime_path_to_remote_admin_and_facts() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();
        let drained = Arc::new(AtomicBool::new(false));
        let factory: Arc<dyn Fn() -> Box<dyn WindowsAuthRemoteEventLogControl> + Send + Sync> =
            Arc::new({
                let drained = Arc::clone(&drained);
                move || {
                    Box::new(RuntimeSshOperationalControl {
                        drained: Arc::clone(&drained),
                    })
                }
            });
        container.ssh_operational_sensing_lifecycle_runtime = Some(
            ServiceOwnedAuthRemoteSensingLifecycleRuntime::for_test(&owner_context, factory),
        );
        container
            .activate_ssh_operational_sensing(
                &owner_context,
                vec!["ssh_operational_handoff_authorized".to_string()],
            )
            .expect("activate ssh operational sensing");

        let result = container
            .pump_ssh_operational_sensing_live_batches()
            .expect("pump ssh operational batch");

        assert_eq!(result.published_batches, 1);
        assert_eq!(result.normalized_batches, 1);
        assert!(result.eventbus_publications > 0);
        assert_eq!(result.auth_detector_invocations, 1);
        assert_eq!(result.auth_consumed, 1);
        assert_eq!(result.remote_admin_invocations, 1);
        assert_eq!(result.remote_admin_consumed, 2);
        assert_eq!(result.lateral_invocations, 0);
        assert!(result.downstream_facts > 0);
        assert_eq!(result.dropped_events, 0);
        let status = container
            .provider_controller_status()
            .expect("provider status");
        assert_eq!(
            status
                .provider(NetworkProviderKind::WindowsSshOperational)
                .expect("ssh provider")
                .provider_kind,
            NetworkProviderKind::WindowsSshOperational
        );
        assert_eq!(
            status
                .provider_zero
                .ssh_operational_remote_admin_invocations,
            1
        );
        assert_eq!(status.provider_zero.ssh_operational_auth_consumed, 1);
        assert_eq!(
            status.provider_zero.ssh_operational_downstream_facts,
            result.downstream_facts
        );
        assert_eq!(status.provider_zero.process_network_facts, 0);
        assert_eq!(status.provider_zero.packet_facts, 0);
        assert!(status.provider_zero.ssh_operational_sensing_only());
        assert!(container.latest_ssh_operational_batch().is_some());
        let read = container
            .app_core_orchestration
            .as_ref()
            .expect("orchestration")
            .read_state();
        assert!(read
            .security_facts
            .items
            .iter()
            .any(|fact| fact.layer == sentinel_contracts::SecurityLayer::AuthIdentity));

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn windows_dns_handoff_uses_existing_runtime_and_counts_detector_consumption() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();
        let drained = Arc::new(AtomicBool::new(false));
        let factory: Arc<dyn Fn() -> Box<dyn WindowsDnsSessionControl> + Send + Sync> = Arc::new({
            let drained = Arc::clone(&drained);
            move || {
                Box::new(RuntimeDnsControl {
                    drained: Arc::clone(&drained),
                })
            }
        });
        container.dns_sensing_lifecycle_runtime = Some(
            ServiceOwnedDnsSensingLifecycleRuntime::for_test(&owner_context, factory),
        );
        container
            .activate_dns_sensing(
                &owner_context,
                vec!["dns_sensing_authorization_ref".to_string()],
            )
            .expect("activate DNS sensing");
        let result = container
            .pump_dns_sensing_live_batches()
            .expect("pump native DNS batch");
        assert_eq!(result.published_batches, 1);
        assert!(result.eventbus_publications > 0);
        assert_eq!(result.detector_invocations, 1);
        assert_eq!(result.detector_consumed, 1);
        let status = container
            .network_provider_status(NetworkProviderKind::WindowsDns)
            .expect("DNS provider status");
        assert_eq!(
            status.lifecycle_state,
            NetworkProviderLifecycleState::Active
        );
        assert!(status.bounded_counters.dns_observation_publications > 0);
        assert_eq!(status.bounded_counters.dns_detector_invocations, 1);
        assert_eq!(status.bounded_counters.dns_detector_consumed, 1);
        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn c2_detection_handoff_uses_existing_eventbus_dag_and_plugin_runtime() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        validate_c2_detection_dag_route(&container).expect("c2 dag route");
        let trace_context = TraceContext::new_root();
        let input_events = c2_runtime_input_events(&trace_context);
        for event in &input_events {
            container
                .publish_container_envelope(
                    event.event_type.as_str(),
                    event.clone(),
                    "c2 runtime container test input",
                )
                .expect("publish c2 input");
        }

        let output_events = container
            .run_c2_detection_runtime(input_events)
            .expect("run c2 detection");
        let topics = output_events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>();
        assert!(topics.contains(&SECURITY_FINDING));
        assert!(topics.contains(&SECURITY_EVIDENCE));
        assert!(topics.contains(&"security.risk_hint"));
        assert!(topics.contains(&GRAPH_HINT));
        assert!(!topics.contains(&SECURITY_ALERT));
        assert!(!topics.contains(&SECURITY_INCIDENT));

        let output_json = serde_json::to_string(&output_events).expect("output json");
        for forbidden in [
            "198.51.100.24",
            "192.0.2.10",
            "\"dst_port\":443",
            "\"src_port\":50000",
            "os_process_id",
            "process_path",
            "command_line",
            "credential",
            "secret",
            "token",
        ] {
            assert!(
                !output_json.contains(forbidden),
                "c2 runtime container output leaked forbidden marker {forbidden}"
            );
        }

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn lateral_movement_handoff_uses_existing_eventbus_dag_and_plugin_runtime() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        validate_lateral_movement_dag_route(&container).expect("lateral dag route");
        let trace_context = TraceContext::new_root();
        let input_events = lateral_runtime_input_events(&trace_context);
        for event in &input_events {
            container
                .publish_container_envelope(
                    event.event_type.as_str(),
                    event.clone(),
                    "lateral runtime container test input",
                )
                .expect("publish lateral input");
        }

        let output_events = container
            .run_lateral_movement_runtime(input_events)
            .expect("run lateral movement");
        let topics = output_events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>();
        assert!(topics.contains(&SECURITY_FINDING));
        assert!(topics.contains(&SECURITY_EVIDENCE));
        assert!(topics.contains(&GRAPH_HINT));
        assert!(!topics.contains(&SECURITY_ALERT));
        assert!(!topics.contains(&SECURITY_INCIDENT));

        let output_json = serde_json::to_string(&output_events).expect("output json");
        for forbidden in [
            "192.168.",
            "\":445",
            "\":3389",
            "\"dst_port\"",
            "\"src_port\"",
            "\"local_port\"",
            "os_process_id",
            "process_path",
            "command_line",
            "credential",
            "secret",
            "token",
        ] {
            assert!(
                !output_json.contains(forbidden),
                "lateral runtime container output leaked forbidden marker {forbidden}"
            );
        }

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn lateral_movement_handoff_stays_empty_without_independent_process_and_asset_context() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        validate_lateral_movement_dag_route(&container).expect("lateral dag route");
        let trace_context = TraceContext::new_root();
        let input_events = lateral_flow_only_input_events(&trace_context);
        for event in &input_events {
            container
                .publish_container_envelope(
                    event.event_type.as_str(),
                    event.clone(),
                    "lateral runtime flow-only test input",
                )
                .expect("publish lateral flow-only input");
        }

        let output_events = container
            .run_lateral_movement_runtime(input_events)
            .expect("run lateral movement");
        assert!(
            output_events.is_empty(),
            "flow-only metadata must not synthesize lateral movement output"
        );

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn etw_handoff_flows_through_eventbus_dag_runtime_and_security_facts() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();
        let lifecycle = container
            .activate_etw_provider(&owner_context, vec!["etw_handoff_authorized".to_string()])
            .expect("authorized etw lifecycle");
        assert_eq!(
            lifecycle.etw_lifecycle.authorization_state,
            EtwAuthorizationState::Authorized
        );
        assert!(matches!(
            lifecycle.etw_lifecycle.lifecycle_state,
            EtwLifecycleState::Active | EtwLifecycleState::Degraded
        ));

        let result = container
            .execute_etw_network_handoff(&owner_context, etw_handoff_batch())
            .expect("etw runtime handoff");

        assert!(result
            .emitted_topics
            .contains(&NATIVE_ETW_NETWORK_METADATA.to_string()));
        assert!(result
            .emitted_topics
            .contains(&NATIVE_CONNECTION_CATEGORY_FACT.to_string()));
        assert_eq!(result.batch.eventbus_publication_count, 0);
        assert_eq!(result.batch.security_fact_count, 0);
        assert!(!result.batch.privacy.raw_event_retention_allowed);
        assert!(!result.batch.privacy.raw_address_retention_allowed);
        assert!(!result.batch.privacy.exact_port_retention_allowed);
        assert!(!result.batch.privacy.process_identity_retention_allowed);
        assert!(!result.batch.privacy.payload_collection_allowed);
        assert!(!result.batch.privacy.dedup_hash_exposed);
        assert!(result.batch.privacy.category_only_output);
        assert!(result.fact_count >= 3);
        assert!(matches!(
            result.provider_status.selected_mode,
            NetworkProviderControllerMode::EtwPlusIpHelper
                | NetworkProviderControllerMode::Degraded
        ));
        assert!(result.provider_status.provider_zero.etw_calls >= 2);
        assert!(
            result
                .provider_status
                .provider_zero
                .native_network_topic_publications
                > 0
        );
        assert_eq!(result.provider_status.provider_zero.npcap_probes, 0);
        assert_eq!(
            result.provider_status.provider_zero.capture_broker_launches,
            0
        );
        assert_eq!(
            result.provider_status.provider_zero.process_network_facts,
            0
        );
        assert_eq!(result.provider_status.provider_zero.packet_facts, 0);
        let etw = result
            .provider_status
            .provider(NetworkProviderKind::EtwNetwork)
            .expect("etw status");
        assert!(matches!(
            etw.lifecycle_state,
            NetworkProviderLifecycleState::Active | NetworkProviderLifecycleState::Degraded
        ));
        let short_lived = result
            .provider_status
            .visibility_summary
            .dimensions
            .iter()
            .find(|dimension| {
                dimension.dimension == NetworkVisibilityDimension::ShortLivedNetworkEventVisibility
            })
            .expect("short lived visibility");
        assert!(matches!(
            short_lived.visibility_state,
            NetworkVisibilityState::Available | NetworkVisibilityState::Degraded
        ));
        let read = container
            .app_core_orchestration
            .as_ref()
            .expect("orchestration")
            .read_state();
        assert_eq!(read.security_facts.items.len(), result.fact_count);
        assert!(read.security_facts.items.iter().all(|fact| {
            fact.layer == sentinel_contracts::SecurityLayer::AuthorizedNativeNetwork
                && fact.process_category.is_none()
                && fact.parent_process_category.is_none()
                && fact.execution_context_category.is_none()
        }));

        let serialized = serde_json::to_string(&json!({
            "batch": result.batch,
            "provider_status": result.provider_status,
            "facts": read.security_facts.items,
        }))
        .expect("serialized etw handoff");
        for forbidden in [
            "security.finding",
            "security.incident",
            "response.plan",
            "llm",
            "203.0.113.77",
            "10.42.0.7",
            "49152",
            "42424",
            "packet_bytes",
            "payload_bytes",
            "credential",
            "secret",
            "token",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(forbidden),
                "etw handoff leaked forbidden marker {forbidden}: {serialized}"
            );
        }

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn etw_read_models_expose_bounded_traceability_without_side_effects() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();
        container
            .activate_etw_provider(
                &owner_context,
                vec!["etw_product_surface_authorized".to_string()],
            )
            .expect("authorized etw lifecycle");

        let result = container
            .execute_etw_network_handoff(&owner_context, etw_handoff_batch())
            .expect("etw runtime handoff");
        let provider_call_count = container.provider_call_count();
        let fact_refs = container
            .app_core_orchestration
            .as_ref()
            .expect("orchestration")
            .read_state()
            .security_facts
            .items
            .iter()
            .map(|fact| fact.fact_id.to_string())
            .collect::<Vec<_>>();

        let status = container
            .provider_controller_status()
            .expect("provider controller status");
        assert_eq!(status.ownership_epoch, owner_context.ownership_epoch);
        assert!(matches!(
            status.selected_mode,
            NetworkProviderControllerMode::EtwPlusIpHelper
                | NetworkProviderControllerMode::Degraded
        ));
        assert!(!status.etw_lifecycle.provider_enabled);
        assert!(!status.etw_lifecycle.collection_started);
        assert!(!status.etw_lifecycle.consumer_started);
        assert_eq!(status.etw_lifecycle.eventbus_publication_count, 0);
        assert_eq!(status.etw_lifecycle.security_fact_count, 0);
        assert!(status.provider_zero.etw_handoff_only());
        assert_eq!(status.provider_zero.process_network_facts, 0);
        assert_eq!(status.provider_zero.packet_facts, 0);

        let provider_item = container
            .canonical_read_model_snapshot()
            .expect("canonical snapshot")
            .items
            .into_iter()
            .find(|item| {
                item.model_category == CanonicalReadModelCategory::ProviderControllerStatus
            })
            .expect("provider controller item");
        assert!(provider_item
            .bounded_categories
            .contains(&"etw_handoff_metadata_only".to_string()));
        assert!(provider_item
            .bounded_categories
            .contains(&"etw_privacy_category_only_true".to_string()));
        assert!(provider_item.bounded_refs.contains(&result.batch.batch_ref));
        assert!(provider_item
            .bounded_refs
            .contains(&result.batch.allowlist_ref));
        assert!(provider_item
            .bounded_categories
            .iter()
            .any(|category| category.starts_with("etw_fallback_")));

        let traceability = container
            .canonical_report_export_traceability()
            .expect("report export traceability");
        assert!(traceability.snapshot_refs.contains(&result.batch.batch_ref));
        assert!(traceability
            .snapshot_refs
            .contains(&result.batch.allowlist_ref));
        assert!(traceability
            .snapshot_refs
            .contains(&status.visibility_summary.visibility_ref));
        assert!(fact_refs
            .iter()
            .all(|fact_ref| traceability.snapshot_refs.contains(fact_ref)));

        let reread_status = container
            .provider_controller_status()
            .expect("provider controller reread");
        let reloaded_generation = container
            .canonical_read_model_snapshot()
            .expect("snapshot reread");
        let reread_traceability = container
            .canonical_report_export_traceability()
            .expect("traceability reread");
        assert_eq!(container.provider_call_count(), provider_call_count);
        assert_eq!(reread_status.provider_zero, status.provider_zero);
        assert_eq!(
            reloaded_generation.ownership_epoch,
            owner_context.ownership_epoch
        );
        assert_eq!(
            reread_traceability.snapshot_refs,
            traceability.snapshot_refs
        );

        let serialized = serde_json::to_string(&json!({
            "status": status,
            "provider_item": provider_item,
            "traceability": traceability,
            "snapshot": reloaded_generation,
        }))
        .expect("serialized etw read models");
        for forbidden in [
            "etw_raw_event",
            "event_payload",
            "packet_bytes",
            "payload_bytes",
            "process_name",
            "pid=",
            "203.0.113.77",
            "10.42.0.7",
            "49152",
            "42424",
            "credential",
            "secret",
            "token",
            "response_execution\":true",
            "automatic_llm_calls\":true",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(forbidden),
                "etw read model leaked forbidden marker {forbidden}: {serialized}"
            );
        }

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn provider_controller_servicehost_owns_one_inactive_controller() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");

        let status = container
            .provider_controller_status()
            .expect("provider controller status");
        status.validate().expect("provider status validates");
        assert_eq!(status.runtime_owner, RuntimeOwnerCategory::ServiceHost);
        assert_eq!(
            status.ownership_epoch,
            container.owner_context.ownership_epoch
        );
        assert_eq!(
            status.controller_state,
            sentinel_contracts::NetworkProviderControllerState::Inactive
        );
        assert_eq!(
            status.selected_mode,
            sentinel_contracts::NetworkProviderControllerMode::PortableOnly
        );
        assert_eq!(container.network_provider_statuses().len(), 11);
        assert_eq!(
            container
                .network_provider_status(NetworkProviderKind::WindowsRdpOperational)
                .expect("rdp operational")
                .implementation_state,
            sentinel_contracts::NetworkProviderImplementationState::ImplementedInactive
        );
        assert_eq!(
            container
                .network_provider_status(NetworkProviderKind::WindowsSmbOperational)
                .expect("smb operational")
                .implementation_state,
            sentinel_contracts::NetworkProviderImplementationState::ImplementedInactive
        );
        assert_eq!(
            container
                .network_provider_status(NetworkProviderKind::WindowsSshOperational)
                .expect("ssh operational")
                .implementation_state,
            sentinel_contracts::NetworkProviderImplementationState::ImplementedInactive
        );
        assert_eq!(
            container
                .network_provider_status(NetworkProviderKind::IpHelper)
                .expect("ip helper")
                .implementation_state,
            sentinel_contracts::NetworkProviderImplementationState::ImplementedInactive
        );
        assert_eq!(
            container
                .network_provider_status(NetworkProviderKind::IpHelper)
                .expect("ip helper")
                .adapter_boundary,
            "infrastructure"
        );
        assert!(container
            .network_visibility_summary()
            .expect("visibility")
            .dimensions
            .iter()
            .any(|dimension| {
                dimension.dimension
                    == sentinel_contracts::NetworkVisibilityDimension::PortableMetadataVisibility
                    && dimension.visibility_state
                        == sentinel_contracts::NetworkVisibilityState::Available
            }));
        assert_eq!(
            container
                .network_fallback_plan()
                .expect("fallback")
                .selected_mode,
            sentinel_contracts::NetworkProviderControllerMode::PortableOnly
        );
        assert!(container
            .network_provider_zero_counters()
            .expect("zero counters")
            .all_zero());
        assert_eq!(container.provider_call_count(), 0);
        assert!(container.summary().provider_zero.all_zero());

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn provider_controller_explicit_ip_helper_handoff_uses_servicehost_runtime_path() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();

        let result = container
            .execute_ip_helper_servicehost_handoff(
                &owner_context,
                IpHelperHandoffRequest::internal_servicehost_test(),
            )
            .expect("explicit ip helper handoff");

        assert_eq!(container.provider_call_count(), 1);
        assert!(result.fact_count >= 2);
        assert_eq!(
            result.emitted_topics,
            vec![
                NATIVE_IP_HELPER_METADATA.to_string(),
                NATIVE_CONNECTION_CATEGORY_FACT.to_string(),
                NETWORK_PROVIDER_STATUS.to_string(),
                NETWORK_VISIBILITY_STATUS.to_string(),
                AUDIT_NETWORK_PROVIDER_EXECUTION.to_string(),
            ]
        );
        result.batch.validate().expect("batch validates");
        assert!(!result.batch.response_execution_allowed);
        assert!(!result.batch.automatic_llm_calls);
        assert!(
            result
                .provider_status
                .policy_summary
                .provider_activation_allowed
        );
        assert!(
            result
                .provider_status
                .policy_summary
                .ip_helper_execution_available_over_production_ipc
        );
        assert_eq!(
            result
                .provider_status
                .policy_summary
                .production_ipc_execution_unavailable_reason,
            "not_applicable"
        );
        assert_eq!(result.provider_status.provider_zero.ip_helper_calls, 1);
        assert_eq!(result.provider_status.provider_zero.etw_calls, 0);
        assert_eq!(result.provider_status.provider_zero.npcap_probes, 0);
        assert_eq!(
            result.provider_status.provider_zero.capture_broker_launches,
            0
        );
        assert_eq!(
            result.provider_status.provider_zero.process_network_facts,
            0
        );
        assert_eq!(result.provider_status.provider_zero.packet_facts, 0);
        assert!(matches!(
            result.provider_status.selected_mode,
            NetworkProviderControllerMode::IpHelperOnly | NetworkProviderControllerMode::Degraded
        ));
        if result.provider_status.selected_mode == NetworkProviderControllerMode::IpHelperOnly {
            let connection_visibility = result
                .provider_status
                .visibility_summary
                .dimensions
                .iter()
                .find(|dimension| {
                    dimension.dimension == NetworkVisibilityDimension::ConnectionTableVisibility
                })
                .expect("connection table visibility");
            assert_eq!(
                connection_visibility.visibility_state,
                NetworkVisibilityState::Available
            );
        }
        let read = container
            .app_core_orchestration
            .as_ref()
            .expect("orchestration")
            .read_state();
        assert_eq!(read.findings.items.len(), 0);
        assert!(read.security_facts.items.iter().all(|fact| {
            fact.layer == sentinel_contracts::SecurityLayer::AuthorizedNativeNetwork
                && fact.process_category.is_none()
                && fact.parent_process_category.is_none()
                && fact.execution_context_category.is_none()
        }));
        assert_eq!(container.canonical_read_model_generation_count(), 2);
        let snapshot = container
            .canonical_read_model_snapshot()
            .expect("canonical snapshot");
        let provider_item = snapshot
            .items
            .iter()
            .find(|item| {
                item.model_category
                    == sentinel_contracts::read_model_snapshot::CanonicalReadModelCategory::ProviderControllerStatus
            })
            .expect("provider controller item");
        assert!(provider_item
            .bounded_refs
            .iter()
            .any(|reference| reference.starts_with("ip_helper_batch_")));

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn provider_controller_rejects_production_ipc_sample_until_activated() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();

        let error = container
            .execute_ip_helper_servicehost_handoff(
                &owner_context,
                IpHelperHandoffRequest::production_ipc_rejected(),
            )
            .expect_err("production ipc execution rejected");

        assert_eq!(
            error.details_redacted,
            Some(json!({ "reason_category": "ip_helper_not_active" }))
        );
        assert_eq!(container.provider_call_count(), 0);
        assert!(container.summary().provider_zero.all_zero());

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn provider_execution_explicit_activation_then_production_ipc_sample_is_bounded() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();

        let activated = container
            .activate_ip_helper_provider(&owner_context)
            .expect("activate ip helper");
        assert_eq!(container.provider_call_count(), 0);
        assert_eq!(
            activated
                .provider(NetworkProviderKind::IpHelper)
                .expect("ip helper")
                .lifecycle_state,
            NetworkProviderLifecycleState::Active
        );
        let connection_visibility = activated
            .visibility_summary
            .dimensions
            .iter()
            .find(|dimension| {
                dimension.dimension == NetworkVisibilityDimension::ConnectionTableVisibility
            })
            .expect("connection table visibility");
        assert_eq!(
            connection_visibility.visibility_state,
            NetworkVisibilityState::Unavailable
        );
        assert_eq!(
            connection_visibility.degraded_reason.as_deref(),
            Some("no_successful_sample")
        );

        let sample = container
            .execute_ip_helper_servicehost_handoff(
                &owner_context,
                IpHelperHandoffRequest::production_ipc(),
            )
            .expect("one production ipc sample");
        assert_eq!(container.provider_call_count(), 1);
        assert!(sample.fact_count >= 2);
        assert_eq!(sample.provider_status.provider_zero.ip_helper_calls, 1);
        assert_eq!(sample.provider_status.provider_zero.etw_calls, 0);
        assert_eq!(sample.provider_status.provider_zero.npcap_probes, 0);
        assert_eq!(
            sample.provider_status.provider_zero.capture_broker_launches,
            0
        );
        assert_eq!(sample.provider_status.provider_zero.packet_facts, 0);

        let stopped = container
            .stop_ip_helper_provider(&owner_context)
            .expect("stop ip helper");
        assert_eq!(container.provider_call_count(), 1);
        assert_eq!(
            stopped
                .provider(NetworkProviderKind::IpHelper)
                .expect("ip helper")
                .lifecycle_state,
            NetworkProviderLifecycleState::Stopped
        );
        let rejected = container
            .execute_ip_helper_servicehost_handoff(
                &owner_context,
                IpHelperHandoffRequest::production_ipc(),
            )
            .expect_err("stopped provider rejects sample");
        assert_eq!(
            rejected.details_redacted,
            Some(json!({ "reason_category": "ip_helper_not_active" }))
        );
        assert_eq!(container.provider_call_count(), 1);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn ip_helper_schedule_control_plane_starts_timer_without_provider_calls() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();

        container
            .activate_ip_helper_provider(&owner_context)
            .expect("activate ip helper without sampling");
        assert_eq!(container.provider_call_count(), 0);

        let configure_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::ConfigureIpHelperSchedule,
        );
        let configured = container
            .configure_ip_helper_schedule(
                &owner_context,
                IpHelperScheduleConfig::default(),
                vec!["ip_helper_schedule_configure_authorized".to_string()],
                configure_policy.policy_ref,
                configure_policy.policy_version,
            )
            .expect("configure schedule");
        assert_eq!(
            configured.ip_helper_schedule.schedule_state,
            IpHelperScheduleState::ConfiguredDisabled
        );
        assert_eq!(container.provider_call_count(), 0);

        let enable_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::EnableIpHelperSchedule,
        );
        let enabled = container
            .enable_ip_helper_schedule(
                &owner_context,
                "ip_helper_schedule_lease_test".to_string(),
                vec!["ip_helper_schedule_enable_authorized".to_string()],
                enable_policy.policy_ref,
                enable_policy.policy_version,
            )
            .expect("enable schedule");
        assert_eq!(
            enabled.ip_helper_schedule.schedule_state,
            IpHelperScheduleState::ConfiguredEnabled
        );
        assert_eq!(
            enabled.ip_helper_schedule.lease_state,
            IpHelperScheduleLeaseState::Active
        );
        assert!(enabled.ip_helper_schedule.timer_runtime_active);
        assert!(enabled.ip_helper_schedule.schedule_lease_valid);
        assert_eq!(
            enabled
                .ip_helper_schedule
                .scheduler_triggered_provider_calls,
            0
        );
        assert_eq!(container.provider_call_count(), 0);

        let pause_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::PauseIpHelperSchedule,
        );
        let paused = container
            .pause_ip_helper_schedule(
                &owner_context,
                vec!["ip_helper_schedule_pause_authorized".to_string()],
                pause_policy.policy_ref,
                pause_policy.policy_version,
            )
            .expect("pause schedule");
        assert_eq!(
            paused.ip_helper_schedule.schedule_state,
            IpHelperScheduleState::Paused
        );
        assert_eq!(container.provider_call_count(), 0);

        let resume_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::ResumeIpHelperSchedule,
        );
        let resumed = container
            .resume_ip_helper_schedule(
                &owner_context,
                "ip_helper_schedule_lease_test_resumed".to_string(),
                vec!["ip_helper_schedule_resume_authorized".to_string()],
                resume_policy.policy_ref,
                resume_policy.policy_version,
            )
            .expect("resume schedule");
        assert_eq!(
            resumed.ip_helper_schedule.schedule_state,
            IpHelperScheduleState::ConfiguredEnabled
        );
        assert_eq!(container.provider_call_count(), 0);

        let stopped = container
            .stop_ip_helper_provider(&owner_context)
            .expect("stop provider invalidates schedule");
        assert_eq!(
            stopped.ip_helper_schedule.schedule_state,
            IpHelperScheduleState::Invalidated
        );
        assert_eq!(
            stopped.ip_helper_schedule.lease_state,
            IpHelperScheduleLeaseState::Invalidated
        );
        assert_eq!(container.provider_call_count(), 0);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn ip_helper_scheduler_due_cycle_uses_existing_handoff_once() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();

        container
            .activate_ip_helper_provider(&owner_context)
            .expect("activate ip helper");
        let configure_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::ConfigureIpHelperSchedule,
        );
        container
            .configure_ip_helper_schedule(
                &owner_context,
                IpHelperScheduleConfig::default(),
                vec!["ip_helper_schedule_configure_authorized".to_string()],
                configure_policy.policy_ref,
                configure_policy.policy_version,
            )
            .expect("configure schedule");
        let enable_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::EnableIpHelperSchedule,
        );
        container
            .enable_ip_helper_schedule(
                &owner_context,
                "ip_helper_schedule_lease_test".to_string(),
                vec!["ip_helper_schedule_enable_authorized".to_string()],
                enable_policy.policy_ref,
                enable_policy.policy_version,
            )
            .expect("enable schedule");
        assert_eq!(container.provider_call_count(), 0);

        let cycle = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_test".to_string(),
                1_000,
            )
            .expect("scheduled sample");
        if cycle.execution_result != IpHelperScheduledExecutionResult::Completed {
            panic!(
                "scheduled cycle did not complete: {:?}",
                cycle.degraded_reason
            );
        }
        assert_eq!(
            cycle.execution_result,
            IpHelperScheduledExecutionResult::Completed
        );
        assert_eq!(
            cycle.provider_call_count_bucket,
            IpHelperScheduleCountBucket::One
        );
        assert_eq!(container.provider_call_count(), 1);
        let status = container.provider_controller_status().expect("status");
        assert_eq!(status.provider_zero.ip_helper_calls, 1);
        assert_eq!(status.provider_zero.etw_calls, 0);
        assert_eq!(status.provider_zero.npcap_probes, 0);
        assert_eq!(status.provider_zero.capture_broker_launches, 0);
        assert_eq!(status.provider_zero.packet_facts, 0);
        assert_eq!(status.provider_zero.process_network_facts, 0);
        assert_eq!(
            status.ip_helper_schedule.scheduler_triggered_provider_calls,
            1
        );
        assert_eq!(
            status.ip_helper_schedule.latest_scheduled_execution_result,
            IpHelperScheduledExecutionResult::Completed
        );

        let duplicate = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_test".to_string(),
                2_000,
            )
            .expect("duplicate skips");
        assert_eq!(
            duplicate.execution_result,
            IpHelperScheduledExecutionResult::Skipped
        );
        assert_eq!(container.provider_call_count(), 1);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn ip_helper_scheduler_two_due_cycles_advance_accounting_without_deferred_catchup() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = activate_and_enable_ip_helper_schedule_for_tests(
            &mut container,
            IpHelperScheduleConfig {
                interval_bucket: IpHelperScheduleIntervalBucket::FifteenSeconds,
                ..IpHelperScheduleConfig::default()
            },
        );

        let first = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_first".to_string(),
                1_000,
            )
            .expect("first due cycle");
        assert_eq!(
            first.execution_result,
            IpHelperScheduledExecutionResult::Completed
        );
        let not_due = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_not_due".to_string(),
                2_000,
            )
            .expect("not due cycle skips");
        assert_eq!(not_due.due_state, IpHelperScheduledDueState::NotDue);
        assert_eq!(
            not_due.execution_result,
            IpHelperScheduledExecutionResult::Skipped
        );
        assert_eq!(container.provider_call_count(), 1);

        let second = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_second".to_string(),
                16_000,
            )
            .expect("second due cycle");
        assert_eq!(
            second.execution_result,
            IpHelperScheduledExecutionResult::Completed
        );
        let status = container.provider_controller_status().expect("status");
        assert_eq!(container.provider_call_count(), 2);
        assert_eq!(
            status.ip_helper_schedule.scheduler_triggered_provider_calls,
            2
        );
        assert_eq!(
            status.ip_helper_schedule.scheduled_sample_count_bucket,
            IpHelperScheduleCountBucket::Few
        );
        assert_eq!(
            status.ip_helper_schedule.freshness_state,
            IpHelperScheduledFreshnessState::Fresh
        );
        assert_eq!(status.provider_zero.etw_calls, 0);
        assert_eq!(status.provider_zero.npcap_probes, 0);
        assert_eq!(status.provider_zero.capture_broker_launches, 0);
        assert_eq!(status.provider_zero.packet_facts, 0);
        assert_eq!(status.provider_zero.process_network_facts, 0);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn ip_helper_scheduler_busy_gate_records_retry_without_adapter_invocation() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = activate_and_enable_ip_helper_schedule_for_tests(
            &mut container,
            IpHelperScheduleConfig {
                retry_budget_bucket: IpHelperScheduleRetryBudgetBucket::One,
                ..IpHelperScheduleConfig::default()
            },
        );
        container.ip_helper_execution_active = true;

        let busy = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_busy".to_string(),
                1_000,
            )
            .expect("busy cycle skips");

        assert_eq!(
            busy.execution_result,
            IpHelperScheduledExecutionResult::Busy
        );
        assert_eq!(busy.retry_state, IpHelperScheduledRetryState::Scheduled);
        assert_eq!(
            busy.backpressure_state,
            IpHelperScheduledBackpressureState::Low
        );
        assert_eq!(container.provider_call_count(), 0);
        let status = container.provider_controller_status().expect("status");
        assert_eq!(
            status.ip_helper_schedule.overlap_skip_count_bucket,
            IpHelperScheduleCountBucket::One
        );
        assert_eq!(
            status.ip_helper_schedule.retry_count_bucket,
            IpHelperScheduleCountBucket::One
        );
        assert_eq!(
            status.ip_helper_schedule.scheduler_triggered_provider_calls,
            0
        );

        container.ip_helper_execution_active = false;
        let completed = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_after_busy".to_string(),
                2_000,
            )
            .expect("cycle after busy completes");
        assert_eq!(
            completed.execution_result,
            IpHelperScheduledExecutionResult::Completed
        );
        assert_eq!(container.provider_call_count(), 1);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn ip_helper_scheduler_fault_injection_is_bounded_and_never_catches_up() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = activate_and_enable_ip_helper_schedule_for_tests(
            &mut container,
            IpHelperScheduleConfig {
                retry_budget_bucket: IpHelperScheduleRetryBudgetBucket::One,
                ..IpHelperScheduleConfig::default()
            },
        );

        container.ip_helper_scheduler_test_fault =
            Some(IpHelperSchedulerTestFault::ProviderTimeout);
        let timed_out = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_timeout".to_string(),
                1_000,
            )
            .expect("timeout records a bounded cycle");
        assert_eq!(
            timed_out.execution_result,
            IpHelperScheduledExecutionResult::TimedOut
        );
        assert_eq!(
            timed_out.retry_state,
            IpHelperScheduledRetryState::Scheduled
        );
        assert_eq!(container.provider_call_count(), 0);

        let no_timeout_catch_up = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_timeout_not_due".to_string(),
                2_000,
            )
            .expect("timeout does not create immediate catch-up work");
        assert_eq!(
            no_timeout_catch_up.due_state,
            IpHelperScheduledDueState::NotDue
        );

        container.ip_helper_scheduler_test_fault =
            Some(IpHelperSchedulerTestFault::ProviderTemporarilyUnavailable);
        let unavailable = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_temporarily_unavailable".to_string(),
                100_000,
            )
            .expect("temporary unavailability records a bounded cycle");
        assert_eq!(
            unavailable.execution_result,
            IpHelperScheduledExecutionResult::Failed
        );
        assert_eq!(
            unavailable.retry_state,
            IpHelperScheduledRetryState::Scheduled
        );
        assert_eq!(
            unavailable.backpressure_state,
            IpHelperScheduledBackpressureState::Moderate
        );
        assert_eq!(container.provider_call_count(), 0);

        container.ip_helper_scheduler_test_fault =
            Some(IpHelperSchedulerTestFault::SaturatedBackpressure);
        let saturated = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_saturated".to_string(),
                200_000,
            )
            .expect("saturated backpressure skips safely");
        assert_eq!(
            saturated.execution_result,
            IpHelperScheduledExecutionResult::Skipped
        );
        assert_eq!(
            saturated.backpressure_state,
            IpHelperScheduledBackpressureState::Saturated
        );
        assert_eq!(saturated.retry_state, IpHelperScheduledRetryState::None);
        assert_eq!(container.provider_call_count(), 0);

        let no_backpressure_catch_up = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_saturated_not_due".to_string(),
                201_000,
            )
            .expect("backpressure skip does not accumulate catch-up work");
        assert_eq!(
            no_backpressure_catch_up.due_state,
            IpHelperScheduledDueState::NotDue
        );

        let status = container.provider_controller_status().expect("status");
        assert_eq!(
            status.ip_helper_schedule.timeout_count_bucket,
            IpHelperScheduleCountBucket::One
        );
        assert_eq!(
            status.ip_helper_schedule.retry_count_bucket,
            IpHelperScheduleCountBucket::Few
        );
        assert_eq!(
            status.ip_helper_schedule.backpressure_state,
            IpHelperScheduledBackpressureState::None
        );
        assert_eq!(
            status.ip_helper_schedule.scheduler_triggered_provider_calls,
            0
        );
        assert_eq!(status.provider_zero.etw_calls, 0);
        assert_eq!(status.provider_zero.npcap_probes, 0);
        assert_eq!(status.provider_zero.capture_broker_launches, 0);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn ip_helper_scheduler_pause_disconnect_and_stop_prevent_additional_calls() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = activate_and_enable_ip_helper_schedule_for_tests(
            &mut container,
            IpHelperScheduleConfig::default(),
        );

        let pause_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::PauseIpHelperSchedule,
        );
        container
            .pause_ip_helper_schedule(
                &owner_context,
                vec!["ip_helper_schedule_pause_authorized".to_string()],
                pause_policy.policy_ref,
                pause_policy.policy_version,
            )
            .expect("pause schedule");
        let paused = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_paused".to_string(),
                1_000,
            )
            .expect("paused schedule skips");
        assert_eq!(
            paused.execution_result,
            IpHelperScheduledExecutionResult::Skipped
        );
        assert_eq!(
            paused.authorization_state,
            IpHelperScheduledAuthorizationState::Invalid
        );
        assert_eq!(container.provider_call_count(), 0);

        let resume_policy = sentinel_contracts::policy_for_command(
            sentinel_contracts::MutationCommandId::ResumeIpHelperSchedule,
        );
        container
            .resume_ip_helper_schedule(
                &owner_context,
                "ip_helper_schedule_lease_resumed".to_string(),
                vec!["ip_helper_schedule_resume_authorized".to_string()],
                resume_policy.policy_ref,
                resume_policy.policy_version,
            )
            .expect("resume schedule");
        container
            .invalidate_ip_helper_schedule_for_session_end(
                &owner_context,
                IP_HELPER_SCHEDULE_SESSION_INVALIDATED,
                "ipc_session_closed",
            )
            .expect("disconnect invalidates schedule");
        let disconnected = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_disconnected".to_string(),
                2_000,
            )
            .expect("disconnected schedule skips");
        assert_eq!(
            disconnected.authorization_state,
            IpHelperScheduledAuthorizationState::Invalid
        );
        assert_eq!(container.provider_call_count(), 0);

        container.shutdown().expect("disconnect case shutdown");
        RuntimeOwnershipGuard::reset_for_tests();

        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container for stop case");
        let owner_context = activate_and_enable_ip_helper_schedule_for_tests(
            &mut container,
            IpHelperScheduleConfig::default(),
        );
        container
            .stop_ip_helper_provider(&owner_context)
            .expect("stop provider");
        let stopped = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_stopped".to_string(),
                3_000,
            )
            .expect("stopped provider skips");
        assert_eq!(
            stopped.execution_result,
            IpHelperScheduledExecutionResult::Skipped
        );
        assert_eq!(container.provider_call_count(), 0);
        let status = container.provider_controller_status().expect("status");
        assert!(!status.ip_helper_schedule.enabled_marker);
        assert!(!status.ip_helper_schedule.schedule_lease_valid);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn ip_helper_scheduler_stale_epoch_and_privacy_markers_never_invoke_provider() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = activate_and_enable_ip_helper_schedule_for_tests(
            &mut container,
            IpHelperScheduleConfig::default(),
        );
        let mut stale_context = owner_context.clone();
        stale_context.ownership_epoch = stale_context.ownership_epoch.saturating_add(1);

        let error = container
            .run_ip_helper_schedule_cycle_for_ref(
                &stale_context,
                "ip_helper_scheduled_cycle_stale_epoch".to_string(),
                1_000,
            )
            .expect_err("stale epoch rejected");
        assert_eq!(
            error.details_redacted,
            Some(json!({ "reason_category": "stale_ownership_epoch" }))
        );
        assert_eq!(container.provider_call_count(), 0);

        let serialized = serde_json::to_string(
            container
                .provider_controller_status()
                .expect("provider status"),
        )
        .expect("status json");
        for marker in [
            "pid_value_778899",
            "203.0.113.77",
            "port_value_65000",
            "process_name_value_calc",
            "c:\\unsafe\\binary.exe",
            "username_value_alice",
            "sid_value_123",
            "token_value_abc",
            "credential_value_abc",
            "secret_value_abc",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "provider status leaked seeded marker {marker}"
            );
        }

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn ip_helper_scheduler_revalidates_lease_without_provider_calls() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context().clone();

        let skipped = container
            .run_ip_helper_schedule_cycle_for_ref(
                &owner_context,
                "ip_helper_scheduled_cycle_no_lease".to_string(),
                1_000,
            )
            .expect("missing lease skips");
        assert_eq!(
            skipped.authorization_state,
            IpHelperScheduledAuthorizationState::Invalid
        );
        assert_eq!(
            skipped.execution_result,
            IpHelperScheduledExecutionResult::Skipped
        );
        assert_eq!(container.provider_call_count(), 0);
        assert!(container.summary().provider_zero.all_zero());

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn provider_controller_rejects_stale_epoch_ip_helper_execution() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let mut stale_context = container.owner_context().clone();
        stale_context.ownership_epoch = stale_context.ownership_epoch.saturating_add(1);

        let error = container
            .execute_ip_helper_servicehost_handoff(
                &stale_context,
                IpHelperHandoffRequest::internal_servicehost_test(),
            )
            .expect_err("stale epoch rejected");

        assert_eq!(
            error.details_redacted,
            Some(json!({ "reason_category": "stale_ownership_epoch" }))
        );
        assert_eq!(container.provider_call_count(), 0);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn canonical_read_store_servicehost_owns_one_coherent_snapshot_generation() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");

        assert_eq!(container.read_model_store_count(), 1);
        assert_eq!(container.canonical_read_model_generation_count(), 1);
        assert_eq!(container.canonical_read_model_current_generation(), Some(1));
        let snapshot = container
            .canonical_read_model_snapshot()
            .expect("canonical snapshot");
        snapshot.validate().expect("snapshot validates");
        assert_eq!(
            snapshot.ownership_epoch,
            container.owner_context.ownership_epoch
        );
        assert_eq!(snapshot.runtime_owner, RuntimeOwnerCategory::ServiceHost);
        assert_eq!(snapshot.runtime_mode, RuntimeMode::ServiceOwned);
        assert_eq!(snapshot.freshness_state, ReadModelSnapshotFreshness::Fresh);
        assert!(!snapshot.partial_state);
        assert_eq!(
            snapshot.items.len(),
            canonical_read_model_ownership_inventory().len()
        );
        let mut categories = snapshot
            .items
            .iter()
            .map(|item| item.model_category)
            .collect::<Vec<_>>();
        let original_categories = categories.clone();
        categories.sort();
        categories.dedup();
        assert_eq!(categories, original_categories);

        let repeated = container
            .canonical_read_model_snapshot()
            .expect("repeated snapshot");
        assert_eq!(snapshot.snapshot_id, repeated.snapshot_id);
        assert_eq!(container.canonical_read_model_generation_count(), 1);
        assert_eq!(container.provider_call_count(), 0);
        assert!(container.summary().provider_zero.all_zero());

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn canonical_read_store_rejects_stale_epoch_mutation() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let mut stale_context = container.owner_context.clone();
        stale_context.ownership_epoch = stale_context.ownership_epoch.saturating_add(1);

        let error = container
            .publish_canonical_read_model_snapshot(&stale_context)
            .expect_err("stale epoch rejected");
        assert_eq!(
            error.details_redacted,
            Some(json!({ "reason_category": "stale_ownership_epoch" }))
        );
        assert_eq!(container.canonical_read_model_generation_count(), 1);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn canonical_read_store_rejects_non_servicehost_owner() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let portable_context = RuntimeOwnerContext::portable_fallback(
            "portable-owner-ref",
            container.owner_context.ownership_epoch,
        );

        let error = container
            .publish_canonical_read_model_snapshot(&portable_context)
            .expect_err("portable owner rejected");
        assert_eq!(
            error.details_redacted,
            Some(json!({ "reason_category": "runtime_owner_mismatch" }))
        );
        assert_eq!(container.canonical_read_model_generation_count(), 1);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn canonical_read_store_publishes_immutable_coherent_generations() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let owner_context = container.owner_context.clone();
        let first = container
            .canonical_read_model_snapshot()
            .expect("first snapshot");
        let second = container
            .publish_canonical_read_model_snapshot(&owner_context)
            .expect("second snapshot");

        assert_ne!(first.snapshot_id, second.snapshot_id);
        assert_eq!(first.ownership_epoch, second.ownership_epoch);
        assert_eq!(second.generation_bucket, "generation_00000002");
        assert_eq!(container.canonical_read_model_generation_count(), 2);
        let store = container
            .canonical_read_model_store
            .as_ref()
            .expect("canonical store");
        assert_eq!(
            store.published_snapshots()[0].snapshot_id,
            first.snapshot_id
        );
        assert_eq!(
            store.published_snapshots()[1].snapshot_id,
            second.snapshot_id
        );
        let read_back = container
            .canonical_read_model_snapshot()
            .expect("read back snapshot");
        assert_eq!(read_back.snapshot_id, second.snapshot_id);
        assert_eq!(container.provider_call_count(), 0);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn canonical_read_store_unavailable_read_returns_partial_snapshot() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        container.canonical_read_model_store = None;

        let snapshot = container
            .canonical_read_model_snapshot()
            .expect("partial snapshot");
        snapshot.validate().expect("partial snapshot validates");
        assert!(snapshot.partial_state);
        assert_eq!(
            snapshot.degraded_reason.as_deref(),
            Some("coherent_snapshot_unavailable")
        );
        assert_eq!(
            snapshot.freshness_state,
            ReadModelSnapshotFreshness::Unavailable
        );
        assert!(snapshot.items.is_empty());
        assert_eq!(container.provider_call_count(), 0);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn storage_ownership_service_host_container_acquires_canonical_writer() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let status = container
            .storage_ownership_status()
            .expect("storage ownership status");

        assert_eq!(
            status.owner_category,
            sentinel_storage::StorageWriterOwnerCategory::ServiceHost
        );
        assert_eq!(status.writer_state, StorageWriterState::Owned);
        assert!(status.canonical_writer);
        assert!(!status.path_exposed);
        assert!(!status.llm_key_transferred);
        assert!(container
            .audit_events()
            .iter()
            .any(|event| event.event_kind == RuntimeOwnershipAuditEventKind::StorageOwnerAcquired));
        let serialized = serde_json::to_string(&container.summary()).expect("summary json");
        for marker in ["c:\\", "sid", "token", "api_key", "password", "nonce"] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "runtime storage summary leaked marker {marker}"
            );
        }

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn storage_ownership_servicehost_durable_manifest_and_recovery_are_service_owned() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");

        let manifest = container.durable_storage_manifest();
        manifest.validate().expect("durable manifest validates");
        assert_eq!(
            manifest.owner_category,
            sentinel_storage::StorageWriterOwnerCategory::ServiceHost
        );
        assert!(manifest.canonical_writer_required);
        assert!(!manifest.desktop_writer_allowed);
        assert!(!manifest.cross_process_sqlite_connection_allowed);
        assert!(manifest.policy("runtime_session_state").is_some());
        assert!(manifest.policy("scheduler_state").is_some());
        assert!(manifest.policy("sampler_state").is_some());
        assert!(manifest.policy("baseline_state").is_some());
        assert!(manifest.policy("incident_linked_state").is_some());
        assert!(manifest
            .policy("portable_reader_cursor_state")
            .is_some_and(|policy| policy.restored_on_restart && policy.servicehost_canonical));
        assert!(manifest.split_owned_state.iter().any(|policy| {
            policy.state_name == "temporary_llm_key"
                && policy.classification
                    == sentinel_storage::StoragePersistenceClassification::NotPersisted
                && !policy.transferred_to_servicehost
                && !policy.persisted_by_servicehost
        }));

        let recovery = container
            .storage_recovery_report()
            .expect("storage recovery report");
        assert!(!recovery.degraded);
        assert_eq!(recovery.writer_state, StorageWriterState::Owned);
        assert!(recovery.schema_validated);
        assert!(recovery.ownership_validated);
        assert!(recovery.new_ownership_epoch_established);
        assert!(recovery.canonical_snapshots_rebuilt);
        assert!(recovery.allowed_state_restored_count >= manifest.durable_state.len());
        assert!(!recovery.scheduler_activated);
        assert!(!recovery.sampler_activated);
        assert!(!recovery.provider_executed);
        assert!(!recovery.stale_findings_replayed);
        assert!(!recovery.llm_invoked);
        assert!(!recovery.cross_process_sqlite_connection_shared);
        assert!(!recovery.storage_path_exposed);
        assert_eq!(container.provider_call_count(), 0);
        let serialized = serde_json::to_string(&(manifest, recovery)).expect("storage json");
        for marker in [
            "c:\\",
            "pid_value",
            "raw_log_value",
            "process_name_value",
            "api_key_value",
            "nonce_value",
            "secret_value",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "durable storage status leaked marker {marker}"
            );
        }

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn storage_ownership_shutdown_releases_writer_before_reopen() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut first = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("first service host container");
        assert_eq!(first.storage_writer_count(), 1);
        let shutdown_summary = first.shutdown().expect("shutdown");
        assert_eq!(first.storage_writer_count(), 0);
        assert!(first
            .audit_events()
            .iter()
            .any(|event| event.event_kind == RuntimeOwnershipAuditEventKind::StorageOwnerReleased));
        shutdown_summary.validate().expect("shutdown summary");

        let mut second = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host reopen after storage release");
        assert_eq!(
            second.storage_writer_state(),
            Some(StorageWriterState::Owned)
        );
        second.shutdown().expect("second shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn storage_ownership_report_export_traceability_remains_canonical() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");

        assert!(container.storage_canonical_writer());
        assert_eq!(container.report_export_traceability_ref_count(), 0);
        assert_eq!(container.baseline_state_count(), 1);
        assert_eq!(container.incident_linking_state_count(), 1);
        assert_eq!(container.app_core_orchestration_count(), 1);
        let traceability = container
            .canonical_report_export_traceability()
            .expect("canonical traceability");
        traceability.validate().expect("traceability validates");
        assert_eq!(
            traceability.runtime_owner,
            RuntimeOwnerCategory::ServiceHost
        );
        assert_eq!(
            traceability.ownership_epoch,
            container.owner_context().ownership_epoch
        );
        assert_eq!(traceability.snapshot_refs.len(), 1);
        assert!(traceability.integrity_hash.starts_with("trace_hash_"));
        assert_eq!(traceability.redaction_status, RedactionStatus::Redacted);
        let serialized = serde_json::to_string(traceability).expect("traceability json");
        for marker in [
            "c:\\",
            "pid:",
            "process_name",
            "raw_log",
            "provider_value",
            "username",
            "sid",
            "token",
            "password",
            "api_key",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "traceability leaked marker {marker}"
            );
        }

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn runtime_container_phase_0b_closure_summary_marks_complete_without_provider_or_response() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");

        let closure = container.phase_0b_closure_summary();
        assert!(closure.complete());
        assert_eq!(closure.legacy_constructor_violations, 0);
        assert!(closure.servicehost_canonical_read_model_owner);
        assert!(!closure.desktop_canonical_owner);
        assert!(!closure.desktop_storage_writer);
        assert_eq!(closure.servicehost_mutable_writer_count, 1);
        assert_eq!(closure.disconnect_replacement_runtime_count, 0);
        assert_eq!(closure.read_only_ipc_side_effects, 0);
        assert_eq!(closure.provider_call_count, 0);
        assert!(closure.provider_zero.all_zero());
        assert_eq!(
            closure.mutation_trust_state,
            RuntimeMutationTrustState::ImpersonationNotImplemented
        );
        assert!(!closure.mutation_commands_enabled);
        assert_eq!(closure.response_execution_state, "unavailable");
        assert_eq!(closure.automatic_llm_state, "forbidden");

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn runtime_ownership_app_core_production_constructor_receives_container_owned_services() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let orchestration = container
            .app_core_orchestration
            .as_ref()
            .expect("app-core orchestration");

        assert!(orchestration.has_container_owned_runtime_context());
        assert_eq!(
            orchestration.runtime_ownership_epoch(),
            Some(container.owner_context.ownership_epoch)
        );
        orchestration
            .validate_current_owner_epoch()
            .expect("active owner epoch");

        let test_owned = MutationCommandState::from_read_state(orchestration.read_state().clone())
            .expect("test-owned local state");
        assert!(
            test_owned.has_container_owned_runtime_context(),
            "test compatibility constructors must use explicit test-harness ownership"
        );
        assert_ne!(
            test_owned.runtime_ownership_epoch(),
            orchestration.runtime_ownership_epoch(),
            "test fixtures must not borrow the ServiceHost ownership epoch"
        );

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn owner_epoch_stale_production_mutation_is_rejected() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let orchestration = container
            .app_core_orchestration
            .as_mut()
            .expect("app-core orchestration");
        let stale_context = orchestration
            .runtime_mutation_context_for_tests()
            .with_expected_epoch_for_tests(container.owner_context.ownership_epoch + 1);
        orchestration.replace_runtime_mutation_context_for_tests(stale_context);

        let error = orchestration
            .tick_native_scheduler(test_tick_request())
            .expect_err("stale epoch rejects mutation");
        assert_eq!(
            error.details_redacted,
            Some(json!({ "reason_category": "stale_ownership_epoch" }))
        );

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn runtime_ownership_shutdown_context_rejects_production_mutation() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");
        let orchestration = container
            .app_core_orchestration
            .as_mut()
            .expect("app-core orchestration");
        let shutdown_context = orchestration
            .runtime_mutation_context_for_tests()
            .shutdown_for_tests();
        orchestration.replace_runtime_mutation_context_for_tests(shutdown_context);

        let error = orchestration
            .tick_native_scheduler(test_tick_request())
            .expect_err("shutdown context rejects mutation");
        assert_eq!(
            error.details_redacted,
            Some(json!({ "reason_category": "runtime_shutdown_in_progress" }))
        );

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn runtime_ownership_container_does_not_duplicate_endpoint_or_fusion_execution() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service host container");

        assert_eq!(container.endpoint_threat_runtime_count(), 1);
        assert_eq!(container.fusion_state_count(), 1);
        assert_eq!(container.evidence_quality_state_count(), 1);
        assert_eq!(container.risk_state_count(), 1);
        assert_eq!(container.endpoint_runtime_finding_count(), 0);
        assert_eq!(container.startup_side_effect_count(), 0);

        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn runtime_container_duplicate_service_construction_is_rejected() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut first = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("first container");
        let second = RuntimeContainerBuilder::for_service_host().build();
        let second = match second {
            Ok(mut duplicate) => {
                let _ = duplicate.shutdown();
                panic!("duplicate rejected");
            }
            Err(error) => error,
        };
        assert_eq!(
            second.details_redacted,
            Some(json!({ "reason_category": "duplicate_runtime_container" }))
        );
        first.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn runtime_ownership_stale_epoch_and_desktop_creation_are_rejected() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service container");
        assert!(matches!(
            container
                .ownership_lease
                .validate_epoch(container.owner_context.ownership_epoch.saturating_add(1)),
            Err(RuntimeOwnershipError::StaleOwnershipEpoch)
        ));
        assert!(desktop_runtime_creation_gate(RuntimeMode::ServiceOwned).is_err());
        container.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn runtime_container_shutdown_is_idempotent_and_releases_guard() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service container");
        let first = container.shutdown().expect("first shutdown");
        let second = container.shutdown().expect("second shutdown");
        assert_eq!(first.transition_state, RuntimeTransitionState::Released);
        assert_eq!(second.transition_state, RuntimeTransitionState::Released);
        let mut reopened = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("reopen after release");
        reopened.shutdown().expect("shutdown reopened");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn runtime_container_shutdown_receipt_enforces_exact_order_and_provider_zero() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("service container");

        let before_ipc = container
            .shutdown_before_ipc_close()
            .expect("pre-ipc shutdown");
        assert_eq!(before_ipc.shutdown.state, RuntimeShutdownState::InProgress);
        assert_eq!(
            before_ipc.shutdown.stages.last().map(|stage| stage.stage),
            Some(RuntimeShutdownStage::ReleaseOwnershipGuard)
        );
        assert!(before_ipc.shutdown.mutation_leases_invalidated);
        assert!(before_ipc.shutdown.scheduler_host_cancellation_signalled);
        assert!(before_ipc.shutdown.scheduler_host_joined);
        assert!(!before_ipc.shutdown.provider_stop_called);
        assert_eq!(before_ipc.provider_call_count, 0);
        assert!(before_ipc.provider_zero.all_zero());
        assert!(!container.provider_controller.stop_called());

        let completed = container
            .complete_shutdown_after_ipc_close()
            .expect("completed shutdown");
        assert_eq!(completed.shutdown.state, RuntimeShutdownState::Completed);
        assert_eq!(
            completed
                .shutdown
                .stages
                .iter()
                .map(|stage| stage.stage)
                .collect::<Vec<_>>(),
            vec![
                RuntimeShutdownStage::RejectMutations,
                RuntimeShutdownStage::ShutdownInProgress,
                RuntimeShutdownStage::InvalidateMutationLeases,
                RuntimeShutdownStage::SignalSchedulerHostCancellation,
                RuntimeShutdownStage::JoinSchedulerHost,
                RuntimeShutdownStage::DisableScheduler,
                RuntimeShutdownStage::StopSamplers,
                RuntimeShutdownStage::StopPortableReaders,
                RuntimeShutdownStage::CancelAnalysisWork,
                RuntimeShutdownStage::DrainEventBus,
                RuntimeShutdownStage::StopPluginRuntime,
                RuntimeShutdownStage::StopDag,
                RuntimeShutdownStage::CloseEventBus,
                RuntimeShutdownStage::FinalizeCanonicalReadModels,
                RuntimeShutdownStage::CloseStorageWriter,
                RuntimeShutdownStage::ClearServiceSessionState,
                RuntimeShutdownStage::ReleaseOwnershipGuard,
                RuntimeShutdownStage::CloseIpc,
                RuntimeShutdownStage::Stopped,
            ]
        );
        assert!(completed
            .shutdown
            .stages
            .iter()
            .all(|stage| stage.state == RuntimeShutdownStageState::Completed));
        assert_eq!(completed.runtime_health, RuntimeHealthState::Stopped);
        assert_eq!(completed.storage_owner_state, "released");
        assert_eq!(completed.canonical_read_model_owner, "released");
        assert_eq!(completed.snapshot_freshness, "finalized");
        completed.validate().expect("completed shutdown summary");

        let idempotent = container.shutdown().expect("idempotent shutdown");
        assert_eq!(idempotent.shutdown.stages, completed.shutdown.stages);
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn runtime_container_partial_initialization_conflict_rolls_back_ownership() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let context =
            RuntimeOwnerContext::service_host("runtime-owner-rollback", 42, "service-instance");
        let blocker = sentinel_storage::StorageWriterLease::acquire_service_host_runtime(42)
            .expect("storage blocker");

        let error = match RuntimeContainerBuilder::for_service_host_context(context.clone()).build()
        {
            Ok(mut unexpected) => {
                let _ = unexpected.shutdown();
                panic!("storage conflict must reject partial initialization");
            }
            Err(error) => error,
        };
        assert_eq!(
            error.details_redacted,
            Some(json!({ "reason_category": "storage_writer_conflict" }))
        );
        blocker.release();

        let mut reopened = RuntimeContainerBuilder::for_service_host_context(context)
            .build()
            .expect("ownership guard released by rollback");
        assert_eq!(reopened.provider_call_count(), 0);
        reopened.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn runtime_ownership_status_does_not_expose_sensitive_markers() {
        let mut container = RuntimeContainerBuilder::for_test("privacy")
            .build()
            .expect("test container");
        let serialized = serde_json::to_string(&serde_json::json!({
            "summary": container.summary(),
            "audit": container.audit_events(),
            "inventory": runtime_constructor_inventory(),
        }))
        .expect("serialize");
        for marker in [
            "process.exe",
            "pid",
            "10.0.0.1",
            "port=",
            "exact_port",
            "c:\\",
            "username",
            "sid",
            "token",
            "credential",
            "nonce",
            "secret",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "runtime ownership status leaked marker {marker}"
            );
        }
        container.shutdown().expect("shutdown");
    }

    #[test]
    fn portable_fallback_requires_explicit_selection() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        assert!(RuntimeContainerBuilder::for_portable_fallback(false)
            .build()
            .is_err());
        let mut fallback = RuntimeContainerBuilder::for_portable_fallback(true)
            .build()
            .expect("explicit fallback");
        assert_eq!(
            fallback.summary().runtime_mode,
            RuntimeMode::PortableInProcess
        );
        fallback.shutdown().expect("shutdown");
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn servicehost_native_health_foreground_path_uses_shared_runtime_and_shuts_down() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("servicehost container");
        let owner = container.owner_context().clone();
        let initial_generation = container
            .canonical_read_model_current_generation()
            .expect("initial generation");

        let authorization = container
            .authorize_native_health_sampler(&owner, "native health runtime test authorization")
            .expect("authorize");
        assert_eq!(
            authorization.capability.permission_state,
            sentinel_contracts::NativePermissionState::GrantedSession
        );
        container
            .apply_native_health_sampler_action(
                &owner,
                NativeSamplerRuntimeAction::Activate,
                "native health runtime test activation",
            )
            .expect("activate");
        let sampled = container
            .apply_native_health_sampler_action(
                &owner,
                NativeSamplerRuntimeAction::SampleNow,
                "native health runtime test sample",
            )
            .expect("sample");
        let batch = sampled.latest_batch.expect("health batch");
        #[cfg(windows)]
        {
            assert!(batch.counters.provider_enabled_count > 0);
            assert!(batch.counters.raw_record_count > 0);
            assert!(batch.counters.normalized_record_count > 0);
        }
        assert!(batch.counters.published_batch_count > 0);
        assert!(batch.counters.eventbus_publication_count > 0);
        assert!(batch.counters.dag_dispatch_count > 0);
        assert!(batch.counters.plugin_runtime_invocation_count > 0);
        assert!(batch.counters.observations_consumed_count > 0);
        assert!(batch.counters.facts_emitted_count > 0);
        assert!(batch.counters.detector_consumer_invocation_count > 0);
        assert!(batch.counters.detector_observations_consumed_count > 0);
        assert!(
            container
                .canonical_read_model_current_generation()
                .expect("updated generation")
                > initial_generation
        );
        assert!(container.evidence_quality_record_count() > 0);

        let serialized = serde_json::to_string(&batch).expect("serialize health batch");
        for forbidden in [
            "raw_ip",
            "raw_port",
            "packet_payload",
            "process_id",
            "process_name",
            "executable_path",
            "command_line",
            "username",
            "\"sid\"",
            "credential",
            "access_token",
            "nonce",
            "secret",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }

        container
            .apply_native_health_sampler_action(
                &owner,
                NativeSamplerRuntimeAction::Stop,
                "native health runtime test stop",
            )
            .expect("stop");
        let shutdown = container.shutdown().expect("shutdown");
        assert_eq!(shutdown.shutdown.state, RuntimeShutdownState::Completed);
        assert!(shutdown.shutdown.scheduler_host_joined);
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn servicehost_native_service_foreground_path_uses_shared_runtime_and_shuts_down() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("servicehost container");
        let owner = container.owner_context().clone();
        let initial_generation = container
            .canonical_read_model_current_generation()
            .expect("initial generation");

        let authorization = container
            .authorize_native_service_sampler(&owner, "service sampler runtime test authorization")
            .expect("authorize");
        assert_eq!(
            authorization.capability.permission_state,
            sentinel_contracts::NativePermissionState::GrantedSession
        );
        container
            .apply_native_service_sampler_action(
                &owner,
                NativeSamplerRuntimeAction::Activate,
                "service sampler runtime test activation",
            )
            .expect("activate");
        let sampled = container
            .apply_native_service_sampler_action(
                &owner,
                NativeSamplerRuntimeAction::SampleNow,
                "service sampler runtime test sample",
            )
            .expect("sample");
        let batch = sampled.latest_batch.expect("service batch");
        #[cfg(windows)]
        {
            assert!(batch.counters.provider_enabled_count > 0);
            assert!(batch.counters.raw_record_count > 0);
            assert!(batch.counters.schema_accepted_count > 0);
            assert_eq!(batch.counters.schema_rejected_count, 0);
            assert!(batch.counters.normalized_record_count > 0);
            assert!(!batch.service_records.is_empty());
        }
        assert!(batch.counters.published_batch_count > 0);
        assert!(batch.counters.eventbus_publication_count > 0);
        assert!(batch.counters.dag_dispatch_count > 0);
        assert!(batch.counters.plugin_runtime_invocation_count > 0);
        assert!(batch.counters.observations_consumed_count > 0);
        assert!(batch.counters.facts_emitted_count > 0);
        assert!(batch.counters.detector_consumer_invocation_count > 0);
        assert!(batch.counters.detector_observations_consumed_count > 0);
        assert_eq!(batch.counters.detector_output_count, 0);
        assert!(container.security_fact_count() > 0);
        assert!(container
            .native_sampler_runtime_status("service_metadata_sampler")
            .is_some_and(|status| status.counters == batch.counters));
        assert!(
            container
                .canonical_read_model_current_generation()
                .expect("updated generation")
                > initial_generation
        );
        assert!(container.evidence_quality_record_count() > 0);

        let serialized = serde_json::to_string(&batch).expect("serialize service batch");
        for forbidden in [
            "service_name",
            "display_name",
            "executable_path",
            "command_line",
            "account_name",
            "username",
            "\"sid\"",
            "\"pid\"",
            "registry_path",
            "raw_ip",
            "raw_port",
            "packet_payload",
            "credential",
            "secret",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }

        container
            .apply_native_service_sampler_action(
                &owner,
                NativeSamplerRuntimeAction::Stop,
                "service sampler runtime test stop",
            )
            .expect("stop");
        container
            .apply_native_service_sampler_action(
                &owner,
                NativeSamplerRuntimeAction::Revoke,
                "service sampler runtime test revoke",
            )
            .expect("revoke");
        let shutdown = container.shutdown().expect("shutdown");
        assert_eq!(shutdown.shutdown.state, RuntimeShutdownState::Completed);
        assert!(shutdown.shutdown.scheduler_host_joined);
        RuntimeOwnershipGuard::reset_for_tests();
    }

    #[test]
    fn servicehost_native_process_foreground_path_uses_shared_runtime_and_shuts_down() {
        let _lock = RUNTIME_CONTAINER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RuntimeOwnershipGuard::reset_for_tests();
        let mut container = RuntimeContainerBuilder::for_service_host()
            .build()
            .expect("servicehost container");
        let owner = container.owner_context().clone();
        let initial_generation = container
            .canonical_read_model_current_generation()
            .expect("initial generation");

        let authorization = container
            .authorize_native_process_sampler(&owner, "process sampler runtime test authorization")
            .expect("authorize");
        assert_eq!(
            authorization.capability.permission_state,
            sentinel_contracts::NativePermissionState::GrantedSession
        );
        container
            .apply_native_process_sampler_action(
                &owner,
                NativeSamplerRuntimeAction::Activate,
                "process sampler runtime test activation",
            )
            .expect("activate");
        let sampled = container
            .apply_native_process_sampler_action(
                &owner,
                NativeSamplerRuntimeAction::SampleNow,
                "process sampler runtime test sample",
            )
            .expect("sample");
        let batch = sampled.latest_batch.expect("process batch");
        #[cfg(windows)]
        {
            assert!(batch.counters.provider_enabled_count > 0);
            assert!(batch.counters.raw_record_count > 0);
            assert!(batch.counters.schema_accepted_count > 0);
            assert_eq!(batch.counters.schema_rejected_count, 0);
            assert!(batch.counters.normalized_record_count > 0);
            assert!(!batch.process_records.is_empty());
        }
        assert!(batch.counters.published_batch_count > 0);
        assert!(batch.counters.eventbus_publication_count > 0);
        assert!(batch.counters.dag_dispatch_count > 0);
        assert!(batch.counters.plugin_runtime_invocation_count > 0);
        assert!(batch.counters.observations_consumed_count > 0);
        assert!(batch.counters.facts_emitted_count > 0);
        assert!(batch.counters.detector_consumer_invocation_count > 0);
        assert!(batch.counters.detector_observations_consumed_count > 0);
        assert!(container.security_fact_count() > 0);
        assert!(container
            .native_sampler_runtime_status("process_metadata_sampler")
            .is_some_and(|status| status.counters == batch.counters));
        assert!(
            container
                .canonical_read_model_current_generation()
                .expect("updated generation")
                > initial_generation
        );
        assert!(container.evidence_quality_record_count() > 0);

        let serialized = serde_json::to_string(&batch).expect("serialize process batch");
        for forbidden in [
            "raw_process_name",
            "process_name",
            "parent_pid",
            "\"pid\"",
            "command_line",
            "executable_path",
            "working_directory",
            "account_name",
            "username",
            "\"sid\"",
            "raw_ip",
            "raw_port",
            "packet_payload",
            "credential",
            "secret",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }

        container
            .apply_native_process_sampler_action(
                &owner,
                NativeSamplerRuntimeAction::Stop,
                "process sampler runtime test stop",
            )
            .expect("stop");
        container
            .apply_native_process_sampler_action(
                &owner,
                NativeSamplerRuntimeAction::Revoke,
                "process sampler runtime test revoke",
            )
            .expect("revoke");
        let shutdown = container.shutdown().expect("shutdown");
        assert_eq!(shutdown.shutdown.state, RuntimeShutdownState::Completed);
        assert!(shutdown.shutdown.scheduler_host_joined);
        RuntimeOwnershipGuard::reset_for_tests();
    }

    fn test_tick_request() -> sentinel_contracts::NativeSchedulerTickRequest {
        sentinel_contracts::NativeSchedulerTickRequest {
            monotonic_elapsed_millis: 1,
            max_samplers_per_tick: 3,
            global_concurrency_limit: 3,
            per_category_concurrency_limit: 1,
            provider_timeout_millis: 5_000,
            execution_timeout_millis: 5_000,
            global_cycle_timeout_millis: 30_000,
            retry_delay_millis: 1_000,
            event_bus_backlog_count: 0,
            dag_backlog_count: 0,
            cancellation_requested: false,
            reason_redacted: "bounded owner epoch test tick".to_string(),
        }
    }
}
