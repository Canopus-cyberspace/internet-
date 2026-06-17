use crate::authorized_native_permissions::{
    default_capability_catalog, native_permission_audit_summary, native_permission_status_summary,
    native_visibility_summary,
};
use crate::baseline_read_models::build_durable_baseline_summary;
use crate::endpoint_threat_runtime::{
    get_endpoint_threat_analysis_summary as build_endpoint_threat_analysis_summary,
    EndpointThreatAnalysisSummary,
};
use crate::evidence_quality::build_evidence_quality_summary;
use crate::investigation_drill_down::build_investigation_drill_down_summary;
use crate::machine_local_capabilities::CapabilityStatusSummary;
use crate::native_sampler_readiness::{
    get_edr_readiness_summary as build_edr_readiness_summary,
    get_future_security_fact_mapping_summary as build_future_security_fact_mapping_summary,
    get_missing_endpoint_visibility_summary as build_missing_endpoint_visibility_summary,
    get_native_sampler_authorization_review as build_native_sampler_authorization_review,
    get_native_sampler_blocked_summary as build_native_sampler_blocked_summary,
    get_native_sampler_contract as build_native_sampler_contract,
    get_native_sampler_readiness_detail as build_native_sampler_readiness_detail,
    get_native_sampler_readiness_summary as build_native_sampler_readiness_summary,
    list_native_sampler_contracts as build_native_sampler_contracts,
};
use crate::native_sampler_runtime::NativeSamplerRuntime;
use crate::native_scheduler::NativeSchedulerController;
use crate::native_scheduler_host::{
    default_native_scheduler_host_status, NativeSchedulerHostController,
};
use crate::reference_navigation::resolve_bounded_reference;
use sentinel_capabilities::{
    layered_sampler_catalog, ExportHistoryRecord, ExportHistoryStorageAdapter, ExportHistoryStore,
    ExportPolicyViolation, GraphAnalyticsError, GraphAnalyticsRequest, GraphAnalyticsService,
    ReportExportHistoryQuery,
};
use sentinel_contracts::{
    Alert, AttackCoverageConfidenceBucket, AttackCoverageCount, AttackCoverageState,
    AttackCoverageSummary, AttackCoverageTechniqueRow, AttackHypothesisId, AttackHypothesisRecord,
    AttackLastObservedBucket, AttackObservedCountBucket, AttackRequiredVisibility, AttackTaxonomy,
    AuthorizedNativeCapabilityStatus, BaselineDrillDownDetail, BaselineIndicator,
    BaselineIndicatorId, BaselineRecord, BaselineRecordId, CapabilityManifest, CommandResult,
    ContractDescriptor, CoreError, DnsObservation, DurableBaselineSummary, EdrReadinessSummary,
    ErrorCode, ErrorSeverity, EvidenceId, EvidenceQualityId, EvidenceQualityRecord,
    EvidenceQualitySummary, ExportResultId, FallbackRendererType, FilterOperator, FilterSpec,
    FilterValue, Finding, FindingId, FlowRecord, FusionSummary, FutureSecurityFactMappingSummary,
    GraphScope, GraphType, GraphViewModel, HttpMetadata, HypothesisExplanationDetail, Incident,
    IncidentGroupInvestigationDetail, IncidentId, IncidentLinkedGroupId,
    IncidentLinkedHypothesisGroup, IncidentTimelineEntry, IncidentTimelineEntryId,
    InvestigationDrillDownSummary, LlmAlertStoryId, LlmAlertStoryRecord, MetadataSamplingBatchId,
    MetadataSamplingBatchSummary, MetadataWatchControllerStatus, MetadataWatchSourceId,
    MetadataWatchSourceStatus, MissingEndpointVisibilitySummary, MutationAuthorizationStatus,
    NativePermissionAuditEntry, NativePermissionAuditSummary, NativePermissionStatusSummary,
    NativeSamplerAuthorizationReview, NativeSamplerBlockedSummary, NativeSamplerContract,
    NativeSamplerReadinessDetail, NativeSamplerReadinessSummary, NativeSamplerRuntimeAuditEntry,
    NativeSamplerRuntimeBatch, NativeSamplerRuntimeStatus, NativeSamplerRuntimeSummary,
    NativeSamplerScheduleStatus, NativeSchedulerAuditEntry, NativeSchedulerControllerState,
    NativeSchedulerCycleSummary, NativeSchedulerHostAuditEntry, NativeSchedulerHostCycleSummary,
    NativeSchedulerHostHealthSummary, NativeSchedulerHostStatus, NativeSchedulerOperationalSummary,
    NativeSchedulerStatus, NativeSchedulerSummary, NativeStatusEvent, NativeVisibilitySummary,
    NavigationResolution, NavigationResolveRequest, NetworkFallbackPlan,
    NetworkProviderControllerStatus, NetworkProviderKind, NetworkProviderStatus,
    NetworkVisibilitySummary, PageRequest, PageResponse, PluginDependencyType, PluginId,
    PluginManifest, PortableCaptureProvenance, PrivacyClass, QualityBreakdown, QueryRequest,
    QueryScope, RedactedLabel, Report, ReportId, ResponsePlan, RiskEventId, RuntimeProfile,
    SchemaVersion, SecurityFact, SecuritySeverity, SessionId, SortDirection, SortSpec,
    SourceReliabilityExplanation, SourceReliabilitySummary, TimeRange, TimelineDrillDownDetail,
    Timestamp, TlsObservation, TraceId, UiContribution, MAX_ATTACK_COVERAGE_REFS,
};
use sentinel_infrastructure::{
    ElevatedServiceIpcClient, ServiceIpcClientError, ServiceIpcClientErrorKind,
};
use sentinel_platform::component::{
    ComponentDefinition, ComponentId, ComponentInstance, ComponentState, ComponentType,
    ContractBinding, DependencyBinding, HealthReference, HealthStatus as ComponentHealthStatus,
    MetricReference, PermissionBinding, TransitionContext, VisualizationBinding,
};
use sentinel_platform::observability::HealthStatus as ObservabilityHealthStatus;
use sentinel_platform::registry::{
    CapabilityRegistry, ComponentRegistry, ContractRegistry, DependencyRegistry, PluginRegistry,
    RegistryError, RuntimeMetadata, RuntimeRegistry,
};
use sentinel_platform::{
    BuiltInPluginCatalog, HealthSnapshot, HealthSubject, MetricSample, MockPlugin,
};
use sentinel_storage::{SqliteStoreFactory, StoreKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{cmp::Ordering, collections::BTreeMap};

const READ_CURSOR_PREFIX: &str = "app_core_read:v1";

#[derive(Clone, Debug)]
pub struct ReadOnlyCommandState {
    pub(crate) component_registry: ComponentRegistry,
    pub(crate) plugin_registry: PluginRegistry,
    pub(crate) capability_registry: CapabilityRegistry,
    pub(crate) contract_registry: ContractRegistry,
    pub(crate) dependency_registry: DependencyRegistry,
    pub(crate) runtime_registry: RuntimeRegistry,
    pub(crate) findings: LogicalReadCollection<Finding>,
    pub(crate) alerts: LogicalReadCollection<Alert>,
    pub(crate) incidents: LogicalReadCollection<Incident>,
    pub(crate) flows: LogicalReadCollection<FlowRecord>,
    pub(crate) dns: LogicalReadCollection<DnsObservation>,
    pub(crate) tls: LogicalReadCollection<TlsObservation>,
    pub(crate) http_metadata: LogicalReadCollection<HttpMetadata>,
    pub(crate) response_plans: LogicalReadCollection<ResponsePlan>,
    pub(crate) reports: LogicalReadCollection<Report>,
    pub(crate) llm_alert_stories: LogicalReadCollection<LlmAlertStoryRecord>,
    pub(crate) security_facts: LogicalReadCollection<SecurityFact>,
    pub(crate) attack_hypotheses: LogicalReadCollection<AttackHypothesisRecord>,
    pub(crate) fusion_summaries: Vec<FusionSummary>,
    pub(crate) endpoint_threat_candidates: Vec<sentinel_contracts::EndpointThreatCandidate>,
    pub(crate) endpoint_threat_findings: Vec<sentinel_contracts::EndpointThreatFinding>,
    pub(crate) endpoint_threat_evidence: Vec<sentinel_contracts::EndpointThreatEvidence>,
    pub(crate) endpoint_threat_risk_hints: Vec<sentinel_contracts::EndpointThreatRiskHint>,
    pub(crate) endpoint_visibility_advisories: Vec<sentinel_contracts::EndpointVisibilityAdvisory>,
    pub(crate) endpoint_threat_rejected: Vec<sentinel_contracts::EndpointRejectedCandidate>,
    pub(crate) endpoint_threat_graph_hints: Vec<sentinel_contracts::GraphHint>,
    pub(crate) endpoint_threat_emitted_topics: Vec<String>,
    pub(crate) metadata_watch_sources: LogicalReadCollection<MetadataWatchSourceStatus>,
    pub(crate) metadata_sampling_batches: LogicalReadCollection<MetadataSamplingBatchSummary>,
    pub(crate) metadata_watch_controller_status: MetadataWatchControllerStatus,
    pub(crate) authorized_native_capabilities: Vec<AuthorizedNativeCapabilityStatus>,
    pub(crate) native_permission_audit_entries: Vec<NativePermissionAuditEntry>,
    pub(crate) native_status_events: Vec<NativeStatusEvent>,
    pub(crate) native_sampler_runtime_statuses: Vec<NativeSamplerRuntimeStatus>,
    pub(crate) native_sampler_runtime_batches: Vec<NativeSamplerRuntimeBatch>,
    pub(crate) native_sampler_runtime_audit_entries: Vec<NativeSamplerRuntimeAuditEntry>,
    pub(crate) native_scheduler_controller_state: NativeSchedulerControllerState,
    pub(crate) native_sampler_schedule_statuses: Vec<NativeSamplerScheduleStatus>,
    pub(crate) native_scheduler_audit_entries: Vec<NativeSchedulerAuditEntry>,
    pub(crate) native_scheduler_cycles: Vec<NativeSchedulerCycleSummary>,
    pub(crate) native_scheduler_last_tick_monotonic_millis: Option<u64>,
    pub(crate) native_scheduler_next_due_monotonic_millis: BTreeMap<String, u64>,
    pub(crate) native_scheduler_retry_attempts: BTreeMap<String, u32>,
    pub(crate) native_scheduler_graceful_shutdown_requested: bool,
    pub(crate) native_scheduler_cycle_gate_active: bool,
    pub(crate) native_scheduler_host_status: NativeSchedulerHostStatus,
    pub(crate) native_scheduler_host_cycles: Vec<NativeSchedulerHostCycleSummary>,
    pub(crate) native_scheduler_host_audit_entries: Vec<NativeSchedulerHostAuditEntry>,
    pub(crate) export_history: ExportHistoryStore,
    pub(crate) portable_capture_sources: Vec<PortableCaptureProvenance>,
    pub(crate) graph_views: Vec<GraphViewModel>,
    pub(crate) health_snapshots: Vec<HealthSnapshot>,
    pub(crate) metric_samples: Vec<MetricSample>,
    pub(crate) runtime_profile: RuntimeProfile,
    pub(crate) service_status: ServiceStatusView,
    pub(crate) catalog_mock_only: bool,
    pub(crate) catalog_production_ready: bool,
}

pub(crate) struct ReadModelRegistries {
    pub(crate) component_registry: ComponentRegistry,
    pub(crate) plugin_registry: PluginRegistry,
    pub(crate) capability_registry: CapabilityRegistry,
    pub(crate) contract_registry: ContractRegistry,
    pub(crate) dependency_registry: DependencyRegistry,
    pub(crate) runtime_registry: RuntimeRegistry,
}

impl ReadOnlyCommandState {
    #[cfg(any(test, feature = "test-support"))]
    pub fn bootstrap() -> CommandResult<Self> {
        crate::runtime_container::RuntimeContainerBuilder::for_test("read-only-command-state")
            .build_read_state_for_test()
    }

    pub(crate) fn from_catalog_with_registries(
        catalog: BuiltInPluginCatalog,
        registries: ReadModelRegistries,
    ) -> CommandResult<Self> {
        let ReadModelRegistries {
            mut component_registry,
            mut plugin_registry,
            mut capability_registry,
            mut contract_registry,
            mut dependency_registry,
            mut runtime_registry,
        } = registries;
        let mut health_snapshots = Vec::new();
        let mut metric_samples = Vec::new();
        let catalog_mock_only = catalog.mock_only_catalog();
        let catalog_production_ready = catalog.production_ready();

        for capability in catalog.capability_manifests() {
            capability_registry
                .register(capability.clone())
                .map_err(registry_error("capability_registry"))?;
        }

        for contract in catalog.contract_descriptors() {
            contract_registry
                .register(contract)
                .map_err(registry_error("contract_registry"))?;
        }

        for plugin in catalog.plugins() {
            let definition = component_definition_for_plugin(plugin)?;
            let component_id = definition.component_id.clone();
            let manifest = plugin.manifest().clone();

            component_registry
                .register(definition.clone())
                .map_err(registry_error("component_registry"))?;
            dependency_registry.register_component_definition(&definition);
            dependency_registry.register_plugin_manifest(&manifest);
            plugin_registry
                .register(manifest.clone(), Some(component_id.clone()))
                .map_err(registry_error("plugin_registry"))?;

            let instance = running_instance(&definition)?;
            component_registry
                .register_instance(instance)
                .map_err(registry_error("component_instance_registry"))?;
            runtime_registry
                .register(RuntimeMetadata {
                    component_id: component_id.clone(),
                    plugin_id: Some(manifest.plugin_id.clone()),
                    runtime_mode: manifest.runtime_mode.clone(),
                    component_state: ComponentState::Running,
                    health_status: ComponentHealthStatus::Healthy,
                    metadata_version: SchemaVersion::new(1, 0, 0),
                    last_resolved_at: Some(Timestamp::now()),
                })
                .map_err(registry_error("runtime_registry"))?;

            let health = plugin.health_provider().snapshot(&manifest.plugin_id);
            health.validate().map_err(|error| {
                internal_error(
                    "plugin_health",
                    "plugin health snapshot failed safety validation",
                    json!({
                        "plugin_id": manifest.plugin_id.to_string(),
                        "error_redacted": error.to_string()
                    }),
                )
            })?;
            health_snapshots.push(health);
            metric_samples.extend(plugin.metric_provider().samples().map_err(|error| {
                internal_error(
                    "plugin_metrics",
                    "plugin metric sample failed safety validation",
                    json!({
                        "plugin_id": manifest.plugin_id.to_string(),
                        "error_redacted": error.to_string()
                    }),
                )
            })?);
        }

        let runtime_profile = RuntimeProfile::safe_default();
        runtime_profile.validate().map_err(|error| {
            internal_error(
                "runtime_profile",
                "safe default runtime profile failed validation",
                json!({ "error_redacted": error.to_string() }),
            )
        })?;

        Ok(Self {
            component_registry,
            plugin_registry,
            capability_registry,
            contract_registry,
            dependency_registry,
            runtime_registry,
            findings: LogicalReadCollection::new(StoreKind::Finding),
            alerts: LogicalReadCollection::new(StoreKind::Alert),
            incidents: LogicalReadCollection::new(StoreKind::Incident),
            flows: LogicalReadCollection::new(StoreKind::Flow),
            dns: LogicalReadCollection::new(StoreKind::Dns),
            tls: LogicalReadCollection::new(StoreKind::Tls),
            http_metadata: LogicalReadCollection::new(StoreKind::HttpMetadata),
            response_plans: LogicalReadCollection::new(StoreKind::ResponsePlan),
            reports: LogicalReadCollection::new(StoreKind::Report),
            llm_alert_stories: LogicalReadCollection::new(StoreKind::Report),
            security_facts: LogicalReadCollection::new(StoreKind::Report),
            attack_hypotheses: LogicalReadCollection::new(StoreKind::Report),
            fusion_summaries: Vec::new(),
            endpoint_threat_candidates: Vec::new(),
            endpoint_threat_findings: Vec::new(),
            endpoint_threat_evidence: Vec::new(),
            endpoint_threat_risk_hints: Vec::new(),
            endpoint_visibility_advisories: Vec::new(),
            endpoint_threat_rejected: Vec::new(),
            endpoint_threat_graph_hints: Vec::new(),
            endpoint_threat_emitted_topics: Vec::new(),
            metadata_watch_sources: LogicalReadCollection::new(StoreKind::Report),
            metadata_sampling_batches: LogicalReadCollection::new(StoreKind::Report),
            metadata_watch_controller_status: MetadataWatchControllerStatus::empty(),
            authorized_native_capabilities: default_capability_catalog(),
            native_permission_audit_entries: Vec::new(),
            native_status_events: Vec::new(),
            native_sampler_runtime_statuses: Vec::new(),
            native_sampler_runtime_batches: Vec::new(),
            native_sampler_runtime_audit_entries: Vec::new(),
            native_scheduler_controller_state: NativeSchedulerControllerState::Disabled,
            native_sampler_schedule_statuses: Vec::new(),
            native_scheduler_audit_entries: Vec::new(),
            native_scheduler_cycles: Vec::new(),
            native_scheduler_last_tick_monotonic_millis: None,
            native_scheduler_next_due_monotonic_millis: BTreeMap::new(),
            native_scheduler_retry_attempts: BTreeMap::new(),
            native_scheduler_graceful_shutdown_requested: false,
            native_scheduler_cycle_gate_active: false,
            native_scheduler_host_status: default_native_scheduler_host_status(),
            native_scheduler_host_cycles: Vec::new(),
            native_scheduler_host_audit_entries: Vec::new(),
            export_history: ExportHistoryStore::new(),
            portable_capture_sources: Vec::new(),
            graph_views: Vec::new(),
            health_snapshots,
            metric_samples,
            runtime_profile,
            service_status: ServiceStatusView::reduced_visibility(),
            catalog_mock_only,
            catalog_production_ready,
        })
    }

    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = LogicalReadCollection::with_items(StoreKind::Finding, findings);
        self
    }

    pub fn with_alerts(mut self, alerts: Vec<Alert>) -> Self {
        self.alerts = LogicalReadCollection::with_items(StoreKind::Alert, alerts);
        self
    }

    pub fn with_incidents(mut self, incidents: Vec<Incident>) -> Self {
        self.incidents = LogicalReadCollection::with_items(StoreKind::Incident, incidents);
        self
    }

    pub fn with_flows(mut self, flows: Vec<FlowRecord>) -> Self {
        self.flows = LogicalReadCollection::with_items(StoreKind::Flow, flows);
        self
    }

    pub fn with_dns(mut self, dns: Vec<DnsObservation>) -> Self {
        self.dns = LogicalReadCollection::with_items(StoreKind::Dns, dns);
        self
    }

    pub fn with_tls(mut self, tls: Vec<TlsObservation>) -> Self {
        self.tls = LogicalReadCollection::with_items(StoreKind::Tls, tls);
        self
    }

    pub fn with_http_metadata(mut self, http_metadata: Vec<HttpMetadata>) -> Self {
        self.http_metadata =
            LogicalReadCollection::with_items(StoreKind::HttpMetadata, http_metadata);
        self
    }

    pub fn with_response_plans(mut self, response_plans: Vec<ResponsePlan>) -> Self {
        self.response_plans =
            LogicalReadCollection::with_items(StoreKind::ResponsePlan, response_plans);
        self
    }

    pub fn with_reports(mut self, reports: Vec<Report>) -> Self {
        self.reports = LogicalReadCollection::with_items(StoreKind::Report, reports);
        self
    }

    pub fn with_llm_alert_stories(mut self, stories: Vec<LlmAlertStoryRecord>) -> Self {
        self.llm_alert_stories = LogicalReadCollection::with_items(StoreKind::Report, stories);
        self
    }

    pub fn with_security_facts(mut self, facts: Vec<SecurityFact>) -> Self {
        self.security_facts = LogicalReadCollection::with_items(StoreKind::Report, facts);
        self
    }

    pub fn with_attack_hypotheses(mut self, hypotheses: Vec<AttackHypothesisRecord>) -> Self {
        self.attack_hypotheses = LogicalReadCollection::with_items(StoreKind::Report, hypotheses);
        self
    }

    pub fn with_fusion_summaries(mut self, summaries: Vec<FusionSummary>) -> Self {
        self.fusion_summaries = summaries;
        self
    }

    pub fn with_metadata_watch_sources(mut self, sources: Vec<MetadataWatchSourceStatus>) -> Self {
        self.metadata_watch_sources = LogicalReadCollection::with_items(StoreKind::Report, sources);
        self
    }

    pub fn with_metadata_sampling_batches(
        mut self,
        batches: Vec<MetadataSamplingBatchSummary>,
    ) -> Self {
        self.metadata_sampling_batches =
            LogicalReadCollection::with_items(StoreKind::Report, batches);
        self
    }

    pub fn with_metadata_watch_controller_status(
        mut self,
        status: MetadataWatchControllerStatus,
    ) -> Self {
        self.metadata_watch_controller_status = status;
        self
    }

    pub fn with_authorized_native_capabilities(
        mut self,
        capabilities: Vec<AuthorizedNativeCapabilityStatus>,
    ) -> Self {
        self.authorized_native_capabilities = capabilities;
        self
    }

    pub fn with_service_status(mut self, service_status: ServiceStatusView) -> Self {
        self.service_status = service_status;
        self
    }

    pub fn with_export_history(mut self, export_history: ExportHistoryStore) -> Self {
        self.export_history = export_history;
        self
    }

    pub fn with_portable_capture_sources(
        mut self,
        portable_capture_sources: Vec<PortableCaptureProvenance>,
    ) -> Self {
        self.portable_capture_sources = portable_capture_sources;
        self
    }

    pub fn with_export_history_from_storage(
        mut self,
        stores: &SqliteStoreFactory<'_>,
    ) -> CommandResult<Self> {
        self.export_history = ExportHistoryStorageAdapter::new()
            .load_store(stores)
            .map_err(|error| {
                internal_error(
                    "export_history_storage",
                    "failed to load export history from logical storage",
                    json!({ "error_redacted": error.to_string() }),
                )
            })?;
        Ok(self)
    }

    pub fn with_graph_views(mut self, graph_views: Vec<GraphViewModel>) -> Self {
        self.graph_views = graph_views;
        self
    }

    pub fn registered_contracts(&self) -> Vec<ContractDescriptor> {
        self.contract_registry.list().into_iter().cloned().collect()
    }
}

#[derive(Clone, Debug)]
pub struct LogicalReadCollection<T> {
    store_kind: StoreKind,
    pub(crate) items: Vec<T>,
}

impl<T> LogicalReadCollection<T> {
    pub fn new(store_kind: StoreKind) -> Self {
        Self {
            store_kind,
            items: Vec::new(),
        }
    }

    pub fn with_items(store_kind: StoreKind, items: Vec<T>) -> Self {
        Self { store_kind, items }
    }

    pub fn store_kind(&self) -> &StoreKind {
        &self.store_kind
    }
}

impl<T: Clone> LogicalReadCollection<T> {
    fn list(&self, page: PageRequest) -> CommandResult<PageResponse<T>> {
        page.validate().map_err(|error| {
            command_error(
                ErrorCode::InvalidRequest,
                "invalid page request",
                json!({ "error_redacted": error.to_string() }),
            )
        })?;
        page_items(&self.items, &page, &self.store_kind)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComponentSummary {
    pub component_id: ComponentId,
    pub component_type: ComponentType,
    pub name: String,
    pub version: String,
    pub state: ComponentState,
    pub health_status: ComponentHealthStatus,
    pub runtime_mode: sentinel_contracts::RuntimeMode,
    pub plugin_id: Option<PluginId>,
    pub capability_domain: Option<String>,
    pub capability_tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComponentDetail {
    pub definition: ComponentDefinition,
    pub instance: Option<ComponentInstance>,
    pub runtime: Option<RuntimeMetadata>,
    pub plugin_manifest: Option<PluginManifest>,
    pub health: Option<HealthSnapshot>,
    pub ui_contributions: Vec<UiContribution>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PluginCatalogView {
    pub plugins: Vec<PluginManifest>,
    pub capabilities: Vec<CapabilityManifest>,
    pub ui_contributions: Vec<UiContribution>,
    pub health: Vec<HealthSnapshot>,
    pub metrics: Vec<MetricSample>,
    pub dependency_edge_count: usize,
    pub mock_only: bool,
    pub production_ready: bool,
    pub generated_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityOverview {
    pub capability: CapabilityManifest,
    pub plugin_names: Vec<String>,
    pub plugin_count: usize,
    pub input_contract_names: Vec<String>,
    pub output_contract_names: Vec<String>,
    pub required_permission_count: usize,
    pub ui_contribution_count: usize,
    pub health_status: ObservabilityHealthStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentDetailView {
    pub incident: Incident,
    pub related_alerts: Vec<Alert>,
    pub related_findings: Vec<Finding>,
    pub graph: GraphViewModel,
    pub response_plans: Vec<ResponsePlan>,
    pub reports: Vec<Report>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphViewRequest {
    pub graph_type: GraphType,
    pub scope: GraphScope,
    pub title_redacted: Option<String>,
    pub node_limit: Option<u32>,
    pub edge_limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceStatusView {
    pub connected: bool,
    pub degraded: bool,
    pub reason: Option<String>,
    pub profile_mode: String,
    pub active_session_id: Option<SessionId>,
    pub local_core_status: ObservabilityHealthStatus,
    pub elevated_service_status: ObservabilityHealthStatus,
    pub ipc_status: ObservabilityHealthStatus,
    pub storage_status: ObservabilityHealthStatus,
    pub storage_owner_state: String,
    pub storage_owner_category: String,
    pub canonical_storage_writer: bool,
    pub desktop_cache_canonical: bool,
    pub llm_key_transferred_to_service: bool,
    pub reduced_visibility: bool,
    pub privileged_actions_available: bool,
    pub capture_available: bool,
    pub machine_local_capability_status: Option<CapabilityStatusSummary>,
    pub mutation_authorization_status: Option<MutationAuthorizationStatus>,
    pub message_redacted: String,
    pub generated_at: Timestamp,
}

impl ServiceStatusView {
    pub fn reduced_visibility() -> Self {
        Self {
            connected: false,
            degraded: true,
            reason: Some("service_unreachable".to_string()),
            profile_mode: "ephemeral".to_string(),
            active_session_id: None,
            local_core_status: ObservabilityHealthStatus::Healthy,
            elevated_service_status: ObservabilityHealthStatus::Disconnected,
            ipc_status: ObservabilityHealthStatus::Disconnected,
            storage_status: ObservabilityHealthStatus::Unknown,
            storage_owner_state: "unknown".to_string(),
            storage_owner_category: "none".to_string(),
            canonical_storage_writer: false,
            desktop_cache_canonical: false,
            llm_key_transferred_to_service: false,
            reduced_visibility: true,
            privileged_actions_available: false,
            capture_available: false,
            machine_local_capability_status: None,
            mutation_authorization_status: None,
            message_redacted:
                "Elevated Windows service is not connected; read-only local metadata is available"
                    .to_string(),
            generated_at: Timestamp::now(),
        }
    }

    pub fn connected_stub(storage_status: ObservabilityHealthStatus, message: String) -> Self {
        Self {
            connected: true,
            degraded: false,
            reason: None,
            profile_mode: "ephemeral".to_string(),
            active_session_id: None,
            local_core_status: ObservabilityHealthStatus::Healthy,
            elevated_service_status: ObservabilityHealthStatus::Healthy,
            ipc_status: ObservabilityHealthStatus::Healthy,
            storage_status,
            storage_owner_state: "desktop_local".to_string(),
            storage_owner_category: "desktop_portable".to_string(),
            canonical_storage_writer: true,
            desktop_cache_canonical: false,
            llm_key_transferred_to_service: false,
            reduced_visibility: false,
            privileged_actions_available: false,
            capture_available: false,
            machine_local_capability_status: None,
            mutation_authorization_status: None,
            message_redacted: message,
            generated_at: Timestamp::now(),
        }
    }

    pub fn service_unreachable(
        storage_status: ObservabilityHealthStatus,
        error: &ServiceIpcClientError,
    ) -> Self {
        let mut status = Self::reduced_visibility();
        status.storage_status = storage_status;
        status.reason = Some(match error.kind {
            ServiceIpcClientErrorKind::Unreachable | ServiceIpcClientErrorKind::Timeout => {
                "service_unreachable".to_string()
            }
            ServiceIpcClientErrorKind::PermissionDenied => "service_permission_denied".to_string(),
            ServiceIpcClientErrorKind::Protocol => "service_protocol_error".to_string(),
            ServiceIpcClientErrorKind::Rejected => error.code.clone(),
        });
        status.message_redacted = format!(
            "Elevated Windows service unavailable; degraded read-only mode is active ({})",
            status.reason.as_deref().unwrap_or("unknown")
        );
        status.generated_at = Timestamp::now();
        status
    }

    pub fn with_profile_mode(mut self, profile_mode: impl Into<String>) -> Self {
        self.profile_mode = profile_mode.into();
        self
    }

    pub fn with_active_session_id(mut self, session_id: Option<SessionId>) -> Self {
        self.active_session_id = session_id;
        self
    }

    pub fn with_capture_available(mut self, capture_available: bool) -> Self {
        self.capture_available = capture_available;
        self
    }
}

pub fn list_components(state: &ReadOnlyCommandState) -> CommandResult<Vec<ComponentSummary>> {
    let summaries = state
        .component_registry
        .list()
        .into_iter()
        .map(|definition| component_summary(state, definition))
        .collect::<Vec<_>>();
    Ok(summaries)
}

pub fn get_component_detail(
    state: &ReadOnlyCommandState,
    component_id: ComponentId,
) -> CommandResult<ComponentDetail> {
    let definition = state
        .component_registry
        .get(&component_id)
        .cloned()
        .ok_or_else(|| {
            not_found_error(
                "component",
                json!({ "component_id": component_id.to_string() }),
            )
        })?;
    let instance = state
        .component_registry
        .list_instances()
        .into_iter()
        .find(|instance| instance.component_id == component_id)
        .cloned();
    let runtime = state.runtime_registry.get(&component_id).cloned();
    let plugin_manifest = state
        .plugin_registry
        .plugin_id_for_component(&component_id)
        .and_then(|plugin_id| state.plugin_registry.get(plugin_id))
        .cloned();
    let health = plugin_manifest
        .as_ref()
        .and_then(|manifest| health_for_plugin(state, &manifest.plugin_id));
    let ui_contributions = plugin_manifest
        .as_ref()
        .map(|manifest| manifest.ui_contributions.clone())
        .unwrap_or_default();

    Ok(ComponentDetail {
        definition,
        instance,
        runtime,
        plugin_manifest,
        health,
        ui_contributions,
    })
}

pub fn get_plugin_catalog(state: &ReadOnlyCommandState) -> CommandResult<PluginCatalogView> {
    let plugins = state
        .plugin_registry
        .list()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let capabilities = state
        .capability_registry
        .list()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let ui_contributions = plugins
        .iter()
        .flat_map(|plugin| plugin.ui_contributions.iter().cloned())
        .collect::<Vec<_>>();

    Ok(PluginCatalogView {
        plugins,
        capabilities,
        ui_contributions,
        health: state.health_snapshots.clone(),
        metrics: state.metric_samples.clone(),
        dependency_edge_count: state
            .dependency_registry
            .plugin_entries()
            .iter()
            .map(|(_, dependencies)| dependencies.len())
            .sum(),
        mock_only: state.catalog_mock_only,
        production_ready: state.catalog_production_ready,
        generated_at: Timestamp::now(),
    })
}

pub fn get_plugin_manifest(
    state: &ReadOnlyCommandState,
    plugin_id: PluginId,
) -> CommandResult<PluginManifest> {
    state
        .plugin_registry
        .get(&plugin_id)
        .cloned()
        .ok_or_else(|| not_found_error("plugin", json!({ "plugin_id": plugin_id.to_string() })))
}

pub fn get_capability_overview(
    state: &ReadOnlyCommandState,
) -> CommandResult<Vec<CapabilityOverview>> {
    let overviews = state
        .capability_registry
        .list()
        .into_iter()
        .map(|capability| {
            let plugins = capability
                .plugin_ids
                .iter()
                .filter_map(|plugin_id| state.plugin_registry.get(plugin_id))
                .collect::<Vec<_>>();
            let plugin_names = plugins
                .iter()
                .map(|plugin| plugin.plugin_name.clone())
                .collect::<Vec<_>>();
            let health_status = aggregate_plugin_health(
                state,
                capability.plugin_ids.iter().collect::<Vec<_>>().as_slice(),
            );

            CapabilityOverview {
                capability: capability.clone(),
                plugin_names,
                plugin_count: plugins.len(),
                input_contract_names: contract_names(&capability.input_contracts),
                output_contract_names: contract_names(&capability.output_contracts),
                required_permission_count: capability.required_permissions.len(),
                ui_contribution_count: capability.ui_contributions.len(),
                health_status,
            }
        })
        .collect();
    Ok(overviews)
}

pub fn search_components(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<ComponentSummary>> {
    query_components(state, request)
}

pub fn search_plugins(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<PluginManifest>> {
    query_plugins(state, request)
}

pub fn search_capabilities(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<CapabilityOverview>> {
    query_capabilities(state, request)
}

pub fn search_findings(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<Finding>> {
    query_findings(state, request)
}

pub fn search_alerts(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<Alert>> {
    query_alerts(state, request)
}

pub fn search_incidents(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<Incident>> {
    query_incidents(state, request)
}

pub fn get_incident_detail(
    state: &ReadOnlyCommandState,
    incident_id: IncidentId,
) -> CommandResult<IncidentDetailView> {
    let incident = state
        .incidents
        .items
        .iter()
        .find(|incident| incident.id() == &incident_id)
        .cloned()
        .ok_or_else(|| {
            not_found_error(
                "incident",
                json!({ "incident_id": incident_id.to_string() }),
            )
        })?;
    let related_alerts = state
        .alerts
        .items
        .iter()
        .filter(|alert| incident.alert_refs().contains(alert.id()))
        .cloned()
        .collect::<Vec<_>>();
    let related_finding_ids = related_alerts
        .iter()
        .flat_map(|alert| alert.finding_refs().iter().cloned())
        .collect::<Vec<_>>();
    let related_findings = state
        .findings
        .items
        .iter()
        .filter(|finding| related_finding_ids.contains(finding.id()))
        .cloned()
        .collect::<Vec<_>>();
    let graph = build_graph_view(
        &GraphViewRequest {
            graph_type: GraphType::IncidentGraph,
            scope: GraphScope::Incident(incident_id.clone()),
            title_redacted: Some("Incident graph".to_string()),
            node_limit: None,
            edge_limit: None,
        },
        state,
    )?;
    let response_plans = state
        .response_plans
        .items
        .iter()
        .filter(|plan| matches!(&plan.source, sentinel_contracts::ResponsePlanSource::Incident(id) if id == &incident_id))
        .cloned()
        .collect::<Vec<_>>();
    let reports = state
        .reports
        .items
        .iter()
        .filter(|report| report.incident_refs.contains(&incident_id))
        .cloned()
        .collect::<Vec<_>>();

    Ok(IncidentDetailView {
        incident,
        related_alerts,
        related_findings,
        graph,
        response_plans,
        reports,
    })
}

pub fn search_flows(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<FlowRecord>> {
    query_flows(state, request)
}

pub fn search_dns(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<DnsObservation>> {
    query_dns(state, request)
}

pub fn search_tls(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<TlsObservation>> {
    query_tls(state, request)
}

pub fn get_graph_view(
    state: &ReadOnlyCommandState,
    request: GraphViewRequest,
) -> CommandResult<GraphViewModel> {
    build_graph_view(&request, state)
}

pub fn try_get_graph_view_from_storage(
    stores: &SqliteStoreFactory<'_>,
    request: GraphViewRequest,
) -> CommandResult<Option<GraphViewModel>> {
    let mut analytics_request =
        GraphAnalyticsRequest::new(request.graph_type.clone(), request.scope.clone());
    analytics_request.node_limit = request.node_limit;
    analytics_request.edge_limit = request.edge_limit;

    let graph_store = stores.graph_store();
    match GraphAnalyticsService::new().analyze_store(&graph_store, analytics_request) {
        Ok(output) => {
            let mut view = output.view_model;
            apply_graph_view_request_title(&mut view, &request)?;
            Ok(Some(view))
        }
        Err(GraphAnalyticsError::EmptyCanonicalGraph) => Ok(None),
        Err(error) => Err(command_error(
            ErrorCode::StorageUnavailable,
            "failed to read graph view from canonical graph store",
            json!({ "error_redacted": error.to_string() }),
        )),
    }
}

pub fn list_active_responses(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<ResponsePlan>> {
    state.response_plans.list(page)
}

pub fn search_response_plans(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<ResponsePlan>> {
    query_response_plans(state, request)
}

pub fn list_reports(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<Report>> {
    state.reports.list(page)
}

pub fn search_reports(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<Report>> {
    query_reports(state, request)
}

pub fn get_report(state: &ReadOnlyCommandState, report_id: ReportId) -> CommandResult<Report> {
    state
        .reports
        .items
        .iter()
        .find(|report| report.report_id == report_id)
        .cloned()
        .ok_or_else(|| not_found_error("report", json!({ "report_id": report_id.to_string() })))
}

pub fn list_llm_alert_stories(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<LlmAlertStoryRecord>> {
    state.llm_alert_stories.list(page)
}

pub fn get_llm_alert_story(
    state: &ReadOnlyCommandState,
    story_id: LlmAlertStoryId,
) -> CommandResult<LlmAlertStoryRecord> {
    state
        .llm_alert_stories
        .items
        .iter()
        .find(|story| story.story_id == story_id)
        .cloned()
        .ok_or_else(|| {
            not_found_error(
                "llm_alert_story",
                json!({ "story_id": story_id.to_string() }),
            )
        })
}

const ATTACK_COVERAGE_VERSION: &str = "enterprise-verified-2026-06-12";

pub fn get_attack_coverage_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<AttackCoverageSummary> {
    build_attack_coverage_summary(state)
}

pub fn get_fusion_summary(state: &ReadOnlyCommandState) -> CommandResult<FusionSummary> {
    if let Some(summary) = state.fusion_summaries.last() {
        let mut summary = summary.clone();
        append_native_visibility_degradation(state, &mut summary.degraded_visibility_context)?;
        summary.validate().map_err(|error| {
            internal_error(
                "fusion_summary",
                "fusion summary failed native visibility safety validation",
                json!({ "error_redacted": error.to_string() }),
            )
        })?;
        return Ok(summary);
    }

    let mut summary = FusionSummary {
        generated_at: Timestamp::now(),
        sampler_health: layered_sampler_catalog().map_err(|error| {
            internal_error(
                "fusion_summary",
                "failed to build bounded fusion sampler summary",
                json!({ "error_redacted": error.to_string() }),
            )
        })?,
        fact_count: 0,
        hypothesis_count: 0,
        facts: Vec::new(),
        hypotheses: Vec::new(),
        top_correlated_layers: Vec::new(),
        top_hypothesis_categories: Vec::new(),
        degraded_visibility_context: vec![
            "metadata_only_visibility".to_string(),
            "no_process_attribution".to_string(),
            "no_packet_visibility".to_string(),
            "no_provider_control_plane".to_string(),
        ],
        fact_refs: Vec::new(),
        hypothesis_refs: Vec::new(),
        evidence_refs: Vec::new(),
        finding_refs: Vec::new(),
        graph_hint_refs: Vec::new(),
        quality: QualityBreakdown::metadata_only(),
        privacy_class: PrivacyClass::Internal,
        automatic_llm_calls: false,
    };
    append_native_visibility_degradation(state, &mut summary.degraded_visibility_context)?;
    summary.validate().map_err(|error| {
        internal_error(
            "fusion_summary",
            "fusion summary failed safety validation",
            json!({ "error_redacted": error.to_string() }),
        )
    })?;
    Ok(summary)
}

pub fn get_endpoint_threat_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<EndpointThreatAnalysisSummary> {
    build_endpoint_threat_analysis_summary(state)
}

pub fn get_provider_controller_status(
    _state: &ReadOnlyCommandState,
) -> CommandResult<NetworkProviderControllerStatus> {
    inactive_provider_controller_status()
}

pub fn list_network_provider_status(
    state: &ReadOnlyCommandState,
) -> CommandResult<Vec<NetworkProviderStatus>> {
    Ok(get_provider_controller_status(state)?.providers)
}

pub fn get_network_provider_status(
    state: &ReadOnlyCommandState,
    provider_id: String,
) -> CommandResult<NetworkProviderStatus> {
    let providers = list_network_provider_status(state)?;
    providers
        .into_iter()
        .find(|provider| {
            provider.provider_id == provider_id || provider.provider_kind.as_str() == provider_id
        })
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::InvalidRequest,
                "network provider status was not found",
            )
            .with_severity(ErrorSeverity::Warning)
            .with_trace_id(TraceId::new_v4())
            .with_redacted_details(json!({
                "reason": "provider_status_not_found",
                "provider_ref": safe_provider_ref(&provider_id)
            }))
        })
}

pub fn get_network_visibility_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<NetworkVisibilitySummary> {
    Ok(get_provider_controller_status(state)?.visibility_summary)
}

pub fn get_network_fallback_plan(
    state: &ReadOnlyCommandState,
) -> CommandResult<NetworkFallbackPlan> {
    Ok(get_provider_controller_status(state)?.fallback_plan)
}

fn inactive_provider_controller_status() -> CommandResult<NetworkProviderControllerStatus> {
    NetworkProviderControllerStatus::inactive_servicehost("provider-controller-read-model", 1)
        .map_err(|error| {
            internal_error(
                "provider_controller",
                "provider controller read model failed validation",
                json!({ "error_redacted": error.to_string() }),
            )
        })
}

fn safe_provider_ref(provider_id: &str) -> String {
    match provider_id {
        "portable_metadata" | "network_provider_portable_metadata" => {
            NetworkProviderKind::PortableMetadata.as_str().to_string()
        }
        "ip_helper" | "network_provider_ip_helper" => {
            NetworkProviderKind::IpHelper.as_str().to_string()
        }
        "etw_network" | "network_provider_etw_network" => {
            NetworkProviderKind::EtwNetwork.as_str().to_string()
        }
        "windows_dns" | "network_provider_windows_dns" => {
            NetworkProviderKind::WindowsDns.as_str().to_string()
        }
        "npcap_packet" | "network_provider_npcap_packet" => {
            NetworkProviderKind::NpcapPacket.as_str().to_string()
        }
        "capture_broker" | "network_provider_capture_broker" => {
            NetworkProviderKind::CaptureBroker.as_str().to_string()
        }
        _ => "unknown_provider_ref".to_string(),
    }
}

fn append_native_visibility_degradation(
    state: &ReadOnlyCommandState,
    degraded_visibility_context: &mut Vec<String>,
) -> CommandResult<()> {
    let permission = native_permission_status_summary(&state.authorized_native_capabilities)?;
    let marker = if permission.granted_inactive_count > 0 {
        "authorized_native_sampler_inactive"
    } else {
        "authorized_native_permission_missing"
    };
    for value in [marker, "native_endpoint_visibility_unavailable"] {
        if !degraded_visibility_context
            .iter()
            .any(|existing| existing == value)
        {
            degraded_visibility_context.push(value.to_string());
        }
    }
    if let Ok(missing_endpoint) = build_missing_endpoint_visibility_summary(state) {
        for value in missing_endpoint
            .missing_visibility_flags
            .into_iter()
            .chain(missing_endpoint.degraded_reasons)
        {
            if !degraded_visibility_context
                .iter()
                .any(|existing| existing == &value)
            {
                degraded_visibility_context.push(value);
            }
        }
    }
    degraded_visibility_context.truncate(32);
    Ok(())
}

pub fn list_authorized_native_capabilities(
    state: &ReadOnlyCommandState,
) -> CommandResult<Vec<AuthorizedNativeCapabilityStatus>> {
    for capability in &state.authorized_native_capabilities {
        capability.validate().map_err(|error| {
            internal_error(
                "authorized_native_capability",
                "authorized native capability failed safety validation",
                json!({ "error_redacted": error.to_string() }),
            )
        })?;
    }
    Ok(state.authorized_native_capabilities.clone())
}

pub fn get_authorized_native_capability(
    state: &ReadOnlyCommandState,
    capability_id: String,
) -> CommandResult<AuthorizedNativeCapabilityStatus> {
    state
        .authorized_native_capabilities
        .iter()
        .find(|capability| capability.capability_id == capability_id)
        .cloned()
        .ok_or_else(|| {
            not_found_error(
                "authorized_native_capability",
                json!({ "capability_id": capability_id }),
            )
        })
}

pub fn get_native_permission_status_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativePermissionStatusSummary> {
    native_permission_status_summary(&state.authorized_native_capabilities)
}

pub fn get_native_visibility_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativeVisibilitySummary> {
    native_visibility_summary(&state.authorized_native_capabilities)
}

pub fn get_native_permission_audit_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativePermissionAuditSummary> {
    native_permission_audit_summary(&state.native_permission_audit_entries)
}

pub fn list_native_sampler_contracts(
    state: &ReadOnlyCommandState,
) -> CommandResult<Vec<NativeSamplerContract>> {
    build_native_sampler_contracts(state)
}

pub fn get_native_sampler_contract(
    state: &ReadOnlyCommandState,
    sampler_id: String,
) -> CommandResult<NativeSamplerContract> {
    build_native_sampler_contract(state, &sampler_id)
}

pub fn get_native_sampler_readiness_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativeSamplerReadinessSummary> {
    build_native_sampler_readiness_summary(state)
}

pub fn get_native_sampler_readiness_detail(
    state: &ReadOnlyCommandState,
    sampler_id: String,
) -> CommandResult<NativeSamplerReadinessDetail> {
    build_native_sampler_readiness_detail(state, &sampler_id)
}

pub fn get_native_sampler_authorization_review(
    state: &ReadOnlyCommandState,
    sampler_id: String,
) -> CommandResult<NativeSamplerAuthorizationReview> {
    build_native_sampler_authorization_review(state, &sampler_id)
}

pub fn get_future_security_fact_mapping_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<FutureSecurityFactMappingSummary> {
    build_future_security_fact_mapping_summary(state)
}

pub fn get_native_sampler_blocked_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativeSamplerBlockedSummary> {
    build_native_sampler_blocked_summary(state)
}

pub fn get_missing_endpoint_visibility_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<MissingEndpointVisibilitySummary> {
    build_missing_endpoint_visibility_summary(state)
}

pub fn get_edr_readiness_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<EdrReadinessSummary> {
    build_edr_readiness_summary(state)
}

pub fn get_native_sampler_runtime_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativeSamplerRuntimeSummary> {
    NativeSamplerRuntime::summary_from_read_state(state)
}

pub fn get_native_sampler_runtime_status(
    state: &ReadOnlyCommandState,
    sampler_id: String,
) -> CommandResult<NativeSamplerRuntimeStatus> {
    NativeSamplerRuntime::status_from_read_state(state, &sampler_id)
}

pub fn get_latest_native_sampler_runtime_batch(
    state: &ReadOnlyCommandState,
    sampler_id: String,
) -> CommandResult<Option<NativeSamplerRuntimeBatch>> {
    NativeSamplerRuntime::latest_batch_from_read_state(state, &sampler_id)
}

pub fn get_native_scheduler_status(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativeSchedulerStatus> {
    Ok(NativeSchedulerController::summary_from_read_state(state)?.status)
}

pub fn list_native_sampler_schedule_statuses(
    state: &ReadOnlyCommandState,
) -> CommandResult<Vec<NativeSamplerScheduleStatus>> {
    Ok(NativeSchedulerController::summary_from_read_state(state)?.schedules)
}

pub fn get_native_sampler_schedule_status(
    state: &ReadOnlyCommandState,
    sampler_id: String,
) -> CommandResult<NativeSamplerScheduleStatus> {
    NativeSchedulerController::schedule_status_from_read_state(state, &sampler_id)
}

pub fn get_native_scheduler_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativeSchedulerSummary> {
    NativeSchedulerController::summary_from_read_state(state)
}

pub fn get_native_scheduler_operational_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativeSchedulerOperationalSummary> {
    NativeSchedulerController::operational_summary_from_read_state(state)
}

pub fn list_native_scheduler_cycles(
    state: &ReadOnlyCommandState,
) -> CommandResult<Vec<NativeSchedulerCycleSummary>> {
    Ok(state.native_scheduler_cycles.clone())
}

pub fn get_latest_native_scheduler_cycle(
    state: &ReadOnlyCommandState,
) -> CommandResult<Option<NativeSchedulerCycleSummary>> {
    Ok(state.native_scheduler_cycles.last().cloned())
}

pub fn get_native_scheduler_host_status(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativeSchedulerHostStatus> {
    NativeSchedulerHostController::status_from_read_state(state)
}

pub fn get_native_scheduler_host_health(
    state: &ReadOnlyCommandState,
) -> CommandResult<NativeSchedulerHostHealthSummary> {
    NativeSchedulerHostController::health_from_read_state(state)
}

pub fn list_native_scheduler_host_cycles(
    state: &ReadOnlyCommandState,
) -> CommandResult<Vec<NativeSchedulerHostCycleSummary>> {
    Ok(state.native_scheduler_host_cycles.clone())
}

pub fn get_latest_native_scheduler_host_cycle(
    state: &ReadOnlyCommandState,
) -> CommandResult<Option<NativeSchedulerHostCycleSummary>> {
    Ok(state.native_scheduler_host_cycles.last().cloned())
}

pub fn list_security_facts(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<SecurityFact>> {
    state.security_facts.list(page)
}

pub fn list_attack_hypotheses(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<AttackHypothesisRecord>> {
    state.attack_hypotheses.list(page)
}

pub fn get_attack_hypothesis(
    state: &ReadOnlyCommandState,
    hypothesis_id: AttackHypothesisId,
) -> CommandResult<AttackHypothesisRecord> {
    state
        .attack_hypotheses
        .items
        .iter()
        .find(|hypothesis| hypothesis.hypothesis_record_id == hypothesis_id)
        .cloned()
        .ok_or_else(|| {
            not_found_error(
                "attack_hypothesis",
                json!({ "hypothesis_id": hypothesis_id.to_string() }),
            )
        })
}

pub fn get_durable_baseline_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<DurableBaselineSummary> {
    build_durable_baseline_summary(state)
}

pub fn get_evidence_quality_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<EvidenceQualitySummary> {
    build_evidence_quality_summary(state)
}

pub fn list_evidence_quality_records(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<EvidenceQualityRecord>> {
    let summary = build_evidence_quality_summary(state)?;
    page_items(&summary.records, &page, &StoreKind::Report)
}

pub fn get_evidence_quality_record(
    state: &ReadOnlyCommandState,
    evidence_quality_id: EvidenceQualityId,
) -> CommandResult<EvidenceQualityRecord> {
    let summary = build_evidence_quality_summary(state)?;
    summary
        .records
        .into_iter()
        .find(|record| record.evidence_quality_id == evidence_quality_id)
        .ok_or_else(|| {
            not_found_error(
                "evidence_quality_record",
                json!({ "evidence_quality_id": evidence_quality_id.to_string() }),
            )
        })
}

pub fn get_investigation_drill_down_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<InvestigationDrillDownSummary> {
    build_investigation_drill_down_summary(state)
}

pub fn resolve_navigation_reference(
    state: &ReadOnlyCommandState,
    request: NavigationResolveRequest,
) -> CommandResult<NavigationResolution> {
    resolve_bounded_reference(state, request)
}

pub fn get_hypothesis_explanation_detail(
    state: &ReadOnlyCommandState,
    hypothesis_id: AttackHypothesisId,
) -> CommandResult<HypothesisExplanationDetail> {
    build_investigation_drill_down_summary(state)?
        .hypotheses
        .into_iter()
        .find(|detail| detail.hypothesis_id == hypothesis_id)
        .ok_or_else(|| {
            not_found_error(
                "hypothesis_explanation_detail",
                json!({ "hypothesis_id": hypothesis_id.to_string() }),
            )
        })
}

pub fn get_baseline_drill_down_detail(
    state: &ReadOnlyCommandState,
    baseline_id: BaselineRecordId,
) -> CommandResult<BaselineDrillDownDetail> {
    build_investigation_drill_down_summary(state)?
        .baselines
        .into_iter()
        .find(|detail| detail.baseline_id == baseline_id)
        .ok_or_else(|| {
            not_found_error(
                "baseline_drill_down_detail",
                json!({ "baseline_id": baseline_id.to_string() }),
            )
        })
}

pub fn get_incident_group_investigation_detail(
    state: &ReadOnlyCommandState,
    group_id: IncidentLinkedGroupId,
) -> CommandResult<IncidentGroupInvestigationDetail> {
    build_investigation_drill_down_summary(state)?
        .incident_groups
        .into_iter()
        .find(|detail| detail.group_id == group_id)
        .ok_or_else(|| {
            not_found_error(
                "incident_group_investigation_detail",
                json!({ "group_id": group_id.to_string() }),
            )
        })
}

pub fn get_timeline_drill_down_detail(
    state: &ReadOnlyCommandState,
    timeline_entry_id: IncidentTimelineEntryId,
) -> CommandResult<TimelineDrillDownDetail> {
    build_investigation_drill_down_summary(state)?
        .timeline
        .into_iter()
        .find(|detail| detail.timeline_entry_id == timeline_entry_id)
        .ok_or_else(|| {
            not_found_error(
                "timeline_drill_down_detail",
                json!({ "timeline_entry_id": timeline_entry_id.to_string() }),
            )
        })
}

pub fn get_source_reliability_explanation(
    state: &ReadOnlyCommandState,
    source_id: MetadataWatchSourceId,
) -> CommandResult<SourceReliabilityExplanation> {
    build_investigation_drill_down_summary(state)?
        .source_reliability
        .into_iter()
        .find(|detail| detail.source_id == source_id)
        .ok_or_else(|| {
            not_found_error(
                "source_reliability_explanation",
                json!({ "source_id": source_id.to_string() }),
            )
        })
}

pub fn list_baseline_records(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<BaselineRecord>> {
    let summary = build_durable_baseline_summary(state)?;
    page_items(&summary.records, &page, &StoreKind::Report)
}

pub fn get_baseline_record(
    state: &ReadOnlyCommandState,
    baseline_id: BaselineRecordId,
) -> CommandResult<BaselineRecord> {
    let summary = build_durable_baseline_summary(state)?;
    summary
        .records
        .into_iter()
        .find(|record| record.baseline_id == baseline_id)
        .ok_or_else(|| {
            not_found_error(
                "baseline_record",
                json!({ "baseline_id": baseline_id.to_string() }),
            )
        })
}

pub fn list_baseline_indicators(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<BaselineIndicator>> {
    let summary = build_durable_baseline_summary(state)?;
    page_items(&summary.indicators, &page, &StoreKind::Report)
}

pub fn get_baseline_indicator(
    state: &ReadOnlyCommandState,
    indicator_id: BaselineIndicatorId,
) -> CommandResult<BaselineIndicator> {
    let summary = build_durable_baseline_summary(state)?;
    summary
        .indicators
        .into_iter()
        .find(|indicator| indicator.indicator_id == indicator_id)
        .ok_or_else(|| {
            not_found_error(
                "baseline_indicator",
                json!({ "indicator_id": indicator_id.to_string() }),
            )
        })
}

pub fn list_incident_linked_hypothesis_groups(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<IncidentLinkedHypothesisGroup>> {
    let summary = build_durable_baseline_summary(state)?;
    page_items(&summary.incident_groups, &page, &StoreKind::Report)
}

pub fn get_incident_linked_hypothesis_group(
    state: &ReadOnlyCommandState,
    group_id: IncidentLinkedGroupId,
) -> CommandResult<IncidentLinkedHypothesisGroup> {
    let summary = build_durable_baseline_summary(state)?;
    summary
        .incident_groups
        .into_iter()
        .find(|group| group.group_id == group_id)
        .ok_or_else(|| {
            not_found_error(
                "incident_linked_hypothesis_group",
                json!({ "group_id": group_id.to_string() }),
            )
        })
}

pub fn list_incident_timeline_entries(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<IncidentTimelineEntry>> {
    let summary = build_durable_baseline_summary(state)?;
    page_items(&summary.incident_timeline, &page, &StoreKind::Report)
}

pub fn get_incident_timeline_entry(
    state: &ReadOnlyCommandState,
    timeline_entry_id: IncidentTimelineEntryId,
) -> CommandResult<IncidentTimelineEntry> {
    let summary = build_durable_baseline_summary(state)?;
    summary
        .incident_timeline
        .into_iter()
        .find(|entry| entry.timeline_entry_id == timeline_entry_id)
        .ok_or_else(|| {
            not_found_error(
                "incident_timeline_entry",
                json!({ "timeline_entry_id": timeline_entry_id.to_string() }),
            )
        })
}

pub fn list_source_reliability_summaries(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<SourceReliabilitySummary>> {
    let summary = build_durable_baseline_summary(state)?;
    page_items(&summary.source_reliability, &page, &StoreKind::Report)
}

pub fn get_metadata_watch_controller_status(
    state: &ReadOnlyCommandState,
) -> CommandResult<MetadataWatchControllerStatus> {
    state
        .metadata_watch_controller_status
        .validate()
        .map_err(|error| {
            internal_error(
                "metadata_watch_controller_status",
                "metadata watch controller status failed safety validation",
                json!({ "error_redacted": error.to_string() }),
            )
        })?;
    Ok(state.metadata_watch_controller_status.clone())
}

pub fn list_metadata_watch_sources(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<MetadataWatchSourceStatus>> {
    state.metadata_watch_sources.list(page)
}

pub fn get_metadata_watch_source(
    state: &ReadOnlyCommandState,
    source_id: MetadataWatchSourceId,
) -> CommandResult<MetadataWatchSourceStatus> {
    state
        .metadata_watch_sources
        .items
        .iter()
        .find(|source| source.source_id == source_id)
        .cloned()
        .ok_or_else(|| {
            not_found_error(
                "metadata_watch_source",
                json!({ "source_id": source_id.to_string() }),
            )
        })
}

pub fn list_metadata_sampling_batches(
    state: &ReadOnlyCommandState,
    page: PageRequest,
) -> CommandResult<PageResponse<MetadataSamplingBatchSummary>> {
    state.metadata_sampling_batches.list(page)
}

pub fn get_metadata_sampling_batch(
    state: &ReadOnlyCommandState,
    batch_id: MetadataSamplingBatchId,
) -> CommandResult<MetadataSamplingBatchSummary> {
    state
        .metadata_sampling_batches
        .items
        .iter()
        .find(|batch| batch.batch_id == batch_id)
        .cloned()
        .ok_or_else(|| {
            not_found_error(
                "metadata_sampling_batch",
                json!({ "batch_id": batch_id.to_string() }),
            )
        })
}

pub(crate) fn build_attack_coverage_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<AttackCoverageSummary> {
    let mut accumulators = BTreeMap::<String, AttackCoverageAccumulator>::new();
    for entry in attack_coverage_catalog_entries() {
        let key = attack_coverage_key(entry.tactic_id, entry.technique_id, entry.package_category);
        accumulators
            .entry(key)
            .and_modify(|accumulator| accumulator.merge_catalog(&entry))
            .or_insert_with(|| AttackCoverageAccumulator::from_catalog(&entry));
    }

    let risk_refs_by_finding = risk_refs_by_finding(state);
    for finding in &state.findings.items {
        for mapping in finding.attack_mappings() {
            if mapping.taxonomy != AttackTaxonomy::MitreAttackEnterprise {
                continue;
            }
            let Some(tactic_id) = mapping.tactic_id.as_deref() else {
                continue;
            };
            let Some(technique_id) = mapping
                .subtechnique_id
                .as_deref()
                .or(mapping.technique_id.as_deref())
            else {
                continue;
            };
            let package_category = attack_package_category(finding.finding_type());
            let key = attack_coverage_key(tactic_id, technique_id, package_category);
            let risk_refs = risk_refs_by_finding
                .get(&finding.id().to_string())
                .cloned()
                .unwrap_or_default();
            accumulators
                .entry(key)
                .and_modify(|accumulator| {
                    accumulator.merge_mapping(finding, mapping, package_category, &risk_refs);
                })
                .or_insert_with(|| {
                    AttackCoverageAccumulator::from_mapping(
                        finding,
                        mapping,
                        tactic_id,
                        technique_id,
                        package_category,
                        &risk_refs,
                    )
                });
        }
    }

    let mut rows = accumulators
        .into_values()
        .map(AttackCoverageAccumulator::into_row)
        .collect::<CommandResult<Vec<_>>>()?;
    rows.sort_by(|left, right| {
        left.tactic_id
            .cmp(&right.tactic_id)
            .then(left.technique_id.cmp(&right.technique_id))
            .then(left.package_category.cmp(&right.package_category))
    });
    rows.truncate(sentinel_contracts::MAX_ATTACK_COVERAGE_ROWS);

    let mut summary = AttackCoverageSummary::new(ATTACK_COVERAGE_VERSION).map_err(|error| {
        internal_error(
            "attack_coverage",
            "failed to create ATT&CK coverage summary",
            json!({ "error_redacted": error.to_string() }),
        )
    })?;
    summary.technique_rows = rows;
    summary.top_tactics = attack_count_summary(
        summary
            .technique_rows
            .iter()
            .map(|row| row.tactic_id.clone()),
    )?;
    summary.package_coverage = attack_count_summary(
        summary
            .technique_rows
            .iter()
            .map(|row| row.package_category.clone()),
    )?;
    summary.state_counts = attack_count_summary(
        summary
            .technique_rows
            .iter()
            .flat_map(|row| row.states.iter().map(attack_state_label)),
    )?;
    summary.finding_refs = bounded_unique_refs_by_string(
        summary
            .technique_rows
            .iter()
            .flat_map(|row| row.finding_refs.iter().cloned())
            .collect(),
    );
    summary.evidence_refs = bounded_unique_refs_by_string(
        summary
            .technique_rows
            .iter()
            .flat_map(|row| row.evidence_refs.iter().cloned())
            .collect(),
    );
    summary.risk_refs = bounded_unique_refs_by_string(
        summary
            .technique_rows
            .iter()
            .flat_map(|row| row.risk_refs.iter().cloned())
            .collect(),
    );
    summary.degraded_reason = Some("metadata_only_visibility".to_string());
    summary.validate().map_err(|error| {
        internal_error(
            "attack_coverage",
            "ATT&CK coverage summary failed safety validation",
            json!({ "error_redacted": error.to_string() }),
        )
    })?;
    Ok(summary)
}

pub fn list_export_history(
    state: &ReadOnlyCommandState,
    query: ReportExportHistoryQuery,
) -> CommandResult<PageResponse<ExportHistoryRecord>> {
    state.export_history.query(query).map_err(|error| {
        command_error(
            ErrorCode::InvalidRequest,
            "invalid export history query",
            json!({ "error_redacted": error.to_string() }),
        )
    })
}

pub fn search_export_history(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<ExportHistoryRecord>> {
    state
        .export_history
        .query_request(request)
        .map_err(|error| {
            command_error(
                ErrorCode::InvalidRequest,
                "invalid export history query",
                json!({ "error_redacted": error.to_string() }),
            )
        })
}

pub fn get_export_history_record(
    state: &ReadOnlyCommandState,
    export_result_id: ExportResultId,
) -> CommandResult<ExportHistoryRecord> {
    state
        .export_history
        .get(&export_result_id)
        .cloned()
        .ok_or_else(|| {
            not_found_error(
                "export_history_record",
                json!({ "export_result_id": export_result_id.to_string() }),
            )
        })
}

pub fn list_export_policy_violations(
    state: &ReadOnlyCommandState,
) -> CommandResult<Vec<ExportPolicyViolation>> {
    Ok(state.export_history.violations().to_vec())
}

pub fn get_runtime_profile(state: &ReadOnlyCommandState) -> CommandResult<RuntimeProfile> {
    Ok(state.runtime_profile.clone())
}

pub fn search_runtime_profiles(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<RuntimeProfile>> {
    query_runtime_profiles(state, request)
}

pub fn search_service_status(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<ServiceStatusView>> {
    query_service_status(state, request)
}

pub fn get_service_status(state: &ReadOnlyCommandState) -> CommandResult<ServiceStatusView> {
    let storage_status = state.service_status.storage_status.clone();
    let profile_mode = state.service_status.profile_mode.clone();
    let active_session_id = state.service_status.active_session_id.clone();
    let capture_available = state.service_status.capture_available;
    let machine_local_capability_status =
        state.service_status.machine_local_capability_status.clone();
    match ElevatedServiceIpcClient::default().status() {
        Ok(status) if status.service_status == "running" => {
            let mutation_authorization_status = status.mutation_authorization_status.clone();
            let mut status = ServiceStatusView::connected_stub(
                storage_status,
                "Elevated service IPC connected in read-only adapter mode".to_string(),
            )
            .with_profile_mode(profile_mode)
            .with_active_session_id(active_session_id)
            .with_capture_available(capture_available);
            status.machine_local_capability_status = machine_local_capability_status;
            status.mutation_authorization_status = mutation_authorization_status;
            Ok(status)
        }
        Ok(status) => {
            let mut degraded = ServiceStatusView::connected_stub(
                storage_status,
                format!(
                    "Elevated service IPC connected but service status is {}",
                    status.service_status
                ),
            );
            degraded.degraded = true;
            degraded.reason = Some("service_degraded".to_string());
            degraded.elevated_service_status = ObservabilityHealthStatus::Degraded;
            degraded.profile_mode = profile_mode;
            degraded.active_session_id = active_session_id;
            degraded.capture_available = capture_available;
            degraded.machine_local_capability_status = machine_local_capability_status;
            degraded.mutation_authorization_status = status.mutation_authorization_status;
            Ok(degraded)
        }
        Err(error) => {
            let mut status = ServiceStatusView::service_unreachable(storage_status, &error)
                .with_profile_mode(profile_mode)
                .with_active_session_id(active_session_id)
                .with_capture_available(capture_available);
            status.machine_local_capability_status = machine_local_capability_status;
            Ok(status)
        }
    }
}

fn component_definition_for_plugin(plugin: &MockPlugin) -> CommandResult<ComponentDefinition> {
    let manifest = plugin.manifest();
    let mut definition = ComponentDefinition::new(
        ComponentType::Plugin,
        manifest.plugin_name.clone(),
        manifest.version.clone(),
        manifest.runtime_mode.clone(),
    )
    .map_err(|error| {
        internal_error(
            "component_definition",
            "failed to build component definition from plugin manifest",
            json!({
                "plugin_id": manifest.plugin_id.to_string(),
                "error_redacted": error.to_string()
            }),
        )
    })?;

    definition.metadata.description = Some(manifest.description.clone());
    definition.metadata.capability_tags = manifest.capability_tags.clone();
    definition.metadata.maturity_level = Some(manifest.maturity_level.clone());
    definition.metadata.privacy_class = PrivacyClass::Internal;

    for contract in manifest
        .input_contracts
        .iter()
        .chain(manifest.output_contracts.iter())
    {
        definition.add_contract_binding(ContractBinding {
            contract: contract.clone(),
            required: contract.required,
            compatibility_reason: Some("declared by plugin manifest".to_string()),
        });
    }

    for dependency in &manifest.dependencies {
        definition.add_dependency_binding(DependencyBinding {
            dependency_type: dependency.dependency_type.clone(),
            dependency_component_id: None,
            dependency_plugin_id: dependency.plugin_id.clone(),
            dependency_capability_id: dependency.capability_id.clone(),
            dependency_name: dependency.name.clone(),
            version_requirement: dependency.version_requirement.clone(),
            required: is_required_dependency(&dependency.dependency_type),
            resolved: true,
            resolution_reason: Some("resolved from built-in static plugin catalog".to_string()),
            incompatibility_reason: None,
        });
    }

    for permission in &manifest.required_permissions {
        definition.add_permission_binding(PermissionBinding {
            permission: permission.clone(),
            required: permission.required,
            granted: true,
            grant_reason: Some("metadata-only read command surface".to_string()),
            denial_reason: None,
        });
    }

    for metric in &manifest.metrics_schema {
        definition.add_metric_reference(MetricReference {
            metric_name: metric.metric_name.clone(),
            schema: Some(metric.clone()),
            source_ref: Some(manifest.plugin_id.to_string()),
            privacy_class: metric.privacy_class.clone(),
        });
    }

    definition.set_health_reference(HealthReference {
        status: ComponentHealthStatus::Healthy,
        schema: Some(manifest.health_schema.clone()),
        liveness_ref: Some(format!("plugin:{}:liveness", manifest.plugin_id)),
        readiness_ref: Some(format!("plugin:{}:readiness", manifest.plugin_id)),
        degraded_reasons: Vec::new(),
        failure_reasons: Vec::new(),
        last_reported_at: Some(Timestamp::now()),
    });

    for contribution in &manifest.ui_contributions {
        definition.add_visualization_binding(VisualizationBinding {
            contribution_id: Some(contribution.contribution_id.clone()),
            slot: Some(contribution.slot.clone()),
            renderer_type: contribution.renderer_type.clone(),
            title: contribution.title.clone(),
            description: None,
            fallback_allowed: contribution.fallback_renderer()
                != FallbackRendererType::UnsupportedContribution,
        });
    }

    Ok(definition)
}

fn running_instance(definition: &ComponentDefinition) -> CommandResult<ComponentInstance> {
    let mut instance = ComponentInstance::from_definition(definition);
    for state in [
        ComponentState::Validated,
        ComponentState::Registered,
        ComponentState::Initialized,
        ComponentState::Enabled,
        ComponentState::Starting,
        ComponentState::Running,
    ] {
        instance
            .transition_to(state, TransitionContext::default())
            .map_err(|error| {
                internal_error(
                    "component_lifecycle",
                    "failed to build running component instance",
                    json!({
                        "component_id": definition.component_id.to_string(),
                        "error_redacted": error.to_string()
                    }),
                )
            })?;
    }
    Ok(instance)
}

fn is_required_dependency(dependency_type: &PluginDependencyType) -> bool {
    matches!(
        dependency_type,
        PluginDependencyType::RequiredPlugin
            | PluginDependencyType::RequiredCapability
            | PluginDependencyType::RequiredContract
            | PluginDependencyType::RequiredInfrastructure
            | PluginDependencyType::RequiredEngine
    )
}

fn component_summary(
    state: &ReadOnlyCommandState,
    definition: &ComponentDefinition,
) -> ComponentSummary {
    let runtime = state.runtime_registry.get(&definition.component_id);
    let plugin_id = state
        .plugin_registry
        .plugin_id_for_component(&definition.component_id)
        .cloned();
    let capability_domain = plugin_id
        .as_ref()
        .and_then(|plugin_id| state.plugin_registry.get(plugin_id))
        .map(|manifest| manifest.capability_domain.clone());

    ComponentSummary {
        component_id: definition.component_id.clone(),
        component_type: definition.component_type.clone(),
        name: definition.metadata.name.clone(),
        version: definition.metadata.version.clone(),
        state: runtime
            .map(|metadata| metadata.component_state.clone())
            .unwrap_or(ComponentState::Registered),
        health_status: runtime
            .map(|metadata| metadata.health_status.clone())
            .unwrap_or(ComponentHealthStatus::Unknown),
        runtime_mode: definition.metadata.runtime_mode.clone(),
        plugin_id,
        capability_domain,
        capability_tags: definition.metadata.capability_tags.clone(),
    }
}

fn health_for_plugin(state: &ReadOnlyCommandState, plugin_id: &PluginId) -> Option<HealthSnapshot> {
    state
        .health_snapshots
        .iter()
        .find(|snapshot| {
            matches!(
                &snapshot.subject,
                HealthSubject::Plugin { plugin_id: subject_id } if subject_id == plugin_id
            )
        })
        .cloned()
}

fn aggregate_plugin_health(
    state: &ReadOnlyCommandState,
    plugin_ids: &[&PluginId],
) -> ObservabilityHealthStatus {
    let statuses = plugin_ids
        .iter()
        .filter_map(|plugin_id| health_for_plugin(state, plugin_id).map(|health| health.status))
        .collect::<Vec<_>>();

    if statuses.is_empty() {
        return ObservabilityHealthStatus::Unknown;
    }
    if statuses
        .iter()
        .any(ObservabilityHealthStatus::is_failure_like)
    {
        return ObservabilityHealthStatus::Failed;
    }
    if statuses.iter().any(|status| {
        matches!(
            status,
            ObservabilityHealthStatus::Degraded | ObservabilityHealthStatus::Stale
        )
    }) {
        return ObservabilityHealthStatus::Degraded;
    }
    ObservabilityHealthStatus::Healthy
}

fn contract_names(contracts: &[ContractDescriptor]) -> Vec<String> {
    contracts
        .iter()
        .map(|contract| contract.contract_name.clone())
        .collect()
}

fn build_graph_view(
    request: &GraphViewRequest,
    state: &ReadOnlyCommandState,
) -> CommandResult<GraphViewModel> {
    if let Some(existing) = state
        .graph_views
        .iter()
        .find(|view| view.graph_type == request.graph_type && view.filters.scope == request.scope)
    {
        return Ok(existing.clone());
    }

    let title = request
        .title_redacted
        .clone()
        .unwrap_or_else(|| default_graph_title(&request.graph_type).to_string());
    let label = RedactedLabel::redacted(title, PrivacyClass::Internal).map_err(|error| {
        command_error(
            ErrorCode::InvalidRequest,
            "invalid graph title",
            json!({ "error_redacted": error.to_string() }),
        )
    })?;
    let mut view = GraphViewModel::new(request.graph_type.clone(), label, request.scope.clone());
    if request.node_limit.is_some() || request.edge_limit.is_some() {
        let node_limit = request.node_limit.unwrap_or(view.node_limit);
        let edge_limit = request.edge_limit.unwrap_or(view.edge_limit);
        view = view.with_bounds(node_limit, edge_limit);
    }
    Ok(view)
}

fn apply_graph_view_request_title(
    view: &mut GraphViewModel,
    request: &GraphViewRequest,
) -> CommandResult<()> {
    if let Some(title) = &request.title_redacted {
        view.title =
            RedactedLabel::redacted(title.clone(), PrivacyClass::Internal).map_err(|error| {
                command_error(
                    ErrorCode::InvalidRequest,
                    "invalid graph title",
                    json!({ "error_redacted": error.to_string() }),
                )
            })?;
    }
    Ok(())
}

fn default_graph_title(graph_type: &GraphType) -> &'static str {
    match graph_type {
        GraphType::OverviewRiskMap => "Overview risk map",
        GraphType::IncidentGraph => "Incident graph",
        GraphType::C2Graph => "C2 graph",
        GraphType::ExfiltrationGraph => "Exfiltration graph",
        GraphType::LateralPropagationGraph => "Lateral propagation graph",
        GraphType::AssetExposureGraph => "Asset exposure graph",
        GraphType::CapabilityDependencyGraph => "Capability dependency graph",
        GraphType::PipelineGraph => "Pipeline graph",
        GraphType::ResponseImpactGraph => "Response impact graph",
    }
}

fn query_findings(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<Finding>> {
    validate_query_page_and_time_range(&request, &StoreKind::Finding)?;
    let mut items = scoped_findings(state, &request.scope)?;
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::Finding,
        security_filter_field_supported,
        finding_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::Finding,
        security_sort_field_supported,
        compare_findings,
    )?;
    page_items(&items, &request.page, &StoreKind::Finding)
}

fn query_alerts(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<Alert>> {
    validate_query_page_and_time_range(&request, &StoreKind::Alert)?;
    let mut items = scoped_alerts(state, &request.scope)?;
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::Alert,
        security_filter_field_supported,
        alert_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::Alert,
        security_sort_field_supported,
        compare_alerts,
    )?;
    page_items(&items, &request.page, &StoreKind::Alert)
}

fn query_incidents(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<Incident>> {
    validate_query_page_and_time_range(&request, &StoreKind::Incident)?;
    let mut items = scoped_incidents(state, &request.scope)?;
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::Incident,
        security_filter_field_supported,
        incident_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::Incident,
        security_sort_field_supported,
        compare_incidents,
    )?;
    page_items(&items, &request.page, &StoreKind::Incident)
}

fn query_flows(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<FlowRecord>> {
    validate_query_page_and_time_range(&request, &StoreKind::Flow)?;
    let mut items = scoped_flows(state, &request.scope)?;
    retain_time_range(&mut items, request.time_range.as_ref(), |flow| {
        &flow.start_time
    });
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::Flow,
        network_filter_field_supported,
        flow_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::Flow,
        network_sort_field_supported,
        compare_flows,
    )?;
    page_items(&items, &request.page, &StoreKind::Flow)
}

fn query_dns(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<DnsObservation>> {
    validate_query_page_and_time_range(&request, &StoreKind::Dns)?;
    let mut items = scoped_dns(state, &request.scope)?;
    retain_time_range(&mut items, request.time_range.as_ref(), |dns| {
        &dns.timestamp
    });
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::Dns,
        network_filter_field_supported,
        dns_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::Dns,
        network_sort_field_supported,
        compare_dns,
    )?;
    page_items(&items, &request.page, &StoreKind::Dns)
}

fn query_tls(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<TlsObservation>> {
    validate_query_page_and_time_range(&request, &StoreKind::Tls)?;
    let mut items = scoped_tls(state, &request.scope)?;
    retain_time_range(&mut items, request.time_range.as_ref(), |tls| {
        &tls.timestamp
    });
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::Tls,
        network_filter_field_supported,
        tls_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::Tls,
        network_sort_field_supported,
        compare_tls,
    )?;
    page_items(&items, &request.page, &StoreKind::Tls)
}

fn query_response_plans(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<ResponsePlan>> {
    validate_query_page_and_time_range(&request, &StoreKind::ResponsePlan)?;
    let mut items = scoped_response_plans(state, &request.scope)?;
    retain_time_range(&mut items, request.time_range.as_ref(), |plan| {
        &plan.created_at
    });
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::ResponsePlan,
        response_filter_field_supported,
        response_plan_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::ResponsePlan,
        response_sort_field_supported,
        compare_response_plans,
    )?;
    page_items(&items, &request.page, &StoreKind::ResponsePlan)
}

fn query_reports(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<Report>> {
    validate_query_page_and_time_range(&request, &StoreKind::Report)?;
    let mut items = scoped_reports(state, &request.scope)?;
    retain_time_range(&mut items, request.time_range.as_ref(), |report| {
        &report.updated_at
    });
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::Report,
        report_filter_field_supported,
        report_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::Report,
        report_sort_field_supported,
        compare_reports,
    )?;
    page_items(&items, &request.page, &StoreKind::Report)
}

fn query_components(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<ComponentSummary>> {
    validate_query_page_and_time_range(&request, &StoreKind::Component)?;
    let mut items = scoped_components(state, &request.scope)?;
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::Component,
        component_filter_field_supported,
        component_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::Component,
        component_sort_field_supported,
        compare_components,
    )?;
    page_items(&items, &request.page, &StoreKind::Component)
}

fn query_plugins(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<PluginManifest>> {
    validate_query_page_and_time_range(&request, &StoreKind::Plugin)?;
    let mut items = scoped_plugins(state, &request.scope)?;
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::Plugin,
        plugin_filter_field_supported,
        plugin_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::Plugin,
        plugin_sort_field_supported,
        compare_plugins,
    )?;
    page_items(&items, &request.page, &StoreKind::Plugin)
}

fn query_capabilities(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<CapabilityOverview>> {
    validate_query_page_and_time_range(&request, &StoreKind::Plugin)?;
    let mut items = scoped_capabilities(state, &request.scope)?;
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::Plugin,
        capability_filter_field_supported,
        capability_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::Plugin,
        capability_sort_field_supported,
        compare_capabilities,
    )?;
    page_items(&items, &request.page, &StoreKind::Plugin)
}

fn query_runtime_profiles(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<RuntimeProfile>> {
    validate_query_page_and_time_range(&request, &StoreKind::Settings)?;
    let mut items = scoped_runtime_profiles(state, &request.scope)?;
    retain_time_range(&mut items, request.time_range.as_ref(), |profile| {
        &profile.updated_at
    });
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::Settings,
        runtime_profile_filter_field_supported,
        runtime_profile_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::Settings,
        runtime_profile_sort_field_supported,
        compare_runtime_profiles,
    )?;
    page_items(&items, &request.page, &StoreKind::Settings)
}

fn query_service_status(
    state: &ReadOnlyCommandState,
    request: QueryRequest,
) -> CommandResult<PageResponse<ServiceStatusView>> {
    validate_query_page_and_time_range(&request, &StoreKind::Settings)?;
    let mut items = scoped_service_status(state, &request.scope)?;
    retain_time_range(&mut items, request.time_range.as_ref(), |status| {
        &status.generated_at
    });
    retain_matching_filters(
        &mut items,
        &request.filters,
        &StoreKind::Settings,
        service_status_filter_field_supported,
        service_status_field_values,
    )?;
    apply_query_sort(
        &mut items,
        &request.sort,
        &StoreKind::Settings,
        service_status_sort_field_supported,
        compare_service_status,
    )?;
    page_items(&items, &request.page, &StoreKind::Settings)
}

fn scoped_components(
    state: &ReadOnlyCommandState,
    scope: &QueryScope,
) -> CommandResult<Vec<ComponentSummary>> {
    let items = list_components(state)?;
    match scope {
        QueryScope::Global => Ok(items),
        QueryScope::Plugin(plugin_id) => Ok(items
            .into_iter()
            .filter(|component| component.plugin_id.as_ref() == Some(plugin_id))
            .collect()),
        QueryScope::Capability(capability_id) => {
            let Some(capability) = state.capability_registry.get(capability_id) else {
                return Ok(Vec::new());
            };
            Ok(items
                .into_iter()
                .filter(|component| {
                    component
                        .plugin_id
                        .as_ref()
                        .is_some_and(|plugin_id| capability.plugin_ids.contains(plugin_id))
                })
                .collect())
        }
        _ => Err(unsupported_scope_error(&StoreKind::Component)),
    }
}

fn scoped_plugins(
    state: &ReadOnlyCommandState,
    scope: &QueryScope,
) -> CommandResult<Vec<PluginManifest>> {
    let items = state
        .plugin_registry
        .list()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    match scope {
        QueryScope::Global => Ok(items),
        QueryScope::Plugin(plugin_id) => Ok(items
            .into_iter()
            .filter(|plugin| &plugin.plugin_id == plugin_id)
            .collect()),
        QueryScope::Capability(capability_id) => {
            let Some(capability) = state.capability_registry.get(capability_id) else {
                return Ok(Vec::new());
            };
            Ok(items
                .into_iter()
                .filter(|plugin| capability.plugin_ids.contains(&plugin.plugin_id))
                .collect())
        }
        _ => Err(unsupported_scope_error(&StoreKind::Plugin)),
    }
}

fn scoped_capabilities(
    state: &ReadOnlyCommandState,
    scope: &QueryScope,
) -> CommandResult<Vec<CapabilityOverview>> {
    let items = get_capability_overview(state)?;
    match scope {
        QueryScope::Global => Ok(items),
        QueryScope::Capability(capability_id) => Ok(items
            .into_iter()
            .filter(|overview| &overview.capability.capability_id == capability_id)
            .collect()),
        QueryScope::Plugin(plugin_id) => Ok(items
            .into_iter()
            .filter(|overview| overview.capability.plugin_ids.contains(plugin_id))
            .collect()),
        _ => Err(unsupported_scope_error(&StoreKind::Plugin)),
    }
}

fn scoped_runtime_profiles(
    state: &ReadOnlyCommandState,
    scope: &QueryScope,
) -> CommandResult<Vec<RuntimeProfile>> {
    match scope {
        QueryScope::Global => Ok(runtime_profile_catalog(state)),
        _ => Err(unsupported_scope_error(&StoreKind::Settings)),
    }
}

fn scoped_service_status(
    state: &ReadOnlyCommandState,
    scope: &QueryScope,
) -> CommandResult<Vec<ServiceStatusView>> {
    match scope {
        QueryScope::Global => Ok(vec![get_service_status(state)?]),
        _ => Err(unsupported_scope_error(&StoreKind::Settings)),
    }
}

fn runtime_profile_catalog(state: &ReadOnlyCommandState) -> Vec<RuntimeProfile> {
    let mut profiles = vec![state.runtime_profile.clone()];
    for profile in RuntimeProfile::default_profiles() {
        if profiles
            .iter()
            .any(|existing| existing.name == profile.name)
        {
            continue;
        }
        profiles.push(profile);
    }
    profiles
}

fn scoped_findings(
    state: &ReadOnlyCommandState,
    scope: &QueryScope,
) -> CommandResult<Vec<Finding>> {
    match scope {
        QueryScope::Global => Ok(state.findings.items.clone()),
        QueryScope::Finding(finding_id) => Ok(state
            .findings
            .items
            .iter()
            .filter(|finding| finding.id() == finding_id)
            .cloned()
            .collect()),
        QueryScope::Alert(alert_id) => {
            let Some(alert) = state
                .alerts
                .items
                .iter()
                .find(|alert| alert.id() == alert_id)
            else {
                return Ok(Vec::new());
            };
            Ok(state
                .findings
                .items
                .iter()
                .filter(|finding| alert.finding_refs().contains(finding.id()))
                .cloned()
                .collect())
        }
        QueryScope::Incident(incident_id) => {
            let Some(incident) = state
                .incidents
                .items
                .iter()
                .find(|incident| incident.id() == incident_id)
            else {
                return Ok(Vec::new());
            };
            let alert_findings = state
                .alerts
                .items
                .iter()
                .filter(|alert| incident.alert_refs().contains(alert.id()))
                .flat_map(|alert| alert.finding_refs().iter());
            let finding_refs = incident
                .finding_refs()
                .iter()
                .chain(alert_findings)
                .collect::<Vec<_>>();
            Ok(state
                .findings
                .items
                .iter()
                .filter(|finding| finding_refs.contains(&finding.id()))
                .cloned()
                .collect())
        }
        QueryScope::Plugin(plugin_id) => Ok(state
            .findings
            .items
            .iter()
            .filter(|finding| finding.producer_plugin() == plugin_id)
            .cloned()
            .collect()),
        QueryScope::Entity(entity_id) => Ok(state
            .findings
            .items
            .iter()
            .filter(|finding| {
                finding
                    .entity_refs()
                    .iter()
                    .any(|entity| &entity.entity_id == entity_id)
            })
            .cloned()
            .collect()),
        _ => Err(unsupported_scope_error(&StoreKind::Finding)),
    }
}

fn scoped_alerts(state: &ReadOnlyCommandState, scope: &QueryScope) -> CommandResult<Vec<Alert>> {
    match scope {
        QueryScope::Global => Ok(state.alerts.items.clone()),
        QueryScope::Alert(alert_id) => Ok(state
            .alerts
            .items
            .iter()
            .filter(|alert| alert.id() == alert_id)
            .cloned()
            .collect()),
        QueryScope::Finding(finding_id) => Ok(state
            .alerts
            .items
            .iter()
            .filter(|alert| alert.finding_refs().contains(finding_id))
            .cloned()
            .collect()),
        QueryScope::Incident(incident_id) => {
            let Some(incident) = state
                .incidents
                .items
                .iter()
                .find(|incident| incident.id() == incident_id)
            else {
                return Ok(Vec::new());
            };
            Ok(state
                .alerts
                .items
                .iter()
                .filter(|alert| incident.alert_refs().contains(alert.id()))
                .cloned()
                .collect())
        }
        QueryScope::Entity(entity_id) => Ok(state
            .alerts
            .items
            .iter()
            .filter(|alert| {
                alert
                    .entity_refs()
                    .iter()
                    .any(|entity| &entity.entity_id == entity_id)
            })
            .cloned()
            .collect()),
        _ => Err(unsupported_scope_error(&StoreKind::Alert)),
    }
}

fn scoped_incidents(
    state: &ReadOnlyCommandState,
    scope: &QueryScope,
) -> CommandResult<Vec<Incident>> {
    match scope {
        QueryScope::Global => Ok(state.incidents.items.clone()),
        QueryScope::Incident(incident_id) => Ok(state
            .incidents
            .items
            .iter()
            .filter(|incident| incident.id() == incident_id)
            .cloned()
            .collect()),
        QueryScope::Alert(alert_id) => Ok(state
            .incidents
            .items
            .iter()
            .filter(|incident| incident.alert_refs().contains(alert_id))
            .cloned()
            .collect()),
        QueryScope::Finding(finding_id) => Ok(state
            .incidents
            .items
            .iter()
            .filter(|incident| incident.finding_refs().contains(finding_id))
            .cloned()
            .collect()),
        _ => Err(unsupported_scope_error(&StoreKind::Incident)),
    }
}

fn scoped_flows(
    state: &ReadOnlyCommandState,
    scope: &QueryScope,
) -> CommandResult<Vec<FlowRecord>> {
    match scope {
        QueryScope::Global => Ok(state.flows.items.clone()),
        QueryScope::Entity(entity_id) => Ok(state
            .flows
            .items
            .iter()
            .filter(|flow| {
                flow.asset_ref
                    .as_ref()
                    .is_some_and(|entity| &entity.entity_id == entity_id)
            })
            .cloned()
            .collect()),
        QueryScope::Trace(trace_id) => Ok(state
            .flows
            .items
            .iter()
            .filter(|flow| flow.trace_id.as_ref() == Some(trace_id))
            .cloned()
            .collect()),
        _ => Err(unsupported_scope_error(&StoreKind::Flow)),
    }
}

fn scoped_dns(
    state: &ReadOnlyCommandState,
    scope: &QueryScope,
) -> CommandResult<Vec<DnsObservation>> {
    match scope {
        QueryScope::Global => Ok(state.dns.items.clone()),
        QueryScope::Entity(entity_id) => Ok(state
            .dns
            .items
            .iter()
            .filter(|dns| {
                dns.asset_ref
                    .as_ref()
                    .is_some_and(|entity| &entity.entity_id == entity_id)
            })
            .cloned()
            .collect()),
        _ => Err(unsupported_scope_error(&StoreKind::Dns)),
    }
}

fn scoped_tls(
    state: &ReadOnlyCommandState,
    scope: &QueryScope,
) -> CommandResult<Vec<TlsObservation>> {
    match scope {
        QueryScope::Global => Ok(state.tls.items.clone()),
        QueryScope::Entity(entity_id) => Ok(state
            .tls
            .items
            .iter()
            .filter(|tls| {
                tls.src_entity
                    .as_ref()
                    .is_some_and(|entity| &entity.entity_id == entity_id)
                    || tls
                        .dst_entity
                        .as_ref()
                        .is_some_and(|entity| &entity.entity_id == entity_id)
            })
            .cloned()
            .collect()),
        _ => Err(unsupported_scope_error(&StoreKind::Tls)),
    }
}

fn scoped_response_plans(
    state: &ReadOnlyCommandState,
    scope: &QueryScope,
) -> CommandResult<Vec<ResponsePlan>> {
    match scope {
        QueryScope::Global => Ok(state.response_plans.items.clone()),
        QueryScope::Finding(finding_id) => Ok(state
            .response_plans
            .items
            .iter()
            .filter(|plan| {
                matches!(&plan.source, sentinel_contracts::ResponsePlanSource::Finding(id) if id == finding_id)
            })
            .cloned()
            .collect()),
        QueryScope::Alert(alert_id) => Ok(state
            .response_plans
            .items
            .iter()
            .filter(|plan| {
                matches!(&plan.source, sentinel_contracts::ResponsePlanSource::Alert(id) if id == alert_id)
            })
            .cloned()
            .collect()),
        QueryScope::Incident(incident_id) => Ok(state
            .response_plans
            .items
            .iter()
            .filter(|plan| {
                matches!(&plan.source, sentinel_contracts::ResponsePlanSource::Incident(id) if id == incident_id)
            })
            .cloned()
            .collect()),
        QueryScope::Entity(entity_id) => Ok(state
            .response_plans
            .items
            .iter()
            .filter(|plan| {
                plan.recommended_actions.iter().any(|action| {
                    action
                        .target
                        .target_entity
                        .as_ref()
                        .is_some_and(|entity| &entity.entity_id == entity_id)
                })
            })
            .cloned()
            .collect()),
        _ => Err(unsupported_scope_error(&StoreKind::ResponsePlan)),
    }
}

fn scoped_reports(state: &ReadOnlyCommandState, scope: &QueryScope) -> CommandResult<Vec<Report>> {
    match scope {
        QueryScope::Global => Ok(state.reports.items.clone()),
        QueryScope::Report(report_id) => Ok(state
            .reports
            .items
            .iter()
            .filter(|report| &report.report_id == report_id)
            .cloned()
            .collect()),
        QueryScope::Incident(incident_id) => Ok(state
            .reports
            .items
            .iter()
            .filter(|report| report.incident_refs.contains(incident_id))
            .cloned()
            .collect()),
        QueryScope::Alert(alert_id) => Ok(state
            .reports
            .items
            .iter()
            .filter(|report| report.alert_refs.contains(alert_id))
            .cloned()
            .collect()),
        QueryScope::Finding(finding_id) => Ok(state
            .reports
            .items
            .iter()
            .filter(|report| report.finding_refs.contains(finding_id))
            .cloned()
            .collect()),
        _ => Err(unsupported_scope_error(&StoreKind::Report)),
    }
}

fn retain_matching_filters<T>(
    items: &mut Vec<T>,
    filters: &[FilterSpec],
    store_kind: &StoreKind,
    field_supported: fn(&StoreKind, &str) -> bool,
    field_values: fn(&T, &str) -> Option<Vec<String>>,
) -> CommandResult<()> {
    for (index, filter) in filters.iter().enumerate() {
        validate_filter_shape(filter, store_kind, index)?;
        if !field_supported(store_kind, filter.field.as_str()) {
            return Err(unsupported_filter_field_error(store_kind, index));
        }
        let needle = filter_needles(filter, store_kind, index)?;
        items.retain(|item| {
            field_values(item, filter.field.as_str())
                .map(|values| matches_filter_values(&values, filter, &needle))
                .unwrap_or(false)
        });
    }
    Ok(())
}

fn validate_filter_shape(
    filter: &FilterSpec,
    store_kind: &StoreKind,
    index: usize,
) -> CommandResult<()> {
    if matches!(
        filter.operator,
        FilterOperator::GreaterThan
            | FilterOperator::GreaterThanOrEqual
            | FilterOperator::LessThan
            | FilterOperator::LessThanOrEqual
    ) {
        return Err(unsupported_filter_operator_error(store_kind, index));
    }

    Ok(())
}

fn filter_needles(
    filter: &FilterSpec,
    store_kind: &StoreKind,
    index: usize,
) -> CommandResult<Vec<String>> {
    if filter.operator == FilterOperator::Exists {
        return Ok(Vec::new());
    }

    match filter.value.as_ref() {
        Some(FilterValue::String(value)) => Ok(vec![normalize_query_value(value)]),
        Some(FilterValue::Strings(values)) => {
            Ok(values.iter().map(normalize_query_value).collect())
        }
        Some(FilterValue::Bool(value)) => Ok(vec![value.to_string()]),
        Some(FilterValue::Number(value)) => Ok(vec![value.to_string()]),
        Some(FilterValue::Null) | None => Err(unsupported_filter_value_error(store_kind, index)),
    }
}

fn matches_filter_values(values: &[String], filter: &FilterSpec, needles: &[String]) -> bool {
    let values = values.iter().map(normalize_query_value).collect::<Vec<_>>();

    match filter.operator {
        FilterOperator::Eq => values.iter().any(|value| needles.contains(value)),
        FilterOperator::NotEq => values.iter().all(|value| !needles.contains(value)),
        FilterOperator::Contains => needles
            .first()
            .is_some_and(|needle| values.iter().any(|value| value.contains(needle))),
        FilterOperator::StartsWith => needles
            .first()
            .is_some_and(|needle| values.iter().any(|value| value.starts_with(needle))),
        FilterOperator::EndsWith => needles
            .first()
            .is_some_and(|needle| values.iter().any(|value| value.ends_with(needle))),
        FilterOperator::In => values.iter().any(|value| needles.contains(value)),
        FilterOperator::NotIn => values.iter().all(|value| !needles.contains(value)),
        FilterOperator::Exists => !values.is_empty(),
        FilterOperator::GreaterThan
        | FilterOperator::GreaterThanOrEqual
        | FilterOperator::LessThan
        | FilterOperator::LessThanOrEqual => false,
    }
}

fn retain_time_range<T>(
    items: &mut Vec<T>,
    time_range: Option<&TimeRange>,
    timestamp: fn(&T) -> &Timestamp,
) {
    let Some(time_range) = time_range else {
        return;
    };

    items.retain(|item| {
        let value = timestamp(item);
        if let Some(start) = &time_range.start {
            if value < start {
                return false;
            }
        }
        if let Some(end) = &time_range.end {
            if value > end {
                return false;
            }
        }
        true
    });
}

fn apply_query_sort<T>(
    items: &mut [T],
    sort: &[SortSpec],
    store_kind: &StoreKind,
    field_supported: fn(&StoreKind, &str) -> bool,
    compare_field: fn(&T, &T, &str) -> Option<Ordering>,
) -> CommandResult<()> {
    for (index, spec) in sort.iter().enumerate() {
        if !field_supported(store_kind, spec.field.as_str()) {
            return Err(unsupported_sort_field_error(store_kind, index));
        }
    }

    for spec in sort.iter().rev() {
        items.sort_by(|left, right| {
            let ordering =
                compare_field(left, right, spec.field.as_str()).unwrap_or(Ordering::Equal);
            match spec.direction {
                SortDirection::Asc => ordering,
                SortDirection::Desc => ordering.reverse(),
            }
        });
    }
    Ok(())
}

fn component_filter_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    matches!(store_kind, StoreKind::Component)
        && matches!(
            field,
            "id" | "component_id"
                | "component_type"
                | "name"
                | "version"
                | "state"
                | "health_status"
                | "runtime_mode"
                | "plugin_id"
                | "capability_domain"
                | "capability_tag"
        )
}

fn component_sort_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    matches!(store_kind, StoreKind::Component)
        && matches!(
            field,
            "id" | "component_id"
                | "component_type"
                | "name"
                | "version"
                | "state"
                | "health_status"
                | "runtime_mode"
                | "plugin_id"
                | "capability_domain"
                | "capability_tag_count"
        )
}

fn plugin_filter_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    matches!(store_kind, StoreKind::Plugin)
        && matches!(
            field,
            "id" | "plugin_id"
                | "name"
                | "plugin_name"
                | "version"
                | "capability_domain"
                | "plugin_type"
                | "runtime_mode"
                | "maturity_level"
                | "capability_tag"
                | "input_contract"
                | "output_contract"
                | "finding_type"
                | "graph_hint_type"
                | "enabled_by_default"
        )
}

fn plugin_sort_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    matches!(store_kind, StoreKind::Plugin)
        && matches!(
            field,
            "id" | "plugin_id"
                | "name"
                | "plugin_name"
                | "version"
                | "capability_domain"
                | "plugin_type"
                | "runtime_mode"
                | "maturity_level"
                | "enabled_by_default"
                | "input_contract_count"
                | "output_contract_count"
                | "permission_count"
                | "capability_tag_count"
        )
}

fn capability_filter_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    matches!(store_kind, StoreKind::Plugin)
        && matches!(
            field,
            "id" | "capability_id"
                | "domain"
                | "capability_domain"
                | "title"
                | "maturity_level"
                | "plugin_id"
                | "plugin_name"
                | "input_contract"
                | "output_contract"
                | "health_status"
        )
}

fn capability_sort_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    matches!(store_kind, StoreKind::Plugin)
        && matches!(
            field,
            "id" | "capability_id"
                | "domain"
                | "capability_domain"
                | "title"
                | "maturity_level"
                | "plugin_count"
                | "required_permission_count"
                | "ui_contribution_count"
                | "health_status"
        )
}

fn runtime_profile_filter_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    matches!(store_kind, StoreKind::Settings)
        && matches!(
            field,
            "id" | "profile_id"
                | "name"
                | "display_name"
                | "is_default"
                | "response_mode"
                | "replay_execution_disabled"
                | "forensic_mode_enabled"
                | "degraded_state_banner_enabled"
                | "export_format"
        )
}

fn runtime_profile_sort_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    matches!(store_kind, StoreKind::Settings)
        && matches!(
            field,
            "id" | "profile_id"
                | "name"
                | "display_name"
                | "created_at"
                | "updated_at"
                | "is_default"
                | "response_mode"
                | "forensic_mode_enabled"
        )
}

fn service_status_filter_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    matches!(store_kind, StoreKind::Settings)
        && matches!(
            field,
            "connected"
                | "degraded"
                | "reason"
                | "profile_mode"
                | "local_core_status"
                | "elevated_service_status"
                | "ipc_status"
                | "storage_status"
                | "reduced_visibility"
                | "privileged_actions_available"
                | "capture_available"
        )
}

fn service_status_sort_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    matches!(store_kind, StoreKind::Settings)
        && matches!(
            field,
            "generated_at"
                | "connected"
                | "degraded"
                | "profile_mode"
                | "local_core_status"
                | "elevated_service_status"
                | "ipc_status"
                | "storage_status"
                | "reduced_visibility"
                | "privileged_actions_available"
                | "capture_available"
        )
}

fn security_filter_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    match store_kind {
        StoreKind::Finding => matches!(
            field,
            "id" | "finding_id"
                | "type"
                | "finding_type"
                | "state"
                | "severity"
                | "producer_plugin"
                | "plugin_id"
                | "evidence_ref"
                | "evidence_id"
                | "entity"
                | "entity_id"
        ),
        StoreKind::Alert => matches!(
            field,
            "id" | "alert_id"
                | "title"
                | "title_redacted"
                | "summary"
                | "summary_redacted"
                | "state"
                | "severity"
                | "finding_ref"
                | "finding_id"
                | "entity"
                | "entity_id"
        ),
        StoreKind::Incident => matches!(
            field,
            "id" | "incident_id"
                | "type"
                | "incident_type"
                | "title"
                | "title_redacted"
                | "summary"
                | "summary_redacted"
                | "state"
                | "severity"
                | "alert_ref"
                | "alert_id"
                | "finding_ref"
                | "finding_id"
        ),
        _ => false,
    }
}

fn security_sort_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    match store_kind {
        StoreKind::Finding => matches!(
            field,
            "id" | "finding_id"
                | "type"
                | "finding_type"
                | "state"
                | "severity"
                | "confidence"
                | "producer_plugin"
                | "plugin_id"
        ),
        StoreKind::Alert => matches!(
            field,
            "id" | "alert_id"
                | "title"
                | "title_redacted"
                | "summary"
                | "summary_redacted"
                | "state"
                | "severity"
                | "confidence"
        ),
        StoreKind::Incident => matches!(
            field,
            "id" | "incident_id"
                | "type"
                | "incident_type"
                | "title"
                | "title_redacted"
                | "summary"
                | "summary_redacted"
                | "state"
                | "severity"
                | "confidence"
        ),
        _ => false,
    }
}

fn network_filter_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    match store_kind {
        StoreKind::Flow => matches!(
            field,
            "id" | "flow_id"
                | "src_ip"
                | "dst_ip"
                | "src_port"
                | "dst_port"
                | "protocol"
                | "direction"
                | "process_ref"
                | "asset_ref"
                | "entity"
                | "entity_id"
                | "session_ref"
                | "session_id"
                | "trace_id"
                | "attribution_confidence"
        ),
        StoreKind::Dns => matches!(
            field,
            "id" | "dns_observation_id"
                | "flow_ref"
                | "flow_id"
                | "query_name"
                | "query_name_protected"
                | "query_type"
                | "response_code"
                | "resolver_ip"
                | "client_ip"
                | "process_ref"
                | "asset_ref"
                | "entity"
                | "entity_id"
                | "privacy_class"
        ),
        StoreKind::Tls => matches!(
            field,
            "id" | "tls_observation_id"
                | "flow_ref"
                | "flow_id"
                | "sni"
                | "sni_protected"
                | "alpn"
                | "ja3"
                | "ja4"
                | "ja4s"
                | "tls_version"
                | "cipher_suite"
                | "certificate_fingerprint"
                | "issuer"
                | "issuer_summary_protected"
                | "san"
                | "san_summary_protected"
                | "process_ref"
                | "src_entity"
                | "dst_entity"
                | "entity"
                | "entity_id"
                | "privacy_class"
        ),
        _ => false,
    }
}

fn network_sort_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    match store_kind {
        StoreKind::Flow => matches!(
            field,
            "id" | "flow_id"
                | "src_ip"
                | "dst_ip"
                | "src_port"
                | "dst_port"
                | "protocol"
                | "direction"
                | "start_time"
                | "end_time"
                | "duration_millis"
                | "bytes_in"
                | "bytes_out"
                | "packets_in"
                | "packets_out"
                | "quality_score"
                | "attribution_confidence"
        ),
        StoreKind::Dns => matches!(
            field,
            "id" | "dns_observation_id"
                | "flow_ref"
                | "flow_id"
                | "query_name"
                | "query_name_protected"
                | "query_type"
                | "response_code"
                | "resolver_ip"
                | "client_ip"
                | "timestamp"
                | "answer_count"
                | "query_length"
                | "label_count"
                | "subdomain_depth"
                | "character_entropy"
                | "quality_score"
        ),
        StoreKind::Tls => matches!(
            field,
            "id" | "tls_observation_id"
                | "flow_ref"
                | "flow_id"
                | "sni"
                | "sni_protected"
                | "tls_version"
                | "cipher_suite"
                | "certificate_fingerprint"
                | "timestamp"
                | "valid_not_before"
                | "valid_not_after"
                | "quality_score"
        ),
        _ => false,
    }
}

fn response_filter_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    match store_kind {
        StoreKind::ResponsePlan => matches!(
            field,
            "id" | "plan_id"
                | "source_type"
                | "source_ref"
                | "finding_id"
                | "alert_id"
                | "incident_id"
                | "graph_path_id"
                | "risk_evaluation"
                | "risk_evaluation_redacted"
                | "business_impact"
                | "business_impact_redacted"
                | "approval_required"
                | "is_replay"
                | "execution_disabled_in_replay"
                | "audit_requirement"
                | "action_type"
                | "response_level"
                | "approval_state"
                | "target_entity"
                | "entity"
                | "entity_id"
                | "target_summary"
                | "target_summary_redacted"
                | "scope"
                | "scope_description"
                | "rollback_available"
                | "recommended_action_count"
                | "policy_decision_count"
                | "rollback_plan_count"
        ),
        _ => false,
    }
}

fn response_sort_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    match store_kind {
        StoreKind::ResponsePlan => matches!(
            field,
            "id" | "plan_id"
                | "source_type"
                | "source_ref"
                | "created_at"
                | "approval_required"
                | "is_replay"
                | "execution_disabled_in_replay"
                | "recommended_action_count"
                | "policy_decision_count"
                | "rollback_plan_count"
        ),
        _ => false,
    }
}

fn report_filter_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    match store_kind {
        StoreKind::Report => matches!(
            field,
            "id" | "report_id"
                | "type"
                | "report_type"
                | "title"
                | "title_redacted"
                | "summary"
                | "summary_redacted"
                | "status"
                | "incident_ref"
                | "incident_id"
                | "alert_ref"
                | "alert_id"
                | "finding_ref"
                | "finding_id"
                | "evidence_ref"
                | "evidence_id"
                | "graph_snapshot_ref"
                | "graph_snapshot_id"
                | "response_result_ref"
                | "response_result_id"
                | "rollback_result_ref"
                | "rollback_result_id"
                | "section_type"
                | "redaction_passed"
                | "redaction_category"
                | "privacy_class"
                | "audit_id"
                | "trace_id"
                | "created_at"
                | "updated_at"
        ),
        _ => false,
    }
}

fn report_sort_field_supported(store_kind: &StoreKind, field: &str) -> bool {
    match store_kind {
        StoreKind::Report => matches!(
            field,
            "id" | "report_id"
                | "type"
                | "report_type"
                | "title"
                | "title_redacted"
                | "summary"
                | "summary_redacted"
                | "status"
                | "created_at"
                | "updated_at"
                | "section_count"
                | "incident_count"
                | "alert_count"
                | "finding_count"
                | "evidence_count"
                | "graph_snapshot_count"
                | "response_result_count"
                | "rollback_result_count"
                | "redaction_passed"
                | "redacted_field_count"
                | "suppressed_section_count"
        ),
        _ => false,
    }
}

fn component_field_values(component: &ComponentSummary, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "component_id" => Some(vec![component.component_id.to_string()]),
        "component_type" => Some(vec![enum_token(&component.component_type)]),
        "name" => Some(vec![component.name.clone()]),
        "version" => Some(vec![component.version.clone()]),
        "state" => Some(vec![enum_token(&component.state)]),
        "health_status" => Some(vec![enum_token(&component.health_status)]),
        "runtime_mode" => Some(vec![enum_token(&component.runtime_mode)]),
        "plugin_id" => Some(optional_to_values(component.plugin_id.as_ref())),
        "capability_domain" => Some(optional_to_values(component.capability_domain.as_ref())),
        "capability_tag" => Some(component.capability_tags.clone()),
        _ => None,
    }
}

fn plugin_field_values(plugin: &PluginManifest, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "plugin_id" => Some(vec![plugin.plugin_id.to_string()]),
        "name" | "plugin_name" => Some(vec![plugin.plugin_name.clone()]),
        "version" => Some(vec![plugin.version.clone()]),
        "capability_domain" => Some(vec![plugin.capability_domain.clone()]),
        "plugin_type" => Some(vec![enum_token(&plugin.plugin_type)]),
        "runtime_mode" => Some(vec![enum_token(&plugin.runtime_mode)]),
        "maturity_level" => Some(vec![enum_token(&plugin.maturity_level)]),
        "capability_tag" => Some(plugin.capability_tags.clone()),
        "input_contract" => Some(contract_names(&plugin.input_contracts)),
        "output_contract" => Some(contract_names(&plugin.output_contracts)),
        "finding_type" => Some(plugin.finding_types.clone()),
        "graph_hint_type" => Some(plugin.graph_hint_types.clone()),
        "enabled_by_default" => Some(vec![plugin.enabled_by_default.to_string()]),
        _ => None,
    }
}

fn capability_field_values(overview: &CapabilityOverview, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "capability_id" => Some(vec![overview.capability.capability_id.to_string()]),
        "domain" | "capability_domain" => Some(vec![overview.capability.capability_domain.clone()]),
        "title" => Some(vec![overview.capability.title.clone()]),
        "maturity_level" => Some(vec![enum_token(&overview.capability.maturity_level)]),
        "plugin_id" => Some(
            overview
                .capability
                .plugin_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "plugin_name" => Some(overview.plugin_names.clone()),
        "input_contract" => Some(overview.input_contract_names.clone()),
        "output_contract" => Some(overview.output_contract_names.clone()),
        "health_status" => Some(vec![enum_token(&overview.health_status)]),
        _ => None,
    }
}

fn runtime_profile_field_values(profile: &RuntimeProfile, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "profile_id" => Some(vec![profile.profile_id.to_string()]),
        "name" => Some(vec![enum_token(&profile.name)]),
        "display_name" => Some(vec![profile.display_name.clone()]),
        "is_default" => Some(vec![profile.is_default.to_string()]),
        "response_mode" => Some(vec![enum_token(&profile.response_policy.mode)]),
        "replay_execution_disabled" => Some(vec![profile
            .response_policy
            .replay_execution_disabled
            .to_string()]),
        "forensic_mode_enabled" => Some(vec![profile
            .privacy_policy
            .forensic_mode
            .enabled
            .to_string()]),
        "degraded_state_banner_enabled" => Some(vec![profile
            .service_status_settings
            .degraded_state_banner_enabled
            .to_string()]),
        "export_format" => Some(
            profile
                .report_export_policy
                .allowed_formats
                .iter()
                .map(|format| format.as_str().to_string())
                .collect(),
        ),
        _ => None,
    }
}

fn service_status_field_values(status: &ServiceStatusView, field: &str) -> Option<Vec<String>> {
    match field {
        "connected" => Some(vec![status.connected.to_string()]),
        "degraded" => Some(vec![status.degraded.to_string()]),
        "reason" => Some(optional_to_values(status.reason.as_ref())),
        "profile_mode" => Some(vec![status.profile_mode.clone()]),
        "local_core_status" => Some(vec![enum_token(&status.local_core_status)]),
        "elevated_service_status" => Some(vec![enum_token(&status.elevated_service_status)]),
        "ipc_status" => Some(vec![enum_token(&status.ipc_status)]),
        "storage_status" => Some(vec![enum_token(&status.storage_status)]),
        "reduced_visibility" => Some(vec![status.reduced_visibility.to_string()]),
        "privileged_actions_available" => {
            Some(vec![status.privileged_actions_available.to_string()])
        }
        "capture_available" => Some(vec![status.capture_available.to_string()]),
        _ => None,
    }
}

fn finding_field_values(finding: &Finding, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "finding_id" => Some(vec![finding.id().to_string()]),
        "type" | "finding_type" => Some(vec![finding.finding_type().to_string()]),
        "state" => Some(vec![enum_token(finding.state())]),
        "severity" => Some(vec![enum_token(finding.severity())]),
        "producer_plugin" | "plugin_id" => Some(vec![finding.producer_plugin().to_string()]),
        "evidence_ref" | "evidence_id" => Some(
            finding
                .evidence_refs()
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "entity" | "entity_id" => Some(
            finding
                .entity_refs()
                .iter()
                .map(|entity| entity.entity_id.to_string())
                .collect(),
        ),
        _ => None,
    }
}

fn alert_field_values(alert: &Alert, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "alert_id" => Some(vec![alert.id().to_string()]),
        "title" | "title_redacted" => Some(vec![alert.title_redacted().to_string()]),
        "summary" | "summary_redacted" => Some(vec![alert.summary_redacted().to_string()]),
        "state" => Some(vec![enum_token(alert.state())]),
        "severity" => Some(vec![enum_token(alert.severity())]),
        "finding_ref" | "finding_id" => Some(
            alert
                .finding_refs()
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "entity" | "entity_id" => Some(
            alert
                .entity_refs()
                .iter()
                .map(|entity| entity.entity_id.to_string())
                .collect(),
        ),
        _ => None,
    }
}

fn incident_field_values(incident: &Incident, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "incident_id" => Some(vec![incident.id().to_string()]),
        "type" | "incident_type" => Some(vec![incident.incident_type().to_string()]),
        "title" | "title_redacted" => Some(vec![incident.title_redacted().to_string()]),
        "summary" | "summary_redacted" => Some(vec![incident.summary_redacted().to_string()]),
        "state" => Some(vec![enum_token(incident.state())]),
        "severity" => Some(vec![enum_token(incident.severity())]),
        "alert_ref" | "alert_id" => Some(
            incident
                .alert_refs()
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "finding_ref" | "finding_id" => Some(
            incident
                .finding_refs()
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        _ => None,
    }
}

fn flow_field_values(flow: &FlowRecord, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "flow_id" => Some(vec![flow.flow_id.to_string()]),
        "src_ip" => Some(vec![flow.src_ip.to_string()]),
        "dst_ip" => Some(vec![flow.dst_ip.to_string()]),
        "src_port" => Some(vec![flow.src_port.to_string()]),
        "dst_port" => Some(vec![flow.dst_port.to_string()]),
        "protocol" => Some(vec![enum_token(&flow.protocol)]),
        "direction" => Some(vec![enum_token(&flow.direction)]),
        "process_ref" => Some(optional_to_values(flow.process_ref.as_ref())),
        "asset_ref" | "entity" | "entity_id" => Some(
            flow.asset_ref
                .as_ref()
                .map(|entity| entity.entity_id.to_string())
                .into_iter()
                .collect(),
        ),
        "session_ref" | "session_id" => Some(optional_to_values(flow.session_ref.as_ref())),
        "trace_id" => Some(optional_to_values(flow.trace_id.as_ref())),
        "attribution_confidence" => Some(vec![enum_token(&flow.attribution_confidence)]),
        _ => None,
    }
}

fn dns_field_values(dns: &DnsObservation, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "dns_observation_id" => Some(vec![dns.dns_observation_id.to_string()]),
        "flow_ref" | "flow_id" => Some(optional_to_values(dns.flow_ref.as_ref())),
        "query_name" | "query_name_protected" => Some(vec![dns.query_name_protected.clone()]),
        "query_type" => Some(vec![dns.query_type.clone()]),
        "response_code" => Some(optional_to_values(dns.response_code.as_ref())),
        "resolver_ip" => Some(vec![dns.resolver_ip.to_string()]),
        "client_ip" => Some(vec![dns.client_ip.to_string()]),
        "process_ref" => Some(optional_to_values(dns.process_ref.as_ref())),
        "asset_ref" | "entity" | "entity_id" => Some(
            dns.asset_ref
                .as_ref()
                .map(|entity| entity.entity_id.to_string())
                .into_iter()
                .collect(),
        ),
        "privacy_class" => Some(vec![enum_token(&dns.privacy_class)]),
        _ => None,
    }
}

fn tls_field_values(tls: &TlsObservation, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "tls_observation_id" => Some(vec![tls.tls_observation_id.to_string()]),
        "flow_ref" | "flow_id" => Some(optional_to_values(tls.flow_ref.as_ref())),
        "sni" | "sni_protected" => Some(optional_to_values(tls.sni_protected.as_ref())),
        "alpn" => Some(tls.alpn.clone()),
        "ja3" => Some(optional_to_values(tls.ja3.as_ref())),
        "ja4" => Some(optional_to_values(tls.ja4.as_ref())),
        "ja4s" => Some(optional_to_values(tls.ja4s.as_ref())),
        "tls_version" => Some(optional_to_values(tls.tls_version.as_ref())),
        "cipher_suite" => Some(optional_to_values(tls.cipher_suite.as_ref())),
        "certificate_fingerprint" => Some(optional_to_values(tls.certificate_fingerprint.as_ref())),
        "issuer" | "issuer_summary_protected" => {
            Some(optional_to_values(tls.issuer_summary_protected.as_ref()))
        }
        "san" | "san_summary_protected" => {
            Some(optional_to_values(tls.san_summary_protected.as_ref()))
        }
        "process_ref" => Some(optional_to_values(tls.process_ref.as_ref())),
        "src_entity" => Some(entity_ref_to_values(tls.src_entity.as_ref())),
        "dst_entity" => Some(entity_ref_to_values(tls.dst_entity.as_ref())),
        "entity" | "entity_id" => Some(
            tls.src_entity
                .as_ref()
                .into_iter()
                .chain(tls.dst_entity.as_ref())
                .map(|entity| entity.entity_id.to_string())
                .collect(),
        ),
        "privacy_class" => Some(vec![enum_token(&tls.privacy_class)]),
        _ => None,
    }
}

fn response_plan_field_values(plan: &ResponsePlan, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "plan_id" => Some(vec![plan.plan_id.to_string()]),
        "source_type" => Some(vec![response_plan_source_type(plan)]),
        "source_ref" => Some(vec![response_plan_source_ref(plan)]),
        "finding_id" => {
            if let sentinel_contracts::ResponsePlanSource::Finding(id) = &plan.source {
                Some(vec![id.to_string()])
            } else {
                Some(Vec::new())
            }
        }
        "alert_id" => {
            if let sentinel_contracts::ResponsePlanSource::Alert(id) = &plan.source {
                Some(vec![id.to_string()])
            } else {
                Some(Vec::new())
            }
        }
        "incident_id" => {
            if let sentinel_contracts::ResponsePlanSource::Incident(id) = &plan.source {
                Some(vec![id.to_string()])
            } else {
                Some(Vec::new())
            }
        }
        "graph_path_id" => {
            if let sentinel_contracts::ResponsePlanSource::GraphPath(id) = &plan.source {
                Some(vec![id.to_string()])
            } else {
                Some(Vec::new())
            }
        }
        "risk_evaluation" | "risk_evaluation_redacted" => {
            Some(vec![plan.risk_evaluation_redacted.clone()])
        }
        "business_impact" | "business_impact_redacted" => {
            Some(vec![plan.business_impact_redacted.clone()])
        }
        "approval_required" => Some(vec![plan.approval_required.to_string()]),
        "is_replay" => Some(vec![plan.is_replay.to_string()]),
        "execution_disabled_in_replay" => Some(vec![plan.execution_disabled_in_replay.to_string()]),
        "audit_requirement" => Some(plan.audit_requirements.clone()),
        "action_type" => Some(
            plan.recommended_actions
                .iter()
                .map(|action| enum_token(&action.action_type))
                .collect(),
        ),
        "response_level" => Some(
            plan.recommended_actions
                .iter()
                .map(|action| enum_token(&action.response_level))
                .collect(),
        ),
        "approval_state" => Some(
            plan.recommended_actions
                .iter()
                .filter_map(|action| action.approval_state.as_ref())
                .map(enum_token)
                .collect(),
        ),
        "target_entity" | "entity" | "entity_id" => Some(
            plan.recommended_actions
                .iter()
                .filter_map(|action| action.target.target_entity.as_ref())
                .map(|entity| entity.entity_id.to_string())
                .collect(),
        ),
        "target_summary" | "target_summary_redacted" => Some(
            plan.recommended_actions
                .iter()
                .map(|action| action.target.target_summary_redacted.clone())
                .collect(),
        ),
        "scope" | "scope_description" => Some(
            plan.recommended_actions
                .iter()
                .map(|action| action.scope.description_redacted.clone())
                .collect(),
        ),
        "rollback_available" => Some(
            plan.recommended_actions
                .iter()
                .map(|action| action.rollback_available.to_string())
                .collect(),
        ),
        "recommended_action_count" => Some(vec![plan.recommended_actions.len().to_string()]),
        "policy_decision_count" => Some(vec![plan.policy_decisions.len().to_string()]),
        "rollback_plan_count" => Some(vec![plan.rollback_plans.len().to_string()]),
        _ => None,
    }
}

fn report_field_values(report: &Report, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "report_id" => Some(vec![report.report_id.to_string()]),
        "type" | "report_type" => Some(vec![enum_token(&report.report_type)]),
        "title" | "title_redacted" => Some(vec![report.title_redacted.clone()]),
        "summary" | "summary_redacted" => Some(vec![report.summary_redacted.clone()]),
        "status" => Some(vec![enum_token(&report.status)]),
        "incident_ref" | "incident_id" => Some(
            report
                .incident_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "alert_ref" | "alert_id" => {
            Some(report.alert_refs.iter().map(ToString::to_string).collect())
        }
        "finding_ref" | "finding_id" => Some(
            report
                .finding_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "evidence_ref" | "evidence_id" => Some(
            report
                .evidence_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "graph_snapshot_ref" | "graph_snapshot_id" => Some(
            report
                .graph_snapshot_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "response_result_ref" | "response_result_id" => Some(
            report
                .response_result_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "rollback_result_ref" | "rollback_result_id" => Some(
            report
                .rollback_result_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "section_type" => Some(
            report
                .sections
                .iter()
                .map(|section| enum_token(&section.section_type))
                .collect(),
        ),
        "redaction_passed" => Some(vec![report.redaction_summary.passed.to_string()]),
        "redaction_category" => Some(
            report
                .redaction_summary
                .redacted_categories
                .iter()
                .map(enum_token)
                .collect(),
        ),
        "privacy_class" => Some(vec![enum_token(&report.privacy_class)]),
        "audit_id" => Some(optional_to_values(
            report.audit_ref.as_ref().map(|audit| &audit.audit_id),
        )),
        "trace_id" => Some(optional_to_values(
            report
                .audit_ref
                .as_ref()
                .and_then(|audit| audit.trace_id.as_ref()),
        )),
        "created_at" => Some(vec![report.created_at.to_string()]),
        "updated_at" => Some(vec![report.updated_at.to_string()]),
        _ => None,
    }
}

fn compare_findings(left: &Finding, right: &Finding, field: &str) -> Option<Ordering> {
    match field {
        "id" | "finding_id" => Some(left.id().to_string().cmp(&right.id().to_string())),
        "type" | "finding_type" => Some(left.finding_type().cmp(right.finding_type())),
        "state" => Some(enum_token(left.state()).cmp(&enum_token(right.state()))),
        "severity" => Some(severity_rank(left.severity()).cmp(&severity_rank(right.severity()))),
        "confidence" => left
            .confidence()
            .value()
            .partial_cmp(&right.confidence().value()),
        "producer_plugin" | "plugin_id" => Some(
            left.producer_plugin()
                .to_string()
                .cmp(&right.producer_plugin().to_string()),
        ),
        _ => None,
    }
}

fn compare_alerts(left: &Alert, right: &Alert, field: &str) -> Option<Ordering> {
    match field {
        "id" | "alert_id" => Some(left.id().to_string().cmp(&right.id().to_string())),
        "title" | "title_redacted" => Some(left.title_redacted().cmp(right.title_redacted())),
        "summary" | "summary_redacted" => {
            Some(left.summary_redacted().cmp(right.summary_redacted()))
        }
        "state" => Some(enum_token(left.state()).cmp(&enum_token(right.state()))),
        "severity" => Some(severity_rank(left.severity()).cmp(&severity_rank(right.severity()))),
        "confidence" => left
            .confidence()
            .value()
            .partial_cmp(&right.confidence().value()),
        _ => None,
    }
}

fn compare_incidents(left: &Incident, right: &Incident, field: &str) -> Option<Ordering> {
    match field {
        "id" | "incident_id" => Some(left.id().to_string().cmp(&right.id().to_string())),
        "type" | "incident_type" => Some(left.incident_type().cmp(right.incident_type())),
        "title" | "title_redacted" => Some(left.title_redacted().cmp(right.title_redacted())),
        "summary" | "summary_redacted" => {
            Some(left.summary_redacted().cmp(right.summary_redacted()))
        }
        "state" => Some(enum_token(left.state()).cmp(&enum_token(right.state()))),
        "severity" => Some(severity_rank(left.severity()).cmp(&severity_rank(right.severity()))),
        "confidence" => left
            .confidence()
            .value()
            .partial_cmp(&right.confidence().value()),
        _ => None,
    }
}

fn compare_flows(left: &FlowRecord, right: &FlowRecord, field: &str) -> Option<Ordering> {
    match field {
        "id" | "flow_id" => Some(left.flow_id.to_string().cmp(&right.flow_id.to_string())),
        "src_ip" => Some(left.src_ip.to_string().cmp(&right.src_ip.to_string())),
        "dst_ip" => Some(left.dst_ip.to_string().cmp(&right.dst_ip.to_string())),
        "src_port" => Some(left.src_port.cmp(&right.src_port)),
        "dst_port" => Some(left.dst_port.cmp(&right.dst_port)),
        "protocol" => Some(enum_token(&left.protocol).cmp(&enum_token(&right.protocol))),
        "direction" => Some(enum_token(&left.direction).cmp(&enum_token(&right.direction))),
        "start_time" => Some(left.start_time.cmp(&right.start_time)),
        "end_time" => Some(left.end_time.as_ref().cmp(&right.end_time.as_ref())),
        "duration_millis" => Some(left.duration_millis.cmp(&right.duration_millis)),
        "bytes_in" => Some(left.bytes_in.cmp(&right.bytes_in)),
        "bytes_out" => Some(left.bytes_out.cmp(&right.bytes_out)),
        "packets_in" => Some(left.packets_in.cmp(&right.packets_in)),
        "packets_out" => Some(left.packets_out.cmp(&right.packets_out)),
        "quality_score" => left
            .quality_score
            .value()
            .partial_cmp(&right.quality_score.value()),
        "attribution_confidence" => Some(
            enum_token(&left.attribution_confidence)
                .cmp(&enum_token(&right.attribution_confidence)),
        ),
        _ => None,
    }
}

fn compare_dns(left: &DnsObservation, right: &DnsObservation, field: &str) -> Option<Ordering> {
    match field {
        "id" | "dns_observation_id" => Some(
            left.dns_observation_id
                .to_string()
                .cmp(&right.dns_observation_id.to_string()),
        ),
        "flow_ref" | "flow_id" => Some(compare_optional_to_string(
            left.flow_ref.as_ref(),
            right.flow_ref.as_ref(),
        )),
        "query_name" | "query_name_protected" => {
            Some(left.query_name_protected.cmp(&right.query_name_protected))
        }
        "query_type" => Some(left.query_type.cmp(&right.query_type)),
        "response_code" => Some(
            left.response_code
                .as_ref()
                .cmp(&right.response_code.as_ref()),
        ),
        "resolver_ip" => Some(
            left.resolver_ip
                .to_string()
                .cmp(&right.resolver_ip.to_string()),
        ),
        "client_ip" => Some(left.client_ip.to_string().cmp(&right.client_ip.to_string())),
        "timestamp" => Some(left.timestamp.cmp(&right.timestamp)),
        "answer_count" => Some(left.features.answer_count.cmp(&right.features.answer_count)),
        "query_length" => Some(left.features.query_length.cmp(&right.features.query_length)),
        "label_count" => Some(left.features.label_count.cmp(&right.features.label_count)),
        "subdomain_depth" => Some(
            left.features
                .subdomain_depth
                .cmp(&right.features.subdomain_depth),
        ),
        "character_entropy" => left
            .features
            .character_entropy
            .partial_cmp(&right.features.character_entropy),
        "quality_score" => left
            .quality_score
            .value()
            .partial_cmp(&right.quality_score.value()),
        _ => None,
    }
}

fn compare_tls(left: &TlsObservation, right: &TlsObservation, field: &str) -> Option<Ordering> {
    match field {
        "id" | "tls_observation_id" => Some(
            left.tls_observation_id
                .to_string()
                .cmp(&right.tls_observation_id.to_string()),
        ),
        "flow_ref" | "flow_id" => Some(compare_optional_to_string(
            left.flow_ref.as_ref(),
            right.flow_ref.as_ref(),
        )),
        "sni" | "sni_protected" => Some(
            left.sni_protected
                .as_ref()
                .cmp(&right.sni_protected.as_ref()),
        ),
        "tls_version" => Some(left.tls_version.as_ref().cmp(&right.tls_version.as_ref())),
        "cipher_suite" => Some(left.cipher_suite.as_ref().cmp(&right.cipher_suite.as_ref())),
        "certificate_fingerprint" => Some(
            left.certificate_fingerprint
                .as_ref()
                .cmp(&right.certificate_fingerprint.as_ref()),
        ),
        "timestamp" => Some(left.timestamp.cmp(&right.timestamp)),
        "valid_not_before" => Some(
            left.valid_not_before
                .as_ref()
                .cmp(&right.valid_not_before.as_ref()),
        ),
        "valid_not_after" => Some(
            left.valid_not_after
                .as_ref()
                .cmp(&right.valid_not_after.as_ref()),
        ),
        "quality_score" => left
            .quality_score
            .value()
            .partial_cmp(&right.quality_score.value()),
        _ => None,
    }
}

fn compare_response_plans(
    left: &ResponsePlan,
    right: &ResponsePlan,
    field: &str,
) -> Option<Ordering> {
    match field {
        "id" | "plan_id" => Some(left.plan_id.to_string().cmp(&right.plan_id.to_string())),
        "source_type" => {
            Some(response_plan_source_type(left).cmp(&response_plan_source_type(right)))
        }
        "source_ref" => Some(response_plan_source_ref(left).cmp(&response_plan_source_ref(right))),
        "created_at" => Some(left.created_at.cmp(&right.created_at)),
        "approval_required" => Some(left.approval_required.cmp(&right.approval_required)),
        "is_replay" => Some(left.is_replay.cmp(&right.is_replay)),
        "execution_disabled_in_replay" => Some(
            left.execution_disabled_in_replay
                .cmp(&right.execution_disabled_in_replay),
        ),
        "recommended_action_count" => Some(
            left.recommended_actions
                .len()
                .cmp(&right.recommended_actions.len()),
        ),
        "policy_decision_count" => Some(
            left.policy_decisions
                .len()
                .cmp(&right.policy_decisions.len()),
        ),
        "rollback_plan_count" => Some(left.rollback_plans.len().cmp(&right.rollback_plans.len())),
        _ => None,
    }
}

fn compare_reports(left: &Report, right: &Report, field: &str) -> Option<Ordering> {
    match field {
        "id" | "report_id" => Some(left.report_id.to_string().cmp(&right.report_id.to_string())),
        "type" | "report_type" => {
            Some(enum_token(&left.report_type).cmp(&enum_token(&right.report_type)))
        }
        "title" | "title_redacted" => Some(left.title_redacted.cmp(&right.title_redacted)),
        "summary" | "summary_redacted" => Some(left.summary_redacted.cmp(&right.summary_redacted)),
        "status" => Some(enum_token(&left.status).cmp(&enum_token(&right.status))),
        "created_at" => Some(left.created_at.cmp(&right.created_at)),
        "updated_at" => Some(left.updated_at.cmp(&right.updated_at)),
        "section_count" => Some(left.sections.len().cmp(&right.sections.len())),
        "incident_count" => Some(left.incident_refs.len().cmp(&right.incident_refs.len())),
        "alert_count" => Some(left.alert_refs.len().cmp(&right.alert_refs.len())),
        "finding_count" => Some(left.finding_refs.len().cmp(&right.finding_refs.len())),
        "evidence_count" => Some(left.evidence_refs.len().cmp(&right.evidence_refs.len())),
        "graph_snapshot_count" => Some(
            left.graph_snapshot_refs
                .len()
                .cmp(&right.graph_snapshot_refs.len()),
        ),
        "response_result_count" => Some(
            left.response_result_refs
                .len()
                .cmp(&right.response_result_refs.len()),
        ),
        "rollback_result_count" => Some(
            left.rollback_result_refs
                .len()
                .cmp(&right.rollback_result_refs.len()),
        ),
        "redaction_passed" => Some(
            left.redaction_summary
                .passed
                .cmp(&right.redaction_summary.passed),
        ),
        "redacted_field_count" => Some(
            left.redaction_summary
                .redacted_field_count
                .cmp(&right.redaction_summary.redacted_field_count),
        ),
        "suppressed_section_count" => Some(
            left.redaction_summary
                .suppressed_section_count
                .cmp(&right.redaction_summary.suppressed_section_count),
        ),
        _ => None,
    }
}

fn compare_components(
    left: &ComponentSummary,
    right: &ComponentSummary,
    field: &str,
) -> Option<Ordering> {
    match field {
        "id" | "component_id" => Some(
            left.component_id
                .to_string()
                .cmp(&right.component_id.to_string()),
        ),
        "component_type" => {
            Some(enum_token(&left.component_type).cmp(&enum_token(&right.component_type)))
        }
        "name" => Some(left.name.cmp(&right.name)),
        "version" => Some(left.version.cmp(&right.version)),
        "state" => Some(enum_token(&left.state).cmp(&enum_token(&right.state))),
        "health_status" => {
            Some(enum_token(&left.health_status).cmp(&enum_token(&right.health_status)))
        }
        "runtime_mode" => {
            Some(enum_token(&left.runtime_mode).cmp(&enum_token(&right.runtime_mode)))
        }
        "plugin_id" => Some(compare_optional_to_string(
            left.plugin_id.as_ref(),
            right.plugin_id.as_ref(),
        )),
        "capability_domain" => Some(
            left.capability_domain
                .as_ref()
                .cmp(&right.capability_domain.as_ref()),
        ),
        "capability_tag_count" => {
            Some(left.capability_tags.len().cmp(&right.capability_tags.len()))
        }
        _ => None,
    }
}

fn compare_plugins(left: &PluginManifest, right: &PluginManifest, field: &str) -> Option<Ordering> {
    match field {
        "id" | "plugin_id" => Some(left.plugin_id.to_string().cmp(&right.plugin_id.to_string())),
        "name" | "plugin_name" => Some(left.plugin_name.cmp(&right.plugin_name)),
        "version" => Some(left.version.cmp(&right.version)),
        "capability_domain" => Some(left.capability_domain.cmp(&right.capability_domain)),
        "plugin_type" => Some(enum_token(&left.plugin_type).cmp(&enum_token(&right.plugin_type))),
        "runtime_mode" => {
            Some(enum_token(&left.runtime_mode).cmp(&enum_token(&right.runtime_mode)))
        }
        "maturity_level" => {
            Some(enum_token(&left.maturity_level).cmp(&enum_token(&right.maturity_level)))
        }
        "enabled_by_default" => Some(left.enabled_by_default.cmp(&right.enabled_by_default)),
        "input_contract_count" => {
            Some(left.input_contracts.len().cmp(&right.input_contracts.len()))
        }
        "output_contract_count" => Some(
            left.output_contracts
                .len()
                .cmp(&right.output_contracts.len()),
        ),
        "permission_count" => Some(
            left.required_permissions
                .len()
                .cmp(&right.required_permissions.len()),
        ),
        "capability_tag_count" => {
            Some(left.capability_tags.len().cmp(&right.capability_tags.len()))
        }
        _ => None,
    }
}

fn compare_capabilities(
    left: &CapabilityOverview,
    right: &CapabilityOverview,
    field: &str,
) -> Option<Ordering> {
    match field {
        "id" | "capability_id" => Some(
            left.capability
                .capability_id
                .to_string()
                .cmp(&right.capability.capability_id.to_string()),
        ),
        "domain" | "capability_domain" => Some(
            left.capability
                .capability_domain
                .cmp(&right.capability.capability_domain),
        ),
        "title" => Some(left.capability.title.cmp(&right.capability.title)),
        "maturity_level" => Some(
            enum_token(&left.capability.maturity_level)
                .cmp(&enum_token(&right.capability.maturity_level)),
        ),
        "plugin_count" => Some(left.plugin_count.cmp(&right.plugin_count)),
        "required_permission_count" => Some(
            left.required_permission_count
                .cmp(&right.required_permission_count),
        ),
        "ui_contribution_count" => {
            Some(left.ui_contribution_count.cmp(&right.ui_contribution_count))
        }
        "health_status" => {
            Some(enum_token(&left.health_status).cmp(&enum_token(&right.health_status)))
        }
        _ => None,
    }
}

fn compare_runtime_profiles(
    left: &RuntimeProfile,
    right: &RuntimeProfile,
    field: &str,
) -> Option<Ordering> {
    match field {
        "id" | "profile_id" => Some(
            left.profile_id
                .to_string()
                .cmp(&right.profile_id.to_string()),
        ),
        "name" => Some(enum_token(&left.name).cmp(&enum_token(&right.name))),
        "display_name" => Some(left.display_name.cmp(&right.display_name)),
        "created_at" => Some(left.created_at.cmp(&right.created_at)),
        "updated_at" => Some(left.updated_at.cmp(&right.updated_at)),
        "is_default" => Some(left.is_default.cmp(&right.is_default)),
        "response_mode" => Some(
            enum_token(&left.response_policy.mode).cmp(&enum_token(&right.response_policy.mode)),
        ),
        "forensic_mode_enabled" => Some(
            left.privacy_policy
                .forensic_mode
                .enabled
                .cmp(&right.privacy_policy.forensic_mode.enabled),
        ),
        _ => None,
    }
}

fn compare_service_status(
    left: &ServiceStatusView,
    right: &ServiceStatusView,
    field: &str,
) -> Option<Ordering> {
    match field {
        "generated_at" => Some(left.generated_at.cmp(&right.generated_at)),
        "connected" => Some(left.connected.cmp(&right.connected)),
        "degraded" => Some(left.degraded.cmp(&right.degraded)),
        "profile_mode" => Some(left.profile_mode.cmp(&right.profile_mode)),
        "local_core_status" => {
            Some(enum_token(&left.local_core_status).cmp(&enum_token(&right.local_core_status)))
        }
        "elevated_service_status" => Some(
            enum_token(&left.elevated_service_status)
                .cmp(&enum_token(&right.elevated_service_status)),
        ),
        "ipc_status" => Some(enum_token(&left.ipc_status).cmp(&enum_token(&right.ipc_status))),
        "storage_status" => {
            Some(enum_token(&left.storage_status).cmp(&enum_token(&right.storage_status)))
        }
        "reduced_visibility" => Some(left.reduced_visibility.cmp(&right.reduced_visibility)),
        "privileged_actions_available" => Some(
            left.privileged_actions_available
                .cmp(&right.privileged_actions_available),
        ),
        "capture_available" => Some(left.capture_available.cmp(&right.capture_available)),
        _ => None,
    }
}

fn response_plan_source_type(plan: &ResponsePlan) -> String {
    match &plan.source {
        sentinel_contracts::ResponsePlanSource::Finding(_) => "finding",
        sentinel_contracts::ResponsePlanSource::Alert(_) => "alert",
        sentinel_contracts::ResponsePlanSource::Incident(_) => "incident",
        sentinel_contracts::ResponsePlanSource::GraphPath(_) => "graph_path",
    }
    .to_string()
}

fn response_plan_source_ref(plan: &ResponsePlan) -> String {
    match &plan.source {
        sentinel_contracts::ResponsePlanSource::Finding(id) => id.to_string(),
        sentinel_contracts::ResponsePlanSource::Alert(id) => id.to_string(),
        sentinel_contracts::ResponsePlanSource::Incident(id) => id.to_string(),
        sentinel_contracts::ResponsePlanSource::GraphPath(id) => id.to_string(),
    }
}

fn optional_to_values<T: ToString>(value: Option<&T>) -> Vec<String> {
    value.map(ToString::to_string).into_iter().collect()
}

fn compare_optional_to_string<T: ToString>(left: Option<&T>, right: Option<&T>) -> Ordering {
    let left = left.map(ToString::to_string);
    let right = right.map(ToString::to_string);
    left.cmp(&right)
}

fn entity_ref_to_values(value: Option<&sentinel_contracts::EntityRef>) -> Vec<String> {
    value
        .map(|entity| entity.entity_id.to_string())
        .into_iter()
        .collect()
}

fn enum_token<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(token)) => token,
        _ => String::new(),
    }
}

fn normalize_query_value(value: impl AsRef<str>) -> String {
    value.as_ref().trim().to_ascii_lowercase()
}

fn severity_rank(severity: &SecuritySeverity) -> u8 {
    match severity {
        SecuritySeverity::Informational => 0,
        SecuritySeverity::Low => 1,
        SecuritySeverity::Medium => 2,
        SecuritySeverity::High => 3,
        SecuritySeverity::Critical => 4,
    }
}

fn validate_query_page_and_time_range(
    request: &QueryRequest,
    store_kind: &StoreKind,
) -> CommandResult<()> {
    request.page.validate().map_err(|error| {
        command_error(
            ErrorCode::InvalidRequest,
            "invalid page request",
            json!({
                "store_kind": store_kind.to_string(),
                "error_redacted": error.to_string()
            }),
        )
    })?;
    if let Some(time_range) = &request.time_range {
        time_range.validate().map_err(|error| {
            command_error(
                ErrorCode::InvalidRequest,
                "invalid time range",
                json!({
                    "store_kind": store_kind.to_string(),
                    "error_redacted": error.to_string()
                }),
            )
        })?;
    }
    Ok(())
}

fn page_items<T: Clone>(
    items: &[T],
    page: &PageRequest,
    store_kind: &StoreKind,
) -> CommandResult<PageResponse<T>> {
    let start = page
        .cursor
        .as_ref()
        .map(|cursor| decode_read_cursor(cursor.as_str(), store_kind))
        .transpose()?
        .unwrap_or(0);

    if start > items.len() {
        return Err(command_error(
            ErrorCode::InvalidRequest,
            "cursor is outside the current read model",
            json!({
                "store_kind": store_kind.to_string(),
                "cursor_position": start,
                "item_count": items.len()
            }),
        ));
    }

    let end = usize::min(start + page.limit as usize, items.len());
    let has_more = end < items.len();
    let next_cursor = if has_more {
        Some(encode_read_cursor(store_kind, end)?)
    } else {
        None
    };

    Ok(PageResponse::from_request(
        items[start..end].to_vec(),
        page,
        next_cursor,
        has_more,
    ))
}

fn encode_read_cursor(
    store_kind: &StoreKind,
    index: usize,
) -> CommandResult<sentinel_contracts::Cursor> {
    sentinel_contracts::Cursor::new(format!(
        "{READ_CURSOR_PREFIX}|{}|{}",
        store_kind.as_str(),
        index
    ))
    .map_err(|error| {
        internal_error(
            "read_cursor",
            "failed to encode read cursor",
            json!({ "error_redacted": error.to_string() }),
        )
    })
}

fn decode_read_cursor(value: &str, expected_store_kind: &StoreKind) -> CommandResult<usize> {
    let mut parts = value.splitn(3, '|');
    let prefix = parts.next();
    let store_kind = parts.next();
    let index = parts.next();

    match (prefix, store_kind, index) {
        (Some(READ_CURSOR_PREFIX), Some(store_kind), Some(index))
            if store_kind == expected_store_kind.as_str() =>
        {
            index.parse::<usize>().map_err(|_| {
                command_error(
                    ErrorCode::InvalidRequest,
                    "cursor position is invalid",
                    json!({
                        "store_kind": expected_store_kind.to_string(),
                        "cursor_redacted": value
                    }),
                )
            })
        }
        _ => Err(command_error(
            ErrorCode::InvalidRequest,
            "cursor was not produced by this read command",
            json!({
                "expected_store_kind": expected_store_kind.to_string(),
                "cursor_redacted": value
            }),
        )),
    }
}

#[derive(Clone)]
struct AttackCoverageCatalogEntry {
    tactic_id: &'static str,
    technique_id: &'static str,
    package_category: &'static str,
    detector_id: &'static str,
    required_visibility: AttackRequiredVisibility,
    confidence_bucket: AttackCoverageConfidenceBucket,
    states: Vec<AttackCoverageState>,
    degraded_reason: Option<&'static str>,
}

#[derive(Clone)]
struct AttackCoverageAccumulator {
    tactic_id: String,
    technique_id: String,
    attack_version: String,
    package_category: String,
    required_visibility: AttackRequiredVisibility,
    confidence_bucket: AttackCoverageConfidenceBucket,
    rule_detector_ids: Vec<String>,
    finding_refs: Vec<FindingId>,
    evidence_refs: Vec<EvidenceId>,
    risk_refs: Vec<RiskEventId>,
    states: Vec<AttackCoverageState>,
    degraded_reason: Option<String>,
    observed_count: u32,
    last_observed: AttackLastObservedBucket,
}

impl AttackCoverageAccumulator {
    fn from_catalog(entry: &AttackCoverageCatalogEntry) -> Self {
        Self {
            tactic_id: entry.tactic_id.to_string(),
            technique_id: entry.technique_id.to_string(),
            attack_version: ATTACK_COVERAGE_VERSION.to_string(),
            package_category: entry.package_category.to_string(),
            required_visibility: entry.required_visibility.clone(),
            confidence_bucket: entry.confidence_bucket.clone(),
            rule_detector_ids: vec![entry.detector_id.to_string()],
            finding_refs: Vec::new(),
            evidence_refs: Vec::new(),
            risk_refs: Vec::new(),
            states: entry.states.clone(),
            degraded_reason: entry.degraded_reason.map(str::to_string),
            observed_count: 0,
            last_observed: AttackLastObservedBucket::None,
        }
    }

    fn from_mapping(
        finding: &Finding,
        mapping: &sentinel_contracts::AttackMapping,
        tactic_id: &str,
        technique_id: &str,
        package_category: &str,
        risk_refs: &[RiskEventId],
    ) -> Self {
        let mut accumulator = Self {
            tactic_id: tactic_id.to_string(),
            technique_id: technique_id.to_string(),
            attack_version: attack_version_for_mapping(mapping),
            package_category: package_category.to_string(),
            required_visibility: required_visibility_for_package(package_category),
            confidence_bucket: confidence_bucket_for_mapping(mapping),
            rule_detector_ids: Vec::new(),
            finding_refs: Vec::new(),
            evidence_refs: Vec::new(),
            risk_refs: Vec::new(),
            states: vec![AttackCoverageState::Covered],
            degraded_reason: Some(degraded_reason_for_mapping(mapping)),
            observed_count: 0,
            last_observed: AttackLastObservedBucket::None,
        };
        accumulator.merge_mapping(finding, mapping, package_category, risk_refs);
        accumulator
    }

    fn merge_catalog(&mut self, entry: &AttackCoverageCatalogEntry) {
        push_bounded_unique_string(&mut self.rule_detector_ids, entry.detector_id.to_string());
        for state in &entry.states {
            push_unique_state(&mut self.states, state.clone());
        }
        if self.degraded_reason.is_none() {
            self.degraded_reason = entry.degraded_reason.map(str::to_string);
        }
        self.confidence_bucket = max_confidence_bucket(
            self.confidence_bucket.clone(),
            entry.confidence_bucket.clone(),
        );
    }

    fn merge_mapping(
        &mut self,
        finding: &Finding,
        mapping: &sentinel_contracts::AttackMapping,
        package_category: &str,
        risk_refs: &[RiskEventId],
    ) {
        self.attack_version = attack_version_for_mapping(mapping);
        self.package_category = package_category.to_string();
        self.required_visibility = required_visibility_for_package(package_category);
        self.confidence_bucket = max_confidence_bucket(
            self.confidence_bucket.clone(),
            confidence_bucket_for_mapping(mapping),
        );
        push_bounded_unique_string(
            &mut self.rule_detector_ids,
            safe_detector_id_for_package(package_category).to_string(),
        );
        push_unique_state(&mut self.states, AttackCoverageState::Covered);
        push_unique_state(&mut self.states, AttackCoverageState::Observed);
        if !finding.evidence_refs().is_empty() {
            push_unique_state(&mut self.states, AttackCoverageState::EvidenceBacked);
        }
        push_unique_state(&mut self.states, AttackCoverageState::Degraded);
        push_bounded_unique_ref(&mut self.finding_refs, finding.id().clone());
        for evidence_id in finding.evidence_refs() {
            push_bounded_unique_ref(&mut self.evidence_refs, evidence_id.clone());
        }
        for risk_ref in risk_refs {
            push_bounded_unique_ref(&mut self.risk_refs, risk_ref.clone());
        }
        self.degraded_reason = Some(degraded_reason_for_mapping(mapping));
        self.observed_count = self.observed_count.saturating_add(1);
        self.last_observed = if mapping
            .provenance
            .as_ref()
            .and_then(|provenance| provenance.mapped_at.clone())
            .is_some()
        {
            AttackLastObservedBucket::CurrentSession
        } else {
            AttackLastObservedBucket::Unknown
        };
    }

    fn into_row(mut self) -> CommandResult<AttackCoverageTechniqueRow> {
        self.rule_detector_ids.sort();
        self.rule_detector_ids.dedup();
        self.rule_detector_ids
            .truncate(sentinel_contracts::MAX_ATTACK_COVERAGE_RULE_IDS);
        self.finding_refs = bounded_unique_refs_by_string(self.finding_refs);
        self.evidence_refs = bounded_unique_refs_by_string(self.evidence_refs);
        self.risk_refs = bounded_unique_refs_by_string(self.risk_refs);
        self.states = ordered_attack_states(self.states);
        self.confidence_bucket = cap_confidence_for_visibility(
            self.confidence_bucket,
            &self.required_visibility,
            &self.states,
            &self.tactic_id,
        );
        let observed_count_bucket = observed_count_bucket(self.observed_count);
        let mut row = AttackCoverageTechniqueRow::new(
            self.tactic_id,
            self.technique_id,
            self.attack_version,
            self.rule_detector_ids,
            self.confidence_bucket,
            self.required_visibility,
            self.package_category,
            observed_count_bucket,
            self.last_observed,
            self.states,
        )
        .map_err(|error| {
            internal_error(
                "attack_coverage",
                "failed to create ATT&CK coverage row",
                json!({ "error_redacted": error.to_string() }),
            )
        })?;
        row.finding_refs = self.finding_refs;
        row.evidence_refs = self.evidence_refs;
        row.risk_refs = self.risk_refs;
        row.degraded_reason = self.degraded_reason;
        row.validate().map_err(|error| {
            internal_error(
                "attack_coverage",
                "ATT&CK coverage row failed safety validation",
                json!({ "error_redacted": error.to_string() }),
            )
        })?;
        Ok(row)
    }
}

fn attack_coverage_catalog_entries() -> Vec<AttackCoverageCatalogEntry> {
    let supported_states = || vec![AttackCoverageState::Covered, AttackCoverageState::Degraded];
    let native_states = || {
        vec![
            AttackCoverageState::Unsupported,
            AttackCoverageState::RequiresAuthorizedNativeExtension,
        ]
    };
    vec![
        AttackCoverageCatalogEntry {
            tactic_id: "TA0011",
            technique_id: "T1071.004",
            package_category: "dns_security_v2",
            detector_id: "portable_dns_security_v2",
            required_visibility: AttackRequiredVisibility::PortableNetworkMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0011",
            technique_id: "T1071.001",
            package_category: "http_analysis_v1",
            detector_id: "portable_http_analysis_v1",
            required_visibility: AttackRequiredVisibility::PortableNetworkMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0011",
            technique_id: "T1071.001",
            package_category: "api_security_lite",
            detector_id: "portable_api_security_lite",
            required_visibility: AttackRequiredVisibility::PortableNetworkMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0011",
            technique_id: "T1071.001",
            package_category: "waf_security_lite",
            detector_id: "portable_waf_security_lite",
            required_visibility: AttackRequiredVisibility::PortableNetworkMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0011",
            technique_id: "T1071.001",
            package_category: "quic_http3_security_lite",
            detector_id: "portable_quic_http3_security_lite",
            required_visibility: AttackRequiredVisibility::PortableNetworkMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0008",
            technique_id: "T1021.001",
            package_category: "smb_rdp_ssh_observation_lite",
            detector_id: "portable_smb_rdp_ssh_observation_lite",
            required_visibility: AttackRequiredVisibility::PortableNetworkMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0008",
            technique_id: "T1021.002",
            package_category: "smb_rdp_ssh_observation_lite",
            detector_id: "portable_smb_rdp_ssh_observation_lite",
            required_visibility: AttackRequiredVisibility::PortableNetworkMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0008",
            technique_id: "T1021.004",
            package_category: "smb_rdp_ssh_observation_lite",
            detector_id: "portable_smb_rdp_ssh_observation_lite",
            required_visibility: AttackRequiredVisibility::PortableNetworkMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0006",
            technique_id: "T1110",
            package_category: "auth_identity_analysis_lite",
            detector_id: "portable_auth_identity_analysis_lite",
            required_visibility: AttackRequiredVisibility::PortableAuthMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0001",
            technique_id: "T1621",
            package_category: "auth_identity_analysis_lite",
            detector_id: "portable_auth_identity_analysis_lite",
            required_visibility: AttackRequiredVisibility::PortableAuthMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0010",
            technique_id: "T1567.002",
            package_category: "provider_category_saas_cloud_abuse_lite",
            detector_id: "portable_provider_category_saas_cloud_abuse_lite",
            required_visibility: AttackRequiredVisibility::PortableProviderMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0001",
            technique_id: "T1078",
            package_category: "provider_category_saas_cloud_abuse_lite",
            detector_id: "portable_provider_category_saas_cloud_abuse_lite",
            required_visibility: AttackRequiredVisibility::PortableProviderMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0007",
            technique_id: "T1046",
            package_category: "deception_honeypot_event_ingest_lite",
            detector_id: "portable_deception_honeypot_event_ingest_lite",
            required_visibility: AttackRequiredVisibility::PortableDeceptionMetadata,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: supported_states(),
            degraded_reason: Some("metadata_only_visibility"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0002",
            technique_id: "T1059",
            package_category: "authorized_native_extension",
            detector_id: "authorized_native_extension_required",
            required_visibility: AttackRequiredVisibility::AuthorizedNativeProcessVisibility,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: native_states(),
            degraded_reason: Some("authorized_native_extension_required"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0003",
            technique_id: "T1547",
            package_category: "authorized_native_extension",
            detector_id: "authorized_native_extension_required",
            required_visibility: AttackRequiredVisibility::AuthorizedNativeProcessVisibility,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: native_states(),
            degraded_reason: Some("authorized_native_extension_required"),
        },
        AttackCoverageCatalogEntry {
            tactic_id: "TA0004",
            technique_id: "T1068",
            package_category: "authorized_native_extension",
            detector_id: "authorized_native_extension_required",
            required_visibility: AttackRequiredVisibility::AuthorizedNativeExtension,
            confidence_bucket: AttackCoverageConfidenceBucket::Low,
            states: native_states(),
            degraded_reason: Some("authorized_native_extension_required"),
        },
    ]
}

fn risk_refs_by_finding(state: &ReadOnlyCommandState) -> BTreeMap<String, Vec<RiskEventId>> {
    let mut refs = BTreeMap::<String, Vec<RiskEventId>>::new();
    for alert in &state.alerts.items {
        for finding_id in alert.finding_refs() {
            let entry = refs.entry(finding_id.to_string()).or_default();
            for risk_ref in alert.risk_event_refs() {
                push_bounded_unique_ref(entry, risk_ref.clone());
            }
        }
    }
    refs
}

fn attack_coverage_key(tactic_id: &str, technique_id: &str, package_category: &str) -> String {
    format!("{tactic_id}|{technique_id}|{package_category}")
}

fn attack_package_category(finding_type: &str) -> &'static str {
    if finding_type.starts_with("portable.dns_security_v2.") {
        "dns_security_v2"
    } else if finding_type.starts_with("portable.http_analysis_v1.") {
        "http_analysis_v1"
    } else if finding_type.starts_with("portable.api_security_lite.") {
        "api_security_lite"
    } else if finding_type.starts_with("portable.waf_security_lite.") {
        "waf_security_lite"
    } else if finding_type.starts_with("portable.quic_http3_security_lite.") {
        "quic_http3_security_lite"
    } else if finding_type.starts_with("portable.remote_admin_protocol_lite.") {
        "smb_rdp_ssh_observation_lite"
    } else if finding_type.starts_with("portable.auth_identity_analysis_lite.") {
        "auth_identity_analysis_lite"
    } else if finding_type.starts_with("portable.saas_cloud_abuse_lite.") {
        "provider_category_saas_cloud_abuse_lite"
    } else if finding_type.starts_with("portable.deception_event_lite.") {
        "deception_honeypot_event_ingest_lite"
    } else {
        "portable_other"
    }
}

fn safe_detector_id_for_package(package_category: &str) -> &'static str {
    match package_category {
        "dns_security_v2" => "portable_dns_security_v2",
        "http_analysis_v1" => "portable_http_analysis_v1",
        "api_security_lite" => "portable_api_security_lite",
        "waf_security_lite" => "portable_waf_security_lite",
        "quic_http3_security_lite" => "portable_quic_http3_security_lite",
        "smb_rdp_ssh_observation_lite" => "portable_smb_rdp_ssh_observation_lite",
        "auth_identity_analysis_lite" => "portable_auth_identity_analysis_lite",
        "provider_category_saas_cloud_abuse_lite" => {
            "portable_provider_category_saas_cloud_abuse_lite"
        }
        "deception_honeypot_event_ingest_lite" => "portable_deception_honeypot_event_ingest_lite",
        _ => "portable_metadata_detector",
    }
}

fn required_visibility_for_package(package_category: &str) -> AttackRequiredVisibility {
    match package_category {
        "auth_identity_analysis_lite" => AttackRequiredVisibility::PortableAuthMetadata,
        "provider_category_saas_cloud_abuse_lite" => {
            AttackRequiredVisibility::PortableProviderMetadata
        }
        "deception_honeypot_event_ingest_lite" => {
            AttackRequiredVisibility::PortableDeceptionMetadata
        }
        "authorized_native_extension" => AttackRequiredVisibility::AuthorizedNativeExtension,
        _ => AttackRequiredVisibility::PortableNetworkMetadata,
    }
}

fn attack_version_for_mapping(mapping: &sentinel_contracts::AttackMapping) -> String {
    mapping
        .provenance
        .as_ref()
        .and_then(|provenance| provenance.source_version.clone())
        .unwrap_or_else(|| ATTACK_COVERAGE_VERSION.to_string())
}

fn confidence_bucket_for_mapping(
    mapping: &sentinel_contracts::AttackMapping,
) -> AttackCoverageConfidenceBucket {
    let confidence = mapping.mapping_confidence.value();
    if confidence <= 0.0 {
        AttackCoverageConfidenceBucket::Unknown
    } else if confidence < 0.4 {
        AttackCoverageConfidenceBucket::Low
    } else if confidence < 0.75 {
        AttackCoverageConfidenceBucket::Medium
    } else {
        AttackCoverageConfidenceBucket::High
    }
}

fn degraded_reason_for_mapping(mapping: &sentinel_contracts::AttackMapping) -> String {
    let allowlisted = mapping
        .provenance
        .as_ref()
        .map(|provenance| provenance.source.contains("allowlist"))
        .unwrap_or(false);
    if allowlisted {
        "metadata_only_allowlisted".to_string()
    } else {
        "single_signal_or_missing_context".to_string()
    }
}

fn observed_count_bucket(count: u32) -> AttackObservedCountBucket {
    match count {
        0 => AttackObservedCountBucket::None,
        1 => AttackObservedCountBucket::Single,
        2..=4 => AttackObservedCountBucket::Low,
        5..=16 => AttackObservedCountBucket::Medium,
        _ => AttackObservedCountBucket::High,
    }
}

fn max_confidence_bucket(
    left: AttackCoverageConfidenceBucket,
    right: AttackCoverageConfidenceBucket,
) -> AttackCoverageConfidenceBucket {
    if confidence_rank(&right) > confidence_rank(&left) {
        right
    } else {
        left
    }
}

fn cap_confidence_for_visibility(
    confidence: AttackCoverageConfidenceBucket,
    required_visibility: &AttackRequiredVisibility,
    states: &[AttackCoverageState],
    tactic_id: &str,
) -> AttackCoverageConfidenceBucket {
    if confidence != AttackCoverageConfidenceBucket::High {
        return confidence;
    }
    let degraded_or_native = states.contains(&AttackCoverageState::Degraded)
        || states.contains(&AttackCoverageState::Unsupported)
        || states.contains(&AttackCoverageState::RequiresAuthorizedNativeExtension)
        || matches!(
            required_visibility,
            AttackRequiredVisibility::AuthorizedNativeProcessVisibility
                | AttackRequiredVisibility::AuthorizedNativeExtension
                | AttackRequiredVisibility::Unsupported
        );
    if degraded_or_native || matches!(tactic_id, "TA0002" | "TA0003" | "TA0004" | "TA0006") {
        AttackCoverageConfidenceBucket::Medium
    } else {
        confidence
    }
}

fn confidence_rank(bucket: &AttackCoverageConfidenceBucket) -> u8 {
    match bucket {
        AttackCoverageConfidenceBucket::Unknown => 0,
        AttackCoverageConfidenceBucket::Low => 1,
        AttackCoverageConfidenceBucket::Medium => 2,
        AttackCoverageConfidenceBucket::High => 3,
    }
}

fn ordered_attack_states(states: Vec<AttackCoverageState>) -> Vec<AttackCoverageState> {
    let mut ordered = Vec::new();
    for candidate in [
        AttackCoverageState::Covered,
        AttackCoverageState::Observed,
        AttackCoverageState::EvidenceBacked,
        AttackCoverageState::Degraded,
        AttackCoverageState::Unsupported,
        AttackCoverageState::RequiresAuthorizedNativeExtension,
    ] {
        if states.contains(&candidate) {
            ordered.push(candidate);
        }
    }
    ordered
}

fn attack_state_label(state: &AttackCoverageState) -> String {
    match state {
        AttackCoverageState::Covered => "covered",
        AttackCoverageState::Observed => "observed",
        AttackCoverageState::EvidenceBacked => "evidence_backed",
        AttackCoverageState::Degraded => "degraded",
        AttackCoverageState::Unsupported => "unsupported",
        AttackCoverageState::RequiresAuthorizedNativeExtension => {
            "requires_authorized_native_extension"
        }
    }
    .to_string()
}

fn attack_count_summary(
    labels: impl Iterator<Item = String>,
) -> CommandResult<Vec<AttackCoverageCount>> {
    let mut counts = BTreeMap::<String, u32>::new();
    for label in labels {
        *counts.entry(label).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(label, count)| {
            AttackCoverageCount::new(label, count).map_err(|error| {
                internal_error(
                    "attack_coverage",
                    "failed to create ATT&CK coverage count",
                    json!({ "error_redacted": error.to_string() }),
                )
            })
        })
        .collect()
}

fn push_unique_state(states: &mut Vec<AttackCoverageState>, state: AttackCoverageState) {
    if !states.contains(&state) {
        states.push(state);
    }
}

fn push_bounded_unique_string(values: &mut Vec<String>, value: String) {
    if values.len() < MAX_ATTACK_COVERAGE_REFS && !values.contains(&value) {
        values.push(value);
    }
}

fn push_bounded_unique_ref<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if values.len() < MAX_ATTACK_COVERAGE_REFS && !values.contains(&value) {
        values.push(value);
    }
}

fn bounded_unique_refs_by_string<T: Clone + ToString>(mut values: Vec<T>) -> Vec<T> {
    values.sort_by_key(ToString::to_string);
    values.dedup_by(|left, right| left.to_string() == right.to_string());
    values.truncate(MAX_ATTACK_COVERAGE_REFS);
    values
}

fn registry_error(context: &'static str) -> impl FnOnce(RegistryError) -> CoreError {
    move |error| {
        internal_error(
            context,
            "registry bootstrap failed",
            json!({ "error_redacted": error.to_string() }),
        )
    }
}

fn unsupported_scope_error(store_kind: &StoreKind) -> CoreError {
    command_error(
        ErrorCode::UnsupportedOperation,
        "query scope is not supported by this read command yet",
        json!({
            "store_kind": store_kind.to_string(),
            "reason_redacted": "scope is outside the selected read-model family"
        }),
    )
}

fn unsupported_filter_field_error(store_kind: &StoreKind, index: usize) -> CoreError {
    command_error(
        ErrorCode::UnsupportedOperation,
        "query filter field is not supported by this read command yet",
        json!({
            "store_kind": store_kind.to_string(),
            "filter_index": index,
            "reason_redacted": "field is not in the selected read-model allowlist"
        }),
    )
}

fn unsupported_filter_operator_error(store_kind: &StoreKind, index: usize) -> CoreError {
    command_error(
        ErrorCode::UnsupportedOperation,
        "query filter operator is not supported by this read command yet",
        json!({
            "store_kind": store_kind.to_string(),
            "filter_index": index,
            "reason_redacted": "range operators require timestamp or numeric indexes"
        }),
    )
}

fn unsupported_filter_value_error(store_kind: &StoreKind, index: usize) -> CoreError {
    command_error(
        ErrorCode::UnsupportedOperation,
        "query filter value is not supported by this read command yet",
        json!({
            "store_kind": store_kind.to_string(),
            "filter_index": index,
            "reason_redacted": "null filter values are not supported for selected read models"
        }),
    )
}

fn unsupported_sort_field_error(store_kind: &StoreKind, index: usize) -> CoreError {
    command_error(
        ErrorCode::UnsupportedOperation,
        "query sort field is not supported by this read command yet",
        json!({
            "store_kind": store_kind.to_string(),
            "sort_index": index,
            "reason_redacted": "field is not in the selected read-model sort allowlist"
        }),
    )
}

fn not_found_error(resource: &'static str, details: Value) -> CoreError {
    command_error(
        ErrorCode::InvalidRequest,
        format!("{resource} was not found"),
        json!({ "resource": resource, "lookup": details }),
    )
}

fn internal_error(context: &'static str, message: impl Into<String>, details: Value) -> CoreError {
    command_error(
        ErrorCode::InternalError,
        message,
        json!({ "context": context, "details": details }),
    )
    .with_severity(ErrorSeverity::Error)
}

fn command_error(error_code: ErrorCode, message: impl Into<String>, details: Value) -> CoreError {
    CoreError::new(error_code, message)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(details)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use sentinel_contracts::report::ExportFormat;
    use sentinel_contracts::{
        Alert, ApprovalState, AuditId, DataSourceId, EntityId, EntityRef, EntityType, EvidenceId,
        FindingExplanation, GraphScope, GraphSnapshotId, IpAddress, MetadataParserFamily,
        MetadataRetentionMode, MetadataSamplingMode, MetadataSourceHealthState,
        MetadataWatchCheckpoint, MetadataWatchCounters, MetadataWatchSourceKind,
        MetadataWatchSourceState, NetworkDirection, RedactedDataCategory, RedactionSummary,
        ReportSection, ReportSectionType, ReportStatus, ReportType, ResponseActionType,
        ResponseLevel, ResponsePlanSource, ResponseResultId, ResponseScope, ResponseTarget,
        RollbackResultId, SecurityFactId, TransportProtocol,
    };

    #[test]
    fn bootstrap_exposes_catalog_components_and_capabilities() {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");

        let catalog = get_plugin_catalog(&state).expect("plugin catalog");
        assert_eq!(catalog.plugins.len(), 30);
        assert!(!catalog.production_ready);
        assert!(!catalog.mock_only);
        assert!(catalog
            .plugins
            .iter()
            .any(|plugin| plugin.plugin_name == "Asset Exposure"));
        assert!(catalog
            .plugins
            .iter()
            .any(|plugin| plugin.plugin_name == "Exfiltration Detection"));
        assert!(catalog
            .plugins
            .iter()
            .any(|plugin| plugin.plugin_name == "C2 Detection"));
        assert!(catalog
            .plugins
            .iter()
            .any(|plugin| plugin.plugin_name == "Native Network Fact Runtime"));
        assert!(catalog
            .plugins
            .iter()
            .any(|plugin| plugin.plugin_name == "Lateral Movement Lite"));
        assert!(catalog
            .plugins
            .iter()
            .any(|plugin| plugin.plugin_name == "Multi-Layer Security Fusion"));
        assert!(catalog
            .plugins
            .iter()
            .any(|plugin| plugin.plugin_name == "Native Sampler Fact Runtime"));
        assert!(catalog
            .plugins
            .iter()
            .any(|plugin| plugin.plugin_name == "Endpoint Threat Analysis Lite"));
        assert!(catalog.plugins.iter().all(|plugin| plugin
            .capability_tags
            .iter()
            .any(|tag| tag == "STATIC_INTERNAL")));
        assert!(catalog
            .plugins
            .iter()
            .all(|plugin| !plugin.capability_tags.iter().any(|tag| tag == "MOCK_ONLY")));

        let components = list_components(&state).expect("components");
        assert_eq!(components.len(), catalog.plugins.len());
        assert!(components
            .iter()
            .all(|component| component.state == ComponentState::Running));

        let capabilities = get_capability_overview(&state).expect("capabilities");
        assert!(capabilities.len() >= 7);
        assert!(capabilities
            .iter()
            .all(|capability| capability.plugin_count > 0));
        assert!(!state.registered_contracts().is_empty());
    }

    #[test]
    fn metadata_watch_controller_status_is_advisory_and_local_only() {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");

        let status = get_metadata_watch_controller_status(&state).expect("metadata watch status");

        assert!(status.triage_advisory_only);
        assert!(!status.automatic_llm_calls);
        assert!(!status.response_execution);
        assert_eq!(status.enabled_source_count, 0);
    }

    #[test]
    fn metadata_watch_sources_and_batches_are_bounded_read_models() {
        let source = metadata_watch_source_for_read();
        let batch = metadata_sampling_batch_for_read(&source);
        let state = ReadOnlyCommandState::bootstrap()
            .expect("bootstrap read commands")
            .with_metadata_watch_sources(vec![source.clone()])
            .with_metadata_sampling_batches(vec![batch.clone()])
            .with_metadata_watch_controller_status(MetadataWatchControllerStatus::empty());

        let sources = list_metadata_watch_sources(&state, PageRequest::default())
            .expect("metadata watch sources");
        let source_detail = get_metadata_watch_source(&state, source.source_id.clone())
            .expect("metadata watch source detail");
        let batches = list_metadata_sampling_batches(&state, PageRequest::default())
            .expect("metadata sampling batches");
        let batch_detail = get_metadata_sampling_batch(&state, batch.batch_id.clone())
            .expect("metadata sampling batch detail");
        let serialized = serde_json::to_string(&json!({
            "sources": sources,
            "source_detail": source_detail,
            "batches": batches,
            "batch_detail": batch_detail,
        }))
        .expect("serialize metadata watch read models");

        assert!(serialized.contains("local_proxy_metadata"));
        for forbidden in [
            "C:\\Users",
            "http://",
            "session_token",
            "alice@example",
            "192.168.1.10",
            "access.log",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[test]
    fn missing_lookup_returns_structured_redacted_error() {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let error = get_plugin_manifest(&state, PluginId::new_v4()).expect_err("missing plugin");

        assert_eq!(error.error_code, ErrorCode::InvalidRequest);
        assert_eq!(error.severity, ErrorSeverity::Error);
        assert!(!error.retryable);
        assert!(error.trace_id.is_some());
        assert!(error.audit_ref.is_none());
        assert!(error.details_redacted.is_some());
    }

    #[test]
    fn search_commands_page_logical_read_models() {
        let state = sample_state();
        let request =
            QueryRequest::new(QueryScope::Global).with_page(PageRequest::first(1).expect("page"));

        let findings = search_findings(&state, request.clone()).expect("findings");
        let alerts = search_alerts(&state, request.clone()).expect("alerts");
        let incidents = search_incidents(&state, request).expect("incidents");

        assert_eq!(findings.items.len(), 1);
        assert_eq!(alerts.items.len(), 1);
        assert_eq!(incidents.items.len(), 1);
        assert!(!findings.has_more);
    }

    #[test]
    fn security_searches_support_typed_scope_filters_and_sort() {
        let state = security_query_state();
        let alert_id = state.alerts.items[0].id().clone();
        let incident_id = state.incidents.items[0].id().clone();
        let first_finding_id = state.findings.items[0].id().clone();

        let findings = search_findings(
            &state,
            QueryRequest::new(QueryScope::Alert(alert_id.clone()))
                .with_filters(vec![FilterSpec::new(
                    "severity",
                    FilterOperator::Eq,
                    Some(FilterValue::String("high".to_string())),
                )
                .expect("filter")])
                .with_sort(vec![
                    SortSpec::new("finding_type", SortDirection::Asc).expect("sort")
                ]),
        )
        .expect("findings");
        assert_eq!(findings.items.len(), 2);
        assert_eq!(findings.items[0].finding_type(), "credential_probe");
        assert_eq!(findings.items[1].finding_type(), "lateral_probe");

        let alerts = search_alerts(
            &state,
            QueryRequest::new(QueryScope::Finding(first_finding_id)).with_filters(vec![
                FilterSpec::new(
                    "title",
                    FilterOperator::Contains,
                    Some(FilterValue::String("lateral".to_string())),
                )
                .expect("filter"),
            ]),
        )
        .expect("alerts");
        assert_eq!(alerts.items.len(), 1);
        assert_eq!(alerts.items[0].id(), &alert_id);

        let incidents = search_incidents(
            &state,
            QueryRequest::new(QueryScope::Alert(alert_id)).with_filters(vec![FilterSpec::new(
                "state",
                FilterOperator::Eq,
                Some(FilterValue::String("new".to_string())),
            )
            .expect("filter")]),
        )
        .expect("incidents");
        assert_eq!(incidents.items.len(), 1);
        assert_eq!(incidents.items[0].id(), &incident_id);
    }

    #[test]
    fn security_search_empty_filters_and_stable_sort() {
        let state = security_query_state();
        let first_high = state.findings.items[0].id().clone();
        let second_high = state.findings.items[1].id().clone();

        let findings = search_findings(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(Vec::new())
                .with_sort(vec![
                    SortSpec::new("severity", SortDirection::Desc).expect("sort")
                ]),
        )
        .expect("findings");

        assert_eq!(findings.items.len(), 3);
        assert_eq!(findings.items[0].id(), &first_high);
        assert_eq!(findings.items[1].id(), &second_high);
        assert_eq!(findings.items[2].severity(), &SecuritySeverity::Low);
    }

    #[test]
    fn security_search_rejects_unsupported_fields_without_private_echo() {
        let state = security_query_state();
        let error = search_findings(
            &state,
            QueryRequest::new(QueryScope::Global).with_filters(vec![FilterSpec::new(
                "authorization_header_value",
                FilterOperator::Eq,
                Some(FilterValue::String("session_token secret".to_string())),
            )
            .expect("filter")]),
        )
        .expect_err("unsupported field");
        let serialized = serde_json::to_string(&error).expect("serialize error");

        assert_eq!(error.error_code, ErrorCode::UnsupportedOperation);
        assert!(error.trace_id.is_some());
        assert!(!serialized.contains("authorization_header_value"));
        assert!(!serialized.contains("session_token"));
        assert!(!serialized.contains("secret"));

        let sort_error = search_findings(
            &state,
            QueryRequest::new(QueryScope::Global).with_sort(vec![SortSpec::new(
                "payload_blob",
                SortDirection::Asc,
            )
            .expect("sort")]),
        )
        .expect_err("unsupported sort");
        let serialized = serde_json::to_string(&sort_error).expect("serialize sort error");
        assert!(!serialized.contains("payload_blob"));
    }

    #[test]
    fn attack_coverage_summary_uses_bounded_allowlisted_mappings() {
        let state = mapped_attack_coverage_state();
        let risk_ref = state.alerts.items[0].risk_event_refs()[0].clone();
        let finding_ref = state.findings.items[0].id().clone();
        let evidence_ref = state.findings.items[0].evidence_refs()[0].clone();

        let summary = get_attack_coverage_summary(&state).expect("coverage summary");
        let row = summary
            .technique_rows
            .iter()
            .find(|row| {
                row.package_category == "http_analysis_v1" && row.technique_id == "T1071.001"
            })
            .expect("http coverage row");

        assert!(!summary.complete_coverage_claimed);
        assert_eq!(summary.attack_version, ATTACK_COVERAGE_VERSION);
        assert_eq!(row.finding_refs, vec![finding_ref]);
        assert_eq!(row.evidence_refs, vec![evidence_ref]);
        assert_eq!(row.risk_refs, vec![risk_ref]);
        assert_eq!(row.observed_count_bucket, AttackObservedCountBucket::Single);
        assert_eq!(
            row.last_observed_bucket,
            AttackLastObservedBucket::CurrentSession
        );
        assert!(row.states.contains(&AttackCoverageState::Covered));
        assert!(row.states.contains(&AttackCoverageState::Observed));
        assert!(row.states.contains(&AttackCoverageState::EvidenceBacked));
        assert!(row.states.contains(&AttackCoverageState::Degraded));
        assert_eq!(row.rule_detector_ids, vec!["portable_http_analysis_v1"]);
    }

    #[test]
    fn attack_coverage_summary_keeps_native_required_rows_degraded() {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let summary = get_attack_coverage_summary(&state).expect("coverage summary");
        let native_rows = summary
            .technique_rows
            .iter()
            .filter(|row| row.package_category == "authorized_native_extension")
            .collect::<Vec<_>>();

        assert!(!native_rows.is_empty());
        for row in native_rows {
            assert!(row.finding_refs.is_empty());
            assert_eq!(row.confidence_bucket, AttackCoverageConfidenceBucket::Low);
            assert_eq!(row.observed_count_bucket, AttackObservedCountBucket::None);
            assert!(row.states.contains(&AttackCoverageState::Unsupported));
            assert!(row
                .states
                .contains(&AttackCoverageState::RequiresAuthorizedNativeExtension));
        }
    }

    #[test]
    fn attack_coverage_summary_does_not_serialize_sensitive_markers() {
        let state = mapped_attack_coverage_state();
        let summary = get_attack_coverage_summary(&state).expect("coverage summary");
        let serialized = serde_json::to_string(&summary)
            .expect("serialize coverage")
            .to_ascii_lowercase();

        for marker in [
            "raw_packet",
            "packet_bytes",
            "raw_payload",
            "payload_blob",
            "http_body",
            "cookie:",
            "authorization:",
            "session_token",
            "access_token",
            "refresh_token",
            "credential",
            "api_key",
            "private_key",
            "query_string",
            "command_line",
            "c:\\users\\",
            "/home/",
        ] {
            assert!(
                !serialized.contains(marker),
                "coverage summary leaked marker {marker}"
            );
        }
    }

    #[test]
    fn empty_fusion_summary_exposes_safe_sampler_boundaries_without_runtime_state() {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let summary = get_fusion_summary(&state).expect("fusion summary");
        let serialized = serde_json::to_string(&summary)
            .expect("serialize fusion summary")
            .to_ascii_lowercase();

        assert_eq!(summary.sampler_health.len(), 12);
        assert_eq!(summary.fact_count, 0);
        assert_eq!(summary.hypothesis_count, 0);
        assert!(!summary.automatic_llm_calls);
        assert!(summary.sampler_health.iter().any(|sampler| {
            sampler.layer == sentinel_contracts::SecurityLayer::SdnControlPlane
                && sampler.portable_default_available
        }));
        assert!(summary.sampler_health.iter().any(|sampler| {
            sampler.layer == sentinel_contracts::SecurityLayer::SdnPlaceholder
                && !sampler.portable_default_available
        }));
        assert!(summary.sampler_health.iter().any(|sampler| {
            sampler.layer == sentinel_contracts::SecurityLayer::AuthorizedNativeHostPlaceholder
                && !sampler.portable_default_available
        }));
        for marker in [
            "session_token",
            "access_token",
            "raw_payload",
            "authorization:",
            "cookie:",
            "alice@example",
            "c:\\users\\",
        ] {
            assert!(!serialized.contains(marker), "leaked marker {marker}");
        }
    }

    #[test]
    fn fusion_hypothesis_read_models_page_and_return_bounded_detail() {
        let hypothesis = AttackHypothesisRecord {
            hypothesis_record_id: AttackHypothesisId::new_v4(),
            definition_id: "possible_api_abuse_chain".to_string(),
            version: "1.0.0".to_string(),
            category: "possible_api_abuse_chain".to_string(),
            fact_refs: vec![sentinel_contracts::SecurityFactId::new_v4()],
            correlated_layers: vec![
                sentinel_contracts::SecurityLayer::Api,
                sentinel_contracts::SecurityLayer::Waf,
            ],
            correlation_count: 2,
            confidence_bucket: sentinel_contracts::FusionConfidenceBucket::Medium,
            degraded_reason: Some("metadata_only_visibility".to_string()),
            missing_visibility_flags: vec!["no_process_attribution".to_string()],
            evidence_refs: vec![EvidenceId::new_v4()],
            finding_refs: Vec::new(),
            risk_refs: Vec::new(),
            graph_hint_refs: Vec::new(),
            attack_candidates: Vec::new(),
            negative_evidence_notes: vec!["native_visibility_unavailable".to_string()],
            benign_baseline_indicators: Vec::new(),
            optional_llm_story_marker: true,
            quality: QualityBreakdown::corroborated_metadata(),
            created_at: Timestamp::now(),
        };
        hypothesis.validate().expect("safe hypothesis");
        let state = ReadOnlyCommandState::bootstrap()
            .expect("bootstrap")
            .with_attack_hypotheses(vec![hypothesis.clone()]);

        let page =
            list_attack_hypotheses(&state, PageRequest::first(10).expect("valid page request"))
                .expect("hypothesis page");
        let detail = get_attack_hypothesis(&state, hypothesis.hypothesis_record_id.clone())
            .expect("hypothesis detail");
        let serialized = serde_json::to_string(&detail).expect("serialize detail");

        assert_eq!(page.items, vec![hypothesis.clone()]);
        assert_eq!(detail, hypothesis);
        assert!(!serialized.contains("raw_payload"));
        assert!(!serialized.contains("session_token"));
        assert!(!serialized.contains("alice@example"));
    }

    #[test]
    fn network_searches_support_typed_scope_filters_and_sort() {
        let state = network_query_state();
        let asset_id = state.flows.items[0]
            .asset_ref
            .as_ref()
            .expect("asset ref")
            .entity_id
            .clone();
        let first_flow_id = state.flows.items[0].flow_id.clone();

        let flows = search_flows(
            &state,
            QueryRequest::new(QueryScope::Entity(asset_id.clone()))
                .with_filters(vec![FilterSpec::new(
                    "protocol",
                    FilterOperator::Eq,
                    Some(FilterValue::String("tcp".to_string())),
                )
                .expect("filter")])
                .with_sort(vec![
                    SortSpec::new("bytes_out", SortDirection::Desc).expect("sort")
                ]),
        )
        .expect("flows");
        assert_eq!(flows.items.len(), 2);
        assert_eq!(flows.items[0].bytes_out, 8192);
        assert_eq!(flows.items[1].bytes_out, 4096);

        let dns = search_dns(
            &state,
            QueryRequest::new(QueryScope::Entity(asset_id.clone()))
                .with_filters(vec![FilterSpec::new(
                    "query_name",
                    FilterOperator::Contains,
                    Some(FilterValue::String("example".to_string())),
                )
                .expect("filter")])
                .with_sort(vec![
                    SortSpec::new("answer_count", SortDirection::Desc).expect("sort")
                ]),
        )
        .expect("dns");
        assert_eq!(dns.items.len(), 2);
        assert_eq!(dns.items[0].features.answer_count, 2);
        assert_eq!(dns.items[0].flow_ref.as_ref(), Some(&first_flow_id));

        let tls = search_tls(
            &state,
            QueryRequest::new(QueryScope::Entity(asset_id)).with_filters(vec![FilterSpec::new(
                "alpn",
                FilterOperator::Eq,
                Some(FilterValue::String("h2".to_string())),
            )
            .expect("filter")]),
        )
        .expect("tls");
        assert_eq!(tls.items.len(), 1);
        assert_eq!(tls.items[0].flow_ref.as_ref(), Some(&first_flow_id));
    }

    #[test]
    fn network_search_empty_filters_stable_sort_and_unsupported_scope() {
        let state = network_query_state();
        let first_flow_id = state.flows.items[0].flow_id.clone();
        let second_flow_id = state.flows.items[1].flow_id.clone();

        let flows = search_flows(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(Vec::new())
                .with_sort(vec![
                    SortSpec::new("dst_port", SortDirection::Asc).expect("sort")
                ]),
        )
        .expect("flows");
        assert_eq!(flows.items.len(), 3);
        assert_eq!(flows.items[0].flow_id, first_flow_id);
        assert_eq!(flows.items[1].flow_id, second_flow_id);

        let error = search_flows(
            &state,
            QueryRequest::new(QueryScope::Incident(IncidentId::new_v4())),
        )
        .expect_err("unsupported scope");
        assert_eq!(error.error_code, ErrorCode::UnsupportedOperation);
        assert!(error.trace_id.is_some());
        assert!(error.details_redacted.is_some());
    }

    #[test]
    fn network_search_rejects_unsupported_fields_without_private_echo() {
        let state = network_query_state();
        let error = search_dns(
            &state,
            QueryRequest::new(QueryScope::Global).with_filters(vec![FilterSpec::new(
                "authorization_header_value",
                FilterOperator::Eq,
                Some(FilterValue::String("api_key token".to_string())),
            )
            .expect("filter")]),
        )
        .expect_err("unsupported field");
        let serialized = serde_json::to_string(&error).expect("serialize error");

        assert_eq!(error.error_code, ErrorCode::UnsupportedOperation);
        assert!(!serialized.contains("authorization_header_value"));
        assert!(!serialized.contains("api_key"));
        assert!(!serialized.contains("token"));

        let sort_error = search_tls(
            &state,
            QueryRequest::new(QueryScope::Global).with_sort(vec![SortSpec::new(
                "payload_blob",
                SortDirection::Asc,
            )
            .expect("sort")]),
        )
        .expect_err("unsupported sort");
        let serialized = serde_json::to_string(&sort_error).expect("serialize sort error");
        assert!(!serialized.contains("payload_blob"));
    }

    #[test]
    fn incident_detail_stays_in_read_only_redacted_view_models() {
        let state = sample_state();
        let incident_id = state.incidents.items[0].id().clone();

        let detail = get_incident_detail(&state, incident_id).expect("incident detail");
        let value = serde_json::to_string(&detail).expect("serialize detail");

        assert_eq!(detail.related_alerts.len(), 1);
        assert_eq!(detail.related_findings.len(), 1);
        assert_eq!(detail.graph.graph_type, GraphType::IncidentGraph);
        assert!(!value.contains("packet_bytes"));
        assert!(!value.contains("payload_blob"));
        assert!(!value.contains("authorization_header_value"));
        assert!(!value.contains("session_token"));
        assert!(!value.contains("credential_value"));
    }

    #[test]
    fn graph_command_returns_graph_view_model_only() {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let view = get_graph_view(
            &state,
            GraphViewRequest {
                graph_type: GraphType::C2Graph,
                scope: GraphScope::Overview,
                title_redacted: None,
                node_limit: Some(50),
                edge_limit: Some(150),
            },
        )
        .expect("graph view");

        assert_eq!(view.graph_type, GraphType::C2Graph);
        assert_eq!(view.node_limit, 50);
        assert_eq!(view.edge_limit, 150);
        assert!(view.nodes.is_empty());
        assert!(view.edges.is_empty());
    }

    #[test]
    fn active_responses_are_recommend_first() {
        let mut plan = ResponsePlan::new(
            ResponsePlanSource::Incident(IncidentId::new_v4()),
            "read_command_test",
        )
        .expect("plan");
        let target = ResponseTarget::new("redacted destination").expect("target");
        let scope = ResponseScope::limited("single destination").expect("scope");
        let action = sentinel_contracts::RecommendedAction::new(
            ResponseActionType::RecommendFirewallBlock,
            target,
            scope,
            "recommend a local firewall review",
            "manual approval required before any execution",
            ResponseLevel::RecommendOnly,
        )
        .expect("recommended action");
        plan.recommended_actions.push(action);

        let state = ReadOnlyCommandState::bootstrap()
            .expect("bootstrap read commands")
            .with_response_plans(vec![plan]);
        let page = list_active_responses(&state, PageRequest::default()).expect("responses");

        assert_eq!(page.items.len(), 1);
        assert!(page.items[0].recommended_actions.iter().all(|action| {
            !action.response_level.execution_allowed_by_default() && !action.approval_required
        }));
    }

    #[test]
    fn response_plan_searches_support_typed_scope_filters_sort_and_time_range() {
        let (state, incident_id, _alert_id, finding_id, entity_id) = response_query_state();

        let scoped = search_response_plans(
            &state,
            QueryRequest::new(QueryScope::Incident(incident_id.clone())).with_filters(vec![
                FilterSpec::new(
                    "response_level",
                    FilterOperator::Eq,
                    Some(FilterValue::String("approval_required".to_string())),
                )
                .expect("filter"),
            ]),
        )
        .expect("scoped response plans");
        assert_eq!(scoped.items.len(), 1);
        assert!(matches!(
            &scoped.items[0].source,
            ResponsePlanSource::Incident(id) if id == &incident_id
        ));

        let ranked = search_response_plans(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_time_range(
                    TimeRange::new(Some(test_timestamp(1)), Some(test_timestamp(2)))
                        .expect("time range"),
                )
                .with_filters(vec![FilterSpec::new(
                    "approval_required",
                    FilterOperator::Eq,
                    Some(FilterValue::Bool(true)),
                )
                .expect("filter")])
                .with_sort(vec![SortSpec::new(
                    "recommended_action_count",
                    SortDirection::Desc,
                )
                .expect("sort")]),
        )
        .expect("ranked response plans");
        assert_eq!(ranked.items.len(), 2);
        assert!(matches!(
            &ranked.items[0].source,
            ResponsePlanSource::Incident(id) if id == &incident_id
        ));
        assert!(matches!(
            &ranked.items[1].source,
            ResponsePlanSource::Finding(id) if id == &finding_id
        ));

        let entity_scoped = search_response_plans(
            &state,
            QueryRequest::new(QueryScope::Entity(entity_id)).with_filters(vec![FilterSpec::new(
                "action_type",
                FilterOperator::Eq,
                Some(FilterValue::String("recommend_firewall_block".to_string())),
            )
            .expect("filter")]),
        )
        .expect("entity response plans");
        assert_eq!(entity_scoped.items.len(), 1);
        assert!(matches!(
            &entity_scoped.items[0].source,
            ResponsePlanSource::Incident(id) if id == &incident_id
        ));
    }

    #[test]
    fn response_plan_search_empty_filters_stable_sort_and_unsupported_scope() {
        let (state, incident_id, _alert_id, finding_id, _entity_id) = response_query_state();

        let page = search_response_plans(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(Vec::new())
                .with_sort(vec![SortSpec::new(
                    "approval_required",
                    SortDirection::Desc,
                )
                .expect("sort")]),
        )
        .expect("response plans");

        assert_eq!(page.items.len(), 3);
        assert!(matches!(
            &page.items[0].source,
            ResponsePlanSource::Incident(id) if id == &incident_id
        ));
        assert!(matches!(
            &page.items[1].source,
            ResponsePlanSource::Finding(id) if id == &finding_id
        ));

        let error = search_response_plans(
            &state,
            QueryRequest::new(QueryScope::Report(ReportId::new_v4())),
        )
        .expect_err("unsupported scope");

        assert_eq!(error.error_code, ErrorCode::UnsupportedOperation);
        assert!(error.trace_id.is_some());
        assert!(error.details_redacted.is_some());
    }

    #[test]
    fn response_plan_search_rejects_unsupported_fields_without_private_echo() {
        let (state, ..) = response_query_state();
        let error = search_response_plans(
            &state,
            QueryRequest::new(QueryScope::Global).with_filters(vec![FilterSpec::new(
                "authorization_header_value",
                FilterOperator::Eq,
                Some(FilterValue::String("credential_value token".to_string())),
            )
            .expect("filter")]),
        )
        .expect_err("unsupported field");
        let serialized = serde_json::to_string(&error).expect("serialize error");

        assert_eq!(error.error_code, ErrorCode::UnsupportedOperation);
        assert!(!serialized.contains("authorization_header_value"));
        assert!(!serialized.contains("credential_value"));
        assert!(!serialized.contains("token"));

        let sort_error = search_response_plans(
            &state,
            QueryRequest::new(QueryScope::Global).with_sort(vec![SortSpec::new(
                "payload_blob",
                SortDirection::Asc,
            )
            .expect("sort")]),
        )
        .expect_err("unsupported sort");
        let serialized = serde_json::to_string(&sort_error).expect("serialize sort error");
        assert!(!serialized.contains("payload_blob"));
    }

    #[test]
    fn report_searches_support_typed_scope_filters_sort_and_time_range() {
        let (state, incident_id, _alert_id, finding_id) = report_query_state();

        let incident_reports = search_reports(
            &state,
            QueryRequest::new(QueryScope::Incident(incident_id.clone()))
                .with_time_range(
                    TimeRange::new(Some(test_timestamp(1)), Some(test_timestamp(3)))
                        .expect("time range"),
                )
                .with_filters(vec![FilterSpec::new(
                    "status",
                    FilterOperator::Eq,
                    Some(FilterValue::String("ready_for_export".to_string())),
                )
                .expect("filter")])
                .with_sort(vec![
                    SortSpec::new("section_count", SortDirection::Desc).expect("sort")
                ]),
        )
        .expect("incident reports");
        assert_eq!(incident_reports.items.len(), 1);
        assert_eq!(incident_reports.items[0].incident_refs, vec![incident_id]);

        let finding_reports = search_reports(
            &state,
            QueryRequest::new(QueryScope::Finding(finding_id.clone())).with_filters(vec![
                FilterSpec::new(
                    "redaction_passed",
                    FilterOperator::Eq,
                    Some(FilterValue::Bool(false)),
                )
                .expect("filter"),
            ]),
        )
        .expect("finding reports");
        assert_eq!(finding_reports.items.len(), 1);
        assert_eq!(finding_reports.items[0].finding_refs, vec![finding_id]);
        assert_eq!(
            finding_reports.items[0].status,
            ReportStatus::RedactionRequired
        );

        let global_incidents = search_reports(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(vec![FilterSpec::new(
                    "report_type",
                    FilterOperator::Eq,
                    Some(FilterValue::String("incident".to_string())),
                )
                .expect("filter")])
                .with_sort(vec![
                    SortSpec::new("updated_at", SortDirection::Desc).expect("sort")
                ]),
        )
        .expect("global incident reports");
        assert_eq!(global_incidents.items.len(), 2);
        assert_eq!(global_incidents.items[0].status, ReportStatus::Exported);
        assert_eq!(
            global_incidents.items[1].status,
            ReportStatus::ReadyForExport
        );
    }

    #[test]
    fn report_search_empty_filters_stable_sort_and_unsupported_scope() {
        let (state, incident_id, alert_id, _finding_id) = report_query_state();

        let reports = search_reports(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(Vec::new())
                .with_sort(vec![
                    SortSpec::new("report_type", SortDirection::Asc).expect("sort")
                ]),
        )
        .expect("reports");

        assert_eq!(reports.items.len(), 3);
        assert_eq!(reports.items[0].incident_refs, vec![incident_id]);
        assert_eq!(reports.items[1].alert_refs, vec![alert_id]);

        let error = search_reports(
            &state,
            QueryRequest::new(QueryScope::Entity(EntityId::new_v4())),
        )
        .expect_err("unsupported scope");
        assert_eq!(error.error_code, ErrorCode::UnsupportedOperation);
        assert!(error.trace_id.is_some());
        assert!(error.details_redacted.is_some());
    }

    #[test]
    fn report_search_rejects_unsupported_fields_without_private_echo() {
        let (state, ..) = report_query_state();
        let error = search_reports(
            &state,
            QueryRequest::new(QueryScope::Global).with_filters(vec![FilterSpec::new(
                "authorization_header_value",
                FilterOperator::Eq,
                Some(FilterValue::String("api_key token".to_string())),
            )
            .expect("filter")]),
        )
        .expect_err("unsupported field");
        let serialized = serde_json::to_string(&error).expect("serialize error");

        assert_eq!(error.error_code, ErrorCode::UnsupportedOperation);
        assert!(!serialized.contains("authorization_header_value"));
        assert!(!serialized.contains("api_key"));
        assert!(!serialized.contains("token"));

        let sort_error = search_reports(
            &state,
            QueryRequest::new(QueryScope::Global).with_sort(vec![SortSpec::new(
                "payload_blob",
                SortDirection::Asc,
            )
            .expect("sort")]),
        )
        .expect_err("unsupported sort");
        let serialized = serde_json::to_string(&sort_error).expect("serialize sort error");
        assert!(!serialized.contains("payload_blob"));
    }

    #[test]
    fn ancillary_catalog_searches_support_scope_filters_sort_pagination_and_empty_filters() {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let plugin = state
            .plugin_registry
            .list()
            .into_iter()
            .next()
            .expect("plugin")
            .clone();
        let capability_id = state
            .capability_registry
            .list()
            .into_iter()
            .find(|capability| capability.plugin_ids.contains(&plugin.plugin_id))
            .expect("capability for plugin")
            .capability_id
            .clone();

        let components = search_components(
            &state,
            QueryRequest::new(QueryScope::Plugin(plugin.plugin_id.clone()))
                .with_filters(vec![FilterSpec::new(
                    "name",
                    FilterOperator::Contains,
                    Some(FilterValue::String(plugin.plugin_name.clone())),
                )
                .expect("filter")])
                .with_sort(vec![
                    SortSpec::new("name", SortDirection::Asc).expect("sort")
                ]),
        )
        .expect("components");
        assert_eq!(components.items.len(), 1);
        assert_eq!(
            components.items[0].plugin_id.as_ref(),
            Some(&plugin.plugin_id)
        );

        let first_page = search_plugins(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(Vec::new())
                .with_sort(vec![
                    SortSpec::new("plugin_name", SortDirection::Asc).expect("sort")
                ])
                .with_page(PageRequest::first(2).expect("page")),
        )
        .expect("first plugin page");
        let second_page = search_plugins(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(Vec::new())
                .with_sort(vec![
                    SortSpec::new("plugin_name", SortDirection::Asc).expect("sort")
                ])
                .with_page(PageRequest::new(2, first_page.next_cursor.clone()).expect("page")),
        )
        .expect("second plugin page");
        assert_eq!(first_page.items.len(), 2);
        assert!(first_page.has_more);
        assert_eq!(second_page.items.len(), 2);
        assert!(first_page.items[0].plugin_name <= first_page.items[1].plugin_name);
        assert!(second_page.items[0].plugin_name <= second_page.items[1].plugin_name);
        assert_ne!(
            first_page.items[0].plugin_id,
            second_page.items[0].plugin_id
        );

        let capabilities = search_capabilities(
            &state,
            QueryRequest::new(QueryScope::Plugin(plugin.plugin_id.clone()))
                .with_filters(vec![FilterSpec::new(
                    "plugin_name",
                    FilterOperator::Eq,
                    Some(FilterValue::String(plugin.plugin_name.clone())),
                )
                .expect("filter")])
                .with_sort(vec![
                    SortSpec::new("title", SortDirection::Asc).expect("sort")
                ]),
        )
        .expect("capabilities");
        assert!(!capabilities.items.is_empty());
        assert!(capabilities.items.iter().all(|overview| {
            overview.plugin_names.contains(&plugin.plugin_name)
                && overview.capability.plugin_ids.contains(&plugin.plugin_id)
        }));

        let scoped_plugins = search_plugins(
            &state,
            QueryRequest::new(QueryScope::Capability(capability_id))
                .with_filters(vec![FilterSpec::new(
                    "capability_tag",
                    FilterOperator::Eq,
                    Some(FilterValue::String("static_internal".to_string())),
                )
                .expect("filter")])
                .with_sort(vec![
                    SortSpec::new("plugin_name", SortDirection::Asc).expect("sort")
                ]),
        )
        .expect("scoped plugins");
        assert!(!scoped_plugins.items.is_empty());
        assert!(scoped_plugins.items.iter().all(|item| item
            .capability_tags
            .iter()
            .any(|tag| tag == "STATIC_INTERNAL")));
    }

    #[test]
    fn settings_searches_support_filters_sort_pagination_and_empty_filters() {
        let state = ReadOnlyCommandState::bootstrap()
            .expect("bootstrap read commands")
            .with_service_status(
                ServiceStatusView::reduced_visibility().with_profile_mode("portable_no_retention"),
            );

        let first_page = search_runtime_profiles(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(Vec::new())
                .with_sort(vec![
                    SortSpec::new("display_name", SortDirection::Asc).expect("sort")
                ])
                .with_page(PageRequest::first(2).expect("page")),
        )
        .expect("first profile page");
        let second_page = search_runtime_profiles(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(Vec::new())
                .with_sort(vec![
                    SortSpec::new("display_name", SortDirection::Asc).expect("sort")
                ])
                .with_page(PageRequest::new(2, first_page.next_cursor.clone()).expect("page")),
        )
        .expect("second profile page");
        assert_eq!(first_page.items.len(), 2);
        assert!(first_page.has_more);
        assert_eq!(second_page.items.len(), 2);
        assert!(first_page.items[0].display_name <= first_page.items[1].display_name);

        let filtered_profiles = search_runtime_profiles(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(vec![FilterSpec::new(
                    "display_name",
                    FilterOperator::Contains,
                    Some(FilterValue::String("resource".to_string())),
                )
                .expect("filter")])
                .with_sort(vec![
                    SortSpec::new("display_name", SortDirection::Asc).expect("sort")
                ]),
        )
        .expect("filtered profiles");
        assert_eq!(filtered_profiles.items.len(), 1);
        assert_eq!(filtered_profiles.items[0].display_name, "Low Resource");

        let status = search_service_status(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(vec![FilterSpec::new(
                    "profile_mode",
                    FilterOperator::Eq,
                    Some(FilterValue::String("portable_no_retention".to_string())),
                )
                .expect("filter")])
                .with_sort(vec![
                    SortSpec::new("generated_at", SortDirection::Desc).expect("sort")
                ]),
        )
        .expect("service status");
        assert_eq!(status.items.len(), 1);
        assert_eq!(status.items[0].profile_mode, "portable_no_retention");
    }

    #[test]
    fn export_history_search_supports_scope_filters_sort_pagination_and_empty_filters() {
        let (state, report_id, response_result_id, rollback_result_id) =
            export_history_query_state();

        let first_page = search_export_history(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(Vec::new())
                .with_sort(vec![
                    SortSpec::new("exported_at", SortDirection::Desc).expect("sort")
                ])
                .with_page(PageRequest::first(1).expect("page")),
        )
        .expect("first export page");
        let second_page = search_export_history(
            &state,
            QueryRequest::new(QueryScope::Global)
                .with_filters(Vec::new())
                .with_sort(vec![
                    SortSpec::new("exported_at", SortDirection::Desc).expect("sort")
                ])
                .with_page(PageRequest::new(1, first_page.next_cursor.clone()).expect("page")),
        )
        .expect("second export page");
        assert_eq!(first_page.items.len(), 1);
        assert!(first_page.has_more);
        assert_eq!(second_page.items.len(), 1);
        assert_ne!(
            first_page.items[0].export_result_id,
            second_page.items[0].export_result_id
        );

        let filtered = search_export_history(
            &state,
            QueryRequest::new(QueryScope::Report(report_id))
                .with_filters(vec![
                    FilterSpec::new(
                        "response_result_ref",
                        FilterOperator::Eq,
                        Some(FilterValue::String(response_result_id.to_string())),
                    )
                    .expect("filter"),
                    FilterSpec::new("success", FilterOperator::Eq, Some(FilterValue::Bool(true)))
                        .expect("filter"),
                ])
                .with_sort(vec![SortSpec::new(
                    "response_result_count",
                    SortDirection::Desc,
                )
                .expect("sort")]),
        )
        .expect("filtered export history");
        assert_eq!(filtered.items.len(), 1);
        assert!(filtered.items[0]
            .response_result_refs
            .contains(&response_result_id));

        let rollback = search_export_history(
            &state,
            QueryRequest::new(QueryScope::Global).with_filters(vec![FilterSpec::new(
                "rollback_result_ref",
                FilterOperator::Eq,
                Some(FilterValue::String(rollback_result_id.to_string())),
            )
            .expect("filter")]),
        )
        .expect("rollback export history");
        assert_eq!(rollback.items.len(), 1);
        assert!(rollback.items[0]
            .rollback_result_refs
            .contains(&rollback_result_id));
    }

    #[test]
    fn ancillary_searches_reject_unsupported_fields_without_private_echo() {
        let (export_history_state, ..) = export_history_query_state();
        let state = ReadOnlyCommandState::bootstrap()
            .expect("bootstrap read commands")
            .with_service_status(
                ServiceStatusView::reduced_visibility().with_profile_mode("portable_no_retention"),
            )
            .with_export_history(export_history_state.export_history.clone());

        let component_error = search_components(
            &state,
            QueryRequest::new(QueryScope::Global).with_filters(vec![FilterSpec::new(
                "authorization_header_value",
                FilterOperator::Eq,
                Some(FilterValue::String("api_key secret".to_string())),
            )
            .expect("filter")]),
        )
        .expect_err("unsupported component field");
        let component_serialized =
            serde_json::to_string(&component_error).expect("serialize component error");
        assert_eq!(component_error.error_code, ErrorCode::UnsupportedOperation);
        assert!(!component_serialized.contains("authorization_header_value"));
        assert!(!component_serialized.contains("api_key"));
        assert!(!component_serialized.contains("secret"));

        let profile_sort_error = search_runtime_profiles(
            &state,
            QueryRequest::new(QueryScope::Global).with_sort(vec![SortSpec::new(
                "payload_blob",
                SortDirection::Asc,
            )
            .expect("sort")]),
        )
        .expect_err("unsupported profile sort");
        let profile_serialized =
            serde_json::to_string(&profile_sort_error).expect("serialize profile error");
        assert_eq!(
            profile_sort_error.error_code,
            ErrorCode::UnsupportedOperation
        );
        assert!(!profile_serialized.contains("payload_blob"));

        let history_error = search_export_history(
            &state,
            QueryRequest::new(QueryScope::Global).with_filters(vec![FilterSpec::new(
                "authorization_header_value",
                FilterOperator::Eq,
                Some(FilterValue::String("access_token secret".to_string())),
            )
            .expect("filter")]),
        )
        .expect_err("unsupported export history field");
        let history_serialized =
            serde_json::to_string(&history_error).expect("serialize export history error");
        assert_eq!(history_error.error_code, ErrorCode::InvalidRequest);
        assert!(!history_serialized.contains("authorization_header_value"));
        assert!(!history_serialized.contains("access_token"));
        assert!(!history_serialized.contains("secret"));
    }

    #[test]
    fn runtime_profile_and_service_status_preserve_safe_boundaries() {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let profile = get_runtime_profile(&state).expect("runtime profile");
        let status = get_service_status(&state).expect("service status");

        assert!(!profile.privacy_policy.raw_packet_storage_enabled);
        assert!(!profile.privacy_policy.payload_storage_enabled);
        assert!(!profile.privacy_policy.http_body_storage_enabled);
        assert_eq!(profile.report_export_policy.allowed_formats.len(), 3);
        assert!(profile
            .report_export_policy
            .allowed_formats
            .contains(&ExportFormat::RedactedJson));
        assert!(status.reduced_visibility);
        assert!(!status.privileged_actions_available);
        assert_eq!(status.profile_mode, "ephemeral");
    }

    #[test]
    fn export_history_read_apis_list_filter_and_detail() {
        let report_id = ReportId::new_v4();
        let export_result_id = ExportResultId::new_v4();
        let mut export_history = ExportHistoryStore::new();
        let record = ExportHistoryRecord {
            export_result_id: export_result_id.clone(),
            report_id: report_id.clone(),
            format: ExportFormat::Markdown,
            destination: sentinel_capabilities::ExportDestinationMetadata::local(Some(
                "local report file".to_string(),
            ))
            .expect("destination"),
            file_hash: Some(sentinel_capabilities::ExportFileHash::from_bytes(
                b"hash-redacted",
            )),
            redaction_summary: RedactionSummary::passed(vec![
                RedactedDataCategory::RawPacket,
                RedactedDataCategory::Payload,
            ]),
            graph_snapshot_refs: Vec::new(),
            evidence_refs: Vec::new(),
            response_result_refs: Vec::new(),
            rollback_result_refs: Vec::new(),
            llm_story_refs: Vec::new(),
            actor_redacted: "local_user".to_string(),
            exported_at: Timestamp::now(),
            trace_id: Some(TraceId::new_v4()),
            audit_id: AuditId::new_v4(),
            success: true,
        };
        export_history.append(record).expect("history append");
        let state = ReadOnlyCommandState::bootstrap()
            .expect("bootstrap read commands")
            .with_export_history(export_history);

        let page = list_export_history(
            &state,
            ReportExportHistoryQuery::for_report(report_id).with_format(ExportFormat::Markdown),
        )
        .expect("history");
        let detail = get_export_history_record(&state, export_result_id).expect("history detail");

        assert_eq!(page.items.len(), 1);
        assert!(page.items[0].file_hash.is_some());
        assert_eq!(detail.audit_id, page.items[0].audit_id);
        assert!(list_export_policy_violations(&state)
            .expect("violations")
            .is_empty());
    }

    #[test]
    fn read_commands_report_export_reads_are_ref_only_and_side_effect_free() {
        let state = sample_state();
        let report_id = state.reports.items[0].report_id.clone();
        let report_count = state.reports.items.len();
        let finding_count = state.findings.items.len();
        let export_count = state.export_history.records().len();
        let llm_story_count = state.llm_alert_stories.items.len();

        let reports = list_reports(&state, PageRequest::default()).expect("reports");
        let report = get_report(&state, report_id).expect("report detail");
        let exports = list_export_history(&state, ReportExportHistoryQuery::default())
            .expect("export history");
        let stories = list_llm_alert_stories(&state, PageRequest::default()).expect("stories");

        assert_eq!(reports.items.len(), report_count);
        assert_eq!(report.finding_refs.len(), 0);
        assert_eq!(exports.items.len(), export_count);
        assert_eq!(stories.items.len(), llm_story_count);
        assert_eq!(state.reports.items.len(), report_count);
        assert_eq!(state.findings.items.len(), finding_count);
        assert_eq!(state.export_history.records().len(), export_count);
        assert_eq!(state.llm_alert_stories.items.len(), llm_story_count);
        let serialized =
            serde_json::to_string(&(reports, report, exports, stories)).expect("read json");
        for marker in [
            "provider_value",
            "automatic_llm_calls\":true",
            "response_execution\":true",
            "raw_log",
            "api_key_value",
            "c:\\",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "read command output leaked marker {marker}"
            );
        }
    }

    #[test]
    fn provider_controller_reads_are_inactive_side_effect_free_and_safe() {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let finding_count = state.findings.items.len();
        let fact_count = state.security_facts.items.len();

        let controller =
            get_provider_controller_status(&state).expect("provider controller status");
        let providers = list_network_provider_status(&state).expect("provider list");
        let ip_helper =
            get_network_provider_status(&state, "ip_helper".to_string()).expect("ip helper");
        let visibility = get_network_visibility_summary(&state).expect("visibility summary");
        let fallback = get_network_fallback_plan(&state).expect("fallback plan");

        assert_eq!(
            controller.controller_state,
            sentinel_contracts::NetworkProviderControllerState::Inactive
        );
        assert_eq!(
            controller.selected_mode,
            sentinel_contracts::NetworkProviderControllerMode::PortableOnly
        );
        assert_eq!(providers.len(), 11);
        assert!(providers.iter().any(|provider| {
            provider.provider_kind == sentinel_contracts::NetworkProviderKind::WindowsRdpOperational
                && provider.implementation_state
                    == sentinel_contracts::NetworkProviderImplementationState::ImplementedInactive
        }));
        assert!(providers.iter().any(|provider| {
            provider.provider_kind == sentinel_contracts::NetworkProviderKind::WindowsSmbOperational
                && provider.implementation_state
                    == sentinel_contracts::NetworkProviderImplementationState::ImplementedInactive
        }));
        assert!(providers.iter().any(|provider| {
            provider.provider_kind == sentinel_contracts::NetworkProviderKind::WindowsSshOperational
                && provider.implementation_state
                    == sentinel_contracts::NetworkProviderImplementationState::ImplementedInactive
        }));
        assert_eq!(
            ip_helper.implementation_state,
            sentinel_contracts::NetworkProviderImplementationState::ImplementedInactive
        );
        assert!(visibility.dimensions.iter().any(|dimension| {
            dimension.dimension
                == sentinel_contracts::NetworkVisibilityDimension::PortableMetadataVisibility
                && dimension.visibility_state
                    == sentinel_contracts::NetworkVisibilityState::Available
        }));
        assert!(fallback
            .selection_order
            .contains(&sentinel_contracts::NetworkProviderKind::PortableMetadata));
        assert!(controller.policy_summary.provider_activation_allowed);
        assert!(
            controller
                .policy_summary
                .ip_helper_execution_available_over_production_ipc
        );
        assert!(
            !controller
                .policy_summary
                .provider_readiness_creates_evidence
        );
        assert!(
            !controller
                .policy_summary
                .provider_availability_creates_findings
        );
        assert!(controller.provider_zero.all_zero());
        assert_eq!(state.findings.items.len(), finding_count);
        assert_eq!(state.security_facts.items.len(), fact_count);

        let serialized =
            serde_json::to_string(&(controller, providers, ip_helper, visibility, fallback))
                .expect("provider json");
        for marker in [
            "process_name",
            "pid",
            "ppid",
            "interface_name",
            "device_identifier",
            "packet_data",
            "provider_handle",
            "npcap_handle",
            "etw_raw_event",
            "credential",
            "secret",
            "token",
            "api_key",
            "http://",
            "https://",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "provider read leaked marker {marker}"
            );
        }
    }

    #[test]
    fn unsupported_query_shapes_return_structured_errors() {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let error = search_flows(
            &state,
            QueryRequest::new(QueryScope::Incident(IncidentId::new_v4())),
        )
        .expect_err("unsupported scope");

        assert_eq!(error.error_code, ErrorCode::UnsupportedOperation);
        assert!(error.trace_id.is_some());
        assert!(error.details_redacted.is_some());
    }

    fn metadata_watch_source_for_read() -> MetadataWatchSourceStatus {
        let source_id = MetadataWatchSourceId::new_v4();
        let source_kind = MetadataWatchSourceKind::LocalhostProxyContinuousDrain;
        let parser_family = MetadataParserFamily::LocalProxyMetadata;
        let checkpoint =
            MetadataWatchCheckpoint::new(source_id.clone(), source_kind.clone(), &parser_family)
                .expect("watch checkpoint");
        let source = MetadataWatchSourceStatus {
            source_id,
            source_kind,
            state: MetadataWatchSourceState::Active,
            health_state: MetadataSourceHealthState::Active,
            sampling_mode: MetadataSamplingMode::ContinuousDrain,
            interval_seconds: 5,
            max_records_per_tick: 100,
            max_bytes_per_tick: 64_000,
            parser_family,
            redaction_policy: "metadata_redaction_v1".to_string(),
            retention_mode: MetadataRetentionMode::NoRetention,
            checkpoint,
            counters: MetadataWatchCounters {
                sampled_record_count: 3,
                sampled_byte_count: 0,
                skipped_record_count: 0,
                malformed_record_count: 0,
                duplicate_record_count: 1,
                backpressure_drop_count: 0,
                batch_count: 1,
            },
            last_sampled_at: Some(Timestamp::now()),
            last_ingested_at: Some(Timestamp::now()),
            degraded_reason: None,
            error_category: None,
            provenance_id: Some(DataSourceId::new_v4()),
            privacy_boundary: "portable_no_retention_metadata_only".to_string(),
            portable_default_available: true,
            sampler_ids: vec!["watch_source_redacted".to_string()],
            fact_count: 1,
            hypothesis_count: 1,
            finding_count: 1,
            evidence_refs: vec![EvidenceId::new_v4()],
        };
        source.validate().expect("watch source validation");
        source
    }

    fn metadata_sampling_batch_for_read(
        source: &MetadataWatchSourceStatus,
    ) -> MetadataSamplingBatchSummary {
        let batch = MetadataSamplingBatchSummary {
            batch_id: MetadataSamplingBatchId::new_v4(),
            source_id: source.source_id.clone(),
            source_kind: source.source_kind.clone(),
            parser_family: source.parser_family.clone(),
            started_at: Timestamp::now(),
            completed_at: Timestamp::now(),
            health_state: MetadataSourceHealthState::Active,
            sampled_record_count: 3,
            sampled_byte_count: 0,
            skipped_record_count: 0,
            malformed_record_count: 0,
            duplicate_record_count: 1,
            backpressure_drop_count: 0,
            emitted_topics: vec![
                "network.http.metadata".to_string(),
                "security.fact".to_string(),
            ],
            fact_refs: vec![SecurityFactId::new_v4()],
            evidence_refs: source.evidence_refs.clone(),
            finding_refs: vec![FindingId::new_v4()],
            risk_refs: vec![RiskEventId::new_v4()],
            report_refresh_marker: true,
            attack_refresh_marker: true,
            story_available_marker: true,
            triage_advisory_only: true,
            automatic_llm_calls: false,
            response_execution: false,
        };
        batch.validate().expect("sampling batch validation");
        batch
    }

    fn sample_state() -> ReadOnlyCommandState {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let producer = state
            .plugin_registry
            .list()
            .into_iter()
            .find(|plugin| !plugin.finding_types.is_empty())
            .expect("detection-ish plugin")
            .plugin_id
            .clone();
        let evidence_id = EvidenceId::new_v4();
        let finding = Finding::new(
            "c2_signal",
            producer,
            vec![evidence_id],
            FindingExplanation::new("redacted C2-like cadence").expect("explanation"),
        )
        .expect("finding");
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
        let mut report = Report::new(
            ReportType::Incident,
            "redacted incident report",
            "redacted report summary",
            RedactionSummary::passed(vec![
                RedactedDataCategory::RawPacket,
                RedactedDataCategory::Payload,
                RedactedDataCategory::HttpBody,
                RedactedDataCategory::Cookie,
                RedactedDataCategory::Token,
                RedactedDataCategory::Credential,
                RedactedDataCategory::ApiKey,
            ]),
        )
        .expect("report");
        report.incident_refs.push(incident.id().clone());

        state
            .with_findings(vec![finding])
            .with_alerts(vec![alert])
            .with_incidents(vec![incident])
            .with_reports(vec![report])
    }

    fn mapped_attack_coverage_state() -> ReadOnlyCommandState {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let producer = state
            .plugin_registry
            .list()
            .into_iter()
            .find(|plugin| !plugin.finding_types.is_empty())
            .expect("detection-ish plugin")
            .plugin_id
            .clone();
        let mut provenance =
            sentinel_contracts::MappingProvenance::new("mitre_attack_enterprise_allowlist")
                .expect("provenance");
        provenance.source_version = Some(ATTACK_COVERAGE_VERSION.to_string());
        provenance.mapped_by = Some("portable_network_web".to_string());
        provenance.mapped_at = Some(Timestamp::now());
        let mapping = sentinel_contracts::AttackMapping::mitre_attack_enterprise(
            "TA0011",
            "Command and Control",
            "T1071",
            "Application Layer Protocol",
            sentinel_contracts::QualityScore::new(0.62).expect("confidence"),
            Some(provenance),
        )
        .expect("mapping")
        .with_subtechnique("T1071.001", "Web Protocols")
        .expect("subtechnique");
        let evidence_id = EvidenceId::new_v4();
        let finding = Finding::new(
            "portable.http_analysis_v1.status_code_burst",
            producer,
            vec![evidence_id],
            FindingExplanation::new("redacted http metadata anomaly").expect("explanation"),
        )
        .expect("finding")
        .with_attack_mappings(vec![mapping])
        .with_confidence(sentinel_contracts::QualityScore::new(0.8).expect("confidence"))
        .with_severity(SecuritySeverity::Medium);
        let alert = Alert::new(
            "redacted metadata alert",
            "redacted alert summary",
            vec![finding.id().clone()],
        )
        .expect("alert")
        .with_risk_event_refs(vec![RiskEventId::new_v4()])
        .with_severity(SecuritySeverity::Medium);

        state.with_findings(vec![finding]).with_alerts(vec![alert])
    }

    fn security_query_state() -> ReadOnlyCommandState {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let producer = state
            .plugin_registry
            .list()
            .into_iter()
            .find(|plugin| !plugin.finding_types.is_empty())
            .expect("detection-ish plugin")
            .plugin_id
            .clone();
        let first = Finding::new(
            "lateral_probe",
            producer.clone(),
            vec![EvidenceId::new_v4()],
            FindingExplanation::new("redacted lateral movement probe").expect("explanation"),
        )
        .expect("finding")
        .with_severity(SecuritySeverity::High);
        let second = Finding::new(
            "credential_probe",
            producer.clone(),
            vec![EvidenceId::new_v4()],
            FindingExplanation::new("redacted credential access probe").expect("explanation"),
        )
        .expect("finding")
        .with_severity(SecuritySeverity::High);
        let low = Finding::new(
            "benign_context",
            producer,
            vec![EvidenceId::new_v4()],
            FindingExplanation::new("redacted benign context").expect("explanation"),
        )
        .expect("finding")
        .with_severity(SecuritySeverity::Low);
        let alert = Alert::new(
            "redacted lateral alert",
            "redacted alert summary",
            vec![first.id().clone(), second.id().clone()],
        )
        .expect("alert")
        .with_severity(SecuritySeverity::High);
        let incident = Incident::new(
            "lateral_incident",
            "redacted incident",
            "redacted incident summary",
            vec![alert.id().clone()],
        )
        .expect("incident")
        .with_finding_refs(vec![first.id().clone(), second.id().clone()])
        .with_severity(SecuritySeverity::High);

        state
            .with_findings(vec![first, second, low])
            .with_alerts(vec![alert])
            .with_incidents(vec![incident])
    }

    fn network_query_state() -> ReadOnlyCommandState {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let asset_id = EntityId::new_v4();
        let asset_ref = EntityRef::new(asset_id, EntityType::Host);

        let mut first = FlowRecord::new(
            ip("192.0.2.10"),
            51515,
            ip("203.0.113.20"),
            443,
            TransportProtocol::Tcp,
            NetworkDirection::Outbound,
        );
        first.bytes_out = 4096;
        first.bytes_in = 512;
        first.packets_out = 8;
        first.packets_in = 4;
        first.asset_ref = Some(asset_ref.clone());

        let mut second = FlowRecord::new(
            ip("192.0.2.10"),
            51516,
            ip("198.51.100.25"),
            443,
            TransportProtocol::Tcp,
            NetworkDirection::Outbound,
        );
        second.bytes_out = 8192;
        second.bytes_in = 256;
        second.packets_out = 12;
        second.packets_in = 3;
        second.asset_ref = Some(asset_ref.clone());

        let mut third = FlowRecord::new(
            ip("198.51.100.25"),
            53,
            ip("192.0.2.10"),
            5353,
            TransportProtocol::Udp,
            NetworkDirection::Inbound,
        );
        third.bytes_out = 64;
        third.bytes_in = 128;

        let mut dns_first = DnsObservation::new(
            "update.example.test",
            "A",
            ip("203.0.113.53"),
            ip("192.0.2.10"),
        )
        .expect("dns");
        dns_first.flow_ref = Some(first.flow_id.clone());
        dns_first.asset_ref = Some(asset_ref.clone());
        dns_first.response_code = Some("NOERROR".to_string());
        dns_first.features.answer_count = 2;
        dns_first.features.query_length = 19;

        let mut dns_second = DnsObservation::new(
            "cdn.example.test",
            "A",
            ip("203.0.113.53"),
            ip("192.0.2.10"),
        )
        .expect("dns");
        dns_second.flow_ref = Some(second.flow_id.clone());
        dns_second.asset_ref = Some(asset_ref.clone());
        dns_second.response_code = Some("NOERROR".to_string());
        dns_second.features.answer_count = 1;
        dns_second.features.query_length = 16;

        let mut tls_first = TlsObservation::new();
        tls_first.flow_ref = Some(first.flow_id.clone());
        tls_first.sni_protected = Some("update.example.test".to_string());
        tls_first.alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        tls_first.tls_version = Some("tls1.3".to_string());
        tls_first.cipher_suite = Some("TLS_AES_128_GCM_SHA256".to_string());
        tls_first.dst_entity = Some(asset_ref);

        let mut tls_second = TlsObservation::new();
        tls_second.flow_ref = Some(third.flow_id.clone());
        tls_second.sni_protected = Some("resolver.example.test".to_string());
        tls_second.alpn = vec!["dot".to_string()];
        tls_second.tls_version = Some("tls1.2".to_string());
        tls_second.cipher_suite = Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string());

        state
            .with_flows(vec![first, second, third])
            .with_dns(vec![dns_first, dns_second])
            .with_tls(vec![tls_first, tls_second])
    }

    fn export_history_query_state() -> (
        ReadOnlyCommandState,
        ReportId,
        ResponseResultId,
        RollbackResultId,
    ) {
        let report_id = ReportId::new_v4();
        let other_report_id = ReportId::new_v4();
        let response_result_id = ResponseResultId::new_v4();
        let rollback_result_id = RollbackResultId::new_v4();
        let mut export_history = ExportHistoryStore::new();

        export_history
            .append(ExportHistoryRecord {
                export_result_id: ExportResultId::new_v4(),
                report_id: report_id.clone(),
                format: ExportFormat::RedactedJson,
                destination: sentinel_capabilities::ExportDestinationMetadata::local(Some(
                    "first export".to_string(),
                ))
                .expect("destination"),
                file_hash: Some(sentinel_capabilities::ExportFileHash::from_bytes(
                    b"hash-first",
                )),
                redaction_summary: RedactionSummary::passed(vec![
                    RedactedDataCategory::RawPacket,
                    RedactedDataCategory::Payload,
                ]),
                graph_snapshot_refs: vec![GraphSnapshotId::new_v4()],
                evidence_refs: vec![EvidenceId::new_v4()],
                response_result_refs: vec![response_result_id.clone()],
                rollback_result_refs: Vec::new(),
                llm_story_refs: Vec::new(),
                actor_redacted: "analyst_one".to_string(),
                exported_at: test_timestamp(3),
                trace_id: Some(TraceId::new_v4()),
                audit_id: AuditId::new_v4(),
                success: true,
            })
            .expect("first history record");
        export_history
            .append(ExportHistoryRecord {
                export_result_id: ExportResultId::new_v4(),
                report_id: other_report_id,
                format: ExportFormat::Markdown,
                destination: sentinel_capabilities::ExportDestinationMetadata::local(Some(
                    "second export".to_string(),
                ))
                .expect("destination"),
                file_hash: None,
                redaction_summary: RedactionSummary::passed(vec![
                    RedactedDataCategory::RawPacket,
                    RedactedDataCategory::Payload,
                ]),
                graph_snapshot_refs: vec![GraphSnapshotId::new_v4()],
                evidence_refs: vec![EvidenceId::new_v4()],
                response_result_refs: Vec::new(),
                rollback_result_refs: vec![rollback_result_id.clone()],
                llm_story_refs: Vec::new(),
                actor_redacted: "analyst_two".to_string(),
                exported_at: test_timestamp(2),
                trace_id: Some(TraceId::new_v4()),
                audit_id: AuditId::new_v4(),
                success: true,
            })
            .expect("second history record");

        (
            ReadOnlyCommandState::bootstrap()
                .expect("bootstrap read commands")
                .with_export_history(export_history),
            report_id,
            response_result_id,
            rollback_result_id,
        )
    }

    fn response_query_state() -> (
        ReadOnlyCommandState,
        IncidentId,
        sentinel_contracts::AlertId,
        sentinel_contracts::FindingId,
        EntityId,
    ) {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let incident_id = IncidentId::new_v4();
        let alert_id = sentinel_contracts::AlertId::new_v4();
        let finding_id = sentinel_contracts::FindingId::new_v4();
        let entity_id = EntityId::new_v4();
        let entity = EntityRef::new(entity_id.clone(), EntityType::Host);

        let incident_plan = response_plan(
            ResponsePlanSource::Incident(incident_id.clone()),
            test_timestamp(2),
            vec![
                response_action(
                    ResponseActionType::RecommendFirewallBlock,
                    ResponseLevel::ApprovalRequired,
                    Some(entity),
                    true,
                    "redacted destination",
                ),
                response_action(
                    ResponseActionType::RecommendProcessReview,
                    ResponseLevel::RecommendOnly,
                    None,
                    false,
                    "redacted process review",
                ),
            ],
        );
        let alert_plan = response_plan(
            ResponsePlanSource::Alert(alert_id.clone()),
            test_timestamp(3),
            vec![response_action(
                ResponseActionType::RecommendDestinationWatchlist,
                ResponseLevel::RecommendOnly,
                None,
                false,
                "redacted watchlist destination",
            )],
        );
        let finding_plan = response_plan(
            ResponsePlanSource::Finding(finding_id.clone()),
            test_timestamp(1),
            vec![response_action(
                ResponseActionType::RecommendQosThrottle,
                ResponseLevel::ApprovalRequired,
                None,
                true,
                "redacted throttle candidate",
            )],
        );

        (
            state.with_response_plans(vec![incident_plan, alert_plan, finding_plan]),
            incident_id,
            alert_id,
            finding_id,
            entity_id,
        )
    }

    fn response_plan(
        source: ResponsePlanSource,
        created_at: Timestamp,
        actions: Vec<sentinel_contracts::RecommendedAction>,
    ) -> ResponsePlan {
        let mut plan = ResponsePlan::new(source, "read_command_test").expect("response plan");
        plan.created_at = created_at;
        plan.risk_evaluation_redacted = "redacted response risk evaluation".to_string();
        plan.business_impact_redacted = "redacted business impact".to_string();
        plan.audit_requirements
            .push("response.runtime.static_internal.process_batch".to_string());
        plan.approval_required = actions.iter().any(|action| action.approval_required);
        plan.execution_disabled_in_replay = true;
        plan.recommended_actions = actions;
        plan.rollback_plans = plan
            .recommended_actions
            .iter()
            .filter(|action| action.rollback_available)
            .map(|_| sentinel_contracts::RollbackPlan::new("rollback-token").expect("rollback"))
            .collect();
        plan
    }

    fn response_action(
        action_type: ResponseActionType,
        response_level: ResponseLevel,
        target_entity: Option<EntityRef>,
        rollback_available: bool,
        target_summary: &str,
    ) -> sentinel_contracts::RecommendedAction {
        let mut target = ResponseTarget::new(target_summary).expect("target");
        target.target_entity = target_entity;
        let mut action = sentinel_contracts::RecommendedAction::new(
            action_type,
            target,
            ResponseScope::limited("bounded metadata response scope").expect("scope"),
            "redacted expected effect",
            "redacted business impact",
            response_level,
        )
        .expect("recommended action");
        action.rollback_available = rollback_available;
        action.approval_state = Some(if action.approval_required {
            ApprovalState::Requested
        } else {
            ApprovalState::NotRequired
        });
        action
    }

    fn report_query_state() -> (
        ReadOnlyCommandState,
        IncidentId,
        sentinel_contracts::AlertId,
        sentinel_contracts::FindingId,
    ) {
        let state = ReadOnlyCommandState::bootstrap().expect("bootstrap read commands");
        let incident_id = IncidentId::new_v4();
        let alert_id = sentinel_contracts::AlertId::new_v4();
        let finding_id = sentinel_contracts::FindingId::new_v4();
        let evidence_id = EvidenceId::new_v4();

        let mut incident_report = report_for_query(
            ReportType::Incident,
            ReportStatus::ReadyForExport,
            true,
            test_timestamp(1),
            test_timestamp(2),
            vec![
                ReportSectionType::ExecutiveSummary,
                ReportSectionType::EvidenceTable,
            ],
        );
        incident_report.incident_refs.push(incident_id.clone());
        incident_report.alert_refs.push(alert_id.clone());
        incident_report.finding_refs.push(finding_id.clone());
        incident_report.evidence_refs.push(evidence_id.clone());
        incident_report
            .graph_snapshot_refs
            .push(sentinel_contracts::GraphSnapshotId::new_v4());
        incident_report
            .response_result_refs
            .push(sentinel_contracts::ResponseResultId::new_v4());

        let mut threat_report = report_for_query(
            ReportType::Threat,
            ReportStatus::RedactionRequired,
            false,
            test_timestamp(2),
            test_timestamp(3),
            vec![ReportSectionType::PrivacyRedactionSummary],
        );
        threat_report.finding_refs.push(finding_id.clone());
        threat_report.evidence_refs.push(evidence_id);

        let mut exported_report = report_for_query(
            ReportType::Incident,
            ReportStatus::Exported,
            true,
            test_timestamp(3),
            test_timestamp(4),
            vec![ReportSectionType::ResponseRecommendation],
        );
        exported_report.alert_refs.push(alert_id.clone());
        exported_report
            .rollback_result_refs
            .push(sentinel_contracts::RollbackResultId::new_v4());

        (
            state.with_reports(vec![incident_report, exported_report, threat_report]),
            incident_id,
            alert_id,
            finding_id,
        )
    }

    fn report_for_query(
        report_type: ReportType,
        status: ReportStatus,
        redaction_passed: bool,
        created_at: Timestamp,
        updated_at: Timestamp,
        section_types: Vec<ReportSectionType>,
    ) -> Report {
        let mut summary = RedactionSummary::passed(vec![
            RedactedDataCategory::RawPacket,
            RedactedDataCategory::Payload,
            RedactedDataCategory::Token,
        ]);
        summary.passed = redaction_passed;
        summary.redacted_field_count = 3;
        summary.suppressed_section_count = if redaction_passed { 0 } else { 1 };

        let mut report = Report::new(
            report_type,
            "redacted report title",
            "redacted report summary",
            summary.clone(),
        )
        .expect("report");
        report.status = status;
        report.created_at = created_at;
        report.updated_at = updated_at;
        report.sections = section_types
            .into_iter()
            .map(|section_type| {
                ReportSection::new(section_type, "redacted section title", summary.clone())
                    .expect("section")
            })
            .collect();
        report
    }

    fn test_timestamp(day: u32) -> Timestamp {
        Timestamp::from_datetime(
            chrono::Utc
                .with_ymd_and_hms(2026, 6, day, 0, 0, 0)
                .single()
                .expect("test timestamp"),
        )
    }

    fn ip(value: &str) -> IpAddress {
        IpAddress::parse_str(value).expect("documentation ip")
    }
}
