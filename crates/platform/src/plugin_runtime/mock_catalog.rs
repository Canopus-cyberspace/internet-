use crate::observability::{HealthDependencyStatus, HealthSnapshot, HealthStatus, MetricValue};
use crate::plugin_runtime::runtime::PluginRuntime;
use crate::plugin_runtime::traits::{
    InternalPlugin, PluginLifecycle, PluginOutput, PluginResult, PluginRuntimeError,
};
use crate::plugin_runtime::PluginContext;
use sentinel_contracts::{
    CapabilityManifest, ContractDescriptor, DataSourceDescriptor, DataSourceKind,
    ManifestValidationError, MaturityLevel, MetricKind, MetricSchema, PermissionCategory,
    PermissionDescriptor, PermissionKey, PermissionRiskLevel, PluginDependency,
    PluginDependencyType, PluginId, PluginManifest, PluginStatefulness, PluginType, RefreshMode,
    RendererType, RuntimeMode, SchemaVersion, SupportLevel, UiContribution, UiContributionSlot,
    VersionRange,
};
use serde_json::json;
use std::collections::BTreeMap;

pub const MOCK_ONLY_LABEL: &str = "MOCK_ONLY";
pub const NOT_FOR_PRODUCTION_LABEL: &str = "NOT_FOR_PRODUCTION";
pub const STATIC_INTERNAL_LABEL: &str = "STATIC_INTERNAL";
pub const PRODUCT_PATH_LABEL: &str = "PRODUCT_PATH";
const PARTIAL_REAL_LABEL: &str = "PARTIAL_REAL";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CatalogFlavor {
    MockOnly,
    StaticInternal,
}

impl CatalogFlavor {
    fn is_mock_only(self) -> bool {
        matches!(self, Self::MockOnly)
    }

    fn production_ready(self) -> bool {
        false
    }

    fn mode_label(self) -> &'static str {
        match self {
            Self::MockOnly => MOCK_ONLY_LABEL,
            Self::StaticInternal => STATIC_INTERNAL_LABEL,
        }
    }

    fn production_status_label(self) -> &'static str {
        match self {
            Self::MockOnly => NOT_FOR_PRODUCTION_LABEL,
            Self::StaticInternal => PARTIAL_REAL_LABEL,
        }
    }

    fn metric_mode(self) -> &'static str {
        match self {
            Self::MockOnly => "mock_only",
            Self::StaticInternal => "static_internal",
        }
    }
}

#[derive(Clone, Debug)]
pub struct BuiltInPluginCatalog {
    plugins: Vec<MockPlugin>,
    capabilities: Vec<CapabilityManifest>,
    flavor: CatalogFlavor,
}

impl BuiltInPluginCatalog {
    pub fn mock_only() -> Result<Self, PluginRuntimeError> {
        let plugins = MockPluginManifestFactory::create_all_plugins(CatalogFlavor::MockOnly)
            .map_err(|error| PluginRuntimeError::ManifestInvalid(error.to_string()))?;
        let capabilities = MockPluginManifestFactory::create_capability_manifests(
            &plugins,
            CatalogFlavor::MockOnly,
        )
        .map_err(|error| PluginRuntimeError::ManifestInvalid(error.to_string()))?;

        Ok(Self {
            plugins,
            capabilities,
            flavor: CatalogFlavor::MockOnly,
        })
    }

    pub fn static_internal() -> Result<Self, PluginRuntimeError> {
        let plugins = MockPluginManifestFactory::create_all_plugins(CatalogFlavor::StaticInternal)
            .map_err(|error| PluginRuntimeError::ManifestInvalid(error.to_string()))?;
        let capabilities = MockPluginManifestFactory::create_capability_manifests(
            &plugins,
            CatalogFlavor::StaticInternal,
        )
        .map_err(|error| PluginRuntimeError::ManifestInvalid(error.to_string()))?;

        Ok(Self {
            plugins,
            capabilities,
            flavor: CatalogFlavor::StaticInternal,
        })
    }

    pub fn plugins(&self) -> &[MockPlugin] {
        &self.plugins
    }

    pub fn manifests(&self) -> Vec<&PluginManifest> {
        self.plugins
            .iter()
            .map(MockPlugin::manifest)
            .collect::<Vec<_>>()
    }

    pub fn capability_manifests(&self) -> &[CapabilityManifest] {
        &self.capabilities
    }

    pub fn mock_only_catalog(&self) -> bool {
        self.flavor.is_mock_only()
    }

    pub fn production_ready(&self) -> bool {
        self.flavor.production_ready()
    }

    pub fn contract_descriptors(&self) -> Vec<ContractDescriptor> {
        let mut by_name = BTreeMap::new();
        for manifest in self.manifests() {
            for contract in manifest
                .input_contracts
                .iter()
                .chain(manifest.output_contracts.iter())
            {
                by_name
                    .entry(contract.contract_name.clone())
                    .or_insert_with(|| contract.clone());
            }
        }
        by_name.into_values().collect()
    }

    pub fn register_with_runtime(
        &self,
        runtime: &mut PluginRuntime,
    ) -> Result<Vec<PluginId>, PluginRuntimeError> {
        self.plugins
            .iter()
            .cloned()
            .map(|plugin| runtime.register_static_plugin(Box::new(plugin)))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct MockPlugin {
    manifest: PluginManifest,
    capability_manifest: Option<CapabilityManifest>,
    health_provider: MockHealthProvider,
    metric_provider: MockMetricProvider,
}

impl MockPlugin {
    pub fn new(
        manifest: PluginManifest,
        capability_manifest: Option<CapabilityManifest>,
        health_provider: MockHealthProvider,
        metric_provider: MockMetricProvider,
    ) -> Self {
        Self {
            manifest,
            capability_manifest,
            health_provider,
            metric_provider,
        }
    }

    pub fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    pub fn metric_provider(&self) -> &MockMetricProvider {
        &self.metric_provider
    }

    pub fn health_provider(&self) -> &MockHealthProvider {
        &self.health_provider
    }
}

impl PluginLifecycle for MockPlugin {
    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(self.health_provider.snapshot(&self.manifest.plugin_id))
    }
}

impl InternalPlugin for MockPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn capability_manifest(&self) -> Option<&CapabilityManifest> {
        self.capability_manifest.as_ref()
    }

    fn process_event(
        &mut self,
        context: &mut PluginContext<'_>,
        _event: &sentinel_contracts::EventEnvelope,
    ) -> PluginResult<PluginOutput> {
        if !context.privacy.raw_content_persistence_forbidden() {
            return Err(PluginRuntimeError::LifecycleFailed {
                plugin_id: self.manifest.plugin_id.clone(),
                phase: "process_event",
                error_redacted: "mock plugin refuses unsafe persistence context".to_string(),
            });
        }

        Ok(PluginOutput {
            events: Vec::new(),
            health: vec![self.health_provider.snapshot(&self.manifest.plugin_id)],
            metrics: self
                .metric_provider
                .samples()
                .map_err(|error| PluginRuntimeError::ManifestInvalid(error.to_string()))?,
            audit_events: Vec::new(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct MockPluginManifestFactory;

impl MockPluginManifestFactory {
    pub fn create_all_mock_plugins() -> Result<Vec<MockPlugin>, ManifestValidationError> {
        Self::create_all_plugins(CatalogFlavor::MockOnly)
    }

    fn create_all_plugins(
        flavor: CatalogFlavor,
    ) -> Result<Vec<MockPlugin>, ManifestValidationError> {
        mock_plugin_specs()
            .into_iter()
            .map(|spec| Self::create_plugin(spec, flavor))
            .collect()
    }

    fn create_capability_manifests(
        plugins: &[MockPlugin],
        flavor: CatalogFlavor,
    ) -> Result<Vec<CapabilityManifest>, ManifestValidationError> {
        let mut grouped: BTreeMap<String, Vec<&MockPlugin>> = BTreeMap::new();
        for plugin in plugins {
            grouped
                .entry(plugin.manifest.capability_domain.clone())
                .or_default()
                .push(plugin);
        }

        grouped
            .into_iter()
            .map(|(domain, plugins)| {
                let mut manifest = CapabilityManifest::new(
                    domain.clone(),
                    capability_title(&domain),
                    capability_description(&domain, flavor),
                )?;
                manifest.maturity_level = capability_maturity(&domain, flavor);
                manifest.plugin_ids = plugins
                    .iter()
                    .map(|plugin| plugin.manifest.plugin_id.clone())
                    .collect();
                manifest.input_contracts = unique_contracts(
                    plugins
                        .iter()
                        .flat_map(|plugin| plugin.manifest.input_contracts.iter()),
                );
                manifest.output_contracts = unique_contracts(
                    plugins
                        .iter()
                        .flat_map(|plugin| plugin.manifest.output_contracts.iter()),
                );
                manifest.required_permissions = unique_permissions(
                    plugins
                        .iter()
                        .flat_map(|plugin| plugin.manifest.required_permissions.iter()),
                );
                manifest.ui_contributions = plugins
                    .iter()
                    .flat_map(|plugin| plugin.manifest.ui_contributions.iter().cloned())
                    .collect();
                Ok(manifest)
            })
            .collect()
    }

    fn create_plugin(
        spec: MockPluginSpec,
        flavor: CatalogFlavor,
    ) -> Result<MockPlugin, ManifestValidationError> {
        let plugin_id =
            PluginId::parse_str(spec.plugin_id).expect("built-in mock plugin ids are stable UUIDs");
        let mut manifest = PluginManifest::new(
            plugin_id.clone(),
            plugin_name(&spec, flavor),
            "0.1.0",
            spec.capability_domain,
            spec.plugin_type.clone(),
            spec.runtime_mode.clone(),
        )?;
        manifest.description = plugin_description(&spec, flavor);
        manifest.enabled_by_default = true;
        manifest.maturity_level = plugin_maturity(&spec, flavor);
        manifest.capability_tags = plugin_tags(&spec, flavor);
        manifest.input_contracts = spec
            .input_contracts
            .iter()
            .map(|name| contract(name))
            .collect();
        manifest.output_contracts = spec
            .output_contracts
            .iter()
            .map(|name| contract(name))
            .collect();
        manifest.dependencies = spec
            .required_plugin_dependencies
            .iter()
            .map(|plugin_key| required_plugin_dependency_for_flavor(plugin_key, flavor))
            .collect();
        manifest.required_permissions = spec
            .permissions
            .iter()
            .map(permission_descriptor)
            .collect::<Result<Vec<_>, _>>()?;
        manifest.metrics_schema = MockMetricProvider::new(spec.plugin_key, flavor).schemas()?;
        manifest.health_schema = MockHealthProvider::healthy(spec.plugin_key, flavor).schema();
        manifest.finding_types = spec.finding_types.iter().map(ToString::to_string).collect();
        manifest.graph_hint_types = spec
            .graph_hint_types
            .iter()
            .map(ToString::to_string)
            .collect();
        manifest.ui_contributions = MockUiContributionProvider::contributions(
            plugin_id,
            plugin_name(&spec, flavor).as_str(),
            spec.plugin_key,
            spec.capability_domain,
            spec.replacement_task,
            spec.plugin_type.clone(),
            flavor,
        )?;
        manifest.statefulness = spec.statefulness;
        manifest.checkpoint_support = spec.checkpoint_support;
        manifest.replay_support = SupportLevel::Optional;
        manifest.validate()?;

        Ok(MockPlugin::new(
            manifest,
            None,
            MockHealthProvider::healthy(spec.plugin_key, flavor),
            MockMetricProvider::new(spec.plugin_key, flavor),
        ))
    }
}

#[derive(Clone, Debug)]
pub struct MockMetricProvider {
    plugin_key: String,
    flavor: CatalogFlavor,
}

impl MockMetricProvider {
    fn new(plugin_key: impl Into<String>, flavor: CatalogFlavor) -> Self {
        Self {
            plugin_key: plugin_key.into(),
            flavor,
        }
    }

    pub fn schemas(&self) -> Result<Vec<MetricSchema>, ManifestValidationError> {
        Ok(vec![
            metric_schema(
                self.metric_name("events_in_total"),
                MetricKind::Counter,
                self.metric_description("events received"),
            )?,
            metric_schema(
                self.metric_name("events_out_total"),
                MetricKind::Counter,
                self.metric_description("events emitted"),
            )?,
            metric_schema(
                self.metric_name("errors_total"),
                MetricKind::Counter,
                self.metric_description("processing errors"),
            )?,
            metric_schema(
                self.metric_name("latency_ms"),
                MetricKind::Gauge,
                self.metric_description("processing latency"),
            )?,
            metric_schema(
                self.metric_name("queue_lag"),
                MetricKind::Gauge,
                self.metric_description("queue lag"),
            )?,
        ])
    }

    pub fn samples(
        &self,
    ) -> Result<Vec<crate::observability::MetricSample>, crate::observability::MetricValidationError>
    {
        use crate::observability::MetricSample;

        let mut events_in =
            MetricSample::new(self.metric_name("events_in_total"), MetricValue::Counter(0))?;
        events_in
            .labels
            .insert("mode".to_string(), self.flavor.metric_mode().to_string());

        let mut events_out = MetricSample::new(
            self.metric_name("events_out_total"),
            MetricValue::Counter(0),
        )?;
        events_out
            .labels
            .insert("mode".to_string(), self.flavor.metric_mode().to_string());

        let mut errors =
            MetricSample::new(self.metric_name("errors_total"), MetricValue::Counter(0))?;
        errors
            .labels
            .insert("mode".to_string(), self.flavor.metric_mode().to_string());

        let mut latency =
            MetricSample::new(self.metric_name("latency_ms"), MetricValue::Gauge(0.0))?;
        latency
            .labels
            .insert("mode".to_string(), self.flavor.metric_mode().to_string());

        let mut lag = MetricSample::new(self.metric_name("queue_lag"), MetricValue::Gauge(0.0))?;
        lag.labels
            .insert("mode".to_string(), self.flavor.metric_mode().to_string());

        Ok(vec![events_in, events_out, errors, latency, lag])
    }

    fn metric_name(&self, suffix: &str) -> String {
        format!("{}.{}", self.plugin_key, suffix)
    }

    fn metric_description(&self, purpose: &str) -> String {
        match self.flavor {
            CatalogFlavor::MockOnly => format!("Mock {purpose}"),
            CatalogFlavor::StaticInternal => format!("Static internal plugin {purpose}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MockHealthProvider {
    plugin_key: String,
    status: HealthStatus,
    flavor: CatalogFlavor,
}

impl MockHealthProvider {
    fn healthy(plugin_key: impl Into<String>, flavor: CatalogFlavor) -> Self {
        Self {
            plugin_key: plugin_key.into(),
            status: HealthStatus::Healthy,
            flavor,
        }
    }

    pub fn schema(&self) -> sentinel_contracts::HealthSchema {
        sentinel_contracts::HealthSchema {
            data_freshness: Some(sentinel_contracts::HealthSignalDescriptor {
                name: format!("{}_catalog_freshness", self.flavor.metric_mode()),
                description: Some("Catalog metadata freshness".to_string()),
                unit: Some("ms".to_string()),
                critical: false,
            }),
            queue_lag: Some(sentinel_contracts::HealthSignalDescriptor {
                name: format!("{}_queue_lag", self.flavor.metric_mode()),
                description: Some("Catalog queue lag".to_string()),
                unit: Some("count".to_string()),
                critical: false,
            }),
            ..Default::default()
        }
    }

    pub fn snapshot(&self, plugin_id: &PluginId) -> HealthSnapshot {
        let mut snapshot = HealthSnapshot::new(
            crate::observability::HealthSubject::Plugin {
                plugin_id: plugin_id.clone(),
            },
            self.status.clone(),
        );
        snapshot.message_redacted = Some(health_message(self.plugin_key.as_str(), self.flavor));
        snapshot.dependencies = vec![HealthDependencyStatus {
            dependency_name: match self.flavor {
                CatalogFlavor::MockOnly => "mock_catalog".to_string(),
                CatalogFlavor::StaticInternal => "static_internal_catalog".to_string(),
            },
            status: HealthStatus::Healthy,
            required: true,
            reason_redacted: Some("Static metadata provider is available".to_string()),
        }];
        snapshot.stale_after_ms = Some(30_000);
        snapshot
    }
}

#[derive(Clone, Debug)]
pub struct MockUiContributionProvider;

impl MockUiContributionProvider {
    #[allow(clippy::too_many_arguments)]
    fn contributions(
        plugin_id: PluginId,
        plugin_name: &str,
        plugin_key: &str,
        capability_domain: &str,
        replacement_task: &str,
        plugin_type: PluginType,
        flavor: CatalogFlavor,
    ) -> Result<Vec<UiContribution>, ManifestValidationError> {
        let context = UiContributionContext {
            plugin_key,
            capability_domain,
            replacement_task,
            flavor,
        };
        let mut contributions = vec![
            contribution(
                plugin_id.clone(),
                UiContributionSlot::ComponentCenterCard,
                RendererType::HealthBadge,
                format!("{plugin_name} status"),
                DataSourceKind::PluginCatalog,
                &context,
            )?,
            contribution(
                plugin_id.clone(),
                UiContributionSlot::ComponentCenterDetailPanel,
                RendererType::KeyValuePanel,
                format!("{plugin_name} details"),
                DataSourceKind::StaticManifestData,
                &context,
            )?,
            contribution(
                plugin_id.clone(),
                UiContributionSlot::CapabilityAnalysisPanel,
                RendererType::MetricCard,
                format!("{plugin_name} metrics"),
                DataSourceKind::CapabilityView,
                &context,
            )?,
        ];

        match plugin_type {
            PluginType::Graph => contributions.push(contribution(
                plugin_id,
                UiContributionSlot::GraphProjection,
                RendererType::GraphProjection,
                format!("{plugin_name} projection"),
                DataSourceKind::CapabilityView,
                &context,
            )?),
            PluginType::Response => contributions.push(contribution(
                plugin_id,
                UiContributionSlot::ResponseActionPanel,
                RendererType::ResponseActionCard,
                format!("{plugin_name} recommendation"),
                DataSourceKind::CapabilityView,
                &context,
            )?),
            PluginType::Report => contributions.push(contribution(
                plugin_id,
                UiContributionSlot::ReportSection,
                RendererType::ReportSection,
                format!("{plugin_name} section"),
                DataSourceKind::CapabilityView,
                &context,
            )?),
            PluginType::PlatformDetection => contributions.push(contribution(
                plugin_id,
                UiContributionSlot::InvestigationEvidencePanel,
                RendererType::EvidenceList,
                format!("{plugin_name} evidence"),
                DataSourceKind::CapabilityView,
                &context,
            )?),
            PluginType::Protocol | PluginType::Transform | PluginType::Source => contributions
                .push(contribution(
                    plugin_id,
                    UiContributionSlot::NetworkPanel,
                    RendererType::Table,
                    format!("{plugin_name} records"),
                    DataSourceKind::CapabilityView,
                    &context,
                )?),
            _ => {}
        }

        Ok(contributions)
    }
}

#[derive(Clone, Debug)]
struct MockPluginSpec {
    plugin_key: &'static str,
    plugin_id: &'static str,
    plugin_name: &'static str,
    description: &'static str,
    replacement_task: &'static str,
    capability_domain: &'static str,
    plugin_type: PluginType,
    runtime_mode: RuntimeMode,
    input_contracts: &'static [&'static str],
    output_contracts: &'static [&'static str],
    required_plugin_dependencies: &'static [&'static str],
    permissions: Vec<MockPermissionSpec>,
    finding_types: &'static [&'static str],
    graph_hint_types: &'static [&'static str],
    statefulness: PluginStatefulness,
    checkpoint_support: SupportLevel,
}

#[derive(Clone, Debug)]
struct MockPermissionSpec {
    key: &'static str,
    category: PermissionCategory,
    risk_level: PermissionRiskLevel,
    description: &'static str,
    scopes: &'static [&'static str],
}

fn mock_plugin_specs() -> Vec<MockPluginSpec> {
    vec![
        MockPluginSpec {
            plugin_key: "packet_capture",
            plugin_id: "00000000-0000-0000-0000-000000000191",
            plugin_name: "Packet Capture Mock",
            description: "Metadata source placeholder for capture adapter UI and registry validation.",
            replacement_task: "330_capture_adapter_metadata",
            capability_domain: "network_visibility",
            plugin_type: PluginType::Source,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[],
            output_contracts: &["raw.packet.metadata", "operational.health"],
            required_plugin_dependencies: &[],
            permissions: vec![
                data_permission("read.capture.metadata"),
                data_permission("write.capture.metadata"),
            ],
            finding_types: &[],
            graph_hint_types: &[],
            statefulness: PluginStatefulness::MemoryState,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "packet_normalization",
            plugin_id: "00000000-0000-0000-0000-000000000192",
            plugin_name: "Packet Normalization Mock",
            description: "Transform placeholder for packet metadata normalization.",
            replacement_task: "360_mock_network_pipeline",
            capability_domain: "network_visibility",
            plugin_type: PluginType::Transform,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &["raw.packet.metadata"],
            output_contracts: &["network.packet.record"],
            required_plugin_dependencies: &["packet_capture"],
            permissions: vec![
                data_permission("read.capture.metadata"),
                data_permission("write.network.packet"),
            ],
            finding_types: &[],
            graph_hint_types: &[],
            statefulness: PluginStatefulness::Stateless,
            checkpoint_support: SupportLevel::None,
        },
        MockPluginSpec {
            plugin_key: "flow_sessionization",
            plugin_id: "00000000-0000-0000-0000-000000000193",
            plugin_name: "Flow Sessionization Mock",
            description: "Session boundary placeholder for flow and session records.",
            replacement_task: "370_flow_dns_tls_http_observations",
            capability_domain: "network_visibility",
            plugin_type: PluginType::Transform,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &["network.packet.record", "identity.flow_attribution"],
            output_contracts: &["network.flow.record", "network.session.record", "graph.hint"],
            required_plugin_dependencies: &["packet_normalization"],
            permissions: vec![
                data_permission("read.network.packet"),
                data_permission("write.network.flow"),
                data_permission("write.graph_hint"),
            ],
            finding_types: &[],
            graph_hint_types: &["process_connects_to_ip"],
            statefulness: PluginStatefulness::Checkpointed,
            checkpoint_support: SupportLevel::Required,
        },
        MockPluginSpec {
            plugin_key: "dns_security",
            plugin_id: "00000000-0000-0000-0000-000000000194",
            plugin_name: "DNS Security Mock",
            description: "Protocol placeholder for DNS observations and DNS security signals.",
            replacement_task: "370_flow_dns_tls_http_observations",
            capability_domain: "network_visibility",
            plugin_type: PluginType::Protocol,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &["network.flow.record", "identity.process_context"],
            output_contracts: &["network.dns.observation", "security.observation", "graph.hint"],
            required_plugin_dependencies: &["flow_sessionization", "process_context"],
            permissions: vec![
                data_permission("read.network.flow"),
                data_permission("read.identity.process_context"),
                data_permission("write.network.dns"),
                data_permission("write.security.observation"),
                data_permission("write.graph_hint"),
            ],
            finding_types: &["high_entropy_domain_hint", "nxdomain_burst_hint", "dns_tunnel_suspected_lite"],
            graph_hint_types: &["process_queries_domain"],
            statefulness: PluginStatefulness::MemoryState,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "tls_fingerprint",
            plugin_id: "00000000-0000-0000-0000-000000000195",
            plugin_name: "TLS Fingerprint Mock",
            description: "Protocol placeholder for TLS metadata observations and fingerprints.",
            replacement_task: "370_flow_dns_tls_http_observations",
            capability_domain: "network_visibility",
            plugin_type: PluginType::Protocol,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &["network.flow.record"],
            output_contracts: &["network.tls.observation", "security.observation", "graph.hint"],
            required_plugin_dependencies: &["flow_sessionization"],
            permissions: vec![
                data_permission("read.network.flow"),
                data_permission("write.network.tls"),
                data_permission("write.security.observation"),
                data_permission("write.graph_hint"),
            ],
            finding_types: &["rare_tls_fingerprint_hint", "sni_certificate_mismatch_hint", "suspicious_certificate_hint"],
            graph_hint_types: &["process_uses_tls_fingerprint"],
            statefulness: PluginStatefulness::Stateless,
            checkpoint_support: SupportLevel::None,
        },
        MockPluginSpec {
            plugin_key: "process_context",
            plugin_id: "00000000-0000-0000-0000-000000000196",
            plugin_name: "Process Context Mock",
            description: "Identity placeholder for best-effort process and flow attribution.",
            replacement_task: "340_process_attribution_stub",
            capability_domain: "identity",
            plugin_type: PluginType::Enrichment,
            runtime_mode: RuntimeMode::Periodic,
            input_contracts: &["network.flow.record"],
            output_contracts: &["identity.process_context", "identity.flow_attribution", "graph.hint"],
            required_plugin_dependencies: &["flow_sessionization"],
            permissions: vec![
                data_permission("read.network.flow"),
                data_permission("write.identity.process_context"),
                data_permission("write.identity.flow_attribution"),
                data_permission("write.graph_hint"),
            ],
            finding_types: &[],
            graph_hint_types: &["user_runs_process", "process_spawned_process", "process_connects_to_ip"],
            statefulness: PluginStatefulness::Cached,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "asset_exposure",
            plugin_id: "00000000-0000-0000-0000-00000000019a",
            plugin_name: "Asset Exposure Mock",
            description: "Asset/service exposure catalog entry for metadata-only local listening-port observations, findings, evidence, and graph hints.",
            replacement_task: "380_asset_exposure_inventory",
            capability_domain: "asset_identity",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &["asset.service_inventory"],
            output_contracts: &[
                "asset.exposure",
                "security.observation",
                "security.finding",
                "security.evidence",
                "graph.hint",
            ],
            required_plugin_dependencies: &["process_context"],
            permissions: vec![
                scoped_data_permission("read.asset.service_inventory", &["asset.service_inventory"]),
                scoped_data_permission("write.asset.exposure", &["asset.exposure"]),
                scoped_data_permission("write.security.observation", &["security.observation"]),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &[
                "asset_risk.new_listening_port",
                "asset_risk.risky_port_exposed",
                "asset_risk.unknown_process_listener",
                "asset_risk.public_service_hint",
            ],
            graph_hint_types: &["process_listens_on_port"],
            statefulness: PluginStatefulness::MemoryState,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "c2_detection",
            plugin_id: "00000000-0000-0000-0000-00000000019d",
            plugin_name: "C2 Detection Mock",
            description: "Metadata-only C2 detection catalog entry for bounded flow, session, DNS, TLS, process, and local intelligence runtime wiring.",
            replacement_task: "400_c2_detection_mvp_static_runtime_binding",
            capability_domain: "platform_detection",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "network.flow.record",
                "network.session.record",
                "network.dns.observation",
                "network.tls.observation",
                "identity.process_context",
                "intel.domain_context",
                "intel.ip_context",
                "intel.cloud_context",
                "intel.certificate_context",
            ],
            output_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &[
                "flow_sessionization",
                "dns_security_v2",
                "process_context",
                "domain_reputation",
                "infrastructure_intelligence",
                "evidence_management",
            ],
            permissions: vec![
                scoped_data_permission(
                    "read.network.metadata",
                    &[
                        "network.flow.record",
                        "network.session.record",
                        "network.dns.observation",
                        "network.tls.observation",
                    ],
                ),
                scoped_data_permission(
                    "read.identity.process_context",
                    &["identity.process_context"],
                ),
                scoped_data_permission(
                    "read.intelligence.local_context",
                    &[
                        "intel.domain_context",
                        "intel.ip_context",
                        "intel.cloud_context",
                        "intel.certificate_context",
                    ],
                ),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &["security.finding.c2"],
            graph_hint_types: &["suspicious_c2_relation"],
            statefulness: PluginStatefulness::Baseline,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "exfiltration_detection",
            plugin_id: "00000000-0000-0000-0000-00000000019b",
            plugin_name: "Exfiltration Detection Mock",
            description: "Metadata-only exfiltration detection catalog entry for flow, process, intelligence, finding, evidence, risk-hint, and graph-hint runtime wiring.",
            replacement_task: "410_exfiltration_detection_mvp",
            capability_domain: "platform_detection",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "network.flow.record",
                "network.session.record",
                "network.http.metadata",
                "identity.process_context",
                "intel.ip_context",
                "intel.cloud_context",
                "security.finding",
                "graph.hint",
            ],
            output_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &[
                "flow_sessionization",
                "process_context",
                "infrastructure_intelligence",
                "evidence_management",
            ],
            permissions: vec![
                scoped_data_permission(
                    "read.network.metadata",
                    &[
                        "network.flow.record",
                        "network.session.record",
                        "network.http.metadata",
                    ],
                ),
                scoped_data_permission(
                    "read.identity.process_context",
                    &["identity.process_context"],
                ),
                scoped_data_permission(
                    "read.intelligence.local_context",
                    &["intel.ip_context", "intel.cloud_context"],
                ),
                scoped_data_permission(
                    "read.security.finding",
                    &["security.finding", "graph.hint"],
                ),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &["security.finding.exfiltration"],
            graph_hint_types: &["process_uploads_to_cloud"],
            statefulness: PluginStatefulness::Baseline,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "lateral_movement_lite",
            plugin_id: "00000000-0000-0000-0000-00000000019c",
            plugin_name: "Lateral Movement Lite Mock",
            description: "Metadata-only lateral movement lite catalog entry for flow, process, asset exposure, finding, evidence, risk-hint, and graph-hint runtime wiring.",
            replacement_task: "420_lateral_movement_lite",
            capability_domain: "platform_detection",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "network.flow.record",
                "network.session.record",
                "identity.process_context",
                "asset.record",
                "asset.service_record",
                "asset.port_exposure",
                "asset.exposure.observation",
                "asset.exposure",
                "security.finding.asset_risk",
            ],
            output_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &[
                "flow_sessionization",
                "process_context",
                "asset_exposure",
                "evidence_management",
            ],
            permissions: vec![
                scoped_data_permission(
                    "read.network.metadata",
                    &["network.flow.record", "network.session.record"],
                ),
                scoped_data_permission(
                    "read.identity.process_context",
                    &["identity.process_context"],
                ),
                scoped_data_permission(
                    "read.asset.exposure",
                    &[
                        "asset.record",
                        "asset.service_record",
                        "asset.port_exposure",
                        "asset.exposure.observation",
                        "asset.exposure",
                        "security.finding.asset_risk",
                    ],
                ),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &["security.finding.lateral_movement_lite"],
            graph_hint_types: &[
                "lateral_internal_fanout",
                "lateral_service_probe",
                "lateral_exposure_linked_movement",
            ],
            statefulness: PluginStatefulness::Baseline,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "domain_reputation",
            plugin_id: "00000000-0000-0000-0000-000000000197",
            plugin_name: "Domain Reputation Mock",
            description: "Offline intelligence placeholder for domain context. Intelligence alone does not alert.",
            replacement_task: "350_local_intelligence_stub",
            capability_domain: "intelligence",
            plugin_type: PluginType::Enrichment,
            runtime_mode: RuntimeMode::Hybrid,
            input_contracts: &["network.dns.observation"],
            output_contracts: &["intel.domain_context"],
            required_plugin_dependencies: &["dns_security"],
            permissions: vec![
                data_permission("read.network.dns"),
                data_permission("read.intel.local"),
                data_permission("write.intel.domain_context"),
            ],
            finding_types: &[],
            graph_hint_types: &[],
            statefulness: PluginStatefulness::Cached,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "infrastructure_intelligence",
            plugin_id: "00000000-0000-0000-0000-000000000198",
            plugin_name: "Infrastructure Intelligence Mock",
            description: "Offline intelligence placeholder for destination and cloud context.",
            replacement_task: "350_local_intelligence_stub",
            capability_domain: "intelligence",
            plugin_type: PluginType::Enrichment,
            runtime_mode: RuntimeMode::Hybrid,
            input_contracts: &["network.flow.record"],
            output_contracts: &["intel.ip_context", "intel.cloud_context"],
            required_plugin_dependencies: &["flow_sessionization"],
            permissions: vec![
                data_permission("read.network.flow"),
                data_permission("read.intel.local"),
                data_permission("write.intel.ip_context"),
                data_permission("write.intel.cloud_context"),
            ],
            finding_types: &[],
            graph_hint_types: &[],
            statefulness: PluginStatefulness::Cached,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "evidence_management",
            plugin_id: "00000000-0000-0000-0000-000000000199",
            plugin_name: "Evidence Management Mock",
            description: "Platform detection placeholder for evidence bundle validation and explanation surfaces.",
            replacement_task: "390_evidence_management",
            capability_domain: "platform_detection",
            plugin_type: PluginType::PlatformDetection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &["security.observation", "security.finding", "graph.hint"],
            output_contracts: &["security.evidence", "security.finding"],
            required_plugin_dependencies: &["dns_security", "tls_fingerprint"],
            permissions: vec![
                data_permission("read.security.observation"),
                data_permission("read.security.finding"),
                data_permission("read.graph_hint"),
                data_permission("write.security.evidence"),
                data_permission("write.finding"),
            ],
            finding_types: &["finding_with_explanation"],
            graph_hint_types: &[],
            statefulness: PluginStatefulness::MemoryState,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "risk_based_alerting",
            plugin_id: "00000000-0000-0000-0000-0000000001a0",
            plugin_name: "Risk Based Alerting Mock",
            description: "Promotion placeholder for risk, alert, and incident candidate surfaces.",
            replacement_task: "430_risk_alert_incident",
            capability_domain: "platform_detection",
            plugin_type: PluginType::PlatformDetection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "asset.exposure",
                "identity.process_context",
                "service.capability_status",
            ],
            output_contracts: &[
                "security.risk",
                "security.alert_candidate",
                "security.alert",
                "security.incident_candidate",
                "security.incident",
            ],
            required_plugin_dependencies: &[
                "evidence_management",
                "asset_exposure",
                "exfiltration_detection",
                "lateral_movement_lite",
            ],
            permissions: vec![
                scoped_data_permission(
                    "read.security.finding",
                    &["security.finding", "security.evidence"],
                ),
                scoped_data_permission("read.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission(
                    "read.service.capability_status",
                    &["service.capability_status"],
                ),
                scoped_data_permission("write.security.risk", &["security.risk"]),
                scoped_data_permission(
                    "write.security.alert",
                    &["security.alert", "security.alert_candidate"],
                ),
                scoped_data_permission(
                    "write.security.incident",
                    &["security.incident", "security.incident_candidate"],
                ),
            ],
            finding_types: &[],
            graph_hint_types: &[],
            statefulness: PluginStatefulness::Checkpointed,
            checkpoint_support: SupportLevel::Required,
        },
        MockPluginSpec {
            plugin_key: "graph_stage",
            plugin_id: "00000000-0000-0000-0000-0000000001a1",
            plugin_name: "Graph Stage Mock",
            description: "Graph ownership placeholder. Only this stage is allowed to represent canonical graph writes later.",
            replacement_task: "440_graph_stage_canonical",
            capability_domain: "graph",
            plugin_type: PluginType::Graph,
            runtime_mode: RuntimeMode::Hybrid,
            input_contracts: &["graph.hint", "security.finding", "security.alert", "security.incident", "response.result"],
            output_contracts: &["graph.update"],
            required_plugin_dependencies: &["risk_based_alerting"],
            permissions: vec![
                data_permission("read.graph_hint"),
                data_permission("read.security.finding"),
                data_permission("read.security.alert"),
                data_permission("read.security.incident"),
                data_permission("read.response.result"),
                data_permission("write.graph.update"),
            ],
            finding_types: &[],
            graph_hint_types: &["suspicious_c2_relation", "process_uploads_to_cloud", "process_listens_on_port"],
            statefulness: PluginStatefulness::Checkpointed,
            checkpoint_support: SupportLevel::Required,
        },
        MockPluginSpec {
            plugin_key: "response_planning",
            plugin_id: "00000000-0000-0000-0000-0000000001a2",
            plugin_name: "Response Planning Mock",
            description: "Recommend-first response placeholder. It does not execute firewall, QoS, or process actions.",
            replacement_task: "460_response_policy_planning",
            capability_domain: "response",
            plugin_type: PluginType::Response,
            runtime_mode: RuntimeMode::OnDemand,
            input_contracts: &[
                "security.finding",
                "security.alert",
                "security.incident",
                "graph.path",
                "settings.response_policy",
                "settings.response_policy_rule",
            ],
            output_contracts: &["response.plan", "response.policy.decision", "response.approval.request"],
            required_plugin_dependencies: &["risk_based_alerting", "graph_stage"],
            permissions: vec![
                data_permission("read.security.finding"),
                data_permission("read.security.alert"),
                data_permission("read.security.incident"),
                data_permission("read.graph.path"),
                scoped_data_permission(
                    "read.settings.response_policy",
                    &["settings.response_policy", "settings.response_policy_rule"],
                ),
                response_permission("write.response_plan"),
            ],
            finding_types: &[],
            graph_hint_types: &[],
            statefulness: PluginStatefulness::Stateless,
            checkpoint_support: SupportLevel::None,
        },
        MockPluginSpec {
            plugin_key: "incident_report",
            plugin_id: "00000000-0000-0000-0000-0000000001a3",
            plugin_name: "Incident Report Mock",
            description: "Report generation placeholder for redacted report sections. It does not export files.",
            replacement_task: "480_report_generation_redaction",
            capability_domain: "reporting",
            plugin_type: PluginType::Report,
            runtime_mode: RuntimeMode::OnDemand,
            input_contracts: &["security.incident", "security.finding", "security.evidence", "graph.path", "response.result"],
            output_contracts: &["report.generated"],
            required_plugin_dependencies: &["response_planning", "graph_stage"],
            permissions: vec![
                data_permission("read.security.incident"),
                data_permission("read.security.finding"),
                data_permission("read.security.evidence"),
                data_permission("read.graph.path"),
                data_permission("read.response.result"),
                data_permission("write.report.generated"),
            ],
            finding_types: &[],
            graph_hint_types: &[],
            statefulness: PluginStatefulness::Stateless,
            checkpoint_support: SupportLevel::None,
        },
        MockPluginSpec {
            plugin_key: "dns_security_v2",
            plugin_id: "00000000-0000-0000-0000-0000000001a4",
            plugin_name: "DNS Security V2 Mock",
            description: "Metadata-only DNS detection catalog entry for bounded DNS heuristics, evidence, risk hints, and graph hints.",
            replacement_task: "portable_network_web_metadata_pack",
            capability_domain: "platform_detection",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &["network.dns.observation"],
            output_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &["flow_sessionization"],
            permissions: vec![
                scoped_data_permission("read.network.dns", &["network.dns.observation"]),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &[
                "portable.dns_security_v2.high_entropy_labels",
                "portable.dns_security_v2.nxdomain_burst",
                "portable.dns_security_v2.fast_flux_lite",
            ],
            graph_hint_types: &[
                "portable_finding_implicates_domain",
                "portable_finding_implicates_client_ip",
            ],
            statefulness: PluginStatefulness::Baseline,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "http_analysis_v1",
            plugin_id: "00000000-0000-0000-0000-0000000001a5",
            plugin_name: "HTTP Analysis V1 Mock",
            description: "Metadata-only HTTP analysis catalog entry for bounded request, status, volume, and route-shape signals.",
            replacement_task: "portable_network_web_metadata_pack",
            capability_domain: "platform_detection",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "network.flow.record",
                "network.session.record",
                "network.http.metadata",
            ],
            output_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &["flow_sessionization"],
            permissions: vec![
                scoped_data_permission(
                    "read.network.metadata",
                    &[
                        "network.flow.record",
                        "network.session.record",
                        "network.http.metadata",
                    ],
                ),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &[
                "portable.http_analysis_v1.status_code_burst",
                "portable.http_analysis_v1.request_volume_anomaly",
                "portable.http_analysis_v1.upload_download_imbalance",
            ],
            graph_hint_types: &[
                "portable_finding_implicates_http_host",
                "portable_finding_implicates_api_endpoint",
            ],
            statefulness: PluginStatefulness::Baseline,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "api_security_lite",
            plugin_id: "00000000-0000-0000-0000-0000000001a6",
            plugin_name: "API Security Lite Mock",
            description: "Metadata-only API analysis catalog entry for endpoint enumeration, probing, bounded user-agent classification, and error clusters.",
            replacement_task: "portable_network_web_metadata_pack",
            capability_domain: "platform_detection",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &["network.flow.record", "network.http.metadata"],
            output_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &["http_analysis_v1"],
            permissions: vec![
                scoped_data_permission(
                    "read.network.metadata",
                    &["network.flow.record", "network.http.metadata"],
                ),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &[
                "portable.api_security_lite.endpoint_enumeration",
                "portable.api_security_lite.method_probing",
                "portable.api_security_lite.high_error_rate_endpoint_cluster",
            ],
            graph_hint_types: &["portable_finding_implicates_api_endpoint"],
            statefulness: PluginStatefulness::Baseline,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "waf_security_lite",
            plugin_id: "00000000-0000-0000-0000-0000000001a7",
            plugin_name: "WAF Security Lite Mock",
            description: "Metadata-only WAF analysis catalog entry for blocked bursts, concentration, rule-id bursts, and bypass-suspected transitions.",
            replacement_task: "portable_network_web_metadata_pack",
            capability_domain: "platform_detection",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &["network.flow.record", "network.http.metadata"],
            output_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &["http_analysis_v1"],
            permissions: vec![
                scoped_data_permission(
                    "read.network.metadata",
                    &["network.flow.record", "network.http.metadata"],
                ),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &[
                "portable.waf_security_lite.repeated_blocked_attack_class",
                "portable.waf_security_lite.rule_id_burst",
                "portable.waf_security_lite.bypass_suspected_status_transition",
            ],
            graph_hint_types: &[
                "portable_finding_implicates_api_endpoint",
                "portable_finding_implicates_client_ip",
            ],
            statefulness: PluginStatefulness::Baseline,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "quic_http3_security_lite",
            plugin_id: "00000000-0000-0000-0000-0000000001a8",
            plugin_name: "QUIC HTTP3 Security Lite Mock",
            description: "Metadata-only QUIC and HTTP/3 catalog entry for rare destination categories, fallback patterns, and bounded error bursts.",
            replacement_task: "portable_metadata_expansion_slice",
            capability_domain: "platform_detection",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "network.flow.record",
                "network.tls.observation",
                "network.http.metadata",
            ],
            output_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &["flow_sessionization", "http_analysis_v1"],
            permissions: vec![
                scoped_data_permission(
                    "read.network.metadata",
                    &[
                        "network.flow.record",
                        "network.tls.observation",
                        "network.http.metadata",
                    ],
                ),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &[
                "portable.quic_http3_security_lite.rare_destination_category",
                "portable.quic_http3_security_lite.protocol_downgrade_fallback_pattern",
                "portable.quic_http3_security_lite.suspicious_api_error_burst",
            ],
            graph_hint_types: &[
                "portable_finding_implicates_http_host",
                "portable_finding_implicates_api_endpoint",
            ],
            statefulness: PluginStatefulness::Baseline,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "remote_admin_protocol_lite",
            plugin_id: "00000000-0000-0000-0000-0000000001a9",
            plugin_name: "SMB RDP SSH Observation Lite Mock",
            description: "Metadata-only remote-admin observation catalog entry for SMB, RDP, and SSH spread and first-seen bounded session patterns.",
            replacement_task: "portable_metadata_expansion_slice",
            capability_domain: "platform_detection",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "network.flow.record",
                "network.session.record",
                "identity.auth_metadata",
                "identity.smb_operational_metadata",
                "identity.ssh_operational_metadata",
            ],
            output_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &["flow_sessionization"],
            permissions: vec![
                scoped_data_permission(
                    "read.network.metadata",
                    &["network.flow.record", "network.session.record"],
                ),
                scoped_data_permission(
                    "read.identity.metadata",
                    &[
                        "identity.auth_metadata",
                        "identity.smb_operational_metadata",
                        "identity.ssh_operational_metadata",
                    ],
                ),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &[
                "portable.remote_admin_protocol_lite.rdp_spread_pattern",
                "portable.remote_admin_protocol_lite.rdp_first_seen_use",
                "portable.remote_admin_protocol_lite.ssh_first_seen_use",
            ],
            graph_hint_types: &[
                "portable_finding_implicates_client_ip",
                "portable_finding_implicates_remote_admin_target",
            ],
            statefulness: PluginStatefulness::Baseline,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "auth_identity_analysis_lite",
            plugin_id: "00000000-0000-0000-0000-0000000001aa",
            plugin_name: "Auth Identity Analysis Lite Mock",
            description: "Metadata-only auth and identity analysis catalog entry for bounded auth failure bursts, MFA fatigue-like patterns, suspicious providers, privileged-role access, and remote-admin auth correlations.",
            replacement_task: "portable_auth_identity_slice",
            capability_domain: "identity",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "identity.auth_metadata",
                "network.flow.record",
                "network.session.record",
            ],
            output_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &["flow_sessionization", "remote_admin_protocol_lite"],
            permissions: vec![
                scoped_data_permission(
                    "read.identity.auth_metadata",
                    &[
                        "identity.auth_metadata",
                        "network.flow.record",
                        "network.session.record",
                    ],
                ),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &[
                "portable.auth_identity_analysis_lite.auth_failure_burst",
                "portable.auth_identity_analysis_lite.mfa_fatigue_like_pattern",
                "portable.auth_identity_analysis_lite.suspicious_provider_category",
                "portable.auth_identity_analysis_lite.privileged_role_access",
                "portable.auth_identity_analysis_lite.remote_admin_auth_failure_correlation",
            ],
            graph_hint_types: &[
                "portable_finding_implicates_identity_session",
                "portable_finding_implicates_auth_provider",
                "portable_finding_implicates_auth_service",
            ],
            statefulness: PluginStatefulness::Baseline,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "saas_cloud_abuse_lite",
            plugin_id: "00000000-0000-0000-0000-0000000001ab",
            plugin_name: "SaaS Cloud Abuse Lite Mock",
            description: "Metadata-only SaaS/cloud abuse catalog entry for provider-category, object-storage, API status, and auth/API/WAF correlation signals.",
            replacement_task: "provider_category_saas_cloud_abuse_slice",
            capability_domain: "cloud",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "cloud.saas_metadata",
                "identity.auth_metadata",
                "network.http.metadata",
                "security.finding",
            ],
            output_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &[
                "api_security_lite",
                "waf_security_lite",
                "auth_identity_analysis_lite",
            ],
            permissions: vec![
                scoped_data_permission(
                    "read.cloud.saas_metadata",
                    &[
                        "cloud.saas_metadata",
                        "identity.auth_metadata",
                        "network.http.metadata",
                        "security.finding",
                    ],
                ),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &[
                "portable.saas_cloud_abuse_lite.suspicious_object_storage_upload",
                "portable.saas_cloud_abuse_lite.unusual_saas_api_error_burst",
                "portable.saas_cloud_abuse_lite.repeated_risky_provider_access",
                "portable.saas_cloud_abuse_lite.api_waf_to_cloud_activity_correlation",
                "portable.saas_cloud_abuse_lite.possible_token_misuse_pattern",
            ],
            graph_hint_types: &[
                "portable_finding_implicates_provider_category",
                "portable_finding_implicates_object_storage_category",
                "portable_finding_implicates_saas_endpoint",
                "portable_finding_implicates_identity_session",
            ],
            statefulness: PluginStatefulness::Baseline,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "deception_event_lite",
            plugin_id: "00000000-0000-0000-0000-0000000001ac",
            plugin_name: "Deception Event Lite Mock",
            description: "Metadata-only deception event catalog entry for bounded decoy interaction, unusual protocol, and correlation signals without honeypot deployment or credential capture.",
            replacement_task: "deception_honeypot_event_ingest_lite_slice",
            capability_domain: "deception",
            plugin_type: PluginType::Detection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "deception.event_metadata",
                "security.finding",
                "security.risk_hint",
            ],
            output_contracts: &[
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &[
                "dns_security_v2",
                "http_analysis_v1",
                "api_security_lite",
                "waf_security_lite",
                "quic_http3_security_lite",
                "remote_admin_protocol_lite",
                "auth_identity_analysis_lite",
                "saas_cloud_abuse_lite",
            ],
            permissions: vec![
                scoped_data_permission(
                    "read.deception.event_metadata",
                    &[
                        "deception.event_metadata",
                        "security.finding",
                        "security.risk_hint",
                    ],
                ),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &[
                "portable.deception_event_lite.repeated_decoy_interaction",
                "portable.deception_event_lite.unusual_protocol_interaction",
                "portable.deception_event_lite.correlated_suspicious_activity",
                "portable.deception_event_lite.risk_chain_correlation",
            ],
            graph_hint_types: &[
                "portable_finding_implicates_decoy_sensor",
                "portable_finding_implicates_deception_category",
                "portable_finding_implicates_protocol_category",
            ],
            statefulness: PluginStatefulness::Baseline,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "multi_layer_security_fusion",
            plugin_id: "00000000-0000-0000-0000-0000000001ad",
            plugin_name: "Multi-Layer Security Fusion Mock",
            description: "Metadata-only sampler, SecurityFact normalization, and data-driven attack-hypothesis fusion foundation.",
            replacement_task: "multi_layer_security_fusion_agent_foundation",
            capability_domain: "platform_detection",
            plugin_type: PluginType::PlatformDetection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "security.fusion.context",
                "network.dns.observation",
                "network.http.metadata",
                "identity.auth_metadata",
                "cloud.saas_metadata",
                "deception.event_metadata",
                "network.sdn_control_plane.metadata",
                "security.finding",
            ],
            output_contracts: &[
                "security.fact",
                "security.hypothesis",
                "security.fusion.summary",
                "security.finding",
                "security.evidence",
                "security.risk_hint",
                "graph.hint",
            ],
            required_plugin_dependencies: &[
                "dns_security_v2",
                "http_analysis_v1",
                "api_security_lite",
                "waf_security_lite",
                "auth_identity_analysis_lite",
                "saas_cloud_abuse_lite",
                "deception_event_lite",
            ],
            permissions: vec![
                scoped_data_permission(
                    "read.security.fusion_metadata",
                    &[
                        "security.fusion.context",
                        "network.dns.observation",
                        "network.http.metadata",
                        "identity.auth_metadata",
                        "cloud.saas_metadata",
                        "deception.event_metadata",
                        "network.sdn_control_plane.metadata",
                        "security.finding",
                    ],
                ),
                scoped_data_permission("write.security.fact", &["security.fact"]),
                scoped_data_permission("write.security.hypothesis", &["security.hypothesis"]),
                scoped_data_permission("write.security.fusion_summary", &["security.fusion.summary"]),
                scoped_data_permission("write.security.finding", &["security.finding"]),
                scoped_data_permission("write.security.evidence", &["security.evidence"]),
                scoped_data_permission("write.security.risk_hint", &["security.risk_hint"]),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &["fusion.possible_multi_layer_pattern"],
            graph_hint_types: &["hypothesis_correlates_security_facts"],
            statefulness: PluginStatefulness::Checkpointed,
            checkpoint_support: SupportLevel::Required,
        },
        MockPluginSpec {
            plugin_key: "native_sampler_fact",
            plugin_id: "00000000-0000-0000-0000-0000000001ae",
            plugin_name: "Native Sampler Fact Runtime",
            description: "Authorized read-only native health, service-category, and process-category metadata fact runtime.",
            replacement_task: "authorized_read_only_native_process_category_sampler_runtime",
            capability_domain: "platform_detection",
            plugin_type: PluginType::Transform,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "native.health.metadata",
                "native.service.metadata",
                "native.process.metadata",
                "native.process_parent.metadata",
            ],
            output_contracts: &[
                "endpoint.native_health.category_fact",
                "endpoint.service.category_fact",
                "endpoint.process.category_fact",
                "endpoint.process_parent.category_fact",
            ],
            required_plugin_dependencies: &["multi_layer_security_fusion"],
            permissions: vec![
                scoped_data_permission(
                    "read.native.bounded_metadata",
                    &[
                        "native.health.metadata",
                        "native.service.metadata",
                        "native.process.metadata",
                        "native.process_parent.metadata",
                    ],
                ),
                scoped_data_permission(
                    "write.endpoint.native_health.category_fact",
                    &["endpoint.native_health.category_fact"],
                ),
                scoped_data_permission(
                    "write.endpoint.service.category_fact",
                    &["endpoint.service.category_fact"],
                ),
                scoped_data_permission(
                    "write.endpoint.process.category_fact",
                    &["endpoint.process.category_fact"],
                ),
                scoped_data_permission(
                    "write.endpoint.process_parent.category_fact",
                    &["endpoint.process_parent.category_fact"],
                ),
            ],
            finding_types: &[],
            graph_hint_types: &["native_sampler_batch_context_fact"],
            statefulness: PluginStatefulness::MemoryState,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "native_network_fact",
            plugin_id: "00000000-0000-0000-0000-0000000001b0",
            plugin_name: "Native Network Fact Runtime",
            description: "ServiceHost-owned metadata-only native network fact runtime for bounded IP Helper and ETW category visibility.",
            replacement_task: "explicit_native_network_servicehost_handoff",
            capability_domain: "platform_detection",
            plugin_type: PluginType::Transform,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &["native.ip_helper.metadata", "native.etw_network.metadata"],
            output_contracts: &["native.connection.category_fact"],
            required_plugin_dependencies: &["multi_layer_security_fusion"],
            permissions: vec![
                scoped_data_permission(
                    "read.native.network_metadata",
                    &["native.ip_helper.metadata", "native.etw_network.metadata"],
                ),
                scoped_data_permission(
                    "write.native.connection.category_fact",
                    &["native.connection.category_fact"],
                ),
            ],
            finding_types: &[],
            graph_hint_types: &["native_connection_category_fact"],
            statefulness: PluginStatefulness::MemoryState,
            checkpoint_support: SupportLevel::Optional,
        },
        MockPluginSpec {
            plugin_key: "endpoint_threat_analysis_lite",
            plugin_id: "00000000-0000-0000-0000-0000000001af",
            plugin_name: "Endpoint Threat Analysis Lite Mock",
            description: "Metadata-only endpoint threat analysis catalog entry for validated category facts, portable evidence, baseline context, risk hints, ATT&CK context, graph refs, and advisory outputs.",
            replacement_task: "endpoint_threat_analysis_lite_runtime_wiring",
            capability_domain: "platform_detection",
            plugin_type: PluginType::PlatformDetection,
            runtime_mode: RuntimeMode::Streaming,
            input_contracts: &[
                "endpoint.native_health.category_fact",
                "endpoint.service.category_fact",
                "endpoint.process.category_fact",
                "endpoint.process_parent.category_fact",
                "security.finding",
                "security.risk_hint",
                "security.hypothesis",
                "security.fusion.summary",
            ],
            output_contracts: &[
                "endpoint.threat.candidate",
                "endpoint.threat.finding",
                "endpoint.threat.evidence",
                "endpoint.threat.risk_hint",
                "endpoint.visibility.advisory",
                "endpoint.threat.rejected",
                "graph.hint",
                "audit.endpoint_threat_analysis",
            ],
            required_plugin_dependencies: &["native_sampler_fact", "multi_layer_security_fusion"],
            permissions: vec![
                scoped_data_permission(
                    "read.endpoint.threat_context",
                    &[
                        "endpoint.native_health.category_fact",
                        "endpoint.service.category_fact",
                        "endpoint.process.category_fact",
                        "endpoint.process_parent.category_fact",
                        "security.finding",
                        "security.risk_hint",
                        "security.hypothesis",
                        "security.fusion.summary",
                    ],
                ),
                scoped_data_permission(
                    "write.endpoint.threat_analysis",
                    &[
                        "endpoint.threat.candidate",
                        "endpoint.threat.finding",
                        "endpoint.threat.evidence",
                        "endpoint.threat.risk_hint",
                        "endpoint.visibility.advisory",
                        "endpoint.threat.rejected",
                        "audit.endpoint_threat_analysis",
                    ],
                ),
                scoped_data_permission("write.graph_hint", &["graph.hint"]),
            ],
            finding_types: &[
                "endpoint.possible_category_population_change",
                "endpoint.possible_parent_category_transition",
                "endpoint.possible_auth_pressure_context",
                "endpoint.possible_service_change_context",
                "endpoint.possible_saas_cloud_context",
                "endpoint.possible_deception_context",
            ],
            graph_hint_types: &[
                "endpoint_finding_to_process_category_fact",
                "endpoint_finding_to_parent_relation_fact",
                "endpoint_finding_to_service_category_fact",
                "endpoint_finding_to_evidence",
                "endpoint_finding_to_hypothesis",
                "endpoint_finding_to_risk",
                "endpoint_finding_to_attack_candidate",
            ],
            statefulness: PluginStatefulness::MemoryState,
            checkpoint_support: SupportLevel::Optional,
        },
    ]
}

fn contract(name: &str) -> ContractDescriptor {
    let mut descriptor = ContractDescriptor::new(name, SchemaVersion::new(1, 0, 0))
        .expect("built-in mock contract names are valid");
    descriptor.topic = Some(name.to_string());
    descriptor
}

fn metric_schema(
    metric_name: String,
    kind: MetricKind,
    description: impl Into<String>,
) -> Result<MetricSchema, ManifestValidationError> {
    let mut schema = MetricSchema::new(metric_name, kind, description)?;
    schema.labels = vec!["mode".to_string()];
    Ok(schema)
}

fn data_permission(key: &'static str) -> MockPermissionSpec {
    MockPermissionSpec {
        key,
        category: PermissionCategory::DataAccess,
        risk_level: PermissionRiskLevel::Low,
        description: "metadata-only mock catalog permission",
        scopes: &[],
    }
}

fn scoped_data_permission(
    key: &'static str,
    scopes: &'static [&'static str],
) -> MockPermissionSpec {
    MockPermissionSpec {
        scopes,
        ..data_permission(key)
    }
}

fn response_permission(key: &'static str) -> MockPermissionSpec {
    MockPermissionSpec {
        key,
        category: PermissionCategory::ResponseAccess,
        risk_level: PermissionRiskLevel::Low,
        description: "recommendation-only mock response permission",
        scopes: &[],
    }
}

fn permission_descriptor(
    spec: &MockPermissionSpec,
) -> Result<PermissionDescriptor, ManifestValidationError> {
    let mut descriptor = PermissionDescriptor::new(
        PermissionKey::new(spec.key)?,
        spec.category.clone(),
        spec.risk_level.clone(),
        spec.description,
    )?;
    descriptor.scopes = spec.scopes.iter().map(ToString::to_string).collect();
    Ok(descriptor)
}

struct UiContributionContext<'a> {
    plugin_key: &'a str,
    capability_domain: &'a str,
    replacement_task: &'a str,
    flavor: CatalogFlavor,
}

fn required_plugin_dependency_for_flavor(
    plugin_key: &str,
    flavor: CatalogFlavor,
) -> PluginDependency {
    PluginDependency {
        dependency_type: PluginDependencyType::RequiredPlugin,
        plugin_id: Some(mock_plugin_id(plugin_key)),
        capability_id: None,
        contract: None,
        name: Some(plugin_name_for_key(plugin_key, flavor).to_string()),
        version_requirement: VersionRange::any(),
        startup_order: None,
        reason: Some(match flavor {
            CatalogFlavor::MockOnly => "MOCK_ONLY catalog pipeline dependency".to_string(),
            CatalogFlavor::StaticInternal => {
                "static internal plugin catalog dependency".to_string()
            }
        }),
    }
}

fn mock_plugin_id(plugin_key: &str) -> PluginId {
    let id = match plugin_key {
        "packet_capture" => "00000000-0000-0000-0000-000000000191",
        "packet_normalization" => "00000000-0000-0000-0000-000000000192",
        "flow_sessionization" => "00000000-0000-0000-0000-000000000193",
        "dns_security" => "00000000-0000-0000-0000-000000000194",
        "tls_fingerprint" => "00000000-0000-0000-0000-000000000195",
        "process_context" => "00000000-0000-0000-0000-000000000196",
        "asset_exposure" => "00000000-0000-0000-0000-00000000019a",
        "c2_detection" => "00000000-0000-0000-0000-00000000019d",
        "exfiltration_detection" => "00000000-0000-0000-0000-00000000019b",
        "lateral_movement_lite" => "00000000-0000-0000-0000-00000000019c",
        "domain_reputation" => "00000000-0000-0000-0000-000000000197",
        "infrastructure_intelligence" => "00000000-0000-0000-0000-000000000198",
        "evidence_management" => "00000000-0000-0000-0000-000000000199",
        "risk_based_alerting" => "00000000-0000-0000-0000-0000000001a0",
        "graph_stage" => "00000000-0000-0000-0000-0000000001a1",
        "response_planning" => "00000000-0000-0000-0000-0000000001a2",
        "incident_report" => "00000000-0000-0000-0000-0000000001a3",
        "dns_security_v2" => "00000000-0000-0000-0000-0000000001a4",
        "http_analysis_v1" => "00000000-0000-0000-0000-0000000001a5",
        "api_security_lite" => "00000000-0000-0000-0000-0000000001a6",
        "waf_security_lite" => "00000000-0000-0000-0000-0000000001a7",
        "quic_http3_security_lite" => "00000000-0000-0000-0000-0000000001a8",
        "remote_admin_protocol_lite" => "00000000-0000-0000-0000-0000000001a9",
        "auth_identity_analysis_lite" => "00000000-0000-0000-0000-0000000001aa",
        "saas_cloud_abuse_lite" => "00000000-0000-0000-0000-0000000001ab",
        "deception_event_lite" => "00000000-0000-0000-0000-0000000001ac",
        "multi_layer_security_fusion" => "00000000-0000-0000-0000-0000000001ad",
        "native_sampler_fact" => "00000000-0000-0000-0000-0000000001ae",
        "native_network_fact" => "00000000-0000-0000-0000-0000000001b0",
        "endpoint_threat_analysis_lite" => "00000000-0000-0000-0000-0000000001af",
        _ => panic!("unknown built-in mock plugin key: {plugin_key}"),
    };

    PluginId::parse_str(id).expect("built-in mock plugin ids are stable UUIDs")
}

fn plugin_name_for_key(plugin_key: &str, flavor: CatalogFlavor) -> &'static str {
    match plugin_key {
        "packet_capture" if flavor.is_mock_only() => "Packet Capture Mock",
        "packet_capture" => "Packet Capture Adapter",
        "packet_normalization" if flavor.is_mock_only() => "Packet Normalization Mock",
        "packet_normalization" => "Packet Normalization",
        "flow_sessionization" if flavor.is_mock_only() => "Flow Sessionization Mock",
        "flow_sessionization" => "Flow Sessionization",
        "dns_security" if flavor.is_mock_only() => "DNS Security Mock",
        "dns_security" => "DNS Security",
        "tls_fingerprint" if flavor.is_mock_only() => "TLS Fingerprint Mock",
        "tls_fingerprint" => "TLS Fingerprint",
        "process_context" if flavor.is_mock_only() => "Process Context Mock",
        "process_context" => "Process Context",
        "asset_exposure" if flavor.is_mock_only() => "Asset Exposure Mock",
        "asset_exposure" => "Asset Exposure",
        "c2_detection" if flavor.is_mock_only() => "C2 Detection Mock",
        "c2_detection" => "C2 Detection",
        "exfiltration_detection" if flavor.is_mock_only() => "Exfiltration Detection Mock",
        "exfiltration_detection" => "Exfiltration Detection",
        "lateral_movement_lite" if flavor.is_mock_only() => "Lateral Movement Lite Mock",
        "lateral_movement_lite" => "Lateral Movement Lite",
        "domain_reputation" if flavor.is_mock_only() => "Domain Reputation Mock",
        "domain_reputation" => "Domain Reputation",
        "infrastructure_intelligence" if flavor.is_mock_only() => {
            "Infrastructure Intelligence Mock"
        }
        "infrastructure_intelligence" => "Infrastructure Intelligence",
        "evidence_management" if flavor.is_mock_only() => "Evidence Management Mock",
        "evidence_management" => "Evidence Management",
        "risk_based_alerting" if flavor.is_mock_only() => "Risk Based Alerting Mock",
        "risk_based_alerting" => "Risk Based Alerting",
        "graph_stage" if flavor.is_mock_only() => "Graph Stage Mock",
        "graph_stage" => "Graph Stage",
        "response_planning" if flavor.is_mock_only() => "Response Planning Mock",
        "response_planning" => "Response Planning",
        "incident_report" if flavor.is_mock_only() => "Incident Report Mock",
        "incident_report" => "Incident Report",
        "dns_security_v2" if flavor.is_mock_only() => "DNS Security V2 Mock",
        "dns_security_v2" => "DNS Security V2",
        "http_analysis_v1" if flavor.is_mock_only() => "HTTP Analysis V1 Mock",
        "http_analysis_v1" => "HTTP Analysis V1",
        "api_security_lite" if flavor.is_mock_only() => "API Security Lite Mock",
        "api_security_lite" => "API Security Lite",
        "waf_security_lite" if flavor.is_mock_only() => "WAF Security Lite Mock",
        "waf_security_lite" => "WAF Security Lite",
        "quic_http3_security_lite" if flavor.is_mock_only() => "QUIC HTTP3 Security Lite Mock",
        "quic_http3_security_lite" => "QUIC HTTP3 Security Lite",
        "remote_admin_protocol_lite" if flavor.is_mock_only() => {
            "SMB RDP SSH Observation Lite Mock"
        }
        "remote_admin_protocol_lite" => "SMB RDP SSH Observation Lite",
        "auth_identity_analysis_lite" if flavor.is_mock_only() => {
            "Auth Identity Analysis Lite Mock"
        }
        "auth_identity_analysis_lite" => "Auth Identity Analysis Lite",
        "saas_cloud_abuse_lite" if flavor.is_mock_only() => "SaaS Cloud Abuse Lite Mock",
        "saas_cloud_abuse_lite" => "SaaS Cloud Abuse Lite",
        "deception_event_lite" if flavor.is_mock_only() => "Deception Event Lite Mock",
        "deception_event_lite" => "Deception Event Lite",
        "multi_layer_security_fusion" if flavor.is_mock_only() => {
            "Multi-Layer Security Fusion Mock"
        }
        "multi_layer_security_fusion" => "Multi-Layer Security Fusion",
        "native_sampler_fact" => "Native Sampler Fact Runtime",
        "native_network_fact" => "Native Network Fact Runtime",
        "endpoint_threat_analysis_lite" if flavor.is_mock_only() => {
            "Endpoint Threat Analysis Lite Mock"
        }
        "endpoint_threat_analysis_lite" => "Endpoint Threat Analysis Lite",
        _ => "Unknown Mock Plugin",
    }
}

fn plugin_name(spec: &MockPluginSpec, flavor: CatalogFlavor) -> String {
    match flavor {
        CatalogFlavor::MockOnly => spec.plugin_name.to_string(),
        CatalogFlavor::StaticInternal => plugin_name_for_key(spec.plugin_key, flavor).to_string(),
    }
}

fn plugin_description(spec: &MockPluginSpec, flavor: CatalogFlavor) -> String {
    match flavor {
        CatalogFlavor::MockOnly => format!(
            "{MOCK_ONLY_LABEL} {NOT_FOR_PRODUCTION_LABEL}. {} Replaced or extended by Task {}.",
            spec.description, spec.replacement_task
        ),
        CatalogFlavor::StaticInternal => format!(
            "{STATIC_INTERNAL_LABEL} {PARTIAL_REAL_LABEL}. Static internal manifest for {}. Runtime behavior remains bounded by existing product capability paths; privileged adapters stay deferred to Task {}.",
            plugin_name_for_key(spec.plugin_key, flavor),
            spec.replacement_task
        ),
    }
}

fn plugin_tags(spec: &MockPluginSpec, flavor: CatalogFlavor) -> Vec<String> {
    match flavor {
        CatalogFlavor::MockOnly => vec![
            MOCK_ONLY_LABEL.to_string(),
            NOT_FOR_PRODUCTION_LABEL.to_string(),
            format!("replacement_task:{}", spec.replacement_task),
        ],
        CatalogFlavor::StaticInternal => vec![
            STATIC_INTERNAL_LABEL.to_string(),
            PRODUCT_PATH_LABEL.to_string(),
            PARTIAL_REAL_LABEL.to_string(),
            format!("successor_task:{}", spec.replacement_task),
        ],
    }
}

fn plugin_maturity(spec: &MockPluginSpec, flavor: CatalogFlavor) -> MaturityLevel {
    match flavor {
        CatalogFlavor::MockOnly => MaturityLevel::Experimental,
        CatalogFlavor::StaticInternal => match spec.plugin_type {
            PluginType::Detection | PluginType::PlatformDetection => MaturityLevel::L2Detectable,
            PluginType::Graph => MaturityLevel::L3Modeling,
            PluginType::Response | PluginType::Report => MaturityLevel::L4Reasoning,
            _ => MaturityLevel::L1Observable,
        },
    }
}

fn capability_description(domain: &str, flavor: CatalogFlavor) -> String {
    match flavor {
        CatalogFlavor::MockOnly => format!("{MOCK_ONLY_LABEL} capability bundle for {domain}"),
        CatalogFlavor::StaticInternal => {
            format!("{STATIC_INTERNAL_LABEL} capability bundle for {domain}")
        }
    }
}

fn capability_maturity(domain: &str, flavor: CatalogFlavor) -> MaturityLevel {
    match flavor {
        CatalogFlavor::MockOnly => MaturityLevel::Experimental,
        CatalogFlavor::StaticInternal => match domain {
            "platform_detection" => MaturityLevel::L2Detectable,
            "graph" => MaturityLevel::L3Modeling,
            "response" | "reporting" => MaturityLevel::L4Reasoning,
            _ => MaturityLevel::L1Observable,
        },
    }
}

fn health_message(plugin_key: &str, flavor: CatalogFlavor) -> String {
    match flavor {
        CatalogFlavor::MockOnly => format!(
            "{MOCK_ONLY_LABEL} {NOT_FOR_PRODUCTION_LABEL} {} catalog entry",
            plugin_key
        ),
        CatalogFlavor::StaticInternal => format!(
            "{STATIC_INTERNAL_LABEL} {PARTIAL_REAL_LABEL} {} manifest registered through the static internal plugin path",
            plugin_key
        ),
    }
}

fn contribution(
    plugin_id: PluginId,
    slot: UiContributionSlot,
    renderer_type: RendererType,
    title: String,
    data_source_kind: DataSourceKind,
    context: &UiContributionContext<'_>,
) -> Result<UiContribution, ManifestValidationError> {
    let mut contribution = UiContribution::new(
        plugin_id,
        slot,
        renderer_type,
        title,
        DataSourceDescriptor::new(data_source_kind),
    )?;
    contribution.schema = json!({
        "mode": context.flavor.mode_label(),
        "production_status": context.flavor.production_status_label(),
        "plugin_key": context.plugin_key,
        "capability_domain": context.capability_domain,
        "replacement_task": context.replacement_task
    });
    contribution.refresh_mode = RefreshMode::Polling;
    Ok(contribution)
}

fn unique_contracts<'a>(
    contracts: impl Iterator<Item = &'a ContractDescriptor>,
) -> Vec<ContractDescriptor> {
    let mut by_name = BTreeMap::new();
    for contract in contracts {
        by_name
            .entry(contract.contract_name.clone())
            .or_insert_with(|| contract.clone());
    }
    by_name.into_values().collect()
}

fn unique_permissions<'a>(
    permissions: impl Iterator<Item = &'a PermissionDescriptor>,
) -> Vec<PermissionDescriptor> {
    let mut by_key = BTreeMap::new();
    for permission in permissions {
        by_key
            .entry(permission.permission.to_string())
            .or_insert_with(|| permission.clone());
    }
    by_key.into_values().collect()
}

fn capability_title(domain: &str) -> String {
    domain
        .split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{PermissionResolver, PermissionSubject};
    use crate::registry::ContractRegistry;
    use sentinel_contracts::{EventEnvelope, EventType, TraceContext};

    #[test]
    fn catalog_contains_required_mock_plugins_with_labels_and_replacements() {
        let catalog = BuiltInPluginCatalog::mock_only().expect("catalog");
        let names = catalog
            .plugins()
            .iter()
            .map(|plugin| plugin.manifest().plugin_name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(catalog.plugins().len(), 30);
        assert!(names.contains(&"Packet Capture Mock"));
        assert!(names.contains(&"Asset Exposure Mock"));
        assert!(names.contains(&"DNS Security V2 Mock"));
        assert!(names.contains(&"HTTP Analysis V1 Mock"));
        assert!(names.contains(&"API Security Lite Mock"));
        assert!(names.contains(&"WAF Security Lite Mock"));
        assert!(names.contains(&"QUIC HTTP3 Security Lite Mock"));
        assert!(names.contains(&"SMB RDP SSH Observation Lite Mock"));
        assert!(names.contains(&"Auth Identity Analysis Lite Mock"));
        assert!(names.contains(&"SaaS Cloud Abuse Lite Mock"));
        assert!(names.contains(&"Deception Event Lite Mock"));
        assert!(names.contains(&"Multi-Layer Security Fusion Mock"));
        assert!(names.contains(&"Native Sampler Fact Runtime"));
        assert!(names.contains(&"Native Network Fact Runtime"));
        assert!(names.contains(&"Endpoint Threat Analysis Lite Mock"));
        assert!(names.contains(&"C2 Detection Mock"));
        assert!(names.contains(&"Exfiltration Detection Mock"));
        assert!(names.contains(&"Lateral Movement Lite Mock"));
        assert!(names.contains(&"Risk Based Alerting Mock"));
        assert!(names.contains(&"Incident Report Mock"));

        for plugin in catalog.plugins() {
            let manifest = plugin.manifest();
            assert!(manifest
                .capability_tags
                .iter()
                .any(|tag| tag == MOCK_ONLY_LABEL));
            assert!(manifest
                .capability_tags
                .iter()
                .any(|tag| tag == NOT_FOR_PRODUCTION_LABEL));
            assert!(manifest
                .capability_tags
                .iter()
                .any(|tag| tag.starts_with("replacement_task:")));
            assert!(!manifest.required_permissions.iter().any(|permission| {
                permission.permission.as_str().contains("raw_packet")
                    || permission.permission.as_str().contains("payload")
                    || permission.permission.as_str().contains("http_body")
                    || permission.permission.as_str().contains("token")
                    || permission.permission.as_str().contains("credential")
                    || permission.permission.as_str().contains("api_key")
            }));
            manifest.validate().expect("valid mock manifest");
        }
    }

    #[test]
    fn static_internal_catalog_uses_product_manifest_metadata_without_mock_labels() {
        let catalog = BuiltInPluginCatalog::static_internal().expect("catalog");
        let names = catalog
            .plugins()
            .iter()
            .map(|plugin| plugin.manifest().plugin_name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(catalog.plugins().len(), 30);
        assert!(!catalog.mock_only_catalog());
        assert!(!catalog.production_ready());
        assert!(names.contains(&"Packet Capture Adapter"));
        assert!(names.contains(&"Asset Exposure"));
        assert!(names.contains(&"DNS Security V2"));
        assert!(names.contains(&"HTTP Analysis V1"));
        assert!(names.contains(&"API Security Lite"));
        assert!(names.contains(&"WAF Security Lite"));
        assert!(names.contains(&"QUIC HTTP3 Security Lite"));
        assert!(names.contains(&"SMB RDP SSH Observation Lite"));
        assert!(names.contains(&"Auth Identity Analysis Lite"));
        assert!(names.contains(&"SaaS Cloud Abuse Lite"));
        assert!(names.contains(&"Deception Event Lite"));
        assert!(names.contains(&"Multi-Layer Security Fusion"));
        assert!(names.contains(&"Native Sampler Fact Runtime"));
        assert!(names.contains(&"Native Network Fact Runtime"));
        assert!(names.contains(&"Endpoint Threat Analysis Lite"));
        assert!(names.contains(&"C2 Detection"));
        assert!(names.contains(&"Exfiltration Detection"));
        assert!(names.contains(&"Lateral Movement Lite"));
        assert!(names.contains(&"Risk Based Alerting"));
        assert!(names.contains(&"Incident Report"));

        for plugin in catalog.plugins() {
            let manifest = plugin.manifest();
            assert!(manifest
                .capability_tags
                .iter()
                .any(|tag| tag == STATIC_INTERNAL_LABEL));
            assert!(manifest
                .capability_tags
                .iter()
                .any(|tag| tag == PRODUCT_PATH_LABEL));
            assert!(manifest
                .capability_tags
                .iter()
                .any(|tag| tag == PARTIAL_REAL_LABEL));
            assert!(!manifest
                .capability_tags
                .iter()
                .any(|tag| tag == MOCK_ONLY_LABEL));
            assert!(!manifest
                .capability_tags
                .iter()
                .any(|tag| tag == NOT_FOR_PRODUCTION_LABEL));
            assert!(manifest.description.contains(STATIC_INTERNAL_LABEL));
            assert!(!manifest.description.contains(MOCK_ONLY_LABEL));
            assert!(manifest.ui_contributions.iter().all(|contribution| {
                contribution.schema["mode"] == STATIC_INTERNAL_LABEL
                    && contribution.schema["production_status"] == PARTIAL_REAL_LABEL
            }));
            let health = plugin.health_provider().snapshot(&manifest.plugin_id);
            assert!(health
                .message_redacted
                .as_deref()
                .is_some_and(|message| message.contains(STATIC_INTERNAL_LABEL)));
            assert!(!health
                .message_redacted
                .as_deref()
                .is_some_and(|message| message.contains(MOCK_ONLY_LABEL)));
            manifest.validate().expect("valid static internal manifest");
        }

        assert!(catalog
            .capability_manifests()
            .iter()
            .all(|manifest| manifest.description.contains(STATIC_INTERNAL_LABEL)));
    }

    #[test]
    fn static_internal_risk_alerting_declares_real_candidate_contracts_and_starts() {
        let catalog = BuiltInPluginCatalog::static_internal().expect("catalog");
        let manifest = catalog
            .manifests()
            .into_iter()
            .find(|manifest| manifest.plugin_name == "Risk Based Alerting")
            .expect("risk alerting manifest");

        let input_contracts = manifest
            .input_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<Vec<_>>();
        for required in [
            "security.finding",
            "security.evidence",
            "security.risk_hint",
            "asset.exposure",
            "identity.process_context",
            "service.capability_status",
        ] {
            assert!(
                input_contracts.contains(&required),
                "missing risk-alerting input contract {required}"
            );
        }

        let output_contracts = manifest
            .output_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<Vec<_>>();
        for required in [
            "security.risk",
            "security.alert_candidate",
            "security.alert",
            "security.incident_candidate",
            "security.incident",
        ] {
            assert!(
                output_contracts.contains(&required),
                "missing risk-alerting output contract {required}"
            );
        }

        let permission = manifest
            .required_permissions
            .iter()
            .find(|permission| permission.permission.as_str() == "read.security.risk_hint")
            .expect("risk hint read permission");
        assert_eq!(permission.scopes, vec!["security.risk_hint".to_string()]);
        let permission = manifest
            .required_permissions
            .iter()
            .find(|permission| permission.permission.as_str() == "read.service.capability_status")
            .expect("service capability status read permission");
        assert_eq!(
            permission.scopes,
            vec!["service.capability_status".to_string()]
        );
        let permission = manifest
            .required_permissions
            .iter()
            .find(|permission| permission.permission.as_str() == "write.security.alert")
            .expect("alert write permission");
        assert!(permission
            .scopes
            .iter()
            .any(|scope| scope == "security.alert_candidate"));
        let permission = manifest
            .required_permissions
            .iter()
            .find(|permission| permission.permission.as_str() == "write.security.incident")
            .expect("incident write permission");
        assert!(permission
            .scopes
            .iter()
            .any(|scope| scope == "security.incident_candidate"));

        let risk_plugin_id = manifest.plugin_id.clone();
        let mut runtime = PluginRuntime::new();
        catalog
            .register_with_runtime(&mut runtime)
            .expect("register static catalog");

        let mut contracts = ContractRegistry::new();
        for contract in catalog.contract_descriptors() {
            contracts.register(contract).expect("register contract");
        }

        let mut permissions = PermissionResolver::new();
        for manifest in catalog.manifests() {
            permissions.register_plugin_manifest_permissions(manifest);
        }

        let validation = runtime
            .registry()
            .validate_startup(&risk_plugin_id, &contracts, &permissions)
            .expect("startup validation");
        assert!(
            validation.allowed,
            "risk alerting startup should be allowed: {:?}",
            validation.issues
        );
    }

    #[test]
    fn static_internal_endpoint_threat_analysis_declares_bounded_runtime_contracts_and_starts() {
        let catalog = BuiltInPluginCatalog::static_internal().expect("catalog");
        let manifest = catalog
            .manifests()
            .into_iter()
            .find(|manifest| manifest.plugin_name == "Endpoint Threat Analysis Lite")
            .expect("endpoint threat manifest");

        let input_contracts = manifest
            .input_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<Vec<_>>();
        for required in [
            "endpoint.process.category_fact",
            "endpoint.process_parent.category_fact",
            "endpoint.service.category_fact",
            "security.finding",
            "security.hypothesis",
            "security.fusion.summary",
        ] {
            assert!(
                input_contracts.contains(&required),
                "missing endpoint input contract {required}"
            );
        }

        let output_contracts = manifest
            .output_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<Vec<_>>();
        for required in [
            "endpoint.threat.candidate",
            "endpoint.threat.finding",
            "endpoint.threat.evidence",
            "endpoint.threat.risk_hint",
            "endpoint.visibility.advisory",
            "endpoint.threat.rejected",
            "audit.endpoint_threat_analysis",
        ] {
            assert!(
                output_contracts.contains(&required),
                "missing endpoint output contract {required}"
            );
        }

        assert!(!manifest.required_permissions.iter().any(|permission| {
            permission.permission.as_str().contains("raw")
                || permission.permission.as_str().contains("process_identity")
                || permission.permission.as_str().contains("response")
                || permission.permission.as_str().contains("credential")
        }));

        let endpoint_plugin_id = manifest.plugin_id.clone();
        let mut runtime = PluginRuntime::new();
        catalog
            .register_with_runtime(&mut runtime)
            .expect("register static catalog");

        let mut contracts = ContractRegistry::new();
        for contract in catalog.contract_descriptors() {
            contracts.register(contract).expect("register contract");
        }

        let mut permissions = PermissionResolver::new();
        for manifest in catalog.manifests() {
            permissions.register_plugin_manifest_permissions(manifest);
        }

        let validation = runtime
            .registry()
            .validate_startup(&endpoint_plugin_id, &contracts, &permissions)
            .expect("startup validation");
        assert!(
            validation.allowed,
            "endpoint threat startup should be allowed: {:?}",
            validation.issues
        );
    }

    #[test]
    fn static_internal_asset_exposure_declares_metadata_only_runtime_contracts_and_starts() {
        let catalog = BuiltInPluginCatalog::static_internal().expect("catalog");
        let manifest = catalog
            .manifests()
            .into_iter()
            .find(|manifest| manifest.plugin_name == "Asset Exposure")
            .expect("asset exposure manifest");

        let input_contracts = manifest
            .input_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<Vec<_>>();
        assert!(input_contracts.contains(&"asset.service_inventory"));

        let output_contracts = manifest
            .output_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<Vec<_>>();
        for required in [
            "asset.exposure",
            "security.observation",
            "security.finding",
            "security.evidence",
            "graph.hint",
        ] {
            assert!(
                output_contracts.contains(&required),
                "missing asset-exposure output contract {required}"
            );
        }
        for forbidden in [
            "security.alert",
            "security.incident",
            "graph.update",
            "graph.path",
            "response.plan",
            "response.result",
            "report.generated",
            "report.exported",
        ] {
            assert!(
                !output_contracts.contains(&forbidden),
                "asset exposure must not declare forbidden output {forbidden}"
            );
        }
        assert!(manifest.required_permissions.iter().all(|permission| {
            let permission = permission.permission.as_str();
            !permission.contains("execute")
                && !permission.contains("firewall")
                && !permission.contains("qos")
                && !permission.contains("process_control")
        }));

        let asset_plugin_id = manifest.plugin_id.clone();
        let mut runtime = PluginRuntime::new();
        catalog
            .register_with_runtime(&mut runtime)
            .expect("register static catalog");

        let mut contracts = ContractRegistry::new();
        for contract in catalog.contract_descriptors() {
            contracts.register(contract).expect("register contract");
        }

        let mut permissions = PermissionResolver::new();
        for manifest in catalog.manifests() {
            permissions.register_plugin_manifest_permissions(manifest);
        }

        let validation = runtime
            .registry()
            .validate_startup(&asset_plugin_id, &contracts, &permissions)
            .expect("startup validation");
        assert!(
            validation.allowed,
            "asset exposure startup should be allowed: {:?}",
            validation.issues
        );
    }

    #[test]
    fn static_internal_c2_detection_declares_metadata_only_runtime_contracts_and_starts() {
        let catalog = BuiltInPluginCatalog::static_internal().expect("catalog");
        let manifest = catalog
            .manifests()
            .into_iter()
            .find(|manifest| manifest.plugin_name == "C2 Detection")
            .expect("c2 detection manifest");

        let input_contracts = manifest
            .input_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<Vec<_>>();
        for required in [
            "network.flow.record",
            "network.session.record",
            "network.dns.observation",
            "network.tls.observation",
            "identity.process_context",
            "intel.domain_context",
            "intel.ip_context",
            "intel.cloud_context",
            "intel.certificate_context",
        ] {
            assert!(
                input_contracts.contains(&required),
                "missing c2 input contract {required}"
            );
        }

        let output_contracts = manifest
            .output_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<Vec<_>>();
        for required in [
            "security.finding",
            "security.evidence",
            "security.risk_hint",
            "graph.hint",
        ] {
            assert!(
                output_contracts.contains(&required),
                "missing c2 output contract {required}"
            );
        }
        for forbidden in [
            "security.risk",
            "security.alert",
            "security.incident",
            "graph.update",
            "graph.path",
            "response.plan",
            "response.result",
            "report.generated",
            "report.exported",
        ] {
            assert!(
                !output_contracts.contains(&forbidden),
                "c2 detection must not declare forbidden output {forbidden}"
            );
        }
        assert_eq!(
            manifest.finding_types,
            vec!["security.finding.c2".to_string()]
        );
        assert_eq!(
            manifest.graph_hint_types,
            vec!["suspicious_c2_relation".to_string()]
        );
        assert!(manifest.required_permissions.iter().all(|permission| {
            let permission = permission.permission.as_str();
            !permission.contains("execute")
                && !permission.contains("firewall")
                && !permission.contains("qos")
                && !permission.contains("process_control")
        }));

        let c2_plugin_id = manifest.plugin_id.clone();
        let mut runtime = PluginRuntime::new();
        catalog
            .register_with_runtime(&mut runtime)
            .expect("register static catalog");

        let mut contracts = ContractRegistry::new();
        for contract in catalog.contract_descriptors() {
            contracts.register(contract).expect("register contract");
        }

        let mut permissions = PermissionResolver::new();
        for manifest in catalog.manifests() {
            permissions.register_plugin_manifest_permissions(manifest);
        }

        let validation = runtime
            .registry()
            .validate_startup(&c2_plugin_id, &contracts, &permissions)
            .expect("startup validation");
        assert!(
            validation.allowed,
            "c2 detection startup should be allowed: {:?}",
            validation.issues
        );
    }

    #[test]
    fn static_internal_exfiltration_detection_declares_metadata_only_runtime_contracts_and_starts()
    {
        let catalog = BuiltInPluginCatalog::static_internal().expect("catalog");
        let manifest = catalog
            .manifests()
            .into_iter()
            .find(|manifest| manifest.plugin_name == "Exfiltration Detection")
            .expect("exfiltration detection manifest");

        let input_contracts = manifest
            .input_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<Vec<_>>();
        for required in [
            "network.flow.record",
            "network.session.record",
            "network.http.metadata",
            "identity.process_context",
            "intel.ip_context",
            "intel.cloud_context",
            "security.finding",
            "graph.hint",
        ] {
            assert!(
                input_contracts.contains(&required),
                "missing exfiltration input contract {required}"
            );
        }

        let output_contracts = manifest
            .output_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<Vec<_>>();
        for required in [
            "security.finding",
            "security.evidence",
            "security.risk_hint",
            "graph.hint",
        ] {
            assert!(
                output_contracts.contains(&required),
                "missing exfiltration output contract {required}"
            );
        }
        for forbidden in [
            "security.risk",
            "security.alert",
            "security.incident",
            "graph.update",
            "graph.path",
            "response.plan",
            "response.result",
            "report.generated",
            "report.exported",
        ] {
            assert!(
                !output_contracts.contains(&forbidden),
                "exfiltration detection must not declare forbidden output {forbidden}"
            );
        }
        assert_eq!(
            manifest.finding_types,
            vec!["security.finding.exfiltration".to_string()]
        );
        assert_eq!(
            manifest.graph_hint_types,
            vec!["process_uploads_to_cloud".to_string()]
        );
        assert!(manifest.required_permissions.iter().all(|permission| {
            let permission = permission.permission.as_str();
            !permission.contains("execute")
                && !permission.contains("firewall")
                && !permission.contains("qos")
                && !permission.contains("process_control")
        }));

        let exfiltration_plugin_id = manifest.plugin_id.clone();
        let mut runtime = PluginRuntime::new();
        catalog
            .register_with_runtime(&mut runtime)
            .expect("register static catalog");

        let mut contracts = ContractRegistry::new();
        for contract in catalog.contract_descriptors() {
            contracts.register(contract).expect("register contract");
        }

        let mut permissions = PermissionResolver::new();
        for manifest in catalog.manifests() {
            permissions.register_plugin_manifest_permissions(manifest);
        }

        let validation = runtime
            .registry()
            .validate_startup(&exfiltration_plugin_id, &contracts, &permissions)
            .expect("startup validation");
        assert!(
            validation.allowed,
            "exfiltration detection startup should be allowed: {:?}",
            validation.issues
        );
    }

    #[test]
    fn static_internal_lateral_movement_declares_metadata_only_runtime_contracts_and_starts() {
        let catalog = BuiltInPluginCatalog::static_internal().expect("catalog");
        let manifest = catalog
            .manifests()
            .into_iter()
            .find(|manifest| manifest.plugin_name == "Lateral Movement Lite")
            .expect("lateral movement manifest");

        let input_contracts = manifest
            .input_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<Vec<_>>();
        for required in [
            "network.flow.record",
            "network.session.record",
            "identity.process_context",
            "asset.record",
            "asset.service_record",
            "asset.port_exposure",
            "asset.exposure.observation",
            "asset.exposure",
            "security.finding.asset_risk",
        ] {
            assert!(
                input_contracts.contains(&required),
                "missing lateral movement input contract {required}"
            );
        }

        let output_contracts = manifest
            .output_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<Vec<_>>();
        for required in [
            "security.finding",
            "security.evidence",
            "security.risk_hint",
            "graph.hint",
        ] {
            assert!(
                output_contracts.contains(&required),
                "missing lateral movement output contract {required}"
            );
        }
        for forbidden in [
            "security.risk",
            "security.alert",
            "security.incident",
            "graph.update",
            "graph.path",
            "response.plan",
            "response.result",
            "report.generated",
            "report.exported",
        ] {
            assert!(
                !output_contracts.contains(&forbidden),
                "lateral movement must not declare forbidden output {forbidden}"
            );
        }
        assert_eq!(
            manifest.finding_types,
            vec!["security.finding.lateral_movement_lite".to_string()]
        );
        assert!(manifest
            .graph_hint_types
            .iter()
            .any(|hint| hint == "lateral_service_probe"));
        assert!(manifest.required_permissions.iter().all(|permission| {
            let permission = permission.permission.as_str();
            !permission.contains("execute")
                && !permission.contains("firewall")
                && !permission.contains("qos")
                && !permission.contains("process_control")
        }));

        let lateral_plugin_id = manifest.plugin_id.clone();
        let mut runtime = PluginRuntime::new();
        catalog
            .register_with_runtime(&mut runtime)
            .expect("register static catalog");

        let mut contracts = ContractRegistry::new();
        for contract in catalog.contract_descriptors() {
            contracts.register(contract).expect("register contract");
        }

        let mut permissions = PermissionResolver::new();
        for manifest in catalog.manifests() {
            permissions.register_plugin_manifest_permissions(manifest);
        }

        let validation = runtime
            .registry()
            .validate_startup(&lateral_plugin_id, &contracts, &permissions)
            .expect("startup validation");
        assert!(
            validation.allowed,
            "lateral movement startup should be allowed: {:?}",
            validation.issues
        );
    }

    #[test]
    fn mock_plugins_register_through_static_runtime_path() {
        let catalog = BuiltInPluginCatalog::mock_only().expect("catalog");
        let mut runtime = PluginRuntime::new();
        let registered = catalog
            .register_with_runtime(&mut runtime)
            .expect("register all mocks");

        assert_eq!(registered.len(), catalog.plugins().len());
        assert_eq!(runtime.registry().list().len(), catalog.plugins().len());
    }

    #[test]
    fn catalog_exposes_component_center_and_capability_ui_contributions() {
        let catalog = BuiltInPluginCatalog::mock_only().expect("catalog");

        for manifest in catalog.manifests() {
            assert!(manifest.ui_contributions.iter().any(|contribution| {
                contribution.slot == UiContributionSlot::ComponentCenterCard
                    && contribution.renderer_type == RendererType::HealthBadge
            }));
            assert!(manifest.ui_contributions.iter().any(|contribution| {
                contribution.slot == UiContributionSlot::CapabilityAnalysisPanel
                    && contribution.renderer_type == RendererType::MetricCard
            }));
            assert!(manifest
                .ui_contributions
                .iter()
                .all(|contribution| contribution.fallback_renderer()
                    != sentinel_contracts::FallbackRendererType::UnsupportedContribution));
        }
    }

    #[test]
    fn mock_health_and_metrics_are_privacy_safe_and_available() {
        let catalog = BuiltInPluginCatalog::mock_only().expect("catalog");
        let plugin = catalog
            .plugins()
            .iter()
            .find(|plugin| plugin.manifest().plugin_name == "DNS Security Mock")
            .expect("dns plugin");
        let snapshot = plugin
            .health_provider()
            .snapshot(&plugin.manifest().plugin_id);
        snapshot.validate().expect("health snapshot is safe");

        let samples = plugin.metric_provider().samples().expect("metric samples");
        assert_eq!(samples.len(), 5);
        for sample in samples {
            sample.validate(None).expect("metric sample is safe");
        }
    }

    #[test]
    fn startup_validation_allows_catalog_when_contracts_and_metadata_permissions_are_registered() {
        let catalog = BuiltInPluginCatalog::mock_only().expect("catalog");
        let mut runtime = PluginRuntime::new();
        catalog
            .register_with_runtime(&mut runtime)
            .expect("register all mocks");

        let mut contracts = ContractRegistry::new();
        for contract in catalog.contract_descriptors() {
            contracts.register(contract).expect("register contract");
        }

        let mut permissions = PermissionResolver::new();
        for manifest in catalog.manifests() {
            permissions.register_plugin_manifest_permissions(manifest);
        }

        for manifest in catalog.manifests() {
            let validation = runtime
                .registry()
                .validate_startup(&manifest.plugin_id, &contracts, &permissions)
                .expect("startup validation");
            assert!(
                validation.allowed,
                "startup should be allowed for {}: {:?}",
                manifest.plugin_name, validation.issues
            );
        }
    }

    #[test]
    fn mock_processing_emits_only_health_and_metrics() {
        let catalog = BuiltInPluginCatalog::mock_only().expect("catalog");
        let mut plugin = catalog.plugins()[0].clone();
        let mut context = PluginContext::new(
            plugin.manifest().plugin_id.clone(),
            plugin.manifest().runtime_mode.clone(),
            TraceContext::new_root(),
        );
        let event = EventEnvelope::new(
            EventType::new("network.flow.record").expect("event type"),
            SchemaVersion::new(1, 0, 0),
            plugin.manifest().plugin_id.clone(),
            TraceContext::new_root(),
        );

        let output = plugin
            .process_event(&mut context, &event)
            .expect("mock process event");

        assert!(output.events.is_empty());
        assert!(output.audit_events.is_empty());
        assert_eq!(output.health.len(), 1);
        assert_eq!(output.metrics.len(), 5);
    }

    #[test]
    fn capability_manifests_group_mock_plugins_by_domain() {
        let catalog = BuiltInPluginCatalog::mock_only().expect("catalog");
        let domains = catalog
            .capability_manifests()
            .iter()
            .map(|manifest| manifest.capability_domain.as_str())
            .collect::<Vec<_>>();

        assert!(domains.contains(&"network_visibility"));
        assert!(domains.contains(&"identity"));
        assert!(domains.contains(&"intelligence"));
        assert!(domains.contains(&"platform_detection"));
        assert!(domains.contains(&"graph"));
        assert!(domains.contains(&"response"));
        assert!(domains.contains(&"reporting"));
        assert!(catalog
            .capability_manifests()
            .iter()
            .all(|manifest| !manifest.plugin_ids.is_empty()));
    }

    #[test]
    fn response_mock_is_recommend_first_and_has_no_execution_permission() {
        let catalog = BuiltInPluginCatalog::mock_only().expect("catalog");
        let response = catalog
            .plugins()
            .iter()
            .find(|plugin| plugin.manifest().plugin_name == "Response Planning Mock")
            .expect("response plugin");

        assert!(response
            .manifest()
            .required_permissions
            .iter()
            .all(|permission| !permission.permission.as_str().contains("execute")));
        assert!(response
            .manifest()
            .input_contracts
            .iter()
            .any(|contract| contract.contract_name == "settings.response_policy_rule"));
        let policy_permission = response
            .manifest()
            .required_permissions
            .iter()
            .find(|permission| permission.permission.as_str() == "read.settings.response_policy")
            .expect("response policy read permission");
        assert!(policy_permission
            .scopes
            .iter()
            .any(|scope| scope == "settings.response_policy_rule"));
        assert!(response.manifest().description.contains("does not execute"));
    }

    #[test]
    fn mock_manifests_declare_pipeline_dependencies() {
        let catalog = BuiltInPluginCatalog::mock_only().expect("catalog");
        let capture = catalog
            .manifests()
            .into_iter()
            .find(|manifest| manifest.plugin_name == "Packet Capture Mock")
            .expect("capture manifest");
        assert!(capture.dependencies.is_empty());

        let dependent_plugins = catalog
            .manifests()
            .into_iter()
            .filter(|manifest| manifest.plugin_name != "Packet Capture Mock")
            .collect::<Vec<_>>();
        assert!(dependent_plugins.iter().all(|manifest| {
            manifest.dependencies.iter().all(|dependency| {
                dependency.dependency_type == PluginDependencyType::RequiredPlugin
            })
        }));
        assert!(dependent_plugins
            .iter()
            .all(|manifest| !manifest.dependencies.is_empty()));
    }

    #[test]
    fn graph_stage_mock_is_only_catalog_entry_that_outputs_graph_update() {
        let catalog = BuiltInPluginCatalog::mock_only().expect("catalog");
        let writers = catalog
            .manifests()
            .into_iter()
            .filter(|manifest| {
                manifest
                    .output_contracts
                    .iter()
                    .any(|contract| contract.contract_name == "graph.update")
            })
            .map(|manifest| manifest.plugin_name.clone())
            .collect::<Vec<_>>();

        assert_eq!(writers, vec!["Graph Stage Mock".to_string()]);
    }

    #[test]
    fn permission_resolver_default_grants_metadata_only_catalog_permissions() {
        let catalog = BuiltInPluginCatalog::mock_only().expect("catalog");
        let manifest = catalog
            .manifests()
            .into_iter()
            .find(|manifest| manifest.plugin_name == "Packet Capture Mock")
            .expect("packet capture manifest");
        let mut resolver = PermissionResolver::new();
        resolver.register_plugin_manifest_permissions(manifest);

        for descriptor in &manifest.required_permissions {
            let subject = PermissionSubject::Plugin(manifest.plugin_id.clone());
            let request = crate::permissions::PermissionRequest::new(
                subject,
                descriptor.permission.clone(),
                crate::permissions::permission_scope_for_descriptor(descriptor),
                crate::permissions::PolicyScope::Plugin,
                "mock catalog startup validation",
            );
            let decision = resolver.evaluate_permission(request, None);
            assert_eq!(
                decision.decision,
                crate::permissions::PermissionDecisionKind::Allow
            );
        }
    }
}
