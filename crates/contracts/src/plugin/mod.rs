use crate::common::{
    ActionDescriptorId, CapabilityId, ContractId, DataSourceId, FilterSpec, PageRequest, PluginId,
    PrivacyClass, QueryScope, SchemaVersion, UiContributionId,
};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginType {
    Source,
    Transform,
    Protocol,
    Enrichment,
    Detection,
    PlatformDetection,
    Graph,
    Response,
    Report,
    Utility,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Streaming,
    Batch,
    Periodic,
    OnDemand,
    Replay,
    Hybrid,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaturityLevel {
    L1Observable,
    L2Detectable,
    L3Modeling,
    L4Reasoning,
    Experimental,
    Stable,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginStatefulness {
    Stateless,
    MemoryState,
    PersistentState,
    Checkpointed,
    Cached,
    Baseline,
    ModelState,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    None,
    Optional,
    Required,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRange {
    pub min: Option<String>,
    pub max: Option<String>,
    pub exact: Option<String>,
}

impl VersionRange {
    pub fn any() -> Self {
        Self {
            min: None,
            max: None,
            exact: None,
        }
    }

    pub fn exact(version: impl Into<String>) -> Result<Self, ManifestValidationError> {
        Ok(Self {
            min: None,
            max: None,
            exact: Some(require_non_empty("version", version.into())?),
        })
    }
}

impl Default for VersionRange {
    fn default() -> Self {
        Self::any()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractDescriptor {
    pub contract_id: ContractId,
    pub contract_name: String,
    pub schema_version: SchemaVersion,
    pub topic: Option<String>,
    pub required: bool,
    pub compatibility: ContractCompatibilityRequirement,
}

impl ContractDescriptor {
    pub fn new(
        contract_name: impl Into<String>,
        schema_version: SchemaVersion,
    ) -> Result<Self, ManifestValidationError> {
        Ok(Self {
            contract_id: ContractId::new_v4(),
            contract_name: require_non_empty("contract_name", contract_name.into())?,
            schema_version,
            topic: None,
            required: true,
            compatibility: ContractCompatibilityRequirement::BackwardCompatible,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCompatibilityRequirement {
    Strict,
    BackwardCompatible,
    MigrationRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginDependencyType {
    RequiredPlugin,
    OptionalPlugin,
    RequiredCapability,
    OptionalCapability,
    RequiredContract,
    RequiredInfrastructure,
    RequiredEngine,
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginDependency {
    pub dependency_type: PluginDependencyType,
    pub plugin_id: Option<PluginId>,
    pub capability_id: Option<CapabilityId>,
    pub contract: Option<ContractDescriptor>,
    pub name: Option<String>,
    pub version_requirement: VersionRange,
    pub startup_order: Option<u32>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct PermissionKey(String);

impl PermissionKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ManifestValidationError> {
        let value = require_non_empty("permission", value.into())?;
        let valid = value
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(is_permission_char));

        if !value.contains('.') || !valid {
            return Err(ManifestValidationError::InvalidPermission(value));
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PermissionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PermissionKey {
    type Err = ManifestValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for PermissionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionCategory {
    DataAccess,
    SystemAccess,
    ResponseAccess,
    ExportAccess,
    DesktopAccess,
    PolicyAccess,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionDescriptor {
    pub permission: PermissionKey,
    pub category: PermissionCategory,
    pub risk_level: PermissionRiskLevel,
    pub description: String,
    pub required: bool,
    pub scopes: Vec<String>,
}

impl PermissionDescriptor {
    pub fn new(
        permission: PermissionKey,
        category: PermissionCategory,
        risk_level: PermissionRiskLevel,
        description: impl Into<String>,
    ) -> Result<Self, ManifestValidationError> {
        Ok(Self {
            permission,
            category,
            risk_level,
            description: require_non_empty("permission description", description.into())?,
            required: true,
            scopes: Vec::new(),
        })
    }

    pub fn is_high_risk(&self) -> bool {
        matches!(
            self.risk_level,
            PermissionRiskLevel::High | PermissionRiskLevel::Critical
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthSchema {
    pub liveness: HealthSignalDescriptor,
    pub readiness: HealthSignalDescriptor,
    pub dependency_health: Vec<HealthSignalDescriptor>,
    pub data_freshness: Option<HealthSignalDescriptor>,
    pub processing_latency: Option<HealthSignalDescriptor>,
    pub error_rate: Option<HealthSignalDescriptor>,
    pub queue_lag: Option<HealthSignalDescriptor>,
}

impl Default for HealthSchema {
    fn default() -> Self {
        Self {
            liveness: HealthSignalDescriptor::new("liveness"),
            readiness: HealthSignalDescriptor::new("readiness"),
            dependency_health: Vec::new(),
            data_freshness: None,
            processing_latency: None,
            error_rate: None,
            queue_lag: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthSignalDescriptor {
    pub name: String,
    pub description: Option<String>,
    pub unit: Option<String>,
    pub critical: bool,
}

impl HealthSignalDescriptor {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            unit: None,
            critical: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
    Distribution,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricSchema {
    pub metric_name: String,
    pub kind: MetricKind,
    pub unit: Option<String>,
    pub description: String,
    pub labels: Vec<String>,
    pub privacy_class: PrivacyClass,
}

impl MetricSchema {
    pub fn new(
        metric_name: impl Into<String>,
        kind: MetricKind,
        description: impl Into<String>,
    ) -> Result<Self, ManifestValidationError> {
        Ok(Self {
            metric_name: require_non_empty("metric_name", metric_name.into())?,
            kind,
            unit: None,
            description: require_non_empty("metric description", description.into())?,
            labels: Vec::new(),
            privacy_class: PrivacyClass::Internal,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Read,
    MutationRequest,
    ResponseRecommendation,
    SettingsUpdate,
    ExportRequest,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionDescriptor {
    pub action_id: ActionDescriptorId,
    pub action_key: String,
    pub title: String,
    pub description: String,
    pub kind: ActionKind,
    pub required_permissions: Vec<PermissionDescriptor>,
    pub confirmation_required: bool,
    pub high_impact: bool,
    pub input_schema: Option<Value>,
    pub output_contract: Option<ContractDescriptor>,
}

impl ActionDescriptor {
    pub fn new(
        action_key: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        kind: ActionKind,
    ) -> Result<Self, ManifestValidationError> {
        Ok(Self {
            action_id: ActionDescriptorId::new_v4(),
            action_key: require_non_empty("action_key", action_key.into())?,
            title: require_non_empty("action title", title.into())?,
            description: require_non_empty("action description", description.into())?,
            kind,
            required_permissions: Vec::new(),
            confirmation_required: false,
            high_impact: false,
            input_schema: None,
            output_contract: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiContributionSlot {
    #[serde(rename = "overview.risk_map")]
    OverviewRiskMap,
    #[serde(rename = "component_center.card")]
    ComponentCenterCard,
    #[serde(rename = "component_center.detail_panel")]
    ComponentCenterDetailPanel,
    #[serde(rename = "capability_analysis.panel")]
    CapabilityAnalysisPanel,
    #[serde(rename = "investigation.evidence_panel")]
    InvestigationEvidencePanel,
    #[serde(rename = "graph.projection")]
    GraphProjection,
    #[serde(rename = "network.panel")]
    NetworkPanel,
    #[serde(rename = "response.action_panel")]
    ResponseActionPanel,
    #[serde(rename = "report.section")]
    ReportSection,
    #[serde(rename = "settings.plugin_config")]
    SettingsPluginConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RendererType {
    HealthBadge,
    MetricCard,
    KeyValuePanel,
    Table,
    Timeline,
    EvidenceList,
    RiskBreakdown,
    GraphProjection,
    DependencyGraph,
    PipelineGraph,
    ResponseActionCard,
    SettingsForm,
    ReportSection,
    Unsupported(String),
}

impl RendererType {
    pub fn parse(value: &str) -> Self {
        match value {
            "health_badge" => Self::HealthBadge,
            "metric_card" => Self::MetricCard,
            "key_value_panel" => Self::KeyValuePanel,
            "table" => Self::Table,
            "timeline" => Self::Timeline,
            "evidence_list" => Self::EvidenceList,
            "risk_breakdown" => Self::RiskBreakdown,
            "graph_projection" => Self::GraphProjection,
            "dependency_graph" => Self::DependencyGraph,
            "pipeline_graph" => Self::PipelineGraph,
            "response_action_card" => Self::ResponseActionCard,
            "settings_form" => Self::SettingsForm,
            "report_section" => Self::ReportSection,
            other => Self::Unsupported(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::HealthBadge => "health_badge",
            Self::MetricCard => "metric_card",
            Self::KeyValuePanel => "key_value_panel",
            Self::Table => "table",
            Self::Timeline => "timeline",
            Self::EvidenceList => "evidence_list",
            Self::RiskBreakdown => "risk_breakdown",
            Self::GraphProjection => "graph_projection",
            Self::DependencyGraph => "dependency_graph",
            Self::PipelineGraph => "pipeline_graph",
            Self::ResponseActionCard => "response_action_card",
            Self::SettingsForm => "settings_form",
            Self::ReportSection => "report_section",
            Self::Unsupported(value) => value.as_str(),
        }
    }

    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported(_))
    }

    pub fn fallback_renderer(&self) -> FallbackRendererType {
        match self {
            Self::HealthBadge | Self::MetricCard => FallbackRendererType::GenericMetricList,
            Self::Table => FallbackRendererType::GenericTable,
            Self::EvidenceList => FallbackRendererType::GenericEvidence,
            Self::GraphProjection | Self::DependencyGraph | Self::PipelineGraph => {
                FallbackRendererType::GenericGraphNode
            }
            Self::Unsupported(_) => FallbackRendererType::UnsupportedContribution,
            _ => FallbackRendererType::GenericKeyValue,
        }
    }
}

impl Serialize for RendererType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RendererType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::parse(&value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackRendererType {
    GenericKeyValue,
    GenericTable,
    GenericFinding,
    GenericEvidence,
    GenericGraphNode,
    GenericMetricList,
    UnsupportedContribution,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSourceKind {
    CoreQuery,
    CoreEventStream,
    LogicalStoreView,
    StaticManifestData,
    CapabilityView,
    PluginCatalog,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DataSourceDescriptor {
    pub data_source_id: DataSourceId,
    pub kind: DataSourceKind,
    pub contract: Option<ContractDescriptor>,
    pub query_scope: Option<QueryScope>,
    pub topic: Option<String>,
    pub page: Option<PageRequest>,
    pub parameters_schema: Option<Value>,
}

impl DataSourceDescriptor {
    pub fn new(kind: DataSourceKind) -> Self {
        Self {
            data_source_id: DataSourceId::new_v4(),
            kind,
            contract: None,
            query_scope: None,
            topic: None,
            page: None,
            parameters_schema: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshMode {
    Manual,
    Polling,
    EventDriven,
    OnDemand,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UiContribution {
    pub contribution_id: UiContributionId,
    pub plugin_id: PluginId,
    pub slot: UiContributionSlot,
    pub renderer_type: RendererType,
    pub title: String,
    pub data_source: DataSourceDescriptor,
    pub schema: Value,
    pub default_filters: Vec<FilterSpec>,
    pub refresh_mode: RefreshMode,
    pub permissions: Vec<PermissionDescriptor>,
}

impl UiContribution {
    pub fn new(
        plugin_id: PluginId,
        slot: UiContributionSlot,
        renderer_type: RendererType,
        title: impl Into<String>,
        data_source: DataSourceDescriptor,
    ) -> Result<Self, ManifestValidationError> {
        Ok(Self {
            contribution_id: UiContributionId::new_v4(),
            plugin_id,
            slot,
            renderer_type,
            title: require_non_empty("contribution title", title.into())?,
            data_source,
            schema: Value::Object(Default::default()),
            default_filters: Vec::new(),
            refresh_mode: RefreshMode::OnDemand,
            permissions: Vec::new(),
        })
    }

    pub fn fallback_renderer(&self) -> FallbackRendererType {
        self.renderer_type.fallback_renderer()
    }

    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        if !self.renderer_type.is_supported() {
            return Err(ManifestValidationError::UnsupportedRendererType(
                self.renderer_type.as_str().to_string(),
            ));
        }

        require_non_empty("contribution title", self.title.clone())?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub capability_id: CapabilityId,
    pub capability_domain: String,
    pub title: String,
    pub description: String,
    pub maturity_level: MaturityLevel,
    pub plugin_ids: Vec<PluginId>,
    pub input_contracts: Vec<ContractDescriptor>,
    pub output_contracts: Vec<ContractDescriptor>,
    pub required_permissions: Vec<PermissionDescriptor>,
    pub ui_contributions: Vec<UiContribution>,
}

impl CapabilityManifest {
    pub fn new(
        capability_domain: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Result<Self, ManifestValidationError> {
        Ok(Self {
            capability_id: CapabilityId::new_v4(),
            capability_domain: require_non_empty("capability_domain", capability_domain.into())?,
            title: require_non_empty("capability title", title.into())?,
            description: require_non_empty("capability description", description.into())?,
            maturity_level: MaturityLevel::L1Observable,
            plugin_ids: Vec::new(),
            input_contracts: Vec::new(),
            output_contracts: Vec::new(),
            required_permissions: Vec::new(),
            ui_contributions: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin_id: PluginId,
    pub plugin_name: String,
    pub plugin_type: PluginType,
    pub capability_domain: String,
    pub description: String,
    pub version: String,
    pub contract_version_range: VersionRange,
    pub platform_version_range: VersionRange,
    pub capability_tags: Vec<String>,
    pub maturity_level: MaturityLevel,
    pub runtime_mode: RuntimeMode,
    pub enabled_by_default: bool,
    pub input_contracts: Vec<ContractDescriptor>,
    pub output_contracts: Vec<ContractDescriptor>,
    pub dependencies: Vec<PluginDependency>,
    pub required_permissions: Vec<PermissionDescriptor>,
    pub required_capabilities: Vec<CapabilityId>,
    pub optional_capabilities: Vec<CapabilityId>,
    pub metrics_schema: Vec<MetricSchema>,
    pub health_schema: HealthSchema,
    pub finding_types: Vec<String>,
    pub graph_hint_types: Vec<String>,
    pub actions: Vec<ActionDescriptor>,
    pub ui_contributions: Vec<UiContribution>,
    pub statefulness: PluginStatefulness,
    pub checkpoint_support: SupportLevel,
    pub replay_support: SupportLevel,
}

impl PluginManifest {
    pub fn new(
        plugin_id: PluginId,
        plugin_name: impl Into<String>,
        version: impl Into<String>,
        capability_domain: impl Into<String>,
        plugin_type: PluginType,
        runtime_mode: RuntimeMode,
    ) -> Result<Self, ManifestValidationError> {
        Ok(Self {
            plugin_id,
            plugin_name: require_non_empty("plugin_name", plugin_name.into())?,
            plugin_type,
            capability_domain: require_non_empty("capability_domain", capability_domain.into())?,
            description: String::new(),
            version: require_non_empty("version", version.into())?,
            contract_version_range: VersionRange::default(),
            platform_version_range: VersionRange::default(),
            capability_tags: Vec::new(),
            maturity_level: MaturityLevel::L1Observable,
            runtime_mode,
            enabled_by_default: false,
            input_contracts: Vec::new(),
            output_contracts: Vec::new(),
            dependencies: Vec::new(),
            required_permissions: Vec::new(),
            required_capabilities: Vec::new(),
            optional_capabilities: Vec::new(),
            metrics_schema: Vec::new(),
            health_schema: HealthSchema::default(),
            finding_types: Vec::new(),
            graph_hint_types: Vec::new(),
            actions: Vec::new(),
            ui_contributions: Vec::new(),
            statefulness: PluginStatefulness::Stateless,
            checkpoint_support: SupportLevel::None,
            replay_support: SupportLevel::None,
        })
    }

    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        require_non_empty("plugin_name", self.plugin_name.clone())?;
        require_non_empty("version", self.version.clone())?;
        require_non_empty("capability_domain", self.capability_domain.clone())?;

        if self.input_contracts.is_empty() && self.output_contracts.is_empty() {
            return Err(ManifestValidationError::MissingContractDeclarations);
        }

        for contribution in &self.ui_contributions {
            contribution.validate()?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestValidationError {
    EmptyField(&'static str),
    InvalidPermission(String),
    MissingContractDeclarations,
    UnsupportedRendererType(String),
}

impl fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::InvalidPermission(value) => {
                write!(f, "permission must be a namespaced identifier: {value}")
            }
            Self::MissingContractDeclarations => {
                write!(
                    f,
                    "manifest must declare at least one input or output contract"
                )
            }
            Self::UnsupportedRendererType(value) => {
                write!(f, "unsupported renderer type: {value}")
            }
        }
    }
}

impl std::error::Error for ManifestValidationError {}

fn require_non_empty(
    field: &'static str,
    value: String,
) -> Result<String, ManifestValidationError> {
    if value.trim().is_empty() {
        return Err(ManifestValidationError::EmptyField(field));
    }

    Ok(value)
}

fn is_permission_char(value: char) -> bool {
    value.is_ascii_lowercase() || value.is_ascii_digit() || matches!(value, '_' | '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_contract(name: &str) -> ContractDescriptor {
        ContractDescriptor::new(name, SchemaVersion::new(1, 0, 0)).expect("valid contract")
    }

    #[test]
    fn permission_key_requires_namespace() {
        assert!(PermissionKey::new("read.event.flow").is_ok());
        assert!(PermissionKey::new("read").is_err());
        assert!(PermissionKey::new("Read.Event.Flow").is_err());
    }

    #[test]
    fn unknown_renderer_deserializes_to_safe_fallback() {
        let renderer: RendererType =
            serde_json::from_str("\"future_renderer\"").expect("deserialize renderer");

        assert_eq!(
            renderer.fallback_renderer(),
            FallbackRendererType::UnsupportedContribution
        );
        assert!(!renderer.is_supported());
    }

    #[test]
    fn manifest_validation_rejects_missing_contracts() {
        let manifest = PluginManifest::new(
            PluginId::new_v4(),
            "dns_security",
            "0.1.0",
            "network_visibility",
            PluginType::Protocol,
            RuntimeMode::Streaming,
        )
        .expect("valid manifest shell");

        assert_eq!(
            manifest.validate(),
            Err(ManifestValidationError::MissingContractDeclarations)
        );
    }

    #[test]
    fn manifest_validation_rejects_unsupported_renderer_types() {
        let plugin_id = PluginId::new_v4();
        let data_source = DataSourceDescriptor::new(DataSourceKind::CoreQuery);
        let contribution = UiContribution::new(
            plugin_id.clone(),
            UiContributionSlot::ComponentCenterCard,
            RendererType::Unsupported("future_renderer".to_string()),
            "Future panel",
            data_source,
        )
        .expect("representable contribution");
        let mut manifest = PluginManifest::new(
            plugin_id,
            "future_plugin",
            "0.1.0",
            "network_visibility",
            PluginType::Protocol,
            RuntimeMode::Streaming,
        )
        .expect("valid manifest shell");
        manifest
            .output_contracts
            .push(sample_contract("network.dns.observation"));
        manifest.ui_contributions.push(contribution);

        assert_eq!(
            manifest.validate(),
            Err(ManifestValidationError::UnsupportedRendererType(
                "future_renderer".to_string()
            ))
        );
    }

    #[test]
    fn missing_plugin_id_fails_deserialization() {
        let json = r#"{
            "plugin_name": "dns_security",
            "plugin_type": "protocol",
            "capability_domain": "network_visibility",
            "description": "",
            "version": "0.1.0",
            "contract_version_range": {},
            "platform_version_range": {},
            "capability_tags": [],
            "maturity_level": "l1_observable",
            "runtime_mode": "streaming",
            "enabled_by_default": false,
            "input_contracts": [],
            "output_contracts": [],
            "dependencies": [],
            "required_permissions": [],
            "required_capabilities": [],
            "optional_capabilities": [],
            "metrics_schema": [],
            "health_schema": {
                "liveness": { "name": "liveness", "description": null, "unit": null, "critical": false },
                "readiness": { "name": "readiness", "description": null, "unit": null, "critical": false },
                "dependency_health": [],
                "data_freshness": null,
                "processing_latency": null,
                "error_rate": null,
                "queue_lag": null
            },
            "finding_types": [],
            "graph_hint_types": [],
            "actions": [],
            "ui_contributions": [],
            "statefulness": "stateless",
            "checkpoint_support": "none",
            "replay_support": "none"
        }"#;

        let result = serde_json::from_str::<PluginManifest>(json);

        assert!(result.is_err());
    }
}
