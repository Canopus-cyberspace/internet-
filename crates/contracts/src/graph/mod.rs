use crate::common::{
    AlertId, CapabilityId, EntityId, EntityRef, EvidenceId, FindingId, GraphEdgeId, GraphHintId,
    GraphNodeId, GraphPathId, GraphSnapshotId, GraphViewId, IncidentId, PluginId, PrivacyClass,
    QualityScore, ResponseActionId, TimeRange, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const DEFAULT_GRAPH_VIEW_NODE_LIMIT: u32 = 500;
pub const DEFAULT_GRAPH_VIEW_EDGE_LIMIT: u32 = 1_500;
pub const MAX_EXPORT_GRAPH_EVIDENCE_REFS: usize = 64;
pub const MAX_EXPORT_GRAPH_PATH_SUMMARIES: usize = 64;
pub const MAX_EXPORT_GRAPH_REDACTION_NOTES: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStatus {
    NotRequired,
    Redacted,
    Tokenized,
    Hashed,
    PartiallyRedacted,
    Suppressed,
    RedactionRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedLabel {
    pub display: String,
    pub redaction_status: RedactionStatus,
    pub privacy_class: PrivacyClass,
}

impl RedactedLabel {
    pub fn new(
        display: impl Into<String>,
        redaction_status: RedactionStatus,
        privacy_class: PrivacyClass,
    ) -> Result<Self, GraphContractError> {
        Ok(Self {
            display: require_non_empty("display label", display.into())?,
            redaction_status,
            privacy_class,
        })
    }

    pub fn redacted(
        display: impl Into<String>,
        privacy_class: PrivacyClass,
    ) -> Result<Self, GraphContractError> {
        Self::new(display, RedactionStatus::Redacted, privacy_class)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphType {
    OverviewRiskMap,
    IncidentGraph,
    C2Graph,
    ExfiltrationGraph,
    LateralPropagationGraph,
    AssetExposureGraph,
    CapabilityDependencyGraph,
    PipelineGraph,
    ResponseImpactGraph,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphHintType {
    ProcessConnectsToIp,
    ProcessQueriesDomain,
    DomainResolvesToIp,
    IpBelongsToAsn,
    IpBelongsToCloudProvider,
    ProcessUsesTlsFingerprint,
    ProcessUploadsToCloud,
    ObservationSupportsFinding,
    FindingSupportsAlert,
    AlertPartOfIncident,
    IncidentRecommendsResponse,
    ResponseActionTargetsEntity,
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphNodeType {
    LocalHost,
    LocalUser,
    Process,
    ProcessBinary,
    LocalService,
    LocalPort,
    NetworkFlow,
    DnsQuery,
    Domain,
    Ip,
    Asn,
    CloudProvider,
    CloudRegion,
    CloudDestination,
    TlsFingerprint,
    Certificate,
    Finding,
    Alert,
    Incident,
    ResponseAction,
    Report,
    Capability,
    PipelineStage,
    Unknown(String),
}

impl GraphNodeType {
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }

    pub fn fallback_icon(&self) -> &'static str {
        match self {
            Self::Process | Self::ProcessBinary => "process",
            Self::Domain => "domain",
            Self::Ip => "ip",
            Self::Finding => "finding",
            Self::Alert => "alert",
            Self::Incident => "incident",
            Self::Unknown(_) => "generic-node",
            _ => "node",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphEdgeType {
    UserRunsProcess,
    ProcessSpawnedProcess,
    ProcessListensOnPort,
    ProcessConnectsToIp,
    ProcessQueriesDomain,
    DomainResolvesToIp,
    IpBelongsToAsn,
    IpBelongsToCloudProvider,
    ProcessUsesTlsFingerprint,
    CertificateObservedForDomain,
    ProcessUploadsToCloud,
    ObservationSupportsFinding,
    FindingSupportsAlert,
    AlertPartOfIncident,
    IncidentRecommendsResponse,
    ResponseActionTargetsEntity,
    ReportSummarizesIncident,
    Custom(String),
    Unknown(String),
}

impl GraphEdgeType {
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }

    pub fn fallback_style(&self) -> GraphEdgeStyleHint {
        match self {
            Self::FindingSupportsAlert | Self::AlertPartOfIncident => GraphEdgeStyleHint::Strong,
            Self::Unknown(_) => GraphEdgeStyleHint::Generic,
            _ => GraphEdgeStyleHint::Default,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphHint {
    pub hint_id: GraphHintId,
    pub hint_type: GraphHintType,
    pub source_entity: EntityRef,
    pub target_entity: EntityRef,
    pub evidence_refs: Vec<EvidenceId>,
    pub confidence: QualityScore,
    pub producer_plugin: PluginId,
    pub privacy_class: PrivacyClass,
    pub timestamp: Timestamp,
}

impl GraphHint {
    pub fn new(
        hint_type: GraphHintType,
        source_entity: EntityRef,
        target_entity: EntityRef,
        producer_plugin: PluginId,
    ) -> Self {
        Self {
            hint_id: GraphHintId::new_v4(),
            hint_type,
            source_entity,
            target_entity,
            evidence_refs: Vec::new(),
            confidence: QualityScore::default(),
            producer_plugin,
            privacy_class: PrivacyClass::default(),
            timestamp: Timestamp::now(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalGraphNode {
    pub node_id: GraphNodeId,
    pub node_type: GraphNodeType,
    pub entity_ref: Option<EntityRef>,
    pub label: RedactedLabel,
    pub risk_score: QualityScore,
    pub confidence: QualityScore,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub privacy_class: PrivacyClass,
    pub source_refs: Vec<EvidenceId>,
}

impl CanonicalGraphNode {
    pub fn new(node_type: GraphNodeType, label: RedactedLabel) -> Self {
        let now = Timestamp::now();
        Self {
            node_id: GraphNodeId::new_v4(),
            node_type,
            entity_ref: None,
            label,
            risk_score: QualityScore::default(),
            confidence: QualityScore::default(),
            first_seen: now.clone(),
            last_seen: now,
            privacy_class: PrivacyClass::default(),
            source_refs: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalGraphEdge {
    pub edge_id: GraphEdgeId,
    pub edge_type: GraphEdgeType,
    pub source_node: GraphNodeId,
    pub target_node: GraphNodeId,
    pub label: Option<RedactedLabel>,
    pub evidence_refs: Vec<EvidenceId>,
    pub confidence: QualityScore,
    pub weight: QualityScore,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub privacy_class: PrivacyClass,
    pub producer_plugin: Option<PluginId>,
}

impl CanonicalGraphEdge {
    pub fn new(
        edge_type: GraphEdgeType,
        source_node: GraphNodeId,
        target_node: GraphNodeId,
    ) -> Self {
        let now = Timestamp::now();
        Self {
            edge_id: GraphEdgeId::new_v4(),
            edge_type,
            source_node,
            target_node,
            label: None,
            evidence_refs: Vec::new(),
            confidence: QualityScore::default(),
            weight: QualityScore::default(),
            first_seen: now.clone(),
            last_seen: now,
            privacy_class: PrivacyClass::default(),
            producer_plugin: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphPathType {
    ProcessToC2Path,
    ProcessToCloudUploadPath,
    LocalAssetExposurePath,
    IncidentSummaryPath,
    CapabilityDependencyPath,
    PipelinePath,
    ResponseImpactPath,
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphPath {
    pub path_id: GraphPathId,
    pub path_type: GraphPathType,
    pub node_sequence: Vec<GraphNodeId>,
    pub edge_sequence: Vec<GraphEdgeId>,
    pub risk_score: QualityScore,
    pub confidence: QualityScore,
    pub explanation: RedactedLabel,
    pub evidence_refs: Vec<EvidenceId>,
    pub redaction_status: RedactionStatus,
}

impl GraphPath {
    pub fn new(
        path_type: GraphPathType,
        node_sequence: Vec<GraphNodeId>,
        edge_sequence: Vec<GraphEdgeId>,
        explanation: RedactedLabel,
    ) -> Result<Self, GraphContractError> {
        if node_sequence.is_empty() {
            return Err(GraphContractError::EmptyPath);
        }

        Ok(Self {
            path_id: GraphPathId::new_v4(),
            path_type,
            node_sequence,
            edge_sequence,
            risk_score: QualityScore::default(),
            confidence: QualityScore::default(),
            explanation,
            evidence_refs: Vec::new(),
            redaction_status: RedactionStatus::NotRequired,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum GraphScope {
    Overview,
    Incident(IncidentId),
    Alert(AlertId),
    Finding(FindingId),
    Entity(EntityId),
    Capability(CapabilityId),
    ResponseAction(ResponseActionId),
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphRedactionSummary {
    pub status: RedactionStatus,
    pub redacted_node_count: u32,
    pub redacted_edge_count: u32,
    pub hidden_label_count: u32,
    pub notes: Vec<String>,
}

impl Default for GraphRedactionSummary {
    fn default() -> Self {
        Self {
            status: RedactionStatus::NotRequired,
            redacted_node_count: 0,
            redacted_edge_count: 0,
            hidden_label_count: 0,
            notes: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub snapshot_id: GraphSnapshotId,
    pub graph_type: GraphType,
    pub scope: GraphScope,
    pub captured_at: Timestamp,
    pub time_bounds: Option<TimeRange>,
    pub node_count: u32,
    pub edge_count: u32,
    pub path_count: u32,
    pub selected_nodes: Vec<GraphNodeViewModel>,
    pub selected_edges: Vec<GraphEdgeViewModel>,
    pub path_summaries: Vec<GraphPathSummary>,
    pub risk_score: QualityScore,
    pub confidence: QualityScore,
    pub evidence_refs: Vec<EvidenceId>,
    pub redaction_status: RedactionStatus,
    pub redaction_summary: GraphRedactionSummary,
}

impl GraphSnapshot {
    pub fn new(graph_type: GraphType, scope: GraphScope) -> Self {
        Self {
            snapshot_id: GraphSnapshotId::new_v4(),
            graph_type,
            scope,
            captured_at: Timestamp::now(),
            time_bounds: None,
            node_count: 0,
            edge_count: 0,
            path_count: 0,
            selected_nodes: Vec::new(),
            selected_edges: Vec::new(),
            path_summaries: Vec::new(),
            risk_score: QualityScore::default(),
            confidence: QualityScore::default(),
            evidence_refs: Vec::new(),
            redaction_status: RedactionStatus::NotRequired,
            redaction_summary: GraphRedactionSummary::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphPathSummary {
    pub path_id: GraphPathId,
    pub path_type: GraphPathType,
    pub label: RedactedLabel,
    pub risk_score: QualityScore,
    pub confidence: QualityScore,
    pub evidence_refs: Vec<EvidenceId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphNodeStatus {
    Normal,
    Highlighted,
    Suspicious,
    Risky,
    Critical,
    Suppressed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphDetailRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<EntityId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<FindingId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_id: Option<AlertId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<IncidentId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<EvidenceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_ref: Option<String>,
}

impl GraphDetailRef {
    pub fn empty() -> Self {
        Self {
            entity_id: None,
            finding_id: None,
            alert_id: None,
            incident_id: None,
            evidence_refs: Vec::new(),
            custom_ref: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphBadge {
    pub label: RedactedLabel,
    pub tone: GraphBadgeTone,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphBadgeTone {
    Neutral,
    Info,
    Warning,
    Danger,
    Success,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphNodeViewModel {
    pub node_id: GraphNodeId,
    pub node_type: GraphNodeType,
    pub label: RedactedLabel,
    pub icon: String,
    pub risk_score: QualityScore,
    pub status: GraphNodeStatus,
    pub badges: Vec<GraphBadge>,
    pub tooltip: Option<RedactedLabel>,
    pub detail_ref: GraphDetailRef,
    pub privacy_class: PrivacyClass,
    pub position_hint: Option<GraphPositionHint>,
    pub generic_fallback: bool,
}

impl GraphNodeViewModel {
    pub fn new(node_type: GraphNodeType, label: RedactedLabel) -> Self {
        let icon = node_type.fallback_icon().to_string();
        let generic_fallback = !node_type.is_known();

        Self {
            node_id: GraphNodeId::new_v4(),
            node_type,
            label,
            icon,
            risk_score: QualityScore::default(),
            status: GraphNodeStatus::Unknown,
            badges: Vec::new(),
            tooltip: None,
            detail_ref: GraphDetailRef::empty(),
            privacy_class: PrivacyClass::default(),
            position_hint: None,
            generic_fallback,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphPositionHint {
    pub x: f32,
    pub y: f32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphEdgeStyleHint {
    Default,
    Strong,
    Dashed,
    Dotted,
    Muted,
    Generic,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphEdgeViewModel {
    pub edge_id: GraphEdgeId,
    pub edge_type: GraphEdgeType,
    pub source: GraphNodeId,
    pub target: GraphNodeId,
    pub label: Option<RedactedLabel>,
    pub confidence: QualityScore,
    pub evidence_refs: Vec<EvidenceId>,
    pub style_hint: GraphEdgeStyleHint,
    pub tooltip: Option<RedactedLabel>,
    pub privacy_class: PrivacyClass,
    pub generic_fallback: bool,
}

impl GraphEdgeViewModel {
    pub fn new(edge_type: GraphEdgeType, source: GraphNodeId, target: GraphNodeId) -> Self {
        let style_hint = edge_type.fallback_style();
        let generic_fallback = !edge_type.is_known();

        Self {
            edge_id: GraphEdgeId::new_v4(),
            edge_type,
            source,
            target,
            label: None,
            confidence: QualityScore::default(),
            evidence_refs: Vec::new(),
            style_hint,
            tooltip: None,
            privacy_class: PrivacyClass::default(),
            generic_fallback,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GraphLegend {
    pub node_items: Vec<GraphLegendItem>,
    pub edge_items: Vec<GraphLegendItem>,
    pub risk_scale: Vec<GraphLegendItem>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphLegendItem {
    pub key: String,
    pub label: RedactedLabel,
    pub color: Option<String>,
    pub icon: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphFilterModel {
    pub node_types: Vec<GraphNodeType>,
    pub edge_types: Vec<GraphEdgeType>,
    pub time_range: Option<TimeRange>,
    pub scope: GraphScope,
    pub evidence_refs: Vec<EvidenceId>,
    pub focus_node: Option<GraphNodeId>,
    pub min_confidence: Option<QualityScore>,
    pub include_suppressed: bool,
}

impl GraphFilterModel {
    pub fn new(scope: GraphScope) -> Self {
        Self {
            node_types: Vec::new(),
            edge_types: Vec::new(),
            time_range: None,
            scope,
            evidence_refs: Vec::new(),
            focus_node: None,
            min_confidence: None,
            include_suppressed: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphLayoutMode {
    Auto,
    Hierarchical,
    ForceDirected,
    Timeline,
    Radial,
    Manual,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphLayoutModel {
    pub mode: GraphLayoutMode,
    pub fit_to_view: bool,
    pub preserve_user_positions: bool,
}

impl Default for GraphLayoutModel {
    fn default() -> Self {
        Self {
            mode: GraphLayoutMode::Auto,
            fit_to_view: true,
            preserve_user_positions: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphExpansionModel {
    pub lazy_expansion_available: bool,
    pub focus_mode_available: bool,
    pub filtering_available: bool,
    pub expansion_cursor: Option<String>,
}

impl Default for GraphExpansionModel {
    fn default() -> Self {
        Self {
            lazy_expansion_available: true,
            focus_mode_available: true,
            filtering_available: true,
            expansion_cursor: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphViewModel {
    pub graph_id: GraphViewId,
    pub graph_type: GraphType,
    pub title: RedactedLabel,
    pub nodes: Vec<GraphNodeViewModel>,
    pub edges: Vec<GraphEdgeViewModel>,
    pub paths: Vec<GraphPathSummary>,
    pub legend: GraphLegend,
    pub filters: GraphFilterModel,
    pub layout: GraphLayoutModel,
    pub redaction_status: RedactionStatus,
    pub redaction_summary: GraphRedactionSummary,
    pub node_limit: u32,
    pub edge_limit: u32,
    pub truncated: bool,
    pub truncation_reason: Option<String>,
    pub original_node_count: u32,
    pub original_edge_count: u32,
    pub expansion: GraphExpansionModel,
    pub generated_at: Timestamp,
}

impl GraphViewModel {
    pub fn new(graph_type: GraphType, title: RedactedLabel, scope: GraphScope) -> Self {
        Self {
            graph_id: GraphViewId::new_v4(),
            graph_type,
            title,
            nodes: Vec::new(),
            edges: Vec::new(),
            paths: Vec::new(),
            legend: GraphLegend::default(),
            filters: GraphFilterModel::new(scope),
            layout: GraphLayoutModel::default(),
            redaction_status: RedactionStatus::NotRequired,
            redaction_summary: GraphRedactionSummary::default(),
            node_limit: DEFAULT_GRAPH_VIEW_NODE_LIMIT,
            edge_limit: DEFAULT_GRAPH_VIEW_EDGE_LIMIT,
            truncated: false,
            truncation_reason: None,
            original_node_count: 0,
            original_edge_count: 0,
            expansion: GraphExpansionModel::default(),
            generated_at: Timestamp::now(),
        }
    }

    pub fn with_bounds(mut self, node_limit: u32, edge_limit: u32) -> Self {
        self.node_limit = node_limit;
        self.edge_limit = edge_limit;
        self
    }

    pub fn mark_truncated(
        mut self,
        original_node_count: u32,
        original_edge_count: u32,
        reason: impl Into<String>,
    ) -> Result<Self, GraphContractError> {
        self.truncated = true;
        self.original_node_count = original_node_count;
        self.original_edge_count = original_edge_count;
        self.truncation_reason = Some(require_non_empty("truncation_reason", reason.into())?);
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphContractError {
    EmptyField(&'static str),
    EmptyPath,
}

impl fmt::Display for GraphContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::EmptyPath => write!(f, "graph path must contain at least one node"),
        }
    }
}

impl std::error::Error for GraphContractError {}

fn require_non_empty(field: &'static str, value: String) -> Result<String, GraphContractError> {
    if value.trim().is_empty() {
        return Err(GraphContractError::EmptyField(field));
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{EntityId, EntityRef, EntityType};

    #[test]
    fn graph_view_model_uses_v1_bounds_and_truncation_metadata() {
        let title =
            RedactedLabel::redacted("Incident graph", PrivacyClass::Internal).expect("label");
        let view = GraphViewModel::new(GraphType::IncidentGraph, title, GraphScope::Overview)
            .mark_truncated(900, 2_000, "node and edge limits exceeded")
            .expect("valid truncation reason");

        assert_eq!(view.node_limit, DEFAULT_GRAPH_VIEW_NODE_LIMIT);
        assert_eq!(view.edge_limit, DEFAULT_GRAPH_VIEW_EDGE_LIMIT);
        assert!(view.truncated);
        assert_eq!(view.original_node_count, 900);
        assert_eq!(view.original_edge_count, 2_000);
        assert!(view.truncation_reason.is_some());
    }

    #[test]
    fn graph_hint_and_view_model_are_distinct_contracts() {
        let source = EntityRef::new(EntityId::new_v4(), EntityType::Process);
        let target = EntityRef::new(EntityId::new_v4(), EntityType::Ip);
        let hint = GraphHint::new(
            GraphHintType::ProcessConnectsToIp,
            source,
            target,
            PluginId::new_v4(),
        );
        let title = RedactedLabel::redacted("C2 graph", PrivacyClass::Internal).expect("label");
        let view = GraphViewModel::new(GraphType::C2Graph, title, GraphScope::Overview);

        assert!(hint.evidence_refs.is_empty());
        assert!(view.nodes.is_empty());
    }

    #[test]
    fn unknown_node_and_edge_types_have_safe_fallbacks() {
        let node = GraphNodeViewModel::new(
            GraphNodeType::Unknown("future_node".to_string()),
            RedactedLabel::redacted("Future node", PrivacyClass::Internal).expect("label"),
        );
        let edge = GraphEdgeViewModel::new(
            GraphEdgeType::Unknown("future_edge".to_string()),
            GraphNodeId::new_v4(),
            GraphNodeId::new_v4(),
        );

        assert!(node.generic_fallback);
        assert_eq!(node.icon, "generic-node");
        assert!(edge.generic_fallback);
        assert_eq!(edge.style_hint, GraphEdgeStyleHint::Generic);
    }

    #[test]
    fn graph_path_requires_a_node_sequence() {
        let label = RedactedLabel::redacted("empty path", PrivacyClass::Internal).expect("label");
        let path = GraphPath::new(
            GraphPathType::IncidentSummaryPath,
            Vec::new(),
            Vec::new(),
            label,
        );

        assert_eq!(path, Err(GraphContractError::EmptyPath));
    }

    #[test]
    fn graph_detail_ref_omits_absent_internal_identifiers_from_serialized_payloads() {
        let detail = GraphDetailRef::empty();
        let serialized = serde_json::to_string(&detail).expect("serialize detail");

        assert!(!serialized.contains("entity_id"));
        assert!(!serialized.contains("finding_id"));
        assert!(!serialized.contains("alert_id"));
        assert!(!serialized.contains("incident_id"));
        assert!(!serialized.contains("custom_ref"));
    }
}
