use sentinel_contracts::{
    Alert, CanonicalGraphEdge, CanonicalGraphNode, ContractDescriptor, DataSourceDescriptor,
    DataSourceKind, EntityId, EntityRef, EntityType, EventId, EvidenceId, Finding, FindingId,
    GraphContractError, GraphEdgeType, GraphHint, GraphHintType, GraphNodeId, GraphNodeType,
    GraphScope, GraphType, GraphViewId, Incident, ManifestValidationError, MaturityLevel,
    MetricKind, MetricSchema, PermissionCategory, PermissionDescriptor, PermissionKey,
    PermissionRiskLevel, PluginId, PluginManifest, PluginStatefulness, PluginType, PrivacyClass,
    QualityScore, RedactedLabel, RedactionStatus, RefreshMode, RendererType, RuntimeMode,
    SchemaVersion, SupportLevel, Timestamp, UiContribution, UiContributionSlot,
};
use sentinel_storage::{GraphStore, LogicalRecord, LogicalStore, StorageError, StoreKind};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fmt;

pub const GRAPH_STAGE_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const GRAPH_STAGE_PLUGIN_NAME: &str = "graph_stage";

#[derive(Debug)]
pub enum GraphStageError {
    EmptyHintBatch,
    EmptyField(&'static str),
    MissingEvidence,
    InvalidHint(&'static str),
    PrivacyMarker { field: &'static str },
    Graph(GraphContractError),
    Manifest(ManifestValidationError),
    Storage(StorageError),
    Serialization(serde_json::Error),
}

impl fmt::Display for GraphStageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyHintBatch => write!(f, "graph stage requires hints or source records"),
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::MissingEvidence => write!(f, "graph hint requires at least one evidence ref"),
            Self::InvalidHint(reason) => write!(f, "invalid graph hint: {reason}"),
            Self::PrivacyMarker { field } => {
                write!(f, "{field} contains a forbidden sensitive marker")
            }
            Self::Graph(error) => write!(f, "{error}"),
            Self::Manifest(error) => write!(f, "{error}"),
            Self::Storage(error) => write!(f, "{error}"),
            Self::Serialization(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for GraphStageError {}

impl From<GraphContractError> for GraphStageError {
    fn from(value: GraphContractError) -> Self {
        Self::Graph(value)
    }
}

impl From<ManifestValidationError> for GraphStageError {
    fn from(value: ManifestValidationError) -> Self {
        Self::Manifest(value)
    }
}

impl From<StorageError> for GraphStageError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

impl From<serde_json::Error> for GraphStageError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphStageInput {
    pub producer_plugin: PluginId,
    pub graph_hints: Vec<GraphHint>,
    pub findings: Vec<Finding>,
    pub alerts: Vec<Alert>,
    pub incidents: Vec<Incident>,
    pub graph_type: GraphType,
    pub scope: GraphScope,
    pub graph_view_id: Option<GraphViewId>,
    pub labels: Vec<String>,
}

impl GraphStageInput {
    pub fn new(producer_plugin: PluginId) -> Self {
        Self {
            producer_plugin,
            graph_hints: Vec::new(),
            findings: Vec::new(),
            alerts: Vec::new(),
            incidents: Vec::new(),
            graph_type: GraphType::IncidentGraph,
            scope: GraphScope::Overview,
            graph_view_id: None,
            labels: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphStageOutput {
    pub nodes: Vec<CanonicalGraphNode>,
    pub edges: Vec<CanonicalGraphEdge>,
    pub graph_updates: Vec<GraphUpdateEvent>,
    pub write_report: CanonicalGraphWriteReport,
    pub dead_letters: Vec<GraphStageDeadLetter>,
    pub accepted_hint_count: usize,
    pub rejected_hint_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphStageDeadLetterReason {
    EmptyEvidence,
    PrivacyPolicyViolation,
    InvalidIdentity,
    UnsupportedHint,
}

impl GraphStageDeadLetterReason {
    fn as_error_code(&self) -> &'static str {
        match self {
            Self::EmptyEvidence => "empty_evidence",
            Self::PrivacyPolicyViolation => "privacy_policy_violation",
            Self::InvalidIdentity => "invalid_identity",
            Self::UnsupportedHint => "unsupported_hint",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphStageDeadLetter {
    pub dead_letter_id: EventId,
    pub hint_id: sentinel_contracts::GraphHintId,
    pub producer_plugin: PluginId,
    pub error_code: String,
    pub error_summary_redacted: String,
    pub redacted_hint_summary: String,
    pub timestamp: Timestamp,
}

impl GraphStageDeadLetter {
    fn from_hint(
        hint: &GraphHint,
        reason: GraphStageDeadLetterReason,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            dead_letter_id: EventId::new_v4(),
            hint_id: hint.hint_id.clone(),
            producer_plugin: hint.producer_plugin.clone(),
            error_code: reason.as_error_code().to_string(),
            error_summary_redacted: summary.into(),
            redacted_hint_summary: "graph hint rejected by graph stage policy".to_string(),
            timestamp: Timestamp::now(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphUpdateEvent {
    pub event_id: EventId,
    pub graph_type: GraphType,
    pub scope: GraphScope,
    pub graph_view_id: Option<GraphViewId>,
    pub changed_node_count: u32,
    pub changed_edge_count: u32,
    pub changed_path_count: u32,
    pub summary_redacted: String,
    pub privacy_class: PrivacyClass,
    pub timestamp: Timestamp,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalGraphWriteReport {
    pub node_records_written: usize,
    pub edge_records_written: usize,
    pub path_records_written: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NormalizedNodeIdentity {
    pub entity_id: EntityId,
    pub entity_type: EntityType,
    pub node_type: GraphNodeType,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct NormalizedEdgeIdentity {
    edge_type: GraphEdgeType,
    source: NormalizedNodeIdentity,
    target: NormalizedNodeIdentity,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValidatedGraphHint {
    pub hint: GraphHint,
    pub source_identity: NormalizedNodeIdentity,
    pub target_identity: NormalizedNodeIdentity,
    pub edge_type: GraphEdgeType,
}

#[derive(Clone, Debug, Default)]
pub struct NodeIdentityNormalizer;

impl NodeIdentityNormalizer {
    pub fn new() -> Self {
        Self
    }

    pub fn normalize(
        &self,
        entity_ref: &EntityRef,
    ) -> Result<NormalizedNodeIdentity, GraphStageError> {
        validate_entity_ref(entity_ref)?;
        Ok(NormalizedNodeIdentity {
            entity_id: entity_ref.entity_id.clone(),
            entity_type: entity_ref.entity_type.clone(),
            node_type: node_type_for_entity(&entity_ref.entity_type),
        })
    }

    pub fn redacted_label(&self, entity_ref: &EntityRef) -> Result<RedactedLabel, GraphStageError> {
        validate_entity_ref(entity_ref)?;
        let display = match entity_ref.entity_type {
            EntityType::Host => "local host",
            EntityType::User => "local user",
            EntityType::Process => "process",
            EntityType::Service => "local service",
            EntityType::Port => "local port",
            EntityType::Ip => "ip destination",
            EntityType::Domain => "domain",
            EntityType::CloudResource => "cloud destination",
            EntityType::Asn => "asn",
            EntityType::Certificate => "certificate",
            EntityType::Finding => "finding",
            EntityType::Alert => "alert",
            EntityType::Incident => "incident",
            _ => "graph entity",
        };
        RedactedLabel::new(display, RedactionStatus::Redacted, PrivacyClass::Internal)
            .map_err(GraphStageError::from)
    }
}

#[derive(Clone, Debug)]
pub struct GraphHintValidator {
    normalizer: NodeIdentityNormalizer,
}

impl Default for GraphHintValidator {
    fn default() -> Self {
        Self {
            normalizer: NodeIdentityNormalizer::new(),
        }
    }
}

impl GraphHintValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(
        &self,
        hint: GraphHint,
    ) -> Result<ValidatedGraphHint, Box<GraphStageDeadLetter>> {
        if hint.evidence_refs.is_empty() {
            return Err(Box::new(GraphStageDeadLetter::from_hint(
                &hint,
                GraphStageDeadLetterReason::EmptyEvidence,
                "graph hint has no evidence refs",
            )));
        }
        if hint.confidence.value() <= 0.0 {
            return Err(Box::new(GraphStageDeadLetter::from_hint(
                &hint,
                GraphStageDeadLetterReason::UnsupportedHint,
                "graph hint confidence is empty",
            )));
        }
        if let GraphHintType::Custom(value) = &hint.hint_type {
            match validate_safe_text("hint_type", value) {
                Ok(()) => {}
                Err(GraphStageError::PrivacyMarker { .. }) => {
                    return Err(Box::new(GraphStageDeadLetter::from_hint(
                        &hint,
                        GraphStageDeadLetterReason::PrivacyPolicyViolation,
                        "graph hint type violated privacy policy",
                    )));
                }
                Err(_) => {
                    return Err(Box::new(GraphStageDeadLetter::from_hint(
                        &hint,
                        GraphStageDeadLetterReason::UnsupportedHint,
                        "graph hint type could not be validated",
                    )));
                }
            }
        }
        let source_identity = match self.normalizer.normalize(&hint.source_entity) {
            Ok(identity) => identity,
            Err(GraphStageError::PrivacyMarker { .. }) => {
                return Err(Box::new(GraphStageDeadLetter::from_hint(
                    &hint,
                    GraphStageDeadLetterReason::PrivacyPolicyViolation,
                    "graph hint source identity violated privacy policy",
                )));
            }
            Err(_) => {
                return Err(Box::new(GraphStageDeadLetter::from_hint(
                    &hint,
                    GraphStageDeadLetterReason::InvalidIdentity,
                    "graph hint source identity could not be normalized",
                )));
            }
        };
        let target_identity = match self.normalizer.normalize(&hint.target_entity) {
            Ok(identity) => identity,
            Err(GraphStageError::PrivacyMarker { .. }) => {
                return Err(Box::new(GraphStageDeadLetter::from_hint(
                    &hint,
                    GraphStageDeadLetterReason::PrivacyPolicyViolation,
                    "graph hint target identity violated privacy policy",
                )));
            }
            Err(_) => {
                return Err(Box::new(GraphStageDeadLetter::from_hint(
                    &hint,
                    GraphStageDeadLetterReason::InvalidIdentity,
                    "graph hint target identity could not be normalized",
                )));
            }
        };
        let edge_type =
            edge_type_for_hint(&hint.hint_type, &hint.source_entity, &hint.target_entity);
        Ok(ValidatedGraphHint {
            hint,
            source_identity,
            target_identity,
            edge_type,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct GraphEvidenceBinder;

impl GraphEvidenceBinder {
    pub fn new() -> Self {
        Self
    }

    pub fn bind_node(&self, node: &mut CanonicalGraphNode, evidence_refs: &[EvidenceId]) {
        for evidence_ref in evidence_refs {
            push_unique(&mut node.source_refs, evidence_ref.clone());
        }
    }

    pub fn bind_edge(&self, edge: &mut CanonicalGraphEdge, evidence_refs: &[EvidenceId]) {
        for evidence_ref in evidence_refs {
            push_unique(&mut edge.evidence_refs, evidence_ref.clone());
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GraphConfidenceAssigner;

impl GraphConfidenceAssigner {
    pub fn new() -> Self {
        Self
    }

    pub fn assign_node(&self, node: &mut CanonicalGraphNode, confidence: &QualityScore) {
        node.confidence = max_quality(&node.confidence, confidence);
    }

    pub fn assign_edge(&self, edge: &mut CanonicalGraphEdge, confidence: &QualityScore) {
        edge.confidence = max_quality(&edge.confidence, confidence);
        edge.weight = max_quality(&edge.weight, confidence);
    }
}

#[derive(Clone, Debug)]
pub struct GraphDeduplicator {
    normalizer: NodeIdentityNormalizer,
    evidence_binder: GraphEvidenceBinder,
    confidence_assigner: GraphConfidenceAssigner,
    nodes_by_identity: HashMap<NormalizedNodeIdentity, CanonicalGraphNode>,
    edges_by_identity: HashMap<NormalizedEdgeIdentity, CanonicalGraphEdge>,
}

impl Default for GraphDeduplicator {
    fn default() -> Self {
        Self {
            normalizer: NodeIdentityNormalizer::new(),
            evidence_binder: GraphEvidenceBinder::new(),
            confidence_assigner: GraphConfidenceAssigner::new(),
            nodes_by_identity: HashMap::new(),
            edges_by_identity: HashMap::new(),
        }
    }
}

impl GraphDeduplicator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest(&mut self, validated: &ValidatedGraphHint) -> Result<(), GraphStageError> {
        let source_id = self.upsert_node(
            &validated.source_identity,
            &validated.hint.source_entity,
            &validated.hint.evidence_refs,
            &validated.hint.confidence,
            &validated.hint.timestamp,
            &validated.hint.privacy_class,
        )?;
        let target_id = self.upsert_node(
            &validated.target_identity,
            &validated.hint.target_entity,
            &validated.hint.evidence_refs,
            &validated.hint.confidence,
            &validated.hint.timestamp,
            &validated.hint.privacy_class,
        )?;
        self.upsert_edge(validated, source_id, target_id);
        Ok(())
    }

    pub fn finish(self) -> CanonicalGraphWriteSet {
        CanonicalGraphWriteSet {
            nodes: self.nodes_by_identity.into_values().collect(),
            edges: self.edges_by_identity.into_values().collect(),
            paths: Vec::new(),
        }
    }

    fn upsert_node(
        &mut self,
        identity: &NormalizedNodeIdentity,
        entity_ref: &EntityRef,
        evidence_refs: &[EvidenceId],
        confidence: &QualityScore,
        timestamp: &Timestamp,
        privacy_class: &PrivacyClass,
    ) -> Result<GraphNodeId, GraphStageError> {
        let node = self
            .nodes_by_identity
            .entry(identity.clone())
            .or_insert_with(|| {
                let mut node = CanonicalGraphNode::new(
                    identity.node_type.clone(),
                    self.normalizer
                        .redacted_label(entity_ref)
                        .expect("validated entity label can be redacted"),
                );
                node.entity_ref = Some(entity_ref.clone());
                node.first_seen = timestamp.clone();
                node.last_seen = timestamp.clone();
                node.privacy_class = privacy_class.clone();
                node
            });

        node.last_seen = timestamp.clone();
        node.privacy_class = most_sensitive_privacy(&node.privacy_class, privacy_class);
        self.evidence_binder.bind_node(node, evidence_refs);
        self.confidence_assigner.assign_node(node, confidence);
        Ok(node.node_id.clone())
    }

    fn upsert_edge(
        &mut self,
        validated: &ValidatedGraphHint,
        source_node: GraphNodeId,
        target_node: GraphNodeId,
    ) {
        let key = NormalizedEdgeIdentity {
            edge_type: validated.edge_type.clone(),
            source: validated.source_identity.clone(),
            target: validated.target_identity.clone(),
        };
        let edge = self.edges_by_identity.entry(key).or_insert_with(|| {
            let mut edge = CanonicalGraphEdge::new(
                validated.edge_type.clone(),
                source_node.clone(),
                target_node.clone(),
            );
            edge.first_seen = validated.hint.timestamp.clone();
            edge.last_seen = validated.hint.timestamp.clone();
            edge.privacy_class = validated.hint.privacy_class.clone();
            edge.producer_plugin = Some(validated.hint.producer_plugin.clone());
            edge.label = Some(
                RedactedLabel::new(
                    hint_type_label(&validated.hint.hint_type),
                    RedactionStatus::Redacted,
                    PrivacyClass::Internal,
                )
                .expect("hint type labels are non-empty"),
            );
            edge
        });
        edge.last_seen = validated.hint.timestamp.clone();
        edge.privacy_class =
            most_sensitive_privacy(&edge.privacy_class, &validated.hint.privacy_class);
        self.evidence_binder
            .bind_edge(edge, &validated.hint.evidence_refs);
        self.confidence_assigner
            .assign_edge(edge, &validated.hint.confidence);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CanonicalGraphWriteSet {
    pub nodes: Vec<CanonicalGraphNode>,
    pub edges: Vec<CanonicalGraphEdge>,
    pub paths: Vec<sentinel_contracts::GraphPath>,
}

#[derive(Clone, Debug, Default)]
pub struct CanonicalGraphWriter;

impl CanonicalGraphWriter {
    pub fn new() -> Self {
        Self
    }

    pub fn write_to_store<G>(
        &self,
        graph_store: &G,
        write_set: &CanonicalGraphWriteSet,
    ) -> Result<CanonicalGraphWriteReport, GraphStageError>
    where
        G: GraphStore,
    {
        for node in &write_set.nodes {
            let record = LogicalRecord::metadata_only(
                node.node_id.clone(),
                GRAPH_STAGE_SCHEMA_VERSION,
                StoreKind::GraphNode.default_storage_privacy_class(),
                serde_json::to_value(node)?,
            )
            .with_entity_refs(node.entity_ref.clone().into_iter().collect())
            .with_record_time(node.last_seen.clone());
            graph_store.nodes().append(record)?;
        }
        for edge in &write_set.edges {
            let record = LogicalRecord::metadata_only(
                edge.edge_id.clone(),
                GRAPH_STAGE_SCHEMA_VERSION,
                StoreKind::GraphEdge.default_storage_privacy_class(),
                serde_json::to_value(edge)?,
            )
            .with_record_time(edge.last_seen.clone());
            graph_store.edges().append(record)?;
        }
        for path in &write_set.paths {
            let record = LogicalRecord::metadata_only(
                path.path_id.clone(),
                GRAPH_STAGE_SCHEMA_VERSION,
                StoreKind::GraphPath.default_storage_privacy_class(),
                serde_json::to_value(path)?,
            );
            graph_store.paths().append(record)?;
        }
        Ok(CanonicalGraphWriteReport {
            node_records_written: write_set.nodes.len(),
            edge_records_written: write_set.edges.len(),
            path_records_written: write_set.paths.len(),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct GraphUpdateEmitter;

impl GraphUpdateEmitter {
    pub fn new() -> Self {
        Self
    }

    pub fn emit(
        &self,
        graph_type: GraphType,
        scope: GraphScope,
        graph_view_id: Option<GraphViewId>,
        report: &CanonicalGraphWriteReport,
    ) -> Result<GraphUpdateEvent, GraphStageError> {
        let changed_node_count = report.node_records_written as u32;
        let changed_edge_count = report.edge_records_written as u32;
        let changed_path_count = 0;
        let summary_redacted = format!(
            "Graph stage updated {changed_node_count} node(s), {changed_edge_count} edge(s), and {changed_path_count} path(s)."
        );
        validate_safe_text("graph_update.summary", &summary_redacted)?;
        Ok(GraphUpdateEvent {
            event_id: EventId::new_v4(),
            graph_type,
            scope,
            graph_view_id,
            changed_node_count,
            changed_edge_count,
            changed_path_count,
            summary_redacted,
            privacy_class: PrivacyClass::Internal,
            timestamp: Timestamp::now(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct GraphStagePlugin {
    hint_validator: GraphHintValidator,
    deduplicator: GraphDeduplicator,
    canonical_writer: CanonicalGraphWriter,
    update_emitter: GraphUpdateEmitter,
}

impl Default for GraphStagePlugin {
    fn default() -> Self {
        Self {
            hint_validator: GraphHintValidator::new(),
            deduplicator: GraphDeduplicator::new(),
            canonical_writer: CanonicalGraphWriter::new(),
            update_emitter: GraphUpdateEmitter::new(),
        }
    }
}

impl GraphStagePlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn manifest() -> Result<PluginManifest, GraphStageError> {
        let plugin_id = PluginId::new_v4();
        let mut manifest = PluginManifest::new(
            plugin_id.clone(),
            GRAPH_STAGE_PLUGIN_NAME,
            "0.1.0",
            "graph",
            PluginType::Graph,
            RuntimeMode::Hybrid,
        )?;
        manifest.description =
            "Canonical graph ownership stage for validated graph hints and security links."
                .to_string();
        manifest.enabled_by_default = true;
        manifest.maturity_level = MaturityLevel::L3Modeling;
        manifest.capability_tags = vec![
            "local_first".to_string(),
            "metadata_first".to_string(),
            "canonical_graph".to_string(),
            "graph_stage_only".to_string(),
        ];
        manifest.input_contracts = [
            "graph.hint",
            "security.finding",
            "security.alert",
            "security.incident",
        ]
        .into_iter()
        .map(contract)
        .collect::<Result<Vec<_>, _>>()?;
        manifest.output_contracts = [
            "graph.update",
            "graph.canonical.node",
            "graph.canonical.edge",
        ]
        .into_iter()
        .map(contract)
        .collect::<Result<Vec<_>, _>>()?;
        manifest.required_permissions = vec![
            permission(
                "read.graph.hint",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "Read graph hints emitted by detection and risk stages.",
                &["graph.hint"],
            )?,
            permission(
                "read.security.finding",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "Read evidence-backed findings for graph relationships.",
                &["security.finding"],
            )?,
            permission(
                "read.security.alert",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "Read promoted alerts for graph relationships.",
                &["security.alert"],
            )?,
            permission(
                "read.security.incident",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "Read incident candidates for graph relationships.",
                &["security.incident"],
            )?,
            permission(
                "write.graph.update",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Medium,
                "Emit compact graph update events after canonical graph writes.",
                &["graph.update"],
            )?,
            permission(
                "write.graph.canonical",
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Medium,
                "Write metadata-only canonical graph node and edge records.",
                &["graph.canonical.node", "graph.canonical.edge"],
            )?,
        ];
        manifest.metrics_schema = vec![
            metric(
                "graph_stage.hints_in_total",
                MetricKind::Counter,
                "Graph hints received by graph stage",
            )?,
            metric(
                "graph_stage.nodes_written_total",
                MetricKind::Counter,
                "Canonical graph node records written",
            )?,
            metric(
                "graph_stage.edges_written_total",
                MetricKind::Counter,
                "Canonical graph edge records written",
            )?,
            metric(
                "graph_stage.dead_letters_total",
                MetricKind::Counter,
                "Graph hints rejected with redacted summaries",
            )?,
        ];
        manifest.graph_hint_types = vec![
            "process_connects_to_ip".to_string(),
            "process_queries_domain".to_string(),
            "process_uploads_to_cloud".to_string(),
            "finding_supports_alert".to_string(),
            "alert_part_of_incident".to_string(),
        ];
        manifest.ui_contributions = vec![ui_contribution(
            plugin_id,
            UiContributionSlot::GraphProjection,
            RendererType::GraphProjection,
            "Canonical Graph Projection",
            "graph.update",
        )?];
        manifest.statefulness = PluginStatefulness::Checkpointed;
        manifest.checkpoint_support = SupportLevel::Required;
        manifest.replay_support = SupportLevel::Required;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn process<G>(
        &mut self,
        input: GraphStageInput,
        graph_store: Option<&G>,
    ) -> Result<GraphStageOutput, GraphStageError>
    where
        G: GraphStore,
    {
        validate_input(&input)?;
        let mut all_hints = input.graph_hints;
        all_hints.extend(synthesize_security_graph_hints(
            &input.findings,
            &input.alerts,
            &input.incidents,
            &input.producer_plugin,
        ));
        if all_hints.is_empty() {
            return Err(GraphStageError::EmptyHintBatch);
        }

        let mut accepted_hint_count = 0;
        let mut dead_letters = Vec::new();
        for hint in all_hints {
            match self.hint_validator.validate(hint) {
                Ok(validated) => {
                    self.deduplicator.ingest(&validated)?;
                    accepted_hint_count += 1;
                }
                Err(dead_letter) => dead_letters.push(*dead_letter),
            }
        }

        let write_set = std::mem::take(&mut self.deduplicator).finish();
        let write_report = if let Some(store) = graph_store {
            self.canonical_writer.write_to_store(store, &write_set)?
        } else {
            CanonicalGraphWriteReport {
                node_records_written: write_set.nodes.len(),
                edge_records_written: write_set.edges.len(),
                path_records_written: write_set.paths.len(),
            }
        };
        let graph_update = self.update_emitter.emit(
            input.graph_type,
            input.scope,
            input.graph_view_id,
            &write_report,
        )?;

        Ok(GraphStageOutput {
            nodes: write_set.nodes,
            edges: write_set.edges,
            graph_updates: vec![graph_update],
            write_report,
            rejected_hint_count: dead_letters.len(),
            dead_letters,
            accepted_hint_count,
        })
    }
}

fn synthesize_security_graph_hints(
    findings: &[Finding],
    alerts: &[Alert],
    incidents: &[Incident],
    producer_plugin: &PluginId,
) -> Vec<GraphHint> {
    let finding_by_id = findings
        .iter()
        .map(|finding| (finding.id().clone(), finding))
        .collect::<HashMap<_, _>>();
    let alert_by_id = alerts
        .iter()
        .map(|alert| (alert.id().clone(), alert))
        .collect::<HashMap<_, _>>();
    let mut hints = Vec::new();

    for alert in alerts {
        for finding_id in alert.finding_refs() {
            let evidence_refs = finding_by_id
                .get(finding_id)
                .map(|finding| finding.evidence_refs().to_vec())
                .unwrap_or_default();
            if evidence_refs.is_empty() {
                continue;
            }
            let mut hint = GraphHint::new(
                GraphHintType::FindingSupportsAlert,
                finding_entity_ref(finding_id),
                alert_entity_ref(alert),
                producer_plugin.clone(),
            );
            hint.evidence_refs = evidence_refs;
            hint.confidence = alert.confidence().clone();
            hint.privacy_class = PrivacyClass::Internal;
            hints.push(hint);
        }
    }

    for incident in incidents {
        for alert_id in incident.alert_refs() {
            let evidence_refs = alert_by_id
                .get(alert_id)
                .map(|alert| {
                    alert
                        .finding_refs()
                        .iter()
                        .filter_map(|finding_id| finding_by_id.get(finding_id))
                        .flat_map(|finding| finding.evidence_refs().iter().cloned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if evidence_refs.is_empty() {
                continue;
            }
            let mut hint = GraphHint::new(
                GraphHintType::AlertPartOfIncident,
                alert_entity_ref_from_id(alert_id),
                incident_entity_ref(incident),
                producer_plugin.clone(),
            );
            hint.evidence_refs = evidence_refs;
            hint.confidence = incident.confidence().clone();
            hint.privacy_class = PrivacyClass::Internal;
            hints.push(hint);
        }
    }

    hints
}

fn validate_input(input: &GraphStageInput) -> Result<(), GraphStageError> {
    for label in &input.labels {
        validate_safe_text("label", label)?;
    }
    for finding in &input.findings {
        validate_safe_text("finding_type", finding.finding_type())?;
        validate_safe_text(
            "finding.explanation",
            &finding.explanation().summary_redacted,
        )?;
        for entity_ref in finding.entity_refs() {
            validate_entity_ref(entity_ref)?;
        }
    }
    for alert in &input.alerts {
        validate_safe_text("alert.title", alert.title_redacted())?;
        validate_safe_text("alert.summary", alert.summary_redacted())?;
        for entity_ref in alert.entity_refs() {
            validate_entity_ref(entity_ref)?;
        }
    }
    for incident in &input.incidents {
        validate_safe_text("incident.type", incident.incident_type())?;
        validate_safe_text("incident.title", incident.title_redacted())?;
        validate_safe_text("incident.summary", incident.summary_redacted())?;
    }
    Ok(())
}

fn validate_entity_ref(entity_ref: &EntityRef) -> Result<(), GraphStageError> {
    if let Some(name) = &entity_ref.entity_name {
        validate_safe_text("entity_name", name)?;
    }
    if let Some(namespace) = &entity_ref.namespace {
        validate_safe_text("entity_namespace", namespace)?;
    }
    if let Some(source) = &entity_ref.source {
        validate_safe_text("entity_source", source)?;
    }
    Ok(())
}

fn node_type_for_entity(entity_type: &EntityType) -> GraphNodeType {
    match entity_type {
        EntityType::Host => GraphNodeType::LocalHost,
        EntityType::User => GraphNodeType::LocalUser,
        EntityType::Process => GraphNodeType::Process,
        EntityType::Service => GraphNodeType::LocalService,
        EntityType::Port => GraphNodeType::LocalPort,
        EntityType::Ip => GraphNodeType::Ip,
        EntityType::Domain => GraphNodeType::Domain,
        EntityType::CloudResource => GraphNodeType::CloudDestination,
        EntityType::Asn => GraphNodeType::Asn,
        EntityType::Certificate => GraphNodeType::Certificate,
        EntityType::Finding => GraphNodeType::Finding,
        EntityType::Alert => GraphNodeType::Alert,
        EntityType::Incident => GraphNodeType::Incident,
        other => GraphNodeType::Unknown(format!("{other:?}").to_ascii_lowercase()),
    }
}

fn edge_type_for_hint(
    hint_type: &GraphHintType,
    source: &EntityRef,
    target: &EntityRef,
) -> GraphEdgeType {
    match hint_type {
        GraphHintType::ProcessConnectsToIp => GraphEdgeType::ProcessConnectsToIp,
        GraphHintType::ProcessQueriesDomain => GraphEdgeType::ProcessQueriesDomain,
        GraphHintType::DomainResolvesToIp => GraphEdgeType::DomainResolvesToIp,
        GraphHintType::IpBelongsToAsn => GraphEdgeType::IpBelongsToAsn,
        GraphHintType::IpBelongsToCloudProvider => GraphEdgeType::IpBelongsToCloudProvider,
        GraphHintType::ProcessUsesTlsFingerprint => GraphEdgeType::ProcessUsesTlsFingerprint,
        GraphHintType::ProcessUploadsToCloud => GraphEdgeType::ProcessUploadsToCloud,
        GraphHintType::ObservationSupportsFinding => GraphEdgeType::ObservationSupportsFinding,
        GraphHintType::FindingSupportsAlert => GraphEdgeType::FindingSupportsAlert,
        GraphHintType::AlertPartOfIncident => GraphEdgeType::AlertPartOfIncident,
        GraphHintType::IncidentRecommendsResponse => GraphEdgeType::IncidentRecommendsResponse,
        GraphHintType::ResponseActionTargetsEntity => GraphEdgeType::ResponseActionTargetsEntity,
        GraphHintType::Custom(value) if value == "process_listens_on_port" => {
            GraphEdgeType::ProcessListensOnPort
        }
        GraphHintType::Custom(value) if value == "suspicious_c2_relation" => {
            if target.entity_type == EntityType::Domain {
                GraphEdgeType::ProcessQueriesDomain
            } else if target.entity_type == EntityType::Ip {
                GraphEdgeType::ProcessConnectsToIp
            } else {
                GraphEdgeType::Custom(value.clone())
            }
        }
        GraphHintType::Custom(value) if value == "lateral_exposure_linked_movement" => {
            GraphEdgeType::Custom("lateral_exposure_linked_movement".to_string())
        }
        GraphHintType::Custom(value) if value == "lateral_internal_fanout" => {
            GraphEdgeType::Custom("lateral_internal_fanout".to_string())
        }
        GraphHintType::Custom(value) if value == "lateral_service_probe" => {
            GraphEdgeType::Custom("lateral_service_probe".to_string())
        }
        GraphHintType::Custom(value) if value == "session_source_context_to_destination_host" => {
            GraphEdgeType::Custom("session_source_context_to_destination_host".to_string())
        }
        GraphHintType::Custom(value) if value == "destination_host_to_service_port" => {
            GraphEdgeType::Custom("destination_host_to_service_port".to_string())
        }
        GraphHintType::Custom(value) if value == "finding_implicates_destination" => {
            GraphEdgeType::Custom("finding_implicates_destination".to_string())
        }
        GraphHintType::Custom(value) if source.entity_type == EntityType::Process => {
            GraphEdgeType::Custom(value.clone())
        }
        GraphHintType::Custom(value) => GraphEdgeType::Unknown(value.clone()),
    }
}

fn finding_entity_ref(finding_id: &FindingId) -> EntityRef {
    let mut entity = EntityRef::new(
        EntityId::from_uuid(finding_id.as_uuid()),
        EntityType::Finding,
    );
    entity.entity_name = Some("finding".to_string());
    entity.source = Some("graph_stage".to_string());
    entity.confidence = QualityScore::perfect();
    entity
}

fn alert_entity_ref(alert: &Alert) -> EntityRef {
    alert_entity_ref_from_id(alert.id())
}

fn alert_entity_ref_from_id(alert_id: &sentinel_contracts::AlertId) -> EntityRef {
    let mut entity = EntityRef::new(EntityId::from_uuid(alert_id.as_uuid()), EntityType::Alert);
    entity.entity_name = Some("alert".to_string());
    entity.source = Some("graph_stage".to_string());
    entity.confidence = QualityScore::perfect();
    entity
}

fn incident_entity_ref(incident: &Incident) -> EntityRef {
    let mut entity = EntityRef::new(
        EntityId::from_uuid(incident.id().as_uuid()),
        EntityType::Incident,
    );
    entity.entity_name = Some("incident".to_string());
    entity.source = Some("graph_stage".to_string());
    entity.confidence = QualityScore::perfect();
    entity
}

fn hint_type_label(hint_type: &GraphHintType) -> String {
    match hint_type {
        GraphHintType::ProcessConnectsToIp => "process_connects_to_ip".to_string(),
        GraphHintType::ProcessQueriesDomain => "process_queries_domain".to_string(),
        GraphHintType::DomainResolvesToIp => "domain_resolves_to_ip".to_string(),
        GraphHintType::IpBelongsToAsn => "ip_belongs_to_asn".to_string(),
        GraphHintType::IpBelongsToCloudProvider => "ip_belongs_to_cloud_provider".to_string(),
        GraphHintType::ProcessUsesTlsFingerprint => "process_uses_tls_fingerprint".to_string(),
        GraphHintType::ProcessUploadsToCloud => "process_uploads_to_cloud".to_string(),
        GraphHintType::ObservationSupportsFinding => "observation_supports_finding".to_string(),
        GraphHintType::FindingSupportsAlert => "finding_supports_alert".to_string(),
        GraphHintType::AlertPartOfIncident => "alert_part_of_incident".to_string(),
        GraphHintType::IncidentRecommendsResponse => "incident_recommends_response".to_string(),
        GraphHintType::ResponseActionTargetsEntity => "response_action_targets_entity".to_string(),
        GraphHintType::Custom(value) => value.clone(),
    }
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn max_quality(left: &QualityScore, right: &QualityScore) -> QualityScore {
    if left.value() >= right.value() {
        left.clone()
    } else {
        right.clone()
    }
}

fn most_sensitive_privacy(left: &PrivacyClass, right: &PrivacyClass) -> PrivacyClass {
    if privacy_rank(left) >= privacy_rank(right) {
        left.clone()
    } else {
        right.clone()
    }
}

fn privacy_rank(value: &PrivacyClass) -> u8 {
    match value {
        PrivacyClass::Public => 0,
        PrivacyClass::Internal => 1,
        PrivacyClass::Sensitive => 2,
        PrivacyClass::Secret => 3,
        PrivacyClass::Redacted => 1,
        PrivacyClass::Tokenized => 1,
    }
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), GraphStageError> {
    if value.trim().is_empty() {
        return Err(GraphStageError::EmptyField(field));
    }
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '/', '=', ':', '?', '\\'], "_");
    for marker in [
        "raw_packet",
        "packet_bytes",
        "raw_payload",
        "payload",
        "http_body",
        "request_body",
        "response_body",
        "authorization",
        "authorization_header",
        "api_key",
        "cookie",
        "credential",
        "password",
        "private_key",
        "session_token",
        "access_token",
        "refresh_token",
        "token",
        "secret",
        "form_content",
        "query_string",
        "raw_command_line",
    ] {
        if normalized.contains(marker) {
            return Err(GraphStageError::PrivacyMarker { field });
        }
    }
    Ok(())
}

fn contract(name: &str) -> Result<ContractDescriptor, ManifestValidationError> {
    ContractDescriptor::new(name, GRAPH_STAGE_SCHEMA_VERSION)
}

fn permission(
    key: &str,
    category: PermissionCategory,
    risk_level: PermissionRiskLevel,
    description: &str,
    scopes: &[&str],
) -> Result<PermissionDescriptor, ManifestValidationError> {
    let mut descriptor =
        PermissionDescriptor::new(PermissionKey::new(key)?, category, risk_level, description)?;
    descriptor.scopes = scopes.iter().map(ToString::to_string).collect();
    Ok(descriptor)
}

fn metric(
    name: &str,
    kind: MetricKind,
    description: &str,
) -> Result<MetricSchema, ManifestValidationError> {
    let mut metric = MetricSchema::new(name, kind, description)?;
    metric.privacy_class = PrivacyClass::Internal;
    Ok(metric)
}

fn ui_contribution(
    plugin_id: PluginId,
    slot: UiContributionSlot,
    renderer_type: RendererType,
    title: &str,
    contract_name: &str,
) -> Result<UiContribution, ManifestValidationError> {
    let mut data_source = DataSourceDescriptor::new(DataSourceKind::CapabilityView);
    data_source.contract = Some(contract(contract_name)?);
    let mut contribution = UiContribution::new(plugin_id, slot, renderer_type, title, data_source)?;
    contribution.refresh_mode = RefreshMode::EventDriven;
    contribution.schema = json!({
        "schema_version": GRAPH_STAGE_SCHEMA_VERSION,
        "metadata_only": true,
        "canonical_graph_owner": true
    });
    Ok(contribution)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use rusqlite::Connection;
    use sentinel_contracts::{
        AlertState, FindingExplanation, IncidentState, PageRequest, QueryRequest, QueryScope,
        SecuritySeverity,
    };
    use sentinel_storage::{
        logical_store_migration, InMemoryMigrationAuditSink, MigrationRunner, SchemaMetadata,
        SqliteStoreFactory,
    };

    fn q(value: f32) -> QualityScore {
        QualityScore::new(value).expect("quality")
    }

    fn entity(entity_type: EntityType, name: &str) -> EntityRef {
        let mut entity = EntityRef::new(EntityId::new_v4(), entity_type);
        entity.entity_name = Some(name.to_string());
        entity.confidence = q(0.9);
        entity
    }

    fn evidence_refs(count: usize) -> Vec<EvidenceId> {
        (0..count).map(|_| EvidenceId::new_v4()).collect()
    }

    fn hint(source: EntityRef, target: EntityRef, hint_type: GraphHintType) -> GraphHint {
        let mut hint = GraphHint::new(hint_type, source, target, PluginId::new_v4());
        hint.evidence_refs = evidence_refs(2);
        hint.confidence = q(0.86);
        hint.privacy_class = PrivacyClass::Internal;
        hint.timestamp = Timestamp::from_datetime(Utc::now() - Duration::minutes(3));
        hint
    }

    fn finding(process: &EntityRef) -> Finding {
        let evidence = evidence_refs(2);
        let explanation = FindingExplanation::new("metadata-only finding").expect("explanation");
        Finding::new(
            "security.finding.c2",
            PluginId::new_v4(),
            evidence,
            explanation,
        )
        .expect("finding")
        .with_entity_refs(vec![process.clone()])
        .with_confidence(q(0.86))
        .with_severity(SecuritySeverity::High)
    }

    fn alert(finding: &Finding, process: &EntityRef) -> Alert {
        Alert::new(
            "risk alert",
            "risk alert summary",
            vec![finding.id().clone()],
        )
        .expect("alert")
        .with_entity_refs(vec![process.clone()])
        .with_confidence(q(0.84))
        .with_severity(SecuritySeverity::High)
        .with_state(AlertState::New)
    }

    fn incident(alert: &Alert, finding: &Finding) -> Incident {
        Incident::new(
            "c2_communication_incident",
            "incident candidate",
            "incident summary",
            vec![alert.id().clone()],
        )
        .expect("incident")
        .with_finding_refs(vec![finding.id().clone()])
        .with_confidence(q(0.82))
        .with_severity(SecuritySeverity::High)
        .with_state(IncidentState::Candidate)
    }

    fn fixture_input() -> GraphStageInput {
        let process = entity(EntityType::Process, "fixture-process");
        let domain = entity(EntityType::Domain, "fixture.example.test");
        let finding = finding(&process);
        let alert = alert(&finding, &process);
        let incident = incident(&alert, &finding);
        let mut input = GraphStageInput::new(PluginId::new_v4());
        input.graph_hints = vec![
            hint(
                process.clone(),
                domain.clone(),
                GraphHintType::ProcessQueriesDomain,
            ),
            hint(process, domain, GraphHintType::ProcessQueriesDomain),
        ];
        input.findings = vec![finding];
        input.alerts = vec![alert];
        input.incidents = vec![incident];
        input.labels = vec!["task_440_fixture".to_string()];
        input
    }

    #[test]
    fn graph_stage_validates_deduplicates_and_writes_canonical_graph() {
        let connection = initialized_connection().expect("connection");
        let factory = SqliteStoreFactory::new(&connection);
        let graph_store = factory.graph_store();
        let output = GraphStagePlugin::new()
            .process(fixture_input(), Some(&graph_store))
            .expect("graph output");

        assert_eq!(output.rejected_hint_count, 0);
        assert!(output.accepted_hint_count >= 3);
        assert_eq!(output.edges.len(), 3);
        assert_eq!(output.nodes.len(), 5);
        assert_eq!(output.write_report.edge_records_written, output.edges.len());
        assert_eq!(output.graph_updates.len(), 1);
        assert!(output.edges.iter().any(|edge| {
            edge.edge_type == GraphEdgeType::ProcessQueriesDomain && edge.evidence_refs.len() == 4
        }));
        assert!(output
            .edges
            .iter()
            .any(|edge| edge.edge_type == GraphEdgeType::FindingSupportsAlert));
        assert!(output
            .edges
            .iter()
            .any(|edge| edge.edge_type == GraphEdgeType::AlertPartOfIncident));
        assert_eq!(
            output.graph_updates[0].changed_node_count,
            output.nodes.len() as u32
        );
        assert_eq!(output.graph_updates[0].changed_path_count, 0);
        assert!(output.nodes.iter().all(|node| !node.source_refs.is_empty()));
        assert!(output
            .edges
            .iter()
            .all(|edge| !edge.evidence_refs.is_empty()));

        let node_records = graph_store
            .nodes()
            .query(QueryRequest::new(QueryScope::Global).with_page(PageRequest::first(50).unwrap()))
            .expect("nodes");
        let edge_records = graph_store
            .edges()
            .query(QueryRequest::new(QueryScope::Global).with_page(PageRequest::first(50).unwrap()))
            .expect("edges");
        assert_eq!(node_records.page.items.len(), output.nodes.len());
        assert_eq!(edge_records.page.items.len(), output.edges.len());
    }

    #[test]
    fn invalid_or_privacy_violating_hints_are_dead_lettered_safely() {
        let process = entity(EntityType::Process, "api_key_scanner");
        let domain = entity(EntityType::Domain, "fixture.example.test");
        let mut input = GraphStageInput::new(PluginId::new_v4());
        input.graph_hints = vec![hint(process, domain, GraphHintType::ProcessQueriesDomain)];

        let output = GraphStagePlugin::new()
            .process(
                input,
                Option::<&sentinel_storage::SqliteGraphStore<'_>>::None,
            )
            .expect("graph output");

        assert_eq!(output.accepted_hint_count, 0);
        assert_eq!(output.dead_letters.len(), 1);
        assert_eq!(
            output.dead_letters[0].error_code,
            "privacy_policy_violation"
        );
        let serialized = serde_json::to_string(&output.dead_letters).expect("serialize");
        assert!(!serialized.contains("api_key_scanner"));
    }

    #[test]
    fn custom_privacy_marker_hint_type_is_dead_lettered_safely() {
        let process = entity(EntityType::Process, "fixture-process");
        let domain = entity(EntityType::Domain, "fixture.example.test");
        let mut input = GraphStageInput::new(PluginId::new_v4());
        input.graph_hints = vec![hint(
            process,
            domain,
            GraphHintType::Custom("raw_payload_relation".to_string()),
        )];

        let output = GraphStagePlugin::new()
            .process(
                input,
                Option::<&sentinel_storage::SqliteGraphStore<'_>>::None,
            )
            .expect("graph output");

        assert_eq!(output.accepted_hint_count, 0);
        assert_eq!(output.dead_letters.len(), 1);
        assert_eq!(
            output.dead_letters[0].error_code,
            "privacy_policy_violation"
        );
        let serialized = serde_json::to_string(&output.dead_letters).expect("serialize");
        assert!(!serialized.contains("raw_payload_relation"));
    }

    #[test]
    fn graph_update_events_do_not_expose_canonical_internals() {
        let output = GraphStagePlugin::new()
            .process(
                fixture_input(),
                Option::<&sentinel_storage::SqliteGraphStore<'_>>::None,
            )
            .expect("graph output");
        let serialized = serde_json::to_string(&output.graph_updates).expect("serialize");

        assert!(!serialized.contains("source_node"));
        assert!(!serialized.contains("target_node"));
        assert!(!serialized.contains("node_sequence"));
        assert!(!serialized.contains("label"));
        assert!(serialized.contains("changed_node_count"));
    }

    #[test]
    fn plugin_manifest_declares_graph_owner_contracts_and_permissions() {
        let manifest = GraphStagePlugin::manifest().expect("manifest");
        manifest.validate().expect("valid manifest");

        let input_contracts = manifest
            .input_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<std::collections::HashSet<_>>();
        assert!(input_contracts.contains("graph.hint"));
        assert!(input_contracts.contains("security.finding"));
        assert!(input_contracts.contains("security.alert"));
        assert!(input_contracts.contains("security.incident"));

        let output_contracts = manifest
            .output_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<std::collections::HashSet<_>>();
        assert!(output_contracts.contains("graph.update"));
        assert!(output_contracts.contains("graph.canonical.node"));
        assert!(output_contracts.contains("graph.canonical.edge"));
        assert!(!output_contracts.contains("graph.path"));
        assert_eq!(manifest.plugin_type, PluginType::Graph);
        assert_eq!(manifest.statefulness, PluginStatefulness::Checkpointed);
        assert!(manifest.required_permissions.iter().any(|permission| {
            permission.permission.as_str() == "write.graph.update"
                && permission.category == PermissionCategory::DataAccess
        }));
        assert!(manifest.required_permissions.iter().any(|permission| {
            permission.permission.as_str() == "write.graph.canonical"
                && permission.category == PermissionCategory::DataAccess
        }));
        assert!(manifest
            .required_permissions
            .iter()
            .all(|permission| !permission.permission.as_str().contains("graph.path")));
        assert!(manifest
            .required_permissions
            .iter()
            .all(|permission| !permission.permission.as_str().contains("response")));
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
}
