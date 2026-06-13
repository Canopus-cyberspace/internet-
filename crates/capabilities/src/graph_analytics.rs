use sentinel_contracts::{
    CanonicalGraphEdge, CanonicalGraphNode, EntityId, EntityType, EvidenceId, GraphBadge,
    GraphBadgeTone, GraphContractError, GraphDetailRef, GraphEdgeId, GraphEdgeType,
    GraphEdgeViewModel, GraphFilterModel, GraphLayoutMode, GraphNodeId, GraphNodeStatus,
    GraphNodeType, GraphNodeViewModel, GraphPath, GraphPathSummary, GraphPathType,
    GraphPositionHint, GraphRedactionSummary, GraphScope, GraphSnapshot, GraphType, GraphViewModel,
    PageRequest, PrivacyClass, QualityScore, QueryRequest, QueryScope, RedactedLabel,
    RedactionStatus, TimeRange, Timestamp, DEFAULT_GRAPH_VIEW_EDGE_LIMIT,
    DEFAULT_GRAPH_VIEW_NODE_LIMIT, MAX_EXPORT_GRAPH_EVIDENCE_REFS, MAX_EXPORT_GRAPH_PATH_SUMMARIES,
    MAX_EXPORT_GRAPH_REDACTION_NOTES, MAX_PAGE_LIMIT,
};
use sentinel_storage::{GraphStore, LogicalStore, StorageError};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use uuid::Uuid;

const GRAPH_EXPANSION_CURSOR: &str = "graph_analytics:v1:expand";
const MAX_GRAPH_PATHS: usize = MAX_EXPORT_GRAPH_PATH_SUMMARIES;
const DEFAULT_CANONICAL_GRAPH_NODE_READ_LIMIT: u32 = DEFAULT_GRAPH_VIEW_NODE_LIMIT * 2;
const DEFAULT_CANONICAL_GRAPH_EDGE_READ_LIMIT: u32 = DEFAULT_GRAPH_VIEW_EDGE_LIMIT * 2;
const MAX_CANONICAL_GRAPH_NODE_READ_LIMIT: u32 = 10_000;
const MAX_CANONICAL_GRAPH_EDGE_READ_LIMIT: u32 = 20_000;
const MAX_CANONICAL_GRAPH_OFFSET: u32 = 10_000;
const DEFAULT_GRAPH_NEIGHBORHOOD_DEPTH: u8 = 4;
pub const DEFAULT_GRAPH_PATH_MAX_DEPTH: u8 = 6;
const MAX_GRAPH_PATH_MAX_DEPTH: u8 = 6;
const MAX_SHORTEST_GRAPH_PATHS: u8 = 3;
const MAX_GRAPH_PATH_SEARCH_STATES: usize = 4_096;

#[derive(Debug)]
pub enum GraphAnalyticsError {
    EmptyCanonicalGraph,
    EmptyField(&'static str),
    InvalidRequest(&'static str),
    PrivacyMarker { field: &'static str },
    Graph(GraphContractError),
    Storage(Box<StorageError>),
    Serialization(serde_json::Error),
}

impl fmt::Display for GraphAnalyticsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCanonicalGraph => write!(f, "canonical graph input is empty"),
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::InvalidRequest(reason) => write!(f, "invalid graph analytics request: {reason}"),
            Self::PrivacyMarker { field } => {
                write!(f, "{field} contains a forbidden sensitive marker")
            }
            Self::Graph(error) => write!(f, "{error}"),
            Self::Storage(error) => write!(f, "{error}"),
            Self::Serialization(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for GraphAnalyticsError {}

impl From<GraphContractError> for GraphAnalyticsError {
    fn from(value: GraphContractError) -> Self {
        Self::Graph(value)
    }
}

impl From<StorageError> for GraphAnalyticsError {
    fn from(value: StorageError) -> Self {
        Self::Storage(Box::new(value))
    }
}

impl From<serde_json::Error> for GraphAnalyticsError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphAnalyticsRequest {
    pub graph_type: GraphType,
    pub scope: GraphScope,
    pub time_bounds: Option<TimeRange>,
    pub node_limit: Option<u32>,
    pub edge_limit: Option<u32>,
    pub min_confidence: Option<QualityScore>,
    pub focus_node: Option<GraphNodeId>,
    pub include_suppressed: bool,
}

impl GraphAnalyticsRequest {
    pub fn new(graph_type: GraphType, scope: GraphScope) -> Self {
        Self {
            graph_type,
            scope,
            time_bounds: None,
            node_limit: None,
            edge_limit: None,
            min_confidence: None,
            focus_node: None,
            include_suppressed: false,
        }
    }

    pub fn with_bounds(mut self, node_limit: u32, edge_limit: u32) -> Self {
        self.node_limit = Some(node_limit);
        self.edge_limit = Some(edge_limit);
        self
    }

    pub fn with_time_bounds(mut self, time_bounds: TimeRange) -> Self {
        self.time_bounds = Some(time_bounds);
        self
    }

    fn validated(&self) -> Result<Self, GraphAnalyticsError> {
        if let Some(time_bounds) = &self.time_bounds {
            time_bounds
                .validate()
                .map_err(|_| GraphAnalyticsError::InvalidRequest("time range is invalid"))?;
        }
        Ok(Self {
            node_limit: Some(clamped_limit(
                self.node_limit,
                DEFAULT_GRAPH_VIEW_NODE_LIMIT,
            )),
            edge_limit: Some(clamped_limit(
                self.edge_limit,
                DEFAULT_GRAPH_VIEW_EDGE_LIMIT,
            )),
            ..self.clone()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphAnalyticsInput {
    pub request: GraphAnalyticsRequest,
    pub nodes: Vec<CanonicalGraphNode>,
    pub edges: Vec<CanonicalGraphEdge>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphAnalyticsOutput {
    pub paths: Vec<GraphPath>,
    pub view_model: GraphViewModel,
    pub snapshot: GraphSnapshot,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CanonicalGraphReadRequest {
    pub node_types: Vec<GraphNodeType>,
    pub edge_types: Vec<GraphEdgeType>,
    pub time_bounds: Option<TimeRange>,
    pub focus_node: Option<GraphNodeId>,
    pub neighborhood_depth: Option<u8>,
    pub node_limit: Option<u32>,
    pub edge_limit: Option<u32>,
    pub offset: Option<u32>,
}

impl CanonicalGraphReadRequest {
    pub fn from_analytics_request(request: &GraphAnalyticsRequest) -> Self {
        Self {
            time_bounds: request.time_bounds.clone(),
            focus_node: request.focus_node.clone(),
            node_limit: Some(DEFAULT_CANONICAL_GRAPH_NODE_READ_LIMIT),
            edge_limit: Some(DEFAULT_CANONICAL_GRAPH_EDGE_READ_LIMIT),
            ..Self::default()
        }
    }

    pub fn with_node_types(mut self, node_types: Vec<GraphNodeType>) -> Self {
        self.node_types = node_types;
        self
    }

    pub fn with_edge_types(mut self, edge_types: Vec<GraphEdgeType>) -> Self {
        self.edge_types = edge_types;
        self
    }

    pub fn with_bounds(mut self, node_limit: u32, edge_limit: u32, offset: u32) -> Self {
        self.node_limit = Some(node_limit);
        self.edge_limit = Some(edge_limit);
        self.offset = Some(offset);
        self
    }

    pub fn with_focus(mut self, focus_node: GraphNodeId, neighborhood_depth: u8) -> Self {
        self.focus_node = Some(focus_node);
        self.neighborhood_depth = Some(neighborhood_depth);
        self
    }

    fn validated(&self) -> Result<Self, GraphAnalyticsError> {
        if let Some(time_bounds) = &self.time_bounds {
            time_bounds
                .validate()
                .map_err(|_| GraphAnalyticsError::InvalidRequest("time range is invalid"))?;
        }
        Ok(Self {
            node_limit: Some(clamped_read_limit(
                self.node_limit,
                DEFAULT_CANONICAL_GRAPH_NODE_READ_LIMIT,
                MAX_CANONICAL_GRAPH_NODE_READ_LIMIT,
            )),
            edge_limit: Some(clamped_read_limit(
                self.edge_limit,
                DEFAULT_CANONICAL_GRAPH_EDGE_READ_LIMIT,
                MAX_CANONICAL_GRAPH_EDGE_READ_LIMIT,
            )),
            offset: Some(self.offset.unwrap_or(0).min(MAX_CANONICAL_GRAPH_OFFSET)),
            neighborhood_depth: Some(
                self.neighborhood_depth
                    .unwrap_or(DEFAULT_GRAPH_NEIGHBORHOOD_DEPTH)
                    .clamp(1, MAX_GRAPH_PATH_MAX_DEPTH),
            ),
            ..self.clone()
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CanonicalGraphReadResult {
    pub nodes: Vec<CanonicalGraphNode>,
    pub edges: Vec<CanonicalGraphEdge>,
    pub node_truncated: bool,
    pub edge_truncated: bool,
}

impl CanonicalGraphReadResult {
    pub fn truncated(&self) -> bool {
        self.node_truncated || self.edge_truncated
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphPathRequest {
    pub source_node: GraphNodeId,
    pub target_node: GraphNodeId,
    pub max_depth: Option<u8>,
    pub max_paths: Option<u8>,
}

impl GraphPathRequest {
    pub fn new(source_node: GraphNodeId, target_node: GraphNodeId) -> Self {
        Self {
            source_node,
            target_node,
            max_depth: None,
            max_paths: None,
        }
    }

    fn validated(&self) -> Self {
        Self {
            max_depth: Some(
                self.max_depth
                    .unwrap_or(DEFAULT_GRAPH_PATH_MAX_DEPTH)
                    .clamp(1, MAX_GRAPH_PATH_MAX_DEPTH),
            ),
            max_paths: Some(
                self.max_paths
                    .unwrap_or(MAX_SHORTEST_GRAPH_PATHS)
                    .clamp(1, MAX_SHORTEST_GRAPH_PATHS),
            ),
            ..self.clone()
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GraphPathComputation {
    pub paths: Vec<GraphPath>,
    pub truncated: bool,
    pub explored_node_count: u32,
    pub explored_edge_count: u32,
}

#[derive(Clone, Debug, Default)]
pub struct GraphAnalyticsService {
    reader: CanonicalGraphReader,
    path_computer: GraphPathComputer,
    incident_subgraph_builder: IncidentSubgraphBuilder,
    c2_path_builder: C2PathBuilder,
    exfiltration_path_builder: ExfiltrationPathBuilder,
    asset_exposure_path_builder: AssetExposurePathBuilder,
    incident_summary_path_builder: IncidentSummaryPathBuilder,
    view_model_builder: GraphViewModelBuilder,
    snapshot_builder: GraphSnapshotBuilder,
    redactor: GraphViewRedactor,
}

impl GraphAnalyticsService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn analyze(
        &self,
        input: GraphAnalyticsInput,
    ) -> Result<GraphAnalyticsOutput, GraphAnalyticsError> {
        let request = input.request.validated()?;
        if input.nodes.is_empty() {
            return Err(GraphAnalyticsError::EmptyCanonicalGraph);
        }
        let subgraph =
            self.incident_subgraph_builder
                .build(&input.nodes, &input.edges, &request)?;
        let paths = self.build_paths(&subgraph, &request)?;
        let view_model =
            self.view_model_builder
                .build(&request, &subgraph, &paths, &self.redactor)?;
        let snapshot = self
            .snapshot_builder
            .build(&request, &view_model, &self.redactor)?;

        Ok(GraphAnalyticsOutput {
            paths,
            view_model,
            snapshot,
        })
    }

    pub fn analyze_store<G>(
        &self,
        graph_store: &G,
        request: GraphAnalyticsRequest,
    ) -> Result<GraphAnalyticsOutput, GraphAnalyticsError>
    where
        G: GraphStore,
    {
        let request = request.validated()?;
        let canonical = self.reader.read(
            graph_store,
            CanonicalGraphReadRequest::from_analytics_request(&request),
        )?;

        self.analyze(GraphAnalyticsInput {
            request,
            nodes: canonical.nodes,
            edges: canonical.edges,
        })
    }

    pub fn read_canonical_graph<G>(
        &self,
        graph_store: &G,
        request: CanonicalGraphReadRequest,
    ) -> Result<CanonicalGraphReadResult, GraphAnalyticsError>
    where
        G: GraphStore,
    {
        self.reader.read(graph_store, request)
    }

    pub fn compute_bounded_paths(
        &self,
        nodes: &[CanonicalGraphNode],
        edges: &[CanonicalGraphEdge],
        request: GraphPathRequest,
    ) -> Result<GraphPathComputation, GraphAnalyticsError> {
        self.path_computer.compute(nodes, edges, request)
    }

    fn build_paths(
        &self,
        subgraph: &GraphSubgraph,
        request: &GraphAnalyticsRequest,
    ) -> Result<Vec<GraphPath>, GraphAnalyticsError> {
        let mut paths = match request.graph_type {
            GraphType::C2Graph => self.c2_path_builder.build(subgraph)?,
            GraphType::ExfiltrationGraph => self.exfiltration_path_builder.build(subgraph)?,
            GraphType::AssetExposureGraph => self.asset_exposure_path_builder.build(subgraph)?,
            GraphType::IncidentGraph | GraphType::OverviewRiskMap => {
                let mut combined = self.c2_path_builder.build(subgraph)?;
                combined.extend(self.exfiltration_path_builder.build(subgraph)?);
                combined.extend(self.asset_exposure_path_builder.build(subgraph)?);
                combined.extend(self.incident_summary_path_builder.build(subgraph)?);
                combined
            }
            _ => self.incident_summary_path_builder.build(subgraph)?,
        };
        paths.truncate(MAX_GRAPH_PATHS);
        Ok(deduplicate_paths(paths))
    }
}

#[derive(Clone, Debug, Default)]
pub struct CanonicalGraphReader;

impl CanonicalGraphReader {
    pub fn new() -> Self {
        Self
    }

    pub fn read<G>(
        &self,
        graph_store: &G,
        request: CanonicalGraphReadRequest,
    ) -> Result<CanonicalGraphReadResult, GraphAnalyticsError>
    where
        G: GraphStore,
    {
        let request = request.validated()?;
        let node_types = request.node_types.clone();
        let edge_types = request.edge_types.clone();
        let node_result = read_filtered_store_metadata::<_, CanonicalGraphNode, _>(
            graph_store.nodes(),
            request.node_limit.expect("validated node limit"),
            request.offset.expect("validated offset"),
            &request.time_bounds,
            |node| {
                (node_types.is_empty() || node_types.contains(&node.node_type))
                    && timestamp_in_range(&node.last_seen, &request.time_bounds)
            },
        )?;
        let edge_result = read_filtered_store_metadata::<_, CanonicalGraphEdge, _>(
            graph_store.edges(),
            request.edge_limit.expect("validated edge limit"),
            request.offset.expect("validated offset"),
            &request.time_bounds,
            |edge| {
                (edge_types.is_empty() || edge_types.contains(&edge.edge_type))
                    && timestamp_in_range(&edge.last_seen, &request.time_bounds)
            },
        )?;

        let mut result = CanonicalGraphReadResult {
            nodes: node_result.items,
            edges: edge_result.items,
            node_truncated: node_result.truncated,
            edge_truncated: edge_result.truncated,
        };

        if let Some(focus_node) = request.focus_node {
            let node_truncated = result.node_truncated;
            let edge_truncated = result.edge_truncated;
            let subgraph = GraphSubgraph::new(result.nodes, result.edges).neighborhood(
                &[focus_node],
                request.neighborhood_depth.expect("validated depth") as usize,
            );
            let edges = retain_edges_with_known_nodes(&subgraph.nodes, &subgraph.edges);
            result = CanonicalGraphReadResult {
                nodes: subgraph.nodes,
                edges,
                node_truncated,
                edge_truncated,
            };
        }

        Ok(result)
    }
}

#[derive(Clone, Debug, Default)]
pub struct GraphPathComputer;

impl GraphPathComputer {
    pub fn new() -> Self {
        Self
    }

    pub fn compute(
        &self,
        nodes: &[CanonicalGraphNode],
        edges: &[CanonicalGraphEdge],
        request: GraphPathRequest,
    ) -> Result<GraphPathComputation, GraphAnalyticsError> {
        let request = request.validated();
        let index = GraphIndex::new(nodes, edges);
        if !index.nodes.contains_key(&request.source_node)
            || !index.nodes.contains_key(&request.target_node)
        {
            return Ok(GraphPathComputation::default());
        }
        if request.source_node == request.target_node {
            return Ok(GraphPathComputation {
                paths: vec![path_from_sequence(
                    GraphPathType::Custom("bounded_shortest_path".to_string()),
                    vec![request.source_node],
                    Vec::new(),
                    "bounded shortest graph path",
                    &index,
                )?],
                truncated: false,
                explored_node_count: 1,
                explored_edge_count: 0,
            });
        }

        let max_depth = request.max_depth.expect("validated depth") as usize;
        let max_paths = request.max_paths.expect("validated path count") as usize;
        let mut queue = VecDeque::new();
        let mut found = Vec::new();
        let mut explored_states = 0_usize;
        let mut explored_edges = HashSet::new();
        let mut explored_nodes = HashSet::new();
        queue.push_back(PathSearchState {
            current: request.source_node.clone(),
            node_sequence: vec![request.source_node.clone()],
            edge_sequence: Vec::new(),
        });

        while let Some(state) = queue.pop_front() {
            explored_states += 1;
            explored_nodes.insert(state.current.clone());
            if explored_states > MAX_GRAPH_PATH_SEARCH_STATES {
                break;
            }
            if state.edge_sequence.len() >= max_depth {
                continue;
            }
            let mut outgoing = index.outgoing(&state.current).to_vec();
            outgoing.sort_by_key(|edge| edge.edge_id.to_string());
            for edge in outgoing {
                explored_edges.insert(edge.edge_id.clone());
                if state.node_sequence.contains(&edge.target_node) {
                    continue;
                }
                let mut next_nodes = state.node_sequence.clone();
                next_nodes.push(edge.target_node.clone());
                let mut next_edges = state.edge_sequence.clone();
                next_edges.push(edge.edge_id.clone());
                if edge.target_node == request.target_node {
                    found.push(path_from_sequence(
                        GraphPathType::Custom("bounded_shortest_path".to_string()),
                        next_nodes,
                        next_edges,
                        "bounded shortest graph path",
                        &index,
                    )?);
                    if found.len() >= max_paths {
                        return Ok(GraphPathComputation {
                            paths: deduplicate_paths(found),
                            truncated: !queue.is_empty(),
                            explored_node_count: explored_nodes.len() as u32,
                            explored_edge_count: explored_edges.len() as u32,
                        });
                    }
                } else {
                    queue.push_back(PathSearchState {
                        current: edge.target_node.clone(),
                        node_sequence: next_nodes,
                        edge_sequence: next_edges,
                    });
                }
            }
        }

        Ok(GraphPathComputation {
            paths: deduplicate_paths(found),
            truncated: !queue.is_empty() || explored_states > MAX_GRAPH_PATH_SEARCH_STATES,
            explored_node_count: explored_nodes.len() as u32,
            explored_edge_count: explored_edges.len() as u32,
        })
    }
}

#[derive(Clone, Debug)]
struct PathSearchState {
    current: GraphNodeId,
    node_sequence: Vec<GraphNodeId>,
    edge_sequence: Vec<GraphEdgeId>,
}

struct StoreMetadataRead<TRecord> {
    items: Vec<TRecord>,
    truncated: bool,
}

fn read_filtered_store_metadata<TId, TRecord, TStore>(
    store: &TStore,
    limit: u32,
    offset: u32,
    time_bounds: &Option<TimeRange>,
    mut include: impl FnMut(&TRecord) -> bool,
) -> Result<StoreMetadataRead<TRecord>, GraphAnalyticsError>
where
    TRecord: DeserializeOwned,
    TStore: LogicalStore<TId>,
{
    let target_count = (offset as usize)
        .saturating_add(limit as usize)
        .saturating_add(1);
    let mut selected = Vec::new();
    let mut cursor = None;
    let mut store_had_more = false;
    while selected.len() < target_count {
        let remaining = (target_count - selected.len()) as u32;
        let page_limit = remaining.clamp(1, MAX_PAGE_LIMIT);
        let page = PageRequest::new(page_limit, cursor).map_err(|_| {
            GraphAnalyticsError::InvalidRequest("graph store page limit is invalid")
        })?;
        let mut query = QueryRequest::new(QueryScope::Global).with_page(page);
        if let Some(bounds) = time_bounds {
            query = query.with_time_range(bounds.clone());
        }
        let response = store.query(query)?;
        for record in response.page.items {
            let item = serde_json::from_value::<TRecord>(record.metadata)?;
            if include(&item) {
                selected.push(item);
            }
            if selected.len() >= target_count {
                break;
            }
        }
        store_had_more = response.page.has_more;
        if !response.page.has_more {
            break;
        }
        cursor = response.page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    let skip = offset as usize;
    let take = limit as usize;
    let truncated = selected.len() > skip.saturating_add(take) || store_had_more;
    let items = selected.into_iter().skip(skip).take(take).collect();
    Ok(StoreMetadataRead { items, truncated })
}

fn retain_edges_with_known_nodes(
    nodes: &[CanonicalGraphNode],
    edges: &[CanonicalGraphEdge],
) -> Vec<CanonicalGraphEdge> {
    let node_ids = nodes
        .iter()
        .map(|node| node.node_id.clone())
        .collect::<HashSet<_>>();
    edges
        .iter()
        .filter(|edge| node_ids.contains(&edge.source_node) && node_ids.contains(&edge.target_node))
        .cloned()
        .collect()
}

#[derive(Clone, Debug, Default)]
pub struct IncidentSubgraphBuilder;

impl IncidentSubgraphBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        nodes: &[CanonicalGraphNode],
        edges: &[CanonicalGraphEdge],
        request: &GraphAnalyticsRequest,
    ) -> Result<GraphSubgraph, GraphAnalyticsError> {
        let filtered_nodes = nodes
            .iter()
            .filter(|node| timestamp_in_range(&node.last_seen, &request.time_bounds))
            .filter(|node| {
                request
                    .min_confidence
                    .as_ref()
                    .is_none_or(|minimum| node.confidence.value() >= minimum.value())
            })
            .cloned()
            .collect::<Vec<_>>();
        let node_ids = filtered_nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect::<HashSet<_>>();
        let filtered_edges = edges
            .iter()
            .filter(|edge| {
                node_ids.contains(&edge.source_node) && node_ids.contains(&edge.target_node)
            })
            .filter(|edge| timestamp_in_range(&edge.last_seen, &request.time_bounds))
            .filter(|edge| {
                request
                    .min_confidence
                    .as_ref()
                    .is_none_or(|minimum| edge.confidence.value() >= minimum.value())
            })
            .cloned()
            .collect::<Vec<_>>();
        let subgraph = GraphSubgraph::new(filtered_nodes, filtered_edges);
        if let Some(focus_node) = &request.focus_node {
            if !subgraph
                .nodes
                .iter()
                .any(|node| &node.node_id == focus_node)
            {
                return Ok(GraphSubgraph::new(Vec::new(), Vec::new()));
            }
            return Ok(subgraph.neighborhood(
                std::slice::from_ref(focus_node),
                DEFAULT_GRAPH_NEIGHBORHOOD_DEPTH as usize,
            ));
        }
        let Some(start_nodes) = start_nodes_for_scope(&subgraph, &request.scope) else {
            return Ok(subgraph);
        };
        if start_nodes.is_empty() {
            return Ok(GraphSubgraph::new(Vec::new(), Vec::new()));
        }
        Ok(subgraph.neighborhood(&start_nodes, 4))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphSubgraph {
    pub nodes: Vec<CanonicalGraphNode>,
    pub edges: Vec<CanonicalGraphEdge>,
}

impl GraphSubgraph {
    fn new(nodes: Vec<CanonicalGraphNode>, edges: Vec<CanonicalGraphEdge>) -> Self {
        Self { nodes, edges }
    }

    fn index(&self) -> GraphIndex {
        GraphIndex::new(&self.nodes, &self.edges)
    }

    fn neighborhood(&self, start_nodes: &[GraphNodeId], max_depth: usize) -> Self {
        let mut visited = HashSet::new();
        let mut selected_edges = HashSet::new();
        let mut queue = VecDeque::new();
        for node_id in start_nodes {
            visited.insert(node_id.clone());
            queue.push_back((node_id.clone(), 0_usize));
        }
        while let Some((node_id, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            for edge in self
                .edges
                .iter()
                .filter(|edge| edge.source_node == node_id || edge.target_node == node_id)
            {
                selected_edges.insert(edge.edge_id.clone());
                for next in [&edge.source_node, &edge.target_node] {
                    if visited.insert(next.clone()) {
                        queue.push_back((next.clone(), depth + 1));
                    }
                }
            }
        }
        let nodes = self
            .nodes
            .iter()
            .filter(|node| visited.contains(&node.node_id))
            .cloned()
            .collect::<Vec<_>>();
        let edges = self
            .edges
            .iter()
            .filter(|edge| selected_edges.contains(&edge.edge_id))
            .cloned()
            .collect::<Vec<_>>();
        Self::new(nodes, edges)
    }
}

#[derive(Clone, Debug, Default)]
pub struct C2PathBuilder;

impl C2PathBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(&self, subgraph: &GraphSubgraph) -> Result<Vec<GraphPath>, GraphAnalyticsError> {
        let index = subgraph.index();
        let mut paths = Vec::new();
        for edge in &subgraph.edges {
            if !matches!(
                edge.edge_type,
                GraphEdgeType::ProcessQueriesDomain | GraphEdgeType::ProcessConnectsToIp
            ) {
                continue;
            }
            if !index.node_is_type(&edge.source_node, GraphNodeType::Process) {
                continue;
            }
            let mut node_sequence = vec![edge.source_node.clone(), edge.target_node.clone()];
            let mut edge_sequence = vec![edge.edge_id.clone()];
            extend_destination_context(&index, &mut node_sequence, &mut edge_sequence);
            extend_to_lifecycle(&index, &mut node_sequence, &mut edge_sequence);
            paths.push(path_from_sequence(
                GraphPathType::ProcessToC2Path,
                node_sequence,
                edge_sequence,
                "process to C2 path",
                &index,
            )?);
        }
        Ok(deduplicate_paths(paths))
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExfiltrationPathBuilder;

impl ExfiltrationPathBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(&self, subgraph: &GraphSubgraph) -> Result<Vec<GraphPath>, GraphAnalyticsError> {
        let index = subgraph.index();
        let mut paths = Vec::new();
        for edge in &subgraph.edges {
            if edge.edge_type != GraphEdgeType::ProcessUploadsToCloud {
                continue;
            }
            if !index.node_is_type(&edge.source_node, GraphNodeType::Process) {
                continue;
            }
            let mut node_sequence = vec![edge.source_node.clone(), edge.target_node.clone()];
            let mut edge_sequence = vec![edge.edge_id.clone()];
            extend_to_lifecycle(&index, &mut node_sequence, &mut edge_sequence);
            paths.push(path_from_sequence(
                GraphPathType::ProcessToCloudUploadPath,
                node_sequence,
                edge_sequence,
                "process to cloud upload path",
                &index,
            )?);
        }
        Ok(deduplicate_paths(paths))
    }
}

#[derive(Clone, Debug, Default)]
pub struct AssetExposurePathBuilder;

impl AssetExposurePathBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(&self, subgraph: &GraphSubgraph) -> Result<Vec<GraphPath>, GraphAnalyticsError> {
        let index = subgraph.index();
        let mut paths = Vec::new();
        for edge in &subgraph.edges {
            if edge.edge_type != GraphEdgeType::ProcessListensOnPort {
                continue;
            }
            if !index.node_is_type(&edge.source_node, GraphNodeType::Process) {
                continue;
            }
            let mut node_sequence = vec![edge.source_node.clone(), edge.target_node.clone()];
            let mut edge_sequence = vec![edge.edge_id.clone()];
            extend_to_lifecycle(&index, &mut node_sequence, &mut edge_sequence);
            paths.push(path_from_sequence(
                GraphPathType::LocalAssetExposurePath,
                node_sequence,
                edge_sequence,
                "local asset exposure path",
                &index,
            )?);
        }
        Ok(deduplicate_paths(paths))
    }
}

#[derive(Clone, Debug, Default)]
pub struct IncidentSummaryPathBuilder;

impl IncidentSummaryPathBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(&self, subgraph: &GraphSubgraph) -> Result<Vec<GraphPath>, GraphAnalyticsError> {
        let index = subgraph.index();
        let mut paths = Vec::new();
        for finding_edge in &subgraph.edges {
            if finding_edge.edge_type != GraphEdgeType::FindingSupportsAlert {
                continue;
            }
            let Some(incident_edge) = index
                .outgoing(&finding_edge.target_node)
                .iter()
                .find(|edge| edge.edge_type == GraphEdgeType::AlertPartOfIncident)
            else {
                continue;
            };
            paths.push(path_from_sequence(
                GraphPathType::IncidentSummaryPath,
                vec![
                    finding_edge.source_node.clone(),
                    finding_edge.target_node.clone(),
                    incident_edge.target_node.clone(),
                ],
                vec![finding_edge.edge_id.clone(), incident_edge.edge_id.clone()],
                "incident summary path",
                &index,
            )?);
        }
        Ok(deduplicate_paths(paths))
    }
}

#[derive(Clone, Debug, Default)]
pub struct GraphViewModelBuilder;

impl GraphViewModelBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        request: &GraphAnalyticsRequest,
        subgraph: &GraphSubgraph,
        paths: &[GraphPath],
        redactor: &GraphViewRedactor,
    ) -> Result<GraphViewModel, GraphAnalyticsError> {
        let title = RedactedLabel::redacted(
            default_graph_title(&request.graph_type),
            PrivacyClass::Internal,
        )?;
        let node_limit = request.node_limit.unwrap_or(DEFAULT_GRAPH_VIEW_NODE_LIMIT);
        let edge_limit = request.edge_limit.unwrap_or(DEFAULT_GRAPH_VIEW_EDGE_LIMIT);
        let mut view =
            GraphViewModel::new(request.graph_type.clone(), title, request.scope.clone())
                .with_bounds(node_limit, edge_limit);

        let mut nodes = subgraph.nodes.clone();
        nodes.sort_by_key(|node| node.node_id.to_string());
        let original_node_count = nodes.len() as u32;
        let visible_nodes = nodes
            .into_iter()
            .take(node_limit as usize)
            .collect::<Vec<_>>();
        let visible_node_ids = visible_nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect::<HashSet<_>>();
        let mut edges = subgraph
            .edges
            .iter()
            .filter(|edge| {
                visible_node_ids.contains(&edge.source_node)
                    && visible_node_ids.contains(&edge.target_node)
            })
            .cloned()
            .collect::<Vec<_>>();
        edges.sort_by_key(|edge| edge.edge_id.to_string());
        let original_edge_count = subgraph.edges.len() as u32;
        let visible_edges = edges
            .into_iter()
            .take(edge_limit as usize)
            .collect::<Vec<_>>();

        view.nodes = visible_nodes
            .iter()
            .enumerate()
            .map(|(index, node)| redactor.node_view_model(node, index))
            .collect::<Result<Vec<_>, _>>()?;
        view.edges = visible_edges
            .iter()
            .map(|edge| redactor.edge_view_model(edge))
            .collect::<Result<Vec<_>, _>>()?;
        let mut visible_paths = paths
            .iter()
            .filter(|path| {
                path.node_sequence
                    .iter()
                    .all(|node_id| visible_node_ids.contains(node_id))
            })
            .collect::<Vec<_>>();
        visible_paths.sort_by(|left, right| path_sort_key(left, right));
        view.paths = visible_paths
            .into_iter()
            .map(path_summary)
            .collect::<Vec<_>>();
        view.legend = build_legend(&view.nodes, &view.edges)?;
        view.filters = filter_model(request, &view.nodes, &view.edges);
        view.layout.mode = match request.graph_type {
            GraphType::IncidentGraph
            | GraphType::C2Graph
            | GraphType::ExfiltrationGraph
            | GraphType::AssetExposureGraph => GraphLayoutMode::Hierarchical,
            _ => GraphLayoutMode::Auto,
        };
        view.redaction_status = RedactionStatus::Redacted;
        view.redaction_summary = redactor.redaction_summary(&visible_nodes, &visible_edges);
        if original_node_count > view.nodes.len() as u32
            || original_edge_count > view.edges.len() as u32
        {
            view = view.mark_truncated(
                original_node_count,
                original_edge_count,
                "graph view bounded for frontend safety",
            )?;
            view.expansion.expansion_cursor = Some(GRAPH_EXPANSION_CURSOR.to_string());
        } else {
            view.original_node_count = original_node_count;
            view.original_edge_count = original_edge_count;
        }
        view.expansion.lazy_expansion_available = view.truncated;
        view.expansion.focus_mode_available = true;
        view.expansion.filtering_available = true;
        view.graph_id = deterministic_graph_view_id(&view)?;
        Ok(view)
    }
}

#[derive(Clone, Debug, Default)]
pub struct GraphSnapshotBuilder;

impl GraphSnapshotBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        request: &GraphAnalyticsRequest,
        view: &GraphViewModel,
        redactor: &GraphViewRedactor,
    ) -> Result<GraphSnapshot, GraphAnalyticsError> {
        let mut snapshot = GraphSnapshot::new(request.graph_type.clone(), request.scope.clone());
        snapshot.time_bounds = request.time_bounds.clone();
        snapshot.selected_nodes = view
            .nodes
            .iter()
            .map(export_safe_node_view_model)
            .collect::<Result<Vec<_>, _>>()?;
        snapshot.selected_edges = view
            .edges
            .iter()
            .map(export_safe_edge_view_model)
            .collect::<Result<Vec<_>, _>>()?;
        snapshot.path_summaries = view
            .paths
            .iter()
            .map(export_safe_path_summary)
            .collect::<Result<Vec<_>, _>>()?;
        snapshot.node_count = snapshot.selected_nodes.len() as u32;
        snapshot.edge_count = snapshot.selected_edges.len() as u32;
        snapshot.path_count = snapshot.path_summaries.len() as u32;
        snapshot.risk_score = max_quality(
            snapshot
                .selected_nodes
                .iter()
                .map(|node| node.risk_score.clone())
                .chain(
                    snapshot
                        .path_summaries
                        .iter()
                        .map(|path| path.risk_score.clone()),
                ),
        );
        snapshot.confidence = average_quality(
            snapshot
                .selected_edges
                .iter()
                .map(|edge| edge.confidence.clone())
                .chain(
                    snapshot
                        .path_summaries
                        .iter()
                        .map(|path| path.confidence.clone()),
                ),
        );
        snapshot.evidence_refs = bounded_evidence_refs(
            snapshot
                .selected_nodes
                .iter()
                .flat_map(|node| node.detail_ref.evidence_refs.iter().cloned())
                .chain(
                    snapshot
                        .selected_edges
                        .iter()
                        .flat_map(|edge| edge.evidence_refs.iter().cloned()),
                )
                .chain(
                    snapshot
                        .path_summaries
                        .iter()
                        .flat_map(|path| path.evidence_refs.iter().cloned()),
                ),
        );
        snapshot.redaction_status = RedactionStatus::Redacted;
        snapshot.redaction_summary = redactor.snapshot_redaction_summary(view)?;
        normalize_export_safe_graph_snapshot(
            &snapshot,
            "snapshot contains only redacted GraphViewModel fields",
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct GraphViewRedactor;

impl GraphViewRedactor {
    pub fn new() -> Self {
        Self
    }

    pub fn node_view_model(
        &self,
        node: &CanonicalGraphNode,
        index: usize,
    ) -> Result<GraphNodeViewModel, GraphAnalyticsError> {
        let mut view = GraphNodeViewModel::new(
            node.node_type.clone(),
            RedactedLabel::redacted(node_type_label(&node.node_type), PrivacyClass::Internal)?,
        );
        view.node_id = node.node_id.clone();
        view.risk_score = node.risk_score.clone();
        view.status = node_status(&node.risk_score);
        view.privacy_class = most_sensitive_privacy(&node.privacy_class, &PrivacyClass::Internal);
        view.detail_ref = detail_ref_for_node(node);
        view.tooltip = Some(RedactedLabel::redacted(
            "redacted graph entity",
            PrivacyClass::Internal,
        )?);
        if !node.source_refs.is_empty() {
            view.badges.push(GraphBadge {
                label: RedactedLabel::redacted("evidence-backed", PrivacyClass::Internal)?,
                tone: GraphBadgeTone::Info,
            });
        }
        view.position_hint = Some(GraphPositionHint {
            x: ((index % 8) as f32) * 160.0,
            y: ((index / 8) as f32) * 96.0,
        });
        Ok(view)
    }

    pub fn edge_view_model(
        &self,
        edge: &CanonicalGraphEdge,
    ) -> Result<GraphEdgeViewModel, GraphAnalyticsError> {
        let mut view = GraphEdgeViewModel::new(
            edge.edge_type.clone(),
            edge.source_node.clone(),
            edge.target_node.clone(),
        );
        view.edge_id = edge.edge_id.clone();
        view.label = Some(RedactedLabel::redacted(
            edge_type_label(&edge.edge_type),
            PrivacyClass::Internal,
        )?);
        view.confidence = edge.confidence.clone();
        view.evidence_refs = bounded_evidence_refs(edge.evidence_refs.iter().cloned());
        view.privacy_class = most_sensitive_privacy(&edge.privacy_class, &PrivacyClass::Internal);
        view.tooltip = Some(RedactedLabel::redacted(
            "redacted graph relationship",
            PrivacyClass::Internal,
        )?);
        Ok(view)
    }

    pub fn redaction_summary(
        &self,
        nodes: &[CanonicalGraphNode],
        edges: &[CanonicalGraphEdge],
    ) -> GraphRedactionSummary {
        GraphRedactionSummary {
            status: RedactionStatus::Redacted,
            redacted_node_count: nodes.len() as u32,
            redacted_edge_count: edges.len() as u32,
            hidden_label_count: (nodes.len() + edges.len()) as u32,
            notes: vec!["canonical graph labels redacted for view model".to_string()],
        }
    }

    pub fn snapshot_redaction_summary(
        &self,
        view: &GraphViewModel,
    ) -> Result<GraphRedactionSummary, GraphAnalyticsError> {
        validate_graph_view_safety(view)?;
        Ok(GraphRedactionSummary {
            status: RedactionStatus::Redacted,
            redacted_node_count: view.nodes.len() as u32,
            redacted_edge_count: view.edges.len() as u32,
            hidden_label_count: (view.nodes.len() + view.edges.len()) as u32,
            notes: vec!["snapshot contains only redacted GraphViewModel fields".to_string()],
        })
    }
}

pub fn build_export_safe_graph_snapshot_from_view(
    view: &GraphViewModel,
    scope: GraphScope,
    fallback_evidence_refs: &[EvidenceId],
    default_note: &str,
) -> Result<Option<GraphSnapshot>, GraphAnalyticsError> {
    if view.nodes.is_empty() && view.edges.is_empty() && view.paths.is_empty() {
        return Ok(None);
    }

    let mut evidence_refs = graph_view_evidence_refs(view);
    for evidence_id in fallback_evidence_refs {
        push_unique_evidence_ref(&mut evidence_refs, evidence_id.clone());
    }
    if evidence_refs.is_empty() {
        return Ok(None);
    }

    let mut snapshot = GraphSnapshot::new(view.graph_type.clone(), scope);
    snapshot.time_bounds = Some(TimeRange::new(None, Some(Timestamp::now())).map_err(|_| {
        GraphAnalyticsError::InvalidRequest("graph export time bounds are invalid")
    })?);
    snapshot.selected_nodes = view
        .nodes
        .iter()
        .map(export_safe_node_view_model)
        .collect::<Result<Vec<_>, _>>()?;
    snapshot.selected_edges = view
        .edges
        .iter()
        .map(export_safe_edge_view_model)
        .collect::<Result<Vec<_>, _>>()?;
    snapshot.path_summaries = view
        .paths
        .iter()
        .map(export_safe_path_summary)
        .collect::<Result<Vec<_>, _>>()?;
    snapshot.node_count = snapshot.selected_nodes.len() as u32;
    snapshot.edge_count = snapshot.selected_edges.len() as u32;
    snapshot.path_count = snapshot.path_summaries.len() as u32;
    snapshot.risk_score = max_quality(
        snapshot
            .selected_nodes
            .iter()
            .map(|node| node.risk_score.clone())
            .chain(
                snapshot
                    .path_summaries
                    .iter()
                    .map(|path| path.risk_score.clone()),
            ),
    );
    snapshot.confidence = average_quality(
        snapshot
            .selected_edges
            .iter()
            .map(|edge| edge.confidence.clone())
            .chain(
                snapshot
                    .path_summaries
                    .iter()
                    .map(|path| path.confidence.clone()),
            ),
    );
    snapshot.evidence_refs = evidence_refs;
    snapshot.redaction_status = view.redaction_status.clone();
    snapshot.redaction_summary = GraphRedactionSummary {
        status: view.redaction_summary.status.clone(),
        redacted_node_count: snapshot.node_count,
        redacted_edge_count: snapshot.edge_count,
        hidden_label_count: snapshot.node_count.saturating_add(snapshot.edge_count),
        notes: bounded_redaction_notes(&view.redaction_summary.notes, default_note)?,
    };

    normalize_export_safe_graph_snapshot(&snapshot, default_note).map(Some)
}

pub fn normalize_export_safe_graph_snapshot(
    snapshot: &GraphSnapshot,
    default_note: &str,
) -> Result<GraphSnapshot, GraphAnalyticsError> {
    let mut normalized = snapshot.clone();
    normalized.selected_nodes = normalized
        .selected_nodes
        .iter()
        .map(normalize_export_safe_node_view_model)
        .collect::<Result<Vec<_>, _>>()?;
    normalized
        .selected_nodes
        .sort_by_key(|node| node.node_id.to_string());
    normalized.selected_edges = normalized
        .selected_edges
        .iter()
        .map(normalize_export_safe_edge_view_model)
        .collect::<Result<Vec<_>, _>>()?;
    normalized
        .selected_edges
        .sort_by_key(|edge| edge.edge_id.to_string());
    normalized.path_summaries = normalized
        .path_summaries
        .iter()
        .map(normalize_export_safe_path_summary)
        .collect::<Result<Vec<_>, _>>()?;
    normalized
        .path_summaries
        .sort_by_key(graph_path_summary_sort_key);
    normalized
        .path_summaries
        .truncate(MAX_EXPORT_GRAPH_PATH_SUMMARIES);
    normalized.node_count = normalized.selected_nodes.len() as u32;
    normalized.edge_count = normalized.selected_edges.len() as u32;
    normalized.path_count = normalized.path_summaries.len() as u32;
    normalized.evidence_refs = bounded_evidence_refs(
        normalized
            .evidence_refs
            .iter()
            .cloned()
            .chain(
                normalized
                    .selected_nodes
                    .iter()
                    .flat_map(|node| node.detail_ref.evidence_refs.iter().cloned()),
            )
            .chain(
                normalized
                    .selected_edges
                    .iter()
                    .flat_map(|edge| edge.evidence_refs.iter().cloned()),
            )
            .chain(
                normalized
                    .path_summaries
                    .iter()
                    .flat_map(|path| path.evidence_refs.iter().cloned()),
            ),
    );
    normalized.redaction_summary = GraphRedactionSummary {
        status: normalized.redaction_status.clone(),
        redacted_node_count: normalized.node_count,
        redacted_edge_count: normalized.edge_count,
        hidden_label_count: normalized.node_count.saturating_add(normalized.edge_count),
        notes: bounded_redaction_notes(&normalized.redaction_summary.notes, default_note)?,
    };
    normalized.snapshot_id = deterministic_graph_snapshot_id(&normalized)?;
    validate_graph_snapshot_safety(&normalized)?;
    Ok(normalized)
}

#[derive(Clone)]
struct GraphIndex {
    nodes: HashMap<GraphNodeId, CanonicalGraphNode>,
    edges: HashMap<GraphEdgeId, CanonicalGraphEdge>,
    outgoing: HashMap<GraphNodeId, Vec<CanonicalGraphEdge>>,
}

impl GraphIndex {
    fn new(nodes: &[CanonicalGraphNode], edges: &[CanonicalGraphEdge]) -> Self {
        let nodes = nodes
            .iter()
            .map(|node| (node.node_id.clone(), node.clone()))
            .collect::<HashMap<_, _>>();
        let edges_by_id = edges
            .iter()
            .map(|edge| (edge.edge_id.clone(), edge.clone()))
            .collect::<HashMap<_, _>>();
        let mut outgoing: HashMap<GraphNodeId, Vec<CanonicalGraphEdge>> = HashMap::new();
        for edge in edges {
            outgoing
                .entry(edge.source_node.clone())
                .or_default()
                .push(edge.clone());
        }
        Self {
            nodes,
            edges: edges_by_id,
            outgoing,
        }
    }

    fn node_is_type(&self, node_id: &GraphNodeId, node_type: GraphNodeType) -> bool {
        self.nodes
            .get(node_id)
            .is_some_and(|node| node.node_type == node_type)
    }

    fn outgoing(&self, node_id: &GraphNodeId) -> &[CanonicalGraphEdge] {
        self.outgoing.get(node_id).map(Vec::as_slice).unwrap_or(&[])
    }

    fn edge(&self, edge_id: &GraphEdgeId) -> Option<&CanonicalGraphEdge> {
        self.edges.get(edge_id)
    }

    fn node(&self, node_id: &GraphNodeId) -> Option<&CanonicalGraphNode> {
        self.nodes.get(node_id)
    }
}

fn start_nodes_for_scope(subgraph: &GraphSubgraph, scope: &GraphScope) -> Option<Vec<GraphNodeId>> {
    match scope {
        GraphScope::Overview => None,
        GraphScope::Incident(incident_id) => {
            let entity_id = EntityId::from_uuid(incident_id.as_uuid());
            Some(nodes_for_entity(
                subgraph,
                &entity_id,
                Some(&EntityType::Incident),
            ))
        }
        GraphScope::Alert(alert_id) => {
            let entity_id = EntityId::from_uuid(alert_id.as_uuid());
            Some(nodes_for_entity(
                subgraph,
                &entity_id,
                Some(&EntityType::Alert),
            ))
        }
        GraphScope::Finding(finding_id) => {
            let entity_id = EntityId::from_uuid(finding_id.as_uuid());
            Some(nodes_for_entity(
                subgraph,
                &entity_id,
                Some(&EntityType::Finding),
            ))
        }
        GraphScope::Entity(entity_id) => Some(nodes_for_entity(subgraph, entity_id, None)),
        _ => None,
    }
}

fn nodes_for_entity(
    subgraph: &GraphSubgraph,
    entity_id: &EntityId,
    entity_type: Option<&EntityType>,
) -> Vec<GraphNodeId> {
    subgraph
        .nodes
        .iter()
        .filter(|node| {
            node.entity_ref.as_ref().is_some_and(|entity_ref| {
                entity_ref.entity_id == *entity_id
                    && entity_type.is_none_or(|expected| &entity_ref.entity_type == expected)
            })
        })
        .map(|node| node.node_id.clone())
        .collect()
}

fn extend_destination_context(
    index: &GraphIndex,
    node_sequence: &mut Vec<GraphNodeId>,
    edge_sequence: &mut Vec<GraphEdgeId>,
) {
    let Some(current) = node_sequence.last().cloned() else {
        return;
    };
    let next_edge = index.outgoing(&current).iter().find(|edge| {
        matches!(
            edge.edge_type,
            GraphEdgeType::DomainResolvesToIp
                | GraphEdgeType::IpBelongsToAsn
                | GraphEdgeType::IpBelongsToCloudProvider
        )
    });
    if let Some(edge) = next_edge {
        push_node_edge(node_sequence, edge_sequence, edge);
        extend_destination_context(index, node_sequence, edge_sequence);
    }
}

fn extend_to_lifecycle(
    index: &GraphIndex,
    node_sequence: &mut Vec<GraphNodeId>,
    edge_sequence: &mut Vec<GraphEdgeId>,
) {
    let finding_edge = node_sequence.iter().find_map(|node_id| {
        index
            .outgoing(node_id)
            .iter()
            .find(|edge| edge.edge_type == GraphEdgeType::ObservationSupportsFinding)
    });
    if let Some(edge) = finding_edge {
        push_node_edge(node_sequence, edge_sequence, edge);
    }
    let Some(last) = node_sequence.last().cloned() else {
        return;
    };
    if !index.node_is_type(&last, GraphNodeType::Finding) {
        return;
    }
    let Some(alert_edge) = index
        .outgoing(&last)
        .iter()
        .find(|edge| edge.edge_type == GraphEdgeType::FindingSupportsAlert)
    else {
        return;
    };
    push_node_edge(node_sequence, edge_sequence, alert_edge);
    let Some(alert_node) = node_sequence.last().cloned() else {
        return;
    };
    let Some(incident_edge) = index
        .outgoing(&alert_node)
        .iter()
        .find(|edge| edge.edge_type == GraphEdgeType::AlertPartOfIncident)
    else {
        return;
    };
    push_node_edge(node_sequence, edge_sequence, incident_edge);
}

fn push_node_edge(
    node_sequence: &mut Vec<GraphNodeId>,
    edge_sequence: &mut Vec<GraphEdgeId>,
    edge: &CanonicalGraphEdge,
) {
    if !node_sequence.contains(&edge.target_node) {
        node_sequence.push(edge.target_node.clone());
    }
    if !edge_sequence.contains(&edge.edge_id) {
        edge_sequence.push(edge.edge_id.clone());
    }
}

fn path_from_sequence(
    path_type: GraphPathType,
    node_sequence: Vec<GraphNodeId>,
    edge_sequence: Vec<GraphEdgeId>,
    explanation: &str,
    index: &GraphIndex,
) -> Result<GraphPath, GraphAnalyticsError> {
    validate_safe_text("graph_path.explanation", explanation)?;
    let mut path = GraphPath::new(
        path_type,
        node_sequence.clone(),
        edge_sequence.clone(),
        RedactedLabel::redacted(explanation, PrivacyClass::Internal)?,
    )?;
    path.evidence_refs = bounded_evidence_refs(
        node_sequence
            .iter()
            .filter_map(|node_id| index.node(node_id))
            .flat_map(|node| node.source_refs.iter().cloned())
            .chain(
                edge_sequence
                    .iter()
                    .filter_map(|edge_id| index.edge(edge_id))
                    .flat_map(|edge| edge.evidence_refs.iter().cloned()),
            ),
    );
    path.risk_score = max_quality(
        node_sequence
            .iter()
            .filter_map(|node_id| index.node(node_id))
            .map(|node| node.risk_score.clone()),
    );
    path.confidence = average_quality(
        edge_sequence
            .iter()
            .filter_map(|edge_id| index.edge(edge_id))
            .map(|edge| edge.confidence.clone()),
    );
    path.redaction_status = RedactionStatus::Redacted;
    path.path_id = deterministic_graph_path_id(&path)?;
    Ok(path)
}

fn path_summary(path: &GraphPath) -> GraphPathSummary {
    GraphPathSummary {
        path_id: path.path_id.clone(),
        path_type: path.path_type.clone(),
        label: path.explanation.clone(),
        risk_score: path.risk_score.clone(),
        confidence: path.confidence.clone(),
        evidence_refs: path.evidence_refs.clone(),
    }
}

fn build_legend(
    nodes: &[GraphNodeViewModel],
    edges: &[GraphEdgeViewModel],
) -> Result<sentinel_contracts::GraphLegend, GraphAnalyticsError> {
    let mut legend = sentinel_contracts::GraphLegend::default();
    let mut node_types = HashSet::new();
    for node in nodes {
        if node_types.insert(node.node_type.clone()) {
            legend.node_items.push(sentinel_contracts::GraphLegendItem {
                key: format!("{:?}", node.node_type).to_ascii_lowercase(),
                label: RedactedLabel::redacted(
                    node_type_label(&node.node_type),
                    PrivacyClass::Internal,
                )?,
                color: None,
                icon: Some(node.icon.clone()),
            });
        }
    }
    let mut edge_types = HashSet::new();
    for edge in edges {
        if edge_types.insert(edge.edge_type.clone()) {
            legend.edge_items.push(sentinel_contracts::GraphLegendItem {
                key: format!("{:?}", edge.edge_type).to_ascii_lowercase(),
                label: RedactedLabel::redacted(
                    edge_type_label(&edge.edge_type),
                    PrivacyClass::Internal,
                )?,
                color: None,
                icon: None,
            });
        }
    }
    legend.risk_scale = vec![
        sentinel_contracts::GraphLegendItem {
            key: "normal".to_string(),
            label: RedactedLabel::redacted("normal", PrivacyClass::Internal)?,
            color: Some("#1f9d55".to_string()),
            icon: None,
        },
        sentinel_contracts::GraphLegendItem {
            key: "risky".to_string(),
            label: RedactedLabel::redacted("risky", PrivacyClass::Internal)?,
            color: Some("#d97706".to_string()),
            icon: None,
        },
        sentinel_contracts::GraphLegendItem {
            key: "critical".to_string(),
            label: RedactedLabel::redacted("critical", PrivacyClass::Internal)?,
            color: Some("#dc2626".to_string()),
            icon: None,
        },
    ];
    Ok(legend)
}

fn filter_model(
    request: &GraphAnalyticsRequest,
    nodes: &[GraphNodeViewModel],
    edges: &[GraphEdgeViewModel],
) -> GraphFilterModel {
    let mut filter = GraphFilterModel::new(request.scope.clone());
    let mut node_types: Vec<_> = nodes
        .iter()
        .map(|node| node.node_type.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    node_types.sort_by_key(graph_node_type_key);
    filter.node_types = node_types;
    let mut edge_types: Vec<_> = edges
        .iter()
        .map(|edge| edge.edge_type.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    edge_types.sort_by_key(graph_edge_type_key);
    filter.edge_types = edge_types;
    filter.time_range = request.time_bounds.clone();
    filter.focus_node = request.focus_node.clone();
    filter.min_confidence = request.min_confidence.clone();
    filter.include_suppressed = request.include_suppressed;
    filter.evidence_refs = bounded_evidence_refs(
        nodes
            .iter()
            .flat_map(|node| node.detail_ref.evidence_refs.iter().cloned())
            .chain(
                edges
                    .iter()
                    .flat_map(|edge| edge.evidence_refs.iter().cloned()),
            ),
    );
    filter
}

fn detail_ref_for_node(node: &CanonicalGraphNode) -> GraphDetailRef {
    let mut detail = GraphDetailRef::empty();
    detail.evidence_refs = bounded_evidence_refs(node.source_refs.iter().cloned());
    if let Some(entity_ref) = &node.entity_ref {
        detail.entity_id = Some(entity_ref.entity_id.clone());
        match entity_ref.entity_type {
            EntityType::Finding => {
                detail.finding_id = Some(sentinel_contracts::FindingId::from_uuid(
                    entity_ref.entity_id.as_uuid(),
                ));
            }
            EntityType::Alert => {
                detail.alert_id = Some(sentinel_contracts::AlertId::from_uuid(
                    entity_ref.entity_id.as_uuid(),
                ));
            }
            EntityType::Incident => {
                detail.incident_id = Some(sentinel_contracts::IncidentId::from_uuid(
                    entity_ref.entity_id.as_uuid(),
                ));
            }
            _ => {}
        }
    }
    detail
}

fn export_safe_node_view_model(
    node: &GraphNodeViewModel,
) -> Result<GraphNodeViewModel, GraphAnalyticsError> {
    let mut sanitized = node.clone();
    sanitized.badges = normalized_badges(&sanitized.badges)?;
    sanitized.detail_ref = export_safe_detail_ref(&sanitized.detail_ref);
    Ok(sanitized)
}

fn normalize_export_safe_node_view_model(
    node: &GraphNodeViewModel,
) -> Result<GraphNodeViewModel, GraphAnalyticsError> {
    let mut normalized = node.clone();
    normalized.badges = normalized_badges(&normalized.badges)?;
    normalized.detail_ref = normalize_export_safe_detail_ref(&normalized.detail_ref)?;
    Ok(normalized)
}

fn export_safe_edge_view_model(
    edge: &GraphEdgeViewModel,
) -> Result<GraphEdgeViewModel, GraphAnalyticsError> {
    let mut sanitized = edge.clone();
    sanitized.evidence_refs = bounded_evidence_refs(sanitized.evidence_refs);
    Ok(sanitized)
}

fn normalize_export_safe_edge_view_model(
    edge: &GraphEdgeViewModel,
) -> Result<GraphEdgeViewModel, GraphAnalyticsError> {
    export_safe_edge_view_model(edge)
}

fn export_safe_path_summary(
    path: &GraphPathSummary,
) -> Result<GraphPathSummary, GraphAnalyticsError> {
    let mut sanitized = path.clone();
    sanitized.evidence_refs = bounded_evidence_refs(sanitized.evidence_refs);
    sanitized.path_id = deterministic_graph_path_summary_id(&sanitized)?;
    Ok(sanitized)
}

fn normalize_export_safe_path_summary(
    path: &GraphPathSummary,
) -> Result<GraphPathSummary, GraphAnalyticsError> {
    let mut normalized = path.clone();
    normalized.evidence_refs = bounded_evidence_refs(normalized.evidence_refs);
    normalized.path_id = deterministic_graph_path_summary_id(&normalized)?;
    Ok(normalized)
}

fn export_safe_detail_ref(detail: &GraphDetailRef) -> GraphDetailRef {
    let mut export_safe = GraphDetailRef::empty();
    export_safe.evidence_refs = bounded_evidence_refs(detail.evidence_refs.iter().cloned());
    export_safe
}

fn normalize_export_safe_detail_ref(
    detail: &GraphDetailRef,
) -> Result<GraphDetailRef, GraphAnalyticsError> {
    if detail.entity_id.is_some()
        || detail.finding_id.is_some()
        || detail.alert_id.is_some()
        || detail.incident_id.is_some()
        || detail.custom_ref.is_some()
    {
        return Err(GraphAnalyticsError::InvalidRequest(
            "graph snapshot contains internal detail references",
        ));
    }
    Ok(export_safe_detail_ref(detail))
}

fn normalized_badges(badges: &[GraphBadge]) -> Result<Vec<GraphBadge>, GraphAnalyticsError> {
    let mut normalized = badges.to_vec();
    normalized.sort_by_key(|badge| {
        (
            badge.label.display.clone(),
            graph_badge_tone_key(&badge.tone).to_string(),
        )
    });
    Ok(normalized)
}

fn bounded_redaction_notes(
    notes: &[String],
    default_note: &str,
) -> Result<Vec<String>, GraphAnalyticsError> {
    let mut bounded = Vec::new();
    for note in notes {
        validate_safe_text("graph.snapshot.redaction_note", note)?;
        if !bounded.contains(note) {
            bounded.push(note.clone());
        }
    }
    if bounded.is_empty() {
        validate_safe_text("graph.snapshot.redaction_note", default_note)?;
        bounded.push(default_note.to_string());
    }
    bounded.sort();
    bounded.truncate(MAX_EXPORT_GRAPH_REDACTION_NOTES);
    Ok(bounded)
}

fn validate_graph_snapshot_safety(snapshot: &GraphSnapshot) -> Result<(), GraphAnalyticsError> {
    if snapshot.selected_nodes.is_empty()
        && snapshot.selected_edges.is_empty()
        && snapshot.path_summaries.is_empty()
    {
        return Err(GraphAnalyticsError::InvalidRequest(
            "graph snapshot is empty",
        ));
    }
    if snapshot.node_count != snapshot.selected_nodes.len() as u32
        || snapshot.edge_count != snapshot.selected_edges.len() as u32
        || snapshot.path_count != snapshot.path_summaries.len() as u32
    {
        return Err(GraphAnalyticsError::InvalidRequest(
            "graph snapshot counts do not match payload",
        ));
    }
    if !is_export_safe_redaction_status(&snapshot.redaction_status)
        || snapshot.redaction_summary.status != snapshot.redaction_status
    {
        return Err(GraphAnalyticsError::InvalidRequest(
            "graph snapshot has not passed redaction",
        ));
    }
    if snapshot.evidence_refs.is_empty() {
        return Err(GraphAnalyticsError::InvalidRequest(
            "graph snapshot is not evidence-backed",
        ));
    }
    for note in &snapshot.redaction_summary.notes {
        validate_safe_text("graph.snapshot.redaction_note", note)?;
    }
    for node in &snapshot.selected_nodes {
        validate_redacted_label("graph.snapshot.node.label", &node.label)?;
        for badge in &node.badges {
            validate_redacted_label("graph.snapshot.node.badge", &badge.label)?;
        }
        if let Some(tooltip) = &node.tooltip {
            validate_redacted_label("graph.snapshot.node.tooltip", tooltip)?;
        }
        normalize_export_safe_detail_ref(&node.detail_ref)?;
    }
    for edge in &snapshot.selected_edges {
        if let Some(label) = &edge.label {
            validate_redacted_label("graph.snapshot.edge.label", label)?;
        }
        if let Some(tooltip) = &edge.tooltip {
            validate_redacted_label("graph.snapshot.edge.tooltip", tooltip)?;
        }
    }
    for path in &snapshot.path_summaries {
        validate_redacted_label("graph.snapshot.path.label", &path.label)?;
    }
    Ok(())
}

fn validate_graph_view_safety(view: &GraphViewModel) -> Result<(), GraphAnalyticsError> {
    validate_redacted_label("graph.title", &view.title)?;
    for node in &view.nodes {
        validate_redacted_label("graph.node.label", &node.label)?;
        for badge in &node.badges {
            validate_redacted_label("graph.node.badge", &badge.label)?;
        }
        if let Some(tooltip) = &node.tooltip {
            validate_redacted_label("graph.node.tooltip", tooltip)?;
        }
    }
    for edge in &view.edges {
        if let Some(label) = &edge.label {
            validate_redacted_label("graph.edge.label", label)?;
        }
        if let Some(tooltip) = &edge.tooltip {
            validate_redacted_label("graph.edge.tooltip", tooltip)?;
        }
    }
    Ok(())
}

fn validate_redacted_label(
    field: &'static str,
    label: &RedactedLabel,
) -> Result<(), GraphAnalyticsError> {
    validate_safe_text(field, &label.display)?;
    if label.redaction_status == RedactionStatus::NotRequired {
        return Err(GraphAnalyticsError::InvalidRequest(
            "graph view labels must be redacted",
        ));
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), GraphAnalyticsError> {
    if value.trim().is_empty() {
        return Err(GraphAnalyticsError::EmptyField(field));
    }
    let lower = value.to_ascii_lowercase();
    for marker in [
        "c:\\users\\",
        "\\appdata\\",
        "%appdata%",
        "%localappdata%",
        "/users/",
        "/home/",
        "/var/tmp/",
        "/tmp/",
    ] {
        if lower.contains(marker) {
            return Err(GraphAnalyticsError::PrivacyMarker { field });
        }
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
        "sid",
        "full_url",
        "private_document",
    ] {
        if normalized.contains(marker) {
            return Err(GraphAnalyticsError::PrivacyMarker { field });
        }
    }
    Ok(())
}

fn is_export_safe_redaction_status(status: &RedactionStatus) -> bool {
    matches!(
        status,
        RedactionStatus::Redacted
            | RedactionStatus::Tokenized
            | RedactionStatus::Hashed
            | RedactionStatus::PartiallyRedacted
            | RedactionStatus::Suppressed
    )
}

fn graph_view_evidence_refs(view: &GraphViewModel) -> Vec<EvidenceId> {
    bounded_evidence_refs(
        view.nodes
            .iter()
            .flat_map(|node| node.detail_ref.evidence_refs.iter().cloned())
            .chain(
                view.edges
                    .iter()
                    .flat_map(|edge| edge.evidence_refs.iter().cloned()),
            )
            .chain(
                view.paths
                    .iter()
                    .flat_map(|path| path.evidence_refs.iter().cloned()),
            ),
    )
}

fn deterministic_graph_view_id(
    view: &GraphViewModel,
) -> Result<sentinel_contracts::GraphViewId, GraphAnalyticsError> {
    deterministic_typed_uuid(
        "graph_view",
        &serde_json::json!({
            "graph_type": &view.graph_type,
            "title": &view.title,
            "scope": &view.filters.scope,
            "time_bounds": &view.filters.time_range,
            "node_limit": view.node_limit,
            "edge_limit": view.edge_limit,
            "truncated": view.truncated,
            "original_node_count": view.original_node_count,
            "original_edge_count": view.original_edge_count,
            "nodes": view.nodes.iter().map(|node| node.node_id.to_string()).collect::<Vec<_>>(),
            "edges": view.edges.iter().map(|edge| edge.edge_id.to_string()).collect::<Vec<_>>(),
            "paths": view.paths.iter().map(graph_path_summary_sort_key).collect::<Vec<_>>(),
        }),
        sentinel_contracts::GraphViewId::from_uuid,
    )
}

fn deterministic_graph_snapshot_id(
    snapshot: &GraphSnapshot,
) -> Result<sentinel_contracts::GraphSnapshotId, GraphAnalyticsError> {
    deterministic_typed_uuid(
        "graph_snapshot",
        &serde_json::json!({
            "graph_type": &snapshot.graph_type,
            "scope": &snapshot.scope,
            "time_bounds": &snapshot.time_bounds,
            "nodes": snapshot.selected_nodes.iter().map(|node| node.node_id.to_string()).collect::<Vec<_>>(),
            "edges": snapshot.selected_edges.iter().map(|edge| edge.edge_id.to_string()).collect::<Vec<_>>(),
            "paths": snapshot.path_summaries.iter().map(graph_path_summary_sort_key).collect::<Vec<_>>(),
            "evidence_refs": snapshot.evidence_refs.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }),
        sentinel_contracts::GraphSnapshotId::from_uuid,
    )
}

fn deterministic_graph_path_id(
    path: &GraphPath,
) -> Result<sentinel_contracts::GraphPathId, GraphAnalyticsError> {
    deterministic_typed_uuid(
        "graph_path",
        &serde_json::json!({
            "path_type": &path.path_type,
            "node_sequence": path.node_sequence.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "edge_sequence": path.edge_sequence.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }),
        sentinel_contracts::GraphPathId::from_uuid,
    )
}

fn deterministic_graph_path_summary_id(
    path: &GraphPathSummary,
) -> Result<sentinel_contracts::GraphPathId, GraphAnalyticsError> {
    deterministic_typed_uuid(
        "graph_path_summary",
        &serde_json::json!({
            "path_type": &path.path_type,
            "label": &path.label,
            "risk_score": path.risk_score.value(),
            "confidence": path.confidence.value(),
            "evidence_refs": path.evidence_refs.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }),
        sentinel_contracts::GraphPathId::from_uuid,
    )
}

fn deterministic_typed_uuid<TId>(
    prefix: &str,
    value: &impl Serialize,
    convert: impl FnOnce(Uuid) -> TId,
) -> Result<TId, GraphAnalyticsError> {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(serde_json::to_vec(value).map_err(GraphAnalyticsError::Serialization)?);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(convert(Uuid::from_bytes(bytes)))
}

fn graph_node_type_key(node_type: &GraphNodeType) -> String {
    format!("{node_type:?}")
}

fn graph_edge_type_key(edge_type: &GraphEdgeType) -> String {
    format!("{edge_type:?}")
}

fn graph_path_summary_sort_key(path: &GraphPathSummary) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        graph_path_type_key(&path.path_type),
        path.label.display.as_str(),
        path.risk_score.value(),
        path.confidence.value(),
        path.evidence_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn graph_path_type_key(path_type: &GraphPathType) -> String {
    format!("{path_type:?}")
}

fn path_sort_key(left: &GraphPath, right: &GraphPath) -> std::cmp::Ordering {
    graph_path_key(left).cmp(&graph_path_key(right))
}

fn graph_path_key(path: &GraphPath) -> String {
    format!(
        "{}|{}|{}",
        graph_path_type_key(&path.path_type),
        path.node_sequence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        path.edge_sequence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn graph_badge_tone_key(tone: &GraphBadgeTone) -> &'static str {
    match tone {
        GraphBadgeTone::Neutral => "neutral",
        GraphBadgeTone::Info => "info",
        GraphBadgeTone::Warning => "warning",
        GraphBadgeTone::Danger => "danger",
        GraphBadgeTone::Success => "success",
    }
}

fn push_unique_evidence_ref(values: &mut Vec<EvidenceId>, value: EvidenceId) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn timestamp_in_range(timestamp: &Timestamp, time_bounds: &Option<TimeRange>) -> bool {
    let Some(time_bounds) = time_bounds else {
        return true;
    };
    if let Some(start) = &time_bounds.start {
        if timestamp < start {
            return false;
        }
    }
    if let Some(end) = &time_bounds.end {
        if timestamp > end {
            return false;
        }
    }
    true
}

fn default_graph_title(graph_type: &GraphType) -> &'static str {
    match graph_type {
        GraphType::OverviewRiskMap => "overview risk map",
        GraphType::IncidentGraph => "incident graph",
        GraphType::C2Graph => "C2 graph",
        GraphType::ExfiltrationGraph => "exfiltration graph",
        GraphType::LateralPropagationGraph => "lateral propagation graph",
        GraphType::AssetExposureGraph => "asset exposure graph",
        GraphType::CapabilityDependencyGraph => "capability dependency graph",
        GraphType::PipelineGraph => "pipeline graph",
        GraphType::ResponseImpactGraph => "response impact graph",
    }
}

fn node_type_label(node_type: &GraphNodeType) -> &'static str {
    match node_type {
        GraphNodeType::LocalHost => "local host",
        GraphNodeType::LocalUser => "local user",
        GraphNodeType::Process => "process",
        GraphNodeType::ProcessBinary => "process binary",
        GraphNodeType::LocalService => "local service",
        GraphNodeType::LocalPort => "local port",
        GraphNodeType::NetworkFlow => "network flow",
        GraphNodeType::DnsQuery => "DNS query",
        GraphNodeType::Domain => "domain",
        GraphNodeType::Ip => "ip destination",
        GraphNodeType::Asn => "asn",
        GraphNodeType::CloudProvider => "cloud provider",
        GraphNodeType::CloudRegion => "cloud region",
        GraphNodeType::CloudDestination => "cloud destination",
        GraphNodeType::TlsFingerprint => "TLS fingerprint",
        GraphNodeType::Certificate => "certificate",
        GraphNodeType::Finding => "finding",
        GraphNodeType::Alert => "alert",
        GraphNodeType::Incident => "incident",
        GraphNodeType::ResponseAction => "response action",
        GraphNodeType::Report => "report",
        GraphNodeType::Capability => "capability",
        GraphNodeType::PipelineStage => "pipeline stage",
        GraphNodeType::Unknown(_) => "graph entity",
    }
}

fn edge_type_label(edge_type: &GraphEdgeType) -> &'static str {
    match edge_type {
        GraphEdgeType::UserRunsProcess => "user runs process",
        GraphEdgeType::ProcessSpawnedProcess => "process spawned process",
        GraphEdgeType::ProcessListensOnPort => "process listens on port",
        GraphEdgeType::ProcessConnectsToIp => "process connects to ip",
        GraphEdgeType::ProcessQueriesDomain => "process queries domain",
        GraphEdgeType::DomainResolvesToIp => "domain resolves to ip",
        GraphEdgeType::IpBelongsToAsn => "ip belongs to asn",
        GraphEdgeType::IpBelongsToCloudProvider => "ip belongs to cloud provider",
        GraphEdgeType::ProcessUsesTlsFingerprint => "process uses TLS fingerprint",
        GraphEdgeType::CertificateObservedForDomain => "certificate observed for domain",
        GraphEdgeType::ProcessUploadsToCloud => "process uploads to cloud",
        GraphEdgeType::ObservationSupportsFinding => "observation supports finding",
        GraphEdgeType::FindingSupportsAlert => "finding supports alert",
        GraphEdgeType::AlertPartOfIncident => "alert part of incident",
        GraphEdgeType::IncidentRecommendsResponse => "incident recommends response",
        GraphEdgeType::ResponseActionTargetsEntity => "response action targets entity",
        GraphEdgeType::ReportSummarizesIncident => "report summarizes incident",
        GraphEdgeType::Custom(_) => "custom relationship",
        GraphEdgeType::Unknown(_) => "unknown relationship",
    }
}

fn node_status(risk_score: &QualityScore) -> GraphNodeStatus {
    match risk_score.value() {
        value if value >= 0.85 => GraphNodeStatus::Critical,
        value if value >= 0.65 => GraphNodeStatus::Risky,
        value if value >= 0.4 => GraphNodeStatus::Suspicious,
        _ => GraphNodeStatus::Normal,
    }
}

fn max_quality(values: impl IntoIterator<Item = QualityScore>) -> QualityScore {
    values
        .into_iter()
        .max_by(|left, right| {
            left.value()
                .partial_cmp(&right.value())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap_or_else(QualityScore::unknown)
}

fn average_quality(values: impl IntoIterator<Item = QualityScore>) -> QualityScore {
    let mut total = 0.0;
    let mut count = 0.0;
    for value in values {
        total += value.value();
        count += 1.0;
    }
    if count == 0.0 {
        return QualityScore::unknown();
    }
    QualityScore::new(total / count).unwrap_or_else(|_| QualityScore::unknown())
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
        PrivacyClass::Redacted | PrivacyClass::Tokenized => 1,
    }
}

fn bounded_evidence_refs(values: impl IntoIterator<Item = EvidenceId>) -> Vec<EvidenceId> {
    let mut evidence_refs = values.into_iter().collect::<Vec<_>>();
    evidence_refs.sort_by_key(|evidence_ref| evidence_ref.to_string());
    evidence_refs.dedup();
    evidence_refs.truncate(MAX_EXPORT_GRAPH_EVIDENCE_REFS);
    evidence_refs
}

fn deduplicate_paths(paths: Vec<GraphPath>) -> Vec<GraphPath> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for path in paths {
        let key = format!(
            "{:?}|{:?}|{:?}",
            path.path_type, path.node_sequence, path.edge_sequence
        );
        if seen.insert(key) {
            deduped.push(path);
        }
    }
    deduped.sort_by(path_sort_key);
    deduped
}

fn clamped_limit(requested: Option<u32>, default: u32) -> u32 {
    requested.unwrap_or(default).clamp(1, default)
}

fn clamped_read_limit(requested: Option<u32>, default: u32, max: u32) -> u32 {
    requested.unwrap_or(default).clamp(1, max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CanonicalGraphWriteSet, CanonicalGraphWriter};
    use chrono::{Duration, Utc};
    use rusqlite::Connection;
    use sentinel_contracts::{EntityRef, GraphEdgeType, GraphPathType};
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

    fn node(node_type: GraphNodeType, entity_type: EntityType, name: &str) -> CanonicalGraphNode {
        let mut node = CanonicalGraphNode::new(
            node_type,
            RedactedLabel::redacted("safe canonical label", PrivacyClass::Internal).expect("label"),
        );
        node.entity_ref = Some(entity(entity_type, name));
        node.confidence = q(0.86);
        node.risk_score = q(0.72);
        node.privacy_class = PrivacyClass::Sensitive;
        node.source_refs = vec![EvidenceId::new_v4()];
        node.last_seen = Timestamp::from_datetime(Utc::now() - Duration::minutes(5));
        node
    }

    fn edge(
        edge_type: GraphEdgeType,
        source: &CanonicalGraphNode,
        target: &CanonicalGraphNode,
    ) -> CanonicalGraphEdge {
        let mut edge =
            CanonicalGraphEdge::new(edge_type, source.node_id.clone(), target.node_id.clone());
        edge.confidence = q(0.84);
        edge.weight = q(0.84);
        edge.privacy_class = PrivacyClass::Sensitive;
        edge.evidence_refs = vec![EvidenceId::new_v4()];
        edge.last_seen = Timestamp::from_datetime(Utc::now() - Duration::minutes(4));
        edge
    }

    fn fixture_graph() -> (Vec<CanonicalGraphNode>, Vec<CanonicalGraphEdge>) {
        let process = node(
            GraphNodeType::Process,
            EntityType::Process,
            "fixture-process",
        );
        let domain = node(
            GraphNodeType::Domain,
            EntityType::Domain,
            "fixture.example.test",
        );
        let ip = node(GraphNodeType::Ip, EntityType::Ip, "198.51.100.24");
        let asn = node(GraphNodeType::Asn, EntityType::Asn, "asn-fixture");
        let cloud = node(
            GraphNodeType::CloudDestination,
            EntityType::CloudResource,
            "object-storage",
        );
        let port = node(GraphNodeType::LocalPort, EntityType::Port, "local-port");
        let finding = node(GraphNodeType::Finding, EntityType::Finding, "finding");
        let alert = node(GraphNodeType::Alert, EntityType::Alert, "alert");
        let incident = node(GraphNodeType::Incident, EntityType::Incident, "incident");
        let edges = vec![
            edge(GraphEdgeType::ProcessQueriesDomain, &process, &domain),
            edge(GraphEdgeType::DomainResolvesToIp, &domain, &ip),
            edge(GraphEdgeType::IpBelongsToAsn, &ip, &asn),
            edge(GraphEdgeType::ObservationSupportsFinding, &ip, &finding),
            edge(GraphEdgeType::ProcessUploadsToCloud, &process, &cloud),
            edge(GraphEdgeType::ObservationSupportsFinding, &cloud, &finding),
            edge(GraphEdgeType::ProcessListensOnPort, &process, &port),
            edge(GraphEdgeType::ObservationSupportsFinding, &port, &finding),
            edge(GraphEdgeType::FindingSupportsAlert, &finding, &alert),
            edge(GraphEdgeType::AlertPartOfIncident, &alert, &incident),
        ];
        (
            vec![
                process, domain, ip, asn, cloud, port, finding, alert, incident,
            ],
            edges,
        )
    }

    #[test]
    fn graph_analytics_produces_mvp_paths_view_and_snapshot() {
        let (nodes, edges) = fixture_graph();
        let output = GraphAnalyticsService::new()
            .analyze(GraphAnalyticsInput {
                request: GraphAnalyticsRequest::new(
                    GraphType::OverviewRiskMap,
                    GraphScope::Overview,
                ),
                nodes,
                edges,
            })
            .expect("analytics output");

        assert!(output
            .paths
            .iter()
            .any(|path| path.path_type == GraphPathType::ProcessToC2Path));
        assert!(output
            .paths
            .iter()
            .any(|path| path.path_type == GraphPathType::ProcessToCloudUploadPath));
        assert!(output
            .paths
            .iter()
            .any(|path| path.path_type == GraphPathType::LocalAssetExposurePath));
        assert!(output
            .paths
            .iter()
            .any(|path| path.path_type == GraphPathType::IncidentSummaryPath));
        assert!(!output.view_model.nodes.is_empty());
        assert!(!output.view_model.edges.is_empty());
        assert_eq!(
            output.view_model.redaction_status,
            RedactionStatus::Redacted
        );
        assert_eq!(output.snapshot.redaction_status, RedactionStatus::Redacted);
        assert!(!output.snapshot.evidence_refs.is_empty());
    }

    #[test]
    fn graph_analytics_builds_deterministic_view_and_snapshot_artifacts() {
        let (nodes, edges) = fixture_graph();
        let request = GraphAnalyticsRequest::new(GraphType::IncidentGraph, GraphScope::Overview);
        let service = GraphAnalyticsService::new();
        let first = service
            .analyze(GraphAnalyticsInput {
                request: request.clone(),
                nodes: nodes.clone(),
                edges: edges.clone(),
            })
            .expect("first analytics output");
        let second = service
            .analyze(GraphAnalyticsInput {
                request,
                nodes,
                edges,
            })
            .expect("second analytics output");

        assert_eq!(first.view_model.graph_id, second.view_model.graph_id);
        assert_eq!(first.snapshot.snapshot_id, second.snapshot.snapshot_id);
        assert_eq!(
            first.view_model.filters.node_types,
            second.view_model.filters.node_types
        );
        assert_eq!(
            first.view_model.filters.edge_types,
            second.view_model.filters.edge_types
        );
        assert_eq!(first.view_model.paths, second.view_model.paths,);
        assert_eq!(
            first.snapshot.path_summaries,
            second.snapshot.path_summaries
        );
        assert_eq!(first.paths, second.paths);
    }

    #[test]
    fn graph_view_model_is_bounded_and_omits_canonical_internals() {
        let (nodes, edges) = fixture_graph();
        let node_count = nodes.len();
        let edge_count = edges.len();
        let output = GraphAnalyticsService::new()
            .analyze(GraphAnalyticsInput {
                request: GraphAnalyticsRequest::new(GraphType::C2Graph, GraphScope::Overview)
                    .with_bounds(3, 2),
                nodes,
                edges,
            })
            .expect("analytics output");
        let serialized = serde_json::to_string(&output.view_model).expect("serialize");

        assert!(output.view_model.truncated);
        assert_eq!(output.view_model.nodes.len(), 3);
        assert!(output.view_model.edges.len() <= 2);
        assert_eq!(output.view_model.original_node_count, node_count as u32);
        assert_eq!(output.view_model.original_edge_count, edge_count as u32);
        assert!(!serialized.contains("source_node"));
        assert!(!serialized.contains("target_node"));
        assert!(!serialized.contains("entity_ref"));
        assert!(!serialized.contains("node_sequence"));
    }

    #[test]
    fn graph_view_redactor_replaces_sensitive_canonical_labels() {
        let (mut nodes, edges) = fixture_graph();
        nodes[0].label = RedactedLabel::new(
            "C:\\Users\\Alice\\AppData\\Local\\Temp\\tool.exe",
            RedactionStatus::NotRequired,
            PrivacyClass::Sensitive,
        )
        .expect("representable unsafe label");
        let output = GraphAnalyticsService::new()
            .analyze(GraphAnalyticsInput {
                request: GraphAnalyticsRequest::new(GraphType::IncidentGraph, GraphScope::Overview),
                nodes,
                edges,
            })
            .expect("analytics output");
        let serialized = serde_json::to_string(&output.view_model).expect("serialize");

        assert!(!serialized.contains("Alice"));
        assert!(!serialized.contains("AppData"));
        assert!(!serialized.contains("tool.exe"));
        assert!(output
            .view_model
            .nodes
            .iter()
            .all(|node| node.label.redaction_status != RedactionStatus::NotRequired));
    }

    #[test]
    fn graph_analytics_reads_canonical_records_through_graph_store() {
        let connection = initialized_connection().expect("connection");
        let factory = SqliteStoreFactory::new(&connection);
        let graph_store = factory.graph_store();
        let (nodes, edges) = fixture_graph();
        CanonicalGraphWriter::new()
            .write_to_store(
                &graph_store,
                &CanonicalGraphWriteSet {
                    nodes,
                    edges,
                    paths: Vec::new(),
                },
            )
            .expect("write graph");

        let output = GraphAnalyticsService::new()
            .analyze_store(
                &graph_store,
                GraphAnalyticsRequest::new(GraphType::C2Graph, GraphScope::Overview),
            )
            .expect("analytics output");

        assert!(output
            .paths
            .iter()
            .any(|path| path.path_type == GraphPathType::ProcessToC2Path));
        assert!(!output.view_model.nodes.is_empty());
    }

    #[test]
    fn canonical_graph_reader_filters_types_and_focus_neighborhood() {
        let connection = initialized_connection().expect("connection");
        let factory = SqliteStoreFactory::new(&connection);
        let graph_store = factory.graph_store();
        let (nodes, edges) = fixture_graph();
        let process_id = nodes
            .iter()
            .find(|node| node.node_type == GraphNodeType::Process)
            .expect("process")
            .node_id
            .clone();
        CanonicalGraphWriter::new()
            .write_to_store(
                &graph_store,
                &CanonicalGraphWriteSet {
                    nodes,
                    edges,
                    paths: Vec::new(),
                },
            )
            .expect("write graph");

        let typed = CanonicalGraphReader::new()
            .read(
                &graph_store,
                CanonicalGraphReadRequest::default()
                    .with_node_types(vec![GraphNodeType::Process])
                    .with_edge_types(vec![GraphEdgeType::ProcessQueriesDomain])
                    .with_bounds(10, 10, 0),
            )
            .expect("typed read");
        assert_eq!(typed.nodes.len(), 1);
        assert!(typed
            .edges
            .iter()
            .all(|edge| edge.edge_type == GraphEdgeType::ProcessQueriesDomain));

        let neighborhood = CanonicalGraphReader::new()
            .read(
                &graph_store,
                CanonicalGraphReadRequest::default()
                    .with_bounds(20, 20, 0)
                    .with_focus(process_id.clone(), 1),
            )
            .expect("focused read");
        assert!(neighborhood
            .nodes
            .iter()
            .any(|node| node.node_id == process_id));
        assert!(neighborhood
            .edges
            .iter()
            .all(|edge| { edge.source_node == process_id || edge.target_node == process_id }));
    }

    #[test]
    fn bounded_path_computer_returns_shortest_deduped_paths_and_handles_cycles() {
        let (nodes, mut edges) = fixture_graph();
        let process = nodes
            .iter()
            .find(|node| node.node_type == GraphNodeType::Process)
            .expect("process");
        let finding = nodes
            .iter()
            .find(|node| node.node_type == GraphNodeType::Finding)
            .expect("finding");
        let incident = nodes
            .iter()
            .find(|node| node.node_type == GraphNodeType::Incident)
            .expect("incident");
        edges.push(edge(
            GraphEdgeType::Custom("cycle_back_to_process".to_string()),
            finding,
            process,
        ));

        let output = GraphPathComputer::new()
            .compute(
                &nodes,
                &edges,
                GraphPathRequest::new(process.node_id.clone(), incident.node_id.clone()),
            )
            .expect("bounded paths");

        assert_eq!(output.paths.len(), 3);
        assert!(output
            .paths
            .iter()
            .all(|path| path.edge_sequence.len() <= DEFAULT_GRAPH_PATH_MAX_DEPTH as usize));
        assert!(output
            .paths
            .iter()
            .all(|path| !path.evidence_refs.is_empty()));

        let disconnected = GraphPathComputer::new()
            .compute(
                &nodes,
                &edges,
                GraphPathRequest::new(process.node_id.clone(), GraphNodeId::new_v4()),
            )
            .expect("disconnected path");
        assert!(disconnected.paths.is_empty());
    }

    #[test]
    fn store_analysis_builds_paths_beyond_view_bounds() {
        let connection = initialized_connection().expect("connection");
        let factory = SqliteStoreFactory::new(&connection);
        let graph_store = factory.graph_store();
        let (nodes, edges) = fixture_graph();
        CanonicalGraphWriter::new()
            .write_to_store(
                &graph_store,
                &CanonicalGraphWriteSet {
                    nodes,
                    edges,
                    paths: Vec::new(),
                },
            )
            .expect("write graph");

        let output = GraphAnalyticsService::new()
            .analyze_store(
                &graph_store,
                GraphAnalyticsRequest::new(GraphType::IncidentGraph, GraphScope::Overview)
                    .with_bounds(3, 2),
            )
            .expect("analytics output");

        assert!(output
            .paths
            .iter()
            .any(|path| path.path_type == GraphPathType::IncidentSummaryPath));
        assert_eq!(output.view_model.nodes.len(), 3);
        assert!(output.view_model.edges.len() <= 2);
        assert!(output.view_model.truncated);
    }

    #[test]
    fn graph_snapshot_contains_only_redacted_selected_view_models() {
        let (nodes, edges) = fixture_graph();
        let output = GraphAnalyticsService::new()
            .analyze(GraphAnalyticsInput {
                request: GraphAnalyticsRequest::new(GraphType::IncidentGraph, GraphScope::Overview),
                nodes,
                edges,
            })
            .expect("analytics output");
        let serialized = serde_json::to_string(&output.snapshot).expect("snapshot json");

        assert_eq!(
            output.snapshot.selected_nodes.len(),
            output.view_model.nodes.len()
        );
        assert_eq!(
            output.snapshot.selected_edges.len(),
            output.view_model.edges.len()
        );
        assert!(!serialized.contains("source_node"));
        assert!(!serialized.contains("target_node"));
        assert!(!serialized.contains("entity_ref"));
        assert!(!serialized.contains("entity_id"));
        assert!(!serialized.contains("finding_id"));
        assert!(!serialized.contains("alert_id"));
        assert!(!serialized.contains("incident_id"));
        assert!(!serialized.contains("custom_ref"));
        assert!(output.snapshot.selected_nodes.iter().all(|node| {
            node.detail_ref.entity_id.is_none()
                && node.detail_ref.finding_id.is_none()
                && node.detail_ref.alert_id.is_none()
                && node.detail_ref.incident_id.is_none()
                && node.detail_ref.custom_ref.is_none()
        }));
        assert_eq!(output.snapshot.redaction_status, RedactionStatus::Redacted);
    }

    #[test]
    fn graph_snapshot_and_view_bound_evidence_refs_for_export_safe_artifacts() {
        let (mut nodes, mut edges) = fixture_graph();
        let overflow_refs = (0..(MAX_EXPORT_GRAPH_EVIDENCE_REFS + 12))
            .map(|_| EvidenceId::new_v4())
            .collect::<Vec<_>>();
        nodes[0].source_refs = overflow_refs.clone();
        edges[0].evidence_refs = overflow_refs;
        let output = GraphAnalyticsService::new()
            .analyze(GraphAnalyticsInput {
                request: GraphAnalyticsRequest::new(GraphType::IncidentGraph, GraphScope::Overview),
                nodes,
                edges,
            })
            .expect("analytics output");

        assert!(output
            .view_model
            .nodes
            .iter()
            .all(|node| node.detail_ref.evidence_refs.len() <= MAX_EXPORT_GRAPH_EVIDENCE_REFS));
        assert!(output
            .view_model
            .edges
            .iter()
            .all(|edge| edge.evidence_refs.len() <= MAX_EXPORT_GRAPH_EVIDENCE_REFS));
        assert!(output.snapshot.evidence_refs.len() <= MAX_EXPORT_GRAPH_EVIDENCE_REFS);
        assert!(output
            .snapshot
            .path_summaries
            .iter()
            .all(|path| path.evidence_refs.len() <= MAX_EXPORT_GRAPH_EVIDENCE_REFS));
    }

    #[test]
    fn incident_scope_builds_bounded_neighborhood() {
        let (nodes, edges) = fixture_graph();
        let incident = nodes
            .iter()
            .find(|node| node.node_type == GraphNodeType::Incident)
            .expect("incident")
            .entity_ref
            .as_ref()
            .expect("incident entity");
        let incident_id = sentinel_contracts::IncidentId::from_uuid(incident.entity_id.as_uuid());
        let output = GraphAnalyticsService::new()
            .analyze(GraphAnalyticsInput {
                request: GraphAnalyticsRequest::new(
                    GraphType::IncidentGraph,
                    GraphScope::Incident(incident_id),
                ),
                nodes,
                edges,
            })
            .expect("analytics output");

        assert!(output
            .paths
            .iter()
            .any(|path| path.path_type == GraphPathType::IncidentSummaryPath));
        assert!(output
            .view_model
            .nodes
            .iter()
            .any(|node| node.node_type == GraphNodeType::Incident));
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
