import {
  Background,
  BaseEdge,
  Controls,
  EdgeLabelRenderer,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  getBezierPath,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  AlertTriangle,
  EyeOff,
  Filter,
  GitBranch,
  ListChecks,
  Maximize2,
  Network,
} from "lucide-react";
import { useMemo } from "react";
import type { JsonValue } from "../../bridge/dto/common";
import type { GraphTypeDto, GraphViewModelDto } from "../../bridge/dto/graph";
import {
  humanize,
  isRecord,
  isSensitiveKey,
  safeEntries,
  stringifySafe,
  stringifySafeForKey,
} from "../renderers";

export type RiskFilter = "all" | "medium_plus" | "high_plus";
export type TimeFilter = "15m" | "1h" | "24h" | "all";

export interface GraphCanvasSelection {
  readonly selectedNodeId: string | null;
  readonly selectedEdgeId: string | null;
  readonly onSelectNode: (nodeId: string | null) => void;
  readonly onSelectEdge: (edgeId: string | null) => void;
}

interface GraphCanvasProps extends GraphCanvasSelection {
  readonly view: GraphViewModelDto;
  readonly riskFilter: RiskFilter;
}

interface GraphToolbarProps {
  readonly view: GraphViewModelDto;
  readonly detached?: boolean;
  readonly loading: boolean;
  readonly sourceStatus: "command" | "empty" | "error" | "redacted";
  readonly nodeLimit: number;
  readonly edgeLimit: number;
  readonly onDetachGraph?: () => void;
  readonly onExpandBounds: () => void;
}

interface GraphLegendProps {
  readonly view: GraphViewModelDto;
}

interface GraphPathPanelProps {
  readonly view: GraphViewModelDto;
}

interface GraphFiltersProps {
  readonly riskFilter: RiskFilter;
  readonly timeFilter: TimeFilter;
  readonly onRiskFilterChange: (filter: RiskFilter) => void;
  readonly onTimeFilterChange: (filter: TimeFilter) => void;
}

interface GraphTypeSelectorProps {
  readonly graphTypes: readonly GraphTypeOption[];
  readonly selectedGraphType: GraphTypeDto;
  readonly onSelectGraphType: (graphType: GraphTypeDto) => void;
}

export interface GraphTypeOption {
  readonly graphType: GraphTypeDto;
  readonly label: string;
}

interface GraphDetailProps {
  readonly view: GraphViewModelDto;
  readonly selectedNodeId: string | null;
  readonly selectedEdgeId: string | null;
}

interface GraphNodeData extends Record<string, unknown> {
  readonly label: string;
  readonly nodeType: string;
  readonly riskScore: number | null;
  readonly status: string | null;
  readonly badges: string[];
  readonly privacyClass: string | null;
  readonly source: Record<string, JsonValue>;
}

interface GraphEdgeData extends Record<string, unknown> {
  readonly label: string;
  readonly edgeType: string;
  readonly confidence: string | null;
  readonly evidenceRefs: string[];
  readonly privacyClass: string | null;
  readonly source: Record<string, JsonValue>;
}

type FlowGraphNode = Node<GraphNodeData, "sentinel">;
type FlowGraphEdge = Edge<GraphEdgeData, "sentinel">;

const nodeTypes = { sentinel: NodeRenderer };
const edgeTypes = { sentinel: EdgeRenderer };
const CANONICAL_GRAPH_FIELD_MARKERS = [
  "canonical_node",
  "canonical_edge",
  "source_node",
  "target_node",
  "node_sequence",
  "adjacency",
  "graph_node_store",
  "graph_edge_store",
];

export function GraphCanvas({
  view,
  riskFilter,
  selectedNodeId,
  selectedEdgeId,
  onSelectNode,
  onSelectEdge,
}: GraphCanvasProps) {
  const { nodes, edges } = useMemo(
    () => mapGraphViewModelToFlow(view, riskFilter),
    [riskFilter, view],
  );

  if (!nodes.length) {
    return (
      <div className="graph-empty-state">
        <EyeOff size={18} aria-hidden="true" />
        <strong>No graph nodes</strong>
        <span>Current GraphViewModel is empty or fully filtered.</span>
      </div>
    );
  }

  return (
    <div className="graph-canvas-shell">
      <ReactFlow
        nodes={nodes.map((node) => ({
          ...node,
          selected: node.id === selectedNodeId,
        }))}
        edges={edges.map((edge) => ({
          ...edge,
          selected: edge.id === selectedEdgeId,
        }))}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        minZoom={0.25}
        maxZoom={1.6}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        onNodeClick={(_event, node) => {
          onSelectNode(node.id);
          onSelectEdge(null);
        }}
        onEdgeClick={(_event, edge) => {
          onSelectEdge(edge.id);
          onSelectNode(null);
        }}
        onPaneClick={() => {
          onSelectNode(null);
          onSelectEdge(null);
        }}
      >
        <Background gap={40} size={1} />
        <MiniMap pannable zoomable nodeStrokeWidth={2} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

export function GraphToolbar({
  detached = false,
  view,
  loading,
  sourceStatus,
  nodeLimit,
  edgeLimit,
  onDetachGraph,
  onExpandBounds,
}: GraphToolbarProps) {
  const title = labelFromGraphTitle(view.title) ?? humanize(view.graph_type);
  const redaction = redactionStatus(view.redaction_status);
  return (
    <section className="graph-toolbar-panel">
      <div className="graph-toolbar-title">
        <GitBranch size={15} aria-hidden="true" />
        <strong>{title}</strong>
      </div>
      <div className="graph-toolbar-stats">
        <span>{loading ? "Loading" : sourceStatus}</span>
        <span>Nodes {view.nodes.length}</span>
        <span>Edges {view.edges.length}</span>
        <span>Paths {view.paths.length}</span>
        <span>Bounds {nodeLimit}/{edgeLimit}</span>
        <span>{view.truncated ? "truncated" : "bounded"}</span>
        <span data-redaction={redaction.toLowerCase()}>{redaction}</span>
      </div>
      <button
        className="toolbar-button"
        type="button"
        title={detached ? "Graph is detached" : "Detach graph"}
        aria-pressed={detached ? "true" : "false"}
        onClick={onDetachGraph}
        disabled={!onDetachGraph}
      >
        <Maximize2 size={14} aria-hidden="true" />
        Detach
      </button>
      <button
        className="toolbar-button"
        type="button"
        title="Increase graph bounds"
        onClick={onExpandBounds}
      >
        <Maximize2 size={14} aria-hidden="true" />
        Expand
      </button>
    </section>
  );
}

export function GraphLegend({ view }: GraphLegendProps) {
  const legendItems = legendEntries(view);
  return (
    <section className="graph-side-panel">
      <div className="analysis-panel-header">
        <strong>Legend</strong>
        <Network size={15} aria-hidden="true" />
      </div>
      <div className="graph-legend-list">
        {legendItems.length ? (
          legendItems.map(([label, value], index) => {
            const safeLabel = stringifySafe(label);
            return (
              <div className="graph-legend-item" key={`${safeLabel}:${index}`}>
                <span className="graph-legend-swatch" />
                <strong>{safeLabel}</strong>
                <small>{value}</small>
              </div>
            );
          })
        ) : (
          <span className="analysis-muted">No legend metadata</span>
        )}
      </div>
    </section>
  );
}

export function GraphPathPanel({ view }: GraphPathPanelProps) {
  const paths = view.paths.filter(isRecord).slice(0, 8);
  return (
    <section className="graph-side-panel">
      <div className="analysis-panel-header">
        <strong>Paths</strong>
        <GitBranch size={15} aria-hidden="true" />
      </div>
      <div className="graph-path-list">
        {paths.length ? (
          paths.map((path, index) => (
            <div className="graph-path-item" key={pathId(path, index)}>
              <strong>{pathTitle(path, index)}</strong>
              <span>{arrayLabel(valueFor(path, "node_refs"))}</span>
              <small>{stringField(path, "path_type") ?? "graph path"}</small>
            </div>
          ))
        ) : (
          <span className="analysis-muted">No paths in this GraphViewModel</span>
        )}
      </div>
    </section>
  );
}

export function GraphFilters({
  riskFilter,
  timeFilter,
  onRiskFilterChange,
  onTimeFilterChange,
}: GraphFiltersProps) {
  return (
    <section className="graph-side-panel compact">
      <div className="analysis-panel-header">
        <strong>Filters</strong>
        <Filter size={15} aria-hidden="true" />
      </div>
      <div className="graph-filter-grid">
        <label>
          <span>Risk</span>
          <select
            value={riskFilter}
            onChange={(event) =>
              onRiskFilterChange(event.currentTarget.value as RiskFilter)
            }
          >
            <option value="all">All</option>
            <option value="medium_plus">Medium+</option>
            <option value="high_plus">High+</option>
          </select>
        </label>
        <label>
          <span>Time</span>
          <select
            value={timeFilter}
            onChange={(event) =>
              onTimeFilterChange(event.currentTarget.value as TimeFilter)
            }
          >
            <option value="15m">Last 15m</option>
            <option value="1h">Last 1h</option>
            <option value="24h">Last 24h</option>
            <option value="all">All</option>
          </select>
        </label>
      </div>
    </section>
  );
}

export function GraphTypeSelector({
  graphTypes,
  selectedGraphType,
  onSelectGraphType,
}: GraphTypeSelectorProps) {
  return (
    <aside className="graph-type-selector" aria-label="Graph types">
      <div className="analysis-panel-header">
        <strong>Graph types</strong>
        <span>{graphTypes.length}</span>
      </div>
      <div className="graph-type-list">
        {graphTypes.map((option) => (
          <button
            className="graph-type-button"
            data-selected={option.graphType === selectedGraphType}
            key={option.graphType}
            type="button"
            onClick={() => onSelectGraphType(option.graphType)}
          >
            <GitBranch size={14} aria-hidden="true" />
            <span>{option.label}</span>
          </button>
        ))}
      </div>
    </aside>
  );
}

export function NodeRenderer({ data, selected }: NodeProps<FlowGraphNode>) {
  return (
    <div className="flow-node" data-selected={selected} data-node-type={data.nodeType}>
      <div className="flow-node-title">
        <span>{data.label}</span>
        {data.riskScore !== null ? <strong>{data.riskScore}</strong> : null}
      </div>
      <div className="flow-node-meta">
        <span>{data.nodeType}</span>
        {data.status ? <span>{data.status}</span> : null}
      </div>
      {data.badges.length ? (
        <div className="flow-node-badges">
          {data.badges.slice(0, 3).map((badge) => (
            <small key={badge}>{badge}</small>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export function EdgeRenderer(props: EdgeProps<FlowGraphEdge>) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX: props.sourceX,
    sourceY: props.sourceY,
    sourcePosition: props.sourcePosition,
    targetX: props.targetX,
    targetY: props.targetY,
    targetPosition: props.targetPosition,
  });
  return (
    <>
      <BaseEdge
        id={props.id}
        path={edgePath}
        markerEnd={props.markerEnd}
        style={props.selected ? { strokeWidth: 2.5 } : undefined}
      />
      <EdgeLabelRenderer>
        <span
          className="flow-edge-label"
          style={{
            transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
          }}
        >
          {props.data?.label ?? props.label}
        </span>
      </EdgeLabelRenderer>
    </>
  );
}

export function NodeDetailPanel({
  view,
  selectedNodeId,
}: Pick<GraphDetailProps, "view" | "selectedNodeId">) {
  const node = findGraphRecord(view.nodes, selectedNodeId);
  return (
    <section className="graph-side-panel">
      <div className="analysis-panel-header">
        <strong>Node detail</strong>
        <GitBranch size={15} aria-hidden="true" />
      </div>
      {node ? (
        <dl className="graph-detail-list">
          <DetailItem label="Label" value={nodeLabel(node)} />
          <DetailItem label="Type" value={nodeType(node)} />
          <DetailItem label="Risk" value={stringifySafe(valueFor(node, "risk_score") ?? null)} />
          <DetailItem label="Status" value={stringField(node, "status") ?? "unknown"} />
          <DetailItem label="Privacy" value={stringField(node, "privacy_class") ?? "internal"} />
          <DetailItem label="Detail ref" value={stringField(node, "detail_ref") ?? "none"} />
        </dl>
      ) : (
        <span className="analysis-muted">Select a node</span>
      )}
    </section>
  );
}

export function EdgeEvidencePanel({
  view,
  selectedEdgeId,
}: Pick<GraphDetailProps, "view" | "selectedEdgeId">) {
  const edge = findGraphRecord(view.edges, selectedEdgeId);
  return (
    <section className="graph-side-panel">
      <div className="analysis-panel-header">
        <strong>Edge evidence</strong>
        <ListChecks size={15} aria-hidden="true" />
      </div>
      {edge ? (
        <dl className="graph-detail-list">
          <DetailItem label="Label" value={edgeLabel(edge)} />
          <DetailItem label="Type" value={edgeType(edge)} />
          <DetailItem label="Confidence" value={stringifySafe(valueFor(edge, "confidence") ?? null)} />
          <DetailItem label="Evidence" value={arrayLabel(valueFor(edge, "evidence_refs"))} />
          <DetailItem label="Privacy" value={stringField(edge, "privacy_class") ?? "internal"} />
        </dl>
      ) : (
        <span className="analysis-muted">Select an edge</span>
      )}
    </section>
  );
}

function DetailItem({
  label,
  value,
}: {
  readonly label: string;
  readonly value: string;
}) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function mapGraphViewModelToFlow(
  view: GraphViewModelDto,
  riskFilter: RiskFilter,
): { nodes: FlowGraphNode[]; edges: FlowGraphEdge[] } {
  const graphNodes = view.nodes.filter(isRecord).filter((node) =>
    passesRiskFilter(riskScore(node), riskFilter),
  );
  const allowedNodeIds = new Set(graphNodes.map((node, index) => nodeId(node, index)));
  const nodes = graphNodes.map<FlowGraphNode>((node, index) => ({
    id: nodeId(node, index),
    type: "sentinel",
    position: nodePosition(index, graphNodes.length),
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    data: {
      label: nodeLabel(node),
      nodeType: nodeType(node),
      riskScore: riskScore(node),
      status: stringField(node, "status"),
      badges: stringArray(valueFor(node, "badges")),
      privacyClass: stringField(node, "privacy_class"),
      source: node,
    },
  }));

  const edges = view.edges.filter(isRecord).flatMap<FlowGraphEdge>((edge, index) => {
    const source = edgeSource(edge);
    const target = edgeTarget(edge);
    if (!source || !target || !allowedNodeIds.has(source) || !allowedNodeIds.has(target)) {
      return [];
    }
    return [
      {
        id: edgeId(edge, index),
        source,
        target,
        type: "sentinel",
        label: edgeLabel(edge),
        markerEnd: { type: MarkerType.ArrowClosed },
        data: {
          label: edgeLabel(edge),
          edgeType: edgeType(edge),
          confidence: stringifySafe(valueFor(edge, "confidence") ?? null),
          evidenceRefs: stringArray(valueFor(edge, "evidence_refs")),
          privacyClass: stringField(edge, "privacy_class"),
          source: edge,
        },
      },
    ];
  });

  return { nodes, edges };
}

function nodePosition(index: number, total: number) {
  const columns = total > 8 ? 4 : 3;
  const row = Math.floor(index / columns);
  const column = index % columns;
  return { x: column * 260, y: row * 140 + (column % 2) * 34 };
}

function passesRiskFilter(score: number | null, filter: RiskFilter) {
  if (filter === "all") {
    return true;
  }
  const value = score ?? 0;
  return filter === "high_plus" ? value >= 70 : value >= 40;
}

function legendEntries(view: GraphViewModelDto): [string, string][] {
  if (isRecord(view.legend)) {
    return safeEntries(view.legend).slice(0, 8);
  }
  const nodeTypes = new Set(
    view.nodes.filter(isRecord).map((node) => nodeType(node)).filter(Boolean),
  );
  return [...nodeTypes].slice(0, 8).map((type) => [humanize(type), "node"]);
}

function findGraphRecord(values: JsonValue[], id: string | null) {
  if (!id) {
    return null;
  }
  return (
    values.filter(isRecord).find((value, index) => {
      const candidate =
        stringField(value, "node_id") ??
        stringField(value, "edge_id") ??
        stringField(value, "id") ??
        `${index}`;
      return candidate === id;
    }) ?? null
  );
}

export function graphViewBoundaryIssue(view: GraphViewModelDto): string | null {
  return containsCanonicalGraphField(view as unknown as JsonValue)
    ? "canonical graph internals blocked"
    : null;
}

function nodeId(node: Record<string, JsonValue>, index: number) {
  return (
    stringField(node, "node_id") ??
    stringField(node, "id") ??
    stringField(node, "entity_ref") ??
    `node:${index}`
  );
}

function edgeId(edge: Record<string, JsonValue>, index: number) {
  return stringField(edge, "edge_id") ?? stringField(edge, "id") ?? `edge:${index}`;
}

function pathId(path: Record<string, JsonValue>, index: number) {
  return stringField(path, "path_id") ?? stringField(path, "id") ?? `path:${index}`;
}

function pathTitle(path: Record<string, JsonValue>, index: number) {
  return (
    stringField(path, "title_redacted") ??
    stringField(path, "label_redacted") ??
    stringField(path, "label") ??
    `Path ${index + 1}`
  );
}

function edgeSource(edge: Record<string, JsonValue>) {
  return stringField(edge, "source") ?? stringField(edge, "source_id");
}

function edgeTarget(edge: Record<string, JsonValue>) {
  return stringField(edge, "target") ?? stringField(edge, "target_id");
}

function nodeLabel(node: Record<string, JsonValue>) {
  return (
    stringField(node, "label") ??
    stringField(node, "label_redacted") ??
    stringField(node, "title_redacted") ??
    nodeType(node)
  );
}

function edgeLabel(edge: Record<string, JsonValue>) {
  return stringField(edge, "label") ?? edgeType(edge);
}

function nodeType(node: Record<string, JsonValue>) {
  return stringField(node, "node_type") ?? "node";
}

function edgeType(edge: Record<string, JsonValue>) {
  return stringField(edge, "edge_type") ?? "edge";
}

function riskScore(node: Record<string, JsonValue>) {
  const value = valueFor(node, "risk_score");
  return typeof value === "number" ? value : null;
}

function stringField(value: JsonValue | undefined, key: string): string | null {
  const nested = valueFor(value, key);
  if (typeof nested === "string") {
    return redactString(nested);
  }
  if (isRecord(nested)) {
    return (
      stringField(nested, "value_redacted") ??
      stringField(nested, "display") ??
      stringField(nested, "value") ??
      stringField(nested, "id") ??
      stringField(nested, "name")
    );
  }
  return null;
}

function valueFor(value: JsonValue | undefined, key: string): JsonValue | undefined {
  if (!isRecord(value) || isSensitiveKey(key)) {
    return undefined;
  }
  return value[key];
}

function stringArray(value: JsonValue | undefined) {
  return Array.isArray(value)
    ? value.map((item) => stringifySafe(item)).slice(0, 8)
    : [];
}

function arrayLabel(value: JsonValue | undefined) {
  const values = stringArray(value);
  return values.length ? values.join(", ") : "none";
}

function labelFromGraphTitle(title: JsonValue | undefined) {
  if (typeof title === "string") {
    return redactString(title);
  }
  if (isRecord(title)) {
    return (
      stringField(title, "value_redacted") ??
      stringField(title, "display") ??
      stringField(title, "label_redacted") ??
      stringField(title, "title_redacted")
    );
  }
  return null;
}

function redactionStatus(value: JsonValue | undefined) {
  if (typeof value === "string") {
    return redactString(value);
  }
  if (isRecord(value)) {
    return (
      stringField(value, "status") ??
      stringField(value, "redaction_status") ??
      "redacted"
    );
  }
  return "redacted";
}

function redactString(value: string) {
  return stringifySafe(value);
}

function containsCanonicalGraphField(value: JsonValue): boolean {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return false;
  }

  if (Array.isArray(value)) {
    return value.slice(0, 32).some(containsCanonicalGraphField);
  }

  return Object.entries(value).slice(0, 32).some(([key, nested]) => {
    const normalized = key.toLowerCase();
    return (
      CANONICAL_GRAPH_FIELD_MARKERS.some((marker) => normalized.includes(marker)) ||
      containsCanonicalGraphField(nested)
    );
  });
}
