import { AlertTriangle } from "lucide-react";
import { useMemo, useState } from "react";
import type { GraphTypeDto, GraphViewModelDto } from "../../../bridge/dto/graph";
import { useSelectionStore } from "../../../stores/selectionStore";
import { useUiStore } from "../../../stores/uiStore";
import {
  EdgeEvidencePanel,
  GraphCanvas,
  GraphFilters,
  GraphLegend,
  GraphPathPanel,
  GraphToolbar,
  GraphTypeSelector,
  graphViewBoundaryIssue,
  NodeDetailPanel,
  type GraphTypeOption,
  type RiskFilter,
  type TimeFilter,
} from "../../../shared/graph";
import { EmptyState } from "../../../shared/layout/EmptyState";
import { useDetachedPaneActions } from "../../../shared/layout/useDetachedPaneWindows";
import { useGraphViewQuery } from "../hooks";
import { NavigationContextPanel } from "../../navigation/components/NavigationContextPanel";
import { NavigationTargetButton } from "../../navigation/components/NavigationTargetButton";

const GRAPH_TYPES: GraphTypeOption[] = [
  { graphType: "incident_graph", label: "Incident Graph" },
  { graphType: "c2_graph", label: "C2 Graph" },
  { graphType: "exfiltration_graph", label: "Exfiltration Graph" },
  { graphType: "lateral_propagation_graph", label: "Lateral Propagation" },
  { graphType: "asset_exposure_graph", label: "Asset Exposure" },
  { graphType: "capability_dependency_graph", label: "Capability Dependency" },
  { graphType: "pipeline_graph", label: "Pipeline Graph" },
  { graphType: "response_impact_graph", label: "Response Impact" },
];

export function GraphWorkspace({ detached = false }: { readonly detached?: boolean }) {
  const [selectedGraphType, setSelectedGraphType] =
    useState<GraphTypeDto>("incident_graph");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [timeFilter, setTimeFilter] = useState<TimeFilter>("24h");
  const [nodeLimit, setNodeLimit] = useState(80);
  const [edgeLimit, setEdgeLimit] = useState(160);
  const selectedNodeId = useSelectionStore((state) => state.selectedGraphNodeId);
  const selectedEdgeId = useSelectionStore((state) => state.selectedGraphEdgeId);
  const setSelectedNodeId = useSelectionStore((state) => state.setSelectedGraphNodeId);
  const setSelectedEdgeId = useSelectionStore((state) => state.setSelectedGraphEdgeId);
  const graphDetached = useUiStore((state) => state.detachedPanes.graph);
  const { detachPane } = useDetachedPaneActions();

  const request = useMemo(
    () => ({
      graph_type: selectedGraphType,
      scope: {
        type: "overview",
      },
      title_redacted: titleForGraphType(selectedGraphType),
      node_limit: nodeLimit,
      edge_limit: edgeLimit,
    }),
    [edgeLimit, nodeLimit, selectedGraphType, timeFilter],
  );
  const graphQuery = useGraphViewQuery(request);
  const commandView = graphQuery.data ?? null;
  const hasCommandContent = Boolean(
    commandView &&
      (commandView.nodes.length || commandView.edges.length || commandView.paths.length),
  );
  const candidateView =
    commandView ?? emptyGraphView(selectedGraphType, nodeLimit, edgeLimit);
  const boundaryIssue = graphViewBoundaryIssue(candidateView);
  const view = boundaryIssue
    ? redactedGraphView(selectedGraphType, nodeLimit, edgeLimit)
    : candidateView;
  const sourceStatus = boundaryIssue
    ? "redacted"
    : hasCommandContent
      ? "command"
      : "empty";

  if (graphQuery.isError) {
    return (
      <EmptyState
        title="Graph read model unavailable"
        detail="The command bridge returned a redacted graph query error."
      />
    );
  }

  return (
    <div className="graph-workspace" data-detached={detached ? "true" : "false"}>
      <GraphTypeSelector
        graphTypes={GRAPH_TYPES}
        selectedGraphType={selectedGraphType}
        onSelectGraphType={(graphType) => {
          setSelectedGraphType(graphType);
          setSelectedNodeId(null);
          setSelectedEdgeId(null);
        }}
      />
      <main className="graph-workspace-main">
        <GraphToolbar
          edgeLimit={edgeLimit}
          loading={graphQuery.isLoading}
          nodeLimit={nodeLimit}
          sourceStatus={sourceStatus}
          view={view}
          detached={detached || graphDetached}
          onDetachGraph={
            detached
              ? undefined
              : () => {
                  void detachPane("graph");
                }
          }
          onExpandBounds={() => {
            setNodeLimit((limit) => Math.min(limit + 40, 240));
            setEdgeLimit((limit) => Math.min(limit + 80, 480));
          }}
        />
        <div className="graph-status-stack" aria-live="polite">
          {!hasCommandContent && graphQuery.data ? (
            <div className="graph-status-banner">
              <AlertTriangle size={15} aria-hidden="true" />
              <span>
                Command GraphViewModel is empty; no graph records are available for this view.
              </span>
            </div>
          ) : null}
          {boundaryIssue ? (
            <div className="graph-status-banner" data-state="redacted">
              <AlertTriangle size={15} aria-hidden="true" />
              <span>GraphViewModel boundary blocked; redacted empty view is rendered.</span>
            </div>
          ) : null}
        </div>
        <div className="graph-canvas-region">
          <GraphCanvas
            riskFilter={riskFilter}
            selectedEdgeId={selectedEdgeId}
            selectedNodeId={selectedNodeId}
            view={view}
            onSelectEdge={setSelectedEdgeId}
            onSelectNode={setSelectedNodeId}
          />
        </div>
      </main>
      <aside className="graph-workspace-detail">
        <GraphFilters
          riskFilter={riskFilter}
          timeFilter={timeFilter}
          onRiskFilterChange={setRiskFilter}
          onTimeFilterChange={setTimeFilter}
        />
        <GraphLegend view={view} />
        <GraphPathPanel view={view} />
        <div className="graph-node-strip" aria-label="Graph bounded navigation">
          {selectedNodeId ? (
            <NavigationTargetButton
              label="Open node links"
              sourceView="graph"
              targetId={selectedNodeId}
              targetKind="graph_node_summary"
            />
          ) : null}
          {selectedEdgeId ? (
            <NavigationTargetButton
              label="Open edge links"
              sourceView="graph"
              targetId={selectedEdgeId}
              targetKind="graph_edge_summary"
            />
          ) : null}
          {view.paths.slice(0, 4).map((path, index) => {
            const pathId = graphReferenceId(path, "path_id");
            return pathId ? (
              <NavigationTargetButton
                key={pathId}
                label={`Open path ${index + 1}`}
                sourceView="graph"
                targetId={pathId}
                targetKind="graph_path_summary"
              />
            ) : null;
          })}
        </div>
        <NodeDetailPanel selectedNodeId={selectedNodeId} view={view} />
        <EdgeEvidencePanel selectedEdgeId={selectedEdgeId} view={view} />
        <NavigationContextPanel />
      </aside>
    </div>
  );
}

function graphReferenceId(value: unknown, field: string) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const candidate = (value as Record<string, unknown>)[field];
  return typeof candidate === "string" ? candidate : null;
}

function redactedGraphView(
  graphType: GraphTypeDto,
  nodeLimit: number,
  edgeLimit: number,
): GraphViewModelDto {
  return {
    graph_id: `redacted:${graphType}`,
    graph_type: graphType,
    title: {
      value_redacted: `${titleForGraphType(graphType)} redacted`,
      privacy_class: "internal",
    },
    nodes: [],
    edges: [],
    paths: [],
    legend: {},
    filters: {
      scope: "overview",
      source: "redacted",
      bounded: true,
    },
    redaction_status: {
      status: "redacted",
      reason_redacted: "GraphViewModel boundary blocked",
    },
    node_limit: nodeLimit,
    edge_limit: edgeLimit,
    truncated: false,
  };
}

function emptyGraphView(
  graphType: GraphTypeDto,
  nodeLimit: number,
  edgeLimit: number,
): GraphViewModelDto {
  return {
    graph_id: `empty:${graphType}`,
    graph_type: graphType,
    title: {
      value_redacted: titleForGraphType(graphType),
      privacy_class: "internal",
    },
    nodes: [],
    edges: [],
    paths: [],
    legend: {},
    filters: {
      scope: "overview",
      source: "command",
      bounded: true,
    },
    redaction_status: {
      status: "passed",
      source: "command",
    },
    node_limit: nodeLimit,
    edge_limit: edgeLimit,
    truncated: false,
  };
}

function titleForGraphType(graphType: GraphTypeDto) {
  return (
    GRAPH_TYPES.find((option) => option.graphType === graphType)?.label ??
    String(graphType)
  );
}
