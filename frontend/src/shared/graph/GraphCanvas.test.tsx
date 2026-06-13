import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { GraphViewModelDto } from "../../bridge/dto/graph";
import {
  EdgeEvidencePanel,
  GraphCanvas,
  GraphFilters,
  GraphLegend,
  GraphPathPanel,
  GraphToolbar,
  GraphTypeSelector,
  NodeDetailPanel,
  graphViewBoundaryIssue,
} from ".";

describe("GraphViewModel renderer panels", () => {
  it("renders paths, node detail, and edge evidence without exposing sensitive markers", () => {
    const view = graphView({
      nodes: [
        {
          node_id: "node:process",
          node_type: "process",
          label: "session_token process label",
          risk_score: 72,
          status: "watch",
          privacy_class: "internal",
          detail_ref: "incident:1",
        },
      ],
      edges: [
        {
          edge_id: "edge:evidence",
          source: "node:process",
          target: "node:finding",
          edge_type: "process_queries_domain",
          label: "cookie edge label",
          confidence: "high",
          evidence_refs: ["api_key_evidence_ref"],
          privacy_class: "internal",
        },
      ],
      paths: [
        {
          path_id: "path:1",
          title_redacted: "private_key path title",
          node_refs: ["node:process", "raw_payload_node"],
          path_type: "process_to_c2_path",
        },
      ],
    });

    const markup = [
      renderToStaticMarkup(<GraphPathPanel view={view} />),
      renderToStaticMarkup(
        <NodeDetailPanel selectedNodeId="node:process" view={view} />,
      ),
      renderToStaticMarkup(
        <EdgeEvidencePanel selectedEdgeId="edge:evidence" view={view} />,
      ),
    ].join("");

    expect(markup).toContain("Paths");
    expect(markup).toContain("Node detail");
    expect(markup).toContain("Edge evidence");
    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("session_token process label");
    expect(markup).not.toContain("cookie edge label");
    expect(markup).not.toContain("private_key path title");
    expect(markup).not.toContain("raw_payload_node");
    expect(markup).not.toContain("api_key_evidence_ref");
  });

  it("renders toolbar, legend, and filters with bounded redaction metadata", () => {
    const view = graphView({
      legend: {
        process: "Local process",
        session_token_legend: "raw_payload legend value",
      },
      redaction_status: { status: "redacted" },
      truncated: true,
    });

    const markup = [
      renderToStaticMarkup(
        <GraphToolbar
          edgeLimit={160}
          loading={false}
          nodeLimit={80}
          sourceStatus="redacted"
          view={view}
          onExpandBounds={() => undefined}
        />,
      ),
      renderToStaticMarkup(<GraphLegend view={view} />),
      renderToStaticMarkup(
        <GraphFilters
          riskFilter="high_plus"
          timeFilter="24h"
          onRiskFilterChange={() => undefined}
          onTimeFilterChange={() => undefined}
        />,
      ),
    ].join("");

    expect(markup).toContain("redacted");
    expect(markup).toContain("truncated");
    expect(markup).toContain("Local process");
    expect(markup).toContain("Last 24h");
    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("session_token_legend");
    expect(markup).not.toContain("raw_payload legend value");
  });

  it("represents every required graph type in the selector", () => {
    const graphTypes = [
      { graphType: "incident_graph", label: "Incident Graph" },
      { graphType: "c2_graph", label: "C2 Graph" },
      { graphType: "exfiltration_graph", label: "Exfiltration Graph" },
      { graphType: "lateral_propagation_graph", label: "Lateral Propagation" },
      { graphType: "asset_exposure_graph", label: "Asset Exposure" },
      { graphType: "capability_dependency_graph", label: "Capability Dependency" },
      { graphType: "pipeline_graph", label: "Pipeline Graph" },
      { graphType: "response_impact_graph", label: "Response Impact" },
    ] as const;

    const markup = renderToStaticMarkup(
      <GraphTypeSelector
        graphTypes={graphTypes}
        selectedGraphType="incident_graph"
        onSelectGraphType={() => undefined}
      />,
    );

    for (const option of graphTypes) {
      expect(markup).toContain(option.label);
    }
  });

  it("rejects canonical graph internals before rendering", () => {
    expect(
      graphViewBoundaryIssue(
        graphView({
          nodes: [
            {
              node_id: "node:1",
              node_type: "process",
              label: "safe label",
              canonical_node: { internal_id: "node-store-row" },
            },
          ],
        }),
      ),
    ).toBe("canonical graph internals blocked");
  });

  it("does not expose pane drag-out detach handles from the graph canvas", () => {
    const markup = renderToStaticMarkup(
      <GraphCanvas
        riskFilter="all"
        selectedEdgeId={null}
        selectedNodeId={null}
        view={graphView({})}
        onSelectEdge={() => undefined}
        onSelectNode={() => undefined}
      />,
    );

    expect(markup).toContain("graph-empty-state");
    expect(markup).not.toContain("data-drag-out-detach-handle");
  });
});

function graphView(overrides: Partial<GraphViewModelDto>): GraphViewModelDto {
  return {
    graph_id: "graph:test",
    graph_type: "incident_graph",
    title: { value_redacted: "Incident graph", privacy_class: "internal" },
    nodes: [],
    edges: [],
    paths: [],
    legend: {},
    filters: { scope: "overview" },
    redaction_status: { status: "passed" },
    node_limit: 80,
    edge_limit: 160,
    truncated: false,
    ...overrides,
  };
}
