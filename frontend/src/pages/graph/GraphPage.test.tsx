import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement, ReactNode } from "react";
import { isValidElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";
import type { GraphViewModelDto } from "../../bridge/dto/graph";
import { queryKeys } from "../../bridge/queryKeys";
import {
  openDetachedPane,
  setDetachedWindowBridgeForTests,
  type DetachedPaneWindowOptions,
} from "../../bridge/detachedWindows";
import { setInvokeCoreForTests } from "../../bridge/tauri/invoke";
import { EdgeEvidencePanel, GraphToolbar } from "../../shared/graph";
import { GraphPage } from "./GraphPage";

describe("Graph page detach control", () => {
  afterEach(() => {
    setInvokeCoreForTests(null);
    setDetachedWindowBridgeForTests({
      create: null,
      emitTo: null,
      getByLabel: null,
      listen: null,
    });
  });

  it("renders a visible detach button and routes it through the detached window bridge", async () => {
    const createdWindows: Array<{
      label: string;
      options: DetachedPaneWindowOptions;
    }> = [];
    let detachPromise: Promise<unknown> | null = null;

    setInvokeCoreForTests(async <T,>() => emptyGraphView() as T);
    setDetachedWindowBridgeForTests({
      create: (label, options) => {
        createdWindows.push({ label, options });
        return testNativeWindow(label);
      },
      emitTo: async () => undefined,
      getByLabel: async () => null,
      listen: async () => () => undefined,
    });

    const pageMarkup = renderToStaticMarkup(withQueryClient(<GraphPage />));
    expect(pageMarkup).toContain("Detach");

    const toolbar = GraphToolbar({
      edgeLimit: 160,
      loading: false,
      nodeLimit: 80,
      sourceStatus: "command",
      view: emptyGraphView(),
      onDetachGraph: () => {
        detachPromise = openDetachedPane("graph");
      },
      onExpandBounds: () => undefined,
    });
    const detachButton = findButtonByTitle(toolbar, "Detach graph");

    detachButton.props.onClick();
    await detachPromise;

    expect(createdWindows).toEqual([
      {
        label: "detached-graph",
        options: expect.objectContaining({
          title: "Sentinel Guard - Graph",
          url: "/detached/graph",
          width: 1180,
          minWidth: 900,
        }),
      },
    ]);
  });

  it("renders an honest empty GraphViewModel without preview records", () => {
    const markup = renderToStaticMarkup(
      withQueryClient(<GraphPage />, (queryClient) => {
        queryClient.setQueryData(graphQueryKey(), emptyGraphView());
      }),
    );

    expect(markup).toContain("Command GraphViewModel is empty");
    expect(markup).toContain("No graph nodes");
    expect(markup).not.toContain(mockOnlyMarker());
  });

  it("renders command GraphViewModel nodes, edges, paths, and evidence metadata", () => {
    const view = commandGraphView();
    const markup = [
      renderToStaticMarkup(
        withQueryClient(<GraphPage />, (queryClient) => {
          queryClient.setQueryData(graphQueryKey(), view);
        }),
      ),
      renderToStaticMarkup(
        <EdgeEvidencePanel selectedEdgeId="edge:command" view={view} />,
      ),
    ].join("");

    expect(markup).toContain("Nodes 2");
    expect(markup).toContain("Edges 1");
    expect(markup).toContain("Paths 1");
    expect(markup).toContain("Command-backed process");
    expect(markup).toContain("Command-backed process to incident path");
    expect(markup).toContain("evidence:command");
    expect(markup).not.toContain(mockOnlyMarker());
  });
});

function withQueryClient(
  element: ReactElement,
  seed?: (queryClient: QueryClient) => void,
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  seed?.(queryClient);
  return <QueryClientProvider client={queryClient}>{element}</QueryClientProvider>;
}

function findButtonByTitle(node: ReactNode, title: string): ReactElement<{
  readonly onClick: () => void;
  readonly title?: string;
}> {
  if (isValidElement(node)) {
    const props = node.props as {
      readonly children?: ReactNode;
      readonly onClick?: () => void;
      readonly title?: string;
    };
    if (node.type === "button" && props.title === title && props.onClick) {
      return node as ReactElement<{
        readonly onClick: () => void;
        readonly title?: string;
      }>;
    }

    const children = props.children;
    const childList = Array.isArray(children) ? children : [children];
    for (const child of childList) {
      try {
        const found = findButtonByTitle(child, title);
        return found;
      } catch {
        // Keep scanning siblings until the requested button is found.
      }
    }
  }

  throw new Error(`Button with title "${title}" was not found`);
}

function emptyGraphView(): GraphViewModelDto {
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
  };
}

function commandGraphView(): GraphViewModelDto {
  return {
    graph_id: "graph:command",
    graph_type: "incident_graph",
    title: { value_redacted: "Command-backed incident graph", privacy_class: "internal" },
    nodes: [
      {
        id: "process:command",
        node_type: "process",
        label: "Command-backed process",
        privacy_class: "internal",
      },
      {
        id: "incident:command",
        node_type: "incident",
        label: "Command-backed incident",
        privacy_class: "internal",
      },
    ],
    edges: [
      {
        id: "edge:command",
        source: "process:command",
        target: "incident:command",
        edge_type: "finding_supports_incident",
        evidence_refs: ["evidence:command"],
        privacy_class: "internal",
      },
    ],
    paths: [
      {
        path_id: "path:command",
        title_redacted: "Command-backed process to incident path",
        node_refs: ["process:command", "incident:command"],
      },
    ],
    legend: { process: "Command-backed process" },
    filters: { scope: "overview" },
    redaction_status: { status: "passed" },
    node_limit: 80,
    edge_limit: 160,
    truncated: false,
  };
}

function graphQueryKey() {
  return queryKeys.graph.view(
    "incident_graph",
    JSON.stringify({ type: "overview" }),
  );
}

function mockOnlyMarker() {
  return ["MOCK", "ONLY"].join("_");
}

function testNativeWindow(label: string) {
  return {
    label,
    async show() {
      return undefined;
    },
    async setFocus() {
      return undefined;
    },
    async close() {
      return undefined;
    },
    async once<T>(event: string, handler: (event: { payload: T }) => void) {
      if (event === "tauri://created") {
        queueMicrotask(() => handler({ payload: null as T }));
      }
      return () => undefined;
    },
  };
}
