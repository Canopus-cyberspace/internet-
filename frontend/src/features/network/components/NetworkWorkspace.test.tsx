import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { NetworkPage } from "../../../pages/network/NetworkPage";
import { registerDefaultRenderers } from "../../../shared/renderers";
import {
  callClick,
  findByClassName,
  textContent,
} from "../../../shared/testing/reactElementQueries";
import {
  FlowTable,
  LocalConnectionGraphPanel,
  NetworkMetadataTable,
  NetworkViewTree,
} from "./NetworkWorkspace";

registerDefaultRenderers();

describe("Network workspace", () => {
  it("renders the page shell with metadata tables, graph, and detail drawer", () => {
    const markup = renderToStaticMarkup(withQueryClient(<NetworkPage />));

    expect(markup).toContain("Network");
    expect(markup).toContain("Flows");
    expect(markup).toContain("DNS");
    expect(markup).toContain("TLS");
    expect(markup).toContain("Processes");
    expect(markup).toContain("Assets");
    expect(markup).toContain("Local connection graph");
    expect(markup).toContain("Import Network Metadata");
    expect(markup).toContain("Local metadata proxy");
    expect(markup).toContain("AutoSecOps watch");
    expect(markup).toContain("Drop one .har or .jsonl file");
    expect(markup).toContain("127.0.0.1:&lt;port&gt;");
    expect(markup).toContain("Detail");
    expect(markup).toContain("Loading redacted network metadata.");
    expect(markup).not.toContain(mockOnlyMarker());
    expect(markup).not.toContain("powershell.exe");
    expect(markup).not.toContain("packet capture");
  });

  it("redacts sensitive flow table display strings", () => {
    const rows: Parameters<typeof FlowTable>[0]["rows"] = [
      {
        id: "flow:1",
        kind: "flow",
        primary: "raw_payload process",
        secondary: "session_token destination",
        protocol: "TLS",
        risk: "api_key_high",
        source: "command",
        raw: { flow_id: "flow:1" },
      },
    ];

    const markup = renderToStaticMarkup(
      <FlowTable
        rows={rows}
        selectedRowId={rows[0].id}
        onSelectRow={() => undefined}
      />,
    );

    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("raw_payload process");
    expect(markup).not.toContain("session_token destination");
    expect(markup).not.toContain("api_key_high");
  });

  it("keeps network view buttons and metadata rows clickable", () => {
    const onSelectView = vi.fn();
    const onSelectRow = vi.fn();
    const rows: Parameters<typeof FlowTable>[0]["rows"] = [
      {
        id: "flow:clickable",
        kind: "flow",
        primary: "powershell.exe",
        secondary: "redacted destination",
        protocol: "TLS",
        risk: "high",
        source: "command",
        raw: { flow_id: "flow:clickable" },
      },
    ];
    const viewTree = NetworkViewTree({
      activeView: "flows",
      counts: {
        assets: 1,
        dns: 1,
        flows: 1,
        processes: 1,
        tls: 1,
      },
      loading: false,
      onSelectView,
    });
    const flowTable = NetworkMetadataTable({
      columns: ["Process", "Destination", "Protocol", "Risk", "Source"],
      rows,
      selectedRowId: null,
      title: "Flows",
      onSelectRow,
    });

    const dnsButton = findByClassName(viewTree, "network-view-item").find(
      (element) => textContent(element).includes("DNS"),
    );
    const rowButton = findByClassName(flowTable, "network-row-button")[0];

    expect(dnsButton).toBeDefined();
    expect(rowButton).toBeDefined();
    callClick(dnsButton!);
    callClick(rowButton);

    expect(onSelectView).toHaveBeenCalledWith("dns");
    expect(onSelectRow).toHaveBeenCalledWith(rows[0]);
  });

  it("uses safe selected graph labels without selecting non-table graph nodes", () => {
    const rows: Parameters<typeof LocalConnectionGraphPanel>[0]["rows"] = [
      {
        id: "flow:1",
        kind: "flow",
        primary: "browser.exe",
        secondary: "redacted cloud service",
        protocol: "HTTPS",
        risk: "low",
        source: "command",
        raw: { flow_id: "flow:1" },
      },
    ];

    const markup = renderToStaticMarkup(
      withQueryClient(
        <LocalConnectionGraphPanel
          rows={rows}
          selectedEntityId="private_key_entity"
          selectedGraphNodeId="flow:1"
          onSelectGraphNode={() => undefined}
        />,
      ),
    );

    expect(markup).toContain("Local connection graph");
    expect(markup).toContain("redacted cloud service");
    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("private_key_entity");
  });

  it("renders a stable empty table state when command rows are absent", () => {
    const markup = renderToStaticMarkup(
      <NetworkMetadataTable
        columns={["Process", "Destination", "Protocol", "Risk", "Source"]}
        rows={[]}
        selectedRowId={null}
        title="Flows"
        onSelectRow={() => undefined}
      />,
    );

    expect(markup).toContain("0 rows");
    expect(markup).toContain("No flow observations are available from the command bridge.");
    expect(markup).not.toContain(mockOnlyMarker());
  });
});

function withQueryClient(element: ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return <QueryClientProvider client={queryClient}>{element}</QueryClientProvider>;
}

function mockOnlyMarker() {
  return ["MOCK", "ONLY"].join("_");
}
