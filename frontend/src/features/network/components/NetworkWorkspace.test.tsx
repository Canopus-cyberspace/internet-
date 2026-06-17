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
    expect(markup).toContain("Provider status");
    expect(markup).toContain("Native network providers are inactive.");
    expect(markup).toContain("Portable metadata analysis remains available.");
    expect(markup).toContain("IP Helper adapter supports explicit bounded execution.");
    expect(markup).toContain(
      "ETW read models expose bounded lifecycle health, counters, handoff refs, and fallback visibility.",
    );
    expect(markup).toContain("ETW product surface");
    expect(markup).toContain("Npcap enhancement is deferred.");
    expect(markup).toContain("Packet capture is unavailable.");
    expect(markup).toContain(
      "Enabled IP Helper commands: Activate, Sample once, Stop, Configure schedule, Enable schedule, Pause schedule, Resume schedule, Disable schedule.",
    );
    expect(markup).toContain("IP Helper sampling is explicit and bounded.");
    expect(markup).toContain("No packet capture is performed.");
    expect(markup).toContain("No process-to-network attribution is provided.");
    expect(markup).toContain(
      "IP Helper schedule control is session-bound; timer sampling remains explicit and bounded.",
    );
    expect(markup).toContain(
      "No ETW provider is automatically activated by reads, reports, exports, or UI refresh.",
    );
    expect(markup).toContain(
      "ETW starts only after explicit authorization. Automatic scheduling, packet visibility, process-network attribution, exact process identity, and response execution remain unavailable.",
    );
    expect(markup).toContain("Activate");
    expect(markup).toContain("Sample once");
    expect(markup).toContain("Stop");
    expect(markup).toContain("Configure schedule");
    expect(markup).toContain("Enable schedule");
    expect(markup).toContain("Pause schedule");
    expect(markup).toContain("Resume schedule");
    expect(markup).toContain("Disable schedule");
    expect(markup).toContain("Drop one .har or .jsonl file");
    expect(markup).toContain("127.0.0.1:&lt;port&gt;");
    expect(markup).toContain("Detail");
    expect(markup).toContain("Loading redacted network metadata.");
    expect(markup).not.toContain(mockOnlyMarker());
    expect(markup).not.toContain("powershell.exe");
    expect(markup).not.toContain("packet bytes");
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
