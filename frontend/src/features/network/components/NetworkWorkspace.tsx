import { Activity, Dna, Globe2, HardDrive, Network, Server } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { JsonValue } from "../../../bridge/dto/common";
import type { GraphViewModelDto } from "../../../bridge/dto/graph";
import type {
  DnsObservationDto,
  FlowRecordDto,
  TlsObservationDto,
} from "../../../bridge/dto/network";
import type { UiContributionDto } from "../../../bridge/dto/plugin";
import { useGraphViewQuery } from "../../graph/hooks";
import { useDnsQuery, useFlowsQuery, useTlsQuery } from "../hooks";
import { useSelectionStore } from "../../../stores/selectionStore";
import { EmptyState } from "../../../shared/layout/EmptyState";
import {
  isSensitiveKey,
  stringifySafe,
  UiContributionRenderer,
} from "../../../shared/renderers";
import { LocalMetadataProxyPanel } from "./LocalMetadataProxyPanel";
import { MetadataWatchPanel } from "./MetadataWatchPanel";
import { PortableCaptureImportPanel } from "./PortableCaptureImportPanel";
import { ProviderStatusPanel } from "./ProviderStatusPanel";

type NetworkView = "flows" | "dns" | "tls" | "processes" | "assets";
type NetworkKind = "flow" | "dns" | "tls" | "process" | "asset";

interface NetworkRow {
  readonly id: string;
  readonly kind: NetworkKind;
  readonly primary: string;
  readonly secondary: string;
  readonly protocol: string;
  readonly risk: string;
  readonly source: "command";
  readonly raw: JsonValue;
}

interface NetworkSelection {
  readonly selectedNetworkEntityId: string | null;
  readonly selectedGraphNodeId: string | null;
  readonly selectNetworkEntity: (row: NetworkRow) => void;
  readonly selectGraphNode: (nodeId: string, entityId?: string | null) => void;
}

export function NetworkWorkspace() {
  const flowsQuery = useFlowsQuery();
  const dnsQuery = useDnsQuery();
  const tlsQuery = useTlsQuery();
  const selection = useNetworkSelectionState();
  const [activeView, setActiveView] = useState<NetworkView>("flows");

  const commandFlowRows = useMemo(
    () => flowRows(flowsQuery.data?.items ?? []),
    [flowsQuery.data?.items],
  );
  const commandDnsRows = useMemo(
    () => dnsRows(dnsQuery.data?.items ?? []),
    [dnsQuery.data?.items],
  );
  const commandTlsRows = useMemo(
    () => tlsRows(tlsQuery.data?.items ?? []),
    [tlsQuery.data?.items],
  );

  const flows = commandFlowRows;
  const dns = commandDnsRows;
  const tls = commandTlsRows;
  const processes = processRows(flows);
  const assets = assetRows(flows, dns, tls);
  const rowsByView = { flows, dns, tls, processes, assets } satisfies Record<
    NetworkView,
    NetworkRow[]
  >;
  const activeRows = rowsByView[activeView];
  const selectedRowInActiveView =
    activeRows.find((row) => row.id === selection.selectedNetworkEntityId) ?? null;
  const selectedRow = selectedRowInActiveView ?? activeRows[0] ?? null;

  useEffect(() => {
    if (selectedRow && selectedRow.id !== selection.selectedNetworkEntityId) {
      selection.selectNetworkEntity(selectedRow);
    }
  }, [selectedRow, selection]);
  const loading = flowsQuery.isLoading || dnsQuery.isLoading || tlsQuery.isLoading;
  const error = flowsQuery.isError || dnsQuery.isError || tlsQuery.isError;

  if (error) {
    return (
      <EmptyState
        title="Network read model unavailable"
        detail="The command bridge returned a redacted query error."
      />
    );
  }

  return (
    <div className="network-workspace">
      <NetworkViewTree
        activeView={activeView}
        counts={{
          flows: flows.length,
          dns: dns.length,
          tls: tls.length,
          processes: processes.length,
          assets: assets.length,
        }}
        loading={loading}
        onSelectView={setActiveView}
      />
      <main className="network-main">
        {activeView === "flows" ? (
          <FlowTable
            rows={flows}
            loading={loading}
            selectedRowId={selectedRow?.id ?? null}
            onSelectRow={selection.selectNetworkEntity}
          />
        ) : null}
        {activeView === "dns" ? (
          <DnsTable
            rows={dns}
            loading={loading}
            selectedRowId={selectedRow?.id ?? null}
            onSelectRow={selection.selectNetworkEntity}
          />
        ) : null}
        {activeView === "tls" ? (
          <TlsTable
            rows={tls}
            loading={loading}
            selectedRowId={selectedRow?.id ?? null}
            onSelectRow={selection.selectNetworkEntity}
          />
        ) : null}
        {activeView === "processes" ? (
          <ProcessTable
            rows={processes}
            loading={loading}
            selectedRowId={selectedRow?.id ?? null}
            onSelectRow={selection.selectNetworkEntity}
          />
        ) : null}
        {activeView === "assets" ? (
          <AssetExposureTable
            rows={assets}
            loading={loading}
            selectedRowId={selectedRow?.id ?? null}
            onSelectRow={selection.selectNetworkEntity}
          />
        ) : null}
        <LocalConnectionGraphPanel
          rows={[...flows, ...dns, ...tls]}
          selectedEntityId={selectedRow?.id ?? null}
          selectedGraphNodeId={selection.selectedGraphNodeId}
          onSelectGraphNode={selection.selectGraphNode}
        />
      </main>
      <div className="network-side-stack">
        <ProviderStatusPanel />
        <PortableCaptureImportPanel />
        <LocalMetadataProxyPanel />
        <MetadataWatchPanel />
        <NetworkDetailPanel row={selectedRow} />
      </div>
    </div>
  );
}

export function useNetworkSelectionState(): NetworkSelection {
  const selectedNetworkEntityId = useSelectionStore(
    (state) => state.selectedNetworkEntityId,
  );
  const selectedGraphNodeId = useSelectionStore((state) => state.selectedGraphNodeId);
  const setSelectedNetworkEntityId = useSelectionStore(
    (state) => state.setSelectedNetworkEntityId,
  );
  const setSelectedGraphNodeId = useSelectionStore(
    (state) => state.setSelectedGraphNodeId,
  );

  return useMemo(
    () => ({
      selectedNetworkEntityId,
      selectedGraphNodeId,
      selectNetworkEntity: (row: NetworkRow) => {
        setSelectedNetworkEntityId(row.id);
        setSelectedGraphNodeId(row.id);
      },
      selectGraphNode: (nodeId: string, entityId?: string | null) => {
        setSelectedGraphNodeId(nodeId);
        if (entityId) {
          setSelectedNetworkEntityId(entityId);
        }
      },
    }),
    [
      selectedGraphNodeId,
      selectedNetworkEntityId,
      setSelectedGraphNodeId,
      setSelectedNetworkEntityId,
    ],
  );
}

interface NetworkViewTreeProps {
  readonly activeView: NetworkView;
  readonly counts: Record<NetworkView, number>;
  readonly loading: boolean;
  readonly onSelectView: (view: NetworkView) => void;
}

export function NetworkViewTree({
  activeView,
  counts,
  loading,
  onSelectView,
}: NetworkViewTreeProps) {
  const views: Array<{ id: NetworkView; label: string; icon: typeof Network }> = [
    { id: "flows", label: "Flows", icon: Network },
    { id: "dns", label: "DNS", icon: Globe2 },
    { id: "tls", label: "TLS", icon: Dna },
    { id: "processes", label: "Processes", icon: Server },
    { id: "assets", label: "Assets", icon: HardDrive },
  ];

  return (
    <aside className="network-view-tree">
      <div className="analysis-panel-header">
        <strong>Views</strong>
        <span>{loading ? "loading" : "metadata"}</span>
      </div>
      <div className="network-view-list">
        {views.map((view) => {
          const Icon = view.icon;
          return (
            <button
              className="network-view-item"
              data-selected={activeView === view.id}
              key={view.id}
              type="button"
              onClick={() => onSelectView(view.id)}
            >
              <Icon size={14} aria-hidden="true" />
              <span>{view.label}</span>
              <small>{counts[view.id]}</small>
            </button>
          );
        })}
      </div>
    </aside>
  );
}

interface NetworkTableProps {
  readonly loading?: boolean;
  readonly rows: NetworkRow[];
  readonly selectedRowId: string | null;
  readonly onSelectRow: (row: NetworkRow) => void;
}

export function FlowTable(props: NetworkTableProps) {
  return (
    <NetworkMetadataTable
      {...props}
      columns={["Process", "Destination", "Protocol", "Risk", "Source"]}
      title="Flows"
    />
  );
}

export function DnsTable(props: NetworkTableProps) {
  return (
    <NetworkMetadataTable
      {...props}
      columns={["Query", "Answers", "Protocol", "Risk", "Source"]}
      title="DNS"
    />
  );
}

export function TlsTable(props: NetworkTableProps) {
  return (
    <NetworkMetadataTable
      {...props}
      columns={["Server", "Certificate", "Protocol", "Risk", "Source"]}
      title="TLS"
    />
  );
}

export function ProcessTable(props: NetworkTableProps) {
  return (
    <NetworkMetadataTable
      {...props}
      columns={["Process", "Connections", "Protocol", "Risk", "Source"]}
      title="Processes"
    />
  );
}

export function AssetExposureTable(props: NetworkTableProps) {
  return (
    <NetworkMetadataTable
      {...props}
      columns={["Asset", "Exposure", "Protocol", "Risk", "Source"]}
      title="Assets"
    />
  );
}

interface NetworkMetadataTableProps extends NetworkTableProps {
  readonly title: string;
  readonly columns: readonly [string, string, string, string, string];
}

export function NetworkMetadataTable({
  title,
  columns,
  rows,
  loading = false,
  selectedRowId,
  onSelectRow,
}: NetworkMetadataTableProps) {
  return (
    <section className="analysis-panel network-table-panel">
      <div className="analysis-panel-header">
        <strong>{title}</strong>
        <span>{rows.length} rows</span>
      </div>
      <div className="network-table scroll-region table-scroll-region" role="table">
        <div className="network-table-row header" role="row">
          {columns.map((column) => (
            <div role="columnheader" key={column}>
              {column}
            </div>
          ))}
        </div>
        {rows.length === 0 ? (
          <div className="network-table-row network-table-empty" role="row">
            <div role="cell">
              {loading
                ? "Loading redacted network metadata."
                : emptyNetworkMessage(title)}
            </div>
          </div>
        ) : null}
        {rows.map((row) => (
          <div
            className="network-table-row"
            data-selected={selectedRowId === row.id}
            data-severity={severityLevel(row.risk)}
            key={row.id}
            role="row"
          >
            <button
              className="network-row-button"
              type="button"
              onClick={() => onSelectRow(row)}
            >
              <span>{displayText(row.primary, "metadata")}</span>
              <small>{row.kind}</small>
            </button>
            <div role="cell">{displayText(row.secondary, "metadata")}</div>
            <div role="cell">{displayText(row.protocol, "metadata")}</div>
            <div role="cell">
              <span className="analysis-severity-pill" data-severity={severityLevel(row.risk)}>
                {displayText(row.risk, "low")}
              </span>
            </div>
            <div role="cell">{row.source}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

interface LocalConnectionGraphPanelProps {
  readonly rows: NetworkRow[];
  readonly selectedEntityId: string | null;
  readonly selectedGraphNodeId: string | null;
  readonly onSelectGraphNode: (nodeId: string, entityId?: string | null) => void;
}

export function LocalConnectionGraphPanel({
  rows,
  selectedEntityId,
  selectedGraphNodeId,
  onSelectGraphNode,
}: LocalConnectionGraphPanelProps) {
  const request = useMemo(
    () => ({
      graph_type: "asset_exposure_graph",
      scope: "overview",
      title_redacted: "Local connection graph",
      node_limit: 80,
      edge_limit: 160,
    }),
    [],
  );
  const graphQuery = useGraphViewQuery(request);
  const graph = graphQuery.data && graphQuery.data.nodes.length
    ? graphQuery.data
    : localConnectionProjection(rows);
  const nodes = graph.nodes.filter(isRecord);
  const tableEntityIds = useMemo(() => new Set(rows.map((row) => row.id)), [rows]);

  return (
    <section className="analysis-panel local-connection-panel">
      <div className="analysis-panel-header">
        <strong>Local connection graph</strong>
        <span>{displayText(selectedEntityId, "overview")}</span>
      </div>
      <UiContributionRenderer
        contribution={contribution("network-local-graph", "graph_projection", "Local connection graph")}
        data={graph as unknown as JsonValue}
      />
      <div className="graph-node-strip">
        {nodes.slice(0, 12).map((node, index) => {
          const nodeId = stringField(node, "node_id") ?? stringField(node, "id") ?? `${index}`;
          return (
            <button
              className="graph-node-chip"
              data-selected={selectedGraphNodeId === nodeId}
              key={nodeId}
              type="button"
              onClick={() =>
                onSelectGraphNode(nodeId, tableEntityIds.has(nodeId) ? nodeId : null)
              }
            >
              <span>
                {stringField(node, "label") ??
                  stringField(node, "node_type") ??
                  "Node"}
              </span>
            </button>
          );
        })}
      </div>
    </section>
  );
}

function NetworkDetailPanel({ row }: { readonly row: NetworkRow | null }) {
  return (
    <aside className="network-detail-panel">
      <div className="analysis-panel-header">
        <strong>Detail</strong>
        <Activity size={15} aria-hidden="true" />
      </div>
      {row ? (
        <dl className="network-detail-list">
          <div>
            <dt>Kind</dt>
            <dd>{row.kind}</dd>
          </div>
          <div>
            <dt>Primary</dt>
            <dd>{displayText(row.primary, "metadata")}</dd>
          </div>
          <div>
            <dt>Secondary</dt>
            <dd>{displayText(row.secondary, "metadata")}</dd>
          </div>
          <div>
            <dt>Protocol</dt>
            <dd>{displayText(row.protocol, "metadata")}</dd>
          </div>
          <div>
            <dt>Source</dt>
            <dd>{row.source}</dd>
          </div>
        </dl>
      ) : (
        <span className="analysis-muted">No network row selected</span>
      )}
    </aside>
  );
}

function flowRows(flows: FlowRecordDto[]): NetworkRow[] {
  return flows.map((flow, index) => ({
    id: `flow:${entityIdFor(flow, "flow_id", index)}`,
    kind: "flow",
    primary: safeText(flow.process_ref, "unknown process"),
    secondary: displayText(
      flow.destination_redacted ?? stringField(flow, "destination"),
      "redacted destination",
    ),
    protocol: displayText(
      flow.protocol ?? stringField(flow, "transport_protocol"),
      "metadata",
    ),
    risk: riskLabel(flow.risk_score),
    source: "command",
    raw: flow as unknown as JsonValue,
  }));
}

function dnsRows(dns: DnsObservationDto[]): NetworkRow[] {
  return dns.map((record, index) => ({
    id: `dns:${entityIdFor(record, "dns_id", index)}`,
    kind: "dns",
    primary: displayText(record.query_name_redacted, "redacted query"),
    secondary: displayText(record.answer_summary_redacted, "redacted answers"),
    protocol: "DNS",
    risk: riskLabel(valueFor(record, "risk_score")),
    source: "command",
    raw: record as unknown as JsonValue,
  }));
}

function tlsRows(tls: TlsObservationDto[]): NetworkRow[] {
  return tls.map((record, index) => ({
    id: `tls:${entityIdFor(record, "tls_id", index)}`,
    kind: "tls",
    primary: displayText(record.server_name_redacted, "redacted server"),
    secondary: displayText(
      record.certificate_summary_redacted,
      "redacted certificate",
    ),
    protocol: "TLS",
    risk: riskLabel(valueFor(record, "risk_score")),
    source: "command",
    raw: record as unknown as JsonValue,
  }));
}

function processRows(flows: NetworkRow[]): NetworkRow[] {
  const byProcess = new Map<string, NetworkRow[]>();
  for (const flow of flows) {
    const process = flow.primary || "unknown process";
    byProcess.set(process, [...(byProcess.get(process) ?? []), flow]);
  }
  return [...byProcess.entries()].map(([process, rows], index) => ({
    id: `process:${index}`,
    kind: "process",
    primary: process,
    secondary: `${rows.length} connection${rows.length === 1 ? "" : "s"}`,
    protocol: unique(rows.map((row) => row.protocol)).join(", "),
    risk: highestRisk(rows.map((row) => row.risk)),
    source: "command",
    raw: {
      process_ref: process,
      connection_count: rows.length,
    },
  }));
}

function assetRows(
  flows: NetworkRow[],
  dns: NetworkRow[],
  tls: NetworkRow[],
): NetworkRow[] {
  const sourceRows = [...flows, ...dns, ...tls];
  const byAsset = new Map<string, NetworkRow[]>();
  for (const row of sourceRows) {
    const asset = row.kind === "flow" ? row.secondary : row.primary;
    byAsset.set(asset, [...(byAsset.get(asset) ?? []), row]);
  }
  return [...byAsset.entries()].map(([asset, rows], index) => ({
    id: `asset:${index}`,
    kind: "asset",
    primary: asset,
    secondary: `${rows.length} metadata observation${rows.length === 1 ? "" : "s"}`,
    protocol: unique(rows.map((row) => row.protocol)).join(", "),
    risk: highestRisk(rows.map((row) => row.risk)),
    source: "command",
    raw: {
      asset_redacted: asset,
      observation_count: rows.length,
    },
  }));
}

function localConnectionProjection(rows: NetworkRow[]): GraphViewModelDto {
  const visibleRows = rows.slice(0, 10);
  return {
    graph_id: "network:local-connection",
    graph_type: "asset_exposure_graph",
    title: { value_redacted: "Local connection graph", privacy_class: "internal" },
    nodes: [
      { id: "local-host", label: "Local host", node_type: "host" },
      ...visibleRows.map((row) => ({
        id: row.id,
        label: displayText(row.kind === "flow" ? row.secondary : row.primary, "Entity"),
        node_type: row.kind,
        status: row.risk,
      })),
    ],
    edges: visibleRows.map((row) => ({
      id: `local-host->${row.id}`,
      source: "local-host",
      target: row.id,
      label: row.protocol,
    })),
    paths: [],
    filters: { scope: "overview" },
    redaction_status: { status: "passed" },
    node_limit: 80,
    edge_limit: 160,
    truncated: false,
  };
}

function contribution(
  id: string,
  rendererType: string,
  title: string,
): UiContributionDto {
  return {
    contribution_id: id,
    plugin_id: "frontend:network",
    slot: "network.panel",
    renderer_type: rendererType,
    title,
  };
}

function entityIdFor(value: unknown, idKey: string, index: number) {
  return stringField(value, idKey) ?? stringField(value, "id") ?? `${idKey}:${index}`;
}

function emptyNetworkMessage(title: string) {
  switch (title) {
    case "Flows":
      return "No flow observations are available from the command bridge.";
    case "DNS":
      return "No DNS observations are available from the command bridge.";
    case "TLS":
      return "No TLS observations are available from the command bridge.";
    case "Processes":
      return "No process connection summaries are available from command-backed flow rows.";
    case "Assets":
      return "No asset exposure summaries are available from command-backed observations.";
    default:
      return "No network metadata is available from the command bridge.";
  }
}

function riskLabel(value: unknown) {
  if (typeof value === "number") {
    if (value >= 80) {
      return "high";
    }
    if (value >= 40) {
      return "medium";
    }
    return "low";
  }
  if (typeof value === "string") {
    return displayText(value, "low");
  }
  return "low";
}

function highestRisk(values: string[]) {
  if (values.some((value) => severityLevel(value) === "critical")) {
    return "critical";
  }
  if (values.some((value) => severityLevel(value) === "high")) {
    return "high";
  }
  if (values.some((value) => severityLevel(value) === "medium")) {
    return "medium";
  }
  return "low";
}

function severityLevel(value: string): "low" | "medium" | "high" | "critical" {
  const normalized = value.toLowerCase();
  if (normalized.includes("critical")) {
    return "critical";
  }
  if (normalized.includes("high")) {
    return "high";
  }
  if (normalized.includes("medium") || normalized.includes("warning")) {
    return "medium";
  }
  return "low";
}

function safeText(value: unknown, fallback: string) {
  if (typeof value === "string") {
    return displayText(value, fallback);
  }
  return fallback;
}

function stringField(value: unknown, key: string): string | null {
  const nested = valueFor(value, key);
  if (typeof nested === "string") {
    return displayText(nested, "");
  }
  if (isRecord(nested)) {
    return (
      stringField(nested, "value_redacted") ??
      stringField(nested, "value") ??
      stringField(nested, "id") ??
      stringField(nested, "name")
    );
  }
  return null;
}

function valueFor(value: unknown, key: string): unknown {
  if (!isRecord(value) || isSensitiveKey(key)) {
    return undefined;
  }
  return value[key];
}

function isRecord(value: unknown): value is Record<string, JsonValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unique(values: string[]) {
  return [...new Set(values.filter(Boolean))];
}

function displayText(value: JsonValue | undefined | null, fallback: string) {
  if (value === undefined || value === null) {
    return fallback;
  }
  const safe = stringifySafe(value);
  return safe.length ? safe : fallback;
}
