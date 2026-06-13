import {
  AlertTriangle,
  BarChart3,
  FileText,
  GitBranch,
  HeartPulse,
  History,
  ListChecks,
  ShieldCheck,
} from "lucide-react";
import type { JsonValue } from "../../bridge/dto/common";
import { ShellTable } from "../table/ShellTable";
import {
  asRecordArray,
  humanize,
  safeEntries,
  stringifySafe,
  stringifySafeForKey,
  tableColumns,
} from "./schemaGuards";
import type { RendererContext, RendererPanelProps } from "./types";

function RendererPanel({ title, subtitle, children }: RendererPanelProps) {
  return (
    <section className="renderer-panel">
      <header className="renderer-panel-header">
        <div>
          <strong>{title}</strong>
          {subtitle ? <span>{subtitle}</span> : null}
        </div>
      </header>
      <div className="renderer-panel-body">{children}</div>
    </section>
  );
}

export function GenericKeyValueRenderer({ contribution, data }: RendererContext) {
  return (
    <RendererPanel title={contribution.title} subtitle="Key value">
      <dl className="renderer-kv-list">
        {safeEntries(data.value).map(([key, value]) => (
          <div key={key}>
            <dt>{humanize(key)}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </RendererPanel>
  );
}

export function GenericTableRenderer({ contribution, data }: RendererContext) {
  const rows = asRecordArray(data.value);
  const columns = tableColumns(rows);
  const tableRows = rows.map((row, index) => ({
    id: String(row.id ?? row.finding_id ?? row.evidence_id ?? index),
    cells: Object.fromEntries(
      columns.map((column) => [
        column.key,
        stringifySafeForKey(column.key, row[column.key] ?? null),
      ]),
    ),
  }));

  return (
    <RendererPanel title={contribution.title} subtitle="Table">
      {columns.length ? (
        <ShellTable columns={columns} rows={tableRows} />
      ) : (
        <span className="renderer-muted">No tabular metadata</span>
      )}
    </RendererPanel>
  );
}

export function GenericFindingRenderer(context: RendererContext) {
  const rows = asRecordArray(context.data.value);
  return (
    <RendererPanel title={context.contribution.title} subtitle="Findings">
      <div className="renderer-list">
        {rows.map((row, index) => (
          <div className="renderer-list-item" key={String(row.finding_id ?? index)}>
            <ShieldCheck size={15} aria-hidden="true" />
            <div>
              <strong>
                {stringifySafe(row.finding_type ?? row.title ?? "Finding")}
              </strong>
              <span>{stringifySafe(row.summary_redacted ?? "Redacted finding")}</span>
            </div>
          </div>
        ))}
      </div>
    </RendererPanel>
  );
}

export function GenericEvidenceRenderer(context: RendererContext) {
  const rows = asRecordArray(context.data.value);
  return (
    <RendererPanel title={context.contribution.title} subtitle="Evidence">
      <div className="renderer-list">
        {rows.map((row, index) => (
          <div className="renderer-list-item" key={String(row.evidence_id ?? index)}>
            <ListChecks size={15} aria-hidden="true" />
            <div>
              <strong>{stringifySafe(row.evidence_type ?? "Evidence")}</strong>
              <span>{stringifySafe(row.summary_redacted ?? "Redacted evidence")}</span>
            </div>
          </div>
        ))}
      </div>
    </RendererPanel>
  );
}

export function GenericGraphNodeRenderer(context: RendererContext) {
  const value = context.data.value;
  const nodes = graphArray(value, "nodes");
  return (
    <RendererPanel title={context.contribution.title} subtitle="Graph nodes">
      <div className="renderer-node-list">
        {nodes.slice(0, 10).map((node, index) => (
          <span key={String(node.node_id ?? node.id ?? index)}>
            {stringifySafe(node.label ?? node.node_type ?? "Graph node")}
          </span>
        ))}
      </div>
    </RendererPanel>
  );
}

export function GenericMetricListRenderer(context: RendererContext) {
  const rows = asRecordArray(context.data.value);
  return (
    <RendererPanel title={context.contribution.title} subtitle="Metrics">
      <div className="renderer-metric-list">
        {rows.map((row, index) => (
          <div key={String(row.metric_name ?? index)}>
            <BarChart3 size={15} aria-hidden="true" />
            <strong>{stringifySafe(row.metric_name ?? row.name ?? "metric")}</strong>
            <span>{stringifySafe(row.value ?? row.summary ?? "updated")}</span>
          </div>
        ))}
      </div>
    </RendererPanel>
  );
}

export function UnsupportedContributionRenderer({
  contribution,
  data,
}: RendererContext) {
  const fallbackKind = classifyFallback(data.value);
  return (
    <RendererPanel title={contribution.title} subtitle="Unsupported renderer">
      <div className="renderer-warning">
        <AlertTriangle size={16} aria-hidden="true" />
        <span>
          {contribution.renderer_type} is not registered. Metadata is shown in a
          safe generic view.
        </span>
      </div>
      <UnsupportedFallbackBody kind={fallbackKind} value={data.value} />
    </RendererPanel>
  );
}

export function MetricCardRenderer(context: RendererContext) {
  return <GenericMetricListRenderer {...context} />;
}

export function HealthBadgeRenderer(context: RendererContext) {
  const entries = safeEntries(context.data.value);
  const status =
    entries.find(([key]) => key.toLowerCase().includes("status"))?.[1] ??
    "unknown";
  return (
    <RendererPanel title={context.contribution.title} subtitle="Health">
      <div className="renderer-health-badge">
        <HeartPulse size={15} aria-hidden="true" />
        {status}
      </div>
    </RendererPanel>
  );
}

export function DynamicTableRenderer(context: RendererContext) {
  return <GenericTableRenderer {...context} />;
}

export function TimelineRenderer(context: RendererContext) {
  const rows = asRecordArray(context.data.value);
  return (
    <RendererPanel title={context.contribution.title} subtitle="Timeline">
      <ol className="renderer-timeline">
        {rows.map((row, index) => (
          <li key={String(row.event_id ?? row.timestamp ?? index)}>
            <History size={14} aria-hidden="true" />
            <span>{stringifySafe(row.timestamp ?? row.occurred_at ?? "time")}</span>
            <strong>{stringifySafe(row.title ?? row.summary_redacted ?? "Event")}</strong>
          </li>
        ))}
      </ol>
    </RendererPanel>
  );
}

export function EvidenceListRenderer(context: RendererContext) {
  return <GenericEvidenceRenderer {...context} />;
}

export function RiskBreakdownRenderer(context: RendererContext) {
  const rows = asRecordArray(context.data.value);
  return (
    <RendererPanel title={context.contribution.title} subtitle="Risk">
      <div className="renderer-risk-list">
        {rows.map((row, index) => (
          <div key={String(row.reason_type ?? index)}>
            <strong>{stringifySafe(row.reason_type ?? row.name ?? "Risk")}</strong>
            <span>{stringifySafe(row.summary_redacted ?? row.score ?? "redacted")}</span>
          </div>
        ))}
      </div>
    </RendererPanel>
  );
}

export function GraphProjectionRenderer(context: RendererContext) {
  return (
    <RendererPanel title={context.contribution.title} subtitle="Graph projection">
      <GraphProjectionBody value={context.data.value} />
    </RendererPanel>
  );
}

export function DependencyGraphRenderer(context: RendererContext) {
  return (
    <RendererPanel title={context.contribution.title} subtitle="Dependency graph">
      <GraphProjectionBody value={context.data.value} />
    </RendererPanel>
  );
}

export function PipelineGraphRenderer(context: RendererContext) {
  return (
    <RendererPanel title={context.contribution.title} subtitle="Pipeline graph">
      <GraphProjectionBody value={context.data.value} />
    </RendererPanel>
  );
}

export function ResponseActionRenderer(context: RendererContext) {
  const rows = asRecordArray(context.data.value);
  return (
    <RendererPanel title={context.contribution.title} subtitle="Response action">
      <div className="renderer-list">
        {rows.map((row, index) => (
          <div className="renderer-list-item" key={String(row.action_id ?? index)}>
            <ShieldCheck size={15} aria-hidden="true" />
            <div>
              <strong>{stringifySafe(row.action_type ?? row.action ?? "Action")}</strong>
              <span>{stringifySafe(row.rationale_redacted ?? row.target ?? "Review")}</span>
            </div>
            <button type="button" className="renderer-disabled-action" disabled>
              Review
            </button>
          </div>
        ))}
      </div>
    </RendererPanel>
  );
}

export function DynamicFormRenderer(context: RendererContext) {
  const rows = asRecordArray(context.data.schema ?? context.data.value);
  return (
    <RendererPanel title={context.contribution.title} subtitle="Settings form">
      <div className="renderer-form">
        {rows.map((row, index) => (
          <label key={String(row.field ?? row.name ?? index)}>
            <span>{stringifySafe(row.label ?? row.field ?? row.name ?? "Setting")}</span>
            <input
              value={stringifySafe(row.default ?? row.value ?? "")}
              readOnly
              aria-readonly="true"
            />
          </label>
        ))}
      </div>
    </RendererPanel>
  );
}

export function ReportSectionRenderer(context: RendererContext) {
  const rows = asRecordArray(context.data.value);
  return (
    <RendererPanel title={context.contribution.title} subtitle="Report section">
      <div className="renderer-list">
        {rows.map((row, index) => (
          <div className="renderer-list-item" key={String(row.section_id ?? index)}>
            <FileText size={15} aria-hidden="true" />
            <div>
              <strong>{stringifySafe(row.title_redacted ?? row.section_type ?? "Section")}</strong>
              <span>{stringifySafe(row.summary_redacted ?? "Redacted section")}</span>
            </div>
          </div>
        ))}
      </div>
    </RendererPanel>
  );
}

function GraphProjectionBody({ value }: { readonly value: JsonValue }) {
  const nodes = graphArray(value, "nodes");
  const edges = graphArray(value, "edges");
  const paths = graphArray(value, "paths");

  return (
    <div className="renderer-graph-projection">
      <div className="renderer-graph-stats">
        <span>
          <GitBranch size={14} aria-hidden="true" />
          Nodes {nodes.length}
        </span>
        <span>Edges {edges.length}</span>
        <span>Paths {paths.length}</span>
      </div>
      <div className="renderer-node-list">
        {nodes.slice(0, 8).map((node, index) => (
          <span key={String(node.node_id ?? node.id ?? index)}>
            {stringifySafe(node.label ?? node.node_type ?? "Node")}
          </span>
        ))}
      </div>
    </div>
  );
}

type UnsupportedFallbackKind =
  | "graph"
  | "finding"
  | "evidence"
  | "metrics"
  | "table"
  | "key_value";

function UnsupportedFallbackBody({
  kind,
  value,
}: {
  readonly kind: UnsupportedFallbackKind;
  readonly value: JsonValue;
}) {
  if (kind === "graph") {
    const nodes = graphArray(value, "nodes");
    return (
      <div className="renderer-graph-projection">
        <span className="renderer-muted">Generic fallback: Graph nodes</span>
        <div className="renderer-node-list">
          {nodes.slice(0, 10).map((node, index) => (
            <span key={String(node.node_id ?? node.id ?? index)}>
              {stringifySafe(node.label ?? node.node_type ?? "Graph node")}
            </span>
          ))}
        </div>
      </div>
    );
  }

  if (kind === "finding") {
    return (
      <div className="renderer-list">
        <span className="renderer-muted">Generic fallback: Findings</span>
        {asRecordArray(value).map((row, index) => (
          <div className="renderer-list-item" key={String(row.finding_id ?? index)}>
            <ShieldCheck size={15} aria-hidden="true" />
            <div>
              <strong>
                {stringifySafe(row.finding_type ?? row.title ?? "Finding")}
              </strong>
              <span>{stringifySafe(row.summary_redacted ?? "Redacted finding")}</span>
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (kind === "evidence") {
    return (
      <div className="renderer-list">
        <span className="renderer-muted">Generic fallback: Evidence</span>
        {asRecordArray(value).map((row, index) => (
          <div className="renderer-list-item" key={String(row.evidence_id ?? index)}>
            <ListChecks size={15} aria-hidden="true" />
            <div>
              <strong>{stringifySafe(row.evidence_type ?? "Evidence")}</strong>
              <span>{stringifySafe(row.summary_redacted ?? "Redacted evidence")}</span>
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (kind === "metrics") {
    return (
      <div className="renderer-metric-list">
        <span className="renderer-muted">Generic fallback: Metrics</span>
        {asRecordArray(value).map((row, index) => (
          <div key={String(row.metric_name ?? row.name ?? index)}>
            <BarChart3 size={15} aria-hidden="true" />
            <strong>{stringifySafe(row.metric_name ?? row.name ?? "metric")}</strong>
            <span>{stringifySafe(row.value ?? row.summary ?? "updated")}</span>
          </div>
        ))}
      </div>
    );
  }

  if (kind === "table") {
    const rows = asRecordArray(value);
    const columns = tableColumns(rows);
    const tableRows = rows.map((row, index) => ({
      id: String(row.id ?? row.finding_id ?? row.evidence_id ?? index),
      cells: Object.fromEntries(
        columns.map((column) => [
          column.key,
          stringifySafeForKey(column.key, row[column.key] ?? null),
        ]),
      ),
    }));
    return (
      <div className="renderer-list">
        <span className="renderer-muted">Generic fallback: Table</span>
        {columns.length ? (
          <ShellTable columns={columns} rows={tableRows} />
        ) : (
          <span className="renderer-muted">No tabular metadata</span>
        )}
      </div>
    );
  }

  const entries = safeEntries(value);
  return (
    <dl className="renderer-kv-list">
      {entries.map(([key, nested]) => (
        <div key={key}>
          <dt>{humanize(key)}</dt>
          <dd>{nested}</dd>
        </div>
      ))}
    </dl>
  );
}

function classifyFallback(value: JsonValue): UnsupportedFallbackKind {
  const nodes = graphArray(value, "nodes");
  if (nodes.length) {
    return "graph";
  }

  const rows = asRecordArray(value);
  if (!rows.length) {
    return "key_value";
  }

  if (rows.some((row) => hasAnyKey(row, ["finding_id", "finding_type"]))) {
    return "finding";
  }

  if (rows.some((row) => hasAnyKey(row, ["evidence_id", "evidence_type"]))) {
    return "evidence";
  }

  if (rows.some((row) => hasAnyKey(row, ["metric_name", "metric_id"]))) {
    return "metrics";
  }

  return rows.length > 1 ? "table" : "key_value";
}

function hasAnyKey(row: Record<string, JsonValue>, keys: string[]) {
  return keys.some((key) => key in row);
}

function graphArray(value: JsonValue, key: string) {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const record = value as Record<string, JsonValue>;
    const nested = record[key];
    if (Array.isArray(nested)) {
      return nested.filter(
        (item): item is Record<string, JsonValue> =>
          typeof item === "object" && item !== null && !Array.isArray(item),
      );
    }
  }
  return [];
}
