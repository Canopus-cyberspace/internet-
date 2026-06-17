import {
  Activity,
  FileText,
  GitBranch,
  History,
  ListChecks,
  ShieldAlert,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { JsonValue } from "../../../bridge/dto/common";
import type { GraphViewModelDto } from "../../../bridge/dto/graph";
import type {
  AlertDto,
  DurableBaselineSummaryDto,
  FindingDto,
  IncidentDetailViewDto,
  IncidentDto,
} from "../../../bridge/dto/security";
import type { UiContributionDto } from "../../../bridge/dto/plugin";
import { useGraphViewQuery } from "../../graph/hooks";
import {
  useAlertsQuery,
  useDurableBaselineSummaryQuery,
  useEndpointThreatSummaryQuery,
  useFindingsQuery,
  useIncidentDetailQuery,
  useIncidentsQuery,
  useInvestigationDrillDownSummaryQuery,
} from "../hooks";
import {
  useGenerateLlmAlertStoryMutation,
  useLlmAlertStoryStatusQuery,
} from "../../settings/hooks";
import { EndpointThreatPanel } from "./EndpointThreatPanel";
import { InvestigationDrillDownPanel } from "./InvestigationDrillDownPanel";
import { NavigationContextPanel } from "../../navigation/components/NavigationContextPanel";
import { useSelectionStore } from "../../../stores/selectionStore";
import { EmptyState } from "../../../shared/layout/EmptyState";
import { ShellTable, type ShellTableRow } from "../../../shared/table/ShellTable";
import {
  humanize,
  isSensitiveKey,
  stringifySafe,
  UiContributionRenderer,
} from "../../../shared/renderers";

type CaseKind = "finding" | "alert" | "incident";

interface CaseRow {
  readonly id: string;
  readonly entityId: string;
  readonly kind: CaseKind;
  readonly title: string;
  readonly severity: string;
  readonly state: string;
  readonly evidence: string;
  readonly source: "command";
  readonly raw: FindingDto | AlertDto | IncidentDto;
}

interface InvestigationSelection {
  readonly selectedCaseId: string | null;
  readonly selectedGraphNodeId: string | null;
  readonly selectCase: (row: CaseRow) => void;
  readonly selectGraphNode: (nodeId: string, caseId?: string | null) => void;
}

export function InvestigationWorkspace() {
  const findingsQuery = useFindingsQuery();
  const alertsQuery = useAlertsQuery();
  const incidentsQuery = useIncidentsQuery();
  const baselineSummaryQuery = useDurableBaselineSummaryQuery();
  const drillDownQuery = useInvestigationDrillDownSummaryQuery();
  const endpointThreatQuery = useEndpointThreatSummaryQuery();
  const llmStatusQuery = useLlmAlertStoryStatusQuery();
  const generateStoryMutation = useGenerateLlmAlertStoryMutation();
  const selection = useInvestigationSelectionState();
  const [activeKind, setActiveKind] = useState<"all" | CaseKind>("all");

  const commandRows = useMemo(
    () =>
      caseRowsFromQueries(
        findingsQuery.data?.items ?? [],
        alertsQuery.data?.items ?? [],
        incidentsQuery.data?.items ?? [],
      ),
    [alertsQuery.data?.items, findingsQuery.data?.items, incidentsQuery.data?.items],
  );
  const rows = commandRows;
  const visibleRows =
    activeKind === "all" ? rows : rows.filter((row) => row.kind === activeKind);
  const selectedVisibleRow =
    visibleRows.find((row) => row.id === selection.selectedCaseId) ?? null;
  const selectedRow = selectedVisibleRow ?? visibleRows[0] ?? null;

  useEffect(() => {
    if (selectedRow && selectedRow.id !== selection.selectedCaseId) {
      selection.selectCase(selectedRow);
    }
  }, [selectedRow, selection]);

  const selectedIncidentId = selectedRow?.kind === "incident" ? selectedRow.entityId : null;
  const incidentDetailQuery = useIncidentDetailQuery(selectedIncidentId);
  const incidentDetail = incidentDetailQuery.data ?? null;
  const loading =
    findingsQuery.isLoading || alertsQuery.isLoading || incidentsQuery.isLoading;
  const error = findingsQuery.isError || alertsQuery.isError || incidentsQuery.isError;

  if (error) {
    return (
      <EmptyState
        title="Investigation read model unavailable"
        detail="The command bridge returned a redacted query error."
      />
    );
  }

  return (
    <div className="investigation-workspace">
      <CaseList
        activeKind={activeKind}
        loading={loading}
        rows={visibleRows}
        selectedCaseId={selectedRow?.id ?? null}
        totalRows={rows.length}
        onSelectKind={setActiveKind}
        onSelectRow={selection.selectCase}
      />
      <main className="investigation-main">
        <AttackPathPanel
          detail={incidentDetail}
          row={selectedRow}
          selectedGraphNodeId={selection.selectedGraphNodeId}
          onSelectGraphNode={selection.selectGraphNode}
        />
        <div className="investigation-detail-grid">
          <EvidenceDrawer detail={incidentDetail} row={selectedRow} />
          <TimelinePanel detail={incidentDetail} row={selectedRow} />
          <BaselineFollowUpPanel
            error={baselineSummaryQuery.isError}
            loading={baselineSummaryQuery.isLoading}
            summary={baselineSummaryQuery.data ?? null}
          />
          <InvestigationDrillDownPanel
            error={drillDownQuery.isError}
            llmStatus={llmStatusQuery.data ?? null}
            loading={drillDownQuery.isLoading}
            pendingStory={generateStoryMutation.isPending}
            summary={drillDownQuery.data ?? null}
            onGenerateStory={(alertId, incidentId) =>
              generateStoryMutation.mutate({
                alert_id: alertId,
                incident_id: incidentId,
                explicit_user_action: true,
                replay: false,
                reason_redacted: "manual_investigation_story",
                requested_by_redacted: "local_user",
              })
            }
          />
          <EndpointThreatPanel
            error={endpointThreatQuery.isError}
            loading={endpointThreatQuery.isLoading}
            summary={endpointThreatQuery.data ?? null}
          />
          <NavigationContextPanel />
          <RiskBreakdownPanel detail={incidentDetail} row={selectedRow} />
          <RelatedEventsTable detail={incidentDetail} row={selectedRow} />
          <ResponsePlanPanel detail={incidentDetail} row={selectedRow} />
          <ReportActionPanel detail={incidentDetail} row={selectedRow} />
        </div>
      </main>
    </div>
  );
}

export function useInvestigationSelectionState(): InvestigationSelection {
  const selectedCaseId = useSelectionStore((state) => state.selectedCaseId);
  const selectedGraphNodeId = useSelectionStore((state) => state.selectedGraphNodeId);
  const setSelectedCaseId = useSelectionStore((state) => state.setSelectedCaseId);
  const setSelectedGraphNodeId = useSelectionStore(
    (state) => state.setSelectedGraphNodeId,
  );

  return useMemo(
    () => ({
      selectedCaseId,
      selectedGraphNodeId,
      selectCase: (row: CaseRow) => {
        setSelectedCaseId(row.id);
        setSelectedGraphNodeId(row.entityId);
      },
      selectGraphNode: (nodeId: string, caseId?: string | null) => {
        setSelectedGraphNodeId(nodeId);
        if (caseId) {
          setSelectedCaseId(caseId);
        }
      },
    }),
    [
      selectedCaseId,
      selectedGraphNodeId,
      setSelectedCaseId,
      setSelectedGraphNodeId,
    ],
  );
}

interface CaseListProps {
  readonly activeKind: "all" | CaseKind;
  readonly rows: CaseRow[];
  readonly selectedCaseId: string | null;
  readonly totalRows: number;
  readonly loading: boolean;
  readonly onSelectKind: (kind: "all" | CaseKind) => void;
  readonly onSelectRow: (row: CaseRow) => void;
}

export function CaseList({
  activeKind,
  rows,
  selectedCaseId,
  totalRows,
  loading,
  onSelectKind,
  onSelectRow,
}: CaseListProps) {
  return (
    <aside className="case-list-panel">
      <div className="analysis-panel-header">
        <strong>Case list</strong>
        <span>{loading ? "loading" : `${totalRows} rows`}</span>
      </div>
      <div className="case-filter-tabs" role="tablist" aria-label="Investigation filters">
        {(["all", "incident", "alert", "finding"] as const).map((kind) => (
          <button
            className="case-filter-tab"
            data-selected={activeKind === kind}
            key={kind}
            type="button"
            onClick={() => onSelectKind(kind)}
          >
            {kind}
          </button>
        ))}
      </div>
      <div className="case-list-table scroll-region table-scroll-region" role="table">
        <div className="case-list-row header" role="row">
          <div role="columnheader">Case</div>
          <div role="columnheader">Severity</div>
        </div>
        {rows.map((row) => (
          <div
            className="case-list-row"
            data-selected={selectedCaseId === row.id}
            data-severity={severityLevel(row.severity)}
            key={row.id}
            role="row"
          >
            <button
              className="case-row-button"
              type="button"
              onClick={() => onSelectRow(row)}
            >
              <span>{displayText(row.title, "Case")}</span>
              <small>
                {row.kind} / {displayText(row.state, "open")} / {row.source}
              </small>
            </button>
            <div role="cell">
              <SeverityPill severity={row.severity} />
            </div>
          </div>
        ))}
        {rows.length === 0 ? (
          <div className="case-list-row case-list-empty" role="row">
            <div role="cell">
              {loading
                ? "Loading command-backed security cases."
                : "No findings, alerts, or incidents are available from the command bridge."}
            </div>
          </div>
        ) : null}
      </div>
    </aside>
  );
}

interface DetailPanelProps {
  readonly row: CaseRow | null;
  readonly detail: IncidentDetailViewDto | null;
}

interface AttackPathPanelProps extends DetailPanelProps {
  readonly selectedGraphNodeId: string | null;
  readonly onSelectGraphNode: (nodeId: string, caseId?: string | null) => void;
}

export function AttackPathPanel({
  row,
  detail,
  selectedGraphNodeId,
  onSelectGraphNode,
}: AttackPathPanelProps) {
  const request = useMemo(
    () => ({
      graph_type: "incident_graph",
      scope: "overview",
      title_redacted: "Investigation attack path",
      node_limit: 80,
      edge_limit: 160,
    }),
    [],
  );
  const graphQuery = useGraphViewQuery(request);
  const graph =
    graphWithNodes(detail?.graph) ??
    graphWithNodes(graphQuery.data) ??
    emptyInvestigationGraph();
  const nodes = graph.nodes.filter(isRecord);

  return (
    <section className="analysis-panel attack-path-panel">
      <div className="analysis-panel-header">
        <strong>Attack path</strong>
        <span>{displayText(selectedGraphNodeId, "no node")}</span>
      </div>
      <UiContributionRenderer
        contribution={contribution("investigation-attack-path", "graph_projection", "Attack path")}
        data={graph as unknown as JsonValue}
      />
      <div className="graph-node-strip">
        {nodes.length ? (
          nodes.slice(0, 10).map((node, index) => {
            const nodeId = stringField(node, "node_id") ?? stringField(node, "id") ?? `${index}`;
            return (
              <button
                className="graph-node-chip"
                data-selected={selectedGraphNodeId === nodeId}
                key={nodeId}
                type="button"
                onClick={() => onSelectGraphNode(nodeId, row?.id ?? null)}
              >
                <span>
                  {stringField(node, "label") ??
                    stringField(node, "node_type") ??
                    "Node"}
                </span>
              </button>
            );
          })
        ) : (
          <span className="analysis-muted">
            No command-backed attack-path graph is available.
          </span>
        )}
      </div>
    </section>
  );
}

export function EvidenceDrawer({ detail, row }: DetailPanelProps) {
  const evidence = evidenceRows(detail, row);
  return (
    <section className="analysis-panel">
      <div className="analysis-panel-header">
        <strong>Evidence</strong>
        <ListChecks size={15} aria-hidden="true" />
      </div>
      <UiContributionRenderer
        contribution={contribution("investigation-evidence", "evidence_list", "Evidence")}
        data={evidence}
      />
    </section>
  );
}

export function TimelinePanel({ detail, row }: DetailPanelProps) {
  const timeline = timelineRows(detail, row);
  return (
    <section className="analysis-panel">
      <div className="analysis-panel-header">
        <strong>Timeline</strong>
        <History size={15} aria-hidden="true" />
      </div>
      <UiContributionRenderer
        contribution={contribution("investigation-timeline", "timeline", "Timeline")}
        data={timeline}
      />
    </section>
  );
}

interface BaselineFollowUpPanelProps {
  readonly error?: boolean;
  readonly loading?: boolean;
  readonly summary: DurableBaselineSummaryDto | null;
}

export function BaselineFollowUpPanel({
  error = false,
  loading = false,
  summary,
}: BaselineFollowUpPanelProps) {
  const timeline = summary?.incident_timeline.slice(0, 4) ?? [];
  const groups = summary?.incident_groups.slice(0, 3) ?? [];
  const degradedSources =
    summary?.source_reliability.filter((source) =>
      ["weak", "degraded", "unknown"].includes(
        displayText(source.reliability_bucket, ""),
      ),
    ) ?? [];

  return (
    <section className="analysis-panel">
      <div className="analysis-panel-header">
        <strong>Baseline follow-up</strong>
        <GitBranch size={15} aria-hidden="true" />
      </div>
      {error ? (
        <span className="analysis-muted">
          Baseline follow-up returned a redacted read-model error.
        </span>
      ) : null}
      {summary ? (
        <>
          <div className="report-redaction-grid">
            <span>
              <strong>{summary.indicator_count}</strong>
              indicators
            </span>
            <span>
              <strong>{summary.incident_group_count}</strong>
              groups
            </span>
            <span>
              <strong>{summary.timeline_entry_count}</strong>
              timeline refs
            </span>
            <span>
              <strong>{degradedSources.length}</strong>
              degraded sources
            </span>
          </div>
          <div className="redaction-category-list">
            {groups.length ? (
              groups.map((group) => (
                <span key={group.group_id}>
                  {group.hypothesis_refs.length} hypotheses /{" "}
                  {group.evidence_refs.length} evidence refs /{" "}
                  {humanize(displayText(group.confidence_trend, "unknown"))}
                </span>
              ))
            ) : (
              <span className="analysis-muted">
                No incident-linked hypothesis groups are active.
              </span>
            )}
          </div>
          <div className="redaction-category-list">
            {timeline.length ? (
              timeline.map((entry) => (
                <span key={entry.timeline_entry_id}>
                  {humanize(displayText(entry.event_category, "baseline"))} /{" "}
                  {humanize(displayText(entry.confidence_bucket, "unknown"))} /{" "}
                  {entry.evidence_refs.length} evidence refs
                </span>
              ))
            ) : (
              <span className="analysis-muted">
                No baseline timeline refs are active.
              </span>
            )}
          </div>
          <span className="analysis-muted">
            Portable Default keeps baseline security data session-bounded unless
            explicitly exported. Automatic LLM calls and response execution are off.
          </span>
        </>
      ) : (
        <span className="analysis-muted">
          {loading
            ? "Loading bounded baseline follow-up."
            : "No baseline follow-up summary is available."}
        </span>
      )}
    </section>
  );
}

export function RiskBreakdownPanel({ detail, row }: DetailPanelProps) {
  return (
    <section className="analysis-panel">
      <div className="analysis-panel-header">
        <strong>Risk</strong>
        <Activity size={15} aria-hidden="true" />
      </div>
      <UiContributionRenderer
        contribution={contribution("investigation-risk", "risk_breakdown", "Risk breakdown")}
        data={riskRows(detail, row)}
      />
    </section>
  );
}

export function RelatedEventsTable({ detail, row }: DetailPanelProps) {
  return (
    <section className="analysis-panel">
      <div className="analysis-panel-header">
        <strong>Related events</strong>
        <ShieldAlert size={15} aria-hidden="true" />
      </div>
      <ShellTable
        columns={[
          { key: "kind", label: "Kind" },
          { key: "summary", label: "Summary" },
          { key: "state", label: "State" },
        ]}
        rows={relatedEventRows(detail, row)}
      />
    </section>
  );
}

function ResponsePlanPanel({ detail, row }: DetailPanelProps) {
  const planRows = (detail?.response_plans ?? []).flatMap((plan, index) =>
    plan.recommended_actions.map((action, actionIndex) => ({
      action_id: `${plan.plan_id ?? index}:${actionIndex}`,
      action_type: stringField(action, "action_type") ?? "recommend_only",
      rationale_redacted:
        stringField(action, "rationale_redacted") ??
        stringField(action, "reason_redacted") ??
        "Redacted recommendation",
    })),
  );

  return (
    <section className="analysis-panel">
      <div className="analysis-panel-header">
        <strong>Response plan</strong>
        <span>recommend-first</span>
      </div>
      {planRows.length ? (
        <UiContributionRenderer
          contribution={contribution("investigation-response", "response_action_card", "Response plan")}
          data={planRows}
        />
      ) : (
        <span className="analysis-muted">
          {row
            ? "No command-backed response plan is available for the selected case."
            : "Select a command-backed case to inspect response planning."}
        </span>
      )}
    </section>
  );
}

function ReportActionPanel({ detail, row }: DetailPanelProps) {
  const reports = detail?.reports ?? [];
  return (
    <section className="analysis-panel report-action-panel">
      <div className="analysis-panel-header">
        <strong>Report action</strong>
        <FileText size={15} aria-hidden="true" />
      </div>
      <div className="report-action-body">
        <span>{reports.length ? `${reports.length} report refs` : "No generated report"}</span>
        <button
          className="analysis-command-button"
          type="button"
          disabled
          title="Report generation is handled by Reports"
        >
          <FileText size={14} aria-hidden="true" />
          {row ? "Generate report" : "No case"}
        </button>
      </div>
    </section>
  );
}

function caseRowsFromQueries(
  findings: FindingDto[],
  alerts: AlertDto[],
  incidents: IncidentDto[],
): CaseRow[] {
  return [
    ...incidents.map((incident, index) => {
      const entityId = entityIdFor(incident, "incident", index);
      return {
        id: `incident:${entityId}`,
        entityId,
        kind: "incident" as const,
        title: displayText(
          incident.summary_redacted ?? stringField(incident, "title_redacted"),
          "Incident",
        ),
        severity: displayText(incident.severity, "medium"),
        state: displayText(incident.state, "open"),
        evidence: `${incident.alert_refs?.length ?? 0} alerts`,
        source: "command" as const,
        raw: incident,
      };
    }),
    ...alerts.map((alert, index) => {
      const entityId = entityIdFor(alert, "alert", index);
      return {
        id: `alert:${entityId}`,
        entityId,
        kind: "alert" as const,
        title: displayText(
          alert.summary_redacted ?? stringField(alert, "title_redacted"),
          "Alert",
        ),
        severity: displayText(alert.severity, "medium"),
        state: displayText(alert.state, "open"),
        evidence: `${alert.finding_refs?.length ?? 0} findings`,
        source: "command" as const,
        raw: alert,
      };
    }),
    ...findings.map((finding, index) => {
      const entityId = entityIdFor(finding, "finding", index);
      return {
        id: `finding:${entityId}`,
        entityId,
        kind: "finding" as const,
        title: displayText(
          finding.summary_redacted ??
            finding.finding_type ??
            stringField(finding, "title_redacted"),
          "Finding",
        ),
        severity: displayText(finding.severity, "medium"),
        state: displayText(finding.state, "open"),
        evidence: evidenceCountLabel(finding),
        source: "command" as const,
        raw: finding,
      };
    }),
  ];
}

function emptyInvestigationGraph(): GraphViewModelDto {
  return {
    graph_id: "investigation:empty",
    graph_type: "incident_graph",
    title: { value_redacted: "Investigation attack path", privacy_class: "internal" },
    nodes: [],
    edges: [],
    paths: [],
    filters: { scope: "overview" },
    redaction_status: { status: "passed" },
    node_limit: 80,
    edge_limit: 160,
    truncated: false,
  };
}

function evidenceRows(detail: IncidentDetailViewDto | null, row: CaseRow | null): JsonValue {
  const findings =
    detail?.related_findings.length
      ? detail.related_findings
      : row?.kind === "finding"
        ? [row.raw as FindingDto]
        : [];
  return findings.flatMap((finding) =>
    evidenceRefs(finding).map((evidenceRef) => ({
      evidence_id: evidenceRef,
      evidence_type: displayText(finding.finding_type, "finding_evidence"),
      summary_redacted: "Evidence reference from the command read model",
    })),
  );
}

function timelineRows(detail: IncidentDetailViewDto | null, row: CaseRow | null): JsonValue {
  return [
    ...(row
      ? [
          {
            event_id: row.id,
            timestamp: timestampFor(row.raw),
            title: row.kind,
            summary_redacted: displayText(row.title, "Case"),
          },
        ]
      : []),
    ...(detail?.related_alerts ?? []).map((alert, index) => ({
      event_id: alert.alert_id ?? `alert:${index}`,
      timestamp: timestampFor(alert),
      title: "alert",
      summary_redacted: displayText(alert.summary_redacted, "Redacted alert"),
    })),
    ...(detail?.related_findings ?? []).map((finding, index) => ({
      event_id: finding.finding_id ?? `finding:${index}`,
      timestamp: timestampFor(finding),
      title: "finding",
      summary_redacted: displayText(
        finding.summary_redacted ?? finding.finding_type,
        "Redacted finding",
      ),
    })),
  ];
}

function riskRows(detail: IncidentDetailViewDto | null, row: CaseRow | null): JsonValue {
  if (!row) {
    return [];
  }
  const riskScore = valueFor(row.raw, "risk_score");
  return [
    {
      reason_type: `${row.kind}_severity`,
      summary_redacted: displayText(row.severity, "medium"),
    },
    ...(detail
      ? [
          {
            reason_type: "related_event_count",
            summary_redacted: `${
              detail.related_alerts.length + detail.related_findings.length
            } related`,
          },
        ]
      : []),
    ...(typeof riskScore === "number"
      ? [
          {
            reason_type: "command_risk_score",
            summary_redacted: `${riskScore}`,
            score: riskScore,
          },
        ]
      : []),
  ];
}

function relatedEventRows(
  detail: IncidentDetailViewDto | null,
  row: CaseRow | null,
): ShellTableRow[] {
  const rows: ShellTableRow[] = [];
  if (row) {
    rows.push({
      id: row.id,
      severity: severityLevel(row.severity),
      cells: {
        kind: row.kind,
        summary: displayText(row.title, "Case"),
        state: displayText(row.state, "open"),
      },
    });
  }
  for (const alert of detail?.related_alerts ?? []) {
    rows.push({
      id: alert.alert_id ?? `alert:${rows.length}`,
      severity: severityLevel(alert.severity ?? "medium"),
      cells: {
        kind: "alert",
        summary: displayText(alert.summary_redacted, "Redacted alert"),
        state: displayText(alert.state, "open"),
      },
    });
  }
  for (const finding of detail?.related_findings ?? []) {
    rows.push({
      id: finding.finding_id ?? `finding:${rows.length}`,
      severity: severityLevel(finding.severity ?? "medium"),
      cells: {
        kind: "finding",
        summary: displayText(
          finding.summary_redacted ?? finding.finding_type,
          "Redacted finding",
        ),
        state: displayText(finding.state, "open"),
      },
    });
  }
  return rows;
}

function contribution(
  id: string,
  rendererType: string,
  title: string,
): UiContributionDto {
  return {
    contribution_id: id,
    plugin_id: "frontend:investigation",
    slot: "investigation.panel",
    renderer_type: rendererType,
    title,
  };
}

function SeverityPill({ severity }: { readonly severity: string }) {
  return (
    <span className="analysis-severity-pill" data-severity={severityLevel(severity)}>
      {displayText(severity, "low")}
    </span>
  );
}

function entityIdFor(
  value: FindingDto | AlertDto | IncidentDto,
  kind: CaseKind,
  index: number,
) {
  return (
    stringField(value, `${kind}_id`) ??
    stringField(value, "id") ??
    `${kind}:${index}`
  );
}

function evidenceCountLabel(finding: FindingDto) {
  const refs = evidenceRefs(finding);
  return refs.length ? `${refs.length} refs` : "no evidence refs";
}

function evidenceRefs(finding: FindingDto) {
  const refs = valueFor(finding, "evidence_refs");
  return Array.isArray(refs)
    ? refs.filter((ref): ref is string => typeof ref === "string")
    : [];
}

function timestampFor(value: unknown) {
  for (const key of [
    "updated_at",
    "created_at",
    "observed_at",
    "timestamp",
    "first_seen",
    "last_seen",
  ]) {
    const timestamp = stringField(value, key);
    if (timestamp) {
      return timestamp;
    }
  }
  return "timestamp unavailable";
}

function graphWithNodes(graph: GraphViewModelDto | null | undefined) {
  return graph?.nodes.length ? graph : null;
}

function severityLevel(value: string | undefined): "low" | "medium" | "high" | "critical" {
  const normalized = (value ?? "").toLowerCase();
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

function displayText(value: JsonValue | undefined | null, fallback: string) {
  if (value === undefined || value === null) {
    return fallback;
  }
  const safe = stringifySafe(value);
  return safe.length ? safe : fallback;
}
