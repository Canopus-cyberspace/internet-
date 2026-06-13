import {
  AlertTriangle,
  CheckCircle,
  Clock,
  History,
  ListChecks,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { JsonValue } from "../../../bridge/dto/common";
import type { GraphViewModelDto } from "../../../bridge/dto/graph";
import type { ResponsePlanDto } from "../../../bridge/dto/response";
import { useSelectionStore } from "../../../stores/selectionStore";
import { GraphCanvas, graphViewBoundaryIssue } from "../../../shared/graph";
import { EmptyState } from "../../../shared/layout/EmptyState";
import { humanize, isRecord, stringifySafe } from "../../../shared/renderers";
import { useGraphViewQuery } from "../../graph/hooks";
import {
  useActiveResponsesQuery,
  useApproveResponseActionMutation,
  useRejectResponseActionMutation,
  useRollbackResponseActionMutation,
} from "../hooks";

type ResponseView = "recommended" | "approval" | "active" | "history";

interface ResponseActionRow {
  readonly id: string;
  readonly planId: string;
  readonly actionId: string | null;
  readonly actionType: string;
  readonly target: string;
  readonly scope: string;
  readonly expectedEffect: string;
  readonly businessImpact: string;
  readonly decision: string;
  readonly risk: "unknown" | "low" | "medium" | "high" | "critical";
  readonly ttl: string;
  readonly rollback: string;
  readonly rollbackAvailable: boolean;
  readonly approvalRequired: boolean;
  readonly approvalState: string;
  readonly auditRef: string;
  readonly status: "recommended" | "approval" | "active" | "history";
  readonly createdAt: string;
}

const RESPONSE_VIEWS: Array<{ readonly id: ResponseView; readonly label: string }> = [
  { id: "recommended", label: "Recommended" },
  { id: "approval", label: "Approval" },
  { id: "active", label: "Active" },
  { id: "history", label: "History" },
];

export function ResponseWorkspace() {
  const activeResponsesQuery = useActiveResponsesQuery();
  const rowsFromCommand = useMemo(
    () => responseRowsFromPlans(activeResponsesQuery.data?.items ?? []),
    [activeResponsesQuery.data?.items],
  );
  const rows = rowsFromCommand;
  const [activeView, setActiveView] = useState<ResponseView>("recommended");
  const selectedPlanId = useSelectionStore((state) => state.selectedResponsePlanId);
  const selectedActionId = useSelectionStore((state) => state.selectedResponseActionId);
  const setSelectedResponsePlanId = useSelectionStore(
    (state) => state.setSelectedResponsePlanId,
  );
  const setSelectedResponseActionId = useSelectionStore(
    (state) => state.setSelectedResponseActionId,
  );

  const visibleRows = rowsForView(rows, activeView);
  const selectedRow =
    visibleRows.find((row) => row.id === selectedActionId) ??
    visibleRows.find((row) => row.planId === selectedPlanId) ??
    visibleRows[0] ??
    null;

  useEffect(() => {
    if (!selectedRow) {
      if (selectedActionId) {
        setSelectedResponseActionId(null);
      }
      if (selectedPlanId) {
        setSelectedResponsePlanId(null);
      }
      return;
    }
    if (selectedActionId !== selectedRow.id) {
      setSelectedResponseActionId(selectedRow.id);
    }
    if (selectedPlanId !== selectedRow.planId) {
      setSelectedResponsePlanId(selectedRow.planId);
    }
  }, [
    selectedActionId,
    selectedPlanId,
    selectedRow,
    setSelectedResponseActionId,
    setSelectedResponsePlanId,
  ]);

  if (activeResponsesQuery.isError) {
    return (
      <EmptyState
        title="Response read model unavailable"
        detail="The command bridge returned a redacted response query error."
        tone="error"
      />
    );
  }

  const selectRow = (row: ResponseActionRow) => {
    setSelectedResponsePlanId(row.planId);
    setSelectedResponseActionId(row.id);
  };

  return (
    <div className="response-workspace">
      <aside className="response-view-tree" aria-label="Response views">
        <div className="analysis-panel-header">
          <strong>Response</strong>
          <span>{rows.length}</span>
        </div>
        <div className="response-view-list">
          {RESPONSE_VIEWS.map((view) => (
            <button
              className="response-view-button"
              data-selected={activeView === view.id}
              key={view.id}
              type="button"
              onClick={() => setActiveView(view.id)}
            >
              <ViewIcon view={view.id} />
              <span>{view.label}</span>
              <small>{rowsForView(rows, view.id).length}</small>
            </button>
          ))}
        </div>
      </aside>

      <main className="response-main">
        <ResponsePrimaryPanel
          activeView={activeView}
          loading={activeResponsesQuery.isLoading}
          rows={visibleRows}
          selectedRowId={selectedRow?.id ?? null}
          onSelectRow={selectRow}
        />
        <ResponseImpactGraphPanel row={selectedRow} />
      </main>

      <aside className="response-detail">
        <ApprovalDialog row={selectedRow} />
        <ResponseSafetyPanel row={selectedRow} />
      </aside>
    </div>
  );
}

interface ResponsePrimaryPanelProps {
  readonly activeView: ResponseView;
  readonly loading: boolean;
  readonly rows: ResponseActionRow[];
  readonly selectedRowId: string | null;
  readonly onSelectRow: (row: ResponseActionRow) => void;
}

function ResponsePrimaryPanel({
  activeView,
  loading,
  rows,
  selectedRowId,
  onSelectRow,
}: ResponsePrimaryPanelProps) {
  if (activeView === "active") {
    return (
      <ActiveResponseTable
        loading={loading}
        rows={rows}
        selectedRowId={selectedRowId}
        onSelectRow={onSelectRow}
      />
    );
  }

  if (activeView === "history") {
    return (
      <ResponseHistoryTable
        loading={loading}
        rows={rows}
        selectedRowId={selectedRowId}
        onSelectRow={onSelectRow}
      />
    );
  }

  return (
    <RecommendedActionsTable
      loading={loading}
      rows={rows}
      selectedRowId={selectedRowId}
      view={activeView}
      onSelectRow={onSelectRow}
    />
  );
}

interface ResponseTableProps {
  readonly loading: boolean;
  readonly rows: ResponseActionRow[];
  readonly selectedRowId: string | null;
  readonly onSelectRow: (row: ResponseActionRow) => void;
}

interface RecommendedActionsTableProps extends ResponseTableProps {
  readonly view: ResponseView;
}

export function RecommendedActionsTable({
  loading,
  rows,
  selectedRowId,
  view,
  onSelectRow,
}: RecommendedActionsTableProps) {
  return (
    <section className="response-table-panel">
      <div className="analysis-panel-header">
        <strong>{view === "approval" ? "Approval queue" : "Recommended actions"}</strong>
        <span>{loading ? "Loading" : `${rows.length} rows`}</span>
      </div>
      <div
        className="response-table response-table-recommended scroll-region table-scroll-region"
        role="table"
      >
        <div className="response-table-row header" role="row">
          <div role="columnheader">Action</div>
          <div role="columnheader">Target</div>
          <div role="columnheader">Decision</div>
          <div role="columnheader">TTL</div>
          <div role="columnheader">Rollback</div>
          <div role="columnheader">Audit</div>
        </div>
        {rows.map((row) => (
          <button
            className="response-table-row"
            data-selected={selectedRowId === row.id}
            data-severity={row.risk}
            key={row.id}
            role="row"
            type="button"
            onClick={() => onSelectRow(row)}
          >
            <div role="cell">
              <strong>{displayText(row.actionType)}</strong>
              <small>command</small>
            </div>
            <div role="cell">{displayText(row.target)}</div>
            <div role="cell">{displayText(row.decision)}</div>
            <div role="cell">{displayText(row.ttl)}</div>
            <div role="cell">{displayText(row.rollback)}</div>
            <div role="cell">{displayText(row.auditRef)}</div>
          </button>
        ))}
        {!rows.length ? (
          <ResponseTableEmpty
            loading={loading}
            message={
              view === "approval"
                ? "No command-backed response actions require approval."
                : "No command-backed response recommendations are available."
            }
          />
        ) : null}
      </div>
    </section>
  );
}

export function ActiveResponseTable({
  loading,
  rows,
  selectedRowId,
  onSelectRow,
}: ResponseTableProps) {
  const rollbackMutation = useRollbackResponseActionMutation();
  return (
    <section className="response-table-panel">
      <div className="analysis-panel-header">
        <strong>Active temporary responses</strong>
        <span>{loading ? "Loading" : `${rows.length} active`}</span>
      </div>
      <div
        className="response-table response-table-active scroll-region table-scroll-region"
        role="table"
      >
        <div className="response-table-row header" role="row">
          <div role="columnheader">Action</div>
          <div role="columnheader">Target</div>
          <div role="columnheader">Time remaining</div>
          <div role="columnheader">Executor</div>
          <div role="columnheader">Rollback</div>
        </div>
        {rows.map((row) => {
          const canRollback = Boolean(row.actionId) && row.rollbackAvailable;
          return (
            <div
              className="response-table-row"
              data-selected={selectedRowId === row.id}
              data-severity={row.risk}
              key={row.id}
              onClick={() => onSelectRow(row)}
              role="row"
            >
              <div role="cell">
                <strong>{displayText(row.actionType)}</strong>
                <small>{displayText(row.auditRef)}</small>
              </div>
              <div role="cell">{displayText(row.target)}</div>
              <div role="cell">{displayText(row.ttl)}</div>
              <div role="cell">Core controlled</div>
              <div role="cell">
                <button
                  className="mini-action-button"
                  disabled={!canRollback || rollbackMutation.isPending}
                  title="Request rollback through Rust Core"
                  type="button"
                  onClick={(event) => {
                    event.stopPropagation();
                    if (!row.actionId) {
                      return;
                    }
                    rollbackMutation.mutate({
                      action_id: row.actionId,
                      actor_redacted: "local operator",
                      reason_redacted: "operator requested rollback from response page",
                    });
                  }}
                >
                  <RotateCcw size={13} aria-hidden="true" />
                  Rollback
                </button>
              </div>
            </div>
          );
        })}
        {!rows.length ? (
          <ResponseTableEmpty
            loading={loading}
            message="No active response executions are reported by Rust Core."
          />
        ) : null}
      </div>
    </section>
  );
}

function ResponseHistoryTable({
  loading,
  rows,
  selectedRowId,
  onSelectRow,
}: ResponseTableProps) {
  return (
    <section className="response-table-panel">
      <div className="analysis-panel-header">
        <strong>Response history</strong>
        <span>{loading ? "Loading" : `${rows.length} entries`}</span>
      </div>
      <div
        className="response-table response-table-history scroll-region table-scroll-region"
        role="table"
      >
        <div className="response-table-row header" role="row">
          <div role="columnheader">Event</div>
          <div role="columnheader">Decision</div>
          <div role="columnheader">Approval</div>
          <div role="columnheader">Audit</div>
          <div role="columnheader">When</div>
        </div>
        {rows.map((row) => (
          <button
            className="response-table-row"
            data-selected={selectedRowId === row.id}
            data-severity={row.risk}
            key={row.id}
            role="row"
            type="button"
            onClick={() => onSelectRow(row)}
          >
            <div role="cell">{displayText(row.actionType)}</div>
            <div role="cell">{displayText(row.decision)}</div>
            <div role="cell">{humanize(displayText(row.approvalState))}</div>
            <div role="cell">{displayText(row.auditRef)}</div>
            <div role="cell">{displayText(row.createdAt)}</div>
          </button>
        ))}
        {!rows.length ? (
          <ResponseTableEmpty
            loading={loading}
            message="No command-backed approval or response history is available."
          />
        ) : null}
      </div>
    </section>
  );
}

function ResponseTableEmpty({
  loading,
  message,
}: {
  readonly loading: boolean;
  readonly message: string;
}) {
  return (
    <div className="response-table-row response-table-empty" role="row">
      <div role="cell">
        {loading ? "Loading command-backed response data." : message}
      </div>
    </div>
  );
}

interface ApprovalDialogProps {
  readonly row: ResponseActionRow | null;
}

export function ApprovalDialog({ row }: ApprovalDialogProps) {
  const approveMutation = useApproveResponseActionMutation();
  const rejectMutation = useRejectResponseActionMutation();
  const [reason, setReason] = useState("");
  const [reviewed, setReviewed] = useState(false);

  useEffect(() => {
    setReason("");
    setReviewed(false);
  }, [row?.id]);

  if (!row) {
    return (
      <section className="response-side-panel">
        <div className="analysis-panel-header">
          <strong>Approval</strong>
          <ShieldAlert size={15} aria-hidden="true" />
        </div>
        <span className="analysis-muted">No response action selected.</span>
      </section>
    );
  }

  const canMutate = Boolean(row.actionId);
  const requiresStrictReview = row.approvalRequired || row.risk === "high" || row.risk === "critical";
  const hasReason = reason.trim().length >= (requiresStrictReview ? 8 : 0);
  const approvalReady = canMutate && (!requiresStrictReview || (reviewed && hasReason));
  const rejectReady = canMutate && (!requiresStrictReview || hasReason);

  return (
    <section className="response-side-panel">
      <div className="analysis-panel-header">
        <strong>Approval dialog</strong>
        <ShieldAlert size={15} aria-hidden="true" />
      </div>
      <div className="response-approval-body">
        <div className="response-callout" data-tone={row.approvalRequired ? "warning" : "ok"}>
          {row.approvalRequired ? (
            <AlertTriangle size={15} aria-hidden="true" />
          ) : (
            <ShieldCheck size={15} aria-hidden="true" />
          )}
          <span>{row.approvalRequired ? "Approval required" : "Recommend first"}</span>
        </div>
        <dl className="response-detail-list">
          <DetailItem label="Action" value={row.actionType} />
          <DetailItem label="Target" value={row.target} />
          <DetailItem label="Scope" value={row.scope} />
          <DetailItem label="TTL" value={row.ttl} />
          <DetailItem label="Business impact" value={row.businessImpact} />
          <DetailItem label="Rollback" value={row.rollback} />
          <DetailItem label="Audit" value={row.auditRef} />
        </dl>
        <label className="response-reason-field">
          <span>Reason</span>
          <textarea
            value={reason}
            placeholder="redacted operator reason"
            onChange={(event) => setReason(event.currentTarget.value)}
          />
        </label>
        <label className="response-check-row">
          <input
            checked={reviewed}
            disabled={!requiresStrictReview}
            type="checkbox"
            onChange={(event) => setReviewed(event.currentTarget.checked)}
          />
          <span>Policy details reviewed</span>
        </label>
        <div className="response-action-bar">
          <button
            className="toolbar-button"
            disabled={!approvalReady || approveMutation.isPending}
            title="Approve through Rust Core mutation"
            type="button"
            onClick={() => {
              if (!row.actionId) {
                return;
              }
              approveMutation.mutate({
                action_id: row.actionId,
                actor_redacted: "local operator",
                reason_redacted: reason.trim() || "operator approval",
              });
            }}
          >
            <CheckCircle size={14} aria-hidden="true" />
            Approve
          </button>
          <button
            className="toolbar-button"
            disabled={!rejectReady || rejectMutation.isPending}
            title="Reject through Rust Core mutation"
            type="button"
            onClick={() => {
              if (!row.actionId) {
                return;
              }
              rejectMutation.mutate({
                action_id: row.actionId,
                actor_redacted: "local operator",
                reason_redacted: reason.trim() || "operator rejection",
              });
            }}
          >
            <XCircle size={14} aria-hidden="true" />
            Reject
          </button>
        </div>
      </div>
    </section>
  );
}

interface ResponseImpactGraphPanelProps {
  readonly row: ResponseActionRow | null;
}

export function ResponseImpactGraphPanel({ row }: ResponseImpactGraphPanelProps) {
  const selectedGraphNodeId = useSelectionStore((state) => state.selectedGraphNodeId);
  const selectedGraphEdgeId = useSelectionStore((state) => state.selectedGraphEdgeId);
  const setSelectedGraphNodeId = useSelectionStore((state) => state.setSelectedGraphNodeId);
  const setSelectedGraphEdgeId = useSelectionStore((state) => state.setSelectedGraphEdgeId);
  const request = useMemo(
    () => ({
      graph_type: "response_impact_graph",
      scope: row?.planId ? { type: "response_plan", value: row.planId } : "overview",
      title_redacted: "Response impact graph",
      node_limit: 40,
      edge_limit: 80,
    }),
    [row?.planId],
  );
  const graphQuery = useGraphViewQuery(request);
  const commandView = graphQuery.data ?? null;
  const hasCommandGraph = Boolean(
    commandView &&
      (commandView.nodes.length || commandView.edges.length || commandView.paths.length),
  );
  const candidateView =
    commandView ?? emptyResponseImpactGraph(row, 40, 80, "empty");
  const boundaryIssue = graphViewBoundaryIssue(candidateView);
  const view = boundaryIssue
    ? emptyResponseImpactGraph(
        row,
        candidateView.node_limit ?? 40,
        candidateView.edge_limit ?? 80,
        "redacted",
      )
    : candidateView;
  const sourceStatus = graphQuery.isLoading
    ? "Loading"
    : graphQuery.isError
      ? "error"
      : boundaryIssue
        ? "redacted"
        : hasCommandGraph
          ? "command"
          : "empty";

  return (
    <section className="response-impact-panel">
      <div className="analysis-panel-header">
        <strong>Response impact graph</strong>
        <span>{sourceStatus}</span>
      </div>
      {graphQuery.isError ? (
        <div className="response-callout" data-tone="warning">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>GraphViewModel command unavailable.</span>
        </div>
      ) : null}
      {!graphQuery.isLoading && !graphQuery.isError && !hasCommandGraph ? (
        <div className="response-callout" data-tone="warning">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>No command-backed response impact graph is available.</span>
        </div>
      ) : null}
      {boundaryIssue ? (
        <div className="response-callout" data-tone="warning">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>GraphViewModel boundary blocked; redacted empty view is rendered.</span>
        </div>
      ) : null}
      <GraphCanvas
        riskFilter="all"
        selectedEdgeId={selectedGraphEdgeId}
        selectedNodeId={selectedGraphNodeId}
        view={view}
        onSelectEdge={setSelectedGraphEdgeId}
        onSelectNode={setSelectedGraphNodeId}
      />
    </section>
  );
}

function ResponseSafetyPanel({ row }: ApprovalDialogProps) {
  return (
    <section className="response-side-panel">
      <div className="analysis-panel-header">
        <strong>Safety state</strong>
        <ListChecks size={15} aria-hidden="true" />
      </div>
      <div className="response-safety-grid">
        <SafetyItem label="Frontend execution" value="Unavailable" tone="blocked" />
        <SafetyItem
          label="Approval"
          value={row ? (row.approvalRequired ? "Required" : "Recommend only") : "No action selected"}
          tone={row ? "warning" : "neutral"}
        />
        <SafetyItem
          label="Rollback"
          value={row?.rollback ?? "No action selected"}
          tone={row ? "ok" : "neutral"}
        />
        <SafetyItem
          label="Audit"
          value={row?.auditRef ?? "No action selected"}
          tone={row ? "ok" : "neutral"}
        />
        <SafetyItem label="Replay" value="Execution disabled" tone="ok" />
      </div>
    </section>
  );
}

function SafetyItem({
  label,
  value,
  tone,
}: {
  readonly label: string;
  readonly value: string;
  readonly tone: "ok" | "warning" | "blocked" | "neutral";
}) {
  return (
    <div className="response-safety-item" data-tone={tone}>
      <span>{label}</span>
      <strong>{displayText(value)}</strong>
    </div>
  );
}

function DetailItem({ label, value }: { readonly label: string; readonly value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{displayText(value)}</dd>
    </div>
  );
}

function ViewIcon({ view }: { readonly view: ResponseView }) {
  switch (view) {
    case "approval":
      return <ShieldAlert size={14} aria-hidden="true" />;
    case "active":
      return <Clock size={14} aria-hidden="true" />;
    case "history":
      return <History size={14} aria-hidden="true" />;
    case "recommended":
    default:
      return <ListChecks size={14} aria-hidden="true" />;
  }
}

function rowsForView(rows: ResponseActionRow[], view: ResponseView) {
  switch (view) {
    case "approval":
      return rows.filter((row) => row.approvalRequired || row.status === "approval");
    case "active":
      return rows.filter((row) => row.status === "active");
    case "history":
      return rows.filter((row) => row.status === "history");
    case "recommended":
    default:
      return rows.filter((row) => row.status === "recommended" || row.status === "approval");
  }
}

export function responseRowsFromPlans(plans: ResponsePlanDto[]): ResponseActionRow[] {
  return plans.flatMap((plan, planIndex) => {
    const planRecord = plan as Record<string, JsonValue | undefined>;
    const planId = stringField(planRecord, "plan_id") ?? `plan:${planIndex}`;
    const actions = Array.isArray(plan.recommended_actions)
      ? plan.recommended_actions
      : [];
    if (!actions.length) {
      return [];
    }
    return actions.map((actionValue, actionIndex) =>
      rowFromPlan(
        planRecord,
        isRecord(actionValue) ? actionValue : {},
        planId,
        planIndex,
        actionIndex,
      ),
    );
  });
}

function rowFromPlan(
  plan: Record<string, JsonValue | undefined>,
  action: Record<string, JsonValue>,
  planId: string,
  planIndex: number,
  actionIndex: number,
): ResponseActionRow {
  const policy: Record<string, JsonValue | undefined> =
    recordField(action, "policy_decision") ??
    recordAt(plan.policy_decisions, actionIndex) ??
    firstRecord(plan.policy_decisions) ??
    {};
  const actionId = stringField(action, "action_id");
  const actionType = reportedHumanized(stringField(action, "action_type"));
  const approvalRequired =
    boolField(action, "approval_required") ??
    boolField(policy, "approval_required") ??
    boolField(plan, "approval_required") ??
    false;
  const approvalState =
    stringField(action, "approval_state") ??
    (approvalRequired ? "requested" : "not_reported");
  const risk = normalizeRisk(stringField(policy, "risk_level"));
  const status = statusFromApproval(approvalState, approvalRequired);
  return {
    id:
      actionId ??
      stringField(action, "recommended_action_id") ??
      `${planId}:recommendation:${planIndex}:${actionIndex}`,
    planId,
    actionId,
    actionType,
    target:
      targetLabel(recordField(action, "target")) ??
      targetLabel(recordField(plan, "source")) ??
      "not reported",
    scope: stringField(recordField(action, "scope"), "description_redacted") ?? "not reported",
    expectedEffect: stringField(action, "expected_effect_redacted") ?? "not reported",
    businessImpact:
      stringField(action, "business_impact_redacted") ??
      stringField(plan, "business_impact_redacted") ??
      "not reported",
    decision: reportedHumanized(
      stringField(policy, "level") ?? stringField(action, "response_level"),
    ),
    risk,
    ttl: ttlLabel(recordField(action, "ttl") ?? recordField(plan, "ttl")),
    rollback: rollbackLabel(boolField(action, "rollback_available")),
    rollbackAvailable: boolField(action, "rollback_available") ?? false,
    approvalRequired,
    approvalState,
    auditRef: auditLabel(recordField(action, "audit_ref"), plan.audit_requirements),
    status,
    createdAt: stringField(action, "created_at") ?? stringField(plan, "created_at") ?? "not reported",
  };
}

function statusFromApproval(
  approvalState: string,
  approvalRequired: boolean,
): ResponseActionRow["status"] {
  const normalized = approvalState.toLowerCase();
  if (normalized === "not_required") {
    return approvalRequired ? "approval" : "recommended";
  }
  if (
    normalized === "approved" ||
    normalized === "rejected" ||
    normalized === "expired"
  ) {
    return "history";
  }
  return approvalRequired ? "approval" : "recommended";
}

function emptyResponseImpactGraph(
  row: ResponseActionRow | null,
  nodeLimit: number,
  edgeLimit: number,
  source: "empty" | "redacted",
): GraphViewModelDto {
  return {
    graph_id: `${source}:response:${row?.planId ?? "overview"}`,
    graph_type: "response_impact_graph",
    title: {
      value_redacted:
        source === "redacted"
          ? "Response impact graph redacted"
          : "Response impact graph",
      privacy_class: "internal",
    },
    nodes: [],
    edges: [],
    paths: [],
    legend: {},
    filters: {
      source,
      plan_id: row?.planId ?? "overview",
    },
    redaction_status: {
      status: source === "redacted" ? "redacted" : "passed",
      source,
    },
    node_limit: nodeLimit,
    edge_limit: edgeLimit,
    truncated: false,
  };
}

function firstRecord(value: JsonValue | undefined) {
  return Array.isArray(value) ? value.find(isRecord) : null;
}

function recordAt(value: JsonValue | undefined, index: number) {
  if (!Array.isArray(value)) {
    return null;
  }
  const nested = value[index];
  return isRecord(nested) ? nested : null;
}

function recordField(
  value: Record<string, JsonValue | undefined> | undefined,
  key: string,
) {
  const nested = value?.[key];
  return isRecord(nested) ? nested : null;
}

function stringField(
  value: Record<string, JsonValue | undefined> | null | undefined,
  key: string,
): string | null {
  const nested = value?.[key];
  if (typeof nested === "string") {
    return stringifySafe(nested);
  }
  if (typeof nested === "number" || typeof nested === "boolean") {
    return stringifySafe(nested);
  }
  if (isRecord(nested)) {
    return (
      stringField(nested, "value_redacted") ??
      stringField(nested, "target_summary_redacted") ??
      stringField(nested, "description_redacted") ??
      stringField(nested, "id")
    );
  }
  return null;
}

function boolField(
  value: Record<string, JsonValue | undefined> | null | undefined,
  key: string,
) {
  const nested = value?.[key];
  return typeof nested === "boolean" ? nested : null;
}

function targetLabel(value: Record<string, JsonValue> | null) {
  if (!value) {
    return null;
  }
  return (
    stringField(value, "target_summary_redacted") ??
    stringField(value, "value_redacted") ??
    stringField(value, "type") ??
    stringifySafe(value)
  );
}

function ttlLabel(value: Record<string, JsonValue> | null) {
  if (!value) {
    return "not reported";
  }
  const expiresAt = stringField(value, "expires_at");
  const seconds = value.duration_seconds;
  if (expiresAt) {
    return `until ${expiresAt}`;
  }
  if (typeof seconds === "number") {
    return `${Math.round(seconds / 60)} minutes`;
  }
  const required = boolField(value, "required_for_execution");
  return required === null ? "not reported" : required ? "required" : "not required";
}

function auditLabel(
  auditRef: Record<string, JsonValue> | null,
  auditRequirements: JsonValue | undefined,
) {
  return (
    stringField(auditRef, "audit_id") ??
    stringField(auditRef, "event_type") ??
    (Array.isArray(auditRequirements) && auditRequirements.length
      ? `${auditRequirements.length} requirements`
      : "not reported")
  );
}

function normalizeRisk(value: string | null): ResponseActionRow["risk"] {
  const normalized = value?.toLowerCase();
  if (normalized === "critical" || normalized === "high" || normalized === "medium") {
    return normalized;
  }
  if (normalized === "low") {
    return "low";
  }
  return "unknown";
}

function reportedHumanized(value: string | null) {
  return value ? humanize(value) : "not reported";
}

function rollbackLabel(value: boolean | null) {
  return value === null ? "not reported" : value ? "available" : "unavailable";
}

function displayText(value: string) {
  return stringifySafe(value);
}
