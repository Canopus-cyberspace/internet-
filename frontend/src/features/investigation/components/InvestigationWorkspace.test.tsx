import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { defaultQueryRequest, queryKeys } from "../../../bridge/queryKeys";
import { InvestigationPage } from "../../../pages/investigation/InvestigationPage";
import { registerDefaultRenderers } from "../../../shared/renderers";
import {
  callClick,
  findByClassName,
  textContent,
} from "../../../shared/testing/reactElementQueries";
import {
  AttackPathPanel,
  BaselineFollowUpPanel,
  CaseList,
} from "./InvestigationWorkspace";

registerDefaultRenderers();

describe("Investigation workspace", () => {
  it("renders the page shell with case, graph, detail, response, and report areas", () => {
    const markup = renderToStaticMarkup(withQueryClient(<InvestigationPage />));

    expect(markup).toContain("Investigation");
    expect(markup).toContain("Case list");
    expect(markup).toContain("Attack path");
    expect(markup).toContain("Evidence");
    expect(markup).toContain("Timeline");
    expect(markup).toContain("Baseline follow-up");
    expect(markup).toContain("Risk");
    expect(markup).toContain("Response plan");
    expect(markup).toContain("Report action");
    expect(markup).toContain("Loading command-backed security cases.");
    expect(markup).not.toContain(mockOnlyMarker());
  });

  it("redacts sensitive case-list display strings", () => {
    const rows: Parameters<typeof CaseList>[0]["rows"] = [
      {
        id: "finding:redacted-marker",
        entityId: "finding:redacted-marker",
        kind: "finding",
        title: "session_token should not be displayed",
        severity: "api_key_high",
        state: "cookie_open",
        evidence: "1 ref",
        source: "command",
        raw: { finding_id: "finding:redacted-marker" },
      },
    ];

    const markup = renderToStaticMarkup(
      <CaseList
        activeKind="all"
        loading={false}
        rows={rows}
        selectedCaseId={rows[0].id}
        totalRows={rows.length}
        onSelectKind={() => undefined}
        onSelectRow={() => undefined}
      />,
    );

    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("session_token should not be displayed");
    expect(markup).not.toContain("api_key_high");
    expect(markup).not.toContain("cookie_open");
  });

  it("keeps case filter tabs and case rows clickable", () => {
    const onSelectKind = vi.fn();
    const onSelectRow = vi.fn();
    const rows: Parameters<typeof CaseList>[0]["rows"] = [
      {
        id: "incident:one",
        entityId: "incident-one",
        kind: "incident",
        title: "Incident one",
        severity: "high",
        state: "triage",
        evidence: "2 alerts",
        source: "command",
        raw: { incident_id: "incident-one" },
      },
      {
        id: "finding:two",
        entityId: "finding-two",
        kind: "finding",
        title: "Finding two",
        severity: "medium",
        state: "open",
        evidence: "1 ref",
        source: "command",
        raw: { finding_id: "finding-two" },
      },
    ];

    const tree = CaseList({
      activeKind: "all",
      loading: false,
      rows,
      selectedCaseId: rows[0].id,
      totalRows: rows.length,
      onSelectKind,
      onSelectRow,
    });

    const incidentFilter = findByClassName(tree, "case-filter-tab").find(
      (element) => textContent(element).trim() === "incident",
    );
    const secondCase = findByClassName(tree, "case-row-button").find((element) =>
      textContent(element).includes("Finding two"),
    );

    expect(incidentFilter).toBeDefined();
    expect(secondCase).toBeDefined();
    callClick(incidentFilter!);
    callClick(secondCase!);

    expect(onSelectKind).toHaveBeenCalledWith("incident");
    expect(onSelectRow).toHaveBeenCalledWith(rows[1]);
  });

  it("keeps attack-path graph selection labels redacted", () => {
    const row: Parameters<typeof CaseList>[0]["rows"][number] = {
      id: "incident:case-1",
      entityId: "incident:case-1",
      kind: "incident",
      title: "Metadata-only incident",
      severity: "high",
      state: "triage",
      evidence: "2 alerts",
      source: "command",
      raw: { incident_id: "case-1" },
    };

    const markup = renderToStaticMarkup(
      withQueryClient(
        <AttackPathPanel
          detail={null}
          row={row}
          selectedGraphNodeId="private_key_node"
          onSelectGraphNode={() => undefined}
        />,
      ),
    );

    expect(markup).toContain("Attack path");
    expect(markup).toContain("No command-backed attack-path graph is available.");
    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("private_key_node");
  });

  it("renders baseline follow-up refs without sensitive values", () => {
    const markup = renderToStaticMarkup(
      <BaselineFollowUpPanel
        summary={{
          generated_at: "2026-06-12T00:00:00Z",
          scope: "current_session",
          persistence_status: {
            mode: "portable_no_retention",
            automatic_durable_persistence: false,
            explicit_export_allowed: true,
            durable_security_history_written: false,
            storage_boundary: "session_memory",
          },
          baseline_count: 2,
          indicator_count: 1,
          incident_group_count: 1,
          timeline_entry_count: 1,
          source_reliability_count: 1,
          records: [],
          indicators: [],
          incident_groups: [
            {
              group_id: "group-safe-ref",
              incident_id: null,
              group_key_hash: "hash:group",
              hypothesis_refs: ["hypothesis-safe-ref"],
              evidence_refs: ["evidence-safe-ref"],
              fact_refs: ["fact-safe-ref"],
              finding_refs: ["finding-safe-ref"],
              risk_refs: ["risk-safe-ref"],
              baseline_refs: ["baseline-safe-ref"],
              attack_refs: [],
              graph_refs: ["graph-safe-ref"],
              confidence_trend: "rising",
              severity_trend: "flat",
              first_seen_bucket: "current_session",
              last_updated_bucket: "current_session",
              degraded_reason: "session_token should stay hidden",
              missing_visibility_flags: ["no_raw_payload"],
              report_section_refs: ["section-safe-ref"],
            },
          ],
          incident_timeline: [
            {
              timeline_entry_id: "timeline-safe-ref",
              incident_id: null,
              group_id: "group-safe-ref",
              time_bucket: "current_session",
              event_category: "baseline_indicator",
              hypothesis_refs: ["hypothesis-safe-ref"],
              evidence_refs: ["evidence-safe-ref"],
              fact_refs: ["fact-safe-ref"],
              finding_refs: ["finding-safe-ref"],
              risk_refs: ["risk-safe-ref"],
              baseline_refs: ["baseline-safe-ref"],
              attack_refs: [],
              source_health_refs: ["source-safe-ref"],
              confidence_bucket: "medium",
              degraded_reason: "api_key should stay hidden",
              summary_redacted: "private_key should stay hidden",
            },
          ],
          source_reliability: [
            {
              source_id: "source-safe-ref",
              source_health_state: "degraded",
              reliability_bucket: "weak",
              sampled_count_bucket: "low",
              malformed_count_bucket: "none",
              backpressure_count_bucket: "none",
              degraded_reason: "cookie should stay hidden",
              evidence_refs: [],
            },
          ],
          baseline_refs: ["baseline-safe-ref"],
          evidence_refs: ["evidence-safe-ref"],
          fact_refs: ["fact-safe-ref"],
          hypothesis_refs: ["hypothesis-safe-ref"],
          finding_refs: ["finding-safe-ref"],
          risk_refs: ["risk-safe-ref"],
          attack_refs: [],
          provenance_refs: ["provenance-safe-ref"],
          degraded_visibility_context: ["metadata_only_visibility"],
          missing_visibility_flags: ["no_process_attribution"],
          report_ref_count: 1,
          export_ref_count: 1,
          automatic_llm_calls: false,
          response_execution: false,
        }}
      />,
    );

    expect(markup).toContain("Baseline follow-up");
    expect(markup).toContain("timeline refs");
    expect(markup).toContain("Portable Default");
    expect(markup).not.toContain("session_token");
    expect(markup).not.toContain("raw_payload");
    expect(markup).not.toContain("api_key");
    expect(markup).not.toContain("private_key");
    expect(markup).not.toContain("cookie");
  });

  it("renders a stable empty case-list state without fallback security records", () => {
    const markup = renderToStaticMarkup(
      <CaseList
        activeKind="all"
        loading={false}
        rows={[]}
        selectedCaseId={null}
        totalRows={0}
        onSelectKind={() => undefined}
        onSelectRow={() => undefined}
      />,
    );

    expect(markup).toContain("0 rows");
    expect(markup).toContain(
      "No findings, alerts, or incidents are available from the command bridge.",
    );
    expect(markup).not.toContain(mockOnlyMarker());
  });

  it("renders findings, alerts, and incidents from command query data only", () => {
    const markup = renderToStaticMarkup(
      withQueryClient(<InvestigationPage />, (queryClient) => {
        queryClient.setQueryData(queryKeys.security.findings(defaultQueryRequest()), {
          items: [
            {
              finding_id: "finding-demo",
              finding_type: "c2.metadata",
              severity: "high",
              state: "open",
              summary_redacted: "Command-backed C2 metadata finding",
              evidence_refs: ["evidence-demo"],
              risk_score: 74,
            },
          ],
          limit: 100,
          next_cursor: null,
          has_more: false,
        });
        queryClient.setQueryData(queryKeys.security.alerts(defaultQueryRequest()), {
          items: [
            {
              alert_id: "alert-demo",
              severity: "high",
              state: "new",
              summary_redacted: "Command-backed promoted alert",
              finding_refs: ["finding-demo"],
            },
          ],
          limit: 100,
          next_cursor: null,
          has_more: false,
        });
        queryClient.setQueryData(queryKeys.security.incidents(defaultQueryRequest()), {
          items: [
            {
              incident_id: "incident-demo",
              severity: "high",
              state: "triage",
              summary_redacted: "Command-backed incident",
              alert_refs: ["alert-demo"],
            },
          ],
          limit: 100,
          next_cursor: null,
          has_more: false,
        });
        queryClient.setQueryData(queryKeys.security.incidentDetail("incident-demo"), {
          incident: {
            incident_id: "incident-demo",
            severity: "high",
            state: "triage",
            summary_redacted: "Command-backed incident",
            alert_refs: ["alert-demo"],
          },
          related_alerts: [],
          related_findings: [],
          graph: emptyGraph(),
          response_plans: [],
          reports: [],
        });
        queryClient.setQueryData(
          queryKeys.graph.view("incident_graph", JSON.stringify("overview")),
          emptyGraph(),
        );
      }),
    );

    expect(markup).toContain("Command-backed incident");
    expect(markup).toContain("Command-backed promoted alert");
    expect(markup).toContain("Command-backed C2 metadata finding");
    expect(markup).toContain("incident / triage / command");
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

function emptyGraph() {
  return {
    graph_id: "graph:empty",
    graph_type: "incident_graph",
    nodes: [],
    edges: [],
    paths: [],
    filters: { scope: "overview" },
    redaction_status: { status: "passed" },
  };
}

function mockOnlyMarker() {
  return ["MOCK", "ONLY"].join("_");
}
