import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { GraphViewModelDto } from "../../../bridge/dto/graph";
import type { ResponsePlanDto } from "../../../bridge/dto/response";
import { queryKeys } from "../../../bridge/queryKeys";
import { ResponsePage } from "../../../pages/response/ResponsePage";
import {
  ApprovalDialog,
  RecommendedActionsTable,
  responseRowsFromPlans,
} from "./ResponseWorkspace";

describe("Response workspace panels", () => {
  it("redacts recommendation table display strings", () => {
    const rows: Parameters<typeof RecommendedActionsTable>[0]["rows"] = [
      responseRow({
        actionType: "api_key firewall action",
        target: "session_token destination",
        ttl: "private_key ttl",
        auditRef: "credential audit ref",
      }),
    ];

    const markup = renderToStaticMarkup(
      <RecommendedActionsTable
        loading={false}
        rows={rows}
        selectedRowId={rows[0].id}
        view="recommended"
        onSelectRow={() => undefined}
      />,
    );

    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("api_key firewall action");
    expect(markup).not.toContain("session_token destination");
    expect(markup).not.toContain("private_key ttl");
    expect(markup).not.toContain("credential audit ref");
  });

  it("keeps high-risk approval actions disabled until review details exist", () => {
    const row = responseRow({
      actionId: "action:1",
      approvalRequired: true,
      risk: "high",
    });

    const markup = renderToStaticMarkup(
      withQueryClient(<ApprovalDialog row={row} />),
    );

    expect(markup).toContain("Approval dialog");
    expect(markup).toContain("Policy details reviewed");
    expect(markup).toContain("disabled");
    expect(markup).toContain("Approve");
    expect(markup).toContain("Reject");
  });

  it("renders honest loading states without fallback actions or graphs", () => {
    const markup = renderToStaticMarkup(withQueryClient(<ResponsePage />));

    expect(markup).toContain("Loading command-backed response data.");
    expect(markup).toContain("No response action selected.");
    expect(markup).toContain("No graph nodes");
    expect(markup).not.toContain(mockOnlyMarker());
  });

  it("renders command recommendations, policy, rollback, and graph data", () => {
    const plan = commandResponsePlan();
    const graph = commandResponseGraph();
    const markup = renderToStaticMarkup(
      withQueryClient(<ResponsePage />, (queryClient) => {
        queryClient.setQueryData(queryKeys.response.active, pageWith(plan));
        queryClient.setQueryData(
          queryKeys.graph.view(
            "response_impact_graph",
            JSON.stringify({ type: "response_plan", value: plan.plan_id }),
          ),
          graph,
        );
      }),
    );

    expect(markup).toContain("Recommend firewall block");
    expect(markup).toContain("Command redacted destination");
    expect(markup).toContain("Approval required");
    expect(markup).toContain("available");
    expect(markup).toContain("Command response target");
    expect(markup).not.toContain(mockOnlyMarker());
  });

  it("does not create an action row for an empty command plan", () => {
    const plan = commandResponsePlan();
    plan.recommended_actions = [];
    const markup = renderToStaticMarkup(
      withQueryClient(<ResponsePage />, (queryClient) => {
        queryClient.setQueryData(queryKeys.response.active, pageWith(plan));
      }),
    );

    expect(markup).toContain(
      "No command-backed response recommendations are available.",
    );
    expect(markup).not.toContain("Command redacted destination");
    expect(markup).not.toContain(mockOnlyMarker());
  });

  it("classifies approval as history without claiming execution started", () => {
    const plan = commandResponsePlan("approved");
    const [row] = responseRowsFromPlans([plan]);

    expect(row.status).toBe("history");
    expect(row.status).not.toBe("active");
  });
});

function responseRow(
  overrides: Partial<
    Parameters<typeof RecommendedActionsTable>[0]["rows"][number]
  >,
): Parameters<typeof RecommendedActionsTable>[0]["rows"][number] {
  return {
    id: "row:1",
    planId: "plan:1",
    actionId: null,
    actionType: "Temporary destination review",
    target: "redacted destination",
    scope: "single destination",
    expectedEffect: "observe",
    businessImpact: "none",
    decision: "recommend only",
    risk: "medium",
    ttl: "manual",
    rollback: "not needed",
    rollbackAvailable: false,
    approvalRequired: false,
    approvalState: "not_required",
    auditRef: "audit:required",
    status: "recommended",
    createdAt: "pending",
    ...overrides,
  };
}

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

function pageWith<T>(item: T) {
  return {
    items: [item],
    limit: 100,
    next_cursor: null,
    has_more: false,
  };
}

function commandResponsePlan(approvalState = "requested"): ResponsePlanDto {
  return {
    plan_id: "plan:command",
    source: {
      type: "incident",
      value: "incident:command",
    },
    recommended_actions: [
      {
        recommended_action_id: "recommendation:command",
        action_id: "action:command",
        action_type: "recommend_firewall_block",
        target: {
          target_summary_redacted: "Command redacted destination",
        },
        scope: {
          description_redacted: "Single command-backed destination",
        },
        expected_effect_redacted: "Reduce outbound risk",
        business_impact_redacted: "Manual operator review",
        ttl: {
          duration_seconds: 600,
          required_for_execution: true,
        },
        rollback_available: true,
        approval_required: true,
        approval_state: approvalState,
        response_level: "approval_required",
      },
    ],
    policy_decisions: [
      {
        level: "approval_required",
        risk_level: "high",
        approval_required: true,
      },
    ],
    approval_required: true,
    audit_requirements: ["policy_evaluation_recorded"],
    business_impact_redacted: "No execution without approval",
    created_at: "2026-06-06T00:00:00Z",
    is_replay: true,
    execution_disabled_in_replay: true,
  };
}

function commandResponseGraph(): GraphViewModelDto {
  return {
    graph_id: "graph:command",
    graph_type: "response_impact_graph",
    title: {
      value_redacted: "Command response impact graph",
      privacy_class: "internal",
    },
    nodes: [
      {
        id: "target:command",
        node_type: "destination",
        label: "Command response target",
        privacy_class: "internal",
      },
    ],
    edges: [],
    paths: [],
    filters: {
      source: "command",
    },
    redaction_status: {
      status: "passed",
    },
    node_limit: 40,
    edge_limit: 80,
    truncated: false,
  };
}

function mockOnlyMarker() {
  return ["MOCK", "ONLY"].join("_");
}
