import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type {
  ExportHistoryRecordDto,
  ReportDto,
  ReportExportHistoryQueryDto,
} from "../../../bridge/dto/report";
import { queryKeys } from "../../../bridge/queryKeys";
import { ReportsPage } from "../../../pages/reports/ReportsPage";
import {
  AttackCoveragePanel,
  BaselineSummaryPanel,
  ExplicitExportPanel,
  ExportHistoryTable,
  FusionSummaryPanel,
  RedactionSummaryPanel,
  ReportPreview,
} from "./ReportsWorkspace";

describe("Reports workspace panels", () => {
  it("redacts report preview and redaction summary display strings", () => {
    const report: ReportDto = {
      report_id: "report:1",
      report_type: "incident",
      title_redacted: "session_token report title",
      summary_redacted: "api_key report summary",
      redaction_summary: {
        passed: true,
        redacted_field_count: 2,
        suppressed_section_count: 0,
        redacted_categories: ["private_key material"],
        completed_at: "credential completion",
      },
      sections: [
        {
          section_id: "section:1",
          section_type: "timeline",
          title_redacted: "raw_payload section",
          privacy_class: "internal",
        },
      ],
    };
    const row: Parameters<typeof ReportPreview>[0]["row"] = {
      id: "command:report:1",
      reportId: "report:1",
      title: "session_token report title",
      summary: "api_key report summary",
      reportType: "Incident",
      status: "Ready",
      redaction: "passed",
      redactionPassed: true,
      sections: 1,
      evidenceRefs: 0,
      graphSnapshots: 0,
      responseResults: 0,
      auditRef: "credential audit",
      privacyClass: "internal",
      createdAt: "pending",
      source: "command",
      raw: report,
    };

    const markup = [
      renderToStaticMarkup(
        <ReportPreview loading={false} report={report} row={row} />,
      ),
      renderToStaticMarkup(<RedactionSummaryPanel report={report} row={row} />),
    ].join("");

    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("session_token report title");
    expect(markup).not.toContain("api_key report summary");
    expect(markup).not.toContain("raw_payload section");
    expect(markup).not.toContain("private_key material");
    expect(markup).not.toContain("credential audit");
  });

  it("redacts export history display strings", () => {
    const rows: Parameters<typeof ExportHistoryTable>[0]["rows"] = [
      {
        id: "export:1",
        report: "api_key report",
        format: "redacted_json",
        destination: "session_token destination",
        redaction: "passed",
        fileHash: "private_key hash",
        audit: "credential audit",
        graphRefs: "1: session_token graph",
        evidenceRefs: "1: api_key evidence",
        responseRefs: "1: authorization response",
        rollbackRefs: "1: password rollback",
        storyRefs: "1: session_token story",
        graphRefCount: 1,
        evidenceRefCount: 1,
        responseRefCount: 1,
        rollbackRefCount: 1,
        storyRefCount: 1,
        status: "completed",
        source: "command",
      },
    ];

    const markup = renderToStaticMarkup(<ExportHistoryTable rows={rows} />);

    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("api_key report");
    expect(markup).not.toContain("session_token destination");
    expect(markup).not.toContain("private_key hash");
    expect(markup).not.toContain("credential audit");
    expect(markup).not.toContain("session_token graph");
    expect(markup).not.toContain("api_key evidence");
    expect(markup).not.toContain("authorization response");
    expect(markup).not.toContain("password rollback");
    expect(markup).not.toContain("session_token story");
  });

  it("renders bounded ATT&CK coverage without sensitive marker strings", () => {
    const markup = renderToStaticMarkup(
      <AttackCoveragePanel
        summary={{
          attack_version: "enterprise-verified-2026-06-12",
          generated_at: "2026-06-12T00:00:00Z",
          complete_coverage_claimed: false,
          technique_rows: [
            {
              tactic_id: "TA0011",
              technique_id: "T1071.001",
              attack_version: "enterprise-verified-2026-06-12",
              rule_detector_ids: ["portable_http_analysis_v1"],
              finding_refs: ["11111111-1111-4111-8111-111111111111"],
              evidence_refs: ["22222222-2222-4222-8222-222222222222"],
              risk_refs: ["33333333-3333-4333-8333-333333333333"],
              confidence_bucket: "medium",
              degraded_reason: "metadata_only_visibility",
              required_visibility: "portable_network_metadata",
              package_category: "http_analysis_v1",
              observed_count_bucket: "single",
              last_observed_bucket: "current_session",
              states: ["covered", "observed", "evidence_backed", "degraded"],
            },
            {
              tactic_id: "TA0002",
              technique_id: "T1059",
              attack_version: "enterprise-verified-2026-06-12",
              rule_detector_ids: ["authorized_native_extension_required"],
              finding_refs: [],
              evidence_refs: [],
              risk_refs: [],
              confidence_bucket: "low",
              degraded_reason: "authorized_native_extension_required",
              required_visibility: "authorized_native_process_visibility",
              package_category: "authorized_native_extension",
              observed_count_bucket: "none",
              last_observed_bucket: "none",
              states: ["unsupported", "requires_authorized_native_extension"],
            },
          ],
          top_tactics: [{ label: "TA0011", count: 1 }],
          package_coverage: [
            { label: "http_analysis_v1", count: 1 },
            { label: "authorized_native_extension", count: 1 },
          ],
          state_counts: [{ label: "observed", count: 1 }],
          finding_refs: ["11111111-1111-4111-8111-111111111111"],
          evidence_refs: ["22222222-2222-4222-8222-222222222222"],
          risk_refs: ["33333333-3333-4333-8333-333333333333"],
          degraded_reason: "metadata_only_visibility",
        }}
      />,
    );

    expect(markup).toContain("ATT&amp;CK coverage");
    expect(markup).toContain("Not complete");
    expect(markup).toContain("Native needed");
    expect(markup).toContain("TA0011");
    expect(markup).not.toContain("session_token");
    expect(markup).not.toContain("credential");
    expect(markup).not.toContain("raw_payload");
  });

  it("renders bounded fusion status and portable boundaries without sensitive values", () => {
    const markup = renderToStaticMarkup(
      <FusionSummaryPanel
        summary={{
          generated_at: "2026-06-12T00:00:00Z",
          sampler_health: [
            {
              sampler_id: "dns_metadata_sampler",
              layer: "dns",
              source_kind: "portable_import",
              state: "enabled",
              sampling_mode: "confirmed_import",
              checkpoint_state: "session_only",
              output_fact_categories: ["dns_observation"],
              event_bus_topics: ["network.dns.observation"],
              privacy_boundary: "bounded_metadata_only",
              visibility_requirements: ["portable_network_metadata"],
              portable_default_available: true,
            },
            {
              sampler_id: "authorized_native_host_placeholder",
              layer: "authorized_native_host_placeholder",
              source_kind: "authorized_native_placeholder",
              state: "not_authorized",
              sampling_mode: "placeholder",
              checkpoint_state: "not_authorized",
              output_fact_categories: ["native_visibility_placeholder"],
              event_bus_topics: ["security.fusion.context"],
              privacy_boundary: "requires_explicit_authorization",
              visibility_requirements: ["authorized_native_extension"],
              portable_default_available: false,
            },
          ],
          fact_count: 2,
          hypothesis_count: 1,
          facts: [],
          hypotheses: [
            {
              hypothesis_record_id: "hypothesis-safe-ref",
              definition_id: "possible_api_abuse_chain",
              version: "1.0.0",
              category: "possible_api_abuse_chain",
              fact_refs: ["fact-safe-ref"],
              correlated_layers: ["api", "waf"],
              correlation_count: 2,
              confidence_bucket: "medium",
              degraded_reason: "metadata_only_visibility",
              missing_visibility_flags: ["no_process_attribution"],
              evidence_refs: ["evidence-safe-ref"],
              finding_refs: ["finding-safe-ref"],
              risk_refs: ["risk-safe-ref"],
              graph_hint_refs: ["graph-safe-ref"],
              optional_llm_story_marker: true,
            },
          ],
          top_correlated_layers: [{ label: "api", count: 1 }],
          top_hypothesis_categories: [{ label: "possible_api_abuse_chain", count: 1 }],
          degraded_visibility_context: [
            "metadata_only_visibility",
            "no_process_attribution",
          ],
          fact_refs: ["fact-safe-ref"],
          hypothesis_refs: ["hypothesis-safe-ref"],
          evidence_refs: ["evidence-safe-ref"],
          finding_refs: ["finding-safe-ref"],
          graph_hint_refs: ["graph-safe-ref"],
          privacy_class: "internal",
          automatic_llm_calls: false,
        }}
      />,
    );

    expect(markup).toContain("Security fusion");
    expect(markup).toContain("2");
    expect(markup).toContain("1 active");
    expect(markup).toContain("Native / SDN");
    expect(markup).toContain("Automatic LLM calls");
    expect(markup).not.toContain("session_token");
    expect(markup).not.toContain("raw_payload");
    expect(markup).not.toContain("alice@example");
  });

  it("renders durable baseline refs without raw or sensitive values", () => {
    const markup = renderToStaticMarkup(
      <BaselineSummaryPanel
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
          indicators: [
            {
              indicator_id: "indicator-safe-ref",
              kind: "first_seen_provider_category",
              baseline_refs: ["baseline-safe-ref"],
              evidence_refs: ["evidence-safe-ref"],
              fact_refs: ["fact-safe-ref"],
              hypothesis_refs: ["hypothesis-safe-ref"],
              confidence_bucket: "medium",
              degraded_reason: "metadata_only_visibility",
              missing_visibility_flags: ["no_process_attribution"],
              summary_redacted: "session_token should stay hidden",
            },
          ],
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
              degraded_reason: "private_key should stay hidden",
              missing_visibility_flags: ["no_raw_payload"],
              report_section_refs: ["section-safe-ref"],
            },
          ],
          incident_timeline: [],
          source_reliability: [
            {
              source_id: "source-safe-ref",
              source_health_state: "degraded",
              reliability_bucket: "weak",
              sampled_count_bucket: "low",
              malformed_count_bucket: "none",
              backpressure_count_bucket: "none",
              degraded_reason: "api_key should stay hidden",
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

    expect(markup).toContain("Durable baseline");
    expect(markup).toContain("Export refs only");
    expect(markup).toContain("Automatic LLM calls");
    expect(markup).toContain("Response execution");
    expect(markup).not.toContain("session_token");
    expect(markup).not.toContain("private_key");
    expect(markup).not.toContain("api_key");
    expect(markup).not.toContain("raw_payload");
  });

  it("renders explicit save/export actions behind preview confirmation", () => {
    const report: ReportDto = {
      report_id: "report:explicit",
      report_type: "incident",
      title_redacted: "Redacted explicit report",
      summary_redacted: "Redacted explicit summary",
      incident_refs: ["11111111-1111-4111-8111-111111111111"],
      redaction_summary: {
        passed: true,
      },
      sections: [],
    };
    const row: Parameters<typeof ExplicitExportPanel>[0]["row"] = {
      id: "command:report:explicit",
      reportId: "report:explicit",
      title: "Redacted explicit report",
      summary: "Redacted explicit summary",
      reportType: "Incident",
      status: "Ready",
      redaction: "passed",
      redactionPassed: true,
      sections: 0,
      evidenceRefs: 0,
      graphSnapshots: 0,
      responseResults: 0,
      auditRef: "audit",
      privacyClass: "internal",
      createdAt: "pending",
      source: "command",
      raw: report,
    };
    const mutation = {
      data: undefined,
      isError: false,
      isPending: false,
      mutate: () => undefined,
      reset: () => undefined,
    };

    const markup = renderToStaticMarkup(
      <ExplicitExportPanel
        confirmMutation={
          mutation as unknown as Parameters<typeof ExplicitExportPanel>[0]["confirmMutation"]
        }
        previewMutation={
          mutation as unknown as Parameters<typeof ExplicitExportPanel>[0]["previewMutation"]
        }
        report={report}
        row={row}
        serviceStatus={{
          connected: false,
          degraded: true,
          reason: "service_unreachable",
          profile_mode: "portable-no-retention",
          active_session_id: "22222222-2222-4222-8222-222222222222",
          local_core_status: "healthy",
          elevated_service_status: "disconnected",
          ipc_status: "disconnected",
          storage_status: "healthy",
          reduced_visibility: true,
          privileged_actions_available: false,
          capture_available: false,
          machine_local_capability_status: null,
          message_redacted: "Read-only local metadata is available",
          generated_at: "2026-06-05T00:00:00Z",
        }}
      />,
    );

    expect(markup).toContain("Save Session");
    expect(markup).toContain("Export Report");
    expect(markup).toContain("Export Graph");
    expect(markup).toContain("Preview Redacted Artifact");
    expect(markup).toContain("Confirm Export");
    expect(markup).not.toContain("raw_payload");
    expect(markup).not.toContain("api_key");
  });

  it("renders honest empty report and export-history states without fallback records", () => {
    const historyRequest = exportHistoryRequest(null);
    const markup = renderToStaticMarkup(
      withQueryClient(<ReportsPage />, (queryClient) => {
        queryClient.setQueryData(queryKeys.report.list, emptyPage());
        queryClient.setQueryData(
          queryKeys.report.exportHistoryList(historyRequest),
          emptyPage(),
        );
      }),
    );

    expect(markup).toContain("No reports are available from the command bridge.");
    expect(markup).toContain(
      "No export history records are available from the command bridge.",
    );
    expect(markup).toContain("Select a command-backed report.");
    expect(markup).not.toContain(mockOnlyMarker());
  });

  it("renders command report detail, redaction summary, sections, and export history", () => {
    const report = commandReport();
    const history = commandExportHistory();
    const historyRequest = exportHistoryRequest(report.report_id);
    const markup = renderToStaticMarkup(
      withQueryClient(<ReportsPage />, (queryClient) => {
        queryClient.setQueryData(queryKeys.report.list, pageWith(report));
        queryClient.setQueryData(queryKeys.report.detail(report.report_id), report);
        queryClient.setQueryData(
          queryKeys.report.exportHistoryList(historyRequest),
          pageWith(history),
        );
      }),
    );

    expect(markup).toContain("Command-backed incident report");
    expect(markup).toContain("Command-backed timeline");
    expect(markup).toContain("Fields removed");
    expect(markup).toContain("4");
    expect(markup).toContain("1 exports");
    expect(markup).toContain("Redacted JSON");
    expect(markup).toContain("abc123");
    expect(markup).toContain("Graph refs");
    expect(markup).toContain("Evidence refs");
    expect(markup).toContain("Response refs");
    expect(markup).toContain("Rollback refs");
    expect(markup).toContain("1: 33333333-3333-4333-8333-333333333333");
    expect(markup).toContain("1: 44444444-4444-4444-8444-444444444444");
    expect(markup).toContain("1: 55555555-5555-4555-8555-555555555555");
    expect(markup).toContain("1: 66666666-6666-4666-8666-666666666666");
    expect(markup).toContain('data-graph-ref-count="1"');
    expect(markup).toContain('data-evidence-ref-count="1"');
    expect(markup).toContain('data-response-ref-count="1"');
    expect(markup).toContain('data-rollback-ref-count="1"');
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

function emptyPage<T>() {
  return {
    items: [] as T[],
    limit: 100,
    next_cursor: null,
    has_more: false,
  };
}

function pageWith<T>(item: T) {
  return {
    items: [item],
    limit: 100,
    next_cursor: null,
    has_more: false,
  };
}

function exportHistoryRequest(reportId: string | null): ReportExportHistoryQueryDto {
  return {
    page: { limit: 100, cursor: null },
    report_id: reportId,
  };
}

function commandReport(): ReportDto {
  return {
    report_id: "report:command",
    report_type: "incident",
    title_redacted: "Command-backed incident report",
    summary_redacted: "Command-backed redacted metadata summary",
    status: "ready_for_export",
    redaction_summary: {
      passed: true,
      redacted_field_count: 4,
      suppressed_section_count: 1,
      redacted_categories: ["network_metadata"],
      completed_at: "2026-06-06T00:00:00Z",
    },
    sections: [
      {
        section_id: "section:command",
        section_type: "timeline",
        title_redacted: "Command-backed timeline",
        privacy_class: "internal",
        evidence_refs: ["evidence:command"],
      },
    ],
    incident_refs: ["11111111-1111-4111-8111-111111111111"],
    audit_ref: {
      audit_id: "audit:command",
    },
    privacy_class: "internal",
    created_at: "2026-06-06T00:00:00Z",
  };
}

function commandExportHistory(): ExportHistoryRecordDto {
  return {
    export_result_id: "export:command",
    report_id: "report:command",
    format: "redacted_json",
    destination: {
      destination_metadata_redacted: "local redacted export",
      local_export_only: true,
    },
    file_hash: {
      algorithm: "sha256",
      value: "abc123",
      calculated_at: "2026-06-06T00:00:01Z",
    },
    redaction_summary: {
      passed: true,
    },
    graph_snapshot_refs: ["33333333-3333-4333-8333-333333333333"],
    evidence_refs: ["44444444-4444-4444-8444-444444444444"],
    response_result_refs: ["55555555-5555-4555-8555-555555555555"],
    rollback_result_refs: ["66666666-6666-4666-8666-666666666666"],
    llm_story_refs: ["77777777-7777-4777-8777-777777777777"],
    actor_redacted: "local operator",
    exported_at: "2026-06-06T00:00:01Z",
    audit_id: "audit:export",
    success: true,
  };
}

function mockOnlyMarker() {
  return ["MOCK", "ONLY"].join("_");
}
