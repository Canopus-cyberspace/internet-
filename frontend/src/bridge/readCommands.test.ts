import { afterEach, describe, expect, it } from "vitest";
import {
  getExportHistoryRecord,
  listExportHistory,
  listExportPolicyViolations,
} from "./readCommands";
import * as readCommands from "./readCommands";
import { setInvokeCoreForTests } from "./tauri/invoke";

const queryRequest = {
  page: { limit: 25, cursor: null },
  time_range: null,
  filters: [],
  sort: [],
  scope: { type: "global" },
};

const READ_CASES = [
  ["list_components", () => readCommands.listComponents()],
  ["get_component_detail", () => readCommands.getComponentDetail("component-1")],
  ["search_components", () => readCommands.searchComponents(queryRequest)],
  ["get_plugin_catalog", () => readCommands.getPluginCatalog()],
  ["get_plugin_manifest", () => readCommands.getPluginManifest("plugin-1")],
  ["search_plugins", () => readCommands.searchPlugins(queryRequest)],
  ["get_capability_overview", () => readCommands.getCapabilityOverview()],
  ["search_capabilities", () => readCommands.searchCapabilities(queryRequest)],
  ["search_findings", () => readCommands.searchFindings(queryRequest)],
  ["search_alerts", () => readCommands.searchAlerts(queryRequest)],
  ["search_incidents", () => readCommands.searchIncidents(queryRequest)],
  ["get_incident_detail", () => readCommands.getIncidentDetail("incident-1")],
  ["search_flows", () => readCommands.searchFlows(queryRequest)],
  ["search_dns", () => readCommands.searchDns(queryRequest)],
  ["search_tls", () => readCommands.searchTls(queryRequest)],
  [
    "get_graph_view",
    () =>
      readCommands.getGraphView({
        graph_type: "incident_graph",
        scope: "overview",
      }),
  ],
  [
    "list_active_responses",
    () => readCommands.listActiveResponses({ limit: 25, cursor: null }),
  ],
  [
    "search_response_plans",
    () => readCommands.searchResponsePlans(queryRequest),
  ],
  ["list_reports", () => readCommands.listReports({ limit: 25, cursor: null })],
  ["search_reports", () => readCommands.searchReports(queryRequest)],
  ["get_report", () => readCommands.getReport("report-1")],
  ["get_attack_coverage_summary", () => readCommands.getAttackCoverageSummary()],
  ["get_fusion_summary", () => readCommands.getFusionSummary()],
  ["list_security_facts", () => readCommands.listSecurityFacts({ limit: 25, cursor: null })],
  ["list_attack_hypotheses", () => readCommands.listAttackHypotheses({ limit: 25, cursor: null })],
  ["get_attack_hypothesis", () => readCommands.getAttackHypothesis("hypothesis-1")],
  ["get_durable_baseline_summary", () => readCommands.getDurableBaselineSummary()],
  ["get_evidence_quality_summary", () => readCommands.getEvidenceQualitySummary()],
  [
    "list_evidence_quality_records",
    () => readCommands.listEvidenceQualityRecords({ limit: 25, cursor: null }),
  ],
  [
    "get_evidence_quality_record",
    () => readCommands.getEvidenceQualityRecord("quality-1"),
  ],
  ["get_investigation_drill_down_summary", () => readCommands.getInvestigationDrillDownSummary()],
  [
    "resolve_navigation_reference",
    () =>
      readCommands.resolveNavigationReference({
        session_id: null,
        source_view: "investigation",
        target_kind: "evidence",
        target_id: "evidence-1",
      }),
  ],
  ["get_hypothesis_explanation_detail", () => readCommands.getHypothesisExplanationDetail("hypothesis-1")],
  ["get_baseline_drill_down_detail", () => readCommands.getBaselineDrillDownDetail("baseline-1")],
  ["get_incident_group_investigation_detail", () => readCommands.getIncidentGroupInvestigationDetail("group-1")],
  ["get_timeline_drill_down_detail", () => readCommands.getTimelineDrillDownDetail("timeline-1")],
  ["get_source_reliability_explanation", () => readCommands.getSourceReliabilityExplanation("source-1")],
  ["list_baseline_records", () => readCommands.listBaselineRecords({ limit: 25, cursor: null })],
  ["get_baseline_record", () => readCommands.getBaselineRecord("baseline-1")],
  ["list_baseline_indicators", () => readCommands.listBaselineIndicators({ limit: 25, cursor: null })],
  ["get_baseline_indicator", () => readCommands.getBaselineIndicator("indicator-1")],
  [
    "list_incident_linked_hypothesis_groups",
    () => readCommands.listIncidentLinkedHypothesisGroups({ limit: 25, cursor: null }),
  ],
  [
    "get_incident_linked_hypothesis_group",
    () => readCommands.getIncidentLinkedHypothesisGroup("group-1"),
  ],
  ["list_incident_timeline_entries", () => readCommands.listIncidentTimelineEntries({ limit: 25, cursor: null })],
  ["get_incident_timeline_entry", () => readCommands.getIncidentTimelineEntry("timeline-1")],
  [
    "list_source_reliability_summaries",
    () => readCommands.listSourceReliabilitySummaries({ limit: 25, cursor: null }),
  ],
  ["get_metadata_watch_controller_status", () => readCommands.getMetadataWatchControllerStatus()],
  ["list_metadata_watch_sources", () => readCommands.listMetadataWatchSources({ limit: 25, cursor: null })],
  ["get_metadata_watch_source", () => readCommands.getMetadataWatchSource("source-1")],
  ["list_metadata_sampling_batches", () => readCommands.listMetadataSamplingBatches({ limit: 25, cursor: null })],
  ["get_metadata_sampling_batch", () => readCommands.getMetadataSamplingBatch("batch-1")],
  [
    "list_export_history",
    () => readCommands.listExportHistory({ page: { limit: 25, cursor: null } }),
  ],
  ["search_export_history", () => readCommands.searchExportHistory(queryRequest)],
  [
    "get_export_history_record",
    () => readCommands.getExportHistoryRecord("export-result-1"),
  ],
  [
    "list_export_policy_violations",
    () => readCommands.listExportPolicyViolations(),
  ],
  ["get_runtime_profile", () => readCommands.getRuntimeProfile()],
  ["search_runtime_profiles", () => readCommands.searchRuntimeProfiles(queryRequest)],
  ["get_llm_alert_story_status", () => readCommands.getLlmAlertStoryStatus()],
  ["list_llm_alert_stories", () => readCommands.listLlmAlertStories({ limit: 24, cursor: null })],
  ["get_llm_alert_story", () => readCommands.getLlmAlertStory("story-id")],
  ["get_service_status", () => readCommands.getServiceStatus()],
  ["search_service_status", () => readCommands.searchServiceStatus(queryRequest)],
  ["list_authorized_native_capabilities", () => readCommands.listAuthorizedNativeCapabilities()],
  ["get_authorized_native_capability", () => readCommands.getAuthorizedNativeCapability("native-host")],
  ["get_native_permission_status_summary", () => readCommands.getNativePermissionStatusSummary()],
  ["get_native_visibility_summary", () => readCommands.getNativeVisibilitySummary()],
  ["get_native_permission_audit_summary", () => readCommands.getNativePermissionAuditSummary()],
  ["list_native_sampler_contracts", () => readCommands.listNativeSamplerContracts()],
  [
    "get_native_sampler_contract",
    () => readCommands.getNativeSamplerContract("process_metadata_sampler"),
  ],
  [
    "get_native_sampler_readiness_summary",
    () => readCommands.getNativeSamplerReadinessSummary(),
  ],
  [
    "get_native_sampler_readiness_detail",
    () => readCommands.getNativeSamplerReadinessDetail("process_metadata_sampler"),
  ],
  [
    "get_native_sampler_authorization_review",
    () => readCommands.getNativeSamplerAuthorizationReview("process_metadata_sampler"),
  ],
  [
    "get_future_security_fact_mapping_summary",
    () => readCommands.getFutureSecurityFactMappingSummary(),
  ],
  [
    "get_native_sampler_blocked_summary",
    () => readCommands.getNativeSamplerBlockedSummary(),
  ],
  [
    "get_missing_endpoint_visibility_summary",
    () => readCommands.getMissingEndpointVisibilitySummary(),
  ],
  ["get_edr_readiness_summary", () => readCommands.getEdrReadinessSummary()],
  ["get_native_scheduler_status", () => readCommands.getNativeSchedulerStatus()],
  [
    "list_native_sampler_schedule_statuses",
    () => readCommands.listNativeSamplerScheduleStatuses(),
  ],
  [
    "get_native_sampler_schedule_status",
    () => readCommands.getNativeSamplerScheduleStatus("process_metadata_sampler"),
  ],
  ["get_native_scheduler_summary", () => readCommands.getNativeSchedulerSummary()],
  [
    "get_native_scheduler_operational_summary",
    () => readCommands.getNativeSchedulerOperationalSummary(),
  ],
  ["get_portable_preferences", () => readCommands.getPortablePreferences()],
] as const;

describe("export history read commands", () => {
  afterEach(() => {
    setInvokeCoreForTests(null);
  });

  it("routes all Task 200 read commands through the safe invoke bridge", async () => {
    const calls: string[] = [];
    setInvokeCoreForTests(async <T,>(command: string): Promise<T> => {
      calls.push(command);
      return {
        items: [],
        limit: 25,
        cursor: null,
        next_cursor: null,
        has_more: false,
      } as T;
    });

    for (const [, invoke] of READ_CASES) {
      await invoke();
    }

    expect(calls).toEqual(READ_CASES.map(([command]) => command));
  });

  it("routes export history reads through the safe invoke bridge", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    setInvokeCoreForTests(async <T,>(
      command: string,
      args?: Record<string, unknown>,
    ): Promise<T> => {
      calls.push({ command, args });
      let response: unknown;
      if (command === "list_export_history") {
        response = {
          items: [],
          limit: 25,
          cursor: null,
          next_cursor: null,
          has_more: false,
        };
      } else if (command === "get_export_history_record") {
        response = {
          export_result_id: "export-result-1",
          report_id: "report-1",
          format: "redacted_json",
          destination: {
            destination_metadata_redacted: "local export",
            local_export_only: true,
          },
          file_hash: null,
          redaction_summary: { passed: true },
          actor_redacted: "local_user",
          exported_at: "2026-06-03T00:00:00Z",
          audit_id: "audit-1",
          success: true,
        };
      } else if (command === "list_export_policy_violations") {
        response = [];
      } else {
        throw new Error(`unexpected command ${command}`);
      }
      return response as T;
    });

    await listExportHistory({
      page: { limit: 25, cursor: null },
      report_id: "report-1",
    });
    await getExportHistoryRecord("export-result-1");
    await listExportPolicyViolations();

    expect(calls.map((call) => call.command)).toEqual([
      "list_export_history",
      "get_export_history_record",
      "list_export_policy_violations",
    ]);
    expect(calls[0]?.args).toEqual({
      query: {
        page: { limit: 25, cursor: null },
        report_id: "report-1",
      },
    });
  });
});
