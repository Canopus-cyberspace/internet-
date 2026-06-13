import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { InvestigationDrillDownSummaryDto } from "../../../bridge/dto/security";
import type { LlmAlertStoryStatusDto } from "../../../bridge/dto/settings";
import { InvestigationDrillDownPanel } from "./InvestigationDrillDownPanel";

describe("Investigation drill-down panel", () => {
  it("renders bounded rationale and advisory refs without sensitive values", () => {
    const markup = renderToStaticMarkup(
      <InvestigationDrillDownPanel
        llmStatus={null}
        summary={summary()}
        onGenerateStory={() => undefined}
      />,
    );

    expect(markup).toContain("Investigation rationale");
    expect(markup).toContain("Required facts");
    expect(markup).toContain("Bounded timeline");
    expect(markup).toContain("Source reliability");
    expect(markup).toContain("Metadata-only");
    expect(markup).not.toContain("Generate story");
    expect(markup).not.toContain("session_token");
    expect(markup).not.toContain("raw_payload");
    expect(markup).not.toContain("alice@example");
  });

  it("shows manual story generation only after every explicit gate is satisfied", () => {
    const onGenerateStory = vi.fn();
    const disabledMarkup = renderToStaticMarkup(
      <InvestigationDrillDownPanel
        llmStatus={status(false)}
        summary={summary()}
        onGenerateStory={onGenerateStory}
      />,
    );
    const enabledMarkup = renderToStaticMarkup(
      <InvestigationDrillDownPanel
        llmStatus={status(true)}
        summary={summary()}
        onGenerateStory={onGenerateStory}
      />,
    );

    expect(disabledMarkup).not.toContain("Generate story");
    expect(enabledMarkup).toContain("Generate story");
    expect(onGenerateStory).not.toHaveBeenCalled();
  });
});

function summary(): InvestigationDrillDownSummaryDto {
  const attackRef = {
    tactic_id: "TA0043",
    technique_id: "T1595",
    attack_version: "enterprise_verified_2026_06_12",
    confidence_bucket: "medium",
    required_visibility: "portable_network_metadata",
  };
  const story = {
    story_refs: [],
    alert_ref: "alert-safe-ref",
    incident_ref: "incident-safe-ref",
    bounded_input_available: true,
    existing_story_available: false,
    explicit_user_action_required: true,
    automatic_generation: false,
  };
  const suggestion = {
    kind: "review_evidence_refs",
    summary_redacted: "Review bounded evidence references",
    advisory_only: true,
    automatic_action: false,
  };
  return {
    generated_at: "2026-06-12T00:00:00Z",
    hypothesis_count: 1,
    baseline_count: 1,
    incident_group_count: 1,
    timeline_count: 1,
    source_reliability_count: 1,
    hypotheses: [
      {
        hypothesis_id: "hypothesis-safe-ref",
        family: "possible_api_abuse_chain",
        version: "fusion_v1",
        confidence_bucket: "medium",
        confidence_trend: "rising",
        supporting_fact_categories: ["api_error_burst"],
        required_fact_status: [
          {
            layer: "api",
            categories: ["api_error_burst"],
            required: true,
            status: "matched",
            matched_count_bucket: "low",
          },
        ],
        optional_fact_status: [],
        disqualifier_status: "not_observed",
        evidence_count_bucket: "low",
        source_count_bucket: "low",
        correlation_time_bucket: "current_session",
        provider_category_relation: "shared_provider_category",
        route_endpoint_relation: "shared_route_fingerprint",
        baseline_refs: ["baseline-safe-ref"],
        indicator_refs: ["indicator-safe-ref"],
        evidence_refs: ["evidence-safe-ref"],
        fact_refs: ["fact-safe-ref"],
        finding_refs: ["finding-safe-ref"],
        risk_refs: ["risk-safe-ref"],
        attack_refs: [attackRef],
        graph_refs: ["graph-safe-ref"],
        report_refs: ["report-section-safe-ref"],
        export_refs: ["export-safe-ref"],
        story_availability: story,
        degraded_reason: "metadata_only_visibility",
        missing_visibility_flags: ["no_process_attribution"],
        suggested_questions: ["Review corroborating metadata"],
        suggestions: [suggestion],
        summary_redacted: "Possible API abuse metadata hypothesis",
      },
    ],
    baselines: [
      {
        baseline_id: "baseline-safe-ref",
        scope: "current_session",
        scope_category: "api_metadata",
        indicator_kinds: ["first_seen_route_shape"],
        indicator_refs: ["indicator-safe-ref"],
        count_bucket: "low",
        rarity_bucket: "rare",
        recurrence_bucket: "single",
        trend_bucket: "rising",
        confidence_trend: "rising",
        confidence_bucket: "medium",
        source_reliability_bucket: "moderate",
        hypothesis_refs: ["hypothesis-safe-ref"],
        incident_group_refs: ["group-safe-ref"],
        evidence_refs: ["evidence-safe-ref"],
        fact_refs: ["fact-safe-ref"],
        finding_refs: ["finding-safe-ref"],
        risk_refs: ["risk-safe-ref"],
        provenance_refs: ["provenance-safe-ref"],
        attack_refs: [attackRef],
        report_refs: ["report-section-safe-ref"],
        export_refs: ["export-safe-ref"],
        degraded_reason: "metadata_only_visibility",
        missing_visibility_flags: ["no_process_attribution"],
        suggestions: [suggestion],
        summary_redacted: "Session baseline metadata",
      },
    ],
    incident_groups: [
      {
        group_id: "group-safe-ref",
        incident_id: "incident-safe-ref",
        hypothesis_refs: ["hypothesis-safe-ref"],
        baseline_refs: ["baseline-safe-ref"],
        indicator_refs: ["indicator-safe-ref"],
        timeline_refs: ["timeline-safe-ref"],
        evidence_refs: ["evidence-safe-ref"],
        fact_refs: ["fact-safe-ref"],
        finding_refs: ["finding-safe-ref"],
        risk_refs: ["risk-safe-ref"],
        attack_refs: [attackRef],
        graph_refs: ["graph-safe-ref"],
        report_refs: ["report-section-safe-ref"],
        export_refs: ["export-safe-ref"],
        source_reliability_refs: ["source-safe-ref"],
        source_reliability_buckets: ["moderate"],
        confidence_trend: "rising",
        severity_risk_trend: "rising",
        story_availability: story,
        degraded_reason: "metadata_only_visibility",
        missing_visibility_flags: ["no_process_attribution"],
        suggestions: [suggestion],
        summary_redacted: "Incident linked metadata group",
      },
    ],
    timeline: [
      {
        timeline_entry_id: "timeline-safe-ref",
        incident_id: "incident-safe-ref",
        group_id: "group-safe-ref",
        time_bucket: "2026-06-12T00:00:00Z",
        event_category: "hypothesis_update",
        hypothesis_refs: ["hypothesis-safe-ref"],
        baseline_refs: ["baseline-safe-ref"],
        evidence_refs: ["evidence-safe-ref"],
        finding_refs: ["finding-safe-ref"],
        risk_refs: ["risk-safe-ref"],
        attack_refs: [attackRef],
        source_health_refs: ["source-safe-ref"],
        report_refs: ["report-section-safe-ref"],
        confidence_bucket: "medium",
        degraded_reason: "metadata_only_visibility",
        summary_redacted: "Bounded timeline update",
      },
    ],
    source_reliability: [
      {
        source_id: "source-safe-ref",
        source_health_state: "active",
        reliability_bucket: "moderate",
        sampled_count_bucket: "low",
        malformed_count_bucket: "none",
        backpressure_count_bucket: "none",
        confidence_impact: "stable",
        baseline_refs: ["baseline-safe-ref"],
        incident_group_refs: ["group-safe-ref"],
        timeline_refs: ["timeline-safe-ref"],
        evidence_refs: ["evidence-safe-ref"],
        missing_visibility_flags: ["metadata_only_visibility"],
        suggestions: [suggestion],
        summary_redacted: "Portable metadata source reliability",
      },
    ],
    report_refs: ["report-section-safe-ref"],
    export_refs: ["export-safe-ref"],
    suggestions: [suggestion],
    portable_no_retention: true,
    metadata_only: true,
    automatic_llm_calls: false,
    response_execution: false,
  };
}

function status(enabled: boolean): LlmAlertStoryStatusDto {
  return {
    settings: {
      enabled,
      provider: "open_ai_compatible",
      model: "safe-model",
      api_key_storage_mode: "session_only",
      authorization_granted: enabled,
      timeout_seconds: 30,
    },
    api_key_configured: enabled,
    capability_status: enabled ? "authorized" : "llm_disabled",
    os_keystore_supported: false,
    last_successful_check: null,
    last_successful_generation: null,
    last_story_id: null,
    story_count: 0,
    base_url_configured: false,
    last_error_code: null,
    warning_redacted: "Explicit user action required",
    generated_at: "2026-06-12T00:00:00Z",
  };
}
