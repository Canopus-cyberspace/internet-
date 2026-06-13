import { BookOpenCheck, GitBranch, Sparkles } from "lucide-react";
import { useState } from "react";
import type {
  IncidentGroupInvestigationDetailDto,
  InvestigationDrillDownSummaryDto,
  LlmStoryAvailabilityDetailDto,
  QualityBreakdownDto,
} from "../../../bridge/dto/security";
import type { LlmAlertStoryStatusDto } from "../../../bridge/dto/settings";
import { humanize } from "../../../shared/renderers";
import {
  NavigationRefButtons,
  NavigationTargetButton,
} from "../../navigation/components/NavigationTargetButton";

interface InvestigationDrillDownPanelProps {
  readonly error?: boolean;
  readonly loading?: boolean;
  readonly pendingStory?: boolean;
  readonly summary: InvestigationDrillDownSummaryDto | null;
  readonly llmStatus: LlmAlertStoryStatusDto | null;
  readonly onGenerateStory: (alertId: string, incidentId?: string | null) => void;
}

export function InvestigationDrillDownPanel({
  error = false,
  loading = false,
  pendingStory = false,
  summary,
  llmStatus,
  onGenerateStory,
}: InvestigationDrillDownPanelProps) {
  const [selectedHypothesisId, setSelectedHypothesisId] = useState<string | null>(
    null,
  );
  const [selectedBaselineId, setSelectedBaselineId] = useState<string | null>(null);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);

  const hypothesis =
    summary?.hypotheses.find((item) => item.hypothesis_id === selectedHypothesisId) ??
    summary?.hypotheses[0] ??
    null;
  const baseline =
    summary?.baselines.find((item) => item.baseline_id === selectedBaselineId) ??
    summary?.baselines[0] ??
    null;
  const group =
    summary?.incident_groups.find((item) => item.group_id === selectedGroupId) ??
    summary?.incident_groups[0] ??
    null;
  const story = group?.story_availability ?? hypothesis?.story_availability ?? null;
  const canGenerateStory = storyGenerationAllowed(llmStatus, story);

  return (
    <section className="analysis-panel investigation-drill-down">
      <div className="analysis-panel-header">
        <strong>Investigation rationale</strong>
        <BookOpenCheck size={15} aria-hidden="true" />
      </div>
      {error ? (
        <span className="analysis-muted">
          Drill-down read model returned a redacted error.
        </span>
      ) : null}
      {summary ? (
        <>
          <div className="report-redaction-grid">
            <Metric label="Hypotheses" value={summary.hypothesis_count} />
            <Metric label="Baselines" value={summary.baseline_count} />
            <Metric label="Groups" value={summary.incident_group_count} />
            <Metric label="Timeline" value={summary.timeline_count} />
          </div>

          <Selector
            label="Hypothesis"
            selected={hypothesis?.hypothesis_id ?? null}
            values={summary.hypotheses.map((item) => ({
              id: item.hypothesis_id,
              label: item.family,
            }))}
            onSelect={setSelectedHypothesisId}
          />
          {hypothesis ? (
            <div className="metadata-watch-source-row">
              <strong>{humanize(hypothesis.family)}</strong>
              <small>
                {humanize(hypothesis.confidence_bucket)} confidence /{" "}
                {humanize(hypothesis.confidence_trend)} trend /{" "}
                {hypothesis.evidence_refs.length} evidence refs
              </small>
              <small>
                Provider relation: {humanize(hypothesis.provider_category_relation)} / route
                relation: {humanize(hypothesis.route_endpoint_relation)}
              </small>
              <QualityLine quality={hypothesis.quality} />
              <RefLine
                label="Traceability"
                refs={[
                  ...hypothesis.fact_refs,
                  ...hypothesis.finding_refs,
                  ...hypothesis.risk_refs,
                  ...hypothesis.graph_refs,
                  ...hypothesis.report_refs,
                  ...hypothesis.export_refs,
                ]}
              />
              <NavigationTargetButton
                label="Open hypothesis links"
                sourceView="investigation"
                targetId={hypothesis.hypothesis_id}
                targetKind="hypothesis"
              />
              <NavigationRefButtons
                refs={hypothesis.evidence_refs}
                sourceView="investigation"
                targetKind="evidence"
              />
              <NavigationRefButtons
                refs={hypothesis.baseline_refs}
                sourceView="investigation"
                targetKind="baseline"
              />
              <NavigationRefButtons
                refs={hypothesis.indicator_refs}
                sourceView="investigation"
                targetKind="baseline_indicator"
              />
              <NavigationRefButtons
                refs={hypothesis.attack_refs.map(
                  (item) => `${item.tactic_id}:${item.technique_id}`,
                )}
                sourceView="investigation"
                targetKind="attack_technique_row"
              />
              <NavigationRefButtons
                refs={hypothesis.graph_refs}
                sourceView="investigation"
                targetKind="graph_hint"
              />
              <StatusLine
                label="Required facts"
                values={hypothesis.required_fact_status.map(
                  (item) =>
                    `${humanize(item.layer)} ${humanize(item.status)} ${humanize(
                      item.matched_count_bucket,
                    )}`,
                )}
              />
              <StatusLine
                label="Missing visibility"
                values={hypothesis.missing_visibility_flags}
              />
              <StatusLine
                label="Suggested questions"
                values={hypothesis.suggested_questions}
              />
            </div>
          ) : null}

          <Selector
            label="Baseline"
            selected={baseline?.baseline_id ?? null}
            values={(summary.baselines ?? []).map((item) => ({
              id: item.baseline_id,
              label: item.scope_category,
            }))}
            onSelect={setSelectedBaselineId}
          />
          {baseline ? (
            <div className="metadata-watch-source-row">
              <strong>{humanize(baseline.scope_category)}</strong>
              <small>
                {humanize(baseline.rarity_bucket)} / {humanize(baseline.trend_bucket)} /{" "}
                {humanize(baseline.confidence_trend)} confidence trend
              </small>
              <QualityLine quality={baseline.quality} />
              <StatusLine
                label="Indicators"
                values={baseline.indicator_kinds.map(humanize)}
              />
              <RefLine
                label="Evidence and provenance"
                refs={[...baseline.evidence_refs, ...baseline.provenance_refs]}
              />
              <NavigationTargetButton
                label="Open baseline links"
                sourceView="investigation"
                targetId={baseline.baseline_id}
                targetKind="baseline"
              />
              <NavigationRefButtons
                refs={baseline.hypothesis_refs}
                sourceView="investigation"
                targetKind="hypothesis"
              />
              <NavigationRefButtons
                refs={baseline.incident_group_refs}
                sourceView="investigation"
                targetKind="incident_linked_group"
              />
              <NavigationRefButtons
                refs={baseline.indicator_refs}
                sourceView="investigation"
                targetKind="baseline_indicator"
              />
            </div>
          ) : null}

          <Selector
            label="Incident-linked group"
            selected={group?.group_id ?? null}
            values={summary.incident_groups.map((item) => ({
              id: item.group_id,
              label: item.summary_redacted,
            }))}
            onSelect={setSelectedGroupId}
          />
          {group ? <IncidentGroupDetail group={group} /> : null}

          <div className="metadata-watch-batch-strip">
            <strong>Bounded timeline</strong>
            <span>{summary.timeline.length} reference-only entries</span>
          </div>
          <div className="metadata-watch-list" role="table" aria-label="Bounded timeline">
            {summary.timeline.slice(0, 8).map((entry) => (
              <div className="metadata-watch-batch" key={entry.timeline_entry_id} role="row">
                <span role="cell">{humanize(entry.event_category)}</span>
                <small role="cell">
                  {humanize(entry.confidence_bucket)} confidence /{" "}
                  {entry.hypothesis_refs.length} hypothesis refs /{" "}
                  {entry.source_health_refs.length} source-health refs
                </small>
                <NavigationTargetButton
                  label="Open timeline links"
                  sourceView="timeline"
                  targetId={entry.timeline_entry_id}
                  targetKind="timeline_entry"
                />
                <NavigationRefButtons
                  refs={entry.evidence_refs}
                  sourceView="timeline"
                  targetKind="evidence"
                />
                <NavigationRefButtons
                  refs={entry.finding_refs}
                  sourceView="timeline"
                  targetKind="finding"
                />
                <NavigationRefButtons
                  refs={entry.risk_refs}
                  sourceView="timeline"
                  targetKind="risk"
                />
              </div>
            ))}
          </div>

          <div className="metadata-watch-batch-strip">
            <strong>Source reliability</strong>
            <span>{summary.source_reliability_count} bounded explanations</span>
          </div>
          {summary.source_reliability.slice(0, 4).map((source) => (
            <div className="metadata-watch-batch" key={source.source_id}>
              <span>
                {humanize(source.source_health_state)} /{" "}
                {humanize(source.reliability_bucket)}
              </span>
              <small>
                Confidence impact {humanize(source.confidence_impact)} /{" "}
                {source.evidence_refs.length} evidence refs
              </small>
              <QualityLine quality={source.quality} />
              <NavigationTargetButton
                label="Open source reliability"
                sourceView="investigation"
                targetId={source.source_id}
                targetKind="source_reliability_summary"
              />
            </div>
          ))}

          {canGenerateStory && story?.alert_ref ? (
            <button
              className="toolbar-button"
              disabled={pendingStory}
              type="button"
              onClick={() => onGenerateStory(story.alert_ref!, story.incident_ref)}
            >
              <Sparkles size={14} aria-hidden="true" />
              Generate story
            </button>
          ) : null}
          <div className="response-callout" data-tone="ok">
            <GitBranch size={15} aria-hidden="true" />
            <span>
              Metadata-only, Portable Default, no-retention drill-down. Suggestions are
              advisory; automatic story generation and response execution are off.
            </span>
          </div>
        </>
      ) : (
        <span className="analysis-muted">
          {loading ? "Loading bounded investigation rationale." : "No drill-down refs are available."}
        </span>
      )}
    </section>
  );
}

function IncidentGroupDetail({
  group,
}: {
  readonly group: IncidentGroupInvestigationDetailDto;
}) {
  return (
    <div className="metadata-watch-source-row">
      <strong>{group.summary_redacted}</strong>
      <small>
        {humanize(group.confidence_trend)} confidence trend /{" "}
        {humanize(group.severity_risk_trend)} risk trend
      </small>
      <QualityLine quality={group.quality} />
      {group.weak_merge_warning || group.broad_provider_only_merge_rejected ? (
        <small>
          Quality warning:{" "}
          {[
            group.weak_merge_warning ? "weak single-signal merge" : null,
            group.broad_provider_only_merge_rejected ? "broad provider-only merge rejected" : null,
          ]
            .filter(Boolean)
            .map((value) => humanize(String(value)))
            .join(", ")}
        </small>
      ) : null}
      <RefLine
        label="Linked refs"
        refs={[
          ...group.hypothesis_refs,
          ...group.baseline_refs,
          ...group.timeline_refs,
          ...group.evidence_refs,
          ...group.risk_refs,
          ...group.attack_refs.map((item) => item.technique_id),
        ]}
      />
      <NavigationTargetButton
        label="Open group links"
        sourceView="investigation"
        targetId={group.group_id}
        targetKind="incident_linked_group"
      />
      <NavigationRefButtons
        refs={group.timeline_refs}
        sourceView="investigation"
        targetKind="timeline_entry"
      />
      <StatusLine label="Missing visibility" values={group.missing_visibility_flags} />
      <StatusLine
        label="Advisory next steps"
        values={group.suggestions.map((item) => item.summary_redacted)}
      />
    </div>
  );
}

function Selector({
  label,
  selected,
  values,
  onSelect,
}: {
  readonly label: string;
  readonly selected: string | null;
  readonly values: Array<{ readonly id: string; readonly label: string }>;
  readonly onSelect: (id: string) => void;
}) {
  return (
    <div className="graph-node-strip" aria-label={`${label} selector`}>
      {values.slice(0, 8).map((value) => (
        <button
          className="graph-node-chip"
          data-selected={selected === value.id}
          key={value.id}
          type="button"
          onClick={() => onSelect(value.id)}
        >
          {humanize(value.label)}
        </button>
      ))}
    </div>
  );
}

function Metric({ label, value }: { readonly label: string; readonly value: number }) {
  return (
    <span>
      <strong>{value}</strong>
      {label}
    </span>
  );
}

function RefLine({ label, refs }: { readonly label: string; readonly refs: string[] }) {
  return (
    <small>
      {label}: {refs.length} bounded refs
    </small>
  );
}

function StatusLine({
  label,
  values,
}: {
  readonly label: string;
  readonly values: string[];
}) {
  return (
    <small>
      {label}: {values.length ? values.slice(0, 4).map(humanize).join(", ") : "none"}
    </small>
  );
}

function QualityLine({ quality }: { readonly quality?: QualityBreakdownDto }) {
  if (!quality) {
    return null;
  }
  const warnings = [
    ...quality.degraded_reasons.slice(0, 2),
    ...quality.missing_visibility_flags.slice(0, 2),
  ];
  return (
    <small>
      Quality: {humanize(quality.evidence_quality_bucket)} / source{" "}
      {humanize(quality.source_reliability_bucket)} / redaction{" "}
      {humanize(quality.redaction_completeness_bucket)} / visibility{" "}
      {humanize(quality.visibility_completeness_bucket)} / uncertainty{" "}
      {humanize(quality.uncertainty_bucket)} / report{" "}
      {humanize(quality.report_suitability_bucket)} / export{" "}
      {humanize(quality.export_suitability_bucket)}
      {warnings.length ? ` / ${warnings.map(humanize).join(", ")}` : ""}
    </small>
  );
}

function storyGenerationAllowed(
  status: LlmAlertStoryStatusDto | null,
  story: LlmStoryAvailabilityDetailDto | null,
) {
  return Boolean(
      status?.settings.enabled &&
      status.settings.authorization_granted &&
      status.settings.api_key_storage_mode === "session_only" &&
      status.api_key_configured &&
      story?.bounded_input_available &&
      story.alert_ref &&
      story.explicit_user_action_required &&
      !story.automatic_generation,
  );
}
