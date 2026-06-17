import { AlertTriangle, ShieldAlert } from "lucide-react";
import type { JsonValue } from "../../../bridge/dto/common";
import type {
  EndpointAttackContextDto,
  EndpointThreatAnalysisSummaryDto,
  EndpointThreatFindingReadModelDto,
} from "../../../bridge/dto/security";
import { humanize, stringifySafe } from "../../../shared/renderers";
import { NavigationRefButtons } from "../../navigation/components/NavigationTargetButton";

interface EndpointThreatPanelProps {
  readonly error?: boolean;
  readonly loading?: boolean;
  readonly summary: EndpointThreatAnalysisSummaryDto | null;
}

const endpointWarnings = [
  "endpoint category context: available",
  "specific process identity: unavailable",
  "process-network attribution: unavailable",
  "confirmed compromise: not established",
] as const;

export function EndpointThreatPanel({
  error = false,
  loading = false,
  summary,
}: EndpointThreatPanelProps) {
  const finding = summary?.findings[0] ?? null;
  const attackRefs = finding?.attack_refs.length
    ? finding.attack_refs
    : summary?.attack_context ?? [];
  const riskRefs = summary?.risk_hints.flatMap((risk) => risk.risk_refs) ?? [];

  return (
    <section className="analysis-panel endpoint-threat-panel">
      <div className="analysis-panel-header">
        <strong>Endpoint threat analysis</strong>
        <ShieldAlert size={15} aria-hidden="true" />
      </div>
      {error ? (
        <span className="analysis-muted">
          Endpoint threat read model returned a redacted error.
        </span>
      ) : null}
      {summary ? (
        <>
          <div className="report-redaction-grid">
            <Metric label="Findings" value={summary.finding_count} />
            <Metric label="Evidence" value={summary.evidence_count} />
            <Metric label="Rejected" value={summary.rejected_count} />
            <Metric label="Advisories" value={summary.advisory_count} />
          </div>

          <div className="response-callout" data-tone="warning">
            <AlertTriangle size={15} aria-hidden="true" />
            <span>{endpointWarnings.map(safeEndpointText).join(" / ")}</span>
          </div>

          {finding ? (
            <FindingDetail
              attackRefs={attackRefs}
              finding={finding}
              graphRefs={summary.graph_refs}
              hypothesisRefs={summary.evidence_correlation.hypothesis_refs}
              riskRefs={riskRefs}
              supportBucket={summary.baseline_support.support_bucket}
              baselineRefs={summary.baseline_support.baseline_refs}
              sourceReliabilityBuckets={summary.quality.source_reliability_buckets}
            />
          ) : (
            <span className="analysis-muted">
              No endpoint threat findings are available. Category facts alone do not
              create findings.
            </span>
          )}

          <StatusLine
            label="Degraded context"
            values={[
              ...summary.degraded_reasons,
              ...summary.missing_visibility.degraded_reasons,
            ]}
          />
          <StatusLine
            label="Rejected candidate reasons"
            values={summary.rejected_candidates.map((candidate) => candidate.reason)}
          />
          <StatusLine
            label="Visibility advisories"
            values={summary.visibility_advisories.map(
              (advisory) =>
                `${advisory.category} / ${advisory.confidence_cap} cap / ${advisory.evidence_refs.length} refs`,
            )}
          />
          <StatusLine
            label="Report and export refs"
            values={[...summary.report_refs, ...summary.export_refs]}
          />
          <span className="analysis-muted">
            Reports and exports use refs only. This panel does not run detectors,
            samplers, schedulers, providers, responses, or LLM generation.
          </span>
        </>
      ) : (
        <span className="analysis-muted">
          {loading
            ? "Loading bounded endpoint threat analysis."
            : "No endpoint threat analysis summary is available."}
        </span>
      )}
    </section>
  );
}

function FindingDetail({
  attackRefs,
  finding,
  graphRefs,
  hypothesisRefs,
  riskRefs,
  supportBucket,
  baselineRefs,
  sourceReliabilityBuckets,
}: {
  readonly attackRefs: EndpointAttackContextDto[];
  readonly finding: EndpointThreatFindingReadModelDto;
  readonly graphRefs: string[];
  readonly hypothesisRefs: string[];
  readonly riskRefs: string[];
  readonly supportBucket: string;
  readonly baselineRefs: string[];
  readonly sourceReliabilityBuckets: string[];
}) {
  return (
    <div className="metadata-watch-source-row">
      <strong>{safeEndpointText(finding.summary_redacted)}</strong>
      <small>Finding category {safeEndpointText(finding.category)}</small>
      <small>
        Detector {safeEndpointText(finding.detector_id)} / v
        {safeEndpointText(finding.detector_version)}
      </small>
      <small>
        {safeEndpointText(finding.confidence_bucket)} confidence /{" "}
        {safeEndpointText(finding.uncertainty_bucket)} uncertainty /{" "}
        {safeEndpointText(finding.severity_bucket)} severity
      </small>
      <small>
        {finding.evidence_refs.length} evidence refs /{" "}
        {finding.independent_source_count} independent sources
      </small>
      <small>
        Process/service category context: category-level metadata only; specific
        identity and process-network attribution are unavailable.
      </small>
      <small>
        Baseline support {safeEndpointText(supportBucket)} / {baselineRefs.length} refs
      </small>
      <small>
        Reliability {safeList(sourceReliabilityBuckets)} / evidence quality{" "}
        {safeEndpointText(finding.evidence_quality_bucket)} / correlation{" "}
        {safeEndpointText(finding.correlation_quality_bucket)}
      </small>
      <StatusLine
        label="ATT&CK context"
        values={attackRefs.map(attackLabel)}
      />
      <StatusLine label="Graph refs" values={graphRefs} />
      <StatusLine label="Related hypotheses" values={hypothesisRefs} />
      <StatusLine label="Related risks" values={riskRefs} />
      <StatusLine
        label="Missing visibility"
        values={finding.missing_visibility_flags}
      />
      <NavigationRefButtons
        refs={finding.evidence_refs}
        sourceView="investigation"
        targetKind="evidence"
      />
      <NavigationRefButtons
        refs={hypothesisRefs}
        sourceView="investigation"
        targetKind="hypothesis"
      />
      <NavigationRefButtons
        refs={riskRefs}
        sourceView="investigation"
        targetKind="risk"
      />
      <NavigationRefButtons
        refs={graphRefs}
        sourceView="investigation"
        targetKind="graph_hint"
      />
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

function StatusLine({
  label,
  values,
}: {
  readonly label: string;
  readonly values: readonly string[];
}) {
  return (
    <small>
      {label}:{" "}
      {values.length ? values.slice(0, 4).map(safeEndpointText).join(", ") : "none"}
    </small>
  );
}

function attackLabel(attack: EndpointAttackContextDto) {
  return `${attack.tactic_id}:${attack.technique_id} ${attack.confidence_bucket} context / observed=${attack.technique_observed}`;
}

function safeList(values: readonly string[]) {
  return values.length ? values.slice(0, 3).map(safeEndpointText).join(", ") : "unknown";
}

function safeEndpointText(value: JsonValue | undefined | null) {
  const rendered = stringifySafe(value ?? "");
  const normalized = rendered.toLowerCase();
  const rawEndpointMarkers = [
    "username",
    "tenant_id",
    "process.exe",
    "cmd.exe",
    "powershell.exe",
    "command_line",
    "c:\\",
    "\\users\\",
    "/users/",
    "/home/",
    "http://",
    "https://",
  ];
  if (
    rawEndpointMarkers.some((marker) => normalized.includes(marker)) ||
    /\b[\w.-]+\.exe\b/i.test(rendered) ||
    /\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(rendered) ||
    /[^\s@]+@[^\s@]+\.[^\s@]+/.test(rendered)
  ) {
    return "[redacted]";
  }
  if (/^\d+(?:\.\d+)+$/.test(rendered)) {
    return rendered;
  }
  return humanize(rendered);
}
