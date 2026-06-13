import {
  AlertTriangle,
  CheckCircle,
  Download,
  FileText,
  Lock,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { CommandReceiptDto, JsonValue } from "../../../bridge/dto/common";
import type { ServiceStatusViewDto } from "../../../bridge/dto/platform";
import type {
  ExplicitExportFormatDto,
  ExplicitExportPreviewDto,
  ExplicitExportRequestDto,
  ExplicitSaveActionDto,
  ExportHistoryRecordDto,
  ExportReportMutationResultDto,
  ReportDto,
} from "../../../bridge/dto/report";
import type {
  AttackCoverageSummaryDto,
  DurableBaselineSummaryDto,
  EvidenceQualitySummaryDto,
  FusionSummaryDto,
  InvestigationDrillDownSummaryDto,
} from "../../../bridge/dto/security";
import { useServiceStatusQuery } from "../../../features/platform/hooks";
import { useSelectionStore } from "../../../stores/selectionStore";
import { EmptyState } from "../../../shared/layout/EmptyState";
import { humanize, isRecord, stringifySafe } from "../../../shared/renderers";
import { NavigationContextPanel } from "../../navigation/components/NavigationContextPanel";
import { NavigationTargetButton } from "../../navigation/components/NavigationTargetButton";
import {
  useConfirmExplicitExportMutation,
  useAttackCoverageSummaryQuery,
  useDurableBaselineSummaryQuery,
  useEvidenceQualitySummaryQuery,
  useExportReportMutation,
  useExportHistoryQuery,
  useFusionSummaryQuery,
  useInvestigationDrillDownSummaryQuery,
  usePreviewExplicitExportMutation,
  useReportQuery,
  useReportsQuery,
} from "../hooks";

type ReportSource = "command";
type ExportFormat = "markdown" | "html" | "redacted_json" | "pdf";
type ExplicitExportKind = "session" | "report" | "graph";

const explicitExportActions: Array<{
  readonly kind: ExplicitExportKind;
  readonly label: string;
  readonly format: ExplicitExportFormatDto;
  readonly extension: string;
  readonly filenamePrefix: string;
}> = [
  {
    kind: "session",
    label: "Save Session",
    format: "sg_session",
    extension: ".sgsession",
    filenamePrefix: "sentinel-session",
  },
  {
    kind: "report",
    label: "Export Report",
    format: "sg_report",
    extension: ".sgreport",
    filenamePrefix: "sentinel-report",
  },
  {
    kind: "graph",
    label: "Export Graph",
    format: "sg_graph",
    extension: ".sggraph",
    filenamePrefix: "sentinel-graph",
  },
];

interface ReportRow {
  readonly id: string;
  readonly reportId: string;
  readonly title: string;
  readonly summary: string;
  readonly reportType: string;
  readonly status: string;
  readonly redaction: string;
  readonly redactionPassed: boolean;
  readonly sections: number;
  readonly evidenceRefs: number;
  readonly graphSnapshots: number;
  readonly responseResults: number;
  readonly auditRef: string;
  readonly privacyClass: string;
  readonly createdAt: string;
  readonly source: ReportSource;
  readonly raw: ReportDto;
}

interface ExportHistoryRow {
  readonly id: string;
  readonly report: string;
  readonly format: string;
  readonly destination: string;
  readonly redaction: string;
  readonly fileHash: string;
  readonly audit: string;
  readonly graphRefs: string;
  readonly evidenceRefs: string;
  readonly responseRefs: string;
  readonly rollbackRefs: string;
  readonly storyRefs: string;
  readonly graphRefCount: number;
  readonly evidenceRefCount: number;
  readonly responseRefCount: number;
  readonly rollbackRefCount: number;
  readonly storyRefCount: number;
  readonly status: string;
  readonly source: ReportSource | "session";
}

export function ReportsWorkspace() {
  const reportsQuery = useReportsQuery();
  const selectedReportId = useSelectionStore((state) => state.selectedReportId);
  const setSelectedReportId = useSelectionStore((state) => state.setSelectedReportId);
  const exportMutation = useExportReportMutation();
  const explicitPreviewMutation = usePreviewExplicitExportMutation();
  const explicitConfirmMutation = useConfirmExplicitExportMutation();
  const serviceStatusQuery = useServiceStatusQuery();
  const attackCoverageQuery = useAttackCoverageSummaryQuery();
  const fusionSummaryQuery = useFusionSummaryQuery();
  const baselineSummaryQuery = useDurableBaselineSummaryQuery();
  const qualitySummaryQuery = useEvidenceQualitySummaryQuery();
  const drillDownQuery = useInvestigationDrillDownSummaryQuery();

  const commandRows = useMemo(
    () => reportRowsFromReports(reportsQuery.data?.items ?? []),
    [reportsQuery.data?.items],
  );
  const rows = commandRows;
  const selectedRow =
    rows.find((row) => row.id === selectedReportId) ??
    rows.find((row) => row.reportId === selectedReportId) ??
    rows[0] ??
    null;
  const reportDetailQuery = useReportQuery(selectedRow?.reportId ?? null);
  const exportHistoryRequest = useMemo(
    () => ({
      page: { limit: 100, cursor: null },
      report_id: selectedRow?.reportId ?? null,
    }),
    [selectedRow?.reportId],
  );
  const exportHistoryQuery = useExportHistoryQuery(exportHistoryRequest);
  const selectedReport = reportDetailQuery.data ?? selectedRow?.raw ?? null;

  useEffect(() => {
    if (selectedRow && selectedRow.id !== selectedReportId) {
      setSelectedReportId(selectedRow.id);
    } else if (!selectedRow && selectedReportId) {
      setSelectedReportId(null);
    }
  }, [selectedReportId, selectedRow, setSelectedReportId]);

  if (reportsQuery.isError) {
    return (
      <EmptyState
        title="Report read model unavailable"
        detail="The command bridge returned a redacted report query error."
      />
    );
  }

  const exportHistory = exportHistoryRows(
    exportHistoryQuery.data?.items ?? [],
    exportMutation.data as CommandReceiptDto<ExportReportMutationResultDto> | undefined,
  );

  return (
    <div className="reports-workspace">
      <ReportList
        loading={reportsQuery.isLoading}
        rows={rows}
        selectedReportId={selectedRow?.id ?? null}
        onSelectRow={(row) => setSelectedReportId(row.id)}
      />
      <main className="reports-main">
        <ReportPreview
          error={reportDetailQuery.isError}
          loading={reportDetailQuery.isLoading}
          report={selectedReport}
          row={selectedRow}
        />
        <ExportHistoryTable
          error={exportHistoryQuery.isError}
          loading={exportHistoryQuery.isLoading}
          rows={exportHistory}
        />
      </main>
      <aside className="reports-detail">
        <FusionSummaryPanel
          error={fusionSummaryQuery.isError}
          loading={fusionSummaryQuery.isLoading}
          summary={fusionSummaryQuery.data ?? null}
        />
        <BaselineSummaryPanel
          error={baselineSummaryQuery.isError}
          loading={baselineSummaryQuery.isLoading}
          summary={baselineSummaryQuery.data ?? null}
        />
        <EvidenceQualityPanel
          error={qualitySummaryQuery.isError}
          loading={qualitySummaryQuery.isLoading}
          summary={qualitySummaryQuery.data ?? null}
        />
        <InvestigationTraceabilityPanel
          error={drillDownQuery.isError}
          loading={drillDownQuery.isLoading}
          summary={drillDownQuery.data ?? null}
        />
        <AttackCoveragePanel
          error={attackCoverageQuery.isError}
          loading={attackCoverageQuery.isLoading}
          summary={attackCoverageQuery.data ?? null}
        />
        <NavigationContextPanel />
        <RedactionSummaryPanel report={selectedReport} row={selectedRow} />
        <ExportDialog
          exportMutation={exportMutation}
          report={selectedReport}
          row={selectedRow}
        />
        <ExplicitExportPanel
          confirmMutation={explicitConfirmMutation}
          previewMutation={explicitPreviewMutation}
          report={selectedReport}
          row={selectedRow}
          serviceStatus={serviceStatusQuery.data ?? null}
        />
      </aside>
    </div>
  );
}

interface FusionSummaryPanelProps {
  readonly error?: boolean;
  readonly loading?: boolean;
  readonly summary: FusionSummaryDto | null;
}

export function FusionSummaryPanel({
  error = false,
  loading = false,
  summary,
}: FusionSummaryPanelProps) {
  const portableSamplers =
    summary?.sampler_health.filter((sampler) => sampler.portable_default_available) ?? [];
  const boundarySamplers =
    summary?.sampler_health.filter((sampler) => !sampler.portable_default_available) ?? [];
  const activeHypotheses = summary?.hypotheses.slice(0, 4) ?? [];

  return (
    <section className="report-side-panel">
      <div className="analysis-panel-header">
        <strong>Security fusion</strong>
        <span>{loading ? "Loading" : `${summary?.hypothesis_count ?? 0} active`}</span>
      </div>
      {error ? (
        <div className="response-callout" data-tone="warning">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>Fusion read model returned a redacted error.</span>
        </div>
      ) : null}
      {summary ? (
        <>
          <div className="report-redaction-grid">
            <StatusBadge label="Facts" value={`${summary.fact_count}`} tone="neutral" />
            <StatusBadge
              label="Hypotheses"
              value={`${summary.hypothesis_count}`}
              tone={summary.hypothesis_count ? "warning" : "neutral"}
            />
            <StatusBadge
              label="Portable"
              value={`${portableSamplers.length} samplers`}
              tone="ok"
            />
            <StatusBadge
              label="Native / SDN"
              value={`${boundarySamplers.length} unavailable`}
              tone={boundarySamplers.length ? "warning" : "neutral"}
            />
          </div>
          <div className="redaction-category-list">
            {summary.degraded_visibility_context.slice(0, 4).map((reason) => (
              <span key={reason}>{humanize(displayText(reason))}</span>
            ))}
          </div>
          <div className="redaction-category-list">
            {activeHypotheses.length ? (
              activeHypotheses.map((hypothesis) => (
                <span key={hypothesis.hypothesis_record_id}>
                  {humanize(displayText(hypothesis.category))} -{" "}
                  {humanize(displayText(hypothesis.confidence_bucket))} -{" "}
                  {hypothesis.evidence_refs.length} evidence refs
                  {hypothesis.quality
                    ? ` - quality ${humanize(displayText(hypothesis.quality.evidence_quality_bucket))}`
                    : ""}
                </span>
              ))
            ) : (
              <span className="analysis-muted">
                No evidence-backed cross-layer hypothesis is active.
              </span>
            )}
          </div>
          <span className="analysis-muted">
            Metadata-only fusion. Automatic LLM calls:{" "}
            {summary.automatic_llm_calls ? "blocked by policy" : "off"}.
          </span>
        </>
      ) : (
        <span className="analysis-muted">
          {loading
            ? "Loading bounded fusion summary."
            : "No fusion summary is available."}
        </span>
      )}
    </section>
  );
}

interface BaselineSummaryPanelProps {
  readonly error?: boolean;
  readonly loading?: boolean;
  readonly summary: DurableBaselineSummaryDto | null;
}

export function BaselineSummaryPanel({
  error = false,
  loading = false,
  summary,
}: BaselineSummaryPanelProps) {
  const indicators = summary?.indicators.slice(0, 4) ?? [];
  const groups = summary?.incident_groups.slice(0, 3) ?? [];
  const degradedSources =
    summary?.source_reliability.filter((source) =>
      ["weak", "degraded", "unknown"].includes(displayText(source.reliability_bucket)),
    ) ?? [];

  return (
    <section className="report-side-panel">
      <div className="analysis-panel-header">
        <strong>Durable baseline</strong>
        <span>{loading ? "Loading" : `${summary?.baseline_count ?? 0} refs`}</span>
      </div>
      {error ? (
        <div className="response-callout" data-tone="warning">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>Baseline read model returned a redacted error.</span>
        </div>
      ) : null}
      {summary ? (
        <>
          <div className="report-redaction-grid">
            <StatusBadge
              label="Indicators"
              value={`${summary.indicator_count}`}
              tone={summary.indicator_count ? "warning" : "neutral"}
            />
            <StatusBadge
              label="Groups"
              value={`${summary.incident_group_count}`}
              tone={summary.incident_group_count ? "warning" : "neutral"}
            />
            <StatusBadge
              label="Timeline"
              value={`${summary.timeline_entry_count}`}
              tone="neutral"
            />
            <StatusBadge
              label="Persistence"
              value={
                summary.persistence_status.automatic_durable_persistence
                  ? "Blocked"
                  : "Export refs only"
              }
              tone={
                summary.persistence_status.automatic_durable_persistence
                  ? "warning"
                  : "ok"
              }
            />
          </div>
          <div className="redaction-category-list">
            {indicators.length ? (
              indicators.map((indicator) => (
                <span key={indicator.indicator_id}>
                  {humanize(displayText(indicator.kind))} -{" "}
                  {humanize(displayText(indicator.confidence_bucket))} -{" "}
                  {indicator.evidence_refs.length} evidence refs
                  {indicator.quality
                    ? ` - quality ${humanize(displayText(indicator.quality.evidence_quality_bucket))}`
                    : ""}
                </span>
              ))
            ) : (
              <span className="analysis-muted">
                No first-seen, rare, or repeated indicators are active.
              </span>
            )}
          </div>
          <div className="redaction-category-list">
            {groups.length ? (
              groups.map((group) => (
                <span key={group.group_id}>
                  Group {group.hypothesis_refs.length} hypotheses /{" "}
                  {group.evidence_refs.length} evidence refs /{" "}
                  {humanize(displayText(group.confidence_trend))}
                  {group.weak_merge_warning ? " / weak merge warning" : ""}
                  {group.quality
                    ? ` / quality ${humanize(displayText(group.quality.correlation_quality_bucket))}`
                    : ""}
                </span>
              ))
            ) : (
              <span className="analysis-muted">
                No incident-linked hypothesis groups are active.
              </span>
            )}
          </div>
          <span className="analysis-muted">
            Portable Default: baseline security data stays session-bounded unless explicitly exported.
            Degraded source refs: {degradedSources.length}. Automatic LLM calls:{" "}
            {summary.automatic_llm_calls ? "blocked" : "off"}. Response execution:{" "}
            {summary.response_execution ? "blocked" : "off"}.
          </span>
        </>
      ) : (
        <span className="analysis-muted">
          {loading
            ? "Loading bounded baseline summary."
            : "No baseline summary is available."}
        </span>
      )}
    </section>
  );
}

interface EvidenceQualityPanelProps {
  readonly error?: boolean;
  readonly loading?: boolean;
  readonly summary: EvidenceQualitySummaryDto | null;
}

export function EvidenceQualityPanel({
  error = false,
  loading = false,
  summary,
}: EvidenceQualityPanelProps) {
  const visibleRecords = summary?.records.slice(0, 4) ?? [];
  return (
    <section className="report-side-panel">
      <div className="analysis-panel-header">
        <strong>Evidence quality</strong>
        <span>{loading ? "Loading" : `${summary?.record_count ?? 0} records`}</span>
      </div>
      {error ? (
        <div className="response-callout" data-tone="warning">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>Quality read model returned a redacted error.</span>
        </div>
      ) : null}
      {summary ? (
        <>
          <div className="report-redaction-grid">
            <StatusBadge
              label="Weak"
              value={`${summary.weak_single_signal_count}`}
              tone={summary.weak_single_signal_count ? "warning" : "neutral"}
            />
            <StatusBadge
              label="Corroborated"
              value={`${summary.corroborated_count}`}
              tone="ok"
            />
            <StatusBadge
              label="Report-ready"
              value={`${summary.report_suitable_count}`}
              tone="neutral"
            />
            <StatusBadge
              label="Blocked"
              value={`${summary.blocked_count}`}
              tone={summary.blocked_count ? "warning" : "neutral"}
            />
          </div>
          <div className="redaction-category-list">
            {visibleRecords.length ? (
              visibleRecords.map((record) => (
                <span key={record.evidence_quality_id}>
                  {humanize(displayText(record.target_kind))} -{" "}
                  {humanize(displayText(record.quality.evidence_quality_bucket))} /{" "}
                  {humanize(displayText(record.quality.visibility_completeness_bucket))} / report{" "}
                  {humanize(displayText(record.quality.report_suitability_bucket))}
                </span>
              ))
            ) : (
              <span className="analysis-muted">
                No evidence quality records are active yet.
              </span>
            )}
          </div>
          <span className="analysis-muted">
            Quality refs: {summary.quality_refs.length}. Missing visibility:{" "}
            {summary.missing_visibility_flags.slice(0, 3).map(humanize).join(", ") || "none"}.
            Automatic LLM calls: {summary.automatic_llm_calls ? "blocked" : "off"}.
          </span>
        </>
      ) : (
        <span className="analysis-muted">
          {loading
            ? "Loading bounded evidence quality summary."
            : "No evidence quality summary is available."}
        </span>
      )}
    </section>
  );
}

export function InvestigationTraceabilityPanel({
  error = false,
  loading = false,
  summary,
}: {
  readonly error?: boolean;
  readonly loading?: boolean;
  readonly summary: InvestigationDrillDownSummaryDto | null;
}) {
  return (
    <section className="report-side-panel">
      <div className="analysis-panel-header">
        <strong>Investigation traceability</strong>
        <span>{loading ? "Loading" : `${summary?.report_refs.length ?? 0} report refs`}</span>
      </div>
      {error ? (
        <div className="response-callout" data-tone="warning">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>Investigation traceability returned a redacted error.</span>
        </div>
      ) : null}
      {summary ? (
        <>
          <div className="report-redaction-grid">
            <StatusBadge label="Hypotheses" value={`${summary.hypothesis_count}`} tone="neutral" />
            <StatusBadge label="Baselines" value={`${summary.baseline_count}`} tone="neutral" />
            <StatusBadge label="Groups" value={`${summary.incident_group_count}`} tone="neutral" />
            <StatusBadge label="Exports" value={`${summary.export_refs.length} refs`} tone="ok" />
          </div>
          <div className="redaction-category-list">
            {summary.incident_groups.slice(0, 3).map((group) => (
              <span key={group.group_id}>
                {group.hypothesis_refs.length} hypothesis refs /{" "}
                {group.evidence_refs.length} evidence refs /{" "}
                {group.attack_refs.length} ATT&amp;CK refs
              </span>
            ))}
          </div>
          <span className="analysis-muted">
            Reports and explicit exports contain bounded references and summaries only.
            No automatic story generation or response execution.
          </span>
        </>
      ) : (
        <span className="analysis-muted">
          {loading
            ? "Loading bounded investigation references."
            : "No investigation references are available."}
        </span>
      )}
    </section>
  );
}

interface ReportListProps {
  readonly loading: boolean;
  readonly rows: ReportRow[];
  readonly selectedReportId: string | null;
  readonly onSelectRow: (row: ReportRow) => void;
}

function ReportList({
  loading,
  rows,
  selectedReportId,
  onSelectRow,
}: ReportListProps) {
  return (
    <aside className="report-list-panel">
      <div className="analysis-panel-header">
        <strong>Report list</strong>
        <span>{loading ? "Loading" : `${rows.length} reports`}</span>
      </div>
      <div className="report-list">
        {rows.length === 0 ? (
          <span className="analysis-muted">
            {loading
              ? "Loading command-backed reports."
              : "No reports are available from the command bridge."}
          </span>
        ) : null}
        {rows.map((row) => (
          <button
            className="report-list-row"
            data-selected={selectedReportId === row.id}
            key={row.id}
            type="button"
            onClick={() => onSelectRow(row)}
          >
            <FileText size={14} aria-hidden="true" />
            <span>{displayText(row.title)}</span>
            <small>{displayText(row.status)}</small>
          </button>
        ))}
      </div>
    </aside>
  );
}

interface ReportPreviewProps {
  readonly error?: boolean;
  readonly loading: boolean;
  readonly report: ReportDto | null;
  readonly row: ReportRow | null;
}

export function ReportPreview({
  error = false,
  loading,
  report,
  row,
}: ReportPreviewProps) {
  const sections = sectionRows(report);
  return (
    <section className="report-preview-panel">
      <div className="analysis-panel-header">
        <strong>Report preview</strong>
        <span>{loading ? "Loading" : row?.source ?? "empty"}</span>
      </div>
      {error && report && row ? (
        <div className="response-callout" data-tone="warning">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>Report detail refresh failed; command list summary is shown.</span>
        </div>
      ) : null}
      {report && row ? (
        <div className="report-preview-body">
          <div className="report-preview-summary">
            <div>
              <span>{displayText(row.reportType)}</span>
              <h2>{displayText(row.title)}</h2>
              <p>{displayText(row.summary)}</p>
            </div>
            <div className="report-status-stack">
              <StatusBadge label="Redaction" value={row.redaction} tone={row.redactionPassed ? "ok" : "warning"} />
              <StatusBadge label="Privacy" value={row.privacyClass} tone="neutral" />
              <StatusBadge label="Audit" value={row.auditRef} tone="neutral" />
            </div>
          </div>
          <div
            className="report-section-table scroll-region table-scroll-region"
            role="table"
          >
            <div className="report-section-row header" role="row">
              <div role="columnheader">Section</div>
              <div role="columnheader">Type</div>
              <div role="columnheader">Privacy</div>
              <div role="columnheader">Refs</div>
              <div role="columnheader">Navigate</div>
            </div>
            {sections.map((section) => (
              <div className="report-section-row" key={section.id} role="row">
                <div role="cell">{displayText(section.title)}</div>
                <div role="cell">{displayText(section.sectionType)}</div>
                <div role="cell">{displayText(section.privacyClass)}</div>
                <div role="cell">{displayText(section.refs)}</div>
                <div role="cell">
                  <NavigationTargetButton
                    label="Open refs"
                    sourceView="report"
                    targetId={section.id}
                    targetKind="report_section"
                  />
                </div>
              </div>
            ))}
            {sections.length === 0 ? (
              <div className="report-section-row report-section-empty" role="row">
                <div role="cell">
                  No report sections are available from the command bridge.
                </div>
              </div>
            ) : null}
          </div>
        </div>
      ) : (
        <span className="analysis-muted">
          {error
            ? "The command bridge returned a redacted report detail error."
            : loading
              ? "Loading command-backed report detail."
              : "No report selected."}
        </span>
      )}
    </section>
  );
}

interface AttackCoveragePanelProps {
  readonly error?: boolean;
  readonly loading?: boolean;
  readonly summary: AttackCoverageSummaryDto | null;
}

export function AttackCoveragePanel({
  error = false,
  loading = false,
  summary,
}: AttackCoveragePanelProps) {
  const rows = summary?.technique_rows ?? [];
  const observedRows = rows.filter((row) => row.states.includes("observed"));
  const evidenceRows = rows.filter((row) => row.states.includes("evidence_backed"));
  const nativeRows = rows.filter((row) =>
    row.states.includes("requires_authorized_native_extension"),
  );
  const visibleRows = rows
    .filter((row) => row.states.includes("observed") || nativeRows.includes(row))
    .slice(0, 5);

  return (
    <section className="report-side-panel">
      <div className="analysis-panel-header">
        <strong>ATT&amp;CK coverage</strong>
        <span>{loading ? "Loading" : `${rows.length} rows`}</span>
      </div>
      {error ? (
        <div className="response-callout" data-tone="warning">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>Coverage read model returned a redacted error.</span>
        </div>
      ) : null}
      {summary ? (
        <>
          <div className="report-redaction-grid">
            <StatusBadge
              label="Claim"
              value={summary.complete_coverage_claimed ? "Complete claim blocked" : "Not complete"}
              tone={summary.complete_coverage_claimed ? "warning" : "ok"}
            />
            <StatusBadge
              label="Observed"
              value={`${observedRows.length}`}
              tone="neutral"
            />
            <StatusBadge
              label="Evidence"
              value={`${evidenceRows.length}`}
              tone="neutral"
            />
            <StatusBadge
              label="Native needed"
              value={`${nativeRows.length}`}
              tone={nativeRows.length ? "warning" : "neutral"}
            />
          </div>
          <div className="redaction-category-list">
            {summary.package_coverage.slice(0, 6).map((count) => (
              <span key={count.label}>
                {humanize(displayText(count.label))}: {count.count}
              </span>
            ))}
          </div>
          <div className="redaction-category-list">
            {visibleRows.length ? (
              visibleRows.map((row) => (
                <span key={`${row.tactic_id}:${row.technique_id}:${row.package_category}`}>
                  {displayText(row.tactic_id)} / {displayText(row.technique_id)} -{" "}
                  {humanize(displayText(row.package_category))} -{" "}
                  {humanize(displayText(row.confidence_bucket))}
                  {row.quality
                    ? ` - quality ${humanize(displayText(row.quality.visibility_completeness_bucket))}`
                    : ""}
                  {row.native_required ? " - native visibility required" : ""}
                  <NavigationTargetButton
                    label="Open links"
                    sourceView="attack_coverage"
                    targetId={`${row.tactic_id}:${row.technique_id}`}
                    targetKind="attack_technique_row"
                  />
                </span>
              ))
            ) : (
              <span className="analysis-muted">
                No ATT&amp;CK observations are linked to current findings yet.
              </span>
            )}
          </div>
        </>
      ) : (
        <span className="analysis-muted">
          {loading
            ? "Loading bounded ATT&CK coverage summary."
            : "No ATT&CK coverage summary is available."}
        </span>
      )}
    </section>
  );
}

interface RedactionSummaryPanelProps {
  readonly report: ReportDto | null;
  readonly row: ReportRow | null;
}

export function RedactionSummaryPanel({ report, row }: RedactionSummaryPanelProps) {
  const summary = redactionSummary(report);
  const categories = arrayField(summary, "redacted_categories");
  const passed = boolField(summary, "passed") ?? false;
  return (
    <section className="report-side-panel">
      <div className="analysis-panel-header">
        <strong>Redaction summary</strong>
        {summary ? (
          passed ? (
            <ShieldCheck size={15} aria-hidden="true" />
          ) : (
            <AlertTriangle size={15} aria-hidden="true" />
          )
        ) : null}
      </div>
      {report && row ? (
        summary ? (
          <>
            <div className="report-redaction-grid">
              <StatusBadge label="Policy" value={passed ? "Passed" : "Required"} tone={passed ? "ok" : "warning"} />
              <StatusBadge
                label="Fields removed"
                value={stringField(summary, "redacted_field_count") ?? "not reported"}
                tone="neutral"
              />
              <StatusBadge
                label="Sections suppressed"
                value={stringField(summary, "suppressed_section_count") ?? "not reported"}
                tone="neutral"
              />
              <StatusBadge
                label="Completed"
                value={stringField(summary, "completed_at") ?? "not reported"}
                tone="neutral"
              />
            </div>
            <div className="redaction-category-list">
              {categories.length ? (
                categories.slice(0, 8).map((category, index) => (
                  <span key={`${category}:${index}`}>{humanize(displayText(category))}</span>
                ))
              ) : (
                <span className="analysis-muted">No redaction categories reported.</span>
              )}
            </div>
          </>
        ) : (
          <span className="analysis-muted">
            No redaction summary is available from the command bridge.
          </span>
        )
      ) : (
        <span className="analysis-muted">Select a command-backed report.</span>
      )}
    </section>
  );
}

interface ExportDialogProps {
  readonly report: ReportDto | null;
  readonly row: ReportRow | null;
  readonly exportMutation: ReturnType<typeof useExportReportMutation>;
}

export function ExportDialog({ report, row, exportMutation }: ExportDialogProps) {
  const [format, setFormat] = useState<ExportFormat>("redacted_json");
  const [confirmed, setConfirmed] = useState(false);
  const [destination, setDestination] = useState("local desktop export");

  useEffect(() => {
    setConfirmed(false);
  }, [row?.id]);

  const supported = format !== "pdf";
  const canExport =
    Boolean(report && row) &&
    row?.source === "command" &&
    row.redactionPassed &&
    supported &&
    confirmed;

  return (
    <section className="report-side-panel">
      <div className="analysis-panel-header">
        <strong>Export detail</strong>
        <Download size={15} aria-hidden="true" />
      </div>
      <div className="export-dialog-body">
        <label>
          <span>Format</span>
          <select
            value={format}
            onChange={(event) => setFormat(event.currentTarget.value as ExportFormat)}
          >
            <option value="redacted_json">Redacted JSON</option>
            <option value="markdown">Markdown</option>
            <option value="html">HTML</option>
            <option value="pdf">PDF deferred</option>
          </select>
        </label>
        <label>
          <span>Destination metadata</span>
          <input
            value={destination}
            onChange={(event) => setDestination(event.currentTarget.value)}
          />
        </label>
        <label className="response-check-row">
          <input
            checked={confirmed}
            type="checkbox"
            onChange={(event) => setConfirmed(event.currentTarget.checked)}
          />
          <span>Redaction and local export confirmed</span>
        </label>
        <div className="response-callout" data-tone={supported ? "ok" : "warning"}>
          {supported ? (
            <CheckCircle size={15} aria-hidden="true" />
          ) : (
            <AlertTriangle size={15} aria-hidden="true" />
          )}
          <span>{supported ? "Export policy gate ready" : "Format deferred"}</span>
        </div>
        <button
          className="toolbar-button"
          disabled={!canExport || exportMutation.isPending}
          title="Export through Rust Core mutation"
          type="button"
          onClick={() => {
            if (!row) {
              return;
            }
            exportMutation.mutate({
              report_id: row.reportId,
              format,
              destination_metadata_redacted: destination.trim() || "local export",
              requested_by_redacted: "local operator",
              user_confirmed: true,
            });
          }}
        >
          <Lock size={14} aria-hidden="true" />
          Export
        </button>
        {exportMutation.data ? (
          <div className="export-receipt">
            <strong>Receipt</strong>
            <span>{displayText(exportMutation.data.trace_id)}</span>
          </div>
        ) : null}
      </div>
    </section>
  );
}

interface ExplicitExportPanelProps {
  readonly report: ReportDto | null;
  readonly row: ReportRow | null;
  readonly serviceStatus: ServiceStatusViewDto | null;
  readonly previewMutation: ReturnType<typeof usePreviewExplicitExportMutation>;
  readonly confirmMutation: ReturnType<typeof useConfirmExplicitExportMutation>;
}

export function ExplicitExportPanel({
  report,
  row,
  serviceStatus,
  previewMutation,
  confirmMutation,
}: ExplicitExportPanelProps) {
  const [selectedKind, setSelectedKind] = useState<ExplicitExportKind>("graph");
  const [preview, setPreview] = useState<ExplicitExportPreviewDto | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const incidentId = firstIncidentId(report);
  const activeSessionId = isUuid(serviceStatus?.active_session_id)
    ? serviceStatus?.active_session_id ?? null
    : null;
  const reportReady = Boolean(row?.source === "command" && incidentId);
  const selectedAction = explicitExportActions.find((action) => action.kind === selectedKind);
  const selectedUnavailableReason = explicitUnavailableReason({
    activeSessionId,
    incidentId,
    reportReady,
    selectedKind,
  });
  const busy = previewMutation.isPending || confirmMutation.isPending;
  const canPreview = !busy && !selectedUnavailableReason;
  const canConfirm = Boolean(preview && confirmed && !busy);

  useEffect(() => {
    setPreview(null);
    setConfirmed(false);
    setNotice(null);
    previewMutation.reset();
    confirmMutation.reset();
  }, [row?.id, selectedKind]);

  return (
    <section className="report-side-panel">
      <div className="analysis-panel-header">
        <strong>Explicit save/export</strong>
        <Lock size={15} aria-hidden="true" />
      </div>
      <div className="export-dialog-body explicit-export-body">
        <div className="explicit-export-actions" role="group" aria-label="Explicit export action">
          {explicitExportActions.map((action) => (
            <button
              className="explicit-export-action"
              data-selected={selectedKind === action.kind}
              key={action.kind}
              type="button"
              onClick={() => setSelectedKind(action.kind)}
            >
              <FileText size={14} aria-hidden="true" />
              <span>{action.label}</span>
            </button>
          ))}
        </div>
        <div className="response-callout" data-tone={selectedUnavailableReason ? "warning" : "ok"}>
          {selectedUnavailableReason ? (
            <AlertTriangle size={15} aria-hidden="true" />
          ) : (
            <CheckCircle size={15} aria-hidden="true" />
          )}
          <span>
            {selectedUnavailableReason ??
              `${selectedAction?.extension ?? ""} preview will run redaction before writing`}
          </span>
        </div>
        <button
          className="toolbar-button"
          disabled={!canPreview}
          title="Preview redacted artifact through Rust Core"
          type="button"
          onClick={() => {
            if (!activeSessionId) {
              return;
            }
            const request = buildExplicitExportRequest(
              selectedKind,
              activeSessionId,
              incidentId,
            );
            if (!request) {
              return;
            }
            setNotice(null);
            setConfirmed(false);
            confirmMutation.reset();
            previewMutation.mutate(request, {
              onSuccess: (result) => {
                setPreview(result);
              },
            });
          }}
        >
          <ShieldCheck size={14} aria-hidden="true" />
          Preview Redacted Artifact
        </button>
        {preview ? (
          <ExplicitExportPreview preview={preview} />
        ) : null}
        <label className="response-check-row">
          <input
            checked={confirmed}
            disabled={!preview || busy}
            type="checkbox"
            onChange={(event) => setConfirmed(event.currentTarget.checked)}
          />
          <span>This redacted artifact and destination are approved</span>
        </label>
        <div className="explicit-export-confirm-row">
          <button
            className="toolbar-button"
            disabled={!canConfirm}
            title="Write only after confirmation and audit"
            type="button"
            onClick={() => {
              if (!preview) {
                return;
              }
              setNotice(null);
              confirmMutation.mutate({
                export_id: preview.export_id,
                user_confirmed: true,
                confirmed_at: new Date().toISOString(),
              });
            }}
          >
            <Download size={14} aria-hidden="true" />
            Confirm Export
          </button>
          <button
            className="toolbar-button"
            disabled={!preview || busy}
            title="Cancel preview without writing a file"
            type="button"
            onClick={() => {
              if (!preview) {
                return;
              }
              confirmMutation.mutate(
                {
                  export_id: preview.export_id,
                  user_confirmed: false,
                  confirmed_at: null,
                },
                {
                  onSettled: () => {
                    setPreview(null);
                    setConfirmed(false);
                    setNotice("Preview cancelled; no artifact was written.");
                    confirmMutation.reset();
                  },
                },
              );
            }}
          >
            <AlertTriangle size={14} aria-hidden="true" />
            Cancel
          </button>
        </div>
        {confirmMutation.data ? (
          <div className="export-receipt">
            <strong>Artifact written</strong>
            <span>{displayText(confirmMutation.data.destination_path)}</span>
            <span>{displayText(confirmMutation.data.file_hash)}</span>
          </div>
        ) : null}
        {previewMutation.isError || (confirmMutation.isError && !notice) ? (
          <div className="response-callout">
            <AlertTriangle size={15} aria-hidden="true" />
            <span>Explicit export command returned a redacted error.</span>
          </div>
        ) : null}
        {notice ? <span className="analysis-muted">{notice}</span> : null}
      </div>
    </section>
  );
}

function ExplicitExportPreview({
  preview,
}: {
  readonly preview: ExplicitExportPreviewDto;
}) {
  return (
    <div className="explicit-export-preview">
      <div className="explicit-preview-grid">
        <StatusBadge
          label="Destination"
          value={preview.destination_path}
          tone="neutral"
        />
        <StatusBadge
          label="Estimated size"
          value={`${preview.estimated_size_bytes} bytes`}
          tone="neutral"
        />
        <StatusBadge
          label="Redacted"
          value={`${preview.redaction_summary.redacted_field_count}`}
          tone={preview.redaction_summary.passed ? "ok" : "warning"}
        />
        <StatusBadge
          label="Removed"
          value={`${preview.redaction_summary.removed_field_count}`}
          tone="neutral"
        />
      </div>
      <div className="redaction-category-list">
        {preview.format_contract.excluded_data_classes.slice(0, 8).map((item) => (
          <span key={item}>{humanize(displayText(item))}</span>
        ))}
      </div>
    </div>
  );
}

export function ExportHistoryTable({
  error = false,
  loading = false,
  rows,
}: {
  readonly error?: boolean;
  readonly loading?: boolean;
  readonly rows: ExportHistoryRow[];
}) {
  return (
    <section className="export-history-panel">
      <div className="analysis-panel-header">
        <strong>Export history</strong>
        <span>{loading ? "Loading" : `${rows.length} exports`}</span>
      </div>
      <div className="export-history-table scroll-region table-scroll-region" role="table">
        <div className="export-history-row header" role="row">
          <div role="columnheader">Report</div>
          <div role="columnheader">Format</div>
          <div role="columnheader">Destination</div>
          <div role="columnheader">Redaction</div>
          <div role="columnheader">File hash</div>
          <div role="columnheader">Audit</div>
          <div role="columnheader">Graph refs</div>
          <div role="columnheader">Evidence refs</div>
          <div role="columnheader">Response refs</div>
          <div role="columnheader">Rollback refs</div>
          <div role="columnheader">Story refs</div>
          <div role="columnheader">Status</div>
        </div>
        {error && rows.length > 0 ? (
          <div className="export-history-row export-history-empty" role="row">
            <div role="cell">
              Export-history refresh failed; cached command records are shown.
            </div>
          </div>
        ) : null}
        {rows.map((row) => (
          <div
            className="export-history-row"
            data-evidence-ref-count={row.evidenceRefCount}
            data-graph-ref-count={row.graphRefCount}
            data-response-ref-count={row.responseRefCount}
            data-rollback-ref-count={row.rollbackRefCount}
            data-story-ref-count={row.storyRefCount}
            data-source={row.source}
            key={row.id}
            role="row"
          >
            <div role="cell">{displayText(row.report)}</div>
            <div role="cell">{displayText(row.format)}</div>
            <div role="cell">{displayText(row.destination)}</div>
            <div role="cell">{displayText(row.redaction)}</div>
            <div role="cell">{displayText(row.fileHash)}</div>
            <div role="cell">{displayText(row.audit)}</div>
            <div role="cell">{displayText(row.graphRefs)}</div>
            <div role="cell">{displayText(row.evidenceRefs)}</div>
            <div role="cell">{displayText(row.responseRefs)}</div>
            <div role="cell">{displayText(row.rollbackRefs)}</div>
            <div role="cell">{displayText(row.storyRefs)}</div>
            <div role="cell">
              {displayText(row.status)}
              {row.source === "command" ? (
                <NavigationTargetButton
                  label="Open refs"
                  sourceView="export"
                  targetId={row.id}
                  targetKind="export_history_entry"
                />
              ) : null}
            </div>
          </div>
        ))}
        {rows.length === 0 ? (
          <div className="export-history-row export-history-empty" role="row">
            <div role="cell">
              {error
                ? "The command bridge returned a redacted export-history error."
                : loading
                  ? "Loading command-backed export history."
                  : "No export history records are available from the command bridge."}
            </div>
          </div>
        ) : null}
      </div>
    </section>
  );
}

function StatusBadge({
  label,
  value,
  tone,
}: {
  readonly label: string;
  readonly value: string;
  readonly tone: "ok" | "warning" | "neutral";
}) {
  return (
    <div className="status-badge" data-tone={tone}>
      <span>{label}</span>
      <strong>{displayText(value)}</strong>
    </div>
  );
}

function reportRowsFromReports(reports: ReportDto[]): ReportRow[] {
  return reports.map((report, index) => {
    const record = report as Record<string, JsonValue | undefined>;
    const reportId = report.report_id ?? `report:${index}`;
    const summary = redactionSummary(report);
    const passed = boolField(summary, "passed") ?? false;
    return {
      id: `command:${reportId}`,
      reportId,
      title:
        safeString(report.title_redacted) ??
        stringField(record, "title") ??
        "Redacted report",
      summary:
        safeString(report.summary_redacted) ??
        stringField(record, "summary") ??
        "Redacted metadata report",
      reportType: humanize(safeString(report.report_type) ?? "incident"),
      status: humanize(stringField(record, "status") ?? "draft"),
      redaction: passed ? "passed" : "required",
      redactionPassed: passed,
      sections: Array.isArray(report.sections) ? report.sections.length : 0,
      evidenceRefs: arrayField(record, "evidence_refs").length,
      graphSnapshots: arrayField(record, "graph_snapshot_refs").length,
      responseResults: arrayField(record, "response_result_refs").length,
      auditRef: auditLabel(recordField(record, "audit_ref")),
      privacyClass: stringField(record, "privacy_class") ?? "internal",
      createdAt: stringField(record, "created_at") ?? "unknown",
      source: "command",
      raw: report,
    };
  });
}

function sectionRows(report: ReportDto | null) {
  if (!report?.sections || !Array.isArray(report.sections)) {
    return [];
  }
  return report.sections.filter(isRecord).map((section, index) => ({
    id: stringField(section, "section_id") ?? `section:${index}`,
    title: stringField(section, "title_redacted") ?? `Section ${index + 1}`,
    sectionType: humanize(stringField(section, "section_type") ?? "custom"),
    privacyClass: stringField(section, "privacy_class") ?? "internal",
    refs: `${arrayField(section, "evidence_refs").length + arrayField(section, "graph_snapshot_refs").length}`,
  }));
}

function exportHistoryRows(
  records: ExportHistoryRecordDto[],
  receipt?: CommandReceiptDto<ExportReportMutationResultDto>,
): ExportHistoryRow[] {
  const rows = records.map<ExportHistoryRow>((record) => {
    const graphRefs = record.graph_snapshot_refs ?? [];
    const evidenceRefs = record.evidence_refs ?? [];
    const responseRefs = record.response_result_refs ?? [];
    const rollbackRefs = record.rollback_result_refs ?? [];
    const storyRefs = record.llm_story_refs ?? [];
    return {
      id: record.export_result_id,
      report: safeString(record.report_id) ?? "report",
      format: humanize(safeString(record.format) ?? "redacted_json"),
      destination:
        safeString(record.destination.destination_metadata_redacted) ?? "local export",
      redaction: boolField(recordFieldFromJson(record.redaction_summary), "passed")
        ? "passed"
        : "required",
      fileHash: safeString(record.file_hash?.value) ?? "pending",
      audit: safeString(record.audit_id) ?? "pending",
      graphRefs: traceRefLabel(graphRefs),
      evidenceRefs: traceRefLabel(evidenceRefs),
      responseRefs: traceRefLabel(responseRefs),
      rollbackRefs: traceRefLabel(rollbackRefs),
      storyRefs: traceRefLabel(storyRefs),
      graphRefCount: graphRefs.length,
      evidenceRefCount: evidenceRefs.length,
      responseRefCount: responseRefs.length,
      rollbackRefCount: rollbackRefs.length,
      storyRefCount: storyRefs.length,
      status: record.success ? "completed" : "pending",
      source: "command",
    };
  });

  if (receipt) {
    const exportResult = receipt.result.export_result;
    const resultRecord = exportResult as Record<string, JsonValue | undefined>;
    const exportResultId = stringField(resultRecord, "export_result_id");
    if (!exportResultId || !rows.some((row) => row.id === exportResultId)) {
      const graphRefs = arrayField(resultRecord, "graph_snapshot_refs");
      const evidenceRefs = arrayField(resultRecord, "evidence_refs");
      const responseRefs = arrayField(resultRecord, "response_result_refs");
      const rollbackRefs = arrayField(resultRecord, "rollback_result_refs");
      const storyRefs = arrayField(resultRecord, "llm_story_refs");
      rows.unshift({
        id: exportResultId ?? `session:${receipt.trace_id}`,
        report: stringField(resultRecord, "report_id") ?? "selected report",
        format: humanize(stringField(resultRecord, "format") ?? "redacted_json"),
        destination:
          stringField(resultRecord, "destination_metadata_redacted") ?? "redacted",
        redaction: boolField(recordField(resultRecord, "redaction_summary"), "passed")
          ? "passed"
          : "required",
        fileHash: stringField(resultRecord, "file_hash") ?? "pending",
        audit: auditLabel(recordField(resultRecord, "audit_ref")),
        graphRefs: traceRefLabel(graphRefs),
        evidenceRefs: traceRefLabel(evidenceRefs),
        responseRefs: traceRefLabel(responseRefs),
        rollbackRefs: traceRefLabel(rollbackRefs),
        storyRefs: traceRefLabel(storyRefs),
        graphRefCount: graphRefs.length,
        evidenceRefCount: evidenceRefs.length,
        responseRefCount: responseRefs.length,
        rollbackRefCount: rollbackRefs.length,
        storyRefCount: storyRefs.length,
        status: boolField(resultRecord, "success") ? "completed" : "pending",
        source: "session",
      });
    }
  }

  return rows;
}

function traceRefLabel(refs: readonly string[]) {
  if (refs.length === 0) {
    return "none";
  }
  const visibleRefs = refs.slice(0, 2).map(displayText);
  const remaining = refs.length - visibleRefs.length;
  return remaining > 0
    ? `${refs.length}: ${visibleRefs.join(", ")} +${remaining}`
    : `${refs.length}: ${visibleRefs.join(", ")}`;
}

function explicitUnavailableReason({
  activeSessionId,
  incidentId,
  reportReady,
  selectedKind,
}: {
  readonly activeSessionId: string | null;
  readonly incidentId: string | null;
  readonly reportReady: boolean;
  readonly selectedKind: ExplicitExportKind;
}) {
  if (!activeSessionId) {
    return "Waiting for active session id from Rust Core.";
  }
  if (selectedKind === "report" && (!reportReady || !incidentId)) {
    return "Select a command report with an incident reference.";
  }
  return null;
}

function buildExplicitExportRequest(
  kind: ExplicitExportKind,
  sessionId: string,
  incidentId: string | null,
): ExplicitExportRequestDto | null {
  const metadata = explicitExportActions.find((action) => action.kind === kind);
  if (!metadata) {
    return null;
  }
  const action = explicitSaveAction(kind, incidentId);
  if (!action) {
    return null;
  }
  const exportId = newUuid();
  return {
    export_id: exportId,
    session_id: sessionId,
    action,
    format: metadata.format,
    destination_path: `${metadata.filenamePrefix}-${shortExportId(exportId)}${metadata.extension}`,
    redaction_options: {
      strict: true,
      include_hostnames: false,
      include_process_names: false,
    },
    requested_by_redacted: "local operator",
    requested_at: new Date().toISOString(),
    user_initiated: true,
  };
}

function explicitSaveAction(
  kind: ExplicitExportKind,
  incidentId: string | null,
): ExplicitSaveActionDto | null {
  switch (kind) {
    case "session":
      return { kind: "save_session" };
    case "graph":
      return { kind: "export_graph" };
    case "report":
      return incidentId ? { kind: "export_report", incident_id: incidentId } : null;
    default:
      return null;
  }
}

function firstIncidentId(report: ReportDto | null) {
  if (!report) {
    return null;
  }
  const refs = arrayField(report as Record<string, JsonValue | undefined>, "incident_refs");
  return refs.find(isUuid) ?? null;
}

function shortExportId(exportId: string) {
  return exportId.replaceAll("-", "").slice(0, 12);
}

function newUuid() {
  const runtimeCrypto = globalThis.crypto;
  if (typeof runtimeCrypto?.randomUUID === "function") {
    return runtimeCrypto.randomUUID();
  }

  const bytes = new Uint8Array(16);
  if (typeof runtimeCrypto?.getRandomValues === "function") {
    runtimeCrypto.getRandomValues(bytes);
  } else {
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Math.floor(Math.random() * 256);
    }
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"));
  return [
    hex.slice(0, 4).join(""),
    hex.slice(4, 6).join(""),
    hex.slice(6, 8).join(""),
    hex.slice(8, 10).join(""),
    hex.slice(10, 16).join(""),
  ].join("-");
}

function isUuid(value: string | null | undefined): value is string {
  return Boolean(
    value &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
        value,
      ),
  );
}

function redactionSummary(report: ReportDto | null) {
  const summary = report?.redaction_summary;
  return isRecord(summary) ? summary : null;
}

function recordField(
  value: Record<string, JsonValue | undefined> | null | undefined,
  key: string,
) {
  const nested = value?.[key];
  return isRecord(nested) ? nested : null;
}

function recordFieldFromJson(value: JsonValue | null | undefined) {
  return isRecord(value) ? value : null;
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
      stringField(nested, "title_redacted") ??
      stringField(nested, "audit_id") ??
      stringifySafe(nested)
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

function arrayField(
  value: Record<string, JsonValue | undefined> | null | undefined,
  key: string,
) {
  const nested = value?.[key];
  if (!Array.isArray(nested)) {
    return [];
  }
  return nested
    .map(safeString)
    .filter((value): value is string => Boolean(value));
}

function auditLabel(value: Record<string, JsonValue> | null) {
  return stringField(value, "audit_id") ?? stringField(value, "event_type") ?? "pending";
}

function safeString(value: JsonValue | undefined) {
  if (value === undefined || value === null) {
    return null;
  }
  return stringifySafe(value);
}

function displayText(value: string) {
  return stringifySafe(value);
}
