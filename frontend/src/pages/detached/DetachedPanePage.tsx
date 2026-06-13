import { type ReactNode } from "react";
import {
  FileSearch,
  History,
  ListChecks,
  PanelBottomClose,
  PanelRight,
} from "lucide-react";
import {
  DETACHED_PANE_LABELS,
  type DetachedPaneId,
} from "../../bridge/detachedWindows";
import type { AlertDto, FindingDto, IncidentDto } from "../../bridge/dto/security";
import { GraphWorkspace } from "../../features/graph/components/GraphWorkspace";
import {
  useAlertsQuery,
  useFindingsQuery,
  useIncidentsQuery,
} from "../../features/investigation/hooks";
import { EmptyState } from "../../shared/layout/EmptyState";
import {
  useDetachedPaneActions,
  useDetachedPaneSnapshot,
} from "../../shared/layout/useDetachedPaneWindows";
import { humanize, stringifySafe } from "../../shared/renderers";
import type { DetachedEntitySnapshot } from "../../bridge/detachedPaneSnapshots";

interface DetachedPanePageProps {
  readonly paneId: string;
}

export function DetachedPanePage({ paneId }: DetachedPanePageProps) {
  if (!isDetachedPaneId(paneId)) {
    return (
      <DetachedChrome title="Detached pane" subtitle="Unsupported pane">
        <EmptyState
          title="Pane unavailable"
          detail="This detached pane is not allowlisted."
        />
      </DetachedChrome>
    );
  }

  return <DetachedPaneContent paneId={paneId} />;
}

function DetachedPaneContent({ paneId }: { readonly paneId: DetachedPaneId }) {
  const { restorePane } = useDetachedPaneActions();
  const title = DETACHED_PANE_TITLES[paneId];
  const subtitle = `${DETACHED_PANE_LABELS[paneId]} / native window`;

  return (
    <DetachedChrome
      title={title}
      subtitle={subtitle}
      onRestore={() => {
        void restorePane(paneId);
      }}
    >
      <DetachedPaneBody paneId={paneId} />
    </DetachedChrome>
  );
}

function DetachedPaneBody({ paneId }: { readonly paneId: DetachedPaneId }) {
  const snapshot = useDetachedPaneSnapshot(paneId);
  if (paneId === "graph") {
    return <GraphWorkspace detached />;
  }
  if (paneId === "evidence") {
    return <DetachedEvidencePane snapshot={snapshot} />;
  }
  if (paneId === "timeline") {
    return <DetachedTimelinePane snapshot={snapshot} />;
  }
  return <DetachedInspectorPane snapshot={snapshot} />;
}

function DetachedInspectorPane({
  snapshot,
}: {
  readonly snapshot: DetachedEntitySnapshot | null;
}) {
  const findingsQuery = useFindingsQuery();
  const alertsQuery = useAlertsQuery();
  const incidentsQuery = useIncidentsQuery();
  const rows: DetachedSummaryRow[] = [
    summaryCountRow(
      "Incidents",
      incidentsQuery.data?.items ?? [],
      incidentsQuery.isLoading,
      topIncidentSummary,
    ),
    summaryCountRow(
      "Alerts",
      alertsQuery.data?.items ?? [],
      alertsQuery.isLoading,
      topAlertSummary,
    ),
    summaryCountRow(
      "Findings",
      findingsQuery.data?.items ?? [],
      findingsQuery.isLoading,
      topFindingSummary,
    ),
  ];

  if (snapshot) {
    return <DetachedSelectedEntityPane paneId="inspector" snapshot={snapshot} />;
  }

  if (findingsQuery.isError || alertsQuery.isError || incidentsQuery.isError) {
    return (
      <EmptyState
        title="Inspector read model unavailable"
        detail="The command bridge returned a redacted investigation query error."
        tone="error"
      />
    );
  }

  return (
    <DetachedReadModelPane
      icon={<PanelRight size={15} aria-hidden="true" />}
      title="Inspector read model"
      subtitle="Independent redacted summary from investigation commands"
      rows={rows}
    />
  );
}

function DetachedEvidencePane({
  snapshot,
}: {
  readonly snapshot: DetachedEntitySnapshot | null;
}) {
  const findingsQuery = useFindingsQuery();
  const rows =
    findingsQuery.data?.items.slice(0, 12).map((finding, index) => ({
      label: displayText(finding.finding_type ?? finding.finding_id, "Finding"),
      value: displayText(finding.summary_redacted, "Redacted finding evidence"),
      meta: `${evidenceRefCount(finding)} evidence refs / ${displayText(
        finding.severity,
        "medium",
      )}`,
      key: finding.finding_id ?? `finding:${index}`,
    })) ?? [];

  if (snapshot) {
    return <DetachedSelectedEntityPane paneId="evidence" snapshot={snapshot} />;
  }

  if (findingsQuery.isError) {
    return (
      <EmptyState
        title="Evidence read model unavailable"
        detail="The command bridge returned a redacted findings query error."
        tone="error"
      />
    );
  }

  return (
    <DetachedReadModelPane
      emptyDetail="No redacted evidence references were returned by the command bridge."
      icon={<ListChecks size={15} aria-hidden="true" />}
      loading={findingsQuery.isLoading}
      title="Evidence read model"
      subtitle="Finding evidence references only; no payloads or packet bodies"
      rows={rows}
    />
  );
}

function DetachedTimelinePane({
  snapshot,
}: {
  readonly snapshot: DetachedEntitySnapshot | null;
}) {
  const findingsQuery = useFindingsQuery();
  const alertsQuery = useAlertsQuery();
  const incidentsQuery = useIncidentsQuery();
  const rows = [
    ...(incidentsQuery.data?.items ?? []).map((incident, index) =>
      timelineRow("Incident", incident, incident.incident_id ?? `incident:${index}`),
    ),
    ...(alertsQuery.data?.items ?? []).map((alert, index) =>
      timelineRow("Alert", alert, alert.alert_id ?? `alert:${index}`),
    ),
    ...(findingsQuery.data?.items ?? []).map((finding, index) =>
      timelineRow("Finding", finding, finding.finding_id ?? `finding:${index}`),
    ),
  ].slice(0, 14);

  if (snapshot) {
    return <DetachedSelectedEntityPane paneId="timeline" snapshot={snapshot} />;
  }

  if (findingsQuery.isError || alertsQuery.isError || incidentsQuery.isError) {
    return (
      <EmptyState
        title="Timeline read model unavailable"
        detail="The command bridge returned a redacted investigation query error."
        tone="error"
      />
    );
  }

  return (
    <DetachedReadModelPane
      emptyDetail="No redacted case timeline entries were returned by the command bridge."
      icon={<History size={15} aria-hidden="true" />}
      loading={
        findingsQuery.isLoading || alertsQuery.isLoading || incidentsQuery.isLoading
      }
      title="Timeline read model"
      subtitle="Current case stream summary from incidents, alerts, and findings"
      rows={rows}
    />
  );
}

function DetachedSelectedEntityPane({
  paneId,
  snapshot,
}: {
  readonly paneId: Extract<DetachedPaneId, "inspector" | "evidence" | "timeline">;
  readonly snapshot: DetachedEntitySnapshot;
}) {
  const rows = snapshotRowsForPane(paneId, snapshot);
  return (
    <DetachedReadModelPane
      icon={iconForSnapshotPane(paneId)}
      title="Selected entity snapshot"
      subtitle={`${humanize(snapshot.entity_type)} / redacted snapshot from main window`}
      rows={rows}
    />
  );
}

function DetachedReadModelPane({
  emptyDetail,
  icon,
  loading = false,
  rows,
  subtitle,
  title,
}: {
  readonly emptyDetail?: string;
  readonly icon: ReactNode;
  readonly loading?: boolean;
  readonly rows: DetachedSummaryRow[];
  readonly subtitle: string;
  readonly title: string;
}) {
  return (
    <section className="detached-payload-pane">
      <header className="detached-payload-header">
        {icon}
        <div>
          <strong>{title}</strong>
          <span>{loading ? "Loading redacted metadata" : subtitle}</span>
        </div>
      </header>
      {rows.length ? (
        <dl className="detail-list">
          {rows.map((row) => (
            <div key={row.key ?? row.label}>
              <dt>{row.label}</dt>
              <dd>
                <span>{row.value}</span>
                {row.meta ? <small>{row.meta}</small> : null}
              </dd>
            </div>
          ))}
        </dl>
      ) : (
        <EmptyState
          title={loading ? "Loading redacted metadata" : "No metadata available"}
          detail={
            loading
              ? "The detached pane is waiting on the command bridge."
              : emptyDetail ?? "No read-model rows are available for this pane."
          }
          icon={FileSearch}
        />
      )}
    </section>
  );
}

function DetachedChrome({
  children,
  onRestore,
  subtitle,
  title,
}: {
  readonly children: ReactNode;
  readonly onRestore?: () => void;
  readonly subtitle: string;
  readonly title: string;
}) {
  return (
    <section className="detached-window-shell">
      <header className="detached-window-header">
        <div>
          <strong>{title}</strong>
          <span>{subtitle}</span>
        </div>
        {onRestore ? (
          <button
            className="toolbar-button"
            type="button"
            title="Restore pane to main window"
            onClick={onRestore}
          >
            <PanelBottomClose size={14} aria-hidden="true" />
            Restore
          </button>
        ) : null}
      </header>
      <main className="detached-window-body">{children}</main>
    </section>
  );
}

function isDetachedPaneId(value: string): value is DetachedPaneId {
  return value in DETACHED_PANE_LABELS;
}

const DETACHED_PANE_TITLES = {
  graph: "Graph",
  inspector: "Inspector",
  evidence: "Evidence",
  timeline: "Timeline",
} as const satisfies Record<DetachedPaneId, string>;

interface DetachedSummaryRow {
  readonly key?: string;
  readonly label: string;
  readonly meta?: string;
  readonly value: string;
}

function snapshotRowsForPane(
  paneId: Extract<DetachedPaneId, "inspector" | "evidence" | "timeline">,
  snapshot: DetachedEntitySnapshot,
): DetachedSummaryRow[] {
  const metadataRows: DetachedSummaryRow[] = [
    { label: "Type", value: humanize(snapshot.entity_type), key: "type" },
    { label: "ID", value: snapshot.entity_id, key: "id" },
    {
      label: "Severity",
      value: snapshot.severity ?? "none",
      key: "severity",
    },
    { label: "Source", value: snapshot.source ?? "view model", key: "source" },
  ];
  const fieldRows = Object.entries(snapshot.fields)
    .filter(([, value]) => value.trim().length > 0)
    .map(([key, value]) => ({
      label: humanize(key),
      value,
      key: `field:${key}`,
    }));

  if (paneId === "timeline") {
    const timelineRows = fieldRows.filter((row) =>
      containsAny(row.label, [
        "time",
        "timestamp",
        "observed",
        "created",
        "updated",
        "first",
        "last",
      ]),
    );
    return timelineRows.length
      ? timelineRows
      : [
          { label: "Selected", value: snapshot.title, key: "selected" },
          { label: "Entity", value: snapshot.entity_id, key: "entity" },
          { label: "Source", value: snapshot.source ?? "view model", key: "source" },
        ];
  }

  if (paneId === "evidence") {
    const evidenceRows = fieldRows.filter((row) =>
      containsAny(row.label, [
        "evidence",
        "finding",
        "summary",
        "ref",
        "source",
        "severity",
      ]),
    );
    return evidenceRows.length
      ? [...metadataRows.slice(0, 2), ...evidenceRows]
      : [...metadataRows, ...fieldRows.slice(0, 8)];
  }

  return [...metadataRows, ...fieldRows];
}

function containsAny(value: string, needles: readonly string[]) {
  const normalized = value.toLowerCase();
  return needles.some((needle) => normalized.includes(needle));
}

function iconForSnapshotPane(
  paneId: Extract<DetachedPaneId, "inspector" | "evidence" | "timeline">,
) {
  if (paneId === "timeline") {
    return <History size={15} aria-hidden="true" />;
  }
  if (paneId === "evidence") {
    return <ListChecks size={15} aria-hidden="true" />;
  }
  return <PanelRight size={15} aria-hidden="true" />;
}

function summaryCountRow<T>(
  label: string,
  items: readonly T[],
  loading: boolean,
  describeTopItem: (item: T) => string,
): DetachedSummaryRow {
  return {
    label,
    value: loading ? "Loading" : String(items.length),
    meta: items.length ? describeTopItem(items[0]) : "No command rows",
  };
}

function timelineRow(
  kind: string,
  item: IncidentDto | AlertDto | FindingDto,
  key: string,
): DetachedSummaryRow {
  return {
    key,
    label: kind,
    value: topCaseSummary(item),
    meta: `${displayText(item.state, "open")} / ${displayText(
      item.severity,
      "medium",
    )}`,
  };
}

function topIncidentSummary(incident: IncidentDto) {
  return topCaseSummary(incident);
}

function topAlertSummary(alert: AlertDto) {
  return topCaseSummary(alert);
}

function topFindingSummary(finding: FindingDto) {
  return topCaseSummary(finding);
}

function topCaseSummary(item: IncidentDto | AlertDto | FindingDto) {
  return displayText(
    item.summary_redacted ??
      item.finding_type ??
      item.incident_id ??
      item.alert_id ??
      item.finding_id,
    "Redacted summary",
  );
}

function evidenceRefCount(finding: FindingDto) {
  const refs = finding.evidence_refs;
  return Array.isArray(refs) ? refs.length : 0;
}

function displayText(value: unknown, fallback: string) {
  if (typeof value === "string" && value.trim().length) {
    return stringifySafe(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return stringifySafe(value);
  }
  return fallback;
}
