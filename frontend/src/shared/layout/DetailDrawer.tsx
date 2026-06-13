import { FileSearch, History, Maximize2, ShieldCheck, X } from "lucide-react";
import { useEffect, useState } from "react";
import type { DetachedPaneId } from "../../bridge/detachedWindows";
import type { JsonValue } from "../../bridge/dto/common";
import {
  useSelectionStore,
  type SelectedEntityView,
} from "../../stores/selectionStore";
import { useUiStore } from "../../stores/uiStore";
import { humanize, isSensitiveKey, stringifySafe } from "../renderers";
import { EmptyState } from "./EmptyState";
import { useDetachedPaneActions } from "./useDetachedPaneWindows";

export type DetailDrawerTabId = "evidence" | "timeline" | "response";

const DETAIL_DRAWER_TABS = [
  { id: "evidence", label: "Evidence", icon: FileSearch },
  { id: "timeline", label: "Timeline", icon: History },
  { id: "response", label: "Response", icon: ShieldCheck },
] as const satisfies ReadonlyArray<{
  readonly id: DetailDrawerTabId;
  readonly label: string;
  readonly icon: typeof FileSearch;
}>;

export function DetailDrawer() {
  const setOpen = useUiStore((state) => state.setDetailDrawerOpen);
  const detachedPanes = useUiStore((state) => state.detachedPanes);
  const selectedEntity = useSelectionStore((state) => state.selectedEntity);
  const { detachPane } = useDetachedPaneActions();
  const [activeTab, setActiveTab] = useState<DetailDrawerTabId>("evidence");
  const activeDetachedPaneId = detachedPaneIdForDetailTab(activeTab);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [setOpen]);

  return (
    <aside className="detail-drawer" aria-label="Detail drawer">
      <div className="drawer-header">
        <div>
          <strong>{selectedEntity?.title ?? "Detail"}</strong>
          <span>
            {selectedEntity
              ? `${humanize(selectedEntity.entityType)} / ${selectedEntity.subtitle ?? selectedEntity.entityId}`
              : "No selection"}
          </span>
        </div>
        <div className="pane-actions">
          <button
            type="button"
            className="tree-toggle"
            onClick={() => {
              void detachPane("inspector");
            }}
            title={
              detachedPanes.inspector
                ? "Focus detached inspector"
                : "Detach inspector"
            }
            aria-pressed={detachedPanes.inspector ? "true" : "false"}
          >
            <Maximize2 size={14} aria-hidden="true" />
          </button>
          {activeDetachedPaneId ? (
            <button
              type="button"
              className="tree-toggle"
              onClick={() => {
                void detachPane(activeDetachedPaneId);
              }}
              title={
                detachedPanes[activeDetachedPaneId]
                  ? `Focus detached ${activeDetachedPaneId}`
                  : `Detach active ${activeDetachedPaneId} tab`
              }
              aria-pressed={
                detachedPanes[activeDetachedPaneId] ? "true" : "false"
              }
            >
              <Maximize2 size={14} aria-hidden="true" />
            </button>
          ) : null}
          <button
            type="button"
            className="tree-toggle"
            onClick={() => setOpen(false)}
            title="Close detail drawer"
          >
            <X size={14} aria-hidden="true" />
          </button>
        </div>
      </div>
      <DetailDrawerTabs activeTab={activeTab} onSelectTab={setActiveTab} />
      <div
        className="drawer-body scroll-region"
        data-active-tab={activeTab}
        id={`detail-tabpanel-${activeTab}`}
        role="tabpanel"
        aria-labelledby={`detail-tab-${activeTab}`}
      >
        {selectedEntity ? (
          <DetailTabPanel activeTab={activeTab} entity={selectedEntity} />
        ) : (
          <EmptyState
            title="No entity selected"
            detail="Select a table row or graph item to inspect redacted metadata."
          />
        )}
      </div>
    </aside>
  );
}

function detachedPaneIdForDetailTab(
  tabId: DetailDrawerTabId,
): Extract<DetachedPaneId, "evidence" | "timeline"> | null {
  if (tabId === "evidence" || tabId === "timeline") {
    return tabId;
  }
  return null;
}

export function DetailDrawerTabs({
  activeTab,
  onSelectTab,
}: {
  readonly activeTab: DetailDrawerTabId;
  readonly onSelectTab: (tabId: DetailDrawerTabId) => void;
}) {
  return (
    <div className="drawer-tabs" role="tablist" aria-label="Detail sections">
      {DETAIL_DRAWER_TABS.map((tab) => {
        const Icon = tab.icon;
        const selected = activeTab === tab.id;
        return (
          <button
            type="button"
            className={`drawer-tab${selected ? " active" : ""}`}
            data-selected={selected ? "true" : "false"}
            id={`detail-tab-${tab.id}`}
            key={tab.id}
            role="tab"
            aria-controls={`detail-tabpanel-${tab.id}`}
            aria-selected={selected}
            onClick={() => onSelectTab(tab.id)}
          >
            <Icon size={14} aria-hidden="true" />
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}

function DetailTabPanel({
  activeTab,
  entity,
}: {
  readonly activeTab: DetailDrawerTabId;
  readonly entity: SelectedEntityView;
}) {
  if (activeTab === "timeline") {
    return <EntityTimelineRenderer entity={entity} />;
  }
  if (activeTab === "response") {
    return <EntityResponseRenderer entity={entity} />;
  }
  return <EntityFieldRenderer entity={entity} />;
}

function EntityFieldRenderer({
  entity,
}: {
  readonly entity: SelectedEntityView;
}) {
  const metadata = {
    Type: humanize(entity.entityType),
    ID: entity.entityId,
    Severity: entity.severity ?? "none",
    Source: entity.source ?? "view model",
  };
  const fields = (Object.entries({ ...metadata, ...entity.fields }) as [
    string,
    JsonValue,
  ][])
    .filter(([key]) => !isSensitiveKey(key))
    .filter(([, value]) => stringifySafe(value).trim().length > 0);

  return (
    <dl className="detail-list">
      {fields.map(([key, value]) => (
        <div key={key}>
          <dt>{humanize(key)}</dt>
          <dd>{stringifySafe(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function EntityTimelineRenderer({
  entity,
}: {
  readonly entity: SelectedEntityView;
}) {
  const timelineFields = fieldsMatching(entity.fields, [
    "time",
    "timestamp",
    "observed",
    "created",
    "updated",
    "first",
    "last",
  ]);
  const fallbackRows: ReadonlyArray<readonly [string, string]> = [
    ["Selected", entity.title],
    ["Entity", entity.entityId],
    ["Source", entity.source ?? "view model"],
  ];
  const rows = timelineFields.length
    ? timelineFields
    : fallbackRows;

  return <FieldList rows={rows} />;
}

function EntityResponseRenderer({
  entity,
}: {
  readonly entity: SelectedEntityView;
}) {
  const responseFields = fieldsMatching(entity.fields, [
    "response",
    "recommend",
    "action",
    "approval",
    "rollback",
    "policy",
    "state",
    "severity",
  ]);
  const fallbackRows: ReadonlyArray<readonly [string, string]> = [
    ["Disposition", "recommend-first"],
    ["Policy", entity.severity === "critical" ? "approval required" : "review"],
    ["Rollback", "required before execution"],
  ];
  const rows = responseFields.length
    ? responseFields
    : fallbackRows;

  return <FieldList rows={rows} />;
}

function FieldList({ rows }: { readonly rows: ReadonlyArray<readonly [string, string]> }) {
  return (
    <dl className="detail-list">
      {rows.map(([key, value]) => (
        <div key={key}>
          <dt>{humanize(key)}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function fieldsMatching(
  fields: Record<string, string>,
  needles: readonly string[],
): Array<readonly [string, string]> {
  return Object.entries(fields)
    .filter(([key]) => !isSensitiveKey(key))
    .filter(([key, value]) => {
      const normalizedKey = key.toLowerCase();
      return (
        needles.some((needle) => normalizedKey.includes(needle)) &&
        value.trim().length > 0
      );
    })
    .map(([key, value]) => [key, value] as const);
}
