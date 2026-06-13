import {
  useEffect,
  useMemo,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type MouseEvent,
} from "react";
import {
  useSelectionStore,
  type SelectedEntityView,
} from "../../stores/selectionStore";
import { useStreamStore } from "../../stores/streamStore";
import { useUiStore } from "../../stores/uiStore";

export interface ShellTableColumn {
  key: string;
  label: string;
}

export interface ShellTableRow {
  id: string;
  cells: Record<string, string>;
  detail?: Record<string, string | number | boolean | null | undefined>;
  entityType?: string;
  severity?: "low" | "medium" | "high" | "critical";
  source?: string;
}

interface ShellTableProps {
  columns: ShellTableColumn[];
  entityType?: string;
  onRowOpen?: (row: ShellTableRow) => void;
  rows: ShellTableRow[];
  selectionScope?: string;
}

const EMPTY_SELECTED_ROW_IDS: string[] = [];

export function ShellTable({
  columns,
  entityType = "metadata",
  onRowOpen,
  rows,
  selectionScope = "shell-table",
}: ShellTableProps) {
  const selectedRowIds = useSelectionStore(
    (state) => state.tableSelections[selectionScope] ?? EMPTY_SELECTED_ROW_IDS,
  );
  const anchorRowId = useSelectionStore(
    (state) => state.tableSelectionAnchors[selectionScope] ?? null,
  );
  const setTableSelection = useSelectionStore(
    (state) => state.setTableSelection,
  );
  const setSelectedEntity = useSelectionStore((state) => state.setSelectedEntity);
  const setDetailDrawerOpen = useUiStore((state) => state.setDetailDrawerOpen);
  const lastPulseAt = useStreamStore((state) => state.lastPulseAt);
  const pulseEntityIds = useStreamStore((state) => state.lastPulseEntityIds);
  const [pulsingRowIds, setPulsingRowIds] = useState<string[]>([]);
  const selectedRowIdSet = useMemo(
    () => new Set(selectedRowIds),
    [selectedRowIds],
  );
  const tableStyle = {
    "--shell-table-min-width": `${Math.max(columns.length * 180, 360)}px`,
  } as CSSProperties;
  const gridStyle = {
    gridTemplateColumns: `repeat(${columns.length}, minmax(160px, 1fr))`,
  } satisfies CSSProperties;

  useEffect(() => {
    if (!lastPulseAt || !pulseEntityIds.length || !rows.length) {
      return;
    }
    const nextPulseRows = rows
      .filter((row) => rowMatchesPulse(row, pulseEntityIds))
      .map((row) => row.id)
      .slice(0, 12);
    if (!nextPulseRows.length) {
      return;
    }
    setPulsingRowIds(nextPulseRows);
    const timeout = window.setTimeout(() => setPulsingRowIds([]), 700);
    return () => window.clearTimeout(timeout);
  }, [lastPulseAt, pulseEntityIds, rows]);

  const selectRow = (
    row: ShellTableRow,
    event: MouseEvent | KeyboardEvent,
  ) => {
    const rowIds = rows.map((item) => item.id);
    const rangeAnchor = anchorRowId ?? selectedRowIds.at(-1) ?? row.id;
    const nextSelection = nextSelectedRowIds({
      anchorRowId: rangeAnchor,
      ctrlKey: "ctrlKey" in event ? event.ctrlKey || event.metaKey : false,
      rowId: row.id,
      rowIds,
      selectedRowIds,
      shiftKey: "shiftKey" in event ? event.shiftKey : false,
    });
    setTableSelection(selectionScope, nextSelection, row.id);
    setSelectedEntity(rowToSelectedEntity(row, columns, entityType));
  };

  const openRow = (row: ShellTableRow) => {
    setSelectedEntity(rowToSelectedEntity(row, columns, entityType));
    setDetailDrawerOpen(true);
    onRowOpen?.(row);
  };

  return (
    <div className="shell-table-scroll scroll-region table-scroll-region">
      <div
        aria-multiselectable="true"
        className="shell-table"
        role="table"
        style={tableStyle}
      >
        <div className="shell-table-row header" role="row" style={gridStyle}>
          {columns.map((column) => (
            <div className="shell-table-cell" role="columnheader" key={column.key}>
              {column.label}
            </div>
          ))}
        </div>
        {rows.map((row) => (
          <div
            aria-selected={selectedRowIdSet.has(row.id)}
            className="shell-table-row"
            data-severity={row.severity ?? "low"}
            data-selected={selectedRowIdSet.has(row.id) ? "true" : "false"}
            data-stream-updated={
              pulsingRowIds.includes(row.id) ? "true" : "false"
            }
            role="row"
            style={gridStyle}
            tabIndex={0}
            key={row.id}
            onClick={(event) => selectRow(row, event)}
            onDoubleClick={() => openRow(row)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                selectRow(row, event);
                openRow(row);
              }
              if (event.key === " ") {
                event.preventDefault();
                selectRow(row, event);
              }
            }}
          >
            {columns.map((column) => (
              <div className="shell-table-cell" role="cell" key={column.key}>
                {row.cells[column.key] ?? ""}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

export function nextSelectedRowIds({
  anchorRowId,
  ctrlKey,
  rowId,
  rowIds,
  selectedRowIds,
  shiftKey,
}: {
  readonly anchorRowId: string;
  readonly ctrlKey: boolean;
  readonly rowId: string;
  readonly rowIds: string[];
  readonly selectedRowIds: string[];
  readonly shiftKey: boolean;
}) {
  if (shiftKey) {
    const start = Math.max(0, rowIds.indexOf(anchorRowId));
    const end = Math.max(0, rowIds.indexOf(rowId));
    const [from, to] = start <= end ? [start, end] : [end, start];
    return rowIds.slice(from, to + 1);
  }
  if (ctrlKey) {
    return selectedRowIds.includes(rowId)
      ? selectedRowIds.filter((id) => id !== rowId)
      : [...selectedRowIds, rowId];
  }
  return [rowId];
}

function rowToSelectedEntity(
  row: ShellTableRow,
  columns: ShellTableColumn[],
  fallbackEntityType: string,
): SelectedEntityView {
  const fields = Object.fromEntries(
    columns.map((column) => [column.label, row.cells[column.key] ?? ""]),
  );
  for (const [key, value] of Object.entries(row.detail ?? {})) {
    if (value !== undefined) {
      fields[key] = String(value);
    }
  }
  const title =
    columns.map((column) => row.cells[column.key]).find(Boolean) ?? row.id;
  return {
    entityId: row.id,
    entityType: row.entityType ?? fallbackEntityType,
    fields,
    severity: row.severity,
    source: row.source,
    subtitle: row.id,
    title,
  };
}

function rowMatchesPulse(row: ShellTableRow, pulseEntityIds: string[]) {
  const rowTokens = [
    row.id,
    row.entityType ?? "",
    row.source ?? "",
    ...Object.values(row.cells),
    ...Object.values(row.detail ?? {}).map((value) =>
      value === undefined || value === null ? "" : String(value),
    ),
  ].map((value) => value.toLowerCase());
  return pulseEntityIds.some((id) => {
    const normalized = id.toLowerCase();
    return rowTokens.some(
      (value) => value === normalized || value.includes(normalized),
    );
  });
}
