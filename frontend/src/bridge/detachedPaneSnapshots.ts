import type { UnlistenFn } from "@tauri-apps/api/event";
import type { SelectedEntityView } from "../stores/selectionStore";
import {
  DETACHED_PANE_LABELS,
  type DetachedPaneId,
} from "./detachedWindows";
import { mapCoreError } from "./tauri/errors";
import { isSensitiveKey, stringifySafe } from "../shared/renderers";

export const DETACHED_PANE_SNAPSHOT_EVENT = "detached_pane_snapshot";
export const DETACHED_PANE_SNAPSHOT_REQUEST_EVENT =
  "detached_pane_snapshot_request";

export const DETACHED_SNAPSHOT_PANE_IDS = [
  "inspector",
  "evidence",
  "timeline",
] as const satisfies readonly DetachedPaneId[];

export type DetachedSnapshotPaneId = (typeof DETACHED_SNAPSHOT_PANE_IDS)[number];

export interface DetachedEntitySnapshot {
  readonly entity_id: string;
  readonly entity_type: string;
  readonly fields: Record<string, string>;
  readonly severity?: string;
  readonly source?: string;
  readonly subtitle?: string;
  readonly title: string;
}

export interface DetachedPaneSnapshotPayload {
  readonly schema_version: 1;
  readonly pane_id: DetachedSnapshotPaneId;
  readonly label: (typeof DETACHED_PANE_LABELS)[DetachedSnapshotPaneId];
  readonly selected_entity: DetachedEntitySnapshot | null;
  readonly sent_at: string;
}

export interface DetachedPaneSnapshotRequestPayload {
  readonly pane_id: DetachedSnapshotPaneId;
  readonly label: (typeof DETACHED_PANE_LABELS)[DetachedSnapshotPaneId];
}

type ListenFn = <T>(
  event: string,
  handler: (event: { payload: T }) => void,
) => Promise<UnlistenFn>;

type EmitToFn = (
  target: string,
  event: string,
  payload?: unknown,
) => Promise<void>;

let bridgeOverride: {
  readonly emitTo?: EmitToFn;
  readonly listen?: ListenFn;
} | null = null;

export function setDetachedPaneSnapshotBridgeForTests({
  emitTo,
  listen,
}: {
  readonly emitTo?: EmitToFn | null;
  readonly listen?: ListenFn | null;
}) {
  if (emitTo === null || listen === null) {
    bridgeOverride = null;
    return;
  }

  bridgeOverride = {
    ...(bridgeOverride ?? {}),
    ...(emitTo ? { emitTo } : {}),
    ...(listen ? { listen } : {}),
  };
}

export async function publishDetachedPaneSnapshot(
  paneId: DetachedSnapshotPaneId,
  selectedEntity: SelectedEntityView | null,
) {
  assertDetachedSnapshotPaneId(paneId);
  const native = await loadDetachedPaneSnapshotApi();
  const payload = detachedPaneSnapshotPayload(paneId, selectedEntity);
  try {
    await native.emitTo(
      DETACHED_PANE_LABELS[paneId],
      DETACHED_PANE_SNAPSHOT_EVENT,
      payload,
    );
  } catch (error) {
    throw mapCoreError(error);
  }
}

export async function requestDetachedPaneSnapshot(paneId: DetachedSnapshotPaneId) {
  assertDetachedSnapshotPaneId(paneId);
  const native = await loadDetachedPaneSnapshotApi();
  try {
    await native.emitTo("main", DETACHED_PANE_SNAPSHOT_REQUEST_EVENT, {
      pane_id: paneId,
      label: DETACHED_PANE_LABELS[paneId],
    } satisfies DetachedPaneSnapshotRequestPayload);
  } catch (error) {
    throw mapCoreError(error);
  }
}

export async function subscribeDetachedPaneSnapshot(
  handler: (payload: DetachedPaneSnapshotPayload) => void,
): Promise<UnlistenFn> {
  const native = await loadDetachedPaneSnapshotApi();
  try {
    return await native.listen<DetachedPaneSnapshotPayload>(
      DETACHED_PANE_SNAPSHOT_EVENT,
      (event) => {
        if (isDetachedPaneSnapshotPayload(event.payload)) {
          handler(event.payload);
        }
      },
    );
  } catch (error) {
    throw mapCoreError(error);
  }
}

export async function subscribeDetachedPaneSnapshotRequests(
  handler: (payload: DetachedPaneSnapshotRequestPayload) => void,
): Promise<UnlistenFn> {
  const native = await loadDetachedPaneSnapshotApi();
  try {
    return await native.listen<DetachedPaneSnapshotRequestPayload>(
      DETACHED_PANE_SNAPSHOT_REQUEST_EVENT,
      (event) => {
        if (isDetachedPaneSnapshotRequestPayload(event.payload)) {
          handler(event.payload);
        }
      },
    );
  } catch (error) {
    throw mapCoreError(error);
  }
}

export function detachedPaneSnapshotPayload(
  paneId: DetachedSnapshotPaneId,
  selectedEntity: SelectedEntityView | null,
): DetachedPaneSnapshotPayload {
  assertDetachedSnapshotPaneId(paneId);
  return {
    schema_version: 1,
    pane_id: paneId,
    label: DETACHED_PANE_LABELS[paneId],
    selected_entity: sanitizeSelectedEntityForDetachedPane(selectedEntity),
    sent_at: new Date().toISOString(),
  };
}

export function sanitizeSelectedEntityForDetachedPane(
  selectedEntity: SelectedEntityView | null,
): DetachedEntitySnapshot | null {
  if (!selectedEntity) {
    return null;
  }

  const fields = Object.fromEntries(
    Object.entries(selectedEntity.fields)
      .filter(([key]) => !isSensitiveKey(key))
      .map(([key, value]) => [key, stringifySafe(value)]),
  );

  return {
    entity_id: stringifySafe(selectedEntity.entityId),
    entity_type: stringifySafe(selectedEntity.entityType),
    fields,
    ...(selectedEntity.severity
      ? { severity: stringifySafe(selectedEntity.severity) }
      : {}),
    ...(selectedEntity.source
      ? { source: stringifySafe(selectedEntity.source) }
      : {}),
    ...(selectedEntity.subtitle
      ? { subtitle: stringifySafe(selectedEntity.subtitle) }
      : {}),
    title: stringifySafe(selectedEntity.title),
  };
}

export function isDetachedSnapshotPaneId(
  paneId: DetachedPaneId,
): paneId is DetachedSnapshotPaneId {
  return (DETACHED_SNAPSHOT_PANE_IDS as readonly string[]).includes(paneId);
}

function assertDetachedSnapshotPaneId(
  paneId: string,
): asserts paneId is DetachedSnapshotPaneId {
  if (
    !(DETACHED_SNAPSHOT_PANE_IDS as readonly string[]).includes(paneId) ||
    !(paneId in DETACHED_PANE_LABELS)
  ) {
    throw new Error(`Detached pane snapshot is not allowlisted: ${paneId}`);
  }
}

function isDetachedPaneSnapshotPayload(
  value: unknown,
): value is DetachedPaneSnapshotPayload {
  if (!isSnapshotEnvelope(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    record.schema_version === 1 &&
    isDetachedSnapshotPaneId(record.pane_id as DetachedPaneId) &&
    DETACHED_PANE_LABELS[record.pane_id as DetachedSnapshotPaneId] ===
      record.label &&
    (record.selected_entity === null ||
      isDetachedEntitySnapshot(record.selected_entity))
  );
}

function isDetachedPaneSnapshotRequestPayload(
  value: unknown,
): value is DetachedPaneSnapshotRequestPayload {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.pane_id === "string" &&
    typeof record.label === "string" &&
    isDetachedSnapshotPaneId(record.pane_id as DetachedPaneId) &&
    DETACHED_PANE_LABELS[record.pane_id as DetachedSnapshotPaneId] ===
      record.label
  );
}

function isSnapshotEnvelope(value: unknown) {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.pane_id === "string" &&
    typeof record.label === "string" &&
    typeof record.sent_at === "string"
  );
}

function isDetachedEntitySnapshot(value: unknown): value is DetachedEntitySnapshot {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.entity_id === "string" &&
    typeof record.entity_type === "string" &&
    typeof record.title === "string" &&
    typeof record.fields === "object" &&
    record.fields !== null &&
    !Array.isArray(record.fields)
  );
}

async function loadDetachedPaneSnapshotApi(): Promise<{
  readonly emitTo: EmitToFn;
  readonly listen: ListenFn;
}> {
  if (bridgeOverride?.emitTo && bridgeOverride.listen) {
    return bridgeOverride as {
      readonly emitTo: EmitToFn;
      readonly listen: ListenFn;
    };
  }

  const eventModule = await import("@tauri-apps/api/event");
  return {
    emitTo: bridgeOverride?.emitTo ?? (eventModule.emitTo as EmitToFn),
    listen: bridgeOverride?.listen ?? (eventModule.listen as ListenFn),
  };
}
