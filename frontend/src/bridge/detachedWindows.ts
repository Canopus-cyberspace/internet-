import type { UnlistenFn } from "@tauri-apps/api/event";
import { mapCoreError } from "./tauri/errors";

export const DETACHED_PANE_LABELS = {
  graph: "detached-graph",
  inspector: "detached-inspector",
  evidence: "detached-evidence",
  timeline: "detached-timeline",
} as const;

export type DetachedPaneId = keyof typeof DETACHED_PANE_LABELS;

export interface DetachedPaneWindowOptions {
  readonly url: string;
  readonly title: string;
  readonly width: number;
  readonly height: number;
  readonly minWidth: number;
  readonly minHeight: number;
  readonly resizable: boolean;
  readonly center: boolean;
  readonly focus: boolean;
  readonly visible: boolean;
}

export interface DetachedPaneWindowResult {
  readonly pane_id: DetachedPaneId;
  readonly label: (typeof DETACHED_PANE_LABELS)[DetachedPaneId];
  readonly route: string;
  readonly created?: boolean;
  readonly closed?: boolean;
}

export interface DetachedPaneLifecyclePayload {
  readonly pane_id: DetachedPaneId;
  readonly label: (typeof DETACHED_PANE_LABELS)[DetachedPaneId];
}

export interface DetachedPaneLifecycleEvent extends DetachedPaneLifecyclePayload {
  readonly state: "opened" | "closed";
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
type NativeWindowEventHandler<T = unknown> = (event: { payload: T }) => void;

interface NativeDetachedWindow {
  readonly label: string;
  readonly show: () => Promise<void>;
  readonly setFocus: () => Promise<void>;
  readonly close: () => Promise<void>;
  readonly once: <T>(
    event: string,
    handler: NativeWindowEventHandler<T>,
  ) => Promise<UnlistenFn>;
}

interface NativeDetachedWindowApi {
  readonly create: (
    label: string,
    options: DetachedPaneWindowOptions,
  ) => NativeDetachedWindow;
  readonly getByLabel: (label: string) => Promise<NativeDetachedWindow | null>;
  readonly emitTo: EmitToFn;
  readonly listen: ListenFn;
}

export const DETACHED_PANE_WINDOW_OPTIONS = {
  graph: {
    url: "/detached/graph",
    title: "Sentinel Guard - Graph",
    width: 1180,
    height: 820,
    minWidth: 900,
    minHeight: 600,
    resizable: true,
    center: true,
    focus: true,
    visible: true,
  },
  inspector: {
    url: "/detached/inspector",
    title: "Sentinel Guard - Inspector",
    width: 760,
    height: 780,
    minWidth: 540,
    minHeight: 520,
    resizable: true,
    center: true,
    focus: true,
    visible: true,
  },
  evidence: {
    url: "/detached/evidence",
    title: "Sentinel Guard - Evidence",
    width: 840,
    height: 760,
    minWidth: 620,
    minHeight: 520,
    resizable: true,
    center: true,
    focus: true,
    visible: true,
  },
  timeline: {
    url: "/detached/timeline",
    title: "Sentinel Guard - Timeline",
    width: 840,
    height: 760,
    minWidth: 620,
    minHeight: 520,
    resizable: true,
    center: true,
    focus: true,
    visible: true,
  },
} as const satisfies Record<DetachedPaneId, DetachedPaneWindowOptions>;

export const DETACHED_GRAPH_WINDOW_OPTIONS = DETACHED_PANE_WINDOW_OPTIONS.graph;

const DETACHED_PANE_IDS = new Set(Object.keys(DETACHED_PANE_LABELS));
const LIFECYCLE_EVENTS = ["detached_pane_opened", "detached_pane_closed"] as const;

let nativeDetachedWindowOverride: Partial<NativeDetachedWindowApi> | null = null;

export function setDetachedWindowBridgeForTests({
  create,
  emitTo,
  getByLabel,
  listen,
}: {
  readonly create?: NativeDetachedWindowApi["create"] | null;
  readonly emitTo?: EmitToFn | null;
  readonly getByLabel?: NativeDetachedWindowApi["getByLabel"] | null;
  readonly listen?: ListenFn | null;
}) {
  if (create === null || emitTo === null || getByLabel === null || listen === null) {
    nativeDetachedWindowOverride = null;
    return;
  }

  nativeDetachedWindowOverride = {
    ...(nativeDetachedWindowOverride ?? {}),
    ...(create ? { create } : {}),
    ...(emitTo ? { emitTo } : {}),
    ...(getByLabel ? { getByLabel } : {}),
    ...(listen ? { listen } : {}),
  };
}

export async function openDetachedPane(
  paneId: DetachedPaneId,
): Promise<DetachedPaneWindowResult> {
  assertDetachedPaneId(paneId);
  const native = await loadNativeDetachedWindowApi();
  const label = DETACHED_PANE_LABELS[paneId];
  const existingWindow = await native.getByLabel(label);

  if (existingWindow) {
    await existingWindow.show();
    await existingWindow.setFocus();
    return detachedPaneResult(paneId, false);
  }

  const detachedWindow = native.create(label, windowOptionsForPane(paneId));
  await waitForNativeWindowCreated(detachedWindow, paneId);
  await detachedWindow.setFocus();
  await emitDetachedPaneLifecycle(native.emitTo, "detached_pane_opened", paneId);
  return detachedPaneResult(paneId, true);
}

export async function closeDetachedPane(
  paneId: DetachedPaneId,
): Promise<DetachedPaneWindowResult> {
  assertDetachedPaneId(paneId);
  const native = await loadNativeDetachedWindowApi();
  const detachedWindow = await native.getByLabel(DETACHED_PANE_LABELS[paneId]);

  if (!detachedWindow) {
    await emitDetachedPaneLifecycle(native.emitTo, "detached_pane_closed", paneId);
    return { ...detachedPaneResult(paneId, false), closed: false };
  }

  await detachedWindow.close();
  await emitDetachedPaneLifecycle(native.emitTo, "detached_pane_closed", paneId);
  return { ...detachedPaneResult(paneId, false), closed: true };
}

export async function subscribeDetachedPaneLifecycle(
  handler: (event: DetachedPaneLifecycleEvent) => void,
): Promise<UnlistenFn> {
  const native = await loadNativeDetachedWindowApi();
  const unlistenFns: UnlistenFn[] = [];
  try {
    for (const eventName of LIFECYCLE_EVENTS) {
      unlistenFns.push(
        await native.listen<DetachedPaneLifecyclePayload>(eventName, (event) => {
          if (isDetachedPaneLifecyclePayload(event.payload)) {
            handler({
              ...event.payload,
              state: eventName === "detached_pane_opened" ? "opened" : "closed",
            });
          }
        }),
      );
    }
  } catch (error) {
    for (const unlisten of unlistenFns) {
      unlisten();
    }
    throw mapCoreError(error);
  }

  return () => {
    for (const unlisten of unlistenFns) {
      unlisten();
    }
  };
}

function windowOptionsForPane(paneId: DetachedPaneId): DetachedPaneWindowOptions {
  return DETACHED_PANE_WINDOW_OPTIONS[paneId];
}

function detachedPaneResult(
  paneId: DetachedPaneId,
  created: boolean,
): DetachedPaneWindowResult {
  return {
    pane_id: paneId,
    label: DETACHED_PANE_LABELS[paneId],
    route: windowOptionsForPane(paneId).url,
    created,
  };
}

async function waitForNativeWindowCreated(
  detachedWindow: NativeDetachedWindow,
  paneId: DetachedPaneId,
): Promise<void> {
  try {
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const unlistenFns: UnlistenFn[] = [];
      const settle = (next: () => void) => {
        if (settled) {
          return;
        }
        settled = true;
        for (const unlisten of unlistenFns) {
          unlisten();
        }
        next();
      };

      void detachedWindow
        .once("tauri://created", () => settle(() => resolve()))
        .then((unlisten) => {
          unlistenFns.push(unlisten);
        });
      void detachedWindow
        .once("tauri://error", (event) =>
          settle(() => reject(nativeDetachedWindowError(paneId, event.payload))),
        )
        .then((unlisten) => {
          unlistenFns.push(unlisten);
        });
    });
  } catch (error) {
    throw mapCoreError(error);
  }
}

function nativeDetachedWindowError(paneId: DetachedPaneId, error: unknown) {
  return new Error(
    `Failed to create native detached pane ${paneId}: ${String(error)}`,
  );
}

async function emitDetachedPaneLifecycle(
  emitTo: EmitToFn,
  eventName: (typeof LIFECYCLE_EVENTS)[number],
  paneId: DetachedPaneId,
) {
  try {
    await emitTo("main", eventName, {
      pane_id: paneId,
      label: DETACHED_PANE_LABELS[paneId],
    });
  } catch (error) {
    throw mapCoreError(error);
  }
}

function assertDetachedPaneId(paneId: string): asserts paneId is DetachedPaneId {
  if (!DETACHED_PANE_IDS.has(paneId)) {
    throw new Error(`Detached pane is not allowlisted: ${paneId}`);
  }
}

function isDetachedPaneLifecyclePayload(
  value: unknown,
): value is DetachedPaneLifecyclePayload {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.pane_id === "string" &&
    typeof record.label === "string" &&
    DETACHED_PANE_LABELS[record.pane_id as DetachedPaneId] === record.label
  );
}

async function loadNativeDetachedWindowApi(): Promise<NativeDetachedWindowApi> {
  if (
    nativeDetachedWindowOverride?.create &&
    nativeDetachedWindowOverride.emitTo &&
    nativeDetachedWindowOverride.getByLabel &&
    nativeDetachedWindowOverride.listen
  ) {
    return nativeDetachedWindowOverride as NativeDetachedWindowApi;
  }

  const [webviewWindowModule, eventModule] = await Promise.all([
    import("@tauri-apps/api/webviewWindow"),
    import("@tauri-apps/api/event"),
  ]);
  const WebviewWindow = webviewWindowModule.WebviewWindow;

  return {
    create:
      nativeDetachedWindowOverride?.create ??
      ((label, options) => new WebviewWindow(label, options) as NativeDetachedWindow),
    emitTo: nativeDetachedWindowOverride?.emitTo ?? (eventModule.emitTo as EmitToFn),
    getByLabel:
      nativeDetachedWindowOverride?.getByLabel ??
      ((label) =>
        WebviewWindow.getByLabel(label) as Promise<NativeDetachedWindow | null>),
    listen: nativeDetachedWindowOverride?.listen ?? (eventModule.listen as ListenFn),
  };
}
