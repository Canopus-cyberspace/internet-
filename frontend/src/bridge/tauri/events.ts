import type { UnlistenFn } from "@tauri-apps/api/event";
import type { StreamEventEnvelope, StreamName } from "../eventHandlers";
import { mapCoreError } from "./errors";

type ListenFn = <T>(
  event: string,
  handler: (event: { payload: T }) => void,
) => Promise<UnlistenFn>;

let listenOverride: ListenFn | null = null;

const STREAM_EVENT_NAMES: Record<StreamName, string> = {
  health: "health_stream",
  metric: "metric_stream",
  capture_status: "capture_status_stream",
  service_status: "service_status_stream",
  alert: "alert_stream",
  incident: "incident_stream",
  graph_update: "graph_update_stream",
  response_status: "response_status_stream",
  report_progress: "report_progress_stream",
  privacy_warning: "privacy_warning_stream",
};

export function setListenCoreForTests(listen: ListenFn | null) {
  listenOverride = listen;
}

export async function subscribeCoreEvent(
  stream: StreamName,
  handler: (envelope: StreamEventEnvelope) => void,
): Promise<UnlistenFn> {
  try {
    const listen = listenOverride ?? (await loadTauriListen());
    return await listen<StreamEventEnvelope>(
      STREAM_EVENT_NAMES[stream],
      (event) => handler(event.payload),
    );
  } catch (error) {
    throw mapCoreError(error);
  }
}

export async function subscribeCoreEvents(
  handler: (envelope: StreamEventEnvelope) => void,
): Promise<UnlistenFn> {
  const unlistenFns: UnlistenFn[] = [];
  try {
    for (const stream of Object.keys(STREAM_EVENT_NAMES) as StreamName[]) {
      unlistenFns.push(await subscribeCoreEvent(stream, handler));
    }
  } catch (error) {
    for (const unlisten of unlistenFns) {
      unlisten();
    }
    throw error;
  }

  return () => {
    for (const unlisten of unlistenFns) {
      unlisten();
    }
  };
}

async function loadTauriListen(): Promise<ListenFn> {
  const module = await import("@tauri-apps/api/event");
  return module.listen as ListenFn;
}
