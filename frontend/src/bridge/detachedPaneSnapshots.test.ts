import { afterEach, describe, expect, it } from "vitest";
import type { SelectedEntityView } from "../stores/selectionStore";
import {
  DETACHED_PANE_SNAPSHOT_EVENT,
  DETACHED_PANE_SNAPSHOT_REQUEST_EVENT,
  detachedPaneSnapshotPayload,
  publishDetachedPaneSnapshot,
  requestDetachedPaneSnapshot,
  sanitizeSelectedEntityForDetachedPane,
  setDetachedPaneSnapshotBridgeForTests,
  subscribeDetachedPaneSnapshot,
  type DetachedPaneSnapshotPayload,
} from "./detachedPaneSnapshots";

type TestListener<T> = (event: { payload: T }) => void;

describe("detached pane selected-entity snapshots", () => {
  afterEach(() => {
    setDetachedPaneSnapshotBridgeForTests({
      emitTo: null,
      listen: null,
    });
  });

  it("sanitizes selected entities before they cross native webview boundaries", () => {
    const snapshot = sanitizeSelectedEntityForDetachedPane({
      entityId: "finding:api_key",
      entityType: "finding",
      fields: {
        Summary: "Redacted metadata",
        Password: "secret",
        Command: "api_key leaked",
      },
      severity: "high",
      source: "command",
      subtitle: "finding:api_key",
      title: "session_token finding",
    });

    expect(snapshot).toEqual({
      entity_id: "[redacted]",
      entity_type: "finding",
      fields: {
        Summary: "Redacted metadata",
        Command: "[redacted]",
      },
      severity: "high",
      source: "command",
      subtitle: "[redacted]",
      title: "[redacted]",
    });
    expect(snapshot?.fields).not.toHaveProperty("Password");
  });

  it("publishes snapshots only to the requested allowlisted detached pane label", async () => {
    const emitted: Array<{ target: string; event: string; payload: unknown }> = [];
    setDetachedPaneSnapshotBridgeForTests({
      emitTo: async (target, event, payload) => {
        emitted.push({ target, event, payload });
      },
      listen: async () => () => undefined,
    });

    await publishDetachedPaneSnapshot("evidence", selectedFinding());

    expect(emitted).toHaveLength(1);
    expect(emitted[0].target).toBe("detached-evidence");
    expect(emitted[0].event).toBe(DETACHED_PANE_SNAPSHOT_EVENT);
    expect(emitted[0].payload).toMatchObject({
      schema_version: 1,
      pane_id: "evidence",
      label: "detached-evidence",
      selected_entity: {
        entity_id: "finding:1",
        title: "Redacted finding",
      },
    });
  });

  it("requests the latest selected-entity snapshot from the main window", async () => {
    const emitted: Array<{ target: string; event: string; payload: unknown }> = [];
    setDetachedPaneSnapshotBridgeForTests({
      emitTo: async (target, event, payload) => {
        emitted.push({ target, event, payload });
      },
      listen: async () => () => undefined,
    });

    await requestDetachedPaneSnapshot("timeline");

    expect(emitted).toEqual([
      {
        target: "main",
        event: DETACHED_PANE_SNAPSHOT_REQUEST_EVENT,
        payload: {
          pane_id: "timeline",
          label: "detached-timeline",
        },
      },
    ]);
  });

  it("subscribes only to valid snapshot payloads with matching labels", async () => {
    const listeners: Record<string, TestListener<DetachedPaneSnapshotPayload>> = {};
    setDetachedPaneSnapshotBridgeForTests({
      emitTo: async () => undefined,
      listen: async (event, handler) => {
        listeners[event] = handler as TestListener<DetachedPaneSnapshotPayload>;
        return () => {
          delete listeners[event];
        };
      },
    });

    const received: DetachedPaneSnapshotPayload[] = [];
    const unlisten = await subscribeDetachedPaneSnapshot((payload) =>
      received.push(payload),
    );
    const valid = detachedPaneSnapshotPayload("inspector", selectedFinding());

    listeners[DETACHED_PANE_SNAPSHOT_EVENT]?.({
      payload: valid,
    });
    listeners[DETACHED_PANE_SNAPSHOT_EVENT]?.({
      payload: {
        ...valid,
        label: "detached-evidence",
      },
    });

    expect(received).toEqual([valid]);
    unlisten();
  });
});

function selectedFinding(): SelectedEntityView {
  return {
    entityId: "finding:1",
    entityType: "finding",
    fields: {
      Summary: "Redacted metadata finding",
      Evidence: "2 refs",
    },
    severity: "high",
    source: "command",
    subtitle: "finding:1",
    title: "Redacted finding",
  };
}
