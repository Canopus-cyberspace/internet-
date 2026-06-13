import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  DETACHED_PANE_LABELS,
  DETACHED_PANE_WINDOW_OPTIONS,
  DETACHED_GRAPH_WINDOW_OPTIONS,
  closeDetachedPane,
  openDetachedPane,
  setDetachedWindowBridgeForTests,
  subscribeDetachedPaneLifecycle,
  type DetachedPaneId,
  type DetachedPaneLifecyclePayload,
  type DetachedPaneWindowOptions,
} from "./detachedWindows";
import { INITIAL_DETACHED_PANE_STATE, useUiStore } from "../stores/uiStore";
import { PANE_SIZE_LIMITS } from "../shared/layout/paneSizing";
import { applyDetachedPaneLifecycleEvent } from "../shared/layout/useDetachedPaneWindows";
import { completePaneDragOutDetach } from "../shared/layout/usePaneDragOutDetach";

type TestListener<T> = (event: { payload: T }) => void;

interface TestNativeWindow {
  readonly label: string;
  readonly showCalls: string[];
  readonly focusCalls: string[];
  readonly closeCalls: string[];
  readonly show: () => Promise<void>;
  readonly setFocus: () => Promise<void>;
  readonly close: () => Promise<void>;
  readonly once: <T>(
    event: string,
    handler: TestListener<T>,
  ) => Promise<() => void>;
}

describe("detached graph native window bridge", () => {
  beforeEach(() => {
    useUiStore.setState({
      bottomGraphHeight: PANE_SIZE_LIMITS.bottomGraph.defaultSize,
      bottomGraphOpen: true,
      detachedPanes: { ...INITIAL_DETACHED_PANE_STATE },
    });
  });

  afterEach(() => {
    setDetachedWindowBridgeForTests({
      create: null,
      emitTo: null,
      getByLabel: null,
      listen: null,
    });
  });

  it("creates each allowlisted pane with a native label and route options", async () => {
    const createdWindows: Array<{
      label: string;
      options: DetachedPaneWindowOptions;
      window: TestNativeWindow;
    }> = [];
    const emitted: Array<{ target: string; event: string; payload: unknown }> = [];

    setDetachedWindowBridgeForTests({
      create: (label, options) => {
        const window = testNativeWindow(label);
        createdWindows.push({ label, options, window });
        return window;
      },
      emitTo: async (target, event, payload) => {
        emitted.push({ target, event, payload });
      },
      getByLabel: async () => null,
      listen: async () => () => undefined,
    });

    for (const paneId of Object.keys(DETACHED_PANE_LABELS) as DetachedPaneId[]) {
      const result = await openDetachedPane(paneId);

      expect(result).toEqual({
        pane_id: paneId,
        label: DETACHED_PANE_LABELS[paneId],
        route: DETACHED_PANE_WINDOW_OPTIONS[paneId].url,
        created: true,
      });
    }

    expect(createdWindows).toHaveLength(4);
    expect(createdWindows.map((entry) => entry.label)).toEqual([
      "detached-graph",
      "detached-inspector",
      "detached-evidence",
      "detached-timeline",
    ]);
    expect(createdWindows[0].options).toEqual(DETACHED_GRAPH_WINDOW_OPTIONS);
    expect(createdWindows.map((entry) => entry.options)).toEqual(
      Object.values(DETACHED_PANE_WINDOW_OPTIONS),
    );
    expect(createdWindows.map((entry) => entry.window.focusCalls)).toEqual([
      ["detached-graph"],
      ["detached-inspector"],
      ["detached-evidence"],
      ["detached-timeline"],
    ]);
    expect(emitted).toEqual(
      (Object.keys(DETACHED_PANE_LABELS) as DetachedPaneId[]).map((paneId) => ({
        target: "main",
        event: "detached_pane_opened",
        payload: {
          pane_id: paneId,
          label: DETACHED_PANE_LABELS[paneId],
        },
      })),
    );
  });

  it("focuses an existing detached-graph window instead of creating a duplicate", async () => {
    const existingWindow = testNativeWindow("detached-graph");
    let createCalls = 0;

    setDetachedWindowBridgeForTests({
      create: () => {
        createCalls += 1;
        return testNativeWindow("detached-graph");
      },
      emitTo: async () => undefined,
      getByLabel: async (label) =>
        label === "detached-graph" ? existingWindow : null,
      listen: async () => () => undefined,
    });

    const result = await openDetachedPane("graph");

    expect(result.created).toBe(false);
    expect(createCalls).toBe(0);
    expect(existingWindow.showCalls).toEqual(["detached-graph"]);
    expect(existingWindow.focusCalls).toEqual(["detached-graph"]);
  });

  it("uses existing focus behavior when drag-out requests an already detached graph", async () => {
    const existingWindow = testNativeWindow("detached-graph");
    let createCalls = 0;

    setDetachedWindowBridgeForTests({
      create: () => {
        createCalls += 1;
        return testNativeWindow("detached-graph");
      },
      emitTo: async () => undefined,
      getByLabel: async (label) =>
        label === "detached-graph" ? existingWindow : null,
      listen: async () => () => undefined,
    });

    const detached = await completePaneDragOutDetach({
      dockZoneRect: {
        bottom: 240,
        left: 80,
        right: 720,
        top: 120,
      },
      onDetach: openDetachedPane,
      paneId: "graph",
      releasePoint: { clientX: 260, clientY: 64 },
      startPoint: { clientX: 260, clientY: 146 },
    });

    expect(detached).toBe(true);
    expect(createCalls).toBe(0);
    expect(existingWindow.showCalls).toEqual(["detached-graph"]);
    expect(existingWindow.focusCalls).toEqual(["detached-graph"]);
  });

  it("closes detached-graph through the native handle and emits the re-dock lifecycle", async () => {
    const existingWindow = testNativeWindow("detached-graph");
    const emitted: Array<{ event: string; payload: unknown }> = [];

    setDetachedWindowBridgeForTests({
      create: () => testNativeWindow("detached-graph"),
      emitTo: async (_target, event, payload) => {
        emitted.push({ event, payload });
      },
      getByLabel: async (label) =>
        label === "detached-graph" ? existingWindow : null,
      listen: async () => () => undefined,
    });

    const result = await closeDetachedPane("graph");

    expect(result.closed).toBe(true);
    expect(existingWindow.closeCalls).toEqual(["detached-graph"]);
    expect(emitted).toEqual([
      {
        event: "detached_pane_closed",
        payload: {
          pane_id: "graph",
          label: "detached-graph",
        },
      },
    ]);
  });

  it("updates graph dock state when the native close lifecycle event arrives", async () => {
    const lifecycleListeners: Record<
      string,
      TestListener<DetachedPaneLifecyclePayload>
    > = {};

    useUiStore.getState().setDetachedPaneOpen("graph", true);
    useUiStore.getState().setBottomGraphOpen(false);

    setDetachedWindowBridgeForTests({
      create: () => testNativeWindow("detached-graph"),
      emitTo: async () => undefined,
      getByLabel: async () => null,
      listen: async (event, handler) => {
        lifecycleListeners[event] =
          handler as TestListener<DetachedPaneLifecyclePayload>;
        return () => {
          delete lifecycleListeners[event];
        };
      },
    });

    const unlisten = await subscribeDetachedPaneLifecycle(
      applyDetachedPaneLifecycleEvent,
    );

    lifecycleListeners.detached_pane_closed?.({
      payload: {
        pane_id: "graph",
        label: "detached-graph",
      },
    });

    expect(useUiStore.getState().detachedPanes.graph).toBe(false);
    expect(useUiStore.getState().bottomGraphOpen).toBe(true);
    unlisten();
  });

  it("tracks non-graph pane lifecycle without reopening the bottom graph pane", async () => {
    const lifecycleListeners: Record<
      string,
      TestListener<DetachedPaneLifecyclePayload>
    > = {};

    useUiStore.getState().setDetachedPaneOpen("timeline", true);
    useUiStore.getState().setBottomGraphOpen(false);

    setDetachedWindowBridgeForTests({
      create: () => testNativeWindow("detached-timeline"),
      emitTo: async () => undefined,
      getByLabel: async () => null,
      listen: async (event, handler) => {
        lifecycleListeners[event] =
          handler as TestListener<DetachedPaneLifecyclePayload>;
        return () => {
          delete lifecycleListeners[event];
        };
      },
    });

    const unlisten = await subscribeDetachedPaneLifecycle(
      applyDetachedPaneLifecycleEvent,
    );

    lifecycleListeners.detached_pane_closed?.({
      payload: {
        pane_id: "timeline",
        label: "detached-timeline",
      },
    });

    expect(useUiStore.getState().detachedPanes.timeline).toBe(false);
    expect(useUiStore.getState().bottomGraphOpen).toBe(false);
    unlisten();
  });
});

function testNativeWindow(label: string): TestNativeWindow {
  return {
    label,
    showCalls: [],
    focusCalls: [],
    closeCalls: [],
    async show() {
      this.showCalls.push(label);
    },
    async setFocus() {
      this.focusCalls.push(label);
    },
    async close() {
      this.closeCalls.push(label);
    },
    async once<T>(event: string, handler: TestListener<T>) {
      if (event === "tauri://created") {
        queueMicrotask(() => handler({ payload: null as T }));
      }
      return () => undefined;
    },
  };
}
