import { useCallback, useEffect, useState } from "react";
import {
  isDetachedSnapshotPaneId,
  publishDetachedPaneSnapshot,
  requestDetachedPaneSnapshot,
  subscribeDetachedPaneSnapshot,
  subscribeDetachedPaneSnapshotRequests,
  type DetachedEntitySnapshot,
  type DetachedPaneSnapshotPayload,
} from "../../bridge/detachedPaneSnapshots";
import {
  closeDetachedPane,
  DETACHED_PANE_LABELS,
  openDetachedPane,
  subscribeDetachedPaneLifecycle,
  type DetachedPaneLifecycleEvent,
  type DetachedPaneId,
} from "../../bridge/detachedWindows";
import { useSelectionStore } from "../../stores/selectionStore";
import { useUiStore } from "../../stores/uiStore";

export function useDetachedPaneLifecycle() {
  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | null = null;

    void subscribeDetachedPaneLifecycle((event) => {
      if (!active) {
        return;
      }
      applyDetachedPaneLifecycleEvent(event);
    })
      .then((unsubscribe) => {
        if (!active) {
          unsubscribe();
          return;
        }
        unlisten = unsubscribe;
      })
      .catch(() => {
        unlisten = null;
      });

    return () => {
      active = false;
      unlisten?.();
    };
  }, []);
}

export function useDetachedPaneSnapshotPublisher() {
  const selectedEntity = useSelectionStore((state) => state.selectedEntity);
  const detachedPanes = useUiStore((state) => state.detachedPanes);

  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | null = null;

    void subscribeDetachedPaneSnapshotRequests((request) => {
      if (!active) {
        return;
      }
      void publishDetachedPaneSnapshot(
        request.pane_id,
        useSelectionStore.getState().selectedEntity,
      );
    })
      .then((unsubscribe) => {
        if (!active) {
          unsubscribe();
          return;
        }
        unlisten = unsubscribe;
      })
      .catch(() => {
        unlisten = null;
      });

    return () => {
      active = false;
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    for (const paneId of Object.keys(detachedPanes) as DetachedPaneId[]) {
      if (detachedPanes[paneId] && isDetachedSnapshotPaneId(paneId)) {
        void publishDetachedPaneSnapshot(paneId, selectedEntity);
      }
    }
  }, [
    selectedEntity,
    detachedPanes.inspector,
    detachedPanes.evidence,
    detachedPanes.timeline,
  ]);
}

export function useDetachedPaneSnapshot(paneId: DetachedPaneId) {
  const [snapshot, setSnapshot] = useState<DetachedEntitySnapshot | null>(null);

  useEffect(() => {
    if (!isDetachedSnapshotPaneId(paneId)) {
      return undefined;
    }

    let active = true;
    let unlisten: (() => void) | null = null;

    void subscribeDetachedPaneSnapshot((payload) => {
      if (!active || payload.pane_id !== paneId) {
        return;
      }
      setSnapshot(payload.selected_entity);
    })
      .then((unsubscribe) => {
        if (!active) {
          unsubscribe();
          return;
        }
        unlisten = unsubscribe;
        void requestDetachedPaneSnapshot(paneId);
      })
      .catch(() => {
        unlisten = null;
      });

    return () => {
      active = false;
      unlisten?.();
    };
  }, [paneId]);

  return snapshot;
}

export function useDetachedPaneActions() {
  const setBottomGraphOpen = useUiStore((state) => state.setBottomGraphOpen);
  const setDetachedPaneOpen = useUiStore((state) => state.setDetachedPaneOpen);
  const selectedEntity = useSelectionStore((state) => state.selectedEntity);

  const detachPane = useCallback(
    async (paneId: DetachedPaneId) => {
      await openDetachedPane(paneId);
      setDetachedPaneOpen(paneId, true);
      if (paneId === "graph") {
        setBottomGraphOpen(false);
      }
      if (isDetachedSnapshotPaneId(paneId)) {
        await publishDetachedPaneSnapshot(paneId, selectedEntity);
      }
    },
    [selectedEntity, setBottomGraphOpen, setDetachedPaneOpen],
  );

  const restorePane = useCallback(
    async (paneId: DetachedPaneId) => {
      await closeDetachedPane(paneId);
      setDetachedPaneOpen(paneId, false);
      restoreDockedPane(paneId, setBottomGraphOpen);
    },
    [setBottomGraphOpen, setDetachedPaneOpen],
  );

  return { detachPane, restorePane };
}

export function applyDetachedPaneSnapshotEvent(
  payload: DetachedPaneSnapshotPayload,
) {
  if (
    isDetachedSnapshotPaneId(payload.pane_id) &&
    DETACHED_PANE_LABELS[payload.pane_id] === payload.label
  ) {
    return payload.selected_entity;
  }
  return null;
}

export function applyDetachedPaneLifecycleEvent(
  event: DetachedPaneLifecycleEvent,
) {
  const open = event.state === "opened";
  const state = useUiStore.getState();
  state.setDetachedPaneOpen(event.pane_id, open);
  if (!open) {
    restoreDockedPane(event.pane_id, state.setBottomGraphOpen);
  }
}

function restoreDockedPane(
  paneId: DetachedPaneId,
  setBottomGraphOpen: (open: boolean) => void,
) {
  if (paneId === "graph") {
    setBottomGraphOpen(true);
  }
}
