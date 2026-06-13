import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type PointerEvent as ReactPointerEvent,
  type RefObject,
} from "react";
import type { DetachedPaneId } from "../../bridge/detachedWindows";

export const PANE_DRAG_OUT_THRESHOLD_PX = 18;
export const PANE_DRAG_OUT_LONG_PRESS_MS = 260;

export interface ClientPoint {
  readonly clientX: number;
  readonly clientY: number;
}

export interface DockZoneRect {
  readonly left: number;
  readonly top: number;
  readonly right: number;
  readonly bottom: number;
}

export interface PaneDragOutPreview {
  readonly clientX: number;
  readonly clientY: number;
  readonly detachTarget: boolean;
  readonly thresholdExceeded: boolean;
}

export type PaneDragOutPhase = "idle" | "tracking" | "preview";

interface PaneDragOutDetachOptions {
  readonly disabled?: boolean;
  readonly dockZoneRef: RefObject<HTMLElement | null>;
  readonly onDetach: (paneId: DetachedPaneId) => unknown;
  readonly paneId: DetachedPaneId;
}

interface PaneDragOutDetachCompletion {
  readonly dockZoneRect: DockZoneRect;
  readonly onDetach: (paneId: DetachedPaneId) => unknown;
  readonly paneId: DetachedPaneId;
  readonly releasePoint: ClientPoint;
  readonly startPoint: ClientPoint;
  readonly threshold?: number;
}

interface ActiveGesture {
  readonly dockZoneRect: DockZoneRect;
  readonly pointerId: number;
  readonly startPoint: ClientPoint;
  readonly target: HTMLElement;
  currentPoint: ClientPoint;
  previewActive: boolean;
  thresholdExceeded: boolean;
}

export interface PaneDragOutWindowListeners {
  readonly blur: EventListener;
  readonly pointercancel: EventListener;
  readonly pointermove: EventListener;
  readonly pointerup: EventListener;
}

interface PaneDragOutEventTarget {
  readonly addEventListener: Window["addEventListener"];
  readonly removeEventListener: Window["removeEventListener"];
}

export function usePaneDragOutDetach({
  disabled = false,
  dockZoneRef,
  onDetach,
  paneId,
}: PaneDragOutDetachOptions) {
  const [phase, setPhase] = useState<PaneDragOutPhase>("idle");
  const [preview, setPreview] = useState<PaneDragOutPreview | null>(null);
  const gestureRef = useRef<ActiveGesture | null>(null);
  const cleanupRef = useRef<(() => void) | null>(null);
  const longPressTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearLongPressTimer = useCallback(() => {
    if (longPressTimerRef.current) {
      clearTimeout(longPressTimerRef.current);
      longPressTimerRef.current = null;
    }
  }, []);

  const stopTracking = useCallback(() => {
    clearLongPressTimer();
    cleanupRef.current?.();
    cleanupRef.current = null;
    gestureRef.current = null;
    setPhase("idle");
    setPreview(null);
    delete document.documentElement.dataset.paneDragOut;
  }, [clearLongPressTimer]);

  useEffect(() => stopTracking, [stopTracking]);

  useEffect(() => {
    if (disabled) {
      stopTracking();
    }
  }, [disabled, stopTracking]);

  const updatePreview = useCallback((gesture: ActiveGesture, point: ClientPoint) => {
    gesture.previewActive = true;
    gesture.currentPoint = point;
    setPhase("preview");
    setPreview({
      ...point,
      detachTarget: !isPointInsideDockZone(point, gesture.dockZoneRect),
      thresholdExceeded: gesture.thresholdExceeded,
    });
  }, []);

  const startTracking = useCallback(
    (event: ReactPointerEvent<HTMLElement>) => {
      if (
        disabled ||
        event.button !== 0 ||
        document.documentElement.dataset.paneResizing ||
        isInteractiveDragStart(event.target)
      ) {
        return;
      }

      const target = event.currentTarget;
      const dockZoneRect = rectForElement(dockZoneRef.current ?? target);
      const startPoint = pointFromEvent(event);
      const gesture: ActiveGesture = {
        currentPoint: startPoint,
        dockZoneRect,
        pointerId: event.pointerId,
        previewActive: false,
        startPoint,
        target,
        thresholdExceeded: false,
      };

      cleanupRef.current?.();
      gestureRef.current = gesture;
      setPhase("tracking");
      document.documentElement.dataset.paneDragOut = paneId;

      try {
        capturePaneDragOutPointer(target, event.pointerId);
      } catch {
        // Pointer capture is best-effort; window listeners still handle the drag.
      }

      longPressTimerRef.current = setTimeout(() => {
        const activeGesture = gestureRef.current;
        if (!activeGesture || activeGesture.pointerId !== gesture.pointerId) {
          return;
        }
        updatePreview(activeGesture, activeGesture.currentPoint);
      }, PANE_DRAG_OUT_LONG_PRESS_MS);

      const onPointerMove = (moveEvent: PointerEvent) => {
        const activeGesture = gestureRef.current;
        if (!activeGesture || activeGesture.pointerId !== gesture.pointerId) {
          return;
        }

        const currentPoint = pointFromEvent(moveEvent);
        activeGesture.currentPoint = currentPoint;
        if (hasExceededDragOutThreshold(activeGesture.startPoint, currentPoint)) {
          activeGesture.thresholdExceeded = true;
        }

        if (activeGesture.thresholdExceeded || activeGesture.previewActive) {
          moveEvent.preventDefault();
          updatePreview(activeGesture, currentPoint);
        }
      };

      const onPointerUp = (upEvent: PointerEvent) => {
        const activeGesture = gestureRef.current;
        if (!activeGesture || activeGesture.pointerId !== gesture.pointerId) {
          return;
        }
        const releasePoint = pointFromEvent(upEvent);
        const completion = completePaneDragOutDetach({
          dockZoneRect: activeGesture.dockZoneRect,
          onDetach,
          paneId,
          releasePoint,
          startPoint: activeGesture.startPoint,
        });
        stopTracking();
        void completion.catch(() => undefined);
      };

      const onPointerCancel = () => {
        stopTracking();
      };

      const removeWindowListeners = addPaneDragOutWindowListeners({
        blur: onPointerCancel,
        pointercancel: onPointerCancel,
        pointermove: onPointerMove as EventListener,
        pointerup: onPointerUp as EventListener,
      });
      cleanupRef.current = () => {
        releasePaneDragOutPointerCapture(target, event.pointerId);
        removeWindowListeners();
      };
    },
    [disabled, dockZoneRef, onDetach, paneId, stopTracking, updatePreview],
  );

  const previewStyle = useMemo<CSSProperties | undefined>(() => {
    if (!preview) {
      return undefined;
    }
    return {
      left: `${preview.clientX}px`,
      top: `${preview.clientY}px`,
    };
  }, [preview]);

  return {
    handleProps: {
      "data-drag-out-detach-handle": "true",
      onPointerDown: startTracking,
      title: disabled ? undefined : "Drag out to detach pane",
    },
    phase,
    preview,
    previewStyle,
  };
}

export function capturePaneDragOutPointer(
  target: Pick<HTMLElement, "setPointerCapture">,
  pointerId: number,
) {
  target.setPointerCapture(pointerId);
}

export function releasePaneDragOutPointerCapture(
  target: Pick<HTMLElement, "hasPointerCapture" | "releasePointerCapture">,
  pointerId: number,
) {
  try {
    if (target.hasPointerCapture(pointerId)) {
      target.releasePointerCapture(pointerId);
    }
  } catch {
    // Pointer capture may not exist in test or fallback environments.
  }
}

export function addPaneDragOutWindowListeners(
  listeners: PaneDragOutWindowListeners,
  eventTarget: PaneDragOutEventTarget = window,
) {
  eventTarget.addEventListener("pointermove", listeners.pointermove);
  eventTarget.addEventListener("pointerup", listeners.pointerup);
  eventTarget.addEventListener("pointercancel", listeners.pointercancel);
  eventTarget.addEventListener("blur", listeners.blur);

  return () => {
    eventTarget.removeEventListener("pointermove", listeners.pointermove);
    eventTarget.removeEventListener("pointerup", listeners.pointerup);
    eventTarget.removeEventListener("pointercancel", listeners.pointercancel);
    eventTarget.removeEventListener("blur", listeners.blur);
  };
}

export async function completePaneDragOutDetach({
  dockZoneRect,
  onDetach,
  paneId,
  releasePoint,
  startPoint,
  threshold = PANE_DRAG_OUT_THRESHOLD_PX,
}: PaneDragOutDetachCompletion) {
  if (
    shouldDetachPaneFromDragOut({
      dockZoneRect,
      releasePoint,
      startPoint,
      threshold,
    })
  ) {
    await onDetach(paneId);
    return true;
  }

  return false;
}

export function shouldDetachPaneFromDragOut({
  dockZoneRect,
  releasePoint,
  startPoint,
  threshold = PANE_DRAG_OUT_THRESHOLD_PX,
}: {
  readonly dockZoneRect: DockZoneRect;
  readonly releasePoint: ClientPoint;
  readonly startPoint: ClientPoint;
  readonly threshold?: number;
}) {
  return (
    hasExceededDragOutThreshold(startPoint, releasePoint, threshold) &&
    !isPointInsideDockZone(releasePoint, dockZoneRect)
  );
}

export function hasExceededDragOutThreshold(
  startPoint: ClientPoint,
  currentPoint: ClientPoint,
  threshold = PANE_DRAG_OUT_THRESHOLD_PX,
) {
  return (
    Math.hypot(
      currentPoint.clientX - startPoint.clientX,
      currentPoint.clientY - startPoint.clientY,
    ) >= threshold
  );
}

export function isPointInsideDockZone(
  point: ClientPoint,
  dockZoneRect: DockZoneRect,
) {
  return (
    point.clientX >= dockZoneRect.left &&
    point.clientX <= dockZoneRect.right &&
    point.clientY >= dockZoneRect.top &&
    point.clientY <= dockZoneRect.bottom
  );
}

function pointFromEvent(event: Pick<PointerEvent, "clientX" | "clientY">) {
  return {
    clientX: event.clientX,
    clientY: event.clientY,
  };
}

function rectForElement(element: HTMLElement): DockZoneRect {
  const rect = element.getBoundingClientRect();
  return {
    bottom: rect.bottom,
    left: rect.left,
    right: rect.right,
    top: rect.top,
  };
}

function isInteractiveDragStart(target: EventTarget | null) {
  if (typeof Element === "undefined" || !(target instanceof Element)) {
    return false;
  }

  return Boolean(
    target.closest(
      [
        "button",
        "a",
        "input",
        "select",
        "textarea",
        "[contenteditable='true']",
        "[role='button']",
        "[role='separator']",
      ].join(","),
    ),
  );
}
