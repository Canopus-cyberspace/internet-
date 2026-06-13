import { describe, expect, it, vi } from "vitest";
import {
  addPaneDragOutWindowListeners,
  capturePaneDragOutPointer,
  completePaneDragOutDetach,
  hasExceededDragOutThreshold,
  isPointInsideDockZone,
  releasePaneDragOutPointerCapture,
  shouldDetachPaneFromDragOut,
  type DockZoneRect,
  type PaneDragOutWindowListeners,
} from "./usePaneDragOutDetach";

const dockZone: DockZoneRect = {
  bottom: 220,
  left: 40,
  right: 360,
  top: 120,
};

describe("pane drag-out detach decisions", () => {
  it("does not detach when the drag stays below the threshold", async () => {
    const onDetach = vi.fn();

    const detached = await completePaneDragOutDetach({
      dockZoneRect: dockZone,
      onDetach,
      paneId: "graph",
      releasePoint: { clientX: 363, clientY: 129 },
      startPoint: { clientX: 352, clientY: 128 },
    });

    expect(detached).toBe(false);
    expect(onDetach).not.toHaveBeenCalled();
  });

  it("calls the detach action for graph when released outside the dock zone", async () => {
    const onDetach = vi.fn();

    const detached = await completePaneDragOutDetach({
      dockZoneRect: dockZone,
      onDetach,
      paneId: "graph",
      releasePoint: { clientX: 220, clientY: 72 },
      startPoint: { clientX: 220, clientY: 144 },
    });

    expect(detached).toBe(true);
    expect(onDetach).toHaveBeenCalledTimes(1);
    expect(onDetach).toHaveBeenCalledWith("graph");
  });

  it("cancels detach when released inside the dock zone", () => {
    expect(
      shouldDetachPaneFromDragOut({
        dockZoneRect: dockZone,
        releasePoint: { clientX: 270, clientY: 180 },
        startPoint: { clientX: 90, clientY: 130 },
      }),
    ).toBe(false);
  });

  it("uses the dock-zone boundary and movement threshold independently", () => {
    expect(
      isPointInsideDockZone({ clientX: 40, clientY: 120 }, dockZone),
    ).toBe(true);
    expect(
      isPointInsideDockZone({ clientX: 39, clientY: 120 }, dockZone),
    ).toBe(false);
    expect(
      hasExceededDragOutThreshold(
        { clientX: 10, clientY: 10 },
        { clientX: 20, clientY: 20 },
      ),
    ).toBe(false);
    expect(
      hasExceededDragOutThreshold(
        { clientX: 10, clientY: 10 },
        { clientX: 30, clientY: 10 },
      ),
    ).toBe(true);
  });

  it("captures the pointer and releases it during cleanup", () => {
    const target = {
      hasPointerCapture: vi.fn(() => true),
      releasePointerCapture: vi.fn(),
      setPointerCapture: vi.fn(),
    };

    capturePaneDragOutPointer(target, 7);
    releasePaneDragOutPointerCapture(target, 7);

    expect(target.setPointerCapture).toHaveBeenCalledWith(7);
    expect(target.hasPointerCapture).toHaveBeenCalledWith(7);
    expect(target.releasePointerCapture).toHaveBeenCalledWith(7);
  });

  it("registers and removes the window listeners used for drag-out tracking", () => {
    const eventTarget = {
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    };
    const listeners: PaneDragOutWindowListeners = {
      blur: vi.fn(),
      pointercancel: vi.fn(),
      pointermove: vi.fn(),
      pointerup: vi.fn(),
    };

    const cleanup = addPaneDragOutWindowListeners(listeners, eventTarget);
    cleanup();

    expect(eventTarget.addEventListener.mock.calls.map(([event]) => event)).toEqual([
      "pointermove",
      "pointerup",
      "pointercancel",
      "blur",
    ]);
    expect(eventTarget.removeEventListener.mock.calls).toEqual(
      eventTarget.addEventListener.mock.calls,
    );
  });
});
