import {
  useCallback,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
} from "react";
import { clampPaneSize, paneSizeFromDrag, PANE_SIZE_LIMITS } from "./paneSizing";

interface SplitPaneProps {
  primary: ReactNode;
  secondary: ReactNode;
}

export function SplitPane({ primary, secondary }: SplitPaneProps) {
  const [secondaryWidth, setSecondaryWidth] = useState<number>(
    PANE_SIZE_LIMITS.splitSecondary.defaultSize,
  );
  const setClampedSecondaryWidth = useCallback((width: number) => {
    setSecondaryWidth(clampPaneSize(width, PANE_SIZE_LIMITS.splitSecondary));
  }, []);
  const startResize = useCallback(
    (event: ReactPointerEvent<HTMLDivElement>) => {
      if (event.button !== 0) {
        return;
      }
      event.preventDefault();
      const target = event.currentTarget;
      const pointerId = event.pointerId;
      target.setPointerCapture(pointerId);
      document.documentElement.dataset.paneResizing = "vertical";
      const startX = event.clientX;
      const startWidth = secondaryWidth;
      const onPointerMove = (moveEvent: PointerEvent) => {
        moveEvent.preventDefault();
        setClampedSecondaryWidth(
          paneSizeFromDrag({
            currentPoint: moveEvent.clientX,
            limits: PANE_SIZE_LIMITS.splitSecondary,
            reverse: true,
            startPoint: startX,
            startSize: startWidth,
          }),
        );
      };
      const stopResize = () => {
        if (target.hasPointerCapture(pointerId)) {
          target.releasePointerCapture(pointerId);
        }
        delete document.documentElement.dataset.paneResizing;
        window.removeEventListener("pointermove", onPointerMove);
        window.removeEventListener("pointerup", stopResize);
        window.removeEventListener("pointercancel", stopResize);
        window.removeEventListener("blur", stopResize);
      };
      window.addEventListener("pointermove", onPointerMove);
      window.addEventListener("pointerup", stopResize);
      window.addEventListener("pointercancel", stopResize);
      window.addEventListener("blur", stopResize);
    },
    [secondaryWidth, setClampedSecondaryWidth],
  );
  const onHandleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "ArrowLeft") {
      event.preventDefault();
      setClampedSecondaryWidth(secondaryWidth + 16);
    }
    if (event.key === "ArrowRight") {
      event.preventDefault();
      setClampedSecondaryWidth(secondaryWidth - 16);
    }
  };
  const style = {
    "--split-secondary-width": `${secondaryWidth}px`,
  } as CSSProperties;

  return (
    <div className="split-pane" style={style}>
      <section className="split-primary scroll-region">{primary}</section>
      <div
        aria-label="Resize overview split pane"
        aria-orientation="vertical"
        aria-valuemax={PANE_SIZE_LIMITS.splitSecondary.max}
        aria-valuemin={PANE_SIZE_LIMITS.splitSecondary.min}
        aria-valuenow={secondaryWidth}
        className="pane-resize-handle split-resize-handle"
        role="separator"
        tabIndex={0}
        onKeyDown={onHandleKeyDown}
        onPointerDown={startResize}
      />
      <section className="split-secondary scroll-region">{secondary}</section>
    </div>
  );
}
