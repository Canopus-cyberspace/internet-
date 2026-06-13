import { Outlet } from "@tanstack/react-router";
import {
  useCallback,
  type CSSProperties,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from "react";
import { BottomGraphPane } from "./BottomGraphPane";
import { DetailDrawer } from "./DetailDrawer";
import { NavigationTree } from "./NavigationTree";
import { StatusStrip } from "./StatusStrip";
import { TopToolbar } from "./TopToolbar";
import { PortablePreferenceSync } from "../../features/settings/PortablePreferenceSync";
import { useUiStore } from "../../stores/uiStore";
import { PixelPet } from "../../components/pet/PixelPet";
import { ParticleBackground } from "../ambient/ParticleBackground";
import {
  paneSizeFromDrag,
  PANE_SIZE_LIMITS,
  type PaneSizeLimits,
} from "./paneSizing";
import {
  useDetachedPaneLifecycle,
  useDetachedPaneSnapshotPublisher,
} from "./useDetachedPaneWindows";

export function MainShell() {
  useDetachedPaneLifecycle();
  useDetachedPaneSnapshotPublisher();
  const sidebarCollapsed = useUiStore((state) => state.sidebarCollapsed);
  const bottomGraphOpen = useUiStore((state) => state.bottomGraphOpen);
  const detailDrawerOpen = useUiStore((state) => state.detailDrawerOpen);
  const sidebarWidth = useUiStore((state) => state.sidebarWidth);
  const detailDrawerWidth = useUiStore((state) => state.detailDrawerWidth);
  const bottomGraphHeight = useUiStore((state) => state.bottomGraphHeight);
  const setSidebarWidth = useUiStore((state) => state.setSidebarWidth);
  const setDetailDrawerWidth = useUiStore((state) => state.setDetailDrawerWidth);
  const setBottomGraphHeight = useUiStore((state) => state.setBottomGraphHeight);

  const startSidebarResize = useDragResize({
    initialValue: sidebarWidth,
    limits: PANE_SIZE_LIMITS.sidebar,
    onChange: setSidebarWidth,
    orientation: "vertical",
    reverse: false,
  });
  const startDetailResize = useDragResize({
    initialValue: detailDrawerWidth,
    limits: PANE_SIZE_LIMITS.detailDrawer,
    onChange: setDetailDrawerWidth,
    orientation: "vertical",
    reverse: true,
  });
  const startBottomResize = useDragResize({
    initialValue: bottomGraphHeight,
    limits: PANE_SIZE_LIMITS.bottomGraph,
    onChange: setBottomGraphHeight,
    orientation: "horizontal",
    reverse: true,
  });

  const shellStyle = {
    "--layout-sidebar-width": `${sidebarWidth}px`,
    "--layout-drawer-width": `${detailDrawerWidth}px`,
  } as CSSProperties;
  const mainPaneStyle = {
    "--layout-bottom-pane-height": `${bottomGraphHeight}px`,
  } as CSSProperties;

  return (
    <div className="app-frame">
      <PortablePreferenceSync />
      <ParticleBackground />
      <TopToolbar />
      <div
        className="workbench"
        data-sidebar-collapsed={sidebarCollapsed ? "true" : "false"}
        data-detail-open={detailDrawerOpen ? "true" : "false"}
        style={shellStyle}
      >
        <NavigationTree />
        <ResizeHandle
          ariaLabel="Resize navigation pane"
          className="sidebar-resize-handle"
          disabled={sidebarCollapsed}
          orientation="vertical"
          value={sidebarCollapsed ? 48 : sidebarWidth}
          valueMax={PANE_SIZE_LIMITS.sidebar.max}
          valueMin={PANE_SIZE_LIMITS.sidebar.min}
          onKeyStep={(delta) => setSidebarWidth(sidebarWidth + delta)}
          onPointerDown={startSidebarResize}
        />
        <main
          className="main-pane"
          data-graph-open={bottomGraphOpen ? "true" : "false"}
          style={mainPaneStyle}
        >
          <section className="content-pane" aria-label="Main content">
            <Outlet />
          </section>
          {bottomGraphOpen ? (
            <>
              <ResizeHandle
                ariaLabel="Resize bottom graph pane"
                className="bottom-resize-handle"
                orientation="horizontal"
                value={bottomGraphHeight}
                valueMax={PANE_SIZE_LIMITS.bottomGraph.max}
                valueMin={PANE_SIZE_LIMITS.bottomGraph.min}
                onKeyStep={(delta) => setBottomGraphHeight(bottomGraphHeight + delta)}
                onPointerDown={startBottomResize}
              />
              <BottomGraphPane />
            </>
          ) : null}
        </main>
        {detailDrawerOpen ? (
          <>
            <ResizeHandle
              ariaLabel="Resize detail drawer"
              className="detail-resize-handle"
              orientation="vertical"
              value={detailDrawerWidth}
              valueMax={PANE_SIZE_LIMITS.detailDrawer.max}
              valueMin={PANE_SIZE_LIMITS.detailDrawer.min}
              onKeyStep={(delta) => setDetailDrawerWidth(detailDrawerWidth - delta)}
              onPointerDown={startDetailResize}
            />
            <DetailDrawer />
          </>
        ) : null}
      </div>
      <StatusStrip />
      <PixelPet />
    </div>
  );
}

interface DragResizeOptions {
  readonly initialValue: number;
  readonly limits: PaneSizeLimits;
  readonly onChange: (value: number) => void;
  readonly orientation: "horizontal" | "vertical";
  readonly reverse: boolean;
}

function useDragResize({
  initialValue,
  limits,
  onChange,
  orientation,
  reverse,
}: DragResizeOptions) {
  return useCallback(
    (event: ReactPointerEvent<HTMLDivElement>) => {
      if (event.button !== 0) {
        return;
      }
      event.preventDefault();
      const target = event.currentTarget;
      const pointerId = event.pointerId;
      target.setPointerCapture(pointerId);
      document.documentElement.dataset.paneResizing = orientation;
      const startPoint = orientation === "vertical" ? event.clientX : event.clientY;
      const onPointerMove = (moveEvent: PointerEvent) => {
        moveEvent.preventDefault();
        const currentPoint =
          orientation === "vertical" ? moveEvent.clientX : moveEvent.clientY;
        onChange(
          paneSizeFromDrag({
            currentPoint,
            limits,
            reverse,
            startPoint,
            startSize: initialValue,
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
    [initialValue, limits, onChange, orientation, reverse],
  );
}

interface ResizeHandleProps {
  readonly ariaLabel: string;
  readonly className: string;
  readonly disabled?: boolean;
  readonly onKeyStep: (delta: number) => void;
  readonly onPointerDown: (event: ReactPointerEvent<HTMLDivElement>) => void;
  readonly orientation: "horizontal" | "vertical";
  readonly value: number;
  readonly valueMax: number;
  readonly valueMin: number;
}

function ResizeHandle({
  ariaLabel,
  className,
  disabled = false,
  onKeyStep,
  onPointerDown,
  orientation,
  value,
  valueMax,
  valueMin,
}: ResizeHandleProps) {
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (disabled) {
      return;
    }
    if (orientation === "vertical" && event.key === "ArrowLeft") {
      event.preventDefault();
      onKeyStep(-16);
    }
    if (orientation === "vertical" && event.key === "ArrowRight") {
      event.preventDefault();
      onKeyStep(16);
    }
    if (orientation === "horizontal" && event.key === "ArrowUp") {
      event.preventDefault();
      onKeyStep(16);
    }
    if (orientation === "horizontal" && event.key === "ArrowDown") {
      event.preventDefault();
      onKeyStep(-16);
    }
  };

  return (
    <div
      aria-disabled={disabled ? "true" : "false"}
      aria-label={ariaLabel}
      aria-orientation={orientation}
      aria-valuemax={valueMax}
      aria-valuemin={valueMin}
      aria-valuenow={value}
      className={`pane-resize-handle ${className}`}
      role="separator"
      tabIndex={disabled ? -1 : 0}
      onKeyDown={onKeyDown}
      onPointerDown={disabled ? undefined : onPointerDown}
    />
  );
}
