import { GitBranch, GripHorizontal, Maximize2, SlidersHorizontal } from "lucide-react";
import { useRef, type PointerEventHandler } from "react";
import { graphViews } from "../../app/navigation";
import { useUiStore } from "../../stores/uiStore";
import { useDetachedPaneActions } from "./useDetachedPaneWindows";
import { usePaneDragOutDetach } from "./usePaneDragOutDetach";

interface BottomGraphPaneHeaderProps {
  readonly dragOutHandleProps: {
    readonly "data-drag-out-detach-handle": string;
    readonly onPointerDown: PointerEventHandler<HTMLElement>;
    readonly title?: string;
  };
  readonly graphDetached: boolean;
  readonly onDetachGraph: () => void;
}

export function BottomGraphPane() {
  const graphDetached = useUiStore((state) => state.detachedPanes.graph);
  const { detachPane } = useDetachedPaneActions();
  const dockZoneRef = useRef<HTMLElement | null>(null);
  const dragOutDetach = usePaneDragOutDetach({
    disabled: graphDetached,
    dockZoneRef,
    onDetach: detachPane,
    paneId: "graph",
  });

  return (
    <section
      ref={dockZoneRef}
      className="bottom-graph-pane"
      aria-label="Graph view model preview"
      data-drag-out-state={dragOutDetach.phase}
      data-pane-dock-zone="true"
    >
      <BottomGraphPaneHeader
        dragOutHandleProps={dragOutDetach.handleProps}
        graphDetached={graphDetached}
        onDetachGraph={() => {
          void detachPane("graph");
        }}
      />
      {dragOutDetach.preview ? (
        <div
          className="pane-detach-ghost"
          data-detach-target={
            dragOutDetach.preview.detachTarget &&
            dragOutDetach.preview.thresholdExceeded
              ? "true"
              : "false"
          }
          style={dragOutDetach.previewStyle}
          aria-hidden="true"
        >
          <strong>GraphViewModel</strong>
          <span>Topology / attack path / dependency view</span>
        </div>
      ) : null}
      <div className="graph-strip scroll-region">
        <div className="graph-preview scroll-region" aria-hidden="true">
          <span className="graph-node node-process">Process</span>
          <span className="graph-edge" />
          <span className="graph-node node-domain">Domain</span>
          <span className="graph-edge warning" />
          <span className="graph-node node-incident">Incident</span>
          <span className="graph-edge" />
          <span className="graph-node node-response">Plan</span>
        </div>
        <div className="graph-view-list">
          {graphViews.map((view) => (
            <button type="button" key={view} className="graph-view-button">
              <GitBranch size={13} aria-hidden="true" />
              <span>{view}</span>
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}

export function BottomGraphPaneHeader({
  dragOutHandleProps,
  graphDetached,
  onDetachGraph,
}: BottomGraphPaneHeaderProps) {
  return (
    <div className="pane-header pane-detach-header">
      <div>
        <span
          className="pane-detach-grip"
          aria-label="Drag graph pane out"
          role="presentation"
          {...dragOutHandleProps}
        >
          <GripHorizontal size={14} />
        </span>
        <strong>GraphViewModel</strong>
        <span>Topology / attack path / dependency view</span>
      </div>
      <div className="pane-actions">
        <button type="button" className="icon-button" title="Graph filters">
          <SlidersHorizontal size={14} aria-hidden="true" />
        </button>
        <button
          type="button"
          className="icon-button"
          title={graphDetached ? "Focus detached graph" : "Detach graph"}
          aria-pressed={graphDetached ? "true" : "false"}
          onClick={onDetachGraph}
        >
          <Maximize2 size={14} aria-hidden="true" />
        </button>
      </div>
    </div>
  );
}
