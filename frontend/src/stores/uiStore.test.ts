import { beforeEach, describe, expect, it } from "vitest";
import { PANE_SIZE_LIMITS } from "../shared/layout/paneSizing";
import { INITIAL_DETACHED_PANE_STATE, useUiStore } from "./uiStore";

describe("uiStore pane layout preferences", () => {
  beforeEach(() => {
    useUiStore.setState({
      bottomGraphHeight: PANE_SIZE_LIMITS.bottomGraph.defaultSize,
      detachedPanes: { ...INITIAL_DETACHED_PANE_STATE },
      detailDrawerWidth: PANE_SIZE_LIMITS.detailDrawer.defaultSize,
      pixelPetEnabled: true,
      pixelPetPosition: null,
      pixelPetSize: "small",
      sidebarWidth: PANE_SIZE_LIMITS.sidebar.defaultSize,
    });
  });

  it("stores only clamped sidebar widths", () => {
    useUiStore.getState().setSidebarWidth(90);
    expect(useUiStore.getState().sidebarWidth).toBe(PANE_SIZE_LIMITS.sidebar.min);

    useUiStore.getState().setSidebarWidth(900);
    expect(useUiStore.getState().sidebarWidth).toBe(PANE_SIZE_LIMITS.sidebar.max);
  });

  it("stores only clamped detail drawer widths", () => {
    useUiStore.getState().setDetailDrawerWidth(120);
    expect(useUiStore.getState().detailDrawerWidth).toBe(
      PANE_SIZE_LIMITS.detailDrawer.min,
    );

    useUiStore.getState().setDetailDrawerWidth(900);
    expect(useUiStore.getState().detailDrawerWidth).toBe(
      PANE_SIZE_LIMITS.detailDrawer.max,
    );
  });

  it("stores only clamped bottom graph heights", () => {
    useUiStore.getState().setBottomGraphHeight(40);
    expect(useUiStore.getState().bottomGraphHeight).toBe(
      PANE_SIZE_LIMITS.bottomGraph.min,
    );

    useUiStore.getState().setBottomGraphHeight(900);
    expect(useUiStore.getState().bottomGraphHeight).toBe(
      PANE_SIZE_LIMITS.bottomGraph.max,
    );
  });

  it("stores detached pane lifecycle state as UI state", () => {
    useUiStore.getState().setDetachedPaneOpen("graph", true);
    expect(useUiStore.getState().detachedPanes.graph).toBe(true);

    useUiStore.getState().setDetachedPaneOpen("graph", false);
    expect(useUiStore.getState().detachedPanes.graph).toBe(false);

    useUiStore.getState().setDetachedPaneOpen("evidence", true);
    expect(useUiStore.getState().detachedPanes.evidence).toBe(true);

    useUiStore.getState().setDetachedPaneOpen("timeline", true);
    expect(useUiStore.getState().detachedPanes.timeline).toBe(true);
  });

  it("stores bounded pixel companion UI preferences", () => {
    useUiStore.getState().setPixelPetEnabled(false);
    useUiStore.getState().setPixelPetSize("medium");
    useUiStore.getState().setPixelPetPosition({ x: -20, y: 12_345 });

    expect(useUiStore.getState().pixelPetEnabled).toBe(false);
    expect(useUiStore.getState().pixelPetSize).toBe("medium");
    expect(useUiStore.getState().pixelPetPosition).toEqual({
      x: 0,
      y: 10_000,
    });

    useUiStore.getState().setPixelPetPosition(null);
    expect(useUiStore.getState().pixelPetPosition).toBeNull();
  });
});
