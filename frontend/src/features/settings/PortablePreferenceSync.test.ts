import { beforeEach, describe, expect, it } from "vitest";
import {
  applyPortablePreferencesToUi,
  buildPortablePreferenceSnapshot,
  shouldSavePortablePreferences,
} from "./PortablePreferenceSync";
import { PANE_SIZE_LIMITS } from "../../shared/layout/paneSizing";
import { useUiStore } from "../../stores/uiStore";

describe("portable preference sync", () => {
  beforeEach(() => {
    useUiStore.setState({
      bottomGraphHeight: PANE_SIZE_LIMITS.bottomGraph.defaultSize,
      bottomGraphOpen: true,
      detailDrawerOpen: true,
      detailDrawerWidth: PANE_SIZE_LIMITS.detailDrawer.defaultSize,
      pixelPetEnabled: true,
      pixelPetPosition: null,
      pixelPetSize: "small",
      reducedMotion: false,
      sidebarCollapsed: false,
      sidebarWidth: PANE_SIZE_LIMITS.sidebar.defaultSize,
      theme: "system",
    });
  });

  it("builds only the seven portable preference keys", () => {
    const snapshot = buildPortablePreferenceSnapshot(
      {
        bottomGraphHeight: 300,
        bottomGraphOpen: true,
        detailDrawerOpen: true,
        detailDrawerWidth: 360,
        pixelPetEnabled: false,
        pixelPetPosition: { x: 440, y: 520 },
        pixelPetSize: "medium",
        reducedMotion: true,
        sidebarCollapsed: false,
        sidebarWidth: 240,
        theme: "dark",
      },
      "/graph",
      { height: 900, width: 1200 },
    );

    expect(Object.keys(snapshot).sort()).toEqual([
      "column_widths",
      "graph_viewport_defaults",
      "last_route",
      "layout",
      "pane_sizes",
      "reduced_motion",
      "theme",
    ]);
    expect(snapshot.theme).toBe("dark");
    expect(snapshot.last_route).toBe("/graph");
    expect(snapshot.layout).toMatchObject({
      pixel_pet: {
        enabled: false,
        position: { x: 440, y: 520 },
        size: "medium",
      },
    });
    expect(JSON.stringify(snapshot)).not.toMatch(
      /finding|alert|incident|evidence|raw_packet|token|credential/u,
    );
  });

  it("applies valid portable preferences into small UI state", () => {
    const route = applyPortablePreferencesToUi(
      {
        column_widths: {},
        graph_viewport_defaults: { layout: "force", x: 0, y: 0, zoom: 1 },
        last_route: "/settings",
        layout: {
          bottom_graph_open: false,
          detail_drawer_open: false,
          pixel_pet: {
            enabled: false,
            position: { x: 500, y: 360 },
            size: "medium",
          },
          sidebar_collapsed: true,
        },
        pane_sizes: {
          horizontal: { content: 50, detail_drawer: 25, sidebar: 25 },
          vertical: { bottom_graph: 30, content: 70 },
        },
        reduced_motion: true,
        theme: "light",
      },
      { height: 1000, width: 1000 },
    );

    const state = useUiStore.getState();
    expect(route).toBe("/settings");
    expect(state.theme).toBe("light");
    expect(state.reducedMotion).toBe(true);
    expect(state.sidebarCollapsed).toBe(true);
    expect(state.detailDrawerOpen).toBe(false);
    expect(state.bottomGraphOpen).toBe(false);
    expect(state.pixelPetEnabled).toBe(false);
    expect(state.pixelPetSize).toBe("medium");
    expect(state.pixelPetPosition).toEqual({ x: 500, y: 360 });
    expect(state.sidebarWidth).toBe(250);
    expect(state.detailDrawerWidth).toBe(280);
    expect(state.bottomGraphHeight).toBe(300);
  });

  it("does not save until portable preferences are hydrated", () => {
    expect(shouldSavePortablePreferences(true, false, false)).toBe(false);
    expect(shouldSavePortablePreferences(false, true, false)).toBe(false);
    expect(shouldSavePortablePreferences(true, true, true)).toBe(false);
    expect(shouldSavePortablePreferences(true, true, false)).toBe(true);
  });
});
