import { create } from "zustand";
import type { DetachedPaneId } from "../bridge/detachedWindows";
import { clampPaneSize, PANE_SIZE_LIMITS } from "../shared/layout/paneSizing";

export type ThemeMode = "system" | "light" | "dark" | "deep-dark";
export type PixelPetSize = "small" | "medium";

export interface PixelPetPosition {
  readonly x: number;
  readonly y: number;
}

export interface UiStore {
  theme: ThemeMode;
  sidebarCollapsed: boolean;
  detailDrawerOpen: boolean;
  bottomGraphOpen: boolean;
  sidebarWidth: number;
  detailDrawerWidth: number;
  bottomGraphHeight: number;
  detachedPanes: Record<DetachedPaneId, boolean>;
  particlesEnabled: boolean;
  pixelPetEnabled: boolean;
  pixelPetPosition: PixelPetPosition | null;
  pixelPetSize: PixelPetSize;
  reducedMotion: boolean;
  setTheme: (theme: ThemeMode) => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setDetailDrawerOpen: (open: boolean) => void;
  setBottomGraphOpen: (open: boolean) => void;
  setSidebarWidth: (width: number) => void;
  setDetailDrawerWidth: (width: number) => void;
  setBottomGraphHeight: (height: number) => void;
  setDetachedPaneOpen: (paneId: DetachedPaneId, open: boolean) => void;
  setParticlesEnabled: (enabled: boolean) => void;
  setPixelPetEnabled: (enabled: boolean) => void;
  setPixelPetPosition: (position: PixelPetPosition | null) => void;
  setPixelPetSize: (size: PixelPetSize) => void;
  setReducedMotion: (reduced: boolean) => void;
}

export const INITIAL_DETACHED_PANE_STATE: Record<DetachedPaneId, boolean> = {
  graph: false,
  inspector: false,
  evidence: false,
  timeline: false,
};

export const useUiStore = create<UiStore>((set) => ({
  theme: "system",
  sidebarCollapsed: false,
  detailDrawerOpen: true,
  bottomGraphOpen: true,
  sidebarWidth: PANE_SIZE_LIMITS.sidebar.defaultSize,
  detailDrawerWidth: PANE_SIZE_LIMITS.detailDrawer.defaultSize,
  bottomGraphHeight: PANE_SIZE_LIMITS.bottomGraph.defaultSize,
  detachedPanes: { ...INITIAL_DETACHED_PANE_STATE },
  particlesEnabled: true,
  pixelPetEnabled: true,
  pixelPetPosition: null,
  pixelPetSize: "small",
  reducedMotion: false,
  setTheme: (theme) => set({ theme }),
  setSidebarCollapsed: (sidebarCollapsed) => set({ sidebarCollapsed }),
  setDetailDrawerOpen: (detailDrawerOpen) => set({ detailDrawerOpen }),
  setBottomGraphOpen: (bottomGraphOpen) => set({ bottomGraphOpen }),
  setSidebarWidth: (sidebarWidth) =>
    set({ sidebarWidth: clampPaneSize(sidebarWidth, PANE_SIZE_LIMITS.sidebar) }),
  setDetailDrawerWidth: (detailDrawerWidth) =>
    set({
      detailDrawerWidth: clampPaneSize(
        detailDrawerWidth,
        PANE_SIZE_LIMITS.detailDrawer,
      ),
    }),
  setBottomGraphHeight: (bottomGraphHeight) =>
    set({
      bottomGraphHeight: clampPaneSize(
        bottomGraphHeight,
        PANE_SIZE_LIMITS.bottomGraph,
      ),
    }),
  setDetachedPaneOpen: (paneId, open) =>
    set((state) => ({
      detachedPanes: {
        ...state.detachedPanes,
        [paneId]: open,
      },
    })),
  setParticlesEnabled: (particlesEnabled) => set({ particlesEnabled }),
  setPixelPetEnabled: (pixelPetEnabled) => set({ pixelPetEnabled }),
  setPixelPetPosition: (pixelPetPosition) =>
    set((state) => {
      const next = sanitizePixelPetPosition(pixelPetPosition);
      if (
        state.pixelPetPosition?.x === next?.x &&
        state.pixelPetPosition?.y === next?.y
      ) {
        return state;
      }
      return { pixelPetPosition: next };
    }),
  setPixelPetSize: (pixelPetSize) => set({ pixelPetSize }),
  setReducedMotion: (reducedMotion) => set({ reducedMotion }),
}));

function sanitizePixelPetPosition(
  position: PixelPetPosition | null,
): PixelPetPosition | null {
  if (
    !position ||
    !Number.isFinite(position.x) ||
    !Number.isFinite(position.y)
  ) {
    return null;
  }

  return {
    x: Math.round(Math.max(0, Math.min(10_000, position.x))),
    y: Math.round(Math.max(0, Math.min(10_000, position.y))),
  };
}
