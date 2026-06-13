import { useNavigate, useRouterState } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import type { JsonValue } from "../../bridge/dto/common";
import type { PortablePreferencesDto } from "../../bridge/dto/platform";
import { PANE_SIZE_LIMITS } from "../../shared/layout/paneSizing";
import { useUiStore, type ThemeMode, type UiStore } from "../../stores/uiStore";
import {
  usePortablePreferencesQuery,
  useSavePortablePreferencesMutation,
  useSettingsServiceStatusQuery,
} from "./hooks";

const PORTABLE_PROFILE_MODE = "portable-no-retention";
const SAVE_DEBOUNCE_MS = 650;

interface ViewportSize {
  readonly height: number;
  readonly width: number;
}

const DEFAULT_VIEWPORT: ViewportSize = {
  height: 900,
  width: 1440,
};

type RoutePath =
  | "/"
  | "/investigation"
  | "/graph"
  | "/components"
  | "/network"
  | "/response"
  | "/reports"
  | "/settings";

export function PortablePreferenceSync() {
  const serviceStatusQuery = useSettingsServiceStatusQuery();
  const isPortable =
    serviceStatusQuery.data?.profile_mode === PORTABLE_PROFILE_MODE;
  const preferencesQuery = usePortablePreferencesQuery(isPortable);
  const saveMutation = useSavePortablePreferencesMutation();
  const loadedRef = useRef(false);
  const [hydrated, setHydrated] = useState(false);
  const navigate = useNavigate();
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  });

  const theme = useUiStore((state) => state.theme);
  const sidebarCollapsed = useUiStore((state) => state.sidebarCollapsed);
  const detailDrawerOpen = useUiStore((state) => state.detailDrawerOpen);
  const bottomGraphOpen = useUiStore((state) => state.bottomGraphOpen);
  const sidebarWidth = useUiStore((state) => state.sidebarWidth);
  const detailDrawerWidth = useUiStore((state) => state.detailDrawerWidth);
  const bottomGraphHeight = useUiStore((state) => state.bottomGraphHeight);
  const reducedMotion = useUiStore((state) => state.reducedMotion);
  const pixelPetEnabled = useUiStore((state) => state.pixelPetEnabled);
  const pixelPetPosition = useUiStore((state) => state.pixelPetPosition);
  const pixelPetSize = useUiStore((state) => state.pixelPetSize);

  useEffect(() => {
    if (!isPortable) {
      loadedRef.current = false;
      if (hydrated) {
        setHydrated(false);
      }
      return;
    }
    if (loadedRef.current || !preferencesQuery.isSuccess) {
      return;
    }
    loadedRef.current = true;
    const route = applyPortablePreferencesToUi(
      preferencesQuery.data,
      currentViewport(),
    );
    setHydrated(true);
    if (route && route !== pathname) {
      void navigate({ to: route });
    }
  }, [
    hydrated,
    isPortable,
    navigate,
    pathname,
    preferencesQuery.data,
    preferencesQuery.isSuccess,
  ]);

  const snapshot = useMemo(
    () =>
      buildPortablePreferenceSnapshot(
        {
          bottomGraphHeight,
          bottomGraphOpen,
          detailDrawerOpen,
          detailDrawerWidth,
          pixelPetEnabled,
          pixelPetPosition,
          pixelPetSize,
          reducedMotion,
          sidebarCollapsed,
          sidebarWidth,
          theme,
        },
        pathname,
        currentViewport(),
      ),
    [
      bottomGraphHeight,
      bottomGraphOpen,
      detailDrawerOpen,
      detailDrawerWidth,
      pathname,
      pixelPetEnabled,
      pixelPetPosition,
      pixelPetSize,
      reducedMotion,
      sidebarCollapsed,
      sidebarWidth,
      theme,
    ],
  );

  useEffect(() => {
    if (
      !shouldSavePortablePreferences(
        isPortable,
        hydrated,
        saveMutation.isPending,
      )
    ) {
      return;
    }
    const timeout = window.setTimeout(() => {
      saveMutation.mutate(snapshot);
    }, SAVE_DEBOUNCE_MS);
    return () => window.clearTimeout(timeout);
  }, [hydrated, isPortable, saveMutation, snapshot]);

  return null;
}

export function shouldSavePortablePreferences(
  isPortable: boolean,
  hydrated: boolean,
  savePending: boolean,
) {
  return isPortable && hydrated && !savePending;
}

export function buildPortablePreferenceSnapshot(
  state: Pick<
    UiStore,
    | "bottomGraphHeight"
    | "bottomGraphOpen"
    | "detailDrawerOpen"
    | "detailDrawerWidth"
    | "pixelPetEnabled"
    | "pixelPetPosition"
    | "pixelPetSize"
    | "reducedMotion"
    | "sidebarCollapsed"
    | "sidebarWidth"
    | "theme"
  >,
  pathname: string,
  viewport: ViewportSize = DEFAULT_VIEWPORT,
): PortablePreferencesDto {
  const sidebarPixels = state.sidebarCollapsed ? 48 : state.sidebarWidth;
  const detailPixels = state.detailDrawerOpen ? state.detailDrawerWidth : 1;
  const centerPixels = Math.max(1, viewport.width - sidebarPixels - detailPixels);
  const bottomPixels = state.bottomGraphOpen ? state.bottomGraphHeight : 1;
  const mainPixels = Math.max(1, viewport.height - bottomPixels);

  return {
    column_widths: {},
    graph_viewport_defaults: {
      layout: "force",
      x: 0,
      y: 0,
      zoom: 1,
    },
    last_route: safeRoute(pathname) ?? "/",
    layout: {
      bottom_graph_open: state.bottomGraphOpen,
      detail_drawer_open: state.detailDrawerOpen,
      pixel_pet: {
        enabled: state.pixelPetEnabled,
        position: state.pixelPetPosition
          ? {
              x: roundCoordinate(state.pixelPetPosition.x),
              y: roundCoordinate(state.pixelPetPosition.y),
            }
          : null,
        size: state.pixelPetSize,
      },
      sidebar_collapsed: state.sidebarCollapsed,
    },
    pane_sizes: {
      horizontal: percentages({
        content: centerPixels,
        detail_drawer: detailPixels,
        sidebar: sidebarPixels,
      }),
      vertical: percentages({
        bottom_graph: bottomPixels,
        content: mainPixels,
      }),
    },
    reduced_motion: state.reducedMotion,
    theme: state.theme,
  };
}

export function applyPortablePreferencesToUi(
  preferences: PortablePreferencesDto,
  viewport: ViewportSize = DEFAULT_VIEWPORT,
): RoutePath | null {
  const state = useUiStore.getState();
  const theme = asTheme(preferences.theme);
  if (theme) {
    state.setTheme(theme);
  }
  if (typeof preferences.reduced_motion === "boolean") {
    state.setReducedMotion(preferences.reduced_motion);
  }

  const layout = objectValue(preferences.layout);
  if (layout) {
    if (typeof layout.sidebar_collapsed === "boolean") {
      state.setSidebarCollapsed(layout.sidebar_collapsed);
    }
    if (typeof layout.detail_drawer_open === "boolean") {
      state.setDetailDrawerOpen(layout.detail_drawer_open);
    }
    if (typeof layout.bottom_graph_open === "boolean") {
      state.setBottomGraphOpen(layout.bottom_graph_open);
    }
    const pixelPet = objectValue(layout.pixel_pet);
    if (pixelPet) {
      if (typeof pixelPet.enabled === "boolean") {
        state.setPixelPetEnabled(pixelPet.enabled);
      }
      const size = asPixelPetSize(pixelPet.size);
      if (size) {
        state.setPixelPetSize(size);
      }
      const position = pixelPetPositionValue(pixelPet.position);
      if (position !== undefined) {
        state.setPixelPetPosition(position);
      }
    }
  }

  const paneSizes = objectValue(preferences.pane_sizes);
  const horizontal = objectValue(paneSizes?.horizontal);
  if (horizontal) {
    const sidebar = percentNumber(horizontal.sidebar);
    const detailDrawer = percentNumber(horizontal.detail_drawer);
    if (sidebar !== null) {
      state.setSidebarWidth((viewport.width * sidebar) / 100);
    }
    if (detailDrawer !== null) {
      state.setDetailDrawerWidth((viewport.width * detailDrawer) / 100);
    }
  }
  const vertical = objectValue(paneSizes?.vertical);
  if (vertical) {
    const bottomGraph = percentNumber(vertical.bottom_graph);
    if (bottomGraph !== null) {
      state.setBottomGraphHeight((viewport.height * bottomGraph) / 100);
    }
  }

  return safeRoute(preferences.last_route);
}

function currentViewport(): ViewportSize {
  if (typeof window === "undefined") {
    return DEFAULT_VIEWPORT;
  }
  return {
    height: Math.max(1, window.innerHeight || DEFAULT_VIEWPORT.height),
    width: Math.max(1, window.innerWidth || DEFAULT_VIEWPORT.width),
  };
}

function percentages(values: Record<string, number>) {
  const total = Object.values(values).reduce(
    (sum, value) => sum + Math.max(1, value),
    0,
  );
  const entries = Object.entries(values).map(([key, value]) => [
    key,
    roundPercent((Math.max(1, value) / total) * 100),
  ]);
  const result = Object.fromEntries(entries) as Record<string, number>;
  const keys = Object.keys(result);
  const currentSum = Object.values(result).reduce((sum, value) => sum + value, 0);
  const lastKey = keys.at(-1);
  if (lastKey) {
    result[lastKey] = roundPercent(result[lastKey] + (100 - currentSum));
  }
  return result;
}

function roundPercent(value: number) {
  return Math.round(value * 100) / 100;
}

function roundCoordinate(value: number) {
  return Math.round(Math.max(0, Math.min(10_000, value)));
}

function asTheme(value: JsonValue | undefined): ThemeMode | null {
  return value === "dark" || value === "light" || value === "system" || value === "deep-dark"
    ? value
    : null;
}

function objectValue(value: JsonValue | undefined) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function asPixelPetSize(value: JsonValue | undefined) {
  return value === "small" || value === "medium" ? value : null;
}

function pixelPetPositionValue(value: JsonValue | undefined) {
  if (value === null) {
    return null;
  }
  const position = objectValue(value);
  if (!position) {
    return undefined;
  }
  const x = boundedCoordinate(position.x);
  const y = boundedCoordinate(position.y);
  return x === null || y === null ? undefined : { x, y };
}

function boundedCoordinate(value: JsonValue | undefined) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }
  return Math.round(Math.max(0, Math.min(10_000, value)));
}

function percentNumber(value: JsonValue | undefined) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return null;
  }
  return value <= 1 ? value * 100 : value;
}

function safeRoute(value: JsonValue | undefined): RoutePath | null {
  return typeof value === "string" && isRoutePath(value) ? value : null;
}

function isRoutePath(value: string): value is RoutePath {
  return [
    "/",
    "/investigation",
    "/graph",
    "/components",
    "/network",
    "/response",
    "/reports",
    "/settings",
  ].includes(value);
}
