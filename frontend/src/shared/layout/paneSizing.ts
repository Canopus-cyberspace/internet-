export interface PaneSizeLimits {
  readonly defaultSize: number;
  readonly max: number;
  readonly min: number;
}

export const PANE_SIZE_LIMITS = {
  sidebar: {
    defaultSize: 260,
    min: 180,
    max: 420,
  },
  detailDrawer: {
    defaultSize: 380,
    min: 280,
    max: 560,
  },
  bottomGraph: {
    defaultSize: 300,
    min: 180,
    max: 520,
  },
  splitSecondary: {
    defaultSize: 320,
    min: 220,
    max: 520,
  },
} as const satisfies Record<string, PaneSizeLimits>;

export function clampPaneSize(value: number, limits: PaneSizeLimits) {
  const normalized = Number.isFinite(value) ? value : limits.defaultSize;
  return Math.min(limits.max, Math.max(limits.min, Math.round(normalized)));
}

export function paneSizeFromDrag({
  currentPoint,
  limits,
  reverse,
  startPoint,
  startSize,
}: {
  readonly currentPoint: number;
  readonly limits: PaneSizeLimits;
  readonly reverse: boolean;
  readonly startPoint: number;
  readonly startSize: number;
}) {
  const delta = reverse ? startPoint - currentPoint : currentPoint - startPoint;
  return clampPaneSize(startSize + delta, limits);
}
