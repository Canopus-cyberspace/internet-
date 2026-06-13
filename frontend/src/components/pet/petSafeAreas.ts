export interface PetPoint {
  readonly x: number;
  readonly y: number;
}

export interface PetRect {
  readonly height: number;
  readonly width: number;
  readonly x: number;
  readonly y: number;
}

export interface PetSize {
  readonly height: number;
  readonly width: number;
}

export interface PetViewport {
  readonly height: number;
  readonly width: number;
}

export interface ComputePixelPetSafeRectsInput {
  readonly boundaryPaddingPx: number;
  readonly minSafeEdgePx?: number;
  readonly obstaclePaddingPx: number;
  readonly obstacles: readonly PetRect[];
  readonly petSize: PetSize;
  readonly viewport: PetViewport;
}

export interface ReadPixelPetSafeRectsOptions {
  readonly boundaryPaddingPx: number;
  readonly obstaclePaddingPx: number;
  readonly root?: ParentNode;
  readonly viewport?: PetViewport;
}

export const PIXEL_PET_OBSTACLE_SELECTORS = [
  ".top-toolbar",
  ".status-strip",
  ".navigation-tree",
  ".detail-drawer",
  ".pane-resize-handle",
  ".drawer-tabs",
  ".detached-window-header",
  ".detached-payload-header",
  "[data-drag-out-detach-handle='true']",
  "[data-pane-dock-zone='true']",
  "[role='dialog']",
  "dialog",
] as const;

const DEFAULT_MIN_SAFE_EDGE_PX = 24;

export function readPixelPetSafeRects(
  petSize: PetSize,
  {
    boundaryPaddingPx,
    obstaclePaddingPx,
    root,
    viewport = currentViewport(),
  }: ReadPixelPetSafeRectsOptions,
): PetRect[] {
  const obstacles =
    root && typeof root.querySelectorAll === "function"
      ? readObstacleRects(root, viewport)
      : [];
  const safeRects = computePixelPetSafeRects({
    boundaryPaddingPx,
    obstaclePaddingPx,
    obstacles,
    petSize,
    viewport,
  });
  console.debug("[PixelPet] viewport:", viewport.width, "x", viewport.height);
  console.debug("[PixelPet] petSize:", petSize.width, "x", petSize.height);
  console.debug("[PixelPet] obstacles:", obstacles.length);
  if (obstacles.length > 0) {
    console.debug("[PixelPet] obstacle rects:", obstacles.slice(0, 10));
  }
  console.debug("[PixelPet] safeRects count:", safeRects.length);
  if (safeRects.length > 0) {
    console.debug("[PixelPet] safeRects:", safeRects.slice(0, 5));
    return safeRects;
  }
  const fallback = computeConservativeAppShellSafeRects(
    viewport,
    petSize,
    boundaryPaddingPx,
    obstacles,
  );
  console.debug("[PixelPet] using CONSERVATIVE fallback:", fallback);
  return fallback;
}

export function computePixelPetSafeRects({
  boundaryPaddingPx,
  minSafeEdgePx = DEFAULT_MIN_SAFE_EDGE_PX,
  obstaclePaddingPx,
  obstacles,
  petSize,
  viewport,
}: ComputePixelPetSafeRectsInput): PetRect[] {
  const base = viewportAllowedRect(viewport, petSize, boundaryPaddingPx);
  if (!base) {
    return [];
  }

  const blockedRects = obstacles
    .map((obstacle) =>
      obstacleToBlockedPositionRect(
        obstacle,
        petSize,
        obstaclePaddingPx,
        viewport,
      ),
    )
    .filter((rect): rect is PetRect => rect !== null);

  let freeRects: PetRect[] = [base];
  for (const blockedRect of blockedRects) {
    freeRects = freeRects.flatMap((freeRect) =>
      subtractRect(freeRect, blockedRect),
    );
    if (freeRects.length === 0) {
      return [];
    }
  }

  return sortSafeRects(
    freeRects.filter(
      (rect) => rect.width >= minSafeEdgePx && rect.height >= minSafeEdgePx,
    ),
  );
}

export function chooseDefaultPetPosition(
  safeRects: readonly PetRect[],
  defaultPosition: "bottom-left" | "bottom-right",
): PetPoint | null {
  if (safeRects.length === 0) {
    return null;
  }
  const candidates = safeRects.map((rect) => ({
    point: {
      x: defaultPosition === "bottom-left" ? rect.x : rectRight(rect),
      y: rectBottom(rect),
    },
    rect,
  }));
  candidates.sort((a, b) => {
    const vertical = b.point.y - a.point.y;
    if (vertical !== 0) {
      return vertical;
    }
    return defaultPosition === "bottom-left"
      ? a.point.x - b.point.x
      : b.point.x - a.point.x;
  });
  return roundPoint(clampPointToRect(candidates[0].point, candidates[0].rect));
}

export function chooseSafeRoamTarget({
  current,
  minDistancePx,
  random = Math.random,
  safeRects,
}: {
  readonly current: PetPoint;
  readonly minDistancePx: number;
  readonly random?: () => number;
  readonly safeRects: readonly PetRect[];
}): PetPoint | null {
  if (safeRects.length === 0) {
    return null;
  }
  const currentRect = findContainingSafeRect(current, safeRects) ?? safeRects[0];
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const target = randomPointInRect(currentRect, random);
    if (distance(current, target) >= minDistancePx) {
      return target;
    }
  }
  return farthestPointInRect(current, currentRect);
}

export function clampPointToSafeRects(
  point: PetPoint,
  safeRects: readonly PetRect[],
  fallback: PetPoint | null = null,
): PetPoint {
  const containingRect = findContainingSafeRect(point, safeRects);
  if (containingRect) {
    return clampPointToRect(point, containingRect);
  }
  if (safeRects.length === 0) {
    return fallback ? roundPoint(fallback) : roundPoint(point);
  }

  let nearest = clampPointToRect(point, safeRects[0]);
  let nearestDistance = squaredDistance(point, nearest);
  for (const safeRect of safeRects.slice(1)) {
    const candidate = clampPointToRect(point, safeRect);
    const candidateDistance = squaredDistance(point, candidate);
    if (candidateDistance < nearestDistance) {
      nearest = candidate;
      nearestDistance = candidateDistance;
    }
  }
  return nearest;
}

export function findContainingSafeRect(
  point: PetPoint,
  safeRects: readonly PetRect[],
): PetRect | null {
  return safeRects.find((rect) => pointInsideRect(point, rect)) ?? null;
}

export function pointInsideRect(point: PetPoint, rect: PetRect): boolean {
  return (
    point.x >= rect.x &&
    point.x <= rectRight(rect) &&
    point.y >= rect.y &&
    point.y <= rectBottom(rect)
  );
}

export function randomPointInRect(
  rect: PetRect,
  random: () => number = Math.random,
): PetPoint {
  return roundPoint({
    x: rect.x + rect.width * boundedRandom(random),
    y: rect.y + rect.height * boundedRandom(random),
  });
}

export function rectBottom(rect: PetRect): number {
  return rect.y + rect.height;
}

export function rectRight(rect: PetRect): number {
  return rect.x + rect.width;
}

export function distance(a: PetPoint, b: PetPoint): number {
  return Math.sqrt(squaredDistance(a, b));
}

export function currentViewport(): PetViewport {
  if (typeof window === "undefined") {
    return { height: 900, width: 1440 };
  }
  return {
    height: Math.max(1, window.innerHeight),
    width: Math.max(1, window.innerWidth),
  };
}

export function clampPointToViewport(
  point: PetPoint,
  viewport: PetViewport,
  petSize: PetSize,
  boundaryPaddingPx: number,
): PetPoint {
  const allowedRect = viewportAllowedRect(viewport, petSize, boundaryPaddingPx);
  if (!allowedRect) {
    return roundPoint({ x: boundaryPaddingPx, y: boundaryPaddingPx });
  }
  return clampPointToRect(point, allowedRect);
}

export function computeConservativeAppShellSafeRects(
  viewport: PetViewport,
  petSize: PetSize,
  boundaryPaddingPx: number,
  obstacles: readonly PetRect[] = [],
): PetRect[] {
  const topReserved = Math.max(
    Math.min(72, viewport.height * 0.16),
    ...obstacles
      .filter((rect) => rect.y <= boundaryPaddingPx && rect.width >= viewport.width * 0.35)
      .map(rectBottom),
  );
  const leftReserved = Math.max(
    Math.min(292, viewport.width * 0.28),
    ...obstacles
      .filter((rect) => rect.x <= boundaryPaddingPx && rect.height >= viewport.height * 0.25)
      .map(rectRight),
  );
  const rightReserved = Math.max(
    Math.min(348, viewport.width * 0.28),
    ...obstacles
      .filter(
        (rect) =>
          rectRight(rect) >= viewport.width - boundaryPaddingPx &&
          rect.height >= viewport.height * 0.25,
      )
      .map((rect) => viewport.width - rect.x),
  );
  const bottomObstacleTop = Math.min(
    viewport.height - Math.min(40, viewport.height * 0.12),
    ...obstacles
      .filter(
        (rect) =>
          (rect.width >= viewport.width * 0.35 && rect.y > viewport.height * 0.25) ||
          rectBottom(rect) >= viewport.height - boundaryPaddingPx,
      )
      .map((rect) => rect.y),
  );

  const minX = leftReserved + boundaryPaddingPx;
  const maxX = viewport.width - rightReserved - petSize.width - boundaryPaddingPx;
  const minY = topReserved + Math.min(4, boundaryPaddingPx);
  const maxY = bottomObstacleTop - petSize.height - Math.min(4, boundaryPaddingPx);
  if (maxX < minX) {
    const base = viewportAllowedRect(viewport, petSize, boundaryPaddingPx);
    return base ? [base] : [];
  }

  const y = Math.max(topReserved, Math.min(maxY, minY));
  const rect: PetRect = {
    height: Math.max(0, maxY - y),
    width: Math.max(0, maxX - minX),
    x: minX,
    y,
  };
  if (rect.width > 0) {
    return [rect];
  }
  const base = viewportAllowedRect(viewport, petSize, boundaryPaddingPx);
  return base ? [base] : [];
}

function readObstacleRects(root: ParentNode, viewport: PetViewport): PetRect[] {
  const rects: PetRect[] = [];
  for (const selector of PIXEL_PET_OBSTACLE_SELECTORS) {
    for (const element of root.querySelectorAll(selector)) {
      if (!(element instanceof Element)) {
        continue;
      }
      const domRect = element.getBoundingClientRect();
      if (domRect.width <= 0 || domRect.height <= 0) {
        continue;
      }
      const clippedRect = clipRectToViewport(
        {
          height: domRect.height,
          width: domRect.width,
          x: domRect.left,
          y: domRect.top,
        },
        viewport,
      );
      if (clippedRect) {
        rects.push(clippedRect);
      }
    }
  }
  return rects;
}

function obstacleToBlockedPositionRect(
  obstacle: PetRect,
  petSize: PetSize,
  obstaclePaddingPx: number,
  viewport: PetViewport,
): PetRect | null {
  return clipRectToViewport(
    {
      height: obstacle.height + petSize.height + obstaclePaddingPx * 2,
      width: obstacle.width + petSize.width + obstaclePaddingPx * 2,
      x: obstacle.x - petSize.width - obstaclePaddingPx,
      y: obstacle.y - petSize.height - obstaclePaddingPx,
    },
    viewport,
  );
}

function viewportAllowedRect(
  viewport: PetViewport,
  petSize: PetSize,
  boundaryPaddingPx: number,
): PetRect | null {
  const width = viewport.width - petSize.width - boundaryPaddingPx * 2;
  const height = viewport.height - petSize.height - boundaryPaddingPx * 2;
  if (width <= 0 || height <= 0) {
    return null;
  }
  return {
    height,
    width,
    x: boundaryPaddingPx,
    y: boundaryPaddingPx,
  };
}

function subtractRect(source: PetRect, blocked: PetRect): PetRect[] {
  const overlap = intersectRect(source, blocked);
  if (!overlap) {
    return [source];
  }

  const pieces: PetRect[] = [
    {
      height: overlap.y - source.y,
      width: source.width,
      x: source.x,
      y: source.y,
    },
    {
      height: rectBottom(source) - rectBottom(overlap),
      width: source.width,
      x: source.x,
      y: rectBottom(overlap),
    },
    {
      height: overlap.height,
      width: overlap.x - source.x,
      x: source.x,
      y: overlap.y,
    },
    {
      height: overlap.height,
      width: rectRight(source) - rectRight(overlap),
      x: rectRight(overlap),
      y: overlap.y,
    },
  ];

  return pieces.filter((rect) => rect.width > 0 && rect.height > 0);
}

function intersectRect(a: PetRect, b: PetRect): PetRect | null {
  const x = Math.max(a.x, b.x);
  const y = Math.max(a.y, b.y);
  const right = Math.min(rectRight(a), rectRight(b));
  const bottom = Math.min(rectBottom(a), rectBottom(b));
  if (right <= x || bottom <= y) {
    return null;
  }
  return {
    height: bottom - y,
    width: right - x,
    x,
    y,
  };
}

function clipRectToViewport(rect: PetRect, viewport: PetViewport): PetRect | null {
  return intersectRect(rect, {
    height: viewport.height,
    width: viewport.width,
    x: 0,
    y: 0,
  });
}

function clampPointToRect(point: PetPoint, rect: PetRect): PetPoint {
  return {
    x: Math.max(rect.x, Math.min(rectRight(rect), point.x)),
    y: Math.max(rect.y, Math.min(rectBottom(rect), point.y)),
  };
}

function farthestPointInRect(point: PetPoint, rect: PetRect): PetPoint {
  const candidates: PetPoint[] = [
    { x: rect.x, y: rect.y },
    { x: rectRight(rect), y: rect.y },
    { x: rect.x, y: rectBottom(rect) },
    { x: rectRight(rect), y: rectBottom(rect) },
  ];
  return roundPoint(
    candidates.reduce((best, candidate) =>
      squaredDistance(point, candidate) > squaredDistance(point, best)
        ? candidate
        : best,
    ),
  );
}

function sortSafeRects(rects: PetRect[]): PetRect[] {
  return [...rects].sort((a, b) => {
    const areaDelta = b.width * b.height - a.width * a.height;
    if (areaDelta !== 0) {
      return areaDelta;
    }
    const yDelta = a.y - b.y;
    return yDelta !== 0 ? yDelta : a.x - b.x;
  });
}

function squaredDistance(a: PetPoint, b: PetPoint): number {
  const dx = a.x - b.x;
  const dy = a.y - b.y;
  return dx * dx + dy * dy;
}

function roundPoint(point: PetPoint): PetPoint {
  return {
    x: Math.round(point.x),
    y: Math.round(point.y),
  };
}

function boundedRandom(random: () => number): number {
  const value = random();
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.max(0, Math.min(0.999_999, value));
}
