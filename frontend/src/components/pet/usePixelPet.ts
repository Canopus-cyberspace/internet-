import { useRouterState } from "@tanstack/react-router";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type PointerEvent as ReactPointerEvent,
} from "react";
import { useUiStore } from "../../stores/uiStore";
import {
  DEFAULT_PIXEL_PET_CONFIG,
  FALLBACK_PIXEL_PET_FRAME_SIZE,
  PIXEL_PET_STATE_ASSETS,
  PIXEL_PET_STATE_FRAME_COUNTS,
  getPixelPetScreenSize,
  resolvePixelPetConfig,
  type PixelPetConfig,
  type PixelPetDirection,
  type PixelPetFrameSize,
  type PixelPetScreenSize,
  type PixelPetState,
} from "./pixelPetAssets";
import {
  chooseDefaultPetPosition,
  chooseSafeRoamTarget,
  clampPointToSafeRects,
  clampPointToViewport,
  currentViewport,
  distance,
  findContainingSafeRect,
  readPixelPetSafeRects,
  type PetPoint,
  type PetRect,
  type PetViewport,
} from "./petSafeAreas";

export type { PetPoint, PetViewport } from "./petSafeAreas";

export interface PixelPetView {
  readonly animationKey: number;
  readonly direction: PixelPetDirection;
  readonly fps: number;
  readonly frameCount: number;
  readonly position: PetPoint;
  readonly reducedMotion: boolean;
  readonly screenSize: PixelPetScreenSize;
  readonly spriteUrl: string;
  readonly state: PixelPetState;
  readonly zIndex: number;
}

export interface PixelPetBindings {
  readonly onClick: (event: ReactMouseEvent<HTMLElement>) => void;
  readonly onKeyDown: (event: KeyboardEvent<HTMLElement>) => void;
  readonly onPointerCancel: (event: ReactPointerEvent<HTMLElement>) => void;
  readonly onPointerDown: (event: ReactPointerEvent<HTMLElement>) => void;
  readonly onPointerMove: (event: ReactPointerEvent<HTMLElement>) => void;
  readonly onPointerUp: (event: ReactPointerEvent<HTMLElement>) => void;
}

const WALK_START_DELAY_MS = 800;
const LANDING_DELAY_MS = 450;
const POSITION_SAVE_INTERVAL_MS = 900;
const DRAG_CLICK_THRESHOLD_PX = 4;
const ROAM_IDLE_MIN_MS = 1_100;
const ROAM_IDLE_MAX_MS = 2_800;
const ROAM_TARGET_REACHED_PX = 3;
const ROAM_MIN_TARGET_DISTANCE_PX = 70;
const SAFE_ZONE_OBSTACLE_PADDING_PX = 10;
const EMPTY_CONFIG_OVERRIDES: Partial<PixelPetConfig> = {};
export const PIXEL_PET_ACTIVITY_EVENTS = [
  "mousemove",
  "pointerdown",
  "click",
  "keydown",
  "touchstart",
  "wheel",
  "scroll",
] as const;

interface DragState {
  readonly offsetX: number;
  readonly offsetY: number;
  readonly pointerId: number;
  readonly start: PetPoint;
}

export function usePixelPet(
  configOverrides?: Partial<PixelPetConfig>,
): {
  readonly bindings: PixelPetBindings;
  readonly enabled: boolean;
  readonly view: PixelPetView;
} {
  const enabled = useUiStore((state) => state.pixelPetEnabled);
  const size = useUiStore((state) => state.pixelPetSize);
  const storedPosition = useUiStore((state) => state.pixelPetPosition);
  const reducedMotion = useUiStore((state) => state.reducedMotion);
  const setPixelPetPosition = useUiStore((state) => state.setPixelPetPosition);
  const sidebarCollapsed = useUiStore((state) => state.sidebarCollapsed);
  const bottomGraphOpen = useUiStore((state) => state.bottomGraphOpen);
  const detailDrawerOpen = useUiStore((state) => state.detailDrawerOpen);
  const sidebarWidth = useUiStore((state) => state.sidebarWidth);
  const detailDrawerWidth = useUiStore((state) => state.detailDrawerWidth);
  const bottomGraphHeight = useUiStore((state) => state.bottomGraphHeight);
  const detachedPanes = useUiStore((state) => state.detachedPanes);
  const routePathname = useRouterState({
    select: (state) => state.location.pathname,
  });

  const config = useMemo(
    () => resolvePixelPetConfig(configOverrides ?? EMPTY_CONFIG_OVERRIDES),
    [configOverrides],
  );
  const frameSize = useSpriteFrameSize(
    PIXEL_PET_STATE_ASSETS.walk,
    PIXEL_PET_STATE_FRAME_COUNTS.walk,
  );
  const screenSize = useMemo(
    () => getPixelPetScreenSize(size, frameSize, config),
    [config, frameSize, size],
  );

  const stateRef = useRef<PixelPetState>("idle");
  const prevStateRef = useRef<PixelPetState>("idle");
  const positionRef = useRef<PetPoint>({ x: 0, y: 0 });
  const directionRef = useRef<PixelPetDirection>(-1);
  const animationKeyRef = useRef(0);
  const interactUntilRef = useRef(0);
  const lastActivityAtRef = useRef(0);
  const nextWalkAtRef = useRef(0);
  const lastPersistAtRef = useRef(0);
  const initializedRef = useRef(false);
  const draggingRef = useRef<DragState | null>(null);
  const dragDistanceRef = useRef(0);
  const ignoreNextClickRef = useRef(false);
  const safeRectsRef = useRef<PetRect[]>([]);
  const targetRef = useRef<PetPoint | null>(null);

  const [view, setView] = useState<PixelPetView>(() => ({
    animationKey: 0,
    direction: -1,
    fps: DEFAULT_PIXEL_PET_CONFIG.fps,
    frameCount: PIXEL_PET_STATE_FRAME_COUNTS.idle,
    position: { x: 0, y: 0 },
    reducedMotion,
    screenSize: getPixelPetScreenSize(size),
    spriteUrl: PIXEL_PET_STATE_ASSETS.idle,
    state: "idle",
    zIndex: DEFAULT_PIXEL_PET_CONFIG.zIndex,
  }));

  const stateFps = useCallback(
    (state: PixelPetState) => {
      if (state === "sleepy") return config.sleepyFps;
      if (state === "drag") return config.dragFps;
      return config.fps;
    },
    [config.dragFps, config.fps, config.sleepyFps],
  );

  const writeView = useCallback(() => {
    const rawState = stateRef.current;
    const currentState = reducedMotion && rawState === "walk" ? "idle" : rawState;
    setView({
      animationKey: animationKeyRef.current,
      direction: directionRef.current,
      fps: stateFps(currentState),
      frameCount: PIXEL_PET_STATE_FRAME_COUNTS[currentState],
      position: positionRef.current,
      reducedMotion,
      screenSize,
      spriteUrl: PIXEL_PET_STATE_ASSETS[currentState],
      state: currentState,
      zIndex: config.zIndex,
    });
  }, [config.fps, config.zIndex, reducedMotion, screenSize, stateFps]);

  const fallbackVisiblePosition = useCallback(
    (source: PetPoint | null = null) => {
      const viewport = currentViewport();
      const fallback = {
        x:
          config.defaultPosition === "bottom-left"
            ? config.boundaryPaddingPx
            : viewport.width - screenSize.width - config.boundaryPaddingPx,
        y: viewport.height - screenSize.height - config.bottomOffsetPx,
      };
      return clampPointToViewport(
        source ?? fallback,
        viewport,
        screenSize,
        config.boundaryPaddingPx,
      );
    },
    [config, screenSize],
  );

  const refreshSafeRects = useCallback(() => {
    const root = typeof document === "undefined" ? undefined : document;
    safeRectsRef.current = readPixelPetSafeRects(screenSize, {
      boundaryPaddingPx: config.boundaryPaddingPx,
      obstaclePaddingPx: SAFE_ZONE_OBSTACLE_PADDING_PX,
      root,
    });
    return safeRectsRef.current;
  }, [config.boundaryPaddingPx, screenSize]);

  const clampToSafeArea = useCallback(
    (source: PetPoint | null) => {
      const safeRects =
        safeRectsRef.current.length > 0
          ? safeRectsRef.current
          : refreshSafeRects();
      const fallback =
        chooseDefaultPetPosition(safeRects, config.defaultPosition) ??
        fallbackVisiblePosition(source);
      if (safeRects.length === 0) {
        return fallbackVisiblePosition(source ?? fallback);
      }
      return clampPointToSafeRects(source ?? fallback, safeRects, fallback);
    },
    [config.defaultPosition, fallbackVisiblePosition, refreshSafeRects],
  );

  const persistPosition = useCallback(
    (now = performance.now()) => {
      if (now - lastPersistAtRef.current < POSITION_SAVE_INTERVAL_MS) {
        return;
      }
      lastPersistAtRef.current = now;
      setPixelPetPosition(positionRef.current);
    },
    [setPixelPetPosition],
  );

  const recordActivity = useCallback(() => {
    const now = performance.now();
    lastActivityAtRef.current = now;
    if (stateRef.current === "sleepy" && !draggingRef.current) {
      stateRef.current = "idle";
      targetRef.current = null;
      animationKeyRef.current += 1;
      nextWalkAtRef.current = now + WALK_START_DELAY_MS;
      positionRef.current = clampToSafeArea(positionRef.current);
      writeView();
    }
  }, [clampToSafeArea, writeView]);

  const startInteract = useCallback(() => {
    if (draggingRef.current) {
      return;
    }
    const now = performance.now();
    recordActivity();
    targetRef.current = null;
    stateRef.current = "interact";
    interactUntilRef.current = now + config.interactDurationMs;
    animationKeyRef.current += 1;
    nextWalkAtRef.current = interactUntilRef.current + WALK_START_DELAY_MS;
    writeView();
  }, [config.interactDurationMs, recordActivity, writeView]);

  useEffect(() => {
    if (!enabled) {
      initializedRef.current = false;
      targetRef.current = null;
      return;
    }
    const now = performance.now();
    refreshSafeRects();
    const startingPosition = storedPosition
      ? { x: storedPosition.x, y: storedPosition.y }
      : null;
    positionRef.current = clampToSafeArea(
      initializedRef.current ? positionRef.current : startingPosition,
    );
    initializedRef.current = true;
    lastActivityAtRef.current ||= now;
    nextWalkAtRef.current ||= now + WALK_START_DELAY_MS;
    writeView();
    setPixelPetPosition(positionRef.current);
  }, [
    clampToSafeArea,
    enabled,
    refreshSafeRects,
    setPixelPetPosition,
    storedPosition,
    writeView,
  ]);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let refreshFrame = 0;
    const refreshAndClamp = () => {
      refreshFrame = 0;
      const safeRects = refreshSafeRects();
      const fallback = chooseDefaultPetPosition(
        safeRects,
        config.defaultPosition,
      );
      const reconciled = reconcilePixelPetSafeZoneChange({
        fallback,
        position: positionRef.current,
        safeRects,
        target: targetRef.current,
      });
      positionRef.current = reconciled.position;
      targetRef.current = reconciled.target;
      writeView();
      setPixelPetPosition(positionRef.current);
    };
    const scheduleRefresh = () => {
      if (refreshFrame || typeof window === "undefined") {
        return;
      }
      refreshFrame = window.requestAnimationFrame(refreshAndClamp);
    };

    scheduleRefresh();
    window.addEventListener("resize", scheduleRefresh);

    const resizeObserver =
      typeof ResizeObserver === "undefined"
        ? null
        : new ResizeObserver(scheduleRefresh);
    const appFrame = document.querySelector(".app-frame") ?? document.body;
    resizeObserver?.observe(appFrame);

    const mutationObserver =
      typeof MutationObserver === "undefined"
        ? null
        : new MutationObserver(scheduleRefresh);
    mutationObserver?.observe(document.body, {
      attributeFilter: [
        "aria-hidden",
        "class",
        "data-detail-open",
        "data-drag-out-state",
        "data-graph-open",
        "data-pane-resizing",
        "data-sidebar-collapsed",
        "hidden",
        "open",
      ],
      attributes: true,
      subtree: true,
    });

    return () => {
      if (refreshFrame) {
        window.cancelAnimationFrame(refreshFrame);
      }
      window.removeEventListener("resize", scheduleRefresh);
      resizeObserver?.disconnect();
      mutationObserver?.disconnect();
    };
  }, [
    bottomGraphHeight,
    bottomGraphOpen,
    clampToSafeArea,
    detailDrawerOpen,
    detailDrawerWidth,
    detachedPanes,
    enabled,
    refreshSafeRects,
    routePathname,
    setPixelPetPosition,
    sidebarCollapsed,
    sidebarWidth,
    writeView,
  ]);

  useEffect(() => {
    if (!enabled) {
      return;
    }
    for (const eventName of PIXEL_PET_ACTIVITY_EVENTS) {
      window.addEventListener(eventName, recordActivity, {
        capture: true,
        passive: true,
      });
    }
    return () => {
      for (const eventName of PIXEL_PET_ACTIVITY_EVENTS) {
        window.removeEventListener(eventName, recordActivity, {
          capture: true,
        });
      }
    };
  }, [enabled, recordActivity]);

  useEffect(() => {
    if (!enabled) {
      return;
    }
    if (reducedMotion) {
      targetRef.current = null;
      stateRef.current = stateRef.current === "drag" ? "drag" : "idle";
      positionRef.current = clampToSafeArea(positionRef.current);
      writeView();
      return;
    }

    let animationFrame = 0;
    let lastTick = performance.now();
    let hidden = document.hidden;

    const onVisibilityChange = () => {
      hidden = document.hidden;
    };

    const tick = (timestamp: number) => {
      animationFrame = window.requestAnimationFrame(tick);
      if (hidden) {
        lastTick = timestamp;
        return;
      }

      const dtMs = Math.min(timestamp - lastTick, 64);
      lastTick = timestamp;
      if (draggingRef.current) {
        writeView();
        return;
      }

      const next = updatePixelPetMotion({
        config,
        direction: directionRef.current,
        dtMs,
        interactUntil: interactUntilRef.current,
        lastActivityAt: lastActivityAtRef.current,
        nextWalkAt: nextWalkAtRef.current,
        now: timestamp,
        position: positionRef.current,
        safeRects: safeRectsRef.current,
        state: stateRef.current,
        target: targetRef.current,
      });

      const prevState = prevStateRef.current;
      if (next.state !== prevState || next.restartAnimation) {
        console.debug(
          "[PixelPet] tick: state=", next.state,
          "pos=(", Math.round(next.position.x), ",", Math.round(next.position.y), ")",
          "target=", next.target ? `(${Math.round(next.target.x)}, ${Math.round(next.target.y)})` : "none",
          "safeRects#=", safeRectsRef.current.length,
          safeRectsRef.current.length > 0
            ? `first=(${safeRectsRef.current[0].x},${safeRectsRef.current[0].y} ${safeRectsRef.current[0].width}x${safeRectsRef.current[0].height})`
            : "none",
        );
      }
      prevStateRef.current = next.state;

      stateRef.current = next.state;
      positionRef.current = next.position;
      directionRef.current = next.direction;
      nextWalkAtRef.current = next.nextWalkAt;
      targetRef.current = next.target;
      if (next.restartAnimation) {
        animationKeyRef.current += 1;
      }
      persistPosition(timestamp);
      writeView();
    };

    document.addEventListener("visibilitychange", onVisibilityChange);
    animationFrame = window.requestAnimationFrame(tick);
    return () => {
      window.cancelAnimationFrame(animationFrame);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [
    clampToSafeArea,
    config,
    enabled,
    persistPosition,
    reducedMotion,
    writeView,
  ]);

  const finishDrag = useCallback(
    (event: ReactPointerEvent<HTMLElement>) => {
      const drag = draggingRef.current;
      if (!drag || drag.pointerId !== event.pointerId) {
        return;
      }
      event.preventDefault();
      if (event.currentTarget.hasPointerCapture(event.pointerId)) {
        event.currentTarget.releasePointerCapture(event.pointerId);
      }
      draggingRef.current = null;
      ignoreNextClickRef.current =
        dragDistanceRef.current > DRAG_CLICK_THRESHOLD_PX;
      dragDistanceRef.current = 0;
      const now = performance.now();
      recordActivity();
      positionRef.current = clampToSafeArea(positionRef.current);
      targetRef.current = null;
      stateRef.current = "idle";
      animationKeyRef.current += 1;
      nextWalkAtRef.current = now + LANDING_DELAY_MS;
      lastPersistAtRef.current = now;
      setPixelPetPosition(positionRef.current);
      writeView();
    },
    [clampToSafeArea, recordActivity, setPixelPetPosition, writeView],
  );

  const bindings = useMemo<PixelPetBindings>(
    () => ({
      onClick: (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (ignoreNextClickRef.current) {
          ignoreNextClickRef.current = false;
          return;
        }
        startInteract();
      },
      onKeyDown: (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          startInteract();
        }
      },
      onPointerCancel: (event) => {
        finishDrag(event);
      },
      onPointerDown: (event) => {
        if (event.button !== 0) {
          return;
        }
        event.preventDefault();
        event.stopPropagation();
        const pointerId = event.pointerId;
        event.currentTarget.setPointerCapture(pointerId);
        const now = performance.now();
        recordActivity();
        draggingRef.current = {
          offsetX: event.clientX - positionRef.current.x,
          offsetY: event.clientY - positionRef.current.y,
          pointerId,
          start: positionRef.current,
        };
        targetRef.current = null;
        dragDistanceRef.current = 0;
        ignoreNextClickRef.current = false;
        stateRef.current = "drag";
        animationKeyRef.current += 1;
        nextWalkAtRef.current = now + LANDING_DELAY_MS;
        writeView();
      },
      onPointerMove: (event) => {
        const drag = draggingRef.current;
        if (!drag || drag.pointerId !== event.pointerId) {
          return;
        }
        event.preventDefault();
        const next = clampToSafeArea({
          x: event.clientX - drag.offsetX,
          y: event.clientY - drag.offsetY,
        });
        dragDistanceRef.current = Math.max(
          dragDistanceRef.current,
          distance(drag.start, next),
        );
        if (next.x !== positionRef.current.x) {
          directionRef.current = next.x < positionRef.current.x ? -1 : 1;
        }
        positionRef.current = next;
        targetRef.current = null;
        stateRef.current = "drag";
        writeView();
      },
      onPointerUp: (event) => {
        finishDrag(event);
      },
    }),
    [clampToSafeArea, finishDrag, recordActivity, startInteract, writeView],
  );

  return { bindings, enabled, view };
}

export interface PixelPetMotionInput {
  readonly config: PixelPetConfig;
  readonly direction: PixelPetDirection;
  readonly dtMs: number;
  readonly interactUntil: number;
  readonly lastActivityAt: number;
  readonly nextWalkAt: number;
  readonly now: number;
  readonly position: PetPoint;
  readonly random?: () => number;
  readonly safeRects: readonly PetRect[];
  readonly state: PixelPetState;
  readonly target: PetPoint | null;
}

export interface PixelPetMotionResult {
  readonly direction: PixelPetDirection;
  readonly nextWalkAt: number;
  readonly position: PetPoint;
  readonly restartAnimation: boolean;
  readonly state: PixelPetState;
  readonly target: PetPoint | null;
}

export function updatePixelPetMotion({
  config,
  direction,
  dtMs,
  interactUntil,
  lastActivityAt,
  nextWalkAt,
  now,
  position,
  random = Math.random,
  safeRects,
  state,
  target,
}: PixelPetMotionInput): PixelPetMotionResult {
  const fallback = chooseDefaultPetPosition(safeRects, config.defaultPosition);
  const clampedPosition =
    safeRects.length > 0
      ? clampPointToSafeRects(position, safeRects, fallback)
      : position;

  if (state === "drag") {
    return {
      direction,
      nextWalkAt: now + LANDING_DELAY_MS,
      position: clampedPosition,
      restartAnimation: false,
      state: "drag",
      target: null,
    };
  }

  if (state === "interact" && now < interactUntil) {
    return {
      direction,
      nextWalkAt,
      position: clampedPosition,
      restartAnimation: false,
      state: "interact",
      target: null,
    };
  }

  if (now - lastActivityAt >= config.inactivityTimeoutMs) {
    return {
      direction,
      nextWalkAt,
      position: clampedPosition,
      restartAnimation: state !== "sleepy",
      state: "sleepy",
      target: null,
    };
  }

  if (safeRects.length === 0 || now < nextWalkAt) {
    return {
      direction,
      nextWalkAt,
      position: clampedPosition,
      restartAnimation: state === "interact" || state === "sleepy",
      state: "idle",
      target: null,
    };
  }

  const currentTarget =
    target ??
    chooseSafeRoamTarget({
      current: clampedPosition,
      minDistancePx: ROAM_MIN_TARGET_DISTANCE_PX,
      random,
      safeRects,
    });

  if (!currentTarget) {
    return {
      direction,
      nextWalkAt: now + nextRoamDelayMs(random),
      position: clampedPosition,
      restartAnimation: state !== "idle",
      state: "idle",
      target: null,
    };
  }

  const advanced = advanceTowardTarget({
    current: clampedPosition,
    currentDirection: direction,
    dtMs,
    speedPxPerSecond: config.walkSpeedPxPerSecond,
    target: currentTarget,
    targetReachedPx: ROAM_TARGET_REACHED_PX,
  });

  if (advanced.arrived) {
    return {
      direction: advanced.direction,
      nextWalkAt: now + nextRoamDelayMs(random),
      position: clampPointToSafeRects(advanced.position, safeRects, fallback),
      restartAnimation: state === "walk",
      state: "idle",
      target: null,
    };
  }

  return {
    direction: advanced.direction,
    nextWalkAt,
    position: clampPointToSafeRects(advanced.position, safeRects, fallback),
    restartAnimation: state !== "walk",
    state: "walk",
    target: currentTarget,
  };
}

export function advanceTowardTarget({
  current,
  currentDirection,
  dtMs,
  speedPxPerSecond,
  target,
  targetReachedPx,
}: {
  readonly current: PetPoint;
  readonly currentDirection: PixelPetDirection;
  readonly dtMs: number;
  readonly speedPxPerSecond: number;
  readonly target: PetPoint;
  readonly targetReachedPx: number;
}): {
  readonly arrived: boolean;
  readonly direction: PixelPetDirection;
  readonly position: PetPoint;
} {
  const totalDistance = distance(current, target);
  const maxDistance = speedPxPerSecond * (dtMs / 1000);
  const direction =
    target.x < current.x ? -1 : target.x > current.x ? 1 : currentDirection;

  if (totalDistance <= Math.max(targetReachedPx, maxDistance)) {
    return {
      arrived: true,
      direction,
      position: roundPoint(target),
    };
  }

  const ratio = maxDistance / totalDistance;
  return {
    arrived: false,
    direction,
    position: {
      x: current.x + (target.x - current.x) * ratio,
      y: current.y + (target.y - current.y) * ratio,
    },
  };
}

export function reconcilePixelPetSafeZoneChange({
  fallback,
  position,
  safeRects,
  target,
}: {
  readonly fallback: PetPoint | null;
  readonly position: PetPoint;
  readonly safeRects: readonly PetRect[];
  readonly target: PetPoint | null;
}): {
  readonly position: PetPoint;
  readonly target: PetPoint | null;
} {
  if (safeRects.length === 0) {
    return { position, target: null };
  }
  return {
    position: clampPointToSafeRects(position, safeRects, fallback),
    target:
      target && findContainingSafeRect(target, safeRects) ? target : null,
  };
}

function useSpriteFrameSize(
  spriteUrl: string,
  frameCount: number,
): PixelPetFrameSize {
  const [frameSize, setFrameSize] = useState<PixelPetFrameSize>(
    FALLBACK_PIXEL_PET_FRAME_SIZE,
  );

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    let cancelled = false;
    const image = new Image();
    image.onload = () => {
      if (cancelled || !image.naturalWidth || !image.naturalHeight) {
        return;
      }
      setFrameSize({
        height: image.naturalHeight,
        width: image.naturalWidth / frameCount,
      });
    };
    image.src = spriteUrl;
    return () => {
      cancelled = true;
    };
  }, [frameCount, spriteUrl]);

  return frameSize;
}

function nextRoamDelayMs(random: () => number): number {
  const span = ROAM_IDLE_MAX_MS - ROAM_IDLE_MIN_MS;
  const randomValue = random();
  const boundedRandom = Number.isFinite(randomValue)
    ? Math.max(0, Math.min(0.999_999, randomValue))
    : 0;
  return ROAM_IDLE_MIN_MS + Math.round(span * boundedRandom);
}

function roundPoint(point: PetPoint): PetPoint {
  return {
    x: Math.round(point.x),
    y: Math.round(point.y),
  };
}
