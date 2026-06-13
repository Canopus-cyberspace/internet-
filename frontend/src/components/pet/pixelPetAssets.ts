import type { PixelPetSize } from "../../stores/uiStore";

export type PixelPetState = "idle" | "walk" | "sleepy" | "interact" | "drag";
export type PixelPetDirection = -1 | 1;

export interface PixelPetFrameSize {
  readonly height: number;
  readonly width: number;
}

export interface PixelPetScreenSize {
  readonly height: number;
  readonly width: number;
}

export interface PixelPetConfig {
  readonly bottomOffsetPx: number;
  readonly boundaryPaddingPx: number;
  readonly defaultPosition: "bottom-left" | "bottom-right";
  readonly fps: number;
  readonly sleepyFps: number;
  readonly dragFps: number;
  readonly frameCount: number;
  readonly inactivityTimeoutMs: number;
  readonly interactDurationMs: number;
  readonly mediumHeightPx: number;
  readonly smallHeightPx: number;
  readonly walkSpeedPxPerSecond: number;
  readonly zIndex: number;
}

export const PIXEL_PET_FRAME_COUNT = 8;
export const PIXEL_PET_DRAG_FRAME_COUNT = 6;
export const INACTIVITY_TIMEOUT_MS = 60_000;

export const PIXEL_PET_SPRITE_ASSETS: Readonly<
  Record<Exclude<PixelPetState, "idle">, string>
> = {
  drag: "/assets/pet/drag_6frames_transparent.png",
  interact: "/assets/pet/interact_click_8frames_transparent.png",
  sleepy: "/assets/pet/sleepy_8frames_transparent.png",
  walk: "/assets/pet/walk_left_8frames_transparent.png",
} as const;

export const PIXEL_PET_STATE_ASSETS: Readonly<Record<PixelPetState, string>> = {
  drag: PIXEL_PET_SPRITE_ASSETS.drag,
  idle: PIXEL_PET_SPRITE_ASSETS.walk,
  interact: PIXEL_PET_SPRITE_ASSETS.interact,
  sleepy: PIXEL_PET_SPRITE_ASSETS.sleepy,
  walk: PIXEL_PET_SPRITE_ASSETS.walk,
} as const;

export const PIXEL_PET_STATE_FRAME_COUNTS: Readonly<
  Record<PixelPetState, number>
> = {
  drag: PIXEL_PET_DRAG_FRAME_COUNT,
  idle: PIXEL_PET_FRAME_COUNT,
  interact: PIXEL_PET_FRAME_COUNT,
  sleepy: PIXEL_PET_FRAME_COUNT,
  walk: PIXEL_PET_FRAME_COUNT,
} as const;

export const FALLBACK_PIXEL_PET_FRAME_SIZE: PixelPetFrameSize = {
  height: 314,
  width: 221.75,
};

export const DEFAULT_PIXEL_PET_CONFIG: PixelPetConfig = {
  bottomOffsetPx: 36,
  boundaryPaddingPx: 16,
  defaultPosition: "bottom-right",
  fps: 8,
  sleepyFps: 6,
  dragFps: 6,
  frameCount: PIXEL_PET_FRAME_COUNT,
  inactivityTimeoutMs: INACTIVITY_TIMEOUT_MS,
  interactDurationMs: 1_000,
  mediumHeightPx: 116,
  smallHeightPx: 92,
  walkSpeedPxPerSecond: 34,
  zIndex: 10,
};

export function resolvePixelPetConfig(
  overrides: Partial<PixelPetConfig> = {},
): PixelPetConfig {
  return {
    ...DEFAULT_PIXEL_PET_CONFIG,
    ...overrides,
    bottomOffsetPx: positiveNumber(
      overrides.bottomOffsetPx,
      DEFAULT_PIXEL_PET_CONFIG.bottomOffsetPx,
    ),
    boundaryPaddingPx: positiveNumber(
      overrides.boundaryPaddingPx,
      DEFAULT_PIXEL_PET_CONFIG.boundaryPaddingPx,
    ),
    fps: positiveNumber(overrides.fps, DEFAULT_PIXEL_PET_CONFIG.fps),
    sleepyFps: positiveNumber(
      overrides.sleepyFps,
      DEFAULT_PIXEL_PET_CONFIG.sleepyFps,
    ),
    dragFps: positiveNumber(
      overrides.dragFps,
      DEFAULT_PIXEL_PET_CONFIG.dragFps,
    ),
    frameCount: Math.max(
      1,
      Math.round(
        positiveNumber(
          overrides.frameCount,
          DEFAULT_PIXEL_PET_CONFIG.frameCount,
        ),
      ),
    ),
    inactivityTimeoutMs: positiveNumber(
      overrides.inactivityTimeoutMs,
      DEFAULT_PIXEL_PET_CONFIG.inactivityTimeoutMs,
    ),
    interactDurationMs: positiveNumber(
      overrides.interactDurationMs,
      DEFAULT_PIXEL_PET_CONFIG.interactDurationMs,
    ),
    mediumHeightPx: positiveNumber(
      overrides.mediumHeightPx,
      DEFAULT_PIXEL_PET_CONFIG.mediumHeightPx,
    ),
    smallHeightPx: positiveNumber(
      overrides.smallHeightPx,
      DEFAULT_PIXEL_PET_CONFIG.smallHeightPx,
    ),
    walkSpeedPxPerSecond: positiveNumber(
      overrides.walkSpeedPxPerSecond,
      DEFAULT_PIXEL_PET_CONFIG.walkSpeedPxPerSecond,
    ),
    zIndex: Number.isFinite(overrides.zIndex)
      ? Number(overrides.zIndex)
      : DEFAULT_PIXEL_PET_CONFIG.zIndex,
  };
}

export function getPixelPetScreenSize(
  size: PixelPetSize,
  frameSize: PixelPetFrameSize = FALLBACK_PIXEL_PET_FRAME_SIZE,
  config: PixelPetConfig = DEFAULT_PIXEL_PET_CONFIG,
): PixelPetScreenSize {
  const height = size === "medium" ? config.mediumHeightPx : config.smallHeightPx;
  return {
    height,
    width: Math.max(1, Math.round(height * (frameSize.width / frameSize.height))),
  };
}

function positiveNumber(value: number | undefined, fallback: number) {
  return Number.isFinite(value) && Number(value) > 0 ? Number(value) : fallback;
}
