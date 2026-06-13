// ── Character AI: state machine, movement, and behavior ─────────
// Pure-logic module (no React / DOM imports). Testable in isolation.

import type { SpriteFrame } from "./pixelSprites";
import {
  IDLE_FRAMES,
  WALK_FRAMES,
  JUMP_FRAME,
  SIT_FRAME,
  IDLE_FRAME_MS,
  WALK_FRAME_MS,
  SPRITE_W,
  SPRITE_H,
} from "./pixelSprites";

// ── Types ──────────────────────────────────────────────────────
export type CharState = "idle" | "walk" | "jump" | "sit";

export interface CharacterPose {
  /** Current state (drives animation selection). */
  state: CharState;
  /** -1 = facing left, 1 = facing right. */
  direction: -1 | 1;
  /** Current frame within the animation set. */
  frameIndex: number;
  /** Timestamp (ms) of last frame advance. */
  lastFrameAdvance: number;
  /** Pixel position (top-left of sprite bounding box). */
  x: number;
  y: number;
  /** Vertical velocity (pixels per ms) — only used during jump. */
  vy: number;
  /** Ground level y (bottom of walking area). */
  groundY: number;
  /** Phase timestamp for state transitions. */
  stateEnteredAt: number;
  /** State-specific duration (ms). */
  stateDuration: number;
  /** Target x for walk-to behavior (-1 = wander). */
  targetX: number;
}

// ── Constants ──────────────────────────────────────────────────
const PX = 4; // pixel-art scale factor (each sprite "pixel" = 4 screen px)
export const CHAR_SCREEN_W = SPRITE_W * PX; // 40
export const CHAR_SCREEN_H = SPRITE_H * PX; // 56

const WALK_SPEED = 0.04; // px per ms (~40 px/s)
const JUMP_VELOCITY = -0.22; // initial upward velocity
const GRAVITY = 0.0005; // gravity per ms²
const GROUND_MARGIN = 8; // px above bottom of viewport

const IDLE_MIN_MS = 1200;
const IDLE_MAX_MS = 4000;
const WALK_MIN_MS = 2000;
const WALK_MAX_MS = 6000;
const SIT_MIN_MS = 3000;
const SIT_MAX_MS = 9000;
const JUMP_COOLDOWN_MS = 6000;

// ── UI zone detector ───────────────────────────────────────────
// We sample a few known DOM classes to approximate the "safe" walking area.
// A more accurate approach would use elementFromPoint, but that is
// expensive per-frame.  Instead we pre-compute safe bounds on resize.
export interface SafeZone {
  /** Y below which the character walks (ground level). */
  groundY: number;
  /** X range where the character can walk freely. */
  minX: number;
  maxX: number;
}

/**
 * Compute a safe walking zone from the current viewport.
 * Characters walk in the bottom portion of the screen,
 * avoiding the status-strip and the toolbar.
 */
export function computeSafeZone(
  viewportW: number,
  viewportH: number,
): SafeZone {
  // Walk on the bottom ~25% of the screen, but stay above the status strip
  const groundY = viewportH - 32 - CHAR_SCREEN_H;
  return {
    groundY: Math.max(CHAR_SCREEN_H + 8, groundY),
    minX: 0,
    maxX: Math.max(0, viewportW - CHAR_SCREEN_W),
  };
}

// ── Factory ────────────────────────────────────────────────────
export function createCharacter(viewportW: number, viewportH: number): CharacterPose {
  const zone = computeSafeZone(viewportW, viewportH);
  return {
    state: "idle",
    direction: 1,
    frameIndex: 0,
    lastFrameAdvance: 0,
    x: zone.minX + Math.random() * Math.max(0, zone.maxX - zone.minX),
    y: zone.groundY,
    vy: 0,
    groundY: zone.groundY,
    stateEnteredAt: 0,
    stateDuration: randomBetween(IDLE_MIN_MS, IDLE_MAX_MS),
    targetX: -1,
  };
}

// ── State machine update ───────────────────────────────────────
export function updateCharacter(
  ch: CharacterPose,
  now: number,
  dt: number,
  viewportW: number,
  viewportH: number,
  mouseX: number,
  mouseY: number,
): CharacterPose {
  const zone = computeSafeZone(viewportW, viewportH);
  const next = { ...ch, groundY: zone.groundY };

  // Clamp x to safe zone
  if (next.x < zone.minX) next.x = zone.minX;
  if (next.x > zone.maxX) next.x = zone.maxX;

  // ── Physics ──────────────────────────────────────────────────
  if (next.state === "jump") {
    next.vy += GRAVITY * dt;
    next.y += next.vy * dt;
    if (next.y >= next.groundY) {
      next.y = next.groundY;
      next.vy = 0;
      next.state = "idle";
      next.stateEnteredAt = now;
      next.stateDuration = randomBetween(IDLE_MIN_MS, IDLE_MAX_MS);
      next.frameIndex = 0;
    }
  } else {
    next.y = next.groundY;
    next.vy = 0;
  }

  // ── Face the mouse if nearby ─────────────────────────────────
  if (mouseX < next.x + CHAR_SCREEN_W / 2) {
    next.direction = -1;
  } else {
    next.direction = 1;
  }

  // ── State transitions ────────────────────────────────────────
  const elapsed = now - next.stateEnteredAt;

  if (next.state === "idle") {
    if (elapsed >= next.stateDuration) {
      // Weighted random: mostly walk, sometimes sit, rarely jump
      const roll = Math.random();
      if (roll < 0.55) {
        next.state = "walk";
        next.stateDuration = randomBetween(WALK_MIN_MS, WALK_MAX_MS);
        next.targetX =
          Math.random() < 0.5
            ? zone.minX + Math.random() * (zone.maxX - zone.minX) * 0.3
            : zone.minX +
              (zone.maxX - zone.minX) * 0.7 +
              Math.random() * (zone.maxX - zone.minX) * 0.3;
      } else if (roll < 0.8) {
        next.state = "sit";
        next.stateDuration = randomBetween(SIT_MIN_MS, SIT_MAX_MS);
      } else {
        // Jump!
        next.state = "jump";
        next.vy = JUMP_VELOCITY;
        next.stateDuration = 0;
      }
      next.stateEnteredAt = now;
      next.frameIndex = 0;
    }
  } else if (next.state === "walk") {
    // Move toward target
    const cx = next.x + CHAR_SCREEN_W / 2;
    if (next.targetX >= 0) {
      const dx = next.targetX - cx;
      if (Math.abs(dx) < 4) {
        // Reached target
        next.state = "idle";
        next.stateEnteredAt = now;
        next.stateDuration = randomBetween(IDLE_MIN_MS, IDLE_MAX_MS);
        next.frameIndex = 0;
        next.targetX = -1;
      } else {
        next.x += Math.sign(dx) * WALK_SPEED * dt;
        next.direction = (Math.sign(dx) as -1 | 1);
      }
    }
    if (elapsed >= next.stateDuration) {
      next.state = "idle";
      next.stateEnteredAt = now;
      next.stateDuration = randomBetween(IDLE_MIN_MS, IDLE_MAX_MS);
      next.frameIndex = 0;
      next.targetX = -1;
    }
    // Occasionally jump while walking
    if (
      next.state === "walk" &&
      elapsed > 800 &&
      Math.random() < 0.0008 * dt
    ) {
      next.state = "jump";
      next.vy = JUMP_VELOCITY;
      next.stateEnteredAt = now;
      next.frameIndex = 0;
    }
  } else if (next.state === "sit") {
    if (elapsed >= next.stateDuration) {
      next.state = "idle";
      next.stateEnteredAt = now;
      next.stateDuration = randomBetween(IDLE_MIN_MS, IDLE_MAX_MS);
      next.frameIndex = 0;
    }
  } else if (next.state === "jump") {
    // Jump ends via physics (see above)
  }

  // ── Frame advance ────────────────────────────────────────────
  const frameMs = next.state === "walk" ? WALK_FRAME_MS : IDLE_FRAME_MS;
  const frameCount =
    next.state === "walk"
      ? WALK_FRAMES.length
      : next.state === "jump"
        ? 1
        : next.state === "sit"
          ? 1
          : IDLE_FRAMES.length;

  if (now - next.lastFrameAdvance >= frameMs && frameCount > 1) {
    next.frameIndex = (next.frameIndex + 1) % frameCount;
    next.lastFrameAdvance = now;
  }

  return next;
}

// ── Current sprite frame ───────────────────────────────────────
export function getCurrentFrame(ch: CharacterPose): SpriteFrame {
  switch (ch.state) {
    case "walk":
      return WALK_FRAMES[ch.frameIndex % WALK_FRAMES.length];
    case "jump":
      return JUMP_FRAME;
    case "sit":
      return SIT_FRAME;
    default:
      return IDLE_FRAMES[ch.frameIndex % IDLE_FRAMES.length];
  }
}

// ── Utility ────────────────────────────────────────────────────
function randomBetween(min: number, max: number): number {
  return min + Math.random() * (max - min);
}
