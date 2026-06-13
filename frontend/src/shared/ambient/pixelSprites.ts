// ── Pixel-art guard character sprites ──────────────────────────
// Each sprite is 10 columns × 14 rows.
// Color indices: 0=transparent 1=primary 2=secondary 3=highlight 4=outline 5=boot

import type { ThemeMode } from "../../stores/uiStore";

// ── Per-theme palettes ─────────────────────────────────────────
export interface SpritePalette {
  primary: string;
  secondary: string;
  highlight: string;
  outline: string;
  boot: string;
}

const PALETTE_DARK: SpritePalette = {
  primary: "#2f81f7",
  secondary: "#1f5fa8",
  highlight: "#8ab8ff",
  outline: "#0d0f14",
  boot: "#5c627a",
};

const PALETTE_LIGHT: SpritePalette = {
  primary: "#2f81f7",
  secondary: "#1554a8",
  highlight: "#4d94ff",
  outline: "#181e2e",
  boot: "#8890a2",
};

const PALETTE_DEEP_DARK: SpritePalette = {
  primary: "#3d8bf7",
  secondary: "#2f6fc8",
  highlight: "#80b4ff",
  outline: "#05070d",
  boot: "#4a5268",
};

const PALETTES: Record<Exclude<ThemeMode, "system">, SpritePalette> = {
  dark: PALETTE_DARK,
  light: PALETTE_LIGHT,
  "deep-dark": PALETTE_DEEP_DARK,
};

export function getSpritePalette(theme: ThemeMode): SpritePalette {
  return PALETTES[theme === "system" ? "dark" : theme];
}

// ── Sprite frame type ──────────────────────────────────────────
// 10 columns × 14 rows, each cell a color index (0–5)
export type SpriteFrame = readonly (readonly number[])[];

export const SPRITE_W = 10;
export const SPRITE_H = 14;

// ── Idle animation (2 frames — gentle bounce) ──────────────────
const IDLE_0: SpriteFrame = [
  [0, 0, 0, 1, 1, 1, 1, 0, 0, 0], // row 0  top of helmet
  [0, 0, 1, 1, 1, 1, 1, 1, 0, 0], // row 1  helmet dome
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0], // row 2  helmet sides
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0], // row 3  helmet wide
  [0, 3, 1, 1, 3, 0, 3, 1, 1, 3], // row 4  visor glow
  [0, 0, 2, 2, 2, 2, 2, 2, 2, 0], // row 5  visor bar
  [0, 0, 0, 2, 2, 2, 2, 2, 0, 0], // row 6  chin
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0], // row 7  shoulders
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0], // row 8  chest
  [0, 1, 1, 0, 1, 1, 1, 0, 1, 1], // row 9  arms out
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0], // row 10 torso
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0], // row 11 waist
  [0, 0, 0, 5, 0, 0, 0, 5, 0, 0], // row 12 legs / boots
  [0, 0, 0, 5, 5, 0, 5, 5, 0, 0], // row 13 boots base
];

const IDLE_1: SpriteFrame = [
  [0, 0, 0, 1, 1, 1, 1, 0, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 0, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 3, 1, 1, 3, 0, 3, 1, 1, 3],
  [0, 0, 2, 2, 2, 2, 2, 2, 2, 0],
  [0, 0, 0, 2, 2, 2, 2, 2, 0, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 1, 1, 0, 1, 1, 1, 0, 1, 1],
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 0, 0, 5, 0, 5, 0, 0, 0], // legs shifted up (bounce)
  [0, 0, 0, 5, 5, 0, 5, 5, 0, 0],
];

// ── Walk animation (4 frames) ──────────────────────────────────
const WALK_0: SpriteFrame = [
  [0, 0, 0, 1, 1, 1, 1, 0, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 0, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 3, 1, 1, 3, 0, 3, 1, 1, 3],
  [0, 0, 2, 2, 2, 2, 2, 2, 2, 0],
  [0, 0, 0, 2, 2, 2, 2, 2, 0, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 1, 0, 1, 1, 1, 1, 0, 1, 0], // left arm forward
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 5, 0, 0, 0, 0, 5, 0, 0], // step: left foot forward
  [0, 5, 5, 0, 0, 0, 5, 5, 0, 0],
];

const WALK_1: SpriteFrame = [
  [0, 0, 0, 1, 1, 1, 1, 0, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 0, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 3, 1, 1, 3, 0, 3, 1, 1, 3],
  [0, 0, 2, 2, 2, 2, 2, 2, 2, 0],
  [0, 0, 0, 2, 2, 2, 2, 2, 0, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 1, 0, 1, 1, 1, 1, 1, 0, 1], // arms neutral
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 5, 5, 0, 0, 5, 5, 0, 0], // legs together
  [0, 0, 5, 5, 0, 0, 5, 5, 0, 0],
];

const WALK_2: SpriteFrame = [
  [0, 0, 0, 1, 1, 1, 1, 0, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 0, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 3, 1, 1, 3, 0, 3, 1, 1, 3],
  [0, 0, 2, 2, 2, 2, 2, 2, 2, 0],
  [0, 0, 0, 2, 2, 2, 2, 2, 0, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 0, 1, 1, 1, 1, 0, 1, 0, 1], // right arm forward
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 0, 0, 5, 0, 0, 0, 5, 0], // step: right foot forward
  [0, 0, 0, 5, 5, 0, 0, 5, 5, 0],
];

const WALK_3: SpriteFrame = [
  [0, 0, 0, 1, 1, 1, 1, 0, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 0, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 3, 1, 1, 3, 0, 3, 1, 1, 3],
  [0, 0, 2, 2, 2, 2, 2, 2, 2, 0],
  [0, 0, 0, 2, 2, 2, 2, 2, 0, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 1, 0, 1, 1, 1, 1, 1, 0, 1], // arms neutral
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 5, 5, 0, 0, 5, 5, 0, 0], // legs together
  [0, 0, 5, 5, 0, 0, 5, 5, 0, 0],
];

// ── Jump frame ─────────────────────────────────────────────────
const JUMP: SpriteFrame = [
  [0, 0, 0, 1, 1, 1, 1, 0, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 0, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 3, 1, 1, 3, 0, 3, 1, 1, 3],
  [0, 0, 2, 2, 2, 2, 2, 2, 2, 0],
  [0, 0, 0, 2, 2, 2, 2, 2, 0, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 0, 1, 0, 1, 1, 1, 0, 1, 0], // arms up
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 5, 0, 0, 0, 0, 5, 0, 0], // feet apart
  [0, 5, 5, 0, 0, 0, 5, 5, 0, 0],
];

// ── Sit / idle variant ─────────────────────────────────────────
const SIT: SpriteFrame = [
  [0, 0, 0, 1, 1, 1, 1, 0, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 0, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 1, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 3, 1, 1, 3, 0, 3, 1, 1, 3],
  [0, 0, 2, 2, 2, 2, 2, 2, 2, 0],
  [0, 0, 0, 2, 2, 2, 2, 2, 0, 0],
  [0, 0, 0, 1, 1, 1, 1, 1, 0, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
  [0, 0, 1, 0, 1, 1, 1, 0, 1, 0],
  [0, 0, 1, 1, 1, 1, 1, 1, 1, 0], // torso (same as above)
  [0, 0, 5, 5, 5, 5, 5, 5, 5, 0], // legs folded / sitting
  [0, 0, 5, 0, 0, 0, 0, 5, 0, 0],
  [0, 0, 5, 5, 0, 0, 5, 5, 0, 0],
];

// ── Exported animation sets ────────────────────────────────────
export const IDLE_FRAMES: readonly SpriteFrame[] = [IDLE_0, IDLE_1];
export const WALK_FRAMES: readonly SpriteFrame[] = [WALK_0, WALK_1, WALK_2, WALK_3];
export const JUMP_FRAME: SpriteFrame = JUMP;
export const SIT_FRAME: SpriteFrame = SIT;

// ── Timing constants ───────────────────────────────────────────
export const IDLE_FRAME_MS = 500; // ms per idle frame
export const WALK_FRAME_MS = 160; // ms per walk frame
