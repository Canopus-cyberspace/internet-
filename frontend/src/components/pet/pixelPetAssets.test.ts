import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_PIXEL_PET_CONFIG,
  FALLBACK_PIXEL_PET_FRAME_SIZE,
  INACTIVITY_TIMEOUT_MS,
  PIXEL_PET_DRAG_FRAME_COUNT,
  PIXEL_PET_FRAME_COUNT,
  PIXEL_PET_SPRITE_ASSETS,
  PIXEL_PET_STATE_ASSETS,
  PIXEL_PET_STATE_FRAME_COUNTS,
  getPixelPetScreenSize,
  resolvePixelPetConfig,
} from "./pixelPetAssets";

describe("PixelPet sprite-sheet assets", () => {
  it("uses the transparent sprite-sheet PNG paths and per-state frame counts", () => {
    expect(PIXEL_PET_FRAME_COUNT).toBe(8);
    expect(PIXEL_PET_DRAG_FRAME_COUNT).toBe(6);
    expect(INACTIVITY_TIMEOUT_MS).toBe(60_000);
    expect(PIXEL_PET_SPRITE_ASSETS).toEqual({
      drag: "/assets/pet/drag_6frames_transparent.png",
      interact: "/assets/pet/interact_click_8frames_transparent.png",
      sleepy: "/assets/pet/sleepy_8frames_transparent.png",
      walk: "/assets/pet/walk_left_8frames_transparent.png",
    });
    expect(PIXEL_PET_STATE_ASSETS.idle).toBe(PIXEL_PET_SPRITE_ASSETS.walk);
    expect(PIXEL_PET_STATE_ASSETS.walk).toBe(PIXEL_PET_SPRITE_ASSETS.walk);
    expect(PIXEL_PET_STATE_ASSETS.sleepy).toBe(PIXEL_PET_SPRITE_ASSETS.sleepy);
    expect(PIXEL_PET_STATE_ASSETS.interact).toBe(
      PIXEL_PET_SPRITE_ASSETS.interact,
    );
    expect(PIXEL_PET_STATE_ASSETS.drag).toBe(PIXEL_PET_SPRITE_ASSETS.drag);
    expect(PIXEL_PET_STATE_FRAME_COUNTS).toEqual({
      drag: 6,
      idle: 8,
      interact: 8,
      sleepy: 8,
      walk: 8,
    });
  });

  it("ships all transparent sprite sheets from the Vite public asset directory", () => {
    for (const [state, assetPath] of Object.entries(PIXEL_PET_SPRITE_ASSETS)) {
      const dimensions = pngDimensions(assetPath);
      const frameCount = PIXEL_PET_STATE_FRAME_COUNTS[state as keyof typeof PIXEL_PET_SPRITE_ASSETS];
      expect(dimensions.width).toBeGreaterThan(dimensions.height);
      expect(dimensions.height).toBeGreaterThan(0);
      expect(dimensions.width / frameCount).toBeGreaterThan(0);
    }
    for (const removedAsset of [
      "/assets/pet/drag_6frames.png",
      "/assets/pet/interact_click_8frames.png",
      "/assets/pet/sleepy_8frames.png",
      "/assets/pet/walk_right_8frames.png",
    ]) {
      expect(publicAssetExists(removedAsset)).toBe(false);
    }
  });

  it("keeps rendered pet sizes stable across configured small and medium sizes", () => {
    expect(getPixelPetScreenSize("small")).toEqual({ height: 92, width: 65 });
    expect(getPixelPetScreenSize("medium")).toEqual({ height: 116, width: 82 });
    expect(
      getPixelPetScreenSize(
        "small",
        FALLBACK_PIXEL_PET_FRAME_SIZE,
        resolvePixelPetConfig({ smallHeightPx: 80 }),
      ),
    ).toEqual({ height: 80, width: 56 });
    expect(DEFAULT_PIXEL_PET_CONFIG.defaultPosition).toBe("bottom-right");
    expect(DEFAULT_PIXEL_PET_CONFIG.inactivityTimeoutMs).toBe(60_000);
  });
});

function pngDimensions(assetPath: string) {
  const bytes = readFileSync(
    new URL(`../../../public${assetPath}`, import.meta.url),
  );
  expect(bytes.subarray(0, 8)).toEqual(
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  );
  return {
    height: bytes.readUInt32BE(20),
    width: bytes.readUInt32BE(16),
  };
}

function publicAssetExists(assetPath: string) {
  return existsSync(new URL(`../../../public${assetPath}`, import.meta.url));
}
