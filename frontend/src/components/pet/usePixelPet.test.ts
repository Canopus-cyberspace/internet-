import { describe, expect, it } from "vitest";
import {
  DEFAULT_PIXEL_PET_CONFIG,
  resolvePixelPetConfig,
} from "./pixelPetAssets";
import {
  PIXEL_PET_ACTIVITY_EVENTS,
  advanceTowardTarget,
  reconcilePixelPetSafeZoneChange,
  updatePixelPetMotion,
} from "./usePixelPet";
import type { PetRect } from "./petSafeAreas";

describe("PixelPet 2D target movement", () => {
  const safeRects: PetRect[] = [{ height: 300, width: 420, x: 100, y: 80 }];

  it("moves both x and y toward a safe target instead of staying on a bottom lane", () => {
    const result = advanceTowardTarget({
      current: { x: 120, y: 110 },
      currentDirection: 1,
      dtMs: 1_000,
      speedPxPerSecond: 100,
      target: { x: 220, y: 210 },
      targetReachedPx: 3,
    });

    expect(result.arrived).toBe(false);
    expect(result.direction).toBe(1);
    expect(result.position.x).toBeCloseTo(190.71, 2);
    expect(result.position.y).toBeCloseTo(180.71, 2);
  });

  it("chooses a random 2D target and keeps walking until it is reached", () => {
    const config = resolvePixelPetConfig({
      inactivityTimeoutMs: 5_000,
      walkSpeedPxPerSecond: 50,
    });
    const result = updatePixelPetMotion({
      config,
      direction: 1,
      dtMs: 1_000,
      interactUntil: 0,
      lastActivityAt: 0,
      nextWalkAt: 0,
      now: 1_000,
      position: { x: 120, y: 120 },
      random: sequenceRandom([0.8, 0.7]),
      safeRects,
      state: "idle",
      target: null,
    });

    expect(result.state).toBe("walk");
    expect(result.target).toEqual({ x: 436, y: 290 });
    expect(result.position.x).toBeGreaterThan(120);
    expect(result.position.y).toBeGreaterThan(120);
  });

  it("idles and clears the target after arriving", () => {
    const config = resolvePixelPetConfig({ walkSpeedPxPerSecond: 80 });
    const result = updatePixelPetMotion({
      config,
      direction: -1,
      dtMs: 1_000,
      interactUntil: 0,
      lastActivityAt: 0,
      nextWalkAt: 0,
      now: 1_000,
      position: { x: 130, y: 130 },
      random: sequenceRandom([0.2]),
      safeRects,
      state: "walk",
      target: { x: 140, y: 145 },
    });

    expect(result).toMatchObject({
      position: { x: 140, y: 145 },
      restartAnimation: true,
      state: "idle",
      target: null,
    });
    expect(result.nextWalkAt).toBeGreaterThan(1_000);
  });

  it("stays idle when no safe route exists", () => {
    const config = resolvePixelPetConfig({ walkSpeedPxPerSecond: 80 });
    expect(
      updatePixelPetMotion({
        config,
        direction: 1,
        dtMs: 1_000,
        interactUntil: 0,
        lastActivityAt: 0,
        nextWalkAt: 0,
        now: 1_000,
        position: { x: 20, y: 20 },
        safeRects: [],
        state: "idle",
        target: null,
      }),
    ).toMatchObject({
      position: { x: 20, y: 20 },
      state: "idle",
      target: null,
    });
  });

  it("uses a 60 second default inactivity timeout", () => {
    expect(DEFAULT_PIXEL_PET_CONFIG.inactivityTimeoutMs).toBe(60_000);
    expect(
      updatePixelPetMotion({
        config: DEFAULT_PIXEL_PET_CONFIG,
        direction: 1,
        dtMs: 16,
        interactUntil: 0,
        lastActivityAt: 0,
        nextWalkAt: 0,
        now: 59_999,
        position: { x: 130, y: 130 },
        safeRects,
        state: "walk",
        target: { x: 300, y: 300 },
      }).state,
    ).toBe("walk");
    expect(
      updatePixelPetMotion({
        config: DEFAULT_PIXEL_PET_CONFIG,
        direction: 1,
        dtMs: 16,
        interactUntil: 0,
        lastActivityAt: 0,
        nextWalkAt: 0,
        now: 60_000,
        position: { x: 130, y: 130 },
        safeRects,
        state: "walk",
        target: { x: 300, y: 300 },
      }),
    ).toMatchObject({
      state: "sleepy",
      target: null,
    });
  });

  it("preserves drag, interact, sleepy loop, and wake transitions by priority", () => {
    const config = resolvePixelPetConfig({
      inactivityTimeoutMs: 5_000,
      interactDurationMs: 1_000,
    });

    expect(
      updatePixelPetMotion({
        config,
        direction: 1,
        dtMs: 16,
        interactUntil: 8_000,
        lastActivityAt: 0,
        nextWalkAt: 3_000,
        now: 7_000,
        position: { x: 130, y: 130 },
        safeRects,
        state: "interact",
        target: { x: 300, y: 300 },
      }),
    ).toMatchObject({
      state: "interact",
      target: null,
    });

    expect(
      updatePixelPetMotion({
        config,
        direction: -1,
        dtMs: 16,
        interactUntil: 0,
        lastActivityAt: 0,
        nextWalkAt: 0,
        now: 7_000,
        position: { x: 130, y: 130 },
        safeRects,
        state: "drag",
        target: { x: 300, y: 300 },
      }),
    ).toMatchObject({
      restartAnimation: false,
      state: "drag",
      target: null,
    });

    expect(
      updatePixelPetMotion({
        config,
        direction: 1,
        dtMs: 16,
        interactUntil: 0,
        lastActivityAt: 1_000,
        nextWalkAt: 0,
        now: 7_000,
        position: { x: 130, y: 130 },
        safeRects,
        state: "walk",
        target: { x: 300, y: 300 },
      }),
    ).toMatchObject({
      restartAnimation: true,
      state: "sleepy",
      target: null,
    });

    expect(
      updatePixelPetMotion({
        config,
        direction: -1,
        dtMs: 16,
        interactUntil: 0,
        lastActivityAt: 7_500,
        nextWalkAt: 9_000,
        now: 8_000,
        position: { x: 130, y: 130 },
        safeRects,
        state: "sleepy",
        target: null,
      }),
    ).toMatchObject({
      restartAnimation: true,
      state: "idle",
    });

    expect(
      updatePixelPetMotion({
        config,
        direction: -1,
        dtMs: 16,
        interactUntil: 0,
        lastActivityAt: 1_000,
        nextWalkAt: 0,
        now: 7_500,
        position: { x: 130, y: 130 },
        safeRects,
        state: "sleepy",
        target: { x: 300, y: 300 },
      }),
    ).toMatchObject({
      restartAnimation: false,
      state: "sleepy",
      target: null,
    });
  });

  it("keeps viewport coordinates stable across route safe-zone refreshes", () => {
    const refreshedSafeRects: PetRect[] = [
      { height: 160, width: 220, x: 200, y: 120 },
    ];

    expect(
      reconcilePixelPetSafeZoneChange({
        fallback: { x: 420, y: 280 },
        position: { x: 240, y: 140 },
        safeRects: refreshedSafeRects,
        target: { x: 300, y: 180 },
      }),
    ).toEqual({
      position: { x: 240, y: 140 },
      target: { x: 300, y: 180 },
    });

    expect(
      reconcilePixelPetSafeZoneChange({
        fallback: { x: 420, y: 280 },
        position: { x: 20, y: 20 },
        safeRects: refreshedSafeRects,
        target: { x: 20, y: 20 },
      }),
    ).toEqual({
      position: { x: 200, y: 120 },
      target: null,
    });
  });

  it("listens to activity events that reset sleep and drag timers", () => {
    expect(PIXEL_PET_ACTIVITY_EVENTS).toEqual([
      "mousemove",
      "pointerdown",
      "click",
      "keydown",
      "touchstart",
      "wheel",
      "scroll",
    ]);
  });
});

function sequenceRandom(values: number[]) {
  let index = 0;
  return () => values[index++] ?? values.at(-1) ?? 0;
}
