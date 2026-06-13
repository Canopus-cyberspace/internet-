import { describe, expect, it } from "vitest";
import {
  PIXEL_PET_OBSTACLE_SELECTORS,
  chooseDefaultPetPosition,
  chooseSafeRoamTarget,
  clampPointToSafeRects,
  computeConservativeAppShellSafeRects,
  computePixelPetSafeRects,
  findContainingSafeRect,
  pointInsideRect,
  randomPointInRect,
  type PetRect,
} from "./petSafeAreas";

describe("PixelPet safe areas", () => {
  it("subtracts controls and dense regions from full-window movement space", () => {
    const obstacles = [
      { height: 64, width: 900, x: 0, y: 0 },
      { height: 600, width: 220, x: 0, y: 64 },
      { height: 600, width: 280, x: 620, y: 64 },
      { height: 120, width: 400, x: 220, y: 544 },
    ];
    const petSize = { height: 90, width: 64 };
    const safeRects = computePixelPetSafeRects({
      boundaryPaddingPx: 10,
      obstaclePaddingPx: 0,
      obstacles,
      petSize,
      viewport: { height: 700, width: 900 },
    });

    expect(safeRects).toContainEqual({
      height: 390,
      width: 336,
      x: 220,
      y: 64,
    });
    for (const rect of safeRects) {
      for (const point of [
        { x: rect.x, y: rect.y },
        { x: rect.x + rect.width, y: rect.y },
        { x: rect.x, y: rect.y + rect.height },
        { x: rect.x + rect.width, y: rect.y + rect.height },
      ]) {
        const footprint = {
          height: petSize.height,
          width: petSize.width,
          x: point.x,
          y: point.y,
        };
        expect(obstacles.some((obstacle) => intersects(footprint, obstacle))).toBe(
          false,
        );
      }
    }
  });

  it("keeps a route target inside the current safe rectangle", () => {
    const left: PetRect = { height: 200, width: 200, x: 20, y: 20 };
    const right: PetRect = { height: 200, width: 200, x: 360, y: 20 };
    const target = chooseSafeRoamTarget({
      current: { x: 80, y: 80 },
      minDistancePx: 40,
      random: sequenceRandom([0.8, 0.8]),
      safeRects: [left, right],
    });

    expect(target).toEqual({ x: 180, y: 180 });
    expect(findContainingSafeRect(target!, [left, right])).toBe(left);
  });

  it("clamps manual drag positions to the nearest free rectangle", () => {
    const safeRects: PetRect[] = [
      { height: 120, width: 120, x: 20, y: 20 },
      { height: 120, width: 120, x: 300, y: 20 },
    ];

    expect(clampPointToSafeRects({ x: 250, y: 80 }, safeRects)).toEqual({
      x: 300,
      y: 80,
    });
    expect(pointInsideRect(randomPointInRect(safeRects[0], () => 0.5), safeRects[0])).toBe(
      true,
    );
    expect(chooseDefaultPetPosition(safeRects, "bottom-right")).toEqual({
      x: 420,
      y: 140,
    });
  });

  it("registers chrome controls as obstacles without blocking content areas", () => {
    expect(PIXEL_PET_OBSTACLE_SELECTORS).toContain(".top-toolbar");
    expect(PIXEL_PET_OBSTACLE_SELECTORS).toContain(".navigation-tree");
    expect(PIXEL_PET_OBSTACLE_SELECTORS).toContain(".status-strip");
    expect(PIXEL_PET_OBSTACLE_SELECTORS).toContain(".detail-drawer");
    expect(PIXEL_PET_OBSTACLE_SELECTORS).toContain(".pane-resize-handle");
    expect(PIXEL_PET_OBSTACLE_SELECTORS).toContain(
      "[data-drag-out-detach-handle='true']",
    );
    expect(PIXEL_PET_OBSTACLE_SELECTORS).toContain("[role='dialog']");
    expect(PIXEL_PET_OBSTACLE_SELECTORS).toContain("dialog");
    expect(PIXEL_PET_OBSTACLE_SELECTORS).not.toContain(".bottom-graph-pane");
    expect(PIXEL_PET_OBSTACLE_SELECTORS).not.toContain(".graph-canvas-shell");
    expect(PIXEL_PET_OBSTACLE_SELECTORS).not.toContain(".graph-canvas-region");
    // Content-area elements are no longer obstacles — the pet roams freely
    expect(PIXEL_PET_OBSTACLE_SELECTORS).not.toContain("table");
    expect(PIXEL_PET_OBSTACLE_SELECTORS).not.toContain(".page-header");
    expect(PIXEL_PET_OBSTACLE_SELECTORS).not.toContain(".shell-table-scroll");
  });

  it("keeps the conservative fallback above the bottom graph in cramped windows", () => {
    const safeRects = computeConservativeAppShellSafeRects(
      { height: 484, width: 762 },
      { height: 92, width: 65 },
      16,
      [
        { height: 48, width: 762, x: 0, y: 0 },
        { height: 412, width: 48, x: 0, y: 48 },
        { height: 300, width: 714, x: 48, y: 160 },
        { height: 24, width: 762, x: 0, y: 460 },
      ],
    );

    expect(safeRects[0].y + 92).toBeLessThanOrEqual(160);
  });
});

function sequenceRandom(values: number[]) {
  let index = 0;
  return () => values[index++] ?? values.at(-1) ?? 0;
}

function intersects(a: PetRect, b: PetRect) {
  return (
    a.x < b.x + b.width &&
    a.x + a.width > b.x &&
    a.y < b.y + b.height &&
    a.y + a.height > b.y
  );
}
