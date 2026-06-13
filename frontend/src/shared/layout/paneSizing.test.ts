import { describe, expect, it } from "vitest";
import { clampPaneSize, paneSizeFromDrag, PANE_SIZE_LIMITS } from "./paneSizing";

describe("pane sizing", () => {
  it("clamps panes to their supported limits", () => {
    expect(clampPaneSize(80, PANE_SIZE_LIMITS.sidebar)).toBe(180);
    expect(clampPaneSize(999, PANE_SIZE_LIMITS.detailDrawer)).toBe(560);
    expect(clampPaneSize(260.4, PANE_SIZE_LIMITS.bottomGraph)).toBe(260);
  });

  it("uses the pane default when a size is not finite", () => {
    expect(clampPaneSize(Number.NaN, PANE_SIZE_LIMITS.splitSecondary)).toBe(320);
  });

  it("calculates forward and reverse drag deltas", () => {
    expect(
      paneSizeFromDrag({
        currentPoint: 320,
        limits: PANE_SIZE_LIMITS.sidebar,
        reverse: false,
        startPoint: 260,
        startSize: 240,
      }),
    ).toBe(300);

    expect(
      paneSizeFromDrag({
        currentPoint: 260,
        limits: PANE_SIZE_LIMITS.detailDrawer,
        reverse: true,
        startPoint: 320,
        startSize: 360,
      }),
    ).toBe(420);
  });

  it("keeps drag results inside min and max boundaries", () => {
    expect(
      paneSizeFromDrag({
        currentPoint: -900,
        limits: PANE_SIZE_LIMITS.bottomGraph,
        reverse: false,
        startPoint: 0,
        startSize: 300,
      }),
    ).toBe(180);

    expect(
      paneSizeFromDrag({
        currentPoint: -900,
        limits: PANE_SIZE_LIMITS.bottomGraph,
        reverse: true,
        startPoint: 0,
        startSize: 300,
      }),
    ).toBe(520);
  });
});
