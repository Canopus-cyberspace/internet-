import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("./usePixelPet", () => ({
  usePixelPet: () => ({
    bindings: {
      onClick: () => undefined,
      onKeyDown: () => undefined,
      onPointerCancel: () => undefined,
      onPointerDown: () => undefined,
      onPointerMove: () => undefined,
      onPointerUp: () => undefined,
    },
    enabled: true,
    view: {
      animationKey: 3,
      direction: -1,
      fps: 8,
      frameCount: 6,
      position: { x: 120, y: 320 },
      reducedMotion: false,
      screenSize: { height: 92, width: 65 },
      spriteUrl: "/assets/pet/drag_6frames_transparent.png",
      state: "drag",
      zIndex: 10,
    },
  }),
}));

describe("PixelPet sprite-sheet shell", () => {
  it("renders only the sprite-sheet desktop pet body without a hover name", async () => {
    const { PixelPet } = await import("./PixelPet");

    const markup = renderToStaticMarkup(<PixelPet />);

    expect(markup).toContain("pixel-pet-layer");
    expect(markup).toContain("pixel-pet-sprite-sheet");
    expect(markup).toContain('aria-label="Desktop pet"');
    expect(markup).toContain('data-state="drag"');
    expect(markup).toContain("/assets/pet/drag_6frames_transparent.png");
    expect(markup).toContain("--pixel-pet-facing-scale:1");
    expect(markup).toContain("--pixel-pet-frame-count:6");
    expect(markup).not.toContain("title=");
    expect(markup).not.toContain("background-color");
    expect(markup).not.toContain("pixel-pet-tooltip");
    expect(markup).not.toContain("pixel-pet-heart");
    expect(markup).not.toContain("pixel-pet-speech");
  });

  it("uses document.body as the runtime portal target", async () => {
    const { getPixelPetPortalTarget } = await import("./PixelPet");
    const body = {} as HTMLElement;

    expect(getPixelPetPortalTarget({ body } as Document)).toBe(body);
    expect(getPixelPetPortalTarget(null)).toBeNull();
  });
});
