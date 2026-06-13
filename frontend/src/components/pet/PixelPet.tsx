import type { CSSProperties } from "react";
import { createPortal } from "react-dom";
import type { PixelPetConfig } from "./pixelPetAssets";
import { usePixelPet } from "./usePixelPet";

export interface PixelPetProps {
  readonly config?: Partial<PixelPetConfig>;
}

export function PixelPet({ config }: PixelPetProps) {
  const { bindings, enabled, view } = usePixelPet(config);

  if (!enabled) {
    return null;
  }

  const wrapperStyle = {
    "--pixel-pet-z-index": view.zIndex,
  } as CSSProperties;
  const petStyle = {
    "--pixel-pet-animation-duration": `${view.frameCount / view.fps}s`,
    "--pixel-pet-facing-scale": view.direction === 1 ? -1 : 1,
    "--pixel-pet-frame-count": view.frameCount,
    "--pixel-pet-height": `${view.screenSize.height}px`,
    "--pixel-pet-sheet-width": `${view.screenSize.width * view.frameCount}px`,
    "--pixel-pet-width": `${view.screenSize.width}px`,
    transform: `translate3d(${view.position.x}px, ${view.position.y}px, 0)`,
  } as CSSProperties;
  const spriteStyle = {
    backgroundImage: `url("${view.spriteUrl}")`,
  } as CSSProperties;

  const layer = (
    <div className="pixel-pet-layer" aria-live="off" style={wrapperStyle}>
      <button
        type="button"
        aria-label="Desktop pet"
        className="pixel-pet"
        data-direction={view.direction === -1 ? "left" : "right"}
        data-reduced-motion={view.reducedMotion ? "true" : "false"}
        data-state={view.state}
        style={petStyle}
        {...bindings}
      >
        <span
          className="pixel-pet-sprite-sheet"
          aria-hidden="true"
          key={`${view.state}:${view.animationKey}`}
          style={spriteStyle}
        />
      </button>
    </div>
  );

  const portalTarget = getPixelPetPortalTarget();
  return portalTarget ? createPortal(layer, portalTarget) : layer;
}

export function getPixelPetPortalTarget(
  ownerDocument: Pick<Document, "body"> | null =
    typeof document === "undefined" ? null : document,
) {
  return ownerDocument?.body ?? null;
}
