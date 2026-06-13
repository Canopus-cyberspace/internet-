import { useEffect, useRef } from "react";
import { useUiStore } from "../../stores/uiStore";
import { getSpritePalette, type SpritePalette } from "./pixelSprites";
import { getCurrentFrame, createCharacter, updateCharacter, CHAR_SCREEN_W, CHAR_SCREEN_H, type CharacterPose } from "./characterAI";

const PX = 4; // pixel-art scale (must match characterAI.ts PX)

/**
 * Renders pixel-art characters wandering along the bottom of the viewport.
 *
 * Driven by the same requestAnimationFrame pattern as ParticleBackground
 * but on an independent canvas so the two systems don't couple.
 */
export function PixelCharacter() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const reducedMotion = useUiStore((state) => state.reducedMotion);
  const theme = useUiStore((state) => state.theme);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || reducedMotion) return;

    const context = canvas.getContext("2d");
    if (!context) return;

    // ── Per-theme palette ──────────────────────────────────────
    let palette: SpritePalette = getSpritePalette(theme);

    // ── Character state ────────────────────────────────────────
    let character: CharacterPose = createCharacter(window.innerWidth, window.innerHeight);

    // ── Mouse tracking ─────────────────────────────────────────
    let mouseX = -100;
    let mouseY = -100;

    // ── Animation state ────────────────────────────────────────
    let animationFrame = 0;
    let lastTick = performance.now();
    let hidden = document.hidden;

    // ── Resize handler ─────────────────────────────────────────
    const resize = () => {
      const ratio = Math.max(1, Math.min(window.devicePixelRatio || 1, 2));
      const width = window.innerWidth;
      const height = window.innerHeight;
      canvas.width = Math.floor(width * ratio);
      canvas.height = Math.floor(height * ratio);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      // Move character back into bounds on resize
      character = updateCharacter(
        character,
        performance.now(),
        0,
        width,
        height,
        mouseX,
        mouseY,
      );
    };

    const onVisibilityChange = () => {
      hidden = document.hidden;
    };

    const onMouseMove = (e: MouseEvent) => {
      mouseX = e.clientX;
      mouseY = e.clientY;
    };

    // ── Render ─────────────────────────────────────────────────
    const tick = (timestamp: number) => {
      animationFrame = window.requestAnimationFrame(tick);
      if (hidden) {
        lastTick = timestamp;
        return;
      }

      const dt = Math.min(timestamp - lastTick, 100); // cap at 100ms to avoid spiral
      lastTick = timestamp;

      const w = window.innerWidth;
      const h = window.innerHeight;

      character = updateCharacter(character, timestamp, dt, w, h, mouseX, mouseY);

      // Draw
      context.clearRect(0, 0, w, h);
      drawSprite(context, getCurrentFrame(character), palette, character);
    };

    // ── Bootstrap ──────────────────────────────────────────────
    resize();
    window.addEventListener("resize", resize);
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("mousemove", onMouseMove, { passive: true });
    animationFrame = window.requestAnimationFrame(tick);

    return () => {
      window.cancelAnimationFrame(animationFrame);
      window.removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("mousemove", onMouseMove);
    };
  }, [reducedMotion, theme]);

  if (reducedMotion) return null;

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="pixel-character-canvas"
    />
  );
}

// ── Sprite renderer ────────────────────────────────────────────

const COLOR_MAP: Array<keyof SpritePalette | null> = [
  null,      // 0 = transparent
  "primary", // 1
  "secondary", // 2
  "highlight", // 3
  "outline", // 4
  "boot",    // 5
];

function drawSprite(
  ctx: CanvasRenderingContext2D,
  frame: ReturnType<typeof getCurrentFrame>,
  palette: SpritePalette,
  ch: CharacterPose,
) {
  const spriteW = frame[0].length; // columns (10)
  const spriteH = frame.length;    // rows (14)

  for (let row = 0; row < spriteH; row++) {
    for (let col = 0; col < spriteW; col++) {
      const idx = frame[row][col];
      if (idx === 0) continue; // transparent

      const colorKey = COLOR_MAP[idx];
      if (!colorKey) continue;

      ctx.fillStyle = palette[colorKey];

      // Flip horizontally when facing left
      const drawCol = ch.direction === -1 ? spriteW - 1 - col : col;
      const sx = ch.x + drawCol * PX;
      const sy = ch.y + row * PX;

      ctx.fillRect(Math.round(sx), Math.round(sy), PX, PX);
    }
  }
}
