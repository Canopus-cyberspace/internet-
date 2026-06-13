import { useEffect, useRef } from "react";
import { useUiStore } from "../../stores/uiStore";
import { getThemeParticleTokens } from "../designTokens";

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  opacity: number;
  color: string;
}

const TARGET_FRAME_MS = 1000 / 30;

export function ParticleBackground() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const particlesEnabled = useUiStore((state) => state.particlesEnabled);
  const reducedMotion = useUiStore((state) => state.reducedMotion);
  const theme = useUiStore((state) => state.theme);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !particlesEnabled || reducedMotion) {
      return;
    }

    const context = canvas.getContext("2d");
    if (!context) {
      return;
    }

    const particleTokens = getThemeParticleTokens(theme);

    let animationFrame = 0;
    let lastFrameAt = 0;
    let hidden = document.hidden;
    let particles: Particle[] = [];

    const resize = () => {
      const ratio = Math.max(1, Math.min(window.devicePixelRatio || 1, 2));
      const width = window.innerWidth;
      const height = window.innerHeight;
      canvas.width = Math.floor(width * ratio);
      canvas.height = Math.floor(height * ratio);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      particles = createParticles(width, height, particleTokens.colors, particleTokens.maxCount);
    };

    const onVisibilityChange = () => {
      hidden = document.hidden;
    };

    const draw = (timestamp: number) => {
      animationFrame = window.requestAnimationFrame(draw);
      if (hidden || timestamp - lastFrameAt < TARGET_FRAME_MS) {
        return;
      }
      lastFrameAt = timestamp;

      const width = window.innerWidth;
      const height = window.innerHeight;
      context.clearRect(0, 0, width, height);
      for (const particle of particles) {
        particle.x += particle.vx;
        particle.y += particle.vy;
        if (particle.x < -4) {
          particle.x = width + 4;
        } else if (particle.x > width + 4) {
          particle.x = -4;
        }
        if (particle.y < -4) {
          particle.y = height + 4;
        } else if (particle.y > height + 4) {
          particle.y = -4;
        }
        context.beginPath();
        context.globalAlpha = particle.opacity;
        context.fillStyle = particle.color;
        context.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
        context.fill();
      }
      context.globalAlpha = 1;
    };

    resize();
    window.addEventListener("resize", resize);
    document.addEventListener("visibilitychange", onVisibilityChange);
    animationFrame = window.requestAnimationFrame(draw);

    return () => {
      window.cancelAnimationFrame(animationFrame);
      window.removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [particlesEnabled, reducedMotion, theme]);

  if (!particlesEnabled || reducedMotion) {
    return null;
  }

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="particle-background"
    />
  );
}

function createParticles(
  width: number,
  height: number,
  colors: readonly string[],
  maxCount: number,
) {
  const count = Math.min(
    maxCount,
    Math.max(24, Math.round((width * height) / 22000)),
  );
  return Array.from({ length: count }, (): Particle => ({
    x: Math.random() * width,
    y: Math.random() * height,
    vx: randomBetween(-0.18, 0.18),
    vy: randomBetween(-0.12, 0.12),
    radius: randomBetween(1, 3),
    opacity: randomBetween(0.05, 0.15),
    color:
      colors[
        Math.floor(Math.random() * colors.length)
      ],
  }));
}

function randomBetween(min: number, max: number) {
  return min + Math.random() * (max - min);
}
