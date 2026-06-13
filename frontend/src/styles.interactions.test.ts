import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

describe("interaction and overflow CSS contracts", () => {
  it("keeps decorative and drag preview layers from blocking clicks", () => {
    expect(ruleFor(".particle-background")).toContain("pointer-events: none");
    expect(ruleFor(".pane-detach-ghost")).toContain("pointer-events: none");
    expect(ruleFor(".pane-resize-handle")).toContain("touch-action: none");
    expect(ruleFor(".pane-header .pane-detach-grip")).toContain(
      "touch-action: none",
    );
    expect(ruleFor(".pane-detach-header")).not.toContain("touch-action: none");
    expect(ruleFor(".bottom-graph-pane")).not.toContain("touch-action: none");
  });

  it("keeps the PixelPet overlay click-through while the sprite body stays interactive", () => {
    expect(styles).toMatch(
      /\.pixel-pet-layer,[\s\S]*?\.app-frame > \.pixel-pet-layer\.pixel-pet-layer\s*\{[\s\S]*?pointer-events: none;/u,
    );
    expect(styles).toMatch(
      /\.pixel-pet-layer,[\s\S]*?\.app-frame > \.pixel-pet-layer\.pixel-pet-layer\s*\{[\s\S]*?overflow: visible;/u,
    );
    expect(styles).toMatch(
      /\.pixel-pet-layer,[\s\S]*?\.app-frame > \.pixel-pet-layer\.pixel-pet-layer\s*\{[\s\S]*?position: fixed;/u,
    );
    expect(ruleFor(".pixel-pet")).toContain("position: fixed");
    expect(ruleFor(".pixel-pet")).toContain("pointer-events: auto");
    expect(ruleFor(".pixel-pet")).toContain("background: transparent");
    expect(ruleFor(".pixel-pet")).toContain("border: 0");
    expect(ruleFor(".pixel-pet")).toContain("touch-action: none");
    expect(styles).toMatch(
      /button\.pixel-pet,[\s\S]*?button\.pixel-pet:active:not\(:disabled\)[\s\S]*?\{[\s\S]*?background: transparent;/u,
    );
    expect(ruleFor(".pixel-pet-sprite-sheet")).toContain("pointer-events: none");
    expect(ruleFor(".pixel-pet-sprite-sheet")).toContain(
      "steps(var(--pixel-pet-frame-count), end)",
    );
    expect(
      ruleFor('.pixel-pet[data-state="drag"] .pixel-pet-sprite-sheet'),
    ).toContain("steps(6, end)");
    expect(styles).not.toContain(".pixel-pet-shadow");
    expect(styles).not.toContain(".pixel-pet-tooltip");
    expect(styles).not.toContain(".pixel-pet-heart");
    expect(styles).not.toContain(".pixel-pet-speech");
  });

  it("keeps page bodies and dense page workspaces scrollable under narrow panes", () => {
    expect(ruleFor(".page-body")).toContain("overflow: auto");
    expect(ruleFor(".drawer-body")).toContain("min-width: 0");
    expect(ruleFor(".investigation-workspace")).toContain("min-width: 860px");
    expect(ruleFor(".network-workspace")).toContain("min-width: 980px");
    expect(ruleFor(".component-center")).toContain("min-width: 1040px");
    expect(styles).toMatch(
      /\.case-list-panel\s*\{[\s\S]*?grid-template-rows: auto auto minmax\(0, 1fr\);[\s\S]*?\}/u,
    );
    expect(styles).toMatch(
      /\.attack-path-panel,[\s\S]*?\.local-connection-panel\s*\{[\s\S]*?grid-template-rows: auto minmax\(0, 1fr\) auto;/u,
    );
  });

  it("uses ellipsis for compact rows and wrapping for detail value blocks", () => {
    expect(styles).toMatch(
      /\.case-row-button span,[\s\S]*?\.plugin-row-button small\s*\{[\s\S]*?text-overflow: ellipsis;[\s\S]*?white-space: nowrap;/u,
    );
    expect(styles).toMatch(
      /\.token-list span,[\s\S]*?\.renderer-node-list span\s*\{[\s\S]*?text-overflow: ellipsis;[\s\S]*?white-space: nowrap;/u,
    );
    expect(styles).toMatch(
      /\.graph-view-button span,[\s\S]*?\.graph-node-chip span\s*\{[\s\S]*?text-overflow: ellipsis;[\s\S]*?white-space: nowrap;/u,
    );
    expect(ruleFor(".graph-node")).toContain("text-overflow: ellipsis");
    expect(ruleFor(".renderer-list-item > div")).toContain("min-width: 0");
    expect(styles).toMatch(
      /\.renderer-list-item strong,[\s\S]*?\.renderer-timeline li > strong\s*\{[\s\S]*?text-overflow: ellipsis;[\s\S]*?white-space: nowrap;/u,
    );
    expect(styles).toMatch(/\ndd\s*\{[\s\S]*?overflow-wrap: anywhere;/u);
  });
});

function ruleFor(selector: string) {
  const escapedSelector = selector.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const match = styles.match(new RegExp(`${escapedSelector}\\s*\\{(?<body>[^}]+)\\}`, "u"));
  return match?.groups?.body ?? "";
}
