import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DESIGN_TOKENS,
  PARTICLE_COLOR_TOKENS,
  getThemeColorTokens,
  getThemeParticleTokens,
} from "./designTokens";

const styles = readFileSync(new URL("../styles.css", import.meta.url), "utf8");
const authoredRules = styles
  .split("\n")
  .filter((line) => !line.trimStart().startsWith("--"))
  .join("\n");

function expectCssToken(name: string, value: string) {
  expect(styles).toContain(`--${name}: ${value};`);
}

function ruleFor(selector: string) {
  const escapedSelector = selector.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const matches = styles.matchAll(
    new RegExp(`${escapedSelector}\\s*\\{(?<body>[^}]+)\\}`, "gu"),
  );
  const bodies = Array.from(matches, (match) => match.groups?.body ?? "");
  return bodies.at(-1) ?? "";
}

function ruleForWithSnippet(selector: string, snippet: string) {
  const escapedSelector = selector.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const matches = styles.matchAll(
    new RegExp(`${escapedSelector}\\s*\\{(?<body>[^}]+)\\}`, "gu"),
  );
  const bodies = Array.from(matches, (match) => match.groups?.body ?? "");
  return [...bodies].reverse().find((body: string) => body.includes(snippet)) ?? "";
}

function selectorListRuleFor(...selectors: string[]) {
  const escapedSelectors = selectors.map((selector) =>
    selector.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"),
  );
  const selectorPattern = escapedSelectors.join(",\\s*");
  const matches = styles.matchAll(
    new RegExp(`${selectorPattern}\\s*\\{(?<body>[^}]+)\\}`, "gu"),
  );
  const bodies = Array.from(matches, (match) => match.groups?.body ?? "");
  return bodies.at(-1) ?? "";
}

function expectNoLiteralColor(rule: string) {
  expect(rule).not.toMatch(/#(?:[0-9A-Fa-f]{3,8})\b|rgba?\(|color-mix\(/u);
}

function expectNoLiteralSpacing(rule: string) {
  expect(rule).not.toMatch(
    /\b(?:gap|column-gap|row-gap|padding(?:-(?:top|right|bottom|left))?|margin(?:-(?:top|right|bottom|left))?|top|right|bottom|left|inset)\s*:\s*[^;]*-?\d+px\b/u,
  );
}

describe("design token visual hierarchy", () => {
  it("keeps functional zone surfaces distinct and synced with CSS", () => {
    const zoneTokens = [
      ["color-zone-topbar", DESIGN_TOKENS.color.zoneTopbar],
      ["color-zone-statusbar", DESIGN_TOKENS.color.zoneStatusbar],
      ["color-zone-navigation", DESIGN_TOKENS.color.zoneNavigation],
      ["color-zone-workspace", DESIGN_TOKENS.color.zoneWorkspace],
      ["color-zone-inspector", DESIGN_TOKENS.color.zoneInspector],
      ["color-zone-bottom-pane", DESIGN_TOKENS.color.zoneBottomPane],
    ] as const;

    expect(new Set(zoneTokens.map(([, value]) => value)).size).toBe(
      zoneTokens.length,
    );
    for (const [name, value] of zoneTokens) {
      expectCssToken(name, value);
    }
  });

  it("defines and uses panel category border tokens", () => {
    const panelBorderTokens = [
      ["color-border-panel-active", DESIGN_TOKENS.color.borderPanelActive],
      ["color-border-panel-graph", DESIGN_TOKENS.color.borderPanelGraph],
      ["color-border-panel-alert", DESIGN_TOKENS.color.borderPanelAlert],
      ["color-border-panel-warning", DESIGN_TOKENS.color.borderPanelWarning],
      ["color-border-panel-report", DESIGN_TOKENS.color.borderPanelReport],
      ["color-border-panel-passive", DESIGN_TOKENS.color.borderPanelPassive],
    ] as const;

    for (const [name, value] of panelBorderTokens) {
      expectCssToken(name, value);
      expect(styles).toContain(`var(--${name})`);
    }
  });

  it("defines shell shadow color tokens and uses them on active shell panels", () => {
    const shadowTokens = [
      ["color-shadow-shell-chrome", DESIGN_TOKENS.shadow.shellChrome],
      ["color-shadow-shell-drawer", DESIGN_TOKENS.shadow.shellDrawer],
      ["color-shadow-ambient-glow", DESIGN_TOKENS.shadow.ambientGlow],
      ["color-shadow-toolbar-inset", DESIGN_TOKENS.shadow.toolbarInset],
      ["color-shadow-surface-inset-soft", DESIGN_TOKENS.shadow.surfaceInsetSoft],
      ["color-shadow-surface-inset", DESIGN_TOKENS.shadow.surfaceInset],
      [
        "color-shadow-surface-inset-strong",
        DESIGN_TOKENS.shadow.surfaceInsetStrong,
      ],
      ["color-shadow-preview-focus", DESIGN_TOKENS.shadow.previewFocus],
      ["color-shadow-floating-panel", DESIGN_TOKENS.shadow.floatingPanel],
      ["color-shadow-preview-overlay", DESIGN_TOKENS.shadow.previewOverlay],
      ["color-shadow-flow-node", DESIGN_TOKENS.shadow.flowNode],
      ["color-shadow-status-pulse", DESIGN_TOKENS.shadow.statusPulse],
    ] as const;

    for (const [name, value] of shadowTokens) {
      expectCssToken(name, value);
    }

    const navigationTreeRule = ruleFor(".navigation-tree");
    expect(navigationTreeRule).toContain("var(--color-shadow-shell-chrome)");
    expectNoLiteralColor(navigationTreeRule);

    const bottomGraphPaneRule = ruleFor(".bottom-graph-pane");
    expect(bottomGraphPaneRule).toContain("var(--color-shadow-shell-chrome)");
    expectNoLiteralColor(bottomGraphPaneRule);

    const detailDrawerRule = ruleForWithSnippet(".detail-drawer", "box-shadow");
    expect(detailDrawerRule).toContain("var(--color-shadow-shell-drawer)");
    expect(detailDrawerRule).toContain("var(--color-shadow-surface-inset)");
    expectNoLiteralColor(detailDrawerRule);

    const toolbarRule = ruleFor(".top-toolbar");
    expect(toolbarRule).toContain("var(--color-shadow-toolbar-inset)");
    expectNoLiteralColor(toolbarRule);

    const floatingPanelRule = selectorListRuleFor(
      ".analysis-panel",
      ".component-panel",
      ".settings-panel",
      ".settings-side-panel",
      ".response-side-panel",
      ".response-table-panel",
      ".response-impact-panel",
      ".report-preview-panel",
      ".report-side-panel",
      ".export-history-panel",
      ".case-list-panel",
      ".network-view-tree",
      ".network-detail-panel",
      ".component-detail-panel",
      ".capability-tree",
      ".report-list-panel",
      ".response-view-tree",
      ".settings-section-nav",
      ".graph-toolbar-panel",
      ".graph-side-panel",
      ".graph-type-selector",
      ".renderer-panel",
    );
    expect(floatingPanelRule).toContain("var(--color-shadow-surface-inset-soft)");
    expect(floatingPanelRule).toContain("var(--color-shadow-floating-panel)");
    expectNoLiteralColor(floatingPanelRule);

    const previewFocusRule = ruleFor(
      '.bottom-graph-pane[data-drag-out-state="preview"] .pane-detach-header',
    );
    expect(previewFocusRule).toContain("var(--color-shadow-preview-focus)");
    expectNoLiteralColor(previewFocusRule);

    const detachGhostRule = ruleFor(".pane-detach-ghost");
    expect(detachGhostRule).toContain("var(--color-shadow-preview-overlay)");
    expect(detachGhostRule).toContain("var(--color-shadow-surface-inset-strong)");
    expectNoLiteralColor(detachGhostRule);

    const pixelPetGlowRule = selectorListRuleFor(
      ".pixel-pet:hover",
      ".pixel-pet:focus-visible",
    );
    expect(pixelPetGlowRule).toContain("var(--color-shadow-ambient-glow)");
    expectNoLiteralColor(pixelPetGlowRule);

    const flowNodeRule = ruleFor(".flow-node");
    expect(flowNodeRule).toContain("var(--color-shadow-flow-node)");
    expectNoLiteralColor(flowNodeRule);

    const statusPulseRule = ruleFor("@keyframes statusPulse");
    expect(statusPulseRule).toContain("var(--color-shadow-status-pulse)");
    expectNoLiteralColor(statusPulseRule);
  });

  it("defines remaining surface tokens and uses them on active shell/page surfaces", () => {
    const surfaceTokens = [
      ["surface-scrollbar-thumb", DESIGN_TOKENS.surface.scrollbarThumb],
      ["surface-scrollbar-thumb-hover", DESIGN_TOKENS.surface.scrollbarThumbHover],
      ["surface-toolbar-background", DESIGN_TOKENS.surface.toolbarBackground],
      ["surface-toolbar-hover", DESIGN_TOKENS.surface.toolbarHover],
      ["surface-header-muted", DESIGN_TOKENS.surface.headerMuted],
      ["surface-navigation-hover", DESIGN_TOKENS.surface.navigationHover],
      ["surface-navigation-active", DESIGN_TOKENS.surface.navigationActive],
      ["surface-preview-detach-ghost", DESIGN_TOKENS.surface.previewDetachGhost],
      ["surface-preview-detach-target", DESIGN_TOKENS.surface.previewDetachTarget],
      ["surface-preview-graph", DESIGN_TOKENS.surface.previewGraph],
      ["border-chip-graph", DESIGN_TOKENS.surface.borderChipGraph],
      ["surface-chip-graph", DESIGN_TOKENS.surface.chipGraph],
      ["border-chip-alert", DESIGN_TOKENS.surface.borderChipAlert],
      ["surface-chip-alert", DESIGN_TOKENS.surface.chipAlert],
      ["surface-chip-navigation", DESIGN_TOKENS.surface.chipNavigation],
      ["surface-selection-active", DESIGN_TOKENS.surface.selectionActive],
      ["surface-status-degraded", DESIGN_TOKENS.surface.statusDegraded],
      ["surface-status-chip", DESIGN_TOKENS.surface.statusChip],
      ["surface-table-selected", DESIGN_TOKENS.surface.tableSelected],
      ["surface-table-alert", DESIGN_TOKENS.surface.tableAlert],
      ["surface-table-warning", DESIGN_TOKENS.surface.tableWarning],
      ["surface-table-report", DESIGN_TOKENS.surface.tableReport],
      ["surface-panel-alert", DESIGN_TOKENS.surface.panelAlert],
      ["border-panel-graph-muted", DESIGN_TOKENS.surface.borderPanelGraphMuted],
      ["surface-panel-report", DESIGN_TOKENS.surface.panelReport],
      ["surface-panel-navigation", DESIGN_TOKENS.surface.panelNavigation],
      ["surface-panel-detail", DESIGN_TOKENS.surface.panelDetail],
      ["surface-header-alert", DESIGN_TOKENS.surface.headerAlert],
      ["surface-header-graph", DESIGN_TOKENS.surface.headerGraph],
      ["surface-header-warning", DESIGN_TOKENS.surface.headerWarning],
      ["surface-header-report", DESIGN_TOKENS.surface.headerReport],
      ["surface-header-navigation", DESIGN_TOKENS.surface.headerNavigation],
      ["border-legend-graph", DESIGN_TOKENS.surface.borderLegendGraph],
      ["surface-legend-graph", DESIGN_TOKENS.surface.legendGraph],
      ["border-report-muted", DESIGN_TOKENS.surface.borderReportMuted],
      ["surface-report-summary", DESIGN_TOKENS.surface.reportSummary],
      [
        "surface-export-action-selected",
        DESIGN_TOKENS.surface.exportActionSelected,
      ],
      ["surface-export-preview", DESIGN_TOKENS.surface.exportPreview],
      ["surface-graph-canvas", DESIGN_TOKENS.surface.graphCanvas],
      [
        "surface-graph-canvas-grid-dot",
        DESIGN_TOKENS.surface.graphCanvasGridDot,
      ],
    ] as const;

    for (const [name, value] of surfaceTokens) {
      expectCssToken(name, value);
    }

    expect(authoredRules).not.toMatch(/#(?:[0-9A-Fa-f]{3,8})\b|rgba?\(|color-mix\(/u);

    const toolbarRule = ruleFor(".top-toolbar");
    expect(toolbarRule).toContain("var(--surface-toolbar-background)");
    expectNoLiteralColor(toolbarRule);

    const toolbarHoverRule = selectorListRuleFor(
      ".top-toolbar .icon-button:hover:not(:disabled)",
      ".top-toolbar .toolbar-button:hover:not(:disabled)",
      ".top-toolbar select:hover:not(:disabled)",
    );
    expect(toolbarHoverRule).toContain("var(--surface-toolbar-hover)");
    expectNoLiteralColor(toolbarHoverRule);

    const mutedHeaderRule = selectorListRuleFor(
      ".tree-header",
      ".drawer-header",
      ".pane-header",
      ".analysis-panel-header",
      ".component-panel-header",
      ".renderer-panel-header",
    );
    expect(mutedHeaderRule).toContain("var(--surface-header-muted)");
    expectNoLiteralColor(mutedHeaderRule);

    const treeHoverRule = ruleFor(".tree-link:hover");
    expect(treeHoverRule).toContain("var(--surface-navigation-hover)");
    expectNoLiteralColor(treeHoverRule);

    const treeActiveRule = ruleFor(".tree-link.active");
    expect(treeActiveRule).toContain("var(--surface-navigation-active)");
    expectNoLiteralColor(treeActiveRule);

    const graphChipRule = selectorListRuleFor(
      ".graph-view-button",
      ".graph-type-button",
      ".graph-node-chip",
    );
    expect(graphChipRule).toContain("var(--border-chip-graph)");
    expect(graphChipRule).toContain("var(--surface-chip-graph)");
    expectNoLiteralColor(graphChipRule);

    const alertChipRule = ruleFor(".case-filter-tab");
    expect(alertChipRule).toContain("var(--border-chip-alert)");
    expect(alertChipRule).toContain("var(--surface-chip-alert)");
    expectNoLiteralColor(alertChipRule);

    const navigationChipRule = selectorListRuleFor(
      ".network-view-item",
      ".response-view-button",
      ".settings-section-button",
      ".capability-tree-item",
    );
    expect(navigationChipRule).toContain("var(--surface-chip-navigation)");
    expectNoLiteralColor(navigationChipRule);

    const selectionRule = selectorListRuleFor(
      '[data-selected="true"]',
      ".drawer-tab.active",
    );
    expect(selectionRule).toContain("var(--surface-selection-active)");
    expectNoLiteralColor(selectionRule);

    const detachGhostRule = ruleFor(".pane-detach-ghost");
    expect(detachGhostRule).toContain("var(--surface-preview-detach-ghost)");
    expectNoLiteralColor(detachGhostRule);

    const detachTargetRule = ruleFor(
      '.pane-detach-ghost[data-detach-target="true"]',
    );
    expect(detachTargetRule).toContain("var(--surface-preview-detach-target)");
    expectNoLiteralColor(detachTargetRule);

    const graphPreviewRule = ruleFor(".graph-preview");
    expect(graphPreviewRule).toContain("var(--surface-preview-graph)");
    expectNoLiteralColor(graphPreviewRule);

    const degradedStatusRule = ruleFor('.status-strip[data-degraded="true"]');
    expect(degradedStatusRule).toContain("var(--surface-status-degraded)");
    expectNoLiteralColor(degradedStatusRule);

    const statusChipRule = ruleFor(".status-chip");
    expect(statusChipRule).toContain("var(--surface-status-chip)");
    expectNoLiteralColor(statusChipRule);

    const selectedTableRule = selectorListRuleFor(
      '.shell-table-row[data-selected="true"]',
      '.case-list-row[data-selected="true"]',
      '.network-table-row[data-selected="true"]',
      '.plugin-table-row[data-selected="true"]',
      '.response-table-row[data-selected="true"]',
      '.report-list-row[data-selected="true"]',
    );
    expect(selectedTableRule).toContain("var(--surface-table-selected)");
    expectNoLiteralColor(selectedTableRule);

    const alertTableRule = selectorListRuleFor(
      '.case-list-row[data-severity="critical"]',
      '.case-list-row[data-severity="high"]',
    );
    expect(alertTableRule).toContain("var(--surface-table-alert)");
    expectNoLiteralColor(alertTableRule);

    const warningTableRule = selectorListRuleFor(
      '.response-table-row[data-severity="critical"]',
      '.response-table-row[data-severity="high"]',
      '.response-table-row[data-severity="medium"]',
    );
    expect(warningTableRule).toContain("var(--surface-table-warning)");
    expectNoLiteralColor(warningTableRule);

    const reportTableRule = selectorListRuleFor(
      ".report-section-row",
      ".export-history-row",
    );
    expect(reportTableRule).toContain("var(--surface-table-report)");
    expectNoLiteralColor(reportTableRule);

    const casePanelRule = ruleForWithSnippet(".case-list-panel", "background");
    expect(casePanelRule).toContain("var(--surface-panel-alert)");
    expectNoLiteralColor(casePanelRule);

    const graphMutedPanelRule = ruleFor(".graph-side-panel.compact");
    expect(graphMutedPanelRule).toContain("var(--border-panel-graph-muted)");
    expectNoLiteralColor(graphMutedPanelRule);

    const reportPanelRule = selectorListRuleFor(
      ".report-preview-panel",
      ".report-side-panel",
      ".report-list-panel",
      ".report-action-panel",
      ".export-history-panel",
    );
    expect(reportPanelRule).toContain("var(--surface-panel-report)");
    expectNoLiteralColor(reportPanelRule);

    const navigationPanelRule = selectorListRuleFor(
      ".network-view-tree",
      ".response-view-tree",
      ".settings-section-nav",
      ".capability-tree",
    );
    expect(navigationPanelRule).toContain("var(--surface-panel-navigation)");
    expectNoLiteralColor(navigationPanelRule);

    const detailPanelRule = selectorListRuleFor(
      ".network-detail-panel",
      ".component-detail-panel",
      ".reports-detail > .report-side-panel",
      ".response-detail > .response-side-panel",
      ".settings-detail > .settings-side-panel",
    );
    expect(detailPanelRule).toContain("var(--surface-panel-detail)");
    expectNoLiteralColor(detailPanelRule);

    const alertHeaderRule = ruleFor(".case-list-panel .analysis-panel-header");
    expect(alertHeaderRule).toContain("var(--surface-header-alert)");
    expectNoLiteralColor(alertHeaderRule);

    const graphHeaderRule = selectorListRuleFor(
      ".graph-toolbar-panel",
      ".graph-side-panel .analysis-panel-header",
      ".graph-type-selector .analysis-panel-header",
      ".attack-path-panel .analysis-panel-header",
      ".local-connection-panel .analysis-panel-header",
      ".response-impact-panel .analysis-panel-header",
    );
    expect(graphHeaderRule).toContain("var(--surface-header-graph)");
    expectNoLiteralColor(graphHeaderRule);

    const warningHeaderRule = selectorListRuleFor(
      ".response-side-panel .analysis-panel-header",
      ".settings-side-panel .analysis-panel-header",
    );
    expect(warningHeaderRule).toContain("var(--surface-header-warning)");
    expectNoLiteralColor(warningHeaderRule);

    const reportHeaderRule = selectorListRuleFor(
      ".report-preview-panel .analysis-panel-header",
      ".report-side-panel .analysis-panel-header",
      ".report-list-panel .analysis-panel-header",
      ".report-action-panel .analysis-panel-header",
      ".export-history-panel .analysis-panel-header",
    );
    expect(reportHeaderRule).toContain("var(--surface-header-report)");
    expectNoLiteralColor(reportHeaderRule);

    const navigationHeaderRule = selectorListRuleFor(
      ".network-view-tree .analysis-panel-header",
      ".response-view-tree .analysis-panel-header",
      ".settings-section-nav .analysis-panel-header",
      ".capability-tree .component-panel-header",
    );
    expect(navigationHeaderRule).toContain("var(--surface-header-navigation)");
    expectNoLiteralColor(navigationHeaderRule);

    const legendRule = selectorListRuleFor(
      ".graph-legend-item",
      ".graph-path-item",
    );
    expect(legendRule).toContain("var(--border-legend-graph)");
    expect(legendRule).toContain("var(--surface-legend-graph)");
    expectNoLiteralColor(legendRule);

    const reportMutedRule = selectorListRuleFor(
      ".report-list-row",
      ".status-badge",
    );
    expect(reportMutedRule).toContain("var(--border-report-muted)");
    expectNoLiteralColor(reportMutedRule);

    const reportSummaryRule = ruleFor(".report-preview-summary");
    expect(reportSummaryRule).toContain("var(--surface-report-summary)");
    expectNoLiteralColor(reportSummaryRule);

    const exportActionRule = ruleFor('.explicit-export-action[data-selected="true"]');
    expect(exportActionRule).toContain("var(--surface-export-action-selected)");
    expectNoLiteralColor(exportActionRule);

    const exportPreviewRule = ruleFor(".explicit-export-preview");
    expect(exportPreviewRule).toContain("var(--surface-export-preview)");
    expectNoLiteralColor(exportPreviewRule);

    const graphCanvasRule = selectorListRuleFor(
      ".graph-canvas-shell",
      ".graph-empty-state",
    );
    expect(graphCanvasRule).toContain("var(--surface-graph-canvas)");
    expect(graphCanvasRule).toContain("var(--surface-graph-canvas-grid-dot)");
    expectNoLiteralColor(graphCanvasRule);
  });

  it("defines compact radius tokens and uses them on active shell chrome", () => {
    expectCssToken("radius-none", DESIGN_TOKENS.radius.none);
    expectCssToken("radius-control", DESIGN_TOKENS.radius.control);
    expectCssToken("radius-card", DESIGN_TOKENS.radius.card);
    expectCssToken("radius-pill", DESIGN_TOKENS.radius.pill);

    expect(styles).toMatch(
      /button,[\s\S]*?textarea\s*\{[\s\S]*?border-radius: var\(--radius-control\);/u,
    );
    expect(ruleFor(".detached-payload-pane")).toContain(
      "border-radius: var(--radius-card)",
    );
    expect(ruleFor(".brand-mark")).toContain("border-radius: var(--radius-card)");
    expect(ruleFor(".notification-badge")).toContain(
      "border-radius: var(--radius-pill)",
    );
  });

  it("defines compact spacing tokens and uses them on active toolbar chrome", () => {
    const spaceTokens = [
      ["space-0", DESIGN_TOKENS.space[0]],
      ["space-hairline", DESIGN_TOKENS.space.hairline],
      ["space-1", DESIGN_TOKENS.space[1]],
      ["space-2", DESIGN_TOKENS.space[2]],
      ["space-compact", DESIGN_TOKENS.space.compact],
      ["space-3", DESIGN_TOKENS.space[3]],
      ["space-row", DESIGN_TOKENS.space.row],
      ["space-badge-offset-y", DESIGN_TOKENS.space.badgeOffsetY],
      ["space-badge-offset-x", DESIGN_TOKENS.space.badgeOffsetX],
      ["space-control-inset", DESIGN_TOKENS.space.controlInset],
      ["space-stack-tight", DESIGN_TOKENS.space.stackTight],
      ["space-4", DESIGN_TOKENS.space[4]],
      ["space-5", DESIGN_TOKENS.space[5]],
      ["space-6", DESIGN_TOKENS.space[6]],
      ["space-7", DESIGN_TOKENS.space[7]],
      ["space-8", DESIGN_TOKENS.space[8]],
      ["space-roomy", DESIGN_TOKENS.space.roomy],
    ] as const;

    for (const [name, value] of spaceTokens) {
      expectCssToken(name, value);
    }

    expect(authoredRules).not.toMatch(
      /\b(?:gap|column-gap|row-gap|padding(?:-(?:top|right|bottom|left))?|margin(?:-(?:top|right|bottom|left))?|top|right|bottom|left|inset)\s*:\s*[^;]*-?\d+px\b/u,
    );

    expect(ruleFor(".top-toolbar")).toContain("gap: var(--space-4)");
    expect(ruleFor(".top-toolbar")).toContain(
      "padding: var(--space-3) var(--space-5)",
    );
    expect(ruleFor(".toolbar-brand")).toContain("gap: var(--space-4)");
    expect(ruleFor(".toolbar-brand")).toContain(
      "padding-right: var(--space-4)",
    );
    expect(
      selectorListRuleFor(
        ".toolbar-actions",
        ".pane-actions",
        ".plugin-action-group",
        ".response-action-bar",
      ),
    ).toContain("gap: var(--space-2)");
    expect(ruleFor(".segmented-button-group")).toContain(
      "gap: var(--space-2)",
    );

    const detachedHeaderRule = ruleFor(".detached-window-header");
    expect(detachedHeaderRule).toContain("gap: var(--space-5)");
    expect(detachedHeaderRule).toContain(
      "padding: var(--space-row) var(--space-5)",
    );
    expectNoLiteralSpacing(detachedHeaderRule);

    const viewListRule = selectorListRuleFor(
      ".graph-view-list",
      ".case-filter-tabs",
      ".network-view-list",
      ".response-view-list",
      ".settings-section-list",
      ".capability-tree-list",
      ".graph-type-list",
    );
    expect(viewListRule).toContain("gap: var(--space-2)");
    expectNoLiteralSpacing(viewListRule);

    const treeLinkRule = ruleForWithSnippet(".tree-link", "gap");
    expect(treeLinkRule).toContain("gap: var(--space-row)");
    expect(treeLinkRule).toContain("padding: var(--space-0) var(--space-row)");
    expectNoLiteralSpacing(treeLinkRule);

    const detachGhostRule = ruleFor(".pane-detach-ghost");
    expect(detachGhostRule).toContain("padding: var(--space-4) var(--space-5)");
    expectNoLiteralSpacing(detachGhostRule);

    const graphStripRule = ruleFor(".graph-strip");
    expect(graphStripRule).toContain("gap: var(--space-4)");
    expect(graphStripRule).toContain("padding: var(--space-4) var(--space-5)");
    expectNoLiteralSpacing(graphStripRule);

    const drawerTabsRule = ruleFor(".drawer-tabs");
    expect(drawerTabsRule).toContain("gap: var(--space-hairline)");
    expect(drawerTabsRule).toContain("padding: var(--space-3) var(--space-4)");
    expectNoLiteralSpacing(drawerTabsRule);

    const statusStripRule = ruleFor(".status-strip");
    expect(statusStripRule).toContain("gap: var(--space-4)");
    expect(statusStripRule).toContain("padding: var(--space-0) var(--space-5)");
    expectNoLiteralSpacing(statusStripRule);

    const emptyStateRule = ruleFor(".empty-state");
    expect(emptyStateRule).toContain("gap: var(--space-row)");
    expect(emptyStateRule).toContain("padding: var(--space-roomy)");
    expectNoLiteralSpacing(emptyStateRule);

    const reportSummaryHeadingRule = ruleFor(".report-preview-summary h2");
    expect(reportSummaryHeadingRule).toContain(
      "margin: var(--space-stack-tight) var(--space-0)",
    );
    expectNoLiteralSpacing(reportSummaryHeadingRule);

    const explicitExportActionRule = ruleFor(".explicit-export-action");
    expect(explicitExportActionRule).toContain("gap: var(--space-compact)");
    expect(explicitExportActionRule).toContain(
      "padding: var(--space-compact) var(--space-row)",
    );
    expectNoLiteralSpacing(explicitExportActionRule);

    const impactStripRule = ruleFor(".settings-impact-strip > div");
    expect(impactStripRule).toContain("gap: var(--space-compact)");
    expectNoLiteralSpacing(impactStripRule);
  });

  it("uses spacing tokens for shared page shell and workspace layout", () => {
    expect(ruleFor(".page-header")).toContain(
      "padding: var(--space-5) var(--space-7) var(--space-4)",
    );
    expect(ruleFor(".page-header h1")).toContain("margin-top: var(--space-1)");
    expect(ruleFor(".page-body")).toContain("padding: var(--space-5)");
    expect(ruleFor(".split-pane")).toContain("column-gap: var(--space-2)");
    expect(
      selectorListRuleFor(
        ".investigation-main",
        ".network-main",
        ".component-center-main",
        ".response-main",
        ".reports-main",
        ".settings-main",
        ".graph-workspace-main",
        ".graph-workspace-detail",
        ".reports-detail",
        ".response-detail",
        ".settings-detail",
      ),
    ).toContain("gap: var(--space-4)");
    expect(
      selectorListRuleFor(
        ".investigation-detail-grid",
        ".component-analysis-grid",
      ),
    ).toContain("gap: var(--space-4)");
    expect(ruleFor(".graph-status-stack")).toContain("gap: var(--space-3)");
    expect(ruleFor(".case-filter-tabs")).toContain("padding: var(--space-3)");
  });

  it("uses spacing tokens for detail widgets and export/report panels", () => {
    expect(ruleFor(".settings-capability-status")).toContain(
      "gap: var(--space-4)",
    );
    expect(ruleFor(".settings-capability-status")).toContain(
      "margin-top: var(--space-4)",
    );
    expect(
      selectorListRuleFor(
        ".settings-warning-banner",
        ".graph-status-banner",
        ".response-callout",
      ),
    ).toContain("gap: var(--space-7)");
    expect(
      selectorListRuleFor(
        ".settings-warning-banner",
        ".graph-status-banner",
        ".response-callout",
      ),
    ).toContain("margin: var(--space-4)");
    expect(
      selectorListRuleFor(
        ".settings-warning-banner",
        ".graph-status-banner",
        ".response-callout",
      ),
    ).toContain("padding: var(--space-4)");
    expect(
      selectorListRuleFor(
        ".settings-message",
        ".component-muted",
        ".analysis-muted",
        ".renderer-muted",
      ),
    ).toContain("padding: var(--space-4)");
    expect(
      selectorListRuleFor(
        ".report-preview-body",
        ".response-approval-body",
        ".export-dialog-body",
        ".component-detail-scroll",
        ".renderer-panel-body",
      ),
    ).toContain("gap: var(--space-4)");
    expect(
      selectorListRuleFor(
        ".report-preview-body",
        ".response-approval-body",
        ".export-dialog-body",
        ".component-detail-scroll",
        ".renderer-panel-body",
      ),
    ).toContain("padding: var(--space-4)");
    expect(ruleFor(".report-preview-summary")).toContain("gap: var(--space-5)");
    expect(ruleFor(".report-preview-summary")).toContain(
      "padding: var(--space-5)",
    );
    expect(ruleFor(".report-status-stack")).toContain("gap: var(--space-3)");
    expect(
      selectorListRuleFor(
        ".export-dialog-body label",
        ".response-reason-field",
        ".graph-filter-grid label",
        ".renderer-form label",
      ),
    ).toContain("gap: var(--space-2)");
    expect(
      selectorListRuleFor(
        ".explicit-export-actions",
        ".explicit-export-confirm-row",
        ".explicit-preview-grid",
      ),
    ).toContain("gap: var(--space-3)");
    expect(ruleFor(".explicit-export-preview")).toContain(
      "gap: var(--space-7)",
    );
    expect(ruleFor(".explicit-export-preview")).toContain(
      "padding: var(--space-4)",
    );
    expect(ruleFor(".response-check-row")).toContain("gap: var(--space-7)");
    expect(ruleFor(".response-check-row")).toContain(
      "padding: var(--space-3) var(--space-0)",
    );
    expect(ruleFor(".settings-impact-strip")).toContain("gap: var(--space-3)");
    expect(ruleFor(".settings-impact-strip")).toContain(
      "padding: var(--space-4)",
    );
    expect(ruleFor(".token-group")).toContain("gap: var(--space-3)");
    expect(ruleFor(".token-group")).toContain(
      "padding-top: var(--space-4)",
    );
    expect(ruleFor(".graph-filter-grid")).toContain("gap: var(--space-4)");
    expect(ruleFor(".graph-filter-grid")).toContain(
      "padding: var(--space-4)",
    );
  });

  it("uses spacing tokens for graph toolbar and shared widget rows", () => {
    expect(
      selectorListRuleFor(
        ".report-list-row",
        ".renderer-list-item",
        ".renderer-risk-list > div",
        ".recommendation-list li",
        ".renderer-timeline li",
        ".graph-legend-item",
        ".graph-path-item",
        ".renderer-metric-list > div",
        ".settings-status-row",
        ".response-safety-item",
        ".summary-metric",
        ".status-badge",
        ".settings-toggle-row",
      ),
    ).toContain("gap: var(--space-4)");
    expect(
      selectorListRuleFor(
        ".report-list-row",
        ".renderer-list-item",
        ".renderer-risk-list > div",
        ".recommendation-list li",
        ".renderer-timeline li",
        ".graph-legend-item",
        ".graph-path-item",
        ".renderer-metric-list > div",
        ".settings-status-row",
        ".response-safety-item",
        ".summary-metric",
        ".status-badge",
        ".settings-toggle-row",
      ),
    ).toContain("padding: var(--space-row) var(--space-4)");
    expect(ruleFor(".settings-toggle-row")).toContain("margin: var(--space-4)");
    expect(ruleFor(".settings-toggle-row > div")).toContain(
      "gap: var(--space-row)",
    );
    expect(ruleFor(".graph-toolbar-panel")).toContain("gap: var(--space-4)");
    expect(ruleFor(".graph-toolbar-panel")).toContain(
      "padding: var(--space-row) var(--space-4)",
    );
    expect(ruleFor(".graph-toolbar-title")).toContain("gap: var(--space-3)");
    expect(ruleFor(".graph-toolbar-stats")).toContain("gap: var(--space-3)");
    expect(ruleFor(".graph-toolbar-stats span")).toContain(
      "padding: var(--space-1) var(--space-3)",
    );
    expect(ruleFor(".renderer-warning")).toContain("gap: var(--space-row)");
    expect(ruleFor(".renderer-warning")).toContain(
      "padding: var(--space-4)",
    );
    expect(ruleFor(".renderer-health-badge")).toContain(
      "gap: var(--space-3)",
    );
    expect(ruleFor(".renderer-health-badge")).toContain(
      "padding: var(--space-0) var(--space-4)",
    );
    expect(ruleFor(".renderer-graph-stats")).toContain("gap: var(--space-3)");
    expect(ruleFor(".renderer-graph-stats")).toContain(
      "padding-bottom: var(--space-4)",
    );
    expect(ruleFor(".renderer-graph-stats span")).toContain(
      "gap: var(--space-compact)",
    );
    expect(ruleFor(".renderer-graph-stats span")).toContain(
      "padding: var(--space-1) var(--space-3)",
    );
  });

  it("uses spacing tokens for graph node chrome and compact chips", () => {
    expect(
      selectorListRuleFor(
        ".token-list span",
        ".muted-token",
        ".redaction-category-list span",
        ".renderer-node-list span",
      ),
    ).toContain("padding: var(--space-1) var(--space-3)");
    expect(ruleFor(".risk-bar-row")).toContain("gap: var(--space-4)");
    expect(ruleFor(".graph-empty-state")).toContain("gap: var(--space-3)");
    expect(ruleFor(".flow-node")).toContain("padding: var(--space-4)");
    expect(
      selectorListRuleFor(
        ".flow-node-title",
        ".flow-node-meta",
        ".flow-node-badges",
      ),
    ).toContain("gap: var(--space-4)");
    expect(
      selectorListRuleFor(".flow-node-meta", ".flow-node-badges"),
    ).toContain("margin-top: var(--space-2)");
    expect(ruleFor(".flow-node-badges small")).toContain(
      "padding: var(--space-hairline) var(--space-2)",
    );
    expect(ruleFor(".flow-edge-label")).toContain(
      "padding: var(--space-hairline) var(--space-compact)",
    );
  });

  it("uses spacing tokens for compact toolbar controls and badges", () => {
    expect(ruleFor(".toolbar-control")).toContain("gap: var(--space-compact)");
    expect(ruleFor(".toolbar-control select")).toContain(
      "padding: var(--space-0) var(--space-control-inset) var(--space-0) var(--space-row)",
    );
    expect(ruleFor(".notification-badge")).toContain(
      "top: var(--space-badge-offset-y)",
    );
    expect(ruleFor(".notification-badge")).toContain(
      "right: var(--space-badge-offset-x)",
    );
    expect(ruleFor(".notification-badge")).toContain(
      "padding: var(--space-0) var(--space-2)",
    );
    expect(
      selectorListRuleFor(
        ".toolbar-button",
        ".analysis-command-button",
        ".mini-action-button",
        ".renderer-disabled-action",
        ".segmented-toggle",
      ),
    ).toContain("gap: var(--space-compact)");
    expect(
      selectorListRuleFor(
        ".toolbar-button",
        ".analysis-command-button",
        ".mini-action-button",
        ".renderer-disabled-action",
        ".segmented-toggle",
      ),
    ).toContain("padding: var(--space-0) var(--space-4)");
  });
});

describe("light theme tokens", () => {
  const light = getThemeColorTokens("light");

  it("provides light backgrounds distinct from dark", () => {
    expect(light.bgPrimary).not.toBe(DESIGN_TOKENS.color.bgPrimary);
    expect(light.textPrimary).not.toBe(DESIGN_TOKENS.color.textPrimary);
  });

  it("keeps zone surfaces distinct within light theme", () => {
    const zones = [
      light.zoneTopbar,
      light.zoneStatusbar,
      light.zoneNavigation,
      light.zoneWorkspace,
      light.zoneInspector,
      light.zoneBottomPane,
    ];
    expect(new Set(zones).size).toBe(zones.length);
  });

  it("has CSS block in stylesheet", () => {
    expect(styles).toContain("[data-theme=\"light\"]");
    expectCssToken("color-bg-primary", light.bgPrimary);
    expectCssToken("color-text-primary", light.textPrimary);
  });

  it("provides light particle colors", () => {
    const particles = getThemeParticleTokens("light");
    expect(particles.colors.length).toBeGreaterThanOrEqual(3);
    expect(particles.maxCount).toBe(60);
  });
});

describe("deep-dark theme tokens", () => {
  const deep = getThemeColorTokens("deep-dark");

  it("provides darker backgrounds than default dark", () => {
    expect(deep.bgPrimary).not.toBe(DESIGN_TOKENS.color.bgPrimary);
    expect(deep.textPrimary).not.toBe(DESIGN_TOKENS.color.textPrimary);
  });

  it("keeps zone surfaces distinct within deep-dark theme", () => {
    const zones = [
      deep.zoneTopbar,
      deep.zoneStatusbar,
      deep.zoneNavigation,
      deep.zoneWorkspace,
      deep.zoneInspector,
      deep.zoneBottomPane,
    ];
    expect(new Set(zones).size).toBe(zones.length);
  });

  it("has CSS block in stylesheet", () => {
    expect(styles).toContain("[data-theme=\"deep-dark\"]");
    expectCssToken("color-bg-primary", deep.bgPrimary);
    expectCssToken("color-text-primary", deep.textPrimary);
  });

  it("provides deep-dark particle colors", () => {
    const particles = getThemeParticleTokens("deep-dark");
    expect(particles.colors.length).toBeGreaterThanOrEqual(3);
    expect(particles.maxCount).toBe(60);
  });
});

describe("theme utilities", () => {
  it('returns dark tokens for "system" mode', () => {
    expect(getThemeColorTokens("system")).toEqual(getThemeColorTokens("dark"));
    expect(getThemeParticleTokens("system")).toEqual(
      getThemeParticleTokens("dark"),
    );
  });

  it("each real theme has distinct color sets", () => {
    const dark = getThemeColorTokens("dark");
    const light = getThemeColorTokens("light");
    const deepDark = getThemeColorTokens("deep-dark");

    expect(dark.bgPrimary).not.toBe(light.bgPrimary);
    expect(dark.bgPrimary).not.toBe(deepDark.bgPrimary);
    expect(light.bgPrimary).not.toBe(deepDark.bgPrimary);
  });
});

describe("particle palette tokens", () => {
  const expectedColdParticlePalette = [
    "#3d5afe",
    "#536dfe",
    "#42a5f5",
    "#5c627a",
    "#1c1f2e",
  ] as const;

  it("uses the UX-spec cold particle palette for every theme", () => {
    expect(PARTICLE_COLOR_TOKENS).toEqual(expectedColdParticlePalette);

    for (const theme of ["dark", "light", "deep-dark"] as const) {
      const particles = getThemeParticleTokens(theme);
      expect(particles.colors).toEqual(PARTICLE_COLOR_TOKENS);
      expect(particles.maxCount).toBeLessThanOrEqual(60);
    }
  });

  it("keeps the legacy DESIGN_TOKENS particle export on the same palette", () => {
    expect(DESIGN_TOKENS.particle.colors).toEqual(PARTICLE_COLOR_TOKENS);
  });
});
