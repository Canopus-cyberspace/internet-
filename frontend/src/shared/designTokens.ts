// CSS custom properties in frontend/src/styles.css are the source of truth.
// These values are provided only for programmatic consumers such as canvas and graph theming.

import type { ThemeMode } from "../stores/uiStore";

export interface ThemeColorTokens {
  bgPrimary: string;
  bgSecondary: string;
  bgTertiary: string;
  bgHover: string;
  bgActive: string;
  bgDisabled: string;
  bgEmpty: string;
  bgDegraded: string;
  zoneTopbar: string;
  zoneStatusbar: string;
  zoneNavigation: string;
  zoneNavigationRaised: string;
  zoneWorkspace: string;
  zoneWorkspaceRaised: string;
  zoneInspector: string;
  zoneInspectorRaised: string;
  zoneBottomPane: string;
  zoneBottomPaneRaised: string;
  surfaceCard: string;
  surfaceCardRaised: string;
  surfaceWidget: string;
  surfaceTable: string;
  surfaceTableHeader: string;
  surfaceTableRow: string;
  border: string;
  borderVariant: string;
  borderEmphasis: string;
  borderFocus: string;
  borderDanger: string;
  borderWarning: string;
  borderSuccess: string;
  borderInfo: string;
  borderZoneTopbar: string;
  borderZoneNavigation: string;
  borderZoneWorkspace: string;
  borderZoneInspector: string;
  borderZoneBottomPane: string;
  borderPanelActive: string;
  borderPanelGraph: string;
  borderPanelAlert: string;
  borderPanelWarning: string;
  borderPanelReport: string;
  borderPanelPassive: string;
  textPrimary: string;
  textSecondary: string;
  textMuted: string;
  textAccent: string;
  textDanger: string;
  textWarning: string;
  textSuccess: string;
  textInverse: string;
  accent: string;
  accentHover: string;
  accentPressed: string;
  danger: string;
  warning: string;
  success: string;
  info: string;
  severityCritical: string;
  severityHigh: string;
  severityMedium: string;
  severityLow: string;
  severityInfo: string;
}

export interface ThemeParticleTokens {
  colors: readonly string[];
  maxCount: number;
}

export interface ThemeTokens {
  color: ThemeColorTokens;
  particle: ThemeParticleTokens;
}

export interface RadiusTokens {
  none: "0";
  control: "2px";
  card: "4px";
  pill: "999px";
}

export interface SpaceTokens {
  0: "0";
  hairline: "1px";
  1: "2px";
  2: "4px";
  compact: "5px";
  3: "6px";
  row: "7px";
  badgeOffsetY: "-4px";
  badgeOffsetX: "-5px";
  controlInset: "24px";
  stackTight: "3px";
  4: "8px";
  5: "10px";
  6: "12px";
  7: "14px";
  8: "16px";
  roomy: "18px";
}

export interface ShadowTokens {
  shellChrome: "rgb(0 0 0 / 16%)";
  shellDrawer: "rgb(0 0 0 / 18%)";
  ambientGlow: "color-mix(in srgb, var(--color-info) 38%, transparent)";
  toolbarInset:
    "color-mix(in srgb, var(--color-border-zone-topbar) 70%, transparent)";
  surfaceInsetSoft:
    "color-mix(in srgb, var(--color-text-primary) 4%, transparent)";
  surfaceInset:
    "color-mix(in srgb, var(--color-text-primary) 5%, transparent)";
  surfaceInsetStrong:
    "color-mix(in srgb, var(--color-text-primary) 6%, transparent)";
  previewFocus:
    "color-mix(in srgb, var(--color-border-emphasis) 72%, transparent)";
  floatingPanel: "rgb(0 0 0 / 14%)";
  previewOverlay: "rgb(0 0 0 / 32%)";
  flowNode: "rgb(0 0 0 / 20%)";
  statusPulse: "color-mix(in srgb, var(--color-success) 52%, transparent)";
}

export interface SurfaceTokens {
  scrollbarThumb:
    "color-mix(in srgb, var(--color-border-emphasis) 76%, transparent)";
  scrollbarThumbHover:
    "color-mix(in srgb, var(--color-border-emphasis) 82%, var(--color-border))";
  toolbarBackground:
    "linear-gradient(180deg, color-mix(in srgb, var(--color-zone-topbar) 86%, var(--color-zone-navigation)) 0%, var(--color-zone-topbar) 100%)";
  toolbarHover:
    "color-mix(in srgb, var(--color-zone-navigation-raised) 72%, var(--color-bg-hover))";
  headerMuted:
    "color-mix(in srgb, var(--color-surface-card) 70%, transparent)";
  navigationHover:
    "color-mix(in srgb, var(--color-zone-navigation-raised) 78%, var(--color-bg-hover))";
  navigationActive:
    "color-mix(in srgb, var(--color-zone-navigation-raised) 46%, var(--color-bg-active))";
  previewDetachGhost:
    "color-mix(in srgb, var(--color-zone-bottom-pane-raised) 92%, transparent)";
  previewDetachTarget:
    "color-mix(in srgb, var(--color-zone-bottom-pane-raised) 86%, var(--color-bg-active))";
  previewGraph:
    "color-mix(in srgb, var(--color-zone-bottom-pane) 72%, var(--color-bg-primary))";
  borderChipGraph:
    "color-mix(in srgb, var(--color-border-panel-graph) 50%, var(--color-border-panel-passive))";
  chipGraph:
    "color-mix(in srgb, var(--color-zone-bottom-pane-raised) 64%, var(--color-surface-card))";
  borderChipAlert:
    "color-mix(in srgb, var(--color-border-panel-alert) 44%, var(--color-border-panel-passive))";
  chipAlert:
    "color-mix(in srgb, var(--color-surface-card) 86%, var(--color-border-panel-alert))";
  chipNavigation:
    "color-mix(in srgb, var(--color-surface-card) 86%, var(--color-zone-navigation))";
  selectionActive:
    "color-mix(in srgb, var(--color-bg-active) 82%, var(--color-border-panel-active))";
  statusDegraded:
    "color-mix(in srgb, var(--color-bg-degraded) 82%, var(--color-zone-statusbar))";
  statusChip:
    "color-mix(in srgb, var(--color-zone-statusbar) 70%, var(--color-zone-navigation-raised))";
  tableSelected:
    "color-mix(in srgb, var(--color-bg-active) 84%, var(--color-surface-table-row))";
  tableAlert:
    "color-mix(in srgb, var(--color-surface-table-row) 84%, var(--color-border-panel-alert))";
  tableWarning:
    "color-mix(in srgb, var(--color-surface-table-row) 88%, var(--color-border-panel-warning))";
  tableReport:
    "color-mix(in srgb, var(--color-surface-table-row) 88%, var(--color-zone-bottom-pane))";
  panelAlert:
    "color-mix(in srgb, var(--color-surface-card) 88%, var(--color-border-panel-alert))";
  borderPanelGraphMuted:
    "color-mix(in srgb, var(--color-border-panel-graph) 54%, var(--color-border-panel-passive))";
  panelReport:
    "color-mix(in srgb, var(--color-surface-card) 86%, var(--color-zone-bottom-pane))";
  panelNavigation:
    "color-mix(in srgb, var(--color-surface-card) 88%, var(--color-zone-navigation))";
  panelDetail:
    "color-mix(in srgb, var(--color-zone-inspector) 72%, var(--color-surface-card))";
  headerAlert:
    "color-mix(in srgb, var(--color-surface-card) 78%, var(--color-border-panel-alert))";
  headerGraph:
    "color-mix(in srgb, var(--color-zone-bottom-pane-raised) 72%, var(--color-surface-card))";
  headerWarning:
    "color-mix(in srgb, var(--color-surface-card) 80%, var(--color-bg-degraded))";
  headerReport:
    "color-mix(in srgb, var(--color-surface-card) 78%, var(--color-zone-bottom-pane))";
  headerNavigation:
    "color-mix(in srgb, var(--color-surface-card) 70%, var(--color-zone-navigation))";
  borderLegendGraph:
    "color-mix(in srgb, var(--color-border-panel-graph) 60%, var(--color-border-panel-passive))";
  legendGraph:
    "color-mix(in srgb, var(--color-surface-widget) 82%, var(--color-zone-bottom-pane))";
  borderReportMuted:
    "color-mix(in srgb, var(--color-border-panel-report) 56%, var(--color-border-panel-passive))";
  reportSummary:
    "color-mix(in srgb, var(--color-surface-widget) 84%, var(--color-zone-bottom-pane))";
  exportActionSelected:
    "color-mix(in srgb, var(--color-zone-bottom-pane) 42%, var(--color-surface-widget))";
  exportPreview:
    "color-mix(in srgb, var(--color-surface-widget) 82%, var(--color-zone-bottom-pane))";
  graphCanvas:
    "color-mix(in srgb, var(--color-bg-primary) 82%, var(--color-zone-bottom-pane))";
  graphCanvasGridDot:
    "color-mix(in srgb, var(--color-border-panel-graph) 28%, transparent)";
}

export const PARTICLE_COLOR_TOKENS = [
  "#3d5afe",
  "#536dfe",
  "#42a5f5",
  "#5c627a",
  "#1c1f2e",
] as const;

// ── Dark (default) ─────────────────────────────────────────────
const darkColor: ThemeColorTokens = {
  bgPrimary: "#0d0f14",
  bgSecondary: "#151820",
  bgTertiary: "#1b1f29",
  bgHover: "#252a34",
  bgActive: "#26364f",
  bgDisabled: "#101219",
  bgEmpty: "#11141b",
  bgDegraded: "#1a1913",
  zoneTopbar: "#0b0d12",
  zoneStatusbar: "#080a0e",
  zoneNavigation: "#15171d",
  zoneNavigationRaised: "#1f232b",
  zoneWorkspace: "#181b22",
  zoneWorkspaceRaised: "#20242c",
  zoneInspector: "#21252c",
  zoneInspectorRaised: "#2a2f39",
  zoneBottomPane: "#15181e",
  zoneBottomPaneRaised: "#20242a",
  surfaceCard: "#1c2028",
  surfaceCardRaised: "#222733",
  surfaceWidget: "#252b35",
  surfaceTable: "#171b22",
  surfaceTableHeader: "#242934",
  surfaceTableRow: "#1c212a",
  border: "#303640",
  borderVariant: "#282d35",
  borderEmphasis: "#4a5361",
  borderFocus: "#2f81f7",
  borderDanger: "#5a2a2e",
  borderWarning: "#5a4520",
  borderSuccess: "#2a4a2e",
  borderInfo: "#1a4050",
  borderZoneTopbar: "#2b3039",
  borderZoneNavigation: "#303642",
  borderZoneWorkspace: "#343a45",
  borderZoneInspector: "#3c434f",
  borderZoneBottomPane: "#333944",
  borderPanelActive: "#2f81f7",
  borderPanelGraph: "#424955",
  borderPanelAlert: "#5a3438",
  borderPanelWarning: "#5a4b2b",
  borderPanelReport: "#454b56",
  borderPanelPassive: "#303640",
  textPrimary: "#e1e4ed",
  textSecondary: "#949bb0",
  textMuted: "#5c627a",
  textAccent: "#8ab8ff",
  textDanger: "#ef7a7a",
  textWarning: "#ffb74d",
  textSuccess: "#81c784",
  textInverse: "#0d0f14",
  accent: "#2f81f7",
  accentHover: "#4d94ff",
  accentPressed: "#1f5fa8",
  danger: "#ef5350",
  warning: "#ffa726",
  success: "#66bb6a",
  info: "#29b6f6",
  severityCritical: "#ef5350",
  severityHigh: "#ff7043",
  severityMedium: "#ffa726",
  severityLow: "#66bb6a",
  severityInfo: "#42a5f5",
};

const darkParticle: ThemeParticleTokens = {
  colors: PARTICLE_COLOR_TOKENS,
  maxCount: 60,
};

// ── Light ──────────────────────────────────────────────────────
const lightColor: ThemeColorTokens = {
  bgPrimary: "#f7f8fa",
  bgSecondary: "#eff1f5",
  bgTertiary: "#e7eaf0",
  bgHover: "#dce0e8",
  bgActive: "#cfd8ea",
  bgDisabled: "#f2f3f7",
  bgEmpty: "#f0f2f6",
  bgDegraded: "#fef9ee",
  zoneTopbar: "#edeff4",
  zoneStatusbar: "#e5e7ee",
  zoneNavigation: "#f2f4f8",
  zoneNavigationRaised: "#e9ecf2",
  zoneWorkspace: "#fafbfc",
  zoneWorkspaceRaised: "#eff1f6",
  zoneInspector: "#f1f3f7",
  zoneInspectorRaised: "#e7eaf1",
  zoneBottomPane: "#f3f5f8",
  zoneBottomPaneRaised: "#ebedf3",
  surfaceCard: "#ffffff",
  surfaceCardRaised: "#f6f7fb",
  surfaceWidget: "#f1f3f8",
  surfaceTable: "#fafbfd",
  surfaceTableHeader: "#edf0f5",
  surfaceTableRow: "#f6f7fa",
  border: "#c4cad4",
  borderVariant: "#d2d7e0",
  borderEmphasis: "#8890a5",
  borderFocus: "#2f81f7",
  borderDanger: "#f0c0c6",
  borderWarning: "#f5d48a",
  borderSuccess: "#b2d8bc",
  borderInfo: "#a8d8f0",
  borderZoneTopbar: "#d2d7e0",
  borderZoneNavigation: "#dadfe8",
  borderZoneWorkspace: "#dde2eb",
  borderZoneInspector: "#dfe4ed",
  borderZoneBottomPane: "#d9dee7",
  borderPanelActive: "#2f81f7",
  borderPanelGraph: "#b8bfcd",
  borderPanelAlert: "#edbcc2",
  borderPanelWarning: "#eed088",
  borderPanelReport: "#c2c8d3",
  borderPanelPassive: "#d5dae3",
  textPrimary: "#181e2e",
  textSecondary: "#565e74",
  textMuted: "#8890a2",
  textAccent: "#1f5fa8",
  textDanger: "#c62828",
  textWarning: "#e65100",
  textSuccess: "#2e7d32",
  textInverse: "#ffffff",
  accent: "#2f81f7",
  accentHover: "#1f6ad6",
  accentPressed: "#1554a8",
  danger: "#e53935",
  warning: "#f57c00",
  success: "#43a047",
  info: "#039be5",
  severityCritical: "#e53935",
  severityHigh: "#f4511e",
  severityMedium: "#f57c00",
  severityLow: "#43a047",
  severityInfo: "#1e88e5",
};

const lightParticle: ThemeParticleTokens = {
  colors: PARTICLE_COLOR_TOKENS,
  maxCount: 60,
};

// ── Deep-dark ──────────────────────────────────────────────────
const deepDarkColor: ThemeColorTokens = {
  bgPrimary: "#05070d",
  bgSecondary: "#090c14",
  bgTertiary: "#0d1019",
  bgHover: "#151a26",
  bgActive: "#1a2440",
  bgDisabled: "#070910",
  bgEmpty: "#080a12",
  bgDegraded: "#14120c",
  zoneTopbar: "#030509",
  zoneStatusbar: "#020306",
  zoneNavigation: "#090b13",
  zoneNavigationRaised: "#11141d",
  zoneWorkspace: "#0b0d15",
  zoneWorkspaceRaised: "#12151e",
  zoneInspector: "#13161f",
  zoneInspectorRaised: "#1b1f2b",
  zoneBottomPane: "#090b12",
  zoneBottomPaneRaised: "#12151d",
  surfaceCard: "#0d1018",
  surfaceCardRaised: "#141822",
  surfaceWidget: "#171b26",
  surfaceTable: "#0a0d14",
  surfaceTableHeader: "#141722",
  surfaceTableRow: "#0e111a",
  border: "#1e2330",
  borderVariant: "#171b26",
  borderEmphasis: "#3a4252",
  borderFocus: "#2f81f7",
  borderDanger: "#4a1a1e",
  borderWarning: "#4a3515",
  borderSuccess: "#1a3a1e",
  borderInfo: "#103040",
  borderZoneTopbar: "#191d28",
  borderZoneNavigation: "#1e2330",
  borderZoneWorkspace: "#222734",
  borderZoneInspector: "#292f3c",
  borderZoneBottomPane: "#212631",
  borderPanelActive: "#2f81f7",
  borderPanelGraph: "#2e3542",
  borderPanelAlert: "#4a2428",
  borderPanelWarning: "#4a3b1b",
  borderPanelReport: "#313a45",
  borderPanelPassive: "#1e2330",
  textPrimary: "#e8ebf2",
  textSecondary: "#8890a5",
  textMuted: "#4a5268",
  textAccent: "#80b4ff",
  textDanger: "#f28080",
  textWarning: "#ffc060",
  textSuccess: "#85cc85",
  textInverse: "#05070d",
  accent: "#3d8bf7",
  accentHover: "#5da4ff",
  accentPressed: "#2f6fc8",
  danger: "#f06060",
  warning: "#ffb040",
  success: "#70c470",
  info: "#3dc0f8",
  severityCritical: "#f06060",
  severityHigh: "#ff8050",
  severityMedium: "#ffb040",
  severityLow: "#70c470",
  severityInfo: "#50b0f8",
};

const deepDarkParticle: ThemeParticleTokens = {
  colors: PARTICLE_COLOR_TOKENS,
  maxCount: 60,
};

// ── Theme lookup ───────────────────────────────────────────────
const THEME_COLORS: Record<Exclude<ThemeMode, "system">, ThemeColorTokens> = {
  dark: darkColor,
  light: lightColor,
  "deep-dark": deepDarkColor,
};

const THEME_PARTICLES: Record<Exclude<ThemeMode, "system">, ThemeParticleTokens> = {
  dark: darkParticle,
  light: lightParticle,
  "deep-dark": deepDarkParticle,
};

const shadowTokens = {
  shellChrome: "rgb(0 0 0 / 16%)",
  shellDrawer: "rgb(0 0 0 / 18%)",
  ambientGlow: "color-mix(in srgb, var(--color-info) 38%, transparent)",
  toolbarInset:
    "color-mix(in srgb, var(--color-border-zone-topbar) 70%, transparent)",
  surfaceInsetSoft:
    "color-mix(in srgb, var(--color-text-primary) 4%, transparent)",
  surfaceInset:
    "color-mix(in srgb, var(--color-text-primary) 5%, transparent)",
  surfaceInsetStrong:
    "color-mix(in srgb, var(--color-text-primary) 6%, transparent)",
  previewFocus:
    "color-mix(in srgb, var(--color-border-emphasis) 72%, transparent)",
  floatingPanel: "rgb(0 0 0 / 14%)",
  previewOverlay: "rgb(0 0 0 / 32%)",
  flowNode: "rgb(0 0 0 / 20%)",
  statusPulse: "color-mix(in srgb, var(--color-success) 52%, transparent)",
} satisfies ShadowTokens;

const surfaceTokens = {
  scrollbarThumb:
    "color-mix(in srgb, var(--color-border-emphasis) 76%, transparent)",
  scrollbarThumbHover:
    "color-mix(in srgb, var(--color-border-emphasis) 82%, var(--color-border))",
  toolbarBackground:
    "linear-gradient(180deg, color-mix(in srgb, var(--color-zone-topbar) 86%, var(--color-zone-navigation)) 0%, var(--color-zone-topbar) 100%)",
  toolbarHover:
    "color-mix(in srgb, var(--color-zone-navigation-raised) 72%, var(--color-bg-hover))",
  headerMuted:
    "color-mix(in srgb, var(--color-surface-card) 70%, transparent)",
  navigationHover:
    "color-mix(in srgb, var(--color-zone-navigation-raised) 78%, var(--color-bg-hover))",
  navigationActive:
    "color-mix(in srgb, var(--color-zone-navigation-raised) 46%, var(--color-bg-active))",
  previewDetachGhost:
    "color-mix(in srgb, var(--color-zone-bottom-pane-raised) 92%, transparent)",
  previewDetachTarget:
    "color-mix(in srgb, var(--color-zone-bottom-pane-raised) 86%, var(--color-bg-active))",
  previewGraph:
    "color-mix(in srgb, var(--color-zone-bottom-pane) 72%, var(--color-bg-primary))",
  borderChipGraph:
    "color-mix(in srgb, var(--color-border-panel-graph) 50%, var(--color-border-panel-passive))",
  chipGraph:
    "color-mix(in srgb, var(--color-zone-bottom-pane-raised) 64%, var(--color-surface-card))",
  borderChipAlert:
    "color-mix(in srgb, var(--color-border-panel-alert) 44%, var(--color-border-panel-passive))",
  chipAlert:
    "color-mix(in srgb, var(--color-surface-card) 86%, var(--color-border-panel-alert))",
  chipNavigation:
    "color-mix(in srgb, var(--color-surface-card) 86%, var(--color-zone-navigation))",
  selectionActive:
    "color-mix(in srgb, var(--color-bg-active) 82%, var(--color-border-panel-active))",
  statusDegraded:
    "color-mix(in srgb, var(--color-bg-degraded) 82%, var(--color-zone-statusbar))",
  statusChip:
    "color-mix(in srgb, var(--color-zone-statusbar) 70%, var(--color-zone-navigation-raised))",
  tableSelected:
    "color-mix(in srgb, var(--color-bg-active) 84%, var(--color-surface-table-row))",
  tableAlert:
    "color-mix(in srgb, var(--color-surface-table-row) 84%, var(--color-border-panel-alert))",
  tableWarning:
    "color-mix(in srgb, var(--color-surface-table-row) 88%, var(--color-border-panel-warning))",
  tableReport:
    "color-mix(in srgb, var(--color-surface-table-row) 88%, var(--color-zone-bottom-pane))",
  panelAlert:
    "color-mix(in srgb, var(--color-surface-card) 88%, var(--color-border-panel-alert))",
  borderPanelGraphMuted:
    "color-mix(in srgb, var(--color-border-panel-graph) 54%, var(--color-border-panel-passive))",
  panelReport:
    "color-mix(in srgb, var(--color-surface-card) 86%, var(--color-zone-bottom-pane))",
  panelNavigation:
    "color-mix(in srgb, var(--color-surface-card) 88%, var(--color-zone-navigation))",
  panelDetail:
    "color-mix(in srgb, var(--color-zone-inspector) 72%, var(--color-surface-card))",
  headerAlert:
    "color-mix(in srgb, var(--color-surface-card) 78%, var(--color-border-panel-alert))",
  headerGraph:
    "color-mix(in srgb, var(--color-zone-bottom-pane-raised) 72%, var(--color-surface-card))",
  headerWarning:
    "color-mix(in srgb, var(--color-surface-card) 80%, var(--color-bg-degraded))",
  headerReport:
    "color-mix(in srgb, var(--color-surface-card) 78%, var(--color-zone-bottom-pane))",
  headerNavigation:
    "color-mix(in srgb, var(--color-surface-card) 70%, var(--color-zone-navigation))",
  borderLegendGraph:
    "color-mix(in srgb, var(--color-border-panel-graph) 60%, var(--color-border-panel-passive))",
  legendGraph:
    "color-mix(in srgb, var(--color-surface-widget) 82%, var(--color-zone-bottom-pane))",
  borderReportMuted:
    "color-mix(in srgb, var(--color-border-panel-report) 56%, var(--color-border-panel-passive))",
  reportSummary:
    "color-mix(in srgb, var(--color-surface-widget) 84%, var(--color-zone-bottom-pane))",
  exportActionSelected:
    "color-mix(in srgb, var(--color-zone-bottom-pane) 42%, var(--color-surface-widget))",
  exportPreview:
    "color-mix(in srgb, var(--color-surface-widget) 82%, var(--color-zone-bottom-pane))",
  graphCanvas:
    "color-mix(in srgb, var(--color-bg-primary) 82%, var(--color-zone-bottom-pane))",
  graphCanvasGridDot:
    "color-mix(in srgb, var(--color-border-panel-graph) 28%, transparent)",
} satisfies SurfaceTokens;

const radiusTokens = {
  none: "0",
  control: "2px",
  card: "4px",
  pill: "999px",
} satisfies RadiusTokens;

const spaceTokens = {
  0: "0",
  hairline: "1px",
  1: "2px",
  2: "4px",
  compact: "5px",
  3: "6px",
  row: "7px",
  badgeOffsetY: "-4px",
  badgeOffsetX: "-5px",
  controlInset: "24px",
  stackTight: "3px",
  4: "8px",
  5: "10px",
  6: "12px",
  7: "14px",
  8: "16px",
  roomy: "18px",
} satisfies SpaceTokens;

/**
 * Resolve a ThemeMode to the effective color tokens.
 * "system" falls back to dark tokens (the ThemeProvider handles
 * the actual OS-level resolution for CSS; programmatic consumers
 * use this as a reasonable default).
 */
export function getThemeColorTokens(mode: ThemeMode): ThemeColorTokens {
  if (mode === "system") {
    return darkColor;
  }
  return THEME_COLORS[mode];
}

/**
 * Return particle configuration for a given ThemeMode.
 */
export function getThemeParticleTokens(mode: ThemeMode): ThemeParticleTokens {
  if (mode === "system") {
    return darkParticle;
  }
  return THEME_PARTICLES[mode];
}

/**
 * Legacy DESIGN_TOKENS export — mirrors the dark theme so existing
 * imports that haven't been migrated still compile.
 *
 * Prefer getThemeColorTokens() / getThemeParticleTokens() in new code.
 */
export const DESIGN_TOKENS = {
  color: darkColor as Readonly<ThemeColorTokens>,
  particle: darkParticle as Readonly<ThemeParticleTokens>,
  font: {
    family:
      '"Segoe UI", "SF Pro Text", -apple-system, BlinkMacSystemFont, system-ui, sans-serif',
    mono: '"Cascadia Code", "Fira Code", "JetBrains Mono", "Consolas", monospace',
    sizeXs: "11px",
    sizeSm: "12px",
    sizeBase: "13px",
    sizeLg: "14px",
    sizeXl: "16px",
    size2xl: "20px",
    size3xl: "28px",
    weightLight: 300,
    weightRegular: 400,
    weightSemibold: 600,
    weightBold: 700,
  },
  motion: {
    instant: "0ms",
    fast: "100ms",
    default: "150ms",
    slow: "200ms",
    deliberate: "300ms",
    easeDefault: "ease",
    easeOut: "ease-out",
    easeInOut: "ease-in-out",
  },
  shadow: shadowTokens,
  surface: surfaceTokens,
  radius: radiusTokens,
  space: spaceTokens,
} as const;
