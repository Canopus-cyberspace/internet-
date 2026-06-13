import type { ComponentType, ReactNode } from "react";
import type { JsonValue } from "../../bridge/dto/common";
import type {
  PluginManifestDto,
  UiContributionDto,
} from "../../bridge/dto/plugin";

export type RendererType =
  | "metric_card"
  | "health_badge"
  | "key_value_panel"
  | "table"
  | "timeline"
  | "evidence_list"
  | "risk_breakdown"
  | "graph_projection"
  | "dependency_graph"
  | "pipeline_graph"
  | "response_action_card"
  | "settings_form"
  | "report_section"
  | string;

export interface RendererDataEnvelope {
  readonly value: JsonValue;
  readonly schema?: JsonValue;
}

export interface RendererContext {
  readonly contribution: UiContributionDto;
  readonly manifest?: PluginManifestDto;
  readonly data: RendererDataEnvelope;
}

export interface RendererValidationResult {
  readonly valid: boolean;
  readonly reasonRedacted?: string;
}

export type UiContributionRendererComponent =
  ComponentType<RendererContext>;

export interface RendererEntry {
  readonly rendererType: RendererType;
  readonly label: string;
  readonly component: UiContributionRendererComponent;
  readonly validate?: (context: RendererContext) => RendererValidationResult;
}

export interface UiContributionRendererProps {
  readonly contribution: UiContributionDto;
  readonly manifest?: PluginManifestDto;
  readonly data?: JsonValue;
  readonly registry?: RendererRegistryApi;
}

export interface RendererRegistryApi {
  registerRenderer: (entry: RendererEntry) => void;
  resolveRenderer: (rendererType: RendererType) => RendererEntry;
  entries: () => RendererEntry[];
}

export interface RendererPanelProps {
  readonly title: string;
  readonly subtitle?: string;
  readonly children: ReactNode;
}
