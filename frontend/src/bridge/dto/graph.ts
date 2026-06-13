import type { Id, JsonValue } from "./common";

export type GraphTypeDto =
  | "overview_risk_map"
  | "incident_graph"
  | "c2_graph"
  | "exfiltration_graph"
  | "lateral_propagation_graph"
  | "asset_exposure_graph"
  | "capability_dependency_graph"
  | "pipeline_graph"
  | "response_impact_graph"
  | string;

export type GraphScopeDto = "overview" | "incident" | "entity" | string;

export interface GraphViewRequestDto {
  graph_type: GraphTypeDto;
  scope: GraphScopeDto | JsonValue;
  title_redacted?: string | null;
  node_limit?: number | null;
  edge_limit?: number | null;
}

export interface GraphViewModelDto {
  graph_id?: Id;
  graph_type: GraphTypeDto;
  title?: JsonValue;
  nodes: JsonValue[];
  edges: JsonValue[];
  paths: JsonValue[];
  legend?: JsonValue;
  filters: JsonValue;
  redaction_status?: JsonValue;
  node_limit?: number;
  edge_limit?: number;
  truncated?: boolean;
}
