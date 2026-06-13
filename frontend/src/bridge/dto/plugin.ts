import type { Id, JsonValue, Timestamp } from "./common";
import type { HealthSnapshotDto, MetricSampleDto } from "./platform";

export interface UiContributionDto {
  contribution_id: Id;
  plugin_id: Id;
  slot: string;
  renderer_type: string;
  title: string;
  data_source?: JsonValue;
  schema?: JsonValue;
  default_filters?: JsonValue;
  refresh_mode?: string;
  permissions?: JsonValue[];
}

export interface PluginManifestDto {
  plugin_id: Id;
  plugin_name: string;
  version: string;
  capability_domain: string;
  plugin_type?: string;
  maturity_level?: string;
  description?: string;
  runtime_mode: string;
  enabled_by_default: boolean;
  capability_tags?: string[];
  input_contracts: JsonValue[];
  output_contracts: JsonValue[];
  dependencies?: JsonValue[];
  required_permissions: JsonValue[];
  required_capabilities?: JsonValue[];
  optional_capabilities?: JsonValue[];
  metrics_schema?: JsonValue[];
  health_schema?: JsonValue[];
  finding_types: string[];
  graph_hint_types: string[];
  actions: JsonValue[];
  ui_contributions: UiContributionDto[];
}

export interface PluginCatalogViewDto {
  plugins: PluginManifestDto[];
  capabilities: JsonValue[];
  ui_contributions: UiContributionDto[];
  health: HealthSnapshotDto[];
  metrics: MetricSampleDto[];
  dependency_edge_count: number;
  mock_only: boolean;
  production_ready: boolean;
  generated_at: Timestamp;
}

export interface PluginLifecycleRequestDto {
  plugin_id: Id;
  reason_redacted: string;
  requested_by_redacted?: string | null;
}

export interface PluginLifecycleMutationResultDto {
  plugin_id: Id;
  plugin_name: string;
  state: "enabled" | "disabled" | "restart_requested" | string;
  applied_to_runtime: boolean;
  reason_redacted: string;
}
