import type { JsonValue } from "./common";
import type { HealthStatusDto } from "./platform";

export interface CapabilityOverviewDto {
  capability: JsonValue;
  plugin_names: string[];
  plugin_count: number;
  input_contract_names: string[];
  output_contract_names: string[];
  required_permission_count: number;
  ui_contribution_count: number;
  health_status: HealthStatusDto;
}
