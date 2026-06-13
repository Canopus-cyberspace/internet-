import {
  DependencyGraphRenderer,
  DynamicFormRenderer,
  DynamicTableRenderer,
  EvidenceListRenderer,
  GenericKeyValueRenderer,
  GraphProjectionRenderer,
  HealthBadgeRenderer,
  MetricCardRenderer,
  PipelineGraphRenderer,
  ReportSectionRenderer,
  ResponseActionRenderer,
  RiskBreakdownRenderer,
  TimelineRenderer,
} from "./fallbackRenderers";
import { registerRenderer } from "./RendererRegistry";
import {
  validateGraphViewModelLike,
  validateSafeRendererContext,
  validateTableLike,
} from "./schemaGuards";
import type { RendererEntry } from "./types";

export const defaultRendererEntries: RendererEntry[] = [
  {
    rendererType: "metric_card",
    label: "Metric card",
    component: MetricCardRenderer,
    validate: validateSafeRendererContext,
  },
  {
    rendererType: "health_badge",
    label: "Health badge",
    component: HealthBadgeRenderer,
    validate: validateSafeRendererContext,
  },
  {
    rendererType: "key_value_panel",
    label: "Key value panel",
    component: GenericKeyValueRenderer,
    validate: validateSafeRendererContext,
  },
  {
    rendererType: "table",
    label: "Table",
    component: DynamicTableRenderer,
    validate: validateTableLike,
  },
  {
    rendererType: "timeline",
    label: "Timeline",
    component: TimelineRenderer,
    validate: validateTableLike,
  },
  {
    rendererType: "evidence_list",
    label: "Evidence list",
    component: EvidenceListRenderer,
    validate: validateTableLike,
  },
  {
    rendererType: "risk_breakdown",
    label: "Risk breakdown",
    component: RiskBreakdownRenderer,
    validate: validateTableLike,
  },
  {
    rendererType: "graph_projection",
    label: "Graph projection",
    component: GraphProjectionRenderer,
    validate: validateGraphViewModelLike,
  },
  {
    rendererType: "dependency_graph",
    label: "Dependency graph",
    component: DependencyGraphRenderer,
    validate: validateGraphViewModelLike,
  },
  {
    rendererType: "pipeline_graph",
    label: "Pipeline graph",
    component: PipelineGraphRenderer,
    validate: validateGraphViewModelLike,
  },
  {
    rendererType: "response_action_card",
    label: "Response action",
    component: ResponseActionRenderer,
    validate: validateTableLike,
  },
  {
    rendererType: "settings_form",
    label: "Settings form",
    component: DynamicFormRenderer,
    validate: validateSafeRendererContext,
  },
  {
    rendererType: "report_section",
    label: "Report section",
    component: ReportSectionRenderer,
    validate: validateTableLike,
  },
];

let registered = false;

export function registerDefaultRenderers() {
  if (registered) {
    return;
  }
  for (const entry of defaultRendererEntries) {
    registerRenderer(entry);
  }
  registered = true;
}
