import { describe, expect, it } from "vitest";
import type { UiContributionDto } from "../../bridge/dto/plugin";
import {
  defaultRendererEntries,
  GraphProjectionRenderer,
  RendererRegistry,
  UiContributionRenderer,
  UnsupportedContributionRenderer,
} from ".";

const REQUIRED_RENDERER_TYPES = [
  "metric_card",
  "health_badge",
  "key_value_panel",
  "table",
  "timeline",
  "evidence_list",
  "risk_breakdown",
  "graph_projection",
  "dependency_graph",
  "pipeline_graph",
  "response_action_card",
  "settings_form",
  "report_section",
];

describe("renderer registry", () => {
  it("registers every Task 250 renderer type", () => {
    const registry = new RendererRegistry();
    for (const entry of defaultRendererEntries) {
      registry.registerRenderer(entry);
    }

    expect(defaultRendererEntries.map((entry) => entry.rendererType)).toEqual(
      REQUIRED_RENDERER_TYPES,
    );
    expect(registry.entries().map((entry) => entry.rendererType)).toEqual(
      REQUIRED_RENDERER_TYPES,
    );
    expect(registry.resolveRenderer("graph_projection").component).toBe(
      GraphProjectionRenderer,
    );
  });

  it("resolves unknown renderer types to the safe unsupported renderer", () => {
    const registry = new RendererRegistry();

    expect(registry.resolveRenderer("future_renderer").component).toBe(
      UnsupportedContributionRenderer,
    );
  });

  it("rejects executable renderer registrations", () => {
    const registry = new RendererRegistry();

    expect(() =>
      registry.registerRenderer({
        rendererType: "javascript_bundle",
        label: "Unsafe",
        component: UnsupportedContributionRenderer,
      }),
    ).toThrow(/executable plugin UI/);
  });

  it("falls back when renderer validation rejects unsafe graph data", () => {
    const registry = new RendererRegistry();
    for (const entry of defaultRendererEntries) {
      registry.registerRenderer(entry);
    }

    const element = UiContributionRenderer({
      contribution: contribution("graph_projection"),
      data: { canonical_node: "must not render" },
      registry,
    });

    expect(element.type).toBe(UnsupportedContributionRenderer);
    expect(element.props.data.value).toEqual({
      validation_error_redacted:
        "graph renderer requires GraphViewModel or projection data",
    });
  });
});

function contribution(rendererType: string): UiContributionDto {
  return {
    contribution_id: `contribution:${rendererType}`,
    plugin_id: "plugin:test",
    slot: "component_center.detail_panel",
    renderer_type: rendererType,
    title: "Contribution",
  };
}
