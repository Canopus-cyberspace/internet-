import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { UiContributionDto } from "../../bridge/dto/plugin";
import { UnsupportedContributionRenderer } from "./fallbackRenderers";

describe("unsupported contribution renderer", () => {
  it("shows metric data through a generic metric fallback", () => {
    const markup = renderToStaticMarkup(
      <UnsupportedContributionRenderer
        contribution={contribution("future_metric")}
        data={{
          value: [
            {
              metric_name: "api_key_value_should_be_redacted",
              value: "session_token should be hidden",
            },
          ],
        }}
      />,
    );

    expect(markup).toContain("Generic fallback: Metrics");
    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("api_key_value_should_be_redacted");
    expect(markup).not.toContain("session_token should be hidden");
  });

  it("shows graph projection nodes without requiring a custom plugin page", () => {
    const markup = renderToStaticMarkup(
      <UnsupportedContributionRenderer
        contribution={contribution("future_graph")}
        data={{
          value: {
            graph_type: "future_projection",
            nodes: [
              {
                node_id: "node-1",
                label: "Suspicious process",
                privacy_class: "internal",
              },
            ],
            edges: [],
            paths: [],
          },
        }}
      />,
    );

    expect(markup).toContain("Generic fallback: Graph nodes");
    expect(markup).toContain("Suspicious process");
  });

  it("shows generic finding and evidence rows", () => {
    const findings = renderToStaticMarkup(
      <UnsupportedContributionRenderer
        contribution={contribution("future_findings")}
        data={{
          value: [
            {
              finding_id: "finding-1",
              finding_type: "c2",
              summary_redacted: "Beacon-like metadata",
            },
          ],
        }}
      />,
    );
    const evidence = renderToStaticMarkup(
      <UnsupportedContributionRenderer
        contribution={contribution("future_evidence")}
        data={{
          value: [
            {
              evidence_id: "evidence-1",
              evidence_type: "dns",
              summary_redacted: "Rare destination metadata",
            },
          ],
        }}
      />,
    );

    expect(findings).toContain("Generic fallback: Findings");
    expect(findings).toContain("Beacon-like metadata");
    expect(evidence).toContain("Generic fallback: Evidence");
    expect(evidence).toContain("Rare destination metadata");
  });
});

function contribution(rendererType: string): UiContributionDto {
  return {
    contribution_id: `contribution:${rendererType}`,
    plugin_id: "plugin:test",
    slot: "component_center.detail_panel",
    renderer_type: rendererType,
    title: "Unknown contribution",
  };
}
