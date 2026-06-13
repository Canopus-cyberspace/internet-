import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { HealthSnapshotDto, MetricSampleDto } from "../../../bridge/dto/platform";
import type { PluginManifestDto } from "../../../bridge/dto/plugin";
import { registerDefaultRenderers } from "../../../shared/renderers";
import {
  callClick,
  findByClassName,
  textContent,
} from "../../../shared/testing/reactElementQueries";
import {
  CapabilityAnalysisView,
  CapabilityTree,
  PluginManifestView,
  PluginMetricsPanel,
  PluginTableRow,
} from "./ComponentCenterView";

registerDefaultRenderers();

describe("Component Center panels", () => {
  it("redacts sensitive manifest strings while showing contract metadata", () => {
    const markup = renderToStaticMarkup(
      <PluginManifestView
        manifest={pluginManifest({
          input_contracts: [{ contract_name: "network.flow" }],
          output_contracts: [{ contract_name: "security.finding" }],
          required_permissions: [{ permission: "api_key_value_read" }],
          finding_types: ["raw_payload_detector"],
          graph_hint_types: ["process_connects_to_domain"],
          actions: [{ action_type: "recommend_only" }],
        })}
      />,
    );

    expect(markup).toContain("network.flow");
    expect(markup).toContain("security.finding");
    expect(markup).toContain("process_connects_to_domain");
    expect(markup).toContain("recommend_only");
    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("api_key_value_read");
    expect(markup).not.toContain("raw_payload_detector");
  });

  it("renders plugin metrics without exposing sensitive marker values", () => {
    const metrics: MetricSampleDto[] = [
      {
        metric_name: "session_token_counter",
        value: "raw_payload marker should be hidden",
        labels: {},
        observed_at: "2026-06-03T00:00:00Z",
        privacy_class: "internal",
      },
    ];

    const markup = renderToStaticMarkup(<PluginMetricsPanel metrics={metrics} />);

    expect(markup).toContain("[redacted]");
    expect(markup).toContain("internal");
    expect(markup).not.toContain("session_token_counter");
    expect(markup).not.toContain("raw_payload marker should be hidden");
  });

  it("keeps capability and plugin rows clickable", () => {
    const onSelectCapability = vi.fn();
    const onSelectPlugin = vi.fn();
    const onEnable = vi.fn();
    const onDisable = vi.fn();
    const onRestart = vi.fn();
    const manifest = pluginManifest({
      plugin_id: "plugin:very.long.identifier.with.sections",
      plugin_name: "Very Long Plugin Name For Overflow Regression Coverage",
      capability_domain: "detection",
      enabled_by_default: false,
    });

    const capabilityTree = CapabilityTree({
      capabilities: [
        {
          capability: {
            capability_domain: "detection",
            title: "Detection Capability With A Long Display Name",
          },
          health_status: "healthy",
          input_contract_names: [],
          output_contract_names: [],
          plugin_count: 1,
          plugin_names: [manifest.plugin_name],
          required_permission_count: 0,
          ui_contribution_count: 0,
        },
      ],
      selectedDomain: null,
      onSelect: onSelectCapability,
    });
    const pluginRow = PluginTableRow({
      health: health("healthy"),
      pending: false,
      plugin: manifest,
      selected: false,
      onDisable,
      onEnable,
      onRestart,
      onSelectPlugin,
    });

    const capabilityButton = findByClassName(
      capabilityTree,
      "capability-tree-item",
    )[0];
    const pluginButton = findByClassName(pluginRow, "plugin-row-button")[0];
    const enableButton = findByClassName(pluginRow, "icon-button").find((element) =>
      textContent(element).length === 0 && element.props.title === "Enable plugin",
    );

    expect(capabilityButton).toBeDefined();
    expect(pluginButton).toBeDefined();
    expect(enableButton).toBeDefined();
    callClick(capabilityButton);
    callClick(pluginButton);
    callClick(enableButton!);

    expect(onSelectCapability).toHaveBeenCalledWith("detection");
    expect(onSelectPlugin).toHaveBeenCalledWith(manifest.plugin_id);
    expect(onEnable).toHaveBeenCalledWith(manifest.plugin_id);
  });

  it("shows capability evidence, risk, graph, response, and recommendation panels", () => {
    const manifest = pluginManifest({
      plugin_id: "plugin:c2",
      plugin_name: "C2 Detection",
      capability_domain: "detection",
      enabled_by_default: false,
      output_contracts: [
        { contract_name: "security.finding" },
        { contract_name: "risk.hint" },
        { contract_name: "graph.hint" },
        { contract_name: "response.recommendation" },
      ],
      finding_types: ["c2_beacon"],
      graph_hint_types: ["process_connects_to_domain"],
    });
    const model = {
      catalog: null,
      capabilityOverviews: [],
      selectedCapabilityDomain: "detection",
      selectedPlugin: manifest,
      pluginHealth: health("degraded"),
      pluginMetrics: [],
      capability: {
        domain: "detection",
        title: "Detection",
        status: "degraded",
        plugins: [manifest],
        enabledPluginCount: 0,
        degradedPluginCount: 1,
        inputContracts: ["network.flow"],
        outputContracts: ["security.finding"],
        requiredPermissionCount: 1,
        uiContributionCount: 1,
        missingDependencies: ["C2 Detection: intelligence"],
        evidenceRows: [
          {
            pluginId: manifest.plugin_id,
            pluginName: manifest.plugin_name,
            evidence: "2 declared",
            findingCoverage: "1 finding types",
            sourceCoverage: "1 inputs",
            impact: "covered",
          },
        ],
        riskRows: [
          {
            pluginId: manifest.plugin_id,
            pluginName: manifest.plugin_name,
            findingTypes: 1,
            riskContracts: 1,
            alertContracts: 0,
            incidentContracts: 0,
          },
        ],
        graphRows: [
          {
            pluginId: manifest.plugin_id,
            pluginName: manifest.plugin_name,
            emittedHints: 1,
            acceptedHints: "graph stage",
            graphWrites: "hints only",
          },
        ],
        responseRows: [
          {
            pluginId: manifest.plugin_id,
            pluginName: manifest.plugin_name,
            recommendations: "plan output",
            approval: "not declared",
            rollback: "not declared",
          },
        ],
        recommendations: [
          "C2 Detection is disabled by default; dependent coverage is reduced.",
        ],
        dependencyProjection: {
          graph_type: "capability_dependency_graph",
          nodes: [{ id: manifest.plugin_id, label: manifest.plugin_name }],
          edges: [],
          paths: [],
        },
      },
    };

    const markup = renderToStaticMarkup(
      <CapabilityAnalysisView model={model as never} />,
    );

    expect(markup).toContain("Evidence coverage");
    expect(markup).toContain("Risk contribution");
    expect(markup).toContain("Graph contribution");
    expect(markup).toContain("Response coverage");
    expect(markup).toContain("Dependency graph");
    expect(markup).toContain("disabled by default");
    expect(markup).toContain("hints only");
  });
});

function pluginManifest(overrides: Partial<PluginManifestDto>): PluginManifestDto {
  return {
    plugin_id: "plugin:test",
    plugin_name: "Test Plugin",
    version: "1.0.0",
    capability_domain: "detection",
    plugin_type: "detection",
    maturity_level: "mock",
    description: "redacted metadata",
    runtime_mode: "static_internal",
    enabled_by_default: true,
    input_contracts: [],
    output_contracts: [],
    dependencies: [],
    required_permissions: [],
    required_capabilities: [],
    optional_capabilities: [],
    metrics_schema: [],
    health_schema: [],
    finding_types: [],
    graph_hint_types: [],
    actions: [],
    ui_contributions: [],
    ...overrides,
  };
}

function health(status: string): HealthSnapshotDto {
  return {
    subject: { plugin_id: "plugin:test" },
    status,
    liveness: status,
    readiness: status,
    message_redacted: "degraded metadata",
    observed_at: "2026-06-03T00:00:00Z",
    privacy_class: "internal",
  };
}
