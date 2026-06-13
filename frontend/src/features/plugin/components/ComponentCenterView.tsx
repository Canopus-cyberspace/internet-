import {
  Activity,
  GitBranch,
  ListChecks,
  Network,
  Power,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { JsonValue } from "../../../bridge/dto/common";
import type {
  HealthSnapshotDto,
  MetricSampleDto,
} from "../../../bridge/dto/platform";
import type {
  PluginCatalogViewDto,
  PluginManifestDto,
  UiContributionDto,
} from "../../../bridge/dto/plugin";
import type { CapabilityOverviewDto } from "../../../bridge/dto/capability";
import { useCapabilityOverviewQuery } from "../../capability/hooks";
import {
  useDisablePluginMutation,
  useEnablePluginMutation,
  usePluginCatalogQuery,
  usePluginManifestQuery,
  useRestartPluginMutation,
} from "../hooks";
import { useSelectionStore } from "../../../stores/selectionStore";
import { EmptyState } from "../../../shared/layout/EmptyState";
import { ShellTable } from "../../../shared/table/ShellTable";
import { stringifySafe, UiContributionRenderer } from "../../../shared/renderers";

type ComponentCenterStatus = "idle" | "loading" | "error" | "ready";

interface ComponentCenterModel {
  catalog: PluginCatalogViewDto | null;
  capabilityOverviews: CapabilityOverviewDto[];
  selectedCapabilityDomain: string | null;
  selectedPlugin: PluginManifestDto | null;
  pluginHealth: HealthSnapshotDto | null;
  pluginMetrics: MetricSampleDto[];
  capability: CapabilityAnalysisModel | null;
}

interface CapabilityAnalysisModel {
  domain: string;
  title: string;
  status: string;
  plugins: PluginManifestDto[];
  enabledPluginCount: number;
  degradedPluginCount: number;
  inputContracts: string[];
  outputContracts: string[];
  requiredPermissionCount: number;
  uiContributionCount: number;
  missingDependencies: string[];
  evidenceRows: CoverageRow[];
  riskRows: RiskContributionRow[];
  graphRows: GraphContributionRow[];
  responseRows: ResponseCoverageRow[];
  recommendations: string[];
  dependencyProjection: JsonValue;
}

interface CoverageRow {
  pluginId: string;
  pluginName: string;
  evidence: string;
  findingCoverage: string;
  sourceCoverage: string;
  impact: string;
}

interface RiskContributionRow {
  pluginId: string;
  pluginName: string;
  findingTypes: number;
  riskContracts: number;
  alertContracts: number;
  incidentContracts: number;
}

interface GraphContributionRow {
  pluginId: string;
  pluginName: string;
  emittedHints: number;
  acceptedHints: string;
  graphWrites: string;
}

interface ResponseCoverageRow {
  pluginId: string;
  pluginName: string;
  recommendations: string;
  approval: string;
  rollback: string;
}

export function ComponentCenterView() {
  const catalogQuery = usePluginCatalogQuery();
  const capabilityQuery = useCapabilityOverviewQuery();
  const selectedPluginId = useSelectionStore((state) => state.selectedPluginId);
  const setSelectedPluginId = useSelectionStore(
    (state) => state.setSelectedPluginId,
  );
  const [selectedCapabilityDomain, setSelectedCapabilityDomain] = useState<
    string | null
  >(null);

  const catalog = catalogQuery.data ?? null;
  const capabilityOverviews = capabilityQuery.data ?? [];
  const plugins = catalog?.plugins ?? [];

  const defaultCapabilityDomain = useMemo(
    () => capabilityOverviews[0] ? capabilityDomain(capabilityOverviews[0]) : null,
    [capabilityOverviews],
  );

  useEffect(() => {
    if (!selectedCapabilityDomain && defaultCapabilityDomain) {
      setSelectedCapabilityDomain(defaultCapabilityDomain);
    }
  }, [defaultCapabilityDomain, selectedCapabilityDomain]);

  useEffect(() => {
    if (!plugins.length) {
      return;
    }
    if (!selectedPluginId || !plugins.some((plugin) => plugin.plugin_id === selectedPluginId)) {
      setSelectedPluginId(plugins[0].plugin_id);
    }
  }, [plugins, selectedPluginId, setSelectedPluginId]);

  const manifestQuery = usePluginManifestQuery(selectedPluginId);
  const selectedPlugin =
    manifestQuery.data ??
    plugins.find((plugin) => plugin.plugin_id === selectedPluginId) ??
    null;

  const healthByPlugin = useMemo(() => buildHealthByPlugin(catalog), [catalog]);
  const metricsByPlugin = useMemo(() => buildMetricsByPlugin(catalog), [catalog]);
  const capability = useMemo(
    () =>
      selectedCapabilityDomain && catalog
        ? buildCapabilityAnalysis(
            selectedCapabilityDomain,
            catalog,
            capabilityOverviews,
            healthByPlugin,
          )
        : null,
    [catalog, capabilityOverviews, healthByPlugin, selectedCapabilityDomain],
  );

  const model: ComponentCenterModel = {
    catalog,
    capabilityOverviews,
    selectedCapabilityDomain,
    selectedPlugin,
    pluginHealth: selectedPlugin ? healthByPlugin.get(selectedPlugin.plugin_id) ?? null : null,
    pluginMetrics: selectedPlugin ? metricsByPlugin.get(selectedPlugin.plugin_id) ?? [] : [],
    capability,
  };

  const status: ComponentCenterStatus = catalogQuery.isLoading || capabilityQuery.isLoading
    ? "loading"
    : catalogQuery.isError || capabilityQuery.isError
      ? "error"
      : "ready";

  if (status === "loading") {
    return <EmptyState title="Loading components" detail="Catalog metadata is being read." />;
  }

  if (status === "error") {
    return (
      <EmptyState
        title="Component catalog unavailable"
        detail="The read model returned a redacted command error."
      />
    );
  }

  return (
    <div className="component-center">
      <CapabilityTree
        capabilities={capabilityOverviews}
        selectedDomain={selectedCapabilityDomain}
        onSelect={(domain) => {
          setSelectedCapabilityDomain(domain);
          const firstPlugin = plugins.find((plugin) => plugin.capability_domain === domain);
          if (firstPlugin) {
            setSelectedPluginId(firstPlugin.plugin_id);
          }
        }}
      />
      <main className="component-center-main">
        <PluginTable
          catalog={catalog}
          selectedPluginId={selectedPlugin?.plugin_id ?? null}
          selectedCapabilityDomain={selectedCapabilityDomain}
          healthByPlugin={healthByPlugin}
          onSelectPlugin={setSelectedPluginId}
        />
        <CapabilityAnalysisView model={model} />
      </main>
      <PluginDetailPanel
        manifest={selectedPlugin}
        health={model.pluginHealth}
        metrics={model.pluginMetrics}
      />
    </div>
  );
}

interface CapabilityTreeProps {
  capabilities: CapabilityOverviewDto[];
  selectedDomain: string | null;
  onSelect: (domain: string) => void;
}

export function CapabilityTree({
  capabilities,
  selectedDomain,
  onSelect,
}: CapabilityTreeProps) {
  return (
    <aside className="capability-tree" aria-label="Capability tree">
      <div className="component-panel-header">
        <strong>Capabilities</strong>
        <span>{capabilities.length}</span>
      </div>
      <div className="capability-tree-list">
        {capabilities.map((capability) => {
          const domain = capabilityDomain(capability);
          const selected = domain === selectedDomain;
          return (
            <button
              className="capability-tree-item"
              data-selected={selected}
              key={domain}
              type="button"
              onClick={() => onSelect(domain)}
            >
              <GitBranch size={14} aria-hidden="true" />
              <span>{displayText(capabilityTitle(capability))}</span>
              <small>{capability.plugin_count}</small>
            </button>
          );
        })}
      </div>
    </aside>
  );
}

interface PluginTableProps {
  catalog: PluginCatalogViewDto | null;
  selectedPluginId: string | null;
  selectedCapabilityDomain: string | null;
  healthByPlugin: Map<string, HealthSnapshotDto>;
  onSelectPlugin: (pluginId: string | null) => void;
}

export function PluginTable({
  catalog,
  selectedPluginId,
  selectedCapabilityDomain,
  healthByPlugin,
  onSelectPlugin,
}: PluginTableProps) {
  const enableMutation = useEnablePluginMutation();
  const disableMutation = useDisablePluginMutation();
  const restartMutation = useRestartPluginMutation();
  const plugins = (catalog?.plugins ?? []).filter((plugin) =>
    selectedCapabilityDomain ? plugin.capability_domain === selectedCapabilityDomain : true,
  );
  const pending =
    enableMutation.isPending || disableMutation.isPending || restartMutation.isPending;

  return (
    <section className="component-panel plugin-table-panel">
      <div className="component-panel-header">
        <strong>Plugin table</strong>
        <span>{plugins.length} visible</span>
      </div>
      <div className="plugin-table scroll-region table-scroll-region" role="table">
        <div className="plugin-table-row header" role="row">
          <div role="columnheader">Plugin</div>
          <div role="columnheader">Health</div>
          <div role="columnheader">Inputs</div>
          <div role="columnheader">Outputs</div>
          <div role="columnheader">UI</div>
          <div role="columnheader">Actions</div>
        </div>
        {plugins.map((plugin) => (
          <PluginTableRow
            health={healthByPlugin.get(plugin.plugin_id) ?? null}
            key={plugin.plugin_id}
            pending={pending}
            plugin={plugin}
            selected={plugin.plugin_id === selectedPluginId}
            onDisable={(pluginId) =>
              disableMutation.mutate(lifecycleRequest(pluginId, "disable requested"))
            }
            onEnable={(pluginId) =>
              enableMutation.mutate(lifecycleRequest(pluginId, "enable requested"))
            }
            onRestart={(pluginId) =>
              restartMutation.mutate(lifecycleRequest(pluginId, "restart requested"))
            }
            onSelectPlugin={onSelectPlugin}
          />
        ))}
      </div>
    </section>
  );
}

interface PluginTableRowProps {
  readonly health: HealthSnapshotDto | null;
  readonly pending: boolean;
  readonly plugin: PluginManifestDto;
  readonly selected: boolean;
  readonly onDisable: (pluginId: string) => void;
  readonly onEnable: (pluginId: string) => void;
  readonly onRestart: (pluginId: string) => void;
  readonly onSelectPlugin: (pluginId: string) => void;
}

export function PluginTableRow({
  health,
  pending,
  plugin,
  selected,
  onDisable,
  onEnable,
  onRestart,
  onSelectPlugin,
}: PluginTableRowProps) {
  const status = health?.status ?? "unknown";

  return (
    <div
      className="plugin-table-row"
      data-selected={selected}
      data-severity={statusSeverity(status)}
      role="row"
    >
      <button
        className="plugin-row-button"
        type="button"
        onClick={() => onSelectPlugin(plugin.plugin_id)}
      >
        <span>{displayText(plugin.plugin_name)}</span>
        <small>{displayText(plugin.capability_domain)}</small>
      </button>
      <div role="cell">
        <StatusPill status={status} />
      </div>
      <div role="cell">{plugin.input_contracts.length}</div>
      <div role="cell">{plugin.output_contracts.length}</div>
      <div role="cell">{plugin.ui_contributions.length}</div>
      <div className="plugin-action-group" role="cell">
        <button
          className="icon-button"
          type="button"
          title="Enable plugin"
          aria-label={`Enable ${displayText(plugin.plugin_name)}`}
          disabled={pending || plugin.enabled_by_default}
          onClick={() => onEnable(plugin.plugin_id)}
        >
          <Power size={14} aria-hidden="true" />
        </button>
        <button
          className="icon-button"
          type="button"
          title="Disable plugin"
          aria-label={`Disable ${displayText(plugin.plugin_name)}`}
          disabled={pending || !plugin.enabled_by_default}
          onClick={() => onDisable(plugin.plugin_id)}
        >
          <ShieldOff size={14} aria-hidden="true" />
        </button>
        <button
          className="icon-button"
          type="button"
          title="Restart plugin"
          aria-label={`Restart ${displayText(plugin.plugin_name)}`}
          disabled={pending}
          onClick={() => onRestart(plugin.plugin_id)}
        >
          <RefreshCw size={14} aria-hidden="true" />
        </button>
      </div>
    </div>
  );
}

interface PluginDetailPanelProps {
  manifest: PluginManifestDto | null;
  health: HealthSnapshotDto | null;
  metrics: MetricSampleDto[];
}

export function PluginDetailPanel({
  manifest,
  health,
  metrics,
}: PluginDetailPanelProps) {
  if (!manifest) {
    return (
      <aside className="component-detail-panel">
        <EmptyState title="No plugin selected" detail="Catalog metadata is empty." />
      </aside>
    );
  }

  return (
    <aside className="component-detail-panel">
      <div className="component-panel-header">
        <strong>{displayText(manifest.plugin_name)}</strong>
        <StatusPill status={health?.status ?? "unknown"} />
      </div>
      <div className="component-detail-scroll">
        <PluginManifestView manifest={manifest} />
        <PluginHealthPanel health={health} />
        <PluginMetricsPanel metrics={metrics} />
        <section className="component-panel compact">
          <div className="component-panel-header">
            <strong>UI contributions</strong>
            <span>{manifest.ui_contributions.length}</span>
          </div>
          <div className="ui-contribution-stack">
            {manifest.ui_contributions.map((contribution) => (
              <UiContributionRenderer
                contribution={contribution}
                data={contributionRendererData(contribution, manifest, health, metrics)}
                key={contribution.contribution_id}
                manifest={manifest}
              />
            ))}
          </div>
        </section>
      </div>
    </aside>
  );
}

export function PluginManifestView({
  manifest,
}: {
  readonly manifest: PluginManifestDto;
}) {
  const dependencies = manifest.dependencies ?? [];
  return (
    <section className="component-panel compact">
      <div className="component-panel-header">
        <strong>Manifest</strong>
        <span>{displayText(manifest.version)}</span>
      </div>
      <dl className="component-kv">
        <div>
          <dt>Runtime</dt>
          <dd>{displayText(manifest.runtime_mode)}</dd>
        </div>
        <div>
          <dt>Type</dt>
          <dd>{displayText(manifest.plugin_type ?? "plugin")}</dd>
        </div>
        <div>
          <dt>Maturity</dt>
          <dd>{displayText(manifest.maturity_level ?? "unknown")}</dd>
        </div>
        <div>
          <dt>Capability</dt>
          <dd>{displayText(manifest.capability_domain)}</dd>
        </div>
      </dl>
      <TokenGroup title="Input contracts" values={manifest.input_contracts.map(contractLabel)} />
      <TokenGroup title="Output contracts" values={manifest.output_contracts.map(contractLabel)} />
      <TokenGroup
        title="Permissions"
        values={manifest.required_permissions.map(permissionLabel)}
      />
      <TokenGroup title="Dependencies" values={dependencies.map(dependencyLabel)} />
      <TokenGroup title="Findings" values={manifest.finding_types} />
      <TokenGroup title="Graph hints" values={manifest.graph_hint_types} />
      <TokenGroup title="Actions" values={manifest.actions.map(actionLabel)} />
    </section>
  );
}

export function PluginHealthPanel({
  health,
}: {
  readonly health: HealthSnapshotDto | null;
}) {
  return (
    <section className="component-panel compact">
      <div className="component-panel-header">
        <strong>Health</strong>
        <StatusPill status={health?.status ?? "unknown"} />
      </div>
      <dl className="component-kv">
        <div>
          <dt>Liveness</dt>
          <dd>{health?.liveness ?? "unknown"}</dd>
        </div>
        <div>
          <dt>Readiness</dt>
          <dd>{health?.readiness ?? "unknown"}</dd>
        </div>
        <div>
          <dt>Privacy</dt>
          <dd>{health?.privacy_class ?? "internal"}</dd>
        </div>
        <div>
          <dt>Observed</dt>
          <dd>{health?.observed_at ?? "not observed"}</dd>
        </div>
      </dl>
      {health?.message_redacted ? (
        <p className="component-muted">{displayText(health.message_redacted)}</p>
      ) : null}
    </section>
  );
}

export function PluginMetricsPanel({
  metrics,
}: {
  readonly metrics: MetricSampleDto[];
}) {
  return (
    <section className="component-panel compact">
      <div className="component-panel-header">
        <strong>Metrics</strong>
        <span>{metrics.length}</span>
      </div>
      {metrics.length ? (
        <ShellTable
          columns={[
            { key: "metric", label: "Metric" },
            { key: "value", label: "Value" },
            { key: "privacy", label: "Privacy" },
          ]}
          rows={metrics.map((metric) => ({
            id: displayText(metric.metric_name),
            cells: {
              metric: displayText(metric.metric_name),
              value: shortJson(metric.value),
              privacy: displayText(metric.privacy_class),
            },
          }))}
        />
      ) : (
        <span className="component-muted">No metric samples</span>
      )}
    </section>
  );
}

export function CapabilityAnalysisView({
  model,
}: {
  readonly model: ComponentCenterModel;
}) {
  if (!model.capability) {
    return (
      <section className="component-analysis-grid">
        <EmptyState title="No capability selected" detail="Capability metadata is empty." />
      </section>
    );
  }

  return (
    <section className="component-analysis-grid">
      <CapabilitySummaryPanel model={model.capability} />
      <CapabilityMatrixView model={model.capability} />
      <EvidenceCoverageMatrix rows={model.capability.evidenceRows} />
      <RiskContributionChart rows={model.capability.riskRows} />
      <GraphContributionPanel rows={model.capability.graphRows} />
      <ResponseCoveragePanel rows={model.capability.responseRows} />
      <section className="component-panel recommendations-panel">
        <div className="component-panel-header">
          <strong>Recommendations</strong>
          <span>{model.capability.recommendations.length}</span>
        </div>
        <ul className="recommendation-list">
          {model.capability.recommendations.map((recommendation) => (
            <li key={recommendation}>
              <ShieldCheck size={14} aria-hidden="true" />
              <span>{displayText(recommendation)}</span>
            </li>
          ))}
        </ul>
      </section>
      <section className="component-panel dependency-graph-panel">
        <UiContributionRenderer
          contribution={dependencyContribution(model.capability.domain)}
          data={model.capability.dependencyProjection}
        />
      </section>
    </section>
  );
}

function CapabilitySummaryPanel({
  model,
}: {
  readonly model: CapabilityAnalysisModel;
}) {
  return (
    <section className="component-panel capability-summary-panel">
      <div className="component-panel-header">
        <strong>{displayText(model.title)}</strong>
        <StatusPill status={model.status} />
      </div>
      <div className="capability-summary-grid">
        <SummaryMetric label="Plugins" value={String(model.plugins.length)} />
        <SummaryMetric label="Enabled" value={String(model.enabledPluginCount)} />
        <SummaryMetric label="Degraded" value={String(model.degradedPluginCount)} />
        <SummaryMetric label="Permissions" value={String(model.requiredPermissionCount)} />
        <SummaryMetric label="Inputs" value={String(model.inputContracts.length)} />
        <SummaryMetric label="Outputs" value={String(model.outputContracts.length)} />
        <SummaryMetric label="UI slots" value={String(model.uiContributionCount)} />
        <SummaryMetric label="Missing deps" value={String(model.missingDependencies.length)} />
      </div>
    </section>
  );
}

function SummaryMetric({
  label,
  value,
}: {
  readonly label: string;
  readonly value: string;
}) {
  return (
    <div className="summary-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function CapabilityMatrixView({
  model,
}: {
  readonly model: CapabilityAnalysisModel;
}) {
  return (
    <section className="component-panel capability-matrix-panel">
      <div className="component-panel-header">
        <strong>Capability matrix</strong>
        <span>{displayText(model.title)}</span>
      </div>
      <ShellTable
        columns={[
          { key: "plugin", label: "Plugin" },
          { key: "health", label: "Health" },
          { key: "inputs", label: "Inputs" },
          { key: "outputs", label: "Outputs" },
          { key: "dependencies", label: "Deps" },
          { key: "findings", label: "Findings" },
          { key: "graph", label: "Graph" },
          { key: "response", label: "Response" },
        ]}
        rows={model.plugins.map((plugin) => ({
          id: plugin.plugin_id,
          severity: statusSeverity(model.status),
          cells: {
            plugin: displayText(plugin.plugin_name),
            health: displayText(model.status),
            inputs: String(plugin.input_contracts.length),
            outputs: String(plugin.output_contracts.length),
            dependencies: String((plugin.dependencies ?? []).length),
            findings: String(plugin.finding_types.length),
            graph: String(plugin.graph_hint_types.length),
            response: responseSupport(plugin),
          },
        }))}
      />
    </section>
  );
}

export function EvidenceCoverageMatrix({
  rows,
}: {
  readonly rows: CoverageRow[];
}) {
  return (
    <section className="component-panel">
      <div className="component-panel-header">
        <strong>Evidence coverage</strong>
        <ListChecks size={15} aria-hidden="true" />
      </div>
      <ShellTable
        columns={[
          { key: "plugin", label: "Plugin" },
          { key: "evidence", label: "Evidence" },
          { key: "findings", label: "Findings" },
          { key: "source", label: "Source" },
          { key: "impact", label: "Impact" },
        ]}
        rows={rows.map((row) => ({
          id: row.pluginId,
          severity: row.impact === "limited" ? "medium" : "low",
          cells: {
            plugin: displayText(row.pluginName),
            evidence: displayText(row.evidence),
            findings: displayText(row.findingCoverage),
            source: displayText(row.sourceCoverage),
            impact: displayText(row.impact),
          },
        }))}
      />
    </section>
  );
}

export function RiskContributionChart({
  rows,
}: {
  readonly rows: RiskContributionRow[];
}) {
  const maxValue = Math.max(1, ...rows.map((row) => riskSignalTotal(row)));
  return (
    <section className="component-panel">
      <div className="component-panel-header">
        <strong>Risk contribution</strong>
        <Activity size={15} aria-hidden="true" />
      </div>
      <div className="risk-bars">
        {rows.map((row) => {
          const total = riskSignalTotal(row);
          const width = `${Math.max(8, Math.round((total / maxValue) * 100))}%`;
          return (
            <div className="risk-bar-row" key={row.pluginId}>
              <span>{displayText(row.pluginName)}</span>
              <div className="risk-bar-track">
                <div className="risk-bar-fill" style={{ width }} />
              </div>
              <strong>{total}</strong>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export function GraphContributionPanel({
  rows,
}: {
  readonly rows: GraphContributionRow[];
}) {
  return (
    <section className="component-panel">
      <div className="component-panel-header">
        <strong>Graph contribution</strong>
        <Network size={15} aria-hidden="true" />
      </div>
      <ShellTable
        columns={[
          { key: "plugin", label: "Plugin" },
          { key: "hints", label: "Hints" },
          { key: "accepted", label: "Accepted" },
          { key: "writes", label: "Writes" },
        ]}
        rows={rows.map((row) => ({
          id: row.pluginId,
          cells: {
            plugin: displayText(row.pluginName),
            hints: String(row.emittedHints),
            accepted: displayText(row.acceptedHints),
            writes: displayText(row.graphWrites),
          },
        }))}
      />
    </section>
  );
}

export function ResponseCoveragePanel({
  rows,
}: {
  readonly rows: ResponseCoverageRow[];
}) {
  return (
    <section className="component-panel">
      <div className="component-panel-header">
        <strong>Response coverage</strong>
        <ShieldCheck size={15} aria-hidden="true" />
      </div>
      <ShellTable
        columns={[
          { key: "plugin", label: "Plugin" },
          { key: "recommend", label: "Recommend" },
          { key: "approval", label: "Approval" },
          { key: "rollback", label: "Rollback" },
        ]}
        rows={rows.map((row) => ({
          id: row.pluginId,
          cells: {
            plugin: displayText(row.pluginName),
            recommend: displayText(row.recommendations),
            approval: displayText(row.approval),
            rollback: displayText(row.rollback),
          },
        }))}
      />
    </section>
  );
}

function buildCapabilityAnalysis(
  domain: string,
  catalog: PluginCatalogViewDto,
  overviews: CapabilityOverviewDto[],
  healthByPlugin: Map<string, HealthSnapshotDto>,
): CapabilityAnalysisModel {
  const plugins = catalog.plugins.filter((plugin) => plugin.capability_domain === domain);
  const overview = overviews.find((item) => capabilityDomain(item) === domain);
  const status = overview?.health_status ?? aggregateHealth(plugins, healthByPlugin);
  const title = overview ? capabilityTitle(overview) : humanize(domain);
  const inputContracts = overview?.input_contract_names ?? unique(plugins.flatMap((plugin) =>
    plugin.input_contracts.map(contractLabel),
  ));
  const outputContracts = overview?.output_contract_names ?? unique(plugins.flatMap((plugin) =>
    plugin.output_contracts.map(contractLabel),
  ));
  const missingDependencies = missingDependencyLabels(plugins, catalog.plugins);
  const evidenceRows = plugins.map((plugin) => evidenceRow(plugin));
  const riskRows = plugins.map((plugin) => riskRow(plugin));
  const graphRows = plugins.map((plugin) => graphRow(plugin));
  const responseRows = plugins.map((plugin) => responseRow(plugin));
  const recommendations = capabilityRecommendations(
    plugins,
    missingDependencies,
    status,
    evidenceRows,
  );

  return {
    domain,
    title,
    status,
    plugins,
    enabledPluginCount: plugins.filter((plugin) => plugin.enabled_by_default).length,
    degradedPluginCount: plugins.filter((plugin) =>
      isDegraded(healthByPlugin.get(plugin.plugin_id)?.status ?? status),
    ).length,
    inputContracts,
    outputContracts,
    requiredPermissionCount:
      overview?.required_permission_count ??
      plugins.reduce((count, plugin) => count + plugin.required_permissions.length, 0),
    uiContributionCount:
      overview?.ui_contribution_count ??
      plugins.reduce((count, plugin) => count + plugin.ui_contributions.length, 0),
    missingDependencies,
    evidenceRows,
    riskRows,
    graphRows,
    responseRows,
    recommendations,
    dependencyProjection: dependencyProjection(domain, plugins),
  };
}

function buildHealthByPlugin(catalog: PluginCatalogViewDto | null) {
  const byPlugin = new Map<string, HealthSnapshotDto>();
  if (!catalog) {
    return byPlugin;
  }
  for (const plugin of catalog.plugins) {
    const health = catalog.health.find((snapshot) =>
      jsonIncludesString(snapshot.subject, plugin.plugin_id),
    );
    if (health) {
      byPlugin.set(plugin.plugin_id, health);
    }
  }
  return byPlugin;
}

function buildMetricsByPlugin(catalog: PluginCatalogViewDto | null) {
  const byPlugin = new Map<string, MetricSampleDto[]>();
  if (!catalog) {
    return byPlugin;
  }
  for (const plugin of catalog.plugins) {
    const pluginKey = pluginKeyFromManifest(plugin);
    const metrics = catalog.metrics.filter((metric) =>
      pluginKey ? metric.metric_name.startsWith(`${pluginKey}.`) : false,
    );
    byPlugin.set(plugin.plugin_id, metrics);
  }
  return byPlugin;
}

function capabilityDomain(capability: CapabilityOverviewDto) {
  return stringField(capability.capability, "capability_domain")
    ?? stringField(capability.capability, "domain")
    ?? stringField(capability.capability, "capability_id")
    ?? capability.plugin_names[0]
    ?? "unknown";
}

function capabilityTitle(capability: CapabilityOverviewDto) {
  return stringField(capability.capability, "title")
    ?? stringField(capability.capability, "capability_name")
    ?? stringField(capability.capability, "name")
    ?? humanize(capabilityDomain(capability));
}

function evidenceRow(plugin: PluginManifestDto): CoverageRow {
  const outputNames = plugin.output_contracts.map(contractLabel);
  const inputNames = plugin.input_contracts.map(contractLabel);
  const evidenceOutputs = outputNames.filter((name) =>
    containsAny(name, ["evidence", "finding", "observation"]),
  );
  const sourceCoverage = inputNames.length ? `${inputNames.length} inputs` : "source";
  const hasEvidence = evidenceOutputs.length > 0 || plugin.finding_types.length > 0;
  return {
    pluginId: plugin.plugin_id,
    pluginName: plugin.plugin_name,
    evidence: hasEvidence ? `${evidenceOutputs.length} declared` : "not declared",
    findingCoverage: plugin.finding_types.length
      ? `${plugin.finding_types.length} finding types`
      : "none",
    sourceCoverage,
    impact: hasEvidence ? "covered" : "limited",
  };
}

function riskRow(plugin: PluginManifestDto): RiskContributionRow {
  const outputs = plugin.output_contracts.map(contractLabel);
  return {
    pluginId: plugin.plugin_id,
    pluginName: plugin.plugin_name,
    findingTypes: plugin.finding_types.length,
    riskContracts: outputs.filter((name) => name.includes("risk")).length,
    alertContracts: outputs.filter((name) => name.includes("alert")).length,
    incidentContracts: outputs.filter((name) => name.includes("incident")).length,
  };
}

function graphRow(plugin: PluginManifestDto): GraphContributionRow {
  const outputs = plugin.output_contracts.map(contractLabel);
  const writesGraph = outputs.some((name) => name.includes("graph.update"));
  return {
    pluginId: plugin.plugin_id,
    pluginName: plugin.plugin_name,
    emittedHints: plugin.graph_hint_types.length,
    acceptedHints: plugin.graph_hint_types.length ? "graph stage" : "none",
    graphWrites: writesGraph ? "canonical stage" : "hints only",
  };
}

function responseRow(plugin: PluginManifestDto): ResponseCoverageRow {
  const outputs = plugin.output_contracts.map(contractLabel);
  const actionLabels = plugin.actions.map(actionLabel);
  const responseOutputs = outputs.filter((name) => name.includes("response"));
  return {
    pluginId: plugin.plugin_id,
    pluginName: plugin.plugin_name,
    recommendations: actionLabels.length
      ? `${actionLabels.length} actions`
      : responseOutputs.length
        ? "plan output"
        : "none",
    approval: responseOutputs.some((name) => name.includes("approval"))
      ? "declared"
      : "not declared",
    rollback: responseOutputs.some((name) => name.includes("result"))
      ? "result-linked"
      : "not declared",
  };
}

function capabilityRecommendations(
  plugins: PluginManifestDto[],
  missingDependencies: string[],
  status: string,
  evidenceRows: CoverageRow[],
) {
  const recommendations: string[] = [];
  if (isDegraded(status)) {
    recommendations.push("Review degraded health before relying on promoted findings.");
  }
  for (const dependency of missingDependencies.slice(0, 4)) {
    recommendations.push(`Resolve missing dependency: ${dependency}.`);
  }
  for (const row of evidenceRows.filter((item) => item.impact === "limited").slice(0, 4)) {
    recommendations.push(`Add evidence output coverage for ${row.pluginName}.`);
  }
  const disabled = plugins.filter((plugin) => !plugin.enabled_by_default);
  for (const plugin of disabled.slice(0, 3)) {
    recommendations.push(`${plugin.plugin_name} is disabled by default; dependent coverage is reduced.`);
  }
  if (!recommendations.length) {
    recommendations.push("No missing dependencies or degraded plugin health reported.");
  }
  return recommendations;
}

function missingDependencyLabels(
  plugins: PluginManifestDto[],
  allPlugins: PluginManifestDto[],
) {
  const knownPluginIds = new Set(allPlugins.map((plugin) => plugin.plugin_id));
  const labels: string[] = [];
  for (const plugin of plugins) {
    for (const dependency of plugin.dependencies ?? []) {
      const dependencyPluginId = stringField(dependency, "plugin_id");
      if (dependencyPluginId && !knownPluginIds.has(dependencyPluginId)) {
        labels.push(`${plugin.plugin_name}: ${dependencyLabel(dependency)}`);
      }
    }
  }
  return labels;
}

function dependencyProjection(domain: string, plugins: PluginManifestDto[]): JsonValue {
  const nodes = plugins.map((plugin) => ({
    id: plugin.plugin_id,
    label: plugin.plugin_name,
    node_type: "plugin",
  }));
  const edges = plugins.flatMap((plugin) =>
    (plugin.dependencies ?? [])
      .map((dependency) => stringField(dependency, "plugin_id"))
      .filter((pluginId): pluginId is string => Boolean(pluginId))
      .map((sourceId) => ({
        id: `${sourceId}->${plugin.plugin_id}`,
        source: sourceId,
        target: plugin.plugin_id,
        label: "requires",
      })),
  );
  return {
    graph_type: "capability_dependency_graph",
    title_redacted: `${humanize(domain)} dependencies`,
    nodes,
    edges,
    paths: [],
  };
}

function dependencyContribution(domain: string): UiContributionDto {
  return {
    contribution_id: `component-center-${domain}-dependency-graph`,
    plugin_id: `capability:${domain}`,
    slot: "component_center.dependency_graph",
    renderer_type: "dependency_graph",
    title: "Dependency graph",
  };
}

function contributionRendererData(
  contribution: UiContributionDto,
  manifest: PluginManifestDto,
  health: HealthSnapshotDto | null,
  metrics: MetricSampleDto[],
): JsonValue {
  if (contribution.renderer_type === "health_badge") {
    return health
      ? (health as unknown as JsonValue)
      : { status: "unknown", plugin_id: manifest.plugin_id };
  }
  if (contribution.renderer_type === "metric_card") {
    return metrics.map((metric) => ({
      metric_name: metric.metric_name,
      value: shortJson(metric.value),
      privacy_class: metric.privacy_class,
    }));
  }
  if (contribution.renderer_type === "key_value_panel") {
    return {
      plugin_id: manifest.plugin_id,
      plugin_name: manifest.plugin_name,
      capability_domain: manifest.capability_domain,
      runtime_mode: manifest.runtime_mode,
      plugin_type: manifest.plugin_type ?? "plugin",
      inputs: manifest.input_contracts.length,
      outputs: manifest.output_contracts.length,
      permissions: manifest.required_permissions.length,
    };
  }
  if (contribution.renderer_type === "table") {
    return manifest.output_contracts.map((contract) => ({
      contract: contractLabel(contract),
      direction: "output",
    }));
  }
  if (contribution.renderer_type === "evidence_list") {
    return manifest.finding_types.map((findingType) => ({
      evidence_type: findingType,
      summary_redacted: "declared finding evidence metadata",
    }));
  }
  if (contribution.renderer_type === "risk_breakdown") {
    return [riskRow(manifest)].map((row) => ({
      reason_type: row.pluginName,
      score: riskSignalTotal(row),
    }));
  }
  if (
    contribution.renderer_type === "graph_projection" ||
    contribution.renderer_type === "dependency_graph" ||
    contribution.renderer_type === "pipeline_graph"
  ) {
    return dependencyProjection(manifest.capability_domain, [manifest]);
  }
  if (contribution.renderer_type === "response_action_card") {
    return responseRow(manifest).recommendations === "none"
      ? []
      : [
          {
            action_type: "recommend_only",
            rationale_redacted: responseRow(manifest).recommendations,
          },
        ];
  }
  if (contribution.renderer_type === "report_section") {
    return [
      {
        section_type: "plugin_manifest",
        title_redacted: manifest.plugin_name,
        summary_redacted: manifest.description ?? "redacted plugin report section",
      },
    ];
  }
  return contribution.data_source ?? {};
}

function lifecycleRequest(pluginId: string, reason: string) {
  return {
    plugin_id: pluginId,
    reason_redacted: `Component Center ${reason}`,
    requested_by_redacted: "local desktop user",
  };
}

function StatusPill({ status }: { readonly status: string }) {
  return (
    <span className="component-status-pill" data-severity={statusSeverity(status)}>
      {status}
    </span>
  );
}

function TokenGroup({
  title,
  values,
}: {
  readonly title: string;
  readonly values: string[];
}) {
  return (
    <div className="token-group">
      <strong>{title}</strong>
      <div className="token-list">
        {values.length ? (
          values
            .slice(0, 10)
            .map((value, index) => (
              <span key={`${title}-${displayText(value)}-${index}`}>
                {displayText(value)}
              </span>
            ))
        ) : (
          <span className="muted-token">none</span>
        )}
      </div>
    </div>
  );
}

function aggregateHealth(
  plugins: PluginManifestDto[],
  healthByPlugin: Map<string, HealthSnapshotDto>,
) {
  const statuses = plugins.map((plugin) => healthByPlugin.get(plugin.plugin_id)?.status ?? "unknown");
  if (statuses.some((status) => statusSeverity(status) === "critical")) {
    return "failed";
  }
  if (statuses.some(isDegraded)) {
    return "degraded";
  }
  if (statuses.every((status) => status === "healthy")) {
    return "healthy";
  }
  return "unknown";
}

function responseSupport(plugin: PluginManifestDto) {
  if ((plugin.plugin_type ?? "").toLowerCase().includes("response")) {
    return "planner";
  }
  return plugin.output_contracts.some((contract) => contractLabel(contract).includes("response"))
    ? "metadata"
    : "none";
}

function riskSignalTotal(row: RiskContributionRow) {
  return row.findingTypes + row.riskContracts + row.alertContracts + row.incidentContracts;
}

function statusSeverity(status: string) {
  const normalized = status.toLowerCase();
  if (
    ["failed", "failure", "unavailable", "disconnected", "unauthorized"].some((item) =>
      normalized.includes(item),
    )
  ) {
    return "critical";
  }
  if (["degraded", "stale", "warning"].some((item) => normalized.includes(item))) {
    return "medium";
  }
  if (normalized.includes("healthy") || normalized.includes("running")) {
    return "low";
  }
  return "medium";
}

function isDegraded(status: string) {
  return statusSeverity(status) !== "low";
}

function pluginKeyFromManifest(manifest: PluginManifestDto) {
  for (const contribution of manifest.ui_contributions) {
    const pluginKey = stringField(contribution.schema, "plugin_key");
    if (pluginKey) {
      return pluginKey;
    }
  }
  return manifest.plugin_name
    .toLowerCase()
    .replace(/\s+mock$/u, "")
    .replace(/[^a-z0-9]+/gu, "_")
    .replace(/^_+|_+$/gu, "");
}

function contractLabel(value: JsonValue) {
  return stringField(value, "contract_name")
    ?? stringField(value, "topic")
    ?? stringField(value, "name")
    ?? shortJson(value);
}

function permissionLabel(value: JsonValue) {
  return stringField(value, "permission")
    ?? stringField(value, "key")
    ?? stringField(value, "name")
    ?? shortJson(value);
}

function dependencyLabel(value: JsonValue) {
  return stringField(value, "name")
    ?? stringField(value, "plugin_id")
    ?? stringField(value, "capability_id")
    ?? stringField(value, "contract")
    ?? stringField(value, "dependency_type")
    ?? shortJson(value);
}

function actionLabel(value: JsonValue) {
  return stringField(value, "action_type")
    ?? stringField(value, "name")
    ?? stringField(value, "title")
    ?? shortJson(value);
}

function stringField(value: JsonValue | undefined, key: string): string | null {
  if (!isRecord(value)) {
    return null;
  }
  const nested = value[key];
  if (typeof nested === "string") {
    return nested;
  }
  if (isRecord(nested)) {
    return (
      stringField(nested, "value")
      ?? stringField(nested, "key")
      ?? stringField(nested, "id")
      ?? stringField(nested, "name")
    );
  }
  return null;
}

function isRecord(value: JsonValue | undefined): value is Record<string, JsonValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function shortJson(value: JsonValue) {
  const safe = stringifySafe(value);
  if (safe !== "object") {
    return safe;
  }
  const name = stringField(value, "name") ?? stringField(value, "kind") ?? stringField(value, "type");
  return name ? displayText(name) : "metadata";
}

function displayText(value: string) {
  return stringifySafe(value);
}

function jsonIncludesString(value: JsonValue, needle: string): boolean {
  if (value === null) {
    return false;
  }
  if (typeof value === "string") {
    return value === needle;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return false;
  }
  if (Array.isArray(value)) {
    return value.some((item) => jsonIncludesString(item, needle));
  }
  return Object.values(value).some((item) => jsonIncludesString(item, needle));
}

function containsAny(value: string, markers: string[]) {
  const normalized = value.toLowerCase();
  return markers.some((marker) => normalized.includes(marker));
}

function unique(values: string[]) {
  return [...new Set(values)].filter(Boolean);
}

function humanize(value: string) {
  return value
    .replace(/[_:.]+/gu, " ")
    .replace(/\s+/gu, " ")
    .trim()
    .replace(/^./u, (first) => first.toUpperCase());
}
