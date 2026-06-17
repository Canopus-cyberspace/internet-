import type { QueryRequestDto } from "./dto/common";
import type { ReportExportHistoryQueryDto } from "./dto/report";
import type { NavigationResolveRequestDto } from "./dto/navigation";

export type QueryKey = readonly unknown[];

export const queryKeys = {
  platform: {
    components: ["platform", "components"] as const,
    componentDetail: (componentId: string) =>
      ["platform", "component", "detail", componentId] as const,
    componentHealth: (componentId: string) =>
      ["platform", "component", "health", componentId] as const,
    componentMetrics: (componentId: string) =>
      ["platform", "component", "metrics", componentId] as const,
    metrics: ["platform", "metrics"] as const,
  },
  plugin: {
    catalog: ["plugin", "catalog"] as const,
    manifest: (pluginId: string) => ["plugin", "manifest", pluginId] as const,
    metrics: (pluginId: string) => ["plugin", "metrics", pluginId] as const,
    findings: (pluginId: string, request?: QueryRequestDto) =>
      ["plugin", "findings", pluginId, request ?? "default"] as const,
  },
  capability: {
    overview: ["capability", "overview"] as const,
    analysis: (domain: string) => ["capability", "analysis", domain] as const,
    matrix: ["capability", "matrix"] as const,
    dependencyGraph: ["capability", "dependency_graph"] as const,
  },
  security: {
    cases: (request?: QueryRequestDto) =>
      ["security", "cases", request ?? "default"] as const,
    findings: (request?: QueryRequestDto) =>
      ["security", "findings", request ?? "default"] as const,
    alerts: (request?: QueryRequestDto) =>
      ["security", "alerts", request ?? "default"] as const,
    incidents: (request?: QueryRequestDto) =>
      ["security", "incidents", request ?? "default"] as const,
    incidentDetail: (incidentId: string) =>
      ["security", "incident", "detail", incidentId] as const,
    attackCoverage: ["security", "attack_coverage"] as const,
    fusion: ["security", "fusion"] as const,
    fusionFacts: ["security", "fusion", "facts"] as const,
    fusionHypotheses: ["security", "fusion", "hypotheses"] as const,
    fusionHypothesisDetail: (hypothesisId: string) =>
      ["security", "fusion", "hypothesis", hypothesisId] as const,
    baseline: ["security", "baseline"] as const,
    evidenceQuality: ["security", "quality"] as const,
    evidenceQualityRecords: ["security", "quality", "records"] as const,
    evidenceQualityRecord: (qualityId: string) =>
      ["security", "quality", "record", qualityId] as const,
    investigationDrillDown: ["security", "investigation", "drill_down"] as const,
    endpointThreat: ["security", "investigation", "endpoint_threat"] as const,
    hypothesisExplanation: (hypothesisId: string) =>
      ["security", "investigation", "hypothesis", hypothesisId] as const,
    baselineDrillDown: (baselineId: string) =>
      ["security", "investigation", "baseline", baselineId] as const,
    incidentGroupInvestigation: (groupId: string) =>
      ["security", "investigation", "group", groupId] as const,
    timelineDrillDown: (timelineEntryId: string) =>
      ["security", "investigation", "timeline", timelineEntryId] as const,
    sourceReliabilityExplanation: (sourceId: string) =>
      ["security", "investigation", "source", sourceId] as const,
    baselineRecords: ["security", "baseline", "records"] as const,
    baselineIndicators: ["security", "baseline", "indicators"] as const,
    incidentLinkedGroups: ["security", "baseline", "incident_groups"] as const,
    incidentTimeline: ["security", "baseline", "incident_timeline"] as const,
    sourceReliability: ["security", "baseline", "source_reliability"] as const,
  },
  network: {
    localMetadataProxy: ["network", "local_metadata_proxy"] as const,
    metadataWatchStatus: ["network", "metadata_watch", "status"] as const,
    metadataWatchSources: ["network", "metadata_watch", "sources"] as const,
    metadataWatchSource: (sourceId: string) =>
      ["network", "metadata_watch", "source", sourceId] as const,
    metadataSamplingBatches: ["network", "metadata_watch", "batches"] as const,
    metadataSamplingBatch: (batchId: string) =>
      ["network", "metadata_watch", "batch", batchId] as const,
    flows: (request?: QueryRequestDto) =>
      ["network", "flows", request ?? "default"] as const,
    dns: (request?: QueryRequestDto) =>
      ["network", "dns", request ?? "default"] as const,
    tls: (request?: QueryRequestDto) =>
      ["network", "tls", request ?? "default"] as const,
    processes: (request?: QueryRequestDto) =>
      ["network", "processes", request ?? "default"] as const,
    providerController: ["network", "provider_controller"] as const,
    providerStatuses: ["network", "provider_controller", "providers"] as const,
    providerStatus: (providerId: string) =>
      ["network", "provider_controller", "provider", providerId] as const,
    providerVisibility: ["network", "provider_controller", "visibility"] as const,
    providerFallbackPlan: ["network", "provider_controller", "fallback"] as const,
  },
  graph: {
    view: (graphType: string, scope: string) =>
      ["graph", "view", graphType, scope] as const,
    incident: (incidentId: string) => ["graph", "incident", incidentId] as const,
    entity: (entityId: string) => ["graph", "entity", entityId] as const,
  },
  navigation: {
    resolve: (request: NavigationResolveRequestDto) =>
      ["navigation", "resolve", request] as const,
  },
  response: {
    plans: (request?: QueryRequestDto) =>
      ["response", "plans", request ?? "default"] as const,
    active: ["response", "active"] as const,
    history: (request?: QueryRequestDto) =>
      ["response", "history", request ?? "default"] as const,
  },
  report: {
    list: ["report", "list"] as const,
    detail: (reportId: string) => ["report", "detail", reportId] as const,
    exportHistory: ["report", "export_history"] as const,
    exportHistoryList: (query?: ReportExportHistoryQueryDto) =>
      ["report", "export_history", query ?? "default"] as const,
    exportHistoryDetail: (exportResultId: string) =>
      ["report", "export_history", "detail", exportResultId] as const,
    exportPolicyViolations: ["report", "export_policy_violations"] as const,
  },
  settings: {
    runtime: ["settings", "runtime"] as const,
    privacy: ["settings", "privacy"] as const,
    capture: ["settings", "capture"] as const,
    response: ["settings", "response"] as const,
    llmAlertStory: ["settings", "llm_alert_story"] as const,
    llmAlertStories: ["settings", "llm_alert_story", "stories"] as const,
    nativeCapabilities: ["settings", "native_capabilities"] as const,
    nativePermission: ["settings", "native_permission"] as const,
    nativeVisibility: ["settings", "native_visibility"] as const,
    nativeAudit: ["settings", "native_audit"] as const,
    nativeSamplerContracts: ["settings", "native_sampler_contracts"] as const,
    nativeSamplerContract: (samplerId: string) =>
      ["settings", "native_sampler_contract", samplerId] as const,
    nativeSamplerReadiness: ["settings", "native_sampler_readiness"] as const,
    nativeSamplerReadinessDetail: (samplerId: string) =>
      ["settings", "native_sampler_readiness_detail", samplerId] as const,
    nativeSamplerAuthorizationReview: (samplerId: string) =>
      ["settings", "native_sampler_authorization_review", samplerId] as const,
    futureSecurityFactMappings: ["settings", "future_security_fact_mappings"] as const,
    nativeSamplerBlocked: ["settings", "native_sampler_blocked"] as const,
    nativeSamplerRuntime: ["settings", "native_sampler_runtime"] as const,
    nativeSamplerRuntimeStatus: (samplerId: string) =>
      ["settings", "native_sampler_runtime", "status", samplerId] as const,
    nativeSamplerRuntimeBatch: (samplerId: string) =>
      ["settings", "native_sampler_runtime", "batch", samplerId] as const,
    nativeScheduler: ["settings", "native_scheduler"] as const,
    nativeSchedulerOperational: [
      "settings",
      "native_scheduler",
      "operational",
    ] as const,
    nativeSchedulerStatus: ["settings", "native_scheduler", "status"] as const,
    nativeSchedulerHostStatus: [
      "settings",
      "native_scheduler",
      "host_status",
    ] as const,
    nativeSchedulerHostHealth: [
      "settings",
      "native_scheduler",
      "host_health",
    ] as const,
    nativeSamplerSchedules: ["settings", "native_scheduler", "schedules"] as const,
    nativeSamplerSchedule: (samplerId: string) =>
      ["settings", "native_scheduler", "schedule", samplerId] as const,
    missingEndpointVisibility: ["settings", "missing_endpoint_visibility"] as const,
    edrReadiness: ["settings", "edr_readiness"] as const,
    service: ["settings", "service"] as const,
    portablePreferences: ["settings", "portable_preferences"] as const,
  },
};

export function defaultQueryRequest(limit = 100): QueryRequestDto {
  return {
    page: {
      limit,
      cursor: null,
    },
    time_range: null,
    filters: [],
    sort: [],
    scope: {
      type: "global",
    },
  };
}

export function queryKeyFromCoreHint(queryKey: string): QueryKey {
  const [root, ...parameters] = queryKey.split(":");
  const parts = root.split(".").filter(Boolean);
  return [...parts, ...parameters.filter(Boolean)];
}
