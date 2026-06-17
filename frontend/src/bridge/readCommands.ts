import type { CapabilityOverviewDto } from "./dto/capability";
import type { PageRequestDto, PageResponseDto, QueryRequestDto } from "./dto/common";
import type { GraphViewModelDto, GraphViewRequestDto } from "./dto/graph";
import type {
  NavigationResolutionDto,
  NavigationResolveRequestDto,
} from "./dto/navigation";
import type {
  DnsObservationDto,
  FlowRecordDto,
  MetadataSamplingBatchSummaryDto,
  MetadataWatchControllerStatusDto,
  MetadataWatchSourceStatusDto,
  NetworkFallbackPlanDto,
  NetworkProviderControllerStatusDto,
  NetworkProviderStatusDto,
  NetworkVisibilitySummaryDto,
  TlsObservationDto,
} from "./dto/network";
import type {
  ComponentDetailDto,
  ComponentSummaryDto,
  PortablePreferencesDto,
  ServiceStatusViewDto,
} from "./dto/platform";
import type { PluginCatalogViewDto, PluginManifestDto } from "./dto/plugin";
import type {
  ExportHistoryRecordDto,
  ExportPolicyViolationDto,
  ReportDto,
  ReportExportHistoryQueryDto,
} from "./dto/report";
import type { ResponsePlanDto } from "./dto/response";
import type {
  AttackCoverageSummaryDto,
  AttackHypothesisRecordDto,
  AlertDto,
  BaselineDrillDownDetailDto,
  BaselineIndicatorDto,
  BaselineRecordDto,
  DurableBaselineSummaryDto,
  EvidenceQualityRecordDto,
  EvidenceQualitySummaryDto,
  EndpointThreatAnalysisSummaryDto,
  FindingDto,
  FusionSummaryDto,
  IncidentDetailViewDto,
  IncidentGroupInvestigationDetailDto,
  IncidentLinkedHypothesisGroupDto,
  IncidentTimelineEntryDto,
  IncidentDto,
  InvestigationDrillDownSummaryDto,
  HypothesisExplanationDetailDto,
  SecurityFactDto,
  SourceReliabilityExplanationDto,
  SourceReliabilitySummaryDto,
  TimelineDrillDownDetailDto,
} from "./dto/security";
import type {
  LlmAlertStoryStatusDto,
  LlmAlertStoryRecordDto,
  AuthorizedNativeCapabilityStatusDto,
  EdrReadinessSummaryDto,
  FutureSecurityFactMappingSummaryDto,
  MissingEndpointVisibilitySummaryDto,
  NativePermissionAuditSummaryDto,
  NativePermissionStatusSummaryDto,
  NativeSamplerAuthorizationReviewDto,
  NativeSamplerBlockedSummaryDto,
  NativeSamplerContractDto,
  NativeSamplerReadinessDetailDto,
  NativeSamplerReadinessSummaryDto,
  NativeSamplerRuntimeBatchDto,
  NativeSamplerRuntimeStatusDto,
  NativeSamplerRuntimeSummaryDto,
  NativeSamplerScheduleStatusDto,
  NativeSchedulerOperationalSummaryDto,
  NativeSchedulerHostHealthSummaryDto,
  NativeSchedulerHostStatusDto,
  NativeSchedulerStatusDto,
  NativeSchedulerSummaryDto,
  NativeVisibilitySummaryDto,
  RuntimeProfileDto,
} from "./dto/settings";
import { invokeCore } from "./tauri/invoke";

export function listComponents() {
  return invokeCore<ComponentSummaryDto[]>("list_components");
}

export function getComponentDetail(componentId: string) {
  return invokeCore<ComponentDetailDto>("get_component_detail", {
    component_id: componentId,
  });
}

export function searchComponents(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<ComponentSummaryDto>>("search_components", {
    request,
  });
}

export function getPluginCatalog() {
  return invokeCore<PluginCatalogViewDto>("get_plugin_catalog");
}

export function getPluginManifest(pluginId: string) {
  return invokeCore<PluginManifestDto>("get_plugin_manifest", {
    plugin_id: pluginId,
  });
}

export function searchPlugins(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<PluginManifestDto>>("search_plugins", {
    request,
  });
}

export function getCapabilityOverview() {
  return invokeCore<CapabilityOverviewDto[]>("get_capability_overview");
}

export function searchCapabilities(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<CapabilityOverviewDto>>("search_capabilities", {
    request,
  });
}

export function searchFindings(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<FindingDto>>("search_findings", { request });
}

export function searchAlerts(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<AlertDto>>("search_alerts", { request });
}

export function searchIncidents(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<IncidentDto>>("search_incidents", {
    request,
  });
}

export function getIncidentDetail(incidentId: string) {
  return invokeCore<IncidentDetailViewDto>("get_incident_detail", {
    incident_id: incidentId,
  });
}

export function searchFlows(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<FlowRecordDto>>("search_flows", { request });
}

export function searchDns(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<DnsObservationDto>>("search_dns", {
    request,
  });
}

export function searchTls(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<TlsObservationDto>>("search_tls", {
    request,
  });
}

export function getProviderControllerStatus() {
  return invokeCore<NetworkProviderControllerStatusDto>(
    "get_provider_controller_status",
  );
}

export function listNetworkProviderStatus() {
  return invokeCore<NetworkProviderStatusDto[]>("list_network_provider_status");
}

export function getNetworkProviderStatus(providerId: string) {
  return invokeCore<NetworkProviderStatusDto>("get_network_provider_status", {
    provider_id: providerId,
  });
}

export function getNetworkVisibilitySummary() {
  return invokeCore<NetworkVisibilitySummaryDto>("get_network_visibility_summary");
}

export function getNetworkFallbackPlan() {
  return invokeCore<NetworkFallbackPlanDto>("get_network_fallback_plan");
}

export function getGraphView(request: GraphViewRequestDto) {
  return invokeCore<GraphViewModelDto>("get_graph_view", { request });
}

export function listActiveResponses(page: PageRequestDto) {
  return invokeCore<PageResponseDto<ResponsePlanDto>>("list_active_responses", {
    page,
  });
}

export function searchResponsePlans(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<ResponsePlanDto>>("search_response_plans", {
    request,
  });
}

export function listReports(page: PageRequestDto) {
  return invokeCore<PageResponseDto<ReportDto>>("list_reports", { page });
}

export function searchReports(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<ReportDto>>("search_reports", { request });
}

export function getReport(reportId: string) {
  return invokeCore<ReportDto>("get_report", { report_id: reportId });
}

export function getAttackCoverageSummary() {
  return invokeCore<AttackCoverageSummaryDto>("get_attack_coverage_summary");
}

export function getFusionSummary() {
  return invokeCore<FusionSummaryDto>("get_fusion_summary");
}

export function listSecurityFacts(page: PageRequestDto) {
  return invokeCore<PageResponseDto<SecurityFactDto>>("list_security_facts", {
    page,
  });
}

export function listAttackHypotheses(page: PageRequestDto) {
  return invokeCore<PageResponseDto<AttackHypothesisRecordDto>>(
    "list_attack_hypotheses",
    { page },
  );
}

export function getAttackHypothesis(hypothesisId: string) {
  return invokeCore<AttackHypothesisRecordDto>("get_attack_hypothesis", {
    hypothesis_id: hypothesisId,
  });
}

export function getDurableBaselineSummary() {
  return invokeCore<DurableBaselineSummaryDto>("get_durable_baseline_summary");
}

export function getEvidenceQualitySummary() {
  return invokeCore<EvidenceQualitySummaryDto>("get_evidence_quality_summary");
}

export function listEvidenceQualityRecords(page: PageRequestDto) {
  return invokeCore<PageResponseDto<EvidenceQualityRecordDto>>(
    "list_evidence_quality_records",
    { page },
  );
}

export function getEvidenceQualityRecord(evidenceQualityId: string) {
  return invokeCore<EvidenceQualityRecordDto>("get_evidence_quality_record", {
    evidence_quality_id: evidenceQualityId,
  });
}

export function getInvestigationDrillDownSummary() {
  return invokeCore<InvestigationDrillDownSummaryDto>(
    "get_investigation_drill_down_summary",
  );
}

export function getEndpointThreatSummary() {
  return invokeCore<EndpointThreatAnalysisSummaryDto>("get_endpoint_threat_summary");
}

export function resolveNavigationReference(request: NavigationResolveRequestDto) {
  return invokeCore<NavigationResolutionDto>("resolve_navigation_reference", {
    request,
  });
}

export function getHypothesisExplanationDetail(hypothesisId: string) {
  return invokeCore<HypothesisExplanationDetailDto>(
    "get_hypothesis_explanation_detail",
    { hypothesis_id: hypothesisId },
  );
}

export function getBaselineDrillDownDetail(baselineId: string) {
  return invokeCore<BaselineDrillDownDetailDto>("get_baseline_drill_down_detail", {
    baseline_id: baselineId,
  });
}

export function getIncidentGroupInvestigationDetail(groupId: string) {
  return invokeCore<IncidentGroupInvestigationDetailDto>(
    "get_incident_group_investigation_detail",
    { group_id: groupId },
  );
}

export function getTimelineDrillDownDetail(timelineEntryId: string) {
  return invokeCore<TimelineDrillDownDetailDto>("get_timeline_drill_down_detail", {
    timeline_entry_id: timelineEntryId,
  });
}

export function getSourceReliabilityExplanation(sourceId: string) {
  return invokeCore<SourceReliabilityExplanationDto>(
    "get_source_reliability_explanation",
    { source_id: sourceId },
  );
}

export function listBaselineRecords(page: PageRequestDto) {
  return invokeCore<PageResponseDto<BaselineRecordDto>>("list_baseline_records", {
    page,
  });
}

export function getBaselineRecord(baselineId: string) {
  return invokeCore<BaselineRecordDto>("get_baseline_record", {
    baseline_id: baselineId,
  });
}

export function listBaselineIndicators(page: PageRequestDto) {
  return invokeCore<PageResponseDto<BaselineIndicatorDto>>(
    "list_baseline_indicators",
    { page },
  );
}

export function getBaselineIndicator(indicatorId: string) {
  return invokeCore<BaselineIndicatorDto>("get_baseline_indicator", {
    indicator_id: indicatorId,
  });
}

export function listIncidentLinkedHypothesisGroups(page: PageRequestDto) {
  return invokeCore<PageResponseDto<IncidentLinkedHypothesisGroupDto>>(
    "list_incident_linked_hypothesis_groups",
    { page },
  );
}

export function getIncidentLinkedHypothesisGroup(groupId: string) {
  return invokeCore<IncidentLinkedHypothesisGroupDto>(
    "get_incident_linked_hypothesis_group",
    { group_id: groupId },
  );
}

export function listIncidentTimelineEntries(page: PageRequestDto) {
  return invokeCore<PageResponseDto<IncidentTimelineEntryDto>>(
    "list_incident_timeline_entries",
    { page },
  );
}

export function getIncidentTimelineEntry(timelineEntryId: string) {
  return invokeCore<IncidentTimelineEntryDto>("get_incident_timeline_entry", {
    timeline_entry_id: timelineEntryId,
  });
}

export function listSourceReliabilitySummaries(page: PageRequestDto) {
  return invokeCore<PageResponseDto<SourceReliabilitySummaryDto>>(
    "list_source_reliability_summaries",
    { page },
  );
}

export function getMetadataWatchControllerStatus() {
  return invokeCore<MetadataWatchControllerStatusDto>(
    "get_metadata_watch_controller_status",
  );
}

export function listMetadataWatchSources(page: PageRequestDto) {
  return invokeCore<PageResponseDto<MetadataWatchSourceStatusDto>>(
    "list_metadata_watch_sources",
    { page },
  );
}

export function getMetadataWatchSource(sourceId: string) {
  return invokeCore<MetadataWatchSourceStatusDto>("get_metadata_watch_source", {
    source_id: sourceId,
  });
}

export function listMetadataSamplingBatches(page: PageRequestDto) {
  return invokeCore<PageResponseDto<MetadataSamplingBatchSummaryDto>>(
    "list_metadata_sampling_batches",
    { page },
  );
}

export function getMetadataSamplingBatch(batchId: string) {
  return invokeCore<MetadataSamplingBatchSummaryDto>("get_metadata_sampling_batch", {
    batch_id: batchId,
  });
}

export function listExportHistory(query: ReportExportHistoryQueryDto) {
  return invokeCore<PageResponseDto<ExportHistoryRecordDto>>("list_export_history", {
    query,
  });
}

export function searchExportHistory(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<ExportHistoryRecordDto>>("search_export_history", {
    request,
  });
}

export function getExportHistoryRecord(exportResultId: string) {
  return invokeCore<ExportHistoryRecordDto>("get_export_history_record", {
    export_result_id: exportResultId,
  });
}

export function listExportPolicyViolations() {
  return invokeCore<ExportPolicyViolationDto[]>("list_export_policy_violations");
}

export function getRuntimeProfile() {
  return invokeCore<RuntimeProfileDto>("get_runtime_profile");
}

export function searchRuntimeProfiles(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<RuntimeProfileDto>>("search_runtime_profiles", {
    request,
  });
}

export function getLlmAlertStoryStatus() {
  return invokeCore<LlmAlertStoryStatusDto>("get_llm_alert_story_status");
}

export function listLlmAlertStories(page: PageRequestDto) {
  return invokeCore<PageResponseDto<LlmAlertStoryRecordDto>>("list_llm_alert_stories", {
    page,
  });
}

export function getLlmAlertStory(storyId: string) {
  return invokeCore<LlmAlertStoryRecordDto>("get_llm_alert_story", {
    story_id: storyId,
  });
}

export function getServiceStatus() {
  return invokeCore<ServiceStatusViewDto>("get_service_status");
}

export function listAuthorizedNativeCapabilities() {
  return invokeCore<AuthorizedNativeCapabilityStatusDto[]>(
    "list_authorized_native_capabilities",
  );
}

export function getAuthorizedNativeCapability(capabilityId: string) {
  return invokeCore<AuthorizedNativeCapabilityStatusDto>(
    "get_authorized_native_capability",
    { capability_id: capabilityId },
  );
}

export function getNativePermissionStatusSummary() {
  return invokeCore<NativePermissionStatusSummaryDto>(
    "get_native_permission_status_summary",
  );
}

export function getNativeVisibilitySummary() {
  return invokeCore<NativeVisibilitySummaryDto>("get_native_visibility_summary");
}

export function getNativePermissionAuditSummary() {
  return invokeCore<NativePermissionAuditSummaryDto>(
    "get_native_permission_audit_summary",
  );
}

export function listNativeSamplerContracts() {
  return invokeCore<NativeSamplerContractDto[]>("list_native_sampler_contracts");
}

export function getNativeSamplerContract(samplerId: string) {
  return invokeCore<NativeSamplerContractDto>("get_native_sampler_contract", {
    sampler_id: samplerId,
  });
}

export function getNativeSamplerReadinessSummary() {
  return invokeCore<NativeSamplerReadinessSummaryDto>(
    "get_native_sampler_readiness_summary",
  );
}

export function getNativeSamplerReadinessDetail(samplerId: string) {
  return invokeCore<NativeSamplerReadinessDetailDto>(
    "get_native_sampler_readiness_detail",
    { sampler_id: samplerId },
  );
}

export function getNativeSamplerAuthorizationReview(samplerId: string) {
  return invokeCore<NativeSamplerAuthorizationReviewDto>(
    "get_native_sampler_authorization_review",
    { sampler_id: samplerId },
  );
}

export function getFutureSecurityFactMappingSummary() {
  return invokeCore<FutureSecurityFactMappingSummaryDto>(
    "get_future_security_fact_mapping_summary",
  );
}

export function getNativeSamplerBlockedSummary() {
  return invokeCore<NativeSamplerBlockedSummaryDto>(
    "get_native_sampler_blocked_summary",
  );
}

export function getNativeSamplerRuntimeSummary() {
  return invokeCore<NativeSamplerRuntimeSummaryDto>(
    "get_native_sampler_runtime_summary",
  );
}

export function getNativeSamplerRuntimeStatus(samplerId: string) {
  return invokeCore<NativeSamplerRuntimeStatusDto>(
    "get_native_sampler_runtime_status",
    { sampler_id: samplerId },
  );
}

export function getLatestNativeSamplerRuntimeBatch(samplerId: string) {
  return invokeCore<NativeSamplerRuntimeBatchDto | null>(
    "get_latest_native_sampler_runtime_batch",
    { sampler_id: samplerId },
  );
}

export function getNativeSchedulerStatus() {
  return invokeCore<NativeSchedulerStatusDto>("get_native_scheduler_status");
}

export function listNativeSamplerScheduleStatuses() {
  return invokeCore<NativeSamplerScheduleStatusDto[]>(
    "list_native_sampler_schedule_statuses",
  );
}

export function getNativeSamplerScheduleStatus(samplerId: string) {
  return invokeCore<NativeSamplerScheduleStatusDto>(
    "get_native_sampler_schedule_status",
    { sampler_id: samplerId },
  );
}

export function getNativeSchedulerSummary() {
  return invokeCore<NativeSchedulerSummaryDto>("get_native_scheduler_summary");
}

export function getNativeSchedulerOperationalSummary() {
  return invokeCore<NativeSchedulerOperationalSummaryDto>(
    "get_native_scheduler_operational_summary",
  );
}

export function getNativeSchedulerHostStatus() {
  return invokeCore<NativeSchedulerHostStatusDto>(
    "get_native_scheduler_host_status",
  );
}

export function getNativeSchedulerHostHealth() {
  return invokeCore<NativeSchedulerHostHealthSummaryDto>(
    "get_native_scheduler_host_health",
  );
}

export function getMissingEndpointVisibilitySummary() {
  return invokeCore<MissingEndpointVisibilitySummaryDto>(
    "get_missing_endpoint_visibility_summary",
  );
}

export function getEdrReadinessSummary() {
  return invokeCore<EdrReadinessSummaryDto>("get_edr_readiness_summary");
}

export function searchServiceStatus(request: QueryRequestDto) {
  return invokeCore<PageResponseDto<ServiceStatusViewDto>>("search_service_status", {
    request,
  });
}

export function getPortablePreferences() {
  return invokeCore<PortablePreferencesDto>("get_portable_preferences");
}
