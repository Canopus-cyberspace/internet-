import type { CommandReceiptDto, JsonValue } from "./dto/common";
import type { DemoStoryResultDto } from "./dto/demo";
import type { PortablePreferencesDto } from "./dto/platform";
import type {
  PluginLifecycleMutationResultDto,
  PluginLifecycleRequestDto,
} from "./dto/plugin";
import type {
  LocalMetadataProxyStartRequestDto,
  LocalMetadataProxyStatusDto,
  MetadataSamplingLoopControlRequestDto,
  MetadataSamplingLoopRunRequestDto,
  MetadataSamplingTickRequestDto,
  MetadataSamplingTickResultDto,
  MetadataWatchControllerStatusDto,
  MetadataWatchLifecycleRequestDto,
  MetadataWatchSourceConfirmationDto,
  MetadataWatchSourcePreviewDto,
  MetadataWatchSourcePreviewRequestDto,
  PortableCaptureImportConfirmationDto,
  PortableCaptureImportFileRequestDto,
  PortableCaptureImportPreviewDto,
  PortableCaptureImportResultDto,
} from "./dto/network";
import type {
  ExplicitExportConfirmationDto,
  ExplicitExportPreviewDto,
  ExplicitExportRequestDto,
  ExplicitExportResultDto,
  ExportReportMutationResultDto,
  ExportReportRequestDto,
  GenerateIncidentReportRequestDto,
  ReportGenerationResultDto,
} from "./dto/report";
import type {
  CreateResponsePlanRequestDto,
  ResponseApprovalMutationRequestDto,
  ResponseApprovalMutationResultDto,
  ResponsePlanMutationResultDto,
  RollbackResponseActionRequestDto,
  RollbackResponseActionResultDto,
} from "./dto/response";
import type {
  AlertEscalationResultDto,
  EscalateAlertRequestDto,
  FindingStateMutationRequestDto,
  FindingStateMutationResultDto,
  IncidentStatusMutationRequestDto,
  IncidentStatusMutationResultDto,
} from "./dto/security";
import type {
  ApplyRuntimeProfileRequestDto,
  ClearLlmAlertStoryApiKeyRequestDto,
  GenerateLlmAlertStoryRequestDto,
  LlmAlertStoryRecordDto,
  DisableForensicModeRequestDto,
  EnableForensicModeRequestDto,
  LlmAlertStoryStatusDto,
  NativePermissionActionRequestDto,
  NativePermissionActionResultDto,
  NativePermissionPreviewDto,
  NativeSamplerActivationPreviewDto,
  NativeSamplerRuntimeActionRequestDto,
  NativeSamplerRuntimeActionResultDto,
  NativeSchedulerActionRequestDto,
  NativeSchedulerActionResultDto,
  NativeSchedulerEnablementPreviewDto,
  NativeSchedulerHostActionResultDto,
  NativeSchedulerHostStartPreviewDto,
  SaveLlmAlertStoryApiKeyRequestDto,
  SettingsMutationResultDto,
  TestLlmAlertStoryConnectionRequestDto,
  UpdateLlmAlertStorySettingsRequestDto,
  UpdatePrivacyPolicyRequestDto,
  UpdateResponsePolicyRequestDto,
} from "./dto/settings";
import { invokeCore } from "./tauri/invoke";

export function enablePlugin(request: PluginLifecycleRequestDto) {
  return invokeCore<CommandReceiptDto<PluginLifecycleMutationResultDto>>(
    "enable_plugin",
    { request },
  );
}

export function disablePlugin(request: PluginLifecycleRequestDto) {
  return invokeCore<CommandReceiptDto<PluginLifecycleMutationResultDto>>(
    "disable_plugin",
    { request },
  );
}

export function restartPlugin(request: PluginLifecycleRequestDto) {
  return invokeCore<CommandReceiptDto<PluginLifecycleMutationResultDto>>(
    "restart_plugin",
    { request },
  );
}

export function suppressFinding(request: FindingStateMutationRequestDto) {
  return invokeCore<CommandReceiptDto<FindingStateMutationResultDto>>(
    "suppress_finding",
    { request },
  );
}

export function dismissFinding(request: FindingStateMutationRequestDto) {
  return invokeCore<CommandReceiptDto<FindingStateMutationResultDto>>(
    "dismiss_finding",
    { request },
  );
}

export function escalateAlert(request: EscalateAlertRequestDto) {
  return invokeCore<CommandReceiptDto<AlertEscalationResultDto>>(
    "escalate_alert",
    { request },
  );
}

export function updateIncidentStatus(request: IncidentStatusMutationRequestDto) {
  return invokeCore<CommandReceiptDto<IncidentStatusMutationResultDto>>(
    "update_incident_status",
    { request },
  );
}

export function createResponsePlan(request: CreateResponsePlanRequestDto) {
  return invokeCore<CommandReceiptDto<ResponsePlanMutationResultDto>>(
    "create_response_plan",
    { request },
  );
}

export function approveResponseAction(request: ResponseApprovalMutationRequestDto) {
  return invokeCore<CommandReceiptDto<ResponseApprovalMutationResultDto>>(
    "approve_response_action",
    { request },
  );
}

export function rejectResponseAction(request: ResponseApprovalMutationRequestDto) {
  return invokeCore<CommandReceiptDto<ResponseApprovalMutationResultDto>>(
    "reject_response_action",
    { request },
  );
}

export function rollbackResponseAction(request: RollbackResponseActionRequestDto) {
  return invokeCore<CommandReceiptDto<RollbackResponseActionResultDto>>(
    "rollback_response_action",
    { request },
  );
}

export function generateIncidentReport(request: GenerateIncidentReportRequestDto) {
  return invokeCore<CommandReceiptDto<ReportGenerationResultDto>>(
    "generate_incident_report",
    { request },
  );
}

export function exportReport(request: ExportReportRequestDto) {
  return invokeCore<CommandReceiptDto<ExportReportMutationResultDto>>(
    "export_report",
    { request },
  );
}

export function getLocalMetadataProxyStatus() {
  return invokeCore<LocalMetadataProxyStatusDto>("get_local_metadata_proxy_status");
}

export function startLocalMetadataProxy(request: LocalMetadataProxyStartRequestDto) {
  return invokeCore<LocalMetadataProxyStatusDto>("start_local_metadata_proxy", {
    request,
  });
}

export function stopLocalMetadataProxy() {
  return invokeCore<LocalMetadataProxyStatusDto>("stop_local_metadata_proxy");
}

export function drainLocalMetadataProxy() {
  return invokeCore<LocalMetadataProxyStatusDto>("drain_local_metadata_proxy");
}

export function previewPortableCaptureImport(
  request: PortableCaptureImportFileRequestDto,
) {
  return invokeCore<PortableCaptureImportPreviewDto>(
    "preview_portable_capture_import",
    { request },
  );
}

export function confirmPortableCaptureImport(
  confirmation: PortableCaptureImportConfirmationDto,
) {
  return invokeCore<CommandReceiptDto<PortableCaptureImportResultDto>>(
    "confirm_portable_capture_import",
    { confirmation },
  );
}

export function previewMetadataWatchSource(
  request: MetadataWatchSourcePreviewRequestDto,
) {
  return invokeCore<MetadataWatchSourcePreviewDto>("preview_metadata_watch_source", {
    request,
  });
}

export function confirmMetadataWatchSource(
  confirmation: MetadataWatchSourceConfirmationDto,
) {
  return invokeCore<CommandReceiptDto<MetadataWatchControllerStatusDto>>(
    "confirm_metadata_watch_source",
    { confirmation },
  );
}

export function updateMetadataWatchSource(request: MetadataWatchLifecycleRequestDto) {
  return invokeCore<CommandReceiptDto<MetadataWatchControllerStatusDto>>(
    "update_metadata_watch_source",
    { request },
  );
}

export function tickMetadataWatchController(request: MetadataSamplingTickRequestDto) {
  return invokeCore<CommandReceiptDto<MetadataSamplingTickResultDto>>(
    "tick_metadata_watch_controller",
    { request },
  );
}

export function updateMetadataSamplingLoop(
  request: MetadataSamplingLoopControlRequestDto,
) {
  return invokeCore<CommandReceiptDto<MetadataWatchControllerStatusDto>>(
    "update_metadata_sampling_loop",
    { request },
  );
}

export function runMetadataSamplingLoop(request: MetadataSamplingLoopRunRequestDto) {
  return invokeCore<CommandReceiptDto<MetadataSamplingTickResultDto>>(
    "run_metadata_sampling_loop",
    { request },
  );
}

export function previewExplicitExport(request: ExplicitExportRequestDto) {
  return invokeCore<ExplicitExportPreviewDto>("preview_explicit_export", {
    request,
  });
}

export function confirmExplicitExport(confirmation: ExplicitExportConfirmationDto) {
  return invokeCore<ExplicitExportResultDto>("confirm_explicit_export", {
    confirmation,
  });
}

export function applyRuntimeProfile(request: ApplyRuntimeProfileRequestDto) {
  return invokeCore<CommandReceiptDto<SettingsMutationResultDto>>(
    "apply_runtime_profile",
    { request },
  );
}

export function updatePrivacyPolicy(request: UpdatePrivacyPolicyRequestDto) {
  return invokeCore<CommandReceiptDto<SettingsMutationResultDto>>(
    "update_privacy_policy",
    { request },
  );
}

export function updateResponsePolicy(request: UpdateResponsePolicyRequestDto) {
  return invokeCore<CommandReceiptDto<SettingsMutationResultDto>>(
    "update_response_policy",
    { request },
  );
}

export function enableForensicMode(request: EnableForensicModeRequestDto) {
  return invokeCore<CommandReceiptDto<SettingsMutationResultDto>>(
    "enable_forensic_mode",
    { request },
  );
}

export function disableForensicMode(request: DisableForensicModeRequestDto) {
  return invokeCore<CommandReceiptDto<SettingsMutationResultDto>>(
    "disable_forensic_mode",
    { request },
  );
}

export function updateLlmAlertStorySettings(
  request: UpdateLlmAlertStorySettingsRequestDto,
) {
  return invokeCore<LlmAlertStoryStatusDto>("update_llm_alert_story_settings", {
    request,
  });
}

export function saveLlmAlertStoryApiKey(request: SaveLlmAlertStoryApiKeyRequestDto) {
  return invokeCore<LlmAlertStoryStatusDto>("save_llm_alert_story_api_key", {
    request,
  });
}

export function clearLlmAlertStoryApiKey(
  request: ClearLlmAlertStoryApiKeyRequestDto,
) {
  return invokeCore<LlmAlertStoryStatusDto>("clear_llm_alert_story_api_key", {
    request,
  });
}

export function testLlmAlertStoryConnection(
  request: TestLlmAlertStoryConnectionRequestDto,
) {
  return invokeCore<LlmAlertStoryStatusDto>("test_llm_alert_story_connection", {
    request,
  });
}

export function generateLlmAlertStory(request: GenerateLlmAlertStoryRequestDto) {
  return invokeCore<LlmAlertStoryRecordDto>("generate_llm_alert_story", {
    request,
  });
}

export function previewNativePermissionRequest(capabilityId: string) {
  return invokeCore<NativePermissionPreviewDto>("preview_native_permission_request", {
    capability_id: capabilityId,
  });
}

export function updateNativePermission(request: NativePermissionActionRequestDto) {
  return invokeCore<NativePermissionActionResultDto>("update_native_permission", {
    request,
  });
}

export function previewNativeSamplerActivation(samplerId: string) {
  return invokeCore<NativeSamplerActivationPreviewDto>(
    "preview_native_sampler_activation",
    { sampler_id: samplerId },
  );
}

export function applyNativeSamplerRuntimeAction(
  request: NativeSamplerRuntimeActionRequestDto,
) {
  return invokeCore<NativeSamplerRuntimeActionResultDto>(
    "apply_native_sampler_runtime_action",
    { request },
  );
}

export function previewNativeSchedulerEnablement(samplerId: string) {
  return invokeCore<NativeSchedulerEnablementPreviewDto>(
    "preview_native_scheduler_enablement",
    { sampler_id: samplerId },
  );
}

export function applyNativeSchedulerAction(request: NativeSchedulerActionRequestDto) {
  return invokeCore<NativeSchedulerActionResultDto>("apply_native_scheduler_action", {
    request,
  });
}

export function previewNativeSchedulerHostStart() {
  return invokeCore<NativeSchedulerHostStartPreviewDto>(
    "preview_native_scheduler_host_start",
  );
}

export function startNativeSchedulerHost() {
  return invokeCore<NativeSchedulerHostActionResultDto>(
    "start_native_scheduler_host",
  );
}

export function pauseNativeSchedulerHost() {
  return invokeCore<NativeSchedulerHostActionResultDto>(
    "pause_native_scheduler_host",
  );
}

export function resumeNativeSchedulerHost() {
  return invokeCore<NativeSchedulerHostActionResultDto>(
    "resume_native_scheduler_host",
  );
}

export function wakeNativeSchedulerHost() {
  return invokeCore<NativeSchedulerHostActionResultDto>(
    "wake_native_scheduler_host",
  );
}

export function stopNativeSchedulerHost() {
  return invokeCore<NativeSchedulerHostActionResultDto>(
    "stop_native_scheduler_host",
  );
}

export function runDemoStory() {
  return invokeCore<DemoStoryResultDto>("run_demo_story");
}

export function savePortablePreferences(preferences: PortablePreferencesDto) {
  return invokeCore<PortablePreferencesDto>("save_portable_preferences", {
    preferences,
  });
}

export function mutationResultInvalidation(_receipt: CommandReceiptDto<JsonValue>) {
  return ["platform", "components"] as const;
}
