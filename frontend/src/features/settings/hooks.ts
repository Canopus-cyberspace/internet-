import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "../../bridge/queryKeys";
import {
  applyNativeSamplerRuntimeAction,
  applyNativeSchedulerAction,
  applyRuntimeProfile,
  clearLlmAlertStoryApiKey,
  generateLlmAlertStory,
  disableForensicMode,
  enableForensicMode,
  getEdrReadinessSummary,
  getFutureSecurityFactMappingSummary,
  getLlmAlertStoryStatus,
  getMissingEndpointVisibilitySummary,
  getNativePermissionAuditSummary,
  getNativePermissionStatusSummary,
  getNativeSamplerAuthorizationReview,
  getNativeSamplerBlockedSummary,
  getNativeSamplerContract,
  getLatestNativeSamplerRuntimeBatch,
  getNativeSamplerReadinessDetail,
  getNativeSamplerReadinessSummary,
  getNativeSamplerRuntimeStatus,
  getNativeSamplerRuntimeSummary,
  getNativeSchedulerOperationalSummary,
  getNativeSchedulerSummary,
  getNativeVisibilitySummary,
  listAuthorizedNativeCapabilities,
  listNativeSamplerContracts,
  listLlmAlertStories,
  getPortablePreferences,
  getRuntimeProfile,
  getServiceStatus,
  savePortablePreferences,
  saveLlmAlertStoryApiKey,
  testLlmAlertStoryConnection,
  updateLlmAlertStorySettings,
  previewNativeSamplerActivation,
  previewNativeSchedulerEnablement,
  previewNativePermissionRequest,
  updateNativePermission,
  updatePrivacyPolicy,
  updateResponsePolicy,
} from "./api";

export function useRuntimeProfileQuery() {
  return useQuery({
    queryKey: queryKeys.settings.runtime,
    queryFn: getRuntimeProfile,
  });
}

export function useSettingsServiceStatusQuery() {
  return useQuery({
    queryKey: queryKeys.settings.service,
    queryFn: getServiceStatus,
  });
}

export function useAuthorizedNativeCapabilitiesQuery() {
  return useQuery({
    queryKey: queryKeys.settings.nativeCapabilities,
    queryFn: listAuthorizedNativeCapabilities,
  });
}

export function useNativePermissionStatusQuery() {
  return useQuery({
    queryKey: queryKeys.settings.nativePermission,
    queryFn: getNativePermissionStatusSummary,
  });
}

export function useNativeVisibilitySummaryQuery() {
  return useQuery({
    queryKey: queryKeys.settings.nativeVisibility,
    queryFn: getNativeVisibilitySummary,
  });
}

export function useNativePermissionAuditSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.settings.nativeAudit,
    queryFn: getNativePermissionAuditSummary,
  });
}

export function useNativeSamplerContractsQuery() {
  return useQuery({
    queryKey: queryKeys.settings.nativeSamplerContracts,
    queryFn: listNativeSamplerContracts,
  });
}

export function useNativeSamplerContractQuery(samplerId: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.settings.nativeSamplerContract(samplerId),
    queryFn: () => getNativeSamplerContract(samplerId),
    enabled,
  });
}

export function useNativeSamplerReadinessSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.settings.nativeSamplerReadiness,
    queryFn: getNativeSamplerReadinessSummary,
  });
}

export function useNativeSamplerReadinessDetailQuery(
  samplerId: string,
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.settings.nativeSamplerReadinessDetail(samplerId),
    queryFn: () => getNativeSamplerReadinessDetail(samplerId),
    enabled,
  });
}

export function useNativeSamplerAuthorizationReviewQuery(
  samplerId: string,
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.settings.nativeSamplerAuthorizationReview(samplerId),
    queryFn: () => getNativeSamplerAuthorizationReview(samplerId),
    enabled,
  });
}

export function useFutureSecurityFactMappingSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.settings.futureSecurityFactMappings,
    queryFn: getFutureSecurityFactMappingSummary,
  });
}

export function useNativeSamplerBlockedSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.settings.nativeSamplerBlocked,
    queryFn: getNativeSamplerBlockedSummary,
  });
}

export function useNativeSamplerRuntimeSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.settings.nativeSamplerRuntime,
    queryFn: getNativeSamplerRuntimeSummary,
  });
}

export function useNativeSchedulerSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.settings.nativeScheduler,
    queryFn: getNativeSchedulerSummary,
  });
}

export function useNativeSchedulerOperationalSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.settings.nativeSchedulerOperational,
    queryFn: getNativeSchedulerOperationalSummary,
  });
}

export function useNativeSamplerRuntimeStatusQuery(
  samplerId: string,
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.settings.nativeSamplerRuntimeStatus(samplerId),
    queryFn: () => getNativeSamplerRuntimeStatus(samplerId),
    enabled,
  });
}

export function useLatestNativeSamplerRuntimeBatchQuery(
  samplerId: string,
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.settings.nativeSamplerRuntimeBatch(samplerId),
    queryFn: () => getLatestNativeSamplerRuntimeBatch(samplerId),
    enabled,
  });
}

export function useMissingEndpointVisibilitySummaryQuery() {
  return useQuery({
    queryKey: queryKeys.settings.missingEndpointVisibility,
    queryFn: getMissingEndpointVisibilitySummary,
  });
}

export function useEdrReadinessSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.settings.edrReadiness,
    queryFn: getEdrReadinessSummary,
  });
}

export function useLlmAlertStoryStatusQuery() {
  return useQuery({
    queryKey: queryKeys.settings.llmAlertStory,
    queryFn: getLlmAlertStoryStatus,
  });
}

export function useLlmAlertStoriesQuery() {
  return useQuery({
    queryKey: queryKeys.settings.llmAlertStories,
    queryFn: () => listLlmAlertStories({ limit: 24, cursor: null }),
  });
}

export function usePortablePreferencesQuery(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.settings.portablePreferences,
    queryFn: getPortablePreferences,
    enabled,
  });
}

export function useSavePortablePreferencesMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: savePortablePreferences,
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.settings.portablePreferences,
      });
    },
  });
}

export function useApplyRuntimeProfileMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: applyRuntimeProfile,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.settings.runtime });
    },
  });
}

export function useUpdatePrivacyPolicyMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: updatePrivacyPolicy,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.settings.privacy });
      void queryClient.invalidateQueries({ queryKey: queryKeys.settings.runtime });
    },
  });
}

export function useUpdateResponsePolicyMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: updateResponsePolicy,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.settings.response });
      void queryClient.invalidateQueries({ queryKey: queryKeys.settings.runtime });
    },
  });
}

export function useEnableForensicModeMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: enableForensicMode,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.settings.privacy });
      void queryClient.invalidateQueries({ queryKey: queryKeys.settings.runtime });
    },
  });
}

export function useDisableForensicModeMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: disableForensicMode,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.settings.privacy });
      void queryClient.invalidateQueries({ queryKey: queryKeys.settings.runtime });
    },
  });
}

export function useUpdateLlmAlertStorySettingsMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: updateLlmAlertStorySettings,
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.settings.llmAlertStory,
      });
    },
  });
}

export function useSaveLlmAlertStoryApiKeyMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: saveLlmAlertStoryApiKey,
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.settings.llmAlertStory,
      });
    },
  });
}

export function useClearLlmAlertStoryApiKeyMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: clearLlmAlertStoryApiKey,
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.settings.llmAlertStory,
      });
    },
  });
}

export function useTestLlmAlertStoryConnectionMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: testLlmAlertStoryConnection,
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.settings.llmAlertStory,
      });
    },
  });
}

export function useGenerateLlmAlertStoryMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: generateLlmAlertStory,
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.settings.llmAlertStory,
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.settings.llmAlertStories,
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.security.investigationDrillDown,
      });
    },
  });
}

export function usePreviewNativePermissionRequestMutation() {
  return useMutation({
    mutationFn: previewNativePermissionRequest,
  });
}

export function useUpdateNativePermissionMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: updateNativePermission,
    onSuccess: () => {
      for (const queryKey of [
        queryKeys.settings.nativeCapabilities,
        queryKeys.settings.nativePermission,
        queryKeys.settings.nativeVisibility,
        queryKeys.settings.nativeAudit,
        queryKeys.settings.nativeSamplerReadiness,
        queryKeys.settings.nativeSamplerRuntime,
        queryKeys.settings.nativeScheduler,
        queryKeys.settings.edrReadiness,
        queryKeys.security.fusion,
        queryKeys.security.attackCoverage,
      ]) {
        void queryClient.invalidateQueries({ queryKey });
      }
    },
  });
}

export function usePreviewNativeSamplerActivationMutation() {
  return useMutation({
    mutationFn: previewNativeSamplerActivation,
  });
}

export function usePreviewNativeSchedulerEnablementMutation() {
  return useMutation({
    mutationFn: previewNativeSchedulerEnablement,
  });
}

export function useApplyNativeSamplerRuntimeActionMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: applyNativeSamplerRuntimeAction,
    onSuccess: (_result, request) => {
      for (const queryKey of [
        queryKeys.settings.nativeCapabilities,
        queryKeys.settings.nativePermission,
        queryKeys.settings.nativeVisibility,
        queryKeys.settings.nativeAudit,
        queryKeys.settings.nativeSamplerReadiness,
        queryKeys.settings.nativeSamplerRuntime,
        queryKeys.settings.nativeScheduler,
        queryKeys.settings.nativeSamplerRuntimeStatus(request.sampler_id),
        queryKeys.settings.nativeSamplerRuntimeBatch(request.sampler_id),
        queryKeys.settings.edrReadiness,
        queryKeys.security.fusion,
        queryKeys.security.fusionFacts,
        queryKeys.security.attackCoverage,
        queryKeys.security.evidenceQuality,
        queryKeys.report.list,
      ]) {
        void queryClient.invalidateQueries({ queryKey });
      }
    },
  });
}

export function useApplyNativeSchedulerActionMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: applyNativeSchedulerAction,
    onSuccess: (_result, request) => {
      for (const queryKey of [
        queryKeys.settings.nativeScheduler,
        queryKeys.settings.nativeSchedulerStatus,
        queryKeys.settings.nativeSamplerSchedules,
        queryKeys.settings.nativeSamplerRuntime,
        queryKeys.settings.nativePermission,
      ]) {
        void queryClient.invalidateQueries({ queryKey });
      }
      if (request.sampler_id) {
        void queryClient.invalidateQueries({
          queryKey: queryKeys.settings.nativeSamplerSchedule(request.sampler_id),
        });
      }
    },
  });
}
