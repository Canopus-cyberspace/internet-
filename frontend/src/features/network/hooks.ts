import { QueryClient, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { QueryRequestDto } from "../../bridge/dto/common";
import type {
  LocalMetadataProxyStartRequestDto,
  MetadataSamplingLoopControlRequestDto,
  MetadataSamplingLoopRunRequestDto,
  MetadataSamplingTickRequestDto,
  MetadataWatchLifecycleRequestDto,
  MetadataWatchSourceConfirmationDto,
  MetadataWatchSourcePreviewRequestDto,
  PortableCaptureImportConfirmationDto,
  PortableCaptureImportFileRequestDto,
} from "../../bridge/dto/network";
import { defaultQueryRequest, queryKeys } from "../../bridge/queryKeys";
import {
  drainLocalMetadataProxy,
  getLocalMetadataProxyStatus,
  getMetadataWatchControllerStatus,
  getNetworkFallbackPlan,
  getNetworkProviderStatus,
  getNetworkVisibilitySummary,
  getProviderControllerStatus,
  getInvestigationDrillDownSummary,
  confirmPortableCaptureImport,
  confirmMetadataWatchSource,
  listMetadataSamplingBatches,
  listMetadataWatchSources,
  listNetworkProviderStatus,
  previewPortableCaptureImport,
  previewMetadataWatchSource,
  runMetadataSamplingLoop,
  searchDns,
  searchFlows,
  startLocalMetadataProxy,
  stopLocalMetadataProxy,
  searchTls,
  tickMetadataWatchController,
  updateMetadataSamplingLoop,
  updateMetadataWatchSource,
} from "./api";

export function useFlowsQuery(request: QueryRequestDto = defaultQueryRequest()) {
  return useQuery({
    queryKey: queryKeys.network.flows(request),
    queryFn: () => searchFlows(request),
  });
}

export function useDnsQuery(request: QueryRequestDto = defaultQueryRequest()) {
  return useQuery({
    queryKey: queryKeys.network.dns(request),
    queryFn: () => searchDns(request),
  });
}

export function useTlsQuery(request: QueryRequestDto = defaultQueryRequest()) {
  return useQuery({
    queryKey: queryKeys.network.tls(request),
    queryFn: () => searchTls(request),
  });
}

export function useProviderControllerStatusQuery() {
  return useQuery({
    queryKey: queryKeys.network.providerController,
    queryFn: getProviderControllerStatus,
  });
}

export function useNetworkProviderStatusesQuery() {
  return useQuery({
    queryKey: queryKeys.network.providerStatuses,
    queryFn: listNetworkProviderStatus,
  });
}

export function useNetworkProviderStatusQuery(providerId: string) {
  return useQuery({
    queryKey: queryKeys.network.providerStatus(providerId),
    queryFn: () => getNetworkProviderStatus(providerId),
    enabled: providerId.length > 0,
  });
}

export function useNetworkVisibilitySummaryQuery() {
  return useQuery({
    queryKey: queryKeys.network.providerVisibility,
    queryFn: getNetworkVisibilitySummary,
  });
}

export function useNetworkFallbackPlanQuery() {
  return useQuery({
    queryKey: queryKeys.network.providerFallbackPlan,
    queryFn: getNetworkFallbackPlan,
  });
}

export function useLocalMetadataProxyStatusQuery() {
  return useQuery({
    queryKey: queryKeys.network.localMetadataProxy,
    queryFn: getLocalMetadataProxyStatus,
    refetchInterval: (query) => {
      const state = query.state.data?.state;
      return state === "running" || state === "degraded" ? 1500 : false;
    },
  });
}

export function useMetadataWatchStatusQuery() {
  return useQuery({
    queryKey: queryKeys.network.metadataWatchStatus,
    queryFn: getMetadataWatchControllerStatus,
    refetchInterval: (query) => {
      const status = query.state.data;
      return status?.loop_enabled && !status.loop_paused ? 1500 : status?.running ? 1500 : false;
    },
  });
}

export function useMetadataWatchSourcesQuery() {
  return useQuery({
    queryKey: queryKeys.network.metadataWatchSources,
    queryFn: () => listMetadataWatchSources({ limit: 50, cursor: null }),
  });
}

export function useMetadataSamplingBatchesQuery() {
  return useQuery({
    queryKey: queryKeys.network.metadataSamplingBatches,
    queryFn: () => listMetadataSamplingBatches({ limit: 50, cursor: null }),
  });
}

export function useInvestigationDrillDownSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.security.investigationDrillDown,
    queryFn: getInvestigationDrillDownSummary,
  });
}

export function usePreviewPortableCaptureImportMutation() {
  return useMutation({
    mutationFn: (request: PortableCaptureImportFileRequestDto) =>
      previewPortableCaptureImport(request),
  });
}

export function invalidateNetworkAnalysisQueries(queryClient: QueryClient) {
  return Promise.all([
    queryClient.invalidateQueries({ queryKey: ["network"] }),
    queryClient.invalidateQueries({ queryKey: ["graph"] }),
    queryClient.invalidateQueries({ queryKey: ["security", "findings"] }),
    queryClient.invalidateQueries({ queryKey: ["security", "alerts"] }),
    queryClient.invalidateQueries({ queryKey: ["security", "incidents"] }),
    queryClient.invalidateQueries({ queryKey: queryKeys.security.fusion }),
    queryClient.invalidateQueries({ queryKey: queryKeys.security.baseline }),
    queryClient.invalidateQueries({
      queryKey: queryKeys.security.investigationDrillDown,
    }),
    queryClient.invalidateQueries({ queryKey: queryKeys.security.attackCoverage }),
    queryClient.invalidateQueries({ queryKey: queryKeys.report.list }),
  ]);
}

export function invalidateLocalMetadataProxyRefreshQueries(queryClient: QueryClient) {
  return Promise.all([
    invalidateNetworkAnalysisQueries(queryClient),
    queryClient.invalidateQueries({ queryKey: queryKeys.report.exportHistory }),
    queryClient.invalidateQueries({
      queryKey: queryKeys.report.exportPolicyViolations,
    }),
  ]);
}

export function useConfirmPortableCaptureImportMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (confirmation: PortableCaptureImportConfirmationDto) =>
      confirmPortableCaptureImport(confirmation),
    onSuccess: () => {
      void invalidateNetworkAnalysisQueries(queryClient);
    },
  });
}

export function usePreviewMetadataWatchSourceMutation() {
  return useMutation({
    mutationFn: (request: MetadataWatchSourcePreviewRequestDto) =>
      previewMetadataWatchSource(request),
  });
}

export function useConfirmMetadataWatchSourceMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (confirmation: MetadataWatchSourceConfirmationDto) =>
      confirmMetadataWatchSource(confirmation),
    onSuccess: () => {
      void invalidateNetworkAnalysisQueries(queryClient);
    },
  });
}

export function useUpdateMetadataWatchSourceMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: MetadataWatchLifecycleRequestDto) =>
      updateMetadataWatchSource(request),
    onSuccess: () => {
      void invalidateNetworkAnalysisQueries(queryClient);
    },
  });
}

export function useTickMetadataWatchControllerMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: MetadataSamplingTickRequestDto) =>
      tickMetadataWatchController(request),
    onSuccess: () => {
      void invalidateLocalMetadataProxyRefreshQueries(queryClient);
    },
  });
}

export function useUpdateMetadataSamplingLoopMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: MetadataSamplingLoopControlRequestDto) =>
      updateMetadataSamplingLoop(request),
    onSuccess: () => {
      void invalidateNetworkAnalysisQueries(queryClient);
    },
  });
}

export function useRunMetadataSamplingLoopMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: MetadataSamplingLoopRunRequestDto) =>
      runMetadataSamplingLoop(request),
    onSuccess: () => {
      void invalidateLocalMetadataProxyRefreshQueries(queryClient);
    },
  });
}

export function useStartLocalMetadataProxyMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: LocalMetadataProxyStartRequestDto) =>
      startLocalMetadataProxy(request),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.network.localMetadataProxy,
      });
      void queryClient.invalidateQueries({ queryKey: queryKeys.settings.service });
    },
  });
}

export function useStopLocalMetadataProxyMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: stopLocalMetadataProxy,
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.network.localMetadataProxy,
      });
      void queryClient.invalidateQueries({ queryKey: queryKeys.settings.service });
      void invalidateLocalMetadataProxyRefreshQueries(queryClient);
    },
  });
}

export function useDrainLocalMetadataProxyMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: drainLocalMetadataProxy,
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.network.localMetadataProxy,
      });
      void queryClient.invalidateQueries({ queryKey: queryKeys.settings.service });
      void invalidateLocalMetadataProxyRefreshQueries(queryClient);
    },
  });
}
