import { describe, expect, it } from "vitest";
import * as capabilityHooks from "./capability/hooks";
import * as demoHooks from "./demo/hooks";
import * as graphHooks from "./graph/hooks";
import * as investigationHooks from "./investigation/hooks";
import * as networkHooks from "./network/hooks";
import * as platformHooks from "./platform/hooks";
import * as pluginHooks from "./plugin/hooks";
import * as reportHooks from "./report/hooks";
import * as responseHooks from "./response/hooks";
import * as settingsHooks from "./settings/hooks";

const REQUIRED_HOOKS: Array<[Record<string, unknown>, string[]]> = [
  [
    platformHooks,
    [
      "useComponentsQuery",
      "useComponentDetailQuery",
      "useServiceStatusQuery",
    ],
  ],
  [
    pluginHooks,
    [
      "usePluginCatalogQuery",
      "usePluginManifestQuery",
      "useEnablePluginMutation",
      "useDisablePluginMutation",
      "useRestartPluginMutation",
    ],
  ],
  [demoHooks, ["useRunDemoStoryMutation"]],
  [capabilityHooks, ["useCapabilityOverviewQuery"]],
  [
    investigationHooks,
    [
      "useFindingsQuery",
      "useAlertsQuery",
      "useIncidentsQuery",
      "useIncidentDetailQuery",
      "useSuppressFindingMutation",
      "useDismissFindingMutation",
      "useEscalateAlertMutation",
      "useUpdateIncidentStatusMutation",
    ],
  ],
  [graphHooks, ["useGraphViewQuery"]],
  [
    networkHooks,
    [
      "useFlowsQuery",
      "useDnsQuery",
      "useTlsQuery",
      "useProviderControllerStatusQuery",
      "useNetworkProviderStatusesQuery",
      "useNetworkProviderStatusQuery",
      "useNetworkVisibilitySummaryQuery",
      "useNetworkFallbackPlanQuery",
      "useLocalMetadataProxyStatusQuery",
      "useStartLocalMetadataProxyMutation",
      "useStopLocalMetadataProxyMutation",
      "useDrainLocalMetadataProxyMutation",
    ],
  ],
  [
    responseHooks,
    [
      "useActiveResponsesQuery",
      "useCreateResponsePlanMutation",
      "useApproveResponseActionMutation",
      "useRejectResponseActionMutation",
      "useRollbackResponseActionMutation",
    ],
  ],
  [
    reportHooks,
    [
      "useReportsQuery",
      "useReportQuery",
      "useExportHistoryQuery",
      "useExportHistoryRecordQuery",
      "useExportPolicyViolationsQuery",
      "useGenerateIncidentReportMutation",
      "useExportReportMutation",
      "usePreviewExplicitExportMutation",
      "useConfirmExplicitExportMutation",
    ],
  ],
  [
    settingsHooks,
    [
      "useRuntimeProfileQuery",
      "useSettingsServiceStatusQuery",
      "useAuthorizedNativeCapabilitiesQuery",
      "useNativePermissionStatusQuery",
      "useNativeVisibilitySummaryQuery",
      "useNativePermissionAuditSummaryQuery",
      "useNativeSamplerContractsQuery",
      "useNativeSamplerContractQuery",
      "useNativeSamplerReadinessSummaryQuery",
      "useNativeSamplerReadinessDetailQuery",
      "useNativeSamplerAuthorizationReviewQuery",
      "useFutureSecurityFactMappingSummaryQuery",
      "useNativeSamplerBlockedSummaryQuery",
      "useNativeSchedulerSummaryQuery",
      "useNativeSchedulerOperationalSummaryQuery",
      "useMissingEndpointVisibilitySummaryQuery",
      "useEdrReadinessSummaryQuery",
      "useLlmAlertStoryStatusQuery",
      "useLlmAlertStoriesQuery",
      "useApplyRuntimeProfileMutation",
      "useUpdatePrivacyPolicyMutation",
      "useUpdateResponsePolicyMutation",
      "useEnableForensicModeMutation",
      "useDisableForensicModeMutation",
      "useUpdateLlmAlertStorySettingsMutation",
      "useSaveLlmAlertStoryApiKeyMutation",
      "useClearLlmAlertStoryApiKeyMutation",
      "useTestLlmAlertStoryConnectionMutation",
      "useGenerateLlmAlertStoryMutation",
      "usePreviewNativePermissionRequestMutation",
      "useUpdateNativePermissionMutation",
      "usePreviewNativeSchedulerEnablementMutation",
      "useApplyNativeSchedulerActionMutation",
    ],
  ],
];

describe("feature bridge hooks", () => {
  it("exports query and mutation hooks for every available command group", () => {
    for (const [module, hookNames] of REQUIRED_HOOKS) {
      for (const hookName of hookNames) {
        expect(typeof module[hookName]).toBe("function");
      }
    }
  });
});
