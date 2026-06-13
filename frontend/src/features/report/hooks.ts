import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { PageRequestDto } from "../../bridge/dto/common";
import type {
  ExplicitExportConfirmationDto,
  ExplicitExportRequestDto,
  ReportExportHistoryQueryDto,
} from "../../bridge/dto/report";
import { queryKeys } from "../../bridge/queryKeys";
import {
  confirmExplicitExport,
  exportReport,
  generateIncidentReport,
  getAttackCoverageSummary,
  getDurableBaselineSummary,
  getEvidenceQualitySummary,
  getFusionSummary,
  getInvestigationDrillDownSummary,
  getExportHistoryRecord,
  getReport,
  listExportHistory,
  listExportPolicyViolations,
  listReports,
  previewExplicitExport,
} from "./api";

const defaultPage: PageRequestDto = { limit: 100, cursor: null };

export function useReportsQuery(page: PageRequestDto = defaultPage) {
  return useQuery({
    queryKey: queryKeys.report.list,
    queryFn: () => listReports(page),
  });
}

export function useReportQuery(reportId: string | null) {
  return useQuery({
    queryKey: reportId
      ? queryKeys.report.detail(reportId)
      : ["report", "detail", "none"],
    queryFn: () => getReport(reportId ?? ""),
    enabled: Boolean(reportId),
  });
}

export function useExportHistoryQuery(query?: ReportExportHistoryQueryDto) {
  const request = query ?? { page: defaultPage };
  return useQuery({
    queryKey: queryKeys.report.exportHistoryList(request),
    queryFn: () => listExportHistory(request),
  });
}

export function useExportHistoryRecordQuery(exportResultId: string | null) {
  return useQuery({
    queryKey: exportResultId
      ? queryKeys.report.exportHistoryDetail(exportResultId)
      : ["report", "export_history", "detail", "none"],
    queryFn: () => getExportHistoryRecord(exportResultId ?? ""),
    enabled: Boolean(exportResultId),
  });
}

export function useExportPolicyViolationsQuery() {
  return useQuery({
    queryKey: queryKeys.report.exportPolicyViolations,
    queryFn: listExportPolicyViolations,
  });
}

export function useAttackCoverageSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.security.attackCoverage,
    queryFn: getAttackCoverageSummary,
  });
}

export function useFusionSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.security.fusion,
    queryFn: getFusionSummary,
  });
}

export function useDurableBaselineSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.security.baseline,
    queryFn: getDurableBaselineSummary,
  });
}

export function useEvidenceQualitySummaryQuery() {
  return useQuery({
    queryKey: queryKeys.security.evidenceQuality,
    queryFn: getEvidenceQualitySummary,
  });
}

export function useInvestigationDrillDownSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.security.investigationDrillDown,
    queryFn: getInvestigationDrillDownSummary,
  });
}

export function useGenerateIncidentReportMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: generateIncidentReport,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.report.list });
    },
  });
}

export function useExportReportMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: exportReport,
    onSuccess: (_receipt, request) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.report.list });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.report.detail(request.report_id),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.report.exportHistory,
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.report.exportPolicyViolations,
      });
    },
  });
}

export function usePreviewExplicitExportMutation() {
  return useMutation({
    mutationFn: (request: ExplicitExportRequestDto) => previewExplicitExport(request),
  });
}

export function useConfirmExplicitExportMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (confirmation: ExplicitExportConfirmationDto) =>
      confirmExplicitExport(confirmation),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.report.exportHistory,
      });
    },
  });
}
