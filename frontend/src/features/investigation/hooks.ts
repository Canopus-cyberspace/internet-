import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { QueryRequestDto } from "../../bridge/dto/common";
import { defaultQueryRequest, queryKeys } from "../../bridge/queryKeys";
import {
  dismissFinding,
  escalateAlert,
  getDurableBaselineSummary,
  getEvidenceQualitySummary,
  getEndpointThreatSummary,
  getIncidentDetail,
  getInvestigationDrillDownSummary,
  searchAlerts,
  searchFindings,
  searchIncidents,
  suppressFinding,
  updateIncidentStatus,
} from "./api";

export function useFindingsQuery(request: QueryRequestDto = defaultQueryRequest()) {
  return useQuery({
    queryKey: queryKeys.security.findings(request),
    queryFn: () => searchFindings(request),
  });
}

export function useAlertsQuery(request: QueryRequestDto = defaultQueryRequest()) {
  return useQuery({
    queryKey: queryKeys.security.alerts(request),
    queryFn: () => searchAlerts(request),
  });
}

export function useIncidentsQuery(request: QueryRequestDto = defaultQueryRequest()) {
  return useQuery({
    queryKey: queryKeys.security.incidents(request),
    queryFn: () => searchIncidents(request),
  });
}

export function useIncidentDetailQuery(incidentId: string | null) {
  return useQuery({
    queryKey: incidentId
      ? queryKeys.security.incidentDetail(incidentId)
      : ["security", "incident", "detail", "none"],
    queryFn: () => getIncidentDetail(incidentId ?? ""),
    enabled: Boolean(incidentId),
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

export function useEndpointThreatSummaryQuery() {
  return useQuery({
    queryKey: queryKeys.security.endpointThreat,
    queryFn: getEndpointThreatSummary,
  });
}

export function useSuppressFindingMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: suppressFinding,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["security", "findings"] });
    },
  });
}

export function useDismissFindingMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: dismissFinding,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["security", "findings"] });
    },
  });
}

export function useEscalateAlertMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: escalateAlert,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["security", "alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["security", "incidents"] });
    },
  });
}

export function useUpdateIncidentStatusMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: updateIncidentStatus,
    onSuccess: (_receipt, request) => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.security.incidentDetail(request.incident_id),
      });
      void queryClient.invalidateQueries({ queryKey: ["security", "incidents"] });
    },
  });
}
