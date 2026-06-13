import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { PageRequestDto } from "../../bridge/dto/common";
import { queryKeys } from "../../bridge/queryKeys";
import {
  approveResponseAction,
  createResponsePlan,
  listActiveResponses,
  rejectResponseAction,
  rollbackResponseAction,
} from "./api";

const defaultPage: PageRequestDto = { limit: 100, cursor: null };

export function useActiveResponsesQuery(page: PageRequestDto = defaultPage) {
  return useQuery({
    queryKey: queryKeys.response.active,
    queryFn: () => listActiveResponses(page),
  });
}

export function useCreateResponsePlanMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: createResponsePlan,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.response.active });
      void queryClient.invalidateQueries({ queryKey: ["response", "plans"] });
    },
  });
}

export function useApproveResponseActionMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: approveResponseAction,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.response.active });
    },
  });
}

export function useRejectResponseActionMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: rejectResponseAction,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.response.active });
    },
  });
}

export function useRollbackResponseActionMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: rollbackResponseAction,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.response.active });
      void queryClient.invalidateQueries({ queryKey: ["response", "history"] });
    },
  });
}
