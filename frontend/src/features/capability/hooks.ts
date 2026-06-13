import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "../../bridge/queryKeys";
import { getCapabilityOverview } from "./api";

export function useCapabilityOverviewQuery() {
  return useQuery({
    queryKey: queryKeys.capability.overview,
    queryFn: getCapabilityOverview,
  });
}
