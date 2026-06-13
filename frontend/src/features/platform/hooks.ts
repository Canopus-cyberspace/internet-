import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "../../bridge/queryKeys";
import { getComponentDetail, getServiceStatus, listComponents } from "./api";

export function useComponentsQuery() {
  return useQuery({
    queryKey: queryKeys.platform.components,
    queryFn: listComponents,
  });
}

export function useComponentDetailQuery(componentId: string | null) {
  return useQuery({
    queryKey: componentId
      ? queryKeys.platform.componentDetail(componentId)
      : ["platform", "component", "detail", "none"],
    queryFn: () => getComponentDetail(componentId ?? ""),
    enabled: Boolean(componentId),
  });
}

export function useServiceStatusQuery() {
  return useQuery({
    queryKey: queryKeys.settings.service,
    queryFn: getServiceStatus,
  });
}
