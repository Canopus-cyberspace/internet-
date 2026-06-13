import { useQuery } from "@tanstack/react-query";
import type { NavigationResolveRequestDto } from "../../bridge/dto/navigation";
import { queryKeys } from "../../bridge/queryKeys";
import { resolveNavigationReference } from "./api";

export function useNavigationResolutionQuery(
  request: NavigationResolveRequestDto | null,
) {
  return useQuery({
    queryKey: request
      ? queryKeys.navigation.resolve(request)
      : ["navigation", "resolve", "none"],
    queryFn: () => resolveNavigationReference(request!),
    enabled: Boolean(request),
  });
}
