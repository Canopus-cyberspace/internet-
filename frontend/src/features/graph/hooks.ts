import { useQuery } from "@tanstack/react-query";
import type { GraphViewRequestDto } from "../../bridge/dto/graph";
import { queryKeys } from "../../bridge/queryKeys";
import { getGraphView } from "./api";

export function useGraphViewQuery(request: GraphViewRequestDto) {
  return useQuery({
    queryKey: queryKeys.graph.view(
      request.graph_type,
      JSON.stringify(request.scope),
    ),
    queryFn: () => getGraphView(request),
  });
}
