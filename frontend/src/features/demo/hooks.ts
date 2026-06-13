import { useMutation, useQueryClient } from "@tanstack/react-query";
import { runDemoStory } from "./api";

const DEMO_INVALIDATION_ROOTS = [
  "security",
  "network",
  "graph",
  "response",
  "report",
  "platform",
] as const;

export function useRunDemoStoryMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: runDemoStory,
    onSuccess: () => {
      for (const root of DEMO_INVALIDATION_ROOTS) {
        void queryClient.invalidateQueries({ queryKey: [root] });
      }
    },
  });
}
