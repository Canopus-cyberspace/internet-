import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "../../bridge/queryKeys";
import {
  disablePlugin,
  enablePlugin,
  getPluginCatalog,
  getPluginManifest,
  restartPlugin,
} from "./api";

export function usePluginCatalogQuery() {
  return useQuery({
    queryKey: queryKeys.plugin.catalog,
    queryFn: getPluginCatalog,
  });
}

export function usePluginManifestQuery(pluginId: string | null) {
  return useQuery({
    queryKey: pluginId
      ? queryKeys.plugin.manifest(pluginId)
      : ["plugin", "manifest", "none"],
    queryFn: () => getPluginManifest(pluginId ?? ""),
    enabled: Boolean(pluginId),
  });
}

export function useEnablePluginMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: enablePlugin,
    onSuccess: (_receipt, request) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.plugin.catalog });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.plugin.manifest(request.plugin_id),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.platform.components,
      });
    },
  });
}

export function useDisablePluginMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: disablePlugin,
    onSuccess: (_receipt, request) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.plugin.catalog });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.plugin.manifest(request.plugin_id),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.platform.components,
      });
    },
  });
}

export function useRestartPluginMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: restartPlugin,
    onSuccess: (_receipt, request) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.plugin.catalog });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.plugin.manifest(request.plugin_id),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.platform.components,
      });
    },
  });
}
