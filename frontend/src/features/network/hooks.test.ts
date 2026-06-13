import { QueryClient } from "@tanstack/react-query";
import { describe, expect, it } from "vitest";
import { queryKeys } from "../../bridge/queryKeys";
import {
  invalidateLocalMetadataProxyRefreshQueries,
  invalidateNetworkAnalysisQueries,
} from "./hooks";

describe("network hook invalidation helpers", () => {
  it("invalidates network analysis views after metadata ingest", async () => {
    const queryClient = seededQueryClient();

    await invalidateNetworkAnalysisQueries(queryClient);

    expect(queryClient.getQueryState(["network", "flows", "default"])?.isInvalidated).toBe(
      true,
    );
    expect(queryClient.getQueryState(["graph", "view", "asset_exposure_graph", "overview"])?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(["security", "findings", "default"])?.isInvalidated).toBe(
      true,
    );
    expect(queryClient.getQueryState(queryKeys.security.fusion)?.isInvalidated).toBe(
      true,
    );
    expect(queryClient.getQueryState(queryKeys.security.baseline)?.isInvalidated).toBe(
      true,
    );
    expect(queryClient.getQueryState(queryKeys.security.attackCoverage)?.isInvalidated).toBe(
      true,
    );
    expect(queryClient.getQueryState(queryKeys.report.list)?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(queryKeys.report.exportHistory)?.isInvalidated).not.toBe(
      true,
    );
  });

  it("adds export-history refresh after proxy stop or drain", async () => {
    const queryClient = seededQueryClient();

    await invalidateLocalMetadataProxyRefreshQueries(queryClient);

    expect(queryClient.getQueryState(queryKeys.report.exportHistory)?.isInvalidated).toBe(
      true,
    );
    expect(
      queryClient.getQueryState(queryKeys.report.exportPolicyViolations)?.isInvalidated,
    ).toBe(true);
  });
});

function seededQueryClient() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  queryClient.setQueryData(["network", "flows", "default"], []);
  queryClient.setQueryData(
    ["graph", "view", "asset_exposure_graph", "overview"],
    { nodes: [], edges: [] },
  );
  queryClient.setQueryData(["security", "findings", "default"], []);
  queryClient.setQueryData(["security", "alerts", "default"], []);
  queryClient.setQueryData(["security", "incidents", "default"], []);
  queryClient.setQueryData(queryKeys.security.fusion, {});
  queryClient.setQueryData(queryKeys.security.baseline, {});
  queryClient.setQueryData(queryKeys.security.attackCoverage, {});
  queryClient.setQueryData(queryKeys.report.list, []);
  queryClient.setQueryData(queryKeys.report.exportHistory, []);
  queryClient.setQueryData(queryKeys.report.exportPolicyViolations, []);
  return queryClient;
}
