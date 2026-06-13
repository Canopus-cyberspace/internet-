import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { queryKeys } from "../../../bridge/queryKeys";
import {
  buildLocalMetadataProxyStartRequest,
  LocalMetadataProxyPanel,
} from "./LocalMetadataProxyPanel";

describe("Local metadata proxy panel", () => {
  it("renders only bounded proxy status and operator guidance", () => {
    const markup = renderToStaticMarkup(
      withQueryClient(<LocalMetadataProxyPanel />, (queryClient) => {
        queryClient.setQueryData(queryKeys.network.localMetadataProxy, {
          state: "degraded",
          listen_host: "127.0.0.1",
          listen_port: 43129,
          requests_captured: 3,
          requests_rejected: 1,
          dropped_batches: 0,
          pending_batches: 1,
          pending_event_count: 6,
          drained_event_count: 18,
          last_capture_at: "2026-06-11T00:00:00Z",
          last_error_code: "queue_backpressure",
          localhost_only: true,
          metadata_only: true,
          message_redacted:
            "Localhost metadata proxy is running on 127.0.0.1:43129 with rejected or dropped requests; metadata-only mode remains active",
        });
      }),
    );

    expect(markup).toContain("Local metadata proxy");
    expect(markup).toContain("127.0.0.1");
    expect(markup).toContain("43129");
    expect(markup).toContain("Queued events");
    expect(markup).toContain("Drained events");
    expect(markup).toContain("metadata only / no raw retention");
    expect(markup).toContain("queue backpressure");
    expect(markup).toContain("client, browser, or tool");
    expect(markup).toContain("requests are not forwarded");
    expect(markup).not.toContain("packet capture");
    expect(markup).not.toContain("full-machine capture");
    expect(markup).not.toContain("https://secret.example.test/private/path");
    expect(markup).not.toContain("authorization:");
  });

  it("accepts only blank or bounded numeric port requests", () => {
    expect(buildLocalMetadataProxyStartRequest("")).toEqual({ listen_port: null });
    expect(buildLocalMetadataProxyStartRequest("8080")).toEqual({ listen_port: 8080 });
    expect(buildLocalMetadataProxyStartRequest("0")).toBeNull();
    expect(buildLocalMetadataProxyStartRequest("70000")).toBeNull();
    expect(buildLocalMetadataProxyStartRequest("abc")).toBeNull();
  });
});

function withQueryClient(
  element: ReactElement,
  seed?: (queryClient: QueryClient) => void,
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  seed?.(queryClient);
  return <QueryClientProvider client={queryClient}>{element}</QueryClientProvider>;
}
