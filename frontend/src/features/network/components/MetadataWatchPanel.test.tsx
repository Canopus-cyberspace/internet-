import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { queryKeys } from "../../../bridge/queryKeys";
import { MetadataWatchPanel } from "./MetadataWatchPanel";

describe("Metadata watch panel", () => {
  it("renders bounded source health and sampling summaries", () => {
    const markup = renderToStaticMarkup(
      withQueryClient(<MetadataWatchPanel />, (queryClient) => {
        queryClient.setQueryData(queryKeys.network.metadataWatchStatus, {
          generated_at: "2026-06-12T00:00:00Z",
          scheduler_mode: "background_sampling_loop",
          running: true,
          loop_state: "running",
          loop_enabled: true,
          loop_paused: false,
          scheduled_source_count: 1,
          max_sources_per_cycle: 8,
          max_concurrent_sources: 1,
          max_files_per_tick: 8,
          per_source_timeout_millis: 5000,
          enabled_source_count: 1,
          active_source_count: 1,
          paused_source_count: 0,
          degraded_source_count: 0,
          revoked_source_count: 0,
          backpressure_source_count: 0,
          total_sampled_record_count: 6,
          total_duplicate_record_count: 1,
          total_malformed_record_count: 0,
          total_backpressure_drop_count: 0,
          last_tick_at: "2026-06-12T00:00:05Z",
          last_scheduled_at: "2026-06-12T00:00:05Z",
          graceful_shutdown_requested: false,
          latest_batch_id: "batch-123456789",
          latest_checkpoint_id: "checkpoint-1",
          latest_provenance_id: "provenance-1",
          fusion_refresh_count: 1,
          report_refresh_marker_count: 1,
          attack_refresh_marker_count: 1,
          triage_advisory_only: true,
          automatic_llm_calls: false,
          response_execution: false,
          privacy_class: "internal",
        });
        queryClient.setQueryData(queryKeys.network.metadataWatchSources, {
          items: [
            {
              source_id: "source-1234",
              source_kind: "localhost_proxy_continuous_drain",
              state: "active",
              health_state: "active",
              sampling_mode: "continuous_drain",
              interval_seconds: 5,
              max_records_per_tick: 500,
              max_bytes_per_tick: 64000,
              parser_family: "local_proxy_metadata",
              redaction_policy: "metadata_redaction_v1",
              retention_mode: "no_retention",
              checkpoint: {
                checkpoint_id: "checkpoint-1",
                source_id: "source-1234",
                source_kind: "localhost_proxy_continuous_drain",
                safe_cursor_bucket: "batch_bucket_1",
                safe_generation_hash:
                  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                sampled_time_bucket: "2026-06-12T00:00:05Z",
                handoff_time_bucket: "2026-06-12T00:00:06Z",
                parser_schema_version: "local_proxy_metadata:v1",
                redaction_schema_version: "redaction:v1",
                health_state: "active",
                provenance_id: "provenance-1",
              },
              counters: {
                sampled_record_count: 6,
                sampled_byte_count: 0,
                skipped_record_count: 0,
                malformed_record_count: 0,
                duplicate_record_count: 1,
                backpressure_drop_count: 0,
                batch_count: 1,
              },
              last_sampled_at: "2026-06-12T00:00:05Z",
              last_ingested_at: "2026-06-12T00:00:06Z",
              degraded_reason: null,
              error_category: null,
              provenance_id: "provenance-1",
              privacy_boundary: "portable_no_retention_metadata_only",
              portable_default_available: true,
              sampler_ids: ["watch_source_redacted"],
              fact_count: 2,
              hypothesis_count: 1,
              finding_count: 1,
              evidence_refs: ["evidence-1"],
            },
          ],
          limit: 50,
          cursor: null,
          next_cursor: null,
          has_more: false,
        });
        queryClient.setQueryData(queryKeys.network.metadataSamplingBatches, {
          items: [
            {
              batch_id: "batch-123456789",
              source_id: "source-1234",
              source_kind: "localhost_proxy_continuous_drain",
              parser_family: "local_proxy_metadata",
              started_at: "2026-06-12T00:00:05Z",
              completed_at: "2026-06-12T00:00:06Z",
              health_state: "active",
              sampled_record_count: 6,
              sampled_byte_count: 0,
              skipped_record_count: 0,
              malformed_record_count: 0,
              duplicate_record_count: 1,
              backpressure_drop_count: 0,
              emitted_topics: ["network.http.metadata", "security.fact"],
              fact_refs: ["fact-1"],
              evidence_refs: ["evidence-1"],
              finding_refs: ["finding-1"],
              risk_refs: ["risk-1"],
              report_refresh_marker: true,
              attack_refresh_marker: true,
              story_available_marker: true,
              triage_advisory_only: true,
              automatic_llm_calls: false,
              response_execution: false,
            },
          ],
          limit: 50,
          cursor: null,
          next_cursor: null,
          has_more: false,
        });
      }),
    );

    expect(markup).toContain("AutoSecOps watch");
    expect(markup).toContain("Portable Default samples metadata only");
    expect(markup).toContain("No-retention mode");
    expect(markup).toContain("Sampling loop");
    expect(markup).toContain("Run cycle");
    expect(markup).toContain("localhost proxy continuous drain");
    expect(markup).toContain("local proxy metadata");
    expect(markup).toContain("checkpoint");
    expect(markup).toContain("6 sampled");
    expect(markup).toContain("1 evidence refs");
    expect(markup).toContain("story available");
    expect(markup).not.toContain("https://secret.example.test/private/path");
    expect(markup).not.toContain("session_token");
    expect(markup).not.toContain("alice@example");
    expect(markup).not.toContain("C:\\Users");
    expect(markup).not.toContain("authorization:");
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
