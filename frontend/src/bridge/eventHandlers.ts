import type { QueryClient } from "@tanstack/react-query";
import { queryKeyFromCoreHint, type QueryKey } from "./queryKeys";

export type StreamPriority =
  | "p0_critical"
  | "p1_high"
  | "p2_normal"
  | "p3_low"
  | "p4_best_effort"
  | "p5_ui_refresh";

export type StreamName =
  | "health"
  | "metric"
  | "capture_status"
  | "service_status"
  | "alert"
  | "incident"
  | "graph_update"
  | "response_status"
  | "report_progress"
  | "privacy_warning";

export interface QueryInvalidationHint {
  query_key: string;
  exact: boolean;
  reason_redacted: string;
}

export interface StreamEventEnvelope {
  event_id: string;
  stream: StreamName;
  event_type: string;
  priority: StreamPriority;
  trace_id: string;
  occurred_at: string;
  redacted_summary: string;
  invalidation_hints: QueryInvalidationHint[];
  body: unknown;
}

export function collectInvalidationKeys(envelope: StreamEventEnvelope) {
  assertSafeStreamEnvelope(envelope);
  return envelope.invalidation_hints.slice(0, 8).map((hint) => ({
    queryKey: queryKeyFromCoreHint(hint.query_key),
    exact: hint.exact,
  }));
}

export function isCriticalStreamEvent(envelope: StreamEventEnvelope) {
  return envelope.priority === "p0_critical";
}

export async function invalidateQueriesForEnvelope(
  queryClient: QueryClient,
  envelope: StreamEventEnvelope,
) {
  const hints = collectInvalidationKeys(envelope);
  await Promise.all(
    hints.map((hint) =>
      queryClient.invalidateQueries({
        queryKey: hint.queryKey as QueryKey,
        exact: hint.exact,
      }),
    ),
  );
}

export function assertSafeStreamEnvelope(envelope: StreamEventEnvelope) {
  assertSafeStreamText("event_type", envelope.event_type);
  assertSafeStreamText("redacted_summary", envelope.redacted_summary);
  for (const hint of envelope.invalidation_hints) {
    assertSafeStreamText("query_key", hint.query_key);
    assertSafeStreamText("reason_redacted", hint.reason_redacted);
  }
}

const forbiddenStreamMarkers = [
  "raw_packet",
  "raw_payload",
  "packet_bytes",
  "payload_blob",
  "http_body",
  "cookie_value",
  "session_token",
  "authorization_header_value",
  "api_key_value",
  "credential_value",
  "private_key_value",
];

function assertSafeStreamText(field: string, value: string) {
  const normalized = value.toLowerCase();
  if (forbiddenStreamMarkers.some((marker) => normalized.includes(marker))) {
    throw new Error(`Unsafe stream ${field} marker was rejected`);
  }
}
