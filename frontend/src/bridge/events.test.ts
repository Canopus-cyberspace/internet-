import { afterEach, describe, expect, it } from "vitest";
import {
  assertSafeStreamEnvelope,
  collectInvalidationKeys,
  type StreamEventEnvelope,
} from "./eventHandlers";
import { setListenCoreForTests, subscribeCoreEvents } from "./tauri/events";

describe("event streams", () => {
  afterEach(() => {
    setListenCoreForTests(null);
  });

  it("subscribes to all Task 220 Tauri stream names", async () => {
    const subscribed: string[] = [];
    const unlistened: string[] = [];
    setListenCoreForTests(async (event, handler) => {
      subscribed.push(event);
      handler({
        payload: envelope(event) as never,
      });
      return () => unlistened.push(event);
    });

    const received: StreamEventEnvelope[] = [];
    const unlisten = await subscribeCoreEvents((event) => received.push(event));
    unlisten();

    expect(subscribed).toEqual([
      "health_stream",
      "metric_stream",
      "capture_status_stream",
      "service_status_stream",
      "alert_stream",
      "incident_stream",
      "graph_update_stream",
      "response_status_stream",
      "report_progress_stream",
      "privacy_warning_stream",
    ]);
    expect(received).toHaveLength(10);
    expect(unlistened).toEqual(subscribed);
  });

  it("keeps invalidation hints compact and rejects unsafe markers", () => {
    const safe = envelope("graph_update_stream");
    expect(collectInvalidationKeys(safe)).toEqual([
      { queryKey: ["graph", "view", "incident_graph", "overview"], exact: true },
    ]);

    expect(() =>
      assertSafeStreamEnvelope({
        ...safe,
        redacted_summary: "raw_payload should not be streamed",
      }),
    ).toThrow(/Unsafe stream/);
  });
});

function envelope(eventName: string): StreamEventEnvelope {
  return {
    event_id: `${eventName}:event`,
    stream: streamName(eventName),
    event_type: eventName.replace("_stream", "_changed"),
    priority: eventName === "service_status_stream" ? "p0_critical" : "p2_normal",
    trace_id: `${eventName}:trace`,
    occurred_at: "2026-06-03T00:00:00Z",
    redacted_summary: `${eventName} changed`,
    invalidation_hints: [
      {
        query_key:
          eventName === "graph_update_stream"
            ? "graph.view:incident_graph:overview"
            : "platform.components",
        exact: true,
        reason_redacted: "stream changed",
      },
    ],
    body: { body_type: streamName(eventName), body: { summary_redacted: "changed" } },
  };
}

function streamName(eventName: string): StreamEventEnvelope["stream"] {
  return eventName.replace("_stream", "") as StreamEventEnvelope["stream"];
}
