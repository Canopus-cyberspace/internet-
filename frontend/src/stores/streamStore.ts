import { create } from "zustand";
import type { StreamEventEnvelope } from "../bridge/eventHandlers";

export type StatusLevel = "unknown" | "ok" | "degraded" | "critical";

interface StreamStore {
  connected: boolean;
  captureStatus: StatusLevel;
  serviceStatus: StatusLevel;
  attributionStatus: StatusLevel;
  riskStatus: StatusLevel;
  incidentCount: number;
  unreadAlertCount: number;
  privacyStatus: StatusLevel;
  activeResponseCount: number;
  lastEventId: string | null;
  lastEventAt: string | null;
  lastPulseAt: string | null;
  lastPulseEntityIds: string[];
  lastSummaryRedacted: string | null;
  setConnected: (connected: boolean) => void;
  resetUnreadAlertCount: () => void;
  applyEnvelope: (envelope: StreamEventEnvelope) => void;
}

export const useStreamStore = create<StreamStore>((set) => ({
  connected: false,
  captureStatus: "unknown",
  serviceStatus: "unknown",
  attributionStatus: "unknown",
  riskStatus: "unknown",
  incidentCount: 0,
  unreadAlertCount: 0,
  privacyStatus: "unknown",
  activeResponseCount: 0,
  lastEventId: null,
  lastEventAt: null,
  lastPulseAt: null,
  lastPulseEntityIds: [],
  lastSummaryRedacted: null,
  setConnected: (connected) => set({ connected }),
  resetUnreadAlertCount: () => set({ unreadAlertCount: 0 }),
  applyEnvelope: (envelope) =>
    set((state) => {
      const feedback = feedbackForEnvelope(envelope);
      const critical = envelope.priority === "p0_critical";
      const degraded = envelope.priority === "p1_high";
      const level: StatusLevel = critical
        ? "critical"
        : degraded
          ? "degraded"
          : "ok";

      if (envelope.stream === "service_status") {
        return {
          ...feedback,
          serviceStatus: level,
          lastEventAt: envelope.occurred_at,
          lastSummaryRedacted: envelope.redacted_summary,
        };
      }

      if (envelope.stream === "capture_status") {
        return {
          ...feedback,
          captureStatus: level,
          lastEventAt: envelope.occurred_at,
          lastSummaryRedacted: envelope.redacted_summary,
        };
      }

      if (envelope.stream === "alert") {
        return {
          ...feedback,
          riskStatus: level,
          unreadAlertCount: state.unreadAlertCount + 1,
          lastEventAt: envelope.occurred_at,
          lastSummaryRedacted: envelope.redacted_summary,
        };
      }

      if (envelope.stream === "incident") {
        return {
          ...feedback,
          riskStatus: level,
          incidentCount: state.incidentCount + 1,
          lastEventAt: envelope.occurred_at,
          lastSummaryRedacted: envelope.redacted_summary,
        };
      }

      if (envelope.stream === "privacy_warning") {
        return {
          ...feedback,
          privacyStatus: level,
          lastEventAt: envelope.occurred_at,
          lastSummaryRedacted: envelope.redacted_summary,
        };
      }

      if (envelope.stream === "response_status") {
        const isNewResponse =
          envelope.event_type === "response_plan_created" ||
          envelope.event_type === "response_approval_required" ||
          envelope.event_type === "response_action_started";
        const isClosedResponse =
          envelope.event_type === "response_completed" ||
          envelope.event_type === "response_rollback_completed";
        return {
          ...feedback,
          activeResponseCount: isNewResponse
            ? state.activeResponseCount + 1
            : isClosedResponse
              ? Math.max(0, state.activeResponseCount - 1)
              : state.activeResponseCount,
          lastEventAt: envelope.occurred_at,
          lastSummaryRedacted: envelope.redacted_summary,
        };
      }

      return {
        ...feedback,
        lastEventAt: envelope.occurred_at,
        lastSummaryRedacted: envelope.redacted_summary,
      };
    }),
}));

function feedbackForEnvelope(envelope: StreamEventEnvelope) {
  return {
    lastEventId: envelope.event_id,
    lastPulseAt: envelope.occurred_at,
    lastPulseEntityIds: collectPulseEntityIds(envelope),
  };
}

function collectPulseEntityIds(envelope: StreamEventEnvelope) {
  const ids = new Set<string>();
  addPulseId(ids, envelope.event_id);
  addPulseId(ids, envelope.trace_id);
  addPulseId(ids, envelope.event_type);
  for (const hint of envelope.invalidation_hints) {
    addPulseId(ids, hint.query_key);
  }
  collectPulseIdsFromBody(envelope.body, ids, 0);
  return [...ids].slice(0, 32);
}

function collectPulseIdsFromBody(value: unknown, ids: Set<string>, depth: number) {
  if (depth > 3 || value === null || value === undefined) {
    return;
  }
  if (typeof value === "string") {
    addPulseId(ids, value);
    return;
  }
  if (typeof value !== "object") {
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 16)) {
      collectPulseIdsFromBody(item, ids, depth + 1);
    }
    return;
  }
  for (const [key, nested] of Object.entries(value).slice(0, 32)) {
    if (!isPulseSafeKey(key)) {
      continue;
    }
    const normalized = key.toLowerCase();
    if (
      typeof nested === "string" &&
      (normalized.endsWith("_id") ||
        normalized.endsWith("_ref") ||
        normalized === "id" ||
        normalized === "entity_ref")
    ) {
      addPulseId(ids, nested);
    } else {
      collectPulseIdsFromBody(nested, ids, depth + 1);
    }
  }
}

function addPulseId(ids: Set<string>, value: string) {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.length <= 128) {
    ids.add(trimmed);
  }
}

const forbiddenPulseKeyMarkers = [
  "raw",
  "payload",
  "packet",
  "body",
  "cookie",
  "token",
  "credential",
  "secret",
  "private_key",
  "authorization",
  "api_key",
];

function isPulseSafeKey(key: string) {
  const normalized = key.toLowerCase();
  return !forbiddenPulseKeyMarkers.some((marker) => normalized.includes(marker));
}
