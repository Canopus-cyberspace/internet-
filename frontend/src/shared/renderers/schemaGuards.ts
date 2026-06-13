import type { JsonValue } from "../../bridge/dto/common";
import type { RendererContext, RendererValidationResult } from "./types";

const MAX_STRING_LENGTH = 160;
const MAX_ARRAY_ITEMS = 12;
const MAX_OBJECT_KEYS = 16;

const sensitiveMarkers = [
  "raw_packet",
  "packet_bytes",
  "raw_payload",
  "payload_blob",
  "http_body",
  "cookie",
  "session_token",
  "authorization",
  "api_key",
  "credential",
  "private_key",
  "password",
  "secret",
];

const canonicalGraphMarkers = [
  "canonical_node",
  "canonical_edge",
  "source_node",
  "target_node",
  "node_sequence",
  "adjacency",
];

export function valid(): RendererValidationResult {
  return { valid: true };
}

export function invalid(reasonRedacted: string): RendererValidationResult {
  return { valid: false, reasonRedacted };
}

export function validateSafeRendererContext(
  context: RendererContext,
): RendererValidationResult {
  const unsafe =
    findUnsafeMarker(context.data.value) ??
    (context.data.schema ? findUnsafeMarker(context.data.schema) : null);
  if (unsafe) {
    return invalid("renderer data contains a sensitive marker");
  }
  return valid();
}

export function validateGraphViewModelLike(
  context: RendererContext,
): RendererValidationResult {
  const unsafe =
    findUnsafeMarker(context.data.value) ??
    (context.data.schema ? findUnsafeMarker(context.data.schema) : null);
  if (unsafe) {
    return invalid("graph projection contains a sensitive marker");
  }

  const canonical = findCanonicalGraphMarker(context.data.value);
  if (canonical) {
    return invalid("graph renderer requires GraphViewModel or projection data");
  }

  const value = context.data.value;
  if (!isRecord(value)) {
    return invalid("graph renderer data must be an object");
  }

  const hasProjectionShape =
    Array.isArray(value.nodes) ||
    Array.isArray(value.edges) ||
    Array.isArray(value.paths);
  return hasProjectionShape
    ? valid()
    : invalid("graph projection data must include nodes, edges, or paths");
}

export function validateTableLike(context: RendererContext) {
  const value = context.data.value;
  if (Array.isArray(value) || isRecord(value)) {
    return validateSafeRendererContext(context);
  }
  return invalid("table renderer data must be an array or object");
}

export function isRecord(value: JsonValue | unknown): value is Record<string, JsonValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asRecordArray(value: JsonValue): Record<string, JsonValue>[] {
  if (Array.isArray(value)) {
    return value.filter(isRecord).slice(0, MAX_ARRAY_ITEMS);
  }

  if (isRecord(value)) {
    if (Array.isArray(value.rows)) {
      return value.rows.filter(isRecord).slice(0, MAX_ARRAY_ITEMS);
    }
    if (Array.isArray(value.items)) {
      return value.items.filter(isRecord).slice(0, MAX_ARRAY_ITEMS);
    }
    return [value];
  }

  return [];
}

export function safeEntries(value: JsonValue): [string, string][] {
  if (!isRecord(value)) {
    return [["value", stringifySafe(value)]];
  }

  return Object.entries(value)
    .slice(0, MAX_OBJECT_KEYS)
    .map(([key, nested]) => [key, stringifySafeForKey(key, nested)]);
}

export function stringifySafeForKey(key: string, value: JsonValue): string {
  if (isSensitiveKey(key)) {
    return "[redacted]";
  }
  return stringifySafe(value);
}

export function stringifySafe(value: JsonValue): string {
  if (value === null) {
    return "null";
  }

  if (typeof value === "string") {
    return redactString(value);
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  if (Array.isArray(value)) {
    return `${value.length} item${value.length === 1 ? "" : "s"}`;
  }

  return "object";
}

export function tableColumns(rows: Record<string, JsonValue>[]) {
  const keys = new Set<string>();
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      if (!isSensitiveKey(key)) {
        keys.add(key);
      }
      if (keys.size >= 6) {
        break;
      }
    }
  }
  return [...keys].slice(0, 6).map((key) => ({ key, label: humanize(key) }));
}

export function humanize(value: string) {
  return value
    .replace(/[_:.]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^./, (first) => first.toUpperCase());
}

export function isSensitiveKey(key: string) {
  const normalized = key.toLowerCase();
  return sensitiveMarkers.some((marker) => normalized.includes(marker));
}

function redactString(value: string) {
  const normalized = value.toLowerCase();
  if (sensitiveMarkers.some((marker) => normalized.includes(marker))) {
    return "[redacted]";
  }

  return value.length > MAX_STRING_LENGTH
    ? `${value.slice(0, MAX_STRING_LENGTH)}...`
    : value;
}

function findUnsafeMarker(value: JsonValue): string | null {
  return findMarker(value, sensitiveMarkers);
}

function findCanonicalGraphMarker(value: JsonValue): string | null {
  return findMarker(value, canonicalGraphMarkers);
}

function findMarker(value: JsonValue, markers: string[]): string | null {
  if (value === null) {
    return null;
  }

  if (typeof value === "string") {
    const normalized = value.toLowerCase();
    return markers.find((marker) => normalized.includes(marker)) ?? null;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return null;
  }

  if (Array.isArray(value)) {
    for (const item of value.slice(0, MAX_ARRAY_ITEMS)) {
      const marker = findMarker(item, markers);
      if (marker) {
        return marker;
      }
    }
    return null;
  }

  for (const [key, nested] of Object.entries(value).slice(0, MAX_OBJECT_KEYS)) {
    const normalized = key.toLowerCase();
    const keyMarker = markers.find((marker) => normalized.includes(marker));
    if (keyMarker) {
      return keyMarker;
    }
    const nestedMarker = findMarker(nested, markers);
    if (nestedMarker) {
      return nestedMarker;
    }
  }

  return null;
}
