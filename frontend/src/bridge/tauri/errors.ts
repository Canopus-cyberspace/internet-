import type { JsonValue } from "../dto/common";

export type CoreErrorCode =
  | "permission_denied"
  | "service_unavailable"
  | "schema_mismatch"
  | "privacy_policy_violation"
  | "policy_denial"
  | "validation_failure"
  | "storage_unavailable"
  | "unsupported_operation"
  | "response_requires_approval"
  | "response_denied_by_policy"
  | "invalid_request"
  | "timeout"
  | "rate_limited"
  | "internal_error"
  | "unknown";

export type CoreErrorSeverity = "info" | "warning" | "error" | "critical";

export interface CoreErrorDto {
  error_code?: CoreErrorCode | string;
  message?: string;
  severity?: CoreErrorSeverity | string;
  retryable?: boolean;
  trace_id?: string | null;
  audit_ref?: string | null;
  details_redacted?: JsonValue | null;
}

export type CoreErrorKind =
  | "permission"
  | "service"
  | "schema"
  | "privacy"
  | "approval"
  | "policy"
  | "validation"
  | "storage"
  | "unsupported"
  | "rate_limit"
  | "timeout"
  | "internal"
  | "unknown";

export class FrontendCoreError extends Error {
  readonly code: CoreErrorCode;
  readonly kind: CoreErrorKind;
  readonly severity: CoreErrorSeverity;
  readonly retryable: boolean;
  readonly traceId: string | null;
  readonly auditRef: string | null;
  readonly detailsRedacted: JsonValue | null;

  constructor(dto: Required<CoreErrorDto>, kind: CoreErrorKind) {
    super(dto.message);
    this.name = "FrontendCoreError";
    this.code = normalizeCode(dto.error_code);
    this.kind = kind;
    this.severity = normalizeSeverity(dto.severity);
    this.retryable = dto.retryable;
    this.traceId = dto.trace_id;
    this.auditRef = dto.audit_ref;
    this.detailsRedacted = dto.details_redacted;
  }
}

export function mapCoreError(error: unknown): FrontendCoreError {
  const dto = toCoreErrorDto(error);
  const complete = {
    error_code: normalizeCode(dto.error_code),
    message: sanitizeErrorMessage(dto.message ?? "Rust Core command failed"),
    severity: normalizeSeverity(dto.severity),
    retryable: Boolean(dto.retryable),
    trace_id: dto.trace_id ?? null,
    audit_ref: dto.audit_ref ?? null,
    details_redacted: sanitizeDetailsRedacted(dto.details_redacted ?? null),
  } satisfies Required<CoreErrorDto>;

  return new FrontendCoreError(complete, mapErrorKind(complete.error_code));
}

function toCoreErrorDto(error: unknown): CoreErrorDto {
  if (isCoreErrorDto(error)) {
    return error;
  }

  if (error instanceof Error) {
    return {
      error_code: "unknown",
      message: error.message,
      severity: "error",
      retryable: false,
    };
  }

  if (typeof error === "string") {
    return {
      error_code: "unknown",
      message: error,
      severity: "error",
      retryable: false,
    };
  }

  return {
    error_code: "unknown",
    message: "Unknown Rust Core error",
    severity: "error",
    retryable: false,
  };
}

function isCoreErrorDto(error: unknown): error is CoreErrorDto {
  return typeof error === "object" && error !== null && "error_code" in error;
}

function normalizeCode(code: unknown): CoreErrorCode {
  if (typeof code !== "string") {
    return "unknown";
  }
  return knownCoreErrorCodes.has(code as CoreErrorCode)
    ? (code as CoreErrorCode)
    : "unknown";
}

function normalizeSeverity(severity: unknown): CoreErrorSeverity {
  return severity === "info" ||
    severity === "warning" ||
    severity === "critical"
    ? severity
    : "error";
}

function mapErrorKind(code: CoreErrorCode): CoreErrorKind {
  switch (code) {
    case "permission_denied":
      return "permission";
    case "service_unavailable":
      return "service";
    case "schema_mismatch":
      return "schema";
    case "privacy_policy_violation":
      return "privacy";
    case "response_requires_approval":
      return "approval";
    case "policy_denial":
    case "response_denied_by_policy":
      return "policy";
    case "validation_failure":
    case "invalid_request":
      return "validation";
    case "storage_unavailable":
      return "storage";
    case "unsupported_operation":
      return "unsupported";
    case "rate_limited":
      return "rate_limit";
    case "timeout":
      return "timeout";
    case "internal_error":
      return "internal";
    default:
      return "unknown";
  }
}

const knownCoreErrorCodes = new Set<CoreErrorCode>([
  "permission_denied",
  "service_unavailable",
  "schema_mismatch",
  "privacy_policy_violation",
  "policy_denial",
  "validation_failure",
  "storage_unavailable",
  "unsupported_operation",
  "response_requires_approval",
  "response_denied_by_policy",
  "invalid_request",
  "timeout",
  "rate_limited",
  "internal_error",
  "unknown",
]);

const forbiddenErrorMarkers = [
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

function sanitizeErrorMessage(message: string) {
  return containsForbiddenMarker(message)
    ? "Rust Core error details were redacted by privacy policy"
    : message;
}

function sanitizeDetailsRedacted(details: JsonValue | null) {
  return details && jsonContainsForbiddenMarker(details) ? null : details;
}

function jsonContainsForbiddenMarker(value: JsonValue): boolean {
  if (typeof value === "string") {
    return containsForbiddenMarker(value);
  }

  if (Array.isArray(value)) {
    return value.some(jsonContainsForbiddenMarker);
  }

  if (value && typeof value === "object") {
    return Object.entries(value).some(
      ([key, child]) =>
        containsForbiddenMarker(key) || jsonContainsForbiddenMarker(child),
    );
  }

  return false;
}

function containsForbiddenMarker(value: string) {
  const normalized = value.toLowerCase();
  return forbiddenErrorMarkers.some((marker) => normalized.includes(marker));
}
