import { describe, expect, it } from "vitest";
import { mapCoreError } from "./errors";

describe("Core error mapping", () => {
  it("maps required Rust Core error codes to frontend kinds", () => {
    expect(mapCoreError({ error_code: "permission_denied" }).kind).toBe(
      "permission",
    );
    expect(mapCoreError({ error_code: "service_unavailable" }).kind).toBe(
      "service",
    );
    expect(mapCoreError({ error_code: "schema_mismatch" }).kind).toBe("schema");
    expect(mapCoreError({ error_code: "privacy_policy_violation" }).kind).toBe(
      "privacy",
    );
    expect(mapCoreError({ error_code: "response_requires_approval" }).kind).toBe(
      "approval",
    );
    expect(mapCoreError({ error_code: "response_denied_by_policy" }).kind).toBe(
      "policy",
    );
  });

  it("normalizes unknown codes and keeps trace fields redacted", () => {
    const mapped = mapCoreError({
      error_code: "backend_new_code",
      message: "new backend shape",
      severity: "critical",
      retryable: true,
      trace_id: "trace-redacted",
      audit_ref: "audit-redacted",
      details_redacted: { reason: "safe summary" },
    });

    expect(mapped.code).toBe("unknown");
    expect(mapped.kind).toBe("unknown");
    expect(mapped.severity).toBe("critical");
    expect(mapped.retryable).toBe(true);
    expect(mapped.traceId).toBe("trace-redacted");
    expect(mapped.auditRef).toBe("audit-redacted");
    expect(mapped.detailsRedacted).toEqual({ reason: "safe summary" });
  });

  it("removes unsafe markers from messages and details", () => {
    const mapped = mapCoreError({
      error_code: "privacy_policy_violation",
      message: "raw_payload marker should never reach UI",
      details_redacted: {
        payload_blob: "not allowed even in redacted error details",
      },
    });

    expect(mapped.message).toBe(
      "Rust Core error details were redacted by privacy policy",
    );
    expect(mapped.detailsRedacted).toBeNull();
  });
});
