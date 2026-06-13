import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import {
  buildPortableCapturePreviewRequest,
  portableCaptureSourceTypeForPath,
  PortableCaptureImportPreviewSummary,
  PortableCaptureImportResultSummary,
} from "./PortableCaptureImportPanel";

describe("Portable capture import panel", () => {
  it("renders only sanitized preview metadata", () => {
    const markup = renderToStaticMarkup(
      <PortableCaptureImportPreviewSummary
        preview={{
          preview_id: "preview-redacted",
          provenance: {
            provenance_id: "prov-redacted",
            source_type: "imported_har",
            record_counts: {
              flow_records: 4,
              session_records: 2,
              dns_records: 1,
              tls_records: 1,
              http_metadata_records: 4,
              auth_metadata_records: 0,
              saas_cloud_metadata_records: 0,
              deception_event_records: 0,
            },
            redaction_status: "redacted",
          },
          declared_topics: [
            "network.flow.record",
            "security.finding",
            "security.alert",
          ],
          generated_at: "2026-06-11T00:00:00Z",
        }}
      />,
    );

    expect(markup).toContain("HAR metadata");
    expect(markup).toContain("prov-redacted");
    expect(markup).toContain("redacted");
    expect(markup).toContain("Flows");
    expect(markup).toContain(">4<");
    expect(markup).toContain("Declared topics");
    expect(markup).not.toContain("capture.har");
    expect(markup).not.toContain("C:/Users/Alice/Desktop");
    expect(markup).not.toContain("token=secret");
  });

  it("renders only sanitized confirmed import summaries", () => {
    const markup = renderToStaticMarkup(
      <PortableCaptureImportResultSummary
        result={{
          preview_id: "preview-redacted",
          provenance: {
            provenance_id: "prov-redacted",
            source_type: "imported_jsonl_network_metadata",
            record_counts: {
              flow_records: 2,
              session_records: 2,
              dns_records: 1,
              tls_records: 1,
              http_metadata_records: 2,
              auth_metadata_records: 0,
              saas_cloud_metadata_records: 0,
              deception_event_records: 0,
            },
            redaction_status: "redacted",
          },
          emitted_topics: [
            "network.flow.record",
            "network.dns.observation",
            "network.tls.observation",
            "network.http_metadata",
            "graph.hint",
            "security.finding",
            "security.alert",
          ],
          flow_count: 2,
          session_count: 2,
          dns_count: 1,
          tls_count: 1,
          http_metadata_count: 2,
          auth_metadata_count: 0,
          auth_summary: null,
          saas_cloud_metadata_count: 0,
          saas_cloud_summary: null,
          deception_event_count: 0,
          deception_summary: null,
          security_fact_count: 3,
          attack_hypothesis_count: 1,
          finding_count: 1,
          alert_candidate_count: 1,
          alert_count: 1,
          incident_candidate_count: 0,
          incident_count: 0,
          incident_ids: [],
          report_traceability_ready: true,
        }}
      />,
    );

    expect(markup).toContain('data-summary="result"');
    expect(markup).toContain("JSONL metadata");
    expect(markup).toContain("prov-redacted");
    expect(markup).toContain("Graph hints");
    expect(markup).toContain("present");
    expect(markup).toContain("HTTP");
    expect(markup).toContain("Report traceability");
    expect(markup).toContain("ready");
    expect(markup).not.toContain("network.jsonl");
    expect(markup).not.toContain("jsonl.example.test/upload/9");
    expect(markup).not.toContain("token=abcdef1234567890");
    expect(markup).not.toContain("Alice");
  });

  it("accepts only one supported portable import path", () => {
    expect(portableCaptureSourceTypeForPath("C:/drop/network.HAR")).toBe(
      "imported_har",
    );
    expect(portableCaptureSourceTypeForPath("C:/drop/network.jsonl")).toBe(
      "imported_jsonl_network_metadata",
    );
    expect(portableCaptureSourceTypeForPath("C:/drop/idp-auth.jsonl")).toBe(
      "imported_auth_security_log",
    );
    expect(portableCaptureSourceTypeForPath("C:/drop/cloud-provider.jsonl")).toBe(
      "imported_saas_cloud_metadata",
    );
    expect(portableCaptureSourceTypeForPath("C:/drop/rdp-decoy.jsonl")).toBe(
      "imported_deception_event_log",
    );
    expect(portableCaptureSourceTypeForPath("C:/drop/network.pcapng")).toBeNull();
    expect(
      buildPortableCapturePreviewRequest(["C:/drop/network.har", "C:/drop/extra.jsonl"]),
    ).toBeNull();
    expect(buildPortableCapturePreviewRequest(["C:/drop/network.jsonl"])).toEqual({
      source_path: "C:/drop/network.jsonl",
      source_type: "imported_jsonl_network_metadata",
    });
  });
});
