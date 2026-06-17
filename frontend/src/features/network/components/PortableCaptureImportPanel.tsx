import { getCurrentWindow } from "@tauri-apps/api/window";
import { AlertTriangle, CheckCircle, ShieldCheck, Upload } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import type {
  PortableAuthSummaryDto,
  PortableCaptureImportFileRequestDto,
  PortableCaptureImportPreviewDto,
  PortableCaptureImportResultDto,
  PortableCaptureInputSourceTypeDto,
  PortableCaptureRecordCountsDto,
  PortableDeceptionSummaryDto,
  PortableSaasCloudSummaryDto,
  RedactionStatusDto,
} from "../../../bridge/dto/network";
import { confirmPortableCaptureImport } from "../api";
import {
  useConfirmPortableCaptureImportMutation,
  usePreviewPortableCaptureImportMutation,
} from "../hooks";

const LOCAL_OPERATOR = "local operator";
const IMPORT_CONFIRM_REASON = "portable metadata import confirmed";
const IMPORT_CANCEL_REASON = "portable metadata import preview cancelled";

interface PortableImportSmokeWindow extends Window {
  __SENTINEL_SMOKE__?: {
    portableImportDropPaths?: ((paths: string[]) => void) | undefined;
  };
}

export function PortableCaptureImportPanel() {
  const previewMutation = usePreviewPortableCaptureImportMutation();
  const confirmMutation = useConfirmPortableCaptureImportMutation();
  const [dropActive, setDropActive] = useState(false);
  const [preview, setPreview] = useState<PortableCaptureImportPreviewDto | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const handleDroppedPaths = useCallback(
    (paths: string[]) => {
      if (previewMutation.isPending || confirmMutation.isPending) {
        setNotice("Wait for the current portable preview or ingest to finish.");
        return;
      }

      const request = buildPortableCapturePreviewRequest(paths);
      if (!request) {
        setNotice("Drop exactly one .har or .jsonl file to preview portable metadata.");
        return;
      }

      if (preview) {
        void discardPortableCapturePreview(preview.preview_id);
      }

      setNotice(null);
      setConfirmed(false);
      setPreview(null);
      previewMutation.reset();
      confirmMutation.reset();
      previewMutation.mutate(request, {
        onSuccess: (nextPreview) => {
          setPreview(nextPreview);
        },
      });
    },
    [confirmMutation, preview, previewMutation],
  );

  usePortableCaptureWindowDrop({
    onDropPaths: handleDroppedPaths,
    onDropStateChange: setDropActive,
  });

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const smokeWindow = window as PortableImportSmokeWindow;
    const nextSmokeState = {
      ...(smokeWindow.__SENTINEL_SMOKE__ ?? {}),
      portableImportDropPaths: handleDroppedPaths,
    };
    smokeWindow.__SENTINEL_SMOKE__ = nextSmokeState;

    return () => {
      const currentSmokeState = smokeWindow.__SENTINEL_SMOKE__;
      if (!currentSmokeState) {
        return;
      }

      if (currentSmokeState.portableImportDropPaths === handleDroppedPaths) {
        delete currentSmokeState.portableImportDropPaths;
      }
      if (!currentSmokeState.portableImportDropPaths) {
        delete smokeWindow.__SENTINEL_SMOKE__;
      }
    };
  }, [handleDroppedPaths]);

  useEffect(() => {
    return () => {
      if (preview?.preview_id) {
        void discardPortableCapturePreview(preview.preview_id);
      }
    };
  }, [preview?.preview_id]);

  const confirmDisabled =
    !preview || !confirmed || previewMutation.isPending || confirmMutation.isPending;
  const ingestResult = confirmMutation.data?.result ?? null;

  return (
    <section className="analysis-panel network-import-panel">
      <div className="analysis-panel-header">
        <strong>Import Network Metadata</strong>
        <Upload size={15} aria-hidden="true" />
      </div>
      <div className="network-import-body">
        <div className="response-callout" data-tone={dropActive ? "ok" : "warning"}>
          {dropActive ? (
            <CheckCircle size={15} aria-hidden="true" />
          ) : (
            <ShieldCheck size={15} aria-hidden="true" />
          )}
          <span>
            {dropActive
              ? "Release to preview one portable HAR or JSONL metadata file."
              : "Drop one .har or .jsonl file into this window to preview sanitized metadata only."}
          </span>
        </div>
        <div className="network-import-dropzone" data-active={dropActive}>
          <Upload size={18} aria-hidden="true" />
          <strong>Portable preview only</strong>
          <span>
            The preview shows source type, bounded counts, redaction status, and
            provenance only.
          </span>
          <small>
            No paths, filenames, URLs, headers, cookies, tokens, usernames, or
            raw content are rendered.
          </small>
        </div>
        {previewMutation.isPending ? (
          <div className="response-callout" data-tone="ok">
            <ShieldCheck size={15} aria-hidden="true" />
            <span>Building a sanitized portable import preview.</span>
          </div>
        ) : null}
        {preview ? <PortableCaptureImportPreviewSummary preview={preview} /> : null}
        <label className="response-check-row">
          <input
            checked={confirmed}
            disabled={!preview || previewMutation.isPending || confirmMutation.isPending}
            type="checkbox"
            onChange={(event) => setConfirmed(event.currentTarget.checked)}
          />
          <span>This redacted preview is approved for metadata ingest</span>
        </label>
        <div className="explicit-export-confirm-row">
          <button
            className="toolbar-button"
            disabled={confirmDisabled}
            title="Ingest only after explicit confirmation"
            type="button"
            onClick={() => {
              if (!preview) {
                return;
              }
              setNotice(null);
              confirmMutation.mutate(
                {
                  preview_id: preview.preview_id,
                  user_confirmed: true,
                  reason_redacted: IMPORT_CONFIRM_REASON,
                  requested_by_redacted: LOCAL_OPERATOR,
                },
                {
                  onSuccess: () => {
                    setPreview(null);
                    setConfirmed(false);
                    setNotice("Portable metadata imported and command-backed views refreshed.");
                  },
                },
              );
            }}
          >
            <ShieldCheck size={14} aria-hidden="true" />
            Confirm Ingest
          </button>
          <button
            className="toolbar-button"
            disabled={!preview || previewMutation.isPending || confirmMutation.isPending}
            title="Discard the preview without ingesting metadata"
            type="button"
            onClick={() => {
              if (!preview) {
                return;
              }
              const activePreviewId = preview.preview_id;
              setNotice(null);
              void discardPortableCapturePreview(activePreviewId).finally(() => {
                setPreview((currentPreview) =>
                  currentPreview?.preview_id === activePreviewId ? null : currentPreview,
                );
                setConfirmed(false);
                previewMutation.reset();
                confirmMutation.reset();
                setNotice("Preview cancelled; no metadata was ingested.");
              });
            }}
          >
            <AlertTriangle size={14} aria-hidden="true" />
            Cancel Preview
          </button>
        </div>
        {ingestResult ? <PortableCaptureImportResultSummary result={ingestResult} /> : null}
        {previewMutation.isError || confirmMutation.isError ? (
          <div className="response-callout">
            <AlertTriangle size={15} aria-hidden="true" />
            <span>Portable import returned a redacted error.</span>
          </div>
        ) : null}
        {notice ? <span className="analysis-muted">{notice}</span> : null}
      </div>
    </section>
  );
}

export function PortableCaptureImportPreviewSummary({
  preview,
}: {
  readonly preview: PortableCaptureImportPreviewDto;
}) {
  const counts = preview.provenance.record_counts;
  return (
    <div className="network-import-preview" data-summary="preview">
      <div className="network-import-preview-grid">
        <ImportStatusBadge
          label="Source type"
          value={portableCaptureSourceLabel(preview.provenance.source_type)}
          tone="neutral"
        />
        <ImportStatusBadge
          label="Provenance"
          value={preview.provenance.provenance_id}
          tone="neutral"
        />
        <ImportStatusBadge
          label="Redaction"
          value={portableCaptureRedactionLabel(preview.provenance.redaction_status)}
          tone={portableCaptureRedactionTone(preview.provenance.redaction_status)}
        />
        <ImportStatusBadge
          label="Declared topics"
          value={`${preview.declared_topics.length}`}
          tone="neutral"
        />
      </div>
      <div className="network-import-count-grid">
        {portableCaptureCountItems(counts).map((item) => (
          <ImportStatusBadge
            key={item.label}
            label={item.label}
            value={`${item.value}`}
            tone="neutral"
          />
        ))}
      </div>
    </div>
  );
}

export function PortableCaptureImportResultSummary({
  result,
}: {
  readonly result: PortableCaptureImportResultDto;
}) {
  const counts = portableCaptureImportResultCountItems(result);
  return (
    <div className="network-import-preview" data-summary="result">
      <div className="network-import-preview-grid">
        <ImportStatusBadge
          label="Source type"
          value={portableCaptureSourceLabel(result.provenance.source_type)}
          tone="neutral"
        />
        <ImportStatusBadge
          label="Provenance"
          value={result.provenance.provenance_id}
          tone="neutral"
        />
        <ImportStatusBadge
          label="Graph hints"
          value={portableCaptureGraphHintLabel(result)}
          tone={portableCaptureGraphHintTone(result)}
        />
        <ImportStatusBadge
          label="Report traceability"
          value={result.report_traceability_ready ? "ready" : "not ready"}
          tone={result.report_traceability_ready ? "ok" : "warning"}
        />
      </div>
      <div className="network-import-count-grid">
        {counts.map((item) => (
          <ImportStatusBadge
            key={item.label}
            label={item.label}
            value={`${item.value}`}
            tone={item.tone}
          />
        ))}
      </div>
      {result.auth_summary ? (
        <div className="network-import-preview-grid">
          <ImportStatusBadge
            label="Identity risk"
            value={result.auth_summary.identity_session_risk_bucket.replaceAll("_", " ")}
            tone={portableAuthRiskTone(result.auth_summary)}
          />
          <ImportStatusBadge
            label="Auth sessions"
            value={`${result.auth_summary.source_session_count}`}
            tone="neutral"
          />
          <ImportStatusBadge
            label="Privileged auth"
            value={`${result.auth_summary.privileged_role_record_count}`}
            tone={
              result.auth_summary.privileged_role_record_count > 0 ? "warning" : "ok"
            }
          />
          <ImportStatusBadge
            label="Visibility flags"
            value={`${result.auth_summary.degraded_visibility_flags.length}`}
            tone={
              result.auth_summary.degraded_visibility_flags.length > 0
                ? "warning"
                : "ok"
            }
          />
        </div>
      ) : null}
      {result.saas_cloud_summary ? (
        <div className="network-import-preview-grid">
          <ImportStatusBadge
            label="Provider cats"
            value={`${result.saas_cloud_summary.provider_category_counts.length}`}
            tone="neutral"
          />
          <ImportStatusBadge
            label="Unknown provider"
            value={`${result.saas_cloud_summary.unknown_provider_count}`}
            tone={
              result.saas_cloud_summary.unknown_provider_count > 0
                ? "warning"
                : "ok"
            }
          />
          <ImportStatusBadge
            label="Cloud findings"
            value={`${result.saas_cloud_summary.finding_refs.length}`}
            tone={
              result.saas_cloud_summary.finding_refs.length > 0
                ? "warning"
                : "neutral"
            }
          />
          <ImportStatusBadge
            label="Cloud flags"
            value={`${result.saas_cloud_summary.degraded_visibility_flags.length}`}
            tone={portableSaasCloudTone(result.saas_cloud_summary)}
          />
        </div>
      ) : null}
      {result.deception_summary ? (
        <div className="network-import-preview-grid">
          <ImportStatusBadge
            label="Decoy sensors"
            value={`${result.deception_summary.decoy_sensor_count}`}
            tone="neutral"
          />
          <ImportStatusBadge
            label="Decoy events"
            value={`${result.deception_summary.event_category_counts.length}`}
            tone="neutral"
          />
          <ImportStatusBadge
            label="Decoy findings"
            value={`${result.deception_summary.finding_refs.length}`}
            tone={
              result.deception_summary.finding_refs.length > 0
                ? "warning"
                : "neutral"
            }
          />
          <ImportStatusBadge
            label="Decoy flags"
            value={`${result.deception_summary.degraded_visibility_flags.length}`}
            tone={portableDeceptionTone(result.deception_summary)}
          />
        </div>
      ) : null}
    </div>
  );
}

interface PortableCaptureWindowDropOptions {
  readonly onDropPaths: (paths: string[]) => void;
  readonly onDropStateChange: (active: boolean) => void;
}

function usePortableCaptureWindowDrop({
  onDropPaths,
  onDropStateChange,
}: PortableCaptureWindowDropOptions) {
  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    let cancelled = false;
    let unlisten: (() => void) | null = null;

    void Promise.resolve(
      getCurrentWindow().onDragDropEvent((event) => {
        switch (event.payload.type) {
          case "enter":
          case "over":
            onDropStateChange(true);
            break;
          case "drop":
            onDropStateChange(false);
            onDropPaths(event.payload.paths);
            break;
          case "leave":
            onDropStateChange(false);
            break;
          default:
            break;
        }
      }),
    )
      .then((dispose) => {
        if (cancelled) {
          dispose();
          return;
        }
        unlisten = dispose;
      })
      .catch(() => {
        onDropStateChange(false);
      });

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [onDropPaths, onDropStateChange]);
}

function ImportStatusBadge({
  label,
  value,
  tone,
}: {
  readonly label: string;
  readonly value: string;
  readonly tone: "neutral" | "ok" | "warning";
}) {
  return (
    <div className="status-badge" data-status-label={label} data-tone={tone}>
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

export function buildPortableCapturePreviewRequest(
  paths: string[],
): PortableCaptureImportFileRequestDto | null {
  if (paths.length !== 1) {
    return null;
  }

  const sourceType = portableCaptureSourceTypeForPath(paths[0]);
  if (!sourceType) {
    return null;
  }

  return {
    source_path: paths[0],
    source_type: sourceType,
  };
}

export function portableCaptureSourceTypeForPath(
  sourcePath: string,
): PortableCaptureInputSourceTypeDto | null {
  const normalized = sourcePath.trim().toLowerCase();
  if (normalized.endsWith(".har")) {
    return "imported_har";
  }
  if (
    (normalized.endsWith(".jsonl") || normalized.endsWith(".log")) &&
    portableDeceptionSourceHint(normalized)
  ) {
    return "imported_deception_event_log";
  }
  if (
    (normalized.endsWith(".jsonl") || normalized.endsWith(".log")) &&
    portableAuthSourceHint(normalized)
  ) {
    return "imported_auth_security_log";
  }
  if (
    (normalized.endsWith(".jsonl") || normalized.endsWith(".log")) &&
    portableWafSourceHint(normalized)
  ) {
    return "imported_waf_log";
  }
  if (
    (normalized.endsWith(".jsonl") || normalized.endsWith(".log")) &&
    portableApiGatewaySourceHint(normalized)
  ) {
    return "imported_api_gateway_log";
  }
  if (
    (normalized.endsWith(".jsonl") || normalized.endsWith(".log")) &&
    portableCdnEdgeSourceHint(normalized)
  ) {
    return "imported_cdn_edge_log";
  }
  if (
    (normalized.endsWith(".jsonl") || normalized.endsWith(".log")) &&
    portableSdnControlPlaneSourceHint(normalized)
  ) {
    return "imported_sdn_control_plane_log";
  }
  if (
    (normalized.endsWith(".jsonl") || normalized.endsWith(".log")) &&
    portableObjectStorageAuditSourceHint(normalized)
  ) {
    return "imported_object_storage_audit_log";
  }
  if (
    (normalized.endsWith(".jsonl") || normalized.endsWith(".log")) &&
    portableSaasCloudSourceHint(normalized)
  ) {
    return "imported_saas_cloud_metadata";
  }
  if (normalized.endsWith(".log") && portableDnsResolverSourceHint(normalized)) {
    return "imported_dns_resolver_log";
  }
  if (normalized.endsWith(".jsonl")) {
    return "imported_jsonl_network_metadata";
  }
  if (normalized.endsWith(".log")) {
    return "imported_web_access_log";
  }
  return null;
}

export function portableCaptureSourceLabel(
  sourceType: PortableCaptureInputSourceTypeDto,
) {
  switch (sourceType) {
    case "imported_har":
      return "HAR metadata";
    case "imported_auth_security_log":
      return "Auth security metadata";
    case "imported_saas_cloud_metadata":
      return "SaaS/cloud metadata";
    case "imported_deception_event_log":
      return "Deception event metadata";
    case "imported_dns_resolver_log":
      return "DNS resolver metadata";
    case "imported_api_gateway_log":
      return "API gateway metadata";
    case "imported_waf_log":
      return "WAF metadata";
    case "imported_cdn_edge_log":
      return "CDN/edge metadata";
    case "imported_sdn_control_plane_log":
      return "SDN control-plane metadata";
    case "imported_object_storage_audit_log":
      return "Object storage audit metadata";
    case "imported_jsonl_network_metadata":
      return "JSONL metadata";
    case "imported_web_access_log":
      return "Web access log metadata";
    default:
      return "Portable metadata";
  }
}

function portableDnsResolverSourceHint(normalizedPath: string) {
  return ["dns", "resolver", "bind", "unbound", "dnsmasq"].some((hint) =>
    normalizedPath.includes(hint),
  );
}

function portableApiGatewaySourceHint(normalizedPath: string) {
  return ["api-gateway", "apigateway", "api_gateway", "gateway", "apim", "kong", "envoy"].some(
    (hint) => normalizedPath.includes(hint),
  );
}

function portableWafSourceHint(normalizedPath: string) {
  return [
    "waf",
    "modsecurity",
    "mod_security",
    "cloudflare-security",
    "aws-waf",
    "azure-waf",
  ].some((hint) => normalizedPath.includes(hint));
}

function portableCdnEdgeSourceHint(normalizedPath: string) {
  return normalizedPath
    .split(/[^\da-z]+/)
    .some((token) =>
      [
        "cdn",
        "edge",
        "cloudfront",
        "frontdoor",
        "front",
        "door",
        "cloudflare",
        "akamai",
        "fastly",
      ].includes(token),
    );
}

function portableSdnControlPlaneSourceHint(normalizedPath: string) {
  return normalizedPath
    .split(/[^\da-z]+/)
    .some((token) =>
      [
        "sdn",
        "controller",
        "control",
        "plane",
        "topology",
        "acl",
        "policy",
        "route",
        "openflow",
        "onos",
        "odl",
        "opendaylight",
        "sdwan",
      ].includes(token),
    );
}

function portableObjectStorageAuditSourceHint(normalizedPath: string) {
  return normalizedPath
    .split(/[^\da-z]+/)
    .some((token) =>
      [
        "object",
        "storage",
        "bucket",
        "s3",
        "blob",
        "gcs",
        "r2",
        "minio",
        "objectstorage",
        "cloudtrail",
      ].includes(token),
    );
}

function portableCaptureCountItems(counts: PortableCaptureRecordCountsDto) {
  return [
    { label: "Flows", value: counts.flow_records },
    { label: "Sessions", value: counts.session_records },
    { label: "DNS", value: counts.dns_records },
    { label: "TLS", value: counts.tls_records },
    { label: "HTTP", value: counts.http_metadata_records },
    { label: "Auth", value: counts.auth_metadata_records },
    { label: "SaaS/cloud", value: counts.saas_cloud_metadata_records },
    { label: "Deception", value: counts.deception_event_records },
    { label: "SDN", value: counts.sdn_control_plane_records },
  ];
}

function portableCaptureImportResultCountItems(
  result: PortableCaptureImportResultDto,
): Array<{
  readonly label: string;
  readonly value: number;
  readonly tone: "neutral" | "ok" | "warning";
}> {
  return [
    { label: "Flows", value: result.flow_count, tone: "neutral" as const },
    { label: "Sessions", value: result.session_count, tone: "neutral" as const },
    { label: "DNS", value: result.dns_count, tone: "neutral" as const },
    { label: "TLS", value: result.tls_count, tone: "neutral" as const },
    { label: "HTTP", value: result.http_metadata_count, tone: "neutral" as const },
    { label: "Auth", value: result.auth_metadata_count, tone: "neutral" as const },
    {
      label: "SaaS/cloud",
      value: result.saas_cloud_metadata_count,
      tone: "neutral" as const,
    },
    {
      label: "Deception",
      value: result.deception_event_count,
      tone: "neutral" as const,
    },
    {
      label: "SDN",
      value: result.sdn_control_plane_metadata_count,
      tone: "neutral" as const,
    },
    { label: "Security facts", value: result.security_fact_count, tone: "neutral" as const },
    {
      label: "Fusion hypotheses",
      value: result.attack_hypothesis_count,
      tone: result.attack_hypothesis_count > 0 ? "warning" : "ok",
    },
    { label: "Findings", value: result.finding_count, tone: "neutral" as const },
    {
      label: "Alerts",
      value: result.alert_count,
      tone:
        result.alert_count > 0 || result.alert_candidate_count > 0 ? "warning" : "ok",
    },
    {
      label: "Incidents",
      value: result.incident_count,
      tone:
        result.incident_count > 0 || result.incident_candidate_count > 0
          ? "warning"
          : "ok",
    },
  ];
}

function portableCaptureRedactionLabel(status: RedactionStatusDto) {
  return status.replaceAll("_", " ");
}

function portableCaptureRedactionTone(status: RedactionStatusDto): "neutral" | "ok" | "warning" {
  switch (status) {
    case "redacted":
    case "tokenized":
    case "hashed":
      return "ok";
    case "partially_redacted":
    case "suppressed":
    case "redaction_required":
      return "warning";
    case "not_required":
    default:
      return "neutral";
  }
}

function portableCaptureGraphHintLabel(result: PortableCaptureImportResultDto) {
  return portableCaptureHasGraphHints(result) ? "present" : "none";
}

function portableCaptureGraphHintTone(
  result: PortableCaptureImportResultDto,
): "neutral" | "ok" | "warning" {
  return portableCaptureHasGraphHints(result) ? "ok" : "neutral";
}

function portableCaptureHasGraphHints(result: PortableCaptureImportResultDto) {
  return result.emitted_topics.some((topic) => topic === "graph.hint");
}

function portableAuthSourceHint(sourcePath: string) {
  return sourcePath
    .split(/[^\da-z]+/)
    .some((token) =>
      ["auth", "identity", "idp", "login", "mfa", "vpn", "sshd", "rdp"].includes(token),
    );
}

function portableDeceptionSourceHint(sourcePath: string) {
  return sourcePath
    .split(/[^\da-z]+/)
    .some((token) =>
      ["deception", "decoy", "honeypot", "honey", "sensor", "canary", "trap"].includes(
        token,
      ),
    );
}

function portableSaasCloudSourceHint(sourcePath: string) {
  return sourcePath
    .split(/[^\da-z]+/)
    .some((token) =>
      [
        "saas",
        "cloud",
        "cdn",
        "provider",
        "object",
        "storage",
        "bucket",
        "proxy",
        "tunnel",
      ].includes(token),
    );
}

function portableAuthRiskTone(
  summary: PortableAuthSummaryDto,
): "neutral" | "ok" | "warning" {
  switch (summary.identity_session_risk_bucket) {
    case "high":
    case "medium":
      return "warning";
    case "low":
      return "ok";
    case "unknown":
    default:
      return "neutral";
  }
}

function portableSaasCloudTone(
  summary: PortableSaasCloudSummaryDto,
): "neutral" | "ok" | "warning" {
  if (
    summary.unknown_provider_count > 0 ||
    summary.degraded_visibility_flags.length > 0
  ) {
    return "warning";
  }
  return "ok";
}

function portableDeceptionTone(
  summary: PortableDeceptionSummaryDto,
): "neutral" | "ok" | "warning" {
  if (
    summary.finding_refs.length > 0 ||
    summary.degraded_visibility_flags.length > 0
  ) {
    return "warning";
  }
  return "ok";
}

async function discardPortableCapturePreview(previewId: string) {
  try {
    await confirmPortableCaptureImport({
      preview_id: previewId,
      user_confirmed: false,
      reason_redacted: IMPORT_CANCEL_REASON,
      requested_by_redacted: LOCAL_OPERATOR,
    });
  } catch {
    // Desktop cleanup intentionally returns a policy denial after discarding the preview.
  }
}
