import {
  AlertTriangle,
  Network,
  Play,
  RefreshCw,
  ShieldCheck,
  Square,
} from "lucide-react";
import { useState } from "react";
import type {
  LocalMetadataProxyStartRequestDto,
  LocalMetadataProxyStatusDto,
} from "../../../bridge/dto/network";
import {
  useDrainLocalMetadataProxyMutation,
  useLocalMetadataProxyStatusQuery,
  useStartLocalMetadataProxyMutation,
  useStopLocalMetadataProxyMutation,
} from "../hooks";

const LOOPBACK_BIND_ADDRESS = "127.0.0.1";

export function LocalMetadataProxyPanel() {
  const statusQuery = useLocalMetadataProxyStatusQuery();
  const startMutation = useStartLocalMetadataProxyMutation();
  const stopMutation = useStopLocalMetadataProxyMutation();
  const drainMutation = useDrainLocalMetadataProxyMutation();
  const [requestedPort, setRequestedPort] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const status = statusQuery.data ?? defaultLocalMetadataProxyStatus();
  const busy =
    statusQuery.isLoading ||
    startMutation.isPending ||
    stopMutation.isPending ||
    drainMutation.isPending;
  const canStart = status.state === "stopped" && !busy;
  const canStop =
    (status.state === "running" || status.state === "degraded") && !busy;
  const canDrain = status.pending_event_count > 0 && !busy;
  const routeTarget = status.listen_port
    ? `${status.listen_host}:${status.listen_port}`
    : `${LOOPBACK_BIND_ADDRESS}:<port>`;

  return (
    <section className="analysis-panel network-proxy-panel">
      <div className="analysis-panel-header">
        <strong>Local metadata proxy</strong>
        <Network size={15} aria-hidden="true" />
      </div>
      <div className="network-import-body">
        <div className="response-callout" data-tone={status.state === "running" ? "ok" : "warning"}>
          {status.state === "running" ? (
            <ShieldCheck size={15} aria-hidden="true" />
          ) : (
            <AlertTriangle size={15} aria-hidden="true" />
          )}
          <span>
            Manually route one client, browser, or tool through {routeTarget}. No
            system proxy changes are made and requests are not forwarded.
          </span>
        </div>
        <div className="network-import-preview">
          <div className="network-import-preview-grid">
            <ProxyStatusBadge
              label="Bind address"
              tone="neutral"
              value={LOOPBACK_BIND_ADDRESS}
            />
            <ProxyStatusBadge
              label="Port"
              tone={status.listen_port ? "ok" : "warning"}
              value={status.listen_port ? `${status.listen_port}` : "await start"}
            />
            <ProxyStatusBadge
              label="Status"
              tone={proxyStatusTone(status)}
              value={proxyStatusLabel(status.state)}
            />
            <ProxyStatusBadge
              label="Queued events"
              tone={status.pending_event_count > 0 ? "warning" : "neutral"}
              value={`${status.pending_event_count}`}
            />
            <ProxyStatusBadge
              label="Drained events"
              tone={status.drained_event_count > 0 ? "ok" : "neutral"}
              value={`${status.drained_event_count}`}
            />
            <ProxyStatusBadge
              label="Privacy"
              tone="ok"
              value={proxyPrivacyLabel(status)}
            />
            {proxyReasonLabel(status) ? (
              <ProxyStatusBadge
                label="Reason"
                tone="warning"
                value={proxyReasonLabel(status) ?? "not reported"}
              />
            ) : null}
          </div>
        </div>
        <label className="network-proxy-port-row">
          <span>Requested port</span>
          <input
            className="network-proxy-port-input"
            disabled={!canStart}
            inputMode="numeric"
            placeholder="Automatic"
            type="text"
            value={requestedPort}
            onChange={(event) => setRequestedPort(event.currentTarget.value)}
          />
          <small>Leave blank to let the app choose a loopback-only port.</small>
        </label>
        <div className="network-proxy-actions">
          <button
            className="toolbar-button"
            disabled={!canStart}
            type="button"
            onClick={() => {
              const request = buildLocalMetadataProxyStartRequest(requestedPort);
              if (!request) {
                setNotice(
                  "Enter a loopback port between 1 and 65535, or leave the field empty.",
                );
                return;
              }
              setNotice(null);
              startMutation.mutate(request, {
                onSuccess: (nextStatus) => {
                  setRequestedPort("");
                  setNotice(
                    nextStatus.listen_port
                      ? `Loopback listener started on ${nextStatus.listen_host}:${nextStatus.listen_port}. Route one client, browser, or tool manually.`
                      : "Loopback listener started with an assigned port.",
                  );
                },
              });
            }}
          >
            <Play size={14} aria-hidden="true" />
            Start
          </button>
          <button
            className="toolbar-button"
            disabled={!canStop}
            type="button"
            onClick={() => {
              setNotice(null);
              stopMutation.mutate(undefined, {
                onSuccess: () => {
                  setNotice(
                    "Loopback listener stopped. Command-backed views were refreshed with any drained metadata.",
                  );
                },
              });
            }}
          >
            <Square size={14} aria-hidden="true" />
            Stop
          </button>
          <button
            className="toolbar-button"
            disabled={!canDrain}
            type="button"
            onClick={() => {
              setNotice(null);
              drainMutation.mutate(undefined, {
                onSuccess: () => {
                  setNotice(
                    "Queued metadata drained into the Network, case, graph, and report views.",
                  );
                },
              });
            }}
          >
            <RefreshCw size={14} aria-hidden="true" />
            Drain
          </button>
        </div>
        {busy ? (
          <div className="response-callout" data-tone="ok">
            <ShieldCheck size={15} aria-hidden="true" />
            <span>Refreshing bounded loopback proxy status.</span>
          </div>
        ) : null}
        {status.message_redacted ? (
          <span className="analysis-muted">{status.message_redacted}</span>
        ) : null}
        {statusQuery.isError || startMutation.isError || stopMutation.isError || drainMutation.isError ? (
          <div className="response-callout">
            <AlertTriangle size={15} aria-hidden="true" />
            <span>Local metadata proxy control returned a redacted error.</span>
          </div>
        ) : null}
        {notice ? <span className="analysis-muted">{notice}</span> : null}
      </div>
    </section>
  );
}

function ProxyStatusBadge({
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

export function buildLocalMetadataProxyStartRequest(
  requestedPort: string,
): LocalMetadataProxyStartRequestDto | null {
  const trimmed = requestedPort.trim();
  if (!trimmed) {
    return { listen_port: null };
  }
  if (!/^\d+$/.test(trimmed)) {
    return null;
  }
  const parsed = Number.parseInt(trimmed, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    return null;
  }
  return { listen_port: parsed };
}

function defaultLocalMetadataProxyStatus(): LocalMetadataProxyStatusDto {
  return {
    state: "stopped",
    listen_host: LOOPBACK_BIND_ADDRESS,
    listen_port: null,
    requests_captured: 0,
    requests_rejected: 0,
    dropped_batches: 0,
    pending_batches: 0,
    pending_event_count: 0,
    drained_event_count: 0,
    last_capture_at: null,
    last_error_code: null,
    localhost_only: true,
    metadata_only: true,
    message_redacted: "Localhost metadata proxy is stopped",
  };
}

function proxyStatusLabel(state: LocalMetadataProxyStatusDto["state"]) {
  switch (state) {
    case "running":
      return "running";
    case "degraded":
      return "degraded";
    case "stopped":
    default:
      return "stopped";
  }
}

function proxyStatusTone(
  status: LocalMetadataProxyStatusDto,
): "neutral" | "ok" | "warning" {
  switch (status.state) {
    case "running":
      return "ok";
    case "degraded":
      return "warning";
    case "stopped":
    default:
      return "neutral";
  }
}

function proxyPrivacyLabel(status: LocalMetadataProxyStatusDto) {
  return status.metadata_only ? "metadata only / no raw retention" : "status unavailable";
}

function proxyReasonLabel(status: LocalMetadataProxyStatusDto) {
  if (status.last_error_code) {
    return status.last_error_code.replaceAll("_", " ");
  }
  if (status.state === "degraded" && status.requests_rejected > 0) {
    return "requests rejected";
  }
  if (status.state === "degraded" && status.dropped_batches > 0) {
    return "queue backpressure";
  }
  return null;
}
