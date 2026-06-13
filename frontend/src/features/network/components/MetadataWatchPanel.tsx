import {
  AlertTriangle,
  Pause,
  Play,
  RefreshCw,
  ShieldCheck,
  Square,
  Trash2,
} from "lucide-react";
import { useEffect } from "react";
import type {
  MetadataSamplingLoopActionDto,
  MetadataSourceHealthStateDto,
  MetadataWatchControllerStatusDto,
  MetadataWatchSourceStatusDto,
} from "../../../bridge/dto/network";
import {
  useConfirmMetadataWatchSourceMutation,
  useInvestigationDrillDownSummaryQuery,
  useMetadataSamplingBatchesQuery,
  useMetadataWatchSourcesQuery,
  useMetadataWatchStatusQuery,
  usePreviewMetadataWatchSourceMutation,
  useRunMetadataSamplingLoopMutation,
  useTickMetadataWatchControllerMutation,
  useUpdateMetadataSamplingLoopMutation,
  useUpdateMetadataWatchSourceMutation,
} from "../hooks";

export function MetadataWatchPanel() {
  const statusQuery = useMetadataWatchStatusQuery();
  const sourcesQuery = useMetadataWatchSourcesQuery();
  const batchesQuery = useMetadataSamplingBatchesQuery();
  const drillDownQuery = useInvestigationDrillDownSummaryQuery();
  const previewMutation = usePreviewMetadataWatchSourceMutation();
  const confirmMutation = useConfirmMetadataWatchSourceMutation();
  const updateMutation = useUpdateMetadataWatchSourceMutation();
  const tickMutation = useTickMetadataWatchControllerMutation();
  const loopMutation = useUpdateMetadataSamplingLoopMutation();
  const runLoopMutation = useRunMetadataSamplingLoopMutation();
  const status = statusQuery.data ?? defaultMetadataWatchStatus();
  const sources = sourcesQuery.data?.items ?? [];
  const batches = batchesQuery.data?.items ?? [];
  const proxySource = sources.find(
    (source) => source.source_kind === "localhost_proxy_continuous_drain",
  );
  const busy =
    previewMutation.isPending ||
    confirmMutation.isPending ||
    updateMutation.isPending ||
    tickMutation.isPending ||
    loopMutation.isPending ||
    runLoopMutation.isPending;

  useEffect(() => {
    if (
      !status.loop_enabled ||
      status.loop_paused ||
      status.loop_state !== "running"
    ) {
      return;
    }
    const intervalMillis = Math.max(
      1500,
      Math.min(status.per_source_timeout_millis || 5000, 10_000),
    );
    const interval = window.setInterval(() => {
      if (!runLoopMutation.isPending) {
        runLoopMutation.mutate({
          max_sources: status.max_sources_per_cycle || 8,
          reason_redacted: "background_sampling_loop",
          requested_by_redacted: "local_user",
        });
      }
    }, intervalMillis);
    return () => window.clearInterval(interval);
  }, [
    runLoopMutation,
    status.loop_enabled,
    status.loop_paused,
    status.loop_state,
    status.max_sources_per_cycle,
    status.per_source_timeout_millis,
  ]);

  const sendLoopAction = (action: MetadataSamplingLoopActionDto) => {
    loopMutation.mutate({
      action,
      max_sources_per_cycle: status.max_sources_per_cycle || 8,
      max_concurrent_sources: status.max_concurrent_sources || 1,
      max_files_per_tick: status.max_files_per_tick || 8,
      per_source_timeout_millis: status.per_source_timeout_millis || 5000,
      reason_redacted: `operator_${action}`,
      requested_by_redacted: "local_user",
    });
  };

  return (
    <section className="analysis-panel metadata-watch-panel">
      <div className="analysis-panel-header">
        <strong>AutoSecOps watch</strong>
        {status.running ? (
          <ShieldCheck size={15} aria-hidden="true" />
        ) : (
          <AlertTriangle size={15} aria-hidden="true" />
        )}
      </div>
      <div className="network-import-body">
        <div className="response-callout" data-tone="ok">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>
            Portable Default samples metadata only. No raw traffic collection,
            system proxy mutation, response execution, or automatic LLM calls.
          </span>
        </div>
        <div className="response-callout" data-tone="ok">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>
            No-retention mode keeps reader output to bounded summaries,
            checkpoints, provenance IDs, evidence refs, and fusion/report markers.
          </span>
        </div>

        <div className="network-import-preview-grid">
          <WatchBadge label="Sources" tone="neutral" value={`${sources.length}`} />
          <WatchBadge
            label="Sampling loop"
            tone={status.loop_enabled ? "ok" : "neutral"}
            value={labelize(status.loop_state)}
          />
          <WatchBadge
            label="Running"
            tone={status.running ? "ok" : "neutral"}
            value={status.running ? "yes" : "no"}
          />
          <WatchBadge
            label="Scheduled"
            tone={status.scheduled_source_count > 0 ? "ok" : "neutral"}
            value={`${status.scheduled_source_count}`}
          />
          <WatchBadge
            label="Sampled"
            tone={status.total_sampled_record_count > 0 ? "ok" : "neutral"}
            value={`${status.total_sampled_record_count}`}
          />
          <WatchBadge
            label="Malformed"
            tone={status.total_malformed_record_count > 0 ? "warning" : "neutral"}
            value={`${status.total_malformed_record_count}`}
          />
          <WatchBadge
            label="Duplicates"
            tone={status.total_duplicate_record_count > 0 ? "warning" : "neutral"}
            value={`${status.total_duplicate_record_count}`}
          />
          <WatchBadge
            label="Backpressure"
            tone={status.backpressure_source_count > 0 ? "warning" : "neutral"}
            value={`${status.total_backpressure_drop_count}`}
          />
          <WatchBadge
            label="Fusion refresh"
            tone={status.fusion_refresh_count > 0 ? "ok" : "neutral"}
            value={`${status.fusion_refresh_count}`}
          />
          <WatchBadge
            label="Latest checkpoint"
            tone={status.latest_checkpoint_id ? "ok" : "neutral"}
            value={
              status.latest_checkpoint_id ? shortRef(status.latest_checkpoint_id) : "none"
            }
          />
        </div>

        <div className="network-proxy-actions">
          <button
            className="toolbar-button"
            disabled={busy}
            type="button"
            onClick={() => sendLoopAction(status.loop_enabled ? "disable" : "enable")}
          >
            <Play size={14} aria-hidden="true" />
            {status.loop_enabled ? "Disable sampling" : "Enable sampling"}
          </button>
          <button
            className="toolbar-button"
            disabled={busy || !status.loop_enabled}
            type="button"
            onClick={() =>
              sendLoopAction(status.loop_paused ? "resume_all" : "pause_all")
            }
          >
            {status.loop_paused ? (
              <Play size={14} aria-hidden="true" />
            ) : (
              <Pause size={14} aria-hidden="true" />
            )}
            {status.loop_paused ? "Resume all" : "Pause all"}
          </button>
          <button
            className="toolbar-button"
            disabled={busy || !status.loop_enabled || status.loop_paused}
            type="button"
            onClick={() => {
              runLoopMutation.mutate({
                max_sources: status.max_sources_per_cycle || 8,
                reason_redacted: "operator_run_sampling_cycle",
                requested_by_redacted: "local_user",
              });
            }}
          >
            <RefreshCw size={14} aria-hidden="true" />
            Run cycle
          </button>
          <button
            className="toolbar-button"
            disabled={busy || Boolean(proxySource)}
            type="button"
            onClick={() => {
              void enableProxyWatchSource(previewMutation, confirmMutation);
            }}
          >
            <Play size={14} aria-hidden="true" />
            Enable proxy drain
          </button>
          <button
            className="toolbar-button"
            disabled={busy || sources.length === 0}
            type="button"
            onClick={() => {
              tickMutation.mutate({
                source_id: null,
                max_sources: 8,
                reason_redacted: "operator_tick",
                requested_by_redacted: "local_user",
              });
            }}
          >
            <RefreshCw size={14} aria-hidden="true" />
            Manual tick
          </button>
        </div>

        <div className="metadata-watch-batch-strip">
          <strong>Local metadata proxy drain</strong>
          <span>
            {proxySource
              ? `${labelize(proxySource.health_state)} | ${proxySource.counters.sampled_record_count} sampled | ${proxySource.counters.backpressure_drop_count} backpressure`
              : "continuous drain source not enabled"}
          </span>
        </div>

        <div className="metadata-watch-list">
          {sources.length === 0 ? (
            <span className="analysis-muted">
              No confirmed watch sources. Enable proxy drain to sample queued
              localhost metadata through the existing pipeline.
            </span>
          ) : null}
          {sources.map((source) => (
            <WatchSourceRow
              busy={busy}
              key={source.source_id}
              source={source}
              onUpdate={(action) =>
                updateMutation.mutate({
                  source_id: source.source_id,
                  action,
                  reason_redacted: `operator_${action}`,
                  requested_by_redacted: "local_user",
                })
              }
            />
          ))}
        </div>

        <div className="metadata-watch-batch-strip">
          <strong>Latest batches</strong>
          <span>
            {batches.length
              ? `${batches.length} bounded summaries`
              : "no sampling batches yet"}
          </span>
        </div>
        {batches.slice(-3).map((batch) => (
          <div className="metadata-watch-batch" key={batch.batch_id}>
            <span>{shortRef(batch.batch_id)}</span>
            <small>
              {labelize(batch.parser_family)} | {batch.sampled_record_count} sampled |{" "}
              {batch.evidence_refs.length} evidence refs | story{" "}
              {batch.story_available_marker ? "available" : "not available"}
            </small>
          </div>
        ))}

        <div className="metadata-watch-batch-strip">
          <strong>Source reliability explanations</strong>
          <span>
            {drillDownQuery.data
              ? `${drillDownQuery.data.source_reliability_count} bounded explanations`
              : "no reliability explanations yet"}
          </span>
        </div>
        {drillDownQuery.data?.source_reliability.slice(0, 4).map((source) => (
          <div className="metadata-watch-batch" key={source.source_id}>
            <span>
              {labelize(source.source_health_state)} /{" "}
              {labelize(source.reliability_bucket)}
            </span>
            <small>
              confidence impact {labelize(source.confidence_impact)} |{" "}
              {source.evidence_refs.length} evidence refs |{" "}
              {source.missing_visibility_flags.length} visibility gaps
            </small>
          </div>
        ))}

        {statusQuery.isError ||
        sourcesQuery.isError ||
        batchesQuery.isError ||
        previewMutation.isError ||
        confirmMutation.isError ||
        updateMutation.isError ||
        tickMutation.isError ||
        loopMutation.isError ||
        runLoopMutation.isError ||
        drillDownQuery.isError ? (
          <div className="response-callout">
            <AlertTriangle size={15} aria-hidden="true" />
            <span>Metadata watch command returned a redacted error.</span>
          </div>
        ) : null}
      </div>
    </section>
  );
}

function WatchSourceRow({
  source,
  busy,
  onUpdate,
}: {
  readonly source: MetadataWatchSourceStatusDto;
  readonly busy: boolean;
  readonly onUpdate: (action: "enable" | "pause" | "resume" | "disable" | "revoke") => void;
}) {
  const paused = source.state === "paused";
  const disabled = source.state === "disabled";
  const revoked = source.state === "revoked";

  return (
    <div className="metadata-watch-source-row" data-health={source.health_state}>
      <div>
        <strong>{labelize(source.source_kind)}</strong>
        <small>
          {labelize(source.parser_family)} | {source.sampling_mode.replaceAll("_", " ")}
        </small>
        <small>
          checkpoint {shortRef(source.checkpoint.checkpoint_id)} | cursor{" "}
          {source.checkpoint.safe_cursor_bucket}
        </small>
      </div>
      <span className="analysis-severity-pill" data-severity={healthTone(source.health_state)}>
        {labelize(source.health_state)}
      </span>
      <small>
        {source.counters.sampled_record_count} sampled |{" "}
        {source.counters.duplicate_record_count} duplicate |{" "}
        {source.counters.malformed_record_count} malformed |{" "}
        {source.counters.skipped_record_count} skipped |{" "}
        {source.counters.backpressure_drop_count} backpressure
      </small>
      <small>
        {source.fact_count} facts | {source.hypothesis_count} hypotheses |{" "}
        {source.finding_count} findings
      </small>
      {source.degraded_reason ? (
        <small className="analysis-muted">warning {source.degraded_reason}</small>
      ) : null}
      {source.health_state === "rotation_detected" ? (
        <small className="analysis-muted">rotation warning</small>
      ) : null}
      {source.health_state === "source_unavailable" ? (
        <small className="analysis-muted">source unavailable warning</small>
      ) : null}
      <div className="metadata-watch-actions">
        <button
          className="toolbar-button"
          disabled={busy || revoked}
          type="button"
          onClick={() => onUpdate(paused || disabled ? "resume" : "pause")}
        >
          {paused || disabled ? (
            <Play size={13} aria-hidden="true" />
          ) : (
            <Pause size={13} aria-hidden="true" />
          )}
          {paused || disabled ? "Resume" : "Pause"}
        </button>
        <button
          className="toolbar-button"
          disabled={busy || disabled || revoked}
          type="button"
          onClick={() => onUpdate("disable")}
        >
          <Square size={13} aria-hidden="true" />
          Disable
        </button>
        <button
          className="toolbar-button"
          disabled={busy || revoked}
          type="button"
          onClick={() => onUpdate("revoke")}
        >
          <Trash2 size={13} aria-hidden="true" />
          Revoke
        </button>
      </div>
    </div>
  );
}

function WatchBadge({
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

async function enableProxyWatchSource(
  previewMutation: ReturnType<typeof usePreviewMetadataWatchSourceMutation>,
  confirmMutation: ReturnType<typeof useConfirmMetadataWatchSourceMutation>,
) {
  const preview = await previewMutation.mutateAsync({
    source_kind: "localhost_proxy_continuous_drain",
    parser_family: "local_proxy_metadata",
    display_label_redacted: "local_metadata_proxy_drain",
    sampling_mode: "continuous_drain",
    interval_seconds: 5,
    max_records_per_tick: 500,
    max_bytes_per_tick: 64_000,
    reason_redacted: "operator_enabled_proxy_drain",
  });
  await confirmMutation.mutateAsync({
    preview_id: preview.preview_id,
    user_confirmed: true,
    reason_redacted: "operator_enabled_proxy_drain",
    requested_by_redacted: "local_user",
  });
}

function defaultMetadataWatchStatus(): MetadataWatchControllerStatusDto {
  return {
    generated_at: new Date(0).toISOString(),
    scheduler_mode: "explicit_tick_controller",
    running: false,
    loop_state: "disabled",
    loop_enabled: false,
    loop_paused: false,
    scheduled_source_count: 0,
    max_sources_per_cycle: 8,
    max_concurrent_sources: 1,
    max_files_per_tick: 8,
    per_source_timeout_millis: 5000,
    enabled_source_count: 0,
    active_source_count: 0,
    paused_source_count: 0,
    degraded_source_count: 0,
    revoked_source_count: 0,
    backpressure_source_count: 0,
    total_sampled_record_count: 0,
    total_duplicate_record_count: 0,
    total_malformed_record_count: 0,
    total_backpressure_drop_count: 0,
    last_tick_at: null,
    last_scheduled_at: null,
    graceful_shutdown_requested: false,
    latest_batch_id: null,
    latest_checkpoint_id: null,
    latest_provenance_id: null,
    fusion_refresh_count: 0,
    report_refresh_marker_count: 0,
    attack_refresh_marker_count: 0,
    triage_advisory_only: true,
    automatic_llm_calls: false,
    response_execution: false,
    privacy_class: "internal",
  };
}

function healthTone(
  health: MetadataSourceHealthStateDto,
): "low" | "medium" | "high" | "critical" {
  switch (health) {
    case "active":
    case "enabled":
    case "idle":
      return "low";
    case "paused":
    case "degraded":
    case "backpressure":
    case "source_unavailable":
    case "cursor_reset_required":
    case "rotation_detected":
    case "oversized_input_skipped":
    case "stopped":
      return "medium";
    case "parser_error":
    case "permission_required":
    case "revoked":
      return "high";
    default:
      return "low";
  }
}

function labelize(value: string) {
  return value.replaceAll("_", " ");
}

function shortRef(value: string) {
  return value.length > 12 ? `${value.slice(0, 8)}...` : value;
}
