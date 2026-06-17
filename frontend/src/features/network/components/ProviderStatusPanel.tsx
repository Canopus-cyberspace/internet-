import { ShieldCheck, WifiOff } from "lucide-react";
import { useState } from "react";
import type {
  EtwLifecycleStatusDto,
  IpHelperScheduleStatusDto,
  NetworkFallbackPlanDto,
  NetworkProviderControllerStatusDto,
  NetworkProviderStatusDto,
  NetworkVisibilitySummaryDto,
} from "../../../bridge/dto/network";
import {
  useNetworkFallbackPlanQuery,
  useNetworkProviderStatusesQuery,
  useNetworkVisibilitySummaryQuery,
  useProviderControllerStatusQuery,
} from "../hooks";

export function ProviderStatusPanel() {
  const controllerQuery = useProviderControllerStatusQuery();
  const providersQuery = useNetworkProviderStatusesQuery();
  const visibilityQuery = useNetworkVisibilitySummaryQuery();
  const fallbackQuery = useNetworkFallbackPlanQuery();
  const controller = controllerQuery.data ?? defaultProviderControllerStatus();
  const providers = providersQuery.data ?? controller.providers;
  const visibility = visibilityQuery.data ?? controller.visibility_summary;
  const fallback = fallbackQuery.data ?? controller.fallback_plan;
  const ipHelper = providers.find((provider) => provider.provider_kind === "ip_helper");
  const etw = providers.find((provider) => provider.provider_kind === "etw_network");
  const windowsDns = providers.find((provider) => provider.provider_kind === "windows_dns");
  const shortLivedVisibility =
    visibility.dimensions.find(
      (dimension) => dimension.dimension === "short_lived_network_event_visibility",
    )?.visibility_state ?? "unavailable";
  const controlsAvailable =
    Boolean(ipHelper) &&
    controller.policy_summary.provider_activation_allowed &&
    controller.policy_summary.ip_helper_execution_available_over_production_ipc &&
    controller.policy_summary.production_provider_mutations_enabled;

  return (
    <section className="analysis-panel provider-status-panel">
      <div className="analysis-panel-header">
        <strong>Provider status</strong>
        <WifiOff size={15} aria-hidden="true" />
      </div>
      <div className="network-import-body">
        <div className="response-callout" data-tone="warning">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>Native network providers are inactive.</span>
        </div>
        <div className="response-callout" data-tone="ok">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>Portable metadata analysis remains available.</span>
        </div>
        <div className="response-callout" data-tone="warning">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>IP Helper adapter supports explicit bounded execution.</span>
        </div>
        <div className="response-callout" data-tone="neutral">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>
            ETW read models expose bounded lifecycle health, counters, handoff refs, and fallback
            visibility.
          </span>
        </div>
        <div className="response-callout" data-tone="neutral">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>Npcap enhancement is deferred.</span>
        </div>
        <div className="response-callout" data-tone="warning">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>Packet capture is unavailable.</span>
        </div>
        <div className="response-callout" data-tone="ok">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>
            Enabled IP Helper commands: Activate, Sample once, Stop, Configure schedule, Enable
            schedule, Pause schedule, Resume schedule, Disable schedule.
          </span>
        </div>
        <div className="response-callout" data-tone="neutral">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>IP Helper sampling is explicit and bounded.</span>
        </div>
        <div className="response-callout" data-tone="neutral">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>No packet capture is performed.</span>
        </div>
        <div className="response-callout" data-tone="neutral">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>No process-to-network attribution is provided.</span>
        </div>
        <div className="response-callout" data-tone="neutral">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>
            IP Helper schedule control is session-bound; timer sampling remains explicit and
            bounded.
          </span>
        </div>
        <div className="response-callout" data-tone="neutral">
          <ShieldCheck size={15} aria-hidden="true" />
          <span>No ETW provider is automatically activated by reads, reports, exports, or UI refresh.</span>
        </div>

        <div className="settings-status-grid">
          <ProviderRow label="Controller" value={label(controller.controller_state)} />
          <ProviderRow label="Selected mode" value={label(controller.selected_mode)} />
          <ProviderRow
            label="Activation"
            value={label(controller.policy_summary.activation_unavailable_reason)}
          />
          <ProviderRow
            label="Fallback"
            value={fallback.selection_order.map(label).join(" -> ")}
          />
          <ProviderRow
            label="Audit refs"
            value={String(controller.audit_summary.audit_refs.length)}
          />
        </div>

        <IpHelperControls
          available={controlsAvailable}
          provider={ipHelper}
          schedule={controller.ip_helper_schedule}
        />

        <EtwStatusSummary
          lifecycle={controller.etw_lifecycle}
          provider={etw}
          shortLivedVisibility={shortLivedVisibility}
          counters={controller.provider_zero}
          fallback={fallback}
        />

        <WindowsDnsStatusSummary provider={windowsDns} counters={controller.provider_zero} />

        <div className="provider-status-list">
          {providers.map((provider) => (
            <ProviderStatusItem key={provider.provider_id} provider={provider} />
          ))}
        </div>

        <VisibilitySummary visibility={visibility} fallback={fallback} />
      </div>
    </section>
  );
}

function WindowsDnsStatusSummary({
  counters,
  provider,
}: {
  readonly counters: NetworkProviderControllerStatusDto["provider_zero"];
  readonly provider?: NetworkProviderStatusDto;
}) {
  return (
    <div className="provider-execution-controls" aria-label="Windows DNS sensing read-only status">
      <div className="provider-execution-copy">
        <strong>Windows DNS sensing</strong>
        <small>
          Disabled by default. Published observations contain protected query refs and bounded
          categories only; raw names, answers, resolver endpoints, ports, and process identity are
          not retained.
        </small>
      </div>
      <div className="settings-status-grid">
        <ProviderRow label="Provider" value={label(provider?.implementation_state ?? "unavailable")} />
        <ProviderRow label="Lifecycle" value={label(provider?.lifecycle_state ?? "unavailable")} />
        <ProviderRow label="Lifecycle calls" value={String(counters.dns_sensing_calls)} />
        <ProviderRow
          label="DNS EventBus publications"
          value={String(counters.dns_observation_publications)}
        />
        <ProviderRow
          label="DNS detector invocations"
          value={String(counters.dns_detector_invocations)}
        />
        <ProviderRow
          label="DNS records consumed"
          value={String(counters.dns_detector_consumed)}
        />
        <ProviderRow label="Degraded reason" value={provider?.degraded_reason ?? "None"} />
      </div>
    </div>
  );
}

function EtwStatusSummary({
  counters,
  fallback,
  lifecycle,
  provider,
  shortLivedVisibility,
}: {
  readonly counters: NetworkProviderControllerStatusDto["provider_zero"];
  readonly fallback: NetworkFallbackPlanDto;
  readonly lifecycle: EtwLifecycleStatusDto;
  readonly provider?: NetworkProviderStatusDto;
  readonly shortLivedVisibility: string;
}) {
  return (
    <div className="provider-execution-controls" aria-label="ETW read-only status">
      <div className="provider-execution-copy">
        <strong>ETW product surface</strong>
        <small>
          Read-only bounded lifecycle, health, counters, and traceability. No raw events, packet
          content, endpoint values, or process identity is displayed.
        </small>
      </div>
      <div className="settings-status-grid">
        <ProviderRow label="Provider" value={label(provider?.implementation_state ?? "unavailable")} />
        <ProviderRow label="Lifecycle" value={label(lifecycle.lifecycle_state)} />
        <ProviderRow label="Session" value={label(lifecycle.session_state)} />
        <ProviderRow label="Authorization" value={label(lifecycle.authorization_state)} />
        <ProviderRow label="Fallback" value={label(lifecycle.fallback_state)} />
        <ProviderRow label="Short-lived event visibility" value={label(shortLivedVisibility)} />
        <ProviderRow
          label="Control thread"
          value={lifecycle.control_thread_active ? "Active" : "Inactive"}
        />
        <ProviderRow
          label="Provider enabled"
          value={lifecycle.provider_enabled ? "Yes" : "No"}
        />
        <ProviderRow
          label="Collection"
          value={lifecycle.collection_started ? "Started" : "Not started"}
        />
        <ProviderRow
          label="Consumer"
          value={lifecycle.consumer_started ? "Started" : "Not started"}
        />
        <ProviderRow
          label="Consumer worker"
          value={lifecycle.consumer_worker_active ? "Active" : "Inactive"}
        />
        <ProviderRow
          label="Consumer joined"
          value={lifecycle.consumer_worker_joined ? "Yes" : "No"}
        />
        <ProviderRow label="Raw records observed" value={String(lifecycle.raw_event_count)} />
        <ProviderRow label="Normalized records" value={String(lifecycle.normalized_event_count)} />
        <ProviderRow label="Dropped records" value={String(lifecycle.dropped_event_count)} />
        <ProviderRow label="Rate-limited records" value={String(lifecycle.rate_limited_event_count)} />
        <ProviderRow
          label="Schema-rejected records"
          value={String(lifecycle.schema_rejected_event_count)}
        />
        <ProviderRow label="Published batches" value={String(lifecycle.published_batch_count)} />
        <ProviderRow
          label="ETW EventBus publications"
          value={String(lifecycle.eventbus_publication_count)}
        />
        <ProviderRow label="Downstream facts" value={String(lifecycle.security_fact_count)} />
        <ProviderRow label="Lifecycle calls" value={String(lifecycle.activation_count)} />
        <ProviderRow label="Pause/resume calls" value={`${lifecycle.pause_count}/${lifecycle.resume_count}`} />
        <ProviderRow label="Stop calls" value={String(lifecycle.stop_count)} />
        <ProviderRow label="ETW handoff calls" value={String(counters.etw_calls)} />
        <ProviderRow
          label="Native topic publications"
          value={String(counters.native_network_topic_publications)}
        />
        <ProviderRow
          label="Process-network facts"
          value={String(counters.process_network_facts)}
        />
        <ProviderRow label="Packet facts" value={String(counters.packet_facts)} />
        <ProviderRow label="Fallback reason" value={fallback.degraded_reason ?? "None"} />
        <ProviderRow label="Degraded reason" value={lifecycle.degraded_reason ?? "None"} />
      </div>
      <small>
        ETW starts only after explicit authorization. Automatic scheduling, packet visibility,
        process-network attribution, exact process identity, and response execution remain unavailable.
      </small>
    </div>
  );
}

function IpHelperControls({
  available,
  provider,
  schedule,
}: {
  readonly available: boolean;
  readonly provider?: NetworkProviderStatusDto;
  readonly schedule: IpHelperScheduleStatusDto;
}) {
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [pendingScheduleAction, setPendingScheduleAction] = useState<string | null>(null);
  const lifecycle = provider?.lifecycle_state ?? "unavailable";
  const scheduleState = schedule.schedule_state;
  const scheduleEnabled = scheduleState === "configured_enabled";
  const schedulePaused = scheduleState === "paused";
  const scheduleConfigured =
    scheduleState === "configured_disabled" || scheduleEnabled || schedulePaused;
  const disableActivate = !available || lifecycle === "active";
  const disableSample = !available || lifecycle !== "active";
  const disableStop = !available || lifecycle === "stopped" || lifecycle === "inactive";
  const disableConfigure = !available || pendingScheduleAction !== null;
  const disableEnable =
    !available || lifecycle !== "active" || !scheduleConfigured || scheduleEnabled;
  const disablePause = !available || !scheduleEnabled;
  const disableResume = !available || lifecycle !== "active" || !schedulePaused;
  const disableDisable =
    !available || (!scheduleConfigured && scheduleState !== "invalidated");

  function requestAction(action: "activate" | "sample" | "stop") {
    const prompt =
      action === "sample"
        ? "Sample bounded Windows connection-table metadata now? No packet capture, raw PID, IP, or port values are displayed."
        : `Confirm IP Helper ${action}. This changes only the bounded provider lifecycle.`;
    if (typeof window !== "undefined" && !window.confirm(prompt)) {
      return;
    }
    setPendingAction(action);
  }

  function requestScheduleAction(
    action: "configure" | "enable" | "pause" | "resume" | "disable",
  ) {
    const prompt =
      action === "enable" || action === "resume"
        ? "Enable the session-bound IP Helper schedule control plane? Timer-backed sampling remains bounded, no-overlap, and explicit to this ServiceHost session."
        : `Confirm IP Helper schedule ${action}. This updates only bounded schedule state.`;
    if (typeof window !== "undefined" && !window.confirm(prompt)) {
      return;
    }
    setPendingScheduleAction(action);
  }

  return (
    <div className="provider-execution-controls" aria-label="IP Helper explicit controls">
      <div className="provider-execution-copy">
        <strong>IP Helper explicit controls</strong>
        <small>
          Current lifecycle {label(lifecycle)}. Controls never start scheduler automation or packet
          capture.
        </small>
      </div>
      <div className="provider-execution-buttons">
        <button
          type="button"
          disabled={disableActivate || pendingAction !== null}
          onClick={() => requestAction("activate")}
        >
          Activate
        </button>
        <button
          type="button"
          disabled={disableSample || pendingAction !== null}
          onClick={() => requestAction("sample")}
        >
          Sample once
        </button>
        <button
          type="button"
          disabled={disableStop || pendingAction !== null}
          onClick={() => requestAction("stop")}
        >
          Stop
        </button>
      </div>
      <small>
        {pendingAction
          ? `Pending explicit ${label(pendingAction)} request.`
          : "No automatic sample is queued on page load, refresh, or reconnect."}
      </small>
      <div className="settings-status-grid">
        <ProviderRow label="Schedule state" value={label(scheduleState)} />
        <ProviderRow
          label="Configured"
          value={schedule.schedule_state === "not_configured" ? "No" : "Yes"}
        />
        <ProviderRow label="Enabled" value={schedule.enabled_marker ? "Yes" : "No"} />
        <ProviderRow label="Paused" value={schedule.paused_marker ? "Yes" : "No"} />
        <ProviderRow label="Lease" value={label(schedule.lease_state)} />
        <ProviderRow label="Lease valid" value={schedule.schedule_lease_valid ? "Yes" : "No"} />
        <ProviderRow label="Interval" value={label(schedule.config.interval_bucket)} />
        <ProviderRow label="Next due" value={label(schedule.next_due_category)} />
        <ProviderRow
          label="Timer runtime"
          value={schedule.timer_runtime_active ? "Active" : "Deferred"}
        />
        <ProviderRow
          label="Scheduled calls"
          value={String(schedule.scheduler_triggered_provider_calls)}
        />
        <ProviderRow label="Latest manual sample" value={schedule.latest_manual_sample_ref ?? "None"} />
        <ProviderRow
          label="Latest scheduled sample"
          value={schedule.latest_scheduled_cycle_ref ?? "None"}
        />
        <ProviderRow
          label="Latest scheduled result"
          value={label(schedule.latest_scheduled_execution_result)}
        />
        <ProviderRow label="Retry" value={label(schedule.retry_count_bucket)} />
        <ProviderRow label="Backpressure" value={label(schedule.backpressure_state)} />
        <ProviderRow label="Freshness" value={label(schedule.freshness_state)} />
        <ProviderRow label="Missed sample" value={label(schedule.missed_sample_state)} />
        <ProviderRow label="Overlap skips" value={label(schedule.overlap_skip_count_bucket)} />
        <ProviderRow label="Degraded reason" value={schedule.degraded_reason ?? "None"} />
      </div>
      <div className="provider-execution-buttons" aria-label="IP Helper schedule controls">
        <button
          type="button"
          disabled={disableConfigure}
          onClick={() => requestScheduleAction("configure")}
        >
          Configure schedule
        </button>
        <button
          type="button"
          disabled={disableEnable || pendingScheduleAction !== null}
          onClick={() => requestScheduleAction("enable")}
        >
          Enable schedule
        </button>
        <button
          type="button"
          disabled={disablePause || pendingScheduleAction !== null}
          onClick={() => requestScheduleAction("pause")}
        >
          Pause schedule
        </button>
        <button
          type="button"
          disabled={disableResume || pendingScheduleAction !== null}
          onClick={() => requestScheduleAction("resume")}
        >
          Resume schedule
        </button>
        <button
          type="button"
          disabled={disableDisable || pendingScheduleAction !== null}
          onClick={() => requestScheduleAction("disable")}
        >
          Disable schedule
        </button>
      </div>
      <small>
        {pendingScheduleAction
          ? `Pending explicit schedule ${label(pendingScheduleAction)} request.`
          : "Scheduled IP Helper sampling is explicitly enabled and session-bound. No packet capture is performed. No process-to-network attribution is provided. The schedule is disabled after ServiceHost restart or authorization loss. Reports, exports, UI refresh, and LLM operations never trigger sampling."}
      </small>
    </div>
  );
}

function ProviderStatusItem({ provider }: { readonly provider: NetworkProviderStatusDto }) {
  return (
    <div className="provider-status-item">
      <strong>{label(provider.provider_kind)}</strong>
      <span>{label(provider.implementation_state)}</span>
      <small>
        {label(provider.lifecycle_state)} · boundary {label(provider.adapter_boundary)}
      </small>
    </div>
  );
}

function VisibilitySummary({
  fallback,
  visibility,
}: {
  readonly fallback: NetworkFallbackPlanDto;
  readonly visibility: NetworkVisibilitySummaryDto;
}) {
  return (
    <div className="provider-visibility-summary">
      <strong>Visibility dimensions</strong>
      <div className="provider-status-list">
        {visibility.dimensions.map((dimension) => (
          <div className="provider-status-item" key={dimension.dimension}>
            <span>{label(dimension.dimension)}</span>
            <small>{label(dimension.visibility_state)}</small>
          </div>
        ))}
      </div>
      <small>Fallback plan ref: {fallback.fallback_plan_ref}</small>
    </div>
  );
}

function ProviderRow({
  label: rowLabel,
  value,
}: {
  readonly label: string;
  readonly value: string;
}) {
  return (
    <div className="settings-status-row" data-tone="neutral">
      <span>{rowLabel}</span>
      <strong>{value}</strong>
    </div>
  );
}

function label(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function defaultProviderControllerStatus(): NetworkProviderControllerStatusDto {
  const providers: NetworkProviderStatusDto[] = [
    provider("portable_metadata", "available"),
    provider("ip_helper", "implemented_inactive"),
    provider("etw_network", "implemented_inactive"),
    provider("windows_dns", "implemented_inactive"),
    provider("npcap_packet", "not_implemented"),
    provider("capture_broker", "not_implemented"),
    provider("none", "unavailable"),
  ];
  const visibility: NetworkVisibilitySummaryDto = {
    visibility_ref: "network_visibility_ref",
    dimensions: [
      { dimension: "portable_metadata_visibility", visibility_state: "available" },
      { dimension: "connection_table_visibility", visibility_state: "unavailable" },
      {
        dimension: "short_lived_network_event_visibility",
        visibility_state: "unavailable",
      },
      { dimension: "process_category_visibility", visibility_state: "unavailable" },
      {
        dimension: "process_network_category_visibility",
        visibility_state: "unavailable",
      },
      { dimension: "packet_header_visibility", visibility_state: "unavailable" },
      { dimension: "packet_payload_visibility", visibility_state: "unavailable" },
      {
        dimension: "specific_process_identity_visibility",
        visibility_state: "unavailable",
      },
      {
        dimension: "specific_destination_identity_visibility",
        visibility_state: "unavailable",
      },
    ],
    provenance_refs: ["provider_controller_foundation"],
    generated_at: new Date(0).toISOString(),
    redaction_status: "redacted",
  };
  const fallback: NetworkFallbackPlanDto = {
    fallback_plan_ref: "network_fallback_plan_ref",
    selected_mode: "portable_only",
    selection_order: [
      "portable_metadata",
      "ip_helper",
      "etw_network",
      "windows_dns",
      "npcap_packet",
      "capture_broker",
    ],
    fallback_rules: [
      "portable_paths_always_available",
      "ip_helper_requires_explicit_activation",
      "etw_failure_falls_back_to_ip_helper",
      "npcap_failure_falls_back_to_etw_or_ip_helper",
      "packet_enhancement_never_replaces_metadata_fallback",
    ],
    degraded_reason: "native_network_providers_inactive",
    policy_refs: ["network_provider_selection_policy_ref"],
    redaction_status: "redacted",
  };

  return {
    controller_ref: "provider_controller_ref",
    ownership_ref: "servicehost_provider_controller",
    ownership_epoch: 1,
    runtime_owner: "service_host",
    schema_version: { major: 1, minor: 0, patch: 0 },
    controller_state: "inactive",
    selected_mode: "portable_only",
    providers,
    visibility_summary: visibility,
    fallback_plan: fallback,
    dependency_summary: {
      dependency_ref: "network_provider_dependency_ref",
      dependency_refs: ["servicehost_runtime_ownership_gate"],
      degraded_reason: "provider_execution_deferred",
      redaction_status: "redacted",
    },
    policy_summary: {
      policy_ref: "network_provider_policy_ref",
      provider_activation_allowed: true,
      activation_unavailable_reason: "not_applicable",
      ip_helper_execution_available_over_production_ipc: true,
      production_ipc_execution_unavailable_reason: "not_applicable",
      required_gates: ["servicehost_runtime_ownership", "production_caller_trust"],
      provider_readiness_creates_evidence: false,
      provider_availability_creates_findings: false,
      production_provider_mutations_enabled: true,
      redaction_status: "redacted",
    },
    lifecycle_summary: {
      lifecycle_ref: "network_provider_lifecycle_ref",
      controller_state: "inactive",
      selected_mode: "portable_only",
      active_provider_count: 0,
      inactive_provider_count: providers.length,
      degraded_provider_count: 0,
      redaction_status: "redacted",
    },
    audit_summary: {
      audit_ref: "network_provider_audit_ref",
      declared_status_topics: [
        "network.provider_controller.status",
        "network.provider.status",
        "network.visibility.status",
        "audit.network_provider_controller",
        "audit.network_provider_execution",
      ],
      audit_refs: ["audit_network_provider_controller_ref"],
      status_publication_count: 0,
      provider_execution_event_count: 0,
      redaction_status: "redacted",
    },
    ip_helper_schedule: defaultIpHelperSchedule(),
    etw_lifecycle: defaultEtwLifecycle(),
    provider_zero: zeroCounters(),
    generated_at: new Date(0).toISOString(),
    redaction_status: "redacted",
  };
}

function defaultEtwLifecycle(): EtwLifecycleStatusDto {
  return {
    lifecycle_ref: "etw_lifecycle_ref",
    ownership_ref: "servicehost_provider_controller",
    ownership_epoch: 1,
    schema_version: { major: 1, minor: 0, patch: 0 },
    lifecycle_state: "inactive",
    session_state: "not_created",
    authorization_state: "required",
    session_generation: 0,
    control_thread_active: false,
    control_thread_joined: false,
    trace_session_created: false,
    provider_enabled: false,
    collection_started: false,
    consumer_started: false,
    consumer_worker_active: false,
    consumer_worker_joined: false,
    raw_event_count: 0,
    normalized_event_count: 0,
    dropped_event_count: 0,
    rate_limited_event_count: 0,
    schema_rejected_event_count: 0,
    published_batch_count: 0,
    eventbus_publication_count: 0,
    security_fact_count: 0,
    activation_count: 0,
    pause_count: 0,
    resume_count: 0,
    stop_count: 0,
    fallback_state: "ip_helper_available",
    degraded_reason: "explicit_authorization_required",
    authorization_refs: [],
    audit_refs: ["etw_lifecycle_initialized"],
    provenance_refs: ["servicehost_etw_lifecycle_runtime"],
    updated_at: new Date(0).toISOString(),
    redaction_status: "redacted",
  };
}

function defaultIpHelperSchedule(): IpHelperScheduleStatusDto {
  return {
    schema_version: { major: 1, minor: 0, patch: 0 },
    schedule_ref: "ip_helper_schedule_ref",
    provider_category: "ip_helper",
    scheduler_owner_ref: "servicehost_scheduler_controller",
    ownership_epoch: 1,
    schedule_state: "not_configured",
    enabled_marker: false,
    paused_marker: false,
    config: {
      interval_bucket: "one_minute",
      provider_timeout_bucket: "two_hundred_fifty_millis",
      execution_timeout_bucket: "one_second",
      retry_budget_bucket: "one",
      retry_delay_bucket: "five_seconds",
      maximum_records: 128,
      maximum_bytes: 131_072,
      no_overlap_marker: true,
      no_catch_up_marker: true,
    },
    session_bound_marker: true,
    restart_disabled_marker: true,
    policy_id: "mutation_policy_configure_ip_helper_schedule",
    policy_version: { major: 1, minor: 0, patch: 0 },
    authorization_refs: [],
    lease_state: "no_lease",
    schedule_lease_ref: null,
    scheduler_registration: "configured",
    timer_runtime_active: false,
    next_due_category: "not_running",
    execution_count_bucket: "zero",
    skipped_count_bucket: "zero",
    automatic_provider_calls: 0,
    scheduler_triggered_provider_calls: 0,
    latest_manual_sample_ref: null,
    latest_scheduled_cycle_ref: null,
    latest_scheduled_execution_result: "not_started",
    latest_scheduled_cycle: null,
    manual_sample_count_bucket: "zero",
    scheduled_sample_count_bucket: "zero",
    retry_count_bucket: "zero",
    timeout_count_bucket: "zero",
    overlap_skip_count_bucket: "zero",
    backpressure_state: "none",
    freshness_state: "unavailable",
    missed_sample_state: "blocked",
    schedule_lease_valid: false,
    created_time_bucket: new Date(0).toISOString(),
    updated_time_bucket: new Date(0).toISOString(),
    audit_refs: ["ip_helper_schedule_not_configured"],
    provenance_id: "servicehost_ip_helper_schedule_control_plane",
    redaction_status: "redacted",
    degraded_reason: "schedule_not_configured",
  };
}

function provider(
  providerKind: NetworkProviderStatusDto["provider_kind"],
  implementationState: NetworkProviderStatusDto["implementation_state"],
): NetworkProviderStatusDto {
  return {
    provider_id: `network_provider_${providerKind}`,
    provider_kind: providerKind,
    adapter_boundary: adapterBoundary(providerKind),
    implementation_state: implementationState,
    lifecycle_state: "inactive",
    activation_allowed:
      providerKind === "ip_helper" ||
      providerKind === "etw_network" ||
      providerKind === "windows_dns",
    activation_unavailable_reason:
      providerKind === "ip_helper" ||
      providerKind === "etw_network" ||
      providerKind === "windows_dns"
        ? null
        : "provider_execution_deferred",
    degraded_reason: null,
    dependency_refs: [`dependency_ref_${providerKind}`],
    policy_refs: [`policy_ref_${providerKind}`],
    provenance_refs: ["provider_controller_foundation"],
    bounded_counters: zeroCounters(),
    redaction_status: "redacted",
  };
}

function adapterBoundary(providerKind: NetworkProviderStatusDto["provider_kind"]) {
  if (providerKind === "ip_helper") {
    return "infrastructure";
  }
  if (providerKind === "etw_network" || providerKind === "windows_dns") {
    return "infrastructure";
  }
  if (providerKind === "portable_metadata") {
    return "portable_default_metadata";
  }
  if (providerKind === "none") {
    return "none";
  }
  return "deferred_infrastructure";
}

function zeroCounters() {
  return {
    ip_helper_calls: 0,
    etw_calls: 0,
    dns_sensing_calls: 0,
    dns_observation_publications: 0,
    dns_detector_invocations: 0,
    dns_detector_consumed: 0,
    npcap_probes: 0,
    capture_broker_launches: 0,
    native_network_topic_publications: 0,
    process_network_facts: 0,
    packet_facts: 0,
  };
}
