import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { ServiceStatusViewDto } from "../../../bridge/dto/platform";
import type {
  LlmAlertStoryStatusDto,
  RuntimeProfileDto,
} from "../../../bridge/dto/settings";
import { queryKeys } from "../../../bridge/queryKeys";
import { SettingsPage } from "../../../pages/settings/SettingsPage";
import {
  AuthorizedNativeControlsPanel,
  LlmAlertStoryPanel,
  PrivacySettingsPanel,
  RuntimeProfileForm,
  ServiceStatusPanel,
} from "./SettingsWorkspace";

describe("Settings workspace panels", () => {
  it("renders runtime and privacy defaults without exposing sensitive strings", () => {
    const profile: RuntimeProfileDto = {
      display_name: "api_key runtime profile",
      privacy_policy: {
        storage_mode: "local_only",
        cloud_sync_enabled: false,
        security_telemetry_enabled: false,
        raw_packet_storage_enabled: false,
        payload_storage_enabled: false,
        http_body_storage_enabled: false,
        cookie_token_credential_storage_enabled: false,
        forensic_mode: {
          enabled: false,
          max_ttl_seconds: 1800,
        },
      },
      response_policy: {
        mode: "recommend_only",
      },
      report_export_policy: {
        require_redaction: true,
      },
    };

    const markup = [
      renderToStaticMarkup(
        <RuntimeProfileForm profile={profile} />,
      ),
      renderToStaticMarkup(
        <PrivacySettingsPanel profile={profile} />,
      ),
    ].join("");

    expect(markup).toContain("Runtime profile");
    expect(markup).toContain("Privacy &amp; data");
    expect(markup).toContain("Forensic mode must be explicit");
    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("api_key runtime profile");
  });

  it("redacts service status messages and keeps reduced visibility visible", () => {
    const serviceStatus: ServiceStatusViewDto = {
      connected: false,
      degraded: true,
      reason: "service_unreachable",
      profile_mode: "ephemeral",
      local_core_status: "healthy",
      elevated_service_status: "disconnected",
      ipc_status: "disconnected",
      storage_status: "unknown",
      reduced_visibility: true,
      privileged_actions_available: false,
      capture_available: false,
      message_redacted: "session_token service message",
      generated_at: "pending",
    };

    const markup = renderToStaticMarkup(
      <ServiceStatusPanel
        loading={false}
        serviceStatus={serviceStatus}
      />,
    );

    expect(markup).toContain("Service status");
    expect(markup).toContain("Reduced visibility");
    expect(markup).toContain("Active");
    expect(markup).toContain("[redacted]");
    expect(markup).not.toContain("session_token service message");
  });

  it("renders mutation authorization as narrow IP Helper execution without operation controls", () => {
    const serviceStatus: ServiceStatusViewDto = {
      connected: true,
      degraded: false,
      profile_mode: "service-owned",
      local_core_status: "healthy",
      elevated_service_status: "healthy",
      ipc_status: "healthy",
      storage_status: "healthy",
      reduced_visibility: false,
      privileged_actions_available: false,
      capture_available: false,
      mutation_authorization_status: {
        schema_version: { major: 1, minor: 0, patch: 0 },
        framework_state: "implemented_narrow_execution",
        policy_catalog_version: { major: 1, minor: 0, patch: 0 },
        supported_command_count: 35,
        dry_run_only: false,
        production_execution_enabled: true,
        last_decision_category: "approved_for_execution",
        denied_count_bucket: "zero",
        expired_count_bucket: "zero",
        replay_count_bucket: "zero",
        caller_trust_ready: true,
        ownership_runtime_ready: true,
        degraded_reasons: [],
        audit_refs: ["mutation_authorization_audit"],
        provenance_id: "servicehost_mutation_authorization",
        redaction_status: "redacted",
      },
      message_redacted: "Service-owned runtime is available",
      generated_at: "pending",
    };

    const markup = renderToStaticMarkup(
      <ServiceStatusPanel loading={false} serviceStatus={serviceStatus} />,
    );

    expect(markup).toContain("Mutation Authorization");
    expect(markup).toContain("Mutation policy evaluation is available");
    expect(markup).toContain("narrow execution enabled only for explicit IP Helper");
    expect(markup).not.toContain("<button");
  });

  it("renders machine-local capability status without raw system details", () => {
    const serviceStatus: ServiceStatusViewDto = {
      connected: false,
      degraded: true,
      reason: "service_unreachable",
      profile_mode: "portable-no-retention",
      local_core_status: "healthy",
      elevated_service_status: "disconnected",
      ipc_status: "disconnected",
      storage_status: "healthy",
      reduced_visibility: true,
      privileged_actions_available: false,
      capture_available: false,
      machine_local_capability_status: {
        all_available: false,
        degraded_count: 0,
        unavailable_count: 1,
        requires_setup_count: 1,
        detected_at: "2026-06-05T00:00:00Z",
        capabilities: [
          {
            capability: "elevated_service",
            status: "unavailable",
            reason: "elevated service did not respond on this machine",
            action: null,
          },
          {
            capability: "installer_service_registration",
            status: "requires_setup",
            reason: null,
            action: "Install the Sentinel Guard elevated service on this machine",
          },
        ],
      },
      message_redacted: "portable service status",
      generated_at: "pending",
    };

    const markup = renderToStaticMarkup(
      <ServiceStatusPanel
        loading={false}
        serviceStatus={serviceStatus}
      />,
    );

    expect(markup).toContain("Machine-local capabilities not configured");
    expect(markup).toContain("Setup needed");
    expect(markup).toContain("Not available");
    expect(markup).not.toContain("C:\\");
    expect(markup).not.toContain("session_token");
  });

  it("renders honest loading states without fallback profile or service records", () => {
    const markup = renderToStaticMarkup(withQueryClient(<SettingsPage />));

    expect(markup).toContain("Loading runtime profile");
    expect(markup).toContain("Loading service status");
    expect(markup).not.toContain(mockOnlyMarker());
    expect(markup).not.toContain("Safe Default");
  });

  it("renders command profile, service status, and machine-local capabilities", () => {
    const profile = commandProfile();
    const serviceStatus = commandServiceStatus();
    const markup = renderToStaticMarkup(
      withQueryClient(<SettingsPage />, (queryClient) => {
        queryClient.setQueryData(queryKeys.settings.runtime, profile);
        queryClient.setQueryData(queryKeys.settings.service, serviceStatus);
      }),
    );

    expect(markup).toContain("Command-backed balanced profile");
    expect(markup).toContain("Portable-no-retention");
    expect(markup).toContain("Admin required");
    expect(markup).toContain("Setup needed");
    expect(markup).toContain("Read-only local metadata is available");
    expect(markup).not.toContain(mockOnlyMarker());
  });

  it("renders command-backed LLM alert-story status without exposing API keys", () => {
    const llmStatus = commandLlmAlertStoryStatus();

    const markup = renderToStaticMarkup(
      withQueryClient(<LlmAlertStoryPanel />, (queryClient) => {
        queryClient.setQueryData(queryKeys.settings.llmAlertStory, llmStatus);
      }),
    );

    expect(markup).toContain("LLM alert story");
    expect(markup).toContain("Authorized");
    expect(markup).toContain("OpenAI");
    expect(markup).toContain("DeepSeek");
    expect(markup).toContain("Anthropic-compatible");
    expect(markup).toContain("Configured");
    expect(markup).toContain("Write-only API key");
    expect(markup).toContain("Generate story");
    expect(markup).toContain("Session only");
    expect(markup).not.toContain("OS keystore");
    expect(markup).not.toContain("sk-test-secret");
  });

  it("discloses stale service data and an empty capability summary", () => {
    const serviceStatus = commandServiceStatus();
    serviceStatus.machine_local_capability_status = {
      all_available: false,
      degraded_count: 0,
      unavailable_count: 0,
      requires_setup_count: 0,
      detected_at: "2026-06-06T00:00:00Z",
      capabilities: [],
    };

    const markup = renderToStaticMarkup(
      <ServiceStatusPanel error loading={false} serviceStatus={serviceStatus} />,
    );

    expect(markup).toContain(
      "service status refresh; cached command data is shown",
    );
    expect(markup).toContain(
      "No machine-local capability records were returned by the command bridge.",
    );
    expect(markup).not.toContain("Machine-local capabilities not configured");
  });

  it("renders authorized native controls as session-bound and inactive", () => {
    const markup = renderToStaticMarkup(
      withQueryClient(<AuthorizedNativeControlsPanel />, (queryClient) => {
        queryClient.setQueryData(queryKeys.settings.nativeCapabilities, [
          {
            capability_id: "process_metadata_visibility",
            category: "process_metadata_visibility",
            lifecycle_state: "granted",
            availability_state: "authorized_sampler_inactive",
            permission_state: "granted_session",
            authorization_mode: "explicit_session_bound",
            access_mode: "read_only_visibility",
            enabled: true,
            revoked: false,
            health_state: "unknown",
            degraded_reason: "authorized_but_no_sampler_enabled",
            visibility_scope: "process_summary",
            portable_default_available: false,
            last_checked_time_bucket: "current_session",
            provenance_id: "authorized_native_control_plane",
            audit_refs: ["audit-ref"],
            redaction_status: "redacted",
            telemetry_collection_active: false,
            response_execution_allowed: false,
            automatic_llm_calls: false,
          },
        ]);
        queryClient.setQueryData(queryKeys.settings.nativePermission, {
          granted_inactive_count: 1,
          session_bound_authorization: true,
        });
        queryClient.setQueryData(queryKeys.settings.nativeVisibility, {
          future_sampler_ready: false,
          native_required_attack_coverage_supported: false,
        });
        queryClient.setQueryData(queryKeys.settings.nativeAudit, {
          audit_refs: ["audit-ref"],
        });
        queryClient.setQueryData(queryKeys.settings.nativeSamplerContracts, [
          {
            contract_id: "contract-ref",
            sampler_id: "process_metadata_sampler",
            category: "process_metadata_sampler",
            required_capability_id: "process_metadata_visibility",
            required_permission_state: "granted_session",
            authorization_mode: "explicit_session_bound_future_activation",
            read_only: true,
            response_capable: false,
            readiness_state: "ready_when_sampler_implemented",
            supported_platform: "windows_native_extension_future",
            portable_default_available: false,
            sampling_mode: "read_only_snapshot_metadata",
            max_records_per_tick: 128,
            max_bytes_per_tick: 65536,
            output_fact_categories: ["endpoint_process_category_fact"],
            declared_event_topics: ["native.sampler.readiness"],
            redaction_policy_id: "native_sampler_redacted_categories_only",
            privacy_boundary: "bounded_endpoint_metadata_future",
            retention_mode: "no_raw_retention",
            visibility_scope: "process_summary",
            schema: {
              schema_id: "schema-ref",
              schema_version: { major: 1, minor: 0, patch: 0 },
              field_categories: ["process_category"],
              declared_field_labels: ["process_category"],
              output_fact_categories: ["endpoint_process_category_fact"],
              declared_only: true,
              raw_fields_allowed: false,
              redaction_status: "redacted",
            },
            degraded_reason: "ready_but_sampler_not_implemented",
            missing_prerequisite_flags: ["sampler_runtime_not_implemented"],
            audit_refs: ["audit-ref"],
            provenance_id: "native_sampler_readiness_catalog",
            redaction_status: "redacted",
            privacy_class: "internal",
            last_reviewed_time_bucket: "current_session",
            sampler_implemented: false,
            sampler_active: false,
            telemetry_collection_active: false,
            response_execution_allowed: false,
            automatic_llm_calls: false,
          },
        ]);
        queryClient.setQueryData(queryKeys.settings.nativeSamplerReadiness, {
          contract_count: 1,
          review_count: 1,
          ready_when_implemented_count: 1,
          blocked_count: 0,
          degraded_count: 0,
          not_implemented_count: 1,
          active_sampler_count: 0,
          future_collection_allowed_count: 1,
          future_response_allowed_count: 0,
          endpoint_security_facts_emitted: false,
          telemetry_collection_active: false,
          response_execution_allowed: false,
          automatic_llm_calls: false,
          portable_default_active: true,
          no_telemetry_collected: true,
          contract_refs: ["process_metadata_sampler"],
          review_refs: ["review-ref"],
          audit_refs: ["audit-ref"],
          missing_endpoint_visibility_flags: ["sampler_runtime_not_implemented"],
          degraded_reasons: ["ready_but_sampler_not_implemented"],
          generated_at: "now",
        });
        queryClient.setQueryData(queryKeys.settings.futureSecurityFactMappings, {
          mappings: [
            {
              mapping_id: "mapping-ref",
              sampler_id: "process_metadata_sampler",
              sampler_category: "process_metadata_sampler",
              output_fact_category: "endpoint_process_category_fact",
              declared_field_categories: ["process_category"],
              declared_only: true,
              emits_security_facts_now: false,
              quality_gate_required: true,
              visibility_gate_required: true,
              report_export_suitability_gate: true,
              forbidden_raw_fields_rejected: true,
              provenance_id: "native_sampler_readiness_catalog",
              schema_version: { major: 1, minor: 0, patch: 0 },
              redaction_status: "redacted",
            },
          ],
          mapping_count: 1,
          emitted_security_fact_count: 0,
          sampler_refs: ["process_metadata_sampler"],
          generated_at: "now",
        });
        queryClient.setQueryData(queryKeys.settings.nativeSamplerBlocked, {
          blocked_count: 0,
          blocked_sampler_refs: [],
          blocked_reasons: [],
          revoked_sampler_refs: [],
          disabled_sampler_refs: [],
          unsafe_schema_sampler_refs: [],
          response_capable_sampler_refs: [],
          generated_at: "now",
        });
        queryClient.setQueryData(queryKeys.settings.missingEndpointVisibility, {
          missing_visibility_flags: ["sampler_runtime_not_implemented"],
          sampler_refs: ["process_metadata_sampler"],
          degraded_reasons: ["ready_but_sampler_not_implemented"],
          endpoint_required_hypotheses_degraded: true,
          native_attack_rows_supported: false,
          edr_coverage_claimed: false,
          generated_at: "now",
        });
        queryClient.setQueryData(queryKeys.settings.edrReadiness, {
          contract_ready_count: 1,
          readiness_approved_count: 1,
          implemented_sampler_count: 0,
          active_sampler_count: 0,
          blocked_sampler_count: 0,
          telemetry_collection_active: false,
          response_execution_allowed: false,
          endpoint_security_facts_emitted: false,
          edr_coverage_claimed: false,
          portable_default_active: true,
          no_telemetry_collected: true,
          sampler_refs: ["process_metadata_sampler"],
          audit_refs: ["audit-ref"],
          missing_endpoint_visibility: {
            missing_visibility_flags: ["sampler_runtime_not_implemented"],
            sampler_refs: ["process_metadata_sampler"],
            degraded_reasons: ["ready_but_sampler_not_implemented"],
            endpoint_required_hypotheses_degraded: true,
            native_attack_rows_supported: false,
            edr_coverage_claimed: false,
            generated_at: "now",
          },
          generated_at: "now",
        });
        queryClient.setQueryData(queryKeys.settings.nativeSchedulerOperational, {
          scheduler_health: "idle",
          status: {
            controller_state: "ready",
            periodic_sampling_enabled: false,
            enabled_schedule_count: 0,
            eligible_schedule_count: 1,
            revoked_schedule_count: 0,
            scheduling_loop_implemented: true,
            scheduling_loop_active: false,
            backpressure_state: "none",
            backpressure_cycle_count: 0,
            latest_backpressure_cycle_id: null,
            freshness_stale_dimension_count: 0,
            freshness_missing_dimension_count: 1,
            missed_sample_dimension_count: 0,
            latest_freshness_cycle_id: "cycle-ref",
            latest_missed_sample_cycle_id: "cycle-ref",
            periodic_execution_started: false,
            sample_requested: false,
            retry_execution_started: false,
            graceful_shutdown_requested: false,
            cycle_count: 1,
            completed_cycle_count: 0,
            skipped_cycle_count: 1,
            latest_cycle_id: "cycle-ref",
            last_tick_monotonic_millis: 1000,
            automatic_llm_calls: false,
            response_execution_started: false,
            emitted_topics: ["native.scheduler.status"],
            audit_refs: ["audit-ref"],
            provenance_id: "native_scheduler_controller",
            redaction_status: "redacted",
            generated_at: "now",
          },
          safe_persisted_schedules: [
            {
              sampler_id: "process_metadata_sampler",
              sampler_category: "process_metadata_sampler",
              schedule_enabled: false,
              interval_bucket: "five_minutes",
              timeout_bucket: "five_seconds",
              retry_budget_bucket: "one",
              provenance_id: "native_scheduler_controller",
              redaction_status: "redacted",
            },
          ],
          freshness_summary: {
            cycle_id: "cycle-ref",
            monotonic_elapsed_millis: 1000,
            worst_freshness_state: "missing",
            dimensions: [],
            fresh_dimension_count: 0,
            aging_dimension_count: 0,
            stale_dimension_count: 0,
            missing_dimension_count: 1,
            unavailable_dimension_count: 0,
            revoked_dimension_count: 0,
            emitted_topics: ["native.scheduler.freshness"],
            provenance_id: "native_scheduler_controller",
            redaction_status: "redacted",
            attack_finding_generation_started: false,
            automatic_llm_calls: false,
            response_execution_started: false,
          },
          missed_sample_summary: {
            cycle_id: "cycle-ref",
            monotonic_elapsed_millis: 1000,
            dimensions: [],
            delayed_dimension_count: 0,
            missed_once_dimension_count: 0,
            repeatedly_missed_dimension_count: 0,
            paused_dimension_count: 0,
            blocked_dimension_count: 0,
            revoked_dimension_count: 0,
            emitted_topics: ["native.scheduler.missed_sample"],
            provenance_id: "native_scheduler_controller",
            redaction_status: "redacted",
            attack_finding_generation_started: false,
            automatic_llm_calls: false,
            response_execution_started: false,
          },
          retry_summary: {
            retry_scheduled_count: 0,
            retry_exhausted_count: 0,
            retry_pending_sampler_count: 0,
            latest_execution_control_cycle_id: "cycle-ref",
            retrying_sampler_ids: [],
            provenance_id: "native_scheduler_controller",
            redaction_status: "redacted",
            automatic_llm_calls: false,
            response_execution_started: false,
          },
          backpressure_summary: {
            cycle_id: "cycle-ref",
            state: "none",
            active_task_count: 0,
            pending_due_task_count: 0,
            event_bus_backlog_count: 0,
            dag_backlog_count: 0,
            timeout_rate_bucket: "none",
            overlap_skip_rate_bucket: "none",
            defer_low_priority_samplers: false,
            skip_cycle: false,
            pause_degraded_samplers: false,
            deferred_sampler_ids: [],
            paused_sampler_ids: [],
            emitted_topics: ["native.scheduler.backpressure"],
            provenance_id: "native_scheduler_controller",
            redaction_status: "redacted",
            automatic_llm_calls: false,
            response_execution_started: false,
          },
          scheduler_refs: ["cycle-ref"],
          freshness_refs: ["cycle-ref"],
          missed_sample_refs: ["cycle-ref"],
          quality_refs: ["quality-ref"],
          safe_persistence_only: true,
          raw_native_data_persisted: false,
          runtime_subject_persisted: false,
          source_location_persisted: false,
          launch_text_persisted: false,
          machine_identifier_persisted: false,
          scheduler_enablement_started: false,
          provider_refresh_started: false,
          automatic_llm_calls: false,
          response_execution_started: false,
          generated_at: "now",
        });
        queryClient.setQueryData(queryKeys.settings.nativeSchedulerHostStatus, {
          orchestrator_id: "session_native_scheduler_host",
          controller_id: "native_scheduler_controller",
          lifecycle_state: "stopped",
          health_state: "stopped",
          wake_state: "idle",
          latest_wake_reason: "status_reconciliation",
          enabled_sampler_count_bucket: "none",
          eligible_sampler_count_bucket: "none",
          next_wake_bucket: "not_running",
          last_wake_bucket: null,
          last_tick_ref: null,
          latest_cycle_ref: null,
          successful_wake_count_bucket: "none",
          no_op_wake_count_bucket: "none",
          degraded_wake_count_bucket: "none",
          cancelled_wake_count_bucket: "none",
          restart_count_bucket: "none",
          manual_cycle_count_bucket: "none",
          autonomous_cycle_count_bucket: "none",
          watchdog_state: "stopped",
          shutdown_state: "completed",
          degraded_reason: null,
          timer_task_active: false,
          task_ownership_state: "released",
          current_wait_state: "inactive",
          pending_wake: false,
          cancellation_state: "none",
          join_state: "joined",
          join_timeout_category: null,
          shutdown_cleanup_status: "completed",
          audit_refs: [],
          provenance_id: "native_scheduler_host_orchestrator",
          redaction_status: "redacted",
          host_task_owned: false,
          singleton_owner: true,
          startup_auto_started: false,
          os_service_started: false,
          provider_direct_calls: false,
          automatic_llm_calls: false,
          response_execution_started: false,
          generated_at: "now",
        });
        queryClient.setQueryData(queryKeys.settings.nativeSchedulerHostHealth, {
          status: queryClient.getQueryData(
            queryKeys.settings.nativeSchedulerHostStatus,
          ),
          latest_cycle: null,
          latest_wake_reason: "status_reconciliation",
          watchdog_state: "stopped",
          shutdown_state: "completed",
          delayed_wake_count_bucket: "none",
          no_op_wake_count_bucket: "none",
          degraded_wake_count_bucket: "none",
          successful_wake_count_bucket: "none",
          session_bound: true,
          startup_auto_run: false,
          os_service: false,
          automatic_llm_calls: false,
          response_execution_started: false,
          generated_at: "now",
        });
      }),
    );

    expect(markup).toContain("Authorized native security controls");
    expect(markup).toContain("Granted but inactive");
    expect(markup).toContain("Grant inactive");
    expect(markup).toContain("never starts a native sampler");
    expect(markup).toContain("Native sampler readiness review");
    expect(markup).toContain("No telemetry collected");
    expect(markup).toContain("Continuous Sampling");
    expect(markup).toContain("Tick-driven native scheduling");
    expect(markup).toContain("Periodic execution");
    expect(markup).toContain("Backpressure");
    expect(markup).toContain("Freshness");
    expect(markup).toContain("Scheduler health");
    expect(markup).toContain("Safe persistence");
    expect(markup).toContain("Missed samples");
    expect(markup).toContain("Retry summary");
    expect(markup).toContain("Report traceability");
    expect(markup).toContain("Autonomous Host");
    expect(markup).toContain("Start autonomous monitoring");
    expect(markup).toContain("not an OS service");
    expect(markup).toContain("Readiness-approved");
    expect(markup).not.toContain("C:\\");
    expect(markup).not.toContain("session_token");
    expect(markup).not.toContain("command_line");
  });
});

function withQueryClient(
  element: ReactElement,
  seed?: (queryClient: QueryClient) => void,
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  seed?.(queryClient);
  return <QueryClientProvider client={queryClient}>{element}</QueryClientProvider>;
}

function commandProfile(): RuntimeProfileDto {
  return {
    profile_id: "profile:command",
    name: "balanced",
    display_name: "Command-backed balanced profile",
    is_default: true,
    privacy_policy: {
      storage_mode: "local_only",
      cloud_sync_enabled: false,
      security_telemetry_enabled: false,
      raw_packet_storage_enabled: false,
      payload_storage_enabled: false,
      http_body_storage_enabled: false,
      cookie_token_credential_storage_enabled: false,
      forensic_mode: {
        enabled: false,
        max_ttl_seconds: 1800,
      },
    },
    response_policy: {
      mode: "recommend_only",
    },
    report_export_policy: {
      require_redaction: true,
    },
  };
}

function commandServiceStatus(): ServiceStatusViewDto {
  return {
    connected: false,
    degraded: true,
    reason: "service_unreachable",
    profile_mode: "portable-no-retention",
    local_core_status: "healthy",
    elevated_service_status: "disconnected",
    ipc_status: "disconnected",
    storage_status: "healthy",
    reduced_visibility: true,
    privileged_actions_available: false,
    capture_available: false,
    machine_local_capability_status: {
      all_available: false,
      degraded_count: 0,
      unavailable_count: 1,
      requires_setup_count: 1,
      detected_at: "2026-06-06T00:00:00Z",
      capabilities: [
        {
          capability: "elevated_service",
          status: "requires_admin",
          reason: "Service probe requires an elevated shell",
          action: null,
        },
        {
          capability: "packet_capture",
          status: "requires_setup",
          reason: null,
          action: "Configure a supported metadata capture adapter",
        },
      ],
    },
    message_redacted: "Read-only local metadata is available",
    generated_at: "2026-06-06T00:00:00Z",
  };
}

function commandLlmAlertStoryStatus(): LlmAlertStoryStatusDto {
  return {
    settings: {
      enabled: true,
      provider: "open_ai_compatible",
      model: "gpt-5.4-mini",
      api_key_storage_mode: "session_only",
      authorization_granted: true,
      timeout_seconds: 20,
    },
    api_key_configured: true,
    capability_status: "authorized",
    os_keystore_supported: false,
    last_successful_check: "2026-06-11T00:00:00Z",
    last_successful_generation: "2026-06-11T00:01:00Z",
    last_story_id: "story-ref",
    story_count: 1,
    base_url_configured: false,
    last_error_code: null,
    warning_redacted:
      "Redacted alert summaries may be sent to the configured provider when this optional feature is enabled.",
    generated_at: "2026-06-11T00:00:00Z",
  };
}

function mockOnlyMarker() {
  return ["MOCK", "ONLY"].join("_");
}
