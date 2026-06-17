import { afterEach, describe, expect, it } from "vitest";
import * as mutations from "./mutations";
import { setInvokeCoreForTests } from "./tauri/invoke";

const MUTATION_CASES = [
  ["enable_plugin", mutations.enablePlugin],
  ["disable_plugin", mutations.disablePlugin],
  ["restart_plugin", mutations.restartPlugin],
  ["suppress_finding", mutations.suppressFinding],
  ["dismiss_finding", mutations.dismissFinding],
  ["escalate_alert", mutations.escalateAlert],
  ["update_incident_status", mutations.updateIncidentStatus],
  ["create_response_plan", mutations.createResponsePlan],
  ["approve_response_action", mutations.approveResponseAction],
  ["reject_response_action", mutations.rejectResponseAction],
  ["rollback_response_action", mutations.rollbackResponseAction],
  ["generate_incident_report", mutations.generateIncidentReport],
  ["export_report", mutations.exportReport],
  ["start_local_metadata_proxy", mutations.startLocalMetadataProxy],
  ["preview_portable_capture_import", mutations.previewPortableCaptureImport],
  ["preview_metadata_watch_source", mutations.previewMetadataWatchSource],
  ["update_metadata_watch_source", mutations.updateMetadataWatchSource],
  ["tick_metadata_watch_controller", mutations.tickMetadataWatchController],
  ["update_metadata_sampling_loop", mutations.updateMetadataSamplingLoop],
  ["run_metadata_sampling_loop", mutations.runMetadataSamplingLoop],
  ["preview_explicit_export", mutations.previewExplicitExport],
  ["apply_runtime_profile", mutations.applyRuntimeProfile],
  ["update_privacy_policy", mutations.updatePrivacyPolicy],
  ["update_response_policy", mutations.updateResponsePolicy],
  ["enable_forensic_mode", mutations.enableForensicMode],
  ["disable_forensic_mode", mutations.disableForensicMode],
  ["update_llm_alert_story_settings", mutations.updateLlmAlertStorySettings],
  ["save_llm_alert_story_api_key", mutations.saveLlmAlertStoryApiKey],
  ["clear_llm_alert_story_api_key", mutations.clearLlmAlertStoryApiKey],
  ["test_llm_alert_story_connection", mutations.testLlmAlertStoryConnection],
  ["generate_llm_alert_story", mutations.generateLlmAlertStory],
  ["update_native_permission", mutations.updateNativePermission],
  ["apply_native_scheduler_action", mutations.applyNativeSchedulerAction],
] as const;

const NO_REQUEST_MUTATION_CASES = [
  ["run_demo_story", mutations.runDemoStory],
  ["get_local_metadata_proxy_status", mutations.getLocalMetadataProxyStatus],
  ["stop_local_metadata_proxy", mutations.stopLocalMetadataProxy],
  ["drain_local_metadata_proxy", mutations.drainLocalMetadataProxy],
  [
    "preview_native_scheduler_host_start",
    mutations.previewNativeSchedulerHostStart,
  ],
  ["start_native_scheduler_host", mutations.startNativeSchedulerHost],
  ["pause_native_scheduler_host", mutations.pauseNativeSchedulerHost],
  ["resume_native_scheduler_host", mutations.resumeNativeSchedulerHost],
  ["wake_native_scheduler_host", mutations.wakeNativeSchedulerHost],
  ["stop_native_scheduler_host", mutations.stopNativeSchedulerHost],
] as const;
const CUSTOM_MUTATION_CASES = [
  [
    "preview_native_permission_request",
    () => mutations.previewNativePermissionRequest("native_host_visibility"),
  ],
  [
    "preview_native_scheduler_enablement",
    () => mutations.previewNativeSchedulerEnablement("process_metadata_sampler"),
  ],
  [
    "save_portable_preferences",
    () => mutations.savePortablePreferences({ theme: "dark" }),
  ],
  [
    "confirm_portable_capture_import",
    () =>
      mutations.confirmPortableCaptureImport({
        preview_id: "preview-redacted",
        user_confirmed: true,
        reason_redacted: "portable metadata import confirmed",
        requested_by_redacted: "local operator",
      }),
  ],
  [
    "confirm_metadata_watch_source",
    () =>
      mutations.confirmMetadataWatchSource({
        preview_id: "watch-preview-redacted",
        user_confirmed: true,
        reason_redacted: "metadata watch confirmed",
        requested_by_redacted: "local operator",
      }),
  ],
  [
    "confirm_explicit_export",
    () =>
      mutations.confirmExplicitExport({
        export_id: "export-redacted",
        user_confirmed: true,
        confirmed_at: "2026-06-05T00:00:00Z",
      }),
  ],
] as const;

describe("mutation commands", () => {
  afterEach(() => {
    setInvokeCoreForTests(null);
  });

  it("routes Task 210 mutations through the safe invoke bridge", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    setInvokeCoreForTests(async <T,>(
      command: string,
      args?: Record<string, unknown>,
    ): Promise<T> => {
      calls.push({ command, args });
      return {
        command,
        result: {},
        permission_decision: {},
        audit_receipt: {},
        trace_id: "trace-redacted",
        rollback: null,
        generated_at: "2026-06-03T00:00:00Z",
      } as T;
    });

    for (const [, invoke] of MUTATION_CASES) {
      await invoke({ reason_redacted: "bridge route test" } as never);
    }
    for (const [, invoke] of NO_REQUEST_MUTATION_CASES) {
      await invoke();
    }
    for (const [, invoke] of CUSTOM_MUTATION_CASES) {
      await invoke();
    }

    expect(calls.map((call) => call.command)).toEqual(
      [
        ...MUTATION_CASES.map(([command]) => command),
        ...NO_REQUEST_MUTATION_CASES.map(([command]) => command),
        ...CUSTOM_MUTATION_CASES.map(([command]) => command),
      ],
    );
    expect(
      calls
        .slice(0, MUTATION_CASES.length)
        .every((call) => call.args && "request" in call.args),
    ).toBe(true);
    expect(calls[MUTATION_CASES.length]?.args).toBeUndefined();
    expect(calls.at(-4)?.args).toEqual({ preferences: { theme: "dark" } });
    expect(calls.at(-3)?.args).toEqual({
      confirmation: {
        preview_id: "preview-redacted",
        user_confirmed: true,
        reason_redacted: "portable metadata import confirmed",
        requested_by_redacted: "local operator",
      },
    });
    expect(calls.at(-2)?.args).toEqual({
      confirmation: {
        preview_id: "watch-preview-redacted",
        user_confirmed: true,
        reason_redacted: "metadata watch confirmed",
        requested_by_redacted: "local operator",
      },
    });
    expect(calls.at(-1)?.args).toEqual({
      confirmation: {
        export_id: "export-redacted",
        user_confirmed: true,
        confirmed_at: "2026-06-05T00:00:00Z",
      },
    });
  });
});
