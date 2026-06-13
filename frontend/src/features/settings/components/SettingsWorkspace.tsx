import {
  AlertTriangle,
  Bug,
  FileText,
  Globe,
  KeyRound,
  Lock,
  Network,
  Radio,
  Server,
  Settings,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
} from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";
import type { JsonValue } from "../../../bridge/dto/common";
import type { ServiceStatusViewDto } from "../../../bridge/dto/platform";
import type {
  AuthorizedNativeCapabilityStatusDto,
  LlmAlertStoryStatusDto,
  NativePermissionActionDto,
  NativeSamplerContractDto,
  NativeSamplerRuntimeActionDto,
  NativeSamplerRuntimeStatusDto,
  NativeSamplerScheduleStatusDto,
  NativeSchedulerActionDto,
  RuntimeProfileDto,
} from "../../../bridge/dto/settings";
import { useSelectionStore } from "../../../stores/selectionStore";
import { useUiStore, type PixelPetSize } from "../../../stores/uiStore";
import { EmptyState } from "../../../shared/layout/EmptyState";
import { humanize, isRecord, stringifySafe } from "../../../shared/renderers";
import {
  useClearLlmAlertStoryApiKeyMutation,
  useAuthorizedNativeCapabilitiesQuery,
  useGenerateLlmAlertStoryMutation,
  useLlmAlertStoriesQuery,
  useLlmAlertStoryStatusQuery,
  useSaveLlmAlertStoryApiKeyMutation,
  useTestLlmAlertStoryConnectionMutation,
  useRuntimeProfileQuery,
  useSettingsServiceStatusQuery,
  useNativePermissionAuditSummaryQuery,
  useNativePermissionStatusQuery,
  useNativeSamplerBlockedSummaryQuery,
  useNativeSamplerContractsQuery,
  useNativeSamplerReadinessSummaryQuery,
  useNativeSamplerRuntimeSummaryQuery,
  useNativeSchedulerOperationalSummaryQuery,
  useNativeSchedulerSummaryQuery,
  useFutureSecurityFactMappingSummaryQuery,
  useMissingEndpointVisibilitySummaryQuery,
  useEdrReadinessSummaryQuery,
  useNativeVisibilitySummaryQuery,
  useApplyNativeSamplerRuntimeActionMutation,
  useApplyNativeSchedulerActionMutation,
  usePreviewNativeSamplerActivationMutation,
  usePreviewNativeSchedulerEnablementMutation,
  usePreviewNativePermissionRequestMutation,
  useUpdateNativePermissionMutation,
  useUpdateLlmAlertStorySettingsMutation,
} from "../hooks";

type SettingsSectionId =
  | "general"
  | "runtime"
  | "privacy"
  | "capture"
  | "attribution"
  | "intelligence"
  | "llm"
  | "native"
  | "api"
  | "waf"
  | "response"
  | "reports"
  | "service"
  | "advanced";

interface SettingsSection {
  readonly id: SettingsSectionId;
  readonly label: string;
  readonly status: string;
}

interface SettingRow {
  readonly label: string;
  readonly value: string;
  readonly tone?: "ok" | "warning" | "blocked" | "neutral";
  readonly detail?: string | null;
}

const SETTINGS_SECTIONS: SettingsSection[] = [
  { id: "general", label: "General", status: "local" },
  { id: "runtime", label: "Runtime Profile", status: "safe" },
  { id: "privacy", label: "Privacy & Data", status: "metadata" },
  { id: "capture", label: "Capture", status: "bounded" },
  { id: "attribution", label: "Process Attribution", status: "visible" },
  { id: "intelligence", label: "Intelligence", status: "local" },
  { id: "llm", label: "LLM Alert Story", status: "optional" },
  { id: "native", label: "Authorized Native", status: "inactive" },
  { id: "api", label: "API Security", status: "packet-only" },
  { id: "waf", label: "WAF Integration", status: "disabled" },
  { id: "response", label: "Response & Isolation", status: "recommend" },
  { id: "reports", label: "Reports & Export", status: "redacted" },
  { id: "service", label: "Service Status", status: "visible" },
  { id: "advanced", label: "Advanced / Developer", status: "quiet" },
];

export function SettingsWorkspace() {
  const runtimeProfileQuery = useRuntimeProfileQuery();
  const serviceStatusQuery = useSettingsServiceStatusQuery();
  const selectedSection = useSelectionStore((state) => state.selectedSettingsSectionId);
  const setSelectedSection = useSelectionStore(
    (state) => state.setSelectedSettingsSectionId,
  );
  const particlesEnabled = useUiStore((state) => state.particlesEnabled);
  const pixelPetEnabled = useUiStore((state) => state.pixelPetEnabled);
  const pixelPetSize = useUiStore((state) => state.pixelPetSize);
  const reducedMotion = useUiStore((state) => state.reducedMotion);
  const setParticlesEnabled = useUiStore((state) => state.setParticlesEnabled);
  const setPixelPetEnabled = useUiStore((state) => state.setPixelPetEnabled);
  const setPixelPetSize = useUiStore((state) => state.setPixelPetSize);
  const activeSection = isSettingsSectionId(selectedSection) ? selectedSection : "general";
  const profile = runtimeProfileQuery.data;
  const serviceStatus = serviceStatusQuery.data;

  useEffect(() => {
    if (!selectedSection) {
      setSelectedSection("general");
    }
  }, [selectedSection, setSelectedSection]);

  return (
    <div className="settings-workspace">
      <SettingsSectionNav
        activeSection={activeSection}
        sections={SETTINGS_SECTIONS}
        onSelectSection={setSelectedSection}
      />
      <main className="settings-main">
        <SettingsSectionPanel
          activeSection={activeSection}
          particlesEnabled={particlesEnabled}
          pixelPetEnabled={pixelPetEnabled}
          pixelPetSize={pixelPetSize}
          profile={profile}
          profileError={runtimeProfileQuery.isError}
          profileLoading={runtimeProfileQuery.isLoading}
          reducedMotion={reducedMotion}
          serviceStatus={serviceStatus}
          serviceError={serviceStatusQuery.isError}
          serviceLoading={serviceStatusQuery.isLoading}
          onParticlesEnabledChange={setParticlesEnabled}
          onPixelPetEnabledChange={setPixelPetEnabled}
          onPixelPetSizeChange={setPixelPetSize}
        />
      </main>
      <aside className="settings-detail">
        <ServiceStatusPanel
          error={serviceStatusQuery.isError}
          loading={serviceStatusQuery.isLoading}
          serviceStatus={serviceStatus}
        />
        <SettingsSafetyPanel
          error={runtimeProfileQuery.isError}
          loading={runtimeProfileQuery.isLoading}
          profile={profile}
        />
      </aside>
    </div>
  );
}

interface SettingsSectionNavProps {
  readonly activeSection: SettingsSectionId;
  readonly sections: SettingsSection[];
  readonly onSelectSection: (sectionId: SettingsSectionId) => void;
}

function SettingsSectionNav({
  activeSection,
  sections,
  onSelectSection,
}: SettingsSectionNavProps) {
  return (
    <aside className="settings-section-nav" aria-label="Settings sections">
      <div className="analysis-panel-header">
        <strong>Settings</strong>
        <span>{sections.length}</span>
      </div>
      <div className="settings-section-list">
        {sections.map((section) => (
          <button
            className="settings-section-button"
            data-selected={section.id === activeSection}
            key={section.id}
            type="button"
            onClick={() => onSelectSection(section.id)}
          >
            <SectionIcon sectionId={section.id} />
            <span>{section.label}</span>
            <small>{section.status}</small>
          </button>
        ))}
      </div>
    </aside>
  );
}

interface SettingsSectionPanelProps {
  readonly activeSection: SettingsSectionId;
  readonly onParticlesEnabledChange: (enabled: boolean) => void;
  readonly onPixelPetEnabledChange: (enabled: boolean) => void;
  readonly onPixelPetSizeChange: (size: PixelPetSize) => void;
  readonly particlesEnabled: boolean;
  readonly pixelPetEnabled: boolean;
  readonly pixelPetSize: PixelPetSize;
  readonly profile?: RuntimeProfileDto;
  readonly profileError: boolean;
  readonly profileLoading: boolean;
  readonly reducedMotion: boolean;
  readonly serviceError: boolean;
  readonly serviceLoading: boolean;
  readonly serviceStatus?: ServiceStatusViewDto;
}

function SettingsSectionPanel({
  activeSection,
  onParticlesEnabledChange,
  onPixelPetEnabledChange,
  onPixelPetSizeChange,
  particlesEnabled,
  pixelPetEnabled,
  pixelPetSize,
  profile,
  profileError,
  profileLoading,
  reducedMotion,
  serviceError,
  serviceLoading,
  serviceStatus,
}: SettingsSectionPanelProps) {
  if (
    activeSection !== "general" &&
    activeSection !== "service" &&
    activeSection !== "llm" &&
    activeSection !== "native" &&
    !profile
  ) {
    const section = SETTINGS_SECTIONS.find((candidate) => candidate.id === activeSection);
    return (
      <SettingsReadModelPanel
        error={profileError}
        icon={<SectionIcon sectionId={activeSection} />}
        loading={profileLoading}
        readModel="runtime profile"
        title={section?.label ?? "Settings"}
        wide
      />
    );
  }

  switch (activeSection) {
    case "runtime":
      return <RuntimeProfileForm profile={profile!} />;
    case "privacy":
      return <PrivacySettingsPanel profile={profile!} />;
    case "capture":
      return (
        <SettingsMatrixPanel
          icon={<Radio size={15} aria-hidden="true" />}
          rows={captureRows(profile!)}
          title="Capture"
        />
      );
    case "attribution":
      return (
        <SettingsMatrixPanel
          icon={<Network size={15} aria-hidden="true" />}
          rows={attributionRows(profile!)}
          title="Process attribution"
        />
      );
    case "intelligence":
      return (
        <SettingsMatrixPanel
          icon={<Globe size={15} aria-hidden="true" />}
          rows={intelligenceRows(profile!)}
          title="Intelligence"
        />
      );
    case "llm":
      return <LlmAlertStoryPanel />;
    case "native":
      return <AuthorizedNativeControlsPanel />;
    case "api":
      return (
        <SettingsMatrixPanel
          callout="Only API traffic hints are available from local encrypted traffic unless logs or explicit integrations are imported."
          icon={<KeyRound size={15} aria-hidden="true" />}
          rows={apiRows(profile!)}
          title="API security"
        />
      );
    case "waf":
      return (
        <SettingsMatrixPanel
          callout="WAF enforcement is disabled in the Personal PC V1 profile."
          icon={<Shield size={15} aria-hidden="true" />}
          rows={wafRows(profile!)}
          title="WAF integration"
        />
      );
    case "response":
      return (
        <SettingsMatrixPanel
          icon={<ShieldCheck size={15} aria-hidden="true" />}
          rows={responseRows(profile!)}
          title="Response & isolation"
        />
      );
    case "reports":
      return (
        <SettingsMatrixPanel
          icon={<FileText size={15} aria-hidden="true" />}
          rows={reportRows(profile!)}
          title="Reports & export"
        />
      );
    case "service":
      return (
        <ServiceStatusPanel
          error={serviceError}
          loading={serviceLoading}
          serviceStatus={serviceStatus}
          wide
        />
      );
    case "advanced":
      return (
        <SettingsMatrixPanel
          callout="Developer diagnostics stay quiet until a later diagnostics task exposes safe read models."
          icon={<Bug size={15} aria-hidden="true" />}
          rows={advancedRows(profile!)}
          title="Advanced / developer"
        />
      );
    case "general":
    default:
      return (
        <GeneralSettingsPanel
          particlesEnabled={particlesEnabled}
          pixelPetEnabled={pixelPetEnabled}
          pixelPetSize={pixelPetSize}
          profile={profile}
          profileError={profileError}
          profileLoading={profileLoading}
          reducedMotion={reducedMotion}
          onParticlesEnabledChange={onParticlesEnabledChange}
          onPixelPetEnabledChange={onPixelPetEnabledChange}
          onPixelPetSizeChange={onPixelPetSizeChange}
        />
      );
  }
}

function GeneralSettingsPanel({
  onParticlesEnabledChange,
  onPixelPetEnabledChange,
  onPixelPetSizeChange,
  particlesEnabled,
  pixelPetEnabled,
  pixelPetSize,
  profile,
  profileError,
  profileLoading,
  reducedMotion,
}: {
  readonly onParticlesEnabledChange: (enabled: boolean) => void;
  readonly onPixelPetEnabledChange: (enabled: boolean) => void;
  readonly onPixelPetSizeChange: (size: PixelPetSize) => void;
  readonly particlesEnabled: boolean;
  readonly pixelPetEnabled: boolean;
  readonly pixelPetSize: PixelPetSize;
  readonly profile?: RuntimeProfileDto;
  readonly profileError: boolean;
  readonly profileLoading: boolean;
  readonly reducedMotion: boolean;
}) {
  return (
    <SettingsMatrixPanel
      icon={<Settings size={15} aria-hidden="true" />}
      rows={generalRows(profile)}
      showCommandSource={Boolean(profile)}
      title="General"
    >
      {!profile ? (
        <SettingsReadModelNotice
          error={profileError}
          loading={profileLoading}
          readModel="runtime profile"
        />
      ) : null}
      <div className="settings-toggle-row">
        <div>
          <Sparkles size={14} aria-hidden="true" />
          <span>Ambient particles</span>
          <small>{reducedMotion ? "Reduced motion" : "Visual"}</small>
        </div>
        <button
          type="button"
          className="segmented-toggle"
          aria-pressed={particlesEnabled && !reducedMotion}
          data-selected={particlesEnabled && !reducedMotion}
          disabled={reducedMotion}
          onClick={() => onParticlesEnabledChange(!particlesEnabled)}
        >
          {particlesEnabled && !reducedMotion ? "On" : "Off"}
        </button>
      </div>
      <div className="settings-toggle-row">
        <div>
          <Sparkles size={14} aria-hidden="true" />
          <span>Desktop pet</span>
          <small>{reducedMotion ? "Reduced motion" : "Local UI"}</small>
        </div>
        <button
          type="button"
          className="segmented-toggle"
          aria-pressed={pixelPetEnabled}
          data-selected={pixelPetEnabled}
          onClick={() => onPixelPetEnabledChange(!pixelPetEnabled)}
        >
          {pixelPetEnabled ? "On" : "Off"}
        </button>
      </div>
      <div className="settings-toggle-row">
        <div>
          <SlidersHorizontal size={14} aria-hidden="true" />
          <span>Pet size</span>
          <small>{pixelPetSize}</small>
        </div>
        <div className="segmented-button-group" role="group" aria-label="Companion size">
          {(["small", "medium"] as const).map((size) => (
            <button
              key={size}
              type="button"
              className="segmented-toggle"
              aria-pressed={pixelPetSize === size}
              data-selected={pixelPetSize === size}
              disabled={!pixelPetEnabled}
              onClick={() => onPixelPetSizeChange(size)}
            >
              {size === "small" ? "Small" : "Medium"}
            </button>
          ))}
        </div>
      </div>
    </SettingsMatrixPanel>
  );
}

export function LlmAlertStoryPanel() {
  const statusQuery = useLlmAlertStoryStatusQuery();
  const updateSettingsMutation = useUpdateLlmAlertStorySettingsMutation();
  const saveApiKeyMutation = useSaveLlmAlertStoryApiKeyMutation();
  const clearApiKeyMutation = useClearLlmAlertStoryApiKeyMutation();
  const testConnectionMutation = useTestLlmAlertStoryConnectionMutation();
  const generateStoryMutation = useGenerateLlmAlertStoryMutation();
  const storiesQuery = useLlmAlertStoriesQuery();
  const status = statusQuery.data;
  const [enabled, setEnabled] = useState(false);
  const [provider, setProvider] =
    useState<LlmAlertStoryStatusDto["settings"]["provider"]>("open_ai_compatible");
  const [model, setModel] = useState("");
  const storageMode = "session_only" as const;
  const [authorizationGranted, setAuthorizationGranted] = useState(false);
  const [timeoutSeconds, setTimeoutSeconds] = useState(20);
  const [baseUrlInput, setBaseUrlInput] = useState("");
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [alertIdInput, setAlertIdInput] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    if (!status) {
      return;
    }
    setEnabled(status.settings.enabled);
    setProvider(status.settings.provider);
    setModel(status.settings.model);
    setAuthorizationGranted(status.settings.authorization_granted);
    setTimeoutSeconds(status.settings.timeout_seconds);
  }, [status]);

  const busy =
    statusQuery.isFetching ||
    updateSettingsMutation.isPending ||
    saveApiKeyMutation.isPending ||
    clearApiKeyMutation.isPending ||
    testConnectionMutation.isPending ||
    generateStoryMutation.isPending;

  if (!status) {
    return (
      <SettingsReadModelPanel
        error={statusQuery.isError}
        icon={<Sparkles size={15} aria-hidden="true" />}
        loading={statusQuery.isLoading}
        readModel="LLM alert-story status"
        title="LLM alert story"
        wide
      />
    );
  }

  const rows: SettingRow[] = [
    {
      label: "Capability status",
      value: llmCapabilityStatusLabel(status.capability_status),
      tone: llmCapabilityStatusTone(status.capability_status),
    },
    {
      label: "Provider",
      value: llmProviderLabel(status.settings.provider),
      tone: "neutral",
    },
    {
      label: "Model",
      value: reportedText(status.settings.model),
      tone: "neutral",
    },
    {
      label: "API key",
      value: status.api_key_configured ? "Configured" : "Required",
      tone: status.api_key_configured ? "ok" : "warning",
    },
    {
      label: "Authorization",
      value: status.settings.authorization_granted ? "Granted" : "Required",
      tone: status.settings.authorization_granted ? "ok" : "warning",
    },
    {
      label: "Storage mode",
      value: llmStorageModeLabel(status.settings.api_key_storage_mode),
      tone: "neutral",
    },
    {
      label: "Base URL",
      value: status.base_url_configured ? "Custom configured" : "Provider default",
      tone: "neutral",
    },
    {
      label: "Last successful check",
      value: status.last_successful_check ?? "not checked",
      tone: status.last_successful_check ? "ok" : "neutral",
    },
    {
      label: "Last story",
      value: status.last_successful_generation ?? "not generated",
      tone: status.last_successful_generation ? "ok" : "neutral",
    },
    {
      label: "Story count",
      value: `${status.story_count}`,
      tone: "neutral",
    },
    {
      label: "Last error",
      value: status.last_error_code ? humanize(status.last_error_code) : "none",
      tone: status.last_error_code ? "warning" : "ok",
    },
  ];

  return (
    <section className="settings-panel">
      <div className="analysis-panel-header">
        <strong>LLM alert story</strong>
        <Sparkles size={15} aria-hidden="true" />
      </div>
      <div className="settings-warning-banner">
        <AlertTriangle size={15} aria-hidden="true" />
        <span>{status.warning_redacted}</span>
      </div>
      <div className="settings-status-grid">
        {rows.map((row) => (
          <SettingsStatusRow key={row.label} row={row} />
        ))}
        <SettingsStatusRow
          row={{
            label: "Source",
            value: "command",
            tone: "ok",
          }}
        />
      </div>
      <div className="settings-form-grid">
        <div className="settings-toggle-row">
          <div>
            <Sparkles size={14} aria-hidden="true" />
            <span>Enable alert stories</span>
            <small>Optional post-alert enrichment</small>
          </div>
          <button
            type="button"
            className="segmented-toggle"
            aria-pressed={enabled}
            data-selected={enabled}
            disabled={busy}
            onClick={() => setEnabled(!enabled)}
          >
            {enabled ? "On" : "Off"}
          </button>
        </div>
        <div className="settings-toggle-row">
          <div>
            <AlertTriangle size={14} aria-hidden="true" />
            <span>Provider upload consent</span>
            <small>Required before any redacted summary can be sent</small>
          </div>
          <button
            type="button"
            className="segmented-toggle"
            aria-pressed={authorizationGranted}
            data-selected={authorizationGranted}
            disabled={busy}
            onClick={() => setAuthorizationGranted(!authorizationGranted)}
          >
            {authorizationGranted ? "Granted" : "Required"}
          </button>
        </div>
        <label className="settings-form-row">
          <span>Provider</span>
          <select
            className="settings-form-input"
            disabled={busy}
            value={provider}
            onChange={(event) =>
              setProvider(
                event.currentTarget
                  .value as LlmAlertStoryStatusDto["settings"]["provider"],
              )
            }
          >
            <option value="open_ai_compatible">OpenAI-compatible</option>
            <option value="deep_seek">DeepSeek</option>
            <option value="anthropic_compatible">Anthropic-compatible</option>
          </select>
          <small>Portable mode remains fully usable with this optional provider disabled.</small>
        </label>
        <label className="settings-form-row">
          <span>Model</span>
          <input
            className="settings-form-input"
            disabled={busy}
            type="text"
            value={model}
            onChange={(event) => setModel(event.currentTarget.value)}
          />
          <small>Use a safe model identifier only. No secrets or host data belong here.</small>
        </label>
        <label className="settings-form-row">
          <span>Timeout seconds</span>
          <input
            className="settings-form-input"
            disabled={busy}
            max={60}
            min={1}
            type="number"
            value={timeoutSeconds}
            onChange={(event) => setTimeoutSeconds(Number(event.currentTarget.value))}
          />
          <small>Provider requests are bounded to 60 seconds.</small>
        </label>
        <label className="settings-form-row">
          <span>Optional write-only base URL</span>
          <input
            className="settings-form-input"
            autoComplete="off"
            disabled={busy}
            placeholder={status.base_url_configured ? "Custom HTTPS base configured" : "Use provider default"}
            type="password"
            value={baseUrlInput}
            onChange={(event) => setBaseUrlInput(event.currentTarget.value)}
          />
          <small>The validated HTTPS value is held in memory and never returned.</small>
        </label>
        <div className="settings-form-row">
          <span>API key storage</span>
          <div className="segmented-button-group" role="group" aria-label="API key storage mode">
            <button
              type="button"
              className="segmented-toggle"
              aria-pressed={storageMode === "session_only"}
              data-selected={storageMode === "session_only"}
              disabled={busy}
            >
              Session only
            </button>
          </div>
          <small>Keys remain memory-only and are cleared on close, cleanup, or revoke.</small>
        </div>
        <label className="settings-form-row">
          <span>Write-only API key</span>
          <input
            className="settings-form-input"
            autoComplete="new-password"
            disabled={busy}
            placeholder={status.api_key_configured ? "Configured. Enter a new key to replace it." : "Paste provider API key"}
            type="password"
            value={apiKeyInput}
            onChange={(event) => setApiKeyInput(event.currentTarget.value)}
          />
          <small>The key is never returned to the frontend after save.</small>
        </label>
        <label className="settings-form-row">
          <span>Alert ref for explicit generation</span>
          <input
            className="settings-form-input"
            disabled={busy}
            placeholder="Alert UUID from Investigation"
            type="text"
            value={alertIdInput}
            onChange={(event) => setAlertIdInput(event.currentTarget.value)}
          />
          <small>Generation runs only when you click Generate story.</small>
        </label>
      </div>
      <div className="settings-action-row">
        <button
          className="toolbar-button"
          disabled={busy}
          type="button"
          onClick={() => {
            setNotice(null);
            updateSettingsMutation.mutate(
              {
                settings: {
                  enabled,
                  provider,
                  model,
                  api_key_storage_mode: storageMode,
                  authorization_granted: authorizationGranted,
                  timeout_seconds: timeoutSeconds,
                },
                base_url: baseUrlInput.trim() || null,
                reason_redacted: "update llm alert-story settings",
                requested_by_redacted: "local_user",
              },
              {
                onSuccess: (nextStatus) => {
                  setBaseUrlInput("");
                  setNotice(
                    `LLM alert-story settings saved with ${llmCapabilityStatusLabel(nextStatus.capability_status).toLowerCase()} status.`,
                  );
                },
              },
            );
          }}
        >
          Save settings
        </button>
        <button
          className="toolbar-button"
          disabled={busy || !alertIdInput.trim()}
          type="button"
          onClick={() => {
            setNotice(null);
            generateStoryMutation.mutate(
              {
                alert_id: alertIdInput.trim(),
                incident_id: null,
                explicit_user_action: true,
                replay: false,
                reason_redacted: "explicitly generate bounded alert story",
                requested_by_redacted: "local_user",
              },
              {
                onSuccess: (story) => {
                  setNotice(`AI-generated redacted story ${story.story_id} is available.`);
                },
              },
            );
          }}
        >
          Generate story
        </button>
        <button
          className="toolbar-button"
          disabled={busy || !apiKeyInput.trim()}
          type="button"
          onClick={() => {
            setNotice(null);
            saveApiKeyMutation.mutate(
              {
                api_key: apiKeyInput,
                storage_mode: storageMode,
                reason_redacted: "save llm alert-story api key",
                requested_by_redacted: "local_user",
              },
              {
                onSuccess: (nextStatus) => {
                  setApiKeyInput("");
                  setNotice(
                    nextStatus.api_key_configured
                      ? "LLM alert-story API key saved through the Rust command bridge."
                      : `API key save returned ${llmCapabilityStatusLabel(nextStatus.capability_status).toLowerCase()} status.`,
                  );
                },
              },
            );
          }}
        >
          Save key
        </button>
        <button
          className="toolbar-button"
          disabled={busy}
          type="button"
          onClick={() => {
            setNotice(null);
            testConnectionMutation.mutate(
              {
                reason_redacted: "test llm alert-story provider connection",
                requested_by_redacted: "local_user",
              },
              {
                onSuccess: (nextStatus) => {
                  setNotice(
                    `Provider check returned ${llmCapabilityStatusLabel(nextStatus.capability_status).toLowerCase()} status.`,
                  );
                },
              },
            );
          }}
        >
          Test connection
        </button>
        <button
          className="toolbar-button"
          disabled={busy || !status.api_key_configured}
          type="button"
          onClick={() => {
            setNotice(null);
            clearApiKeyMutation.mutate(
              {
                reason_redacted: "clear llm alert-story api key",
                requested_by_redacted: "local_user",
              },
              {
                onSuccess: () => {
                  setApiKeyInput("");
                  setNotice("LLM alert-story API key cleared.");
                },
              },
            );
          }}
        >
          Clear key
        </button>
      </div>
      {busy ? (
        <div className="response-callout" data-tone="ok">
          <Sparkles size={15} aria-hidden="true" />
          <span>Refreshing optional LLM alert-story status.</span>
        </div>
      ) : null}
      {statusQuery.isError ||
      updateSettingsMutation.isError ||
      saveApiKeyMutation.isError ||
      clearApiKeyMutation.isError ||
      testConnectionMutation.isError ||
      generateStoryMutation.isError ||
      storiesQuery.isError ? (
        <div className="response-callout">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>LLM alert-story controls returned a redacted error.</span>
        </div>
      ) : null}
      <div className="redaction-category-list">
        {(storiesQuery.data?.items ?? []).slice(0, 3).map((story) => (
          <span key={story.story_id}>
            AI-generated: {reportedText(story.story.alert_narrative_redacted)}
          </span>
        ))}
        {!storiesQuery.isLoading && !storiesQuery.data?.items.length ? (
          <span className="analysis-muted">No explicitly generated redacted stories yet.</span>
        ) : null}
      </div>
      {notice ? <span className="analysis-muted">{notice}</span> : null}
    </section>
  );
}

export function AuthorizedNativeControlsPanel() {
  const capabilitiesQuery = useAuthorizedNativeCapabilitiesQuery();
  const permissionQuery = useNativePermissionStatusQuery();
  const visibilityQuery = useNativeVisibilitySummaryQuery();
  const auditQuery = useNativePermissionAuditSummaryQuery();
  const previewMutation = usePreviewNativePermissionRequestMutation();
  const updateMutation = useUpdateNativePermissionMutation();
  const capabilities = capabilitiesQuery.data ?? [];
  const permission = permissionQuery.data;
  const visibility = visibilityQuery.data;
  const audit = auditQuery.data;
  const pending = previewMutation.isPending || updateMutation.isPending;

  const act = (
    capability: AuthorizedNativeCapabilityStatusDto,
    action: NativePermissionActionDto,
  ) => {
    updateMutation.mutate({
      capability_id: capability.capability_id,
      action,
      explicit_user_action: action === "grant_authorization",
      reason_redacted: `authorized native ${action}`,
    });
  };

  return (
    <section className="settings-panel">
      <div className="analysis-panel-header">
        <strong>Authorized native security controls</strong>
        <ShieldCheck size={15} aria-hidden="true" />
      </div>
      <div className="settings-warning-banner">
        <AlertTriangle size={15} aria-hidden="true" />
        <span>
          Portable Default remains active. Authorization is session-bound, read-only,
          revocable, and permission grant alone never starts a native sampler.
        </span>
      </div>
      <div className="settings-status-grid">
        <SettingsStatusRow
          row={{
            label: "Permission boundary",
            value: permission?.session_bound_authorization
              ? "Explicit session-bound"
              : "Unavailable",
            tone: "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Granted but inactive",
            value: stringifySafe(permission?.granted_inactive_count ?? 0),
            tone: permission?.granted_inactive_count ? "warning" : "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Future sampler readiness",
            value: visibility?.future_sampler_ready ? "Ready" : "Not ready",
            tone: visibility?.future_sampler_ready ? "warning" : "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Native ATT&CK visibility",
            value: visibility?.native_required_attack_coverage_supported
              ? "Supported"
              : "Requires authorized extension telemetry",
            tone: "warning",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Audit references",
            value: stringifySafe(audit?.audit_refs.length ?? 0),
            tone: "neutral",
          }}
        />
      </div>
      <div className="settings-capability-status">
        {capabilities.map((capability) => (
          <div className="settings-status-row" data-tone={nativeCapabilityTone(capability)} key={capability.capability_id}>
            <span>{humanize(capability.category)}</span>
            <strong>{humanize(capability.lifecycle_state)}</strong>
            <small>
              {humanize(
                capability.degraded_reason ??
                  capability.availability_state ??
                  "status unavailable",
              )}
            </small>
            <div className="settings-action-row">
              <button
                type="button"
                disabled={pending}
                onClick={() => previewMutation.mutate(capability.capability_id)}
              >
                Preview
              </button>
              <button
                type="button"
                disabled={pending}
                onClick={() => act(capability, "request_authorization")}
              >
                Request
              </button>
              <button
                type="button"
                disabled={
                  pending ||
                  capability.access_mode === "response_capability_placeholder"
                }
                onClick={() => act(capability, "grant_authorization")}
              >
                Grant inactive
              </button>
              <button
                type="button"
                disabled={pending}
                onClick={() => act(capability, "revoke_authorization")}
              >
                Revoke
              </button>
              <button
                type="button"
                disabled={pending}
                onClick={() => act(capability, "disable_capability")}
              >
                Disable
              </button>
              <button
                type="button"
                disabled={pending}
                onClick={() => act(capability, "recheck_status")}
              >
                Re-check
              </button>
            </div>
          </div>
        ))}
      </div>
      <NativeSamplerReadinessPanel />
      <NativeSamplerRuntimePanel />
      <NativeContinuousSamplingPanel />
      {previewMutation.data ? (
        <p className="settings-message">
          {stringifySafe(previewMutation.data.boundary_summary_redacted)}
        </p>
      ) : null}
      {capabilitiesQuery.isError ||
      permissionQuery.isError ||
      visibilityQuery.isError ||
      auditQuery.isError ? (
        <SettingsReadModelNotice
          error
          loading={false}
          readModel="authorized native control-plane status"
        />
      ) : null}
    </section>
  );
}

function NativeSamplerReadinessPanel() {
  const contractsQuery = useNativeSamplerContractsQuery();
  const readinessQuery = useNativeSamplerReadinessSummaryQuery();
  const mappingsQuery = useFutureSecurityFactMappingSummaryQuery();
  const blockedQuery = useNativeSamplerBlockedSummaryQuery();
  const missingQuery = useMissingEndpointVisibilitySummaryQuery();
  const edrQuery = useEdrReadinessSummaryQuery();
  const contracts = contractsQuery.data ?? [];
  const readiness = readinessQuery.data;
  const mappings = mappingsQuery.data;
  const blocked = blockedQuery.data;
  const missing = missingQuery.data;
  const edr = edrQuery.data;
  const loading =
    contractsQuery.isLoading ||
    readinessQuery.isLoading ||
    mappingsQuery.isLoading ||
    blockedQuery.isLoading ||
    missingQuery.isLoading ||
    edrQuery.isLoading;
  const error =
    contractsQuery.isError ||
    readinessQuery.isError ||
    mappingsQuery.isError ||
    blockedQuery.isError ||
    missingQuery.isError ||
    edrQuery.isError;

  return (
    <section className="settings-panel">
      <div className="analysis-panel-header">
        <strong>Native sampler readiness review</strong>
        <Shield size={15} aria-hidden="true" />
      </div>
      <div className="settings-warning-banner">
        <Lock size={15} aria-hidden="true" />
        <span>
          Readiness review only. Authorization and runtime activation are separate;
          no process enumeration, packet capture, service install, driver load,
          response execution, or automatic LLM call is performed here.
        </span>
      </div>
      <div className="settings-status-grid">
        <SettingsStatusRow
          row={{
            label: "Readiness-approved",
            value: stringifySafe(readiness?.ready_when_implemented_count ?? 0),
            detail: "Permission review only; activation still requires an explicit runtime action.",
            tone: readiness?.ready_when_implemented_count ? "warning" : "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Blocked samplers",
            value: stringifySafe(readiness?.blocked_count ?? 0),
            detail: blocked?.blocked_reasons.slice(0, 3).map(humanize).join(", "),
            tone: readiness?.blocked_count ? "warning" : "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Active samplers",
            value: stringifySafe(edr?.active_sampler_count ?? 0),
            detail: "Authorized metadata samplers only; no process or packet visibility.",
            tone: edr?.active_sampler_count ? "warning" : "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "EDR coverage claim",
            value: edr?.edr_coverage_claimed ? "Claimed" : "Not claimed",
            detail: "Readiness is not endpoint coverage.",
            tone: edr?.edr_coverage_claimed ? "blocked" : "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Future mappings",
            value: stringifySafe(mappings?.mapping_count ?? 0),
            detail: "Declared mappings remain separate from runtime-emitted bounded facts.",
            tone: mappings?.emitted_security_fact_count ? "warning" : "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Missing endpoint visibility",
            value: stringifySafe(missing?.missing_visibility_flags.length ?? 0),
            detail: missing?.degraded_reasons.slice(0, 2).map(humanize).join(", "),
            tone: missing?.missing_visibility_flags.length ? "warning" : "ok",
          }}
        />
      </div>
      <div className="settings-capability-status">
        {contracts.slice(0, 10).map((contract) => (
          <NativeSamplerContractRow contract={contract} key={contract.sampler_id} />
        ))}
      </div>
      {mappings?.mappings.length ? (
        <div className="settings-status-grid">
          {mappings.mappings.slice(0, 6).map((mapping) => (
            <SettingsStatusRow
              key={mapping.mapping_id}
              row={{
                label: humanize(mapping.output_fact_category),
                value: humanize(mapping.sampler_category),
                detail: "Future bounded SecurityFact mapping declaration only.",
                tone: mapping.emits_security_facts_now ? "blocked" : "neutral",
              }}
            />
          ))}
        </div>
      ) : null}
      <div className="settings-status-grid">
        <SettingsStatusRow
          row={{
            label: "Report/export refs",
            value: stringifySafe(readiness?.review_refs.length ?? 0),
            detail: "Bounded sampler/readiness/audit refs only.",
            tone: "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Portable Default",
            value: readiness?.portable_default_active ? "Active" : "Inactive",
            detail: "Adminless, driverless, no host mutation.",
            tone: "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "No telemetry collected",
            value: readiness?.no_telemetry_collected
              ? "Readiness only"
              : "Runtime metadata available",
            detail: "No raw endpoint data, paths, service names, PIDs, or secrets are displayed.",
            tone: "ok",
          }}
        />
      </div>
      {loading || error ? (
        <SettingsReadModelNotice
          error={error}
          loading={loading}
          readModel="native sampler readiness review"
        />
      ) : null}
    </section>
  );
}

function NativeSamplerRuntimePanel() {
  const runtimeQuery = useNativeSamplerRuntimeSummaryQuery();
  const previewActivationMutation = usePreviewNativeSamplerActivationMutation();
  const runtimeActionMutation = useApplyNativeSamplerRuntimeActionMutation();
  const runtime = runtimeQuery.data;
  const pending =
    previewActivationMutation.isPending || runtimeActionMutation.isPending;
  const serviceBucketCounts = runtime
    ? [...runtime.service_state_counts, ...runtime.startup_type_counts]
    : [];
  const processBucketCounts = runtime
    ? [
        ...runtime.process_relation_counts,
        ...runtime.execution_context_counts,
        ...runtime.process_trust_counts,
        ...runtime.process_signedness_counts,
        ...runtime.process_privilege_counts,
        ...runtime.process_lifecycle_counts,
      ]
    : [];
  const unknownProcessCategories =
    runtime?.process_category_counts.find(
      (count) => count.process_category === "unknown",
    )?.observation_count ?? 0;

  const act = (
    samplerId: string,
    action: NativeSamplerRuntimeActionDto,
    enableIntervalSampling = false,
  ) => {
    runtimeActionMutation.mutate({
      sampler_id: samplerId,
      action,
      explicit_user_action: true,
      enable_interval_sampling: enableIntervalSampling,
      max_records_per_sample: 128,
      max_bytes_per_sample: 65536,
      timeout_millis: 5000,
      reason_redacted: `native sampler runtime ${action}`,
    });
  };

  return (
    <section className="settings-panel">
      <div className="analysis-panel-header">
        <strong>Authorized native sampler runtime</strong>
        <Server size={15} aria-hidden="true" />
      </div>
      <div className="settings-warning-banner">
        <Shield size={15} aria-hidden="true" />
        <span>
          Runtime samples are explicit, read-only, metadata-only, and revocable.
          They expose provider health, service buckets, and process-category
          relationships only. Portable Default remains unaffected.
        </span>
      </div>
      <div className="settings-status-grid">
        <SettingsStatusRow
          row={{
            label: "Runtime statuses",
            value: stringifySafe(runtime?.runtime_count ?? 0),
            tone: runtime?.runtime_count ? "neutral" : "warning",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Active",
            value: stringifySafe(runtime?.active_count ?? 0),
            tone: runtime?.active_count ? "warning" : "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Latest batches",
            value: stringifySafe(runtime?.latest_batch_refs.length ?? 0),
            detail: "Batch refs only.",
            tone: "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Runtime facts",
            value: stringifySafe(runtime?.fact_refs.length ?? 0),
            detail: "Bounded SecurityFact refs only.",
            tone: runtime?.fact_refs.length ? "ok" : "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Service visibility",
            value: runtime?.service_visibility_available ? "Available" : "Unavailable",
            detail: "Category/state/startup buckets only.",
            tone: runtime?.service_visibility_available ? "ok" : "warning",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Health visibility",
            value: runtime?.native_health_visibility_available
              ? "Available"
              : "Unavailable",
            detail: `Quality ${humanize(runtime?.quality_bucket ?? "unknown")}`,
            tone: runtime?.native_health_visibility_available ? "ok" : "warning",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Process category visibility",
            value: runtime?.process_visibility_available ? "Available" : "Unavailable",
            detail: "Category aggregates only; specific process identity unavailable.",
            tone: runtime?.process_visibility_available ? "ok" : "warning",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Parent category visibility",
            value: runtime?.parent_process_visibility_available
              ? "Available"
              : "Unavailable or degraded",
            detail: "Category-to-category relations only; no durable lineage.",
            tone: runtime?.parent_process_visibility_available ? "ok" : "warning",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Process-network attribution",
            value: runtime?.process_network_attribution_available
              ? "Unexpected"
              : "Unavailable",
            detail: "No sockets, ports, IPs, packet capture, or process destinations.",
            tone: runtime?.process_network_attribution_available ? "blocked" : "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Raw process retention",
            value: runtime?.packet_visibility_available ? "Unexpected" : "Disabled",
            detail: "No process names, PIDs, command lines, paths, users, or raw inventory.",
            tone: runtime?.packet_visibility_available ? "blocked" : "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Response / LLM",
            value:
              runtime?.response_execution_allowed || runtime?.automatic_llm_calls
                ? "Unexpected"
                : "Disabled",
            detail: "Sampling never calls LLM providers or executes responses.",
            tone:
              runtime?.response_execution_allowed || runtime?.automatic_llm_calls
                ? "blocked"
                : "ok",
          }}
        />
      </div>
      <div className="settings-capability-status">
        {(runtime?.statuses ?? []).map((status) => (
          <NativeSamplerRuntimeRow
            key={status.sampler_id}
            pending={pending}
            status={status}
            onAction={act}
            onPreview={(samplerId) =>
              previewActivationMutation.mutate(samplerId)
            }
          />
        ))}
      </div>
      {runtime?.service_category_counts.length ? (
        <div className="settings-status-grid">
          {runtime.service_category_counts.slice(0, 6).map((count) => (
            <SettingsStatusRow
              key={`${count.service_category}-${count.count_bucket}`}
              row={{
                label: humanize(count.service_category),
                value: stringifySafe(count.observation_count),
                detail: humanize(count.count_bucket),
                tone: "neutral",
              }}
            />
          ))}
        </div>
      ) : null}
      {serviceBucketCounts.length ? (
        <div className="settings-status-grid">
          {serviceBucketCounts.slice(0, 8).map((count) => (
              <SettingsStatusRow
                key={`${count.label}-${count.count_bucket}`}
                row={{
                  label: humanize(count.label),
                  value: stringifySafe(count.observation_count),
                  detail: humanize(count.count_bucket),
                  tone: "neutral",
                }}
              />
            ))}
        </div>
      ) : null}
      {runtime?.process_category_counts.length ? (
        <div className="settings-status-grid">
          {runtime.process_category_counts.slice(0, 8).map((count) => (
            <SettingsStatusRow
              key={`process-${count.process_category}-${count.count_bucket}`}
              row={{
                label: `Process ${humanize(count.process_category)}`,
                value: stringifySafe(count.observation_count),
                detail: humanize(count.count_bucket),
                tone: count.process_category === "unknown" ? "warning" : "neutral",
              }}
            />
          ))}
        </div>
      ) : null}
      {runtime?.parent_process_category_counts.length ? (
        <div className="settings-status-grid">
          {runtime.parent_process_category_counts.slice(0, 8).map((count) => (
            <SettingsStatusRow
              key={`parent-${count.process_category}-${count.count_bucket}`}
              row={{
                label: `Parent ${humanize(count.process_category)}`,
                value: stringifySafe(count.observation_count),
                detail: humanize(count.count_bucket),
                tone: count.process_category === "unknown" ? "warning" : "neutral",
              }}
            />
          ))}
        </div>
      ) : null}
      {processBucketCounts.length ? (
        <div className="settings-status-grid">
          {processBucketCounts.slice(0, 12).map((count, index) => (
            <SettingsStatusRow
              key={`process-bucket-${count.label}-${count.count_bucket}-${index}`}
              row={{
                label: humanize(count.label),
                value: stringifySafe(count.observation_count),
                detail: humanize(count.count_bucket),
                tone: count.label.includes("unknown") ? "warning" : "neutral",
              }}
            />
          ))}
        </div>
      ) : null}
      {unknownProcessCategories ? (
        <div className="settings-warning-banner">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>
            Unknown process categories reduce relationship confidence. Underlying
            process values remain unavailable.
          </span>
        </div>
      ) : null}
      {previewActivationMutation.data ? (
        <p className="settings-message">
          {stringifySafe(previewActivationMutation.data.boundary_summary_redacted)}
        </p>
      ) : null}
      {runtimeActionMutation.data ? (
        <p className="settings-message">
          Native sampler {runtimeActionMutation.data.status.sampler_id} is{" "}
          {humanize(runtimeActionMutation.data.status.runtime_state)}.
        </p>
      ) : null}
      {runtimeQuery.isLoading || runtimeQuery.isError ? (
        <SettingsReadModelNotice
          error={runtimeQuery.isError}
          loading={runtimeQuery.isLoading}
          readModel="native sampler runtime"
        />
      ) : null}
    </section>
  );
}

function NativeSamplerRuntimeRow({
  onAction,
  onPreview,
  pending,
  status,
}: {
  readonly onAction: (
    samplerId: string,
    action: NativeSamplerRuntimeActionDto,
    enableIntervalSampling?: boolean,
  ) => void;
  readonly onPreview: (samplerId: string) => void;
  readonly pending: boolean;
  readonly status: NativeSamplerRuntimeStatusDto;
}) {
  const blocked =
    status.runtime_state === "revoked" ||
    status.runtime_state === "not_implemented" ||
    status.runtime_state === "readiness_blocked";
  return (
    <div className="settings-status-row" data-tone={nativeRuntimeTone(status)}>
      <span>{humanize(status.category)}</span>
      <strong>{humanize(status.runtime_state)}</strong>
      <small>
        Provider {humanize(status.provider_availability_state)}; health{" "}
        {humanize(status.health_state)}; permission{" "}
        {humanize(status.permission_state)}.
      </small>
      <small>
        Records {status.counters.sampled_record_count_bucket}; skipped{" "}
        {status.counters.skipped_record_count_bucket}; facts{" "}
        {stringifySafe(status.fact_refs.length)}; latest batch{" "}
        {status.latest_batch_id ? "available" : "none"}.
      </small>
      <div className="settings-action-row">
        <button
          type="button"
          disabled={pending}
          onClick={() => onPreview(status.sampler_id)}
        >
          Preview activation
        </button>
        <button
          type="button"
          disabled={pending || blocked}
          onClick={() => onAction(status.sampler_id, "activate")}
        >
          Activate
        </button>
        <button
          type="button"
          disabled={pending || blocked}
          onClick={() => onAction(status.sampler_id, "sample_now")}
        >
          Sample now
        </button>
        <button
          type="button"
          disabled={pending || blocked}
          onClick={() => onAction(status.sampler_id, "pause")}
        >
          Pause
        </button>
        <button
          type="button"
          disabled={pending || blocked}
          onClick={() => onAction(status.sampler_id, "resume")}
        >
          Resume
        </button>
        <button
          type="button"
          disabled={pending}
          onClick={() => onAction(status.sampler_id, "stop")}
        >
          Stop
        </button>
        <button
          type="button"
          disabled={pending}
          onClick={() => onAction(status.sampler_id, "revoke")}
        >
          Revoke
        </button>
        <button
          type="button"
          disabled={pending}
          onClick={() => onAction(status.sampler_id, "refresh_status")}
        >
          Refresh
        </button>
        <button
          type="button"
          disabled={pending}
          onClick={() => onAction(status.sampler_id, "clear_inactive_runtime_state")}
        >
          Clear inactive
        </button>
      </div>
    </div>
  );
}

function NativeContinuousSamplingPanel() {
  const schedulerQuery = useNativeSchedulerSummaryQuery();
  const operationalQuery = useNativeSchedulerOperationalSummaryQuery();
  const previewMutation = usePreviewNativeSchedulerEnablementMutation();
  const actionMutation = useApplyNativeSchedulerActionMutation();
  const scheduler = schedulerQuery.data;
  const operational = operationalQuery.data;
  const status = operational?.status ?? scheduler?.status;
  const latestBackpressure =
    operational?.backpressure_summary ?? scheduler?.latest_cycle?.backpressure;
  const latestFreshness =
    operational?.freshness_summary ?? scheduler?.latest_cycle?.freshness;
  const latestMissedSample =
    operational?.missed_sample_summary ?? scheduler?.latest_cycle?.missed_sample;
  const retrySummary = operational?.retry_summary;
  const pending = previewMutation.isPending || actionMutation.isPending;

  const act = (action: NativeSchedulerActionDto, samplerId?: string) => {
    actionMutation.mutate({
      sampler_id: samplerId ?? null,
      action,
      explicit_user_action: true,
      interval_bucket: "five_minutes",
      timeout_bucket: "five_seconds",
      retry_budget_bucket: "one",
      max_records: 128,
      max_bytes: 65536,
      reason_redacted: `native scheduler control ${action}`,
    });
  };

  return (
    <section className="settings-panel">
      <div className="analysis-panel-header">
        <strong>Continuous Sampling</strong>
        <Radio size={15} aria-hidden="true" />
      </div>
      <div className="settings-warning-banner">
        <Lock size={15} aria-hidden="true" />
        <span>
          Tick-driven native scheduling is active only after separate authorization,
          sampler activation, and periodic enablement. Every due sample revalidates
          runtime gates and traverses EventBus, DAG, and Static PluginRuntime. Retry,
          freshness tracking, and autonomous startup remain disabled.
        </span>
      </div>
      <div className="settings-status-grid">
        <SettingsStatusRow
          row={{
            label: "Scheduler health",
            value: humanize(operational?.scheduler_health ?? "idle"),
            detail: "Operational read model only; it cannot enable schedules or refresh providers.",
            tone:
              operational?.scheduler_health === "healthy"
                ? "ok"
                : operational?.scheduler_health === "backpressure" ||
                    operational?.scheduler_health === "degraded"
                  ? "warning"
                  : operational?.scheduler_health === "failed" ||
                      operational?.scheduler_health === "revoked"
                    ? "blocked"
                    : "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Scheduler state",
            value: humanize(status?.controller_state ?? "disabled"),
            detail: "Running schedules are eligible for bounded monotonic ticks.",
            tone:
              status?.controller_state === "running"
                ? "warning"
                : "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Enabled schedules",
            value: stringifySafe(status?.enabled_schedule_count ?? 0),
            detail: "Each schedule retains bounded interval, timeout, record, and byte limits.",
            tone: status?.enabled_schedule_count ? "warning" : "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Safe persistence",
            value: operational?.safe_persistence_only ? "Buckets only" : "Pending",
            detail: `Persisted schedule rows ${operational?.safe_persisted_schedules.length ?? 0}; raw native data, PID, paths, command lines, and host identifiers are blocked.`,
            tone: operational?.safe_persistence_only ? "ok" : "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Eligible schedules",
            value: stringifySafe(status?.eligible_schedule_count ?? 0),
            detail: "Requires separate authorization and activation.",
            tone: "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Periodic execution",
            value: status?.scheduling_loop_implemented
              ? status.scheduling_loop_active
                ? "Tick loop ready"
                : "Implemented, inactive"
              : "Unavailable",
            detail: `Completed ${status?.completed_cycle_count ?? 0}; skipped ${status?.skipped_cycle_count ?? 0}.`,
            tone: status?.scheduling_loop_active ? "warning" : "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Backpressure",
            value: humanize(status?.backpressure_state ?? "none"),
            detail: `Pressure cycles ${status?.backpressure_cycle_count ?? 0}; latest due ${latestBackpressure?.pending_due_task_count ?? 0}, EventBus backlog ${latestBackpressure?.event_bus_backlog_count ?? 0}, DAG backlog ${latestBackpressure?.dag_backlog_count ?? 0}.`,
            tone:
              status?.backpressure_state === "saturated" ||
              status?.backpressure_state === "high"
                ? "blocked"
                : status?.backpressure_state === "moderate" ||
                    status?.backpressure_state === "low"
                  ? "warning"
                : "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Freshness",
            value: humanize(
              latestFreshness?.worst_freshness_state ?? "missing",
            ),
            detail: `Stale ${status?.freshness_stale_dimension_count ?? 0}; missing/unavailable ${status?.freshness_missing_dimension_count ?? 0}; missed ${status?.missed_sample_dimension_count ?? 0}.`,
            tone:
              (status?.freshness_stale_dimension_count ?? 0) > 0 ||
              (status?.freshness_missing_dimension_count ?? 0) > 0
                ? "warning"
                : "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Missed samples",
            value: `${latestMissedSample?.missed_once_dimension_count ?? 0} missed once`,
            detail: `Delayed ${latestMissedSample?.delayed_dimension_count ?? 0}; repeatedly missed ${latestMissedSample?.repeatedly_missed_dimension_count ?? 0}; blocked ${latestMissedSample?.blocked_dimension_count ?? 0}.`,
            tone:
              (latestMissedSample?.repeatedly_missed_dimension_count ?? 0) > 0 ||
              (latestMissedSample?.missed_once_dimension_count ?? 0) > 0
                ? "warning"
                : "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Retry summary",
            value: `${retrySummary?.retry_pending_sampler_count ?? 0} pending`,
            detail: `Scheduled ${retrySummary?.retry_scheduled_count ?? 0}; exhausted ${retrySummary?.retry_exhausted_count ?? 0}; no tight retry loops.`,
            tone:
              (retrySummary?.retry_exhausted_count ?? 0) > 0
                ? "warning"
                : "neutral",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Report traceability",
            value: `${operational?.scheduler_refs.length ?? 0} scheduler refs`,
            detail: `Freshness refs ${operational?.freshness_refs.length ?? 0}; quality refs ${operational?.quality_refs.length ?? 0}; reports/exports cannot enable scheduler or call LLMs.`,
            tone: "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Startup auto-enable",
            value: scheduler?.startup_auto_enablement ? "Unexpected" : "Disabled",
            detail: "Startup never enables native schedules.",
            tone: scheduler?.startup_auto_enablement ? "blocked" : "ok",
          }}
        />
        <SettingsStatusRow
          row={{
            label: "Execution boundaries",
            value:
              status?.sample_requested ||
              status?.periodic_execution_started ||
              status?.response_execution_started ||
              status?.automatic_llm_calls ||
              operational?.provider_refresh_started ||
              operational?.scheduler_enablement_started ||
              operational?.automatic_llm_calls
                ? "Unexpected"
                : "Inactive",
            detail: "Reports, exports, provider refresh, responses, and LLM calls remain explicit-action-only.",
            tone:
              status?.sample_requested ||
              status?.periodic_execution_started ||
              status?.response_execution_started ||
              status?.automatic_llm_calls ||
              operational?.provider_refresh_started ||
              operational?.scheduler_enablement_started ||
              operational?.automatic_llm_calls
                ? "blocked"
                : "ok",
          }}
        />
      </div>
      <div className="settings-action-row">
        <button
          type="button"
          disabled={pending || status?.controller_state !== "running"}
          onClick={() => act("pause")}
        >
          Pause scheduler
        </button>
        <button
          type="button"
          disabled={pending || status?.controller_state !== "paused"}
          onClick={() => act("resume")}
        >
          Resume scheduler
        </button>
        <button type="button" disabled={pending} onClick={() => act("disable_scheduler")}>
          Disable scheduler
        </button>
        <button type="button" disabled={pending} onClick={() => act("begin_stop")}>
          Begin stop
        </button>
        <button
          type="button"
          disabled={pending || status?.controller_state !== "stopping"}
          onClick={() => act("complete_stop")}
        >
          Complete stop
        </button>
        <button type="button" disabled={pending} onClick={() => act("refresh_status")}>
          Refresh status
        </button>
      </div>
      <div className="settings-capability-status">
        {(scheduler?.schedules ?? []).map((schedule) => (
          <NativeSamplerScheduleRow
            key={schedule.contract.sampler_id}
            pending={pending}
            schedule={schedule}
            onAction={act}
            onPreview={(samplerId) => previewMutation.mutate(samplerId)}
          />
        ))}
      </div>
      {previewMutation.data ? (
        <p className="settings-message">
          {stringifySafe(previewMutation.data.boundary_summary_redacted)}
        </p>
      ) : null}
      {actionMutation.data ? (
        <p className="settings-message">
          Scheduler control state is{" "}
          {humanize(actionMutation.data.status.controller_state)}; runtime gates will
          be revalidated on every due cycle.
        </p>
      ) : null}
      {schedulerQuery.isLoading ||
      schedulerQuery.isError ||
      operationalQuery.isLoading ||
      operationalQuery.isError ? (
        <SettingsReadModelNotice
          error={schedulerQuery.isError || operationalQuery.isError}
          loading={schedulerQuery.isLoading || operationalQuery.isLoading}
          readModel="native scheduler operational integration"
        />
      ) : null}
    </section>
  );
}

function NativeSamplerScheduleRow({
  onAction,
  onPreview,
  pending,
  schedule,
}: {
  readonly onAction: (action: NativeSchedulerActionDto, samplerId?: string) => void;
  readonly onPreview: (samplerId: string) => void;
  readonly pending: boolean;
  readonly schedule: NativeSamplerScheduleStatusDto;
}) {
  return (
    <div
      className="settings-status-row"
      data-tone={schedule.contract.schedule_enabled ? "warning" : "neutral"}
    >
      <span>{humanize(schedule.contract.sampler_category)}</span>
      <strong>
        {schedule.contract.schedule_enabled ? "Schedule enabled" : "Schedule disabled"}
      </strong>
      <small>
        Authorization {schedule.authorized ? "granted" : "required"}; activation{" "}
        {schedule.activated ? "active" : "required"}; eligibility{" "}
        {schedule.schedule_eligible ? "ready" : humanize(schedule.blocked_reason ?? "blocked")}.
      </small>
      <small>
        Interval {humanize(schedule.contract.interval_bucket)}; timeout{" "}
        {humanize(schedule.contract.timeout_bucket)}; retry budget{" "}
        {humanize(schedule.contract.retry_budget_bucket)}; no raw retention.
      </small>
      <div className="settings-action-row">
        <button
          type="button"
          disabled={pending}
          onClick={() => onPreview(schedule.contract.sampler_id)}
        >
          Preview enablement
        </button>
        <button
          type="button"
          disabled={pending || !schedule.schedule_eligible}
          onClick={() => onAction("enable_sampler", schedule.contract.sampler_id)}
        >
          Enable periodic intent
        </button>
        <button
          type="button"
          disabled={pending || !schedule.contract.schedule_enabled}
          onClick={() => onAction("disable_sampler", schedule.contract.sampler_id)}
        >
          Disable schedule
        </button>
      </div>
    </div>
  );
}

function NativeSamplerContractRow({
  contract,
}: {
  readonly contract: NativeSamplerContractDto;
}) {
  return (
    <div
      className="settings-status-row"
      data-tone={nativeSamplerTone(contract)}
    >
      <span>{humanize(contract.category)}</span>
      <strong>{humanize(contract.readiness_state)}</strong>
      <small>
        Permission {humanize(contract.required_permission_state)} via{" "}
        {humanize(contract.required_capability_id)};{" "}
        {contract.sampler_active ? "active" : "not active"};{" "}
        {contract.sampler_implemented ? "implemented" : "not implemented"}.
      </small>
      <small>
        Schema {humanize(contract.schema.redaction_status)};{" "}
        {contract.output_fact_categories.slice(0, 2).map(humanize).join(", ")}
      </small>
    </div>
  );
}

interface RuntimeProfileFormProps {
  readonly profile: RuntimeProfileDto;
}

export function RuntimeProfileForm({ profile }: RuntimeProfileFormProps) {
  const profileRows: SettingRow[] = [
    { label: "Current profile", value: reportedText(stringField(profile, "display_name")), tone: "ok" },
    { label: "Profile ID", value: reportedText(stringField(profile, "profile_id")), tone: "neutral" },
    { label: "Profile name", value: reportedText(stringField(profile, "name")), tone: "neutral" },
    { label: "Default profile", value: reportedBoolean(boolField(profile, "is_default")), tone: "neutral" },
    { label: "Schema version", value: nestedVersion(profile.schema_version), tone: "neutral" },
    { label: "Profile source", value: "command", tone: "ok" },
  ];
  return (
    <section className="settings-panel">
      <div className="analysis-panel-header">
        <strong>Runtime profile</strong>
        <SlidersHorizontal size={15} aria-hidden="true" />
      </div>
      <div className="runtime-profile-grid">
        {profileRows.map((row) => (
          <SettingsStatusRow key={row.label} row={row} />
        ))}
      </div>
      <div className="settings-impact-strip">
        <ImpactStep label="Validate" />
        <ImpactStep label="Impact" />
        <ImpactStep label="Audit" />
        <ImpactStep label="Rollback" />
      </div>
    </section>
  );
}

interface PrivacySettingsPanelProps {
  readonly profile: RuntimeProfileDto;
}

export function PrivacySettingsPanel({ profile }: PrivacySettingsPanelProps) {
  const privacy = recordField(profile, "privacy_policy");
  const forensic = recordField(privacy, "forensic_mode");
  const rows: SettingRow[] = [
    { label: "Data storage mode", value: reportedHumanized(stringField(privacy, "storage_mode")), tone: "ok" },
    { label: "Cloud sync", value: enabledLabel(boolField(privacy, "cloud_sync_enabled")), tone: disabledTone(boolField(privacy, "cloud_sync_enabled")) },
    { label: "Security telemetry", value: enabledLabel(boolField(privacy, "security_telemetry_enabled")), tone: disabledTone(boolField(privacy, "security_telemetry_enabled")) },
    { label: "Packet content retention", value: enabledLabel(boolField(privacy, "raw_packet_storage_enabled")), tone: disabledTone(boolField(privacy, "raw_packet_storage_enabled")) },
    { label: "Payload retention", value: enabledLabel(boolField(privacy, "payload_storage_enabled")), tone: disabledTone(boolField(privacy, "payload_storage_enabled")) },
    { label: "HTTP body retention", value: enabledLabel(boolField(privacy, "http_body_storage_enabled")), tone: disabledTone(boolField(privacy, "http_body_storage_enabled")) },
    { label: "Sensitive auth material retention", value: enabledLabel(boolField(privacy, "cookie_token_credential_storage_enabled")), tone: disabledTone(boolField(privacy, "cookie_token_credential_storage_enabled")) },
    { label: "Forensic mode", value: choiceLabel(boolField(forensic, "enabled"), "Active", "Off"), tone: choiceTone(boolField(forensic, "enabled"), "blocked", "ok") },
    { label: "Forensic max TTL", value: durationLabel(numberField(forensic, "max_ttl_seconds")), tone: "neutral" },
    { label: "Settings source", value: "command", tone: "ok" },
  ];

  return (
    <section className="settings-panel">
      <div className="analysis-panel-header">
        <strong>Privacy & data</strong>
        <Lock size={15} aria-hidden="true" />
      </div>
      <div className="settings-warning-banner">
        <AlertTriangle size={15} aria-hidden="true" />
        <span>Forensic mode must be explicit, scoped, time-limited, encrypted, audited, and export-gated.</span>
      </div>
      <div className="settings-status-grid">
        {rows.map((row) => (
          <SettingsStatusRow key={row.label} row={row} />
        ))}
      </div>
    </section>
  );
}

interface ServiceStatusPanelProps {
  readonly error?: boolean;
  readonly loading: boolean;
  readonly serviceStatus?: ServiceStatusViewDto;
  readonly wide?: boolean;
}

export function ServiceStatusPanel({
  error = false,
  loading,
  serviceStatus,
  wide = false,
}: ServiceStatusPanelProps) {
  if (!serviceStatus) {
    return (
      <SettingsReadModelPanel
        error={error}
        icon={<Server size={15} aria-hidden="true" />}
        loading={loading}
        readModel="service status"
        title="Service status"
        wide={wide}
      />
    );
  }

  const rows: SettingRow[] = [
    { label: "Connected", value: serviceStatus.connected ? "Yes" : "No", tone: serviceStatus.connected ? "ok" : "warning" },
    { label: "Degraded", value: serviceStatus.degraded ? "Yes" : "No", tone: serviceStatus.degraded ? "warning" : "ok" },
    { label: "Reason", value: serviceStatus.reason ? humanize(serviceStatus.reason) : "None", tone: serviceStatus.reason ? "warning" : "ok" },
    { label: "Profile mode", value: humanize(serviceStatus.profile_mode), tone: serviceStatus.profile_mode === "portable-no-retention" ? "warning" : "neutral" },
    { label: "Local Core", value: humanize(serviceStatus.local_core_status), tone: statusTone(serviceStatus.local_core_status) },
    { label: "Elevated service", value: humanize(serviceStatus.elevated_service_status), tone: statusTone(serviceStatus.elevated_service_status) },
    { label: "IPC", value: humanize(serviceStatus.ipc_status), tone: statusTone(serviceStatus.ipc_status) },
    { label: "Storage", value: humanize(serviceStatus.storage_status), tone: statusTone(serviceStatus.storage_status) },
    { label: "Capture", value: serviceStatus.capture_available ? "Available" : "Unavailable", tone: serviceStatus.capture_available ? "ok" : "warning" },
    { label: "Privileged actions", value: serviceStatus.privileged_actions_available ? "Available" : "Unavailable", tone: serviceStatus.privileged_actions_available ? "warning" : "ok" },
    { label: "Reduced visibility", value: serviceStatus.reduced_visibility ? "Active" : "Off", tone: serviceStatus.reduced_visibility ? "warning" : "ok" },
    { label: "Source", value: "command", tone: "ok" },
  ];
  return (
    <section className={wide ? "settings-panel" : "settings-side-panel"}>
      <div className="analysis-panel-header">
        <strong>Service status</strong>
        <Server size={15} aria-hidden="true" />
      </div>
      <div className="settings-status-grid">
        {rows.map((row) => (
          <SettingsStatusRow key={row.label} row={row} />
        ))}
      </div>
      {error ? (
        <SettingsReadModelNotice
          error
          loading={false}
          readModel="service status refresh; cached command data is shown"
        />
      ) : null}
      {serviceStatus.machine_local_capability_status ? (
        <MachineLocalCapabilityPanel serviceStatus={serviceStatus} />
      ) : (
        <p className="settings-message">
          No machine-local capability status was returned by the command bridge.
        </p>
      )}
      <p className="settings-message">{stringifySafe(serviceStatus.message_redacted)}</p>
    </section>
  );
}

function MachineLocalCapabilityPanel({
  serviceStatus,
}: {
  readonly serviceStatus: ServiceStatusViewDto;
}) {
  const summary = serviceStatus.machine_local_capability_status;
  if (!summary) {
    return null;
  }
  const notConfigured =
    summary.capabilities.length > 0 &&
    summary.capabilities.every((capability) =>
      ["unavailable", "requires_setup", "requires_admin"].includes(
        capability.status,
      ),
    );
  const rows = summary.capabilities.map((capability) => ({
    label: humanize(capability.capability),
    value: capabilityLabel(capability.status),
    tone: capabilityStatusTone(capability.status),
    detail: capability.action ?? capability.reason ?? null,
  }));

  return (
    <div className="settings-capability-status">
      {notConfigured ? (
        <div className="settings-warning-banner">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>Machine-local capabilities not configured</span>
        </div>
      ) : null}
      {rows.length ? (
        <div className="settings-status-grid">
          {rows.map((row) => (
            <SettingsStatusRow key={row.label} row={row} />
          ))}
        </div>
      ) : (
        <p className="settings-message">
          No machine-local capability records were returned by the command bridge.
        </p>
      )}
      <small className="analysis-muted">
        Detected on this machine at {stringifySafe(summary.detected_at)}.
      </small>
    </div>
  );
}

interface SettingsMatrixPanelProps {
  readonly title: string;
  readonly rows: SettingRow[];
  readonly icon: ReactNode;
  readonly callout?: string;
  readonly children?: ReactNode;
  readonly showCommandSource?: boolean;
}

function SettingsMatrixPanel({
  title,
  rows,
  icon,
  callout,
  children,
  showCommandSource = true,
}: SettingsMatrixPanelProps) {
  return (
    <section className="settings-panel">
      <div className="analysis-panel-header">
        <strong>{title}</strong>
        {icon}
      </div>
      {callout ? (
        <div className="settings-warning-banner">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>{callout}</span>
        </div>
      ) : null}
      <div className="settings-status-grid">
        {rows.map((row) => (
          <SettingsStatusRow key={row.label} row={row} />
        ))}
        {showCommandSource ? (
          <SettingsStatusRow
            row={{
              label: "Source",
              value: "command",
              tone: "ok",
            }}
          />
        ) : null}
      </div>
      {children}
    </section>
  );
}

function SettingsReadModelPanel({
  error,
  icon,
  loading,
  readModel,
  title,
  wide = false,
}: {
  readonly error: boolean;
  readonly icon: ReactNode;
  readonly loading: boolean;
  readonly readModel: string;
  readonly title: string;
  readonly wide?: boolean;
}) {
  const stateTitle = error
    ? `${title} unavailable`
    : loading
      ? `Loading ${readModel}`
      : `No ${readModel} available`;
  const detail = error
    ? `The command bridge returned a redacted ${readModel} query error.`
    : loading
      ? `Waiting for ${readModel} from the command bridge.`
      : `The command bridge returned no ${readModel} data.`;

  return (
    <section className={wide ? "settings-panel" : "settings-side-panel"}>
      <div className="analysis-panel-header">
        <strong>{title}</strong>
        {icon}
      </div>
      <EmptyState
        detail={detail}
        title={stateTitle}
        tone={error ? "error" : loading ? "degraded" : "empty"}
      />
    </section>
  );
}

function SettingsReadModelNotice({
  error,
  loading,
  readModel,
}: {
  readonly error: boolean;
  readonly loading: boolean;
  readonly readModel: string;
}) {
  const message = error
    ? `The command bridge returned a redacted ${readModel} error.`
    : loading
      ? `Loading ${readModel} from the command bridge.`
      : `No ${readModel} data was returned by the command bridge.`;
  return (
    <div className="settings-warning-banner">
      <AlertTriangle size={15} aria-hidden="true" />
      <span>{message}</span>
    </div>
  );
}

function SettingsSafetyPanel({
  error,
  loading,
  profile,
}: {
  readonly error: boolean;
  readonly loading: boolean;
  readonly profile?: RuntimeProfileDto;
}) {
  if (!profile) {
    return (
      <SettingsReadModelPanel
        error={error}
        icon={<ShieldCheck size={15} aria-hidden="true" />}
        loading={loading}
        readModel="runtime profile safety posture"
        title="Safety posture"
      />
    );
  }

  const privacy = recordField(profile, "privacy_policy");
  const forensic = recordField(privacy, "forensic_mode");
  const api = recordField(profile, "api_security_settings");
  const waf = recordField(profile, "waf_integration_settings");
  const response = recordField(profile, "response_policy");
  const reports = recordField(profile, "report_export_policy");
  const rows: SettingRow[] = [
    { label: "API visibility", value: choiceLabel(boolField(api, "packet_only_hints_enabled"), "Packet-only hints", "Off"), tone: "warning" },
    { label: "WAF enforcement", value: enabledLabel(boolField(waf, "enforcement_response_enabled")), tone: disabledTone(boolField(waf, "enforcement_response_enabled")) },
    { label: "Forensic mode", value: choiceLabel(boolField(forensic, "enabled"), "Active", "Off"), tone: choiceTone(boolField(forensic, "enabled"), "blocked", "ok") },
    { label: "Response mode", value: reportedHumanized(stringField(response, "mode")), tone: "ok" },
    { label: "Export redaction", value: choiceLabel(boolField(reports, "require_redaction"), "Required", "Off"), tone: choiceTone(boolField(reports, "require_redaction"), "ok", "blocked") },
    { label: "Profile source", value: "command", tone: "ok" },
  ];
  return (
    <section className="settings-side-panel">
      <div className="analysis-panel-header">
        <strong>Safety posture</strong>
        <ShieldCheck size={15} aria-hidden="true" />
      </div>
      <div className="settings-status-grid">
        {rows.map((row) => (
          <SettingsStatusRow key={row.label} row={row} />
        ))}
      </div>
    </section>
  );
}

function SettingsStatusRow({ row }: { readonly row: SettingRow }) {
  return (
    <div className="settings-status-row" data-tone={row.tone ?? "neutral"}>
      <span>{row.label}</span>
      <strong>{stringifySafe(row.value)}</strong>
      {row.detail ? <small>{stringifySafe(row.detail)}</small> : null}
    </div>
  );
}

function ImpactStep({ label }: { readonly label: string }) {
  return (
    <div>
      <ShieldCheck size={14} aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

function SectionIcon({ sectionId }: { readonly sectionId: SettingsSectionId }) {
  switch (sectionId) {
    case "runtime":
      return <SlidersHorizontal size={14} aria-hidden="true" />;
    case "privacy":
      return <Lock size={14} aria-hidden="true" />;
    case "capture":
      return <Radio size={14} aria-hidden="true" />;
    case "attribution":
      return <Network size={14} aria-hidden="true" />;
    case "intelligence":
      return <Globe size={14} aria-hidden="true" />;
    case "llm":
      return <Sparkles size={14} aria-hidden="true" />;
    case "native":
      return <ShieldCheck size={14} aria-hidden="true" />;
    case "api":
      return <KeyRound size={14} aria-hidden="true" />;
    case "waf":
      return <Shield size={14} aria-hidden="true" />;
    case "response":
      return <ShieldCheck size={14} aria-hidden="true" />;
    case "reports":
      return <FileText size={14} aria-hidden="true" />;
    case "service":
      return <Server size={14} aria-hidden="true" />;
    case "advanced":
      return <Bug size={14} aria-hidden="true" />;
    case "general":
    default:
      return <Settings size={14} aria-hidden="true" />;
  }
}

function generalRows(profile?: RuntimeProfileDto): SettingRow[] {
  const rows: SettingRow[] = [
    { label: "Product mode", value: "Windows Local Desktop", tone: "ok" },
    { label: "Core", value: "Rust Local Core", tone: "ok" },
    { label: "Desktop shell", value: "Tauri", tone: "ok" },
    { label: "Data strategy", value: "Local-only by default", tone: "ok" },
  ];
  if (profile) {
    rows.push(
      { label: "Profile", value: reportedText(stringField(profile, "display_name")), tone: "ok" },
      { label: "Schema version", value: nestedVersion(profile.schema_version), tone: "neutral" },
    );
  }
  return rows;
}

function nativeCapabilityTone(
  capability: AuthorizedNativeCapabilityStatusDto,
): SettingRow["tone"] {
  if (capability.revoked || capability.lifecycle_state === "denied") {
    return "blocked";
  }
  if (
    capability.lifecycle_state === "granted" ||
    capability.lifecycle_state === "available"
  ) {
    return "warning";
  }
  return "neutral";
}

function nativeSamplerTone(contract: NativeSamplerContractDto): SettingRow["tone"] {
  if (contract.sampler_active || contract.telemetry_collection_active) {
    return "blocked";
  }
  if (contract.readiness_state.startsWith("blocked_")) {
    return "warning";
  }
  if (contract.readiness_state === "ready_when_sampler_implemented") {
    return "warning";
  }
  return "neutral";
}

function nativeRuntimeTone(status: NativeSamplerRuntimeStatusDto): SettingRow["tone"] {
  if (
    status.response_execution_allowed ||
    status.service_installation_started ||
    status.driver_loading_started ||
    status.host_mutation_performed ||
    status.automatic_llm_calls
  ) {
    return "blocked";
  }
  if (
    status.runtime_state === "revoked" ||
    status.runtime_state === "failed" ||
    status.runtime_state === "not_implemented"
  ) {
    return "blocked";
  }
  if (
    status.runtime_state === "active" ||
    status.runtime_state === "idle" ||
    status.runtime_state === "paused" ||
    status.runtime_state === "ready_inactive"
  ) {
    return status.provider_availability_state === "available" ? "ok" : "warning";
  }
  if (
    status.runtime_state === "degraded" ||
    status.runtime_state === "readiness_blocked"
  ) {
    return "warning";
  }
  return "neutral";
}

function captureRows(profile: RuntimeProfileDto): SettingRow[] {
  const capture = recordField(profile, "capture_settings");
  return [
    { label: "Capture status", value: enabledLabel(boolField(capture, "enabled")), tone: boolField(capture, "enabled") ? "ok" : "warning" },
    { label: "Adapter preference", value: reportedHumanized(stringField(capture, "adapter_preference")), tone: "ok" },
    { label: "Direction", value: reportedHumanized(stringField(capture, "direction")), tone: "neutral" },
    { label: "Packet metadata", value: enabledLabel(boolField(capture, "store_packet_metadata")), tone: "ok" },
    { label: "Packet content retention", value: enabledLabel(boolField(capture, "store_raw_packets")), tone: disabledTone(boolField(capture, "store_raw_packets")) },
    { label: "Payload retention", value: enabledLabel(boolField(capture, "store_payloads")), tone: disabledTone(boolField(capture, "store_payloads")) },
    { label: "HTTP body retention", value: enabledLabel(boolField(capture, "store_http_bodies")), tone: disabledTone(boolField(capture, "store_http_bodies")) },
    { label: "Reduced visibility warning", value: enabledLabel(boolField(capture, "reduced_visibility_warning_enabled")), tone: "ok" },
  ];
}

function attributionRows(profile: RuntimeProfileDto): SettingRow[] {
  const attribution = recordField(profile, "process_attribution_settings");
  return [
    { label: "Collection mode", value: reportedHumanized(stringField(attribution, "collection_mode")), tone: "neutral" },
    { label: "Unknown attribution", value: choiceLabel(boolField(attribution, "allow_unknown_attribution"), "Allowed with label", "Hidden"), tone: "warning" },
    { label: "UDP warning", value: enabledLabel(boolField(attribution, "show_udp_limitation_warning")), tone: "ok" },
    { label: "VPN/proxy warning", value: enabledLabel(boolField(attribution, "show_vpn_proxy_limitation_warning")), tone: "ok" },
    { label: "Protected process warning", value: enabledLabel(boolField(attribution, "show_protected_process_limitation_warning")), tone: "ok" },
    { label: "Confidence visible", value: enabledLabel(boolField(attribution, "attribution_confidence_visible")), tone: "ok" },
  ];
}

function intelligenceRows(profile: RuntimeProfileDto): SettingRow[] {
  const intelligence = recordField(profile, "intelligence_settings");
  return [
    { label: "Local bundled intelligence", value: enabledLabel(boolField(intelligence, "local_bundled_intelligence_enabled")), tone: "ok" },
    { label: "Signed updates", value: enabledLabel(boolField(intelligence, "signed_updates_enabled")), tone: "ok" },
    { label: "User IOC import", value: enabledLabel(boolField(intelligence, "user_ioc_import_enabled")), tone: "neutral" },
    { label: "Online lookup", value: enabledLabel(boolField(intelligence, "online_lookup_enabled")), tone: disabledTone(boolField(intelligence, "online_lookup_enabled")) },
    { label: "Commercial feed", value: choiceLabel(boolField(intelligence, "commercial_feed_configured"), "Configured", "Not configured"), tone: "neutral" },
    { label: "Source provenance", value: enabledLabel(boolField(intelligence, "source_provenance_required")), tone: "ok" },
  ];
}

function apiRows(profile: RuntimeProfileDto): SettingRow[] {
  const api = recordField(profile, "api_security_settings");
  return [
    { label: "Mode", value: reportedHumanized(stringField(api, "mode")), tone: "warning" },
    { label: "Packet-only hints", value: enabledLabel(boolField(api, "packet_only_hints_enabled")), tone: "ok" },
    { label: "Full API security", value: choiceLabel(boolField(api, "full_api_security_configured"), "Configured", "Not configured"), tone: "neutral" },
    { label: "Local TLS inspection", value: enabledLabel(boolField(api, "local_tls_inspection_enabled")), tone: disabledTone(boolField(api, "local_tls_inspection_enabled")) },
    { label: "Browser extension visibility", value: enabledLabel(boolField(api, "browser_extension_visibility_enabled")), tone: disabledTone(boolField(api, "browser_extension_visibility_enabled")) },
    { label: "API policy response", value: enabledLabel(boolField(api, "api_policy_response_enabled")), tone: disabledTone(boolField(api, "api_policy_response_enabled")) },
    { label: "Import logs", value: enabledLabel(boolField(api, "import_logs_available")), tone: "neutral" },
  ];
}

function wafRows(profile: RuntimeProfileDto): SettingRow[] {
  const waf = recordField(profile, "waf_integration_settings");
  return [
    { label: "WAF security", value: enabledLabel(boolField(waf, "security_enabled")), tone: disabledTone(boolField(waf, "security_enabled")) },
    { label: "ModSecurity audit import", value: enabledLabel(boolField(waf, "import_modsecurity_audit_log_available")), tone: "neutral" },
    { label: "Generic JSON event import", value: enabledLabel(boolField(waf, "import_generic_json_event_available")), tone: "neutral" },
    { label: "Generic CSV event import", value: enabledLabel(boolField(waf, "import_generic_csv_event_available")), tone: "neutral" },
    { label: "Access log import", value: enabledLabel(boolField(waf, "access_log_as_web_access_log_available")), tone: "neutral" },
    { label: "Cloud connectors", value: enabledLabel(boolField(waf, "cloud_waf_connectors_enabled")), tone: disabledTone(boolField(waf, "cloud_waf_connectors_enabled")) },
    { label: "Enforcement response", value: enabledLabel(boolField(waf, "enforcement_response_enabled")), tone: disabledTone(boolField(waf, "enforcement_response_enabled")) },
  ];
}

function responseRows(profile: RuntimeProfileDto): SettingRow[] {
  const response = recordField(profile, "response_policy");
  return [
    { label: "Response mode", value: reportedHumanized(stringField(response, "mode")), tone: "ok" },
    { label: "Default auto TTL", value: durationLabel(numberField(response, "auto_containment_ttl_seconds")), tone: "neutral" },
    { label: "Max auto TTL", value: durationLabel(numberField(response, "auto_containment_max_ttl_seconds")), tone: "neutral" },
    { label: "Allowed auto actions", value: listLabel(arrayField(response, "allowed_auto_actions")), tone: "warning" },
    { label: "High impact approval", value: enabledLabel(boolField(response, "approval_required_for_high_impact")), tone: "ok" },
    { label: "Broad scope approval", value: enabledLabel(boolField(response, "approval_required_for_broad_scope")), tone: "ok" },
    { label: "Rollback required", value: enabledLabel(boolField(response, "rollback_required")), tone: "ok" },
    { label: "Audit required", value: enabledLabel(boolField(response, "audit_required")), tone: "ok" },
  ];
}

function reportRows(profile: RuntimeProfileDto): SettingRow[] {
  const reports = recordField(profile, "report_export_policy");
  return [
    { label: "Formats", value: listLabel(arrayField(reports, "allowed_formats")), tone: "neutral" },
    { label: "Redaction", value: choiceLabel(boolField(reports, "require_redaction"), "Required", "Off"), tone: choiceTone(boolField(reports, "require_redaction"), "ok", "blocked") },
    { label: "User confirmation", value: choiceLabel(boolField(reports, "require_user_confirmation"), "Required", "Off"), tone: choiceTone(boolField(reports, "require_user_confirmation"), "ok", "blocked") },
    { label: "Export audit", value: enabledLabel(boolField(reports, "audit_required")), tone: "ok" },
    { label: "Local export only", value: enabledLabel(boolField(reports, "local_export_only")), tone: "ok" },
    { label: "Export history", value: enabledLabel(boolField(reports, "export_history_enabled")), tone: "ok" },
  ];
}

function advancedRows(profile: RuntimeProfileDto): SettingRow[] {
  const retention = recordField(profile, "retention_policy");
  const risk = recordField(profile, "risk_policy");
  return [
    { label: "Flow retention", value: daysLabel(numberField(retention, "flows_days")), tone: "neutral" },
    { label: "Incident retention", value: daysLabel(numberField(retention, "incidents_days")), tone: "neutral" },
    { label: "Audit retention minimum", value: daysLabel(numberField(retention, "audit_events_days_minimum")), tone: "ok" },
    { label: "Reports user controlled", value: enabledLabel(boolField(retention, "reports_user_controlled")), tone: "ok" },
    { label: "Risk alerting", value: enabledLabel(boolField(risk, "risk_based_alerting_enabled")), tone: "ok" },
    { label: "Evidence required", value: enabledLabel(boolField(risk, "require_evidence_for_finding")), tone: "ok" },
  ];
}

function isSettingsSectionId(value: string | null): value is SettingsSectionId {
  return SETTINGS_SECTIONS.some((section) => section.id === value);
}

function recordField(
  value: RuntimeProfileDto | Record<string, JsonValue | undefined> | null | undefined,
  key: string,
) {
  const nested = value?.[key];
  return isRecord(nested) ? nested : null;
}

function stringField(
  value: RuntimeProfileDto | Record<string, JsonValue | undefined> | null | undefined,
  key: string,
) {
  const nested = value?.[key];
  if (typeof nested === "string") {
    return stringifySafe(nested);
  }
  if (typeof nested === "number" || typeof nested === "boolean") {
    return stringifySafe(nested);
  }
  return nested ? stringifySafe(nested) : null;
}

function boolField(
  value: RuntimeProfileDto | Record<string, JsonValue | undefined> | null | undefined,
  key: string,
) {
  const nested = value?.[key];
  return typeof nested === "boolean" ? nested : null;
}

function numberField(
  value: RuntimeProfileDto | Record<string, JsonValue | undefined> | null | undefined,
  key: string,
) {
  const nested = value?.[key];
  return typeof nested === "number" ? nested : null;
}

function arrayField(
  value: RuntimeProfileDto | Record<string, JsonValue | undefined> | null | undefined,
  key: string,
) {
  const nested = value?.[key];
  return Array.isArray(nested) ? nested.map((item) => stringifySafe(item)) : [];
}

function enabledLabel(value: boolean | null) {
  return value === null ? "not reported" : value ? "On" : "Off";
}

function disabledTone(value: boolean | null): SettingRow["tone"] {
  return value === null ? "neutral" : value ? "blocked" : "ok";
}

function statusTone(status: string): SettingRow["tone"] {
  const normalized = status.toLowerCase();
  if (normalized.includes("healthy") || normalized.includes("running")) {
    return "ok";
  }
  if (normalized.includes("disconnected") || normalized.includes("unavailable")) {
    return "warning";
  }
  if (normalized.includes("unauthorized") || normalized.includes("failed")) {
    return "blocked";
  }
  return "neutral";
}

function capabilityStatusTone(status: string): SettingRow["tone"] {
  switch (status) {
    case "available":
      return "ok";
    case "requires_setup":
    case "requires_admin":
    case "degraded":
      return "warning";
    case "blocked_by_env":
      return "blocked";
    default:
      return "neutral";
  }
}

function capabilityLabel(status: string) {
  switch (status) {
    case "available":
      return "Available";
    case "requires_setup":
      return "Setup needed";
    case "requires_admin":
      return "Admin required";
    case "blocked_by_env":
      return "Blocked";
    case "unsupported":
      return "Unsupported";
    case "degraded":
      return "Degraded";
    case "unavailable":
      return "Not available";
    default:
      return humanize(status);
  }
}

function llmProviderLabel(provider: LlmAlertStoryStatusDto["settings"]["provider"]) {
  switch (provider) {
    case "open_ai_compatible":
      return "OpenAI-compatible";
    case "deep_seek":
      return "DeepSeek";
    case "anthropic_compatible":
      return "Anthropic-compatible";
    default:
      return humanize(provider);
  }
}

function llmStorageModeLabel(mode: LlmAlertStoryStatusDto["settings"]["api_key_storage_mode"]) {
  switch (mode) {
    case "session_only":
      return "Session only";
    case "os_keystore":
      return "OS keystore";
    default:
      return humanize(mode);
  }
}

function llmCapabilityStatusLabel(status: LlmAlertStoryStatusDto["capability_status"]) {
  switch (status) {
    case "portable_available":
      return "Portable available";
    case "llm_disabled":
      return "LLM disabled";
    case "api_key_required":
      return "API key required";
    case "authorization_required":
      return "Authorization required";
    case "authorized":
      return "Authorized";
    case "provider_unavailable":
      return "Provider unavailable";
    case "degraded":
      return "Degraded";
    case "revoked":
      return "Revoked";
    case "unsupported":
      return "Unsupported";
    case "pending":
      return "Pending";
    case "redaction_failed":
      return "Redaction failed";
    default:
      return humanize(status);
  }
}

function llmCapabilityStatusTone(
  status: LlmAlertStoryStatusDto["capability_status"],
): SettingRow["tone"] {
  switch (status) {
    case "portable_available":
    case "llm_disabled":
      return "neutral";
    case "authorized":
      return "ok";
    case "api_key_required":
    case "authorization_required":
    case "provider_unavailable":
    case "degraded":
    case "pending":
      return "warning";
    case "revoked":
    case "unsupported":
    case "redaction_failed":
      return "blocked";
    default:
      return "neutral";
  }
}

function durationLabel(seconds: number | null) {
  if (!seconds) {
    return "not set";
  }
  return `${Math.round(seconds / 60)} minutes`;
}

function daysLabel(days: number | null) {
  return days === null ? "not set" : `${days} days`;
}

function listLabel(values: string[]) {
  return values.length ? values.map(humanize).join(", ") : "none";
}

function nestedVersion(value: JsonValue | undefined) {
  if (typeof value === "string") {
    return value;
  }
  if (isRecord(value)) {
    const major = stringField(value, "major");
    const minor = stringField(value, "minor");
    const patch = stringField(value, "patch");
    return [major, minor, patch].filter(Boolean).join(".") || stringifySafe(value);
  }
  return "not reported";
}

function reportedBoolean(value: boolean | null) {
  return value === null ? "not reported" : value ? "Yes" : "No";
}

function reportedHumanized(value: string | null) {
  return value ? humanize(value) : "not reported";
}

function reportedText(value: string | null) {
  return value ?? "not reported";
}

function choiceLabel(
  value: boolean | null,
  whenTrue: string,
  whenFalse: string,
) {
  return value === null ? "not reported" : value ? whenTrue : whenFalse;
}

function choiceTone(
  value: boolean | null,
  whenTrue: SettingRow["tone"],
  whenFalse: SettingRow["tone"],
) {
  return value === null ? "neutral" : value ? whenTrue : whenFalse;
}
