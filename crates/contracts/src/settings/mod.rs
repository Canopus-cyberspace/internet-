use crate::common::{
    AlertId, AuditId, EvidenceId, IncidentId, LlmAlertStoryId, RiskEventId, RuntimeProfileId,
    SchemaVersion, SettingsChangeRequestId, SettingsImpactAnalysisId, Timestamp,
};
use crate::report::ExportFormat;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const SETTINGS_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const DEFAULT_FORENSIC_TTL_SECONDS: u64 = 10 * 60;
pub const MAX_FORENSIC_TTL_SECONDS: u64 = 30 * 60;
pub const DEFAULT_AUTO_CONTAINMENT_TTL_SECONDS: u64 = 10 * 60;
pub const MAX_AUTO_CONTAINMENT_TTL_SECONDS: u64 = 30 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsContractError {
    EmptyField(&'static str),
    UnsafeDefault(&'static str),
    ForensicModeMissing(&'static str),
    SensitiveMarker(&'static str),
    BoundedFieldTooLarge(&'static str),
    InvalidHash(&'static str),
    InvalidTtl {
        field: &'static str,
        max_seconds: u64,
        actual_seconds: u64,
    },
    UnsupportedExportFormat(String),
}

impl fmt::Display for SettingsContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::UnsafeDefault(field) => write!(f, "{field} is not allowed by safe defaults"),
            Self::ForensicModeMissing(field) => {
                write!(f, "forensic mode requires explicit {field}")
            }
            Self::SensitiveMarker(field) => {
                write!(f, "{field} contains a forbidden sensitive marker")
            }
            Self::BoundedFieldTooLarge(field) => write!(f, "{field} exceeds its bounded limit"),
            Self::InvalidHash(field) => write!(f, "{field} must be a sha256 hex digest"),
            Self::InvalidTtl {
                field,
                max_seconds,
                actual_seconds,
            } => write!(
                f,
                "{field} TTL {actual_seconds}s exceeds max {max_seconds}s"
            ),
            Self::UnsupportedExportFormat(format) => {
                write!(f, "export format {format} is not supported by settings")
            }
        }
    }
}

impl std::error::Error for SettingsContractError {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfileName {
    #[default]
    SafeDefault,
    LowResource,
    Balanced,
    HighPerformance,
    ForensicManual,
    ReplayMode,
    DeveloperTest,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    LocalOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForensicScopeKind {
    SelectedFlow,
    SelectedProcess,
    SelectedDestination,
    CaseScoped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicScope {
    pub scope_kind: ForensicScopeKind,
    pub scope_ref: String,
}

impl ForensicScope {
    pub fn new(
        scope_kind: ForensicScopeKind,
        scope_ref: impl Into<String>,
    ) -> Result<Self, SettingsContractError> {
        Ok(Self {
            scope_kind,
            scope_ref: require_non_empty("forensic scope_ref", scope_ref.into())?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicModeSettings {
    pub enabled: bool,
    pub reason_redacted: Option<String>,
    pub scope: Option<ForensicScope>,
    pub ttl_seconds: Option<u64>,
    pub max_ttl_seconds: u64,
    pub local_encryption_required: bool,
    pub visible_active_indicator_required: bool,
    pub audit_required: bool,
    pub export_requires_redaction: bool,
    pub export_requires_confirmation: bool,
    pub raw_packet_persistence_allowed: bool,
    pub payload_persistence_allowed: bool,
    pub http_body_persistence_allowed: bool,
}

impl ForensicModeSettings {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            reason_redacted: None,
            scope: None,
            ttl_seconds: None,
            max_ttl_seconds: MAX_FORENSIC_TTL_SECONDS,
            local_encryption_required: true,
            visible_active_indicator_required: true,
            audit_required: true,
            export_requires_redaction: true,
            export_requires_confirmation: true,
            raw_packet_persistence_allowed: false,
            payload_persistence_allowed: false,
            http_body_persistence_allowed: false,
        }
    }

    pub fn manual_schema_reserved(
        reason_redacted: impl Into<String>,
        scope: ForensicScope,
    ) -> Result<Self, SettingsContractError> {
        let mut settings = Self::disabled();
        settings.enabled = true;
        settings.reason_redacted = Some(require_non_empty(
            "forensic reason_redacted",
            reason_redacted.into(),
        )?);
        settings.scope = Some(scope);
        settings.ttl_seconds = Some(DEFAULT_FORENSIC_TTL_SECONDS);
        settings.validate()?;
        Ok(settings)
    }

    pub fn validate(&self) -> Result<(), SettingsContractError> {
        if self.raw_packet_persistence_allowed {
            return Err(SettingsContractError::UnsafeDefault(
                "forensic raw_packet_persistence_allowed",
            ));
        }
        if self.payload_persistence_allowed {
            return Err(SettingsContractError::UnsafeDefault(
                "forensic payload_persistence_allowed",
            ));
        }
        if self.http_body_persistence_allowed {
            return Err(SettingsContractError::UnsafeDefault(
                "forensic http_body_persistence_allowed",
            ));
        }

        if self.enabled {
            if self
                .reason_redacted
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(SettingsContractError::ForensicModeMissing("reason"));
            }
            if self.scope.is_none() {
                return Err(SettingsContractError::ForensicModeMissing("scope"));
            }
            let ttl_seconds = self
                .ttl_seconds
                .ok_or(SettingsContractError::ForensicModeMissing("TTL"))?;
            validate_ttl("forensic ttl_seconds", ttl_seconds, self.max_ttl_seconds)?;
            if !self.local_encryption_required {
                return Err(SettingsContractError::UnsafeDefault(
                    "forensic local_encryption_required",
                ));
            }
            if !self.visible_active_indicator_required {
                return Err(SettingsContractError::UnsafeDefault(
                    "forensic visible_active_indicator_required",
                ));
            }
            if !self.audit_required {
                return Err(SettingsContractError::UnsafeDefault(
                    "forensic audit_required",
                ));
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPolicy {
    pub policy_version: SchemaVersion,
    pub storage_mode: StorageMode,
    pub cloud_sync_enabled: bool,
    pub security_telemetry_enabled: bool,
    pub raw_packet_storage_enabled: bool,
    pub payload_storage_enabled: bool,
    pub http_body_storage_enabled: bool,
    pub cookie_token_credential_storage_enabled: bool,
    pub authorization_header_storage_enabled: bool,
    pub api_key_storage_enabled: bool,
    pub forensic_mode: ForensicModeSettings,
}

impl PrivacyPolicy {
    pub fn safe_default() -> Self {
        Self {
            policy_version: SETTINGS_SCHEMA_VERSION,
            storage_mode: StorageMode::LocalOnly,
            cloud_sync_enabled: false,
            security_telemetry_enabled: false,
            raw_packet_storage_enabled: false,
            payload_storage_enabled: false,
            http_body_storage_enabled: false,
            cookie_token_credential_storage_enabled: false,
            authorization_header_storage_enabled: false,
            api_key_storage_enabled: false,
            forensic_mode: ForensicModeSettings::disabled(),
        }
    }

    pub fn validate(&self) -> Result<(), SettingsContractError> {
        if self.cloud_sync_enabled {
            return Err(SettingsContractError::UnsafeDefault("cloud_sync_enabled"));
        }
        if self.security_telemetry_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "security_telemetry_enabled",
            ));
        }
        if self.raw_packet_storage_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "raw_packet_storage_enabled",
            ));
        }
        if self.payload_storage_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "payload_storage_enabled",
            ));
        }
        if self.http_body_storage_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "http_body_storage_enabled",
            ));
        }
        if self.cookie_token_credential_storage_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "cookie_token_credential_storage_enabled",
            ));
        }
        if self.authorization_header_storage_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "authorization_header_storage_enabled",
            ));
        }
        if self.api_key_storage_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "api_key_storage_enabled",
            ));
        }
        self.forensic_mode.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureAdapterPreference {
    AutoMetadataOnly,
    WinDivert,
    PktmonDiagnostic,
    ImportedOnly,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureDirectionSetting {
    Inbound,
    Outbound,
    Both,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureSettings {
    pub enabled: bool,
    pub adapter_preference: CaptureAdapterPreference,
    pub direction: CaptureDirectionSetting,
    pub protocol_filters: Vec<String>,
    pub interface_allowlist: Vec<String>,
    pub store_packet_metadata: bool,
    pub store_raw_packets: bool,
    pub store_payloads: bool,
    pub store_http_bodies: bool,
    pub reduced_visibility_warning_enabled: bool,
    pub capture_health_visible: bool,
    pub drop_rate_visible: bool,
}

impl CaptureSettings {
    pub fn safe_default() -> Self {
        Self {
            enabled: true,
            adapter_preference: CaptureAdapterPreference::AutoMetadataOnly,
            direction: CaptureDirectionSetting::Both,
            protocol_filters: Vec::new(),
            interface_allowlist: Vec::new(),
            store_packet_metadata: true,
            store_raw_packets: false,
            store_payloads: false,
            store_http_bodies: false,
            reduced_visibility_warning_enabled: true,
            capture_health_visible: true,
            drop_rate_visible: true,
        }
    }

    pub fn validate(&self) -> Result<(), SettingsContractError> {
        if self.store_raw_packets {
            return Err(SettingsContractError::UnsafeDefault("store_raw_packets"));
        }
        if self.store_payloads {
            return Err(SettingsContractError::UnsafeDefault("store_payloads"));
        }
        if self.store_http_bodies {
            return Err(SettingsContractError::UnsafeDefault("store_http_bodies"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessAttributionCollectionMode {
    StandardUser,
    ElevatedService,
    AdvancedFuture,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessAttributionSettings {
    pub collection_mode: ProcessAttributionCollectionMode,
    pub allow_unknown_attribution: bool,
    pub show_udp_limitation_warning: bool,
    pub show_vpn_proxy_limitation_warning: bool,
    pub show_protected_process_limitation_warning: bool,
    pub attribution_confidence_visible: bool,
}

impl ProcessAttributionSettings {
    pub fn safe_default() -> Self {
        Self {
            collection_mode: ProcessAttributionCollectionMode::ElevatedService,
            allow_unknown_attribution: true,
            show_udp_limitation_warning: true,
            show_vpn_proxy_limitation_warning: true,
            show_protected_process_limitation_warning: true,
            attribution_confidence_visible: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntelligenceSettings {
    pub local_bundled_intelligence_enabled: bool,
    pub signed_updates_enabled: bool,
    pub user_ioc_import_enabled: bool,
    pub online_lookup_enabled: bool,
    pub commercial_feed_configured: bool,
    pub source_provenance_required: bool,
    pub stale_feed_allowed_with_reduced_confidence: bool,
    pub online_lookup_warning_enabled: bool,
}

impl IntelligenceSettings {
    pub fn safe_default() -> Self {
        Self {
            local_bundled_intelligence_enabled: true,
            signed_updates_enabled: true,
            user_ioc_import_enabled: true,
            online_lookup_enabled: false,
            commercial_feed_configured: false,
            source_provenance_required: true,
            stale_feed_allowed_with_reduced_confidence: true,
            online_lookup_warning_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<(), SettingsContractError> {
        if self.online_lookup_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "online_lookup_enabled",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmAlertStoryProvider {
    #[default]
    OpenAiCompatible,
    DeepSeek,
    AnthropicCompatible,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmApiKeyStorageMode {
    #[default]
    SessionOnly,
    OsKeystore,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmAlertStoryCapabilityStatus {
    PortableAvailable,
    LlmDisabled,
    ApiKeyRequired,
    AuthorizationRequired,
    Authorized,
    ProviderUnavailable,
    Degraded,
    Revoked,
    Unsupported,
    Pending,
    RedactionFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmAlertStorySettings {
    pub enabled: bool,
    pub provider: LlmAlertStoryProvider,
    pub model: String,
    pub api_key_storage_mode: LlmApiKeyStorageMode,
    pub authorization_granted: bool,
    pub timeout_seconds: u64,
}

impl LlmAlertStorySettings {
    pub fn safe_default() -> Self {
        Self {
            enabled: false,
            provider: LlmAlertStoryProvider::OpenAiCompatible,
            model: "gpt-5.4-mini".to_string(),
            api_key_storage_mode: LlmApiKeyStorageMode::SessionOnly,
            authorization_granted: false,
            timeout_seconds: 20,
        }
    }

    pub fn validate(&self) -> Result<(), SettingsContractError> {
        require_non_empty("llm_alert_story.model", self.model.clone())?;
        validate_safe_text("llm_alert_story.model", &self.model)?;
        validate_ttl("llm_alert_story.timeout_seconds", self.timeout_seconds, 60)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmAlertStoryStatusView {
    pub settings: LlmAlertStorySettings,
    pub api_key_configured: bool,
    pub capability_status: LlmAlertStoryCapabilityStatus,
    pub os_keystore_supported: bool,
    pub last_successful_check: Option<Timestamp>,
    pub last_successful_generation: Option<Timestamp>,
    pub last_story_id: Option<LlmAlertStoryId>,
    pub story_count: u32,
    pub base_url_configured: bool,
    pub last_error_code: Option<String>,
    pub warning_redacted: String,
    pub generated_at: Timestamp,
}

impl LlmAlertStoryStatusView {
    pub fn portable_default() -> Self {
        Self::disabled(true)
    }

    pub fn disabled(portable_mode: bool) -> Self {
        Self {
            settings: LlmAlertStorySettings::safe_default(),
            api_key_configured: false,
            capability_status: if portable_mode {
                LlmAlertStoryCapabilityStatus::PortableAvailable
            } else {
                LlmAlertStoryCapabilityStatus::LlmDisabled
            },
            os_keystore_supported: cfg!(windows),
            last_successful_check: None,
            last_successful_generation: None,
            last_story_id: None,
            story_count: 0,
            base_url_configured: false,
            last_error_code: None,
            warning_redacted:
                "Redacted alert summaries may be sent to the configured provider when this optional feature is enabled."
                    .to_string(),
            generated_at: Timestamp::now(),
        }
    }
}

pub const MAX_LLM_STORY_LIST_ITEMS: usize = 24;
pub const MAX_LLM_STORY_TEXT_BYTES: usize = 2_048;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmAttackTechniqueRef {
    pub tactic_id: String,
    pub technique_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmAlertStoryTimelineItem {
    pub timestamp: Timestamp,
    pub category: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmAlertStoryRequest {
    pub alert_ref: AlertId,
    pub incident_ref: Option<IncidentId>,
    pub severity: String,
    pub risk_bucket: String,
    pub detector_ids: Vec<String>,
    pub finding_categories: Vec<String>,
    pub redacted_entity_labels: Vec<String>,
    pub destination_categories: Vec<String>,
    pub provider_categories: Vec<String>,
    pub evidence_refs: Vec<EvidenceId>,
    pub risk_refs: Vec<RiskEventId>,
    pub attack_refs: Vec<LlmAttackTechniqueRef>,
    pub timeline: Vec<LlmAlertStoryTimelineItem>,
    pub quality_summaries: Vec<String>,
    pub native_sampler_readiness_summaries: Vec<String>,
    pub redaction_indicators: Vec<String>,
    pub degraded_indicators: Vec<String>,
}

impl LlmAlertStoryRequest {
    pub fn validate(&self) -> Result<(), SettingsContractError> {
        validate_story_text("llm_story.severity", &self.severity)?;
        validate_story_text("llm_story.risk_bucket", &self.risk_bucket)?;
        validate_story_text_list("llm_story.detector_ids", &self.detector_ids)?;
        validate_story_text_list("llm_story.finding_categories", &self.finding_categories)?;
        validate_story_text_list(
            "llm_story.redacted_entity_labels",
            &self.redacted_entity_labels,
        )?;
        validate_story_text_list(
            "llm_story.destination_categories",
            &self.destination_categories,
        )?;
        validate_story_text_list("llm_story.provider_categories", &self.provider_categories)?;
        validate_story_text_list("llm_story.quality_summaries", &self.quality_summaries)?;
        validate_story_text_list(
            "llm_story.native_sampler_readiness_summaries",
            &self.native_sampler_readiness_summaries,
        )?;
        validate_story_text_list("llm_story.redaction_indicators", &self.redaction_indicators)?;
        validate_story_text_list("llm_story.degraded_indicators", &self.degraded_indicators)?;
        validate_story_len("llm_story.evidence_refs", self.evidence_refs.len())?;
        validate_story_len("llm_story.risk_refs", self.risk_refs.len())?;
        validate_story_len("llm_story.attack_refs", self.attack_refs.len())?;
        validate_story_len("llm_story.timeline", self.timeline.len())?;
        for attack_ref in &self.attack_refs {
            validate_story_text("llm_story.tactic_id", &attack_ref.tactic_id)?;
            validate_story_text("llm_story.technique_id", &attack_ref.technique_id)?;
        }
        for item in &self.timeline {
            validate_story_text("llm_story.timeline.category", &item.category)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmAlertStoryDraft {
    pub alert_narrative_redacted: String,
    pub likely_attack_summary_redacted: String,
    pub confidence_uncertainty_redacted: String,
    pub evidence_summary_redacted: String,
    pub affected_entities_redacted: Vec<String>,
    pub investigation_suggestions_redacted: Vec<String>,
    pub report_text_redacted: String,
}

impl LlmAlertStoryDraft {
    pub fn validate(&self) -> Result<(), SettingsContractError> {
        validate_story_text(
            "llm_story.alert_narrative_redacted",
            &self.alert_narrative_redacted,
        )?;
        validate_story_text(
            "llm_story.likely_attack_summary_redacted",
            &self.likely_attack_summary_redacted,
        )?;
        validate_story_text(
            "llm_story.confidence_uncertainty_redacted",
            &self.confidence_uncertainty_redacted,
        )?;
        validate_story_text(
            "llm_story.evidence_summary_redacted",
            &self.evidence_summary_redacted,
        )?;
        validate_story_text_list(
            "llm_story.affected_entities_redacted",
            &self.affected_entities_redacted,
        )?;
        validate_story_text_list(
            "llm_story.investigation_suggestions_redacted",
            &self.investigation_suggestions_redacted,
        )?;
        validate_story_text("llm_story.report_text_redacted", &self.report_text_redacted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmAlertStoryRecord {
    pub story_id: LlmAlertStoryId,
    pub alert_ref: AlertId,
    pub incident_ref: Option<IncidentId>,
    pub provider: LlmAlertStoryProvider,
    pub model: String,
    pub request_hash: String,
    pub response_hash: String,
    pub generated_at: Timestamp,
    pub ai_generated: bool,
    pub redaction_passed: bool,
    pub degraded: bool,
    pub story: LlmAlertStoryDraft,
    pub evidence_refs: Vec<EvidenceId>,
    pub risk_refs: Vec<RiskEventId>,
    pub attack_refs: Vec<LlmAttackTechniqueRef>,
}

impl LlmAlertStoryRecord {
    pub fn validate(&self) -> Result<(), SettingsContractError> {
        if !self.ai_generated || !self.redaction_passed {
            return Err(SettingsContractError::UnsafeDefault(
                "llm_story.redaction_passed",
            ));
        }
        validate_story_text("llm_story.model", &self.model)?;
        validate_sha256("llm_story.request_hash", &self.request_hash)?;
        validate_sha256("llm_story.response_hash", &self.response_hash)?;
        validate_story_len("llm_story.evidence_refs", self.evidence_refs.len())?;
        validate_story_len("llm_story.risk_refs", self.risk_refs.len())?;
        validate_story_len("llm_story.attack_refs", self.attack_refs.len())?;
        if self.evidence_refs.is_empty() || self.risk_refs.is_empty() || self.attack_refs.is_empty()
        {
            return Err(SettingsContractError::EmptyField("llm_story.traceability"));
        }
        self.story.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiSecurityMode {
    PacketOnlyApiHint,
    ImportedLogsMonitorOnly,
    FullApiSecurityNotConfigured,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSecuritySettings {
    pub mode: ApiSecurityMode,
    pub packet_only_hints_enabled: bool,
    pub full_api_security_configured: bool,
    pub local_tls_inspection_enabled: bool,
    pub browser_extension_visibility_enabled: bool,
    pub api_policy_response_enabled: bool,
    pub import_logs_available: bool,
    pub packet_only_warning_enabled: bool,
}

impl ApiSecuritySettings {
    pub fn safe_default() -> Self {
        Self {
            mode: ApiSecurityMode::PacketOnlyApiHint,
            packet_only_hints_enabled: true,
            full_api_security_configured: false,
            local_tls_inspection_enabled: false,
            browser_extension_visibility_enabled: false,
            api_policy_response_enabled: false,
            import_logs_available: true,
            packet_only_warning_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<(), SettingsContractError> {
        if self.local_tls_inspection_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "local_tls_inspection_enabled",
            ));
        }
        if self.browser_extension_visibility_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "browser_extension_visibility_enabled",
            ));
        }
        if self.api_policy_response_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "api_policy_response_enabled",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WafIntegrationSettings {
    pub security_enabled: bool,
    pub import_modsecurity_audit_log_available: bool,
    pub import_generic_json_event_available: bool,
    pub import_generic_csv_event_available: bool,
    pub access_log_as_web_access_log_available: bool,
    pub cloud_waf_connectors_enabled: bool,
    pub enforcement_response_enabled: bool,
    pub disabled_by_default_warning_enabled: bool,
    pub access_log_not_waf_warning_enabled: bool,
}

impl WafIntegrationSettings {
    pub fn safe_default() -> Self {
        Self {
            security_enabled: false,
            import_modsecurity_audit_log_available: true,
            import_generic_json_event_available: true,
            import_generic_csv_event_available: true,
            access_log_as_web_access_log_available: true,
            cloud_waf_connectors_enabled: false,
            enforcement_response_enabled: false,
            disabled_by_default_warning_enabled: true,
            access_log_not_waf_warning_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<(), SettingsContractError> {
        if self.cloud_waf_connectors_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "cloud_waf_connectors_enabled",
            ));
        }
        if self.enforcement_response_enabled {
            return Err(SettingsContractError::UnsafeDefault(
                "waf enforcement_response_enabled",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    RecommendOnly,
    AutoContainmentLite,
    ApprovalRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsePolicy {
    pub mode: ResponseMode,
    pub auto_containment_ttl_seconds: u64,
    pub auto_containment_max_ttl_seconds: u64,
    pub allowed_auto_actions: Vec<String>,
    pub approval_required_for_high_impact: bool,
    pub approval_required_for_broad_scope: bool,
    pub waf_api_enforcement_requires_approval: bool,
    pub permanent_block_requires_approval: bool,
    pub rollback_required: bool,
    pub audit_required: bool,
    pub replay_execution_disabled: bool,
}

impl ResponsePolicy {
    pub fn recommend_only() -> Self {
        Self {
            mode: ResponseMode::RecommendOnly,
            auto_containment_ttl_seconds: DEFAULT_AUTO_CONTAINMENT_TTL_SECONDS,
            auto_containment_max_ttl_seconds: MAX_AUTO_CONTAINMENT_TTL_SECONDS,
            allowed_auto_actions: Vec::new(),
            approval_required_for_high_impact: true,
            approval_required_for_broad_scope: true,
            waf_api_enforcement_requires_approval: true,
            permanent_block_requires_approval: true,
            rollback_required: true,
            audit_required: true,
            replay_execution_disabled: true,
        }
    }

    pub fn auto_containment_lite() -> Self {
        let mut policy = Self::recommend_only();
        policy.mode = ResponseMode::AutoContainmentLite;
        policy.allowed_auto_actions = vec![
            "malicious_destination_auto_block".to_string(),
            "exfiltration_auto_throttle".to_string(),
        ];
        policy
    }

    pub fn approval_required() -> Self {
        let mut policy = Self::recommend_only();
        policy.mode = ResponseMode::ApprovalRequired;
        policy
    }

    pub fn validate(&self) -> Result<(), SettingsContractError> {
        validate_ttl(
            "auto_containment_ttl_seconds",
            self.auto_containment_ttl_seconds,
            self.auto_containment_max_ttl_seconds,
        )?;
        if !self.rollback_required {
            return Err(SettingsContractError::UnsafeDefault("rollback_required"));
        }
        if !self.audit_required {
            return Err(SettingsContractError::UnsafeDefault("audit_required"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportExportPolicy {
    pub allowed_formats: Vec<ExportFormat>,
    pub require_redaction: bool,
    pub require_user_confirmation: bool,
    pub audit_required: bool,
    pub local_export_only: bool,
    pub export_history_enabled: bool,
}

impl ReportExportPolicy {
    pub fn safe_default() -> Self {
        Self {
            allowed_formats: vec![
                ExportFormat::Markdown,
                ExportFormat::Html,
                ExportFormat::RedactedJson,
            ],
            require_redaction: true,
            require_user_confirmation: true,
            audit_required: true,
            local_export_only: true,
            export_history_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<(), SettingsContractError> {
        for format in &self.allowed_formats {
            if !format.is_supported_v1() {
                return Err(SettingsContractError::UnsupportedExportFormat(
                    format.as_str().to_string(),
                ));
            }
        }
        if !self.require_redaction {
            return Err(SettingsContractError::UnsafeDefault("require_redaction"));
        }
        if !self.require_user_confirmation {
            return Err(SettingsContractError::UnsafeDefault(
                "require_user_confirmation",
            ));
        }
        if !self.audit_required {
            return Err(SettingsContractError::UnsafeDefault(
                "export audit_required",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub flows_days: u16,
    pub sessions_days: u16,
    pub dns_observations_days: u16,
    pub tls_observations_days: u16,
    pub http_metadata_days: u16,
    pub process_context_days: u16,
    pub asset_exposure_days: u16,
    pub findings_days: u16,
    pub alerts_days: u16,
    pub incidents_days: u16,
    pub audit_events_days_minimum: u16,
    pub reports_user_controlled: bool,
    pub preserve_incident_related_evidence: bool,
    pub preserve_audit_events: bool,
}

impl RetentionPolicy {
    pub fn safe_default() -> Self {
        Self {
            flows_days: 30,
            sessions_days: 30,
            dns_observations_days: 30,
            tls_observations_days: 90,
            http_metadata_days: 14,
            process_context_days: 30,
            asset_exposure_days: 90,
            findings_days: 90,
            alerts_days: 180,
            incidents_days: 365,
            audit_events_days_minimum: 365,
            reports_user_controlled: true,
            preserve_incident_related_evidence: true,
            preserve_audit_events: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatusSettings {
    pub show_elevated_service_status: bool,
    pub show_capture_health: bool,
    pub show_process_attribution_quality: bool,
    pub show_storage_status: bool,
    pub show_intelligence_status: bool,
    pub show_response_executor_status: bool,
    pub show_ipc_status: bool,
    pub degraded_state_banner_enabled: bool,
}

impl ServiceStatusSettings {
    pub fn safe_default() -> Self {
        Self {
            show_elevated_service_status: true,
            show_capture_health: true,
            show_process_attribution_quality: true,
            show_storage_status: true,
            show_intelligence_status: true,
            show_response_executor_status: true,
            show_ipc_status: true,
            degraded_state_banner_enabled: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionPolicy {
    pub c2_detection_enabled: bool,
    pub exfiltration_detection_enabled: bool,
    pub lateral_movement_lite_enabled: bool,
    pub intelligence_hit_can_create_alert_directly: bool,
    pub low_confidence_single_signal_alerts_allowed: bool,
}

impl DetectionPolicy {
    pub fn safe_default() -> Self {
        Self {
            c2_detection_enabled: true,
            exfiltration_detection_enabled: true,
            lateral_movement_lite_enabled: true,
            intelligence_hit_can_create_alert_directly: false,
            low_confidence_single_signal_alerts_allowed: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskPolicy {
    pub risk_based_alerting_enabled: bool,
    pub require_evidence_for_finding: bool,
    pub require_alert_traceability: bool,
    pub require_incident_traceability: bool,
}

impl RiskPolicy {
    pub fn safe_default() -> Self {
        Self {
            risk_based_alerting_enabled: true,
            require_evidence_for_finding: true,
            require_alert_traceability: true,
            require_incident_traceability: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeProfile {
    pub profile_id: RuntimeProfileId,
    pub name: RuntimeProfileName,
    pub display_name: String,
    pub schema_version: SchemaVersion,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub is_default: bool,
    pub privacy_policy: PrivacyPolicy,
    pub capture_settings: CaptureSettings,
    pub process_attribution_settings: ProcessAttributionSettings,
    pub intelligence_settings: IntelligenceSettings,
    pub api_security_settings: ApiSecuritySettings,
    pub waf_integration_settings: WafIntegrationSettings,
    pub response_policy: ResponsePolicy,
    pub report_export_policy: ReportExportPolicy,
    pub retention_policy: RetentionPolicy,
    pub service_status_settings: ServiceStatusSettings,
    pub detection_policy: DetectionPolicy,
    pub risk_policy: RiskPolicy,
}

impl RuntimeProfile {
    pub fn safe_default() -> Self {
        Self::base(RuntimeProfileName::SafeDefault, "Safe Default", true)
    }

    pub fn balanced() -> Self {
        Self::base(RuntimeProfileName::Balanced, "Balanced", false)
    }

    pub fn low_resource() -> Self {
        let mut profile = Self::base(RuntimeProfileName::LowResource, "Low Resource", false);
        profile.capture_settings.reduced_visibility_warning_enabled = true;
        profile
            .service_status_settings
            .degraded_state_banner_enabled = true;
        profile
    }

    pub fn high_performance() -> Self {
        let mut profile = Self::base(
            RuntimeProfileName::HighPerformance,
            "High Performance",
            false,
        );
        profile.response_policy = ResponsePolicy::auto_containment_lite();
        profile
    }

    pub fn forensic_manual(
        reason_redacted: impl Into<String>,
        scope: ForensicScope,
    ) -> Result<Self, SettingsContractError> {
        let mut profile = Self::base(RuntimeProfileName::ForensicManual, "Forensic Manual", false);
        profile.privacy_policy.forensic_mode =
            ForensicModeSettings::manual_schema_reserved(reason_redacted, scope)?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn replay_mode() -> Self {
        let mut profile = Self::base(RuntimeProfileName::ReplayMode, "Replay Mode", false);
        profile.response_policy.replay_execution_disabled = true;
        profile.response_policy.mode = ResponseMode::RecommendOnly;
        profile
    }

    pub fn developer_test() -> Self {
        let mut profile = Self::base(RuntimeProfileName::DeveloperTest, "Developer Test", false);
        profile.capture_settings.adapter_preference = CaptureAdapterPreference::ImportedOnly;
        profile.response_policy.mode = ResponseMode::RecommendOnly;
        profile
    }

    pub fn default_profiles() -> Vec<Self> {
        vec![
            Self::safe_default(),
            Self::low_resource(),
            Self::balanced(),
            Self::high_performance(),
            Self::replay_mode(),
            Self::developer_test(),
        ]
    }

    pub fn validate(&self) -> Result<(), SettingsContractError> {
        require_non_empty("display_name", self.display_name.clone())?;
        self.privacy_policy.validate()?;
        self.capture_settings.validate()?;
        self.intelligence_settings.validate()?;
        self.api_security_settings.validate()?;
        self.waf_integration_settings.validate()?;
        self.response_policy.validate()?;
        self.report_export_policy.validate()
    }

    fn base(name: RuntimeProfileName, display_name: &'static str, is_default: bool) -> Self {
        let now = Timestamp::now();
        Self {
            profile_id: RuntimeProfileId::new_v4(),
            name,
            display_name: display_name.to_string(),
            schema_version: SETTINGS_SCHEMA_VERSION,
            created_at: now.clone(),
            updated_at: now,
            is_default,
            privacy_policy: PrivacyPolicy::safe_default(),
            capture_settings: CaptureSettings::safe_default(),
            process_attribution_settings: ProcessAttributionSettings::safe_default(),
            intelligence_settings: IntelligenceSettings::safe_default(),
            api_security_settings: ApiSecuritySettings::safe_default(),
            waf_integration_settings: WafIntegrationSettings::safe_default(),
            response_policy: ResponsePolicy::recommend_only(),
            report_export_policy: ReportExportPolicy::safe_default(),
            retention_policy: RetentionPolicy::safe_default(),
            service_status_settings: ServiceStatusSettings::safe_default(),
            detection_policy: DetectionPolicy::safe_default(),
            risk_policy: RiskPolicy::safe_default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsChangeKind {
    RuntimeProfile,
    PrivacyPolicy,
    CaptureSettings,
    AttributionSettings,
    IntelligenceSettings,
    ApiSecuritySettings,
    WafIntegrationSettings,
    ResponsePolicy,
    ReportExportPolicy,
    RetentionPolicy,
    ServiceStatusSettings,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsChangeRequest {
    pub request_id: SettingsChangeRequestId,
    pub change_kind: SettingsChangeKind,
    pub requested_profile: RuntimeProfile,
    pub reason_redacted: String,
    pub requested_by: Option<String>,
    pub created_at: Timestamp,
    pub validate_before_apply: bool,
    pub impact_analysis_required: bool,
    pub audit_required: bool,
    pub rollback_supported: bool,
}

impl SettingsChangeRequest {
    pub fn new(
        change_kind: SettingsChangeKind,
        requested_profile: RuntimeProfile,
        reason_redacted: impl Into<String>,
    ) -> Result<Self, SettingsContractError> {
        let request = Self {
            request_id: SettingsChangeRequestId::new_v4(),
            change_kind,
            requested_profile,
            reason_redacted: require_non_empty("reason_redacted", reason_redacted.into())?,
            requested_by: None,
            created_at: Timestamp::now(),
            validate_before_apply: true,
            impact_analysis_required: true,
            audit_required: true,
            rollback_supported: true,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), SettingsContractError> {
        if !self.validate_before_apply {
            return Err(SettingsContractError::UnsafeDefault(
                "validate_before_apply",
            ));
        }
        if !self.impact_analysis_required {
            return Err(SettingsContractError::UnsafeDefault(
                "impact_analysis_required",
            ));
        }
        if !self.audit_required {
            return Err(SettingsContractError::UnsafeDefault(
                "settings audit_required",
            ));
        }
        self.requested_profile.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsImpactLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsImpactAnalysis {
    pub analysis_id: SettingsImpactAnalysisId,
    pub request_id: SettingsChangeRequestId,
    pub profile_name: RuntimeProfileName,
    pub impact_level: SettingsImpactLevel,
    pub warnings_redacted: Vec<String>,
    pub forbidden_changes: Vec<String>,
    pub confirmation_required: bool,
    pub audit_required: bool,
    pub rollback_supported: bool,
    pub audit_ref: Option<AuditId>,
    pub created_at: Timestamp,
}

impl SettingsImpactAnalysis {
    pub fn from_request(request: &SettingsChangeRequest) -> Self {
        let mut warnings = Vec::new();
        let mut forbidden_changes = Vec::new();
        let profile = &request.requested_profile;

        if profile.privacy_policy.forensic_mode.enabled {
            warnings.push(
                "Forensic mode is explicit, time-limited, audited, and schema-reserved in V1"
                    .to_string(),
            );
        }
        if profile.intelligence_settings.online_lookup_enabled {
            forbidden_changes.push("online lookup is disabled by default".to_string());
        }
        if profile.api_security_settings.api_policy_response_enabled {
            forbidden_changes.push("API policy response is disabled in personal PC V1".to_string());
        }
        if profile
            .waf_integration_settings
            .enforcement_response_enabled
        {
            forbidden_changes
                .push("WAF enforcement response is disabled in personal PC V1".to_string());
        }

        let impact_level = if !forbidden_changes.is_empty() {
            SettingsImpactLevel::Critical
        } else if profile.privacy_policy.forensic_mode.enabled {
            SettingsImpactLevel::High
        } else if matches!(
            profile.response_policy.mode,
            ResponseMode::AutoContainmentLite
        ) {
            SettingsImpactLevel::Medium
        } else {
            SettingsImpactLevel::Low
        };

        Self {
            analysis_id: SettingsImpactAnalysisId::new_v4(),
            request_id: request.request_id.clone(),
            profile_name: profile.name.clone(),
            impact_level,
            warnings_redacted: warnings,
            forbidden_changes,
            confirmation_required: true,
            audit_required: request.audit_required,
            rollback_supported: request.rollback_supported,
            audit_ref: None,
            created_at: Timestamp::now(),
        }
    }
}

fn validate_ttl(
    field: &'static str,
    actual_seconds: u64,
    max_seconds: u64,
) -> Result<(), SettingsContractError> {
    if actual_seconds == 0 || actual_seconds > max_seconds {
        Err(SettingsContractError::InvalidTtl {
            field,
            max_seconds,
            actual_seconds,
        })
    } else {
        Ok(())
    }
}

fn require_non_empty(field: &'static str, value: String) -> Result<String, SettingsContractError> {
    if value.trim().is_empty() {
        Err(SettingsContractError::EmptyField(field))
    } else {
        validate_safe_text(field, &value)?;
        Ok(value)
    }
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), SettingsContractError> {
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '/', '='], "_");
    for marker in [
        "raw_packet",
        "raw_payload",
        "payload",
        "http_body",
        "authorization",
        "api_key",
        "cookie",
        "credential",
        "password",
        "private_key",
        "session_token",
        "access_token",
        "refresh_token",
        "token",
        "secret",
        "command_line",
        "filepath",
        "username",
    ] {
        if normalized.contains(marker) {
            return Err(SettingsContractError::SensitiveMarker(field));
        }
    }
    Ok(())
}

fn validate_story_len(field: &'static str, len: usize) -> Result<(), SettingsContractError> {
    if len > MAX_LLM_STORY_LIST_ITEMS {
        Err(SettingsContractError::BoundedFieldTooLarge(field))
    } else {
        Ok(())
    }
}

fn validate_story_text_list(
    field: &'static str,
    values: &[String],
) -> Result<(), SettingsContractError> {
    validate_story_len(field, values.len())?;
    for value in values {
        validate_story_text(field, value)?;
    }
    Ok(())
}

fn validate_story_text(field: &'static str, value: &str) -> Result<(), SettingsContractError> {
    if value.trim().is_empty() {
        return Err(SettingsContractError::EmptyField(field));
    }
    if value.len() > MAX_LLM_STORY_TEXT_BYTES {
        return Err(SettingsContractError::BoundedFieldTooLarge(field));
    }
    validate_safe_text(field, value)?;
    let lower = value.to_ascii_lowercase();
    if lower.contains("://")
        || lower.contains('@')
        || lower.contains(":\\")
        || lower.contains("\\\\")
        || lower.contains("tenant_id")
        || lower.contains("filename")
        || lower.contains("full_path")
        || looks_like_ipv4(value)
    {
        return Err(SettingsContractError::SensitiveMarker(field));
    }
    Ok(())
}

fn looks_like_ipv4(value: &str) -> bool {
    value.split_whitespace().any(|part| {
        let trimmed =
            part.trim_matches(|character: char| !character.is_ascii_digit() && character != '.');
        let segments = trimmed.split('.').collect::<Vec<_>>();
        segments.len() == 4
            && segments
                .iter()
                .all(|segment| !segment.is_empty() && segment.parse::<u8>().is_ok())
    })
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), SettingsContractError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(SettingsContractError::InvalidHash(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_default_is_local_only_metadata_first() {
        let profile = RuntimeProfile::safe_default();

        assert_eq!(profile.name, RuntimeProfileName::SafeDefault);
        assert!(profile.is_default);
        assert!(!profile.privacy_policy.cloud_sync_enabled);
        assert!(!profile.privacy_policy.raw_packet_storage_enabled);
        assert!(!profile.privacy_policy.payload_storage_enabled);
        assert!(!profile.privacy_policy.http_body_storage_enabled);
        assert!(!profile.privacy_policy.forensic_mode.enabled);
        assert_eq!(profile.response_policy.mode, ResponseMode::RecommendOnly);
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn llm_alert_story_defaults_to_disabled_safe_local_configuration() {
        let settings = LlmAlertStorySettings::safe_default();
        let status = LlmAlertStoryStatusView::portable_default();

        assert!(!settings.enabled);
        assert_eq!(settings.provider, LlmAlertStoryProvider::OpenAiCompatible);
        assert_eq!(
            settings.api_key_storage_mode,
            LlmApiKeyStorageMode::SessionOnly
        );
        assert!(settings.validate().is_ok());
        assert_eq!(
            status.capability_status,
            LlmAlertStoryCapabilityStatus::PortableAvailable
        );
        assert!(!status.api_key_configured);
    }

    #[test]
    fn llm_alert_story_rejects_sensitive_marker_in_model_field() {
        let mut settings = LlmAlertStorySettings::safe_default();
        settings.model = "api_key-secret".to_string();

        assert_eq!(
            settings.validate(),
            Err(SettingsContractError::SensitiveMarker(
                "llm_alert_story.model"
            ))
        );
    }

    #[test]
    fn llm_alert_story_request_and_record_reject_sensitive_content() {
        let mut request = LlmAlertStoryRequest {
            alert_ref: AlertId::new_v4(),
            incident_ref: Some(IncidentId::new_v4()),
            severity: "high".to_string(),
            risk_bucket: "elevated".to_string(),
            detector_ids: vec!["dns_high_entropy".to_string()],
            finding_categories: vec!["dns_security".to_string()],
            redacted_entity_labels: vec!["domain:redacted".to_string()],
            destination_categories: vec!["object_storage".to_string()],
            provider_categories: vec!["cloud".to_string()],
            evidence_refs: vec![EvidenceId::new_v4()],
            risk_refs: vec![RiskEventId::new_v4()],
            attack_refs: vec![LlmAttackTechniqueRef {
                tactic_id: "TA0010".to_string(),
                technique_id: "T1048".to_string(),
            }],
            timeline: vec![LlmAlertStoryTimelineItem {
                timestamp: Timestamp::now(),
                category: "finding_observed".to_string(),
            }],
            quality_summaries: vec!["quality_bucket_low".to_string()],
            native_sampler_readiness_summaries: vec![
                "sampler:process_metadata_sampler:blocked_portable_default".to_string(),
            ],
            redaction_indicators: vec!["metadata_only".to_string()],
            degraded_indicators: vec!["no_process_visibility".to_string()],
        };
        assert!(request.validate().is_ok());

        request.redacted_entity_labels = vec!["192.0.2.42".to_string()];
        assert_eq!(
            request.validate(),
            Err(SettingsContractError::SensitiveMarker(
                "llm_story.redacted_entity_labels"
            ))
        );
    }

    #[test]
    fn forensic_manual_requires_explicit_scope_reason_ttl_and_audit() {
        let scope = ForensicScope::new(ForensicScopeKind::SelectedFlow, "flow-ref").unwrap();
        let profile = RuntimeProfile::forensic_manual("case investigation", scope).unwrap();

        assert!(profile.privacy_policy.forensic_mode.enabled);
        assert!(profile.privacy_policy.forensic_mode.audit_required);
        assert!(
            profile
                .privacy_policy
                .forensic_mode
                .local_encryption_required
        );
        assert!(
            !profile
                .privacy_policy
                .forensic_mode
                .payload_persistence_allowed
        );
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn unsafe_privacy_settings_are_rejected() {
        let mut policy = PrivacyPolicy::safe_default();
        policy.raw_packet_storage_enabled = true;

        assert_eq!(
            policy.validate(),
            Err(SettingsContractError::UnsafeDefault(
                "raw_packet_storage_enabled"
            ))
        );
    }

    #[test]
    fn api_and_waf_defaults_are_warning_first_disabled_by_default() {
        let profile = RuntimeProfile::safe_default();

        assert_eq!(
            profile.api_security_settings.mode,
            ApiSecurityMode::PacketOnlyApiHint
        );
        assert!(profile.api_security_settings.packet_only_warning_enabled);
        assert!(!profile.api_security_settings.api_policy_response_enabled);
        assert!(!profile.waf_integration_settings.security_enabled);
        assert!(
            profile
                .waf_integration_settings
                .disabled_by_default_warning_enabled
        );
        assert!(
            !profile
                .waf_integration_settings
                .enforcement_response_enabled
        );
    }

    #[test]
    fn export_policy_supports_only_v1_formats() {
        let mut policy = ReportExportPolicy::safe_default();
        policy
            .allowed_formats
            .push(ExportFormat::Unsupported("pdf".to_string()));

        assert_eq!(
            policy.validate(),
            Err(SettingsContractError::UnsupportedExportFormat(
                "pdf".to_string()
            ))
        );
    }

    #[test]
    fn settings_change_request_is_validation_and_audit_aware() {
        let profile = RuntimeProfile::safe_default();
        let request = SettingsChangeRequest::new(
            SettingsChangeKind::RuntimeProfile,
            profile,
            "switch to default profile",
        )
        .unwrap();
        let impact = SettingsImpactAnalysis::from_request(&request);

        assert!(request.validate_before_apply);
        assert!(request.impact_analysis_required);
        assert!(request.audit_required);
        assert_eq!(impact.impact_level, SettingsImpactLevel::Low);
        assert!(impact.audit_required);
    }
}
