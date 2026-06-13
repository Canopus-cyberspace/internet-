use crate::report::{ExportFormat, RedactedDataCategory};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseGateArea {
    Platform,
    Privacy,
    Capture,
    ProcessAttribution,
    Detection,
    Graph,
    Response,
    ApiWaf,
    Report,
    Performance,
    Reliability,
}

impl ReleaseGateArea {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Privacy => "privacy",
            Self::Capture => "capture",
            Self::ProcessAttribution => "process_attribution",
            Self::Detection => "detection",
            Self::Graph => "graph",
            Self::Response => "response",
            Self::ApiWaf => "api_waf",
            Self::Report => "report",
            Self::Performance => "performance",
            Self::Reliability => "reliability",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseGateStatus {
    ValidatedInFixtureSlice,
    ProvisionalStub,
    ManualReleaseGate,
    NotReadyForRelease,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGate {
    pub area: ReleaseGateArea,
    pub acceptance_criteria: Vec<String>,
    pub evidence_required: Vec<String>,
    pub status: ReleaseGateStatus,
    pub known_limitations_redacted: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallerPlan {
    pub installer_shape: String,
    pub planned_technology_redacted: String,
    pub includes_tauri_desktop: bool,
    pub includes_rust_local_core: bool,
    pub includes_elevated_windows_service: bool,
    pub sqlite_storage_location_redacted: String,
    pub update_strategy_redacted: String,
    pub rollback_strategy_redacted: String,
    pub code_signing_required: bool,
    pub actual_tooling_deferred: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInstallPlan {
    pub service_name: String,
    pub installed_by_elevated_installer: bool,
    pub start_stop_expectations: Vec<String>,
    pub ipc_transport: String,
    pub degraded_behavior: Vec<String>,
    pub non_admin_behavior: Vec<String>,
    pub forbidden_service_responsibilities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReducedVisibilityModePlan {
    pub active_when: Vec<String>,
    pub user_visible_banners: Vec<String>,
    pub allowed_capabilities: Vec<String>,
    pub disabled_capabilities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyDefaultChecklist {
    pub local_only_storage: bool,
    pub cloud_sync_enabled: bool,
    pub online_intelligence_lookup_enabled: bool,
    pub raw_packet_persistence_enabled: bool,
    pub payload_persistence_enabled: bool,
    pub http_body_persistence_enabled: bool,
    pub cookie_token_credential_persistence_enabled: bool,
    pub api_key_persistence_enabled: bool,
    pub forensic_mode_manual_ttl_audited: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseSafetyChecklist {
    pub default_mode_recommend_only: bool,
    pub limited_auto_containment_allowlisted: bool,
    pub high_impact_requires_approval: bool,
    pub execution_requires_policy_permission_audit_ttl_rollback: bool,
    pub replay_never_executes_real_actions: bool,
    pub disabled_in_reduced_visibility: bool,
    pub prohibited_v1_actions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportExportChecklist {
    pub allowed_formats: Vec<ExportFormat>,
    pub deferred_formats: Vec<String>,
    pub redaction_required: bool,
    pub user_confirmation_required: bool,
    pub audit_required: bool,
    pub file_hash_recorded_where_available: bool,
    pub export_history_required: bool,
    pub excluded_by_default: Vec<RedactedDataCategory>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRisk {
    pub risk_id: String,
    pub area: ReleaseGateArea,
    pub summary_redacted: String,
    pub mitigation_redacted: String,
    pub release_blocking_until_resolved: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRiskRegister {
    pub risks: Vec<ReleaseRisk>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseChecklist {
    pub checklist_id: String,
    pub product_profile: String,
    pub planning_only: bool,
    pub release_ready: bool,
    pub installer_plan: InstallerPlan,
    pub service_install_plan: ServiceInstallPlan,
    pub reduced_visibility_mode: ReducedVisibilityModePlan,
    pub privacy_defaults: PrivacyDefaultChecklist,
    pub response_safety: ResponseSafetyChecklist,
    pub report_export: ReportExportChecklist,
    pub release_gates: Vec<ReleaseGate>,
    pub risk_register: ReleaseRiskRegister,
}

impl ReleaseChecklist {
    pub fn windows_personal_pc_v1_planning() -> Self {
        Self {
            checklist_id: "sentinel-guard-windows-v1-planning".to_string(),
            product_profile: "Windows local desktop personal PC V1".to_string(),
            planning_only: true,
            release_ready: false,
            installer_plan: InstallerPlan::windows_v1_planning(),
            service_install_plan: ServiceInstallPlan::windows_v1_planning(),
            reduced_visibility_mode: ReducedVisibilityModePlan::windows_v1(),
            privacy_defaults: PrivacyDefaultChecklist::safe_default(),
            response_safety: ResponseSafetyChecklist::recommend_first_v1(),
            report_export: ReportExportChecklist::safe_v1(),
            release_gates: release_gates(),
            risk_register: ReleaseRiskRegister::windows_v1(),
        }
    }

    pub fn validate(&self) -> Result<(), ReleaseContractError> {
        require_non_empty("checklist_id", &self.checklist_id)?;
        require_non_empty("product_profile", &self.product_profile)?;
        if !self.planning_only {
            return Err(ReleaseContractError::UnsafeClaim("planning_only"));
        }
        if self.release_ready {
            return Err(ReleaseContractError::UnsafeClaim("release_ready"));
        }
        self.installer_plan.validate()?;
        self.service_install_plan.validate()?;
        self.reduced_visibility_mode.validate()?;
        self.privacy_defaults.validate()?;
        self.response_safety.validate()?;
        self.report_export.validate()?;
        validate_release_gates(&self.release_gates)?;
        self.risk_register.validate()?;
        Ok(())
    }
}

impl InstallerPlan {
    pub fn windows_v1_planning() -> Self {
        Self {
            installer_shape: "Signed Windows desktop installer for Tauri app plus local service"
                .to_string(),
            planned_technology_redacted:
                "Tauri bundler MSI or WiX customization; final toolchain selection is open"
                    .to_string(),
            includes_tauri_desktop: true,
            includes_rust_local_core: true,
            includes_elevated_windows_service: true,
            sqlite_storage_location_redacted:
                "per-machine or per-user local app data directory, never cloud sync by default"
                    .to_string(),
            update_strategy_redacted:
                "signed installer update with schema migration preflight and rollback notes"
                    .to_string(),
            rollback_strategy_redacted:
                "uninstall/reinstall application files; preserve local SQLite unless user confirms data removal"
                    .to_string(),
            code_signing_required: true,
            actual_tooling_deferred: true,
        }
    }

    pub fn validate(&self) -> Result<(), ReleaseContractError> {
        require_non_empty("installer_shape", &self.installer_shape)?;
        require_non_empty(
            "planned_technology_redacted",
            &self.planned_technology_redacted,
        )?;
        require_non_empty(
            "sqlite_storage_location_redacted",
            &self.sqlite_storage_location_redacted,
        )?;
        require_non_empty("update_strategy_redacted", &self.update_strategy_redacted)?;
        require_non_empty(
            "rollback_strategy_redacted",
            &self.rollback_strategy_redacted,
        )?;
        if !self.includes_tauri_desktop
            || !self.includes_rust_local_core
            || !self.includes_elevated_windows_service
        {
            return Err(ReleaseContractError::MissingInstallerComponent);
        }
        if !self.code_signing_required {
            return Err(ReleaseContractError::UnsafeClaim("code_signing_required"));
        }
        if !self.actual_tooling_deferred {
            return Err(ReleaseContractError::UnsafeClaim("actual_tooling_deferred"));
        }
        Ok(())
    }
}

impl ServiceInstallPlan {
    pub fn windows_v1_planning() -> Self {
        Self {
            service_name: "Sentinel Guard Elevated Service".to_string(),
            installed_by_elevated_installer: true,
            start_stop_expectations: vec![
                "install service during elevated setup".to_string(),
                "start service after install when policy permits".to_string(),
                "stop service during uninstall or explicit user action".to_string(),
                "surface service start/stop failures as degraded local-core status".to_string(),
            ],
            ipc_transport: "Windows Named Pipe, local authenticated client only".to_string(),
            degraded_behavior: vec![
                "disable packet capture".to_string(),
                "disable firewall and QoS execution".to_string(),
                "mark process attribution low or unknown".to_string(),
                "allow report viewing and imported-log analysis".to_string(),
            ],
            non_admin_behavior: vec![
                "show reduced visibility mode".to_string(),
                "allow existing local metadata reads".to_string(),
                "disable high-risk operations".to_string(),
            ],
            forbidden_service_responsibilities: vec![
                "UI rendering".to_string(),
                "full graph analytics".to_string(),
                "report rendering".to_string(),
                "third-party plugin execution".to_string(),
                "unredacted report export".to_string(),
            ],
        }
    }

    pub fn validate(&self) -> Result<(), ReleaseContractError> {
        require_non_empty("service_name", &self.service_name)?;
        require_non_empty("ipc_transport", &self.ipc_transport)?;
        if !self.installed_by_elevated_installer {
            return Err(ReleaseContractError::UnsafeClaim(
                "installed_by_elevated_installer",
            ));
        }
        require_non_empty_list("start_stop_expectations", &self.start_stop_expectations)?;
        require_non_empty_list("degraded_behavior", &self.degraded_behavior)?;
        require_non_empty_list("non_admin_behavior", &self.non_admin_behavior)?;
        require_non_empty_list(
            "forbidden_service_responsibilities",
            &self.forbidden_service_responsibilities,
        )?;
        Ok(())
    }
}

impl ReducedVisibilityModePlan {
    pub fn windows_v1() -> Self {
        Self {
            active_when: vec![
                "standard user mode without connected elevated service".to_string(),
                "IPC disconnected, unauthorized, or degraded".to_string(),
                "capture adapter unavailable".to_string(),
            ],
            user_visible_banners: vec![
                "Reduced visibility mode is active".to_string(),
                "Some network/process attribution and response capabilities are unavailable"
                    .to_string(),
            ],
            allowed_capabilities: vec![
                "view existing local metadata".to_string(),
                "view reports and export history".to_string(),
                "manual imported-log analysis".to_string(),
            ],
            disabled_capabilities: vec![
                "system-wide capture".to_string(),
                "reliable process-to-flow attribution".to_string(),
                "firewall write".to_string(),
                "QoS write".to_string(),
                "auto_containment_lite".to_string(),
            ],
        }
    }

    pub fn validate(&self) -> Result<(), ReleaseContractError> {
        require_non_empty_list("active_when", &self.active_when)?;
        require_non_empty_list("user_visible_banners", &self.user_visible_banners)?;
        require_non_empty_list("allowed_capabilities", &self.allowed_capabilities)?;
        require_non_empty_list("disabled_capabilities", &self.disabled_capabilities)?;
        Ok(())
    }
}

impl PrivacyDefaultChecklist {
    pub fn safe_default() -> Self {
        Self {
            local_only_storage: true,
            cloud_sync_enabled: false,
            online_intelligence_lookup_enabled: false,
            raw_packet_persistence_enabled: false,
            payload_persistence_enabled: false,
            http_body_persistence_enabled: false,
            cookie_token_credential_persistence_enabled: false,
            api_key_persistence_enabled: false,
            forensic_mode_manual_ttl_audited: true,
        }
    }

    pub fn validate(&self) -> Result<(), ReleaseContractError> {
        if !self.local_only_storage {
            return Err(ReleaseContractError::UnsafeDefault("local_only_storage"));
        }
        if self.cloud_sync_enabled {
            return Err(ReleaseContractError::UnsafeDefault("cloud_sync_enabled"));
        }
        if self.online_intelligence_lookup_enabled {
            return Err(ReleaseContractError::UnsafeDefault(
                "online_intelligence_lookup_enabled",
            ));
        }
        if self.raw_packet_persistence_enabled
            || self.payload_persistence_enabled
            || self.http_body_persistence_enabled
            || self.cookie_token_credential_persistence_enabled
            || self.api_key_persistence_enabled
        {
            return Err(ReleaseContractError::UnsafeDefault(
                "private_content_persistence",
            ));
        }
        if !self.forensic_mode_manual_ttl_audited {
            return Err(ReleaseContractError::UnsafeDefault(
                "forensic_mode_manual_ttl_audited",
            ));
        }
        Ok(())
    }
}

impl ResponseSafetyChecklist {
    pub fn recommend_first_v1() -> Self {
        Self {
            default_mode_recommend_only: true,
            limited_auto_containment_allowlisted: true,
            high_impact_requires_approval: true,
            execution_requires_policy_permission_audit_ttl_rollback: true,
            replay_never_executes_real_actions: true,
            disabled_in_reduced_visibility: true,
            prohibited_v1_actions: vec![
                "full_host_isolation".to_string(),
                "segment_isolation".to_string(),
                "permanent_firewall_deny".to_string(),
                "process_kill".to_string(),
                "privileged_user_lockout".to_string(),
                "WAF/API enforcement".to_string(),
            ],
        }
    }

    pub fn validate(&self) -> Result<(), ReleaseContractError> {
        if !self.default_mode_recommend_only
            || !self.limited_auto_containment_allowlisted
            || !self.high_impact_requires_approval
            || !self.execution_requires_policy_permission_audit_ttl_rollback
            || !self.replay_never_executes_real_actions
            || !self.disabled_in_reduced_visibility
        {
            return Err(ReleaseContractError::UnsafeDefault("response_safety_gate"));
        }
        require_non_empty_list("prohibited_v1_actions", &self.prohibited_v1_actions)?;
        Ok(())
    }
}

impl ReportExportChecklist {
    pub fn safe_v1() -> Self {
        Self {
            allowed_formats: vec![
                ExportFormat::Markdown,
                ExportFormat::Html,
                ExportFormat::RedactedJson,
            ],
            deferred_formats: vec!["pdf".to_string()],
            redaction_required: true,
            user_confirmation_required: true,
            audit_required: true,
            file_hash_recorded_where_available: true,
            export_history_required: true,
            excluded_by_default: required_redaction_categories(),
        }
    }

    pub fn validate(&self) -> Result<(), ReleaseContractError> {
        if !self.redaction_required
            || !self.user_confirmation_required
            || !self.audit_required
            || !self.file_hash_recorded_where_available
            || !self.export_history_required
        {
            return Err(ReleaseContractError::UnsafeDefault("report_export_gate"));
        }
        if self
            .allowed_formats
            .iter()
            .any(|format| !format.is_supported_v1())
        {
            return Err(ReleaseContractError::UnsafeDefault(
                "unsupported_export_format",
            ));
        }
        for category in required_redaction_categories() {
            if !self.excluded_by_default.contains(&category) {
                return Err(ReleaseContractError::MissingReportRedaction(category));
            }
        }
        Ok(())
    }
}

impl ReleaseRiskRegister {
    pub fn windows_v1() -> Self {
        Self {
            risks: vec![
                ReleaseRisk {
                    risk_id: "rel-risk-001".to_string(),
                    area: ReleaseGateArea::Capture,
                    summary_redacted:
                        "WinDivert capture and driver installation need real installer validation"
                            .to_string(),
                    mitigation_redacted:
                        "Gate release on signed installer, driver preflight, degraded fallback, and uninstall validation"
                            .to_string(),
                    release_blocking_until_resolved: true,
                },
                ReleaseRisk {
                    risk_id: "rel-risk-002".to_string(),
                    area: ReleaseGateArea::ProcessAttribution,
                    summary_redacted:
                        "Process attribution remains best effort and can be low or unknown"
                            .to_string(),
                    mitigation_redacted:
                        "Expose confidence, method, reduced visibility notes, and report limitations"
                            .to_string(),
                    release_blocking_until_resolved: false,
                },
                ReleaseRisk {
                    risk_id: "rel-risk-003".to_string(),
                    area: ReleaseGateArea::ApiWaf,
                    summary_redacted:
                        "Packet-only API hints must not be marketed as full API or WAF security"
                            .to_string(),
                    mitigation_redacted:
                        "Keep WAF disabled by default and require imported/proxy/gateway logs for full API visibility"
                            .to_string(),
                    release_blocking_until_resolved: true,
                },
                ReleaseRisk {
                    risk_id: "rel-risk-004".to_string(),
                    area: ReleaseGateArea::Report,
                    summary_redacted:
                        "Export history currently depends on logical app state until release persistence is finalized"
                            .to_string(),
                    mitigation_redacted:
                        "Gate release on SQLite-backed export history and file-hash validation"
                            .to_string(),
                    release_blocking_until_resolved: true,
                },
            ],
        }
    }

    pub fn validate(&self) -> Result<(), ReleaseContractError> {
        if self.risks.is_empty() {
            return Err(ReleaseContractError::EmptyField("risks"));
        }
        for risk in &self.risks {
            require_non_empty("risk_id", &risk.risk_id)?;
            require_non_empty("summary_redacted", &risk.summary_redacted)?;
            require_non_empty("mitigation_redacted", &risk.mitigation_redacted)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseContractError {
    EmptyField(&'static str),
    UnsafeDefault(&'static str),
    UnsafeClaim(&'static str),
    MissingInstallerComponent,
    MissingReleaseGate(&'static str),
    MissingReportRedaction(RedactedDataCategory),
}

impl fmt::Display for ReleaseContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::UnsafeDefault(field) => write!(f, "{field} is not safe for V1 release"),
            Self::UnsafeClaim(field) => write!(f, "{field} overstates release readiness"),
            Self::MissingInstallerComponent => {
                write!(f, "installer plan must include UI, Local Core, and service")
            }
            Self::MissingReleaseGate(area) => write!(f, "release gate is missing for {area}"),
            Self::MissingReportRedaction(category) => {
                write!(
                    f,
                    "report export checklist is missing {category:?} redaction"
                )
            }
        }
    }
}

impl std::error::Error for ReleaseContractError {}

fn release_gates() -> Vec<ReleaseGate> {
    vec![
        gate(
            ReleaseGateArea::Platform,
            &[
                "plugin registry, lifecycle, dependency validation, contract validation, event bus, checkpoint/replay, health, metrics, audit, and service degraded state are visible",
            ],
            &[
                "workspace platform tests",
                "Task 500 plugin catalog and service IPC slices",
            ],
            ReleaseGateStatus::ValidatedInFixtureSlice,
            &["production installer/service integration remains separate"],
        ),
        gate(
            ReleaseGateArea::Privacy,
            &[
                "cloud sync off by default",
                "normal mode does not persist raw packets, payloads, HTTP bodies, tokens, cookies, credentials, or API keys",
                "exports require redaction and audit",
                "forensic mode is manual, time-limited, locally encrypted, and audited",
            ],
            &["privacy contract tests", "report export slice"],
            ReleaseGateStatus::ValidatedInFixtureSlice,
            &["forensic encrypted bundle UX is deferred"],
        ),
        gate(
            ReleaseGateArea::Capture,
            &[
                "WinDivert capture can start/stop",
                "capture health and drop rate are visible",
                "capture failure enters degraded mode",
            ],
            &["service/capture adapter validation", "installer driver preflight"],
            ReleaseGateStatus::ProvisionalStub,
            &["real WinDivert installer validation is not implemented by Task 510"],
        ),
        gate(
            ReleaseGateArea::ProcessAttribution,
            &[
                "flow-to-process attribution exists when possible",
                "status, method, confidence, visibility, and limitations are visible",
                "reduced visibility mode works without admin",
            ],
            &["attribution tests", "reduced visibility UI/service checks"],
            ReleaseGateStatus::ProvisionalStub,
            &["best-effort attribution can be low or unknown"],
        ),
        gate(
            ReleaseGateArea::Detection,
            &[
                "DNS/TLS observations exist",
                "C2 and exfiltration findings are evidence-backed",
                "risk engine can promote alert and incident",
                "low-confidence single signal does not create high-severity alert",
            ],
            &["detection and risk tests", "Task 500 detection MVP slice"],
            ReleaseGateStatus::ValidatedInFixtureSlice,
            &["metadata-only detection is not content proof"],
        ),
        gate(
            ReleaseGateArea::Graph,
            &[
                "graph hints are emitted",
                "graph_stage writes canonical graph",
                "graph paths can be included in incident and report snapshots",
                "GraphViewModel remains bounded and redacted",
            ],
            &["graph stage/analytics tests", "Task 500 graph rendering slice"],
            ReleaseGateStatus::ValidatedInFixtureSlice,
            &["browser Playwright rendering waits for runnable packaged app"],
        ),
        gate(
            ReleaseGateArea::Response,
            &[
                "response plan is created from incident",
                "policy evaluator returns decisions",
                "limited auto actions are allowlisted, TTL-bound, rollback-capable, and audited",
                "approval-required action cannot execute without approval",
                "detection plugin cannot call firewall directly",
            ],
            &["response planning/execution tests", "Task 500 response planning slice"],
            ReleaseGateStatus::ValidatedInFixtureSlice,
            &["real firewall/QoS adapters require installer and service validation"],
        ),
        gate(
            ReleaseGateArea::ApiWaf,
            &[
                "API Security default is packet_only_api_hint",
                "packet-only mode does not claim HTTPS path visibility",
                "full API detection requires imported/proxy/gateway logs",
                "WAF Security and WAF/API policy response are disabled by default",
            ],
            &["settings defaults tests", "UI release checklist"],
            ReleaseGateStatus::ManualReleaseGate,
            &["WAF/API automation is not enabled for personal PC V1"],
        ),
        gate(
            ReleaseGateArea::Report,
            &[
                "report includes summary, timeline, findings, evidence, graph snapshot, and response recommendation",
                "report excludes raw packet, payload, body, cookie, token, and credential content",
                "export creates audit event, file hash, history, and redaction summary",
            ],
            &["report generation/export tests", "Task 500 report export slice"],
            ReleaseGateStatus::ValidatedInFixtureSlice,
            &["PDF is deferred for V1"],
        ),
        gate(
            ReleaseGateArea::Performance,
            &[
                "UI remains responsive during capture",
                "event bus and storage writes stay bounded",
                "graph view is bounded and lazy-loaded",
                "report generation works for one incident within acceptable time",
            ],
            &["packaged-app smoke tests", "load and backpressure validation"],
            ReleaseGateStatus::NotReadyForRelease,
            &["packaged runtime performance validation is not present yet"],
        ),
        gate(
            ReleaseGateArea::Reliability,
            &[
                "UI crash does not corrupt storage",
                "service crash marks capture degraded",
                "SQLite migration is transactional",
                "IPC disconnect disables high-risk operations",
                "rollback works after UI restart",
            ],
            &["migration tests", "service crash/disconnect tests", "installer rollback tests"],
            ReleaseGateStatus::ProvisionalStub,
            &["post-install rollback and restart validation remain future release gates"],
        ),
    ]
}

fn gate(
    area: ReleaseGateArea,
    acceptance_criteria: &[&str],
    evidence_required: &[&str],
    status: ReleaseGateStatus,
    known_limitations_redacted: &[&str],
) -> ReleaseGate {
    ReleaseGate {
        area,
        acceptance_criteria: acceptance_criteria
            .iter()
            .map(|value| value.to_string())
            .collect(),
        evidence_required: evidence_required
            .iter()
            .map(|value| value.to_string())
            .collect(),
        status,
        known_limitations_redacted: known_limitations_redacted
            .iter()
            .map(|value| value.to_string())
            .collect(),
    }
}

fn validate_release_gates(gates: &[ReleaseGate]) -> Result<(), ReleaseContractError> {
    let present = gates
        .iter()
        .map(|gate| gate.area.clone())
        .collect::<HashSet<_>>();
    for area in required_release_gate_areas() {
        if !present.contains(area) {
            return Err(ReleaseContractError::MissingReleaseGate(area.as_str()));
        }
    }
    for gate in gates {
        require_non_empty_list("acceptance_criteria", &gate.acceptance_criteria)?;
        require_non_empty_list("evidence_required", &gate.evidence_required)?;
    }
    Ok(())
}

fn required_release_gate_areas() -> &'static [ReleaseGateArea] {
    &[
        ReleaseGateArea::Platform,
        ReleaseGateArea::Privacy,
        ReleaseGateArea::Capture,
        ReleaseGateArea::ProcessAttribution,
        ReleaseGateArea::Detection,
        ReleaseGateArea::Graph,
        ReleaseGateArea::Response,
        ReleaseGateArea::ApiWaf,
        ReleaseGateArea::Report,
        ReleaseGateArea::Performance,
        ReleaseGateArea::Reliability,
    ]
}

fn required_redaction_categories() -> Vec<RedactedDataCategory> {
    vec![
        RedactedDataCategory::RawPacket,
        RedactedDataCategory::Payload,
        RedactedDataCategory::HttpBody,
        RedactedDataCategory::Cookie,
        RedactedDataCategory::Token,
        RedactedDataCategory::Credential,
        RedactedDataCategory::ApiKey,
        RedactedDataCategory::PrivateKey,
        RedactedDataCategory::FullQueryString,
        RedactedDataCategory::FormContent,
        RedactedDataCategory::CommandLine,
    ]
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), ReleaseContractError> {
    if value.trim().is_empty() {
        return Err(ReleaseContractError::EmptyField(field));
    }
    Ok(())
}

fn require_non_empty_list(
    field: &'static str,
    values: &[String],
) -> Result<(), ReleaseContractError> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        return Err(ReleaseContractError::EmptyField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_checklist_maps_all_acceptance_gate_areas() {
        let checklist = ReleaseChecklist::windows_personal_pc_v1_planning();
        checklist.validate().expect("release checklist");

        let areas = checklist
            .release_gates
            .iter()
            .map(|gate| gate.area.clone())
            .collect::<HashSet<_>>();
        for area in required_release_gate_areas() {
            assert!(areas.contains(area), "missing {}", area.as_str());
        }
    }

    #[test]
    fn release_plan_is_planning_only_and_includes_required_install_targets() {
        let checklist = ReleaseChecklist::windows_personal_pc_v1_planning();

        assert!(checklist.planning_only);
        assert!(!checklist.release_ready);
        assert!(checklist.installer_plan.includes_tauri_desktop);
        assert!(checklist.installer_plan.includes_rust_local_core);
        assert!(checklist.installer_plan.includes_elevated_windows_service);
        assert!(checklist.installer_plan.actual_tooling_deferred);
        assert!(checklist.installer_plan.code_signing_required);
    }

    #[test]
    fn privacy_response_and_report_defaults_are_safe_for_v1() {
        let checklist = ReleaseChecklist::windows_personal_pc_v1_planning();

        checklist.privacy_defaults.validate().expect("privacy");
        checklist.response_safety.validate().expect("response");
        checklist.report_export.validate().expect("report");
        assert!(!checklist.privacy_defaults.cloud_sync_enabled);
        assert!(
            !checklist
                .privacy_defaults
                .online_intelligence_lookup_enabled
        );
        assert!(!checklist.privacy_defaults.raw_packet_persistence_enabled);
        assert!(checklist
            .report_export
            .allowed_formats
            .iter()
            .all(ExportFormat::is_supported_v1));
        assert!(checklist
            .report_export
            .deferred_formats
            .iter()
            .any(|format| format == "pdf"));
        assert!(checklist
            .response_safety
            .prohibited_v1_actions
            .iter()
            .any(|action| action == "WAF/API enforcement"));
    }
}
