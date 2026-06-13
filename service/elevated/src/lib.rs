//! STUB_ONLY Elevated Windows Local Service boundary.
//!
//! NOT_FOR_PRODUCTION: this crate defines the service process boundary and
//! local-only health, IPC, security-gate, capture metadata, and process
//! attribution stubs. It does not install a Windows service, open capture
//! handles, mutate OS policy, execute response actions, host plugins, render UI,
//! run detection, build graphs, render reports, or persist private content.

use sentinel_contracts::{PrivacyClass, SchemaVersion, Timestamp};
use sentinel_platform::observability::{
    HealthDependencyStatus, HealthProbeKind, HealthProbeResult,
};
use sentinel_platform::{
    ComponentId, HealthProbe, HealthSnapshot as PlatformHealthSnapshot, HealthSubject,
    ObservabilityHealthStatus,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod attribution;
pub mod capture;
pub mod ipc;
pub mod runtime_ipc;
pub mod security;
pub use attribution::*;
pub use capture::*;
pub use ipc::*;
pub use runtime_ipc::*;
pub use security::*;

pub const STUB_ONLY_LABEL: &str = "STUB_ONLY";
pub const NOT_FOR_PRODUCTION_LABEL: &str = "NOT_FOR_PRODUCTION";
pub const SERVICE_STUB_NAME: &str = "sentinel_guard_elevated_service_stub";
pub const SERVICE_STUB_VERSION: &str = "0.1.0";

const SERVICE_ALLOWED_ROLE: &str = "privileged_adapter_host_stub";
const SERVICE_FORBIDDEN_ROLES: [&str; 8] = [
    "platform_runtime",
    "ui_renderer",
    "graph_analytics",
    "report_renderer",
    "detection_engine",
    "plugin_runtime",
    "response_planner",
    "storage_owner",
];
const LOCAL_CORE_OWNED_DOMAINS: [&str; 8] = [
    "authorization",
    "policy",
    "audit",
    "graph",
    "response_planning",
    "reporting",
    "storage_facade",
    "plugin_runtime",
];
const DISABLED_PRIVILEGED_ADAPTERS: [&str; 6] = [
    "windivert_capture",
    "firewall_write",
    "qos_write",
    "process_control",
    "host_isolation",
    "privileged_inventory",
];

const SERVICE_SCHEMA_VERSION: SchemaVersion = SchemaVersion {
    major: 1,
    minor: 0,
    patch: 0,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Running,
    Stopped,
    Degraded,
    Disconnected,
    Unauthorized,
    Unavailable,
}

impl ServiceStatus {
    pub fn as_observability_status(&self) -> ObservabilityHealthStatus {
        match self {
            Self::Running => ObservabilityHealthStatus::Healthy,
            Self::Stopped => ObservabilityHealthStatus::Disconnected,
            Self::Degraded => ObservabilityHealthStatus::Degraded,
            Self::Disconnected => ObservabilityHealthStatus::Disconnected,
            Self::Unauthorized => ObservabilityHealthStatus::Unauthorized,
            Self::Unavailable => ObservabilityHealthStatus::Unavailable,
        }
    }

    pub fn allows_privileged_operations(&self) -> bool {
        false
    }

    pub fn required_states() -> [Self; 6] {
        [
            Self::Running,
            Self::Stopped,
            Self::Degraded,
            Self::Disconnected,
            Self::Unauthorized,
            Self::Unavailable,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceLifecycleState {
    NotInstalled,
    InstalledStub,
    Starting,
    Running,
    Stopping,
    Stopped,
    Degraded,
    Failed,
    Disabled,
}

impl ServiceLifecycleState {
    pub fn default_stub_state() -> Self {
        Self::Stopped
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCapability {
    pub capability_id: String,
    pub display_name: String,
    pub status: ServiceStatus,
    pub lifecycle_state: ServiceLifecycleState,
    pub available: bool,
    pub requires_ipc: bool,
    pub requires_local_core_authorization: bool,
    pub requires_audit: bool,
    pub stub_only: bool,
    pub not_for_production: bool,
    pub description_redacted: String,
}

impl ServiceCapability {
    pub fn stub_only(
        capability_id: impl Into<String>,
        display_name: impl Into<String>,
        description_redacted: impl Into<String>,
    ) -> Result<Self, ServiceError> {
        let capability = Self {
            capability_id: require_safe_text("capability_id", capability_id.into())?,
            display_name: require_safe_text("display_name", display_name.into())?,
            status: ServiceStatus::Unavailable,
            lifecycle_state: ServiceLifecycleState::Disabled,
            available: false,
            requires_ipc: true,
            requires_local_core_authorization: true,
            requires_audit: true,
            stub_only: true,
            not_for_production: true,
            description_redacted: require_safe_text(
                "description_redacted",
                description_redacted.into(),
            )?,
        };
        capability.validate()?;
        Ok(capability)
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        validate_safe_text("capability_id", &self.capability_id)?;
        validate_safe_text("display_name", &self.display_name)?;
        validate_safe_text("description_redacted", &self.description_redacted)?;

        if self.available {
            return Err(ServiceError::invalid(
                "available",
                "service capabilities must remain unavailable in the Task 300 stub",
            ));
        }
        if !self.stub_only || !self.not_for_production {
            return Err(ServiceError::invalid(
                "labels",
                "service capabilities must be STUB_ONLY and NOT_FOR_PRODUCTION",
            ));
        }
        if !self.requires_ipc || !self.requires_local_core_authorization || !self.requires_audit {
            return Err(ServiceError::invalid(
                "boundary",
                "service capabilities must require IPC, Local Core authorization, and audit",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStartupConfig {
    pub service_name: String,
    pub display_name: String,
    pub version: String,
    pub lifecycle_state: ServiceLifecycleState,
    pub local_only: bool,
    pub named_pipe_enabled: bool,
    pub named_pipe_name_redacted: Option<String>,
    pub allow_remote_clients: bool,
    pub require_authenticated_client: bool,
    pub installer_enabled: bool,
    pub privileged_adapters_enabled: bool,
    pub local_core_owns_authorization: bool,
    pub local_core_owns_policy: bool,
    pub local_core_owns_audit: bool,
    pub local_core_owns_graph_response_report: bool,
    pub labels: Vec<String>,
    pub schema_version: SchemaVersion,
}

impl ServiceStartupConfig {
    pub fn stub_only_local() -> Self {
        Self {
            service_name: SERVICE_STUB_NAME.to_string(),
            display_name: "Sentinel Guard Elevated Service STUB_ONLY".to_string(),
            version: SERVICE_STUB_VERSION.to_string(),
            lifecycle_state: ServiceLifecycleState::default_stub_state(),
            local_only: true,
            named_pipe_enabled: false,
            named_pipe_name_redacted: Some(
                "STUB_ONLY local named pipe protocol placeholder; runtime binding deferred"
                    .to_string(),
            ),
            allow_remote_clients: false,
            require_authenticated_client: true,
            installer_enabled: false,
            privileged_adapters_enabled: false,
            local_core_owns_authorization: true,
            local_core_owns_policy: true,
            local_core_owns_audit: true,
            local_core_owns_graph_response_report: true,
            labels: vec![
                STUB_ONLY_LABEL.to_string(),
                NOT_FOR_PRODUCTION_LABEL.to_string(),
            ],
            schema_version: SERVICE_SCHEMA_VERSION,
        }
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        validate_safe_text("service_name", &self.service_name)?;
        validate_safe_text("display_name", &self.display_name)?;
        validate_safe_text("version", &self.version)?;
        if let Some(pipe_name) = &self.named_pipe_name_redacted {
            validate_safe_text("named_pipe_name_redacted", pipe_name)?;
        }

        if !self.local_only {
            return Err(ServiceError::invalid(
                "local_only",
                "service stub must be local-only",
            ));
        }
        if self.allow_remote_clients {
            return Err(ServiceError::invalid(
                "allow_remote_clients",
                "remote service clients are not allowed in V1",
            ));
        }
        if !self.require_authenticated_client {
            return Err(ServiceError::invalid(
                "require_authenticated_client",
                "authenticated local client boundary is required",
            ));
        }
        if self.installer_enabled {
            return Err(ServiceError::invalid(
                "installer_enabled",
                "Task 300 must not implement service installation",
            ));
        }
        if self.privileged_adapters_enabled {
            return Err(ServiceError::invalid(
                "privileged_adapters_enabled",
                "Task 300 must not enable privileged adapters",
            ));
        }
        if !self.local_core_owns_authorization
            || !self.local_core_owns_policy
            || !self.local_core_owns_audit
            || !self.local_core_owns_graph_response_report
        {
            return Err(ServiceError::invalid(
                "local_core_ownership",
                "Local Core remains owner of authorization, policy, audit, graph, response, and report",
            ));
        }
        require_label(&self.labels, STUB_ONLY_LABEL)?;
        require_label(&self.labels, NOT_FOR_PRODUCTION_LABEL)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceBoundaryManifest {
    pub service_name: String,
    pub allowed_role: String,
    pub forbidden_roles: Vec<String>,
    pub local_core_owned_domains: Vec<String>,
    pub disabled_privileged_adapters: Vec<String>,
    pub local_only: bool,
    pub installer_enabled: bool,
    pub adapter_runtime_enabled: bool,
    pub raw_content_persistence_enabled: bool,
    pub labels: Vec<String>,
}

impl ServiceBoundaryManifest {
    pub fn stub_only(config: &ServiceStartupConfig) -> Result<Self, ServiceError> {
        config.validate()?;
        let manifest = Self {
            service_name: config.service_name.clone(),
            allowed_role: SERVICE_ALLOWED_ROLE.to_string(),
            forbidden_roles: SERVICE_FORBIDDEN_ROLES
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            local_core_owned_domains: LOCAL_CORE_OWNED_DOMAINS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            disabled_privileged_adapters: DISABLED_PRIVILEGED_ADAPTERS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            local_only: config.local_only,
            installer_enabled: config.installer_enabled,
            adapter_runtime_enabled: config.privileged_adapters_enabled,
            raw_content_persistence_enabled: false,
            labels: config.labels.clone(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        validate_safe_text("service_name", &self.service_name)?;
        validate_safe_text("allowed_role", &self.allowed_role)?;
        validate_safe_text_list("forbidden_roles", &self.forbidden_roles)?;
        validate_safe_text_list("local_core_owned_domains", &self.local_core_owned_domains)?;
        validate_safe_text_list(
            "disabled_privileged_adapters",
            &self.disabled_privileged_adapters,
        )?;
        require_label(&self.labels, STUB_ONLY_LABEL)?;
        require_label(&self.labels, NOT_FOR_PRODUCTION_LABEL)?;

        if self.allowed_role != SERVICE_ALLOWED_ROLE {
            return Err(ServiceError::invalid(
                "allowed_role",
                "elevated service stub may only be a privileged adapter host",
            ));
        }
        for role in SERVICE_FORBIDDEN_ROLES {
            require_text_value("forbidden_roles", &self.forbidden_roles, role)?;
        }
        for domain in LOCAL_CORE_OWNED_DOMAINS {
            require_text_value(
                "local_core_owned_domains",
                &self.local_core_owned_domains,
                domain,
            )?;
        }
        for adapter in DISABLED_PRIVILEGED_ADAPTERS {
            require_text_value(
                "disabled_privileged_adapters",
                &self.disabled_privileged_adapters,
                adapter,
            )?;
        }

        if !self.local_only {
            return Err(ServiceError::invalid(
                "local_only",
                "service boundary manifest must remain local-only",
            ));
        }
        if self.installer_enabled {
            return Err(ServiceError::invalid(
                "installer_enabled",
                "Task 300 boundary manifest must not enable installation",
            ));
        }
        if self.adapter_runtime_enabled {
            return Err(ServiceError::invalid(
                "adapter_runtime_enabled",
                "Task 300 boundary manifest must not enable privileged adapter runtime",
            ));
        }
        if self.raw_content_persistence_enabled {
            return Err(ServiceError::invalid(
                "raw_content_persistence_enabled",
                "elevated service must not persist raw packets, payloads, or private content",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceHealthSnapshot {
    pub service_name: String,
    pub status: ServiceStatus,
    pub lifecycle_state: ServiceLifecycleState,
    pub capabilities: Vec<ServiceCapability>,
    pub boundary_manifest: ServiceBoundaryManifest,
    pub platform_health: PlatformHealthSnapshot,
    pub observed_at: Timestamp,
    pub privacy_class: PrivacyClass,
    pub schema_version: SchemaVersion,
    pub labels: Vec<String>,
    pub message_redacted: String,
}

impl ServiceHealthSnapshot {
    pub fn stub_only(
        config: &ServiceStartupConfig,
        status: ServiceStatus,
    ) -> Result<Self, ServiceError> {
        config.validate()?;
        let mut platform_health = PlatformHealthSnapshot::new(
            HealthSubject::ServiceAdapter {
                component_id: ComponentId::new_v4(),
                adapter_name: config.service_name.clone(),
            },
            status.as_observability_status(),
        )
        .with_message_redacted(
            "STUB_ONLY NOT_FOR_PRODUCTION elevated service boundary; no privileged adapters are active",
        )
        .map_err(ServiceError::from_health_validation)?;
        platform_health
            .probes
            .push(stub_only_health_probe_result(&status)?);
        platform_health.dependencies.push(HealthDependencyStatus {
            dependency_name: "local_core_policy_gate".to_string(),
            status: ObservabilityHealthStatus::Healthy,
            required: true,
            reason_redacted: Some("Local Core owns policy checks".to_string()),
        });
        platform_health.dependencies.push(HealthDependencyStatus {
            dependency_name: "named_pipe_ipc".to_string(),
            status: ObservabilityHealthStatus::Unavailable,
            required: false,
            reason_redacted: Some(
                "STUB_ONLY IPC protocol contracts defined; runtime binding deferred".to_string(),
            ),
        });
        platform_health
            .validate()
            .map_err(ServiceError::from_health_validation)?;
        let boundary_manifest = ServiceBoundaryManifest::stub_only(config)?;

        let snapshot = Self {
            service_name: config.service_name.clone(),
            status,
            lifecycle_state: config.lifecycle_state.clone(),
            capabilities: default_stub_capabilities()?,
            boundary_manifest,
            platform_health,
            observed_at: Timestamp::now(),
            privacy_class: PrivacyClass::Internal,
            schema_version: SERVICE_SCHEMA_VERSION,
            labels: config.labels.clone(),
            message_redacted:
                "STUB_ONLY NOT_FOR_PRODUCTION service boundary; Local Core keeps control-plane ownership"
                    .to_string(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        validate_safe_text("service_name", &self.service_name)?;
        validate_safe_text("message_redacted", &self.message_redacted)?;
        require_label(&self.labels, STUB_ONLY_LABEL)?;
        require_label(&self.labels, NOT_FOR_PRODUCTION_LABEL)?;
        if self.status.allows_privileged_operations() {
            return Err(ServiceError::invalid(
                "status",
                "Task 300 status must not enable privileged operations",
            ));
        }
        if self.capabilities.is_empty() {
            return Err(ServiceError::invalid(
                "capabilities",
                "service snapshot must describe stub capabilities",
            ));
        }
        for capability in &self.capabilities {
            capability.validate()?;
        }
        self.boundary_manifest.validate()?;
        if self.boundary_manifest.service_name != self.service_name {
            return Err(ServiceError::invalid(
                "boundary_manifest",
                "service boundary manifest must describe the same service as the health snapshot",
            ));
        }
        self.platform_health
            .validate()
            .map_err(ServiceError::from_health_validation)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceError {
    pub error_code: String,
    pub field: Option<String>,
    pub message_redacted: String,
    pub stub_only: bool,
    pub not_for_production: bool,
}

impl ServiceError {
    pub fn invalid(field: impl Into<String>, message_redacted: impl Into<String>) -> Self {
        Self {
            error_code: "service_stub_invalid".to_string(),
            field: Some(field.into()),
            message_redacted: message_redacted.into(),
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn unsupported(operation: impl Into<String>) -> Self {
        Self {
            error_code: "service_operation_stub_only".to_string(),
            field: Some("operation".to_string()),
            message_redacted: format!(
                "STUB_ONLY NOT_FOR_PRODUCTION operation is unavailable: {}",
                operation.into()
            ),
            stub_only: true,
            not_for_production: true,
        }
    }

    fn from_health_validation(error: impl ToString) -> Self {
        Self {
            error_code: "service_health_validation_failed".to_string(),
            field: Some("health".to_string()),
            message_redacted: error.to_string(),
            stub_only: true,
            not_for_production: true,
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_code, self.message_redacted)
    }
}

impl std::error::Error for ServiceError {}

pub fn stub_only_health_probe(
    config: &ServiceStartupConfig,
) -> Result<ServiceHealthSnapshot, ServiceError> {
    ServiceHealthSnapshot::stub_only(config, ServiceStatus::Stopped)
}

pub fn service_boundary_manifest(
    config: &ServiceStartupConfig,
) -> Result<ServiceBoundaryManifest, ServiceError> {
    ServiceBoundaryManifest::stub_only(config)
}

pub fn default_stub_capabilities() -> Result<Vec<ServiceCapability>, ServiceError> {
    [
        (
            "capture_adapter",
            "Capture adapter host",
            "STUB_ONLY metadata capture adapter placeholder; real driver capture is deferred",
        ),
        (
            "process_inventory",
            "Process inventory adapter host",
            "STUB_ONLY process attribution provider; real Windows inventory is deferred",
        ),
        (
            "firewall_adapter",
            "Firewall adapter host",
            "STUB_ONLY response adapter placeholder; policy changes are disabled",
        ),
        (
            "qos_adapter",
            "QoS adapter host",
            "STUB_ONLY traffic policy placeholder; policy changes are disabled",
        ),
        (
            "response_executor",
            "Response executor host",
            "STUB_ONLY executor placeholder; response execution is disabled",
        ),
    ]
    .into_iter()
    .map(|(capability_id, display_name, description)| {
        ServiceCapability::stub_only(capability_id, display_name, description)
    })
    .collect()
}

pub fn reject_privileged_operation(operation: impl Into<String>) -> ServiceError {
    ServiceError::unsupported(operation)
}

fn stub_only_health_probe_result(
    status: &ServiceStatus,
) -> Result<HealthProbeResult, ServiceError> {
    let mut probe = HealthProbe::new(
        "STUB_ONLY elevated service liveness",
        HealthProbeKind::Liveness,
    )
    .map_err(ServiceError::from_health_validation)?;
    probe.critical = true;
    probe.timeout_ms = Some(250);
    probe.description_redacted = Some(
        "STUB_ONLY NOT_FOR_PRODUCTION local-only health probe; no adapters are started".to_string(),
    );
    let mut result = HealthProbeResult::new(probe, status.as_observability_status());
    result.detail_redacted =
        Some("STUB_ONLY health probe completed without OS interaction".to_string());
    Ok(result)
}

fn require_label(labels: &[String], label: &str) -> Result<(), ServiceError> {
    if labels.iter().any(|value| value == label) {
        return Ok(());
    }
    Err(ServiceError::invalid(
        "labels",
        format!("missing required label: {label}"),
    ))
}

fn require_text_value(
    field: &'static str,
    values: &[String],
    required: &str,
) -> Result<(), ServiceError> {
    if values.iter().any(|value| value == required) {
        return Ok(());
    }
    Err(ServiceError::invalid(
        field,
        format!("missing required value: {required}"),
    ))
}

fn require_safe_text(field: &'static str, value: String) -> Result<String, ServiceError> {
    if value.trim().is_empty() {
        return Err(ServiceError::invalid(field, "value must not be empty"));
    }
    validate_safe_text(field, &value)?;
    Ok(value)
}

fn validate_safe_text_list(field: &'static str, values: &[String]) -> Result<(), ServiceError> {
    if values.is_empty() {
        return Err(ServiceError::invalid(field, "list must not be empty"));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

pub(crate) fn validate_safe_text(field: &'static str, value: &str) -> Result<(), ServiceError> {
    let normalized = value.to_ascii_lowercase();
    for marker in [
        "packet_bytes",
        "payload_blob",
        "http_body",
        "session_token",
        "authorization_header",
        "api_key",
        "credential_value",
        "private_key",
        "password",
        "secret_value",
    ] {
        if normalized.contains(marker) {
            return Err(ServiceError::invalid(
                field,
                "service stub metadata contains a sensitive marker",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_status_covers_required_task_states() {
        let states = ServiceStatus::required_states();

        assert_eq!(states.len(), 6);
        assert!(states.contains(&ServiceStatus::Running));
        assert!(states.contains(&ServiceStatus::Stopped));
        assert!(states.contains(&ServiceStatus::Degraded));
        assert!(states.contains(&ServiceStatus::Disconnected));
        assert!(states.contains(&ServiceStatus::Unauthorized));
        assert!(states.contains(&ServiceStatus::Unavailable));

        for status in states {
            assert!(!status.allows_privileged_operations());
            let config = ServiceStartupConfig::stub_only_local();
            let snapshot =
                ServiceHealthSnapshot::stub_only(&config, status).expect("stub health snapshot");
            assert!(snapshot.labels.contains(&STUB_ONLY_LABEL.to_string()));
            assert!(snapshot
                .labels
                .contains(&NOT_FOR_PRODUCTION_LABEL.to_string()));
        }
    }

    #[test]
    fn boundary_manifest_documents_local_core_ownership_and_forbidden_roles() {
        let config = ServiceStartupConfig::stub_only_local();
        let manifest = service_boundary_manifest(&config).expect("boundary manifest");

        assert_eq!(manifest.service_name, SERVICE_STUB_NAME);
        assert_eq!(manifest.allowed_role, SERVICE_ALLOWED_ROLE);
        assert!(manifest.local_only);
        assert!(!manifest.installer_enabled);
        assert!(!manifest.adapter_runtime_enabled);
        assert!(!manifest.raw_content_persistence_enabled);

        for role in SERVICE_FORBIDDEN_ROLES {
            assert!(manifest.forbidden_roles.contains(&role.to_string()));
        }
        for domain in LOCAL_CORE_OWNED_DOMAINS {
            assert!(manifest
                .local_core_owned_domains
                .contains(&domain.to_string()));
        }
        for adapter in DISABLED_PRIVILEGED_ADAPTERS {
            assert!(manifest
                .disabled_privileged_adapters
                .contains(&adapter.to_string()));
        }
    }

    #[test]
    fn boundary_manifest_rejects_runtime_installation_or_raw_content_persistence() {
        let config = ServiceStartupConfig::stub_only_local();

        let mut installer = service_boundary_manifest(&config).expect("boundary manifest");
        installer.installer_enabled = true;
        assert_eq!(
            installer.validate().expect_err("installer rejected").field,
            Some("installer_enabled".to_string())
        );

        let mut runtime = service_boundary_manifest(&config).expect("boundary manifest");
        runtime.adapter_runtime_enabled = true;
        assert_eq!(
            runtime.validate().expect_err("runtime rejected").field,
            Some("adapter_runtime_enabled".to_string())
        );

        let mut private_content = service_boundary_manifest(&config).expect("boundary manifest");
        private_content.raw_content_persistence_enabled = true;
        assert_eq!(
            private_content
                .validate()
                .expect_err("raw content persistence rejected")
                .field,
            Some("raw_content_persistence_enabled".to_string())
        );
    }

    #[test]
    fn startup_config_is_local_only_stub_and_rejects_service_installer_or_adapters() {
        let config = ServiceStartupConfig::stub_only_local();
        assert!(config.validate().is_ok());
        assert!(!config.named_pipe_enabled);
        assert!(!config.installer_enabled);
        assert!(!config.privileged_adapters_enabled);
        assert!(config.local_core_owns_authorization);
        assert!(config.local_core_owns_policy);
        assert!(config.local_core_owns_audit);
        assert!(config.local_core_owns_graph_response_report);

        let mut remote = config.clone();
        remote.allow_remote_clients = true;
        assert!(remote.validate().is_err());

        let mut installer = config.clone();
        installer.installer_enabled = true;
        assert!(installer.validate().is_err());

        let mut adapters = config;
        adapters.privileged_adapters_enabled = true;
        assert!(adapters.validate().is_err());
    }

    #[test]
    fn stub_health_probe_is_labeled_and_does_not_activate_capabilities() {
        let config = ServiceStartupConfig::stub_only_local();
        let snapshot = stub_only_health_probe(&config).expect("stub health probe");

        assert_eq!(snapshot.status, ServiceStatus::Stopped);
        assert!(snapshot.validate().is_ok());
        assert_eq!(
            snapshot.platform_health.subject,
            HealthSubject::ServiceAdapter {
                component_id: match &snapshot.platform_health.subject {
                    HealthSubject::ServiceAdapter { component_id, .. } => component_id.clone(),
                    _ => unreachable!("service adapter subject"),
                },
                adapter_name: SERVICE_STUB_NAME.to_string(),
            }
        );
        assert_eq!(snapshot.platform_health.probes.len(), 1);
        assert_eq!(snapshot.capabilities.len(), 5);
        assert_eq!(
            snapshot.boundary_manifest.allowed_role,
            SERVICE_ALLOWED_ROLE
        );
        assert!(snapshot
            .boundary_manifest
            .forbidden_roles
            .contains(&"detection_engine".to_string()));
        assert!(snapshot
            .boundary_manifest
            .local_core_owned_domains
            .contains(&"graph".to_string()));
        assert!(snapshot
            .boundary_manifest
            .disabled_privileged_adapters
            .contains(&"firewall_write".to_string()));
        assert!(snapshot.capabilities.iter().all(|capability| {
            !capability.available && capability.stub_only && capability.not_for_production
        }));
    }

    #[test]
    fn service_capabilities_require_ipc_authorization_and_audit() {
        for capability in default_stub_capabilities().expect("capabilities") {
            assert!(!capability.available);
            assert_eq!(capability.status, ServiceStatus::Unavailable);
            assert!(capability.requires_ipc);
            assert!(capability.requires_local_core_authorization);
            assert!(capability.requires_audit);
            assert!(capability.validate().is_ok());
        }
    }

    #[test]
    fn service_errors_are_structured_and_marked_stub_only() {
        let error = reject_privileged_operation("temporary response execution");

        assert_eq!(error.error_code, "service_operation_stub_only");
        assert!(error.stub_only);
        assert!(error.not_for_production);
        assert!(error.to_string().contains("STUB_ONLY"));
    }

    #[test]
    fn service_stub_metadata_rejects_sensitive_markers() {
        let error = ServiceCapability::stub_only(
            "bad",
            "Bad",
            "authorization_header should not be carried by service metadata",
        )
        .expect_err("sensitive marker rejected");

        assert_eq!(error.error_code, "service_stub_invalid");
    }
}
