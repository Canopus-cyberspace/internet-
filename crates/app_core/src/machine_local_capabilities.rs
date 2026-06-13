use sentinel_contracts::Timestamp;
use sentinel_infrastructure::{
    ElevatedServiceIpcClient, ServiceIpcClientError, ServiceIpcClientErrorKind,
};
use sentinel_storage::EncryptionKeyHook;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::process::Command;

const ELEVATED_SERVICE_NAME: &str = "SentinelGuardElevated";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineLocalCapability {
    ElevatedService,
    WinDivertCapture,
    PktmonDiagnostic,
    NamedPipeIpc,
    FirewallResponse,
    QosResponse,
    ProcessAttribution,
    DpapiProtection,
    InstallerServiceRegistration,
}

impl MachineLocalCapability {
    pub const fn all() -> [Self; 9] {
        [
            Self::ElevatedService,
            Self::WinDivertCapture,
            Self::PktmonDiagnostic,
            Self::NamedPipeIpc,
            Self::FirewallResponse,
            Self::QosResponse,
            Self::ProcessAttribution,
            Self::DpapiProtection,
            Self::InstallerServiceRegistration,
        ]
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ElevatedService => "elevated_service",
            Self::WinDivertCapture => "windivert_capture",
            Self::PktmonDiagnostic => "pktmon_diagnostic",
            Self::NamedPipeIpc => "named_pipe_ipc",
            Self::FirewallResponse => "firewall_response",
            Self::QosResponse => "qos_response",
            Self::ProcessAttribution => "process_attribution",
            Self::DpapiProtection => "dpapi_protection",
            Self::InstallerServiceRegistration => "installer_service_registration",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CapabilityStatus {
    Available,
    Degraded { reason: String },
    Unavailable { reason: String },
    RequiresSetup { action: String },
    RequiresAdmin { action: String },
    Unsupported { reason: String },
    BlockedByEnv { reason: String },
}

impl CapabilityStatus {
    pub const fn status_str(&self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Degraded { .. } => "degraded",
            Self::Unavailable { .. } => "unavailable",
            Self::RequiresSetup { .. } => "requires_setup",
            Self::RequiresAdmin { .. } => "requires_admin",
            Self::Unsupported { .. } => "unsupported",
            Self::BlockedByEnv { .. } => "blocked_by_env",
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Degraded { reason }
            | Self::Unavailable { reason }
            | Self::Unsupported { reason }
            | Self::BlockedByEnv { reason } => Some(reason),
            _ => None,
        }
    }

    pub fn action(&self) -> Option<&str> {
        match self {
            Self::RequiresSetup { action } | Self::RequiresAdmin { action } => Some(action),
            _ => None,
        }
    }

    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineLocalCapabilityStatusDto {
    pub capability: String,
    pub status: String,
    pub reason: Option<String>,
    pub action: Option<String>,
}

impl MachineLocalCapabilityStatusDto {
    pub fn new(capability: MachineLocalCapability, status: &CapabilityStatus) -> Self {
        Self {
            capability: capability.as_str().to_string(),
            status: status.status_str().to_string(),
            reason: status.reason().map(str::to_string),
            action: status.action().map(str::to_string),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityStatusSummary {
    pub capabilities: Vec<MachineLocalCapabilityStatusDto>,
    pub all_available: bool,
    pub degraded_count: usize,
    pub unavailable_count: usize,
    pub requires_setup_count: usize,
    pub detected_at: Timestamp,
}

impl CapabilityStatusSummary {
    pub fn from_statuses(statuses: &HashMap<MachineLocalCapability, CapabilityStatus>) -> Self {
        let capabilities = MachineLocalCapability::all()
            .into_iter()
            .map(|capability| {
                let status = statuses.get(&capability).cloned().unwrap_or_else(|| {
                    CapabilityStatus::Unavailable {
                        reason: "capability was not detected on this launch".to_string(),
                    }
                });
                MachineLocalCapabilityStatusDto::new(capability, &status)
            })
            .collect::<Vec<_>>();
        Self {
            all_available: capabilities
                .iter()
                .all(|capability| capability.status == "available"),
            degraded_count: capabilities
                .iter()
                .filter(|capability| capability.status == "degraded")
                .count(),
            unavailable_count: capabilities
                .iter()
                .filter(|capability| capability.status == "unavailable")
                .count(),
            requires_setup_count: capabilities
                .iter()
                .filter(|capability| capability.status == "requires_setup")
                .count(),
            capabilities,
            detected_at: Timestamp::now(),
        }
    }

    pub fn not_configured_banner(&self) -> bool {
        self.capabilities.iter().all(|capability| {
            matches!(
                capability.status.as_str(),
                "unavailable" | "requires_setup" | "requires_admin"
            )
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeFailure {
    reason_redacted: String,
}

impl ProbeFailure {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason_redacted: sanitize_probe_reason(reason.into()),
        }
    }

    fn reason(&self) -> &str {
        &self.reason_redacted
    }
}

impl fmt::Display for ProbeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.reason_redacted)
    }
}

impl std::error::Error for ProbeFailure {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceProbeStatus {
    Running,
    Degraded,
    Unavailable,
    AccessDenied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverProbeStatus {
    Present,
    Missing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessSnapshotProbeStatus {
    Full,
    StubLimited,
    Unavailable,
    AccessDenied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpapiProbeStatus {
    Available,
    Unsupported,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceRegistrationProbeStatus {
    Running,
    RegisteredStopped,
    Missing,
    AccessDenied,
    Unsupported,
}

pub trait MachineLocalCapabilityProbe {
    fn elevated_service(&self) -> Result<ServiceProbeStatus, ProbeFailure>;
    fn named_pipe_ipc(&self) -> Result<ServiceProbeStatus, ProbeFailure>;
    fn windivert_driver(&self) -> Result<DriverProbeStatus, ProbeFailure>;
    fn pktmon_diagnostic(&self) -> Result<bool, ProbeFailure>;
    fn firewall_response(&self) -> Result<ServiceProbeStatus, ProbeFailure>;
    fn qos_response(&self) -> Result<ServiceProbeStatus, ProbeFailure>;
    fn process_snapshot(&self) -> Result<ProcessSnapshotProbeStatus, ProbeFailure>;
    fn dpapi_roundtrip(&self) -> Result<DpapiProbeStatus, ProbeFailure>;
    fn service_registration(&self) -> Result<ServiceRegistrationProbeStatus, ProbeFailure>;
}

#[derive(Clone, Debug, Default)]
pub struct SystemCapabilityProbe;

impl MachineLocalCapabilityProbe for SystemCapabilityProbe {
    fn elevated_service(&self) -> Result<ServiceProbeStatus, ProbeFailure> {
        service_status_probe()
    }

    fn named_pipe_ipc(&self) -> Result<ServiceProbeStatus, ProbeFailure> {
        service_status_probe()
    }

    fn windivert_driver(&self) -> Result<DriverProbeStatus, ProbeFailure> {
        let system_root = std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
        let drivers = system_root.join("System32").join("drivers");
        let present = ["WinDivert64.sys", "WinDivert.sys"]
            .iter()
            .any(|driver| drivers.join(driver).is_file());
        Ok(if present {
            DriverProbeStatus::Present
        } else {
            DriverProbeStatus::Missing
        })
    }

    fn pktmon_diagnostic(&self) -> Result<bool, ProbeFailure> {
        let system_root = std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
        if system_root.join("System32").join("pktmon.exe").is_file() {
            return Ok(true);
        }
        let path_result = std::env::var_os("PATH")
            .into_iter()
            .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
            .any(|directory| directory.join("pktmon.exe").is_file());
        Ok(path_result)
    }

    fn firewall_response(&self) -> Result<ServiceProbeStatus, ProbeFailure> {
        service_status_probe()
    }

    fn qos_response(&self) -> Result<ServiceProbeStatus, ProbeFailure> {
        service_status_probe()
    }

    fn process_snapshot(&self) -> Result<ProcessSnapshotProbeStatus, ProbeFailure> {
        let client = ElevatedServiceIpcClient::default();
        match client.process_snapshot(None) {
            Ok(snapshot)
                if snapshot
                    .processes
                    .iter()
                    .any(|process| !process.path.starts_with("redacted:")) =>
            {
                Ok(ProcessSnapshotProbeStatus::Full)
            }
            Ok(_) => Ok(ProcessSnapshotProbeStatus::StubLimited),
            Err(error) if matches!(error.kind, ServiceIpcClientErrorKind::PermissionDenied) => {
                Ok(ProcessSnapshotProbeStatus::AccessDenied)
            }
            Err(error)
                if matches!(
                    error.kind,
                    ServiceIpcClientErrorKind::Unreachable | ServiceIpcClientErrorKind::Timeout
                ) =>
            {
                Ok(ProcessSnapshotProbeStatus::Unavailable)
            }
            Err(error) => Err(ProbeFailure::new(error.to_string())),
        }
    }

    fn dpapi_roundtrip(&self) -> Result<DpapiProbeStatus, ProbeFailure> {
        let hook = EncryptionKeyHook::local_dpapi_current_user();
        let probe = b"sentinel-guard-dpapi-probe";
        match hook.protect_local_master_key(probe) {
            Ok(protected) => match hook.unprotect_local_master_key(&protected) {
                Ok(unprotected) if unprotected == probe => Ok(DpapiProbeStatus::Available),
                Ok(_) => Ok(DpapiProbeStatus::Unavailable),
                Err(error) => Err(ProbeFailure::new(error.to_string())),
            },
            Err(error) => {
                let reason = error.to_string();
                if reason
                    .to_ascii_lowercase()
                    .contains("only available on windows")
                {
                    Ok(DpapiProbeStatus::Unsupported)
                } else {
                    Err(ProbeFailure::new(reason))
                }
            }
        }
    }

    fn service_registration(&self) -> Result<ServiceRegistrationProbeStatus, ProbeFailure> {
        service_registration_probe()
    }
}

pub struct MachineLocalCapabilityDetector<P = SystemCapabilityProbe>
where
    P: MachineLocalCapabilityProbe,
{
    capabilities: HashMap<MachineLocalCapability, CapabilityStatus>,
    probe: P,
}

impl MachineLocalCapabilityDetector<SystemCapabilityProbe> {
    pub fn new() -> Self {
        Self::with_probe(SystemCapabilityProbe)
    }
}

impl Default for MachineLocalCapabilityDetector<SystemCapabilityProbe> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> MachineLocalCapabilityDetector<P>
where
    P: MachineLocalCapabilityProbe,
{
    pub fn with_probe(probe: P) -> Self {
        Self {
            capabilities: HashMap::new(),
            probe,
        }
    }

    pub fn detect_all(&mut self) -> &HashMap<MachineLocalCapability, CapabilityStatus> {
        self.capabilities.clear();
        for capability in MachineLocalCapability::all() {
            let status = match capability {
                MachineLocalCapability::ElevatedService => self.detect_elevated_service(),
                MachineLocalCapability::WinDivertCapture => self.detect_windivert_capture(),
                MachineLocalCapability::PktmonDiagnostic => self.detect_pktmon_diagnostic(),
                MachineLocalCapability::NamedPipeIpc => self.detect_named_pipe_ipc(),
                MachineLocalCapability::FirewallResponse => self.detect_firewall_response(),
                MachineLocalCapability::QosResponse => self.detect_qos_response(),
                MachineLocalCapability::ProcessAttribution => self.detect_process_attribution(),
                MachineLocalCapability::DpapiProtection => self.detect_dpapi_protection(),
                MachineLocalCapability::InstallerServiceRegistration => {
                    self.detect_installer_service_registration()
                }
            };
            self.capabilities.insert(capability, status);
        }
        &self.capabilities
    }

    pub fn status_of(&self, capability: MachineLocalCapability) -> CapabilityStatus {
        self.capabilities
            .get(&capability)
            .cloned()
            .unwrap_or_else(|| CapabilityStatus::Unavailable {
                reason: "capability was not detected on this launch".to_string(),
            })
    }

    pub fn all_available(&self) -> bool {
        !self.capabilities.is_empty()
            && MachineLocalCapability::all()
                .into_iter()
                .all(|capability| self.status_of(capability).is_available())
    }

    pub fn summary(&self) -> CapabilityStatusSummary {
        CapabilityStatusSummary::from_statuses(&self.capabilities)
    }

    fn detect_elevated_service(&self) -> CapabilityStatus {
        match self.probe.elevated_service() {
            Ok(ServiceProbeStatus::Running) => CapabilityStatus::Available,
            Ok(ServiceProbeStatus::Degraded) => CapabilityStatus::Degraded {
                reason: "elevated service responded with reduced health".to_string(),
            },
            Ok(ServiceProbeStatus::AccessDenied) => CapabilityStatus::RequiresAdmin {
                action:
                    "Run Sentinel Guard with administrator rights to inspect the elevated service"
                        .to_string(),
            },
            Ok(ServiceProbeStatus::Unavailable) => CapabilityStatus::Unavailable {
                reason: "elevated service did not respond on this machine".to_string(),
            },
            Err(error) => CapabilityStatus::Unavailable {
                reason: error.reason().to_string(),
            },
        }
    }

    fn detect_named_pipe_ipc(&self) -> CapabilityStatus {
        match self.probe.named_pipe_ipc() {
            Ok(ServiceProbeStatus::Running) => CapabilityStatus::Available,
            Ok(ServiceProbeStatus::Degraded) => CapabilityStatus::Degraded {
                reason: "named pipe IPC responded with reduced health".to_string(),
            },
            Ok(ServiceProbeStatus::AccessDenied) => CapabilityStatus::RequiresAdmin {
                action: "Run as Administrator to access the local Sentinel Guard named pipe"
                    .to_string(),
            },
            Ok(ServiceProbeStatus::Unavailable) => CapabilityStatus::Unavailable {
                reason: "named pipe IPC is not available on this machine".to_string(),
            },
            Err(error) => CapabilityStatus::Unavailable {
                reason: error.reason().to_string(),
            },
        }
    }

    fn detect_windivert_capture(&self) -> CapabilityStatus {
        match self.probe.windivert_driver() {
            Ok(DriverProbeStatus::Present) => CapabilityStatus::RequiresAdmin {
                action: "Run as Administrator to verify and enable the WinDivert capture driver"
                    .to_string(),
            },
            Ok(DriverProbeStatus::Missing) => CapabilityStatus::RequiresSetup {
                action: "Install the Sentinel Guard capture driver on this machine".to_string(),
            },
            Err(error) => CapabilityStatus::Unavailable {
                reason: error.reason().to_string(),
            },
        }
    }

    fn detect_pktmon_diagnostic(&self) -> CapabilityStatus {
        match self.probe.pktmon_diagnostic() {
            Ok(true) => CapabilityStatus::Available,
            Ok(false) => CapabilityStatus::Unsupported {
                reason: "Pktmon diagnostic tool was not detected on this machine".to_string(),
            },
            Err(error) => CapabilityStatus::Unavailable {
                reason: error.reason().to_string(),
            },
        }
    }

    fn detect_firewall_response(&self) -> CapabilityStatus {
        match self.probe.firewall_response() {
            Ok(ServiceProbeStatus::Running) => CapabilityStatus::RequiresSetup {
                action: "Enable Sentinel Guard firewall response adapter through approved setup"
                    .to_string(),
            },
            Ok(ServiceProbeStatus::Degraded) => CapabilityStatus::Degraded {
                reason: "firewall response adapter is degraded".to_string(),
            },
            Ok(ServiceProbeStatus::AccessDenied) => CapabilityStatus::RequiresAdmin {
                action: "Run as Administrator to inspect Windows Firewall response capability"
                    .to_string(),
            },
            Ok(ServiceProbeStatus::Unavailable) => CapabilityStatus::Unavailable {
                reason: "firewall response adapter is unavailable until the elevated service is configured"
                    .to_string(),
            },
            Err(error) => CapabilityStatus::BlockedByEnv {
                reason: error.reason().to_string(),
            },
        }
    }

    fn detect_qos_response(&self) -> CapabilityStatus {
        match self.probe.qos_response() {
            Ok(ServiceProbeStatus::Running) => CapabilityStatus::RequiresSetup {
                action: "Enable Sentinel Guard QoS response adapter through approved setup"
                    .to_string(),
            },
            Ok(ServiceProbeStatus::Degraded) => CapabilityStatus::Degraded {
                reason: "QoS response adapter is degraded".to_string(),
            },
            Ok(ServiceProbeStatus::AccessDenied) => CapabilityStatus::RequiresAdmin {
                action: "Run as Administrator to inspect Windows QoS response capability"
                    .to_string(),
            },
            Ok(ServiceProbeStatus::Unavailable) => CapabilityStatus::Unavailable {
                reason:
                    "QoS response adapter is unavailable until the elevated service is configured"
                        .to_string(),
            },
            Err(error) => CapabilityStatus::Unsupported {
                reason: error.reason().to_string(),
            },
        }
    }

    fn detect_process_attribution(&self) -> CapabilityStatus {
        match self.probe.process_snapshot() {
            Ok(ProcessSnapshotProbeStatus::Full) => CapabilityStatus::Available,
            Ok(ProcessSnapshotProbeStatus::StubLimited) => CapabilityStatus::Degraded {
                reason: "process attribution is using limited read-only service metadata"
                    .to_string(),
            },
            Ok(ProcessSnapshotProbeStatus::AccessDenied) => CapabilityStatus::RequiresAdmin {
                action: "Run as Administrator to inspect process attribution capability"
                    .to_string(),
            },
            Ok(ProcessSnapshotProbeStatus::Unavailable) => CapabilityStatus::Unavailable {
                reason: "process attribution requires the local elevated service on this machine"
                    .to_string(),
            },
            Err(error) => CapabilityStatus::Unavailable {
                reason: error.reason().to_string(),
            },
        }
    }

    fn detect_dpapi_protection(&self) -> CapabilityStatus {
        match self.probe.dpapi_roundtrip() {
            Ok(DpapiProbeStatus::Available) => CapabilityStatus::Available,
            Ok(DpapiProbeStatus::Unsupported) => CapabilityStatus::Unsupported {
                reason: "DPAPI protection is only available on Windows".to_string(),
            },
            Ok(DpapiProbeStatus::Unavailable) => CapabilityStatus::Unavailable {
                reason: "DPAPI protect/unprotect probe failed on this machine".to_string(),
            },
            Err(error) => CapabilityStatus::Unavailable {
                reason: error.reason().to_string(),
            },
        }
    }

    fn detect_installer_service_registration(&self) -> CapabilityStatus {
        match self.probe.service_registration() {
            Ok(ServiceRegistrationProbeStatus::Running) => CapabilityStatus::Available,
            Ok(ServiceRegistrationProbeStatus::RegisteredStopped) => {
                CapabilityStatus::RequiresAdmin {
                    action: "Run as Administrator to start or repair the Sentinel Guard elevated service"
                        .to_string(),
                }
            }
            Ok(ServiceRegistrationProbeStatus::Missing) => CapabilityStatus::RequiresSetup {
                action: "Install the Sentinel Guard elevated service on this machine".to_string(),
            },
            Ok(ServiceRegistrationProbeStatus::AccessDenied) => CapabilityStatus::RequiresAdmin {
                action: "Run as Administrator to inspect Sentinel Guard service registration"
                    .to_string(),
            },
            Ok(ServiceRegistrationProbeStatus::Unsupported) => CapabilityStatus::Unsupported {
                reason: "Windows Service Control Manager is not available".to_string(),
            },
            Err(error) => CapabilityStatus::Unavailable {
                reason: error.reason().to_string(),
            },
        }
    }
}

fn service_status_probe() -> Result<ServiceProbeStatus, ProbeFailure> {
    let client = ElevatedServiceIpcClient::default();
    match client.status() {
        Ok(status) if status.service_status == "running" => Ok(ServiceProbeStatus::Running),
        Ok(_) => Ok(ServiceProbeStatus::Degraded),
        Err(error) => Ok(service_probe_from_error(&error)),
    }
}

fn service_probe_from_error(error: &ServiceIpcClientError) -> ServiceProbeStatus {
    match error.kind {
        ServiceIpcClientErrorKind::PermissionDenied => ServiceProbeStatus::AccessDenied,
        ServiceIpcClientErrorKind::Unreachable | ServiceIpcClientErrorKind::Timeout => {
            ServiceProbeStatus::Unavailable
        }
        ServiceIpcClientErrorKind::Protocol | ServiceIpcClientErrorKind::Rejected => {
            ServiceProbeStatus::Degraded
        }
    }
}

#[cfg(windows)]
fn service_registration_probe() -> Result<ServiceRegistrationProbeStatus, ProbeFailure> {
    let output = Command::new("sc.exe")
        .args(["query", ELEVATED_SERVICE_NAME])
        .output()
        .map_err(|error| ProbeFailure::new(error.to_string()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_uppercase();
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_uppercase();
    if output.status.success() {
        if stdout.contains("RUNNING") {
            Ok(ServiceRegistrationProbeStatus::Running)
        } else {
            Ok(ServiceRegistrationProbeStatus::RegisteredStopped)
        }
    } else if stdout.contains("1060") || stderr.contains("1060") {
        Ok(ServiceRegistrationProbeStatus::Missing)
    } else if stdout.contains("ACCESS") || stderr.contains("ACCESS") {
        Ok(ServiceRegistrationProbeStatus::AccessDenied)
    } else {
        Err(ProbeFailure::new("service registration query failed"))
    }
}

#[cfg(not(windows))]
fn service_registration_probe() -> Result<ServiceRegistrationProbeStatus, ProbeFailure> {
    Ok(ServiceRegistrationProbeStatus::Unsupported)
}

fn sanitize_probe_reason(reason: String) -> String {
    let normalized = reason.to_ascii_lowercase();
    if normalized.contains("access") && normalized.contains("denied") {
        "capability probe was denied by local permissions".to_string()
    } else if normalized.contains("only available on windows") {
        "capability is unsupported on this platform".to_string()
    } else if normalized.contains("timeout") || normalized.contains("timed out") {
        "capability probe timed out".to_string()
    } else if normalized.contains("not found")
        || normalized.contains("cannot find")
        || normalized.contains("unreachable")
    {
        "capability endpoint was not found on this machine".to_string()
    } else {
        "capability probe failed without exposing raw system details".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Clone)]
    struct MockProbe {
        service: ServiceProbeStatus,
        driver: DriverProbeStatus,
        pktmon: bool,
        firewall: ServiceProbeStatus,
        qos: ServiceProbeStatus,
        process: ProcessSnapshotProbeStatus,
        dpapi: DpapiProbeStatus,
        registration: ServiceRegistrationProbeStatus,
        failures: HashMap<MachineLocalCapability, ProbeFailure>,
        calls: Rc<Cell<usize>>,
    }

    impl MockProbe {
        fn unconfigured() -> Self {
            Self {
                service: ServiceProbeStatus::Unavailable,
                driver: DriverProbeStatus::Missing,
                pktmon: false,
                firewall: ServiceProbeStatus::Unavailable,
                qos: ServiceProbeStatus::Unavailable,
                process: ProcessSnapshotProbeStatus::Unavailable,
                dpapi: DpapiProbeStatus::Unavailable,
                registration: ServiceRegistrationProbeStatus::Missing,
                failures: HashMap::new(),
                calls: Rc::new(Cell::new(0)),
            }
        }

        fn available() -> Self {
            Self {
                service: ServiceProbeStatus::Running,
                driver: DriverProbeStatus::Present,
                pktmon: true,
                firewall: ServiceProbeStatus::Running,
                qos: ServiceProbeStatus::Running,
                process: ProcessSnapshotProbeStatus::Full,
                dpapi: DpapiProbeStatus::Available,
                registration: ServiceRegistrationProbeStatus::Running,
                failures: HashMap::new(),
                calls: Rc::new(Cell::new(0)),
            }
        }

        fn call(&self) {
            self.calls.set(self.calls.get() + 1);
        }

        fn failure_for(&self, capability: MachineLocalCapability) -> Option<ProbeFailure> {
            self.failures.get(&capability).cloned()
        }
    }

    impl MachineLocalCapabilityProbe for MockProbe {
        fn elevated_service(&self) -> Result<ServiceProbeStatus, ProbeFailure> {
            self.call();
            self.failure_for(MachineLocalCapability::ElevatedService)
                .map_or(Ok(self.service), Err)
        }

        fn named_pipe_ipc(&self) -> Result<ServiceProbeStatus, ProbeFailure> {
            self.call();
            self.failure_for(MachineLocalCapability::NamedPipeIpc)
                .map_or(Ok(self.service), Err)
        }

        fn windivert_driver(&self) -> Result<DriverProbeStatus, ProbeFailure> {
            self.call();
            self.failure_for(MachineLocalCapability::WinDivertCapture)
                .map_or(Ok(self.driver), Err)
        }

        fn pktmon_diagnostic(&self) -> Result<bool, ProbeFailure> {
            self.call();
            self.failure_for(MachineLocalCapability::PktmonDiagnostic)
                .map_or(Ok(self.pktmon), Err)
        }

        fn firewall_response(&self) -> Result<ServiceProbeStatus, ProbeFailure> {
            self.call();
            self.failure_for(MachineLocalCapability::FirewallResponse)
                .map_or(Ok(self.firewall), Err)
        }

        fn qos_response(&self) -> Result<ServiceProbeStatus, ProbeFailure> {
            self.call();
            self.failure_for(MachineLocalCapability::QosResponse)
                .map_or(Ok(self.qos), Err)
        }

        fn process_snapshot(&self) -> Result<ProcessSnapshotProbeStatus, ProbeFailure> {
            self.call();
            self.failure_for(MachineLocalCapability::ProcessAttribution)
                .map_or(Ok(self.process), Err)
        }

        fn dpapi_roundtrip(&self) -> Result<DpapiProbeStatus, ProbeFailure> {
            self.call();
            self.failure_for(MachineLocalCapability::DpapiProtection)
                .map_or(Ok(self.dpapi), Err)
        }

        fn service_registration(&self) -> Result<ServiceRegistrationProbeStatus, ProbeFailure> {
            self.call();
            self.failure_for(MachineLocalCapability::InstallerServiceRegistration)
                .map_or(Ok(self.registration), Err)
        }
    }

    #[test]
    fn unconfigured_machine_reports_service_dependent_capabilities_not_ready() {
        let mut detector = MachineLocalCapabilityDetector::with_probe(MockProbe::unconfigured());
        detector.detect_all();

        for capability in [
            MachineLocalCapability::ElevatedService,
            MachineLocalCapability::NamedPipeIpc,
            MachineLocalCapability::ProcessAttribution,
            MachineLocalCapability::FirewallResponse,
            MachineLocalCapability::QosResponse,
        ] {
            assert!(!detector.status_of(capability).is_available());
        }
        assert!(matches!(
            detector.status_of(MachineLocalCapability::InstallerServiceRegistration),
            CapabilityStatus::RequiresSetup { .. }
        ));
    }

    #[test]
    fn detection_uses_read_only_probes_without_cached_state() {
        let probe = MockProbe::unconfigured();
        let calls = probe.calls.clone();
        let mut detector = MachineLocalCapabilityDetector::with_probe(probe);

        detector.detect_all();
        let first_count = calls.get();
        detector.detect_all();

        assert_eq!(first_count, 9);
        assert_eq!(calls.get(), 18);
    }

    #[test]
    fn summary_counts_status_variants() {
        let mut detector = MachineLocalCapabilityDetector::with_probe(MockProbe::unconfigured());
        detector.detect_all();
        let summary = detector.summary();

        assert_eq!(summary.capabilities.len(), 9);
        assert!(!summary.all_available);
        assert!(summary.unavailable_count >= 4);
        assert!(summary.requires_setup_count >= 2);
    }

    #[test]
    fn bridge_dto_serializes_all_status_variants() {
        let statuses = [
            CapabilityStatus::Available,
            CapabilityStatus::Degraded {
                reason: "reduced metadata".to_string(),
            },
            CapabilityStatus::Unavailable {
                reason: "not configured".to_string(),
            },
            CapabilityStatus::RequiresSetup {
                action: "install service".to_string(),
            },
            CapabilityStatus::RequiresAdmin {
                action: "run as administrator".to_string(),
            },
            CapabilityStatus::Unsupported {
                reason: "unsupported platform".to_string(),
            },
            CapabilityStatus::BlockedByEnv {
                reason: "blocked by policy".to_string(),
            },
        ];

        let serialized = statuses
            .iter()
            .map(|status| {
                serde_json::to_value(MachineLocalCapabilityStatusDto::new(
                    MachineLocalCapability::ElevatedService,
                    status,
                ))
                .expect("serialize dto")
            })
            .collect::<Vec<_>>();

        assert_eq!(serialized[0]["status"], json!("available"));
        assert_eq!(serialized[1]["reason"], json!("reduced metadata"));
        assert_eq!(serialized[3]["action"], json!("install service"));
        assert_eq!(serialized[6]["status"], json!("blocked_by_env"));
    }

    #[test]
    fn copied_state_does_not_affect_current_machine_detection() {
        let copied_state = json!({
            "machine_local_capability_status": {
                "capabilities": [{ "capability": "elevated_service", "status": "available" }]
            }
        });
        let mut detector = MachineLocalCapabilityDetector::with_probe(MockProbe::unconfigured());
        detector.detect_all();

        assert_eq!(
            copied_state["machine_local_capability_status"]["capabilities"][0]["status"],
            "available"
        );
        assert!(!detector
            .status_of(MachineLocalCapability::ElevatedService)
            .is_available());
    }

    #[test]
    fn available_probe_reports_available_without_false_degradation() {
        let mut probe = MockProbe::available();
        probe.driver = DriverProbeStatus::Missing;
        probe.firewall = ServiceProbeStatus::Degraded;
        let mut detector = MachineLocalCapabilityDetector::with_probe(probe);
        detector.detect_all();

        assert!(detector
            .status_of(MachineLocalCapability::ElevatedService)
            .is_available());
        assert!(detector
            .status_of(MachineLocalCapability::NamedPipeIpc)
            .is_available());
        assert!(detector
            .status_of(MachineLocalCapability::ProcessAttribution)
            .is_available());
        assert!(detector
            .status_of(MachineLocalCapability::DpapiProtection)
            .is_available());
    }

    #[test]
    fn probe_failure_becomes_unavailable_without_panic_or_raw_details() {
        let mut probe = MockProbe::unconfigured();
        probe.failures.insert(
            MachineLocalCapability::ElevatedService,
            ProbeFailure::new(r"Access is denied at C:\Users\Alice\secret"),
        );
        let mut detector = MachineLocalCapabilityDetector::with_probe(probe);
        detector.detect_all();

        let status = detector.status_of(MachineLocalCapability::ElevatedService);
        assert!(matches!(status, CapabilityStatus::Unavailable { .. }));
        let serialized = serde_json::to_string(&detector.summary()).expect("summary json");
        assert!(!serialized.contains("Alice"));
        assert!(!serialized.contains("C:\\"));
    }
}
