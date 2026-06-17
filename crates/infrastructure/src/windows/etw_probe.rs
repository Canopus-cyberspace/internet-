//! Read-only ETW capability probe.
//!
//! This adapter checks only for the bounded Windows API surface required by a
//! future ServiceHost-owned ETW provider. It never creates an ETW session,
//! opens a trace, processes events, or owns Sentinel runtime state.

use crate::provider_adapter::{
    ProviderAdapterMetadata, ProviderAdapterOwnership, ProviderProbe,
    PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
};
use sentinel_contracts::{
    EtwApiSurfaceState, EtwCapabilityProbeSnapshot, EtwCapabilityState, EtwCollectionState,
    EtwNetworkSchemaDeclaration, EtwSchemaSupportState, EtwSessionState, NetworkProviderKind,
    RedactionStatus, Timestamp, ETW_PROBE_SCHEMA_VERSION,
};

pub const ETW_CAPABILITY_PROBE_ID: &str = "etw_network_capability_probe";

pub trait EtwCapabilityProbeSource {
    fn probe_etw_capability(&self) -> EtwCapabilityProbeSnapshot;
}

#[derive(Clone, Debug, Default)]
pub struct EtwCapabilityProbeAdapter;

impl EtwCapabilityProbeAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn probe(&self) -> EtwCapabilityProbeSnapshot {
        <Self as EtwCapabilityProbeSource>::probe_etw_capability(self)
    }
}

impl ProviderProbe for EtwCapabilityProbeAdapter {
    fn adapter_metadata(&self) -> ProviderAdapterMetadata {
        ProviderAdapterMetadata {
            adapter_id: "etw_capability_probe_adapter".to_string(),
            provider_kind: NetworkProviderKind::EtwNetwork,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            ownership: ProviderAdapterOwnership::infrastructure_adapter(),
            supported_request_refs: vec!["read_only_etw_capability_probe".to_string()],
            supported_result_refs: vec!["bounded_etw_probe_snapshot".to_string()],
            privacy_notes: vec![
                "system_api_categories_only".to_string(),
                "event_content_not_collected".to_string(),
                "runtime_state_not_created".to_string(),
            ],
            redaction_status: RedactionStatus::Redacted,
        }
    }
}

impl EtwCapabilityProbeSource for EtwCapabilityProbeAdapter {
    fn probe_etw_capability(&self) -> EtwCapabilityProbeSnapshot {
        let surface = detect_etw_api_surface();
        build_probe_snapshot(surface)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EtwApiSurface {
    core_available: bool,
    schema_metadata_available: bool,
    unsupported_platform: bool,
}

fn build_probe_snapshot(surface: EtwApiSurface) -> EtwCapabilityProbeSnapshot {
    let (capability_state, api_surface_state, schema_support_state, degraded_reason) =
        classify_surface(surface);
    EtwCapabilityProbeSnapshot {
        probe_ref: "etw_capability_probe_ref".to_string(),
        schema_version: ETW_PROBE_SCHEMA_VERSION,
        provider_kind: NetworkProviderKind::EtwNetwork,
        capability_state,
        api_surface_state,
        schema_support_state,
        session_state: EtwSessionState::NotCreated,
        collection_state: EtwCollectionState::Inactive,
        activation_allowed: false,
        event_session_created: false,
        collection_started: false,
        provider_execution_count: 0,
        events_observed_count: 0,
        eventbus_publication_count: 0,
        finding_count: 0,
        degraded_reason,
        schema_declaration: EtwNetworkSchemaDeclaration::metadata_only_v1(),
        audit_refs: vec!["audit_etw_capability_probe_ref".to_string()],
        provenance_refs: vec![
            "etw_infrastructure_capability_probe".to_string(),
            "windows_system_api_surface".to_string(),
        ],
        probed_at: Timestamp::now(),
        redaction_status: RedactionStatus::Redacted,
    }
}

fn classify_surface(
    surface: EtwApiSurface,
) -> (
    EtwCapabilityState,
    EtwApiSurfaceState,
    EtwSchemaSupportState,
    Option<String>,
) {
    if surface.unsupported_platform {
        return (
            EtwCapabilityState::UnsupportedPlatform,
            EtwApiSurfaceState::UnsupportedPlatform,
            EtwSchemaSupportState::UnsupportedPlatform,
            Some("unsupported_platform".to_string()),
        );
    }
    if surface.core_available && surface.schema_metadata_available {
        return (
            EtwCapabilityState::Available,
            EtwApiSurfaceState::Complete,
            EtwSchemaSupportState::RuntimeMetadataAvailable,
            None,
        );
    }
    if surface.core_available {
        return (
            EtwCapabilityState::Degraded,
            EtwApiSurfaceState::CoreOnly,
            EtwSchemaSupportState::DeclaredOnly,
            Some("runtime_schema_metadata_api_unavailable".to_string()),
        );
    }
    (
        EtwCapabilityState::Unavailable,
        EtwApiSurfaceState::Missing,
        EtwSchemaSupportState::Unavailable,
        Some("etw_control_api_unavailable".to_string()),
    )
}

#[cfg(windows)]
fn detect_etw_api_surface() -> EtwApiSurface {
    EtwApiSurface {
        core_available: system_library_has_exports(
            "advapi32.dll",
            &[
                "StartTraceW",
                "ControlTraceW",
                "OpenTraceW",
                "ProcessTrace",
                "CloseTrace",
            ],
        ),
        schema_metadata_available: system_library_has_exports(
            "tdh.dll",
            &["TdhGetEventInformation", "TdhGetProperty"],
        ),
        unsupported_platform: false,
    }
}

#[cfg(not(windows))]
fn detect_etw_api_surface() -> EtwApiSurface {
    EtwApiSurface {
        core_available: false,
        schema_metadata_available: false,
        unsupported_platform: true,
    }
}

#[cfg(windows)]
fn system_library_has_exports(library_name: &str, exports: &[&str]) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    let wide_name = std::ffi::OsStr::new(library_name)
        .encode_wide()
        .chain([0])
        .collect::<Vec<_>>();
    let module = unsafe {
        // The system32-only search prevents a probe from loading a same-named
        // library from an application or working directory.
        LoadLibraryExW(
            wide_name.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return false;
    }

    let all_present = exports.iter().all(|export| {
        let mut name = export.as_bytes().to_vec();
        name.push(0);
        unsafe { GetProcAddress(module, name.as_ptr()).is_some() }
    });
    unsafe {
        FreeLibrary(module);
    }
    all_present
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_adapter::ProviderProbe;

    #[test]
    fn etw_probe_is_read_only_bounded_and_infrastructure_owned() {
        let adapter = EtwCapabilityProbeAdapter::new();
        let metadata = adapter.adapter_metadata();
        let probe = adapter.probe();

        assert!(metadata.validate().is_ok());
        assert!(probe.validate().is_ok());
        assert_eq!(probe.provider_kind, NetworkProviderKind::EtwNetwork);
        assert_eq!(probe.session_state, EtwSessionState::NotCreated);
        assert_eq!(probe.collection_state, EtwCollectionState::Inactive);
        assert!(!probe.activation_allowed);
        assert!(!probe.event_session_created);
        assert!(!probe.collection_started);
        assert_eq!(probe.provider_execution_count, 0);
        assert_eq!(probe.events_observed_count, 0);
        assert_eq!(probe.eventbus_publication_count, 0);
        assert_eq!(probe.finding_count, 0);
    }

    #[test]
    fn etw_probe_classifies_degraded_unavailable_and_unsupported_states() {
        let degraded = build_probe_snapshot(EtwApiSurface {
            core_available: true,
            schema_metadata_available: false,
            unsupported_platform: false,
        });
        assert_eq!(degraded.capability_state, EtwCapabilityState::Degraded);
        assert_eq!(degraded.api_surface_state, EtwApiSurfaceState::CoreOnly);
        assert_eq!(
            degraded.schema_support_state,
            EtwSchemaSupportState::DeclaredOnly
        );

        let unavailable = build_probe_snapshot(EtwApiSurface {
            core_available: false,
            schema_metadata_available: true,
            unsupported_platform: false,
        });
        assert_eq!(
            unavailable.capability_state,
            EtwCapabilityState::Unavailable
        );
        assert_eq!(unavailable.provider_execution_count, 0);

        let unsupported = build_probe_snapshot(EtwApiSurface {
            core_available: false,
            schema_metadata_available: false,
            unsupported_platform: true,
        });
        assert_eq!(
            unsupported.capability_state,
            EtwCapabilityState::UnsupportedPlatform
        );
        assert!(unsupported.validate().is_ok());
    }

    #[test]
    fn etw_probe_serialization_contains_no_runtime_or_sensitive_values() {
        let serialized =
            serde_json::to_string(&EtwCapabilityProbeAdapter::new().probe()).expect("serialize");
        for marker in [
            "203.0.113.77",
            "65000",
            "process_name_value",
            "c:\\unsafe\\binary.exe",
            "username_value",
            "sid_value",
            "token_value",
            "credential_value",
            "secret_value",
        ] {
            assert!(!serialized.contains(marker));
        }
        assert!(!serialized.contains("StartTraceW"));
        assert!(!serialized.contains("TdhGetEventInformation"));
    }
}
