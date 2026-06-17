//! Bounded Windows Service Control Manager category adapter.
//!
//! Raw service names and display names are used transiently for classification
//! inside this module. Only bounded category aggregates leave the adapter.

use sentinel_contracts::{
    NativeProviderAvailabilityState, NativeProviderCategory, NativeRuntimePlatformCategory,
    NativeServiceCategory, NativeServiceStartupTypeBucket, NativeServiceStateBucket,
    NativeServiceTrustCategory,
};
use serde::{Deserialize, Serialize};

pub const WINDOWS_NATIVE_SERVICE_PROVIDER_ID: &str = "windows_service_control_manager";

#[derive(Clone, Copy, Debug)]
pub struct WindowsNativeServiceBounds {
    pub max_records: u32,
    pub max_bytes: u32,
    pub timeout_millis: u32,
    pub cancellation_requested: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsNativeServiceAggregate {
    pub service_category: NativeServiceCategory,
    pub service_state_bucket: NativeServiceStateBucket,
    pub startup_type_bucket: NativeServiceStartupTypeBucket,
    pub trust_category: NativeServiceTrustCategory,
    pub observation_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsNativeServiceSample {
    pub provider_category: NativeProviderCategory,
    pub platform_category: NativeRuntimePlatformCategory,
    pub availability_state: NativeProviderAvailabilityState,
    pub degraded_reason: Option<String>,
    pub aggregates: Vec<WindowsNativeServiceAggregate>,
    pub provider_enabled_count: u32,
    pub raw_record_count: u32,
    pub schema_accepted_count: u32,
    pub schema_rejected_count: u32,
    pub rate_limited_count: u32,
    pub queue_dropped_count: u32,
    pub normalized_record_count: u32,
    pub skipped_record_count: u32,
    pub malformed_record_count: u32,
    pub rejected_record_count: u32,
    pub timeout_count: u32,
    pub bytes_processed_bucket: String,
    pub unknown_category_ratio_bucket: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsNativeServiceAdapter;

impl WindowsNativeServiceAdapter {
    pub fn sample(&self, bounds: WindowsNativeServiceBounds) -> WindowsNativeServiceSample {
        sample_windows_services(bounds)
    }
}

#[cfg(windows)]
fn sample_windows_services(bounds: WindowsNativeServiceBounds) -> WindowsNativeServiceSample {
    use std::collections::BTreeMap;
    use std::ptr::{null, null_mut};
    use std::slice;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA,
    };
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
        SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32,
    };

    let mut sample = empty_sample(
        NativeRuntimePlatformCategory::Windows,
        NativeProviderAvailabilityState::ProviderUnavailable,
    );
    if bounds.cancellation_requested {
        sample.degraded_reason = Some("sampling_cancelled".to_string());
        sample.skipped_record_count = 1;
        return sample;
    }

    let started = Instant::now();
    let timeout = Duration::from_millis(u64::from(bounds.timeout_millis));
    let mut aggregates = BTreeMap::<ServiceAggregateKey, u32>::new();

    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            sample.degraded_reason = Some("scm_open_failed".to_string());
            sample.rejected_record_count = 1;
            return sample;
        }
        sample.provider_enabled_count = 1;

        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let mut resume_handle = 0u32;
        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            null_mut(),
            0,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            null(),
        );
        let probe_error = GetLastError();
        if bytes_needed == 0
            || !(probe_error == ERROR_MORE_DATA || probe_error == ERROR_INSUFFICIENT_BUFFER)
        {
            CloseServiceHandle(scm);
            sample.degraded_reason = Some("scm_probe_failed".to_string());
            sample.rejected_record_count = 1;
            return sample;
        }
        if bytes_needed > bounds.max_bytes {
            CloseServiceHandle(scm);
            sample.availability_state = NativeProviderAvailabilityState::Degraded;
            sample.degraded_reason = Some("scm_buffer_bound_exceeded".to_string());
            sample.schema_rejected_count = 1;
            sample.rejected_record_count = 1;
            sample.bytes_processed_bucket = "oversized_rejected".to_string();
            return sample;
        }

        let mut buffer = vec![0u8; bytes_needed as usize];
        let ok = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            buffer.as_mut_ptr(),
            bytes_needed,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            null(),
        );
        if ok == 0 {
            CloseServiceHandle(scm);
            sample.degraded_reason = Some("scm_enumeration_failed".to_string());
            sample.rejected_record_count = 1;
            return sample;
        }

        sample.availability_state = NativeProviderAvailabilityState::Available;
        sample.raw_record_count = services_returned;
        let services = slice::from_raw_parts(
            buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            services_returned as usize,
        );
        for (index, service) in services.iter().enumerate() {
            if index >= bounds.max_records as usize {
                sample.skipped_record_count = sample
                    .skipped_record_count
                    .saturating_add((services.len() - index) as u32);
                break;
            }
            if started.elapsed() >= timeout {
                sample.availability_state = NativeProviderAvailabilityState::Degraded;
                sample.degraded_reason = Some("scm_sampling_timeout".to_string());
                sample.timeout_count = 1;
                sample.skipped_record_count = sample
                    .skipped_record_count
                    .saturating_add((services.len() - index) as u32);
                break;
            }

            let raw_name = wide_ptr_to_string(service.lpServiceName);
            let raw_display = wide_ptr_to_string(service.lpDisplayName);
            let category = classify_service(&raw_name, &raw_display);
            let key = ServiceAggregateKey {
                state: state_bucket(service.ServiceStatusProcess.dwCurrentState),
                startup: startup_bucket(scm, service.lpServiceName),
                trust: trust_category(&category),
                category,
            };
            *aggregates.entry(key).or_insert(0) += 1;
            sample.schema_accepted_count = sample.schema_accepted_count.saturating_add(1);
        }
        CloseServiceHandle(scm);
    }

    let unknown = aggregates
        .iter()
        .filter(|(key, _)| key.category == NativeServiceCategory::Unknown)
        .map(|(_, count)| *count)
        .sum::<u32>();
    sample.unknown_category_ratio_bucket =
        ratio_bucket(unknown, sample.schema_accepted_count).to_string();
    sample.aggregates = aggregates
        .into_iter()
        .map(|(key, observation_count)| WindowsNativeServiceAggregate {
            service_category: key.category,
            service_state_bucket: key.state,
            startup_type_bucket: key.startup,
            trust_category: key.trust,
            observation_count,
        })
        .collect();
    sample.normalized_record_count = sample.aggregates.len().min(u32::MAX as usize) as u32;
    sample
}

#[cfg(not(windows))]
fn sample_windows_services(_bounds: WindowsNativeServiceBounds) -> WindowsNativeServiceSample {
    let mut sample = empty_sample(
        NativeRuntimePlatformCategory::Unsupported,
        NativeProviderAvailabilityState::UnsupportedPlatform,
    );
    sample.provider_category = NativeProviderCategory::UnsupportedPlatform;
    sample.degraded_reason = Some("unsupported_platform".to_string());
    sample
}

fn empty_sample(
    platform_category: NativeRuntimePlatformCategory,
    availability_state: NativeProviderAvailabilityState,
) -> WindowsNativeServiceSample {
    WindowsNativeServiceSample {
        provider_category: NativeProviderCategory::WindowsServiceControlManager,
        platform_category,
        availability_state,
        degraded_reason: None,
        aggregates: Vec::new(),
        provider_enabled_count: 0,
        raw_record_count: 0,
        schema_accepted_count: 0,
        schema_rejected_count: 0,
        rate_limited_count: 0,
        queue_dropped_count: 0,
        normalized_record_count: 0,
        skipped_record_count: 0,
        malformed_record_count: 0,
        rejected_record_count: 0,
        timeout_count: 0,
        bytes_processed_bucket: "metadata_only_low".to_string(),
        unknown_category_ratio_bucket: "none".to_string(),
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ServiceAggregateKey {
    category: NativeServiceCategory,
    state: NativeServiceStateBucket,
    startup: NativeServiceStartupTypeBucket,
    trust: NativeServiceTrustCategory,
}

#[cfg(windows)]
unsafe fn startup_bucket(
    scm: windows_sys::Win32::System::Services::SC_HANDLE,
    service_name: *const u16,
) -> NativeServiceStartupTypeBucket {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenServiceW, QueryServiceConfigW, QUERY_SERVICE_CONFIGW,
        SERVICE_AUTO_START, SERVICE_BOOT_START, SERVICE_DEMAND_START, SERVICE_DISABLED,
        SERVICE_QUERY_CONFIG, SERVICE_SYSTEM_START,
    };

    let handle = OpenServiceW(scm, service_name, SERVICE_QUERY_CONFIG);
    if handle.is_null() {
        return NativeServiceStartupTypeBucket::Unknown;
    }
    let mut needed = 0u32;
    let _ = QueryServiceConfigW(handle, std::ptr::null_mut(), 0, &mut needed);
    if needed == 0 || needed > 16_384 {
        CloseServiceHandle(handle);
        return NativeServiceStartupTypeBucket::Unknown;
    }
    let mut buffer = vec![0u8; needed as usize];
    let ok = QueryServiceConfigW(
        handle,
        buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW,
        needed,
        &mut needed,
    );
    if ok == 0 {
        CloseServiceHandle(handle);
        return NativeServiceStartupTypeBucket::Unknown;
    }
    let config = &*(buffer.as_ptr() as *const QUERY_SERVICE_CONFIGW);
    let bucket = match config.dwStartType {
        SERVICE_AUTO_START | SERVICE_BOOT_START | SERVICE_SYSTEM_START => {
            NativeServiceStartupTypeBucket::Automatic
        }
        SERVICE_DEMAND_START => NativeServiceStartupTypeBucket::Manual,
        SERVICE_DISABLED => NativeServiceStartupTypeBucket::Disabled,
        _ => NativeServiceStartupTypeBucket::Unknown,
    };
    CloseServiceHandle(handle);
    bucket
}

#[cfg(windows)]
fn state_bucket(state: u32) -> NativeServiceStateBucket {
    use windows_sys::Win32::System::Services::{
        SERVICE_CONTINUE_PENDING, SERVICE_PAUSED, SERVICE_PAUSE_PENDING, SERVICE_RUNNING,
        SERVICE_START_PENDING, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    };
    match state {
        SERVICE_RUNNING => NativeServiceStateBucket::Running,
        SERVICE_STOPPED => NativeServiceStateBucket::Stopped,
        SERVICE_PAUSED => NativeServiceStateBucket::Paused,
        SERVICE_START_PENDING
        | SERVICE_STOP_PENDING
        | SERVICE_PAUSE_PENDING
        | SERVICE_CONTINUE_PENDING => NativeServiceStateBucket::Transitional,
        _ => NativeServiceStateBucket::Unknown,
    }
}

#[cfg(windows)]
fn classify_service(raw_name: &str, raw_display: &str) -> NativeServiceCategory {
    let value = format!("{raw_name} {raw_display}").to_ascii_lowercase();
    if contains_any(
        &value,
        &["windefend", "security", "wscsvc", "mpssvc", "sense"],
    ) {
        NativeServiceCategory::Security
    } else if contains_any(&value, &["termservice", "winrm", "remote", "ssh"]) {
        NativeServiceCategory::RemoteManagement
    } else if contains_any(
        &value,
        &[
            "dnscache", "dhcp", "netlogon", "nsi", "tcpip", "wlan", "network",
        ],
    ) {
        NativeServiceCategory::Network
    } else if contains_any(&value, &["wuauserv", "bits", "update", "trustedinstaller"]) {
        NativeServiceCategory::Update
    } else if contains_any(&value, &["vss", "stor", "disk", "defrag", "volume"]) {
        NativeServiceCategory::Storage
    } else if contains_any(
        &value,
        &[
            "rpc", "eventlog", "plugplay", "profsvc", "dcom", "winmgmt", "schedule",
        ],
    ) {
        NativeServiceCategory::OperatingSystemCore
    } else if contains_any(&value, &["spooler", "msi", "app", "browser"]) {
        NativeServiceCategory::ApplicationSupport
    } else {
        NativeServiceCategory::Unknown
    }
}

#[cfg(windows)]
fn contains_any(value: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| value.contains(marker))
}

#[cfg(windows)]
fn trust_category(category: &NativeServiceCategory) -> NativeServiceTrustCategory {
    match category {
        NativeServiceCategory::OperatingSystemCore
        | NativeServiceCategory::Update
        | NativeServiceCategory::Storage => NativeServiceTrustCategory::OperatingSystemOwned,
        NativeServiceCategory::Security => NativeServiceTrustCategory::SecurityRelevant,
        NativeServiceCategory::Unknown => NativeServiceTrustCategory::Unknown,
        _ => NativeServiceTrustCategory::ThirdPartyCategory,
    }
}

#[cfg(windows)]
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 && len < 256 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

fn ratio_bucket(part: u32, total: u32) -> &'static str {
    if total == 0 || part == 0 {
        "none"
    } else if part.saturating_mul(4) < total {
        "low"
    } else if part.saturating_mul(4) < total.saturating_mul(3) {
        "medium"
    } else {
        "high"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds() -> WindowsNativeServiceBounds {
        WindowsNativeServiceBounds {
            max_records: 128,
            max_bytes: 65_536,
            timeout_millis: 5_000,
            cancellation_requested: false,
        }
    }

    #[test]
    fn serialized_adapter_output_is_category_only() {
        let sample = WindowsNativeServiceAdapter.sample(bounds());
        let serialized = serde_json::to_string(&sample).expect("serialize service sample");
        for forbidden in [
            "service_name",
            "display_name",
            "executable_path",
            "command_line",
            "account_name",
            "username",
            "\"sid\"",
            "\"pid\"",
            "registry_path",
            "credential",
            "secret",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[cfg(windows)]
    #[test]
    fn classifier_never_echoes_raw_service_values() {
        let raw_name = "sentinel-sensitive-service-name";
        let raw_display = "Sentinel Sensitive Display Value";
        let category = classify_service(raw_name, raw_display);
        let serialized = serde_json::to_string(&category).expect("serialize category");
        assert!(!serialized.contains(raw_name));
        assert!(!serialized.contains(raw_display));
    }

    #[cfg(windows)]
    #[test]
    fn windows_scm_observes_bounded_category_aggregates() {
        let sample = WindowsNativeServiceAdapter.sample(bounds());
        assert_eq!(sample.provider_enabled_count, 1);
        assert!(sample.raw_record_count > 0);
        assert!(sample.schema_accepted_count > 0);
        assert!(sample.normalized_record_count > 0);
        assert!(!sample.aggregates.is_empty());
        assert!(sample.aggregates.len() <= 128);
        assert_eq!(sample.schema_rejected_count, 0);
        assert_eq!(sample.queue_dropped_count, 0);
    }
}
