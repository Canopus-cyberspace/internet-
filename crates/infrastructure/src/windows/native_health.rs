//! Bounded Windows host-health snapshot adapter.
//!
//! The adapter reads only aggregate memory pressure and system uptime. Raw
//! values remain transient and only bounded categories leave this module.

use sentinel_contracts::{
    NativeHostUptimeBucket, NativeProviderAvailabilityState, NativeProviderCategory,
    NativeResourcePressureBucket, NativeRuntimeHealthState, NativeRuntimePlatformCategory,
    NativeSampleFreshnessBucket,
};
use serde::{Deserialize, Serialize};

pub const WINDOWS_NATIVE_HEALTH_PROVIDER_ID: &str = "windows_native_health_snapshot";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsNativeHealthSample {
    pub provider_category: NativeProviderCategory,
    pub platform_category: NativeRuntimePlatformCategory,
    pub availability_state: NativeProviderAvailabilityState,
    pub health_state: NativeRuntimeHealthState,
    pub resource_pressure_bucket: NativeResourcePressureBucket,
    pub uptime_bucket: NativeHostUptimeBucket,
    pub freshness_bucket: NativeSampleFreshnessBucket,
    pub degraded_reason: Option<String>,
    pub provider_enabled_count: u32,
    pub raw_record_count: u32,
    pub schema_accepted_count: u32,
    pub schema_rejected_count: u32,
    pub normalized_record_count: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsNativeHealthAdapter;

impl WindowsNativeHealthAdapter {
    pub fn sample(&self) -> WindowsNativeHealthSample {
        sample_windows_health()
    }
}

#[cfg(windows)]
fn sample_windows_health() -> WindowsNativeHealthSample {
    use std::mem::size_of;
    use windows_sys::Win32::System::SystemInformation::{
        GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX,
    };

    let mut memory = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        dwMemoryLoad: 0,
        ullTotalPhys: 0,
        ullAvailPhys: 0,
        ullTotalPageFile: 0,
        ullAvailPageFile: 0,
        ullTotalVirtual: 0,
        ullAvailVirtual: 0,
        ullAvailExtendedVirtual: 0,
    };
    let memory_available = unsafe { GlobalMemoryStatusEx(&mut memory) != 0 };
    if !memory_available {
        return WindowsNativeHealthSample {
            provider_category: NativeProviderCategory::WindowsSystemHealthSnapshot,
            platform_category: NativeRuntimePlatformCategory::Windows,
            availability_state: NativeProviderAvailabilityState::ProviderUnavailable,
            health_state: NativeRuntimeHealthState::Degraded,
            resource_pressure_bucket: NativeResourcePressureBucket::Unknown,
            uptime_bucket: NativeHostUptimeBucket::Unknown,
            freshness_bucket: NativeSampleFreshnessBucket::Unavailable,
            degraded_reason: Some("aggregate_memory_status_unavailable".to_string()),
            provider_enabled_count: 1,
            raw_record_count: 0,
            schema_accepted_count: 0,
            schema_rejected_count: 1,
            normalized_record_count: 0,
        };
    }

    let pressure = pressure_bucket(memory.dwMemoryLoad);
    let uptime = uptime_bucket(unsafe { GetTickCount64() });
    let (health_state, degraded_reason) = match pressure {
        NativeResourcePressureBucket::High => (
            NativeRuntimeHealthState::Degraded,
            Some("resource_pressure_high".to_string()),
        ),
        NativeResourcePressureBucket::Critical => (
            NativeRuntimeHealthState::Degraded,
            Some("resource_pressure_critical".to_string()),
        ),
        _ => (NativeRuntimeHealthState::Healthy, None),
    };
    WindowsNativeHealthSample {
        provider_category: NativeProviderCategory::WindowsSystemHealthSnapshot,
        platform_category: NativeRuntimePlatformCategory::Windows,
        availability_state: NativeProviderAvailabilityState::Available,
        health_state,
        resource_pressure_bucket: pressure,
        uptime_bucket: uptime,
        freshness_bucket: NativeSampleFreshnessBucket::Current,
        degraded_reason,
        provider_enabled_count: 1,
        raw_record_count: 2,
        schema_accepted_count: 2,
        schema_rejected_count: 0,
        normalized_record_count: 1,
    }
}

#[cfg(not(windows))]
fn sample_windows_health() -> WindowsNativeHealthSample {
    WindowsNativeHealthSample {
        provider_category: NativeProviderCategory::UnsupportedPlatform,
        platform_category: NativeRuntimePlatformCategory::Unsupported,
        availability_state: NativeProviderAvailabilityState::UnsupportedPlatform,
        health_state: NativeRuntimeHealthState::Unsupported,
        resource_pressure_bucket: NativeResourcePressureBucket::Unknown,
        uptime_bucket: NativeHostUptimeBucket::Unknown,
        freshness_bucket: NativeSampleFreshnessBucket::Unavailable,
        degraded_reason: Some("unsupported_platform".to_string()),
        provider_enabled_count: 0,
        raw_record_count: 0,
        schema_accepted_count: 0,
        schema_rejected_count: 0,
        normalized_record_count: 0,
    }
}

fn pressure_bucket(memory_load_percent: u32) -> NativeResourcePressureBucket {
    match memory_load_percent {
        0..=59 => NativeResourcePressureBucket::Low,
        60..=74 => NativeResourcePressureBucket::Moderate,
        75..=89 => NativeResourcePressureBucket::High,
        90..=100 => NativeResourcePressureBucket::Critical,
        _ => NativeResourcePressureBucket::Unknown,
    }
}

fn uptime_bucket(uptime_millis: u64) -> NativeHostUptimeBucket {
    const HOUR_MS: u64 = 60 * 60 * 1_000;
    const DAY_MS: u64 = 24 * HOUR_MS;
    match uptime_millis {
        0..HOUR_MS => NativeHostUptimeBucket::LessThanOneHour,
        HOUR_MS..DAY_MS => NativeHostUptimeBucket::OneToTwentyFourHours,
        DAY_MS..=604_800_000 => NativeHostUptimeBucket::OneToSevenDays,
        _ => NativeHostUptimeBucket::MoreThanSevenDays,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pressure_and_uptime_are_bounded_categories() {
        assert_eq!(pressure_bucket(40), NativeResourcePressureBucket::Low);
        assert_eq!(pressure_bucket(70), NativeResourcePressureBucket::Moderate);
        assert_eq!(pressure_bucket(80), NativeResourcePressureBucket::High);
        assert_eq!(pressure_bucket(95), NativeResourcePressureBucket::Critical);
        assert_eq!(
            uptime_bucket(3_600_000),
            NativeHostUptimeBucket::OneToTwentyFourHours
        );
    }

    #[test]
    fn serialized_sample_contains_no_host_or_identity_values() {
        let sample = WindowsNativeHealthAdapter.sample();
        let serialized = serde_json::to_string(&sample).expect("serialize health sample");
        for forbidden in [
            "computer_name",
            "host_name",
            "username",
            "sid",
            "process",
            "pid",
            "command_line",
            "path",
            "token",
            "credential",
            "secret",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_health_snapshot_observes_real_aggregate_source() {
        let sample = WindowsNativeHealthAdapter.sample();
        assert_eq!(sample.provider_enabled_count, 1);
        assert!(sample.raw_record_count > 0);
        assert!(sample.schema_accepted_count > 0);
        assert!(sample.normalized_record_count > 0);
        assert_eq!(
            sample.availability_state,
            NativeProviderAvailabilityState::Available
        );
        assert_eq!(
            sample.freshness_bucket,
            NativeSampleFreshnessBucket::Current
        );
    }
}
