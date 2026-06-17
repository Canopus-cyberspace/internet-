//! Metadata-only Windows IP Helper snapshot adapter.
//!
//! The adapter reads transient TCP/UDP table rows, derives bounded category
//! metadata, and discards raw owner and endpoint values before returning. It is
//! infrastructure-only and does not own Sentinel runtime state.

use crate::provider_adapter::{
    BoundedProviderRequest, NetworkMetadataAdapter, ProviderAdapterMetadata,
    ProviderAdapterOwnership, ProviderProbe, PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
};
use sentinel_contracts::{NetworkProviderKind, RedactionStatus, SchemaVersion, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub const IP_HELPER_PROVIDER_ID: &str = "ip_helper_network_metadata";
const IP_HELPER_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
const DEFAULT_MAX_ROWS_PER_SNAPSHOT: usize = 4_096;
const DEFAULT_MAX_CATEGORIES: usize = 256;
const DEFAULT_TIMEOUT_MS: u64 = 500;
const MAX_ROWS_PER_SNAPSHOT: usize = 16_384;
const MAX_CATEGORIES: usize = 512;
#[cfg(windows)]
const MAX_TABLE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperProviderStatus {
    Available,
    Degraded,
    Unavailable,
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperTransport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperAddressScope {
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Public,
    Unspecified,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperEndpointRange {
    SystemRange,
    RegisteredRange,
    EphemeralRange,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperServiceCategory {
    Web,
    Dns,
    RemoteAdmin,
    FileSharing,
    Mail,
    Directory,
    Time,
    Other,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperStateCategory {
    Listen,
    Established,
    Closing,
    Stateless,
    Other,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHelperOwnerSignal {
    OwnerObservedNotRetained,
    OwnerUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpHelperSnapshotConfig {
    pub max_rows_per_snapshot: usize,
    pub max_categories: usize,
    pub timeout_ms: u64,
    pub suppress_loopback_only: bool,
}

impl Default for IpHelperSnapshotConfig {
    fn default() -> Self {
        Self {
            max_rows_per_snapshot: DEFAULT_MAX_ROWS_PER_SNAPSHOT,
            max_categories: DEFAULT_MAX_CATEGORIES,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            suppress_loopback_only: true,
        }
    }
}

impl IpHelperSnapshotConfig {
    pub fn bounded(mut self) -> Self {
        self.max_rows_per_snapshot = self.max_rows_per_snapshot.clamp(1, MAX_ROWS_PER_SNAPSHOT);
        self.max_categories = self.max_categories.clamp(1, MAX_CATEGORIES);
        self.timeout_ms = self.timeout_ms.clamp(25, 2_000);
        self
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpHelperConfigSummary {
    pub max_rows_per_snapshot: usize,
    pub max_categories: usize,
    pub timeout_bucket: String,
    pub loopback_only_suppression: bool,
}

impl IpHelperConfigSummary {
    fn from_config(config: &IpHelperSnapshotConfig) -> Self {
        Self {
            max_rows_per_snapshot: config.max_rows_per_snapshot,
            max_categories: config.max_categories,
            timeout_bucket: timeout_bucket(config.timeout_ms).to_string(),
            loopback_only_suppression: config.suppress_loopback_only,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpHelperPrivacySummary {
    pub retention_policy: String,
    pub endpoint_identity: String,
    pub owner_identity: String,
    pub executable_identity: String,
    pub raw_payload_state: String,
}

impl Default for IpHelperPrivacySummary {
    fn default() -> Self {
        Self {
            retention_policy: "category_only_no_raw_endpoint_or_owner_values".to_string(),
            endpoint_identity: "not_retained".to_string(),
            owner_identity: "not_retained".to_string(),
            executable_identity: "not_requested".to_string(),
            raw_payload_state: "not_available".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpHelperConnectionCategory {
    pub transport: IpHelperTransport,
    pub state_category: IpHelperStateCategory,
    pub local_scope: IpHelperAddressScope,
    pub remote_scope: IpHelperAddressScope,
    pub local_endpoint_range: IpHelperEndpointRange,
    pub remote_endpoint_range: IpHelperEndpointRange,
    pub service_category: IpHelperServiceCategory,
    pub owner_signal: IpHelperOwnerSignal,
    pub count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpHelperSnapshotSummary {
    pub provider_id: String,
    pub provider_status: IpHelperProviderStatus,
    pub schema_version: SchemaVersion,
    pub sampled_at: Timestamp,
    pub config: IpHelperConfigSummary,
    pub rows_observed: u32,
    pub rows_processed: u32,
    pub rows_suppressed: u32,
    pub rows_dropped: u32,
    pub tcp_rows: u32,
    pub udp_rows: u32,
    pub category_count: u32,
    pub categories: Vec<IpHelperConnectionCategory>,
    pub privacy: IpHelperPrivacySummary,
    pub degraded_reason: Option<String>,
}

impl IpHelperSnapshotSummary {
    pub fn unsupported_platform(config: IpHelperSnapshotConfig) -> Self {
        Self {
            provider_id: IP_HELPER_PROVIDER_ID.to_string(),
            provider_status: IpHelperProviderStatus::UnsupportedPlatform,
            schema_version: IP_HELPER_SCHEMA_VERSION,
            sampled_at: Timestamp::now(),
            config: IpHelperConfigSummary::from_config(&config.bounded()),
            rows_observed: 0,
            rows_processed: 0,
            rows_suppressed: 0,
            rows_dropped: 0,
            tcp_rows: 0,
            udp_rows: 0,
            category_count: 0,
            categories: Vec::new(),
            privacy: IpHelperPrivacySummary::default(),
            degraded_reason: Some("unsupported_platform".to_string()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct IpHelperSnapshotAdapter;

impl IpHelperSnapshotAdapter {
    pub fn new() -> Self {
        Self
    }

    #[cfg(windows)]
    pub fn snapshot(
        &self,
        config: IpHelperSnapshotConfig,
    ) -> Result<IpHelperSnapshotSummary, IpHelperProviderError> {
        let config = config.bounded();
        let started_at = Instant::now();
        let mut rows = Vec::new();
        let mut reasons = Vec::new();

        match collect_tcp4_rows(&config, started_at) {
            Ok(mut tcp_rows) => rows.append(&mut tcp_rows),
            Err(error) => reasons.push(error.reason_redacted),
        }

        if started_at.elapsed() < config.timeout() {
            match collect_udp4_rows(&config, started_at) {
                Ok(mut udp_rows) => rows.append(&mut udp_rows),
                Err(error) => reasons.push(error.reason_redacted),
            }
        } else {
            reasons.push("snapshot_timeout_before_udp_table".to_string());
        }

        let status = if reasons.is_empty() {
            IpHelperProviderStatus::Available
        } else if rows.is_empty() {
            IpHelperProviderStatus::Unavailable
        } else {
            IpHelperProviderStatus::Degraded
        };
        let degraded_reason = if reasons.is_empty() {
            None
        } else {
            Some(join_reasons(reasons))
        };

        Ok(summarize_raw_rows(
            config,
            rows,
            status,
            degraded_reason,
            started_at,
        ))
    }

    #[cfg(not(windows))]
    pub fn snapshot(
        &self,
        config: IpHelperSnapshotConfig,
    ) -> Result<IpHelperSnapshotSummary, IpHelperProviderError> {
        Ok(IpHelperSnapshotSummary::unsupported_platform(config))
    }
}

impl ProviderProbe for IpHelperSnapshotAdapter {
    fn adapter_metadata(&self) -> ProviderAdapterMetadata {
        ProviderAdapterMetadata {
            adapter_id: "ip_helper_infrastructure_adapter".to_string(),
            provider_kind: NetworkProviderKind::IpHelper,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            ownership: ProviderAdapterOwnership::infrastructure_adapter(),
            supported_request_refs: vec!["bounded_ip_helper_snapshot_request".to_string()],
            supported_result_refs: vec!["bounded_ip_helper_category_summary".to_string()],
            privacy_notes: vec![
                "category_only_endpoint_values_not_retained".to_string(),
                "owner_values_observed_only_not_retained".to_string(),
                "raw_content_not_available".to_string(),
            ],
            redaction_status: RedactionStatus::Redacted,
        }
    }
}

impl NetworkMetadataAdapter for IpHelperSnapshotAdapter {
    type Request = BoundedProviderRequest;
    type Result = IpHelperSnapshotSummary;
    type Error = IpHelperProviderError;

    fn read_bounded(&self, request: Self::Request) -> Result<Self::Result, Self::Error> {
        if request.provider_kind != NetworkProviderKind::IpHelper || request.validate().is_err() {
            return Err(IpHelperProviderError::new("bounded_request_rejected"));
        }
        self.snapshot(IpHelperSnapshotConfig {
            max_rows_per_snapshot: request.max_records,
            max_categories: request.max_records.min(MAX_CATEGORIES),
            timeout_ms: request.timeout_ms,
            suppress_loopback_only: true,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpHelperProviderError {
    pub reason_redacted: String,
}

impl IpHelperProviderError {
    fn new(reason_redacted: impl Into<String>) -> Self {
        Self {
            reason_redacted: reason_redacted.into(),
        }
    }
}

impl std::fmt::Display for IpHelperProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IP Helper provider unavailable: {}",
            self.reason_redacted
        )
    }
}

impl std::error::Error for IpHelperProviderError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RawIpHelperRow {
    transport: IpHelperTransport,
    local_addr_v4: u32,
    remote_addr_v4: Option<u32>,
    local_endpoint: u16,
    remote_endpoint: Option<u16>,
    tcp_state: Option<u32>,
    owner_seen: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CategoryKey {
    transport: IpHelperTransport,
    state_category: IpHelperStateCategory,
    local_scope: IpHelperAddressScope,
    remote_scope: IpHelperAddressScope,
    local_endpoint_range: IpHelperEndpointRange,
    remote_endpoint_range: IpHelperEndpointRange,
    service_category: IpHelperServiceCategory,
    owner_signal: IpHelperOwnerSignal,
}

fn summarize_raw_rows(
    config: IpHelperSnapshotConfig,
    rows: Vec<RawIpHelperRow>,
    status: IpHelperProviderStatus,
    degraded_reason: Option<String>,
    started_at: Instant,
) -> IpHelperSnapshotSummary {
    let timeout = config.timeout();
    let rows_observed = rows.len();
    let mut rows_processed = 0usize;
    let mut rows_suppressed = 0usize;
    let mut rows_dropped = 0usize;
    let mut tcp_rows = 0usize;
    let mut udp_rows = 0usize;
    let mut categories = BTreeMap::<CategoryKey, u32>::new();
    let mut timed_out = false;

    for row in rows.iter().take(config.max_rows_per_snapshot) {
        if started_at.elapsed() > timeout {
            timed_out = true;
            rows_dropped += 1;
            break;
        }

        match row.transport {
            IpHelperTransport::Tcp => tcp_rows += 1,
            IpHelperTransport::Udp => udp_rows += 1,
        }

        let key = category_key(*row);
        if config.suppress_loopback_only && is_loopback_only(&key) {
            rows_suppressed += 1;
            continue;
        }

        rows_processed += 1;
        if categories.len() >= config.max_categories && !categories.contains_key(&key) {
            rows_dropped += 1;
            continue;
        }
        *categories.entry(key).or_insert(0) += 1;
    }

    if rows_observed > config.max_rows_per_snapshot {
        rows_dropped += rows_observed - config.max_rows_per_snapshot;
    }

    let mut degraded_reason = degraded_reason;
    if timed_out {
        degraded_reason = Some(join_reasons(
            degraded_reason
                .into_iter()
                .chain(["snapshot_processing_timeout".to_string()])
                .collect(),
        ));
    }

    let category_rows = categories
        .into_iter()
        .map(|(key, count)| IpHelperConnectionCategory {
            transport: key.transport,
            state_category: key.state_category,
            local_scope: key.local_scope,
            remote_scope: key.remote_scope,
            local_endpoint_range: key.local_endpoint_range,
            remote_endpoint_range: key.remote_endpoint_range,
            service_category: key.service_category,
            owner_signal: key.owner_signal,
            count,
        })
        .collect::<Vec<_>>();

    IpHelperSnapshotSummary {
        provider_id: IP_HELPER_PROVIDER_ID.to_string(),
        provider_status: if timed_out && status == IpHelperProviderStatus::Available {
            IpHelperProviderStatus::Degraded
        } else {
            status
        },
        schema_version: IP_HELPER_SCHEMA_VERSION,
        sampled_at: Timestamp::now(),
        config: IpHelperConfigSummary::from_config(&config),
        rows_observed: saturating_u32(rows_observed),
        rows_processed: saturating_u32(rows_processed),
        rows_suppressed: saturating_u32(rows_suppressed),
        rows_dropped: saturating_u32(rows_dropped),
        tcp_rows: saturating_u32(tcp_rows),
        udp_rows: saturating_u32(udp_rows),
        category_count: saturating_u32(category_rows.len()),
        categories: category_rows,
        privacy: IpHelperPrivacySummary::default(),
        degraded_reason,
    }
}

fn category_key(row: RawIpHelperRow) -> CategoryKey {
    let local_endpoint = row.local_endpoint;
    let remote_endpoint = row.remote_endpoint.unwrap_or_default();
    CategoryKey {
        transport: row.transport,
        state_category: state_category(row.transport, row.tcp_state),
        local_scope: address_scope(row.local_addr_v4),
        remote_scope: row
            .remote_addr_v4
            .map(address_scope)
            .unwrap_or(IpHelperAddressScope::Unknown),
        local_endpoint_range: endpoint_range(local_endpoint),
        remote_endpoint_range: row
            .remote_endpoint
            .map(endpoint_range)
            .unwrap_or(IpHelperEndpointRange::Unknown),
        service_category: service_category(local_endpoint, remote_endpoint),
        owner_signal: if row.owner_seen {
            IpHelperOwnerSignal::OwnerObservedNotRetained
        } else {
            IpHelperOwnerSignal::OwnerUnavailable
        },
    }
}

fn is_loopback_only(key: &CategoryKey) -> bool {
    key.local_scope == IpHelperAddressScope::Loopback
        && matches!(
            key.remote_scope,
            IpHelperAddressScope::Loopback
                | IpHelperAddressScope::Unspecified
                | IpHelperAddressScope::Unknown
        )
}

fn address_scope(raw_v4: u32) -> IpHelperAddressScope {
    let address = Ipv4Addr::from(raw_v4.to_le_bytes());
    if address.is_unspecified() {
        IpHelperAddressScope::Unspecified
    } else if address.is_loopback() {
        IpHelperAddressScope::Loopback
    } else if address.is_private() {
        IpHelperAddressScope::Private
    } else if address.is_link_local() {
        IpHelperAddressScope::LinkLocal
    } else if address.is_multicast() {
        IpHelperAddressScope::Multicast
    } else {
        IpHelperAddressScope::Public
    }
}

fn endpoint_range(endpoint: u16) -> IpHelperEndpointRange {
    match endpoint {
        0 => IpHelperEndpointRange::Unknown,
        1..=1023 => IpHelperEndpointRange::SystemRange,
        1024..=49_151 => IpHelperEndpointRange::RegisteredRange,
        _ => IpHelperEndpointRange::EphemeralRange,
    }
}

fn service_category(local_endpoint: u16, remote_endpoint: u16) -> IpHelperServiceCategory {
    let selected = if remote_endpoint == 0 {
        local_endpoint
    } else {
        remote_endpoint
    };
    match selected {
        0 => IpHelperServiceCategory::Unknown,
        53 => IpHelperServiceCategory::Dns,
        80 | 443 | 8080 | 8443 => IpHelperServiceCategory::Web,
        22 | 3389 | 5985 | 5986 => IpHelperServiceCategory::RemoteAdmin,
        139 | 445 => IpHelperServiceCategory::FileSharing,
        25 | 110 | 143 | 465 | 587 | 993 | 995 => IpHelperServiceCategory::Mail,
        88 | 389 | 636 | 3268 | 3269 => IpHelperServiceCategory::Directory,
        123 => IpHelperServiceCategory::Time,
        _ => IpHelperServiceCategory::Other,
    }
}

fn state_category(transport: IpHelperTransport, state: Option<u32>) -> IpHelperStateCategory {
    if transport == IpHelperTransport::Udp {
        return IpHelperStateCategory::Stateless;
    }
    match state {
        Some(2) => IpHelperStateCategory::Listen,
        Some(5) => IpHelperStateCategory::Established,
        Some(6..=11) => IpHelperStateCategory::Closing,
        Some(_) => IpHelperStateCategory::Other,
        None => IpHelperStateCategory::Unknown,
    }
}

fn timeout_bucket(timeout_ms: u64) -> &'static str {
    match timeout_ms {
        0..=249 => "sub_250ms",
        250..=999 => "sub_second",
        _ => "multi_second",
    }
}

fn join_reasons(reasons: Vec<String>) -> String {
    let mut clean = reasons
        .into_iter()
        .filter(|reason| !reason.trim().is_empty())
        .take(4)
        .collect::<Vec<_>>();
    clean.sort();
    clean.dedup();
    if clean.is_empty() {
        "degraded".to_string()
    } else {
        clean.join("|")
    }
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(windows)]
fn collect_tcp4_rows(
    config: &IpHelperSnapshotConfig,
    started_at: Instant,
) -> Result<Vec<RawIpHelperRow>, IpHelperProviderError> {
    use std::ptr::{addr_of, null_mut};
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let mut size = 0u32;
    let initial = unsafe {
        GetExtendedTcpTable(
            null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if initial != ERROR_INSUFFICIENT_BUFFER && initial != NO_ERROR {
        return Err(IpHelperProviderError::new("tcp_table_unavailable"));
    }
    let table_size = size as usize;
    if table_size == 0 || table_size > MAX_TABLE_BYTES {
        return Err(IpHelperProviderError::new("tcp_table_size_rejected"));
    }

    let mut buffer = vec![0u8; table_size];
    let result = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if result != NO_ERROR {
        return Err(IpHelperProviderError::new("tcp_table_read_failed"));
    }

    let table = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries as usize };
    let row_ptr = unsafe { addr_of!((*table).table).cast::<MIB_TCPROW_OWNER_PID>() };
    let take = count.min(config.max_rows_per_snapshot);
    let mut rows = Vec::with_capacity(take);
    for index in 0..take {
        if started_at.elapsed() > config.timeout() {
            break;
        }
        let row = unsafe { *row_ptr.add(index) };
        rows.push(RawIpHelperRow {
            transport: IpHelperTransport::Tcp,
            local_addr_v4: row.dwLocalAddr,
            remote_addr_v4: Some(row.dwRemoteAddr),
            local_endpoint: endpoint_from_windows_dword(row.dwLocalPort),
            remote_endpoint: Some(endpoint_from_windows_dword(row.dwRemotePort)),
            tcp_state: Some(row.dwState),
            owner_seen: row.dwOwningPid != 0,
        });
    }
    Ok(rows)
}

#[cfg(windows)]
fn collect_udp4_rows(
    config: &IpHelperSnapshotConfig,
    started_at: Instant,
) -> Result<Vec<RawIpHelperRow>, IpHelperProviderError> {
    use std::ptr::{addr_of, null_mut};
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let mut size = 0u32;
    let initial = unsafe {
        GetExtendedUdpTable(
            null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if initial != ERROR_INSUFFICIENT_BUFFER && initial != NO_ERROR {
        return Err(IpHelperProviderError::new("udp_table_unavailable"));
    }
    let table_size = size as usize;
    if table_size == 0 || table_size > MAX_TABLE_BYTES {
        return Err(IpHelperProviderError::new("udp_table_size_rejected"));
    }

    let mut buffer = vec![0u8; table_size];
    let result = unsafe {
        GetExtendedUdpTable(
            buffer.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if result != NO_ERROR {
        return Err(IpHelperProviderError::new("udp_table_read_failed"));
    }

    let table = buffer.as_ptr().cast::<MIB_UDPTABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries as usize };
    let row_ptr = unsafe { addr_of!((*table).table).cast::<MIB_UDPROW_OWNER_PID>() };
    let take = count.min(config.max_rows_per_snapshot);
    let mut rows = Vec::with_capacity(take);
    for index in 0..take {
        if started_at.elapsed() > config.timeout() {
            break;
        }
        let row = unsafe { *row_ptr.add(index) };
        rows.push(RawIpHelperRow {
            transport: IpHelperTransport::Udp,
            local_addr_v4: row.dwLocalAddr,
            remote_addr_v4: None,
            local_endpoint: endpoint_from_windows_dword(row.dwLocalPort),
            remote_endpoint: None,
            tcp_state: None,
            owner_seen: row.dwOwningPid != 0,
        });
    }
    Ok(rows)
}

#[cfg(windows)]
fn endpoint_from_windows_dword(value: u32) -> u16 {
    u16::from_be((value & 0xffff) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_le_bytes([a, b, c, d])
    }

    fn tcp_row(
        local: [u8; 4],
        remote: [u8; 4],
        local_endpoint: u16,
        remote_endpoint: u16,
    ) -> RawIpHelperRow {
        RawIpHelperRow {
            transport: IpHelperTransport::Tcp,
            local_addr_v4: v4(local[0], local[1], local[2], local[3]),
            remote_addr_v4: Some(v4(remote[0], remote[1], remote[2], remote[3])),
            local_endpoint,
            remote_endpoint: Some(remote_endpoint),
            tcp_state: Some(5),
            owner_seen: true,
        }
    }

    #[test]
    fn ip_helper_summary_keeps_only_categories_and_counters() {
        let config = IpHelperSnapshotConfig {
            max_rows_per_snapshot: 16,
            max_categories: 8,
            timeout_ms: 250,
            suppress_loopback_only: true,
        }
        .bounded();
        let rows = vec![
            tcp_row([10, 0, 0, 10], [203, 0, 113, 77], 49_152, 443),
            tcp_row([10, 0, 0, 10], [203, 0, 113, 77], 49_153, 443),
        ];

        let summary = summarize_raw_rows(
            config,
            rows,
            IpHelperProviderStatus::Available,
            None,
            Instant::now(),
        );

        assert_eq!(summary.provider_status, IpHelperProviderStatus::Available);
        assert_eq!(summary.rows_observed, 2);
        assert_eq!(summary.rows_processed, 2);
        assert_eq!(summary.category_count, 1);
        assert_eq!(
            summary.categories[0].service_category,
            IpHelperServiceCategory::Web
        );

        let serialized = serde_json::to_string(&summary).expect("summary serializes");
        for forbidden in [
            "203.0.113.77",
            "10.0.0.10",
            "49152",
            "49153",
            "424242",
            "cmd.exe",
            "powershell",
            "c:\\",
            "secret",
            "token",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(forbidden),
                "serialized summary leaked forbidden value {forbidden}: {serialized}"
            );
        }
    }

    #[test]
    fn loopback_only_rows_are_suppressed_by_default() {
        let rows = vec![tcp_row([127, 0, 0, 1], [127, 0, 0, 1], 49_152, 80)];
        let summary = summarize_raw_rows(
            IpHelperSnapshotConfig::default().bounded(),
            rows,
            IpHelperProviderStatus::Available,
            None,
            Instant::now(),
        );

        assert_eq!(summary.rows_observed, 1);
        assert_eq!(summary.rows_suppressed, 1);
        assert_eq!(summary.rows_processed, 0);
        assert!(summary.categories.is_empty());
    }

    #[test]
    fn bounded_processing_drops_rows_beyond_configured_limit() {
        let config = IpHelperSnapshotConfig {
            max_rows_per_snapshot: 2,
            max_categories: 8,
            timeout_ms: 250,
            suppress_loopback_only: false,
        }
        .bounded();
        let rows = vec![
            tcp_row([10, 0, 0, 10], [198, 51, 100, 10], 49_152, 443),
            tcp_row([10, 0, 0, 11], [198, 51, 100, 11], 49_153, 53),
            tcp_row([10, 0, 0, 12], [198, 51, 100, 12], 49_154, 3389),
        ];

        let summary = summarize_raw_rows(
            config,
            rows,
            IpHelperProviderStatus::Available,
            None,
            Instant::now(),
        );

        assert_eq!(summary.rows_observed, 3);
        assert_eq!(summary.rows_processed, 2);
        assert_eq!(summary.rows_dropped, 1);
        assert_eq!(summary.category_count, 2);
    }

    #[test]
    fn udp_rows_are_stateless_and_use_local_service_bucket() {
        let rows = vec![RawIpHelperRow {
            transport: IpHelperTransport::Udp,
            local_addr_v4: v4(10, 0, 0, 10),
            remote_addr_v4: None,
            local_endpoint: 53,
            remote_endpoint: None,
            tcp_state: None,
            owner_seen: false,
        }];

        let summary = summarize_raw_rows(
            IpHelperSnapshotConfig {
                suppress_loopback_only: false,
                ..IpHelperSnapshotConfig::default()
            }
            .bounded(),
            rows,
            IpHelperProviderStatus::Available,
            None,
            Instant::now(),
        );

        assert_eq!(summary.udp_rows, 1);
        assert_eq!(
            summary.categories[0].state_category,
            IpHelperStateCategory::Stateless
        );
        assert_eq!(
            summary.categories[0].service_category,
            IpHelperServiceCategory::Dns
        );
        assert_eq!(
            summary.categories[0].owner_signal,
            IpHelperOwnerSignal::OwnerUnavailable
        );
    }

    #[test]
    fn unsupported_platform_summary_is_explicit_and_bounded() {
        let summary =
            IpHelperSnapshotSummary::unsupported_platform(IpHelperSnapshotConfig::default());

        assert_eq!(
            summary.provider_status,
            IpHelperProviderStatus::UnsupportedPlatform
        );
        assert_eq!(summary.rows_observed, 0);
        assert_eq!(
            summary.degraded_reason.as_deref(),
            Some("unsupported_platform")
        );
    }

    #[test]
    fn provider_adapter_metadata_is_infrastructure_owned_without_runtime_ownership() {
        let adapter = IpHelperSnapshotAdapter::new();
        let metadata = adapter.adapter_metadata();

        assert_eq!(metadata.provider_kind, NetworkProviderKind::IpHelper);
        assert_eq!(
            metadata.ownership,
            ProviderAdapterOwnership::infrastructure_adapter()
        );
        assert!(metadata.validate().is_ok());

        let serialized = serde_json::to_string(&metadata).expect("adapter metadata serializes");
        for forbidden in [
            "event_bus_owner",
            "dag_owner",
            "plugin_runtime_owner",
            "provider_controller_owner",
            "process_name",
            "pid",
            "ip_address",
            "port:",
            "packet_bytes",
            "credential",
            "secret",
            "token",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(forbidden),
                "adapter metadata leaked forbidden value {forbidden}: {serialized}"
            );
        }
    }
}
