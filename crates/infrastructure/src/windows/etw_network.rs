//! Bounded ETW network-event normalization boundary.
//!
//! Raw endpoint and owner values exist only in the opaque transient input and
//! are immediately reduced to category metadata. This module does not create
//! an ETW session, collect events, publish runtime topics, or create facts.

use crate::provider_adapter::{
    ProviderAdapterMetadata, ProviderAdapterOwnership, ProviderProbe,
    PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
};
use sentinel_contracts::{
    EtwAllowedSchemaId, EtwByteCountBucket, EtwCountBucket, EtwDirectionCategory,
    EtwMissingVisibilityFlag, EtwNetworkActivityCategory, EtwNetworkEventFamily,
    EtwNormalizationPrivacySummary, EtwNormalizedNetworkBatch, EtwNormalizedNetworkRecord,
    EtwOwnerPresenceCategory, EtwSchemaAllowlist, EtwTransportCategory, NativeEndpointRangeBucket,
    NativeEndpointScopeCategory, NetworkProviderKind, RedactionStatus, Timestamp,
    ETW_NORMALIZATION_SCHEMA_VERSION, MAX_ETW_NORMALIZED_RECORDS,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use uuid::Uuid;

pub const ETW_NETWORK_NORMALIZER_ID: &str = "etw_network_event_normalizer";
const DEFAULT_MAX_EVENTS: usize = 4_096;
const DEFAULT_MAX_RECORDS: usize = 128;
const DEFAULT_MAX_DEDUP_ENTRIES: usize = 4_096;
const MAX_EVENTS: usize = 16_384;
const MAX_DEDUP_ENTRIES: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtwNetworkNormalizerConfig {
    pub max_events: usize,
    pub max_records: usize,
    pub max_dedup_entries: usize,
}

impl Default for EtwNetworkNormalizerConfig {
    fn default() -> Self {
        Self {
            max_events: DEFAULT_MAX_EVENTS,
            max_records: DEFAULT_MAX_RECORDS,
            max_dedup_entries: DEFAULT_MAX_DEDUP_ENTRIES,
        }
    }
}

impl EtwNetworkNormalizerConfig {
    pub fn bounded(mut self) -> Self {
        self.max_events = self.max_events.clamp(1, MAX_EVENTS);
        self.max_records = self.max_records.clamp(1, MAX_ETW_NORMALIZED_RECORDS);
        self.max_dedup_entries = self.max_dedup_entries.clamp(1, MAX_DEDUP_ENTRIES);
        self
    }
}

/// Opaque provider-boundary input. Exact values are neither serializable nor
/// exposed through accessors and are discarded after normalization.
pub struct EtwTransientNetworkEvent {
    schema_id: Option<EtwAllowedSchemaId>,
    schema_version: u16,
    activity: EtwNetworkActivityCategory,
    local_address_v4: u32,
    remote_address_v4: u32,
    local_port: u16,
    remote_port: u16,
    byte_count: u64,
    owner_process_id: Option<u32>,
    sequence: u64,
}

impl EtwTransientNetworkEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new_ipv4(
        schema_id: Option<EtwAllowedSchemaId>,
        schema_version: u16,
        activity: EtwNetworkActivityCategory,
        local_address: Ipv4Addr,
        remote_address: Ipv4Addr,
        local_port: u16,
        remote_port: u16,
        byte_count: u64,
        owner_process_id: Option<u32>,
        sequence: u64,
    ) -> Self {
        Self {
            schema_id,
            schema_version,
            activity,
            local_address_v4: u32::from(local_address),
            remote_address_v4: u32::from(remote_address),
            local_port,
            remote_port,
            byte_count,
            owner_process_id,
            sequence,
        }
    }

    /// Builds a category-only event from an allowlisted provider descriptor.
    /// The live ETW callback intentionally does not read or copy provider
    /// payload fields, endpoints, ports, or process identifiers.
    pub fn new_provider_metadata(
        schema_id: EtwAllowedSchemaId,
        activity: EtwNetworkActivityCategory,
        sequence: u64,
    ) -> Self {
        Self::new_ipv4(
            Some(schema_id),
            ETW_NORMALIZATION_SCHEMA_VERSION.major,
            activity,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            0,
            0,
            0,
            None,
            sequence,
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct EtwNetworkEventNormalizer;

impl EtwNetworkEventNormalizer {
    pub fn new() -> Self {
        Self
    }

    pub fn schema_allowlist(&self) -> EtwSchemaAllowlist {
        EtwSchemaAllowlist::metadata_only_v1()
    }

    pub fn normalize_bounded(
        &self,
        events: Vec<EtwTransientNetworkEvent>,
        config: EtwNetworkNormalizerConfig,
    ) -> EtwNormalizedNetworkBatch {
        normalize_events(events, config.bounded(), self.schema_allowlist())
    }
}

impl ProviderProbe for EtwNetworkEventNormalizer {
    fn adapter_metadata(&self) -> ProviderAdapterMetadata {
        ProviderAdapterMetadata {
            adapter_id: ETW_NETWORK_NORMALIZER_ID.to_string(),
            provider_kind: NetworkProviderKind::EtwNetwork,
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION,
            ownership: ProviderAdapterOwnership::infrastructure_adapter(),
            supported_request_refs: vec!["transient_allowlisted_etw_network_event".to_string()],
            supported_result_refs: vec!["bounded_etw_network_category_batch".to_string()],
            privacy_notes: vec![
                "raw_event_values_transient_only".to_string(),
                "dedup_hash_private_not_exposed".to_string(),
                "category_only_output".to_string(),
            ],
            redaction_status: RedactionStatus::Redacted,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CategoryKey {
    schema_id: EtwAllowedSchemaId,
    event_family: EtwNetworkEventFamily,
    transport: EtwTransportCategory,
    activity: EtwNetworkActivityCategory,
    direction: EtwDirectionCategory,
    local_scope: NativeEndpointScopeCategory,
    destination_scope: NativeEndpointScopeCategory,
    local_range: NativeEndpointRangeBucket,
    remote_range: NativeEndpointRangeBucket,
    byte_bucket: EtwByteCountBucket,
    owner_presence: EtwOwnerPresenceCategory,
}

fn normalize_events(
    events: Vec<EtwTransientNetworkEvent>,
    config: EtwNetworkNormalizerConfig,
    allowlist: EtwSchemaAllowlist,
) -> EtwNormalizedNetworkBatch {
    let observed = events.len();
    let mut accepted = 0usize;
    let mut deduplicated = 0usize;
    let mut rejected = 0usize;
    let mut dropped = observed.saturating_sub(config.max_events);
    let mut dedup = BTreeSet::<[u8; 32]>::new();
    let mut categories = BTreeMap::<CategoryKey, u32>::new();

    for event in events.into_iter().take(config.max_events) {
        let Some(schema_id) = event.schema_id else {
            rejected += 1;
            continue;
        };
        let Some(schema) = allowlist.entry(schema_id) else {
            rejected += 1;
            continue;
        };
        if event.schema_version != schema.schema_version.major {
            rejected += 1;
            continue;
        }

        let fingerprint = transient_fingerprint(&event);
        if dedup.contains(&fingerprint) {
            deduplicated += 1;
            continue;
        }
        if dedup.len() >= config.max_dedup_entries {
            dropped += 1;
            continue;
        }
        dedup.insert(fingerprint);

        let key = category_key(&event, schema.event_family, schema.transport_category);
        if categories.len() >= config.max_records && !categories.contains_key(&key) {
            dropped += 1;
            continue;
        }
        *categories.entry(key).or_insert(0) += 1;
        accepted += 1;
    }

    let records = categories
        .into_iter()
        .map(|(key, count)| normalized_record(key, count))
        .collect::<Vec<_>>();
    let degraded_reason = if dropped > 0 || rejected > 0 {
        Some("bounded_input_rejected_or_dropped".to_string())
    } else {
        None
    };

    EtwNormalizedNetworkBatch {
        batch_ref: format!("etw_normalization_batch_{}", Uuid::new_v4()),
        schema_version: ETW_NORMALIZATION_SCHEMA_VERSION,
        provider_kind: NetworkProviderKind::EtwNetwork,
        generated_at: Timestamp::now(),
        allowlist_ref: allowlist.allowlist_ref,
        events_observed: saturating_u32(observed),
        events_accepted: saturating_u32(accepted),
        events_deduplicated: saturating_u32(deduplicated),
        events_rejected: saturating_u32(rejected),
        events_dropped: saturating_u32(dropped),
        records,
        privacy: EtwNormalizationPrivacySummary::default(),
        event_session_created: false,
        collection_started: false,
        eventbus_publication_count: 0,
        security_fact_count: 0,
        provenance_refs: vec![
            "etw_infrastructure_normalizer".to_string(),
            "etw_schema_allowlist_v1".to_string(),
        ],
        redaction_status: RedactionStatus::Redacted,
        degraded_reason,
    }
}

fn category_key(
    event: &EtwTransientNetworkEvent,
    event_family: EtwNetworkEventFamily,
    transport: EtwTransportCategory,
) -> CategoryKey {
    let local_scope = address_scope(event.local_address_v4);
    let destination_scope = address_scope(event.remote_address_v4);
    CategoryKey {
        schema_id: event
            .schema_id
            .expect("schema is validated before category normalization"),
        event_family,
        transport,
        activity: event.activity,
        direction: direction(event.activity, local_scope, destination_scope),
        local_scope,
        destination_scope,
        local_range: endpoint_range(event.local_port),
        remote_range: endpoint_range(event.remote_port),
        byte_bucket: byte_count_bucket(event.byte_count),
        owner_presence: if event.owner_process_id.is_some() {
            EtwOwnerPresenceCategory::OwnerObservedNotRetained
        } else {
            EtwOwnerPresenceCategory::OwnerUnavailable
        },
    }
}

fn normalized_record(key: CategoryKey, count: u32) -> EtwNormalizedNetworkRecord {
    let mut hasher = Sha256::new();
    hasher.update(format!("{key:?}").as_bytes());
    let digest = hasher.finalize();
    let record_ref = format!(
        "etw_category_{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    );
    EtwNormalizedNetworkRecord {
        record_ref,
        schema_id: key.schema_id,
        event_family: key.event_family,
        transport_category: key.transport,
        activity_category: key.activity,
        direction_category: key.direction,
        local_scope_category: key.local_scope,
        destination_scope_category: key.destination_scope,
        local_endpoint_range_bucket: key.local_range,
        remote_endpoint_range_bucket: key.remote_range,
        byte_count_bucket: key.byte_bucket,
        owner_presence_category: key.owner_presence,
        count_bucket: EtwCountBucket::from_count(count),
        provenance_refs: vec!["etw_bounded_category_normalization".to_string()],
        redaction_status: RedactionStatus::Redacted,
        missing_visibility_flags: vec![
            EtwMissingVisibilityFlag::SpecificProcessIdentityUnavailable,
            EtwMissingVisibilityFlag::ProcessNetworkAttributionUnavailable,
            EtwMissingVisibilityFlag::PacketPayloadUnavailable,
            EtwMissingVisibilityFlag::CommandLineUnavailable,
            EtwMissingVisibilityFlag::FileRegistryUnavailable,
        ],
    }
}

fn transient_fingerprint(event: &EtwTransientNetworkEvent) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([event.schema_id.map(schema_discriminant).unwrap_or(0)]);
    hasher.update(event.schema_version.to_le_bytes());
    hasher.update([activity_discriminant(event.activity)]);
    hasher.update(event.local_address_v4.to_le_bytes());
    hasher.update(event.remote_address_v4.to_le_bytes());
    hasher.update(event.local_port.to_le_bytes());
    hasher.update(event.remote_port.to_le_bytes());
    hasher.update(event.byte_count.to_le_bytes());
    hasher.update(event.owner_process_id.unwrap_or_default().to_le_bytes());
    hasher.update(event.sequence.to_le_bytes());
    hasher.finalize().into()
}

fn schema_discriminant(schema: EtwAllowedSchemaId) -> u8 {
    match schema {
        EtwAllowedSchemaId::TcpConnectionLifecycleV1 => 1,
        EtwAllowedSchemaId::TcpTransferMetadataV1 => 2,
        EtwAllowedSchemaId::UdpDatagramActivityV1 => 3,
    }
}

fn activity_discriminant(activity: EtwNetworkActivityCategory) -> u8 {
    match activity {
        EtwNetworkActivityCategory::Connect => 1,
        EtwNetworkActivityCategory::Accept => 2,
        EtwNetworkActivityCategory::Disconnect => 3,
        EtwNetworkActivityCategory::Send => 4,
        EtwNetworkActivityCategory::Receive => 5,
        EtwNetworkActivityCategory::Other => 6,
    }
}

fn address_scope(raw: u32) -> NativeEndpointScopeCategory {
    let address = Ipv4Addr::from(raw);
    if address.is_unspecified() {
        NativeEndpointScopeCategory::Unspecified
    } else if address.is_loopback() {
        NativeEndpointScopeCategory::Loopback
    } else if address.is_private() {
        NativeEndpointScopeCategory::Private
    } else if address.is_link_local() {
        NativeEndpointScopeCategory::LinkLocal
    } else if address.is_multicast() {
        NativeEndpointScopeCategory::Multicast
    } else {
        NativeEndpointScopeCategory::Public
    }
}

fn endpoint_range(port: u16) -> NativeEndpointRangeBucket {
    match port {
        0 => NativeEndpointRangeBucket::Unknown,
        1..=1023 => NativeEndpointRangeBucket::SystemRange,
        1024..=49_151 => NativeEndpointRangeBucket::RegisteredRange,
        _ => NativeEndpointRangeBucket::EphemeralRange,
    }
}

fn byte_count_bucket(value: u64) -> EtwByteCountBucket {
    match value {
        0 => EtwByteCountBucket::None,
        1..=512 => EtwByteCountBucket::Tiny,
        513..=4_096 => EtwByteCountBucket::Small,
        4_097..=65_536 => EtwByteCountBucket::Medium,
        65_537..=1_048_576 => EtwByteCountBucket::Large,
        _ => EtwByteCountBucket::VeryLarge,
    }
}

fn direction(
    activity: EtwNetworkActivityCategory,
    local_scope: NativeEndpointScopeCategory,
    destination_scope: NativeEndpointScopeCategory,
) -> EtwDirectionCategory {
    if local_scope == NativeEndpointScopeCategory::Loopback
        && destination_scope == NativeEndpointScopeCategory::Loopback
    {
        return EtwDirectionCategory::Local;
    }
    match activity {
        EtwNetworkActivityCategory::Connect | EtwNetworkActivityCategory::Send => {
            EtwDirectionCategory::Outbound
        }
        EtwNetworkActivityCategory::Accept | EtwNetworkActivityCategory::Receive => {
            EtwDirectionCategory::Inbound
        }
        EtwNetworkActivityCategory::Disconnect | EtwNetworkActivityCategory::Other => {
            EtwDirectionCategory::Unknown
        }
    }
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(schema: Option<EtwAllowedSchemaId>, sequence: u64) -> EtwTransientNetworkEvent {
        EtwTransientNetworkEvent::new_ipv4(
            schema,
            1,
            EtwNetworkActivityCategory::Connect,
            Ipv4Addr::new(10, 0, 0, 7),
            Ipv4Addr::new(203, 0, 113, 77),
            61_234,
            443,
            4_096,
            Some(42_424),
            sequence,
        )
    }

    #[test]
    fn etw_network_schema_allowlist_accepts_only_declared_schemas() {
        let normalizer = EtwNetworkEventNormalizer::new();
        let allowlist = normalizer.schema_allowlist();
        assert!(allowlist.validate().is_ok());
        assert_eq!(allowlist.entries.len(), 3);

        let batch = normalizer.normalize_bounded(
            vec![
                event(Some(EtwAllowedSchemaId::TcpConnectionLifecycleV1), 1),
                event(None, 2),
            ],
            EtwNetworkNormalizerConfig::default(),
        );
        assert!(batch.validate().is_ok());
        assert_eq!(batch.events_observed, 2);
        assert_eq!(batch.events_accepted, 1);
        assert_eq!(batch.events_rejected, 1);
        assert_eq!(batch.records.len(), 1);
    }

    #[test]
    fn etw_network_normalization_is_bounded_and_deduplicated() {
        let normalizer = EtwNetworkEventNormalizer::new();
        let duplicate = event(Some(EtwAllowedSchemaId::TcpConnectionLifecycleV1), 1);
        let duplicate_again = event(Some(EtwAllowedSchemaId::TcpConnectionLifecycleV1), 1);
        let extra = event(Some(EtwAllowedSchemaId::TcpConnectionLifecycleV1), 2);
        let batch = normalizer.normalize_bounded(
            vec![duplicate, duplicate_again, extra],
            EtwNetworkNormalizerConfig {
                max_events: 3,
                max_records: 1,
                max_dedup_entries: 3,
            },
        );

        assert!(batch.validate().is_ok());
        assert_eq!(batch.events_observed, 3);
        assert_eq!(batch.events_accepted, 2);
        assert_eq!(batch.events_deduplicated, 1);
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].count_bucket, EtwCountBucket::Low);
        assert!(!batch.event_session_created);
        assert!(!batch.collection_started);
        assert_eq!(batch.eventbus_publication_count, 0);
        assert_eq!(batch.security_fact_count, 0);
    }

    #[test]
    fn etw_privacy_raw_values_and_private_dedup_hash_never_serialize() {
        let normalizer = EtwNetworkEventNormalizer::new();
        let metadata = normalizer.adapter_metadata();
        let batch = normalizer.normalize_bounded(
            vec![event(
                Some(EtwAllowedSchemaId::TcpConnectionLifecycleV1),
                9_999_999,
            )],
            EtwNetworkNormalizerConfig::default(),
        );
        assert!(metadata.validate().is_ok());
        assert!(batch.validate().is_ok());

        let serialized = serde_json::to_string(&batch).expect("serialize ETW batch");
        for marker in [
            "203.0.113.77",
            "10.0.0.7",
            "61234",
            "42424",
            "9999999",
            "process_name_value",
            "c:\\unsafe\\binary.exe",
            "username_value",
            "token_value",
            "credential_value",
            "secret_value",
        ] {
            assert!(!serialized.contains(marker), "leaked marker: {marker}");
        }
        assert!(!batch.privacy.dedup_hash_exposed);
        assert!(!batch.privacy.raw_event_retention_allowed);
        assert!(!batch.privacy.process_identity_retention_allowed);
    }

    #[test]
    fn etw_privacy_rejects_wrong_schema_version_without_raw_echo() {
        let normalizer = EtwNetworkEventNormalizer::new();
        let mut wrong_version = event(Some(EtwAllowedSchemaId::TcpConnectionLifecycleV1), 3);
        wrong_version.schema_version = 99;
        let batch = normalizer
            .normalize_bounded(vec![wrong_version], EtwNetworkNormalizerConfig::default());
        assert!(batch.validate().is_ok());
        assert_eq!(batch.events_rejected, 1);
        assert!(batch.records.is_empty());
        assert_eq!(
            batch.degraded_reason.as_deref(),
            Some("bounded_input_rejected_or_dropped")
        );
    }
}
