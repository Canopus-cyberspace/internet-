use sentinel_contracts::{
    DataSourceId, EtwByteCountBucket, EtwCountBucket, EtwDirectionCategory,
    EtwMissingVisibilityFlag, EtwNetworkActivityCategory, EtwNetworkEventFamily,
    EtwNormalizedNetworkBatch, EtwNormalizedNetworkRecord, EtwOwnerPresenceCategory,
    EtwTransportCategory, FusionContractError, NativeConnectionRelationCategory,
    NativeConnectionServiceBucket, NativeConnectionStateBucket, NativeEndpointScopeCategory,
    NativeIpHelperMetadataBatch, NativeNetworkProviderHealth, NativeNetworkTransportCategory,
    RedactionStatus, SecurityFact, SecurityLayer, Timestamp,
};

pub const NATIVE_NETWORK_FACT_CONTRACT: &str = "native.connection.category_fact";
pub const NATIVE_NETWORK_PROVIDER_HEALTH_FACT_CONTRACT: &str =
    "native.ip_helper.provider_health_fact";
pub const NATIVE_NETWORK_VISIBILITY_FACT_CONTRACT: &str = "native.connection_table.visibility_fact";
pub const NATIVE_ETW_NETWORK_PROVIDER_HEALTH_FACT_CONTRACT: &str =
    "native.etw_network.provider_health_fact";
pub const NATIVE_ETW_NETWORK_VISIBILITY_FACT_CONTRACT: &str = "native.etw_network.visibility_fact";
pub const NATIVE_NETWORK_FACT_SCHEMA_VERSION: sentinel_contracts::SchemaVersion =
    sentinel_contracts::SchemaVersion::new(1, 0, 0);

#[derive(Clone, Debug, Default)]
pub struct NativeNetworkFactPlugin;

impl NativeNetworkFactPlugin {
    pub fn new() -> Self {
        Self
    }

    pub fn process_batch(
        &self,
        batch: &NativeIpHelperMetadataBatch,
    ) -> Result<Vec<SecurityFact>, FusionContractError> {
        batch
            .validate()
            .map_err(|_| FusionContractError::UnsafeField("native_network_batch"))?;

        let mut facts = Vec::new();
        for record in &batch.categories {
            let mut fact = SecurityFact::new(
                SecurityLayer::AuthorizedNativeNetwork,
                NATIVE_NETWORK_FACT_CONTRACT,
                "ip_helper_metadata_adapter",
                record.time_bucket.clone(),
            )?;
            fact.provider_service_category =
                Some(service_bucket(record.service_category_bucket).to_string());
            fact.protocol_category = Some(transport_bucket(record.transport_category).to_string());
            fact.status_category = Some(state_bucket(record.connection_state_bucket).to_string());
            fact.relation_category =
                Some(relation_bucket(record.local_remote_relation_category).to_string());
            fact.cache_edge_origin_bucket =
                Some(scope_bucket(record.destination_scope_category).to_string());
            fact.lifecycle_bucket = Some(provider_health(record.provider_health).to_string());
            fact.count_bucket = Some(record.count_bucket.clone());
            fact.confidence_hint = record.confidence_hint.clone();
            fact.evidence_refs = record.evidence_refs.clone();
            fact.provenance_id = Some(DataSourceId::new_v4());
            fact.redaction_status = RedactionStatus::Redacted;
            fact.missing_visibility_flags =
                bounded_visibility_flags(record.missing_visibility_flags.iter().cloned());
            fact.degraded_reason = batch.degraded_reason.clone();
            fact.validate()?;
            facts.push(fact);
        }

        facts.push(provider_health_fact(batch)?);
        facts.push(visibility_fact(batch)?);
        Ok(facts)
    }

    pub fn process_etw_batch(
        &self,
        batch: &EtwNormalizedNetworkBatch,
    ) -> Result<Vec<SecurityFact>, FusionContractError> {
        batch
            .validate()
            .map_err(|_| FusionContractError::UnsafeField("etw_network_batch"))?;

        let mut facts = Vec::new();
        for record in &batch.records {
            facts.push(etw_event_fact(batch, record)?);
        }

        facts.push(etw_provider_health_fact(batch)?);
        facts.push(etw_visibility_fact(batch)?);
        Ok(facts)
    }
}

fn provider_health_fact(
    batch: &NativeIpHelperMetadataBatch,
) -> Result<SecurityFact, FusionContractError> {
    let mut fact = SecurityFact::new(
        SecurityLayer::AuthorizedNativeNetwork,
        NATIVE_NETWORK_PROVIDER_HEALTH_FACT_CONTRACT,
        "ip_helper_metadata_adapter",
        batch.sampled_time_bucket.clone(),
    )?;
    fact.lifecycle_bucket = Some(provider_health(batch.provider_health).to_string());
    fact.count_bucket = Some(batch.rows_processed_bucket.clone());
    fact.confidence_hint = confidence_for_health(batch.provider_health)?;
    fact.provenance_id = Some(DataSourceId::new_v4());
    fact.redaction_status = RedactionStatus::Redacted;
    fact.missing_visibility_flags = bounded_visibility_flags([
        "specific_process_identity_unavailable".to_string(),
        "process_network_attribution_unavailable".to_string(),
        "packet_visibility_unavailable".to_string(),
    ]);
    fact.degraded_reason = batch.degraded_reason.clone();
    fact.validate()?;
    Ok(fact)
}

fn visibility_fact(
    batch: &NativeIpHelperMetadataBatch,
) -> Result<SecurityFact, FusionContractError> {
    let mut fact = SecurityFact::new(
        SecurityLayer::AuthorizedNativeNetwork,
        NATIVE_NETWORK_VISIBILITY_FACT_CONTRACT,
        "ip_helper_metadata_adapter",
        Timestamp::now(),
    )?;
    fact.status_category = Some("connection_table_visibility_available".to_string());
    fact.lifecycle_bucket = Some(provider_health(batch.provider_health).to_string());
    fact.count_bucket = Some(batch.category_count_bucket.clone());
    fact.confidence_hint = confidence_for_health(batch.provider_health)?;
    fact.provenance_id = Some(DataSourceId::new_v4());
    fact.redaction_status = RedactionStatus::Redacted;
    fact.missing_visibility_flags = bounded_visibility_flags([
        "short_lived_network_event_visibility_unavailable".to_string(),
        "process_network_attribution_unavailable".to_string(),
        "specific_process_identity_unavailable".to_string(),
        "packet_header_visibility_unavailable".to_string(),
        "packet_visibility_unavailable".to_string(),
        "command_visibility_unavailable".to_string(),
        "file_registry_visibility_unavailable".to_string(),
    ]);
    fact.degraded_reason = batch.degraded_reason.clone();
    fact.validate()?;
    Ok(fact)
}

fn etw_event_fact(
    batch: &EtwNormalizedNetworkBatch,
    record: &EtwNormalizedNetworkRecord,
) -> Result<SecurityFact, FusionContractError> {
    let mut fact = SecurityFact::new(
        SecurityLayer::AuthorizedNativeNetwork,
        NATIVE_NETWORK_FACT_CONTRACT,
        "etw_network_metadata_adapter",
        batch.generated_at.clone(),
    )?;
    fact.provider_service_category = Some(etw_family_bucket(record.event_family).to_string());
    fact.protocol_category = Some(etw_transport_bucket(record.transport_category).to_string());
    fact.status_category = Some(etw_activity_bucket(record.activity_category).to_string());
    fact.relation_category = Some(etw_direction_bucket(record.direction_category).to_string());
    fact.cache_edge_origin_bucket =
        Some(scope_bucket(record.destination_scope_category).to_string());
    fact.lifecycle_bucket = Some(etw_owner_bucket(record.owner_presence_category).to_string());
    fact.method_category = Some(etw_byte_bucket(record.byte_count_bucket).to_string());
    fact.count_bucket = Some(etw_count_bucket(record.count_bucket).to_string());
    fact.confidence_hint = etw_confidence(batch)?;
    fact.provenance_id = Some(DataSourceId::new_v4());
    fact.redaction_status = RedactionStatus::Redacted;
    fact.missing_visibility_flags =
        bounded_visibility_flags(record.missing_visibility_flags.iter().map(etw_missing_flag));
    fact.degraded_reason = batch.degraded_reason.clone();
    fact.validate()?;
    Ok(fact)
}

fn etw_provider_health_fact(
    batch: &EtwNormalizedNetworkBatch,
) -> Result<SecurityFact, FusionContractError> {
    let mut fact = SecurityFact::new(
        SecurityLayer::AuthorizedNativeNetwork,
        NATIVE_ETW_NETWORK_PROVIDER_HEALTH_FACT_CONTRACT,
        "etw_network_metadata_adapter",
        batch.generated_at.clone(),
    )?;
    fact.status_category = Some("etw_metadata_handoff".to_string());
    fact.lifecycle_bucket = Some(etw_batch_health(batch).to_string());
    fact.count_bucket =
        Some(etw_count_bucket(EtwCountBucket::from_count(batch.events_accepted)).to_string());
    fact.confidence_hint = etw_confidence(batch)?;
    fact.provenance_id = Some(DataSourceId::new_v4());
    fact.redaction_status = RedactionStatus::Redacted;
    fact.missing_visibility_flags = bounded_visibility_flags([
        "specific_process_identity_unavailable".to_string(),
        "process_network_attribution_unavailable".to_string(),
        "packet_visibility_unavailable".to_string(),
        "command_visibility_unavailable".to_string(),
        "file_registry_visibility_unavailable".to_string(),
    ]);
    fact.degraded_reason = batch.degraded_reason.clone();
    fact.validate()?;
    Ok(fact)
}

fn etw_visibility_fact(
    batch: &EtwNormalizedNetworkBatch,
) -> Result<SecurityFact, FusionContractError> {
    let mut fact = SecurityFact::new(
        SecurityLayer::AuthorizedNativeNetwork,
        NATIVE_ETW_NETWORK_VISIBILITY_FACT_CONTRACT,
        "etw_network_metadata_adapter",
        Timestamp::now(),
    )?;
    fact.status_category = Some(if batch.events_accepted > 0 {
        "short_lived_event_visibility_available".to_string()
    } else {
        "short_lived_event_visibility_idle".to_string()
    });
    fact.lifecycle_bucket = Some(etw_batch_health(batch).to_string());
    fact.count_bucket =
        Some(etw_count_bucket(EtwCountBucket::from_count(batch.records.len() as u32)).to_string());
    fact.confidence_hint = etw_confidence(batch)?;
    fact.provenance_id = Some(DataSourceId::new_v4());
    fact.redaction_status = RedactionStatus::Redacted;
    fact.missing_visibility_flags = bounded_visibility_flags([
        "specific_process_identity_unavailable".to_string(),
        "process_network_attribution_unavailable".to_string(),
        "packet_visibility_unavailable".to_string(),
        "command_visibility_unavailable".to_string(),
        "file_registry_visibility_unavailable".to_string(),
    ]);
    fact.degraded_reason = batch.degraded_reason.clone();
    fact.validate()?;
    Ok(fact)
}

fn confidence_for_health(
    health: NativeNetworkProviderHealth,
) -> Result<sentinel_contracts::QualityScore, FusionContractError> {
    let value = match health {
        NativeNetworkProviderHealth::Available => 0.7,
        NativeNetworkProviderHealth::Degraded => 0.45,
        NativeNetworkProviderHealth::Unavailable
        | NativeNetworkProviderHealth::UnsupportedPlatform => 0.2,
    };
    sentinel_contracts::QualityScore::new(value)
        .map_err(|_| FusionContractError::UnsafeField("confidence_hint"))
}

fn etw_confidence(
    batch: &EtwNormalizedNetworkBatch,
) -> Result<sentinel_contracts::QualityScore, FusionContractError> {
    let value = if batch.events_accepted == 0 {
        0.3
    } else if batch.degraded_reason.is_some()
        || batch.events_dropped > 0
        || batch.events_rejected > 0
    {
        0.45
    } else {
        0.65
    };
    sentinel_contracts::QualityScore::new(value)
        .map_err(|_| FusionContractError::UnsafeField("confidence_hint"))
}

fn bounded_visibility_flags(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut flags = Vec::new();
    for value in values {
        if !flags.iter().any(|existing| existing == &value) {
            flags.push(value);
        }
        if flags.len() >= 12 {
            break;
        }
    }
    flags
}

fn transport_bucket(value: NativeNetworkTransportCategory) -> &'static str {
    match value {
        NativeNetworkTransportCategory::Tcp => "tcp",
        NativeNetworkTransportCategory::Udp => "udp",
    }
}

fn state_bucket(value: NativeConnectionStateBucket) -> &'static str {
    match value {
        NativeConnectionStateBucket::Listen => "listen",
        NativeConnectionStateBucket::Established => "established",
        NativeConnectionStateBucket::Closing => "closing",
        NativeConnectionStateBucket::Stateless => "stateless",
        NativeConnectionStateBucket::Other => "other",
        NativeConnectionStateBucket::Unknown => "unknown",
    }
}

fn scope_bucket(value: NativeEndpointScopeCategory) -> &'static str {
    match value {
        NativeEndpointScopeCategory::Loopback => "loopback",
        NativeEndpointScopeCategory::Private => "private",
        NativeEndpointScopeCategory::LinkLocal => "link_local",
        NativeEndpointScopeCategory::Multicast => "multicast",
        NativeEndpointScopeCategory::Public => "public",
        NativeEndpointScopeCategory::Unspecified => "unspecified",
        NativeEndpointScopeCategory::Unknown => "unknown",
    }
}

fn service_bucket(value: NativeConnectionServiceBucket) -> &'static str {
    match value {
        NativeConnectionServiceBucket::Web => "web",
        NativeConnectionServiceBucket::Dns => "dns",
        NativeConnectionServiceBucket::RemoteAdmin => "remote_admin",
        NativeConnectionServiceBucket::FileSharing => "file_sharing",
        NativeConnectionServiceBucket::Mail => "mail",
        NativeConnectionServiceBucket::Directory => "directory",
        NativeConnectionServiceBucket::Time => "time",
        NativeConnectionServiceBucket::Other => "other",
        NativeConnectionServiceBucket::Unknown => "unknown",
    }
}

fn relation_bucket(value: NativeConnectionRelationCategory) -> &'static str {
    match value {
        NativeConnectionRelationCategory::LocalOnly => "local_only",
        NativeConnectionRelationCategory::LocalToPrivate => "local_to_private",
        NativeConnectionRelationCategory::LocalToPublic => "local_to_public",
        NativeConnectionRelationCategory::LocalToMulticast => "local_to_multicast",
        NativeConnectionRelationCategory::Unknown => "unknown",
    }
}

fn provider_health(value: NativeNetworkProviderHealth) -> &'static str {
    match value {
        NativeNetworkProviderHealth::Available => "available",
        NativeNetworkProviderHealth::Degraded => "degraded",
        NativeNetworkProviderHealth::Unavailable => "unavailable",
        NativeNetworkProviderHealth::UnsupportedPlatform => "unsupported_platform",
    }
}

fn etw_batch_health(batch: &EtwNormalizedNetworkBatch) -> &'static str {
    if batch.events_accepted == 0 {
        "idle"
    } else if batch.degraded_reason.is_some()
        || batch.events_dropped > 0
        || batch.events_rejected > 0
    {
        "degraded"
    } else {
        "available"
    }
}

fn etw_family_bucket(value: EtwNetworkEventFamily) -> &'static str {
    match value {
        EtwNetworkEventFamily::ConnectionLifecycle => "connection_lifecycle",
        EtwNetworkEventFamily::DatagramActivity => "datagram_activity",
        EtwNetworkEventFamily::TransferMetadata => "transfer_metadata",
    }
}

fn etw_transport_bucket(value: EtwTransportCategory) -> &'static str {
    match value {
        EtwTransportCategory::Tcp => "tcp",
        EtwTransportCategory::Udp => "udp",
    }
}

fn etw_activity_bucket(value: EtwNetworkActivityCategory) -> &'static str {
    match value {
        EtwNetworkActivityCategory::Connect => "connect",
        EtwNetworkActivityCategory::Accept => "accept",
        EtwNetworkActivityCategory::Disconnect => "disconnect",
        EtwNetworkActivityCategory::Send => "send",
        EtwNetworkActivityCategory::Receive => "receive",
        EtwNetworkActivityCategory::Other => "other",
    }
}

fn etw_direction_bucket(value: EtwDirectionCategory) -> &'static str {
    match value {
        EtwDirectionCategory::Inbound => "inbound",
        EtwDirectionCategory::Outbound => "outbound",
        EtwDirectionCategory::Local => "local",
        EtwDirectionCategory::Unknown => "unknown",
    }
}

fn etw_byte_bucket(value: EtwByteCountBucket) -> &'static str {
    match value {
        EtwByteCountBucket::None => "none",
        EtwByteCountBucket::Tiny => "tiny",
        EtwByteCountBucket::Small => "small",
        EtwByteCountBucket::Medium => "medium",
        EtwByteCountBucket::Large => "large",
        EtwByteCountBucket::VeryLarge => "very_large",
    }
}

fn etw_owner_bucket(value: EtwOwnerPresenceCategory) -> &'static str {
    match value {
        EtwOwnerPresenceCategory::OwnerObservedNotRetained => "owner_observed_not_retained",
        EtwOwnerPresenceCategory::OwnerUnavailable => "owner_unavailable",
    }
}

fn etw_count_bucket(value: EtwCountBucket) -> &'static str {
    match value {
        EtwCountBucket::Zero => "zero",
        EtwCountBucket::One => "one",
        EtwCountBucket::Low => "low",
        EtwCountBucket::Medium => "medium",
        EtwCountBucket::High => "high",
    }
}

fn etw_missing_flag(value: &EtwMissingVisibilityFlag) -> String {
    match value {
        EtwMissingVisibilityFlag::SpecificProcessIdentityUnavailable => {
            "specific_process_identity_unavailable"
        }
        EtwMissingVisibilityFlag::ProcessNetworkAttributionUnavailable => {
            "process_network_attribution_unavailable"
        }
        EtwMissingVisibilityFlag::PacketPayloadUnavailable => "packet_visibility_unavailable",
        EtwMissingVisibilityFlag::CommandLineUnavailable => "command_visibility_unavailable",
        EtwMissingVisibilityFlag::FileRegistryUnavailable => "file_registry_visibility_unavailable",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        EtwAllowedSchemaId, EtwNormalizationPrivacySummary, NativeEndpointRangeBucket,
        NativeNetworkFreshness, NativeNetworkProviderCategory, NativeOwnerPresenceCategory,
        NetworkProviderKind, ETW_NORMALIZATION_SCHEMA_VERSION,
    };

    fn batch() -> NativeIpHelperMetadataBatch {
        NativeIpHelperMetadataBatch {
            batch_ref: "ip_helper_batch_ref".to_string(),
            provider_ref: "ip_helper_provider_ref".to_string(),
            provider_category: NativeNetworkProviderCategory::IpHelper,
            schema_version: sentinel_contracts::NATIVE_NETWORK_SCHEMA_VERSION,
            sampled_time_bucket: Timestamp::now(),
            provider_health: NativeNetworkProviderHealth::Available,
            rows_observed_bucket: "low".to_string(),
            rows_processed_bucket: "low".to_string(),
            rows_suppressed_bucket: "none".to_string(),
            rows_dropped_bucket: "none".to_string(),
            tcp_count_bucket: "low".to_string(),
            udp_count_bucket: "none".to_string(),
            category_count_bucket: "single".to_string(),
            categories: vec![sentinel_contracts::NativeIpHelperConnectionCategoryRecord {
                observation_ref: "ip_helper_observation_ref".to_string(),
                provider_category: NativeNetworkProviderCategory::IpHelper,
                transport_category: NativeNetworkTransportCategory::Tcp,
                connection_state_bucket: NativeConnectionStateBucket::Established,
                local_scope_category: NativeEndpointScopeCategory::Private,
                destination_scope_category: NativeEndpointScopeCategory::Public,
                local_endpoint_range_bucket: NativeEndpointRangeBucket::EphemeralRange,
                remote_endpoint_range_bucket: NativeEndpointRangeBucket::SystemRange,
                service_category_bucket: NativeConnectionServiceBucket::Web,
                local_remote_relation_category: NativeConnectionRelationCategory::LocalToPublic,
                owner_presence_category: NativeOwnerPresenceCategory::OwnerObservedNotRetained,
                count_bucket: "low".to_string(),
                change_bucket: "observed".to_string(),
                time_bucket: Timestamp::now(),
                confidence_hint: sentinel_contracts::QualityScore::new(0.7).expect("quality"),
                provider_health: NativeNetworkProviderHealth::Available,
                evidence_refs: Vec::new(),
                provenance_refs: vec!["ip_helper_test".to_string()],
                redaction_status: RedactionStatus::Redacted,
                missing_visibility_flags: vec![
                    "specific_process_identity_unavailable".to_string(),
                    "process_network_attribution_unavailable".to_string(),
                ],
            }],
            skipped_count_bucket: "none".to_string(),
            rejected_count_bucket: "none".to_string(),
            freshness: NativeNetworkFreshness::Fresh,
            provider_status_ref: "network_provider_ip_helper".to_string(),
            visibility_ref: "network_visibility_ref".to_string(),
            fact_refs: Vec::new(),
            audit_refs: vec!["audit_network_provider_execution_ref".to_string()],
            provenance_id: "ip_helper_servicehost_handoff".to_string(),
            redaction_status: RedactionStatus::Redacted,
            missing_visibility_flags: vec![
                "short_lived_network_event_visibility_unavailable".to_string(),
                "packet_visibility_unavailable".to_string(),
            ],
            degraded_reason: None,
            response_execution_allowed: false,
            automatic_llm_calls: false,
        }
    }

    fn etw_batch() -> EtwNormalizedNetworkBatch {
        EtwNormalizedNetworkBatch {
            batch_ref: "etw_normalization_batch_ref".to_string(),
            schema_version: ETW_NORMALIZATION_SCHEMA_VERSION,
            provider_kind: NetworkProviderKind::EtwNetwork,
            generated_at: Timestamp::now(),
            allowlist_ref: "etw_network_schema_allowlist_v1".to_string(),
            events_observed: 1,
            events_accepted: 1,
            events_deduplicated: 0,
            events_rejected: 0,
            events_dropped: 0,
            records: vec![EtwNormalizedNetworkRecord {
                record_ref: "etw_category_redacted_ref".to_string(),
                schema_id: EtwAllowedSchemaId::TcpConnectionLifecycleV1,
                event_family: EtwNetworkEventFamily::ConnectionLifecycle,
                transport_category: EtwTransportCategory::Tcp,
                activity_category: EtwNetworkActivityCategory::Connect,
                direction_category: EtwDirectionCategory::Outbound,
                local_scope_category: NativeEndpointScopeCategory::Private,
                destination_scope_category: NativeEndpointScopeCategory::Public,
                local_endpoint_range_bucket: NativeEndpointRangeBucket::EphemeralRange,
                remote_endpoint_range_bucket: NativeEndpointRangeBucket::SystemRange,
                byte_count_bucket: EtwByteCountBucket::Small,
                owner_presence_category: EtwOwnerPresenceCategory::OwnerObservedNotRetained,
                count_bucket: EtwCountBucket::One,
                provenance_refs: vec!["etw_bounded_category_normalization".to_string()],
                redaction_status: RedactionStatus::Redacted,
                missing_visibility_flags: vec![
                    EtwMissingVisibilityFlag::SpecificProcessIdentityUnavailable,
                    EtwMissingVisibilityFlag::ProcessNetworkAttributionUnavailable,
                    EtwMissingVisibilityFlag::PacketPayloadUnavailable,
                    EtwMissingVisibilityFlag::CommandLineUnavailable,
                    EtwMissingVisibilityFlag::FileRegistryUnavailable,
                ],
            }],
            privacy: EtwNormalizationPrivacySummary::default(),
            event_session_created: false,
            collection_started: false,
            eventbus_publication_count: 0,
            security_fact_count: 0,
            provenance_refs: vec!["etw_infrastructure_normalizer".to_string()],
            redaction_status: RedactionStatus::Redacted,
            degraded_reason: None,
        }
    }

    #[test]
    fn native_network_fact_plugin_emits_category_health_and_visibility_facts() {
        let facts = NativeNetworkFactPlugin::new()
            .process_batch(&batch())
            .expect("facts");

        assert_eq!(facts.len(), 3);
        assert!(facts.iter().all(|fact| {
            fact.layer == SecurityLayer::AuthorizedNativeNetwork
                && fact.process_category.is_none()
                && fact.parent_process_category.is_none()
                && fact.execution_context_category.is_none()
        }));
        assert!(facts
            .iter()
            .any(|fact| fact.category == NATIVE_NETWORK_FACT_CONTRACT));
        assert!(facts
            .iter()
            .any(|fact| fact.category == NATIVE_NETWORK_PROVIDER_HEALTH_FACT_CONTRACT));
        assert!(facts
            .iter()
            .any(|fact| fact.category == NATIVE_NETWORK_VISIBILITY_FACT_CONTRACT));
    }

    #[test]
    fn native_network_fact_plugin_does_not_emit_findings_or_response_claims() {
        let serialized = serde_json::to_string(
            &NativeNetworkFactPlugin::new()
                .process_batch(&batch())
                .expect("facts"),
        )
        .expect("facts json");

        for forbidden in [
            "security.finding",
            "compromise",
            "process_network_category_fact",
            "packet_bytes",
            "response.plan",
            "llm",
            "203.0.113.10",
            "49152",
            "pid",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(forbidden),
                "native network facts leaked forbidden marker {forbidden}: {serialized}"
            );
        }
    }

    #[test]
    fn native_network_fact_plugin_accepts_etw_normalized_batches() {
        let facts = NativeNetworkFactPlugin::new()
            .process_etw_batch(&etw_batch())
            .expect("etw facts");

        assert_eq!(facts.len(), 3);
        assert!(facts.iter().all(|fact| {
            fact.layer == SecurityLayer::AuthorizedNativeNetwork
                && fact.process_category.is_none()
                && fact.parent_process_category.is_none()
                && fact.execution_context_category.is_none()
        }));
        assert!(facts
            .iter()
            .any(|fact| fact.category == NATIVE_NETWORK_FACT_CONTRACT));
        assert!(facts
            .iter()
            .any(|fact| fact.category == NATIVE_ETW_NETWORK_PROVIDER_HEALTH_FACT_CONTRACT));
        assert!(facts
            .iter()
            .any(|fact| fact.category == NATIVE_ETW_NETWORK_VISIBILITY_FACT_CONTRACT));
        assert!(facts.iter().any(|fact| {
            fact.status_category.as_deref() == Some("short_lived_event_visibility_available")
        }));
    }

    #[test]
    fn etw_native_network_facts_do_not_expose_raw_values_or_claim_response() {
        let serialized = serde_json::to_string(
            &NativeNetworkFactPlugin::new()
                .process_etw_batch(&etw_batch())
                .expect("etw facts"),
        )
        .expect("facts json");

        for forbidden in [
            "security.finding",
            "incident",
            "response.plan",
            "llm",
            "process_network_category_fact",
            "packet_bytes",
            "packet_payload",
            "203.0.113.10",
            "10.0.0.10",
            "49152",
            "pid",
            "command_line",
            "token",
            "credential",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(forbidden),
                "etw facts leaked forbidden marker {forbidden}: {serialized}"
            );
        }
    }
}
