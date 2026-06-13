use crate::common::{
    DataSourceId, DeceptionEventId, DnsObservationId, EntityRef, EvidenceId, FindingId, FlowId,
    GraphHintId, HttpMetadataId, PacketRecordId, PrivacyClass, ProcessContextId, QualityScore,
    SaasCloudMetadataId, SessionId, Timestamp, TlsObservationId, TraceId,
};
use crate::graph::RedactionStatus;
use crate::identity::{AttributionConfidence, CollectionMode, VisibilityLevel};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpAddress(IpAddr);

impl IpAddress {
    pub fn new(value: IpAddr) -> Self {
        Self(value)
    }

    pub fn parse_str(value: &str) -> Result<Self, IpAddressParseError> {
        IpAddr::from_str(value)
            .map(Self)
            .map_err(|_| IpAddressParseError::new(value))
    }

    pub fn as_ip_addr(&self) -> IpAddr {
        self.0
    }

    pub fn version(&self) -> IpVersion {
        match self.0 {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        }
    }

    pub fn is_ipv4(&self) -> bool {
        matches!(self.0, IpAddr::V4(_))
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self.0, IpAddr::V6(_))
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<IpAddr> for IpAddress {
    fn from(value: IpAddr) -> Self {
        Self::new(value)
    }
}

impl FromStr for IpAddress {
    type Err = IpAddressParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_str(value)
    }
}

impl Serialize for IpAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IpAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse_str(&value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpAddressParseError {
    value: String,
}

impl IpAddressParseError {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for IpAddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IP address: {}", self.value)
    }
}

impl std::error::Error for IpAddressParseError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Quic,
    Other,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDirection {
    Inbound,
    Outbound,
    Lateral,
    Loopback,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSource {
    Windivert,
    Pktmon,
    RawSocket,
    ImportedLog,
    ExistingRecord,
    Mock,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableCaptureInputSourceType {
    ImportedHar,
    ImportedJsonlNetworkMetadata,
    ImportedWebAccessLog,
    ImportedAuthSecurityLog,
    ImportedSaasCloudMetadata,
    ImportedDeceptionEventLog,
    LocalProxyMetadata,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableCaptureRecordCounts {
    pub flow_records: u32,
    pub session_records: u32,
    pub dns_records: u32,
    pub tls_records: u32,
    pub http_metadata_records: u32,
    pub auth_metadata_records: u32,
    pub saas_cloud_metadata_records: u32,
    pub deception_event_records: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableCaptureProvenance {
    pub provenance_id: DataSourceId,
    pub source_type: PortableCaptureInputSourceType,
    pub record_counts: PortableCaptureRecordCounts,
    pub redaction_status: RedactionStatus,
}

impl PortableCaptureProvenance {
    pub fn new(
        source_type: PortableCaptureInputSourceType,
        record_counts: PortableCaptureRecordCounts,
        redaction_status: RedactionStatus,
    ) -> Self {
        Self {
            provenance_id: DataSourceId::new_v4(),
            source_type,
            record_counts,
            redaction_status,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableProviderCategory {
    Saas,
    Cloud,
    Cdn,
    ObjectStorage,
    TunnelProxy,
    Anonymizing,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableProviderRiskCategory {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableProviderConfidenceBucket {
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableApiMethodCategory {
    Read,
    Write,
    Delete,
    Admin,
    Auth,
    Other,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableStatusBucket {
    Success,
    Redirect,
    AuthError,
    NotFound,
    RateLimited,
    ClientError,
    ServerError,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableUploadDownloadRatioBucket {
    DownloadHeavy,
    Balanced,
    UploadHeavy,
    UploadBurst,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortableSaasCloudMetadata {
    pub saas_cloud_metadata_id: SaasCloudMetadataId,
    pub provenance_id: DataSourceId,
    pub provider_category: PortableProviderCategory,
    pub service_category: Option<String>,
    pub provider_risk_category: PortableProviderRiskCategory,
    pub provider_confidence: PortableProviderConfidenceBucket,
    pub endpoint_fingerprint: Option<String>,
    pub api_method_category: PortableApiMethodCategory,
    pub status_bucket: PortableStatusBucket,
    pub upload_download_ratio_bucket: PortableUploadDownloadRatioBucket,
    pub auth_result_category: Option<String>,
    pub identity_label_redacted: Option<String>,
    pub source_session_label: Option<String>,
    pub destination_category: Option<String>,
    pub time_bucket_start: Timestamp,
    pub redaction_status: RedactionStatus,
    pub evidence_refs: Vec<EvidenceId>,
    pub quality_score: QualityScore,
}

impl PortableSaasCloudMetadata {
    pub fn new(provider_category: PortableProviderCategory, time_bucket_start: Timestamp) -> Self {
        Self {
            saas_cloud_metadata_id: SaasCloudMetadataId::new_v4(),
            provenance_id: DataSourceId::new_v4(),
            provider_category,
            service_category: None,
            provider_risk_category: PortableProviderRiskCategory::Unknown,
            provider_confidence: PortableProviderConfidenceBucket::Unknown,
            endpoint_fingerprint: None,
            api_method_category: PortableApiMethodCategory::Unknown,
            status_bucket: PortableStatusBucket::Unknown,
            upload_download_ratio_bucket: PortableUploadDownloadRatioBucket::Unknown,
            auth_result_category: None,
            identity_label_redacted: None,
            source_session_label: None,
            destination_category: None,
            time_bucket_start,
            redaction_status: RedactionStatus::Redacted,
            evidence_refs: Vec::new(),
            quality_score: QualityScore::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableSaasCloudCategoryCount {
    pub category: String,
    pub count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableSaasCloudSummary {
    pub provenance_id: DataSourceId,
    pub metadata_record_count: u32,
    pub provider_category_counts: Vec<PortableSaasCloudCategoryCount>,
    pub provider_risk_counts: Vec<PortableSaasCloudCategoryCount>,
    pub unknown_provider_count: u32,
    pub degraded_visibility_flags: Vec<String>,
    pub finding_refs: Vec<FindingId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub graph_hint_refs: Vec<GraphHintId>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableDeceptionProtocolCategory {
    Http,
    Dns,
    Ssh,
    Smb,
    Rdp,
    Ftp,
    Telnet,
    Database,
    Ics,
    Other,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableDecoyInteractionCountBucket {
    Single,
    Low,
    Medium,
    High,
    Burst,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortableDeceptionEventMetadata {
    pub deception_event_id: DeceptionEventId,
    pub provenance_id: DataSourceId,
    pub decoy_sensor_ref: Option<String>,
    pub event_category: String,
    pub source_context_category: Option<String>,
    pub destination_service_category: Option<String>,
    pub interaction_count_bucket: PortableDecoyInteractionCountBucket,
    pub protocol_category: PortableDeceptionProtocolCategory,
    pub time_bucket_start: Timestamp,
    pub redaction_status: RedactionStatus,
    pub evidence_refs: Vec<EvidenceId>,
    pub quality_score: QualityScore,
}

impl PortableDeceptionEventMetadata {
    pub fn new(
        event_category: impl Into<String>,
        protocol_category: PortableDeceptionProtocolCategory,
        time_bucket_start: Timestamp,
    ) -> Self {
        Self {
            deception_event_id: DeceptionEventId::new_v4(),
            provenance_id: DataSourceId::new_v4(),
            decoy_sensor_ref: None,
            event_category: event_category.into(),
            source_context_category: None,
            destination_service_category: None,
            interaction_count_bucket: PortableDecoyInteractionCountBucket::Unknown,
            protocol_category,
            time_bucket_start,
            redaction_status: RedactionStatus::Redacted,
            evidence_refs: Vec::new(),
            quality_score: QualityScore::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableDeceptionCategoryCount {
    pub category: String,
    pub count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableDeceptionSummary {
    pub provenance_id: DataSourceId,
    pub event_record_count: u32,
    pub decoy_sensor_count: u32,
    pub event_category_counts: Vec<PortableDeceptionCategoryCount>,
    pub protocol_category_counts: Vec<PortableDeceptionCategoryCount>,
    pub degraded_visibility_flags: Vec<String>,
    pub finding_refs: Vec<FindingId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub graph_hint_refs: Vec<GraphHintId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpFlag {
    Syn,
    Ack,
    Fin,
    Rst,
    Psh,
    Urg,
    Ece,
    Cwr,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketFlags {
    pub tcp_flags: Vec<TcpFlag>,
    pub fragmented: bool,
    pub malformed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PacketRecord {
    pub packet_record_id: PacketRecordId,
    pub timestamp: Timestamp,
    pub direction: NetworkDirection,
    pub interface_id: Option<String>,
    pub protocol: TransportProtocol,
    pub src_ip: IpAddress,
    pub src_port: Option<u16>,
    pub dst_ip: IpAddress,
    pub dst_port: Option<u16>,
    pub length_bytes: u32,
    pub flags: PacketFlags,
    pub capture_source: CaptureSource,
    pub collection_mode: CollectionMode,
    pub visibility_level: VisibilityLevel,
    pub quality_score: QualityScore,
    pub trace_id: Option<TraceId>,
}

impl PacketRecord {
    pub fn new(
        protocol: TransportProtocol,
        direction: NetworkDirection,
        src_ip: IpAddress,
        dst_ip: IpAddress,
        length_bytes: u32,
    ) -> Self {
        Self {
            packet_record_id: PacketRecordId::new_v4(),
            timestamp: Timestamp::now(),
            direction,
            interface_id: None,
            protocol,
            src_ip,
            src_port: None,
            dst_ip,
            dst_port: None,
            length_bytes,
            flags: PacketFlags::default(),
            capture_source: CaptureSource::Unknown,
            collection_mode: CollectionMode::Normal,
            visibility_level: VisibilityLevel::MetadataOnly,
            quality_score: QualityScore::default(),
            trace_id: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlowRecord {
    pub flow_id: FlowId,
    pub src_ip: IpAddress,
    pub src_port: u16,
    pub dst_ip: IpAddress,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
    pub direction: NetworkDirection,
    pub start_time: Timestamp,
    pub end_time: Option<Timestamp>,
    pub duration_millis: Option<u64>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub process_ref: Option<ProcessContextId>,
    pub asset_ref: Option<EntityRef>,
    pub session_ref: Option<SessionId>,
    pub attribution_confidence: AttributionConfidence,
    pub quality_score: QualityScore,
    pub trace_id: Option<TraceId>,
}

impl FlowRecord {
    pub fn new(
        src_ip: IpAddress,
        src_port: u16,
        dst_ip: IpAddress,
        dst_port: u16,
        protocol: TransportProtocol,
        direction: NetworkDirection,
    ) -> Self {
        Self {
            flow_id: FlowId::new_v4(),
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
            direction,
            start_time: Timestamp::now(),
            end_time: None,
            duration_millis: None,
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            process_ref: None,
            asset_ref: None,
            session_ref: None,
            attribution_confidence: AttributionConfidence::Unknown,
            quality_score: QualityScore::default(),
            trace_id: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: SessionId,
    pub flow_refs: Vec<FlowId>,
    pub local_ip: IpAddress,
    pub local_port: u16,
    pub remote_ip: IpAddress,
    pub remote_port: u16,
    pub protocol: TransportProtocol,
    pub direction: NetworkDirection,
    pub start_time: Timestamp,
    pub end_time: Option<Timestamp>,
    pub duration_millis: Option<u64>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub process_ref: Option<ProcessContextId>,
    pub attribution_confidence: AttributionConfidence,
    pub quality_score: QualityScore,
}

impl SessionRecord {
    pub fn new(
        local_ip: IpAddress,
        local_port: u16,
        remote_ip: IpAddress,
        remote_port: u16,
        protocol: TransportProtocol,
        direction: NetworkDirection,
    ) -> Self {
        Self {
            session_id: SessionId::new_v4(),
            flow_refs: Vec::new(),
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol,
            direction,
            start_time: Timestamp::now(),
            end_time: None,
            duration_millis: None,
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            process_ref: None,
            attribution_confidence: AttributionConfidence::Unknown,
            quality_score: QualityScore::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
pub enum DnsAnswer {
    Ip {
        address: IpAddress,
        ttl_seconds: Option<u32>,
    },
    Cname {
        name_protected: String,
        ttl_seconds: Option<u32>,
    },
    Other {
        summary_protected: String,
        ttl_seconds: Option<u32>,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsFeatures {
    pub query_length: u16,
    pub label_count: u16,
    pub subdomain_depth: u16,
    pub character_entropy: Option<f32>,
    pub answer_count: u16,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DnsObservation {
    pub dns_observation_id: DnsObservationId,
    pub flow_ref: Option<FlowId>,
    pub query_name_protected: String,
    pub query_type: String,
    pub response_code: Option<String>,
    pub resolver_ip: IpAddress,
    pub client_ip: IpAddress,
    pub timestamp: Timestamp,
    pub answers: Vec<DnsAnswer>,
    pub cname_chain_protected: Vec<String>,
    pub features: DnsFeatures,
    pub process_ref: Option<ProcessContextId>,
    pub asset_ref: Option<EntityRef>,
    pub privacy_class: PrivacyClass,
    pub quality_score: QualityScore,
}

impl DnsObservation {
    pub fn new(
        query_name_protected: impl Into<String>,
        query_type: impl Into<String>,
        resolver_ip: IpAddress,
        client_ip: IpAddress,
    ) -> Result<Self, NetworkContractError> {
        Ok(Self {
            dns_observation_id: DnsObservationId::new_v4(),
            flow_ref: None,
            query_name_protected: require_non_empty(
                "query_name_protected",
                query_name_protected.into(),
            )?,
            query_type: require_non_empty("query_type", query_type.into())?,
            response_code: None,
            resolver_ip,
            client_ip,
            timestamp: Timestamp::now(),
            answers: Vec::new(),
            cname_chain_protected: Vec::new(),
            features: DnsFeatures::default(),
            process_ref: None,
            asset_ref: None,
            privacy_class: PrivacyClass::default(),
            quality_score: QualityScore::default(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TlsObservation {
    pub tls_observation_id: TlsObservationId,
    pub flow_ref: Option<FlowId>,
    pub timestamp: Timestamp,
    pub sni_protected: Option<String>,
    pub alpn: Vec<String>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub ja4s: Option<String>,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub extension_summary_protected: Option<String>,
    pub certificate_fingerprint: Option<String>,
    pub issuer_summary_protected: Option<String>,
    pub san_summary_protected: Option<String>,
    pub valid_not_before: Option<Timestamp>,
    pub valid_not_after: Option<Timestamp>,
    pub src_entity: Option<EntityRef>,
    pub dst_entity: Option<EntityRef>,
    pub process_ref: Option<ProcessContextId>,
    pub privacy_class: PrivacyClass,
    pub quality_score: QualityScore,
}

impl TlsObservation {
    pub fn new() -> Self {
        Self {
            tls_observation_id: TlsObservationId::new_v4(),
            flow_ref: None,
            timestamp: Timestamp::now(),
            sni_protected: None,
            alpn: Vec::new(),
            ja3: None,
            ja4: None,
            ja4s: None,
            tls_version: None,
            cipher_suite: None,
            extension_summary_protected: None,
            certificate_fingerprint: None,
            issuer_summary_protected: None,
            san_summary_protected: None,
            valid_not_before: None,
            valid_not_after: None,
            src_entity: None,
            dst_entity: None,
            process_ref: None,
            privacy_class: PrivacyClass::default(),
            quality_score: QualityScore::default(),
        }
    }
}

impl Default for TlsObservation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    Trace,
    Connect,
    Other,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HttpMetadata {
    pub http_metadata_id: HttpMetadataId,
    pub flow_ref: Option<FlowId>,
    pub timestamp: Timestamp,
    pub method: HttpMethod,
    pub scheme: Option<String>,
    pub host_protected: Option<String>,
    pub path_template_protected: Option<String>,
    pub endpoint_fingerprint: Option<String>,
    pub status_code: Option<u16>,
    pub status_family: Option<String>,
    pub result_label: Option<String>,
    pub request_size_bytes: Option<u64>,
    pub response_size_bytes: Option<u64>,
    pub request_content_length_bytes: Option<u64>,
    pub response_content_length_bytes: Option<u64>,
    pub upload_download_ratio: Option<f32>,
    pub content_type: Option<String>,
    pub user_agent_family: Option<String>,
    pub api_hint: Option<String>,
    pub waf_action: Option<String>,
    pub waf_rule_id: Option<String>,
    pub waf_attack_class: Option<String>,
    pub sensitive_hint: Option<String>,
    pub visible_plaintext: bool,
    pub process_ref: Option<ProcessContextId>,
    pub privacy_class: PrivacyClass,
    pub quality_score: QualityScore,
}

impl HttpMetadata {
    pub fn new(method: HttpMethod) -> Self {
        Self {
            http_metadata_id: HttpMetadataId::new_v4(),
            flow_ref: None,
            timestamp: Timestamp::now(),
            method,
            scheme: None,
            host_protected: None,
            path_template_protected: None,
            endpoint_fingerprint: None,
            status_code: None,
            status_family: None,
            result_label: None,
            request_size_bytes: None,
            response_size_bytes: None,
            request_content_length_bytes: None,
            response_content_length_bytes: None,
            upload_download_ratio: None,
            content_type: None,
            user_agent_family: None,
            api_hint: None,
            waf_action: None,
            waf_rule_id: None,
            waf_attack_class: None,
            sensitive_hint: None,
            visible_plaintext: true,
            process_ref: None,
            privacy_class: PrivacyClass::default(),
            quality_score: QualityScore::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkContractError {
    EmptyField(&'static str),
}

impl fmt::Display for NetworkContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
        }
    }
}

impl std::error::Error for NetworkContractError {}

fn require_non_empty(field: &'static str, value: String) -> Result<String, NetworkContractError> {
    if value.trim().is_empty() {
        return Err(NetworkContractError::EmptyField(field));
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ip_address_serializes_as_normalized_string() {
        let ip =
            IpAddress::parse_str("2001:0db8:0000:0000:0000:0000:0000:0001").expect("valid IPv6");
        let value = serde_json::to_value(ip).expect("serialize IP");

        assert_eq!(value, json!("2001:db8::1"));
    }

    #[test]
    fn ip_address_rejects_invalid_values() {
        let error = IpAddress::parse_str("not-an-ip").expect_err("invalid IP rejected");

        assert_eq!(error.value(), "not-an-ip");
    }

    #[test]
    fn http_metadata_serializes_metadata_only() {
        let value = serde_json::to_string(&HttpMetadata::new(HttpMethod::Get))
            .expect("serialize HTTP metadata");

        assert!(!value.contains("authorization"));
        assert!(!value.contains("cookie"));
        assert!(!value.contains("credential"));
        assert!(!value.contains("api_key"));
        assert!(!value.contains("payload"));
    }

    #[test]
    fn portable_capture_provenance_stores_only_safe_summary_fields() {
        let provenance = PortableCaptureProvenance::new(
            PortableCaptureInputSourceType::ImportedHar,
            PortableCaptureRecordCounts {
                flow_records: 2,
                session_records: 2,
                dns_records: 0,
                tls_records: 2,
                http_metadata_records: 2,
                auth_metadata_records: 0,
                saas_cloud_metadata_records: 0,
                deception_event_records: 0,
            },
            RedactionStatus::Redacted,
        );
        let value = serde_json::to_string(&provenance).expect("serialize provenance");

        assert!(value.contains("imported_har"));
        assert!(value.contains("flow_records"));
        assert!(value.contains("redacted"));
        assert!(!value.contains("source_path"));
        assert!(!value.contains("raw_packet"));
        assert!(!value.contains("payload"));
    }

    #[test]
    fn portable_capture_provenance_supports_imported_web_access_logs() {
        let provenance = PortableCaptureProvenance::new(
            PortableCaptureInputSourceType::ImportedWebAccessLog,
            PortableCaptureRecordCounts {
                flow_records: 3,
                session_records: 2,
                dns_records: 0,
                tls_records: 0,
                http_metadata_records: 3,
                auth_metadata_records: 0,
                saas_cloud_metadata_records: 0,
                deception_event_records: 0,
            },
            RedactionStatus::Redacted,
        );

        let value = serde_json::to_string(&provenance).expect("serialize provenance");

        assert!(value.contains("imported_web_access_log"));
        assert!(!value.contains("authorization"));
        assert!(!value.contains("payload"));
    }

    #[test]
    fn portable_capture_provenance_supports_auth_security_logs() {
        let provenance = PortableCaptureProvenance::new(
            PortableCaptureInputSourceType::ImportedAuthSecurityLog,
            PortableCaptureRecordCounts {
                flow_records: 0,
                session_records: 0,
                dns_records: 0,
                tls_records: 0,
                http_metadata_records: 0,
                auth_metadata_records: 4,
                saas_cloud_metadata_records: 0,
                deception_event_records: 0,
            },
            RedactionStatus::Hashed,
        );

        let value = serde_json::to_string(&provenance).expect("serialize provenance");

        assert!(value.contains("imported_auth_security_log"));
        assert!(value.contains("auth_metadata_records"));
        assert!(value.contains("hashed"));
        assert!(!value.contains("username"));
        assert!(!value.contains("payload"));
    }

    #[test]
    fn portable_capture_provenance_supports_saas_cloud_metadata() {
        let provenance = PortableCaptureProvenance::new(
            PortableCaptureInputSourceType::ImportedSaasCloudMetadata,
            PortableCaptureRecordCounts {
                flow_records: 0,
                session_records: 0,
                dns_records: 0,
                tls_records: 0,
                http_metadata_records: 0,
                auth_metadata_records: 0,
                saas_cloud_metadata_records: 3,
                deception_event_records: 0,
            },
            RedactionStatus::Hashed,
        );

        let value = serde_json::to_string(&provenance).expect("serialize provenance");

        assert!(value.contains("imported_saas_cloud_metadata"));
        assert!(value.contains("saas_cloud_metadata_records"));
        assert!(!value.contains("tenant"));
        assert!(!value.contains("token"));
    }

    #[test]
    fn portable_capture_provenance_supports_deception_event_logs() {
        let provenance = PortableCaptureProvenance::new(
            PortableCaptureInputSourceType::ImportedDeceptionEventLog,
            PortableCaptureRecordCounts {
                flow_records: 0,
                session_records: 0,
                dns_records: 0,
                tls_records: 0,
                http_metadata_records: 0,
                auth_metadata_records: 0,
                saas_cloud_metadata_records: 0,
                deception_event_records: 2,
            },
            RedactionStatus::Redacted,
        );

        let value = serde_json::to_string(&provenance).expect("serialize provenance");

        assert!(value.contains("imported_deception_event_log"));
        assert!(value.contains("deception_event_records"));
        assert!(!value.contains("credential"));
        assert!(!value.contains("payload"));
    }

    #[test]
    fn portable_saas_cloud_metadata_is_bounded_and_redacted() {
        let mut metadata = PortableSaasCloudMetadata::new(
            PortableProviderCategory::ObjectStorage,
            Timestamp::now(),
        );
        metadata.provider_confidence = PortableProviderConfidenceBucket::Medium;
        metadata.endpoint_fingerprint = Some("endpoint#abc123".to_string());
        metadata.identity_label_redacted = Some("identity#def456".to_string());
        metadata.source_session_label = Some("session#123456".to_string());
        metadata.upload_download_ratio_bucket = PortableUploadDownloadRatioBucket::UploadBurst;

        let value = serde_json::to_string(&metadata).expect("serialize saas metadata");

        assert!(value.contains("object_storage"));
        assert!(value.contains("endpoint#"));
        assert!(!value.contains("alice@example.test"));
        assert!(!value.contains("tenant"));
        assert!(!value.contains("authorization"));
        assert!(!value.contains("payload"));
    }

    #[test]
    fn portable_deception_event_metadata_is_bounded_and_redacted() {
        let mut metadata = PortableDeceptionEventMetadata::new(
            "probe",
            PortableDeceptionProtocolCategory::Ssh,
            Timestamp::now(),
        );
        metadata.decoy_sensor_ref = Some("sensor#abc123".to_string());
        metadata.source_context_category = Some("external".to_string());
        metadata.destination_service_category = Some("ssh".to_string());
        metadata.interaction_count_bucket = PortableDecoyInteractionCountBucket::High;

        let value = serde_json::to_string(&metadata).expect("serialize deception metadata");

        assert!(value.contains("sensor#"));
        assert!(value.contains("probe"));
        assert!(value.contains("ssh"));
        assert!(!value.contains("alice@example.test"));
        assert!(!value.contains("credential"));
        assert!(!value.contains("payload"));
        assert!(!value.contains("source_ip"));
    }
}
