use crate::common::{
    DataSourceId, DeceptionEventId, DnsObservationId, EntityRef, EvidenceId, FindingId, FlowId,
    GraphHintId, HttpMetadataId, PacketRecordId, PrivacyClass, ProcessContextId, QualityScore,
    SaasCloudMetadataId, SdnControlPlaneMetadataId, SessionId, Timestamp, TlsObservationId,
    TraceId,
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
    ImportedDnsResolverLog,
    ImportedApiGatewayLog,
    ImportedWafLog,
    ImportedCdnEdgeLog,
    ImportedSdnControlPlaneLog,
    ImportedObjectStorageAuditLog,
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
    pub sdn_control_plane_records: u32,
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

pub const MAX_OBJECT_STORAGE_AUDIT_PAGES_PER_TICK: u8 = 8;
pub const MAX_OBJECT_STORAGE_AUDIT_RECORDS_PER_PAGE: u16 = 256;
pub const DEFAULT_OBJECT_STORAGE_AUDIT_TIMEOUT_MILLIS: u64 = 10_000;
pub const DEFAULT_OBJECT_STORAGE_AUDIT_RATE_LIMIT_PER_MINUTE: u16 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectStorageAuditProviderKind {
    AwsCloudTrail,
    AzureActivity,
    GoogleCloudAudit,
    CloudflareR2,
    Minio,
    Generic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectStorageAuditEndpointKind {
    CloudTrailLookupEvents,
    AzureActivityLogs,
    GoogleCloudAuditLogs,
    CloudflareR2Audit,
    MinioAudit,
    GenericJsonPage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectStorageAuditAuthMode {
    AwsSigV4Session,
    BearerTokenSession,
    AccessKeySession,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectStorageAuditClientState {
    Ready,
    MissingCredentials,
    PageFetched,
    RateLimited,
    RetryScheduled,
    Degraded,
    Revoked,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectStorageAuditCheckpointState {
    Empty,
    CursorHashPresent,
    EndReached,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectStorageAuditCredentialRef {
    pub session_ref: String,
    pub auth_mode: ObjectStorageAuditAuthMode,
    pub expires_at: Option<Timestamp>,
}

impl ObjectStorageAuditCredentialRef {
    pub fn new(
        session_ref: impl Into<String>,
        auth_mode: ObjectStorageAuditAuthMode,
        expires_at: Option<Timestamp>,
    ) -> Self {
        Self {
            session_ref: session_ref.into(),
            auth_mode,
            expires_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectStorageAuditClientConfig {
    pub provider_kind: ObjectStorageAuditProviderKind,
    pub endpoint_kind: ObjectStorageAuditEndpointKind,
    pub region_bucket: Option<String>,
    pub max_pages_per_tick: u8,
    pub max_records_per_page: u16,
    pub timeout_millis: u64,
    pub rate_limit_per_minute: u16,
}

impl ObjectStorageAuditClientConfig {
    pub fn new(
        provider_kind: ObjectStorageAuditProviderKind,
        endpoint_kind: ObjectStorageAuditEndpointKind,
    ) -> Self {
        Self {
            provider_kind,
            endpoint_kind,
            region_bucket: None,
            max_pages_per_tick: 1,
            max_records_per_page: 100,
            timeout_millis: DEFAULT_OBJECT_STORAGE_AUDIT_TIMEOUT_MILLIS,
            rate_limit_per_minute: DEFAULT_OBJECT_STORAGE_AUDIT_RATE_LIMIT_PER_MINUTE,
        }
    }

    pub fn bounded_max_pages_per_tick(&self) -> u8 {
        self.max_pages_per_tick
            .clamp(1, MAX_OBJECT_STORAGE_AUDIT_PAGES_PER_TICK)
    }

    pub fn bounded_max_records_per_page(&self) -> u16 {
        self.max_records_per_page
            .clamp(1, MAX_OBJECT_STORAGE_AUDIT_RECORDS_PER_PAGE)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectStorageAuditPageCursor {
    pub safe_cursor_bucket: String,
    pub next_page_token_hash: Option<String>,
    pub checkpoint_state: ObjectStorageAuditCheckpointState,
    pub updated_at: Timestamp,
}

impl ObjectStorageAuditPageCursor {
    pub fn empty(updated_at: Timestamp) -> Self {
        Self {
            safe_cursor_bucket: "not_started".to_string(),
            next_page_token_hash: None,
            checkpoint_state: ObjectStorageAuditCheckpointState::Empty,
            updated_at,
        }
    }

    pub fn from_safe_checkpoint(
        safe_cursor_bucket: impl Into<String>,
        next_page_token_hash: Option<String>,
        updated_at: Timestamp,
    ) -> Self {
        let checkpoint_state = if next_page_token_hash.is_some() {
            ObjectStorageAuditCheckpointState::CursorHashPresent
        } else {
            ObjectStorageAuditCheckpointState::EndReached
        };
        Self {
            safe_cursor_bucket: safe_cursor_bucket.into(),
            next_page_token_hash,
            checkpoint_state,
            updated_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectStorageAuditPollRequest {
    pub config: ObjectStorageAuditClientConfig,
    pub credential_ref: Option<ObjectStorageAuditCredentialRef>,
    pub cursor: ObjectStorageAuditPageCursor,
}

impl ObjectStorageAuditPollRequest {
    pub fn new(
        config: ObjectStorageAuditClientConfig,
        credential_ref: Option<ObjectStorageAuditCredentialRef>,
        cursor: ObjectStorageAuditPageCursor,
    ) -> Self {
        Self {
            config,
            credential_ref,
            cursor,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObjectStorageAuditPollOutcome {
    pub client_state: ObjectStorageAuditClientState,
    pub metadata: Vec<PortableSaasCloudMetadata>,
    pub cursor: ObjectStorageAuditPageCursor,
    pub requested_page_count: u8,
    pub accepted_record_count: u16,
    pub skipped_record_count: u16,
    pub retry_after_bucket: Option<String>,
    pub degraded_reasons: Vec<String>,
}

impl ObjectStorageAuditPollOutcome {
    pub fn empty(
        client_state: ObjectStorageAuditClientState,
        cursor: ObjectStorageAuditPageCursor,
    ) -> Self {
        Self {
            client_state,
            metadata: Vec::new(),
            cursor,
            requested_page_count: 0,
            accepted_record_count: 0,
            skipped_record_count: 0,
            retry_after_bucket: None,
            degraded_reasons: Vec::new(),
        }
    }
}

pub const MAX_CDN_EDGE_PAGES_PER_TICK: u8 = 8;
pub const MAX_CDN_EDGE_RECORDS_PER_PAGE: u16 = 512;
pub const DEFAULT_CDN_EDGE_TIMEOUT_MILLIS: u64 = 10_000;
pub const DEFAULT_CDN_EDGE_RATE_LIMIT_PER_MINUTE: u16 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CdnEdgeProviderKind {
    CloudflareHttp,
    CloudFront,
    AzureFrontDoor,
    Fastly,
    Akamai,
    Generic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CdnEdgeEndpointKind {
    CloudflareHttpRequests,
    CloudFrontStandardLogs,
    AzureFrontDoorAccessLogs,
    FastlyLogInsights,
    AkamaiDataStream,
    GenericJsonPage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CdnEdgeAuthMode {
    BearerTokenSession,
    AwsSigV4Session,
    SharedKeySession,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CdnEdgeClientState {
    Ready,
    MissingCredentials,
    PageFetched,
    RateLimited,
    RetryScheduled,
    Degraded,
    Revoked,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CdnEdgeCheckpointState {
    Empty,
    CursorHashPresent,
    EndReached,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnEdgeCredentialRef {
    pub session_ref: String,
    pub auth_mode: CdnEdgeAuthMode,
    pub expires_at: Option<Timestamp>,
}

impl CdnEdgeCredentialRef {
    pub fn new(
        session_ref: impl Into<String>,
        auth_mode: CdnEdgeAuthMode,
        expires_at: Option<Timestamp>,
    ) -> Self {
        Self {
            session_ref: session_ref.into(),
            auth_mode,
            expires_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnEdgeClientConfig {
    pub provider_kind: CdnEdgeProviderKind,
    pub endpoint_kind: CdnEdgeEndpointKind,
    pub region_bucket: Option<String>,
    pub dataset_bucket: Option<String>,
    pub max_pages_per_tick: u8,
    pub max_records_per_page: u16,
    pub timeout_millis: u64,
    pub rate_limit_per_minute: u16,
}

impl CdnEdgeClientConfig {
    pub fn new(provider_kind: CdnEdgeProviderKind, endpoint_kind: CdnEdgeEndpointKind) -> Self {
        Self {
            provider_kind,
            endpoint_kind,
            region_bucket: None,
            dataset_bucket: None,
            max_pages_per_tick: 1,
            max_records_per_page: 100,
            timeout_millis: DEFAULT_CDN_EDGE_TIMEOUT_MILLIS,
            rate_limit_per_minute: DEFAULT_CDN_EDGE_RATE_LIMIT_PER_MINUTE,
        }
    }

    pub fn bounded_max_pages_per_tick(&self) -> u8 {
        self.max_pages_per_tick
            .clamp(1, MAX_CDN_EDGE_PAGES_PER_TICK)
    }

    pub fn bounded_max_records_per_page(&self) -> u16 {
        self.max_records_per_page
            .clamp(1, MAX_CDN_EDGE_RECORDS_PER_PAGE)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnEdgePageCursor {
    pub safe_cursor_bucket: String,
    pub next_page_token_hash: Option<String>,
    pub checkpoint_state: CdnEdgeCheckpointState,
    pub updated_at: Timestamp,
}

impl CdnEdgePageCursor {
    pub fn empty(updated_at: Timestamp) -> Self {
        Self {
            safe_cursor_bucket: "not_started".to_string(),
            next_page_token_hash: None,
            checkpoint_state: CdnEdgeCheckpointState::Empty,
            updated_at,
        }
    }

    pub fn from_safe_checkpoint(
        safe_cursor_bucket: impl Into<String>,
        next_page_token_hash: Option<String>,
        updated_at: Timestamp,
    ) -> Self {
        let checkpoint_state = if next_page_token_hash.is_some() {
            CdnEdgeCheckpointState::CursorHashPresent
        } else {
            CdnEdgeCheckpointState::EndReached
        };
        Self {
            safe_cursor_bucket: safe_cursor_bucket.into(),
            next_page_token_hash,
            checkpoint_state,
            updated_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnEdgePollRequest {
    pub config: CdnEdgeClientConfig,
    pub credential_ref: Option<CdnEdgeCredentialRef>,
    pub cursor: CdnEdgePageCursor,
}

impl CdnEdgePollRequest {
    pub fn new(
        config: CdnEdgeClientConfig,
        credential_ref: Option<CdnEdgeCredentialRef>,
        cursor: CdnEdgePageCursor,
    ) -> Self {
        Self {
            config,
            credential_ref,
            cursor,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CdnEdgePollOutcome {
    pub client_state: CdnEdgeClientState,
    pub http_metadata: Vec<HttpMetadata>,
    pub provider_metadata: Vec<PortableSaasCloudMetadata>,
    pub cursor: CdnEdgePageCursor,
    pub requested_page_count: u8,
    pub accepted_record_count: u16,
    pub skipped_record_count: u16,
    pub retry_after_bucket: Option<String>,
    pub degraded_reasons: Vec<String>,
}

impl CdnEdgePollOutcome {
    pub fn empty(client_state: CdnEdgeClientState, cursor: CdnEdgePageCursor) -> Self {
        Self {
            client_state,
            http_metadata: Vec::new(),
            provider_metadata: Vec::new(),
            cursor,
            requested_page_count: 0,
            accepted_record_count: 0,
            skipped_record_count: 0,
            retry_after_bucket: None,
            degraded_reasons: Vec::new(),
        }
    }
}

pub const MAX_API_GATEWAY_PAGES_PER_TICK: u8 = 8;
pub const MAX_API_GATEWAY_RECORDS_PER_PAGE: u16 = 512;
pub const DEFAULT_API_GATEWAY_TIMEOUT_MILLIS: u64 = 10_000;
pub const DEFAULT_API_GATEWAY_RATE_LIMIT_PER_MINUTE: u16 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiGatewayProviderKind {
    AwsApiGateway,
    AzureApim,
    Kong,
    Envoy,
    Generic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiGatewayEndpointKind {
    AwsCloudWatchLogEvents,
    AzureApimGatewayLogs,
    KongAdminApiRequests,
    EnvoyAdminAccessLogs,
    GenericJsonPage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiGatewayAuthMode {
    AwsSigV4Session,
    BearerTokenSession,
    ApiKeySession,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiGatewayClientState {
    Ready,
    MissingCredentials,
    PageFetched,
    RateLimited,
    RetryScheduled,
    Degraded,
    Revoked,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiGatewayCheckpointState {
    Empty,
    CursorHashPresent,
    EndReached,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiGatewayCredentialRef {
    pub session_ref: String,
    pub auth_mode: ApiGatewayAuthMode,
    pub expires_at: Option<Timestamp>,
}

impl ApiGatewayCredentialRef {
    pub fn new(
        session_ref: impl Into<String>,
        auth_mode: ApiGatewayAuthMode,
        expires_at: Option<Timestamp>,
    ) -> Self {
        Self {
            session_ref: session_ref.into(),
            auth_mode,
            expires_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiGatewayClientConfig {
    pub provider_kind: ApiGatewayProviderKind,
    pub endpoint_kind: ApiGatewayEndpointKind,
    pub region_bucket: Option<String>,
    pub workspace_bucket: Option<String>,
    pub max_pages_per_tick: u8,
    pub max_records_per_page: u16,
    pub timeout_millis: u64,
    pub rate_limit_per_minute: u16,
}

impl ApiGatewayClientConfig {
    pub fn new(
        provider_kind: ApiGatewayProviderKind,
        endpoint_kind: ApiGatewayEndpointKind,
    ) -> Self {
        Self {
            provider_kind,
            endpoint_kind,
            region_bucket: None,
            workspace_bucket: None,
            max_pages_per_tick: 1,
            max_records_per_page: 100,
            timeout_millis: DEFAULT_API_GATEWAY_TIMEOUT_MILLIS,
            rate_limit_per_minute: DEFAULT_API_GATEWAY_RATE_LIMIT_PER_MINUTE,
        }
    }

    pub fn bounded_max_pages_per_tick(&self) -> u8 {
        self.max_pages_per_tick
            .clamp(1, MAX_API_GATEWAY_PAGES_PER_TICK)
    }

    pub fn bounded_max_records_per_page(&self) -> u16 {
        self.max_records_per_page
            .clamp(1, MAX_API_GATEWAY_RECORDS_PER_PAGE)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiGatewayPageCursor {
    pub safe_cursor_bucket: String,
    pub next_page_token_hash: Option<String>,
    pub checkpoint_state: ApiGatewayCheckpointState,
    pub updated_at: Timestamp,
}

impl ApiGatewayPageCursor {
    pub fn empty(updated_at: Timestamp) -> Self {
        Self {
            safe_cursor_bucket: "not_started".to_string(),
            next_page_token_hash: None,
            checkpoint_state: ApiGatewayCheckpointState::Empty,
            updated_at,
        }
    }

    pub fn from_safe_checkpoint(
        safe_cursor_bucket: impl Into<String>,
        next_page_token_hash: Option<String>,
        updated_at: Timestamp,
    ) -> Self {
        let checkpoint_state = if next_page_token_hash.is_some() {
            ApiGatewayCheckpointState::CursorHashPresent
        } else {
            ApiGatewayCheckpointState::EndReached
        };
        Self {
            safe_cursor_bucket: safe_cursor_bucket.into(),
            next_page_token_hash,
            checkpoint_state,
            updated_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiGatewayPollRequest {
    pub config: ApiGatewayClientConfig,
    pub credential_ref: Option<ApiGatewayCredentialRef>,
    pub cursor: ApiGatewayPageCursor,
}

impl ApiGatewayPollRequest {
    pub fn new(
        config: ApiGatewayClientConfig,
        credential_ref: Option<ApiGatewayCredentialRef>,
        cursor: ApiGatewayPageCursor,
    ) -> Self {
        Self {
            config,
            credential_ref,
            cursor,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApiGatewayPollOutcome {
    pub client_state: ApiGatewayClientState,
    pub http_metadata: Vec<HttpMetadata>,
    pub cursor: ApiGatewayPageCursor,
    pub requested_page_count: u8,
    pub accepted_record_count: u16,
    pub skipped_record_count: u16,
    pub retry_after_bucket: Option<String>,
    pub degraded_reasons: Vec<String>,
}

impl ApiGatewayPollOutcome {
    pub fn empty(client_state: ApiGatewayClientState, cursor: ApiGatewayPageCursor) -> Self {
        Self {
            client_state,
            http_metadata: Vec::new(),
            cursor,
            requested_page_count: 0,
            accepted_record_count: 0,
            skipped_record_count: 0,
            retry_after_bucket: None,
            degraded_reasons: Vec::new(),
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableSdnControllerCategory {
    OpenFlow,
    Ovsdb,
    Onos,
    OpenDaylight,
    SdWan,
    CloudNetworkController,
    KubernetesCni,
    GenericController,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableSdnControlPlaneEventCategory {
    TopologyChange,
    RouteChange,
    PolicyChange,
    AclChange,
    ControllerHealth,
    FlowRuleChange,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableSdnImpactScopeBucket {
    SingleSegment,
    MultipleSegments,
    Edge,
    Datacenter,
    Global,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableSdnReliabilityBucket {
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortableSdnControlPlaneMetadata {
    pub sdn_control_plane_metadata_id: SdnControlPlaneMetadataId,
    pub provenance_id: DataSourceId,
    pub controller_category: PortableSdnControllerCategory,
    pub event_category: PortableSdnControlPlaneEventCategory,
    pub impact_scope_bucket: PortableSdnImpactScopeBucket,
    pub reliability_bucket: PortableSdnReliabilityBucket,
    pub policy_action_category: Option<String>,
    pub route_change_category: Option<String>,
    pub topology_change_category: Option<String>,
    pub affected_asset_category: Option<String>,
    pub exposure_category: Option<String>,
    pub status_bucket: PortableStatusBucket,
    pub count_bucket: Option<String>,
    pub time_bucket_start: Timestamp,
    pub redaction_status: RedactionStatus,
    pub missing_visibility_flags: Vec<String>,
    pub evidence_refs: Vec<EvidenceId>,
    pub quality_score: QualityScore,
}

impl PortableSdnControlPlaneMetadata {
    pub fn new(
        controller_category: PortableSdnControllerCategory,
        event_category: PortableSdnControlPlaneEventCategory,
        time_bucket_start: Timestamp,
    ) -> Self {
        Self {
            sdn_control_plane_metadata_id: SdnControlPlaneMetadataId::new_v4(),
            provenance_id: DataSourceId::new_v4(),
            controller_category,
            event_category,
            impact_scope_bucket: PortableSdnImpactScopeBucket::Unknown,
            reliability_bucket: PortableSdnReliabilityBucket::Unknown,
            policy_action_category: None,
            route_change_category: None,
            topology_change_category: None,
            affected_asset_category: None,
            exposure_category: None,
            status_bucket: PortableStatusBucket::Unknown,
            count_bucket: None,
            time_bucket_start,
            redaction_status: RedactionStatus::Redacted,
            missing_visibility_flags: vec![
                "metadata_only_visibility".to_string(),
                "no_packet_content_visibility".to_string(),
                "no_live_controller_api_visibility".to_string(),
            ],
            evidence_refs: Vec::new(),
            quality_score: QualityScore::default(),
        }
    }
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

pub const WINDOWS_DNS_SENSING_SCHEMA_VERSION: crate::SchemaVersion =
    crate::SchemaVersion::new(1, 0, 0);
pub const MAX_WINDOWS_DNS_BATCH_RECORDS: usize = 128;
pub const MAX_WINDOWS_DNS_SAFE_REF_LEN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDnsQueryTypeCategory {
    Address,
    Alias,
    Mail,
    Service,
    Reverse,
    Text,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDnsResultCategory {
    Pending,
    Success,
    NameError,
    Timeout,
    Refused,
    ServerFailure,
    Cancelled,
    OtherFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDnsLengthBucket {
    Short,
    Medium,
    Long,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDnsDepthBucket {
    Shallow,
    Moderate,
    Deep,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDnsEntropyBucket {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDnsAnswerCountBucket {
    Unknown,
    Zero,
    One,
    Few,
    Many,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDnsRecurrenceBucket {
    One,
    Few,
    Many,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsDnsObservation {
    pub schema_version: crate::SchemaVersion,
    pub observation_ref: String,
    pub query_ref: String,
    pub query_type_category: WindowsDnsQueryTypeCategory,
    pub result_category: WindowsDnsResultCategory,
    pub query_length_bucket: WindowsDnsLengthBucket,
    pub subdomain_depth_bucket: WindowsDnsDepthBucket,
    pub entropy_bucket: WindowsDnsEntropyBucket,
    pub answer_count_bucket: WindowsDnsAnswerCountBucket,
    pub recurrence_bucket: WindowsDnsRecurrenceBucket,
    pub observed_at: Timestamp,
    pub provenance_refs: Vec<String>,
    pub redaction_status: RedactionStatus,
}

impl WindowsDnsObservation {
    pub fn validate(&self) -> Result<(), NetworkContractError> {
        if self.schema_version != WINDOWS_DNS_SENSING_SCHEMA_VERSION {
            return Err(NetworkContractError::UnsupportedSchemaVersion);
        }
        validate_windows_dns_safe_ref("observation_ref", &self.observation_ref)?;
        validate_windows_dns_safe_ref("query_ref", &self.query_ref)?;
        if self.provenance_refs.len() > 8 {
            return Err(NetworkContractError::TooManyItems("provenance_refs"));
        }
        for reference in &self.provenance_refs {
            validate_windows_dns_safe_ref("provenance_ref", reference)?;
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(NetworkContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsDnsObservationBatch {
    pub schema_version: crate::SchemaVersion,
    pub batch_ref: String,
    pub allowlist_ref: String,
    pub records: Vec<WindowsDnsObservation>,
    pub raw_events_observed: u32,
    pub normalized_events: u32,
    pub dropped_events: u32,
    pub overflow_events: u32,
    pub rate_limited_events: u32,
    pub schema_rejected_events: u32,
    pub duplicate_events: u32,
    pub provenance_refs: Vec<String>,
    pub generated_at: Timestamp,
    pub redaction_status: RedactionStatus,
}

impl WindowsDnsObservationBatch {
    pub fn validate(&self) -> Result<(), NetworkContractError> {
        if self.schema_version != WINDOWS_DNS_SENSING_SCHEMA_VERSION {
            return Err(NetworkContractError::UnsupportedSchemaVersion);
        }
        validate_windows_dns_safe_ref("batch_ref", &self.batch_ref)?;
        validate_windows_dns_safe_ref("allowlist_ref", &self.allowlist_ref)?;
        if self.records.is_empty() || self.records.len() > MAX_WINDOWS_DNS_BATCH_RECORDS {
            return Err(NetworkContractError::InvalidLimit("records"));
        }
        for record in &self.records {
            record.validate()?;
        }
        if self.normalized_events < self.records.len() as u32 {
            return Err(NetworkContractError::InvalidLimit("normalized_events"));
        }
        if self.provenance_refs.len() > 8 {
            return Err(NetworkContractError::TooManyItems("provenance_refs"));
        }
        for reference in &self.provenance_refs {
            validate_windows_dns_safe_ref("provenance_ref", reference)?;
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(NetworkContractError::RedactionRequired);
        }
        Ok(())
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
    UnsafeField(&'static str),
    TooManyItems(&'static str),
    InvalidLimit(&'static str),
    UnsupportedSchemaVersion,
    RedactionRequired,
}

impl fmt::Display for NetworkContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::UnsafeField(field) => write!(f, "{field} contains unsafe network metadata"),
            Self::TooManyItems(field) => write!(f, "{field} contains too many items"),
            Self::InvalidLimit(field) => write!(f, "{field} is outside the bounded limit"),
            Self::UnsupportedSchemaVersion => write!(f, "network schema version is unsupported"),
            Self::RedactionRequired => write!(f, "network metadata must be redacted"),
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

fn validate_windows_dns_safe_ref(
    field: &'static str,
    value: &str,
) -> Result<(), NetworkContractError> {
    if value.is_empty() {
        return Err(NetworkContractError::EmptyField(field));
    }
    if value.len() > MAX_WINDOWS_DNS_SAFE_REF_LEN
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(NetworkContractError::UnsafeField(field));
    }
    Ok(())
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
    fn windows_dns_observation_accepts_only_safe_refs_and_categories() {
        let observation = WindowsDnsObservation {
            schema_version: WINDOWS_DNS_SENSING_SCHEMA_VERSION,
            observation_ref: "dns_observation_0001".to_string(),
            query_ref: "dns_query_0123456789abcdef".to_string(),
            query_type_category: WindowsDnsQueryTypeCategory::Address,
            result_category: WindowsDnsResultCategory::Success,
            query_length_bucket: WindowsDnsLengthBucket::Medium,
            subdomain_depth_bucket: WindowsDnsDepthBucket::Shallow,
            entropy_bucket: WindowsDnsEntropyBucket::Low,
            answer_count_bucket: WindowsDnsAnswerCountBucket::Unknown,
            recurrence_bucket: WindowsDnsRecurrenceBucket::One,
            observed_at: Timestamp::now(),
            provenance_refs: vec!["windows_dns_client_etw".to_string()],
            redaction_status: RedactionStatus::Redacted,
        };
        assert!(observation.validate().is_ok());
        let serialized = serde_json::to_string(&observation).expect("serialize");
        assert!(!serialized.contains("query_name"));
        assert!(!serialized.contains("resolver"));
        assert!(!serialized.contains("source_ip"));
        assert!(!serialized.contains("port"));
        assert!(!serialized.contains("pid"));
        assert!(!serialized.contains("payload"));
    }

    #[test]
    fn windows_dns_observation_rejects_raw_looking_query_ref() {
        let mut observation = WindowsDnsObservation {
            schema_version: WINDOWS_DNS_SENSING_SCHEMA_VERSION,
            observation_ref: "dns_observation_0001".to_string(),
            query_ref: "raw.example.test".to_string(),
            query_type_category: WindowsDnsQueryTypeCategory::Address,
            result_category: WindowsDnsResultCategory::Pending,
            query_length_bucket: WindowsDnsLengthBucket::Short,
            subdomain_depth_bucket: WindowsDnsDepthBucket::Shallow,
            entropy_bucket: WindowsDnsEntropyBucket::Low,
            answer_count_bucket: WindowsDnsAnswerCountBucket::Unknown,
            recurrence_bucket: WindowsDnsRecurrenceBucket::One,
            observed_at: Timestamp::now(),
            provenance_refs: Vec::new(),
            redaction_status: RedactionStatus::Redacted,
        };
        assert!(matches!(
            observation.validate(),
            Err(NetworkContractError::UnsafeField("query_ref"))
        ));
        observation.query_ref = "dns_query_safe".to_string();
        assert!(observation.validate().is_ok());
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
                sdn_control_plane_records: 0,
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
                sdn_control_plane_records: 0,
            },
            RedactionStatus::Redacted,
        );

        let value = serde_json::to_string(&provenance).expect("serialize provenance");

        assert!(value.contains("imported_web_access_log"));
        assert!(!value.contains("authorization"));
        assert!(!value.contains("payload"));
    }

    #[test]
    fn portable_capture_provenance_supports_dns_resolver_logs() {
        let provenance = PortableCaptureProvenance::new(
            PortableCaptureInputSourceType::ImportedDnsResolverLog,
            PortableCaptureRecordCounts {
                flow_records: 0,
                session_records: 0,
                dns_records: 3,
                tls_records: 0,
                http_metadata_records: 0,
                auth_metadata_records: 0,
                saas_cloud_metadata_records: 0,
                deception_event_records: 0,
                sdn_control_plane_records: 0,
            },
            RedactionStatus::Redacted,
        );

        let value = serde_json::to_string(&provenance).expect("serialize provenance");

        assert!(value.contains("imported_dns_resolver_log"));
        assert!(value.contains("dns_records"));
        assert!(!value.contains("query_name"));
        assert!(!value.contains("client_ip"));
        assert!(!value.contains("payload"));
    }

    #[test]
    fn portable_capture_provenance_supports_api_gateway_logs() {
        let provenance = PortableCaptureProvenance::new(
            PortableCaptureInputSourceType::ImportedApiGatewayLog,
            PortableCaptureRecordCounts {
                flow_records: 2,
                session_records: 2,
                dns_records: 0,
                tls_records: 0,
                http_metadata_records: 2,
                auth_metadata_records: 0,
                saas_cloud_metadata_records: 0,
                deception_event_records: 0,
                sdn_control_plane_records: 0,
            },
            RedactionStatus::Redacted,
        );

        let value = serde_json::to_string(&provenance).expect("serialize provenance");

        assert!(value.contains("imported_api_gateway_log"));
        assert!(value.contains("http_metadata_records"));
        assert!(!value.contains("domainName"));
        assert!(!value.contains("sourceIp"));
        assert!(!value.contains("requestId"));
        assert!(!value.contains("payload"));
    }

    #[test]
    fn portable_capture_provenance_supports_waf_logs() {
        let provenance = PortableCaptureProvenance::new(
            PortableCaptureInputSourceType::ImportedWafLog,
            PortableCaptureRecordCounts {
                flow_records: 2,
                session_records: 2,
                dns_records: 0,
                tls_records: 0,
                http_metadata_records: 2,
                auth_metadata_records: 0,
                saas_cloud_metadata_records: 0,
                deception_event_records: 0,
                sdn_control_plane_records: 0,
            },
            RedactionStatus::Redacted,
        );

        let value = serde_json::to_string(&provenance).expect("serialize provenance");

        assert!(value.contains("imported_waf_log"));
        assert!(value.contains("http_metadata_records"));
        assert!(!value.contains("clientIp"));
        assert!(!value.contains("requestUri"));
        assert!(!value.contains("ruleMessage"));
        assert!(!value.contains("payload"));
    }

    #[test]
    fn portable_capture_provenance_supports_cdn_edge_logs() {
        let provenance = PortableCaptureProvenance::new(
            PortableCaptureInputSourceType::ImportedCdnEdgeLog,
            PortableCaptureRecordCounts {
                flow_records: 3,
                session_records: 3,
                dns_records: 0,
                tls_records: 0,
                http_metadata_records: 3,
                auth_metadata_records: 0,
                saas_cloud_metadata_records: 3,
                deception_event_records: 0,
                sdn_control_plane_records: 0,
            },
            RedactionStatus::Redacted,
        );

        let value = serde_json::to_string(&provenance).expect("serialize provenance");

        assert!(value.contains("imported_cdn_edge_log"));
        assert!(value.contains("http_metadata_records"));
        assert!(value.contains("saas_cloud_metadata_records"));
        assert!(!value.contains("ClientIP"));
        assert!(!value.contains("ClientRequestHost"));
        assert!(!value.contains("RayID"));
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
                sdn_control_plane_records: 0,
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
                sdn_control_plane_records: 0,
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
                sdn_control_plane_records: 0,
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
    fn portable_capture_provenance_supports_sdn_control_plane_logs() {
        let provenance = PortableCaptureProvenance::new(
            PortableCaptureInputSourceType::ImportedSdnControlPlaneLog,
            PortableCaptureRecordCounts {
                flow_records: 0,
                session_records: 0,
                dns_records: 0,
                tls_records: 0,
                http_metadata_records: 0,
                auth_metadata_records: 0,
                saas_cloud_metadata_records: 0,
                deception_event_records: 0,
                sdn_control_plane_records: 2,
            },
            RedactionStatus::Redacted,
        );

        let value = serde_json::to_string(&provenance).expect("serialize provenance");

        assert!(value.contains("imported_sdn_control_plane_log"));
        assert!(value.contains("sdn_control_plane_records"));
        assert!(!value.contains("controller-prod-a"));
        assert!(!value.contains("tenant"));
        assert!(!value.contains("payload"));
    }

    #[test]
    fn portable_capture_provenance_supports_object_storage_audit_logs() {
        let provenance = PortableCaptureProvenance::new(
            PortableCaptureInputSourceType::ImportedObjectStorageAuditLog,
            PortableCaptureRecordCounts {
                flow_records: 0,
                session_records: 0,
                dns_records: 0,
                tls_records: 0,
                http_metadata_records: 0,
                auth_metadata_records: 0,
                saas_cloud_metadata_records: 2,
                deception_event_records: 0,
                sdn_control_plane_records: 0,
            },
            RedactionStatus::Redacted,
        );

        let value = serde_json::to_string(&provenance).expect("serialize provenance");

        assert!(value.contains("imported_object_storage_audit_log"));
        assert!(value.contains("saas_cloud_metadata_records"));
        assert!(!value.contains("bucket_name"));
        assert!(!value.contains("object_key"));
        assert!(!value.contains("principal"));
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
    fn object_storage_audit_client_contract_serializes_safe_state_only() {
        let config = ObjectStorageAuditClientConfig::new(
            ObjectStorageAuditProviderKind::AwsCloudTrail,
            ObjectStorageAuditEndpointKind::CloudTrailLookupEvents,
        );
        let request = ObjectStorageAuditPollRequest::new(
            config,
            Some(ObjectStorageAuditCredentialRef::new(
                "credential_session#current",
                ObjectStorageAuditAuthMode::AwsSigV4Session,
                None,
            )),
            ObjectStorageAuditPageCursor::from_safe_checkpoint(
                "continuation_present",
                Some("sha256#abc123".to_string()),
                Timestamp::now(),
            ),
        );
        let mut outcome = ObjectStorageAuditPollOutcome::empty(
            ObjectStorageAuditClientState::PageFetched,
            request.cursor.clone(),
        );
        outcome.accepted_record_count = 1;
        outcome
            .degraded_reasons
            .push("metadata_only_object_storage_audit".to_string());

        let request_value = serde_json::to_string(&request).expect("serialize request");
        let outcome_value = serde_json::to_string(&outcome).expect("serialize outcome");

        assert!(request_value.contains("aws_cloud_trail"));
        assert!(request_value.contains("credential_session#current"));
        assert!(request_value.contains("sha256#abc123"));
        assert!(outcome_value.contains("metadata_only_object_storage_audit"));
        for value in [request_value, outcome_value] {
            assert!(!value.contains("AKIA"));
            assert!(!value.contains("secret_access_key"));
            assert!(!value.contains("session_token"));
            assert!(!value.contains("RAW_NEXT_PAGE_TOKEN"));
            assert!(!value.contains("private-bucket"));
            assert!(!value.contains("alice@example.test"));
            assert!(!value.contains("payload"));
        }
    }

    #[test]
    fn cdn_edge_client_contract_serializes_safe_state_only() {
        let config = CdnEdgeClientConfig::new(
            CdnEdgeProviderKind::CloudflareHttp,
            CdnEdgeEndpointKind::CloudflareHttpRequests,
        );
        let request = CdnEdgePollRequest::new(
            config,
            Some(CdnEdgeCredentialRef::new(
                "credential_session#cdn-edge",
                CdnEdgeAuthMode::BearerTokenSession,
                None,
            )),
            CdnEdgePageCursor::from_safe_checkpoint(
                "continuation_present",
                Some("sha256#def456".to_string()),
                Timestamp::now(),
            ),
        );
        let mut outcome =
            CdnEdgePollOutcome::empty(CdnEdgeClientState::PageFetched, request.cursor.clone());
        outcome.accepted_record_count = 1;
        outcome
            .degraded_reasons
            .push("metadata_only_cdn_edge_page".to_string());

        let request_value = serde_json::to_string(&request).expect("serialize request");
        let outcome_value = serde_json::to_string(&outcome).expect("serialize outcome");

        assert!(request_value.contains("cloudflare_http"));
        assert!(request_value.contains("credential_session#cdn-edge"));
        assert!(request_value.contains("sha256#def456"));
        assert!(outcome_value.contains("metadata_only_cdn_edge_page"));
        for value in [request_value, outcome_value] {
            assert!(!value.contains("Bearer"));
            assert!(!value.contains("authorization"));
            assert!(!value.contains("secret_access_key"));
            assert!(!value.contains("RAW_CDN_CURSOR"));
            assert!(!value.contains("customer.example.test"));
            assert!(!value.contains("/private/path"));
            assert!(!value.contains("203.0.113."));
            assert!(!value.contains("payload"));
        }
    }

    #[test]
    fn api_gateway_client_contract_serializes_safe_state_only() {
        let config = ApiGatewayClientConfig::new(
            ApiGatewayProviderKind::AwsApiGateway,
            ApiGatewayEndpointKind::AwsCloudWatchLogEvents,
        );
        let request = ApiGatewayPollRequest::new(
            config,
            Some(ApiGatewayCredentialRef::new(
                "credential_session#api-gateway",
                ApiGatewayAuthMode::AwsSigV4Session,
                None,
            )),
            ApiGatewayPageCursor::from_safe_checkpoint(
                "continuation_present",
                Some("sha256#fed789".to_string()),
                Timestamp::now(),
            ),
        );
        let mut outcome = ApiGatewayPollOutcome::empty(
            ApiGatewayClientState::PageFetched,
            request.cursor.clone(),
        );
        outcome.accepted_record_count = 1;
        outcome
            .degraded_reasons
            .push("metadata_only_api_gateway_page".to_string());

        let request_value = serde_json::to_string(&request).expect("serialize request");
        let outcome_value = serde_json::to_string(&outcome).expect("serialize outcome");

        assert!(request_value.contains("aws_api_gateway"));
        assert!(request_value.contains("credential_session#api-gateway"));
        assert!(request_value.contains("sha256#fed789"));
        assert!(outcome_value.contains("metadata_only_api_gateway_page"));
        for value in [request_value, outcome_value] {
            assert!(!value.contains("AKIA"));
            assert!(!value.contains("secret_access_key"));
            assert!(!value.contains("x-api-key"));
            assert!(!value.contains("RAW_API_CURSOR"));
            assert!(!value.contains("customer.example.test"));
            assert!(!value.contains("/prod/orders"));
            assert!(!value.contains("203.0.113."));
            assert!(!value.contains("payload"));
        }
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

    #[test]
    fn portable_sdn_control_plane_metadata_is_bounded_and_redacted() {
        let mut metadata = PortableSdnControlPlaneMetadata::new(
            PortableSdnControllerCategory::Onos,
            PortableSdnControlPlaneEventCategory::PolicyChange,
            Timestamp::now(),
        );
        metadata.impact_scope_bucket = PortableSdnImpactScopeBucket::MultipleSegments;
        metadata.reliability_bucket = PortableSdnReliabilityBucket::Medium;
        metadata.policy_action_category = Some("blocked".to_string());
        metadata.affected_asset_category = Some("cloud_workload".to_string());
        metadata.exposure_category = Some("reduced_exposure".to_string());

        let value = serde_json::to_string(&metadata).expect("serialize sdn metadata");

        assert!(value.contains("onos"));
        assert!(value.contains("policy_change"));
        assert!(value.contains("reduced_exposure"));
        assert!(!value.contains("controller-prod-a"));
        assert!(!value.contains("10.0.0."));
        assert!(!value.contains("acl_text"));
        assert!(!value.contains("payload"));
        assert!(!value.contains("tenant"));
    }
}
