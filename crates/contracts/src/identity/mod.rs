use crate::common::{
    AssetIdentityId, AuthMetadataId, DataSourceId, EntityRef, EvidenceId, FindingId,
    FlowAttributionId, FlowId, GraphHintId, HostIdentityId, ProcessContextId, QualityScore,
    Timestamp, UserSessionId,
};
use crate::graph::RedactionStatus;
use crate::network::IpAddress;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionStatus {
    Confirmed,
    Probable,
    Possible,
    Unknown,
    Conflict,
    ExpiredProcess,
    InsufficientVisibility,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionMethod {
    TcpEndpointSnapshot,
    UdpEndpointSnapshot,
    ConnectionTableCorrelation,
    ProcessCreationCorrelation,
    CaptureTimeCorrelation,
    WfpAleFuture,
    ManualImport,
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionConfidence {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityLevel {
    Full,
    Reduced,
    MetadataOnly,
    Degraded,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionMode {
    #[default]
    Normal,
    Reduced,
    ForensicScoped,
    Imported,
    Mock,
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerStatus {
    Trusted,
    Signed,
    Unsigned,
    InvalidSignature,
    Revoked,
    Protected,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessTrustScore {
    pub overall: QualityScore,
    pub signer: QualityScore,
    pub path_location: QualityScore,
    pub newly_seen: QualityScore,
    pub parent_child_anomaly: QualityScore,
    pub network_rarity: QualityScore,
    pub destination_risk: QualityScore,
    pub known_system_process: bool,
    pub user_allowlisted: bool,
    pub user_blocklisted: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserSessionRef {
    pub user_session_id: UserSessionId,
    pub user_pseudonym: Option<String>,
    pub user_sid_hash: Option<String>,
    pub session_name_protected: Option<String>,
    pub logon_time: Option<Timestamp>,
    pub visibility_level: VisibilityLevel,
}

impl UserSessionRef {
    pub fn unknown() -> Self {
        Self {
            user_session_id: UserSessionId::new_v4(),
            user_pseudonym: None,
            user_sid_hash: None,
            session_name_protected: None,
            logon_time: None,
            visibility_level: VisibilityLevel::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcessContext {
    pub process_context_id: ProcessContextId,
    pub os_process_id: u32,
    pub process_start_time: Timestamp,
    pub process_end_time: Option<Timestamp>,
    pub process_name: String,
    pub process_path_protected: Option<String>,
    pub process_hash: Option<String>,
    pub signer_status: SignerStatus,
    pub parent_process_ref: Option<ProcessContextId>,
    pub user_session_ref: Option<UserSessionRef>,
    pub trust_score: ProcessTrustScore,
    pub visibility_level: VisibilityLevel,
    pub collection_mode: CollectionMode,
    pub known_limitations: Vec<String>,
    pub captured_at: Timestamp,
}

impl ProcessContext {
    pub fn new(os_process_id: u32, process_name: impl Into<String>) -> Self {
        let now = Timestamp::now();
        Self {
            process_context_id: ProcessContextId::new_v4(),
            os_process_id,
            process_start_time: now.clone(),
            process_end_time: None,
            process_name: process_name.into(),
            process_path_protected: None,
            process_hash: None,
            signer_status: SignerStatus::Unknown,
            parent_process_ref: None,
            user_session_ref: None,
            trust_score: ProcessTrustScore::default(),
            visibility_level: VisibilityLevel::Unknown,
            collection_mode: CollectionMode::Normal,
            known_limitations: Vec::new(),
            captured_at: now,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlowAttribution {
    pub flow_attribution_id: FlowAttributionId,
    pub flow_id: FlowId,
    pub process_ref: Option<ProcessContextId>,
    pub os_process_id: Option<u32>,
    pub process_start_time: Option<Timestamp>,
    pub process_path_protected: Option<String>,
    pub process_hash: Option<String>,
    pub signer_status: SignerStatus,
    pub parent_process_ref: Option<ProcessContextId>,
    pub user_session_ref: Option<UserSessionRef>,
    pub local_ip: Option<IpAddress>,
    pub local_port: Option<u16>,
    pub remote_ip: Option<IpAddress>,
    pub remote_port: Option<u16>,
    pub attribution_status: AttributionStatus,
    pub attribution_method: AttributionMethod,
    pub attribution_confidence: AttributionConfidence,
    pub visibility_level: VisibilityLevel,
    pub collection_mode: CollectionMode,
    pub known_limitations: Vec<String>,
    pub timestamp: Timestamp,
}

impl FlowAttribution {
    pub fn unknown(flow_id: FlowId) -> Self {
        Self {
            flow_attribution_id: FlowAttributionId::new_v4(),
            flow_id,
            process_ref: None,
            os_process_id: None,
            process_start_time: None,
            process_path_protected: None,
            process_hash: None,
            signer_status: SignerStatus::Unknown,
            parent_process_ref: None,
            user_session_ref: None,
            local_ip: None,
            local_port: None,
            remote_ip: None,
            remote_port: None,
            attribution_status: AttributionStatus::Unknown,
            attribution_method: AttributionMethod::Unknown,
            attribution_confidence: AttributionConfidence::Unknown,
            visibility_level: VisibilityLevel::Unknown,
            collection_mode: CollectionMode::Normal,
            known_limitations: vec!["No reliable process mapping available.".to_string()],
            timestamp: Timestamp::now(),
        }
    }

    pub fn with_process(
        mut self,
        process_ref: ProcessContextId,
        method: AttributionMethod,
        confidence: AttributionConfidence,
    ) -> Self {
        self.process_ref = Some(process_ref);
        self.attribution_method = method;
        self.attribution_confidence = confidence;
        self.attribution_status = match self.attribution_confidence {
            AttributionConfidence::High => AttributionStatus::Confirmed,
            AttributionConfidence::Medium => AttributionStatus::Probable,
            AttributionConfidence::Low => AttributionStatus::Possible,
            AttributionConfidence::Unknown => AttributionStatus::Unknown,
        };
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostIdentity {
    pub host_identity_id: HostIdentityId,
    pub host_name_protected: Option<String>,
    pub local_ip: Option<IpAddress>,
    pub asset_ref: Option<EntityRef>,
    pub visibility_level: VisibilityLevel,
    pub collection_mode: CollectionMode,
}

impl HostIdentity {
    pub fn new() -> Self {
        Self {
            host_identity_id: HostIdentityId::new_v4(),
            host_name_protected: None,
            local_ip: None,
            asset_ref: None,
            visibility_level: VisibilityLevel::Unknown,
            collection_mode: CollectionMode::Normal,
        }
    }
}

impl Default for HostIdentity {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ListeningEndpoint {
    pub listening_ip: IpAddress,
    pub listening_port: u16,
    pub protocol: String,
    pub process_ref: Option<ProcessContextId>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetIdentity {
    pub asset_identity_id: AssetIdentityId,
    pub asset_ref: Option<EntityRef>,
    pub host_identity_ref: Option<HostIdentityId>,
    pub listening_endpoints: Vec<ListeningEndpoint>,
    pub visibility_level: VisibilityLevel,
    pub collection_mode: CollectionMode,
}

impl AssetIdentity {
    pub fn new() -> Self {
        Self {
            asset_identity_id: AssetIdentityId::new_v4(),
            asset_ref: None,
            host_identity_ref: None,
            listening_endpoints: Vec::new(),
            visibility_level: VisibilityLevel::Unknown,
            collection_mode: CollectionMode::Normal,
        }
    }
}

impl Default for AssetIdentity {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableAuthResultCategory {
    Success,
    Failure,
    Blocked,
    Challenge,
    Timeout,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableMfaResultCategory {
    Satisfied,
    Failed,
    Denied,
    Prompted,
    Timeout,
    NotPresent,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableAuthAttemptCountBucket {
    One,
    Few,
    Burst,
    Many,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableAuthRiskBucket {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortableAuthMetadata {
    pub auth_metadata_id: AuthMetadataId,
    pub provenance_id: DataSourceId,
    pub provider_category: String,
    pub identity_label_redacted: Option<String>,
    pub source_session_label: Option<String>,
    pub auth_result: PortableAuthResultCategory,
    pub mfa_result: Option<PortableMfaResultCategory>,
    pub role_privilege_class: Option<String>,
    pub device_client_category: Option<String>,
    pub destination_service_category: Option<String>,
    pub time_bucket_start: Timestamp,
    pub attempt_count_bucket: PortableAuthAttemptCountBucket,
    pub failure_reason_category: Option<String>,
    pub redaction_status: RedactionStatus,
    pub quality_score: QualityScore,
}

impl PortableAuthMetadata {
    pub fn new(
        provider_category: impl Into<String>,
        auth_result: PortableAuthResultCategory,
        time_bucket_start: Timestamp,
    ) -> Self {
        Self {
            auth_metadata_id: AuthMetadataId::new_v4(),
            provenance_id: DataSourceId::new_v4(),
            provider_category: provider_category.into(),
            identity_label_redacted: None,
            source_session_label: None,
            auth_result,
            mfa_result: None,
            role_privilege_class: None,
            device_client_category: None,
            destination_service_category: None,
            time_bucket_start,
            attempt_count_bucket: PortableAuthAttemptCountBucket::One,
            failure_reason_category: None,
            redaction_status: RedactionStatus::Redacted,
            quality_score: QualityScore::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableAuthCategoryCount {
    pub category: String,
    pub count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableAuthServiceOutcomeCount {
    pub service_category: String,
    pub auth_result: PortableAuthResultCategory,
    pub count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableAuthSummary {
    pub provenance_id: DataSourceId,
    pub auth_record_count: u32,
    pub identity_session_risk_bucket: PortableAuthRiskBucket,
    pub source_session_count: u32,
    pub provider_category_counts: Vec<PortableAuthCategoryCount>,
    pub service_outcome_counts: Vec<PortableAuthServiceOutcomeCount>,
    pub first_seen_category_flags: Vec<String>,
    pub privileged_role_record_count: u32,
    pub degraded_visibility_flags: Vec<String>,
    pub finding_refs: Vec<FindingId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub graph_hint_refs: Vec<GraphHintId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribution_can_express_all_confidence_levels() {
        let levels = [
            AttributionConfidence::Unknown,
            AttributionConfidence::Low,
            AttributionConfidence::Medium,
            AttributionConfidence::High,
        ];

        assert_eq!(levels.len(), 4);
    }

    #[test]
    fn unknown_flow_attribution_keeps_visible_limitations() {
        let attribution = FlowAttribution::unknown(FlowId::new_v4());

        assert_eq!(attribution.attribution_status, AttributionStatus::Unknown);
        assert_eq!(attribution.attribution_method, AttributionMethod::Unknown);
        assert_eq!(
            attribution.attribution_confidence,
            AttributionConfidence::Unknown
        );
        assert!(!attribution.known_limitations.is_empty());
    }

    #[test]
    fn portable_auth_metadata_is_bounded_and_redacted() {
        let mut metadata =
            PortableAuthMetadata::new("vpn", PortableAuthResultCategory::Failure, Timestamp::now());
        metadata.identity_label_redacted = Some("identity#abc123".to_string());
        metadata.source_session_label = Some("session#def456".to_string());
        metadata.redaction_status = RedactionStatus::Hashed;
        let value = serde_json::to_string(&metadata).expect("serialize auth metadata");

        assert!(value.contains("identity#abc123"));
        assert!(value.contains("session#def456"));
        assert!(!value.contains("@example.com"));
        assert!(!value.contains("password"));
        assert!(!value.contains("token"));
    }
}
