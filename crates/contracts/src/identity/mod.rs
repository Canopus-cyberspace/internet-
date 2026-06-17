use crate::common::{
    AssetIdentityId, AuthMetadataId, DataSourceId, EntityRef, EvidenceId, FindingId,
    FlowAttributionId, FlowId, GraphHintId, HostIdentityId, ProcessContextId, QualityScore,
    SchemaVersion, Timestamp, UserSessionId,
};
use crate::graph::RedactionStatus;
use crate::network::IpAddress;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const WINDOWS_AUTH_REMOTE_METADATA_TOPIC: &str = "identity.windows_auth_remote.metadata";
pub const WINDOWS_RDP_OPERATIONAL_METADATA_TOPIC: &str = "identity.rdp_operational_metadata";
pub const WINDOWS_SMB_OPERATIONAL_METADATA_TOPIC: &str = "identity.smb_operational_metadata";
pub const WINDOWS_SSH_OPERATIONAL_METADATA_TOPIC: &str = "identity.ssh_operational_metadata";
pub const MAX_WINDOWS_AUTH_REMOTE_RECORDS: usize = 256;
pub const MAX_WINDOWS_AUTH_REMOTE_REFS: usize = 12;
pub const MAX_WINDOWS_AUTH_REMOTE_TEXT_LEN: usize = 96;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAuthRemoteEventId {
    SuccessfulLogon,
    FailedLogon,
    ExplicitCredentialUse,
    SpecialPrivilegesAssigned,
    AccountLockout,
    KerberosServiceTicket,
    KerberosPreauthFailure,
    NtlmFailure,
    Logoff,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAuthResultCategory {
    Success,
    Failure,
    PrivilegedSuccess,
    Lockout,
    Logoff,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAuthMechanismCategory {
    Kerberos,
    Ntlm,
    Negotiate,
    Local,
    ExplicitCredential,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAuthAccountCategory {
    LocalUser,
    DomainUser,
    Machine,
    Service,
    AdminLike,
    Anonymous,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAuthPrivilegeBucket {
    None,
    Standard,
    Elevated,
    SpecialPrivileges,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsRemoteProtocolCategory {
    LocalInteractive,
    Network,
    Rdp,
    Smb,
    Ssh,
    WinRm,
    Service,
    ScheduledTask,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAuthFailureCategory {
    BadSecret,
    UnknownIdentity,
    LockedOut,
    Expired,
    NotAllowed,
    TimeSkew,
    ProtocolFailure,
    MissingVisibility,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAuthObservedBucket {
    CurrentWindow,
    RecentWindow,
    ExistingHostEvents,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAuthSourceReliability {
    SecurityLogVerified,
    OptionalChannelVerified,
    Degraded,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAuthFreshnessCategory {
    Fresh,
    Recent,
    Stale,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAuthSchemaCategory {
    Security4624V0,
    Security4624V1,
    Security4624V2,
    Security4625V0,
    Security4625V1,
    Security4648V0,
    Security4672V0,
    Security4740V0,
    Security4768V0,
    Security4769V0,
    Security4771V0,
    Security4776V0,
    Security4634V0,
    TerminalServicesRemoteConnectionManager1149V0,
    TerminalServicesLocalSessionManager21V0,
    TerminalServicesLocalSessionManager23V0,
    TerminalServicesLocalSessionManager24V0,
    TerminalServicesLocalSessionManager25V0,
    TerminalServicesLocalSessionManager39V0,
    TerminalServicesLocalSessionManager40V0,
    SmbClientConnectivity30803V0,
    SmbClientConnectivity30806V2,
    SmbClientConnectivity30808V2,
    SmbClientConnectivity30832V0,
    SmbClientConnectivity30834V0,
    SmbClientConnectivity30835V0,
    SmbClientSecurity31017V0,
    SmbClientSecurity31019V0,
    SmbClientSecurity31020V0,
    SmbClientSecurity31023V0,
    SmbServerOperational1001V1,
    SmbServerOperational1003V1,
    SmbServerOperational1004V1,
    SmbServerOperational1005V2,
    SmbServerSecurity551V1,
    OpenSshOperational4AuthSuccessPublicKeyV0,
    OpenSshOperational4AuthSuccessPasswordV0,
    OpenSshOperational4AuthFailurePublicKeyV0,
    OpenSshOperational4AuthFailurePasswordV0,
    OpenSshOperational4InvalidUserV0,
    OpenSshOperational4ConnectionOpenedV0,
    OpenSshOperational4SessionOpenedV0,
    OpenSshOperational4SessionClosedV0,
    OpenSshOperational4SubsystemRequestedV0,
    OpenSshOperational4DisconnectV0,
    OpenSshOperational3PolicyRejectionV0,
    OpenSshOperational3ProtocolErrorV0,
    OpenSshOperational3KeyExchangeFailureV0,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAuthRemoteObservation {
    pub observation_ref: String,
    pub event_category: WindowsAuthRemoteEventId,
    pub schema_category: WindowsAuthSchemaCategory,
    pub event_version: u8,
    pub auth_result: WindowsAuthResultCategory,
    pub auth_mechanism: WindowsAuthMechanismCategory,
    pub account_category: WindowsAuthAccountCategory,
    pub privilege_bucket: WindowsAuthPrivilegeBucket,
    pub remote_protocol_category: Option<WindowsRemoteProtocolCategory>,
    pub failure_category: Option<WindowsAuthFailureCategory>,
    pub repeated_failure_bucket: Option<PortableAuthAttemptCountBucket>,
    pub success_after_failure: bool,
    pub identity_ref: Option<String>,
    pub source_ref: Option<String>,
    pub target_ref: Option<String>,
    pub observed_bucket: WindowsAuthObservedBucket,
    pub source_reliability: WindowsAuthSourceReliability,
    pub freshness: WindowsAuthFreshnessCategory,
    pub provenance_ref: String,
    pub missing_visibility: Vec<String>,
    pub time_bucket_start: Timestamp,
    pub redaction_status: RedactionStatus,
    pub quality_score: QualityScore,
}

impl WindowsAuthRemoteObservation {
    pub fn validate(&self) -> Result<(), WindowsAuthRemoteContractError> {
        validate_windows_auth_safe_text("observation_ref", &self.observation_ref)?;
        validate_windows_auth_safe_text("provenance_ref", &self.provenance_ref)?;
        validate_optional_windows_auth_safe_text("identity_ref", self.identity_ref.as_deref())?;
        validate_optional_windows_auth_safe_text("source_ref", self.source_ref.as_deref())?;
        validate_optional_windows_auth_safe_text("target_ref", self.target_ref.as_deref())?;
        validate_windows_auth_string_list("missing_visibility", &self.missing_visibility)?;
        if self.event_version > 8 {
            return Err(WindowsAuthRemoteContractError::UnsupportedVersion);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(WindowsAuthRemoteContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAuthRemoteCounters {
    pub provider_enabled: u32,
    pub channels_ready: u32,
    pub channels_unavailable: u32,
    pub raw_events_observed: u32,
    pub schema_accepted: u32,
    pub schema_rejected: u32,
    pub malformed: u32,
    pub rate_limited: u32,
    pub queue_dropped: u32,
    pub duplicate_suppressed: u32,
    pub normalized_auth_observations: u32,
    pub normalized_remote_access_observations: u32,
    pub published_batches: u32,
    pub eventbus_publications: u32,
    pub dag_dispatches: u32,
    pub auth_detector_invocations: u32,
    pub auth_consumed: u32,
    pub remote_admin_invocations: u32,
    pub remote_admin_consumed: u32,
    pub lateral_invocations: u32,
    pub lateral_consumed: u32,
    pub outputs: u32,
    pub downstream_facts: u32,
    pub bookmark_updates: u32,
    pub record_gaps: u32,
    pub worker_active: bool,
    pub worker_joined: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAuthRemoteObservationBatch {
    pub batch_ref: String,
    pub provider_ref: String,
    pub schema_version: SchemaVersion,
    pub observations: Vec<WindowsAuthRemoteObservation>,
    pub counters: WindowsAuthRemoteCounters,
    pub cursor_ref: Option<String>,
    pub channel_refs: Vec<String>,
    pub degraded_reason: Option<String>,
    pub generated_at: Timestamp,
    pub redaction_status: RedactionStatus,
}

impl WindowsAuthRemoteObservationBatch {
    pub fn validate(&self) -> Result<(), WindowsAuthRemoteContractError> {
        validate_windows_auth_safe_text("batch_ref", &self.batch_ref)?;
        validate_windows_auth_safe_text("provider_ref", &self.provider_ref)?;
        validate_optional_windows_auth_safe_text("cursor_ref", self.cursor_ref.as_deref())?;
        validate_optional_windows_auth_safe_text(
            "degraded_reason",
            self.degraded_reason.as_deref(),
        )?;
        validate_windows_auth_string_list("channel_refs", &self.channel_refs)?;
        if self.schema_version != WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION {
            return Err(WindowsAuthRemoteContractError::UnsupportedVersion);
        }
        if self.observations.len() > MAX_WINDOWS_AUTH_REMOTE_RECORDS {
            return Err(WindowsAuthRemoteContractError::TooManyItems("observations"));
        }
        let mut seen = BTreeSet::new();
        for observation in &self.observations {
            observation.validate()?;
            if !seen.insert(observation.observation_ref.clone()) {
                return Err(WindowsAuthRemoteContractError::DuplicateObservation);
            }
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(WindowsAuthRemoteContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WindowsAuthRemoteContractError {
    EmptyField(&'static str),
    TooLong(&'static str),
    UnsafeField(&'static str),
    TooManyItems(&'static str),
    UnsupportedVersion,
    DuplicateObservation,
    RedactionRequired,
}

impl fmt::Display for WindowsAuthRemoteContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::TooLong(field) => write!(f, "{field} exceeds bounded auth text length"),
            Self::UnsafeField(field) => write!(f, "{field} contains sensitive auth data"),
            Self::TooManyItems(field) => write!(f, "{field} contains too many auth items"),
            Self::UnsupportedVersion => write!(f, "auth remote schema version is unsupported"),
            Self::DuplicateObservation => {
                write!(f, "auth remote batch contains duplicate observations")
            }
            Self::RedactionRequired => write!(f, "auth remote output must be redacted"),
        }
    }
}

impl std::error::Error for WindowsAuthRemoteContractError {}

fn validate_windows_auth_string_list(
    field: &'static str,
    values: &[String],
) -> Result<(), WindowsAuthRemoteContractError> {
    if values.len() > MAX_WINDOWS_AUTH_REMOTE_REFS {
        return Err(WindowsAuthRemoteContractError::TooManyItems(field));
    }
    for value in values {
        validate_windows_auth_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_optional_windows_auth_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), WindowsAuthRemoteContractError> {
    if let Some(value) = value {
        validate_windows_auth_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_windows_auth_safe_text(
    field: &'static str,
    value: &str,
) -> Result<(), WindowsAuthRemoteContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(WindowsAuthRemoteContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_WINDOWS_AUTH_REMOTE_TEXT_LEN {
        return Err(WindowsAuthRemoteContractError::TooLong(field));
    }
    let lowered = trimmed.to_ascii_lowercase();
    for marker in [
        "s-1-",
        "sid",
        "username",
        "domain\\",
        "token",
        "nonce",
        "credential",
        "secret",
        "password",
        "ticket",
        "command",
        "cmd",
        "powershell",
        "process",
        "pid",
        ".exe",
        "c:\\",
        "\\users\\",
        "ip_address",
        "ipv4",
        "ipv6",
        "port",
        "workstation",
        "host:",
        "payload",
    ] {
        if lowered.contains(marker) {
            return Err(WindowsAuthRemoteContractError::UnsafeField(field));
        }
    }
    if looks_like_ip_or_endpoint(trimmed) {
        return Err(WindowsAuthRemoteContractError::UnsafeField(field));
    }
    Ok(())
}

fn looks_like_ip_or_endpoint(value: &str) -> bool {
    let has_ipv4 = value
        .split(|ch: char| !ch.is_ascii_digit() && ch != '.')
        .any(|part| {
            let octets = part.split('.').collect::<Vec<_>>();
            octets.len() == 4 && octets.iter().all(|octet| octet.parse::<u8>().is_ok())
        });
    has_ipv4 || value.contains("::")
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

    #[test]
    fn windows_auth_remote_observation_rejects_sensitive_values() {
        let mut observation = WindowsAuthRemoteObservation {
            observation_ref: "auth_obs_ref".to_string(),
            event_category: WindowsAuthRemoteEventId::FailedLogon,
            schema_category: WindowsAuthSchemaCategory::Security4625V0,
            event_version: 0,
            auth_result: WindowsAuthResultCategory::Failure,
            auth_mechanism: WindowsAuthMechanismCategory::Ntlm,
            account_category: WindowsAuthAccountCategory::DomainUser,
            privilege_bucket: WindowsAuthPrivilegeBucket::Standard,
            remote_protocol_category: Some(WindowsRemoteProtocolCategory::Network),
            failure_category: Some(WindowsAuthFailureCategory::BadSecret),
            repeated_failure_bucket: Some(PortableAuthAttemptCountBucket::Few),
            success_after_failure: false,
            identity_ref: Some("acct_bucket_ref".to_string()),
            source_ref: Some("source_bucket_ref".to_string()),
            target_ref: Some("target_scope_ref".to_string()),
            observed_bucket: WindowsAuthObservedBucket::ExistingHostEvents,
            source_reliability: WindowsAuthSourceReliability::SecurityLogVerified,
            freshness: WindowsAuthFreshnessCategory::Recent,
            provenance_ref: "windows_event_log_security".to_string(),
            missing_visibility: vec!["no_raw_subject".to_string()],
            time_bucket_start: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
            quality_score: QualityScore::new(0.7).expect("quality"),
        };
        observation.validate().expect("safe observation");
        observation.identity_ref = Some("S-1-5-21-123".to_string());
        assert!(matches!(
            observation.validate(),
            Err(WindowsAuthRemoteContractError::UnsafeField("identity_ref"))
        ));
    }

    #[test]
    fn windows_auth_remote_batch_is_bounded_and_redacted() {
        let batch = WindowsAuthRemoteObservationBatch {
            batch_ref: "auth_remote_batch_ref".to_string(),
            provider_ref: "windows_auth_remote_source".to_string(),
            schema_version: WINDOWS_AUTH_REMOTE_SENSING_SCHEMA_VERSION,
            observations: Vec::new(),
            counters: WindowsAuthRemoteCounters {
                provider_enabled: 1,
                worker_joined: true,
                ..WindowsAuthRemoteCounters::default()
            },
            cursor_ref: Some("bookmark_bucket_ref".to_string()),
            channel_refs: vec!["security_log".to_string()],
            degraded_reason: Some("existing_host_events_only".to_string()),
            generated_at: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        };
        batch.validate().expect("safe batch");
        let json = serde_json::to_string(&batch).expect("json");
        for forbidden in ["S-1-", "192.168.", "username", "token", "password", "cmd"] {
            assert!(!json
                .to_ascii_lowercase()
                .contains(&forbidden.to_ascii_lowercase()));
        }
    }
}
