use crate::{
    AuditId, AuthorizedNativeCapabilityCategory, EvidenceId, FutureSecurityFactMappingId,
    NativeHealthObservationId, NativePermissionState, NativeProcessObservationId,
    NativeSamplerBatchId, NativeSamplerId, NativeSamplerReviewId, NativeSamplerSchemaId,
    NativeServiceObservationId, NativeVisibilityScopeCategory, PrivacyClass, QualityScore,
    RedactionStatus, SchemaVersion, SecurityFactId, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_NATIVE_SAMPLER_REFS: usize = 32;
pub const MAX_NATIVE_SAMPLER_TOPICS: usize = 12;
pub const MAX_NATIVE_SAMPLER_FIELDS: usize = 24;
pub const MAX_NATIVE_SAMPLER_EVENTS: usize = 8;
pub const MAX_NATIVE_SAMPLER_MAPPINGS: usize = 32;
pub const MAX_NATIVE_RUNTIME_BATCHES: usize = 16;
pub const MAX_NATIVE_RUNTIME_RECORDS: usize = 64;
pub const MAX_NATIVE_RUNTIME_COUNTERS: usize = 16;

pub const NATIVE_SAMPLER_ALLOWED_TOPICS: &[&str] = &[
    "native.sampler.contract",
    "native.sampler.readiness",
    "native.sampler.review",
    "native.sampler.runtime_status",
    "native.health.metadata",
    "native.service.metadata",
    "native.process.metadata",
    "native.process_parent.metadata",
    "endpoint.native_health.category_fact",
    "endpoint.service.category_fact",
    "endpoint.process.category_fact",
    "endpoint.process_parent.category_fact",
    "native.visibility.status",
    "security.visibility.status",
    "security.visibility.degraded",
    "audit.native_sampler_review",
    "audit.native_sampler_runtime",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeSamplerContractError {
    EmptyField(&'static str),
    UnsafeField(&'static str),
    BoundedFieldTooLarge(&'static str),
    UnsafeSamplerState(&'static str),
}

impl fmt::Display for NativeSamplerContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains an unsafe marker"),
            Self::BoundedFieldTooLarge(field) => write!(formatter, "{field} exceeds its limit"),
            Self::UnsafeSamplerState(field) => {
                write!(
                    formatter,
                    "{field} is not allowed for native sampler readiness"
                )
            }
        }
    }
}

impl std::error::Error for NativeSamplerContractError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSamplerCategory {
    NativeHostVisibilitySampler,
    ProcessMetadataSampler,
    ProcessNetworkAttributionSampler,
    ServiceMetadataSampler,
    AutorunPersistenceMetadataSampler,
    FileActivitySummarySampler,
    RegistrySummarySampler,
    EndpointNetworkAttributionSampler,
    NativeHealthProbeSampler,
    NativeResponseCapabilityPlaceholder,
}

impl NativeSamplerCategory {
    pub fn capability_category(&self) -> AuthorizedNativeCapabilityCategory {
        match self {
            Self::NativeHostVisibilitySampler => {
                AuthorizedNativeCapabilityCategory::NativeHostVisibility
            }
            Self::ProcessMetadataSampler => {
                AuthorizedNativeCapabilityCategory::ProcessMetadataVisibility
            }
            Self::ProcessNetworkAttributionSampler => {
                AuthorizedNativeCapabilityCategory::ProcessNetworkAttributionVisibility
            }
            Self::ServiceMetadataSampler => {
                AuthorizedNativeCapabilityCategory::ServiceMetadataVisibility
            }
            Self::AutorunPersistenceMetadataSampler => {
                AuthorizedNativeCapabilityCategory::AutorunPersistenceVisibility
            }
            Self::FileActivitySummarySampler => {
                AuthorizedNativeCapabilityCategory::FileActivitySummaryVisibility
            }
            Self::RegistrySummarySampler => {
                AuthorizedNativeCapabilityCategory::RegistrySummaryVisibility
            }
            Self::EndpointNetworkAttributionSampler => {
                AuthorizedNativeCapabilityCategory::EndpointNetworkAttributionVisibility
            }
            Self::NativeHealthProbeSampler => AuthorizedNativeCapabilityCategory::NativeHealthProbe,
            Self::NativeResponseCapabilityPlaceholder => {
                AuthorizedNativeCapabilityCategory::NativeResponseCapabilityPlaceholder
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSamplerAuthorizationMode {
    ExplicitSessionBoundFutureActivation,
    PermissionRequired,
    NotGrantableResponsePlaceholder,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSamplerPlatformCategory {
    WindowsNativeExtensionFuture,
    UnsupportedPortableDefault,
    StatusOnlyCrossPlatform,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSamplerSamplingModeDeclaration {
    ReadOnlySnapshotMetadata,
    ReadOnlyAppendSummary,
    HealthStatusOnly,
    ResponsePlaceholderNoTelemetry,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSamplerRetentionModeCategory {
    NoRawRetention,
    RawEndpointRetentionRejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSamplerPrivacyBoundaryCategory {
    SentinelOwnedAppScopedStateOnly,
    BoundedEndpointMetadataFuture,
    ResponsePlaceholderOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FutureNativeFieldCategory {
    ProcessCategory,
    ParentProcessCategory,
    ParentChildRelationCategory,
    ExecutionContextCategory,
    SignednessBucket,
    BinaryTrustBucket,
    PrivilegeContextCategory,
    IntegrityContextBucket,
    SessionContextCategory,
    LifecycleStateBucket,
    PopulationCountBucket,
    StartCountBucket,
    StopCountBucket,
    ChangedCategoryFlag,
    PathCategory,
    CommandLineRiskCategory,
    ServiceCategory,
    AutorunCategory,
    RegistryActivityCategory,
    FileActivityCategory,
    EndpointNetworkRelationCategory,
    DestinationServiceCategory,
    TimestampBucket,
    CountBucket,
    ConfidenceHint,
    EvidenceRef,
    ProvenanceId,
    RedactionStatus,
    MissingVisibilityFlags,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FutureEndpointSecurityFactCategory {
    EndpointProcessCategoryFact,
    EndpointProcessParentCategoryFact,
    EndpointProcessNetworkRelationCategoryFact,
    EndpointServiceCategoryFact,
    EndpointAutorunCategoryFact,
    EndpointPersistenceCategoryFact,
    EndpointFileActivityCategoryFact,
    EndpointRegistryActivityCategoryFact,
    EndpointNativeHealthCategoryFact,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSamplerReadinessState {
    ReadyWhenSamplerImplemented,
    BlockedPortableDefault,
    BlockedPermissionRequired,
    BlockedPermissionRevoked,
    BlockedPermissionDisabled,
    BlockedUnsupportedPlatform,
    BlockedMissingNativeService,
    BlockedSchemaUnsafe,
    BlockedResponseCapable,
    BlockedRetentionPolicy,
    BlockedRedactionPolicy,
    BlockedTopicNotDeclared,
    DegradedMissingVisibility,
    NotImplemented,
}

impl NativeSamplerReadinessState {
    pub fn is_blocked(&self) -> bool {
        matches!(
            self,
            Self::BlockedPortableDefault
                | Self::BlockedPermissionRequired
                | Self::BlockedPermissionRevoked
                | Self::BlockedPermissionDisabled
                | Self::BlockedUnsupportedPlatform
                | Self::BlockedMissingNativeService
                | Self::BlockedSchemaUnsafe
                | Self::BlockedResponseCapable
                | Self::BlockedRetentionPolicy
                | Self::BlockedRedactionPolicy
                | Self::BlockedTopicNotDeclared
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSamplerRequiredUserActionCategory {
    None,
    GrantNativePermission,
    ReauthorizeAfterRevocation,
    EnableCapability,
    FutureNativeServiceRequired,
    FixSchemaDeclaration,
    DeclareEventTopics,
    SeparateResponsePolicyRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSamplerSchemaSafetyState {
    SafeDeclarationOnly,
    UnsafeForbiddenField,
    UnsafeTopicDeclaration,
    UnsafeRetentionPolicy,
    ResponseCapableBlocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSamplerQualityEffect {
    ReadinessOnlyNoEvidence,
    DegradesMissingEndpointVisibility,
    BlockedNoEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSamplerRuntimeState {
    NotImplemented,
    ReadinessBlocked,
    ReadyInactive,
    Activating,
    Active,
    Idle,
    Paused,
    Degraded,
    Stopping,
    Stopped,
    Revoked,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSamplerRuntimeAction {
    PreviewActivation,
    Activate,
    SampleNow,
    ScheduledSample,
    Pause,
    Resume,
    Stop,
    Revoke,
    RefreshStatus,
    ReadLatestBoundedBatch,
    ClearInactiveRuntimeState,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProviderCategory {
    WindowsServiceControlManager,
    WindowsToolhelpProcessSnapshot,
    UnsupportedPlatform,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRuntimePlatformCategory {
    Windows,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProviderAvailabilityState {
    Available,
    ProviderUnavailable,
    UnsupportedPlatform,
    Unauthorized,
    Degraded,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRuntimeHealthState {
    Healthy,
    Idle,
    Paused,
    Degraded,
    Backpressure,
    Timeout,
    Revoked,
    Failed,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeServiceCategory {
    OperatingSystemCore,
    Security,
    Network,
    RemoteManagement,
    Update,
    Storage,
    ApplicationSupport,
    UserInstalled,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeServiceStateBucket {
    Running,
    Stopped,
    Paused,
    Transitional,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeServiceStartupTypeBucket {
    Automatic,
    DelayedAutomatic,
    Manual,
    Disabled,
    TriggerBased,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeServiceTrustCategory {
    OperatingSystemOwned,
    SecurityRelevant,
    ThirdPartyCategory,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSignednessBucket {
    SignedTrusted,
    SignedUnknown,
    UnsignedUnknown,
    NotChecked,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePrivilegeContextCategory {
    LocalSystemLike,
    ServiceAccountLike,
    UserContextUnknown,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeHostCriticalityCategory {
    Critical,
    Important,
    Standard,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProcessCategory {
    OperatingSystemCore,
    ServiceHost,
    Security,
    Browser,
    OfficeProductivity,
    ScriptingRuntime,
    CommandShell,
    DevelopmentTool,
    AdministrativeTool,
    RemoteManagement,
    NetworkingTool,
    UpdaterInstaller,
    ApplicationSupport,
    UserApplication,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProcessExecutionContextCategory {
    Interactive,
    Service,
    Scheduled,
    System,
    Background,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProcessParentRelationCategory {
    SystemToService,
    ServiceToWorker,
    ShellToScript,
    BrowserToHelper,
    OfficeToHelper,
    UpdaterToInstaller,
    ApplicationToChild,
    AdministrativeToolToChild,
    UnknownToUnknown,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProcessTrustCategory {
    OperatingSystemOwned,
    SecurityRelevant,
    AllowlistedCategory,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeIntegrityContextBucket {
    SystemLike,
    ElevatedUnknown,
    StandardUnknown,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSessionContextCategory {
    SystemLike,
    ServiceLike,
    InteractiveUnknown,
    BackgroundUnknown,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProcessLifecycleStateBucket {
    ObservedRunning,
    NewlyObserved,
    NoLongerObserved,
    PopulationChanged,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerSchemaDeclaration {
    pub schema_id: NativeSamplerSchemaId,
    pub schema_version: SchemaVersion,
    pub field_categories: Vec<FutureNativeFieldCategory>,
    pub declared_field_labels: Vec<String>,
    pub output_fact_categories: Vec<FutureEndpointSecurityFactCategory>,
    pub declared_only: bool,
    pub raw_fields_allowed: bool,
    pub redaction_status: RedactionStatus,
}

impl NativeSamplerSchemaDeclaration {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text_list(
            "native sampler schema field labels",
            &self.declared_field_labels,
            MAX_NATIVE_SAMPLER_FIELDS,
        )?;
        if self.field_categories.is_empty() || self.output_fact_categories.is_empty() {
            return Err(NativeSamplerContractError::EmptyField(
                "native sampler schema categories",
            ));
        }
        if self.field_categories.len() > MAX_NATIVE_SAMPLER_FIELDS
            || self.output_fact_categories.len() > MAX_NATIVE_SAMPLER_FIELDS
        {
            return Err(NativeSamplerContractError::BoundedFieldTooLarge(
                "native sampler schema categories",
            ));
        }
        if !self.declared_only
            || self.raw_fields_allowed
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler schema policy",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerContract {
    pub contract_id: NativeSamplerId,
    pub sampler_id: String,
    pub category: NativeSamplerCategory,
    pub required_capability_id: String,
    pub required_permission_state: NativePermissionState,
    pub authorization_mode: NativeSamplerAuthorizationMode,
    pub read_only: bool,
    pub response_capable: bool,
    pub readiness_state: NativeSamplerReadinessState,
    pub supported_platform: NativeSamplerPlatformCategory,
    pub portable_default_available: bool,
    pub sampling_mode: NativeSamplerSamplingModeDeclaration,
    pub max_records_per_tick: u32,
    pub max_bytes_per_tick: u32,
    pub output_fact_categories: Vec<FutureEndpointSecurityFactCategory>,
    pub declared_event_topics: Vec<String>,
    pub redaction_policy_id: String,
    pub privacy_boundary: NativeSamplerPrivacyBoundaryCategory,
    pub retention_mode: NativeSamplerRetentionModeCategory,
    pub visibility_scope: NativeVisibilityScopeCategory,
    pub schema: NativeSamplerSchemaDeclaration,
    pub degraded_reason: Option<String>,
    pub missing_prerequisite_flags: Vec<String>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub privacy_class: PrivacyClass,
    pub last_reviewed_time_bucket: Option<String>,
    pub sampler_implemented: bool,
    pub sampler_active: bool,
    pub telemetry_collection_active: bool,
    pub response_execution_allowed: bool,
    pub automatic_llm_calls: bool,
}

impl NativeSamplerContract {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native sampler id", &self.sampler_id)?;
        validate_safe_text(
            "native sampler required capability id",
            &self.required_capability_id,
        )?;
        validate_safe_text("native sampler redaction policy", &self.redaction_policy_id)?;
        validate_optional_safe_text(
            "native sampler degraded reason",
            self.degraded_reason.as_deref(),
        )?;
        validate_optional_safe_text(
            "native sampler reviewed bucket",
            self.last_reviewed_time_bucket.as_deref(),
        )?;
        validate_safe_text("native sampler provenance id", &self.provenance_id)?;
        validate_safe_text_list(
            "native sampler missing prerequisites",
            &self.missing_prerequisite_flags,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        validate_declared_topics(&self.declared_event_topics)?;
        self.schema.validate()?;
        if self.output_fact_categories.is_empty()
            || self.output_fact_categories.len() > MAX_NATIVE_SAMPLER_FIELDS
            || self.audit_refs.len() > MAX_NATIVE_SAMPLER_REFS
        {
            return Err(NativeSamplerContractError::BoundedFieldTooLarge(
                "native sampler refs",
            ));
        }
        if self.retention_mode != NativeSamplerRetentionModeCategory::NoRawRetention {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler retention",
            ));
        }
        if !self.read_only
            || self.portable_default_available
            || self.sampler_active
            || self.telemetry_collection_active
            || self.response_execution_allowed
            || self.automatic_llm_calls
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler runtime flags",
            ));
        }
        if self.sampler_implemented
            && !matches!(
                self.category,
                NativeSamplerCategory::NativeHealthProbeSampler
                    | NativeSamplerCategory::ServiceMetadataSampler
                    | NativeSamplerCategory::ProcessMetadataSampler
            )
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler implemented category",
            ));
        }
        if self.response_capable
            && self.category != NativeSamplerCategory::NativeResponseCapabilityPlaceholder
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler response marker",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerAuthorizationReview {
    pub review_id: NativeSamplerReviewId,
    pub sampler_id: String,
    pub category: NativeSamplerCategory,
    pub capability_id: String,
    pub permission_state: NativePermissionState,
    pub readiness_state: NativeSamplerReadinessState,
    pub allowed: bool,
    pub blocked_reason: Option<NativeSamplerReadinessState>,
    pub degraded_reason: Option<String>,
    pub missing_prerequisite_flags: Vec<String>,
    pub required_user_action: NativeSamplerRequiredUserActionCategory,
    pub future_collection_allowed: bool,
    pub future_response_allowed: bool,
    pub sampler_active: bool,
    pub telemetry_collection_started: bool,
    pub response_execution_started: bool,
    pub service_installation_started: bool,
    pub driver_loading_started: bool,
    pub host_mutation_performed: bool,
    pub automatic_llm_calls: bool,
    pub schema_safety_state: NativeSamplerSchemaSafetyState,
    pub evidence_quality_effect: NativeSamplerQualityEffect,
    pub report_export_suitable: bool,
    pub declared_event_topics: Vec<String>,
    pub output_fact_categories: Vec<FutureEndpointSecurityFactCategory>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub time_bucket: String,
    pub redaction_status: RedactionStatus,
}

impl NativeSamplerAuthorizationReview {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native sampler review sampler id", &self.sampler_id)?;
        validate_safe_text("native sampler review capability id", &self.capability_id)?;
        validate_optional_safe_text(
            "native sampler review degraded reason",
            self.degraded_reason.as_deref(),
        )?;
        validate_safe_text_list(
            "native sampler review missing prerequisites",
            &self.missing_prerequisite_flags,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        validate_declared_topics(&self.declared_event_topics)?;
        validate_safe_text("native sampler review provenance id", &self.provenance_id)?;
        validate_safe_text("native sampler review time bucket", &self.time_bucket)?;
        if self.audit_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.output_fact_categories.len() > MAX_NATIVE_SAMPLER_FIELDS
        {
            return Err(NativeSamplerContractError::BoundedFieldTooLarge(
                "native sampler review refs",
            ));
        }
        if self.future_response_allowed
            || self.sampler_active
            || self.telemetry_collection_started
            || self.response_execution_started
            || self.service_installation_started
            || self.driver_loading_started
            || self.host_mutation_performed
            || self.automatic_llm_calls
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler review side effects",
            ));
        }
        if self.readiness_state.is_blocked() && self.blocked_reason.is_none() {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler review blocked reason",
            ));
        }
        if self.allowed
            && self.readiness_state != NativeSamplerReadinessState::ReadyWhenSamplerImplemented
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler review allowed state",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerStatusEvent {
    pub topic: String,
    pub sampler_id: String,
    pub category: NativeSamplerCategory,
    pub capability_id: String,
    pub readiness_state: NativeSamplerReadinessState,
    pub permission_state: NativePermissionState,
    pub health_state: String,
    pub degraded_reason: Option<String>,
    pub missing_prerequisite_flags: Vec<String>,
    pub schema_version: SchemaVersion,
    pub declared_output_categories: Vec<FutureEndpointSecurityFactCategory>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub time_bucket: String,
    pub redaction_status: RedactionStatus,
}

impl NativeSamplerStatusEvent {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_declared_topics(std::slice::from_ref(&self.topic))?;
        validate_safe_text("native sampler event sampler id", &self.sampler_id)?;
        validate_safe_text("native sampler event capability id", &self.capability_id)?;
        validate_safe_text("native sampler event health", &self.health_state)?;
        validate_optional_safe_text(
            "native sampler event degraded reason",
            self.degraded_reason.as_deref(),
        )?;
        validate_safe_text_list(
            "native sampler event missing prerequisites",
            &self.missing_prerequisite_flags,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        validate_safe_text("native sampler event provenance id", &self.provenance_id)?;
        validate_safe_text("native sampler event time bucket", &self.time_bucket)?;
        if self.audit_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.declared_output_categories.len() > MAX_NATIVE_SAMPLER_FIELDS
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler event refs",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FutureSecurityFactMappingDeclaration {
    pub mapping_id: FutureSecurityFactMappingId,
    pub sampler_id: String,
    pub sampler_category: NativeSamplerCategory,
    pub output_fact_category: FutureEndpointSecurityFactCategory,
    pub declared_field_categories: Vec<FutureNativeFieldCategory>,
    pub declared_only: bool,
    pub emits_security_facts_now: bool,
    pub quality_gate_required: bool,
    pub visibility_gate_required: bool,
    pub report_export_suitability_gate: bool,
    pub forbidden_raw_fields_rejected: bool,
    pub provenance_id: String,
    pub schema_version: SchemaVersion,
    pub redaction_status: RedactionStatus,
}

impl FutureSecurityFactMappingDeclaration {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native sampler mapping sampler id", &self.sampler_id)?;
        validate_safe_text("native sampler mapping provenance id", &self.provenance_id)?;
        if self.declared_field_categories.is_empty()
            || self.declared_field_categories.len() > MAX_NATIVE_SAMPLER_FIELDS
        {
            return Err(NativeSamplerContractError::BoundedFieldTooLarge(
                "native sampler mapping fields",
            ));
        }
        if !self.declared_only
            || self.emits_security_facts_now
            || !self.quality_gate_required
            || !self.visibility_gate_required
            || !self.report_export_suitability_gate
            || !self.forbidden_raw_fields_rejected
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler mapping policy",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FutureSecurityFactMappingSummary {
    pub mappings: Vec<FutureSecurityFactMappingDeclaration>,
    pub mapping_count: u32,
    pub emitted_security_fact_count: u32,
    pub sampler_refs: Vec<String>,
    pub generated_at: Timestamp,
}

impl FutureSecurityFactMappingSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        if self.mappings.len() > MAX_NATIVE_SAMPLER_MAPPINGS
            || self.sampler_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.emitted_security_fact_count != 0
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler mapping summary",
            ));
        }
        validate_safe_text_list(
            "native sampler mapping summary sampler refs",
            &self.sampler_refs,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        for mapping in &self.mappings {
            mapping.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerRuntimeActionRequest {
    pub sampler_id: String,
    pub action: NativeSamplerRuntimeAction,
    pub explicit_user_action: bool,
    pub enable_interval_sampling: bool,
    pub max_records_per_sample: u32,
    pub max_bytes_per_sample: u32,
    pub timeout_millis: u32,
    pub reason_redacted: String,
}

impl NativeSamplerRuntimeActionRequest {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native sampler runtime action sampler id", &self.sampler_id)?;
        validate_safe_text(
            "native sampler runtime action reason",
            &self.reason_redacted,
        )?;
        if matches!(
            self.action,
            NativeSamplerRuntimeAction::Activate
                | NativeSamplerRuntimeAction::SampleNow
                | NativeSamplerRuntimeAction::Pause
                | NativeSamplerRuntimeAction::Resume
                | NativeSamplerRuntimeAction::Stop
                | NativeSamplerRuntimeAction::Revoke
                | NativeSamplerRuntimeAction::ClearInactiveRuntimeState
        ) && !self.explicit_user_action
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler runtime explicit user action",
            ));
        }
        if self.action == NativeSamplerRuntimeAction::ScheduledSample && self.explicit_user_action {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native scheduled sample must use scheduler authorization",
            ));
        }
        if self.max_records_per_sample == 0
            || self.max_records_per_sample > 512
            || self.max_bytes_per_sample == 0
            || self.max_bytes_per_sample > 1_048_576
            || self.timeout_millis == 0
            || self.timeout_millis > 30_000
        {
            return Err(NativeSamplerContractError::BoundedFieldTooLarge(
                "native sampler runtime bounds",
            ));
        }
        if self.enable_interval_sampling {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler runtime interval enablement must use scheduler control plane",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerActivationPreview {
    pub sampler_id: String,
    pub category: NativeSamplerCategory,
    pub readiness_state: NativeSamplerReadinessState,
    pub current_runtime_state: NativeSamplerRuntimeState,
    pub activation_allowed: bool,
    pub blocked_reason: Option<String>,
    pub state_change_performed: bool,
    pub telemetry_collection_started: bool,
    pub response_execution_started: bool,
    pub service_installation_started: bool,
    pub driver_loading_started: bool,
    pub host_mutation_performed: bool,
    pub automatic_llm_calls: bool,
    pub boundary_summary_redacted: String,
}

impl NativeSamplerActivationPreview {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text(
            "native sampler activation preview sampler id",
            &self.sampler_id,
        )?;
        validate_optional_safe_text(
            "native sampler activation preview blocked reason",
            self.blocked_reason.as_deref(),
        )?;
        validate_safe_text(
            "native sampler activation preview boundary",
            &self.boundary_summary_redacted,
        )?;
        if self.state_change_performed
            || self.telemetry_collection_started
            || self.response_execution_started
            || self.service_installation_started
            || self.driver_loading_started
            || self.host_mutation_performed
            || self.automatic_llm_calls
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler activation preview side effects",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerCounterSummary {
    pub sampled_record_count: u32,
    pub sampled_record_count_bucket: String,
    pub skipped_record_count: u32,
    pub skipped_record_count_bucket: String,
    pub malformed_record_count: u32,
    pub rejected_record_count: u32,
    pub duplicate_suppressed_count: u32,
    pub backpressure_event_count: u32,
    pub timeout_count: u32,
    pub duration_bucket: String,
    pub bytes_processed_bucket: String,
    pub unknown_category_ratio_bucket: String,
}

impl NativeSamplerCounterSummary {
    pub fn empty() -> Self {
        Self {
            sampled_record_count: 0,
            sampled_record_count_bucket: "none".to_string(),
            skipped_record_count: 0,
            skipped_record_count_bucket: "none".to_string(),
            malformed_record_count: 0,
            rejected_record_count: 0,
            duplicate_suppressed_count: 0,
            backpressure_event_count: 0,
            timeout_count: 0,
            duration_bucket: "none".to_string(),
            bytes_processed_bucket: "none".to_string(),
            unknown_category_ratio_bucket: "none".to_string(),
        }
    }

    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text(
            "native sampler counter sampled bucket",
            &self.sampled_record_count_bucket,
        )?;
        validate_safe_text(
            "native sampler counter skipped bucket",
            &self.skipped_record_count_bucket,
        )?;
        validate_safe_text(
            "native sampler counter duration bucket",
            &self.duration_bucket,
        )?;
        validate_safe_text(
            "native sampler counter bytes bucket",
            &self.bytes_processed_bucket,
        )?;
        validate_safe_text(
            "native sampler counter unknown ratio bucket",
            &self.unknown_category_ratio_bucket,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerRuntimeStatus {
    pub sampler_id: String,
    pub category: NativeSamplerCategory,
    pub capability_id: String,
    pub readiness_state: NativeSamplerReadinessState,
    pub runtime_state: NativeSamplerRuntimeState,
    pub permission_state: NativePermissionState,
    pub provider_category: NativeProviderCategory,
    pub platform_category: NativeRuntimePlatformCategory,
    pub provider_availability_state: NativeProviderAvailabilityState,
    pub health_state: NativeRuntimeHealthState,
    pub degraded_reason: Option<String>,
    pub missing_prerequisite_flags: Vec<String>,
    pub interval_sampling_enabled: bool,
    pub max_records_per_sample: u32,
    pub max_bytes_per_sample: u32,
    pub timeout_millis: u32,
    pub queue_size_bound: u32,
    pub latest_batch_id: Option<NativeSamplerBatchId>,
    pub latest_sample_time_bucket: Option<String>,
    pub counters: NativeSamplerCounterSummary,
    pub emitted_topics: Vec<String>,
    pub fact_refs: Vec<SecurityFactId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub telemetry_collection_active: bool,
    pub response_execution_allowed: bool,
    pub service_installation_started: bool,
    pub driver_loading_started: bool,
    pub host_mutation_performed: bool,
    pub automatic_llm_calls: bool,
}

impl NativeSamplerRuntimeStatus {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native sampler runtime status sampler id", &self.sampler_id)?;
        validate_safe_text(
            "native sampler runtime status capability id",
            &self.capability_id,
        )?;
        validate_optional_safe_text(
            "native sampler runtime degraded reason",
            self.degraded_reason.as_deref(),
        )?;
        validate_safe_text_list(
            "native sampler runtime missing prerequisites",
            &self.missing_prerequisite_flags,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        if let Some(bucket) = &self.latest_sample_time_bucket {
            validate_safe_text("native sampler runtime sample bucket", bucket)?;
        }
        self.counters.validate()?;
        validate_declared_topics(&self.emitted_topics)?;
        validate_safe_text("native sampler runtime provenance", &self.provenance_id)?;
        if self.fact_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.evidence_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.audit_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.max_records_per_sample == 0
            || self.max_records_per_sample > 512
            || self.max_bytes_per_sample == 0
            || self.max_bytes_per_sample > 1_048_576
            || self.timeout_millis == 0
            || self.timeout_millis > 30_000
            || self.queue_size_bound > 512
            || self.response_execution_allowed
            || self.service_installation_started
            || self.driver_loading_started
            || self.host_mutation_performed
            || self.automatic_llm_calls
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler runtime status bounds or forbidden flags",
            ));
        }
        if self.telemetry_collection_active
            && !matches!(
                self.runtime_state,
                NativeSamplerRuntimeState::Active | NativeSamplerRuntimeState::Idle
            )
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler runtime telemetry state",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NativeHealthMetadataRecord {
    pub health_observation_id: NativeHealthObservationId,
    pub sampler_id: String,
    pub provider_category: NativeProviderCategory,
    pub platform_category: NativeRuntimePlatformCategory,
    pub provider_availability_state: NativeProviderAvailabilityState,
    pub authorization_state: NativePermissionState,
    pub runtime_state: NativeSamplerRuntimeState,
    pub health_state: NativeRuntimeHealthState,
    pub degraded_reason: Option<String>,
    pub missing_prerequisite_flags: Vec<String>,
    pub sample_duration_bucket: String,
    pub sampled_record_count_bucket: String,
    pub skipped_record_count_bucket: String,
    pub malformed_record_count_bucket: String,
    pub rejected_record_count_bucket: String,
    pub timeout_bucket: String,
    pub last_sample_time_bucket: String,
    pub schema_version: SchemaVersion,
    pub provenance_id: String,
    pub audit_refs: Vec<AuditId>,
    pub redaction_status: RedactionStatus,
    pub quality_score: QualityScore,
}

impl NativeHealthMetadataRecord {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native health sampler id", &self.sampler_id)?;
        validate_optional_safe_text(
            "native health degraded reason",
            self.degraded_reason.as_deref(),
        )?;
        validate_safe_text_list(
            "native health missing prerequisites",
            &self.missing_prerequisite_flags,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        for value in [
            &self.sample_duration_bucket,
            &self.sampled_record_count_bucket,
            &self.skipped_record_count_bucket,
            &self.malformed_record_count_bucket,
            &self.rejected_record_count_bucket,
            &self.timeout_bucket,
            &self.last_sample_time_bucket,
            &self.provenance_id,
        ] {
            validate_safe_text("native health metadata bucket", value)?;
        }
        if self.audit_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native health metadata refs",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NativeServiceMetadataRecord {
    pub service_observation_id: NativeServiceObservationId,
    pub service_category: NativeServiceCategory,
    pub service_state_bucket: NativeServiceStateBucket,
    pub startup_type_bucket: NativeServiceStartupTypeBucket,
    pub trust_category: NativeServiceTrustCategory,
    pub signedness_bucket: NativeSignednessBucket,
    pub privilege_context_category: NativePrivilegeContextCategory,
    pub host_criticality_category: NativeHostCriticalityCategory,
    pub first_seen_in_session: bool,
    pub count_bucket: String,
    pub changed_state: bool,
    pub sampler_id: String,
    pub sample_batch_id: NativeSamplerBatchId,
    pub time_bucket: String,
    pub confidence_hint: QualityScore,
    pub evidence_refs: Vec<EvidenceId>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub missing_visibility_flags: Vec<String>,
}

impl NativeServiceMetadataRecord {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native service sampler id", &self.sampler_id)?;
        validate_safe_text("native service count bucket", &self.count_bucket)?;
        validate_safe_text("native service time bucket", &self.time_bucket)?;
        validate_safe_text("native service provenance", &self.provenance_id)?;
        validate_safe_text_list(
            "native service missing visibility",
            &self.missing_visibility_flags,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        if self.evidence_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native service metadata refs",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NativeProcessMetadataRecord {
    pub process_observation_id: NativeProcessObservationId,
    pub process_category: NativeProcessCategory,
    pub parent_process_category: NativeProcessCategory,
    pub relation_category: NativeProcessParentRelationCategory,
    pub execution_context_category: NativeProcessExecutionContextCategory,
    pub trust_category: NativeProcessTrustCategory,
    pub signedness_bucket: NativeSignednessBucket,
    pub privilege_context_category: NativePrivilegeContextCategory,
    pub integrity_context_bucket: NativeIntegrityContextBucket,
    pub session_context_category: NativeSessionContextCategory,
    pub lifecycle_state_bucket: NativeProcessLifecycleStateBucket,
    pub first_seen_in_session: bool,
    pub population_count_bucket: String,
    pub start_count_bucket: String,
    pub stop_count_bucket: String,
    pub changed_category: bool,
    pub sampler_id: String,
    pub sample_batch_id: NativeSamplerBatchId,
    pub time_bucket: String,
    pub confidence_hint: QualityScore,
    pub evidence_refs: Vec<EvidenceId>,
    pub provenance_id: String,
    pub redaction_status: RedactionStatus,
    pub missing_visibility_flags: Vec<String>,
}

impl NativeProcessMetadataRecord {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native process sampler id", &self.sampler_id)?;
        validate_safe_text(
            "native process population bucket",
            &self.population_count_bucket,
        )?;
        validate_safe_text("native process start bucket", &self.start_count_bucket)?;
        validate_safe_text("native process stop bucket", &self.stop_count_bucket)?;
        validate_safe_text("native process time bucket", &self.time_bucket)?;
        validate_safe_text("native process provenance", &self.provenance_id)?;
        validate_safe_text_list(
            "native process missing visibility",
            &self.missing_visibility_flags,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        if self.evidence_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native process metadata refs",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NativeSamplerRuntimeBatch {
    pub batch_id: NativeSamplerBatchId,
    pub sampler_id: String,
    pub category: NativeSamplerCategory,
    pub runtime_state: NativeSamplerRuntimeState,
    pub provider_category: NativeProviderCategory,
    pub platform_category: NativeRuntimePlatformCategory,
    pub health_record: Option<NativeHealthMetadataRecord>,
    pub service_records: Vec<NativeServiceMetadataRecord>,
    pub process_records: Vec<NativeProcessMetadataRecord>,
    pub counters: NativeSamplerCounterSummary,
    pub emitted_topics: Vec<String>,
    pub fact_refs: Vec<SecurityFactId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub audit_refs: Vec<AuditId>,
    pub provenance_id: String,
    pub time_bucket: String,
    pub redaction_status: RedactionStatus,
    pub response_execution_allowed: bool,
    pub host_mutation_performed: bool,
    pub automatic_llm_calls: bool,
}

impl NativeSamplerRuntimeBatch {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native sampler batch sampler id", &self.sampler_id)?;
        validate_declared_topics(&self.emitted_topics)?;
        validate_safe_text("native sampler batch provenance", &self.provenance_id)?;
        validate_safe_text("native sampler batch time bucket", &self.time_bucket)?;
        self.counters.validate()?;
        if let Some(health) = &self.health_record {
            health.validate()?;
        }
        if self.service_records.len() > MAX_NATIVE_RUNTIME_RECORDS
            || self.process_records.len() > MAX_NATIVE_RUNTIME_RECORDS
            || self.fact_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.evidence_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.audit_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.response_execution_allowed
            || self.host_mutation_performed
            || self.automatic_llm_calls
            || self.redaction_status == RedactionStatus::RedactionRequired
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler batch policy",
            ));
        }
        for record in &self.service_records {
            record.validate()?;
        }
        for record in &self.process_records {
            record.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeServiceCategoryCount {
    pub service_category: NativeServiceCategory,
    pub count_bucket: String,
    pub observation_count: u32,
}

impl NativeServiceCategoryCount {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native service category count bucket", &self.count_bucket)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeServiceBucketCount {
    pub label: String,
    pub count_bucket: String,
    pub observation_count: u32,
}

impl NativeServiceBucketCount {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native service bucket label", &self.label)?;
        validate_safe_text("native service bucket count", &self.count_bucket)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeProcessCategoryCount {
    pub process_category: NativeProcessCategory,
    pub count_bucket: String,
    pub observation_count: u32,
}

impl NativeProcessCategoryCount {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native process category count bucket", &self.count_bucket)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeProcessBucketCount {
    pub label: String,
    pub count_bucket: String,
    pub observation_count: u32,
}

impl NativeProcessBucketCount {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native process bucket label", &self.label)?;
        validate_safe_text("native process bucket count", &self.count_bucket)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NativeSamplerRuntimeSummary {
    pub runtime_count: u32,
    pub active_count: u32,
    pub paused_count: u32,
    pub degraded_count: u32,
    pub stopped_count: u32,
    pub revoked_count: u32,
    pub latest_batch_refs: Vec<NativeSamplerBatchId>,
    pub fact_refs: Vec<SecurityFactId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub audit_refs: Vec<AuditId>,
    pub service_category_counts: Vec<NativeServiceCategoryCount>,
    pub service_state_counts: Vec<NativeServiceBucketCount>,
    pub startup_type_counts: Vec<NativeServiceBucketCount>,
    pub process_category_counts: Vec<NativeProcessCategoryCount>,
    pub parent_process_category_counts: Vec<NativeProcessCategoryCount>,
    pub process_relation_counts: Vec<NativeProcessBucketCount>,
    pub execution_context_counts: Vec<NativeProcessBucketCount>,
    pub process_trust_counts: Vec<NativeProcessBucketCount>,
    pub process_signedness_counts: Vec<NativeProcessBucketCount>,
    pub process_privilege_counts: Vec<NativeProcessBucketCount>,
    pub process_lifecycle_counts: Vec<NativeProcessBucketCount>,
    pub quality_bucket: String,
    pub service_visibility_available: bool,
    pub native_health_visibility_available: bool,
    pub process_visibility_available: bool,
    pub parent_process_visibility_available: bool,
    pub process_network_attribution_available: bool,
    pub packet_visibility_available: bool,
    pub response_execution_allowed: bool,
    pub edr_coverage_claimed: bool,
    pub automatic_llm_calls: bool,
    pub statuses: Vec<NativeSamplerRuntimeStatus>,
    pub generated_at: Timestamp,
}

impl NativeSamplerRuntimeSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text(
            "native sampler runtime quality bucket",
            &self.quality_bucket,
        )?;
        if self.latest_batch_refs.len() > MAX_NATIVE_RUNTIME_BATCHES
            || self.fact_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.evidence_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.audit_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.service_category_counts.len() > MAX_NATIVE_RUNTIME_COUNTERS
            || self.service_state_counts.len() > MAX_NATIVE_RUNTIME_COUNTERS
            || self.startup_type_counts.len() > MAX_NATIVE_RUNTIME_COUNTERS
            || self.process_category_counts.len() > MAX_NATIVE_RUNTIME_COUNTERS
            || self.parent_process_category_counts.len() > MAX_NATIVE_RUNTIME_COUNTERS
            || self.process_relation_counts.len() > MAX_NATIVE_RUNTIME_COUNTERS
            || self.execution_context_counts.len() > MAX_NATIVE_RUNTIME_COUNTERS
            || self.process_trust_counts.len() > MAX_NATIVE_RUNTIME_COUNTERS
            || self.process_signedness_counts.len() > MAX_NATIVE_RUNTIME_COUNTERS
            || self.process_privilege_counts.len() > MAX_NATIVE_RUNTIME_COUNTERS
            || self.process_lifecycle_counts.len() > MAX_NATIVE_RUNTIME_COUNTERS
            || self.statuses.len() > MAX_NATIVE_RUNTIME_RECORDS
            || self.process_network_attribution_available
            || self.packet_visibility_available
            || self.response_execution_allowed
            || self.edr_coverage_claimed
            || self.automatic_llm_calls
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler runtime summary policy",
            ));
        }
        for count in &self.service_category_counts {
            count.validate()?;
        }
        for count in self
            .service_state_counts
            .iter()
            .chain(self.startup_type_counts.iter())
        {
            count.validate()?;
        }
        for count in self
            .process_category_counts
            .iter()
            .chain(self.parent_process_category_counts.iter())
        {
            count.validate()?;
        }
        for count in self
            .process_relation_counts
            .iter()
            .chain(self.execution_context_counts.iter())
            .chain(self.process_trust_counts.iter())
            .chain(self.process_signedness_counts.iter())
            .chain(self.process_privilege_counts.iter())
            .chain(self.process_lifecycle_counts.iter())
        {
            count.validate()?;
        }
        for status in &self.statuses {
            status.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerRuntimeAuditEntry {
    pub audit_id: AuditId,
    pub sampler_id: String,
    pub action: NativeSamplerRuntimeAction,
    pub resulting_runtime_state: NativeSamplerRuntimeState,
    pub time_bucket: String,
    pub provenance_id: String,
    pub summary_redacted: String,
}

impl NativeSamplerRuntimeAuditEntry {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text("native runtime audit sampler id", &self.sampler_id)?;
        validate_safe_text("native runtime audit time bucket", &self.time_bucket)?;
        validate_safe_text("native runtime audit provenance", &self.provenance_id)?;
        validate_safe_text("native runtime audit summary", &self.summary_redacted)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NativeSamplerRuntimeActionResult {
    pub status: NativeSamplerRuntimeStatus,
    pub latest_batch: Option<NativeSamplerRuntimeBatch>,
    pub audit_entry: NativeSamplerRuntimeAuditEntry,
    pub emitted_topics: Vec<String>,
    pub preview_only: bool,
    pub telemetry_collection_started: bool,
    pub response_execution_started: bool,
    pub service_installation_started: bool,
    pub driver_loading_started: bool,
    pub host_mutation_performed: bool,
    pub automatic_llm_calls: bool,
}

impl NativeSamplerRuntimeActionResult {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        self.status.validate()?;
        if let Some(batch) = &self.latest_batch {
            batch.validate()?;
        }
        self.audit_entry.validate()?;
        validate_declared_topics(&self.emitted_topics)?;
        if self.response_execution_started
            || self.service_installation_started
            || self.driver_loading_started
            || self.host_mutation_performed
            || self.automatic_llm_calls
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native runtime action forbidden side effects",
            ));
        }
        if self.preview_only && self.telemetry_collection_started {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native runtime preview telemetry",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerReadinessSummary {
    pub contract_count: u32,
    pub review_count: u32,
    pub ready_when_implemented_count: u32,
    pub blocked_count: u32,
    pub degraded_count: u32,
    pub not_implemented_count: u32,
    pub active_sampler_count: u32,
    pub future_collection_allowed_count: u32,
    pub future_response_allowed_count: u32,
    pub endpoint_security_facts_emitted: bool,
    pub telemetry_collection_active: bool,
    pub response_execution_allowed: bool,
    pub automatic_llm_calls: bool,
    pub portable_default_active: bool,
    pub no_telemetry_collected: bool,
    pub contract_refs: Vec<String>,
    pub review_refs: Vec<NativeSamplerReviewId>,
    pub audit_refs: Vec<AuditId>,
    pub missing_endpoint_visibility_flags: Vec<String>,
    pub degraded_reasons: Vec<String>,
    pub generated_at: Timestamp,
}

impl NativeSamplerReadinessSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text_list(
            "native sampler summary contract refs",
            &self.contract_refs,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        validate_safe_text_list(
            "native sampler summary missing visibility",
            &self.missing_endpoint_visibility_flags,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        validate_safe_text_list(
            "native sampler summary degraded reasons",
            &self.degraded_reasons,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        if self.review_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.audit_refs.len() > MAX_NATIVE_SAMPLER_REFS
            || self.active_sampler_count != 0
            || self.future_response_allowed_count != 0
            || self.endpoint_security_facts_emitted
            || self.telemetry_collection_active
            || self.response_execution_allowed
            || self.automatic_llm_calls
            || !self.no_telemetry_collected
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "native sampler summary flags",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerReadinessDetail {
    pub contract: NativeSamplerContract,
    pub review: NativeSamplerAuthorizationReview,
    pub status_events: Vec<NativeSamplerStatusEvent>,
    pub future_mappings: Vec<FutureSecurityFactMappingDeclaration>,
}

impl NativeSamplerReadinessDetail {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        self.contract.validate()?;
        self.review.validate()?;
        if self.future_mappings.len() > MAX_NATIVE_SAMPLER_MAPPINGS {
            return Err(NativeSamplerContractError::BoundedFieldTooLarge(
                "native sampler detail mappings",
            ));
        }
        if self.status_events.len() > MAX_NATIVE_SAMPLER_EVENTS {
            return Err(NativeSamplerContractError::BoundedFieldTooLarge(
                "native sampler detail status events",
            ));
        }
        for event in &self.status_events {
            event.validate()?;
        }
        for mapping in &self.future_mappings {
            mapping.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSamplerBlockedSummary {
    pub blocked_count: u32,
    pub blocked_sampler_refs: Vec<String>,
    pub blocked_reasons: Vec<String>,
    pub revoked_sampler_refs: Vec<String>,
    pub disabled_sampler_refs: Vec<String>,
    pub unsafe_schema_sampler_refs: Vec<String>,
    pub response_capable_sampler_refs: Vec<String>,
    pub generated_at: Timestamp,
}

impl NativeSamplerBlockedSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text_list(
            "native sampler blocked refs",
            &self.blocked_sampler_refs,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        validate_safe_text_list(
            "native sampler blocked reasons",
            &self.blocked_reasons,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        validate_safe_text_list(
            "native sampler revoked refs",
            &self.revoked_sampler_refs,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        validate_safe_text_list(
            "native sampler disabled refs",
            &self.disabled_sampler_refs,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        validate_safe_text_list(
            "native sampler unsafe schema refs",
            &self.unsafe_schema_sampler_refs,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        validate_safe_text_list(
            "native sampler response refs",
            &self.response_capable_sampler_refs,
            MAX_NATIVE_SAMPLER_REFS,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingEndpointVisibilitySummary {
    pub missing_visibility_flags: Vec<String>,
    pub sampler_refs: Vec<String>,
    pub degraded_reasons: Vec<String>,
    pub endpoint_required_hypotheses_degraded: bool,
    pub native_attack_rows_supported: bool,
    pub edr_coverage_claimed: bool,
    pub generated_at: Timestamp,
}

impl MissingEndpointVisibilitySummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text_list(
            "missing endpoint visibility flags",
            &self.missing_visibility_flags,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        validate_safe_text_list(
            "missing endpoint visibility sampler refs",
            &self.sampler_refs,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        validate_safe_text_list(
            "missing endpoint visibility degraded reasons",
            &self.degraded_reasons,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        if self.native_attack_rows_supported || self.edr_coverage_claimed {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "missing endpoint visibility claims",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdrReadinessSummary {
    pub contract_ready_count: u32,
    pub readiness_approved_count: u32,
    pub implemented_sampler_count: u32,
    pub active_sampler_count: u32,
    pub blocked_sampler_count: u32,
    pub telemetry_collection_active: bool,
    pub response_execution_allowed: bool,
    pub endpoint_security_facts_emitted: bool,
    pub edr_coverage_claimed: bool,
    pub portable_default_active: bool,
    pub no_telemetry_collected: bool,
    pub sampler_refs: Vec<String>,
    pub audit_refs: Vec<AuditId>,
    pub missing_endpoint_visibility: MissingEndpointVisibilitySummary,
    pub generated_at: Timestamp,
}

impl EdrReadinessSummary {
    pub fn validate(&self) -> Result<(), NativeSamplerContractError> {
        validate_safe_text_list(
            "edr readiness sampler refs",
            &self.sampler_refs,
            MAX_NATIVE_SAMPLER_REFS,
        )?;
        self.missing_endpoint_visibility.validate()?;
        if self.implemented_sampler_count > 3
            || self.active_sampler_count > 3
            || self.response_execution_allowed
            || self.edr_coverage_claimed
            || (self.no_telemetry_collected
                && (self.telemetry_collection_active || self.endpoint_security_facts_emitted))
        {
            return Err(NativeSamplerContractError::UnsafeSamplerState(
                "edr readiness claims",
            ));
        }
        Ok(())
    }
}

fn validate_declared_topics(values: &[String]) -> Result<(), NativeSamplerContractError> {
    if values.is_empty() || values.len() > MAX_NATIVE_SAMPLER_TOPICS {
        return Err(NativeSamplerContractError::BoundedFieldTooLarge(
            "native sampler event topics",
        ));
    }
    for value in values {
        validate_safe_text("native sampler event topic", value)?;
        if !NATIVE_SAMPLER_ALLOWED_TOPICS.contains(&value.as_str()) {
            return Err(NativeSamplerContractError::UnsafeField(
                "native sampler event topic",
            ));
        }
    }
    Ok(())
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), NativeSamplerContractError> {
    value.map_or(Ok(()), |value| validate_safe_text(field, value))
}

fn validate_safe_text_list(
    field: &'static str,
    values: &[String],
    limit: usize,
) -> Result<(), NativeSamplerContractError> {
    if values.len() > limit {
        return Err(NativeSamplerContractError::BoundedFieldTooLarge(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), NativeSamplerContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(NativeSamplerContractError::EmptyField(field));
    }
    if trimmed.len() > 160 {
        return Err(NativeSamplerContractError::BoundedFieldTooLarge(field));
    }
    let normalized = trimmed.to_ascii_lowercase();
    if [
        "c:\\",
        "/home/",
        "/users/",
        "http://",
        "https://",
        "raw_process_name",
        "process_name",
        "process_id",
        "pid",
        "command_line",
        "cmdline",
        "full_path",
        "file_path",
        "executable_path",
        "filename",
        "registry_key",
        "raw_registry_key",
        "username",
        "user_name",
        "email",
        "ip_address",
        "source_ip",
        "destination_ip",
        "hostname",
        "host_name",
        "device_id",
        "sid",
        "token",
        "cookie",
        "credential",
        "certificate",
        "packet bytes",
        "payload",
        "memory_contents",
        "browser_secret",
        "private_marker",
        "plaintext_secret",
        "secret",
        "password",
        "api_key",
        "ssh_key",
        "tenant_id",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
    {
        return Err(NativeSamplerContractError::UnsafeField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> NativeSamplerSchemaDeclaration {
        NativeSamplerSchemaDeclaration {
            schema_id: NativeSamplerSchemaId::new_v4(),
            schema_version: SchemaVersion::new(1, 0, 0),
            field_categories: vec![
                FutureNativeFieldCategory::ProcessCategory,
                FutureNativeFieldCategory::SignednessBucket,
                FutureNativeFieldCategory::EvidenceRef,
            ],
            declared_field_labels: vec![
                "process_category".to_string(),
                "signedness_bucket".to_string(),
                "evidence_ref".to_string(),
            ],
            output_fact_categories: vec![
                FutureEndpointSecurityFactCategory::EndpointProcessCategoryFact,
            ],
            declared_only: true,
            raw_fields_allowed: false,
            redaction_status: RedactionStatus::Redacted,
        }
    }

    fn contract() -> NativeSamplerContract {
        NativeSamplerContract {
            contract_id: NativeSamplerId::new_v4(),
            sampler_id: "process_metadata_sampler".to_string(),
            category: NativeSamplerCategory::ProcessMetadataSampler,
            required_capability_id: "process_metadata_visibility".to_string(),
            required_permission_state: NativePermissionState::GrantedSession,
            authorization_mode:
                NativeSamplerAuthorizationMode::ExplicitSessionBoundFutureActivation,
            read_only: true,
            response_capable: false,
            readiness_state: NativeSamplerReadinessState::BlockedPortableDefault,
            supported_platform: NativeSamplerPlatformCategory::WindowsNativeExtensionFuture,
            portable_default_available: false,
            sampling_mode: NativeSamplerSamplingModeDeclaration::ReadOnlySnapshotMetadata,
            max_records_per_tick: 128,
            max_bytes_per_tick: 65536,
            output_fact_categories: vec![
                FutureEndpointSecurityFactCategory::EndpointProcessCategoryFact,
            ],
            declared_event_topics: vec![
                "native.sampler.contract".to_string(),
                "native.sampler.readiness".to_string(),
                "native.sampler.review".to_string(),
            ],
            redaction_policy_id: "native_sampler_redacted_categories_only".to_string(),
            privacy_boundary: NativeSamplerPrivacyBoundaryCategory::BoundedEndpointMetadataFuture,
            retention_mode: NativeSamplerRetentionModeCategory::NoRawRetention,
            visibility_scope: NativeVisibilityScopeCategory::ProcessSummary,
            schema: schema(),
            degraded_reason: Some("portable_default_native_unavailable".to_string()),
            missing_prerequisite_flags: vec!["native_permission_missing".to_string()],
            audit_refs: Vec::new(),
            provenance_id: "native_sampler_contract_catalog".to_string(),
            redaction_status: RedactionStatus::Redacted,
            privacy_class: PrivacyClass::Internal,
            last_reviewed_time_bucket: Some("current_session".to_string()),
            sampler_implemented: false,
            sampler_active: false,
            telemetry_collection_active: false,
            response_execution_allowed: false,
            automatic_llm_calls: false,
        }
    }

    #[test]
    fn sampler_contract_is_bounded_and_inactive() {
        let contract = contract();
        contract.validate().expect("safe contract");
        let json = serde_json::to_string(&contract).expect("json");
        assert!(!json.contains("process.exe"));
        assert!(!json.contains("C:\\"));
        assert!(!json.contains("token"));
    }

    #[test]
    fn schema_rejects_forbidden_future_field_labels() {
        let mut schema = schema();
        schema
            .declared_field_labels
            .push("raw_process_name".to_string());
        assert!(matches!(
            schema.validate(),
            Err(NativeSamplerContractError::UnsafeField(_))
        ));
    }

    #[test]
    fn contract_rejects_unsafe_topics_and_raw_retention() {
        let mut unsafe_topic_contract = contract();
        unsafe_topic_contract
            .declared_event_topics
            .push("security.fact".to_string());
        assert!(matches!(
            unsafe_topic_contract.validate(),
            Err(NativeSamplerContractError::UnsafeField(_))
        ));
        let mut raw_retention_contract = contract();
        raw_retention_contract.retention_mode =
            NativeSamplerRetentionModeCategory::RawEndpointRetentionRejected;
        assert!(matches!(
            raw_retention_contract.validate(),
            Err(NativeSamplerContractError::UnsafeSamplerState(_))
        ));
    }

    #[test]
    fn review_grant_ready_does_not_activate_sampler() {
        let review = NativeSamplerAuthorizationReview {
            review_id: NativeSamplerReviewId::new_v4(),
            sampler_id: "process_metadata_sampler".to_string(),
            category: NativeSamplerCategory::ProcessMetadataSampler,
            capability_id: "process_metadata_visibility".to_string(),
            permission_state: NativePermissionState::GrantedSession,
            readiness_state: NativeSamplerReadinessState::ReadyWhenSamplerImplemented,
            allowed: true,
            blocked_reason: None,
            degraded_reason: Some("ready_but_sampler_not_implemented".to_string()),
            missing_prerequisite_flags: vec!["sampler_runtime_not_implemented".to_string()],
            required_user_action: NativeSamplerRequiredUserActionCategory::None,
            future_collection_allowed: true,
            future_response_allowed: false,
            sampler_active: false,
            telemetry_collection_started: false,
            response_execution_started: false,
            service_installation_started: false,
            driver_loading_started: false,
            host_mutation_performed: false,
            automatic_llm_calls: false,
            schema_safety_state: NativeSamplerSchemaSafetyState::SafeDeclarationOnly,
            evidence_quality_effect: NativeSamplerQualityEffect::ReadinessOnlyNoEvidence,
            report_export_suitable: true,
            declared_event_topics: vec![
                "native.sampler.readiness".to_string(),
                "native.sampler.review".to_string(),
            ],
            output_fact_categories: vec![
                FutureEndpointSecurityFactCategory::EndpointProcessCategoryFact,
            ],
            audit_refs: Vec::new(),
            provenance_id: "native_sampler_readiness_review".to_string(),
            time_bucket: "current_session".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        review.validate().expect("safe readiness review");
        assert!(review.future_collection_allowed);
        assert!(!review.sampler_active);
        assert!(!review.telemetry_collection_started);
    }
}
