use crate::{RedactionStatus, SchemaVersion, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const ETW_LIFECYCLE_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_ETW_LIFECYCLE_REFS: usize = 16;
const MAX_ETW_LIFECYCLE_TEXT_LEN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwAuthorizationState {
    Required,
    Authorized,
    Invalidated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwLifecycleState {
    Inactive,
    Activating,
    Active,
    Pausing,
    Paused,
    Resuming,
    Degraded,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwRuntimeSessionState {
    NotCreated,
    ControlSessionActive,
    ControlSessionPaused,
    ControlSessionStopped,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwFallbackState {
    IpHelperActive,
    IpHelperAvailable,
    PortableMetadataOnly,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtwLifecycleStatus {
    pub lifecycle_ref: String,
    pub ownership_ref: String,
    pub ownership_epoch: u64,
    pub schema_version: SchemaVersion,
    pub lifecycle_state: EtwLifecycleState,
    pub session_state: EtwRuntimeSessionState,
    pub authorization_state: EtwAuthorizationState,
    pub session_generation: u32,
    pub control_thread_active: bool,
    pub control_thread_joined: bool,
    pub trace_session_created: bool,
    pub provider_enabled: bool,
    pub collection_started: bool,
    pub consumer_started: bool,
    pub consumer_worker_active: bool,
    pub consumer_worker_joined: bool,
    pub raw_event_count: u32,
    pub normalized_event_count: u32,
    pub dropped_event_count: u32,
    pub rate_limited_event_count: u32,
    pub schema_rejected_event_count: u32,
    pub published_batch_count: u32,
    pub eventbus_publication_count: u32,
    pub security_fact_count: u32,
    pub activation_count: u32,
    pub pause_count: u32,
    pub resume_count: u32,
    pub stop_count: u32,
    pub fallback_state: EtwFallbackState,
    pub degraded_reason: Option<String>,
    pub authorization_refs: Vec<String>,
    pub audit_refs: Vec<String>,
    pub provenance_refs: Vec<String>,
    pub updated_at: Timestamp,
    pub redaction_status: RedactionStatus,
}

impl EtwLifecycleStatus {
    pub fn inactive(
        ownership_ref: impl Into<String>,
        ownership_epoch: u64,
        fallback_state: EtwFallbackState,
    ) -> Self {
        Self {
            lifecycle_ref: "etw_lifecycle_ref".to_string(),
            ownership_ref: ownership_ref.into(),
            ownership_epoch,
            schema_version: ETW_LIFECYCLE_SCHEMA_VERSION,
            lifecycle_state: EtwLifecycleState::Inactive,
            session_state: EtwRuntimeSessionState::NotCreated,
            authorization_state: EtwAuthorizationState::Required,
            session_generation: 0,
            control_thread_active: false,
            control_thread_joined: false,
            trace_session_created: false,
            provider_enabled: false,
            collection_started: false,
            consumer_started: false,
            consumer_worker_active: false,
            consumer_worker_joined: false,
            raw_event_count: 0,
            normalized_event_count: 0,
            dropped_event_count: 0,
            rate_limited_event_count: 0,
            schema_rejected_event_count: 0,
            published_batch_count: 0,
            eventbus_publication_count: 0,
            security_fact_count: 0,
            activation_count: 0,
            pause_count: 0,
            resume_count: 0,
            stop_count: 0,
            fallback_state,
            degraded_reason: Some("explicit_authorization_required".to_string()),
            authorization_refs: Vec::new(),
            audit_refs: vec!["etw_lifecycle_initialized".to_string()],
            provenance_refs: vec!["servicehost_etw_lifecycle_runtime".to_string()],
            updated_at: Timestamp::now(),
            redaction_status: RedactionStatus::Redacted,
        }
    }

    pub fn validate(&self) -> Result<(), EtwLifecycleContractError> {
        validate_safe_text("lifecycle_ref", &self.lifecycle_ref)?;
        validate_safe_text("ownership_ref", &self.ownership_ref)?;
        validate_optional_safe_text("degraded_reason", self.degraded_reason.as_deref())?;
        validate_refs("authorization_refs", &self.authorization_refs)?;
        validate_refs("audit_refs", &self.audit_refs)?;
        validate_refs("provenance_refs", &self.provenance_refs)?;
        if self.ownership_epoch == 0 {
            return Err(EtwLifecycleContractError::OwnershipEpochRequired);
        }
        if self.schema_version != ETW_LIFECYCLE_SCHEMA_VERSION {
            return Err(EtwLifecycleContractError::UnsupportedSchemaVersion);
        }
        if self.normalized_event_count > self.raw_event_count
            || self.rate_limited_event_count > self.dropped_event_count
            || self.schema_rejected_event_count > self.dropped_event_count
            || self.published_batch_count > self.normalized_event_count
        {
            return Err(EtwLifecycleContractError::InvalidCounters);
        }
        let state_valid = match self.lifecycle_state {
            EtwLifecycleState::Inactive => {
                self.authorization_state == EtwAuthorizationState::Required
                    && self.session_state == EtwRuntimeSessionState::NotCreated
                    && !self.control_thread_active
                    && !self.trace_session_created
                    && !self.provider_enabled
                    && !self.collection_started
                    && !self.consumer_started
                    && !self.consumer_worker_active
            }
            EtwLifecycleState::Activating
            | EtwLifecycleState::Pausing
            | EtwLifecycleState::Resuming
            | EtwLifecycleState::Stopping => {
                self.authorization_state == EtwAuthorizationState::Authorized
            }
            EtwLifecycleState::Active => {
                self.authorization_state == EtwAuthorizationState::Authorized
                    && self.session_state == EtwRuntimeSessionState::ControlSessionActive
                    && self.control_thread_active
                    && self.trace_session_created
                    && self.provider_enabled
                    && self.collection_started
                    && self.consumer_started
                    && self.consumer_worker_active
                    && !self.consumer_worker_joined
            }
            EtwLifecycleState::Paused => {
                self.authorization_state == EtwAuthorizationState::Authorized
                    && self.session_state == EtwRuntimeSessionState::ControlSessionPaused
                    && self.control_thread_active
                    && !self.trace_session_created
                    && !self.provider_enabled
                    && !self.collection_started
                    && !self.consumer_started
                    && !self.consumer_worker_active
                    && self.consumer_worker_joined
            }
            EtwLifecycleState::Degraded | EtwLifecycleState::Failed => {
                !self.trace_session_created
                    && !self.provider_enabled
                    && !self.collection_started
                    && !self.consumer_started
                    && !self.consumer_worker_active
            }
            EtwLifecycleState::Stopped => {
                self.session_state == EtwRuntimeSessionState::ControlSessionStopped
                    && !self.control_thread_active
                    && self.control_thread_joined
                    && !self.trace_session_created
                    && !self.provider_enabled
                    && !self.collection_started
                    && !self.consumer_started
                    && !self.consumer_worker_active
                    && self.consumer_worker_joined
            }
        };
        if !state_valid {
            return Err(EtwLifecycleContractError::InvalidLifecycleState);
        }
        if self.redaction_status == RedactionStatus::RedactionRequired {
            return Err(EtwLifecycleContractError::RedactionRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EtwLifecycleContractError {
    EmptyField(&'static str),
    TooLong(&'static str),
    UnsafeField(&'static str),
    TooManyItems(&'static str),
    OwnershipEpochRequired,
    UnsupportedSchemaVersion,
    InvalidLifecycleState,
    CollectionBoundaryViolation,
    InvalidCounters,
    RedactionRequired,
}

impl fmt::Display for EtwLifecycleContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::TooLong(field) => write!(formatter, "{field} exceeds bounded length"),
            Self::UnsafeField(field) => write!(formatter, "{field} contains unsafe metadata"),
            Self::TooManyItems(field) => write!(formatter, "{field} exceeds bounded item count"),
            Self::OwnershipEpochRequired => write!(formatter, "ETW ownership epoch is required"),
            Self::UnsupportedSchemaVersion => write!(formatter, "ETW lifecycle schema unsupported"),
            Self::InvalidLifecycleState => write!(formatter, "ETW lifecycle state is invalid"),
            Self::CollectionBoundaryViolation => {
                write!(formatter, "ETW lifecycle crossed the collection boundary")
            }
            Self::InvalidCounters => write!(formatter, "ETW lifecycle counters are invalid"),
            Self::RedactionRequired => write!(formatter, "ETW lifecycle output must be redacted"),
        }
    }
}

impl std::error::Error for EtwLifecycleContractError {}

fn validate_refs(field: &'static str, values: &[String]) -> Result<(), EtwLifecycleContractError> {
    if values.len() > MAX_ETW_LIFECYCLE_REFS {
        return Err(EtwLifecycleContractError::TooManyItems(field));
    }
    for value in values {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_optional_safe_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), EtwLifecycleContractError> {
    if let Some(value) = value {
        validate_safe_text(field, value)?;
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), EtwLifecycleContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(EtwLifecycleContractError::EmptyField(field));
    }
    if trimmed.len() > MAX_ETW_LIFECYCLE_TEXT_LEN {
        return Err(EtwLifecycleContractError::TooLong(field));
    }
    let normalized = trimmed.to_ascii_lowercase();
    for marker in [
        "handle=",
        "session_name=",
        "provider_guid=",
        "pid=",
        "process_name=",
        "raw_address=",
        "exact_port=",
        "path=",
        "token=",
        "credential=",
        "secret=",
        "password=",
        "api_key=",
    ] {
        if normalized.contains(marker) {
            return Err(EtwLifecycleContractError::UnsafeField(field));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etw_lifecycle_inactive_contract_is_collection_free() {
        let status =
            EtwLifecycleStatus::inactive("owner_ref", 1, EtwFallbackState::IpHelperAvailable);
        assert!(status.validate().is_ok());
        assert!(!status.collection_started);
        assert_eq!(status.eventbus_publication_count, 0);
        assert_eq!(status.security_fact_count, 0);
    }

    #[test]
    fn etw_lifecycle_rejects_collection_claims_while_inactive() {
        let mut status =
            EtwLifecycleStatus::inactive("owner_ref", 1, EtwFallbackState::IpHelperAvailable);
        status.collection_started = true;
        assert_eq!(
            status.validate(),
            Err(EtwLifecycleContractError::InvalidLifecycleState)
        );
    }

    #[test]
    fn etw_lifecycle_accepts_authorized_bounded_live_collection() {
        let mut status =
            EtwLifecycleStatus::inactive("owner_ref", 1, EtwFallbackState::IpHelperAvailable);
        status.lifecycle_state = EtwLifecycleState::Active;
        status.session_state = EtwRuntimeSessionState::ControlSessionActive;
        status.authorization_state = EtwAuthorizationState::Authorized;
        status.control_thread_active = true;
        status.trace_session_created = true;
        status.provider_enabled = true;
        status.collection_started = true;
        status.consumer_started = true;
        status.consumer_worker_active = true;
        status.raw_event_count = 3;
        status.normalized_event_count = 2;
        status.dropped_event_count = 1;
        status.published_batch_count = 1;
        assert!(status.validate().is_ok());
    }
}
