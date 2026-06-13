use crate::event_bus::subscription::SubscriptionId;
use crate::event_bus::topic::TopicName;
use sentinel_contracts::{EventId, EventType, PluginId, SchemaVersion, Timestamp, TraceId};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeadLetterId(Uuid);

impl DeadLetterId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for DeadLetterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for DeadLetterId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadLetterReason {
    SchemaValidationFailed,
    PrivacyPolicyViolation,
    PermissionDenied,
    PluginTimeout,
    PluginError,
    StorageWriteFailed,
    UnsupportedContractVersion,
    QueueOverflow,
    HandlerError,
    NoSubscription,
}

impl DeadLetterReason {
    pub fn as_error_code(&self) -> &'static str {
        match self {
            Self::SchemaValidationFailed => "schema_validation_failed",
            Self::PrivacyPolicyViolation => "privacy_policy_violation",
            Self::PermissionDenied => "permission_denied",
            Self::PluginTimeout => "plugin_timeout",
            Self::PluginError => "plugin_error",
            Self::StorageWriteFailed => "storage_write_failed",
            Self::UnsupportedContractVersion => "unsupported_contract_version",
            Self::QueueOverflow => "queue_overflow",
            Self::HandlerError => "handler_error",
            Self::NoSubscription => "no_subscription",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeadLetterRecord {
    pub dead_letter_id: DeadLetterId,
    pub source_topic: TopicName,
    pub event_id: EventId,
    pub event_type: EventType,
    pub schema_version: SchemaVersion,
    pub producer_plugin: PluginId,
    pub error_code: String,
    pub error_summary_redacted: String,
    pub trace_id: TraceId,
    pub timestamp: Timestamp,
    pub redacted_payload_summary: String,
    pub subscription_id: Option<SubscriptionId>,
    pub attempt: u16,
}
