use crate::component::ComponentId;
use crate::event_bus::{PriorityLane, TopicName, OPERATIONAL_HEALTH};
use crate::observability::diagnostics::{validate_privacy_safe_text, DiagnosticsValidationError};
use crate::pipeline::{PipelineNodeId, PipelineStage};
use sentinel_contracts::{PipelineId, PluginId, PrivacyClass, SchemaVersion, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;

use super::diagnostics::TraceLink;

pub const HEALTH_SNAPSHOT_EVENT_TYPE: &str = "platform.health.snapshot";

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unavailable,
    Disconnected,
    Unauthorized,
    Stale,
    Failed,
    Unknown,
}

impl HealthStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    pub fn is_failure_like(&self) -> bool {
        matches!(
            self,
            Self::Unavailable | Self::Disconnected | Self::Unauthorized | Self::Failed
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HealthSubject {
    Component {
        component_id: ComponentId,
    },
    Plugin {
        plugin_id: PluginId,
    },
    Pipeline {
        pipeline_id: PipelineId,
    },
    PipelineStage {
        pipeline_id: PipelineId,
        node_id: PipelineNodeId,
        stage: PipelineStage,
    },
    ServiceAdapter {
        component_id: ComponentId,
        adapter_name: String,
    },
    Storage {
        store_name: String,
    },
    Capture {
        adapter_name: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum HealthProbeKind {
    Liveness,
    Readiness,
    Dependency,
    DataFreshness,
    Latency,
    ErrorRate,
    QueueLag,
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthProbe {
    pub name: String,
    pub kind: HealthProbeKind,
    pub required: bool,
    pub critical: bool,
    pub timeout_ms: Option<u64>,
    pub description_redacted: Option<String>,
}

impl HealthProbe {
    pub fn new(
        name: impl Into<String>,
        kind: HealthProbeKind,
    ) -> Result<Self, HealthValidationError> {
        Ok(Self {
            name: require_health_text("name", name)?,
            kind,
            required: true,
            critical: false,
            timeout_ms: None,
            description_redacted: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthProbeResult {
    pub probe: HealthProbe,
    pub status: HealthStatus,
    pub observed_at: Timestamp,
    pub detail_redacted: Option<String>,
}

impl HealthProbeResult {
    pub fn new(probe: HealthProbe, status: HealthStatus) -> Self {
        Self {
            probe,
            status,
            observed_at: Timestamp::now(),
            detail_redacted: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthDependencyStatus {
    pub dependency_name: String,
    pub status: HealthStatus,
    pub required: bool,
    pub reason_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthSnapshot {
    pub subject: HealthSubject,
    pub status: HealthStatus,
    pub liveness: HealthStatus,
    pub readiness: HealthStatus,
    pub probes: Vec<HealthProbeResult>,
    pub dependencies: Vec<HealthDependencyStatus>,
    pub message_redacted: Option<String>,
    pub observed_at: Timestamp,
    pub stale_after_ms: Option<u64>,
    pub schema_version: SchemaVersion,
    pub trace_link: Option<TraceLink>,
    pub privacy_class: PrivacyClass,
}

impl HealthSnapshot {
    pub fn new(subject: HealthSubject, status: HealthStatus) -> Self {
        Self {
            subject,
            liveness: status.clone(),
            readiness: status.clone(),
            status,
            probes: Vec::new(),
            dependencies: Vec::new(),
            message_redacted: None,
            observed_at: Timestamp::now(),
            stale_after_ms: None,
            schema_version: SchemaVersion::new(1, 0, 0),
            trace_link: None,
            privacy_class: PrivacyClass::Internal,
        }
    }

    pub fn topic_name() -> TopicName {
        TopicName::new(OPERATIONAL_HEALTH).expect("operational health topic is valid")
    }

    pub fn event_type() -> &'static str {
        HEALTH_SNAPSHOT_EVENT_TYPE
    }

    pub fn priority_lane(&self) -> PriorityLane {
        if self.status.is_failure_like() || matches!(self.status, HealthStatus::Degraded) {
            PriorityLane::P1High
        } else {
            PriorityLane::P2Normal
        }
    }

    pub fn with_message_redacted(
        mut self,
        message_redacted: impl Into<String>,
    ) -> Result<Self, HealthValidationError> {
        self.message_redacted = Some(require_health_text("message_redacted", message_redacted)?);
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), HealthValidationError> {
        if let Some(message) = &self.message_redacted {
            validate_health_text("message_redacted", message)?;
        }

        for probe in &self.probes {
            if let Some(description) = &probe.probe.description_redacted {
                validate_health_text("description_redacted", description)?;
            }
            if let Some(detail) = &probe.detail_redacted {
                validate_health_text("detail_redacted", detail)?;
            }
        }

        for dependency in &self.dependencies {
            validate_health_text("dependency_name", &dependency.dependency_name)?;
            if let Some(reason) = &dependency.reason_redacted {
                validate_health_text("reason_redacted", reason)?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HealthValidationError {
    Diagnostics(DiagnosticsValidationError),
}

impl fmt::Display for HealthValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Diagnostics(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for HealthValidationError {}

impl From<DiagnosticsValidationError> for HealthValidationError {
    fn from(value: DiagnosticsValidationError) -> Self {
        Self::Diagnostics(value)
    }
}

fn require_health_text(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, HealthValidationError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(HealthValidationError::Diagnostics(
            DiagnosticsValidationError::EmptyField(field),
        ));
    }
    validate_privacy_safe_text(field, &value)?;
    Ok(value)
}

fn validate_health_text(field: &'static str, value: &str) -> Result<(), HealthValidationError> {
    validate_privacy_safe_text(field, value)?;
    Ok(())
}
