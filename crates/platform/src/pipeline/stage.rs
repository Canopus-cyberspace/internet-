use crate::component::{ComponentId, ComponentState, HealthStatus};
use crate::event_bus::{PriorityLane, RetryPolicy, TopicName};
use sentinel_contracts::{PermissionKey, PluginId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    Source,
    Ingest,
    Transform,
    Normalize,
    Privacy,
    Protocol,
    Enrichment,
    Context,
    Detection,
    Evidence,
    Risk,
    Correlation,
    Graph,
    Response,
    Report,
}

impl PipelineStage {
    pub fn can_emit_response_execution(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageReadiness {
    NotReady,
    Ready,
    Blocked,
    Paused,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyScope {
    EventId,
    TraceAndStage,
    ProducerStreamSequence,
    CheckpointCursor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageBinding {
    pub component_id: Option<ComponentId>,
    pub plugin_id: Option<PluginId>,
    pub input_topics: Vec<TopicName>,
    pub output_topics: Vec<TopicName>,
    pub required_permissions: Vec<PermissionKey>,
    pub retry_policy: RetryPolicy,
    pub priority_lane: PriorityLane,
    pub idempotency_scope: IdempotencyScope,
    pub checkpoint_required: bool,
}

impl StageBinding {
    pub fn metadata_only(input_topics: Vec<TopicName>, output_topics: Vec<TopicName>) -> Self {
        Self {
            component_id: None,
            plugin_id: None,
            input_topics,
            output_topics,
            required_permissions: Vec::new(),
            retry_policy: RetryPolicy::default(),
            priority_lane: PriorityLane::P2Normal,
            idempotency_scope: IdempotencyScope::EventId,
            checkpoint_required: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineNodeRuntimeState {
    pub component_state: ComponentState,
    pub readiness: StageReadiness,
    pub health_status: HealthStatus,
    pub blocked_reasons_redacted: Vec<String>,
}

impl Default for PipelineNodeRuntimeState {
    fn default() -> Self {
        Self {
            component_state: ComponentState::Discovered,
            readiness: StageReadiness::NotReady,
            health_status: HealthStatus::Unknown,
            blocked_reasons_redacted: Vec::new(),
        }
    }
}
