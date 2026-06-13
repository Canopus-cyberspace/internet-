use crate::pipeline::checkpoint::CheckpointHandle;
use sentinel_contracts::{ReplayId, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayScope {
    Event,
    Finding,
    Alert,
    Incident,
    Graph,
    Report,
    Pipeline,
    AttackStory,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayContext {
    pub replay_id: ReplayId,
    pub scope: ReplayScope,
    pub started_at: Timestamp,
    pub source_checkpoint: Option<CheckpointHandle>,
    pub reason_redacted: String,
    pub response_execution_disabled: bool,
    pub firewall_qos_isolation_disabled: bool,
    pub online_lookup_disabled: bool,
    pub external_upload_disabled: bool,
}

impl ReplayContext {
    pub fn new(scope: ReplayScope, reason_redacted: impl Into<String>) -> Self {
        Self {
            replay_id: ReplayId::new_v4(),
            scope,
            started_at: Timestamp::now(),
            source_checkpoint: None,
            reason_redacted: reason_redacted.into(),
            response_execution_disabled: true,
            firewall_qos_isolation_disabled: true,
            online_lookup_disabled: true,
            external_upload_disabled: true,
        }
    }

    pub fn with_checkpoint(mut self, checkpoint: CheckpointHandle) -> Self {
        self.source_checkpoint = Some(checkpoint);
        self
    }

    pub fn real_response_forbidden(&self) -> bool {
        self.response_execution_disabled || self.firewall_qos_isolation_disabled
    }
}
