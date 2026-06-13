use crate::common::{
    CapabilityId, CorrelationId, EntityRef, EventId, PipelineId, PluginId, PrivacyClass,
    QualityScore, ReplayId, SchemaVersion, Timestamp, TraceContext, TraceId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventType(String);

impl EventType {
    pub fn new(value: impl Into<String>) -> Result<Self, EventTypeError> {
        let value = value.into();
        if value.trim().is_empty() {
            Err(EventTypeError)
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventTypeError;

impl std::fmt::Display for EventTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "event type must not be empty")
    }
}

impl std::error::Error for EventTypeError {}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: EventId,
    pub event_type: EventType,
    pub schema_version: SchemaVersion,
    pub producer_plugin: PluginId,
    pub producer_capability: Option<CapabilityId>,
    pub timestamp: Timestamp,
    pub ingest_time: Timestamp,
    pub trace_id: TraceId,
    pub correlation_id: Option<CorrelationId>,
    pub causality_id: Option<crate::common::CausalityId>,
    pub pipeline_id: Option<PipelineId>,
    pub replay_id: Option<ReplayId>,
    pub entity_refs: Vec<EntityRef>,
    pub privacy_class: PrivacyClass,
    pub quality_score: QualityScore,
    pub payload: Value,
}

impl EventEnvelope {
    pub fn new(
        event_type: EventType,
        schema_version: SchemaVersion,
        producer_plugin: PluginId,
        trace: TraceContext,
    ) -> Self {
        let now = Timestamp::now();
        Self {
            event_id: EventId::new_v4(),
            event_type,
            schema_version,
            producer_plugin,
            producer_capability: None,
            timestamp: now.clone(),
            ingest_time: now,
            trace_id: trace.trace_id,
            correlation_id: trace.correlation_id,
            causality_id: trace.causality_id,
            pipeline_id: trace.pipeline_id,
            replay_id: trace.replay_id,
            entity_refs: Vec::new(),
            privacy_class: PrivacyClass::default(),
            quality_score: QualityScore::default(),
            payload: Value::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_envelope_carries_common_contract_fields() {
        let trace = TraceContext::new_root();
        let envelope = EventEnvelope::new(
            EventType::new("security.observation").expect("event type"),
            SchemaVersion::new(1, 0, 0),
            PluginId::new_v4(),
            trace,
        );

        assert_eq!(envelope.schema_version, SchemaVersion::new(1, 0, 0));
        assert_eq!(envelope.privacy_class, PrivacyClass::Internal);
        assert_eq!(envelope.quality_score, QualityScore::unknown());
    }
}
