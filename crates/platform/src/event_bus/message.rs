use crate::event_bus::dead_letter::DeadLetterReason;
use crate::event_bus::subscription::SubscriptionId;
use crate::event_bus::topic::{PriorityLane, TopicName};
use sentinel_contracts::{EventEnvelope, EventId, PluginId, Timestamp, TraceId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u16,
    pub backoff_millis: u64,
    pub route_to_dead_letter: bool,
}

impl RetryPolicy {
    pub fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            backoff_millis: 0,
            route_to_dead_letter: true,
        }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            backoff_millis: 250,
            route_to_dead_letter: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderingMetadata {
    pub trace_id: TraceId,
    pub producer_plugin: PluginId,
    pub producer_stream: Option<String>,
    pub sequence: Option<u64>,
}

impl OrderingMetadata {
    pub fn from_envelope(envelope: &EventEnvelope, producer_stream: Option<String>) -> Self {
        Self {
            trace_id: envelope.trace_id.clone(),
            producer_plugin: envelope.producer_plugin.clone(),
            producer_stream,
            sequence: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishOptions {
    pub priority_lane: Option<PriorityLane>,
    pub retry_policy: RetryPolicy,
    pub producer_stream: Option<String>,
    pub sequence: Option<u64>,
    pub redacted_payload_summary: String,
    pub validate_schema: bool,
}

impl PublishOptions {
    pub fn new(redacted_payload_summary: impl Into<String>) -> Self {
        Self {
            priority_lane: None,
            retry_policy: RetryPolicy::default(),
            producer_stream: None,
            sequence: None,
            redacted_payload_summary: redacted_payload_summary.into(),
            validate_schema: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BusEvent {
    pub topic: TopicName,
    pub envelope: EventEnvelope,
    pub priority_lane: PriorityLane,
    pub ordering: OrderingMetadata,
    pub redacted_payload_summary: String,
    pub published_at: Timestamp,
}

impl BusEvent {
    pub fn new(
        topic: TopicName,
        envelope: EventEnvelope,
        priority_lane: PriorityLane,
        mut options: PublishOptions,
    ) -> Self {
        let mut ordering = OrderingMetadata::from_envelope(&envelope, options.producer_stream);
        ordering.sequence = options.sequence;

        Self {
            topic,
            envelope,
            priority_lane,
            ordering,
            redacted_payload_summary: std::mem::take(&mut options.redacted_payload_summary),
            published_at: Timestamp::now(),
        }
    }

    pub fn is_drop_allowed(&self) -> bool {
        self.priority_lane.can_drop_under_pressure()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventDelivery {
    pub subscription_id: SubscriptionId,
    pub event: BusEvent,
    pub attempt: u16,
    pub idempotency_key: String,
}

impl EventDelivery {
    pub fn event_id(&self) -> &EventId {
        &self.event.envelope.event_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventHandlerResult {
    Ack,
    Retry {
        error_summary_redacted: String,
    },
    DeadLetter {
        reason: DeadLetterReason,
        error_summary_redacted: String,
    },
}

pub trait EventHandler {
    fn handle(&self, delivery: &EventDelivery) -> EventHandlerResult;
}
