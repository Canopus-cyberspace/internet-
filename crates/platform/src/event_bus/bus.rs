use crate::event_bus::dead_letter::{DeadLetterId, DeadLetterReason, DeadLetterRecord};
use crate::event_bus::message::{
    BusEvent, EventDelivery, EventHandler, EventHandlerResult, PublishOptions,
};
use crate::event_bus::subscription::{EventRoute, Subscription, SubscriptionId};
use crate::event_bus::topic::{core_v1_topics, Topic, TopicName};
use sentinel_contracts::{EventEnvelope, EventId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fmt;

#[derive(Clone, Debug)]
struct QueuedDelivery {
    event: BusEvent,
    attempt: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishReport {
    pub topic: TopicName,
    pub matched_subscriptions: usize,
    pub enqueued: usize,
    pub dropped: usize,
    pub rejected: usize,
    pub dead_letter_ids: Vec<DeadLetterId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventBusError {
    TopicNotRegistered(TopicName),
    SubscriptionNotRegistered(SubscriptionId),
    SchemaMismatch {
        topic: TopicName,
        expected_major: u16,
        actual_major: u16,
    },
    ProtectedDeliveryRejected(TopicName),
}

impl fmt::Display for EventBusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TopicNotRegistered(topic) => write!(f, "topic is not registered: {topic}"),
            Self::SubscriptionNotRegistered(subscription_id) => {
                write!(f, "subscription is not registered: {subscription_id}")
            }
            Self::SchemaMismatch {
                topic,
                expected_major,
                actual_major,
            } => write!(
                f,
                "schema mismatch on {topic}: expected major {expected_major}, got {actual_major}"
            ),
            Self::ProtectedDeliveryRejected(topic) => {
                write!(
                    f,
                    "protected event could not be delivered for topic {topic}"
                )
            }
        }
    }
}

impl std::error::Error for EventBusError {}

#[derive(Clone, Debug, Default)]
pub struct EventBus {
    topics: HashMap<TopicName, Topic>,
    subscriptions: HashMap<SubscriptionId, Subscription>,
    queues: HashMap<SubscriptionId, VecDeque<QueuedDelivery>>,
    dead_letters: Vec<DeadLetterRecord>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_core_topics() -> Self {
        let mut bus = Self::new();
        for topic in core_v1_topics() {
            bus.register_topic(topic);
        }
        bus
    }

    pub fn register_topic(&mut self, topic: Topic) {
        self.topics.insert(topic.name.clone(), topic);
    }

    pub fn topic(&self, topic_name: &TopicName) -> Option<&Topic> {
        self.topics.get(topic_name)
    }

    pub fn topics(&self) -> Vec<&Topic> {
        let mut topics = self.topics.values().collect::<Vec<_>>();
        topics.sort_by_key(|topic| topic.name.to_string());
        topics
    }

    pub fn subscribe(
        &mut self,
        subscription: Subscription,
    ) -> Result<SubscriptionId, EventBusError> {
        if !self.topics.contains_key(&subscription.route.source_topic) {
            return Err(EventBusError::TopicNotRegistered(
                subscription.route.source_topic.clone(),
            ));
        }

        let subscription_id = subscription.subscription_id.clone();
        self.queues.entry(subscription_id.clone()).or_default();
        self.subscriptions
            .insert(subscription_id.clone(), subscription);
        Ok(subscription_id)
    }

    pub fn subscribe_to(
        &mut self,
        topic_name: TopicName,
        consumer_name: impl Into<String>,
    ) -> Result<SubscriptionId, EventBusError> {
        let route = EventRoute::new(topic_name, consumer_name)
            .expect("consumer name is provided by caller");
        self.subscribe(Subscription::new(route))
    }

    pub fn subscriptions(&self) -> Vec<&Subscription> {
        let mut subscriptions = self.subscriptions.values().collect::<Vec<_>>();
        subscriptions.sort_by_key(|subscription| subscription.subscription_id.to_string());
        subscriptions
    }

    pub fn publish(
        &mut self,
        topic_name: TopicName,
        envelope: EventEnvelope,
        options: PublishOptions,
    ) -> Result<PublishReport, EventBusError> {
        let Some(topic) = self.topics.get(&topic_name).cloned() else {
            return Err(EventBusError::TopicNotRegistered(topic_name));
        };

        if options.validate_schema && !topic.is_schema_compatible(&envelope.schema_version) {
            let record = self.dead_letter_from_envelope(
                &topic_name,
                &envelope,
                None,
                0,
                DeadLetterReason::UnsupportedContractVersion,
                "event schema major version is not compatible with topic",
                &options.redacted_payload_summary,
            );
            let report = PublishReport {
                topic: topic_name.clone(),
                matched_subscriptions: 0,
                enqueued: 0,
                dropped: 0,
                rejected: 1,
                dead_letter_ids: vec![record.dead_letter_id.clone()],
            };
            self.dead_letters.push(record);
            return Ok(report);
        }

        let priority = options
            .priority_lane
            .clone()
            .unwrap_or_else(|| topic.default_priority.clone());
        let event = BusEvent::new(topic_name.clone(), envelope, priority, options);
        let subscriptions = self
            .subscriptions
            .values()
            .filter(|subscription| {
                subscription.active
                    && subscription.route.source_topic == topic_name
                    && subscription.route.accepts(&event.priority_lane)
            })
            .cloned()
            .collect::<Vec<_>>();

        let mut report = PublishReport {
            topic: topic_name.clone(),
            matched_subscriptions: subscriptions.len(),
            enqueued: 0,
            dropped: 0,
            rejected: 0,
            dead_letter_ids: Vec::new(),
        };

        if subscriptions.is_empty() {
            let record = self.dead_letter_from_event(
                &event,
                None,
                0,
                DeadLetterReason::NoSubscription,
                "no active subscription matched event topic",
            );
            report.dead_letter_ids.push(record.dead_letter_id.clone());
            self.dead_letters.push(record);
            return Ok(report);
        }

        for subscription in subscriptions {
            match self.enqueue(
                subscription.subscription_id.clone(),
                &subscription,
                event.clone(),
            ) {
                EnqueueOutcome::Enqueued => report.enqueued += 1,
                EnqueueOutcome::Dropped(dead_letter_id) => {
                    report.dropped += 1;
                    report.dead_letter_ids.push(dead_letter_id);
                }
                EnqueueOutcome::Rejected(dead_letter_id) => {
                    report.rejected += 1;
                    report.dead_letter_ids.push(dead_letter_id);
                }
            }
        }

        if report.rejected > 0 && topic.protected_delivery {
            return Err(EventBusError::ProtectedDeliveryRejected(topic_name));
        }

        Ok(report)
    }

    pub fn poll(
        &self,
        subscription_id: &SubscriptionId,
    ) -> Result<Option<EventDelivery>, EventBusError> {
        if !self.subscriptions.contains_key(subscription_id) {
            return Err(EventBusError::SubscriptionNotRegistered(
                subscription_id.clone(),
            ));
        }

        Ok(self
            .queues
            .get(subscription_id)
            .and_then(|queue| queue.front())
            .map(|queued| delivery(subscription_id, queued)))
    }

    pub fn ack(
        &mut self,
        subscription_id: &SubscriptionId,
        event_id: &EventId,
    ) -> Result<bool, EventBusError> {
        if !self.subscriptions.contains_key(subscription_id) {
            return Err(EventBusError::SubscriptionNotRegistered(
                subscription_id.clone(),
            ));
        }

        let Some(queue) = self.queues.get_mut(subscription_id) else {
            return Ok(false);
        };

        if queue
            .front()
            .is_some_and(|queued| queued.event.envelope.event_id == *event_id)
        {
            queue.pop_front();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn fail_delivery(
        &mut self,
        subscription_id: &SubscriptionId,
        event_id: &EventId,
        reason: DeadLetterReason,
        error_summary_redacted: impl Into<String>,
    ) -> Result<Option<DeadLetterId>, EventBusError> {
        if !self.subscriptions.contains_key(subscription_id) {
            return Err(EventBusError::SubscriptionNotRegistered(
                subscription_id.clone(),
            ));
        }

        let Some(queue) = self.queues.get_mut(subscription_id) else {
            return Ok(None);
        };

        let Some(front) = queue.front_mut() else {
            return Ok(None);
        };

        if front.event.envelope.event_id != *event_id {
            return Ok(None);
        }

        front.attempt = front.attempt.saturating_add(1);
        let max_attempts = self
            .subscriptions
            .get(subscription_id)
            .map(|subscription| subscription.retry_policy.max_attempts)
            .unwrap_or(1);

        if front.attempt < max_attempts {
            return Ok(None);
        }

        let queued = queue.pop_front().expect("front exists");
        let record = dead_letter_record(
            &queued.event,
            Some(subscription_id.clone()),
            queued.attempt,
            reason,
            error_summary_redacted.into(),
        );
        let dead_letter_id = record.dead_letter_id.clone();
        self.dead_letters.push(record);
        Ok(Some(dead_letter_id))
    }

    pub fn dispatch_next(
        &mut self,
        subscription_id: &SubscriptionId,
        handler: &dyn EventHandler,
    ) -> Result<Option<EventHandlerResult>, EventBusError> {
        let Some(delivery) = self.poll(subscription_id)? else {
            return Ok(None);
        };

        let result = handler.handle(&delivery);
        match &result {
            EventHandlerResult::Ack => {
                self.ack(subscription_id, delivery.event_id())?;
            }
            EventHandlerResult::Retry {
                error_summary_redacted,
            } => {
                self.fail_delivery(
                    subscription_id,
                    delivery.event_id(),
                    DeadLetterReason::HandlerError,
                    error_summary_redacted.clone(),
                )?;
            }
            EventHandlerResult::DeadLetter {
                reason,
                error_summary_redacted,
            } => {
                let mut queued = self
                    .queues
                    .get_mut(subscription_id)
                    .and_then(VecDeque::pop_front);
                if let Some(queued) = queued.take() {
                    let record = dead_letter_record(
                        &queued.event,
                        Some(subscription_id.clone()),
                        queued.attempt,
                        reason.clone(),
                        error_summary_redacted.clone(),
                    );
                    self.dead_letters.push(record);
                }
            }
        }

        Ok(Some(result))
    }

    pub fn queue_len(&self, subscription_id: &SubscriptionId) -> usize {
        self.queues
            .get(subscription_id)
            .map(VecDeque::len)
            .unwrap_or_default()
    }

    pub fn dead_letters(&self) -> &[DeadLetterRecord] {
        &self.dead_letters
    }

    fn enqueue(
        &mut self,
        subscription_id: SubscriptionId,
        subscription: &Subscription,
        event: BusEvent,
    ) -> EnqueueOutcome {
        let queue = self.queues.entry(subscription_id.clone()).or_default();
        if queue.len() < subscription.queue_capacity {
            queue.push_back(QueuedDelivery { event, attempt: 1 });
            return EnqueueOutcome::Enqueued;
        }

        if let Some(index) = queue
            .iter()
            .position(|queued| queued.event.is_drop_allowed())
        {
            let dropped = queue.remove(index).expect("drop candidate exists");
            let record = dead_letter_record(
                &dropped.event,
                Some(subscription_id.clone()),
                dropped.attempt,
                DeadLetterReason::QueueOverflow,
                "low-priority event dropped under backpressure",
            );
            let dead_letter_id = record.dead_letter_id.clone();
            self.dead_letters.push(record);
            queue.push_back(QueuedDelivery { event, attempt: 1 });
            return EnqueueOutcome::Dropped(dead_letter_id);
        }

        let record = dead_letter_record(
            &event,
            Some(subscription_id),
            1,
            DeadLetterReason::QueueOverflow,
            "queue capacity reached and no droppable event was available",
        );
        let dead_letter_id = record.dead_letter_id.clone();
        self.dead_letters.push(record);

        if event.priority_lane.can_drop_under_pressure() {
            EnqueueOutcome::Dropped(dead_letter_id)
        } else {
            EnqueueOutcome::Rejected(dead_letter_id)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dead_letter_from_envelope(
        &self,
        topic: &TopicName,
        envelope: &EventEnvelope,
        subscription_id: Option<SubscriptionId>,
        attempt: u16,
        reason: DeadLetterReason,
        error_summary_redacted: impl Into<String>,
        redacted_payload_summary: impl Into<String>,
    ) -> DeadLetterRecord {
        DeadLetterRecord {
            dead_letter_id: DeadLetterId::new_v4(),
            source_topic: topic.clone(),
            event_id: envelope.event_id.clone(),
            event_type: envelope.event_type.clone(),
            schema_version: envelope.schema_version.clone(),
            producer_plugin: envelope.producer_plugin.clone(),
            error_code: reason.as_error_code().to_string(),
            error_summary_redacted: error_summary_redacted.into(),
            trace_id: envelope.trace_id.clone(),
            timestamp: Timestamp::now(),
            redacted_payload_summary: redacted_payload_summary.into(),
            subscription_id,
            attempt,
        }
    }

    fn dead_letter_from_event(
        &self,
        event: &BusEvent,
        subscription_id: Option<SubscriptionId>,
        attempt: u16,
        reason: DeadLetterReason,
        error_summary_redacted: impl Into<String>,
    ) -> DeadLetterRecord {
        dead_letter_record(
            event,
            subscription_id,
            attempt,
            reason,
            error_summary_redacted.into(),
        )
    }
}

enum EnqueueOutcome {
    Enqueued,
    Dropped(DeadLetterId),
    Rejected(DeadLetterId),
}

fn delivery(subscription_id: &SubscriptionId, queued: &QueuedDelivery) -> EventDelivery {
    let event_id = queued.event.envelope.event_id.to_string();
    EventDelivery {
        subscription_id: subscription_id.clone(),
        event: queued.event.clone(),
        attempt: queued.attempt,
        idempotency_key: format!("{}:{}:{}", subscription_id, queued.event.topic, event_id),
    }
}

fn dead_letter_record(
    event: &BusEvent,
    subscription_id: Option<SubscriptionId>,
    attempt: u16,
    reason: DeadLetterReason,
    error_summary_redacted: impl Into<String>,
) -> DeadLetterRecord {
    DeadLetterRecord {
        dead_letter_id: DeadLetterId::new_v4(),
        source_topic: event.topic.clone(),
        event_id: event.envelope.event_id.clone(),
        event_type: event.envelope.event_type.clone(),
        schema_version: event.envelope.schema_version.clone(),
        producer_plugin: event.envelope.producer_plugin.clone(),
        error_code: reason.as_error_code().to_string(),
        error_summary_redacted: error_summary_redacted.into(),
        trace_id: event.envelope.trace_id.clone(),
        timestamp: Timestamp::now(),
        redacted_payload_summary: event.redacted_payload_summary.clone(),
        subscription_id,
        attempt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_bus::message::RetryPolicy;
    use crate::event_bus::topic::{
        PriorityLane, AUDIT_EVENT, NETWORK_FLOW_RECORD, REPORT_GENERATED, SECURITY_INCIDENT,
    };
    use sentinel_contracts::{EventEnvelope, EventType, PluginId, SchemaVersion, TraceContext};

    fn envelope(event_type: &str, schema_version: SchemaVersion) -> EventEnvelope {
        EventEnvelope::new(
            EventType::new(event_type).expect("event type"),
            schema_version,
            PluginId::new_v4(),
            TraceContext::new_root(),
        )
    }

    fn topic(name: &str) -> TopicName {
        TopicName::new(name).expect("topic")
    }

    #[test]
    fn core_v1_topics_are_registered() {
        let bus = EventBus::with_core_topics();

        assert!(bus.topic(&topic(AUDIT_EVENT)).is_some());
        assert!(bus.topic(&topic(NETWORK_FLOW_RECORD)).is_some());
        assert!(bus.topic(&topic(SECURITY_INCIDENT)).is_some());
    }

    #[test]
    fn publish_subscribe_preserves_trace_and_supports_ack() {
        let mut bus = EventBus::with_core_topics();
        let subscription_id = bus
            .subscribe_to(topic(NETWORK_FLOW_RECORD), "flow-consumer")
            .expect("subscribe");
        let envelope = envelope(NETWORK_FLOW_RECORD, SchemaVersion::new(1, 0, 0));
        let trace_id = envelope.trace_id.clone();
        let report = bus
            .publish(
                topic(NETWORK_FLOW_RECORD),
                envelope,
                PublishOptions::new("flow metadata summary"),
            )
            .expect("publish");

        assert_eq!(report.enqueued, 1);
        let delivery = bus.poll(&subscription_id).expect("poll").expect("delivery");
        assert_eq!(delivery.event.ordering.trace_id, trace_id);
        assert!(delivery
            .idempotency_key
            .contains(&subscription_id.to_string()));
        assert!(bus.ack(&subscription_id, delivery.event_id()).expect("ack"));
        assert!(bus.poll(&subscription_id).expect("poll").is_none());
    }

    #[test]
    fn dead_letter_uses_redacted_payload_summary_for_schema_mismatch() {
        let mut bus = EventBus::with_core_topics();
        let report = bus
            .publish(
                topic(NETWORK_FLOW_RECORD),
                envelope(NETWORK_FLOW_RECORD, SchemaVersion::new(2, 0, 0)),
                PublishOptions::new("redacted flow summary only"),
            )
            .expect("publish report");

        assert_eq!(report.rejected, 1);
        assert_eq!(bus.dead_letters().len(), 1);
        let dead_letter = &bus.dead_letters()[0];
        assert_eq!(
            dead_letter.error_code,
            DeadLetterReason::UnsupportedContractVersion.as_error_code()
        );
        assert_eq!(
            dead_letter.redacted_payload_summary,
            "redacted flow summary only"
        );
    }

    #[test]
    fn low_priority_events_can_be_dropped_to_preserve_p0_events() {
        let mut bus = EventBus::with_core_topics();
        let route = EventRoute::new(topic(AUDIT_EVENT), "audit-consumer").expect("route");
        let subscription_id = bus
            .subscribe(Subscription::new(route).with_queue_capacity(1))
            .expect("subscribe");

        let mut low_options = PublishOptions::new("report generated summary");
        low_options.priority_lane = Some(PriorityLane::P5UiRefresh);
        bus.publish(
            topic(AUDIT_EVENT),
            envelope(AUDIT_EVENT, SchemaVersion::new(1, 0, 0)),
            low_options,
        )
        .expect("low priority publish");

        let report = bus
            .publish(
                topic(AUDIT_EVENT),
                envelope(AUDIT_EVENT, SchemaVersion::new(1, 0, 0)),
                PublishOptions::new("audit event summary"),
            )
            .expect("p0 publish");

        assert_eq!(report.dropped, 1);
        let delivery = bus.poll(&subscription_id).expect("poll").expect("delivery");
        assert_eq!(delivery.event.priority_lane, PriorityLane::P0Critical);
        assert_eq!(bus.dead_letters().len(), 1);
    }

    #[test]
    fn protected_events_are_not_silently_dropped_when_queue_has_no_room() {
        let mut bus = EventBus::with_core_topics();
        let route = EventRoute::new(topic(SECURITY_INCIDENT), "incident-consumer").expect("route");
        bus.subscribe(Subscription::new(route).with_queue_capacity(1))
            .expect("subscribe");

        bus.publish(
            topic(SECURITY_INCIDENT),
            envelope(SECURITY_INCIDENT, SchemaVersion::new(1, 0, 0)),
            PublishOptions::new("incident summary"),
        )
        .expect("first publish");

        let error = bus
            .publish(
                topic(SECURITY_INCIDENT),
                envelope(SECURITY_INCIDENT, SchemaVersion::new(1, 0, 0)),
                PublishOptions::new("second incident summary"),
            )
            .expect_err("protected overflow is reported");

        assert!(matches!(error, EventBusError::ProtectedDeliveryRejected(_)));
        assert_eq!(bus.dead_letters().len(), 1);
    }

    #[test]
    fn retry_exhaustion_routes_to_dead_letter_without_raw_payload() {
        let mut bus = EventBus::with_core_topics();
        let route = EventRoute::new(topic(NETWORK_FLOW_RECORD), "flow-consumer").expect("route");
        let subscription_id = bus
            .subscribe(
                Subscription::new(route)
                    .with_queue_capacity(4)
                    .with_retry_policy(RetryPolicy::no_retry()),
            )
            .expect("subscribe");
        bus.publish(
            topic(NETWORK_FLOW_RECORD),
            envelope(NETWORK_FLOW_RECORD, SchemaVersion::new(1, 0, 0)),
            PublishOptions::new("redacted flow only"),
        )
        .expect("publish");

        let delivery = bus.poll(&subscription_id).expect("poll").expect("delivery");
        let dead_letter_id = bus
            .fail_delivery(
                &subscription_id,
                delivery.event_id(),
                DeadLetterReason::SchemaValidationFailed,
                "schema validation failed",
            )
            .expect("fail delivery")
            .expect("dead letter id");

        assert_eq!(bus.queue_len(&subscription_id), 0);
        assert_eq!(bus.dead_letters()[0].dead_letter_id, dead_letter_id);
        assert_eq!(
            bus.dead_letters()[0].redacted_payload_summary,
            "redacted flow only"
        );
    }

    struct AckHandler;

    impl EventHandler for AckHandler {
        fn handle(&self, _delivery: &EventDelivery) -> EventHandlerResult {
            EventHandlerResult::Ack
        }
    }

    #[test]
    fn event_handler_dispatch_is_idempotency_aware_and_ackable() {
        let mut bus = EventBus::with_core_topics();
        let subscription_id = bus
            .subscribe_to(topic(REPORT_GENERATED), "report-consumer")
            .expect("subscribe");
        bus.publish(
            topic(REPORT_GENERATED),
            envelope(REPORT_GENERATED, SchemaVersion::new(1, 0, 0)),
            PublishOptions::new("report generated summary"),
        )
        .expect("publish");

        let result = bus
            .dispatch_next(&subscription_id, &AckHandler)
            .expect("dispatch")
            .expect("handler result");

        assert_eq!(result, EventHandlerResult::Ack);
        assert_eq!(bus.queue_len(&subscription_id), 0);
    }
}
