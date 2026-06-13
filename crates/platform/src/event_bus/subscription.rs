use crate::event_bus::message::RetryPolicy;
use crate::event_bus::topic::{PriorityLane, TopicName};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubscriptionId(Uuid);

impl SubscriptionId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse_str(value: &str) -> Result<Self, SubscriptionIdParseError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| SubscriptionIdParseError {
                value: value.to_string(),
            })
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for SubscriptionId {
    type Err = SubscriptionIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_str(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionIdParseError {
    value: String,
}

impl fmt::Display for SubscriptionIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid SubscriptionId UUID: {}", self.value)
    }
}

impl std::error::Error for SubscriptionIdParseError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRoute {
    pub source_topic: TopicName,
    pub consumer_name: String,
    pub accepted_priorities: Vec<PriorityLane>,
    pub require_schema_match: bool,
}

impl EventRoute {
    pub fn new(
        source_topic: TopicName,
        consumer_name: impl Into<String>,
    ) -> Result<Self, SubscriptionError> {
        let consumer_name = consumer_name.into();
        if consumer_name.trim().is_empty() {
            return Err(SubscriptionError::EmptyConsumerName);
        }

        Ok(Self {
            source_topic,
            consumer_name,
            accepted_priorities: Vec::new(),
            require_schema_match: true,
        })
    }

    pub fn accepts(&self, priority: &PriorityLane) -> bool {
        self.accepted_priorities.is_empty() || self.accepted_priorities.contains(priority)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub subscription_id: SubscriptionId,
    pub route: EventRoute,
    pub retry_policy: RetryPolicy,
    pub queue_capacity: usize,
    pub active: bool,
    pub idempotency_required: bool,
}

impl Subscription {
    pub fn new(route: EventRoute) -> Self {
        Self {
            subscription_id: SubscriptionId::new_v4(),
            route,
            retry_policy: RetryPolicy::default(),
            queue_capacity: 1024,
            active: true,
            idempotency_required: true,
        }
    }

    pub fn with_queue_capacity(mut self, capacity: usize) -> Self {
        self.queue_capacity = capacity.max(1);
        self
    }

    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriptionError {
    EmptyConsumerName,
}

impl fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyConsumerName => write!(f, "subscription consumer_name must not be empty"),
        }
    }
}

impl std::error::Error for SubscriptionError {}
