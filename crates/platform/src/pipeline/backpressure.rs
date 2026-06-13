use crate::event_bus::topic::{
    AUDIT_EVENT, RESPONSE_RESULT, RESPONSE_ROLLBACK_RESULT, SECURITY_ALERT, SECURITY_FINDING,
    SECURITY_INCIDENT,
};
use crate::event_bus::{PriorityLane, TopicName};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureLevel {
    Normal,
    Warning,
    Degraded,
    Critical,
    ShutdownProtection,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureAction {
    DisableExpensiveEnrichment,
    SampleLowPriorityEvents,
    DelayBatchJobs,
    ReduceGraphUpdateFrequency,
    SkipOptionalPlugins,
    PreserveCriticalDetection,
    StopNonCriticalWork,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureState {
    pub level: BackpressureLevel,
    pub queue_depth: usize,
    pub max_queue_depth: usize,
    pub dropped_low_priority_events: u64,
    pub active_actions: Vec<BackpressureAction>,
}

impl BackpressureState {
    pub fn normal(max_queue_depth: usize) -> Self {
        Self {
            level: BackpressureLevel::Normal,
            queue_depth: 0,
            max_queue_depth,
            dropped_low_priority_events: 0,
            active_actions: Vec::new(),
        }
    }

    pub fn utilization(&self) -> f32 {
        if self.max_queue_depth == 0 {
            0.0
        } else {
            self.queue_depth as f32 / self.max_queue_depth as f32
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressurePolicy {
    pub max_queue_depth: usize,
    pub protected_topics: Vec<TopicName>,
    pub protected_priorities: Vec<PriorityLane>,
    pub droppable_priorities: Vec<PriorityLane>,
    pub degradation_actions: Vec<BackpressureAction>,
}

impl BackpressurePolicy {
    pub fn v1_default() -> Self {
        Self {
            max_queue_depth: 4096,
            protected_topics: vec![
                topic(AUDIT_EVENT),
                topic(RESPONSE_RESULT),
                topic(RESPONSE_ROLLBACK_RESULT),
                topic(SECURITY_INCIDENT),
                topic(SECURITY_ALERT),
                topic(SECURITY_FINDING),
            ],
            protected_priorities: vec![PriorityLane::P0Critical, PriorityLane::P1High],
            droppable_priorities: vec![
                PriorityLane::P3Low,
                PriorityLane::P4BestEffort,
                PriorityLane::P5UiRefresh,
            ],
            degradation_actions: vec![
                BackpressureAction::DisableExpensiveEnrichment,
                BackpressureAction::SampleLowPriorityEvents,
                BackpressureAction::DelayBatchJobs,
                BackpressureAction::ReduceGraphUpdateFrequency,
                BackpressureAction::SkipOptionalPlugins,
                BackpressureAction::PreserveCriticalDetection,
            ],
        }
    }

    pub fn protects_topic(&self, topic: &TopicName) -> bool {
        self.protected_topics.contains(topic)
    }

    pub fn may_drop(&self, topic: &TopicName, priority: &PriorityLane) -> bool {
        !self.protects_topic(topic)
            && !self.protected_priorities.contains(priority)
            && self.droppable_priorities.contains(priority)
    }

    pub fn classify(&self, queue_depth: usize) -> BackpressureState {
        let utilization = if self.max_queue_depth == 0 {
            0.0
        } else {
            queue_depth as f32 / self.max_queue_depth as f32
        };

        let level = if utilization >= 0.95 {
            BackpressureLevel::ShutdownProtection
        } else if utilization >= 0.85 {
            BackpressureLevel::Critical
        } else if utilization >= 0.70 {
            BackpressureLevel::Degraded
        } else if utilization >= 0.50 {
            BackpressureLevel::Warning
        } else {
            BackpressureLevel::Normal
        };

        let active_actions = match level {
            BackpressureLevel::Normal => Vec::new(),
            BackpressureLevel::Warning => vec![BackpressureAction::SampleLowPriorityEvents],
            BackpressureLevel::Degraded => vec![
                BackpressureAction::DisableExpensiveEnrichment,
                BackpressureAction::SampleLowPriorityEvents,
            ],
            BackpressureLevel::Critical => self.degradation_actions.clone(),
            BackpressureLevel::ShutdownProtection => {
                let mut actions = self.degradation_actions.clone();
                actions.push(BackpressureAction::StopNonCriticalWork);
                actions
            }
        };

        BackpressureState {
            level,
            queue_depth,
            max_queue_depth: self.max_queue_depth,
            dropped_low_priority_events: 0,
            active_actions,
        }
    }
}

impl Default for BackpressurePolicy {
    fn default() -> Self {
        Self::v1_default()
    }
}

fn topic(value: &str) -> TopicName {
    TopicName::new(value).expect("core protected topic is valid")
}
