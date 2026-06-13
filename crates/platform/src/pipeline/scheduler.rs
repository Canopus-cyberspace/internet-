use crate::event_bus::PriorityLane;
use crate::pipeline::backpressure::{BackpressurePolicy, BackpressureState};
use crate::pipeline::dag::{ExecutionPlan, PipelineDag, PipelineDagError, PipelineNodeId};
use crate::pipeline::replay::ReplayContext;
use sentinel_contracts::Timestamp;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerKind {
    Realtime,
    Batch,
    Periodic,
    Priority,
    Resource,
    Replay,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerMetadata {
    pub kind: SchedulerKind,
    pub max_concurrency: usize,
    pub interval_seconds: Option<u64>,
    pub at_least_once_delivery: bool,
    pub local_in_process: bool,
}

impl SchedulerMetadata {
    pub fn new(kind: SchedulerKind) -> Self {
        Self {
            kind,
            max_concurrency: 1,
            interval_seconds: None,
            at_least_once_delivery: true,
            local_in_process: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleDecision {
    pub ready_nodes: Vec<PipelineNodeId>,
    pub delayed_nodes: Vec<PipelineNodeId>,
    pub backpressure_state: BackpressureState,
    pub replay_context: Option<ReplayContext>,
    pub decided_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scheduler {
    pub metadata: SchedulerMetadata,
    pub backpressure_policy: BackpressurePolicy,
}

impl Scheduler {
    pub fn new(kind: SchedulerKind) -> Self {
        Self {
            metadata: SchedulerMetadata::new(kind),
            backpressure_policy: BackpressurePolicy::default(),
        }
    }

    pub fn build_plan(&self, dag: &PipelineDag) -> Result<ExecutionPlan, PipelineDagError> {
        dag.build_execution_plan()
    }

    pub fn decide_ready(
        &self,
        plan: &ExecutionPlan,
        completed_nodes: &[PipelineNodeId],
        queue_depth: usize,
        replay_context: Option<ReplayContext>,
    ) -> ScheduleDecision {
        let completed = completed_nodes.iter().cloned().collect::<HashSet<_>>();
        let mut ready_nodes = Vec::new();
        let mut delayed_nodes = Vec::new();
        let backpressure_state = self.backpressure_policy.classify(queue_depth);

        for step in &plan.steps {
            if completed.contains(&step.node_id) {
                continue;
            }

            if self.should_delay_for_backpressure(step.priority_lane.clone(), &backpressure_state) {
                delayed_nodes.push(step.node_id.clone());
            } else {
                ready_nodes.push(step.node_id.clone());
            }
        }

        ready_nodes.truncate(self.metadata.max_concurrency.max(1));

        ScheduleDecision {
            ready_nodes,
            delayed_nodes,
            backpressure_state,
            replay_context,
            decided_at: Timestamp::now(),
        }
    }

    pub fn replay(replay_context: ReplayContext) -> ReplayScheduler {
        ReplayScheduler {
            scheduler: Self::new(SchedulerKind::Replay),
            replay_context,
        }
    }

    fn should_delay_for_backpressure(
        &self,
        priority: PriorityLane,
        state: &BackpressureState,
    ) -> bool {
        matches!(
            state.level,
            crate::pipeline::backpressure::BackpressureLevel::Critical
                | crate::pipeline::backpressure::BackpressureLevel::ShutdownProtection
        ) && priority.can_drop_under_pressure()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayScheduler {
    pub scheduler: Scheduler,
    pub replay_context: ReplayContext,
}

impl ReplayScheduler {
    pub fn build_plan(&self, dag: &PipelineDag) -> Result<ExecutionPlan, PipelineDagError> {
        self.scheduler.build_plan(dag)
    }

    pub fn response_execution_disabled(&self) -> bool {
        self.replay_context.real_response_forbidden()
    }
}
