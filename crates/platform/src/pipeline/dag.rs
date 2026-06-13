use crate::event_bus::{EventRoute, PriorityLane, RetryPolicy, TopicName};
use crate::pipeline::stage::{PipelineNodeRuntimeState, PipelineStage, StageBinding};
use sentinel_contracts::{PipelineId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PipelineNodeId(Uuid);

impl PipelineNodeId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse_str(value: &str) -> Result<Self, PipelineNodeIdParseError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| PipelineNodeIdParseError {
                value: value.to_string(),
            })
    }
}

impl fmt::Display for PipelineNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PipelineNodeId {
    type Err = PipelineNodeIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_str(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipelineNodeIdParseError {
    value: String,
}

impl fmt::Display for PipelineNodeIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid PipelineNodeId UUID: {}", self.value)
    }
}

impl std::error::Error for PipelineNodeIdParseError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineNode {
    pub node_id: PipelineNodeId,
    pub name: String,
    pub stage: PipelineStage,
    pub binding: StageBinding,
    pub dependencies: Vec<PipelineNodeId>,
    pub optional: bool,
    pub enabled: bool,
    pub runtime_state: PipelineNodeRuntimeState,
}

impl PipelineNode {
    pub fn new(
        name: impl Into<String>,
        stage: PipelineStage,
        binding: StageBinding,
    ) -> Result<Self, PipelineDagError> {
        Ok(Self {
            node_id: PipelineNodeId::new_v4(),
            name: require_non_empty("pipeline node name", name.into())?,
            stage,
            binding,
            dependencies: Vec::new(),
            optional: false,
            enabled: true,
            runtime_state: PipelineNodeRuntimeState::default(),
        })
    }

    pub fn depends_on(mut self, dependency: PipelineNodeId) -> Self {
        self.dependencies.push(dependency);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPlanStep {
    pub node_id: PipelineNodeId,
    pub stage: PipelineStage,
    pub order_index: usize,
    pub input_topics: Vec<TopicName>,
    pub output_topics: Vec<TopicName>,
    pub priority_lane: PriorityLane,
    pub retry_policy: RetryPolicy,
    pub idempotency_required: bool,
    pub checkpoint_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub pipeline_id: PipelineId,
    pub steps: Vec<ExecutionPlanStep>,
    pub routes: Vec<EventRoute>,
    pub created_at: Timestamp,
}

impl ExecutionPlan {
    pub fn step_for(&self, node_id: &PipelineNodeId) -> Option<&ExecutionPlanStep> {
        self.steps.iter().find(|step| &step.node_id == node_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineDag {
    pub pipeline_id: PipelineId,
    pub name: String,
    pub nodes: Vec<PipelineNode>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl PipelineDag {
    pub fn new(name: impl Into<String>) -> Result<Self, PipelineDagError> {
        let now = Timestamp::now();
        Ok(Self {
            pipeline_id: PipelineId::new_v4(),
            name: require_non_empty("pipeline name", name.into())?,
            nodes: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn add_node(&mut self, node: PipelineNode) -> Result<PipelineNodeId, PipelineDagError> {
        if self
            .nodes
            .iter()
            .any(|existing| existing.node_id == node.node_id)
        {
            return Err(PipelineDagError::DuplicateNode(node.node_id));
        }

        let node_id = node.node_id.clone();
        self.nodes.push(node);
        self.updated_at = Timestamp::now();
        Ok(node_id)
    }

    pub fn add_dependency(
        &mut self,
        node_id: &PipelineNodeId,
        dependency_id: PipelineNodeId,
    ) -> Result<(), PipelineDagError> {
        if self.node(&dependency_id).is_none() {
            return Err(PipelineDagError::MissingNode(dependency_id));
        }

        let Some(node) = self.nodes.iter_mut().find(|node| &node.node_id == node_id) else {
            return Err(PipelineDagError::MissingNode(node_id.clone()));
        };

        if !node.dependencies.contains(&dependency_id) {
            node.dependencies.push(dependency_id);
            self.updated_at = Timestamp::now();
        }
        Ok(())
    }

    pub fn node(&self, node_id: &PipelineNodeId) -> Option<&PipelineNode> {
        self.nodes.iter().find(|node| &node.node_id == node_id)
    }

    pub fn validate(&self) -> Result<(), PipelineDagError> {
        let ids = self
            .nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect::<HashSet<_>>();

        for node in &self.nodes {
            if node.name.trim().is_empty() {
                return Err(PipelineDagError::EmptyField("pipeline node name"));
            }
            for dependency in &node.dependencies {
                if !ids.contains(dependency) {
                    return Err(PipelineDagError::MissingNode(dependency.clone()));
                }
            }
        }

        if let Some(cycle) = self.detect_cycle() {
            return Err(PipelineDagError::CycleDetected(cycle));
        }

        Ok(())
    }

    pub fn build_execution_plan(&self) -> Result<ExecutionPlan, PipelineDagError> {
        self.validate()?;
        let ordered = self.topological_order()?;
        let mut steps = Vec::new();

        for (order_index, node_id) in ordered.iter().enumerate() {
            let node = self
                .node(node_id)
                .ok_or_else(|| PipelineDagError::MissingNode(node_id.clone()))?;
            if !node.enabled {
                continue;
            }
            steps.push(ExecutionPlanStep {
                node_id: node.node_id.clone(),
                stage: node.stage.clone(),
                order_index,
                input_topics: node.binding.input_topics.clone(),
                output_topics: node.binding.output_topics.clone(),
                priority_lane: node.binding.priority_lane.clone(),
                retry_policy: node.binding.retry_policy.clone(),
                idempotency_required: true,
                checkpoint_required: node.binding.checkpoint_required,
            });
        }

        Ok(ExecutionPlan {
            pipeline_id: self.pipeline_id.clone(),
            routes: self.routes()?,
            steps,
            created_at: Timestamp::now(),
        })
    }

    fn routes(&self) -> Result<Vec<EventRoute>, PipelineDagError> {
        let mut routes = Vec::new();
        for node in &self.nodes {
            for dependency_id in &node.dependencies {
                let dependency = self
                    .node(dependency_id)
                    .ok_or_else(|| PipelineDagError::MissingNode(dependency_id.clone()))?;
                for topic in &dependency.binding.output_topics {
                    if node.binding.input_topics.contains(topic) {
                        routes.push(
                            EventRoute::new(topic.clone(), node.name.clone())
                                .map_err(|_| PipelineDagError::EmptyField("route consumer"))?,
                        );
                    }
                }
            }
        }
        Ok(routes)
    }

    fn topological_order(&self) -> Result<Vec<PipelineNodeId>, PipelineDagError> {
        let mut indegree: HashMap<PipelineNodeId, usize> = HashMap::new();
        let mut reverse: HashMap<PipelineNodeId, Vec<PipelineNodeId>> = HashMap::new();

        for node in &self.nodes {
            indegree.entry(node.node_id.clone()).or_insert(0);
            for dependency in &node.dependencies {
                reverse
                    .entry(dependency.clone())
                    .or_default()
                    .push(node.node_id.clone());
                *indegree.entry(node.node_id.clone()).or_insert(0) += 1;
            }
        }

        let mut ready = indegree
            .iter()
            .filter_map(|(node_id, count)| (*count == 0).then_some(node_id.clone()))
            .collect::<Vec<_>>();
        ready.sort_by_key(ToString::to_string);

        let mut queue = VecDeque::from(ready);
        let mut ordered = Vec::new();

        while let Some(node_id) = queue.pop_front() {
            ordered.push(node_id.clone());
            let mut dependents = reverse.remove(&node_id).unwrap_or_default();
            dependents.sort_by_key(ToString::to_string);

            for dependent in dependents {
                if let Some(count) = indegree.get_mut(&dependent) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        queue.push_back(dependent);
                    }
                }
            }
        }

        if ordered.len() != self.nodes.len() {
            return Err(PipelineDagError::CycleDetected(Vec::new()));
        }

        Ok(ordered)
    }

    fn detect_cycle(&self) -> Option<Vec<PipelineNodeId>> {
        self.topological_order()
            .err()
            .and_then(|error| match error {
                PipelineDagError::CycleDetected(cycle) => Some(cycle),
                _ => None,
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipelineDagError {
    EmptyField(&'static str),
    DuplicateNode(PipelineNodeId),
    MissingNode(PipelineNodeId),
    CycleDetected(Vec<PipelineNodeId>),
}

impl fmt::Display for PipelineDagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::DuplicateNode(node_id) => write!(f, "duplicate pipeline node: {node_id}"),
            Self::MissingNode(node_id) => write!(f, "missing pipeline node: {node_id}"),
            Self::CycleDetected(_) => write!(f, "pipeline DAG contains a cycle"),
        }
    }
}

impl std::error::Error for PipelineDagError {}

fn require_non_empty(field: &'static str, value: String) -> Result<String, PipelineDagError> {
    if value.trim().is_empty() {
        Err(PipelineDagError::EmptyField(field))
    } else {
        Ok(value)
    }
}
