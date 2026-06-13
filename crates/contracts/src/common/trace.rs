use crate::common::{CausalityId, CorrelationId, PipelineId, ReplayId, TraceId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceContext {
    pub trace_id: TraceId,
    pub correlation_id: Option<CorrelationId>,
    pub causality_id: Option<CausalityId>,
    pub pipeline_id: Option<PipelineId>,
    pub replay_id: Option<ReplayId>,
}

impl TraceContext {
    pub fn new(trace_id: TraceId) -> Self {
        Self {
            trace_id,
            correlation_id: None,
            causality_id: None,
            pipeline_id: None,
            replay_id: None,
        }
    }

    pub fn new_root() -> Self {
        Self::new(TraceId::new_v4())
    }
}
