use super::*;
use crate::event_bus::topic::{
    AUDIT_EVENT, GRAPH_HINT, NETWORK_FLOW_RECORD, RESPONSE_PLAN, RESPONSE_RESULT,
    RESPONSE_ROLLBACK_RESULT, SECURITY_ALERT, SECURITY_EVIDENCE, SECURITY_FINDING,
    SECURITY_INCIDENT, SECURITY_RISK,
};
use crate::event_bus::{PriorityLane, TopicName};
use sentinel_contracts::{PipelineId, PluginId};
use std::collections::BTreeMap;

fn topic(value: &str) -> TopicName {
    TopicName::new(value).expect("topic")
}

fn node(name: &str, stage: PipelineStage, input: Vec<&str>, output: Vec<&str>) -> PipelineNode {
    PipelineNode::new(
        name,
        stage,
        StageBinding::metadata_only(
            input.into_iter().map(topic).collect(),
            output.into_iter().map(topic).collect(),
        ),
    )
    .expect("node")
}

#[test]
fn dag_execution_plan_represents_required_stage_types() {
    let mut dag = PipelineDag::new("metadata security story").expect("dag");

    let source = dag
        .add_node(node(
            "flow_source",
            PipelineStage::Source,
            Vec::new(),
            vec![NETWORK_FLOW_RECORD],
        ))
        .expect("source");
    let transform = dag
        .add_node(node(
            "flow_transform",
            PipelineStage::Transform,
            vec![NETWORK_FLOW_RECORD],
            vec![NETWORK_FLOW_RECORD],
        ))
        .expect("transform");
    let enrichment = dag
        .add_node(node(
            "local_enrichment",
            PipelineStage::Enrichment,
            vec![NETWORK_FLOW_RECORD],
            vec![SECURITY_EVIDENCE],
        ))
        .expect("enrichment");
    let detection = dag
        .add_node(node(
            "finding_detection",
            PipelineStage::Detection,
            vec![SECURITY_EVIDENCE],
            vec![SECURITY_FINDING],
        ))
        .expect("detection");
    let evidence = dag
        .add_node(node(
            "evidence_management",
            PipelineStage::Evidence,
            vec![SECURITY_FINDING],
            vec![SECURITY_EVIDENCE],
        ))
        .expect("evidence");
    let risk = dag
        .add_node(node(
            "risk_stage",
            PipelineStage::Risk,
            vec![SECURITY_EVIDENCE],
            vec![SECURITY_RISK],
        ))
        .expect("risk");
    let graph = dag
        .add_node(node(
            "graph_stage",
            PipelineStage::Graph,
            vec![SECURITY_RISK],
            vec![GRAPH_HINT],
        ))
        .expect("graph");
    let response = dag
        .add_node(node(
            "response_planning",
            PipelineStage::Response,
            vec![GRAPH_HINT],
            vec![RESPONSE_PLAN],
        ))
        .expect("response");
    let report = dag
        .add_node(node(
            "incident_report",
            PipelineStage::Report,
            vec![RESPONSE_PLAN],
            vec!["report.generated"],
        ))
        .expect("report");

    for (node_id, dependency) in [
        (&transform, source),
        (&enrichment, transform.clone()),
        (&detection, enrichment.clone()),
        (&evidence, detection.clone()),
        (&risk, evidence.clone()),
        (&graph, risk.clone()),
        (&response, graph.clone()),
        (&report, response.clone()),
    ] {
        dag.add_dependency(node_id, dependency).expect("dependency");
    }

    let plan = dag.build_execution_plan().expect("plan");
    let stages = plan
        .steps
        .iter()
        .map(|step| step.stage.clone())
        .collect::<Vec<_>>();

    assert!(stages.contains(&PipelineStage::Source));
    assert!(stages.contains(&PipelineStage::Transform));
    assert!(stages.contains(&PipelineStage::Enrichment));
    assert!(stages.contains(&PipelineStage::Detection));
    assert!(stages.contains(&PipelineStage::Evidence));
    assert!(stages.contains(&PipelineStage::Risk));
    assert!(stages.contains(&PipelineStage::Graph));
    assert!(stages.contains(&PipelineStage::Response));
    assert!(stages.contains(&PipelineStage::Report));
    assert!(!plan.routes.is_empty());
}

#[test]
fn replay_context_disables_real_response_execution_by_default() {
    let replay = ReplayContext::new(ReplayScope::Pipeline, "regression replay");
    let scheduler = Scheduler::replay(replay.clone());

    assert!(replay.response_execution_disabled);
    assert!(replay.firewall_qos_isolation_disabled);
    assert!(replay.online_lookup_disabled);
    assert!(scheduler.response_execution_disabled());
}

#[test]
fn backpressure_policy_preserves_critical_paths() {
    let policy = BackpressurePolicy::v1_default();

    for protected in [
        AUDIT_EVENT,
        RESPONSE_RESULT,
        RESPONSE_ROLLBACK_RESULT,
        SECURITY_INCIDENT,
        SECURITY_ALERT,
        SECURITY_FINDING,
    ] {
        let topic = topic(protected);
        assert!(policy.protects_topic(&topic));
        assert!(!policy.may_drop(&topic, &PriorityLane::P5UiRefresh));
    }

    let report_topic = topic("report.generated");
    assert!(policy.may_drop(&report_topic, &PriorityLane::P5UiRefresh));

    let state = policy.classify(policy.max_queue_depth);
    assert_eq!(state.level, BackpressureLevel::ShutdownProtection);
    assert!(state
        .active_actions
        .contains(&BackpressureAction::PreserveCriticalDetection));
}

#[test]
fn checkpoint_records_are_scoped_cursor_based_and_privacy_safe() {
    let handle = CheckpointHandle::new(
        CheckpointScope::PluginStage {
            pipeline_id: PipelineId::new_v4(),
            plugin_id: PluginId::new_v4(),
            stage: PipelineStage::Risk,
        },
        "risk_cursor",
    )
    .expect("handle");
    let mut metadata = BTreeMap::new();
    metadata.insert("redacted_entity_count".to_string(), "42".to_string());

    let record = CheckpointRecord::new(&handle, "cursor-123", metadata).expect("checkpoint");

    assert_eq!(record.cursor, "cursor-123");
    assert!(!record.stores_raw_packet);
    assert!(!record.stores_raw_payload);
    assert!(!record.stores_http_body);
}

#[test]
fn checkpoint_rejects_raw_or_secret_metadata_keys() {
    let handle = CheckpointHandle::new(
        CheckpointScope::Pipeline {
            pipeline_id: PipelineId::new_v4(),
        },
        "cursor",
    )
    .expect("handle");
    let mut metadata = BTreeMap::new();
    metadata.insert("raw_payload_offset".to_string(), "unsafe".to_string());

    let error = CheckpointRecord::new(&handle, "cursor-123", metadata).expect_err("reject");

    assert!(matches!(error, CheckpointError::ForbiddenMetadataKey(_)));
}

#[test]
fn scheduler_is_local_and_delays_low_priority_under_critical_backpressure() {
    let mut dag = PipelineDag::new("scheduler test").expect("dag");
    let mut low_priority = node(
        "optional_report_refresh",
        PipelineStage::Report,
        Vec::new(),
        vec!["report.generated"],
    );
    low_priority.binding.priority_lane = PriorityLane::P5UiRefresh;
    let low_id = dag.add_node(low_priority).expect("node");

    let mut scheduler = Scheduler::new(SchedulerKind::Priority);
    scheduler.metadata.max_concurrency = 4;
    let plan = scheduler.build_plan(&dag).expect("plan");
    let decision = scheduler.decide_ready(
        &plan,
        &[],
        scheduler.backpressure_policy.max_queue_depth,
        None,
    );

    assert!(scheduler.metadata.local_in_process);
    assert!(scheduler.metadata.at_least_once_delivery);
    assert!(decision.delayed_nodes.contains(&low_id));
    assert!(decision.ready_nodes.is_empty());
}
