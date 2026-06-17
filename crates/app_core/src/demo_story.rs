//! Safe DEMO_ONLY attack-story replay for Task 540.
//!
//! The runner builds a deterministic local read model from fixture metadata.
//! It never captures packets, persists payloads, or executes response actions.

use crate::mutation_commands::fixture_response_planning_output;
use crate::read_commands::ReadOnlyCommandState;
use chrono::{DateTime, Duration, Utc};
use sentinel_capabilities::{
    ExportDestinationMetadata, ExportFileHash, ExportHistoryRecord, ExportHistoryStorageAdapter,
    ExportHistoryStore, ResponsePlanningInput, RiskBasedAlertingInput, RiskBasedAlertingPlugin,
};
use sentinel_contracts::report::ExportFormat;
use sentinel_contracts::{
    Alert, AlertState, ApprovalState, AttackMapping, AuditRef, CanonicalGraphEdge,
    CanonicalGraphNode, CommandResult, CoreError, CorrelationId, DnsAnswer, DnsFeatures,
    DnsObservation, EntityId, EntityRef, EntityType, ErrorCode, ErrorSeverity, EvidenceBundle,
    EvidenceId, EvidenceItem, Finding, FindingExplanation, FindingId, FindingState, FlowRecord,
    GraphBadge, GraphBadgeTone, GraphDetailRef, GraphEdgeId, GraphEdgeStyleHint, GraphEdgeType,
    GraphEdgeViewModel, GraphLegend, GraphLegendItem, GraphNodeId, GraphNodeStatus, GraphNodeType,
    GraphNodeViewModel, GraphPath, GraphPathId, GraphPathSummary, GraphPathType, GraphPositionHint,
    GraphRedactionSummary, GraphScope, GraphType, GraphViewModel, Incident, IncidentState,
    IntelligenceRecordId, IpAddress, MappingProvenance, NetworkDirection, PluginId, PrivacyClass,
    ProcessContext, ProcessContextId, QualityScore, RedactedDataCategory, RedactedLabel,
    RedactionStatus, RedactionSummary, Report, ReportSection, ReportSectionType, ReportType,
    ResponseActionId, ResponsePlan, ResponsePlanSource, ResponsePolicy, ResponseResult, RiskEvent,
    RiskHint, RiskReason, SchemaVersion, SecuritySeverity, Timestamp, TlsObservation, TraceId,
    TransportProtocol,
};
use sentinel_storage::{
    GraphStore, LogicalRecord, LogicalStore, ResponseStore, SqliteStoreFactory, StoreKind,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt::Display;
use std::str::FromStr;

const FIXTURE_ATTACK_STORY_JSON: &str =
    include_str!("../../../fixtures/mock/fixture_attack_story.json");
const STORY_START_RFC3339: &str = "2026-06-03T00:00:00Z";
const DEMO_STORY_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
const RISK_RUNTIME_PROVENANCE: &str = "risk.fixture.pure_capability.process";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureAttackStory {
    pub story_id: String,
    pub fixture_mode: String,
    pub title_redacted: String,
    pub metadata: FixtureStoryMetadata,
    pub stages: Vec<StoryStageDefinition>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureStoryMetadata {
    pub local_ip: String,
    pub resolver_ip: String,
    pub c2_ip: String,
    pub exfil_ip: String,
    pub lateral_ip: String,
    pub c2_domain_protected: String,
    pub exfil_domain_protected: String,
    pub host_label_redacted: String,
    pub process_name_redacted: String,
    pub process_path_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoryStageDefinition {
    pub stage: StoryStage,
    pub summary_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoryStage {
    MetadataInput,
    Observation,
    EnrichmentContext,
    FindingEvidence,
    RiskAlertIncident,
    Graph,
    ResponseRecommendation,
    RedactedReport,
}

impl StoryStage {
    pub fn ordered() -> [Self; 8] {
        [
            Self::MetadataInput,
            Self::Observation,
            Self::EnrichmentContext,
            Self::FindingEvidence,
            Self::RiskAlertIncident,
            Self::Graph,
            Self::ResponseRecommendation,
            Self::RedactedReport,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MetadataInput => "metadata_input",
            Self::Observation => "observation",
            Self::EnrichmentContext => "enrichment_context",
            Self::FindingEvidence => "finding_evidence",
            Self::RiskAlertIncident => "risk_alert_incident",
            Self::Graph => "graph",
            Self::ResponseRecommendation => "response_recommendation",
            Self::RedactedReport => "redacted_report",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoryStageResult {
    pub stage: StoryStage,
    pub summary_redacted: String,
    pub started_at: Timestamp,
    pub completed_at: Timestamp,
    pub duration_millis: u64,
    pub input_artifact_count: u32,
    pub produced_artifact_count: u32,
    pub evidence_ref_count: u32,
    pub replay_only: bool,
    pub safe_replay_note_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DemoStoryResult {
    pub story_id: String,
    pub fixture_mode: String,
    pub title_redacted: String,
    pub replay_only: bool,
    pub execution_disabled: bool,
    pub started_at: Timestamp,
    pub completed_at: Timestamp,
    pub stage_count: u32,
    pub stages: Vec<StoryStageResult>,
    pub flow_count: u32,
    pub dns_observation_count: u32,
    pub tls_observation_count: u32,
    pub evidence_item_count: u32,
    pub finding_count: u32,
    pub risk_event_count: u32,
    pub alert_count: u32,
    pub incident_count: u32,
    pub graph_view_count: u32,
    pub graph_node_count: u32,
    pub graph_edge_count: u32,
    pub graph_path_count: u32,
    pub response_plan_count: u32,
    pub recommended_action_count: u32,
    pub policy_decision_count: u32,
    pub report_count: u32,
    pub report_section_count: u32,
    pub export_history_count: u32,
    pub incident_id: String,
    pub report_id: String,
    pub export_result_id: String,
    pub graph_view_id: String,
    pub response_plan_id: String,
    pub redaction_summary: RedactionSummary,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DemoStoryReadModel {
    pub story_id: String,
    pub fixture_mode: String,
    pub process_contexts: Vec<ProcessContext>,
    pub flows: Vec<FlowRecord>,
    pub dns: Vec<DnsObservation>,
    pub tls: Vec<TlsObservation>,
    pub evidence_items: Vec<EvidenceItem>,
    pub evidence_bundles: Vec<EvidenceBundle>,
    pub findings: Vec<Finding>,
    pub risk_events: Vec<RiskEvent>,
    pub alerts: Vec<Alert>,
    pub incidents: Vec<Incident>,
    pub canonical_graph_nodes: Vec<CanonicalGraphNode>,
    pub canonical_graph_edges: Vec<CanonicalGraphEdge>,
    pub graph_paths: Vec<GraphPath>,
    pub graph_views: Vec<GraphViewModel>,
    pub response_plans: Vec<ResponsePlan>,
    pub reports: Vec<Report>,
    pub export_history: ExportHistoryStore,
}

impl DemoStoryReadModel {
    pub fn into_read_state(self, state: ReadOnlyCommandState) -> ReadOnlyCommandState {
        state
            .with_flows(self.flows)
            .with_dns(self.dns)
            .with_tls(self.tls)
            .with_findings(self.findings)
            .with_alerts(self.alerts)
            .with_incidents(self.incidents)
            .with_graph_views(self.graph_views)
            .with_response_plans(self.response_plans)
            .with_reports(self.reports)
            .with_export_history(self.export_history)
    }

    pub fn persist_to_storage(
        &self,
        stores: &SqliteStoreFactory<'_>,
    ) -> CommandResult<DemoStoryPersistenceSummary> {
        clear_previous_demo_records(stores, self)?;
        let mut summary = DemoStoryPersistenceSummary::default();

        let process_context_store = stores.process_context_store();
        for context in &self.process_contexts {
            process_context_store
                .append(logical_record(
                    context.process_context_id.clone(),
                    StoreKind::ProcessContext,
                    context,
                    context.captured_at.clone(),
                    &self.story_id,
                    &self.fixture_mode,
                    Vec::new(),
                )?)
                .map_err(storage_error)?;
            summary.process_context_count += 1;
        }

        let flow_store = stores.flow_store();
        for flow in &self.flows {
            flow_store
                .append(logical_record(
                    flow.flow_id.clone(),
                    StoreKind::Flow,
                    flow,
                    flow.end_time
                        .clone()
                        .unwrap_or_else(|| flow.start_time.clone()),
                    &self.story_id,
                    &self.fixture_mode,
                    flow.asset_ref.clone().into_iter().collect(),
                )?)
                .map_err(storage_error)?;
            summary.flow_count += 1;
        }

        let dns_store = stores.dns_store();
        for dns in &self.dns {
            dns_store
                .append(logical_record(
                    dns.dns_observation_id.clone(),
                    StoreKind::Dns,
                    dns,
                    dns.timestamp.clone(),
                    &self.story_id,
                    &self.fixture_mode,
                    dns.asset_ref.clone().into_iter().collect(),
                )?)
                .map_err(storage_error)?;
            summary.dns_observation_count += 1;
        }

        let tls_store = stores.tls_store();
        for tls in &self.tls {
            tls_store
                .append(logical_record(
                    tls.tls_observation_id.clone(),
                    StoreKind::Tls,
                    tls,
                    tls.timestamp.clone(),
                    &self.story_id,
                    &self.fixture_mode,
                    tls.src_entity
                        .clone()
                        .into_iter()
                        .chain(tls.dst_entity.clone())
                        .collect(),
                )?)
                .map_err(storage_error)?;
            summary.tls_observation_count += 1;
        }

        let evidence_store = stores.evidence_store();
        for evidence in &self.evidence_items {
            evidence_store
                .append(logical_record(
                    evidence.evidence_id.clone(),
                    StoreKind::Evidence,
                    evidence,
                    evidence.timestamp.clone(),
                    &self.story_id,
                    &self.fixture_mode,
                    evidence.entity_refs.clone(),
                )?)
                .map_err(storage_error)?;
            summary.evidence_item_count += 1;
        }

        let finding_store = stores.finding_store();
        for finding in &self.findings {
            finding_store
                .append(logical_record(
                    finding.id().clone(),
                    StoreKind::Finding,
                    finding,
                    story_time(5)?,
                    &self.story_id,
                    &self.fixture_mode,
                    finding.entity_refs().to_vec(),
                )?)
                .map_err(storage_error)?;
            summary.finding_count += 1;
        }

        let risk_store = stores.risk_store();
        for risk in &self.risk_events {
            risk_store
                .append(logical_value_record(
                    risk.risk_event_id.clone(),
                    StoreKind::Risk,
                    security_runtime_storage_metadata(risk, RISK_RUNTIME_PROVENANCE)?,
                    risk.created_at.clone(),
                    &self.story_id,
                    &self.fixture_mode,
                    vec![risk.entity_ref.clone()],
                )?)
                .map_err(storage_error)?;
            summary.risk_event_count += 1;
        }

        let alert_store = stores.alert_store();
        for alert in &self.alerts {
            alert_store
                .append(logical_value_record(
                    alert.id().clone(),
                    StoreKind::Alert,
                    security_runtime_storage_metadata(alert, RISK_RUNTIME_PROVENANCE)?,
                    story_time(7)?,
                    &self.story_id,
                    &self.fixture_mode,
                    alert.entity_refs().to_vec(),
                )?)
                .map_err(storage_error)?;
            summary.alert_count += 1;
        }

        let incident_store = stores.incident_store();
        for incident in &self.incidents {
            incident_store
                .append(logical_value_record(
                    incident.id().clone(),
                    StoreKind::Incident,
                    security_runtime_storage_metadata(incident, RISK_RUNTIME_PROVENANCE)?,
                    story_time(9)?,
                    &self.story_id,
                    &self.fixture_mode,
                    Vec::new(),
                )?)
                .map_err(storage_error)?;
            summary.incident_count += 1;
        }

        let graph_store = stores.graph_store();
        for node in &self.canonical_graph_nodes {
            graph_store
                .nodes()
                .append(logical_record(
                    node.node_id.clone(),
                    StoreKind::GraphNode,
                    node,
                    node.last_seen.clone(),
                    &self.story_id,
                    &self.fixture_mode,
                    node.entity_ref.clone().into_iter().collect(),
                )?)
                .map_err(storage_error)?;
            summary.canonical_graph_node_count += 1;
        }
        for edge in &self.canonical_graph_edges {
            graph_store
                .edges()
                .append(logical_record(
                    edge.edge_id.clone(),
                    StoreKind::GraphEdge,
                    edge,
                    edge.last_seen.clone(),
                    &self.story_id,
                    &self.fixture_mode,
                    Vec::new(),
                )?)
                .map_err(storage_error)?;
            summary.canonical_graph_edge_count += 1;
        }
        for path in &self.graph_paths {
            graph_store
                .paths()
                .append(logical_record(
                    path.path_id.clone(),
                    StoreKind::GraphPath,
                    path,
                    story_time(9)?,
                    &self.story_id,
                    &self.fixture_mode,
                    Vec::new(),
                )?)
                .map_err(storage_error)?;
            summary.graph_path_count += 1;
        }

        let response_store = stores.response_store();
        for plan in &self.response_plans {
            response_store
                .plans()
                .append(logical_value_record(
                    plan.plan_id.clone(),
                    StoreKind::ResponsePlan,
                    response_plan_storage_metadata(plan)?,
                    plan.created_at.clone(),
                    &self.story_id,
                    &self.fixture_mode,
                    Vec::new(),
                )?)
                .map_err(storage_error)?;
            summary.response_plan_count += 1;
        }

        let report_store = stores.report_store();
        for report in &self.reports {
            report_store
                .append(logical_record(
                    report.report_id.clone(),
                    StoreKind::Report,
                    report,
                    report.updated_at.clone(),
                    &self.story_id,
                    &self.fixture_mode,
                    Vec::new(),
                )?)
                .map_err(storage_error)?;
            summary.report_count += 1;
        }

        let export_history_summary = ExportHistoryStorageAdapter::new()
            .persist_store(stores, &self.export_history)
            .map_err(|error| {
                storage_error(format!("export history persistence failed: {error}"))
            })?;
        summary.export_history_count = export_history_summary.history_records as u32;

        Ok(summary)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoStoryPersistenceSummary {
    pub process_context_count: u32,
    pub flow_count: u32,
    pub dns_observation_count: u32,
    pub tls_observation_count: u32,
    pub evidence_item_count: u32,
    pub finding_count: u32,
    pub risk_event_count: u32,
    pub alert_count: u32,
    pub incident_count: u32,
    pub canonical_graph_node_count: u32,
    pub canonical_graph_edge_count: u32,
    pub graph_path_count: u32,
    pub response_plan_count: u32,
    pub report_count: u32,
    pub export_history_count: u32,
}

fn clear_previous_demo_records(
    stores: &SqliteStoreFactory<'_>,
    read_model: &DemoStoryReadModel,
) -> CommandResult<()> {
    let process_context_store = stores.process_context_store();
    for context in &read_model.process_contexts {
        process_context_store
            .delete_by_id(&context.process_context_id)
            .map_err(storage_error)?;
    }

    let flow_store = stores.flow_store();
    for flow in &read_model.flows {
        flow_store
            .delete_by_id(&flow.flow_id)
            .map_err(storage_error)?;
    }

    let dns_store = stores.dns_store();
    for dns in &read_model.dns {
        dns_store
            .delete_by_id(&dns.dns_observation_id)
            .map_err(storage_error)?;
    }

    let tls_store = stores.tls_store();
    for tls in &read_model.tls {
        tls_store
            .delete_by_id(&tls.tls_observation_id)
            .map_err(storage_error)?;
    }

    let evidence_store = stores.evidence_store();
    for evidence in &read_model.evidence_items {
        evidence_store
            .delete_by_id(&evidence.evidence_id)
            .map_err(storage_error)?;
    }

    let finding_store = stores.finding_store();
    for finding in &read_model.findings {
        finding_store
            .delete_by_id(finding.id())
            .map_err(storage_error)?;
    }

    let risk_store = stores.risk_store();
    for risk in &read_model.risk_events {
        risk_store
            .delete_by_id(&risk.risk_event_id)
            .map_err(storage_error)?;
    }

    let alert_store = stores.alert_store();
    for alert in &read_model.alerts {
        alert_store
            .delete_by_id(alert.id())
            .map_err(storage_error)?;
    }

    let incident_store = stores.incident_store();
    for incident in &read_model.incidents {
        incident_store
            .delete_by_id(incident.id())
            .map_err(storage_error)?;
    }

    let graph_store = stores.graph_store();
    graph_store.nodes().delete_all().map_err(storage_error)?;
    graph_store.edges().delete_all().map_err(storage_error)?;
    graph_store.paths().delete_all().map_err(storage_error)?;

    let response_store = stores.response_store();
    for plan in &read_model.response_plans {
        response_store
            .plans()
            .delete_by_id(&plan.plan_id)
            .map_err(storage_error)?;
    }

    let report_store = stores.report_store();
    for report in &read_model.reports {
        report_store
            .delete_by_id(&report.report_id)
            .map_err(storage_error)?;
    }

    let export_history_store = stores.export_history_store();
    for record in read_model.export_history.records() {
        export_history_store
            .delete_by_id(&record.export_result_id)
            .map_err(storage_error)?;
    }

    Ok(())
}

fn logical_record<TId, TRecord>(
    id: TId,
    store_kind: StoreKind,
    record: &TRecord,
    record_time: Timestamp,
    story_id: &str,
    fixture_mode: &str,
    entity_refs: Vec<EntityRef>,
) -> CommandResult<LogicalRecord<TId>>
where
    TRecord: Serialize,
{
    Ok(LogicalRecord::metadata_only(
        id,
        DEMO_STORY_SCHEMA_VERSION,
        store_kind.default_storage_privacy_class(),
        fixture_metadata(record, story_id, fixture_mode)?,
    )
    .with_record_time(record_time)
    .with_entity_refs(entity_refs))
}

fn logical_value_record<TId>(
    id: TId,
    store_kind: StoreKind,
    metadata: Value,
    record_time: Timestamp,
    story_id: &str,
    fixture_mode: &str,
    entity_refs: Vec<EntityRef>,
) -> CommandResult<LogicalRecord<TId>> {
    Ok(LogicalRecord::metadata_only(
        id,
        DEMO_STORY_SCHEMA_VERSION,
        store_kind.default_storage_privacy_class(),
        fixture_metadata(&metadata, story_id, fixture_mode)?,
    )
    .with_record_time(record_time)
    .with_entity_refs(entity_refs))
}

fn fixture_metadata<TRecord>(
    record: &TRecord,
    story_id: &str,
    fixture_mode: &str,
) -> CommandResult<Value>
where
    TRecord: Serialize,
{
    let value = to_value(record)?;
    let mut object = match value {
        Value::Object(object) => object,
        other => {
            let mut object = serde_json::Map::new();
            object.insert("record_redacted".to_string(), other);
            object
        }
    };
    object.insert(
        "fixture_mode".to_string(),
        Value::String(fixture_mode.to_string()),
    );
    object.insert(
        "fixture_story_id".to_string(),
        Value::String(story_id.to_string()),
    );
    object.insert(
        "fixture_marker".to_string(),
        Value::String("DEMO_ONLY".to_string()),
    );
    Ok(Value::Object(object))
}

fn response_plan_storage_metadata(plan: &ResponsePlan) -> CommandResult<Value> {
    let action_types = plan
        .recommended_actions
        .iter()
        .map(|action| serde_json::to_value(&action.action_type).map_err(serialization_error))
        .collect::<CommandResult<Vec<_>>>()?;
    let response_levels = plan
        .recommended_actions
        .iter()
        .map(|action| serde_json::to_value(&action.response_level).map_err(serialization_error))
        .collect::<CommandResult<Vec<_>>>()?;
    let approval_required_count = plan
        .recommended_actions
        .iter()
        .filter(|action| action.approval_required)
        .count();
    let execution_allowed_by_default_count = plan
        .recommended_actions
        .iter()
        .filter(|action| action.response_level.execution_allowed_by_default())
        .count();
    let static_runtime_provenance_recorded = plan
        .audit_requirements
        .iter()
        .any(|requirement| requirement == "response.runtime.static_internal.process_batch");
    Ok(json!({
        "record_kind": "demo_response_plan_summary",
        "plan_id": plan.plan_id.to_string(),
        "source": &plan.source,
        "recommended_action_count": plan.recommended_actions.len(),
        "recommended_action_types": action_types,
        "response_levels": response_levels,
        "policy_decision_count": plan.policy_decisions.len(),
        "approval_required": plan.approval_required,
        "approval_required_action_count": approval_required_count,
        "execution_allowed_by_default_count": execution_allowed_by_default_count,
        "static_runtime_provenance_recorded": static_runtime_provenance_recorded,
        "is_replay": plan.is_replay,
        "execution_disabled_in_replay": plan.execution_disabled_in_replay,
        "created_at": plan.created_at.to_string(),
        "created_by_redacted": &plan.created_by
    }))
}

fn security_runtime_storage_metadata<TRecord>(
    record: &TRecord,
    runtime_provenance: &str,
) -> CommandResult<Value>
where
    TRecord: Serialize,
{
    let mut value = to_value(record)?;
    let object = value.as_object_mut().ok_or_else(|| {
        story_error(
            "fixture_contract",
            "security runtime record did not serialize to an object",
            json!({}),
        )
    })?;
    object.insert(
        "static_runtime_provenance".to_string(),
        Value::String(runtime_provenance.to_string()),
    );
    object.insert(
        "static_runtime_provenance_recorded".to_string(),
        Value::Bool(true),
    );
    Ok(value)
}

#[derive(Clone, Debug, PartialEq)]
pub struct FixtureRun {
    pub story: FixtureAttackStory,
    pub read_model: DemoStoryReadModel,
    pub result: DemoStoryResult,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureRunner {
    story: FixtureAttackStory,
}

impl FixtureRunner {
    pub fn from_default_fixture() -> CommandResult<Self> {
        let story = serde_json::from_str(FIXTURE_ATTACK_STORY_JSON).map_err(|error| {
            story_error(
                "fixture_parse",
                "failed to parse fixture attack story",
                json!({ "error_redacted": error.to_string() }),
            )
        })?;
        Self::new(story)
    }

    pub fn new(story: FixtureAttackStory) -> CommandResult<Self> {
        validate_story(&story)?;
        Ok(Self { story })
    }

    pub fn run(&self) -> CommandResult<FixtureRun> {
        let read_model = build_read_model(&self.story)?;
        let result = build_result(&self.story, &read_model)?;
        log_story_stage_transitions(&result);

        Ok(FixtureRun {
            story: self.story.clone(),
            read_model,
            result,
        })
    }
}

fn log_story_stage_transitions(result: &DemoStoryResult) {
    for stage in &result.stages {
        println!(
            "DEMO_STORY_STAGE story_id={} stage={} started_at={} completed_at={} duration_millis={} inputs={} produced={} evidence_refs={} replay_only=true",
            result.story_id,
            stage.stage.as_str(),
            stage.started_at,
            stage.completed_at,
            stage.duration_millis,
            stage.input_artifact_count,
            stage.produced_artifact_count,
            stage.evidence_ref_count
        );
    }
}

fn build_read_model(story: &FixtureAttackStory) -> CommandResult<DemoStoryReadModel> {
    let ids = StoryIds::new()?;
    let trace_id: TraceId = fixed_id(1, "trace_id")?;
    let correlation_id: CorrelationId = fixed_id(2, "correlation_id")?;
    let producer_plugin: PluginId = fixed_id(3, "producer_plugin")?;
    let process_context_id: ProcessContextId = fixed_id(4, "process_context")?;
    let process_context = process_context(process_context_id.clone(), story)?;

    let host_entity = entity_ref(
        10,
        EntityType::Host,
        story.metadata.host_label_redacted.clone(),
    )?;
    let process_entity = entity_ref(
        11,
        EntityType::Process,
        story.metadata.process_name_redacted.clone(),
    )?;
    let c2_domain_entity = entity_ref(
        12,
        EntityType::Domain,
        story.metadata.c2_domain_protected.clone(),
    )?;
    let c2_ip_entity = entity_ref(13, EntityType::Ip, story.metadata.c2_ip.clone())?;
    let exfil_domain_entity = entity_ref(
        14,
        EntityType::Domain,
        story.metadata.exfil_domain_protected.clone(),
    )?;
    let exfil_ip_entity = entity_ref(15, EntityType::Ip, story.metadata.exfil_ip.clone())?;
    let lateral_ip_entity = entity_ref(16, EntityType::Ip, story.metadata.lateral_ip.clone())?;

    let mut flows = vec![
        flow_record(
            ids.flow_beacon.clone(),
            &story.metadata.local_ip,
            49152,
            &story.metadata.c2_ip,
            443,
            1024,
            8320,
            14,
            22,
            process_context_id.clone(),
            process_entity.clone(),
            trace_id.clone(),
            1,
        )?,
        flow_record(
            ids.flow_tls.clone(),
            &story.metadata.local_ip,
            49154,
            &story.metadata.c2_ip,
            443,
            768,
            6400,
            10,
            18,
            process_context_id.clone(),
            process_entity.clone(),
            trace_id.clone(),
            2,
        )?,
        flow_record(
            ids.flow_upload.clone(),
            &story.metadata.local_ip,
            49156,
            &story.metadata.exfil_ip,
            443,
            2048,
            98240,
            18,
            134,
            process_context_id.clone(),
            process_entity.clone(),
            trace_id.clone(),
            3,
        )?,
        flow_record(
            ids.flow_lateral.clone(),
            &story.metadata.local_ip,
            49158,
            &story.metadata.lateral_ip,
            445,
            512,
            4608,
            8,
            16,
            process_context_id.clone(),
            process_entity.clone(),
            trace_id.clone(),
            4,
        )?,
    ];
    flows[0].end_time = Some(story_time(2)?);
    flows[1].end_time = Some(story_time(3)?);
    flows[2].end_time = Some(story_time(4)?);
    flows[3].end_time = Some(story_time(5)?);

    let dns = vec![
        dns_observation(
            ids.dns_c2.clone(),
            &story.metadata.c2_domain_protected,
            &story.metadata.c2_ip,
            &story.metadata.resolver_ip,
            &story.metadata.local_ip,
            ids.flow_beacon.clone(),
            process_context_id.clone(),
            process_entity.clone(),
        )?,
        dns_observation(
            ids.dns_exfil.clone(),
            &story.metadata.exfil_domain_protected,
            &story.metadata.exfil_ip,
            &story.metadata.resolver_ip,
            &story.metadata.local_ip,
            ids.flow_upload.clone(),
            process_context_id.clone(),
            process_entity.clone(),
        )?,
    ];

    let mut tls = TlsObservation::new();
    tls.tls_observation_id = ids.tls_c2.clone();
    tls.flow_ref = Some(ids.flow_tls.clone());
    tls.timestamp = story_time(2)?;
    tls.sni_protected = Some(story.metadata.c2_domain_protected.clone());
    tls.alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    tls.ja4 = Some("DEMO_ONLY:ja4:metadata-fingerprint".to_string());
    tls.tls_version = Some("TLS 1.3".to_string());
    tls.cipher_suite = Some("TLS_AES_128_GCM_SHA256".to_string());
    tls.certificate_fingerprint = Some("DEMO_ONLY:cert:fingerprint".to_string());
    tls.src_entity = Some(process_entity.clone());
    tls.dst_entity = Some(c2_domain_entity.clone());
    tls.process_ref = Some(process_context_id.clone());
    tls.quality_score = quality(0.94)?;

    let evidence_items = evidence_items(
        &ids,
        &producer_plugin,
        &process_entity,
        &c2_domain_entity,
        &c2_ip_entity,
        &exfil_domain_entity,
        &exfil_ip_entity,
        &lateral_ip_entity,
    )?;

    let c2_mapping = AttackMapping::mitre_attack_enterprise(
        "TA0011",
        "Command and Control",
        "T1071.001",
        "Web Protocols",
        quality(0.86)?,
        Some(MappingProvenance::new("DEMO_ONLY fixture mapping").map_err(contract_error)?),
    )
    .map_err(contract_error)?;
    let exfil_mapping = AttackMapping::mitre_attack_enterprise(
        "TA0010",
        "Exfiltration",
        "T1041",
        "Exfiltration Over C2 Channel",
        quality(0.82)?,
        Some(MappingProvenance::new("DEMO_ONLY fixture mapping").map_err(contract_error)?),
    )
    .map_err(contract_error)?;
    let lateral_mapping = AttackMapping::mitre_attack_enterprise(
        "TA0008",
        "Lateral Movement",
        "T1021.002",
        "SMB/Windows Admin Shares",
        quality(0.74)?,
        Some(MappingProvenance::new("DEMO_ONLY fixture mapping").map_err(contract_error)?),
    )
    .map_err(contract_error)?;

    let c2_reason = risk_reason(
        "demo_c2_cadence",
        "DEMO_ONLY repeated outbound metadata cadence to .test control domain",
        vec![ids.evidence_beacon.clone(), ids.evidence_dns.clone()],
        vec![c2_mapping.clone()],
        0.88,
    )?;
    let exfil_reason = risk_reason(
        "demo_upload_anomaly",
        "DEMO_ONLY outbound upload metadata exceeds the local fixture baseline",
        vec![ids.evidence_upload.clone()],
        vec![exfil_mapping.clone()],
        0.81,
    )?;
    let lateral_reason = risk_reason(
        "demo_lateral_probe",
        "DEMO_ONLY local host metadata shows a bounded SMB probe to a documentation IP",
        vec![ids.evidence_lateral.clone()],
        vec![lateral_mapping.clone()],
        0.69,
    )?;

    let finding_c2 = finding(
        80,
        "DEMO_ONLY:c2_beacon_metadata",
        producer_plugin.clone(),
        vec![
            ids.evidence_beacon.clone(),
            ids.evidence_dns.clone(),
            ids.evidence_tls.clone(),
        ],
        "DEMO_ONLY C2-like metadata cadence without content inspection",
        vec![
            process_entity.clone(),
            c2_domain_entity.clone(),
            c2_ip_entity.clone(),
        ],
        vec![c2_reason.clone()],
        vec![c2_mapping],
        SecuritySeverity::High,
        0.9,
        trace_id.clone(),
        correlation_id.clone(),
        4,
    )?;
    let finding_exfil = finding(
        81,
        "DEMO_ONLY:exfil_upload_metadata",
        producer_plugin.clone(),
        vec![ids.evidence_upload.clone()],
        "DEMO_ONLY upload anomaly derived from flow counters only",
        vec![
            process_entity.clone(),
            exfil_domain_entity.clone(),
            exfil_ip_entity.clone(),
        ],
        vec![exfil_reason.clone()],
        vec![exfil_mapping],
        SecuritySeverity::High,
        0.84,
        trace_id.clone(),
        correlation_id.clone(),
        5,
    )?;
    let finding_lateral = finding(
        82,
        "DEMO_ONLY:lateral_probe_metadata",
        producer_plugin.clone(),
        vec![ids.evidence_lateral.clone()],
        "DEMO_ONLY bounded lateral probe metadata",
        vec![process_entity.clone(), lateral_ip_entity.clone()],
        vec![lateral_reason.clone()],
        vec![lateral_mapping],
        SecuritySeverity::Medium,
        0.76,
        trace_id.clone(),
        correlation_id.clone(),
        5,
    )?;

    let evidence_bundles = vec![
        evidence_bundle(
            90,
            Some(finding_c2.id().clone()),
            vec![
                ids.evidence_beacon.clone(),
                ids.evidence_dns.clone(),
                ids.evidence_tls.clone(),
            ],
            "DEMO_ONLY C2 evidence bundle",
            SecuritySeverity::High,
            0.88,
        )?,
        evidence_bundle(
            91,
            Some(finding_exfil.id().clone()),
            vec![ids.evidence_upload.clone()],
            "DEMO_ONLY exfiltration evidence bundle",
            SecuritySeverity::High,
            0.81,
        )?,
        evidence_bundle(
            92,
            Some(finding_lateral.id().clone()),
            vec![ids.evidence_lateral.clone()],
            "DEMO_ONLY lateral probe evidence bundle",
            SecuritySeverity::Medium,
            0.7,
        )?,
    ];

    let risk_hints = vec![
        risk_hint(
            70,
            "demo_c2_control_context",
            "DEMO_ONLY local intelligence context for reserved C2 domain",
            &c2_domain_entity,
            0.12,
            0.82,
        )?,
        risk_hint(
            71,
            "demo_exfil_context",
            "DEMO_ONLY upload destination context for reserved archive domain",
            &exfil_domain_entity,
            0.1,
            0.78,
        )?,
        risk_hint(
            72,
            "demo_lateral_context",
            "DEMO_ONLY internal probe context for documentation address",
            &lateral_ip_entity,
            0.06,
            0.7,
        )?,
    ];

    let risk_runtime_output = risk_alert_incident_from_static_runtime(
        producer_plugin.clone(),
        &process_context,
        &evidence_items,
        &[
            finding_c2.clone(),
            finding_exfil.clone(),
            finding_lateral.clone(),
        ],
        &risk_hints,
        &trace_id,
        &correlation_id,
    )?;
    let risk_events = risk_runtime_output.risk_events;
    let alerts = risk_runtime_output.alerts;
    let alert_c2 = alerts
        .first()
        .cloned()
        .ok_or_else(|| story_error("risk_runtime", "runtime alert output is missing", json!({})))?;
    let alert_exfil = alerts.get(1).cloned().ok_or_else(|| {
        story_error(
            "risk_runtime",
            "runtime did not produce the second demo alert",
            json!({ "alert_count": alerts.len() }),
        )
    })?;
    let mut incident = risk_runtime_output.incident;

    let graph_views = vec![
        graph_view(
            120,
            GraphScope::Overview,
            "DEMO_ONLY overview attack path",
            &ids,
            &host_entity,
            &process_entity,
            &c2_domain_entity,
            &c2_ip_entity,
            &exfil_domain_entity,
            &exfil_ip_entity,
            &lateral_ip_entity,
            &finding_c2,
            &finding_exfil,
            &finding_lateral,
            &alert_c2,
            &alert_exfil,
            &incident,
        )?,
        graph_view(
            121,
            GraphScope::Incident(incident.id().clone()),
            "DEMO_ONLY incident attack path",
            &ids,
            &host_entity,
            &process_entity,
            &c2_domain_entity,
            &c2_ip_entity,
            &exfil_domain_entity,
            &exfil_ip_entity,
            &lateral_ip_entity,
            &finding_c2,
            &finding_exfil,
            &finding_lateral,
            &alert_c2,
            &alert_exfil,
            &incident,
        )?,
    ];
    let primary_graph = graph_views.first().ok_or_else(|| {
        story_error(
            "fixture_graph",
            "fixture graph view was not generated",
            json!({}),
        )
    })?;
    let canonical_graph_nodes = canonical_graph_nodes_from_view(primary_graph)?;
    let canonical_graph_edges =
        canonical_graph_edges_from_view(primary_graph, producer_plugin.clone())?;
    let graph_paths = graph_paths(&ids)?;
    incident = attach_graph_path_to_runtime_incident(incident, ids.graph_path.clone())?;

    let response_plan = response_plan_from_fixture_capability(
        140,
        incident.id().clone(),
        producer_plugin.clone(),
        &[
            finding_c2.clone(),
            finding_exfil.clone(),
            finding_lateral.clone(),
        ],
        &alerts,
        &incident,
        &graph_paths,
        &trace_id,
    )?;
    let response_results = response_results_for_report(&response_plan, &trace_id)?;
    let report = report(
        160,
        ReportBuildContext {
            ids: &ids,
            incident: &incident,
            alerts: &[alert_c2.clone(), alert_exfil.clone()],
            findings: &[
                finding_c2.clone(),
                finding_exfil.clone(),
                finding_lateral.clone(),
            ],
            response_plan: &response_plan,
            response_results: &response_results,
            trace_id: &trace_id,
        },
    )?;
    let mut export_history = ExportHistoryStore::new();
    export_history
        .append(export_history_record(180, &report, &trace_id)?)
        .map_err(export_history_error)?;

    Ok(DemoStoryReadModel {
        story_id: story.story_id.clone(),
        fixture_mode: story.fixture_mode.clone(),
        process_contexts: vec![process_context],
        flows,
        dns,
        tls: vec![tls],
        evidence_items,
        evidence_bundles,
        findings: vec![finding_c2, finding_exfil, finding_lateral],
        risk_events,
        alerts,
        incidents: vec![incident],
        canonical_graph_nodes,
        canonical_graph_edges,
        graph_paths,
        graph_views,
        response_plans: vec![response_plan],
        reports: vec![report],
        export_history,
    })
}

fn build_result(
    story: &FixtureAttackStory,
    read_model: &DemoStoryReadModel,
) -> CommandResult<DemoStoryResult> {
    let primary_graph = read_model
        .graph_views
        .first()
        .ok_or_else(|| story_error("fixture_result", "fixture graph view is missing", json!({})))?;
    let incident = read_model
        .incidents
        .first()
        .ok_or_else(|| story_error("fixture_result", "fixture incident is missing", json!({})))?;
    let report = read_model
        .reports
        .first()
        .ok_or_else(|| story_error("fixture_result", "fixture report is missing", json!({})))?;
    let plan = read_model.response_plans.first().ok_or_else(|| {
        story_error(
            "fixture_result",
            "fixture response plan is missing",
            json!({}),
        )
    })?;
    let export = read_model.export_history.records().first().ok_or_else(|| {
        story_error(
            "fixture_result",
            "fixture export history is missing",
            json!({}),
        )
    })?;
    let redaction_summary = report.redaction_summary.clone();
    let recommended_action_count = read_model
        .response_plans
        .iter()
        .map(|plan| plan.recommended_actions.len() as u32)
        .sum();
    let policy_decision_count = read_model
        .response_plans
        .iter()
        .map(|plan| plan.policy_decisions.len() as u32)
        .sum();

    Ok(DemoStoryResult {
        story_id: story.story_id.clone(),
        fixture_mode: story.fixture_mode.clone(),
        title_redacted: story.title_redacted.clone(),
        replay_only: true,
        execution_disabled: true,
        started_at: story_time(0)?,
        completed_at: story_time(12)?,
        stage_count: StoryStage::ordered().len() as u32,
        stages: stage_results(story, read_model)?,
        flow_count: read_model.flows.len() as u32,
        dns_observation_count: read_model.dns.len() as u32,
        tls_observation_count: read_model.tls.len() as u32,
        evidence_item_count: read_model.evidence_items.len() as u32,
        finding_count: read_model.findings.len() as u32,
        risk_event_count: read_model.risk_events.len() as u32,
        alert_count: read_model.alerts.len() as u32,
        incident_count: read_model.incidents.len() as u32,
        graph_view_count: read_model.graph_views.len() as u32,
        graph_node_count: primary_graph.nodes.len() as u32,
        graph_edge_count: primary_graph.edges.len() as u32,
        graph_path_count: primary_graph.paths.len() as u32,
        response_plan_count: read_model.response_plans.len() as u32,
        recommended_action_count,
        policy_decision_count,
        report_count: read_model.reports.len() as u32,
        report_section_count: report.sections.len() as u32,
        export_history_count: read_model.export_history.records().len() as u32,
        incident_id: incident.id().to_string(),
        report_id: report.report_id.to_string(),
        export_result_id: export.export_result_id.to_string(),
        graph_view_id: primary_graph.graph_id.to_string(),
        response_plan_id: plan.plan_id.to_string(),
        redaction_summary,
    })
}

fn stage_results(
    story: &FixtureAttackStory,
    read_model: &DemoStoryReadModel,
) -> CommandResult<Vec<StoryStageResult>> {
    let definitions = StoryStage::ordered()
        .into_iter()
        .map(|stage| {
            story
                .stages
                .iter()
                .find(|definition| definition.stage == stage)
                .cloned()
                .ok_or_else(|| {
                    story_error(
                        "fixture_stage",
                        "fixture stage definition is missing",
                        json!({ "stage": format!("{stage:?}") }),
                    )
                })
        })
        .collect::<CommandResult<Vec<_>>>()?;

    let counts = [
        (
            3,
            read_model.flows.len() + read_model.dns.len() + read_model.tls.len(),
            0,
        ),
        (
            read_model.flows.len(),
            read_model.flows.len() + read_model.dns.len() + read_model.tls.len(),
            0,
        ),
        (
            read_model.flows.len() + read_model.dns.len(),
            read_model.process_contexts.len() + 2,
            0,
        ),
        (
            read_model.evidence_items.len(),
            read_model.findings.len() + read_model.evidence_bundles.len(),
            read_model.evidence_items.len(),
        ),
        (
            read_model.findings.len(),
            read_model.risk_events.len() + read_model.alerts.len() + read_model.incidents.len(),
            read_model.evidence_items.len(),
        ),
        (
            read_model.incidents.len(),
            read_model
                .graph_views
                .first()
                .map_or(0, |view| view.nodes.len() + view.edges.len()),
            read_model.evidence_items.len(),
        ),
        (
            read_model.incidents.len(),
            read_model
                .response_plans
                .iter()
                .map(|plan| plan.recommended_actions.len() + plan.policy_decisions.len())
                .sum(),
            read_model.evidence_items.len(),
        ),
        (
            read_model.reports.len(),
            read_model
                .reports
                .iter()
                .map(|report| report.sections.len())
                .sum::<usize>()
                + read_model.export_history.records().len(),
            read_model.evidence_items.len(),
        ),
    ];

    definitions
        .into_iter()
        .zip(counts)
        .enumerate()
        .map(
            |(index, (definition, (input, produced, evidence)))| -> CommandResult<_> {
                let started_at = story_time(index as i64)?;
                let completed_at = story_time(index as i64 + 1)?;
                Ok(StoryStageResult {
                    stage: definition.stage,
                    summary_redacted: definition.summary_redacted,
                    started_at,
                    completed_at,
                    duration_millis: 60_000,
                    input_artifact_count: input as u32,
                    produced_artifact_count: produced as u32,
                    evidence_ref_count: evidence as u32,
                    replay_only: true,
                    safe_replay_note_redacted:
                        "DEMO_ONLY replay; no capture, payload persistence, or response execution"
                            .to_string(),
                })
            },
        )
        .collect::<CommandResult<Vec<_>>>()
}

fn process_context(
    process_context_id: ProcessContextId,
    story: &FixtureAttackStory,
) -> CommandResult<ProcessContext> {
    let mut context = ProcessContext::new(5400, story.metadata.process_name_redacted.clone());
    context.process_context_id = process_context_id;
    context.process_start_time = story_time(0)?;
    context.captured_at = story_time(2)?;
    context.process_path_protected = Some(format!(
        "DEMO_ONLY {}",
        story.metadata.process_path_redacted
    ));
    context.known_limitations = vec![
        "DEMO_ONLY process attribution is fixture metadata; no ETW or process scan was performed"
            .to_string(),
    ];
    Ok(context)
}

#[allow(clippy::too_many_arguments)]
fn flow_record(
    flow_id: sentinel_contracts::FlowId,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    bytes_in: u64,
    bytes_out: u64,
    packets_in: u64,
    packets_out: u64,
    process_ref: ProcessContextId,
    asset_ref: EntityRef,
    trace_id: TraceId,
    time_slot: i64,
) -> CommandResult<FlowRecord> {
    let mut flow = FlowRecord::new(
        parse_ip(src_ip)?,
        src_port,
        parse_ip(dst_ip)?,
        dst_port,
        TransportProtocol::Tcp,
        NetworkDirection::Outbound,
    );
    flow.flow_id = flow_id;
    flow.start_time = story_time(time_slot)?;
    flow.duration_millis = Some(30_000);
    flow.bytes_in = bytes_in;
    flow.bytes_out = bytes_out;
    flow.packets_in = packets_in;
    flow.packets_out = packets_out;
    flow.process_ref = Some(process_ref);
    flow.asset_ref = Some(asset_ref);
    flow.quality_score = quality(0.95)?;
    flow.trace_id = Some(trace_id);
    Ok(flow)
}

#[allow(clippy::too_many_arguments)]
fn dns_observation(
    dns_id: sentinel_contracts::DnsObservationId,
    query_name: &str,
    answer_ip: &str,
    resolver_ip: &str,
    client_ip: &str,
    flow_ref: sentinel_contracts::FlowId,
    process_ref: ProcessContextId,
    asset_ref: EntityRef,
) -> CommandResult<DnsObservation> {
    let mut dns = DnsObservation::new(
        query_name,
        "A",
        parse_ip(resolver_ip)?,
        parse_ip(client_ip)?,
    )
    .map_err(contract_error)?;
    dns.dns_observation_id = dns_id;
    dns.flow_ref = Some(flow_ref);
    dns.response_code = Some("NOERROR".to_string());
    dns.answers.push(DnsAnswer::Ip {
        address: parse_ip(answer_ip)?,
        ttl_seconds: Some(300),
    });
    dns.features = DnsFeatures {
        query_length: query_name.len() as u16,
        label_count: query_name.split('.').count() as u16,
        subdomain_depth: 2,
        character_entropy: Some(3.6),
        answer_count: 1,
    };
    dns.process_ref = Some(process_ref);
    dns.asset_ref = Some(asset_ref);
    dns.quality_score = quality(0.96)?;
    Ok(dns)
}

#[allow(clippy::too_many_arguments)]
fn evidence_items(
    ids: &StoryIds,
    producer_plugin: &PluginId,
    process_entity: &EntityRef,
    c2_domain_entity: &EntityRef,
    c2_ip_entity: &EntityRef,
    exfil_domain_entity: &EntityRef,
    exfil_ip_entity: &EntityRef,
    lateral_ip_entity: &EntityRef,
) -> CommandResult<Vec<EvidenceItem>> {
    Ok(vec![
        evidence_item(
            ids.evidence_beacon.clone(),
            "demo_flow_cadence",
            "DEMO_ONLY outbound flow cadence to documentation C2 address",
            vec![process_entity.clone(), c2_ip_entity.clone()],
            producer_plugin.clone(),
            3,
            0.88,
        )?,
        evidence_item(
            ids.evidence_dns.clone(),
            "demo_dns_resolution",
            "DEMO_ONLY .test control domain resolved to RFC 5737 address",
            vec![c2_domain_entity.clone(), c2_ip_entity.clone()],
            producer_plugin.clone(),
            3,
            0.84,
        )?,
        evidence_item(
            ids.evidence_tls.clone(),
            "demo_tls_fingerprint",
            "DEMO_ONLY TLS metadata fingerprint observed without content inspection",
            vec![process_entity.clone(), c2_domain_entity.clone()],
            producer_plugin.clone(),
            4,
            0.78,
        )?,
        evidence_item(
            ids.evidence_upload.clone(),
            "demo_upload_ratio",
            "DEMO_ONLY upload-heavy flow counters to .test archive destination",
            vec![
                process_entity.clone(),
                exfil_domain_entity.clone(),
                exfil_ip_entity.clone(),
            ],
            producer_plugin.clone(),
            5,
            0.82,
        )?,
        evidence_item(
            ids.evidence_lateral.clone(),
            "demo_lateral_probe",
            "DEMO_ONLY bounded SMB probe metadata to documentation address",
            vec![process_entity.clone(), lateral_ip_entity.clone()],
            producer_plugin.clone(),
            5,
            0.7,
        )?,
    ])
}

fn evidence_item(
    evidence_id: EvidenceId,
    evidence_type: &str,
    summary: &str,
    entity_refs: Vec<EntityRef>,
    producer_plugin: PluginId,
    time_slot: i64,
    score: f32,
) -> CommandResult<EvidenceItem> {
    let mut item = EvidenceItem::new(evidence_type, summary).map_err(contract_error)?;
    item.evidence_id = evidence_id;
    item.source_plugin = Some(producer_plugin);
    item.entity_refs = entity_refs;
    item.timestamp = story_time(time_slot)?;
    item.weight = quality(score)?;
    item.confidence = quality(score)?;
    item.privacy_class = PrivacyClass::Internal;
    item.description_redacted = Some("DEMO_ONLY metadata evidence; raw content absent".to_string());
    Ok(item)
}

fn risk_reason(
    reason_type: &str,
    summary: &str,
    evidence_refs: Vec<EvidenceId>,
    attack_mappings: Vec<AttackMapping>,
    confidence: f32,
) -> CommandResult<RiskReason> {
    let mut reason = RiskReason::new(reason_type, summary).map_err(contract_error)?;
    reason.evidence_refs = evidence_refs;
    reason.attack_mappings = attack_mappings;
    reason.confidence = quality(confidence)?;
    Ok(reason)
}

fn risk_hint(
    id_slot: u16,
    hint_type: &str,
    summary: &str,
    entity_ref: &EntityRef,
    risk_delta: f32,
    confidence: f32,
) -> CommandResult<RiskHint> {
    let source_record: IntelligenceRecordId = fixed_id(id_slot, "intelligence_record_id")?;
    let mut hint = RiskHint::new(hint_type, summary, vec![source_record])
        .map_err(contract_error)?
        .with_risk_delta(risk_delta)
        .with_confidence(quality(confidence)?);
    hint.risk_hint_id = fixed_id(id_slot + 10, "risk_hint_id")?;
    hint.entity_ref = Some(entity_ref.clone());
    hint.timestamp = story_time(5)?;
    Ok(hint)
}

#[derive(Clone, Debug, PartialEq)]
struct RiskAlertIncidentRuntimeOutput {
    risk_events: Vec<RiskEvent>,
    alerts: Vec<Alert>,
    incident: Incident,
}

fn risk_alert_incident_from_static_runtime(
    producer_plugin: PluginId,
    _process_context: &ProcessContext,
    _evidence_items: &[EvidenceItem],
    findings: &[Finding],
    risk_hints: &[RiskHint],
    trace_id: &TraceId,
    correlation_id: &CorrelationId,
) -> CommandResult<RiskAlertIncidentRuntimeOutput> {
    let mut input = RiskBasedAlertingInput::new(producer_plugin);
    input.findings = findings.to_vec();
    input.risk_hints = risk_hints.to_vec();
    input.labels = vec!["DEMO_ONLY pure risk fixture".to_string()];
    let output = RiskBasedAlertingPlugin::new()
        .process(input)
        .map_err(|error| risk_runtime_error(error, trace_id))?;
    let mut risk_events = output.risk_events;
    let alerts = output.alerts;
    let incidents = output.incidents;
    let alert_candidate_count = output.alert_candidates.len();
    let incident_candidate_count = output.incident_candidates.len();

    if risk_events.is_empty() || alerts.len() < 2 || incidents.is_empty() {
        return Err(risk_runtime_error(
            format!(
                "risk alerting runtime output was incomplete: risk_events={} alerts={} incidents={}",
                risk_events.len(),
                alerts.len(),
                incidents.len()
            ),
            trace_id,
        ));
    }
    if alert_candidate_count == 0 || incident_candidate_count == 0 {
        return Err(risk_runtime_error(
            "risk alerting runtime did not emit candidate events",
            trace_id,
        ));
    }

    normalize_runtime_risk_events(&mut risk_events)?;
    let selected_incident = select_primary_runtime_incident(&incidents, &alerts, trace_id)?;
    let mut selected_alerts = select_alerts_for_incident(&alerts, &selected_incident, trace_id)?;
    normalize_runtime_alerts(&mut selected_alerts, &risk_events, trace_id, correlation_id)?;
    let incident = normalize_runtime_incident(
        selected_incident,
        &selected_alerts,
        trace_id,
        correlation_id,
    )?;

    Ok(RiskAlertIncidentRuntimeOutput {
        risk_events,
        alerts: selected_alerts,
        incident,
    })
}

fn normalize_runtime_risk_events(risk_events: &mut [RiskEvent]) -> CommandResult<()> {
    risk_events.sort_by(|left, right| {
        right
            .risk_score
            .value()
            .partial_cmp(&left.risk_score.value())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                left.entity_ref
                    .entity_id
                    .to_string()
                    .cmp(&right.entity_ref.entity_id.to_string())
            })
    });
    for (index, risk_event) in risk_events.iter_mut().enumerate() {
        risk_event.risk_event_id = fixed_id(50 + index as u16, "risk_event_id")?;
        risk_event.created_at = story_time(6 + index.min(2) as i64)?;
        risk_event.decay_policy = Some(RISK_RUNTIME_PROVENANCE.to_string());
    }
    Ok(())
}

fn select_primary_runtime_incident(
    incidents: &[Incident],
    alerts: &[Alert],
    trace_id: &TraceId,
) -> CommandResult<Incident> {
    let alert_ids = alerts
        .iter()
        .map(|alert| alert.id().clone())
        .collect::<Vec<_>>();
    incidents
        .iter()
        .filter(|incident| {
            incident
                .alert_refs()
                .iter()
                .any(|alert_id| alert_ids.contains(alert_id))
        })
        .max_by(|left, right| {
            left.finding_refs()
                .len()
                .cmp(&right.finding_refs().len())
                .then_with(|| left.alert_refs().len().cmp(&right.alert_refs().len()))
                .then_with(|| {
                    left.confidence()
                        .value()
                        .partial_cmp(&right.confidence().value())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        })
        .cloned()
        .ok_or_else(|| {
            risk_runtime_error("risk alerting runtime incident was not usable", trace_id)
        })
}

fn select_alerts_for_incident(
    alerts: &[Alert],
    incident: &Incident,
    trace_id: &TraceId,
) -> CommandResult<Vec<Alert>> {
    let mut selected = alerts
        .iter()
        .filter(|alert| incident.alert_refs().contains(alert.id()))
        .cloned()
        .collect::<Vec<_>>();
    if selected.len() < 2 {
        selected = alerts.to_vec();
    }
    selected.sort_by(|left, right| {
        right
            .finding_refs()
            .len()
            .cmp(&left.finding_refs().len())
            .then_with(|| {
                right
                    .confidence()
                    .value()
                    .partial_cmp(&left.confidence().value())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| left.title_redacted().cmp(right.title_redacted()))
    });
    selected.truncate(2);
    if selected.len() < 2 {
        return Err(risk_runtime_error(
            "risk alerting runtime produced fewer than two demo alerts",
            trace_id,
        ));
    }
    Ok(selected)
}

fn normalize_runtime_alerts(
    alerts: &mut [Alert],
    risk_events: &[RiskEvent],
    trace_id: &TraceId,
    correlation_id: &CorrelationId,
) -> CommandResult<()> {
    let risk_event_refs = risk_events
        .iter()
        .map(|risk_event| risk_event.risk_event_id.clone())
        .collect::<Vec<_>>();
    for (index, alert) in alerts.iter_mut().enumerate() {
        let normalized = alert
            .clone()
            .with_risk_event_refs(
                alert
                    .risk_event_refs()
                    .iter()
                    .filter_map(|risk_ref| {
                        risk_events
                            .iter()
                            .find(|risk| {
                                risk.contributing_findings
                                    .iter()
                                    .any(|finding_id| alert.finding_refs().contains(finding_id))
                            })
                            .map(|risk| risk.risk_event_id.clone())
                            .or_else(|| {
                                if risk_event_refs.contains(risk_ref) {
                                    Some(risk_ref.clone())
                                } else {
                                    None
                                }
                            })
                    })
                    .collect(),
            )
            .with_trace_id(trace_id.clone())
            .with_correlation_id(correlation_id.clone())
            .with_state(AlertState::EscalatedToIncident);
        *alert = rewrite_contract_fields(
            normalized,
            vec![
                ("alert_id", Value::String(fixed_uuid(100 + index as u16))),
                ("created_at", to_value(story_time(8)?)?),
                ("updated_at", to_value(story_time(9)?)?),
            ],
        )?;
    }
    Ok(())
}

fn normalize_runtime_incident(
    incident: Incident,
    alerts: &[Alert],
    trace_id: &TraceId,
    correlation_id: &CorrelationId,
) -> CommandResult<Incident> {
    let alert_refs = alerts
        .iter()
        .map(|alert| alert.id().clone())
        .collect::<Vec<_>>();
    let mut finding_refs = Vec::new();
    for alert in alerts {
        for finding_ref in alert.finding_refs() {
            if !finding_refs.contains(finding_ref) {
                finding_refs.push(finding_ref.clone());
            }
        }
    }
    let normalized = incident
        .with_finding_refs(finding_refs.clone())
        .with_trace_id(trace_id.clone())
        .with_correlation_id(correlation_id.clone())
        .with_root_cause_hint_redacted(
            "DEMO_ONLY risk runtime linked evidence-backed alerts into the local metadata story",
        )
        .with_recommended_response_summary_redacted(
            "Review response planning recommendations; no action was executed.",
        )
        .with_state(IncidentState::Triaged);
    rewrite_contract_fields(
        normalized,
        vec![
            ("incident_id", Value::String(fixed_uuid(110))),
            ("alert_refs", to_value(alert_refs)?),
            ("finding_refs", to_value(finding_refs)?),
            ("created_at", to_value(story_time(8)?)?),
            ("updated_at", to_value(story_time(9)?)?),
        ],
    )
}

fn attach_graph_path_to_runtime_incident(
    incident: Incident,
    graph_path_id: GraphPathId,
) -> CommandResult<Incident> {
    rewrite_contract_fields(
        incident.with_graph_path_refs(vec![graph_path_id.clone()]),
        vec![("graph_path_refs", to_value(vec![graph_path_id])?)],
    )
}

fn risk_runtime_error(error: impl Display, trace_id: &TraceId) -> CoreError {
    CoreError::new(
        ErrorCode::ValidationFailure,
        "fixture story risk alerting runtime failed",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(trace_id.clone())
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

#[allow(clippy::too_many_arguments)]
fn finding(
    id_slot: u16,
    finding_type: &str,
    producer_plugin: PluginId,
    evidence_refs: Vec<EvidenceId>,
    summary: &str,
    entity_refs: Vec<EntityRef>,
    risk_reasons: Vec<RiskReason>,
    attack_mappings: Vec<AttackMapping>,
    severity: SecuritySeverity,
    confidence: f32,
    trace_id: TraceId,
    correlation_id: CorrelationId,
    time_slot: i64,
) -> CommandResult<Finding> {
    let mut explanation = FindingExplanation::new(summary).map_err(contract_error)?;
    explanation.risk_reasons = risk_reasons.clone();
    explanation
        .limitations_redacted
        .push("DEMO_ONLY replay; no private content or packet capture is available".to_string());
    let finding = Finding::new(finding_type, producer_plugin, evidence_refs, explanation)
        .map_err(contract_error)?
        .with_entity_refs(entity_refs)
        .with_confidence(quality(confidence)?)
        .with_severity(severity)
        .with_risk_reasons(risk_reasons)
        .with_attack_mappings(attack_mappings)
        .with_trace_id(trace_id)
        .with_correlation_id(correlation_id)
        .with_state(FindingState::Promoted);
    rewrite_contract_fields(
        finding,
        vec![
            ("finding_id", Value::String(fixed_uuid(id_slot))),
            ("created_at", to_value(story_time(time_slot)?)?),
            ("updated_at", to_value(story_time(time_slot + 1)?)?),
        ],
    )
}

fn evidence_bundle(
    id_slot: u16,
    finding_id: Option<FindingId>,
    evidence_refs: Vec<EvidenceId>,
    summary: &str,
    severity: SecuritySeverity,
    confidence: f32,
) -> CommandResult<EvidenceBundle> {
    let mut bundle = EvidenceBundle::new(
        evidence_refs,
        FindingExplanation::new(summary).map_err(contract_error)?,
    )
    .map_err(contract_error)?;
    bundle.bundle_id = fixed_id(id_slot, "evidence_bundle_id")?;
    bundle.finding_id = finding_id;
    bundle.total_weight = quality(confidence)?;
    bundle.confidence = quality(confidence)?;
    bundle.severity = severity;
    Ok(bundle)
}

#[allow(clippy::too_many_arguments)]
fn graph_view(
    view_slot: u16,
    scope: GraphScope,
    title: &str,
    ids: &StoryIds,
    host: &EntityRef,
    process: &EntityRef,
    c2_domain: &EntityRef,
    c2_ip: &EntityRef,
    exfil_domain: &EntityRef,
    exfil_ip: &EntityRef,
    lateral_ip: &EntityRef,
    finding_c2: &Finding,
    finding_exfil: &Finding,
    finding_lateral: &Finding,
    alert_c2: &Alert,
    alert_exfil: &Alert,
    incident: &Incident,
) -> CommandResult<GraphViewModel> {
    let mut nodes = vec![
        graph_node(
            ids.node_host.clone(),
            GraphNodeType::LocalHost,
            "DEMO_ONLY host 192.0.2.10",
            GraphNodeStatus::Normal,
            Some(host),
            None,
            0.2,
            -520.0,
            -40.0,
        )?,
        graph_node(
            ids.node_process.clone(),
            GraphNodeType::Process,
            "DEMO_ONLY sg-demo-agent.exe",
            GraphNodeStatus::Risky,
            Some(process),
            None,
            0.74,
            -320.0,
            -40.0,
        )?,
        graph_node(
            ids.node_c2_domain.clone(),
            GraphNodeType::Domain,
            "beacon-control.example.test",
            GraphNodeStatus::Suspicious,
            Some(c2_domain),
            None,
            0.76,
            -100.0,
            -130.0,
        )?,
        graph_node(
            ids.node_c2_ip.clone(),
            GraphNodeType::Ip,
            "198.51.100.42",
            GraphNodeStatus::Suspicious,
            Some(c2_ip),
            None,
            0.8,
            120.0,
            -130.0,
        )?,
        graph_node(
            ids.node_exfil_domain.clone(),
            GraphNodeType::Domain,
            "archive-upload.example.test",
            GraphNodeStatus::Risky,
            Some(exfil_domain),
            None,
            0.78,
            -100.0,
            60.0,
        )?,
        graph_node(
            ids.node_exfil_ip.clone(),
            GraphNodeType::CloudDestination,
            "203.0.113.77",
            GraphNodeStatus::Risky,
            Some(exfil_ip),
            None,
            0.82,
            120.0,
            60.0,
        )?,
        graph_node(
            ids.node_lateral_ip.clone(),
            GraphNodeType::Ip,
            "192.0.2.55",
            GraphNodeStatus::Suspicious,
            Some(lateral_ip),
            None,
            0.62,
            -100.0,
            210.0,
        )?,
        graph_case_node(
            ids.node_finding_c2.clone(),
            GraphNodeType::Finding,
            "DEMO_ONLY C2 finding",
            GraphNodeStatus::Critical,
            Some(finding_c2.id().clone()),
            None,
            None,
            0.9,
            360.0,
            -120.0,
        )?,
        graph_case_node(
            ids.node_finding_exfil.clone(),
            GraphNodeType::Finding,
            "DEMO_ONLY exfil finding",
            GraphNodeStatus::Risky,
            Some(finding_exfil.id().clone()),
            None,
            None,
            0.84,
            360.0,
            30.0,
        )?,
        graph_case_node(
            ids.node_finding_lateral.clone(),
            GraphNodeType::Finding,
            "DEMO_ONLY lateral finding",
            GraphNodeStatus::Risky,
            Some(finding_lateral.id().clone()),
            None,
            None,
            0.76,
            360.0,
            190.0,
        )?,
        graph_case_node(
            ids.node_alert_c2.clone(),
            GraphNodeType::Alert,
            "DEMO_ONLY C2 alert",
            GraphNodeStatus::Critical,
            None,
            Some(alert_c2.id().clone()),
            None,
            0.86,
            590.0,
            -80.0,
        )?,
        graph_case_node(
            ids.node_alert_exfil.clone(),
            GraphNodeType::Alert,
            "DEMO_ONLY exfil alert",
            GraphNodeStatus::Risky,
            None,
            Some(alert_exfil.id().clone()),
            None,
            0.82,
            590.0,
            90.0,
        )?,
        graph_case_node(
            ids.node_incident.clone(),
            GraphNodeType::Incident,
            "DEMO_ONLY incident",
            GraphNodeStatus::Critical,
            None,
            None,
            Some(incident.id().clone()),
            0.86,
            840.0,
            0.0,
        )?,
    ];
    for node in &mut nodes {
        node.badges.push(GraphBadge {
            label: redacted_label("DEMO_ONLY")?,
            tone: GraphBadgeTone::Info,
        });
    }

    let mut edges = vec![
        graph_edge(
            ids.edge_host_process.clone(),
            GraphEdgeType::UserRunsProcess,
            ids.node_host.clone(),
            ids.node_process.clone(),
            "runs",
            Vec::new(),
            0.93,
        )?,
        graph_edge(
            ids.edge_process_c2_domain.clone(),
            GraphEdgeType::ProcessQueriesDomain,
            ids.node_process.clone(),
            ids.node_c2_domain.clone(),
            "queries",
            vec![ids.evidence_dns.clone()],
            0.84,
        )?,
        graph_edge(
            ids.edge_c2_domain_ip.clone(),
            GraphEdgeType::DomainResolvesToIp,
            ids.node_c2_domain.clone(),
            ids.node_c2_ip.clone(),
            "resolves",
            vec![ids.evidence_dns.clone()],
            0.84,
        )?,
        graph_edge(
            ids.edge_process_c2_ip.clone(),
            GraphEdgeType::ProcessConnectsToIp,
            ids.node_process.clone(),
            ids.node_c2_ip.clone(),
            "connects",
            vec![ids.evidence_beacon.clone(), ids.evidence_tls.clone()],
            0.88,
        )?,
        graph_edge(
            ids.edge_process_exfil_domain.clone(),
            GraphEdgeType::ProcessQueriesDomain,
            ids.node_process.clone(),
            ids.node_exfil_domain.clone(),
            "queries",
            vec![ids.evidence_upload.clone()],
            0.82,
        )?,
        graph_edge(
            ids.edge_exfil_domain_ip.clone(),
            GraphEdgeType::DomainResolvesToIp,
            ids.node_exfil_domain.clone(),
            ids.node_exfil_ip.clone(),
            "resolves",
            vec![ids.evidence_upload.clone()],
            0.82,
        )?,
        graph_edge(
            ids.edge_process_lateral_ip.clone(),
            GraphEdgeType::ProcessConnectsToIp,
            ids.node_process.clone(),
            ids.node_lateral_ip.clone(),
            "probes",
            vec![ids.evidence_lateral.clone()],
            0.7,
        )?,
        graph_edge(
            ids.edge_c2_finding.clone(),
            GraphEdgeType::ObservationSupportsFinding,
            ids.node_c2_ip.clone(),
            ids.node_finding_c2.clone(),
            "supports",
            vec![ids.evidence_beacon.clone(), ids.evidence_dns.clone()],
            0.9,
        )?,
        graph_edge(
            ids.edge_exfil_finding.clone(),
            GraphEdgeType::ObservationSupportsFinding,
            ids.node_exfil_ip.clone(),
            ids.node_finding_exfil.clone(),
            "supports",
            vec![ids.evidence_upload.clone()],
            0.84,
        )?,
        graph_edge(
            ids.edge_lateral_finding.clone(),
            GraphEdgeType::ObservationSupportsFinding,
            ids.node_lateral_ip.clone(),
            ids.node_finding_lateral.clone(),
            "supports",
            vec![ids.evidence_lateral.clone()],
            0.74,
        )?,
        graph_edge(
            ids.edge_finding_alert.clone(),
            GraphEdgeType::FindingSupportsAlert,
            ids.node_finding_c2.clone(),
            ids.node_alert_c2.clone(),
            "promotes",
            vec![ids.evidence_beacon.clone()],
            0.88,
        )?,
        graph_edge(
            ids.edge_exfil_alert.clone(),
            GraphEdgeType::FindingSupportsAlert,
            ids.node_finding_exfil.clone(),
            ids.node_alert_exfil.clone(),
            "promotes",
            vec![ids.evidence_upload.clone()],
            0.82,
        )?,
        graph_edge(
            ids.edge_alert_incident.clone(),
            GraphEdgeType::AlertPartOfIncident,
            ids.node_alert_c2.clone(),
            ids.node_incident.clone(),
            "joins",
            vec![ids.evidence_beacon.clone()],
            0.86,
        )?,
        graph_edge(
            ids.edge_exfil_incident.clone(),
            GraphEdgeType::AlertPartOfIncident,
            ids.node_alert_exfil.clone(),
            ids.node_incident.clone(),
            "joins",
            vec![ids.evidence_upload.clone()],
            0.82,
        )?,
    ];
    for edge in &mut edges {
        edge.style_hint = match &edge.edge_type {
            GraphEdgeType::FindingSupportsAlert | GraphEdgeType::AlertPartOfIncident => {
                GraphEdgeStyleHint::Strong
            }
            _ => edge.style_hint.clone(),
        };
    }

    let mut view = GraphViewModel::new(GraphType::IncidentGraph, redacted_label(title)?, scope);
    view.graph_id = fixed_id(view_slot, "graph_view_id")?;
    view.nodes = nodes;
    view.edges = edges;
    view.paths = vec![GraphPathSummary {
        path_id: ids.graph_path.clone(),
        path_type: GraphPathType::IncidentSummaryPath,
        label: redacted_label("DEMO_ONLY process to incident attack path")?,
        risk_score: quality(0.86)?,
        confidence: quality(0.84)?,
        evidence_refs: vec![
            ids.evidence_beacon.clone(),
            ids.evidence_upload.clone(),
            ids.evidence_lateral.clone(),
        ],
    }];
    view.legend = GraphLegend {
        node_items: vec![
            legend_item("process", "Process")?,
            legend_item("domain", "Domain")?,
            legend_item("finding", "Finding")?,
            legend_item("incident", "Incident")?,
        ],
        edge_items: vec![
            legend_item("metadata", "Metadata link")?,
            legend_item("promotion", "Promotion")?,
        ],
        risk_scale: vec![
            legend_item("medium", "Medium")?,
            legend_item("high", "High")?,
        ],
    };
    view.redaction_status = RedactionStatus::Redacted;
    view.redaction_summary = GraphRedactionSummary {
        status: RedactionStatus::Redacted,
        redacted_node_count: 0,
        redacted_edge_count: 0,
        hidden_label_count: 0,
        notes: vec!["DEMO_ONLY GraphViewModel contains no canonical graph internals".to_string()],
    };
    view.original_node_count = view.nodes.len() as u32;
    view.original_edge_count = view.edges.len() as u32;
    view.generated_at = story_time(9)?;
    Ok(view)
}

#[allow(clippy::too_many_arguments)]
fn graph_node(
    node_id: GraphNodeId,
    node_type: GraphNodeType,
    label: &str,
    status: GraphNodeStatus,
    entity_ref: Option<&EntityRef>,
    custom_ref: Option<String>,
    risk: f32,
    x: f32,
    y: f32,
) -> CommandResult<GraphNodeViewModel> {
    let mut node = GraphNodeViewModel::new(node_type, redacted_label(label)?);
    node.node_id = node_id;
    node.status = status;
    node.risk_score = quality(risk)?;
    node.detail_ref = GraphDetailRef {
        entity_id: entity_ref.map(|entity| entity.entity_id.clone()),
        finding_id: None,
        alert_id: None,
        incident_id: None,
        evidence_refs: Vec::new(),
        custom_ref,
    };
    node.privacy_class = PrivacyClass::Internal;
    node.position_hint = Some(GraphPositionHint { x, y });
    Ok(node)
}

#[allow(clippy::too_many_arguments)]
fn graph_case_node(
    node_id: GraphNodeId,
    node_type: GraphNodeType,
    label: &str,
    status: GraphNodeStatus,
    finding_id: Option<FindingId>,
    alert_id: Option<sentinel_contracts::AlertId>,
    incident_id: Option<sentinel_contracts::IncidentId>,
    risk: f32,
    x: f32,
    y: f32,
) -> CommandResult<GraphNodeViewModel> {
    let mut node = graph_node(node_id, node_type, label, status, None, None, risk, x, y)?;
    node.detail_ref.finding_id = finding_id;
    node.detail_ref.alert_id = alert_id;
    node.detail_ref.incident_id = incident_id;
    Ok(node)
}

fn graph_edge(
    edge_id: GraphEdgeId,
    edge_type: GraphEdgeType,
    source: GraphNodeId,
    target: GraphNodeId,
    label: &str,
    evidence_refs: Vec<EvidenceId>,
    confidence: f32,
) -> CommandResult<GraphEdgeViewModel> {
    let mut edge = GraphEdgeViewModel::new(edge_type, source, target);
    edge.edge_id = edge_id;
    edge.label = Some(redacted_label(label)?);
    edge.evidence_refs = evidence_refs;
    edge.confidence = quality(confidence)?;
    edge.privacy_class = PrivacyClass::Internal;
    Ok(edge)
}

fn canonical_graph_nodes_from_view(
    view: &GraphViewModel,
) -> CommandResult<Vec<CanonicalGraphNode>> {
    view.nodes
        .iter()
        .map(|node| {
            let mut canonical = CanonicalGraphNode::new(node.node_type.clone(), node.label.clone());
            canonical.node_id = node.node_id.clone();
            canonical.entity_ref = entity_ref_for_graph_node(node)?;
            canonical.risk_score = node.risk_score.clone();
            canonical.confidence = quality(0.86)?;
            canonical.first_seen = story_time(6)?;
            canonical.last_seen = story_time(9)?;
            canonical.privacy_class = PrivacyClass::Sensitive;
            canonical.source_refs = node.detail_ref.evidence_refs.clone();
            Ok(canonical)
        })
        .collect()
}

fn canonical_graph_edges_from_view(
    view: &GraphViewModel,
    producer_plugin: PluginId,
) -> CommandResult<Vec<CanonicalGraphEdge>> {
    view.edges
        .iter()
        .map(|edge| {
            let mut canonical = CanonicalGraphEdge::new(
                edge.edge_type.clone(),
                edge.source.clone(),
                edge.target.clone(),
            );
            canonical.edge_id = edge.edge_id.clone();
            canonical.label = edge.label.clone();
            canonical.evidence_refs = edge.evidence_refs.clone();
            canonical.confidence = edge.confidence.clone();
            canonical.weight = edge.confidence.clone();
            canonical.first_seen = story_time(6)?;
            canonical.last_seen = story_time(9)?;
            canonical.privacy_class = PrivacyClass::Sensitive;
            canonical.producer_plugin = Some(producer_plugin.clone());
            Ok(canonical)
        })
        .collect()
}

fn entity_ref_for_graph_node(node: &GraphNodeViewModel) -> CommandResult<Option<EntityRef>> {
    if let Some(entity_id) = &node.detail_ref.entity_id {
        let mut entity_ref =
            EntityRef::new(entity_id.clone(), entity_type_for_node(&node.node_type));
        entity_ref.entity_name = Some(node.label.display.clone());
        entity_ref.confidence = quality(0.86)?;
        entity_ref.first_seen = Some(story_time(6)?);
        entity_ref.last_seen = Some(story_time(9)?);
        return Ok(Some(entity_ref));
    }

    let typed_entity = if let Some(finding_id) = &node.detail_ref.finding_id {
        Some((
            EntityId::from_uuid(finding_id.as_uuid()),
            EntityType::Finding,
        ))
    } else if let Some(alert_id) = &node.detail_ref.alert_id {
        Some((EntityId::from_uuid(alert_id.as_uuid()), EntityType::Alert))
    } else {
        node.detail_ref.incident_id.as_ref().map(|incident_id| {
            (
                EntityId::from_uuid(incident_id.as_uuid()),
                EntityType::Incident,
            )
        })
    };

    typed_entity
        .map(|(entity_id, entity_type)| {
            let mut entity_ref = EntityRef::new(entity_id, entity_type);
            entity_ref.entity_name = Some(node.label.display.clone());
            entity_ref.confidence = quality(0.86)?;
            entity_ref.first_seen = Some(story_time(6)?);
            entity_ref.last_seen = Some(story_time(9)?);
            Ok(entity_ref)
        })
        .transpose()
}

fn entity_type_for_node(node_type: &GraphNodeType) -> EntityType {
    match node_type {
        GraphNodeType::LocalHost => EntityType::Host,
        GraphNodeType::Process | GraphNodeType::ProcessBinary => EntityType::Process,
        GraphNodeType::Domain => EntityType::Domain,
        GraphNodeType::Ip => EntityType::Ip,
        GraphNodeType::Alert => EntityType::Alert,
        GraphNodeType::Finding => EntityType::Finding,
        GraphNodeType::Incident => EntityType::Incident,
        GraphNodeType::LocalPort => EntityType::Port,
        GraphNodeType::CloudDestination | GraphNodeType::CloudProvider => EntityType::CloudResource,
        _ => EntityType::Other,
    }
}

fn graph_paths(ids: &StoryIds) -> CommandResult<Vec<GraphPath>> {
    let mut path = GraphPath::new(
        GraphPathType::IncidentSummaryPath,
        vec![
            ids.node_process.clone(),
            ids.node_c2_domain.clone(),
            ids.node_c2_ip.clone(),
            ids.node_finding_c2.clone(),
            ids.node_alert_c2.clone(),
            ids.node_incident.clone(),
        ],
        vec![
            ids.edge_process_c2_domain.clone(),
            ids.edge_c2_domain_ip.clone(),
            ids.edge_c2_finding.clone(),
            ids.edge_finding_alert.clone(),
            ids.edge_alert_incident.clone(),
        ],
        redacted_label("DEMO_ONLY process to suspicious IP via domain to incident")?,
    )
    .map_err(contract_error)?;
    path.path_id = ids.graph_path.clone();
    path.risk_score = quality(0.86)?;
    path.confidence = quality(0.84)?;
    path.evidence_refs = vec![
        ids.evidence_beacon.clone(),
        ids.evidence_dns.clone(),
        ids.evidence_tls.clone(),
    ];
    path.redaction_status = RedactionStatus::Redacted;
    Ok(vec![path])
}

#[allow(clippy::too_many_arguments)]
fn response_plan_from_fixture_capability(
    id_slot: u16,
    incident_id: sentinel_contracts::IncidentId,
    producer_plugin: PluginId,
    findings: &[Finding],
    alerts: &[Alert],
    incident: &Incident,
    graph_paths: &[GraphPath],
    trace_id: &TraceId,
) -> CommandResult<ResponsePlan> {
    let output = fixture_response_planning_output(
        response_planning_input(producer_plugin, findings, alerts, incident, graph_paths)?,
        trace_id,
    )?;

    let source = ResponsePlanSource::Incident(incident_id);
    let mut plan = output
        .response_plans
        .into_iter()
        .find(|plan| plan.source == source)
        .ok_or_else(|| {
            story_error(
                "response_runtime",
                "fixture response planning capability did not return an incident-sourced plan",
                json!({ "source": "incident" }),
            )
        })?;
    normalize_runtime_response_plan(&mut plan, id_slot)?;
    Ok(plan)
}

fn response_planning_input(
    producer_plugin: PluginId,
    findings: &[Finding],
    alerts: &[Alert],
    incident: &Incident,
    graph_paths: &[GraphPath],
) -> CommandResult<ResponsePlanningInput> {
    let mut input = ResponsePlanningInput::new(producer_plugin)
        .with_response_policy(ResponsePolicy::auto_containment_lite())
        .with_replay();
    input.findings = findings.to_vec();
    input.alerts = alerts.to_vec();
    input.incidents = vec![incident.clone()];
    input.graph_paths = graph_paths.to_vec();
    input.labels = vec!["task_540_demo_story_response_planning".to_string()];
    input.observed_at = story_time(10)?;
    Ok(input)
}

fn normalize_runtime_response_plan(plan: &mut ResponsePlan, id_slot: u16) -> CommandResult<()> {
    let plan_id: sentinel_contracts::ResponsePlanId = fixed_id(id_slot, "response_plan_id")?;
    plan.plan_id = plan_id.clone();
    plan.created_at = story_time(10)?;
    plan.is_replay = true;
    plan.execution_disabled_in_replay = true;

    for (index, action) in plan.recommended_actions.iter_mut().enumerate() {
        action.recommended_action_id = fixed_id(141 + index as u16, "recommended_action_id")?;
        action.action_id = None;
        action.approval_state = Some(if action.approval_required {
            ApprovalState::Requested
        } else {
            ApprovalState::NotRequired
        });
    }

    for (index, decision) in plan.policy_decisions.iter_mut().enumerate() {
        decision.decision_id = fixed_id(151 + index as u16, "policy_decision_id")?;
        decision.plan_id = Some(plan_id.clone());
        decision.action_id = None;
        decision.created_at = story_time(10)?;
    }

    for (index, rollback) in plan.rollback_plans.iter_mut().enumerate() {
        rollback.rollback_plan_id = fixed_id(154 + index as u16, "rollback_plan_id")?;
        rollback.action_id = None;
        rollback.rollback_token = format!("rollback:demo_story:{}:{}", index + 1, plan_id);
    }

    Ok(())
}

fn response_results_for_report(
    response_plan: &ResponsePlan,
    trace_id: &TraceId,
) -> CommandResult<Vec<ResponseResult>> {
    let mut results = Vec::new();
    for (index, action) in response_plan.recommended_actions.iter().enumerate() {
        let rollback_plan = response_plan.rollback_plans.get(index).ok_or_else(|| {
            story_error(
                "response_result",
                "demo response result requires matching rollback metadata",
                json!({ "action_index": index }),
            )
        })?;
        let mut result = ResponseResult::new(
            fixed_id::<ResponseActionId, _>(270 + index as u16, "response_action_id")?,
            "execution_disabled_recommendation_only",
            action.target.clone(),
            rollback_plan,
            audit_ref(
                280 + index as u16,
                "DEMO_ONLY.response.execution_disabled",
                Some(trace_id.clone()),
            )?,
        )
        .map_err(contract_error)?;
        result.result_id = fixed_id(260 + index as u16, "response_result_id")?;
        result.started_at = story_time(11)?;
        result.ended_at = Some(story_time(11)?);
        result.success = false;
        result.error_summary_redacted = Some(
            "DEMO_ONLY no OS action was performed; response execution is disabled for replay"
                .to_string(),
        );
        result.rollback_token.clear();
        result.rollback_deadline = None;
        result.is_replay = true;
        result.execution_disabled = true;
        results.push(result);
    }

    if results.is_empty() {
        return Err(story_error(
            "response_result",
            "demo response report requires at least one disabled-execution result",
            json!({ "response_plan": response_plan.plan_id.to_string() }),
        ));
    }

    Ok(results)
}

struct ReportBuildContext<'a> {
    ids: &'a StoryIds,
    incident: &'a Incident,
    alerts: &'a [Alert],
    findings: &'a [Finding],
    response_plan: &'a ResponsePlan,
    response_results: &'a [ResponseResult],
    trace_id: &'a TraceId,
}

fn report(id_slot: u16, context: ReportBuildContext<'_>) -> CommandResult<Report> {
    let mut redaction = redaction_summary();
    redaction.redacted_field_count = 18;
    redaction.notes_redacted = vec![
        "Raw packets, payloads, HTTP bodies, cookies, tokens, credentials, API keys, private keys, full query strings, form content, command lines, local paths, usernames, and SIDs excluded by default.".to_string(),
    ];
    let mut report = Report::new(
        ReportType::Incident,
        "DEMO_ONLY redacted incident report",
        "DEMO_ONLY local-first metadata report generated from fixture story replay",
        redaction.clone(),
    )
    .map_err(contract_error)?;
    report.report_id = fixed_id(id_slot, "report_id")?;
    report.incident_refs = vec![context.incident.id().clone()];
    report.alert_refs = context
        .alerts
        .iter()
        .map(|alert| alert.id().clone())
        .collect();
    report.finding_refs = context
        .findings
        .iter()
        .map(|finding| finding.id().clone())
        .collect();
    report.evidence_refs = vec![
        context.ids.evidence_beacon.clone(),
        context.ids.evidence_dns.clone(),
        context.ids.evidence_tls.clone(),
        context.ids.evidence_upload.clone(),
        context.ids.evidence_lateral.clone(),
    ];
    report.graph_snapshot_refs = vec![fixed_id(170, "graph_snapshot_id")?];
    report.response_result_refs = context
        .response_results
        .iter()
        .map(|result| result.result_id.clone())
        .collect();
    report.audit_ref = Some(audit_ref(
        171,
        "DEMO_ONLY.report.generated",
        Some(context.trace_id.clone()),
    )?);
    report.created_at = story_time(11)?;
    report.updated_at = story_time(12)?;
    report.sections = report_sections(
        context.ids,
        context.response_plan,
        context.response_results,
        &redaction,
    )?;
    Ok(report)
}

fn report_sections(
    ids: &StoryIds,
    response_plan: &ResponsePlan,
    response_results: &[ResponseResult],
    redaction: &RedactionSummary,
) -> CommandResult<Vec<ReportSection>> {
    let response_result_refs = response_results
        .iter()
        .map(|result| result.result_id.clone())
        .collect::<Vec<_>>();
    let response_result_summaries = response_results
        .iter()
        .map(|result| {
            json!({
                "response_result_id": result.result_id.to_string(),
                "executor": result.executor,
                "target_summary_redacted": result.target.target_summary_redacted,
                "success": result.success,
                "execution_disabled": result.execution_disabled,
                "is_replay": result.is_replay,
                "audit_event_type": result.audit_ref.event_type,
                "rollback_available": !result.rollback_token.trim().is_empty()
            })
        })
        .collect::<Vec<_>>();
    let mut sections = vec![
        report_section(
            161,
            ReportSectionType::ExecutiveSummary,
            "Executive summary",
            json!({
                "summary_redacted": "DEMO_ONLY metadata story promoted to one incident.",
                "finding_count": 3,
                "alert_count": 2
            }),
            redaction.clone(),
        )?,
        report_section(
            162,
            ReportSectionType::Timeline,
            "Timeline",
            json!({
                "events_redacted": [
                    "metadata input",
                    "flow and DNS observation",
                    "finding promotion",
                    "report redaction"
                ]
            }),
            redaction.clone(),
        )?,
        report_section(
            163,
            ReportSectionType::EvidenceTable,
            "Evidence table",
            json!({
                "evidence_ref_count": 5,
                "content_policy": "metadata_only"
            }),
            redaction.clone(),
        )?,
        report_section(
            164,
            ReportSectionType::GraphSnapshot,
            "Graph snapshot",
            json!({
                "graph_view_model_only": true,
                "canonical_graph_internals_excluded": true
            }),
            redaction.clone(),
        )?,
        report_section(
            165,
            ReportSectionType::ResponseRecommendation,
            "Response recommendation",
            json!({
                "plan_id": response_plan.plan_id.to_string(),
                "recommended_actions": response_plan.recommended_actions.len(),
                "execution_disabled_in_replay": response_plan.execution_disabled_in_replay,
                "static_runtime_provenance_recorded": response_plan.audit_requirements.iter().any(
                    |requirement| requirement == "response.runtime.static_internal.process_batch"
                )
            }),
            redaction.clone(),
        )?,
        report_section(
            166,
            ReportSectionType::ResponseResult,
            "Response result evidence",
            json!({
                "results": response_result_summaries,
                "result_count": response_result_refs.len(),
                "execution_disabled": true,
                "no_real_response_execution": true
            }),
            redaction.clone(),
        )?,
        report_section(
            167,
            ReportSectionType::PrivacyRedactionSummary,
            "Privacy redaction summary",
            json!({
                "redaction_passed": true,
                "raw_content_absent": true,
                "export_gated": true
            }),
            redaction.clone(),
        )?,
    ];
    sections[2].evidence_refs = vec![
        ids.evidence_beacon.clone(),
        ids.evidence_dns.clone(),
        ids.evidence_tls.clone(),
        ids.evidence_upload.clone(),
        ids.evidence_lateral.clone(),
    ];
    sections[3].graph_snapshot_refs = vec![fixed_id(170, "graph_snapshot_id")?];
    sections[5].response_result_refs = response_result_refs;
    Ok(sections)
}

fn report_section(
    id_slot: u16,
    section_type: ReportSectionType,
    title: &str,
    content: Value,
    redaction: RedactionSummary,
) -> CommandResult<ReportSection> {
    let mut section = ReportSection::new(section_type, title, redaction).map_err(contract_error)?;
    section.section_id = fixed_id(id_slot, "report_section_id")?;
    section.content_redacted = content;
    section.privacy_class = PrivacyClass::Internal;
    Ok(section)
}

fn export_history_record(
    id_slot: u16,
    report: &Report,
    trace_id: &TraceId,
) -> CommandResult<ExportHistoryRecord> {
    Ok(ExportHistoryRecord {
        export_result_id: fixed_id(id_slot, "export_result_id")?,
        report_id: report.report_id.clone(),
        format: ExportFormat::RedactedJson,
        destination: ExportDestinationMetadata::local(Some(
            "DEMO_ONLY local redacted export history".to_string(),
        ))
        .map_err(export_history_error)?,
        file_hash: Some(ExportFileHash::from_bytes(
            b"demo-only-redacted-export-hash",
        )),
        redaction_summary: report.redaction_summary.clone(),
        graph_snapshot_refs: report.graph_snapshot_refs.clone(),
        evidence_refs: report.evidence_refs.clone(),
        response_result_refs: report.response_result_refs.clone(),
        rollback_result_refs: report.rollback_result_refs.clone(),
        llm_story_refs: report.llm_story_refs.clone(),
        actor_redacted: "local_operator".to_string(),
        exported_at: story_time(12)?,
        trace_id: Some(trace_id.clone()),
        audit_id: fixed_id(id_slot + 1, "audit_id")?,
        success: true,
    })
}

fn redaction_summary() -> RedactionSummary {
    RedactionSummary::passed(vec![
        RedactedDataCategory::RawPacket,
        RedactedDataCategory::Payload,
        RedactedDataCategory::HttpBody,
        RedactedDataCategory::Cookie,
        RedactedDataCategory::Token,
        RedactedDataCategory::Credential,
        RedactedDataCategory::ApiKey,
        RedactedDataCategory::PrivateKey,
        RedactedDataCategory::FullQueryString,
        RedactedDataCategory::FormContent,
        RedactedDataCategory::CommandLine,
        RedactedDataCategory::LocalPath,
        RedactedDataCategory::Username,
        RedactedDataCategory::Sid,
    ])
}

fn validate_story(story: &FixtureAttackStory) -> CommandResult<()> {
    if !matches!(story.fixture_mode.as_str(), "DEMO_ONLY" | "FIXTURE_ONLY") {
        return Err(story_error(
            "fixture_mode",
            "fixture attack story must be explicitly labeled DEMO_ONLY or FIXTURE_ONLY",
            json!({ "fixture_mode": story.fixture_mode }),
        ));
    }

    let expected = StoryStage::ordered();
    if story.stages.len() != expected.len()
        || expected.iter().any(|stage| {
            !story
                .stages
                .iter()
                .any(|definition| &definition.stage == stage)
        })
    {
        return Err(story_error(
            "fixture_stages",
            "fixture attack story must define all eight required stages",
            json!({ "stage_count": story.stages.len() }),
        ));
    }

    for ip in [
        &story.metadata.local_ip,
        &story.metadata.resolver_ip,
        &story.metadata.c2_ip,
        &story.metadata.exfil_ip,
        &story.metadata.lateral_ip,
    ] {
        if !is_documentation_ip(ip) {
            return Err(story_error(
                "fixture_ip",
                "fixture attack story IPs must use RFC 5737 documentation ranges",
                json!({ "ip_redacted": ip }),
            ));
        }
    }

    for domain in [
        &story.metadata.c2_domain_protected,
        &story.metadata.exfil_domain_protected,
    ] {
        if !domain.ends_with(".test") && !domain.ends_with(".example") {
            return Err(story_error(
                "fixture_domain",
                "fixture attack story domains must use reserved .test or .example names",
                json!({ "domain_redacted": domain }),
            ));
        }
    }

    let serialized = serde_json::to_string(story).map_err(serialization_error)?;
    if forbidden_fixture_markers()
        .iter()
        .any(|marker| serialized.to_ascii_lowercase().contains(marker))
    {
        return Err(story_error(
            "fixture_privacy",
            "fixture attack story contains a forbidden sensitive marker",
            json!({ "fixture_id": story.story_id }),
        ));
    }

    Ok(())
}

fn is_documentation_ip(value: &str) -> bool {
    value.starts_with("192.0.2.")
        || value.starts_with("198.51.100.")
        || value.starts_with("203.0.113.")
}

fn forbidden_fixture_markers() -> &'static [&'static str] {
    &[
        "raw_payload",
        "payload_blob",
        "http_body",
        "authorization:",
        "set-cookie",
        "session_token",
        "access_token",
        "refresh_token",
        "api_key",
        "private_key",
        "password=",
        "credential=",
        "query_string=",
        "form_content",
        "command_line=",
    ]
}

fn parse_ip(value: &str) -> CommandResult<IpAddress> {
    IpAddress::parse_str(value).map_err(|error| {
        story_error(
            "fixture_ip",
            "invalid fixture IP address",
            json!({ "error_redacted": error.to_string() }),
        )
    })
}

fn entity_ref(slot: u16, entity_type: EntityType, name: String) -> CommandResult<EntityRef> {
    let mut entity = EntityRef::new(fixed_id::<EntityId, _>(slot, "entity_id")?, entity_type);
    entity.entity_name = Some(name);
    entity.namespace = Some("DEMO_ONLY".to_string());
    entity.source = Some("fixture_attack_story".to_string());
    entity.confidence = quality(0.98)?;
    entity.first_seen = Some(story_time(0)?);
    entity.last_seen = Some(story_time(12)?);
    Ok(entity)
}

fn legend_item(key: &str, label: &str) -> CommandResult<GraphLegendItem> {
    Ok(GraphLegendItem {
        key: key.to_string(),
        label: redacted_label(label)?,
        color: None,
        icon: None,
    })
}

fn redacted_label(value: &str) -> CommandResult<RedactedLabel> {
    RedactedLabel::redacted(value, PrivacyClass::Internal).map_err(contract_error)
}

fn audit_ref(id_slot: u16, event_type: &str, trace_id: Option<TraceId>) -> CommandResult<AuditRef> {
    let mut audit = AuditRef::new(event_type).map_err(contract_error)?;
    audit.audit_id = fixed_id(id_slot, "audit_id")?;
    audit.trace_id = trace_id;
    audit.timestamp = story_time(11)?;
    Ok(audit)
}

fn quality(value: f32) -> CommandResult<QualityScore> {
    QualityScore::new(value).map_err(contract_error)
}

fn story_time(step: i64) -> CommandResult<Timestamp> {
    let base = DateTime::parse_from_rfc3339(STORY_START_RFC3339)
        .map_err(|error| {
            story_error(
                "fixture_time",
                "failed to parse fixture start time",
                json!({ "error_redacted": error.to_string() }),
            )
        })?
        .with_timezone(&Utc);
    Ok(Timestamp::from_datetime(
        base + Duration::seconds(step * 30),
    ))
}

fn fixed_id<T, E>(slot: u16, field: &'static str) -> CommandResult<T>
where
    T: FromStr<Err = E>,
    E: Display,
{
    let value = fixed_uuid(slot);
    T::from_str(&value).map_err(|error| {
        story_error(
            "fixture_id",
            "failed to parse deterministic fixture id",
            json!({
                "field": field,
                "id_redacted": value,
                "error_redacted": error.to_string()
            }),
        )
    })
}

fn fixed_uuid(slot: u16) -> String {
    format!("54000000-0000-4000-8000-{slot:012x}")
}

fn rewrite_contract_fields<T>(contract: T, fields: Vec<(&'static str, Value)>) -> CommandResult<T>
where
    T: Serialize + DeserializeOwned,
{
    let mut value = serde_json::to_value(contract).map_err(serialization_error)?;
    let object = value.as_object_mut().ok_or_else(|| {
        story_error(
            "fixture_contract",
            "fixture contract did not serialize to an object",
            json!({}),
        )
    })?;
    for (field, field_value) in fields {
        object.insert(field.to_string(), field_value);
    }
    serde_json::from_value(value).map_err(serialization_error)
}

fn to_value<T: Serialize>(value: T) -> CommandResult<Value> {
    serde_json::to_value(value).map_err(serialization_error)
}

fn story_error(context: &'static str, message: &'static str, details: Value) -> CoreError {
    CoreError::new(ErrorCode::InvalidRequest, message)
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({
            "context": context,
            "details": details
        }))
}

fn contract_error(error: impl Display) -> CoreError {
    CoreError::new(
        ErrorCode::ValidationFailure,
        "fixture story contract validation failed",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn export_history_error(error: impl Display) -> CoreError {
    CoreError::new(
        ErrorCode::ValidationFailure,
        "fixture story export history validation failed",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn storage_error(error: impl Display) -> CoreError {
    CoreError::new(
        ErrorCode::StorageUnavailable,
        "fixture story storage persistence failed",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn serialization_error(error: impl Display) -> CoreError {
    CoreError::new(
        ErrorCode::InternalError,
        "fixture story serialization failed",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoryIds {
    flow_beacon: sentinel_contracts::FlowId,
    flow_tls: sentinel_contracts::FlowId,
    flow_upload: sentinel_contracts::FlowId,
    flow_lateral: sentinel_contracts::FlowId,
    dns_c2: sentinel_contracts::DnsObservationId,
    dns_exfil: sentinel_contracts::DnsObservationId,
    tls_c2: sentinel_contracts::TlsObservationId,
    evidence_beacon: EvidenceId,
    evidence_dns: EvidenceId,
    evidence_tls: EvidenceId,
    evidence_upload: EvidenceId,
    evidence_lateral: EvidenceId,
    risk_c2: sentinel_contracts::RiskEventId,
    risk_exfil: sentinel_contracts::RiskEventId,
    risk_lateral: sentinel_contracts::RiskEventId,
    graph_path: GraphPathId,
    node_host: GraphNodeId,
    node_process: GraphNodeId,
    node_c2_domain: GraphNodeId,
    node_c2_ip: GraphNodeId,
    node_exfil_domain: GraphNodeId,
    node_exfil_ip: GraphNodeId,
    node_lateral_ip: GraphNodeId,
    node_finding_c2: GraphNodeId,
    node_finding_exfil: GraphNodeId,
    node_finding_lateral: GraphNodeId,
    node_alert_c2: GraphNodeId,
    node_alert_exfil: GraphNodeId,
    node_incident: GraphNodeId,
    edge_host_process: GraphEdgeId,
    edge_process_c2_domain: GraphEdgeId,
    edge_c2_domain_ip: GraphEdgeId,
    edge_process_c2_ip: GraphEdgeId,
    edge_process_exfil_domain: GraphEdgeId,
    edge_exfil_domain_ip: GraphEdgeId,
    edge_process_lateral_ip: GraphEdgeId,
    edge_c2_finding: GraphEdgeId,
    edge_exfil_finding: GraphEdgeId,
    edge_lateral_finding: GraphEdgeId,
    edge_finding_alert: GraphEdgeId,
    edge_exfil_alert: GraphEdgeId,
    edge_alert_incident: GraphEdgeId,
    edge_exfil_incident: GraphEdgeId,
}

impl StoryIds {
    fn new() -> CommandResult<Self> {
        Ok(Self {
            flow_beacon: fixed_id(20, "flow_beacon")?,
            flow_tls: fixed_id(21, "flow_tls")?,
            flow_upload: fixed_id(22, "flow_upload")?,
            flow_lateral: fixed_id(23, "flow_lateral")?,
            dns_c2: fixed_id(30, "dns_c2")?,
            dns_exfil: fixed_id(31, "dns_exfil")?,
            tls_c2: fixed_id(32, "tls_c2")?,
            evidence_beacon: fixed_id(40, "evidence_beacon")?,
            evidence_dns: fixed_id(41, "evidence_dns")?,
            evidence_tls: fixed_id(42, "evidence_tls")?,
            evidence_upload: fixed_id(43, "evidence_upload")?,
            evidence_lateral: fixed_id(44, "evidence_lateral")?,
            risk_c2: fixed_id(50, "risk_c2")?,
            risk_exfil: fixed_id(51, "risk_exfil")?,
            risk_lateral: fixed_id(52, "risk_lateral")?,
            graph_path: fixed_id(60, "graph_path")?,
            node_host: fixed_id(200, "node_host")?,
            node_process: fixed_id(201, "node_process")?,
            node_c2_domain: fixed_id(202, "node_c2_domain")?,
            node_c2_ip: fixed_id(203, "node_c2_ip")?,
            node_exfil_domain: fixed_id(204, "node_exfil_domain")?,
            node_exfil_ip: fixed_id(205, "node_exfil_ip")?,
            node_lateral_ip: fixed_id(206, "node_lateral_ip")?,
            node_finding_c2: fixed_id(207, "node_finding_c2")?,
            node_finding_exfil: fixed_id(208, "node_finding_exfil")?,
            node_finding_lateral: fixed_id(209, "node_finding_lateral")?,
            node_alert_c2: fixed_id(210, "node_alert_c2")?,
            node_alert_exfil: fixed_id(211, "node_alert_exfil")?,
            node_incident: fixed_id(212, "node_incident")?,
            edge_host_process: fixed_id(230, "edge_host_process")?,
            edge_process_c2_domain: fixed_id(231, "edge_process_c2_domain")?,
            edge_c2_domain_ip: fixed_id(232, "edge_c2_domain_ip")?,
            edge_process_c2_ip: fixed_id(233, "edge_process_c2_ip")?,
            edge_process_exfil_domain: fixed_id(234, "edge_process_exfil_domain")?,
            edge_exfil_domain_ip: fixed_id(235, "edge_exfil_domain_ip")?,
            edge_process_lateral_ip: fixed_id(236, "edge_process_lateral_ip")?,
            edge_c2_finding: fixed_id(237, "edge_c2_finding")?,
            edge_exfil_finding: fixed_id(238, "edge_exfil_finding")?,
            edge_lateral_finding: fixed_id(239, "edge_lateral_finding")?,
            edge_finding_alert: fixed_id(240, "edge_finding_alert")?,
            edge_exfil_alert: fixed_id(241, "edge_exfil_alert")?,
            edge_alert_incident: fixed_id(242, "edge_alert_incident")?,
            edge_exfil_incident: fixed_id(243, "edge_exfil_incident")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_fixture_replays_full_safe_story() {
        let run = FixtureRunner::from_default_fixture()
            .expect("fixture runner")
            .run()
            .expect("fixture run");

        assert_eq!(run.result.fixture_mode, "DEMO_ONLY");
        assert_eq!(run.result.stage_count, 8);
        assert!(run.result.replay_only);
        assert!(run.result.execution_disabled);
        assert_eq!(run.result.flow_count, 4);
        assert_eq!(run.result.finding_count, 3);
        assert_eq!(run.result.alert_count, 2);
        assert_eq!(run.result.incident_count, 1);
        assert_eq!(run.result.response_plan_count, 1);
        assert_eq!(run.result.report_count, 1);
        assert_eq!(run.result.export_history_count, 1);
        assert!(run.result.redaction_summary.passed);
        assert!(run.result.stages.iter().all(|stage| {
            stage.duration_millis == 60_000 && stage.completed_at > stage.started_at
        }));
        assert_eq!(run.read_model.process_contexts.len(), 1);
        assert_eq!(run.read_model.canonical_graph_nodes.len(), 13);
        assert_eq!(run.read_model.canonical_graph_edges.len(), 14);
        assert_eq!(run.read_model.graph_paths.len(), 1);
        assert_eq!(run.read_model.graph_views.len(), 2);
        assert!(run.read_model.risk_events.iter().all(|event| {
            event.decay_policy.as_deref() == Some(RISK_RUNTIME_PROVENANCE)
                && !event.contributing_findings.is_empty()
        }));
        assert!(run
            .read_model
            .incidents
            .iter()
            .all(|incident| !incident.graph_path_refs().is_empty()));
        assert!(run
            .read_model
            .response_plans
            .iter()
            .all(|plan| plan.execution_disabled_in_replay));
        let plan = run
            .read_model
            .response_plans
            .first()
            .expect("response plan");
        assert!(plan
            .audit_requirements
            .iter()
            .any(|requirement| requirement == "response.fixture.pure_capability.process"));
        assert_eq!(plan.recommended_actions.len(), 3);
        assert_eq!(plan.policy_decisions.len(), plan.recommended_actions.len());
        assert_eq!(plan.rollback_plans.len(), plan.recommended_actions.len());
        assert!(plan.recommended_actions.iter().all(|action| {
            !action.response_level.execution_allowed_by_default() && action.action_id.is_none()
        }));
        assert!(plan.recommended_actions.iter().all(|action| {
            action.approval_state
                == Some(if action.approval_required {
                    ApprovalState::Requested
                } else {
                    ApprovalState::NotRequired
                })
        }));
        let report = run.read_model.reports.first().expect("report");
        assert!(!report.response_result_refs.is_empty());
        let response_section = report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::ResponseResult)
            .expect("response result section");
        assert_eq!(
            response_section.response_result_refs,
            report.response_result_refs
        );
        assert_eq!(
            response_section
                .content_redacted
                .get("result_count")
                .and_then(Value::as_u64),
            Some(report.response_result_refs.len() as u64)
        );
        let result_summaries = response_section
            .content_redacted
            .get("results")
            .and_then(Value::as_array)
            .expect("response result summaries");
        assert!(!result_summaries.is_empty());
        assert!(result_summaries.iter().all(|summary| {
            summary.get("executor").and_then(Value::as_str)
                == Some("execution_disabled_recommendation_only")
                && summary.get("execution_disabled").and_then(Value::as_bool) == Some(true)
                && summary.get("is_replay").and_then(Value::as_bool) == Some(true)
                && summary.get("success").and_then(Value::as_bool) == Some(false)
                && summary.get("rollback_available").and_then(Value::as_bool) == Some(false)
        }));
        let export = run
            .read_model
            .export_history
            .records()
            .first()
            .expect("export history");
        assert_eq!(export.response_result_refs, report.response_result_refs);
        assert!(export.rollback_result_refs.is_empty());
        assert!(serde_json::to_string(&run.read_model.reports)
            .expect("serialize reports")
            .contains("static_runtime_provenance_recorded"));
    }

    #[test]
    fn fixture_story_installs_into_read_state() {
        let run = FixtureRunner::from_default_fixture()
            .expect("fixture runner")
            .run()
            .expect("fixture run");
        let state = run
            .read_model
            .into_read_state(ReadOnlyCommandState::bootstrap().expect("read state"));

        assert_eq!(state.findings.items.len(), 3);
        assert_eq!(state.alerts.items.len(), 2);
        assert_eq!(state.incidents.items.len(), 1);
        assert_eq!(state.graph_views[0].nodes.len(), 13);
        assert_eq!(state.export_history.records().len(), 1);
        assert!(!state.reports.items[0].response_result_refs.is_empty());
        assert_eq!(
            state.export_history.records()[0].response_result_refs,
            state.reports.items[0].response_result_refs
        );
    }

    #[test]
    fn runtime_response_plan_serializes_without_sensitive_markers() {
        let run = FixtureRunner::from_default_fixture()
            .expect("fixture runner")
            .run()
            .expect("fixture run");
        let security_serialized = serde_json::to_string(&json!({
            "risk_events": &run.read_model.risk_events,
            "alerts": &run.read_model.alerts,
            "incidents": &run.read_model.incidents,
        }))
        .expect("serialize security runtime outputs");
        assert!(security_serialized.contains(RISK_RUNTIME_PROVENANCE));
        let serialized =
            serde_json::to_string(&run.read_model.response_plans).expect("serialize plans");
        let lower = serialized.to_ascii_lowercase();

        for marker in forbidden_fixture_markers() {
            assert!(!lower.contains(marker), "marker leaked: {marker}");
        }
        assert!(serialized.contains("response.fixture.pure_capability.process"));
        assert!(!lower.contains("response_result"));
        assert!(!lower.contains("response_rollback_result"));

        let report_and_history = serde_json::to_string(&json!({
            "reports": &run.read_model.reports,
            "export_history": run.read_model.export_history.records(),
        }))
        .expect("serialize report and history");
        let report_and_history_lower = report_and_history.to_ascii_lowercase();
        for marker in [
            "raw_payload=",
            "payload_blob",
            "http_body=",
            "session_token=secret",
            "access_token=secret",
            "refresh_token=secret",
            "authorization:",
            "api_key=",
            "private_key=",
            "password=",
            "credential=",
            "query_string=",
            "form_content=",
            "command_line=",
        ] {
            assert!(
                !report_and_history_lower.contains(marker),
                "unsafe value marker leaked: {marker}"
            );
        }
        assert!(report_and_history.contains("execution_disabled_recommendation_only"));
        assert!(report_and_history.contains("response_result_refs"));
    }

    #[test]
    fn fixture_story_persists_storage_backed_pipeline_and_replaces_seed_graph(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let run = FixtureRunner::from_default_fixture()
            .expect("fixture runner")
            .run()
            .expect("fixture run");
        let runtime = sentinel_storage::DatabaseRuntime::bootstrap(
            sentinel_storage::DatabaseConfig::demo_in_memory("task-540-test"),
        )?;

        let summary = persist_run_to_runtime(&runtime, &run)?;
        assert_eq!(summary.flow_count, 4);
        assert_eq!(summary.dns_observation_count, 2);
        assert_eq!(summary.tls_observation_count, 1);
        assert_eq!(summary.finding_count, 3);
        assert_eq!(summary.alert_count, 2);
        assert_eq!(summary.incident_count, 1);
        assert_eq!(summary.canonical_graph_node_count, 13);
        assert_eq!(summary.canonical_graph_edge_count, 14);
        assert_eq!(summary.graph_path_count, 1);
        assert_eq!(summary.response_plan_count, 1);
        assert_eq!(summary.report_count, 1);
        assert_eq!(summary.export_history_count, 1);

        let second_summary = persist_run_to_runtime(&runtime, &run)?;
        assert_eq!(second_summary, summary);

        runtime.handle().with_connection(|connection| {
            let stores = SqliteStoreFactory::new(connection);
            let graph_store = stores.graph_store();
            assert_eq!(graph_store.nodes().create_snapshot()?.record_count, 13);
            assert_eq!(graph_store.edges().create_snapshot()?.record_count, 14);
            assert_eq!(graph_store.paths().create_snapshot()?.record_count, 1);

            let graph = crate::read_commands::try_get_graph_view_from_storage(
                &stores,
                crate::read_commands::GraphViewRequest {
                    graph_type: GraphType::IncidentGraph,
                    scope: GraphScope::Overview,
                    title_redacted: Some("DEMO_ONLY storage graph".to_string()),
                    node_limit: Some(100),
                    edge_limit: Some(200),
                },
            )
            .map_err(core_error_to_storage)?
            .expect("storage graph view");
            assert_eq!(graph.original_node_count, 13);
            assert_eq!(graph.original_edge_count, 14);
            assert!(!graph.nodes.is_empty());
            assert!(!graph.edges.is_empty());
            assert!(!graph.paths.is_empty());
            assert!(serde_json::to_string(&graph)
                .expect("serialize graph")
                .contains("DEMO_ONLY storage graph"));

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn fixture_validation_rejects_non_documentation_ips() {
        let mut story: FixtureAttackStory =
            serde_json::from_str(FIXTURE_ATTACK_STORY_JSON).expect("fixture json");
        story.metadata.c2_ip = "8.8.8.8".to_string();

        let error = FixtureRunner::new(story).expect_err("invalid story");

        assert_eq!(error.error_code, ErrorCode::InvalidRequest);
        assert!(error.details_redacted.is_some());
    }

    fn persist_run_to_runtime(
        runtime: &sentinel_storage::DatabaseRuntime,
        run: &FixtureRun,
    ) -> Result<DemoStoryPersistenceSummary, sentinel_storage::StorageError> {
        runtime.handle().with_connection(|connection| {
            let stores = SqliteStoreFactory::new(connection);
            run.read_model
                .persist_to_storage(&stores)
                .map_err(core_error_to_storage)
        })
    }

    fn core_error_to_storage(error: CoreError) -> sentinel_storage::StorageError {
        sentinel_storage::StorageError::UnsupportedQuery(error.message)
    }
}
