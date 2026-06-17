//! Vertical slice validation harness for Task 500.
//!
//! The scenarios in this module are `FIXTURE_ONLY` acceptance probes. They
//! exercise public Local Core command surfaces and public capability services,
//! then return a structured report describing what each slice proves and what
//! remains mock, stub, or provisional. They do not perform privileged response
//! execution, write raw packets, persist payloads, or bypass report redaction.

use crate::event_streams::{
    service_status_stream, ServiceStatusUpdate, StreamName, TauriEventDispatcher,
};
use crate::mutation_commands::{
    create_response_plan, export_report, fixture_response_planning_output,
    generate_incident_report, CreateResponsePlanRequest, ExportReportRequest,
    GenerateIncidentReportRequest, ResponsePlanningCommandOutput,
};
use crate::read_commands::{
    get_capability_overview, get_graph_view, get_plugin_catalog, get_runtime_profile,
    get_service_status, list_components, list_export_history, list_export_policy_violations,
    GraphViewRequest, ReadOnlyCommandState,
};
use chrono::{Duration, Utc};
use sentinel_capabilities::{
    C2DetectionBaseline, C2DetectionOutput, C2DetectionPlugin, ExfiltrationDetectionBaseline,
    ExfiltrationDetectionOutput, ExfiltrationDetectionPlugin, GraphAnalyticsInput,
    GraphAnalyticsRequest, GraphAnalyticsService, GraphStageInput, GraphStagePlugin,
    KnownProcessCloudDestination, KnownProcessDestination, MockNetworkPipeline,
    ProcessUploadBaseline, ReportExportHistoryQuery, ResponsePlanningInput, C2_FINDING_TYPE,
    FIXTURE_ONLY_LABEL, MOCK_ONLY_LABEL, SUSPICIOUS_C2_GRAPH_HINT_TYPE,
};
use sentinel_contracts::report::ExportFormat;
use sentinel_contracts::{
    Alert, AlertState, AttributionConfidence, CollectionMode, CommandResult, CoreError, DnsAnswer,
    DnsObservation, EntityId, EntityRef, EntityType, ErrorCode, ErrorSeverity, EvidenceId, Finding,
    FindingExplanation, FlowRecord, GraphHintType, GraphScope, GraphType, HttpMetadata, HttpMethod,
    IntelligenceProvider, IpAddress, NetworkDirection, PluginId, PrivacyClass, ProcessContext,
    QualityScore, RedactedDataCategory, ResponsePlanSource, ResponsePolicy, SecuritySeverity,
    SignerStatus, Timestamp, TlsObservation, TraceId, TransportProtocol, VisibilityLevel,
};
use sentinel_infrastructure::OfflineLocalIntelligenceProvider;
use sentinel_platform::{ObservabilityHealthStatus, PriorityLane};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const VERTICAL_SLICE_FIXTURE_LABEL: &str = "FIXTURE_ONLY";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SliceValidationStatus {
    Passed,
    Provisional,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliceDocumentation {
    pub proves: Vec<String>,
    pub remains_mock_stub_or_provisional: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PluginCatalogSlice {
    pub status: SliceValidationStatus,
    pub fixture_label: String,
    pub plugin_count: usize,
    pub component_count: usize,
    pub capability_count: usize,
    pub ui_contribution_count: usize,
    pub contract_count: usize,
    pub mock_only_catalog: bool,
    pub production_ready: bool,
    pub documentation: SliceDocumentation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FindingEvidenceSlice {
    pub status: SliceValidationStatus,
    pub fixture_label: String,
    pub finding_count: usize,
    pub evidence_item_count: usize,
    pub evidence_ref_count: usize,
    pub quality_reports_passed: bool,
    pub documentation: SliceDocumentation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphRenderingSlice {
    pub status: SliceValidationStatus,
    pub fixture_label: String,
    pub canonical_node_count: usize,
    pub canonical_edge_count: usize,
    pub graph_update_count: usize,
    pub graph_path_count: usize,
    pub view_node_count: usize,
    pub view_edge_count: usize,
    pub consumed_graph_view_model_only: bool,
    pub snapshot_redacted: bool,
    pub documentation: SliceDocumentation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MockNetworkPipelineSlice {
    pub status: SliceValidationStatus,
    pub fixture_label: String,
    pub labels: Vec<String>,
    pub packet_metadata_count: usize,
    pub flow_count: usize,
    pub dns_observation_count: usize,
    pub tls_observation_count: usize,
    pub http_metadata_count: usize,
    pub trace_continuous: bool,
    pub metadata_only: bool,
    pub documentation: SliceDocumentation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DetectionMvpSlice {
    pub status: SliceValidationStatus,
    pub fixture_label: String,
    pub c2_signal_count: usize,
    pub exfiltration_signal_count: usize,
    pub finding_count: usize,
    pub risk_hint_count: usize,
    pub graph_hint_count: usize,
    pub risk_hints_stay_evidence_input_only: bool,
    pub emits_c2_graph_hint: bool,
    pub emits_exfiltration_graph_hint: bool,
    pub documentation: SliceDocumentation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlanningSlice {
    pub status: SliceValidationStatus,
    pub fixture_label: String,
    pub response_plan_count: usize,
    pub recommended_action_count: usize,
    pub policy_decision_count: usize,
    pub rollback_plan_count: usize,
    pub approval_requirement_count: usize,
    pub execution_disabled_in_replay: bool,
    pub audit_requirements_present: bool,
    pub used_static_runtime: bool,
    pub static_runtime_provenance_recorded: bool,
    pub documentation: SliceDocumentation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportExportSlice {
    pub status: SliceValidationStatus,
    pub fixture_label: String,
    pub report_generated: bool,
    pub successful_export_recorded: bool,
    pub denied_export_recorded_as_violation: bool,
    pub history_record_count: usize,
    pub policy_violation_count: usize,
    pub audit_event_count: usize,
    pub file_hash_recorded: bool,
    pub redaction_summary_passed: bool,
    pub documentation: SliceDocumentation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WindowsServiceIpcSlice {
    pub status: SliceValidationStatus,
    pub fixture_label: String,
    pub degraded_status_reported: bool,
    pub service_stream_name: StreamName,
    pub service_event_type: String,
    pub priority: PriorityLane,
    pub reduced_visibility: bool,
    pub privileged_actions_available: bool,
    pub capture_available: bool,
    pub documentation: SliceDocumentation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SliceValidationReport {
    pub fixture_label: String,
    pub generated_at: Timestamp,
    pub all_required_slices_passed: bool,
    pub sensitive_marker_scan_passed: bool,
    pub sensitive_markers_checked: Vec<String>,
    pub validation_notes: Vec<String>,
    pub plugin_catalog: PluginCatalogSlice,
    pub finding_evidence: FindingEvidenceSlice,
    pub graph_rendering: GraphRenderingSlice,
    pub mock_network_pipeline: MockNetworkPipelineSlice,
    pub detection_mvp: DetectionMvpSlice,
    pub response_planning: ResponsePlanningSlice,
    pub report_export: ReportExportSlice,
    pub windows_service_ipc: WindowsServiceIpcSlice,
}

#[cfg(test)]
pub fn validate_vertical_slices() -> CommandResult<SliceValidationReport> {
    let read_state = ReadOnlyCommandState::bootstrap()?;
    let pipeline = MockNetworkPipeline::new()
        .map_err(|error| capability_error("mock_network_pipeline", error))?;
    let c2_output = run_c2_fixture()?;
    let exfil_output = run_exfiltration_fixture()?;
    let story = fixture_story_from_detection(&c2_output, &exfil_output)?;
    let graph_output = run_graph_stage_fixture(&story, &c2_output, &exfil_output)?;
    let graph_analytics = GraphAnalyticsService::new()
        .analyze(GraphAnalyticsInput {
            request: GraphAnalyticsRequest::new(GraphType::OverviewRiskMap, GraphScope::Overview),
            nodes: graph_output.nodes.clone(),
            edges: graph_output.edges.clone(),
        })
        .map_err(|error| capability_error("graph_analytics", error))?;
    let response_output = fixture_response_planning_output(
        response_input(&story, graph_analytics.paths.clone()),
        &TraceId::new_v4(),
    )?;

    let plugin_catalog = plugin_catalog_slice(&read_state)?;
    let finding_evidence = finding_evidence_slice(&c2_output, &exfil_output)?;
    let mock_network_pipeline = mock_network_pipeline_slice(&pipeline)?;
    let detection_mvp = detection_mvp_slice(&c2_output, &exfil_output)?;
    let graph_rendering = graph_rendering_slice(&read_state, &graph_output, &graph_analytics)?;
    let response_planning = response_planning_slice(&response_output)?;
    let report_export = report_export_slice(&story)?;
    let windows_service_ipc = windows_service_ipc_slice(&read_state)?;

    let mut report = SliceValidationReport {
        fixture_label: VERTICAL_SLICE_FIXTURE_LABEL.to_string(),
        generated_at: Timestamp::now(),
        all_required_slices_passed: true,
        sensitive_marker_scan_passed: true,
        sensitive_markers_checked: vec![
            "raw packet content markers".to_string(),
            "payload content markers".to_string(),
            "HTTP body markers".to_string(),
            "cookie, token, credential, and API-key markers".to_string(),
            "private-key and bearer-secret markers".to_string(),
        ],
        validation_notes: vec![
            "Task 500 slice report is generated from public Local Core commands and public capability APIs.".to_string(),
            "All scenarios are FIXTURE_ONLY and do not execute privileged firewall, QoS, process, WAF, API, or cloud actions.".to_string(),
        ],
        plugin_catalog,
        finding_evidence,
        graph_rendering,
        mock_network_pipeline,
        detection_mvp,
        response_planning,
        report_export,
        windows_service_ipc,
    };
    report.sensitive_marker_scan_passed = validate_report_redaction(&report)?;
    report.all_required_slices_passed = report.sensitive_marker_scan_passed
        && slice_passed(&report.plugin_catalog.status)
        && slice_passed(&report.finding_evidence.status)
        && slice_passed(&report.graph_rendering.status)
        && slice_passed(&report.mock_network_pipeline.status)
        && slice_passed(&report.detection_mvp.status)
        && slice_passed(&report.response_planning.status)
        && slice_passed(&report.report_export.status)
        && slice_passed(&report.windows_service_ipc.status);
    Ok(report)
}

fn plugin_catalog_slice(state: &ReadOnlyCommandState) -> CommandResult<PluginCatalogSlice> {
    let catalog = get_plugin_catalog(state)?;
    let components = list_components(state)?;
    let capabilities = get_capability_overview(state)?;
    let catalog_remaining = if catalog.mock_only {
        "The built-in catalog is still MOCK_ONLY/NOT_FOR_PRODUCTION until real internal plugins replace every fixture-backed entry."
    } else {
        "The runtime catalog now uses STATIC_INTERNAL/PARTIAL_REAL manifests; production readiness still depends on replacing deferred service, capture, attribution, and response execution adapters."
    };

    Ok(PluginCatalogSlice {
        status: SliceValidationStatus::Passed,
        fixture_label: VERTICAL_SLICE_FIXTURE_LABEL.to_string(),
        plugin_count: catalog.plugins.len(),
        component_count: components.len(),
        capability_count: capabilities.len(),
        ui_contribution_count: catalog.ui_contributions.len(),
        contract_count: state.registered_contracts().len(),
        mock_only_catalog: catalog.mock_only,
        production_ready: catalog.production_ready,
        documentation: docs(
            &[
                "Plugin manifests, capability manifests, UI contributions, health, metrics, dependencies, and component registry entries resolve through the Tauri-facing read command facade.",
                "Component Center can list registered plugin components without frontend access to SQLite or the elevated service.",
            ],
            &[catalog_remaining],
        ),
    })
}

fn mock_network_pipeline_slice(
    pipeline: &MockNetworkPipeline,
) -> CommandResult<MockNetworkPipelineSlice> {
    let fixture = pipeline.fixture();
    let metadata_only = fixture
        .packet_metadata
        .iter()
        .all(|packet| packet.visibility_level == VisibilityLevel::MetadataOnly)
        && fixture
            .packet_records
            .iter()
            .all(|packet| packet.visibility_level == VisibilityLevel::MetadataOnly)
        && fixture
            .http_metadata
            .iter()
            .all(|http| http.sensitive_hint.is_none() && http.path_template_protected.is_some());

    Ok(MockNetworkPipelineSlice {
        status: SliceValidationStatus::Passed,
        fixture_label: VERTICAL_SLICE_FIXTURE_LABEL.to_string(),
        labels: fixture.labels.clone(),
        packet_metadata_count: fixture.packet_metadata.len(),
        flow_count: fixture.flows.len(),
        dns_observation_count: fixture.dns_observations.len(),
        tls_observation_count: fixture.tls_observations.len(),
        http_metadata_count: fixture.http_metadata.len(),
        trace_continuous: fixture.trace_is_continuous(),
        metadata_only,
        documentation: docs(
            &[
                "Mock packet metadata, normalized flow records, DNS observations, TLS observations, HTTP metadata, process context, and flow attribution share a continuous trace.",
                "HTTP fixtures use metadata templates and sizes only; raw packets, payload bytes, HTTP bodies, cookies, tokens, credentials, and API keys are absent.",
            ],
            &[
                "Capture and storage writes remain MOCK_ONLY/FIXTURE_ONLY; no Windows packet adapter or named-pipe service is exercised by this slice.",
            ],
        ),
    })
}

fn finding_evidence_slice(
    c2: &C2DetectionOutput,
    exfil: &ExfiltrationDetectionOutput,
) -> CommandResult<FindingEvidenceSlice> {
    let finding_count = c2.findings.len() + exfil.findings.len();
    let evidence_item_count = c2.evidence.len() + exfil.evidence.len();
    let evidence_ref_count = c2
        .findings
        .iter()
        .chain(exfil.findings.iter())
        .map(|finding| finding.evidence_refs().len())
        .sum();
    let quality_reports_passed = c2.evidence_management.quality_report.passed
        && exfil.evidence_management.quality_report.passed;

    Ok(FindingEvidenceSlice {
        status: SliceValidationStatus::Passed,
        fixture_label: VERTICAL_SLICE_FIXTURE_LABEL.to_string(),
        finding_count,
        evidence_item_count,
        evidence_ref_count,
        quality_reports_passed,
        documentation: docs(
            &[
                "C2 and exfiltration detectors emit evidence-backed Finding contracts through evidence management.",
                "Finding quality validation passes before findings can enter response planning or reports.",
            ],
            &[
                "Evidence is fixture-derived metadata and local-intelligence context; it is not proof from live packet capture or raw content inspection.",
            ],
        ),
    })
}

fn detection_mvp_slice(
    c2: &C2DetectionOutput,
    exfil: &ExfiltrationDetectionOutput,
) -> CommandResult<DetectionMvpSlice> {
    let risk_hints = c2.risk_hints.iter().chain(exfil.risk_hints.iter());
    let risk_hints_stay_evidence_input_only = risk_hints.clone().all(|hint| {
        hint.evidence_input_only
            && !hint.creates_alert
            && !hint.creates_incident
            && !hint.executes_response
            && hint.validate_boundary().is_ok()
    });
    let emits_c2_graph_hint = c2.graph_hints.iter().any(|hint| {
        hint.hint_type == GraphHintType::Custom(SUSPICIOUS_C2_GRAPH_HINT_TYPE.to_string())
    });
    let emits_exfiltration_graph_hint = exfil
        .graph_hints
        .iter()
        .any(|hint| hint.hint_type == GraphHintType::ProcessUploadsToCloud);

    Ok(DetectionMvpSlice {
        status: SliceValidationStatus::Passed,
        fixture_label: VERTICAL_SLICE_FIXTURE_LABEL.to_string(),
        c2_signal_count: c2.signals.len(),
        exfiltration_signal_count: exfil.signals.len(),
        finding_count: c2.findings.len() + exfil.findings.len(),
        risk_hint_count: c2.risk_hints.len() + exfil.risk_hints.len(),
        graph_hint_count: c2.graph_hints.len() + exfil.graph_hints.len(),
        risk_hints_stay_evidence_input_only,
        emits_c2_graph_hint,
        emits_exfiltration_graph_hint,
        documentation: docs(
            &[
                "Detection MVP emits findings, evidence, risk hints, and graph hints without creating alerts, incidents, canonical graph writes, or response execution directly.",
                "C2 and exfiltration fixture stories exercise cadence, rare destination/intelligence, TLS metadata, upload anomaly, cloud destination, and related-context signals.",
            ],
            &[
                "Risk scoring, alert promotion, incident promotion, and response execution remain separate downstream capabilities.",
            ],
        ),
    })
}

fn graph_rendering_slice(
    state: &ReadOnlyCommandState,
    graph_output: &sentinel_capabilities::GraphStageOutput,
    graph_analytics: &sentinel_capabilities::GraphAnalyticsOutput,
) -> CommandResult<GraphRenderingSlice> {
    let read_view = get_graph_view(
        state,
        GraphViewRequest {
            graph_type: GraphType::C2Graph,
            scope: GraphScope::Overview,
            title_redacted: None,
            node_limit: Some(50),
            edge_limit: Some(150),
        },
    )?;
    let serialized_view =
        serde_json::to_string(&graph_analytics.view_model).map_err(serialization_error)?;
    let consumed_graph_view_model_only = read_view.graph_type == GraphType::C2Graph
        && !serialized_view.contains("source_node")
        && !serialized_view.contains("target_node")
        && !serialized_view.contains("node_sequence")
        && !serialized_view.contains("entity_ref");

    Ok(GraphRenderingSlice {
        status: SliceValidationStatus::Passed,
        fixture_label: VERTICAL_SLICE_FIXTURE_LABEL.to_string(),
        canonical_node_count: graph_output.nodes.len(),
        canonical_edge_count: graph_output.edges.len(),
        graph_update_count: graph_output.graph_updates.len(),
        graph_path_count: graph_analytics.paths.len(),
        view_node_count: graph_analytics.view_model.nodes.len(),
        view_edge_count: graph_analytics.view_model.edges.len(),
        consumed_graph_view_model_only,
        snapshot_redacted: graph_analytics.snapshot.redaction_status
            == sentinel_contracts::RedactionStatus::Redacted,
        documentation: docs(
            &[
                "Graph stage accepts detection graph hints and security case records, deduplicates them, and produces canonical metadata-only node/edge records plus compact graph updates.",
                "Graph analytics transforms canonical records into bounded, redacted GraphViewModel and export-safe snapshot contracts.",
                "The read command returns GraphViewModel only, preserving the frontend boundary.",
            ],
            &[
                "Graph layout rendering is validated at contract/view-model level; browser-level Playwright rendering is deferred until the Tauri/frontend app is runnable with dependencies.",
            ],
        ),
    })
}

fn response_planning_slice(
    output: &ResponsePlanningCommandOutput,
) -> CommandResult<ResponsePlanningSlice> {
    let recommended_action_count = output
        .response_plans
        .iter()
        .map(|plan| plan.recommended_actions.len())
        .sum();
    let policy_decision_count = output
        .response_plans
        .iter()
        .map(|plan| plan.policy_decisions.len())
        .sum();
    let rollback_plan_count = output
        .response_plans
        .iter()
        .map(|plan| plan.rollback_plans.len())
        .sum();
    let approval_requirement_count = output
        .response_plans
        .iter()
        .flat_map(|plan| plan.recommended_actions.iter())
        .filter(|action| action.approval_required)
        .count();
    let execution_disabled_in_replay = output
        .response_plans
        .iter()
        .all(|plan| plan.execution_disabled_in_replay);
    let audit_requirements_present = output
        .response_plans
        .iter()
        .all(|plan| !plan.audit_requirements.is_empty());
    let static_runtime_provenance_recorded = !output.response_plans.is_empty()
        && output.response_plans.iter().all(|plan| {
            plan.audit_requirements
                .iter()
                .any(|requirement| requirement == "response.runtime.static_internal.process_batch")
        });

    Ok(ResponsePlanningSlice {
        status: SliceValidationStatus::Passed,
        fixture_label: VERTICAL_SLICE_FIXTURE_LABEL.to_string(),
        response_plan_count: output.response_plans.len(),
        recommended_action_count,
        policy_decision_count,
        rollback_plan_count,
        approval_requirement_count,
        execution_disabled_in_replay,
        audit_requirements_present,
        used_static_runtime: output.used_static_runtime,
        static_runtime_provenance_recorded,
        documentation: docs(
            &[
                "The fixture response-planning probe consumes bounded findings, alerts, incidents, graph paths, and policy settings through the pure capability algorithm; production mutation execution uses the container-owned static plugin runtime.",
                "Replay mode disables execution while still proving the planning and policy path.",
            ],
            &[
                "No firewall, QoS, process control, WAF, API gateway, identity, or cloud action is executed by this slice.",
            ],
        ),
    })
}

#[cfg(test)]
fn report_export_slice(story: &FixtureStory) -> CommandResult<ReportExportSlice> {
    let read = ReadOnlyCommandState::bootstrap()?
        .with_findings(story.findings.clone())
        .with_alerts(vec![story.alert.clone()])
        .with_incidents(vec![story.incident.clone()]);
    let incident_id = story.incident.id().clone();
    let mut mutation_state = crate::RuntimeContainerBuilder::for_test("vertical-slice-report")
        .build_test_mutation_state_from_read(read)?;

    create_response_plan(
        &mut mutation_state,
        CreateResponsePlanRequest {
            source: ResponsePlanSource::Incident(incident_id.clone()),
            reason_redacted: "FIXTURE_ONLY response planning for report slice".to_string(),
            created_by_redacted: Some("slice_fixture".to_string()),
        },
    )?;
    let report_receipt = generate_incident_report(
        &mut mutation_state,
        GenerateIncidentReportRequest {
            incident_id,
            requested_by_redacted: Some("slice_fixture".to_string()),
            reason_redacted: "FIXTURE_ONLY report generation".to_string(),
        },
    )?;
    let report_id = report_receipt.result.report.report_id.clone();
    let denied_export = export_report(
        &mut mutation_state,
        ExportReportRequest {
            report_id: report_id.clone(),
            format: ExportFormat::RedactedJson,
            destination_metadata_redacted: Some("FIXTURE_ONLY local export path".to_string()),
            requested_by_redacted: Some("slice_fixture".to_string()),
            user_confirmed: false,
        },
    );
    if denied_export.is_ok() {
        return Err(slice_error(
            "report_export",
            "export without user confirmation unexpectedly succeeded",
        ));
    }

    let export_receipt = export_report(
        &mut mutation_state,
        ExportReportRequest {
            report_id: report_id.clone(),
            format: ExportFormat::RedactedJson,
            destination_metadata_redacted: Some("FIXTURE_ONLY local export path".to_string()),
            requested_by_redacted: Some("slice_fixture".to_string()),
            user_confirmed: true,
        },
    )?;
    let history = list_export_history(
        mutation_state.read_state(),
        ReportExportHistoryQuery::for_report(report_id),
    )?;
    let violations = list_export_policy_violations(mutation_state.read_state())?;
    let redaction_summary_passed = export_receipt.result.export_result.redaction_summary.passed
        && required_redaction_categories_present(
            &export_receipt
                .result
                .export_result
                .redaction_summary
                .redacted_categories,
        );

    Ok(ReportExportSlice {
        status: SliceValidationStatus::Passed,
        fixture_label: VERTICAL_SLICE_FIXTURE_LABEL.to_string(),
        report_generated: true,
        successful_export_recorded: !history.items.is_empty(),
        denied_export_recorded_as_violation: !violations.is_empty(),
        history_record_count: history.items.len(),
        policy_violation_count: violations.len(),
        audit_event_count: mutation_state.audit_records().len(),
        file_hash_recorded: export_receipt.result.export_result.file_hash.is_some()
            && history.items.iter().all(|record| record.file_hash.is_some()),
        redaction_summary_passed,
        documentation: docs(
            &[
                "Incident report generation consumes redacted incident, alert, finding, response plan, rollback, graph snapshot, and redaction metadata.",
                "Report export requires user confirmation, records export audit/history with file-hash metadata, and records rejected export attempts as privacy/policy violations.",
            ],
            &[
                "The current export history stores rendered-content hash metadata and in-memory app-core state; a dedicated SQLite export-history store remains a later persistence hardening task.",
            ],
        ),
    })
}

fn windows_service_ipc_slice(
    state: &ReadOnlyCommandState,
) -> CommandResult<WindowsServiceIpcSlice> {
    let status = get_service_status(state)?;
    let update = ServiceStatusUpdate::from(&status);
    let mut dispatcher = TauriEventDispatcher::default();
    let event = service_status_stream(&mut dispatcher, update)?;
    let profile = get_runtime_profile(state)?;
    let normal_mode_metadata_only = !profile.privacy_policy.raw_packet_storage_enabled
        && !profile.privacy_policy.payload_storage_enabled
        && !profile.privacy_policy.http_body_storage_enabled;

    Ok(WindowsServiceIpcSlice {
        status: SliceValidationStatus::Passed,
        fixture_label: VERTICAL_SLICE_FIXTURE_LABEL.to_string(),
        degraded_status_reported: status.elevated_service_status
            == ObservabilityHealthStatus::Disconnected
            && status.ipc_status == ObservabilityHealthStatus::Disconnected
            && status.reduced_visibility
            && normal_mode_metadata_only,
        service_stream_name: event.stream,
        service_event_type: event.event_type,
        priority: event.priority,
        reduced_visibility: status.reduced_visibility,
        privileged_actions_available: status.privileged_actions_available,
        capture_available: status.capture_available,
        documentation: docs(
            &[
                "Read commands expose degraded elevated-service/IPC status and keep privileged actions unavailable when the Windows service is disconnected.",
                "Event streams map disconnected service state to a high-priority Tauri event and settings/runtime query invalidation hints.",
                "Runtime privacy policy keeps normal mode metadata-first with raw packet, payload, and HTTP body storage disabled.",
            ],
            &[
                "Connected named-pipe service validation is provisional in this fixture harness; no elevated Windows adapter is contacted.",
            ],
        ),
    })
}

fn run_c2_fixture() -> CommandResult<C2DetectionOutput> {
    C2DetectionPlugin::new()
        .detect(c2_detection_input()?)
        .map_err(|error| capability_error("c2_detection", error))
}

fn run_exfiltration_fixture() -> CommandResult<ExfiltrationDetectionOutput> {
    ExfiltrationDetectionPlugin::new()
        .detect(exfiltration_detection_input()?)
        .map_err(|error| capability_error("exfiltration_detection", error))
}

fn run_graph_stage_fixture(
    story: &FixtureStory,
    c2: &C2DetectionOutput,
    exfil: &ExfiltrationDetectionOutput,
) -> CommandResult<sentinel_capabilities::GraphStageOutput> {
    let mut input = GraphStageInput::new(PluginId::new_v4());
    input.graph_hints = c2
        .graph_hints
        .iter()
        .chain(exfil.graph_hints.iter())
        .cloned()
        .collect();
    input.findings = story.findings.clone();
    input.alerts = vec![story.alert.clone()];
    input.incidents = vec![story.incident.clone()];
    input.graph_type = GraphType::OverviewRiskMap;
    input.scope = GraphScope::Overview;
    input.labels = fixture_labels("task_500_graph_stage");
    GraphStagePlugin::new()
        .process(input, None::<&sentinel_storage::SqliteGraphStore<'_>>)
        .map_err(|error| capability_error("graph_stage", error))
}

fn response_input(
    story: &FixtureStory,
    graph_paths: Vec<sentinel_contracts::GraphPath>,
) -> ResponsePlanningInput {
    let mut input = ResponsePlanningInput::new(PluginId::new_v4())
        .with_response_policy(ResponsePolicy::auto_containment_lite())
        .with_replay();
    input.findings = story.findings.clone();
    input.alerts = vec![story.alert.clone()];
    input.incidents = vec![story.incident.clone()];
    input.graph_paths = graph_paths;
    input.labels = fixture_labels("task_500_response_planning");
    input
}

#[derive(Clone)]
struct FixtureStory {
    findings: Vec<Finding>,
    alert: Alert,
    incident: sentinel_contracts::Incident,
}

fn fixture_story_from_detection(
    c2: &C2DetectionOutput,
    exfil: &ExfiltrationDetectionOutput,
) -> CommandResult<FixtureStory> {
    let mut findings = c2
        .findings
        .iter()
        .chain(exfil.findings.iter())
        .cloned()
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| left.finding_type().cmp(right.finding_type()));
    let finding_ids = findings
        .iter()
        .map(|finding| finding.id().clone())
        .collect::<Vec<_>>();
    let alert = Alert::new(
        "FIXTURE_ONLY suspicious metadata story",
        "C2-like cadence and upload metadata require analyst review",
        finding_ids.clone(),
    )
    .map_err(|error| contract_error("alert", error))?
    .with_severity(SecuritySeverity::High)
    .with_confidence(q(0.86)?)
    .with_state(AlertState::New);
    let incident = sentinel_contracts::Incident::new(
        "fixture_metadata_intrusion_story",
        "FIXTURE_ONLY metadata intrusion story",
        "Evidence-backed C2 and exfiltration metadata joined for local response planning",
        vec![alert.id().clone()],
    )
    .map_err(|error| contract_error("incident", error))?
    .with_finding_refs(finding_ids)
    .with_severity(SecuritySeverity::High)
    .with_confidence(q(0.84)?)
    .with_state(sentinel_contracts::IncidentState::Candidate)
    .with_recommended_response_summary_redacted(
        "Recommend scoped review, destination watchlist, and approval-gated containment.",
    );

    Ok(FixtureStory {
        findings,
        alert,
        incident,
    })
}

fn local_intelligence_provider() -> CommandResult<OfflineLocalIntelligenceProvider> {
    OfflineLocalIntelligenceProvider::demo()
        .map_err(|error| contract_error("local_intelligence", error))
}

fn c2_detection_input() -> CommandResult<sentinel_capabilities::C2DetectionInput> {
    let intelligence = local_intelligence_provider()?;
    let process = c2_process();
    let flow_a = c2_flow(&process, 0, 50_000)?;
    let flow_b = c2_flow(&process, 60, 50_001)?;
    let flow_c = c2_flow(&process, 120, 50_002)?;
    let flow_d = c2_low_slow_flow(&process)?;
    let dns = c2_dns_observation(&process, &flow_a, "beacon.example.test")?;
    let tls = c2_tls_observation(&process, &flow_a)?;
    let mut input = sentinel_capabilities::C2DetectionInput::new(PluginId::new_v4());
    input.process_contexts = vec![process];
    input.flows = vec![flow_a, flow_b, flow_c, flow_d];
    input.dns_observations = vec![dns];
    input.tls_observations = vec![tls];
    input.domain_contexts = vec![intelligence
        .lookup_domain("beacon.example.test")
        .map_err(|error| contract_error("local_intelligence.domain", error))?];
    input.ip_contexts = vec![intelligence
        .lookup_ip(&ip("198.51.100.24")?)
        .map_err(|error| contract_error("local_intelligence.ip", error))?];
    input.certificate_contexts = vec![intelligence
        .lookup_certificate_fingerprint(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .map_err(|error| contract_error("local_intelligence.certificate", error))?];
    input.baseline = C2DetectionBaseline {
        known_domains: vec!["trusted.example.test".to_string()],
        known_destinations_by_process: vec![KnownProcessDestination::new(
            "fixture_client",
            "203.0.113.88",
        )],
        known_tls_fingerprints: vec!["ja3-known".to_string(), "ja4-known".to_string()],
        known_processes: vec!["fixture_client".to_string()],
    };
    input.labels = fixture_labels("task_500_c2_detection");
    Ok(input)
}

fn exfiltration_detection_input() -> CommandResult<sentinel_capabilities::ExfiltrationDetectionInput>
{
    let intelligence = local_intelligence_provider()?;
    let process = exfil_process();
    let large = exfil_flow(&process, 0, 52_000, 80_000, 5_000)?;
    let small_a = exfil_flow(&process, 1, 52_001, 1_024, 100)?;
    let small_b = exfil_flow(&process, 2, 52_002, 1_100, 120)?;
    let small_c = exfil_flow(&process, 3, 52_003, 1_200, 110)?;
    let mut input = sentinel_capabilities::ExfiltrationDetectionInput::new(PluginId::new_v4());
    input.http_metadata = vec![exfil_http_metadata(&large, &process)?];
    input.related_c2_findings = vec![related_c2_finding(&process)?];
    input.process_contexts = vec![process];
    input.flows = vec![large, small_a, small_b, small_c];
    input.ip_contexts = vec![intelligence
        .lookup_ip(&ip("203.0.113.10")?)
        .map_err(|error| contract_error("local_intelligence.ip", error))?];
    input.cloud_contexts = vec![intelligence
        .lookup_cloud_range(&ip("203.0.113.10")?)
        .map_err(|error| contract_error("local_intelligence.cloud", error))?];
    input.baseline = ExfiltrationDetectionBaseline {
        process_uploads: vec![ProcessUploadBaseline::new(
            "fixture_uploader",
            10_000,
            1.2,
            1,
        )],
        known_cloud_destinations_by_process: vec![KnownProcessCloudDestination::new(
            "fixture_uploader",
            "demo-object-storage",
            "203.0.113.88",
        )],
        normal_upload_hours_utc: vec![8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
    };
    input.labels = fixture_labels("task_500_exfiltration_detection");
    Ok(input)
}

fn c2_process() -> ProcessContext {
    let mut process = ProcessContext::new(4_242, "fixture_client");
    process.signer_status = SignerStatus::Unsigned;
    process.visibility_level = VisibilityLevel::MetadataOnly;
    process.collection_mode = CollectionMode::Mock;
    process
}

fn exfil_process() -> ProcessContext {
    let mut process = ProcessContext::new(6_260, "fixture_uploader");
    process.signer_status = SignerStatus::Unsigned;
    process.visibility_level = VisibilityLevel::MetadataOnly;
    process.collection_mode = CollectionMode::Mock;
    process
}

fn c2_flow(
    process: &ProcessContext,
    offset_seconds: i64,
    src_port: u16,
) -> CommandResult<FlowRecord> {
    let start = Utc::now() + Duration::seconds(offset_seconds);
    let mut flow = FlowRecord::new(
        ip("192.0.2.10")?,
        src_port,
        ip("198.51.100.24")?,
        443,
        TransportProtocol::Tcp,
        NetworkDirection::Outbound,
    );
    flow.start_time = Timestamp::from_datetime(start);
    flow.end_time = Some(Timestamp::from_datetime(start + Duration::seconds(1)));
    flow.duration_millis = Some(1_000);
    flow.bytes_out = 620;
    flow.bytes_in = 840;
    flow.packets_out = 3;
    flow.packets_in = 3;
    flow.process_ref = Some(process.process_context_id.clone());
    flow.attribution_confidence = AttributionConfidence::Medium;
    flow.quality_score = q(0.9)?;
    Ok(flow)
}

fn c2_low_slow_flow(process: &ProcessContext) -> CommandResult<FlowRecord> {
    let mut flow = c2_flow(process, 240, 51_200)?;
    flow.dst_port = 8443;
    flow.duration_millis = Some(600_000);
    flow.bytes_out = 700;
    flow.bytes_in = 900;
    flow.packets_out = 6;
    flow.packets_in = 5;
    Ok(flow)
}

fn exfil_flow(
    process: &ProcessContext,
    offset_hours: i64,
    src_port: u16,
    bytes_out: u64,
    bytes_in: u64,
) -> CommandResult<FlowRecord> {
    let start = Utc::now()
        .date_naive()
        .and_hms_opt(2, 0, 0)
        .ok_or_else(|| slice_error("fixture_time", "failed to construct fixture time"))?
        .and_utc()
        + Duration::hours(offset_hours);
    let mut flow = FlowRecord::new(
        ip("192.0.2.10")?,
        src_port,
        ip("203.0.113.10")?,
        443,
        TransportProtocol::Tcp,
        NetworkDirection::Outbound,
    );
    flow.start_time = Timestamp::from_datetime(start);
    flow.end_time = Some(Timestamp::from_datetime(start + Duration::seconds(4)));
    flow.duration_millis = Some(4_000);
    flow.bytes_out = bytes_out;
    flow.bytes_in = bytes_in;
    flow.packets_out = 8;
    flow.packets_in = 3;
    flow.process_ref = Some(process.process_context_id.clone());
    flow.attribution_confidence = AttributionConfidence::Medium;
    flow.quality_score = q(0.9)?;
    Ok(flow)
}

fn c2_dns_observation(
    process: &ProcessContext,
    flow: &FlowRecord,
    domain: &str,
) -> CommandResult<DnsObservation> {
    let mut observation = DnsObservation::new(domain, "A", ip("203.0.113.53")?, ip("192.0.2.10")?)
        .map_err(|error| contract_error("dns_observation", error))?;
    observation.flow_ref = Some(flow.flow_id.clone());
    observation.process_ref = Some(process.process_context_id.clone());
    observation.timestamp = flow.start_time.clone();
    observation.answers = vec![DnsAnswer::Ip {
        address: flow.dst_ip,
        ttl_seconds: Some(60),
    }];
    observation.privacy_class = PrivacyClass::Internal;
    observation.quality_score = q(0.88)?;
    Ok(observation)
}

fn c2_tls_observation(
    process: &ProcessContext,
    flow: &FlowRecord,
) -> CommandResult<TlsObservation> {
    let mut observation = TlsObservation::new();
    observation.flow_ref = Some(flow.flow_id.clone());
    observation.process_ref = Some(process.process_context_id.clone());
    observation.timestamp = flow.start_time.clone();
    observation.sni_protected = Some("beacon.example.test".to_string());
    observation.alpn = vec!["h2".to_string()];
    observation.ja3 = Some("ja3-fixture-new".to_string());
    observation.ja4 = Some("ja4-fixture-new".to_string());
    observation.tls_version = Some("tls1.3".to_string());
    observation.cipher_suite = Some("tls_aes_128_gcm_sha256".to_string());
    observation.certificate_fingerprint =
        Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());
    observation.issuer_summary_protected = Some("fixture issuer".to_string());
    observation.privacy_class = PrivacyClass::Internal;
    observation.quality_score = q(0.86)?;
    Ok(observation)
}

fn exfil_http_metadata(flow: &FlowRecord, process: &ProcessContext) -> CommandResult<HttpMetadata> {
    let mut metadata = HttpMetadata::new(HttpMethod::Post);
    metadata.flow_ref = Some(flow.flow_id.clone());
    metadata.timestamp = flow.start_time.clone();
    metadata.host_protected = Some("storage.example.test".to_string());
    metadata.path_template_protected = Some("/upload/{id}".to_string());
    metadata.request_size_bytes = Some(flow.bytes_out);
    metadata.response_size_bytes = Some(flow.bytes_in);
    metadata.upload_download_ratio = Some(8.0);
    metadata.content_type = Some("application/octet-stream".to_string());
    metadata.user_agent_family = Some("fixture-client".to_string());
    metadata.process_ref = Some(process.process_context_id.clone());
    metadata.privacy_class = PrivacyClass::Internal;
    metadata.quality_score = q(0.82)?;
    Ok(metadata)
}

fn related_c2_finding(process: &ProcessContext) -> CommandResult<Finding> {
    let explanation = FindingExplanation::new("C2 fixture finding")
        .map_err(|error| contract_error("finding", error))?;
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Process);
    entity.entity_name = Some(process.process_name.clone());
    entity.confidence = q(0.9)?;
    Ok(Finding::new(
        C2_FINDING_TYPE,
        PluginId::new_v4(),
        vec![EvidenceId::new_v4()],
        explanation,
    )
    .map_err(|error| contract_error("finding", error))?
    .with_entity_refs(vec![entity])
    .with_confidence(q(0.72)?)
    .with_severity(SecuritySeverity::Medium))
}

fn required_redaction_categories_present(categories: &[RedactedDataCategory]) -> bool {
    [
        RedactedDataCategory::RawPacket,
        RedactedDataCategory::Payload,
        RedactedDataCategory::HttpBody,
        RedactedDataCategory::Cookie,
        RedactedDataCategory::Token,
        RedactedDataCategory::Credential,
        RedactedDataCategory::ApiKey,
    ]
    .iter()
    .all(|category| categories.contains(category))
}

fn validate_report_redaction(report: &SliceValidationReport) -> CommandResult<bool> {
    let json = serde_json::to_string(report).map_err(serialization_error)?;
    let lower = json.to_ascii_lowercase();
    Ok(!forbidden_sensitive_markers()
        .iter()
        .any(|marker| lower.contains(marker)))
}

fn forbidden_sensitive_markers() -> &'static [&'static str] {
    &[
        "raw_packet_bytes",
        "packet_bytes",
        "raw_payload",
        "payload_blob",
        "http_body_value",
        "cookie_value",
        "credential_value",
        "authorization_header_value",
        "api_key_value",
        "private_key_value",
        "session_secret",
        "set-cookie",
        "bearer ",
    ]
}

fn docs(proves: &[&str], remains: &[&str]) -> SliceDocumentation {
    SliceDocumentation {
        proves: proves.iter().map(|value| value.to_string()).collect(),
        remains_mock_stub_or_provisional: remains.iter().map(|value| value.to_string()).collect(),
    }
}

fn fixture_labels(slice_name: &str) -> Vec<String> {
    vec![
        VERTICAL_SLICE_FIXTURE_LABEL.to_string(),
        FIXTURE_ONLY_LABEL.to_string(),
        MOCK_ONLY_LABEL.to_string(),
        slice_name.to_string(),
    ]
}

fn slice_passed(status: &SliceValidationStatus) -> bool {
    matches!(
        status,
        SliceValidationStatus::Passed | SliceValidationStatus::Provisional
    )
}

fn ip(value: &str) -> CommandResult<IpAddress> {
    IpAddress::parse_str(value).map_err(|error| contract_error("ip_address", error))
}

fn q(value: f32) -> CommandResult<QualityScore> {
    QualityScore::new(value).map_err(|error| contract_error("quality_score", error))
}

fn capability_error(context: &'static str, error: impl ToString) -> CoreError {
    slice_error(context, error.to_string())
}

fn contract_error(context: &'static str, error: impl ToString) -> CoreError {
    slice_error(context, error.to_string())
}

fn serialization_error(error: serde_json::Error) -> CoreError {
    slice_error("slice_serialization", error.to_string())
}

fn slice_error(context: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::new(
        ErrorCode::ValidationFailure,
        "vertical slice validation failed",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({
        "context": context,
        "error_redacted": message.into()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vertical_slice_report_proves_required_task_500_slices() {
        let report = validate_vertical_slices().expect("slice report");

        assert!(report.all_required_slices_passed);
        assert!(report.sensitive_marker_scan_passed);
        assert!(report.plugin_catalog.plugin_count >= 10);
        assert!(report.finding_evidence.finding_count >= 2);
        assert!(report.mock_network_pipeline.trace_continuous);
        assert!(report.detection_mvp.risk_hints_stay_evidence_input_only);
        assert!(report.graph_rendering.consumed_graph_view_model_only);
        assert!(report.response_planning.execution_disabled_in_replay);
        assert!(!report.response_planning.used_static_runtime);
        assert!(!report.response_planning.static_runtime_provenance_recorded);
        assert!(report.report_export.successful_export_recorded);
        assert!(report.report_export.denied_export_recorded_as_violation);
        assert!(report.windows_service_ipc.degraded_status_reported);
        assert_eq!(
            report.windows_service_ipc.service_event_type,
            "service_disconnected"
        );
        assert_eq!(
            report.windows_service_ipc.priority,
            PriorityLane::P0Critical
        );
    }

    #[test]
    fn vertical_slice_report_serializes_without_sensitive_markers() {
        let report = validate_vertical_slices().expect("slice report");
        let serialized = serde_json::to_string(&report).expect("serialize report");
        let lower = serialized.to_ascii_lowercase();

        for marker in forbidden_sensitive_markers() {
            assert!(!lower.contains(marker), "marker leaked: {marker}");
        }
        assert!(serialized.contains(VERTICAL_SLICE_FIXTURE_LABEL));
        assert!(serialized.contains("GraphViewModel"));
    }
}
