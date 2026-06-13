use crate::baseline_read_models::build_durable_baseline_summary;
use crate::evidence_quality::build_evidence_quality_summary;
use crate::investigation_drill_down::build_investigation_drill_down_summary;
use crate::mutation_commands::export_safe_graph_snapshot_from_view;
use crate::native_sampler_readiness::get_native_sampler_readiness_summary;
use crate::read_commands::{get_native_sampler_runtime_summary, ReadOnlyCommandState};
use sentinel_capabilities::{
    ExportFileHash, ReportGenerationError, ReportGraphSnapshotProvider, ReportGraphSnapshotSummary,
};
use sentinel_contracts::session_export::{
    ExportConfirmation, ExportHistoryEntry, ExportPreview, ExportRedactionSummary, ExportRequest,
    ExportResult, ExportSummary,
};
use sentinel_contracts::{
    CommandResult, CoreError, ErrorCode, ErrorSeverity, ExportResultId, GraphSnapshot,
    GraphViewModel, Timestamp, TraceId,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreparedExplicitExport {
    pub request: ExportRequest,
    pub preview: ExportPreview,
    pub content_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplicitExportArtifactIntegrity {
    pub file_hash: String,
    pub file_size_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExplicitExportCompletion {
    pub result: ExportResult,
    pub history_entry: ExportHistoryEntry,
    pub audit_event: Value,
}

pub fn explicit_export_artifact_integrity_from_bytes(
    artifact_bytes: &[u8],
) -> ExplicitExportArtifactIntegrity {
    ExplicitExportArtifactIntegrity {
        file_hash: ExportFileHash::from_bytes(artifact_bytes).value,
        file_size_bytes: artifact_bytes.len() as u64,
    }
}

pub fn prepare_explicit_export(
    state: &ReadOnlyCommandState,
    request: ExportRequest,
) -> CommandResult<PreparedExplicitExport> {
    if !request.user_initiated {
        return Err(policy_error(
            "explicit save/export requires a user gesture",
            json!({ "export_id": request.export_id.to_string() }),
        ));
    }
    if !request.redaction_options.strict {
        return Err(policy_error(
            "explicit save/export requires strict redaction",
            json!({ "export_id": request.export_id.to_string() }),
        ));
    }
    if request.format != request.action.expected_format() {
        return Err(validation_error(
            "explicit save/export action does not match format",
            json!({
                "export_id": request.export_id.to_string(),
                "export_type": request.action.export_type(),
                "format": request.format.extension()
            }),
        ));
    }

    let summary = export_summary_for_state(state);
    let redaction_summary = ExportRedactionSummary::strict_default();
    let content = redacted_export_content(state, &request, &summary, &redaction_summary)?;
    let content_redacted = serde_json::to_string_pretty(&content).map_err(|error| {
        validation_error(
            "explicit export serialization failed",
            json!({ "error_redacted": error.to_string() }),
        )
    })?;
    let preview = ExportPreview {
        export_id: request.export_id.clone(),
        summary,
        redaction_summary,
        estimated_size_bytes: content_redacted.len() as u64,
        destination_path: request.destination_path.clone(),
        format_contract: request.format.contract(),
        generated_at: Timestamp::now(),
    };

    Ok(PreparedExplicitExport {
        request,
        preview,
        content_redacted,
    })
}

pub fn finalize_explicit_export(
    prepared: &PreparedExplicitExport,
    confirmation: ExportConfirmation,
    destination_path_redacted: impl Into<String>,
    artifact_integrity: ExplicitExportArtifactIntegrity,
) -> CommandResult<ExplicitExportCompletion> {
    if confirmation.export_id != prepared.request.export_id {
        return Err(validation_error(
            "explicit export confirmation does not match preview",
            json!({
                "preview_export_id": prepared.request.export_id.to_string(),
                "confirmation_export_id": confirmation.export_id.to_string()
            }),
        ));
    }
    if !confirmation.user_confirmed {
        return Err(policy_error(
            "explicit export cancelled before file write",
            json!({
                "export_id": prepared.request.export_id.to_string(),
                "stage": "confirmation"
            }),
        ));
    }
    let Some(user_confirmed_at) = confirmation.confirmed_at.clone() else {
        return Err(validation_error(
            "explicit export confirmation timestamp is required",
            json!({ "export_id": prepared.request.export_id.to_string() }),
        ));
    };

    let destination_path = destination_path_redacted.into();
    let written_at = Timestamp::now();
    let result = ExportResult {
        export_result_id: ExportResultId::new_v4(),
        export_id: prepared.request.export_id.clone(),
        file_hash: artifact_integrity.file_hash.clone(),
        file_size_bytes: artifact_integrity.file_size_bytes,
        written_at: written_at.clone(),
        redaction_summary_applied: prepared.preview.redaction_summary.clone(),
        format: prepared.request.format.clone(),
        destination_path: destination_path.clone(),
    };
    let history_entry = ExportHistoryEntry {
        export_id: prepared.request.export_id.clone(),
        session_id: prepared.request.session_id.clone(),
        export_type: prepared.request.action.export_type().to_string(),
        format: prepared.request.format.clone(),
        destination_path: destination_path.clone(),
        file_hash: artifact_integrity.file_hash.clone(),
        file_size_bytes: artifact_integrity.file_size_bytes,
        redaction_summary: prepared.preview.redaction_summary.clone(),
        user_confirmed_at,
        exported_at: written_at,
    };
    let audit_event = json!({
        "event_type": "export_performed",
        "action": prepared.request.action.audit_action(),
        "actor": "user",
        "session_id": prepared.request.session_id.to_string(),
        "export_id": prepared.request.export_id.to_string(),
        "export_type": prepared.request.action.export_type(),
        "format": prepared.request.format.dotted_extension(),
        "destination_path": destination_path,
        "file_hash": artifact_integrity.file_hash,
        "file_size_bytes": artifact_integrity.file_size_bytes,
        "redaction_applied": true,
        "user_confirmed": true,
        "timestamp": Timestamp::now().to_string(),
    });

    Ok(ExplicitExportCompletion {
        result,
        history_entry,
        audit_event,
    })
}

pub fn explicit_export_cancelled_audit_event(
    prepared: &PreparedExplicitExport,
    stage: &'static str,
) -> Value {
    json!({
        "event_type": "export_cancelled",
        "action": "export_cancelled",
        "actor": "user",
        "session_id": prepared.request.session_id.to_string(),
        "export_id": prepared.request.export_id.to_string(),
        "export_type": prepared.request.action.export_type(),
        "format": prepared.request.format.dotted_extension(),
        "stage": stage,
        "redaction_applied": true,
        "user_confirmed": false,
        "timestamp": Timestamp::now().to_string(),
    })
}

fn export_summary_for_state(state: &ReadOnlyCommandState) -> ExportSummary {
    let graph_node_count = state
        .graph_views
        .iter()
        .map(|view| view.nodes.len() as u32)
        .sum();
    let graph_edge_count = state
        .graph_views
        .iter()
        .map(|view| view.edges.len() as u32)
        .sum();
    let baseline_summary = build_durable_baseline_summary(state).ok();
    let investigation = build_investigation_drill_down_summary(state).ok();
    let quality_summary = build_evidence_quality_summary(state).ok();
    let native_sampler_readiness = get_native_sampler_readiness_summary(state).ok();
    let native_sampler_runtime = get_native_sampler_runtime_summary(state).ok();
    ExportSummary {
        observation_count: saturating_u32(
            state.flows.items.len()
                + state.dns.items.len()
                + state.tls.items.len()
                + state.http_metadata.items.len(),
        ),
        finding_count: saturating_u32(state.findings.items.len()),
        alert_count: saturating_u32(state.alerts.items.len()),
        incident_count: saturating_u32(state.incidents.items.len()),
        imported_capture_source_count: saturating_u32(state.portable_capture_sources.len()),
        graph_node_count,
        graph_edge_count,
        response_recommendation_count: saturating_u32(state.response_plans.items.len()),
        report_count: saturating_u32(state.reports.items.len()),
        baseline_summary_count: baseline_summary
            .as_ref()
            .map(|summary| summary.baseline_count)
            .unwrap_or_default(),
        baseline_indicator_count: baseline_summary
            .as_ref()
            .map(|summary| summary.indicator_count)
            .unwrap_or_default(),
        incident_linked_group_count: baseline_summary
            .as_ref()
            .map(|summary| summary.incident_group_count)
            .unwrap_or_default(),
        incident_timeline_entry_count: baseline_summary
            .as_ref()
            .map(|summary| summary.timeline_entry_count)
            .unwrap_or_default(),
        hypothesis_explanation_count: investigation
            .as_ref()
            .map(|summary| summary.hypothesis_count)
            .unwrap_or_default(),
        baseline_drill_down_count: investigation
            .as_ref()
            .map(|summary| summary.baseline_count)
            .unwrap_or_default(),
        incident_group_detail_count: investigation
            .as_ref()
            .map(|summary| summary.incident_group_count)
            .unwrap_or_default(),
        timeline_drill_down_count: investigation
            .as_ref()
            .map(|summary| summary.timeline_count)
            .unwrap_or_default(),
        source_reliability_explanation_count: investigation
            .as_ref()
            .map(|summary| summary.source_reliability_count)
            .unwrap_or_default(),
        quality_record_count: quality_summary
            .as_ref()
            .map(|summary| summary.record_count)
            .unwrap_or_default(),
        report_suitable_quality_count: quality_summary
            .as_ref()
            .map(|summary| summary.report_suitable_count)
            .unwrap_or_default(),
        export_suitable_quality_count: quality_summary
            .as_ref()
            .map(|summary| summary.export_suitable_count)
            .unwrap_or_default(),
        blocked_quality_count: quality_summary
            .as_ref()
            .map(|summary| summary.blocked_count)
            .unwrap_or_default(),
        native_sampler_contract_count: native_sampler_readiness
            .as_ref()
            .map(|summary| summary.contract_count)
            .unwrap_or_default(),
        native_sampler_ready_count: native_sampler_readiness
            .as_ref()
            .map(|summary| summary.ready_when_implemented_count)
            .unwrap_or_default(),
        native_sampler_blocked_count: native_sampler_readiness
            .as_ref()
            .map(|summary| summary.blocked_count)
            .unwrap_or_default(),
        edr_active_sampler_count: native_sampler_readiness
            .as_ref()
            .map(|summary| summary.active_sampler_count)
            .unwrap_or_default(),
        native_sampler_runtime_count: native_sampler_runtime
            .as_ref()
            .map(|summary| summary.runtime_count)
            .unwrap_or_default(),
        native_sampler_runtime_active_count: native_sampler_runtime
            .as_ref()
            .map(|summary| summary.active_count)
            .unwrap_or_default(),
        native_sampler_runtime_batch_count: native_sampler_runtime
            .as_ref()
            .map(|summary| saturating_u32(summary.latest_batch_refs.len()))
            .unwrap_or_default(),
        native_sampler_runtime_fact_count: native_sampler_runtime
            .as_ref()
            .map(|summary| saturating_u32(summary.fact_refs.len()))
            .unwrap_or_default(),
        native_service_visibility_available: native_sampler_runtime
            .as_ref()
            .map(|summary| summary.service_visibility_available)
            .unwrap_or(false),
        native_health_visibility_available: native_sampler_runtime
            .as_ref()
            .map(|summary| summary.native_health_visibility_available)
            .unwrap_or(false),
        native_process_visibility_available: native_sampler_runtime
            .as_ref()
            .map(|summary| summary.process_visibility_available)
            .unwrap_or(false),
        included_sections: vec![
            "metadata_counts".to_string(),
            "redaction_manifest".to_string(),
            "evidence_backed_summaries".to_string(),
            "bounded_baseline_refs".to_string(),
            "bounded_investigation_drill_down_refs".to_string(),
            "bounded_quality_refs".to_string(),
            "bounded_native_sampler_readiness_refs".to_string(),
            "bounded_native_sampler_runtime_refs".to_string(),
        ],
        excluded_sections: vec![
            "raw_packets".to_string(),
            "payloads".to_string(),
            "http_bodies".to_string(),
            "cookies_tokens_credentials_api_keys".to_string(),
            "full_query_strings_form_content_unredacted_command_lines".to_string(),
        ],
    }
}

fn redacted_export_content(
    state: &ReadOnlyCommandState,
    request: &ExportRequest,
    summary: &ExportSummary,
    redaction_summary: &ExportRedactionSummary,
) -> CommandResult<Value> {
    let baseline_summary = build_durable_baseline_summary(state)?;
    let investigation = build_investigation_drill_down_summary(state)?;
    let quality_summary = build_evidence_quality_summary(state)?;
    let native_sampler_readiness = get_native_sampler_readiness_summary(state)?;
    let native_sampler_runtime = get_native_sampler_runtime_summary(state)?;
    let baseline_refs = json!({
        "baseline_refs": baseline_summary.baseline_refs,
        "indicator_refs": baseline_summary
            .indicators
            .iter()
            .map(|indicator| indicator.indicator_id.clone())
            .collect::<Vec<_>>(),
        "incident_group_refs": baseline_summary
            .incident_groups
            .iter()
            .map(|group| group.group_id.clone())
            .collect::<Vec<_>>(),
        "timeline_refs": baseline_summary
            .incident_timeline
            .iter()
            .map(|entry| entry.timeline_entry_id.clone())
            .collect::<Vec<_>>(),
        "source_reliability_refs": baseline_summary
            .source_reliability
            .iter()
            .map(|source| source.source_id.clone())
            .collect::<Vec<_>>(),
        "evidence_refs": baseline_summary.evidence_refs,
        "fact_refs": baseline_summary.fact_refs,
        "hypothesis_refs": baseline_summary.hypothesis_refs,
        "finding_refs": baseline_summary.finding_refs,
        "risk_refs": baseline_summary.risk_refs,
        "provenance_refs": baseline_summary.provenance_refs,
        "automatic_durable_persistence": false,
        "explicit_export_refs_only": true,
        "metadata_only": true
    });
    let investigation_refs = json!({
        "hypothesis_refs": investigation
            .hypotheses
            .iter()
            .map(|detail| detail.hypothesis_id.clone())
            .collect::<Vec<_>>(),
        "baseline_refs": investigation
            .baselines
            .iter()
            .map(|detail| detail.baseline_id.clone())
            .collect::<Vec<_>>(),
        "incident_group_refs": investigation
            .incident_groups
            .iter()
            .map(|detail| detail.group_id.clone())
            .collect::<Vec<_>>(),
        "timeline_refs": investigation
            .timeline
            .iter()
            .map(|detail| detail.timeline_entry_id.clone())
            .collect::<Vec<_>>(),
        "source_reliability_refs": investigation
            .source_reliability
            .iter()
            .map(|detail| detail.source_id.clone())
            .collect::<Vec<_>>(),
        "report_refs": investigation.report_refs,
        "export_refs": investigation.export_refs,
        "portable_no_retention": investigation.portable_no_retention,
        "metadata_only": investigation.metadata_only,
        "automatic_llm_calls": false,
        "response_execution": false
    });
    let quality_refs = json!({
        "quality_refs": quality_summary.quality_refs,
        "evidence_refs": quality_summary.evidence_refs,
        "finding_refs": quality_summary.finding_refs,
        "hypothesis_refs": quality_summary.hypothesis_refs,
        "risk_refs": quality_summary.risk_refs,
        "baseline_refs": quality_summary.baseline_refs,
        "incident_group_refs": quality_summary.incident_group_refs,
        "report_section_refs": quality_summary.report_section_refs,
        "export_result_refs": quality_summary.export_result_refs,
        "record_count": quality_summary.record_count,
        "weak_single_signal_count": quality_summary.weak_single_signal_count,
        "corroborated_count": quality_summary.corroborated_count,
        "report_suitable_count": quality_summary.report_suitable_count,
        "export_suitable_count": quality_summary.export_suitable_count,
        "blocked_count": quality_summary.blocked_count,
        "degraded_reason_summary": quality_summary.degraded_reason_summary,
        "missing_visibility_flags": quality_summary.missing_visibility_flags,
        "portable_no_retention": quality_summary.portable_no_retention,
        "metadata_only": quality_summary.metadata_only,
        "automatic_llm_calls": false,
        "response_execution": false,
        "bounded_refs_only": true
    });
    let native_sampler_readiness_refs = json!({
        "contract_count": native_sampler_readiness.contract_count,
        "review_count": native_sampler_readiness.review_count,
        "ready_when_implemented_count": native_sampler_readiness.ready_when_implemented_count,
        "blocked_count": native_sampler_readiness.blocked_count,
        "not_implemented_count": native_sampler_readiness.not_implemented_count,
        "active_sampler_count": native_sampler_readiness.active_sampler_count,
        "future_collection_allowed_count": native_sampler_readiness.future_collection_allowed_count,
        "future_response_allowed_count": native_sampler_readiness.future_response_allowed_count,
        "contract_refs": native_sampler_readiness.contract_refs,
        "review_refs": native_sampler_readiness.review_refs,
        "audit_refs": native_sampler_readiness.audit_refs,
        "missing_endpoint_visibility_flags": native_sampler_readiness.missing_endpoint_visibility_flags,
        "degraded_reasons": native_sampler_readiness.degraded_reasons,
        "portable_default_active": native_sampler_readiness.portable_default_active,
        "no_telemetry_collected": native_sampler_readiness.no_telemetry_collected,
        "endpoint_security_facts_emitted": native_sampler_readiness.endpoint_security_facts_emitted,
        "telemetry_collection_active": native_sampler_readiness.telemetry_collection_active,
        "response_execution_allowed": native_sampler_readiness.response_execution_allowed,
        "automatic_llm_calls": native_sampler_readiness.automatic_llm_calls,
        "edr_coverage_claimed": false,
        "bounded_refs_only": true
    });
    let native_sampler_runtime_refs = json!({
        "runtime_count": native_sampler_runtime.runtime_count,
        "active_count": native_sampler_runtime.active_count,
        "paused_count": native_sampler_runtime.paused_count,
        "degraded_count": native_sampler_runtime.degraded_count,
        "stopped_count": native_sampler_runtime.stopped_count,
        "revoked_count": native_sampler_runtime.revoked_count,
        "latest_batch_refs": native_sampler_runtime.latest_batch_refs,
        "fact_refs": native_sampler_runtime.fact_refs,
        "evidence_refs": native_sampler_runtime.evidence_refs,
        "audit_refs": native_sampler_runtime.audit_refs,
        "service_category_counts": native_sampler_runtime.service_category_counts,
        "service_state_counts": native_sampler_runtime.service_state_counts,
        "startup_type_counts": native_sampler_runtime.startup_type_counts,
        "process_category_counts": native_sampler_runtime.process_category_counts,
        "parent_process_category_counts": native_sampler_runtime.parent_process_category_counts,
        "process_relation_counts": native_sampler_runtime.process_relation_counts,
        "execution_context_counts": native_sampler_runtime.execution_context_counts,
        "process_trust_counts": native_sampler_runtime.process_trust_counts,
        "process_signedness_counts": native_sampler_runtime.process_signedness_counts,
        "process_privilege_counts": native_sampler_runtime.process_privilege_counts,
        "process_lifecycle_counts": native_sampler_runtime.process_lifecycle_counts,
        "quality_bucket": native_sampler_runtime.quality_bucket,
        "service_visibility_available": native_sampler_runtime.service_visibility_available,
        "native_health_visibility_available": native_sampler_runtime.native_health_visibility_available,
        "process_visibility_available": native_sampler_runtime.process_visibility_available,
        "parent_process_visibility_available": native_sampler_runtime.parent_process_visibility_available,
        "process_network_attribution_available": false,
        "packet_visibility_available": false,
        "response_execution_allowed": false,
        "edr_coverage_claimed": false,
        "automatic_llm_calls": false,
        "metadata_only": true,
        "bounded_refs_only": true,
        "category_only_process_telemetry": native_sampler_runtime.process_visibility_available,
        "specific_process_identity_unavailable": true,
        "no_process_network_attribution": true,
        "no_packet_capture": true,
        "no_service_installation": true,
        "no_host_mutation": true
    });
    let base = json!({
        "schema_version": 1,
        "format": request.format.dotted_extension(),
        "schema_name": request.format.schema_name(),
        "content_type": request.format.content_type(),
        "session_id": request.session_id.to_string(),
        "generated_at": Timestamp::now().to_string(),
        "redaction_summary": redaction_summary,
        "redaction_contract": request.format.contract(),
        "summary": summary,
    });

    let artifact = match &request.action {
        sentinel_contracts::session_export::SaveAction::SaveSession => json!({
            "artifact_type": "session_snapshot",
            "snapshot": base,
            "session_metadata": {
                "session_id": request.session_id.to_string(),
                "session_mode": "ephemeral_or_portable",
                "save_restore_status": "restore_deferred_future_task"
            },
            "portable_capture_sources": state.portable_capture_sources,
            "metadata_only_collections": {
                "observations": summary.observation_count,
                "findings": summary.finding_count,
                "alerts": summary.alert_count,
                "incidents": summary.incident_count,
                "imported_capture_sources": summary.imported_capture_source_count,
                "graph_nodes": summary.graph_node_count,
                "graph_edges": summary.graph_edge_count,
                "response_recommendations": summary.response_recommendation_count,
                "reports": summary.report_count,
                "baseline_summaries": summary.baseline_summary_count,
                "baseline_indicators": summary.baseline_indicator_count,
                "incident_linked_groups": summary.incident_linked_group_count,
                "incident_timeline_entries": summary.incident_timeline_entry_count,
                "hypothesis_explanations": summary.hypothesis_explanation_count,
                "baseline_drill_downs": summary.baseline_drill_down_count,
                "incident_group_details": summary.incident_group_detail_count,
                "timeline_drill_downs": summary.timeline_drill_down_count,
                "source_reliability_explanations": summary.source_reliability_explanation_count,
                "quality_records": summary.quality_record_count,
                "report_suitable_quality": summary.report_suitable_quality_count,
                "export_suitable_quality": summary.export_suitable_quality_count,
                "blocked_quality": summary.blocked_quality_count,
                "native_sampler_contracts": summary.native_sampler_contract_count,
                "native_sampler_ready": summary.native_sampler_ready_count,
                "native_sampler_blocked": summary.native_sampler_blocked_count,
                "edr_active_samplers": summary.edr_active_sampler_count,
                "native_sampler_runtime_count": summary.native_sampler_runtime_count,
                "native_sampler_runtime_active": summary.native_sampler_runtime_active_count,
                "native_sampler_runtime_batches": summary.native_sampler_runtime_batch_count,
                "native_sampler_runtime_facts": summary.native_sampler_runtime_fact_count,
                "native_service_visibility_available": summary.native_service_visibility_available,
                "native_health_visibility_available": summary.native_health_visibility_available,
                "native_process_visibility_available": summary.native_process_visibility_available
            },
            "baseline_refs": baseline_refs,
            "investigation_refs": investigation_refs,
            "quality_refs": quality_refs,
            "native_sampler_readiness_refs": native_sampler_readiness_refs,
            "native_sampler_runtime_refs": native_sampler_runtime_refs
        }),
        sentinel_contracts::session_export::SaveAction::ExportReport { incident_id } => {
            let reports = state
                .reports
                .items
                .iter()
                .filter(|report| report.incident_refs.iter().any(|id| id == incident_id))
                .map(|report| {
                    json!({
                        "report_id": report.report_id.to_string(),
                        "report_type": report.report_type.clone(),
                        "title_redacted": report.title_redacted.clone(),
                        "summary_redacted": report.summary_redacted.clone(),
                        "section_count": report.sections.len(),
                        "redaction_passed": report.redaction_summary.passed
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "artifact_type": "incident_report",
                "report_type": "redacted_incident_report",
                "incident_id": incident_id.to_string(),
                "report": base,
                "reports": reports,
                "baseline_refs": baseline_refs,
                "investigation_refs": investigation_refs,
                "quality_refs": quality_refs,
                "native_sampler_readiness_refs": native_sampler_readiness_refs,
                "native_sampler_runtime_refs": native_sampler_runtime_refs,
                "graph_path_summary": "redacted graph path summary; full topology excluded from .sgreport",
                "response_recommendations_only": true
            })
        }
        sentinel_contracts::session_export::SaveAction::ExportGraph => {
            let graph = export_graph_snapshot(state)?;
            json!({
                "artifact_type": "export_safe_graph_snapshot",
                "snapshot": base,
                "graph_snapshot": graph.snapshot,
                "graph_export_summary": graph.summary,
                "source_graph_view_id": graph.source_graph_view_id,
                "baseline_refs": baseline_refs,
                "investigation_refs": investigation_refs,
                "quality_refs": quality_refs,
                "native_sampler_readiness_refs": native_sampler_readiness_refs,
                "native_sampler_runtime_refs": native_sampler_runtime_refs,
                "canonical_graph_internals_included": false
            })
        }
    };

    Ok(artifact)
}

#[derive(Clone, Debug)]
struct ExportGraphSnapshotArtifact {
    snapshot: GraphSnapshot,
    summary: ReportGraphSnapshotSummary,
    source_graph_view_id: String,
}

fn export_graph_snapshot(
    state: &ReadOnlyCommandState,
) -> CommandResult<ExportGraphSnapshotArtifact> {
    let view = state
        .graph_views
        .iter()
        .find(|view| !view.nodes.is_empty() || !view.edges.is_empty() || !view.paths.is_empty())
        .ok_or_else(|| {
            validation_error(
                "explicit graph export requires an available GraphViewModel",
                json!({
                    "graph_view_count": state.graph_views.len(),
                    "required": "non_empty_graph_view"
                }),
            )
        })?;

    let snapshot = export_safe_graph_snapshot_from_view(
        view,
        view.filters.scope.clone(),
        &[],
        "explicit graph export uses redacted GraphViewModel data only",
    )?
    .ok_or_else(|| evidence_required_error(view))?;

    let export_safe = ReportGraphSnapshotProvider::with_bounds(view.node_limit, view.edge_limit)
        .prepare_export_safe(&snapshot)
        .map_err(graph_snapshot_export_error)?;

    Ok(ExportGraphSnapshotArtifact {
        snapshot: export_safe.snapshot,
        summary: export_safe.summary,
        source_graph_view_id: view.graph_id.to_string(),
    })
}

fn evidence_required_error(view: &GraphViewModel) -> CoreError {
    policy_error(
        "explicit graph export requires evidence-backed graph references",
        json!({
            "graph_id": view.graph_id.to_string(),
            "graph_type": format!("{:?}", view.graph_type),
            "reason_redacted": "no evidence refs in nodes, edges, or paths"
        }),
    )
}

fn graph_snapshot_export_error(error: ReportGenerationError) -> CoreError {
    let error_code = if error.is_policy_or_privacy_denial() {
        ErrorCode::PrivacyPolicyViolation
    } else {
        ErrorCode::ValidationFailure
    };
    CoreError::new(
        error_code,
        "explicit graph export rejected unsafe graph snapshot",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn saturating_u32(value: usize) -> u32 {
    value.try_into().unwrap_or(u32::MAX)
}

fn validation_error(message: impl Into<String>, details: Value) -> CoreError {
    CoreError::new(ErrorCode::ValidationFailure, message)
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(details)
}

fn policy_error(message: impl Into<String>, details: Value) -> CoreError {
    CoreError::new(ErrorCode::PolicyDenial, message)
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(details)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::session_export::{ExportConfirmation, SaveAction};
    use sentinel_contracts::{
        EvidenceId, GraphEdgeType, GraphEdgeViewModel, GraphNodeType, GraphNodeViewModel,
        GraphPathId, GraphPathSummary, GraphPathType, GraphRedactionSummary, GraphScope, GraphType,
        GraphViewModel, PrivacyClass, QualityScore, RedactedLabel, RedactionStatus, SessionId,
    };

    #[test]
    fn explicit_export_preview_builds_redacted_graph_snapshot_without_writing() {
        let state = graph_export_state();
        let request = ExportRequest::new(
            SessionId::new_v4(),
            SaveAction::ExportGraph,
            "graph.sggraph",
            "local_user",
        )
        .expect("request");

        let prepared = prepare_explicit_export(&state, request).expect("preview");

        assert_eq!(prepared.preview.format_contract.extension, ".sggraph");
        assert!(prepared.preview.redaction_summary.passed);
        assert!(prepared
            .content_redacted
            .contains("export_safe_graph_snapshot"));
        assert!(prepared.content_redacted.contains("\"graph_snapshot\""));
        assert!(prepared
            .content_redacted
            .contains("\"graph_export_summary\""));
        assert!(prepared.content_redacted.contains("\"time_bounds\""));
        assert!(prepared.content_redacted.contains("\"evidence_refs\""));
        assert!(prepared
            .content_redacted
            .contains("\"canonical_graph_internals_included\": false"));
        assert!(!prepared.content_redacted.contains("\"source_node\""));
        assert!(!prepared.content_redacted.contains("\"target_node\""));
        assert!(!prepared.content_redacted.contains("\"entity_ref\""));
        assert!(!prepared.content_redacted.contains("\"entity_id\""));
        assert!(!prepared.content_redacted.contains("\"finding_id\""));
        assert!(!prepared.content_redacted.contains("\"alert_id\""));
        assert!(!prepared.content_redacted.contains("\"incident_id\""));
        assert!(!prepared.content_redacted.contains("\"custom_ref\""));
        assert!(!prepared
            .content_redacted
            .contains("session_token destination"));
        assert!(!prepared.content_redacted.contains("authorization:"));
    }

    #[test]
    fn explicit_export_rejects_missing_graph_view() {
        let state = ReadOnlyCommandState::bootstrap().expect("state");
        let request = ExportRequest::new(
            SessionId::new_v4(),
            SaveAction::ExportGraph,
            "graph.sggraph",
            "local_user",
        )
        .expect("request");

        let error = prepare_explicit_export(&state, request).expect_err("missing graph rejected");

        assert_eq!(error.error_code, ErrorCode::ValidationFailure);
        assert!(error.message.contains("GraphViewModel"));
    }

    #[test]
    fn explicit_export_rejects_evidence_free_snapshot() {
        let state = graph_export_state_with(|view| {
            for node in &mut view.nodes {
                node.detail_ref.evidence_refs.clear();
            }
            for edge in &mut view.edges {
                edge.evidence_refs.clear();
            }
            for path in &mut view.paths {
                path.evidence_refs.clear();
            }
        });
        let request = ExportRequest::new(
            SessionId::new_v4(),
            SaveAction::ExportGraph,
            "graph.sggraph",
            "local_user",
        )
        .expect("request");

        let error = prepare_explicit_export(&state, request).expect_err("evidence rejected");

        assert_eq!(error.error_code, ErrorCode::PolicyDenial);
        assert!(error.message.contains("evidence-backed"));
    }

    #[test]
    fn explicit_export_rejects_unredacted_snapshot_status() {
        let state = graph_export_state_with(|view| {
            view.redaction_status = RedactionStatus::NotRequired;
            view.redaction_summary.status = RedactionStatus::NotRequired;
        });
        let request = ExportRequest::new(
            SessionId::new_v4(),
            SaveAction::ExportGraph,
            "graph.sggraph",
            "local_user",
        )
        .expect("request");

        let error = prepare_explicit_export(&state, request).expect_err("redaction rejected");

        assert_eq!(error.error_code, ErrorCode::PrivacyPolicyViolation);
        assert!(error.details_redacted.expect("details")["error_redacted"]
            .as_str()
            .expect("error text")
            .contains("redaction"));
    }

    #[test]
    fn explicit_export_rejects_sensitive_graph_snapshot_text() {
        let state = graph_export_state_with(|view| {
            view.nodes[0].label = RedactedLabel::redacted(
                "authorization: bearer session_token destination",
                PrivacyClass::Sensitive,
            )
            .expect("representable unsafe label");
        });
        let request = ExportRequest::new(
            SessionId::new_v4(),
            SaveAction::ExportGraph,
            "graph.sggraph",
            "local_user",
        )
        .expect("request");

        let error = prepare_explicit_export(&state, request).expect_err("privacy marker rejected");

        assert_eq!(error.error_code, ErrorCode::PrivacyPolicyViolation);
        assert!(error.details_redacted.expect("details")["error_redacted"]
            .as_str()
            .expect("error text")
            .contains("forbidden sensitive marker"));
    }

    #[test]
    fn explicit_export_strips_internal_detail_refs_from_view_models() {
        let state = graph_export_state_with(|view| {
            view.nodes[0].detail_ref.entity_id = Some(sentinel_contracts::EntityId::new_v4());
            view.nodes[0].detail_ref.custom_ref = Some("redacted-internal-ref".to_string());
        });
        let request = ExportRequest::new(
            SessionId::new_v4(),
            SaveAction::ExportGraph,
            "graph.sggraph",
            "local_user",
        )
        .expect("request");

        let prepared = prepare_explicit_export(&state, request).expect("preview");

        assert!(!prepared.content_redacted.contains("\"entity_id\""));
        assert!(!prepared.content_redacted.contains("\"custom_ref\""));
    }

    #[test]
    fn explicit_export_finalize_requires_matching_confirmation() {
        let state = ReadOnlyCommandState::bootstrap().expect("state");
        let request = ExportRequest::new(
            SessionId::new_v4(),
            SaveAction::SaveSession,
            "session.sgsession",
            "local_user",
        )
        .expect("request");
        let prepared = prepare_explicit_export(&state, request).expect("preview");
        let artifact_integrity =
            explicit_export_artifact_integrity_from_bytes(prepared.content_redacted.as_bytes());

        let cancelled = finalize_explicit_export(
            &prepared,
            ExportConfirmation::cancelled(prepared.request.export_id.clone()),
            "[export-dir]",
            artifact_integrity.clone(),
        )
        .expect_err("cancelled export is denied before write");
        assert_eq!(cancelled.error_code, ErrorCode::PolicyDenial);

        let confirmed = finalize_explicit_export(
            &prepared,
            ExportConfirmation::confirmed(prepared.request.export_id.clone()),
            "[export-dir]",
            artifact_integrity.clone(),
        )
        .expect("confirmed export");
        assert_eq!(confirmed.result.format, prepared.request.format);
        assert_eq!(
            confirmed.history_entry.export_id,
            prepared.request.export_id
        );
        assert_eq!(confirmed.result.file_hash, artifact_integrity.file_hash);
        assert_eq!(
            confirmed.result.file_size_bytes,
            artifact_integrity.file_size_bytes
        );
        assert!(confirmed.audit_event["redaction_applied"]
            .as_bool()
            .unwrap());
        assert!(confirmed.audit_event["user_confirmed"].as_bool().unwrap());
    }

    fn graph_export_state() -> ReadOnlyCommandState {
        graph_export_state_with(|_| {})
    }

    fn graph_export_state_with(
        mut mutate: impl FnMut(&mut GraphViewModel),
    ) -> ReadOnlyCommandState {
        let mut view = graph_view();
        mutate(&mut view);
        ReadOnlyCommandState::bootstrap()
            .expect("state")
            .with_graph_views(vec![view])
    }

    fn graph_view() -> GraphViewModel {
        let evidence_id = EvidenceId::new_v4();
        let mut process = GraphNodeViewModel::new(
            GraphNodeType::Process,
            RedactedLabel::redacted("process", PrivacyClass::Internal).expect("label"),
        );
        process.risk_score = QualityScore::new(0.74).expect("quality");
        process.detail_ref.evidence_refs = vec![evidence_id.clone()];

        let mut incident = GraphNodeViewModel::new(
            GraphNodeType::Incident,
            RedactedLabel::redacted("incident", PrivacyClass::Internal).expect("label"),
        );
        incident.risk_score = QualityScore::new(0.88).expect("quality");
        incident.detail_ref.evidence_refs = vec![evidence_id.clone()];

        let mut edge = GraphEdgeViewModel::new(
            GraphEdgeType::ObservationSupportsFinding,
            process.node_id.clone(),
            incident.node_id.clone(),
        );
        edge.label = Some(
            RedactedLabel::redacted("evidence-backed link", PrivacyClass::Internal).expect("label"),
        );
        edge.confidence = QualityScore::new(0.86).expect("quality");
        edge.evidence_refs = vec![evidence_id.clone()];

        let mut view = GraphViewModel::new(
            GraphType::IncidentGraph,
            RedactedLabel::redacted("incident graph", PrivacyClass::Internal).expect("title"),
            GraphScope::Overview,
        );
        view.nodes = vec![process, incident];
        view.edges = vec![edge];
        view.paths = vec![GraphPathSummary {
            path_id: GraphPathId::new_v4(),
            path_type: GraphPathType::IncidentSummaryPath,
            label: RedactedLabel::redacted("incident summary path", PrivacyClass::Internal)
                .expect("path label"),
            risk_score: QualityScore::new(0.88).expect("quality"),
            confidence: QualityScore::new(0.86).expect("quality"),
            evidence_refs: vec![evidence_id],
        }];
        view.redaction_status = RedactionStatus::Redacted;
        view.redaction_summary = GraphRedactionSummary {
            status: RedactionStatus::Redacted,
            redacted_node_count: view.nodes.len() as u32,
            redacted_edge_count: view.edges.len() as u32,
            hidden_label_count: (view.nodes.len() + view.edges.len()) as u32,
            notes: vec!["test GraphViewModel is redacted before export".to_string()],
        };
        view.original_node_count = view.nodes.len() as u32;
        view.original_edge_count = view.edges.len() as u32;
        view
    }
}
