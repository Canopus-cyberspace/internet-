use crate::baseline_read_models::build_durable_baseline_summary;
use crate::evidence_quality::build_evidence_quality_summary;
use crate::investigation_drill_down::build_investigation_drill_down_summary;
use crate::read_commands::{get_attack_coverage_summary, ReadOnlyCommandState};
use sentinel_contracts::{
    CommandResult, CoreError, ErrorCode, ErrorSeverity, EvidenceQualityRecord,
    EvidenceQualitySummary, InvestigationDrillDownSummary, NavigationBreadcrumb,
    NavigationReference, NavigationResolution, NavigationResolutionStatus,
    NavigationResolveRequest, NavigationTargetKind, NavigationTargetSummary, NavigationViewKind,
    RedactionStatus, MAX_NAVIGATION_REFS,
};
use serde_json::json;

pub fn resolve_bounded_reference(
    state: &ReadOnlyCommandState,
    request: NavigationResolveRequest,
) -> CommandResult<NavigationResolution> {
    request.validate().map_err(navigation_validation_error)?;
    enforce_session_scope(state, &request)?;

    let drill_down = build_investigation_drill_down_summary(state)?;
    let quality_summary = build_evidence_quality_summary(state)?;
    let mut target = empty_target(&request);
    resolve_direct_target(state, &drill_down, &quality_summary, &mut target)?;
    add_reverse_links(&drill_down, &mut target);
    add_quality_context(&quality_summary, &mut target);
    let reverse_seeds = target
        .evidence_refs
        .iter()
        .chain(target.finding_refs.iter())
        .chain(target.risk_refs.iter())
        .chain(target.attack_refs.iter())
        .chain(target.graph_refs.iter())
        .take(MAX_NAVIGATION_REFS)
        .cloned()
        .collect::<Vec<_>>();
    for seed in reverse_seeds {
        add_reverse_links_for_id(&drill_down, &seed, &mut target);
    }
    normalize_target(&mut target);

    let mut outgoing_refs = outgoing_references(&request, &target);
    add_derived_references(
        &request,
        &drill_down,
        &quality_summary,
        &target,
        &mut outgoing_refs,
    );
    let breadcrumb = NavigationBreadcrumb {
        view_kind: target_view(&target.target_kind),
        target_kind: target.target_kind.clone(),
        target_id: target.target_id.clone(),
        display_label_category: target.category.clone(),
        time_bucket: target.created_time_bucket.clone(),
        confidence_bucket: target.confidence_bucket.clone(),
        degraded_reason: target.degraded_reason.clone(),
        redaction_status: target.redaction_status.clone(),
    };
    let resolution = NavigationResolution {
        session_id: state.service_status.active_session_id.clone(),
        status: target.status.clone(),
        breadcrumb,
        target,
        outgoing_refs,
        portable_no_retention: true,
        automatic_llm_calls: false,
        response_execution: false,
    };
    resolution.validate().map_err(navigation_validation_error)?;
    Ok(resolution)
}

fn enforce_session_scope(
    state: &ReadOnlyCommandState,
    request: &NavigationResolveRequest,
) -> CommandResult<()> {
    if request.session_id != state.service_status.active_session_id {
        return Err(CoreError::new(
            ErrorCode::PermissionDenied,
            "navigation reference is outside the active session",
        )
        .with_severity(ErrorSeverity::Warning)
        .with_redacted_details(json!({
            "reason_redacted": "session_scope_mismatch",
            "target_kind": request.target_kind,
        })));
    }
    Ok(())
}

fn empty_target(request: &NavigationResolveRequest) -> NavigationTargetSummary {
    NavigationTargetSummary {
        target_kind: request.target_kind.clone(),
        target_id: request.target_id.clone(),
        status: NavigationResolutionStatus::Missing,
        category: kind_label(&request.target_kind),
        severity_risk_bucket: None,
        confidence_bucket: None,
        evidence_quality_bucket: None,
        evidence_refs: Vec::new(),
        fact_refs: Vec::new(),
        hypothesis_refs: Vec::new(),
        finding_refs: Vec::new(),
        risk_refs: Vec::new(),
        baseline_refs: Vec::new(),
        incident_group_refs: Vec::new(),
        timeline_refs: Vec::new(),
        attack_refs: Vec::new(),
        graph_refs: Vec::new(),
        report_refs: Vec::new(),
        export_refs: Vec::new(),
        story_refs: Vec::new(),
        quality_refs: Vec::new(),
        provenance_refs: Vec::new(),
        redacted_summary: "Bounded reference is unavailable in the active session".to_string(),
        created_time_bucket: None,
        degraded_reason: Some("reference_unavailable".to_string()),
        missing_visibility_flags: vec!["reference_not_present_in_active_session".to_string()],
        redaction_status: RedactionStatus::Redacted,
        metadata_only: true,
        session_scoped: true,
        automatic_llm_calls: false,
        response_execution: false,
    }
}

fn resolve_direct_target(
    state: &ReadOnlyCommandState,
    drill_down: &InvestigationDrillDownSummary,
    quality_summary: &EvidenceQualitySummary,
    target: &mut NavigationTargetSummary,
) -> CommandResult<()> {
    match target.target_kind {
        NavigationTargetKind::Hypothesis => {
            if let Some(detail) = drill_down
                .hypotheses
                .iter()
                .find(|detail| detail.hypothesis_id.to_string() == target.target_id)
            {
                mark_resolved(target, "hypothesis", &detail.summary_redacted);
                target.confidence_bucket = Some(debug_slug(&detail.confidence_bucket));
                target.evidence_refs = strings(&detail.evidence_refs);
                target.fact_refs = strings(&detail.fact_refs);
                target.finding_refs = strings(&detail.finding_refs);
                target.risk_refs = strings(&detail.risk_refs);
                target.baseline_refs = strings(&detail.baseline_refs);
                target.attack_refs = attack_strings(&detail.attack_refs);
                target.graph_refs = strings(&detail.graph_refs);
                target.report_refs = strings(&detail.report_refs);
                target.export_refs = strings(&detail.export_refs);
                target.story_refs = strings(&detail.story_availability.story_refs);
                target.degraded_reason = detail.degraded_reason.clone();
                target.missing_visibility_flags = detail.missing_visibility_flags.clone();
            }
        }
        NavigationTargetKind::Baseline => {
            if let Some(detail) = drill_down
                .baselines
                .iter()
                .find(|detail| detail.baseline_id.to_string() == target.target_id)
            {
                mark_resolved(target, "baseline", &detail.summary_redacted);
                target.confidence_bucket = Some(debug_slug(&detail.confidence_bucket));
                target.evidence_refs = strings(&detail.evidence_refs);
                target.fact_refs = strings(&detail.fact_refs);
                target.hypothesis_refs = strings(&detail.hypothesis_refs);
                target.evidence_refs = strings(&detail.evidence_refs);
                target.finding_refs = strings(&detail.finding_refs);
                target.risk_refs = strings(&detail.risk_refs);
                target.incident_group_refs = strings(&detail.incident_group_refs);
                target.attack_refs = attack_strings(&detail.attack_refs);
                target.report_refs = strings(&detail.report_refs);
                target.export_refs = strings(&detail.export_refs);
                target.provenance_refs = strings(&detail.provenance_refs);
                target.degraded_reason = detail.degraded_reason.clone();
                target.missing_visibility_flags = detail.missing_visibility_flags.clone();
            }
        }
        NavigationTargetKind::BaselineIndicator => {
            let baseline = build_durable_baseline_summary(state)?;
            if let Some(indicator) = baseline
                .indicators
                .iter()
                .find(|indicator| indicator.indicator_id.to_string() == target.target_id)
            {
                mark_resolved(target, "baseline_indicator", &indicator.summary_redacted);
                target.confidence_bucket = Some(debug_slug(&indicator.confidence_bucket));
                target.evidence_refs = strings(&indicator.evidence_refs);
                target.fact_refs = strings(&indicator.fact_refs);
                target.hypothesis_refs = strings(&indicator.hypothesis_refs);
                target.baseline_refs = strings(&indicator.baseline_refs);
                target.degraded_reason = indicator.degraded_reason.clone();
                target.missing_visibility_flags = indicator.missing_visibility_flags.clone();
            }
        }
        NavigationTargetKind::IncidentLinkedGroup => {
            if let Some(detail) = drill_down
                .incident_groups
                .iter()
                .find(|detail| detail.group_id.to_string() == target.target_id)
            {
                mark_resolved(target, "incident_linked_group", &detail.summary_redacted);
                target.evidence_refs = strings(&detail.evidence_refs);
                target.fact_refs = strings(&detail.fact_refs);
                target.hypothesis_refs = strings(&detail.hypothesis_refs);
                target.finding_refs = strings(&detail.finding_refs);
                target.risk_refs = strings(&detail.risk_refs);
                target.baseline_refs = strings(&detail.baseline_refs);
                target.timeline_refs = strings(&detail.timeline_refs);
                target.attack_refs = attack_strings(&detail.attack_refs);
                target.graph_refs = strings(&detail.graph_refs);
                target.report_refs = strings(&detail.report_refs);
                target.export_refs = strings(&detail.export_refs);
                target.story_refs = strings(&detail.story_availability.story_refs);
                target.created_time_bucket = detail.last_updated_bucket.clone();
                target.degraded_reason = detail.degraded_reason.clone();
                target.missing_visibility_flags = detail.missing_visibility_flags.clone();
            }
        }
        NavigationTargetKind::TimelineEntry => {
            if let Some(detail) = drill_down
                .timeline
                .iter()
                .find(|detail| detail.timeline_entry_id.to_string() == target.target_id)
            {
                mark_resolved(target, "timeline_entry", &detail.summary_redacted);
                target.category = detail.event_category.clone();
                target.confidence_bucket = Some(debug_slug(&detail.confidence_bucket));
                target.hypothesis_refs = strings(&detail.hypothesis_refs);
                target.finding_refs = strings(&detail.finding_refs);
                target.risk_refs = strings(&detail.risk_refs);
                target.baseline_refs = strings(&detail.baseline_refs);
                target.incident_group_refs = vec![detail.group_id.to_string()];
                target.attack_refs = attack_strings(&detail.attack_refs);
                target.report_refs = strings(&detail.report_refs);
                target.created_time_bucket = Some(detail.time_bucket.clone());
                target.degraded_reason = detail.degraded_reason.clone();
            }
        }
        NavigationTargetKind::SourceReliabilitySummary => {
            if let Some(detail) = drill_down
                .source_reliability
                .iter()
                .find(|detail| detail.source_id.to_string() == target.target_id)
            {
                mark_resolved(
                    target,
                    "source_reliability_summary",
                    &detail.summary_redacted,
                );
                target.confidence_bucket = Some(debug_slug(&detail.reliability_bucket));
                target.evidence_refs = strings(&detail.evidence_refs);
                target.baseline_refs = strings(&detail.baseline_refs);
                target.incident_group_refs = strings(&detail.incident_group_refs);
                target.timeline_refs = strings(&detail.timeline_refs);
                target.degraded_reason = detail.degraded_reason.clone();
                target.missing_visibility_flags = detail.missing_visibility_flags.clone();
            }
        }
        NavigationTargetKind::Finding => {
            if let Some(finding) = state
                .findings
                .items
                .iter()
                .find(|finding| finding.id().to_string() == target.target_id)
            {
                mark_resolved(target, "finding", "Evidence-backed finding summary");
                target.category = safe_slug(finding.finding_type());
                target.severity_risk_bucket = Some(debug_slug(finding.severity()));
                target.confidence_bucket = Some(quality_bucket(finding.confidence().value()));
                target.evidence_refs = strings(finding.evidence_refs());
                target.attack_refs = finding
                    .attack_mappings()
                    .iter()
                    .filter_map(|mapping| {
                        Some(format!(
                            "{}:{}",
                            mapping.tactic_id.as_ref()?,
                            mapping.technique_id.as_ref()?
                        ))
                    })
                    .collect();
            }
        }
        NavigationTargetKind::AttackTechniqueRow => {
            let coverage = get_attack_coverage_summary(state)?;
            if let Some(row) = coverage
                .technique_rows
                .iter()
                .find(|row| attack_key(&row.tactic_id, &row.technique_id) == target.target_id)
            {
                mark_resolved(
                    target,
                    "attack_technique_row",
                    "Metadata-only ATT&CK coverage row",
                );
                target.confidence_bucket = Some(debug_slug(&row.confidence_bucket));
                target.evidence_refs = strings(&row.evidence_refs);
                target.finding_refs = strings(&row.finding_refs);
                target.risk_refs = strings(&row.risk_refs);
                target.degraded_reason = row.degraded_reason.clone();
                target.missing_visibility_flags =
                    vec![
                        format!("required_visibility_{:?}", row.required_visibility).to_lowercase()
                    ];
            }
        }
        NavigationTargetKind::GraphNodeSummary => {
            if let Some(node) = state
                .graph_views
                .iter()
                .flat_map(|view| view.nodes.iter())
                .find(|node| node.node_id.to_string() == target.target_id)
            {
                mark_degraded(target, "graph_node_summary", "Bounded graph node summary");
                target.severity_risk_bucket = Some(quality_bucket(node.risk_score.value()));
                target.evidence_refs = strings(&node.detail_ref.evidence_refs);
                if let Some(finding_id) = &node.detail_ref.finding_id {
                    target.finding_refs = vec![finding_id.to_string()];
                }
                target.missing_visibility_flags = vec!["metadata_only_graph_view".to_string()];
            }
        }
        NavigationTargetKind::GraphEdgeSummary => {
            if let Some(edge) = state
                .graph_views
                .iter()
                .flat_map(|view| view.edges.iter())
                .find(|edge| edge.edge_id.to_string() == target.target_id)
            {
                mark_degraded(
                    target,
                    "graph_edge_summary",
                    "Evidence-backed graph edge summary",
                );
                target.confidence_bucket = Some(quality_bucket(edge.confidence.value()));
                target.evidence_refs = strings(&edge.evidence_refs);
                target.graph_refs = vec![edge.source.to_string(), edge.target.to_string()];
                target.missing_visibility_flags = vec!["metadata_only_graph_view".to_string()];
            }
        }
        NavigationTargetKind::GraphPathSummary => {
            if let Some(path) = state
                .graph_views
                .iter()
                .flat_map(|view| view.paths.iter())
                .find(|path| path.path_id.to_string() == target.target_id)
            {
                mark_degraded(target, "graph_path_summary", "Bounded graph path summary");
                target.confidence_bucket = Some(quality_bucket(path.confidence.value()));
                target.severity_risk_bucket = Some(quality_bucket(path.risk_score.value()));
                target.evidence_refs = strings(&path.evidence_refs);
                target.missing_visibility_flags = vec!["metadata_only_graph_view".to_string()];
            }
        }
        NavigationTargetKind::ReportSection => {
            if let Some(section) = state
                .reports
                .items
                .iter()
                .flat_map(|report| report.sections.iter())
                .find(|section| section.section_id.to_string() == target.target_id)
            {
                mark_resolved(
                    target,
                    "report_section",
                    "Redacted report section references",
                );
                target.category = debug_slug(&section.section_type);
                target.evidence_refs = strings(&section.evidence_refs);
                target.graph_refs = strings(&section.graph_snapshot_refs);
                target.story_refs = strings(&section.llm_story_refs);
                target.quality_refs = strings(&section.quality_refs);
                target.evidence_quality_bucket =
                    Some(debug_slug(&section.quality.evidence_quality_bucket));
            }
        }
        NavigationTargetKind::ExportHistoryEntry => {
            if let Some(record) = state
                .export_history
                .records()
                .iter()
                .find(|record| record.export_result_id.to_string() == target.target_id)
            {
                mark_resolved(
                    target,
                    "export_history_entry",
                    "Redacted export history references",
                );
                target.evidence_refs = strings(&record.evidence_refs);
                target.graph_refs = strings(&record.graph_snapshot_refs);
                target.story_refs = strings(&record.llm_story_refs);
                target.report_refs = state
                    .reports
                    .items
                    .iter()
                    .find(|report| report.report_id == record.report_id)
                    .map(|report| {
                        strings(
                            &report
                                .sections
                                .iter()
                                .map(|section| section.section_id.clone())
                                .collect::<Vec<_>>(),
                        )
                    })
                    .unwrap_or_default();
                target.created_time_bucket = Some(record.exported_at.clone());
            }
        }
        NavigationTargetKind::LlmStoryRecord => {
            if let Some(story) = state
                .llm_alert_stories
                .items
                .iter()
                .find(|story| story.story_id.to_string() == target.target_id)
            {
                mark_resolved(
                    target,
                    "llm_story_record",
                    "Explicitly generated redacted alert story",
                );
                target.evidence_refs = strings(&story.evidence_refs);
                target.risk_refs = strings(&story.risk_refs);
                target.attack_refs = story
                    .attack_refs
                    .iter()
                    .map(|reference| attack_key(&reference.tactic_id, &reference.technique_id))
                    .collect();
                target.created_time_bucket = Some(story.generated_at.clone());
                if story.degraded {
                    target.status = NavigationResolutionStatus::Degraded;
                    target.degraded_reason = Some("story_provider_degraded".to_string());
                }
            }
        }
        NavigationTargetKind::EvidenceQualityDetail => {
            if let Some(record) = quality_summary
                .records
                .iter()
                .find(|record| record.evidence_quality_id.to_string() == target.target_id)
            {
                mark_resolved(target, "evidence_quality_detail", "Bounded quality summary");
                apply_quality_record_to_target(record, target);
                target.quality_refs = vec![record.evidence_quality_id.to_string()];
            }
        }
        NavigationTargetKind::Evidence
        | NavigationTargetKind::Risk
        | NavigationTargetKind::GraphHint => {}
    }
    Ok(())
}

fn add_reverse_links(
    drill_down: &InvestigationDrillDownSummary,
    target: &mut NavigationTargetSummary,
) {
    let id = target.target_id.clone();
    add_reverse_links_for_id(drill_down, &id, target);
    if target.status == NavigationResolutionStatus::Missing
        && (!target.hypothesis_refs.is_empty()
            || !target.baseline_refs.is_empty()
            || !target.incident_group_refs.is_empty()
            || !target.timeline_refs.is_empty())
    {
        mark_degraded(
            target,
            &kind_label(&target.target_kind),
            "Reference-only bounded summary",
        );
        target.degraded_reason = Some("reference_body_unavailable".to_string());
        target.missing_visibility_flags = vec!["reference_only_visibility".to_string()];
    }
}

fn add_reverse_links_for_id(
    drill_down: &InvestigationDrillDownSummary,
    id: &str,
    target: &mut NavigationTargetSummary,
) {
    for detail in &drill_down.hypotheses {
        if hypothesis_contains(detail, id) {
            push_ref(
                &mut target.hypothesis_refs,
                detail.hypothesis_id.to_string(),
            );
        }
    }
    for detail in &drill_down.baselines {
        if baseline_contains(detail, id) {
            push_ref(&mut target.baseline_refs, detail.baseline_id.to_string());
        }
    }
    for detail in &drill_down.incident_groups {
        if group_contains(detail, id) {
            push_ref(&mut target.incident_group_refs, detail.group_id.to_string());
        }
    }
    for detail in &drill_down.timeline {
        if timeline_contains(detail, id) {
            push_ref(
                &mut target.timeline_refs,
                detail.timeline_entry_id.to_string(),
            );
        }
    }
}

fn hypothesis_contains(detail: &sentinel_contracts::HypothesisExplanationDetail, id: &str) -> bool {
    strings(&detail.evidence_refs).contains(&id.to_string())
        || strings(&detail.fact_refs).contains(&id.to_string())
        || strings(&detail.finding_refs).contains(&id.to_string())
        || strings(&detail.risk_refs).contains(&id.to_string())
        || strings(&detail.baseline_refs).contains(&id.to_string())
        || attack_strings(&detail.attack_refs).contains(&id.to_string())
        || strings(&detail.graph_refs).contains(&id.to_string())
        || strings(&detail.report_refs).contains(&id.to_string())
        || strings(&detail.export_refs).contains(&id.to_string())
        || strings(&detail.story_availability.story_refs).contains(&id.to_string())
}

fn baseline_contains(detail: &sentinel_contracts::BaselineDrillDownDetail, id: &str) -> bool {
    strings(&detail.hypothesis_refs).contains(&id.to_string())
        || strings(&detail.incident_group_refs).contains(&id.to_string())
        || strings(&detail.indicator_refs).contains(&id.to_string())
        || strings(&detail.evidence_refs).contains(&id.to_string())
        || strings(&detail.fact_refs).contains(&id.to_string())
        || strings(&detail.finding_refs).contains(&id.to_string())
        || strings(&detail.risk_refs).contains(&id.to_string())
        || attack_strings(&detail.attack_refs).contains(&id.to_string())
        || strings(&detail.report_refs).contains(&id.to_string())
        || strings(&detail.export_refs).contains(&id.to_string())
}

fn group_contains(detail: &sentinel_contracts::IncidentGroupInvestigationDetail, id: &str) -> bool {
    strings(&detail.hypothesis_refs).contains(&id.to_string())
        || strings(&detail.baseline_refs).contains(&id.to_string())
        || strings(&detail.timeline_refs).contains(&id.to_string())
        || strings(&detail.evidence_refs).contains(&id.to_string())
        || strings(&detail.fact_refs).contains(&id.to_string())
        || strings(&detail.finding_refs).contains(&id.to_string())
        || strings(&detail.risk_refs).contains(&id.to_string())
        || attack_strings(&detail.attack_refs).contains(&id.to_string())
        || strings(&detail.graph_refs).contains(&id.to_string())
        || strings(&detail.report_refs).contains(&id.to_string())
        || strings(&detail.export_refs).contains(&id.to_string())
        || strings(&detail.story_availability.story_refs).contains(&id.to_string())
}

fn timeline_contains(detail: &sentinel_contracts::TimelineDrillDownDetail, id: &str) -> bool {
    strings(&detail.hypothesis_refs).contains(&id.to_string())
        || strings(&detail.baseline_refs).contains(&id.to_string())
        || strings(&detail.evidence_refs).contains(&id.to_string())
        || strings(&detail.finding_refs).contains(&id.to_string())
        || strings(&detail.risk_refs).contains(&id.to_string())
        || attack_strings(&detail.attack_refs).contains(&id.to_string())
        || strings(&detail.report_refs).contains(&id.to_string())
}

fn outgoing_references(
    request: &NavigationResolveRequest,
    target: &NavigationTargetSummary,
) -> Vec<NavigationReference> {
    let groups = [
        (NavigationTargetKind::Evidence, &target.evidence_refs),
        (NavigationTargetKind::Hypothesis, &target.hypothesis_refs),
        (NavigationTargetKind::Finding, &target.finding_refs),
        (NavigationTargetKind::Risk, &target.risk_refs),
        (NavigationTargetKind::Baseline, &target.baseline_refs),
        (
            NavigationTargetKind::IncidentLinkedGroup,
            &target.incident_group_refs,
        ),
        (NavigationTargetKind::TimelineEntry, &target.timeline_refs),
        (
            NavigationTargetKind::AttackTechniqueRow,
            &target.attack_refs,
        ),
        (NavigationTargetKind::GraphHint, &target.graph_refs),
        (NavigationTargetKind::ReportSection, &target.report_refs),
        (
            NavigationTargetKind::ExportHistoryEntry,
            &target.export_refs,
        ),
        (NavigationTargetKind::LlmStoryRecord, &target.story_refs),
        (
            NavigationTargetKind::EvidenceQualityDetail,
            &target.quality_refs,
        ),
    ];
    let mut references = Vec::new();
    for (kind, refs) in groups {
        for target_id in refs.iter().take(MAX_NAVIGATION_REFS - references.len()) {
            references.push(NavigationReference {
                ref_id: format!("{}:{}", kind_label(&kind), target_id),
                ref_kind: kind.clone(),
                target_kind: kind.clone(),
                target_id: target_id.clone(),
                source_view: request.source_view.clone(),
                target_view: target_view(&kind),
                display_label_category: kind_label(&kind),
                confidence_bucket: None,
                degraded_reason: None,
                missing_visibility_flags: Vec::new(),
                redacted_summary: "Open bounded reference summary".to_string(),
                created_time_bucket: None,
                provenance_id: None,
                redaction_status: RedactionStatus::Redacted,
            });
        }
    }
    references
}

fn add_derived_references(
    request: &NavigationResolveRequest,
    drill_down: &InvestigationDrillDownSummary,
    quality_summary: &EvidenceQualitySummary,
    target: &NavigationTargetSummary,
    references: &mut Vec<NavigationReference>,
) {
    let mut derived = Vec::<(NavigationTargetKind, String)>::new();
    if let Some(detail) = drill_down
        .hypotheses
        .iter()
        .find(|detail| detail.hypothesis_id.to_string() == target.target_id)
    {
        derived.extend(
            strings(&detail.indicator_refs)
                .into_iter()
                .map(|id| (NavigationTargetKind::BaselineIndicator, id)),
        );
    }
    if let Some(detail) = drill_down
        .baselines
        .iter()
        .find(|detail| detail.baseline_id.to_string() == target.target_id)
    {
        derived.extend(
            strings(&detail.indicator_refs)
                .into_iter()
                .map(|id| (NavigationTargetKind::BaselineIndicator, id)),
        );
        derived.extend(drill_down.source_reliability.iter().filter_map(|source| {
            if source
                .baseline_refs
                .iter()
                .any(|reference| reference.to_string() == target.target_id)
            {
                Some((
                    NavigationTargetKind::SourceReliabilitySummary,
                    source.source_id.to_string(),
                ))
            } else {
                None
            }
        }));
    }
    if let Some(detail) = drill_down
        .incident_groups
        .iter()
        .find(|detail| detail.group_id.to_string() == target.target_id)
    {
        derived.extend(
            strings(&detail.source_reliability_refs)
                .into_iter()
                .map(|id| (NavigationTargetKind::SourceReliabilitySummary, id)),
        );
    }
    derived.extend(
        quality_summary
            .records
            .iter()
            .filter(|record| quality_record_matches_target(record, target))
            .map(|record| {
                (
                    NavigationTargetKind::EvidenceQualityDetail,
                    record.evidence_quality_id.to_string(),
                )
            }),
    );
    for (kind, target_id) in derived {
        if references.len() >= MAX_NAVIGATION_REFS
            || references
                .iter()
                .any(|reference| reference.target_kind == kind && reference.target_id == target_id)
        {
            continue;
        }
        references.push(navigation_reference(request, kind, target_id));
    }
}

fn navigation_reference(
    request: &NavigationResolveRequest,
    kind: NavigationTargetKind,
    target_id: String,
) -> NavigationReference {
    NavigationReference {
        ref_id: format!("{}:{}", kind_label(&kind), target_id),
        ref_kind: kind.clone(),
        target_kind: kind.clone(),
        target_id,
        source_view: request.source_view.clone(),
        target_view: target_view(&kind),
        display_label_category: kind_label(&kind),
        confidence_bucket: None,
        degraded_reason: None,
        missing_visibility_flags: Vec::new(),
        redacted_summary: "Open bounded reference summary".to_string(),
        created_time_bucket: None,
        provenance_id: None,
        redaction_status: RedactionStatus::Redacted,
    }
}

fn normalize_target(target: &mut NavigationTargetSummary) {
    for refs in [
        &mut target.evidence_refs,
        &mut target.fact_refs,
        &mut target.hypothesis_refs,
        &mut target.finding_refs,
        &mut target.risk_refs,
        &mut target.baseline_refs,
        &mut target.incident_group_refs,
        &mut target.timeline_refs,
        &mut target.attack_refs,
        &mut target.graph_refs,
        &mut target.report_refs,
        &mut target.export_refs,
        &mut target.story_refs,
        &mut target.quality_refs,
        &mut target.provenance_refs,
    ] {
        refs.sort();
        refs.dedup();
        refs.truncate(MAX_NAVIGATION_REFS);
    }
    target.missing_visibility_flags.sort();
    target.missing_visibility_flags.dedup();
}

fn add_quality_context(
    quality_summary: &EvidenceQualitySummary,
    target: &mut NavigationTargetSummary,
) {
    for record in &quality_summary.records {
        if quality_record_matches_target(record, target) {
            push_ref(
                &mut target.quality_refs,
                record.evidence_quality_id.to_string(),
            );
            if target.evidence_quality_bucket.is_none() {
                target.evidence_quality_bucket =
                    Some(debug_slug(&record.quality.evidence_quality_bucket));
            }
            if target.degraded_reason.is_none() {
                target.degraded_reason = record.quality.degraded_reasons.first().cloned();
            }
            for flag in &record.quality.missing_visibility_flags {
                push_ref(&mut target.missing_visibility_flags, flag.clone());
            }
        }
    }
}

fn quality_record_matches_target(
    record: &EvidenceQualityRecord,
    target: &NavigationTargetSummary,
) -> bool {
    match target.target_kind {
        NavigationTargetKind::Evidence => optional_ref_matches(&record.evidence_ref, target),
        NavigationTargetKind::Finding => optional_ref_matches(&record.finding_ref, target),
        NavigationTargetKind::Hypothesis => optional_ref_matches(&record.hypothesis_ref, target),
        NavigationTargetKind::Risk => optional_ref_matches(&record.risk_ref, target),
        NavigationTargetKind::Baseline => optional_ref_matches(&record.baseline_ref, target),
        NavigationTargetKind::BaselineIndicator => {
            optional_ref_matches(&record.baseline_indicator_ref, target)
        }
        NavigationTargetKind::AttackTechniqueRow => record
            .attack_ref
            .as_ref()
            .is_some_and(|value| value == &target.target_id),
        NavigationTargetKind::GraphHint => optional_ref_matches(&record.graph_ref, target),
        NavigationTargetKind::IncidentLinkedGroup => {
            optional_ref_matches(&record.incident_group_ref, target)
        }
        NavigationTargetKind::ReportSection => {
            optional_ref_matches(&record.report_section_ref, target)
        }
        NavigationTargetKind::ExportHistoryEntry => {
            optional_ref_matches(&record.export_result_ref, target)
        }
        NavigationTargetKind::EvidenceQualityDetail => {
            record.evidence_quality_id.to_string() == target.target_id
        }
        NavigationTargetKind::TimelineEntry
        | NavigationTargetKind::SourceReliabilitySummary
        | NavigationTargetKind::GraphNodeSummary
        | NavigationTargetKind::GraphEdgeSummary
        | NavigationTargetKind::GraphPathSummary
        | NavigationTargetKind::LlmStoryRecord => false,
    }
}

fn apply_quality_record_to_target(
    record: &EvidenceQualityRecord,
    target: &mut NavigationTargetSummary,
) {
    target.category = debug_slug(&record.target_kind);
    target.evidence_quality_bucket = Some(debug_slug(&record.quality.evidence_quality_bucket));
    target.confidence_bucket = Some(debug_slug(&record.detector_confidence_bucket));
    target.evidence_refs = optional_string(&record.evidence_ref);
    target.finding_refs = optional_string(&record.finding_ref);
    target.hypothesis_refs = optional_string(&record.hypothesis_ref);
    target.risk_refs = optional_string(&record.risk_ref);
    target.baseline_refs = optional_string(&record.baseline_ref);
    target.incident_group_refs = optional_string(&record.incident_group_ref);
    target.attack_refs = record.attack_ref.clone().into_iter().collect();
    target.graph_refs = optional_string(&record.graph_ref);
    target.report_refs = optional_string(&record.report_section_ref);
    target.export_refs = optional_string(&record.export_result_ref);
    target.fact_refs = strings(&record.fact_refs);
    target.provenance_refs = optional_string(&record.provenance_id);
    target.created_time_bucket = Some(record.time_bucket.clone());
    target.degraded_reason = record.quality.degraded_reasons.first().cloned();
    target.missing_visibility_flags = record.quality.missing_visibility_flags.clone();
    if record.quality.evidence_quality_bucket == sentinel_contracts::EvidenceQualityBucket::Low {
        target.status = NavigationResolutionStatus::Degraded;
    }
}

fn optional_ref_matches<T: ToString>(value: &Option<T>, target: &NavigationTargetSummary) -> bool {
    value
        .as_ref()
        .is_some_and(|value| value.to_string() == target.target_id)
}

fn optional_string<T: ToString>(value: &Option<T>) -> Vec<String> {
    value
        .as_ref()
        .map(ToString::to_string)
        .into_iter()
        .collect()
}

fn mark_resolved(target: &mut NavigationTargetSummary, category: &str, summary: &str) {
    target.status = NavigationResolutionStatus::Resolved;
    target.category = safe_slug(category);
    target.redacted_summary = safe_slug(summary);
    target.degraded_reason = None;
    target.missing_visibility_flags.clear();
}

fn mark_degraded(target: &mut NavigationTargetSummary, category: &str, summary: &str) {
    mark_resolved(target, category, summary);
    target.status = NavigationResolutionStatus::Degraded;
    target.degraded_reason = Some("metadata_only_visibility".to_string());
}

fn strings<T: ToString>(values: &[T]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

fn attack_strings(values: &[sentinel_contracts::BaselineAttackTechniqueRef]) -> Vec<String> {
    values
        .iter()
        .map(|reference| attack_key(&reference.tactic_id, &reference.technique_id))
        .collect()
}

fn attack_key(tactic_id: &str, technique_id: &str) -> String {
    format!("{tactic_id}:{technique_id}")
}

fn push_ref(refs: &mut Vec<String>, value: String) {
    if refs.len() < MAX_NAVIGATION_REFS && !refs.contains(&value) {
        refs.push(value);
    }
}

fn quality_bucket(value: f32) -> String {
    if value >= 0.75 {
        "high".to_string()
    } else if value >= 0.4 {
        "medium".to_string()
    } else if value > 0.0 {
        "low".to_string()
    } else {
        "unknown".to_string()
    }
}

fn debug_slug(value: &impl std::fmt::Debug) -> String {
    safe_slug(&format!("{value:?}"))
}

fn safe_slug(value: &str) -> String {
    let mut result = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || "-_:.".contains(character) {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    result.truncate(180);
    if result.trim_matches('_').is_empty() {
        "redacted_summary".to_string()
    } else {
        result
    }
}

fn kind_label(kind: &NavigationTargetKind) -> String {
    debug_slug(kind)
}

fn target_view(kind: &NavigationTargetKind) -> NavigationViewKind {
    match kind {
        NavigationTargetKind::Hypothesis
        | NavigationTargetKind::Baseline
        | NavigationTargetKind::BaselineIndicator
        | NavigationTargetKind::IncidentLinkedGroup
        | NavigationTargetKind::SourceReliabilitySummary => NavigationViewKind::Investigation,
        NavigationTargetKind::TimelineEntry => NavigationViewKind::Timeline,
        NavigationTargetKind::Evidence
        | NavigationTargetKind::Finding
        | NavigationTargetKind::Risk => NavigationViewKind::Evidence,
        NavigationTargetKind::AttackTechniqueRow => NavigationViewKind::AttackCoverage,
        NavigationTargetKind::GraphHint
        | NavigationTargetKind::GraphNodeSummary
        | NavigationTargetKind::GraphEdgeSummary
        | NavigationTargetKind::GraphPathSummary => NavigationViewKind::Graph,
        NavigationTargetKind::ReportSection => NavigationViewKind::Report,
        NavigationTargetKind::ExportHistoryEntry => NavigationViewKind::Export,
        NavigationTargetKind::LlmStoryRecord => NavigationViewKind::Story,
        NavigationTargetKind::EvidenceQualityDetail => NavigationViewKind::Evidence,
    }
}

fn navigation_validation_error(error: impl ToString) -> CoreError {
    CoreError::new(
        ErrorCode::ValidationFailure,
        "bounded navigation reference failed safety validation",
    )
    .with_severity(ErrorSeverity::Warning)
    .with_redacted_details(json!({ "reason_redacted": safe_slug(&error.to_string()) }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        AttackHypothesisId, AttackHypothesisRecord, EvidenceId, FusionConfidenceBucket,
        QualityBreakdown, SessionId, Timestamp,
    };

    fn state_with_hypothesis(
        session_id: SessionId,
    ) -> (ReadOnlyCommandState, AttackHypothesisId, EvidenceId) {
        let evidence_id = EvidenceId::new_v4();
        let hypothesis = AttackHypothesisRecord {
            hypothesis_record_id: AttackHypothesisId::new_v4(),
            definition_id: "possible_api_abuse_chain".to_string(),
            version: "1.0.0".to_string(),
            category: "possible_api_abuse_chain".to_string(),
            fact_refs: vec![sentinel_contracts::SecurityFactId::new_v4()],
            correlated_layers: vec![sentinel_contracts::SecurityLayer::Api],
            correlation_count: 1,
            confidence_bucket: FusionConfidenceBucket::Low,
            degraded_reason: Some("metadata_only_visibility".to_string()),
            missing_visibility_flags: vec!["no_process_attribution".to_string()],
            evidence_refs: vec![evidence_id.clone()],
            finding_refs: Vec::new(),
            risk_refs: Vec::new(),
            graph_hint_refs: Vec::new(),
            attack_candidates: Vec::new(),
            negative_evidence_notes: Vec::new(),
            benign_baseline_indicators: Vec::new(),
            optional_llm_story_marker: false,
            quality: QualityBreakdown::metadata_only(),
            created_at: Timestamp::now(),
        };
        let hypothesis_id = hypothesis.hypothesis_record_id.clone();
        let state = ReadOnlyCommandState::bootstrap()
            .expect("bootstrap")
            .with_service_status(
                crate::read_commands::ServiceStatusView::reduced_visibility()
                    .with_active_session_id(Some(session_id)),
            )
            .with_attack_hypotheses(vec![hypothesis]);
        (state, hypothesis_id, evidence_id)
    }

    #[test]
    fn resolver_returns_bounded_hypothesis_and_degraded_evidence_summary() {
        let session_id = SessionId::new_v4();
        let (state, hypothesis_id, evidence_id) = state_with_hypothesis(session_id.clone());

        let hypothesis = resolve_bounded_reference(
            &state,
            NavigationResolveRequest {
                session_id: Some(session_id.clone()),
                source_view: NavigationViewKind::Investigation,
                target_kind: NavigationTargetKind::Hypothesis,
                target_id: hypothesis_id.to_string(),
            },
        )
        .expect("hypothesis navigation");
        assert_eq!(hypothesis.status, NavigationResolutionStatus::Resolved);
        assert!(hypothesis
            .target
            .evidence_refs
            .contains(&evidence_id.to_string()));
        assert!(!hypothesis.automatic_llm_calls);
        assert!(!hypothesis.response_execution);

        let evidence = resolve_bounded_reference(
            &state,
            NavigationResolveRequest {
                session_id: Some(session_id),
                source_view: NavigationViewKind::Investigation,
                target_kind: NavigationTargetKind::Evidence,
                target_id: evidence_id.to_string(),
            },
        )
        .expect("evidence navigation");
        assert_eq!(evidence.status, NavigationResolutionStatus::Degraded);
        assert!(evidence
            .target
            .hypothesis_refs
            .contains(&hypothesis_id.to_string()));
        let serialized = serde_json::to_string(&evidence).expect("serialize");
        assert!(!serialized.contains("https://"));
        assert!(!serialized.contains("session_token"));
    }

    #[test]
    fn resolver_rejects_unsafe_and_cross_session_refs() {
        let session_id = SessionId::new_v4();
        let (state, _, _) = state_with_hypothesis(session_id);
        let unsafe_error = resolve_bounded_reference(
            &state,
            NavigationResolveRequest {
                session_id: state.service_status.active_session_id.clone(),
                source_view: NavigationViewKind::Evidence,
                target_kind: NavigationTargetKind::Evidence,
                target_id: "https://example.test/private?token=secret".to_string(),
            },
        )
        .expect_err("unsafe ref rejected");
        assert_eq!(unsafe_error.error_code, ErrorCode::ValidationFailure);

        let scope_error = resolve_bounded_reference(
            &state,
            NavigationResolveRequest {
                session_id: Some(SessionId::new_v4()),
                source_view: NavigationViewKind::Evidence,
                target_kind: NavigationTargetKind::Evidence,
                target_id: EvidenceId::new_v4().to_string(),
            },
        )
        .expect_err("cross-session ref rejected");
        assert_eq!(scope_error.error_code, ErrorCode::PermissionDenied);
    }
}
