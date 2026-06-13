use crate::baseline_read_models::build_durable_baseline_summary;
use crate::native_sampler_readiness::get_native_sampler_readiness_summary;
use crate::read_commands::get_native_sampler_runtime_summary;
use crate::read_commands::{build_attack_coverage_summary, ReadOnlyCommandState};
use sentinel_contracts::{
    AttackCoverageConfidenceBucket, AttackCoverageState, BaselineIndicator, BaselineRecord,
    CommandResult, CoreError, CorrelationQualityBucket, EvidenceId, EvidenceQualityBucket,
    EvidenceQualityId, EvidenceQualityRecord, EvidenceQualitySummary, EvidenceQualityTargetKind,
    Finding, FreshnessBucket, IncidentLinkedHypothesisGroup, NativeTelemetryDimension,
    NativeTelemetryFreshnessState, OperationalInfluenceBucket, ProvenanceQualityBucket,
    QualityBreakdown, RedactionCompletenessBucket, RedactionStatus, ReportSection,
    SourceReliabilityQualityBucket, SuitabilityBucket, Timestamp, UncertaintyBucket,
    VisibilityCompletenessBucket, MAX_QUALITY_RECORDS, MAX_QUALITY_REFS,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

pub fn build_evidence_quality_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<EvidenceQualitySummary> {
    let baseline = build_durable_baseline_summary(state)?;
    let attack_coverage = build_attack_coverage_summary(state)?;
    let mut records = Vec::<EvidenceQualityRecord>::new();

    for finding in &state.findings.items {
        for evidence_ref in finding.evidence_refs().iter().take(MAX_QUALITY_REFS) {
            push_record(
                &mut records,
                finding_quality_record(finding, evidence_ref.clone()),
            )?;
        }
    }

    for hypothesis in &state.attack_hypotheses.items {
        let quality_id = quality_id("hypothesis", &hypothesis.hypothesis_record_id.to_string());
        let mut quality = hypothesis
            .quality
            .clone()
            .with_quality_ref(quality_id.clone());
        if hypothesis.correlation_count <= 1 || hypothesis.evidence_refs.len() <= 1 {
            quality.correlation_quality_bucket = CorrelationQualityBucket::SingleSignal;
            quality.evidence_strength_bucket =
                sentinel_contracts::EvidenceStrengthBucket::WeakSingleSignal;
            quality.uncertainty_bucket = UncertaintyBucket::High;
            push_quality_reason(&mut quality, "weak_single_signal");
        }
        push_record(
            &mut records,
            EvidenceQualityRecord {
                evidence_quality_id: quality_id,
                target_kind: EvidenceQualityTargetKind::Hypothesis,
                evidence_ref: hypothesis.evidence_refs.first().cloned(),
                finding_ref: hypothesis.finding_refs.first().cloned(),
                hypothesis_ref: Some(hypothesis.hypothesis_record_id.clone()),
                risk_ref: hypothesis.risk_refs.first().cloned(),
                baseline_ref: None,
                baseline_indicator_ref: None,
                attack_ref: hypothesis
                    .attack_candidates
                    .first()
                    .map(|candidate| attack_ref(&candidate.tactic_id, &candidate.technique_id)),
                graph_ref: hypothesis.graph_hint_refs.first().cloned(),
                incident_group_ref: None,
                report_section_ref: None,
                export_result_ref: None,
                fact_refs: bounded_refs(hypothesis.fact_refs.iter().cloned()),
                source_kind_category: "fusion_hypothesis".to_string(),
                parser_family: "multi_layer_security_fusion".to_string(),
                detector_id: Some(safe_slug(&hypothesis.definition_id)),
                detector_confidence_bucket: fusion_bucket(&hypothesis.confidence_bucket),
                unsafe_field_rejection_bucket: EvidenceQualityBucket::Unknown,
                malformed_skipped_backpressure_bucket: OperationalInfluenceBucket::None,
                redaction_status: RedactionStatus::Redacted,
                provenance_id: None,
                time_bucket: hypothesis.created_at.clone(),
                quality,
            },
        )?;
    }

    for row in &attack_coverage.technique_rows {
        let quality_id = quality_id("attack", &format!("{}:{}", row.tactic_id, row.technique_id));
        let mut quality = row.quality.clone().with_quality_ref(quality_id.clone());
        if row.states.contains(&AttackCoverageState::Unsupported)
            || row
                .states
                .contains(&AttackCoverageState::RequiresAuthorizedNativeExtension)
        {
            quality.visibility_completeness_bucket =
                VisibilityCompletenessBucket::RequiresAuthorizedNative;
            quality.report_suitability_bucket = SuitabilityBucket::Degraded;
            quality.export_suitability_bucket = SuitabilityBucket::Degraded;
            push_quality_reason(&mut quality, "requires_authorized_native_visibility");
        }
        push_record(
            &mut records,
            EvidenceQualityRecord {
                evidence_quality_id: quality_id,
                target_kind: EvidenceQualityTargetKind::AttackMapping,
                evidence_ref: row.evidence_refs.first().cloned(),
                finding_ref: row.finding_refs.first().cloned(),
                hypothesis_ref: None,
                risk_ref: row.risk_refs.first().cloned(),
                baseline_ref: None,
                baseline_indicator_ref: None,
                attack_ref: Some(attack_ref(&row.tactic_id, &row.technique_id)),
                graph_ref: None,
                incident_group_ref: None,
                report_section_ref: None,
                export_result_ref: None,
                fact_refs: Vec::new(),
                source_kind_category: safe_slug(&row.package_category),
                parser_family: "attack_coverage_matrix".to_string(),
                detector_id: row.rule_detector_ids.first().map(|value| safe_slug(value)),
                detector_confidence_bucket: attack_bucket(&row.confidence_bucket),
                unsafe_field_rejection_bucket: EvidenceQualityBucket::Unknown,
                malformed_skipped_backpressure_bucket: OperationalInfluenceBucket::None,
                redaction_status: RedactionStatus::Redacted,
                provenance_id: None,
                time_bucket: attack_coverage.generated_at.clone(),
                quality,
            },
        )?;
    }

    for record in &baseline.records {
        push_record(&mut records, baseline_record_quality_record(record))?;
    }
    for indicator in &baseline.indicators {
        push_record(&mut records, baseline_indicator_quality_record(indicator))?;
    }
    for group in &baseline.incident_groups {
        push_record(&mut records, incident_group_quality_record(group))?;
    }
    for report in &state.reports.items {
        for section in &report.sections {
            push_record(&mut records, report_section_quality_record(section))?;
        }
    }
    for export in state.export_history.records() {
        let quality_id = quality_id("export", &export.export_result_id.to_string());
        let mut quality =
            QualityBreakdown::corroborated_metadata().with_quality_ref(quality_id.clone());
        quality.redaction_completeness_bucket = if export.redaction_summary.passed {
            RedactionCompletenessBucket::Complete
        } else {
            RedactionCompletenessBucket::UnsafeBlocked
        };
        if !export.redaction_summary.passed {
            quality.report_suitability_bucket = SuitabilityBucket::Blocked;
            quality.export_suitability_bucket = SuitabilityBucket::Blocked;
        }
        push_record(
            &mut records,
            EvidenceQualityRecord {
                evidence_quality_id: quality_id,
                target_kind: EvidenceQualityTargetKind::ExportArtifact,
                evidence_ref: export.evidence_refs.first().cloned(),
                finding_ref: None,
                hypothesis_ref: None,
                risk_ref: None,
                baseline_ref: None,
                baseline_indicator_ref: None,
                attack_ref: None,
                graph_ref: None,
                incident_group_ref: None,
                report_section_ref: None,
                export_result_ref: Some(export.export_result_id.clone()),
                fact_refs: Vec::new(),
                source_kind_category: "explicit_export".to_string(),
                parser_family: "report_export_gate".to_string(),
                detector_id: None,
                detector_confidence_bucket: EvidenceQualityBucket::Medium,
                unsafe_field_rejection_bucket: EvidenceQualityBucket::Unknown,
                malformed_skipped_backpressure_bucket: OperationalInfluenceBucket::None,
                redaction_status: RedactionStatus::Redacted,
                provenance_id: None,
                time_bucket: export.exported_at.clone(),
                quality,
            },
        )?;
    }

    records.sort_by(|left, right| {
        left.evidence_quality_id
            .to_string()
            .cmp(&right.evidence_quality_id.to_string())
    });
    records.dedup_by(|left, right| left.evidence_quality_id == right.evidence_quality_id);
    records.truncate(MAX_QUALITY_RECORDS);

    let native_sampler_readiness = get_native_sampler_readiness_summary(state).ok();
    let native_sampler_runtime = get_native_sampler_runtime_summary(state).ok();
    let mut degraded_reason_summary = records
        .iter()
        .flat_map(|record| record.quality.degraded_reasons.iter().cloned())
        .collect::<Vec<_>>();
    let mut missing_visibility_flags = records
        .iter()
        .flat_map(|record| record.quality.missing_visibility_flags.iter().cloned())
        .collect::<Vec<_>>();
    if let Some(readiness) = &native_sampler_readiness {
        degraded_reason_summary.extend(readiness.degraded_reasons.iter().cloned());
        missing_visibility_flags
            .extend(readiness.missing_endpoint_visibility_flags.iter().cloned());
    }
    if native_sampler_runtime
        .as_ref()
        .is_none_or(|runtime| runtime.fact_refs.is_empty())
    {
        missing_visibility_flags.push("native_sampler_readiness_no_endpoint_telemetry".to_string());
    }
    if let Some(runtime) = &native_sampler_runtime {
        if runtime.process_visibility_available {
            missing_visibility_flags.retain(|flag| flag != "missing_process_category_visibility");
            degraded_reason_summary.push(
                "process_category_visibility_available_specific_attribution_unavailable"
                    .to_string(),
            );
            missing_visibility_flags.push("process_network_attribution_unavailable".to_string());
            missing_visibility_flags.push("packet_visibility_unavailable".to_string());
            missing_visibility_flags.push("file_visibility_unavailable".to_string());
            missing_visibility_flags.push("registry_visibility_unavailable".to_string());
        }
        if runtime.quality_bucket.starts_with("degraded_") {
            degraded_reason_summary.push(runtime.quality_bucket.clone());
        }
    }
    apply_native_freshness_quality_degradation(
        state,
        &mut degraded_reason_summary,
        &mut missing_visibility_flags,
    );

    let mut summary = EvidenceQualitySummary {
        generated_at: Timestamp::now(),
        record_count: records.len() as u32,
        weak_single_signal_count: records
            .iter()
            .filter(|record| {
                record.quality.correlation_quality_bucket == CorrelationQualityBucket::SingleSignal
                    || record.quality.evidence_strength_bucket
                        == sentinel_contracts::EvidenceStrengthBucket::WeakSingleSignal
            })
            .count() as u32,
        corroborated_count: records
            .iter()
            .filter(|record| {
                matches!(
                    record.quality.correlation_quality_bucket,
                    CorrelationQualityBucket::Corroborated | CorrelationQualityBucket::Diverse
                )
            })
            .count() as u32,
        report_suitable_count: records
            .iter()
            .filter(|record| {
                record.quality.report_suitability_bucket == SuitabilityBucket::Suitable
            })
            .count() as u32,
        export_suitable_count: records
            .iter()
            .filter(|record| {
                record.quality.export_suitability_bucket == SuitabilityBucket::Suitable
            })
            .count() as u32,
        blocked_count: records
            .iter()
            .filter(|record| {
                record.quality.report_suitability_bucket == SuitabilityBucket::Blocked
                    || record.quality.export_suitability_bucket == SuitabilityBucket::Blocked
            })
            .count() as u32,
        quality_refs: bounded_refs(
            records
                .iter()
                .map(|record| record.evidence_quality_id.clone()),
        ),
        evidence_refs: bounded_refs(
            records
                .iter()
                .filter_map(|record| record.evidence_ref.clone()),
        ),
        finding_refs: bounded_refs(
            records
                .iter()
                .filter_map(|record| record.finding_ref.clone()),
        ),
        hypothesis_refs: bounded_refs(
            records
                .iter()
                .filter_map(|record| record.hypothesis_ref.clone()),
        ),
        risk_refs: bounded_refs(records.iter().filter_map(|record| record.risk_ref.clone())),
        baseline_refs: bounded_refs(
            records
                .iter()
                .filter_map(|record| record.baseline_ref.clone()),
        ),
        incident_group_refs: bounded_refs(
            records
                .iter()
                .filter_map(|record| record.incident_group_ref.clone()),
        ),
        report_section_refs: bounded_refs(
            records
                .iter()
                .filter_map(|record| record.report_section_ref.clone()),
        ),
        export_result_refs: bounded_refs(
            records
                .iter()
                .filter_map(|record| record.export_result_ref.clone()),
        ),
        degraded_reason_summary: bounded_strings(degraded_reason_summary),
        missing_visibility_flags: bounded_strings(missing_visibility_flags),
        records,
        portable_no_retention: true,
        metadata_only: true,
        automatic_llm_calls: false,
        response_execution: false,
    };
    summary.record_count = summary.records.len() as u32;
    summary.validate().map_err(|error| {
        CoreError::new(
            sentinel_contracts::ErrorCode::InternalError,
            "evidence quality summary failed safety validation",
        )
        .with_severity(sentinel_contracts::ErrorSeverity::Error)
        .with_redacted_details(json!({ "error_redacted": safe_slug(&error.to_string()) }))
    })?;
    Ok(summary)
}

fn finding_quality_record(finding: &Finding, evidence_ref: EvidenceId) -> EvidenceQualityRecord {
    let quality_id = quality_id(
        "finding_evidence",
        &format!("{}:{evidence_ref}", finding.id()),
    );
    let mut quality =
        if finding.evidence_refs().len() > 1 && finding.confidence().value() >= 0.55 {
            QualityBreakdown::corroborated_metadata()
        } else {
            QualityBreakdown::metadata_only()
        }
        .with_quality_ref(quality_id.clone());
    quality.evidence_quality_bucket = score_bucket(finding.confidence().value());
    quality.provenance_quality_bucket = ProvenanceQualityBucket::ReferenceOnly;
    quality.freshness_bucket = FreshnessBucket::CurrentSession;
    if finding.evidence_refs().len() <= 1 {
        quality.correlation_quality_bucket = CorrelationQualityBucket::SingleSignal;
        quality.uncertainty_bucket = UncertaintyBucket::High;
        push_quality_reason(&mut quality, "weak_single_signal");
    }
    EvidenceQualityRecord {
        evidence_quality_id: quality_id,
        target_kind: EvidenceQualityTargetKind::Evidence,
        evidence_ref: Some(evidence_ref),
        finding_ref: Some(finding.id().clone()),
        hypothesis_ref: None,
        risk_ref: None,
        baseline_ref: None,
        baseline_indicator_ref: None,
        attack_ref: finding.attack_mappings().first().and_then(|mapping| {
            Some(attack_ref(
                mapping.tactic_id.as_ref()?,
                mapping
                    .subtechnique_id
                    .as_ref()
                    .or(mapping.technique_id.as_ref())?,
            ))
        }),
        graph_ref: None,
        incident_group_ref: None,
        report_section_ref: None,
        export_result_ref: None,
        fact_refs: Vec::new(),
        source_kind_category: "finding_evidence".to_string(),
        parser_family: "static_plugin_runtime".to_string(),
        detector_id: Some(safe_slug(finding.finding_type())),
        detector_confidence_bucket: score_bucket(finding.confidence().value()),
        unsafe_field_rejection_bucket: EvidenceQualityBucket::Unknown,
        malformed_skipped_backpressure_bucket: OperationalInfluenceBucket::None,
        redaction_status: RedactionStatus::Redacted,
        provenance_id: None,
        time_bucket: Timestamp::now(),
        quality,
    }
}

fn apply_native_freshness_quality_degradation(
    state: &ReadOnlyCommandState,
    degraded_reason_summary: &mut Vec<String>,
    missing_visibility_flags: &mut Vec<String>,
) {
    let Some(freshness) = state
        .native_scheduler_cycles
        .iter()
        .rev()
        .filter_map(|cycle| cycle.freshness.as_ref())
        .next()
    else {
        return;
    };
    for dimension in &freshness.dimensions {
        let label = native_dimension_label(&dimension.dimension);
        match dimension.freshness_state {
            NativeTelemetryFreshnessState::Fresh => {}
            NativeTelemetryFreshnessState::Aging => {
                degraded_reason_summary.push(format!("{label}_native_visibility_aging"));
            }
            NativeTelemetryFreshnessState::Stale => {
                degraded_reason_summary.push(format!("{label}_native_visibility_stale"));
                missing_visibility_flags.push(format!("{label}_visibility_stale"));
            }
            NativeTelemetryFreshnessState::Missing => {
                degraded_reason_summary.push(format!("{label}_native_visibility_missing"));
                missing_visibility_flags.push(format!("{label}_visibility_missing"));
            }
            NativeTelemetryFreshnessState::Unavailable => {
                degraded_reason_summary.push(format!("{label}_native_visibility_unavailable"));
                missing_visibility_flags.push(format!("{label}_visibility_unavailable"));
            }
            NativeTelemetryFreshnessState::Revoked => {
                degraded_reason_summary.push(format!("{label}_native_visibility_revoked"));
                missing_visibility_flags.push(format!("{label}_visibility_revoked"));
            }
        }
    }
}

fn native_dimension_label(dimension: &NativeTelemetryDimension) -> &'static str {
    match dimension {
        NativeTelemetryDimension::Health => "native_health",
        NativeTelemetryDimension::Service => "service",
        NativeTelemetryDimension::Process => "process_category",
        NativeTelemetryDimension::ParentCategory => "parent_category",
    }
}

fn baseline_record_quality_record(record: &BaselineRecord) -> EvidenceQualityRecord {
    let quality_id = quality_id("baseline", &record.baseline_id.to_string());
    let mut quality = record.quality.clone().with_quality_ref(quality_id.clone());
    quality.source_reliability_bucket = match record.source_reliability_bucket {
        sentinel_contracts::SourceReliabilityBucket::Unknown => {
            SourceReliabilityQualityBucket::Unknown
        }
        sentinel_contracts::SourceReliabilityBucket::Weak => SourceReliabilityQualityBucket::Weak,
        sentinel_contracts::SourceReliabilityBucket::Degraded => {
            SourceReliabilityQualityBucket::Degraded
        }
        sentinel_contracts::SourceReliabilityBucket::Stable => {
            SourceReliabilityQualityBucket::Stable
        }
        sentinel_contracts::SourceReliabilityBucket::Corroborated => {
            SourceReliabilityQualityBucket::Corroborated
        }
    };
    EvidenceQualityRecord {
        evidence_quality_id: quality_id,
        target_kind: EvidenceQualityTargetKind::BaselineRecord,
        evidence_ref: record.evidence_refs.first().cloned(),
        finding_ref: record.finding_refs.first().cloned(),
        hypothesis_ref: record.hypothesis_refs.first().cloned(),
        risk_ref: record.risk_refs.first().cloned(),
        baseline_ref: Some(record.baseline_id.clone()),
        baseline_indicator_ref: None,
        attack_ref: record
            .attack_refs
            .first()
            .map(|reference| attack_ref(&reference.tactic_id, &reference.technique_id)),
        graph_ref: None,
        incident_group_ref: None,
        report_section_ref: None,
        export_result_ref: None,
        fact_refs: bounded_refs(record.fact_refs.iter().cloned()),
        source_kind_category: safe_slug(&record.safe_label),
        parser_family: "session_baseline".to_string(),
        detector_id: None,
        detector_confidence_bucket: EvidenceQualityBucket::Low,
        unsafe_field_rejection_bucket: EvidenceQualityBucket::Unknown,
        malformed_skipped_backpressure_bucket: OperationalInfluenceBucket::None,
        redaction_status: record.redaction_status.clone(),
        provenance_id: record.provenance_refs.first().cloned(),
        time_bucket: record
            .last_seen_time_bucket
            .clone()
            .unwrap_or_else(Timestamp::now),
        quality,
    }
}

fn baseline_indicator_quality_record(indicator: &BaselineIndicator) -> EvidenceQualityRecord {
    let quality_id = quality_id("indicator", &indicator.indicator_id.to_string());
    EvidenceQualityRecord {
        evidence_quality_id: quality_id.clone(),
        target_kind: EvidenceQualityTargetKind::BaselineIndicator,
        evidence_ref: indicator.evidence_refs.first().cloned(),
        finding_ref: None,
        hypothesis_ref: indicator.hypothesis_refs.first().cloned(),
        risk_ref: None,
        baseline_ref: indicator.baseline_refs.first().cloned(),
        baseline_indicator_ref: Some(indicator.indicator_id.clone()),
        attack_ref: None,
        graph_ref: None,
        incident_group_ref: None,
        report_section_ref: None,
        export_result_ref: None,
        fact_refs: bounded_refs(indicator.fact_refs.iter().cloned()),
        source_kind_category: safe_slug(&format!("{:?}", indicator.kind)),
        parser_family: "session_baseline_indicator".to_string(),
        detector_id: None,
        detector_confidence_bucket: fusion_bucket(&indicator.confidence_bucket),
        unsafe_field_rejection_bucket: EvidenceQualityBucket::Unknown,
        malformed_skipped_backpressure_bucket: OperationalInfluenceBucket::None,
        redaction_status: RedactionStatus::Redacted,
        provenance_id: None,
        time_bucket: Timestamp::now(),
        quality: indicator.quality.clone().with_quality_ref(quality_id),
    }
}

fn incident_group_quality_record(group: &IncidentLinkedHypothesisGroup) -> EvidenceQualityRecord {
    let quality_id = quality_id("group", &group.group_id.to_string());
    EvidenceQualityRecord {
        evidence_quality_id: quality_id.clone(),
        target_kind: EvidenceQualityTargetKind::IncidentLinkedGroup,
        evidence_ref: group.evidence_refs.first().cloned(),
        finding_ref: group.finding_refs.first().cloned(),
        hypothesis_ref: group.hypothesis_refs.first().cloned(),
        risk_ref: group.risk_refs.first().cloned(),
        baseline_ref: group.baseline_refs.first().cloned(),
        baseline_indicator_ref: None,
        attack_ref: group
            .attack_refs
            .first()
            .map(|reference| attack_ref(&reference.tactic_id, &reference.technique_id)),
        graph_ref: group.graph_refs.first().cloned(),
        incident_group_ref: Some(group.group_id.clone()),
        report_section_ref: group.report_section_refs.first().cloned(),
        export_result_ref: None,
        fact_refs: bounded_refs(group.fact_refs.iter().cloned()),
        source_kind_category: "incident_linked_group".to_string(),
        parser_family: "session_incident_linking".to_string(),
        detector_id: None,
        detector_confidence_bucket: EvidenceQualityBucket::Low,
        unsafe_field_rejection_bucket: EvidenceQualityBucket::Unknown,
        malformed_skipped_backpressure_bucket: OperationalInfluenceBucket::None,
        redaction_status: RedactionStatus::Redacted,
        provenance_id: None,
        time_bucket: group
            .last_updated_bucket
            .clone()
            .unwrap_or_else(Timestamp::now),
        quality: group.quality.clone().with_quality_ref(quality_id),
    }
}

fn report_section_quality_record(section: &ReportSection) -> EvidenceQualityRecord {
    let quality_id = quality_id("report_section", &section.section_id.to_string());
    let mut quality = section.quality.clone().with_quality_ref(quality_id.clone());
    if !section.redaction_summary.passed {
        quality = QualityBreakdown::blocked_by_redaction().with_quality_ref(quality_id.clone());
    }
    EvidenceQualityRecord {
        evidence_quality_id: quality_id,
        target_kind: EvidenceQualityTargetKind::ReportSection,
        evidence_ref: section.evidence_refs.first().cloned(),
        finding_ref: None,
        hypothesis_ref: None,
        risk_ref: None,
        baseline_ref: None,
        baseline_indicator_ref: None,
        attack_ref: None,
        graph_ref: None,
        incident_group_ref: None,
        report_section_ref: Some(section.section_id.clone()),
        export_result_ref: None,
        fact_refs: Vec::new(),
        source_kind_category: safe_slug(&format!("{:?}", section.section_type)),
        parser_family: "report_generation".to_string(),
        detector_id: None,
        detector_confidence_bucket: EvidenceQualityBucket::Low,
        unsafe_field_rejection_bucket: if section.redaction_summary.passed {
            EvidenceQualityBucket::Unknown
        } else {
            EvidenceQualityBucket::Blocked
        },
        malformed_skipped_backpressure_bucket: OperationalInfluenceBucket::None,
        redaction_status: if section.redaction_summary.passed {
            RedactionStatus::Redacted
        } else {
            RedactionStatus::Suppressed
        },
        provenance_id: None,
        time_bucket: Timestamp::now(),
        quality,
    }
}

fn push_record(
    records: &mut Vec<EvidenceQualityRecord>,
    record: EvidenceQualityRecord,
) -> CommandResult<()> {
    if records.len() >= MAX_QUALITY_RECORDS {
        return Ok(());
    }
    record.validate().map_err(|error| {
        CoreError::new(
            sentinel_contracts::ErrorCode::InternalError,
            "evidence quality record failed safety validation",
        )
        .with_severity(sentinel_contracts::ErrorSeverity::Error)
        .with_redacted_details(json!({ "error_redacted": safe_slug(&error.to_string()) }))
    })?;
    records.push(record);
    Ok(())
}

fn score_bucket(value: f32) -> EvidenceQualityBucket {
    if value >= 0.75 {
        EvidenceQualityBucket::High
    } else if value >= 0.55 {
        EvidenceQualityBucket::Medium
    } else if value > 0.0 {
        EvidenceQualityBucket::Low
    } else {
        EvidenceQualityBucket::Unknown
    }
}

fn fusion_bucket(bucket: &sentinel_contracts::FusionConfidenceBucket) -> EvidenceQualityBucket {
    match bucket {
        sentinel_contracts::FusionConfidenceBucket::Unknown => EvidenceQualityBucket::Unknown,
        sentinel_contracts::FusionConfidenceBucket::Low => EvidenceQualityBucket::Low,
        sentinel_contracts::FusionConfidenceBucket::Medium => EvidenceQualityBucket::Medium,
    }
}

fn attack_bucket(bucket: &AttackCoverageConfidenceBucket) -> EvidenceQualityBucket {
    match bucket {
        AttackCoverageConfidenceBucket::Unknown => EvidenceQualityBucket::Unknown,
        AttackCoverageConfidenceBucket::Low => EvidenceQualityBucket::Low,
        AttackCoverageConfidenceBucket::Medium => EvidenceQualityBucket::Medium,
        AttackCoverageConfidenceBucket::High => EvidenceQualityBucket::High,
    }
}

fn push_quality_reason(quality: &mut QualityBreakdown, reason: &str) {
    let reason = safe_slug(reason);
    if !quality.degraded_reasons.contains(&reason) && quality.degraded_reasons.len() < 32 {
        quality.degraded_reasons.push(reason);
    }
}

fn quality_id(prefix: &str, key: &str) -> EvidenceQualityId {
    let digest = Sha256::digest(format!("{prefix}:{key}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    EvidenceQualityId::from_uuid(Uuid::from_bytes(bytes))
}

fn attack_ref(tactic_id: &str, technique_id: &str) -> String {
    format!("{}:{}", safe_slug(tactic_id), safe_slug(technique_id))
}

fn bounded_refs<T: Clone + ToString>(values: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.to_string()))
        .take(MAX_QUALITY_REFS)
        .collect()
}

fn bounded_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .map(|value| safe_slug(&value))
        .filter(|value| !value.is_empty())
        .filter(|value| seen.insert(value.clone()))
        .take(MAX_QUALITY_REFS)
        .collect()
}

fn safe_slug(value: &str) -> String {
    let mut normalized = value.to_ascii_lowercase();
    for (from, to) in [
        ("credential", "auth_material"),
        ("token", "auth_material"),
        ("secret", "redacted_material"),
        ("password", "redacted_material"),
        ("payload", "content_summary"),
        ("raw_log", "redacted_log"),
        ("raw_json", "redacted_json"),
        ("raw_packet", "redacted_packet"),
        ("username", "identity_label"),
        ("email", "identity_label"),
        ("tenant_id", "provider_scope"),
        ("account_id", "provider_scope"),
        ("device_id", "device_scope"),
        ("command_line", "command_metadata"),
        ("private_marker", "redacted_marker"),
        ("confirmed_compromise", "possible_metadata_pattern"),
        ("credential_theft", "auth_material_abuse"),
        ("host_compromise", "host_visibility_required"),
        ("malware_execution", "execution_visibility_required"),
        ("process_attribution", "native_visibility_required"),
        ("filename", "file_ref"),
        ("local_path", "path_ref"),
    ] {
        normalized = normalized.replace(from, to);
    }
    let mut slug = normalized
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | ':' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    while slug.contains("__") {
        slug = slug.replace("__", "_");
    }
    slug = slug.trim_matches('_').to_string();
    if slug.is_empty() {
        "redacted_quality".to_string()
    } else {
        slug.truncate(120);
        slug
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        Finding, FindingExplanation, PluginId, QualityScore, SecuritySeverity,
    };

    #[test]
    fn quality_summary_marks_single_signal_and_remains_safe() {
        let evidence_id = EvidenceId::new_v4();
        let finding = Finding::new(
            "portable.api_security_lite.status_error_pattern",
            PluginId::new_v4(),
            vec![evidence_id.clone()],
            FindingExplanation::new("redacted metadata finding").expect("explanation"),
        )
        .expect("finding")
        .with_confidence(QualityScore::new(0.45).expect("confidence"))
        .with_severity(SecuritySeverity::Medium);
        let state = ReadOnlyCommandState::bootstrap()
            .expect("state")
            .with_findings(vec![finding]);

        let summary = build_evidence_quality_summary(&state).expect("quality");
        assert!(summary.record_count >= 1);
        assert!(summary.weak_single_signal_count >= 1);
        assert!(summary
            .records
            .iter()
            .any(|record| record.evidence_ref.as_ref() == Some(&evidence_id)));
        assert!(!summary.automatic_llm_calls);
        assert!(!summary.response_execution);
        let serialized = serde_json::to_string(&summary).expect("serialize");
        for marker in [
            "https://",
            "session_token",
            "authorization:",
            "raw_payload",
            "alice@example",
            "confirmed_compromise",
        ] {
            assert!(!serialized.contains(marker), "{marker} leaked");
        }
    }

    #[test]
    fn native_permission_status_alone_does_not_raise_quality() {
        let state = ReadOnlyCommandState::bootstrap().expect("state");
        let summary = build_evidence_quality_summary(&state).expect("quality");
        assert!(summary.records.iter().all(|record| {
            record.quality.evidence_quality_bucket != EvidenceQualityBucket::High
        }));
    }
}
