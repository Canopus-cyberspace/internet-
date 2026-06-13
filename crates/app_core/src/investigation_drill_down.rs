use crate::baseline_read_models::build_durable_baseline_summary;
use crate::read_commands::ReadOnlyCommandState;
use sentinel_capabilities::attack_hypothesis_catalog;
use sentinel_contracts::{
    AttackHypothesisDefinition, AttackHypothesisRecord, BaselineAttackTechniqueRef,
    BaselineConfidenceTrendBucket, BaselineCountBucket, BaselineDrillDownDetail, BaselineIndicator,
    BaselineRecord, BaselineRecordId, BaselineScope, CommandResult, CoreError, ErrorCode,
    ErrorSeverity, EvidenceId, ExportResultId, FactRequirementExplanation, FusionConfidenceBucket,
    HypothesisExplanationDetail, IncidentGroupInvestigationDetail, IncidentLinkedHypothesisGroup,
    IncidentTimelineEntry, InvestigationDrillDownSummary, InvestigationRequirementStatus,
    InvestigationSuggestion, InvestigationSuggestionKind, LlmStoryAvailabilityDetail,
    ReportSectionId, ReportSectionType, SecurityFact, SourceReliabilityBucket,
    SourceReliabilityExplanation, SourceReliabilitySummary, TimelineDrillDownDetail,
    MAX_INVESTIGATION_ITEMS, MAX_INVESTIGATION_REFS,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

pub fn build_investigation_drill_down_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<InvestigationDrillDownSummary> {
    let baseline = build_durable_baseline_summary(state)?;
    let definitions = attack_hypothesis_catalog().map_err(|error| {
        drill_down_error(
            "failed to load bounded hypothesis explanation catalog",
            error.to_string(),
        )
    })?;
    let definition_by_id = definitions
        .iter()
        .map(|definition| (definition.hypothesis_id.as_str(), definition))
        .collect::<BTreeMap<_, _>>();
    let fact_by_id = state
        .security_facts
        .items
        .iter()
        .map(|fact| (fact.fact_id.to_string(), fact))
        .collect::<BTreeMap<_, _>>();

    let hypotheses = state
        .attack_hypotheses
        .items
        .iter()
        .take(MAX_INVESTIGATION_ITEMS)
        .map(|hypothesis| {
            build_hypothesis_explanation(
                state,
                hypothesis,
                definition_by_id
                    .get(hypothesis.definition_id.as_str())
                    .copied(),
                &fact_by_id,
                &baseline.records,
                &baseline.indicators,
                &baseline.incident_groups,
            )
        })
        .collect::<Vec<_>>();
    let baselines = baseline
        .records
        .iter()
        .take(MAX_INVESTIGATION_ITEMS)
        .map(|record| {
            build_baseline_detail(
                state,
                record,
                &baseline.indicators,
                &baseline.incident_groups,
            )
        })
        .collect::<Vec<_>>();
    let incident_groups = baseline
        .incident_groups
        .iter()
        .take(MAX_INVESTIGATION_ITEMS)
        .map(|group| {
            build_group_detail(
                state,
                group,
                &baseline.indicators,
                &baseline.incident_timeline,
                &baseline.source_reliability,
            )
        })
        .collect::<Vec<_>>();
    let timeline = baseline
        .incident_timeline
        .iter()
        .take(MAX_INVESTIGATION_ITEMS)
        .map(|entry| build_timeline_detail(entry, &baseline.incident_groups))
        .collect::<Vec<_>>();
    let source_reliability = baseline
        .source_reliability
        .iter()
        .take(MAX_INVESTIGATION_ITEMS)
        .map(|source| {
            build_source_reliability_explanation(
                source,
                &baseline.records,
                &baseline.incident_groups,
                &baseline.incident_timeline,
            )
        })
        .collect::<Vec<_>>();
    let report_refs = bounded_refs(
        hypotheses
            .iter()
            .flat_map(|detail| detail.report_refs.iter().cloned())
            .chain(
                baselines
                    .iter()
                    .flat_map(|detail| detail.report_refs.iter().cloned()),
            )
            .chain(
                incident_groups
                    .iter()
                    .flat_map(|detail| detail.report_refs.iter().cloned()),
            )
            .chain(
                timeline
                    .iter()
                    .flat_map(|detail| detail.report_refs.iter().cloned()),
            ),
    );
    let export_refs = bounded_refs(
        hypotheses
            .iter()
            .flat_map(|detail| detail.export_refs.iter().cloned())
            .chain(
                baselines
                    .iter()
                    .flat_map(|detail| detail.export_refs.iter().cloned()),
            )
            .chain(
                incident_groups
                    .iter()
                    .flat_map(|detail| detail.export_refs.iter().cloned()),
            ),
    );

    let summary = InvestigationDrillDownSummary {
        generated_at: sentinel_contracts::Timestamp::now(),
        hypothesis_count: hypotheses.len() as u32,
        baseline_count: baselines.len() as u32,
        incident_group_count: incident_groups.len() as u32,
        timeline_count: timeline.len() as u32,
        source_reliability_count: source_reliability.len() as u32,
        hypotheses,
        baselines,
        incident_groups,
        timeline,
        source_reliability,
        report_refs,
        export_refs,
        suggestions: advisory_suggestions(),
        quality: baseline.quality.clone(),
        portable_no_retention: true,
        metadata_only: true,
        automatic_llm_calls: false,
        response_execution: false,
    };
    summary.validate().map_err(|error| {
        drill_down_error(
            "investigation drill-down failed safety validation",
            error.to_string(),
        )
    })?;
    Ok(summary)
}

fn build_hypothesis_explanation(
    state: &ReadOnlyCommandState,
    hypothesis: &AttackHypothesisRecord,
    definition: Option<&AttackHypothesisDefinition>,
    fact_by_id: &BTreeMap<String, &SecurityFact>,
    baseline_records: &[BaselineRecord],
    indicators: &[BaselineIndicator],
    groups: &[IncidentLinkedHypothesisGroup],
) -> HypothesisExplanationDetail {
    let facts = hypothesis
        .fact_refs
        .iter()
        .filter_map(|fact_ref| fact_by_id.get(&fact_ref.to_string()).copied())
        .collect::<Vec<_>>();
    let baseline_refs = bounded_refs(baseline_records.iter().filter_map(|record| {
        if record
            .hypothesis_refs
            .contains(&hypothesis.hypothesis_record_id)
            || record
                .fact_refs
                .iter()
                .any(|fact_ref| hypothesis.fact_refs.contains(fact_ref))
        {
            Some(record.baseline_id.clone())
        } else {
            None
        }
    }));
    let indicator_refs = indicator_refs_for_baselines(indicators, &baseline_refs);
    let related_groups = groups
        .iter()
        .filter(|group| {
            group
                .hypothesis_refs
                .contains(&hypothesis.hypothesis_record_id)
        })
        .collect::<Vec<_>>();
    let incident_id = related_groups
        .iter()
        .find_map(|group| group.incident_id.clone());
    let report_refs = report_refs_for_evidence(state, &hypothesis.evidence_refs);
    let export_refs = export_refs_for_evidence(state, &hypothesis.evidence_refs);

    HypothesisExplanationDetail {
        hypothesis_id: hypothesis.hypothesis_record_id.clone(),
        family: safe_slug(&hypothesis.category),
        version: safe_slug(&hypothesis.version),
        confidence_bucket: hypothesis.confidence_bucket.clone(),
        confidence_trend: hypothesis_confidence_trend(hypothesis, baseline_records),
        supporting_fact_categories: bounded_strings(
            facts.iter().map(|fact| safe_slug(&fact.category)),
        ),
        required_fact_status: definition
            .map(|definition| {
                definition
                    .required_facts
                    .iter()
                    .map(|requirement| fact_requirement(requirement, &facts, true))
                    .collect()
            })
            .unwrap_or_default(),
        optional_fact_status: definition
            .map(|definition| {
                definition
                    .optional_facts
                    .iter()
                    .map(|requirement| fact_requirement(requirement, &facts, false))
                    .collect()
            })
            .unwrap_or_default(),
        disqualifier_status: if hypothesis.benign_baseline_indicators.is_empty() {
            InvestigationRequirementStatus::NotObserved
        } else {
            InvestigationRequirementStatus::Matched
        },
        evidence_count_bucket: count_bucket(hypothesis.evidence_refs.len()),
        source_count_bucket: count_bucket(
            facts
                .iter()
                .map(|fact| fact.sampler_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
        ),
        correlation_time_bucket: correlation_time_bucket(&facts),
        provider_category_relation: provider_relation(&facts),
        route_endpoint_relation: route_relation(&facts),
        baseline_refs,
        indicator_refs,
        evidence_refs: bounded_refs(hypothesis.evidence_refs.iter().cloned()),
        fact_refs: bounded_refs(hypothesis.fact_refs.iter().cloned()),
        finding_refs: bounded_refs(hypothesis.finding_refs.iter().cloned()),
        risk_refs: bounded_refs(hypothesis.risk_refs.iter().cloned()),
        attack_refs: bounded_refs(hypothesis.attack_candidates.iter().map(|candidate| {
            BaselineAttackTechniqueRef {
                tactic_id: candidate.tactic_id.clone(),
                technique_id: candidate.technique_id.clone(),
                attack_version: candidate.attack_version.clone(),
                confidence_bucket: candidate.confidence.clone(),
                required_visibility: safe_slug(&candidate.required_visibility),
            }
        })),
        graph_refs: bounded_refs(hypothesis.graph_hint_refs.iter().cloned()),
        report_refs,
        export_refs,
        story_availability: story_availability(
            state,
            &hypothesis.evidence_refs,
            &hypothesis.finding_refs,
            incident_id,
        ),
        degraded_reason: hypothesis
            .degraded_reason
            .as_ref()
            .map(|value| safe_slug(value)),
        missing_visibility_flags: bounded_strings(
            hypothesis
                .missing_visibility_flags
                .iter()
                .map(|value| safe_slug(value)),
        ),
        suggested_questions: suggested_questions(),
        suggestions: advisory_suggestions(),
        summary_redacted: "Evidence-backed metadata hypothesis explanation".to_string(),
        quality: hypothesis.quality.clone(),
    }
}

fn build_baseline_detail(
    state: &ReadOnlyCommandState,
    record: &BaselineRecord,
    indicators: &[BaselineIndicator],
    groups: &[IncidentLinkedHypothesisGroup],
) -> BaselineDrillDownDetail {
    let related_indicators = indicators
        .iter()
        .filter(|indicator| indicator.baseline_refs.contains(&record.baseline_id))
        .collect::<Vec<_>>();
    BaselineDrillDownDetail {
        baseline_id: record.baseline_id.clone(),
        scope: record.scope.clone(),
        scope_category: safe_slug(&record.safe_label),
        indicator_kinds: related_indicators
            .iter()
            .map(|indicator| indicator.kind.clone())
            .take(MAX_INVESTIGATION_ITEMS)
            .collect(),
        indicator_refs: bounded_refs(
            related_indicators
                .iter()
                .map(|indicator| indicator.indicator_id.clone()),
        ),
        count_bucket: record.count_bucket.clone(),
        rarity_bucket: record.rarity_bucket.clone(),
        recurrence_bucket: record.recurrence_bucket.clone(),
        first_seen_bucket: record.first_seen_time_bucket.clone(),
        last_seen_bucket: record.last_seen_time_bucket.clone(),
        trend_bucket: record.trend_bucket.clone(),
        confidence_trend: record.confidence_trend_bucket.clone(),
        confidence_bucket: baseline_confidence(record),
        source_reliability_bucket: record.source_reliability_bucket.clone(),
        hypothesis_refs: bounded_refs(record.hypothesis_refs.iter().cloned()),
        incident_group_refs: bounded_refs(groups.iter().filter_map(|group| {
            if group.baseline_refs.contains(&record.baseline_id) {
                Some(group.group_id.clone())
            } else {
                None
            }
        })),
        evidence_refs: bounded_refs(record.evidence_refs.iter().cloned()),
        fact_refs: bounded_refs(record.fact_refs.iter().cloned()),
        finding_refs: bounded_refs(record.finding_refs.iter().cloned()),
        risk_refs: bounded_refs(record.risk_refs.iter().cloned()),
        provenance_refs: bounded_refs(record.provenance_refs.iter().cloned()),
        attack_refs: bounded_refs(record.attack_refs.iter().cloned()),
        report_refs: report_refs_for_evidence(state, &record.evidence_refs),
        export_refs: export_refs_for_evidence(state, &record.evidence_refs),
        degraded_reason: record
            .degraded_reason
            .as_ref()
            .map(|value| safe_slug(value)),
        missing_visibility_flags: bounded_strings(
            record
                .missing_visibility_flags
                .iter()
                .map(|value| safe_slug(value)),
        ),
        suggestions: advisory_suggestions(),
        summary_redacted: "Bounded session baseline drill-down".to_string(),
        quality: record.quality.clone(),
    }
}

fn build_group_detail(
    state: &ReadOnlyCommandState,
    group: &IncidentLinkedHypothesisGroup,
    indicators: &[BaselineIndicator],
    timeline: &[IncidentTimelineEntry],
    source_reliability: &[SourceReliabilitySummary],
) -> IncidentGroupInvestigationDetail {
    let timeline_entries = timeline
        .iter()
        .filter(|entry| entry.group_id == group.group_id)
        .collect::<Vec<_>>();
    let source_refs = bounded_refs(
        timeline_entries
            .iter()
            .flat_map(|entry| entry.source_health_refs.iter().cloned()),
    );
    let source_buckets = source_reliability
        .iter()
        .filter(|source| source_refs.contains(&source.source_id))
        .map(|source| source.reliability_bucket.clone())
        .take(MAX_INVESTIGATION_ITEMS)
        .collect::<Vec<_>>();
    IncidentGroupInvestigationDetail {
        group_id: group.group_id.clone(),
        incident_id: group.incident_id.clone(),
        hypothesis_refs: bounded_refs(group.hypothesis_refs.iter().cloned()),
        baseline_refs: bounded_refs(group.baseline_refs.iter().cloned()),
        indicator_refs: indicator_refs_for_baselines(indicators, &group.baseline_refs),
        timeline_refs: bounded_refs(
            timeline_entries
                .iter()
                .map(|entry| entry.timeline_entry_id.clone()),
        ),
        evidence_refs: bounded_refs(group.evidence_refs.iter().cloned()),
        fact_refs: bounded_refs(group.fact_refs.iter().cloned()),
        finding_refs: bounded_refs(group.finding_refs.iter().cloned()),
        risk_refs: bounded_refs(group.risk_refs.iter().cloned()),
        attack_refs: bounded_refs(group.attack_refs.iter().cloned()),
        graph_refs: bounded_refs(group.graph_refs.iter().cloned()),
        report_refs: bounded_refs(
            group
                .report_section_refs
                .iter()
                .cloned()
                .chain(report_refs_for_evidence(state, &group.evidence_refs)),
        ),
        export_refs: export_refs_for_evidence(state, &group.evidence_refs),
        source_reliability_refs: source_refs,
        source_reliability_buckets: source_buckets,
        confidence_trend: group.confidence_trend.clone(),
        severity_risk_trend: group.severity_trend.clone(),
        first_seen_bucket: group.first_seen_bucket.clone(),
        last_updated_bucket: group.last_updated_bucket.clone(),
        story_availability: story_availability(
            state,
            &group.evidence_refs,
            &group.finding_refs,
            group.incident_id.clone(),
        ),
        degraded_reason: group.degraded_reason.as_ref().map(|value| safe_slug(value)),
        missing_visibility_flags: bounded_strings(
            group
                .missing_visibility_flags
                .iter()
                .map(|value| safe_slug(value)),
        ),
        suggestions: advisory_suggestions(),
        summary_redacted: "Incident-linked metadata hypothesis group".to_string(),
        quality: group.quality.clone(),
        weak_merge_warning: group.weak_merge_warning,
        broad_provider_only_merge_rejected: group.broad_provider_only_merge_rejected,
    }
}

fn build_timeline_detail(
    entry: &IncidentTimelineEntry,
    groups: &[IncidentLinkedHypothesisGroup],
) -> TimelineDrillDownDetail {
    let report_refs = groups
        .iter()
        .find(|group| group.group_id == entry.group_id)
        .map(|group| group.report_section_refs.clone())
        .unwrap_or_default();
    TimelineDrillDownDetail {
        timeline_entry_id: entry.timeline_entry_id.clone(),
        incident_id: entry.incident_id.clone(),
        group_id: entry.group_id.clone(),
        time_bucket: entry.time_bucket.clone(),
        event_category: safe_slug(&entry.event_category),
        hypothesis_refs: bounded_refs(entry.hypothesis_refs.iter().cloned()),
        baseline_refs: bounded_refs(entry.baseline_refs.iter().cloned()),
        evidence_refs: bounded_refs(entry.evidence_refs.iter().cloned()),
        finding_refs: bounded_refs(entry.finding_refs.iter().cloned()),
        risk_refs: bounded_refs(entry.risk_refs.iter().cloned()),
        attack_refs: bounded_refs(entry.attack_refs.iter().cloned()),
        source_health_refs: bounded_refs(entry.source_health_refs.iter().cloned()),
        report_refs: bounded_refs(report_refs),
        confidence_bucket: entry.confidence_bucket.clone(),
        degraded_reason: entry.degraded_reason.as_ref().map(|value| safe_slug(value)),
        summary_redacted: safe_slug(&entry.summary_redacted),
        quality: entry.quality.clone(),
    }
}

fn build_source_reliability_explanation(
    source: &SourceReliabilitySummary,
    records: &[BaselineRecord],
    groups: &[IncidentLinkedHypothesisGroup],
    timeline: &[IncidentTimelineEntry],
) -> SourceReliabilityExplanation {
    let timeline_refs = bounded_refs(timeline.iter().filter_map(|entry| {
        if entry.source_health_refs.contains(&source.source_id) {
            Some(entry.timeline_entry_id.clone())
        } else {
            None
        }
    }));
    let related_group_ids = timeline
        .iter()
        .filter(|entry| entry.source_health_refs.contains(&source.source_id))
        .map(|entry| entry.group_id.to_string())
        .collect::<BTreeSet<_>>();
    SourceReliabilityExplanation {
        source_id: source.source_id.clone(),
        source_health_state: safe_slug(&source.source_health_state),
        reliability_bucket: source.reliability_bucket.clone(),
        sampled_count_bucket: source.sampled_count_bucket.clone(),
        malformed_count_bucket: source.malformed_count_bucket.clone(),
        backpressure_count_bucket: source.backpressure_count_bucket.clone(),
        confidence_impact: reliability_confidence_impact(&source.reliability_bucket),
        baseline_refs: bounded_refs(records.iter().filter_map(|record| {
            if record.scope == BaselineScope::SourceId {
                Some(record.baseline_id.clone())
            } else {
                None
            }
        })),
        incident_group_refs: bounded_refs(groups.iter().filter_map(|group| {
            if related_group_ids.contains(&group.group_id.to_string()) {
                Some(group.group_id.clone())
            } else {
                None
            }
        })),
        timeline_refs,
        evidence_refs: bounded_refs(source.evidence_refs.iter().cloned()),
        degraded_reason: source
            .degraded_reason
            .as_ref()
            .map(|value| safe_slug(value)),
        missing_visibility_flags: if matches!(
            source.reliability_bucket,
            SourceReliabilityBucket::Weak
                | SourceReliabilityBucket::Degraded
                | SourceReliabilityBucket::Unknown
        ) {
            vec!["source_visibility_reduced".to_string()]
        } else {
            Vec::new()
        },
        suggestions: advisory_suggestions(),
        summary_redacted: "Source reliability affects confidence only".to_string(),
        quality: source.quality.clone(),
    }
}

fn fact_requirement(
    requirement: &sentinel_contracts::HypothesisFactRequirement,
    facts: &[&SecurityFact],
    required: bool,
) -> FactRequirementExplanation {
    let matched = facts
        .iter()
        .filter(|fact| {
            fact.layer == requirement.layer
                && (requirement.categories.is_empty()
                    || requirement
                        .categories
                        .iter()
                        .any(|category| fact.category.contains(category)))
        })
        .count();
    FactRequirementExplanation {
        layer: requirement.layer.clone(),
        categories: if requirement.categories.is_empty() {
            vec!["any_safe_category".to_string()]
        } else {
            bounded_strings(requirement.categories.iter().map(|value| safe_slug(value)))
        },
        required,
        status: if matched > 0 {
            InvestigationRequirementStatus::Matched
        } else {
            InvestigationRequirementStatus::Missing
        },
        matched_count_bucket: count_bucket(matched),
    }
}

fn story_availability(
    state: &ReadOnlyCommandState,
    evidence_refs: &[EvidenceId],
    finding_refs: &[sentinel_contracts::FindingId],
    incident_id: Option<sentinel_contracts::IncidentId>,
) -> LlmStoryAvailabilityDetail {
    let incident = incident_id.as_ref().and_then(|incident_id| {
        state
            .incidents
            .items
            .iter()
            .find(|incident| incident.id() == incident_id)
    });
    let alert_ref = incident
        .and_then(|incident| incident.alert_refs().first().cloned())
        .or_else(|| {
            state.alerts.items.iter().find_map(|alert| {
                if alert
                    .finding_refs()
                    .iter()
                    .any(|finding_id| finding_refs.contains(finding_id))
                {
                    Some(alert.id().clone())
                } else {
                    None
                }
            })
        });
    let evidence = evidence_refs
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let story_refs = bounded_refs(state.llm_alert_stories.items.iter().filter_map(|story| {
        let shares_evidence = story
            .evidence_refs
            .iter()
            .any(|evidence_ref| evidence.contains(&evidence_ref.to_string()));
        if shares_evidence || story.incident_ref == incident_id {
            Some(story.story_id.clone())
        } else {
            None
        }
    }));
    LlmStoryAvailabilityDetail {
        existing_story_available: !story_refs.is_empty(),
        story_refs,
        alert_ref: alert_ref.clone(),
        incident_ref: incident_id,
        bounded_input_available: !evidence_refs.is_empty() && alert_ref.is_some(),
        explicit_user_action_required: true,
        automatic_generation: false,
    }
}

fn report_refs_for_evidence(
    state: &ReadOnlyCommandState,
    evidence_refs: &[EvidenceId],
) -> Vec<ReportSectionId> {
    let evidence = evidence_refs
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    bounded_refs(state.reports.items.iter().flat_map(|report| {
        report.sections.iter().filter_map(|section| {
            if section
                .evidence_refs
                .iter()
                .any(|evidence_ref| evidence.contains(&evidence_ref.to_string()))
                || section.section_type == ReportSectionType::BaselineSummary
                || section.section_type == ReportSectionType::InvestigationDrillDown
            {
                Some(section.section_id.clone())
            } else {
                None
            }
        })
    }))
}

fn export_refs_for_evidence(
    state: &ReadOnlyCommandState,
    evidence_refs: &[EvidenceId],
) -> Vec<ExportResultId> {
    let evidence = evidence_refs
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    bounded_refs(state.export_history.records().iter().filter_map(|record| {
        if record
            .evidence_refs
            .iter()
            .any(|evidence_ref| evidence.contains(&evidence_ref.to_string()))
        {
            Some(record.export_result_id.clone())
        } else {
            None
        }
    }))
}

fn indicator_refs_for_baselines(
    indicators: &[BaselineIndicator],
    baseline_refs: &[BaselineRecordId],
) -> Vec<sentinel_contracts::BaselineIndicatorId> {
    bounded_refs(indicators.iter().filter_map(|indicator| {
        if indicator
            .baseline_refs
            .iter()
            .any(|baseline_id| baseline_refs.contains(baseline_id))
        {
            Some(indicator.indicator_id.clone())
        } else {
            None
        }
    }))
}

fn hypothesis_confidence_trend(
    hypothesis: &AttackHypothesisRecord,
    records: &[BaselineRecord],
) -> BaselineConfidenceTrendBucket {
    records
        .iter()
        .find(|record| {
            record
                .hypothesis_refs
                .contains(&hypothesis.hypothesis_record_id)
        })
        .map(|record| record.confidence_trend_bucket.clone())
        .unwrap_or_else(|| {
            if hypothesis.degraded_reason.is_some() {
                BaselineConfidenceTrendBucket::Degraded
            } else if hypothesis.confidence_bucket == FusionConfidenceBucket::Medium {
                BaselineConfidenceTrendBucket::StableMedium
            } else {
                BaselineConfidenceTrendBucket::StableLow
            }
        })
}

fn baseline_confidence(record: &BaselineRecord) -> FusionConfidenceBucket {
    if record.evidence_refs.is_empty() && record.fact_refs.is_empty() {
        FusionConfidenceBucket::Unknown
    } else if record.degraded_reason.is_none()
        && matches!(
            record.source_reliability_bucket,
            SourceReliabilityBucket::Stable | SourceReliabilityBucket::Corroborated
        )
        && record.evidence_refs.len() > 1
    {
        FusionConfidenceBucket::Medium
    } else {
        FusionConfidenceBucket::Low
    }
}

fn reliability_confidence_impact(
    reliability: &SourceReliabilityBucket,
) -> BaselineConfidenceTrendBucket {
    match reliability {
        SourceReliabilityBucket::Stable | SourceReliabilityBucket::Corroborated => {
            BaselineConfidenceTrendBucket::StableMedium
        }
        SourceReliabilityBucket::Weak | SourceReliabilityBucket::Degraded => {
            BaselineConfidenceTrendBucket::Degraded
        }
        SourceReliabilityBucket::Unknown => BaselineConfidenceTrendBucket::Unknown,
    }
}

fn correlation_time_bucket(facts: &[&SecurityFact]) -> String {
    let buckets = facts
        .iter()
        .map(|fact| fact.time_bucket.to_string())
        .collect::<BTreeSet<_>>();
    match buckets.len() {
        0 => "time_bucket_unavailable",
        1 => "single_time_bucket",
        _ => "bounded_session_window",
    }
    .to_string()
}

fn provider_relation(facts: &[&SecurityFact]) -> String {
    relation_bucket(
        facts.iter().filter_map(|fact| {
            fact.provider_service_category
                .as_ref()
                .or(fact.saas_cloud_category.as_ref())
        }),
        "provider_category",
    )
}

fn route_relation(facts: &[&SecurityFact]) -> String {
    relation_bucket(
        facts
            .iter()
            .filter_map(|fact| fact.route_fingerprint.as_ref()),
        "route_fingerprint",
    )
}

fn relation_bucket<'a>(values: impl Iterator<Item = &'a String>, label: &str) -> String {
    let values = values
        .map(|value| safe_slug(value))
        .collect::<BTreeSet<_>>();
    match values.len() {
        0 => format!("{label}_unavailable"),
        1 => format!("shared_{label}"),
        _ => format!("mixed_{label}"),
    }
}

fn suggested_questions() -> Vec<String> {
    vec![
        "Which evidence references support this metadata hypothesis".to_string(),
        "Is the pattern first seen rare or repeated in this session".to_string(),
        "Does reduced source health lower confidence".to_string(),
        "Which ATT&CK references remain degraded by missing visibility".to_string(),
    ]
}

fn advisory_suggestions() -> Vec<InvestigationSuggestion> {
    [
        (
            InvestigationSuggestionKind::ReviewEvidenceRefs,
            "Review linked evidence references before drawing conclusions",
        ),
        (
            InvestigationSuggestionKind::CompareBaselineIndicators,
            "Compare first seen rare and repeated session indicators",
        ),
        (
            InvestigationSuggestionKind::VerifySourceHealth,
            "Verify source health and missing visibility context",
        ),
        (
            InvestigationSuggestionKind::InspectAttackCoverage,
            "Inspect ATT&CK coverage and confidence limits",
        ),
        (
            InvestigationSuggestionKind::ReviewProviderCategoryContext,
            "Review provider category and route relationship context",
        ),
        (
            InvestigationSuggestionKind::GenerateStoryManually,
            "Generate an alert story manually only when configured",
        ),
        (
            InvestigationSuggestionKind::ExportReportManually,
            "Export a redacted report manually when needed",
        ),
        (
            InvestigationSuggestionKind::ConsiderAuthorizedVisibility,
            "Consider authorized visibility in a future approved workflow",
        ),
    ]
    .into_iter()
    .map(|(kind, summary_redacted)| InvestigationSuggestion {
        kind,
        summary_redacted: summary_redacted.to_string(),
        advisory_only: true,
        automatic_action: false,
    })
    .collect()
}

fn count_bucket(count: usize) -> BaselineCountBucket {
    match count {
        0 => BaselineCountBucket::None,
        1 => BaselineCountBucket::Single,
        2..=4 => BaselineCountBucket::Low,
        5..=9 => BaselineCountBucket::Medium,
        _ => BaselineCountBucket::High,
    }
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
        ("host_compromise", "host_risk_context"),
        ("malware_execution", "execution_visibility_required"),
        ("process_attribution", "native_visibility_required"),
        ("full_capture", "capture_visibility_required"),
        ("response_execution", "recommendation_only"),
        ("active_scan", "manual_review"),
        ("firewall_change", "future_authorized_action"),
        ("account_disable", "future_authorized_action"),
        ("host_isolation", "future_authorized_action"),
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
        "redacted_category".to_string()
    } else {
        slug.truncate(120);
        slug
    }
}

fn bounded_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut bounded = values
        .into_iter()
        .map(|value| safe_slug(&value))
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    bounded.truncate(MAX_INVESTIGATION_REFS);
    bounded
}

fn bounded_refs<T: Clone + PartialEq>(values: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut bounded = Vec::new();
    for value in values {
        if bounded.len() >= MAX_INVESTIGATION_REFS {
            break;
        }
        if !bounded.contains(&value) {
            bounded.push(value);
        }
    }
    bounded
}

fn drill_down_error(summary: &'static str, error: String) -> CoreError {
    CoreError::new(ErrorCode::InternalError, summary)
        .with_severity(ErrorSeverity::Error)
        .with_redacted_details(json!({ "error_redacted": safe_slug(&error) }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        AttackHypothesisId, AttackHypothesisRecord, EvidenceId, FusionAttackCandidate, GraphHintId,
        QualityBreakdown, QualityScore, RedactionStatus, SecurityFact, SecurityLayer, Timestamp,
    };

    #[test]
    fn drill_down_summary_is_bounded_advisory_and_non_executing() {
        let fact = safe_fact();
        let hypothesis = safe_hypothesis(&fact);
        let state = ReadOnlyCommandState::bootstrap()
            .expect("state")
            .with_security_facts(vec![fact])
            .with_attack_hypotheses(vec![hypothesis]);

        let summary = build_investigation_drill_down_summary(&state).expect("drill-down");
        assert_eq!(summary.hypothesis_count, 1);
        assert!(summary.metadata_only);
        assert!(summary.portable_no_retention);
        assert!(!summary.automatic_llm_calls);
        assert!(!summary.response_execution);
        assert!(summary
            .suggestions
            .iter()
            .all(|suggestion| suggestion.advisory_only && !suggestion.automatic_action));
        let serialized = serde_json::to_string(&summary).expect("serialize");
        for marker in [
            "api_key",
            "session_token",
            "raw_payload",
            "alice@example",
            "confirmed_compromise",
        ] {
            assert!(!serialized.contains(marker));
        }
    }

    #[test]
    fn drill_down_story_availability_never_calls_or_auto_generates() {
        let fact = safe_fact();
        let hypothesis = safe_hypothesis(&fact);
        let state = ReadOnlyCommandState::bootstrap()
            .expect("state")
            .with_security_facts(vec![fact])
            .with_attack_hypotheses(vec![hypothesis]);
        let summary = build_investigation_drill_down_summary(&state).expect("drill-down");
        let availability = &summary.hypotheses[0].story_availability;
        assert!(!availability.automatic_generation);
        assert!(availability.explicit_user_action_required);
        assert!(!availability.existing_story_available);
    }

    fn safe_fact() -> SecurityFact {
        let mut fact = SecurityFact::new(
            SecurityLayer::Api,
            "api_error_burst",
            "api_metadata_sampler",
            Timestamp::now(),
        )
        .expect("fact");
        fact.evidence_refs = vec![EvidenceId::new_v4()];
        fact.confidence_hint = QualityScore::new(0.5).expect("quality");
        fact.redaction_status = RedactionStatus::Redacted;
        fact
    }

    fn safe_hypothesis(fact: &SecurityFact) -> AttackHypothesisRecord {
        AttackHypothesisRecord {
            hypothesis_record_id: AttackHypothesisId::new_v4(),
            definition_id: "possible_api_abuse_chain".to_string(),
            version: "fusion_v1".to_string(),
            category: "possible_api_abuse_chain".to_string(),
            fact_refs: vec![fact.fact_id.clone()],
            correlated_layers: vec![SecurityLayer::Api],
            correlation_count: 1,
            confidence_bucket: FusionConfidenceBucket::Low,
            degraded_reason: Some("metadata_only_visibility".to_string()),
            missing_visibility_flags: vec!["no_process_attribution".to_string()],
            evidence_refs: fact.evidence_refs.clone(),
            finding_refs: Vec::new(),
            risk_refs: Vec::new(),
            graph_hint_refs: vec![GraphHintId::new_v4()],
            attack_candidates: vec![FusionAttackCandidate {
                tactic_id: "TA0043".to_string(),
                technique_id: "T1595".to_string(),
                attack_version: "enterprise_verified_2026_06_12".to_string(),
                confidence: FusionConfidenceBucket::Low,
                required_visibility: "portable_metadata".to_string(),
            }],
            negative_evidence_notes: Vec::new(),
            benign_baseline_indicators: Vec::new(),
            optional_llm_story_marker: true,
            quality: QualityBreakdown::metadata_only(),
            created_at: Timestamp::now(),
        }
    }
}
