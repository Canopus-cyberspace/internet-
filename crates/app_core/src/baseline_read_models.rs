use crate::read_commands::ReadOnlyCommandState;
use sentinel_contracts::{
    AttackHypothesisRecord, BaselineAttackTechniqueRef, BaselineCategory,
    BaselineConfidenceTrendBucket, BaselineCountBucket, BaselineIndicator, BaselineIndicatorId,
    BaselineIndicatorKind, BaselinePersistenceStatus, BaselineRarityBucket, BaselineRecord,
    BaselineRecordId, BaselineRecurrenceBucket, BaselineScope, BaselineTrendBucket, CommandResult,
    CoreError, DataSourceId, DurableBaselineSummary, ErrorCode, ErrorSeverity, EvidenceId,
    FindingId, FusionConfidenceBucket, GraphHintId, IncidentId, IncidentLinkedGroupId,
    IncidentLinkedHypothesisGroup, IncidentTimelineEntry, IncidentTimelineEntryId,
    MetadataSourceHealthState, MetadataWatchSourceId, OperationalInfluenceBucket, QualityBreakdown,
    ReportSectionId, ReportSectionType, RiskEventId, SecurityFact, SecurityFactId,
    SourceReliabilityBucket, SourceReliabilityQualityBucket, SourceReliabilitySummary,
    SuitabilityBucket, Timestamp, UncertaintyBucket, MAX_BASELINE_ITEMS, MAX_BASELINE_REFS,
};
use sentinel_contracts::{RedactionStatus, SecurityLayer, SecuritySeverity};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone, Debug)]
struct BaselineAccumulator {
    scope: BaselineScope,
    category: BaselineCategory,
    key: String,
    safe_label: String,
    times: Vec<Timestamp>,
    confidence_values: Vec<f32>,
    evidence_refs: Vec<EvidenceId>,
    fact_refs: Vec<SecurityFactId>,
    hypothesis_refs: Vec<sentinel_contracts::AttackHypothesisId>,
    finding_refs: Vec<FindingId>,
    risk_refs: Vec<RiskEventId>,
    provenance_refs: Vec<DataSourceId>,
    attack_refs: Vec<BaselineAttackTechniqueRef>,
    missing_visibility_flags: Vec<String>,
    degraded_reasons: Vec<String>,
    source_reliability_bucket: SourceReliabilityBucket,
}

impl BaselineAccumulator {
    fn new(
        scope: BaselineScope,
        category: BaselineCategory,
        key: impl Into<String>,
        safe_label: impl Into<String>,
    ) -> Self {
        Self {
            scope,
            category,
            key: key.into(),
            safe_label: safe_label.into(),
            times: Vec::new(),
            confidence_values: Vec::new(),
            evidence_refs: Vec::new(),
            fact_refs: Vec::new(),
            hypothesis_refs: Vec::new(),
            finding_refs: Vec::new(),
            risk_refs: Vec::new(),
            provenance_refs: Vec::new(),
            attack_refs: Vec::new(),
            missing_visibility_flags: Vec::new(),
            degraded_reasons: Vec::new(),
            source_reliability_bucket: SourceReliabilityBucket::Weak,
        }
    }

    fn add_fact(&mut self, fact: &SecurityFact) {
        self.times.push(fact.time_bucket.clone());
        self.confidence_values.push(fact.confidence_hint.value());
        push_ref(&mut self.fact_refs, fact.fact_id.clone());
        extend_refs(&mut self.evidence_refs, fact.evidence_refs.iter().cloned());
        if let Some(provenance_id) = &fact.provenance_id {
            push_ref(&mut self.provenance_refs, provenance_id.clone());
        }
        extend_strings(
            &mut self.missing_visibility_flags,
            fact.missing_visibility_flags.iter().cloned(),
        );
        if let Some(reason) = &fact.degraded_reason {
            push_safe_string(&mut self.degraded_reasons, reason.clone());
        }
    }

    fn add_hypothesis(&mut self, hypothesis: &AttackHypothesisRecord) {
        self.times.push(hypothesis.created_at.clone());
        self.confidence_values
            .push(confidence_bucket_value(&hypothesis.confidence_bucket));
        push_ref(
            &mut self.hypothesis_refs,
            hypothesis.hypothesis_record_id.clone(),
        );
        extend_refs(&mut self.fact_refs, hypothesis.fact_refs.iter().cloned());
        extend_refs(
            &mut self.evidence_refs,
            hypothesis.evidence_refs.iter().cloned(),
        );
        extend_refs(
            &mut self.finding_refs,
            hypothesis.finding_refs.iter().cloned(),
        );
        extend_refs(&mut self.risk_refs, hypothesis.risk_refs.iter().cloned());
        extend_strings(
            &mut self.missing_visibility_flags,
            hypothesis.missing_visibility_flags.iter().cloned(),
        );
        if let Some(reason) = &hypothesis.degraded_reason {
            push_safe_string(&mut self.degraded_reasons, reason.clone());
        }
        for candidate in &hypothesis.attack_candidates {
            push_ref(
                &mut self.attack_refs,
                BaselineAttackTechniqueRef {
                    tactic_id: candidate.tactic_id.clone(),
                    technique_id: candidate.technique_id.clone(),
                    attack_version: candidate.attack_version.clone(),
                    confidence_bucket: candidate.confidence.clone(),
                    required_visibility: candidate.required_visibility.clone(),
                },
            );
        }
    }

    fn add_finding(&mut self, finding: &sentinel_contracts::Finding) {
        self.times.push(Timestamp::now());
        self.confidence_values.push(finding.confidence().value());
        push_ref(&mut self.finding_refs, finding.id().clone());
        extend_refs(
            &mut self.evidence_refs,
            finding.evidence_refs().iter().cloned(),
        );
        for mapping in finding.attack_mappings() {
            if let (Some(tactic_id), Some(technique_id)) = (
                mapping.tactic_id.as_ref(),
                mapping
                    .subtechnique_id
                    .as_ref()
                    .or(mapping.technique_id.as_ref()),
            ) {
                push_ref(
                    &mut self.attack_refs,
                    BaselineAttackTechniqueRef {
                        tactic_id: tactic_id.clone(),
                        technique_id: technique_id.clone(),
                        attack_version: "enterprise-verified-2026-06-12".to_string(),
                        confidence_bucket: confidence_from_score(
                            mapping.mapping_confidence.value(),
                        ),
                        required_visibility: "portable_metadata".to_string(),
                    },
                );
            }
        }
    }

    fn add_source_health(
        &mut self,
        source_id: &MetadataWatchSourceId,
        health: &MetadataSourceHealthState,
        evidence_refs: &[EvidenceId],
        degraded_reason: Option<&String>,
        sample_count: u64,
    ) {
        let _ = source_id;
        self.times.push(Timestamp::now());
        self.confidence_values
            .push(source_health_confidence(health, sample_count));
        extend_refs(&mut self.evidence_refs, evidence_refs.iter().cloned());
        if let Some(reason) = degraded_reason {
            push_safe_string(&mut self.degraded_reasons, reason.clone());
        }
        self.source_reliability_bucket = reliability_for_health(health, sample_count);
        if is_degraded_health(health) {
            push_safe_string(
                &mut self.missing_visibility_flags,
                "weak_source_health".to_string(),
            );
        }
    }

    fn into_record(mut self) -> BaselineRecord {
        self.times.sort();
        let first_seen_time_bucket = self.times.first().cloned();
        let last_seen_time_bucket = self.times.last().cloned();
        let count = self
            .fact_refs
            .len()
            .max(self.hypothesis_refs.len())
            .max(self.finding_refs.len())
            .max(self.evidence_refs.len())
            .max(self.times.len());
        let degraded_reason = self.degraded_reasons.first().cloned().or_else(|| {
            if self.missing_visibility_flags.is_empty() {
                None
            } else {
                Some("metadata_only_visibility".to_string())
            }
        });
        let quality = quality_for_baseline_record(
            self.source_reliability_bucket.clone(),
            count,
            degraded_reason.as_ref(),
            &self.missing_visibility_flags,
        );
        BaselineRecord {
            baseline_id: baseline_record_id(&self.scope, &self.category, &self.key),
            scope: self.scope,
            category: self.category,
            scope_key_hash: stable_hash(["baseline_record", &self.key]),
            safe_label: safe_slug(&self.safe_label),
            count_bucket: count_bucket(count as u64),
            first_seen_time_bucket,
            last_seen_time_bucket,
            recurrence_bucket: recurrence_bucket(count as u64),
            rarity_bucket: rarity_bucket(count as u64),
            trend_bucket: trend_bucket(&self.times),
            confidence_trend_bucket: confidence_trend_bucket(
                &self.confidence_values,
                degraded_reason.as_ref(),
            ),
            source_reliability_bucket: self.source_reliability_bucket,
            degraded_reason,
            missing_visibility_flags: bounded_strings(self.missing_visibility_flags),
            evidence_refs: bounded_refs(self.evidence_refs),
            fact_refs: bounded_refs(self.fact_refs),
            hypothesis_refs: bounded_refs(self.hypothesis_refs),
            finding_refs: bounded_refs(self.finding_refs),
            risk_refs: bounded_refs(self.risk_refs),
            provenance_refs: bounded_refs(self.provenance_refs),
            attack_refs: bounded_refs(self.attack_refs),
            redaction_status: RedactionStatus::Redacted,
            quality,
        }
    }
}

pub fn build_durable_baseline_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<DurableBaselineSummary> {
    let mut accumulators = BTreeMap::<String, BaselineAccumulator>::new();

    for fact in &state.security_facts.items {
        accumulate_fact(&mut accumulators, fact);
    }
    for hypothesis in &state.attack_hypotheses.items {
        accumulate_hypothesis(&mut accumulators, hypothesis);
    }
    for finding in &state.findings.items {
        accumulate_finding(&mut accumulators, finding);
    }
    for source in &state.metadata_watch_sources.items {
        accumulate_source_health(&mut accumulators, source);
    }
    for batch in &state.metadata_sampling_batches.items {
        accumulate_sampling_batch(&mut accumulators, batch);
    }

    let mut records = accumulators
        .into_values()
        .map(BaselineAccumulator::into_record)
        .filter(|record| !record.evidence_refs.is_empty() || !record.fact_refs.is_empty())
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        baseline_scope_rank(&left.scope)
            .cmp(&baseline_scope_rank(&right.scope))
            .then(left.safe_label.cmp(&right.safe_label))
            .then(left.scope_key_hash.cmp(&right.scope_key_hash))
    });
    records.truncate(MAX_BASELINE_ITEMS);

    let source_reliability = build_source_reliability(state);
    let indicators = build_indicators(&records);
    let incident_groups = build_incident_groups(state, &records);
    let incident_timeline = build_incident_timeline(&incident_groups, &source_reliability);
    let summary_quality = quality_for_baseline_summary(&records, &source_reliability);

    let mut summary = DurableBaselineSummary {
        generated_at: Timestamp::now(),
        scope: BaselineScope::CurrentSession,
        persistence_status: BaselinePersistenceStatus::portable_no_retention(),
        baseline_count: records.len() as u32,
        indicator_count: indicators.len() as u32,
        incident_group_count: incident_groups.len() as u32,
        timeline_entry_count: incident_timeline.len() as u32,
        source_reliability_count: source_reliability.len() as u32,
        baseline_refs: bounded_refs(records.iter().map(|record| record.baseline_id.clone())),
        evidence_refs: bounded_refs(records.iter().flat_map(|record| {
            record.evidence_refs.iter().cloned().chain(
                indicators
                    .iter()
                    .flat_map(|indicator| indicator.evidence_refs.clone()),
            )
        })),
        fact_refs: bounded_refs(records.iter().flat_map(|record| record.fact_refs.clone())),
        hypothesis_refs: bounded_refs(
            records
                .iter()
                .flat_map(|record| record.hypothesis_refs.clone()),
        ),
        finding_refs: bounded_refs(
            records
                .iter()
                .flat_map(|record| record.finding_refs.clone()),
        ),
        risk_refs: bounded_refs(records.iter().flat_map(|record| record.risk_refs.clone())),
        attack_refs: bounded_refs(records.iter().flat_map(|record| record.attack_refs.clone())),
        provenance_refs: bounded_refs(
            records
                .iter()
                .flat_map(|record| record.provenance_refs.clone()),
        ),
        degraded_visibility_context: bounded_strings(
            records
                .iter()
                .filter_map(|record| record.degraded_reason.clone())
                .chain(["metadata_only_visibility".to_string()])
                .collect::<Vec<_>>(),
        ),
        missing_visibility_flags: bounded_strings(
            records
                .iter()
                .flat_map(|record| record.missing_visibility_flags.clone())
                .chain([
                    "no_process_visibility".to_string(),
                    "no_packet_visibility".to_string(),
                ])
                .collect::<Vec<_>>(),
        ),
        quality: summary_quality,
        report_ref_count: baseline_report_section_count(state),
        export_ref_count: baseline_export_ref_count(state),
        records,
        indicators,
        incident_groups,
        incident_timeline,
        source_reliability,
        automatic_llm_calls: false,
        response_execution: false,
    };
    summary.baseline_count = summary.records.len() as u32;
    summary.indicator_count = summary.indicators.len() as u32;
    summary.incident_group_count = summary.incident_groups.len() as u32;
    summary.timeline_entry_count = summary.incident_timeline.len() as u32;
    summary.source_reliability_count = summary.source_reliability.len() as u32;
    summary.validate().map_err(|error| {
        CoreError::new(
            ErrorCode::InternalError,
            "durable baseline summary failed safety validation",
        )
        .with_severity(ErrorSeverity::Error)
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
    })?;
    Ok(summary)
}

fn accumulate_fact(accumulators: &mut BTreeMap<String, BaselineAccumulator>, fact: &SecurityFact) {
    add_fact_record(
        accumulators,
        BaselineScope::CurrentSession,
        "current_session",
        "current_session",
        fact,
    );
    add_fact_record(
        accumulators,
        BaselineScope::SamplerLayer,
        &format!("layer:{}", layer_label(&fact.layer)),
        &format!("layer_{}", layer_label(&fact.layer)),
        fact,
    );
    add_fact_record(
        accumulators,
        BaselineScope::HypothesisFamily,
        &format!("fact_category:{}", safe_slug(&fact.category)),
        &fact.category,
        fact,
    );
    if let Some(category) = fact
        .provider_service_category
        .as_ref()
        .or(fact.saas_cloud_category.as_ref())
    {
        add_fact_record(
            accumulators,
            BaselineScope::ProviderCategory,
            &format!("provider:{}", safe_slug(category)),
            category,
            fact,
        );
    }
    if let Some(category) = fact
        .domain_category_ref
        .as_ref()
        .or(fact.protocol_category.as_ref())
        .or(fact.status_category.as_ref())
    {
        add_fact_record(
            accumulators,
            BaselineScope::DestinationServiceCategory,
            &format!("service:{}", safe_slug(category)),
            category,
            fact,
        );
    }
    if let Some(route) = &fact.route_fingerprint {
        add_fact_record(
            accumulators,
            BaselineScope::RouteEndpointFingerprint,
            &format!("route_hash:{}", stable_hash(["route", route])),
            "route_endpoint_fingerprint",
            fact,
        );
    }
    if let Some(identity) = &fact.identity_session_label_redacted {
        add_fact_record(
            accumulators,
            BaselineScope::RedactedIdentitySessionCategory,
            &format!("identity_hash:{}", stable_hash(["identity", identity])),
            "redacted_identity_session",
            fact,
        );
    }
    if let Some(deception) = &fact.deception_category {
        add_fact_record(
            accumulators,
            BaselineScope::DecoySensorRef,
            &format!("deception:{}", safe_slug(deception)),
            "decoy_sensor_interaction",
            fact,
        );
    }
}

fn add_fact_record(
    accumulators: &mut BTreeMap<String, BaselineAccumulator>,
    scope: BaselineScope,
    key: &str,
    safe_label: &str,
    fact: &SecurityFact,
) {
    accumulator(
        accumulators,
        scope,
        BaselineCategory::SecurityFact,
        key,
        safe_label,
    )
    .add_fact(fact);
}

fn accumulate_hypothesis(
    accumulators: &mut BTreeMap<String, BaselineAccumulator>,
    hypothesis: &AttackHypothesisRecord,
) {
    let label = safe_slug(&hypothesis.category);
    accumulator(
        accumulators,
        BaselineScope::HypothesisFamily,
        BaselineCategory::Hypothesis,
        &format!("hypothesis:{label}"),
        &label,
    )
    .add_hypothesis(hypothesis);
    for candidate in &hypothesis.attack_candidates {
        accumulator(
            accumulators,
            BaselineScope::AttackTechniqueRef,
            BaselineCategory::AttackTechnique,
            &format!(
                "attack:{}:{}:{}",
                safe_slug(&candidate.tactic_id),
                safe_slug(&candidate.technique_id),
                safe_slug(&candidate.attack_version)
            ),
            "attack_technique_ref",
        )
        .add_hypothesis(hypothesis);
    }
}

fn accumulate_finding(
    accumulators: &mut BTreeMap<String, BaselineAccumulator>,
    finding: &sentinel_contracts::Finding,
) {
    accumulator(
        accumulators,
        BaselineScope::HypothesisFamily,
        BaselineCategory::Finding,
        &format!("finding:{}", safe_slug(finding.finding_type())),
        finding.finding_type(),
    )
    .add_finding(finding);
}

fn accumulate_source_health(
    accumulators: &mut BTreeMap<String, BaselineAccumulator>,
    source: &sentinel_contracts::MetadataWatchSourceStatus,
) {
    let key = format!("source_health:{}", source.source_id);
    accumulator(
        accumulators,
        BaselineScope::SourceId,
        BaselineCategory::SourceHealth,
        &key,
        "source_health",
    )
    .add_source_health(
        &source.source_id,
        &source.health_state,
        &source.evidence_refs,
        source.degraded_reason.as_ref(),
        source.counters.sampled_record_count,
    );
}

fn accumulate_sampling_batch(
    accumulators: &mut BTreeMap<String, BaselineAccumulator>,
    batch: &sentinel_contracts::MetadataSamplingBatchSummary,
) {
    let key = format!("sampling_batch:{}", batch.source_id);
    let accumulator = accumulator(
        accumulators,
        BaselineScope::SourceId,
        BaselineCategory::SamplingBatch,
        &key,
        "sampling_batch",
    );
    accumulator.times.push(batch.completed_at.clone());
    accumulator.confidence_values.push(
        if batch.backpressure_drop_count > 0 || batch.malformed_record_count > 0 {
            0.35
        } else {
            0.55
        },
    );
    extend_refs(&mut accumulator.fact_refs, batch.fact_refs.iter().cloned());
    extend_refs(
        &mut accumulator.evidence_refs,
        batch.evidence_refs.iter().cloned(),
    );
    extend_refs(
        &mut accumulator.finding_refs,
        batch.finding_refs.iter().cloned(),
    );
    extend_refs(&mut accumulator.risk_refs, batch.risk_refs.iter().cloned());
    if batch.backpressure_drop_count > 0 {
        push_safe_string(
            &mut accumulator.degraded_reasons,
            "sampling_backpressure".to_string(),
        );
    }
    if batch.malformed_record_count > 0 {
        push_safe_string(
            &mut accumulator.degraded_reasons,
            "parser_errors".to_string(),
        );
    }
}

fn accumulator<'a>(
    accumulators: &'a mut BTreeMap<String, BaselineAccumulator>,
    scope: BaselineScope,
    category: BaselineCategory,
    key: &str,
    safe_label: &str,
) -> &'a mut BaselineAccumulator {
    let map_key = format!("{scope:?}:{category:?}:{key}");
    accumulators
        .entry(map_key)
        .or_insert_with(|| BaselineAccumulator::new(scope, category, key, safe_label))
}

fn build_source_reliability(state: &ReadOnlyCommandState) -> Vec<SourceReliabilitySummary> {
    let mut summaries = state
        .metadata_watch_sources
        .items
        .iter()
        .map(|source| SourceReliabilitySummary {
            source_id: source.source_id.clone(),
            source_health_state: safe_slug(&format!("{:?}", source.health_state)),
            reliability_bucket: reliability_for_health(
                &source.health_state,
                source.counters.sampled_record_count,
            ),
            sampled_count_bucket: count_bucket(source.counters.sampled_record_count),
            malformed_count_bucket: count_bucket(source.counters.malformed_record_count),
            backpressure_count_bucket: count_bucket(source.counters.backpressure_drop_count),
            degraded_reason: source
                .degraded_reason
                .as_ref()
                .map(|reason| safe_slug(reason)),
            evidence_refs: bounded_refs(source.evidence_refs.iter().cloned()),
            quality: quality_for_source_reliability(
                reliability_for_health(&source.health_state, source.counters.sampled_record_count),
                source.counters.malformed_record_count,
                source.counters.backpressure_drop_count,
                source.degraded_reason.as_ref(),
            ),
        })
        .collect::<Vec<_>>();
    summaries.sort_by_key(|summary| summary.source_id.to_string());
    summaries.truncate(MAX_BASELINE_ITEMS);
    summaries
}

fn build_indicators(records: &[BaselineRecord]) -> Vec<BaselineIndicator> {
    let mut indicators = Vec::new();
    for record in records {
        if record.evidence_refs.is_empty() && record.fact_refs.is_empty() {
            continue;
        }
        let kind = indicator_kind(record);
        if let Some(kind) = kind {
            let indicator = BaselineIndicator {
                indicator_id: baseline_indicator_id(&kind, &record.scope_key_hash),
                kind: kind.clone(),
                baseline_refs: vec![record.baseline_id.clone()],
                evidence_refs: record.evidence_refs.clone(),
                fact_refs: record.fact_refs.clone(),
                hypothesis_refs: record.hypothesis_refs.clone(),
                confidence_bucket: conservative_confidence(record),
                degraded_reason: record
                    .degraded_reason
                    .clone()
                    .or_else(|| Some("metadata_only_visibility".to_string())),
                missing_visibility_flags: record.missing_visibility_flags.clone(),
                summary_redacted: indicator_summary(&kind),
                quality: quality_for_indicator(record),
            };
            indicators.push(indicator);
        }
        if indicators.len() >= MAX_BASELINE_ITEMS {
            break;
        }
    }
    indicators
}

fn indicator_kind(record: &BaselineRecord) -> Option<BaselineIndicatorKind> {
    match (
        &record.scope,
        &record.rarity_bucket,
        &record.recurrence_bucket,
    ) {
        (BaselineScope::ProviderCategory, BaselineRarityBucket::FirstSeen, _) => {
            Some(BaselineIndicatorKind::FirstSeenProviderCategory)
        }
        (BaselineScope::RouteEndpointFingerprint, BaselineRarityBucket::FirstSeen, _) => {
            Some(BaselineIndicatorKind::FirstSeenRouteEndpointFingerprint)
        }
        (BaselineScope::DestinationServiceCategory, BaselineRarityBucket::FirstSeen, _) => {
            Some(BaselineIndicatorKind::FirstSeenDestinationServiceCategory)
        }
        (BaselineScope::RedactedIdentitySessionCategory, BaselineRarityBucket::FirstSeen, _) => {
            Some(BaselineIndicatorKind::FirstSeenAuthProviderSessionCategory)
        }
        (BaselineScope::DecoySensorRef, BaselineRarityBucket::FirstSeen, _) => {
            Some(BaselineIndicatorKind::FirstSeenDecoySensorInteractionCategory)
        }
        (BaselineScope::ProviderCategory, BaselineRarityBucket::Rare, _) => {
            Some(BaselineIndicatorKind::RareProviderCategory)
        }
        (BaselineScope::RouteEndpointFingerprint, BaselineRarityBucket::Rare, _) => {
            Some(BaselineIndicatorKind::RareRouteFingerprint)
        }
        (
            BaselineScope::RedactedIdentitySessionCategory,
            _,
            BaselineRecurrenceBucket::Repeated | BaselineRecurrenceBucket::Frequent,
        ) => Some(BaselineIndicatorKind::RepeatedFailedAuthSessionPattern),
        (
            BaselineScope::DecoySensorRef,
            _,
            BaselineRecurrenceBucket::Repeated | BaselineRecurrenceBucket::Frequent,
        ) => Some(BaselineIndicatorKind::RepeatedDeceptionInteraction),
        (_, _, BaselineRecurrenceBucket::Repeated | BaselineRecurrenceBucket::Frequent)
            if record.category == BaselineCategory::SourceHealth =>
        {
            Some(BaselineIndicatorKind::RepeatedSourceHealthDegradation)
        }
        (_, _, BaselineRecurrenceBucket::Repeated | BaselineRecurrenceBucket::Frequent)
            if record.safe_label.contains("api")
                || record.safe_label.contains("waf")
                || record.safe_label.contains("error")
                || record.safe_label.contains("status") =>
        {
            Some(BaselineIndicatorKind::RepeatedCdnWafApiErrorPattern)
        }
        _ if record.confidence_trend_bucket == BaselineConfidenceTrendBucket::Rising => {
            Some(BaselineIndicatorKind::RisingHypothesisConfidenceTrend)
        }
        _ if !record.risk_refs.is_empty()
            && matches!(
                record.trend_bucket,
                BaselineTrendBucket::Rising | BaselineTrendBucket::Flat
            ) =>
        {
            Some(BaselineIndicatorKind::RisingRiskTrend)
        }
        _ => None,
    }
}

fn build_incident_groups(
    state: &ReadOnlyCommandState,
    records: &[BaselineRecord],
) -> Vec<IncidentLinkedHypothesisGroup> {
    let records_by_fact = records_by_fact(records);
    let mut groups = BTreeMap::<String, IncidentLinkedHypothesisGroupBuilder>::new();
    for hypothesis in &state.attack_hypotheses.items {
        if hypothesis.evidence_refs.is_empty() {
            continue;
        }
        let key = group_key_for_hypothesis(hypothesis, &state.security_facts.items);
        let builder = groups
            .entry(key.clone())
            .or_insert_with(|| IncidentLinkedHypothesisGroupBuilder::new(key.clone()));
        builder.add_hypothesis(hypothesis, &records_by_fact);
    }
    let finding_to_incident = finding_to_incident(state);
    let mut built = groups
        .into_values()
        .filter_map(|builder| builder.build(&finding_to_incident, state))
        .collect::<Vec<_>>();
    built.sort_by(|left, right| {
        left.first_seen_bucket
            .cmp(&right.first_seen_bucket)
            .then(left.group_key_hash.cmp(&right.group_key_hash))
    });
    built.truncate(MAX_BASELINE_ITEMS);
    built
}

#[derive(Clone, Debug)]
struct IncidentLinkedHypothesisGroupBuilder {
    key: String,
    hypothesis_refs: Vec<sentinel_contracts::AttackHypothesisId>,
    evidence_refs: Vec<EvidenceId>,
    fact_refs: Vec<SecurityFactId>,
    finding_refs: Vec<FindingId>,
    risk_refs: Vec<RiskEventId>,
    baseline_refs: Vec<BaselineRecordId>,
    attack_refs: Vec<BaselineAttackTechniqueRef>,
    graph_refs: Vec<GraphHintId>,
    missing_visibility_flags: Vec<String>,
    degraded_reasons: Vec<String>,
    times: Vec<Timestamp>,
    confidence_values: Vec<f32>,
}

impl IncidentLinkedHypothesisGroupBuilder {
    fn new(key: String) -> Self {
        Self {
            key,
            hypothesis_refs: Vec::new(),
            evidence_refs: Vec::new(),
            fact_refs: Vec::new(),
            finding_refs: Vec::new(),
            risk_refs: Vec::new(),
            baseline_refs: Vec::new(),
            attack_refs: Vec::new(),
            graph_refs: Vec::new(),
            missing_visibility_flags: Vec::new(),
            degraded_reasons: Vec::new(),
            times: Vec::new(),
            confidence_values: Vec::new(),
        }
    }

    fn add_hypothesis(
        &mut self,
        hypothesis: &AttackHypothesisRecord,
        records_by_fact: &BTreeMap<String, Vec<BaselineRecordId>>,
    ) {
        push_ref(
            &mut self.hypothesis_refs,
            hypothesis.hypothesis_record_id.clone(),
        );
        extend_refs(
            &mut self.evidence_refs,
            hypothesis.evidence_refs.iter().cloned(),
        );
        extend_refs(&mut self.fact_refs, hypothesis.fact_refs.iter().cloned());
        extend_refs(
            &mut self.finding_refs,
            hypothesis.finding_refs.iter().cloned(),
        );
        extend_refs(&mut self.risk_refs, hypothesis.risk_refs.iter().cloned());
        extend_refs(
            &mut self.graph_refs,
            hypothesis.graph_hint_refs.iter().cloned(),
        );
        extend_strings(
            &mut self.missing_visibility_flags,
            hypothesis.missing_visibility_flags.iter().cloned(),
        );
        if let Some(reason) = &hypothesis.degraded_reason {
            push_safe_string(&mut self.degraded_reasons, reason.clone());
        }
        for fact_ref in &hypothesis.fact_refs {
            if let Some(baseline_refs) = records_by_fact.get(&fact_ref.to_string()) {
                extend_refs(&mut self.baseline_refs, baseline_refs.iter().cloned());
            }
        }
        for candidate in &hypothesis.attack_candidates {
            push_ref(
                &mut self.attack_refs,
                BaselineAttackTechniqueRef {
                    tactic_id: candidate.tactic_id.clone(),
                    technique_id: candidate.technique_id.clone(),
                    attack_version: candidate.attack_version.clone(),
                    confidence_bucket: candidate.confidence.clone(),
                    required_visibility: candidate.required_visibility.clone(),
                },
            );
        }
        self.times.push(hypothesis.created_at.clone());
        self.confidence_values
            .push(confidence_bucket_value(&hypothesis.confidence_bucket));
    }

    fn build(
        mut self,
        finding_to_incident: &BTreeMap<String, IncidentId>,
        state: &ReadOnlyCommandState,
    ) -> Option<IncidentLinkedHypothesisGroup> {
        if self.hypothesis_refs.is_empty() || self.evidence_refs.is_empty() {
            return None;
        }
        self.times.sort();
        let incident_id = self
            .finding_refs
            .iter()
            .find_map(|finding_id| finding_to_incident.get(&finding_id.to_string()).cloned());
        let report_section_refs = report_sections_for_group(state, &self.evidence_refs);
        let severity_trend = group_severity_trend(state, &self.finding_refs);
        let weak_merge_warning = self.hypothesis_refs.len() <= 1 || self.evidence_refs.len() <= 1;
        let broad_provider_only_merge_rejected = self.baseline_refs.len() <= 1
            && self.fact_refs.len() <= 1
            && self.hypothesis_refs.len() > 1;
        let quality = quality_for_incident_group(
            self.hypothesis_refs.len(),
            self.evidence_refs.len(),
            self.fact_refs.len(),
            self.degraded_reasons.first(),
            &self.missing_visibility_flags,
        );
        Some(IncidentLinkedHypothesisGroup {
            group_id: incident_group_id(&self.key),
            incident_id,
            group_key_hash: stable_hash(["incident_group", &self.key]),
            hypothesis_refs: bounded_refs(self.hypothesis_refs),
            evidence_refs: bounded_refs(self.evidence_refs),
            fact_refs: bounded_refs(self.fact_refs),
            finding_refs: bounded_refs(self.finding_refs),
            risk_refs: bounded_refs(self.risk_refs),
            baseline_refs: bounded_refs(self.baseline_refs),
            attack_refs: bounded_refs(self.attack_refs),
            graph_refs: bounded_refs(self.graph_refs),
            confidence_trend: confidence_trend_bucket(
                &self.confidence_values,
                self.degraded_reasons.first(),
            ),
            severity_trend,
            first_seen_bucket: self.times.first().cloned(),
            last_updated_bucket: self.times.last().cloned(),
            degraded_reason: self
                .degraded_reasons
                .first()
                .cloned()
                .or_else(|| Some("metadata_only_visibility".to_string())),
            missing_visibility_flags: bounded_strings(self.missing_visibility_flags),
            report_section_refs,
            quality,
            weak_merge_warning,
            broad_provider_only_merge_rejected,
        })
    }
}

fn build_incident_timeline(
    groups: &[IncidentLinkedHypothesisGroup],
    source_reliability: &[SourceReliabilitySummary],
) -> Vec<IncidentTimelineEntry> {
    let source_health_refs = bounded_refs(
        source_reliability
            .iter()
            .filter(|source| {
                matches!(
                    source.reliability_bucket,
                    SourceReliabilityBucket::Weak | SourceReliabilityBucket::Degraded
                )
            })
            .map(|source| source.source_id.clone()),
    );
    let mut entries = groups
        .iter()
        .filter_map(|group| {
            let time_bucket = group.last_updated_bucket.clone()?;
            Some(IncidentTimelineEntry {
                timeline_entry_id: timeline_entry_id(&group.group_key_hash),
                incident_id: group.incident_id.clone(),
                group_id: group.group_id.clone(),
                time_bucket,
                event_category: "incident_linked_hypothesis_update".to_string(),
                hypothesis_refs: group.hypothesis_refs.clone(),
                evidence_refs: group.evidence_refs.clone(),
                fact_refs: group.fact_refs.clone(),
                finding_refs: group.finding_refs.clone(),
                risk_refs: group.risk_refs.clone(),
                baseline_refs: group.baseline_refs.clone(),
                attack_refs: group.attack_refs.clone(),
                source_health_refs: source_health_refs.clone(),
                confidence_bucket: confidence_from_group(group),
                degraded_reason: group.degraded_reason.clone(),
                summary_redacted: "Evidence-backed metadata hypothesis group updated".to_string(),
                quality: quality_for_timeline_entry(group),
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.time_bucket.cmp(&right.time_bucket));
    entries.truncate(MAX_BASELINE_ITEMS);
    entries
}

fn group_key_for_hypothesis(hypothesis: &AttackHypothesisRecord, facts: &[SecurityFact]) -> String {
    let fact_lookup = facts
        .iter()
        .map(|fact| (fact.fact_id.to_string(), fact))
        .collect::<BTreeMap<_, _>>();
    let mut components = Vec::new();
    components.push(format!("category:{}", safe_slug(&hypothesis.category)));
    if let Some(evidence) = hypothesis.evidence_refs.first() {
        components.push(format!("evidence:{evidence}"));
    }
    for fact_ref in hypothesis.fact_refs.iter().take(8) {
        if let Some(fact) = fact_lookup.get(&fact_ref.to_string()) {
            if let Some(route) = &fact.route_fingerprint {
                components.push(format!("route:{}", stable_hash(["route", route])));
            }
            if let Some(provider) = fact
                .provider_service_category
                .as_ref()
                .or(fact.saas_cloud_category.as_ref())
            {
                components.push(format!("provider:{}", safe_slug(provider)));
            }
            if let Some(identity) = &fact.identity_session_label_redacted {
                components.push(format!("identity:{}", stable_hash(["identity", identity])));
            }
            if let Some(deception) = &fact.deception_category {
                components.push(format!("deception:{}", safe_slug(deception)));
            }
            if let Some(provenance) = &fact.provenance_id {
                components.push(format!("provenance:{provenance}"));
            }
        }
    }
    components.sort();
    components.dedup();
    components.join("|")
}

fn records_by_fact(records: &[BaselineRecord]) -> BTreeMap<String, Vec<BaselineRecordId>> {
    let mut by_fact = BTreeMap::<String, Vec<BaselineRecordId>>::new();
    for record in records {
        for fact_ref in &record.fact_refs {
            by_fact
                .entry(fact_ref.to_string())
                .or_default()
                .push(record.baseline_id.clone());
        }
    }
    by_fact
}

fn finding_to_incident(state: &ReadOnlyCommandState) -> BTreeMap<String, IncidentId> {
    let mut by_finding = BTreeMap::new();
    for incident in &state.incidents.items {
        for finding_id in incident.finding_refs() {
            by_finding.insert(finding_id.to_string(), incident.id().clone());
        }
        for alert_id in incident.alert_refs() {
            for alert in &state.alerts.items {
                if alert.id() == alert_id {
                    for finding_id in alert.finding_refs() {
                        by_finding.insert(finding_id.to_string(), incident.id().clone());
                    }
                }
            }
        }
    }
    by_finding
}

fn report_sections_for_group(
    state: &ReadOnlyCommandState,
    evidence_refs: &[EvidenceId],
) -> Vec<ReportSectionId> {
    let evidence = evidence_refs
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    bounded_refs(state.reports.items.iter().flat_map(|report| {
        report.sections.iter().filter_map(|section| {
            let has_evidence = section
                .evidence_refs
                .iter()
                .any(|evidence_ref| evidence.contains(&evidence_ref.to_string()));
            if has_evidence || section.section_type == ReportSectionType::BaselineSummary {
                Some(section.section_id.clone())
            } else {
                None
            }
        })
    }))
}

fn baseline_report_section_count(state: &ReadOnlyCommandState) -> u32 {
    state
        .reports
        .items
        .iter()
        .flat_map(|report| report.sections.iter())
        .filter(|section| section.section_type == ReportSectionType::BaselineSummary)
        .count()
        .min(u32::MAX as usize) as u32
}

fn baseline_export_ref_count(state: &ReadOnlyCommandState) -> u32 {
    state
        .export_history
        .records()
        .iter()
        .filter(|record| !record.evidence_refs.is_empty())
        .count()
        .min(u32::MAX as usize) as u32
}

fn group_severity_trend(
    state: &ReadOnlyCommandState,
    finding_refs: &[FindingId],
) -> BaselineTrendBucket {
    let refs = finding_refs
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let max_rank = state
        .findings
        .items
        .iter()
        .filter(|finding| refs.contains(&finding.id().to_string()))
        .map(|finding| severity_rank(finding.severity()))
        .max()
        .unwrap_or(0);
    if max_rank >= 3 {
        BaselineTrendBucket::Rising
    } else if max_rank > 0 {
        BaselineTrendBucket::Flat
    } else {
        BaselineTrendBucket::Unknown
    }
}

fn confidence_from_group(group: &IncidentLinkedHypothesisGroup) -> FusionConfidenceBucket {
    match group.confidence_trend {
        BaselineConfidenceTrendBucket::Rising | BaselineConfidenceTrendBucket::StableMedium => {
            FusionConfidenceBucket::Medium
        }
        BaselineConfidenceTrendBucket::StableLow | BaselineConfidenceTrendBucket::Degraded => {
            FusionConfidenceBucket::Low
        }
        BaselineConfidenceTrendBucket::Unknown => FusionConfidenceBucket::Unknown,
    }
}

fn conservative_confidence(record: &BaselineRecord) -> FusionConfidenceBucket {
    if record.evidence_refs.len() > 1
        && matches!(
            record.source_reliability_bucket,
            SourceReliabilityBucket::Stable | SourceReliabilityBucket::Corroborated
        )
        && record.degraded_reason.is_none()
    {
        FusionConfidenceBucket::Medium
    } else if record.evidence_refs.is_empty() && record.fact_refs.is_empty() {
        FusionConfidenceBucket::Unknown
    } else {
        FusionConfidenceBucket::Low
    }
}

fn indicator_summary(kind: &BaselineIndicatorKind) -> String {
    match kind {
        BaselineIndicatorKind::FirstSeenProviderCategory => {
            "First-seen provider category baseline indicator"
        }
        BaselineIndicatorKind::FirstSeenRouteEndpointFingerprint => {
            "First-seen route fingerprint baseline indicator"
        }
        BaselineIndicatorKind::FirstSeenDestinationServiceCategory => {
            "First-seen destination service category baseline indicator"
        }
        BaselineIndicatorKind::FirstSeenAuthProviderSessionCategory => {
            "First-seen redacted auth session category baseline indicator"
        }
        BaselineIndicatorKind::FirstSeenDecoySensorInteractionCategory => {
            "First-seen decoy interaction category baseline indicator"
        }
        BaselineIndicatorKind::RareProviderCategory => "Rare provider category baseline indicator",
        BaselineIndicatorKind::RareRouteFingerprint => "Rare route fingerprint baseline indicator",
        BaselineIndicatorKind::RepeatedFailedAuthSessionPattern => {
            "Repeated failed auth or session metadata pattern"
        }
        BaselineIndicatorKind::RepeatedCdnWafApiErrorPattern => {
            "Repeated CDN WAF or API error metadata pattern"
        }
        BaselineIndicatorKind::RepeatedDeceptionInteraction => {
            "Repeated deception interaction metadata pattern"
        }
        BaselineIndicatorKind::RepeatedSourceHealthDegradation => {
            "Repeated source health degradation pattern"
        }
        BaselineIndicatorKind::RisingHypothesisConfidenceTrend => {
            "Rising metadata hypothesis confidence trend"
        }
        BaselineIndicatorKind::RisingRiskTrend => "Rising metadata risk reference trend",
    }
    .to_string()
}

fn baseline_record_id(
    scope: &BaselineScope,
    category: &BaselineCategory,
    key: &str,
) -> BaselineRecordId {
    BaselineRecordId::from_uuid(uuid_from_hash(&format!("{scope:?}:{category:?}:{key}")))
}

fn baseline_indicator_id(kind: &BaselineIndicatorKind, key: &str) -> BaselineIndicatorId {
    BaselineIndicatorId::from_uuid(uuid_from_hash(&format!("{kind:?}:{key}")))
}

fn incident_group_id(key: &str) -> IncidentLinkedGroupId {
    IncidentLinkedGroupId::from_uuid(uuid_from_hash(&format!("incident_group:{key}")))
}

fn timeline_entry_id(key: &str) -> IncidentTimelineEntryId {
    IncidentTimelineEntryId::from_uuid(uuid_from_hash(&format!("incident_timeline:{key}")))
}

fn uuid_from_hash(key: &str) -> Uuid {
    let digest = Sha256::digest(key.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

fn stable_hash<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn count_bucket(count: u64) -> BaselineCountBucket {
    match count {
        0 => BaselineCountBucket::None,
        1 => BaselineCountBucket::Single,
        2..=4 => BaselineCountBucket::Low,
        5..=9 => BaselineCountBucket::Medium,
        _ => BaselineCountBucket::High,
    }
}

fn recurrence_bucket(count: u64) -> BaselineRecurrenceBucket {
    match count {
        0 => BaselineRecurrenceBucket::Unknown,
        1 => BaselineRecurrenceBucket::FirstSeen,
        2 => BaselineRecurrenceBucket::Rare,
        3..=9 => BaselineRecurrenceBucket::Repeated,
        _ => BaselineRecurrenceBucket::Frequent,
    }
}

fn rarity_bucket(count: u64) -> BaselineRarityBucket {
    match count {
        0 => BaselineRarityBucket::Unknown,
        1 => BaselineRarityBucket::FirstSeen,
        2 => BaselineRarityBucket::Rare,
        3..=5 => BaselineRarityBucket::Uncommon,
        _ => BaselineRarityBucket::Common,
    }
}

fn trend_bucket(times: &[Timestamp]) -> BaselineTrendBucket {
    if times.len() < 3 {
        return BaselineTrendBucket::Flat;
    }
    let midpoint = times.len() / 2;
    if times.len().saturating_sub(midpoint) > midpoint {
        BaselineTrendBucket::Rising
    } else {
        BaselineTrendBucket::Flat
    }
}

fn confidence_trend_bucket(
    values: &[f32],
    degraded_reason: Option<&String>,
) -> BaselineConfidenceTrendBucket {
    if degraded_reason.is_some() {
        return BaselineConfidenceTrendBucket::Degraded;
    }
    if values.is_empty() {
        return BaselineConfidenceTrendBucket::Unknown;
    }
    let first = values.first().copied().unwrap_or_default();
    let last = values.last().copied().unwrap_or_default();
    if values.len() > 1 && last > first + 0.1 {
        BaselineConfidenceTrendBucket::Rising
    } else if last >= 0.6 {
        BaselineConfidenceTrendBucket::StableMedium
    } else {
        BaselineConfidenceTrendBucket::StableLow
    }
}

fn confidence_bucket_value(bucket: &FusionConfidenceBucket) -> f32 {
    match bucket {
        FusionConfidenceBucket::Unknown => 0.0,
        FusionConfidenceBucket::Low => 0.35,
        FusionConfidenceBucket::Medium => 0.65,
    }
}

fn confidence_from_score(score: f32) -> FusionConfidenceBucket {
    if score >= 0.6 {
        FusionConfidenceBucket::Medium
    } else if score > 0.0 {
        FusionConfidenceBucket::Low
    } else {
        FusionConfidenceBucket::Unknown
    }
}

fn quality_for_baseline_record(
    reliability: SourceReliabilityBucket,
    count: usize,
    degraded_reason: Option<&String>,
    missing_visibility_flags: &[String],
) -> QualityBreakdown {
    let mut quality = if count > 1
        && degraded_reason.is_none()
        && matches!(
            reliability,
            SourceReliabilityBucket::Stable | SourceReliabilityBucket::Corroborated
        ) {
        QualityBreakdown::corroborated_metadata()
    } else {
        QualityBreakdown::metadata_only()
    };
    quality.source_reliability_bucket = quality_reliability(&reliability);
    quality.correlation_quality_bucket = if count > 3 {
        sentinel_contracts::CorrelationQualityBucket::Corroborated
    } else if count > 1 {
        sentinel_contracts::CorrelationQualityBucket::Limited
    } else {
        sentinel_contracts::CorrelationQualityBucket::SingleSignal
    };
    quality.evidence_strength_bucket = if count > 1 {
        sentinel_contracts::EvidenceStrengthBucket::Moderate
    } else {
        sentinel_contracts::EvidenceStrengthBucket::WeakSingleSignal
    };
    quality.uncertainty_bucket = if degraded_reason.is_some() || count <= 1 {
        UncertaintyBucket::High
    } else {
        UncertaintyBucket::Medium
    };
    quality.degraded_reasons = bounded_strings(
        degraded_reason
            .cloned()
            .into_iter()
            .chain(["metadata_only_visibility".to_string()])
            .collect::<Vec<_>>(),
    );
    quality.missing_visibility_flags = bounded_strings(
        missing_visibility_flags
            .iter()
            .cloned()
            .chain([
                "no_process_visibility".to_string(),
                "no_packet_visibility".to_string(),
            ])
            .collect::<Vec<_>>(),
    );
    quality
}

fn quality_for_source_reliability(
    reliability: SourceReliabilityBucket,
    malformed_count: u64,
    backpressure_count: u64,
    degraded_reason: Option<&String>,
) -> QualityBreakdown {
    let mut quality = QualityBreakdown::metadata_only();
    quality.source_reliability_bucket = quality_reliability(&reliability);
    quality.operational_influence_bucket = if backpressure_count > 0 {
        OperationalInfluenceBucket::Backpressure
    } else if malformed_count > 0 {
        OperationalInfluenceBucket::MalformedSkipped
    } else if matches!(reliability, SourceReliabilityBucket::Degraded) {
        OperationalInfluenceBucket::SourceUnavailable
    } else {
        OperationalInfluenceBucket::None
    };
    if matches!(
        reliability,
        SourceReliabilityBucket::Stable | SourceReliabilityBucket::Corroborated
    ) && malformed_count == 0
        && backpressure_count == 0
    {
        quality.evidence_quality_bucket = sentinel_contracts::EvidenceQualityBucket::Medium;
        quality.report_suitability_bucket = SuitabilityBucket::Suitable;
        quality.export_suitability_bucket = SuitabilityBucket::Suitable;
        quality.uncertainty_bucket = UncertaintyBucket::Medium;
    }
    if let Some(reason) = degraded_reason {
        quality.degraded_reasons = bounded_strings(vec![
            safe_slug(reason),
            "metadata_only_visibility".to_string(),
        ]);
    }
    quality
}

fn quality_for_indicator(record: &BaselineRecord) -> QualityBreakdown {
    let mut quality = record.quality.clone();
    quality.correlation_quality_bucket = match record.recurrence_bucket {
        BaselineRecurrenceBucket::Repeated | BaselineRecurrenceBucket::Frequent => {
            sentinel_contracts::CorrelationQualityBucket::Limited
        }
        _ => sentinel_contracts::CorrelationQualityBucket::SingleSignal,
    };
    quality
}

fn quality_for_incident_group(
    hypothesis_count: usize,
    evidence_count: usize,
    fact_count: usize,
    degraded_reason: Option<&String>,
    missing_visibility_flags: &[String],
) -> QualityBreakdown {
    let mut quality = if hypothesis_count > 1 && evidence_count > 1 && fact_count > 1 {
        QualityBreakdown::corroborated_metadata()
    } else {
        QualityBreakdown::metadata_only()
    };
    quality.correlation_quality_bucket = if hypothesis_count > 1 && fact_count > 1 {
        sentinel_contracts::CorrelationQualityBucket::Corroborated
    } else {
        sentinel_contracts::CorrelationQualityBucket::SingleSignal
    };
    quality.evidence_strength_bucket = if evidence_count > 1 {
        sentinel_contracts::EvidenceStrengthBucket::Moderate
    } else {
        sentinel_contracts::EvidenceStrengthBucket::WeakSingleSignal
    };
    quality.uncertainty_bucket = if degraded_reason.is_some() || evidence_count <= 1 {
        UncertaintyBucket::High
    } else {
        UncertaintyBucket::Medium
    };
    quality.degraded_reasons = bounded_strings(
        degraded_reason
            .cloned()
            .into_iter()
            .chain(["metadata_only_visibility".to_string()])
            .collect::<Vec<_>>(),
    );
    quality.missing_visibility_flags = bounded_strings(
        missing_visibility_flags
            .iter()
            .cloned()
            .chain(["no_process_visibility".to_string()])
            .collect::<Vec<_>>(),
    );
    quality
}

fn quality_for_timeline_entry(group: &IncidentLinkedHypothesisGroup) -> QualityBreakdown {
    let mut quality = group.quality.clone();
    if group.hypothesis_refs.len() <= 1 {
        quality.correlation_quality_bucket =
            sentinel_contracts::CorrelationQualityBucket::SingleSignal;
        quality.uncertainty_bucket = UncertaintyBucket::High;
    }
    quality
}

fn quality_for_baseline_summary(
    records: &[BaselineRecord],
    source_reliability: &[SourceReliabilitySummary],
) -> QualityBreakdown {
    let degraded_sources = source_reliability
        .iter()
        .filter(|source| {
            matches!(
                source.reliability_bucket,
                SourceReliabilityBucket::Weak
                    | SourceReliabilityBucket::Degraded
                    | SourceReliabilityBucket::Unknown
            )
        })
        .count();
    let corroborated_records = records
        .iter()
        .filter(|record| {
            matches!(
                record.quality.correlation_quality_bucket,
                sentinel_contracts::CorrelationQualityBucket::Corroborated
                    | sentinel_contracts::CorrelationQualityBucket::Diverse
            )
        })
        .count();
    let mut quality = if corroborated_records > 0 && degraded_sources == 0 {
        QualityBreakdown::corroborated_metadata()
    } else {
        QualityBreakdown::metadata_only()
    };
    if degraded_sources > 0 {
        quality.source_reliability_bucket = SourceReliabilityQualityBucket::Degraded;
        quality.report_suitability_bucket = SuitabilityBucket::Degraded;
        quality.export_suitability_bucket = SuitabilityBucket::Degraded;
        quality.degraded_reasons = bounded_strings(vec![
            "source_health_degraded".to_string(),
            "metadata_only_visibility".to_string(),
        ]);
    }
    quality
}

fn quality_reliability(reliability: &SourceReliabilityBucket) -> SourceReliabilityQualityBucket {
    match reliability {
        SourceReliabilityBucket::Unknown => SourceReliabilityQualityBucket::Unknown,
        SourceReliabilityBucket::Weak => SourceReliabilityQualityBucket::Weak,
        SourceReliabilityBucket::Degraded => SourceReliabilityQualityBucket::Degraded,
        SourceReliabilityBucket::Stable => SourceReliabilityQualityBucket::Stable,
        SourceReliabilityBucket::Corroborated => SourceReliabilityQualityBucket::Corroborated,
    }
}

fn source_health_confidence(health: &MetadataSourceHealthState, sample_count: u64) -> f32 {
    if is_degraded_health(health) {
        0.25
    } else if sample_count > 1 {
        0.55
    } else {
        0.4
    }
}

fn reliability_for_health(
    health: &MetadataSourceHealthState,
    sample_count: u64,
) -> SourceReliabilityBucket {
    match health {
        MetadataSourceHealthState::Active | MetadataSourceHealthState::Idle if sample_count > 1 => {
            SourceReliabilityBucket::Stable
        }
        MetadataSourceHealthState::Active | MetadataSourceHealthState::Idle => {
            SourceReliabilityBucket::Weak
        }
        MetadataSourceHealthState::Degraded
        | MetadataSourceHealthState::Backpressure
        | MetadataSourceHealthState::ParserError
        | MetadataSourceHealthState::SourceUnavailable
        | MetadataSourceHealthState::CursorResetRequired
        | MetadataSourceHealthState::OversizedInputSkipped => SourceReliabilityBucket::Degraded,
        _ => SourceReliabilityBucket::Unknown,
    }
}

fn is_degraded_health(health: &MetadataSourceHealthState) -> bool {
    matches!(
        health,
        MetadataSourceHealthState::Degraded
            | MetadataSourceHealthState::Backpressure
            | MetadataSourceHealthState::ParserError
            | MetadataSourceHealthState::SourceUnavailable
            | MetadataSourceHealthState::CursorResetRequired
            | MetadataSourceHealthState::OversizedInputSkipped
    )
}

fn baseline_scope_rank(scope: &BaselineScope) -> u8 {
    match scope {
        BaselineScope::CurrentSession => 0,
        BaselineScope::SourceId => 1,
        BaselineScope::SamplerLayer => 2,
        BaselineScope::ProviderCategory => 3,
        BaselineScope::DestinationServiceCategory => 4,
        BaselineScope::RouteEndpointFingerprint => 5,
        BaselineScope::RedactedIdentitySessionCategory => 6,
        BaselineScope::SourceSessionLabel => 7,
        BaselineScope::DecoySensorRef => 8,
        BaselineScope::HypothesisFamily => 9,
        BaselineScope::AttackTechniqueRef => 10,
    }
}

fn severity_rank(severity: &SecuritySeverity) -> u8 {
    match severity {
        SecuritySeverity::Informational => 0,
        SecuritySeverity::Low => 1,
        SecuritySeverity::Medium => 2,
        SecuritySeverity::High => 3,
        SecuritySeverity::Critical => 4,
    }
}

fn layer_label(layer: &SecurityLayer) -> &'static str {
    match layer {
        SecurityLayer::Dns => "dns",
        SecurityLayer::CdnEdge => "cdn_edge",
        SecurityLayer::Waf => "waf",
        SecurityLayer::Api => "api",
        SecurityLayer::Http => "http",
        SecurityLayer::AuthIdentity => "auth_identity",
        SecurityLayer::SaasCloud => "saas_cloud",
        SecurityLayer::Deception => "deception",
        SecurityLayer::LocalMetadataProxy => "local_metadata_proxy",
        SecurityLayer::SdnControlPlane => "sdn_control_plane",
        SecurityLayer::SdnPlaceholder => "sdn_placeholder",
        SecurityLayer::AuthorizedNativeHostPlaceholder => "authorized_native_host_placeholder",
        SecurityLayer::AuthorizedNativeHealth => "authorized_native_health",
        SecurityLayer::AuthorizedNativeService => "authorized_native_service",
        SecurityLayer::AuthorizedNativeProcess => "authorized_native_process",
        SecurityLayer::AuthorizedNativeNetwork => "authorized_native_network",
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
        slug.truncate(96);
        slug
    }
}

fn push_safe_string(values: &mut Vec<String>, value: String) {
    let value = safe_slug(&value);
    if !value.is_empty() && values.len() < MAX_BASELINE_REFS && !values.contains(&value) {
        values.push(value);
    }
}

fn extend_strings(values: &mut Vec<String>, incoming: impl Iterator<Item = String>) {
    for value in incoming {
        push_safe_string(values, value);
    }
}

fn bounded_strings(values: Vec<String>) -> Vec<String> {
    let mut bounded = Vec::new();
    for value in values {
        push_safe_string(&mut bounded, value);
    }
    bounded.sort();
    bounded.dedup();
    bounded.truncate(MAX_BASELINE_REFS);
    bounded
}

fn push_ref<T: Clone + PartialEq>(values: &mut Vec<T>, value: T) {
    if values.len() < MAX_BASELINE_REFS && !values.contains(&value) {
        values.push(value);
    }
}

fn extend_refs<T: Clone + PartialEq>(values: &mut Vec<T>, incoming: impl Iterator<Item = T>) {
    for value in incoming {
        push_ref(values, value);
    }
}

fn bounded_refs<T: Clone + PartialEq>(incoming: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut bounded = Vec::new();
    for value in incoming {
        push_ref(&mut bounded, value);
    }
    bounded
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        Alert, Finding, FindingExplanation, Incident, LayeredSamplerDeclaration, PluginId,
        PrivacyClass, QualityScore, SamplerState, SamplingMode,
    };

    #[test]
    fn baseline_summary_contains_only_bounded_fields_and_no_auto_actions() {
        let state = baseline_state();
        let summary = build_durable_baseline_summary(&state).expect("summary");
        summary.validate().expect("safe summary");
        assert!(!summary.records.is_empty());
        assert!(!summary.automatic_llm_calls);
        assert!(!summary.response_execution);
        assert!(!summary.persistence_status.automatic_durable_persistence);
        let serialized = serde_json::to_string(&summary).expect("serialize");
        for marker in [
            "https://",
            "session_token",
            "payload_blob",
            "C:\\",
            "alice@example.test",
            "confirmed_compromise",
        ] {
            assert!(!serialized.contains(marker), "{marker} leaked");
        }
    }

    #[test]
    fn baseline_records_are_deterministic_across_reads() {
        let state = baseline_state();
        let first = build_durable_baseline_summary(&state).expect("first");
        let second = build_durable_baseline_summary(&state).expect("second");
        let first_ids = first
            .records
            .iter()
            .map(|record| record.baseline_id.to_string())
            .collect::<Vec<_>>();
        let second_ids = second
            .records
            .iter()
            .map(|record| record.baseline_id.to_string())
            .collect::<Vec<_>>();
        assert_eq!(first_ids, second_ids);
        assert_eq!(first.baseline_count, second.baseline_count);
    }

    #[test]
    fn incident_groups_do_not_merge_on_provider_category_alone() {
        let mut state = ReadOnlyCommandState::bootstrap().expect("state");
        let first_fact = fact_with_provider("provider_shared", "route_a");
        let second_fact = fact_with_provider("provider_shared", "route_b");
        let first_hypothesis = hypothesis_for_fact(&first_fact, "edge_probe", 0);
        let second_hypothesis = hypothesis_for_fact(&second_fact, "edge_probe", 1);
        state.security_facts.items = vec![first_fact, second_fact];
        state.attack_hypotheses.items = vec![first_hypothesis, second_hypothesis];

        let summary = build_durable_baseline_summary(&state).expect("summary");
        assert_eq!(summary.incident_groups.len(), 2);
    }

    fn baseline_state() -> ReadOnlyCommandState {
        let mut state = ReadOnlyCommandState::bootstrap().expect("state");
        let fact = fact_with_provider("saas", "route_a");
        let hypothesis = hypothesis_for_fact(&fact, "saas_upload_anomaly", 0);
        let producer = PluginId::new_v4();
        let finding = Finding::new(
            "portable.api_security_lite.status_error_pattern",
            producer,
            hypothesis.evidence_refs.clone(),
            FindingExplanation::new("redacted metadata finding").expect("explanation"),
        )
        .expect("finding")
        .with_confidence(QualityScore::new(0.62).expect("confidence"))
        .with_severity(SecuritySeverity::Medium);
        let alert = Alert::new(
            "redacted metadata alert",
            "redacted metadata alert summary",
            vec![finding.id().clone()],
        )
        .expect("alert");
        let incident = Incident::new(
            "metadata_incident",
            "redacted metadata incident",
            "redacted metadata incident summary",
            vec![alert.id().clone()],
        )
        .expect("incident")
        .with_finding_refs(vec![finding.id().clone()]);

        state.security_facts.items = vec![fact];
        state.attack_hypotheses.items = vec![hypothesis];
        state.findings.items = vec![finding];
        state.alerts.items = vec![alert];
        state.incidents.items = vec![incident];
        state.fusion_summaries = vec![sentinel_contracts::FusionSummary {
            generated_at: Timestamp::now(),
            sampler_health: vec![LayeredSamplerDeclaration {
                sampler_id: "portable_api".to_string(),
                layer: SecurityLayer::Api,
                source_kind: "portable_jsonl".to_string(),
                state: SamplerState::Enabled,
                sampling_mode: SamplingMode::ConfirmedImport,
                interval_seconds: Some(60),
                record_limit: 100,
                byte_limit: 8192,
                checkpoint_state: "session".to_string(),
                health_reason: None,
                output_fact_categories: vec!["api_status".to_string()],
                event_bus_topics: vec!["security.fact".to_string()],
                privacy_boundary: "metadata_only".to_string(),
                visibility_requirements: vec!["metadata_only_visibility".to_string()],
                portable_default_available: true,
            }],
            fact_count: 1,
            hypothesis_count: 1,
            facts: state.security_facts.items.clone(),
            hypotheses: state.attack_hypotheses.items.clone(),
            top_correlated_layers: Vec::new(),
            top_hypothesis_categories: Vec::new(),
            degraded_visibility_context: vec!["metadata_only_visibility".to_string()],
            fact_refs: state
                .security_facts
                .items
                .iter()
                .map(|fact| fact.fact_id.clone())
                .collect(),
            hypothesis_refs: state
                .attack_hypotheses
                .items
                .iter()
                .map(|hypothesis| hypothesis.hypothesis_record_id.clone())
                .collect(),
            evidence_refs: state
                .attack_hypotheses
                .items
                .iter()
                .flat_map(|hypothesis| hypothesis.evidence_refs.clone())
                .collect(),
            finding_refs: state
                .findings
                .items
                .iter()
                .map(|finding| finding.id().clone())
                .collect(),
            graph_hint_refs: Vec::new(),
            quality: QualityBreakdown::metadata_only(),
            privacy_class: PrivacyClass::Internal,
            automatic_llm_calls: false,
        }];
        state
    }

    fn fact_with_provider(provider: &str, route: &str) -> SecurityFact {
        let mut fact = SecurityFact::new(
            SecurityLayer::Api,
            "status_error",
            "api_sampler",
            Timestamp::now(),
        )
        .expect("fact");
        fact.provider_service_category = Some(provider.to_string());
        fact.route_fingerprint = Some(format!("sha256_{route}"));
        fact.status_category = Some("status_4xx".to_string());
        fact.evidence_refs = vec![EvidenceId::new_v4()];
        fact.confidence_hint = QualityScore::new(0.55).expect("confidence");
        fact
    }

    fn hypothesis_for_fact(
        fact: &SecurityFact,
        category: &str,
        salt: u8,
    ) -> AttackHypothesisRecord {
        AttackHypothesisRecord {
            hypothesis_record_id: sentinel_contracts::AttackHypothesisId::from_uuid(
                uuid_from_hash(&format!("hypothesis:{category}:{salt}")),
            ),
            definition_id: "portable_metadata_hypothesis".to_string(),
            version: "v1".to_string(),
            category: category.to_string(),
            fact_refs: vec![fact.fact_id.clone()],
            correlated_layers: vec![SecurityLayer::Api],
            correlation_count: 1,
            confidence_bucket: FusionConfidenceBucket::Low,
            degraded_reason: Some("metadata_only_visibility".to_string()),
            missing_visibility_flags: vec!["metadata_only_visibility".to_string()],
            evidence_refs: fact.evidence_refs.clone(),
            finding_refs: Vec::new(),
            risk_refs: Vec::new(),
            graph_hint_refs: Vec::new(),
            attack_candidates: vec![sentinel_contracts::FusionAttackCandidate {
                tactic_id: "TA0011".to_string(),
                technique_id: "T1071.001".to_string(),
                attack_version: "enterprise-verified-2026-06-12".to_string(),
                confidence: FusionConfidenceBucket::Low,
                required_visibility: "portable_metadata".to_string(),
            }],
            negative_evidence_notes: vec!["no_process_visibility".to_string()],
            benign_baseline_indicators: Vec::new(),
            optional_llm_story_marker: false,
            quality: QualityBreakdown::metadata_only(),
            created_at: Timestamp::now(),
        }
    }
}
