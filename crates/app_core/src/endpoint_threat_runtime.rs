use crate::read_commands::ReadOnlyCommandState;
use crate::runtime_container::{RuntimeEventBusHandle, RuntimeServices};
use sentinel_capabilities::ENDPOINT_THREAT_ANALYSIS_LITE_STATIC_PLUGIN_ID;
use sentinel_contracts::{
    CommandResult, ContractDescriptor, CoreError, EndpointRejectedCandidate,
    EndpointThreatCandidate, EndpointThreatEvidence, EndpointThreatFinding, EndpointThreatRiskHint,
    EndpointVisibilityAdvisory, ErrorCode, ErrorSeverity, EventEnvelope, EventType, GraphHint,
    PluginId, PluginManifest, PrivacyClass, QualityScore, SchemaVersion, SecurityFact,
    SecurityLayer, Timestamp, TraceContext,
};
use sentinel_platform::{
    CheckpointSupport, ContractRegistry, PermissionResolver, PluginContext, PluginEventBatch,
    PolicyScope, PublishOptions, ReplaySupport, TopicName, AUDIT_ENDPOINT_THREAT_ANALYSIS,
    ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT, ENDPOINT_PROCESS_CATEGORY_FACT,
    ENDPOINT_PROCESS_PARENT_CATEGORY_FACT, ENDPOINT_SERVICE_CATEGORY_FACT,
    ENDPOINT_THREAT_CANDIDATE, ENDPOINT_THREAT_EVIDENCE, ENDPOINT_THREAT_FINDING,
    ENDPOINT_THREAT_REJECTED, ENDPOINT_THREAT_RISK_HINT, ENDPOINT_VISIBILITY_ADVISORY, GRAPH_HINT,
    SECURITY_FINDING, SECURITY_FUSION_SUMMARY, SECURITY_HYPOTHESIS,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointThreatRuntimeReceipt {
    pub consumer_invocations: u32,
    pub observations_consumed: u32,
    pub emitted_topics: Vec<String>,
    pub candidate_count: u32,
    pub finding_count: u32,
    pub evidence_count: u32,
    pub risk_hint_count: u32,
    pub advisory_count: u32,
    pub rejected_count: u32,
    pub graph_ref_count: u32,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointThreatAnalysisSummary {
    pub generated_at: Timestamp,
    pub detector_status: String,
    pub candidate_count: u32,
    pub finding_count: u32,
    pub evidence_count: u32,
    pub risk_hint_count: u32,
    pub advisory_count: u32,
    pub rejected_count: u32,
    pub graph_ref_count: u32,
    pub findings: Vec<EndpointThreatFindingReadModel>,
    pub rejected_candidates: Vec<EndpointThreatRejectedReadModel>,
    pub evidence_correlation: EndpointEvidenceCorrelationSummary,
    pub quality: EndpointThreatQualitySummary,
    pub baseline_support: EndpointBaselineSupportSummary,
    pub missing_visibility: EndpointMissingVisibilitySummary,
    pub risk_hints: Vec<EndpointRiskHintReadModel>,
    pub attack_context: Vec<EndpointAttackContextReadModel>,
    pub graph_refs: Vec<String>,
    pub report_refs: Vec<String>,
    pub export_refs: Vec<String>,
    pub visibility_advisories: Vec<EndpointVisibilityAdvisoryReadModel>,
    pub degraded_reasons: Vec<String>,
    pub automatic_llm_calls: bool,
    pub response_execution_started: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointThreatFindingReadModel {
    pub finding_id: String,
    pub candidate_ref: String,
    pub category: String,
    pub detector_id: String,
    pub detector_version: String,
    pub evidence_refs: Vec<String>,
    pub endpoint_evidence_refs: Vec<String>,
    pub risk_hint_refs: Vec<String>,
    pub attack_refs: Vec<EndpointAttackContextReadModel>,
    pub confidence_bucket: String,
    pub uncertainty_bucket: String,
    pub severity_bucket: String,
    pub independent_source_count: u32,
    pub causal_claim: String,
    pub summary_redacted: String,
    pub missing_visibility_flags: Vec<String>,
    pub evidence_quality_bucket: String,
    pub correlation_quality_bucket: String,
    pub provenance_id: String,
    pub redaction_status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointThreatRejectedReadModel {
    pub rejected_candidate_id: String,
    pub analysis_input_ref: String,
    pub category: String,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub missing_visibility_flags: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointEvidenceCorrelationSummary {
    pub evidence_refs: Vec<String>,
    pub endpoint_evidence_refs: Vec<String>,
    pub portable_finding_refs: Vec<String>,
    pub hypothesis_refs: Vec<String>,
    pub baseline_refs: Vec<String>,
    pub risk_refs: Vec<String>,
    pub provenance_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointThreatQualitySummary {
    pub detector_status: String,
    pub evidence_quality_buckets: Vec<String>,
    pub source_reliability_buckets: Vec<String>,
    pub correlation_quality_buckets: Vec<String>,
    pub redaction_statuses: Vec<String>,
    pub freshness_categories: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointBaselineSupportSummary {
    pub baseline_refs: Vec<String>,
    pub support_bucket: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointMissingVisibilitySummary {
    pub missing_visibility_flags: Vec<String>,
    pub degraded_reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRiskHintReadModel {
    pub risk_hint_id: String,
    pub finding_ref: Option<String>,
    pub candidate_ref: Option<String>,
    pub category: String,
    pub risk_bucket: String,
    pub confidence_bucket: String,
    pub evidence_refs: Vec<String>,
    pub risk_refs: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointAttackContextReadModel {
    pub tactic_id: String,
    pub technique_id: String,
    pub attack_version: String,
    pub confidence_bucket: String,
    pub required_visibility: Vec<String>,
    pub technique_observed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointVisibilityAdvisoryReadModel {
    pub advisory_id: String,
    pub analysis_input_ref: Option<String>,
    pub category: String,
    pub missing_visibility_flags: Vec<String>,
    pub confidence_cap: String,
    pub evidence_refs: Vec<String>,
    pub provenance_id: String,
    pub redaction_status: String,
}

#[cfg(test)]
pub fn run_endpoint_threat_analysis_runtime(
    state: &mut ReadOnlyCommandState,
) -> CommandResult<EndpointThreatRuntimeReceipt> {
    run_endpoint_threat_analysis_runtime_with_services(
        state,
        RuntimeServices::for_test("endpoint-threat-analysis")?,
    )
}

pub(crate) fn run_endpoint_threat_analysis_runtime_with_services(
    state: &mut ReadOnlyCommandState,
    runtime_services: RuntimeServices,
) -> CommandResult<EndpointThreatRuntimeReceipt> {
    validate_endpoint_threat_dag()?;
    let output = runtime_services.with_plugin_runtime(|runtime| {
        let plugin_id = PluginId::parse_str(ENDPOINT_THREAT_ANALYSIS_LITE_STATIC_PLUGIN_ID)
            .map_err(endpoint_runtime_error)?;
        let manifest = runtime
            .manifest(&plugin_id)
            .ok_or_else(|| endpoint_runtime_error("endpoint threat analysis manifest missing"))?
            .clone();
        let contracts = contract_registry_for_manifest(&manifest)?;
        let mut permissions = PermissionResolver::new();
        permissions.register_plugin_manifest_permissions(&manifest);
        let validation = runtime
            .registry()
            .validate_startup(&plugin_id, &contracts, &permissions)
            .map_err(endpoint_runtime_error)?;
        let trace_context = TraceContext::new_root();
        let mut context = plugin_context_for_manifest(&manifest, trace_context.clone())?;
        context.policy_scope = PolicyScope::Plugin;
        runtime
            .start_plugin(&plugin_id, &validation, &mut context)
            .map_err(endpoint_runtime_error)?;

        let producer_plugin = PluginId::new_v4();
        let mut batch = PluginEventBatch::new(
            plugin_id.clone(),
            state.security_facts.items.len()
                + state.findings.items.len()
                + state.attack_hypotheses.items.len()
                + state.fusion_summaries.len(),
        );
        for fact in state.security_facts.items.iter().filter(|fact| {
            matches!(
                fact.layer,
                SecurityLayer::AuthorizedNativeHealth
                    | SecurityLayer::AuthorizedNativeService
                    | SecurityLayer::AuthorizedNativeProcess
            )
        }) {
            batch
                .push(endpoint_runtime_event(
                    &producer_plugin,
                    topic_for_security_fact(fact)?,
                    fact,
                    &trace_context,
                )?)
                .map_err(endpoint_runtime_error)?;
        }
        for finding in &state.findings.items {
            batch
                .push(endpoint_runtime_event(
                    &producer_plugin,
                    SECURITY_FINDING,
                    finding,
                    &trace_context,
                )?)
                .map_err(endpoint_runtime_error)?;
        }
        for hypothesis in &state.attack_hypotheses.items {
            batch
                .push(endpoint_runtime_event(
                    &producer_plugin,
                    SECURITY_HYPOTHESIS,
                    hypothesis,
                    &trace_context,
                )?)
                .map_err(endpoint_runtime_error)?;
        }
        for summary in &state.fusion_summaries {
            batch
                .push(endpoint_runtime_event(
                    &producer_plugin,
                    SECURITY_FUSION_SUMMARY,
                    summary,
                    &trace_context,
                )?)
                .map_err(endpoint_runtime_error)?;
        }

        let observations_consumed = batch.events.len().min(u32::MAX as usize) as u32;
        let output = runtime
            .process_batch(&plugin_id, &mut context, &batch)
            .map_err(endpoint_runtime_error)?;
        Ok((observations_consumed, output))
    })?;
    let event_bus = runtime_services.event_bus();
    let mut emitted_topics = Vec::new();
    state.endpoint_threat_candidates.clear();
    state.endpoint_threat_findings.clear();
    state.endpoint_threat_evidence.clear();
    state.endpoint_threat_risk_hints.clear();
    state.endpoint_visibility_advisories.clear();
    state.endpoint_threat_rejected.clear();
    state.endpoint_threat_graph_hints.clear();

    for event in output.1.events {
        let topic = event.event_type.as_str().to_string();
        publish_endpoint_event(&event_bus, &topic, event.clone())?;
        emitted_topics.push(topic.clone());
        match topic.as_str() {
            ENDPOINT_THREAT_CANDIDATE => state.endpoint_threat_candidates.push(
                parse_event_payload::<EndpointThreatCandidate>(event.payload)?,
            ),
            ENDPOINT_THREAT_FINDING => {
                state
                    .endpoint_threat_findings
                    .push(parse_event_payload::<EndpointThreatFinding>(event.payload)?)
            }
            ENDPOINT_THREAT_EVIDENCE => state.endpoint_threat_evidence.push(parse_event_payload::<
                EndpointThreatEvidence,
            >(
                event.payload
            )?),
            ENDPOINT_THREAT_RISK_HINT => state.endpoint_threat_risk_hints.push(
                parse_event_payload::<EndpointThreatRiskHint>(event.payload)?,
            ),
            ENDPOINT_VISIBILITY_ADVISORY => {
                state
                    .endpoint_visibility_advisories
                    .push(parse_event_payload::<EndpointVisibilityAdvisory>(
                        event.payload,
                    )?)
            }
            ENDPOINT_THREAT_REJECTED => {
                state.endpoint_threat_rejected.push(
                    parse_event_payload::<EndpointRejectedCandidate>(event.payload)?,
                )
            }
            GRAPH_HINT => state
                .endpoint_threat_graph_hints
                .push(parse_event_payload::<GraphHint>(event.payload)?),
            AUDIT_ENDPOINT_THREAT_ANALYSIS => {}
            other => {
                return Err(CoreError::validation_failure(
                    "endpoint threat runtime emitted undeclared output",
                )
                .with_redacted_details(json!({ "topic": other })));
            }
        }
    }
    state.endpoint_threat_emitted_topics = bounded_unique_strings(emitted_topics.clone());

    Ok(EndpointThreatRuntimeReceipt {
        consumer_invocations: 1,
        observations_consumed: output.0,
        emitted_topics: bounded_unique_strings(emitted_topics),
        candidate_count: state.endpoint_threat_candidates.len() as u32,
        finding_count: state.endpoint_threat_findings.len() as u32,
        evidence_count: state.endpoint_threat_evidence.len() as u32,
        risk_hint_count: state.endpoint_threat_risk_hints.len() as u32,
        advisory_count: state.endpoint_visibility_advisories.len() as u32,
        rejected_count: state.endpoint_threat_rejected.len() as u32,
        graph_ref_count: state.endpoint_threat_graph_hints.len() as u32,
        automatic_llm_calls: false,
        response_execution_started: false,
    })
}

pub fn get_endpoint_threat_analysis_summary(
    state: &ReadOnlyCommandState,
) -> CommandResult<EndpointThreatAnalysisSummary> {
    let findings = state
        .endpoint_threat_findings
        .iter()
        .map(endpoint_finding_read_model)
        .collect::<Vec<_>>();
    let rejected_candidates = state
        .endpoint_threat_rejected
        .iter()
        .map(endpoint_rejected_read_model)
        .collect::<Vec<_>>();
    let risk_hints = state
        .endpoint_threat_risk_hints
        .iter()
        .map(endpoint_risk_hint_read_model)
        .collect::<Vec<_>>();
    let visibility_advisories = state
        .endpoint_visibility_advisories
        .iter()
        .map(endpoint_visibility_advisory_read_model)
        .collect::<Vec<_>>();

    Ok(EndpointThreatAnalysisSummary {
        generated_at: Timestamp::now(),
        detector_status: if state.endpoint_threat_emitted_topics.is_empty() {
            "idle".to_string()
        } else {
            "completed_metadata_only".to_string()
        },
        candidate_count: state.endpoint_threat_candidates.len() as u32,
        finding_count: findings.len() as u32,
        evidence_count: state.endpoint_threat_evidence.len() as u32,
        risk_hint_count: risk_hints.len() as u32,
        advisory_count: visibility_advisories.len() as u32,
        rejected_count: rejected_candidates.len() as u32,
        graph_ref_count: state.endpoint_threat_graph_hints.len() as u32,
        findings,
        rejected_candidates,
        evidence_correlation: endpoint_evidence_correlation_summary(state),
        quality: endpoint_quality_summary(state),
        baseline_support: endpoint_baseline_support_summary(state),
        missing_visibility: endpoint_missing_visibility_summary(state),
        risk_hints,
        attack_context: endpoint_attack_context(state),
        graph_refs: state
            .endpoint_threat_graph_hints
            .iter()
            .map(|hint| hint.hint_id.to_string())
            .collect(),
        report_refs: state
            .reports
            .items
            .iter()
            .map(|report| report.report_id.to_string())
            .take(32)
            .collect(),
        export_refs: state
            .export_history
            .records()
            .iter()
            .map(|record| record.export_result_id.to_string())
            .take(32)
            .collect(),
        visibility_advisories,
        degraded_reasons: vec![
            "metadata_only_endpoint_visibility".to_string(),
            "no_process_network_attribution".to_string(),
        ],
        automatic_llm_calls: false,
        response_execution_started: false,
    })
}

fn endpoint_finding_read_model(finding: &EndpointThreatFinding) -> EndpointThreatFindingReadModel {
    EndpointThreatFindingReadModel {
        finding_id: finding.finding_id.to_string(),
        candidate_ref: finding.candidate_ref.to_string(),
        category: format!("{:?}", finding.category),
        detector_id: endpoint_detector_id_for_finding(finding),
        detector_version: "1.0.0".to_string(),
        evidence_refs: id_strings(&finding.evidence_refs),
        endpoint_evidence_refs: id_strings(&finding.endpoint_evidence_refs),
        risk_hint_refs: id_strings(&finding.risk_hint_refs),
        attack_refs: finding
            .attack_refs
            .iter()
            .map(endpoint_attack_ref)
            .collect(),
        confidence_bucket: format!("{:?}", finding.confidence_bucket),
        uncertainty_bucket: endpoint_uncertainty_bucket(finding),
        severity_bucket: format!("{:?}", finding.severity_bucket),
        independent_source_count: u32::try_from(finding.evidence_refs.len().min(32)).unwrap_or(0),
        causal_claim: format!("{:?}", finding.causal_claim),
        summary_redacted: finding.summary_redacted.clone(),
        missing_visibility_flags: debug_strings(&finding.missing_visibility_flags),
        evidence_quality_bucket: format!("{:?}", finding.evidence_quality_bucket),
        correlation_quality_bucket: format!("{:?}", finding.correlation_quality_bucket),
        provenance_id: finding.provenance_id.to_string(),
        redaction_status: format!("{:?}", finding.redaction_status),
    }
}

fn endpoint_detector_id_for_finding(finding: &EndpointThreatFinding) -> String {
    match finding.summary_redacted.as_str() {
        "possible unusual endpoint category activity" => {
            "possible_unusual_process_category_population_change"
        }
        "possible remote-admin endpoint activity with authentication pressure" => {
            "possible_remote_admin_endpoint_activity_with_auth_pressure"
        }
        "possible service change with independent security evidence" => {
            "possible_service_state_change_with_security_context"
        }
        "possible endpoint context supporting an existing security finding" => {
            "endpoint_threat_lite.context_supporting_security_finding"
        }
        "endpoint visibility degradation advisory" => "endpoint_visibility_degradation_advisory",
        _ => "endpoint_threat_lite.category_correlation",
    }
    .to_string()
}

fn endpoint_uncertainty_bucket(finding: &EndpointThreatFinding) -> String {
    if !finding.missing_visibility_flags.is_empty()
        || finding.endpoint_evidence_refs.len() < 2
        || finding.evidence_refs.len() < 2
    {
        "elevated_metadata_uncertainty".to_string()
    } else {
        "bounded_metadata_uncertainty".to_string()
    }
}

fn endpoint_rejected_read_model(
    rejected: &EndpointRejectedCandidate,
) -> EndpointThreatRejectedReadModel {
    EndpointThreatRejectedReadModel {
        rejected_candidate_id: rejected.rejected_candidate_id.to_string(),
        analysis_input_ref: rejected.analysis_input_ref.to_string(),
        category: format!("{:?}", rejected.category),
        reason: format!("{:?}", rejected.reason),
        evidence_refs: id_strings(&rejected.evidence_refs),
        missing_visibility_flags: debug_strings(&rejected.missing_visibility_flags),
        provenance_id: rejected.provenance_id.to_string(),
        redaction_status: format!("{:?}", rejected.redaction_status),
    }
}

fn endpoint_risk_hint_read_model(hint: &EndpointThreatRiskHint) -> EndpointRiskHintReadModel {
    EndpointRiskHintReadModel {
        risk_hint_id: hint.risk_hint_id.to_string(),
        finding_ref: hint.finding_ref.as_ref().map(ToString::to_string),
        candidate_ref: hint.candidate_ref.as_ref().map(ToString::to_string),
        category: format!("{:?}", hint.category),
        risk_bucket: format!("{:?}", hint.risk_bucket),
        confidence_bucket: format!("{:?}", hint.confidence_bucket),
        evidence_refs: id_strings(&hint.evidence_refs),
        risk_refs: id_strings(&hint.risk_refs),
        provenance_id: hint.provenance_id.to_string(),
        redaction_status: format!("{:?}", hint.redaction_status),
    }
}

fn endpoint_visibility_advisory_read_model(
    advisory: &EndpointVisibilityAdvisory,
) -> EndpointVisibilityAdvisoryReadModel {
    EndpointVisibilityAdvisoryReadModel {
        advisory_id: advisory.advisory_id.to_string(),
        analysis_input_ref: advisory
            .analysis_input_ref
            .as_ref()
            .map(ToString::to_string),
        category: format!("{:?}", advisory.category),
        missing_visibility_flags: debug_strings(&advisory.missing_visibility_flags),
        confidence_cap: format!("{:?}", advisory.confidence_cap),
        evidence_refs: id_strings(&advisory.evidence_refs),
        provenance_id: advisory.provenance_id.to_string(),
        redaction_status: format!("{:?}", advisory.redaction_status),
    }
}

fn endpoint_evidence_correlation_summary(
    state: &ReadOnlyCommandState,
) -> EndpointEvidenceCorrelationSummary {
    EndpointEvidenceCorrelationSummary {
        evidence_refs: bounded_unique_strings(
            state
                .endpoint_threat_evidence
                .iter()
                .map(|evidence| evidence.source_evidence_ref.to_string())
                .collect(),
        ),
        endpoint_evidence_refs: bounded_unique_strings(
            state
                .endpoint_threat_evidence
                .iter()
                .map(|evidence| evidence.endpoint_evidence_id.to_string())
                .collect(),
        ),
        portable_finding_refs: bounded_unique_strings(
            state
                .endpoint_threat_evidence
                .iter()
                .flat_map(|evidence| {
                    evidence
                        .portable_finding_refs
                        .iter()
                        .map(ToString::to_string)
                })
                .collect(),
        ),
        hypothesis_refs: bounded_unique_strings(
            state
                .endpoint_threat_evidence
                .iter()
                .flat_map(|evidence| evidence.hypothesis_refs.iter().map(ToString::to_string))
                .collect(),
        ),
        baseline_refs: bounded_unique_strings(
            state
                .endpoint_threat_evidence
                .iter()
                .flat_map(|evidence| evidence.baseline_refs.iter().map(ToString::to_string))
                .collect(),
        ),
        risk_refs: bounded_unique_strings(
            state
                .endpoint_threat_evidence
                .iter()
                .flat_map(|evidence| evidence.risk_refs.iter().map(ToString::to_string))
                .collect(),
        ),
        provenance_refs: bounded_unique_strings(
            state
                .endpoint_threat_evidence
                .iter()
                .map(|evidence| evidence.provenance_id.to_string())
                .collect(),
        ),
    }
}

fn endpoint_quality_summary(state: &ReadOnlyCommandState) -> EndpointThreatQualitySummary {
    EndpointThreatQualitySummary {
        detector_status: if state.endpoint_threat_findings.is_empty() {
            "no_validated_findings".to_string()
        } else {
            "validated_findings_available".to_string()
        },
        evidence_quality_buckets: bounded_unique_strings(
            state
                .endpoint_threat_evidence
                .iter()
                .map(|evidence| format!("{:?}", evidence.evidence_quality_bucket))
                .collect(),
        ),
        source_reliability_buckets: bounded_unique_strings(
            state
                .endpoint_threat_evidence
                .iter()
                .map(|evidence| format!("{:?}", evidence.source_reliability_bucket))
                .collect(),
        ),
        correlation_quality_buckets: bounded_unique_strings(
            state
                .endpoint_threat_evidence
                .iter()
                .map(|evidence| format!("{:?}", evidence.correlation_quality_bucket))
                .collect(),
        ),
        redaction_statuses: bounded_unique_strings(
            state
                .endpoint_threat_evidence
                .iter()
                .map(|evidence| format!("{:?}", evidence.redaction_status))
                .collect(),
        ),
        freshness_categories: bounded_unique_strings(
            state
                .endpoint_threat_evidence
                .iter()
                .map(|evidence| format!("{:?}", evidence.freshness_category))
                .collect(),
        ),
    }
}

fn endpoint_baseline_support_summary(
    state: &ReadOnlyCommandState,
) -> EndpointBaselineSupportSummary {
    let baseline_refs = bounded_unique_strings(
        state
            .endpoint_threat_evidence
            .iter()
            .flat_map(|evidence| evidence.baseline_refs.iter().map(ToString::to_string))
            .collect(),
    );
    EndpointBaselineSupportSummary {
        support_bucket: if baseline_refs.is_empty() {
            "missing".to_string()
        } else {
            "fresh_metadata_baseline_refs".to_string()
        },
        baseline_refs,
    }
}

fn endpoint_missing_visibility_summary(
    state: &ReadOnlyCommandState,
) -> EndpointMissingVisibilitySummary {
    EndpointMissingVisibilitySummary {
        missing_visibility_flags: bounded_unique_strings(
            state
                .endpoint_visibility_advisories
                .iter()
                .flat_map(|advisory| advisory.missing_visibility_flags.iter())
                .map(|flag| format!("{flag:?}"))
                .collect(),
        ),
        degraded_reasons: vec![
            "process_network_attribution_unavailable".to_string(),
            "command_line_visibility_unavailable".to_string(),
            "file_registry_visibility_unavailable".to_string(),
            "packet_visibility_unavailable".to_string(),
        ],
    }
}

fn endpoint_attack_context(state: &ReadOnlyCommandState) -> Vec<EndpointAttackContextReadModel> {
    state
        .endpoint_threat_findings
        .iter()
        .flat_map(|finding| finding.attack_refs.iter())
        .map(endpoint_attack_ref)
        .take(32)
        .collect()
}

fn endpoint_attack_ref(
    attack_ref: &sentinel_contracts::EndpointAttackRef,
) -> EndpointAttackContextReadModel {
    EndpointAttackContextReadModel {
        tactic_id: attack_ref.tactic_id.clone(),
        technique_id: attack_ref.technique_id.clone(),
        attack_version: attack_ref.attack_version.clone(),
        confidence_bucket: format!("{:?}", attack_ref.confidence_bucket),
        required_visibility: debug_strings(&attack_ref.required_visibility),
        technique_observed: false,
    }
}

fn topic_for_security_fact(fact: &SecurityFact) -> CommandResult<&'static str> {
    match fact.layer {
        SecurityLayer::AuthorizedNativeHealth => Ok(ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT),
        SecurityLayer::AuthorizedNativeService => Ok(ENDPOINT_SERVICE_CATEGORY_FACT),
        SecurityLayer::AuthorizedNativeProcess => {
            if fact.category == ENDPOINT_PROCESS_PARENT_CATEGORY_FACT {
                Ok(ENDPOINT_PROCESS_PARENT_CATEGORY_FACT)
            } else {
                Ok(ENDPOINT_PROCESS_CATEGORY_FACT)
            }
        }
        _ => Err(CoreError::validation_failure(
            "endpoint threat runtime accepts native category facts only",
        )),
    }
}

fn validate_endpoint_threat_dag() -> CommandResult<()> {
    let input_topics = [
        ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT,
        ENDPOINT_SERVICE_CATEGORY_FACT,
        ENDPOINT_PROCESS_CATEGORY_FACT,
        ENDPOINT_PROCESS_PARENT_CATEGORY_FACT,
        SECURITY_FINDING,
        SECURITY_HYPOTHESIS,
        SECURITY_FUSION_SUMMARY,
    ]
    .into_iter()
    .map(TopicName::new)
    .collect::<Result<Vec<_>, _>>()
    .map_err(contract_error)?;
    let output_topics = [
        ENDPOINT_THREAT_CANDIDATE,
        ENDPOINT_THREAT_FINDING,
        ENDPOINT_THREAT_EVIDENCE,
        ENDPOINT_THREAT_RISK_HINT,
        ENDPOINT_VISIBILITY_ADVISORY,
        ENDPOINT_THREAT_REJECTED,
        GRAPH_HINT,
        AUDIT_ENDPOINT_THREAT_ANALYSIS,
    ]
    .into_iter()
    .map(TopicName::new)
    .collect::<Result<Vec<_>, _>>()
    .map_err(contract_error)?;
    let unique_inputs = input_topics
        .iter()
        .map(TopicName::as_str)
        .collect::<BTreeSet<_>>();
    let unique_outputs = output_topics
        .iter()
        .map(TopicName::as_str)
        .collect::<BTreeSet<_>>();
    if unique_inputs.len() != input_topics.len() || unique_outputs.len() != output_topics.len() {
        return Err(CoreError::validation_failure(
            "endpoint threat test runtime topics must be unique",
        ));
    }
    Ok(())
}

fn publish_endpoint_event(
    event_bus: &RuntimeEventBusHandle,
    topic: &str,
    event: EventEnvelope,
) -> CommandResult<()> {
    event_bus
        .publish(
            TopicName::new(topic).map_err(contract_error)?,
            event,
            PublishOptions::new("bounded endpoint threat analysis runtime output"),
        )
        .map_err(endpoint_runtime_error)?;
    Ok(())
}

fn endpoint_runtime_event<T: serde::Serialize>(
    producer_plugin: &PluginId,
    topic: &str,
    payload: &T,
    trace_context: &TraceContext,
) -> CommandResult<EventEnvelope> {
    let mut event = EventEnvelope::new(
        EventType::new(topic).map_err(contract_error)?,
        SchemaVersion::new(1, 0, 0),
        producer_plugin.clone(),
        trace_context.clone(),
    );
    event.privacy_class = PrivacyClass::Internal;
    event.quality_score = QualityScore::new(0.7).map_err(contract_error)?;
    event.payload = serde_json::to_value(payload).map_err(endpoint_runtime_error)?;
    Ok(event)
}

fn contract_registry_for_manifest(manifest: &PluginManifest) -> CommandResult<ContractRegistry> {
    let mut registry = ContractRegistry::new();
    for contract in manifest
        .input_contracts
        .iter()
        .chain(manifest.output_contracts.iter())
    {
        registry
            .register(contract.clone())
            .map_err(endpoint_runtime_error)?;
    }
    Ok(registry)
}

fn plugin_context_for_manifest(
    manifest: &PluginManifest,
    trace_context: TraceContext,
) -> CommandResult<PluginContext<'static>> {
    let mut context = PluginContext::new(
        manifest.plugin_id.clone(),
        manifest.runtime_mode.clone(),
        trace_context,
    );
    for contract in &manifest.input_contracts {
        context
            .topic_scope
            .subscribe_topics
            .insert(topic_for_contract(contract)?);
    }
    for contract in &manifest.output_contracts {
        context
            .topic_scope
            .publish_topics
            .insert(topic_for_contract(contract)?);
    }
    for permission in &manifest.required_permissions {
        context
            .permission_scope
            .required_permissions
            .insert(permission.permission.clone());
        context
            .permission_scope
            .granted_permissions
            .insert(permission.permission.clone());
    }
    context.checkpoint =
        CheckpointSupport::from_manifest_level(manifest.checkpoint_support.clone());
    context.replay = ReplaySupport::from_manifest_level(manifest.replay_support.clone());
    Ok(context)
}

fn topic_for_contract(contract: &ContractDescriptor) -> CommandResult<TopicName> {
    TopicName::new(
        contract
            .topic
            .as_deref()
            .unwrap_or(contract.contract_name.as_str()),
    )
    .map_err(contract_error)
}

fn parse_event_payload<T: serde::de::DeserializeOwned>(
    payload: serde_json::Value,
) -> CommandResult<T> {
    serde_json::from_value(payload).map_err(endpoint_runtime_error)
}

fn id_strings<T: ToString>(values: &[T]) -> Vec<String> {
    values.iter().map(ToString::to_string).take(32).collect()
}

fn debug_strings<T: std::fmt::Debug>(values: &[T]) -> Vec<String> {
    values
        .iter()
        .map(|value| format!("{value:?}"))
        .take(32)
        .collect()
}

fn bounded_unique_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .take(64)
        .collect()
}

fn endpoint_runtime_error(error: impl ToString) -> CoreError {
    CoreError::new(ErrorCode::InternalError, "endpoint threat runtime failed")
        .with_severity(ErrorSeverity::Error)
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

fn contract_error(error: impl ToString) -> CoreError {
    CoreError::validation_failure("endpoint threat runtime contract validation failed")
        .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        AttackHypothesisId, AttackHypothesisRecord, EvidenceId, Finding, FindingExplanation,
        FusionConfidenceBucket, FusionCount, FusionSummary, QualityBreakdown, RedactionStatus,
        SecuritySeverity,
    };

    #[test]
    fn endpoint_threat_runtime_emits_declared_topics_only() {
        let mut state = endpoint_runtime_state();
        let receipt =
            run_endpoint_threat_analysis_runtime(&mut state).expect("endpoint runtime receipt");
        let allowed = [
            ENDPOINT_THREAT_CANDIDATE,
            ENDPOINT_THREAT_FINDING,
            ENDPOINT_THREAT_EVIDENCE,
            ENDPOINT_THREAT_RISK_HINT,
            ENDPOINT_VISIBILITY_ADVISORY,
            ENDPOINT_THREAT_REJECTED,
            GRAPH_HINT,
            AUDIT_ENDPOINT_THREAT_ANALYSIS,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();

        assert!(!receipt.emitted_topics.is_empty());
        assert!(receipt
            .emitted_topics
            .iter()
            .all(|topic| allowed.contains(topic.as_str())));
        assert!(receipt.finding_count > 0);
        assert!(!receipt.automatic_llm_calls);
        assert!(!receipt.response_execution_started);
    }

    #[test]
    fn endpoint_threat_scheduler_and_sampler_contain_no_detector_logic() {
        let scheduler = include_str!("native_scheduler.rs");
        let sampler = include_str!("native_sampler_runtime.rs");
        for source in [scheduler, sampler] {
            assert!(!source.contains("EndpointThreatDetectorPack"));
            assert!(!source.contains("endpoint_threat_detection"));
            assert!(!source.contains("register_static_endpoint_threat_analysis"));
        }
    }

    #[test]
    fn endpoint_threat_read_models_contain_no_raw_endpoint_values() {
        let mut state = endpoint_runtime_state();
        run_endpoint_threat_analysis_runtime(&mut state).expect("endpoint runtime");
        let summary =
            get_endpoint_threat_analysis_summary(&state).expect("endpoint threat summary");
        let serialized = serde_json::to_string(&summary).expect("summary serializes");

        assert!(summary.finding_count > 0);
        for forbidden in [
            "process.exe",
            "cmd.exe",
            "powershell.exe",
            "C:\\",
            "/users/",
            "username",
            "alice@example.com",
            "10.0.0.1",
            "192.168.1.1",
            "tenant_id",
            "token",
            "secret",
            "credential",
        ] {
            assert!(
                !serialized
                    .to_ascii_lowercase()
                    .contains(&forbidden.to_ascii_lowercase()),
                "read model leaked {forbidden}"
            );
        }
        assert!(!serialized.contains("automatic_llm_calls\":true"));
        assert!(!serialized.contains("response_execution_started\":true"));
    }

    fn endpoint_runtime_state() -> ReadOnlyCommandState {
        let evidence = EvidenceId::new_v4();
        let process = fact(
            SecurityLayer::AuthorizedNativeProcess,
            ENDPOINT_PROCESS_CATEGORY_FACT,
            "script_capable_activity",
        );
        let service = fact(
            SecurityLayer::AuthorizedNativeService,
            ENDPOINT_SERVICE_CATEGORY_FACT,
            "service_state_change",
        );
        let parent = fact(
            SecurityLayer::AuthorizedNativeProcess,
            ENDPOINT_PROCESS_PARENT_CATEGORY_FACT,
            "parent_category_transition",
        );
        let finding = Finding::new(
            "endpoint_auth_pressure",
            PluginId::new_v4(),
            vec![evidence.clone()],
            FindingExplanation::new("bounded endpoint auth pressure").expect("safe explanation"),
        )
        .expect("finding")
        .with_confidence(QualityScore::new(0.72).expect("quality"))
        .with_severity(SecuritySeverity::Medium);
        let hypothesis = hypothesis(&process, &evidence, finding.id().clone());
        let fusion_summary = fusion_summary(
            vec![process.clone(), service.clone(), parent.clone()],
            &hypothesis,
            &evidence,
            finding.id().clone(),
        );
        ReadOnlyCommandState::bootstrap()
            .expect("bootstrap")
            .with_security_facts(vec![process, service, parent])
            .with_findings(vec![finding])
            .with_attack_hypotheses(vec![hypothesis])
            .with_fusion_summaries(vec![fusion_summary])
    }

    fn fact(layer: SecurityLayer, category: &str, context: &str) -> SecurityFact {
        let mut fact =
            SecurityFact::new(layer, category, "endpoint_runtime_test", Timestamp::now())
                .expect("fact");
        fact.evidence_refs = vec![EvidenceId::new_v4()];
        fact.provenance_id = Some(sentinel_contracts::DataSourceId::new_v4());
        fact.redaction_status = RedactionStatus::Redacted;
        fact.count_bucket = Some("low".to_string());
        match context {
            "script_capable_activity" => {
                fact.process_category = Some("script_category".to_string());
                fact.auth_category = Some("auth_failure_bucket".to_string());
                fact.saas_cloud_category = Some("saas_cloud_category".to_string());
            }
            "service_state_change" => {
                fact.status_category = Some("service_state_change".to_string());
            }
            "parent_category_transition" => {
                fact.parent_process_category = Some("shell_category".to_string());
                fact.relation_category = Some("parent_category_transition".to_string());
            }
            _ => {}
        }
        fact.validate().expect("safe fact");
        fact
    }

    fn hypothesis(
        fact: &SecurityFact,
        evidence: &EvidenceId,
        finding_id: sentinel_contracts::FindingId,
    ) -> AttackHypothesisRecord {
        let record = AttackHypothesisRecord {
            hypothesis_record_id: AttackHypothesisId::new_v4(),
            definition_id: "endpoint_threat_lite.possible_endpoint_activity_with_auth_pressure"
                .to_string(),
            version: "1.0.0".to_string(),
            category: "possible_endpoint_activity_with_auth_pressure".to_string(),
            fact_refs: vec![fact.fact_id.clone()],
            correlated_layers: vec![SecurityLayer::AuthorizedNativeProcess],
            correlation_count: 2,
            confidence_bucket: FusionConfidenceBucket::Low,
            degraded_reason: Some("metadata_only_visibility".to_string()),
            missing_visibility_flags: vec!["command_visibility_context_unavailable".to_string()],
            evidence_refs: vec![evidence.clone(), EvidenceId::new_v4()],
            finding_refs: vec![finding_id],
            risk_refs: Vec::new(),
            graph_hint_refs: Vec::new(),
            attack_candidates: Vec::new(),
            negative_evidence_notes: Vec::new(),
            benign_baseline_indicators: Vec::new(),
            optional_llm_story_marker: false,
            quality: QualityBreakdown::metadata_only(),
            created_at: Timestamp::now(),
        };
        record.validate().expect("safe hypothesis");
        record
    }

    fn fusion_summary(
        facts: Vec<SecurityFact>,
        hypothesis: &AttackHypothesisRecord,
        evidence: &EvidenceId,
        finding_id: sentinel_contracts::FindingId,
    ) -> FusionSummary {
        let summary = FusionSummary {
            generated_at: Timestamp::now(),
            sampler_health: Vec::new(),
            fact_count: facts.len() as u32,
            hypothesis_count: 1,
            fact_refs: facts.iter().map(|fact| fact.fact_id.clone()).collect(),
            hypothesis_refs: vec![hypothesis.hypothesis_record_id.clone()],
            facts,
            hypotheses: vec![hypothesis.clone()],
            top_correlated_layers: vec![FusionCount {
                label: "authorized_native_process".to_string(),
                count: 1,
            }],
            top_hypothesis_categories: vec![FusionCount {
                label: "possible_endpoint_activity_with_auth_pressure".to_string(),
                count: 1,
            }],
            degraded_visibility_context: vec!["metadata_only_visibility".to_string()],
            evidence_refs: vec![evidence.clone()],
            finding_refs: vec![finding_id],
            graph_hint_refs: Vec::new(),
            quality: QualityBreakdown::metadata_only(),
            privacy_class: PrivacyClass::Internal,
            automatic_llm_calls: false,
        };
        summary.validate().expect("safe fusion summary");
        summary
    }
}
