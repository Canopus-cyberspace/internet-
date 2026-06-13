use crate::evidence_quality::build_evidence_quality_summary;
use crate::native_sampler_readiness::get_native_sampler_readiness_summary;
use crate::read_commands::{
    build_attack_coverage_summary, get_native_sampler_runtime_summary, ReadOnlyCommandState,
};
use sentinel_contracts::{
    AlertId, AttackTaxonomy, CommandResult, CoreError, ErrorCode, ErrorSeverity, IncidentId,
    LlmAlertStoryDraft, LlmAlertStoryId, LlmAlertStoryProvider, LlmAlertStoryRecord,
    LlmAlertStoryRequest, LlmAlertStoryTimelineItem, LlmAttackTechniqueRef, SecuritySeverity,
    Timestamp, TraceId, MAX_LLM_STORY_LIST_ITEMS,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerateLlmAlertStoryRequest {
    pub alert_id: AlertId,
    pub incident_id: Option<IncidentId>,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
    pub explicit_user_action: bool,
    pub replay: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LlmAlertStoryGenerationGate {
    pub enabled: bool,
    pub authorization_granted: bool,
    pub session_api_key_available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LlmAlertStoryProviderOutput {
    pub draft: LlmAlertStoryDraft,
    pub response_hash: String,
}

pub trait LlmAlertStoryProviderClient {
    fn generate(
        &self,
        request: &LlmAlertStoryRequest,
    ) -> CommandResult<LlmAlertStoryProviderOutput>;
}

pub fn build_llm_alert_story_request(
    state: &ReadOnlyCommandState,
    alert_id: &AlertId,
    incident_id: Option<IncidentId>,
) -> CommandResult<LlmAlertStoryRequest> {
    let alert = state
        .alerts
        .items
        .iter()
        .find(|alert| alert.id() == alert_id)
        .ok_or_else(|| {
            safe_error(
                ErrorCode::InvalidRequest,
                "alert is not available for story generation",
            )
        })?;
    let findings = state
        .findings
        .items
        .iter()
        .filter(|finding| alert.finding_refs().contains(finding.id()))
        .collect::<Vec<_>>();
    let coverage = build_attack_coverage_summary(state)?;
    let quality = build_evidence_quality_summary(state)?;

    let detector_ids = bounded_unique_strings(
        findings
            .iter()
            .map(|finding| finding.finding_type().to_string()),
    );
    let finding_categories = detector_ids.clone();
    let redacted_entity_labels =
        bounded_unique_strings(alert.entity_refs().iter().map(|entity| {
            format!("entity:{:?}:redacted", entity.entity_type).to_ascii_lowercase()
        }));
    let provider_categories = bounded_unique_strings(findings.iter().filter_map(|finding| {
        let category = finding.finding_type().to_ascii_lowercase();
        ["saas", "cloud", "cdn", "object_storage", "tunnel", "proxy"]
            .into_iter()
            .find(|candidate| category.contains(candidate))
            .map(str::to_string)
    }));
    let attack_refs = bounded_attack_refs(findings.iter().flat_map(|finding| {
        finding.attack_mappings().iter().filter_map(|mapping| {
            if mapping.taxonomy != AttackTaxonomy::MitreAttackEnterprise {
                return None;
            }
            Some(LlmAttackTechniqueRef {
                tactic_id: mapping.tactic_id.clone()?,
                technique_id: mapping
                    .subtechnique_id
                    .clone()
                    .or_else(|| mapping.technique_id.clone())?,
            })
        })
    }));
    let evidence_refs = findings
        .iter()
        .flat_map(|finding| finding.evidence_refs().iter().cloned())
        .take(MAX_LLM_STORY_LIST_ITEMS)
        .collect();
    let risk_refs = alert
        .risk_event_refs()
        .iter()
        .take(MAX_LLM_STORY_LIST_ITEMS)
        .cloned()
        .collect();
    let quality_summaries = bounded_unique_strings(
        [
            format!("quality_records:{}", quality.record_count),
            format!("weak_single_signal:{}", quality.weak_single_signal_count),
            format!("corroborated:{}", quality.corroborated_count),
            format!("report_suitable:{}", quality.report_suitable_count),
            format!("export_suitable:{}", quality.export_suitable_count),
            format!("blocked_quality:{}", quality.blocked_count),
            "metadata_only:true".to_string(),
            "bounded_refs_only:true".to_string(),
        ]
        .into_iter()
        .chain(
            quality
                .degraded_reason_summary
                .iter()
                .map(|reason| format!("degraded:{reason}")),
        )
        .chain(
            quality
                .missing_visibility_flags
                .iter()
                .map(|flag| format!("missing_visibility:{flag}")),
        )
        .chain(
            quality
                .records
                .iter()
                .take(MAX_LLM_STORY_LIST_ITEMS)
                .map(|record| {
                    format!(
                        "bucket:{:?}:visibility:{:?}:uncertainty:{:?}:report:{:?}:export:{:?}",
                        record.quality.evidence_quality_bucket,
                        record.quality.visibility_completeness_bucket,
                        record.quality.uncertainty_bucket,
                        record.quality.report_suitability_bucket,
                        record.quality.export_suitability_bucket
                    )
                    .to_ascii_lowercase()
                }),
        ),
    );
    let mut timeline = vec![LlmAlertStoryTimelineItem {
        timestamp: Timestamp::now(),
        category: "alert_selected".to_string(),
    }];
    timeline.extend(
        findings
            .iter()
            .take(MAX_LLM_STORY_LIST_ITEMS - 1)
            .map(|finding| LlmAlertStoryTimelineItem {
                timestamp: Timestamp::now(),
                category: format!("finding:{}", finding.finding_type()),
            }),
    );
    let native_readiness_summaries = get_native_sampler_readiness_summary(state)
        .ok()
        .map(|summary| {
            bounded_unique_strings(summary.contract_refs.iter().map(|sampler_ref| {
                format!(
                    "sampler:{sampler_ref}:ready:{}:blocked:{}:active:0",
                    summary.ready_when_implemented_count, summary.blocked_count
                )
            }))
        })
        .unwrap_or_default();
    let native_runtime_summaries = get_native_sampler_runtime_summary(state)
        .ok()
        .map(|summary| {
            bounded_unique_strings(
                [
                    format!("native_runtime_count:{}", summary.runtime_count),
                    format!("native_active_count:{}", summary.active_count),
                    format!("native_quality_bucket:{}", summary.quality_bucket),
                    format!(
                        "native_health_visibility:{}",
                        summary.native_health_visibility_available
                    ),
                    format!(
                        "native_service_visibility:{}",
                        summary.service_visibility_available
                    ),
                    format!(
                        "native_process_category_visibility:{}",
                        summary.process_visibility_available
                    ),
                    format!(
                        "native_parent_process_category_visibility:{}",
                        summary.parent_process_visibility_available
                    ),
                    "native_specific_process_identity:false".to_string(),
                    "native_process_network_attribution:false".to_string(),
                    "native_packet_visibility:false".to_string(),
                    "native_response_execution:false".to_string(),
                    format!("native_fact_refs:{}", summary.fact_refs.len()),
                ]
                .into_iter()
                .chain(summary.statuses.iter().map(|status| {
                    format!(
                        "native_sampler:{}:{:?}:{:?}:health:{:?}",
                        status.sampler_id,
                        status.runtime_state,
                        status.provider_availability_state,
                        status.health_state
                    )
                    .to_ascii_lowercase()
                }))
                .chain(summary.service_category_counts.iter().map(|count| {
                    format!(
                        "native_service_category:{:?}:{}",
                        count.service_category, count.count_bucket
                    )
                    .to_ascii_lowercase()
                }))
                .chain(summary.service_state_counts.iter().map(|count| {
                    format!(
                        "native_service_state:{}:{}",
                        count.label, count.count_bucket
                    )
                }))
                .chain(summary.startup_type_counts.iter().map(|count| {
                    format!(
                        "native_service_startup:{}:{}",
                        count.label, count.count_bucket
                    )
                }))
                .chain(summary.process_category_counts.iter().map(|count| {
                    format!(
                        "native_process_category:{:?}:{}",
                        count.process_category, count.count_bucket
                    )
                    .to_ascii_lowercase()
                }))
                .chain(summary.parent_process_category_counts.iter().map(|count| {
                    format!(
                        "native_parent_process_category:{:?}:{}",
                        count.process_category, count.count_bucket
                    )
                    .to_ascii_lowercase()
                }))
                .chain(summary.process_relation_counts.iter().map(|count| {
                    format!(
                        "native_process_relation:{}:{}",
                        count.label, count.count_bucket
                    )
                })),
            )
        })
        .unwrap_or_default();
    let native_sampler_readiness_summaries = bounded_unique_strings(
        native_readiness_summaries
            .into_iter()
            .chain(native_runtime_summaries),
    );

    let request = LlmAlertStoryRequest {
        alert_ref: alert.id().clone(),
        incident_ref: incident_id,
        severity: severity_label(alert.severity()).to_string(),
        risk_bucket: risk_bucket(alert.severity()).to_string(),
        detector_ids,
        finding_categories,
        redacted_entity_labels,
        destination_categories: provider_categories.clone(),
        provider_categories,
        quality_summaries,
        native_sampler_readiness_summaries,
        evidence_refs,
        risk_refs,
        attack_refs,
        timeline,
        redaction_indicators: vec![
            "metadata_only".to_string(),
            "bounded_refs_only".to_string(),
            "no_raw_values".to_string(),
        ],
        degraded_indicators: vec![
            "specific_process_identity_unavailable".to_string(),
            "process_network_attribution_unavailable".to_string(),
            "no_complete_attack_coverage".to_string(),
            coverage
                .degraded_reason
                .unwrap_or_else(|| "metadata_only_visibility".to_string()),
        ],
    };
    request.validate().map_err(contract_error)?;
    Ok(request)
}

pub fn generate_llm_alert_story(
    state: &ReadOnlyCommandState,
    request: &GenerateLlmAlertStoryRequest,
    gate: &LlmAlertStoryGenerationGate,
    provider_kind: LlmAlertStoryProvider,
    model: String,
    provider: &dyn LlmAlertStoryProviderClient,
) -> CommandResult<LlmAlertStoryRecord> {
    if request.reason_redacted.trim().is_empty() || !request.explicit_user_action {
        return Err(safe_error(
            ErrorCode::InvalidRequest,
            "LLM alert story generation requires an explicit user action and reason",
        ));
    }
    if request.replay {
        return Err(safe_error(
            ErrorCode::PolicyDenial,
            "LLM alert story generation is disabled during replay",
        ));
    }
    if !gate.enabled {
        return Err(safe_error(
            ErrorCode::PolicyDenial,
            "LLM alert story generation is disabled",
        ));
    }
    if !gate.authorization_granted {
        return Err(safe_error(
            ErrorCode::PermissionDenied,
            "LLM provider authorization is required",
        ));
    }
    if !gate.session_api_key_available {
        return Err(safe_error(
            ErrorCode::ServiceUnavailable,
            "A session-only API key is required",
        ));
    }

    let bounded_request =
        build_llm_alert_story_request(state, &request.alert_id, request.incident_id.clone())?;
    let request_hash = sha256_json(&bounded_request)?;
    let output = provider.generate(&bounded_request)?;
    output.draft.validate().map_err(contract_error)?;
    validate_sha256(&output.response_hash)?;

    let story = LlmAlertStoryRecord {
        story_id: LlmAlertStoryId::new_v4(),
        alert_ref: bounded_request.alert_ref,
        incident_ref: bounded_request.incident_ref,
        provider: provider_kind,
        model,
        request_hash,
        response_hash: output.response_hash,
        generated_at: Timestamp::now(),
        ai_generated: true,
        redaction_passed: true,
        degraded: !bounded_request.degraded_indicators.is_empty(),
        story: output.draft,
        evidence_refs: bounded_request.evidence_refs,
        risk_refs: bounded_request.risk_refs,
        attack_refs: bounded_request.attack_refs,
    };
    story.validate().map_err(contract_error)?;
    Ok(story)
}

fn bounded_unique_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut bounded = Vec::new();
    for value in values {
        if bounded.len() >= MAX_LLM_STORY_LIST_ITEMS {
            break;
        }
        if !bounded.contains(&value) {
            bounded.push(value);
        }
    }
    bounded
}

fn bounded_attack_refs(
    values: impl IntoIterator<Item = LlmAttackTechniqueRef>,
) -> Vec<LlmAttackTechniqueRef> {
    let mut bounded = Vec::new();
    for value in values {
        if bounded.len() >= MAX_LLM_STORY_LIST_ITEMS {
            break;
        }
        if !bounded.contains(&value) {
            bounded.push(value);
        }
    }
    bounded
}

fn severity_label(severity: &SecuritySeverity) -> &'static str {
    match severity {
        SecuritySeverity::Informational => "informational",
        SecuritySeverity::Low => "low",
        SecuritySeverity::Medium => "medium",
        SecuritySeverity::High => "high",
        SecuritySeverity::Critical => "critical",
    }
}

fn risk_bucket(severity: &SecuritySeverity) -> &'static str {
    match severity {
        SecuritySeverity::Informational | SecuritySeverity::Low => "guarded",
        SecuritySeverity::Medium => "elevated",
        SecuritySeverity::High | SecuritySeverity::Critical => "high",
    }
}

fn sha256_json(value: &impl Serialize) -> CommandResult<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| {
        safe_error(
            ErrorCode::InternalError,
            "bounded LLM story request serialization failed",
        )
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_sha256(value: &str) -> CommandResult<()> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(safe_error(
            ErrorCode::ValidationFailure,
            "LLM provider response hash is invalid",
        ))
    }
}

fn contract_error(error: impl std::fmt::Display) -> CoreError {
    safe_error(
        ErrorCode::ValidationFailure,
        format!("LLM alert story failed safety validation: {error}"),
    )
}

fn safe_error(code: ErrorCode, message: impl Into<String>) -> CoreError {
    CoreError::new(code, message)
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({ "operation": "llm_alert_story" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{demo_story::FixtureRunner, ReadOnlyCommandState};
    use std::cell::Cell;

    struct FakeProvider {
        calls: Cell<u32>,
        draft: LlmAlertStoryDraft,
    }

    impl LlmAlertStoryProviderClient for FakeProvider {
        fn generate(
            &self,
            _request: &LlmAlertStoryRequest,
        ) -> CommandResult<LlmAlertStoryProviderOutput> {
            self.calls.set(self.calls.get() + 1);
            Ok(LlmAlertStoryProviderOutput {
                draft: self.draft.clone(),
                response_hash: "a".repeat(64),
            })
        }
    }

    #[test]
    fn llm_alert_story_disabled_replay_and_missing_key_never_call_provider() {
        let (state, alert_id) = story_state();
        let provider = FakeProvider {
            calls: Cell::new(0),
            draft: safe_draft(),
        };
        let request = explicit_request(alert_id);
        for gate in [
            LlmAlertStoryGenerationGate {
                enabled: false,
                authorization_granted: true,
                session_api_key_available: true,
            },
            LlmAlertStoryGenerationGate {
                enabled: true,
                authorization_granted: true,
                session_api_key_available: false,
            },
        ] {
            assert!(generate_llm_alert_story(
                &state,
                &request,
                &gate,
                LlmAlertStoryProvider::OpenAiCompatible,
                "safe-model".to_string(),
                &provider,
            )
            .is_err());
        }
        let mut replay = request.clone();
        replay.replay = true;
        assert!(generate_llm_alert_story(
            &state,
            &replay,
            &enabled_gate(),
            LlmAlertStoryProvider::OpenAiCompatible,
            "safe-model".to_string(),
            &provider,
        )
        .is_err());
        assert_eq!(provider.calls.get(), 0);
    }

    #[test]
    fn llm_alert_story_explicit_generation_stores_only_bounded_redacted_record() {
        let (state, alert_id) = story_state();
        let provider = FakeProvider {
            calls: Cell::new(0),
            draft: safe_draft(),
        };
        let story = generate_llm_alert_story(
            &state,
            &explicit_request(alert_id),
            &enabled_gate(),
            LlmAlertStoryProvider::AnthropicCompatible,
            "safe-model".to_string(),
            &provider,
        )
        .expect("story");
        let serialized = serde_json::to_string(&story).expect("serialized story");

        assert_eq!(provider.calls.get(), 1);
        assert!(story.redaction_passed);
        assert!(!story.evidence_refs.is_empty());
        assert!(!story.risk_refs.is_empty());
        assert!(!story.attack_refs.is_empty());
        for forbidden in [
            "api_key",
            "authorization",
            "cookie",
            "192.0.2.42",
            "https://",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn llm_alert_story_rejects_unsafe_provider_output_without_storing_it() {
        let (state, alert_id) = story_state();
        let mut draft = safe_draft();
        draft.report_text_redacted = "contact analyst@example.test".to_string();
        let provider = FakeProvider {
            calls: Cell::new(0),
            draft,
        };
        assert!(generate_llm_alert_story(
            &state,
            &explicit_request(alert_id),
            &enabled_gate(),
            LlmAlertStoryProvider::DeepSeek,
            "safe-model".to_string(),
            &provider,
        )
        .is_err());
        assert_eq!(provider.calls.get(), 1);
    }

    fn story_state() -> (ReadOnlyCommandState, AlertId) {
        let replay = FixtureRunner::from_default_fixture()
            .expect("fixture")
            .run()
            .expect("replay");
        let state = replay
            .read_model
            .into_read_state(ReadOnlyCommandState::bootstrap().expect("state"));
        let alert_id = state.alerts.items[0].id().clone();
        (state, alert_id)
    }

    fn explicit_request(alert_id: AlertId) -> GenerateLlmAlertStoryRequest {
        GenerateLlmAlertStoryRequest {
            alert_id,
            incident_id: None,
            reason_redacted: "generate bounded alert story".to_string(),
            requested_by_redacted: Some("local_user".to_string()),
            explicit_user_action: true,
            replay: false,
        }
    }

    fn enabled_gate() -> LlmAlertStoryGenerationGate {
        LlmAlertStoryGenerationGate {
            enabled: true,
            authorization_granted: true,
            session_api_key_available: true,
        }
    }

    fn safe_draft() -> LlmAlertStoryDraft {
        LlmAlertStoryDraft {
            alert_narrative_redacted: "Metadata signals form a bounded alert sequence.".to_string(),
            likely_attack_summary_redacted:
                "Observed behavior may align with the linked degraded ATT&CK techniques."
                    .to_string(),
            confidence_uncertainty_redacted: "Confidence is limited by metadata-only visibility."
                .to_string(),
            evidence_summary_redacted: "Linked evidence refs support the bounded finding."
                .to_string(),
            affected_entities_redacted: vec!["entity:redacted".to_string()],
            investigation_suggestions_redacted: vec![
                "Review linked evidence refs and timeline buckets.".to_string(),
            ],
            report_text_redacted: "AI-generated bounded story for analyst review.".to_string(),
        }
    }
}
