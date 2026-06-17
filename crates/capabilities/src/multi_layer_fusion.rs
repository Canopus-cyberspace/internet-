use sentinel_contracts::{
    AttackHypothesisRecord, AttackMapping, DnsObservation, EntityId, EntityRef, EntityType,
    EvidenceItem, Finding, FindingExplanation, FusionAttackCandidate, FusionConfidenceBucket,
    FusionContractError, FusionCount, FusionSummary, GraphHint, GraphHintType, HttpMetadata,
    IntelligenceRecordId, LayeredSamplerDeclaration, MappingProvenance, PluginId,
    PortableAuthMetadata, PortableCaptureInputSourceType, PortableCaptureProvenance,
    PortableDeceptionEventMetadata, PortableProviderCategory, PortableSaasCloudMetadata,
    PortableSdnControlPlaneEventCategory, PortableSdnControlPlaneMetadata, PrivacyClass,
    QualityBreakdown, QualityScore, RiskHint, RiskReason, SamplerState, SamplingMode, SecurityFact,
    SecurityLayer, SecuritySeverity, Timestamp, MAX_FUSION_ITEMS, MAX_FUSION_REFS,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MULTI_LAYER_FUSION_SCHEMA_VERSION: sentinel_contracts::SchemaVersion =
    sentinel_contracts::SchemaVersion::new(1, 0, 0);
pub const SECURITY_FACT_CONTRACT: &str = "security.fact";
pub const SECURITY_HYPOTHESIS_CONTRACT: &str = "security.hypothesis";
pub const MULTI_LAYER_FUSION_STATIC_PLUGIN_KEY: &str = "multi_layer_security_fusion";

#[derive(Clone, Debug, PartialEq)]
pub struct MultiLayerFusionInput<'a> {
    pub provenance: &'a PortableCaptureProvenance,
    pub dns_observations: &'a [DnsObservation],
    pub http_metadata: &'a [HttpMetadata],
    pub auth_metadata: &'a [PortableAuthMetadata],
    pub saas_cloud_metadata: &'a [PortableSaasCloudMetadata],
    pub deception_events: &'a [PortableDeceptionEventMetadata],
    pub sdn_control_plane_metadata: &'a [PortableSdnControlPlaneMetadata],
    pub findings: &'a [Finding],
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MultiLayerFusionOutput {
    pub facts: Vec<SecurityFact>,
    pub hypotheses: Vec<AttackHypothesisRecord>,
    pub findings: Vec<Finding>,
    pub evidence: Vec<EvidenceItem>,
    pub risk_hints: Vec<RiskHint>,
    pub graph_hints: Vec<GraphHint>,
    pub summary: Option<FusionSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultiLayerFusionError {
    Contract(String),
}

impl fmt::Display for MultiLayerFusionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(reason) => write!(formatter, "fusion contract error: {reason}"),
        }
    }
}

impl std::error::Error for MultiLayerFusionError {}

impl From<FusionContractError> for MultiLayerFusionError {
    fn from(value: FusionContractError) -> Self {
        Self::Contract(value.to_string())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MultiLayerSecurityFusionPlugin;

impl MultiLayerSecurityFusionPlugin {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(
        &self,
        producer_plugin: &PluginId,
        input: MultiLayerFusionInput<'_>,
    ) -> Result<MultiLayerFusionOutput, MultiLayerFusionError> {
        let mut facts = normalize_security_facts(&input)?;
        facts.truncate(MAX_FUSION_ITEMS);
        let mut output = MultiLayerFusionOutput {
            facts,
            ..MultiLayerFusionOutput::default()
        };

        for definition in attack_hypothesis_catalog()? {
            if output.hypotheses.len() >= MAX_FUSION_ITEMS {
                break;
            }
            let Some(matched_facts) = match_definition(&definition, &output.facts) else {
                continue;
            };
            emit_hypothesis(producer_plugin, &definition, &matched_facts, &mut output)?;
        }

        let mut summary = FusionSummary {
            generated_at: Timestamp::now(),
            sampler_health: layered_sampler_catalog()?,
            fact_count: output.facts.len() as u32,
            hypothesis_count: output.hypotheses.len() as u32,
            facts: output.facts.clone(),
            hypotheses: output.hypotheses.clone(),
            top_correlated_layers: count_labels(
                output
                    .hypotheses
                    .iter()
                    .flat_map(|record| record.correlated_layers.iter())
                    .map(layer_label),
            ),
            top_hypothesis_categories: count_labels(
                output
                    .hypotheses
                    .iter()
                    .map(|record| record.category.clone()),
            ),
            degraded_visibility_context: vec![
                "metadata_only_visibility".to_string(),
                "no_process_attribution".to_string(),
                "no_packet_visibility".to_string(),
                "no_provider_control_plane".to_string(),
            ],
            fact_refs: output
                .facts
                .iter()
                .map(|fact| fact.fact_id.clone())
                .collect(),
            hypothesis_refs: output
                .hypotheses
                .iter()
                .map(|record| record.hypothesis_record_id.clone())
                .collect(),
            evidence_refs: bounded_unique(
                output
                    .hypotheses
                    .iter()
                    .flat_map(|record| record.evidence_refs.iter().cloned())
                    .collect(),
            ),
            finding_refs: output
                .findings
                .iter()
                .map(|finding| finding.id().clone())
                .collect(),
            graph_hint_refs: output
                .graph_hints
                .iter()
                .map(|hint| hint.hint_id.clone())
                .collect(),
            quality: quality_for_fusion_summary(&output.hypotheses),
            privacy_class: PrivacyClass::Internal,
            automatic_llm_calls: false,
        };
        summary.fact_refs.truncate(MAX_FUSION_REFS);
        summary.hypothesis_refs.truncate(MAX_FUSION_REFS);
        summary.finding_refs.truncate(MAX_FUSION_REFS);
        summary.graph_hint_refs.truncate(MAX_FUSION_REFS);
        summary.validate()?;
        output.summary = Some(summary);
        Ok(output)
    }
}

pub fn layered_sampler_catalog() -> Result<Vec<LayeredSamplerDeclaration>, MultiLayerFusionError> {
    let portable = [
        (
            "dns_metadata_sampler",
            SecurityLayer::Dns,
            "portable_import",
            &["dns_observation", "nxdomain_burst", "entropy_category"][..],
            &["network.dns.observation"][..],
        ),
        (
            "cdn_edge_metadata_sampler",
            SecurityLayer::CdnEdge,
            "imported_edge_metadata",
            &["edge_result", "cache_origin_bucket"][..],
            &["network.http.metadata"][..],
        ),
        (
            "waf_metadata_sampler",
            SecurityLayer::Waf,
            "imported_waf_metadata",
            &["waf_action", "attack_class", "bypass_transition"][..],
            &["network.http.metadata"][..],
        ),
        (
            "api_metadata_sampler",
            SecurityLayer::Api,
            "portable_http_metadata",
            &["api_method_status", "route_fingerprint"][..],
            &["network.http.metadata"][..],
        ),
        (
            "http_metadata_sampler",
            SecurityLayer::Http,
            "portable_http_metadata",
            &["http_method_status", "upload_download_bucket"][..],
            &["network.http.metadata"][..],
        ),
        (
            "auth_identity_metadata_sampler",
            SecurityLayer::AuthIdentity,
            "imported_auth_metadata",
            &["auth_result", "mfa_result", "failure_burst"][..],
            &["identity.auth_metadata"][..],
        ),
        (
            "saas_cloud_metadata_sampler",
            SecurityLayer::SaasCloud,
            "imported_provider_metadata",
            &["provider_category", "api_anomaly", "upload_ratio"][..],
            &["cloud.saas_metadata"][..],
        ),
        (
            "deception_metadata_sampler",
            SecurityLayer::Deception,
            "imported_deception_metadata",
            &["deception_interaction", "protocol_category"][..],
            &["deception.event_metadata"][..],
        ),
        (
            "sdn_control_plane_metadata_sampler",
            SecurityLayer::SdnControlPlane,
            "imported_sdn_control_plane_metadata",
            &["control_plane_change", "policy_route_scope"][..],
            &["network.sdn_control_plane.metadata"][..],
        ),
        (
            "localhost_metadata_proxy_sampler",
            SecurityLayer::LocalMetadataProxy,
            "explicit_local_proxy_drain",
            &["proxy_result", "duration_bucket", "byte_bucket"][..],
            &["network.http.metadata"][..],
        ),
    ];
    let mut samplers = portable
        .into_iter()
        .map(
            |(id, layer, source, categories, topics)| LayeredSamplerDeclaration {
                sampler_id: id.to_string(),
                layer,
                source_kind: source.to_string(),
                state: SamplerState::Enabled,
                sampling_mode: if id == "localhost_metadata_proxy_sampler" {
                    SamplingMode::ExplicitDrain
                } else {
                    SamplingMode::ConfirmedImport
                },
                interval_seconds: None,
                record_limit: 128,
                byte_limit: 4 * 1024 * 1024,
                checkpoint_state: "session_scoped".to_string(),
                health_reason: Some("portable_metadata_only".to_string()),
                output_fact_categories: categories
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                event_bus_topics: topics.iter().map(|value| (*value).to_string()).collect(),
                privacy_boundary: "bounded_redacted_metadata_only".to_string(),
                visibility_requirements: vec!["portable_metadata".to_string()],
                portable_default_available: true,
            },
        )
        .collect::<Vec<_>>();
    samplers.extend([
        placeholder_sampler("sdn_metadata_placeholder", SecurityLayer::SdnPlaceholder),
        placeholder_sampler(
            "authorized_native_host_placeholder",
            SecurityLayer::AuthorizedNativeHostPlaceholder,
        ),
    ]);
    for sampler in &samplers {
        sampler.validate()?;
    }
    Ok(samplers)
}

fn placeholder_sampler(id: &str, layer: SecurityLayer) -> LayeredSamplerDeclaration {
    LayeredSamplerDeclaration {
        sampler_id: id.to_string(),
        layer,
        source_kind: "placeholder".to_string(),
        state: SamplerState::NotAuthorized,
        sampling_mode: SamplingMode::Placeholder,
        interval_seconds: None,
        record_limit: 1,
        byte_limit: 1,
        checkpoint_state: "not_available".to_string(),
        health_reason: Some("requires_authorized_integration".to_string()),
        output_fact_categories: vec!["placeholder_status".to_string()],
        event_bus_topics: vec![SECURITY_FACT_CONTRACT.to_string()],
        privacy_boundary: "no_data_access".to_string(),
        visibility_requirements: vec!["authorized_integration".to_string()],
        portable_default_available: false,
    }
}

fn normalize_security_facts(
    input: &MultiLayerFusionInput<'_>,
) -> Result<Vec<SecurityFact>, MultiLayerFusionError> {
    let mut facts = Vec::new();
    for dns in input.dns_observations {
        let category = if dns
            .response_code
            .as_deref()
            .is_some_and(|code| code.eq_ignore_ascii_case("nxdomain"))
        {
            "nxdomain_observed"
        } else if dns
            .features
            .character_entropy
            .is_some_and(|value| value >= 3.5)
        {
            "high_entropy_label"
        } else if dns.features.subdomain_depth >= 4 {
            "excessive_subdomain_depth"
        } else if dns.features.answer_count <= 1 {
            "sparse_answer_domain"
        } else {
            "dns_observation"
        };
        let mut fact = SecurityFact::new(
            SecurityLayer::Dns,
            category,
            "dns_metadata_sampler",
            dns.timestamp.clone(),
        )?;
        fact.provenance_id = Some(input.provenance.provenance_id.clone());
        fact.domain_category_ref = Some("redacted_domain_category".to_string());
        fact.confidence_hint = dns.quality_score.clone();
        fact.validate()?;
        facts.push(fact);
    }
    for http in input.http_metadata {
        let mut fact = SecurityFact::new(
            if http.api_hint.is_some() {
                SecurityLayer::Api
            } else {
                SecurityLayer::Http
            },
            http_category(http),
            if http.api_hint.is_some() {
                "api_metadata_sampler"
            } else {
                "http_metadata_sampler"
            },
            http.timestamp.clone(),
        )?;
        fact.provenance_id = Some(input.provenance.provenance_id.clone());
        fact.route_fingerprint = http.endpoint_fingerprint.clone();
        fact.method_category = Some(format!("{:?}", http.method).to_ascii_lowercase());
        fact.status_category = Some(status_bucket(http.status_code));
        fact.confidence_hint = http.quality_score.clone();
        fact.validate()?;
        facts.push(fact);

        if http.waf_action.is_some() || http.waf_attack_class.is_some() {
            let mut waf = SecurityFact::new(
                SecurityLayer::Waf,
                if http
                    .waf_action
                    .as_deref()
                    .is_some_and(|value| value.to_ascii_lowercase().contains("block"))
                {
                    "waf_blocked_action"
                } else {
                    "waf_observation"
                },
                "waf_metadata_sampler",
                http.timestamp.clone(),
            )?;
            waf.provenance_id = Some(input.provenance.provenance_id.clone());
            waf.route_fingerprint = http.endpoint_fingerprint.clone();
            waf.confidence_hint = http.quality_score.clone();
            waf.validate()?;
            facts.push(waf);
        }
        if http.result_label.as_deref().is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("edge") || value.contains("cache") || value.contains("origin")
        }) {
            let mut edge = SecurityFact::new(
                SecurityLayer::CdnEdge,
                "edge_result_observed",
                "cdn_edge_metadata_sampler",
                http.timestamp.clone(),
            )?;
            edge.provenance_id = Some(input.provenance.provenance_id.clone());
            edge.cache_edge_origin_bucket = Some("edge_origin_metadata".to_string());
            edge.route_fingerprint = http.endpoint_fingerprint.clone();
            edge.confidence_hint = http.quality_score.clone();
            edge.validate()?;
            facts.push(edge);
        }
        if input.provenance.source_type == PortableCaptureInputSourceType::LocalProxyMetadata {
            let mut proxy = SecurityFact::new(
                SecurityLayer::LocalMetadataProxy,
                "proxy_metadata_observed",
                "localhost_metadata_proxy_sampler",
                http.timestamp.clone(),
            )?;
            proxy.provenance_id = Some(input.provenance.provenance_id.clone());
            proxy.route_fingerprint = http.endpoint_fingerprint.clone();
            proxy.status_category = Some(status_bucket(http.status_code));
            proxy.validate()?;
            facts.push(proxy);
        }
    }
    for auth in input.auth_metadata {
        let mut fact = SecurityFact::new(
            SecurityLayer::AuthIdentity,
            "auth_result_observed",
            "auth_identity_metadata_sampler",
            auth.time_bucket_start.clone(),
        )?;
        fact.provider_service_category = Some(auth.provider_category.clone());
        fact.auth_category = Some(format!("{:?}", auth.auth_result).to_ascii_lowercase());
        fact.identity_session_label_redacted = auth
            .identity_label_redacted
            .clone()
            .or_else(|| auth.source_session_label.clone());
        fact.provenance_id = Some(auth.provenance_id.clone());
        fact.redaction_status = auth.redaction_status.clone();
        fact.confidence_hint = auth.quality_score.clone();
        fact.validate()?;
        facts.push(fact);
    }
    for saas in input.saas_cloud_metadata {
        let mut fact = SecurityFact::new(
            SecurityLayer::SaasCloud,
            "provider_activity_observed",
            "saas_cloud_metadata_sampler",
            saas.time_bucket_start.clone(),
        )?;
        fact.provider_service_category = Some(provider_label(&saas.provider_category));
        fact.route_fingerprint = saas.endpoint_fingerprint.clone();
        fact.method_category = Some(format!("{:?}", saas.api_method_category).to_ascii_lowercase());
        fact.status_category = Some(format!("{:?}", saas.status_bucket).to_ascii_lowercase());
        fact.saas_cloud_category =
            Some(format!("{:?}", saas.upload_download_ratio_bucket).to_ascii_lowercase());
        fact.identity_session_label_redacted = saas
            .identity_label_redacted
            .clone()
            .or_else(|| saas.source_session_label.clone());
        fact.evidence_refs = saas.evidence_refs.clone();
        fact.provenance_id = Some(saas.provenance_id.clone());
        fact.redaction_status = saas.redaction_status.clone();
        fact.confidence_hint = saas.quality_score.clone();
        fact.validate()?;
        facts.push(fact);
    }
    for event in input.deception_events {
        let mut fact = SecurityFact::new(
            SecurityLayer::Deception,
            "deception_interaction_observed",
            "deception_metadata_sampler",
            event.time_bucket_start.clone(),
        )?;
        fact.deception_category = Some(event.event_category.clone());
        fact.protocol_category =
            Some(format!("{:?}", event.protocol_category).to_ascii_lowercase());
        fact.identity_session_label_redacted = event.decoy_sensor_ref.clone();
        fact.evidence_refs = event.evidence_refs.clone();
        fact.provenance_id = Some(event.provenance_id.clone());
        fact.redaction_status = event.redaction_status.clone();
        fact.confidence_hint = event.quality_score.clone();
        fact.validate()?;
        facts.push(fact);
    }
    for sdn in input.sdn_control_plane_metadata {
        let mut fact = SecurityFact::new(
            SecurityLayer::SdnControlPlane,
            sdn_fact_category(&sdn.event_category),
            "sdn_control_plane_metadata_sampler",
            sdn.time_bucket_start.clone(),
        )?;
        fact.provider_service_category = Some(sdn_controller_label(&sdn.controller_category));
        fact.status_category = Some(format!("{:?}", sdn.status_bucket).to_ascii_lowercase());
        fact.relation_category = sdn
            .route_change_category
            .clone()
            .or_else(|| sdn.topology_change_category.clone())
            .or_else(|| sdn.policy_action_category.clone());
        fact.execution_context_category = sdn.affected_asset_category.clone();
        fact.trust_category = sdn.exposure_category.clone();
        fact.lifecycle_bucket = Some(format!("{:?}", sdn.impact_scope_bucket).to_ascii_lowercase());
        fact.count_bucket = sdn.count_bucket.clone();
        fact.evidence_refs = sdn.evidence_refs.clone();
        fact.provenance_id = Some(sdn.provenance_id.clone());
        fact.redaction_status = sdn.redaction_status.clone();
        fact.missing_visibility_flags = bounded_unique(
            sdn.missing_visibility_flags
                .iter()
                .cloned()
                .chain(["no_live_controller_api_visibility".to_string()])
                .collect(),
        );
        fact.degraded_reason = Some("metadata_only_sdn_control_plane_import".to_string());
        fact.confidence_hint = sdn.quality_score.clone();
        fact.validate()?;
        facts.push(fact);
    }
    for finding in input.findings {
        let mut fact = SecurityFact::new(
            layer_from_finding(finding.finding_type()),
            finding.finding_type(),
            "evidence_backed_finding_sampler",
            Timestamp::now(),
        )?;
        fact.evidence_refs = finding.evidence_refs().to_vec();
        fact.provenance_id = Some(input.provenance.provenance_id.clone());
        fact.confidence_hint = finding.confidence().clone();
        fact.validate()?;
        facts.push(fact);
    }
    Ok(facts)
}

fn emit_hypothesis(
    producer_plugin: &PluginId,
    definition: &sentinel_contracts::AttackHypothesisDefinition,
    facts: &[SecurityFact],
    output: &mut MultiLayerFusionOutput,
) -> Result<(), MultiLayerFusionError> {
    let prior_evidence = bounded_unique(
        facts
            .iter()
            .flat_map(|fact| fact.evidence_refs.iter().cloned())
            .collect(),
    );
    if prior_evidence.len() < definition.minimum_evidence as usize {
        return Ok(());
    }
    let layers = facts
        .iter()
        .map(|fact| fact.layer.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let confidence_bucket = if layers.len() >= 3 && prior_evidence.len() >= 2 {
        definition.confidence_cap.clone()
    } else {
        FusionConfidenceBucket::Low
    };
    let confidence = quality(match confidence_bucket {
        FusionConfidenceBucket::Medium => 0.68,
        FusionConfidenceBucket::Low => 0.48,
        FusionConfidenceBucket::Unknown => 0.35,
    })?;
    let prior_evidence_count = prior_evidence.len();
    let hypothesis_quality = quality_for_hypothesis(&layers, prior_evidence_count, definition);
    let summary = format!(
        "Possible {} correlated across {} bounded metadata layers.",
        definition.category.replace('_', " "),
        layers.len()
    );
    let mut evidence = EvidenceItem::new("multi_layer_fusion_hypothesis", summary.clone())
        .map_err(contract_error)?;
    evidence.confidence = confidence.clone();
    evidence.weight = confidence.clone();
    evidence.privacy_class = PrivacyClass::Internal;
    evidence.description_redacted = Some(
        "Evidence-backed fusion record; missing native and provider-control visibility reduces confidence."
            .to_string(),
    );

    let mut reason =
        RiskReason::new("multi_layer_fusion", summary.clone()).map_err(contract_error)?;
    reason.confidence = confidence.clone();
    reason.evidence_refs = vec![evidence.evidence_id.clone()];
    reason.attack_mappings = attack_mappings(definition, &confidence)?;
    let mut explanation = FindingExplanation::new(summary.clone()).map_err(contract_error)?;
    explanation.risk_reasons = vec![reason.clone()];
    explanation.limitations_redacted = vec![
        "Metadata-only fusion does not confirm compromise, credential use, process attribution, or execution."
            .to_string(),
    ];
    let finding = Finding::new(
        format!("fusion.{}", definition.category),
        producer_plugin.clone(),
        vec![evidence.evidence_id.clone()],
        explanation,
    )
    .map_err(contract_error)?
    .with_confidence(confidence.clone())
    .with_severity(SecuritySeverity::Medium)
    .with_risk_reasons(vec![reason])
    .with_attack_mappings(attack_mappings(definition, &confidence)?);

    let mut record = AttackHypothesisRecord {
        hypothesis_record_id: sentinel_contracts::AttackHypothesisId::new_v4(),
        definition_id: definition.hypothesis_id.clone(),
        version: definition.version.clone(),
        category: definition.category.clone(),
        fact_refs: facts.iter().map(|fact| fact.fact_id.clone()).collect(),
        correlated_layers: layers,
        correlation_count: facts.len() as u32,
        confidence_bucket,
        degraded_reason: Some("metadata_only_visibility".to_string()),
        missing_visibility_flags: definition.missing_visibility_flags.clone(),
        evidence_refs: {
            let mut refs = prior_evidence;
            refs.push(evidence.evidence_id.clone());
            bounded_unique(refs)
        },
        finding_refs: vec![finding.id().clone()],
        risk_refs: Vec::new(),
        graph_hint_refs: Vec::new(),
        attack_candidates: definition.attack_candidates.clone(),
        negative_evidence_notes: vec!["no_authorized_native_corroboration".to_string()],
        benign_baseline_indicators: Vec::new(),
        optional_llm_story_marker: true,
        quality: hypothesis_quality,
        created_at: Timestamp::now(),
    };

    let mut risk_hint = RiskHint::new(
        format!("fusion.{}", definition.category),
        summary,
        vec![IntelligenceRecordId::new_v4()],
    )
    .map_err(contract_error)?
    .with_risk_delta(8.0 + record.correlation_count.min(5) as f32)
    .with_confidence(confidence.clone());
    risk_hint.entity_ref = Some(finding_entity(&finding));
    risk_hint.privacy_class = PrivacyClass::Internal;

    let mut graph_hint = GraphHint::new(
        GraphHintType::Custom("hypothesis_correlates_security_facts".to_string()),
        hypothesis_entity(&record),
        finding_entity(&finding),
        producer_plugin.clone(),
    );
    graph_hint.evidence_refs = vec![evidence.evidence_id.clone()];
    graph_hint.confidence = confidence;
    graph_hint.privacy_class = PrivacyClass::Internal;
    record.graph_hint_refs.push(graph_hint.hint_id.clone());
    record.validate()?;

    output.evidence.push(evidence);
    output.findings.push(finding);
    output.risk_hints.push(risk_hint);
    output.graph_hints.push(graph_hint);
    output.hypotheses.push(record);
    Ok(())
}

fn match_definition(
    definition: &sentinel_contracts::AttackHypothesisDefinition,
    facts: &[SecurityFact],
) -> Option<Vec<SecurityFact>> {
    if facts.iter().any(|fact| {
        definition
            .disqualifier_categories
            .iter()
            .any(|category| category == &fact.category)
    }) {
        return None;
    }
    let mut matched = Vec::new();
    for requirement in &definition.required_facts {
        let candidates = facts
            .iter()
            .filter(|fact| requirement_matches(requirement, fact))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return None;
        }
        matched.extend(candidates);
    }
    for requirement in &definition.optional_facts {
        matched.extend(
            facts
                .iter()
                .filter(|fact| requirement_matches(requirement, fact)),
        );
    }
    let mut seen = BTreeSet::new();
    matched.retain(|fact| seen.insert(fact.fact_id.to_string()));
    Some(matched.into_iter().cloned().collect())
}

fn requirement_matches(
    requirement: &sentinel_contracts::HypothesisFactRequirement,
    fact: &SecurityFact,
) -> bool {
    requirement.layer == fact.layer
        && (requirement.categories.is_empty()
            || requirement
                .categories
                .iter()
                .any(|category| fact.category.contains(category)))
}

pub fn attack_hypothesis_catalog(
) -> Result<Vec<sentinel_contracts::AttackHypothesisDefinition>, MultiLayerFusionError> {
    use sentinel_contracts::{AttackHypothesisDefinition, HypothesisFactRequirement};
    let families = [
        (
            "possible_dns_recon_to_edge_probe",
            &[SecurityLayer::Dns, SecurityLayer::CdnEdge][..],
        ),
        (
            "possible_origin_exposure_or_cdn_bypass_pattern",
            &[SecurityLayer::CdnEdge, SecurityLayer::Waf][..],
        ),
        (
            "possible_cache_bypass_or_origin_pressure",
            &[SecurityLayer::CdnEdge, SecurityLayer::Http][..],
        ),
        (
            "possible_bot_or_credential_probe_through_edge",
            &[SecurityLayer::CdnEdge, SecurityLayer::AuthIdentity][..],
        ),
        (
            "possible_provider_fronted_abuse_pattern",
            &[SecurityLayer::CdnEdge, SecurityLayer::SaasCloud][..],
        ),
        (
            "possible_api_abuse_chain",
            &[SecurityLayer::Api, SecurityLayer::Waf][..],
        ),
        (
            "possible_saas_cloud_abuse_chain",
            &[SecurityLayer::AuthIdentity, SecurityLayer::SaasCloud][..],
        ),
        (
            "possible_deception_confirmed_probe",
            &[SecurityLayer::Deception, SecurityLayer::Http][..],
        ),
        (
            "possible_remote_admin_probe_with_auth_failure",
            &[SecurityLayer::AuthIdentity, SecurityLayer::Http][..],
        ),
        (
            "possible_multi_layer_attack_chain",
            &[SecurityLayer::Dns, SecurityLayer::Http, SecurityLayer::Waf][..],
        ),
    ];
    let mut definitions = Vec::new();
    for (id, layers) in families {
        let definition = AttackHypothesisDefinition {
            hypothesis_id: id.to_string(),
            version: "fusion_v1".to_string(),
            category: id.to_string(),
            required_facts: layers
                .iter()
                .cloned()
                .map(|layer| HypothesisFactRequirement {
                    layer,
                    categories: Vec::new(),
                })
                .collect(),
            optional_facts: Vec::new(),
            disqualifier_categories: vec!["benign_baseline".to_string()],
            minimum_evidence: 1,
            confidence_cap: FusionConfidenceBucket::Medium,
            confidence_formula: "independent_layers_plus_evidence_capped_metadata_only".to_string(),
            degradation_rules: vec![
                "degrade_without_native_visibility".to_string(),
                "degrade_without_provider_control_plane".to_string(),
            ],
            missing_visibility_flags: vec![
                "no_process_attribution".to_string(),
                "no_packet_visibility".to_string(),
                "no_provider_control_plane".to_string(),
            ],
            attack_candidates: vec![FusionAttackCandidate {
                tactic_id: "TA0043".to_string(),
                technique_id: "T1595".to_string(),
                attack_version: "enterprise_verified_2026_06_12".to_string(),
                confidence: FusionConfidenceBucket::Low,
                required_visibility: "portable_metadata".to_string(),
            }],
            report_template: "possible_multi_layer_pattern_with_uncertainty".to_string(),
            safety_notes: vec![
                "does_not_confirm_compromise".to_string(),
                "does_not_claim_process_attribution".to_string(),
            ],
        };
        definition.validate()?;
        definitions.push(definition);
    }
    Ok(definitions)
}

fn attack_mappings(
    definition: &sentinel_contracts::AttackHypothesisDefinition,
    confidence: &QualityScore,
) -> Result<Vec<AttackMapping>, MultiLayerFusionError> {
    definition
        .attack_candidates
        .iter()
        .map(|candidate| {
            let mut provenance =
                MappingProvenance::new("multi_layer_fusion_allowlist").map_err(contract_error)?;
            provenance.source_version = Some(definition.version.clone());
            AttackMapping::mitre_attack_enterprise(
                candidate.tactic_id.clone(),
                "Reconnaissance",
                candidate.technique_id.clone(),
                "Active Scanning",
                quality(confidence.value().min(0.48))?,
                Some(provenance),
            )
            .map_err(contract_error)
        })
        .collect()
}

fn layer_from_finding(finding_type: &str) -> SecurityLayer {
    if finding_type.contains("dns") {
        SecurityLayer::Dns
    } else if finding_type.contains("waf") {
        SecurityLayer::Waf
    } else if finding_type.contains("api") {
        SecurityLayer::Api
    } else if finding_type.contains("auth") || finding_type.contains("identity") {
        SecurityLayer::AuthIdentity
    } else if finding_type.contains("saas") || finding_type.contains("cloud") {
        SecurityLayer::SaasCloud
    } else if finding_type.contains("deception") {
        SecurityLayer::Deception
    } else {
        SecurityLayer::Http
    }
}

fn http_category(metadata: &HttpMetadata) -> &'static str {
    match metadata.status_code {
        Some(401 | 403) => "http_auth_error",
        Some(404) => "http_not_found",
        Some(429) => "http_rate_limited",
        Some(status) if status >= 500 => "http_server_error",
        Some(status) if status >= 400 => "http_client_error",
        _ if metadata
            .upload_download_ratio
            .is_some_and(|ratio| ratio >= 2.0) =>
        {
            "http_upload_heavy"
        }
        _ => "http_observation",
    }
}

fn status_bucket(status: Option<u16>) -> String {
    match status {
        Some(200..=299) => "success",
        Some(300..=399) => "redirect",
        Some(401 | 403) => "auth_error",
        Some(404) => "not_found",
        Some(429) => "rate_limited",
        Some(400..=499) => "client_error",
        Some(500..=599) => "server_error",
        _ => "unknown",
    }
    .to_string()
}

fn provider_label(provider: &PortableProviderCategory) -> String {
    format!("{provider:?}").to_ascii_lowercase()
}

fn sdn_fact_category(event_category: &PortableSdnControlPlaneEventCategory) -> &'static str {
    match event_category {
        PortableSdnControlPlaneEventCategory::TopologyChange => "topology_change_observed",
        PortableSdnControlPlaneEventCategory::RouteChange => "route_change_observed",
        PortableSdnControlPlaneEventCategory::PolicyChange => "policy_change_observed",
        PortableSdnControlPlaneEventCategory::AclChange => "acl_change_observed",
        PortableSdnControlPlaneEventCategory::ControllerHealth => "controller_health_observed",
        PortableSdnControlPlaneEventCategory::FlowRuleChange => "flow_rule_change_observed",
        PortableSdnControlPlaneEventCategory::Unknown => "control_plane_change_observed",
    }
}

fn sdn_controller_label(controller: &sentinel_contracts::PortableSdnControllerCategory) -> String {
    format!("{controller:?}").to_ascii_lowercase()
}

fn layer_label(layer: &SecurityLayer) -> String {
    format!("{layer:?}").to_ascii_lowercase()
}

fn quality_for_hypothesis(
    layers: &[SecurityLayer],
    evidence_count: usize,
    definition: &sentinel_contracts::AttackHypothesisDefinition,
) -> QualityBreakdown {
    let mut quality = if layers.len() >= 2 && evidence_count >= 2 {
        QualityBreakdown::corroborated_metadata()
    } else {
        QualityBreakdown::metadata_only()
    };
    quality.correlation_quality_bucket = if layers.len() >= 3 {
        sentinel_contracts::CorrelationQualityBucket::Diverse
    } else if layers.len() >= 2 {
        sentinel_contracts::CorrelationQualityBucket::Corroborated
    } else {
        sentinel_contracts::CorrelationQualityBucket::SingleSignal
    };
    quality.evidence_strength_bucket = if evidence_count >= 2 {
        sentinel_contracts::EvidenceStrengthBucket::Moderate
    } else {
        sentinel_contracts::EvidenceStrengthBucket::WeakSingleSignal
    };
    quality.uncertainty_bucket = if layers.len() >= 2 && evidence_count >= 2 {
        sentinel_contracts::UncertaintyBucket::Medium
    } else {
        sentinel_contracts::UncertaintyBucket::High
    };
    quality.degraded_reasons = bounded_unique(
        definition
            .degradation_rules
            .iter()
            .cloned()
            .chain(["metadata_only_visibility".to_string()])
            .collect(),
    );
    quality.missing_visibility_flags = bounded_unique(
        definition
            .missing_visibility_flags
            .iter()
            .cloned()
            .chain([
                "no_process_attribution".to_string(),
                "no_packet_visibility".to_string(),
            ])
            .collect(),
    );
    quality
}

fn quality_for_fusion_summary(records: &[AttackHypothesisRecord]) -> QualityBreakdown {
    if records.iter().any(|record| {
        matches!(
            record.quality.correlation_quality_bucket,
            sentinel_contracts::CorrelationQualityBucket::Corroborated
                | sentinel_contracts::CorrelationQualityBucket::Diverse
        )
    }) {
        QualityBreakdown::corroborated_metadata()
    } else {
        QualityBreakdown::metadata_only()
    }
}

fn count_labels(values: impl Iterator<Item = String>) -> Vec<FusionCount> {
    let mut counts = BTreeMap::<String, u32>::new();
    for value in values {
        *counts.entry(value).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(label, count)| FusionCount { label, count })
        .collect()
}

fn finding_entity(finding: &Finding) -> EntityRef {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Finding);
    entity.entity_name = Some("fusion_finding".to_string());
    entity.namespace = Some("multi_layer_fusion".to_string());
    entity.confidence = finding.confidence().clone();
    entity
}

fn hypothesis_entity(record: &AttackHypothesisRecord) -> EntityRef {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Other);
    entity.entity_name = Some("fusion_hypothesis".to_string());
    entity.namespace = Some(record.category.clone());
    entity.confidence = quality(match record.confidence_bucket {
        FusionConfidenceBucket::Medium => 0.68,
        FusionConfidenceBucket::Low => 0.48,
        FusionConfidenceBucket::Unknown => 0.35,
    })
    .unwrap_or_default();
    entity
}

fn quality(value: f32) -> Result<QualityScore, MultiLayerFusionError> {
    QualityScore::new(value).map_err(|error| MultiLayerFusionError::Contract(error.to_string()))
}

fn contract_error(error: impl ToString) -> MultiLayerFusionError {
    MultiLayerFusionError::Contract(error.to_string())
}

fn bounded_unique<T: Clone + ToString>(values: Vec<T>) -> Vec<T> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.to_string()))
        .take(MAX_FUSION_REFS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{HttpMethod, PortableAuthResultCategory, RedactionStatus};

    fn provenance() -> PortableCaptureProvenance {
        PortableCaptureProvenance::new(
            PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata,
            sentinel_contracts::PortableCaptureRecordCounts::default(),
            RedactionStatus::Redacted,
        )
    }

    #[test]
    fn sampler_catalog_declares_portable_and_placeholder_boundaries() {
        let samplers = layered_sampler_catalog().expect("samplers");
        assert_eq!(samplers.len(), 12);
        assert!(samplers.iter().any(|sampler| {
            sampler.layer == SecurityLayer::SdnPlaceholder
                && !sampler.portable_default_available
                && sampler.state == SamplerState::NotAuthorized
        }));
        assert!(samplers.iter().all(|sampler| sampler.validate().is_ok()));
    }

    #[test]
    fn fusion_correlates_evidence_backed_layers_and_degrades_confidence() {
        let plugin = PluginId::new_v4();
        let provenance = provenance();
        let mut http = HttpMetadata::new(HttpMethod::Get);
        http.status_code = Some(403);
        http.waf_action = Some("blocked".to_string());
        let evidence = EvidenceItem::new("dns_signal", "bounded dns signal").expect("evidence");
        let finding = Finding::new(
            "portable.dns_security_v2.nxdomain_burst",
            plugin.clone(),
            vec![evidence.evidence_id.clone()],
            FindingExplanation::new("bounded dns finding").expect("explanation"),
        )
        .expect("finding");
        let output = MultiLayerSecurityFusionPlugin::new()
            .analyze(
                &plugin,
                MultiLayerFusionInput {
                    provenance: &provenance,
                    dns_observations: &[],
                    http_metadata: &[http],
                    auth_metadata: &[],
                    saas_cloud_metadata: &[],
                    deception_events: &[],
                    sdn_control_plane_metadata: &[],
                    findings: &[finding],
                },
            )
            .expect("fusion");
        assert!(!output.hypotheses.is_empty());
        assert!(output
            .hypotheses
            .iter()
            .all(|record| record.confidence_bucket != FusionConfidenceBucket::Unknown));
        assert!(output
            .hypotheses
            .iter()
            .all(|record| record.degraded_reason.as_deref() == Some("metadata_only_visibility")));
        assert!(output
            .graph_hints
            .iter()
            .all(|hint| !hint.evidence_refs.is_empty()));
    }

    #[test]
    fn benign_single_layer_produces_facts_without_hypotheses() {
        let plugin = PluginId::new_v4();
        let provenance = provenance();
        let auth = PortableAuthMetadata::new(
            "identity_provider",
            PortableAuthResultCategory::Success,
            Timestamp::now(),
        );
        let output = MultiLayerSecurityFusionPlugin::new()
            .analyze(
                &plugin,
                MultiLayerFusionInput {
                    provenance: &provenance,
                    dns_observations: &[],
                    http_metadata: &[],
                    auth_metadata: &[auth],
                    saas_cloud_metadata: &[],
                    deception_events: &[],
                    sdn_control_plane_metadata: &[],
                    findings: &[],
                },
            )
            .expect("fusion");
        assert_eq!(output.facts.len(), 1);
        assert!(output.hypotheses.is_empty());
        assert!(output.findings.is_empty());
    }

    #[test]
    fn fusion_serialization_excludes_sensitive_values_and_never_calls_llm() {
        let catalog = attack_hypothesis_catalog().expect("catalog");
        let serialized = serde_json::to_string(&catalog).expect("serialize");
        for marker in [
            "password",
            "api_key",
            "authorization",
            "cookie",
            "payload",
            "raw_packet",
            "confirmed_compromise",
        ] {
            assert!(!serialized.contains(marker));
        }
        assert!(!serialized.contains("llm_provider"));
    }
}
