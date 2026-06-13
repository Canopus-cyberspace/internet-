use sentinel_contracts::{
    AttackMapping, DnsAnswer, DnsObservation, EntityId, EntityRef, EntityType, EvidenceItem,
    Finding, FindingExplanation, FlowRecord, GraphHint, GraphHintType, HttpMetadata, HttpMethod,
    IntelligenceRecordId, IpAddress, MappingProvenance, PluginId, PortableAuthMetadata,
    PortableAuthResultCategory, PortableDeceptionEventMetadata, PortableDeceptionProtocolCategory,
    PortableDecoyInteractionCountBucket, PortableMfaResultCategory, PortableProviderCategory,
    PortableProviderConfidenceBucket, PortableProviderRiskCategory, PortableSaasCloudMetadata,
    PortableStatusBucket, PortableUploadDownloadRatioBucket, PrivacyClass, QualityScore, RiskHint,
    RiskReason, SecuritySeverity, SessionRecord, Timestamp, TlsObservation, TransportProtocol,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use uuid::Uuid;

pub const PORTABLE_NETWORK_WEB_SCHEMA_VERSION: sentinel_contracts::SchemaVersion =
    sentinel_contracts::SchemaVersion::new(1, 0, 0);
const PORTABLE_ATTACK_MAPPING_SOURCE: &str = "mitre_attack_enterprise_allowlist";
const PORTABLE_ATTACK_MAPPING_VERSION: &str = "enterprise-verified-2026-06-12";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableNetworkWebAnalysisError {
    EmptyInput(&'static str),
    NoSignals,
    Contract(String),
}

impl fmt::Display for PortableNetworkWebAnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput(kind) => write!(f, "{kind} input is empty"),
            Self::NoSignals => write!(f, "bounded metadata did not support a detection signal"),
            Self::Contract(error) => write!(f, "portable network/web contract error: {error}"),
        }
    }
}

impl std::error::Error for PortableNetworkWebAnalysisError {}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PortableNetworkWebOutput {
    pub findings: Vec<Finding>,
    pub evidence: Vec<EvidenceItem>,
    pub risk_hints: Vec<RiskHint>,
    pub graph_hints: Vec<GraphHint>,
}

impl PortableNetworkWebOutput {
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
            && self.evidence.is_empty()
            && self.risk_hints.is_empty()
            && self.graph_hints.is_empty()
    }

    pub fn extend(&mut self, other: Self) {
        self.findings.extend(other.findings);
        self.evidence.extend(other.evidence);
        self.risk_hints.extend(other.risk_hints);
        self.graph_hints.extend(other.graph_hints);
    }
}

#[derive(Clone, Debug, Default)]
pub struct PortableDnsSecurityV2Plugin;

impl PortableDnsSecurityV2Plugin {
    pub fn analyze(
        &self,
        plugin_id: &PluginId,
        observations: &[DnsObservation],
    ) -> Result<PortableNetworkWebOutput, PortableNetworkWebAnalysisError> {
        if observations.is_empty() {
            return Err(PortableNetworkWebAnalysisError::EmptyInput("dns"));
        }

        let mut output = PortableNetworkWebOutput::default();
        let mut by_domain = BTreeMap::<String, Vec<&DnsObservation>>::new();
        let mut nxdomain_by_client = BTreeMap::<String, Vec<&DnsObservation>>::new();

        for observation in observations {
            by_domain
                .entry(observation.query_name_protected.clone())
                .or_default()
                .push(observation);
            if observation
                .response_code
                .as_deref()
                .is_some_and(|code| code.eq_ignore_ascii_case("NXDOMAIN"))
            {
                nxdomain_by_client
                    .entry(observation.client_ip.to_string())
                    .or_default()
                    .push(observation);
            }

            let domain_entity =
                domain_entity(&observation.query_name_protected, &observation.timestamp)?;
            let client_entity = ip_entity(
                "portable.dns.client",
                observation.client_ip,
                &observation.timestamp,
                EntityType::Ip,
            )?;

            if observation.features.character_entropy.unwrap_or_default() >= 3.9
                && observation.features.query_length >= 20
            {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.dns_security_v2.high_entropy_labels",
                    "DNS metadata shows a long high-entropy query pattern.",
                    domain_entity.clone(),
                    Some(client_entity.clone()),
                    SecuritySeverity::Medium,
                    0.31,
                    0.73,
                    "portable_dns_high_entropy",
                    "portable_finding_implicates_domain",
                )?;
            }

            if observation.features.subdomain_depth >= 4 {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.dns_security_v2.excessive_subdomain_depth",
                    "DNS metadata shows excessive subdomain depth.",
                    domain_entity.clone(),
                    Some(client_entity.clone()),
                    SecuritySeverity::Medium,
                    0.24,
                    0.7,
                    "portable_dns_subdomain_depth",
                    "portable_finding_implicates_domain",
                )?;
            }

            if observation.features.answer_count <= 1
                && observation
                    .response_code
                    .as_deref()
                    .is_some_and(|code| code.eq_ignore_ascii_case("NOERROR"))
                && (observation.features.character_entropy.unwrap_or_default() >= 3.5
                    || observation.features.subdomain_depth >= 3)
            {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.dns_security_v2.sparse_answer_suspicious_domain",
                    "DNS metadata has sparse answers for a suspicious domain pattern.",
                    domain_entity,
                    Some(client_entity),
                    SecuritySeverity::Medium,
                    0.22,
                    0.68,
                    "portable_dns_sparse_answer",
                    "portable_finding_implicates_domain",
                )?;
            }
        }

        for entries in nxdomain_by_client.values() {
            if entries.len() < 3 {
                continue;
            }
            let client = entries[0];
            let client_entity = ip_entity(
                "portable.dns.client",
                client.client_ip,
                &client.timestamp,
                EntityType::Ip,
            )?;
            let domain_count = entries
                .iter()
                .map(|observation| observation.query_name_protected.as_str())
                .collect::<BTreeSet<_>>()
                .len();
            push_detection(
                &mut output,
                plugin_id,
                "portable.dns_security_v2.nxdomain_burst",
                &format!(
                    "DNS metadata shows an NXDOMAIN burst across {domain_count} bounded domains."
                ),
                client_entity.clone(),
                Some(domain_entity(
                    &entries[0].query_name_protected,
                    &entries[0].timestamp,
                )?),
                SecuritySeverity::Medium,
                0.29,
                0.75,
                "portable_dns_nxdomain_burst",
                "portable_finding_implicates_client_ip",
            )?;
        }

        for (domain, entries) in by_domain {
            let answer_ips = entries
                .iter()
                .flat_map(|observation| observation.answers.iter())
                .filter_map(|answer| match answer {
                    DnsAnswer::Ip { address, .. } => Some(address.to_string()),
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            if answer_ips.len() < 3 {
                continue;
            }
            let domain_entity = domain_entity(&domain, &entries[0].timestamp)?;
            let related_ip = ip_entity_from_text(
                "portable.dns.answer_ip",
                answer_ips
                    .iter()
                    .next()
                    .map(|value| value.as_str())
                    .unwrap_or("198.51.100.1"),
                &entries[0].timestamp,
            )?;
            push_detection(
                &mut output,
                plugin_id,
                "portable.dns_security_v2.fast_flux_lite",
                &format!(
                    "DNS metadata shows repeated destination changes across {} bounded answers.",
                    answer_ips.len()
                ),
                domain_entity,
                Some(related_ip),
                SecuritySeverity::High,
                0.34,
                0.79,
                "portable_dns_fast_flux_lite",
                "portable_finding_implicates_domain",
            )?;
        }

        if output.is_empty() {
            Err(PortableNetworkWebAnalysisError::NoSignals)
        } else {
            Ok(output)
        }
    }
}

#[derive(Clone, Debug)]
pub struct PortableHttpAnalysisInput<'a> {
    pub flow_records: &'a [FlowRecord],
    pub session_records: &'a [SessionRecord],
    pub http_metadata: &'a [HttpMetadata],
}

#[derive(Clone, Debug, Default)]
pub struct PortableHttpAnalysisV1Plugin;

impl PortableHttpAnalysisV1Plugin {
    pub fn analyze(
        &self,
        plugin_id: &PluginId,
        input: PortableHttpAnalysisInput<'_>,
    ) -> Result<PortableNetworkWebOutput, PortableNetworkWebAnalysisError> {
        if input.http_metadata.is_empty() {
            return Err(PortableNetworkWebAnalysisError::EmptyInput("http"));
        }

        let mut output = PortableNetworkWebOutput::default();
        let http_by_host = group_http_by_host(input.http_metadata);
        let http_by_endpoint = group_http_by_endpoint(input.http_metadata);

        for entries in http_by_host.values() {
            if entries.len() >= 4 {
                let mutating = entries
                    .iter()
                    .filter(|http| is_mutating_method(&http.method))
                    .count();
                if mutating >= 4 && (mutating as f32 / entries.len() as f32) >= 0.75 {
                    let entity = http_host_entity(entries[0])?;
                    push_detection(
                        &mut output,
                        plugin_id,
                        "portable.http_analysis_v1.method_distribution_shift",
                        "HTTP metadata shows a mutating method distribution shift.",
                        entity,
                        http_related_source_entity(entries[0], input.flow_records),
                        SecuritySeverity::Medium,
                        0.23,
                        0.68,
                        "portable_http_method_shift",
                        "portable_finding_implicates_http_host",
                    )?;
                }
            }

            for family in ["4xx", "5xx"] {
                let count = entries
                    .iter()
                    .filter(|http| http.status_family.as_deref() == Some(family))
                    .count();
                if count >= 3 {
                    let entity = http_host_entity(entries[0])?;
                    push_detection(
                        &mut output,
                        plugin_id,
                        "portable.http_analysis_v1.status_code_burst",
                        &format!("HTTP metadata shows a {family} burst at a bounded host."),
                        entity,
                        http_related_source_entity(entries[0], input.flow_records),
                        SecuritySeverity::Medium,
                        0.25,
                        0.7,
                        "portable_http_status_burst",
                        "portable_finding_implicates_http_host",
                    )?;
                }
            }

            if entries.len() >= 6 {
                let entity = http_host_entity(entries[0])?;
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.http_analysis_v1.request_volume_anomaly",
                    "HTTP metadata shows a bounded request volume anomaly.",
                    entity,
                    http_related_source_entity(entries[0], input.flow_records),
                    SecuritySeverity::Medium,
                    0.2,
                    0.66,
                    "portable_http_request_volume",
                    "portable_finding_implicates_http_host",
                )?;
            }
        }

        for entries in http_by_endpoint.values() {
            let http = entries[0];
            if http.upload_download_ratio.unwrap_or_default() >= 8.0
                && http.request_size_bytes.unwrap_or_default() >= 4_096
            {
                let entity = http_endpoint_entity(http)?;
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.http_analysis_v1.upload_download_imbalance",
                    "HTTP metadata shows a large upload to download imbalance.",
                    entity,
                    http_related_source_entity(http, input.flow_records),
                    SecuritySeverity::Medium,
                    0.24,
                    0.72,
                    "portable_http_upload_download_imbalance",
                    "portable_finding_implicates_api_endpoint",
                )?;
            }

            if input.http_metadata.len() >= 5
                && entries.len() == 1
                && http
                    .status_code
                    .is_some_and(|status_code| status_code >= 400)
            {
                let entity = http_endpoint_entity(http)?;
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.http_analysis_v1.rare_route_shape",
                    "HTTP metadata shows a rare redacted route shape with elevated error context.",
                    entity,
                    http_related_source_entity(http, input.flow_records),
                    SecuritySeverity::Low,
                    0.16,
                    0.64,
                    "portable_http_rare_route_shape",
                    "portable_finding_implicates_api_endpoint",
                )?;
            }
        }

        let _ = input.session_records;

        if output.is_empty() {
            Err(PortableNetworkWebAnalysisError::NoSignals)
        } else {
            Ok(output)
        }
    }
}

#[derive(Clone, Debug)]
pub struct PortableApiSecurityLiteInput<'a> {
    pub flow_records: &'a [FlowRecord],
    pub http_metadata: &'a [HttpMetadata],
}

#[derive(Clone, Debug, Default)]
pub struct PortableApiSecurityLitePlugin;

impl PortableApiSecurityLitePlugin {
    pub fn analyze(
        &self,
        plugin_id: &PluginId,
        input: PortableApiSecurityLiteInput<'_>,
    ) -> Result<PortableNetworkWebOutput, PortableNetworkWebAnalysisError> {
        if input.http_metadata.is_empty() {
            return Err(PortableNetworkWebAnalysisError::EmptyInput("api"));
        }

        let mut output = PortableNetworkWebOutput::default();
        let http_by_host = group_http_by_host(input.http_metadata);
        let http_by_endpoint = group_http_by_endpoint(input.http_metadata);

        for entries in http_by_host.values() {
            let unique_endpoints = entries
                .iter()
                .filter_map(|http| http.endpoint_fingerprint.as_ref())
                .collect::<BTreeSet<_>>();
            if unique_endpoints.len() >= 5 {
                let entity = http_host_entity(entries[0])?;
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.api_security_lite.endpoint_enumeration",
                    "HTTP metadata shows bounded endpoint enumeration behavior.",
                    entity,
                    http_related_source_entity(entries[0], input.flow_records),
                    SecuritySeverity::Medium,
                    0.27,
                    0.72,
                    "portable_api_endpoint_enumeration",
                    "portable_finding_implicates_http_host",
                )?;
            }
        }

        for entries in http_by_endpoint.values() {
            let endpoint = http_endpoint_entity(entries[0])?;
            let failure_burst = entries
                .iter()
                .filter(|http| matches!(http.status_code, Some(401 | 403 | 404)))
                .count();
            if failure_burst >= 3 {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.api_security_lite.auth_error_burst",
                    "HTTP metadata shows repeated 401, 403, or 404 responses at a bounded endpoint.",
                    endpoint.clone(),
                    http_related_source_entity(entries[0], input.flow_records),
                    SecuritySeverity::Medium,
                    0.26,
                    0.71,
                    "portable_api_auth_error_burst",
                    "portable_finding_implicates_api_endpoint",
                )?;
            }

            let method_count = entries
                .iter()
                .map(|http| http_method_token(&http.method))
                .collect::<BTreeSet<_>>()
                .len();
            if method_count >= 3 {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.api_security_lite.method_probing",
                    "HTTP metadata shows multi-method probing against a bounded endpoint.",
                    endpoint.clone(),
                    http_related_source_entity(entries[0], input.flow_records),
                    SecuritySeverity::Medium,
                    0.25,
                    0.69,
                    "portable_api_method_probing",
                    "portable_finding_implicates_api_endpoint",
                )?;
            }

            let suspicious_ua_count = entries
                .iter()
                .filter(|http| is_suspicious_user_agent(http.user_agent_family.as_deref()))
                .filter(|http| {
                    matches!(http.status_code, Some(401 | 403 | 404))
                        || is_mutating_method(&http.method)
                })
                .count();
            if suspicious_ua_count >= 2 {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.api_security_lite.suspicious_user_agent_class",
                    "HTTP metadata shows a suspicious user-agent class in bounded API activity.",
                    endpoint.clone(),
                    http_related_source_entity(entries[0], input.flow_records),
                    SecuritySeverity::Low,
                    0.18,
                    0.65,
                    "portable_api_suspicious_user_agent",
                    "portable_finding_implicates_api_endpoint",
                )?;
            }

            if entries.len() >= 3 {
                let error_count = entries
                    .iter()
                    .filter(|http| http.status_code.is_some_and(|status| status >= 400))
                    .count();
                if (error_count as f32 / entries.len() as f32) >= 0.6 {
                    push_detection(
                        &mut output,
                        plugin_id,
                        "portable.api_security_lite.high_error_rate_endpoint_cluster",
                        "HTTP metadata shows a high error-rate endpoint cluster.",
                        endpoint,
                        http_related_source_entity(entries[0], input.flow_records),
                        SecuritySeverity::Medium,
                        0.24,
                        0.7,
                        "portable_api_high_error_cluster",
                        "portable_finding_implicates_api_endpoint",
                    )?;
                }
            }
        }

        if output.is_empty() {
            Err(PortableNetworkWebAnalysisError::NoSignals)
        } else {
            Ok(output)
        }
    }
}

#[derive(Clone, Debug)]
pub struct PortableWafSecurityLiteInput<'a> {
    pub flow_records: &'a [FlowRecord],
    pub http_metadata: &'a [HttpMetadata],
}

#[derive(Clone, Debug, Default)]
pub struct PortableWafSecurityLitePlugin;

impl PortableWafSecurityLitePlugin {
    pub fn analyze(
        &self,
        plugin_id: &PluginId,
        input: PortableWafSecurityLiteInput<'_>,
    ) -> Result<PortableNetworkWebOutput, PortableNetworkWebAnalysisError> {
        if input.http_metadata.is_empty() {
            return Err(PortableNetworkWebAnalysisError::EmptyInput("waf"));
        }

        let blocked = input
            .http_metadata
            .iter()
            .filter(|http| is_blocked_waf_event(http))
            .collect::<Vec<_>>();
        if blocked.is_empty() {
            return Err(PortableNetworkWebAnalysisError::NoSignals);
        }

        let mut output = PortableNetworkWebOutput::default();
        let blocked_by_attack_class = blocked
            .iter()
            .filter_map(|http| {
                http.waf_attack_class
                    .as_ref()
                    .map(|class| (class.clone(), *http))
            })
            .fold(
                BTreeMap::<String, Vec<&HttpMetadata>>::new(),
                |mut map, (class, http)| {
                    map.entry(class).or_default().push(http);
                    map
                },
            );
        let blocked_by_rule_id = blocked
            .iter()
            .filter_map(|http| http.waf_rule_id.as_ref().map(|rule| (rule.clone(), *http)))
            .fold(
                BTreeMap::<String, Vec<&HttpMetadata>>::new(),
                |mut map, (rule, http)| {
                    map.entry(rule).or_default().push(http);
                    map
                },
            );
        let blocked_by_endpoint = blocked
            .iter()
            .filter_map(|http| {
                http.endpoint_fingerprint
                    .as_ref()
                    .map(|key| (key.clone(), *http))
            })
            .fold(
                BTreeMap::<String, Vec<&HttpMetadata>>::new(),
                |mut map, (key, http)| {
                    map.entry(key).or_default().push(http);
                    map
                },
            );

        for entries in blocked_by_attack_class.values() {
            if entries.len() < 2 {
                continue;
            }
            let entity = http_endpoint_or_host_entity(entries[0])?;
            push_detection(
                &mut output,
                plugin_id,
                "portable.waf_security_lite.repeated_blocked_attack_class",
                "WAF metadata shows repeated blocked attack-class activity.",
                entity,
                http_related_source_entity(entries[0], input.flow_records),
                SecuritySeverity::High,
                0.33,
                0.79,
                "portable_waf_attack_class_burst",
                "portable_finding_implicates_api_endpoint",
            )?;
        }

        for entries in blocked_by_rule_id.values() {
            if entries.len() < 2 {
                continue;
            }
            let entity = http_endpoint_or_host_entity(entries[0])?;
            push_detection(
                &mut output,
                plugin_id,
                "portable.waf_security_lite.rule_id_burst",
                "WAF metadata shows a repeated rule-id burst.",
                entity,
                http_related_source_entity(entries[0], input.flow_records),
                SecuritySeverity::Medium,
                0.28,
                0.74,
                "portable_waf_rule_id_burst",
                "portable_finding_implicates_api_endpoint",
            )?;
        }

        for entries in blocked_by_endpoint.values() {
            if entries.len() >= 3 {
                let entity = http_endpoint_entity(entries[0])?;
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.waf_security_lite.attack_concentration",
                    "WAF metadata shows concentrated blocked activity at a bounded endpoint.",
                    entity.clone(),
                    http_related_source_entity(entries[0], input.flow_records),
                    SecuritySeverity::High,
                    0.32,
                    0.78,
                    "portable_waf_attack_concentration",
                    "portable_finding_implicates_api_endpoint",
                )?;
            }
        }

        let flow_index = flow_index(input.flow_records);
        let mut blocked_by_source_ip = BTreeMap::<String, Vec<&HttpMetadata>>::new();
        for http in blocked {
            let Some(flow_ref) = &http.flow_ref else {
                continue;
            };
            let Some(flow) = flow_index.get(&flow_ref.to_string()) else {
                continue;
            };
            blocked_by_source_ip
                .entry(flow.src_ip.to_string())
                .or_default()
                .push(http);
        }
        for entries in blocked_by_source_ip.values() {
            if entries.len() < 3 {
                continue;
            }
            let source_entity = http_related_source_entity(entries[0], input.flow_records)
                .ok_or_else(|| {
                    PortableNetworkWebAnalysisError::Contract("missing source entity".to_string())
                })?;
            let endpoint_entity = http_endpoint_or_host_entity(entries[0])?;
            push_detection(
                &mut output,
                plugin_id,
                "portable.waf_security_lite.attack_concentration",
                "WAF metadata shows concentrated blocked activity from a bounded source IP.",
                source_entity,
                Some(endpoint_entity),
                SecuritySeverity::High,
                0.35,
                0.8,
                "portable_waf_source_concentration",
                "portable_finding_implicates_client_ip",
            )?;
        }

        for entries in group_http_by_endpoint(input.http_metadata).values() {
            let mut saw_blocked = false;
            let mut saw_success_after = false;
            let mut sorted = entries.clone();
            sorted.sort_by_key(|http| http.timestamp.to_string());
            for http in sorted {
                if is_blocked_waf_event(http) {
                    saw_blocked = true;
                    continue;
                }
                if saw_blocked
                    && http
                        .status_code
                        .is_some_and(|status| (200..400).contains(&status))
                {
                    saw_success_after = true;
                    break;
                }
            }
            if saw_success_after {
                let entity = http_endpoint_entity(entries[0])?;
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.waf_security_lite.bypass_suspected_status_transition",
                    "WAF metadata shows a blocked-then-success status transition at a bounded endpoint.",
                    entity,
                    http_related_source_entity(entries[0], input.flow_records),
                    SecuritySeverity::High,
                    0.37,
                    0.81,
                    "portable_waf_bypass_suspected",
                    "portable_finding_implicates_api_endpoint",
                )?;
            }
        }

        if output.is_empty() {
            Err(PortableNetworkWebAnalysisError::NoSignals)
        } else {
            Ok(output)
        }
    }
}

#[derive(Clone, Debug)]
pub struct PortableQuicHttp3SecurityLiteInput<'a> {
    pub flow_records: &'a [FlowRecord],
    pub tls_observations: &'a [TlsObservation],
    pub http_metadata: &'a [HttpMetadata],
}

#[derive(Clone, Debug, Default)]
pub struct PortableQuicHttp3SecurityLitePlugin;

impl PortableQuicHttp3SecurityLitePlugin {
    pub fn analyze(
        &self,
        plugin_id: &PluginId,
        input: PortableQuicHttp3SecurityLiteInput<'_>,
    ) -> Result<PortableNetworkWebOutput, PortableNetworkWebAnalysisError> {
        if input.flow_records.is_empty() {
            return Err(PortableNetworkWebAnalysisError::EmptyInput("quic_http3"));
        }

        let flow_by_id = flow_index(input.flow_records);
        let http3_flow_refs = input
            .tls_observations
            .iter()
            .filter(|observation| observation.alpn.iter().any(|alpn| is_http3_alpn(alpn)))
            .filter_map(|observation| observation.flow_ref.as_ref().map(ToString::to_string))
            .collect::<BTreeSet<_>>();

        let mut http3_by_host = BTreeMap::<String, Vec<&HttpMetadata>>::new();
        let mut fallback_by_host = BTreeMap::<String, Vec<&HttpMetadata>>::new();

        for http in input.http_metadata {
            let Some(flow_ref) = http.flow_ref.as_ref().map(ToString::to_string) else {
                continue;
            };
            let Some(flow) = flow_by_id.get(&flow_ref).copied() else {
                continue;
            };
            let host = http
                .host_protected
                .clone()
                .unwrap_or_else(|| "host#unknown".to_string());
            if http3_flow_refs.contains(&flow_ref)
                || (flow.protocol == TransportProtocol::Udp && flow.dst_port == 443)
            {
                http3_by_host.entry(host).or_default().push(http);
            } else if matches!(flow.dst_port, 80 | 443) {
                fallback_by_host.entry(host).or_default().push(http);
            }
        }

        let mut category_counts = BTreeMap::<&'static str, usize>::new();
        for entries in http3_by_host.values() {
            let category = quic_destination_category(entries[0]);
            *category_counts.entry(category).or_default() += 1;
        }

        let mut output = PortableNetworkWebOutput::default();

        for (host, entries) in &http3_by_host {
            let category = quic_destination_category(entries[0]);
            let related_source = http_related_source_entity(entries[0], input.flow_records);
            if category_counts.get(category).copied().unwrap_or_default() == 1 && entries.len() <= 2
            {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.quic_http3_security_lite.rare_destination_category",
                    &format!(
                        "QUIC/HTTP3 metadata reached a rare {category} destination category within this bounded import."
                    ),
                    domain_entity(host, &entries[0].timestamp)?,
                    related_source.clone(),
                    SecuritySeverity::Medium,
                    0.18,
                    0.58,
                    "portable_quic_http3_rare_destination",
                    "portable_finding_implicates_http_host",
                )?;
            }

            let failure_count = entries.iter().filter(|http| is_http_failure(http)).count();
            if failure_count >= 3 {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.quic_http3_security_lite.repeated_failed_attempts",
                    &format!(
                        "QUIC/HTTP3 metadata shows {} repeated failed attempts for a bounded host.",
                        failure_count
                    ),
                    domain_entity(host, &entries[0].timestamp)?,
                    related_source.clone(),
                    SecuritySeverity::High,
                    0.28,
                    0.73,
                    "portable_quic_http3_failed_attempt_burst",
                    "portable_finding_implicates_http_host",
                )?;
            }

            if fallback_by_host.contains_key(host) {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.quic_http3_security_lite.protocol_downgrade_fallback_pattern",
                    "Bounded host metadata shows both HTTP/3 and non-HTTP/3 web sessions within one import.",
                    domain_entity(host, &entries[0].timestamp)?,
                    related_source.clone(),
                    SecuritySeverity::Medium,
                    0.22,
                    0.68,
                    "portable_quic_http3_fallback_pattern",
                    "portable_finding_implicates_http_host",
                )?;
            }

            let api_error_entries = entries
                .iter()
                .filter(|http| {
                    is_http_failure(http)
                        && (http.api_hint.is_some() || http.endpoint_fingerprint.is_some())
                })
                .copied()
                .collect::<Vec<_>>();
            if api_error_entries.len() >= 3 {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.quic_http3_security_lite.suspicious_api_error_burst",
                    &format!(
                        "HTTP/3 API metadata shows a burst of {} bounded error responses.",
                        api_error_entries.len()
                    ),
                    http_endpoint_or_host_entity(api_error_entries[0])?,
                    related_source,
                    SecuritySeverity::High,
                    0.3,
                    0.76,
                    "portable_quic_http3_api_error_burst",
                    "portable_finding_implicates_api_endpoint",
                )?;
            }
        }

        if output.is_empty() {
            Err(PortableNetworkWebAnalysisError::NoSignals)
        } else {
            Ok(output)
        }
    }
}

#[derive(Clone, Debug)]
pub struct PortableRemoteAdminObservationLiteInput<'a> {
    pub flow_records: &'a [FlowRecord],
    pub session_records: &'a [SessionRecord],
}

#[derive(Clone, Debug, Default)]
pub struct PortableRemoteAdminObservationLitePlugin;

impl PortableRemoteAdminObservationLitePlugin {
    pub fn analyze(
        &self,
        plugin_id: &PluginId,
        input: PortableRemoteAdminObservationLiteInput<'_>,
    ) -> Result<PortableNetworkWebOutput, PortableNetworkWebAnalysisError> {
        if input.flow_records.is_empty() && input.session_records.is_empty() {
            return Err(PortableNetworkWebAnalysisError::EmptyInput(
                "remote_admin_protocol",
            ));
        }

        let session_view = if input.session_records.is_empty() {
            input
                .flow_records
                .iter()
                .filter_map(admin_observation_from_flow)
                .collect::<Vec<_>>()
        } else {
            input
                .session_records
                .iter()
                .filter_map(admin_observation_from_session)
                .collect::<Vec<_>>()
        };

        if session_view.is_empty() {
            return Err(PortableNetworkWebAnalysisError::NoSignals);
        }

        let mut grouped =
            BTreeMap::<(String, &'static str), Vec<&RemoteAdminObservation<'_>>>::new();
        for observation in &session_view {
            grouped
                .entry((observation.source_ip.to_string(), observation.service.key))
                .or_default()
                .push(observation);
        }

        let mut output = PortableNetworkWebOutput::default();

        for entries in grouped.values() {
            let first = entries[0];
            let distinct_destinations = entries
                .iter()
                .map(|entry| entry.target_ip.to_string())
                .collect::<BTreeSet<_>>();
            let source_entity = ip_entity(
                "portable.remote_admin.source_ip",
                first.source_ip,
                first.timestamp,
                EntityType::Ip,
            )?;
            let target_entity = ip_entity(
                "portable.remote_admin.target_ip",
                first.target_ip,
                first.timestamp,
                EntityType::Ip,
            )?;

            if distinct_destinations.len() >= 3 {
                push_detection(
                    &mut output,
                    plugin_id,
                    &format!(
                        "portable.remote_admin_protocol_lite.{}_spread_pattern",
                        first.service.key
                    ),
                    &format!(
                        "Bounded {} metadata touched {} internal destinations within this import.",
                        first.service.label,
                        distinct_destinations.len()
                    ),
                    source_entity.clone(),
                    Some(target_entity.clone()),
                    SecuritySeverity::High,
                    0.31,
                    0.74,
                    "portable_remote_admin_spread_pattern",
                    "portable_finding_implicates_client_ip",
                )?;
                continue;
            }

            if entries.len() == 1 {
                push_detection(
                    &mut output,
                    plugin_id,
                    &format!(
                        "portable.remote_admin_protocol_lite.{}_first_seen_use",
                        first.service.key
                    ),
                    &format!(
                        "Bounded {} metadata appeared for the first time within this import.",
                        first.service.label
                    ),
                    target_entity,
                    Some(source_entity),
                    SecuritySeverity::Medium,
                    0.17,
                    0.53,
                    "portable_remote_admin_first_seen_use",
                    "portable_finding_implicates_remote_admin_target",
                )?;
            }
        }

        if output.is_empty() {
            Err(PortableNetworkWebAnalysisError::NoSignals)
        } else {
            Ok(output)
        }
    }
}

#[derive(Clone, Debug)]
pub struct PortableAuthIdentityAnalysisLiteInput<'a> {
    pub flow_records: &'a [FlowRecord],
    pub session_records: &'a [SessionRecord],
    pub auth_metadata: &'a [PortableAuthMetadata],
}

#[derive(Clone, Debug, Default)]
pub struct PortableAuthIdentityAnalysisLitePlugin;

impl PortableAuthIdentityAnalysisLitePlugin {
    pub fn analyze(
        &self,
        plugin_id: &PluginId,
        input: PortableAuthIdentityAnalysisLiteInput<'_>,
    ) -> Result<PortableNetworkWebOutput, PortableNetworkWebAnalysisError> {
        if input.auth_metadata.is_empty() {
            return Err(PortableNetworkWebAnalysisError::EmptyInput("auth"));
        }

        let mut output = PortableNetworkWebOutput::default();
        let auth_by_provider = group_auth_by_provider(input.auth_metadata);
        let auth_by_identity_provider = group_auth_by_identity_provider(input.auth_metadata);
        let auth_by_service = group_auth_by_service(input.auth_metadata);
        let correlated_remote_admin =
            remote_admin_service_keys(input.flow_records, input.session_records);

        for entries in auth_by_identity_provider.values() {
            let primary = entries[0];
            let failure_count = entries
                .iter()
                .filter(|record| is_auth_failure(record))
                .count();
            if failure_count >= 3 {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.auth_identity_analysis_lite.auth_failure_burst",
                    "Authentication metadata shows a repeated failure burst within a bounded identity and provider cohort.",
                    auth_identity_or_session_entity(primary)?,
                    Some(auth_provider_entity(primary)?),
                    SecuritySeverity::Medium,
                    0.27,
                    0.72,
                    "portable_auth_failure_burst",
                    "portable_finding_implicates_identity_session",
                )?;
            }

            let mfa_events = entries
                .iter()
                .filter(|record| {
                    matches!(
                        record.mfa_result,
                        Some(
                            PortableMfaResultCategory::Failed
                                | PortableMfaResultCategory::Denied
                                | PortableMfaResultCategory::Prompted
                                | PortableMfaResultCategory::Timeout
                        )
                    )
                })
                .count();
            let distinct_mfa_buckets = entries
                .iter()
                .filter(|record| {
                    matches!(
                        record.mfa_result,
                        Some(
                            PortableMfaResultCategory::Failed
                                | PortableMfaResultCategory::Denied
                                | PortableMfaResultCategory::Prompted
                                | PortableMfaResultCategory::Timeout
                        )
                    )
                })
                .map(|record| record.time_bucket_start.as_datetime().to_rfc3339())
                .collect::<BTreeSet<_>>()
                .len();
            if mfa_events >= 3
                && distinct_mfa_buckets >= 2
                && entries.iter().any(|record| {
                    matches!(
                        record.mfa_result,
                        Some(
                            PortableMfaResultCategory::Failed
                                | PortableMfaResultCategory::Denied
                                | PortableMfaResultCategory::Timeout
                        )
                    )
                })
            {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.auth_identity_analysis_lite.mfa_fatigue_like_pattern",
                    "Authentication metadata shows repeated MFA failures or prompts for a bounded identity/provider cohort.",
                    auth_identity_or_session_entity(primary)?,
                    Some(auth_provider_entity(primary)?),
                    SecuritySeverity::Medium,
                    0.29,
                    0.7,
                    "portable_auth_mfa_fatigue",
                    "portable_finding_implicates_auth_provider",
                )?;
            }

            if is_first_seen_identity_provider_pair(primary, entries, input.auth_metadata) {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.auth_identity_analysis_lite.first_seen_identity_provider_combination",
                    "Authentication metadata shows a first-seen identity and provider combination within the current bounded import.",
                    auth_identity_or_session_entity(primary)?,
                    Some(auth_provider_entity(primary)?),
                    SecuritySeverity::Low,
                    0.16,
                    0.63,
                    "portable_auth_first_seen_identity_provider",
                    "portable_finding_implicates_auth_provider",
                )?;
            }
        }

        for entries in auth_by_provider.values() {
            let provider = entries[0];
            if is_suspicious_provider_category(&provider.provider_category) && entries.len() >= 3 {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.auth_identity_analysis_lite.suspicious_provider_category",
                    "Authentication metadata shows repeated logins through a suspicious provider category.",
                    auth_provider_entity(provider)?,
                    Some(auth_identity_or_session_entity(provider)?),
                    SecuritySeverity::Medium,
                    0.24,
                    0.67,
                    "portable_auth_suspicious_provider",
                    "portable_finding_implicates_auth_provider",
                )?;
            }
        }

        for record in input.auth_metadata.iter().filter(|record| {
            record.role_privilege_class.as_deref() == Some("privileged")
                && matches!(
                    record.auth_result,
                    PortableAuthResultCategory::Success | PortableAuthResultCategory::Challenge
                )
        }) {
            push_detection(
                &mut output,
                plugin_id,
                "portable.auth_identity_analysis_lite.privileged_role_access",
                "Authentication metadata shows privileged-role access through a bounded redacted role class.",
                auth_identity_or_session_entity(record)?,
                auth_service_related_entity(record),
                SecuritySeverity::Medium,
                0.22,
                0.66,
                "portable_auth_privileged_role_access",
                "portable_finding_implicates_identity_session",
            )?;
        }

        for (service, entries) in auth_by_service {
            if !is_remote_admin_auth_service(&service) {
                continue;
            }
            let failure_count = entries
                .iter()
                .filter(|record| is_auth_failure(record))
                .count();
            if failure_count < 2 {
                continue;
            }
            let primary = entries[0];
            let correlation_supported = correlated_remote_admin.contains(service.as_str());
            push_detection(
                &mut output,
                plugin_id,
                "portable.auth_identity_analysis_lite.remote_admin_auth_failure_correlation",
                if correlation_supported {
                    "Authentication metadata shows repeated remote-admin authentication failures with correlated bounded SMB/RDP/SSH activity."
                } else {
                    "Authentication metadata shows repeated remote-admin authentication failures in a bounded SMB/RDP/SSH service category."
                },
                auth_service_entity(&service, &primary.time_bucket_start)?,
                Some(auth_identity_or_session_entity(primary)?),
                SecuritySeverity::Medium,
                0.25,
                if correlation_supported { 0.72 } else { 0.64 },
                "portable_auth_remote_admin_failure",
                "portable_finding_implicates_auth_service",
            )?;
        }

        if output.is_empty() {
            Err(PortableNetworkWebAnalysisError::NoSignals)
        } else {
            Ok(output)
        }
    }
}

#[derive(Clone, Debug)]
pub struct PortableSaasCloudAbuseLiteInput<'a> {
    pub saas_cloud_metadata: &'a [PortableSaasCloudMetadata],
    pub auth_metadata: &'a [PortableAuthMetadata],
    pub http_metadata: &'a [HttpMetadata],
    pub related_findings: &'a [Finding],
}

#[derive(Clone, Debug, Default)]
pub struct PortableSaasCloudAbuseLitePlugin;

impl PortableSaasCloudAbuseLitePlugin {
    pub fn analyze(
        &self,
        plugin_id: &PluginId,
        input: PortableSaasCloudAbuseLiteInput<'_>,
    ) -> Result<PortableNetworkWebOutput, PortableNetworkWebAnalysisError> {
        if input.saas_cloud_metadata.is_empty() {
            return Err(PortableNetworkWebAnalysisError::EmptyInput("saas_cloud"));
        }

        let mut output = PortableNetworkWebOutput::default();
        let by_provider = group_saas_by_provider(input.saas_cloud_metadata);
        let by_endpoint = group_saas_by_endpoint(input.saas_cloud_metadata);
        let has_api_or_waf_finding = input.related_findings.iter().any(|finding| {
            finding
                .finding_type()
                .starts_with("portable.api_security_lite.")
                || finding
                    .finding_type()
                    .starts_with("portable.waf_security_lite.")
        });

        for entries in by_provider.values() {
            let primary = entries[0];
            let upload_heavy = entries
                .iter()
                .filter(|item| is_saas_upload_heavy(item))
                .count();
            if primary.provider_category == PortableProviderCategory::ObjectStorage
                && upload_heavy >= 2
            {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.saas_cloud_abuse_lite.suspicious_object_storage_upload",
                    "SaaS/cloud metadata shows repeated upload-heavy activity toward an object-storage provider category.",
                    saas_provider_entity(primary)?,
                    saas_endpoint_related_entity(primary)?,
                    SecuritySeverity::Medium,
                    0.3,
                    saas_confidence(primary, 0.76),
                    "portable_saas_object_storage_upload",
                    "portable_finding_implicates_object_storage_category",
                )?;
            }

            if is_risky_provider(primary) && entries.len() >= 2 {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.saas_cloud_abuse_lite.repeated_risky_provider_access",
                    "SaaS/cloud metadata shows repeated access to a risky provider category.",
                    saas_provider_entity(primary)?,
                    saas_identity_or_session_entity(primary),
                    SecuritySeverity::Medium,
                    0.24,
                    saas_confidence(primary, 0.68),
                    "portable_saas_risky_provider_access",
                    "portable_finding_implicates_provider_category",
                )?;
            }

            let low_confidence_known_provider = primary.provider_category
                != PortableProviderCategory::Unknown
                && matches!(
                    primary.provider_confidence,
                    PortableProviderConfidenceBucket::Low
                        | PortableProviderConfidenceBucket::Unknown
                );
            if low_confidence_known_provider && entries.len() >= 2 {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.saas_cloud_abuse_lite.rare_provider_usage",
                    "SaaS/cloud metadata shows rare or low-confidence provider-category usage within the current import.",
                    saas_provider_entity(primary)?,
                    saas_endpoint_related_entity(primary)?,
                    SecuritySeverity::Low,
                    0.15,
                    saas_confidence(primary, 0.55),
                    "portable_saas_rare_provider_usage",
                    "portable_finding_implicates_provider_category",
                )?;
            }

            if has_api_or_waf_finding
                && entries.iter().any(|item| {
                    item.provider_category == PortableProviderCategory::ObjectStorage
                        || is_saas_upload_heavy(item)
                })
            {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.saas_cloud_abuse_lite.api_waf_to_cloud_activity_correlation",
                    "SaaS/cloud metadata correlates API or WAF findings with cloud/object-storage activity in the same bounded import.",
                    saas_provider_entity(primary)?,
                    saas_endpoint_related_entity(primary)?,
                    SecuritySeverity::Medium,
                    0.28,
                    saas_confidence(primary, 0.7),
                    "portable_saas_api_waf_cloud_correlation",
                    "portable_finding_implicates_provider_category",
                )?;
            }
        }

        for entries in by_endpoint.values() {
            let primary = entries[0];
            let error_count = entries.iter().filter(|item| is_saas_error(item)).count();
            let write_error_count = entries
                .iter()
                .filter(|item| is_saas_write_or_admin(item) && is_saas_error(item))
                .count();
            if error_count >= 3
                && matches!(
                    primary.provider_category,
                    PortableProviderCategory::Saas | PortableProviderCategory::Cloud
                )
            {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.saas_cloud_abuse_lite.unusual_saas_api_error_burst",
                    "SaaS/cloud metadata shows an unusual API error burst for a bounded provider endpoint.",
                    saas_endpoint_entity(primary)?,
                    Some(saas_provider_entity(primary)?),
                    SecuritySeverity::Medium,
                    0.24,
                    saas_confidence(primary, 0.67),
                    "portable_saas_api_error_burst",
                    "portable_finding_implicates_saas_endpoint",
                )?;
            }

            if write_error_count >= 2 {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.saas_cloud_abuse_lite.api_method_status_anomaly",
                    "SaaS/cloud metadata shows write/admin API methods paired with repeated error status buckets.",
                    saas_endpoint_entity(primary)?,
                    Some(saas_provider_entity(primary)?),
                    SecuritySeverity::Medium,
                    0.22,
                    saas_confidence(primary, 0.63),
                    "portable_saas_api_method_status_anomaly",
                    "portable_finding_implicates_saas_endpoint",
                )?;
            }
        }

        for item in input.saas_cloud_metadata {
            if has_related_auth_failure(item, input.auth_metadata)
                && (is_saas_error(item) || is_saas_upload_heavy(item))
            {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.saas_cloud_abuse_lite.auth_failure_followed_by_saas_anomaly",
                    "SaaS/cloud metadata shows an auth failure correlation with a bounded SaaS/API anomaly.",
                    saas_identity_or_session_entity(item)
                        .unwrap_or(saas_provider_entity(item)?),
                    Some(saas_provider_entity(item)?),
                    SecuritySeverity::Medium,
                    0.25,
                    saas_confidence(item, 0.66),
                    "portable_saas_auth_failure_correlation",
                    "portable_finding_implicates_identity_session",
                )?;
            }

            if possible_token_misuse_supported(item, input.auth_metadata) {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.saas_cloud_abuse_lite.possible_token_misuse_pattern",
                    "Bounded auth and SaaS/cloud metadata show a low-confidence authorized-session misuse pattern; no sensitive value was observed or retained.",
                    saas_identity_or_session_entity(item)
                        .unwrap_or(saas_provider_entity(item)?),
                    Some(saas_provider_entity(item)?),
                    SecuritySeverity::Medium,
                    0.2,
                    saas_confidence(item, 0.54),
                    "portable_saas_authorized_session_anomaly",
                    "portable_finding_implicates_identity_session",
                )?;
            }
        }

        if !input.http_metadata.is_empty() && input.saas_cloud_metadata.iter().any(is_saas_error) {
            let http_error_count = input
                .http_metadata
                .iter()
                .filter(|item| {
                    item.status_code
                        .is_some_and(|status| status == 401 || status == 403 || status >= 500)
                })
                .count();
            if http_error_count >= 2 {
                let primary = &input.saas_cloud_metadata[0];
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.saas_cloud_abuse_lite.http_saas_status_correlation",
                    "HTTP and SaaS/cloud metadata show correlated bounded status anomalies.",
                    saas_provider_entity(primary)?,
                    saas_endpoint_related_entity(primary)?,
                    SecuritySeverity::Low,
                    0.14,
                    saas_confidence(primary, 0.58),
                    "portable_saas_http_status_correlation",
                    "portable_finding_implicates_provider_category",
                )?;
            }
        }

        if output.is_empty() {
            Err(PortableNetworkWebAnalysisError::NoSignals)
        } else {
            Ok(output)
        }
    }
}

#[derive(Clone, Debug)]
pub struct PortableDeceptionEventLiteInput<'a> {
    pub deception_events: &'a [PortableDeceptionEventMetadata],
    pub related_findings: &'a [Finding],
    pub related_risk_hints: &'a [RiskHint],
}

#[derive(Clone, Debug, Default)]
pub struct PortableDeceptionEventLitePlugin;

impl PortableDeceptionEventLitePlugin {
    pub fn analyze(
        &self,
        plugin_id: &PluginId,
        input: PortableDeceptionEventLiteInput<'_>,
    ) -> Result<PortableNetworkWebOutput, PortableNetworkWebAnalysisError> {
        if input.deception_events.is_empty() {
            return Err(PortableNetworkWebAnalysisError::EmptyInput("deception"));
        }

        let mut output = PortableNetworkWebOutput::default();
        let by_sensor = group_deception_by_sensor(input.deception_events);
        let has_related_suspicious_finding = input.related_findings.iter().any(|finding| {
            finding
                .finding_type()
                .starts_with("portable.dns_security_v2.")
                || finding
                    .finding_type()
                    .starts_with("portable.http_analysis_v1.")
                || finding
                    .finding_type()
                    .starts_with("portable.api_security_lite.")
                || finding
                    .finding_type()
                    .starts_with("portable.waf_security_lite.")
                || finding
                    .finding_type()
                    .starts_with("portable.quic_http3_security_lite.")
                || finding
                    .finding_type()
                    .starts_with("portable.remote_admin_protocol_lite.")
                || finding
                    .finding_type()
                    .starts_with("portable.auth_identity_analysis_lite.")
                || finding
                    .finding_type()
                    .starts_with("portable.saas_cloud_abuse_lite.")
        });
        let has_related_risk_chain = !input.related_risk_hints.is_empty();

        for entries in by_sensor.values() {
            let primary = entries[0];
            let repeated = entries.len() >= 3
                || entries
                    .iter()
                    .any(|event| deception_interaction_is_high(event));
            if repeated {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.deception_event_lite.repeated_decoy_interaction",
                    "Deception metadata shows repeated interaction with a bounded decoy or sensor category.",
                    deception_sensor_entity(primary)?,
                    Some(deception_event_category_entity(primary)?),
                    SecuritySeverity::Medium,
                    0.26,
                    deception_confidence(primary, 0.7),
                    "portable_deception_repeated_interaction",
                    "portable_finding_implicates_decoy_sensor",
                )?;
            }

            if entries
                .iter()
                .any(|event| deception_protocol_is_unusual(event))
            {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.deception_event_lite.unusual_protocol_interaction",
                    "Deception metadata shows an unusual protocol category interacting with a decoy or sensor.",
                    deception_protocol_entity(primary)?,
                    Some(deception_sensor_entity(primary)?),
                    SecuritySeverity::Medium,
                    0.24,
                    deception_confidence(primary, 0.66),
                    "portable_deception_unusual_protocol",
                    "portable_finding_implicates_protocol_category",
                )?;
            }

            if has_related_suspicious_finding && repeated {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.deception_event_lite.correlated_suspicious_activity",
                    "Deception metadata correlates repeated decoy interaction with existing portable network, auth, API, WAF, or SaaS findings.",
                    deception_sensor_entity(primary)?,
                    Some(deception_event_category_entity(primary)?),
                    SecuritySeverity::Medium,
                    0.3,
                    deception_confidence(primary, 0.68),
                    "portable_deception_correlated_activity",
                    "portable_finding_implicates_deception_category",
                )?;
            }

            if has_related_risk_chain && (repeated || entries.len() >= 2) {
                push_detection(
                    &mut output,
                    plugin_id,
                    "portable.deception_event_lite.risk_chain_correlation",
                    "Deception metadata correlates decoy interaction with existing bounded risk hints in the portable run.",
                    deception_sensor_entity(primary)?,
                    Some(deception_source_context_entity(primary)?),
                    SecuritySeverity::Low,
                    0.18,
                    deception_confidence(primary, 0.58),
                    "portable_deception_risk_chain_correlation",
                    "portable_finding_implicates_deception_category",
                )?;
            }
        }

        if output.is_empty() {
            Err(PortableNetworkWebAnalysisError::NoSignals)
        } else {
            Ok(output)
        }
    }
}

struct RemoteAdminService {
    key: &'static str,
    label: &'static str,
}

struct RemoteAdminObservation<'a> {
    service: RemoteAdminService,
    source_ip: IpAddress,
    target_ip: IpAddress,
    timestamp: &'a Timestamp,
}

#[allow(clippy::too_many_arguments)]
fn push_detection(
    output: &mut PortableNetworkWebOutput,
    plugin_id: &PluginId,
    finding_type: &str,
    summary: &str,
    entity: EntityRef,
    related_entity: Option<EntityRef>,
    severity: SecuritySeverity,
    risk_delta: f32,
    confidence: f32,
    risk_hint_type: &str,
    graph_hint_type: &str,
) -> Result<(), PortableNetworkWebAnalysisError> {
    let confidence = quality(confidence)?;
    let attack_mappings = portable_attack_mappings(finding_type, &confidence)?;

    let mut evidence = EvidenceItem::new(finding_type, summary)
        .map_err(|error| PortableNetworkWebAnalysisError::Contract(error.to_string()))?;
    evidence.source_plugin = Some(plugin_id.clone());
    evidence.entity_refs = vec![entity.clone()];
    if let Some(related_entity) = &related_entity {
        evidence.entity_refs.push(related_entity.clone());
    }
    evidence.timestamp = Timestamp::now();
    evidence.weight = confidence.clone();
    evidence.confidence = confidence.clone();
    evidence.privacy_class = PrivacyClass::Internal;
    evidence.description_redacted =
        Some("Metadata-only evidence; raw content was not retained.".to_string());

    let mut reason = RiskReason::new(risk_hint_type, summary)
        .map_err(|error| PortableNetworkWebAnalysisError::Contract(error.to_string()))?;
    reason.confidence = confidence.clone();
    reason.evidence_refs = vec![evidence.evidence_id.clone()];
    reason.attack_mappings = attack_mappings.clone();

    let mut explanation = FindingExplanation::new(summary)
        .map_err(|error| PortableNetworkWebAnalysisError::Contract(error.to_string()))?;
    explanation.risk_reasons.push(reason.clone());
    explanation.limitations_redacted.push(
        "Metadata-only detection; raw packets, bodies, and sensitive account material were not retained."
            .to_string(),
    );
    if !attack_mappings.is_empty() {
        explanation.limitations_redacted.push(
            "ATT&CK mapping confidence is intentionally degraded because the signal is bounded metadata only."
                .to_string(),
        );
    }

    let finding = Finding::new(
        finding_type,
        plugin_id.clone(),
        vec![evidence.evidence_id.clone()],
        explanation,
    )
    .map_err(|error| PortableNetworkWebAnalysisError::Contract(error.to_string()))?
    .with_entity_refs({
        let mut entities = vec![entity.clone()];
        if let Some(related_entity) = &related_entity {
            entities.push(related_entity.clone());
        }
        entities
    })
    .with_confidence(confidence.clone())
    .with_severity(severity)
    .with_risk_reasons(vec![reason])
    .with_attack_mappings(attack_mappings);

    let mut hint = RiskHint::new(
        risk_hint_type,
        summary,
        vec![IntelligenceRecordId::new_v4()],
    )
    .map_err(|error| PortableNetworkWebAnalysisError::Contract(error.to_string()))?
    .with_risk_delta(risk_delta)
    .with_confidence(confidence.clone());
    hint.entity_ref = Some(entity.clone());
    hint.privacy_class = PrivacyClass::Internal;
    hint.timestamp = Timestamp::now();

    let mut graph_hint = GraphHint::new(
        GraphHintType::Custom(graph_hint_type.to_string()),
        finding_entity_ref(&finding),
        related_entity.unwrap_or(entity),
        plugin_id.clone(),
    );
    graph_hint.evidence_refs = vec![evidence.evidence_id.clone()];
    graph_hint.confidence = confidence;
    graph_hint.privacy_class = PrivacyClass::Internal;
    graph_hint.timestamp = Timestamp::now();

    output.evidence.push(evidence);
    output.findings.push(finding);
    output.risk_hints.push(hint);
    output.graph_hints.push(graph_hint);
    Ok(())
}

fn portable_attack_mappings(
    finding_type: &str,
    confidence: &QualityScore,
) -> Result<Vec<AttackMapping>, PortableNetworkWebAnalysisError> {
    let Some((mapping_id, mapping_confidence)) =
        portable_attack_mapping_spec(finding_type, confidence.value())
    else {
        return Ok(Vec::new());
    };

    let Some(definition) = allowlisted_attack_mapping(mapping_id) else {
        return Ok(Vec::new());
    };

    let mut provenance = MappingProvenance::new(PORTABLE_ATTACK_MAPPING_SOURCE)
        .map_err(|error| PortableNetworkWebAnalysisError::Contract(error.to_string()))?;
    provenance.source_version = Some(PORTABLE_ATTACK_MAPPING_VERSION.to_string());
    provenance.mapped_by = Some("portable_network_web".to_string());
    provenance.mapped_at = Some(Timestamp::now());

    let confidence = quality(mapping_confidence)?;
    let mut mapping = AttackMapping::mitre_attack_enterprise(
        definition.tactic_id,
        definition.tactic_name,
        definition.technique_id,
        definition.technique_name,
        confidence,
        Some(provenance),
    )
    .map_err(|error| PortableNetworkWebAnalysisError::Contract(error.to_string()))?;
    if let Some((subtechnique_id, subtechnique_name)) = definition.subtechnique {
        mapping = mapping
            .with_subtechnique(subtechnique_id, subtechnique_name)
            .map_err(|error| PortableNetworkWebAnalysisError::Contract(error.to_string()))?;
    }
    Ok(vec![mapping])
}

fn portable_attack_mapping_spec(
    finding_type: &str,
    base_confidence: f32,
) -> Option<(&'static str, f32)> {
    if finding_type.starts_with("portable.dns_security_v2.") {
        Some((
            "T1071.004",
            degraded_mapping_confidence(base_confidence, 0.72, 0.58),
        ))
    } else if finding_type.starts_with("portable.http_analysis_v1.")
        || finding_type.starts_with("portable.api_security_lite.")
        || finding_type.starts_with("portable.waf_security_lite.")
        || finding_type.starts_with("portable.quic_http3_security_lite.")
    {
        Some((
            "T1071.001",
            degraded_mapping_confidence(base_confidence, 0.74, 0.62),
        ))
    } else if finding_type.starts_with("portable.remote_admin_protocol_lite.rdp_") {
        Some((
            "T1021.001",
            degraded_mapping_confidence(base_confidence, 0.84, 0.69),
        ))
    } else if finding_type.starts_with("portable.remote_admin_protocol_lite.smb_") {
        Some((
            "T1021.002",
            degraded_mapping_confidence(base_confidence, 0.84, 0.69),
        ))
    } else if finding_type.starts_with("portable.remote_admin_protocol_lite.ssh_") {
        Some((
            "T1021.004",
            degraded_mapping_confidence(base_confidence, 0.84, 0.69),
        ))
    } else if finding_type.starts_with("portable.remote_admin_protocol_lite.") {
        Some((
            "T1021",
            degraded_mapping_confidence(base_confidence, 0.78, 0.64),
        ))
    } else if finding_type == "portable.auth_identity_analysis_lite.mfa_fatigue_like_pattern" {
        Some((
            "T1621",
            degraded_mapping_confidence(base_confidence, 0.78, 0.61),
        ))
    } else if finding_type == "portable.auth_identity_analysis_lite.auth_failure_burst"
        || finding_type == "portable.auth_identity_analysis_lite.suspicious_provider_category"
        || finding_type
            == "portable.auth_identity_analysis_lite.remote_admin_auth_failure_correlation"
    {
        Some((
            "T1110",
            degraded_mapping_confidence(base_confidence, 0.76, 0.6),
        ))
    } else if finding_type == "portable.saas_cloud_abuse_lite.suspicious_object_storage_upload"
        || finding_type == "portable.saas_cloud_abuse_lite.api_waf_to_cloud_activity_correlation"
    {
        Some((
            "T1567.002",
            degraded_mapping_confidence(base_confidence, 0.72, 0.56),
        ))
    } else if finding_type.starts_with("portable.saas_cloud_abuse_lite.") {
        Some((
            "T1078",
            degraded_mapping_confidence(base_confidence, 0.6, 0.48),
        ))
    } else if finding_type.starts_with("portable.deception_event_lite.") {
        Some((
            "T1046",
            degraded_mapping_confidence(base_confidence, 0.66, 0.46),
        ))
    } else {
        None
    }
}

fn degraded_mapping_confidence(base_confidence: f32, factor: f32, cap: f32) -> f32 {
    (base_confidence * factor).min(cap).max(0.12)
}

struct AttackMappingDefinition {
    tactic_id: &'static str,
    tactic_name: &'static str,
    technique_id: &'static str,
    technique_name: &'static str,
    subtechnique: Option<(&'static str, &'static str)>,
}

fn allowlisted_attack_mapping(mapping_id: &str) -> Option<AttackMappingDefinition> {
    match mapping_id {
        "T1071.001" => Some(AttackMappingDefinition {
            tactic_id: "TA0011",
            tactic_name: "Command and Control",
            technique_id: "T1071",
            technique_name: "Application Layer Protocol",
            subtechnique: Some(("T1071.001", "Web Protocols")),
        }),
        "T1071.004" => Some(AttackMappingDefinition {
            tactic_id: "TA0011",
            tactic_name: "Command and Control",
            technique_id: "T1071",
            technique_name: "Application Layer Protocol",
            subtechnique: Some(("T1071.004", "DNS")),
        }),
        "T1021" => Some(AttackMappingDefinition {
            tactic_id: "TA0008",
            tactic_name: "Lateral Movement",
            technique_id: "T1021",
            technique_name: "Remote Services",
            subtechnique: None,
        }),
        "T1021.001" => Some(AttackMappingDefinition {
            tactic_id: "TA0008",
            tactic_name: "Lateral Movement",
            technique_id: "T1021",
            technique_name: "Remote Services",
            subtechnique: Some(("T1021.001", "Remote Desktop Protocol")),
        }),
        "T1021.002" => Some(AttackMappingDefinition {
            tactic_id: "TA0008",
            tactic_name: "Lateral Movement",
            technique_id: "T1021",
            technique_name: "Remote Services",
            subtechnique: Some(("T1021.002", "SMB/Windows Admin Shares")),
        }),
        "T1021.004" => Some(AttackMappingDefinition {
            tactic_id: "TA0008",
            tactic_name: "Lateral Movement",
            technique_id: "T1021",
            technique_name: "Remote Services",
            subtechnique: Some(("T1021.004", "SSH")),
        }),
        "T1110" => Some(AttackMappingDefinition {
            tactic_id: "TA0006",
            tactic_name: "Credential Access",
            technique_id: "T1110",
            technique_name: "Brute Force",
            subtechnique: None,
        }),
        "T1621" => Some(AttackMappingDefinition {
            tactic_id: "TA0001",
            tactic_name: "Initial Access",
            technique_id: "T1621",
            technique_name: "Multi-Factor Authentication Request Generation",
            subtechnique: None,
        }),
        "T1567.002" => Some(AttackMappingDefinition {
            tactic_id: "TA0010",
            tactic_name: "Exfiltration",
            technique_id: "T1567",
            technique_name: "Exfiltration Over Web Service",
            subtechnique: Some(("T1567.002", "Exfiltration to Cloud Storage")),
        }),
        "T1078" => Some(AttackMappingDefinition {
            tactic_id: "TA0001",
            tactic_name: "Initial Access",
            technique_id: "T1078",
            technique_name: "Valid Accounts",
            subtechnique: None,
        }),
        "T1046" => Some(AttackMappingDefinition {
            tactic_id: "TA0007",
            tactic_name: "Discovery",
            technique_id: "T1046",
            technique_name: "Network Service Discovery",
            subtechnique: None,
        }),
        _ => None,
    }
}

fn finding_entity_ref(finding: &Finding) -> EntityRef {
    let mut entity = EntityRef::new(
        EntityId::from_uuid(finding.id().as_uuid()),
        EntityType::Finding,
    );
    entity.entity_name = Some("finding".to_string());
    entity.namespace = Some("security.finding".to_string());
    entity.source = Some("portable.network_web.analysis".to_string());
    entity.confidence = finding.confidence().clone();
    entity
}

fn domain_entity(
    value: &str,
    timestamp: &Timestamp,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.domain", value),
        EntityType::Domain,
    );
    entity.entity_name = Some(value.to_string());
    entity.namespace = Some("network.domain".to_string());
    entity.source = Some("portable.network_web.analysis".to_string());
    entity.confidence = quality(0.7)?;
    entity.first_seen = Some(timestamp.clone());
    entity.last_seen = Some(timestamp.clone());
    Ok(entity)
}

fn ip_entity(
    prefix: &str,
    ip: IpAddress,
    timestamp: &Timestamp,
    entity_type: EntityType,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    ip_entity_from_text(prefix, &ip.to_string(), timestamp).map(|mut entity| {
        entity.entity_type = entity_type;
        entity
    })
}

fn ip_entity_from_text(
    prefix: &str,
    value: &str,
    timestamp: &Timestamp,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    let mut entity = EntityRef::new(deterministic_entity_id(prefix, value), EntityType::Ip);
    entity.entity_name = Some(value.to_string());
    entity.namespace = Some("network.ip".to_string());
    entity.source = Some("portable.network_web.analysis".to_string());
    entity.confidence = quality(0.7)?;
    entity.first_seen = Some(timestamp.clone());
    entity.last_seen = Some(timestamp.clone());
    Ok(entity)
}

fn http_host_entity(http: &HttpMetadata) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    let host = http.host_protected.as_deref().unwrap_or("host#unknown");
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.http.host", host),
        EntityType::Domain,
    );
    entity.entity_name = Some(host.to_string());
    entity.namespace = Some("network.domain".to_string());
    entity.source = Some("portable.network_web.analysis".to_string());
    entity.confidence = quality(0.7)?;
    entity.first_seen = Some(http.timestamp.clone());
    entity.last_seen = Some(http.timestamp.clone());
    Ok(entity)
}

fn http_endpoint_entity(http: &HttpMetadata) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    let endpoint = http
        .endpoint_fingerprint
        .as_deref()
        .unwrap_or("endpoint-unknown");
    let name = format!(
        "{}:{}",
        http.host_protected.as_deref().unwrap_or("host#unknown"),
        http.path_template_protected
            .as_deref()
            .unwrap_or("/redacted/{id}")
    );
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.http.endpoint", endpoint),
        EntityType::ApiEndpoint,
    );
    entity.entity_name = Some(name);
    entity.namespace = Some("network.api_endpoint".to_string());
    entity.source = Some("portable.network_web.analysis".to_string());
    entity.confidence = quality(0.72)?;
    entity.first_seen = Some(http.timestamp.clone());
    entity.last_seen = Some(http.timestamp.clone());
    Ok(entity)
}

fn http_endpoint_or_host_entity(
    http: &HttpMetadata,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    if http.endpoint_fingerprint.is_some() {
        http_endpoint_entity(http)
    } else {
        http_host_entity(http)
    }
}

fn http_related_source_entity(http: &HttpMetadata, flows: &[FlowRecord]) -> Option<EntityRef> {
    let flow_ref = http.flow_ref.as_ref()?;
    let flow = flow_index(flows).get(&flow_ref.to_string()).copied()?;
    ip_entity(
        "portable.http.source_ip",
        flow.src_ip,
        &http.timestamp,
        EntityType::Ip,
    )
    .ok()
}

fn flow_index(flows: &[FlowRecord]) -> BTreeMap<String, &FlowRecord> {
    flows
        .iter()
        .map(|flow| (flow.flow_id.to_string(), flow))
        .collect()
}

fn group_http_by_host(http: &[HttpMetadata]) -> BTreeMap<String, Vec<&HttpMetadata>> {
    let mut grouped = BTreeMap::<String, Vec<&HttpMetadata>>::new();
    for item in http {
        grouped
            .entry(
                item.host_protected
                    .clone()
                    .unwrap_or_else(|| "host#unknown".to_string()),
            )
            .or_default()
            .push(item);
    }
    grouped
}

fn group_http_by_endpoint(http: &[HttpMetadata]) -> BTreeMap<String, Vec<&HttpMetadata>> {
    let mut grouped = BTreeMap::<String, Vec<&HttpMetadata>>::new();
    for item in http {
        let key = item
            .endpoint_fingerprint
            .clone()
            .or_else(|| item.path_template_protected.clone())
            .unwrap_or_else(|| "endpoint#unknown".to_string());
        grouped.entry(key).or_default().push(item);
    }
    grouped
}

fn group_auth_by_provider(
    auth_metadata: &[PortableAuthMetadata],
) -> BTreeMap<String, Vec<&PortableAuthMetadata>> {
    let mut grouped = BTreeMap::<String, Vec<&PortableAuthMetadata>>::new();
    for item in auth_metadata {
        grouped
            .entry(item.provider_category.clone())
            .or_default()
            .push(item);
    }
    grouped
}

fn group_auth_by_identity_provider(
    auth_metadata: &[PortableAuthMetadata],
) -> BTreeMap<String, Vec<&PortableAuthMetadata>> {
    let mut grouped = BTreeMap::<String, Vec<&PortableAuthMetadata>>::new();
    for item in auth_metadata {
        let identity = item
            .identity_label_redacted
            .clone()
            .or_else(|| item.source_session_label.clone())
            .unwrap_or_else(|| "identity#unknown".to_string());
        grouped
            .entry(format!("{identity}|{}", item.provider_category))
            .or_default()
            .push(item);
    }
    grouped
}

fn group_auth_by_service(
    auth_metadata: &[PortableAuthMetadata],
) -> BTreeMap<String, Vec<&PortableAuthMetadata>> {
    let mut grouped = BTreeMap::<String, Vec<&PortableAuthMetadata>>::new();
    for item in auth_metadata {
        grouped
            .entry(
                item.destination_service_category
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            )
            .or_default()
            .push(item);
    }
    grouped
}

fn group_deception_by_sensor(
    events: &[PortableDeceptionEventMetadata],
) -> BTreeMap<String, Vec<&PortableDeceptionEventMetadata>> {
    let mut grouped = BTreeMap::<String, Vec<&PortableDeceptionEventMetadata>>::new();
    for item in events {
        grouped
            .entry(
                item.decoy_sensor_ref
                    .clone()
                    .unwrap_or_else(|| "sensor#unknown".to_string()),
            )
            .or_default()
            .push(item);
    }
    grouped
}

fn deception_sensor_entity(
    record: &PortableDeceptionEventMetadata,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    let sensor = record
        .decoy_sensor_ref
        .as_deref()
        .unwrap_or("sensor#unknown");
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.deception.sensor", sensor),
        EntityType::Decoy,
    );
    entity.entity_name = Some(sensor.to_string());
    entity.namespace = Some("deception.decoy_sensor".to_string());
    entity.source = Some("portable.deception_event_metadata".to_string());
    entity.confidence = quality(deception_confidence(record, 0.78))?;
    entity.first_seen = Some(record.time_bucket_start.clone());
    entity.last_seen = Some(record.time_bucket_start.clone());
    Ok(entity)
}

fn deception_event_category_entity(
    record: &PortableDeceptionEventMetadata,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.deception.event", &record.event_category),
        EntityType::Honeypot,
    );
    entity.entity_name = Some(record.event_category.clone());
    entity.namespace = Some("deception.event_category".to_string());
    entity.source = Some("portable.deception_event_metadata".to_string());
    entity.confidence = quality(deception_confidence(record, 0.7))?;
    entity.first_seen = Some(record.time_bucket_start.clone());
    entity.last_seen = Some(record.time_bucket_start.clone());
    Ok(entity)
}

fn deception_protocol_entity(
    record: &PortableDeceptionEventMetadata,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    let label = deception_protocol_label(&record.protocol_category);
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.deception.protocol", label),
        EntityType::Service,
    );
    entity.entity_name = Some(label.to_string());
    entity.namespace = Some("deception.protocol_category".to_string());
    entity.source = Some("portable.deception_event_metadata".to_string());
    entity.confidence = quality(deception_confidence(record, 0.68))?;
    entity.first_seen = Some(record.time_bucket_start.clone());
    entity.last_seen = Some(record.time_bucket_start.clone());
    Ok(entity)
}

fn deception_source_context_entity(
    record: &PortableDeceptionEventMetadata,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    let label = record
        .source_context_category
        .as_deref()
        .unwrap_or("source_context_unknown");
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.deception.source_context", label),
        EntityType::Other,
    );
    entity.entity_name = Some(label.to_string());
    entity.namespace = Some("deception.source_context".to_string());
    entity.source = Some("portable.deception_event_metadata".to_string());
    entity.confidence = quality(deception_confidence(record, 0.62))?;
    entity.first_seen = Some(record.time_bucket_start.clone());
    entity.last_seen = Some(record.time_bucket_start.clone());
    Ok(entity)
}

fn group_saas_by_provider(
    metadata: &[PortableSaasCloudMetadata],
) -> BTreeMap<String, Vec<&PortableSaasCloudMetadata>> {
    let mut grouped = BTreeMap::<String, Vec<&PortableSaasCloudMetadata>>::new();
    for item in metadata {
        grouped
            .entry(format!("{:?}", item.provider_category))
            .or_default()
            .push(item);
    }
    grouped
}

fn group_saas_by_endpoint(
    metadata: &[PortableSaasCloudMetadata],
) -> BTreeMap<String, Vec<&PortableSaasCloudMetadata>> {
    let mut grouped = BTreeMap::<String, Vec<&PortableSaasCloudMetadata>>::new();
    for item in metadata {
        let key = format!(
            "{:?}|{}",
            item.provider_category,
            item.endpoint_fingerprint
                .as_deref()
                .unwrap_or("endpoint#unknown")
        );
        grouped.entry(key).or_default().push(item);
    }
    grouped
}

fn saas_provider_entity(
    record: &PortableSaasCloudMetadata,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    let label = provider_category_label(&record.provider_category);
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.saas.provider", label),
        EntityType::CloudResource,
    );
    entity.entity_name = Some(label.to_string());
    entity.namespace = Some("cloud.provider_category".to_string());
    entity.source = Some("portable.saas_cloud_metadata".to_string());
    entity.confidence = quality(saas_confidence(record, 0.82))?;
    entity.first_seen = Some(record.time_bucket_start.clone());
    entity.last_seen = Some(record.time_bucket_start.clone());
    Ok(entity)
}

fn saas_endpoint_entity(
    record: &PortableSaasCloudMetadata,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    let endpoint = record
        .endpoint_fingerprint
        .as_deref()
        .unwrap_or("endpoint#unknown");
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.saas.endpoint", endpoint),
        EntityType::ApiEndpoint,
    );
    entity.entity_name = Some(endpoint.to_string());
    entity.namespace = Some("cloud.endpoint_fingerprint".to_string());
    entity.source = Some("portable.saas_cloud_metadata".to_string());
    entity.confidence = quality(saas_confidence(record, 0.78))?;
    entity.first_seen = Some(record.time_bucket_start.clone());
    entity.last_seen = Some(record.time_bucket_start.clone());
    Ok(entity)
}

fn saas_endpoint_related_entity(
    record: &PortableSaasCloudMetadata,
) -> Result<Option<EntityRef>, PortableNetworkWebAnalysisError> {
    if record.endpoint_fingerprint.is_some() {
        Ok(Some(saas_endpoint_entity(record)?))
    } else {
        Ok(None)
    }
}

fn saas_identity_or_session_entity(record: &PortableSaasCloudMetadata) -> Option<EntityRef> {
    let (namespace, value, entity_type) =
        if let Some(identity) = record.identity_label_redacted.as_deref() {
            ("identity.redacted", identity, EntityType::User)
        } else if let Some(session) = record.source_session_label.as_deref() {
            ("session.redacted", session, EntityType::Other)
        } else {
            return None;
        };
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.saas.identity_session", value),
        entity_type,
    );
    entity.entity_name = Some(value.to_string());
    entity.namespace = Some(namespace.to_string());
    entity.source = Some("portable.saas_cloud_metadata".to_string());
    entity.confidence = QualityScore::new(0.62).unwrap_or_default();
    entity.first_seen = Some(record.time_bucket_start.clone());
    entity.last_seen = Some(record.time_bucket_start.clone());
    Some(entity)
}

fn provider_category_label(category: &PortableProviderCategory) -> &'static str {
    match category {
        PortableProviderCategory::Saas => "saas",
        PortableProviderCategory::Cloud => "cloud",
        PortableProviderCategory::Cdn => "cdn",
        PortableProviderCategory::ObjectStorage => "object_storage",
        PortableProviderCategory::TunnelProxy => "tunnel_proxy",
        PortableProviderCategory::Anonymizing => "anonymizing",
        PortableProviderCategory::Unknown => "unknown",
    }
}

fn deception_protocol_label(category: &PortableDeceptionProtocolCategory) -> &'static str {
    match category {
        PortableDeceptionProtocolCategory::Http => "http",
        PortableDeceptionProtocolCategory::Dns => "dns",
        PortableDeceptionProtocolCategory::Ssh => "ssh",
        PortableDeceptionProtocolCategory::Smb => "smb",
        PortableDeceptionProtocolCategory::Rdp => "rdp",
        PortableDeceptionProtocolCategory::Ftp => "ftp",
        PortableDeceptionProtocolCategory::Telnet => "telnet",
        PortableDeceptionProtocolCategory::Database => "database",
        PortableDeceptionProtocolCategory::Ics => "ics",
        PortableDeceptionProtocolCategory::Other => "other",
        PortableDeceptionProtocolCategory::Unknown => "unknown",
    }
}

fn deception_confidence(record: &PortableDeceptionEventMetadata, base: f32) -> f32 {
    let mut value = base * record.quality_score.value().max(0.35);
    if record.decoy_sensor_ref.is_none() {
        value *= 0.82;
    }
    if matches!(
        record.protocol_category,
        PortableDeceptionProtocolCategory::Unknown
    ) {
        value *= 0.72;
    }
    if matches!(
        record.interaction_count_bucket,
        PortableDecoyInteractionCountBucket::Unknown
    ) {
        value *= 0.8;
    }
    value.clamp(0.22, 0.78)
}

fn deception_interaction_is_high(record: &PortableDeceptionEventMetadata) -> bool {
    matches!(
        record.interaction_count_bucket,
        PortableDecoyInteractionCountBucket::High | PortableDecoyInteractionCountBucket::Burst
    )
}

fn deception_protocol_is_unusual(record: &PortableDeceptionEventMetadata) -> bool {
    matches!(
        record.protocol_category,
        PortableDeceptionProtocolCategory::Ftp
            | PortableDeceptionProtocolCategory::Telnet
            | PortableDeceptionProtocolCategory::Database
            | PortableDeceptionProtocolCategory::Ics
    ) || (record.source_context_category.as_deref() == Some("external")
        && matches!(
            record.protocol_category,
            PortableDeceptionProtocolCategory::Ssh
                | PortableDeceptionProtocolCategory::Smb
                | PortableDeceptionProtocolCategory::Rdp
        ))
}

fn saas_confidence(record: &PortableSaasCloudMetadata, base: f32) -> f32 {
    let confidence_factor = match record.provider_confidence {
        PortableProviderConfidenceBucket::High => 1.0,
        PortableProviderConfidenceBucket::Medium => 0.88,
        PortableProviderConfidenceBucket::Low => 0.66,
        PortableProviderConfidenceBucket::Unknown => 0.54,
    };
    let provider_factor = if record.provider_category == PortableProviderCategory::Unknown {
        0.62
    } else {
        1.0
    };
    (base * confidence_factor * provider_factor).clamp(0.24, 0.82)
}

fn is_saas_upload_heavy(record: &PortableSaasCloudMetadata) -> bool {
    matches!(
        record.upload_download_ratio_bucket,
        PortableUploadDownloadRatioBucket::UploadHeavy
            | PortableUploadDownloadRatioBucket::UploadBurst
    )
}

fn is_saas_error(record: &PortableSaasCloudMetadata) -> bool {
    matches!(
        record.status_bucket,
        PortableStatusBucket::AuthError
            | PortableStatusBucket::NotFound
            | PortableStatusBucket::RateLimited
            | PortableStatusBucket::ClientError
            | PortableStatusBucket::ServerError
    )
}

fn is_saas_write_or_admin(record: &PortableSaasCloudMetadata) -> bool {
    matches!(
        record.api_method_category,
        sentinel_contracts::PortableApiMethodCategory::Write
            | sentinel_contracts::PortableApiMethodCategory::Delete
            | sentinel_contracts::PortableApiMethodCategory::Admin
    )
}

fn is_risky_provider(record: &PortableSaasCloudMetadata) -> bool {
    matches!(
        record.provider_risk_category,
        PortableProviderRiskCategory::High
    ) || matches!(
        record.provider_category,
        PortableProviderCategory::TunnelProxy | PortableProviderCategory::Anonymizing
    )
}

fn has_related_auth_failure(
    record: &PortableSaasCloudMetadata,
    auth_metadata: &[PortableAuthMetadata],
) -> bool {
    auth_metadata.iter().any(|auth| {
        is_auth_failure(auth)
            && same_bounded_identity_or_session(
                record.identity_label_redacted.as_deref(),
                record.source_session_label.as_deref(),
                auth.identity_label_redacted.as_deref(),
                auth.source_session_label.as_deref(),
            )
    })
}

fn possible_token_misuse_supported(
    record: &PortableSaasCloudMetadata,
    auth_metadata: &[PortableAuthMetadata],
) -> bool {
    let has_failed_auth = has_related_auth_failure(record, auth_metadata);
    has_failed_auth
        && matches!(
            record.status_bucket,
            PortableStatusBucket::Success | PortableStatusBucket::RateLimited
        )
        && (is_saas_upload_heavy(record) || is_saas_write_or_admin(record))
        && record.auth_result_category.as_deref() == Some("success")
}

fn same_bounded_identity_or_session(
    left_identity: Option<&str>,
    left_session: Option<&str>,
    right_identity: Option<&str>,
    right_session: Option<&str>,
) -> bool {
    left_identity
        .zip(right_identity)
        .is_some_and(|(left, right)| left == right)
        || left_session
            .zip(right_session)
            .is_some_and(|(left, right)| left == right)
}

fn auth_identity_or_session_entity(
    record: &PortableAuthMetadata,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    if let Some(identity) = record.identity_label_redacted.as_deref() {
        let mut entity = EntityRef::new(
            deterministic_entity_id("portable.auth.identity", identity),
            EntityType::User,
        );
        entity.entity_name = Some(identity.to_string());
        entity.namespace = Some("identity.auth_subject".to_string());
        entity.source = Some("portable.network_web.analysis".to_string());
        entity.confidence = quality(0.7)?;
        entity.first_seen = Some(record.time_bucket_start.clone());
        entity.last_seen = Some(record.time_bucket_start.clone());
        return Ok(entity);
    }

    let session = record
        .source_session_label
        .as_deref()
        .unwrap_or("session#unknown");
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.auth.session", session),
        EntityType::Other,
    );
    entity.entity_name = Some(session.to_string());
    entity.namespace = Some("identity.auth_session".to_string());
    entity.source = Some("portable.network_web.analysis".to_string());
    entity.confidence = quality(0.65)?;
    entity.first_seen = Some(record.time_bucket_start.clone());
    entity.last_seen = Some(record.time_bucket_start.clone());
    Ok(entity)
}

fn auth_provider_entity(
    record: &PortableAuthMetadata,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.auth.provider", &record.provider_category),
        EntityType::Service,
    );
    entity.entity_name = Some(record.provider_category.clone());
    entity.namespace = Some("identity.provider_category".to_string());
    entity.source = Some("portable.network_web.analysis".to_string());
    entity.confidence = quality(0.68)?;
    entity.first_seen = Some(record.time_bucket_start.clone());
    entity.last_seen = Some(record.time_bucket_start.clone());
    Ok(entity)
}

fn auth_service_entity(
    service_category: &str,
    timestamp: &Timestamp,
) -> Result<EntityRef, PortableNetworkWebAnalysisError> {
    let mut entity = EntityRef::new(
        deterministic_entity_id("portable.auth.service", service_category),
        EntityType::Service,
    );
    entity.entity_name = Some(service_category.to_string());
    entity.namespace = Some("identity.auth_service".to_string());
    entity.source = Some("portable.network_web.analysis".to_string());
    entity.confidence = quality(0.68)?;
    entity.first_seen = Some(timestamp.clone());
    entity.last_seen = Some(timestamp.clone());
    Ok(entity)
}

fn auth_service_related_entity(record: &PortableAuthMetadata) -> Option<EntityRef> {
    let service = record.destination_service_category.as_deref()?;
    auth_service_entity(service, &record.time_bucket_start).ok()
}

fn quic_destination_category(http: &HttpMetadata) -> &'static str {
    if http.api_hint.is_some() {
        return "api";
    }

    let host = http.host_protected.as_deref().unwrap_or_default();
    let host = host.to_ascii_lowercase();
    if host.contains("cdn") || host.contains("edge") {
        "cdn"
    } else if host.contains("storage") || host.contains("blob") || host.contains("bucket") {
        "object_storage"
    } else {
        "web"
    }
}

fn is_http_failure(http: &HttpMetadata) -> bool {
    http.status_code.is_some_and(|status| status >= 400)
        || http
            .result_label
            .as_deref()
            .map(|label| {
                let label = label.to_ascii_lowercase();
                label.contains("fail")
                    || label.contains("error")
                    || label.contains("timeout")
                    || label.contains("deny")
            })
            .unwrap_or(false)
}

fn is_http3_alpn(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower == "h3" || lower.starts_with("h3-")
}

fn admin_observation_from_session(session: &SessionRecord) -> Option<RemoteAdminObservation<'_>> {
    let service = remote_admin_service(session.remote_port)?;
    if session.direction != sentinel_contracts::NetworkDirection::Outbound
        || !is_internal_ip(&session.remote_ip)
        || session.local_ip == session.remote_ip
    {
        return None;
    }

    Some(RemoteAdminObservation {
        service,
        source_ip: session.local_ip,
        target_ip: session.remote_ip,
        timestamp: &session.start_time,
    })
}

fn admin_observation_from_flow(flow: &FlowRecord) -> Option<RemoteAdminObservation<'_>> {
    let service = remote_admin_service(flow.dst_port)?;
    if flow.direction != sentinel_contracts::NetworkDirection::Outbound
        || !is_internal_ip(&flow.dst_ip)
        || flow.src_ip == flow.dst_ip
    {
        return None;
    }

    Some(RemoteAdminObservation {
        service,
        source_ip: flow.src_ip,
        target_ip: flow.dst_ip,
        timestamp: &flow.start_time,
    })
}

fn remote_admin_service(port: u16) -> Option<RemoteAdminService> {
    match port {
        22 => Some(RemoteAdminService {
            key: "ssh",
            label: "SSH",
        }),
        445 => Some(RemoteAdminService {
            key: "smb",
            label: "SMB",
        }),
        3389 => Some(RemoteAdminService {
            key: "rdp",
            label: "RDP",
        }),
        _ => None,
    }
}

fn remote_admin_service_keys(
    flows: &[FlowRecord],
    sessions: &[SessionRecord],
) -> BTreeSet<&'static str> {
    let mut keys = BTreeSet::new();
    for flow in flows {
        if let Some(service) = remote_admin_service(flow.dst_port) {
            keys.insert(service.key);
        }
    }
    for session in sessions {
        if let Some(service) = remote_admin_service(session.remote_port) {
            keys.insert(service.key);
        }
    }
    keys
}

fn is_auth_failure(record: &PortableAuthMetadata) -> bool {
    matches!(
        record.auth_result,
        PortableAuthResultCategory::Failure
            | PortableAuthResultCategory::Blocked
            | PortableAuthResultCategory::Timeout
    )
}

fn is_suspicious_provider_category(category: &str) -> bool {
    matches!(
        category,
        "vpn" | "remote_admin" | "waf_gateway" | "external_identity"
    )
}

fn is_remote_admin_auth_service(service: &str) -> bool {
    matches!(service, "ssh" | "rdp" | "smb")
}

fn is_first_seen_identity_provider_pair(
    primary: &PortableAuthMetadata,
    entries: &[&PortableAuthMetadata],
    all_records: &[PortableAuthMetadata],
) -> bool {
    if entries.len() != 1 || all_records.len() < 4 {
        return false;
    }

    let Some(identity) = primary.identity_label_redacted.as_deref() else {
        return false;
    };

    let identity_has_other_provider = all_records.iter().any(|record| {
        record.identity_label_redacted.as_deref() == Some(identity)
            && record.provider_category != primary.provider_category
    });
    let provider_has_other_identity = all_records.iter().any(|record| {
        record.provider_category == primary.provider_category
            && record.identity_label_redacted.as_deref() != Some(identity)
    });
    identity_has_other_provider || provider_has_other_identity
}

fn is_internal_ip(ip: &IpAddress) -> bool {
    match ip.as_ip_addr() {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || matches!(
                    address.octets(),
                    [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
                )
        }
        IpAddr::V6(address) => address.is_loopback() || address.is_unique_local(),
    }
}

fn deterministic_entity_id(prefix: &str, value: &str) -> EntityId {
    let mut digest = Sha256::new();
    digest.update(prefix.as_bytes());
    digest.update(value.as_bytes());
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId::from_uuid(Uuid::from_bytes(bytes))
}

fn is_mutating_method(method: &HttpMethod) -> bool {
    matches!(
        method,
        HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch | HttpMethod::Delete
    )
}

fn is_suspicious_user_agent(value: Option<&str>) -> bool {
    matches!(
        value,
        Some("curl" | "powershell" | "python_requests" | "other")
    )
}

fn is_blocked_waf_event(http: &HttpMetadata) -> bool {
    http.waf_action
        .as_deref()
        .map(|action| {
            let action = action.to_ascii_lowercase();
            action.contains("block") || action.contains("deny")
        })
        .unwrap_or(false)
        || (http.waf_rule_id.is_some() && http.status_code == Some(403))
}

fn http_method_token(method: &HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "get",
        HttpMethod::Post => "post",
        HttpMethod::Put => "put",
        HttpMethod::Patch => "patch",
        HttpMethod::Delete => "delete",
        HttpMethod::Head => "head",
        HttpMethod::Options => "options",
        HttpMethod::Trace => "trace",
        HttpMethod::Connect => "connect",
        HttpMethod::Other => "other",
    }
}

fn quality(value: f32) -> Result<QualityScore, PortableNetworkWebAnalysisError> {
    QualityScore::new(value)
        .map_err(|error| PortableNetworkWebAnalysisError::Contract(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        DnsFeatures, EvidenceId, FlowRecord, NetworkDirection, PortableApiMethodCategory,
        RedactionStatus, SessionRecord, TlsObservation, TransportProtocol,
    };

    fn ip(value: &str) -> IpAddress {
        IpAddress::parse_str(value).expect("ip")
    }

    fn flow(src_ip: &str, dst_ip: &str, dst_port: u16) -> FlowRecord {
        let mut flow = FlowRecord::new(
            ip(src_ip),
            49_152,
            ip(dst_ip),
            dst_port,
            TransportProtocol::Tcp,
            NetworkDirection::Outbound,
        );
        flow.start_time = Timestamp::now();
        flow
    }

    fn udp_flow(src_ip: &str, dst_ip: &str, dst_port: u16) -> FlowRecord {
        let mut flow = FlowRecord::new(
            ip(src_ip),
            49_152,
            ip(dst_ip),
            dst_port,
            TransportProtocol::Udp,
            NetworkDirection::Outbound,
        );
        flow.start_time = Timestamp::now();
        flow
    }

    fn session(local_ip: &str, remote_ip: &str, remote_port: u16) -> SessionRecord {
        let mut session = SessionRecord::new(
            ip(local_ip),
            49_152,
            ip(remote_ip),
            remote_port,
            TransportProtocol::Tcp,
            NetworkDirection::Outbound,
        );
        session.start_time = Timestamp::now();
        session
    }

    fn tls(flow: &FlowRecord, alpn: &[&str]) -> TlsObservation {
        let mut observation = TlsObservation::new();
        observation.flow_ref = Some(flow.flow_id.clone());
        observation.timestamp = flow.start_time.clone();
        observation.alpn = alpn.iter().map(|value| (*value).to_string()).collect();
        observation.quality_score = quality(0.74).expect("quality");
        observation
    }

    fn dns(
        name: &str,
        response_code: &str,
        entropy: f32,
        depth: u16,
        answer_ips: &[&str],
    ) -> DnsObservation {
        let mut observation =
            DnsObservation::new(name, "A", ip("203.0.113.53"), ip("192.0.2.10")).expect("dns");
        observation.response_code = Some(response_code.to_string());
        observation.features = DnsFeatures {
            query_length: name.len() as u16,
            label_count: (depth + 2).max(2),
            subdomain_depth: depth,
            character_entropy: Some(entropy),
            answer_count: answer_ips.len() as u16,
        };
        observation.answers = answer_ips
            .iter()
            .map(|value| DnsAnswer::Ip {
                address: ip(value),
                ttl_seconds: Some(60),
            })
            .collect();
        observation.quality_score = quality(0.8).expect("quality");
        observation
    }

    fn http(
        flow: &FlowRecord,
        host: &str,
        path: &str,
        method: HttpMethod,
        status_code: u16,
    ) -> HttpMetadata {
        let mut metadata = HttpMetadata::new(method);
        metadata.flow_ref = Some(flow.flow_id.clone());
        metadata.timestamp = Timestamp::now();
        metadata.host_protected = Some(host.to_string());
        metadata.path_template_protected = Some(path.to_string());
        metadata.endpoint_fingerprint = Some(format!("endpoint-{}-{path}", host));
        metadata.status_code = Some(status_code);
        metadata.status_family = Some(format!("{}xx", status_code / 100));
        metadata.visible_plaintext = true;
        metadata.quality_score = quality(0.75).expect("quality");
        metadata
    }

    fn saas_cloud(
        provider_category: PortableProviderCategory,
        endpoint_fingerprint: &str,
        method: PortableApiMethodCategory,
        status_bucket: PortableStatusBucket,
        ratio_bucket: PortableUploadDownloadRatioBucket,
    ) -> PortableSaasCloudMetadata {
        let mut metadata = PortableSaasCloudMetadata::new(provider_category, Timestamp::now());
        metadata.provider_confidence = PortableProviderConfidenceBucket::High;
        metadata.provider_risk_category = PortableProviderRiskCategory::Low;
        metadata.endpoint_fingerprint = Some(endpoint_fingerprint.to_string());
        metadata.api_method_category = method;
        metadata.status_bucket = status_bucket;
        metadata.upload_download_ratio_bucket = ratio_bucket;
        metadata.redaction_status = RedactionStatus::Redacted;
        metadata.quality_score = quality(0.74).expect("quality");
        metadata
    }

    fn deception_event(
        sensor_ref: &str,
        event_category: &str,
        source_context: &str,
        protocol: PortableDeceptionProtocolCategory,
        bucket: PortableDecoyInteractionCountBucket,
    ) -> PortableDeceptionEventMetadata {
        let mut metadata =
            PortableDeceptionEventMetadata::new(event_category, protocol, Timestamp::now());
        metadata.decoy_sensor_ref = Some(sensor_ref.to_string());
        metadata.source_context_category = Some(source_context.to_string());
        metadata.destination_service_category = Some("admin_service".to_string());
        metadata.interaction_count_bucket = bucket;
        metadata.quality_score = quality(0.74).expect("quality");
        metadata
    }

    #[test]
    fn dns_security_v2_emits_entropy_burst_and_fast_flux_findings() {
        let plugin_id = PluginId::new_v4();
        let observations = vec![
            dns("domain#a", "NXDOMAIN", 4.2, 5, &[]),
            dns("domain#b", "NXDOMAIN", 4.1, 4, &[]),
            dns("domain#c", "NXDOMAIN", 4.0, 4, &[]),
            dns(
                "domain#flux",
                "NOERROR",
                3.7,
                3,
                &["198.51.100.10", "198.51.100.11", "198.51.100.12"],
            ),
        ];

        let output = PortableDnsSecurityV2Plugin
            .analyze(&plugin_id, &observations)
            .expect("dns output");

        assert!(!output.findings.is_empty());
        assert_eq!(output.findings.len(), output.evidence.len());
        assert_eq!(output.findings.len(), output.risk_hints.len());
        assert_eq!(output.findings.len(), output.graph_hints.len());
    }

    #[test]
    fn http_and_api_security_emit_bounded_findings() {
        let plugin_id = PluginId::new_v4();
        let flow = flow("192.0.2.20", "203.0.113.20", 443);
        let mut http_items = Vec::new();
        for index in 0..5 {
            let mut metadata = http(
                &flow,
                "host#api",
                &format!("/v1/items/{index}"),
                HttpMethod::Get,
                if index < 3 { 404 } else { 200 },
            );
            metadata.user_agent_family = Some("curl".to_string());
            http_items.push(metadata);
        }
        let mut upload = http(&flow, "host#api", "/v1/upload/{id}", HttpMethod::Post, 201);
        upload.upload_download_ratio = Some(12.0);
        upload.request_size_bytes = Some(16_384);
        upload.user_agent_family = Some("python_requests".to_string());
        http_items.push(upload);

        let http_output = PortableHttpAnalysisV1Plugin
            .analyze(
                &plugin_id,
                PortableHttpAnalysisInput {
                    flow_records: std::slice::from_ref(&flow),
                    session_records: &[],
                    http_metadata: &http_items,
                },
            )
            .expect("http output");
        let api_output = PortableApiSecurityLitePlugin
            .analyze(
                &plugin_id,
                PortableApiSecurityLiteInput {
                    flow_records: std::slice::from_ref(&flow),
                    http_metadata: &http_items,
                },
            )
            .expect("api output");

        assert!(!http_output.findings.is_empty());
        assert!(!api_output.findings.is_empty());
    }

    #[test]
    fn waf_security_emits_block_and_bypass_findings() {
        let plugin_id = PluginId::new_v4();
        let flow = flow("192.0.2.44", "203.0.113.44", 443);
        let mut blocked_one = http(&flow, "host#waf", "/v1/login/{id}", HttpMethod::Post, 403);
        blocked_one.waf_action = Some("blocked".to_string());
        blocked_one.waf_rule_id = Some("rule_942100".to_string());
        blocked_one.waf_attack_class = Some("sql_injection".to_string());

        let mut blocked_two = blocked_one.clone();
        blocked_two.timestamp = Timestamp::now();

        let mut allowed = http(&flow, "host#waf", "/v1/login/{id}", HttpMethod::Post, 200);
        allowed.waf_action = Some("allowed".to_string());

        let output = PortableWafSecurityLitePlugin
            .analyze(
                &plugin_id,
                PortableWafSecurityLiteInput {
                    flow_records: &[flow],
                    http_metadata: &[blocked_one, blocked_two, allowed],
                },
            )
            .expect("waf output");

        assert!(!output.findings.is_empty());
        assert!(output
            .findings
            .iter()
            .any(|finding| finding.finding_type().contains("waf_security_lite")));
    }

    #[test]
    fn benign_http_batch_returns_no_signals() {
        let plugin_id = PluginId::new_v4();
        let flow = flow("192.0.2.55", "203.0.113.55", 443);
        let benign = http(&flow, "host#benign", "/v1/health", HttpMethod::Get, 200);

        assert_eq!(
            PortableHttpAnalysisV1Plugin.analyze(
                &plugin_id,
                PortableHttpAnalysisInput {
                    flow_records: &[flow],
                    session_records: &[],
                    http_metadata: &[benign],
                },
            ),
            Err(PortableNetworkWebAnalysisError::NoSignals)
        );
    }

    #[test]
    fn quic_http3_lite_emits_findings_with_allowlisted_attack_mappings() {
        let plugin_id = PluginId::new_v4();
        let h3_flow = udp_flow("192.0.2.60", "203.0.113.60", 443);
        let fallback_flow = flow("192.0.2.60", "203.0.113.60", 443);
        let tls_observations = vec![tls(&h3_flow, &["h3"])];
        let mut http_items = Vec::new();
        for _ in 0..3 {
            let mut metadata = http(
                &h3_flow,
                "cdn-host#quic-api",
                "/v1/sync/{id}",
                HttpMethod::Post,
                503,
            );
            metadata.api_hint = Some("api".to_string());
            http_items.push(metadata);
        }
        let fallback_http = http(
            &fallback_flow,
            "cdn-host#quic-api",
            "/v1/sync/{id}",
            HttpMethod::Post,
            200,
        );
        http_items.push(fallback_http);

        let output = PortableQuicHttp3SecurityLitePlugin
            .analyze(
                &plugin_id,
                PortableQuicHttp3SecurityLiteInput {
                    flow_records: &[h3_flow, fallback_flow],
                    tls_observations: &tls_observations,
                    http_metadata: &http_items,
                },
            )
            .expect("quic/http3 output");

        assert!(output.findings.iter().any(|finding| {
            finding
                .finding_type()
                .contains("quic_http3_security_lite.protocol_downgrade_fallback_pattern")
        }));
        assert!(output.findings.iter().all(|finding| {
            finding.attack_mappings().iter().all(|mapping| {
                mapping.subtechnique_id.as_deref() == Some("T1071.001")
                    && mapping.mapping_confidence.value() < finding.confidence().value()
            })
        }));
    }

    #[test]
    fn remote_admin_lite_emits_spread_and_first_seen_findings() {
        let plugin_id = PluginId::new_v4();
        let sessions = vec![
            session("192.168.1.10", "192.168.1.21", 3389),
            session("192.168.1.10", "192.168.1.22", 3389),
            session("192.168.1.10", "192.168.1.23", 3389),
            session("192.168.1.30", "192.168.1.40", 22),
        ];

        let output = PortableRemoteAdminObservationLitePlugin
            .analyze(
                &plugin_id,
                PortableRemoteAdminObservationLiteInput {
                    flow_records: &[],
                    session_records: &sessions,
                },
            )
            .expect("remote admin output");

        assert!(output
            .findings
            .iter()
            .any(|finding| finding.finding_type().contains("rdp_spread_pattern")));
        assert!(output
            .findings
            .iter()
            .any(|finding| finding.finding_type().contains("ssh_first_seen_use")));
        assert!(output.findings.iter().any(|finding| {
            finding.attack_mappings().iter().any(|mapping| {
                mapping.subtechnique_id.as_deref() == Some("T1021.001")
                    || mapping.subtechnique_id.as_deref() == Some("T1021.004")
            })
        }));
    }

    #[test]
    fn auth_identity_lite_emits_failure_mfa_and_remote_admin_findings() {
        let plugin_id = PluginId::new_v4();
        let sessions = vec![session("192.168.1.50", "192.168.1.60", 22)];
        let mut auth_metadata = Vec::new();
        for index in 0..3 {
            let mut item = PortableAuthMetadata::new(
                "vpn",
                PortableAuthResultCategory::Failure,
                Timestamp::from_datetime(
                    Timestamp::now().as_datetime().to_owned()
                        + chrono::Duration::minutes((index as i64) * 5),
                ),
            );
            item.identity_label_redacted = Some("identity#abc".to_string());
            item.source_session_label = Some("session#abc".to_string());
            item.destination_service_category = Some("ssh".to_string());
            item.mfa_result = Some(if index == 0 {
                PortableMfaResultCategory::Prompted
            } else {
                PortableMfaResultCategory::Failed
            });
            item.failure_reason_category = Some("invalid_password".to_string());
            auth_metadata.push(item);
        }

        let mut privileged =
            PortableAuthMetadata::new("idp", PortableAuthResultCategory::Success, Timestamp::now());
        privileged.identity_label_redacted = Some("identity#priv".to_string());
        privileged.role_privilege_class = Some("privileged".to_string());
        privileged.destination_service_category = Some("admin_portal".to_string());
        auth_metadata.push(privileged);

        let output = PortableAuthIdentityAnalysisLitePlugin
            .analyze(
                &plugin_id,
                PortableAuthIdentityAnalysisLiteInput {
                    flow_records: &[],
                    session_records: &sessions,
                    auth_metadata: &auth_metadata,
                },
            )
            .expect("auth output");

        assert!(output
            .findings
            .iter()
            .any(|finding| finding.finding_type().contains("auth_failure_burst")));
        assert!(output
            .findings
            .iter()
            .any(|finding| finding.finding_type().contains("mfa_fatigue_like_pattern")));
        assert!(output.findings.iter().any(|finding| {
            finding
                .finding_type()
                .contains("remote_admin_auth_failure_correlation")
        }));
        assert!(output
            .findings
            .iter()
            .any(|finding| finding.finding_type().contains("privileged_role_access")));
        assert!(output.findings.iter().any(|finding| {
            finding.attack_mappings().iter().any(|mapping| {
                matches!(
                    mapping.technique_id.as_deref(),
                    Some("T1110") | Some("T1621")
                )
            })
        }));
    }

    #[test]
    fn benign_auth_batch_returns_no_signals() {
        let plugin_id = PluginId::new_v4();
        let mut auth =
            PortableAuthMetadata::new("idp", PortableAuthResultCategory::Success, Timestamp::now());
        auth.identity_label_redacted = Some("identity#benign".to_string());
        auth.destination_service_category = Some("sso".to_string());

        assert_eq!(
            PortableAuthIdentityAnalysisLitePlugin.analyze(
                &plugin_id,
                PortableAuthIdentityAnalysisLiteInput {
                    flow_records: &[],
                    session_records: &[],
                    auth_metadata: &[auth],
                },
            ),
            Err(PortableNetworkWebAnalysisError::NoSignals)
        );
    }

    #[test]
    fn saas_cloud_abuse_lite_emits_evidence_risk_and_graph_backed_findings() {
        let plugin_id = PluginId::new_v4();
        let mut object_upload_one = saas_cloud(
            PortableProviderCategory::ObjectStorage,
            "endpoint#object-storage",
            PortableApiMethodCategory::Write,
            PortableStatusBucket::Success,
            PortableUploadDownloadRatioBucket::UploadBurst,
        );
        object_upload_one.service_category = Some("object_storage".to_string());

        let mut object_upload_two = object_upload_one.clone();
        object_upload_two.saas_cloud_metadata_id =
            sentinel_contracts::SaasCloudMetadataId::new_v4();

        let cloud_errors = (0..3)
            .map(|_| {
                saas_cloud(
                    PortableProviderCategory::Cloud,
                    "endpoint#admin-api",
                    PortableApiMethodCategory::Write,
                    PortableStatusBucket::ServerError,
                    PortableUploadDownloadRatioBucket::Balanced,
                )
            })
            .collect::<Vec<_>>();

        let mut possible_token_misuse = saas_cloud(
            PortableProviderCategory::Saas,
            "endpoint#saas-sync",
            PortableApiMethodCategory::Write,
            PortableStatusBucket::Success,
            PortableUploadDownloadRatioBucket::UploadHeavy,
        );
        possible_token_misuse.identity_label_redacted = Some("identity#shared".to_string());
        possible_token_misuse.source_session_label = Some("session#shared".to_string());
        possible_token_misuse.auth_result_category = Some("success".to_string());

        let mut risky_provider_one = saas_cloud(
            PortableProviderCategory::TunnelProxy,
            "endpoint#tunnel",
            PortableApiMethodCategory::Read,
            PortableStatusBucket::Success,
            PortableUploadDownloadRatioBucket::Balanced,
        );
        risky_provider_one.provider_risk_category = PortableProviderRiskCategory::High;
        let mut risky_provider_two = risky_provider_one.clone();
        risky_provider_two.saas_cloud_metadata_id =
            sentinel_contracts::SaasCloudMetadataId::new_v4();

        let mut auth_failure =
            PortableAuthMetadata::new("idp", PortableAuthResultCategory::Failure, Timestamp::now());
        auth_failure.identity_label_redacted = Some("identity#shared".to_string());
        auth_failure.source_session_label = Some("session#shared".to_string());

        let flow = flow("192.0.2.70", "203.0.113.70", 443);
        let http_errors = vec![
            http(&flow, "host#cloud", "/api/{id}", HttpMethod::Post, 500),
            http(&flow, "host#cloud", "/api/{id}", HttpMethod::Post, 403),
        ];

        let related_finding = Finding::new(
            "portable.api_security_lite.method_probing",
            plugin_id.clone(),
            vec![EvidenceId::new_v4()],
            FindingExplanation::new("bounded API metadata finding").expect("explanation"),
        )
        .expect("related finding");

        let mut metadata = vec![
            object_upload_one,
            object_upload_two,
            possible_token_misuse,
            risky_provider_one,
            risky_provider_two,
        ];
        metadata.extend(cloud_errors);

        let output = PortableSaasCloudAbuseLitePlugin
            .analyze(
                &plugin_id,
                PortableSaasCloudAbuseLiteInput {
                    saas_cloud_metadata: &metadata,
                    auth_metadata: &[auth_failure],
                    http_metadata: &http_errors,
                    related_findings: &[related_finding],
                },
            )
            .expect("saas cloud output");

        assert_eq!(output.findings.len(), output.evidence.len());
        assert_eq!(output.findings.len(), output.risk_hints.len());
        assert_eq!(output.findings.len(), output.graph_hints.len());
        for finding in &output.findings {
            assert!(!finding.evidence_refs().is_empty());
            assert!(finding
                .attack_mappings()
                .iter()
                .all(|mapping| mapping.mapping_confidence.value() <= finding.confidence().value()));
        }
        assert!(output.findings.iter().any(|finding| finding
            .finding_type()
            .contains("suspicious_object_storage_upload")));
        assert!(output.findings.iter().any(|finding| finding
            .finding_type()
            .contains("unusual_saas_api_error_burst")));
        assert!(output.findings.iter().any(|finding| finding
            .finding_type()
            .contains("api_waf_to_cloud_activity_correlation")));
        assert!(output.findings.iter().any(|finding| finding
            .finding_type()
            .contains("possible_token_misuse_pattern")));
        assert!(output.findings.iter().any(|finding| {
            finding.attack_mappings().iter().any(|mapping| {
                mapping.subtechnique_id.as_deref() == Some("T1567.002")
                    || mapping.technique_id.as_deref() == Some("T1078")
            })
        }));
    }

    #[test]
    fn saas_cloud_abuse_lite_degrades_unknown_provider_confidence() {
        let plugin_id = PluginId::new_v4();
        let mut first = saas_cloud(
            PortableProviderCategory::Unknown,
            "endpoint#unknown-write",
            PortableApiMethodCategory::Write,
            PortableStatusBucket::ServerError,
            PortableUploadDownloadRatioBucket::Balanced,
        );
        first.provider_confidence = PortableProviderConfidenceBucket::Unknown;
        let mut second = first.clone();
        second.saas_cloud_metadata_id = sentinel_contracts::SaasCloudMetadataId::new_v4();

        let output = PortableSaasCloudAbuseLitePlugin
            .analyze(
                &plugin_id,
                PortableSaasCloudAbuseLiteInput {
                    saas_cloud_metadata: &[first, second],
                    auth_metadata: &[],
                    http_metadata: &[],
                    related_findings: &[],
                },
            )
            .expect("unknown provider signal");

        assert!(output
            .findings
            .iter()
            .all(|finding| finding.confidence().value() <= 0.4));
    }

    #[test]
    fn benign_saas_cloud_batch_returns_no_signals() {
        let plugin_id = PluginId::new_v4();
        let benign = saas_cloud(
            PortableProviderCategory::Saas,
            "endpoint#health",
            PortableApiMethodCategory::Read,
            PortableStatusBucket::Success,
            PortableUploadDownloadRatioBucket::Balanced,
        );

        assert_eq!(
            PortableSaasCloudAbuseLitePlugin.analyze(
                &plugin_id,
                PortableSaasCloudAbuseLiteInput {
                    saas_cloud_metadata: &[benign],
                    auth_metadata: &[],
                    http_metadata: &[],
                    related_findings: &[],
                },
            ),
            Err(PortableNetworkWebAnalysisError::NoSignals)
        );
    }

    #[test]
    fn deception_event_lite_emits_evidence_risk_graph_and_degraded_attack_mapping() {
        let plugin_id = PluginId::new_v4();
        let events = vec![
            deception_event(
                "sensor#edge-a",
                "probe",
                "external",
                PortableDeceptionProtocolCategory::Ssh,
                PortableDecoyInteractionCountBucket::High,
            ),
            deception_event(
                "sensor#edge-a",
                "probe",
                "external",
                PortableDeceptionProtocolCategory::Telnet,
                PortableDecoyInteractionCountBucket::Single,
            ),
            deception_event(
                "sensor#edge-a",
                "scan",
                "external",
                PortableDeceptionProtocolCategory::Http,
                PortableDecoyInteractionCountBucket::Low,
            ),
        ];
        let related_finding = Finding::new(
            "portable.api_security_lite.method_probing",
            plugin_id.clone(),
            vec![EvidenceId::new_v4()],
            FindingExplanation::new("bounded API metadata finding").expect("explanation"),
        )
        .expect("related finding");
        let related_risk = RiskHint::new(
            "portable_prior_risk_hint",
            "bounded prior risk hint",
            vec![IntelligenceRecordId::new_v4()],
        )
        .expect("related risk");

        let output = PortableDeceptionEventLitePlugin
            .analyze(
                &plugin_id,
                PortableDeceptionEventLiteInput {
                    deception_events: &events,
                    related_findings: &[related_finding],
                    related_risk_hints: &[related_risk],
                },
            )
            .expect("deception output");

        assert_eq!(output.findings.len(), output.evidence.len());
        assert_eq!(output.findings.len(), output.risk_hints.len());
        assert_eq!(output.findings.len(), output.graph_hints.len());
        for finding in &output.findings {
            assert!(!finding.evidence_refs().is_empty());
            assert!(finding.attack_mappings().iter().all(|mapping| {
                mapping.technique_id.as_deref() == Some("T1046")
                    && mapping.mapping_confidence.value() < finding.confidence().value()
            }));
        }
        assert!(output.findings.iter().any(|finding| finding
            .finding_type()
            .contains("repeated_decoy_interaction")));
        assert!(output.findings.iter().any(|finding| finding
            .finding_type()
            .contains("unusual_protocol_interaction")));
        assert!(output.findings.iter().any(|finding| finding
            .finding_type()
            .contains("correlated_suspicious_activity")));
        assert!(output
            .findings
            .iter()
            .any(|finding| finding.finding_type().contains("risk_chain_correlation")));
    }

    #[test]
    fn deception_event_lite_correlation_requires_supporting_evidence() {
        let plugin_id = PluginId::new_v4();
        let events = vec![
            deception_event(
                "sensor#edge-b",
                "probe",
                "external",
                PortableDeceptionProtocolCategory::Http,
                PortableDecoyInteractionCountBucket::Low,
            ),
            deception_event(
                "sensor#edge-b",
                "probe",
                "external",
                PortableDeceptionProtocolCategory::Http,
                PortableDecoyInteractionCountBucket::Low,
            ),
            deception_event(
                "sensor#edge-b",
                "probe",
                "external",
                PortableDeceptionProtocolCategory::Http,
                PortableDecoyInteractionCountBucket::Low,
            ),
        ];

        let output = PortableDeceptionEventLitePlugin
            .analyze(
                &plugin_id,
                PortableDeceptionEventLiteInput {
                    deception_events: &events,
                    related_findings: &[],
                    related_risk_hints: &[],
                },
            )
            .expect("deception output");

        assert!(output.findings.iter().any(|finding| finding
            .finding_type()
            .contains("repeated_decoy_interaction")));
        assert!(!output.findings.iter().any(|finding| finding
            .finding_type()
            .contains("correlated_suspicious_activity")));
        assert!(!output
            .findings
            .iter()
            .any(|finding| finding.finding_type().contains("risk_chain_correlation")));
    }

    #[test]
    fn benign_deception_event_batch_returns_no_signals() {
        let plugin_id = PluginId::new_v4();
        let benign = deception_event(
            "sensor#benign",
            "health_check",
            "internal",
            PortableDeceptionProtocolCategory::Http,
            PortableDecoyInteractionCountBucket::Single,
        );

        assert_eq!(
            PortableDeceptionEventLitePlugin.analyze(
                &plugin_id,
                PortableDeceptionEventLiteInput {
                    deception_events: &[benign],
                    related_findings: &[],
                    related_risk_hints: &[],
                },
            ),
            Err(PortableNetworkWebAnalysisError::NoSignals)
        );
    }
}
