use crate::network_observations::{
    DnsMetadataInput, DnsSecurityObservationPlugin, HttpMetadataExtractor, HttpMetadataInput,
    NetworkObservationError, TlsFingerprintPlugin, TlsMetadataInput,
};
use crate::risk_alerting::{ALERT_CANDIDATE_CONTRACT, INCIDENT_CANDIDATE_CONTRACT};
use crate::static_plugin_runtime::{
    register_static_api_security_lite_plugin, register_static_auth_identity_analysis_lite_plugin,
    register_static_deception_event_lite_plugin, register_static_dns_security_v2_plugin,
    register_static_exfiltration_detection_plugin, register_static_http_analysis_v1_plugin,
    register_static_multi_layer_security_fusion_plugin,
    register_static_portable_saas_cloud_abuse_lite_plugin,
    register_static_quic_http3_security_lite_plugin,
    register_static_remote_admin_protocol_lite_plugin, register_static_risk_alerting_plugin,
    register_static_waf_security_lite_plugin,
};
use chrono::{DateTime, Duration, Utc};
use sentinel_contracts::{
    Alert, AttackHypothesisRecord, ContractDescriptor, DataSourceId, DnsAnswer, DnsObservation,
    EventEnvelope, EventType, EvidenceItem, Finding, FlowRecord, FusionSummary, GraphHint,
    HttpMetadata, HttpMethod, Incident, IpAddress, NetworkDirection, PluginId,
    PortableApiMethodCategory, PortableAuthAttemptCountBucket, PortableAuthCategoryCount,
    PortableAuthMetadata, PortableAuthResultCategory, PortableAuthRiskBucket,
    PortableAuthServiceOutcomeCount, PortableAuthSummary, PortableCaptureInputSourceType,
    PortableCaptureProvenance, PortableCaptureRecordCounts, PortableDeceptionCategoryCount,
    PortableDeceptionEventMetadata, PortableDeceptionProtocolCategory, PortableDeceptionSummary,
    PortableDecoyInteractionCountBucket, PortableMfaResultCategory, PortableProviderCategory,
    PortableProviderConfidenceBucket, PortableProviderRiskCategory, PortableSaasCloudCategoryCount,
    PortableSaasCloudMetadata, PortableSaasCloudSummary, PortableStatusBucket,
    PortableUploadDownloadRatioBucket, PrivacyClass, QualityScore, RedactionStatus, RiskEvent,
    SchemaVersion, SecurityFact, ServiceAdapterMode, ServiceCapabilityContext,
    ServiceCapabilityStatus, ServiceLimitationFlag, ServiceReasonCode, SessionRecord, Timestamp,
    TlsObservation, TraceContext, TraceId, TransportProtocol,
};
use sentinel_platform::{
    ContractRegistry, EventBus, EventBusError, PermissionResolver, PipelineDag, PipelineDagError,
    PipelineNode, PipelineStage, PluginContext, PluginEventBatch, PluginRuntime, PriorityLane,
    PublishOptions, ReplayContext, ReplayScope, Scheduler, SchedulerKind, StageBinding, Topic,
    TopicLayer, TopicName, CLOUD_SAAS_METADATA, DECEPTION_EVENT_METADATA, GRAPH_HINT,
    IDENTITY_AUTH_METADATA, NETWORK_DNS_OBSERVATION, NETWORK_FLOW_RECORD, NETWORK_HTTP_METADATA,
    NETWORK_SESSION_RECORD, NETWORK_TLS_OBSERVATION, SECURITY_ALERT, SECURITY_EVIDENCE,
    SECURITY_FACT, SECURITY_FINDING, SECURITY_FUSION_CONTEXT, SECURITY_FUSION_SUMMARY,
    SECURITY_HYPOTHESIS, SECURITY_INCIDENT, SECURITY_RISK, SERVICE_CAPABILITY_STATUS,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

pub const PORTABLE_CAPTURE_LITE_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MAX_PORTABLE_CAPTURE_IMPORT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PORTABLE_CAPTURE_RECORDS: usize = 128;
const SYNTHETIC_LOCAL_IP_OCTET_BASE: u8 = 10;
const SYNTHETIC_REMOTE_IP_OCTET_BASE: u8 = 20;

#[derive(Clone, Debug, PartialEq)]
pub struct PortableCaptureLitePreparedBatch {
    pub provenance: PortableCaptureProvenance,
    pub flow_records: Vec<FlowRecord>,
    pub session_records: Vec<SessionRecord>,
    pub dns_observations: Vec<DnsObservation>,
    pub tls_observations: Vec<TlsObservation>,
    pub http_metadata: Vec<HttpMetadata>,
    pub auth_metadata: Vec<PortableAuthMetadata>,
    pub saas_cloud_metadata: Vec<PortableSaasCloudMetadata>,
    pub deception_events: Vec<PortableDeceptionEventMetadata>,
    pub declared_topics: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PortableCaptureLiteRunResult {
    pub provenance: PortableCaptureProvenance,
    pub trace_id: TraceId,
    pub scheduler_kind: SchedulerKind,
    pub emitted_topics: Vec<String>,
    pub flow_records: Vec<FlowRecord>,
    pub session_records: Vec<SessionRecord>,
    pub dns_observations: Vec<DnsObservation>,
    pub tls_observations: Vec<TlsObservation>,
    pub http_metadata: Vec<HttpMetadata>,
    pub auth_metadata: Vec<PortableAuthMetadata>,
    pub auth_summary: Option<PortableAuthSummary>,
    pub saas_cloud_metadata: Vec<PortableSaasCloudMetadata>,
    pub saas_cloud_summary: Option<PortableSaasCloudSummary>,
    pub deception_events: Vec<PortableDeceptionEventMetadata>,
    pub deception_summary: Option<PortableDeceptionSummary>,
    pub service_capability_contexts: Vec<ServiceCapabilityContext>,
    pub security_facts: Vec<SecurityFact>,
    pub attack_hypotheses: Vec<AttackHypothesisRecord>,
    pub fusion_summary: Option<FusionSummary>,
    pub findings: Vec<Finding>,
    pub evidence: Vec<EvidenceItem>,
    pub graph_hints: Vec<GraphHint>,
    pub risk_events: Vec<RiskEvent>,
    pub alert_candidate_count: usize,
    pub alerts: Vec<Alert>,
    pub incident_candidate_count: usize,
    pub incidents: Vec<Incident>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableCaptureLiteError {
    OversizedFile,
    UnsupportedSourceType,
    TooManyRecords,
    EmptyInput,
    Malformed(&'static str),
    Parse(String),
    Contract(String),
    Runtime(String),
}

impl fmt::Display for PortableCaptureLiteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OversizedFile => write!(
                f,
                "portable capture import exceeds the bounded metadata size limit"
            ),
            Self::UnsupportedSourceType => {
                write!(f, "portable capture import source type is unsupported")
            }
            Self::TooManyRecords => {
                write!(
                    f,
                    "portable capture import exceeds the bounded record limit"
                )
            }
            Self::EmptyInput => write!(f, "portable capture import input must not be empty"),
            Self::Malformed(kind) => write!(f, "portable capture import {kind} is malformed"),
            Self::Parse(reason) => write!(f, "portable capture import parse error: {reason}"),
            Self::Contract(reason) => write!(f, "portable capture import contract error: {reason}"),
            Self::Runtime(reason) => write!(f, "portable capture import runtime error: {reason}"),
        }
    }
}

impl std::error::Error for PortableCaptureLiteError {}

impl From<serde_json::Error> for PortableCaptureLiteError {
    fn from(value: serde_json::Error) -> Self {
        Self::Parse(value.to_string())
    }
}

impl From<chrono::ParseError> for PortableCaptureLiteError {
    fn from(value: chrono::ParseError) -> Self {
        Self::Parse(value.to_string())
    }
}

impl From<NetworkObservationError> for PortableCaptureLiteError {
    fn from(value: NetworkObservationError) -> Self {
        Self::Contract(value.to_string())
    }
}

impl From<EventBusError> for PortableCaptureLiteError {
    fn from(value: EventBusError) -> Self {
        Self::Runtime(value.to_string())
    }
}

impl From<PipelineDagError> for PortableCaptureLiteError {
    fn from(value: PipelineDagError) -> Self {
        Self::Runtime(value.to_string())
    }
}

impl From<sentinel_platform::PluginRuntimeError> for PortableCaptureLiteError {
    fn from(value: sentinel_platform::PluginRuntimeError) -> Self {
        Self::Runtime(value.to_string())
    }
}

pub fn preview_portable_capture_import(
    source_type: PortableCaptureInputSourceType,
    content: &str,
    file_size_bytes: usize,
) -> Result<PortableCaptureLitePreparedBatch, PortableCaptureLiteError> {
    if file_size_bytes > MAX_PORTABLE_CAPTURE_IMPORT_BYTES {
        return Err(PortableCaptureLiteError::OversizedFile);
    }
    if content.trim().is_empty() {
        return Err(PortableCaptureLiteError::EmptyInput);
    }

    let parsed = match source_type {
        PortableCaptureInputSourceType::ImportedHar => parse_har(content)?,
        PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata => parse_jsonl(content)?,
        PortableCaptureInputSourceType::ImportedWebAccessLog => parse_web_access_log(content)?,
        PortableCaptureInputSourceType::ImportedAuthSecurityLog => {
            parse_auth_security_log(content)?
        }
        PortableCaptureInputSourceType::ImportedSaasCloudMetadata => {
            parse_saas_cloud_metadata_log(content)?
        }
        PortableCaptureInputSourceType::ImportedDeceptionEventLog => {
            parse_deception_event_log(content)?
        }
        PortableCaptureInputSourceType::LocalProxyMetadata => {
            return Err(PortableCaptureLiteError::UnsupportedSourceType)
        }
    };

    build_portable_capture_prepared_batch(source_type, parsed)
}

pub(crate) fn build_portable_capture_prepared_batch(
    source_type: PortableCaptureInputSourceType,
    mut parsed: ParsedPortableCaptureInput,
) -> Result<PortableCaptureLitePreparedBatch, PortableCaptureLiteError> {
    if (!parsed.flow_records.is_empty() && parsed.session_records.is_empty())
        || (parsed.flow_records.is_empty() && !parsed.session_records.is_empty())
    {
        return Err(PortableCaptureLiteError::Malformed("metadata"));
    }
    if parsed.flow_records.is_empty()
        && parsed.session_records.is_empty()
        && parsed.dns_observations.is_empty()
        && parsed.tls_observations.is_empty()
        && parsed.http_metadata.is_empty()
        && parsed.auth_metadata.is_empty()
        && parsed.saas_cloud_metadata.is_empty()
        && parsed.deception_events.is_empty()
    {
        return Err(PortableCaptureLiteError::Malformed("metadata"));
    }
    if parsed.flow_records.len() > MAX_PORTABLE_CAPTURE_RECORDS
        || parsed.session_records.len() > MAX_PORTABLE_CAPTURE_RECORDS
        || parsed.dns_observations.len() > MAX_PORTABLE_CAPTURE_RECORDS
        || parsed.tls_observations.len() > MAX_PORTABLE_CAPTURE_RECORDS
        || parsed.http_metadata.len() > MAX_PORTABLE_CAPTURE_RECORDS
        || parsed.auth_metadata.len() > MAX_PORTABLE_CAPTURE_RECORDS
        || parsed.saas_cloud_metadata.len() > MAX_PORTABLE_CAPTURE_RECORDS
        || parsed.deception_events.len() > MAX_PORTABLE_CAPTURE_RECORDS
    {
        return Err(PortableCaptureLiteError::TooManyRecords);
    }

    let topic_flags = DeclaredTopicFlags {
        has_flow: !parsed.flow_records.is_empty(),
        has_session: !parsed.session_records.is_empty(),
        has_dns: !parsed.dns_observations.is_empty(),
        has_tls: !parsed.tls_observations.is_empty(),
        has_http: !parsed.http_metadata.is_empty(),
        has_auth: !parsed.auth_metadata.is_empty(),
        has_saas_cloud: !parsed.saas_cloud_metadata.is_empty(),
        has_deception: !parsed.deception_events.is_empty(),
    };
    let record_counts = PortableCaptureRecordCounts {
        flow_records: parsed.flow_records.len() as u32,
        session_records: parsed.session_records.len() as u32,
        dns_records: parsed.dns_observations.len() as u32,
        tls_records: parsed.tls_observations.len() as u32,
        http_metadata_records: parsed.http_metadata.len() as u32,
        auth_metadata_records: parsed.auth_metadata.len() as u32,
        saas_cloud_metadata_records: parsed.saas_cloud_metadata.len() as u32,
        deception_event_records: parsed.deception_events.len() as u32,
    };
    let provenance =
        PortableCaptureProvenance::new(source_type, record_counts, parsed.redaction_status);
    for item in &mut parsed.auth_metadata {
        item.provenance_id = provenance.provenance_id.clone();
    }
    for item in &mut parsed.saas_cloud_metadata {
        item.provenance_id = provenance.provenance_id.clone();
    }
    for item in &mut parsed.deception_events {
        item.provenance_id = provenance.provenance_id.clone();
    }

    Ok(PortableCaptureLitePreparedBatch {
        provenance,
        flow_records: parsed.flow_records,
        session_records: parsed.session_records,
        dns_observations: parsed.dns_observations,
        tls_observations: parsed.tls_observations,
        http_metadata: parsed.http_metadata,
        auth_metadata: parsed.auth_metadata,
        saas_cloud_metadata: parsed.saas_cloud_metadata,
        deception_events: parsed.deception_events,
        declared_topics: declared_topics(topic_flags),
    })
}

pub fn run_portable_capture_lite(
    prepared: &PortableCaptureLitePreparedBatch,
) -> Result<PortableCaptureLiteRunResult, PortableCaptureLiteError> {
    run_portable_capture_lite_with_service_contexts(prepared, &[])
}

pub fn run_portable_capture_lite_with_service_contexts(
    prepared: &PortableCaptureLitePreparedBatch,
    runtime_service_contexts: &[ServiceCapabilityContext],
) -> Result<PortableCaptureLiteRunResult, PortableCaptureLiteError> {
    let scheduler = Scheduler::new(SchedulerKind::Realtime);
    let execution_plan = portable_capture_lite_dag()?.build_execution_plan()?;
    let replay_context = ReplayContext::new(
        ReplayScope::Pipeline,
        "portable imported metadata replay-safe ingest; response execution disabled",
    );
    let mut trace_context = TraceContext::new_root();
    trace_context.pipeline_id = Some(execution_plan.pipeline_id.clone());
    trace_context.replay_id = Some(replay_context.replay_id.clone());
    let trace_id = trace_context.trace_id.clone();
    let source_plugin_id = PluginId::new_v4();
    let mut bus = EventBus::with_core_topics();
    ensure_topic_registered(
        &mut bus,
        ALERT_CANDIDATE_CONTRACT,
        TopicLayer::Security,
        PriorityLane::P1High,
    )?;
    ensure_topic_registered(
        &mut bus,
        INCIDENT_CANDIDATE_CONTRACT,
        TopicLayer::Security,
        PriorityLane::P1High,
    )?;
    ensure_topic_registered(
        &mut bus,
        "security.risk_hint",
        TopicLayer::Security,
        PriorityLane::P1High,
    )?;
    for topic_name in &prepared.declared_topics {
        bus.subscribe_to(topic(topic_name)?, "portable-capture-lite-observer")?;
    }

    let mut source_events = SourceStageEvents::default();
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut graph_hints = Vec::new();
    let mut security_facts = Vec::new();
    let mut attack_hypotheses = Vec::new();
    let mut fusion_summary = None;
    let mut risk_events = Vec::new();
    let mut alerts = Vec::new();
    let mut incidents = Vec::new();
    let mut emitted_topics = BTreeSet::new();
    let mut alert_candidate_count = 0usize;
    let mut incident_candidate_count = 0usize;
    let service_capability_contexts = portable_service_capability_contexts(
        prepared.provenance.provenance_id.clone(),
        runtime_service_contexts,
    )?;

    let mut completed_nodes = Vec::new();
    while completed_nodes.len() < execution_plan.steps.len() {
        let decision = scheduler.decide_ready(&execution_plan, &completed_nodes, 0, None);
        let Some(node_id) = decision.ready_nodes.first() else {
            return Err(PortableCaptureLiteError::Runtime(
                "scheduler did not produce a ready portable capture DAG node".to_string(),
            ));
        };
        let step = execution_plan.step_for(node_id).ok_or_else(|| {
            PortableCaptureLiteError::Runtime(
                "scheduled portable capture node is missing".to_string(),
            )
        })?;

        match step.stage {
            PipelineStage::Source => {
                source_events = publish_source_stage(
                    &mut bus,
                    &source_plugin_id,
                    &trace_context,
                    prepared,
                    &service_capability_contexts,
                    &mut emitted_topics,
                )?;
            }
            PipelineStage::Detection => {
                run_detection_stage(
                    &mut bus,
                    &trace_context,
                    &mut source_events,
                    &mut findings,
                    &mut evidence,
                    &mut graph_hints,
                    &mut security_facts,
                    &mut attack_hypotheses,
                    &mut fusion_summary,
                    &mut emitted_topics,
                )?;
            }
            PipelineStage::Risk => {
                let risk_stage = run_risk_stage(
                    &mut bus,
                    &trace_context,
                    &service_capability_contexts,
                    &source_events,
                    &findings,
                    &evidence,
                    &mut emitted_topics,
                )?;
                risk_events = risk_stage.risk_events;
                alerts = risk_stage.alerts;
                incidents = risk_stage.incidents;
                alert_candidate_count = risk_stage.alert_candidate_count;
                incident_candidate_count = risk_stage.incident_candidate_count;
            }
            _ => {}
        }

        completed_nodes.push(step.node_id.clone());
    }

    let auth_summary = build_portable_auth_summary(
        &prepared.provenance.provenance_id,
        &prepared.auth_metadata,
        &findings,
        &evidence,
        &graph_hints,
    );
    let saas_cloud_summary = build_portable_saas_cloud_summary(
        &prepared.provenance.provenance_id,
        &prepared.saas_cloud_metadata,
        &findings,
        &evidence,
        &graph_hints,
    );
    let deception_summary = build_portable_deception_summary(
        &prepared.provenance.provenance_id,
        &prepared.deception_events,
        &findings,
        &evidence,
        &graph_hints,
    );

    Ok(PortableCaptureLiteRunResult {
        provenance: prepared.provenance.clone(),
        trace_id,
        scheduler_kind: scheduler.metadata.kind,
        emitted_topics: emitted_topics.into_iter().collect(),
        flow_records: prepared.flow_records.clone(),
        session_records: prepared.session_records.clone(),
        dns_observations: prepared.dns_observations.clone(),
        tls_observations: prepared.tls_observations.clone(),
        http_metadata: prepared.http_metadata.clone(),
        auth_metadata: prepared.auth_metadata.clone(),
        auth_summary,
        saas_cloud_metadata: prepared.saas_cloud_metadata.clone(),
        saas_cloud_summary,
        deception_events: prepared.deception_events.clone(),
        deception_summary,
        service_capability_contexts,
        security_facts,
        attack_hypotheses,
        fusion_summary,
        findings,
        evidence,
        graph_hints,
        risk_events,
        alert_candidate_count,
        alerts,
        incident_candidate_count,
        incidents,
    })
}

#[derive(Default)]
struct SourceStageEvents {
    flow_events: Vec<EventEnvelope>,
    session_events: Vec<EventEnvelope>,
    dns_events: Vec<EventEnvelope>,
    tls_events: Vec<EventEnvelope>,
    http_events: Vec<EventEnvelope>,
    auth_events: Vec<EventEnvelope>,
    saas_cloud_events: Vec<EventEnvelope>,
    deception_events: Vec<EventEnvelope>,
    fusion_context_events: Vec<EventEnvelope>,
    finding_events: Vec<EventEnvelope>,
    service_context_events: Vec<EventEnvelope>,
    risk_hint_events: Vec<EventEnvelope>,
}

pub(crate) struct ParsedPortableCaptureInput {
    pub(crate) flow_records: Vec<FlowRecord>,
    pub(crate) session_records: Vec<SessionRecord>,
    pub(crate) dns_observations: Vec<DnsObservation>,
    pub(crate) tls_observations: Vec<TlsObservation>,
    pub(crate) http_metadata: Vec<HttpMetadata>,
    pub(crate) auth_metadata: Vec<PortableAuthMetadata>,
    pub(crate) saas_cloud_metadata: Vec<PortableSaasCloudMetadata>,
    pub(crate) deception_events: Vec<PortableDeceptionEventMetadata>,
    pub(crate) redaction_status: RedactionStatus,
}

struct JsonlHttpFields {
    scheme: Option<String>,
    host_protected: Option<String>,
    path_visible: Option<String>,
    redaction_applied: bool,
}

struct ParsedWebLogFields {
    timestamp: Timestamp,
    src_ip: IpAddress,
    src_port: u16,
    dst_ip: IpAddress,
    dst_port: u16,
    direction: NetworkDirection,
    duration_millis: u64,
    bytes_in: u64,
    bytes_out: u64,
    scheme: String,
    host_raw: Option<String>,
    path_visible: Option<String>,
    method: HttpMethod,
    status_code: Option<u16>,
    user_agent_family: Option<String>,
    content_type: Option<String>,
    result_label: Option<String>,
    waf_action: Option<String>,
    waf_rule_id: Option<String>,
    waf_attack_class: Option<String>,
    redaction_applied: bool,
}

fn parse_har(content: &str) -> Result<ParsedPortableCaptureInput, PortableCaptureLiteError> {
    let archive: HarArchive = serde_json::from_str(content)?;
    if archive.log.entries.is_empty() {
        return Err(PortableCaptureLiteError::Malformed("har"));
    }
    if archive.log.entries.len() > MAX_PORTABLE_CAPTURE_RECORDS {
        return Err(PortableCaptureLiteError::TooManyRecords);
    }

    let http_extractor = HttpMetadataExtractor;
    let tls_plugin = TlsFingerprintPlugin::new();
    let mut flows = Vec::new();
    let mut sessions = Vec::new();
    let mut tls = Vec::new();
    let mut http = Vec::new();
    let mut redaction_applied = false;

    for (index, entry) in archive.log.entries.iter().enumerate() {
        let timestamp = timestamp_from_rfc3339(&entry.started_date_time)?;
        let url = entry
            .request
            .url
            .as_deref()
            .ok_or(PortableCaptureLiteError::Malformed("har"))?;
        let url_parts = parse_url_parts(url)?;
        redaction_applied |= url_parts.redaction_applied;
        let method = parse_http_method(
            entry
                .request
                .method
                .as_deref()
                .ok_or(PortableCaptureLiteError::Malformed("har"))?,
        );
        let dst_ip = destination_ip(
            entry.server_ip_address.as_deref(),
            Some(&url_parts.host),
            index,
        )?;
        let dst_port = url_parts.port.unwrap_or(default_port(&url_parts.scheme));
        let src_ip = synthetic_local_ip(index);
        let src_port = synthetic_local_port(index);
        let request_bytes =
            har_size(entry.request.body_size) + har_size(entry.request.headers_size);
        let response_bytes =
            har_size(entry.response.body_size) + har_size(entry.response.headers_size);
        let duration_millis = entry.time.unwrap_or(0.0).max(0.0).round() as u64;

        let mut flow = FlowRecord::new(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            TransportProtocol::Tcp,
            NetworkDirection::Outbound,
        );
        flow.start_time = timestamp.clone();
        flow.end_time = Some(timestamp_plus_millis(&timestamp, duration_millis));
        flow.duration_millis = Some(duration_millis);
        flow.bytes_out = request_bytes;
        flow.bytes_in = response_bytes;
        flow.packets_out = 1;
        flow.packets_in = usize::from(response_bytes > 0) as u64;
        flow.quality_score = q(0.84)?;
        let mut session = SessionRecord::new(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            TransportProtocol::Tcp,
            NetworkDirection::Outbound,
        );
        session.flow_refs.push(flow.flow_id.clone());
        session.start_time = flow.start_time.clone();
        session.end_time = flow.end_time.clone();
        session.duration_millis = flow.duration_millis;
        session.bytes_out = flow.bytes_out;
        session.bytes_in = flow.bytes_in;
        session.packets_out = flow.packets_out;
        session.packets_in = flow.packets_in;
        session.quality_score = q(0.84)?;
        flow.session_ref = Some(session.session_id.clone());

        let (host_protected, had_host_redaction) = redact_host(&url_parts.host);
        redaction_applied |= had_host_redaction;
        let (path_visible, path_redaction) =
            sanitize_path_input(url_parts.path_and_query.as_deref());
        redaction_applied |= path_redaction;
        redaction_applied |= har_headers_redacted(entry.request.headers.as_deref())
            || har_headers_redacted(entry.response.headers.as_deref());
        let content_type = entry
            .response
            .content
            .as_ref()
            .and_then(|content| content.mime_type.clone());
        let user_agent_family = har_user_agent_family(entry.request.headers.as_deref());
        let metadata = http_extractor
            .extract(HttpMetadataInput {
                flow_ref: Some(flow.flow_id.clone()),
                timestamp: timestamp.clone(),
                method,
                scheme: Some(url_parts.scheme.clone()),
                host_protected: Some(host_protected),
                path_visible,
                status_code: entry.response.status,
                result_label: None,
                request_size_bytes: Some(request_bytes),
                response_size_bytes: Some(response_bytes),
                request_content_length_bytes: positive_u64(entry.request.body_size),
                response_content_length_bytes: positive_u64(
                    entry
                        .response
                        .content
                        .as_ref()
                        .and_then(|content| content.size),
                )
                .or_else(|| positive_u64(entry.response.body_size)),
                content_type,
                user_agent_family,
                waf_action: None,
                waf_rule_id: None,
                waf_attack_class: None,
                visible_plaintext: true,
                process_ref: None,
            })?
            .ok_or(PortableCaptureLiteError::Malformed("har"))?;
        http.push(metadata);

        if url_parts.scheme.eq_ignore_ascii_case("https") {
            let tls_record = tls_plugin.observe(TlsMetadataInput {
                flow_ref: Some(flow.flow_id.clone()),
                timestamp: timestamp.clone(),
                sni_protected: Some(redact_domain(&url_parts.host)),
                alpn: Vec::new(),
                tls_version: None,
                cipher_suite: None,
                extension_summary_protected: None,
                certificate_fingerprint: None,
                issuer_summary_protected: None,
                san_summary_protected: None,
                valid_not_before: None,
                valid_not_after: None,
                process_ref: None,
            })?;
            tls.push(tls_record);
            redaction_applied = true;
        }

        flows.push(flow);
        sessions.push(session);
    }

    Ok(ParsedPortableCaptureInput {
        flow_records: flows,
        session_records: sessions,
        dns_observations: Vec::new(),
        tls_observations: tls,
        http_metadata: http,
        auth_metadata: Vec::new(),
        saas_cloud_metadata: Vec::new(),
        deception_events: Vec::new(),
        redaction_status: if redaction_applied {
            RedactionStatus::Redacted
        } else {
            RedactionStatus::NotRequired
        },
    })
}

fn parse_web_access_log(
    content: &str,
) -> Result<ParsedPortableCaptureInput, PortableCaptureLiteError> {
    let first_line = content
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or(PortableCaptureLiteError::EmptyInput)?;
    if first_line.trim_start().starts_with('{') {
        return parse_jsonl(content);
    }

    let http_extractor = HttpMetadataExtractor;
    let mut flows = Vec::new();
    let mut sessions = Vec::new();
    let mut http = Vec::new();
    let mut redaction_applied = false;
    let mut line_count = 0usize;

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        line_count += 1;
        if line_count > MAX_PORTABLE_CAPTURE_RECORDS {
            return Err(PortableCaptureLiteError::TooManyRecords);
        }
        append_access_log_line(
            index,
            trimmed,
            &http_extractor,
            &mut flows,
            &mut sessions,
            &mut http,
            &mut redaction_applied,
        )?;
    }

    if line_count == 0 {
        return Err(PortableCaptureLiteError::EmptyInput);
    }

    Ok(ParsedPortableCaptureInput {
        flow_records: flows,
        session_records: sessions,
        dns_observations: Vec::new(),
        tls_observations: Vec::new(),
        http_metadata: http,
        auth_metadata: Vec::new(),
        saas_cloud_metadata: Vec::new(),
        deception_events: Vec::new(),
        redaction_status: if redaction_applied {
            RedactionStatus::Redacted
        } else {
            RedactionStatus::NotRequired
        },
    })
}

fn parse_jsonl(content: &str) -> Result<ParsedPortableCaptureInput, PortableCaptureLiteError> {
    let http_extractor = HttpMetadataExtractor;
    let dns_plugin = DnsSecurityObservationPlugin::new();
    let tls_plugin = TlsFingerprintPlugin::new();
    let mut flows = Vec::new();
    let mut sessions = Vec::new();
    let mut dns = Vec::new();
    let mut tls = Vec::new();
    let mut http = Vec::new();
    let mut redaction_applied = false;
    let mut line_count = 0usize;

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        line_count += 1;
        if line_count > MAX_PORTABLE_CAPTURE_RECORDS {
            return Err(PortableCaptureLiteError::TooManyRecords);
        }
        if let Ok(record) = serde_json::from_str::<JsonlNetworkRecord>(trimmed) {
            append_jsonl_network_record(
                index,
                record,
                &http_extractor,
                &dns_plugin,
                &tls_plugin,
                &mut flows,
                &mut sessions,
                &mut dns,
                &mut tls,
                &mut http,
                &mut redaction_applied,
            )?;
            continue;
        }
        if let Ok(record) = serde_json::from_str::<JsonlWebLogRecord>(trimmed) {
            append_jsonl_web_log_record(
                index,
                record,
                &http_extractor,
                &mut flows,
                &mut sessions,
                &mut http,
                &mut redaction_applied,
            )?;
            continue;
        }
        return Err(PortableCaptureLiteError::Malformed(
            "jsonl_network_metadata",
        ));
    }

    if line_count == 0 {
        return Err(PortableCaptureLiteError::EmptyInput);
    }

    Ok(ParsedPortableCaptureInput {
        flow_records: flows,
        session_records: sessions,
        dns_observations: dns,
        tls_observations: tls,
        http_metadata: http,
        auth_metadata: Vec::new(),
        saas_cloud_metadata: Vec::new(),
        deception_events: Vec::new(),
        redaction_status: if redaction_applied {
            RedactionStatus::Redacted
        } else {
            RedactionStatus::NotRequired
        },
    })
}

fn parse_auth_security_log(
    content: &str,
) -> Result<ParsedPortableCaptureInput, PortableCaptureLiteError> {
    let first_line = content
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or(PortableCaptureLiteError::EmptyInput)?;
    let mut auth_metadata = Vec::new();
    let mut line_count = 0usize;

    if first_line.trim_start().starts_with('{') {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            line_count += 1;
            if line_count > MAX_PORTABLE_CAPTURE_RECORDS {
                return Err(PortableCaptureLiteError::TooManyRecords);
            }
            let record = serde_json::from_str::<JsonlAuthRecord>(trimmed)
                .map_err(|_| PortableCaptureLiteError::Malformed("auth_security_log"))?;
            auth_metadata.push(auth_metadata_from_parsed_auth(
                parsed_auth_record_from_jsonl(record)?,
            )?);
        }
    } else {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            line_count += 1;
            if line_count > MAX_PORTABLE_CAPTURE_RECORDS {
                return Err(PortableCaptureLiteError::TooManyRecords);
            }
            auth_metadata.push(auth_metadata_from_parsed_auth(
                parsed_auth_record_from_text_line(trimmed)?,
            )?);
        }
    }

    if line_count == 0 {
        return Err(PortableCaptureLiteError::EmptyInput);
    }

    let redaction_status = if auth_metadata
        .iter()
        .any(|item| item.redaction_status == RedactionStatus::Hashed)
    {
        RedactionStatus::Hashed
    } else {
        RedactionStatus::Redacted
    };

    Ok(ParsedPortableCaptureInput {
        flow_records: Vec::new(),
        session_records: Vec::new(),
        dns_observations: Vec::new(),
        tls_observations: Vec::new(),
        http_metadata: Vec::new(),
        auth_metadata,
        saas_cloud_metadata: Vec::new(),
        deception_events: Vec::new(),
        redaction_status,
    })
}

fn parse_saas_cloud_metadata_log(
    content: &str,
) -> Result<ParsedPortableCaptureInput, PortableCaptureLiteError> {
    let mut metadata = Vec::new();
    let mut line_count = 0usize;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        line_count += 1;
        if line_count > MAX_PORTABLE_CAPTURE_RECORDS {
            return Err(PortableCaptureLiteError::TooManyRecords);
        }
        reject_saas_cloud_sensitive_json(trimmed)?;
        let record = serde_json::from_str::<JsonlSaasCloudRecord>(trimmed)
            .map_err(|_| PortableCaptureLiteError::Malformed("saas_cloud_metadata"))?;
        metadata.push(saas_cloud_metadata_from_jsonl(record)?);
    }

    if line_count == 0 {
        return Err(PortableCaptureLiteError::EmptyInput);
    }

    let redaction_status = if metadata
        .iter()
        .any(|item| item.identity_label_redacted.is_some() || item.source_session_label.is_some())
    {
        RedactionStatus::Hashed
    } else {
        RedactionStatus::Redacted
    };

    Ok(ParsedPortableCaptureInput {
        flow_records: Vec::new(),
        session_records: Vec::new(),
        dns_observations: Vec::new(),
        tls_observations: Vec::new(),
        http_metadata: Vec::new(),
        auth_metadata: Vec::new(),
        saas_cloud_metadata: metadata,
        deception_events: Vec::new(),
        redaction_status,
    })
}

fn parse_deception_event_log(
    content: &str,
) -> Result<ParsedPortableCaptureInput, PortableCaptureLiteError> {
    let mut deception_events = Vec::new();
    let mut line_count = 0usize;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        line_count += 1;
        if line_count > MAX_PORTABLE_CAPTURE_RECORDS {
            return Err(PortableCaptureLiteError::TooManyRecords);
        }
        reject_deception_sensitive_json(trimmed)?;
        let record = serde_json::from_str::<JsonlDeceptionEventRecord>(trimmed)
            .map_err(|_| PortableCaptureLiteError::Malformed("deception_event_log"))?;
        deception_events.push(deception_event_from_jsonl(record)?);
    }

    if line_count == 0 {
        return Err(PortableCaptureLiteError::EmptyInput);
    }

    Ok(ParsedPortableCaptureInput {
        flow_records: Vec::new(),
        session_records: Vec::new(),
        dns_observations: Vec::new(),
        tls_observations: Vec::new(),
        http_metadata: Vec::new(),
        auth_metadata: Vec::new(),
        saas_cloud_metadata: Vec::new(),
        deception_events,
        redaction_status: RedactionStatus::Redacted,
    })
}

fn saas_cloud_metadata_from_jsonl(
    record: JsonlSaasCloudRecord,
) -> Result<PortableSaasCloudMetadata, PortableCaptureLiteError> {
    let timestamp = first_owned(&[record.timestamp, record.time, record.ts])
        .ok_or(PortableCaptureLiteError::Malformed("saas_cloud_metadata"))
        .and_then(|value| timestamp_from_rfc3339(&value))?;
    let provider_category = normalize_provider_category(
        record
            .provider_category
            .as_deref()
            .or(record.provider.as_deref())
            .or(record.service_category.as_deref()),
    );
    let mut metadata =
        PortableSaasCloudMetadata::new(provider_category, bucket_auth_timestamp(&timestamp));
    metadata.service_category =
        normalize_saas_safe_category(first_owned(&[record.service_category, record.service]));
    metadata.provider_risk_category =
        normalize_provider_risk(record.provider_risk_category.as_deref(), &metadata);
    metadata.provider_confidence =
        normalize_provider_confidence(record.provider_confidence.as_deref(), &metadata);
    metadata.endpoint_fingerprint = normalize_endpoint_fingerprint(first_owned(&[
        record.endpoint_fingerprint,
        record.route_fingerprint,
        record.api_endpoint_fingerprint,
    ]));
    metadata.api_method_category = normalize_saas_api_method(
        record
            .api_method_category
            .as_deref()
            .or(record.method_category.as_deref())
            .or(record.api_method.as_deref()),
    );
    metadata.status_bucket = normalize_saas_status_bucket(
        record.status_bucket.as_deref(),
        record.status_code.or(record.status),
    );
    metadata.upload_download_ratio_bucket = normalize_saas_ratio_bucket(
        record.upload_download_ratio_bucket.as_deref(),
        record.upload_download_ratio,
        record.request_size_bytes,
        record.response_size_bytes,
    );
    metadata.auth_result_category = normalize_saas_auth_result(record.auth_result.as_deref());
    metadata.identity_label_redacted = first_owned(&[
        record.identity_hash,
        record.user_hash,
        record.identity,
        record.user,
        record.account,
    ])
    .map(|value| redact_auth_label("identity", &value));
    metadata.source_session_label = first_owned(&[
        record.source_session,
        record.session,
        record.session_id,
        record.connection_id,
    ])
    .map(|value| redact_auth_label("session", &value));
    metadata.destination_category = normalize_saas_safe_category(first_owned(&[
        record.destination_category,
        record.host_category,
    ]));
    metadata.redaction_status =
        if metadata.identity_label_redacted.is_some() || metadata.source_session_label.is_some() {
            RedactionStatus::Hashed
        } else {
            RedactionStatus::Redacted
        };
    metadata.quality_score = q(saas_cloud_quality_score(&metadata))?;
    Ok(metadata)
}

fn deception_event_from_jsonl(
    record: JsonlDeceptionEventRecord,
) -> Result<PortableDeceptionEventMetadata, PortableCaptureLiteError> {
    let timestamp = first_owned(&[record.timestamp, record.time, record.ts])
        .ok_or(PortableCaptureLiteError::Malformed("deception_event_log"))
        .and_then(|value| timestamp_from_rfc3339(&value))?;
    let event_category = normalize_deception_safe_category(
        first_owned(&[
            record.event_category,
            record.event,
            record.interaction_category,
        ])
        .as_deref(),
        "interaction",
    );
    let protocol_category = normalize_deception_protocol(
        first_owned(&[record.protocol_category, record.protocol]).as_deref(),
    );
    let mut metadata = PortableDeceptionEventMetadata::new(
        event_category,
        protocol_category,
        bucket_auth_timestamp(&timestamp),
    );
    metadata.decoy_sensor_ref = normalize_deception_ref(first_owned(&[
        record.decoy_sensor_ref,
        record.decoy_ref,
        record.sensor_ref,
        record.sensor,
        record.decoy,
    ]));
    metadata.source_context_category = normalize_deception_optional_category(first_owned(&[
        record.source_context_category,
        record.source_context,
        record.source_category,
    ]));
    metadata.destination_service_category = normalize_deception_optional_category(first_owned(&[
        record.destination_service_category,
        record.destination_category,
        record.service_category,
        record.service,
    ]));
    metadata.interaction_count_bucket = normalize_deception_interaction_bucket(
        record.interaction_count_bucket.as_deref(),
        record.interaction_count.or(record.count),
    );
    metadata.redaction_status = RedactionStatus::Redacted;
    metadata.quality_score = q(deception_quality_score(&metadata))?;
    Ok(metadata)
}

fn reject_saas_cloud_sensitive_json(line: &str) -> Result<(), PortableCaptureLiteError> {
    let value = serde_json::from_str::<serde_json::Value>(line)
        .map_err(|_| PortableCaptureLiteError::Malformed("saas_cloud_metadata"))?;
    if saas_cloud_value_has_sensitive_shape(&value) {
        return Err(PortableCaptureLiteError::Malformed("saas_cloud_metadata"));
    }
    Ok(())
}

fn saas_cloud_value_has_sensitive_shape(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            matches!(
                key.as_str(),
                "url"
                    | "full_url"
                    | "query"
                    | "query_params"
                    | "headers"
                    | "authorization"
                    | "cookie"
                    | "set_cookie"
                    | "token"
                    | "access_token"
                    | "refresh_token"
                    | "api_key"
                    | "username"
                    | "email"
                    | "tenant"
                    | "tenant_id"
                    | "source_ip"
                    | "src_ip"
                    | "destination_ip"
                    | "dst_ip"
                    | "path"
                    | "file"
                    | "filename"
                    | "command"
                    | "command_line"
                    | "body"
                    | "payload"
                    | "raw"
            ) || saas_cloud_value_has_sensitive_shape(value)
        }),
        serde_json::Value::Array(items) => items.iter().any(saas_cloud_value_has_sensitive_shape),
        serde_json::Value::String(value) => {
            contains_private_marker(value) || contains_local_path(value) || value.contains('@')
        }
        _ => false,
    }
}

fn reject_deception_sensitive_json(line: &str) -> Result<(), PortableCaptureLiteError> {
    let value = serde_json::from_str::<serde_json::Value>(line)
        .map_err(|_| PortableCaptureLiteError::Malformed("deception_event_log"))?;
    if deception_value_has_sensitive_shape(&value) {
        return Err(PortableCaptureLiteError::Malformed("deception_event_log"));
    }
    Ok(())
}

fn deception_value_has_sensitive_shape(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            !is_deception_json_key_allowed(&key) || deception_value_has_sensitive_shape(value)
        }),
        serde_json::Value::Array(items) => items.iter().any(deception_value_has_sensitive_shape),
        serde_json::Value::String(value) => {
            contains_private_marker(value)
                || contains_local_path(value)
                || value.contains('@')
                || IpAddress::parse_str(value).is_ok()
                || value.to_ascii_lowercase().contains("password")
                || value.to_ascii_lowercase().contains("credential")
                || value.to_ascii_lowercase().contains("malware")
                || value.to_ascii_lowercase().contains("payload")
                || value.to_ascii_lowercase().contains("cookie")
                || value.to_ascii_lowercase().contains("token")
                || value.to_ascii_lowercase().contains("secret")
        }
        _ => false,
    }
}

fn is_deception_json_key_allowed(key: &str) -> bool {
    matches!(
        key,
        "timestamp"
            | "time"
            | "ts"
            | "decoy_sensor_ref"
            | "decoy_ref"
            | "sensor_ref"
            | "sensor"
            | "decoy"
            | "event_category"
            | "event"
            | "interaction_category"
            | "source_context_category"
            | "source_context"
            | "source_category"
            | "destination_service_category"
            | "destination_category"
            | "service_category"
            | "service"
            | "interaction_count_bucket"
            | "interaction_count"
            | "count"
            | "protocol_category"
            | "protocol"
    )
}

fn normalize_provider_category(raw: Option<&str>) -> PortableProviderCategory {
    let value = raw.unwrap_or_default().to_ascii_lowercase();
    if value.contains("object")
        || value.contains("bucket")
        || value.contains("blob")
        || value.contains("s3")
    {
        PortableProviderCategory::ObjectStorage
    } else if value.contains("cdn") || value.contains("front") {
        PortableProviderCategory::Cdn
    } else if value.contains("tunnel") || value.contains("proxy") || value.contains("vpn") {
        PortableProviderCategory::TunnelProxy
    } else if value.contains("anon") || value.contains("tor") {
        PortableProviderCategory::Anonymizing
    } else if value.contains("saas") || value.contains("app") {
        PortableProviderCategory::Saas
    } else if value.contains("cloud") {
        PortableProviderCategory::Cloud
    } else {
        PortableProviderCategory::Unknown
    }
}

fn normalize_provider_risk(
    raw: Option<&str>,
    metadata: &PortableSaasCloudMetadata,
) -> PortableProviderRiskCategory {
    let value = raw.unwrap_or_default().to_ascii_lowercase();
    if value.contains("high")
        || matches!(
            metadata.provider_category,
            PortableProviderCategory::TunnelProxy | PortableProviderCategory::Anonymizing
        )
    {
        PortableProviderRiskCategory::High
    } else if value.contains("medium")
        || matches!(
            metadata.provider_category,
            PortableProviderCategory::ObjectStorage | PortableProviderCategory::Cdn
        )
    {
        PortableProviderRiskCategory::Medium
    } else if value.contains("low")
        || matches!(
            metadata.provider_category,
            PortableProviderCategory::Saas | PortableProviderCategory::Cloud
        )
    {
        PortableProviderRiskCategory::Low
    } else {
        PortableProviderRiskCategory::Unknown
    }
}

fn normalize_provider_confidence(
    raw: Option<&str>,
    metadata: &PortableSaasCloudMetadata,
) -> PortableProviderConfidenceBucket {
    let value = raw.unwrap_or_default().to_ascii_lowercase();
    if value.contains("high") {
        PortableProviderConfidenceBucket::High
    } else if value.contains("medium") || value.contains("local") || value.contains("demo") {
        PortableProviderConfidenceBucket::Medium
    } else if value.contains("low")
        || metadata.provider_category == PortableProviderCategory::Unknown
    {
        PortableProviderConfidenceBucket::Low
    } else {
        PortableProviderConfidenceBucket::Medium
    }
}

fn normalize_saas_api_method(raw: Option<&str>) -> PortableApiMethodCategory {
    let value = raw.unwrap_or_default().to_ascii_lowercase();
    if value.contains("admin") || value.contains("privilege") || value.contains("iam") {
        PortableApiMethodCategory::Admin
    } else if value.contains("delete") || value == "del" {
        PortableApiMethodCategory::Delete
    } else if value.contains("post")
        || value.contains("put")
        || value.contains("patch")
        || value.contains("write")
        || value.contains("upload")
    {
        PortableApiMethodCategory::Write
    } else if value.contains("auth") || value.contains("login") || value.contains("token") {
        PortableApiMethodCategory::Auth
    } else if value.contains("get") || value.contains("read") || value.contains("list") {
        PortableApiMethodCategory::Read
    } else if value.trim().is_empty() {
        PortableApiMethodCategory::Unknown
    } else {
        PortableApiMethodCategory::Other
    }
}

fn normalize_saas_status_bucket(raw: Option<&str>, status: Option<u16>) -> PortableStatusBucket {
    let value = raw.unwrap_or_default().to_ascii_lowercase();
    if value.contains("auth") || status == Some(401) || status == Some(403) {
        PortableStatusBucket::AuthError
    } else if value.contains("not_found") || status == Some(404) {
        PortableStatusBucket::NotFound
    } else if value.contains("rate") || status == Some(429) {
        PortableStatusBucket::RateLimited
    } else if value.contains("client") || status.is_some_and(|status| (400..500).contains(&status))
    {
        PortableStatusBucket::ClientError
    } else if value.contains("server") || status.is_some_and(|status| status >= 500) {
        PortableStatusBucket::ServerError
    } else if value.contains("redirect")
        || status.is_some_and(|status| (300..400).contains(&status))
    {
        PortableStatusBucket::Redirect
    } else if value.contains("success") || status.is_some_and(|status| (200..300).contains(&status))
    {
        PortableStatusBucket::Success
    } else {
        PortableStatusBucket::Unknown
    }
}

fn normalize_saas_ratio_bucket(
    raw: Option<&str>,
    ratio: Option<f32>,
    request_size: Option<u64>,
    response_size: Option<u64>,
) -> PortableUploadDownloadRatioBucket {
    let value = raw.unwrap_or_default().to_ascii_lowercase();
    if value.contains("burst") {
        PortableUploadDownloadRatioBucket::UploadBurst
    } else if value.contains("upload") {
        PortableUploadDownloadRatioBucket::UploadHeavy
    } else if value.contains("download") {
        PortableUploadDownloadRatioBucket::DownloadHeavy
    } else if value.contains("balanced") {
        PortableUploadDownloadRatioBucket::Balanced
    } else if let Some(ratio) = ratio {
        if ratio >= 8.0 {
            PortableUploadDownloadRatioBucket::UploadBurst
        } else if ratio >= 2.0 {
            PortableUploadDownloadRatioBucket::UploadHeavy
        } else if ratio <= 0.25 {
            PortableUploadDownloadRatioBucket::DownloadHeavy
        } else {
            PortableUploadDownloadRatioBucket::Balanced
        }
    } else if let (Some(request_size), Some(response_size)) = (request_size, response_size) {
        let denominator = response_size.max(1) as f32;
        normalize_saas_ratio_bucket(None, Some(request_size as f32 / denominator), None, None)
    } else {
        PortableUploadDownloadRatioBucket::Unknown
    }
}

fn normalize_saas_auth_result(raw: Option<&str>) -> Option<String> {
    let value = raw?.to_ascii_lowercase();
    Some(
        if value.contains("success") || value.contains("allow") || value.contains("pass") {
            "success".to_string()
        } else if value.contains("fail") || value.contains("deny") || value.contains("invalid") {
            "failure".to_string()
        } else if value.contains("block") {
            "blocked".to_string()
        } else if value.contains("challenge") || value.contains("mfa") {
            "challenge".to_string()
        } else if value.contains("timeout") {
            "timeout".to_string()
        } else {
            "unknown".to_string()
        },
    )
}

fn normalize_endpoint_fingerprint(value: Option<String>) -> Option<String> {
    let value = value?;
    if value.starts_with("endpoint#") || value.starts_with("route#") {
        Some(value)
    } else {
        Some(format!("endpoint#{}", stable_hash_hex(&value, 12)))
    }
}

fn normalize_saas_safe_category(value: Option<String>) -> Option<String> {
    let value = value?;
    let normalized = value
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    (!normalized.trim_matches('_').is_empty()).then_some(normalized)
}

fn saas_cloud_quality_score(metadata: &PortableSaasCloudMetadata) -> f32 {
    let mut score: f32 = match metadata.provider_confidence {
        PortableProviderConfidenceBucket::High => 0.82,
        PortableProviderConfidenceBucket::Medium => 0.72,
        PortableProviderConfidenceBucket::Low => 0.52,
        PortableProviderConfidenceBucket::Unknown => 0.42,
    };
    if metadata.provider_category == PortableProviderCategory::Unknown {
        score -= 0.12;
    }
    if metadata.endpoint_fingerprint.is_none() {
        score -= 0.06;
    }
    if matches!(
        metadata.upload_download_ratio_bucket,
        PortableUploadDownloadRatioBucket::Unknown
    ) {
        score -= 0.04;
    }
    score.clamp(0.28, 0.86)
}

fn normalize_deception_ref(value: Option<String>) -> Option<String> {
    let value = value?;
    if value.starts_with("sensor#") || value.starts_with("decoy#") {
        Some(value)
    } else {
        Some(format!("sensor#{}", stable_hash_hex(&value, 12)))
    }
}

fn normalize_deception_optional_category(value: Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(|value| normalize_deception_safe_category(Some(value), "unknown"))
        .filter(|value| value != "unknown")
}

fn normalize_deception_safe_category(raw: Option<&str>, fallback: &str) -> String {
    let normalized = raw
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if normalized.is_empty() {
        fallback.to_string()
    } else if normalized.contains("scan") || normalized.contains("probe") {
        "probe".to_string()
    } else if normalized.contains("login") || normalized.contains("auth") {
        "auth_interaction".to_string()
    } else if normalized.contains("connect") || normalized.contains("session") {
        "connection".to_string()
    } else if normalized.contains("exploit") || normalized.contains("attack") {
        "exploit_attempt".to_string()
    } else {
        normalized
    }
}

fn normalize_deception_protocol(raw: Option<&str>) -> PortableDeceptionProtocolCategory {
    let value = raw.unwrap_or_default().to_ascii_lowercase();
    if value.contains("http") || value.contains("web") {
        PortableDeceptionProtocolCategory::Http
    } else if value.contains("dns") {
        PortableDeceptionProtocolCategory::Dns
    } else if value.contains("ssh") {
        PortableDeceptionProtocolCategory::Ssh
    } else if value.contains("smb") || value.contains("445") {
        PortableDeceptionProtocolCategory::Smb
    } else if value.contains("rdp") || value.contains("3389") {
        PortableDeceptionProtocolCategory::Rdp
    } else if value.contains("ftp") {
        PortableDeceptionProtocolCategory::Ftp
    } else if value.contains("telnet") {
        PortableDeceptionProtocolCategory::Telnet
    } else if value.contains("sql") || value.contains("database") || value.contains("db") {
        PortableDeceptionProtocolCategory::Database
    } else if value.contains("ics") || value.contains("scada") || value.contains("ot") {
        PortableDeceptionProtocolCategory::Ics
    } else if value.trim().is_empty() {
        PortableDeceptionProtocolCategory::Unknown
    } else {
        PortableDeceptionProtocolCategory::Other
    }
}

fn normalize_deception_interaction_bucket(
    raw: Option<&str>,
    count: Option<u32>,
) -> PortableDecoyInteractionCountBucket {
    let value = raw.unwrap_or_default().to_ascii_lowercase();
    if value.contains("burst") {
        PortableDecoyInteractionCountBucket::Burst
    } else if value.contains("high") {
        PortableDecoyInteractionCountBucket::High
    } else if value.contains("medium") {
        PortableDecoyInteractionCountBucket::Medium
    } else if value.contains("low") {
        PortableDecoyInteractionCountBucket::Low
    } else if value.contains("single") {
        PortableDecoyInteractionCountBucket::Single
    } else if let Some(count) = count {
        match count {
            0 | 1 => PortableDecoyInteractionCountBucket::Single,
            2..=3 => PortableDecoyInteractionCountBucket::Low,
            4..=9 => PortableDecoyInteractionCountBucket::Medium,
            10..=24 => PortableDecoyInteractionCountBucket::High,
            _ => PortableDecoyInteractionCountBucket::Burst,
        }
    } else {
        PortableDecoyInteractionCountBucket::Unknown
    }
}

fn deception_quality_score(metadata: &PortableDeceptionEventMetadata) -> f32 {
    let mut score: f32 = 0.76;
    if metadata.decoy_sensor_ref.is_none() {
        score -= 0.12;
    }
    if metadata.source_context_category.is_none() {
        score -= 0.06;
    }
    if metadata.destination_service_category.is_none() {
        score -= 0.06;
    }
    if matches!(
        metadata.protocol_category,
        PortableDeceptionProtocolCategory::Unknown
    ) {
        score -= 0.1;
    }
    if matches!(
        metadata.interaction_count_bucket,
        PortableDecoyInteractionCountBucket::Unknown
    ) {
        score -= 0.08;
    }
    score.clamp(0.3, 0.82)
}

struct ParsedAuthRecord {
    timestamp: Timestamp,
    provider_category: String,
    identity_source: Option<String>,
    source_session: Option<String>,
    auth_result: PortableAuthResultCategory,
    mfa_result: Option<PortableMfaResultCategory>,
    role_privilege_class: Option<String>,
    device_client_category: Option<String>,
    destination_service_category: Option<String>,
    attempt_count: u32,
    failure_reason_category: Option<String>,
}

fn parsed_auth_record_from_jsonl(
    record: JsonlAuthRecord,
) -> Result<ParsedAuthRecord, PortableCaptureLiteError> {
    let timestamp = timestamp_from_rfc3339(
        record
            .timestamp
            .as_deref()
            .or(record.time.as_deref())
            .or(record.ts.as_deref())
            .ok_or(PortableCaptureLiteError::Malformed("auth_security_log"))?,
    )?;
    let service_hint = record
        .destination_service
        .as_deref()
        .or(record.service.as_deref())
        .or(record.protocol.as_deref());
    Ok(ParsedAuthRecord {
        timestamp,
        provider_category: normalize_auth_provider_category(
            record
                .provider_category
                .as_deref()
                .or(record.provider.as_deref())
                .or(record.source_type.as_deref()),
            service_hint,
        ),
        identity_source: first_owned(&[
            record.identity_hash,
            record.user_hash,
            record.identity,
            record.username,
            record.user,
            record.email,
            record.account,
            record.subject,
        ]),
        source_session: first_owned(&[record.session, record.session_id, record.connection_id]),
        auth_result: normalize_auth_result(
            record
                .auth_result
                .as_deref()
                .or(record.result.as_deref())
                .or(record.outcome.as_deref())
                .or(record.status.as_deref()),
        ),
        mfa_result: normalize_mfa_result(
            record
                .mfa_result
                .as_deref()
                .or(record.mfa_status.as_deref())
                .or(record.mfa.as_deref()),
        ),
        role_privilege_class: normalize_role_privilege_class(
            record
                .role_class
                .as_deref()
                .or(record.privilege_class.as_deref()),
        ),
        device_client_category: normalize_device_client_category(
            record
                .device_category
                .as_deref()
                .or(record.client_category.as_deref())
                .or(record.client_type.as_deref()),
        ),
        destination_service_category: normalize_destination_service_category(service_hint),
        attempt_count: record.attempt_count.or(record.attempts).unwrap_or(1),
        failure_reason_category: normalize_failure_reason_category(
            record
                .failure_reason
                .as_deref()
                .or(record.reason.as_deref()),
        ),
    })
}

fn parsed_auth_record_from_text_line(
    line: &str,
) -> Result<ParsedAuthRecord, PortableCaptureLiteError> {
    let fields = key_value_fields(line);
    let timestamp = timestamp_from_rfc3339(
        fields
            .get("timestamp")
            .or_else(|| fields.get("time"))
            .or_else(|| fields.get("ts"))
            .map(String::as_str)
            .ok_or(PortableCaptureLiteError::Malformed("auth_security_log"))?,
    )?;
    let service_hint = fields
        .get("destination_service")
        .or_else(|| fields.get("service"))
        .or_else(|| fields.get("protocol"))
        .map(String::as_str);
    Ok(ParsedAuthRecord {
        timestamp,
        provider_category: normalize_auth_provider_category(
            fields
                .get("provider_category")
                .or_else(|| fields.get("provider"))
                .or_else(|| fields.get("source_type"))
                .map(String::as_str),
            service_hint,
        ),
        identity_source: first_owned(&[
            fields.get("identity_hash").cloned(),
            fields.get("user_hash").cloned(),
            fields.get("identity").cloned(),
            fields.get("username").cloned(),
            fields.get("user").cloned(),
            fields.get("email").cloned(),
            fields.get("account").cloned(),
            fields.get("subject").cloned(),
        ]),
        source_session: first_owned(&[
            fields.get("session").cloned(),
            fields.get("session_id").cloned(),
            fields.get("connection_id").cloned(),
        ]),
        auth_result: normalize_auth_result(
            fields
                .get("auth_result")
                .or_else(|| fields.get("result"))
                .or_else(|| fields.get("outcome"))
                .or_else(|| fields.get("status"))
                .map(String::as_str),
        ),
        mfa_result: normalize_mfa_result(
            fields
                .get("mfa_result")
                .or_else(|| fields.get("mfa_status"))
                .or_else(|| fields.get("mfa"))
                .map(String::as_str),
        ),
        role_privilege_class: normalize_role_privilege_class(
            fields
                .get("role_class")
                .or_else(|| fields.get("privilege_class"))
                .map(String::as_str),
        ),
        device_client_category: normalize_device_client_category(
            fields
                .get("device_category")
                .or_else(|| fields.get("client_category"))
                .or_else(|| fields.get("client_type"))
                .map(String::as_str),
        ),
        destination_service_category: normalize_destination_service_category(service_hint),
        attempt_count: fields
            .get("attempt_count")
            .or_else(|| fields.get("attempts"))
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(1),
        failure_reason_category: normalize_failure_reason_category(
            fields
                .get("failure_reason")
                .or_else(|| fields.get("reason"))
                .map(String::as_str),
        ),
    })
}

fn auth_metadata_from_parsed_auth(
    record: ParsedAuthRecord,
) -> Result<PortableAuthMetadata, PortableCaptureLiteError> {
    let mut metadata = PortableAuthMetadata::new(
        record.provider_category,
        record.auth_result,
        bucket_auth_timestamp(&record.timestamp),
    );
    metadata.identity_label_redacted = record
        .identity_source
        .as_deref()
        .map(|value| redact_auth_label("identity", value));
    metadata.source_session_label = record
        .source_session
        .as_deref()
        .map(|value| redact_auth_label("session", value));
    metadata.mfa_result = record.mfa_result;
    metadata.role_privilege_class = record.role_privilege_class;
    metadata.device_client_category = record.device_client_category;
    metadata.destination_service_category = record.destination_service_category;
    metadata.attempt_count_bucket = auth_attempt_count_bucket(record.attempt_count);
    metadata.failure_reason_category = record.failure_reason_category;
    metadata.redaction_status =
        if metadata.identity_label_redacted.is_some() || metadata.source_session_label.is_some() {
            RedactionStatus::Hashed
        } else {
            RedactionStatus::Redacted
        };
    metadata.quality_score = q(auth_quality_score(&metadata))?;
    Ok(metadata)
}

fn key_value_fields(line: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for token in line.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let normalized_key = key.trim().to_ascii_lowercase();
        let normalized_value = value.trim_matches('"').trim_matches('\'').to_string();
        if !normalized_key.is_empty() && !normalized_value.is_empty() {
            fields.insert(normalized_key, normalized_value);
        }
    }
    fields
}

fn first_owned(candidates: &[Option<String>]) -> Option<String> {
    candidates.iter().find_map(|value| value.clone())
}

fn bucket_auth_timestamp(timestamp: &Timestamp) -> Timestamp {
    let remainder = timestamp.as_datetime().timestamp().rem_euclid(300);
    Timestamp::from_datetime(timestamp.as_datetime().to_owned() - Duration::seconds(remainder))
}

fn redact_auth_label(prefix: &str, value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"portable-auth-label");
    digest.update(prefix.as_bytes());
    digest.update(value.as_bytes());
    let digest = digest.finalize();
    let suffix = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{prefix}#{suffix}")
}

fn normalize_auth_provider_category(raw: Option<&str>, service_hint: Option<&str>) -> String {
    let value = raw.unwrap_or_default().to_ascii_lowercase();
    let service = service_hint.unwrap_or_default().to_ascii_lowercase();
    if value.contains("vpn") || service.contains("vpn") {
        "vpn".to_string()
    } else if value.contains("ssh")
        || value.contains("rdp")
        || value.contains("smb")
        || value.contains("remote")
        || service.contains("ssh")
        || service.contains("rdp")
        || service.contains("smb")
    {
        "remote_admin".to_string()
    } else if value.contains("waf") || value.contains("gateway") {
        "waf_gateway".to_string()
    } else if value.contains("proxy") {
        "reverse_proxy".to_string()
    } else if value.contains("cloud") || value.contains("external") {
        "external_identity".to_string()
    } else {
        "idp".to_string()
    }
}

fn normalize_auth_result(raw: Option<&str>) -> PortableAuthResultCategory {
    let value = raw.unwrap_or_default().to_ascii_lowercase();
    if value.contains("success") || value.contains("accept") || value.contains("allow") {
        PortableAuthResultCategory::Success
    } else if value.contains("block") || value.contains("deny") || value.contains("forbid") {
        PortableAuthResultCategory::Blocked
    } else if value.contains("timeout") || value.contains("expired") {
        PortableAuthResultCategory::Timeout
    } else if value.contains("challenge") || value.contains("prompt") || value.contains("mfa") {
        PortableAuthResultCategory::Challenge
    } else if value.contains("fail")
        || value.contains("invalid")
        || value.contains("reject")
        || value.contains("error")
    {
        PortableAuthResultCategory::Failure
    } else {
        PortableAuthResultCategory::Unknown
    }
}

fn normalize_mfa_result(raw: Option<&str>) -> Option<PortableMfaResultCategory> {
    let value = raw?.to_ascii_lowercase();
    Some(
        if value.contains("satisfied") || value.contains("success") || value.contains("pass") {
            PortableMfaResultCategory::Satisfied
        } else if value.contains("deny") || value.contains("reject") {
            PortableMfaResultCategory::Denied
        } else if value.contains("prompt") || value.contains("push") {
            PortableMfaResultCategory::Prompted
        } else if value.contains("timeout") || value.contains("expired") {
            PortableMfaResultCategory::Timeout
        } else if value.contains("fail") || value.contains("error") {
            PortableMfaResultCategory::Failed
        } else if value.contains("none") || value.contains("absent") || value.contains("n/a") {
            PortableMfaResultCategory::NotPresent
        } else {
            PortableMfaResultCategory::Unknown
        },
    )
}

fn normalize_role_privilege_class(raw: Option<&str>) -> Option<String> {
    let value = raw?.to_ascii_lowercase();
    if value.contains("admin") || value.contains("root") || value.contains("privileged") {
        Some("privileged".to_string())
    } else if value.contains("service") || value.contains("bot") || value.contains("machine") {
        Some("service".to_string())
    } else if value.contains("guest") {
        Some("guest".to_string())
    } else if value.contains("user") || value.contains("member") || value.contains("standard") {
        Some("standard".to_string())
    } else {
        None
    }
}

fn normalize_device_client_category(raw: Option<&str>) -> Option<String> {
    let value = raw?.to_ascii_lowercase();
    Some(if value.contains("browser") || value.contains("web") {
        "browser".to_string()
    } else if value.contains("mobile") || value.contains("ios") || value.contains("android") {
        "mobile".to_string()
    } else if value.contains("desktop")
        || value.contains("windows")
        || value.contains("mac")
        || value.contains("linux")
    {
        "desktop".to_string()
    } else if value.contains("vpn") {
        "vpn_client".to_string()
    } else if value.contains("script")
        || value.contains("curl")
        || value.contains("python")
        || value.contains("powershell")
        || value.contains("automation")
    {
        "automation".to_string()
    } else {
        "other".to_string()
    })
}

fn normalize_destination_service_category(raw: Option<&str>) -> Option<String> {
    let value = raw?.to_ascii_lowercase();
    Some(if value.contains("ssh") {
        "ssh".to_string()
    } else if value.contains("rdp") {
        "rdp".to_string()
    } else if value.contains("smb") {
        "smb".to_string()
    } else if value.contains("vpn") {
        "vpn".to_string()
    } else if value.contains("admin") {
        "admin_portal".to_string()
    } else if value.contains("sso") || value.contains("idp") {
        "sso".to_string()
    } else if value.contains("gateway") || value.contains("proxy") {
        "auth_gateway".to_string()
    } else if value.contains("saas") || value.contains("cloud") {
        "saas".to_string()
    } else {
        "other".to_string()
    })
}

fn normalize_failure_reason_category(raw: Option<&str>) -> Option<String> {
    let value = raw?.to_ascii_lowercase();
    Some(
        if value.contains("password") || value.contains("invalid") || value.contains("credential") {
            "invalid_password".to_string()
        } else if value.contains("lock") || value.contains("disabled") {
            "account_locked".to_string()
        } else if value.contains("mfa") && (value.contains("timeout") || value.contains("expired"))
        {
            "mfa_timeout".to_string()
        } else if value.contains("mfa") {
            "mfa_denied".to_string()
        } else if value.contains("policy") || value.contains("block") {
            "policy_block".to_string()
        } else if value.contains("access") || value.contains("forbid") {
            "access_denied".to_string()
        } else if value.contains("network") {
            "network_denied".to_string()
        } else {
            "other".to_string()
        },
    )
}

fn auth_attempt_count_bucket(value: u32) -> PortableAuthAttemptCountBucket {
    match value {
        0 | 1 => PortableAuthAttemptCountBucket::One,
        2 | 3 => PortableAuthAttemptCountBucket::Few,
        4..=6 => PortableAuthAttemptCountBucket::Burst,
        _ => PortableAuthAttemptCountBucket::Many,
    }
}

fn auth_quality_score(metadata: &PortableAuthMetadata) -> f32 {
    let mut score: f32 = 0.86;
    if metadata.identity_label_redacted.is_none() {
        score -= 0.08;
    }
    if metadata.mfa_result.is_none() {
        score -= 0.06;
    }
    if metadata.role_privilege_class.is_none() {
        score -= 0.04;
    }
    if metadata.destination_service_category.is_none() {
        score -= 0.04;
    }
    score.max(0.55)
}

#[allow(clippy::too_many_arguments)]
fn append_jsonl_network_record(
    index: usize,
    record: JsonlNetworkRecord,
    http_extractor: &HttpMetadataExtractor,
    dns_plugin: &DnsSecurityObservationPlugin,
    tls_plugin: &TlsFingerprintPlugin,
    flows: &mut Vec<FlowRecord>,
    sessions: &mut Vec<SessionRecord>,
    dns: &mut Vec<DnsObservation>,
    tls: &mut Vec<TlsObservation>,
    http: &mut Vec<HttpMetadata>,
    redaction_applied: &mut bool,
) -> Result<(), PortableCaptureLiteError> {
    let timestamp = timestamp_from_rfc3339(&record.timestamp)?;
    let src_ip = parse_ip(record.src_ip.as_deref().unwrap_or("192.0.2.10"))?;
    let dst_ip = parse_ip(record.dst_ip.as_deref().unwrap_or("198.51.100.20"))?;
    let src_port = record
        .src_port
        .unwrap_or_else(|| synthetic_local_port(index));
    let dst_port = record.dst_port.unwrap_or_else(|| {
        record
            .http
            .as_ref()
            .and_then(|http| http.url.as_deref())
            .and_then(|url| parse_url_parts(url).ok())
            .and_then(|parts| parts.port)
            .unwrap_or(443)
    });

    let mut flow = FlowRecord::new(
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        record.protocol.unwrap_or(TransportProtocol::Tcp),
        record.direction.unwrap_or(NetworkDirection::Outbound),
    );
    flow.start_time = timestamp.clone();
    flow.end_time = Some(timestamp_plus_millis(
        &timestamp,
        record.duration_millis.unwrap_or(0),
    ));
    flow.duration_millis = Some(record.duration_millis.unwrap_or(0));
    flow.bytes_out = record.bytes_out.unwrap_or(0);
    flow.bytes_in = record.bytes_in.unwrap_or(0);
    flow.packets_out = record.packets_out.unwrap_or(1);
    flow.packets_in = record
        .packets_in
        .unwrap_or_else(|| usize::from(flow.bytes_in > 0) as u64);
    flow.quality_score = q(0.9)?;

    let mut session = SessionRecord::new(
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        flow.protocol.clone(),
        flow.direction.clone(),
    );
    session.flow_refs.push(flow.flow_id.clone());
    session.start_time = flow.start_time.clone();
    session.end_time = flow.end_time.clone();
    session.duration_millis = flow.duration_millis;
    session.bytes_out = flow.bytes_out;
    session.bytes_in = flow.bytes_in;
    session.packets_out = flow.packets_out;
    session.packets_in = flow.packets_in;
    session.quality_score = q(0.9)?;
    flow.session_ref = Some(session.session_id.clone());

    if let Some(http_record) = record.http {
        let http_fields = jsonl_http_fields(&http_record)?;
        *redaction_applied |= http_fields.redaction_applied;
        let metadata = http_extractor
            .extract(HttpMetadataInput {
                flow_ref: Some(flow.flow_id.clone()),
                timestamp: timestamp.clone(),
                method: parse_http_method(http_record.method.as_deref().unwrap_or("GET")),
                scheme: http_fields.scheme,
                host_protected: http_fields.host_protected,
                path_visible: http_fields.path_visible,
                status_code: http_record.status_code,
                result_label: http_record.result_label,
                request_size_bytes: http_record.request_size_bytes.or(Some(flow.bytes_out)),
                response_size_bytes: http_record.response_size_bytes.or(Some(flow.bytes_in)),
                request_content_length_bytes: http_record
                    .request_content_length_bytes
                    .or(Some(flow.bytes_out)),
                response_content_length_bytes: http_record
                    .response_content_length_bytes
                    .or(Some(flow.bytes_in)),
                content_type: http_record.content_type,
                user_agent_family: http_user_agent_family(http_record.user_agent.as_deref()),
                waf_action: http_record.waf_action,
                waf_rule_id: http_record.waf_rule_id,
                waf_attack_class: http_record.waf_attack_class,
                visible_plaintext: true,
                process_ref: None,
            })?
            .ok_or(PortableCaptureLiteError::Malformed(
                "jsonl_network_metadata",
            ))?;
        http.push(metadata);
    }

    if let Some(dns_record) = record.dns {
        let observation = dns_plugin.observe(DnsMetadataInput {
            flow_ref: Some(flow.flow_id.clone()),
            query_name_protected: redact_domain(&dns_record.query_name),
            feature_source_name: Some(dns_record.query_name.clone()),
            query_type: dns_record.query_type.unwrap_or_else(|| "A".to_string()),
            response_code: dns_record.response_code,
            resolver_ip: parse_ip(&dns_record.resolver_ip)?,
            client_ip: parse_ip(&dns_record.client_ip)?,
            timestamp: timestamp.clone(),
            answers: dns_record
                .answers
                .unwrap_or_default()
                .into_iter()
                .map(jsonl_dns_answer)
                .collect::<Result<Vec<_>, _>>()?,
            cname_chain_protected: dns_record
                .cname_chain
                .unwrap_or_default()
                .into_iter()
                .map(|value| redact_domain(&value))
                .collect(),
            process_ref: None,
        })?;
        *redaction_applied = true;
        dns.push(observation);
    }

    if let Some(tls_record) = record.tls {
        let observation = tls_plugin.observe(TlsMetadataInput {
            flow_ref: Some(flow.flow_id.clone()),
            timestamp: timestamp.clone(),
            sni_protected: tls_record.sni.map(|value| redact_domain(&value)),
            alpn: tls_record.alpn.unwrap_or_default(),
            tls_version: tls_record.tls_version,
            cipher_suite: tls_record.cipher_suite,
            extension_summary_protected: tls_record
                .extension_summary
                .map(|value| redact_text("tls-extension", &value)),
            certificate_fingerprint: tls_record.certificate_fingerprint,
            issuer_summary_protected: tls_record
                .issuer_summary
                .map(|value| redact_text("tls-issuer", &value)),
            san_summary_protected: tls_record
                .san_summary
                .map(|value| redact_text("tls-san", &value)),
            valid_not_before: None,
            valid_not_after: None,
            process_ref: None,
        })?;
        *redaction_applied |= observation.sni_protected.is_some();
        tls.push(observation);
    }

    flows.push(flow);
    sessions.push(session);
    Ok(())
}

fn append_jsonl_web_log_record(
    index: usize,
    record: JsonlWebLogRecord,
    http_extractor: &HttpMetadataExtractor,
    flows: &mut Vec<FlowRecord>,
    sessions: &mut Vec<SessionRecord>,
    http: &mut Vec<HttpMetadata>,
    redaction_applied: &mut bool,
) -> Result<(), PortableCaptureLiteError> {
    let fields = web_log_fields_from_jsonl(index, record)?;
    append_http_only_web_fields(
        fields,
        http_extractor,
        flows,
        sessions,
        http,
        redaction_applied,
    )
}

fn append_access_log_line(
    index: usize,
    line: &str,
    http_extractor: &HttpMetadataExtractor,
    flows: &mut Vec<FlowRecord>,
    sessions: &mut Vec<SessionRecord>,
    http: &mut Vec<HttpMetadata>,
    redaction_applied: &mut bool,
) -> Result<(), PortableCaptureLiteError> {
    let fields = web_log_fields_from_access_line(index, line)?;
    append_http_only_web_fields(
        fields,
        http_extractor,
        flows,
        sessions,
        http,
        redaction_applied,
    )
}

fn append_http_only_web_fields(
    fields: ParsedWebLogFields,
    http_extractor: &HttpMetadataExtractor,
    flows: &mut Vec<FlowRecord>,
    sessions: &mut Vec<SessionRecord>,
    http: &mut Vec<HttpMetadata>,
    redaction_applied: &mut bool,
) -> Result<(), PortableCaptureLiteError> {
    let mut flow = FlowRecord::new(
        fields.src_ip,
        fields.src_port,
        fields.dst_ip,
        fields.dst_port,
        TransportProtocol::Tcp,
        fields.direction.clone(),
    );
    flow.start_time = fields.timestamp.clone();
    flow.end_time = Some(timestamp_plus_millis(
        &fields.timestamp,
        fields.duration_millis,
    ));
    flow.duration_millis = Some(fields.duration_millis);
    flow.bytes_in = fields.bytes_in;
    flow.bytes_out = fields.bytes_out;
    flow.packets_in = u64::from(fields.bytes_in > 0);
    flow.packets_out = u64::from(fields.bytes_out > 0);
    flow.quality_score = q(0.87)?;

    let mut session = SessionRecord::new(
        flow.src_ip,
        flow.src_port,
        flow.dst_ip,
        flow.dst_port,
        flow.protocol.clone(),
        flow.direction.clone(),
    );
    session.flow_refs.push(flow.flow_id.clone());
    session.start_time = flow.start_time.clone();
    session.end_time = flow.end_time.clone();
    session.duration_millis = flow.duration_millis;
    session.bytes_in = flow.bytes_in;
    session.bytes_out = flow.bytes_out;
    session.packets_in = flow.packets_in;
    session.packets_out = flow.packets_out;
    session.quality_score = q(0.87)?;
    flow.session_ref = Some(session.session_id.clone());

    let host = fields.host_raw.as_deref().map(redact_host);
    let (host_protected, host_redaction) = match host {
        Some((value, applied)) => (Some(value), applied),
        None => (None, false),
    };
    let (path_visible, path_redaction) = sanitize_path_input(fields.path_visible.as_deref());
    *redaction_applied |= fields.redaction_applied || host_redaction || path_redaction;

    let metadata = http_extractor
        .extract(HttpMetadataInput {
            flow_ref: Some(flow.flow_id.clone()),
            timestamp: fields.timestamp.clone(),
            method: fields.method,
            scheme: Some(fields.scheme),
            host_protected,
            path_visible,
            status_code: fields.status_code,
            result_label: fields.result_label,
            request_size_bytes: Some(fields.bytes_in),
            response_size_bytes: Some(fields.bytes_out),
            request_content_length_bytes: (fields.bytes_in > 0).then_some(fields.bytes_in),
            response_content_length_bytes: (fields.bytes_out > 0).then_some(fields.bytes_out),
            content_type: fields.content_type,
            user_agent_family: fields.user_agent_family,
            waf_action: fields.waf_action,
            waf_rule_id: fields.waf_rule_id,
            waf_attack_class: fields.waf_attack_class,
            visible_plaintext: true,
            process_ref: None,
        })?
        .ok_or(PortableCaptureLiteError::Malformed("web_access_log"))?;

    flows.push(flow);
    sessions.push(session);
    http.push(metadata);
    Ok(())
}

fn web_log_fields_from_jsonl(
    index: usize,
    record: JsonlWebLogRecord,
) -> Result<ParsedWebLogFields, PortableCaptureLiteError> {
    let timestamp = timestamp_from_rfc3339(
        record
            .timestamp
            .as_deref()
            .or(record.time.as_deref())
            .or(record.ts.as_deref())
            .ok_or(PortableCaptureLiteError::Malformed(
                "jsonl_network_metadata",
            ))?,
    )?;
    let request_line = record.request.as_deref();
    let request_target = record
        .path
        .as_deref()
        .or(record.request_uri.as_deref())
        .or(record.uri.as_deref())
        .or_else(|| request_line.and_then(parse_request_target));
    let request_method = record
        .method
        .as_deref()
        .or(record.request_method.as_deref())
        .or_else(|| request_line.and_then(parse_request_method))
        .unwrap_or("GET");
    let parsed_target = request_target
        .filter(|target| target.contains("://"))
        .map(parse_url_parts)
        .transpose()?;
    let host_with_port = record
        .host
        .as_deref()
        .or(record.server_name.as_deref())
        .or(record.upstream_host.as_deref())
        .or(parsed_target.as_ref().map(|parts| parts.host.as_str()));
    let (host_raw, port_override) = host_with_port
        .map(parse_host_with_optional_port)
        .transpose()?
        .unwrap_or((None, None));
    let scheme = record
        .scheme
        .or_else(|| parsed_target.as_ref().map(|parts| parts.scheme.clone()))
        .unwrap_or_else(|| {
            if port_override == Some(443) {
                "https"
            } else {
                "http"
            }
            .to_string()
        });
    let dst_port = record
        .dst_port
        .or(port_override)
        .or_else(|| parsed_target.as_ref().and_then(|parts| parts.port))
        .unwrap_or(default_port(&scheme));
    let path_visible = request_target.map(ToString::to_string).or_else(|| {
        parsed_target
            .as_ref()
            .and_then(|parts| parts.path_and_query.clone())
    });
    let dst_ip = parse_web_log_destination_ip(
        index,
        record
            .dst_ip
            .as_deref()
            .or(record.upstream_ip.as_deref())
            .or(record.upstream_addr.as_deref()),
        host_raw.as_deref(),
    )?;

    Ok(ParsedWebLogFields {
        timestamp,
        src_ip: parse_ip(
            record
                .src_ip
                .as_deref()
                .or(record.client_ip.as_deref())
                .or(record.remote_addr.as_deref())
                .unwrap_or("192.0.2.10"),
        )?,
        src_port: synthetic_local_port(index),
        dst_ip,
        dst_port,
        direction: NetworkDirection::Inbound,
        duration_millis: record
            .duration_millis
            .or(record.duration_ms)
            .or(record.request_time_ms)
            .or_else(|| {
                record
                    .request_time
                    .map(|seconds| (seconds * 1000.0).round() as u64)
            })
            .unwrap_or(0),
        bytes_in: record
            .bytes_in
            .or(record.request_size_bytes)
            .or(record.request_length)
            .unwrap_or(0),
        bytes_out: record
            .bytes_out
            .or(record.response_size_bytes)
            .or(record.body_bytes_sent)
            .unwrap_or(0),
        scheme,
        host_raw,
        path_visible,
        method: parse_http_method(request_method),
        status_code: record
            .status_code
            .or(record.status)
            .or(record.upstream_status),
        user_agent_family: http_user_agent_family(
            record
                .user_agent
                .as_deref()
                .or(record.http_user_agent.as_deref()),
        ),
        content_type: record.content_type,
        result_label: record
            .result_label
            .or_else(|| Some("web_access_log_observed".to_string())),
        waf_action: record.waf_action.or(record.action).or_else(|| {
            record
                .blocked
                .filter(|blocked| *blocked)
                .map(|_| "blocked".to_string())
        }),
        waf_rule_id: record.waf_rule_id.or(record.rule_id),
        waf_attack_class: record.waf_attack_class.or(record.attack_class),
        redaction_applied: parsed_target
            .as_ref()
            .is_some_and(|parts| parts.redaction_applied)
            || record.blocked.unwrap_or(false),
    })
}

fn web_log_fields_from_access_line(
    index: usize,
    line: &str,
) -> Result<ParsedWebLogFields, PortableCaptureLiteError> {
    let timestamp_start = line
        .find('[')
        .ok_or(PortableCaptureLiteError::Malformed("web_access_log"))?;
    let timestamp_end = line[timestamp_start + 1..]
        .find(']')
        .map(|offset| timestamp_start + 1 + offset)
        .ok_or(PortableCaptureLiteError::Malformed("web_access_log"))?;
    let timestamp = DateTime::parse_from_str(
        &line[timestamp_start + 1..timestamp_end],
        "%d/%b/%Y:%H:%M:%S %z",
    )
    .map(|parsed| Timestamp::from_datetime(parsed.with_timezone(&Utc)))
    .map_err(PortableCaptureLiteError::from)?;
    let src_ip = parse_ip(
        line.split_whitespace()
            .next()
            .ok_or(PortableCaptureLiteError::Malformed("web_access_log"))?,
    )?;

    let quoted = line.split('"').collect::<Vec<_>>();
    if quoted.len() < 2 {
        return Err(PortableCaptureLiteError::Malformed("web_access_log"));
    }
    let request_line = quoted[1];
    let method = parse_http_method(parse_request_method(request_line).unwrap_or("GET"));
    let target = parse_request_target(request_line).unwrap_or("/");
    let parsed_target = target
        .contains("://")
        .then(|| parse_url_parts(target))
        .transpose()?;
    let scheme = parsed_target
        .as_ref()
        .map(|parts| parts.scheme.clone())
        .unwrap_or_else(|| "http".to_string());
    let host_raw = parsed_target.as_ref().map(|parts| parts.host.clone());
    let path_visible = parsed_target
        .as_ref()
        .and_then(|parts| parts.path_and_query.clone())
        .or_else(|| Some(target.to_string()));
    let status_and_size = quoted
        .get(2)
        .ok_or(PortableCaptureLiteError::Malformed("web_access_log"))?
        .split_whitespace()
        .collect::<Vec<_>>();
    let status_code = status_and_size
        .first()
        .and_then(|value| value.parse::<u16>().ok());
    let bytes_out = status_and_size
        .get(1)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);

    Ok(ParsedWebLogFields {
        timestamp,
        src_ip,
        src_port: synthetic_local_port(index),
        dst_ip: synthetic_local_ip(index),
        dst_port: parsed_target
            .as_ref()
            .and_then(|parts| parts.port)
            .unwrap_or(default_port(&scheme)),
        direction: NetworkDirection::Inbound,
        duration_millis: 0,
        bytes_in: 0,
        bytes_out,
        scheme,
        host_raw,
        path_visible,
        method,
        status_code,
        user_agent_family: quoted
            .get(5)
            .and_then(|value| http_user_agent_family(Some(value))),
        content_type: None,
        result_label: Some("web_access_log_observed".to_string()),
        waf_action: None,
        waf_rule_id: None,
        waf_attack_class: None,
        redaction_applied: target.contains('?'),
    })
}

fn parse_request_method(value: &str) -> Option<&str> {
    value.split_whitespace().next()
}

fn parse_request_target(value: &str) -> Option<&str> {
    value.split_whitespace().nth(1)
}

fn parse_host_with_optional_port(
    value: &str,
) -> Result<(Option<String>, Option<u16>), PortableCaptureLiteError> {
    if value.trim().is_empty() {
        return Ok((None, None));
    }
    if value.starts_with('[') {
        let closing = value
            .find(']')
            .ok_or(PortableCaptureLiteError::Malformed("web_access_log"))?;
        let host = value[1..closing].to_string();
        let port = value[closing + 1..]
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok());
        return Ok((Some(host), port));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if port.chars().all(|character| character.is_ascii_digit()) && !host.contains(':') {
            return Ok((Some(host.to_string()), port.parse::<u16>().ok()));
        }
    }
    Ok((Some(value.to_string()), None))
}

fn parse_web_log_destination_ip(
    index: usize,
    value: Option<&str>,
    host: Option<&str>,
) -> Result<IpAddress, PortableCaptureLiteError> {
    if let Some(value) = value {
        let candidate = value
            .rsplit_once(':')
            .filter(|(host, port)| !host.contains(':') && port.parse::<u16>().is_ok())
            .map(|(host, _)| host)
            .unwrap_or(value);
        if let Ok(ip) = IpAddress::parse_str(candidate) {
            return Ok(ip);
        }
    }
    destination_ip(None, host, index)
}

fn portable_capture_lite_dag() -> Result<PipelineDag, PortableCaptureLiteError> {
    let mut dag = PipelineDag::new("portable capture lite import pipeline")?;
    let source = dag.add_node(PipelineNode::new(
        "portable imported metadata source",
        PipelineStage::Source,
        StageBinding::metadata_only(
            Vec::new(),
            topic_names(&[
                NETWORK_FLOW_RECORD,
                NETWORK_SESSION_RECORD,
                NETWORK_DNS_OBSERVATION,
                NETWORK_TLS_OBSERVATION,
                NETWORK_HTTP_METADATA,
                IDENTITY_AUTH_METADATA,
                CLOUD_SAAS_METADATA,
                DECEPTION_EVENT_METADATA,
                SERVICE_CAPABILITY_STATUS,
                SECURITY_FUSION_CONTEXT,
            ])?,
        ),
    )?)?;
    let detection = dag.add_node(
        PipelineNode::new(
            "portable imported exfiltration detection",
            PipelineStage::Detection,
            StageBinding::metadata_only(
                topic_names(&[
                    NETWORK_FLOW_RECORD,
                    NETWORK_SESSION_RECORD,
                    NETWORK_DNS_OBSERVATION,
                    NETWORK_TLS_OBSERVATION,
                    NETWORK_HTTP_METADATA,
                    IDENTITY_AUTH_METADATA,
                    CLOUD_SAAS_METADATA,
                    DECEPTION_EVENT_METADATA,
                    SECURITY_FINDING,
                    SECURITY_FUSION_CONTEXT,
                ])?,
                topic_names(&[
                    SECURITY_FINDING,
                    SECURITY_EVIDENCE,
                    "security.risk_hint",
                    GRAPH_HINT,
                    SECURITY_FACT,
                    SECURITY_HYPOTHESIS,
                    SECURITY_FUSION_SUMMARY,
                ])?,
            ),
        )?
        .depends_on(source.clone()),
    )?;
    dag.add_node(
        PipelineNode::new(
            "portable imported risk alerting",
            PipelineStage::Risk,
            StageBinding::metadata_only(
                topic_names(&[
                    SECURITY_FINDING,
                    SECURITY_EVIDENCE,
                    "security.risk_hint",
                    SERVICE_CAPABILITY_STATUS,
                ])?,
                topic_names(&[
                    SECURITY_RISK,
                    ALERT_CANDIDATE_CONTRACT,
                    SECURITY_ALERT,
                    INCIDENT_CANDIDATE_CONTRACT,
                    SECURITY_INCIDENT,
                ])?,
            ),
        )?
        .depends_on(detection),
    )?;
    Ok(dag)
}

fn publish_source_stage(
    bus: &mut EventBus,
    source_plugin_id: &PluginId,
    trace_context: &TraceContext,
    prepared: &PortableCaptureLitePreparedBatch,
    service_contexts: &[ServiceCapabilityContext],
    emitted_topics: &mut BTreeSet<String>,
) -> Result<SourceStageEvents, PortableCaptureLiteError> {
    let mut events = SourceStageEvents::default();
    let fusion_context_event = source_event(
        source_plugin_id,
        SECURITY_FUSION_CONTEXT,
        &prepared.provenance,
        QualityScore::new(0.9)
            .map_err(|error| PortableCaptureLiteError::Contract(error.to_string()))?,
        trace_context.clone(),
    )?;
    publish_event(bus, SECURITY_FUSION_CONTEXT, fusion_context_event.clone())?;
    emitted_topics.insert(SECURITY_FUSION_CONTEXT.to_string());
    events.fusion_context_events.push(fusion_context_event);
    for flow in &prepared.flow_records {
        let event = source_event(
            source_plugin_id,
            NETWORK_FLOW_RECORD,
            flow,
            flow.quality_score.clone(),
            trace_context.clone(),
        )?;
        publish_event(bus, NETWORK_FLOW_RECORD, event.clone())?;
        emitted_topics.insert(NETWORK_FLOW_RECORD.to_string());
        events.flow_events.push(event);
    }
    for session in &prepared.session_records {
        let event = source_event(
            source_plugin_id,
            NETWORK_SESSION_RECORD,
            session,
            session.quality_score.clone(),
            trace_context.clone(),
        )?;
        publish_event(bus, NETWORK_SESSION_RECORD, event.clone())?;
        emitted_topics.insert(NETWORK_SESSION_RECORD.to_string());
        events.session_events.push(event);
    }
    for dns in &prepared.dns_observations {
        let event = source_event(
            source_plugin_id,
            NETWORK_DNS_OBSERVATION,
            dns,
            dns.quality_score.clone(),
            trace_context.clone(),
        )?;
        publish_event(bus, NETWORK_DNS_OBSERVATION, event.clone())?;
        emitted_topics.insert(NETWORK_DNS_OBSERVATION.to_string());
        events.dns_events.push(event);
    }
    for tls in &prepared.tls_observations {
        let event = source_event(
            source_plugin_id,
            NETWORK_TLS_OBSERVATION,
            tls,
            tls.quality_score.clone(),
            trace_context.clone(),
        )?;
        publish_event(bus, NETWORK_TLS_OBSERVATION, event.clone())?;
        emitted_topics.insert(NETWORK_TLS_OBSERVATION.to_string());
        events.tls_events.push(event);
    }
    for http in &prepared.http_metadata {
        let event = source_event(
            source_plugin_id,
            NETWORK_HTTP_METADATA,
            http,
            http.quality_score.clone(),
            trace_context.clone(),
        )?;
        publish_event(bus, NETWORK_HTTP_METADATA, event.clone())?;
        emitted_topics.insert(NETWORK_HTTP_METADATA.to_string());
        events.http_events.push(event);
    }
    for auth_metadata in &prepared.auth_metadata {
        let event = source_event(
            source_plugin_id,
            IDENTITY_AUTH_METADATA,
            auth_metadata,
            auth_metadata.quality_score.clone(),
            trace_context.clone(),
        )?;
        publish_event(bus, IDENTITY_AUTH_METADATA, event.clone())?;
        emitted_topics.insert(IDENTITY_AUTH_METADATA.to_string());
        events.auth_events.push(event);
    }
    for saas_cloud_metadata in &prepared.saas_cloud_metadata {
        let event = source_event(
            source_plugin_id,
            CLOUD_SAAS_METADATA,
            saas_cloud_metadata,
            saas_cloud_metadata.quality_score.clone(),
            trace_context.clone(),
        )?;
        publish_event(bus, CLOUD_SAAS_METADATA, event.clone())?;
        emitted_topics.insert(CLOUD_SAAS_METADATA.to_string());
        events.saas_cloud_events.push(event);
    }
    for deception_event in &prepared.deception_events {
        let event = source_event(
            source_plugin_id,
            DECEPTION_EVENT_METADATA,
            deception_event,
            deception_event.quality_score.clone(),
            trace_context.clone(),
        )?;
        publish_event(bus, DECEPTION_EVENT_METADATA, event.clone())?;
        emitted_topics.insert(DECEPTION_EVENT_METADATA.to_string());
        events.deception_events.push(event);
    }
    for service_context in service_contexts {
        let event = source_event(
            source_plugin_id,
            SERVICE_CAPABILITY_STATUS,
            service_context,
            QualityScore::new(0.82)
                .map_err(|error| PortableCaptureLiteError::Contract(error.to_string()))?,
            trace_context.clone(),
        )?;
        publish_event(bus, SERVICE_CAPABILITY_STATUS, event.clone())?;
        emitted_topics.insert(SERVICE_CAPABILITY_STATUS.to_string());
        events.service_context_events.push(event);
    }
    Ok(events)
}

#[allow(clippy::too_many_arguments)]
fn run_detection_stage(
    bus: &mut EventBus,
    trace_context: &TraceContext,
    source: &mut SourceStageEvents,
    findings: &mut Vec<Finding>,
    evidence: &mut Vec<EvidenceItem>,
    graph_hints: &mut Vec<GraphHint>,
    security_facts: &mut Vec<SecurityFact>,
    attack_hypotheses: &mut Vec<AttackHypothesisRecord>,
    fusion_summary: &mut Option<FusionSummary>,
    emitted_topics: &mut BTreeSet<String>,
) -> Result<(), PortableCaptureLiteError> {
    if source.flow_events.is_empty()
        && source.dns_events.is_empty()
        && source.http_events.is_empty()
        && source.auth_events.is_empty()
        && source.saas_cloud_events.is_empty()
        && source.deception_events.is_empty()
    {
        return Ok(());
    }

    run_detection_plugin(
        bus,
        trace_context,
        source.dns_events.clone(),
        register_static_dns_security_v2_plugin,
        "static dns security v2 manifest missing",
        findings,
        evidence,
        graph_hints,
        &mut source.risk_hint_events,
        &mut source.finding_events,
        emitted_topics,
    )?;
    run_detection_plugin(
        bus,
        trace_context,
        source
            .flow_events
            .iter()
            .chain(source.session_events.iter())
            .chain(source.auth_events.iter())
            .cloned()
            .collect(),
        register_static_auth_identity_analysis_lite_plugin,
        "static auth identity analysis lite manifest missing",
        findings,
        evidence,
        graph_hints,
        &mut source.risk_hint_events,
        &mut source.finding_events,
        emitted_topics,
    )?;
    run_detection_plugin(
        bus,
        trace_context,
        source
            .flow_events
            .iter()
            .chain(source.session_events.iter())
            .chain(source.http_events.iter())
            .cloned()
            .collect(),
        register_static_http_analysis_v1_plugin,
        "static http analysis v1 manifest missing",
        findings,
        evidence,
        graph_hints,
        &mut source.risk_hint_events,
        &mut source.finding_events,
        emitted_topics,
    )?;
    run_detection_plugin(
        bus,
        trace_context,
        source
            .flow_events
            .iter()
            .chain(source.tls_events.iter())
            .chain(source.http_events.iter())
            .cloned()
            .collect(),
        register_static_quic_http3_security_lite_plugin,
        "static quic http3 security lite manifest missing",
        findings,
        evidence,
        graph_hints,
        &mut source.risk_hint_events,
        &mut source.finding_events,
        emitted_topics,
    )?;
    run_detection_plugin(
        bus,
        trace_context,
        source
            .flow_events
            .iter()
            .chain(source.session_events.iter())
            .cloned()
            .collect(),
        register_static_remote_admin_protocol_lite_plugin,
        "static remote admin protocol lite manifest missing",
        findings,
        evidence,
        graph_hints,
        &mut source.risk_hint_events,
        &mut source.finding_events,
        emitted_topics,
    )?;
    run_detection_plugin(
        bus,
        trace_context,
        source
            .flow_events
            .iter()
            .chain(source.http_events.iter())
            .cloned()
            .collect(),
        register_static_api_security_lite_plugin,
        "static api security lite manifest missing",
        findings,
        evidence,
        graph_hints,
        &mut source.risk_hint_events,
        &mut source.finding_events,
        emitted_topics,
    )?;
    run_detection_plugin(
        bus,
        trace_context,
        source
            .flow_events
            .iter()
            .chain(source.http_events.iter())
            .cloned()
            .collect(),
        register_static_waf_security_lite_plugin,
        "static waf security lite manifest missing",
        findings,
        evidence,
        graph_hints,
        &mut source.risk_hint_events,
        &mut source.finding_events,
        emitted_topics,
    )?;
    run_detection_plugin(
        bus,
        trace_context,
        source
            .saas_cloud_events
            .iter()
            .chain(source.auth_events.iter())
            .chain(source.http_events.iter())
            .chain(source.finding_events.iter())
            .cloned()
            .collect(),
        register_static_portable_saas_cloud_abuse_lite_plugin,
        "static saas cloud abuse lite manifest missing",
        findings,
        evidence,
        graph_hints,
        &mut source.risk_hint_events,
        &mut source.finding_events,
        emitted_topics,
    )?;
    run_detection_plugin(
        bus,
        trace_context,
        source
            .deception_events
            .iter()
            .chain(source.finding_events.iter())
            .chain(source.risk_hint_events.iter())
            .cloned()
            .collect(),
        register_static_deception_event_lite_plugin,
        "static deception event lite manifest missing",
        findings,
        evidence,
        graph_hints,
        &mut source.risk_hint_events,
        &mut source.finding_events,
        emitted_topics,
    )?;
    run_detection_plugin(
        bus,
        trace_context,
        source
            .flow_events
            .iter()
            .chain(source.session_events.iter())
            .chain(source.http_events.iter())
            .cloned()
            .collect(),
        register_static_exfiltration_detection_plugin,
        "static exfiltration manifest missing",
        findings,
        evidence,
        graph_hints,
        &mut source.risk_hint_events,
        &mut source.finding_events,
        emitted_topics,
    )?;
    run_fusion_plugin(
        bus,
        trace_context,
        source
            .fusion_context_events
            .iter()
            .chain(source.dns_events.iter())
            .chain(source.http_events.iter())
            .chain(source.auth_events.iter())
            .chain(source.saas_cloud_events.iter())
            .chain(source.deception_events.iter())
            .chain(source.finding_events.iter())
            .cloned()
            .collect(),
        findings,
        evidence,
        graph_hints,
        &mut source.risk_hint_events,
        &mut source.finding_events,
        security_facts,
        attack_hypotheses,
        fusion_summary,
        emitted_topics,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_detection_plugin(
    bus: &mut EventBus,
    trace_context: &TraceContext,
    batch_events: Vec<EventEnvelope>,
    register_plugin: fn(&mut PluginRuntime) -> sentinel_platform::PluginResult<PluginId>,
    missing_manifest_message: &str,
    findings: &mut Vec<Finding>,
    evidence: &mut Vec<EvidenceItem>,
    graph_hints: &mut Vec<GraphHint>,
    risk_hint_events: &mut Vec<EventEnvelope>,
    finding_events: &mut Vec<EventEnvelope>,
    emitted_topics: &mut BTreeSet<String>,
) -> Result<(), PortableCaptureLiteError> {
    if batch_events.is_empty() {
        return Ok(());
    }

    let mut runtime = PluginRuntime::new();
    let plugin_id = register_plugin(&mut runtime)?;
    let manifest = runtime
        .manifest(&plugin_id)
        .ok_or_else(|| PortableCaptureLiteError::Runtime(missing_manifest_message.to_string()))?
        .clone();
    let contracts = contract_registry_for_manifest(&manifest)?;
    let mut permissions = PermissionResolver::new();
    permissions.register_plugin_manifest_permissions(&manifest);
    let validation = runtime
        .registry()
        .validate_startup(&plugin_id, &contracts, &permissions)?;
    let mut context = plugin_context_for_manifest(&manifest, trace_context.clone())?;
    runtime.start_plugin(&plugin_id, &validation, &mut context)?;

    let mut batch = PluginEventBatch::new(plugin_id.clone(), batch_events.len());
    for event in batch_events {
        batch.push(event)?;
    }
    let output = runtime.process_batch(&plugin_id, &mut context, &batch)?;
    for event in output.events {
        emitted_topics.insert(event.event_type.as_str().to_string());
        publish_event(bus, event.event_type.as_str(), event.clone())?;
        match event.event_type.as_str() {
            SECURITY_FINDING => {
                findings.push(serde_json::from_value(event.payload.clone())?);
                finding_events.push(event.clone());
            }
            SECURITY_EVIDENCE => evidence.push(serde_json::from_value(event.payload)?),
            "security.risk_hint" => risk_hint_events.push(event.clone()),
            GRAPH_HINT => graph_hints.push(serde_json::from_value(event.payload)?),
            _ => {}
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_fusion_plugin(
    bus: &mut EventBus,
    trace_context: &TraceContext,
    batch_events: Vec<EventEnvelope>,
    findings: &mut Vec<Finding>,
    evidence: &mut Vec<EvidenceItem>,
    graph_hints: &mut Vec<GraphHint>,
    risk_hint_events: &mut Vec<EventEnvelope>,
    finding_events: &mut Vec<EventEnvelope>,
    security_facts: &mut Vec<SecurityFact>,
    attack_hypotheses: &mut Vec<AttackHypothesisRecord>,
    fusion_summary: &mut Option<FusionSummary>,
    emitted_topics: &mut BTreeSet<String>,
) -> Result<(), PortableCaptureLiteError> {
    let mut runtime = PluginRuntime::new();
    let plugin_id = register_static_multi_layer_security_fusion_plugin(&mut runtime)?;
    let manifest = runtime
        .manifest(&plugin_id)
        .ok_or_else(|| {
            PortableCaptureLiteError::Runtime(
                "static multi-layer fusion manifest missing".to_string(),
            )
        })?
        .clone();
    let contracts = contract_registry_for_manifest(&manifest)?;
    let mut permissions = PermissionResolver::new();
    permissions.register_plugin_manifest_permissions(&manifest);
    let validation = runtime
        .registry()
        .validate_startup(&plugin_id, &contracts, &permissions)?;
    let mut context = plugin_context_for_manifest(&manifest, trace_context.clone())?;
    runtime.start_plugin(&plugin_id, &validation, &mut context)?;

    let mut batch = PluginEventBatch::new(plugin_id.clone(), batch_events.len());
    for event in batch_events {
        batch.push(event)?;
    }
    let output = runtime.process_batch(&plugin_id, &mut context, &batch)?;
    for event in output.events {
        emitted_topics.insert(event.event_type.as_str().to_string());
        publish_event(bus, event.event_type.as_str(), event.clone())?;
        match event.event_type.as_str() {
            SECURITY_FACT => security_facts.push(serde_json::from_value(event.payload)?),
            SECURITY_HYPOTHESIS => attack_hypotheses.push(serde_json::from_value(event.payload)?),
            SECURITY_FUSION_SUMMARY => {
                *fusion_summary = Some(serde_json::from_value(event.payload)?)
            }
            SECURITY_FINDING => {
                findings.push(serde_json::from_value(event.payload.clone())?);
                finding_events.push(event);
            }
            SECURITY_EVIDENCE => evidence.push(serde_json::from_value(event.payload)?),
            "security.risk_hint" => risk_hint_events.push(event),
            GRAPH_HINT => graph_hints.push(serde_json::from_value(event.payload)?),
            _ => {}
        }
    }
    Ok(())
}

struct RiskStageOutput {
    risk_events: Vec<RiskEvent>,
    alerts: Vec<Alert>,
    incidents: Vec<Incident>,
    alert_candidate_count: usize,
    incident_candidate_count: usize,
}

fn run_risk_stage(
    bus: &mut EventBus,
    trace_context: &TraceContext,
    service_contexts: &[ServiceCapabilityContext],
    source: &SourceStageEvents,
    findings: &[Finding],
    evidence: &[EvidenceItem],
    emitted_topics: &mut BTreeSet<String>,
) -> Result<RiskStageOutput, PortableCaptureLiteError> {
    if findings.is_empty() {
        return Ok(RiskStageOutput {
            risk_events: Vec::new(),
            alerts: Vec::new(),
            incidents: Vec::new(),
            alert_candidate_count: 0,
            incident_candidate_count: 0,
        });
    }

    let mut runtime = PluginRuntime::new();
    let plugin_id = register_static_risk_alerting_plugin(&mut runtime)?;
    let manifest = runtime
        .manifest(&plugin_id)
        .ok_or_else(|| {
            PortableCaptureLiteError::Runtime("static risk manifest missing".to_string())
        })?
        .clone();
    let contracts = contract_registry_for_manifest(&manifest)?;
    let mut permissions = PermissionResolver::new();
    permissions.register_plugin_manifest_permissions(&manifest);
    let validation = runtime
        .registry()
        .validate_startup(&plugin_id, &contracts, &permissions)?;
    let mut context = plugin_context_for_manifest(&manifest, trace_context.clone())?;
    runtime.start_plugin(&plugin_id, &validation, &mut context)?;

    let mut batch = PluginEventBatch::new(
        plugin_id.clone(),
        findings.len()
            + evidence.len()
            + source.service_context_events.len()
            + source.risk_hint_events.len(),
    );
    for item in evidence {
        batch.push(source_event(
            &plugin_id,
            SECURITY_EVIDENCE,
            item,
            item.confidence.clone(),
            trace_context.clone(),
        )?)?;
    }
    for context_event in &source.service_context_events {
        batch.push(context_event.clone())?;
    }
    for risk_hint_event in &source.risk_hint_events {
        batch.push(risk_hint_event.clone())?;
    }
    for finding in findings {
        batch.push(source_event(
            &plugin_id,
            SECURITY_FINDING,
            finding,
            finding.confidence().clone(),
            trace_context.clone(),
        )?)?;
    }
    if service_contexts.is_empty() {
        return Err(PortableCaptureLiteError::Runtime(
            "portable capture risk stage requires bounded service context".to_string(),
        ));
    }

    let output = runtime.process_batch(&plugin_id, &mut context, &batch)?;
    let mut risk_events = Vec::new();
    let mut alerts = Vec::new();
    let mut incidents = Vec::new();
    let mut alert_candidate_count = 0usize;
    let mut incident_candidate_count = 0usize;

    for event in output.events {
        emitted_topics.insert(event.event_type.as_str().to_string());
        publish_event(bus, event.event_type.as_str(), event.clone())?;
        match event.event_type.as_str() {
            SECURITY_RISK => risk_events.push(serde_json::from_value(event.payload)?),
            ALERT_CANDIDATE_CONTRACT => alert_candidate_count += 1,
            SECURITY_ALERT => alerts.push(serde_json::from_value(event.payload)?),
            INCIDENT_CANDIDATE_CONTRACT => incident_candidate_count += 1,
            SECURITY_INCIDENT => incidents.push(serde_json::from_value(event.payload)?),
            _ => {}
        }
    }

    Ok(RiskStageOutput {
        risk_events,
        alerts,
        incidents,
        alert_candidate_count,
        incident_candidate_count,
    })
}

fn portable_service_capability_contexts(
    provenance_id: DataSourceId,
    runtime_service_contexts: &[ServiceCapabilityContext],
) -> Result<Vec<ServiceCapabilityContext>, PortableCaptureLiteError> {
    let observed_at = Timestamp::now();
    let mut contexts = vec![
        service_context(
            "portable_import_capture",
            ServiceAdapterMode::MetadataOnly,
            ServiceCapabilityStatus::Degraded,
            Some(ServiceReasonCode::CaptureUnavailable),
            vec![
                ServiceLimitationFlag::LocalOnly,
                ServiceLimitationFlag::MetadataOnly,
                ServiceLimitationFlag::NoRawContentRetention,
                ServiceLimitationFlag::NoPrivilegedCapture,
                ServiceLimitationFlag::ReducedVisibility,
                ServiceLimitationFlag::NoProductionServiceLifecycle,
            ],
            &provenance_id.to_string(),
            observed_at.clone(),
        )?,
        service_context(
            "portable_import_process_attribution",
            ServiceAdapterMode::Disabled,
            ServiceCapabilityStatus::Unavailable,
            Some(ServiceReasonCode::ProcessAttributionLimited),
            vec![
                ServiceLimitationFlag::MetadataOnly,
                ServiceLimitationFlag::NoProcessAttribution,
                ServiceLimitationFlag::ReducedVisibility,
                ServiceLimitationFlag::NoProductionServiceLifecycle,
            ],
            &format!("{}-process", provenance_id),
            observed_at,
        )?,
    ];

    for context in runtime_service_contexts {
        context
            .validate_boundary()
            .map_err(|error| PortableCaptureLiteError::Contract(error.to_string()))?;
        contexts.push(context.clone());
    }

    Ok(contexts)
}

fn service_context(
    capability_id: &str,
    adapter_mode: ServiceAdapterMode,
    status: ServiceCapabilityStatus,
    reason_code: Option<ServiceReasonCode>,
    limitation_flags: Vec<ServiceLimitationFlag>,
    source_provenance_id: &str,
    observed_at: Timestamp,
) -> Result<ServiceCapabilityContext, PortableCaptureLiteError> {
    let mut context =
        ServiceCapabilityContext::new(capability_id, adapter_mode, status, source_provenance_id)
            .map_err(|error| PortableCaptureLiteError::Contract(error.to_string()))?;
    context.reason_code = reason_code;
    context.limitation_flags = limitation_flags;
    context.observed_at = observed_at;
    context
        .validate_boundary()
        .map_err(|error| PortableCaptureLiteError::Contract(error.to_string()))?;
    Ok(context)
}

fn contract_registry_for_manifest(
    manifest: &sentinel_contracts::PluginManifest,
) -> Result<ContractRegistry, PortableCaptureLiteError> {
    let mut registry = ContractRegistry::new();
    for contract in manifest
        .input_contracts
        .iter()
        .chain(manifest.output_contracts.iter())
    {
        registry
            .register(contract.clone())
            .map_err(|error| PortableCaptureLiteError::Runtime(error.to_string()))?;
    }
    Ok(registry)
}

fn plugin_context_for_manifest(
    manifest: &sentinel_contracts::PluginManifest,
    trace_context: TraceContext,
) -> Result<PluginContext<'static>, PortableCaptureLiteError> {
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
    context.policy_scope = sentinel_platform::PolicyScope::Plugin;
    context.current_permission_scope = Some(sentinel_platform::PermissionScope::Data {
        resource: "portable_capture_import".to_string(),
        operation: "metadata_only".to_string(),
        metadata_only: true,
    });
    context.checkpoint = sentinel_platform::CheckpointSupport::from_manifest_level(
        manifest.checkpoint_support.clone(),
    );
    context.replay =
        sentinel_platform::ReplaySupport::from_manifest_level(manifest.replay_support.clone());
    Ok(context)
}

fn topic_for_contract(
    contract: &ContractDescriptor,
) -> Result<TopicName, PortableCaptureLiteError> {
    TopicName::new(
        contract
            .topic
            .as_deref()
            .unwrap_or(contract.contract_name.as_str()),
    )
    .map_err(|error| PortableCaptureLiteError::Runtime(error.to_string()))
}

fn ensure_topic_registered(
    bus: &mut EventBus,
    topic_name: &str,
    layer: TopicLayer,
    priority: PriorityLane,
) -> Result<(), PortableCaptureLiteError> {
    let topic_name = topic(topic_name)?;
    if bus.topic(&topic_name).is_none() {
        bus.register_topic(Topic::new(
            topic_name,
            layer,
            PORTABLE_CAPTURE_LITE_SCHEMA_VERSION,
            priority,
        ));
    }
    Ok(())
}

fn publish_event(
    bus: &mut EventBus,
    topic_name: &str,
    event: EventEnvelope,
) -> Result<(), PortableCaptureLiteError> {
    bus.publish(
        topic(topic_name)?,
        event,
        PublishOptions::new("portable imported metadata only"),
    )?;
    Ok(())
}

fn source_event<T: serde::Serialize>(
    producer_plugin: &PluginId,
    event_type: &str,
    payload: &T,
    quality_score: QualityScore,
    trace_context: TraceContext,
) -> Result<EventEnvelope, PortableCaptureLiteError> {
    let mut event = EventEnvelope::new(
        EventType::new(event_type)
            .map_err(|error| PortableCaptureLiteError::Contract(error.to_string()))?,
        PORTABLE_CAPTURE_LITE_SCHEMA_VERSION,
        producer_plugin.clone(),
        trace_context,
    );
    event.privacy_class = PrivacyClass::Internal;
    event.quality_score = quality_score;
    event.payload = serde_json::to_value(payload)?;
    Ok(event)
}

fn topic(name: &str) -> Result<TopicName, PortableCaptureLiteError> {
    TopicName::new(name).map_err(|error| PortableCaptureLiteError::Runtime(error.to_string()))
}

fn topic_names(values: &[&str]) -> Result<Vec<TopicName>, PortableCaptureLiteError> {
    values.iter().map(|value| topic(value)).collect()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DeclaredTopicFlags {
    has_flow: bool,
    has_session: bool,
    has_dns: bool,
    has_tls: bool,
    has_http: bool,
    has_auth: bool,
    has_saas_cloud: bool,
    has_deception: bool,
}

fn declared_topics(flags: DeclaredTopicFlags) -> Vec<String> {
    let mut topics = vec![
        SERVICE_CAPABILITY_STATUS.to_string(),
        SECURITY_FUSION_CONTEXT.to_string(),
    ];
    if flags.has_flow {
        topics.push(NETWORK_FLOW_RECORD.to_string());
    }
    if flags.has_session {
        topics.push(NETWORK_SESSION_RECORD.to_string());
    }
    if flags.has_dns {
        topics.push(NETWORK_DNS_OBSERVATION.to_string());
    }
    if flags.has_tls {
        topics.push(NETWORK_TLS_OBSERVATION.to_string());
    }
    if flags.has_http {
        topics.push(NETWORK_HTTP_METADATA.to_string());
    }
    if flags.has_auth {
        topics.push(IDENTITY_AUTH_METADATA.to_string());
    }
    if flags.has_saas_cloud {
        topics.push(CLOUD_SAAS_METADATA.to_string());
    }
    if flags.has_deception {
        topics.push(DECEPTION_EVENT_METADATA.to_string());
    }
    topics.extend([
        SECURITY_FINDING.to_string(),
        SECURITY_EVIDENCE.to_string(),
        "security.risk_hint".to_string(),
        SECURITY_RISK.to_string(),
        ALERT_CANDIDATE_CONTRACT.to_string(),
        SECURITY_ALERT.to_string(),
        INCIDENT_CANDIDATE_CONTRACT.to_string(),
        SECURITY_INCIDENT.to_string(),
        GRAPH_HINT.to_string(),
        SECURITY_FACT.to_string(),
        SECURITY_HYPOTHESIS.to_string(),
        SECURITY_FUSION_SUMMARY.to_string(),
    ]);
    topics
}

fn build_portable_auth_summary(
    provenance_id: &DataSourceId,
    auth_metadata: &[PortableAuthMetadata],
    findings: &[Finding],
    evidence: &[EvidenceItem],
    graph_hints: &[GraphHint],
) -> Option<PortableAuthSummary> {
    if auth_metadata.is_empty() {
        return None;
    }

    let auth_findings = findings
        .iter()
        .filter(|finding| {
            finding
                .finding_type()
                .starts_with("portable.auth_identity_analysis_lite.")
        })
        .collect::<Vec<_>>();
    let auth_evidence = evidence
        .iter()
        .filter(|item| {
            item.evidence_type
                .starts_with("portable.auth_identity_analysis_lite.")
        })
        .collect::<Vec<_>>();
    let auth_evidence_refs = auth_evidence
        .iter()
        .map(|item| item.evidence_id.to_string())
        .collect::<BTreeSet<_>>();

    let mut provider_counts = BTreeMap::<String, u32>::new();
    let mut service_outcome_counts = BTreeMap::<(String, PortableAuthResultCategory), u32>::new();
    let mut source_sessions = BTreeSet::new();
    let mut degraded_flags = BTreeSet::new();
    let privileged_role_record_count = auth_metadata
        .iter()
        .filter(|item| item.role_privilege_class.as_deref() == Some("privileged"))
        .count() as u32;

    for item in auth_metadata {
        *provider_counts
            .entry(item.provider_category.clone())
            .or_insert(0) += 1;
        *service_outcome_counts
            .entry((
                item.destination_service_category
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                item.auth_result.clone(),
            ))
            .or_insert(0) += 1;
        if let Some(session) = item.source_session_label.as_deref() {
            source_sessions.insert(session.to_string());
        }
        if item.identity_label_redacted.is_none() {
            degraded_flags.insert("missing_identity".to_string());
        }
        if item.source_session_label.is_none() {
            degraded_flags.insert("missing_source_session".to_string());
        }
        if item.mfa_result.is_none() {
            degraded_flags.insert("missing_mfa".to_string());
        }
        if item.role_privilege_class.is_none() {
            degraded_flags.insert("missing_role".to_string());
        }
        if item.destination_service_category.is_none() {
            degraded_flags.insert("missing_service_category".to_string());
        }
    }

    let failure_count = auth_metadata
        .iter()
        .filter(|item| {
            matches!(
                item.auth_result,
                PortableAuthResultCategory::Failure
                    | PortableAuthResultCategory::Blocked
                    | PortableAuthResultCategory::Timeout
            )
        })
        .count();
    let identity_session_risk_bucket = if auth_findings.iter().any(|finding| {
        matches!(
            finding.severity(),
            &sentinel_contracts::SecuritySeverity::High
                | &sentinel_contracts::SecuritySeverity::Critical
        )
    }) || auth_findings.len() >= 3
    {
        PortableAuthRiskBucket::High
    } else if !auth_findings.is_empty() || failure_count >= 3 || privileged_role_record_count > 0 {
        PortableAuthRiskBucket::Medium
    } else {
        PortableAuthRiskBucket::Low
    };

    let first_seen_category_flags = auth_findings
        .iter()
        .filter_map(|finding| {
            finding
                .finding_type()
                .contains("first_seen_identity_provider_combination")
                .then_some("identity_provider_combination".to_string())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let graph_hint_refs = graph_hints
        .iter()
        .filter(|hint| {
            hint.evidence_refs
                .iter()
                .any(|reference| auth_evidence_refs.contains(&reference.to_string()))
        })
        .map(|hint| hint.hint_id.clone())
        .collect();

    Some(PortableAuthSummary {
        provenance_id: provenance_id.clone(),
        auth_record_count: auth_metadata.len() as u32,
        identity_session_risk_bucket,
        source_session_count: source_sessions.len() as u32,
        provider_category_counts: provider_counts
            .into_iter()
            .map(|(category, count)| PortableAuthCategoryCount { category, count })
            .collect(),
        service_outcome_counts: service_outcome_counts
            .into_iter()
            .map(
                |((service_category, auth_result), count)| PortableAuthServiceOutcomeCount {
                    service_category,
                    auth_result,
                    count,
                },
            )
            .collect(),
        first_seen_category_flags,
        privileged_role_record_count,
        degraded_visibility_flags: degraded_flags.into_iter().collect(),
        finding_refs: auth_findings
            .iter()
            .map(|finding| finding.id().clone())
            .collect(),
        evidence_refs: auth_evidence
            .iter()
            .map(|item| item.evidence_id.clone())
            .collect(),
        graph_hint_refs,
    })
}

fn build_portable_saas_cloud_summary(
    provenance_id: &DataSourceId,
    metadata: &[PortableSaasCloudMetadata],
    findings: &[Finding],
    evidence: &[EvidenceItem],
    graph_hints: &[GraphHint],
) -> Option<PortableSaasCloudSummary> {
    if metadata.is_empty() {
        return None;
    }

    let saas_findings = findings
        .iter()
        .filter(|finding| {
            finding
                .finding_type()
                .starts_with("portable.saas_cloud_abuse_lite.")
        })
        .collect::<Vec<_>>();
    let saas_evidence = evidence
        .iter()
        .filter(|item| {
            item.evidence_type
                .starts_with("portable.saas_cloud_abuse_lite.")
        })
        .collect::<Vec<_>>();
    let saas_evidence_refs = saas_evidence
        .iter()
        .map(|item| item.evidence_id.to_string())
        .collect::<BTreeSet<_>>();

    let mut provider_counts = BTreeMap::<String, u32>::new();
    let mut provider_risk_counts = BTreeMap::<String, u32>::new();
    let mut degraded_flags = BTreeSet::new();
    let mut unknown_provider_count = 0u32;

    for item in metadata {
        *provider_counts
            .entry(portable_provider_category_label(&item.provider_category).to_string())
            .or_insert(0) += 1;
        *provider_risk_counts
            .entry(portable_provider_risk_label(&item.provider_risk_category).to_string())
            .or_insert(0) += 1;
        if item.provider_category == PortableProviderCategory::Unknown {
            unknown_provider_count += 1;
            degraded_flags.insert("unknown_provider_category".to_string());
        }
        if matches!(
            item.provider_confidence,
            PortableProviderConfidenceBucket::Low | PortableProviderConfidenceBucket::Unknown
        ) {
            degraded_flags.insert("provider_classification_confidence_limited".to_string());
        }
        if item.endpoint_fingerprint.is_none() {
            degraded_flags.insert("missing_endpoint_fingerprint".to_string());
        }
        if item.identity_label_redacted.is_none() {
            degraded_flags.insert("missing_redacted_identity".to_string());
        }
        if item.source_session_label.is_none() {
            degraded_flags.insert("missing_source_session".to_string());
        }
    }

    let graph_hint_refs = graph_hints
        .iter()
        .filter(|hint| {
            hint.evidence_refs
                .iter()
                .any(|reference| saas_evidence_refs.contains(&reference.to_string()))
        })
        .map(|hint| hint.hint_id.clone())
        .collect();

    Some(PortableSaasCloudSummary {
        provenance_id: provenance_id.clone(),
        metadata_record_count: metadata.len() as u32,
        provider_category_counts: provider_counts
            .into_iter()
            .map(|(category, count)| PortableSaasCloudCategoryCount { category, count })
            .collect(),
        provider_risk_counts: provider_risk_counts
            .into_iter()
            .map(|(category, count)| PortableSaasCloudCategoryCount { category, count })
            .collect(),
        unknown_provider_count,
        degraded_visibility_flags: degraded_flags.into_iter().collect(),
        finding_refs: saas_findings
            .iter()
            .map(|finding| finding.id().clone())
            .collect(),
        evidence_refs: saas_evidence
            .iter()
            .map(|item| item.evidence_id.clone())
            .collect(),
        graph_hint_refs,
    })
}

fn build_portable_deception_summary(
    provenance_id: &DataSourceId,
    events: &[PortableDeceptionEventMetadata],
    findings: &[Finding],
    evidence: &[EvidenceItem],
    graph_hints: &[GraphHint],
) -> Option<PortableDeceptionSummary> {
    if events.is_empty() {
        return None;
    }

    let deception_findings = findings
        .iter()
        .filter(|finding| {
            finding
                .finding_type()
                .starts_with("portable.deception_event_lite.")
        })
        .collect::<Vec<_>>();
    let deception_evidence = evidence
        .iter()
        .filter(|item| {
            item.evidence_type
                .starts_with("portable.deception_event_lite.")
        })
        .collect::<Vec<_>>();
    let deception_evidence_refs = deception_evidence
        .iter()
        .map(|item| item.evidence_id.to_string())
        .collect::<BTreeSet<_>>();

    let mut decoy_sensors = BTreeSet::new();
    let mut event_counts = BTreeMap::<String, u32>::new();
    let mut protocol_counts = BTreeMap::<String, u32>::new();
    let mut degraded_flags = BTreeSet::new();

    for item in events {
        if let Some(sensor) = item.decoy_sensor_ref.as_deref() {
            decoy_sensors.insert(sensor.to_string());
        } else {
            degraded_flags.insert("missing_decoy_sensor".to_string());
        }
        *event_counts.entry(item.event_category.clone()).or_insert(0) += 1;
        *protocol_counts
            .entry(portable_deception_protocol_label(&item.protocol_category).to_string())
            .or_insert(0) += 1;
        if item.source_context_category.is_none() {
            degraded_flags.insert("missing_source_context".to_string());
        }
        if item.destination_service_category.is_none() {
            degraded_flags.insert("missing_destination_service".to_string());
        }
        if matches!(
            item.protocol_category,
            PortableDeceptionProtocolCategory::Unknown
        ) {
            degraded_flags.insert("unknown_protocol".to_string());
        }
        if matches!(
            item.interaction_count_bucket,
            PortableDecoyInteractionCountBucket::Unknown
        ) {
            degraded_flags.insert("unknown_interaction_count".to_string());
        }
    }

    let graph_hint_refs = graph_hints
        .iter()
        .filter(|hint| {
            hint.evidence_refs
                .iter()
                .any(|reference| deception_evidence_refs.contains(&reference.to_string()))
        })
        .map(|hint| hint.hint_id.clone())
        .collect();

    Some(PortableDeceptionSummary {
        provenance_id: provenance_id.clone(),
        event_record_count: events.len() as u32,
        decoy_sensor_count: decoy_sensors.len() as u32,
        event_category_counts: event_counts
            .into_iter()
            .map(|(category, count)| PortableDeceptionCategoryCount { category, count })
            .collect(),
        protocol_category_counts: protocol_counts
            .into_iter()
            .map(|(category, count)| PortableDeceptionCategoryCount { category, count })
            .collect(),
        degraded_visibility_flags: degraded_flags.into_iter().collect(),
        finding_refs: deception_findings
            .iter()
            .map(|finding| finding.id().clone())
            .collect(),
        evidence_refs: deception_evidence
            .iter()
            .map(|item| item.evidence_id.clone())
            .collect(),
        graph_hint_refs,
    })
}

fn portable_provider_category_label(category: &PortableProviderCategory) -> &'static str {
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

fn portable_deception_protocol_label(category: &PortableDeceptionProtocolCategory) -> &'static str {
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

fn portable_provider_risk_label(category: &PortableProviderRiskCategory) -> &'static str {
    match category {
        PortableProviderRiskCategory::Low => "low",
        PortableProviderRiskCategory::Medium => "medium",
        PortableProviderRiskCategory::High => "high",
        PortableProviderRiskCategory::Unknown => "unknown",
    }
}

fn timestamp_from_rfc3339(value: &str) -> Result<Timestamp, PortableCaptureLiteError> {
    let parsed = DateTime::parse_from_rfc3339(value)?;
    Ok(Timestamp::from_datetime(parsed.with_timezone(&Utc)))
}

fn timestamp_plus_millis(timestamp: &Timestamp, millis: u64) -> Timestamp {
    Timestamp::from_datetime(
        timestamp.as_datetime().to_owned() + Duration::milliseconds(millis as i64),
    )
}

fn q(value: f32) -> Result<QualityScore, PortableCaptureLiteError> {
    QualityScore::new(value).map_err(|error| PortableCaptureLiteError::Contract(error.to_string()))
}

fn parse_ip(value: &str) -> Result<IpAddress, PortableCaptureLiteError> {
    IpAddress::parse_str(value).map_err(|error| PortableCaptureLiteError::Parse(error.to_string()))
}

fn synthetic_local_ip(index: usize) -> IpAddress {
    IpAddress::from(IpAddr::V4(Ipv4Addr::new(
        192,
        0,
        2,
        SYNTHETIC_LOCAL_IP_OCTET_BASE.saturating_add(index as u8),
    )))
}

fn destination_ip(
    server_ip: Option<&str>,
    host: Option<&str>,
    index: usize,
) -> Result<IpAddress, PortableCaptureLiteError> {
    if let Some(server_ip) = server_ip {
        return parse_ip(server_ip);
    }
    if let Some(host) = host {
        if let Ok(ip) = IpAddress::parse_str(host) {
            return Ok(ip);
        }
        let hash = stable_hash(host);
        let octet = SYNTHETIC_REMOTE_IP_OCTET_BASE + (hash[0] % 200);
        return Ok(IpAddress::from(IpAddr::V4(Ipv4Addr::new(
            198, 51, 100, octet,
        ))));
    }
    Ok(IpAddress::from(IpAddr::V4(Ipv4Addr::new(
        198,
        51,
        100,
        SYNTHETIC_REMOTE_IP_OCTET_BASE.saturating_add(index as u8),
    ))))
}

fn synthetic_local_port(index: usize) -> u16 {
    49_152 + (index as u16 % 8_192)
}

fn parse_http_method(value: &str) -> HttpMethod {
    match value.trim().to_ascii_uppercase().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        "TRACE" => HttpMethod::Trace,
        "CONNECT" => HttpMethod::Connect,
        _ => HttpMethod::Other,
    }
}

fn default_port(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("http") {
        80
    } else {
        443
    }
}

fn har_size(value: Option<i64>) -> u64 {
    positive_u64(value).unwrap_or(0)
}

fn positive_u64(value: Option<i64>) -> Option<u64> {
    value.and_then(|value| (value >= 0).then_some(value as u64))
}

fn redact_host(host: &str) -> (String, bool) {
    if host.parse::<IpAddr>().is_ok() {
        (host.to_ascii_lowercase(), false)
    } else {
        (format!("host#{}", stable_hash_hex(host, 12)), true)
    }
}

fn redact_domain(value: &str) -> String {
    format!("domain#{}", stable_hash_hex(value, 12))
}

fn redact_text(label: &str, value: &str) -> String {
    format!("{label}#{}", stable_hash_hex(value, 12))
}

fn sanitize_path_input(path_and_query: Option<&str>) -> (Option<String>, bool) {
    let Some(path_and_query) = path_and_query else {
        return (None, false);
    };
    let path = path_and_query.split('#').next().unwrap_or_default();
    let had_query = path.contains('?');
    let stripped = path.split('?').next().unwrap_or_default();
    let path = if contains_local_path(stripped) || contains_private_marker(stripped) {
        "/redacted/{id}".to_string()
    } else {
        stripped
            .split('/')
            .map(|segment| {
                if segment.parse::<u64>().is_ok()
                    || looks_like_hex_identifier(segment)
                    || looks_like_secret_token(segment)
                {
                    "{id}".to_string()
                } else {
                    segment.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    };
    (
        Some(path),
        had_query || contains_local_path(stripped) || contains_private_marker(stripped),
    )
}

fn har_headers_redacted(headers: Option<&[HarHeader]>) -> bool {
    headers.is_some_and(|headers| {
        headers.iter().any(|header| {
            let name = header.name.to_ascii_lowercase();
            matches!(
                name.as_str(),
                "authorization" | "cookie" | "set-cookie" | "x-api-key" | "proxy-authorization"
            ) || contains_local_path(&header.value)
                || contains_private_marker(&header.value)
                || looks_like_secret_token(&header.value)
        })
    })
}

fn har_user_agent_family(headers: Option<&[HarHeader]>) -> Option<String> {
    headers
        .and_then(|headers| {
            headers.iter().find(|header| {
                header.name.eq_ignore_ascii_case("user-agent")
                    || header.name.eq_ignore_ascii_case("user_agent")
            })
        })
        .and_then(|header| http_user_agent_family(Some(&header.value)))
}

fn http_user_agent_family(value: Option<&str>) -> Option<String> {
    let value = value?.to_ascii_lowercase();
    if value.contains("curl") {
        Some("curl".to_string())
    } else if value.contains("python-requests") {
        Some("python_requests".to_string())
    } else if value.contains("powershell") {
        Some("powershell".to_string())
    } else if value.contains("firefox") {
        Some("firefox".to_string())
    } else if value.contains("chrome") || value.contains("chromium") {
        Some("chromium".to_string())
    } else if value.contains("edge") {
        Some("edge".to_string())
    } else if value.trim().is_empty() {
        None
    } else {
        Some("other".to_string())
    }
}

fn jsonl_http_fields(
    record: &JsonlHttpRecord,
) -> Result<JsonlHttpFields, PortableCaptureLiteError> {
    let mut redaction_applied = false;
    if let Some(url) = &record.url {
        let url_parts = parse_url_parts(url)?;
        let (host, host_redaction) = redact_host(&url_parts.host);
        let (path, path_redaction) = sanitize_path_input(url_parts.path_and_query.as_deref());
        redaction_applied |= url_parts.redaction_applied || host_redaction || path_redaction;
        return Ok(JsonlHttpFields {
            scheme: Some(url_parts.scheme),
            host_protected: Some(host),
            path_visible: path,
            redaction_applied,
        });
    }
    let host = record.host.as_deref().map(redact_host);
    let (host_protected, host_redaction) = match host {
        Some((host, redaction)) => (Some(host), redaction),
        None => (None, false),
    };
    let (path_visible, path_redaction) = sanitize_path_input(record.path.as_deref());
    redaction_applied |= host_redaction || path_redaction;
    Ok(JsonlHttpFields {
        scheme: None,
        host_protected,
        path_visible,
        redaction_applied,
    })
}

fn jsonl_dns_answer(answer: JsonlDnsAnswer) -> Result<DnsAnswer, PortableCaptureLiteError> {
    match answer.answer_type.as_deref().unwrap_or("ip") {
        "ip" => Ok(DnsAnswer::Ip {
            address: parse_ip(answer.value.as_deref().ok_or(
                PortableCaptureLiteError::Malformed("jsonl_network_metadata"),
            )?)?,
            ttl_seconds: answer.ttl_seconds,
        }),
        "cname" => Ok(DnsAnswer::Cname {
            name_protected: redact_domain(answer.value.as_deref().ok_or(
                PortableCaptureLiteError::Malformed("jsonl_network_metadata"),
            )?),
            ttl_seconds: answer.ttl_seconds,
        }),
        _ => Ok(DnsAnswer::Other {
            summary_protected: redact_text(
                "dns-answer",
                answer
                    .value
                    .as_deref()
                    .ok_or(PortableCaptureLiteError::Malformed(
                        "jsonl_network_metadata",
                    ))?,
            ),
            ttl_seconds: answer.ttl_seconds,
        }),
    }
}

fn contains_private_marker(value: &str) -> bool {
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '/', '=', ':', '\\'], "_");
    [
        "authorization",
        "api_key",
        "cookie",
        "credential",
        "password",
        "private_key",
        "session_token",
        "access_token",
        "refresh_token",
        "token",
        "secret",
        "form_content",
    ]
    .into_iter()
    .any(|marker| normalized.contains(marker))
}

fn contains_local_path(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("file:///")
        || normalized.contains(":\\")
        || normalized.contains("\\users\\")
        || normalized.contains("/users/")
        || normalized.contains("/home/")
        || normalized.contains("/var/")
        || normalized.contains("%appdata%")
        || normalized.contains("%localappdata%")
}

fn looks_like_hex_identifier(value: &str) -> bool {
    value.len() >= 12 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn looks_like_secret_token(value: &str) -> bool {
    let trimmed = value.trim_matches(|character: char| {
        character == '"' || character == '\'' || character == ';' || character == ','
    });
    trimmed.len() > 24
        && trimmed.chars().any(|ch| ch.is_ascii_lowercase())
        && trimmed.chars().any(|ch| ch.is_ascii_uppercase())
        && trimmed.chars().any(|ch| ch.is_ascii_digit())
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '='))
}

fn stable_hash(value: &str) -> [u8; 32] {
    let digest = Sha256::digest(value.as_bytes());
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn stable_hash_hex(value: &str, limit: usize) -> String {
    let digest = stable_hash(value);
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .chars()
        .take(limit)
        .collect()
}

#[derive(Deserialize)]
struct HarArchive {
    log: HarLog,
}

#[derive(Deserialize)]
struct HarLog {
    entries: Vec<HarEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HarEntry {
    started_date_time: String,
    #[serde(default)]
    time: Option<f64>,
    #[serde(default)]
    server_ip_address: Option<String>,
    request: HarRequest,
    response: HarResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HarRequest {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    headers_size: Option<i64>,
    #[serde(default)]
    body_size: Option<i64>,
    #[serde(default)]
    headers: Option<Vec<HarHeader>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HarResponse {
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    headers_size: Option<i64>,
    #[serde(default)]
    body_size: Option<i64>,
    #[serde(default)]
    headers: Option<Vec<HarHeader>>,
    #[serde(default)]
    content: Option<HarContent>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HarContent {
    #[serde(default)]
    mime_type: Option<String>,
    #[serde(default)]
    size: Option<i64>,
}

#[derive(Deserialize)]
struct HarHeader {
    name: String,
    value: String,
}

struct ParsedUrlParts {
    scheme: String,
    host: String,
    port: Option<u16>,
    path_and_query: Option<String>,
    redaction_applied: bool,
}

fn parse_url_parts(value: &str) -> Result<ParsedUrlParts, PortableCaptureLiteError> {
    let (scheme, remainder) = value
        .split_once("://")
        .ok_or(PortableCaptureLiteError::Malformed("har"))?;
    if scheme.eq_ignore_ascii_case("file") {
        return Err(PortableCaptureLiteError::Malformed("har"));
    }
    let slash_index = remainder.find('/').unwrap_or(remainder.len());
    let host_port_and_userinfo = &remainder[..slash_index];
    let path_and_query =
        (slash_index < remainder.len()).then(|| remainder[slash_index..].to_string());
    let had_userinfo = host_port_and_userinfo.contains('@');
    let host_port = host_port_and_userinfo
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(host_port_and_userinfo);
    let (host, port) = if host_port.starts_with('[') {
        let closing = host_port
            .find(']')
            .ok_or(PortableCaptureLiteError::Malformed("har"))?;
        let host = host_port[1..closing].to_string();
        let port = host_port[closing + 1..]
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok());
        (host, port)
    } else if let Some((host, port)) = host_port.rsplit_once(':') {
        if port.chars().all(|ch| ch.is_ascii_digit()) {
            (host.to_string(), port.parse::<u16>().ok())
        } else {
            (host_port.to_string(), None)
        }
    } else {
        (host_port.to_string(), None)
    };

    if host.trim().is_empty() {
        return Err(PortableCaptureLiteError::Malformed("har"));
    }

    Ok(ParsedUrlParts {
        scheme: scheme.to_ascii_lowercase(),
        host,
        port,
        path_and_query,
        redaction_applied: had_userinfo || value.contains('?'),
    })
}

#[derive(Deserialize)]
struct JsonlNetworkRecord {
    timestamp: String,
    #[serde(default)]
    src_ip: Option<String>,
    #[serde(default)]
    src_port: Option<u16>,
    #[serde(default)]
    dst_ip: Option<String>,
    #[serde(default)]
    dst_port: Option<u16>,
    #[serde(default)]
    protocol: Option<TransportProtocol>,
    #[serde(default)]
    direction: Option<NetworkDirection>,
    #[serde(default)]
    duration_millis: Option<u64>,
    #[serde(default)]
    bytes_in: Option<u64>,
    #[serde(default)]
    bytes_out: Option<u64>,
    #[serde(default)]
    packets_in: Option<u64>,
    #[serde(default)]
    packets_out: Option<u64>,
    #[serde(default)]
    dns: Option<JsonlDnsRecord>,
    #[serde(default)]
    tls: Option<JsonlTlsRecord>,
    #[serde(default)]
    http: Option<JsonlHttpRecord>,
}

#[derive(Deserialize)]
struct JsonlHttpRecord {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    status_code: Option<u16>,
    #[serde(default)]
    request_size_bytes: Option<u64>,
    #[serde(default)]
    response_size_bytes: Option<u64>,
    #[serde(default)]
    request_content_length_bytes: Option<u64>,
    #[serde(default)]
    response_content_length_bytes: Option<u64>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    result_label: Option<String>,
    #[serde(default)]
    waf_action: Option<String>,
    #[serde(default)]
    waf_rule_id: Option<String>,
    #[serde(default)]
    waf_attack_class: Option<String>,
}

#[derive(Deserialize)]
struct JsonlWebLogRecord {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    ts: Option<String>,
    #[serde(default)]
    remote_addr: Option<String>,
    #[serde(default)]
    client_ip: Option<String>,
    #[serde(default)]
    src_ip: Option<String>,
    #[serde(default)]
    dst_ip: Option<String>,
    #[serde(default)]
    dst_port: Option<u16>,
    #[serde(default)]
    upstream_ip: Option<String>,
    #[serde(default)]
    upstream_addr: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    upstream_host: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    request_method: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    request_uri: Option<String>,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    request: Option<String>,
    #[serde(default)]
    scheme: Option<String>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    status_code: Option<u16>,
    #[serde(default)]
    upstream_status: Option<u16>,
    #[serde(default)]
    duration_millis: Option<u64>,
    #[serde(default)]
    duration_ms: Option<u64>,
    #[serde(default)]
    request_time_ms: Option<u64>,
    #[serde(default)]
    request_time: Option<f64>,
    #[serde(default)]
    bytes_in: Option<u64>,
    #[serde(default)]
    request_size_bytes: Option<u64>,
    #[serde(default)]
    request_length: Option<u64>,
    #[serde(default)]
    bytes_out: Option<u64>,
    #[serde(default)]
    response_size_bytes: Option<u64>,
    #[serde(default)]
    body_bytes_sent: Option<u64>,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    http_user_agent: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    result_label: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    waf_action: Option<String>,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    waf_rule_id: Option<String>,
    #[serde(default)]
    attack_class: Option<String>,
    #[serde(default)]
    waf_attack_class: Option<String>,
    #[serde(default)]
    blocked: Option<bool>,
}

#[derive(Deserialize)]
struct JsonlSaasCloudRecord {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    ts: Option<String>,
    #[serde(default)]
    provider_category: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    service_category: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    provider_risk_category: Option<String>,
    #[serde(default)]
    provider_confidence: Option<String>,
    #[serde(default)]
    endpoint_fingerprint: Option<String>,
    #[serde(default)]
    route_fingerprint: Option<String>,
    #[serde(default)]
    api_endpoint_fingerprint: Option<String>,
    #[serde(default)]
    api_method_category: Option<String>,
    #[serde(default)]
    method_category: Option<String>,
    #[serde(default)]
    api_method: Option<String>,
    #[serde(default)]
    status_bucket: Option<String>,
    #[serde(default)]
    status_code: Option<u16>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    upload_download_ratio_bucket: Option<String>,
    #[serde(default)]
    upload_download_ratio: Option<f32>,
    #[serde(default)]
    request_size_bytes: Option<u64>,
    #[serde(default)]
    response_size_bytes: Option<u64>,
    #[serde(default)]
    auth_result: Option<String>,
    #[serde(default)]
    identity_hash: Option<String>,
    #[serde(default)]
    user_hash: Option<String>,
    #[serde(default)]
    identity: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    source_session: Option<String>,
    #[serde(default)]
    session: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    connection_id: Option<String>,
    #[serde(default)]
    destination_category: Option<String>,
    #[serde(default)]
    host_category: Option<String>,
}

#[derive(Deserialize)]
struct JsonlDeceptionEventRecord {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    ts: Option<String>,
    #[serde(default)]
    decoy_sensor_ref: Option<String>,
    #[serde(default)]
    decoy_ref: Option<String>,
    #[serde(default)]
    sensor_ref: Option<String>,
    #[serde(default)]
    sensor: Option<String>,
    #[serde(default)]
    decoy: Option<String>,
    #[serde(default)]
    event_category: Option<String>,
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    interaction_category: Option<String>,
    #[serde(default)]
    source_context_category: Option<String>,
    #[serde(default)]
    source_context: Option<String>,
    #[serde(default)]
    source_category: Option<String>,
    #[serde(default)]
    destination_service_category: Option<String>,
    #[serde(default)]
    destination_category: Option<String>,
    #[serde(default)]
    service_category: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    interaction_count_bucket: Option<String>,
    #[serde(default)]
    interaction_count: Option<u32>,
    #[serde(default)]
    count: Option<u32>,
    #[serde(default)]
    protocol_category: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
}

#[derive(Deserialize)]
struct JsonlAuthRecord {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    ts: Option<String>,
    #[serde(default)]
    provider_category: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    source_type: Option<String>,
    #[serde(default)]
    identity: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    identity_hash: Option<String>,
    #[serde(default)]
    user_hash: Option<String>,
    #[serde(default)]
    session: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    connection_id: Option<String>,
    #[serde(default)]
    auth_result: Option<String>,
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    mfa_result: Option<String>,
    #[serde(default)]
    mfa_status: Option<String>,
    #[serde(default)]
    mfa: Option<String>,
    #[serde(default)]
    role_class: Option<String>,
    #[serde(default)]
    privilege_class: Option<String>,
    #[serde(default)]
    device_category: Option<String>,
    #[serde(default)]
    client_category: Option<String>,
    #[serde(default)]
    client_type: Option<String>,
    #[serde(default)]
    destination_service: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    attempt_count: Option<u32>,
    #[serde(default)]
    attempts: Option<u32>,
    #[serde(default)]
    failure_reason: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct JsonlDnsRecord {
    query_name: String,
    #[serde(default)]
    query_type: Option<String>,
    #[serde(default)]
    response_code: Option<String>,
    resolver_ip: String,
    client_ip: String,
    #[serde(default)]
    answers: Option<Vec<JsonlDnsAnswer>>,
    #[serde(default)]
    cname_chain: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct JsonlDnsAnswer {
    #[serde(default)]
    answer_type: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    ttl_seconds: Option<u32>,
}

#[derive(Deserialize)]
struct JsonlTlsRecord {
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    alpn: Option<Vec<String>>,
    #[serde(default)]
    tls_version: Option<String>,
    #[serde(default)]
    cipher_suite: Option<String>,
    #[serde(default)]
    extension_summary: Option<String>,
    #[serde(default)]
    certificate_fingerprint: Option<String>,
    #[serde(default)]
    issuer_summary: Option<String>,
    #[serde(default)]
    san_summary: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn har_fixture() -> String {
        serde_json::json!({
            "log": {
                "entries": [
                    {
                        "startedDateTime": "2026-06-11T02:00:00Z",
                        "time": 150,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://uploader.example.test/upload/42?access_token=secret",
                            "headersSize": 240,
                            "bodySize": 64000,
                            "headers": [
                                { "name": "User-Agent", "value": "curl/8.8.0" },
                                { "name": "Authorization", "value": "Bearer super-secret-token-value" }
                            ]
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 180,
                            "bodySize": 1024,
                            "headers": [],
                            "content": { "mimeType": "application/json", "size": 1024 }
                        }
                    },
                    {
                        "startedDateTime": "2026-06-11T02:00:10Z",
                        "time": 80,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://uploader.example.test/upload/43?user=alice",
                            "headersSize": 220,
                            "bodySize": 1024,
                            "headers": [
                                { "name": "User-Agent", "value": "curl/8.8.0" }
                            ]
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 180,
                            "bodySize": 120,
                            "headers": [],
                            "content": { "mimeType": "application/json", "size": 120 }
                        }
                    },
                    {
                        "startedDateTime": "2026-06-11T02:00:20Z",
                        "time": 75,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://uploader.example.test/upload/44?session_token=shh",
                            "headersSize": 220,
                            "bodySize": 1100,
                            "headers": [
                                { "name": "User-Agent", "value": "curl/8.8.0" }
                            ]
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 180,
                            "bodySize": 110,
                            "headers": [],
                            "content": { "mimeType": "application/json", "size": 110 }
                        }
                    },
                    {
                        "startedDateTime": "2026-06-11T02:00:30Z",
                        "time": 70,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://uploader.example.test/upload/45?path=C:/Users/Alice/Desktop",
                            "headersSize": 220,
                            "bodySize": 1200,
                            "headers": [
                                { "name": "User-Agent", "value": "curl/8.8.0" }
                            ]
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 180,
                            "bodySize": 100,
                            "headers": [],
                            "content": { "mimeType": "application/json", "size": 100 }
                        }
                    }
                ]
            }
        })
        .to_string()
    }

    fn jsonl_fixture() -> String {
        [
            serde_json::json!({
                "timestamp": "2026-06-11T10:05:00Z",
                "src_ip": "192.0.2.15",
                "src_port": 51515,
                "dst_ip": "203.0.113.22",
                "dst_port": 443,
                "protocol": "tcp",
                "direction": "outbound",
                "bytes_out": 72000,
                "bytes_in": 2200,
                "packets_out": 5,
                "packets_in": 3,
                "http": {
                    "method": "POST",
                    "url": "https://jsonl.example.test/upload/9?token=abcdef1234567890",
                    "status_code": 200,
                    "request_size_bytes": 72000,
                    "response_size_bytes": 2200,
                    "content_type": "application/json",
                    "user_agent": "python-requests/2.32.0"
                },
                "dns": {
                    "query_name": "api.jsonl.example.test",
                    "query_type": "A",
                    "resolver_ip": "192.0.2.53",
                    "client_ip": "192.0.2.15",
                    "answers": [{ "answer_type": "ip", "value": "203.0.113.22", "ttl_seconds": 60 }]
                },
                "tls": {
                    "sni": "api.jsonl.example.test",
                    "alpn": ["h2"],
                    "tls_version": "TLS1.3",
                    "cipher_suite": "TLS_AES_256_GCM_SHA384"
                }
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-11T10:05:30Z",
                "src_ip": "192.0.2.15",
                "src_port": 51516,
                "dst_ip": "203.0.113.22",
                "dst_port": 443,
                "protocol": "tcp",
                "direction": "outbound",
                "bytes_out": 76000,
                "bytes_in": 1800,
                "packets_out": 5,
                "packets_in": 2,
                "http": {
                    "method": "POST",
                    "url": "https://jsonl.example.test/upload/10?path=C:/Users/Alice/Desktop",
                    "status_code": 200,
                    "request_size_bytes": 76000,
                    "response_size_bytes": 1800,
                    "content_type": "application/json",
                    "user_agent": "python-requests/2.32.0"
                }
            })
            .to_string(),
        ]
        .join("\n")
    }

    fn auth_jsonl_fixture() -> String {
        [
            serde_json::json!({
                "timestamp": "2026-06-12T06:00:00Z",
                "provider": "vpn",
                "identity": "alice@example.test",
                "session_id": "alpha-session",
                "auth_result": "failed",
                "mfa_result": "prompted",
                "service": "ssh",
                "attempt_count": 3,
                "failure_reason": "invalid_password"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T06:02:00Z",
                "provider": "vpn",
                "identity": "alice@example.test",
                "session_id": "alpha-session",
                "auth_result": "failed",
                "mfa_result": "failed",
                "service": "ssh",
                "attempt_count": 4,
                "failure_reason": "invalid_password"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T06:04:00Z",
                "provider": "vpn",
                "identity": "alice@example.test",
                "session_id": "alpha-session",
                "auth_result": "failed",
                "mfa_result": "failed",
                "service": "ssh",
                "attempt_count": 5,
                "failure_reason": "invalid_password"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T06:10:00Z",
                "provider": "idp",
                "identity": "priv@example.test",
                "session_id": "beta-session",
                "auth_result": "success",
                "role_class": "admin",
                "service": "admin_portal",
                "attempt_count": 1
            })
            .to_string(),
        ]
        .join("\n")
    }

    fn saas_cloud_jsonl_fixture() -> String {
        [
            serde_json::json!({
                "timestamp": "2026-06-12T07:00:00Z",
                "provider_category": "object_storage",
                "service_category": "object_storage",
                "provider_risk_category": "medium",
                "provider_confidence": "high",
                "endpoint_fingerprint": "endpoint#object-storage",
                "api_method_category": "write",
                "status_bucket": "success",
                "upload_download_ratio_bucket": "upload_burst",
                "identity_hash": "identity-cloud-a",
                "session": "session-cloud-a",
                "destination_category": "object_storage"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T07:01:00Z",
                "provider_category": "object_storage",
                "service_category": "object_storage",
                "provider_risk_category": "medium",
                "provider_confidence": "high",
                "endpoint_fingerprint": "endpoint#object-storage",
                "api_method_category": "write",
                "status_bucket": "success",
                "upload_download_ratio_bucket": "upload_burst",
                "identity_hash": "identity-cloud-a",
                "session": "session-cloud-a",
                "destination_category": "object_storage"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T07:02:00Z",
                "provider_category": "cloud",
                "service_category": "api",
                "provider_risk_category": "low",
                "provider_confidence": "medium",
                "endpoint_fingerprint": "endpoint#cloud-api",
                "api_method_category": "write",
                "status_bucket": "server_error",
                "upload_download_ratio_bucket": "balanced",
                "destination_category": "cloud_api"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T07:03:00Z",
                "provider_category": "cloud",
                "service_category": "api",
                "provider_risk_category": "low",
                "provider_confidence": "medium",
                "endpoint_fingerprint": "endpoint#cloud-api",
                "api_method_category": "write",
                "status_bucket": "server_error",
                "upload_download_ratio_bucket": "balanced",
                "destination_category": "cloud_api"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T07:04:00Z",
                "provider_category": "cloud",
                "service_category": "api",
                "provider_risk_category": "low",
                "provider_confidence": "medium",
                "endpoint_fingerprint": "endpoint#cloud-api",
                "api_method_category": "write",
                "status_bucket": "server_error",
                "upload_download_ratio_bucket": "balanced",
                "destination_category": "cloud_api"
            })
            .to_string(),
        ]
        .join("\n")
    }

    fn deception_jsonl_fixture() -> String {
        [
            serde_json::json!({
                "timestamp": "2026-06-12T08:00:00Z",
                "decoy_sensor_ref": "edge-sensor-a",
                "event_category": "probe",
                "source_context_category": "external",
                "destination_service_category": "admin_service",
                "interaction_count": 12,
                "protocol_category": "ssh"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T08:01:00Z",
                "decoy_sensor_ref": "edge-sensor-a",
                "event_category": "probe",
                "source_context_category": "external",
                "destination_service_category": "admin_service",
                "interaction_count_bucket": "single",
                "protocol_category": "telnet"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T08:02:00Z",
                "decoy_sensor_ref": "edge-sensor-a",
                "event_category": "connection",
                "source_context_category": "external",
                "destination_service_category": "admin_service",
                "interaction_count_bucket": "low",
                "protocol_category": "http"
            })
            .to_string(),
        ]
        .join("\n")
    }

    #[test]
    fn network_har_import_preview_builds_bounded_metadata() {
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            &har_fixture(),
            har_fixture().len(),
        )
        .expect("har preview");

        assert_eq!(
            prepared.provenance.source_type,
            PortableCaptureInputSourceType::ImportedHar
        );
        assert_eq!(prepared.flow_records.len(), 4);
        assert_eq!(prepared.session_records.len(), 4);
        assert_eq!(prepared.tls_observations.len(), 4);
        assert_eq!(prepared.http_metadata.len(), 4);
        assert_eq!(
            prepared.provenance.redaction_status,
            RedactionStatus::Redacted
        );
    }

    #[test]
    fn network_jsonl_import_preview_builds_dns_tls_and_http_metadata() {
        let fixture = jsonl_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata,
            &fixture,
            fixture.len(),
        )
        .expect("jsonl preview");

        assert_eq!(
            prepared.provenance.source_type,
            PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata
        );
        assert_eq!(prepared.flow_records.len(), 2);
        assert_eq!(prepared.session_records.len(), 2);
        assert_eq!(prepared.dns_observations.len(), 1);
        assert_eq!(prepared.tls_observations.len(), 1);
        assert_eq!(prepared.http_metadata.len(), 2);
    }

    #[test]
    fn network_import_rejects_malformed_har() {
        let error = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            "{\"log\": {\"entries\": [}}",
            24,
        )
        .expect_err("malformed har rejected");

        assert!(error.to_string().contains("parse error"));
    }

    #[test]
    fn network_import_rejects_oversized_file() {
        let oversized = "x".repeat(MAX_PORTABLE_CAPTURE_IMPORT_BYTES + 1);
        let error = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata,
            &oversized,
            oversized.len(),
        )
        .expect_err("oversized file rejected");

        assert_eq!(error, PortableCaptureLiteError::OversizedFile);
    }

    #[test]
    fn network_import_rejects_local_proxy_as_file_input_source() {
        let error = preview_portable_capture_import(
            PortableCaptureInputSourceType::LocalProxyMetadata,
            "{}",
            2,
        )
        .expect_err("local proxy file preview rejected");

        assert_eq!(error, PortableCaptureLiteError::UnsupportedSourceType);
    }

    #[test]
    fn network_web_access_log_preview_builds_bounded_metadata() {
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedWebAccessLog,
            "127.0.0.1 - - [11/Jun/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 12",
            72,
        )
        .expect("web access log preview");

        assert_eq!(
            prepared.provenance.source_type,
            PortableCaptureInputSourceType::ImportedWebAccessLog
        );
        assert_eq!(prepared.flow_records.len(), 1);
        assert_eq!(prepared.session_records.len(), 1);
        assert_eq!(prepared.http_metadata.len(), 1);
        assert_eq!(prepared.dns_observations.len(), 0);
        assert_eq!(prepared.tls_observations.len(), 0);
        assert_eq!(prepared.http_metadata[0].method, HttpMethod::Get);
        assert_eq!(prepared.http_metadata[0].status_code, Some(200));
        assert_eq!(
            prepared.http_metadata[0].status_family.as_deref(),
            Some("2xx")
        );
        assert_eq!(
            prepared.http_metadata[0].path_template_protected.as_deref(),
            Some("/")
        );
        assert!(prepared
            .declared_topics
            .iter()
            .any(|topic| topic == NETWORK_HTTP_METADATA));
    }

    #[test]
    fn auth_security_log_preview_builds_hashed_bounded_metadata() {
        let fixture = auth_jsonl_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedAuthSecurityLog,
            &fixture,
            fixture.len(),
        )
        .expect("auth preview");

        assert_eq!(
            prepared.provenance.source_type,
            PortableCaptureInputSourceType::ImportedAuthSecurityLog
        );
        assert_eq!(prepared.auth_metadata.len(), 4);
        assert_eq!(prepared.flow_records.len(), 0);
        assert_eq!(prepared.session_records.len(), 0);
        assert_eq!(
            prepared.provenance.redaction_status,
            RedactionStatus::Hashed
        );
        assert!(prepared
            .declared_topics
            .iter()
            .any(|topic| topic == IDENTITY_AUTH_METADATA));
    }

    #[test]
    fn saas_cloud_metadata_preview_builds_bounded_metadata() {
        let fixture = saas_cloud_jsonl_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedSaasCloudMetadata,
            &fixture,
            fixture.len(),
        )
        .expect("saas cloud preview");

        assert_eq!(
            prepared.provenance.source_type,
            PortableCaptureInputSourceType::ImportedSaasCloudMetadata
        );
        assert_eq!(prepared.saas_cloud_metadata.len(), 5);
        assert_eq!(prepared.flow_records.len(), 0);
        assert_eq!(prepared.http_metadata.len(), 0);
        assert_eq!(
            prepared
                .provenance
                .record_counts
                .saas_cloud_metadata_records,
            5
        );
        assert!(prepared
            .declared_topics
            .iter()
            .any(|topic| topic == CLOUD_SAAS_METADATA));

        let serialized =
            serde_json::to_string(&prepared.saas_cloud_metadata).expect("serialize saas cloud");
        for marker in [
            "identity-cloud-a",
            "session-cloud-a",
            "https://",
            "authorization",
            "cookie",
            "tenant",
        ] {
            assert!(
                !serialized.contains(marker),
                "SaaS/cloud preview leaked forbidden marker {marker}"
            );
        }
        assert!(serialized.contains("identity#"));
        assert!(serialized.contains("session#"));
    }

    #[test]
    fn saas_cloud_metadata_import_rejects_sensitive_fields() {
        let fixture = serde_json::json!({
            "timestamp": "2026-06-12T07:00:00Z",
            "provider_category": "saas",
            "endpoint_fingerprint": "endpoint#safe",
            "url": "https://example.invalid/private?token=secret"
        })
        .to_string();

        let error = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedSaasCloudMetadata,
            &fixture,
            fixture.len(),
        )
        .expect_err("sensitive raw url rejected");

        assert_eq!(
            error,
            PortableCaptureLiteError::Malformed("saas_cloud_metadata")
        );
    }

    #[test]
    fn deception_event_log_preview_builds_bounded_metadata() {
        let fixture = deception_jsonl_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedDeceptionEventLog,
            &fixture,
            fixture.len(),
        )
        .expect("deception preview");

        assert_eq!(
            prepared.provenance.source_type,
            PortableCaptureInputSourceType::ImportedDeceptionEventLog
        );
        assert_eq!(prepared.deception_events.len(), 3);
        assert_eq!(prepared.flow_records.len(), 0);
        assert_eq!(prepared.http_metadata.len(), 0);
        assert_eq!(prepared.provenance.record_counts.deception_event_records, 3);
        assert!(prepared
            .declared_topics
            .iter()
            .any(|topic| topic == DECEPTION_EVENT_METADATA));

        let serialized =
            serde_json::to_string(&prepared.deception_events).expect("serialize deception events");
        for marker in [
            "edge-sensor-a",
            "source_ip",
            "192.0.2.",
            "https://",
            "payload",
            "credential",
            "token",
        ] {
            assert!(
                !serialized.contains(marker),
                "deception preview leaked forbidden marker {marker}"
            );
        }
        assert!(serialized.contains("sensor#"));
    }

    #[test]
    fn deception_event_log_rejects_sensitive_fields() {
        let fixture = serde_json::json!({
            "timestamp": "2026-06-12T08:00:00Z",
            "decoy_sensor_ref": "edge-sensor-a",
            "event_category": "probe",
            "protocol_category": "ssh",
            "source_ip": "192.0.2.99"
        })
        .to_string();

        let error = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedDeceptionEventLog,
            &fixture,
            fixture.len(),
        )
        .expect_err("sensitive source IP rejected");

        assert_eq!(
            error,
            PortableCaptureLiteError::Malformed("deception_event_log")
        );
    }

    #[test]
    fn network_import_redacts_private_markers_local_paths_and_tokens() {
        let fixture = jsonl_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata,
            &fixture,
            fixture.len(),
        )
        .expect("preview");
        let serialized = serde_json::to_string(&prepared.http_metadata).expect("serialize http");

        for marker in [
            "access_token",
            "token=abcdef1234567890",
            "C:/Users/Alice/Desktop",
            "alice",
        ] {
            assert!(
                !serialized.contains(marker),
                "serialized metadata leaked forbidden marker {marker}"
            );
        }
    }

    #[test]
    fn auth_import_redacts_identities_sessions_and_raw_markers() {
        let fixture = auth_jsonl_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedAuthSecurityLog,
            &fixture,
            fixture.len(),
        )
        .expect("auth preview");
        let serialized =
            serde_json::to_string(&prepared.auth_metadata).expect("serialize auth metadata");

        for marker in [
            "alice@example.test",
            "priv@example.test",
            "alpha-session",
            "beta-session",
        ] {
            assert!(
                !serialized.contains(marker),
                "serialized auth metadata leaked forbidden marker {marker}"
            );
        }
        assert!(serialized.contains("identity#"));
        assert!(serialized.contains("session#"));
    }

    #[test]
    fn static_portable_capture_import_emits_declared_topics_only() {
        let fixture = har_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            &fixture,
            fixture.len(),
        )
        .expect("preview");
        let result = run_portable_capture_lite(&prepared).expect("run portable import");

        let declared = prepared
            .declared_topics
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(result
            .emitted_topics
            .iter()
            .all(|topic| declared.contains(topic)));
        for forbidden in [
            "graph.update",
            "response.plan",
            "response.result",
            "response.rollback.result",
            "report.generated",
            "report.exported",
        ] {
            assert!(
                !result.emitted_topics.iter().any(|topic| topic == forbidden),
                "portable import emitted forbidden topic {forbidden}"
            );
        }
    }

    #[test]
    fn risk_portable_capture_import_reaches_alerting_path_from_multi_flow_metadata() {
        let fixture = har_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            &fixture,
            fixture.len(),
        )
        .expect("preview");
        let result = run_portable_capture_lite(&prepared).expect("run portable import");

        assert!(!result.findings.is_empty());
        assert!(!result.risk_events.is_empty());
        assert!(result.alert_candidate_count > 0 || !result.alerts.is_empty());
    }

    #[test]
    fn portable_auth_import_reaches_runtime_findings_and_summary_refs() {
        let fixture = auth_jsonl_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedAuthSecurityLog,
            &fixture,
            fixture.len(),
        )
        .expect("auth preview");
        let result = run_portable_capture_lite(&prepared).expect("run auth import");

        assert!(result.findings.iter().any(|finding| finding
            .finding_type()
            .contains("auth_identity_analysis_lite")));
        assert_eq!(result.auth_metadata.len(), 4);
        let summary = result.auth_summary.expect("auth summary");
        assert_eq!(summary.auth_record_count, 4);
        assert!(!summary.finding_refs.is_empty());
        assert!(!summary.evidence_refs.is_empty());
        assert!(!result.risk_events.is_empty());
    }

    #[test]
    fn portable_saas_cloud_import_reaches_runtime_findings_and_summary_refs() {
        let fixture = saas_cloud_jsonl_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedSaasCloudMetadata,
            &fixture,
            fixture.len(),
        )
        .expect("saas cloud preview");
        let result = run_portable_capture_lite(&prepared).expect("run saas cloud import");

        assert_eq!(result.saas_cloud_metadata.len(), 5);
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.finding_type().contains("saas_cloud_abuse_lite")));
        let summary = result.saas_cloud_summary.expect("saas cloud summary");
        assert_eq!(summary.metadata_record_count, 5);
        assert!(!summary.provider_category_counts.is_empty());
        assert!(!summary.finding_refs.is_empty());
        assert!(!summary.evidence_refs.is_empty());
        assert!(!result.risk_events.is_empty());
        assert!(result
            .emitted_topics
            .iter()
            .any(|topic| topic == CLOUD_SAAS_METADATA));
    }

    #[test]
    fn portable_deception_import_reaches_runtime_findings_and_summary_refs() {
        let fixture = deception_jsonl_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedDeceptionEventLog,
            &fixture,
            fixture.len(),
        )
        .expect("deception preview");
        let result = run_portable_capture_lite(&prepared).expect("run deception import");

        assert_eq!(result.deception_events.len(), 3);
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.finding_type().contains("deception_event_lite")));
        let summary = result.deception_summary.expect("deception summary");
        assert_eq!(summary.event_record_count, 3);
        assert_eq!(summary.decoy_sensor_count, 1);
        assert!(!summary.event_category_counts.is_empty());
        assert!(!summary.finding_refs.is_empty());
        assert!(!summary.evidence_refs.is_empty());
        assert!(!result.risk_events.is_empty());
        assert!(result
            .emitted_topics
            .iter()
            .any(|topic| topic == DECEPTION_EVENT_METADATA));

        let declared = prepared
            .declared_topics
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(result
            .emitted_topics
            .iter()
            .all(|topic| declared.contains(topic)));
    }

    #[test]
    fn portable_capture_jsonl_quic_and_remote_admin_slice_reaches_runtime_outputs() {
        let fixture = [
            serde_json::json!({
                "timestamp": "2026-06-12T04:00:00Z",
                "src_ip": "192.0.2.60",
                "src_port": 49152,
                "dst_ip": "203.0.113.60",
                "dst_port": 443,
                "protocol": "udp",
                "direction": "outbound",
                "duration_millis": 1200,
                "bytes_in": 2200,
                "bytes_out": 5400,
                "tls": {
                    "alpn": ["h3"]
                },
                "http": {
                    "method": "POST",
                    "url": "https://cdn-host.example.test/v1/sync/42?token=secret",
                    "status_code": 503,
                    "request_size_bytes": 2048,
                    "response_size_bytes": 512,
                    "result_label": "gateway_error"
                }
            }),
            serde_json::json!({
                "timestamp": "2026-06-12T04:00:05Z",
                "src_ip": "192.0.2.60",
                "src_port": 49153,
                "dst_ip": "203.0.113.60",
                "dst_port": 443,
                "protocol": "tcp",
                "direction": "outbound",
                "duration_millis": 900,
                "bytes_in": 2100,
                "bytes_out": 1800,
                "http": {
                    "method": "POST",
                    "url": "https://cdn-host.example.test/v1/sync/43",
                    "status_code": 200,
                    "request_size_bytes": 512,
                    "response_size_bytes": 256
                }
            }),
            serde_json::json!({
                "timestamp": "2026-06-12T04:10:00Z",
                "src_ip": "192.168.1.10",
                "src_port": 53000,
                "dst_ip": "192.168.1.21",
                "dst_port": 3389,
                "protocol": "tcp",
                "direction": "outbound"
            }),
            serde_json::json!({
                "timestamp": "2026-06-12T04:10:20Z",
                "src_ip": "192.168.1.10",
                "src_port": 53001,
                "dst_ip": "192.168.1.22",
                "dst_port": 3389,
                "protocol": "tcp",
                "direction": "outbound"
            }),
            serde_json::json!({
                "timestamp": "2026-06-12T04:10:40Z",
                "src_ip": "192.168.1.10",
                "src_port": 53002,
                "dst_ip": "192.168.1.23",
                "dst_port": 3389,
                "protocol": "tcp",
                "direction": "outbound"
            }),
        ]
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata,
            &fixture,
            fixture.len(),
        )
        .expect("preview");
        let result = run_portable_capture_lite(&prepared).expect("run portable import");

        assert!(result
            .findings
            .iter()
            .any(|finding| finding.finding_type().contains("quic_http3_security_lite")));
        assert!(result.findings.iter().any(|finding| finding
            .finding_type()
            .contains("remote_admin_protocol_lite.rdp_spread_pattern")));
        assert!(result
            .findings
            .iter()
            .filter(|finding| {
                finding.finding_type().contains("quic_http3_security_lite")
                    || finding
                        .finding_type()
                        .contains("remote_admin_protocol_lite")
            })
            .flat_map(|finding| finding.attack_mappings().iter())
            .next()
            .is_some());
        assert!(result
            .findings
            .iter()
            .filter(|finding| {
                finding.finding_type().contains("quic_http3_security_lite")
                    || finding
                        .finding_type()
                        .contains("remote_admin_protocol_lite")
            })
            .flat_map(|finding| finding.attack_mappings().iter())
            .all(|mapping| {
                matches!(
                    mapping.technique_id.as_deref(),
                    Some("T1071") | Some("T1021")
                )
            }));
        assert!(!result.risk_events.is_empty());
    }

    #[test]
    fn portable_capture_import_appends_optional_service_snapshot_contexts() {
        let fixture = har_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            &fixture,
            fixture.len(),
        )
        .expect("preview");
        let runtime_service_context = service_context(
            "service_boundary",
            ServiceAdapterMode::Disconnected,
            ServiceCapabilityStatus::Disconnected,
            Some(ServiceReasonCode::IpcDisconnected),
            vec![
                ServiceLimitationFlag::LocalOnly,
                ServiceLimitationFlag::StubOnly,
                ServiceLimitationFlag::ReadOnlyAllowlist,
                ServiceLimitationFlag::NoRawContentRetention,
                ServiceLimitationFlag::ControlPlaneOwnedByLocalCore,
                ServiceLimitationFlag::NoProductionServiceLifecycle,
            ],
            "service_ipc.status",
            Timestamp::now(),
        )
        .expect("service context");

        let result =
            run_portable_capture_lite_with_service_contexts(&prepared, &[runtime_service_context])
                .expect("run portable import");

        assert!(result
            .service_capability_contexts
            .iter()
            .any(|context| context.source_provenance_id == "service_ipc.status"));
        assert_eq!(result.service_capability_contexts.len(), 3);
        assert!(result
            .service_capability_contexts
            .iter()
            .all(|context| context.validate_boundary().is_ok()));
        assert!(result
            .emitted_topics
            .iter()
            .any(|topic| topic == SERVICE_CAPABILITY_STATUS));
        assert!(!result.risk_events.is_empty());
    }

    #[test]
    fn network_portable_capture_runtime_payloads_remain_metadata_only() {
        let fixture = har_fixture();
        let prepared = preview_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            &fixture,
            fixture.len(),
        )
        .expect("preview");
        let result = run_portable_capture_lite(&prepared).expect("run");
        let serialized = serde_json::json!({
            "provenance": result.provenance,
            "emitted_topics": result.emitted_topics,
            "flow_records": result.flow_records,
            "session_records": result.session_records,
            "dns_observations": result.dns_observations,
            "tls_observations": result.tls_observations,
            "http_metadata": result.http_metadata,
            "auth_metadata": result.auth_metadata,
            "auth_summary": result.auth_summary,
            "saas_cloud_metadata": result.saas_cloud_metadata,
            "saas_cloud_summary": result.saas_cloud_summary,
            "deception_events": result.deception_events,
            "deception_summary": result.deception_summary,
            "service_capability_contexts": result.service_capability_contexts,
            "findings": result.findings,
            "evidence": result.evidence,
            "graph_hints": result.graph_hints,
            "risk_events": result.risk_events,
            "alerts": result.alerts,
            "incidents": result.incidents,
        })
        .to_string();

        for marker in [
            "authorization",
            "cookie",
            "credential",
            "access_token",
            "request_body",
            "response_body",
            "payload",
        ] {
            assert!(
                !serialized.to_ascii_lowercase().contains(marker),
                "portable import runtime leaked forbidden marker {marker}"
            );
        }
    }
}
