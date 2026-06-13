use crate::{
    asset_exposure::{
        AssetExposureOutput, BindScope, InventorySource, ListeningPortInput, ServiceInventoryInput,
        ServiceKind,
    },
    risk_alerting::{ALERT_CANDIDATE_CONTRACT, INCIDENT_CANDIDATE_CONTRACT},
    static_plugin_runtime::{
        register_static_asset_exposure_plugin, register_static_exfiltration_detection_plugin,
        register_static_flow_sessionization_plugin, register_static_lateral_movement_plugin,
        register_static_risk_alerting_plugin,
    },
    DnsMetadataInput, DnsSecurityObservationPlugin, FlowSessionizationInput,
    FlowSessionizationPlugin, HttpMetadataInput, HttpMetadataPlugin, NetworkObservationError,
    TlsFingerprintPlugin, TlsMetadataInput,
};
use sentinel_contracts::{
    Alert, AttributionConfidence, AttributionMethod, CaptureSource, CollectionMode,
    ContractDescriptor, DnsAnswer, DnsObservation, EventEnvelope, EventId, EventType, EvidenceItem,
    Finding, FlowAttribution, FlowRecord, GraphHint, HttpMetadata, HttpMethod, Incident, IpAddress,
    NetworkDirection, PacketFlags, PacketRecord, PluginId, PluginManifest, PrivacyClass,
    ProcessContext, QualityScore, RiskEvent, RiskHint, SchemaVersion, SecurityObservation,
    ServiceAdapterMode, ServiceCapabilityContext, ServiceCapabilityStatus, ServiceLimitationFlag,
    ServiceReasonCode, SessionRecord, SignerStatus, Timestamp, TlsObservation, TraceContext,
    TraceId, TransportProtocol, VisibilityLevel,
};
use sentinel_platform::{
    CheckpointError, CheckpointHandle, CheckpointRecord, CheckpointScope, CheckpointSupport,
    ContractRegistry, EventBus, EventBusError, ExecutionPlan, ExecutionPlanStep,
    PermissionResolver, PipelineDag, PipelineDagError, PipelineNode, PipelineNodeId, PipelineStage,
    PluginContext, PluginEventBatch, PluginRuntime, PluginRuntimeError, PriorityLane,
    PublishOptions, PublishReport, ReplayContext, ReplayScope, ReplaySupport, Scheduler,
    SchedulerKind, StageBinding, Topic, TopicLayer, TopicName, ASSET_EXPOSURE, GRAPH_HINT,
    GRAPH_PATH, GRAPH_UPDATE, IDENTITY_FLOW_ATTRIBUTION, IDENTITY_PROCESS_CONTEXT,
    NETWORK_DNS_OBSERVATION, NETWORK_FLOW_RECORD, NETWORK_HTTP_METADATA, NETWORK_PACKET_RECORD,
    NETWORK_SESSION_RECORD, NETWORK_TLS_OBSERVATION, RAW_PACKET_METADATA, REPORT_EXPORTED,
    REPORT_GENERATED, RESPONSE_PLAN, RESPONSE_RESULT, RESPONSE_ROLLBACK_RESULT, SECURITY_ALERT,
    SECURITY_EVIDENCE, SECURITY_FINDING, SECURITY_INCIDENT, SECURITY_OBSERVATION, SECURITY_RISK,
    SERVICE_CAPABILITY_STATUS,
};
use sentinel_storage::{LogicalRecord, LogicalStore, SqliteStoreFactory, StorageError, StoreKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fmt;

pub const MOCK_NETWORK_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const MOCK_ONLY_LABEL: &str = "MOCK_ONLY";
pub const FIXTURE_ONLY_LABEL: &str = "FIXTURE_ONLY";
pub const NOT_FOR_PRODUCTION_LABEL: &str = "NOT_FOR_PRODUCTION";

const PACKET_CAPTURE_PLUGIN_ID: &str = "00000000-0000-0000-0000-000000000191";
const PACKET_NORMALIZATION_PLUGIN_ID: &str = "00000000-0000-0000-0000-000000000192";
const FLOW_SESSIONIZATION_PLUGIN_ID: &str = "00000000-0000-0000-0000-000000000193";
const DNS_SECURITY_PLUGIN_ID: &str = "00000000-0000-0000-0000-000000000194";
const TLS_FINGERPRINT_PLUGIN_ID: &str = "00000000-0000-0000-0000-000000000195";
const PROCESS_CONTEXT_PLUGIN_ID: &str = "00000000-0000-0000-0000-000000000196";
const HTTP_METADATA_PLUGIN_ID: &str = "00000000-0000-0000-0000-000000000197";
const ASSET_SERVICE_INVENTORY_PLUGIN_ID: &str = "00000000-0000-0000-0000-000000000198";
const SERVICE_CAPABILITY_CONTEXT_PLUGIN_ID: &str = "00000000-0000-0000-0000-00000000018f";
#[cfg(test)]
const ASSET_EXPOSURE_PLUGIN_ID: &str = "00000000-0000-0000-0000-00000000019a";
#[cfg(test)]
const LATERAL_MOVEMENT_PLUGIN_ID: &str = "00000000-0000-0000-0000-00000000019c";
#[cfg(test)]
const EXFILTRATION_DETECTION_PLUGIN_ID: &str = "00000000-0000-0000-0000-00000000019b";
#[cfg(test)]
const RISK_ALERTING_PLUGIN_ID: &str = "00000000-0000-0000-0000-0000000001a0";
const ASSET_SERVICE_INVENTORY: &str = "asset.service_inventory";
const SECURITY_RISK_HINT: &str = "security.risk_hint";
const MOCK_EXFIL_UPLOAD_BYTES: u32 = 80_000;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MockPacketMetadata {
    pub observed_at: Timestamp,
    pub interface_id: String,
    pub direction: NetworkDirection,
    pub protocol: TransportProtocol,
    pub src_ip: IpAddress,
    pub src_port: Option<u16>,
    pub dst_ip: IpAddress,
    pub dst_port: Option<u16>,
    pub length_bytes: u32,
    pub capture_source: CaptureSource,
    pub collection_mode: CollectionMode,
    pub visibility_level: VisibilityLevel,
    pub trace_id: TraceId,
    pub privacy_class: PrivacyClass,
    pub labels: Vec<String>,
}

impl MockPacketMetadata {
    pub fn to_packet_record(&self) -> PacketRecord {
        let mut record = PacketRecord::new(
            self.protocol.clone(),
            self.direction.clone(),
            self.src_ip,
            self.dst_ip,
            self.length_bytes,
        );
        record.timestamp = self.observed_at.clone();
        record.interface_id = Some(self.interface_id.clone());
        record.src_port = self.src_port;
        record.dst_port = self.dst_port;
        record.flags = PacketFlags::default();
        record.capture_source = self.capture_source.clone();
        record.collection_mode = self.collection_mode.clone();
        record.visibility_level = self.visibility_level.clone();
        record.quality_score = QualityScore::new(0.92).expect("fixture score is in range");
        record.trace_id = Some(self.trace_id.clone());
        record
    }
}

#[derive(Clone, Debug)]
pub struct MockPacketMetadataSource {
    labels: Vec<String>,
}

impl MockPacketMetadataSource {
    pub fn new(labels: Vec<String>) -> Self {
        Self { labels }
    }

    pub fn packets(
        &self,
        trace_id: &TraceId,
    ) -> Result<Vec<MockPacketMetadata>, MockPipelineError> {
        Ok(vec![
            MockPacketMetadata {
                observed_at: Timestamp::now(),
                interface_id: "mock_interface_0".to_string(),
                direction: NetworkDirection::Outbound,
                protocol: TransportProtocol::Udp,
                src_ip: ip("192.0.2.10")?,
                src_port: Some(53_000),
                dst_ip: ip("203.0.113.53")?,
                dst_port: Some(53),
                length_bytes: 92,
                capture_source: CaptureSource::Mock,
                collection_mode: CollectionMode::Mock,
                visibility_level: VisibilityLevel::MetadataOnly,
                trace_id: trace_id.clone(),
                privacy_class: PrivacyClass::Internal,
                labels: self.labels.clone(),
            },
            MockPacketMetadata {
                observed_at: Timestamp::now(),
                interface_id: "mock_interface_0".to_string(),
                direction: NetworkDirection::Outbound,
                protocol: TransportProtocol::Tcp,
                src_ip: ip("192.0.2.10")?,
                src_port: Some(49_152),
                dst_ip: ip("198.51.100.24")?,
                dst_port: Some(443),
                length_bytes: 1_280,
                capture_source: CaptureSource::Mock,
                collection_mode: CollectionMode::Mock,
                visibility_level: VisibilityLevel::MetadataOnly,
                trace_id: trace_id.clone(),
                privacy_class: PrivacyClass::Internal,
                labels: self.labels.clone(),
            },
            MockPacketMetadata {
                observed_at: Timestamp::now(),
                interface_id: "mock_interface_0".to_string(),
                direction: NetworkDirection::Outbound,
                protocol: TransportProtocol::Tcp,
                src_ip: ip("192.0.2.10")?,
                src_port: Some(51_080),
                dst_ip: ip("198.51.100.80")?,
                dst_port: Some(80),
                length_bytes: MOCK_EXFIL_UPLOAD_BYTES,
                capture_source: CaptureSource::Mock,
                collection_mode: CollectionMode::Mock,
                visibility_level: VisibilityLevel::MetadataOnly,
                trace_id: trace_id.clone(),
                privacy_class: PrivacyClass::Internal,
                labels: self.labels.clone(),
            },
            MockPacketMetadata {
                observed_at: Timestamp::now(),
                interface_id: "mock_interface_0".to_string(),
                direction: NetworkDirection::Lateral,
                protocol: TransportProtocol::Tcp,
                src_ip: ip("192.168.1.10")?,
                src_port: Some(52_445),
                dst_ip: ip("192.168.1.21")?,
                dst_port: Some(445),
                length_bytes: 640,
                capture_source: CaptureSource::Mock,
                collection_mode: CollectionMode::Mock,
                visibility_level: VisibilityLevel::MetadataOnly,
                trace_id: trace_id.clone(),
                privacy_class: PrivacyClass::Internal,
                labels: self.labels.clone(),
            },
            MockPacketMetadata {
                observed_at: Timestamp::now(),
                interface_id: "mock_interface_0".to_string(),
                direction: NetworkDirection::Lateral,
                protocol: TransportProtocol::Tcp,
                src_ip: ip("192.168.1.10")?,
                src_port: Some(52_389),
                dst_ip: ip("192.168.1.22")?,
                dst_port: Some(3389),
                length_bytes: 704,
                capture_source: CaptureSource::Mock,
                collection_mode: CollectionMode::Mock,
                visibility_level: VisibilityLevel::MetadataOnly,
                trace_id: trace_id.clone(),
                privacy_class: PrivacyClass::Internal,
                labels: self.labels.clone(),
            },
            MockPacketMetadata {
                observed_at: Timestamp::now(),
                interface_id: "mock_interface_0".to_string(),
                direction: NetworkDirection::Lateral,
                protocol: TransportProtocol::Tcp,
                src_ip: ip("192.168.1.10")?,
                src_port: Some(52_985),
                dst_ip: ip("192.168.1.25")?,
                dst_port: Some(5985),
                length_bytes: 672,
                capture_source: CaptureSource::Mock,
                collection_mode: CollectionMode::Mock,
                visibility_level: VisibilityLevel::MetadataOnly,
                trace_id: trace_id.clone(),
                privacy_class: PrivacyClass::Internal,
                labels: self.labels.clone(),
            },
        ])
    }
}

#[derive(Clone, Debug, Default)]
pub struct MockFlowEmitter;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MockFlowEmission {
    pub flows: Vec<FlowRecord>,
    pub sessions: Vec<SessionRecord>,
    pub attributions: Vec<FlowAttribution>,
}

impl MockFlowEmitter {
    pub fn emit(
        &self,
        packets: &[PacketRecord],
        process: &ProcessContext,
    ) -> Result<MockFlowEmission, MockPipelineError> {
        let output = FlowSessionizationPlugin::new().process(
            FlowSessionizationInput::new(packets.to_vec())
                .with_process_context(process.clone())
                .with_default_attribution_confidence(AttributionConfidence::High),
        )?;
        Ok(MockFlowEmission {
            flows: output.flows,
            sessions: output.sessions,
            attributions: output.attributions,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct MockDnsEmitter;

impl MockDnsEmitter {
    pub fn emit(
        &self,
        flows: &[FlowRecord],
        process: &ProcessContext,
    ) -> Result<Vec<DnsObservation>, MockPipelineError> {
        let mut observations = Vec::new();
        for flow in flows
            .iter()
            .filter(|flow| flow.protocol == TransportProtocol::Udp && flow.dst_port == 53)
        {
            observations.push(
                DnsSecurityObservationPlugin::new().observe(DnsMetadataInput {
                    flow_ref: Some(flow.flow_id.clone()),
                    query_name_protected: "beacon.example.test".to_string(),
                    feature_source_name: None,
                    query_type: "A".to_string(),
                    response_code: Some("NOERROR".to_string()),
                    resolver_ip: flow.dst_ip,
                    client_ip: flow.src_ip,
                    timestamp: flow.start_time.clone(),
                    answers: vec![DnsAnswer::Ip {
                        address: ip("198.51.100.24")?,
                        ttl_seconds: Some(60),
                    }],
                    cname_chain_protected: Vec::new(),
                    process_ref: Some(process.process_context_id.clone()),
                })?,
            );
        }
        Ok(observations)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MockTlsEmitter;

impl MockTlsEmitter {
    pub fn emit(
        &self,
        flows: &[FlowRecord],
        process: &ProcessContext,
    ) -> Result<Vec<TlsObservation>, MockPipelineError> {
        flows
            .iter()
            .filter(|flow| flow.protocol == TransportProtocol::Tcp && flow.dst_port == 443)
            .map(|flow| {
                TlsFingerprintPlugin::new().observe(TlsMetadataInput {
                    flow_ref: Some(flow.flow_id.clone()),
                    timestamp: flow.start_time.clone(),
                    sni_protected: Some("beacon.example.test".to_string()),
                    alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                    tls_version: Some("tls1.3".to_string()),
                    cipher_suite: Some("tls_aes_128_gcm_sha256".to_string()),
                    extension_summary_protected: Some("sni,alpn,key_share".to_string()),
                    certificate_fingerprint: Some(
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                            .to_string(),
                    ),
                    issuer_summary_protected: Some("fixture issuer".to_string()),
                    san_summary_protected: Some("fixture SAN summary".to_string()),
                    valid_not_before: None,
                    valid_not_after: None,
                    process_ref: Some(process.process_context_id.clone()),
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(MockPipelineError::from)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MockHttpEmitter;

impl MockHttpEmitter {
    pub fn emit(
        &self,
        flows: &[FlowRecord],
        process: &ProcessContext,
    ) -> Result<Vec<HttpMetadata>, MockPipelineError> {
        let mut records = Vec::new();
        for flow in flows
            .iter()
            .filter(|flow| flow.protocol == TransportProtocol::Tcp && flow.dst_port == 80)
        {
            if let Some(metadata) = HttpMetadataPlugin::new().observe(HttpMetadataInput {
                flow_ref: Some(flow.flow_id.clone()),
                timestamp: flow.start_time.clone(),
                method: HttpMethod::Post,
                scheme: Some("https".to_string()),
                host_protected: Some("api.example.test".to_string()),
                path_visible: Some("/v1/upload/12345?case=local".to_string()),
                status_code: Some(200),
                result_label: Some("upstream_response_observed".to_string()),
                request_size_bytes: Some(flow.bytes_out),
                response_size_bytes: Some(512),
                request_content_length_bytes: Some(flow.bytes_out),
                response_content_length_bytes: Some(512),
                content_type: Some("application/json".to_string()),
                user_agent_family: Some("fixture-client".to_string()),
                waf_action: None,
                waf_rule_id: None,
                waf_attack_class: None,
                visible_plaintext: true,
                process_ref: Some(process.process_context_id.clone()),
            })? {
                records.push(metadata);
            }
        }
        Ok(records)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MockPipelineFixture {
    pub trace_context: TraceContext,
    pub labels: Vec<String>,
    pub packet_metadata: Vec<MockPacketMetadata>,
    pub packet_records: Vec<PacketRecord>,
    pub flows: Vec<FlowRecord>,
    pub sessions: Vec<SessionRecord>,
    pub dns_observations: Vec<DnsObservation>,
    pub tls_observations: Vec<TlsObservation>,
    pub http_metadata: Vec<HttpMetadata>,
    pub process_context: ProcessContext,
    pub flow_attributions: Vec<FlowAttribution>,
    pub asset_service_inventory: ServiceInventoryInput,
    pub service_capability_contexts: Vec<ServiceCapabilityContext>,
}

impl MockPipelineFixture {
    pub fn build() -> Result<Self, MockPipelineError> {
        let mut trace_context = TraceContext::new_root();
        let labels = mock_labels();
        let source = MockPacketMetadataSource::new(labels.clone());
        let packet_metadata = source.packets(&trace_context.trace_id)?;
        let packet_records = packet_metadata
            .iter()
            .map(MockPacketMetadata::to_packet_record)
            .collect::<Vec<_>>();
        let process_context = mock_process_context();
        let flow_emission = MockFlowEmitter.emit(&packet_records, &process_context)?;
        let flows = flow_emission.flows;
        let sessions = flow_emission.sessions;
        let flow_attributions = flow_emission.attributions;
        let dns_observations = MockDnsEmitter.emit(&flows, &process_context)?;
        let tls_observations = MockTlsEmitter.emit(&flows, &process_context)?;
        let http_metadata = MockHttpEmitter.emit(&flows, &process_context)?;
        let asset_service_inventory = mock_asset_service_inventory_input()?;
        let service_capability_contexts = mock_service_capability_contexts()?;
        trace_context.pipeline_id = Some(sentinel_contracts::PipelineId::new_v4());

        Ok(Self {
            trace_context,
            labels,
            packet_metadata,
            packet_records,
            flows,
            sessions,
            dns_observations,
            tls_observations,
            http_metadata,
            process_context,
            flow_attributions,
            asset_service_inventory,
            service_capability_contexts,
        })
    }

    pub fn trace_is_continuous(&self) -> bool {
        let trace_id = &self.trace_context.trace_id;
        self.packet_metadata
            .iter()
            .all(|metadata| metadata.trace_id == *trace_id)
            && self
                .packet_records
                .iter()
                .all(|record| record.trace_id.as_ref() == Some(trace_id))
            && self
                .flows
                .iter()
                .all(|flow| flow.trace_id.as_ref() == Some(trace_id))
            && self.dns_observations.iter().all(|dns| {
                self.flows
                    .iter()
                    .any(|flow| Some(&flow.flow_id) == dns.flow_ref.as_ref())
            })
            && self.tls_observations.iter().all(|tls| {
                self.flows
                    .iter()
                    .any(|flow| Some(&flow.flow_id) == tls.flow_ref.as_ref())
            })
            && self.http_metadata.iter().all(|http| {
                self.flows
                    .iter()
                    .any(|flow| Some(&flow.flow_id) == http.flow_ref.as_ref())
            })
            && self.flow_attributions.iter().all(|attribution| {
                self.flows
                    .iter()
                    .any(|flow| flow.flow_id == attribution.flow_id)
            })
    }
}

#[derive(Clone, Debug)]
pub struct MockNetworkPipeline {
    fixture: MockPipelineFixture,
    execution_plan: ExecutionPlan,
}

struct MockPipelineRuntime<'run, 'store> {
    bus: &'run mut EventBus,
    stores: &'run SqliteStoreFactory<'store>,
    event_ids: &'run mut Vec<EventId>,
    publish_reports: &'run mut Vec<PublishReport>,
    process_context: ProcessContext,
    flow_records: Vec<FlowRecord>,
    session_records: Vec<SessionRecord>,
    dns_observations: Vec<DnsObservation>,
    tls_observations: Vec<TlsObservation>,
    http_metadata: Vec<HttpMetadata>,
    flow_attributions: Vec<FlowAttribution>,
    flow_events: Vec<EventEnvelope>,
    session_events: Vec<EventEnvelope>,
    process_context_events: Vec<EventEnvelope>,
    http_metadata_events: Vec<EventEnvelope>,
    finding_events: Vec<EventEnvelope>,
    evidence_events: Vec<EventEnvelope>,
    risk_hint_events: Vec<EventEnvelope>,
    service_context_events: Vec<EventEnvelope>,
    asset_service_inventory: Option<ServiceInventoryInput>,
    service_capability_contexts: Vec<ServiceCapabilityContext>,
    asset_inventory_events: Vec<EventEnvelope>,
    asset_exposure_events: Vec<EventEnvelope>,
    asset_exposures: Vec<AssetExposureOutput>,
    asset_observations: Vec<SecurityObservation>,
    asset_findings: Vec<Finding>,
    asset_evidence: Vec<EvidenceItem>,
    asset_graph_hints: Vec<GraphHint>,
    lateral_findings: Vec<Finding>,
    lateral_evidence: Vec<EvidenceItem>,
    lateral_risk_hints: Vec<RiskHint>,
    lateral_graph_hints: Vec<GraphHint>,
    exfil_findings: Vec<Finding>,
    exfil_evidence: Vec<EvidenceItem>,
    exfil_risk_hints: Vec<RiskHint>,
    exfil_graph_hints: Vec<GraphHint>,
    risk_events: Vec<RiskEvent>,
    alert_candidate_count: usize,
    alerts: Vec<Alert>,
    incident_candidate_count: usize,
    incidents: Vec<Incident>,
}

#[derive(Clone, Debug)]
struct MockPipelineDynamicOutput {
    flow_records: Vec<FlowRecord>,
    session_records: Vec<SessionRecord>,
    dns_observations: Vec<DnsObservation>,
    tls_observations: Vec<TlsObservation>,
    http_metadata: Vec<HttpMetadata>,
    process_context: ProcessContext,
    flow_attributions: Vec<FlowAttribution>,
    asset_service_inventory: Option<ServiceInventoryInput>,
    service_capability_contexts: Vec<ServiceCapabilityContext>,
    asset_exposures: Vec<AssetExposureOutput>,
    asset_observations: Vec<SecurityObservation>,
    asset_findings: Vec<Finding>,
    asset_evidence: Vec<EvidenceItem>,
    asset_graph_hints: Vec<GraphHint>,
    lateral_findings: Vec<Finding>,
    lateral_evidence: Vec<EvidenceItem>,
    lateral_risk_hints: Vec<RiskHint>,
    lateral_graph_hints: Vec<GraphHint>,
    exfil_findings: Vec<Finding>,
    exfil_evidence: Vec<EvidenceItem>,
    exfil_risk_hints: Vec<RiskHint>,
    exfil_graph_hints: Vec<GraphHint>,
    risk_events: Vec<RiskEvent>,
    alert_candidate_count: usize,
    alerts: Vec<Alert>,
    incident_candidate_count: usize,
    incidents: Vec<Incident>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MockStageExecution {
    used_plugin_runtime: bool,
}

impl MockPipelineRuntime<'_, '_> {
    fn dynamic_output(&self) -> MockPipelineDynamicOutput {
        MockPipelineDynamicOutput {
            flow_records: self.flow_records.clone(),
            session_records: self.session_records.clone(),
            dns_observations: self.dns_observations.clone(),
            tls_observations: self.tls_observations.clone(),
            http_metadata: self.http_metadata.clone(),
            process_context: self.process_context.clone(),
            flow_attributions: self.flow_attributions.clone(),
            asset_service_inventory: self.asset_service_inventory.clone(),
            service_capability_contexts: self.service_capability_contexts.clone(),
            asset_exposures: self.asset_exposures.clone(),
            asset_observations: self.asset_observations.clone(),
            asset_findings: self.asset_findings.clone(),
            asset_evidence: self.asset_evidence.clone(),
            asset_graph_hints: self.asset_graph_hints.clone(),
            lateral_findings: self.lateral_findings.clone(),
            lateral_evidence: self.lateral_evidence.clone(),
            lateral_risk_hints: self.lateral_risk_hints.clone(),
            lateral_graph_hints: self.lateral_graph_hints.clone(),
            exfil_findings: self.exfil_findings.clone(),
            exfil_evidence: self.exfil_evidence.clone(),
            exfil_risk_hints: self.exfil_risk_hints.clone(),
            exfil_graph_hints: self.exfil_graph_hints.clone(),
            risk_events: self.risk_events.clone(),
            alert_candidate_count: self.alert_candidate_count,
            alerts: self.alerts.clone(),
            incident_candidate_count: self.incident_candidate_count,
            incidents: self.incidents.clone(),
        }
    }
}

impl MockNetworkPipeline {
    pub fn new() -> Result<Self, MockPipelineError> {
        let fixture = MockPipelineFixture::build()?;
        let execution_plan = mock_pipeline_dag()?.build_execution_plan()?;
        Ok(Self {
            fixture,
            execution_plan,
        })
    }

    pub fn fixture(&self) -> &MockPipelineFixture {
        &self.fixture
    }

    pub fn execution_plan(&self) -> &ExecutionPlan {
        &self.execution_plan
    }

    pub fn run(
        &self,
        bus: &mut EventBus,
        stores: &SqliteStoreFactory<'_>,
    ) -> Result<MockPipelineRunResult, MockPipelineError> {
        ensure_observer_subscriptions(bus)?;
        let scheduler = Scheduler::new(SchedulerKind::Realtime);
        let replay_context = ReplayContext::new(
            ReplayScope::Pipeline,
            "metadata replay mode; response execution disabled",
        );
        let mut publish_reports = Vec::new();
        let mut event_ids = Vec::new();
        let mut completed_nodes = Vec::new();
        let mut stage_runs = Vec::new();

        let dynamic_output = {
            let mut runtime = MockPipelineRuntime {
                bus,
                stores,
                event_ids: &mut event_ids,
                publish_reports: &mut publish_reports,
                process_context: self.fixture.process_context.clone(),
                flow_records: Vec::new(),
                session_records: Vec::new(),
                dns_observations: Vec::new(),
                tls_observations: Vec::new(),
                http_metadata: Vec::new(),
                flow_attributions: Vec::new(),
                flow_events: Vec::new(),
                session_events: Vec::new(),
                process_context_events: Vec::new(),
                http_metadata_events: Vec::new(),
                finding_events: Vec::new(),
                evidence_events: Vec::new(),
                risk_hint_events: Vec::new(),
                service_context_events: Vec::new(),
                asset_service_inventory: None,
                service_capability_contexts: Vec::new(),
                asset_inventory_events: Vec::new(),
                asset_exposure_events: Vec::new(),
                asset_exposures: Vec::new(),
                asset_observations: Vec::new(),
                asset_findings: Vec::new(),
                asset_evidence: Vec::new(),
                asset_graph_hints: Vec::new(),
                lateral_findings: Vec::new(),
                lateral_evidence: Vec::new(),
                lateral_risk_hints: Vec::new(),
                lateral_graph_hints: Vec::new(),
                exfil_findings: Vec::new(),
                exfil_evidence: Vec::new(),
                exfil_risk_hints: Vec::new(),
                exfil_graph_hints: Vec::new(),
                risk_events: Vec::new(),
                alert_candidate_count: 0,
                alerts: Vec::new(),
                incident_candidate_count: 0,
                incidents: Vec::new(),
            };

            while completed_nodes.len() < self.execution_plan.steps.len() {
                let decision =
                    scheduler.decide_ready(&self.execution_plan, &completed_nodes, 0, None);
                let Some(node_id) = decision.ready_nodes.first() else {
                    return Err(MockPipelineError::Contract(
                        "scheduler did not produce a ready DAG node".to_string(),
                    ));
                };
                let step = self.execution_plan.step_for(node_id).ok_or_else(|| {
                    MockPipelineError::Contract("scheduled node is missing".into())
                })?;
                let report_start = runtime.publish_reports.len();
                let stage_execution = self.run_stage(step, &replay_context, &mut runtime)?;
                let emitted_event_count = runtime.publish_reports.len() - report_start;
                let checkpoint =
                    self.stage_checkpoint(step, emitted_event_count, &replay_context)?;
                stage_runs.push(MockPipelineStageRun {
                    node_id: step.node_id.clone(),
                    stage: step.stage.clone(),
                    order_index: step.order_index,
                    input_topics: step.input_topics.clone(),
                    output_topics: step.output_topics.clone(),
                    emitted_event_count,
                    checkpoint,
                    replay_response_execution_disabled: replay_context.real_response_forbidden(),
                    used_plugin_runtime: stage_execution.used_plugin_runtime,
                });
                completed_nodes.push(step.node_id.clone());
            }
            runtime.dynamic_output()
        };

        Ok(MockPipelineRunResult {
            trace_id: self.fixture.trace_context.trace_id.clone(),
            labels: self.fixture.labels.clone(),
            event_ids,
            publish_reports,
            execution_plan: self.execution_plan.clone(),
            scheduler_kind: scheduler.metadata.kind,
            replay_context,
            stage_runs,
            packet_metadata_count: self.fixture.packet_metadata.len(),
            packet_record_count: self.fixture.packet_records.len(),
            flow_count: dynamic_output.flow_records.len(),
            session_count: dynamic_output.session_records.len(),
            dns_count: dynamic_output.dns_observations.len(),
            tls_count: dynamic_output.tls_observations.len(),
            http_count: dynamic_output.http_metadata.len(),
            process_context_count: 1,
            flow_attribution_count: dynamic_output.flow_attributions.len(),
            service_capability_context_count: dynamic_output.service_capability_contexts.len(),
            asset_service_inventory_count: usize::from(
                dynamic_output.asset_service_inventory.is_some(),
            ),
            asset_exposure_count: dynamic_output.asset_exposures.len(),
            asset_observation_count: dynamic_output.asset_observations.len(),
            asset_finding_count: dynamic_output.asset_findings.len(),
            asset_evidence_count: dynamic_output.asset_evidence.len(),
            asset_graph_hint_count: dynamic_output.asset_graph_hints.len(),
            lateral_finding_count: dynamic_output.lateral_findings.len(),
            lateral_evidence_count: dynamic_output.lateral_evidence.len(),
            lateral_risk_hint_count: dynamic_output.lateral_risk_hints.len(),
            lateral_graph_hint_count: dynamic_output.lateral_graph_hints.len(),
            exfil_finding_count: dynamic_output.exfil_findings.len(),
            exfil_evidence_count: dynamic_output.exfil_evidence.len(),
            exfil_risk_hint_count: dynamic_output.exfil_risk_hints.len(),
            exfil_graph_hint_count: dynamic_output.exfil_graph_hints.len(),
            risk_event_count: dynamic_output.risk_events.len(),
            alert_candidate_count: dynamic_output.alert_candidate_count,
            alert_count: dynamic_output.alerts.len(),
            incident_candidate_count: dynamic_output.incident_candidate_count,
            incident_count: dynamic_output.incidents.len(),
            packet_metadata: self.fixture.packet_metadata.clone(),
            packet_records: self.fixture.packet_records.clone(),
            flows: dynamic_output.flow_records,
            sessions: dynamic_output.session_records,
            dns_observations: dynamic_output.dns_observations,
            tls_observations: dynamic_output.tls_observations,
            http_metadata: dynamic_output.http_metadata,
            process_context: dynamic_output.process_context,
            flow_attributions: dynamic_output.flow_attributions,
            service_capability_contexts: dynamic_output.service_capability_contexts,
            asset_service_inventory: dynamic_output
                .asset_service_inventory
                .unwrap_or_else(|| self.fixture.asset_service_inventory.clone()),
            asset_exposures: dynamic_output.asset_exposures,
            asset_observations: dynamic_output.asset_observations,
            asset_findings: dynamic_output.asset_findings,
            asset_evidence: dynamic_output.asset_evidence,
            asset_graph_hints: dynamic_output.asset_graph_hints,
            lateral_findings: dynamic_output.lateral_findings,
            lateral_evidence: dynamic_output.lateral_evidence,
            lateral_risk_hints: dynamic_output.lateral_risk_hints,
            lateral_graph_hints: dynamic_output.lateral_graph_hints,
            exfil_findings: dynamic_output.exfil_findings,
            exfil_evidence: dynamic_output.exfil_evidence,
            exfil_risk_hints: dynamic_output.exfil_risk_hints,
            exfil_graph_hints: dynamic_output.exfil_graph_hints,
            risk_events: dynamic_output.risk_events,
            alerts: dynamic_output.alerts,
            incidents: dynamic_output.incidents,
        })
    }

    fn run_stage(
        &self,
        step: &ExecutionPlanStep,
        replay_context: &ReplayContext,
        runtime: &mut MockPipelineRuntime<'_, '_>,
    ) -> Result<MockStageExecution, MockPipelineError> {
        if is_flow_sessionization_step(step) {
            self.run_static_flow_sessionization_stage(replay_context, runtime)?;
            return Ok(MockStageExecution {
                used_plugin_runtime: true,
            });
        }
        if is_asset_exposure_detection_step(step) {
            self.run_static_asset_exposure_stage(replay_context, runtime)?;
            return Ok(MockStageExecution {
                used_plugin_runtime: true,
            });
        }
        if is_lateral_movement_detection_step(step) {
            self.run_static_lateral_movement_stage(replay_context, runtime)?;
            return Ok(MockStageExecution {
                used_plugin_runtime: true,
            });
        }
        if is_exfiltration_detection_step(step) {
            self.run_static_exfiltration_detection_stage(replay_context, runtime)?;
            return Ok(MockStageExecution {
                used_plugin_runtime: true,
            });
        }
        if is_risk_alerting_step(step) {
            self.run_static_risk_alerting_stage(replay_context, runtime)?;
            return Ok(MockStageExecution {
                used_plugin_runtime: true,
            });
        }

        for output_topic in &step.output_topics {
            self.emit_topic(output_topic.as_str(), replay_context, runtime)?;
        }
        Ok(MockStageExecution::default())
    }

    fn run_static_flow_sessionization_stage(
        &self,
        replay_context: &ReplayContext,
        runtime: &mut MockPipelineRuntime<'_, '_>,
    ) -> Result<(), MockPipelineError> {
        let mut plugin_runtime = PluginRuntime::new();
        let flow_plugin_id = register_static_flow_sessionization_plugin(&mut plugin_runtime)?;
        let manifest = plugin_runtime
            .manifest(&flow_plugin_id)
            .ok_or_else(|| {
                MockPipelineError::Contract(
                    "static flow sessionization manifest was not registered".to_string(),
                )
            })?
            .clone();
        let contracts = contract_registry_for_manifest(&manifest)?;
        let mut permissions = PermissionResolver::new();
        permissions.register_plugin_manifest_permissions(&manifest);
        let validation = plugin_runtime.registry().validate_startup(
            &flow_plugin_id,
            &contracts,
            &permissions,
        )?;
        let mut context =
            plugin_context_for_manifest(&manifest, self.replay_trace_context(replay_context))?;
        plugin_runtime.start_plugin(&flow_plugin_id, &validation, &mut context)?;

        let packet_producer = plugin_id(PACKET_NORMALIZATION_PLUGIN_ID)?;
        let mut batch =
            PluginEventBatch::new(flow_plugin_id.clone(), self.fixture.packet_records.len());
        for packet in &self.fixture.packet_records {
            batch.push(self.packet_record_event(
                &packet_producer,
                packet.clone(),
                replay_context,
            )?)?;
        }

        let output = plugin_runtime.process_batch(&flow_plugin_id, &mut context, &batch)?;
        for event in output.events {
            self.publish_static_flow_output(runtime, event)?;
        }

        Ok(())
    }

    fn run_static_asset_exposure_stage(
        &self,
        replay_context: &ReplayContext,
        runtime: &mut MockPipelineRuntime<'_, '_>,
    ) -> Result<(), MockPipelineError> {
        let mut plugin_runtime = PluginRuntime::new();
        let asset_plugin_id = register_static_asset_exposure_plugin(&mut plugin_runtime)?;
        let manifest = plugin_runtime
            .manifest(&asset_plugin_id)
            .ok_or_else(|| {
                MockPipelineError::Contract(
                    "static asset exposure manifest was not registered".to_string(),
                )
            })?
            .clone();
        let contracts = contract_registry_for_manifest(&manifest)?;
        let mut permissions = PermissionResolver::new();
        permissions.register_plugin_manifest_permissions(&manifest);
        let validation = plugin_runtime.registry().validate_startup(
            &asset_plugin_id,
            &contracts,
            &permissions,
        )?;
        let mut context =
            plugin_context_for_manifest(&manifest, self.replay_trace_context(replay_context))?;
        plugin_runtime.start_plugin(&asset_plugin_id, &validation, &mut context)?;

        let mut batch = PluginEventBatch::new(
            asset_plugin_id.clone(),
            runtime.asset_inventory_events.len(),
        );
        for event in &runtime.asset_inventory_events {
            batch.push(event.clone())?;
        }

        let output = plugin_runtime.process_batch(&asset_plugin_id, &mut context, &batch)?;
        for event in output.events {
            self.publish_static_asset_output(runtime, event)?;
        }

        Ok(())
    }

    fn run_static_lateral_movement_stage(
        &self,
        replay_context: &ReplayContext,
        runtime: &mut MockPipelineRuntime<'_, '_>,
    ) -> Result<(), MockPipelineError> {
        let mut plugin_runtime = PluginRuntime::new();
        let lateral_plugin_id = register_static_lateral_movement_plugin(&mut plugin_runtime)?;
        let manifest = plugin_runtime
            .manifest(&lateral_plugin_id)
            .ok_or_else(|| {
                MockPipelineError::Contract(
                    "static lateral movement manifest was not registered".to_string(),
                )
            })?
            .clone();
        let contracts = contract_registry_for_manifest(&manifest)?;
        let mut permissions = PermissionResolver::new();
        permissions.register_plugin_manifest_permissions(&manifest);
        let validation = plugin_runtime.registry().validate_startup(
            &lateral_plugin_id,
            &contracts,
            &permissions,
        )?;
        let mut context =
            plugin_context_for_manifest(&manifest, self.replay_trace_context(replay_context))?;
        plugin_runtime.start_plugin(&lateral_plugin_id, &validation, &mut context)?;

        let batch_size = runtime.flow_events.len()
            + runtime.session_events.len()
            + runtime.process_context_events.len()
            + runtime.asset_exposure_events.len();
        let mut batch = PluginEventBatch::new(lateral_plugin_id.clone(), batch_size);
        for event in runtime
            .flow_events
            .iter()
            .chain(runtime.session_events.iter())
            .chain(runtime.process_context_events.iter())
            .chain(runtime.asset_exposure_events.iter())
        {
            batch.push(event.clone())?;
        }

        let output = plugin_runtime.process_batch(&lateral_plugin_id, &mut context, &batch)?;
        for event in output.events {
            self.publish_static_lateral_output(runtime, event)?;
        }

        Ok(())
    }

    fn run_static_exfiltration_detection_stage(
        &self,
        replay_context: &ReplayContext,
        runtime: &mut MockPipelineRuntime<'_, '_>,
    ) -> Result<(), MockPipelineError> {
        let mut plugin_runtime = PluginRuntime::new();
        let exfil_plugin_id = register_static_exfiltration_detection_plugin(&mut plugin_runtime)?;
        let manifest = plugin_runtime
            .manifest(&exfil_plugin_id)
            .ok_or_else(|| {
                MockPipelineError::Contract(
                    "static exfiltration detection manifest was not registered".to_string(),
                )
            })?
            .clone();
        let contracts = contract_registry_for_manifest(&manifest)?;
        let mut permissions = PermissionResolver::new();
        permissions.register_plugin_manifest_permissions(&manifest);
        let validation = plugin_runtime.registry().validate_startup(
            &exfil_plugin_id,
            &contracts,
            &permissions,
        )?;
        let mut context =
            plugin_context_for_manifest(&manifest, self.replay_trace_context(replay_context))?;
        plugin_runtime.start_plugin(&exfil_plugin_id, &validation, &mut context)?;

        let batch_size = runtime.flow_events.len()
            + runtime.session_events.len()
            + runtime.process_context_events.len()
            + runtime.http_metadata_events.len();
        let mut batch = PluginEventBatch::new(exfil_plugin_id.clone(), batch_size);
        for event in runtime
            .flow_events
            .iter()
            .chain(runtime.session_events.iter())
            .chain(runtime.process_context_events.iter())
            .chain(runtime.http_metadata_events.iter())
        {
            batch.push(event.clone())?;
        }

        let output = plugin_runtime.process_batch(&exfil_plugin_id, &mut context, &batch)?;
        for event in output.events {
            self.publish_static_exfiltration_output(runtime, event)?;
        }

        Ok(())
    }

    fn run_static_risk_alerting_stage(
        &self,
        replay_context: &ReplayContext,
        runtime: &mut MockPipelineRuntime<'_, '_>,
    ) -> Result<(), MockPipelineError> {
        let mut plugin_runtime = PluginRuntime::new();
        let risk_plugin_id = register_static_risk_alerting_plugin(&mut plugin_runtime)?;
        let manifest = plugin_runtime
            .manifest(&risk_plugin_id)
            .ok_or_else(|| {
                MockPipelineError::Contract(
                    "static risk alerting manifest was not registered".to_string(),
                )
            })?
            .clone();
        let contracts = contract_registry_for_manifest(&manifest)?;
        let mut permissions = PermissionResolver::new();
        permissions.register_plugin_manifest_permissions(&manifest);
        let validation = plugin_runtime.registry().validate_startup(
            &risk_plugin_id,
            &contracts,
            &permissions,
        )?;
        let mut context =
            plugin_context_for_manifest(&manifest, self.replay_trace_context(replay_context))?;
        plugin_runtime.start_plugin(&risk_plugin_id, &validation, &mut context)?;

        let batch_size = runtime.finding_events.len()
            + runtime.evidence_events.len()
            + runtime.risk_hint_events.len()
            + runtime.service_context_events.len()
            + runtime.asset_exposure_events.len()
            + runtime.process_context_events.len();
        let mut batch = PluginEventBatch::new(risk_plugin_id.clone(), batch_size);
        for event in runtime
            .evidence_events
            .iter()
            .chain(runtime.risk_hint_events.iter())
            .chain(runtime.service_context_events.iter())
            .chain(runtime.process_context_events.iter())
            .chain(runtime.asset_exposure_events.iter())
            .chain(runtime.finding_events.iter())
        {
            batch.push(event.clone())?;
        }

        let output = plugin_runtime.process_batch(&risk_plugin_id, &mut context, &batch)?;
        for event in output.events {
            self.publish_static_risk_output(runtime, event)?;
        }

        Ok(())
    }

    fn emit_topic(
        &self,
        topic_name: &str,
        replay_context: &ReplayContext,
        runtime: &mut MockPipelineRuntime<'_, '_>,
    ) -> Result<(), MockPipelineError> {
        match topic_name {
            RAW_PACKET_METADATA => {
                for metadata in &self.fixture.packet_metadata {
                    let event = self.envelope(
                        RAW_PACKET_METADATA,
                        plugin_id(PACKET_CAPTURE_PLUGIN_ID)?,
                        replay_context,
                        json!({
                            "record_kind": "packet_metadata",
                            "labels": self.fixture.labels,
                            "metadata": metadata
                        }),
                    )?;
                    self.publish_event(runtime, RAW_PACKET_METADATA, event, "packet metadata")?;
                }
            }
            NETWORK_PACKET_RECORD => {
                for packet in &self.fixture.packet_records {
                    let event = self.envelope(
                        NETWORK_PACKET_RECORD,
                        plugin_id(PACKET_NORMALIZATION_PLUGIN_ID)?,
                        replay_context,
                        json!({
                            "record_kind": "packet_record",
                            "labels": self.fixture.labels,
                            "record": packet
                        }),
                    )?;
                    self.publish_event(runtime, NETWORK_PACKET_RECORD, event, "packet record")?;
                }
            }
            NETWORK_FLOW_RECORD => {
                for flow in runtime.flow_records.clone() {
                    write_record(
                        runtime.stores.flow_store(),
                        flow.flow_id.clone(),
                        StoreKind::Flow,
                        labeled_metadata("flow_record", &flow, &self.fixture.labels)?,
                    )?;
                    let event = self.envelope(
                        NETWORK_FLOW_RECORD,
                        plugin_id(FLOW_SESSIONIZATION_PLUGIN_ID)?,
                        replay_context,
                        json!({
                            "record_kind": "flow_record",
                            "labels": self.fixture.labels,
                            "record": flow
                        }),
                    )?;
                    self.publish_event(runtime, NETWORK_FLOW_RECORD, event, "flow record")?;
                }
            }
            NETWORK_SESSION_RECORD => {
                for session in runtime.session_records.clone() {
                    write_record(
                        runtime.stores.session_store(),
                        session.session_id.clone(),
                        StoreKind::Session,
                        labeled_metadata("session_record", &session, &self.fixture.labels)?,
                    )?;
                    let event = self.envelope(
                        NETWORK_SESSION_RECORD,
                        plugin_id(FLOW_SESSIONIZATION_PLUGIN_ID)?,
                        replay_context,
                        json!({
                            "record_kind": "session_record",
                            "labels": self.fixture.labels,
                            "record": session
                        }),
                    )?;
                    self.publish_event(runtime, NETWORK_SESSION_RECORD, event, "session record")?;
                }
            }
            IDENTITY_PROCESS_CONTEXT => {
                let process = runtime.process_context.clone();
                write_record(
                    runtime.stores.process_context_store(),
                    process.process_context_id.clone(),
                    StoreKind::ProcessContext,
                    labeled_metadata("process_context", &process, &self.fixture.labels)?,
                )?;
                let event = self.envelope(
                    IDENTITY_PROCESS_CONTEXT,
                    plugin_id(PROCESS_CONTEXT_PLUGIN_ID)?,
                    replay_context,
                    serde_json::to_value(&process)?,
                )?;
                runtime.process_context_events.push(event.clone());
                self.publish_event(runtime, IDENTITY_PROCESS_CONTEXT, event, "process context")?;
            }
            IDENTITY_FLOW_ATTRIBUTION => {
                if runtime.flow_attributions.is_empty() {
                    runtime.flow_attributions = runtime
                        .flow_records
                        .iter()
                        .map(|flow| flow_attribution_for(flow, &runtime.process_context))
                        .collect();
                }
                for attribution in runtime.flow_attributions.clone() {
                    let event = self.envelope(
                        IDENTITY_FLOW_ATTRIBUTION,
                        plugin_id(PROCESS_CONTEXT_PLUGIN_ID)?,
                        replay_context,
                        json!({
                            "record_kind": "flow_attribution",
                            "labels": self.fixture.labels,
                            "record": attribution
                        }),
                    )?;
                    self.publish_event(
                        runtime,
                        IDENTITY_FLOW_ATTRIBUTION,
                        event,
                        "flow attribution",
                    )?;
                }
            }
            NETWORK_DNS_OBSERVATION => {
                if runtime.dns_observations.is_empty() {
                    runtime.dns_observations =
                        MockDnsEmitter.emit(&runtime.flow_records, &runtime.process_context)?;
                }
                for dns in runtime.dns_observations.clone() {
                    write_record(
                        runtime.stores.dns_store(),
                        dns.dns_observation_id.clone(),
                        StoreKind::Dns,
                        labeled_metadata("dns_observation", &dns, &self.fixture.labels)?,
                    )?;
                    let event = self.envelope(
                        NETWORK_DNS_OBSERVATION,
                        plugin_id(DNS_SECURITY_PLUGIN_ID)?,
                        replay_context,
                        json!({
                            "record_kind": "dns_observation",
                            "labels": self.fixture.labels,
                            "record": dns
                        }),
                    )?;
                    self.publish_event(runtime, NETWORK_DNS_OBSERVATION, event, "dns observation")?;
                }
            }
            NETWORK_TLS_OBSERVATION => {
                if runtime.tls_observations.is_empty() {
                    runtime.tls_observations =
                        MockTlsEmitter.emit(&runtime.flow_records, &runtime.process_context)?;
                }
                for tls in runtime.tls_observations.clone() {
                    write_record(
                        runtime.stores.tls_store(),
                        tls.tls_observation_id.clone(),
                        StoreKind::Tls,
                        labeled_metadata("tls_observation", &tls, &self.fixture.labels)?,
                    )?;
                    let event = self.envelope(
                        NETWORK_TLS_OBSERVATION,
                        plugin_id(TLS_FINGERPRINT_PLUGIN_ID)?,
                        replay_context,
                        json!({
                            "record_kind": "tls_observation",
                            "labels": self.fixture.labels,
                            "record": tls
                        }),
                    )?;
                    self.publish_event(runtime, NETWORK_TLS_OBSERVATION, event, "tls observation")?;
                }
            }
            NETWORK_HTTP_METADATA => {
                if runtime.http_metadata.is_empty() {
                    runtime.http_metadata =
                        MockHttpEmitter.emit(&runtime.flow_records, &runtime.process_context)?;
                }
                for http in runtime.http_metadata.clone() {
                    write_record(
                        runtime.stores.http_metadata_store(),
                        http.http_metadata_id.clone(),
                        StoreKind::HttpMetadata,
                        labeled_metadata("http_metadata", &http, &self.fixture.labels)?,
                    )?;
                    let event = self.envelope(
                        NETWORK_HTTP_METADATA,
                        plugin_id(HTTP_METADATA_PLUGIN_ID)?,
                        replay_context,
                        serde_json::to_value(&http)?,
                    )?;
                    runtime.http_metadata_events.push(event.clone());
                    self.publish_event(runtime, NETWORK_HTTP_METADATA, event, "http metadata")?;
                }
            }
            SERVICE_CAPABILITY_STATUS => {
                for service_context in self.fixture.service_capability_contexts.clone() {
                    let event = self.envelope(
                        SERVICE_CAPABILITY_STATUS,
                        plugin_id(SERVICE_CAPABILITY_CONTEXT_PLUGIN_ID)?,
                        replay_context,
                        serde_json::to_value(&service_context)?,
                    )?;
                    runtime.service_capability_contexts.push(service_context);
                    runtime.service_context_events.push(event.clone());
                    self.publish_event(
                        runtime,
                        SERVICE_CAPABILITY_STATUS,
                        event,
                        "service capability context",
                    )?;
                }
            }
            ASSET_SERVICE_INVENTORY => {
                let inventory = self.fixture.asset_service_inventory.clone();
                let event = self.envelope(
                    ASSET_SERVICE_INVENTORY,
                    plugin_id(ASSET_SERVICE_INVENTORY_PLUGIN_ID)?,
                    replay_context,
                    serde_json::to_value(&inventory)?,
                )?;
                runtime.asset_service_inventory = Some(inventory);
                runtime.asset_inventory_events.push(event.clone());
                self.publish_event(
                    runtime,
                    ASSET_SERVICE_INVENTORY,
                    event,
                    "asset service inventory",
                )?;
            }
            other => {
                return Err(MockPipelineError::Contract(format!(
                    "mock pipeline cannot emit undeclared topic {other}"
                )));
            }
        }
        Ok(())
    }

    fn publish_event(
        &self,
        runtime: &mut MockPipelineRuntime<'_, '_>,
        topic_name: &str,
        event: EventEnvelope,
        summary: &str,
    ) -> Result<(), MockPipelineError> {
        write_event_summary(runtime.stores, topic_name, &event)?;
        runtime.event_ids.push(event.event_id.clone());
        runtime
            .publish_reports
            .push(publish(runtime.bus, topic_name, event, summary)?);
        Ok(())
    }

    fn publish_static_flow_output(
        &self,
        runtime: &mut MockPipelineRuntime<'_, '_>,
        event: EventEnvelope,
    ) -> Result<(), MockPipelineError> {
        let topic_name = event.event_type.as_str().to_string();
        match topic_name.as_str() {
            NETWORK_FLOW_RECORD => {
                let flow = serde_json::from_value::<FlowRecord>(event.payload.clone())?;
                write_record(
                    runtime.stores.flow_store(),
                    flow.flow_id.clone(),
                    StoreKind::Flow,
                    labeled_metadata("flow_record", &flow, &self.fixture.labels)?,
                )?;
                runtime.flow_records.push(flow);
                runtime.flow_events.push(event.clone());
                self.publish_event(runtime, &topic_name, event, "flow record")?;
            }
            NETWORK_SESSION_RECORD => {
                let session = serde_json::from_value::<SessionRecord>(event.payload.clone())?;
                write_record(
                    runtime.stores.session_store(),
                    session.session_id.clone(),
                    StoreKind::Session,
                    labeled_metadata("session_record", &session, &self.fixture.labels)?,
                )?;
                runtime.session_records.push(session);
                runtime.session_events.push(event.clone());
                self.publish_event(runtime, &topic_name, event, "session record")?;
            }
            other => {
                return Err(MockPipelineError::Contract(format!(
                    "static flow sessionization emitted undeclared topic {other}"
                )));
            }
        }
        Ok(())
    }

    fn publish_static_asset_output(
        &self,
        runtime: &mut MockPipelineRuntime<'_, '_>,
        event: EventEnvelope,
    ) -> Result<(), MockPipelineError> {
        let topic_name = event.event_type.as_str().to_string();
        match topic_name.as_str() {
            ASSET_EXPOSURE => {
                let exposure =
                    serde_json::from_value::<AssetExposureOutput>(event.payload.clone())?;
                runtime.asset_exposures.push(exposure);
                runtime.asset_exposure_events.push(event.clone());
                self.publish_event(runtime, &topic_name, event, "asset exposure")?;
            }
            SECURITY_OBSERVATION => {
                let observation =
                    serde_json::from_value::<SecurityObservation>(event.payload.clone())?;
                runtime.asset_observations.push(observation);
                self.publish_event(runtime, &topic_name, event, "asset exposure observation")?;
            }
            SECURITY_FINDING => {
                let finding = serde_json::from_value::<Finding>(event.payload.clone())?;
                runtime.asset_findings.push(finding);
                runtime.finding_events.push(event.clone());
                self.publish_event(runtime, &topic_name, event, "asset exposure finding")?;
            }
            SECURITY_EVIDENCE => {
                let evidence = serde_json::from_value::<EvidenceItem>(event.payload.clone())?;
                runtime.asset_evidence.push(evidence);
                runtime.evidence_events.push(event.clone());
                self.publish_event(runtime, &topic_name, event, "asset exposure evidence")?;
            }
            GRAPH_HINT => {
                let hint = serde_json::from_value::<GraphHint>(event.payload.clone())?;
                runtime.asset_graph_hints.push(hint);
                self.publish_event(runtime, &topic_name, event, "asset exposure graph hint")?;
            }
            SECURITY_RISK
            | SECURITY_ALERT
            | SECURITY_INCIDENT
            | GRAPH_UPDATE
            | GRAPH_PATH
            | RESPONSE_PLAN
            | RESPONSE_RESULT
            | RESPONSE_ROLLBACK_RESULT
            | REPORT_GENERATED
            | REPORT_EXPORTED => {
                return Err(MockPipelineError::Contract(format!(
                    "static asset exposure emitted forbidden downstream topic {topic_name}"
                )));
            }
            other => {
                return Err(MockPipelineError::Contract(format!(
                    "static asset exposure emitted undeclared topic {other}"
                )));
            }
        }
        Ok(())
    }

    fn publish_static_lateral_output(
        &self,
        runtime: &mut MockPipelineRuntime<'_, '_>,
        event: EventEnvelope,
    ) -> Result<(), MockPipelineError> {
        let topic_name = event.event_type.as_str().to_string();
        match topic_name.as_str() {
            SECURITY_FINDING => {
                let finding = serde_json::from_value::<Finding>(event.payload.clone())?;
                runtime.lateral_findings.push(finding);
                runtime.finding_events.push(event.clone());
                self.publish_event(runtime, &topic_name, event, "lateral movement finding")?;
            }
            SECURITY_EVIDENCE => {
                let evidence = serde_json::from_value::<EvidenceItem>(event.payload.clone())?;
                runtime.lateral_evidence.push(evidence);
                runtime.evidence_events.push(event.clone());
                self.publish_event(runtime, &topic_name, event, "lateral movement evidence")?;
            }
            SECURITY_RISK_HINT => {
                let hint = serde_json::from_value::<RiskHint>(event.payload.clone())?;
                runtime.lateral_risk_hints.push(hint);
                runtime.risk_hint_events.push(event.clone());
                self.publish_event(runtime, &topic_name, event, "lateral movement risk hint")?;
            }
            GRAPH_HINT => {
                let hint = serde_json::from_value::<GraphHint>(event.payload.clone())?;
                runtime.lateral_graph_hints.push(hint);
                self.publish_event(runtime, &topic_name, event, "lateral movement graph hint")?;
            }
            SECURITY_RISK
            | SECURITY_ALERT
            | SECURITY_INCIDENT
            | GRAPH_UPDATE
            | GRAPH_PATH
            | RESPONSE_PLAN
            | RESPONSE_RESULT
            | RESPONSE_ROLLBACK_RESULT
            | REPORT_GENERATED
            | REPORT_EXPORTED => {
                return Err(MockPipelineError::Contract(format!(
                    "static lateral movement emitted forbidden downstream topic {topic_name}"
                )));
            }
            other => {
                return Err(MockPipelineError::Contract(format!(
                    "static lateral movement emitted undeclared topic {other}"
                )));
            }
        }
        Ok(())
    }

    fn publish_static_exfiltration_output(
        &self,
        runtime: &mut MockPipelineRuntime<'_, '_>,
        event: EventEnvelope,
    ) -> Result<(), MockPipelineError> {
        let topic_name = event.event_type.as_str().to_string();
        match topic_name.as_str() {
            SECURITY_FINDING => {
                let finding = serde_json::from_value::<Finding>(event.payload.clone())?;
                runtime.exfil_findings.push(finding);
                runtime.finding_events.push(event.clone());
                self.publish_event(runtime, &topic_name, event, "exfiltration finding")?;
            }
            SECURITY_EVIDENCE => {
                let evidence = serde_json::from_value::<EvidenceItem>(event.payload.clone())?;
                runtime.exfil_evidence.push(evidence);
                runtime.evidence_events.push(event.clone());
                self.publish_event(runtime, &topic_name, event, "exfiltration evidence")?;
            }
            SECURITY_RISK_HINT => {
                let hint = serde_json::from_value::<RiskHint>(event.payload.clone())?;
                runtime.exfil_risk_hints.push(hint);
                runtime.risk_hint_events.push(event.clone());
                self.publish_event(runtime, &topic_name, event, "exfiltration risk hint")?;
            }
            GRAPH_HINT => {
                let hint = serde_json::from_value::<GraphHint>(event.payload.clone())?;
                runtime.exfil_graph_hints.push(hint);
                self.publish_event(runtime, &topic_name, event, "exfiltration graph hint")?;
            }
            SECURITY_RISK
            | SECURITY_ALERT
            | SECURITY_INCIDENT
            | GRAPH_UPDATE
            | GRAPH_PATH
            | RESPONSE_PLAN
            | RESPONSE_RESULT
            | RESPONSE_ROLLBACK_RESULT
            | REPORT_GENERATED
            | REPORT_EXPORTED => {
                return Err(MockPipelineError::Contract(format!(
                    "static exfiltration detection emitted forbidden downstream topic {topic_name}"
                )));
            }
            other => {
                return Err(MockPipelineError::Contract(format!(
                    "static exfiltration detection emitted undeclared topic {other}"
                )));
            }
        }
        Ok(())
    }

    fn publish_static_risk_output(
        &self,
        runtime: &mut MockPipelineRuntime<'_, '_>,
        event: EventEnvelope,
    ) -> Result<(), MockPipelineError> {
        let topic_name = event.event_type.as_str().to_string();
        match topic_name.as_str() {
            SECURITY_RISK => {
                let risk = serde_json::from_value::<RiskEvent>(event.payload.clone())?;
                write_record(
                    runtime.stores.risk_store(),
                    risk.risk_event_id.clone(),
                    StoreKind::Risk,
                    labeled_metadata("risk_event", &risk, &self.fixture.labels)?,
                )?;
                runtime.risk_events.push(risk);
                self.publish_event(runtime, &topic_name, event, "risk event")?;
            }
            ALERT_CANDIDATE_CONTRACT => {
                runtime.alert_candidate_count += 1;
                self.publish_event(runtime, &topic_name, event, "alert candidate")?;
            }
            SECURITY_ALERT => {
                let alert = serde_json::from_value::<Alert>(event.payload.clone())?;
                write_record(
                    runtime.stores.alert_store(),
                    alert.id().clone(),
                    StoreKind::Alert,
                    labeled_metadata("alert", &alert, &self.fixture.labels)?,
                )?;
                runtime.alerts.push(alert);
                self.publish_event(runtime, &topic_name, event, "alert")?;
            }
            INCIDENT_CANDIDATE_CONTRACT => {
                runtime.incident_candidate_count += 1;
                self.publish_event(runtime, &topic_name, event, "incident candidate")?;
            }
            SECURITY_INCIDENT => {
                let incident = serde_json::from_value::<Incident>(event.payload.clone())?;
                write_record(
                    runtime.stores.incident_store(),
                    incident.id().clone(),
                    StoreKind::Incident,
                    labeled_metadata("incident", &incident, &self.fixture.labels)?,
                )?;
                runtime.incidents.push(incident);
                self.publish_event(runtime, &topic_name, event, "incident")?;
            }
            GRAPH_UPDATE
            | GRAPH_PATH
            | RESPONSE_PLAN
            | RESPONSE_RESULT
            | RESPONSE_ROLLBACK_RESULT
            | REPORT_GENERATED
            | REPORT_EXPORTED => {
                return Err(MockPipelineError::Contract(format!(
                    "static risk alerting emitted forbidden downstream topic {topic_name}"
                )));
            }
            other => {
                return Err(MockPipelineError::Contract(format!(
                    "static risk alerting emitted undeclared topic {other}"
                )));
            }
        }
        Ok(())
    }

    fn stage_checkpoint(
        &self,
        step: &ExecutionPlanStep,
        emitted_event_count: usize,
        replay_context: &ReplayContext,
    ) -> Result<MockPipelineCheckpoint, MockPipelineError> {
        let handle = CheckpointHandle::new(
            CheckpointScope::Node {
                pipeline_id: self.execution_plan.pipeline_id.clone(),
                node_id: step.node_id.clone(),
            },
            format!("mock_network_stage_{}", step.order_index),
        )?;
        let mut metadata = BTreeMap::new();
        metadata.insert("stage".to_string(), format!("{:?}", step.stage));
        metadata.insert("order_index".to_string(), step.order_index.to_string());
        metadata.insert(
            "input_topic_count".to_string(),
            step.input_topics.len().to_string(),
        );
        metadata.insert(
            "output_topic_count".to_string(),
            step.output_topics.len().to_string(),
        );
        metadata.insert(
            "emitted_event_count".to_string(),
            emitted_event_count.to_string(),
        );
        metadata.insert(
            "replay_id".to_string(),
            replay_context.replay_id.to_string(),
        );
        metadata.insert(
            "response_execution_disabled".to_string(),
            replay_context.response_execution_disabled.to_string(),
        );
        metadata.insert(
            "firewall_qos_isolation_disabled".to_string(),
            replay_context.firewall_qos_isolation_disabled.to_string(),
        );
        metadata.insert("labels".to_string(), self.fixture.labels.join(","));

        CheckpointRecord::new(
            &handle,
            format!("stage-{}-events-{emitted_event_count}", step.order_index),
            metadata,
        )
        .map(MockPipelineCheckpoint::from)
        .map_err(MockPipelineError::from)
    }

    fn envelope(
        &self,
        topic: &str,
        producer_plugin: sentinel_contracts::PluginId,
        replay_context: &ReplayContext,
        metadata_body: Value,
    ) -> Result<EventEnvelope, MockPipelineError> {
        let trace_context = self.replay_trace_context(replay_context);
        let mut envelope = EventEnvelope::new(
            EventType::new(topic)
                .map_err(|error| MockPipelineError::Contract(error.to_string()))?,
            MOCK_NETWORK_SCHEMA_VERSION,
            producer_plugin,
            trace_context,
        );
        envelope.privacy_class = PrivacyClass::Internal;
        envelope.quality_score = QualityScore::new(0.9).expect("fixture score is in range");
        envelope.payload = metadata_body;
        Ok(envelope)
    }

    fn packet_record_event(
        &self,
        producer_plugin: &PluginId,
        packet: PacketRecord,
        replay_context: &ReplayContext,
    ) -> Result<EventEnvelope, MockPipelineError> {
        let mut envelope = EventEnvelope::new(
            EventType::new(NETWORK_PACKET_RECORD)
                .map_err(|error| MockPipelineError::Contract(error.to_string()))?,
            MOCK_NETWORK_SCHEMA_VERSION,
            producer_plugin.clone(),
            self.replay_trace_context(replay_context),
        );
        envelope.privacy_class = PrivacyClass::Internal;
        envelope.quality_score = packet.quality_score.clone();
        envelope.payload = serde_json::to_value(packet)?;
        Ok(envelope)
    }

    fn replay_trace_context(&self, replay_context: &ReplayContext) -> TraceContext {
        let mut trace_context = self.fixture.trace_context.clone();
        trace_context.replay_id = Some(replay_context.replay_id.clone());
        trace_context
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockPipelineCheckpoint {
    pub checkpoint_id: String,
    pub scope: CheckpointScope,
    pub cursor: String,
    pub timestamp: Timestamp,
    pub metadata_redacted: BTreeMap<String, String>,
    pub privacy_class: PrivacyClass,
    pub normal_mode_content_persistence_blocked: bool,
}

impl From<CheckpointRecord> for MockPipelineCheckpoint {
    fn from(record: CheckpointRecord) -> Self {
        Self {
            checkpoint_id: record.checkpoint_id.to_string(),
            scope: record.scope,
            cursor: record.cursor,
            timestamp: record.timestamp,
            metadata_redacted: record.metadata_redacted,
            privacy_class: record.privacy_class,
            normal_mode_content_persistence_blocked: !record.stores_raw_payload
                && !record.stores_raw_packet
                && !record.stores_http_body,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MockPipelineStageRun {
    pub node_id: PipelineNodeId,
    pub stage: PipelineStage,
    pub order_index: usize,
    pub input_topics: Vec<TopicName>,
    pub output_topics: Vec<TopicName>,
    pub emitted_event_count: usize,
    pub checkpoint: MockPipelineCheckpoint,
    pub replay_response_execution_disabled: bool,
    pub used_plugin_runtime: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MockPipelineRunResult {
    pub trace_id: TraceId,
    pub labels: Vec<String>,
    pub event_ids: Vec<EventId>,
    pub publish_reports: Vec<PublishReport>,
    pub execution_plan: ExecutionPlan,
    pub scheduler_kind: SchedulerKind,
    pub replay_context: ReplayContext,
    pub stage_runs: Vec<MockPipelineStageRun>,
    pub packet_metadata_count: usize,
    pub packet_record_count: usize,
    pub flow_count: usize,
    pub session_count: usize,
    pub dns_count: usize,
    pub tls_count: usize,
    pub http_count: usize,
    pub process_context_count: usize,
    pub flow_attribution_count: usize,
    pub service_capability_context_count: usize,
    pub asset_service_inventory_count: usize,
    pub asset_exposure_count: usize,
    pub asset_observation_count: usize,
    pub asset_finding_count: usize,
    pub asset_evidence_count: usize,
    pub asset_graph_hint_count: usize,
    pub lateral_finding_count: usize,
    pub lateral_evidence_count: usize,
    pub lateral_risk_hint_count: usize,
    pub lateral_graph_hint_count: usize,
    pub exfil_finding_count: usize,
    pub exfil_evidence_count: usize,
    pub exfil_risk_hint_count: usize,
    pub exfil_graph_hint_count: usize,
    pub risk_event_count: usize,
    pub alert_candidate_count: usize,
    pub alert_count: usize,
    pub incident_candidate_count: usize,
    pub incident_count: usize,
    pub packet_metadata: Vec<MockPacketMetadata>,
    pub packet_records: Vec<PacketRecord>,
    pub flows: Vec<FlowRecord>,
    pub sessions: Vec<SessionRecord>,
    pub dns_observations: Vec<DnsObservation>,
    pub tls_observations: Vec<TlsObservation>,
    pub http_metadata: Vec<HttpMetadata>,
    pub process_context: ProcessContext,
    pub flow_attributions: Vec<FlowAttribution>,
    pub service_capability_contexts: Vec<ServiceCapabilityContext>,
    pub asset_service_inventory: ServiceInventoryInput,
    pub asset_exposures: Vec<AssetExposureOutput>,
    pub asset_observations: Vec<SecurityObservation>,
    pub asset_findings: Vec<Finding>,
    pub asset_evidence: Vec<EvidenceItem>,
    pub asset_graph_hints: Vec<GraphHint>,
    pub lateral_findings: Vec<Finding>,
    pub lateral_evidence: Vec<EvidenceItem>,
    pub lateral_risk_hints: Vec<RiskHint>,
    pub lateral_graph_hints: Vec<GraphHint>,
    pub exfil_findings: Vec<Finding>,
    pub exfil_evidence: Vec<EvidenceItem>,
    pub exfil_risk_hints: Vec<RiskHint>,
    pub exfil_graph_hints: Vec<GraphHint>,
    pub risk_events: Vec<RiskEvent>,
    pub alerts: Vec<Alert>,
    pub incidents: Vec<Incident>,
}

impl MockPipelineRunResult {
    pub fn emitted_topics(&self) -> Vec<String> {
        self.publish_reports
            .iter()
            .map(|report| report.topic.to_string())
            .collect()
    }

    pub fn all_events_enqueued(&self) -> bool {
        self.publish_reports.iter().all(|report| {
            report.enqueued > 0
                && report.rejected == 0
                && report.dropped == 0
                && report.dead_letter_ids.is_empty()
        })
    }

    pub fn exposes_complete_metadata_slice(&self) -> bool {
        self.packet_metadata_count == self.packet_metadata.len()
            && self.packet_record_count == self.packet_records.len()
            && self.flow_count == self.flows.len()
            && self.session_count == self.sessions.len()
            && self.dns_count == self.dns_observations.len()
            && self.tls_count == self.tls_observations.len()
            && self.http_count == self.http_metadata.len()
            && self.process_context_count == 1
            && self.flow_attribution_count == self.flow_attributions.len()
            && self.service_capability_context_count == self.service_capability_contexts.len()
            && self.asset_service_inventory_count == 1
            && self.asset_exposure_count == self.asset_exposures.len()
            && self.asset_observation_count == self.asset_observations.len()
            && self.asset_finding_count == self.asset_findings.len()
            && self.asset_evidence_count == self.asset_evidence.len()
            && self.asset_graph_hint_count == self.asset_graph_hints.len()
            && self.lateral_finding_count == self.lateral_findings.len()
            && self.lateral_evidence_count == self.lateral_evidence.len()
            && self.lateral_risk_hint_count == self.lateral_risk_hints.len()
            && self.lateral_graph_hint_count == self.lateral_graph_hints.len()
            && self.exfil_finding_count == self.exfil_findings.len()
            && self.exfil_evidence_count == self.exfil_evidence.len()
            && self.exfil_risk_hint_count == self.exfil_risk_hints.len()
            && self.exfil_graph_hint_count == self.exfil_graph_hints.len()
            && self.risk_event_count == self.risk_events.len()
            && self.alert_count == self.alerts.len()
            && self.incident_count == self.incidents.len()
    }

    pub fn trace_is_continuous(&self) -> bool {
        let trace_id = &self.trace_id;
        self.packet_metadata
            .iter()
            .all(|metadata| metadata.trace_id == *trace_id)
            && self
                .packet_records
                .iter()
                .all(|record| record.trace_id.as_ref() == Some(trace_id))
            && self
                .flows
                .iter()
                .all(|flow| flow.trace_id.as_ref() == Some(trace_id))
            && self.dns_observations.iter().all(|dns| {
                self.flows
                    .iter()
                    .any(|flow| Some(&flow.flow_id) == dns.flow_ref.as_ref())
                    && dns.process_ref == Some(self.process_context.process_context_id.clone())
            })
            && self.tls_observations.iter().all(|tls| {
                self.flows
                    .iter()
                    .any(|flow| Some(&flow.flow_id) == tls.flow_ref.as_ref())
                    && tls.process_ref == Some(self.process_context.process_context_id.clone())
            })
            && self.http_metadata.iter().all(|http| {
                self.flows
                    .iter()
                    .any(|flow| Some(&flow.flow_id) == http.flow_ref.as_ref())
                    && http.process_ref == Some(self.process_context.process_context_id.clone())
            })
            && self.flow_attributions.iter().all(|attribution| {
                self.flows
                    .iter()
                    .any(|flow| flow.flow_id == attribution.flow_id)
                    && attribution.process_ref
                        == Some(self.process_context.process_context_id.clone())
            })
    }

    pub fn stage_runtime_follows_execution_plan(&self) -> bool {
        self.stage_runs.len() == self.execution_plan.steps.len()
            && self
                .stage_runs
                .iter()
                .zip(self.execution_plan.steps.iter())
                .all(|(run, step)| {
                    run.node_id == step.node_id
                        && run.stage == step.stage
                        && run.order_index == step.order_index
                        && run.input_topics == step.input_topics
                        && run.output_topics == step.output_topics
                })
    }

    pub fn checkpoints_are_privacy_safe(&self) -> bool {
        self.stage_runs.iter().all(|run| {
            run.checkpoint.normal_mode_content_persistence_blocked
                && run
                    .checkpoint
                    .metadata_redacted
                    .keys()
                    .all(|key| !contains_private_marker(key))
        })
    }

    pub fn replay_disables_response_execution(&self) -> bool {
        self.replay_context.real_response_forbidden()
            && self
                .stage_runs
                .iter()
                .all(|run| run.replay_response_execution_disabled)
    }

    pub fn concrete_plugin_runtime_stage_count(&self) -> usize {
        self.stage_runs
            .iter()
            .filter(|run| run.used_plugin_runtime)
            .count()
    }

    pub fn detection_outputs_are_boundary_safe(&self) -> bool {
        let emitted = self.emitted_topics();
        let detection_outputs = self
            .stage_runs
            .iter()
            .filter(|run| run.stage == PipelineStage::Detection)
            .flat_map(|run| run.output_topics.iter().map(|topic| topic.as_str()))
            .collect::<Vec<_>>();
        !detection_outputs.iter().any(|topic| {
            matches!(
                *topic,
                SECURITY_RISK
                    | ALERT_CANDIDATE_CONTRACT
                    | SECURITY_ALERT
                    | INCIDENT_CANDIDATE_CONTRACT
                    | SECURITY_INCIDENT
            )
        }) && !emitted.iter().any(|topic| {
            matches!(
                topic.as_str(),
                GRAPH_UPDATE
                    | GRAPH_PATH
                    | RESPONSE_PLAN
                    | RESPONSE_RESULT
                    | RESPONSE_ROLLBACK_RESULT
                    | REPORT_GENERATED
                    | REPORT_EXPORTED
            )
        }) && self
            .exfil_risk_hints
            .iter()
            .all(|hint| hint.evidence_input_only && !hint.creates_alert && !hint.creates_incident)
            && self.lateral_risk_hints.iter().all(|hint| {
                hint.evidence_input_only && !hint.creates_alert && !hint.creates_incident
            })
    }

    pub fn risk_outputs_are_boundary_safe(&self) -> bool {
        self.risk_events.iter().all(|event| {
            !event.contributing_findings.is_empty()
                && event
                    .risk_reasons
                    .iter()
                    .all(|reason| !contains_private_marker(&reason.summary_redacted))
        }) && self.alerts.iter().all(|alert| {
            !alert.finding_refs().is_empty()
                && !contains_private_marker(alert.title_redacted())
                && !contains_private_marker(alert.summary_redacted())
        }) && self.incidents.iter().all(|incident| {
            !incident.alert_refs().is_empty()
                && !contains_private_marker(incident.title_redacted())
                && !contains_private_marker(incident.summary_redacted())
        })
    }

    pub fn exfil_evidence_has_metadata_source_refs(&self) -> bool {
        !self.exfil_evidence.is_empty()
            && self
                .exfil_evidence
                .iter()
                .all(|evidence| !evidence.source_event_refs.is_empty())
    }

    pub fn lateral_evidence_has_metadata_source_refs(&self) -> bool {
        !self.lateral_evidence.is_empty()
            && self
                .lateral_evidence
                .iter()
                .all(|evidence| !evidence.source_event_refs.is_empty())
    }

    pub fn asset_outputs_have_metadata_source_refs(&self) -> bool {
        !self.asset_observations.is_empty()
            && self
                .asset_observations
                .iter()
                .all(|observation| !observation.source_event_refs.is_empty())
            && self
                .asset_evidence
                .iter()
                .all(|evidence| !evidence.source_event_refs.is_empty())
    }
}

#[derive(Debug)]
pub enum MockPipelineError {
    Checkpoint(CheckpointError),
    Contract(String),
    EventBus(EventBusError),
    Observation(NetworkObservationError),
    Pipeline(PipelineDagError),
    PluginRuntime(PluginRuntimeError),
    Storage(StorageError),
    Serialization(serde_json::Error),
}

impl fmt::Display for MockPipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Checkpoint(error) => write!(f, "mock pipeline checkpoint error: {error}"),
            Self::Contract(error) => write!(f, "mock pipeline contract error: {error}"),
            Self::EventBus(error) => write!(f, "mock pipeline event bus error: {error}"),
            Self::Observation(error) => write!(f, "mock pipeline observation error: {error}"),
            Self::Pipeline(error) => write!(f, "mock pipeline DAG error: {error}"),
            Self::PluginRuntime(error) => {
                write!(f, "mock pipeline plugin runtime error: {error}")
            }
            Self::Storage(error) => write!(f, "mock pipeline storage error: {error}"),
            Self::Serialization(error) => write!(f, "mock pipeline serialization error: {error}"),
        }
    }
}

impl std::error::Error for MockPipelineError {}

impl From<CheckpointError> for MockPipelineError {
    fn from(value: CheckpointError) -> Self {
        Self::Checkpoint(value)
    }
}

impl From<EventBusError> for MockPipelineError {
    fn from(value: EventBusError) -> Self {
        Self::EventBus(value)
    }
}

impl From<NetworkObservationError> for MockPipelineError {
    fn from(value: NetworkObservationError) -> Self {
        Self::Observation(value)
    }
}

impl From<PipelineDagError> for MockPipelineError {
    fn from(value: PipelineDagError) -> Self {
        Self::Pipeline(value)
    }
}

impl From<PluginRuntimeError> for MockPipelineError {
    fn from(value: PluginRuntimeError) -> Self {
        Self::PluginRuntime(value)
    }
}

impl From<StorageError> for MockPipelineError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

impl From<serde_json::Error> for MockPipelineError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

fn is_flow_sessionization_step(step: &ExecutionPlanStep) -> bool {
    step.input_topics
        .iter()
        .any(|topic| topic.as_str() == NETWORK_PACKET_RECORD)
        && step
            .output_topics
            .iter()
            .any(|topic| topic.as_str() == NETWORK_FLOW_RECORD)
        && step
            .output_topics
            .iter()
            .any(|topic| topic.as_str() == NETWORK_SESSION_RECORD)
}

fn is_exfiltration_detection_step(step: &ExecutionPlanStep) -> bool {
    step.stage == PipelineStage::Detection
        && step
            .input_topics
            .iter()
            .any(|topic| topic.as_str() == NETWORK_HTTP_METADATA)
        && step
            .output_topics
            .iter()
            .any(|topic| topic.as_str() == SECURITY_FINDING)
        && step
            .output_topics
            .iter()
            .any(|topic| topic.as_str() == GRAPH_HINT)
}

fn is_asset_exposure_detection_step(step: &ExecutionPlanStep) -> bool {
    step.stage == PipelineStage::Detection
        && step
            .input_topics
            .iter()
            .any(|topic| topic.as_str() == ASSET_SERVICE_INVENTORY)
        && step
            .output_topics
            .iter()
            .any(|topic| topic.as_str() == ASSET_EXPOSURE)
}

fn is_lateral_movement_detection_step(step: &ExecutionPlanStep) -> bool {
    step.stage == PipelineStage::Detection
        && step
            .input_topics
            .iter()
            .any(|topic| topic.as_str() == ASSET_EXPOSURE)
        && step
            .input_topics
            .iter()
            .any(|topic| topic.as_str() == NETWORK_FLOW_RECORD)
        && step
            .output_topics
            .iter()
            .any(|topic| topic.as_str() == SECURITY_RISK_HINT)
        && step
            .output_topics
            .iter()
            .any(|topic| topic.as_str() == GRAPH_HINT)
}

fn is_risk_alerting_step(step: &ExecutionPlanStep) -> bool {
    step.stage == PipelineStage::Risk
        && step
            .input_topics
            .iter()
            .any(|topic| topic.as_str() == SECURITY_FINDING)
        && step
            .input_topics
            .iter()
            .any(|topic| topic.as_str() == SECURITY_RISK_HINT)
        && step
            .output_topics
            .iter()
            .any(|topic| topic.as_str() == SECURITY_RISK)
        && step
            .output_topics
            .iter()
            .any(|topic| topic.as_str() == SECURITY_INCIDENT)
}

fn contract_registry_for_manifest(
    manifest: &PluginManifest,
) -> Result<ContractRegistry, MockPipelineError> {
    let mut registry = ContractRegistry::new();
    for contract in manifest
        .input_contracts
        .iter()
        .chain(manifest.output_contracts.iter())
    {
        registry
            .register(contract.clone())
            .map_err(|error| MockPipelineError::Contract(error.to_string()))?;
    }
    Ok(registry)
}

fn plugin_context_for_manifest(
    manifest: &PluginManifest,
    trace_context: TraceContext,
) -> Result<PluginContext<'static>, MockPipelineError> {
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

fn topic_for_contract(contract: &ContractDescriptor) -> Result<TopicName, MockPipelineError> {
    topic(
        contract
            .topic
            .as_deref()
            .unwrap_or(contract.contract_name.as_str()),
    )
}

fn flow_attribution_for(flow: &FlowRecord, process: &ProcessContext) -> FlowAttribution {
    let method = match flow.protocol {
        TransportProtocol::Tcp => AttributionMethod::TcpEndpointSnapshot,
        TransportProtocol::Udp => AttributionMethod::UdpEndpointSnapshot,
        _ => AttributionMethod::ConnectionTableCorrelation,
    };
    let mut attribution = FlowAttribution::unknown(flow.flow_id.clone()).with_process(
        process.process_context_id.clone(),
        method,
        AttributionConfidence::High,
    );
    attribution.os_process_id = Some(process.os_process_id);
    attribution.process_start_time = Some(process.process_start_time.clone());
    attribution.process_path_protected = process.process_path_protected.clone();
    attribution.process_hash = process.process_hash.clone();
    attribution.signer_status = process.signer_status.clone();
    attribution.parent_process_ref = process.parent_process_ref.clone();
    attribution.user_session_ref = process.user_session_ref.clone();
    attribution.local_ip = Some(flow.src_ip);
    attribution.local_port = Some(flow.src_port);
    attribution.remote_ip = Some(flow.dst_ip);
    attribution.remote_port = Some(flow.dst_port);
    attribution.visibility_level = VisibilityLevel::MetadataOnly;
    attribution.collection_mode = CollectionMode::Mock;
    attribution.known_limitations = vec![
        "Attribution is derived from metadata correlation.".to_string(),
        "Packet metadata alone does not prove packet-to-process truth.".to_string(),
    ];
    attribution.timestamp = Timestamp::now();
    attribution
}

fn mock_pipeline_dag() -> Result<PipelineDag, MockPipelineError> {
    let mut dag = PipelineDag::new("MOCK_ONLY network metadata pipeline")?;
    let packet_source = dag.add_node(node(
        "MOCK_ONLY packet metadata source",
        PipelineStage::Source,
        vec![],
        vec![RAW_PACKET_METADATA],
    )?)?;
    let packet_normalization = dag.add_node(
        node(
            "MOCK_ONLY packet normalization",
            PipelineStage::Normalize,
            vec![RAW_PACKET_METADATA],
            vec![NETWORK_PACKET_RECORD],
        )?
        .depends_on(packet_source.clone()),
    )?;
    let flow_sessionization = dag.add_node(
        node(
            "static runtime flow sessionization",
            PipelineStage::Transform,
            vec![NETWORK_PACKET_RECORD],
            vec![NETWORK_FLOW_RECORD, NETWORK_SESSION_RECORD],
        )?
        .depends_on(packet_normalization.clone()),
    )?;
    let process_context = dag.add_node(
        node(
            "MOCK_ONLY process context",
            PipelineStage::Context,
            vec![NETWORK_FLOW_RECORD],
            vec![IDENTITY_PROCESS_CONTEXT, IDENTITY_FLOW_ATTRIBUTION],
        )?
        .depends_on(flow_sessionization.clone()),
    )?;
    let dns = dag.add_node(
        node(
            "MOCK_ONLY DNS observation",
            PipelineStage::Protocol,
            vec![NETWORK_FLOW_RECORD, IDENTITY_PROCESS_CONTEXT],
            vec![NETWORK_DNS_OBSERVATION],
        )?
        .depends_on(flow_sessionization.clone())
        .depends_on(process_context.clone()),
    )?;
    let tls = dag.add_node(
        node(
            "MOCK_ONLY TLS observation",
            PipelineStage::Protocol,
            vec![NETWORK_FLOW_RECORD, IDENTITY_PROCESS_CONTEXT],
            vec![NETWORK_TLS_OBSERVATION],
        )?
        .depends_on(flow_sessionization.clone())
        .depends_on(process_context.clone()),
    )?;
    let asset_inventory = dag.add_node(node(
        "MOCK_ONLY asset service inventory",
        PipelineStage::Context,
        vec![],
        vec![ASSET_SERVICE_INVENTORY],
    )?)?;
    let service_context = dag.add_node(node(
        "MOCK_ONLY service capability context",
        PipelineStage::Context,
        vec![],
        vec![SERVICE_CAPABILITY_STATUS],
    )?)?;
    let asset_exposure = dag.add_node(
        node(
            "static runtime asset exposure detection",
            PipelineStage::Detection,
            vec![ASSET_SERVICE_INVENTORY],
            vec![
                ASSET_EXPOSURE,
                SECURITY_OBSERVATION,
                SECURITY_FINDING,
                SECURITY_EVIDENCE,
                GRAPH_HINT,
            ],
        )?
        .depends_on(asset_inventory.clone()),
    )?;
    let lateral = dag.add_node(
        node(
            "static runtime lateral movement detection",
            PipelineStage::Detection,
            vec![
                NETWORK_FLOW_RECORD,
                NETWORK_SESSION_RECORD,
                IDENTITY_PROCESS_CONTEXT,
                ASSET_EXPOSURE,
            ],
            vec![
                SECURITY_FINDING,
                SECURITY_EVIDENCE,
                SECURITY_RISK_HINT,
                GRAPH_HINT,
            ],
        )?
        .depends_on(flow_sessionization.clone())
        .depends_on(process_context.clone())
        .depends_on(asset_exposure.clone()),
    )?;
    let http = dag.add_node(
        node(
            "MOCK_ONLY HTTP metadata observation",
            PipelineStage::Protocol,
            vec![NETWORK_FLOW_RECORD, IDENTITY_PROCESS_CONTEXT],
            vec![NETWORK_HTTP_METADATA],
        )?
        .depends_on(flow_sessionization)
        .depends_on(process_context.clone()),
    )?;
    let exfil = dag.add_node(
        node(
            "static runtime exfiltration detection",
            PipelineStage::Detection,
            vec![
                NETWORK_FLOW_RECORD,
                NETWORK_SESSION_RECORD,
                IDENTITY_PROCESS_CONTEXT,
                NETWORK_HTTP_METADATA,
            ],
            vec![
                SECURITY_FINDING,
                SECURITY_EVIDENCE,
                SECURITY_RISK_HINT,
                GRAPH_HINT,
            ],
        )?
        .depends_on(http.clone()),
    )?;
    let risk = dag.add_node(
        node(
            "static runtime risk alerting",
            PipelineStage::Risk,
            vec![
                SECURITY_FINDING,
                SECURITY_EVIDENCE,
                SECURITY_RISK_HINT,
                ASSET_EXPOSURE,
                IDENTITY_PROCESS_CONTEXT,
                SERVICE_CAPABILITY_STATUS,
            ],
            vec![
                SECURITY_RISK,
                ALERT_CANDIDATE_CONTRACT,
                SECURITY_ALERT,
                INCIDENT_CANDIDATE_CONTRACT,
                SECURITY_INCIDENT,
            ],
        )?
        .depends_on(asset_exposure.clone())
        .depends_on(lateral.clone())
        .depends_on(exfil.clone())
        .depends_on(service_context.clone())
        .depends_on(process_context.clone()),
    )?;
    let _ = (
        dns,
        tls,
        asset_inventory,
        service_context,
        asset_exposure,
        lateral,
        http,
        exfil,
        risk,
    );
    dag.validate()?;
    Ok(dag)
}

fn node(
    name: &str,
    stage: PipelineStage,
    input: Vec<&str>,
    output: Vec<&str>,
) -> Result<PipelineNode, MockPipelineError> {
    let input_topics = input
        .into_iter()
        .map(topic)
        .collect::<Result<Vec<_>, _>>()?;
    let output_topics = output
        .into_iter()
        .map(topic)
        .collect::<Result<Vec<_>, _>>()?;
    let mut binding = StageBinding::metadata_only(input_topics, output_topics);
    binding.priority_lane = PriorityLane::P2Normal;
    PipelineNode::new(name, stage, binding).map_err(MockPipelineError::from)
}

fn ensure_observer_subscriptions(bus: &mut EventBus) -> Result<(), MockPipelineError> {
    ensure_topic_registered(
        bus,
        SECURITY_RISK_HINT,
        TopicLayer::Security,
        PriorityLane::P1High,
    )?;
    ensure_topic_registered(
        bus,
        ASSET_SERVICE_INVENTORY,
        TopicLayer::Context,
        PriorityLane::P2Normal,
    )?;
    ensure_topic_registered(
        bus,
        SERVICE_CAPABILITY_STATUS,
        TopicLayer::Context,
        PriorityLane::P2Normal,
    )?;
    ensure_topic_registered(
        bus,
        ALERT_CANDIDATE_CONTRACT,
        TopicLayer::Security,
        PriorityLane::P1High,
    )?;
    ensure_topic_registered(
        bus,
        INCIDENT_CANDIDATE_CONTRACT,
        TopicLayer::Security,
        PriorityLane::P1High,
    )?;
    for topic_name in [
        RAW_PACKET_METADATA,
        NETWORK_PACKET_RECORD,
        NETWORK_FLOW_RECORD,
        NETWORK_SESSION_RECORD,
        IDENTITY_PROCESS_CONTEXT,
        IDENTITY_FLOW_ATTRIBUTION,
        NETWORK_DNS_OBSERVATION,
        NETWORK_TLS_OBSERVATION,
        NETWORK_HTTP_METADATA,
        ASSET_SERVICE_INVENTORY,
        SERVICE_CAPABILITY_STATUS,
        ASSET_EXPOSURE,
        SECURITY_OBSERVATION,
        SECURITY_FINDING,
        SECURITY_EVIDENCE,
        SECURITY_RISK_HINT,
        SECURITY_RISK,
        ALERT_CANDIDATE_CONTRACT,
        SECURITY_ALERT,
        INCIDENT_CANDIDATE_CONTRACT,
        SECURITY_INCIDENT,
        GRAPH_HINT,
    ] {
        bus.subscribe_to(topic(topic_name)?, "mock-network-pipeline-observer")?;
    }
    Ok(())
}

fn ensure_topic_registered(
    bus: &mut EventBus,
    topic_name: &str,
    layer: TopicLayer,
    priority: PriorityLane,
) -> Result<(), MockPipelineError> {
    let topic_name = topic(topic_name)?;
    if bus.topic(&topic_name).is_none() {
        bus.register_topic(Topic::new(
            topic_name,
            layer,
            MOCK_NETWORK_SCHEMA_VERSION,
            priority,
        ));
    }
    Ok(())
}

fn publish(
    bus: &mut EventBus,
    topic_name: &str,
    event: EventEnvelope,
    summary: &str,
) -> Result<PublishReport, MockPipelineError> {
    let mut options = PublishOptions::new(format!("{summary} metadata only"));
    options.priority_lane = Some(PriorityLane::P2Normal);
    bus.publish(topic(topic_name)?, event, options)
        .map_err(MockPipelineError::from)
}

fn write_record<TId>(
    store: impl LogicalStore<TId>,
    id: TId,
    store_kind: StoreKind,
    metadata: Value,
) -> Result<(), MockPipelineError>
where
    TId: Clone + fmt::Display + Serialize + serde::de::DeserializeOwned,
{
    let record = LogicalRecord::metadata_only(
        id,
        MOCK_NETWORK_SCHEMA_VERSION,
        store_kind.default_storage_privacy_class(),
        metadata,
    );
    store.append(record).map_err(MockPipelineError::from)
}

fn write_event_summary(
    stores: &SqliteStoreFactory<'_>,
    topic_name: &str,
    event: &EventEnvelope,
) -> Result<(), MockPipelineError> {
    write_record(
        stores.event_store(),
        event.event_id.clone(),
        StoreKind::Event,
        json!({
            "record_kind": "event_summary",
            "topic": topic_name,
            "event_id": event.event_id.to_string(),
            "event_type": event.event_type.as_str(),
            "trace_id": event.trace_id.to_string(),
            "producer_plugin": event.producer_plugin.to_string(),
            "privacy_class": event.privacy_class,
            "labels": mock_labels()
        }),
    )
}

fn labeled_metadata<T: Serialize>(
    record_kind: &str,
    record: &T,
    labels: &[String],
) -> Result<Value, MockPipelineError> {
    Ok(json!({
        "record_kind": record_kind,
        "labels": labels,
        "record": serde_json::to_value(record)?
    }))
}

fn mock_process_context() -> ProcessContext {
    let mut process = ProcessContext::new(4_240, "mock_browser_process");
    process.process_path_protected = Some("pathref_mock_browser_process".to_string());
    process.process_hash = Some("sha256_mock_browser_process".to_string());
    process.signer_status = SignerStatus::Signed;
    process.visibility_level = VisibilityLevel::MetadataOnly;
    process.collection_mode = CollectionMode::Mock;
    process.known_limitations = vec![
        "MOCK_ONLY process metadata fixture.".to_string(),
        "Attribution confidence must remain visible.".to_string(),
    ];
    process
}

fn mock_service_capability_contexts() -> Result<Vec<ServiceCapabilityContext>, MockPipelineError> {
    let observed_at = Timestamp::now();
    Ok(vec![
        service_capability_context(
            "service_boundary",
            ServiceAdapterMode::StubOnly,
            ServiceCapabilityStatus::Available,
            Some(ServiceReasonCode::StubOnlyMode),
            vec![
                ServiceLimitationFlag::LocalOnly,
                ServiceLimitationFlag::StubOnly,
                ServiceLimitationFlag::ReadOnlyAllowlist,
                ServiceLimitationFlag::NoRawContentRetention,
                ServiceLimitationFlag::ControlPlaneOwnedByLocalCore,
                ServiceLimitationFlag::NoProductionServiceLifecycle,
            ],
            "service_ipc.status",
            observed_at.clone(),
        )?,
        service_capability_context(
            "capture_adapter",
            ServiceAdapterMode::StubOnly,
            ServiceCapabilityStatus::Unavailable,
            Some(ServiceReasonCode::CaptureUnavailable),
            vec![
                ServiceLimitationFlag::StubOnly,
                ServiceLimitationFlag::MetadataOnly,
                ServiceLimitationFlag::NoRawContentRetention,
                ServiceLimitationFlag::NoPrivilegedCapture,
                ServiceLimitationFlag::ReducedVisibility,
                ServiceLimitationFlag::NoProductionServiceLifecycle,
            ],
            "service_ipc.capture_health",
            observed_at.clone(),
        )?,
        service_capability_context(
            "process_attribution",
            ServiceAdapterMode::StubOnly,
            ServiceCapabilityStatus::Degraded,
            Some(ServiceReasonCode::ProcessAttributionLimited),
            vec![
                ServiceLimitationFlag::StubOnly,
                ServiceLimitationFlag::MetadataOnly,
                ServiceLimitationFlag::NoProcessAttribution,
                ServiceLimitationFlag::ReducedVisibility,
                ServiceLimitationFlag::NoProductionServiceLifecycle,
            ],
            "service_stub.process_attribution",
            observed_at.clone(),
        )?,
        service_capability_context(
            "response_executor",
            ServiceAdapterMode::Disabled,
            ServiceCapabilityStatus::Disabled,
            Some(ServiceReasonCode::ResponseExecutionDisabled),
            vec![
                ServiceLimitationFlag::StubOnly,
                ServiceLimitationFlag::ReadOnlyAllowlist,
                ServiceLimitationFlag::NoResponseExecution,
                ServiceLimitationFlag::NoOsAction,
                ServiceLimitationFlag::NoProductionServiceLifecycle,
            ],
            "service_stub.response_executor",
            observed_at,
        )?,
    ])
}

fn service_capability_context(
    capability_id: &str,
    adapter_mode: ServiceAdapterMode,
    status: ServiceCapabilityStatus,
    reason_code: Option<ServiceReasonCode>,
    limitation_flags: Vec<ServiceLimitationFlag>,
    source_provenance_id: &str,
    observed_at: Timestamp,
) -> Result<ServiceCapabilityContext, MockPipelineError> {
    let mut context =
        ServiceCapabilityContext::new(capability_id, adapter_mode, status, source_provenance_id)
            .map_err(|error| MockPipelineError::Contract(error.to_string()))?;
    context.reason_code = reason_code;
    context.limitation_flags = limitation_flags;
    context.observed_at = observed_at;
    context
        .validate_boundary()
        .map_err(|error| MockPipelineError::Contract(error.to_string()))?;
    Ok(context)
}

fn mock_asset_service_inventory_input() -> Result<ServiceInventoryInput, MockPipelineError> {
    let mut process = ProcessContext::new(4_454, "mock_winrm_listener");
    process.process_path_protected = Some("pathref_mock_winrm_listener".to_string());
    process.process_hash = Some("sha256_mock_winrm_listener".to_string());
    process.signer_status = SignerStatus::Signed;
    process.visibility_level = VisibilityLevel::MetadataOnly;
    process.collection_mode = CollectionMode::Mock;
    process.known_limitations = vec![
        "Service inventory is derived from fixture endpoint metadata.".to_string(),
        "Process-to-port attribution remains metadata confidence only.".to_string(),
    ];

    let mut listening = ListeningPortInput::new(
        ip("192.168.1.25")?,
        5985,
        TransportProtocol::Tcp,
        BindScope::Lan,
    )
    .with_process_context(process, AttributionConfidence::High)
    .with_service(
        "service_ref_winrm",
        "Windows Remote Management Service",
        ServiceKind::WindowsService,
    )
    .with_source(InventorySource::MockEndpointSnapshot);
    listening.known_limitations = vec![
        "Fixture service inventory is metadata only.".to_string(),
        "Reachability scope is declared by the endpoint snapshot.".to_string(),
    ];

    let mut input = ServiceInventoryInput::new(vec![listening]);
    input.asset_hostname_protected = Some("hostref_mock_internal_server".to_string());
    input.asset_ip = Some(ip("192.168.1.25")?);
    input.visibility_level = VisibilityLevel::MetadataOnly;
    input.collection_mode = CollectionMode::Mock;
    input.labels = mock_labels();
    Ok(input)
}

fn topic(value: &str) -> Result<TopicName, MockPipelineError> {
    TopicName::new(value).map_err(|error| MockPipelineError::Contract(error.to_string()))
}

fn plugin_id(value: &str) -> Result<sentinel_contracts::PluginId, MockPipelineError> {
    sentinel_contracts::PluginId::parse_str(value)
        .map_err(|error| MockPipelineError::Contract(error.to_string()))
}

fn ip(value: &str) -> Result<IpAddress, MockPipelineError> {
    IpAddress::parse_str(value).map_err(|error| MockPipelineError::Contract(error.to_string()))
}

fn mock_labels() -> Vec<String> {
    vec![
        MOCK_ONLY_LABEL.to_string(),
        FIXTURE_ONLY_LABEL.to_string(),
        NOT_FOR_PRODUCTION_LABEL.to_string(),
    ]
}

fn contains_private_marker(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "raw_packet",
        "packet_bytes",
        "payload",
        "http_body",
        "cookie",
        "token",
        "credential",
        "api_key",
        "secret",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use sentinel_contracts::{PageRequest, QueryRequest, QueryScope};
    use sentinel_platform::GRAPH_UPDATE;
    use sentinel_storage::{
        logical_store_migration, InMemoryMigrationAuditSink, MigrationRunner, SchemaMetadata,
    };

    #[test]
    fn mock_pipeline_emits_declared_topics_and_writes_metadata_stores(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = MockNetworkPipeline::new()?;
        let result = pipeline.run(&mut bus, &stores)?;

        assert_eq!(result.scheduler_kind, SchedulerKind::Realtime);
        assert!(result.stage_runtime_follows_execution_plan());
        assert_eq!(result.concrete_plugin_runtime_stage_count(), 5);
        assert!(result.checkpoints_are_privacy_safe());
        assert!(result.replay_disables_response_execution());
        assert!(result
            .stage_runs
            .iter()
            .all(|stage| stage.emitted_event_count > 0));
        assert_eq!(result.service_capability_context_count, 4);
        assert_eq!(result.asset_service_inventory_count, 1);
        assert_eq!(result.asset_exposure_count, 1);
        assert_eq!(result.asset_observation_count, 1);
        assert!(result.asset_finding_count >= 1);
        assert!(result.asset_evidence_count >= 1);
        assert!(result.asset_graph_hint_count >= 1);
        assert_eq!(result.lateral_finding_count, 1);
        assert!(result.lateral_evidence_count >= 1);
        assert_eq!(result.lateral_risk_hint_count, 0);
        assert!(result.lateral_graph_hint_count >= 1);
        assert_eq!(result.exfil_finding_count, 1);
        assert!(result.exfil_evidence_count >= 1);
        assert_eq!(result.exfil_graph_hint_count, 0);
        assert!(result.risk_event_count >= 1);
        assert!(result.alert_candidate_count >= 1);
        assert!(result.alert_count <= result.alert_candidate_count);
        assert!(result.incident_count <= result.incident_candidate_count);
        assert_eq!(result.incident_count, result.incidents.len());
        assert!(result.detection_outputs_are_boundary_safe());
        assert!(result.risk_outputs_are_boundary_safe());
        assert!(result.asset_outputs_have_metadata_source_refs());
        assert!(result.lateral_evidence_has_metadata_source_refs());
        assert!(result.exfil_evidence_has_metadata_source_refs());
        assert!(result.all_events_enqueued());
        assert!(result
            .emitted_topics()
            .contains(&RAW_PACKET_METADATA.to_string()));
        assert!(result
            .emitted_topics()
            .contains(&NETWORK_FLOW_RECORD.to_string()));
        assert!(result
            .emitted_topics()
            .contains(&NETWORK_DNS_OBSERVATION.to_string()));
        assert!(result
            .emitted_topics()
            .contains(&NETWORK_TLS_OBSERVATION.to_string()));
        assert!(result
            .emitted_topics()
            .contains(&NETWORK_HTTP_METADATA.to_string()));
        assert!(result
            .emitted_topics()
            .contains(&ASSET_SERVICE_INVENTORY.to_string()));
        assert!(result
            .emitted_topics()
            .contains(&SERVICE_CAPABILITY_STATUS.to_string()));
        assert!(result
            .emitted_topics()
            .contains(&ASSET_EXPOSURE.to_string()));
        assert!(result
            .emitted_topics()
            .contains(&SECURITY_OBSERVATION.to_string()));
        assert!(result
            .emitted_topics()
            .contains(&SECURITY_FINDING.to_string()));
        assert!(result
            .emitted_topics()
            .contains(&SECURITY_EVIDENCE.to_string()));
        assert!(result.emitted_topics().contains(&SECURITY_RISK.to_string()));
        assert!(result
            .emitted_topics()
            .contains(&ALERT_CANDIDATE_CONTRACT.to_string()));
        assert_eq!(stores.flow_store().create_snapshot()?.record_count, 6);
        assert_eq!(stores.dns_store().create_snapshot()?.record_count, 1);
        assert_eq!(stores.tls_store().create_snapshot()?.record_count, 1);
        assert_eq!(
            stores.http_metadata_store().create_snapshot()?.record_count,
            1
        );
        assert_eq!(
            stores
                .process_context_store()
                .create_snapshot()?
                .record_count,
            1
        );
        assert_eq!(
            usize::try_from(stores.risk_store().create_snapshot()?.record_count)
                .expect("risk record count fits in usize"),
            result.risk_event_count
        );
        assert_eq!(
            usize::try_from(stores.alert_store().create_snapshot()?.record_count)
                .expect("alert record count fits in usize"),
            result.alert_count
        );
        assert_eq!(
            usize::try_from(stores.incident_store().create_snapshot()?.record_count)
                .expect("incident record count fits in usize"),
            result.incident_count
        );
        let serialized_service_contexts =
            serde_json::to_string(&result.service_capability_contexts)?.to_ascii_lowercase();
        for forbidden in [
            "raw_packet",
            "http_body",
            "cookie",
            "credential",
            "api_key",
            "path",
        ] {
            assert!(
                !serialized_service_contexts.contains(forbidden),
                "service context leaked forbidden marker {forbidden}"
            );
        }
        let raw_subscription = bus
            .subscriptions()
            .into_iter()
            .find(|subscription| subscription.route.source_topic.as_str() == RAW_PACKET_METADATA)
            .expect("raw metadata subscription")
            .subscription_id
            .clone();
        let raw_delivery = bus.poll(&raw_subscription)?.expect("raw metadata delivery");
        assert_eq!(
            raw_delivery.event.envelope.replay_id,
            Some(result.replay_context.replay_id.clone())
        );
        assert!(bus.dead_letters().is_empty());
        Ok(())
    }

    #[test]
    fn dag_flow_stage_uses_static_plugin_runtime_outputs() -> Result<(), Box<dyn std::error::Error>>
    {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = MockNetworkPipeline::new()?;
        let result = pipeline.run(&mut bus, &stores)?;

        let flow_stage = result
            .stage_runs
            .iter()
            .find(|stage| {
                stage
                    .output_topics
                    .iter()
                    .any(|topic| topic.as_str() == NETWORK_FLOW_RECORD)
                    && stage
                        .output_topics
                        .iter()
                        .any(|topic| topic.as_str() == NETWORK_SESSION_RECORD)
            })
            .expect("flow stage");
        assert!(flow_stage.used_plugin_runtime);
        assert_eq!(
            flow_stage.emitted_event_count,
            result.flow_count + result.session_count
        );

        let flow_subscription = bus
            .subscriptions()
            .into_iter()
            .find(|subscription| subscription.route.source_topic.as_str() == NETWORK_FLOW_RECORD)
            .expect("flow subscription")
            .subscription_id
            .clone();
        let flow_delivery = bus.poll(&flow_subscription)?.expect("flow delivery");
        assert_eq!(
            flow_delivery.event.envelope.producer_plugin.to_string(),
            FLOW_SESSIONIZATION_PLUGIN_ID
        );
        assert!(flow_delivery
            .event
            .envelope
            .payload
            .get("record_kind")
            .is_none());
        let flow =
            serde_json::from_value::<FlowRecord>(flow_delivery.event.envelope.payload.clone())?;
        assert!(result
            .flows
            .iter()
            .any(|result_flow| result_flow.flow_id == flow.flow_id));

        let session_subscription = bus
            .subscriptions()
            .into_iter()
            .find(|subscription| subscription.route.source_topic.as_str() == NETWORK_SESSION_RECORD)
            .expect("session subscription")
            .subscription_id
            .clone();
        let session_delivery = bus.poll(&session_subscription)?.expect("session delivery");
        assert_eq!(
            session_delivery.event.envelope.producer_plugin.to_string(),
            FLOW_SESSIONIZATION_PLUGIN_ID
        );
        assert!(session_delivery
            .event
            .envelope
            .payload
            .get("record_kind")
            .is_none());
        let session = serde_json::from_value::<SessionRecord>(
            session_delivery.event.envelope.payload.clone(),
        )?;
        assert!(result
            .sessions
            .iter()
            .any(|result_session| result_session.session_id == session.session_id));
        Ok(())
    }

    #[test]
    fn dag_asset_stage_uses_static_runtime_outputs_and_source_refs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = MockNetworkPipeline::new()?;
        let result = pipeline.run(&mut bus, &stores)?;

        let asset_stage = result
            .stage_runs
            .iter()
            .find(|stage| {
                stage.stage == PipelineStage::Detection
                    && stage
                        .output_topics
                        .iter()
                        .any(|topic| topic.as_str() == ASSET_EXPOSURE)
            })
            .expect("asset exposure detection stage");
        assert!(asset_stage.used_plugin_runtime);
        assert_eq!(
            asset_stage.emitted_event_count,
            result.asset_exposure_count
                + result.asset_observation_count
                + result.asset_finding_count
                + result.asset_evidence_count
                + result.asset_graph_hint_count
        );
        assert_eq!(result.asset_service_inventory_count, 1);
        assert_eq!(result.asset_exposure_count, 1);
        assert_eq!(result.asset_observation_count, 1);
        assert!(result.asset_finding_count >= 1);
        assert!(result.asset_evidence_count >= 1);
        assert!(result.asset_graph_hint_count >= 1);
        assert!(result.asset_observations.iter().all(|observation| {
            observation
                .producer_plugin
                .as_ref()
                .is_some_and(|plugin_id| plugin_id.to_string() == ASSET_EXPOSURE_PLUGIN_ID)
        }));
        assert!(result.asset_findings.iter().all(|finding| {
            finding.producer_plugin().to_string() == ASSET_EXPOSURE_PLUGIN_ID
                && finding.finding_type().starts_with("asset_risk.")
        }));
        assert!(result.asset_outputs_have_metadata_source_refs());

        let source_event_ids = result
            .event_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert!(result
            .asset_observations
            .iter()
            .all(|observation| observation
                .source_event_refs
                .iter()
                .all(|event_id| source_event_ids.contains(&event_id.to_string()))));
        assert!(result.asset_evidence.iter().all(|evidence| evidence
            .source_event_refs
            .iter()
            .all(|event_id| source_event_ids.contains(&event_id.to_string()))));

        let exposure_subscription = bus
            .subscriptions()
            .into_iter()
            .find(|subscription| subscription.route.source_topic.as_str() == ASSET_EXPOSURE)
            .expect("asset exposure subscription")
            .subscription_id
            .clone();
        let exposure_delivery = bus
            .poll(&exposure_subscription)?
            .expect("asset exposure delivery");
        assert_eq!(
            exposure_delivery.event.envelope.producer_plugin.to_string(),
            ASSET_EXPOSURE_PLUGIN_ID
        );
        let exposure = serde_json::from_value::<AssetExposureOutput>(
            exposure_delivery.event.envelope.payload.clone(),
        )?;
        assert_eq!(exposure.observations.len(), result.asset_observation_count);
        assert_eq!(exposure.findings.len(), result.asset_finding_count);

        assert!(result.detection_outputs_are_boundary_safe());
        assert!(bus.dead_letters().is_empty());
        Ok(())
    }

    #[test]
    fn dag_lateral_stage_uses_static_runtime_outputs_and_source_refs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = MockNetworkPipeline::new()?;
        let result = pipeline.run(&mut bus, &stores)?;

        let lateral_stage = result
            .stage_runs
            .iter()
            .find(|stage| {
                stage.stage == PipelineStage::Detection
                    && stage
                        .input_topics
                        .iter()
                        .any(|topic| topic.as_str() == ASSET_EXPOSURE)
                    && stage
                        .input_topics
                        .iter()
                        .any(|topic| topic.as_str() == NETWORK_FLOW_RECORD)
            })
            .expect("lateral movement detection stage");
        assert!(lateral_stage.used_plugin_runtime);
        assert_eq!(
            lateral_stage.emitted_event_count,
            result.lateral_finding_count
                + result.lateral_evidence_count
                + result.lateral_risk_hint_count
                + result.lateral_graph_hint_count
        );
        assert_eq!(result.lateral_finding_count, 1);
        assert!(result.lateral_evidence_count >= 1);
        assert_eq!(result.lateral_risk_hint_count, 0);
        assert!(result.lateral_graph_hint_count >= 1);
        assert!(result.lateral_findings.iter().all(|finding| {
            finding.producer_plugin().to_string() == LATERAL_MOVEMENT_PLUGIN_ID
                && finding.finding_type() == "security.finding.lateral_movement_lite"
        }));
        assert!(result.lateral_evidence_has_metadata_source_refs());

        let source_event_ids = result
            .event_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert!(result.lateral_evidence.iter().all(|evidence| evidence
            .source_event_refs
            .iter()
            .all(|event_id| source_event_ids.contains(&event_id.to_string()))));
        assert!(result.lateral_graph_hints.iter().all(|hint| {
            hint.producer_plugin.to_string() == LATERAL_MOVEMENT_PLUGIN_ID
                && !hint.evidence_refs.is_empty()
        }));
        assert!(result.detection_outputs_are_boundary_safe());
        assert!(bus.dead_letters().is_empty());
        Ok(())
    }

    #[test]
    fn dag_exfil_stage_uses_static_runtime_outputs_and_source_refs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = MockNetworkPipeline::new()?;
        let result = pipeline.run(&mut bus, &stores)?;

        let exfil_stage = result
            .stage_runs
            .iter()
            .find(|stage| {
                stage.stage == PipelineStage::Detection
                    && stage
                        .input_topics
                        .iter()
                        .any(|topic| topic.as_str() == NETWORK_HTTP_METADATA)
                    && stage
                        .output_topics
                        .iter()
                        .any(|topic| topic.as_str() == SECURITY_RISK_HINT)
            })
            .expect("exfil detection stage");
        assert!(exfil_stage.used_plugin_runtime);
        assert_eq!(
            exfil_stage.emitted_event_count,
            result.exfil_finding_count
                + result.exfil_evidence_count
                + result.exfil_risk_hint_count
                + result.exfil_graph_hint_count
        );
        assert_eq!(result.exfil_finding_count, 1);
        assert!(result.exfil_evidence_count >= 1);
        assert_eq!(
            result.exfil_graph_hint_count, 0,
            "process attribution is not claimed by this safe metadata source"
        );
        assert!(result.exfil_findings.iter().all(|finding| {
            finding.producer_plugin().to_string() == EXFILTRATION_DETECTION_PLUGIN_ID
                && finding.finding_type() == "security.finding.exfiltration"
        }));
        assert!(result.exfil_evidence_has_metadata_source_refs());
        let source_event_ids = result
            .event_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert!(result.exfil_evidence.iter().all(|evidence| evidence
            .source_event_refs
            .iter()
            .all(|event_id| source_event_ids.contains(&event_id.to_string()))));

        let evidence_subscription = bus
            .subscriptions()
            .into_iter()
            .find(|subscription| subscription.route.source_topic.as_str() == SECURITY_EVIDENCE)
            .expect("evidence subscription")
            .subscription_id
            .clone();
        let evidence_delivery = bus
            .poll(&evidence_subscription)?
            .expect("evidence delivery");
        let evidence = serde_json::from_value::<EvidenceItem>(
            evidence_delivery.event.envelope.payload.clone(),
        )?;
        assert!(!evidence.source_event_refs.is_empty());
        assert!(result.detection_outputs_are_boundary_safe());
        assert!(bus.dead_letters().is_empty());
        Ok(())
    }

    #[test]
    fn dag_risk_stage_uses_static_runtime_outputs_and_declared_topics(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = MockNetworkPipeline::new()?;
        let result = pipeline.run(&mut bus, &stores)?;

        let risk_stage = result
            .stage_runs
            .iter()
            .find(|stage| {
                stage.stage == PipelineStage::Risk
                    && stage
                        .output_topics
                        .iter()
                        .any(|topic| topic.as_str() == SECURITY_RISK)
                    && stage
                        .output_topics
                        .iter()
                        .any(|topic| topic.as_str() == SECURITY_INCIDENT)
            })
            .expect("risk alerting stage");
        assert!(risk_stage.used_plugin_runtime);
        assert!(risk_stage
            .input_topics
            .iter()
            .any(|topic| topic.as_str() == SERVICE_CAPABILITY_STATUS));
        assert_eq!(
            risk_stage.emitted_event_count,
            result.risk_event_count
                + result.alert_candidate_count
                + result.alert_count
                + result.incident_candidate_count
                + result.incident_count
        );
        assert!(result.risk_event_count >= 1);
        assert!(result.alert_candidate_count >= 1);
        assert!(result.alert_count <= result.alert_candidate_count);
        assert!(result.incident_count <= result.incident_candidate_count);
        assert_eq!(result.incident_count, result.incidents.len());

        let risk_subscription = bus
            .subscriptions()
            .into_iter()
            .find(|subscription| subscription.route.source_topic.as_str() == SECURITY_RISK)
            .expect("risk subscription")
            .subscription_id
            .clone();
        let risk_delivery = bus.poll(&risk_subscription)?.expect("risk delivery");
        assert_eq!(
            risk_delivery.event.envelope.producer_plugin.to_string(),
            RISK_ALERTING_PLUGIN_ID
        );
        let risk =
            serde_json::from_value::<RiskEvent>(risk_delivery.event.envelope.payload.clone())?;
        assert!(result
            .risk_events
            .iter()
            .any(|event| event.risk_event_id == risk.risk_event_id));
        assert!(result.risk_events.iter().any(|event| {
            event.risk_reasons.iter().any(|reason| {
                reason.reason_type == "service_capture_unavailable"
                    || reason.reason_type == "service_process_visibility_reduced"
            })
        }));

        if result.alert_count > 0 {
            let alert_subscription = bus
                .subscriptions()
                .into_iter()
                .find(|subscription| subscription.route.source_topic.as_str() == SECURITY_ALERT)
                .expect("alert subscription")
                .subscription_id
                .clone();
            let alert_delivery = bus.poll(&alert_subscription)?.expect("alert delivery");
            assert_eq!(
                alert_delivery.event.envelope.producer_plugin.to_string(),
                RISK_ALERTING_PLUGIN_ID
            );
            let alert =
                serde_json::from_value::<Alert>(alert_delivery.event.envelope.payload.clone())?;
            assert!(result.alerts.iter().any(|item| item.id() == alert.id()));
        }

        if result.incident_count > 0 {
            let incident_subscription = bus
                .subscriptions()
                .into_iter()
                .find(|subscription| subscription.route.source_topic.as_str() == SECURITY_INCIDENT)
                .expect("incident subscription")
                .subscription_id
                .clone();
            let incident_delivery = bus
                .poll(&incident_subscription)?
                .expect("incident delivery");
            assert_eq!(
                incident_delivery.event.envelope.producer_plugin.to_string(),
                RISK_ALERTING_PLUGIN_ID
            );
            let incident = serde_json::from_value::<Incident>(
                incident_delivery.event.envelope.payload.clone(),
            )?;
            assert!(result
                .incidents
                .iter()
                .any(|item| item.id() == incident.id()));
        }

        assert!(result.detection_outputs_are_boundary_safe());
        assert!(result.risk_outputs_are_boundary_safe());
        assert!(bus.dead_letters().is_empty());
        Ok(())
    }

    #[test]
    fn dag_asset_stage_returns_observation_only_for_benign_local_listener(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = benign_asset_inventory_pipeline()?;
        let result = pipeline.run(&mut bus, &stores)?;

        let asset_stage = result
            .stage_runs
            .iter()
            .find(|stage| {
                stage.stage == PipelineStage::Detection
                    && stage
                        .output_topics
                        .iter()
                        .any(|topic| topic.as_str() == ASSET_EXPOSURE)
            })
            .expect("asset exposure detection stage");
        assert!(asset_stage.used_plugin_runtime);
        assert_eq!(asset_stage.emitted_event_count, 3);
        assert_eq!(result.asset_service_inventory_count, 1);
        assert_eq!(result.asset_exposure_count, 1);
        assert_eq!(result.asset_observation_count, 1);
        assert_eq!(result.asset_finding_count, 0);
        assert_eq!(result.asset_evidence_count, 0);
        assert_eq!(result.asset_graph_hint_count, 1);
        assert!(result.asset_outputs_have_metadata_source_refs());
        assert!(result.detection_outputs_are_boundary_safe());
        assert!(bus.dead_letters().is_empty());
        Ok(())
    }

    #[test]
    fn dag_lateral_stage_returns_no_events_without_internal_probe_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = benign_lateral_pipeline()?;
        let result = pipeline.run(&mut bus, &stores)?;

        let lateral_stage = result
            .stage_runs
            .iter()
            .find(|stage| {
                stage.stage == PipelineStage::Detection
                    && stage
                        .input_topics
                        .iter()
                        .any(|topic| topic.as_str() == ASSET_EXPOSURE)
                    && stage
                        .input_topics
                        .iter()
                        .any(|topic| topic.as_str() == NETWORK_FLOW_RECORD)
            })
            .expect("lateral movement detection stage");
        assert!(lateral_stage.used_plugin_runtime);
        assert_eq!(lateral_stage.emitted_event_count, 0);
        assert_eq!(result.lateral_finding_count, 0);
        assert_eq!(result.lateral_evidence_count, 0);
        assert_eq!(result.lateral_risk_hint_count, 0);
        assert_eq!(result.lateral_graph_hint_count, 0);
        assert!(result.detection_outputs_are_boundary_safe());
        assert!(bus.dead_letters().is_empty());
        Ok(())
    }

    #[test]
    fn dag_exfil_stage_returns_no_events_for_benign_metadata_window(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = benign_upload_pipeline()?;
        let result = pipeline.run(&mut bus, &stores)?;

        let exfil_stage = result
            .stage_runs
            .iter()
            .find(|stage| {
                stage.stage == PipelineStage::Detection
                    && stage
                        .input_topics
                        .iter()
                        .any(|topic| topic.as_str() == NETWORK_HTTP_METADATA)
                    && stage
                        .output_topics
                        .iter()
                        .any(|topic| topic.as_str() == SECURITY_RISK_HINT)
            })
            .expect("exfil detection stage");
        assert!(exfil_stage.used_plugin_runtime);
        assert_eq!(exfil_stage.emitted_event_count, 0);
        assert_eq!(result.exfil_finding_count, 0);
        assert_eq!(result.exfil_evidence_count, 0);
        assert_eq!(result.exfil_risk_hint_count, 0);
        assert_eq!(result.exfil_graph_hint_count, 0);
        assert!(result.detection_outputs_are_boundary_safe());
        assert!(bus.dead_letters().is_empty());
        Ok(())
    }

    #[test]
    fn dag_risk_stage_returns_no_events_without_upstream_findings(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = benign_risk_pipeline()?;
        let result = pipeline.run(&mut bus, &stores)?;

        let risk_stage = result
            .stage_runs
            .iter()
            .find(|stage| stage.stage == PipelineStage::Risk)
            .expect("risk stage");
        assert!(risk_stage.used_plugin_runtime);
        assert_eq!(risk_stage.emitted_event_count, 0);
        assert_eq!(result.risk_event_count, 0);
        assert_eq!(result.alert_candidate_count, 0);
        assert_eq!(result.alert_count, 0);
        assert_eq!(result.incident_candidate_count, 0);
        assert_eq!(result.incident_count, 0);
        assert!(result.detection_outputs_are_boundary_safe());
        assert!(result.risk_outputs_are_boundary_safe());
        assert!(bus.dead_letters().is_empty());
        Ok(())
    }

    #[test]
    fn fixture_trace_connects_packet_flow_dns_tls_http_and_attribution(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pipeline = MockNetworkPipeline::new()?;
        let fixture = pipeline.fixture();

        assert!(fixture.trace_is_continuous());
        assert!(
            fixture
                .dns_observations
                .iter()
                .all(|dns| dns.process_ref
                    == Some(fixture.process_context.process_context_id.clone()))
        );
        assert!(
            fixture
                .tls_observations
                .iter()
                .all(|tls| tls.process_ref
                    == Some(fixture.process_context.process_context_id.clone()))
        );
        assert!(fixture.http_metadata.iter().all(
            |http| http.process_ref == Some(fixture.process_context.process_context_id.clone())
        ));
        assert!(fixture
            .flow_attributions
            .iter()
            .all(|attribution| attribution.process_ref
                == Some(fixture.process_context.process_context_id.clone())));
        Ok(())
    }

    #[test]
    fn run_result_exposes_full_metadata_only_slice_for_next_tasks(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = MockNetworkPipeline::new()?;
        let result = pipeline.run(&mut bus, &stores)?;

        assert!(result.exposes_complete_metadata_slice());
        assert!(result.trace_is_continuous());
        assert_eq!(result.stage_runs.len(), result.execution_plan.steps.len());
        assert!(result.stage_runtime_follows_execution_plan());
        assert!(result.checkpoints_are_privacy_safe());
        assert!(result.replay_disables_response_execution());
        assert!(result
            .stage_runs
            .iter()
            .all(|stage| stage.checkpoint.privacy_class == PrivacyClass::Internal));
        assert!(result
            .packet_metadata
            .iter()
            .all(|packet| packet.labels.iter().any(|label| label == MOCK_ONLY_LABEL)));
        assert!(result
            .packet_records
            .iter()
            .all(|packet| packet.visibility_level == VisibilityLevel::MetadataOnly));
        assert_eq!(
            result.process_context.visibility_level,
            VisibilityLevel::MetadataOnly
        );
        assert_eq!(
            result.asset_service_inventory.visibility_level,
            VisibilityLevel::MetadataOnly
        );
        assert_eq!(
            result.asset_service_inventory.collection_mode,
            CollectionMode::Mock
        );
        assert!(result
            .asset_service_inventory
            .listening_ports
            .iter()
            .all(|port| port.process_context.as_ref().is_some_and(|process| {
                process.visibility_level == VisibilityLevel::MetadataOnly
                    && process.collection_mode == CollectionMode::Mock
            })));
        assert!(result.asset_outputs_have_metadata_source_refs());
        assert!(result.lateral_evidence_has_metadata_source_refs());
        assert!(result.risk_outputs_are_boundary_safe());
        assert!(result
            .lateral_findings
            .iter()
            .all(|finding| finding.finding_type() == "security.finding.lateral_movement_lite"));
        assert!(result
            .flow_attributions
            .iter()
            .all(|attribution| attribution.process_ref
                == Some(result.process_context.process_context_id.clone())));

        let serialized = serde_json::to_string(&result)?;
        assert!(!serialized.contains("raw_payload"));
        assert!(!serialized.contains("packet_bytes"));
        assert!(!serialized.contains("http_body"));
        assert!(!serialized.contains("cookie"));
        assert!(!serialized.contains("credential"));
        assert!(!serialized.contains("api_key"));
        assert!(!serialized.contains("case=local"));
        Ok(())
    }

    #[test]
    fn pipeline_dag_uses_metadata_detection_and_risk_topics_without_graph_or_response_writes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pipeline = MockNetworkPipeline::new()?;
        let topics = pipeline
            .execution_plan()
            .steps
            .iter()
            .flat_map(|step| step.output_topics.iter().map(ToString::to_string))
            .collect::<Vec<_>>();

        assert!(topics.contains(&RAW_PACKET_METADATA.to_string()));
        assert!(topics.contains(&NETWORK_PACKET_RECORD.to_string()));
        assert!(topics.contains(&NETWORK_FLOW_RECORD.to_string()));
        assert!(topics.contains(&NETWORK_HTTP_METADATA.to_string()));
        assert!(topics.contains(&ASSET_SERVICE_INVENTORY.to_string()));
        assert!(topics.contains(&ASSET_EXPOSURE.to_string()));
        assert!(topics.contains(&SECURITY_OBSERVATION.to_string()));
        assert!(topics.contains(&SECURITY_FINDING.to_string()));
        assert!(topics.contains(&SECURITY_EVIDENCE.to_string()));
        assert!(topics.contains(&SECURITY_RISK_HINT.to_string()));
        assert!(topics.contains(&GRAPH_HINT.to_string()));
        assert!(topics.contains(&SECURITY_RISK.to_string()));
        assert!(topics.contains(&ALERT_CANDIDATE_CONTRACT.to_string()));
        assert!(topics.contains(&SECURITY_ALERT.to_string()));
        assert!(topics.contains(&INCIDENT_CANDIDATE_CONTRACT.to_string()));
        assert!(topics.contains(&SECURITY_INCIDENT.to_string()));
        assert!(!topics.contains(&GRAPH_UPDATE.to_string()));
        assert!(!topics.contains(&GRAPH_PATH.to_string()));
        assert!(!topics.contains(&RESPONSE_PLAN.to_string()));
        assert!(!topics.contains(&RESPONSE_RESULT.to_string()));
        assert!(!topics.contains(&RESPONSE_ROLLBACK_RESULT.to_string()));
        assert!(pipeline
            .execution_plan()
            .steps
            .iter()
            .filter(|step| step.stage == PipelineStage::Detection)
            .all(|step| {
                step.output_topics.iter().all(|topic| {
                    !matches!(
                        topic.as_str(),
                        SECURITY_RISK
                            | ALERT_CANDIDATE_CONTRACT
                            | SECURITY_ALERT
                            | INCIDENT_CANDIDATE_CONTRACT
                            | SECURITY_INCIDENT
                    )
                })
            }));
        assert!(pipeline
            .execution_plan()
            .steps
            .iter()
            .all(|step| !step.stage.can_emit_response_execution()));
        Ok(())
    }

    #[test]
    fn stored_metadata_rejects_private_content_markers() -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = MockNetworkPipeline::new()?;
        pipeline.run(&mut bus, &stores)?;

        let events = stores
            .event_store()
            .query(QueryRequest::new(QueryScope::Global).with_page(PageRequest::first(50)?))?;
        let risk = stores.risk_store().create_snapshot()?;
        let alerts = stores.alert_store().create_snapshot()?;
        let incidents = stores.incident_store().create_snapshot()?;
        let serialized = serde_json::to_string(&serde_json::json!({
            "events": events,
            "risk": risk,
            "alerts": alerts,
            "incidents": incidents,
        }))?;

        assert!(!serialized.contains("raw_payload"));
        assert!(!serialized.contains("packet_bytes"));
        assert!(!serialized.contains("http_body"));
        assert!(!serialized.contains("cookie"));
        assert!(!serialized.contains("credential"));
        assert!(!serialized.contains("api_key"));
        assert!(!serialized.contains("case=local"));
        assert!(!serialized.contains("query_string"));
        Ok(())
    }

    #[test]
    fn mock_labels_are_visible_in_run_result_and_store_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let mut bus = EventBus::with_core_topics();
        let pipeline = MockNetworkPipeline::new()?;
        let result = pipeline.run(&mut bus, &stores)?;
        let flow_snapshot = stores.flow_store().create_snapshot()?;

        assert!(result.labels.contains(&MOCK_ONLY_LABEL.to_string()));
        assert!(result.labels.contains(&FIXTURE_ONLY_LABEL.to_string()));
        assert!(flow_snapshot.records.iter().all(|record| record
            .metadata
            .get("labels")
            .is_some_and(|labels| labels.to_string().contains(MOCK_ONLY_LABEL))));
        Ok(())
    }

    fn initialized_connection() -> Result<Connection, Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        {
            let mut runner = MigrationRunner::new(&mut connection);
            runner.initialize(&SchemaMetadata::storage_foundation())?;
            let mut audit = InMemoryMigrationAuditSink::default();
            runner.apply_all(&[logical_store_migration()?], &mut audit)?;
        }
        Ok(connection)
    }

    fn benign_upload_pipeline() -> Result<MockNetworkPipeline, MockPipelineError> {
        let mut fixture = MockPipelineFixture::build()?;
        for metadata in &mut fixture.packet_metadata {
            metadata.direction = NetworkDirection::Inbound;
            if metadata.dst_port == Some(80) {
                metadata.length_bytes = 640;
            }
        }
        rebuild_fixture_network_derivatives(&mut fixture)?;

        Ok(MockNetworkPipeline {
            fixture,
            execution_plan: mock_pipeline_dag()?.build_execution_plan()?,
        })
    }

    fn benign_lateral_pipeline() -> Result<MockNetworkPipeline, MockPipelineError> {
        let mut fixture = MockPipelineFixture::build()?;
        fixture
            .packet_metadata
            .retain(|metadata| metadata.direction != NetworkDirection::Lateral);
        rebuild_fixture_network_derivatives(&mut fixture)?;

        Ok(MockNetworkPipeline {
            fixture,
            execution_plan: mock_pipeline_dag()?.build_execution_plan()?,
        })
    }

    fn benign_risk_pipeline() -> Result<MockNetworkPipeline, MockPipelineError> {
        let mut fixture = MockPipelineFixture::build()?;
        fixture.asset_service_inventory = benign_asset_service_inventory_input()?;
        fixture
            .packet_metadata
            .retain(|metadata| metadata.direction != NetworkDirection::Lateral);
        for metadata in &mut fixture.packet_metadata {
            metadata.direction = NetworkDirection::Inbound;
            if metadata.dst_port == Some(80) {
                metadata.length_bytes = 640;
            }
        }
        rebuild_fixture_network_derivatives(&mut fixture)?;

        Ok(MockNetworkPipeline {
            fixture,
            execution_plan: mock_pipeline_dag()?.build_execution_plan()?,
        })
    }

    fn rebuild_fixture_network_derivatives(
        fixture: &mut MockPipelineFixture,
    ) -> Result<(), MockPipelineError> {
        fixture.packet_records = fixture
            .packet_metadata
            .iter()
            .map(MockPacketMetadata::to_packet_record)
            .collect::<Vec<_>>();
        let flow_emission =
            MockFlowEmitter.emit(&fixture.packet_records, &fixture.process_context)?;
        fixture.flows = flow_emission.flows;
        fixture.sessions = flow_emission.sessions;
        fixture.flow_attributions = flow_emission.attributions;
        fixture.dns_observations = MockDnsEmitter.emit(&fixture.flows, &fixture.process_context)?;
        fixture.tls_observations = MockTlsEmitter.emit(&fixture.flows, &fixture.process_context)?;
        fixture.http_metadata = MockHttpEmitter.emit(&fixture.flows, &fixture.process_context)?;
        Ok(())
    }

    fn benign_asset_inventory_pipeline() -> Result<MockNetworkPipeline, MockPipelineError> {
        let mut fixture = MockPipelineFixture::build()?;
        fixture.asset_service_inventory = benign_asset_service_inventory_input()?;

        Ok(MockNetworkPipeline {
            fixture,
            execution_plan: mock_pipeline_dag()?.build_execution_plan()?,
        })
    }

    fn benign_asset_service_inventory_input() -> Result<ServiceInventoryInput, MockPipelineError> {
        let mut process = ProcessContext::new(4_455, "mock_local_metadata_service");
        process.process_path_protected = Some("pathref_mock_local_metadata_service".to_string());
        process.process_hash = Some("sha256_mock_local_metadata_service".to_string());
        process.signer_status = SignerStatus::Signed;
        process.visibility_level = VisibilityLevel::MetadataOnly;
        process.collection_mode = CollectionMode::Mock;
        process.known_limitations = vec![
            "Service inventory is derived from fixture endpoint metadata.".to_string(),
            "Process-to-port attribution remains metadata confidence only.".to_string(),
        ];

        let mut listening = ListeningPortInput::new(
            ip("127.0.0.1")?,
            8443,
            TransportProtocol::Tcp,
            BindScope::Loopback,
        )
        .with_process_context(process, AttributionConfidence::High)
        .with_service(
            "service_ref_local_metadata",
            "Local Metadata Service",
            ServiceKind::UserProcess,
        )
        .with_seen_before(true)
        .with_source(InventorySource::MockEndpointSnapshot);
        listening.known_limitations = vec![
            "Fixture service inventory is metadata only.".to_string(),
            "Loopback listener is not reachable beyond the local host.".to_string(),
        ];

        let mut input = ServiceInventoryInput::new(vec![listening]);
        input.asset_hostname_protected = Some("hostref_mock_workstation".to_string());
        input.asset_ip = Some(ip("192.0.2.10")?);
        input.visibility_level = VisibilityLevel::MetadataOnly;
        input.collection_mode = CollectionMode::Mock;
        input.labels = mock_labels();
        Ok(input)
    }
}
