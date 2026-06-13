use crate::evidence_management::{
    CollectedEvidence, EvidenceCollectionInput, EvidenceManagementError, EvidenceManagementInput,
    EvidenceManagementOutput, EvidenceManagementPlugin,
};
use sentinel_contracts::{
    CertificateContext, CloudContext, ContractDescriptor, DataSourceDescriptor, DataSourceKind,
    DnsObservation, DomainContext, EntityId, EntityRef, EntityType, EvidenceId, EvidenceItem,
    FlowId, FlowRecord, GraphHint, GraphHintType, IntelligenceContractError, IpAddress, IpContext,
    ManifestValidationError, MaturityLevel, MetricKind, MetricSchema, NetworkDirection,
    PermissionCategory, PermissionDescriptor, PermissionKey, PermissionRiskLevel, PluginId,
    PluginManifest, PluginStatefulness, PluginType, PrivacyClass, ProcessContext, ProcessContextId,
    QualityScore, RefreshMode, RendererType, RiskHint, RuntimeMode, SchemaVersion, SessionRecord,
    SignerStatus, SupportLevel, TlsObservation, TraceId, TransportProtocol, UiContribution,
    UiContributionSlot,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

pub const C2_DETECTION_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const C2_FINDING_TYPE: &str = "security.finding.c2";
pub const SUSPICIOUS_C2_GRAPH_HINT_TYPE: &str = "suspicious_c2_relation";

#[derive(Debug)]
pub enum C2DetectionError {
    EmptyInput,
    NoSignals,
    EmptyField(&'static str),
    PrivacyMarker { field: &'static str },
    InvalidQualityScore,
    Evidence(EvidenceManagementError),
    Contract(String),
    Intelligence(String),
    Manifest(String),
}

impl fmt::Display for C2DetectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "at least one C2 detection input is required"),
            Self::NoSignals => write!(f, "no C2 detection signals were produced"),
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::PrivacyMarker { field } => {
                write!(f, "{field} contains a forbidden private-content marker")
            }
            Self::InvalidQualityScore => write!(f, "quality score is outside valid range"),
            Self::Evidence(error) => write!(f, "C2 evidence management error: {error}"),
            Self::Contract(error) => write!(f, "C2 contract error: {error}"),
            Self::Intelligence(error) => write!(f, "C2 intelligence boundary error: {error}"),
            Self::Manifest(error) => write!(f, "C2 plugin manifest error: {error}"),
        }
    }
}

impl std::error::Error for C2DetectionError {}

impl From<EvidenceManagementError> for C2DetectionError {
    fn from(value: EvidenceManagementError) -> Self {
        Self::Evidence(value)
    }
}

impl From<IntelligenceContractError> for C2DetectionError {
    fn from(value: IntelligenceContractError) -> Self {
        Self::Intelligence(value.to_string())
    }
}

impl From<sentinel_contracts::SecurityContractError> for C2DetectionError {
    fn from(value: sentinel_contracts::SecurityContractError) -> Self {
        Self::Contract(value.to_string())
    }
}

impl From<ManifestValidationError> for C2DetectionError {
    fn from(value: ManifestValidationError) -> Self {
        Self::Manifest(value.to_string())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownProcessDestination {
    pub process_name: String,
    pub destination_protected: String,
}

impl KnownProcessDestination {
    pub fn new(process_name: impl Into<String>, destination_protected: impl Into<String>) -> Self {
        Self {
            process_name: process_name.into(),
            destination_protected: destination_protected.into(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct C2DetectionBaseline {
    pub known_domains: Vec<String>,
    pub known_destinations_by_process: Vec<KnownProcessDestination>,
    pub known_tls_fingerprints: Vec<String>,
    pub known_processes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct C2DetectionInput {
    pub flows: Vec<FlowRecord>,
    pub sessions: Vec<SessionRecord>,
    pub dns_observations: Vec<DnsObservation>,
    pub tls_observations: Vec<TlsObservation>,
    pub process_contexts: Vec<ProcessContext>,
    pub domain_contexts: Vec<DomainContext>,
    pub ip_contexts: Vec<IpContext>,
    pub cloud_contexts: Vec<CloudContext>,
    pub certificate_contexts: Vec<CertificateContext>,
    pub baseline: C2DetectionBaseline,
    pub producer_plugin: PluginId,
    pub trace_id: Option<TraceId>,
    pub labels: Vec<String>,
}

impl C2DetectionInput {
    pub fn new(producer_plugin: PluginId) -> Self {
        Self {
            flows: Vec::new(),
            sessions: Vec::new(),
            dns_observations: Vec::new(),
            tls_observations: Vec::new(),
            process_contexts: Vec::new(),
            domain_contexts: Vec::new(),
            ip_contexts: Vec::new(),
            cloud_contexts: Vec::new(),
            certificate_contexts: Vec::new(),
            baseline: C2DetectionBaseline::default(),
            producer_plugin,
            trace_id: None,
            labels: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct C2DetectionOutput {
    pub signals: Vec<C2DetectionSignal>,
    pub findings: Vec<sentinel_contracts::Finding>,
    pub evidence: Vec<CollectedEvidence>,
    pub risk_hints: Vec<RiskHint>,
    pub graph_hints: Vec<GraphHint>,
    pub evidence_management: EvidenceManagementOutput,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum C2SignalKind {
    BeaconPeriodicity,
    JitteredBeaconLite,
    LowAndSlowFlow,
    RareDestination,
    NewDomainFlow,
    SuspiciousDnsStructure,
    SuspiciousTlsMetadata,
    DomainRisk,
    RiskyAsn,
    RareTlsFingerprint,
    SuspiciousProcess,
}

impl C2SignalKind {
    pub fn evidence_type(&self) -> &'static str {
        match self {
            Self::BeaconPeriodicity => "c2.network.periodicity",
            Self::JitteredBeaconLite => "c2.network.jittered_beacon_lite",
            Self::LowAndSlowFlow => "c2.network.low_and_slow",
            Self::RareDestination => "c2.network.rare_destination",
            Self::NewDomainFlow => "c2.dns.new_domain_flow",
            Self::SuspiciousDnsStructure => "c2.dns.suspicious_structure",
            Self::SuspiciousTlsMetadata => "c2.tls.suspicious_metadata",
            Self::DomainRisk => "c2.dns.domain_risk",
            Self::RiskyAsn => "c2.network.risky_asn",
            Self::RareTlsFingerprint => "c2.tls.rare_fingerprint",
            Self::SuspiciousProcess => "c2.process.suspicious_process",
        }
    }

    fn signal_label(&self) -> &'static str {
        match self {
            Self::BeaconPeriodicity => "periodic beacon cadence",
            Self::JitteredBeaconLite => "jittered beacon cadence",
            Self::LowAndSlowFlow => "low-volume long-duration flow",
            Self::RareDestination => "rare process destination",
            Self::NewDomainFlow => "new domain flow",
            Self::SuspiciousDnsStructure => "suspicious DNS structure",
            Self::SuspiciousTlsMetadata => "suspicious TLS metadata",
            Self::DomainRisk => "domain risk context",
            Self::RiskyAsn => "risky ASN context",
            Self::RareTlsFingerprint => "rare TLS fingerprint",
            Self::SuspiciousProcess => "suspicious process context",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "destination_type", content = "value", rename_all = "snake_case")]
pub enum C2Destination {
    Ip(IpAddress),
    Domain(String),
    TlsFingerprint(String),
    Process(String),
}

impl C2Destination {
    fn key(&self) -> String {
        match self {
            Self::Ip(ip) => format!("ip:{}", ip),
            Self::Domain(domain) => format!("domain:{}", normalize(domain)),
            Self::TlsFingerprint(fingerprint) => format!("tls:{}", normalize(fingerprint)),
            Self::Process(process) => format!("process:{}", normalize(process)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct C2DetectionSignal {
    pub signal_key: String,
    pub kind: C2SignalKind,
    pub summary_redacted: String,
    pub confidence: QualityScore,
    pub weight: QualityScore,
    pub entity_refs: Vec<EntityRef>,
    pub flow_refs: Vec<FlowId>,
    pub dns_refs: Vec<sentinel_contracts::DnsObservationId>,
    pub tls_refs: Vec<sentinel_contracts::TlsObservationId>,
    pub process_ref: Option<ProcessContextId>,
    pub destination: Option<C2Destination>,
    pub first_seen: Option<sentinel_contracts::Timestamp>,
    pub last_seen: Option<sentinel_contracts::Timestamp>,
}

impl C2DetectionSignal {
    fn new(
        kind: C2SignalKind,
        signal_key: impl Into<String>,
        summary_redacted: impl Into<String>,
        confidence: f32,
        weight: f32,
    ) -> Result<Self, C2DetectionError> {
        let summary_redacted = require_safe_text("summary_redacted", summary_redacted.into())?;
        Ok(Self {
            signal_key: require_safe_text("signal_key", signal_key.into())?,
            kind,
            summary_redacted,
            confidence: quality_score(confidence)?,
            weight: quality_score(weight)?,
            entity_refs: Vec::new(),
            flow_refs: Vec::new(),
            dns_refs: Vec::new(),
            tls_refs: Vec::new(),
            process_ref: None,
            destination: None,
            first_seen: None,
            last_seen: None,
        })
    }

    fn with_entities(mut self, entity_refs: Vec<EntityRef>) -> Self {
        self.entity_refs = entity_refs;
        self
    }

    fn with_flows(mut self, flows: &[&FlowRecord]) -> Self {
        self.flow_refs = flows.iter().map(|flow| flow.flow_id.clone()).collect();
        self.first_seen = flows.first().map(|flow| flow.start_time.clone());
        self.last_seen = flows.last().map(|flow| flow.start_time.clone());
        self
    }

    fn with_flow(mut self, flow: &FlowRecord) -> Self {
        self.flow_refs = vec![flow.flow_id.clone()];
        self.first_seen = Some(flow.start_time.clone());
        self.last_seen = flow
            .end_time
            .clone()
            .or_else(|| Some(flow.start_time.clone()));
        self.process_ref = flow.process_ref.clone();
        self
    }
}

#[derive(Clone, Debug)]
struct C2DetectionContext<'input> {
    flow_by_id: HashMap<FlowId, &'input FlowRecord>,
    processes: HashMap<ProcessContextId, &'input ProcessContext>,
    dns_by_flow: HashMap<FlowId, Vec<&'input DnsObservation>>,
    dns_by_domain: HashMap<String, Vec<&'input DnsObservation>>,
    tls_by_flow: HashMap<FlowId, Vec<&'input TlsObservation>>,
    domain_contexts: HashMap<String, &'input DomainContext>,
    certificate_contexts: HashMap<String, &'input CertificateContext>,
    known_domains: HashSet<String>,
    known_process_destinations: HashSet<String>,
    process_destination_baselines: HashSet<String>,
    known_tls_fingerprints: HashSet<String>,
    known_processes: HashSet<String>,
}

impl<'input> C2DetectionContext<'input> {
    fn new(input: &'input C2DetectionInput) -> Self {
        let flow_by_id = input
            .flows
            .iter()
            .map(|flow| (flow.flow_id.clone(), flow))
            .collect::<HashMap<_, _>>();
        let processes = input
            .process_contexts
            .iter()
            .map(|process| (process.process_context_id.clone(), process))
            .collect::<HashMap<_, _>>();

        let mut dns_by_flow = HashMap::<FlowId, Vec<&DnsObservation>>::new();
        let mut dns_by_domain = HashMap::<String, Vec<&DnsObservation>>::new();
        for observation in &input.dns_observations {
            if let Some(flow_ref) = &observation.flow_ref {
                dns_by_flow
                    .entry(flow_ref.clone())
                    .or_default()
                    .push(observation);
            }
            dns_by_domain
                .entry(normalize(&observation.query_name_protected))
                .or_default()
                .push(observation);
        }

        let mut tls_by_flow = HashMap::<FlowId, Vec<&TlsObservation>>::new();
        for observation in &input.tls_observations {
            if let Some(flow_ref) = &observation.flow_ref {
                tls_by_flow
                    .entry(flow_ref.clone())
                    .or_default()
                    .push(observation);
            }
        }

        let domain_contexts = input
            .domain_contexts
            .iter()
            .map(|context| (normalize(&context.domain_protected), context))
            .collect::<HashMap<_, _>>();
        let certificate_contexts = input
            .certificate_contexts
            .iter()
            .map(|context| (normalize(&context.fingerprint_protected), context))
            .collect::<HashMap<_, _>>();

        let known_domains = input
            .baseline
            .known_domains
            .iter()
            .map(|value| normalize(value))
            .collect::<HashSet<_>>();
        let known_tls_fingerprints = input
            .baseline
            .known_tls_fingerprints
            .iter()
            .map(|value| normalize(value))
            .collect::<HashSet<_>>();
        let known_processes = input
            .baseline
            .known_processes
            .iter()
            .map(|value| normalize(value))
            .collect::<HashSet<_>>();
        let mut known_process_destinations = HashSet::new();
        let mut process_destination_baselines = HashSet::new();
        for destination in &input.baseline.known_destinations_by_process {
            let process = normalize(&destination.process_name);
            process_destination_baselines.insert(process.clone());
            known_process_destinations.insert(process_destination_key(
                &process,
                &destination.destination_protected,
            ));
        }

        Self {
            flow_by_id,
            processes,
            dns_by_flow,
            dns_by_domain,
            tls_by_flow,
            domain_contexts,
            certificate_contexts,
            known_domains,
            known_process_destinations,
            process_destination_baselines,
            known_tls_fingerprints,
            known_processes,
        }
    }

    fn process(&self, process_ref: &ProcessContextId) -> Option<&ProcessContext> {
        self.processes.get(process_ref).copied()
    }

    fn flow(&self, flow_ref: &FlowId) -> Option<&FlowRecord> {
        self.flow_by_id.get(flow_ref).copied()
    }

    fn process_for_flow(&self, flow: &FlowRecord) -> Option<&ProcessContext> {
        flow.process_ref.as_ref().and_then(|id| self.process(id))
    }
}

#[derive(Clone, Debug)]
pub struct BeaconPeriodicityDetector {
    pub min_flows: usize,
    pub min_interval_millis: i64,
    pub max_relative_deviation: f64,
}

impl Default for BeaconPeriodicityDetector {
    fn default() -> Self {
        Self {
            min_flows: 3,
            min_interval_millis: 30_000,
            max_relative_deviation: 0.08,
        }
    }
}

impl BeaconPeriodicityDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(
        &self,
        input: &C2DetectionInput,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let context = C2DetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &C2DetectionInput,
        context: &C2DetectionContext<'_>,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let mut signals = Vec::new();
        for (key, mut flows) in grouped_external_flows(&input.flows) {
            if flows.len() < self.min_flows {
                continue;
            }
            flows.sort_by(|left, right| left.start_time.cmp(&right.start_time));
            let Some(stats) = interval_stats(&flows) else {
                continue;
            };
            if stats.average_millis < self.min_interval_millis as f64
                || stats.max_relative_deviation > self.max_relative_deviation
            {
                continue;
            }

            let representative = flows[0];
            let destination = destination_for_flow(representative, context);
            let mut signal = C2DetectionSignal::new(
                C2SignalKind::BeaconPeriodicity,
                format!("periodic:{key}"),
                "Periodic outbound metadata cadence indicates possible C2 beaconing.",
                0.78,
                0.74,
            )?
            .with_flows(&flows)
            .with_entities(entities_for_flow(
                representative,
                context,
                destination.as_ref(),
            )?);
            signal.process_ref = representative.process_ref.clone();
            signal.destination = destination;
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug)]
pub struct JitteredBeaconLiteDetector {
    pub min_flows: usize,
    pub min_interval_millis: i64,
    pub min_relative_deviation: f64,
    pub max_relative_deviation: f64,
}

impl Default for JitteredBeaconLiteDetector {
    fn default() -> Self {
        Self {
            min_flows: 4,
            min_interval_millis: 30_000,
            min_relative_deviation: 0.08,
            max_relative_deviation: 0.35,
        }
    }
}

impl JitteredBeaconLiteDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(
        &self,
        input: &C2DetectionInput,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let context = C2DetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &C2DetectionInput,
        context: &C2DetectionContext<'_>,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let mut signals = Vec::new();
        for (key, mut flows) in grouped_external_flows(&input.flows) {
            if flows.len() < self.min_flows {
                continue;
            }
            flows.sort_by(|left, right| left.start_time.cmp(&right.start_time));
            let Some(stats) = interval_stats(&flows) else {
                continue;
            };
            if stats.average_millis < self.min_interval_millis as f64
                || stats.max_relative_deviation < self.min_relative_deviation
                || stats.max_relative_deviation > self.max_relative_deviation
            {
                continue;
            }

            let representative = flows[0];
            let destination = destination_for_flow(representative, context);
            let mut signal = C2DetectionSignal::new(
                C2SignalKind::JitteredBeaconLite,
                format!("jittered:{key}"),
                "Jittered outbound metadata cadence indicates possible C2 beaconing.",
                0.68,
                0.62,
            )?
            .with_flows(&flows)
            .with_entities(entities_for_flow(
                representative,
                context,
                destination.as_ref(),
            )?);
            signal.process_ref = representative.process_ref.clone();
            signal.destination = destination;
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug)]
pub struct LowAndSlowFlowDetector {
    pub min_duration_millis: u64,
    pub max_total_bytes: u64,
    pub max_packets: u64,
}

impl Default for LowAndSlowFlowDetector {
    fn default() -> Self {
        Self {
            min_duration_millis: 300_000,
            max_total_bytes: 12_288,
            max_packets: 48,
        }
    }
}

impl LowAndSlowFlowDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(
        &self,
        input: &C2DetectionInput,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let context = C2DetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &C2DetectionInput,
        context: &C2DetectionContext<'_>,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let mut signals = Vec::new();
        for flow in input.flows.iter().filter(|flow| is_external_flow(flow)) {
            let duration = flow.duration_millis.unwrap_or_default();
            let total_bytes = flow.bytes_in.saturating_add(flow.bytes_out);
            let total_packets = flow.packets_in.saturating_add(flow.packets_out);
            if duration < self.min_duration_millis
                || total_bytes > self.max_total_bytes
                || total_packets > self.max_packets
            {
                continue;
            }

            let destination = destination_for_flow(flow, context);
            let mut signal = C2DetectionSignal::new(
                C2SignalKind::LowAndSlowFlow,
                format!("low_slow:{}", flow.flow_id),
                "Long-duration low-volume external flow is a possible C2 channel.",
                0.57,
                0.48,
            )?
            .with_flow(flow)
            .with_entities(entities_for_flow(flow, context, destination.as_ref())?);
            signal.destination = destination;
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RareDestinationDetector;

impl RareDestinationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(
        &self,
        input: &C2DetectionInput,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let context = C2DetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &C2DetectionInput,
        context: &C2DetectionContext<'_>,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let mut signals = Vec::new();
        for flow in input.flows.iter().filter(|flow| is_external_flow(flow)) {
            let Some(process) = context.process_for_flow(flow) else {
                continue;
            };
            let process_name = normalize(&process.process_name);
            if !context
                .process_destination_baselines
                .contains(&process_name)
                && !context.known_processes.contains(&process_name)
            {
                continue;
            }

            let destination = destination_for_flow(flow, context);
            let Some(destination) = destination else {
                continue;
            };
            if context
                .known_process_destinations
                .contains(&process_destination_key(&process_name, &destination.key()))
            {
                continue;
            }

            let mut signal = C2DetectionSignal::new(
                C2SignalKind::RareDestination,
                format!(
                    "rare_destination:{}:{}",
                    process.process_context_id,
                    destination.key()
                ),
                "Process contacted a destination outside its local metadata baseline.",
                0.56,
                0.52,
            )?
            .with_flow(flow)
            .with_entities(entities_for_flow(flow, context, Some(&destination))?);
            signal.process_ref = Some(process.process_context_id.clone());
            signal.destination = Some(destination);
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug, Default)]
pub struct NewDomainFlowDetector;

impl NewDomainFlowDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(
        &self,
        input: &C2DetectionInput,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let context = C2DetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &C2DetectionInput,
        context: &C2DetectionContext<'_>,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let mut signals = Vec::new();
        for observation in &input.dns_observations {
            let domain = normalize(&observation.query_name_protected);
            if context.known_domains.contains(&domain) {
                continue;
            }
            let flow = observation
                .flow_ref
                .as_ref()
                .and_then(|flow_ref| context.flow(flow_ref));
            let process_ref = observation
                .process_ref
                .clone()
                .or_else(|| flow.and_then(|flow| flow.process_ref.clone()));
            let mut entities = vec![domain_entity(&observation.query_name_protected)?];
            if let Some(process_ref) = &process_ref {
                entities.push(process_entity(process_ref, context.process(process_ref))?);
            }
            let risk_boost = context
                .domain_contexts
                .get(&domain)
                .is_some_and(|context| domain_context_has_risk(context));
            let mut signal = C2DetectionSignal::new(
                C2SignalKind::NewDomainFlow,
                format!("new_domain:{}", observation.dns_observation_id),
                "Process queried a domain absent from the local metadata baseline.",
                if risk_boost { 0.62 } else { 0.5 },
                if risk_boost { 0.58 } else { 0.44 },
            )?
            .with_entities(entities);
            signal.dns_refs = vec![observation.dns_observation_id.clone()];
            signal.flow_refs = observation.flow_ref.clone().into_iter().collect();
            signal.process_ref = process_ref;
            signal.destination = Some(C2Destination::Domain(
                observation.query_name_protected.clone(),
            ));
            signal.first_seen = Some(observation.timestamp.clone());
            signal.last_seen = Some(observation.timestamp.clone());
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug)]
pub struct SuspiciousDnsStructureDetector {
    pub min_query_length: u16,
    pub min_entropy: f32,
    pub min_deep_entropy: f32,
    pub min_subdomain_depth: u16,
    pub min_label_count: u16,
    pub min_long_label_length: usize,
}

impl Default for SuspiciousDnsStructureDetector {
    fn default() -> Self {
        Self {
            min_query_length: 48,
            min_entropy: 3.7,
            min_deep_entropy: 3.35,
            min_subdomain_depth: 2,
            min_label_count: 5,
            min_long_label_length: 24,
        }
    }
}

impl SuspiciousDnsStructureDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(
        &self,
        input: &C2DetectionInput,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let context = C2DetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &C2DetectionInput,
        context: &C2DetectionContext<'_>,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let mut signals = Vec::new();
        for observation in &input.dns_observations {
            if context
                .known_domains
                .contains(&normalize(&observation.query_name_protected))
            {
                continue;
            }
            let Some(profile) = SuspiciousDnsProfile::from_observation(observation, self) else {
                continue;
            };
            let flow = observation
                .flow_ref
                .as_ref()
                .and_then(|flow_ref| context.flow(flow_ref));
            let process_ref = observation
                .process_ref
                .clone()
                .or_else(|| flow.and_then(|flow| flow.process_ref.clone()));
            let mut entities = vec![domain_entity(&observation.query_name_protected)?];
            if let Some(process_ref) = &process_ref {
                entities.push(process_entity(process_ref, context.process(process_ref))?);
            }
            let mut signal = C2DetectionSignal::new(
                C2SignalKind::SuspiciousDnsStructure,
                format!("dns_structure:{}", observation.dns_observation_id),
                profile.summary(),
                profile.confidence(),
                profile.weight(),
            )?
            .with_entities(entities);
            signal.dns_refs = vec![observation.dns_observation_id.clone()];
            signal.flow_refs = observation.flow_ref.clone().into_iter().collect();
            signal.process_ref = process_ref;
            signal.destination = Some(C2Destination::Domain(
                observation.query_name_protected.clone(),
            ));
            signal.first_seen = Some(observation.timestamp.clone());
            signal.last_seen = Some(observation.timestamp.clone());
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug)]
struct SuspiciousDnsProfile {
    long_high_entropy: bool,
    deep_encoded: bool,
    sparse_answer: bool,
    nxdomain: bool,
}

impl SuspiciousDnsProfile {
    fn from_observation(
        observation: &DnsObservation,
        detector: &SuspiciousDnsStructureDetector,
    ) -> Option<Self> {
        let entropy = observation.features.character_entropy?;
        let long_high_entropy = observation.features.query_length >= detector.min_query_length
            && observation.features.subdomain_depth >= detector.min_subdomain_depth
            && entropy >= detector.min_entropy;
        let deep_encoded = observation.features.label_count >= detector.min_label_count
            && entropy >= detector.min_deep_entropy
            && has_long_dns_label(
                &observation.query_name_protected,
                detector.min_long_label_length,
            );
        let nxdomain = observation
            .response_code
            .as_deref()
            .is_some_and(|code| code.eq_ignore_ascii_case("nxdomain"));
        let sparse_answer = observation.features.answer_count <= 1;
        if long_high_entropy || deep_encoded {
            Some(Self {
                long_high_entropy,
                deep_encoded,
                sparse_answer,
                nxdomain,
            })
        } else {
            None
        }
    }

    fn confidence(&self) -> f32 {
        let mut confidence: f32 = if self.long_high_entropy && self.deep_encoded {
            0.68
        } else {
            0.58
        };
        if self.nxdomain {
            confidence += 0.04;
        }
        if self.sparse_answer {
            confidence += 0.03;
        }
        confidence.min(0.76)
    }

    fn weight(&self) -> f32 {
        if self.long_high_entropy && self.deep_encoded {
            0.62
        } else {
            0.52
        }
    }

    fn summary(&self) -> &'static str {
        if self.long_high_entropy && self.deep_encoded {
            "DNS metadata has long high-entropy labels consistent with tunnel or DGA-style structure."
        } else if self.long_high_entropy {
            "DNS metadata has a long high-entropy query structure."
        } else {
            "DNS metadata has a deeply nested encoded-label structure."
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SuspiciousTlsMetadataDetector;

impl SuspiciousTlsMetadataDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(
        &self,
        input: &C2DetectionInput,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let context = C2DetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &C2DetectionInput,
        context: &C2DetectionContext<'_>,
    ) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
        let mut signals = Vec::new();
        for observation in &input.tls_observations {
            let flow = observation
                .flow_ref
                .as_ref()
                .and_then(|flow_ref| context.flow(flow_ref));
            let process_ref = observation
                .process_ref
                .clone()
                .or_else(|| flow.and_then(|flow| flow.process_ref.clone()));
            let destination = tls_destination(observation, flow);
            let entities = entities_for_tls(observation, flow, context, destination.as_ref())?;

            for fingerprint in tls_fingerprints(observation) {
                if context.known_tls_fingerprints.is_empty()
                    || context
                        .known_tls_fingerprints
                        .contains(&normalize(&fingerprint))
                {
                    continue;
                }
                let mut signal = C2DetectionSignal::new(
                    C2SignalKind::RareTlsFingerprint,
                    format!(
                        "rare_tls:{}:{}",
                        observation.tls_observation_id, fingerprint
                    ),
                    "TLS fingerprint is absent from the local metadata baseline.",
                    0.58,
                    0.54,
                )?
                .with_entities(entities.clone());
                signal.tls_refs = vec![observation.tls_observation_id.clone()];
                signal.flow_refs = observation.flow_ref.clone().into_iter().collect();
                signal.process_ref = process_ref.clone();
                signal.destination = Some(C2Destination::TlsFingerprint(fingerprint));
                signal.first_seen = Some(observation.timestamp.clone());
                signal.last_seen = Some(observation.timestamp.clone());
                signals.push(signal);
            }

            let cert_risk = observation
                .certificate_fingerprint
                .as_ref()
                .and_then(|fingerprint| context.certificate_contexts.get(&normalize(fingerprint)))
                .is_some_and(|context| {
                    context.self_signed_hint
                        || context.suspicious_issuer_hint
                        || !context.risk_hints.is_empty()
                });
            let no_sni_on_web_tls = observation.sni_protected.is_none()
                && flow.is_some_and(|flow| {
                    flow.dst_port == 443
                        && matches!(
                            flow.protocol,
                            TransportProtocol::Tcp | TransportProtocol::Quic
                        )
                });
            if cert_risk || no_sni_on_web_tls {
                let mut signal = C2DetectionSignal::new(
                    C2SignalKind::SuspiciousTlsMetadata,
                    format!("tls_metadata:{}", observation.tls_observation_id),
                    "TLS metadata has suspicious certificate or missing-SNI indicators.",
                    if cert_risk { 0.62 } else { 0.48 },
                    if cert_risk { 0.58 } else { 0.42 },
                )?
                .with_entities(entities);
                signal.tls_refs = vec![observation.tls_observation_id.clone()];
                signal.flow_refs = observation.flow_ref.clone().into_iter().collect();
                signal.process_ref = process_ref;
                signal.destination = destination;
                signal.first_seen = Some(observation.timestamp.clone());
                signal.last_seen = Some(observation.timestamp.clone());
                signals.push(signal);
            }
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug)]
pub struct C2EvidenceBuildResult {
    pub evidence_items: Vec<EvidenceItem>,
    pub evidence_refs_by_signal: BTreeMap<String, Vec<EvidenceId>>,
}

#[derive(Clone, Debug, Default)]
pub struct C2EvidenceBuilder;

impl C2EvidenceBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        producer_plugin: &PluginId,
        signals: &[C2DetectionSignal],
    ) -> Result<C2EvidenceBuildResult, C2DetectionError> {
        let mut evidence_items = Vec::new();
        let mut evidence_refs_by_signal = BTreeMap::new();
        for signal in signals {
            let mut evidence =
                EvidenceItem::new(signal.kind.evidence_type(), signal.summary_redacted.clone())?;
            evidence.source_plugin = Some(producer_plugin.clone());
            evidence.entity_refs = signal.entity_refs.clone();
            evidence.timestamp = signal
                .first_seen
                .clone()
                .unwrap_or_else(sentinel_contracts::Timestamp::now);
            evidence.weight = signal.weight.clone();
            evidence.confidence = signal.confidence.clone();
            evidence.privacy_class = PrivacyClass::Internal;
            evidence.description_redacted = Some(format!(
                "Metadata-only C2 signal: {}.",
                signal.kind.signal_label()
            ));
            evidence_refs_by_signal
                .entry(signal.signal_key.clone())
                .or_insert_with(Vec::new)
                .push(evidence.evidence_id.clone());
            evidence_items.push(evidence);
        }
        if evidence_items.is_empty() {
            return Err(C2DetectionError::NoSignals);
        }
        Ok(C2EvidenceBuildResult {
            evidence_items,
            evidence_refs_by_signal,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct C2RiskHintBuilder;

impl C2RiskHintBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(&self, input: &C2DetectionInput) -> Result<Vec<RiskHint>, C2DetectionError> {
        let mut hints = BTreeMap::<String, RiskHint>::new();
        for context in &input.domain_contexts {
            let entity = domain_entity(&context.domain_protected)?;
            collect_context_hints(&mut hints, &context.risk_hints, Some(entity.clone()))?;
            if context.risk_hints.is_empty() && domain_context_has_risk(context) {
                add_record_backed_hint(
                    &mut hints,
                    "c2_domain_context",
                    "Local domain context supports C2 risk as evidence input.",
                    0.35,
                    context.confidence.clone(),
                    context
                        .records
                        .iter()
                        .map(|record| record.record_id.clone())
                        .collect(),
                    Some(entity),
                )?;
            }
        }
        for context in &input.ip_contexts {
            let entity = ip_entity(&context.ip)?;
            collect_context_hints(&mut hints, &context.risk_hints, Some(entity.clone()))?;
            if context.risk_hints.is_empty() && ip_context_has_risk(context) {
                add_record_backed_hint(
                    &mut hints,
                    "c2_ip_context",
                    "Local IP or ASN context supports C2 risk as evidence input.",
                    0.35,
                    context.confidence.clone(),
                    context
                        .records
                        .iter()
                        .map(|record| record.record_id.clone())
                        .collect(),
                    Some(entity),
                )?;
            }
        }
        for context in &input.cloud_contexts {
            let entity = cloud_entity(&context.provider_protected)?;
            collect_context_hints(&mut hints, &context.risk_hints, Some(entity))?;
        }
        for context in &input.certificate_contexts {
            let entity = certificate_entity(&context.fingerprint_protected)?;
            collect_context_hints(&mut hints, &context.risk_hints, Some(entity.clone()))?;
            if context.risk_hints.is_empty()
                && (context.self_signed_hint || context.suspicious_issuer_hint)
            {
                add_record_backed_hint(
                    &mut hints,
                    "c2_certificate_context",
                    "Local certificate context supports C2 risk as evidence input.",
                    0.35,
                    context.confidence.clone(),
                    context
                        .records
                        .iter()
                        .map(|record| record.record_id.clone())
                        .collect(),
                    Some(entity),
                )?;
            }
        }
        Ok(hints.into_values().collect())
    }
}

#[derive(Clone, Debug, Default)]
pub struct C2GraphHintBuilder;

impl C2GraphHintBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        producer_plugin: &PluginId,
        signals: &[C2DetectionSignal],
        evidence_refs_by_signal: &BTreeMap<String, Vec<EvidenceId>>,
    ) -> Result<Vec<GraphHint>, C2DetectionError> {
        let mut hints = BTreeMap::<String, GraphHint>::new();
        for signal in signals {
            let Some(source) = signal
                .entity_refs
                .iter()
                .find(|entity| entity.entity_type == EntityType::Process)
                .cloned()
            else {
                continue;
            };
            let Some(target) = signal
                .entity_refs
                .iter()
                .find(|entity| {
                    matches!(
                        entity.entity_type,
                        EntityType::Domain
                            | EntityType::Ip
                            | EntityType::Certificate
                            | EntityType::CloudResource
                    )
                })
                .cloned()
            else {
                continue;
            };
            let key = format!("{}:{}", source.entity_id, target.entity_id);
            let mut hint = GraphHint::new(
                GraphHintType::Custom(SUSPICIOUS_C2_GRAPH_HINT_TYPE.to_string()),
                source,
                target,
                producer_plugin.clone(),
            );
            hint.evidence_refs = evidence_refs_by_signal
                .get(&signal.signal_key)
                .cloned()
                .unwrap_or_default();
            hint.confidence = signal.confidence.clone();
            hint.privacy_class = PrivacyClass::Internal;
            hints.insert(key, hint);
        }
        Ok(hints.into_values().collect())
    }
}

#[derive(Clone, Debug)]
pub struct C2DetectionPlugin {
    beacon_periodicity: BeaconPeriodicityDetector,
    jittered_beacon_lite: JitteredBeaconLiteDetector,
    low_and_slow_flow: LowAndSlowFlowDetector,
    rare_destination: RareDestinationDetector,
    new_domain_flow: NewDomainFlowDetector,
    suspicious_dns_structure: SuspiciousDnsStructureDetector,
    suspicious_tls_metadata: SuspiciousTlsMetadataDetector,
    evidence_builder: C2EvidenceBuilder,
    risk_hint_builder: C2RiskHintBuilder,
    graph_hint_builder: C2GraphHintBuilder,
    evidence_management: EvidenceManagementPlugin,
}

impl Default for C2DetectionPlugin {
    fn default() -> Self {
        Self {
            beacon_periodicity: BeaconPeriodicityDetector::new(),
            jittered_beacon_lite: JitteredBeaconLiteDetector::new(),
            low_and_slow_flow: LowAndSlowFlowDetector::new(),
            rare_destination: RareDestinationDetector::new(),
            new_domain_flow: NewDomainFlowDetector::new(),
            suspicious_dns_structure: SuspiciousDnsStructureDetector::new(),
            suspicious_tls_metadata: SuspiciousTlsMetadataDetector::new(),
            evidence_builder: C2EvidenceBuilder::new(),
            risk_hint_builder: C2RiskHintBuilder::new(),
            graph_hint_builder: C2GraphHintBuilder::new(),
            evidence_management: EvidenceManagementPlugin::new(),
        }
    }
}

impl C2DetectionPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn manifest() -> Result<PluginManifest, C2DetectionError> {
        let plugin_id = PluginId::new_v4();
        let mut manifest = PluginManifest::new(
            plugin_id.clone(),
            "c2_detection_mvp",
            "0.1.0",
            "c2_detection",
            PluginType::Detection,
            RuntimeMode::Streaming,
        )?;
        manifest.description = "Metadata-first C2 detection MVP that emits findings, evidence, risk hints, and graph hints only.".to_string();
        manifest.enabled_by_default = true;
        manifest.maturity_level = MaturityLevel::L2Detectable;
        manifest.capability_tags = vec![
            "local_first".to_string(),
            "metadata_first".to_string(),
            "c2".to_string(),
            "finding_only".to_string(),
        ];
        manifest.input_contracts = [
            "network.flow.record",
            "network.session.record",
            "network.dns.observation",
            "network.tls.observation",
            "identity.process_context",
            "intel.domain_context",
            "intel.ip_context",
            "intel.cloud_context",
            "intel.certificate_context",
        ]
        .into_iter()
        .map(contract)
        .collect::<Result<Vec<_>, _>>()?;
        manifest.output_contracts = [
            C2_FINDING_TYPE,
            "security.evidence",
            "security.risk_hint",
            "graph.hint.suspicious_c2_relation",
        ]
        .into_iter()
        .map(contract)
        .collect::<Result<Vec<_>, _>>()?;
        manifest.required_permissions = vec![
            permission(
                "read.network.metadata",
                PermissionCategory::DataAccess,
                "Read metadata-only flow, DNS, and TLS observations.",
                &[
                    "network.flow.record",
                    "network.dns.observation",
                    "network.tls.observation",
                ],
            )?,
            permission(
                "read.identity.process_context",
                PermissionCategory::DataAccess,
                "Read local process attribution metadata.",
                &["identity.process_context"],
            )?,
            permission(
                "read.intelligence.local_context",
                PermissionCategory::DataAccess,
                "Read offline local intelligence context and evidence-input-only risk hints.",
                &[
                    "intel.domain_context",
                    "intel.ip_context",
                    "intel.cloud_context",
                    "intel.certificate_context",
                ],
            )?,
        ];
        manifest.metrics_schema = vec![
            metric(
                "c2_detection.events_in_total",
                MetricKind::Counter,
                "C2 detection input records received",
            )?,
            metric(
                "c2_detection.signals_out_total",
                MetricKind::Counter,
                "C2 detection signals emitted",
            )?,
            metric(
                "c2_detection.findings_out_total",
                MetricKind::Counter,
                "C2 evidence-backed findings emitted",
            )?,
            metric(
                "c2_detection.graph_hints_out_total",
                MetricKind::Counter,
                "C2 graph hints emitted",
            )?,
            metric(
                "c2_detection.latency_ms",
                MetricKind::Histogram,
                "C2 detection processing latency",
            )?,
        ];
        manifest.finding_types = vec![C2_FINDING_TYPE.to_string()];
        manifest.graph_hint_types = vec![SUSPICIOUS_C2_GRAPH_HINT_TYPE.to_string()];
        manifest.ui_contributions = vec![
            ui_contribution(
                plugin_id.clone(),
                UiContributionSlot::InvestigationEvidencePanel,
                RendererType::EvidenceList,
                "C2 Evidence",
                "security.evidence",
            )?,
            ui_contribution(
                plugin_id.clone(),
                UiContributionSlot::GraphProjection,
                RendererType::GraphProjection,
                "C2 Relation Hints",
                "graph.hint.suspicious_c2_relation",
            )?,
        ];
        manifest.statefulness = PluginStatefulness::Baseline;
        manifest.checkpoint_support = SupportLevel::Optional;
        manifest.replay_support = SupportLevel::Optional;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn detect(&self, input: C2DetectionInput) -> Result<C2DetectionOutput, C2DetectionError> {
        validate_input(&input)?;
        if input.flows.is_empty()
            && input.dns_observations.is_empty()
            && input.tls_observations.is_empty()
            && input.domain_contexts.is_empty()
            && input.ip_contexts.is_empty()
            && input.certificate_contexts.is_empty()
        {
            return Err(C2DetectionError::EmptyInput);
        }

        let context = C2DetectionContext::new(&input);
        let mut signals = Vec::new();
        signals.extend(
            self.beacon_periodicity
                .detect_with_context(&input, &context)?,
        );
        signals.extend(
            self.jittered_beacon_lite
                .detect_with_context(&input, &context)?,
        );
        signals.extend(
            self.low_and_slow_flow
                .detect_with_context(&input, &context)?,
        );
        signals.extend(
            self.rare_destination
                .detect_with_context(&input, &context)?,
        );
        signals.extend(self.new_domain_flow.detect_with_context(&input, &context)?);
        signals.extend(
            self.suspicious_dns_structure
                .detect_with_context(&input, &context)?,
        );
        signals.extend(
            self.suspicious_tls_metadata
                .detect_with_context(&input, &context)?,
        );
        signals.extend(intelligence_signals(&input, &context)?);
        let signals = merge_signals(signals);
        if signals.is_empty() {
            return Err(C2DetectionError::NoSignals);
        }

        let evidence_build = self
            .evidence_builder
            .build(&input.producer_plugin, &signals)?;
        let risk_hints = self.risk_hint_builder.build(&input)?;
        let graph_hints = self.graph_hint_builder.build(
            &input.producer_plugin,
            &signals,
            &evidence_build.evidence_refs_by_signal,
        )?;

        let evidence_management = self.evidence_management.manage(EvidenceManagementInput {
            finding_type: C2_FINDING_TYPE.to_string(),
            producer_plugin: input.producer_plugin.clone(),
            entity_refs: entity_refs_for_finding(&signals),
            evidence_collection: EvidenceCollectionInput {
                evidence_items: evidence_build.evidence_items,
                risk_hints: risk_hints.clone(),
                graph_hints: graph_hints.clone(),
                producer_plugin: Some(input.producer_plugin),
                ..EvidenceCollectionInput::default()
            },
            high_confidence_requires_independent_sources: true,
            trace_id: input.trace_id,
            labels: input.labels,
        })?;

        Ok(C2DetectionOutput {
            signals,
            findings: vec![evidence_management.finding.clone()],
            evidence: evidence_management.evidence.clone(),
            risk_hints,
            graph_hints,
            evidence_management,
        })
    }
}

fn intelligence_signals(
    input: &C2DetectionInput,
    context: &C2DetectionContext<'_>,
) -> Result<Vec<C2DetectionSignal>, C2DetectionError> {
    let mut signals = Vec::new();
    for domain in &input.domain_contexts {
        if domain.allowlisted || !domain_context_has_risk(domain) {
            continue;
        }
        let matching_dns = context
            .dns_by_domain
            .get(&normalize(&domain.domain_protected))
            .cloned()
            .unwrap_or_default();
        let process_ref = matching_dns
            .iter()
            .find_map(|observation| observation.process_ref.clone())
            .or_else(|| {
                matching_dns
                    .iter()
                    .find_map(|observation| observation.flow_ref.as_ref())
                    .and_then(|flow_ref| context.flow(flow_ref))
                    .and_then(|flow| flow.process_ref.clone())
            });
        let mut entities = vec![domain_entity(&domain.domain_protected)?];
        if let Some(process_ref) = &process_ref {
            entities.push(process_entity(process_ref, context.process(process_ref))?);
        }
        let mut signal = C2DetectionSignal::new(
            C2SignalKind::DomainRisk,
            format!("domain_risk:{}", normalize(&domain.domain_protected)),
            "Local domain context supports possible C2 risk.",
            context_confidence(domain.confidence.value(), 0.56, 0.72),
            0.56,
        )?
        .with_entities(entities);
        signal.dns_refs = matching_dns
            .iter()
            .map(|observation| observation.dns_observation_id.clone())
            .collect();
        signal.flow_refs = matching_dns
            .iter()
            .filter_map(|observation| observation.flow_ref.clone())
            .collect();
        signal.process_ref = process_ref;
        signal.destination = Some(C2Destination::Domain(domain.domain_protected.clone()));
        signal.first_seen = Some(domain.retrieved_at.clone());
        signal.last_seen = domain
            .expires_at
            .clone()
            .or_else(|| Some(domain.retrieved_at.clone()));
        signals.push(signal);
    }

    for ip_context in &input.ip_contexts {
        if ip_context.allowlisted || !ip_context_has_risk(ip_context) {
            continue;
        }
        let matching_flows = input
            .flows
            .iter()
            .filter(|flow| flow.dst_ip == ip_context.ip)
            .collect::<Vec<_>>();
        let process_ref = matching_flows
            .iter()
            .find_map(|flow| flow.process_ref.clone());
        let mut entities = vec![ip_entity(&ip_context.ip)?];
        if let Some(asn) = ip_context.asn {
            entities.push(asn_entity(asn)?);
        }
        if let Some(process_ref) = &process_ref {
            entities.push(process_entity(process_ref, context.process(process_ref))?);
        }
        let flow_refs = matching_flows
            .iter()
            .map(|flow| flow.flow_id.clone())
            .collect::<Vec<_>>();
        let mut signal = C2DetectionSignal::new(
            C2SignalKind::RiskyAsn,
            format!("risky_asn:{}", ip_context.ip),
            "Local IP or ASN context supports possible C2 risk.",
            context_confidence(ip_context.confidence.value(), 0.52, 0.68),
            0.52,
        )?
        .with_entities(entities);
        signal.flow_refs = flow_refs;
        signal.process_ref = process_ref;
        signal.destination = Some(C2Destination::Ip(ip_context.ip));
        signal.first_seen = Some(ip_context.retrieved_at.clone());
        signal.last_seen = ip_context
            .expires_at
            .clone()
            .or_else(|| Some(ip_context.retrieved_at.clone()));
        signals.push(signal);
    }

    for process in &input.process_contexts {
        if !process_has_suspicious_context(process) {
            continue;
        }
        let matching_flows = input
            .flows
            .iter()
            .filter(|flow| {
                flow.process_ref
                    .as_ref()
                    .is_some_and(|process_ref| process_ref == &process.process_context_id)
            })
            .collect::<Vec<_>>();
        let mut signal = C2DetectionSignal::new(
            C2SignalKind::SuspiciousProcess,
            format!("suspicious_process:{}", process.process_context_id),
            "Process trust metadata supports possible C2 risk.",
            0.5,
            0.46,
        )?
        .with_entities(vec![process_entity(
            &process.process_context_id,
            Some(process),
        )?]);
        signal.flow_refs = matching_flows
            .iter()
            .map(|flow| flow.flow_id.clone())
            .collect();
        signal.process_ref = Some(process.process_context_id.clone());
        signal.destination = Some(C2Destination::Process(process.process_name.clone()));
        signal.first_seen = Some(process.captured_at.clone());
        signal.last_seen = Some(process.captured_at.clone());
        signals.push(signal);
    }

    Ok(signals)
}

#[derive(Clone, Debug)]
struct IntervalStats {
    average_millis: f64,
    max_relative_deviation: f64,
}

fn interval_stats(flows: &[&FlowRecord]) -> Option<IntervalStats> {
    if flows.len() < 2 {
        return None;
    }
    let mut intervals = Vec::new();
    for pair in flows.windows(2) {
        let millis = pair[1]
            .start_time
            .as_datetime()
            .signed_duration_since(*pair[0].start_time.as_datetime())
            .num_milliseconds();
        if millis <= 0 {
            return None;
        }
        intervals.push(millis as f64);
    }
    let average = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if average <= 0.0 {
        return None;
    }
    let max_relative_deviation = intervals
        .iter()
        .map(|interval| ((interval - average) / average).abs())
        .fold(0.0_f64, f64::max);
    Some(IntervalStats {
        average_millis: average,
        max_relative_deviation,
    })
}

fn grouped_external_flows(flows: &[FlowRecord]) -> BTreeMap<String, Vec<&FlowRecord>> {
    let mut groups = BTreeMap::<String, Vec<&FlowRecord>>::new();
    for flow in flows.iter().filter(|flow| is_external_flow(flow)) {
        let process = flow
            .process_ref
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown_process".to_string());
        let key = format!(
            "{}:{}:{}:{:?}",
            process, flow.dst_ip, flow.dst_port, flow.protocol
        );
        groups.entry(key).or_default().push(flow);
    }
    groups
}

fn is_external_flow(flow: &FlowRecord) -> bool {
    matches!(flow.direction, NetworkDirection::Outbound)
        && !flow.dst_ip.as_ip_addr().is_loopback()
        && !matches!(
            flow.protocol,
            TransportProtocol::Icmp | TransportProtocol::Icmpv6
        )
}

fn destination_for_flow(
    flow: &FlowRecord,
    context: &C2DetectionContext<'_>,
) -> Option<C2Destination> {
    if let Some(observations) = context.tls_by_flow.get(&flow.flow_id) {
        if let Some(sni) = observations
            .iter()
            .find_map(|observation| observation.sni_protected.clone())
        {
            return Some(C2Destination::Domain(sni));
        }
    }
    if let Some(observations) = context.dns_by_flow.get(&flow.flow_id) {
        if let Some(domain) = observations
            .iter()
            .find(|observation| !observation.query_name_protected.trim().is_empty())
            .map(|observation| observation.query_name_protected.clone())
        {
            return Some(C2Destination::Domain(domain));
        }
    }
    Some(C2Destination::Ip(flow.dst_ip))
}

fn tls_destination(
    observation: &TlsObservation,
    flow: Option<&FlowRecord>,
) -> Option<C2Destination> {
    observation
        .sni_protected
        .clone()
        .map(C2Destination::Domain)
        .or_else(|| flow.map(|flow| C2Destination::Ip(flow.dst_ip)))
}

fn tls_fingerprints(observation: &TlsObservation) -> Vec<String> {
    [
        observation.ja3.clone(),
        observation.ja4.clone(),
        observation.ja4s.clone(),
    ]
    .into_iter()
    .flatten()
    .filter(|value| !value.trim().is_empty())
    .collect()
}

fn entities_for_flow(
    flow: &FlowRecord,
    context: &C2DetectionContext<'_>,
    destination: Option<&C2Destination>,
) -> Result<Vec<EntityRef>, C2DetectionError> {
    let mut entities = Vec::new();
    if let Some(process_ref) = &flow.process_ref {
        entities.push(process_entity(process_ref, context.process(process_ref))?);
    }
    if let Some(destination) = destination {
        entities.push(destination_entity(destination)?);
    } else {
        entities.push(ip_entity(&flow.dst_ip)?);
    }
    Ok(entities)
}

fn entities_for_tls(
    observation: &TlsObservation,
    flow: Option<&FlowRecord>,
    context: &C2DetectionContext<'_>,
    destination: Option<&C2Destination>,
) -> Result<Vec<EntityRef>, C2DetectionError> {
    let mut entities = Vec::new();
    let process_ref = observation
        .process_ref
        .as_ref()
        .or_else(|| flow.and_then(|flow| flow.process_ref.as_ref()));
    if let Some(process_ref) = process_ref {
        entities.push(process_entity(process_ref, context.process(process_ref))?);
    }
    if let Some(destination) = destination {
        entities.push(destination_entity(destination)?);
    }
    if let Some(fingerprint) = &observation.certificate_fingerprint {
        entities.push(certificate_entity(fingerprint)?);
    }
    Ok(entities)
}

fn destination_entity(destination: &C2Destination) -> Result<EntityRef, C2DetectionError> {
    match destination {
        C2Destination::Ip(ip) => ip_entity(ip),
        C2Destination::Domain(domain) => domain_entity(domain),
        C2Destination::TlsFingerprint(fingerprint) => certificate_entity(fingerprint),
        C2Destination::Process(process) => process_name_entity(process),
    }
}

fn process_entity(
    process_ref: &ProcessContextId,
    process: Option<&ProcessContext>,
) -> Result<EntityRef, C2DetectionError> {
    let mut entity = EntityRef::new(
        EntityId::from_uuid(process_ref.as_uuid()),
        EntityType::Process,
    );
    entity.entity_name = process.map(|process| process.process_name.clone());
    entity.namespace = Some("identity.process_context".to_string());
    entity.source = Some("c2_detection".to_string());
    entity.confidence = quality_score(0.75)?;
    Ok(entity)
}

fn process_name_entity(process_name: &str) -> Result<EntityRef, C2DetectionError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Process);
    entity.entity_name = Some(require_safe_text("process_name", process_name.to_string())?);
    entity.namespace = Some("identity.process_name".to_string());
    entity.source = Some("c2_detection".to_string());
    entity.confidence = quality_score(0.45)?;
    Ok(entity)
}

fn ip_entity(ip: &IpAddress) -> Result<EntityRef, C2DetectionError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Ip);
    entity.entity_name = Some(ip.to_string());
    entity.namespace = Some("network.ip".to_string());
    entity.source = Some("c2_detection".to_string());
    entity.confidence = quality_score(0.72)?;
    Ok(entity)
}

fn domain_entity(domain: &str) -> Result<EntityRef, C2DetectionError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Domain);
    entity.entity_name = Some(require_safe_text("domain_protected", domain.to_string())?);
    entity.namespace = Some("network.domain".to_string());
    entity.source = Some("c2_detection".to_string());
    entity.confidence = quality_score(0.72)?;
    Ok(entity)
}

fn asn_entity(asn: u32) -> Result<EntityRef, C2DetectionError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Asn);
    entity.entity_name = Some(format!("asn:{asn}"));
    entity.namespace = Some("network.asn".to_string());
    entity.source = Some("c2_detection".to_string());
    entity.confidence = quality_score(0.65)?;
    Ok(entity)
}

fn certificate_entity(fingerprint: &str) -> Result<EntityRef, C2DetectionError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Certificate);
    entity.entity_name = Some(require_safe_text(
        "certificate_fingerprint",
        fingerprint.to_string(),
    )?);
    entity.namespace = Some("tls.certificate".to_string());
    entity.source = Some("c2_detection".to_string());
    entity.confidence = quality_score(0.62)?;
    Ok(entity)
}

fn cloud_entity(provider: &str) -> Result<EntityRef, C2DetectionError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::CloudResource);
    entity.entity_name = Some(require_safe_text("cloud_provider", provider.to_string())?);
    entity.namespace = Some("cloud.provider".to_string());
    entity.source = Some("c2_detection".to_string());
    entity.confidence = quality_score(0.55)?;
    Ok(entity)
}

fn entity_refs_for_finding(signals: &[C2DetectionSignal]) -> Vec<EntityRef> {
    let mut entities = BTreeMap::<String, EntityRef>::new();
    for signal in signals {
        for entity in &signal.entity_refs {
            entities
                .entry(entity.entity_id.to_string())
                .or_insert_with(|| entity.clone());
        }
    }
    entities.into_values().collect()
}

fn merge_signals(signals: Vec<C2DetectionSignal>) -> Vec<C2DetectionSignal> {
    let mut merged = BTreeMap::<String, C2DetectionSignal>::new();
    for signal in signals {
        if let Some(existing) = merged.get_mut(&signal.signal_key) {
            existing.confidence = max_quality(&existing.confidence, &signal.confidence);
            existing.weight = max_quality(&existing.weight, &signal.weight);
            merge_by_string(&mut existing.flow_refs, signal.flow_refs);
            merge_by_string(&mut existing.dns_refs, signal.dns_refs);
            merge_by_string(&mut existing.tls_refs, signal.tls_refs);
            merge_entities(&mut existing.entity_refs, signal.entity_refs);
        } else {
            merged.insert(signal.signal_key.clone(), signal);
        }
    }
    merged.into_values().collect()
}

fn merge_by_string<T: Clone + ToString>(target: &mut Vec<T>, source: Vec<T>) {
    let mut seen = target
        .iter()
        .map(ToString::to_string)
        .collect::<HashSet<_>>();
    for value in source {
        if seen.insert(value.to_string()) {
            target.push(value);
        }
    }
}

fn merge_entities(target: &mut Vec<EntityRef>, source: Vec<EntityRef>) {
    let mut seen = target
        .iter()
        .map(|entity| entity.entity_id.to_string())
        .collect::<HashSet<_>>();
    for entity in source {
        if seen.insert(entity.entity_id.to_string()) {
            target.push(entity);
        }
    }
}

fn max_quality(left: &QualityScore, right: &QualityScore) -> QualityScore {
    if right.value() > left.value() {
        right.clone()
    } else {
        left.clone()
    }
}

fn collect_context_hints(
    hints: &mut BTreeMap<String, RiskHint>,
    context_hints: &[RiskHint],
    entity_ref: Option<EntityRef>,
) -> Result<(), C2DetectionError> {
    for hint in context_hints {
        let mut hint = hint.clone();
        if hint.entity_ref.is_none() {
            hint.entity_ref = entity_ref.clone();
        }
        hint.validate_boundary()?;
        hints.insert(hint.risk_hint_id.to_string(), hint);
    }
    Ok(())
}

fn add_record_backed_hint(
    hints: &mut BTreeMap<String, RiskHint>,
    hint_type: &str,
    summary: &str,
    risk_delta: f32,
    confidence: QualityScore,
    source_record_refs: Vec<sentinel_contracts::IntelligenceRecordId>,
    entity_ref: Option<EntityRef>,
) -> Result<(), C2DetectionError> {
    if source_record_refs.is_empty() {
        return Ok(());
    }
    let mut hint = RiskHint::new(hint_type, summary, source_record_refs)?
        .with_risk_delta(risk_delta)
        .with_confidence(confidence);
    hint.entity_ref = entity_ref;
    hint.validate_boundary()?;
    hints.insert(hint.risk_hint_id.to_string(), hint);
    Ok(())
}

fn domain_context_has_risk(context: &DomainContext) -> bool {
    context.blocklisted
        || context.user_ioc_match
        || context.suspicious_tld
        || !context.risk_hints.is_empty()
}

fn ip_context_has_risk(context: &IpContext) -> bool {
    context.risky_asn
        || context.blocklisted
        || context.user_ioc_match
        || !context.risk_hints.is_empty()
}

fn process_has_suspicious_context(process: &ProcessContext) -> bool {
    matches!(
        process.signer_status,
        SignerStatus::Unsigned | SignerStatus::InvalidSignature | SignerStatus::Revoked
    ) || process.trust_score.destination_risk.value() >= 0.65
        || process.trust_score.network_rarity.value() >= 0.65
}

fn context_confidence(value: f32, minimum: f32, maximum: f32) -> f32 {
    value.clamp(minimum, maximum)
}

fn process_destination_key(process_name: &str, destination: &str) -> String {
    format!(
        "{}|{}",
        normalize(process_name),
        normalize_destination(destination)
    )
}

fn normalize_destination(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("ip:")
        .trim_start_matches("domain:")
        .trim_start_matches("tls:")
        .to_ascii_lowercase()
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn has_long_dns_label(domain: &str, min_length: usize) -> bool {
    domain
        .split('.')
        .any(|label| label.chars().count() >= min_length)
}

fn validate_input(input: &C2DetectionInput) -> Result<(), C2DetectionError> {
    for domain in &input.baseline.known_domains {
        validate_safe_text("known_domain", domain)?;
    }
    for destination in &input.baseline.known_destinations_by_process {
        validate_safe_text("known_process", &destination.process_name)?;
        validate_safe_text("known_destination", &destination.destination_protected)?;
    }
    for fingerprint in &input.baseline.known_tls_fingerprints {
        validate_safe_text("known_tls_fingerprint", fingerprint)?;
    }
    for process in &input.process_contexts {
        validate_safe_text("process_name", &process.process_name)?;
        if let Some(path) = &process.process_path_protected {
            validate_safe_text("process_path_protected", path)?;
        }
        if let Some(hash) = &process.process_hash {
            validate_safe_text("process_hash", hash)?;
        }
    }
    for observation in &input.dns_observations {
        validate_safe_text("query_name_protected", &observation.query_name_protected)?;
        validate_safe_text("query_type", &observation.query_type)?;
        if let Some(response_code) = &observation.response_code {
            validate_safe_text("response_code", response_code)?;
        }
        for cname in &observation.cname_chain_protected {
            validate_safe_text("cname_chain_protected", cname)?;
        }
    }
    for observation in &input.tls_observations {
        if let Some(value) = &observation.sni_protected {
            validate_safe_text("sni_protected", value)?;
        }
        for value in &observation.alpn {
            validate_safe_text("alpn", value)?;
        }
        for (field, value) in [
            ("ja3", &observation.ja3),
            ("ja4", &observation.ja4),
            ("ja4s", &observation.ja4s),
            ("tls_version", &observation.tls_version),
            ("cipher_suite", &observation.cipher_suite),
            (
                "extension_summary_protected",
                &observation.extension_summary_protected,
            ),
            (
                "certificate_fingerprint",
                &observation.certificate_fingerprint,
            ),
            (
                "issuer_summary_protected",
                &observation.issuer_summary_protected,
            ),
            ("san_summary_protected", &observation.san_summary_protected),
        ] {
            if let Some(value) = value {
                validate_safe_text(field, value)?;
            }
        }
    }
    for context in &input.domain_contexts {
        validate_safe_text("domain_protected", &context.domain_protected)?;
    }
    for context in &input.cloud_contexts {
        validate_safe_text("cloud_range", &context.range_protected)?;
        validate_safe_text("cloud_provider", &context.provider_protected)?;
    }
    for context in &input.certificate_contexts {
        validate_safe_text("certificate_fingerprint", &context.fingerprint_protected)?;
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), C2DetectionError> {
    if value.trim().is_empty() {
        return Err(C2DetectionError::EmptyField(field));
    }
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '/', '=', ':', '?'], "_");
    let contains_private_marker = [
        "raw_packet",
        "packet_bytes",
        "raw_payload",
        "payload",
        "http_body",
        "request_body",
        "response_body",
        "authorization",
        "authorization_header",
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
        "query_string",
        "raw_command_line",
    ]
    .iter()
    .any(|marker| normalized.contains(marker));
    if contains_private_marker {
        return Err(C2DetectionError::PrivacyMarker { field });
    }
    Ok(())
}

fn require_safe_text(field: &'static str, value: String) -> Result<String, C2DetectionError> {
    validate_safe_text(field, &value)?;
    Ok(value)
}

fn quality_score(value: f32) -> Result<QualityScore, C2DetectionError> {
    QualityScore::new(value).map_err(|_| C2DetectionError::InvalidQualityScore)
}

fn contract(name: &str) -> Result<ContractDescriptor, ManifestValidationError> {
    ContractDescriptor::new(name, C2_DETECTION_SCHEMA_VERSION)
}

fn permission(
    key: &str,
    category: PermissionCategory,
    description: &str,
    scopes: &[&str],
) -> Result<PermissionDescriptor, ManifestValidationError> {
    let mut descriptor = PermissionDescriptor::new(
        PermissionKey::new(key)?,
        category,
        PermissionRiskLevel::Low,
        description,
    )?;
    descriptor.scopes = scopes.iter().map(ToString::to_string).collect();
    Ok(descriptor)
}

fn metric(
    name: &str,
    kind: MetricKind,
    description: &str,
) -> Result<MetricSchema, ManifestValidationError> {
    let mut metric = MetricSchema::new(name, kind, description)?;
    metric.privacy_class = PrivacyClass::Internal;
    Ok(metric)
}

fn ui_contribution(
    plugin_id: PluginId,
    slot: UiContributionSlot,
    renderer_type: RendererType,
    title: &str,
    contract_name: &str,
) -> Result<UiContribution, ManifestValidationError> {
    let mut data_source = DataSourceDescriptor::new(DataSourceKind::CapabilityView);
    data_source.contract = Some(contract(contract_name)?);
    let mut contribution = UiContribution::new(plugin_id, slot, renderer_type, title, data_source)?;
    contribution.refresh_mode = RefreshMode::EventDriven;
    contribution.schema = json!({
        "schema_version": C2_DETECTION_SCHEMA_VERSION,
        "metadata_only": true
    });
    Ok(contribution)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use sentinel_contracts::{
        AttributionConfidence, CollectionMode, DnsAnswer, DnsFeatures, IndicatorType,
        IntelligenceExportPolicy, IntelligenceLicenseClass, IntelligenceLookupStatus,
        IntelligenceRecord, IntelligenceSource, IntelligenceSourceClass, NetworkDirection,
        PrivacyClass, SignerStatus, VisibilityLevel,
    };

    fn ip(value: &str) -> IpAddress {
        IpAddress::parse_str(value).expect("test IP")
    }

    fn q(value: f32) -> QualityScore {
        QualityScore::new(value).expect("quality")
    }

    fn process() -> ProcessContext {
        let mut process = ProcessContext::new(4_242, "fixture_client");
        process.signer_status = SignerStatus::Unsigned;
        process.visibility_level = VisibilityLevel::MetadataOnly;
        process.collection_mode = CollectionMode::Mock;
        process
    }

    fn flow(process: &ProcessContext, offset_seconds: i64, src_port: u16) -> FlowRecord {
        let start = Utc::now() + Duration::seconds(offset_seconds);
        let mut flow = FlowRecord::new(
            ip("192.0.2.10"),
            src_port,
            ip("198.51.100.24"),
            443,
            TransportProtocol::Tcp,
            NetworkDirection::Outbound,
        );
        flow.start_time = sentinel_contracts::Timestamp::from_datetime(start);
        flow.end_time = Some(sentinel_contracts::Timestamp::from_datetime(
            start + Duration::seconds(1),
        ));
        flow.duration_millis = Some(1_000);
        flow.bytes_out = 620;
        flow.bytes_in = 840;
        flow.packets_out = 3;
        flow.packets_in = 3;
        flow.process_ref = Some(process.process_context_id.clone());
        flow.attribution_confidence = AttributionConfidence::Medium;
        flow.quality_score = q(0.9);
        flow
    }

    fn low_slow_flow(process: &ProcessContext) -> FlowRecord {
        let mut flow = flow(process, 240, 51_200);
        flow.dst_port = 8443;
        flow.duration_millis = Some(600_000);
        flow.bytes_out = 700;
        flow.bytes_in = 900;
        flow.packets_out = 6;
        flow.packets_in = 5;
        flow
    }

    fn dns_observation(
        process: &ProcessContext,
        flow: &FlowRecord,
        domain: &str,
    ) -> DnsObservation {
        let mut observation =
            DnsObservation::new(domain, "A", ip("203.0.113.53"), ip("192.0.2.10")).expect("dns");
        observation.flow_ref = Some(flow.flow_id.clone());
        observation.process_ref = Some(process.process_context_id.clone());
        observation.timestamp = flow.start_time.clone();
        observation.answers = vec![DnsAnswer::Ip {
            address: flow.dst_ip,
            ttl_seconds: Some(60),
        }];
        observation.privacy_class = PrivacyClass::Internal;
        observation.quality_score = q(0.88);
        observation
    }

    fn tls_observation(process: &ProcessContext, flow: &FlowRecord) -> TlsObservation {
        let mut observation = TlsObservation::new();
        observation.flow_ref = Some(flow.flow_id.clone());
        observation.process_ref = Some(process.process_context_id.clone());
        observation.timestamp = flow.start_time.clone();
        observation.sni_protected = Some("beacon.example.test".to_string());
        observation.alpn = vec!["h2".to_string()];
        observation.ja3 = Some("ja3-fixture-new".to_string());
        observation.ja4 = Some("ja4-fixture-new".to_string());
        observation.tls_version = Some("tls1.3".to_string());
        observation.cipher_suite = Some("tls_aes_128_gcm_sha256".to_string());
        observation.certificate_fingerprint =
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());
        observation.issuer_summary_protected = Some("fixture issuer".to_string());
        observation.privacy_class = PrivacyClass::Internal;
        observation.quality_score = q(0.86);
        observation
    }

    fn source() -> IntelligenceSource {
        IntelligenceSource::new(
            "fixture-local-intel",
            IntelligenceSourceClass::BundledLocal,
            "bundled fixture data",
            "2026.06.01",
            IntelligenceLicenseClass::RedistributableFixture,
            PrivacyClass::Internal,
            IntelligenceExportPolicy::AllowRedactedSummary,
        )
        .expect("source")
    }

    fn record(
        indicator_type: IndicatorType,
        indicator: &str,
        confidence: f32,
    ) -> IntelligenceRecord {
        IntelligenceRecord::new(
            indicator_type,
            indicator,
            &source(),
            "Fixture local intelligence context",
        )
        .expect("record")
        .with_confidence(q(confidence))
        .with_expires_at(sentinel_contracts::Timestamp::from_datetime(
            Utc::now() + Duration::days(30),
        ))
    }

    fn risk_hint(
        hint_type: &str,
        delta: f32,
        confidence: f32,
        record: &IntelligenceRecord,
    ) -> RiskHint {
        RiskHint::new(
            hint_type,
            "Local intelligence context; evidence input only.",
            vec![record.record_id.clone()],
        )
        .expect("risk hint")
        .with_risk_delta(delta)
        .with_confidence(q(confidence))
    }

    fn domain_context(domain: &str) -> DomainContext {
        let record = record(IndicatorType::Domain, domain, 0.72);
        DomainContext {
            domain_protected: domain.to_string(),
            tld_protected: Some("test".to_string()),
            suspicious_tld: true,
            allowlisted: false,
            blocklisted: false,
            user_ioc_match: false,
            lexical_score: q(0.62),
            lookup_status: IntelligenceLookupStatus::Hit,
            risk_hints: vec![risk_hint("domain_reputation_context", 0.3, 0.72, &record)],
            records: vec![record],
            confidence: q(0.72),
            retrieved_at: sentinel_contracts::Timestamp::now(),
            expires_at: None,
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn ip_context() -> IpContext {
        let record = record(IndicatorType::Asn, "64512", 0.66);
        IpContext {
            ip: ip("198.51.100.24"),
            asn: Some(64_512),
            asn_name_protected: Some("fixture documentation ASN".to_string()),
            cloud_provider_protected: None,
            risky_asn: true,
            allowlisted: false,
            blocklisted: false,
            user_ioc_match: false,
            lookup_status: IntelligenceLookupStatus::Hit,
            records: vec![record.clone()],
            risk_hints: vec![risk_hint("asn_risk_context", 0.45, 0.66, &record)],
            confidence: q(0.66),
            retrieved_at: sentinel_contracts::Timestamp::now(),
            expires_at: None,
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn certificate_context() -> CertificateContext {
        let fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let record = record(IndicatorType::CertificateFingerprint, fingerprint, 0.58);
        CertificateContext {
            fingerprint_protected: fingerprint.to_string(),
            issuer_summary_protected: Some("fixture issuer profile".to_string()),
            self_signed_hint: true,
            suspicious_issuer_hint: true,
            lookup_status: IntelligenceLookupStatus::Hit,
            records: vec![record.clone()],
            risk_hints: vec![risk_hint("certificate_profile_context", 0.4, 0.58, &record)],
            confidence: q(0.58),
            retrieved_at: sentinel_contracts::Timestamp::now(),
            expires_at: None,
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn fixture_input() -> C2DetectionInput {
        let process = process();
        let flow_a = flow(&process, 0, 50_000);
        let flow_b = flow(&process, 60, 50_001);
        let flow_c = flow(&process, 120, 50_002);
        let flow_d = low_slow_flow(&process);
        let dns = dns_observation(&process, &flow_a, "beacon.example.test");
        let tls = tls_observation(&process, &flow_a);
        let mut input = C2DetectionInput::new(PluginId::new_v4());
        input.process_contexts = vec![process];
        input.flows = vec![flow_a, flow_b, flow_c, flow_d];
        input.dns_observations = vec![dns];
        input.tls_observations = vec![tls];
        input.domain_contexts = vec![domain_context("beacon.example.test")];
        input.ip_contexts = vec![ip_context()];
        input.certificate_contexts = vec![certificate_context()];
        input.baseline = C2DetectionBaseline {
            known_domains: vec!["trusted.example.test".to_string()],
            known_destinations_by_process: vec![KnownProcessDestination::new(
                "fixture_client",
                "203.0.113.88",
            )],
            known_tls_fingerprints: vec!["ja3-known".to_string(), "ja4-known".to_string()],
            known_processes: vec!["fixture_client".to_string()],
        };
        input.labels = vec!["task_400_fixture".to_string()];
        input
    }

    #[test]
    fn c2_detection_emits_evidence_backed_finding_for_fixture_story() {
        let output = C2DetectionPlugin::new()
            .detect(fixture_input())
            .expect("c2 output");

        assert_eq!(output.findings.len(), 1);
        assert_eq!(output.findings[0].finding_type(), C2_FINDING_TYPE);
        assert!(!output.findings[0].evidence_refs().is_empty());
        assert!(output.evidence_management.quality_report.passed);

        let evidence_types = output
            .evidence
            .iter()
            .map(|item| item.evidence.evidence_type.as_str())
            .collect::<HashSet<_>>();
        for required in [
            "c2.network.periodicity",
            "c2.network.rare_destination",
            "c2.dns.domain_risk",
            "c2.network.risky_asn",
            "c2.tls.rare_fingerprint",
            "c2.tls.suspicious_metadata",
            "c2.process.suspicious_process",
            "c2.network.low_and_slow",
        ] {
            assert!(evidence_types.contains(required), "missing {required}");
        }
        assert!(!output.risk_hints.is_empty());
        assert!(output.risk_hints.iter().all(|hint| {
            hint.evidence_input_only
                && !hint.creates_alert
                && !hint.creates_incident
                && !hint.executes_response
                && hint.validate_boundary().is_ok()
        }));
        assert!(output.graph_hints.iter().any(|hint| {
            hint.hint_type == GraphHintType::Custom(SUSPICIOUS_C2_GRAPH_HINT_TYPE.to_string())
        }));
    }

    #[test]
    fn jittered_beacon_detector_finds_lite_jitter_without_fixed_periodicity() {
        let process = process();
        let mut input = C2DetectionInput::new(PluginId::new_v4());
        input.process_contexts = vec![process.clone()];
        input.flows = vec![
            flow(&process, 0, 50_000),
            flow(&process, 50, 50_001),
            flow(&process, 112, 50_002),
            flow(&process, 180, 50_003),
            flow(&process, 230, 50_004),
        ];

        let periodic = BeaconPeriodicityDetector::new()
            .detect(&input)
            .expect("periodic detection");
        let jittered = JitteredBeaconLiteDetector::new()
            .detect(&input)
            .expect("jitter detection");

        assert!(periodic.is_empty());
        assert_eq!(jittered.len(), 1);
        assert_eq!(jittered[0].kind, C2SignalKind::JitteredBeaconLite);
    }

    #[test]
    fn suspicious_dns_structure_emits_metadata_only_c2_evidence() {
        let process = process();
        let flow = flow(&process, 0, 50_000);
        let domain = "xq7m4z8n2p5r9v1c3b6t0y4u.stage01.longlabel.example.test";
        let mut dns = dns_observation(&process, &flow, domain);
        dns.response_code = Some("NXDOMAIN".to_string());
        dns.features = DnsFeatures {
            query_length: domain.len() as u16,
            label_count: 5,
            subdomain_depth: 3,
            character_entropy: Some(4.1),
            answer_count: 0,
        };

        let mut input = C2DetectionInput::new(PluginId::new_v4());
        input.process_contexts = vec![process];
        input.flows = vec![flow];
        input.dns_observations = vec![dns];

        let output = C2DetectionPlugin::new()
            .detect(input)
            .expect("dns anomaly c2 output");

        assert!(output
            .signals
            .iter()
            .any(|signal| signal.kind == C2SignalKind::SuspiciousDnsStructure));
        assert!(output.evidence.iter().any(|item| {
            item.evidence.evidence_type == "c2.dns.suspicious_structure"
                && item.evidence.privacy_class == PrivacyClass::Internal
        }));
        assert!(output.graph_hints.iter().any(|hint| {
            hint.hint_type == GraphHintType::Custom(SUSPICIOUS_C2_GRAPH_HINT_TYPE.to_string())
        }));

        let serialized = serde_json::to_value(&output).expect("serialize output");
        assert!(serialized.get("alerts").is_none());
        assert!(serialized.get("incidents").is_none());
        assert!(serialized.get("response_execution").is_none());
        assert!(serialized.get("canonical_graph").is_none());
    }

    #[test]
    fn low_confidence_single_signal_remains_finding_and_risk_hint_only() {
        let mut input = C2DetectionInput::new(PluginId::new_v4());
        let mut context = domain_context("beacon.example.test");
        context.confidence = q(0.32);
        for hint in &mut context.risk_hints {
            hint.confidence = q(0.32);
            hint.risk_delta = 0.2;
        }
        input.domain_contexts = vec![context];

        let output = C2DetectionPlugin::new()
            .detect(input)
            .expect("single-signal output");
        assert_eq!(output.findings.len(), 1);
        assert!(output.findings[0].confidence().value() < 0.75);
        assert!(output.risk_hints.iter().all(|hint| {
            hint.evidence_input_only
                && !hint.creates_alert
                && !hint.creates_incident
                && !hint.executes_response
        }));

        let serialized = serde_json::to_value(&output).expect("serialize output");
        assert!(serialized.get("alerts").is_none());
        assert!(serialized.get("incidents").is_none());
        assert_eq!(
            output.findings[0].state(),
            &sentinel_contracts::FindingState::New
        );
    }

    #[test]
    fn graph_hints_are_emitted_without_canonical_graph_writes() {
        let output = C2DetectionPlugin::new()
            .detect(fixture_input())
            .expect("c2 output");
        assert!(!output.graph_hints.is_empty());
        let serialized = serde_json::to_string(&output).expect("serialize output");
        assert!(!serialized.contains("canonical_graph"));
        assert!(!serialized.contains("graph.update"));
        assert!(!serialized.contains("graph_update"));
    }

    #[test]
    fn plugin_manifest_declares_contracts_permissions_metrics_and_ui() {
        let manifest = C2DetectionPlugin::manifest().expect("manifest");
        manifest.validate().expect("valid manifest");

        let input_contracts = manifest
            .input_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<HashSet<_>>();
        for required in [
            "network.flow.record",
            "network.dns.observation",
            "network.tls.observation",
            "identity.process_context",
            "intel.domain_context",
            "intel.ip_context",
            "intel.certificate_context",
        ] {
            assert!(input_contracts.contains(required), "missing {required}");
        }

        let output_contracts = manifest
            .output_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<HashSet<_>>();
        assert!(output_contracts.contains(C2_FINDING_TYPE));
        assert!(output_contracts.contains("security.evidence"));
        assert!(output_contracts.contains("security.risk_hint"));
        assert!(output_contracts.contains("graph.hint.suspicious_c2_relation"));

        assert_eq!(manifest.plugin_type, PluginType::Detection);
        assert_eq!(manifest.finding_types, vec![C2_FINDING_TYPE.to_string()]);
        assert_eq!(
            manifest.graph_hint_types,
            vec![SUSPICIOUS_C2_GRAPH_HINT_TYPE.to_string()]
        );
        assert!(!manifest.metrics_schema.is_empty());
        assert!(!manifest.ui_contributions.is_empty());
        assert!(manifest.required_permissions.iter().all(|permission| {
            permission.category == PermissionCategory::DataAccess
                && permission.risk_level == PermissionRiskLevel::Low
                && !permission.permission.as_str().contains("response")
        }));

        let local_intel_permission = manifest
            .required_permissions
            .iter()
            .find(|permission| permission.permission.as_str() == "read.intelligence.local_context")
            .expect("local intelligence permission");
        let local_intel_scopes = local_intel_permission
            .scopes
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        for required in [
            "intel.domain_context",
            "intel.ip_context",
            "intel.cloud_context",
            "intel.certificate_context",
        ] {
            assert!(
                local_intel_scopes.contains(required),
                "missing local intel scope {required}"
            );
        }
    }

    #[test]
    fn sensitive_metadata_marker_is_rejected() {
        let process = process();
        let flow = flow(&process, 0, 50_000);
        let mut input = C2DetectionInput::new(PluginId::new_v4());
        input.process_contexts = vec![process.clone()];
        input.flows = vec![flow.clone()];
        input.dns_observations = vec![dns_observation(&process, &flow, "api_key.example.test")];

        let error = C2DetectionPlugin::new()
            .detect(input)
            .expect_err("privacy marker rejected");
        assert!(matches!(
            error,
            C2DetectionError::PrivacyMarker {
                field: "query_name_protected"
            }
        ));
    }
}
