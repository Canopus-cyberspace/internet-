use crate::asset_exposure::{
    AssetExposureObservation, AssetRecord, AssetRiskFinding, PortExposureRecord, ServiceRecord,
};
use crate::evidence_management::{
    CollectedEvidence, EvidenceCollectionInput, EvidenceManagementError, EvidenceManagementInput,
    EvidenceManagementOutput, EvidenceManagementPlugin,
};
use sentinel_contracts::{
    AttributionConfidence, ContractDescriptor, DataSourceDescriptor, DataSourceKind, EntityId,
    EntityRef, EntityType, EvidenceId, EvidenceItem, Finding, FlowId, FlowRecord, GraphHint,
    GraphHintType, IpAddress, ManifestValidationError, MaturityLevel, MetricKind, MetricSchema,
    NetworkDirection, PermissionCategory, PermissionDescriptor, PermissionKey, PermissionRiskLevel,
    PluginId, PluginManifest, PluginStatefulness, PluginType, PrivacyClass, ProcessContext,
    ProcessContextId, QualityScore, RefreshMode, RendererType, RiskHint, RuntimeMode,
    SchemaVersion, SessionRecord, SignerStatus, SupportLevel, Timestamp, TraceId, UiContribution,
    UiContributionSlot,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

pub const LATERAL_MOVEMENT_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const LATERAL_FINDING_TYPE: &str = "security.finding.lateral_movement_lite";
pub const LATERAL_INTERNAL_FANOUT_HINT: &str = "lateral_internal_fanout";
pub const LATERAL_SERVICE_PROBE_HINT: &str = "lateral_service_probe";
pub const LATERAL_EXPOSURE_LINKED_HINT: &str = "lateral_exposure_linked_movement";

#[derive(Debug)]
pub enum LateralMovementError {
    EmptyInput,
    NoSignals,
    EmptyField(&'static str),
    PrivacyMarker { field: &'static str },
    InvalidQualityScore,
    Evidence(EvidenceManagementError),
    Contract(String),
    Manifest(String),
}

impl fmt::Display for LateralMovementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "at least one lateral movement input is required"),
            Self::NoSignals => write!(f, "no lateral movement lite signals were produced"),
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::PrivacyMarker { field } => {
                write!(f, "{field} contains a forbidden private-content marker")
            }
            Self::InvalidQualityScore => write!(f, "quality score is outside valid range"),
            Self::Evidence(error) => write!(f, "lateral movement evidence error: {error}"),
            Self::Contract(error) => write!(f, "lateral movement contract error: {error}"),
            Self::Manifest(error) => write!(f, "lateral movement manifest error: {error}"),
        }
    }
}

impl std::error::Error for LateralMovementError {}

impl From<EvidenceManagementError> for LateralMovementError {
    fn from(value: EvidenceManagementError) -> Self {
        Self::Evidence(value)
    }
}

impl From<sentinel_contracts::SecurityContractError> for LateralMovementError {
    fn from(value: sentinel_contracts::SecurityContractError) -> Self {
        Self::Contract(value.to_string())
    }
}

impl From<ManifestValidationError> for LateralMovementError {
    fn from(value: ManifestValidationError) -> Self {
        Self::Manifest(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownInternalDestination {
    pub process_name: String,
    pub destination_ip: IpAddress,
    pub destination_port: u16,
}

impl KnownInternalDestination {
    pub fn new(
        process_name: impl Into<String>,
        destination_ip: IpAddress,
        destination_port: u16,
    ) -> Self {
        Self {
            process_name: process_name.into(),
            destination_ip,
            destination_port,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LateralMovementBaseline {
    pub max_unique_internal_destinations_per_process: usize,
    pub known_internal_destinations: Vec<KnownInternalDestination>,
    pub service_probe_ports: Vec<u16>,
}

impl Default for LateralMovementBaseline {
    fn default() -> Self {
        Self {
            max_unique_internal_destinations_per_process: 3,
            known_internal_destinations: Vec::new(),
            service_probe_ports: vec![22, 135, 139, 445, 3389, 5985, 5986],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LateralMovementLiteInput {
    pub flows: Vec<FlowRecord>,
    pub sessions: Vec<SessionRecord>,
    pub process_contexts: Vec<ProcessContext>,
    pub assets: Vec<AssetRecord>,
    pub services: Vec<ServiceRecord>,
    pub port_exposures: Vec<PortExposureRecord>,
    pub asset_observations: Vec<AssetExposureObservation>,
    pub asset_findings: Vec<AssetRiskFinding>,
    pub baseline: LateralMovementBaseline,
    pub producer_plugin: PluginId,
    pub trace_id: Option<TraceId>,
    pub labels: Vec<String>,
}

impl LateralMovementLiteInput {
    pub fn new(producer_plugin: PluginId) -> Self {
        Self {
            flows: Vec::new(),
            sessions: Vec::new(),
            process_contexts: Vec::new(),
            assets: Vec::new(),
            services: Vec::new(),
            port_exposures: Vec::new(),
            asset_observations: Vec::new(),
            asset_findings: Vec::new(),
            baseline: LateralMovementBaseline::default(),
            producer_plugin,
            trace_id: None,
            labels: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LateralMovementLiteOutput {
    pub signals: Vec<LateralMovementSignal>,
    pub findings: Vec<Finding>,
    pub evidence: Vec<CollectedEvidence>,
    pub risk_hints: Vec<RiskHint>,
    pub graph_hints: Vec<GraphHint>,
    pub evidence_management: EvidenceManagementOutput,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LateralSignalKind {
    InternalFanout,
    ServiceProbe,
    UnknownProcessInternalAccess,
    ExposureLinkedMovement,
}

impl LateralSignalKind {
    pub fn evidence_type(&self) -> &'static str {
        match self {
            Self::InternalFanout => "lateral.network.internal_fanout",
            Self::ServiceProbe => "lateral.network.service_probe",
            Self::UnknownProcessInternalAccess => "lateral.process.unknown_internal_access",
            Self::ExposureLinkedMovement => "lateral.asset.exposure_linked_movement",
        }
    }

    fn graph_hint_name(&self) -> &'static str {
        match self {
            Self::InternalFanout => LATERAL_INTERNAL_FANOUT_HINT,
            Self::ServiceProbe => LATERAL_SERVICE_PROBE_HINT,
            Self::UnknownProcessInternalAccess => LATERAL_SERVICE_PROBE_HINT,
            Self::ExposureLinkedMovement => LATERAL_EXPOSURE_LINKED_HINT,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::InternalFanout => "internal fanout",
            Self::ServiceProbe => "service probe",
            Self::UnknownProcessInternalAccess => "unknown process internal access",
            Self::ExposureLinkedMovement => "exposure-linked movement",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "target_type", content = "value", rename_all = "snake_case")]
pub enum LateralTarget {
    Ip(IpAddress),
    Port { ip: IpAddress, port: u16 },
    Service(String),
    UnknownInternal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LateralMovementSignal {
    pub signal_key: String,
    pub kind: LateralSignalKind,
    pub summary_redacted: String,
    pub confidence: QualityScore,
    pub weight: QualityScore,
    pub entity_refs: Vec<EntityRef>,
    pub flow_refs: Vec<FlowId>,
    pub related_asset_finding_refs: Vec<sentinel_contracts::FindingId>,
    pub related_port_exposure_refs: Vec<String>,
    pub process_ref: Option<ProcessContextId>,
    pub target: Option<LateralTarget>,
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
}

impl LateralMovementSignal {
    fn new(
        kind: LateralSignalKind,
        signal_key: impl Into<String>,
        summary_redacted: impl Into<String>,
        confidence: f32,
        weight: f32,
    ) -> Result<Self, LateralMovementError> {
        Ok(Self {
            signal_key: require_safe_text("signal_key", signal_key.into())?,
            kind,
            summary_redacted: require_safe_text("summary_redacted", summary_redacted.into())?,
            confidence: quality_score(confidence)?,
            weight: quality_score(weight)?,
            entity_refs: Vec::new(),
            flow_refs: Vec::new(),
            related_asset_finding_refs: Vec::new(),
            related_port_exposure_refs: Vec::new(),
            process_ref: None,
            target: None,
            first_seen: None,
            last_seen: None,
        })
    }

    fn with_flow(mut self, flow: &FlowRecord) -> Self {
        self.flow_refs = vec![flow.flow_id.clone()];
        self.process_ref = flow.process_ref.clone();
        self.first_seen = Some(flow.start_time.clone());
        self.last_seen = flow
            .end_time
            .clone()
            .or_else(|| Some(flow.start_time.clone()));
        self
    }

    fn with_flows(mut self, flows: &[&FlowRecord]) -> Self {
        self.flow_refs = flows.iter().map(|flow| flow.flow_id.clone()).collect();
        self.process_ref = flows.iter().find_map(|flow| flow.process_ref.clone());
        self.first_seen = flows.first().map(|flow| flow.start_time.clone());
        self.last_seen = flows
            .last()
            .and_then(|flow| flow.end_time.clone())
            .or_else(|| flows.last().map(|flow| flow.start_time.clone()));
        self
    }

    fn with_entities(mut self, entities: Vec<EntityRef>) -> Self {
        self.entity_refs = entities;
        self
    }
}

#[derive(Clone, Debug)]
struct LateralMovementContext<'input> {
    processes: HashMap<ProcessContextId, &'input ProcessContext>,
    known_internal_destinations: HashSet<String>,
    service_probe_ports: HashSet<u16>,
    port_exposures_by_endpoint: HashMap<String, Vec<&'input PortExposureRecord>>,
    asset_findings_by_port: HashMap<String, Vec<&'input AssetRiskFinding>>,
}

impl<'input> LateralMovementContext<'input> {
    fn new(input: &'input LateralMovementLiteInput) -> Self {
        let processes = input
            .process_contexts
            .iter()
            .map(|process| (process.process_context_id.clone(), process))
            .collect::<HashMap<_, _>>();
        let known_internal_destinations = input
            .baseline
            .known_internal_destinations
            .iter()
            .map(|destination| {
                process_destination_key(
                    &destination.process_name,
                    &destination.destination_ip,
                    destination.destination_port,
                )
            })
            .collect::<HashSet<_>>();
        let mut port_exposures_by_endpoint = HashMap::<String, Vec<&PortExposureRecord>>::new();
        for exposure in &input.port_exposures {
            port_exposures_by_endpoint
                .entry(endpoint_key(&exposure.local_ip, exposure.local_port))
                .or_default()
                .push(exposure);
        }
        let mut asset_findings_by_port = HashMap::<String, Vec<&AssetRiskFinding>>::new();
        for finding in &input.asset_findings {
            asset_findings_by_port
                .entry(finding.port_exposure_record_ref.clone())
                .or_default()
                .push(finding);
        }

        Self {
            processes,
            known_internal_destinations,
            service_probe_ports: input.baseline.service_probe_ports.iter().copied().collect(),
            port_exposures_by_endpoint,
            asset_findings_by_port,
        }
    }

    fn process(&self, process_ref: &ProcessContextId) -> Option<&ProcessContext> {
        self.processes.get(process_ref).copied()
    }

    fn process_for_flow(&self, flow: &FlowRecord) -> Option<&ProcessContext> {
        flow.process_ref.as_ref().and_then(|id| self.process(id))
    }
}

#[derive(Clone, Debug)]
pub struct InternalFanoutDetector {
    pub min_unique_destinations: usize,
}

impl Default for InternalFanoutDetector {
    fn default() -> Self {
        Self {
            min_unique_destinations: 3,
        }
    }
}

impl InternalFanoutDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(
        &self,
        input: &LateralMovementLiteInput,
    ) -> Result<Vec<LateralMovementSignal>, LateralMovementError> {
        let context = LateralMovementContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &LateralMovementLiteInput,
        context: &LateralMovementContext<'_>,
    ) -> Result<Vec<LateralMovementSignal>, LateralMovementError> {
        let mut groups = BTreeMap::<String, Vec<&FlowRecord>>::new();
        for flow in input.flows.iter().filter(|flow| is_internal_flow(flow)) {
            let process = flow
                .process_ref
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown_process".to_string());
            groups.entry(process).or_default().push(flow);
        }

        let mut signals = Vec::new();
        for (process_key, flows) in groups {
            let unique_destinations = flows
                .iter()
                .map(|flow| flow.dst_ip.to_string())
                .collect::<HashSet<_>>();
            let baseline_limit = input
                .baseline
                .max_unique_internal_destinations_per_process
                .max(self.min_unique_destinations);
            if unique_destinations.len() < baseline_limit {
                continue;
            }

            let representative = flows[0];
            let process = context.process_for_flow(representative);
            let process_name = process
                .map(|process| process.process_name.as_str())
                .unwrap_or("unknown_process");
            let all_known = flows.iter().all(|flow| {
                known_internal_destination(context, process_name, &flow.dst_ip, flow.dst_port)
            });
            if all_known {
                continue;
            }

            let mut signal = LateralMovementSignal::new(
                LateralSignalKind::InternalFanout,
                format!("fanout:{process_key}"),
                "Process reached multiple internal destinations using metadata-only flow visibility.",
                0.62,
                0.58,
            )?
            .with_flows(&flows)
            .with_entities(entities_for_flow(representative, context, None)?);
            signal.target = Some(LateralTarget::Ip(representative.dst_ip));
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ServiceProbeDetector;

impl ServiceProbeDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(
        &self,
        input: &LateralMovementLiteInput,
    ) -> Result<Vec<LateralMovementSignal>, LateralMovementError> {
        let context = LateralMovementContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &LateralMovementLiteInput,
        context: &LateralMovementContext<'_>,
    ) -> Result<Vec<LateralMovementSignal>, LateralMovementError> {
        let mut signals = Vec::new();
        for flow in input.flows.iter().filter(|flow| {
            is_internal_flow(flow) && context.service_probe_ports.contains(&flow.dst_port)
        }) {
            let process = context.process_for_flow(flow);
            let process_name = process
                .map(|process| process.process_name.as_str())
                .unwrap_or("unknown_process");
            if known_internal_destination(context, process_name, &flow.dst_ip, flow.dst_port) {
                continue;
            }
            let service = service_name_for_port(flow.dst_port);
            let mut signal = LateralMovementSignal::new(
                LateralSignalKind::ServiceProbe,
                format!(
                    "service_probe:{}:{}:{}",
                    flow.flow_id, flow.dst_ip, flow.dst_port
                ),
                format!("{service} service probe visible from flow metadata only."),
                0.58,
                0.52,
            )?
            .with_flow(flow)
            .with_entities(entities_for_flow(
                flow,
                context,
                Some(&LateralTarget::Port {
                    ip: flow.dst_ip,
                    port: flow.dst_port,
                }),
            )?);
            signal.target = Some(LateralTarget::Port {
                ip: flow.dst_ip,
                port: flow.dst_port,
            });
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug, Default)]
pub struct UnknownProcessInternalAccessDetector;

impl UnknownProcessInternalAccessDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(
        &self,
        input: &LateralMovementLiteInput,
    ) -> Result<Vec<LateralMovementSignal>, LateralMovementError> {
        let context = LateralMovementContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &LateralMovementLiteInput,
        context: &LateralMovementContext<'_>,
    ) -> Result<Vec<LateralMovementSignal>, LateralMovementError> {
        let mut signals = Vec::new();
        for flow in input.flows.iter().filter(|flow| is_internal_flow(flow)) {
            let unknown_process = flow.process_ref.is_none()
                || matches!(
                    flow.attribution_confidence,
                    AttributionConfidence::Unknown | AttributionConfidence::Low
                )
                || flow
                    .process_ref
                    .as_ref()
                    .and_then(|process_ref| context.process(process_ref))
                    .is_some_and(process_has_suspicious_context);
            if !unknown_process {
                continue;
            }
            let mut signal = LateralMovementSignal::new(
                LateralSignalKind::UnknownProcessInternalAccess,
                format!("unknown_process_access:{}", flow.flow_id),
                "Internal access is tied to unknown or low-confidence process metadata.",
                0.52,
                0.46,
            )?
            .with_flow(flow)
            .with_entities(entities_for_flow(
                flow,
                context,
                Some(&LateralTarget::Port {
                    ip: flow.dst_ip,
                    port: flow.dst_port,
                }),
            )?);
            signal.target = Some(LateralTarget::Port {
                ip: flow.dst_ip,
                port: flow.dst_port,
            });
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExposureLinkedMovementDetector;

impl ExposureLinkedMovementDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(
        &self,
        input: &LateralMovementLiteInput,
    ) -> Result<Vec<LateralMovementSignal>, LateralMovementError> {
        let context = LateralMovementContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &LateralMovementLiteInput,
        context: &LateralMovementContext<'_>,
    ) -> Result<Vec<LateralMovementSignal>, LateralMovementError> {
        let mut signals = Vec::new();
        for flow in input.flows.iter().filter(|flow| is_internal_flow(flow)) {
            let endpoint = endpoint_key(&flow.dst_ip, flow.dst_port);
            let Some(exposures) = context.port_exposures_by_endpoint.get(&endpoint) else {
                continue;
            };
            for exposure in exposures {
                let findings = context
                    .asset_findings_by_port
                    .get(&exposure.port_exposure_record_id)
                    .cloned()
                    .unwrap_or_default();
                let confidence = if findings.is_empty() { 0.58 } else { 0.66 };
                let mut signal = LateralMovementSignal::new(
                    LateralSignalKind::ExposureLinkedMovement,
                    format!(
                        "exposure_linked:{}:{}",
                        flow.flow_id, exposure.port_exposure_record_id
                    ),
                    "Internal flow reached a known exposed service using metadata-only visibility.",
                    confidence,
                    if findings.is_empty() { 0.54 } else { 0.64 },
                )?
                .with_flow(flow)
                .with_entities(entities_for_exposure(
                    flow,
                    exposure,
                    findings.as_slice(),
                    context,
                )?);
                signal.target = Some(LateralTarget::Port {
                    ip: flow.dst_ip,
                    port: flow.dst_port,
                });
                signal.related_port_exposure_refs = vec![exposure.port_exposure_record_id.clone()];
                signal.related_asset_finding_refs = findings
                    .iter()
                    .map(|finding| finding.finding.id().clone())
                    .collect();
                signals.push(signal);
            }
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug)]
pub struct LateralEvidenceBuildResult {
    pub evidence_items: Vec<EvidenceItem>,
    pub evidence_refs_by_signal: BTreeMap<String, Vec<EvidenceId>>,
}

#[derive(Clone, Debug, Default)]
pub struct LateralEvidenceBuilder;

impl LateralEvidenceBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        producer_plugin: &PluginId,
        signals: &[LateralMovementSignal],
    ) -> Result<LateralEvidenceBuildResult, LateralMovementError> {
        let mut evidence_items = Vec::new();
        let mut evidence_refs_by_signal = BTreeMap::new();
        for signal in signals {
            let mut evidence =
                EvidenceItem::new(signal.kind.evidence_type(), signal.summary_redacted.clone())?;
            evidence.source_plugin = Some(producer_plugin.clone());
            evidence.entity_refs = signal.entity_refs.clone();
            evidence.timestamp = signal.first_seen.clone().unwrap_or_else(Timestamp::now);
            evidence.weight = signal.weight.clone();
            evidence.confidence = signal.confidence.clone();
            evidence.privacy_class = PrivacyClass::Internal;
            evidence.description_redacted = Some(format!(
                "Metadata-only lateral movement lite signal: {}; flow and exposure context only.",
                signal.kind.label()
            ));
            evidence_refs_by_signal
                .entry(signal.signal_key.clone())
                .or_insert_with(Vec::new)
                .push(evidence.evidence_id.clone());
            evidence_items.push(evidence);
        }
        if evidence_items.is_empty() {
            return Err(LateralMovementError::NoSignals);
        }
        Ok(LateralEvidenceBuildResult {
            evidence_items,
            evidence_refs_by_signal,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct LateralGraphHintBuilder;

impl LateralGraphHintBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        producer_plugin: &PluginId,
        signals: &[LateralMovementSignal],
        evidence_refs_by_signal: &BTreeMap<String, Vec<EvidenceId>>,
    ) -> Result<Vec<GraphHint>, LateralMovementError> {
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
                        EntityType::Ip | EntityType::Port | EntityType::Service
                    )
                })
                .cloned()
            else {
                continue;
            };
            let key = format!(
                "{}:{}:{}",
                signal.kind.graph_hint_name(),
                source.entity_id,
                target.entity_id
            );
            let mut hint = GraphHint::new(
                GraphHintType::Custom(signal.kind.graph_hint_name().to_string()),
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
pub struct LateralMovementLitePlugin {
    internal_fanout: InternalFanoutDetector,
    service_probe: ServiceProbeDetector,
    unknown_process_internal_access: UnknownProcessInternalAccessDetector,
    exposure_linked_movement: ExposureLinkedMovementDetector,
    evidence_builder: LateralEvidenceBuilder,
    graph_hint_builder: LateralGraphHintBuilder,
    evidence_management: EvidenceManagementPlugin,
}

impl Default for LateralMovementLitePlugin {
    fn default() -> Self {
        Self {
            internal_fanout: InternalFanoutDetector::new(),
            service_probe: ServiceProbeDetector::new(),
            unknown_process_internal_access: UnknownProcessInternalAccessDetector::new(),
            exposure_linked_movement: ExposureLinkedMovementDetector::new(),
            evidence_builder: LateralEvidenceBuilder::new(),
            graph_hint_builder: LateralGraphHintBuilder::new(),
            evidence_management: EvidenceManagementPlugin::new(),
        }
    }
}

impl LateralMovementLitePlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn manifest() -> Result<PluginManifest, LateralMovementError> {
        let plugin_id = PluginId::new_v4();
        let mut manifest = PluginManifest::new(
            plugin_id.clone(),
            "lateral_movement_lite",
            "0.1.0",
            "lateral_movement",
            PluginType::Detection,
            RuntimeMode::Streaming,
        )?;
        manifest.description = "Metadata-first lateral movement lite detector that emits findings, evidence, risk context, and graph hints only.".to_string();
        manifest.enabled_by_default = true;
        manifest.maturity_level = MaturityLevel::L2Detectable;
        manifest.capability_tags = vec![
            "local_first".to_string(),
            "metadata_first".to_string(),
            "lateral_movement".to_string(),
            "finding_only".to_string(),
        ];
        manifest.input_contracts = [
            "network.flow.record",
            "network.session.record",
            "identity.process_context",
            "asset.record",
            "asset.service_record",
            "asset.port_exposure",
            "asset.exposure.observation",
            "security.finding.asset_risk",
        ]
        .into_iter()
        .map(contract)
        .collect::<Result<Vec<_>, _>>()?;
        manifest.output_contracts = [
            LATERAL_FINDING_TYPE,
            "security.evidence",
            "security.risk_hint",
            "graph.hint.lateral_internal_fanout",
            "graph.hint.lateral_service_probe",
            "graph.hint.lateral_exposure_linked_movement",
        ]
        .into_iter()
        .map(contract)
        .collect::<Result<Vec<_>, _>>()?;
        manifest.required_permissions = vec![
            permission(
                "read.network.metadata",
                PermissionCategory::DataAccess,
                "Read metadata-only internal flow and session records.",
                &["network.flow.record", "network.session.record"],
            )?,
            permission(
                "read.identity.process_context",
                PermissionCategory::DataAccess,
                "Read process attribution metadata.",
                &["identity.process_context"],
            )?,
            permission(
                "read.asset.exposure",
                PermissionCategory::DataAccess,
                "Read local asset exposure inventory and findings.",
                &[
                    "asset.record",
                    "asset.service_record",
                    "asset.port_exposure",
                    "asset.exposure.observation",
                    "security.finding.asset_risk",
                ],
            )?,
        ];
        manifest.metrics_schema = vec![
            metric(
                "lateral_lite.events_in_total",
                MetricKind::Counter,
                "Lateral movement lite input records received",
            )?,
            metric(
                "lateral_lite.signals_out_total",
                MetricKind::Counter,
                "Lateral movement lite signals emitted",
            )?,
            metric(
                "lateral_lite.findings_out_total",
                MetricKind::Counter,
                "Lateral movement lite findings emitted",
            )?,
            metric(
                "lateral_lite.graph_hints_out_total",
                MetricKind::Counter,
                "Lateral movement graph hints emitted",
            )?,
            metric(
                "lateral_lite.latency_ms",
                MetricKind::Histogram,
                "Lateral movement lite processing latency",
            )?,
        ];
        manifest.finding_types = vec![LATERAL_FINDING_TYPE.to_string()];
        manifest.graph_hint_types = vec![
            LATERAL_INTERNAL_FANOUT_HINT.to_string(),
            LATERAL_SERVICE_PROBE_HINT.to_string(),
            LATERAL_EXPOSURE_LINKED_HINT.to_string(),
        ];
        manifest.ui_contributions = vec![
            ui_contribution(
                plugin_id.clone(),
                UiContributionSlot::InvestigationEvidencePanel,
                RendererType::EvidenceList,
                "Lateral Movement Evidence",
                "security.evidence",
            )?,
            ui_contribution(
                plugin_id.clone(),
                UiContributionSlot::GraphProjection,
                RendererType::GraphProjection,
                "Lateral Movement Hints",
                "graph.hint.lateral_service_probe",
            )?,
        ];
        manifest.statefulness = PluginStatefulness::Baseline;
        manifest.checkpoint_support = SupportLevel::Optional;
        manifest.replay_support = SupportLevel::Optional;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn detect(
        &self,
        input: LateralMovementLiteInput,
    ) -> Result<LateralMovementLiteOutput, LateralMovementError> {
        validate_input(&input)?;
        if input.flows.is_empty()
            && input.process_contexts.is_empty()
            && input.port_exposures.is_empty()
            && input.asset_findings.is_empty()
        {
            return Err(LateralMovementError::EmptyInput);
        }

        let context = LateralMovementContext::new(&input);
        let mut signals = Vec::new();
        signals.extend(self.internal_fanout.detect_with_context(&input, &context)?);
        signals.extend(self.service_probe.detect_with_context(&input, &context)?);
        signals.extend(
            self.unknown_process_internal_access
                .detect_with_context(&input, &context)?,
        );
        signals.extend(
            self.exposure_linked_movement
                .detect_with_context(&input, &context)?,
        );
        let signals = merge_signals(signals);
        if signals.is_empty() {
            return Err(LateralMovementError::NoSignals);
        }

        let evidence_build = self
            .evidence_builder
            .build(&input.producer_plugin, &signals)?;
        let graph_hints = self.graph_hint_builder.build(
            &input.producer_plugin,
            &signals,
            &evidence_build.evidence_refs_by_signal,
        )?;

        let evidence_management = self.evidence_management.manage(EvidenceManagementInput {
            finding_type: LATERAL_FINDING_TYPE.to_string(),
            producer_plugin: input.producer_plugin.clone(),
            entity_refs: entity_refs_for_finding(&signals),
            evidence_collection: EvidenceCollectionInput {
                evidence_items: evidence_build.evidence_items,
                risk_hints: Vec::new(),
                graph_hints: graph_hints.clone(),
                producer_plugin: Some(input.producer_plugin),
                ..EvidenceCollectionInput::default()
            },
            high_confidence_requires_independent_sources: true,
            trace_id: input.trace_id,
            labels: input.labels,
        })?;

        Ok(LateralMovementLiteOutput {
            signals,
            findings: vec![evidence_management.finding.clone()],
            evidence: evidence_management.evidence.clone(),
            risk_hints: Vec::new(),
            graph_hints,
            evidence_management,
        })
    }
}

fn is_internal_flow(flow: &FlowRecord) -> bool {
    matches!(
        flow.direction,
        NetworkDirection::Outbound | NetworkDirection::Lateral
    ) && is_internal_ip(&flow.dst_ip)
        && !flow.dst_ip.as_ip_addr().is_loopback()
}

fn is_internal_ip(ip: &IpAddress) -> bool {
    match ip.as_ip_addr() {
        IpAddr::V4(value) => {
            let octets = value.octets();
            octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 169 && octets[1] == 254)
        }
        IpAddr::V6(value) => value.is_unique_local() || value.is_unicast_link_local(),
    }
}

fn entities_for_flow(
    flow: &FlowRecord,
    context: &LateralMovementContext<'_>,
    target: Option<&LateralTarget>,
) -> Result<Vec<EntityRef>, LateralMovementError> {
    let mut entities = Vec::new();
    if let Some(process_ref) = &flow.process_ref {
        entities.push(process_entity(process_ref, context.process(process_ref))?);
    } else {
        entities.push(unknown_process_entity()?);
    }
    if let Some(target) = target {
        entities.push(target_entity(target)?);
    } else {
        entities.push(ip_entity(&flow.dst_ip)?);
    }
    Ok(entities)
}

fn entities_for_exposure(
    flow: &FlowRecord,
    exposure: &PortExposureRecord,
    findings: &[&AssetRiskFinding],
    context: &LateralMovementContext<'_>,
) -> Result<Vec<EntityRef>, LateralMovementError> {
    let mut entities = entities_for_flow(
        flow,
        context,
        Some(&LateralTarget::Port {
            ip: flow.dst_ip,
            port: flow.dst_port,
        }),
    )?;
    entities.push(exposure.port_entity.clone());
    if let Some(process_entity) = &exposure.process_entity {
        entities.push(process_entity.clone());
    }
    for finding in findings {
        for entity in finding.finding.entity_refs() {
            entities.push(entity.clone());
        }
    }
    Ok(entities)
}

fn target_entity(target: &LateralTarget) -> Result<EntityRef, LateralMovementError> {
    match target {
        LateralTarget::Ip(ip) => ip_entity(ip),
        LateralTarget::Port { ip, port } => port_entity(ip, *port),
        LateralTarget::Service(service) => service_entity(service),
        LateralTarget::UnknownInternal => unknown_internal_entity(),
    }
}

fn process_entity(
    process_ref: &ProcessContextId,
    process: Option<&ProcessContext>,
) -> Result<EntityRef, LateralMovementError> {
    let mut entity = EntityRef::new(
        EntityId::from_uuid(process_ref.as_uuid()),
        EntityType::Process,
    );
    entity.entity_name = process.map(|process| process.process_name.clone());
    entity.namespace = Some("identity.process_context".to_string());
    entity.source = Some("lateral_movement_lite".to_string());
    entity.confidence = quality_score(0.75)?;
    Ok(entity)
}

fn unknown_process_entity() -> Result<EntityRef, LateralMovementError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Process);
    entity.entity_name = Some("unknown_process".to_string());
    entity.namespace = Some("identity.process_context".to_string());
    entity.source = Some("lateral_movement_lite".to_string());
    entity.confidence = quality_score(0.35)?;
    Ok(entity)
}

fn ip_entity(ip: &IpAddress) -> Result<EntityRef, LateralMovementError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Ip);
    entity.entity_name = Some(ip.to_string());
    entity.namespace = Some("network.ip".to_string());
    entity.source = Some("lateral_movement_lite".to_string());
    entity.confidence = quality_score(0.7)?;
    Ok(entity)
}

fn port_entity(ip: &IpAddress, port: u16) -> Result<EntityRef, LateralMovementError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Port);
    entity.entity_name = Some(format!("{}:{port}", ip));
    entity.namespace = Some("network.internal_port".to_string());
    entity.source = Some("lateral_movement_lite".to_string());
    entity.confidence = quality_score(0.68)?;
    Ok(entity)
}

fn service_entity(service: &str) -> Result<EntityRef, LateralMovementError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Service);
    entity.entity_name = Some(require_safe_text("service_name", service.to_string())?);
    entity.namespace = Some("asset.service".to_string());
    entity.source = Some("lateral_movement_lite".to_string());
    entity.confidence = quality_score(0.62)?;
    Ok(entity)
}

fn unknown_internal_entity() -> Result<EntityRef, LateralMovementError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Other);
    entity.entity_name = Some("unknown_internal_target".to_string());
    entity.namespace = Some("network.internal".to_string());
    entity.source = Some("lateral_movement_lite".to_string());
    entity.confidence = quality_score(0.35)?;
    Ok(entity)
}

fn entity_refs_for_finding(signals: &[LateralMovementSignal]) -> Vec<EntityRef> {
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

fn merge_signals(signals: Vec<LateralMovementSignal>) -> Vec<LateralMovementSignal> {
    let mut merged = BTreeMap::<String, LateralMovementSignal>::new();
    for signal in signals {
        if let Some(existing) = merged.get_mut(&signal.signal_key) {
            existing.confidence = max_quality(&existing.confidence, &signal.confidence);
            existing.weight = max_quality(&existing.weight, &signal.weight);
            merge_by_string(&mut existing.flow_refs, signal.flow_refs);
            merge_by_string(
                &mut existing.related_asset_finding_refs,
                signal.related_asset_finding_refs,
            );
            merge_strings(
                &mut existing.related_port_exposure_refs,
                signal.related_port_exposure_refs,
            );
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

fn merge_strings(target: &mut Vec<String>, source: Vec<String>) {
    let mut seen = target.iter().cloned().collect::<HashSet<_>>();
    for value in source {
        if seen.insert(value.clone()) {
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

fn process_has_suspicious_context(process: &ProcessContext) -> bool {
    matches!(
        process.signer_status,
        SignerStatus::Unsigned | SignerStatus::InvalidSignature | SignerStatus::Revoked
    ) || process.trust_score.network_rarity.value() >= 0.65
        || process.trust_score.destination_risk.value() >= 0.65
}

fn process_destination_key(process_name: &str, ip: &IpAddress, port: u16) -> String {
    format!("{}|{}|{}", normalize(process_name), ip, port)
}

fn known_internal_destination(
    context: &LateralMovementContext<'_>,
    process_name: &str,
    ip: &IpAddress,
    port: u16,
) -> bool {
    context
        .known_internal_destinations
        .contains(&process_destination_key(process_name, ip, port))
}

fn endpoint_key(ip: &IpAddress, port: u16) -> String {
    format!("{}|{}", ip, port)
}

fn service_name_for_port(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        135 => "RPC",
        139 | 445 => "SMB",
        3389 => "RDP",
        5985 | 5986 => "WinRM",
        _ => "internal service",
    }
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn validate_input(input: &LateralMovementLiteInput) -> Result<(), LateralMovementError> {
    for destination in &input.baseline.known_internal_destinations {
        validate_safe_text("known_process", &destination.process_name)?;
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
    for asset in &input.assets {
        if let Some(hostname) = &asset.hostname_protected {
            validate_safe_text("asset_hostname_protected", hostname)?;
        }
        for label in &asset.labels {
            validate_safe_text("asset_label", label)?;
        }
    }
    for service in &input.services {
        if let Some(process_name) = &service.process_name_protected {
            validate_safe_text("service_process_name", process_name)?;
        }
        if let Some(service_name) = &service.service_name_protected {
            validate_safe_text("service_name", service_name)?;
        }
    }
    for exposure in &input.port_exposures {
        if exposure.local_port == 0 {
            return Err(LateralMovementError::Contract(
                "port exposure local_port must be non-zero".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), LateralMovementError> {
    if value.trim().is_empty() {
        return Err(LateralMovementError::EmptyField(field));
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
        return Err(LateralMovementError::PrivacyMarker { field });
    }
    Ok(())
}

fn require_safe_text(field: &'static str, value: String) -> Result<String, LateralMovementError> {
    validate_safe_text(field, &value)?;
    Ok(value)
}

fn quality_score(value: f32) -> Result<QualityScore, LateralMovementError> {
    QualityScore::new(value).map_err(|_| LateralMovementError::InvalidQualityScore)
}

fn contract(name: &str) -> Result<ContractDescriptor, ManifestValidationError> {
    ContractDescriptor::new(name, LATERAL_MOVEMENT_SCHEMA_VERSION)
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
        "schema_version": LATERAL_MOVEMENT_SCHEMA_VERSION,
        "metadata_only": true
    });
    Ok(contribution)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset_exposure::{
        AssetExposureInput, AssetExposurePlugin, BindScope, InventorySource, ListeningPortInput,
        ServiceInventoryInput, ServiceInventoryPlugin, ServiceKind,
    };
    use chrono::{Duration, Utc};
    use sentinel_contracts::{
        AttributionConfidence, CollectionMode, NetworkDirection, SignerStatus, TransportProtocol,
        VisibilityLevel,
    };

    fn ip(value: &str) -> IpAddress {
        IpAddress::parse_str(value).expect("test IP")
    }

    fn q(value: f32) -> QualityScore {
        QualityScore::new(value).expect("quality")
    }

    fn process() -> ProcessContext {
        let mut process = ProcessContext::new(7_770, "fixture_scanner");
        process.signer_status = SignerStatus::Unsigned;
        process.visibility_level = VisibilityLevel::MetadataOnly;
        process.collection_mode = CollectionMode::Mock;
        process
    }

    fn flow(
        process: Option<&ProcessContext>,
        dst_ip: &str,
        dst_port: u16,
        offset_seconds: i64,
    ) -> FlowRecord {
        let start = Utc::now() + Duration::seconds(offset_seconds);
        let mut flow = FlowRecord::new(
            ip("192.168.1.10"),
            50_000 + offset_seconds as u16,
            ip(dst_ip),
            dst_port,
            TransportProtocol::Tcp,
            NetworkDirection::Lateral,
        );
        flow.start_time = Timestamp::from_datetime(start);
        flow.end_time = Some(Timestamp::from_datetime(start + Duration::seconds(1)));
        flow.duration_millis = Some(1_000);
        flow.bytes_out = 640;
        flow.bytes_in = 180;
        flow.packets_out = 3;
        flow.packets_in = 1;
        flow.process_ref = process.map(|process| process.process_context_id.clone());
        flow.attribution_confidence = if process.is_some() {
            AttributionConfidence::Medium
        } else {
            AttributionConfidence::Unknown
        };
        flow.quality_score = q(0.88);
        flow
    }

    type AssetFixture = (
        Vec<AssetRecord>,
        Vec<ServiceRecord>,
        Vec<PortExposureRecord>,
        Vec<AssetExposureObservation>,
        Vec<AssetRiskFinding>,
    );

    fn asset_fixture(service_process: &ProcessContext) -> AssetFixture {
        let listening = ListeningPortInput::new(
            ip("192.168.1.25"),
            445,
            TransportProtocol::Tcp,
            BindScope::Lan,
        )
        .with_process_context(service_process.clone(), AttributionConfidence::Low)
        .with_service("lan_smb", "LAN SMB Fixture", ServiceKind::WindowsService)
        .with_source(InventorySource::MockEndpointSnapshot);
        let inventory = ServiceInventoryPlugin::new()
            .inventory(ServiceInventoryInput::new(vec![listening]))
            .expect("inventory");
        let exposure_input =
            AssetExposureInput::from_inventory(inventory, PluginId::new_v4()).expect("input");
        let output = AssetExposurePlugin::new()
            .observe(exposure_input.clone())
            .expect("asset exposure");
        (
            vec![exposure_input.asset],
            exposure_input.services,
            exposure_input.port_exposures,
            output.observations,
            output.findings,
        )
    }

    fn fixture_input() -> LateralMovementLiteInput {
        let scanner = process();
        let service_process = ProcessContext::new(4, "lan_service");
        let (assets, services, port_exposures, asset_observations, asset_findings) =
            asset_fixture(&service_process);
        let mut input = LateralMovementLiteInput::new(PluginId::new_v4());
        input.process_contexts = vec![scanner.clone(), service_process];
        input.flows = vec![
            flow(Some(&scanner), "192.168.1.21", 445, 1),
            flow(Some(&scanner), "192.168.1.22", 3389, 2),
            flow(Some(&scanner), "192.168.1.23", 5985, 3),
            flow(Some(&scanner), "192.168.1.25", 445, 4),
            flow(None, "192.168.1.26", 22, 5),
        ];
        input.assets = assets;
        input.services = services;
        input.port_exposures = port_exposures;
        input.asset_observations = asset_observations;
        input.asset_findings = asset_findings;
        input.baseline = LateralMovementBaseline {
            max_unique_internal_destinations_per_process: 3,
            known_internal_destinations: vec![KnownInternalDestination::new(
                "fixture_scanner",
                ip("192.168.1.20"),
                445,
            )],
            service_probe_ports: vec![22, 445, 3389, 5985, 5986],
        };
        input.labels = vec!["task_420_fixture".to_string()];
        input
    }

    #[test]
    fn lateral_detection_emits_evidence_backed_finding_for_fixture_story() {
        let output = LateralMovementLitePlugin::new()
            .detect(fixture_input())
            .expect("lateral output");

        assert_eq!(output.findings.len(), 1);
        assert_eq!(output.findings[0].finding_type(), LATERAL_FINDING_TYPE);
        assert!(!output.findings[0].evidence_refs().is_empty());
        assert!(output.evidence_management.quality_report.passed);

        let evidence_types = output
            .evidence
            .iter()
            .map(|item| item.evidence.evidence_type.as_str())
            .collect::<HashSet<_>>();
        for required in [
            "lateral.network.internal_fanout",
            "lateral.network.service_probe",
            "lateral.process.unknown_internal_access",
            "lateral.asset.exposure_linked_movement",
        ] {
            assert!(evidence_types.contains(required), "missing {required}");
        }

        let explanation =
            serde_json::to_string(output.findings[0].explanation()).expect("explanation json");
        assert!(explanation.contains("metadata-only"));
        assert!(explanation.contains("flow") || explanation.contains("exposure"));
        assert!(output.risk_hints.iter().all(|hint| {
            hint.evidence_input_only
                && !hint.creates_alert
                && !hint.creates_incident
                && !hint.executes_response
        }));
        assert!(output.graph_hints.iter().any(|hint| {
            hint.hint_type == GraphHintType::Custom(LATERAL_INTERNAL_FANOUT_HINT.to_string())
        }));
        assert!(output.graph_hints.iter().any(|hint| {
            hint.hint_type == GraphHintType::Custom(LATERAL_SERVICE_PROBE_HINT.to_string())
        }));
    }

    #[test]
    fn known_internal_destination_suppresses_service_probe_signal() {
        let scanner = process();
        let mut input = LateralMovementLiteInput::new(PluginId::new_v4());
        input.process_contexts = vec![scanner.clone()];
        input.flows = vec![flow(Some(&scanner), "192.168.1.21", 445, 1)];
        input.baseline.known_internal_destinations = vec![KnownInternalDestination::new(
            "fixture_scanner",
            ip("192.168.1.21"),
            445,
        )];

        let signals = ServiceProbeDetector::new()
            .detect(&input)
            .expect("service probe detection");

        assert!(signals
            .iter()
            .all(|signal| signal.kind != LateralSignalKind::ServiceProbe));
    }

    #[test]
    fn graph_hints_are_emitted_without_canonical_graph_writes() {
        let output = LateralMovementLitePlugin::new()
            .detect(fixture_input())
            .expect("lateral output");

        assert!(!output.graph_hints.is_empty());
        assert!(output.graph_hints.iter().all(|hint| {
            matches!(
                &hint.hint_type,
                GraphHintType::Custom(value)
                    if value == LATERAL_INTERNAL_FANOUT_HINT
                        || value == LATERAL_SERVICE_PROBE_HINT
                        || value == LATERAL_EXPOSURE_LINKED_HINT
            )
        }));
        let serialized = serde_json::to_string(&output).expect("serialize output");
        assert!(!serialized.contains("canonical_graph"));
        assert!(!serialized.contains("graph.update"));
        assert!(!serialized.contains("graph_update"));
    }

    #[test]
    fn plugin_manifest_declares_contracts_permissions_metrics_and_ui() {
        let manifest = LateralMovementLitePlugin::manifest().expect("manifest");
        manifest.validate().expect("valid manifest");

        let input_contracts = manifest
            .input_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<HashSet<_>>();
        for required in [
            "network.flow.record",
            "network.session.record",
            "identity.process_context",
            "asset.port_exposure",
            "security.finding.asset_risk",
        ] {
            assert!(input_contracts.contains(required), "missing {required}");
        }

        let output_contracts = manifest
            .output_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<HashSet<_>>();
        assert!(output_contracts.contains(LATERAL_FINDING_TYPE));
        assert!(output_contracts.contains("security.evidence"));
        assert!(output_contracts.contains("security.risk_hint"));
        assert!(output_contracts.contains("graph.hint.lateral_internal_fanout"));
        assert_eq!(manifest.plugin_type, PluginType::Detection);
        assert_eq!(
            manifest.finding_types,
            vec![LATERAL_FINDING_TYPE.to_string()]
        );
        assert!(manifest
            .graph_hint_types
            .contains(&LATERAL_SERVICE_PROBE_HINT.to_string()));
        assert!(!manifest.metrics_schema.is_empty());
        assert!(!manifest.ui_contributions.is_empty());
        assert!(manifest.required_permissions.iter().all(|permission| {
            permission.category == PermissionCategory::DataAccess
                && permission.risk_level == PermissionRiskLevel::Low
                && !permission.permission.as_str().contains("response")
        }));

        let asset_permission = manifest
            .required_permissions
            .iter()
            .find(|permission| permission.permission.as_str() == "read.asset.exposure")
            .expect("asset exposure permission");
        let asset_scopes = asset_permission
            .scopes
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        for required in [
            "asset.record",
            "asset.service_record",
            "asset.port_exposure",
            "asset.exposure.observation",
            "security.finding.asset_risk",
        ] {
            assert!(asset_scopes.contains(required), "missing {required}");
        }
    }

    #[test]
    fn sensitive_metadata_marker_is_rejected() {
        let scanner = process();
        let mut input = LateralMovementLiteInput::new(PluginId::new_v4());
        let mut bad_process = scanner.clone();
        bad_process.process_name = "api_key_scanner".to_string();
        input.process_contexts = vec![bad_process.clone()];
        input.flows = vec![flow(Some(&bad_process), "192.168.1.21", 445, 1)];

        let error = LateralMovementLitePlugin::new()
            .detect(input)
            .expect_err("privacy marker rejected");
        assert!(matches!(
            error,
            LateralMovementError::PrivacyMarker {
                field: "process_name"
            }
        ));
    }
}
