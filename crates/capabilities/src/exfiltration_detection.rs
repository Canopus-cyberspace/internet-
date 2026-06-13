use crate::evidence_management::{
    CollectedEvidence, EvidenceCollectionInput, EvidenceManagementError, EvidenceManagementInput,
    EvidenceManagementOutput, EvidenceManagementPlugin,
};
use sentinel_contracts::{
    CloudContext, ContractDescriptor, DataSourceDescriptor, DataSourceKind, EntityId, EntityRef,
    EntityType, EvidenceId, EvidenceItem, Finding, FlowId, FlowRecord, GraphHint, GraphHintType,
    HttpMetadata, IntelligenceContractError, IpAddress, IpContext, ManifestValidationError,
    MaturityLevel, MetricKind, MetricSchema, NetworkDirection, PermissionCategory,
    PermissionDescriptor, PermissionKey, PermissionRiskLevel, PluginId, PluginManifest,
    PluginStatefulness, PluginType, PrivacyClass, ProcessContext, ProcessContextId, QualityScore,
    RefreshMode, RendererType, RiskHint, RuntimeMode, SchemaVersion, SessionRecord, SignerStatus,
    SupportLevel, Timestamp, TraceId, TransportProtocol, UiContribution, UiContributionSlot,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

pub const EXFILTRATION_DETECTION_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const EXFILTRATION_FINDING_TYPE: &str = "security.finding.exfiltration";
pub const PROCESS_UPLOADS_TO_CLOUD_GRAPH_HINT: &str = "process_uploads_to_cloud";

#[derive(Debug)]
pub enum ExfiltrationDetectionError {
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

impl fmt::Display for ExfiltrationDetectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "at least one exfiltration detection input is required"),
            Self::NoSignals => write!(f, "no exfiltration detection signals were produced"),
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::PrivacyMarker { field } => {
                write!(f, "{field} contains a forbidden private-content marker")
            }
            Self::InvalidQualityScore => write!(f, "quality score is outside valid range"),
            Self::Evidence(error) => write!(f, "exfiltration evidence management error: {error}"),
            Self::Contract(error) => write!(f, "exfiltration contract error: {error}"),
            Self::Intelligence(error) => {
                write!(f, "exfiltration intelligence boundary error: {error}")
            }
            Self::Manifest(error) => write!(f, "exfiltration plugin manifest error: {error}"),
        }
    }
}

impl std::error::Error for ExfiltrationDetectionError {}

impl From<EvidenceManagementError> for ExfiltrationDetectionError {
    fn from(value: EvidenceManagementError) -> Self {
        Self::Evidence(value)
    }
}

impl From<sentinel_contracts::SecurityContractError> for ExfiltrationDetectionError {
    fn from(value: sentinel_contracts::SecurityContractError) -> Self {
        Self::Contract(value.to_string())
    }
}

impl From<IntelligenceContractError> for ExfiltrationDetectionError {
    fn from(value: IntelligenceContractError) -> Self {
        Self::Intelligence(value.to_string())
    }
}

impl From<ManifestValidationError> for ExfiltrationDetectionError {
    fn from(value: ManifestValidationError) -> Self {
        Self::Manifest(value.to_string())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessUploadBaseline {
    pub process_name: String,
    pub max_upload_bytes_per_window: u64,
    pub max_upload_download_ratio: f32,
    pub max_small_upload_count_per_window: usize,
}

impl ProcessUploadBaseline {
    pub fn new(
        process_name: impl Into<String>,
        max_upload_bytes_per_window: u64,
        max_upload_download_ratio: f32,
        max_small_upload_count_per_window: usize,
    ) -> Self {
        Self {
            process_name: process_name.into(),
            max_upload_bytes_per_window,
            max_upload_download_ratio,
            max_small_upload_count_per_window,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownProcessCloudDestination {
    pub process_name: String,
    pub provider_protected: String,
    pub destination_protected: String,
}

impl KnownProcessCloudDestination {
    pub fn new(
        process_name: impl Into<String>,
        provider_protected: impl Into<String>,
        destination_protected: impl Into<String>,
    ) -> Self {
        Self {
            process_name: process_name.into(),
            provider_protected: provider_protected.into(),
            destination_protected: destination_protected.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExfiltrationDetectionBaseline {
    pub process_uploads: Vec<ProcessUploadBaseline>,
    pub known_cloud_destinations_by_process: Vec<KnownProcessCloudDestination>,
    pub normal_upload_hours_utc: Vec<u8>,
}

impl Default for ExfiltrationDetectionBaseline {
    fn default() -> Self {
        Self {
            process_uploads: Vec::new(),
            known_cloud_destinations_by_process: Vec::new(),
            normal_upload_hours_utc: (8_u8..=18).collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExfiltrationDetectionInput {
    pub flows: Vec<FlowRecord>,
    pub sessions: Vec<SessionRecord>,
    pub http_metadata: Vec<HttpMetadata>,
    pub process_contexts: Vec<ProcessContext>,
    pub ip_contexts: Vec<IpContext>,
    pub cloud_contexts: Vec<CloudContext>,
    pub related_c2_findings: Vec<Finding>,
    pub related_c2_graph_hints: Vec<GraphHint>,
    pub baseline: ExfiltrationDetectionBaseline,
    pub producer_plugin: PluginId,
    pub trace_id: Option<TraceId>,
    pub labels: Vec<String>,
}

impl ExfiltrationDetectionInput {
    pub fn new(producer_plugin: PluginId) -> Self {
        Self {
            flows: Vec::new(),
            sessions: Vec::new(),
            http_metadata: Vec::new(),
            process_contexts: Vec::new(),
            ip_contexts: Vec::new(),
            cloud_contexts: Vec::new(),
            related_c2_findings: Vec::new(),
            related_c2_graph_hints: Vec::new(),
            baseline: ExfiltrationDetectionBaseline::default(),
            producer_plugin,
            trace_id: None,
            labels: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExfiltrationDetectionOutput {
    pub signals: Vec<ExfiltrationSignal>,
    pub findings: Vec<Finding>,
    pub evidence: Vec<CollectedEvidence>,
    pub risk_hints: Vec<RiskHint>,
    pub graph_hints: Vec<GraphHint>,
    pub evidence_management: EvidenceManagementOutput,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExfiltrationSignalKind {
    UploadVolumeSpike,
    UploadRatioAnomaly,
    NewCloudDestination,
    RiskyAsnUpload,
    RepeatedSmallUpload,
    OffHourUpload,
    RelatedC2Signal,
    ProcessContext,
}

impl ExfiltrationSignalKind {
    pub fn evidence_type(&self) -> &'static str {
        match self {
            Self::UploadVolumeSpike => "exfil.network.upload_volume_spike",
            Self::UploadRatioAnomaly => "exfil.network.upload_ratio_anomaly",
            Self::NewCloudDestination => "exfil.cloud.new_destination",
            Self::RiskyAsnUpload => "exfil.network.risky_asn_upload",
            Self::RepeatedSmallUpload => "exfil.network.repeated_small_upload",
            Self::OffHourUpload => "exfil.network.off_hour_upload",
            Self::RelatedC2Signal => "exfil.c2.related_signal",
            Self::ProcessContext => "exfil.process.context",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::UploadVolumeSpike => "upload volume spike",
            Self::UploadRatioAnomaly => "upload ratio anomaly",
            Self::NewCloudDestination => "new cloud destination",
            Self::RiskyAsnUpload => "risky ASN upload",
            Self::RepeatedSmallUpload => "repeated small uploads",
            Self::OffHourUpload => "off-hour upload",
            Self::RelatedC2Signal => "related C2 signal",
            Self::ProcessContext => "process context",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "destination_type", content = "value", rename_all = "snake_case")]
pub enum ExfiltrationDestination {
    Ip(IpAddress),
    CloudProvider(String),
    CloudRange(String),
    Process(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExfiltrationSignal {
    pub signal_key: String,
    pub kind: ExfiltrationSignalKind,
    pub summary_redacted: String,
    pub confidence: QualityScore,
    pub weight: QualityScore,
    pub entity_refs: Vec<EntityRef>,
    pub flow_refs: Vec<FlowId>,
    pub http_refs: Vec<sentinel_contracts::HttpMetadataId>,
    pub related_finding_refs: Vec<sentinel_contracts::FindingId>,
    pub related_graph_hint_refs: Vec<sentinel_contracts::GraphHintId>,
    pub process_ref: Option<ProcessContextId>,
    pub destination: Option<ExfiltrationDestination>,
    pub upload_bytes: u64,
    pub upload_download_ratio: Option<f32>,
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
}

impl ExfiltrationSignal {
    fn new(
        kind: ExfiltrationSignalKind,
        signal_key: impl Into<String>,
        summary_redacted: impl Into<String>,
        confidence: f32,
        weight: f32,
    ) -> Result<Self, ExfiltrationDetectionError> {
        Ok(Self {
            signal_key: require_safe_text("signal_key", signal_key.into())?,
            kind,
            summary_redacted: require_safe_text("summary_redacted", summary_redacted.into())?,
            confidence: quality_score(confidence)?,
            weight: quality_score(weight)?,
            entity_refs: Vec::new(),
            flow_refs: Vec::new(),
            http_refs: Vec::new(),
            related_finding_refs: Vec::new(),
            related_graph_hint_refs: Vec::new(),
            process_ref: None,
            destination: None,
            upload_bytes: 0,
            upload_download_ratio: None,
            first_seen: None,
            last_seen: None,
        })
    }

    fn with_flow(mut self, flow: &FlowRecord) -> Self {
        self.flow_refs = vec![flow.flow_id.clone()];
        self.process_ref = flow.process_ref.clone();
        self.upload_bytes = flow.bytes_out;
        self.upload_download_ratio = flow_ratio(flow);
        self.first_seen = Some(flow.start_time.clone());
        self.last_seen = flow
            .end_time
            .clone()
            .or_else(|| Some(flow.start_time.clone()));
        self
    }

    fn with_flows(mut self, flows: &[&FlowRecord]) -> Self {
        self.flow_refs = flows.iter().map(|flow| flow.flow_id.clone()).collect();
        self.upload_bytes = flows.iter().map(|flow| flow.bytes_out).sum();
        self.upload_download_ratio = aggregate_ratio(flows);
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
struct ExfiltrationDetectionContext<'input> {
    processes: HashMap<ProcessContextId, &'input ProcessContext>,
    ip_contexts: HashMap<String, &'input IpContext>,
    http_by_flow: HashMap<FlowId, Vec<&'input HttpMetadata>>,
    process_upload_baselines: HashMap<String, &'input ProcessUploadBaseline>,
    known_cloud_destinations_by_process: Vec<&'input KnownProcessCloudDestination>,
    known_process_cloud_baselines: HashSet<String>,
    normal_upload_hours: HashSet<u8>,
}

impl<'input> ExfiltrationDetectionContext<'input> {
    fn new(input: &'input ExfiltrationDetectionInput) -> Self {
        let processes = input
            .process_contexts
            .iter()
            .map(|process| (process.process_context_id.clone(), process))
            .collect::<HashMap<_, _>>();
        let ip_contexts = input
            .ip_contexts
            .iter()
            .map(|context| (context.ip.to_string(), context))
            .collect::<HashMap<_, _>>();
        let mut http_by_flow = HashMap::<FlowId, Vec<&HttpMetadata>>::new();
        for metadata in &input.http_metadata {
            if let Some(flow_ref) = &metadata.flow_ref {
                http_by_flow
                    .entry(flow_ref.clone())
                    .or_default()
                    .push(metadata);
            }
        }
        let process_upload_baselines = input
            .baseline
            .process_uploads
            .iter()
            .map(|baseline| (normalize(&baseline.process_name), baseline))
            .collect::<HashMap<_, _>>();

        let mut known_cloud_destinations_by_process = Vec::new();
        let mut known_process_cloud_baselines = HashSet::new();
        for destination in &input.baseline.known_cloud_destinations_by_process {
            let process = normalize(&destination.process_name);
            known_process_cloud_baselines.insert(process.clone());
            known_cloud_destinations_by_process.push(destination);
        }

        Self {
            processes,
            ip_contexts,
            http_by_flow,
            process_upload_baselines,
            known_cloud_destinations_by_process,
            known_process_cloud_baselines,
            normal_upload_hours: input
                .baseline
                .normal_upload_hours_utc
                .iter()
                .copied()
                .collect(),
        }
    }

    fn process(&self, process_ref: &ProcessContextId) -> Option<&ProcessContext> {
        self.processes.get(process_ref).copied()
    }

    fn process_for_flow(&self, flow: &FlowRecord) -> Option<&ProcessContext> {
        flow.process_ref.as_ref().and_then(|id| self.process(id))
    }

    fn upload_baseline_for_process(
        &self,
        process: &ProcessContext,
    ) -> Option<&ProcessUploadBaseline> {
        self.process_upload_baselines
            .get(&normalize(&process.process_name))
            .copied()
    }

    fn ip_context_for_flow(&self, flow: &FlowRecord) -> Option<&IpContext> {
        self.ip_contexts.get(&flow.dst_ip.to_string()).copied()
    }
}

#[derive(Clone, Debug)]
pub struct UploadVolumeSpikeDetector {
    pub minimum_upload_bytes_without_baseline: u64,
    pub baseline_multiplier: f32,
}

impl Default for UploadVolumeSpikeDetector {
    fn default() -> Self {
        Self {
            minimum_upload_bytes_without_baseline: 50_000,
            baseline_multiplier: 1.5,
        }
    }
}

impl UploadVolumeSpikeDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(
        &self,
        input: &ExfiltrationDetectionInput,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let context = ExfiltrationDetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &ExfiltrationDetectionInput,
        context: &ExfiltrationDetectionContext<'_>,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let mut groups = BTreeMap::<String, Vec<&FlowRecord>>::new();
        for flow in input.flows.iter().filter(|flow| is_upload_flow(flow)) {
            let process = flow
                .process_ref
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown_process".to_string());
            groups.entry(process).or_default().push(flow);
        }

        let mut signals = Vec::new();
        for (process_key, flows) in groups {
            let upload_bytes = flows.iter().map(|flow| flow.bytes_out).sum::<u64>();
            let process = flows
                .iter()
                .find_map(|flow| context.process_for_flow(flow))
                .or_else(|| {
                    flows
                        .iter()
                        .find_map(|flow| flow.process_ref.as_ref())
                        .and_then(|id| context.process(id))
                });
            let baseline_limit = process
                .and_then(|process| context.upload_baseline_for_process(process))
                .map(|baseline| baseline.max_upload_bytes_per_window);
            let threshold = baseline_limit
                .map(|limit| ((limit as f32) * self.baseline_multiplier) as u64)
                .unwrap_or(self.minimum_upload_bytes_without_baseline);
            if upload_bytes <= threshold {
                continue;
            }

            let representative = flows[0];
            let destination = destination_for_flow(representative, input, context);
            let mut signal = ExfiltrationSignal::new(
                ExfiltrationSignalKind::UploadVolumeSpike,
                format!("upload_volume:{process_key}"),
                "Metadata-only upload volume exceeded the local baseline; content was not inspected.",
                0.68,
                0.64,
            )?
            .with_flows(&flows)
            .with_entities(entities_for_flow(representative, input, context, destination.as_ref())?);
            signal.destination = destination;
            signal.upload_bytes = upload_bytes;
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug)]
pub struct UploadRatioAnomalyDetector {
    pub default_ratio_threshold: f32,
    pub minimum_upload_bytes: u64,
}

impl Default for UploadRatioAnomalyDetector {
    fn default() -> Self {
        Self {
            default_ratio_threshold: 3.0,
            minimum_upload_bytes: 2_048,
        }
    }
}

impl UploadRatioAnomalyDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(
        &self,
        input: &ExfiltrationDetectionInput,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let context = ExfiltrationDetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &ExfiltrationDetectionInput,
        context: &ExfiltrationDetectionContext<'_>,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let mut signals = Vec::new();
        for flow in input.flows.iter().filter(|flow| is_external_flow(flow)) {
            if flow.bytes_out < self.minimum_upload_bytes {
                continue;
            }
            let process = context.process_for_flow(flow);
            let baseline_ratio = process
                .and_then(|process| context.upload_baseline_for_process(process))
                .map(|baseline| baseline.max_upload_download_ratio);
            let threshold = baseline_ratio
                .map(|ratio| (ratio * 1.5).max(self.default_ratio_threshold))
                .unwrap_or(self.default_ratio_threshold);
            let flow_ratio = flow_ratio(flow).unwrap_or(0.0);
            let http_ratio = context.http_by_flow.get(&flow.flow_id).and_then(|items| {
                items
                    .iter()
                    .filter_map(|item| item.upload_download_ratio)
                    .reduce(f32::max)
            });
            let ratio = http_ratio.unwrap_or(flow_ratio);
            if ratio < threshold {
                continue;
            }

            let destination = destination_for_flow(flow, input, context);
            let mut signal = ExfiltrationSignal::new(
                ExfiltrationSignalKind::UploadRatioAnomaly,
                format!("upload_ratio:{}", flow.flow_id),
                "Metadata-only upload/download ratio was anomalous; content was not inspected.",
                0.62,
                0.58,
            )?
            .with_flow(flow)
            .with_entities(entities_for_flow(
                flow,
                input,
                context,
                destination.as_ref(),
            )?);
            signal.destination = destination;
            signal.upload_download_ratio = Some(ratio);
            signal.http_refs = context
                .http_by_flow
                .get(&flow.flow_id)
                .into_iter()
                .flatten()
                .map(|metadata| metadata.http_metadata_id.clone())
                .collect();
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug, Default)]
pub struct NewCloudDestinationDetector;

impl NewCloudDestinationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(
        &self,
        input: &ExfiltrationDetectionInput,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let context = ExfiltrationDetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &ExfiltrationDetectionInput,
        context: &ExfiltrationDetectionContext<'_>,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let mut signals = Vec::new();
        for flow in input.flows.iter().filter(|flow| is_upload_flow(flow)) {
            let Some(process) = context.process_for_flow(flow) else {
                continue;
            };
            let Some(cloud) = cloud_context_for_flow(flow, input, context) else {
                continue;
            };
            let process_name = normalize(&process.process_name);
            if !context
                .known_process_cloud_baselines
                .contains(&process_name)
                && !cloud.object_storage_hint
            {
                continue;
            }
            if known_cloud_destination_matches(
                context,
                &process_name,
                &cloud.provider_protected,
                &flow.dst_ip,
            ) {
                continue;
            }

            let destination = Some(ExfiltrationDestination::CloudProvider(
                cloud.provider_protected.clone(),
            ));
            let mut signal = ExfiltrationSignal::new(
                ExfiltrationSignalKind::NewCloudDestination,
                format!(
                    "new_cloud:{}:{}",
                    process.process_context_id, cloud.provider_protected
                ),
                "Metadata-only upload reached a cloud destination outside the local baseline.",
                if cloud.object_storage_hint {
                    0.66
                } else {
                    0.56
                },
                if cloud.object_storage_hint { 0.62 } else { 0.5 },
            )?
            .with_flow(flow)
            .with_entities(entities_for_flow(
                flow,
                input,
                context,
                destination.as_ref(),
            )?);
            signal.process_ref = Some(process.process_context_id.clone());
            signal.destination = destination;
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug)]
pub struct RiskyAsnUploadDetector {
    pub minimum_upload_bytes: u64,
}

impl Default for RiskyAsnUploadDetector {
    fn default() -> Self {
        Self {
            minimum_upload_bytes: 2_048,
        }
    }
}

impl RiskyAsnUploadDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(
        &self,
        input: &ExfiltrationDetectionInput,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let context = ExfiltrationDetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &ExfiltrationDetectionInput,
        context: &ExfiltrationDetectionContext<'_>,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let mut signals = Vec::new();
        for flow in input.flows.iter().filter(|flow| is_upload_flow(flow)) {
            if flow.bytes_out < self.minimum_upload_bytes {
                continue;
            }
            let Some(ip_context) = context.ip_context_for_flow(flow) else {
                continue;
            };
            if ip_context.allowlisted
                || !(ip_context.risky_asn
                    || ip_context.blocklisted
                    || ip_context.user_ioc_match
                    || !ip_context.risk_hints.is_empty())
            {
                continue;
            }
            let destination = destination_for_flow(flow, input, context);
            let mut signal = ExfiltrationSignal::new(
                ExfiltrationSignalKind::RiskyAsnUpload,
                format!("risky_asn_upload:{}", flow.flow_id),
                "Metadata-only upload reached a destination with local ASN or IP risk context.",
                context_confidence(ip_context.confidence.value(), 0.52, 0.68),
                0.54,
            )?
            .with_flow(flow)
            .with_entities(entities_for_flow(
                flow,
                input,
                context,
                destination.as_ref(),
            )?);
            signal.destination = destination;
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug)]
pub struct RepeatedSmallUploadDetector {
    pub min_repetitions: usize,
    pub min_upload_bytes: u64,
    pub max_upload_bytes: u64,
}

impl Default for RepeatedSmallUploadDetector {
    fn default() -> Self {
        Self {
            min_repetitions: 3,
            min_upload_bytes: 256,
            max_upload_bytes: 4_096,
        }
    }
}

impl RepeatedSmallUploadDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(
        &self,
        input: &ExfiltrationDetectionInput,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let context = ExfiltrationDetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &ExfiltrationDetectionInput,
        context: &ExfiltrationDetectionContext<'_>,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let mut groups = BTreeMap::<String, Vec<&FlowRecord>>::new();
        for flow in input.flows.iter().filter(|flow| is_external_flow(flow)) {
            if flow.bytes_out < self.min_upload_bytes || flow.bytes_out > self.max_upload_bytes {
                continue;
            }
            let process = flow
                .process_ref
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown_process".to_string());
            let key = format!("{}:{}:{}", process, flow.dst_ip, flow.dst_port);
            groups.entry(key).or_default().push(flow);
        }

        let mut signals = Vec::new();
        for (key, flows) in groups {
            if flows.len() < self.min_repetitions {
                continue;
            }
            let representative = flows[0];
            let process_baseline = context
                .process_for_flow(representative)
                .and_then(|process| context.upload_baseline_for_process(process));
            if process_baseline
                .is_some_and(|baseline| flows.len() <= baseline.max_small_upload_count_per_window)
            {
                continue;
            }
            let destination = destination_for_flow(representative, input, context);
            let mut signal = ExfiltrationSignal::new(
                ExfiltrationSignalKind::RepeatedSmallUpload,
                format!("repeated_small:{key}"),
                "Repeated small metadata-only uploads may indicate staged exfiltration; content was not inspected.",
                0.54,
                0.46,
            )?
            .with_flows(&flows)
            .with_entities(entities_for_flow(
                representative,
                input,
                context,
                destination.as_ref(),
            )?);
            signal.destination = destination;
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug, Default)]
pub struct OffHourUploadDetector;

impl OffHourUploadDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(
        &self,
        input: &ExfiltrationDetectionInput,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let context = ExfiltrationDetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &ExfiltrationDetectionInput,
        context: &ExfiltrationDetectionContext<'_>,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let mut signals = Vec::new();
        for flow in input.flows.iter().filter(|flow| is_upload_flow(flow)) {
            let Some(hour) = hour_utc(&flow.start_time) else {
                continue;
            };
            if context.normal_upload_hours.contains(&hour) {
                continue;
            }
            let destination = destination_for_flow(flow, input, context);
            let mut signal = ExfiltrationSignal::new(
                ExfiltrationSignalKind::OffHourUpload,
                format!("off_hour:{}:{}", flow.flow_id, hour),
                "Upload metadata occurred outside the configured normal UTC hour window.",
                0.5,
                0.42,
            )?
            .with_flow(flow)
            .with_entities(entities_for_flow(
                flow,
                input,
                context,
                destination.as_ref(),
            )?);
            signal.destination = destination;
            signals.push(signal);
        }
        Ok(signals)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RelatedC2SignalJoiner;

impl RelatedC2SignalJoiner {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(
        &self,
        input: &ExfiltrationDetectionInput,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let context = ExfiltrationDetectionContext::new(input);
        self.detect_with_context(input, &context)
    }

    fn detect_with_context(
        &self,
        input: &ExfiltrationDetectionInput,
        context: &ExfiltrationDetectionContext<'_>,
    ) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
        let upload_processes = input
            .flows
            .iter()
            .filter(|flow| is_upload_flow(flow))
            .filter_map(|flow| flow.process_ref.clone())
            .collect::<HashSet<_>>();
        if upload_processes.is_empty() {
            return Ok(Vec::new());
        }

        let mut signals = Vec::new();
        for finding in input
            .related_c2_findings
            .iter()
            .filter(|finding| finding.finding_type().contains("c2"))
        {
            let shared_process = finding.entity_refs().iter().find(|entity| {
                entity.entity_type == EntityType::Process
                    && upload_processes
                        .iter()
                        .any(|process| EntityId::from_uuid(process.as_uuid()) == entity.entity_id)
            });
            let Some(process_entity_ref) = shared_process.cloned() else {
                continue;
            };
            let process_ref = upload_processes
                .iter()
                .find(|process| {
                    EntityId::from_uuid(process.as_uuid()) == process_entity_ref.entity_id
                })
                .cloned();
            let mut signal = ExfiltrationSignal::new(
                ExfiltrationSignalKind::RelatedC2Signal,
                format!("related_c2:{}", finding.id()),
                "Related C2 finding shares upload process context; metadata only, not content proof.",
                context_confidence(finding.confidence().value(), 0.5, 0.74),
                0.5,
            )?
            .with_entities(vec![process_entity_ref]);
            signal.related_finding_refs = vec![finding.id().clone()];
            signal.process_ref = process_ref.clone();
            signal.destination = process_ref
                .as_ref()
                .and_then(|process_ref| context.process(process_ref))
                .map(|process| ExfiltrationDestination::Process(process.process_name.clone()));
            signals.push(signal);
        }

        for hint in input
            .related_c2_graph_hints
            .iter()
            .filter(|hint| matches!(hint.hint_type, GraphHintType::Custom(_)))
        {
            if hint.source_entity.entity_type != EntityType::Process {
                continue;
            }
            let process_ref = upload_processes
                .iter()
                .find(|process| {
                    EntityId::from_uuid(process.as_uuid()) == hint.source_entity.entity_id
                })
                .cloned();
            let Some(process_ref) = process_ref else {
                continue;
            };
            let mut signal = ExfiltrationSignal::new(
                ExfiltrationSignalKind::RelatedC2Signal,
                format!("related_c2_graph:{}", hint.hint_id),
                "Related C2 graph hint shares upload process context; metadata only, not content proof.",
                context_confidence(hint.confidence.value(), 0.48, 0.7),
                0.46,
            )?
            .with_entities(vec![hint.source_entity.clone(), hint.target_entity.clone()]);
            signal.related_graph_hint_refs = vec![hint.hint_id.clone()];
            signal.process_ref = Some(process_ref);
            signals.push(signal);
        }

        Ok(signals)
    }
}

#[derive(Clone, Debug)]
pub struct ExfilEvidenceBuildResult {
    pub evidence_items: Vec<EvidenceItem>,
    pub evidence_refs_by_signal: BTreeMap<String, Vec<EvidenceId>>,
}

#[derive(Clone, Debug, Default)]
pub struct ExfilEvidenceBuilder;

impl ExfilEvidenceBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        producer_plugin: &PluginId,
        signals: &[ExfiltrationSignal],
    ) -> Result<ExfilEvidenceBuildResult, ExfiltrationDetectionError> {
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
                "Metadata-only exfiltration signal: {}; byte-count and timing context only.",
                signal.kind.label()
            ));
            evidence_refs_by_signal
                .entry(signal.signal_key.clone())
                .or_insert_with(Vec::new)
                .push(evidence.evidence_id.clone());
            evidence_items.push(evidence);
        }
        if evidence_items.is_empty() {
            return Err(ExfiltrationDetectionError::NoSignals);
        }
        Ok(ExfilEvidenceBuildResult {
            evidence_items,
            evidence_refs_by_signal,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExfilGraphHintBuilder;

impl ExfilGraphHintBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        producer_plugin: &PluginId,
        signals: &[ExfiltrationSignal],
        evidence_refs_by_signal: &BTreeMap<String, Vec<EvidenceId>>,
    ) -> Result<Vec<GraphHint>, ExfiltrationDetectionError> {
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
                        EntityType::CloudResource | EntityType::Ip | EntityType::Asn
                    )
                })
                .cloned()
            else {
                continue;
            };
            let key = format!("{}:{}", source.entity_id, target.entity_id);
            let mut hint = GraphHint::new(
                GraphHintType::ProcessUploadsToCloud,
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
pub struct ExfiltrationDetectionPlugin {
    upload_volume_spike: UploadVolumeSpikeDetector,
    upload_ratio_anomaly: UploadRatioAnomalyDetector,
    new_cloud_destination: NewCloudDestinationDetector,
    risky_asn_upload: RiskyAsnUploadDetector,
    repeated_small_upload: RepeatedSmallUploadDetector,
    off_hour_upload: OffHourUploadDetector,
    related_c2_signal: RelatedC2SignalJoiner,
    evidence_builder: ExfilEvidenceBuilder,
    graph_hint_builder: ExfilGraphHintBuilder,
    evidence_management: EvidenceManagementPlugin,
}

impl Default for ExfiltrationDetectionPlugin {
    fn default() -> Self {
        Self {
            upload_volume_spike: UploadVolumeSpikeDetector::new(),
            upload_ratio_anomaly: UploadRatioAnomalyDetector::new(),
            new_cloud_destination: NewCloudDestinationDetector::new(),
            risky_asn_upload: RiskyAsnUploadDetector::new(),
            repeated_small_upload: RepeatedSmallUploadDetector::new(),
            off_hour_upload: OffHourUploadDetector::new(),
            related_c2_signal: RelatedC2SignalJoiner::new(),
            evidence_builder: ExfilEvidenceBuilder::new(),
            graph_hint_builder: ExfilGraphHintBuilder::new(),
            evidence_management: EvidenceManagementPlugin::new(),
        }
    }
}

impl ExfiltrationDetectionPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn manifest() -> Result<PluginManifest, ExfiltrationDetectionError> {
        let plugin_id = PluginId::new_v4();
        let mut manifest = PluginManifest::new(
            plugin_id.clone(),
            "exfiltration_detection_mvp",
            "0.1.0",
            "exfiltration_detection",
            PluginType::Detection,
            RuntimeMode::Streaming,
        )?;
        manifest.description = "Metadata-first exfiltration detection MVP that emits findings, evidence, risk hints, and process-upload graph hints only.".to_string();
        manifest.enabled_by_default = true;
        manifest.maturity_level = MaturityLevel::L2Detectable;
        manifest.capability_tags = vec![
            "local_first".to_string(),
            "metadata_first".to_string(),
            "exfiltration".to_string(),
            "finding_only".to_string(),
        ];
        manifest.input_contracts = [
            "network.flow.record",
            "network.session.record",
            "network.http.metadata",
            "identity.process_context",
            "intel.ip_context",
            "intel.cloud_context",
            "security.finding.c2",
            "graph.hint.suspicious_c2_relation",
        ]
        .into_iter()
        .map(contract)
        .collect::<Result<Vec<_>, _>>()?;
        manifest.output_contracts = [
            EXFILTRATION_FINDING_TYPE,
            "security.evidence",
            "security.risk_hint",
            "graph.hint.process_uploads_to_cloud",
        ]
        .into_iter()
        .map(contract)
        .collect::<Result<Vec<_>, _>>()?;
        manifest.required_permissions = vec![
            permission(
                "read.network.metadata",
                PermissionCategory::DataAccess,
                "Read metadata-only flow, session, and optional HTTP metadata.",
                &[
                    "network.flow.record",
                    "network.session.record",
                    "network.http.metadata",
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
                "Read offline local destination and cloud intelligence context.",
                &["intel.ip_context", "intel.cloud_context"],
            )?,
            permission(
                "read.security.finding",
                PermissionCategory::DataAccess,
                "Read C2 findings and graph hints as related metadata context only.",
                &["security.finding.c2", "graph.hint.suspicious_c2_relation"],
            )?,
        ];
        manifest.metrics_schema = vec![
            metric(
                "exfil_detection.events_in_total",
                MetricKind::Counter,
                "Exfiltration detection input records received",
            )?,
            metric(
                "exfil_detection.signals_out_total",
                MetricKind::Counter,
                "Exfiltration detection signals emitted",
            )?,
            metric(
                "exfil_detection.findings_out_total",
                MetricKind::Counter,
                "Exfiltration findings emitted",
            )?,
            metric(
                "exfil_detection.graph_hints_out_total",
                MetricKind::Counter,
                "Process upload graph hints emitted",
            )?,
            metric(
                "exfil_detection.latency_ms",
                MetricKind::Histogram,
                "Exfiltration detection processing latency",
            )?,
        ];
        manifest.finding_types = vec![EXFILTRATION_FINDING_TYPE.to_string()];
        manifest.graph_hint_types = vec![PROCESS_UPLOADS_TO_CLOUD_GRAPH_HINT.to_string()];
        manifest.ui_contributions = vec![
            ui_contribution(
                plugin_id.clone(),
                UiContributionSlot::InvestigationEvidencePanel,
                RendererType::EvidenceList,
                "Exfiltration Evidence",
                "security.evidence",
            )?,
            ui_contribution(
                plugin_id.clone(),
                UiContributionSlot::GraphProjection,
                RendererType::GraphProjection,
                "Process Upload Hints",
                "graph.hint.process_uploads_to_cloud",
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
        input: ExfiltrationDetectionInput,
    ) -> Result<ExfiltrationDetectionOutput, ExfiltrationDetectionError> {
        validate_input(&input)?;
        if input.flows.is_empty()
            && input.http_metadata.is_empty()
            && input.ip_contexts.is_empty()
            && input.cloud_contexts.is_empty()
            && input.related_c2_findings.is_empty()
            && input.related_c2_graph_hints.is_empty()
        {
            return Err(ExfiltrationDetectionError::EmptyInput);
        }

        let context = ExfiltrationDetectionContext::new(&input);
        let mut signals = Vec::new();
        signals.extend(
            self.upload_volume_spike
                .detect_with_context(&input, &context)?,
        );
        signals.extend(
            self.upload_ratio_anomaly
                .detect_with_context(&input, &context)?,
        );
        signals.extend(
            self.new_cloud_destination
                .detect_with_context(&input, &context)?,
        );
        signals.extend(
            self.risky_asn_upload
                .detect_with_context(&input, &context)?,
        );
        signals.extend(
            self.repeated_small_upload
                .detect_with_context(&input, &context)?,
        );
        signals.extend(self.off_hour_upload.detect_with_context(&input, &context)?);
        signals.extend(
            self.related_c2_signal
                .detect_with_context(&input, &context)?,
        );
        signals.extend(process_context_signals(&input, &context)?);
        let signals = merge_signals(signals);
        if signals.is_empty() {
            return Err(ExfiltrationDetectionError::NoSignals);
        }

        let evidence_build = self
            .evidence_builder
            .build(&input.producer_plugin, &signals)?;
        let risk_hints = risk_hints_for_context(&input, &context)?;
        let graph_hints = self.graph_hint_builder.build(
            &input.producer_plugin,
            &signals,
            &evidence_build.evidence_refs_by_signal,
        )?;

        let evidence_management = self.evidence_management.manage(EvidenceManagementInput {
            finding_type: EXFILTRATION_FINDING_TYPE.to_string(),
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

        Ok(ExfiltrationDetectionOutput {
            signals,
            findings: vec![evidence_management.finding.clone()],
            evidence: evidence_management.evidence.clone(),
            risk_hints,
            graph_hints,
            evidence_management,
        })
    }
}

fn process_context_signals(
    input: &ExfiltrationDetectionInput,
    context: &ExfiltrationDetectionContext<'_>,
) -> Result<Vec<ExfiltrationSignal>, ExfiltrationDetectionError> {
    let mut signals = Vec::new();
    for process in &input.process_contexts {
        if !process_has_suspicious_context(process) {
            continue;
        }
        let upload_flows = input
            .flows
            .iter()
            .filter(|flow| {
                is_upload_flow(flow)
                    && flow
                        .process_ref
                        .as_ref()
                        .is_some_and(|process_ref| process_ref == &process.process_context_id)
            })
            .collect::<Vec<_>>();
        if upload_flows.is_empty() {
            continue;
        }
        let representative = upload_flows[0];
        let destination = destination_for_flow(representative, input, context);
        let mut signal = ExfiltrationSignal::new(
            ExfiltrationSignalKind::ProcessContext,
            format!("process_context:{}", process.process_context_id),
            "Process trust metadata adds exfiltration risk context; metadata only, not content proof.",
            0.5,
            0.44,
        )?
        .with_flows(&upload_flows)
        .with_entities(entities_for_flow(
            representative,
            input,
            context,
            destination.as_ref(),
        )?);
        signal.process_ref = Some(process.process_context_id.clone());
        signal.destination = destination;
        signals.push(signal);
    }
    Ok(signals)
}

fn risk_hints_for_context(
    input: &ExfiltrationDetectionInput,
    context: &ExfiltrationDetectionContext<'_>,
) -> Result<Vec<RiskHint>, ExfiltrationDetectionError> {
    let mut hints = BTreeMap::<String, RiskHint>::new();
    for flow in input.flows.iter().filter(|flow| is_upload_flow(flow)) {
        if let Some(ip_context) = context.ip_context_for_flow(flow) {
            let entity = ip_entity(&ip_context.ip)?;
            collect_context_hints(&mut hints, &ip_context.risk_hints, Some(entity))?;
        }
        if let Some(cloud) = cloud_context_for_flow(flow, input, context) {
            let entity = cloud_entity(&cloud.provider_protected)?;
            collect_context_hints(&mut hints, &cloud.risk_hints, Some(entity))?;
        }
    }
    Ok(hints.into_values().collect())
}

fn collect_context_hints(
    hints: &mut BTreeMap<String, RiskHint>,
    source_hints: &[RiskHint],
    entity_ref: Option<EntityRef>,
) -> Result<(), ExfiltrationDetectionError> {
    for hint in source_hints {
        let mut hint = hint.clone();
        if hint.entity_ref.is_none() {
            hint.entity_ref = entity_ref.clone();
        }
        hint.validate_boundary()?;
        hints.insert(hint.risk_hint_id.to_string(), hint);
    }
    Ok(())
}

fn is_external_flow(flow: &FlowRecord) -> bool {
    matches!(flow.direction, NetworkDirection::Outbound)
        && !flow.dst_ip.as_ip_addr().is_loopback()
        && !matches!(
            flow.protocol,
            TransportProtocol::Icmp | TransportProtocol::Icmpv6
        )
}

fn is_upload_flow(flow: &FlowRecord) -> bool {
    is_external_flow(flow) && flow.bytes_out > flow.bytes_in && flow.bytes_out > 0
}

fn flow_ratio(flow: &FlowRecord) -> Option<f32> {
    if flow.bytes_out == 0 {
        return None;
    }
    if flow.bytes_in == 0 {
        return Some(flow.bytes_out as f32);
    }
    Some(flow.bytes_out as f32 / flow.bytes_in as f32)
}

fn aggregate_ratio(flows: &[&FlowRecord]) -> Option<f32> {
    let upload = flows.iter().map(|flow| flow.bytes_out).sum::<u64>();
    let download = flows.iter().map(|flow| flow.bytes_in).sum::<u64>();
    if upload == 0 {
        None
    } else if download == 0 {
        Some(upload as f32)
    } else {
        Some(upload as f32 / download as f32)
    }
}

fn destination_for_flow(
    flow: &FlowRecord,
    input: &ExfiltrationDetectionInput,
    context: &ExfiltrationDetectionContext<'_>,
) -> Option<ExfiltrationDestination> {
    cloud_context_for_flow(flow, input, context)
        .map(|cloud| ExfiltrationDestination::CloudProvider(cloud.provider_protected.clone()))
        .or(Some(ExfiltrationDestination::Ip(flow.dst_ip)))
}

fn cloud_context_for_flow<'input>(
    flow: &FlowRecord,
    input: &'input ExfiltrationDetectionInput,
    context: &ExfiltrationDetectionContext<'_>,
) -> Option<&'input CloudContext> {
    if let Some(provider) = context
        .ip_context_for_flow(flow)
        .and_then(|context| context.cloud_provider_protected.as_ref())
    {
        if let Some(cloud) = input
            .cloud_contexts
            .iter()
            .find(|cloud| normalize(&cloud.provider_protected) == normalize(provider))
        {
            return Some(cloud);
        }
    }
    input
        .cloud_contexts
        .iter()
        .find(|cloud| ip_matches_cloud_range(&flow.dst_ip, &cloud.range_protected))
}

fn ip_matches_cloud_range(ip: &IpAddress, range: &str) -> bool {
    let ip_text = ip.to_string();
    if let Some(prefix) = range.strip_suffix(".0/24") {
        return ip_text.starts_with(&format!("{prefix}."));
    }
    if let Some(prefix) = range.strip_suffix("/24") {
        let mut parts = prefix.split('.').collect::<Vec<_>>();
        if parts.len() == 4 {
            parts.pop();
            return ip_text.starts_with(&format!("{}.", parts.join(".")));
        }
    }
    ip_text == range
}

fn entities_for_flow(
    flow: &FlowRecord,
    input: &ExfiltrationDetectionInput,
    context: &ExfiltrationDetectionContext<'_>,
    destination: Option<&ExfiltrationDestination>,
) -> Result<Vec<EntityRef>, ExfiltrationDetectionError> {
    let mut entities = Vec::new();
    if let Some(process_ref) = &flow.process_ref {
        entities.push(process_entity(process_ref, context.process(process_ref))?);
    }
    if let Some(destination) = destination {
        entities.push(destination_entity(destination)?);
    } else {
        entities.push(ip_entity(&flow.dst_ip)?);
    }
    if let Some(ip_context) = context
        .ip_context_for_flow(flow)
        .and_then(|context| context.asn)
    {
        entities.push(asn_entity(ip_context)?);
    }
    if let Some(cloud) = cloud_context_for_flow(flow, input, context) {
        entities.push(cloud_entity(&cloud.provider_protected)?);
    }
    Ok(entities)
}

fn destination_entity(
    destination: &ExfiltrationDestination,
) -> Result<EntityRef, ExfiltrationDetectionError> {
    match destination {
        ExfiltrationDestination::Ip(ip) => ip_entity(ip),
        ExfiltrationDestination::CloudProvider(provider) => cloud_entity(provider),
        ExfiltrationDestination::CloudRange(range) => cloud_range_entity(range),
        ExfiltrationDestination::Process(process) => process_name_entity(process),
    }
}

fn process_entity(
    process_ref: &ProcessContextId,
    process: Option<&ProcessContext>,
) -> Result<EntityRef, ExfiltrationDetectionError> {
    let mut entity = EntityRef::new(
        EntityId::from_uuid(process_ref.as_uuid()),
        EntityType::Process,
    );
    entity.entity_name = process.map(|process| process.process_name.clone());
    entity.namespace = Some("identity.process_context".to_string());
    entity.source = Some("exfiltration_detection".to_string());
    entity.confidence = quality_score(0.75)?;
    Ok(entity)
}

fn process_name_entity(process_name: &str) -> Result<EntityRef, ExfiltrationDetectionError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Process);
    entity.entity_name = Some(require_safe_text("process_name", process_name.to_string())?);
    entity.namespace = Some("identity.process_name".to_string());
    entity.source = Some("exfiltration_detection".to_string());
    entity.confidence = quality_score(0.45)?;
    Ok(entity)
}

fn ip_entity(ip: &IpAddress) -> Result<EntityRef, ExfiltrationDetectionError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Ip);
    entity.entity_name = Some(ip.to_string());
    entity.namespace = Some("network.ip".to_string());
    entity.source = Some("exfiltration_detection".to_string());
    entity.confidence = quality_score(0.72)?;
    Ok(entity)
}

fn asn_entity(asn: u32) -> Result<EntityRef, ExfiltrationDetectionError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Asn);
    entity.entity_name = Some(format!("asn:{asn}"));
    entity.namespace = Some("network.asn".to_string());
    entity.source = Some("exfiltration_detection".to_string());
    entity.confidence = quality_score(0.65)?;
    Ok(entity)
}

fn cloud_entity(provider: &str) -> Result<EntityRef, ExfiltrationDetectionError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::CloudResource);
    entity.entity_name = Some(require_safe_text("cloud_provider", provider.to_string())?);
    entity.namespace = Some("cloud.provider".to_string());
    entity.source = Some("exfiltration_detection".to_string());
    entity.confidence = quality_score(0.65)?;
    Ok(entity)
}

fn cloud_range_entity(range: &str) -> Result<EntityRef, ExfiltrationDetectionError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::CloudResource);
    entity.entity_name = Some(require_safe_text("cloud_range", range.to_string())?);
    entity.namespace = Some("cloud.range".to_string());
    entity.source = Some("exfiltration_detection".to_string());
    entity.confidence = quality_score(0.6)?;
    Ok(entity)
}

fn entity_refs_for_finding(signals: &[ExfiltrationSignal]) -> Vec<EntityRef> {
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

fn merge_signals(signals: Vec<ExfiltrationSignal>) -> Vec<ExfiltrationSignal> {
    let mut merged = BTreeMap::<String, ExfiltrationSignal>::new();
    for signal in signals {
        if let Some(existing) = merged.get_mut(&signal.signal_key) {
            existing.confidence = max_quality(&existing.confidence, &signal.confidence);
            existing.weight = max_quality(&existing.weight, &signal.weight);
            existing.upload_bytes = existing.upload_bytes.max(signal.upload_bytes);
            existing.upload_download_ratio =
                max_optional_ratio(existing.upload_download_ratio, signal.upload_download_ratio);
            merge_by_string(&mut existing.flow_refs, signal.flow_refs);
            merge_by_string(&mut existing.http_refs, signal.http_refs);
            merge_by_string(
                &mut existing.related_finding_refs,
                signal.related_finding_refs,
            );
            merge_by_string(
                &mut existing.related_graph_hint_refs,
                signal.related_graph_hint_refs,
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

fn max_optional_ratio(left: Option<f32>, right: Option<f32>) -> Option<f32> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
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

fn known_cloud_destination_matches(
    context: &ExfiltrationDetectionContext<'_>,
    process_name: &str,
    provider: &str,
    dst_ip: &IpAddress,
) -> bool {
    context
        .known_cloud_destinations_by_process
        .iter()
        .any(|destination| {
            normalize(&destination.process_name) == normalize(process_name)
                && normalize(&destination.provider_protected) == normalize(provider)
                && cloud_destination_matches_ip(&destination.destination_protected, dst_ip)
        })
}

fn cloud_destination_matches_ip(destination: &str, dst_ip: &IpAddress) -> bool {
    let destination = normalize_destination(destination);
    destination == dst_ip.to_string() || ip_matches_cloud_range(dst_ip, &destination)
}

fn normalize_destination(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("ip:")
        .trim_start_matches("cloud:")
        .trim_start_matches("cloud_range:")
        .to_ascii_lowercase()
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn hour_utc(timestamp: &Timestamp) -> Option<u8> {
    timestamp
        .as_datetime()
        .format("%H")
        .to_string()
        .parse()
        .ok()
}

fn validate_input(input: &ExfiltrationDetectionInput) -> Result<(), ExfiltrationDetectionError> {
    for baseline in &input.baseline.process_uploads {
        validate_safe_text("process_baseline_name", &baseline.process_name)?;
    }
    for destination in &input.baseline.known_cloud_destinations_by_process {
        validate_safe_text("known_process", &destination.process_name)?;
        validate_safe_text("known_cloud_provider", &destination.provider_protected)?;
        validate_safe_text(
            "known_cloud_destination",
            &destination.destination_protected,
        )?;
    }
    for hour in &input.baseline.normal_upload_hours_utc {
        if *hour > 23 {
            return Err(ExfiltrationDetectionError::Contract(
                "normal upload hour must be 0..23".to_string(),
            ));
        }
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
    for metadata in &input.http_metadata {
        if let Some(host) = &metadata.host_protected {
            validate_safe_text("host_protected", host)?;
        }
        if let Some(path) = &metadata.path_template_protected {
            validate_safe_text("path_template_protected", path)?;
        }
        if let Some(content_type) = &metadata.content_type {
            validate_safe_text("content_type", content_type)?;
        }
        if let Some(user_agent) = &metadata.user_agent_family {
            validate_safe_text("user_agent_family", user_agent)?;
        }
    }
    for context in &input.cloud_contexts {
        validate_safe_text("cloud_range", &context.range_protected)?;
        validate_safe_text("cloud_provider", &context.provider_protected)?;
        if let Some(service) = &context.service_protected {
            validate_safe_text("cloud_service", service)?;
        }
        if let Some(region) = &context.region_protected {
            validate_safe_text("cloud_region", region)?;
        }
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), ExfiltrationDetectionError> {
    if value.trim().is_empty() {
        return Err(ExfiltrationDetectionError::EmptyField(field));
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
        return Err(ExfiltrationDetectionError::PrivacyMarker { field });
    }
    Ok(())
}

fn require_safe_text(
    field: &'static str,
    value: String,
) -> Result<String, ExfiltrationDetectionError> {
    validate_safe_text(field, &value)?;
    Ok(value)
}

fn quality_score(value: f32) -> Result<QualityScore, ExfiltrationDetectionError> {
    QualityScore::new(value).map_err(|_| ExfiltrationDetectionError::InvalidQualityScore)
}

fn contract(name: &str) -> Result<ContractDescriptor, ManifestValidationError> {
    ContractDescriptor::new(name, EXFILTRATION_DETECTION_SCHEMA_VERSION)
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
        "schema_version": EXFILTRATION_DETECTION_SCHEMA_VERSION,
        "metadata_only": true
    });
    Ok(contribution)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use sentinel_contracts::{
        AttributionConfidence, CollectionMode, FindingExplanation, HttpMethod, IndicatorType,
        IntelligenceExportPolicy, IntelligenceLicenseClass, IntelligenceLookupStatus,
        IntelligenceRecord, IntelligenceSource, IntelligenceSourceClass, NetworkDirection,
        PrivacyClass, SecuritySeverity, SignerStatus, VisibilityLevel,
    };

    fn ip(value: &str) -> IpAddress {
        IpAddress::parse_str(value).expect("test IP")
    }

    fn q(value: f32) -> QualityScore {
        QualityScore::new(value).expect("quality")
    }

    fn process() -> ProcessContext {
        let mut process = ProcessContext::new(6_260, "fixture_uploader");
        process.signer_status = SignerStatus::Unsigned;
        process.visibility_level = VisibilityLevel::MetadataOnly;
        process.collection_mode = CollectionMode::Mock;
        process
    }

    fn flow(
        process: &ProcessContext,
        offset_hours: i64,
        src_port: u16,
        bytes_out: u64,
        bytes_in: u64,
    ) -> FlowRecord {
        let start = Utc::now()
            .date_naive()
            .and_hms_opt(2, 0, 0)
            .expect("fixture time")
            .and_utc()
            + Duration::hours(offset_hours);
        let mut flow = FlowRecord::new(
            ip("192.0.2.10"),
            src_port,
            ip("203.0.113.10"),
            443,
            TransportProtocol::Tcp,
            NetworkDirection::Outbound,
        );
        flow.start_time = Timestamp::from_datetime(start);
        flow.end_time = Some(Timestamp::from_datetime(start + Duration::seconds(4)));
        flow.duration_millis = Some(4_000);
        flow.bytes_out = bytes_out;
        flow.bytes_in = bytes_in;
        flow.packets_out = 8;
        flow.packets_in = 3;
        flow.process_ref = Some(process.process_context_id.clone());
        flow.attribution_confidence = AttributionConfidence::Medium;
        flow.quality_score = q(0.9);
        flow
    }

    fn http_metadata(flow: &FlowRecord, process: &ProcessContext) -> HttpMetadata {
        let mut metadata = HttpMetadata::new(HttpMethod::Post);
        metadata.flow_ref = Some(flow.flow_id.clone());
        metadata.timestamp = flow.start_time.clone();
        metadata.host_protected = Some("storage.example.test".to_string());
        metadata.path_template_protected = Some("/upload/{id}".to_string());
        metadata.request_size_bytes = Some(flow.bytes_out);
        metadata.response_size_bytes = Some(flow.bytes_in);
        metadata.upload_download_ratio = Some(8.0);
        metadata.content_type = Some("application/octet-stream".to_string());
        metadata.user_agent_family = Some("fixture-client".to_string());
        metadata.process_ref = Some(process.process_context_id.clone());
        metadata.privacy_class = PrivacyClass::Internal;
        metadata.quality_score = q(0.82);
        metadata
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
        .with_expires_at(Timestamp::from_datetime(Utc::now() + Duration::days(30)))
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

    fn ip_context() -> IpContext {
        let record = record(IndicatorType::Asn, "64512", 0.66);
        IpContext {
            ip: ip("203.0.113.10"),
            asn: Some(64_512),
            asn_name_protected: Some("fixture documentation ASN".to_string()),
            cloud_provider_protected: Some("fixture-cloud".to_string()),
            risky_asn: true,
            allowlisted: false,
            blocklisted: false,
            user_ioc_match: false,
            lookup_status: IntelligenceLookupStatus::Hit,
            records: vec![record.clone()],
            risk_hints: vec![risk_hint("asn_risk_context", 0.45, 0.66, &record)],
            confidence: q(0.66),
            retrieved_at: Timestamp::now(),
            expires_at: None,
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn cloud_context() -> CloudContext {
        let record = record(IndicatorType::CloudRange, "203.0.113.0/24", 0.66);
        CloudContext {
            range_protected: "203.0.113.0/24".to_string(),
            provider_protected: "fixture-cloud".to_string(),
            service_protected: Some("object-storage-fixture".to_string()),
            region_protected: Some("local-fixture-region".to_string()),
            object_storage_hint: true,
            lookup_status: IntelligenceLookupStatus::Hit,
            records: vec![record.clone()],
            risk_hints: vec![risk_hint("cloud_range_context", 0.35, 0.66, &record)],
            confidence: q(0.66),
            retrieved_at: Timestamp::now(),
            expires_at: None,
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn related_c2_finding(process: &ProcessContext) -> Finding {
        let explanation = FindingExplanation::new("C2 fixture finding").expect("explanation");
        Finding::new(
            "security.finding.c2",
            PluginId::new_v4(),
            vec![EvidenceId::new_v4()],
            explanation,
        )
        .expect("finding")
        .with_entity_refs(vec![process_entity(
            &process.process_context_id,
            Some(process),
        )
        .expect("entity")])
        .with_confidence(q(0.72))
        .with_severity(SecuritySeverity::Medium)
    }

    fn fixture_input() -> ExfiltrationDetectionInput {
        let process = process();
        let large = flow(&process, 0, 52_000, 80_000, 5_000);
        let small_a = flow(&process, 1, 52_001, 1_024, 100);
        let small_b = flow(&process, 2, 52_002, 1_100, 120);
        let small_c = flow(&process, 3, 52_003, 1_200, 110);
        let mut input = ExfiltrationDetectionInput::new(PluginId::new_v4());
        input.http_metadata = vec![http_metadata(&large, &process)];
        input.related_c2_findings = vec![related_c2_finding(&process)];
        input.process_contexts = vec![process];
        input.flows = vec![large, small_a, small_b, small_c];
        input.ip_contexts = vec![ip_context()];
        input.cloud_contexts = vec![cloud_context()];
        input.baseline = ExfiltrationDetectionBaseline {
            process_uploads: vec![ProcessUploadBaseline::new(
                "fixture_uploader",
                10_000,
                1.2,
                1,
            )],
            known_cloud_destinations_by_process: vec![KnownProcessCloudDestination::new(
                "fixture_uploader",
                "fixture-cloud",
                "203.0.113.88",
            )],
            normal_upload_hours_utc: vec![8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
        };
        input.labels = vec!["task_410_fixture".to_string()];
        input
    }

    #[test]
    fn exfil_detection_emits_evidence_backed_finding_for_fixture_story() {
        let output = ExfiltrationDetectionPlugin::new()
            .detect(fixture_input())
            .expect("exfil output");

        assert_eq!(output.findings.len(), 1);
        assert_eq!(output.findings[0].finding_type(), EXFILTRATION_FINDING_TYPE);
        assert!(!output.findings[0].evidence_refs().is_empty());
        assert!(output.evidence_management.quality_report.passed);

        let evidence_types = output
            .evidence
            .iter()
            .map(|item| item.evidence.evidence_type.as_str())
            .collect::<HashSet<_>>();
        for required in [
            "exfil.network.upload_volume_spike",
            "exfil.network.upload_ratio_anomaly",
            "exfil.cloud.new_destination",
            "exfil.network.risky_asn_upload",
            "exfil.network.repeated_small_upload",
            "exfil.network.off_hour_upload",
            "exfil.process.context",
            "exfil.c2.related_signal",
        ] {
            assert!(evidence_types.contains(required), "missing {required}");
        }

        let explanation =
            serde_json::to_string(output.findings[0].explanation()).expect("explanation json");
        assert!(explanation.contains("Metadata-only"));
        assert!(explanation.contains("not content proof") || explanation.contains("not inspected"));
        assert!(!output.risk_hints.is_empty());
        assert!(output.risk_hints.iter().all(|hint| {
            hint.evidence_input_only
                && !hint.creates_alert
                && !hint.creates_incident
                && !hint.executes_response
                && hint.validate_boundary().is_ok()
        }));
        assert!(output
            .graph_hints
            .iter()
            .any(|hint| hint.hint_type == GraphHintType::ProcessUploadsToCloud));
    }

    #[test]
    fn known_cloud_range_baseline_suppresses_new_cloud_destination_signal() {
        let mut input = fixture_input();
        input.baseline.known_cloud_destinations_by_process =
            vec![KnownProcessCloudDestination::new(
                "fixture_uploader",
                "fixture-cloud",
                "203.0.113.0/24",
            )];

        let signals = NewCloudDestinationDetector::new()
            .detect(&input)
            .expect("new cloud destination detection");

        assert!(signals
            .iter()
            .all(|signal| signal.kind != ExfiltrationSignalKind::NewCloudDestination));
    }

    #[test]
    fn related_c2_joiner_uses_contract_findings_without_alerting() {
        let process = process();
        let upload = flow(&process, 0, 52_000, 8_000, 500);
        let mut input = ExfiltrationDetectionInput::new(PluginId::new_v4());
        input.process_contexts = vec![process.clone()];
        input.flows = vec![upload];
        input.related_c2_findings = vec![related_c2_finding(&process)];

        let output = ExfiltrationDetectionPlugin::new()
            .detect(input)
            .expect("joined output");
        assert!(output
            .signals
            .iter()
            .any(|signal| signal.kind == ExfiltrationSignalKind::RelatedC2Signal));
        let serialized = serde_json::to_value(&output).expect("serialize output");
        assert!(serialized.get("alerts").is_none());
        assert!(serialized.get("incidents").is_none());
    }

    #[test]
    fn graph_hints_are_process_uploads_without_canonical_graph_writes() {
        let output = ExfiltrationDetectionPlugin::new()
            .detect(fixture_input())
            .expect("exfil output");

        assert!(!output.graph_hints.is_empty());
        assert!(output
            .graph_hints
            .iter()
            .all(|hint| hint.hint_type == GraphHintType::ProcessUploadsToCloud));
        let serialized = serde_json::to_string(&output).expect("serialize output");
        assert!(!serialized.contains("canonical_graph"));
        assert!(!serialized.contains("graph.update"));
        assert!(!serialized.contains("graph_update"));
    }

    #[test]
    fn plugin_manifest_declares_contracts_permissions_metrics_and_ui() {
        let manifest = ExfiltrationDetectionPlugin::manifest().expect("manifest");
        manifest.validate().expect("valid manifest");

        let input_contracts = manifest
            .input_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<HashSet<_>>();
        for required in [
            "network.flow.record",
            "network.session.record",
            "network.http.metadata",
            "identity.process_context",
            "intel.ip_context",
            "intel.cloud_context",
            "security.finding.c2",
        ] {
            assert!(input_contracts.contains(required), "missing {required}");
        }

        let output_contracts = manifest
            .output_contracts
            .iter()
            .map(|contract| contract.contract_name.as_str())
            .collect::<HashSet<_>>();
        assert!(output_contracts.contains(EXFILTRATION_FINDING_TYPE));
        assert!(output_contracts.contains("security.evidence"));
        assert!(output_contracts.contains("security.risk_hint"));
        assert!(output_contracts.contains("graph.hint.process_uploads_to_cloud"));
        assert_eq!(manifest.plugin_type, PluginType::Detection);
        assert_eq!(
            manifest.finding_types,
            vec![EXFILTRATION_FINDING_TYPE.to_string()]
        );
        assert_eq!(
            manifest.graph_hint_types,
            vec![PROCESS_UPLOADS_TO_CLOUD_GRAPH_HINT.to_string()]
        );
        assert!(!manifest.metrics_schema.is_empty());
        assert!(!manifest.ui_contributions.is_empty());
        assert!(manifest.required_permissions.iter().all(|permission| {
            permission.category == PermissionCategory::DataAccess
                && permission.risk_level == PermissionRiskLevel::Low
                && !permission.permission.as_str().contains("response")
        }));
    }

    #[test]
    fn sensitive_metadata_marker_is_rejected() {
        let process = process();
        let upload = flow(&process, 0, 52_000, 8_000, 500);
        let mut metadata = http_metadata(&upload, &process);
        metadata.host_protected = Some("api_key.example.test".to_string());
        let mut input = ExfiltrationDetectionInput::new(PluginId::new_v4());
        input.process_contexts = vec![process];
        input.flows = vec![upload];
        input.http_metadata = vec![metadata];

        let error = ExfiltrationDetectionPlugin::new()
            .detect(input)
            .expect_err("privacy marker rejected");
        assert!(matches!(
            error,
            ExfiltrationDetectionError::PrivacyMarker {
                field: "host_protected"
            }
        ));
    }
}
