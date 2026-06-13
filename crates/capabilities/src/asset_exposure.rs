use sentinel_contracts::{
    AssetIdentity, AssetIdentityId, AttributionConfidence, AttributionMethod, AttributionStatus,
    CollectionMode, EntityId, EntityRef, EntityType, EventId, EvidenceItem, Finding,
    FindingExplanation, GraphEdgeType, GraphHint, GraphHintType, IpAddress, ListeningEndpoint,
    PluginId, PrivacyClass, ProcessContext, ProcessContextId, QualityScore, RiskReason,
    SchemaVersion, SecurityContractError, SecurityObservation, Timestamp, TransportProtocol,
    VisibilityLevel,
};
use sentinel_storage::{LogicalRecord, LogicalStore, SqliteStoreFactory, StorageError, StoreKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;

pub const ASSET_EXPOSURE_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const PROCESS_LISTENS_ON_PORT_HINT: &str = "process_listens_on_port";

#[derive(Debug)]
pub enum AssetExposureError {
    EmptyField(&'static str),
    MissingListeningPorts,
    InvalidPort,
    PrivacyMarker { field: &'static str },
    InvalidQualityScore,
    Contract(String),
    Storage(StorageError),
    Serialization(serde_json::Error),
}

impl fmt::Display for AssetExposureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::MissingListeningPorts => {
                write!(f, "service inventory requires at least one listening port")
            }
            Self::InvalidPort => write!(f, "listening port must be non-zero"),
            Self::PrivacyMarker { field } => {
                write!(f, "{field} contains a forbidden private-content marker")
            }
            Self::InvalidQualityScore => write!(f, "quality score is outside valid range"),
            Self::Contract(error) => write!(f, "asset exposure contract error: {error}"),
            Self::Storage(error) => write!(f, "asset exposure storage error: {error}"),
            Self::Serialization(error) => {
                write!(f, "asset exposure serialization error: {error}")
            }
        }
    }
}

impl std::error::Error for AssetExposureError {}

impl From<SecurityContractError> for AssetExposureError {
    fn from(value: SecurityContractError) -> Self {
        Self::Contract(value.to_string())
    }
}

impl From<StorageError> for AssetExposureError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

impl From<serde_json::Error> for AssetExposureError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventorySource {
    MockEndpointSnapshot,
    WindowsEndpointSnapshot,
    ManualImport,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    WindowsService,
    UserProcess,
    SystemProcess,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindScope {
    Loopback,
    LocalOnly,
    Lan,
    Public,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceExposureLevel {
    LoopbackOnly,
    LocalOnly,
    LocalNetwork,
    Public,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetRiskKind {
    NewListeningPort,
    RiskyPortExposed,
    UnknownProcessListener,
    PublicServiceHint,
}

impl AssetRiskKind {
    pub fn finding_type(&self) -> &'static str {
        match self {
            Self::NewListeningPort => "asset_risk.new_listening_port",
            Self::RiskyPortExposed => "asset_risk.risky_port_exposed",
            Self::UnknownProcessListener => "asset_risk.unknown_process_listener",
            Self::PublicServiceHint => "asset_risk.public_service_hint",
        }
    }

    fn reason_type(&self) -> &'static str {
        match self {
            Self::NewListeningPort => "new_listening_port",
            Self::RiskyPortExposed => "risky_port_exposed",
            Self::UnknownProcessListener => "unknown_process_listener",
            Self::PublicServiceHint => "public_service_hint",
        }
    }

    fn summary(&self, port: &PortExposureRecord) -> String {
        match self {
            Self::NewListeningPort => format!(
                "New {} listener observed on local port {}.",
                protocol_label(&port.protocol),
                port.local_port
            ),
            Self::RiskyPortExposed => format!(
                "Risk-sensitive {} port {} is reachable at {} scope.",
                protocol_label(&port.protocol),
                port.local_port,
                exposure_label(&port.exposure_level)
            ),
            Self::UnknownProcessListener => format!(
                "Local port {} is listening without high-confidence process attribution.",
                port.local_port
            ),
            Self::PublicServiceHint => format!(
                "Local port {} appears exposed beyond the loopback or local-only boundary.",
                port.local_port
            ),
        }
    }

    fn evidence_weight(&self) -> Result<QualityScore, AssetExposureError> {
        match self {
            Self::NewListeningPort => quality_score(0.55),
            Self::RiskyPortExposed => quality_score(0.75),
            Self::UnknownProcessListener => quality_score(0.65),
            Self::PublicServiceHint => quality_score(0.7),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ListeningPortInput {
    pub local_ip: IpAddress,
    pub local_port: u16,
    pub protocol: TransportProtocol,
    pub bind_scope: BindScope,
    pub process_context: Option<ProcessContext>,
    pub attribution_confidence: AttributionConfidence,
    pub service_name_protected: Option<String>,
    pub service_display_name_protected: Option<String>,
    pub service_kind: ServiceKind,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub seen_before: bool,
    pub source: InventorySource,
    pub known_limitations: Vec<String>,
}

impl ListeningPortInput {
    pub fn new(
        local_ip: IpAddress,
        local_port: u16,
        protocol: TransportProtocol,
        bind_scope: BindScope,
    ) -> Self {
        let now = Timestamp::now();
        Self {
            local_ip,
            local_port,
            protocol,
            bind_scope,
            process_context: None,
            attribution_confidence: AttributionConfidence::Unknown,
            service_name_protected: None,
            service_display_name_protected: None,
            service_kind: ServiceKind::Unknown,
            first_seen: now.clone(),
            last_seen: now,
            seen_before: false,
            source: InventorySource::Unknown,
            known_limitations: Vec::new(),
        }
    }

    pub fn with_process_context(
        mut self,
        process_context: ProcessContext,
        confidence: AttributionConfidence,
    ) -> Self {
        self.process_context = Some(process_context);
        self.attribution_confidence = confidence;
        self
    }

    pub fn with_service(
        mut self,
        service_name_protected: impl Into<String>,
        service_display_name_protected: impl Into<String>,
        service_kind: ServiceKind,
    ) -> Self {
        self.service_name_protected = Some(service_name_protected.into());
        self.service_display_name_protected = Some(service_display_name_protected.into());
        self.service_kind = service_kind;
        self
    }

    pub fn with_seen_before(mut self, seen_before: bool) -> Self {
        self.seen_before = seen_before;
        self
    }

    pub fn with_source(mut self, source: InventorySource) -> Self {
        self.source = source;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceInventoryInput {
    pub asset_hostname_protected: Option<String>,
    pub asset_ip: Option<IpAddress>,
    pub asset_entity: Option<EntityRef>,
    pub host_identity_ref: Option<sentinel_contracts::HostIdentityId>,
    pub visibility_level: VisibilityLevel,
    pub collection_mode: CollectionMode,
    pub listening_ports: Vec<ListeningPortInput>,
    pub labels: Vec<String>,
}

impl ServiceInventoryInput {
    pub fn new(listening_ports: Vec<ListeningPortInput>) -> Self {
        Self {
            asset_hostname_protected: None,
            asset_ip: None,
            asset_entity: None,
            host_identity_ref: None,
            visibility_level: VisibilityLevel::MetadataOnly,
            collection_mode: CollectionMode::Normal,
            listening_ports,
            labels: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetRecord {
    pub asset_identity: AssetIdentity,
    pub hostname_protected: Option<String>,
    pub asset_ip: Option<IpAddress>,
    pub service_record_refs: Vec<String>,
    pub port_exposure_record_refs: Vec<String>,
    pub labels: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub service_record_id: String,
    pub logical_record_id: AssetIdentityId,
    pub asset_identity_ref: AssetIdentityId,
    pub service_entity: EntityRef,
    pub process_entity: Option<EntityRef>,
    pub process_ref: Option<ProcessContextId>,
    pub os_process_id: Option<u32>,
    pub process_name_protected: Option<String>,
    pub process_hash: Option<String>,
    pub service_name_protected: Option<String>,
    pub service_display_name_protected: Option<String>,
    pub service_kind: ServiceKind,
    pub listening_port_refs: Vec<String>,
    pub attribution_status: AttributionStatus,
    pub attribution_method: AttributionMethod,
    pub attribution_confidence: AttributionConfidence,
    pub visibility_level: VisibilityLevel,
    pub collection_mode: CollectionMode,
    pub known_limitations: Vec<String>,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortExposureRecord {
    pub port_exposure_record_id: String,
    pub logical_record_id: AssetIdentityId,
    pub asset_identity_ref: AssetIdentityId,
    pub service_record_ref: Option<String>,
    pub port_entity: EntityRef,
    pub process_entity: Option<EntityRef>,
    pub local_ip: IpAddress,
    pub local_port: u16,
    pub protocol: TransportProtocol,
    pub bind_scope: BindScope,
    pub exposure_level: ServiceExposureLevel,
    pub process_ref: Option<ProcessContextId>,
    pub attribution_status: AttributionStatus,
    pub attribution_method: AttributionMethod,
    pub attribution_confidence: AttributionConfidence,
    pub visibility_level: VisibilityLevel,
    pub collection_mode: CollectionMode,
    pub source: InventorySource,
    pub seen_before: bool,
    pub known_limitations: Vec<String>,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
}

impl PortExposureRecord {
    fn entity_refs(&self, asset: &AssetRecord) -> Vec<EntityRef> {
        let mut refs = Vec::new();
        if let Some(asset_ref) = &asset.asset_identity.asset_ref {
            refs.push(asset_ref.clone());
        }
        refs.push(self.port_entity.clone());
        if let Some(process_entity) = &self.process_entity {
            refs.push(process_entity.clone());
        }
        refs
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceInventoryOutput {
    pub assets: Vec<AssetRecord>,
    pub services: Vec<ServiceRecord>,
    pub port_exposures: Vec<PortExposureRecord>,
}

#[derive(Clone, Debug, Default)]
pub struct ServiceInventoryPlugin;

impl ServiceInventoryPlugin {
    pub fn new() -> Self {
        Self
    }

    pub fn inventory(
        &self,
        input: ServiceInventoryInput,
    ) -> Result<ServiceInventoryOutput, AssetExposureError> {
        validate_inventory_input(&input)?;

        let asset_entity = input
            .asset_entity
            .clone()
            .unwrap_or_else(|| asset_entity_ref(input.asset_hostname_protected.as_deref()));
        let mut asset_identity = AssetIdentity::new();
        asset_identity.asset_ref = Some(asset_entity);
        asset_identity.host_identity_ref = input.host_identity_ref.clone();
        asset_identity.visibility_level = input.visibility_level.clone();
        asset_identity.collection_mode = input.collection_mode.clone();

        let mut services = Vec::new();
        let mut port_exposures = Vec::new();

        for listening in &input.listening_ports {
            let process_ref = listening
                .process_context
                .as_ref()
                .map(|process| process.process_context_id.clone());
            let process_entity = listening
                .process_context
                .as_ref()
                .map(process_entity_ref)
                .transpose()?;
            let service_record_id = synthetic_record_id("service");
            let port_exposure_record_id = synthetic_record_id("port_exposure");
            let service_entity = service_entity_ref(listening, process_entity.as_ref())?;
            let port_entity = port_entity_ref(listening)?;
            let attribution_method = attribution_method_for(&listening.protocol);
            let attribution_status = attribution_status_for(&listening.attribution_confidence);
            let known_limitations = known_limitations_for(listening);

            asset_identity.listening_endpoints.push(ListeningEndpoint {
                listening_ip: listening.local_ip,
                listening_port: listening.local_port,
                protocol: protocol_label(&listening.protocol).to_string(),
                process_ref: process_ref.clone(),
            });

            services.push(ServiceRecord {
                service_record_id: service_record_id.clone(),
                logical_record_id: AssetIdentityId::new_v4(),
                asset_identity_ref: asset_identity.asset_identity_id.clone(),
                service_entity,
                process_entity: process_entity.clone(),
                process_ref: process_ref.clone(),
                os_process_id: listening
                    .process_context
                    .as_ref()
                    .map(|process| process.os_process_id),
                process_name_protected: listening
                    .process_context
                    .as_ref()
                    .map(|process| process.process_name.clone()),
                process_hash: listening
                    .process_context
                    .as_ref()
                    .and_then(|process| process.process_hash.clone()),
                service_name_protected: listening.service_name_protected.clone(),
                service_display_name_protected: listening.service_display_name_protected.clone(),
                service_kind: listening.service_kind.clone(),
                listening_port_refs: vec![port_exposure_record_id.clone()],
                attribution_status: attribution_status.clone(),
                attribution_method: attribution_method.clone(),
                attribution_confidence: listening.attribution_confidence.clone(),
                visibility_level: listening
                    .process_context
                    .as_ref()
                    .map(|process| process.visibility_level.clone())
                    .unwrap_or_else(|| input.visibility_level.clone()),
                collection_mode: listening
                    .process_context
                    .as_ref()
                    .map(|process| process.collection_mode.clone())
                    .unwrap_or_else(|| input.collection_mode.clone()),
                known_limitations: known_limitations.clone(),
                first_seen: listening.first_seen.clone(),
                last_seen: listening.last_seen.clone(),
            });

            port_exposures.push(PortExposureRecord {
                port_exposure_record_id,
                logical_record_id: AssetIdentityId::new_v4(),
                asset_identity_ref: asset_identity.asset_identity_id.clone(),
                service_record_ref: Some(service_record_id),
                port_entity,
                process_entity,
                local_ip: listening.local_ip,
                local_port: listening.local_port,
                protocol: listening.protocol.clone(),
                bind_scope: listening.bind_scope.clone(),
                exposure_level: exposure_level_for(&listening.bind_scope),
                process_ref,
                attribution_status,
                attribution_method,
                attribution_confidence: listening.attribution_confidence.clone(),
                visibility_level: listening
                    .process_context
                    .as_ref()
                    .map(|process| process.visibility_level.clone())
                    .unwrap_or_else(|| input.visibility_level.clone()),
                collection_mode: listening
                    .process_context
                    .as_ref()
                    .map(|process| process.collection_mode.clone())
                    .unwrap_or_else(|| input.collection_mode.clone()),
                source: listening.source.clone(),
                seen_before: listening.seen_before,
                known_limitations,
                first_seen: listening.first_seen.clone(),
                last_seen: listening.last_seen.clone(),
            });
        }

        let asset = AssetRecord {
            asset_identity,
            hostname_protected: input.asset_hostname_protected,
            asset_ip: input.asset_ip,
            service_record_refs: services
                .iter()
                .map(|service| service.service_record_id.clone())
                .collect(),
            port_exposure_record_refs: port_exposures
                .iter()
                .map(|port| port.port_exposure_record_id.clone())
                .collect(),
            labels: input.labels,
        };

        Ok(ServiceInventoryOutput {
            assets: vec![asset],
            services,
            port_exposures,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetExposureInput {
    pub asset: AssetRecord,
    pub services: Vec<ServiceRecord>,
    pub port_exposures: Vec<PortExposureRecord>,
    pub producer_plugin: PluginId,
    pub source_event_refs: Vec<EventId>,
    pub labels: Vec<String>,
}

impl AssetExposureInput {
    pub fn from_inventory(
        inventory: ServiceInventoryOutput,
        producer_plugin: PluginId,
    ) -> Result<Self, AssetExposureError> {
        let asset = inventory
            .assets
            .into_iter()
            .next()
            .ok_or(AssetExposureError::MissingListeningPorts)?;
        Ok(Self {
            asset,
            services: inventory.services,
            port_exposures: inventory.port_exposures,
            producer_plugin,
            source_event_refs: Vec::new(),
            labels: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetExposureObservation {
    pub observation: SecurityObservation,
    pub port_exposure_record_ref: String,
    pub process_ref: Option<ProcessContextId>,
    pub attribution_status: AttributionStatus,
    pub attribution_method: AttributionMethod,
    pub attribution_confidence: AttributionConfidence,
    pub exposure_level: ServiceExposureLevel,
    pub risk_kinds: Vec<AssetRiskKind>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetRiskFinding {
    pub finding: Finding,
    pub risk_kind: AssetRiskKind,
    pub port_exposure_record_ref: String,
    pub process_ref: Option<ProcessContextId>,
    pub attribution_confidence: AttributionConfidence,
    pub evidence: EvidenceItem,
    pub explanation: FindingExplanation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcessListensOnPortHint {
    pub graph_hint: GraphHint,
    pub edge_type: GraphEdgeType,
    pub process_ref: ProcessContextId,
    pub port_exposure_record_ref: String,
    pub local_port: u16,
    pub protocol: TransportProtocol,
    pub attribution_confidence: AttributionConfidence,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetExposureOutput {
    pub observations: Vec<AssetExposureObservation>,
    pub findings: Vec<AssetRiskFinding>,
    pub evidence: Vec<EvidenceItem>,
    pub graph_hints: Vec<ProcessListensOnPortHint>,
}

#[derive(Clone, Debug, Default)]
pub struct AssetRiskFindingBuilder;

impl AssetRiskFindingBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        asset: &AssetRecord,
        port: &PortExposureRecord,
        producer_plugin: &PluginId,
    ) -> Result<Vec<AssetRiskFinding>, AssetExposureError> {
        risk_kinds_for(port)
            .into_iter()
            .map(|kind| self.build_one(asset, port, producer_plugin, kind))
            .collect()
    }

    fn build_one(
        &self,
        asset: &AssetRecord,
        port: &PortExposureRecord,
        producer_plugin: &PluginId,
        risk_kind: AssetRiskKind,
    ) -> Result<AssetRiskFinding, AssetExposureError> {
        let summary = risk_kind.summary(port);
        let entity_refs = port.entity_refs(asset);
        let mut evidence =
            EvidenceItem::new("asset_exposure.port", format!("Metadata-only: {summary}"))?;
        evidence.source_plugin = Some(producer_plugin.clone());
        evidence.entity_refs = entity_refs;
        evidence.timestamp = port.last_seen.clone();
        evidence.weight = risk_kind.evidence_weight()?;
        evidence.confidence = attribution_quality(&port.attribution_confidence)?;
        evidence.privacy_class = PrivacyClass::Internal;
        evidence.description_redacted = Some(
            "Derived from local endpoint and service metadata; no packet content or private data retained."
                .to_string(),
        );

        let mut reason = RiskReason::new(risk_kind.reason_type(), summary.clone())?;
        reason.confidence = evidence.confidence.clone();
        reason.evidence_refs.push(evidence.evidence_id.clone());

        let mut explanation = FindingExplanation::new(summary)?;
        explanation.risk_reasons.push(reason.clone());
        explanation.limitations_redacted = port.known_limitations.clone();

        let finding = Finding::new(
            risk_kind.finding_type(),
            producer_plugin.clone(),
            vec![evidence.evidence_id.clone()],
            explanation.clone(),
        )?
        .with_risk_reasons(vec![reason]);

        Ok(AssetRiskFinding {
            finding,
            risk_kind,
            port_exposure_record_ref: port.port_exposure_record_id.clone(),
            process_ref: port.process_ref.clone(),
            attribution_confidence: port.attribution_confidence.clone(),
            evidence,
            explanation,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct AssetExposurePlugin {
    finding_builder: AssetRiskFindingBuilder,
}

impl AssetExposurePlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(
        &self,
        input: AssetExposureInput,
    ) -> Result<AssetExposureOutput, AssetExposureError> {
        let mut observations = Vec::new();
        let mut findings = Vec::new();
        let mut evidence = Vec::new();
        let mut graph_hints = Vec::new();

        for port in &input.port_exposures {
            let risk_kinds = risk_kinds_for(port);
            let mut observation = SecurityObservation::new(
                "asset.exposure",
                format!(
                    "{} listener on local port {} observed at {} scope.",
                    protocol_label(&port.protocol),
                    port.local_port,
                    exposure_label(&port.exposure_level)
                ),
            )?;
            observation.source_event_refs = input.source_event_refs.clone();
            observation.entity_refs = port.entity_refs(&input.asset);
            observation.producer_plugin = Some(input.producer_plugin.clone());
            observation.timestamp = port.last_seen.clone();
            observation.privacy_class = PrivacyClass::Internal;
            observation.confidence = attribution_quality(&port.attribution_confidence)?;

            observations.push(AssetExposureObservation {
                observation,
                port_exposure_record_ref: port.port_exposure_record_id.clone(),
                process_ref: port.process_ref.clone(),
                attribution_status: port.attribution_status.clone(),
                attribution_method: port.attribution_method.clone(),
                attribution_confidence: port.attribution_confidence.clone(),
                exposure_level: port.exposure_level.clone(),
                risk_kinds,
            });

            let mut port_findings =
                self.finding_builder
                    .build(&input.asset, port, &input.producer_plugin)?;
            evidence.extend(port_findings.iter().map(|finding| finding.evidence.clone()));

            if let Some(hint) =
                process_listens_on_port_hint(port, &input.producer_plugin, &port_findings)?
            {
                graph_hints.push(hint);
            }

            findings.append(&mut port_findings);
        }

        Ok(AssetExposureOutput {
            observations,
            findings,
            evidence,
            graph_hints,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetInventoryStoreWriteSummary {
    pub asset_records: usize,
    pub service_records: usize,
    pub port_exposure_records: usize,
}

#[derive(Clone, Debug, Default)]
pub struct AssetExposureInventoryStoreWriter;

impl AssetExposureInventoryStoreWriter {
    pub fn new() -> Self {
        Self
    }

    pub fn write_inventory(
        &self,
        stores: &SqliteStoreFactory<'_>,
        inventory: &ServiceInventoryOutput,
    ) -> Result<AssetInventoryStoreWriteSummary, AssetExposureError> {
        let store = stores.asset_store();
        let mut summary = AssetInventoryStoreWriteSummary::default();

        for asset in &inventory.assets {
            write_asset_metadata_record(
                &store,
                asset.asset_identity.asset_identity_id.clone(),
                "asset_record",
                asset,
                &asset.labels,
            )?;
            summary.asset_records += 1;
        }

        for service in &inventory.services {
            write_asset_metadata_record(
                &store,
                service.logical_record_id.clone(),
                "service_record",
                service,
                &[],
            )?;
            summary.service_records += 1;
        }

        for port in &inventory.port_exposures {
            write_asset_metadata_record(
                &store,
                port.logical_record_id.clone(),
                "port_exposure_record",
                port,
                &[],
            )?;
            summary.port_exposure_records += 1;
        }

        Ok(summary)
    }
}

fn process_listens_on_port_hint(
    port: &PortExposureRecord,
    producer_plugin: &PluginId,
    findings: &[AssetRiskFinding],
) -> Result<Option<ProcessListensOnPortHint>, AssetExposureError> {
    let (Some(process_ref), Some(process_entity)) =
        (port.process_ref.clone(), port.process_entity.clone())
    else {
        return Ok(None);
    };

    let mut hint = GraphHint::new(
        GraphHintType::Custom(PROCESS_LISTENS_ON_PORT_HINT.to_string()),
        process_entity,
        port.port_entity.clone(),
        producer_plugin.clone(),
    );
    hint.confidence = attribution_quality(&port.attribution_confidence)?;
    hint.privacy_class = PrivacyClass::Internal;
    hint.evidence_refs = findings
        .iter()
        .map(|finding| finding.evidence.evidence_id.clone())
        .collect();

    Ok(Some(ProcessListensOnPortHint {
        graph_hint: hint,
        edge_type: GraphEdgeType::ProcessListensOnPort,
        process_ref,
        port_exposure_record_ref: port.port_exposure_record_id.clone(),
        local_port: port.local_port,
        protocol: port.protocol.clone(),
        attribution_confidence: port.attribution_confidence.clone(),
    }))
}

fn validate_inventory_input(input: &ServiceInventoryInput) -> Result<(), AssetExposureError> {
    if input.listening_ports.is_empty() {
        return Err(AssetExposureError::MissingListeningPorts);
    }
    if let Some(hostname) = &input.asset_hostname_protected {
        validate_safe_text("asset_hostname_protected", hostname)?;
    }
    for listening in &input.listening_ports {
        validate_listening_port(listening)?;
    }
    Ok(())
}

fn validate_listening_port(input: &ListeningPortInput) -> Result<(), AssetExposureError> {
    if input.local_port == 0 {
        return Err(AssetExposureError::InvalidPort);
    }
    if let Some(service_name) = &input.service_name_protected {
        validate_safe_text("service_name_protected", service_name)?;
    }
    if let Some(display_name) = &input.service_display_name_protected {
        validate_safe_text("service_display_name_protected", display_name)?;
    }
    if let Some(process) = &input.process_context {
        validate_safe_text("process_name", &process.process_name)?;
        for limitation in &process.known_limitations {
            validate_safe_text("process_known_limitation", limitation)?;
        }
    }
    for limitation in &input.known_limitations {
        validate_safe_text("known_limitation", limitation)?;
    }
    Ok(())
}

fn service_entity_ref(
    listening: &ListeningPortInput,
    process_entity: Option<&EntityRef>,
) -> Result<EntityRef, AssetExposureError> {
    let name = listening
        .service_name_protected
        .clone()
        .or_else(|| {
            listening
                .process_context
                .as_ref()
                .map(|process| process.process_name.clone())
        })
        .unwrap_or_else(|| {
            format!(
                "{}:{}",
                protocol_label(&listening.protocol),
                listening.local_port
            )
        });
    validate_safe_text("service_entity_name", &name)?;

    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Service);
    entity.entity_name = Some(name);
    entity.namespace = Some("local_service_inventory".to_string());
    entity.source = Some(format!("{:?}", listening.source).to_ascii_lowercase());
    entity.confidence = attribution_quality(&listening.attribution_confidence)?;
    entity.first_seen = Some(listening.first_seen.clone());
    entity.last_seen = Some(listening.last_seen.clone());

    if let Some(process_entity) = process_entity {
        entity.confidence = process_entity.confidence.clone();
    }

    Ok(entity)
}

fn port_entity_ref(listening: &ListeningPortInput) -> Result<EntityRef, AssetExposureError> {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Port);
    entity.entity_name = Some(format!(
        "{}:{}:{}",
        protocol_label(&listening.protocol),
        listening.local_ip,
        listening.local_port
    ));
    entity.namespace = Some("local_asset_port".to_string());
    entity.source = Some(format!("{:?}", listening.source).to_ascii_lowercase());
    entity.confidence = attribution_quality(&listening.attribution_confidence)?;
    entity.first_seen = Some(listening.first_seen.clone());
    entity.last_seen = Some(listening.last_seen.clone());
    Ok(entity)
}

fn process_entity_ref(process: &ProcessContext) -> Result<EntityRef, AssetExposureError> {
    validate_safe_text("process_name", &process.process_name)?;
    let mut entity = EntityRef::new(
        EntityId::from_uuid(process.process_context_id.as_uuid()),
        EntityType::Process,
    );
    entity.entity_name = Some(process.process_name.clone());
    entity.namespace = Some("local_process_context".to_string());
    entity.source = Some("process_context".to_string());
    entity.confidence = quality_score(match process.visibility_level {
        VisibilityLevel::Full => 0.8,
        VisibilityLevel::MetadataOnly | VisibilityLevel::Reduced => 0.65,
        VisibilityLevel::Degraded => 0.45,
        VisibilityLevel::Unknown => 0.3,
    })?;
    entity.first_seen = Some(process.process_start_time.clone());
    entity.last_seen = Some(process.captured_at.clone());
    Ok(entity)
}

fn asset_entity_ref(hostname_protected: Option<&str>) -> EntityRef {
    let mut entity = EntityRef::new(EntityId::new_v4(), EntityType::Host);
    entity.entity_name = hostname_protected.map(ToString::to_string);
    entity.namespace = Some("local_asset".to_string());
    entity.source = Some("service_inventory".to_string());
    entity.confidence = QualityScore::default();
    entity
}

fn known_limitations_for(input: &ListeningPortInput) -> Vec<String> {
    let mut limitations = input.known_limitations.clone();
    if input.process_context.is_none() {
        limitations.push("No process context was available for this listener.".to_string());
    }
    if input.attribution_confidence == AttributionConfidence::Unknown {
        limitations.push("Process attribution confidence is unknown.".to_string());
    }
    limitations
}

fn attribution_method_for(protocol: &TransportProtocol) -> AttributionMethod {
    match protocol {
        TransportProtocol::Tcp => AttributionMethod::TcpEndpointSnapshot,
        TransportProtocol::Udp => AttributionMethod::UdpEndpointSnapshot,
        _ => AttributionMethod::ConnectionTableCorrelation,
    }
}

fn attribution_status_for(confidence: &AttributionConfidence) -> AttributionStatus {
    match confidence {
        AttributionConfidence::High => AttributionStatus::Confirmed,
        AttributionConfidence::Medium => AttributionStatus::Probable,
        AttributionConfidence::Low => AttributionStatus::Possible,
        AttributionConfidence::Unknown => AttributionStatus::Unknown,
    }
}

fn exposure_level_for(scope: &BindScope) -> ServiceExposureLevel {
    match scope {
        BindScope::Loopback => ServiceExposureLevel::LoopbackOnly,
        BindScope::LocalOnly => ServiceExposureLevel::LocalOnly,
        BindScope::Lan => ServiceExposureLevel::LocalNetwork,
        BindScope::Public => ServiceExposureLevel::Public,
        BindScope::Unknown => ServiceExposureLevel::Unknown,
    }
}

fn risk_kinds_for(port: &PortExposureRecord) -> Vec<AssetRiskKind> {
    let mut risks = Vec::new();
    if !port.seen_before {
        risks.push(AssetRiskKind::NewListeningPort);
    }
    if risky_port(port.local_port)
        && matches!(
            port.exposure_level,
            ServiceExposureLevel::LocalNetwork | ServiceExposureLevel::Public
        )
    {
        risks.push(AssetRiskKind::RiskyPortExposed);
    }
    if port.process_ref.is_none() || port.attribution_confidence == AttributionConfidence::Unknown {
        risks.push(AssetRiskKind::UnknownProcessListener);
    }
    if matches!(port.exposure_level, ServiceExposureLevel::Public) {
        risks.push(AssetRiskKind::PublicServiceHint);
    }
    risks
}

fn risky_port(port: u16) -> bool {
    matches!(
        port,
        21 | 22 | 23 | 25 | 135 | 139 | 445 | 1433 | 3306 | 3389 | 5432 | 5985 | 5986 | 6379 | 9200
    )
}

fn protocol_label(protocol: &TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
        TransportProtocol::Icmp => "icmp",
        TransportProtocol::Icmpv6 => "icmpv6",
        TransportProtocol::Quic => "quic",
        TransportProtocol::Other => "other",
        TransportProtocol::Unknown => "unknown",
    }
}

fn exposure_label(exposure_level: &ServiceExposureLevel) -> &'static str {
    match exposure_level {
        ServiceExposureLevel::LoopbackOnly => "loopback",
        ServiceExposureLevel::LocalOnly => "local_only",
        ServiceExposureLevel::LocalNetwork => "local_network",
        ServiceExposureLevel::Public => "public",
        ServiceExposureLevel::Unknown => "unknown",
    }
}

fn attribution_quality(
    confidence: &AttributionConfidence,
) -> Result<QualityScore, AssetExposureError> {
    match confidence {
        AttributionConfidence::High => quality_score(0.8),
        AttributionConfidence::Medium => quality_score(0.65),
        AttributionConfidence::Low => quality_score(0.45),
        AttributionConfidence::Unknown => quality_score(0.25),
    }
}

fn quality_score(value: f32) -> Result<QualityScore, AssetExposureError> {
    QualityScore::new(value).map_err(|_| AssetExposureError::InvalidQualityScore)
}

fn synthetic_record_id(prefix: &str) -> String {
    format!("{prefix}:{}", EntityId::new_v4())
}

fn write_asset_metadata_record<T: Serialize>(
    store: &impl LogicalStore<AssetIdentityId>,
    id: AssetIdentityId,
    record_kind: &str,
    record: &T,
    labels: &[String],
) -> Result<(), AssetExposureError> {
    let metadata = asset_metadata(record_kind, record, labels)?;
    let logical_record = LogicalRecord::metadata_only(
        id,
        ASSET_EXPOSURE_SCHEMA_VERSION,
        StoreKind::Asset.default_storage_privacy_class(),
        metadata,
    );
    store
        .append(logical_record)
        .map_err(AssetExposureError::from)
}

fn asset_metadata<T: Serialize>(
    record_kind: &str,
    record: &T,
    labels: &[String],
) -> Result<Value, AssetExposureError> {
    Ok(json!({
        "record_kind": record_kind,
        "labels": labels,
        "record": serde_json::to_value(record)?
    }))
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), AssetExposureError> {
    if value.trim().is_empty() {
        return Err(AssetExposureError::EmptyField(field));
    }
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '/', '=', ':', '?'], "_");
    for marker in [
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
    ] {
        if normalized.contains(marker) {
            return Err(AssetExposureError::PrivacyMarker { field });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use sentinel_contracts::{PageRequest, QueryRequest, QueryScope, SignerStatus};
    use sentinel_storage::{
        logical_store_migration, InMemoryMigrationAuditSink, MigrationRunner, SchemaMetadata,
    };

    fn ip(value: &str) -> IpAddress {
        IpAddress::parse_str(value).expect("test IP")
    }

    fn process() -> ProcessContext {
        let mut process = ProcessContext::new(4_242, "rdp_service_host");
        process.process_hash = Some("sha256_rdp_service_host".to_string());
        process.signer_status = SignerStatus::Signed;
        process.visibility_level = VisibilityLevel::MetadataOnly;
        process.collection_mode = CollectionMode::Mock;
        process.known_limitations = vec!["Endpoint snapshot can be stale.".to_string()];
        process
    }

    fn inventory_input() -> ServiceInventoryInput {
        let listening = ListeningPortInput::new(
            ip("0.0.0.0"),
            3389,
            TransportProtocol::Tcp,
            BindScope::Public,
        )
        .with_process_context(process(), AttributionConfidence::High)
        .with_service(
            "termservice",
            "Remote Desktop Services",
            ServiceKind::WindowsService,
        )
        .with_source(InventorySource::MockEndpointSnapshot);
        let mut input = ServiceInventoryInput::new(vec![listening]);
        input.asset_hostname_protected = Some("hostref_workstation".to_string());
        input.asset_ip = Some(ip("192.0.2.10"));
        input.collection_mode = CollectionMode::Mock;
        input.labels = vec!["FIXTURE_ONLY".to_string()];
        input
    }

    #[test]
    fn service_inventory_plugin_builds_asset_service_and_port_records() {
        let output = ServiceInventoryPlugin::new()
            .inventory(inventory_input())
            .expect("inventory output");

        assert_eq!(output.assets.len(), 1);
        assert_eq!(output.services.len(), 1);
        assert_eq!(output.port_exposures.len(), 1);
        assert_eq!(
            output.assets[0].asset_identity.listening_endpoints[0].listening_port,
            3389
        );
        assert_eq!(
            output.port_exposures[0].process_ref,
            output.services[0].process_ref
        );
        assert_eq!(
            output.port_exposures[0].attribution_confidence,
            AttributionConfidence::High
        );
        assert_eq!(
            output.port_exposures[0].exposure_level,
            ServiceExposureLevel::Public
        );
    }

    #[test]
    fn asset_exposure_observations_include_process_and_confidence() {
        let inventory = ServiceInventoryPlugin::new()
            .inventory(inventory_input())
            .expect("inventory output");
        let output = AssetExposurePlugin::new()
            .observe(
                AssetExposureInput::from_inventory(inventory, PluginId::new_v4())
                    .expect("asset exposure input"),
            )
            .expect("asset exposure output");

        assert_eq!(output.observations.len(), 1);
        assert_eq!(
            output.observations[0].attribution_confidence,
            AttributionConfidence::High
        );
        assert!(output.observations[0].process_ref.is_some());
        assert!(output.observations[0]
            .risk_kinds
            .contains(&AssetRiskKind::RiskyPortExposed));
        assert!(output.observations[0]
            .risk_kinds
            .contains(&AssetRiskKind::PublicServiceHint));
    }

    #[test]
    fn local_only_listener_keeps_scope_without_risky_port_finding() {
        let listening = ListeningPortInput::new(
            ip("127.0.0.1"),
            3389,
            TransportProtocol::Tcp,
            BindScope::LocalOnly,
        )
        .with_process_context(process(), AttributionConfidence::High)
        .with_service(
            "local_termservice",
            "Local Remote Desktop Services",
            ServiceKind::WindowsService,
        )
        .with_seen_before(true)
        .with_source(InventorySource::MockEndpointSnapshot);
        let inventory = ServiceInventoryPlugin::new()
            .inventory(ServiceInventoryInput::new(vec![listening]))
            .expect("inventory output");

        assert_eq!(
            inventory.port_exposures[0].exposure_level,
            ServiceExposureLevel::LocalOnly
        );

        let output = AssetExposurePlugin::new()
            .observe(
                AssetExposureInput::from_inventory(inventory, PluginId::new_v4())
                    .expect("asset exposure input"),
            )
            .expect("asset exposure output");

        assert!(output.observations[0]
            .risk_kinds
            .iter()
            .all(|risk| risk != &AssetRiskKind::RiskyPortExposed
                && risk != &AssetRiskKind::PublicServiceHint));
        assert!(output.findings.iter().all(|finding| finding.risk_kind
            != AssetRiskKind::RiskyPortExposed
            && finding.risk_kind != AssetRiskKind::PublicServiceHint));
        assert_eq!(output.graph_hints.len(), 1);
    }

    #[test]
    fn asset_risk_findings_include_evidence_and_explanation() {
        let inventory = ServiceInventoryPlugin::new()
            .inventory(inventory_input())
            .expect("inventory output");
        let output = AssetExposurePlugin::new()
            .observe(
                AssetExposureInput::from_inventory(inventory, PluginId::new_v4())
                    .expect("asset exposure input"),
            )
            .expect("asset exposure output");

        assert!(output.findings.len() >= 3);
        assert_eq!(output.evidence.len(), output.findings.len());
        for finding in &output.findings {
            assert!(!finding.finding.evidence_refs().is_empty());
            assert!(!finding.explanation.summary_redacted.is_empty());
            assert_eq!(
                finding.finding.evidence_refs()[0],
                finding.evidence.evidence_id
            );
        }
    }

    #[test]
    fn asset_exposure_plugin_emits_process_listens_on_port_graph_hint() {
        let inventory = ServiceInventoryPlugin::new()
            .inventory(inventory_input())
            .expect("inventory output");
        let output = AssetExposurePlugin::new()
            .observe(
                AssetExposureInput::from_inventory(inventory, PluginId::new_v4())
                    .expect("asset exposure input"),
            )
            .expect("asset exposure output");

        assert_eq!(output.graph_hints.len(), 1);
        assert_eq!(
            output.graph_hints[0].edge_type,
            GraphEdgeType::ProcessListensOnPort
        );
        assert_eq!(
            output.graph_hints[0].graph_hint.hint_type,
            GraphHintType::Custom(PROCESS_LISTENS_ON_PORT_HINT.to_string())
        );
        assert_eq!(
            output.graph_hints[0].graph_hint.source_entity.entity_type,
            EntityType::Process
        );
        assert_eq!(
            output.graph_hints[0].graph_hint.target_entity.entity_type,
            EntityType::Port
        );
    }

    #[test]
    fn unknown_process_listener_still_observes_without_graph_hint() {
        let listening = ListeningPortInput::new(
            ip("192.0.2.10"),
            8080,
            TransportProtocol::Tcp,
            BindScope::Lan,
        )
        .with_seen_before(true)
        .with_source(InventorySource::MockEndpointSnapshot);
        let inventory = ServiceInventoryPlugin::new()
            .inventory(ServiceInventoryInput::new(vec![listening]))
            .expect("inventory output");
        let output = AssetExposurePlugin::new()
            .observe(
                AssetExposureInput::from_inventory(inventory, PluginId::new_v4())
                    .expect("asset exposure input"),
            )
            .expect("asset exposure output");

        assert!(output.graph_hints.is_empty());
        assert!(output.observations[0].process_ref.is_none());
        assert!(output.observations[0]
            .risk_kinds
            .contains(&AssetRiskKind::UnknownProcessListener));
    }

    #[test]
    fn asset_inventory_records_are_queryable_through_logical_asset_store(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let inventory = ServiceInventoryPlugin::new().inventory(inventory_input())?;
        let summary =
            AssetExposureInventoryStoreWriter::new().write_inventory(&stores, &inventory)?;

        assert_eq!(summary.asset_records, 1);
        assert_eq!(summary.service_records, 1);
        assert_eq!(summary.port_exposure_records, 1);

        let snapshot = stores.asset_store().create_snapshot()?;
        assert_eq!(snapshot.record_count, 3);
        let queried = stores
            .asset_store()
            .query(QueryRequest::new(QueryScope::Global).with_page(PageRequest::first(10)?))?;
        let serialized = serde_json::to_string(&queried)?;

        assert!(serialized.contains("\"record_kind\":\"asset_record\""));
        assert!(serialized.contains("\"record_kind\":\"service_record\""));
        assert!(serialized.contains("\"record_kind\":\"port_exposure_record\""));
        assert!(!serialized.contains("http_body"));
        assert!(!serialized.contains("api_key"));
        assert!(!serialized.contains("credential"));
        Ok(())
    }

    #[test]
    fn asset_exposure_rejects_sensitive_markers_and_invalid_ports() {
        let sensitive = ListeningPortInput::new(
            ip("127.0.0.1"),
            8080,
            TransportProtocol::Tcp,
            BindScope::Loopback,
        )
        .with_service(
            "api_key_listener",
            "Local Service",
            ServiceKind::UserProcess,
        );

        assert!(matches!(
            ServiceInventoryPlugin::new().inventory(ServiceInventoryInput::new(vec![sensitive])),
            Err(AssetExposureError::PrivacyMarker {
                field: "service_name_protected"
            })
        ));

        let invalid = ListeningPortInput::new(
            ip("127.0.0.1"),
            0,
            TransportProtocol::Tcp,
            BindScope::Loopback,
        );
        assert!(matches!(
            ServiceInventoryPlugin::new().inventory(ServiceInventoryInput::new(vec![invalid])),
            Err(AssetExposureError::InvalidPort)
        ));
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
}
