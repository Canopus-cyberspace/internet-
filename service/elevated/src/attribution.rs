//! STUB_ONLY process inventory and flow attribution boundary.
//!
//! NOT_FOR_PRODUCTION: this module provides safe process snapshot,
//! connection snapshot, and flow attribution DTOs/traits using fixture
//! metadata only. It does not read process memory, store raw command lines,
//! expose credentials in arguments, read private file content, or control
//! processes.

use crate::ipc::{command_spec, IpcCaller, IpcCommand, IpcRequestEnvelope};
use crate::security::{
    PrivilegedCommandPrecheck, SensitiveCommandAudit, ServiceCommandAllowlist,
    ServiceCommandDecision, ServiceDegradedState,
};
use crate::{NOT_FOR_PRODUCTION_LABEL, STUB_ONLY_LABEL};
use sentinel_contracts::{
    AttributionConfidence, AttributionMethod, AttributionStatus, CollectionMode, ErrorCode,
    FlowAttribution, FlowId, FlowRecord, IpAddress, NetworkDirection, ProcessContext,
    ProcessContextId, ProcessTrustScore, SchemaVersion, SignerStatus, Timestamp, TransportProtocol,
    UserSessionRef, VisibilityLevel,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt;
use uuid::Uuid;

pub const ATTRIBUTION_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const STUB_ATTRIBUTION_REPLACEMENT_TASK: &str =
    "real Windows process attribution adapter after metadata pipeline";

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProcessSnapshotId(Uuid);

impl ProcessSnapshotId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for ProcessSnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConnectionSnapshotId(Uuid);

impl ConnectionSnapshotId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for ConnectionSnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionLimitation {
    UdpStateless,
    VpnOrProxyMayShiftDestination,
    BrowserMultiplexing,
    ProtectedProcessMetadataHidden,
    ShortLivedProcessMayExit,
    ReducedVisibilityMode,
    PacketCaptureIsNotAbsoluteTruth,
    StubOnlyFixture,
}

impl AttributionLimitation {
    pub fn message_redacted(&self) -> &'static str {
        match self {
            Self::UdpStateless => "UDP is stateless and may be lower confidence.",
            Self::VpnOrProxyMayShiftDestination => {
                "VPN or proxy use can shift destination visibility."
            }
            Self::BrowserMultiplexing => {
                "Browser and proxy multiplexing can obscure app-level origin."
            }
            Self::ProtectedProcessMetadataHidden => {
                "Protected processes may hide path or command line."
            }
            Self::ShortLivedProcessMayExit => {
                "Short-lived processes may exit before snapshot confirmation."
            }
            Self::ReducedVisibilityMode => {
                "Reduced visibility mode limits process-to-flow attribution."
            }
            Self::PacketCaptureIsNotAbsoluteTruth => {
                "Packet capture alone does not guarantee packet-to-process truth."
            }
            Self::StubOnlyFixture => "STUB_ONLY attribution is fixture metadata only.",
        }
    }

    pub fn default_visible_set() -> Vec<Self> {
        vec![
            Self::UdpStateless,
            Self::VpnOrProxyMayShiftDestination,
            Self::BrowserMultiplexing,
            Self::ProtectedProcessMetadataHidden,
            Self::ShortLivedProcessMayExit,
            Self::ReducedVisibilityMode,
            Self::PacketCaptureIsNotAbsoluteTruth,
            Self::StubOnlyFixture,
        ]
    }

    pub fn from_message(message_redacted: &str) -> Option<Self> {
        [
            Self::UdpStateless,
            Self::VpnOrProxyMayShiftDestination,
            Self::BrowserMultiplexing,
            Self::ProtectedProcessMetadataHidden,
            Self::ShortLivedProcessMayExit,
            Self::ReducedVisibilityMode,
            Self::PacketCaptureIsNotAbsoluteTruth,
            Self::StubOnlyFixture,
        ]
        .into_iter()
        .find(|limitation| limitation.message_redacted() == message_redacted)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub snapshot_id: ProcessSnapshotId,
    pub processes: Vec<ProcessContext>,
    pub visibility_level: VisibilityLevel,
    pub collection_mode: CollectionMode,
    pub known_limitations: Vec<AttributionLimitation>,
    pub captured_at: Timestamp,
    pub labels: Vec<String>,
    pub replacement_task: String,
    pub schema_version: SchemaVersion,
}

impl ProcessSnapshot {
    pub fn new(processes: Vec<ProcessContext>) -> Self {
        Self {
            snapshot_id: ProcessSnapshotId::new_v4(),
            processes,
            visibility_level: VisibilityLevel::Reduced,
            collection_mode: CollectionMode::Mock,
            known_limitations: AttributionLimitation::default_visible_set(),
            captured_at: Timestamp::now(),
            labels: vec![
                STUB_ONLY_LABEL.to_string(),
                NOT_FOR_PRODUCTION_LABEL.to_string(),
            ],
            replacement_task: STUB_ATTRIBUTION_REPLACEMENT_TASK.to_string(),
            schema_version: ATTRIBUTION_SCHEMA_VERSION,
        }
    }

    pub fn validate(&self) -> Result<(), AttributionProviderError> {
        if self.schema_version != ATTRIBUTION_SCHEMA_VERSION {
            return Err(AttributionProviderError::invalid(
                "process snapshot schema version is unsupported",
            ));
        }
        if self.known_limitations.is_empty() {
            return Err(AttributionProviderError::invalid(
                "process snapshot must expose known limitations",
            ));
        }
        validate_attribution_text("replacement_task", &self.replacement_task)?;
        for process in &self.processes {
            validate_process_context(process)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectionSnapshotRecord {
    pub local_ip: IpAddress,
    pub local_port: u16,
    pub remote_ip: IpAddress,
    pub remote_port: u16,
    pub protocol: TransportProtocol,
    pub direction: NetworkDirection,
    pub candidate_process_ref: Option<ProcessContextId>,
    pub os_process_id: Option<u32>,
    pub observed_at: Timestamp,
    pub visibility_level: VisibilityLevel,
    pub collection_mode: CollectionMode,
    pub known_limitations: Vec<AttributionLimitation>,
}

impl ConnectionSnapshotRecord {
    pub fn validate(&self) -> Result<(), AttributionProviderError> {
        if self.known_limitations.is_empty() {
            return Err(AttributionProviderError::invalid(
                "connection snapshot record must expose known limitations",
            ));
        }
        if matches!(self.visibility_level, VisibilityLevel::Full) {
            return Err(AttributionProviderError::invalid(
                "STUB_ONLY connection visibility must not claim full fidelity",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    pub snapshot_id: ConnectionSnapshotId,
    pub connections: Vec<ConnectionSnapshotRecord>,
    pub visibility_level: VisibilityLevel,
    pub collection_mode: CollectionMode,
    pub known_limitations: Vec<AttributionLimitation>,
    pub captured_at: Timestamp,
    pub labels: Vec<String>,
    pub replacement_task: String,
    pub schema_version: SchemaVersion,
}

impl ConnectionSnapshot {
    pub fn new(connections: Vec<ConnectionSnapshotRecord>) -> Self {
        Self {
            snapshot_id: ConnectionSnapshotId::new_v4(),
            connections,
            visibility_level: VisibilityLevel::Reduced,
            collection_mode: CollectionMode::Mock,
            known_limitations: AttributionLimitation::default_visible_set(),
            captured_at: Timestamp::now(),
            labels: vec![
                STUB_ONLY_LABEL.to_string(),
                NOT_FOR_PRODUCTION_LABEL.to_string(),
            ],
            replacement_task: STUB_ATTRIBUTION_REPLACEMENT_TASK.to_string(),
            schema_version: ATTRIBUTION_SCHEMA_VERSION,
        }
    }

    pub fn validate(&self) -> Result<(), AttributionProviderError> {
        if self.schema_version != ATTRIBUTION_SCHEMA_VERSION {
            return Err(AttributionProviderError::invalid(
                "connection snapshot schema version is unsupported",
            ));
        }
        if self.known_limitations.is_empty() {
            return Err(AttributionProviderError::invalid(
                "connection snapshot must expose known limitations",
            ));
        }
        validate_attribution_text("replacement_task", &self.replacement_task)?;
        for connection in &self.connections {
            connection.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttributionResult {
    pub attribution: FlowAttribution,
    pub status: AttributionStatus,
    pub method: AttributionMethod,
    pub confidence: AttributionConfidence,
    pub visibility_level: VisibilityLevel,
    pub collection_mode: CollectionMode,
    pub known_limitations: Vec<AttributionLimitation>,
    pub explanation_redacted: String,
    pub absolute_truth_claimed: bool,
    pub timestamp: Timestamp,
    pub labels: Vec<String>,
    pub schema_version: SchemaVersion,
}

impl AttributionResult {
    pub fn new(
        attribution: FlowAttribution,
        explanation_redacted: impl Into<String>,
        limitations: Vec<AttributionLimitation>,
    ) -> Self {
        Self {
            status: attribution.attribution_status.clone(),
            method: attribution.attribution_method.clone(),
            confidence: attribution.attribution_confidence.clone(),
            visibility_level: attribution.visibility_level.clone(),
            collection_mode: attribution.collection_mode.clone(),
            known_limitations: limitations,
            explanation_redacted: explanation_redacted.into(),
            absolute_truth_claimed: false,
            timestamp: attribution.timestamp.clone(),
            labels: vec![
                STUB_ONLY_LABEL.to_string(),
                NOT_FOR_PRODUCTION_LABEL.to_string(),
            ],
            schema_version: ATTRIBUTION_SCHEMA_VERSION,
            attribution,
        }
    }

    pub fn validate(&self) -> Result<(), AttributionProviderError> {
        if self.schema_version != ATTRIBUTION_SCHEMA_VERSION {
            return Err(AttributionProviderError::invalid(
                "attribution result schema version is unsupported",
            ));
        }
        if self.absolute_truth_claimed {
            return Err(AttributionProviderError::invalid(
                "flow attribution must not claim absolute packet-to-process truth",
            ));
        }
        if self.known_limitations.is_empty() || self.attribution.known_limitations.is_empty() {
            return Err(AttributionProviderError::invalid(
                "attribution result must expose known limitations",
            ));
        }
        if limitation_messages(self.known_limitations.clone()) != self.attribution.known_limitations
        {
            return Err(AttributionProviderError::invalid(
                "attribution result limitations must mirror the contract record",
            ));
        }
        if self.status != self.attribution.attribution_status
            || self.method != self.attribution.attribution_method
            || self.confidence != self.attribution.attribution_confidence
            || self.visibility_level != self.attribution.visibility_level
            || self.collection_mode != self.attribution.collection_mode
        {
            return Err(AttributionProviderError::invalid(
                "attribution result summary fields must mirror the contract record",
            ));
        }
        validate_attribution_text("explanation_redacted", &self.explanation_redacted)?;
        Ok(())
    }
}

pub trait ProcessInventoryProvider {
    fn refresh_process_inventory(&mut self) -> Result<ProcessSnapshot, AttributionProviderError>;
    fn process_snapshot(&self) -> Result<ProcessSnapshot, AttributionProviderError>;
}

pub trait ConnectionSnapshotProvider {
    fn connection_snapshot(&self) -> Result<ConnectionSnapshot, AttributionProviderError>;
}

pub trait FlowAttributionProvider {
    fn attribute_flow(
        &self,
        flow: &FlowRecord,
        process_snapshot: &ProcessSnapshot,
        connection_snapshot: &ConnectionSnapshot,
    ) -> Result<AttributionResult, AttributionProviderError>;
}

#[derive(Clone, Debug)]
pub struct StubOnlyProcessAttributionProvider {
    provider_name: String,
    process_snapshot: ProcessSnapshot,
    connection_snapshot: ConnectionSnapshot,
    precheck: PrivilegedCommandPrecheck,
}

impl StubOnlyProcessAttributionProvider {
    pub fn new() -> Result<Self, AttributionProviderError> {
        let process_snapshot = ProcessSnapshot::new(stub_process_contexts()?);
        let connection_snapshot =
            ConnectionSnapshot::new(stub_connection_records(&process_snapshot)?);
        process_snapshot.validate()?;
        connection_snapshot.validate()?;

        Ok(Self {
            provider_name: "STUB_ONLY process attribution provider".to_string(),
            process_snapshot,
            connection_snapshot,
            precheck: PrivilegedCommandPrecheck::new(
                ServiceCommandAllowlist::v1_default()
                    .map_err(AttributionProviderError::from_ipc)?,
                ServiceDegradedState::healthy(),
            ),
        })
    }

    pub fn with_precheck(
        precheck: PrivilegedCommandPrecheck,
    ) -> Result<Self, AttributionProviderError> {
        Ok(Self {
            precheck,
            ..Self::new()?
        })
    }

    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    pub fn attribution_examples(&self) -> Result<Vec<AttributionResult>, AttributionProviderError> {
        Ok(vec![
            self.result_for_status(
                AttributionStatus::Confirmed,
                AttributionMethod::TcpEndpointSnapshot,
                AttributionConfidence::High,
                VisibilityLevel::Reduced,
                CollectionMode::Mock,
            )?,
            self.result_for_status(
                AttributionStatus::Probable,
                AttributionMethod::ConnectionTableCorrelation,
                AttributionConfidence::Medium,
                VisibilityLevel::Reduced,
                CollectionMode::Mock,
            )?,
            self.result_for_status(
                AttributionStatus::Possible,
                AttributionMethod::UdpEndpointSnapshot,
                AttributionConfidence::Low,
                VisibilityLevel::MetadataOnly,
                CollectionMode::Mock,
            )?,
            self.result_for_status(
                AttributionStatus::Unknown,
                AttributionMethod::Unknown,
                AttributionConfidence::Unknown,
                VisibilityLevel::Unknown,
                CollectionMode::Mock,
            )?,
            self.result_for_status(
                AttributionStatus::Conflict,
                AttributionMethod::ConnectionTableCorrelation,
                AttributionConfidence::Low,
                VisibilityLevel::Reduced,
                CollectionMode::Mock,
            )?,
            self.result_for_status(
                AttributionStatus::ExpiredProcess,
                AttributionMethod::CaptureTimeCorrelation,
                AttributionConfidence::Low,
                VisibilityLevel::Degraded,
                CollectionMode::Mock,
            )?,
            self.result_for_status(
                AttributionStatus::InsufficientVisibility,
                AttributionMethod::Unknown,
                AttributionConfidence::Unknown,
                VisibilityLevel::Degraded,
                CollectionMode::Reduced,
            )?,
        ])
    }

    fn precheck_command(&self, command: IpcCommand) -> Result<(), AttributionProviderError> {
        let spec = command_spec(&command).map_err(AttributionProviderError::from_ipc)?;
        let request = IpcRequestEnvelope::new(
            IpcCaller::local_core("process attribution control")
                .map_err(AttributionProviderError::from_ipc)?,
            command,
            spec.permission_scope,
            json!({
                "target_scope": "process_attribution_metadata",
                "provider": self.provider_name,
                "metadata_only": true
            }),
            sentinel_contracts::PrivacyClass::Internal,
            crate::ipc::IpcAuthContext::local_core_stub(),
        );
        let permission_check = self
            .precheck
            .trusted_local_core_permission_check(&request.command);
        let audit =
            SensitiveCommandAudit::for_request(&request, "process attribution metadata", None);
        let decision = self
            .precheck
            .evaluate_request(&request, &permission_check, Some(&audit));
        if decision.allowed {
            Ok(())
        } else {
            Err(AttributionProviderError::from_decision(&decision))
        }
    }

    fn result_for_status(
        &self,
        status: AttributionStatus,
        method: AttributionMethod,
        confidence: AttributionConfidence,
        visibility_level: VisibilityLevel,
        collection_mode: CollectionMode,
    ) -> Result<AttributionResult, AttributionProviderError> {
        let flow_id = FlowId::new_v4();
        let mut attribution = FlowAttribution::unknown(flow_id);
        attribution.attribution_status = status.clone();
        attribution.attribution_method = method;
        attribution.attribution_confidence = confidence;
        attribution.visibility_level = visibility_level;
        attribution.collection_mode = collection_mode;
        attribution.known_limitations =
            limitation_messages(AttributionLimitation::default_visible_set());
        if !matches!(
            status,
            AttributionStatus::Unknown | AttributionStatus::InsufficientVisibility
        ) {
            if let Some(process) = self.process_snapshot.processes.first() {
                attribution.process_ref = Some(process.process_context_id.clone());
                attribution.os_process_id = Some(process.os_process_id);
                attribution.process_start_time = Some(process.process_start_time.clone());
                attribution.process_path_protected = process.process_path_protected.clone();
                attribution.process_hash = process.process_hash.clone();
                attribution.signer_status = process.signer_status.clone();
                attribution.parent_process_ref = process.parent_process_ref.clone();
                attribution.user_session_ref = process.user_session_ref.clone();
            }
        }
        let result = AttributionResult::new(
            attribution,
            "STUB_ONLY attribution example; UI and reports must show limitations",
            AttributionLimitation::default_visible_set(),
        );
        result.validate()?;
        Ok(result)
    }
}

impl ProcessInventoryProvider for StubOnlyProcessAttributionProvider {
    fn refresh_process_inventory(&mut self) -> Result<ProcessSnapshot, AttributionProviderError> {
        self.precheck_command(IpcCommand::RefreshProcessInventory)?;
        self.process_snapshot = ProcessSnapshot::new(stub_process_contexts()?);
        self.process_snapshot.validate()?;
        Ok(self.process_snapshot.clone())
    }

    fn process_snapshot(&self) -> Result<ProcessSnapshot, AttributionProviderError> {
        self.precheck_command(IpcCommand::ListProcessSnapshot)?;
        self.process_snapshot.validate()?;
        Ok(self.process_snapshot.clone())
    }
}

impl ConnectionSnapshotProvider for StubOnlyProcessAttributionProvider {
    fn connection_snapshot(&self) -> Result<ConnectionSnapshot, AttributionProviderError> {
        self.precheck_command(IpcCommand::ListConnectionSnapshot)?;
        self.connection_snapshot.validate()?;
        Ok(self.connection_snapshot.clone())
    }
}

impl FlowAttributionProvider for StubOnlyProcessAttributionProvider {
    fn attribute_flow(
        &self,
        flow: &FlowRecord,
        process_snapshot: &ProcessSnapshot,
        connection_snapshot: &ConnectionSnapshot,
    ) -> Result<AttributionResult, AttributionProviderError> {
        process_snapshot.validate()?;
        connection_snapshot.validate()?;

        let mut attribution = FlowAttribution::unknown(flow.flow_id.clone());
        attribution.local_ip = Some(flow.src_ip);
        attribution.local_port = Some(flow.src_port);
        attribution.remote_ip = Some(flow.dst_ip);
        attribution.remote_port = Some(flow.dst_port);
        attribution.collection_mode = CollectionMode::Mock;
        attribution.visibility_level = VisibilityLevel::Reduced;
        attribution.known_limitations =
            limitation_messages(AttributionLimitation::default_visible_set());
        let mut result_limitations = AttributionLimitation::default_visible_set();

        if let Some(connection) = matching_connection(flow, connection_snapshot) {
            attribution.local_ip = Some(connection.local_ip);
            attribution.local_port = Some(connection.local_port);
            attribution.remote_ip = Some(connection.remote_ip);
            attribution.remote_port = Some(connection.remote_port);
            attribution.collection_mode = connection.collection_mode.clone();
            attribution.visibility_level = connection.visibility_level.clone();
            result_limitations = limitations_for_connection(flow, connection, None);
            attribution.known_limitations = limitation_messages(result_limitations.clone());

            if let Some(process_ref) = &connection.candidate_process_ref {
                if let Some(process) = process_snapshot
                    .processes
                    .iter()
                    .find(|process| &process.process_context_id == process_ref)
                {
                    attribution.process_ref = Some(process.process_context_id.clone());
                    attribution.os_process_id = Some(process.os_process_id);
                    attribution.process_start_time = Some(process.process_start_time.clone());
                    attribution.process_path_protected = process.process_path_protected.clone();
                    attribution.process_hash = process.process_hash.clone();
                    attribution.signer_status = process.signer_status.clone();
                    attribution.parent_process_ref = process.parent_process_ref.clone();
                    attribution.user_session_ref = process.user_session_ref.clone();
                    attribution.attribution_method = match flow.protocol {
                        TransportProtocol::Tcp => AttributionMethod::TcpEndpointSnapshot,
                        TransportProtocol::Udp => AttributionMethod::UdpEndpointSnapshot,
                        _ => AttributionMethod::ConnectionTableCorrelation,
                    };
                    attribution.attribution_confidence =
                        confidence_for_connection(flow, connection, process);
                    attribution.attribution_status = status_for_confidence(
                        &attribution.attribution_confidence,
                        connection,
                        process,
                    );
                    result_limitations =
                        limitations_for_connection(flow, connection, Some(process));
                    attribution.known_limitations = limitation_messages(result_limitations.clone());
                }
            }
        }

        if attribution.process_ref.is_none() {
            attribution.attribution_status = AttributionStatus::Unknown;
            attribution.attribution_method = AttributionMethod::Unknown;
            attribution.attribution_confidence = AttributionConfidence::Unknown;
            attribution.visibility_level = VisibilityLevel::Unknown;
            result_limitations = limitations_for_unknown_flow(flow);
            attribution.known_limitations = limitation_messages(result_limitations.clone());
        }

        let result = AttributionResult::new(
            attribution,
            "STUB_ONLY best-effort process attribution; not absolute packet-to-process truth",
            result_limitations,
        );
        result.validate()?;
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionProviderError {
    pub error_code: ErrorCode,
    pub message_redacted: String,
    pub field: Option<String>,
    pub retryable: bool,
    pub stub_only: bool,
    pub not_for_production: bool,
}

impl AttributionProviderError {
    pub fn invalid(message_redacted: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::InvalidRequest,
            message_redacted: message_redacted.into(),
            field: Some("process_attribution".to_string()),
            retryable: false,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn privacy_violation(message_redacted: impl Into<String>, field: &'static str) -> Self {
        Self {
            error_code: ErrorCode::PrivacyPolicyViolation,
            message_redacted: message_redacted.into(),
            field: Some(field.to_string()),
            retryable: false,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn from_ipc(error: crate::ipc::IpcProtocolError) -> Self {
        Self {
            error_code: error.error_code,
            message_redacted: error.message_redacted,
            field: error.field,
            retryable: error.retryable,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn from_decision(decision: &ServiceCommandDecision) -> Self {
        let ipc_error = decision.to_ipc_error();
        Self {
            error_code: ipc_error.error_code,
            message_redacted: ipc_error.message_redacted,
            field: ipc_error.field,
            retryable: ipc_error.retryable,
            stub_only: true,
            not_for_production: true,
        }
    }
}

impl fmt::Display for AttributionProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_code, self.message_redacted)
    }
}

impl std::error::Error for AttributionProviderError {}

fn validate_process_context(process: &ProcessContext) -> Result<(), AttributionProviderError> {
    validate_attribution_text("process_name", &process.process_name)?;
    if let Some(path) = &process.process_path_protected {
        validate_attribution_text("process_path_protected", path)?;
    }
    if let Some(hash) = &process.process_hash {
        validate_attribution_text("process_hash", hash)?;
    }
    if let Some(user_session) = &process.user_session_ref {
        if let Some(user_pseudonym) = &user_session.user_pseudonym {
            validate_attribution_text("user_pseudonym", user_pseudonym)?;
        }
        if let Some(user_sid_hash) = &user_session.user_sid_hash {
            validate_attribution_text("user_sid_hash", user_sid_hash)?;
        }
        if let Some(session_name) = &user_session.session_name_protected {
            validate_attribution_text("session_name_protected", session_name)?;
        }
    }
    if process.known_limitations.is_empty() {
        return Err(AttributionProviderError::invalid(
            "process context must expose known limitations",
        ));
    }
    if matches!(process.visibility_level, VisibilityLevel::Full) {
        return Err(AttributionProviderError::invalid(
            "STUB_ONLY process context must not claim full visibility",
        ));
    }
    for limitation in &process.known_limitations {
        validate_attribution_text("known_limitations", limitation)?;
    }
    Ok(())
}

fn validate_attribution_text(
    field: &'static str,
    value: &str,
) -> Result<(), AttributionProviderError> {
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '/', '='], "_");
    for marker in [
        "raw_command_line",
        "command_line_with",
        "process_memory",
        "private_file",
        "credential",
        "authorization",
        "api_key",
        "secret",
        "private_key",
        "password",
        "cookie",
        "token",
        "payload",
        "http_body",
    ] {
        if normalized.contains(marker) {
            return Err(AttributionProviderError::privacy_violation(
                "process attribution metadata contains a forbidden private-content marker",
                field,
            ));
        }
    }
    Ok(())
}

fn stub_process_contexts() -> Result<Vec<ProcessContext>, AttributionProviderError> {
    let mut browser = ProcessContext::new(4_240, "browser_stub");
    browser.process_path_protected = Some("pathref_browser_stub".to_string());
    browser.process_hash = Some("sha256_stub_browser_process".to_string());
    browser.signer_status = SignerStatus::Signed;
    browser.visibility_level = VisibilityLevel::Reduced;
    browser.collection_mode = CollectionMode::Mock;
    browser.known_limitations = limitation_messages(vec![
        AttributionLimitation::BrowserMultiplexing,
        AttributionLimitation::VpnOrProxyMayShiftDestination,
        AttributionLimitation::PacketCaptureIsNotAbsoluteTruth,
        AttributionLimitation::StubOnlyFixture,
    ]);
    browser.user_session_ref = Some(UserSessionRef {
        user_session_id: sentinel_contracts::UserSessionId::new_v4(),
        user_pseudonym: Some("userref_local".to_string()),
        user_sid_hash: Some("sid_hash_stub".to_string()),
        session_name_protected: Some("local_interactive".to_string()),
        logon_time: Some(Timestamp::now()),
        visibility_level: VisibilityLevel::Reduced,
    });

    let mut service = ProcessContext::new(1_188, "sync_agent_stub");
    service.process_path_protected = Some("pathref_sync_agent".to_string());
    service.process_hash = Some("sha256_stub_sync_agent".to_string());
    service.signer_status = SignerStatus::Unknown;
    service.visibility_level = VisibilityLevel::Reduced;
    service.collection_mode = CollectionMode::Mock;
    service.trust_score = ProcessTrustScore::default();
    service.known_limitations = limitation_messages(vec![
        AttributionLimitation::ShortLivedProcessMayExit,
        AttributionLimitation::ReducedVisibilityMode,
        AttributionLimitation::PacketCaptureIsNotAbsoluteTruth,
        AttributionLimitation::StubOnlyFixture,
    ]);

    validate_process_context(&browser)?;
    validate_process_context(&service)?;
    Ok(vec![browser, service])
}

fn stub_connection_records(
    snapshot: &ProcessSnapshot,
) -> Result<Vec<ConnectionSnapshotRecord>, AttributionProviderError> {
    let browser_ref = snapshot
        .processes
        .first()
        .map(|process| process.process_context_id.clone());
    let service_ref = snapshot
        .processes
        .get(1)
        .map(|process| process.process_context_id.clone());

    let records = vec![
        ConnectionSnapshotRecord {
            local_ip: parse_ip("192.0.2.10")?,
            local_port: 49_152,
            remote_ip: parse_ip("198.51.100.24")?,
            remote_port: 443,
            protocol: TransportProtocol::Tcp,
            direction: NetworkDirection::Outbound,
            candidate_process_ref: browser_ref,
            os_process_id: Some(4_240),
            observed_at: Timestamp::now(),
            visibility_level: VisibilityLevel::Reduced,
            collection_mode: CollectionMode::Mock,
            known_limitations: vec![
                AttributionLimitation::BrowserMultiplexing,
                AttributionLimitation::PacketCaptureIsNotAbsoluteTruth,
                AttributionLimitation::StubOnlyFixture,
            ],
        },
        ConnectionSnapshotRecord {
            local_ip: parse_ip("192.0.2.10")?,
            local_port: 53_000,
            remote_ip: parse_ip("203.0.113.53")?,
            remote_port: 53,
            protocol: TransportProtocol::Udp,
            direction: NetworkDirection::Outbound,
            candidate_process_ref: service_ref,
            os_process_id: Some(1_188),
            observed_at: Timestamp::now(),
            visibility_level: VisibilityLevel::MetadataOnly,
            collection_mode: CollectionMode::Mock,
            known_limitations: vec![
                AttributionLimitation::UdpStateless,
                AttributionLimitation::ReducedVisibilityMode,
                AttributionLimitation::PacketCaptureIsNotAbsoluteTruth,
                AttributionLimitation::StubOnlyFixture,
            ],
        },
    ];

    for record in &records {
        record.validate()?;
    }
    Ok(records)
}

fn matching_connection<'a>(
    flow: &FlowRecord,
    snapshot: &'a ConnectionSnapshot,
) -> Option<&'a ConnectionSnapshotRecord> {
    snapshot.connections.iter().find(|connection| {
        connection.protocol == flow.protocol
            && connection.local_ip == flow.src_ip
            && connection.local_port == flow.src_port
            && connection.remote_ip == flow.dst_ip
            && connection.remote_port == flow.dst_port
    })
}

fn confidence_for_connection(
    flow: &FlowRecord,
    connection: &ConnectionSnapshotRecord,
    process: &ProcessContext,
) -> AttributionConfidence {
    if process.process_end_time.is_some() {
        return AttributionConfidence::Low;
    }
    if matches!(flow.protocol, TransportProtocol::Udp) {
        return AttributionConfidence::Low;
    }
    if matches!(connection.visibility_level, VisibilityLevel::MetadataOnly) {
        return AttributionConfidence::Medium;
    }
    AttributionConfidence::High
}

fn status_for_confidence(
    confidence: &AttributionConfidence,
    connection: &ConnectionSnapshotRecord,
    process: &ProcessContext,
) -> AttributionStatus {
    if process.process_end_time.is_some() {
        return AttributionStatus::ExpiredProcess;
    }
    if matches!(connection.visibility_level, VisibilityLevel::Degraded) {
        return AttributionStatus::InsufficientVisibility;
    }
    match confidence {
        AttributionConfidence::High => AttributionStatus::Confirmed,
        AttributionConfidence::Medium => AttributionStatus::Probable,
        AttributionConfidence::Low => AttributionStatus::Possible,
        AttributionConfidence::Unknown => AttributionStatus::Unknown,
    }
}

fn limitations_for_connection(
    flow: &FlowRecord,
    connection: &ConnectionSnapshotRecord,
    process: Option<&ProcessContext>,
) -> Vec<AttributionLimitation> {
    let mut limitations = Vec::new();
    if matches!(flow.protocol, TransportProtocol::Udp) {
        limitations.push(AttributionLimitation::UdpStateless);
    }
    if matches!(
        connection.visibility_level,
        VisibilityLevel::Reduced | VisibilityLevel::Degraded | VisibilityLevel::MetadataOnly
    ) {
        limitations.push(AttributionLimitation::ReducedVisibilityMode);
    }
    for limitation in &connection.known_limitations {
        push_unique_limitation(&mut limitations, limitation.clone());
    }
    if let Some(process) = process {
        if process.process_end_time.is_some() {
            push_unique_limitation(
                &mut limitations,
                AttributionLimitation::ShortLivedProcessMayExit,
            );
        }
        if matches!(
            process.visibility_level,
            VisibilityLevel::Reduced | VisibilityLevel::Degraded | VisibilityLevel::MetadataOnly
        ) {
            push_unique_limitation(
                &mut limitations,
                AttributionLimitation::ReducedVisibilityMode,
            );
        }
        for message in &process.known_limitations {
            if let Some(limitation) = AttributionLimitation::from_message(message) {
                push_unique_limitation(&mut limitations, limitation);
            }
        }
    }
    push_unique_limitation(
        &mut limitations,
        AttributionLimitation::PacketCaptureIsNotAbsoluteTruth,
    );
    push_unique_limitation(&mut limitations, AttributionLimitation::StubOnlyFixture);
    limitations
}

fn limitations_for_unknown_flow(flow: &FlowRecord) -> Vec<AttributionLimitation> {
    let mut limitations = Vec::new();
    if matches!(flow.protocol, TransportProtocol::Udp) {
        limitations.push(AttributionLimitation::UdpStateless);
    }
    push_unique_limitation(
        &mut limitations,
        AttributionLimitation::ReducedVisibilityMode,
    );
    push_unique_limitation(
        &mut limitations,
        AttributionLimitation::PacketCaptureIsNotAbsoluteTruth,
    );
    push_unique_limitation(&mut limitations, AttributionLimitation::StubOnlyFixture);
    limitations
}

fn push_unique_limitation(
    limitations: &mut Vec<AttributionLimitation>,
    limitation: AttributionLimitation,
) {
    if !limitations.contains(&limitation) {
        limitations.push(limitation);
    }
}

fn parse_ip(value: &str) -> Result<IpAddress, AttributionProviderError> {
    IpAddress::parse_str(value)
        .map_err(|error| AttributionProviderError::invalid(format!("fixture IP invalid: {error}")))
}

fn limitation_messages(limitations: Vec<AttributionLimitation>) -> Vec<String> {
    limitations
        .into_iter()
        .map(|limitation| limitation.message_redacted().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow_for_stub_tcp() -> FlowRecord {
        FlowRecord::new(
            parse_ip("192.0.2.10").expect("local ip"),
            49_152,
            parse_ip("198.51.100.24").expect("remote ip"),
            443,
            TransportProtocol::Tcp,
            NetworkDirection::Outbound,
        )
    }

    fn flow_for_stub_udp() -> FlowRecord {
        FlowRecord::new(
            parse_ip("192.0.2.10").expect("local ip"),
            53_000,
            parse_ip("203.0.113.53").expect("remote ip"),
            53,
            TransportProtocol::Udp,
            NetworkDirection::Outbound,
        )
    }

    #[test]
    fn process_and_connection_snapshots_are_stub_labeled_and_privacy_safe() {
        let provider = StubOnlyProcessAttributionProvider::new().expect("provider");
        let processes = provider.process_snapshot().expect("process snapshot");
        let connections = provider.connection_snapshot().expect("connection snapshot");

        assert!(processes.labels.contains(&STUB_ONLY_LABEL.to_string()));
        assert!(connections
            .labels
            .contains(&NOT_FOR_PRODUCTION_LABEL.to_string()));
        assert!(!processes.processes.is_empty());
        assert!(!connections.connections.is_empty());
        assert!(processes.processes.iter().all(|process| {
            process.process_path_protected.is_some()
                && !process.known_limitations.is_empty()
                && process.collection_mode == CollectionMode::Mock
        }));
        assert!(processes.validate().is_ok());
        assert!(connections.validate().is_ok());
    }

    #[test]
    fn default_visible_limitations_cover_required_ui_and_report_warnings() {
        let limitations = AttributionLimitation::default_visible_set();

        assert!(limitations.contains(&AttributionLimitation::UdpStateless));
        assert!(limitations.contains(&AttributionLimitation::VpnOrProxyMayShiftDestination));
        assert!(limitations.contains(&AttributionLimitation::BrowserMultiplexing));
        assert!(limitations.contains(&AttributionLimitation::ProtectedProcessMetadataHidden));
        assert!(limitations.contains(&AttributionLimitation::ShortLivedProcessMayExit));
        assert!(limitations.contains(&AttributionLimitation::ReducedVisibilityMode));
        assert!(limitations.contains(&AttributionLimitation::PacketCaptureIsNotAbsoluteTruth));
        assert!(limitations.contains(&AttributionLimitation::StubOnlyFixture));
    }

    #[test]
    fn attribution_result_includes_required_uncertainty_fields() {
        let provider = StubOnlyProcessAttributionProvider::new().expect("provider");
        let flow = flow_for_stub_tcp();
        let processes = provider.process_snapshot().expect("process snapshot");
        let connections = provider.connection_snapshot().expect("connection snapshot");
        let result = provider
            .attribute_flow(&flow, &processes, &connections)
            .expect("attribution");

        assert_eq!(result.status, AttributionStatus::Confirmed);
        assert_eq!(result.method, AttributionMethod::TcpEndpointSnapshot);
        assert_eq!(result.confidence, AttributionConfidence::High);
        assert_eq!(result.visibility_level, VisibilityLevel::Reduced);
        assert_eq!(result.collection_mode, CollectionMode::Mock);
        assert!(!result.known_limitations.is_empty());
        assert_eq!(
            limitation_messages(result.known_limitations.clone()),
            result.attribution.known_limitations
        );
        assert!(!result.absolute_truth_claimed);
        assert!(result.validate().is_ok());
    }

    #[test]
    fn udp_attribution_is_low_confidence_and_carries_udp_limitations() {
        let provider = StubOnlyProcessAttributionProvider::new().expect("provider");
        let processes = provider.process_snapshot().expect("process snapshot");
        let connections = provider.connection_snapshot().expect("connection snapshot");
        let result = provider
            .attribute_flow(&flow_for_stub_udp(), &processes, &connections)
            .expect("udp attribution");

        assert_eq!(result.status, AttributionStatus::Possible);
        assert_eq!(result.method, AttributionMethod::UdpEndpointSnapshot);
        assert_eq!(result.confidence, AttributionConfidence::Low);
        assert_eq!(result.visibility_level, VisibilityLevel::MetadataOnly);
        assert!(result
            .known_limitations
            .contains(&AttributionLimitation::UdpStateless));
        assert!(result
            .known_limitations
            .contains(&AttributionLimitation::ReducedVisibilityMode));
        assert_eq!(
            limitation_messages(result.known_limitations.clone()),
            result.attribution.known_limitations
        );
        assert!(result.validate().is_ok());
    }

    #[test]
    fn attribution_examples_cover_all_required_statuses() {
        let provider = StubOnlyProcessAttributionProvider::new().expect("provider");
        let examples = provider.attribution_examples().expect("examples");
        let statuses = examples
            .iter()
            .map(|example| example.status.clone())
            .collect::<Vec<_>>();

        assert!(statuses.contains(&AttributionStatus::Confirmed));
        assert!(statuses.contains(&AttributionStatus::Probable));
        assert!(statuses.contains(&AttributionStatus::Possible));
        assert!(statuses.contains(&AttributionStatus::Unknown));
        assert!(statuses.contains(&AttributionStatus::Conflict));
        assert!(statuses.contains(&AttributionStatus::ExpiredProcess));
        assert!(statuses.contains(&AttributionStatus::InsufficientVisibility));
        assert!(examples.iter().all(|example| example.validate().is_ok()));
    }

    #[test]
    fn unknown_flow_does_not_claim_process_truth() {
        let provider = StubOnlyProcessAttributionProvider::new().expect("provider");
        let flow = FlowRecord::new(
            parse_ip("192.0.2.10").expect("local ip"),
            40_000,
            parse_ip("203.0.113.99").expect("remote ip"),
            8443,
            TransportProtocol::Tcp,
            NetworkDirection::Outbound,
        );
        let processes = provider.process_snapshot().expect("process snapshot");
        let connections = provider.connection_snapshot().expect("connection snapshot");
        let result = provider
            .attribute_flow(&flow, &processes, &connections)
            .expect("attribution");

        assert_eq!(result.status, AttributionStatus::Unknown);
        assert_eq!(result.confidence, AttributionConfidence::Unknown);
        assert!(result.attribution.process_ref.is_none());
        assert!(result
            .known_limitations
            .contains(&AttributionLimitation::ReducedVisibilityMode));
        assert_eq!(
            limitation_messages(result.known_limitations.clone()),
            result.attribution.known_limitations
        );
        assert!(!result.absolute_truth_claimed);
    }

    #[test]
    fn attribution_result_rejects_limitation_summary_mismatch() {
        let provider = StubOnlyProcessAttributionProvider::new().expect("provider");
        let processes = provider.process_snapshot().expect("process snapshot");
        let connections = provider.connection_snapshot().expect("connection snapshot");
        let mut result = provider
            .attribute_flow(&flow_for_stub_tcp(), &processes, &connections)
            .expect("attribution");

        result.known_limitations = vec![AttributionLimitation::StubOnlyFixture];
        assert_eq!(
            result
                .validate()
                .expect_err("limitation mismatch rejected")
                .error_code,
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn privacy_markers_are_rejected_from_process_metadata() {
        let mut process = ProcessContext::new(9_999, "bad_process");
        process.process_path_protected = Some("raw_command_line with secret".to_string());
        process.visibility_level = VisibilityLevel::Reduced;
        process.collection_mode = CollectionMode::Mock;
        process.known_limitations =
            limitation_messages(vec![AttributionLimitation::StubOnlyFixture]);

        assert_eq!(
            validate_process_context(&process)
                .expect_err("private marker rejected")
                .error_code,
            ErrorCode::PrivacyPolicyViolation
        );
    }

    #[test]
    fn service_precheck_failures_reject_refresh() {
        let mut provider = StubOnlyProcessAttributionProvider::with_precheck(
            PrivilegedCommandPrecheck::stub_only(),
        )
        .expect("provider");
        let error = provider
            .refresh_process_inventory()
            .expect_err("degraded service rejects refresh");

        assert_eq!(error.error_code, ErrorCode::ServiceUnavailable);
        assert!(error.stub_only);
    }
}
