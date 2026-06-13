//! STUB_ONLY metadata-first capture adapter boundary.
//!
//! NOT_FOR_PRODUCTION: this module models capture control, filtering, health,
//! stats, and packet metadata batches without opening driver handles, exposing
//! packet bytes, persisting private content, or streaming unbounded data.

use crate::ipc::{command_spec, IpcCaller, IpcCommand, IpcRequestEnvelope};
use crate::security::{
    PrivilegedCommandPrecheck, SensitiveCommandAudit, ServiceCommandAllowlist,
    ServiceCommandDecision, ServiceDegradedState,
};
use crate::{NOT_FOR_PRODUCTION_LABEL, STUB_ONLY_LABEL};
pub use sentinel_contracts::CaptureSource;
use sentinel_contracts::{
    CollectionMode, ErrorCode, ForensicScope, IpAddress, NetworkDirection, PacketFlags,
    PacketRecord, PrivacyClass, QualityScore, SchemaVersion, Timestamp, TraceId, TransportProtocol,
    VisibilityLevel,
};
use sentinel_platform::ObservabilityHealthStatus;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt;
use uuid::Uuid;

pub const CAPTURE_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
pub const DEFAULT_CAPTURE_BATCH_LIMIT: usize = 64;
pub const MAX_CAPTURE_BATCH_RECORDS: usize = 1_024;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CaptureSessionId(Uuid);

impl CaptureSessionId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for CaptureSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PacketMetadataBatchId(Uuid);

impl PacketMetadataBatchId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for PacketMetadataBatchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSessionState {
    Created,
    Running,
    Paused,
    Stopped,
    Degraded,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureDegradedReason {
    StubOnlyAdapter,
    DriverUnavailable,
    CaptureNotRunning,
    AdapterPaused,
    InvalidFilter,
    DropRateHigh,
    IpcUnavailable,
    PermissionDenied,
    ReducedVisibility,
    UnsupportedRealCapture,
    PrivacyPolicyRejected,
}

impl CaptureDegradedReason {
    pub fn message_redacted(&self) -> &'static str {
        match self {
            Self::StubOnlyAdapter => "STUB_ONLY capture adapter emits fixture metadata only",
            Self::DriverUnavailable => "capture driver is unavailable",
            Self::CaptureNotRunning => "capture session is not running",
            Self::AdapterPaused => "capture adapter is paused",
            Self::InvalidFilter => "capture filter is invalid",
            Self::DropRateHigh => "capture drop rate is above configured threshold",
            Self::IpcUnavailable => "service IPC precheck is unavailable",
            Self::PermissionDenied => "capture command permission was denied",
            Self::ReducedVisibility => "capture is operating with reduced visibility",
            Self::UnsupportedRealCapture => "real capture implementation is not present",
            Self::PrivacyPolicyRejected => "capture privacy policy rejected private content",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureDestinationFilter {
    pub ip: Option<IpAddress>,
    pub port: Option<u16>,
    pub domain_protected: Option<String>,
}

impl CaptureDestinationFilter {
    pub fn single_ip(ip: IpAddress, port: Option<u16>) -> Self {
        Self {
            ip: Some(ip),
            port,
            domain_protected: None,
        }
    }

    pub fn validate(&self) -> Result<(), CaptureAdapterError> {
        if let Some(domain) = &self.domain_protected {
            validate_capture_text("domain_protected", domain)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureFilter {
    pub directions: Vec<NetworkDirection>,
    pub protocols: Vec<TransportProtocol>,
    pub interface_ids: Vec<String>,
    pub destination: Option<CaptureDestinationFilter>,
    pub local_process_hint_redacted: Option<String>,
    pub forensic_scope: Option<ForensicScope>,
    pub metadata_only: bool,
    pub allow_packet_bytes_persistence: bool,
    pub allow_payload_persistence: bool,
    pub allow_http_body_persistence: bool,
    pub max_batch_records: usize,
    pub schema_version: SchemaVersion,
}

impl CaptureFilter {
    pub fn metadata_only_default() -> Self {
        Self {
            directions: vec![NetworkDirection::Inbound, NetworkDirection::Outbound],
            protocols: vec![TransportProtocol::Tcp, TransportProtocol::Udp],
            interface_ids: Vec::new(),
            destination: None,
            local_process_hint_redacted: None,
            forensic_scope: None,
            metadata_only: true,
            allow_packet_bytes_persistence: false,
            allow_payload_persistence: false,
            allow_http_body_persistence: false,
            max_batch_records: DEFAULT_CAPTURE_BATCH_LIMIT,
            schema_version: CAPTURE_SCHEMA_VERSION,
        }
    }

    pub fn forensic_selected_scope(scope: ForensicScope) -> Self {
        let mut filter = Self::metadata_only_default();
        filter.forensic_scope = Some(scope);
        filter
    }

    pub fn validate(&self) -> Result<(), CaptureAdapterError> {
        if self.schema_version != CAPTURE_SCHEMA_VERSION {
            return Err(CaptureAdapterError::invalid_filter(
                "capture filter schema version is unsupported",
            ));
        }
        if !self.metadata_only
            || self.allow_packet_bytes_persistence
            || self.allow_payload_persistence
            || self.allow_http_body_persistence
        {
            return Err(CaptureAdapterError::privacy_violation(
                "capture filter must remain metadata-first in normal mode",
            ));
        }
        if self.directions.is_empty() {
            return Err(CaptureAdapterError::invalid_filter(
                "capture filter must include at least one direction",
            ));
        }
        if self.protocols.is_empty() {
            return Err(CaptureAdapterError::invalid_filter(
                "capture filter must include at least one protocol",
            ));
        }
        if self.max_batch_records == 0 || self.max_batch_records > MAX_CAPTURE_BATCH_RECORDS {
            return Err(CaptureAdapterError::invalid_filter(
                "capture filter batch bound is invalid",
            ));
        }
        for interface_id in &self.interface_ids {
            validate_capture_text("interface_id", interface_id)?;
        }
        if let Some(process_hint) = &self.local_process_hint_redacted {
            validate_capture_text("local_process_hint_redacted", process_hint)?;
        }
        if let Some(destination) = &self.destination {
            destination.validate()?;
        }
        if let Some(scope) = &self.forensic_scope {
            validate_capture_text("forensic_scope_ref", &scope.scope_ref)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CaptureStats {
    pub capture_source: CaptureSource,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub dropped_packets: u64,
    pub malformed_packets: u64,
    pub batches_emitted: u64,
    pub packet_rate_per_second: Option<f64>,
    pub drop_rate: Option<f64>,
    pub last_packet_time: Option<Timestamp>,
    pub metadata_only: bool,
    pub schema_version: SchemaVersion,
}

impl CaptureStats {
    pub fn empty(capture_source: CaptureSource) -> Self {
        Self {
            capture_source,
            total_packets: 0,
            total_bytes: 0,
            dropped_packets: 0,
            malformed_packets: 0,
            batches_emitted: 0,
            packet_rate_per_second: Some(0.0),
            drop_rate: Some(0.0),
            last_packet_time: None,
            metadata_only: true,
            schema_version: CAPTURE_SCHEMA_VERSION,
        }
    }

    pub fn validate(&self) -> Result<(), CaptureAdapterError> {
        if self.schema_version != CAPTURE_SCHEMA_VERSION {
            return Err(CaptureAdapterError::invalid_filter(
                "capture stats schema version is unsupported",
            ));
        }
        if !self.metadata_only {
            return Err(CaptureAdapterError::privacy_violation(
                "capture stats must be metadata-only",
            ));
        }
        if let Some(rate) = self.packet_rate_per_second {
            if !rate.is_finite() || rate < 0.0 {
                return Err(CaptureAdapterError::invalid_filter(
                    "packet rate must be finite and non-negative",
                ));
            }
        }
        if let Some(drop_rate) = self.drop_rate {
            if !drop_rate.is_finite() || !(0.0..=1.0).contains(&drop_rate) {
                return Err(CaptureAdapterError::invalid_filter(
                    "drop rate must be between zero and one",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CaptureHealth {
    pub capture_source: CaptureSource,
    pub driver_loaded: bool,
    pub capture_running: bool,
    pub packet_rate_per_second: Option<f64>,
    pub drop_rate: Option<f64>,
    pub last_packet_time: Option<Timestamp>,
    pub degraded_reason: Option<CaptureDegradedReason>,
    pub status: ObservabilityHealthStatus,
    pub metadata_only: bool,
    pub reduced_visibility: bool,
    pub labels: Vec<String>,
    pub observed_at: Timestamp,
    pub schema_version: SchemaVersion,
}

impl CaptureHealth {
    pub fn validate(&self) -> Result<(), CaptureAdapterError> {
        if self.schema_version != CAPTURE_SCHEMA_VERSION {
            return Err(CaptureAdapterError::invalid_filter(
                "capture health schema version is unsupported",
            ));
        }
        if !self.metadata_only {
            return Err(CaptureAdapterError::privacy_violation(
                "capture health must be metadata-only",
            ));
        }
        if let Some(rate) = self.packet_rate_per_second {
            if !rate.is_finite() || rate < 0.0 {
                return Err(CaptureAdapterError::invalid_filter(
                    "capture health packet rate is invalid",
                ));
            }
        }
        if let Some(drop_rate) = self.drop_rate {
            if !drop_rate.is_finite() || !(0.0..=1.0).contains(&drop_rate) {
                return Err(CaptureAdapterError::invalid_filter(
                    "capture health drop rate is invalid",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CaptureSession {
    pub session_id: CaptureSessionId,
    pub capture_source: CaptureSource,
    pub filter: CaptureFilter,
    pub state: CaptureSessionState,
    pub started_at: Timestamp,
    pub paused_at: Option<Timestamp>,
    pub stopped_at: Option<Timestamp>,
    pub metadata_only: bool,
    pub driver_handle_exposed: bool,
    pub packet_bytes_persistence_allowed: bool,
    pub payload_persistence_allowed: bool,
    pub http_body_persistence_allowed: bool,
    pub replacement_task: String,
    pub labels: Vec<String>,
    pub schema_version: SchemaVersion,
}

impl CaptureSession {
    pub fn new(capture_source: CaptureSource, filter: CaptureFilter) -> Self {
        Self {
            session_id: CaptureSessionId::new_v4(),
            capture_source,
            filter,
            state: CaptureSessionState::Created,
            started_at: Timestamp::now(),
            paused_at: None,
            stopped_at: None,
            metadata_only: true,
            driver_handle_exposed: false,
            packet_bytes_persistence_allowed: false,
            payload_persistence_allowed: false,
            http_body_persistence_allowed: false,
            replacement_task: "real capture adapter implementation after metadata pipeline"
                .to_string(),
            labels: vec![
                STUB_ONLY_LABEL.to_string(),
                NOT_FOR_PRODUCTION_LABEL.to_string(),
            ],
            schema_version: CAPTURE_SCHEMA_VERSION,
        }
    }

    pub fn validate(&self) -> Result<(), CaptureAdapterError> {
        if self.schema_version != CAPTURE_SCHEMA_VERSION {
            return Err(CaptureAdapterError::invalid_filter(
                "capture session schema version is unsupported",
            ));
        }
        self.filter.validate()?;
        if !self.metadata_only
            || self.driver_handle_exposed
            || self.packet_bytes_persistence_allowed
            || self.payload_persistence_allowed
            || self.http_body_persistence_allowed
        {
            return Err(CaptureAdapterError::privacy_violation(
                "capture session exposes forbidden private content capability",
            ));
        }
        validate_capture_text("replacement_task", &self.replacement_task)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PacketMetadataBatch {
    pub batch_id: PacketMetadataBatchId,
    pub session_id: CaptureSessionId,
    pub capture_source: CaptureSource,
    pub sequence_number: u64,
    pub records: Vec<PacketRecord>,
    pub stats: CaptureStats,
    pub emitted_at: Timestamp,
    pub max_records: usize,
    pub bounded: bool,
    pub metadata_only: bool,
    pub packet_bytes_included: bool,
    pub payload_bytes_included: bool,
    pub http_body_included: bool,
    pub privacy_class: PrivacyClass,
    pub trace_id: Option<TraceId>,
    pub labels: Vec<String>,
    pub schema_version: SchemaVersion,
}

impl PacketMetadataBatch {
    pub fn new(
        session_id: CaptureSessionId,
        capture_source: CaptureSource,
        sequence_number: u64,
        records: Vec<PacketRecord>,
        stats: CaptureStats,
        max_records: usize,
    ) -> Self {
        Self {
            batch_id: PacketMetadataBatchId::new_v4(),
            session_id,
            capture_source,
            sequence_number,
            records,
            stats,
            emitted_at: Timestamp::now(),
            max_records,
            bounded: true,
            metadata_only: true,
            packet_bytes_included: false,
            payload_bytes_included: false,
            http_body_included: false,
            privacy_class: PrivacyClass::Internal,
            trace_id: None,
            labels: vec![
                STUB_ONLY_LABEL.to_string(),
                NOT_FOR_PRODUCTION_LABEL.to_string(),
            ],
            schema_version: CAPTURE_SCHEMA_VERSION,
        }
    }

    pub fn validate(&self) -> Result<(), CaptureAdapterError> {
        if self.schema_version != CAPTURE_SCHEMA_VERSION {
            return Err(CaptureAdapterError::invalid_filter(
                "packet metadata batch schema version is unsupported",
            ));
        }
        if !self.bounded || self.max_records == 0 || self.max_records > MAX_CAPTURE_BATCH_RECORDS {
            return Err(CaptureAdapterError::invalid_filter(
                "packet metadata batch bound is invalid",
            ));
        }
        if self.records.len() > self.max_records {
            return Err(CaptureAdapterError::invalid_filter(
                "packet metadata batch exceeds configured record bound",
            ));
        }
        if !self.metadata_only
            || self.packet_bytes_included
            || self.payload_bytes_included
            || self.http_body_included
        {
            return Err(CaptureAdapterError::privacy_violation(
                "packet metadata batch must not include private content bytes",
            ));
        }
        if !matches!(
            self.privacy_class,
            PrivacyClass::Internal | PrivacyClass::Public
        ) {
            return Err(CaptureAdapterError::privacy_violation(
                "packet metadata batch privacy class is not allowed for normal mode",
            ));
        }
        self.stats.validate()?;
        for record in &self.records {
            validate_packet_record(record)?;
        }
        Ok(())
    }
}

pub trait CaptureAdapter {
    fn capture_source(&self) -> CaptureSource;
    fn current_filter(&self) -> &CaptureFilter;
    fn start(&mut self, filter: CaptureFilter) -> Result<CaptureSession, CaptureAdapterError>;
    fn stop(&mut self) -> Result<CaptureSession, CaptureAdapterError>;
    fn pause(&mut self) -> Result<CaptureSession, CaptureAdapterError>;
    fn resume(&mut self) -> Result<CaptureSession, CaptureAdapterError>;
    fn update_filter(
        &mut self,
        filter: CaptureFilter,
    ) -> Result<CaptureSession, CaptureAdapterError>;
    fn read_packet_metadata_batch(
        &mut self,
        max_records: usize,
    ) -> Result<PacketMetadataBatch, CaptureAdapterError>;
    fn stats(&self) -> CaptureStats;
    fn drop_rate(&self) -> Option<f64>;
    fn driver_health(&self) -> CaptureHealth;
}

#[derive(Clone, Debug)]
pub struct StubOnlyCaptureAdapter {
    adapter_name: String,
    filter: CaptureFilter,
    session: Option<CaptureSession>,
    stats: CaptureStats,
    sequence_number: u64,
    precheck: PrivilegedCommandPrecheck,
}

impl StubOnlyCaptureAdapter {
    pub fn new() -> Result<Self, CaptureAdapterError> {
        Ok(Self {
            adapter_name: "STUB_ONLY metadata capture adapter".to_string(),
            filter: CaptureFilter::metadata_only_default(),
            session: None,
            stats: CaptureStats::empty(CaptureSource::Mock),
            sequence_number: 0,
            precheck: PrivilegedCommandPrecheck::new(
                ServiceCommandAllowlist::v1_default().map_err(CaptureAdapterError::from_ipc)?,
                ServiceDegradedState::healthy(),
            ),
        })
    }

    pub fn with_precheck(precheck: PrivilegedCommandPrecheck) -> Result<Self, CaptureAdapterError> {
        Ok(Self {
            precheck,
            ..Self::new()?
        })
    }

    pub fn adapter_name(&self) -> &str {
        &self.adapter_name
    }

    fn precheck_command(
        &self,
        command: IpcCommand,
        audit_target_redacted: &'static str,
    ) -> Result<(), CaptureAdapterError> {
        let spec = command_spec(&command).map_err(CaptureAdapterError::from_ipc)?;
        let request = IpcRequestEnvelope::new(
            IpcCaller::local_core("capture adapter control")
                .map_err(CaptureAdapterError::from_ipc)?,
            command,
            spec.permission_scope,
            json!({
                "target_scope": "capture_metadata",
                "adapter": self.adapter_name,
                "metadata_only": true,
                "bounded": true
            }),
            PrivacyClass::Internal,
            crate::ipc::IpcAuthContext::local_core_stub(),
        );
        let permission_check = self
            .precheck
            .trusted_local_core_permission_check(&request.command);
        let audit = SensitiveCommandAudit::for_request(&request, audit_target_redacted, None);
        let decision = self
            .precheck
            .evaluate_request(&request, &permission_check, Some(&audit));
        if decision.allowed {
            Ok(())
        } else {
            Err(CaptureAdapterError::from_decision(&decision))
        }
    }

    fn session_mut(&mut self) -> Result<&mut CaptureSession, CaptureAdapterError> {
        self.session
            .as_mut()
            .ok_or_else(|| CaptureAdapterError::not_running("capture session has not started"))
    }

    fn session_ref(&self) -> Result<&CaptureSession, CaptureAdapterError> {
        self.session
            .as_ref()
            .ok_or_else(|| CaptureAdapterError::not_running("capture session has not started"))
    }
}

impl CaptureAdapter for StubOnlyCaptureAdapter {
    fn capture_source(&self) -> CaptureSource {
        CaptureSource::Mock
    }

    fn current_filter(&self) -> &CaptureFilter {
        &self.filter
    }

    fn start(&mut self, filter: CaptureFilter) -> Result<CaptureSession, CaptureAdapterError> {
        filter.validate()?;
        self.precheck_command(IpcCommand::StartCapture, "capture metadata start")?;
        let mut session = CaptureSession::new(CaptureSource::Mock, filter.clone());
        session.state = CaptureSessionState::Running;
        session.validate()?;
        self.filter = filter;
        self.session = Some(session.clone());
        Ok(session)
    }

    fn stop(&mut self) -> Result<CaptureSession, CaptureAdapterError> {
        self.precheck_command(IpcCommand::StopCapture, "capture metadata stop")?;
        let mut session = self.session_mut()?.clone();
        session.state = CaptureSessionState::Stopped;
        session.stopped_at = Some(Timestamp::now());
        session.validate()?;
        self.session = Some(session.clone());
        Ok(session)
    }

    fn pause(&mut self) -> Result<CaptureSession, CaptureAdapterError> {
        self.precheck_command(IpcCommand::PauseCapture, "capture metadata pause")?;
        let mut session = self.session_mut()?.clone();
        if !matches!(session.state, CaptureSessionState::Running) {
            return Err(CaptureAdapterError::not_running(
                "capture session must be running before pause",
            ));
        }
        session.state = CaptureSessionState::Paused;
        session.paused_at = Some(Timestamp::now());
        session.validate()?;
        self.session = Some(session.clone());
        Ok(session)
    }

    fn resume(&mut self) -> Result<CaptureSession, CaptureAdapterError> {
        self.precheck_command(IpcCommand::ResumeCapture, "capture metadata resume")?;
        let mut session = self.session_mut()?.clone();
        if !matches!(session.state, CaptureSessionState::Paused) {
            return Err(CaptureAdapterError::not_running(
                "capture session must be paused before resume",
            ));
        }
        session.state = CaptureSessionState::Running;
        session.paused_at = None;
        session.validate()?;
        self.session = Some(session.clone());
        Ok(session)
    }

    fn update_filter(
        &mut self,
        filter: CaptureFilter,
    ) -> Result<CaptureSession, CaptureAdapterError> {
        filter.validate()?;
        self.precheck_command(
            IpcCommand::UpdateCaptureFilter,
            "capture metadata filter update",
        )?;
        let mut session = self.session_mut()?.clone();
        session.filter = filter.clone();
        session.validate()?;
        self.filter = filter;
        self.session = Some(session.clone());
        Ok(session)
    }

    fn read_packet_metadata_batch(
        &mut self,
        max_records: usize,
    ) -> Result<PacketMetadataBatch, CaptureAdapterError> {
        if max_records == 0 {
            return Err(CaptureAdapterError::invalid_filter(
                "packet metadata batch size must be positive",
            ));
        }
        let session = self.session_ref()?.clone();
        if matches!(session.state, CaptureSessionState::Paused) {
            return Err(CaptureAdapterError::adapter_paused());
        }
        if !matches!(session.state, CaptureSessionState::Running) {
            return Err(CaptureAdapterError::not_running(
                "capture session is not running",
            ));
        }

        let max_records = max_records.min(self.filter.max_batch_records);
        let records = filtered_stub_packet_metadata_records(&self.filter, max_records)?;
        let packet_count = records.len() as u64;
        let byte_count = records
            .iter()
            .map(|record| u64::from(record.length_bytes))
            .sum::<u64>();

        self.sequence_number = self.sequence_number.saturating_add(1);
        self.stats.total_packets = self.stats.total_packets.saturating_add(packet_count);
        self.stats.total_bytes = self.stats.total_bytes.saturating_add(byte_count);
        self.stats.batches_emitted = self.stats.batches_emitted.saturating_add(1);
        self.stats.packet_rate_per_second = Some(packet_count as f64);
        self.stats.drop_rate = Some(0.0);
        self.stats.last_packet_time = records.last().map(|record| record.timestamp.clone());
        self.stats.validate()?;

        let batch = PacketMetadataBatch::new(
            session.session_id,
            CaptureSource::Mock,
            self.sequence_number,
            records,
            self.stats.clone(),
            max_records,
        );
        batch.validate()?;
        Ok(batch)
    }

    fn stats(&self) -> CaptureStats {
        self.stats.clone()
    }

    fn drop_rate(&self) -> Option<f64> {
        self.stats.drop_rate
    }

    fn driver_health(&self) -> CaptureHealth {
        let state = self
            .session
            .as_ref()
            .map(|session| session.state.clone())
            .unwrap_or(CaptureSessionState::Stopped);
        let capture_running = matches!(state, CaptureSessionState::Running);
        let status = if capture_running {
            ObservabilityHealthStatus::Degraded
        } else {
            ObservabilityHealthStatus::Unavailable
        };
        let health = CaptureHealth {
            capture_source: CaptureSource::Mock,
            driver_loaded: false,
            capture_running,
            packet_rate_per_second: self.stats.packet_rate_per_second,
            drop_rate: self.stats.drop_rate,
            last_packet_time: self.stats.last_packet_time.clone(),
            degraded_reason: Some(CaptureDegradedReason::StubOnlyAdapter),
            status,
            metadata_only: true,
            reduced_visibility: true,
            labels: vec![
                STUB_ONLY_LABEL.to_string(),
                NOT_FOR_PRODUCTION_LABEL.to_string(),
            ],
            observed_at: Timestamp::now(),
            schema_version: CAPTURE_SCHEMA_VERSION,
        };
        debug_assert!(health.validate().is_ok());
        health
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureAdapterError {
    pub error_code: ErrorCode,
    pub degraded_reason: CaptureDegradedReason,
    pub message_redacted: String,
    pub field: Option<String>,
    pub retryable: bool,
    pub stub_only: bool,
    pub not_for_production: bool,
}

impl CaptureAdapterError {
    pub fn invalid_filter(message_redacted: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::InvalidRequest,
            degraded_reason: CaptureDegradedReason::InvalidFilter,
            message_redacted: message_redacted.into(),
            field: Some("capture_filter".to_string()),
            retryable: false,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn privacy_violation(message_redacted: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::PrivacyPolicyViolation,
            degraded_reason: CaptureDegradedReason::PrivacyPolicyRejected,
            message_redacted: message_redacted.into(),
            field: Some("privacy".to_string()),
            retryable: false,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn not_running(message_redacted: impl Into<String>) -> Self {
        Self {
            error_code: ErrorCode::ServiceUnavailable,
            degraded_reason: CaptureDegradedReason::CaptureNotRunning,
            message_redacted: message_redacted.into(),
            field: Some("capture_session".to_string()),
            retryable: true,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn adapter_paused() -> Self {
        Self {
            error_code: ErrorCode::ServiceUnavailable,
            degraded_reason: CaptureDegradedReason::AdapterPaused,
            message_redacted: CaptureDegradedReason::AdapterPaused
                .message_redacted()
                .to_string(),
            field: Some("capture_session".to_string()),
            retryable: true,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn from_ipc(error: crate::ipc::IpcProtocolError) -> Self {
        Self {
            error_code: error.error_code,
            degraded_reason: CaptureDegradedReason::IpcUnavailable,
            message_redacted: error.message_redacted,
            field: error.field,
            retryable: error.retryable,
            stub_only: true,
            not_for_production: true,
        }
    }

    pub fn from_decision(decision: &ServiceCommandDecision) -> Self {
        let ipc_error = decision.to_ipc_error();
        let degraded_reason = match ipc_error.error_code {
            ErrorCode::PermissionDenied => CaptureDegradedReason::PermissionDenied,
            ErrorCode::PrivacyPolicyViolation => CaptureDegradedReason::PrivacyPolicyRejected,
            ErrorCode::ServiceUnavailable => CaptureDegradedReason::IpcUnavailable,
            _ => CaptureDegradedReason::UnsupportedRealCapture,
        };
        Self {
            error_code: ipc_error.error_code,
            degraded_reason,
            message_redacted: ipc_error.message_redacted,
            field: ipc_error.field,
            retryable: ipc_error.retryable,
            stub_only: true,
            not_for_production: true,
        }
    }
}

impl fmt::Display for CaptureAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_code, self.message_redacted)
    }
}

impl std::error::Error for CaptureAdapterError {}

fn validate_packet_record(record: &PacketRecord) -> Result<(), CaptureAdapterError> {
    if record.length_bytes == 0 {
        return Err(CaptureAdapterError::invalid_filter(
            "packet metadata record length must be positive",
        ));
    }
    if !matches!(record.visibility_level, VisibilityLevel::MetadataOnly) {
        return Err(CaptureAdapterError::privacy_violation(
            "packet metadata record must use metadata-only visibility",
        ));
    }
    if let Some(interface_id) = &record.interface_id {
        validate_capture_text("interface_id", interface_id)?;
    }
    Ok(())
}

fn validate_capture_text(field: &'static str, value: &str) -> Result<(), CaptureAdapterError> {
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '/'], "_");
    for marker in [
        "raw_packet",
        "packet_bytes",
        "payload",
        "http_body",
        "cookie",
        "token",
        "credential",
        "authorization",
        "api_key",
        "secret",
        "private_key",
        "password",
    ] {
        if normalized.contains(marker) {
            return Err(CaptureAdapterError {
                error_code: ErrorCode::PrivacyPolicyViolation,
                degraded_reason: CaptureDegradedReason::PrivacyPolicyRejected,
                message_redacted: "capture metadata contains a forbidden private-content marker"
                    .to_string(),
                field: Some(field.to_string()),
                retryable: false,
                stub_only: true,
                not_for_production: true,
            });
        }
    }
    Ok(())
}

fn filtered_stub_packet_metadata_records(
    filter: &CaptureFilter,
    limit: usize,
) -> Result<Vec<PacketRecord>, CaptureAdapterError> {
    let records = stub_packet_metadata_records(MAX_CAPTURE_BATCH_RECORDS)?;
    records
        .into_iter()
        .filter(|record| packet_record_matches_filter(record, filter))
        .take(limit)
        .map(|record| {
            validate_packet_record(&record)?;
            Ok(record)
        })
        .collect()
}

fn packet_record_matches_filter(record: &PacketRecord, filter: &CaptureFilter) -> bool {
    if !filter.directions.contains(&record.direction) {
        return false;
    }
    if !filter.protocols.contains(&record.protocol) {
        return false;
    }
    if !filter.interface_ids.is_empty()
        && !record
            .interface_id
            .as_ref()
            .is_some_and(|interface_id| filter.interface_ids.contains(interface_id))
    {
        return false;
    }
    if let Some(destination) = &filter.destination {
        if let Some(ip) = destination.ip {
            if record.dst_ip != ip {
                return false;
            }
        }
        if let Some(port) = destination.port {
            if record.dst_port != Some(port) {
                return false;
            }
        }
    }
    true
}

fn stub_packet_metadata_records(limit: usize) -> Result<Vec<PacketRecord>, CaptureAdapterError> {
    let mut records = Vec::new();
    let requested = limit.min(3);
    if requested == 0 {
        return Ok(records);
    }

    let mut first = PacketRecord::new(
        TransportProtocol::Tcp,
        NetworkDirection::Outbound,
        IpAddress::parse_str("192.0.2.10").map_err(|error| {
            CaptureAdapterError::invalid_filter(format!("fixture IP is invalid: {error}"))
        })?,
        IpAddress::parse_str("198.51.100.24").map_err(|error| {
            CaptureAdapterError::invalid_filter(format!("fixture IP is invalid: {error}"))
        })?,
        96,
    );
    first.src_port = Some(49_152);
    first.dst_port = Some(443);
    first.interface_id = Some("stub_interface_0".to_string());
    first.flags = PacketFlags {
        tcp_flags: vec![sentinel_contracts::TcpFlag::Syn],
        fragmented: false,
        malformed: false,
    };
    first.capture_source = CaptureSource::Mock;
    first.collection_mode = CollectionMode::Mock;
    first.visibility_level = VisibilityLevel::MetadataOnly;
    first.quality_score = QualityScore::default();
    records.push(first);

    if requested > 1 {
        let mut second = PacketRecord::new(
            TransportProtocol::Udp,
            NetworkDirection::Outbound,
            IpAddress::parse_str("192.0.2.10").map_err(|error| {
                CaptureAdapterError::invalid_filter(format!("fixture IP is invalid: {error}"))
            })?,
            IpAddress::parse_str("203.0.113.53").map_err(|error| {
                CaptureAdapterError::invalid_filter(format!("fixture IP is invalid: {error}"))
            })?,
            72,
        );
        second.src_port = Some(53_000);
        second.dst_port = Some(53);
        second.interface_id = Some("stub_interface_0".to_string());
        second.capture_source = CaptureSource::Mock;
        second.collection_mode = CollectionMode::Mock;
        second.visibility_level = VisibilityLevel::MetadataOnly;
        records.push(second);
    }

    if requested > 2 {
        let mut third = PacketRecord::new(
            TransportProtocol::Tcp,
            NetworkDirection::Inbound,
            IpAddress::parse_str("198.51.100.24").map_err(|error| {
                CaptureAdapterError::invalid_filter(format!("fixture IP is invalid: {error}"))
            })?,
            IpAddress::parse_str("192.0.2.10").map_err(|error| {
                CaptureAdapterError::invalid_filter(format!("fixture IP is invalid: {error}"))
            })?,
            128,
        );
        third.src_port = Some(443);
        third.dst_port = Some(49_152);
        third.interface_id = Some("stub_interface_0".to_string());
        third.flags = PacketFlags {
            tcp_flags: vec![
                sentinel_contracts::TcpFlag::Syn,
                sentinel_contracts::TcpFlag::Ack,
            ],
            fragmented: false,
            malformed: false,
        };
        third.capture_source = CaptureSource::Mock;
        third.collection_mode = CollectionMode::Mock;
        third.visibility_level = VisibilityLevel::MetadataOnly;
        records.push(third);
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_filter_is_metadata_first_and_rejects_private_content_flags() {
        let filter = CaptureFilter::metadata_only_default();
        assert!(filter.validate().is_ok());

        let mut unsafe_filter = filter.clone();
        unsafe_filter.allow_payload_persistence = true;
        let error = unsafe_filter
            .validate()
            .expect_err("payload persistence rejected");
        assert_eq!(error.error_code, ErrorCode::PrivacyPolicyViolation);

        let mut bad_text = filter;
        bad_text.local_process_hint_redacted = Some("authorization header marker".to_string());
        assert_eq!(
            bad_text.validate().expect_err("marker rejected").error_code,
            ErrorCode::PrivacyPolicyViolation
        );

        let mut empty_directions = CaptureFilter::metadata_only_default();
        empty_directions.directions.clear();
        assert_eq!(
            empty_directions
                .validate()
                .expect_err("empty directions rejected")
                .error_code,
            ErrorCode::InvalidRequest
        );

        let mut empty_protocols = CaptureFilter::metadata_only_default();
        empty_protocols.protocols.clear();
        assert_eq!(
            empty_protocols
                .validate()
                .expect_err("empty protocols rejected")
                .error_code,
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn forensic_selected_scope_filter_remains_metadata_only() {
        let scope = ForensicScope::new(
            sentinel_contracts::ForensicScopeKind::SelectedFlow,
            "flow_ref_1",
        )
        .expect("forensic scope");
        let filter = CaptureFilter::forensic_selected_scope(scope);

        assert!(filter.validate().is_ok());
        assert!(filter.metadata_only);
        assert!(!filter.allow_packet_bytes_persistence);
        assert!(!filter.allow_payload_persistence);
        assert!(!filter.allow_http_body_persistence);
    }

    #[test]
    fn stub_adapter_controls_session_without_real_driver_actions() {
        let mut adapter = StubOnlyCaptureAdapter::new().expect("adapter");
        let session = adapter
            .start(CaptureFilter::metadata_only_default())
            .expect("start");
        assert_eq!(session.state, CaptureSessionState::Running);
        assert_eq!(session.capture_source, CaptureSource::Mock);
        assert!(session.metadata_only);
        assert!(!session.driver_handle_exposed);

        let paused = adapter.pause().expect("pause");
        assert_eq!(paused.state, CaptureSessionState::Paused);

        let resumed = adapter.resume().expect("resume");
        assert_eq!(resumed.state, CaptureSessionState::Running);

        let mut filter = CaptureFilter::metadata_only_default();
        filter.protocols = vec![TransportProtocol::Tcp];
        let updated = adapter.update_filter(filter).expect("update filter");
        assert_eq!(updated.filter.protocols, vec![TransportProtocol::Tcp]);

        let stopped = adapter.stop().expect("stop");
        assert_eq!(stopped.state, CaptureSessionState::Stopped);
    }

    #[test]
    fn packet_metadata_batch_contains_only_bounded_metadata_records() {
        let mut adapter = StubOnlyCaptureAdapter::new().expect("adapter");
        adapter
            .start(CaptureFilter::metadata_only_default())
            .expect("start");
        let batch = adapter.read_packet_metadata_batch(16).expect("batch");

        assert!(batch.validate().is_ok());
        assert!(!batch.records.is_empty());
        assert!(batch.bounded);
        assert!(batch.metadata_only);
        assert!(!batch.packet_bytes_included);
        assert!(!batch.payload_bytes_included);
        assert!(!batch.http_body_included);
        assert!(batch
            .records
            .iter()
            .all(|record| record.capture_source == CaptureSource::Mock
                && record.visibility_level == VisibilityLevel::MetadataOnly));
    }

    #[test]
    fn stub_adapter_applies_metadata_filters_before_emitting_batches() {
        let mut filter = CaptureFilter::metadata_only_default();
        filter.directions = vec![NetworkDirection::Outbound];
        filter.protocols = vec![TransportProtocol::Tcp];
        filter.interface_ids = vec!["stub_interface_0".to_string()];
        filter.destination = Some(CaptureDestinationFilter::single_ip(
            IpAddress::parse_str("198.51.100.24").expect("fixture ip"),
            Some(443),
        ));

        let mut adapter = StubOnlyCaptureAdapter::new().expect("adapter");
        adapter.start(filter).expect("start");
        let batch = adapter.read_packet_metadata_batch(16).expect("batch");

        assert_eq!(batch.records.len(), 1);
        let record = &batch.records[0];
        assert_eq!(record.direction, NetworkDirection::Outbound);
        assert_eq!(record.protocol, TransportProtocol::Tcp);
        assert_eq!(record.dst_ip.to_string(), "198.51.100.24");
        assert_eq!(record.dst_port, Some(443));
        assert_eq!(record.interface_id.as_deref(), Some("stub_interface_0"));
        assert!(batch.validate().is_ok());
    }

    #[test]
    fn stub_adapter_returns_empty_metadata_batch_when_valid_filter_has_no_matches() {
        let mut filter = CaptureFilter::metadata_only_default();
        filter.interface_ids = vec!["missing_interface".to_string()];

        let mut adapter = StubOnlyCaptureAdapter::new().expect("adapter");
        adapter.start(filter).expect("start");
        let batch = adapter.read_packet_metadata_batch(16).expect("batch");

        assert!(batch.records.is_empty());
        assert_eq!(batch.stats.total_packets, 0);
        assert!(batch.validate().is_ok());
    }

    #[test]
    fn stub_adapter_rejects_controls_when_service_precheck_fails_closed() {
        let mut adapter =
            StubOnlyCaptureAdapter::with_precheck(PrivilegedCommandPrecheck::stub_only())
                .expect("adapter");
        let error = adapter
            .start(CaptureFilter::metadata_only_default())
            .expect_err("stub-only service state rejects start");

        assert_eq!(error.error_code, ErrorCode::ServiceUnavailable);
        assert!(error.stub_only);
    }

    #[test]
    fn capture_health_exposes_required_driver_running_rate_and_degraded_fields() {
        let mut adapter = StubOnlyCaptureAdapter::new().expect("adapter");
        let initial = adapter.driver_health();
        assert!(!initial.driver_loaded);
        assert!(!initial.capture_running);
        assert_eq!(
            initial.degraded_reason,
            Some(CaptureDegradedReason::StubOnlyAdapter)
        );

        adapter
            .start(CaptureFilter::metadata_only_default())
            .expect("start");
        let _batch = adapter.read_packet_metadata_batch(2).expect("batch");
        let health = adapter.driver_health();

        assert!(!health.driver_loaded);
        assert!(health.capture_running);
        assert!(health.packet_rate_per_second.is_some());
        assert_eq!(health.drop_rate, Some(0.0));
        assert!(health.last_packet_time.is_some());
        assert_eq!(health.status, ObservabilityHealthStatus::Degraded);
        assert!(health.validate().is_ok());
    }

    #[test]
    fn capture_stats_validate_drop_rate_bounds() {
        let mut stats = CaptureStats::empty(CaptureSource::Mock);
        stats.drop_rate = Some(1.2);

        assert_eq!(
            stats.validate().expect_err("drop rate rejected").error_code,
            ErrorCode::InvalidRequest
        );
    }
}
