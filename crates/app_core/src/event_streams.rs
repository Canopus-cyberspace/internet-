use crate::machine_local_capabilities::CapabilityStatusSummary;
use crate::read_commands::ServiceStatusView;
use sentinel_contracts::{
    AlertId, AlertState, CommandResult, CoreError, ErrorCode, ErrorSeverity, EventId, GraphScope,
    GraphType, GraphViewId, IncidentId, IncidentState, PluginId, PrivacyClass, ReportId,
    ReportStatus, ResponseActionId, ResponsePlanId, SchemaVersion, SecuritySeverity, Timestamp,
    TraceId,
};
use sentinel_platform::{
    ComponentId, HealthSnapshot, HealthSubject, MetricSample, MetricValue,
    ObservabilityHealthStatus, PriorityLane,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const DEFAULT_STREAM_BUFFER_CAPACITY: usize = 128;

const STREAM_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);
const MAX_HINTS_PER_EVENT: usize = 8;
const MAX_SUMMARY_LENGTH: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamName {
    Health,
    Metric,
    CaptureStatus,
    ServiceStatus,
    Alert,
    Incident,
    GraphUpdate,
    ResponseStatus,
    ReportProgress,
    PrivacyWarning,
}

impl StreamName {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Health => "health_stream",
            Self::Metric => "metric_stream",
            Self::CaptureStatus => "capture_status_stream",
            Self::ServiceStatus => "service_status_stream",
            Self::Alert => "alert_stream",
            Self::Incident => "incident_stream",
            Self::GraphUpdate => "graph_update_stream",
            Self::ResponseStatus => "response_status_stream",
            Self::ReportProgress => "report_progress_stream",
            Self::PrivacyWarning => "privacy_warning_stream",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryInvalidationHint {
    pub query_key: String,
    pub exact: bool,
    pub reason_redacted: String,
}

impl QueryInvalidationHint {
    pub fn new(query_key: impl Into<String>, reason_redacted: impl Into<String>) -> Self {
        Self {
            query_key: query_key.into(),
            exact: true,
            reason_redacted: reason_redacted.into(),
        }
    }

    pub fn prefix(query_key: impl Into<String>, reason_redacted: impl Into<String>) -> Self {
        Self {
            query_key: query_key.into(),
            exact: false,
            reason_redacted: reason_redacted.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StreamEventEnvelope {
    pub event_id: EventId,
    pub stream: StreamName,
    pub event_type: String,
    pub priority: PriorityLane,
    pub trace_id: TraceId,
    pub schema_version: SchemaVersion,
    pub occurred_at: Timestamp,
    pub redacted_summary: String,
    pub invalidation_hints: Vec<QueryInvalidationHint>,
    pub body: StreamEventBody,
}

impl StreamEventEnvelope {
    fn new(
        stream: StreamName,
        event_type: impl Into<String>,
        priority: PriorityLane,
        redacted_summary: impl Into<String>,
        invalidation_hints: Vec<QueryInvalidationHint>,
        body: StreamEventBody,
    ) -> CommandResult<Self> {
        if invalidation_hints.len() > MAX_HINTS_PER_EVENT {
            return Err(stream_error(
                ErrorCode::ValidationFailure,
                "stream event has too many invalidation hints",
                json!({ "hint_count": invalidation_hints.len(), "max": MAX_HINTS_PER_EVENT }),
                TraceId::new_v4(),
            ));
        }

        let envelope = Self {
            event_id: EventId::new_v4(),
            stream,
            event_type: require_stream_text("event_type", event_type.into())?,
            priority,
            trace_id: TraceId::new_v4(),
            schema_version: STREAM_SCHEMA_VERSION,
            occurred_at: Timestamp::now(),
            redacted_summary: require_stream_text("redacted_summary", redacted_summary.into())?,
            invalidation_hints,
            body,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> CommandResult<()> {
        validate_stream_text("event_type", &self.event_type, &self.trace_id)?;
        validate_stream_text("redacted_summary", &self.redacted_summary, &self.trace_id)?;
        for hint in &self.invalidation_hints {
            validate_stream_text("query_key", &hint.query_key, &self.trace_id)?;
            validate_stream_text("reason_redacted", &hint.reason_redacted, &self.trace_id)?;
        }
        validate_stream_body_is_redacted(self)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "body_type", content = "body", rename_all = "snake_case")]
pub enum StreamEventBody {
    Health(HealthStreamUpdate),
    Metric(MetricStreamUpdate),
    CaptureStatus(CaptureStatusUpdate),
    ServiceStatus(ServiceStatusUpdate),
    Alert(AlertStreamUpdate),
    Incident(IncidentStreamUpdate),
    GraphUpdate(GraphUpdateStreamUpdate),
    ResponseStatus(ResponseStatusUpdate),
    ReportProgress(ReportProgressUpdate),
    PrivacyWarning(PrivacyWarningUpdate),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "subject_type", content = "subject", rename_all = "snake_case")]
pub enum HealthSubjectRef {
    Component { component_id: ComponentId },
    Plugin { plugin_id: PluginId },
    Pipeline { pipeline_id: String },
    ServiceAdapter { adapter_name: String },
    Storage { store_name: String },
    Capture { adapter_name: String },
    Other { summary_redacted: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthStreamUpdate {
    pub subject: HealthSubjectRef,
    pub status: ObservabilityHealthStatus,
    pub liveness: ObservabilityHealthStatus,
    pub readiness: ObservabilityHealthStatus,
    pub message_redacted: Option<String>,
    pub observed_at: Timestamp,
    pub privacy_class: PrivacyClass,
}

impl HealthStreamUpdate {
    pub fn from_snapshot(snapshot: &HealthSnapshot) -> Self {
        Self {
            subject: HealthSubjectRef::from_health_subject(&snapshot.subject),
            status: snapshot.status.clone(),
            liveness: snapshot.liveness.clone(),
            readiness: snapshot.readiness.clone(),
            message_redacted: snapshot.message_redacted.clone(),
            observed_at: snapshot.observed_at.clone(),
            privacy_class: snapshot.privacy_class.clone(),
        }
    }
}

impl HealthSubjectRef {
    fn from_health_subject(subject: &HealthSubject) -> Self {
        match subject {
            HealthSubject::Component { component_id } => Self::Component {
                component_id: component_id.clone(),
            },
            HealthSubject::Plugin { plugin_id } => Self::Plugin {
                plugin_id: plugin_id.clone(),
            },
            HealthSubject::Pipeline { pipeline_id } => Self::Pipeline {
                pipeline_id: pipeline_id.to_string(),
            },
            HealthSubject::PipelineStage {
                pipeline_id,
                node_id,
                ..
            } => Self::Other {
                summary_redacted: format!("pipeline:{pipeline_id}:stage:{node_id}"),
            },
            HealthSubject::ServiceAdapter { adapter_name, .. } => Self::ServiceAdapter {
                adapter_name: adapter_name.clone(),
            },
            HealthSubject::Storage { store_name } => Self::Storage {
                store_name: store_name.clone(),
            },
            HealthSubject::Capture { adapter_name } => Self::Capture {
                adapter_name: adapter_name.clone(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricStreamUpdate {
    pub plugin_id: Option<PluginId>,
    pub metric_name: String,
    pub value: MetricValueSummary,
    pub label_count: usize,
    pub observed_at: Timestamp,
    pub privacy_class: PrivacyClass,
}

impl MetricStreamUpdate {
    pub fn from_sample(plugin_id: Option<PluginId>, sample: &MetricSample) -> Self {
        Self {
            plugin_id,
            metric_name: sample.metric_name.clone(),
            value: MetricValueSummary::from_metric_value(&sample.value),
            label_count: sample.labels.len(),
            observed_at: sample.observed_at.clone(),
            privacy_class: sample.privacy_class.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MetricValueSummary {
    Counter(u64),
    Gauge(f64),
    Histogram {
        bucket_count: usize,
        count: u64,
        sum: f64,
    },
    Distribution {
        count: usize,
        min: Option<f64>,
        max: Option<f64>,
    },
}

impl MetricValueSummary {
    fn from_metric_value(value: &MetricValue) -> Self {
        match value {
            MetricValue::Counter(value) => Self::Counter(*value),
            MetricValue::Gauge(value) => Self::Gauge(*value),
            MetricValue::Histogram {
                buckets,
                count,
                sum,
            } => Self::Histogram {
                bucket_count: buckets.len(),
                count: *count,
                sum: *sum,
            },
            MetricValue::Distribution { values } => {
                let min = values.iter().copied().reduce(f64::min);
                let max = values.iter().copied().reduce(f64::max);
                Self::Distribution {
                    count: values.len(),
                    min,
                    max,
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatusKind {
    Unavailable,
    Stopped,
    Running,
    Degraded,
    ReducedVisibility,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CaptureStatusUpdate {
    pub status: CaptureStatusKind,
    pub adapter_name: String,
    pub packet_rate_per_second: Option<f64>,
    pub drop_rate: Option<f64>,
    pub reduced_visibility: bool,
    pub message_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceStatusUpdate {
    pub profile_mode: String,
    pub local_core_status: ObservabilityHealthStatus,
    pub elevated_service_status: ObservabilityHealthStatus,
    pub ipc_status: ObservabilityHealthStatus,
    pub storage_status: ObservabilityHealthStatus,
    pub reduced_visibility: bool,
    pub privileged_actions_available: bool,
    pub capture_available: bool,
    pub machine_local_capability_status: Option<CapabilityStatusSummary>,
    pub message_redacted: String,
}

impl From<&ServiceStatusView> for ServiceStatusUpdate {
    fn from(status: &ServiceStatusView) -> Self {
        Self {
            profile_mode: status.profile_mode.clone(),
            local_core_status: status.local_core_status.clone(),
            elevated_service_status: status.elevated_service_status.clone(),
            ipc_status: status.ipc_status.clone(),
            storage_status: status.storage_status.clone(),
            reduced_visibility: status.reduced_visibility,
            privileged_actions_available: status.privileged_actions_available,
            capture_available: status.capture_available,
            machine_local_capability_status: status.machine_local_capability_status.clone(),
            message_redacted: status.message_redacted.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AlertStreamUpdate {
    pub alert_id: AlertId,
    pub state: AlertState,
    pub severity: SecuritySeverity,
    pub finding_count: usize,
    pub summary_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentStreamUpdate {
    pub incident_id: IncidentId,
    pub state: IncidentState,
    pub severity: SecuritySeverity,
    pub alert_count: usize,
    pub graph_path_count: usize,
    pub summary_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphUpdateStreamUpdate {
    pub graph_type: GraphType,
    pub scope: GraphScope,
    pub graph_view_id: Option<GraphViewId>,
    pub changed_node_count: u32,
    pub changed_edge_count: u32,
    pub changed_path_count: u32,
    pub summary_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatusKind {
    PlanCreated,
    ApprovalRequired,
    ActionStarted,
    ActionCompleted,
    ActionFailed,
    RollbackCompleted,
    RollbackFailed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseStatusUpdate {
    pub plan_id: Option<ResponsePlanId>,
    pub action_id: Option<ResponseActionId>,
    pub status: ResponseStatusKind,
    pub rollback_available: bool,
    pub approval_required: bool,
    pub summary_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportProgressPhase {
    GenerationStarted,
    GenerationProgress,
    Generated,
    Exported,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportProgressUpdate {
    pub report_id: Option<ReportId>,
    pub phase: ReportProgressPhase,
    pub status: Option<ReportStatus>,
    pub progress_percent: Option<u8>,
    pub summary_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyWarningKind {
    ForensicModeEnabled,
    ForensicModeDisabled,
    ReducedVisibility,
    ExportRedactionRequired,
    SensitiveDataSuppressed,
    OnlineLookupDisabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyWarningUpdate {
    pub warning_kind: PrivacyWarningKind,
    pub active: bool,
    pub user_visible: bool,
    pub summary_redacted: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StreamDispatchReport {
    pub accepted: bool,
    pub buffered_count: usize,
    pub dropped_count: usize,
    pub last_event_id: Option<EventId>,
}

#[derive(Clone, Debug)]
pub struct TauriEventDispatcher {
    buffer: Vec<StreamEventEnvelope>,
    max_events: usize,
    dropped_count: usize,
}

impl TauriEventDispatcher {
    pub fn new(max_events: usize) -> CommandResult<Self> {
        if max_events == 0 {
            return Err(stream_error(
                ErrorCode::ValidationFailure,
                "stream buffer capacity must be greater than zero",
                json!({ "max_events": max_events }),
                TraceId::new_v4(),
            ));
        }
        Ok(Self {
            buffer: Vec::new(),
            max_events,
            dropped_count: 0,
        })
    }

    pub fn pending_events(&self) -> &[StreamEventEnvelope] {
        &self.buffer
    }

    pub fn dropped_count(&self) -> usize {
        self.dropped_count
    }

    pub fn drain(&mut self) -> Vec<StreamEventEnvelope> {
        std::mem::take(&mut self.buffer)
    }

    pub fn dispatch(
        &mut self,
        envelope: StreamEventEnvelope,
    ) -> CommandResult<StreamDispatchReport> {
        envelope.validate()?;
        if self.buffer.len() >= self.max_events {
            if let Some(drop_index) = self
                .buffer
                .iter()
                .position(|event| event.priority.can_drop_under_pressure())
            {
                self.buffer.remove(drop_index);
                self.dropped_count += 1;
            } else if envelope.priority.can_drop_under_pressure() {
                self.dropped_count += 1;
                return Ok(StreamDispatchReport {
                    accepted: false,
                    buffered_count: self.buffer.len(),
                    dropped_count: self.dropped_count,
                    last_event_id: Some(envelope.event_id),
                });
            } else {
                return Err(stream_error(
                    ErrorCode::RateLimited,
                    "protected stream event could not be buffered",
                    json!({
                        "stream": envelope.stream.as_str(),
                        "event_type": envelope.event_type,
                        "priority": envelope.priority
                    }),
                    envelope.trace_id,
                ));
            }
        }
        let event_id = envelope.event_id.clone();
        self.buffer.push(envelope);
        Ok(StreamDispatchReport {
            accepted: true,
            buffered_count: self.buffer.len(),
            dropped_count: self.dropped_count,
            last_event_id: Some(event_id),
        })
    }
}

impl Default for TauriEventDispatcher {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            max_events: DEFAULT_STREAM_BUFFER_CAPACITY,
            dropped_count: 0,
        }
    }
}

pub fn health_stream(
    dispatcher: &mut TauriEventDispatcher,
    update: HealthStreamUpdate,
) -> CommandResult<StreamEventEnvelope> {
    let event_type = match update.status {
        ObservabilityHealthStatus::Failed
        | ObservabilityHealthStatus::Unavailable
        | ObservabilityHealthStatus::Disconnected
        | ObservabilityHealthStatus::Unauthorized => "health_critical",
        ObservabilityHealthStatus::Degraded | ObservabilityHealthStatus::Stale => "health_degraded",
        _ => "health_update",
    };
    let priority = match update.status {
        ObservabilityHealthStatus::Failed
        | ObservabilityHealthStatus::Unavailable
        | ObservabilityHealthStatus::Disconnected
        | ObservabilityHealthStatus::Unauthorized => PriorityLane::P1High,
        _ => PriorityLane::P2Normal,
    };
    let hints = health_invalidation_hints(&update);
    dispatch_envelope(
        dispatcher,
        StreamName::Health,
        event_type,
        priority,
        update
            .message_redacted
            .clone()
            .unwrap_or_else(|| "component health changed".to_string()),
        hints,
        StreamEventBody::Health(update),
    )
}

pub fn metric_stream(
    dispatcher: &mut TauriEventDispatcher,
    update: MetricStreamUpdate,
) -> CommandResult<StreamEventEnvelope> {
    let hints = match &update.plugin_id {
        Some(plugin_id) => vec![
            QueryInvalidationHint::new(format!("plugin.metrics:{plugin_id}"), "plugin metric tick"),
            QueryInvalidationHint::new("plugin.catalog", "plugin metric tick"),
        ],
        None => vec![QueryInvalidationHint::prefix(
            "platform.metrics",
            "platform metric tick",
        )],
    };
    dispatch_envelope(
        dispatcher,
        StreamName::Metric,
        "metrics_update",
        PriorityLane::P3Low,
        format!("metric {} updated", update.metric_name),
        hints,
        StreamEventBody::Metric(update),
    )
}

pub fn capture_status_stream(
    dispatcher: &mut TauriEventDispatcher,
    update: CaptureStatusUpdate,
) -> CommandResult<StreamEventEnvelope> {
    let priority = if matches!(
        update.status,
        CaptureStatusKind::Degraded | CaptureStatusKind::ReducedVisibility
    ) {
        PriorityLane::P1High
    } else {
        PriorityLane::P2Normal
    };
    let event_type = if matches!(
        update.status,
        CaptureStatusKind::Degraded | CaptureStatusKind::ReducedVisibility
    ) {
        "capture_degraded"
    } else {
        "capture_status_changed"
    };
    let summary = update.message_redacted.clone();
    dispatch_envelope(
        dispatcher,
        StreamName::CaptureStatus,
        event_type,
        priority,
        summary,
        vec![
            QueryInvalidationHint::new("settings.service", "capture status changed"),
            QueryInvalidationHint::prefix("network.flows", "capture status changed"),
        ],
        StreamEventBody::CaptureStatus(update),
    )
}

pub fn service_status_stream(
    dispatcher: &mut TauriEventDispatcher,
    update: ServiceStatusUpdate,
) -> CommandResult<StreamEventEnvelope> {
    let disconnected = update.elevated_service_status == ObservabilityHealthStatus::Disconnected
        || update.ipc_status == ObservabilityHealthStatus::Disconnected;
    let priority = if disconnected {
        PriorityLane::P0Critical
    } else if update.reduced_visibility {
        PriorityLane::P1High
    } else {
        PriorityLane::P2Normal
    };
    let event_type = if update.machine_local_capability_status.is_some() {
        "capability_status_update"
    } else if disconnected {
        "service_disconnected"
    } else {
        "service_status_changed"
    };
    let summary = update.message_redacted.clone();
    dispatch_envelope(
        dispatcher,
        StreamName::ServiceStatus,
        event_type,
        priority,
        summary,
        vec![
            QueryInvalidationHint::new("settings.service", "service status changed"),
            QueryInvalidationHint::new("settings.runtime", "service status changed"),
        ],
        StreamEventBody::ServiceStatus(update),
    )
}

pub fn alert_stream(
    dispatcher: &mut TauriEventDispatcher,
    update: AlertStreamUpdate,
) -> CommandResult<StreamEventEnvelope> {
    let event_type = if update.state == AlertState::New {
        "new_alert"
    } else {
        "alert_updated"
    };
    let summary = update.summary_redacted.clone();
    dispatch_envelope(
        dispatcher,
        StreamName::Alert,
        event_type,
        PriorityLane::P1High,
        summary,
        vec![
            QueryInvalidationHint::prefix("security.alerts", "alert changed"),
            QueryInvalidationHint::prefix("security.cases", "alert changed"),
        ],
        StreamEventBody::Alert(update),
    )
}

pub fn incident_stream(
    dispatcher: &mut TauriEventDispatcher,
    update: IncidentStreamUpdate,
) -> CommandResult<StreamEventEnvelope> {
    let critical = update.severity == SecuritySeverity::Critical;
    let event_type = if critical {
        "critical_incident"
    } else if update.state == IncidentState::New {
        "new_incident"
    } else {
        "incident_updated"
    };
    let priority = if critical {
        PriorityLane::P0Critical
    } else {
        PriorityLane::P1High
    };
    let incident_id = update.incident_id.clone();
    let summary = update.summary_redacted.clone();
    dispatch_envelope(
        dispatcher,
        StreamName::Incident,
        event_type,
        priority,
        summary,
        vec![
            QueryInvalidationHint::prefix("security.incidents", "incident changed"),
            QueryInvalidationHint::new(
                format!("security.incident.detail:{incident_id}"),
                "incident changed",
            ),
            QueryInvalidationHint::new(
                format!("graph.incident:{incident_id}"),
                "incident graph may need refresh",
            ),
        ],
        StreamEventBody::Incident(update),
    )
}

pub fn graph_update_stream(
    dispatcher: &mut TauriEventDispatcher,
    update: GraphUpdateStreamUpdate,
) -> CommandResult<StreamEventEnvelope> {
    let key = format!("graph.view:{:?}:{:?}", update.graph_type, update.scope);
    let summary = update.summary_redacted.clone();
    dispatch_envelope(
        dispatcher,
        StreamName::GraphUpdate,
        "graph_update",
        PriorityLane::P2Normal,
        summary,
        vec![QueryInvalidationHint::new(
            key,
            "graph view model may need refresh",
        )],
        StreamEventBody::GraphUpdate(update),
    )
}

pub fn response_status_stream(
    dispatcher: &mut TauriEventDispatcher,
    update: ResponseStatusUpdate,
) -> CommandResult<StreamEventEnvelope> {
    let (event_type, priority) = match update.status {
        ResponseStatusKind::ActionFailed => ("response_action_failed", PriorityLane::P0Critical),
        ResponseStatusKind::RollbackFailed => ("rollback_failed", PriorityLane::P0Critical),
        ResponseStatusKind::ActionCompleted => ("response_completed", PriorityLane::P1High),
        ResponseStatusKind::RollbackCompleted => {
            ("response_rollback_completed", PriorityLane::P1High)
        }
        ResponseStatusKind::PlanCreated => ("response_plan_created", PriorityLane::P1High),
        ResponseStatusKind::ApprovalRequired => {
            ("response_approval_required", PriorityLane::P1High)
        }
        ResponseStatusKind::ActionStarted => ("response_action_started", PriorityLane::P1High),
    };
    let summary = update.summary_redacted.clone();
    dispatch_envelope(
        dispatcher,
        StreamName::ResponseStatus,
        event_type,
        priority,
        summary,
        vec![
            QueryInvalidationHint::new("response.active", "response status changed"),
            QueryInvalidationHint::prefix("response.plans", "response status changed"),
            QueryInvalidationHint::prefix("response.history", "response status changed"),
        ],
        StreamEventBody::ResponseStatus(update),
    )
}

pub fn report_progress_stream(
    dispatcher: &mut TauriEventDispatcher,
    update: ReportProgressUpdate,
) -> CommandResult<StreamEventEnvelope> {
    let (event_type, priority) = match update.phase {
        ReportProgressPhase::GenerationStarted => {
            ("report_generation_started", PriorityLane::P4BestEffort)
        }
        ReportProgressPhase::GenerationProgress => {
            ("report_generation_progress", PriorityLane::P4BestEffort)
        }
        ReportProgressPhase::Generated => ("report_generated", PriorityLane::P1High),
        ReportProgressPhase::Exported => ("report_exported", PriorityLane::P1High),
        ReportProgressPhase::Failed => ("report_failed", PriorityLane::P1High),
    };
    let mut hints = vec![QueryInvalidationHint::prefix(
        "report.list",
        "report progress changed",
    )];
    if let Some(report_id) = &update.report_id {
        hints.push(QueryInvalidationHint::new(
            format!("report.detail:{report_id}"),
            "report progress changed",
        ));
    }
    if update.phase == ReportProgressPhase::Exported {
        hints.push(QueryInvalidationHint::new(
            "report.export_history",
            "report exported",
        ));
    }
    let summary = update.summary_redacted.clone();
    dispatch_envelope(
        dispatcher,
        StreamName::ReportProgress,
        event_type,
        priority,
        summary,
        hints,
        StreamEventBody::ReportProgress(update),
    )
}

pub fn privacy_warning_stream(
    dispatcher: &mut TauriEventDispatcher,
    update: PrivacyWarningUpdate,
) -> CommandResult<StreamEventEnvelope> {
    let (event_type, priority) = match update.warning_kind {
        PrivacyWarningKind::ForensicModeEnabled => {
            ("forensic_mode_enabled", PriorityLane::P0Critical)
        }
        PrivacyWarningKind::ForensicModeDisabled => {
            ("forensic_mode_disabled", PriorityLane::P1High)
        }
        PrivacyWarningKind::ReducedVisibility => {
            ("privacy_reduced_visibility", PriorityLane::P1High)
        }
        PrivacyWarningKind::ExportRedactionRequired => {
            ("export_redaction_required", PriorityLane::P1High)
        }
        PrivacyWarningKind::SensitiveDataSuppressed => {
            ("sensitive_data_suppressed", PriorityLane::P2Normal)
        }
        PrivacyWarningKind::OnlineLookupDisabled => {
            ("online_lookup_disabled", PriorityLane::P2Normal)
        }
    };
    let summary = update.summary_redacted.clone();
    dispatch_envelope(
        dispatcher,
        StreamName::PrivacyWarning,
        event_type,
        priority,
        summary,
        vec![
            QueryInvalidationHint::new("settings.privacy", "privacy state changed"),
            QueryInvalidationHint::new("settings.runtime", "privacy state changed"),
        ],
        StreamEventBody::PrivacyWarning(update),
    )
}

fn dispatch_envelope(
    dispatcher: &mut TauriEventDispatcher,
    stream: StreamName,
    event_type: impl Into<String>,
    priority: PriorityLane,
    summary: impl Into<String>,
    hints: Vec<QueryInvalidationHint>,
    body: StreamEventBody,
) -> CommandResult<StreamEventEnvelope> {
    let envelope = StreamEventEnvelope::new(stream, event_type, priority, summary, hints, body)?;
    dispatcher.dispatch(envelope.clone())?;
    Ok(envelope)
}

fn health_invalidation_hints(update: &HealthStreamUpdate) -> Vec<QueryInvalidationHint> {
    match &update.subject {
        HealthSubjectRef::Component { component_id } => vec![
            QueryInvalidationHint::new(
                format!("platform.component.health:{component_id}"),
                "component health changed",
            ),
            QueryInvalidationHint::new("platform.components", "component health changed"),
        ],
        HealthSubjectRef::Plugin { plugin_id } => vec![
            QueryInvalidationHint::new(
                format!("plugin.metrics:{plugin_id}"),
                "plugin health changed",
            ),
            QueryInvalidationHint::new(
                format!("plugin.manifest:{plugin_id}"),
                "plugin health changed",
            ),
            QueryInvalidationHint::new("plugin.catalog", "plugin health changed"),
        ],
        HealthSubjectRef::ServiceAdapter { .. } => vec![QueryInvalidationHint::new(
            "settings.service",
            "service adapter health changed",
        )],
        HealthSubjectRef::Storage { .. } => vec![QueryInvalidationHint::new(
            "settings.service",
            "storage health changed",
        )],
        HealthSubjectRef::Capture { .. } => vec![QueryInvalidationHint::new(
            "settings.service",
            "capture health changed",
        )],
        _ => vec![QueryInvalidationHint::prefix(
            "platform.components",
            "health changed",
        )],
    }
}

fn require_stream_text(field: &'static str, value: String) -> CommandResult<String> {
    validate_stream_text(field, &value, &TraceId::new_v4())?;
    Ok(value)
}

fn validate_stream_text(field: &'static str, value: &str, trace_id: &TraceId) -> CommandResult<()> {
    if value.trim().is_empty() {
        return Err(stream_error(
            ErrorCode::ValidationFailure,
            "stream text field must not be empty",
            json!({ "field": field }),
            trace_id.clone(),
        ));
    }
    if value.len() > MAX_SUMMARY_LENGTH {
        return Err(stream_error(
            ErrorCode::ValidationFailure,
            "stream text field is too long",
            json!({ "field": field, "max": MAX_SUMMARY_LENGTH, "actual": value.len() }),
            trace_id.clone(),
        ));
    }
    let normalized = value.to_ascii_lowercase();
    if FORBIDDEN_STREAM_TOKENS
        .iter()
        .any(|token| normalized.contains(token))
    {
        return Err(stream_error(
            ErrorCode::PrivacyPolicyViolation,
            "stream text contains sensitive content marker",
            json!({ "field": field }),
            trace_id.clone(),
        ));
    }
    Ok(())
}

const FORBIDDEN_STREAM_TOKENS: &[&str] = &[
    "raw_packet_bytes",
    "packet_bytes",
    "raw_payload",
    "payload_blob",
    "http_body_value",
    "cookie_value",
    "credential_value",
    "authorization_header_value",
    "api_key_value",
    "private_key_value",
    "session_secret",
];

fn validate_stream_body_is_redacted(envelope: &StreamEventEnvelope) -> CommandResult<()> {
    let value = serde_json::to_value(&envelope.body).map_err(|error| {
        stream_error(
            ErrorCode::InternalError,
            "stream body serialization failed",
            json!({ "error_redacted": error.to_string() }),
            envelope.trace_id.clone(),
        )
    })?;
    validate_json_value(&value, "$", &envelope.trace_id)
}

fn validate_json_value(value: &Value, path: &str, trace_id: &TraceId) -> CommandResult<()> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                validate_stream_text("json_key", key, trace_id)?;
                validate_json_value(nested, &format!("{path}.{key}"), trace_id)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 16 {
                return Err(stream_error(
                    ErrorCode::ValidationFailure,
                    "stream event arrays must remain compact",
                    json!({ "path": path, "item_count": values.len() }),
                    trace_id.clone(),
                ));
            }
            for (index, nested) in values.iter().enumerate() {
                validate_json_value(nested, &format!("{path}[{index}]"), trace_id)?;
            }
        }
        Value::String(value) => validate_stream_text("json_value", value, trace_id)?,
        _ => {}
    }
    Ok(())
}

fn stream_error(
    error_code: ErrorCode,
    message: impl Into<String>,
    details: Value,
    trace_id: TraceId,
) -> CoreError {
    CoreError::new(error_code, message)
        .with_severity(ErrorSeverity::Error)
        .with_trace_id(trace_id)
        .with_redacted_details(details)
}

#[cfg(test)]
mod tests {
    use crate::machine_local_capabilities::{
        CapabilityStatusSummary, MachineLocalCapability, MachineLocalCapabilityStatusDto,
    };

    use super::*;

    #[test]
    fn all_named_streams_dispatch_compact_events_with_query_hints() {
        let mut dispatcher = TauriEventDispatcher::default();
        health_stream(
            &mut dispatcher,
            HealthStreamUpdate {
                subject: HealthSubjectRef::Plugin {
                    plugin_id: PluginId::new_v4(),
                },
                status: ObservabilityHealthStatus::Healthy,
                liveness: ObservabilityHealthStatus::Healthy,
                readiness: ObservabilityHealthStatus::Healthy,
                message_redacted: Some("plugin healthy".to_string()),
                observed_at: Timestamp::now(),
                privacy_class: PrivacyClass::Internal,
            },
        )
        .expect("health");
        metric_stream(
            &mut dispatcher,
            MetricStreamUpdate {
                plugin_id: Some(PluginId::new_v4()),
                metric_name: "events_out_total".to_string(),
                value: MetricValueSummary::Counter(3),
                label_count: 1,
                observed_at: Timestamp::now(),
                privacy_class: PrivacyClass::Internal,
            },
        )
        .expect("metric");
        capture_status_stream(&mut dispatcher, capture_update(CaptureStatusKind::Running))
            .expect("capture");
        service_status_stream(&mut dispatcher, connected_service_update()).expect("service");
        alert_stream(&mut dispatcher, alert_update()).expect("alert");
        incident_stream(&mut dispatcher, incident_update(SecuritySeverity::High))
            .expect("incident");
        graph_update_stream(&mut dispatcher, graph_update()).expect("graph");
        response_status_stream(
            &mut dispatcher,
            response_update(ResponseStatusKind::PlanCreated),
        )
        .expect("response");
        report_progress_stream(
            &mut dispatcher,
            report_update(ReportProgressPhase::Generated),
        )
        .expect("report");
        privacy_warning_stream(
            &mut dispatcher,
            privacy_update(PrivacyWarningKind::SensitiveDataSuppressed),
        )
        .expect("privacy");

        assert_eq!(dispatcher.pending_events().len(), 10);
        assert!(dispatcher
            .pending_events()
            .iter()
            .all(|event| !event.invalidation_hints.is_empty()));
        assert!(dispatcher
            .pending_events()
            .iter()
            .all(|event| serde_json::to_string(event).expect("json").len() < 4096));
    }

    #[test]
    fn service_status_stream_emits_capability_status_update_when_summary_present() {
        let mut dispatcher = TauriEventDispatcher::default();
        let mut update = connected_service_update();
        update.machine_local_capability_status = Some(CapabilityStatusSummary {
            capabilities: vec![MachineLocalCapabilityStatusDto {
                capability: MachineLocalCapability::ElevatedService.as_str().to_string(),
                status: "unavailable".to_string(),
                reason: Some("elevated service did not respond on this machine".to_string()),
                action: None,
            }],
            all_available: false,
            degraded_count: 0,
            unavailable_count: 1,
            requires_setup_count: 0,
            detected_at: Timestamp::now(),
        });

        let event = service_status_stream(&mut dispatcher, update).expect("capability status");

        assert_eq!(event.event_type, "capability_status_update");
        assert_eq!(event.stream, StreamName::ServiceStatus);
        assert!(event
            .invalidation_hints
            .iter()
            .any(|hint| hint.query_key == "settings.service"));
    }

    #[test]
    fn required_p0_events_are_mapped_to_critical_priority() {
        let mut dispatcher = TauriEventDispatcher::default();
        let service =
            service_status_stream(&mut dispatcher, disconnected_service_update()).expect("service");
        let response_failed = response_status_stream(
            &mut dispatcher,
            response_update(ResponseStatusKind::ActionFailed),
        )
        .expect("response failed");
        let rollback_failed = response_status_stream(
            &mut dispatcher,
            response_update(ResponseStatusKind::RollbackFailed),
        )
        .expect("rollback failed");
        let incident =
            incident_stream(&mut dispatcher, incident_update(SecuritySeverity::Critical))
                .expect("critical incident");
        let forensic = privacy_warning_stream(
            &mut dispatcher,
            privacy_update(PrivacyWarningKind::ForensicModeEnabled),
        )
        .expect("forensic");

        for event in [
            service,
            response_failed,
            rollback_failed,
            incident,
            forensic,
        ] {
            assert_eq!(event.priority, PriorityLane::P0Critical);
            assert!(!event.priority.can_drop_under_pressure());
        }
    }

    #[test]
    fn graph_stream_uses_invalidation_without_canonical_graph_data() {
        let mut dispatcher = TauriEventDispatcher::default();
        let event = graph_update_stream(&mut dispatcher, graph_update()).expect("graph");
        let json = serde_json::to_string(&event).expect("serialize event");

        assert_eq!(event.stream, StreamName::GraphUpdate);
        assert!(event.invalidation_hints[0]
            .query_key
            .starts_with("graph.view:"));
        assert!(!json.contains("canonical"));
        assert!(!json.contains("source_node"));
        assert!(!json.contains("target_node"));
        assert!(!json.contains("node_sequence"));
    }

    #[test]
    fn stream_validation_rejects_sensitive_markers_and_keeps_errors_traceable() {
        let mut dispatcher = TauriEventDispatcher::default();
        let error = privacy_warning_stream(
            &mut dispatcher,
            PrivacyWarningUpdate {
                warning_kind: PrivacyWarningKind::SensitiveDataSuppressed,
                active: true,
                user_visible: true,
                summary_redacted: "raw_payload marker should not stream".to_string(),
            },
        )
        .expect_err("sensitive marker rejected");

        assert_eq!(error.error_code, ErrorCode::PrivacyPolicyViolation);
        assert!(error.trace_id.is_some());
        assert!(error.details_redacted.is_some());
    }

    #[test]
    fn dispatcher_bounds_history_and_preserves_protected_events() {
        let mut dispatcher = TauriEventDispatcher::new(2).expect("dispatcher");
        metric_stream(
            &mut dispatcher,
            MetricStreamUpdate {
                plugin_id: None,
                metric_name: "low_priority_one".to_string(),
                value: MetricValueSummary::Gauge(1.0),
                label_count: 0,
                observed_at: Timestamp::now(),
                privacy_class: PrivacyClass::Internal,
            },
        )
        .expect("metric one");
        metric_stream(
            &mut dispatcher,
            MetricStreamUpdate {
                plugin_id: None,
                metric_name: "low_priority_two".to_string(),
                value: MetricValueSummary::Gauge(2.0),
                label_count: 0,
                observed_at: Timestamp::now(),
                privacy_class: PrivacyClass::Internal,
            },
        )
        .expect("metric two");
        let critical =
            service_status_stream(&mut dispatcher, disconnected_service_update()).expect("service");

        assert_eq!(critical.priority, PriorityLane::P0Critical);
        assert_eq!(dispatcher.pending_events().len(), 2);
        assert_eq!(dispatcher.dropped_count(), 1);
        assert!(dispatcher
            .pending_events()
            .iter()
            .any(|event| event.event_type == "service_disconnected"));
    }

    fn capture_update(status: CaptureStatusKind) -> CaptureStatusUpdate {
        CaptureStatusUpdate {
            status,
            adapter_name: "metadata_capture".to_string(),
            packet_rate_per_second: Some(12.0),
            drop_rate: Some(0.0),
            reduced_visibility: false,
            message_redacted: "capture status changed".to_string(),
        }
    }

    fn connected_service_update() -> ServiceStatusUpdate {
        ServiceStatusUpdate {
            profile_mode: "ephemeral".to_string(),
            local_core_status: ObservabilityHealthStatus::Healthy,
            elevated_service_status: ObservabilityHealthStatus::Healthy,
            ipc_status: ObservabilityHealthStatus::Healthy,
            storage_status: ObservabilityHealthStatus::Healthy,
            reduced_visibility: false,
            privileged_actions_available: false,
            capture_available: false,
            machine_local_capability_status: None,
            message_redacted: "service status changed".to_string(),
        }
    }

    fn disconnected_service_update() -> ServiceStatusUpdate {
        ServiceStatusUpdate {
            elevated_service_status: ObservabilityHealthStatus::Disconnected,
            ipc_status: ObservabilityHealthStatus::Disconnected,
            reduced_visibility: true,
            message_redacted: "elevated service disconnected".to_string(),
            ..connected_service_update()
        }
    }

    fn alert_update() -> AlertStreamUpdate {
        AlertStreamUpdate {
            alert_id: AlertId::new_v4(),
            state: AlertState::New,
            severity: SecuritySeverity::High,
            finding_count: 1,
            summary_redacted: "new alert".to_string(),
        }
    }

    fn incident_update(severity: SecuritySeverity) -> IncidentStreamUpdate {
        IncidentStreamUpdate {
            incident_id: IncidentId::new_v4(),
            state: IncidentState::New,
            severity,
            alert_count: 1,
            graph_path_count: 0,
            summary_redacted: "incident changed".to_string(),
        }
    }

    fn graph_update() -> GraphUpdateStreamUpdate {
        GraphUpdateStreamUpdate {
            graph_type: GraphType::IncidentGraph,
            scope: GraphScope::Overview,
            graph_view_id: Some(GraphViewId::new_v4()),
            changed_node_count: 2,
            changed_edge_count: 1,
            changed_path_count: 0,
            summary_redacted: "graph view changed".to_string(),
        }
    }

    fn response_update(status: ResponseStatusKind) -> ResponseStatusUpdate {
        ResponseStatusUpdate {
            plan_id: Some(ResponsePlanId::new_v4()),
            action_id: Some(ResponseActionId::new_v4()),
            status,
            rollback_available: true,
            approval_required: true,
            summary_redacted: "response status changed".to_string(),
        }
    }

    fn report_update(phase: ReportProgressPhase) -> ReportProgressUpdate {
        ReportProgressUpdate {
            report_id: Some(ReportId::new_v4()),
            phase,
            status: Some(ReportStatus::ReadyForExport),
            progress_percent: Some(100),
            summary_redacted: "report progress changed".to_string(),
        }
    }

    fn privacy_update(warning_kind: PrivacyWarningKind) -> PrivacyWarningUpdate {
        PrivacyWarningUpdate {
            warning_kind,
            active: true,
            user_visible: true,
            summary_redacted: "privacy warning changed".to_string(),
        }
    }
}
