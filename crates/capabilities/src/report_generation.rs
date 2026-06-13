use crate::graph_analytics::{normalize_export_safe_graph_snapshot, GraphAnalyticsError};
use sentinel_contracts::{
    report::{ExportFormat, ExportRequest, ExportResult},
    Alert, AlertId, AttackCoverageSummary, AuditRef, DurableBaselineSummary, EvidenceId,
    EvidenceItem, EvidenceQualitySummary, Finding, FindingId, FusionSummary, GraphScope,
    GraphSnapshot, GraphSnapshotId, Incident, IncidentId, InvestigationDrillDownSummary,
    LlmAlertStoryId, LlmAlertStoryRecord, MetadataSamplingBatchSummary,
    MetadataWatchControllerStatus, NativePermissionStatusSummary, NativeSamplerReadinessSummary,
    NativeSamplerRuntimeSummary, NativeSchedulerOperationalSummary, NativeVisibilitySummary,
    PrivacyClass, QualityBreakdown, RedactedDataCategory, RedactionStatus, RedactionSummary,
    Report, ReportContractError, ReportExportPolicy, ReportId, ReportSection, ReportSectionType,
    ReportStatus, ReportType, ResponsePlan, ResponsePlanId, ResponseResult, ResponseResultId,
    RollbackResult, RollbackResultId, SecuritySeverity, TimeRange, Timestamp,
    DEFAULT_GRAPH_VIEW_EDGE_LIMIT, DEFAULT_GRAPH_VIEW_NODE_LIMIT, MAX_EXPORT_GRAPH_EVIDENCE_REFS,
};
use sentinel_storage::privacy_service::{
    ExportPrivacyCheckRequest, ExportPrivacyGate, RedactionEngine,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fmt;

pub const REPORT_GENERATION_SCHEMA_VERSION: sentinel_contracts::SchemaVersion =
    sentinel_contracts::SchemaVersion::new(1, 0, 0);
const MAX_TRACEABILITY_REFS: usize = 100;

#[derive(Clone, Debug, PartialEq)]
pub enum ReportGenerationError {
    EmptyField(&'static str),
    MissingTraceability(&'static str),
    UnsafeContent(Vec<UnsafeReportMarker>),
    GraphSnapshotNotExportSafe {
        snapshot_id: GraphSnapshotId,
        reason: String,
    },
    ExportDenied(Vec<String>),
    UnsupportedExportFormat(ExportFormat),
    RedactionNotPassed,
    ReportContract(ReportContractError),
    Serialization(String),
    Storage(String),
}

impl ReportGenerationError {
    pub fn is_policy_or_privacy_denial(&self) -> bool {
        matches!(
            self,
            Self::UnsafeContent(_)
                | Self::GraphSnapshotNotExportSafe { .. }
                | Self::ExportDenied(_)
                | Self::RedactionNotPassed
        )
    }
}

impl fmt::Display for ReportGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::MissingTraceability(field) => {
                write!(f, "report generation requires traceability for {field}")
            }
            Self::UnsafeContent(markers) => {
                write!(
                    f,
                    "report content contains unsafe export markers: {markers:?}"
                )
            }
            Self::GraphSnapshotNotExportSafe {
                snapshot_id,
                reason,
            } => write!(
                f,
                "graph snapshot {snapshot_id} is not safe for report export: {reason}"
            ),
            Self::ExportDenied(reasons) => {
                write!(
                    f,
                    "report export denied by privacy gate: {}",
                    reasons.join("; ")
                )
            }
            Self::UnsupportedExportFormat(format) => {
                write!(f, "unsupported report export format: {}", format.as_str())
            }
            Self::RedactionNotPassed => write!(f, "report redaction did not pass"),
            Self::ReportContract(error) => write!(f, "{error}"),
            Self::Serialization(error) => write!(f, "report serialization failed: {error}"),
            Self::Storage(error) => write!(f, "privacy storage service failed: {error}"),
        }
    }
}

impl std::error::Error for ReportGenerationError {}

impl From<ReportContractError> for ReportGenerationError {
    fn from(value: ReportContractError) -> Self {
        Self::ReportContract(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsafeReportMarker {
    pub path_redacted: String,
    pub marker: String,
    pub category: RedactedDataCategory,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentReportInput {
    pub incident: Incident,
    pub alerts: Vec<Alert>,
    pub findings: Vec<Finding>,
    pub evidence_items: Vec<EvidenceItem>,
    pub graph_snapshots: Vec<GraphSnapshot>,
    pub attack_coverage: Option<AttackCoverageSummary>,
    pub fusion_summary: Option<FusionSummary>,
    pub baseline_summary: Option<DurableBaselineSummary>,
    pub investigation_drill_down: Option<InvestigationDrillDownSummary>,
    pub evidence_quality_summary: Option<EvidenceQualitySummary>,
    pub metadata_watch_status: Option<MetadataWatchControllerStatus>,
    pub metadata_sampling_batches: Vec<MetadataSamplingBatchSummary>,
    pub native_permission_status: Option<NativePermissionStatusSummary>,
    pub native_visibility_summary: Option<NativeVisibilitySummary>,
    pub native_sampler_readiness: Option<NativeSamplerReadinessSummary>,
    pub native_sampler_runtime: Option<NativeSamplerRuntimeSummary>,
    pub native_scheduler_operational: Option<NativeSchedulerOperationalSummary>,
    pub llm_alert_stories: Vec<LlmAlertStoryRecord>,
    pub response_plans: Vec<ResponsePlan>,
    pub response_results: Vec<ResponseResult>,
    pub rollback_results: Vec<RollbackResult>,
}

impl IncidentReportInput {
    pub fn new(incident: Incident) -> Self {
        Self {
            incident,
            alerts: Vec::new(),
            findings: Vec::new(),
            evidence_items: Vec::new(),
            graph_snapshots: Vec::new(),
            attack_coverage: None,
            fusion_summary: None,
            baseline_summary: None,
            investigation_drill_down: None,
            evidence_quality_summary: None,
            metadata_watch_status: None,
            metadata_sampling_batches: Vec::new(),
            native_permission_status: None,
            native_visibility_summary: None,
            native_sampler_readiness: None,
            native_sampler_runtime: None,
            native_scheduler_operational: None,
            llm_alert_stories: Vec::new(),
            response_plans: Vec::new(),
            response_results: Vec::new(),
            rollback_results: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportTraceability {
    pub incident_refs: Vec<IncidentId>,
    pub alert_refs: Vec<AlertId>,
    pub finding_refs: Vec<FindingId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub graph_snapshot_refs: Vec<GraphSnapshotId>,
    pub response_plan_refs: Vec<ResponsePlanId>,
    pub response_result_refs: Vec<ResponseResultId>,
    pub rollback_result_refs: Vec<RollbackResultId>,
    pub llm_story_refs: Vec<LlmAlertStoryId>,
}

impl ReportTraceability {
    fn new(incident_id: IncidentId) -> Self {
        Self {
            incident_refs: vec![incident_id],
            alert_refs: Vec::new(),
            finding_refs: Vec::new(),
            evidence_refs: Vec::new(),
            graph_snapshot_refs: Vec::new(),
            response_plan_refs: Vec::new(),
            response_result_refs: Vec::new(),
            rollback_result_refs: Vec::new(),
            llm_story_refs: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentReportOutput {
    pub report: Report,
    pub traceability: ReportTraceability,
    pub export_ready: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportTimelineEntry {
    pub timestamp: Timestamp,
    pub event_type: String,
    pub summary_redacted: String,
    pub alert_refs: Vec<AlertId>,
    pub finding_refs: Vec<FindingId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub response_result_refs: Vec<ResponseResultId>,
}

#[derive(Clone, Debug, Default)]
pub struct ReportTimelineBuilder;

impl ReportTimelineBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(&self, input: &IncidentReportInput) -> Vec<ReportTimelineEntry> {
        let mut entries = vec![ReportTimelineEntry {
            timestamp: Timestamp::now(),
            event_type: "incident_summary".to_string(),
            summary_redacted: input.incident.summary_redacted().to_string(),
            alert_refs: input.incident.alert_refs().to_vec(),
            finding_refs: input.incident.finding_refs().to_vec(),
            evidence_refs: Vec::new(),
            response_result_refs: Vec::new(),
        }];

        entries.extend(input.alerts.iter().map(|alert| ReportTimelineEntry {
            timestamp: Timestamp::now(),
            event_type: "alert_context".to_string(),
            summary_redacted: alert.summary_redacted().to_string(),
            alert_refs: vec![alert.id().clone()],
            finding_refs: alert.finding_refs().to_vec(),
            evidence_refs: Vec::new(),
            response_result_refs: Vec::new(),
        }));

        entries.extend(input.findings.iter().map(|finding| ReportTimelineEntry {
            timestamp: Timestamp::now(),
            event_type: "finding_context".to_string(),
            summary_redacted: finding.explanation().summary_redacted.clone(),
            alert_refs: Vec::new(),
            finding_refs: vec![finding.id().clone()],
            evidence_refs: finding.evidence_refs().to_vec(),
            response_result_refs: Vec::new(),
        }));

        entries.extend(
            input
                .evidence_items
                .iter()
                .map(|evidence| ReportTimelineEntry {
                    timestamp: evidence.timestamp.clone(),
                    event_type: "evidence_observed".to_string(),
                    summary_redacted: evidence.value_summary_redacted.clone(),
                    alert_refs: Vec::new(),
                    finding_refs: Vec::new(),
                    evidence_refs: vec![evidence.evidence_id.clone()],
                    response_result_refs: Vec::new(),
                }),
        );

        entries.extend(input.response_results.iter().map(|result| {
            let summary = if result.success {
                "response result recorded successfully"
            } else {
                "response result recorded with no execution success"
            };
            ReportTimelineEntry {
                timestamp: result.started_at.clone(),
                event_type: "response_result".to_string(),
                summary_redacted: summary.to_string(),
                alert_refs: Vec::new(),
                finding_refs: Vec::new(),
                evidence_refs: Vec::new(),
                response_result_refs: vec![result.result_id.clone()],
            }
        }));

        entries.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
        entries
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportEvidenceRow {
    pub evidence_id: EvidenceId,
    pub evidence_type: String,
    pub summary_redacted: String,
    pub confidence: f32,
    pub privacy_class: PrivacyClass,
    pub finding_refs: Vec<FindingId>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportEvidenceCollection {
    pub rows: Vec<ReportEvidenceRow>,
    pub evidence_refs: Vec<EvidenceId>,
}

#[derive(Clone, Debug, Default)]
pub struct ReportEvidenceCollector;

impl ReportEvidenceCollector {
    pub fn new() -> Self {
        Self
    }

    pub fn collect(&self, input: &IncidentReportInput) -> ReportEvidenceCollection {
        let mut rows = Vec::new();
        let mut evidence_refs = Vec::new();
        let mut known_evidence = HashSet::new();

        for evidence in &input.evidence_items {
            push_unique(&mut evidence_refs, evidence.evidence_id.clone());
            known_evidence.insert(evidence.evidence_id.clone());
            let finding_refs = input
                .findings
                .iter()
                .filter(|finding| finding.evidence_refs().contains(&evidence.evidence_id))
                .map(|finding| finding.id().clone())
                .collect::<Vec<_>>();
            rows.push(ReportEvidenceRow {
                evidence_id: evidence.evidence_id.clone(),
                evidence_type: evidence.evidence_type.clone(),
                summary_redacted: evidence.value_summary_redacted.clone(),
                confidence: evidence.confidence.value(),
                privacy_class: evidence.privacy_class.clone(),
                finding_refs,
            });
        }

        for finding in &input.findings {
            for evidence_id in finding.evidence_refs() {
                push_unique(&mut evidence_refs, evidence_id.clone());
                if known_evidence.contains(evidence_id) {
                    continue;
                }
                rows.push(ReportEvidenceRow {
                    evidence_id: evidence_id.clone(),
                    evidence_type: "referenced_evidence".to_string(),
                    summary_redacted: "evidence reference supplied by finding metadata".to_string(),
                    confidence: finding.confidence().value(),
                    privacy_class: PrivacyClass::Internal,
                    finding_refs: vec![finding.id().clone()],
                });
            }
        }

        ReportEvidenceCollection {
            rows,
            evidence_refs,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportGraphSnapshotSummary {
    pub snapshot_id: GraphSnapshotId,
    pub graph_type: String,
    pub node_count: u32,
    pub edge_count: u32,
    pub path_count: u32,
    pub risk_score: f32,
    pub confidence: f32,
    pub evidence_refs: Vec<EvidenceId>,
    pub time_bounds: TimeRange,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportSafeGraphSnapshotArtifact {
    pub snapshot: GraphSnapshot,
    pub summary: ReportGraphSnapshotSummary,
}

#[derive(Clone, Debug)]
pub struct ReportGraphSnapshotProvider {
    max_nodes: u32,
    max_edges: u32,
    redaction_pipeline: ReportRedactionPipeline,
}

impl Default for ReportGraphSnapshotProvider {
    fn default() -> Self {
        Self {
            max_nodes: DEFAULT_GRAPH_VIEW_NODE_LIMIT,
            max_edges: DEFAULT_GRAPH_VIEW_EDGE_LIMIT,
            redaction_pipeline: ReportRedactionPipeline::new(),
        }
    }
}

impl ReportGraphSnapshotProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_bounds(max_nodes: u32, max_edges: u32) -> Self {
        Self {
            max_nodes,
            max_edges,
            redaction_pipeline: ReportRedactionPipeline::new(),
        }
    }

    pub fn collect_export_safe(
        &self,
        incident_id: &IncidentId,
        snapshots: &[GraphSnapshot],
    ) -> Result<Vec<ExportSafeGraphSnapshotArtifact>, ReportGenerationError> {
        snapshots
            .iter()
            .filter(|snapshot| snapshot_matches_incident(snapshot, incident_id))
            .map(|snapshot| self.prepare_export_safe(snapshot))
            .collect()
    }

    pub fn prepare_export_safe(
        &self,
        snapshot: &GraphSnapshot,
    ) -> Result<ExportSafeGraphSnapshotArtifact, ReportGenerationError> {
        let export_safe = normalize_export_safe_graph_snapshot(
            snapshot,
            "report snapshot contains only redacted export-safe graph fields",
        )
        .map_err(|error| map_graph_snapshot_error(&snapshot.snapshot_id, error))?;
        let summary = self.summary(&export_safe)?;
        let snapshot_value = serde_json::to_value(&export_safe).map_err(|error| {
            ReportGenerationError::GraphSnapshotNotExportSafe {
                snapshot_id: export_safe.snapshot_id.clone(),
                reason: format!("snapshot serialization failed: {error}"),
            }
        })?;
        self.redaction_pipeline
            .validate_redacted_content(&snapshot_value)?;
        let summary_value = serde_json::to_value(&summary).map_err(|error| {
            ReportGenerationError::GraphSnapshotNotExportSafe {
                snapshot_id: export_safe.snapshot_id.clone(),
                reason: format!("graph summary serialization failed: {error}"),
            }
        })?;
        self.redaction_pipeline
            .validate_redacted_content(&summary_value)?;

        Ok(ExportSafeGraphSnapshotArtifact {
            snapshot: export_safe,
            summary,
        })
    }

    pub fn summarize_export_safe(
        &self,
        snapshot: &GraphSnapshot,
    ) -> Result<ReportGraphSnapshotSummary, ReportGenerationError> {
        self.prepare_export_safe(snapshot)
            .map(|artifact| artifact.summary)
    }

    fn summary(
        &self,
        snapshot: &GraphSnapshot,
    ) -> Result<ReportGraphSnapshotSummary, ReportGenerationError> {
        let time_bounds = snapshot.time_bounds.clone().ok_or_else(|| {
            ReportGenerationError::GraphSnapshotNotExportSafe {
                snapshot_id: snapshot.snapshot_id.clone(),
                reason: "snapshot is missing report time bounds".to_string(),
            }
        })?;

        if !time_bounds.is_bounded() {
            return Err(ReportGenerationError::GraphSnapshotNotExportSafe {
                snapshot_id: snapshot.snapshot_id.clone(),
                reason: "snapshot time bounds are not scoped".to_string(),
            });
        }

        if !matches!(
            snapshot.redaction_status,
            RedactionStatus::Redacted
                | RedactionStatus::Tokenized
                | RedactionStatus::Hashed
                | RedactionStatus::PartiallyRedacted
                | RedactionStatus::Suppressed
        ) {
            return Err(ReportGenerationError::GraphSnapshotNotExportSafe {
                snapshot_id: snapshot.snapshot_id.clone(),
                reason: "snapshot has not passed graph redaction".to_string(),
            });
        }

        if snapshot.node_count > self.max_nodes || snapshot.edge_count > self.max_edges {
            return Err(ReportGenerationError::GraphSnapshotNotExportSafe {
                snapshot_id: snapshot.snapshot_id.clone(),
                reason: "snapshot exceeds report bounds".to_string(),
            });
        }

        let evidence_refs = bounded_evidence_refs(
            snapshot.evidence_refs.iter().cloned().chain(
                snapshot
                    .path_summaries
                    .iter()
                    .flat_map(|path| path.evidence_refs.iter().cloned()),
            ),
        );
        if evidence_refs.is_empty() {
            return Err(ReportGenerationError::GraphSnapshotNotExportSafe {
                snapshot_id: snapshot.snapshot_id.clone(),
                reason: "snapshot is not evidence-backed".to_string(),
            });
        }

        Ok(ReportGraphSnapshotSummary {
            snapshot_id: snapshot.snapshot_id.clone(),
            graph_type: format!("{:?}", snapshot.graph_type),
            node_count: snapshot.node_count,
            edge_count: snapshot.edge_count,
            path_count: snapshot.path_count,
            risk_score: snapshot.risk_score.value(),
            confidence: snapshot.confidence.value(),
            evidence_refs,
            time_bounds,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportResponseSection {
    pub plan_refs: Vec<ResponsePlanId>,
    pub recommended_actions: Vec<ReportRecommendedActionSummary>,
    pub response_results: Vec<ReportResponseResultSummary>,
    pub rollback_status: Vec<ReportRollbackStatusSummary>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportRecommendedActionSummary {
    pub plan_id: ResponsePlanId,
    pub action_type: String,
    pub target_summary_redacted: String,
    pub scope_redacted: String,
    pub response_level: String,
    pub approval_required: bool,
    pub rollback_available: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportResponseResultSummary {
    pub response_result_id: ResponseResultId,
    pub executor: String,
    pub target_summary_redacted: String,
    pub success: bool,
    pub execution_disabled: bool,
    pub audit_event_type: String,
    pub rollback_available: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportRollbackStatusSummary {
    pub rollback_result_id: RollbackResultId,
    pub success: bool,
    pub audit_event_type: String,
    pub rollback_available: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ReportResponseSectionBuilder;

impl ReportResponseSectionBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        plans: &[ResponsePlan],
        results: &[ResponseResult],
        rollback_results: &[RollbackResult],
    ) -> ReportResponseSection {
        ReportResponseSection {
            plan_refs: plans.iter().map(|plan| plan.plan_id.clone()).collect(),
            recommended_actions: plans
                .iter()
                .flat_map(|plan| {
                    plan.recommended_actions
                        .iter()
                        .map(|action| ReportRecommendedActionSummary {
                            plan_id: plan.plan_id.clone(),
                            action_type: format!("{:?}", action.action_type),
                            target_summary_redacted: action.target.target_summary_redacted.clone(),
                            scope_redacted: action.scope.description_redacted.clone(),
                            response_level: format!("{:?}", action.response_level),
                            approval_required: action.approval_required,
                            rollback_available: action.rollback_available,
                        })
                })
                .collect(),
            response_results: results
                .iter()
                .map(|result| ReportResponseResultSummary {
                    response_result_id: result.result_id.clone(),
                    executor: result.executor.clone(),
                    target_summary_redacted: result.target.target_summary_redacted.clone(),
                    success: result.success,
                    execution_disabled: result.execution_disabled,
                    audit_event_type: result.audit_ref.event_type.clone(),
                    rollback_available: !result.rollback_token.trim().is_empty(),
                })
                .collect(),
            rollback_status: rollback_results
                .iter()
                .map(|result| ReportRollbackStatusSummary {
                    rollback_result_id: result.rollback_result_id.clone(),
                    success: result.success,
                    audit_event_type: result.audit_ref.event_type.clone(),
                    rollback_available: !result.rollback_token.trim().is_empty(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReportRedactionPipeline {
    redaction_engine: RedactionEngine,
}

impl ReportRedactionPipeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn default_summary(&self) -> RedactionSummary {
        safe_report_redaction_summary()
    }

    pub fn redact_content(&self, value: &Value) -> Result<Value, ReportGenerationError> {
        let redacted = self
            .redaction_engine
            .redact_json(value)
            .map_err(|error| ReportGenerationError::Storage(error.to_string()))?;
        self.validate_value("$", &redacted.value)?;
        Ok(redacted.value)
    }

    pub fn validate_redacted_content(&self, value: &Value) -> Result<(), ReportGenerationError> {
        self.validate_value("$", value)
    }

    pub fn validate_report(&self, report: &Report) -> Result<(), ReportGenerationError> {
        if !report.redaction_summary.passed {
            return Err(ReportGenerationError::RedactionNotPassed);
        }

        self.validate_text("report.title_redacted", &report.title_redacted)?;
        self.validate_text("report.summary_redacted", &report.summary_redacted)?;
        for section in &report.sections {
            self.validate_text("report.section.title_redacted", &section.title_redacted)?;
            self.validate_value("report.section.content_redacted", &section.content_redacted)?;
        }
        Ok(())
    }

    fn validate_value(&self, path: &str, value: &Value) -> Result<(), ReportGenerationError> {
        let mut markers = Vec::new();
        collect_unsafe_markers(path, value, &mut markers);
        if markers.is_empty() {
            Ok(())
        } else {
            Err(ReportGenerationError::UnsafeContent(markers))
        }
    }

    fn validate_text(&self, path: &'static str, value: &str) -> Result<(), ReportGenerationError> {
        let mut markers = Vec::new();
        collect_unsafe_text_marker(path, value, &mut markers);
        if markers.is_empty() {
            Ok(())
        } else {
            Err(ReportGenerationError::UnsafeContent(markers))
        }
    }
}

#[derive(Clone, Debug)]
pub struct IncidentReportGenerator {
    timeline_builder: ReportTimelineBuilder,
    evidence_collector: ReportEvidenceCollector,
    graph_snapshot_provider: ReportGraphSnapshotProvider,
    response_section_builder: ReportResponseSectionBuilder,
    redaction_pipeline: ReportRedactionPipeline,
}

#[derive(Clone, Copy)]
struct SectionTraceRefs<'a> {
    evidence_refs: &'a [EvidenceId],
    graph_snapshot_refs: &'a [GraphSnapshotId],
    response_result_refs: &'a [ResponseResultId],
    rollback_result_refs: &'a [RollbackResultId],
}

impl<'a> SectionTraceRefs<'a> {
    fn empty() -> Self {
        Self {
            evidence_refs: &[],
            graph_snapshot_refs: &[],
            response_result_refs: &[],
            rollback_result_refs: &[],
        }
    }

    fn evidence(evidence_refs: &'a [EvidenceId]) -> Self {
        Self {
            evidence_refs,
            ..Self::empty()
        }
    }

    fn evidence_and_responses(
        evidence_refs: &'a [EvidenceId],
        response_result_refs: &'a [ResponseResultId],
    ) -> Self {
        Self {
            evidence_refs,
            response_result_refs,
            ..Self::empty()
        }
    }

    fn graph(evidence_refs: &'a [EvidenceId], graph_snapshot_refs: &'a [GraphSnapshotId]) -> Self {
        Self {
            evidence_refs,
            graph_snapshot_refs,
            ..Self::empty()
        }
    }

    fn responses(response_result_refs: &'a [ResponseResultId]) -> Self {
        Self {
            response_result_refs,
            ..Self::empty()
        }
    }

    fn rollbacks(rollback_result_refs: &'a [RollbackResultId]) -> Self {
        Self {
            rollback_result_refs,
            ..Self::empty()
        }
    }
}

impl Default for IncidentReportGenerator {
    fn default() -> Self {
        Self {
            timeline_builder: ReportTimelineBuilder::new(),
            evidence_collector: ReportEvidenceCollector::new(),
            graph_snapshot_provider: ReportGraphSnapshotProvider::new(),
            response_section_builder: ReportResponseSectionBuilder::new(),
            redaction_pipeline: ReportRedactionPipeline::new(),
        }
    }
}

impl IncidentReportGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generate(
        &self,
        mut input: IncidentReportInput,
    ) -> Result<IncidentReportOutput, ReportGenerationError> {
        if input.incident.alert_refs().is_empty() {
            return Err(ReportGenerationError::MissingTraceability(
                "incident alerts",
            ));
        }
        input
            .response_results
            .retain(is_safe_disabled_response_result);
        input
            .rollback_results
            .retain(is_safe_non_executing_rollback_result);
        if let Some(attack_coverage) = &input.attack_coverage {
            attack_coverage.validate().map_err(|error| {
                ReportGenerationError::Serialization(format!(
                    "ATT&CK coverage summary failed safety validation: {error}"
                ))
            })?;
        }
        if let Some(fusion_summary) = &input.fusion_summary {
            fusion_summary.validate().map_err(|error| {
                ReportGenerationError::Serialization(format!(
                    "fusion summary failed safety validation: {error}"
                ))
            })?;
        }
        if let Some(baseline_summary) = &input.baseline_summary {
            baseline_summary.validate().map_err(|error| {
                ReportGenerationError::Serialization(format!(
                    "baseline summary failed safety validation: {error}"
                ))
            })?;
        }
        if let Some(investigation_drill_down) = &input.investigation_drill_down {
            investigation_drill_down.validate().map_err(|error| {
                ReportGenerationError::Serialization(format!(
                    "investigation drill-down summary failed safety validation: {error}"
                ))
            })?;
        }
        if let Some(evidence_quality_summary) = &input.evidence_quality_summary {
            evidence_quality_summary.validate().map_err(|error| {
                ReportGenerationError::Serialization(format!(
                    "evidence quality summary failed safety validation: {error}"
                ))
            })?;
        }
        if let Some(native_sampler_readiness) = &input.native_sampler_readiness {
            native_sampler_readiness.validate().map_err(|error| {
                ReportGenerationError::Serialization(format!(
                    "native sampler readiness summary failed safety validation: {error}"
                ))
            })?;
        }
        if let Some(native_sampler_runtime) = &input.native_sampler_runtime {
            native_sampler_runtime.validate().map_err(|error| {
                ReportGenerationError::Serialization(format!(
                    "native sampler runtime summary failed safety validation: {error}"
                ))
            })?;
        }
        if let Some(native_scheduler) = &input.native_scheduler_operational {
            native_scheduler.validate().map_err(|error| {
                ReportGenerationError::Serialization(format!(
                    "native scheduler operational summary failed safety validation: {error}"
                ))
            })?;
        }

        let redaction = self.redaction_pipeline.default_summary();
        let mut report = Report::new(
            ReportType::Incident,
            format!("Incident report: {}", input.incident.title_redacted()),
            input.incident.summary_redacted().to_string(),
            redaction.clone(),
        )?;
        report.privacy_class = PrivacyClass::Sensitive;

        let mut traceability = self.traceability(&input)?;
        report.incident_refs = traceability.incident_refs.clone();
        report.alert_refs = traceability.alert_refs.clone();
        report.finding_refs = traceability.finding_refs.clone();
        report.evidence_refs = traceability.evidence_refs.clone();
        report.response_result_refs = traceability.response_result_refs.clone();
        report.rollback_result_refs = traceability.rollback_result_refs.clone();
        report.llm_story_refs = traceability.llm_story_refs.clone();

        let timeline = self.timeline_builder.build(&input);
        let evidence = self.evidence_collector.collect(&input);
        traceability.evidence_refs = bounded_unique_refs(
            evidence
                .evidence_refs
                .clone()
                .into_iter()
                .chain(metadata_watch_evidence_refs(
                    &input.metadata_sampling_batches,
                ))
                .chain(
                    input
                        .baseline_summary
                        .as_ref()
                        .into_iter()
                        .flat_map(|summary| summary.evidence_refs.clone()),
                )
                .chain(investigation_drill_down_evidence_refs(
                    input.investigation_drill_down.as_ref(),
                ))
                .chain(
                    input
                        .native_sampler_runtime
                        .as_ref()
                        .into_iter()
                        .flat_map(|summary| summary.evidence_refs.clone()),
                )
                .collect(),
        );
        report.evidence_refs = traceability.evidence_refs.clone();
        let graph_snapshot_artifacts = self
            .graph_snapshot_provider
            .collect_export_safe(input.incident.id(), &input.graph_snapshots)?;
        let graph_summaries = graph_snapshot_artifacts
            .iter()
            .map(|artifact| artifact.summary.clone())
            .collect::<Vec<_>>();
        traceability.graph_snapshot_refs = bounded_unique_refs(
            graph_summaries
                .iter()
                .map(|summary| summary.snapshot_id.clone())
                .collect(),
        );
        report.graph_snapshot_refs = traceability.graph_snapshot_refs.clone();
        let export_safe_snapshots = graph_snapshot_artifacts
            .iter()
            .map(|artifact| artifact.snapshot.clone())
            .collect::<Vec<_>>();
        let response_section = self.response_section_builder.build(
            &input.response_plans,
            &input.response_results,
            &input.rollback_results,
        );

        let mut sections = vec![
            self.section(
                ReportSectionType::ExecutiveSummary,
                "Executive summary",
                json!({
                    "incident_type": input.incident.incident_type(),
                    "title_redacted": input.incident.title_redacted(),
                    "summary_redacted": input.incident.summary_redacted(),
                    "severity": severity_label(input.incident.severity()),
                    "confidence": input.incident.confidence().value(),
                    "state": format!("{:?}", input.incident.state()),
                    "alert_count": traceability.alert_refs.len(),
                    "finding_count": traceability.finding_refs.len(),
                    "evidence_count": traceability.evidence_refs.len()
                }),
                &redaction,
                SectionTraceRefs::empty(),
            )?,
            self.section(
                ReportSectionType::Timeline,
                "Timeline",
                json!({ "entries": timeline }),
                &redaction,
                SectionTraceRefs::evidence_and_responses(
                    &traceability.evidence_refs,
                    &traceability.response_result_refs,
                ),
            )?,
            self.section(
                ReportSectionType::EvidenceTable,
                "Evidence table",
                json!({
                    "rows": evidence.rows,
                    "row_count": evidence.evidence_refs.len()
                }),
                &redaction,
                SectionTraceRefs::evidence(&traceability.evidence_refs),
            )?,
            self.section(
                ReportSectionType::AffectedScope,
                "Affected process and destination scope",
                affected_scope_content(&input),
                &redaction,
                SectionTraceRefs::evidence(&traceability.evidence_refs),
            )?,
            self.section(
                ReportSectionType::GraphSnapshot,
                "Attack graph snapshot",
                json!({
                    "snapshots": graph_summaries,
                    "export_safe_snapshots": export_safe_snapshots,
                    "snapshot_count": traceability.graph_snapshot_refs.len(),
                    "bounded": true,
                    "evidence_backed": !traceability.graph_snapshot_refs.is_empty()
                }),
                &redaction,
                SectionTraceRefs::graph(
                    &traceability.evidence_refs,
                    &traceability.graph_snapshot_refs,
                ),
            )?,
        ];

        if let Some(attack_coverage) = &input.attack_coverage {
            sections.push(self.section(
                ReportSectionType::AttackCoverage,
                "ATT&CK coverage summary",
                json!({
                    "summary": attack_coverage,
                    "bounded": true,
                    "complete_coverage_claimed": false
                }),
                &redaction,
                SectionTraceRefs::evidence(&attack_coverage.evidence_refs),
            )?);
        }

        if let Some(fusion_summary) = &input.fusion_summary {
            let risk_refs = bounded_unique_refs(
                fusion_summary
                    .hypotheses
                    .iter()
                    .flat_map(|hypothesis| hypothesis.risk_refs.iter().cloned())
                    .collect(),
            );
            let attack_refs = bounded_unique_refs(
                fusion_summary
                    .hypotheses
                    .iter()
                    .flat_map(|hypothesis| hypothesis.attack_candidates.iter())
                    .map(|candidate| {
                        format!(
                            "{}:{}:{}",
                            candidate.tactic_id, candidate.technique_id, candidate.attack_version
                        )
                    })
                    .collect(),
            );
            sections.push(self.section(
                ReportSectionType::FusionSummary,
                "Multi-layer security fusion references",
                json!({
                    "fact_count": fusion_summary.fact_count,
                    "hypothesis_count": fusion_summary.hypothesis_count,
                    "fact_refs": fusion_summary.fact_refs,
                    "hypothesis_refs": fusion_summary.hypothesis_refs,
                    "evidence_refs": fusion_summary.evidence_refs,
                    "finding_refs": fusion_summary.finding_refs,
                    "risk_refs": risk_refs,
                    "attack_refs": attack_refs,
                    "graph_hint_refs": fusion_summary.graph_hint_refs,
                    "metadata_only": true,
                    "bounded_refs_only": true,
                    "automatic_llm_calls": false
                }),
                &redaction,
                SectionTraceRefs::evidence(&fusion_summary.evidence_refs),
            )?);
        }

        if let Some(baseline_summary) = &input.baseline_summary {
            sections.push(self.section(
                ReportSectionType::BaselineSummary,
                "Durable baseline and incident-linked fusion references",
                json!({
                    "baseline_count": baseline_summary.baseline_count,
                    "indicator_count": baseline_summary.indicator_count,
                    "incident_group_count": baseline_summary.incident_group_count,
                    "timeline_entry_count": baseline_summary.timeline_entry_count,
                    "source_reliability_count": baseline_summary.source_reliability_count,
                    "baseline_refs": baseline_summary.baseline_refs,
                    "indicator_refs": baseline_summary
                        .indicators
                        .iter()
                        .map(|indicator| indicator.indicator_id.clone())
                        .collect::<Vec<_>>(),
                    "incident_group_refs": baseline_summary
                        .incident_groups
                        .iter()
                        .map(|group| group.group_id.clone())
                        .collect::<Vec<_>>(),
                    "timeline_refs": baseline_summary
                        .incident_timeline
                        .iter()
                        .map(|entry| entry.timeline_entry_id.clone())
                        .collect::<Vec<_>>(),
                    "source_refs": baseline_summary
                        .source_reliability
                        .iter()
                        .map(|source| source.source_id.clone())
                        .collect::<Vec<_>>(),
                    "evidence_refs": baseline_summary.evidence_refs,
                    "fact_refs": baseline_summary.fact_refs,
                    "hypothesis_refs": baseline_summary.hypothesis_refs,
                    "finding_refs": baseline_summary.finding_refs,
                    "risk_refs": baseline_summary.risk_refs,
                    "provenance_refs": baseline_summary.provenance_refs,
                    "degraded_visibility_context": baseline_summary.degraded_visibility_context,
                    "missing_visibility_flags": baseline_summary.missing_visibility_flags,
                    "persistence_mode": baseline_summary.persistence_status.mode,
                    "automatic_durable_persistence": false,
                    "explicit_export_refs_only": true,
                    "metadata_only": true,
                    "bounded_refs_only": true,
                    "automatic_llm_calls": false,
                    "response_execution": false
                }),
                &redaction,
                SectionTraceRefs::evidence(&baseline_summary.evidence_refs),
            )?);
        }

        if let Some(drill_down) = &input.investigation_drill_down {
            let evidence_refs = investigation_drill_down_evidence_refs(Some(drill_down));
            sections.push(self.section(
                ReportSectionType::InvestigationDrillDown,
                "Investigation drill-down references",
                json!({
                    "hypothesis_count": drill_down.hypothesis_count,
                    "baseline_count": drill_down.baseline_count,
                    "incident_group_count": drill_down.incident_group_count,
                    "timeline_count": drill_down.timeline_count,
                    "source_reliability_count": drill_down.source_reliability_count,
                    "hypothesis_refs": drill_down
                        .hypotheses
                        .iter()
                        .map(|detail| detail.hypothesis_id.clone())
                        .collect::<Vec<_>>(),
                    "baseline_refs": drill_down
                        .baselines
                        .iter()
                        .map(|detail| detail.baseline_id.clone())
                        .collect::<Vec<_>>(),
                    "incident_group_refs": drill_down
                        .incident_groups
                        .iter()
                        .map(|detail| detail.group_id.clone())
                        .collect::<Vec<_>>(),
                    "timeline_refs": drill_down
                        .timeline
                        .iter()
                        .map(|detail| detail.timeline_entry_id.clone())
                        .collect::<Vec<_>>(),
                    "source_refs": drill_down
                        .source_reliability
                        .iter()
                        .map(|detail| detail.source_id.clone())
                        .collect::<Vec<_>>(),
                    "report_refs": drill_down.report_refs,
                    "export_refs": drill_down.export_refs,
                    "evidence_refs": evidence_refs,
                    "portable_no_retention": drill_down.portable_no_retention,
                    "metadata_only": drill_down.metadata_only,
                    "automatic_llm_calls": false,
                    "response_execution": false,
                    "bounded_refs_only": true
                }),
                &redaction,
                SectionTraceRefs::evidence(&evidence_refs),
            )?);
        }

        if let Some(quality_summary) = &input.evidence_quality_summary {
            let mut section = self.section(
                ReportSectionType::EvidenceQuality,
                "Evidence quality summary",
                json!({
                    "record_count": quality_summary.record_count,
                    "weak_single_signal_count": quality_summary.weak_single_signal_count,
                    "corroborated_count": quality_summary.corroborated_count,
                    "report_suitable_count": quality_summary.report_suitable_count,
                    "export_suitable_count": quality_summary.export_suitable_count,
                    "blocked_count": quality_summary.blocked_count,
                    "quality_refs": quality_summary.quality_refs,
                    "evidence_refs": quality_summary.evidence_refs,
                    "finding_refs": quality_summary.finding_refs,
                    "hypothesis_refs": quality_summary.hypothesis_refs,
                    "risk_refs": quality_summary.risk_refs,
                    "baseline_refs": quality_summary.baseline_refs,
                    "incident_group_refs": quality_summary.incident_group_refs,
                    "report_section_refs": quality_summary.report_section_refs,
                    "export_result_refs": quality_summary.export_result_refs,
                    "degraded_reason_summary": quality_summary.degraded_reason_summary,
                    "missing_visibility_flags": quality_summary.missing_visibility_flags,
                    "portable_no_retention": quality_summary.portable_no_retention,
                    "metadata_only": quality_summary.metadata_only,
                    "automatic_llm_calls": false,
                    "response_execution": false,
                    "bounded_refs_only": true
                }),
                &redaction,
                SectionTraceRefs::evidence(&quality_summary.evidence_refs),
            )?;
            let mut section_quality =
                if quality_summary.corroborated_count > 0 && quality_summary.blocked_count == 0 {
                    QualityBreakdown::corroborated_metadata()
                } else {
                    QualityBreakdown::metadata_only()
                };
            if quality_summary.blocked_count > 0 {
                section_quality = QualityBreakdown::blocked_by_redaction();
                section_quality.degraded_reasons = quality_summary.degraded_reason_summary.clone();
                section_quality.missing_visibility_flags =
                    quality_summary.missing_visibility_flags.clone();
            }
            section_quality.quality_refs = quality_summary.quality_refs.clone();
            section.quality_refs = quality_summary.quality_refs.clone();
            section.quality = section_quality;
            sections.push(section);
        }

        if input.metadata_watch_status.is_some() || !input.metadata_sampling_batches.is_empty() {
            let evidence_refs = metadata_watch_evidence_refs(&input.metadata_sampling_batches);
            sections.push(self.section(
                ReportSectionType::MetadataWatch,
                "Continuous metadata watch references",
                metadata_watch_content(
                    input.metadata_watch_status.as_ref(),
                    &input.metadata_sampling_batches,
                ),
                &redaction,
                SectionTraceRefs::evidence(&evidence_refs),
            )?);
        }

        if input.native_permission_status.is_some() || input.native_visibility_summary.is_some() {
            sections.push(self.section(
                ReportSectionType::NativeVisibility,
                "Authorized native visibility control-plane references",
                native_visibility_content(
                    input.native_permission_status.as_ref(),
                    input.native_visibility_summary.as_ref(),
                ),
                &redaction,
                SectionTraceRefs::empty(),
            )?);
        }

        if let Some(readiness) = &input.native_sampler_readiness {
            sections.push(self.section(
                ReportSectionType::NativeSamplerReadiness,
                "Read-only native sampler readiness references",
                json!({
                    "contract_count": readiness.contract_count,
                    "review_count": readiness.review_count,
                    "ready_when_implemented_count": readiness.ready_when_implemented_count,
                    "blocked_count": readiness.blocked_count,
                    "not_implemented_count": readiness.not_implemented_count,
                    "active_sampler_count": readiness.active_sampler_count,
                    "future_collection_allowed_count": readiness.future_collection_allowed_count,
                    "future_response_allowed_count": readiness.future_response_allowed_count,
                    "contract_refs": readiness.contract_refs,
                    "review_refs": readiness.review_refs,
                    "audit_refs": readiness.audit_refs,
                    "missing_endpoint_visibility_flags": readiness.missing_endpoint_visibility_flags,
                    "degraded_reasons": readiness.degraded_reasons,
                    "portable_default_active": readiness.portable_default_active,
                    "no_telemetry_collected": readiness.no_telemetry_collected,
                    "endpoint_security_facts_emitted": readiness.endpoint_security_facts_emitted,
                    "telemetry_collection_active": readiness.telemetry_collection_active,
                    "response_execution_allowed": readiness.response_execution_allowed,
                    "automatic_llm_calls": readiness.automatic_llm_calls,
                    "edr_coverage_claimed": false,
                    "bounded_refs_only": true
                }),
                &redaction,
                SectionTraceRefs::empty(),
            )?);
        }

        if let Some(runtime) = &input.native_sampler_runtime {
            sections.push(self.section(
                ReportSectionType::NativeSamplerRuntime,
                "Authorized read-only native sampler runtime references",
                native_sampler_runtime_content(runtime),
                &redaction,
                SectionTraceRefs::evidence(&runtime.evidence_refs),
            )?);
        }

        if let Some(scheduler) = &input.native_scheduler_operational {
            let mut section = self.section(
                ReportSectionType::NativeScheduler,
                "Native scheduler operational traceability",
                native_scheduler_operational_content(scheduler),
                &redaction,
                SectionTraceRefs::empty(),
            )?;
            section.quality_refs = scheduler.quality_refs.clone();
            sections.push(section);
        }

        if !input.llm_alert_stories.is_empty() {
            sections.push(self.section(
                ReportSectionType::LlmAlertStory,
                "AI-generated alert stories",
                json!({
                    "stories": input.llm_alert_stories,
                    "story_refs": traceability.llm_story_refs,
                    "story_count": traceability.llm_story_refs.len(),
                    "ai_generated": true,
                    "stored_refs_only": true
                }),
                &redaction,
                SectionTraceRefs::evidence(&traceability.evidence_refs),
            )?);
        }

        sections.extend([
            self.section(
                ReportSectionType::ResponseRecommendation,
                "Response recommendations",
                json!({
                    "plan_refs": response_section.plan_refs.clone(),
                    "recommended_actions": response_section.recommended_actions.clone(),
                    "recommend_first_default": true
                }),
                &redaction,
                SectionTraceRefs::empty(),
            )?,
            self.section(
                ReportSectionType::Recommendations,
                "Recommendations",
                json!({
                    "next_steps_redacted": [
                        "review approval-required response actions",
                        "confirm rollback metadata before any execution",
                        "export only the redacted report package"
                    ],
                    "recommendation_count": response_section.recommended_actions.len(),
                    "approval_required_count": response_section
                        .recommended_actions
                        .iter()
                        .filter(|action| action.approval_required)
                        .count(),
                    "no_real_response_execution": true
                }),
                &redaction,
                SectionTraceRefs::empty(),
            )?,
            self.section(
                ReportSectionType::ResponseResult,
                "Response results",
                json!({
                    "results": response_section.response_results.clone(),
                    "result_count": traceability.response_result_refs.len()
                }),
                &redaction,
                SectionTraceRefs::responses(&traceability.response_result_refs),
            )?,
            self.section(
                ReportSectionType::RollbackStatus,
                "Rollback status",
                json!({
                    "rollback_results": response_section.rollback_status.clone(),
                    "rollback_result_count": traceability.rollback_result_refs.len()
                }),
                &redaction,
                SectionTraceRefs::rollbacks(&traceability.rollback_result_refs),
            )?,
            self.section(
                ReportSectionType::PrivacyRedactionSummary,
                "Privacy redaction summary",
                redaction_summary_content(&redaction),
                &redaction,
                SectionTraceRefs::empty(),
            )?,
        ]);

        report.sections = sections;

        self.redaction_pipeline.validate_report(&report)?;
        let export_ready = matches!(report.status, ReportStatus::ReadyForExport);

        Ok(IncidentReportOutput {
            report,
            traceability,
            export_ready,
        })
    }

    fn traceability(
        &self,
        input: &IncidentReportInput,
    ) -> Result<ReportTraceability, ReportGenerationError> {
        let mut traceability = ReportTraceability::new(input.incident.id().clone());

        for alert_id in input.incident.alert_refs() {
            push_unique(&mut traceability.alert_refs, alert_id.clone());
        }
        for alert in &input.alerts {
            push_unique(&mut traceability.alert_refs, alert.id().clone());
            for finding_id in alert.finding_refs() {
                push_unique(&mut traceability.finding_refs, finding_id.clone());
            }
        }
        for finding_id in input.incident.finding_refs() {
            push_unique(&mut traceability.finding_refs, finding_id.clone());
        }
        for finding in &input.findings {
            push_unique(&mut traceability.finding_refs, finding.id().clone());
            for evidence_id in finding.evidence_refs() {
                push_bounded_unique(&mut traceability.evidence_refs, evidence_id.clone());
            }
        }
        for evidence in &input.evidence_items {
            push_bounded_unique(
                &mut traceability.evidence_refs,
                evidence.evidence_id.clone(),
            );
        }
        for plan in &input.response_plans {
            push_unique(&mut traceability.response_plan_refs, plan.plan_id.clone());
        }
        for result in &input.response_results {
            push_bounded_unique(
                &mut traceability.response_result_refs,
                result.result_id.clone(),
            );
        }
        for result in &input.rollback_results {
            push_bounded_unique(
                &mut traceability.rollback_result_refs,
                result.rollback_result_id.clone(),
            );
        }
        for story in &input.llm_alert_stories {
            story.validate().map_err(|error| {
                ReportGenerationError::Serialization(format!(
                    "LLM alert story failed safety validation: {error}"
                ))
            })?;
            push_bounded_unique(&mut traceability.llm_story_refs, story.story_id.clone());
            for evidence_ref in &story.evidence_refs {
                push_bounded_unique(&mut traceability.evidence_refs, evidence_ref.clone());
            }
        }

        if traceability.alert_refs.is_empty() {
            return Err(ReportGenerationError::MissingTraceability("alert refs"));
        }
        if traceability.finding_refs.is_empty() {
            return Err(ReportGenerationError::MissingTraceability("finding refs"));
        }
        if traceability.evidence_refs.is_empty() {
            return Err(ReportGenerationError::MissingTraceability("evidence refs"));
        }

        Ok(traceability)
    }

    fn section(
        &self,
        section_type: ReportSectionType,
        title: &'static str,
        content: Value,
        redaction: &RedactionSummary,
        refs: SectionTraceRefs<'_>,
    ) -> Result<ReportSection, ReportGenerationError> {
        let mut section = ReportSection::new(section_type, title, redaction.clone())?;
        section.content_redacted = self.redaction_pipeline.redact_content(&content)?;
        section.evidence_refs = refs.evidence_refs.to_vec();
        section.graph_snapshot_refs = refs.graph_snapshot_refs.to_vec();
        section.response_result_refs = refs.response_result_refs.to_vec();
        section.rollback_result_refs = refs.rollback_result_refs.to_vec();
        section.privacy_class = PrivacyClass::Sensitive;
        Ok(section)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedReport {
    pub report_id: ReportId,
    pub format: ExportFormat,
    pub content_redacted: String,
}

#[derive(Clone, Debug, Default)]
pub struct MarkdownReportRenderer;

impl MarkdownReportRenderer {
    pub fn new() -> Self {
        Self
    }

    pub fn render(&self, report: &Report) -> Result<RenderedReport, ReportGenerationError> {
        ensure_report_is_redacted(report)?;
        let mut content = format!(
            "# {}\n\n{}\n\n",
            report.title_redacted, report.summary_redacted
        );
        for section in &report.sections {
            content.push_str("## ");
            content.push_str(&section.title_redacted);
            content.push_str("\n\n```json\n");
            content.push_str(&redacted_json_pretty(&section.content_redacted)?);
            content.push_str("\n```\n\n");
        }
        Ok(RenderedReport {
            report_id: report.report_id.clone(),
            format: ExportFormat::Markdown,
            content_redacted: content,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct HtmlReportRenderer;

impl HtmlReportRenderer {
    pub fn new() -> Self {
        Self
    }

    pub fn render(&self, report: &Report) -> Result<RenderedReport, ReportGenerationError> {
        ensure_report_is_redacted(report)?;
        let mut content = format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>{}</title></head><body><h1>{}</h1><p>{}</p>",
            html_escape(&report.title_redacted),
            html_escape(&report.title_redacted),
            html_escape(&report.summary_redacted)
        );
        for section in &report.sections {
            content.push_str("<section><h2>");
            content.push_str(&html_escape(&section.title_redacted));
            content.push_str("</h2><pre>");
            content.push_str(&html_escape(&redacted_json_pretty(
                &section.content_redacted,
            )?));
            content.push_str("</pre></section>");
        }
        content.push_str("</body></html>");
        Ok(RenderedReport {
            report_id: report.report_id.clone(),
            format: ExportFormat::Html,
            content_redacted: content,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct RedactedJsonReportRenderer;

impl RedactedJsonReportRenderer {
    pub fn new() -> Self {
        Self
    }

    pub fn render(&self, report: &Report) -> Result<RenderedReport, ReportGenerationError> {
        ensure_report_is_redacted(report)?;
        Ok(RenderedReport {
            report_id: report.report_id.clone(),
            format: ExportFormat::RedactedJson,
            content_redacted: serde_json::to_string_pretty(report)
                .map_err(|error| ReportGenerationError::Serialization(error.to_string()))?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportExportGateRequest {
    pub report: Report,
    pub format: ExportFormat,
    pub policy: ReportExportPolicy,
    pub requested_by_redacted: String,
    pub user_confirmed: bool,
    pub audit_ref: AuditRef,
    pub destination_metadata_redacted: Option<String>,
    pub file_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportExportPackage {
    pub export_request: ExportRequest,
    pub export_result: ExportResult,
    pub rendered_report: RenderedReport,
}

#[derive(Clone, Debug, Default)]
pub struct ReportExportGate {
    redaction_pipeline: ReportRedactionPipeline,
    privacy_gate: ExportPrivacyGate,
    markdown_renderer: MarkdownReportRenderer,
    html_renderer: HtmlReportRenderer,
    json_renderer: RedactedJsonReportRenderer,
}

impl ReportExportGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare_export(
        &self,
        request: ReportExportGateRequest,
    ) -> Result<ReportExportPackage, ReportGenerationError> {
        if !request.format.is_supported_v1() {
            return Err(ReportGenerationError::UnsupportedExportFormat(
                request.format,
            ));
        }
        self.redaction_pipeline.validate_report(&request.report)?;
        request
            .policy
            .validate()
            .map_err(|error| ReportGenerationError::ExportDenied(vec![error.to_string()]))?;

        let decision = self
            .privacy_gate
            .evaluate(
                &request.policy,
                ExportPrivacyCheckRequest {
                    format: request.format.clone(),
                    redaction_summary: request.report.redaction_summary.clone(),
                    user_confirmed: request.user_confirmed,
                    audit_ref: Some(request.audit_ref.clone()),
                },
            )
            .map_err(|error| ReportGenerationError::Storage(error.to_string()))?;
        if !decision.allowed {
            return Err(ReportGenerationError::ExportDenied(decision.denied_reasons));
        }

        let rendered_report = match request.format {
            ExportFormat::Markdown => self.markdown_renderer.render(&request.report)?,
            ExportFormat::Html => self.html_renderer.render(&request.report)?,
            ExportFormat::RedactedJson => self.json_renderer.render(&request.report)?,
            ExportFormat::Unsupported(_) => {
                return Err(ReportGenerationError::UnsupportedExportFormat(
                    request.format,
                ));
            }
        };

        let export_request = ExportRequest::new(
            request.report.report_id.clone(),
            request.format,
            request.requested_by_redacted,
            request.report.redaction_summary.clone(),
            request.audit_ref,
        )?;
        let mut export_result = ExportResult::from_request(export_request.clone(), true);
        export_result.destination_metadata_redacted = request.destination_metadata_redacted;
        export_result.file_hash = request.file_hash;

        Ok(ReportExportPackage {
            export_request,
            export_result,
            rendered_report,
        })
    }
}

fn ensure_report_is_redacted(report: &Report) -> Result<(), ReportGenerationError> {
    if report.redaction_summary.passed
        && matches!(
            report.status,
            ReportStatus::ReadyForExport | ReportStatus::Exported
        )
    {
        Ok(())
    } else {
        Err(ReportGenerationError::RedactionNotPassed)
    }
}

fn safe_report_redaction_summary() -> RedactionSummary {
    let categories = vec![
        RedactedDataCategory::RawPacket,
        RedactedDataCategory::Payload,
        RedactedDataCategory::HttpBody,
        RedactedDataCategory::Cookie,
        RedactedDataCategory::Token,
        RedactedDataCategory::Credential,
        RedactedDataCategory::ApiKey,
        RedactedDataCategory::PrivateKey,
        RedactedDataCategory::FullQueryString,
        RedactedDataCategory::FormContent,
        RedactedDataCategory::CommandLine,
        RedactedDataCategory::LocalPath,
        RedactedDataCategory::Username,
        RedactedDataCategory::Sid,
    ];
    RedactionSummary {
        redaction_summary_id: sentinel_contracts::RedactionSummaryId::new_v4(),
        passed: true,
        redacted_field_count: categories.len() as u32,
        suppressed_section_count: 0,
        reviewer: None,
        completed_at: Some(Timestamp::now()),
        notes_redacted: vec![
            "report generated from redacted metadata contracts only".to_string(),
            "export requires policy check, user confirmation, and audit".to_string(),
        ],
        redacted_categories: categories,
    }
}

fn redaction_summary_content(redaction: &RedactionSummary) -> Value {
    json!({
        "redaction_summary_id": redaction.redaction_summary_id,
        "passed": redaction.passed,
        "redacted_field_count": redaction.redacted_field_count,
        "suppressed_section_count": redaction.suppressed_section_count,
        "completed_at": redaction.completed_at,
        "default_exclusions_active": true,
        "local_export_only": true
    })
}

fn affected_scope_content(input: &IncidentReportInput) -> Value {
    let entities = input
        .alerts
        .iter()
        .flat_map(|alert| alert.entity_refs().iter())
        .chain(
            input
                .findings
                .iter()
                .flat_map(|finding| finding.entity_refs()),
        )
        .cloned()
        .collect::<Vec<_>>();
    let process_count = entities
        .iter()
        .filter(|entity| matches!(entity.entity_type, sentinel_contracts::EntityType::Process))
        .count();
    let destination_count = entities
        .iter()
        .filter(|entity| {
            matches!(
                entity.entity_type,
                sentinel_contracts::EntityType::Ip
                    | sentinel_contracts::EntityType::Domain
                    | sentinel_contracts::EntityType::Url
                    | sentinel_contracts::EntityType::CloudResource
            )
        })
        .count();

    json!({
        "entity_count": entities.len(),
        "process_count": process_count,
        "destination_count": destination_count,
        "entities_redacted": entities
    })
}

fn metadata_watch_content(
    status: Option<&MetadataWatchControllerStatus>,
    batches: &[MetadataSamplingBatchSummary],
) -> Value {
    let batch_rows = batches
        .iter()
        .map(|batch| {
            json!({
                "batch_ref": batch.batch_id,
                "source_ref": batch.source_id,
                "source_kind": batch.source_kind,
                "parser_family": batch.parser_family,
                "health_state": batch.health_state,
                "sampled_record_count": batch.sampled_record_count,
                "sampled_byte_count": batch.sampled_byte_count,
                "skipped_record_count": batch.skipped_record_count,
                "malformed_record_count": batch.malformed_record_count,
                "duplicate_record_count": batch.duplicate_record_count,
                "backpressure_drop_count": batch.backpressure_drop_count,
                "emitted_topics": batch.emitted_topics,
                "fact_refs": batch.fact_refs,
                "evidence_refs": batch.evidence_refs,
                "finding_refs": batch.finding_refs,
                "risk_refs": batch.risk_refs,
                "report_refresh_marker": batch.report_refresh_marker,
                "attack_refresh_marker": batch.attack_refresh_marker,
                "story_available_marker": batch.story_available_marker,
                "triage_advisory_only": batch.triage_advisory_only,
                "automatic_llm_calls": false,
                "response_execution": false
            })
        })
        .collect::<Vec<_>>();

    json!({
        "controller_status": status,
        "batch_rows": batch_rows,
        "batch_count": batches.len(),
        "source_refs": bounded_unique_refs(
            batches
                .iter()
                .map(|batch| batch.source_id.clone())
                .collect(),
        ),
        "evidence_refs": metadata_watch_evidence_refs(batches),
        "finding_refs": bounded_unique_refs(
            batches
                .iter()
                .flat_map(|batch| batch.finding_refs.iter().cloned())
                .collect(),
        ),
        "risk_refs": bounded_unique_refs(
            batches
                .iter()
                .flat_map(|batch| batch.risk_refs.iter().cloned())
                .collect(),
        ),
        "metadata_only": true,
        "bounded_refs_only": true,
        "no_response_execution": true,
        "automatic_llm_calls": false
    })
}

fn native_visibility_content(
    permission: Option<&NativePermissionStatusSummary>,
    visibility: Option<&NativeVisibilitySummary>,
) -> Value {
    let degraded_reasons = visibility
        .map(|summary| {
            summary
                .degraded_reasons
                .iter()
                .map(|reason| reason.replace("authorization", "permission"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "capability_refs": permission
            .map(|summary| summary.capability_refs.clone())
            .unwrap_or_default(),
        "audit_refs": permission
            .map(|summary| summary.audit_refs.clone())
            .unwrap_or_default(),
        "capability_count": permission.map(|summary| summary.capability_count).unwrap_or(0),
        "permission_required_count": permission
            .map(|summary| summary.permission_required_count)
            .unwrap_or(0),
        "requested_count": permission.map(|summary| summary.requested_count).unwrap_or(0),
        "granted_inactive_count": permission
            .map(|summary| summary.granted_inactive_count)
            .unwrap_or(0),
        "revoked_count": permission.map(|summary| summary.revoked_count).unwrap_or(0),
        "degraded_count": permission.map(|summary| summary.degraded_count).unwrap_or(0),
        "unsupported_count": permission.map(|summary| summary.unsupported_count).unwrap_or(0),
        "session_bound_permission": permission
            .map(|summary| summary.session_bound_authorization)
            .unwrap_or(true),
        "available_scope_categories": visibility
            .map(|summary| summary.available_scope_categories.clone())
            .unwrap_or_default(),
        "missing_visibility_flags": visibility
            .map(|summary| summary.missing_visibility_flags.clone())
            .unwrap_or_default(),
        "degraded_reasons": degraded_reasons,
        "future_sampler_ready": false,
        "control_plane_only": true,
        "telemetry_included": false,
        "endpoint_values_included": false,
        "native_required_attack_coverage_supported": false,
        "response_execution": false,
        "automatic_llm_calls": false,
        "bounded_refs_only": true
    })
}

fn native_sampler_runtime_content(runtime: &NativeSamplerRuntimeSummary) -> Value {
    let status_rows = runtime
        .statuses
        .iter()
        .map(|status| {
            json!({
                "sampler_ref": status.sampler_id,
                "category": status.category,
                "runtime_state": status.runtime_state,
                "permission_state": status.permission_state,
                "provider_category": status.provider_category,
                "platform_category": status.platform_category,
                "provider_availability_state": status.provider_availability_state,
                "health_state": status.health_state,
                "degraded_reason": status.degraded_reason,
                "missing_prerequisite_flags": status.missing_prerequisite_flags,
                "latest_batch_ref": status.latest_batch_id,
                "latest_sample_time_bucket": status.latest_sample_time_bucket,
                "counter_summary": status.counters,
                "emitted_topics": status.emitted_topics,
                "fact_refs": status.fact_refs,
                "evidence_refs": status.evidence_refs,
                "audit_refs": status.audit_refs,
                "provenance_id": status.provenance_id,
                "telemetry_collection_active": status.telemetry_collection_active,
                "response_execution_allowed": false,
                "service_installation_started": false,
                "driver_loading_started": false,
                "host_mutation_performed": false,
                "automatic_llm_calls": false
            })
        })
        .collect::<Vec<_>>();

    json!({
        "runtime_count": runtime.runtime_count,
        "active_count": runtime.active_count,
        "paused_count": runtime.paused_count,
        "degraded_count": runtime.degraded_count,
        "stopped_count": runtime.stopped_count,
        "revoked_count": runtime.revoked_count,
        "latest_batch_refs": runtime.latest_batch_refs,
        "fact_refs": runtime.fact_refs,
        "evidence_refs": runtime.evidence_refs,
        "audit_refs": runtime.audit_refs,
        "service_category_counts": runtime.service_category_counts,
        "service_state_counts": runtime.service_state_counts,
        "startup_type_counts": runtime.startup_type_counts,
        "process_category_counts": runtime.process_category_counts,
        "parent_process_category_counts": runtime.parent_process_category_counts,
        "process_relation_counts": runtime.process_relation_counts,
        "execution_context_counts": runtime.execution_context_counts,
        "process_trust_counts": runtime.process_trust_counts,
        "process_signedness_counts": runtime.process_signedness_counts,
        "process_privilege_counts": runtime.process_privilege_counts,
        "process_lifecycle_counts": runtime.process_lifecycle_counts,
        "quality_bucket": runtime.quality_bucket,
        "service_visibility_available": runtime.service_visibility_available,
        "native_health_visibility_available": runtime.native_health_visibility_available,
        "process_visibility_available": runtime.process_visibility_available,
        "parent_process_visibility_available": runtime.parent_process_visibility_available,
        "process_network_attribution_available": false,
        "packet_visibility_available": false,
        "response_execution_allowed": false,
        "edr_coverage_claimed": false,
        "automatic_llm_calls": false,
        "status_rows": status_rows,
        "generated_at": runtime.generated_at,
        "metadata_only": true,
        "bounded_refs_only": true,
        "category_only_process_telemetry": runtime.process_visibility_available,
        "specific_process_identity_unavailable": true,
        "no_process_network_attribution": true,
        "no_packet_capture": true,
        "no_service_installation": true,
        "no_host_mutation": true
    })
}

fn native_scheduler_operational_content(scheduler: &NativeSchedulerOperationalSummary) -> Value {
    let safe_schedule_rows = scheduler
        .safe_persisted_schedules
        .iter()
        .map(|schedule| {
            json!({
                "sampler_ref": schedule.sampler_id,
                "sampler_category": schedule.sampler_category,
                "schedule_enabled": schedule.schedule_enabled,
                "interval_bucket": schedule.interval_bucket,
                "timeout_bucket": schedule.timeout_bucket,
                "retry_budget_bucket": schedule.retry_budget_bucket,
                "provenance_id": schedule.provenance_id,
                "redaction_status": schedule.redaction_status,
            })
        })
        .collect::<Vec<_>>();
    let freshness_dimension_rows = scheduler
        .freshness_summary
        .as_ref()
        .map(|summary| {
            summary
                .dimensions
                .iter()
                .map(|dimension| {
                    json!({
                        "dimension": dimension.dimension,
                        "sampler_ref": dimension.sampler_id,
                        "freshness_state": dimension.freshness_state,
                        "age_bucket": dimension.age_bucket,
                        "source_reliability_bucket": dimension.source_reliability_bucket,
                        "visibility_completeness_bucket": dimension.visibility_completeness_bucket,
                        "evidence_quality_bucket": dimension.evidence_quality_bucket,
                        "degraded_reason": dimension.degraded_reason,
                        "batch_refs": dimension.batch_refs,
                        "fact_refs": dimension.fact_refs,
                        "audit_refs": dimension.audit_refs,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let missed_sample_dimension_rows = scheduler
        .missed_sample_summary
        .as_ref()
        .map(|summary| {
            summary
                .dimensions
                .iter()
                .map(|dimension| {
                    json!({
                        "dimension": dimension.dimension,
                        "sampler_ref": dimension.sampler_id,
                        "missed_sample_state": dimension.missed_sample_state,
                        "expected_interval_bucket": dimension.expected_interval_bucket,
                        "missed_expected_count_bucket": dimension.missed_expected_count_bucket,
                        "blocked_reason": dimension.blocked_reason,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "scheduler_health": scheduler.scheduler_health,
        "controller_state": scheduler.status.controller_state,
        "enabled_schedule_count": scheduler.status.enabled_schedule_count,
        "eligible_schedule_count": scheduler.status.eligible_schedule_count,
        "cycle_count": scheduler.status.cycle_count,
        "completed_cycle_count": scheduler.status.completed_cycle_count,
        "skipped_cycle_count": scheduler.status.skipped_cycle_count,
        "backpressure_state": scheduler.status.backpressure_state,
        "backpressure_cycle_count": scheduler.status.backpressure_cycle_count,
        "freshness_stale_dimension_count": scheduler.status.freshness_stale_dimension_count,
        "freshness_missing_dimension_count": scheduler.status.freshness_missing_dimension_count,
        "missed_sample_dimension_count": scheduler.status.missed_sample_dimension_count,
        "retry_scheduled_count": scheduler.retry_summary.retry_scheduled_count,
        "retry_exhausted_count": scheduler.retry_summary.retry_exhausted_count,
        "retry_pending_sampler_count": scheduler.retry_summary.retry_pending_sampler_count,
        "scheduler_refs": scheduler.scheduler_refs,
        "freshness_refs": scheduler.freshness_refs,
        "missed_sample_refs": scheduler.missed_sample_refs,
        "quality_refs": scheduler.quality_refs,
        "safe_schedule_rows": safe_schedule_rows,
        "freshness_dimension_rows": freshness_dimension_rows,
        "missed_sample_dimension_rows": missed_sample_dimension_rows,
        "safe_persistence_only": scheduler.safe_persistence_only,
        "raw_native_data_persisted": scheduler.raw_native_data_persisted,
        "runtime_subject_persisted": scheduler.runtime_subject_persisted,
        "source_location_persisted": scheduler.source_location_persisted,
        "launch_text_persisted": scheduler.launch_text_persisted,
        "machine_identifier_persisted": scheduler.machine_identifier_persisted,
        "scheduler_enablement_started": scheduler.scheduler_enablement_started,
        "provider_refresh_started": scheduler.provider_refresh_started,
        "report_export_side_effects": false,
        "provider_refresh_on_report": false,
        "scheduler_enablement_on_report": false,
        "response_execution": false,
        "automatic_llm_calls": false,
        "redacted_input_only": true,
        "explicit_action_only": true,
        "bounded_refs_only": true,
        "metadata_only": true,
        "generated_at": scheduler.generated_at,
    })
}

fn metadata_watch_evidence_refs(batches: &[MetadataSamplingBatchSummary]) -> Vec<EvidenceId> {
    bounded_unique_refs(
        batches
            .iter()
            .flat_map(|batch| batch.evidence_refs.iter().cloned())
            .collect(),
    )
}

fn investigation_drill_down_evidence_refs(
    summary: Option<&InvestigationDrillDownSummary>,
) -> Vec<EvidenceId> {
    bounded_unique_refs(
        summary
            .into_iter()
            .flat_map(|summary| {
                summary
                    .hypotheses
                    .iter()
                    .flat_map(|detail| detail.evidence_refs.iter().cloned())
                    .chain(
                        summary
                            .baselines
                            .iter()
                            .flat_map(|detail| detail.evidence_refs.iter().cloned()),
                    )
                    .chain(
                        summary
                            .incident_groups
                            .iter()
                            .flat_map(|detail| detail.evidence_refs.iter().cloned()),
                    )
                    .chain(
                        summary
                            .source_reliability
                            .iter()
                            .flat_map(|detail| detail.evidence_refs.iter().cloned()),
                    )
            })
            .collect(),
    )
}

fn snapshot_matches_incident(snapshot: &GraphSnapshot, incident_id: &IncidentId) -> bool {
    matches!(&snapshot.scope, GraphScope::Incident(id) if id == incident_id)
}

fn map_graph_snapshot_error(
    snapshot_id: &GraphSnapshotId,
    error: GraphAnalyticsError,
) -> ReportGenerationError {
    ReportGenerationError::GraphSnapshotNotExportSafe {
        snapshot_id: snapshot_id.clone(),
        reason: error.to_string(),
    }
}

fn severity_label(severity: &SecuritySeverity) -> &'static str {
    match severity {
        SecuritySeverity::Informational => "informational",
        SecuritySeverity::Low => "low",
        SecuritySeverity::Medium => "medium",
        SecuritySeverity::High => "high",
        SecuritySeverity::Critical => "critical",
    }
}

fn redacted_json_pretty(value: &Value) -> Result<String, ReportGenerationError> {
    serde_json::to_string_pretty(value)
        .map_err(|error| ReportGenerationError::Serialization(error.to_string()))
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn collect_unsafe_markers(path: &str, value: &Value, markers: &mut Vec<UnsafeReportMarker>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let child_path = format!("{path}.{key}");
                collect_unsafe_key_marker(&child_path, key, markers);
                collect_unsafe_markers(&child_path, nested, markers);
            }
        }
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                collect_unsafe_markers(&format!("{path}[{index}]"), nested, markers);
            }
        }
        Value::String(value) => collect_unsafe_text_marker(path, value, markers),
        _ => {}
    }
}

fn collect_unsafe_key_marker(path: &str, key: &str, markers: &mut Vec<UnsafeReportMarker>) {
    let lower = key.to_ascii_lowercase();
    for (needle, category) in FORBIDDEN_KEY_MARKERS {
        if lower.contains(needle) {
            markers.push(UnsafeReportMarker {
                path_redacted: path.to_string(),
                marker: (*needle).to_string(),
                category: category.clone(),
            });
            break;
        }
    }
}

fn collect_unsafe_text_marker(path: &str, value: &str, markers: &mut Vec<UnsafeReportMarker>) {
    if value.starts_with("[REDACTED_") || value.starts_with("user:local#") {
        return;
    }

    let lower = value.to_ascii_lowercase();
    for (needle, category) in FORBIDDEN_TEXT_MARKERS {
        if lower.contains(needle) {
            markers.push(UnsafeReportMarker {
                path_redacted: path.to_string(),
                marker: (*needle).to_string(),
                category: category.clone(),
            });
            break;
        }
    }
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn push_bounded_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if values.len() >= MAX_TRACEABILITY_REFS || values.contains(&value) {
        return;
    }
    values.push(value);
}

fn bounded_unique_refs<T: PartialEq>(values: Vec<T>) -> Vec<T> {
    let mut bounded = Vec::new();
    for value in values {
        push_bounded_unique(&mut bounded, value);
    }
    bounded
}

fn bounded_evidence_refs(values: impl Iterator<Item = EvidenceId>) -> Vec<EvidenceId> {
    let mut refs = values.collect::<Vec<_>>();
    refs.sort_by_key(|value| value.to_string());
    refs.dedup();
    refs.truncate(MAX_EXPORT_GRAPH_EVIDENCE_REFS);
    refs
}

fn is_safe_disabled_response_result(result: &ResponseResult) -> bool {
    let event_type = normalized_marker(&result.audit_ref.event_type);
    result.execution_disabled
        && result.is_replay
        && !result.success
        && result.ended_at.is_some()
        && result.rollback_token.trim().is_empty()
        && event_type.contains("execution_disabled")
}

fn is_safe_non_executing_rollback_result(result: &RollbackResult) -> bool {
    let event_type = normalized_marker(&result.audit_ref.event_type);
    let summary = result
        .error_summary_redacted
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    !result.success
        && result.ended_at.is_some()
        && (event_type.contains("rollback_requested") || event_type.contains("rollback_disabled"))
        && (summary.contains("no privileged executor has run")
            || summary.contains("execution is disabled")
            || summary.contains("recorded only"))
}

fn normalized_marker(value: &str) -> String {
    value.replace('.', "_").to_ascii_lowercase()
}

const FORBIDDEN_KEY_MARKERS: &[(&str, RedactedDataCategory)] = &[
    ("raw_packet", RedactedDataCategory::RawPacket),
    ("packet_bytes", RedactedDataCategory::RawPacket),
    ("raw_payload", RedactedDataCategory::Payload),
    ("payload", RedactedDataCategory::Payload),
    ("http_body", RedactedDataCategory::HttpBody),
    ("request_body", RedactedDataCategory::HttpBody),
    ("response_body", RedactedDataCategory::HttpBody),
    ("cookie", RedactedDataCategory::Cookie),
    ("authorization", RedactedDataCategory::Token),
    ("auth_header", RedactedDataCategory::Token),
    ("token", RedactedDataCategory::Token),
    ("credential", RedactedDataCategory::Credential),
    ("password", RedactedDataCategory::Credential),
    ("api_key", RedactedDataCategory::ApiKey),
    ("apikey", RedactedDataCategory::ApiKey),
    ("private_key", RedactedDataCategory::PrivateKey),
    ("query_string", RedactedDataCategory::FullQueryString),
    ("full_query", RedactedDataCategory::FullQueryString),
    ("form_content", RedactedDataCategory::FormContent),
    ("file_content", RedactedDataCategory::Payload),
    ("browser_form", RedactedDataCategory::FormContent),
    ("command_line", RedactedDataCategory::CommandLine),
    ("local_path", RedactedDataCategory::LocalPath),
];

const FORBIDDEN_TEXT_MARKERS: &[(&str, RedactedDataCategory)] = &[
    ("authorization:", RedactedDataCategory::Token),
    ("bearer ", RedactedDataCategory::Token),
    ("set-cookie", RedactedDataCategory::Cookie),
    ("cookie:", RedactedDataCategory::Cookie),
    ("password=", RedactedDataCategory::Credential),
    ("password:", RedactedDataCategory::Credential),
    ("api_key=", RedactedDataCategory::ApiKey),
    ("apikey=", RedactedDataCategory::ApiKey),
    ("begin private key", RedactedDataCategory::PrivateKey),
    ("private key", RedactedDataCategory::PrivateKey),
    ("session_token", RedactedDataCategory::Token),
    ("access_token", RedactedDataCategory::Token),
    ("refresh_token", RedactedDataCategory::Token),
    ("raw_packet=", RedactedDataCategory::RawPacket),
    ("packet_bytes", RedactedDataCategory::RawPacket),
    ("raw_payload=", RedactedDataCategory::Payload),
    ("payload_blob", RedactedDataCategory::Payload),
    ("http_body=", RedactedDataCategory::HttpBody),
    ("query_string=", RedactedDataCategory::FullQueryString),
    ("form_content=", RedactedDataCategory::FormContent),
    ("file_content=", RedactedDataCategory::Payload),
    ("command_line=", RedactedDataCategory::CommandLine),
    ("c:\\users\\", RedactedDataCategory::LocalPath),
    ("\\appdata\\", RedactedDataCategory::LocalPath),
    ("%appdata%", RedactedDataCategory::LocalPath),
    ("%localappdata%", RedactedDataCategory::LocalPath),
    ("/users/", RedactedDataCategory::LocalPath),
    ("/home/", RedactedDataCategory::LocalPath),
    ("/var/tmp/", RedactedDataCategory::LocalPath),
    ("/tmp/", RedactedDataCategory::LocalPath),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        Alert, AttackCoverageConfidenceBucket, AttackCoverageCount, AttackCoverageState,
        AttackCoverageTechniqueRow, AttackLastObservedBucket, AttackObservedCountBucket,
        AttackRequiredVisibility, BaselinePersistenceStatus, BaselineRecordId, BaselineScope,
        DurableBaselineSummary, EntityId, EntityRef, EntityType, EvidenceQualityBucket,
        EvidenceQualityId, EvidenceQualityRecord, EvidenceQualitySummary,
        EvidenceQualityTargetKind, FindingExplanation, GraphEdgeType, GraphEdgeViewModel,
        GraphNodeType, GraphNodeViewModel, GraphPathSummary, GraphPathType, GraphRedactionSummary,
        GraphType, MetadataParserFamily, MetadataSamplingBatchId, MetadataSamplingBatchSummary,
        MetadataSourceHealthState, MetadataWatchControllerStatus, MetadataWatchSourceId,
        MetadataWatchSourceKind, NativePermissionStatusSummary, NativeVisibilityScopeCategory,
        NativeVisibilitySummary, OperationalInfluenceBucket, QualityScore, RedactedLabel,
        ResponseActionId, ResponseActionType, ResponseLevel, ResponsePlanSource, ResponseScope,
        ResponseTarget, RiskEventId, RollbackPlan, SecurityFactId,
    };

    #[test]
    fn incident_report_includes_required_sections_and_traceability(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let input = report_input()?;
        let output = IncidentReportGenerator::new().generate(input)?;

        assert!(output.export_ready);
        assert_eq!(output.traceability.incident_refs.len(), 1);
        assert_eq!(output.traceability.alert_refs.len(), 1);
        assert_eq!(output.traceability.finding_refs.len(), 1);
        assert_eq!(output.traceability.evidence_refs.len(), 1);
        assert_eq!(output.traceability.graph_snapshot_refs.len(), 1);
        assert_eq!(output.traceability.response_plan_refs.len(), 1);
        assert_eq!(output.traceability.response_result_refs.len(), 1);
        assert_eq!(output.traceability.rollback_result_refs.len(), 1);
        assert_eq!(output.report.response_result_refs.len(), 1);
        assert_eq!(output.report.rollback_result_refs.len(), 1);

        let section_types = output
            .report
            .sections
            .iter()
            .map(|section| section.section_type.clone())
            .collect::<Vec<_>>();
        for required in [
            ReportSectionType::ExecutiveSummary,
            ReportSectionType::Timeline,
            ReportSectionType::EvidenceTable,
            ReportSectionType::AffectedScope,
            ReportSectionType::GraphSnapshot,
            ReportSectionType::AttackCoverage,
            ReportSectionType::ResponseRecommendation,
            ReportSectionType::Recommendations,
            ReportSectionType::ResponseResult,
            ReportSectionType::RollbackStatus,
            ReportSectionType::PrivacyRedactionSummary,
        ] {
            assert!(section_types.contains(&required));
        }
        let graph_section = output
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::GraphSnapshot)
            .expect("graph section");
        let export_safe_snapshots = graph_section
            .content_redacted
            .get("export_safe_snapshots")
            .and_then(Value::as_array)
            .expect("export-safe graph snapshots");
        assert_eq!(export_safe_snapshots.len(), 1);
        assert!(export_safe_snapshots[0].get("selected_nodes").is_some());
        assert!(export_safe_snapshots[0].get("selected_edges").is_some());
        let serialized_snapshot =
            serde_json::to_string(&export_safe_snapshots[0]).expect("graph snapshot json");
        assert!(!serialized_snapshot.contains("\"entity_id\""));
        assert!(!serialized_snapshot.contains("\"finding_id\""));
        assert!(!serialized_snapshot.contains("\"alert_id\""));
        assert!(!serialized_snapshot.contains("\"incident_id\""));
        assert!(!serialized_snapshot.contains("\"custom_ref\""));
        let attack_section = output
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::AttackCoverage)
            .expect("attack coverage section");
        assert_eq!(attack_section.evidence_refs.len(), 1);
        assert_eq!(
            attack_section
                .content_redacted
                .pointer("/complete_coverage_claimed")
                .and_then(Value::as_bool),
            Some(false)
        );
        let serialized_attack =
            serde_json::to_string(&attack_section.content_redacted).expect("attack json");
        assert!(!serialized_attack.contains("session_token"));
        assert!(!serialized_attack.contains("credential"));
        assert!(!serialized_attack.contains("raw_payload"));
        let rollback_section = output
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::RollbackStatus)
            .expect("rollback section");
        assert_eq!(rollback_section.rollback_result_refs.len(), 1);
        assert!(rollback_section.response_result_refs.is_empty());
        Ok(())
    }

    #[test]
    fn incident_report_fusion_section_contains_bounded_refs_only(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = report_input()?;
        let evidence_ref = input.evidence_items[0].evidence_id.clone();
        let finding_ref = input.findings[0].id().clone();
        let fact_ref = sentinel_contracts::SecurityFactId::new_v4();
        let hypothesis_ref = sentinel_contracts::AttackHypothesisId::new_v4();
        let graph_hint_ref = sentinel_contracts::GraphHintId::new_v4();
        input.fusion_summary = Some(FusionSummary {
            generated_at: Timestamp::now(),
            sampler_health: crate::multi_layer_fusion::layered_sampler_catalog()?,
            fact_count: 1,
            hypothesis_count: 1,
            facts: Vec::new(),
            hypotheses: Vec::new(),
            top_correlated_layers: Vec::new(),
            top_hypothesis_categories: Vec::new(),
            degraded_visibility_context: vec!["metadata_only_visibility".to_string()],
            fact_refs: vec![fact_ref.clone()],
            hypothesis_refs: vec![hypothesis_ref.clone()],
            evidence_refs: vec![evidence_ref],
            finding_refs: vec![finding_ref],
            graph_hint_refs: vec![graph_hint_ref.clone()],
            quality: QualityBreakdown::metadata_only(),
            privacy_class: PrivacyClass::Internal,
            automatic_llm_calls: false,
        });

        let output = IncidentReportGenerator::new().generate(input)?;
        let fusion = output
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::FusionSummary)
            .expect("fusion section");

        assert_eq!(
            fusion.content_redacted["fact_refs"][0],
            fact_ref.to_string()
        );
        assert_eq!(
            fusion.content_redacted["hypothesis_refs"][0],
            hypothesis_ref.to_string()
        );
        assert_eq!(
            fusion.content_redacted["graph_hint_refs"][0],
            graph_hint_ref.to_string()
        );
        assert!(fusion.content_redacted.get("facts").is_none());
        assert!(fusion.content_redacted.get("hypotheses").is_none());
        assert_eq!(fusion.content_redacted["bounded_refs_only"], json!(true));
        assert_eq!(fusion.content_redacted["automatic_llm_calls"], json!(false));
        Ok(())
    }

    #[test]
    fn incident_report_baseline_section_contains_bounded_refs_only(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = report_input()?;
        let evidence_ref = input.evidence_items[0].evidence_id.clone();
        let fact_ref = SecurityFactId::new_v4();
        let hypothesis_ref = sentinel_contracts::AttackHypothesisId::new_v4();
        let baseline_ref = BaselineRecordId::new_v4();
        input.baseline_summary = Some(DurableBaselineSummary {
            generated_at: Timestamp::now(),
            scope: BaselineScope::CurrentSession,
            persistence_status: BaselinePersistenceStatus::portable_no_retention(),
            baseline_count: 1,
            indicator_count: 0,
            incident_group_count: 0,
            timeline_entry_count: 0,
            source_reliability_count: 0,
            records: Vec::new(),
            indicators: Vec::new(),
            incident_groups: Vec::new(),
            incident_timeline: Vec::new(),
            source_reliability: Vec::new(),
            baseline_refs: vec![baseline_ref.clone()],
            evidence_refs: vec![evidence_ref.clone()],
            fact_refs: vec![fact_ref.clone()],
            hypothesis_refs: vec![hypothesis_ref.clone()],
            finding_refs: Vec::new(),
            risk_refs: Vec::new(),
            attack_refs: Vec::new(),
            provenance_refs: Vec::new(),
            degraded_visibility_context: vec!["metadata_only_visibility".to_string()],
            missing_visibility_flags: vec!["no_process_visibility".to_string()],
            quality: QualityBreakdown::metadata_only(),
            report_ref_count: 0,
            export_ref_count: 0,
            automatic_llm_calls: false,
            response_execution: false,
        });

        let output = IncidentReportGenerator::new().generate(input)?;
        let baseline = output
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::BaselineSummary)
            .expect("baseline section");

        assert_eq!(
            baseline.content_redacted["baseline_refs"][0],
            baseline_ref.to_string()
        );
        assert_eq!(
            baseline.content_redacted["fact_refs"][0],
            fact_ref.to_string()
        );
        assert_eq!(
            baseline.content_redacted["hypothesis_refs"][0],
            hypothesis_ref.to_string()
        );
        assert_eq!(baseline.content_redacted["bounded_refs_only"], json!(true));
        assert_eq!(
            baseline.content_redacted["automatic_durable_persistence"],
            json!(false)
        );
        assert_eq!(
            baseline.content_redacted["automatic_llm_calls"],
            json!(false)
        );
        assert_eq!(
            baseline.content_redacted["response_execution"],
            json!(false)
        );
        assert!(baseline.content_redacted.get("records").is_none());
        assert!(baseline.content_redacted.get("raw_logs").is_none());
        let serialized = serde_json::to_string(&baseline.content_redacted)?;
        assert!(!serialized.contains("session_token"));
        assert!(!serialized.contains("raw_payload"));
        assert!(!serialized.contains("credential"));
        Ok(())
    }

    #[test]
    fn incident_report_quality_section_contains_bounded_refs_only(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = report_input()?;
        let evidence_ref = input.evidence_items[0].evidence_id.clone();
        let finding_ref = input.findings[0].id().clone();
        let quality_id = EvidenceQualityId::new_v4();
        let quality = QualityBreakdown::metadata_only().with_quality_ref(quality_id.clone());
        let record = EvidenceQualityRecord {
            evidence_quality_id: quality_id.clone(),
            target_kind: EvidenceQualityTargetKind::Evidence,
            evidence_ref: Some(evidence_ref.clone()),
            finding_ref: Some(finding_ref.clone()),
            hypothesis_ref: None,
            risk_ref: None,
            baseline_ref: None,
            baseline_indicator_ref: None,
            attack_ref: None,
            graph_ref: None,
            incident_group_ref: None,
            report_section_ref: None,
            export_result_ref: None,
            fact_refs: Vec::new(),
            source_kind_category: "finding_evidence".to_string(),
            parser_family: "static_plugin_runtime".to_string(),
            detector_id: Some("portable_http_analysis_v1".to_string()),
            detector_confidence_bucket: EvidenceQualityBucket::Low,
            unsafe_field_rejection_bucket: EvidenceQualityBucket::Unknown,
            malformed_skipped_backpressure_bucket: OperationalInfluenceBucket::None,
            redaction_status: RedactionStatus::Redacted,
            provenance_id: None,
            time_bucket: Timestamp::now(),
            quality,
        };
        let summary = EvidenceQualitySummary {
            generated_at: Timestamp::now(),
            record_count: 1,
            weak_single_signal_count: 1,
            corroborated_count: 0,
            report_suitable_count: 0,
            export_suitable_count: 0,
            blocked_count: 0,
            records: vec![record],
            quality_refs: vec![quality_id.clone()],
            evidence_refs: vec![evidence_ref.clone()],
            finding_refs: vec![finding_ref],
            hypothesis_refs: Vec::new(),
            risk_refs: Vec::new(),
            baseline_refs: Vec::new(),
            incident_group_refs: Vec::new(),
            report_section_refs: Vec::new(),
            export_result_refs: Vec::new(),
            degraded_reason_summary: vec!["weak_single_signal".to_string()],
            missing_visibility_flags: vec!["metadata_only_visibility".to_string()],
            portable_no_retention: true,
            metadata_only: true,
            automatic_llm_calls: false,
            response_execution: false,
        };
        summary.validate()?;
        input.evidence_quality_summary = Some(summary);

        let output = IncidentReportGenerator::new().generate(input)?;
        let quality_section = output
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::EvidenceQuality)
            .expect("quality section");

        assert_eq!(quality_section.quality_refs, vec![quality_id.clone()]);
        assert_eq!(quality_section.evidence_refs, vec![evidence_ref]);
        assert_eq!(
            quality_section.content_redacted["quality_refs"][0],
            quality_id.to_string()
        );
        assert_eq!(
            quality_section.content_redacted["bounded_refs_only"],
            json!(true)
        );
        assert_eq!(
            quality_section.content_redacted["automatic_llm_calls"],
            json!(false)
        );
        let serialized = serde_json::to_string(&quality_section.content_redacted)?;
        for marker in [
            "session_token",
            "authorization:",
            "raw_payload",
            "credential",
        ] {
            assert!(!serialized.contains(marker), "{marker} leaked");
        }
        Ok(())
    }

    #[test]
    fn incident_report_investigation_drill_down_contains_refs_only(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = report_input()?;
        input.investigation_drill_down = Some(InvestigationDrillDownSummary {
            generated_at: Timestamp::now(),
            hypothesis_count: 0,
            baseline_count: 0,
            incident_group_count: 0,
            timeline_count: 0,
            source_reliability_count: 0,
            hypotheses: Vec::new(),
            baselines: Vec::new(),
            incident_groups: Vec::new(),
            timeline: Vec::new(),
            source_reliability: Vec::new(),
            report_refs: Vec::new(),
            export_refs: Vec::new(),
            suggestions: Vec::new(),
            quality: QualityBreakdown::metadata_only(),
            portable_no_retention: true,
            metadata_only: true,
            automatic_llm_calls: false,
            response_execution: false,
        });

        let output = IncidentReportGenerator::new().generate(input)?;
        let drill_down = output
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::InvestigationDrillDown)
            .expect("investigation drill-down section");

        assert_eq!(
            drill_down.content_redacted["bounded_refs_only"],
            json!(true)
        );
        assert_eq!(
            drill_down.content_redacted["automatic_llm_calls"],
            json!(false)
        );
        assert_eq!(
            drill_down.content_redacted["response_execution"],
            json!(false)
        );
        assert!(drill_down.content_redacted.get("raw_content").is_none());
        assert!(drill_down.content_redacted.get("paths").is_none());
        Ok(())
    }

    #[test]
    fn report_generation_omits_executing_response_and_rollback_refs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = report_input()?;
        let rollback_plan = RollbackPlan::new("rollback-redacted")?;
        let mut executed_result = ResponseResult::new(
            ResponseActionId::new_v4(),
            "windows_service_executor",
            ResponseTarget::new("redacted destination")?,
            &rollback_plan,
            AuditRef::new("response.action.completed")?,
        )?;
        executed_result.success = true;
        executed_result.ended_at = Some(Timestamp::now());
        input.response_results.push(executed_result);

        let mut executed_rollback = RollbackResult::new(
            ResponseActionId::new_v4(),
            &rollback_plan,
            AuditRef::new("response.rollback.completed")?,
        );
        executed_rollback.success = true;
        executed_rollback.ended_at = Some(Timestamp::now());
        input.rollback_results.push(executed_rollback);

        let output = IncidentReportGenerator::new().generate(input)?;

        assert_eq!(output.traceability.response_result_refs.len(), 1);
        assert_eq!(output.traceability.rollback_result_refs.len(), 1);
        let response_section = output
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::ResponseResult)
            .expect("response result section");
        let rollback_section = output
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::RollbackStatus)
            .expect("rollback section");
        assert_eq!(response_section.response_result_refs.len(), 1);
        assert_eq!(rollback_section.rollback_result_refs.len(), 1);
        Ok(())
    }

    #[test]
    fn incident_report_includes_metadata_watch_traceability_refs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = report_input()?;
        let evidence_id = input.findings[0].evidence_refs()[0].clone();
        let finding_id = input.findings[0].id().clone();
        input.metadata_watch_status = Some(MetadataWatchControllerStatus::empty());
        input.metadata_sampling_batches = vec![MetadataSamplingBatchSummary {
            batch_id: MetadataSamplingBatchId::new_v4(),
            source_id: MetadataWatchSourceId::new_v4(),
            source_kind: MetadataWatchSourceKind::LocalhostProxyContinuousDrain,
            parser_family: MetadataParserFamily::LocalProxyMetadata,
            started_at: Timestamp::now(),
            completed_at: Timestamp::now(),
            health_state: MetadataSourceHealthState::Active,
            sampled_record_count: 2,
            sampled_byte_count: 0,
            skipped_record_count: 0,
            malformed_record_count: 0,
            duplicate_record_count: 0,
            backpressure_drop_count: 0,
            emitted_topics: vec![
                "network.http.metadata".to_string(),
                "security.fact".to_string(),
            ],
            fact_refs: vec![SecurityFactId::new_v4()],
            evidence_refs: vec![evidence_id],
            finding_refs: vec![finding_id],
            risk_refs: vec![RiskEventId::new_v4()],
            report_refresh_marker: true,
            attack_refresh_marker: true,
            story_available_marker: true,
            triage_advisory_only: true,
            automatic_llm_calls: false,
            response_execution: false,
        }];

        let output = IncidentReportGenerator::new().generate(input)?;
        let section = output
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::MetadataWatch)
            .expect("metadata watch section");
        let serialized = serde_json::to_string(section).expect("watch section json");

        assert_eq!(section.evidence_refs.len(), 1);
        assert!(serialized.contains("bounded_refs_only"));
        assert!(serialized.contains("local_proxy_metadata"));
        for forbidden in [
            "session_token",
            "authorization:",
            "C:\\Users",
            "raw_payload",
        ] {
            assert!(!serialized.contains(forbidden));
        }
        Ok(())
    }

    #[test]
    fn incident_report_native_visibility_section_contains_status_refs_only(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = report_input()?;
        input.native_permission_status = Some(NativePermissionStatusSummary {
            capability_count: 1,
            permission_required_count: 0,
            requested_count: 0,
            granted_inactive_count: 1,
            revoked_count: 0,
            degraded_count: 0,
            unsupported_count: 0,
            portable_default_active: true,
            session_bound_authorization: true,
            telemetry_collection_active: false,
            response_execution_allowed: false,
            automatic_llm_calls: false,
            capability_refs: vec!["process_metadata_visibility".to_string()],
            audit_refs: Vec::new(),
            generated_at: Timestamp::now(),
        });
        input.native_visibility_summary = Some(NativeVisibilitySummary {
            available_scope_categories: vec![NativeVisibilityScopeCategory::ProcessSummary],
            missing_visibility_flags: vec!["native_sampler_inactive".to_string()],
            degraded_reasons: vec!["authorized_but_no_sampler_enabled".to_string()],
            capability_refs: vec!["process_metadata_visibility".to_string()],
            audit_refs: Vec::new(),
            granted_permission_creates_evidence: false,
            native_required_attack_coverage_supported: false,
            future_sampler_ready: false,
            portable_default_active: true,
            metadata_only: true,
            generated_at: Timestamp::now(),
        });

        let output = IncidentReportGenerator::new().generate(input)?;
        let section = output
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::NativeVisibility)
            .expect("native visibility section");
        let serialized = serde_json::to_string(section).expect("native visibility json");
        assert!(serialized.contains("control_plane_only"));
        assert!(serialized.contains("process_metadata_visibility"));
        assert!(!serialized.contains("C:\\"));
        assert!(!serialized.contains("session_token"));
        assert!(!serialized.contains("https://"));
        Ok(())
    }

    #[test]
    fn incident_report_native_sampler_readiness_section_contains_refs_only(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = report_input()?;
        input.native_sampler_readiness = Some(NativeSamplerReadinessSummary {
            contract_count: 1,
            review_count: 1,
            ready_when_implemented_count: 1,
            blocked_count: 0,
            degraded_count: 0,
            not_implemented_count: 1,
            active_sampler_count: 0,
            future_collection_allowed_count: 1,
            future_response_allowed_count: 0,
            endpoint_security_facts_emitted: false,
            telemetry_collection_active: false,
            response_execution_allowed: false,
            automatic_llm_calls: false,
            portable_default_active: true,
            no_telemetry_collected: true,
            contract_refs: vec!["process_metadata_sampler".to_string()],
            review_refs: vec![sentinel_contracts::NativeSamplerReviewId::new_v4()],
            audit_refs: Vec::new(),
            missing_endpoint_visibility_flags: vec!["sampler_runtime_not_implemented".to_string()],
            degraded_reasons: vec!["ready_but_sampler_not_implemented".to_string()],
            generated_at: Timestamp::now(),
        });

        let output = IncidentReportGenerator::new().generate(input)?;
        let section = output
            .report
            .sections
            .iter()
            .find(|section| section.section_type == ReportSectionType::NativeSamplerReadiness)
            .expect("native sampler readiness section");
        let serialized = serde_json::to_string(section).expect("native sampler json");
        assert!(serialized.contains("process_metadata_sampler"));
        assert!(serialized.contains("edr_coverage_claimed"));
        assert!(serialized.contains("no_telemetry_collected"));
        for forbidden in ["C:\\", "session_token", "https://", "api_key_secret"] {
            assert!(!serialized.contains(forbidden));
        }
        Ok(())
    }

    #[test]
    fn redaction_gate_rejects_unsafe_exports() -> Result<(), Box<dyn std::error::Error>> {
        let mut output = IncidentReportGenerator::new().generate(report_input()?)?;
        output.report.sections[0].content_redacted = json!({
            "raw_payload": "secret bytes"
        });
        let gate = ReportExportGate::new();
        let error = gate
            .prepare_export(export_request(output.report, true)?)
            .expect_err("unsafe report denied");

        assert!(matches!(error, ReportGenerationError::UnsafeContent(_)));
        Ok(())
    }

    #[test]
    fn export_gate_requires_policy_confirmation_and_audit() -> Result<(), Box<dyn std::error::Error>>
    {
        let output = IncidentReportGenerator::new().generate(report_input()?)?;
        let gate = ReportExportGate::new();
        let denied = gate
            .prepare_export(export_request(output.report.clone(), false)?)
            .expect_err("confirmation required");

        assert!(matches!(denied, ReportGenerationError::ExportDenied(_)));

        let allowed = gate.prepare_export(export_request(output.report, true)?)?;
        assert!(allowed.export_result.success);
        assert!(allowed
            .rendered_report
            .content_redacted
            .contains("Privacy redaction summary"));
        Ok(())
    }

    #[test]
    fn renderers_consume_redacted_report_models() -> Result<(), Box<dyn std::error::Error>> {
        let output = IncidentReportGenerator::new().generate(report_input()?)?;
        let markdown = MarkdownReportRenderer::new().render(&output.report)?;
        let html = HtmlReportRenderer::new().render(&output.report)?;
        let redacted_json = RedactedJsonReportRenderer::new().render(&output.report)?;

        assert!(markdown.content_redacted.contains("Executive summary"));
        assert!(html.content_redacted.contains("<section>"));
        assert!(redacted_json.content_redacted.contains("content_redacted"));
        assert!(redacted_json
            .content_redacted
            .contains("export_safe_snapshots"));
        for rendered in [markdown, html, redacted_json] {
            assert!(!rendered.content_redacted.contains("payload_blob"));
            assert!(!rendered
                .content_redacted
                .contains("authorization_header_value"));
            assert!(!rendered.content_redacted.contains("session_token=secret"));
        }
        Ok(())
    }

    #[test]
    fn graph_snapshots_must_be_bounded_redacted_and_evidence_backed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = report_input()?;
        input.graph_snapshots[0].time_bounds = None;
        let error = IncidentReportGenerator::new()
            .generate(input)
            .expect_err("unbounded snapshot rejected");

        assert!(matches!(
            error,
            ReportGenerationError::GraphSnapshotNotExportSafe { .. }
        ));
        Ok(())
    }

    #[test]
    fn graph_snapshot_provider_rejects_empty_export_snapshot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let incident_id = IncidentId::new_v4();
        let mut snapshot =
            GraphSnapshot::new(GraphType::IncidentGraph, GraphScope::Incident(incident_id));
        snapshot.time_bounds = Some(TimeRange::new(Some(Timestamp::now()), None)?);
        snapshot.redaction_status = RedactionStatus::Redacted;
        snapshot.redaction_summary = GraphRedactionSummary {
            status: RedactionStatus::Redacted,
            redacted_node_count: 0,
            redacted_edge_count: 0,
            hidden_label_count: 0,
            notes: vec!["empty snapshot".to_string()],
        };

        let error = ReportGraphSnapshotProvider::new()
            .prepare_export_safe(&snapshot)
            .expect_err("empty snapshot rejected");

        assert!(matches!(
            error,
            ReportGenerationError::GraphSnapshotNotExportSafe { .. }
        ));
        Ok(())
    }

    #[test]
    fn graph_snapshot_provider_rejects_internal_detail_refs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut snapshot = graph_snapshot(IncidentId::new_v4(), EvidenceId::new_v4())?;
        snapshot.selected_nodes[0].detail_ref.entity_id = Some(EntityId::new_v4());

        let error = ReportGraphSnapshotProvider::new()
            .prepare_export_safe(&snapshot)
            .expect_err("internal detail refs rejected");

        assert!(matches!(
            error,
            ReportGenerationError::GraphSnapshotNotExportSafe { .. }
        ));
        Ok(())
    }

    #[test]
    fn graph_snapshot_provider_rejects_privacy_markers() -> Result<(), Box<dyn std::error::Error>> {
        let mut snapshot = graph_snapshot(IncidentId::new_v4(), EvidenceId::new_v4())?;
        snapshot.path_summaries[0].label = RedactedLabel::redacted(
            "C:\\Users\\Alice\\AppData\\Local\\Temp\\payload.exe",
            PrivacyClass::Sensitive,
        )?;

        let error = ReportGraphSnapshotProvider::new()
            .prepare_export_safe(&snapshot)
            .expect_err("privacy marker rejected");

        assert!(matches!(
            error,
            ReportGenerationError::GraphSnapshotNotExportSafe { .. }
        ));
        Ok(())
    }

    fn report_input() -> Result<IncidentReportInput, Box<dyn std::error::Error>> {
        let evidence = EvidenceItem::new("flow_metadata", "periodic destination cadence")?;
        let producer = sentinel_contracts::PluginId::new_v4();
        let mut process = EntityRef::new(EntityId::new_v4(), EntityType::Process);
        process.entity_name = Some("redacted process".to_string());
        let mut destination = EntityRef::new(EntityId::new_v4(), EntityType::Domain);
        destination.entity_name = Some("redacted destination".to_string());
        let finding = Finding::new(
            "c2_signal",
            producer,
            vec![evidence.evidence_id.clone()],
            FindingExplanation::new("redacted C2-like cadence")?,
        )?
        .with_entity_refs(vec![process, destination])
        .with_confidence(QualityScore::new(0.82)?);
        let alert = Alert::new(
            "redacted C2 alert",
            "redacted alert summary",
            vec![finding.id().clone()],
        )?;
        let incident = Incident::new(
            "c2_incident",
            "redacted incident",
            "redacted incident summary",
            vec![alert.id().clone()],
        )?
        .with_finding_refs(vec![finding.id().clone()])
        .with_severity(SecuritySeverity::High)
        .with_confidence(QualityScore::new(0.78)?);
        let graph_snapshot = graph_snapshot(incident.id().clone(), evidence.evidence_id.clone())?;
        let attack_coverage =
            attack_coverage_summary(finding.id().clone(), evidence.evidence_id.clone())?;
        let plan = response_plan(incident.id().clone())?;
        let rollback_plan = RollbackPlan::new("rollback-redacted")?;
        let audit = AuditRef::new("response.execution.disabled")?;
        let mut response_result = ResponseResult::new(
            ResponseActionId::new_v4(),
            "recommendation_only",
            ResponseTarget::new("redacted destination")?,
            &rollback_plan,
            audit,
        )?;
        response_result.ended_at = Some(Timestamp::now());
        response_result.success = false;
        response_result.error_summary_redacted =
            Some("no OS action was performed; response execution is disabled".to_string());
        response_result.rollback_token.clear();
        response_result.rollback_deadline = None;
        response_result.is_replay = true;
        response_result.execution_disabled = true;
        let mut rollback_result = RollbackResult::new(
            response_result.action_id.clone(),
            &rollback_plan,
            AuditRef::new("response.rollback.disabled")?,
        );
        rollback_result.ended_at = Some(Timestamp::now());
        rollback_result.error_summary_redacted =
            Some("no privileged executor has run; rollback request recorded only".to_string());

        Ok(IncidentReportInput {
            incident,
            alerts: vec![alert],
            findings: vec![finding],
            evidence_items: vec![evidence],
            graph_snapshots: vec![graph_snapshot],
            attack_coverage: Some(attack_coverage),
            fusion_summary: None,
            baseline_summary: None,
            investigation_drill_down: None,
            evidence_quality_summary: None,
            metadata_watch_status: None,
            metadata_sampling_batches: Vec::new(),
            native_permission_status: None,
            native_visibility_summary: None,
            native_sampler_readiness: None,
            native_sampler_runtime: None,
            native_scheduler_operational: None,
            llm_alert_stories: Vec::new(),
            response_plans: vec![plan],
            response_results: vec![response_result],
            rollback_results: vec![rollback_result],
        })
    }

    fn attack_coverage_summary(
        finding_id: FindingId,
        evidence_id: EvidenceId,
    ) -> Result<AttackCoverageSummary, Box<dyn std::error::Error>> {
        let mut row = AttackCoverageTechniqueRow::new(
            "TA0011",
            "T1071.001",
            "enterprise-verified-2026-06-12",
            vec!["portable_http_analysis_v1".to_string()],
            AttackCoverageConfidenceBucket::Medium,
            AttackRequiredVisibility::PortableNetworkMetadata,
            "http_analysis_v1",
            AttackObservedCountBucket::Single,
            AttackLastObservedBucket::CurrentSession,
            vec![
                AttackCoverageState::Covered,
                AttackCoverageState::Observed,
                AttackCoverageState::EvidenceBacked,
                AttackCoverageState::Degraded,
            ],
        )?;
        row.finding_refs = vec![finding_id.clone()];
        row.evidence_refs = vec![evidence_id.clone()];
        row.degraded_reason = Some("metadata_only_visibility".to_string());

        let mut summary = AttackCoverageSummary::new("enterprise-verified-2026-06-12")?;
        summary.technique_rows = vec![row];
        summary.top_tactics = vec![AttackCoverageCount::new("TA0011", 1)?];
        summary.package_coverage = vec![AttackCoverageCount::new("http_analysis_v1", 1)?];
        summary.state_counts = vec![
            AttackCoverageCount::new("covered", 1)?,
            AttackCoverageCount::new("observed", 1)?,
            AttackCoverageCount::new("evidence_backed", 1)?,
            AttackCoverageCount::new("degraded", 1)?,
        ];
        summary.finding_refs = vec![finding_id];
        summary.evidence_refs = vec![evidence_id];
        summary.degraded_reason = Some("metadata_only_visibility".to_string());
        summary.validate()?;
        Ok(summary)
    }

    fn graph_snapshot(
        incident_id: IncidentId,
        evidence_id: EvidenceId,
    ) -> Result<GraphSnapshot, Box<dyn std::error::Error>> {
        let mut snapshot =
            GraphSnapshot::new(GraphType::IncidentGraph, GraphScope::Incident(incident_id));
        snapshot.time_bounds = Some(TimeRange::new(Some(Timestamp::now()), None)?);
        snapshot.node_count = 2;
        snapshot.edge_count = 1;
        snapshot.path_count = 1;
        snapshot.evidence_refs = vec![evidence_id.clone()];
        let mut source = GraphNodeViewModel::new(
            GraphNodeType::Process,
            RedactedLabel::redacted("redacted process", PrivacyClass::Internal)?,
        );
        source.detail_ref.evidence_refs = vec![evidence_id.clone()];
        let destination = GraphNodeViewModel::new(
            GraphNodeType::Domain,
            RedactedLabel::redacted("redacted destination", PrivacyClass::Internal)?,
        );
        let mut edge = GraphEdgeViewModel::new(
            GraphEdgeType::ProcessQueriesDomain,
            source.node_id.clone(),
            destination.node_id.clone(),
        );
        edge.label = Some(RedactedLabel::redacted(
            "redacted metadata edge",
            PrivacyClass::Internal,
        )?);
        edge.evidence_refs = vec![evidence_id.clone()];
        snapshot.selected_nodes = vec![source, destination];
        snapshot.selected_edges = vec![edge];
        snapshot.redaction_status = RedactionStatus::Redacted;
        snapshot.redaction_summary = GraphRedactionSummary {
            status: RedactionStatus::Redacted,
            redacted_node_count: 2,
            redacted_edge_count: 1,
            hidden_label_count: 0,
            notes: Vec::new(),
        };
        snapshot.path_summaries = vec![GraphPathSummary {
            path_id: sentinel_contracts::GraphPathId::new_v4(),
            path_type: GraphPathType::IncidentSummaryPath,
            label: RedactedLabel::redacted("redacted path", PrivacyClass::Internal)?,
            risk_score: QualityScore::new(0.72)?,
            confidence: QualityScore::new(0.8)?,
            evidence_refs: vec![evidence_id],
        }];
        Ok(snapshot)
    }

    fn response_plan(incident_id: IncidentId) -> Result<ResponsePlan, Box<dyn std::error::Error>> {
        let mut plan = ResponsePlan::new(ResponsePlanSource::Incident(incident_id), "report_test")?;
        let target = ResponseTarget::new("redacted destination")?;
        let scope = ResponseScope::limited("single destination")?;
        let action = sentinel_contracts::RecommendedAction::new(
            ResponseActionType::RecommendFirewallBlock,
            target,
            scope,
            "recommend local review",
            "manual approval before execution",
            ResponseLevel::RecommendOnly,
        )?;
        plan.recommended_actions.push(action);
        Ok(plan)
    }

    fn export_request(
        report: Report,
        user_confirmed: bool,
    ) -> Result<ReportExportGateRequest, Box<dyn std::error::Error>> {
        Ok(ReportExportGateRequest {
            report,
            format: ExportFormat::Markdown,
            policy: ReportExportPolicy::safe_default(),
            requested_by_redacted: "local_user".to_string(),
            user_confirmed,
            audit_ref: AuditRef::new("report.export.requested")?,
            destination_metadata_redacted: Some("local file".to_string()),
            file_hash: None,
        })
    }
}
