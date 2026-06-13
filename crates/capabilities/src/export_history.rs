use sentinel_contracts::{
    report::{ExportFormat, ExportResult},
    AuditId, Cursor, EvidenceId, ExportResultId, FilterOperator, FilterSpec, FilterValue,
    GraphSnapshotId, LlmAlertStoryId, PageRequest, PageResponse, QueryRequest, QueryScope,
    RedactionSummary, ReportId, ResponseResultId, RollbackResultId, SortDirection, SortSpec,
    TimeRange, Timestamp, TraceId,
};
use sentinel_platform::AuditReceipt;
use sentinel_storage::{LogicalRecord, LogicalStore, SqliteStoreFactory, StorageError, StoreKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub const EXPORT_HISTORY_SCHEMA_VERSION: sentinel_contracts::SchemaVersion =
    sentinel_contracts::SchemaVersion::new(1, 0, 0);

const EXPORT_HISTORY_CURSOR_PREFIX: &str = "export_history:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportHistoryError {
    EmptyField(&'static str),
    SensitiveMarker { field: &'static str },
    InvalidFileHash,
    BoundedFieldTooLarge { field: &'static str },
    InvalidCursor,
    InvalidTimeRange,
    UnsupportedScope,
    UnsupportedFilterField { index: usize },
    UnsupportedFilterOperator { index: usize },
    UnsupportedFilterValue { index: usize },
    UnsupportedSortField { index: usize },
    MissingAudit,
    MissingRedaction,
    ExportFailed,
    FileHashMismatch,
    InvalidStoredRecord { record_kind: &'static str },
    Storage(String),
    Serialization(String),
}

impl fmt::Display for ExportHistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::SensitiveMarker { field } => {
                write!(f, "{field} contains a forbidden sensitive marker")
            }
            Self::InvalidFileHash => write!(
                f,
                "export history file hash must be a bounded sha256 hex digest"
            ),
            Self::BoundedFieldTooLarge { field } => write!(
                f,
                "{field} exceeds the bounded export history reference limit"
            ),
            Self::InvalidCursor => write!(f, "export history cursor is invalid"),
            Self::InvalidTimeRange => write!(f, "export history time range is invalid"),
            Self::UnsupportedScope => {
                write!(f, "export history query scope is not supported")
            }
            Self::UnsupportedFilterField { index } => {
                write!(
                    f,
                    "export history filter field at index {index} is not supported"
                )
            }
            Self::UnsupportedFilterOperator { index } => {
                write!(
                    f,
                    "export history filter operator at index {index} is not supported"
                )
            }
            Self::UnsupportedFilterValue { index } => {
                write!(
                    f,
                    "export history filter value at index {index} is not supported"
                )
            }
            Self::UnsupportedSortField { index } => {
                write!(
                    f,
                    "export history sort field at index {index} is not supported"
                )
            }
            Self::MissingAudit => write!(f, "export history requires an audit id"),
            Self::MissingRedaction => {
                write!(f, "export history requires a passed redaction summary")
            }
            Self::ExportFailed => write!(
                f,
                "successful export history requires a successful export result"
            ),
            Self::FileHashMismatch => write!(
                f,
                "recorded export hash does not match the final export artifact bytes"
            ),
            Self::InvalidStoredRecord { record_kind } => {
                write!(
                    f,
                    "stored {record_kind} record is missing required metadata"
                )
            }
            Self::Storage(error) => write!(f, "export history storage error: {error}"),
            Self::Serialization(error) => {
                write!(f, "export history serialization error: {error}")
            }
        }
    }
}

impl std::error::Error for ExportHistoryError {}

impl From<StorageError> for ExportHistoryError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<serde_json::Error> for ExportHistoryError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportDestinationMetadata {
    pub destination_metadata_redacted: Option<String>,
    pub local_export_only: bool,
}

impl ExportDestinationMetadata {
    pub fn local(
        destination_metadata_redacted: Option<String>,
    ) -> Result<Self, ExportHistoryError> {
        if let Some(destination) = &destination_metadata_redacted {
            require_safe_export_text("destination_metadata_redacted", destination)?;
        }
        Ok(Self {
            destination_metadata_redacted,
            local_export_only: true,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportFileHash {
    pub algorithm: String,
    pub value: String,
    pub calculated_at: Timestamp,
}

impl ExportFileHash {
    pub fn from_recorded_hash(value: impl Into<String>) -> Result<Self, ExportHistoryError> {
        let value = require_non_empty("file_hash", value.into())?;
        if !is_valid_sha256_hex(&value) {
            return Err(ExportHistoryError::InvalidFileHash);
        }
        Ok(Self {
            algorithm: "sha256".to_string(),
            value,
            calculated_at: Timestamp::now(),
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        Self {
            algorithm: "sha256".to_string(),
            value: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
            calculated_at: Timestamp::now(),
        }
    }

    pub fn from_redacted_content(content_redacted: &str) -> Self {
        Self::from_bytes(content_redacted.as_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportHistoryRecord {
    pub export_result_id: ExportResultId,
    pub report_id: ReportId,
    pub format: ExportFormat,
    pub destination: ExportDestinationMetadata,
    pub file_hash: Option<ExportFileHash>,
    pub redaction_summary: RedactionSummary,
    #[serde(default)]
    pub graph_snapshot_refs: Vec<GraphSnapshotId>,
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceId>,
    #[serde(default)]
    pub response_result_refs: Vec<ResponseResultId>,
    #[serde(default)]
    pub rollback_result_refs: Vec<RollbackResultId>,
    #[serde(default)]
    pub llm_story_refs: Vec<LlmAlertStoryId>,
    pub actor_redacted: String,
    pub exported_at: Timestamp,
    pub trace_id: Option<TraceId>,
    pub audit_id: AuditId,
    pub success: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportPolicyViolation {
    pub violation_id: sentinel_contracts::AuditId,
    pub report_id: ReportId,
    pub format: ExportFormat,
    pub destination: ExportDestinationMetadata,
    pub actor_redacted: String,
    pub reason_redacted: String,
    pub redaction_summary: RedactionSummary,
    pub occurred_at: Timestamp,
    pub trace_id: Option<TraceId>,
    pub audit_id: AuditId,
    pub export_audit_id: Option<AuditId>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ReportExportHistoryQuery {
    pub page: PageRequest,
    pub report_id: Option<ReportId>,
    pub format: Option<ExportFormat>,
    pub actor_redacted: Option<String>,
    pub time_range: Option<TimeRange>,
    pub success: Option<bool>,
}

impl ReportExportHistoryQuery {
    pub fn for_report(report_id: ReportId) -> Self {
        Self {
            report_id: Some(report_id),
            ..Self::default()
        }
    }

    pub fn with_page(mut self, page: PageRequest) -> Self {
        self.page = page;
        self
    }

    pub fn with_format(mut self, format: ExportFormat) -> Self {
        self.format = Some(format);
        self
    }

    pub fn with_actor(mut self, actor_redacted: impl Into<String>) -> Self {
        self.actor_redacted = Some(actor_redacted.into());
        self
    }

    pub fn with_time_range(mut self, time_range: TimeRange) -> Self {
        self.time_range = Some(time_range);
        self
    }

    pub fn with_success(mut self, success: bool) -> Self {
        self.success = Some(success);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportAuditSuccessInput {
    pub export_result: ExportResult,
    pub actor_redacted: String,
    pub destination: ExportDestinationMetadata,
    pub audit_receipt: AuditReceipt,
    pub artifact_bytes: Option<Vec<u8>>,
    pub graph_snapshot_refs: Vec<GraphSnapshotId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub response_result_refs: Vec<ResponseResultId>,
    pub rollback_result_refs: Vec<RollbackResultId>,
    pub llm_story_refs: Vec<LlmAlertStoryId>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportPolicyViolationInput {
    pub report_id: ReportId,
    pub format: ExportFormat,
    pub actor_redacted: String,
    pub destination: ExportDestinationMetadata,
    pub reason_redacted: String,
    pub redaction_summary: RedactionSummary,
    pub trace_id: Option<TraceId>,
    pub violation_audit_receipt: AuditReceipt,
    pub export_audit_id: Option<AuditId>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ExportHistoryStore {
    records: Vec<ExportHistoryRecord>,
    violations: Vec<ExportPolicyViolation>,
}

impl ExportHistoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, record: ExportHistoryRecord) -> Result<(), ExportHistoryError> {
        validate_history_record(&record)?;
        self.records.push(record);
        self.records
            .sort_by(|left, right| right.exported_at.cmp(&left.exported_at));
        Ok(())
    }

    pub fn append_violation(
        &mut self,
        violation: ExportPolicyViolation,
    ) -> Result<(), ExportHistoryError> {
        validate_violation(&violation)?;
        self.violations.push(violation);
        self.violations
            .sort_by(|left, right| right.occurred_at.cmp(&left.occurred_at));
        Ok(())
    }

    pub fn get(&self, export_result_id: &ExportResultId) -> Option<&ExportHistoryRecord> {
        self.records
            .iter()
            .find(|record| &record.export_result_id == export_result_id)
    }

    pub fn records(&self) -> &[ExportHistoryRecord] {
        &self.records
    }

    pub fn violations(&self) -> &[ExportPolicyViolation] {
        &self.violations
    }

    pub fn query(
        &self,
        query: ReportExportHistoryQuery,
    ) -> Result<PageResponse<ExportHistoryRecord>, ExportHistoryError> {
        query
            .page
            .validate()
            .map_err(|_| ExportHistoryError::InvalidCursor)?;
        if let Some(actor) = &query.actor_redacted {
            require_safe_export_text("actor_redacted", actor)?;
        }

        let filtered = self
            .records
            .iter()
            .filter(|record| matches_report(record, query.report_id.as_ref()))
            .filter(|record| matches_format(record, query.format.as_ref()))
            .filter(|record| matches_actor(record, query.actor_redacted.as_deref()))
            .filter(|record| matches_time_range(&record.exported_at, query.time_range.as_ref()))
            .filter(|record| {
                query
                    .success
                    .is_none_or(|success| record.success == success)
            })
            .cloned()
            .collect::<Vec<_>>();

        page_records(filtered, &query.page)
    }

    pub fn query_request(
        &self,
        request: QueryRequest,
    ) -> Result<PageResponse<ExportHistoryRecord>, ExportHistoryError> {
        request
            .page
            .validate()
            .map_err(|_| ExportHistoryError::InvalidCursor)?;
        if let Some(time_range) = &request.time_range {
            time_range
                .validate()
                .map_err(|_| ExportHistoryError::InvalidTimeRange)?;
        }

        let mut filtered = scoped_records(self.records(), &request.scope)?
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        retain_time_range(&mut filtered, request.time_range.as_ref());
        retain_query_filters(&mut filtered, &request.filters)?;
        apply_query_sort(&mut filtered, &request.sort)?;
        page_records(filtered, &request.page)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportHistoryStoreWriteSummary {
    pub history_records: usize,
    pub policy_violation_records: usize,
}

#[derive(Clone, Debug, Default)]
pub struct ExportHistoryStorageAdapter;

impl ExportHistoryStorageAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn persist_store(
        &self,
        stores: &SqliteStoreFactory<'_>,
        store: &ExportHistoryStore,
    ) -> Result<ExportHistoryStoreWriteSummary, ExportHistoryError> {
        let mut summary = ExportHistoryStoreWriteSummary::default();

        for record in store.records() {
            self.persist_record(stores, record)?;
            summary.history_records += 1;
        }

        for violation in store.violations() {
            self.persist_violation(stores, violation)?;
            summary.policy_violation_records += 1;
        }

        Ok(summary)
    }

    pub fn persist_record(
        &self,
        stores: &SqliteStoreFactory<'_>,
        record: &ExportHistoryRecord,
    ) -> Result<(), ExportHistoryError> {
        validate_history_record(record)?;
        let logical_record = LogicalRecord::metadata_only(
            record.export_result_id.clone(),
            EXPORT_HISTORY_SCHEMA_VERSION,
            StoreKind::ExportHistory.default_storage_privacy_class(),
            export_history_metadata(record)?,
        )
        .with_record_time(record.exported_at.clone());

        stores.export_history_store().append(logical_record)?;
        Ok(())
    }

    pub fn persist_violation(
        &self,
        stores: &SqliteStoreFactory<'_>,
        violation: &ExportPolicyViolation,
    ) -> Result<(), ExportHistoryError> {
        validate_violation(violation)?;
        let logical_record = LogicalRecord::metadata_only(
            violation.violation_id.clone(),
            EXPORT_HISTORY_SCHEMA_VERSION,
            StoreKind::ExportPolicyViolation.default_storage_privacy_class(),
            export_policy_violation_metadata(violation)?,
        )
        .with_record_time(violation.occurred_at.clone());

        stores
            .export_policy_violation_store()
            .append(logical_record)?;
        Ok(())
    }

    pub fn load_store(
        &self,
        stores: &SqliteStoreFactory<'_>,
    ) -> Result<ExportHistoryStore, ExportHistoryError> {
        let mut store = ExportHistoryStore::new();

        for record in read_all_export_history_records(stores)? {
            store.append(record)?;
        }

        for violation in read_all_export_policy_violations(stores)? {
            store.append_violation(violation)?;
        }

        Ok(store)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExportAuditService;

impl ExportAuditService {
    pub fn new() -> Self {
        Self
    }

    pub fn record_success(
        &self,
        store: &mut ExportHistoryStore,
        input: ExportAuditSuccessInput,
    ) -> Result<ExportHistoryRecord, ExportHistoryError> {
        if !input.export_result.success {
            return Err(ExportHistoryError::ExportFailed);
        }
        if !input.export_result.redaction_summary.passed {
            return Err(ExportHistoryError::MissingRedaction);
        }
        let file_hash = success_file_hash(
            input.export_result.file_hash.as_deref(),
            input.artifact_bytes.as_deref(),
        )?;
        let record = ExportHistoryRecord {
            export_result_id: input.export_result.export_result_id.clone(),
            report_id: input.export_result.report_id.clone(),
            format: input.export_result.format.clone(),
            destination: input.destination,
            file_hash,
            redaction_summary: input.export_result.redaction_summary.clone(),
            graph_snapshot_refs: bounded_unique(input.graph_snapshot_refs),
            evidence_refs: bounded_unique(input.evidence_refs),
            response_result_refs: bounded_unique(input.response_result_refs),
            rollback_result_refs: bounded_unique(input.rollback_result_refs),
            llm_story_refs: bounded_unique(input.llm_story_refs),
            actor_redacted: require_safe_export_text("actor_redacted", input.actor_redacted)?,
            exported_at: input.export_result.completed_at.clone(),
            trace_id: input.export_result.trace_id.clone(),
            audit_id: input.audit_receipt.audit_id.clone(),
            success: input.export_result.success,
        };
        store.append(record.clone())?;
        Ok(record)
    }

    pub fn record_violation(
        &self,
        store: &mut ExportHistoryStore,
        input: ExportPolicyViolationInput,
    ) -> Result<ExportPolicyViolation, ExportHistoryError> {
        let violation = ExportPolicyViolation {
            violation_id: input.violation_audit_receipt.audit_id.clone(),
            report_id: input.report_id,
            format: input.format,
            destination: input.destination,
            actor_redacted: require_safe_export_text("actor_redacted", input.actor_redacted)?,
            reason_redacted: require_safe_export_text("reason_redacted", input.reason_redacted)?,
            redaction_summary: input.redaction_summary,
            occurred_at: input.violation_audit_receipt.appended_at,
            trace_id: input.trace_id,
            audit_id: input.violation_audit_receipt.audit_id,
            export_audit_id: input.export_audit_id,
        };
        store.append_violation(violation.clone())?;
        Ok(violation)
    }
}

fn success_file_hash(
    recorded_hash: Option<&str>,
    artifact_bytes: Option<&[u8]>,
) -> Result<Option<ExportFileHash>, ExportHistoryError> {
    match (recorded_hash, artifact_bytes) {
        (Some(recorded_hash), Some(artifact_bytes)) => {
            let recorded_hash = require_non_empty("file_hash", recorded_hash)?;
            let calculated_hash = ExportFileHash::from_bytes(artifact_bytes);
            if recorded_hash != calculated_hash.value {
                return Err(ExportHistoryError::FileHashMismatch);
            }
            Ok(Some(calculated_hash))
        }
        (Some(recorded_hash), None) => Ok(Some(ExportFileHash::from_recorded_hash(recorded_hash)?)),
        (None, Some(artifact_bytes)) => Ok(Some(ExportFileHash::from_bytes(artifact_bytes))),
        (None, None) => Ok(None),
    }
}

fn validate_history_record(record: &ExportHistoryRecord) -> Result<(), ExportHistoryError> {
    if !record.success {
        return Err(ExportHistoryError::ExportFailed);
    }
    if !record.redaction_summary.passed {
        return Err(ExportHistoryError::MissingRedaction);
    }
    if let Some(file_hash) = &record.file_hash {
        validate_file_hash(file_hash)?;
    }
    validate_bounded_refs("graph_snapshot_refs", &record.graph_snapshot_refs)?;
    validate_bounded_refs("evidence_refs", &record.evidence_refs)?;
    validate_bounded_refs("response_result_refs", &record.response_result_refs)?;
    validate_bounded_refs("rollback_result_refs", &record.rollback_result_refs)?;
    validate_bounded_refs("llm_story_refs", &record.llm_story_refs)?;
    require_safe_export_text("actor_redacted", &record.actor_redacted)?;
    if let Some(destination) = &record.destination.destination_metadata_redacted {
        require_safe_export_text("destination_metadata_redacted", destination)?;
    }
    if record.audit_id.to_string().trim().is_empty() {
        return Err(ExportHistoryError::MissingAudit);
    }
    Ok(())
}

fn validate_violation(violation: &ExportPolicyViolation) -> Result<(), ExportHistoryError> {
    require_safe_export_text("actor_redacted", &violation.actor_redacted)?;
    require_safe_export_text("reason_redacted", &violation.reason_redacted)?;
    if let Some(destination) = &violation.destination.destination_metadata_redacted {
        require_safe_export_text("destination_metadata_redacted", destination)?;
    }
    if violation.audit_id.to_string().trim().is_empty() {
        return Err(ExportHistoryError::MissingAudit);
    }
    Ok(())
}

fn validate_file_hash(file_hash: &ExportFileHash) -> Result<(), ExportHistoryError> {
    if file_hash.algorithm != "sha256" || !is_valid_sha256_hex(&file_hash.value) {
        return Err(ExportHistoryError::InvalidFileHash);
    }
    Ok(())
}

fn validate_bounded_refs<T>(field: &'static str, values: &[T]) -> Result<(), ExportHistoryError> {
    if values.len() > 100 {
        return Err(ExportHistoryError::BoundedFieldTooLarge { field });
    }
    Ok(())
}

fn matches_report(record: &ExportHistoryRecord, report_id: Option<&ReportId>) -> bool {
    report_id.is_none_or(|report_id| &record.report_id == report_id)
}

fn matches_format(record: &ExportHistoryRecord, format: Option<&ExportFormat>) -> bool {
    format.is_none_or(|format| &record.format == format)
}

fn matches_actor(record: &ExportHistoryRecord, actor: Option<&str>) -> bool {
    actor.is_none_or(|actor| record.actor_redacted == actor)
}

fn matches_time_range(timestamp: &Timestamp, time_range: Option<&TimeRange>) -> bool {
    let Some(time_range) = time_range else {
        return true;
    };
    if let Some(start) = &time_range.start {
        if timestamp < start {
            return false;
        }
    }
    if let Some(end) = &time_range.end {
        if timestamp > end {
            return false;
        }
    }
    true
}

fn scoped_records<'a>(
    records: &'a [ExportHistoryRecord],
    scope: &QueryScope,
) -> Result<Vec<&'a ExportHistoryRecord>, ExportHistoryError> {
    match scope {
        QueryScope::Global => Ok(records.iter().collect()),
        QueryScope::Report(report_id) => Ok(records
            .iter()
            .filter(|record| &record.report_id == report_id)
            .collect()),
        QueryScope::Trace(trace_id) => Ok(records
            .iter()
            .filter(|record| record.trace_id.as_ref() == Some(trace_id))
            .collect()),
        _ => Err(ExportHistoryError::UnsupportedScope),
    }
}

fn retain_time_range(records: &mut Vec<ExportHistoryRecord>, time_range: Option<&TimeRange>) {
    let Some(time_range) = time_range else {
        return;
    };
    records.retain(|record| matches_time_range(&record.exported_at, Some(time_range)));
}

fn retain_query_filters(
    records: &mut Vec<ExportHistoryRecord>,
    filters: &[FilterSpec],
) -> Result<(), ExportHistoryError> {
    for (index, filter) in filters.iter().enumerate() {
        validate_filter_shape(filter, index)?;
        if !filter_field_supported(filter.field.as_str()) {
            return Err(ExportHistoryError::UnsupportedFilterField { index });
        }
        let needles = filter_needles(filter, index)?;
        records.retain(|record| {
            record_field_values(record, filter.field.as_str())
                .map(|values| matches_filter_values(&values, filter, &needles))
                .unwrap_or(false)
        });
    }
    Ok(())
}

fn validate_filter_shape(filter: &FilterSpec, index: usize) -> Result<(), ExportHistoryError> {
    if matches!(
        filter.operator,
        FilterOperator::GreaterThan
            | FilterOperator::GreaterThanOrEqual
            | FilterOperator::LessThan
            | FilterOperator::LessThanOrEqual
    ) {
        return Err(ExportHistoryError::UnsupportedFilterOperator { index });
    }
    Ok(())
}

fn filter_needles(filter: &FilterSpec, index: usize) -> Result<Vec<String>, ExportHistoryError> {
    if filter.operator == FilterOperator::Exists {
        return Ok(Vec::new());
    }

    match filter.value.as_ref() {
        Some(FilterValue::String(value)) => Ok(vec![normalize_query_value(value)]),
        Some(FilterValue::Strings(values)) => {
            Ok(values.iter().map(normalize_query_value).collect())
        }
        Some(FilterValue::Bool(value)) => Ok(vec![value.to_string()]),
        Some(FilterValue::Number(value)) => Ok(vec![value.to_string()]),
        Some(FilterValue::Null) | None => Err(ExportHistoryError::UnsupportedFilterValue { index }),
    }
}

fn matches_filter_values(values: &[String], filter: &FilterSpec, needles: &[String]) -> bool {
    let values = values.iter().map(normalize_query_value).collect::<Vec<_>>();
    match filter.operator {
        FilterOperator::Eq => values.iter().any(|value| needles.contains(value)),
        FilterOperator::NotEq => values.iter().all(|value| !needles.contains(value)),
        FilterOperator::Contains => needles
            .first()
            .is_some_and(|needle| values.iter().any(|value| value.contains(needle))),
        FilterOperator::StartsWith => needles
            .first()
            .is_some_and(|needle| values.iter().any(|value| value.starts_with(needle))),
        FilterOperator::EndsWith => needles
            .first()
            .is_some_and(|needle| values.iter().any(|value| value.ends_with(needle))),
        FilterOperator::In => values.iter().any(|value| needles.contains(value)),
        FilterOperator::NotIn => values.iter().all(|value| !needles.contains(value)),
        FilterOperator::Exists => !values.is_empty(),
        FilterOperator::GreaterThan
        | FilterOperator::GreaterThanOrEqual
        | FilterOperator::LessThan
        | FilterOperator::LessThanOrEqual => false,
    }
}

fn apply_query_sort(
    records: &mut [ExportHistoryRecord],
    sort: &[SortSpec],
) -> Result<(), ExportHistoryError> {
    for (index, spec) in sort.iter().enumerate() {
        if !sort_field_supported(spec.field.as_str()) {
            return Err(ExportHistoryError::UnsupportedSortField { index });
        }
    }

    for spec in sort.iter().rev() {
        records.sort_by(|left, right| {
            let ordering = compare_records(left, right, spec.field.as_str())
                .unwrap_or(std::cmp::Ordering::Equal);
            match spec.direction {
                SortDirection::Asc => ordering,
                SortDirection::Desc => ordering.reverse(),
            }
        });
    }
    Ok(())
}

fn filter_field_supported(field: &str) -> bool {
    matches!(
        field,
        "id" | "export_result_id"
            | "report_id"
            | "report_ref"
            | "format"
            | "actor"
            | "actor_redacted"
            | "success"
            | "audit_id"
            | "trace_id"
            | "graph_snapshot_ref"
            | "graph_snapshot_id"
            | "evidence_ref"
            | "evidence_id"
            | "response_result_ref"
            | "response_result_id"
            | "rollback_result_ref"
            | "rollback_result_id"
            | "file_hash_present"
    )
}

fn sort_field_supported(field: &str) -> bool {
    matches!(
        field,
        "id" | "export_result_id"
            | "report_id"
            | "format"
            | "actor"
            | "actor_redacted"
            | "exported_at"
            | "success"
            | "graph_snapshot_count"
            | "evidence_count"
            | "response_result_count"
            | "rollback_result_count"
    )
}

fn record_field_values(record: &ExportHistoryRecord, field: &str) -> Option<Vec<String>> {
    match field {
        "id" | "export_result_id" => Some(vec![record.export_result_id.to_string()]),
        "report_id" | "report_ref" => Some(vec![record.report_id.to_string()]),
        "format" => Some(vec![record.format.as_str().to_string()]),
        "actor" | "actor_redacted" => Some(vec![record.actor_redacted.clone()]),
        "success" => Some(vec![record.success.to_string()]),
        "audit_id" => Some(vec![record.audit_id.to_string()]),
        "trace_id" => Some(optional_to_values(record.trace_id.as_ref())),
        "graph_snapshot_ref" | "graph_snapshot_id" => Some(
            record
                .graph_snapshot_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "evidence_ref" | "evidence_id" => Some(
            record
                .evidence_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "response_result_ref" | "response_result_id" => Some(
            record
                .response_result_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "rollback_result_ref" | "rollback_result_id" => Some(
            record
                .rollback_result_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        "file_hash_present" => Some(vec![record.file_hash.is_some().to_string()]),
        _ => None,
    }
}

fn compare_records(
    left: &ExportHistoryRecord,
    right: &ExportHistoryRecord,
    field: &str,
) -> Option<std::cmp::Ordering> {
    match field {
        "id" | "export_result_id" => Some(
            left.export_result_id
                .to_string()
                .cmp(&right.export_result_id.to_string()),
        ),
        "report_id" => Some(left.report_id.to_string().cmp(&right.report_id.to_string())),
        "format" => Some(left.format.as_str().cmp(right.format.as_str())),
        "actor" | "actor_redacted" => Some(left.actor_redacted.cmp(&right.actor_redacted)),
        "exported_at" => Some(left.exported_at.cmp(&right.exported_at)),
        "success" => Some(left.success.cmp(&right.success)),
        "graph_snapshot_count" => Some(
            left.graph_snapshot_refs
                .len()
                .cmp(&right.graph_snapshot_refs.len()),
        ),
        "evidence_count" => Some(left.evidence_refs.len().cmp(&right.evidence_refs.len())),
        "response_result_count" => Some(
            left.response_result_refs
                .len()
                .cmp(&right.response_result_refs.len()),
        ),
        "rollback_result_count" => Some(
            left.rollback_result_refs
                .len()
                .cmp(&right.rollback_result_refs.len()),
        ),
        _ => None,
    }
}

fn optional_to_values<T: ToString>(value: Option<&T>) -> Vec<String> {
    value.map(ToString::to_string).into_iter().collect()
}

fn normalize_query_value(value: impl AsRef<str>) -> String {
    value.as_ref().trim().to_ascii_lowercase()
}

fn page_records(
    records: Vec<ExportHistoryRecord>,
    page: &PageRequest,
) -> Result<PageResponse<ExportHistoryRecord>, ExportHistoryError> {
    let start = page
        .cursor
        .as_ref()
        .map(|cursor| decode_cursor(cursor.as_str()))
        .transpose()?
        .unwrap_or(0);
    if start > records.len() {
        return Err(ExportHistoryError::InvalidCursor);
    }

    let end = usize::min(start + page.limit as usize, records.len());
    let has_more = end < records.len();
    let next_cursor = if has_more {
        Some(encode_cursor(end)?)
    } else {
        None
    };
    Ok(PageResponse::from_request(
        records[start..end].to_vec(),
        page,
        next_cursor,
        has_more,
    ))
}

fn export_history_metadata(record: &ExportHistoryRecord) -> Result<Value, ExportHistoryError> {
    Ok(json!({
        "record_kind": "export_history_record",
        "record": serde_json::to_value(record)?
    }))
}

fn export_policy_violation_metadata(
    violation: &ExportPolicyViolation,
) -> Result<Value, ExportHistoryError> {
    Ok(json!({
        "record_kind": "export_policy_violation",
        "record": serde_json::to_value(violation)?
    }))
}

fn read_all_export_history_records(
    stores: &SqliteStoreFactory<'_>,
) -> Result<Vec<ExportHistoryRecord>, ExportHistoryError> {
    let store = stores.export_history_store();
    let mut page = PageRequest::first(1_000).map_err(|_| ExportHistoryError::InvalidCursor)?;
    let mut records = Vec::new();

    loop {
        let response = store.query(QueryRequest::new(QueryScope::Global).with_page(page))?;
        for record in response.page.items {
            records.push(export_history_from_logical_record(record)?);
        }

        let Some(cursor) = response.page.next_cursor else {
            break;
        };
        page =
            PageRequest::new(1_000, Some(cursor)).map_err(|_| ExportHistoryError::InvalidCursor)?;
    }

    Ok(records)
}

fn read_all_export_policy_violations(
    stores: &SqliteStoreFactory<'_>,
) -> Result<Vec<ExportPolicyViolation>, ExportHistoryError> {
    let store = stores.export_policy_violation_store();
    let mut page = PageRequest::first(1_000).map_err(|_| ExportHistoryError::InvalidCursor)?;
    let mut violations = Vec::new();

    loop {
        let response = store.query(QueryRequest::new(QueryScope::Global).with_page(page))?;
        for record in response.page.items {
            violations.push(export_policy_violation_from_logical_record(record)?);
        }

        let Some(cursor) = response.page.next_cursor else {
            break;
        };
        page =
            PageRequest::new(1_000, Some(cursor)).map_err(|_| ExportHistoryError::InvalidCursor)?;
    }

    Ok(violations)
}

fn export_history_from_logical_record(
    record: LogicalRecord<ExportResultId>,
) -> Result<ExportHistoryRecord, ExportHistoryError> {
    let record_value = stored_record_value(&record.metadata, "export_history_record")?;
    let history_record = serde_json::from_value::<ExportHistoryRecord>(record_value)?;
    validate_history_record(&history_record)?;
    Ok(history_record)
}

fn export_policy_violation_from_logical_record(
    record: LogicalRecord<AuditId>,
) -> Result<ExportPolicyViolation, ExportHistoryError> {
    let record_value = stored_record_value(&record.metadata, "export_policy_violation")?;
    let violation = serde_json::from_value::<ExportPolicyViolation>(record_value)?;
    validate_violation(&violation)?;
    Ok(violation)
}

fn stored_record_value(
    metadata: &Value,
    record_kind: &'static str,
) -> Result<Value, ExportHistoryError> {
    metadata
        .get("record")
        .cloned()
        .ok_or(ExportHistoryError::InvalidStoredRecord { record_kind })
}

fn encode_cursor(index: usize) -> Result<Cursor, ExportHistoryError> {
    Cursor::new(format!("{EXPORT_HISTORY_CURSOR_PREFIX}|{index}"))
        .map_err(|_| ExportHistoryError::InvalidCursor)
}

fn decode_cursor(value: &str) -> Result<usize, ExportHistoryError> {
    let mut parts = value.splitn(2, '|');
    match (parts.next(), parts.next()) {
        (Some(EXPORT_HISTORY_CURSOR_PREFIX), Some(index)) => index
            .parse::<usize>()
            .map_err(|_| ExportHistoryError::InvalidCursor),
        _ => Err(ExportHistoryError::InvalidCursor),
    }
}

fn require_non_empty(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, ExportHistoryError> {
    let value = value.into();
    if value.trim().is_empty() {
        Err(ExportHistoryError::EmptyField(field))
    } else {
        Ok(value)
    }
}

fn require_safe_export_text(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, ExportHistoryError> {
    let value = require_non_empty(field, value)?;
    let normalized = value.to_ascii_lowercase();
    if FORBIDDEN_EXPORT_HISTORY_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
        || contains_local_path_or_filename(&normalized)
    {
        Err(ExportHistoryError::SensitiveMarker { field })
    } else {
        Ok(value)
    }
}

fn contains_local_path_or_filename(value: &str) -> bool {
    if FORBIDDEN_LOCAL_PATH_MARKERS
        .iter()
        .any(|marker| value.contains(marker))
    {
        return true;
    }

    if value.contains('\\') || value.contains('/') {
        return true;
    }

    value.split_whitespace().any(|token| {
        let token = token.trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
            )
        });
        FORBIDDEN_FILENAME_EXTENSIONS
            .iter()
            .any(|extension| token.ends_with(extension))
    })
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn bounded_unique<T: PartialEq>(values: Vec<T>) -> Vec<T> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
        if unique.len() >= 100 {
            break;
        }
    }
    unique
}

const FORBIDDEN_EXPORT_HISTORY_MARKERS: &[&str] = &[
    "raw_packet",
    "packet_bytes",
    "payload_blob",
    "raw_payload",
    "http_body",
    "request_body",
    "response_body",
    "authorization:",
    "set-cookie",
    "session_token",
    "access_token",
    "refresh_token",
    "api_key",
    "private_key",
    "password=",
    "credential=",
    "query_string=",
    "form_content",
    "file_content",
    "command_line=",
];

const FORBIDDEN_LOCAL_PATH_MARKERS: &[&str] = &[
    "c:\\users\\",
    "\\users\\",
    "\\appdata\\",
    "%appdata%",
    "%localappdata%",
    "\\temp\\",
    "\\tmp\\",
    "/users/",
    "/home/",
    "/tmp/",
];

const FORBIDDEN_FILENAME_EXTENSIONS: &[&str] = &[
    ".sgsession",
    ".sgreport",
    ".sggraph",
    ".md",
    ".markdown",
    ".html",
    ".json",
];

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use sentinel_contracts::{
        report::{ExportFormat, ExportRequest, ExportResult},
        AuditRef, IncidentId, RedactedDataCategory, ReportId, ResponseContractError,
        ResponseResultId, RollbackResultId,
    };
    use sentinel_storage::{
        logical_store_migration, InMemoryMigrationAuditSink, MigrationRunner, SchemaMetadata,
        SqliteStoreFactory,
    };

    #[test]
    fn successful_exports_create_history_with_audit_redaction_and_hash(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut store = ExportHistoryStore::new();
        let service = ExportAuditService::new();
        let result = export_result()?;
        let response_result_id = ResponseResultId::new_v4();
        let rollback_result_id = RollbackResultId::new_v4();
        let record = service.record_success(
            &mut store,
            ExportAuditSuccessInput {
                export_result: result.clone(),
                actor_redacted: "local_user".to_string(),
                destination: ExportDestinationMetadata::local(Some(
                    "local report file".to_string(),
                ))?,
                audit_receipt: audit_receipt(),
                artifact_bytes: Some(b"redacted report body".to_vec()),
                graph_snapshot_refs: vec![GraphSnapshotId::new_v4()],
                evidence_refs: vec![EvidenceId::new_v4()],
                response_result_refs: vec![response_result_id.clone(), response_result_id.clone()],
                rollback_result_refs: vec![rollback_result_id.clone(), rollback_result_id.clone()],
                llm_story_refs: Vec::new(),
            },
        )?;

        assert_eq!(store.records().len(), 1);
        assert_eq!(record.report_id, result.report_id);
        assert!(record.redaction_summary.passed);
        assert!(record.file_hash.is_some());
        assert_eq!(
            record
                .file_hash
                .as_ref()
                .map(|hash| hash.algorithm.as_str()),
            Some("sha256")
        );
        assert_eq!(record.audit_id, store.records()[0].audit_id);
        assert_eq!(record.graph_snapshot_refs.len(), 1);
        assert_eq!(record.evidence_refs.len(), 1);
        assert_eq!(record.response_result_refs, vec![response_result_id]);
        assert_eq!(record.rollback_result_refs, vec![rollback_result_id]);
        Ok(())
    }

    #[test]
    fn failed_exports_do_not_append_history_records() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = ExportHistoryStore::new();
        let service = ExportAuditService::new();
        let mut result = export_result()?;
        result.success = false;

        let error = service
            .record_success(
                &mut store,
                ExportAuditSuccessInput {
                    export_result: result,
                    actor_redacted: "local_user".to_string(),
                    destination: ExportDestinationMetadata::local(Some(
                        "local report file".to_string(),
                    ))?,
                    audit_receipt: audit_receipt(),
                    artifact_bytes: Some(b"redacted report body".to_vec()),
                    graph_snapshot_refs: Vec::new(),
                    evidence_refs: Vec::new(),
                    response_result_refs: Vec::new(),
                    rollback_result_refs: Vec::new(),
                    llm_story_refs: Vec::new(),
                },
            )
            .expect_err("failed export should not append history");

        assert_eq!(error, ExportHistoryError::ExportFailed);
        assert!(store.records().is_empty());
        Ok(())
    }

    #[test]
    fn artifact_byte_hash_is_sha256_of_final_export_bytes() {
        let hash = ExportFileHash::from_bytes(b"redacted report body");
        let repeated = ExportFileHash::from_bytes(b"redacted report body");
        let different = ExportFileHash::from_bytes(b"different redacted report body");

        assert_eq!(hash.algorithm, "sha256");
        assert_eq!(
            hash.value,
            "920a822af08d89837abfd528ac0021279e314623f1a5942c79b38efb637f582f"
        );
        assert_eq!(hash.value.len(), 64);
        assert_eq!(hash.value, repeated.value);
        assert_ne!(hash.value, different.value);
    }

    #[test]
    fn recorded_hash_must_match_final_export_artifact_bytes_when_both_are_present(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut store = ExportHistoryStore::new();
        let service = ExportAuditService::new();
        let mut result = export_result()?;
        result.file_hash = Some("not-the-final-artifact-byte-hash".to_string());

        let error = service
            .record_success(
                &mut store,
                ExportAuditSuccessInput {
                    export_result: result,
                    actor_redacted: "local_user".to_string(),
                    destination: ExportDestinationMetadata::local(Some(
                        "local report file".to_string(),
                    ))?,
                    audit_receipt: audit_receipt(),
                    artifact_bytes: Some(b"redacted report body".to_vec()),
                    graph_snapshot_refs: Vec::new(),
                    evidence_refs: Vec::new(),
                    response_result_refs: Vec::new(),
                    rollback_result_refs: Vec::new(),
                    llm_story_refs: Vec::new(),
                },
            )
            .expect_err("mismatched hash rejected");

        assert_eq!(error, ExportHistoryError::FileHashMismatch);
        assert!(store.records().is_empty());
        Ok(())
    }

    #[test]
    fn export_history_can_be_listed_and_filtered() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = ExportHistoryStore::new();
        let service = ExportAuditService::new();
        let result = export_result()?;
        let report_id = result.report_id.clone();
        service.record_success(
            &mut store,
            ExportAuditSuccessInput {
                export_result: result,
                actor_redacted: "local_user".to_string(),
                destination: ExportDestinationMetadata::local(Some(
                    "local report file".to_string(),
                ))?,
                audit_receipt: audit_receipt(),
                artifact_bytes: Some(b"redacted report body".to_vec()),
                graph_snapshot_refs: Vec::new(),
                evidence_refs: Vec::new(),
                response_result_refs: Vec::new(),
                rollback_result_refs: Vec::new(),
                llm_story_refs: Vec::new(),
            },
        )?;

        let page = store.query(
            ReportExportHistoryQuery::for_report(report_id)
                .with_format(ExportFormat::Markdown)
                .with_actor("local_user"),
        )?;

        assert_eq!(page.items.len(), 1);
        assert!(!page.has_more);
        Ok(())
    }

    #[test]
    fn query_request_supports_scope_filters_sort_pagination_and_empty_filters(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut store = ExportHistoryStore::new();
        let service = ExportAuditService::new();
        let mut first = export_result()?;
        let report_id = first.report_id.clone();
        first.completed_at = Timestamp::now();
        let first_record = service.record_success(
            &mut store,
            ExportAuditSuccessInput {
                export_result: first,
                actor_redacted: "local_user".to_string(),
                destination: ExportDestinationMetadata::local(Some(
                    "local report file".to_string(),
                ))?,
                audit_receipt: audit_receipt(),
                artifact_bytes: Some(b"redacted report body".to_vec()),
                graph_snapshot_refs: vec![GraphSnapshotId::new_v4()],
                evidence_refs: vec![EvidenceId::new_v4()],
                response_result_refs: vec![ResponseResultId::new_v4()],
                rollback_result_refs: Vec::new(),
                llm_story_refs: Vec::new(),
            },
        )?;
        let mut second = export_result()?;
        second.report_id = report_id.clone();
        second.completed_at = Timestamp::now();
        let second_record = service.record_success(
            &mut store,
            ExportAuditSuccessInput {
                export_result: second,
                actor_redacted: "local_responder".to_string(),
                destination: ExportDestinationMetadata::local(Some(
                    "local report file".to_string(),
                ))?,
                audit_receipt: audit_receipt(),
                artifact_bytes: Some(b"redacted report body 2".to_vec()),
                graph_snapshot_refs: vec![GraphSnapshotId::new_v4(), GraphSnapshotId::new_v4()],
                evidence_refs: vec![EvidenceId::new_v4(), EvidenceId::new_v4()],
                response_result_refs: vec![ResponseResultId::new_v4(), ResponseResultId::new_v4()],
                rollback_result_refs: vec![RollbackResultId::new_v4()],
                llm_story_refs: Vec::new(),
            },
        )?;

        let first_page = store.query_request(
            QueryRequest::new(QueryScope::Global)
                .with_page(PageRequest::first(1)?)
                .with_filters(Vec::new())
                .with_sort(vec![SortSpec::new(
                    "response_result_count",
                    SortDirection::Desc,
                )?]),
        )?;
        assert_eq!(first_page.items, vec![second_record.clone()]);
        assert!(first_page.has_more);

        let second_page = store.query_request(
            QueryRequest::new(QueryScope::Global)
                .with_page(PageRequest::new(1, first_page.next_cursor.clone())?)
                .with_sort(vec![SortSpec::new(
                    "response_result_count",
                    SortDirection::Desc,
                )?]),
        )?;
        assert_eq!(second_page.items, vec![first_record.clone()]);
        assert!(!second_page.has_more);

        let filtered = store.query_request(
            QueryRequest::new(QueryScope::Report(report_id)).with_filters(vec![
                FilterSpec::new(
                    "actor_redacted",
                    FilterOperator::Contains,
                    Some(FilterValue::String("responder".to_string())),
                )?,
                FilterSpec::new("success", FilterOperator::Eq, Some(FilterValue::Bool(true)))?,
            ]),
        )?;
        assert_eq!(filtered.items, vec![second_record]);
        Ok(())
    }

    #[test]
    fn query_request_rejects_unsupported_scope_fields_and_sorts() {
        let store = ExportHistoryStore::new();

        let scope_error = store
            .query_request(QueryRequest::new(
                QueryScope::Incident(IncidentId::new_v4()),
            ))
            .expect_err("unsupported scope");
        assert_eq!(scope_error, ExportHistoryError::UnsupportedScope);

        let field_error = store
            .query_request(QueryRequest::new(QueryScope::Global).with_filters(vec![
                FilterSpec::new(
                    "authorization_header_value",
                    FilterOperator::Eq,
                    Some(FilterValue::String("session_token".to_string())),
                )
                .expect("filter"),
            ]))
            .expect_err("unsupported filter field");
        assert_eq!(
            field_error,
            ExportHistoryError::UnsupportedFilterField { index: 0 }
        );
        assert!(!field_error
            .to_string()
            .contains("authorization_header_value"));
        assert!(!field_error.to_string().contains("session_token"));

        let sort_error = store
            .query_request(QueryRequest::new(QueryScope::Global).with_sort(vec![
                SortSpec::new("payload_blob", SortDirection::Asc).expect("sort"),
            ]))
            .expect_err("unsupported sort field");
        assert_eq!(
            sort_error,
            ExportHistoryError::UnsupportedSortField { index: 0 }
        );
        assert!(!sort_error.to_string().contains("payload_blob"));
    }

    #[test]
    fn rejected_exports_create_policy_violation_records() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut store = ExportHistoryStore::new();
        let service = ExportAuditService::new();
        let violation = service.record_violation(
            &mut store,
            ExportPolicyViolationInput {
                report_id: ReportId::new_v4(),
                format: ExportFormat::RedactedJson,
                actor_redacted: "local_user".to_string(),
                destination: ExportDestinationMetadata::local(Some(
                    "local report file".to_string(),
                ))?,
                reason_redacted: "report export denied by privacy gate".to_string(),
                redaction_summary: redaction_summary(),
                trace_id: Some(TraceId::new_v4()),
                violation_audit_receipt: audit_receipt(),
                export_audit_id: Some(AuditId::new_v4()),
            },
        )?;

        assert_eq!(store.violations().len(), 1);
        assert_eq!(violation.audit_id, store.violations()[0].audit_id);
        assert!(violation.export_audit_id.is_some());
        Ok(())
    }

    #[test]
    fn export_history_round_trips_through_logical_storage() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut store = ExportHistoryStore::new();
        let service = ExportAuditService::new();
        let result = export_result()?;
        let report_id = result.report_id.clone();
        let record = service.record_success(
            &mut store,
            ExportAuditSuccessInput {
                export_result: result,
                actor_redacted: "local_user".to_string(),
                destination: ExportDestinationMetadata::local(Some(
                    "local report file".to_string(),
                ))?,
                audit_receipt: audit_receipt(),
                artifact_bytes: Some(b"redacted report body".to_vec()),
                graph_snapshot_refs: vec![GraphSnapshotId::new_v4()],
                evidence_refs: vec![EvidenceId::new_v4()],
                response_result_refs: Vec::new(),
                rollback_result_refs: Vec::new(),
                llm_story_refs: Vec::new(),
            },
        )?;
        let violation = service.record_violation(
            &mut store,
            ExportPolicyViolationInput {
                report_id: report_id.clone(),
                format: ExportFormat::Markdown,
                actor_redacted: "local_user".to_string(),
                destination: ExportDestinationMetadata::local(Some(
                    "local report file".to_string(),
                ))?,
                reason_redacted: "report export denied by privacy gate".to_string(),
                redaction_summary: redaction_summary(),
                trace_id: Some(TraceId::new_v4()),
                violation_audit_receipt: audit_receipt(),
                export_audit_id: Some(record.audit_id.clone()),
            },
        )?;
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let adapter = ExportHistoryStorageAdapter::new();

        let summary = adapter.persist_store(&stores, &store)?;
        let loaded = adapter.load_store(&stores)?;
        let page = loaded.query(
            ReportExportHistoryQuery::for_report(report_id)
                .with_format(ExportFormat::Markdown)
                .with_actor("local_user"),
        )?;

        assert_eq!(summary.history_records, 1);
        assert_eq!(summary.policy_violation_records, 1);
        assert_eq!(page.items, vec![record]);
        assert_eq!(loaded.violations(), &[violation]);
        Ok(())
    }

    #[test]
    fn append_rejects_records_with_oversized_reference_vectors() {
        let mut store = ExportHistoryStore::new();
        let mut record = valid_history_record();
        record.graph_snapshot_refs = (0..101).map(|_| GraphSnapshotId::new_v4()).collect();

        let error = store
            .append(record)
            .expect_err("oversized graph refs should be rejected");

        assert_eq!(
            error,
            ExportHistoryError::BoundedFieldTooLarge {
                field: "graph_snapshot_refs"
            }
        );
        assert!(store.records().is_empty());
    }

    #[test]
    fn append_rejects_records_with_invalid_file_hash_metadata() {
        let mut store = ExportHistoryStore::new();
        let mut record = valid_history_record();
        record.file_hash = Some(ExportFileHash {
            algorithm: "md5".to_string(),
            value: "not-a-sha256".to_string(),
            calculated_at: Timestamp::now(),
        });

        let error = store
            .append(record)
            .expect_err("invalid file hash should be rejected");

        assert_eq!(error, ExportHistoryError::InvalidFileHash);
        assert!(store.records().is_empty());
    }

    #[test]
    fn history_rejects_sensitive_destination_markers() {
        let destination =
            ExportDestinationMetadata::local(Some("authorization: bearer secret".to_string()));

        assert!(matches!(
            destination,
            Err(ExportHistoryError::SensitiveMarker {
                field: "destination_metadata_redacted"
            })
        ));
    }

    #[test]
    fn history_rejects_local_paths_and_filenames_in_destination_metadata() {
        for leaked_value in [
            "C:\\Users\\Lenovo\\AppData\\Local\\Temp\\report.sgreport",
            "/Users/lenovo/export/report.json",
            "incident_report.sgreport",
        ] {
            let destination = ExportDestinationMetadata::local(Some(leaked_value.to_string()));
            let error = destination.expect_err("unsafe destination rejected");

            assert_eq!(
                error,
                ExportHistoryError::SensitiveMarker {
                    field: "destination_metadata_redacted"
                }
            );
            assert!(!error.to_string().contains(leaked_value));
        }
    }

    #[test]
    fn changing_final_artifact_bytes_changes_recorded_hash(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut store = ExportHistoryStore::new();
        let service = ExportAuditService::new();

        let mut first_result = export_result()?;
        first_result.completed_at = Timestamp::now();
        let first = service.record_success(
            &mut store,
            ExportAuditSuccessInput {
                export_result: first_result,
                actor_redacted: "local_user".to_string(),
                destination: ExportDestinationMetadata::local(Some(
                    "local report file".to_string(),
                ))?,
                audit_receipt: audit_receipt(),
                artifact_bytes: Some(b"artifact bytes one".to_vec()),
                graph_snapshot_refs: Vec::new(),
                evidence_refs: Vec::new(),
                response_result_refs: Vec::new(),
                rollback_result_refs: Vec::new(),
                llm_story_refs: Vec::new(),
            },
        )?;

        let mut second_result = export_result()?;
        second_result.completed_at = Timestamp::now();
        let second = service.record_success(
            &mut store,
            ExportAuditSuccessInput {
                export_result: second_result,
                actor_redacted: "local_user".to_string(),
                destination: ExportDestinationMetadata::local(Some(
                    "local report file".to_string(),
                ))?,
                audit_receipt: audit_receipt(),
                artifact_bytes: Some(b"artifact bytes two".to_vec()),
                graph_snapshot_refs: Vec::new(),
                evidence_refs: Vec::new(),
                response_result_refs: Vec::new(),
                rollback_result_refs: Vec::new(),
                llm_story_refs: Vec::new(),
            },
        )?;

        assert_ne!(
            first.file_hash.as_ref().map(|hash| hash.value.clone()),
            second.file_hash.as_ref().map(|hash| hash.value.clone())
        );
        Ok(())
    }

    #[test]
    fn serialized_history_remains_privacy_safe_without_paths_filenames_or_raw_content(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut store = ExportHistoryStore::new();
        let service = ExportAuditService::new();
        let response_result_id = ResponseResultId::new_v4();
        let rollback_result_id = RollbackResultId::new_v4();
        let record = service.record_success(
            &mut store,
            ExportAuditSuccessInput {
                export_result: export_result()?,
                actor_redacted: "local_user".to_string(),
                destination: ExportDestinationMetadata::local(Some(
                    "local report file".to_string(),
                ))?,
                audit_receipt: audit_receipt(),
                artifact_bytes: Some(b"privacy-safe final artifact".to_vec()),
                graph_snapshot_refs: vec![GraphSnapshotId::new_v4()],
                evidence_refs: vec![EvidenceId::new_v4()],
                response_result_refs: vec![response_result_id.clone(), response_result_id.clone()],
                rollback_result_refs: vec![rollback_result_id.clone(), rollback_result_id.clone()],
                llm_story_refs: Vec::new(),
            },
        )?;

        let serialized = serde_json::to_string(&record)?;

        assert!(!serialized.contains("privacy-safe final artifact"));
        assert!(!serialized.contains("C:\\Users\\"));
        assert!(!serialized.contains("/Users/"));
        assert!(!serialized.contains(".sgreport"));
        assert_eq!(record.response_result_refs, vec![response_result_id]);
        assert_eq!(record.rollback_result_refs, vec![rollback_result_id]);
        Ok(())
    }

    #[test]
    fn persisted_history_metadata_remains_bounded_and_privacy_safe(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let stores = SqliteStoreFactory::new(&connection);
        let adapter = ExportHistoryStorageAdapter::new();
        let mut store = ExportHistoryStore::new();
        let record = ExportAuditService::new().record_success(
            &mut store,
            ExportAuditSuccessInput {
                export_result: export_result()?,
                actor_redacted: "local_user".to_string(),
                destination: ExportDestinationMetadata::local(Some(
                    "local report file".to_string(),
                ))?,
                audit_receipt: audit_receipt(),
                artifact_bytes: Some(b"privacy-safe final artifact".to_vec()),
                graph_snapshot_refs: (0..120).map(|_| GraphSnapshotId::new_v4()).collect(),
                evidence_refs: (0..120).map(|_| EvidenceId::new_v4()).collect(),
                response_result_refs: (0..120).map(|_| ResponseResultId::new_v4()).collect(),
                rollback_result_refs: (0..120).map(|_| RollbackResultId::new_v4()).collect(),
                llm_story_refs: (0..120).map(|_| LlmAlertStoryId::new_v4()).collect(),
            },
        )?;

        adapter.persist_record(&stores, &record)?;
        let stored = stores
            .export_history_store()
            .get_by_id(&record.export_result_id)?
            .expect("stored export history record");
        let serialized = serde_json::to_string(&stored.metadata)?;

        assert_eq!(record.graph_snapshot_refs.len(), 100);
        assert_eq!(record.evidence_refs.len(), 100);
        assert_eq!(record.response_result_refs.len(), 100);
        assert_eq!(record.rollback_result_refs.len(), 100);
        assert!(!serialized.contains("privacy-safe final artifact"));
        assert!(!serialized.contains("C:\\Users\\"));
        assert!(!serialized.contains("/Users/"));
        assert!(!serialized.contains(".sgreport"));
        Ok(())
    }

    fn valid_history_record() -> ExportHistoryRecord {
        ExportHistoryRecord {
            export_result_id: ExportResultId::new_v4(),
            report_id: ReportId::new_v4(),
            format: ExportFormat::Markdown,
            destination: ExportDestinationMetadata::local(Some("local report file".to_string()))
                .expect("destination"),
            file_hash: Some(ExportFileHash::from_bytes(b"redacted report body")),
            redaction_summary: redaction_summary(),
            graph_snapshot_refs: vec![GraphSnapshotId::new_v4()],
            evidence_refs: vec![EvidenceId::new_v4()],
            response_result_refs: vec![ResponseResultId::new_v4()],
            rollback_result_refs: vec![RollbackResultId::new_v4()],
            llm_story_refs: vec![LlmAlertStoryId::new_v4()],
            actor_redacted: "local_user".to_string(),
            exported_at: Timestamp::now(),
            trace_id: Some(TraceId::new_v4()),
            audit_id: AuditId::new_v4(),
            success: true,
        }
    }

    fn export_result() -> Result<ExportResult, Box<dyn std::error::Error>> {
        let request = ExportRequest::new(
            ReportId::new_v4(),
            ExportFormat::Markdown,
            "local_user",
            redaction_summary(),
            AuditRef::new("report.export.requested")
                .map_err(|error: ResponseContractError| error.to_string())?,
        )?;
        let mut result = ExportResult::from_request(request, true);
        result.destination_metadata_redacted = Some("local report file".to_string());
        result.trace_id = Some(TraceId::new_v4());
        Ok(result)
    }

    fn redaction_summary() -> RedactionSummary {
        RedactionSummary::passed(vec![
            RedactedDataCategory::RawPacket,
            RedactedDataCategory::Payload,
            RedactedDataCategory::HttpBody,
            RedactedDataCategory::Cookie,
            RedactedDataCategory::Token,
            RedactedDataCategory::Credential,
            RedactedDataCategory::ApiKey,
        ])
    }

    fn audit_receipt() -> AuditReceipt {
        AuditReceipt {
            audit_id: AuditId::new_v4(),
            sequence: 1,
            appended_at: Timestamp::now(),
        }
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
