use crate::error::{StorageError, StorageResult};
use crate::ids::{ComponentRecordId, IntelligenceCacheId, SettingsRecordId, StoreSnapshotId};
use crate::migration::{Migration, MigrationId, MigrationStatement, RowCountVerificationHook};
use crate::privacy::{DataClass, FieldProtection, RetentionClass, StoragePrivacyClass};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use sentinel_contracts::{
    AlertId, AssetIdentityId, AuditId, Cursor, DnsObservationId, EntityRef, EventId, EvidenceId,
    ExportResultId, FindingId, FlowId, GraphEdgeId, GraphNodeId, GraphPathId, HttpMetadataId,
    IncidentId, PageRequest, PageResponse, PluginId, PrivacyClass, QueryRequest, QueryResponse,
    QueryScope, ReportId, ResponseActionId, ResponsePlanId, ResponseResultId, RiskEventId,
    RollbackResultId, SchemaVersion, SessionId, TimeRange, Timestamp, TlsObservationId,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::marker::PhantomData;

const LOGICAL_STORE_CURSOR_PREFIX: &str = "logical_store:v1";

const FORBIDDEN_METADATA_KEYS: &[&str] = &[
    "raw_packet",
    "raw_packets",
    "packet_bytes",
    "payload",
    "raw_payload",
    "payload_blob",
    "http_body",
    "request_body",
    "response_body",
    "cookie",
    "cookies",
    "authorization",
    "authorization_header",
    "api_key",
    "password",
    "credential",
    "credentials",
    "private_key",
    "session_token",
    "access_token",
    "refresh_token",
    "token",
    "tokens",
    "secret",
    "secrets",
];

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreKind {
    Event,
    Plugin,
    Component,
    Flow,
    Session,
    Dns,
    Tls,
    HttpMetadata,
    ProcessContext,
    IntelligenceCache,
    Asset,
    Finding,
    Evidence,
    Risk,
    Alert,
    Incident,
    GraphNode,
    GraphEdge,
    GraphPath,
    ResponsePlan,
    ResponseAction,
    ResponseResult,
    RollbackResult,
    Report,
    ExportHistory,
    ExportPolicyViolation,
    Audit,
    Settings,
    Migration,
}

impl StoreKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Event => "event",
            Self::Plugin => "plugin",
            Self::Component => "component",
            Self::Flow => "flow",
            Self::Session => "session",
            Self::Dns => "dns",
            Self::Tls => "tls",
            Self::HttpMetadata => "http_metadata",
            Self::ProcessContext => "process_context",
            Self::IntelligenceCache => "intelligence_cache",
            Self::Asset => "asset",
            Self::Finding => "finding",
            Self::Evidence => "evidence",
            Self::Risk => "risk",
            Self::Alert => "alert",
            Self::Incident => "incident",
            Self::GraphNode => "graph_node",
            Self::GraphEdge => "graph_edge",
            Self::GraphPath => "graph_path",
            Self::ResponsePlan => "response_plan",
            Self::ResponseAction => "response_action",
            Self::ResponseResult => "response_result",
            Self::RollbackResult => "rollback_result",
            Self::Report => "report",
            Self::ExportHistory => "export_history",
            Self::ExportPolicyViolation => "export_policy_violation",
            Self::Audit => "audit",
            Self::Settings => "settings",
            Self::Migration => "migration",
        }
    }

    pub fn default_storage_privacy_class(&self) -> StoragePrivacyClass {
        match self {
            Self::Event
            | Self::Plugin
            | Self::Component
            | Self::Settings
            | Self::Migration
            | Self::IntelligenceCache => StoragePrivacyClass::operational_metadata(),
            Self::Flow | Self::Session | Self::Dns | Self::ProcessContext => {
                StoragePrivacyClass::network_behavioral_metadata()
            }
            Self::Tls => StoragePrivacyClass::new(
                DataClass::D3NetworkBehavioralMetadata,
                RetentionClass::Days90,
                PrivacyClass::Sensitive,
                vec![
                    FieldProtection::Encrypt,
                    FieldProtection::RedactBeforeExport,
                ],
            ),
            Self::HttpMetadata => StoragePrivacyClass::new(
                DataClass::D3NetworkBehavioralMetadata,
                RetentionClass::Days14,
                PrivacyClass::Sensitive,
                vec![
                    FieldProtection::Encrypt,
                    FieldProtection::RedactBeforeExport,
                ],
            ),
            Self::Asset | Self::Finding | Self::Evidence | Self::Risk | Self::GraphPath => {
                StoragePrivacyClass::security_metadata()
            }
            Self::Alert => StoragePrivacyClass::new(
                DataClass::D1SecurityMetadata,
                RetentionClass::Days180,
                PrivacyClass::Sensitive,
                vec![
                    FieldProtection::Encrypt,
                    FieldProtection::RedactBeforeExport,
                ],
            ),
            Self::Incident => StoragePrivacyClass::new(
                DataClass::D1SecurityMetadata,
                RetentionClass::Days365,
                PrivacyClass::Sensitive,
                vec![
                    FieldProtection::Encrypt,
                    FieldProtection::RedactBeforeExport,
                ],
            ),
            Self::GraphNode | Self::GraphEdge => StoragePrivacyClass::new(
                DataClass::D1SecurityMetadata,
                RetentionClass::Days90,
                PrivacyClass::Sensitive,
                vec![
                    FieldProtection::Encrypt,
                    FieldProtection::RedactBeforeExport,
                ],
            ),
            Self::ResponsePlan
            | Self::ResponseAction
            | Self::ResponseResult
            | Self::RollbackResult => StoragePrivacyClass::new(
                DataClass::D1SecurityMetadata,
                RetentionClass::Days365,
                PrivacyClass::Sensitive,
                vec![
                    FieldProtection::Encrypt,
                    FieldProtection::RedactBeforeExport,
                ],
            ),
            Self::Report => StoragePrivacyClass::new(
                DataClass::D1SecurityMetadata,
                RetentionClass::UserControlled,
                PrivacyClass::Sensitive,
                vec![
                    FieldProtection::Encrypt,
                    FieldProtection::RedactBeforeExport,
                ],
            ),
            Self::ExportHistory | Self::ExportPolicyViolation | Self::Audit => {
                StoragePrivacyClass::new(
                    DataClass::D0OperationalMetadata,
                    RetentionClass::Days365,
                    PrivacyClass::Internal,
                    vec![FieldProtection::None],
                )
            }
        }
    }
}

impl fmt::Display for StoreKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordState {
    New,
    #[default]
    Active,
    Updated,
    Suppressed,
    Promoted,
    Dismissed,
    Expired,
    Archived,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogicalRecord<TId> {
    pub id: TId,
    pub schema_version: SchemaVersion,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub record_time: Timestamp,
    pub entity_refs: Vec<EntityRef>,
    pub privacy_class: PrivacyClass,
    pub storage_privacy_class: StoragePrivacyClass,
    pub state: RecordState,
    pub metadata: Value,
}

impl<TId> LogicalRecord<TId> {
    pub fn metadata_only(
        id: TId,
        schema_version: SchemaVersion,
        storage_privacy_class: StoragePrivacyClass,
        metadata: Value,
    ) -> Self {
        let now = Timestamp::now();
        Self {
            id,
            schema_version,
            created_at: now.clone(),
            updated_at: now.clone(),
            record_time: now,
            entity_refs: Vec::new(),
            privacy_class: storage_privacy_class.privacy_class.clone(),
            storage_privacy_class,
            state: RecordState::Active,
            metadata,
        }
    }

    pub fn with_entity_refs(mut self, entity_refs: Vec<EntityRef>) -> Self {
        self.entity_refs = entity_refs;
        self
    }

    pub fn with_record_time(mut self, record_time: Timestamp) -> Self {
        self.record_time = record_time;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoreSnapshot<TId> {
    pub snapshot_id: StoreSnapshotId,
    pub store_kind: StoreKind,
    pub created_at: Timestamp,
    pub record_count: u64,
    pub storage_privacy_class: StoragePrivacyClass,
    pub records: Vec<LogicalRecord<TId>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionDeleteRequest {
    pub older_than: Timestamp,
    pub dry_run: bool,
    pub preserve_audit_records: bool,
}

impl RetentionDeleteRequest {
    pub fn dry_run(older_than: Timestamp) -> Self {
        Self {
            older_than,
            dry_run: true,
            preserve_audit_records: true,
        }
    }

    pub fn delete_expired(older_than: Timestamp) -> Self {
        Self {
            older_than,
            dry_run: false,
            preserve_audit_records: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionDeleteSummary {
    pub store_kind: StoreKind,
    pub matched_count: u64,
    pub deleted_count: u64,
    pub dry_run: bool,
    pub preserve_reason: Option<String>,
}

pub trait LogicalStore<TId> {
    fn append(&self, record: LogicalRecord<TId>) -> StorageResult<()>;
    fn get_by_id(&self, id: &TId) -> StorageResult<Option<LogicalRecord<TId>>>;
    fn query(&self, request: QueryRequest) -> StorageResult<QueryResponse<LogicalRecord<TId>>>;
    fn query_by_time_range(
        &self,
        time_range: TimeRange,
        page: PageRequest,
    ) -> StorageResult<QueryResponse<LogicalRecord<TId>>>;
    fn query_by_entity(
        &self,
        entity_ref: &EntityRef,
        page: PageRequest,
    ) -> StorageResult<QueryResponse<LogicalRecord<TId>>>;
    fn update_state(&self, id: &TId, state: RecordState) -> StorageResult<()>;
    fn delete_by_retention(
        &self,
        request: RetentionDeleteRequest,
    ) -> StorageResult<RetentionDeleteSummary>;
    fn create_snapshot(&self) -> StorageResult<StoreSnapshot<TId>>;
    fn restore_snapshot(&self, snapshot: &StoreSnapshot<TId>) -> StorageResult<()>;
}

macro_rules! define_marker_store {
    ($trait_name:ident, $id_type:ty) => {
        pub trait $trait_name: LogicalStore<$id_type> {}

        impl<'connection> $trait_name for SqliteLogicalStore<'connection, $id_type> {}
    };
}

define_marker_store!(EventStore, EventId);
define_marker_store!(PluginStore, PluginId);
define_marker_store!(ComponentStore, ComponentRecordId);
define_marker_store!(FlowStore, FlowId);
define_marker_store!(SessionStore, SessionId);
define_marker_store!(DnsStore, DnsObservationId);
define_marker_store!(TlsStore, TlsObservationId);
define_marker_store!(HttpMetadataStore, HttpMetadataId);
define_marker_store!(ProcessContextStore, sentinel_contracts::ProcessContextId);
define_marker_store!(IntelligenceCacheStore, IntelligenceCacheId);
define_marker_store!(AssetStore, AssetIdentityId);
define_marker_store!(FindingStore, FindingId);
define_marker_store!(EvidenceStore, EvidenceId);
define_marker_store!(RiskStore, RiskEventId);
define_marker_store!(AlertStore, AlertId);
define_marker_store!(IncidentStore, IncidentId);
define_marker_store!(ReportStore, ReportId);
define_marker_store!(ExportHistoryLogicalStore, ExportResultId);
define_marker_store!(ExportPolicyViolationStore, AuditId);
define_marker_store!(AuditStore, AuditId);
define_marker_store!(SettingsStore, SettingsRecordId);
define_marker_store!(MigrationStore, MigrationId);

pub trait GraphStore {
    type NodeStore: LogicalStore<GraphNodeId>;
    type EdgeStore: LogicalStore<GraphEdgeId>;
    type PathStore: LogicalStore<GraphPathId>;

    fn nodes(&self) -> &Self::NodeStore;
    fn edges(&self) -> &Self::EdgeStore;
    fn paths(&self) -> &Self::PathStore;
}

pub trait ResponseStore {
    type PlanStore: LogicalStore<ResponsePlanId>;
    type ActionStore: LogicalStore<ResponseActionId>;
    type ResultStore: LogicalStore<ResponseResultId>;
    type RollbackStore: LogicalStore<RollbackResultId>;

    fn plans(&self) -> &Self::PlanStore;
    fn actions(&self) -> &Self::ActionStore;
    fn results(&self) -> &Self::ResultStore;
    fn rollback_results(&self) -> &Self::RollbackStore;
}

pub struct SqliteLogicalStore<'connection, TId> {
    connection: &'connection Connection,
    store_kind: StoreKind,
    storage_privacy_class: StoragePrivacyClass,
    _id: PhantomData<TId>,
}

impl<'connection, TId> SqliteLogicalStore<'connection, TId> {
    pub fn new(
        connection: &'connection Connection,
        store_kind: StoreKind,
        storage_privacy_class: StoragePrivacyClass,
    ) -> Self {
        Self {
            connection,
            store_kind,
            storage_privacy_class,
            _id: PhantomData,
        }
    }

    pub fn store_kind(&self) -> &StoreKind {
        &self.store_kind
    }

    pub fn storage_privacy_class(&self) -> &StoragePrivacyClass {
        &self.storage_privacy_class
    }

    pub fn delete_by_id(&self, id: &TId) -> StorageResult<bool>
    where
        TId: fmt::Display,
    {
        let deleted = self.connection.execute(
            "DELETE FROM sg_logical_records WHERE store_kind = ?1 AND record_id = ?2",
            params![self.store_kind.as_str(), id.to_string()],
        )?;
        Ok(deleted > 0)
    }

    pub fn delete_all(&self) -> StorageResult<u64> {
        let deleted = self.connection.execute(
            "DELETE FROM sg_logical_records WHERE store_kind = ?1",
            params![self.store_kind.as_str()],
        )?;
        Ok(deleted as u64)
    }
}

impl<'connection, TId> LogicalStore<TId> for SqliteLogicalStore<'connection, TId>
where
    TId: Clone + fmt::Display + Serialize + DeserializeOwned,
{
    fn append(&self, record: LogicalRecord<TId>) -> StorageResult<()> {
        validate_logical_record(&self.store_kind, &record)?;
        insert_record(self.connection, &self.store_kind, &record)
    }

    fn get_by_id(&self, id: &TId) -> StorageResult<Option<LogicalRecord<TId>>> {
        let record_json = self
            .connection
            .query_row(
                "SELECT record_json FROM sg_logical_records WHERE store_kind = ?1 AND record_id = ?2",
                params![self.store_kind.as_str(), id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        match record_json {
            Some(value) => Ok(Some(serde_json::from_str::<LogicalRecord<TId>>(&value)?)),
            None => Ok(None),
        }
    }

    fn query(&self, request: QueryRequest) -> StorageResult<QueryResponse<LogicalRecord<TId>>> {
        let mut sql =
            String::from("SELECT record_json FROM sg_logical_records WHERE store_kind = ?1");
        let mut bind_values = vec![self.store_kind.as_str().to_string()];

        if let Some(time_range) = &request.time_range {
            push_time_range(&mut sql, &mut bind_values, time_range);
        }

        if let Some(cursor) = &request.page.cursor {
            let decoded = decode_cursor(cursor)?;
            sql.push_str(" AND (record_time < ? OR (record_time = ? AND record_id > ?))");
            bind_values.push(decoded.record_time.clone());
            bind_values.push(decoded.record_time);
            bind_values.push(decoded.record_id);
        }

        if let QueryScope::Entity(entity_id) = &request.scope {
            sql.push_str(" AND entity_refs_json LIKE ?");
            bind_values.push(format!("%{}%", entity_id));
        }

        for filter in &request.filters {
            let column = filter_column(&filter.field)?;
            let filter_value = filter_value_to_storage(filter.value.as_ref())?;
            match &filter.operator {
                sentinel_contracts::FilterOperator::Eq => {
                    sql.push_str(" AND ");
                    sql.push_str(column);
                    sql.push_str(" = ?");
                    bind_values.push(filter_value);
                }
                sentinel_contracts::FilterOperator::NotEq => {
                    sql.push_str(" AND ");
                    sql.push_str(column);
                    sql.push_str(" != ?");
                    bind_values.push(filter_value);
                }
                _ => {
                    return Err(StorageError::UnsupportedQuery(format!(
                        "filter operator {:?} is not supported by logical stores yet",
                        filter.operator
                    )));
                }
            }
        }

        sql.push_str(" ORDER BY record_time DESC, record_id ASC LIMIT ?");
        bind_values.push((request.page.limit + 1).to_string());

        let mut statement = self.connection.prepare(&sql)?;
        let record_jsons = statement
            .query_map(params_from_iter(bind_values.iter()), |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut records = Vec::with_capacity(record_jsons.len());
        for record_json in record_jsons {
            records.push(serde_json::from_str::<LogicalRecord<TId>>(&record_json)?);
        }

        let has_more = records.len() > request.page.limit as usize;
        if has_more {
            records.pop();
        }

        let next_cursor = if has_more {
            records
                .last()
                .map(|record| encode_cursor(&record.record_time, &record.id))
                .transpose()?
        } else {
            None
        };

        Ok(QueryResponse::new(PageResponse::from_request(
            records,
            &request.page,
            next_cursor,
            has_more,
        )))
    }

    fn query_by_time_range(
        &self,
        time_range: TimeRange,
        page: PageRequest,
    ) -> StorageResult<QueryResponse<LogicalRecord<TId>>> {
        self.query(
            QueryRequest::new(QueryScope::Global)
                .with_page(page)
                .with_time_range(time_range),
        )
    }

    fn query_by_entity(
        &self,
        entity_ref: &EntityRef,
        page: PageRequest,
    ) -> StorageResult<QueryResponse<LogicalRecord<TId>>> {
        self.query(
            QueryRequest::new(QueryScope::Entity(entity_ref.entity_id.clone())).with_page(page),
        )
    }

    fn update_state(&self, id: &TId, state: RecordState) -> StorageResult<()> {
        let mut record = self
            .get_by_id(id)?
            .ok_or_else(|| StorageError::InvalidRecord {
                store_kind: self.store_kind.to_string(),
                reason: format!("record {} does not exist", id),
            })?;
        record.state = state;
        record.updated_at = Timestamp::now();
        validate_logical_record(&self.store_kind, &record)?;
        self.connection.execute(
            r#"
            UPDATE sg_logical_records
            SET updated_at = ?3,
                state = ?4,
                record_json = ?5
            WHERE store_kind = ?1 AND record_id = ?2
            "#,
            params![
                self.store_kind.as_str(),
                id.to_string(),
                record.updated_at.to_string(),
                enum_to_storage(&record.state)?,
                serde_json::to_string(&record)?,
            ],
        )?;
        Ok(())
    }

    fn delete_by_retention(
        &self,
        request: RetentionDeleteRequest,
    ) -> StorageResult<RetentionDeleteSummary> {
        if request.preserve_audit_records
            && matches!(
                self.store_kind,
                StoreKind::Audit
                    | StoreKind::ExportHistory
                    | StoreKind::ExportPolicyViolation
                    | StoreKind::Migration
            )
        {
            return Ok(RetentionDeleteSummary {
                store_kind: self.store_kind.clone(),
                matched_count: 0,
                deleted_count: 0,
                dry_run: request.dry_run,
                preserve_reason: Some(
                    "audit, export history, and migration records are preserved by default".into(),
                ),
            });
        }

        let matched_count = self.connection.query_row(
            "SELECT COUNT(*) FROM sg_logical_records WHERE store_kind = ?1 AND record_time < ?2",
            params![self.store_kind.as_str(), request.older_than.to_string()],
            |row| row.get::<_, i64>(0),
        )? as u64;

        let deleted_count = if request.dry_run {
            0
        } else {
            self.connection.execute(
                "DELETE FROM sg_logical_records WHERE store_kind = ?1 AND record_time < ?2",
                params![self.store_kind.as_str(), request.older_than.to_string()],
            )? as u64
        };

        Ok(RetentionDeleteSummary {
            store_kind: self.store_kind.clone(),
            matched_count,
            deleted_count,
            dry_run: request.dry_run,
            preserve_reason: None,
        })
    }

    fn create_snapshot(&self) -> StorageResult<StoreSnapshot<TId>> {
        let page = PageRequest::first(sentinel_contracts::MAX_PAGE_LIMIT)
            .map_err(|error| StorageError::UnsupportedQuery(error.to_string()))?;
        let request = QueryRequest::new(QueryScope::Global).with_page(page);
        let response = self.query(request)?;
        Ok(StoreSnapshot {
            snapshot_id: StoreSnapshotId::new_v4(),
            store_kind: self.store_kind.clone(),
            created_at: Timestamp::now(),
            record_count: response.page.items.len() as u64,
            storage_privacy_class: self.storage_privacy_class.clone(),
            records: response.page.items,
        })
    }

    fn restore_snapshot(&self, snapshot: &StoreSnapshot<TId>) -> StorageResult<()> {
        if snapshot.store_kind != self.store_kind {
            return Err(StorageError::StoreKindMismatch {
                expected: self.store_kind.to_string(),
                actual: snapshot.store_kind.to_string(),
            });
        }

        self.connection.execute(
            "DELETE FROM sg_logical_records WHERE store_kind = ?1",
            params![self.store_kind.as_str()],
        )?;
        for record in &snapshot.records {
            validate_logical_record(&self.store_kind, record)?;
            insert_record(self.connection, &self.store_kind, record)?;
        }
        Ok(())
    }
}

pub struct SqliteGraphStore<'connection> {
    nodes: SqliteLogicalStore<'connection, GraphNodeId>,
    edges: SqliteLogicalStore<'connection, GraphEdgeId>,
    paths: SqliteLogicalStore<'connection, GraphPathId>,
}

impl<'connection> GraphStore for SqliteGraphStore<'connection> {
    type NodeStore = SqliteLogicalStore<'connection, GraphNodeId>;
    type EdgeStore = SqliteLogicalStore<'connection, GraphEdgeId>;
    type PathStore = SqliteLogicalStore<'connection, GraphPathId>;

    fn nodes(&self) -> &Self::NodeStore {
        &self.nodes
    }

    fn edges(&self) -> &Self::EdgeStore {
        &self.edges
    }

    fn paths(&self) -> &Self::PathStore {
        &self.paths
    }
}

pub struct SqliteResponseStore<'connection> {
    plans: SqliteLogicalStore<'connection, ResponsePlanId>,
    actions: SqliteLogicalStore<'connection, ResponseActionId>,
    results: SqliteLogicalStore<'connection, ResponseResultId>,
    rollback_results: SqliteLogicalStore<'connection, RollbackResultId>,
}

impl<'connection> ResponseStore for SqliteResponseStore<'connection> {
    type PlanStore = SqliteLogicalStore<'connection, ResponsePlanId>;
    type ActionStore = SqliteLogicalStore<'connection, ResponseActionId>;
    type ResultStore = SqliteLogicalStore<'connection, ResponseResultId>;
    type RollbackStore = SqliteLogicalStore<'connection, RollbackResultId>;

    fn plans(&self) -> &Self::PlanStore {
        &self.plans
    }

    fn actions(&self) -> &Self::ActionStore {
        &self.actions
    }

    fn results(&self) -> &Self::ResultStore {
        &self.results
    }

    fn rollback_results(&self) -> &Self::RollbackStore {
        &self.rollback_results
    }
}

pub struct SqliteStoreFactory<'connection> {
    connection: &'connection Connection,
}

impl<'connection> SqliteStoreFactory<'connection> {
    pub fn new(connection: &'connection Connection) -> Self {
        Self { connection }
    }

    pub fn event_store(&self) -> SqliteLogicalStore<'connection, EventId> {
        self.store(StoreKind::Event)
    }

    pub fn plugin_store(&self) -> SqliteLogicalStore<'connection, PluginId> {
        self.store(StoreKind::Plugin)
    }

    pub fn component_store(&self) -> SqliteLogicalStore<'connection, ComponentRecordId> {
        self.store(StoreKind::Component)
    }

    pub fn flow_store(&self) -> SqliteLogicalStore<'connection, FlowId> {
        self.store(StoreKind::Flow)
    }

    pub fn session_store(&self) -> SqliteLogicalStore<'connection, SessionId> {
        self.store(StoreKind::Session)
    }

    pub fn dns_store(&self) -> SqliteLogicalStore<'connection, DnsObservationId> {
        self.store(StoreKind::Dns)
    }

    pub fn tls_store(&self) -> SqliteLogicalStore<'connection, TlsObservationId> {
        self.store(StoreKind::Tls)
    }

    pub fn http_metadata_store(&self) -> SqliteLogicalStore<'connection, HttpMetadataId> {
        self.store(StoreKind::HttpMetadata)
    }

    pub fn process_context_store(
        &self,
    ) -> SqliteLogicalStore<'connection, sentinel_contracts::ProcessContextId> {
        self.store(StoreKind::ProcessContext)
    }

    pub fn intelligence_cache_store(&self) -> SqliteLogicalStore<'connection, IntelligenceCacheId> {
        self.store(StoreKind::IntelligenceCache)
    }

    pub fn asset_store(&self) -> SqliteLogicalStore<'connection, AssetIdentityId> {
        self.store(StoreKind::Asset)
    }

    pub fn finding_store(&self) -> SqliteLogicalStore<'connection, FindingId> {
        self.store(StoreKind::Finding)
    }

    pub fn evidence_store(&self) -> SqliteLogicalStore<'connection, EvidenceId> {
        self.store(StoreKind::Evidence)
    }

    pub fn risk_store(&self) -> SqliteLogicalStore<'connection, RiskEventId> {
        self.store(StoreKind::Risk)
    }

    pub fn alert_store(&self) -> SqliteLogicalStore<'connection, AlertId> {
        self.store(StoreKind::Alert)
    }

    pub fn incident_store(&self) -> SqliteLogicalStore<'connection, IncidentId> {
        self.store(StoreKind::Incident)
    }

    pub fn graph_store(&self) -> SqliteGraphStore<'connection> {
        SqliteGraphStore {
            nodes: self.store(StoreKind::GraphNode),
            edges: self.store(StoreKind::GraphEdge),
            paths: self.store(StoreKind::GraphPath),
        }
    }

    pub fn response_store(&self) -> SqliteResponseStore<'connection> {
        SqliteResponseStore {
            plans: self.store(StoreKind::ResponsePlan),
            actions: self.store(StoreKind::ResponseAction),
            results: self.store(StoreKind::ResponseResult),
            rollback_results: self.store(StoreKind::RollbackResult),
        }
    }

    pub fn report_store(&self) -> SqliteLogicalStore<'connection, ReportId> {
        self.store(StoreKind::Report)
    }

    pub fn export_history_store(&self) -> SqliteLogicalStore<'connection, ExportResultId> {
        self.store(StoreKind::ExportHistory)
    }

    pub fn export_policy_violation_store(&self) -> SqliteLogicalStore<'connection, AuditId> {
        self.store(StoreKind::ExportPolicyViolation)
    }

    pub fn audit_store(&self) -> SqliteLogicalStore<'connection, AuditId> {
        self.store(StoreKind::Audit)
    }

    pub fn settings_store(&self) -> SqliteLogicalStore<'connection, SettingsRecordId> {
        self.store(StoreKind::Settings)
    }

    pub fn migration_store(&self) -> SqliteLogicalStore<'connection, MigrationId> {
        self.store(StoreKind::Migration)
    }

    fn store<TId>(&self, store_kind: StoreKind) -> SqliteLogicalStore<'connection, TId> {
        let storage_privacy_class = store_kind.default_storage_privacy_class();
        SqliteLogicalStore::new(self.connection, store_kind, storage_privacy_class)
    }
}

pub fn logical_store_migration() -> StorageResult<Migration> {
    Migration::new(
        "090_logical_store_records",
        "create logical store record facades",
        SchemaVersion::new(0, 2, 0),
        vec![MigrationStatement::new(
            "create_logical_store_records",
            r#"
            CREATE TABLE IF NOT EXISTS sg_logical_records (
                store_kind TEXT NOT NULL,
                record_id TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                record_time TEXT NOT NULL,
                privacy_class TEXT NOT NULL,
                retention_class TEXT NOT NULL,
                data_class TEXT NOT NULL,
                state TEXT NOT NULL,
                entity_refs_json TEXT NOT NULL,
                record_json TEXT NOT NULL,
                PRIMARY KEY (store_kind, record_id)
            );

            CREATE INDEX IF NOT EXISTS idx_sg_logical_records_time
                ON sg_logical_records (store_kind, record_time DESC, record_id ASC);

            CREATE INDEX IF NOT EXISTS idx_sg_logical_records_state
                ON sg_logical_records (store_kind, state);

            CREATE INDEX IF NOT EXISTS idx_sg_logical_records_privacy
                ON sg_logical_records (store_kind, privacy_class, retention_class, data_class);
            "#,
        )],
        StoragePrivacyClass::operational_metadata(),
    )?
    .with_row_count_verification(RowCountVerificationHook::new("sg_logical_records")?)
}

fn insert_record<TId>(
    connection: &Connection,
    store_kind: &StoreKind,
    record: &LogicalRecord<TId>,
) -> StorageResult<()>
where
    TId: fmt::Display + Serialize,
{
    connection.execute(
        r#"
        INSERT INTO sg_logical_records (
            store_kind,
            record_id,
            schema_version,
            created_at,
            updated_at,
            record_time,
            privacy_class,
            retention_class,
            data_class,
            state,
            entity_refs_json,
            record_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
        params![
            store_kind.as_str(),
            record.id.to_string(),
            record.schema_version.to_string(),
            record.created_at.to_string(),
            record.updated_at.to_string(),
            record.record_time.to_string(),
            enum_to_storage(&record.privacy_class)?,
            enum_to_storage(&record.storage_privacy_class.retention_class)?,
            enum_to_storage(&record.storage_privacy_class.data_class)?,
            enum_to_storage(&record.state)?,
            serde_json::to_string(&record.entity_refs)?,
            serde_json::to_string(record)?,
        ],
    )?;
    Ok(())
}

fn validate_logical_record<TId>(
    store_kind: &StoreKind,
    record: &LogicalRecord<TId>,
) -> StorageResult<()> {
    if !record.storage_privacy_class.normal_mode_persistence_allowed {
        return Err(StorageError::InvalidRecord {
            store_kind: store_kind.to_string(),
            reason:
                "normal-mode logical stores cannot persist forensic-only or raw content classes"
                    .to_string(),
        });
    }

    validate_metadata_value(store_kind, "$", &record.metadata)
}

fn validate_metadata_value(store_kind: &StoreKind, path: &str, value: &Value) -> StorageResult<()> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                validate_metadata_key(store_kind, path, key, nested)?;
                let nested_path = format!("{path}.{key}");
                validate_metadata_value(store_kind, &nested_path, nested)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                validate_metadata_value(store_kind, &format!("{path}[{index}]"), nested)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_metadata_key(
    store_kind: &StoreKind,
    path: &str,
    key: &str,
    value: &Value,
) -> StorageResult<()> {
    let normalized = key.to_ascii_lowercase();
    let blocked = FORBIDDEN_METADATA_KEYS
        .iter()
        .any(|forbidden| normalized == *forbidden || normalized.contains(&format!("_{forbidden}")));

    if blocked && value != &Value::Bool(false) {
        Err(StorageError::InvalidRecord {
            store_kind: store_kind.to_string(),
            reason: format!("metadata key `{path}.{key}` is not allowed in normal-mode storage"),
        })
    } else {
        Ok(())
    }
}

fn push_time_range(sql: &mut String, bind_values: &mut Vec<String>, time_range: &TimeRange) {
    if let Some(start) = &time_range.start {
        sql.push_str(" AND record_time >= ?");
        bind_values.push(start.to_string());
    }

    if let Some(end) = &time_range.end {
        sql.push_str(" AND record_time <= ?");
        bind_values.push(end.to_string());
    }
}

fn filter_column(field: &str) -> StorageResult<&'static str> {
    match field {
        "state" => Ok("state"),
        "privacy_class" => Ok("privacy_class"),
        "data_class" => Ok("data_class"),
        "retention_class" => Ok("retention_class"),
        other => Err(StorageError::UnsupportedQuery(format!(
            "field `{other}` is not indexed by logical stores"
        ))),
    }
}

fn filter_value_to_storage(
    value: Option<&sentinel_contracts::FilterValue>,
) -> StorageResult<String> {
    match value {
        Some(sentinel_contracts::FilterValue::String(value)) => Ok(value.clone()),
        Some(sentinel_contracts::FilterValue::Bool(value)) => Ok(value.to_string()),
        Some(sentinel_contracts::FilterValue::Number(value)) => Ok(value.to_string()),
        Some(other) => Err(StorageError::UnsupportedQuery(format!(
            "filter value {:?} is not supported by logical stores yet",
            other
        ))),
        None => Err(StorageError::UnsupportedQuery(
            "filter value is required for logical store filters".to_string(),
        )),
    }
}

struct DecodedCursor {
    record_time: String,
    record_id: String,
}

fn encode_cursor<TId: fmt::Display>(
    record_time: &Timestamp,
    record_id: &TId,
) -> StorageResult<Cursor> {
    Cursor::new(format!(
        "{LOGICAL_STORE_CURSOR_PREFIX}|{}|{}",
        record_time, record_id
    ))
    .map_err(|error| StorageError::InvalidCursor(error.to_string()))
}

fn decode_cursor(cursor: &Cursor) -> StorageResult<DecodedCursor> {
    let mut parts = cursor.as_str().splitn(3, '|');
    let prefix = parts.next();
    let record_time = parts.next();
    let record_id = parts.next();

    match (prefix, record_time, record_id) {
        (Some(LOGICAL_STORE_CURSOR_PREFIX), Some(record_time), Some(record_id)) => {
            Ok(DecodedCursor {
                record_time: record_time.to_string(),
                record_id: record_id.to_string(),
            })
        }
        _ => Err(StorageError::InvalidCursor(
            "cursor was not produced by the logical store facade".to_string(),
        )),
    }
}

fn enum_to_storage<T: Serialize>(value: &T) -> StorageResult<String> {
    match serde_json::to_value(value)? {
        Value::String(value) => Ok(value),
        other => Ok(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{InMemoryMigrationAuditSink, MigrationRunner, SchemaMetadata};
    use sentinel_contracts::{FilterOperator, FilterSpec, FilterValue};
    use serde_json::json;

    #[test]
    fn logical_store_appends_and_queries_with_cursor_pagination(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let factory = SqliteStoreFactory::new(&connection);
        let flow_store = factory.flow_store();

        for sequence in 0..3 {
            let record = LogicalRecord::metadata_only(
                FlowId::new_v4(),
                SchemaVersion::new(1, 0, 0),
                StoreKind::Flow.default_storage_privacy_class(),
                json!({ "sequence": sequence, "bytes_in": 100 }),
            );
            flow_store.append(record)?;
        }

        let first_page = flow_store
            .query(QueryRequest::new(QueryScope::Global).with_page(PageRequest::first(2)?))?;

        assert_eq!(first_page.page.items.len(), 2);
        assert!(first_page.page.has_more);
        assert!(first_page.page.next_cursor.is_some());
        assert!(first_page
            .page
            .next_cursor
            .unwrap()
            .as_str()
            .starts_with(LOGICAL_STORE_CURSOR_PREFIX));

        Ok(())
    }

    #[test]
    fn logical_store_rejects_raw_payload_metadata_keys() -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let factory = SqliteStoreFactory::new(&connection);
        let event_store = factory.event_store();
        let record = LogicalRecord::metadata_only(
            EventId::new_v4(),
            SchemaVersion::new(1, 0, 0),
            StoreKind::Event.default_storage_privacy_class(),
            json!({ "raw_payload": "not allowed" }),
        );

        assert!(event_store.append(record).is_err());
        Ok(())
    }

    #[test]
    fn logical_store_rejects_sensitive_metadata_keys_without_echoing_values(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let factory = SqliteStoreFactory::new(&connection);
        let event_store = factory.event_store();
        let record = LogicalRecord::metadata_only(
            EventId::new_v4(),
            SchemaVersion::new(1, 0, 0),
            StoreKind::Event.default_storage_privacy_class(),
            json!({
                "request": {
                    "api_key": "sk-local-raw-secret-token",
                    "command_line": "tool.exe --token sk-local-raw-secret-token"
                }
            }),
        );

        let error = event_store
            .append(record)
            .expect_err("sensitive metadata keys should be rejected");
        let error_text = error.to_string();

        assert!(error_text.contains("$.request.api_key"));
        assert!(!error_text.contains("sk-local-raw-secret-token"));
        Ok(())
    }

    #[test]
    fn logical_store_rejects_ephemeral_session_only_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let factory = SqliteStoreFactory::new(&connection);
        let flow_store = factory.flow_store();
        let record = LogicalRecord::metadata_only(
            FlowId::new_v4(),
            SchemaVersion::new(1, 0, 0),
            StoragePrivacyClass::ephemeral_session_only(),
            json!({ "summary_redacted": "transient decode value" }),
        );

        assert!(flow_store.append(record).is_err());
        Ok(())
    }

    #[test]
    fn logical_store_updates_state_and_uses_shared_filter_contracts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let factory = SqliteStoreFactory::new(&connection);
        let finding_store = factory.finding_store();
        let finding_id = FindingId::new_v4();
        let record = LogicalRecord::metadata_only(
            finding_id.clone(),
            SchemaVersion::new(1, 0, 0),
            StoreKind::Finding.default_storage_privacy_class(),
            json!({ "summary_redacted": "rare destination" }),
        );

        finding_store.append(record)?;
        finding_store.update_state(&finding_id, RecordState::Suppressed)?;
        let response = finding_store.query(
            QueryRequest::new(QueryScope::Global)
                .with_page(PageRequest::first(10)?)
                .with_filters(vec![FilterSpec::new(
                    "state",
                    FilterOperator::Eq,
                    Some(FilterValue::String("suppressed".to_string())),
                )?]),
        )?;

        assert_eq!(response.page.items.len(), 1);
        assert_eq!(response.page.items[0].state, RecordState::Suppressed);
        Ok(())
    }

    #[test]
    fn logical_store_snapshot_restore_keeps_store_boundary(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let factory = SqliteStoreFactory::new(&connection);
        let report_store = factory.report_store();
        let record = LogicalRecord::metadata_only(
            ReportId::new_v4(),
            SchemaVersion::new(1, 0, 0),
            StoreKind::Report.default_storage_privacy_class(),
            json!({ "summary_redacted": "incident report" }),
        );

        report_store.append(record)?;
        let snapshot = report_store.create_snapshot()?;
        report_store.delete_by_retention(RetentionDeleteRequest {
            older_than: Timestamp::now(),
            dry_run: false,
            preserve_audit_records: true,
        })?;
        report_store.restore_snapshot(&snapshot)?;

        let restored = report_store.create_snapshot()?;
        assert_eq!(restored.record_count, 1);
        Ok(())
    }

    #[test]
    fn logical_store_factory_exposes_graph_and_response_facades(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let factory = SqliteStoreFactory::new(&connection);
        let plugin_store = factory.plugin_store();
        let component_store = factory.component_store();
        let graph_store = factory.graph_store();
        let response_store = factory.response_store();

        assert_eq!(plugin_store.store_kind(), &StoreKind::Plugin);
        assert_eq!(component_store.store_kind(), &StoreKind::Component);
        assert_eq!(graph_store.nodes().store_kind(), &StoreKind::GraphNode);
        assert_eq!(graph_store.edges().store_kind(), &StoreKind::GraphEdge);
        assert_eq!(graph_store.paths().store_kind(), &StoreKind::GraphPath);
        assert_eq!(
            response_store.plans().store_kind(),
            &StoreKind::ResponsePlan
        );
        assert_eq!(
            response_store.actions().store_kind(),
            &StoreKind::ResponseAction
        );
        assert_eq!(
            response_store.results().store_kind(),
            &StoreKind::ResponseResult
        );
        assert_eq!(
            factory.export_history_store().store_kind(),
            &StoreKind::ExportHistory
        );
        assert_eq!(
            factory.export_policy_violation_store().store_kind(),
            &StoreKind::ExportPolicyViolation
        );
        Ok(())
    }

    #[test]
    fn retention_delete_preserves_audit_by_default() -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let factory = SqliteStoreFactory::new(&connection);
        let audit_store = factory.audit_store();
        let export_history_store = factory.export_history_store();

        let summary = audit_store
            .delete_by_retention(RetentionDeleteRequest::delete_expired(Timestamp::now()))?;
        let export_history_summary = export_history_store
            .delete_by_retention(RetentionDeleteRequest::delete_expired(Timestamp::now()))?;

        assert_eq!(summary.deleted_count, 0);
        assert!(summary.preserve_reason.is_some());
        assert_eq!(export_history_summary.deleted_count, 0);
        assert!(export_history_summary.preserve_reason.is_some());
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
}
