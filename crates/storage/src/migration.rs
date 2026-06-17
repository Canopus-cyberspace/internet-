use crate::error::{StorageError, StorageResult};
use crate::privacy::{DataClass, RetentionClass, StoragePrivacyClass};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Transaction};
use sentinel_contracts::{AuditId, PrivacyClass, SchemaVersion, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use uuid::Uuid;

const INTERNAL_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS sg_schema_metadata (
    schema_version TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    privacy_class TEXT NOT NULL,
    retention_class TEXT NOT NULL,
    data_class TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sg_migrations (
    migration_id TEXT PRIMARY KEY,
    migration_key TEXT NOT NULL UNIQUE,
    schema_version TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    applied_at TEXT,
    privacy_class TEXT NOT NULL,
    retention_class TEXT NOT NULL,
    data_class TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sg_migration_audit (
    audit_id TEXT PRIMARY KEY,
    migration_id TEXT NOT NULL,
    migration_key TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    dry_run INTEGER NOT NULL,
    statement_count INTEGER NOT NULL,
    row_count_verifications TEXT NOT NULL,
    error_message TEXT
);
"#;

const FORBIDDEN_STORAGE_TOKENS: &[&str] = &[
    "raw_packet",
    "raw_packets",
    "raw_payload",
    "payload_blob",
    "http_body",
    "request_body",
    "response_body",
    "cookie",
    "authorization",
    "api_key",
    "password",
    "credential",
    "private_key",
    "session_token",
    "access_token",
    "refresh_token",
    "token_value",
];
const MAX_MIGRATION_STATEMENT_COUNT: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MigrationId(Uuid);

impl MigrationId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse_str(value: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(value).map(Self)
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Display for MigrationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaMetadata {
    pub schema_version: SchemaVersion,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub privacy_class: PrivacyClass,
    pub retention_class: RetentionClass,
    pub data_class: DataClass,
}

impl SchemaMetadata {
    pub fn new(schema_version: SchemaVersion, storage_privacy_class: &StoragePrivacyClass) -> Self {
        let now = Timestamp::now();
        Self {
            schema_version,
            created_at: now.clone(),
            updated_at: now,
            privacy_class: storage_privacy_class.privacy_class.clone(),
            retention_class: storage_privacy_class.retention_class.clone(),
            data_class: storage_privacy_class.data_class.clone(),
        }
    }

    pub fn storage_foundation() -> Self {
        Self::new(
            SchemaVersion::new(0, 1, 0),
            &StoragePrivacyClass::operational_metadata(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    Pending,
    Applied,
    Failed,
    Skipped,
    DryRun,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationStatement {
    pub label: String,
    pub sql: String,
}

impl MigrationStatement {
    pub fn new(label: impl Into<String>, sql: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            sql: sql.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowCountVerificationHook {
    pub table_name: String,
}

impl RowCountVerificationHook {
    pub fn new(table_name: impl Into<String>) -> StorageResult<Self> {
        let table_name = table_name.into();
        validate_sql_identifier(&table_name)?;
        Ok(Self { table_name })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowCountVerificationResult {
    pub table_name: String,
    pub before_count: Option<u64>,
    pub after_count: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FtsRebuildHook {
    pub table_name: String,
    pub rebuild_sql: String,
}

impl FtsRebuildHook {
    pub fn new(
        table_name: impl Into<String>,
        rebuild_sql: impl Into<String>,
    ) -> StorageResult<Self> {
        let table_name = table_name.into();
        let rebuild_sql = rebuild_sql.into();
        validate_sql_identifier(&table_name)?;
        validate_sql_privacy(&table_name, &rebuild_sql)?;

        Ok(Self {
            table_name,
            rebuild_sql,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Migration {
    pub migration_id: MigrationId,
    pub migration_key: String,
    pub name: String,
    pub schema_version: SchemaVersion,
    pub statements: Vec<MigrationStatement>,
    pub storage_privacy_class: StoragePrivacyClass,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub row_count_verifications: Vec<RowCountVerificationHook>,
    pub fts_rebuild_hooks: Vec<FtsRebuildHook>,
}

impl Migration {
    pub fn new(
        migration_key: impl Into<String>,
        name: impl Into<String>,
        schema_version: SchemaVersion,
        statements: Vec<MigrationStatement>,
        storage_privacy_class: StoragePrivacyClass,
    ) -> StorageResult<Self> {
        let now = Timestamp::now();
        let migration = Self {
            migration_id: MigrationId::new_v4(),
            migration_key: migration_key.into(),
            name: name.into(),
            schema_version,
            statements,
            storage_privacy_class,
            created_at: now.clone(),
            updated_at: now,
            row_count_verifications: Vec::new(),
            fts_rebuild_hooks: Vec::new(),
        };
        migration.validate()?;
        Ok(migration)
    }

    pub fn with_row_count_verification(
        mut self,
        hook: RowCountVerificationHook,
    ) -> StorageResult<Self> {
        validate_sql_identifier(&hook.table_name)?;
        self.row_count_verifications.push(hook);
        Ok(self)
    }

    pub fn with_fts_rebuild_hook(mut self, hook: FtsRebuildHook) -> StorageResult<Self> {
        validate_sql_privacy(&hook.table_name, &hook.rebuild_sql)?;
        self.fts_rebuild_hooks.push(hook);
        Ok(self)
    }

    pub fn validate(&self) -> StorageResult<()> {
        require_non_empty("migration_key", &self.migration_key)?;
        require_non_empty("name", &self.name)?;
        if self.statements.is_empty() {
            return Err(StorageError::InvalidMigration {
                migration_key: self.migration_key.clone(),
                reason: "migration must contain at least one SQL statement".to_string(),
            });
        }
        let statement_count = self
            .statements
            .len()
            .saturating_add(self.fts_rebuild_hooks.len());
        if statement_count > MAX_MIGRATION_STATEMENT_COUNT {
            return Err(StorageError::InvalidMigration {
                migration_key: self.migration_key.clone(),
                reason: "migration statement count exceeds bounded limit".to_string(),
            });
        }
        if !self.storage_privacy_class.normal_mode_persistence_allowed {
            return Err(StorageError::InvalidMigration {
                migration_key: self.migration_key.clone(),
                reason:
                    "normal-mode migrations cannot persist raw content or forensic-only classes"
                        .to_string(),
            });
        }
        for statement in &self.statements {
            require_non_empty("statement.label", &statement.label)?;
            require_non_empty("statement.sql", &statement.sql)?;
            validate_sql_privacy(&self.migration_key, &statement.sql)?;
        }
        for hook in &self.row_count_verifications {
            validate_sql_identifier(&hook.table_name)?;
        }
        for hook in &self.fts_rebuild_hooks {
            validate_sql_identifier(&hook.table_name)?;
            validate_sql_privacy(&hook.table_name, &hook.rebuild_sql)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationAuditRecord {
    pub audit_id: AuditId,
    pub migration_id: MigrationId,
    pub migration_key: String,
    pub schema_version: SchemaVersion,
    pub status: MigrationStatus,
    pub started_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    pub dry_run: bool,
    pub statement_count: u32,
    pub row_count_verifications: Vec<RowCountVerificationResult>,
    pub error_message: Option<String>,
}

impl MigrationAuditRecord {
    fn skipped(migration: &Migration) -> Self {
        let now = Timestamp::now();
        Self {
            audit_id: AuditId::new_v4(),
            migration_id: migration.migration_id.clone(),
            migration_key: migration.migration_key.clone(),
            schema_version: migration.schema_version.clone(),
            status: MigrationStatus::Skipped,
            started_at: now.clone(),
            finished_at: Some(now),
            dry_run: false,
            statement_count: 0,
            row_count_verifications: Vec::new(),
            error_message: None,
        }
    }

    fn failed(migration: &Migration, reason: String) -> Self {
        let now = Timestamp::now();
        Self {
            audit_id: AuditId::new_v4(),
            migration_id: migration.migration_id.clone(),
            migration_key: migration.migration_key.clone(),
            schema_version: migration.schema_version.clone(),
            status: MigrationStatus::Failed,
            started_at: now.clone(),
            finished_at: Some(now),
            dry_run: false,
            statement_count: migration.statements.len() as u32,
            row_count_verifications: Vec::new(),
            error_message: Some(reason),
        }
    }
}

pub trait MigrationAuditSink {
    fn record(&mut self, record: &MigrationAuditRecord) -> StorageResult<()>;
}

#[derive(Default)]
pub struct InMemoryMigrationAuditSink {
    records: Vec<MigrationAuditRecord>,
}

impl InMemoryMigrationAuditSink {
    pub fn records(&self) -> &[MigrationAuditRecord] {
        &self.records
    }
}

impl MigrationAuditSink for InMemoryMigrationAuditSink {
    fn record(&mut self, record: &MigrationAuditRecord) -> StorageResult<()> {
        self.records.push(record.clone());
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MigrationRunReport {
    pub applied: u32,
    pub skipped: u32,
    pub dry_run: u32,
    pub failed: u32,
    pub audit_records: Vec<MigrationAuditRecord>,
}

pub struct MigrationRunner<'connection> {
    connection: &'connection mut Connection,
}

impl<'connection> MigrationRunner<'connection> {
    pub fn new(connection: &'connection mut Connection) -> Self {
        Self { connection }
    }

    pub fn initialize(&mut self, metadata: &SchemaMetadata) -> StorageResult<()> {
        self.configure_sqlite()?;
        self.connection.execute_batch(INTERNAL_SCHEMA_SQL)?;
        upsert_schema_metadata(self.connection, metadata)?;
        Ok(())
    }

    pub fn apply_all(
        &mut self,
        migrations: &[Migration],
        audit_sink: &mut dyn MigrationAuditSink,
    ) -> StorageResult<MigrationRunReport> {
        self.run(migrations, audit_sink, false)
    }

    pub fn dry_run(
        &mut self,
        migrations: &[Migration],
        audit_sink: &mut dyn MigrationAuditSink,
    ) -> StorageResult<MigrationRunReport> {
        self.run(migrations, audit_sink, true)
    }

    fn configure_sqlite(&mut self) -> StorageResult<()> {
        self.connection.pragma_update(None, "journal_mode", "WAL")?;
        self.connection.pragma_update(None, "busy_timeout", 5000)?;
        self.connection.pragma_update(None, "foreign_keys", "ON")?;
        self.connection.pragma_update(None, "secure_delete", "ON")?;
        self.connection
            .pragma_update(None, "synchronous", "NORMAL")?;
        Ok(())
    }

    fn run(
        &mut self,
        migrations: &[Migration],
        audit_sink: &mut dyn MigrationAuditSink,
        dry_run: bool,
    ) -> StorageResult<MigrationRunReport> {
        let mut report = MigrationRunReport::default();

        for migration in migrations {
            if let Err(error) = migration.validate() {
                let record = MigrationAuditRecord::failed(migration, error.to_string());
                insert_audit_record(self.connection, &record)?;
                audit_sink.record(&record)?;
                report.failed += 1;
                report.audit_records.push(record);
                return Err(error);
            }

            if self.is_applied(&migration.migration_key)? {
                let record = MigrationAuditRecord::skipped(migration);
                insert_audit_record(self.connection, &record)?;
                audit_sink.record(&record)?;
                report.skipped += 1;
                report.audit_records.push(record);
                continue;
            }

            match apply_one(self.connection, migration, dry_run) {
                Ok(record) => {
                    audit_sink.record(&record)?;
                    match record.status {
                        MigrationStatus::Applied => report.applied += 1,
                        MigrationStatus::DryRun => report.dry_run += 1,
                        MigrationStatus::Skipped => report.skipped += 1,
                        MigrationStatus::Failed => report.failed += 1,
                        MigrationStatus::Pending => {}
                    }
                    report.audit_records.push(record);
                }
                Err(error) => {
                    let record = MigrationAuditRecord::failed(migration, error.to_string());
                    insert_audit_record(self.connection, &record)?;
                    audit_sink.record(&record)?;
                    report.failed += 1;
                    report.audit_records.push(record);
                    return Err(StorageError::MigrationFailed {
                        migration_key: migration.migration_key.clone(),
                        reason: error.to_string(),
                    });
                }
            }
        }

        Ok(report)
    }

    fn is_applied(&self, migration_key: &str) -> StorageResult<bool> {
        let status = self
            .connection
            .query_row(
                "SELECT status FROM sg_migrations WHERE migration_key = ?1",
                params![migration_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        Ok(matches!(status.as_deref(), Some("applied")))
    }
}

fn apply_one(
    connection: &mut Connection,
    migration: &Migration,
    dry_run: bool,
) -> StorageResult<MigrationAuditRecord> {
    let started_at = Timestamp::now();
    let tx = connection.transaction()?;
    let before_counts = collect_row_counts(&tx, &migration.row_count_verifications)?;

    for statement in &migration.statements {
        tx.execute_batch(&statement.sql)?;
    }

    for hook in &migration.fts_rebuild_hooks {
        tx.execute_batch(&hook.rebuild_sql)?;
    }

    let after_counts = collect_row_counts(&tx, &migration.row_count_verifications)?;
    let row_count_verifications = merge_row_count_results(before_counts, after_counts);
    let status = if dry_run {
        MigrationStatus::DryRun
    } else {
        MigrationStatus::Applied
    };
    let record = MigrationAuditRecord {
        audit_id: AuditId::new_v4(),
        migration_id: migration.migration_id.clone(),
        migration_key: migration.migration_key.clone(),
        schema_version: migration.schema_version.clone(),
        status,
        started_at,
        finished_at: Some(Timestamp::now()),
        dry_run,
        statement_count: (migration.statements.len() + migration.fts_rebuild_hooks.len()) as u32,
        row_count_verifications,
        error_message: None,
    };

    if dry_run {
        tx.rollback()?;
    } else {
        insert_migration_record(&tx, migration)?;
        insert_audit_record_tx(&tx, &record)?;
        tx.commit()?;
    }

    Ok(record)
}

fn upsert_schema_metadata(connection: &Connection, metadata: &SchemaMetadata) -> StorageResult<()> {
    connection.execute(
        r#"
        INSERT INTO sg_schema_metadata (
            schema_version,
            created_at,
            updated_at,
            privacy_class,
            retention_class,
            data_class
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(schema_version) DO UPDATE SET
            updated_at = excluded.updated_at,
            privacy_class = excluded.privacy_class,
            retention_class = excluded.retention_class,
            data_class = excluded.data_class
        "#,
        params![
            metadata.schema_version.to_string(),
            metadata.created_at.to_string(),
            metadata.updated_at.to_string(),
            enum_to_storage(&metadata.privacy_class)?,
            enum_to_storage(&metadata.retention_class)?,
            enum_to_storage(&metadata.data_class)?,
        ],
    )?;
    Ok(())
}

fn insert_migration_record(tx: &Transaction<'_>, migration: &Migration) -> StorageResult<()> {
    let applied_at = Timestamp::now().to_string();
    tx.execute(
        r#"
        INSERT INTO sg_migrations (
            migration_id,
            migration_key,
            schema_version,
            name,
            status,
            created_at,
            updated_at,
            applied_at,
            privacy_class,
            retention_class,
            data_class
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
        params![
            migration.migration_id.to_string(),
            &migration.migration_key,
            migration.schema_version.to_string(),
            &migration.name,
            "applied",
            migration.created_at.to_string(),
            migration.updated_at.to_string(),
            applied_at,
            enum_to_storage(&migration.storage_privacy_class.privacy_class)?,
            enum_to_storage(&migration.storage_privacy_class.retention_class)?,
            enum_to_storage(&migration.storage_privacy_class.data_class)?,
        ],
    )?;
    Ok(())
}

fn insert_audit_record(
    connection: &Connection,
    record: &MigrationAuditRecord,
) -> StorageResult<()> {
    let values = audit_insert_params(record)?;
    connection.execute(audit_insert_sql(), params_from_iter(values.iter()))?;
    Ok(())
}

fn insert_audit_record_tx(
    tx: &Transaction<'_>,
    record: &MigrationAuditRecord,
) -> StorageResult<()> {
    let values = audit_insert_params(record)?;
    tx.execute(audit_insert_sql(), params_from_iter(values.iter()))?;
    Ok(())
}

fn audit_insert_sql() -> &'static str {
    r#"
    INSERT INTO sg_migration_audit (
        audit_id,
        migration_id,
        migration_key,
        schema_version,
        status,
        started_at,
        finished_at,
        dry_run,
        statement_count,
        row_count_verifications,
        error_message
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
    "#
}

fn audit_insert_params(record: &MigrationAuditRecord) -> StorageResult<Vec<String>> {
    Ok(vec![
        record.audit_id.to_string(),
        record.migration_id.to_string(),
        record.migration_key.clone(),
        record.schema_version.to_string(),
        enum_to_storage(&record.status)?,
        record.started_at.to_string(),
        record
            .finished_at
            .as_ref()
            .map(Timestamp::to_string)
            .unwrap_or_default(),
        if record.dry_run { "1" } else { "0" }.to_string(),
        record.statement_count.to_string(),
        serde_json::to_string(&record.row_count_verifications)?,
        record.error_message.clone().unwrap_or_default(),
    ])
}

fn collect_row_counts(
    tx: &Transaction<'_>,
    hooks: &[RowCountVerificationHook],
) -> StorageResult<Vec<(String, Option<u64>)>> {
    let mut counts = Vec::with_capacity(hooks.len());
    for hook in hooks {
        if !table_exists(tx, &hook.table_name)? {
            counts.push((hook.table_name.clone(), None));
            continue;
        }
        let table_name = quote_identifier(&hook.table_name)?;
        let sql = format!("SELECT COUNT(*) FROM {table_name}");
        let count = tx.query_row(&sql, [], |row| row.get::<_, i64>(0))?;
        counts.push((hook.table_name.clone(), Some(count as u64)));
    }
    Ok(counts)
}

fn merge_row_count_results(
    before: Vec<(String, Option<u64>)>,
    after: Vec<(String, Option<u64>)>,
) -> Vec<RowCountVerificationResult> {
    before
        .into_iter()
        .zip(after)
        .map(
            |((table_name, before_count), (_, after_count))| RowCountVerificationResult {
                table_name,
                before_count,
                after_count,
            },
        )
        .collect()
}

fn table_exists(tx: &Transaction<'_>, table_name: &str) -> StorageResult<bool> {
    let count = tx.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?1",
        params![table_name],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(count > 0)
}

fn enum_to_storage<T: Serialize>(value: &T) -> StorageResult<String> {
    match serde_json::to_value(value)? {
        Value::String(value) => Ok(value),
        other => Ok(other.to_string()),
    }
}

fn validate_sql_identifier(value: &str) -> StorageResult<()> {
    let valid = !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_');
    if valid {
        Ok(())
    } else {
        Err(StorageError::InvalidIdentifier(value.to_string()))
    }
}

fn quote_identifier(value: &str) -> StorageResult<String> {
    validate_sql_identifier(value)?;
    Ok(format!("\"{value}\""))
}

fn validate_sql_privacy(migration_key: &str, sql: &str) -> StorageResult<()> {
    let normalized = sql.to_ascii_lowercase();
    for forbidden in FORBIDDEN_STORAGE_TOKENS {
        if normalized.contains(forbidden) {
            return Err(StorageError::InvalidMigration {
                migration_key: migration_key.to_string(),
                reason: format!("SQL contains forbidden sensitive storage token `{forbidden}`"),
            });
        }
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> StorageResult<()> {
    if value.trim().is_empty() {
        Err(StorageError::InvalidMigration {
            migration_key: field.to_string(),
            reason: "value must not be empty".to_string(),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn migration_runner_applies_transaction_and_writes_audit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        let mut runner = MigrationRunner::new(&mut connection);
        runner.initialize(&SchemaMetadata::storage_foundation())?;
        let migration = metadata_table_migration()?
            .with_row_count_verification(RowCountVerificationHook::new("safe_metadata_records")?)?;
        let mut sink = InMemoryMigrationAuditSink::default();

        let report = runner.apply_all(&[migration], &mut sink)?;

        assert_eq!(report.applied, 1);
        assert_eq!(sink.records().len(), 1);
        assert_eq!(sink.records()[0].status, MigrationStatus::Applied);
        assert_eq!(
            sink.records()[0].row_count_verifications[0].after_count,
            Some(0)
        );

        let migration_count: i64 =
            connection.query_row("SELECT COUNT(*) FROM sg_migrations", [], |row| row.get(0))?;
        let audit_count: i64 =
            connection.query_row("SELECT COUNT(*) FROM sg_migration_audit", [], |row| {
                row.get(0)
            })?;
        assert_eq!(migration_count, 1);
        assert_eq!(audit_count, 1);
        Ok(())
    }

    #[test]
    fn failed_migration_rolls_back_partial_schema_and_records_audit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        let mut runner = MigrationRunner::new(&mut connection);
        runner.initialize(&SchemaMetadata::storage_foundation())?;
        let migration = Migration::new(
            "001_partial_failure",
            "rollback partial schema on failure",
            SchemaVersion::new(0, 1, 1),
            vec![MigrationStatement::new(
                "create_then_fail",
                r#"
                CREATE TABLE should_rollback (
                    record_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    privacy_class TEXT NOT NULL,
                    retention_class TEXT NOT NULL
                );
                INSERT INTO missing_table (value) VALUES ('boom');
                "#,
            )],
            StoragePrivacyClass::operational_metadata(),
        )?;
        let mut sink = InMemoryMigrationAuditSink::default();

        let result = runner.apply_all(&[migration], &mut sink);

        assert!(matches!(result, Err(StorageError::MigrationFailed { .. })));
        assert_eq!(sink.records().len(), 1);
        assert_eq!(sink.records()[0].status, MigrationStatus::Failed);

        let table_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'should_rollback'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(table_count, 0);

        let migration_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sg_migrations WHERE migration_key = '001_partial_failure'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(migration_count, 0);

        let failed_audit_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sg_migration_audit WHERE migration_key = '001_partial_failure' AND status = 'failed'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(failed_audit_count, 1);
        Ok(())
    }

    #[test]
    fn dry_run_rolls_back_schema_changes() -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        let mut runner = MigrationRunner::new(&mut connection);
        runner.initialize(&SchemaMetadata::storage_foundation())?;
        let migration = metadata_table_migration()?;
        let mut sink = InMemoryMigrationAuditSink::default();

        let report = runner.dry_run(&[migration], &mut sink)?;

        assert_eq!(report.dry_run, 1);
        assert_eq!(sink.records()[0].status, MigrationStatus::DryRun);
        let exists: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'safe_metadata_records'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(exists, 0);
        Ok(())
    }

    #[test]
    fn migration_sql_rejects_sensitive_persistence_tokens() {
        let migration = Migration::new(
            "001_raw_payload",
            "raw payload table",
            SchemaVersion::new(0, 1, 0),
            vec![MigrationStatement::new(
                "create_raw_payload",
                "CREATE TABLE packet_payloads (raw_payload TEXT NOT NULL)",
            )],
            StoragePrivacyClass::operational_metadata(),
        );

        assert!(migration.is_err());
    }

    #[test]
    fn migration_statement_count_is_bounded() {
        let statements = (0..=MAX_MIGRATION_STATEMENT_COUNT)
            .map(|index| {
                MigrationStatement::new(
                    format!("create_safe_table_{index}"),
                    format!(
                        "CREATE TABLE safe_table_{index} (record_id TEXT PRIMARY KEY, schema_version TEXT NOT NULL)"
                    ),
                )
            })
            .collect::<Vec<_>>();

        let migration = Migration::new(
            "001_too_many_statements",
            "too many statements",
            SchemaVersion::new(0, 1, 0),
            statements,
            StoragePrivacyClass::operational_metadata(),
        );

        assert!(matches!(
            migration,
            Err(StorageError::InvalidMigration { .. })
        ));
    }

    #[test]
    fn file_backed_storage_initialization_enables_wal() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_db_path();
        let mut connection = Connection::open(&path)?;
        {
            let mut runner = MigrationRunner::new(&mut connection);
            runner.initialize(&SchemaMetadata::storage_foundation())?;
        }

        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        assert_eq!(journal_mode, "wal");

        drop(connection);
        cleanup_temp_db(&path);
        Ok(())
    }

    fn metadata_table_migration() -> StorageResult<Migration> {
        Migration::new(
            "001_safe_metadata_records",
            "create safe metadata records table",
            SchemaVersion::new(0, 1, 0),
            vec![MigrationStatement::new(
                "create_safe_metadata_records",
                r#"
                CREATE TABLE safe_metadata_records (
                    record_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    privacy_class TEXT NOT NULL,
                    retention_class TEXT NOT NULL
                )
                "#,
            )],
            StoragePrivacyClass::operational_metadata(),
        )
    }

    fn temp_db_path() -> PathBuf {
        std::env::temp_dir().join(format!("sentinel-storage-{}.db", Uuid::new_v4()))
    }

    fn cleanup_temp_db(path: &PathBuf) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(path.with_extension("db-wal"));
        let _ = fs::remove_file(path.with_extension("db-shm"));
    }
}
