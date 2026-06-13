use crate::error::{StorageError, StorageResult};
use crate::ids::SettingsRecordId;
use crate::privacy::StoragePrivacyClass;
use crate::store::{LogicalRecord, LogicalStore, RecordState, SqliteLogicalStore, StoreKind};
use sentinel_contracts::{
    RuntimeProfile, SettingsChangeRequest, SettingsImpactAnalysis, SETTINGS_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SETTINGS_DOCUMENT_TYPE_FIELD: &str = "settings_document_type";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsDocumentType {
    RuntimeProfile,
    ChangeRequest,
    ImpactAnalysis,
}

impl SettingsDocumentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RuntimeProfile => "runtime_profile",
            Self::ChangeRequest => "change_request",
            Self::ImpactAnalysis => "impact_analysis",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "settings_document_type",
    content = "document",
    rename_all = "snake_case"
)]
pub enum SettingsDocument {
    RuntimeProfile(RuntimeProfile),
    ChangeRequest(SettingsChangeRequest),
    ImpactAnalysis(SettingsImpactAnalysis),
}

impl SettingsDocument {
    pub fn document_type(&self) -> SettingsDocumentType {
        match self {
            Self::RuntimeProfile(_) => SettingsDocumentType::RuntimeProfile,
            Self::ChangeRequest(_) => SettingsDocumentType::ChangeRequest,
            Self::ImpactAnalysis(_) => SettingsDocumentType::ImpactAnalysis,
        }
    }

    pub fn validate(&self) -> StorageResult<()> {
        match self {
            Self::RuntimeProfile(profile) => {
                profile
                    .validate()
                    .map_err(|error| StorageError::InvalidRecord {
                        store_kind: StoreKind::Settings.to_string(),
                        reason: error.to_string(),
                    })
            }
            Self::ChangeRequest(request) => {
                request
                    .validate()
                    .map_err(|error| StorageError::InvalidRecord {
                        store_kind: StoreKind::Settings.to_string(),
                        reason: error.to_string(),
                    })
            }
            Self::ImpactAnalysis(_) => Ok(()),
        }
    }
}

pub struct SettingsConfigRepository<'connection> {
    settings_store: SqliteLogicalStore<'connection, SettingsRecordId>,
}

impl<'connection> SettingsConfigRepository<'connection> {
    pub fn new(settings_store: SqliteLogicalStore<'connection, SettingsRecordId>) -> Self {
        Self { settings_store }
    }

    pub fn save_runtime_profile(&self, profile: RuntimeProfile) -> StorageResult<SettingsRecordId> {
        self.append_document(SettingsDocument::RuntimeProfile(profile))
    }

    pub fn save_change_request(
        &self,
        request: SettingsChangeRequest,
    ) -> StorageResult<SettingsRecordId> {
        self.append_document(SettingsDocument::ChangeRequest(request))
    }

    pub fn save_impact_analysis(
        &self,
        analysis: SettingsImpactAnalysis,
    ) -> StorageResult<SettingsRecordId> {
        self.append_document(SettingsDocument::ImpactAnalysis(analysis))
    }

    pub fn get_document(
        &self,
        record_id: &SettingsRecordId,
    ) -> StorageResult<Option<SettingsDocument>> {
        self.settings_store
            .get_by_id(record_id)?
            .map(|record| document_from_record(&record))
            .transpose()
    }

    pub fn get_runtime_profile(
        &self,
        record_id: &SettingsRecordId,
    ) -> StorageResult<Option<RuntimeProfile>> {
        match self.get_document(record_id)? {
            Some(SettingsDocument::RuntimeProfile(profile)) => Ok(Some(profile)),
            Some(other) => Err(StorageError::InvalidRecord {
                store_kind: StoreKind::Settings.to_string(),
                reason: format!("expected runtime profile, got {:?}", other.document_type()),
            }),
            None => Ok(None),
        }
    }

    pub fn archive_document(&self, record_id: &SettingsRecordId) -> StorageResult<()> {
        self.settings_store
            .update_state(record_id, RecordState::Archived)
    }

    fn append_document(&self, document: SettingsDocument) -> StorageResult<SettingsRecordId> {
        document.validate()?;
        let record_id = SettingsRecordId::new_v4();
        let metadata = document_to_metadata(&document)?;
        let record = LogicalRecord::metadata_only(
            record_id.clone(),
            SETTINGS_SCHEMA_VERSION,
            StoragePrivacyClass::operational_metadata(),
            metadata,
        );
        self.settings_store.append(record)?;
        Ok(record_id)
    }
}

pub fn default_runtime_profile_documents() -> Vec<SettingsDocument> {
    RuntimeProfile::default_profiles()
        .into_iter()
        .map(SettingsDocument::RuntimeProfile)
        .collect()
}

fn document_to_metadata(document: &SettingsDocument) -> StorageResult<Value> {
    let value = serde_json::to_value(document)?;
    Ok(json!({
        SETTINGS_DOCUMENT_TYPE_FIELD: document.document_type().as_str(),
        "settings_schema_version": SETTINGS_SCHEMA_VERSION.to_string(),
        "settings_document": value,
    }))
}

fn document_from_record(
    record: &LogicalRecord<SettingsRecordId>,
) -> StorageResult<SettingsDocument> {
    let payload =
        record
            .metadata
            .get("settings_document")
            .ok_or_else(|| StorageError::InvalidRecord {
                store_kind: StoreKind::Settings.to_string(),
                reason: "settings_document is missing".to_string(),
            })?;
    Ok(serde_json::from_value(payload.clone())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{InMemoryMigrationAuditSink, MigrationRunner, SchemaMetadata};
    use crate::store::{logical_store_migration, SqliteStoreFactory};
    use rusqlite::Connection;
    use sentinel_contracts::{
        ForensicScope, ForensicScopeKind, SettingsChangeKind, SettingsImpactLevel,
    };

    #[test]
    fn settings_repository_persists_runtime_profile_through_logical_store(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let factory = SqliteStoreFactory::new(&connection);
        let repository = SettingsConfigRepository::new(factory.settings_store());
        let record_id = repository.save_runtime_profile(RuntimeProfile::safe_default())?;

        let profile = repository
            .get_runtime_profile(&record_id)?
            .expect("profile was stored");

        assert!(profile.is_default);
        assert!(!profile.privacy_policy.raw_packet_storage_enabled);
        assert!(!profile.privacy_policy.payload_storage_enabled);
        assert!(!profile.privacy_policy.http_body_storage_enabled);
        Ok(())
    }

    #[test]
    fn settings_repository_rejects_unsafe_profile() -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let factory = SqliteStoreFactory::new(&connection);
        let repository = SettingsConfigRepository::new(factory.settings_store());
        let mut profile = RuntimeProfile::safe_default();
        profile.capture_settings.store_payloads = true;

        assert!(repository.save_runtime_profile(profile).is_err());
        Ok(())
    }

    #[test]
    fn settings_repository_persists_change_request_and_impact_analysis(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = initialized_connection()?;
        let factory = SqliteStoreFactory::new(&connection);
        let repository = SettingsConfigRepository::new(factory.settings_store());
        let scope = ForensicScope::new(ForensicScopeKind::SelectedDestination, "domain#redacted")?;
        let profile = RuntimeProfile::forensic_manual("manual investigation", scope)?;
        let request = SettingsChangeRequest::new(
            SettingsChangeKind::RuntimeProfile,
            profile,
            "enable explicit forensic profile",
        )?;
        let analysis = SettingsImpactAnalysis::from_request(&request);

        let request_record = repository.save_change_request(request)?;
        let analysis_record = repository.save_impact_analysis(analysis.clone())?;

        assert!(repository.get_document(&request_record)?.is_some());
        assert!(repository.get_document(&analysis_record)?.is_some());
        assert_eq!(analysis.impact_level, SettingsImpactLevel::High);
        assert!(analysis.audit_required);
        Ok(())
    }

    #[test]
    fn default_profile_documents_are_safe_to_validate() {
        let documents = default_runtime_profile_documents();

        assert!(documents.len() >= 5);
        for document in documents {
            assert!(document.validate().is_ok());
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
