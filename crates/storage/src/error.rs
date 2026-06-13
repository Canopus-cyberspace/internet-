use std::fmt;

#[derive(Debug)]
pub enum StorageError {
    Sqlite(String),
    Io(String),
    Serialization(String),
    InvalidCursor(String),
    InvalidRecord {
        store_kind: String,
        reason: String,
    },
    InvalidMigration {
        migration_key: String,
        reason: String,
    },
    MigrationFailed {
        migration_key: String,
        reason: String,
    },
    InvalidIdentifier(String),
    StoreKindMismatch {
        expected: String,
        actual: String,
    },
    UnsupportedQuery(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(message) => write!(f, "sqlite error: {message}"),
            Self::Io(message) => write!(f, "io error: {message}"),
            Self::Serialization(message) => write!(f, "serialization error: {message}"),
            Self::InvalidCursor(message) => write!(f, "invalid store cursor: {message}"),
            Self::InvalidRecord { store_kind, reason } => {
                write!(f, "invalid {store_kind} record: {reason}")
            }
            Self::InvalidMigration {
                migration_key,
                reason,
            } => {
                write!(f, "invalid migration {migration_key}: {reason}")
            }
            Self::MigrationFailed {
                migration_key,
                reason,
            } => {
                write!(f, "migration {migration_key} failed: {reason}")
            }
            Self::InvalidIdentifier(value) => write!(f, "invalid sqlite identifier: {value}"),
            Self::StoreKindMismatch { expected, actual } => {
                write!(
                    f,
                    "store snapshot kind mismatch: expected {expected}, got {actual}"
                )
            }
            Self::UnsupportedQuery(message) => write!(f, "unsupported store query: {message}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<rusqlite::Error> for StorageError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value.to_string())
    }
}

impl From<std::io::Error> for StorageError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

pub type StorageResult<T> = Result<T, StorageError>;
