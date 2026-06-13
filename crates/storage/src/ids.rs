use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageIdParseError {
    id_type: &'static str,
    value: String,
}

impl StorageIdParseError {
    pub fn new(id_type: &'static str, value: impl Into<String>) -> Self {
        Self {
            id_type,
            value: value.into(),
        }
    }
}

impl fmt::Display for StorageIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {} UUID: {}", self.id_type, self.value)
    }
}

impl std::error::Error for StorageIdParseError {}

macro_rules! define_storage_uuid_id {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new_v4() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            pub fn parse_str(value: &str) -> Result<Self, StorageIdParseError> {
                Uuid::parse_str(value)
                    .map(Self)
                    .map_err(|_| StorageIdParseError::new(stringify!($name), value))
            }

            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self::from_uuid(value)
            }
        }

        impl FromStr for $name {
            type Err = StorageIdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse_str(value)
            }
        }
    };
}

define_storage_uuid_id!(IntelligenceCacheId);
define_storage_uuid_id!(ComponentRecordId);
define_storage_uuid_id!(SettingsRecordId);
define_storage_uuid_id!(StoreSnapshotId);
