use sentinel_contracts::PrivacyClass;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    D0OperationalMetadata,
    D1SecurityMetadata,
    D2EndpointIdentityMetadata,
    D3NetworkBehavioralMetadata,
    D4SensitiveApplicationMetadata,
    D5RawContentPayload,
    EphemeralSessionOnly,
}

impl DataClass {
    pub fn default_retention_class(&self) -> RetentionClass {
        match self {
            Self::D0OperationalMetadata => RetentionClass::LongLived,
            Self::D1SecurityMetadata => RetentionClass::Days90,
            Self::D2EndpointIdentityMetadata => RetentionClass::Days30,
            Self::D3NetworkBehavioralMetadata => RetentionClass::Days30,
            Self::D4SensitiveApplicationMetadata => RetentionClass::ShortestPossible,
            Self::D5RawContentPayload => RetentionClass::ForensicOnlyTimeLimited,
            Self::EphemeralSessionOnly => RetentionClass::NotStored,
        }
    }

    pub fn normal_mode_persistence_allowed(&self) -> bool {
        !matches!(self, Self::D5RawContentPayload | Self::EphemeralSessionOnly)
    }

    pub fn fts_index_allowed(&self) -> bool {
        matches!(
            self,
            Self::D0OperationalMetadata
                | Self::D1SecurityMetadata
                | Self::D3NetworkBehavioralMetadata
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    LongLived,
    Days14,
    Days30,
    Days90,
    Days180,
    Days365,
    UserControlled,
    FeedExpiry,
    ShortestPossible,
    ForensicOnlyTimeLimited,
    NotStored,
}

impl RetentionClass {
    pub fn retention_days(&self) -> Option<u16> {
        match self {
            Self::Days14 => Some(14),
            Self::Days30 => Some(30),
            Self::Days90 => Some(90),
            Self::Days180 => Some(180),
            Self::Days365 => Some(365),
            Self::LongLived
            | Self::UserControlled
            | Self::FeedExpiry
            | Self::ShortestPossible
            | Self::ForensicOnlyTimeLimited
            | Self::NotStored => None,
        }
    }

    pub fn normal_mode_persistence_allowed(&self) -> bool {
        !matches!(self, Self::ForensicOnlyTimeLimited | Self::NotStored)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldProtection {
    None,
    RedactBeforeExport,
    Tokenize,
    Hash,
    Encrypt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoragePrivacyClass {
    pub data_class: DataClass,
    pub retention_class: RetentionClass,
    pub privacy_class: PrivacyClass,
    pub field_protection: Vec<FieldProtection>,
    pub normal_mode_persistence_allowed: bool,
    pub fts_index_allowed: bool,
}

impl StoragePrivacyClass {
    pub fn new(
        data_class: DataClass,
        retention_class: RetentionClass,
        privacy_class: PrivacyClass,
        field_protection: Vec<FieldProtection>,
    ) -> Self {
        let normal_mode_persistence_allowed = data_class.normal_mode_persistence_allowed()
            && retention_class.normal_mode_persistence_allowed();
        let fts_index_allowed = data_class.fts_index_allowed()
            && !matches!(privacy_class, PrivacyClass::Secret)
            && normal_mode_persistence_allowed;

        Self {
            data_class,
            retention_class,
            privacy_class,
            field_protection,
            normal_mode_persistence_allowed,
            fts_index_allowed,
        }
    }

    pub fn operational_metadata() -> Self {
        Self::new(
            DataClass::D0OperationalMetadata,
            RetentionClass::LongLived,
            PrivacyClass::Internal,
            vec![FieldProtection::None],
        )
    }

    pub fn security_metadata() -> Self {
        Self::new(
            DataClass::D1SecurityMetadata,
            RetentionClass::Days90,
            PrivacyClass::Sensitive,
            vec![
                FieldProtection::Encrypt,
                FieldProtection::RedactBeforeExport,
            ],
        )
    }

    pub fn network_behavioral_metadata() -> Self {
        Self::new(
            DataClass::D3NetworkBehavioralMetadata,
            RetentionClass::Days30,
            PrivacyClass::Sensitive,
            vec![
                FieldProtection::Encrypt,
                FieldProtection::RedactBeforeExport,
            ],
        )
    }

    pub fn raw_content_forensic_only() -> Self {
        Self::new(
            DataClass::D5RawContentPayload,
            RetentionClass::ForensicOnlyTimeLimited,
            PrivacyClass::Secret,
            vec![
                FieldProtection::Encrypt,
                FieldProtection::RedactBeforeExport,
            ],
        )
    }

    pub fn ephemeral_session_only() -> Self {
        Self::new(
            DataClass::EphemeralSessionOnly,
            RetentionClass::NotStored,
            PrivacyClass::Sensitive,
            vec![FieldProtection::RedactBeforeExport],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_content_is_not_allowed_in_normal_mode() {
        let class = StoragePrivacyClass::raw_content_forensic_only();

        assert!(!class.normal_mode_persistence_allowed);
        assert!(!class.fts_index_allowed);
    }

    #[test]
    fn ephemeral_session_only_is_never_persisted() {
        let class = StoragePrivacyClass::ephemeral_session_only();

        assert_eq!(class.data_class, DataClass::EphemeralSessionOnly);
        assert_eq!(class.retention_class, RetentionClass::NotStored);
        assert!(!class.normal_mode_persistence_allowed);
        assert!(!class.fts_index_allowed);
    }

    #[test]
    fn storage_privacy_class_carries_retention_and_contract_privacy() {
        let class = StoragePrivacyClass::network_behavioral_metadata();

        assert_eq!(class.retention_class, RetentionClass::Days30);
        assert_eq!(class.privacy_class, PrivacyClass::Sensitive);
        assert!(class.normal_mode_persistence_allowed);
    }
}
