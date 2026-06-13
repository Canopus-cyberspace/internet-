use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl SchemaVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn compatibility_with(&self, consumer: &SchemaVersion) -> SchemaCompatibility {
        if self.major != consumer.major {
            SchemaCompatibility::Unsupported
        } else if self.minor > consumer.minor {
            SchemaCompatibility::BackwardCompatible
        } else {
            SchemaCompatibility::Strict
        }
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaVersionParseError {
    value: String,
}

impl SchemaVersionParseError {
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for SchemaVersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid schema version: {}", self.value)
    }
}

impl std::error::Error for SchemaVersionParseError {}

impl FromStr for SchemaVersion {
    type Err = SchemaVersionParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.split('.');
        let major = parts.next().and_then(|part| part.parse::<u16>().ok());
        let minor = parts.next().and_then(|part| part.parse::<u16>().ok());
        let patch = parts.next().and_then(|part| part.parse::<u16>().ok());

        if parts.next().is_some() {
            return Err(SchemaVersionParseError {
                value: value.to_string(),
            });
        }

        match (major, minor, patch) {
            (Some(major), Some(minor), Some(patch)) => Ok(Self::new(major, minor, patch)),
            _ => Err(SchemaVersionParseError {
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaCompatibility {
    Strict,
    BackwardCompatible,
    MigrationRequired,
    Deprecated,
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_schema_version() {
        let version = "1.2.3".parse::<SchemaVersion>().expect("valid version");

        assert_eq!(version, SchemaVersion::new(1, 2, 3));
        assert_eq!(version.to_string(), "1.2.3");
    }

    #[test]
    fn rejects_invalid_schema_version() {
        assert!("1.2".parse::<SchemaVersion>().is_err());
        assert!("1.2.3.4".parse::<SchemaVersion>().is_err());
    }

    #[test]
    fn reports_schema_compatibility() {
        assert_eq!(
            SchemaVersion::new(1, 2, 0).compatibility_with(&SchemaVersion::new(1, 1, 0)),
            SchemaCompatibility::BackwardCompatible
        );
        assert_eq!(
            SchemaVersion::new(2, 0, 0).compatibility_with(&SchemaVersion::new(1, 9, 0)),
            SchemaCompatibility::Unsupported
        );
    }
}
