use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyClass {
    Public,
    #[default]
    Internal,
    Sensitive,
    Secret,
    Redacted,
    Tokenized,
}

impl PrivacyClass {
    pub fn export_requires_redaction(&self) -> bool {
        matches!(self, Self::Sensitive | Self::Secret)
    }

    pub fn export_allowed_after_redaction(&self) -> bool {
        !matches!(self, Self::Secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_privacy_class_is_internal() {
        assert_eq!(PrivacyClass::default(), PrivacyClass::Internal);
    }
}
