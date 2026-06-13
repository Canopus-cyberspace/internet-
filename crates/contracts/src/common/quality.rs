use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct QualityScore(f32);

impl QualityScore {
    pub fn new(value: f32) -> Result<Self, QualityScoreError> {
        if (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(QualityScoreError { value })
        }
    }

    pub fn perfect() -> Self {
        Self(1.0)
    }

    pub fn unknown() -> Self {
        Self(0.0)
    }

    pub fn value(&self) -> f32 {
        self.0
    }
}

impl Default for QualityScore {
    fn default() -> Self {
        Self::unknown()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct QualityScoreError {
    value: f32,
}

impl QualityScoreError {
    pub fn value(&self) -> f32 {
        self.value
    }
}

impl fmt::Display for QualityScoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "quality score must be between 0.0 and 1.0: {}",
            self.value
        )
    }
}

impl std::error::Error for QualityScoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_quality_score_bounds() {
        assert!(QualityScore::new(0.0).is_ok());
        assert!(QualityScore::new(1.0).is_ok());
        assert!(QualityScore::new(1.1).is_err());
    }
}
