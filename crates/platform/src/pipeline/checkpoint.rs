use crate::pipeline::dag::PipelineNodeId;
use crate::pipeline::stage::PipelineStage;
use sentinel_contracts::{PipelineId, PluginId, PrivacyClass, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CheckpointId(Uuid);

impl CheckpointId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for CheckpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for CheckpointId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope_kind", rename_all = "snake_case")]
pub enum CheckpointScope {
    Pipeline {
        pipeline_id: PipelineId,
    },
    Node {
        pipeline_id: PipelineId,
        node_id: PipelineNodeId,
    },
    Stage {
        pipeline_id: PipelineId,
        stage: PipelineStage,
    },
    Plugin {
        pipeline_id: PipelineId,
        plugin_id: PluginId,
    },
    PluginStage {
        pipeline_id: PipelineId,
        plugin_id: PluginId,
        stage: PipelineStage,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointHandle {
    pub checkpoint_id: CheckpointId,
    pub scope: CheckpointScope,
    pub cursor_key: String,
}

impl CheckpointHandle {
    pub fn new(
        scope: CheckpointScope,
        cursor_key: impl Into<String>,
    ) -> Result<Self, CheckpointError> {
        let cursor_key = cursor_key.into();
        if cursor_key.trim().is_empty() {
            return Err(CheckpointError::EmptyField("cursor_key"));
        }

        Ok(Self {
            checkpoint_id: CheckpointId::new_v4(),
            scope,
            cursor_key,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointRecord {
    pub checkpoint_id: CheckpointId,
    pub scope: CheckpointScope,
    pub cursor: String,
    pub timestamp: Timestamp,
    pub metadata_redacted: BTreeMap<String, String>,
    pub privacy_class: PrivacyClass,
    pub stores_raw_payload: bool,
    pub stores_raw_packet: bool,
    pub stores_http_body: bool,
}

impl CheckpointRecord {
    pub fn new(
        handle: &CheckpointHandle,
        cursor: impl Into<String>,
        metadata_redacted: BTreeMap<String, String>,
    ) -> Result<Self, CheckpointError> {
        let cursor = cursor.into();
        if cursor.trim().is_empty() {
            return Err(CheckpointError::EmptyField("cursor"));
        }

        validate_metadata_keys(&metadata_redacted)?;

        Ok(Self {
            checkpoint_id: handle.checkpoint_id.clone(),
            scope: handle.scope.clone(),
            cursor,
            timestamp: Timestamp::now(),
            metadata_redacted,
            privacy_class: PrivacyClass::Internal,
            stores_raw_payload: false,
            stores_raw_packet: false,
            stores_http_body: false,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointError {
    EmptyField(&'static str),
    ForbiddenMetadataKey(String),
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::ForbiddenMetadataKey(key) => {
                write!(f, "checkpoint metadata key is not privacy-safe: {key}")
            }
        }
    }
}

impl std::error::Error for CheckpointError {}

fn validate_metadata_keys(metadata: &BTreeMap<String, String>) -> Result<(), CheckpointError> {
    for key in metadata.keys() {
        let normalized = key.to_ascii_lowercase();
        if normalized.contains("raw_packet")
            || normalized.contains("payload")
            || normalized.contains("http_body")
            || normalized.contains("cookie")
            || normalized.contains("token")
            || normalized.contains("credential")
            || normalized.contains("api_key")
        {
            return Err(CheckpointError::ForbiddenMetadataKey(key.clone()));
        }
    }
    Ok(())
}
