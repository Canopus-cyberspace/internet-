use crate::common::{EntityId, QualityScore, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Host,
    User,
    Process,
    Service,
    Port,
    Ip,
    Domain,
    Url,
    ApiEndpoint,
    CloudResource,
    Asn,
    Certificate,
    Honeypot,
    Decoy,
    Finding,
    Alert,
    Incident,
    Other,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntityRef {
    pub entity_id: EntityId,
    pub entity_type: EntityType,
    pub entity_name: Option<String>,
    pub namespace: Option<String>,
    pub source: Option<String>,
    pub confidence: QualityScore,
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
}

impl EntityRef {
    pub fn new(entity_id: EntityId, entity_type: EntityType) -> Self {
        Self {
            entity_id,
            entity_type,
            entity_name: None,
            namespace: None,
            source: None,
            confidence: QualityScore::default(),
            first_seen: None,
            last_seen: None,
        }
    }
}
