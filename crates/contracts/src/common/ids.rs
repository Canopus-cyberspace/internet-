use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdParseError {
    id_type: &'static str,
    value: String,
}

impl IdParseError {
    pub fn new(id_type: &'static str, value: impl Into<String>) -> Self {
        Self {
            id_type,
            value: value.into(),
        }
    }

    pub fn id_type(&self) -> &'static str {
        self.id_type
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for IdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {} UUID: {}", self.id_type, self.value)
    }
}

impl std::error::Error for IdParseError {}

macro_rules! define_uuid_id {
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

            pub fn parse_str(value: &str) -> Result<Self, IdParseError> {
                Uuid::parse_str(value)
                    .map(Self)
                    .map_err(|_| IdParseError::new(stringify!($name), value))
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
            type Err = IdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse_str(value)
            }
        }
    };
}

define_uuid_id!(PluginId);
define_uuid_id!(CapabilityId);
define_uuid_id!(ContractId);
define_uuid_id!(UiContributionId);
define_uuid_id!(ActionDescriptorId);
define_uuid_id!(DataSourceId);
define_uuid_id!(EventId);
define_uuid_id!(PacketRecordId);
define_uuid_id!(FlowId);
define_uuid_id!(SessionId);
define_uuid_id!(DnsObservationId);
define_uuid_id!(TlsObservationId);
define_uuid_id!(HttpMetadataId);
define_uuid_id!(AuthMetadataId);
define_uuid_id!(SaasCloudMetadataId);
define_uuid_id!(DeceptionEventId);
define_uuid_id!(ProcessContextId);
define_uuid_id!(UserSessionId);
define_uuid_id!(FlowAttributionId);
define_uuid_id!(HostIdentityId);
define_uuid_id!(AssetIdentityId);
define_uuid_id!(SecurityObservationId);
define_uuid_id!(FindingId);
define_uuid_id!(EvidenceId);
define_uuid_id!(EvidenceQualityId);
define_uuid_id!(NativeSamplerId);
define_uuid_id!(NativeSamplerReviewId);
define_uuid_id!(NativeSamplerSchemaId);
define_uuid_id!(NativeSamplerBatchId);
define_uuid_id!(NativeSchedulerCycleId);
define_uuid_id!(NativeServiceObservationId);
define_uuid_id!(NativeHealthObservationId);
define_uuid_id!(NativeProcessObservationId);
define_uuid_id!(FutureSecurityFactMappingId);
define_uuid_id!(EvidenceBundleId);
define_uuid_id!(RiskEventId);
define_uuid_id!(RiskHintId);
define_uuid_id!(AlertCandidateId);
define_uuid_id!(AlertId);
define_uuid_id!(IncidentCandidateId);
define_uuid_id!(IncidentId);
define_uuid_id!(GraphHintId);
define_uuid_id!(GraphNodeId);
define_uuid_id!(GraphEdgeId);
define_uuid_id!(GraphPathId);
define_uuid_id!(GraphSnapshotId);
define_uuid_id!(GraphViewId);
define_uuid_id!(PolicyDecisionId);
define_uuid_id!(RecommendedActionId);
define_uuid_id!(ResponsePlanId);
define_uuid_id!(ResponseActionId);
define_uuid_id!(ResponseResultId);
define_uuid_id!(ApprovalRequestId);
define_uuid_id!(ApprovalResultId);
define_uuid_id!(RollbackPlanId);
define_uuid_id!(RollbackResultId);
define_uuid_id!(ReportId);
define_uuid_id!(ReportSectionId);
define_uuid_id!(LlmAlertStoryId);
define_uuid_id!(SecurityFactId);
define_uuid_id!(AttackHypothesisId);
define_uuid_id!(BaselineRecordId);
define_uuid_id!(BaselineIndicatorId);
define_uuid_id!(IncidentLinkedGroupId);
define_uuid_id!(IncidentTimelineEntryId);
define_uuid_id!(MetadataWatchSourceId);
define_uuid_id!(MetadataWatchCheckpointId);
define_uuid_id!(MetadataSamplingBatchId);
define_uuid_id!(RedactionSummaryId);
define_uuid_id!(ExportRequestId);
define_uuid_id!(ExportResultId);
define_uuid_id!(RuntimeProfileId);
define_uuid_id!(SettingsChangeRequestId);
define_uuid_id!(SettingsImpactAnalysisId);
define_uuid_id!(AuditId);
define_uuid_id!(TraceId);
define_uuid_id!(CorrelationId);
define_uuid_id!(CausalityId);
define_uuid_id!(PipelineId);
define_uuid_id!(ReplayId);
define_uuid_id!(EntityId);
define_uuid_id!(IntelligenceRecordId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_id_serializes_as_json_string() {
        let id = EventId::new_v4();
        let json = serde_json::to_string(&id).expect("serialize id");

        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));

        let parsed: EventId = serde_json::from_str(&json).expect("deserialize id");
        assert_eq!(id, parsed);
    }

    #[test]
    fn uuid_id_rejects_invalid_value() {
        let error = EventId::parse_str("not-a-uuid").expect_err("invalid id rejected");

        assert_eq!(error.id_type(), "EventId");
        assert_eq!(error.value(), "not-a-uuid");
    }
}
