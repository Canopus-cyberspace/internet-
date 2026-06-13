use sentinel_contracts::SchemaVersion;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub const RAW_PACKET_METADATA: &str = "raw.packet.metadata";
pub const NETWORK_PACKET_RECORD: &str = "network.packet.record";
pub const NETWORK_FLOW_RECORD: &str = "network.flow.record";
pub const NETWORK_SESSION_RECORD: &str = "network.session.record";
pub const NETWORK_DNS_OBSERVATION: &str = "network.dns.observation";
pub const NETWORK_TLS_OBSERVATION: &str = "network.tls.observation";
pub const NETWORK_HTTP_METADATA: &str = "network.http.metadata";
pub const IDENTITY_AUTH_METADATA: &str = "identity.auth_metadata";
pub const CLOUD_SAAS_METADATA: &str = "cloud.saas_metadata";
pub const DECEPTION_EVENT_METADATA: &str = "deception.event_metadata";
pub const IDENTITY_PROCESS_CONTEXT: &str = "identity.process_context";
pub const IDENTITY_FLOW_ATTRIBUTION: &str = "identity.flow_attribution";
pub const SERVICE_CAPABILITY_STATUS: &str = "service.capability_status";
pub const NATIVE_CAPABILITY_STATUS: &str = "native.capability.status";
pub const NATIVE_PERMISSION_STATUS: &str = "native.permission.status";
pub const NATIVE_SAMPLER_CONTRACT: &str = "native.sampler.contract";
pub const NATIVE_SAMPLER_READINESS: &str = "native.sampler.readiness";
pub const NATIVE_SAMPLER_REVIEW: &str = "native.sampler.review";
pub const NATIVE_SAMPLER_RUNTIME_STATUS: &str = "native.sampler.runtime_status";
pub const NATIVE_SCHEDULER_STATUS: &str = "native.scheduler.status";
pub const NATIVE_SCHEDULER_CYCLE_STARTED: &str = "native.scheduler.cycle_started";
pub const NATIVE_SCHEDULER_CYCLE_COMPLETED: &str = "native.scheduler.cycle_completed";
pub const NATIVE_SCHEDULER_CYCLE_SKIPPED: &str = "native.scheduler.cycle_skipped";
pub const NATIVE_SCHEDULER_EXECUTION_CONTROL: &str = "native.scheduler.execution_control";
pub const NATIVE_SCHEDULER_BACKPRESSURE: &str = "native.scheduler.backpressure";
pub const NATIVE_SCHEDULER_FRESHNESS: &str = "native.scheduler.freshness";
pub const NATIVE_SCHEDULER_MISSED_SAMPLE: &str = "native.scheduler.missed_sample";
pub const NATIVE_SCHEDULER_HOST_STATUS: &str = "native.scheduler.host_status";
pub const NATIVE_SCHEDULER_HOST_STARTED: &str = "native.scheduler.host_started";
pub const NATIVE_SCHEDULER_HOST_WAKE: &str = "native.scheduler.host_wake";
pub const NATIVE_SCHEDULER_HOST_PAUSED: &str = "native.scheduler.host_paused";
pub const NATIVE_SCHEDULER_HOST_RESUMED: &str = "native.scheduler.host_resumed";
pub const NATIVE_SCHEDULER_HOST_STOPPED: &str = "native.scheduler.host_stopped";
pub const NATIVE_SCHEDULER_HOST_FAILED: &str = "native.scheduler.host_failed";
pub const NATIVE_HEALTH_METADATA: &str = "native.health.metadata";
pub const NATIVE_SERVICE_METADATA: &str = "native.service.metadata";
pub const NATIVE_PROCESS_METADATA: &str = "native.process.metadata";
pub const NATIVE_PROCESS_PARENT_METADATA: &str = "native.process_parent.metadata";
pub const ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT: &str = "endpoint.native_health.category_fact";
pub const ENDPOINT_SERVICE_CATEGORY_FACT: &str = "endpoint.service.category_fact";
pub const ENDPOINT_PROCESS_CATEGORY_FACT: &str = "endpoint.process.category_fact";
pub const ENDPOINT_PROCESS_PARENT_CATEGORY_FACT: &str = "endpoint.process_parent.category_fact";
pub const NATIVE_VISIBILITY_STATUS: &str = "native.visibility.status";
pub const SECURITY_VISIBILITY_STATUS: &str = "security.visibility.status";
pub const SECURITY_VISIBILITY_DEGRADED: &str = "security.visibility.degraded";
pub const AUDIT_NATIVE_PERMISSION: &str = "audit.native_permission";
pub const AUDIT_NATIVE_SAMPLER_REVIEW: &str = "audit.native_sampler_review";
pub const AUDIT_NATIVE_SAMPLER_RUNTIME: &str = "audit.native_sampler_runtime";
pub const AUDIT_NATIVE_SCHEDULER: &str = "audit.native_scheduler";
pub const AUDIT_NATIVE_SCHEDULER_HOST: &str = "audit.native_scheduler_host";
pub const INTEL_DOMAIN_CONTEXT: &str = "intel.domain_context";
pub const INTEL_IP_CONTEXT: &str = "intel.ip_context";
pub const INTEL_CLOUD_CONTEXT: &str = "intel.cloud_context";
pub const ASSET_EXPOSURE: &str = "asset.exposure";
pub const SECURITY_OBSERVATION: &str = "security.observation";
pub const SECURITY_FUSION_CONTEXT: &str = "security.fusion.context";
pub const SECURITY_FACT: &str = "security.fact";
pub const SECURITY_HYPOTHESIS: &str = "security.hypothesis";
pub const SECURITY_FUSION_SUMMARY: &str = "security.fusion.summary";
pub const SECURITY_FINDING: &str = "security.finding";
pub const SECURITY_EVIDENCE: &str = "security.evidence";
pub const SECURITY_RISK: &str = "security.risk";
pub const SECURITY_ALERT: &str = "security.alert";
pub const SECURITY_INCIDENT: &str = "security.incident";
pub const GRAPH_HINT: &str = "graph.hint";
pub const GRAPH_UPDATE: &str = "graph.update";
pub const GRAPH_PATH: &str = "graph.path";
pub const RESPONSE_PLAN: &str = "response.plan";
pub const RESPONSE_POLICY_DECISION: &str = "response.policy.decision";
pub const RESPONSE_APPROVAL_REQUEST: &str = "response.approval.request";
pub const RESPONSE_APPROVAL_RESULT: &str = "response.approval.result";
pub const RESPONSE_RESULT: &str = "response.result";
pub const RESPONSE_ROLLBACK_RESULT: &str = "response.rollback.result";
pub const OPERATIONAL_HEALTH: &str = "operational.health";
pub const OPERATIONAL_METRIC: &str = "operational.metric";
pub const AUDIT_EVENT: &str = "audit.event";
pub const REPORT_GENERATED: &str = "report.generated";
pub const REPORT_EXPORTED: &str = "report.exported";

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TopicName(String);

impl TopicName {
    pub fn new(value: impl Into<String>) -> Result<Self, TopicNameError> {
        let value = value.into();
        let valid = !value.trim().is_empty()
            && value
                .split('.')
                .all(|part| !part.is_empty() && part.chars().all(is_topic_char));

        if valid {
            Ok(Self(value))
        } else {
            Err(TopicNameError { value })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TopicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for TopicName {
    type Err = TopicNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopicNameError {
    value: String,
}

impl fmt::Display for TopicNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid topic name: {}", self.value)
    }
}

impl std::error::Error for TopicNameError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopicLayer {
    Raw,
    Network,
    Context,
    Security,
    Graph,
    Response,
    Operational,
    Audit,
    Report,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityLane {
    P0Critical,
    P1High,
    P2Normal,
    P3Low,
    P4BestEffort,
    P5UiRefresh,
}

impl PriorityLane {
    pub fn can_drop_under_pressure(&self) -> bool {
        matches!(self, Self::P3Low | Self::P4BestEffort | Self::P5UiRefresh)
    }

    pub fn rank(&self) -> u8 {
        match self {
            Self::P0Critical => 0,
            Self::P1High => 1,
            Self::P2Normal => 2,
            Self::P3Low => 3,
            Self::P4BestEffort => 4,
            Self::P5UiRefresh => 5,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Topic {
    pub name: TopicName,
    pub layer: TopicLayer,
    pub schema_version: SchemaVersion,
    pub default_priority: PriorityLane,
    pub protected_delivery: bool,
    pub description: Option<String>,
}

impl Topic {
    pub fn new(
        name: TopicName,
        layer: TopicLayer,
        schema_version: SchemaVersion,
        default_priority: PriorityLane,
    ) -> Self {
        let protected_delivery = matches!(
            default_priority,
            PriorityLane::P0Critical | PriorityLane::P1High
        );

        Self {
            name,
            layer,
            schema_version,
            default_priority,
            protected_delivery,
            description: None,
        }
    }

    pub fn protected(mut self) -> Self {
        self.protected_delivery = true;
        self
    }

    pub fn is_schema_compatible(&self, actual: &SchemaVersion) -> bool {
        self.schema_version.major == actual.major
    }
}

pub fn core_v1_topics() -> Vec<Topic> {
    let v1 = SchemaVersion::new(1, 0, 0);
    vec![
        topic(
            RAW_PACKET_METADATA,
            TopicLayer::Raw,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NETWORK_PACKET_RECORD,
            TopicLayer::Network,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NETWORK_FLOW_RECORD,
            TopicLayer::Network,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NETWORK_SESSION_RECORD,
            TopicLayer::Network,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NETWORK_DNS_OBSERVATION,
            TopicLayer::Network,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NETWORK_TLS_OBSERVATION,
            TopicLayer::Network,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NETWORK_HTTP_METADATA,
            TopicLayer::Network,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            IDENTITY_AUTH_METADATA,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            CLOUD_SAAS_METADATA,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            DECEPTION_EVENT_METADATA,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            IDENTITY_PROCESS_CONTEXT,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            IDENTITY_FLOW_ATTRIBUTION,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            SERVICE_CAPABILITY_STATUS,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_CAPABILITY_STATUS,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_PERMISSION_STATUS,
            TopicLayer::Context,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            NATIVE_SAMPLER_CONTRACT,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SAMPLER_READINESS,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SAMPLER_REVIEW,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SAMPLER_RUNTIME_STATUS,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_STATUS,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_CYCLE_STARTED,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_CYCLE_COMPLETED,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_CYCLE_SKIPPED,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_EXECUTION_CONTROL,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_BACKPRESSURE,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_FRESHNESS,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_MISSED_SAMPLE,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_HOST_STATUS,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_HOST_STARTED,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_HOST_WAKE,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_HOST_PAUSED,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_HOST_RESUMED,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_HOST_STOPPED,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SCHEDULER_HOST_FAILED,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_HEALTH_METADATA,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_SERVICE_METADATA,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_PROCESS_METADATA,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_PROCESS_PARENT_METADATA,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT,
            TopicLayer::Security,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            ENDPOINT_SERVICE_CATEGORY_FACT,
            TopicLayer::Security,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            ENDPOINT_PROCESS_CATEGORY_FACT,
            TopicLayer::Security,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            ENDPOINT_PROCESS_PARENT_CATEGORY_FACT,
            TopicLayer::Security,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            NATIVE_VISIBILITY_STATUS,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            INTEL_DOMAIN_CONTEXT,
            TopicLayer::Context,
            PriorityLane::P3Low,
            &v1,
        ),
        topic(
            INTEL_IP_CONTEXT,
            TopicLayer::Context,
            PriorityLane::P3Low,
            &v1,
        ),
        topic(
            INTEL_CLOUD_CONTEXT,
            TopicLayer::Context,
            PriorityLane::P3Low,
            &v1,
        ),
        topic(
            ASSET_EXPOSURE,
            TopicLayer::Context,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            SECURITY_OBSERVATION,
            TopicLayer::Security,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            SECURITY_VISIBILITY_DEGRADED,
            TopicLayer::Security,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            SECURITY_VISIBILITY_STATUS,
            TopicLayer::Security,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            SECURITY_FUSION_CONTEXT,
            TopicLayer::Security,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            SECURITY_FACT,
            TopicLayer::Security,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            SECURITY_HYPOTHESIS,
            TopicLayer::Security,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            SECURITY_FUSION_SUMMARY,
            TopicLayer::Security,
            PriorityLane::P2Normal,
            &v1,
        ),
        topic(
            SECURITY_FINDING,
            TopicLayer::Security,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            SECURITY_EVIDENCE,
            TopicLayer::Security,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            SECURITY_RISK,
            TopicLayer::Security,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            SECURITY_ALERT,
            TopicLayer::Security,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            SECURITY_INCIDENT,
            TopicLayer::Security,
            PriorityLane::P0Critical,
            &v1,
        )
        .protected(),
        topic(GRAPH_HINT, TopicLayer::Graph, PriorityLane::P2Normal, &v1),
        topic(GRAPH_UPDATE, TopicLayer::Graph, PriorityLane::P3Low, &v1),
        topic(GRAPH_PATH, TopicLayer::Graph, PriorityLane::P3Low, &v1),
        topic(
            RESPONSE_PLAN,
            TopicLayer::Response,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            RESPONSE_POLICY_DECISION,
            TopicLayer::Response,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            RESPONSE_APPROVAL_REQUEST,
            TopicLayer::Response,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            RESPONSE_APPROVAL_RESULT,
            TopicLayer::Response,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            RESPONSE_RESULT,
            TopicLayer::Response,
            PriorityLane::P0Critical,
            &v1,
        )
        .protected(),
        topic(
            RESPONSE_ROLLBACK_RESULT,
            TopicLayer::Response,
            PriorityLane::P0Critical,
            &v1,
        )
        .protected(),
        topic(
            OPERATIONAL_HEALTH,
            TopicLayer::Operational,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            OPERATIONAL_METRIC,
            TopicLayer::Operational,
            PriorityLane::P3Low,
            &v1,
        ),
        topic(
            AUDIT_EVENT,
            TopicLayer::Audit,
            PriorityLane::P0Critical,
            &v1,
        )
        .protected(),
        topic(
            AUDIT_NATIVE_PERMISSION,
            TopicLayer::Audit,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            AUDIT_NATIVE_SAMPLER_REVIEW,
            TopicLayer::Audit,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            AUDIT_NATIVE_SAMPLER_RUNTIME,
            TopicLayer::Audit,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            AUDIT_NATIVE_SCHEDULER,
            TopicLayer::Audit,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            AUDIT_NATIVE_SCHEDULER_HOST,
            TopicLayer::Audit,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
        topic(
            REPORT_GENERATED,
            TopicLayer::Report,
            PriorityLane::P4BestEffort,
            &v1,
        ),
        topic(
            REPORT_EXPORTED,
            TopicLayer::Report,
            PriorityLane::P1High,
            &v1,
        )
        .protected(),
    ]
}

fn topic(
    name: &str,
    layer: TopicLayer,
    priority: PriorityLane,
    schema_version: &SchemaVersion,
) -> Topic {
    Topic::new(
        TopicName::new(name).expect("core topic names are valid"),
        layer,
        schema_version.clone(),
        priority,
    )
}

fn is_topic_char(value: char) -> bool {
    value.is_ascii_lowercase() || value.is_ascii_digit() || value == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_control_plane_status_topics_are_declared_without_telemetry_topics() {
        let topics = core_v1_topics()
            .into_iter()
            .map(|topic| topic.name.to_string())
            .collect::<Vec<_>>();
        for expected in [
            NATIVE_CAPABILITY_STATUS,
            NATIVE_PERMISSION_STATUS,
            NATIVE_VISIBILITY_STATUS,
            NATIVE_SCHEDULER_CYCLE_STARTED,
            NATIVE_SCHEDULER_CYCLE_COMPLETED,
            NATIVE_SCHEDULER_CYCLE_SKIPPED,
            NATIVE_SCHEDULER_EXECUTION_CONTROL,
            NATIVE_SCHEDULER_BACKPRESSURE,
            NATIVE_SCHEDULER_FRESHNESS,
            NATIVE_SCHEDULER_MISSED_SAMPLE,
            NATIVE_SCHEDULER_HOST_STATUS,
            NATIVE_SCHEDULER_HOST_STARTED,
            NATIVE_SCHEDULER_HOST_WAKE,
            NATIVE_SCHEDULER_HOST_PAUSED,
            NATIVE_SCHEDULER_HOST_RESUMED,
            NATIVE_SCHEDULER_HOST_STOPPED,
            NATIVE_SCHEDULER_HOST_FAILED,
            SECURITY_VISIBILITY_DEGRADED,
            AUDIT_NATIVE_PERMISSION,
            AUDIT_NATIVE_SCHEDULER_HOST,
        ] {
            assert!(topics.iter().any(|topic| topic == expected));
        }
        assert!(!topics.iter().any(|topic| topic == "native.telemetry"));
        assert!(!topics.iter().any(|topic| topic == "native.process.record"));
    }
}
