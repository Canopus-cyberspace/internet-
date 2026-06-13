use crate::event_bus::TopicName;
use crate::observability::{AuditSink, MetricsSink};
use crate::permissions::{PermissionScope, PolicyScope};
use crate::plugin_runtime::policy::{
    CheckpointSupport, FailurePolicy, ReplaySupport, ResourceQuota, TimeoutPolicy,
};
use sentinel_contracts::{
    PermissionKey, PluginId, PrivacyClass, RuntimeMode, SchemaVersion, Timestamp, TraceContext,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeContext {
    pub plugin_id: PluginId,
    pub runtime_mode: RuntimeMode,
    pub lifecycle_state: PluginLifecycleState,
    pub resource_quota: ResourceQuota,
    pub timeout_policy: TimeoutPolicy,
    pub failure_policy: FailurePolicy,
    pub schema_version: SchemaVersion,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl RuntimeContext {
    pub fn new(plugin_id: PluginId, runtime_mode: RuntimeMode) -> Self {
        let now = Timestamp::now();
        Self {
            resource_quota: ResourceQuota::static_internal_default(&runtime_mode),
            timeout_policy: TimeoutPolicy::default(),
            failure_policy: FailurePolicy::default(),
            plugin_id,
            runtime_mode,
            lifecycle_state: PluginLifecycleState::Discovered,
            schema_version: SchemaVersion::new(1, 0, 0),
            created_at: now.clone(),
            updated_at: now,
        }
    }

    pub fn transition_to(&mut self, state: PluginLifecycleState) {
        self.lifecycle_state = state;
        self.updated_at = Timestamp::now();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginLifecycleState {
    Discovered,
    Registered,
    Initialized,
    Starting,
    Running,
    Degraded,
    Stopping,
    Stopped,
    Disabled,
    Failed,
    Incompatible,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicScope {
    pub subscribe_topics: HashSet<TopicName>,
    pub publish_topics: HashSet<TopicName>,
}

impl TopicScope {
    pub fn can_subscribe(&self, topic: &TopicName) -> bool {
        self.subscribe_topics.contains(topic)
    }

    pub fn can_publish(&self, topic: &TopicName) -> bool {
        self.publish_topics.contains(topic)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageScope {
    pub logical_store_names: HashSet<String>,
    pub metadata_only: bool,
    pub raw_sql_allowed: bool,
    pub unscoped_filesystem_allowed: bool,
}

impl StorageScope {
    pub fn metadata_only(logical_store_names: impl IntoIterator<Item = String>) -> Self {
        Self {
            logical_store_names: logical_store_names.into_iter().collect(),
            metadata_only: true,
            raw_sql_allowed: false,
            unscoped_filesystem_allowed: false,
        }
    }
}

impl Default for StorageScope {
    fn default() -> Self {
        Self::metadata_only(Vec::<String>::new())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionGrantScope {
    pub required_permissions: HashSet<PermissionKey>,
    pub granted_permissions: HashSet<PermissionKey>,
}

impl PermissionGrantScope {
    pub fn has_grant(&self, permission: &PermissionKey) -> bool {
        self.granted_permissions.contains(permission)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginPrivacyContext {
    pub privacy_class: PrivacyClass,
    pub metadata_only: bool,
    pub normal_mode: bool,
    pub raw_packet_persistence_allowed: bool,
    pub payload_persistence_allowed: bool,
    pub http_body_persistence_allowed: bool,
    pub secret_material_persistence_allowed: bool,
    pub export_gate_required: bool,
}

impl PluginPrivacyContext {
    pub fn normal_metadata_only() -> Self {
        Self {
            privacy_class: PrivacyClass::Internal,
            metadata_only: true,
            normal_mode: true,
            raw_packet_persistence_allowed: false,
            payload_persistence_allowed: false,
            http_body_persistence_allowed: false,
            secret_material_persistence_allowed: false,
            export_gate_required: true,
        }
    }

    pub fn raw_content_persistence_forbidden(&self) -> bool {
        !self.raw_packet_persistence_allowed
            && !self.payload_persistence_allowed
            && !self.http_body_persistence_allowed
            && !self.secret_material_persistence_allowed
    }
}

pub struct PluginContext<'a> {
    pub runtime: RuntimeContext,
    pub topic_scope: TopicScope,
    pub storage_scope: StorageScope,
    pub permission_scope: PermissionGrantScope,
    pub policy_scope: PolicyScope,
    pub current_permission_scope: Option<PermissionScope>,
    pub trace_context: TraceContext,
    pub metrics_sink: Option<&'a mut dyn MetricsSink>,
    pub audit_sink: Option<&'a mut dyn AuditSink>,
    pub checkpoint: CheckpointSupport,
    pub replay: ReplaySupport,
    pub privacy: PluginPrivacyContext,
}

impl<'a> PluginContext<'a> {
    pub fn new(
        plugin_id: PluginId,
        runtime_mode: RuntimeMode,
        trace_context: TraceContext,
    ) -> Self {
        Self {
            runtime: RuntimeContext::new(plugin_id, runtime_mode),
            topic_scope: TopicScope::default(),
            storage_scope: StorageScope::default(),
            permission_scope: PermissionGrantScope::default(),
            policy_scope: PolicyScope::Plugin,
            current_permission_scope: None,
            trace_context,
            metrics_sink: None,
            audit_sink: None,
            checkpoint: CheckpointSupport::none(),
            replay: ReplaySupport::from_manifest_level(sentinel_contracts::SupportLevel::None),
            privacy: PluginPrivacyContext::normal_metadata_only(),
        }
    }

    pub fn replay_safe(&self) -> bool {
        self.replay.real_response_forbidden()
            && self.replay.online_lookup_forbidden()
            && !self.runtime.resource_quota.allow_response_execution
            && !self.runtime.resource_quota.allow_online_lookup
    }
}
