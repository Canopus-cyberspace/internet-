use super::*;
use crate::permissions::{PermissionResolver, PermissionSubject};
use crate::registry::ContractRegistry;
use sentinel_contracts::{
    ContractDescriptor, PermissionCategory, PermissionDescriptor, PermissionKey,
    PermissionRiskLevel, PluginId, PluginManifest, PluginType, RuntimeMode, SchemaVersion,
    TraceContext,
};

struct NoopPlugin {
    manifest: PluginManifest,
    fail_start: bool,
}

impl NoopPlugin {
    fn new(name: &str) -> Self {
        let mut manifest = PluginManifest::new(
            PluginId::new_v4(),
            name,
            "0.1.0",
            "test.capability",
            PluginType::Utility,
            RuntimeMode::Streaming,
        )
        .expect("manifest");
        manifest
            .output_contracts
            .push(contract("plugin.output", SchemaVersion::new(1, 0, 0)));

        Self {
            manifest,
            fail_start: false,
        }
    }
}

impl PluginLifecycle for NoopPlugin {
    fn start(&mut self, _context: &mut PluginContext<'_>) -> PluginResult<()> {
        if self.fail_start {
            return Err(PluginRuntimeError::LifecycleFailed {
                plugin_id: self.manifest.plugin_id.clone(),
                phase: "start",
                error_redacted: "redacted startup failure".to_string(),
            });
        }
        Ok(())
    }
}

impl InternalPlugin for NoopPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

#[test]
fn static_internal_plugin_exposes_manifest_and_lifecycle_hooks() {
    let plugin = NoopPlugin::new("noop");
    let plugin_id = plugin.manifest.plugin_id.clone();
    let mut runtime = PluginRuntime::new();
    let registered_id = runtime
        .register_static_plugin(Box::new(plugin))
        .expect("register plugin");
    let validation = PluginStartupValidation::allowed(plugin_id.clone());
    let mut context = PluginContext::new(
        plugin_id.clone(),
        RuntimeMode::Streaming,
        TraceContext::new_root(),
    );

    runtime
        .start_plugin(&plugin_id, &validation, &mut context)
        .expect("start plugin");

    assert_eq!(registered_id, plugin_id);
    assert_eq!(
        runtime
            .registry()
            .get(&plugin_id)
            .expect("descriptor")
            .runtime_context
            .lifecycle_state,
        PluginLifecycleState::Running
    );
}

#[test]
fn plugin_context_is_scoped_and_privacy_safe() {
    let plugin_id = PluginId::new_v4();
    let mut context = PluginContext::new(
        plugin_id.clone(),
        RuntimeMode::Hybrid,
        TraceContext::new_root(),
    );
    let topic = crate::event_bus::TopicName::new("security.finding").expect("topic");
    let permission = PermissionKey::new("write.finding").expect("permission");
    context.topic_scope.publish_topics.insert(topic.clone());
    context
        .storage_scope
        .logical_store_names
        .insert("findings".to_string());
    context
        .permission_scope
        .granted_permissions
        .insert(permission.clone());

    assert_eq!(context.runtime.plugin_id, plugin_id);
    assert!(context.topic_scope.can_publish(&topic));
    assert!(context.permission_scope.has_grant(&permission));
    assert!(context.storage_scope.metadata_only);
    assert!(!context.storage_scope.raw_sql_allowed);
    assert!(!context.runtime.resource_quota.allow_elevated_service);
    assert!(!context.runtime.resource_quota.allow_response_execution);
    assert!(context.privacy.raw_content_persistence_forbidden());
}

#[test]
fn contract_mismatch_or_missing_permission_blocks_startup() {
    let mut plugin = NoopPlugin::new("blocked");
    plugin
        .manifest
        .input_contracts
        .push(contract("network.flow.record", SchemaVersion::new(2, 0, 0)));
    plugin.manifest.required_permissions.push(
        PermissionDescriptor::new(
            PermissionKey::new("read.event.flow").expect("permission"),
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
            "read flow metadata",
        )
        .expect("descriptor"),
    );
    let plugin_id = plugin.manifest.plugin_id.clone();
    let mut registry = PluginRuntimeRegistry::new();
    registry
        .register_static(PluginRuntimeDescriptor::static_internal(
            plugin.manifest,
            None,
            None,
        ))
        .expect("register descriptor");

    let mut contracts = ContractRegistry::new();
    contracts
        .register(contract("network.flow.record", SchemaVersion::new(1, 0, 0)))
        .expect("register v1 contract");
    let permissions = PermissionResolver::new();

    let validation = registry
        .validate_startup(&plugin_id, &contracts, &permissions)
        .expect("validate startup");

    assert!(!validation.allowed);
    assert_eq!(
        validation.status,
        crate::resolver::ResolutionStatus::Incompatible
    );
    assert!(validation
        .issues
        .iter()
        .any(|issue| issue.kind == crate::resolver::ResolutionIssueKind::UnsupportedContract));
    assert!(validation
        .issues
        .iter()
        .any(|issue| issue.kind == crate::resolver::ResolutionIssueKind::MissingPermission));
}

#[test]
fn granted_metadata_permission_allows_startup_when_contracts_match() {
    let mut plugin = NoopPlugin::new("allowed");
    let permission_descriptor = PermissionDescriptor::new(
        PermissionKey::new("read.event.flow").expect("permission"),
        PermissionCategory::DataAccess,
        PermissionRiskLevel::Low,
        "read flow metadata",
    )
    .expect("descriptor");
    plugin
        .manifest
        .required_permissions
        .push(permission_descriptor.clone());
    let plugin_id = plugin.manifest.plugin_id.clone();

    let mut registry = PluginRuntimeRegistry::new();
    registry
        .register_static(PluginRuntimeDescriptor::static_internal(
            plugin.manifest,
            None,
            None,
        ))
        .expect("register descriptor");

    let mut contracts = ContractRegistry::new();
    contracts
        .register(contract("plugin.output", SchemaVersion::new(1, 0, 0)))
        .expect("register contract");
    let mut permissions = PermissionResolver::new();
    permissions.register_descriptor(&permission_descriptor);
    permissions.grant(
        PermissionSubject::Plugin(plugin_id.clone()),
        permission_descriptor.permission.clone(),
    );

    let validation = registry
        .validate_startup(&plugin_id, &contracts, &permissions)
        .expect("validate startup");

    assert!(validation.allowed);
}

#[test]
fn replay_context_disables_online_lookup_and_real_response_execution() {
    let replay = ReplaySupport::from_manifest_level(sentinel_contracts::SupportLevel::Required)
        .with_context(crate::pipeline::ReplayContext::new(
            crate::pipeline::ReplayScope::Event,
            "replay validation",
        ));

    assert!(replay.real_response_forbidden());
    assert!(replay.online_lookup_forbidden());
}

#[test]
fn plugin_failure_degrades_without_panicking() {
    let mut plugin = NoopPlugin::new("failing");
    plugin.fail_start = true;
    let plugin_id = plugin.manifest.plugin_id.clone();
    let mut runtime = PluginRuntime::new();
    runtime
        .register_static_plugin(Box::new(plugin))
        .expect("register plugin");
    let validation = PluginStartupValidation::allowed(plugin_id.clone());
    let mut context = PluginContext::new(
        plugin_id.clone(),
        RuntimeMode::Streaming,
        TraceContext::new_root(),
    );

    let error = runtime
        .start_plugin(&plugin_id, &validation, &mut context)
        .expect_err("startup failure is returned");

    assert!(matches!(
        error,
        PluginRuntimeError::LifecycleFailed { phase: "start", .. }
    ));
    assert_eq!(
        runtime
            .registry()
            .get(&plugin_id)
            .expect("descriptor")
            .runtime_context
            .lifecycle_state,
        PluginLifecycleState::Degraded
    );
}

#[test]
fn event_batches_enforce_resource_limits() {
    let plugin_id = PluginId::new_v4();
    let mut batch = PluginEventBatch::new(plugin_id, 0);
    let envelope = sentinel_contracts::EventEnvelope::new(
        sentinel_contracts::EventType::new("network.flow.record").expect("event type"),
        SchemaVersion::new(1, 0, 0),
        PluginId::new_v4(),
        TraceContext::new_root(),
    );

    assert!(matches!(
        batch.push(envelope),
        Err(PluginRuntimeError::BatchLimitExceeded { max_events: 0 })
    ));
}

fn contract(name: &str, version: SchemaVersion) -> ContractDescriptor {
    ContractDescriptor::new(name, version).expect("contract")
}
