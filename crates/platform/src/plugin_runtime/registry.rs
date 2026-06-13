use crate::component::ComponentId;
use crate::permissions::{
    permission_scope_for_descriptor, PermissionDecision, PermissionDecisionKind, PermissionRequest,
    PermissionResolver, PermissionSubject, PolicyScope,
};
use crate::plugin_runtime::context::{PluginLifecycleState, RuntimeContext};
use crate::plugin_runtime::policy::{
    CheckpointSupport, FailureMode, FailurePolicy, ReplaySupport, ResourceQuota, TimeoutPolicy,
};
use crate::plugin_runtime::traits::PluginRuntimeError;
use crate::registry::ContractRegistry;
use crate::resolver::{
    ContractResolver, ResolutionIssue, ResolutionIssueKind, ResolutionReport, ResolutionSeverity,
    ResolutionStatus,
};
use sentinel_contracts::{CapabilityManifest, PluginId, PluginManifest, RuntimeMode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginRuntimeKind {
    StaticInternal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PluginRuntimeDescriptor {
    pub runtime_kind: PluginRuntimeKind,
    pub manifest: PluginManifest,
    pub capability_manifest: Option<CapabilityManifest>,
    pub component_id: Option<ComponentId>,
    pub runtime_context: RuntimeContext,
    pub resource_quota: ResourceQuota,
    pub timeout_policy: TimeoutPolicy,
    pub failure_policy: FailurePolicy,
    pub checkpoint: CheckpointSupport,
    pub replay: ReplaySupport,
    pub failure_count: u32,
}

impl PluginRuntimeDescriptor {
    pub fn static_internal(
        manifest: PluginManifest,
        capability_manifest: Option<CapabilityManifest>,
        component_id: Option<ComponentId>,
    ) -> Self {
        let runtime_mode = manifest.runtime_mode.clone();
        Self {
            runtime_kind: PluginRuntimeKind::StaticInternal,
            runtime_context: RuntimeContext::new(manifest.plugin_id.clone(), runtime_mode.clone()),
            resource_quota: ResourceQuota::static_internal_default(&runtime_mode),
            timeout_policy: TimeoutPolicy::default(),
            failure_policy: FailurePolicy::default(),
            checkpoint: CheckpointSupport::from_manifest_level(manifest.checkpoint_support.clone()),
            replay: ReplaySupport::from_manifest_level(manifest.replay_support.clone()),
            manifest,
            capability_manifest,
            component_id,
            failure_count: 0,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PluginRuntimeRegistry {
    descriptors: HashMap<PluginId, PluginRuntimeDescriptor>,
}

impl PluginRuntimeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_static(
        &mut self,
        descriptor: PluginRuntimeDescriptor,
    ) -> Result<(), PluginRuntimeError> {
        descriptor
            .manifest
            .validate()
            .map_err(|error| PluginRuntimeError::ManifestInvalid(error.to_string()))?;

        let plugin_id = descriptor.manifest.plugin_id.clone();
        if self.descriptors.contains_key(&plugin_id) {
            return Err(PluginRuntimeError::DuplicatePlugin(plugin_id));
        }

        self.descriptors.insert(plugin_id, descriptor);
        Ok(())
    }

    pub fn get(&self, plugin_id: &PluginId) -> Option<&PluginRuntimeDescriptor> {
        self.descriptors.get(plugin_id)
    }

    pub fn get_mut(&mut self, plugin_id: &PluginId) -> Option<&mut PluginRuntimeDescriptor> {
        self.descriptors.get_mut(plugin_id)
    }

    pub fn list(&self) -> Vec<&PluginRuntimeDescriptor> {
        let mut descriptors = self.descriptors.values().collect::<Vec<_>>();
        descriptors.sort_by_key(|descriptor| descriptor.manifest.plugin_id.to_string());
        descriptors
    }

    pub fn validate_startup(
        &self,
        plugin_id: &PluginId,
        contract_registry: &ContractRegistry,
        permission_resolver: &PermissionResolver,
    ) -> Result<PluginStartupValidation, PluginRuntimeError> {
        let descriptor = self
            .get(plugin_id)
            .ok_or_else(|| PluginRuntimeError::MissingPlugin(plugin_id.clone()))?;
        let manifest = &descriptor.manifest;
        let contract_report =
            ContractResolver::new().resolve_plugin_manifest(manifest, contract_registry);
        let mut issues = contract_report.issues.clone();
        let mut permission_decisions = Vec::new();

        for descriptor in &manifest.required_permissions {
            let request = PermissionRequest::new(
                PermissionSubject::Plugin(manifest.plugin_id.clone()),
                descriptor.permission.clone(),
                permission_scope_for_descriptor(descriptor),
                PolicyScope::Plugin,
                "plugin startup permission validation",
            );
            let decision = permission_resolver.evaluate_permission(request, None);
            if !matches!(decision.decision, PermissionDecisionKind::Allow) {
                issues.push(permission_issue(manifest.plugin_id.clone(), &decision));
            }
            permission_decisions.push(decision);
        }

        let status = ResolutionStatus::from_issues(&issues);

        Ok(PluginStartupValidation {
            plugin_id: manifest.plugin_id.clone(),
            allowed: matches!(status, ResolutionStatus::Compatible),
            status,
            contract_report,
            permission_decisions,
            issues,
        })
    }

    pub fn transition(
        &mut self,
        plugin_id: &PluginId,
        state: PluginLifecycleState,
    ) -> Result<(), PluginRuntimeError> {
        let descriptor = self
            .get_mut(plugin_id)
            .ok_or_else(|| PluginRuntimeError::MissingPlugin(plugin_id.clone()))?;
        descriptor.runtime_context.transition_to(state);
        Ok(())
    }

    pub fn record_failure(
        &mut self,
        plugin_id: &PluginId,
        error_redacted: impl Into<String>,
    ) -> Result<PluginLifecycleState, PluginRuntimeError> {
        let descriptor = self
            .get_mut(plugin_id)
            .ok_or_else(|| PluginRuntimeError::MissingPlugin(plugin_id.clone()))?;
        descriptor.failure_count = descriptor.failure_count.saturating_add(1);
        let next_state = match descriptor.failure_policy.mode {
            FailureMode::MarkDegraded | FailureMode::RestartWithinLimit
                if descriptor.failure_count
                    < descriptor.failure_policy.max_failures_before_disable =>
            {
                PluginLifecycleState::Degraded
            }
            FailureMode::DisablePlugin => PluginLifecycleState::Disabled,
            FailureMode::RestartWithinLimit
            | FailureMode::MarkFailed
            | FailureMode::MarkDegraded => PluginLifecycleState::Failed,
        };

        let _ = error_redacted.into();
        descriptor.runtime_context.transition_to(next_state.clone());
        Ok(next_state)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PluginStartupValidation {
    pub plugin_id: PluginId,
    pub allowed: bool,
    pub status: ResolutionStatus,
    pub contract_report: ResolutionReport,
    pub permission_decisions: Vec<PermissionDecision>,
    pub issues: Vec<ResolutionIssue>,
}

impl PluginStartupValidation {
    pub fn allowed(plugin_id: PluginId) -> Self {
        Self {
            plugin_id,
            allowed: true,
            status: ResolutionStatus::Compatible,
            contract_report: ResolutionReport::from_issues(Vec::new()),
            permission_decisions: Vec::new(),
            issues: Vec::new(),
        }
    }

    pub fn blocker_reasons(&self) -> Vec<String> {
        self.issues
            .iter()
            .filter(|issue| issue.severity == ResolutionSeverity::Blocker)
            .map(|issue| issue.message.clone())
            .collect()
    }
}

fn permission_issue(plugin_id: PluginId, decision: &PermissionDecision) -> ResolutionIssue {
    ResolutionIssue::blocker(
        ResolutionIssueKind::MissingPermission,
        format!(
            "plugin permission {} is not granted for startup",
            decision.permission
        ),
    )
    .for_plugin(plugin_id)
    .for_dependency(decision.permission.to_string())
}

pub fn scheduler_kind_for_runtime_mode(
    runtime_mode: &RuntimeMode,
) -> crate::pipeline::SchedulerKind {
    match runtime_mode {
        RuntimeMode::Streaming | RuntimeMode::Hybrid => crate::pipeline::SchedulerKind::Realtime,
        RuntimeMode::Batch => crate::pipeline::SchedulerKind::Batch,
        RuntimeMode::Periodic => crate::pipeline::SchedulerKind::Periodic,
        RuntimeMode::OnDemand => crate::pipeline::SchedulerKind::Priority,
        RuntimeMode::Replay => crate::pipeline::SchedulerKind::Replay,
    }
}
