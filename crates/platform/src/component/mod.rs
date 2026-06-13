use sentinel_contracts::{
    CapabilityId, ContractDescriptor, ContractId, HealthSchema, MaturityLevel, MetricSchema,
    PermissionDescriptor, PermissionKey, PluginDependencyType, PluginId, PrivacyClass,
    RendererType, RuntimeMode, SchemaVersion, Timestamp, UiContributionId, UiContributionSlot,
    VersionRange,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentIdParseError {
    value: String,
}

impl ComponentIdParseError {
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for ComponentIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid ComponentId UUID: {}", self.value)
    }
}

impl std::error::Error for ComponentIdParseError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ComponentId(Uuid);

impl ComponentId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub fn parse_str(value: &str) -> Result<Self, ComponentIdParseError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| ComponentIdParseError {
                value: value.to_string(),
            })
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for ComponentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for ComponentId {
    fn from(value: Uuid) -> Self {
        Self::from_uuid(value)
    }
}

impl FromStr for ComponentId {
    type Err = ComponentIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_str(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentType {
    PlatformKernel,
    Plugin,
    Capability,
    ServiceAdapter,
    Store,
    InfrastructureAdapter,
    PermissionResolver,
    DependencyResolver,
    ContractResolver,
    HealthReporter,
    MetricsReporter,
    Visualization,
    Settings,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    Unknown,
    Discovered,
    Validated,
    Registered,
    Initialized,
    Enabled,
    Starting,
    Running,
    Degraded,
    Paused,
    Stopping,
    Stopped,
    Disabled,
    Failed,
    Incompatible,
    Upgrading,
    RollingBack,
}

impl ComponentState {
    pub fn allows_direct_transition_to(&self, target: &Self) -> bool {
        match (self, target) {
            (Self::Unknown, Self::Discovered) => true,
            (
                Self::Discovered,
                Self::Validated | Self::Incompatible | Self::Disabled | Self::Failed,
            ) => true,
            (
                Self::Validated,
                Self::Registered | Self::Incompatible | Self::Disabled | Self::Failed,
            ) => true,
            (Self::Registered, Self::Initialized | Self::Disabled | Self::Failed) => true,
            (Self::Initialized, Self::Enabled | Self::Disabled | Self::Failed) => true,
            (Self::Enabled, Self::Starting | Self::Disabled | Self::Failed) => true,
            (Self::Starting, Self::Running | Self::Degraded | Self::Stopped | Self::Failed) => true,
            (
                Self::Running,
                Self::Degraded
                | Self::Paused
                | Self::Stopping
                | Self::Upgrading
                | Self::Disabled
                | Self::Failed,
            ) => true,
            (
                Self::Degraded,
                Self::Running | Self::Paused | Self::Stopping | Self::Disabled | Self::Failed,
            ) => true,
            (
                Self::Paused,
                Self::Running | Self::Stopping | Self::Stopped | Self::Disabled | Self::Failed,
            ) => true,
            (Self::Stopping, Self::Stopped | Self::Failed) => true,
            (Self::Stopped, Self::Starting | Self::Disabled | Self::Failed) => true,
            (Self::Disabled, Self::Enabled | Self::Discovered | Self::Failed) => true,
            (Self::Failed, Self::Starting | Self::Disabled | Self::Discovered) => true,
            (
                Self::Incompatible,
                Self::Disabled | Self::Discovered | Self::Validated | Self::Failed,
            ) => true,
            (Self::Upgrading, Self::Running | Self::RollingBack | Self::Failed) => true,
            (Self::RollingBack, Self::Running | Self::Disabled | Self::Failed) => true,
            (current, next) if current == next => true,
            _ => false,
        }
    }

    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Running | Self::Degraded)
    }

    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failed | Self::Incompatible)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentMetadata {
    pub name: String,
    pub version: String,
    pub schema_version: SchemaVersion,
    pub owner: Option<String>,
    pub description: Option<String>,
    pub capability_tags: Vec<String>,
    pub runtime_mode: RuntimeMode,
    pub maturity_level: Option<MaturityLevel>,
    pub privacy_class: PrivacyClass,
    pub contract_refs: Vec<ContractId>,
    pub permission_refs: Vec<PermissionKey>,
    pub dependency_refs: Vec<String>,
    pub metric_refs: Vec<String>,
    pub health_refs: Vec<String>,
    pub visualization_refs: Vec<UiContributionId>,
}

impl ComponentMetadata {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        runtime_mode: RuntimeMode,
    ) -> Result<Self, ComponentLifecycleError> {
        Ok(Self {
            name: require_non_empty("component name", name.into())?,
            version: require_non_empty("component version", version.into())?,
            schema_version: SchemaVersion::new(1, 0, 0),
            owner: None,
            description: None,
            capability_tags: Vec::new(),
            runtime_mode,
            maturity_level: None,
            privacy_class: PrivacyClass::Internal,
            contract_refs: Vec::new(),
            permission_refs: Vec::new(),
            dependency_refs: Vec::new(),
            metric_refs: Vec::new(),
            health_refs: Vec::new(),
            visualization_refs: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityBinding {
    pub capability_id: CapabilityId,
    pub capability_name: String,
    pub required: bool,
    pub contract_refs: Vec<ContractId>,
    pub binding_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractBinding {
    pub contract: ContractDescriptor,
    pub required: bool,
    pub compatibility_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyBinding {
    pub dependency_type: PluginDependencyType,
    pub dependency_component_id: Option<ComponentId>,
    pub dependency_plugin_id: Option<PluginId>,
    pub dependency_capability_id: Option<CapabilityId>,
    pub dependency_name: Option<String>,
    pub version_requirement: VersionRange,
    pub required: bool,
    pub resolved: bool,
    pub resolution_reason: Option<String>,
    pub incompatibility_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionBinding {
    pub permission: PermissionDescriptor,
    pub required: bool,
    pub granted: bool,
    pub grant_reason: Option<String>,
    pub denial_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthReference {
    pub status: HealthStatus,
    pub schema: Option<HealthSchema>,
    pub liveness_ref: Option<String>,
    pub readiness_ref: Option<String>,
    pub degraded_reasons: Vec<String>,
    pub failure_reasons: Vec<String>,
    pub last_reported_at: Option<Timestamp>,
}

impl Default for HealthReference {
    fn default() -> Self {
        Self {
            status: HealthStatus::Unknown,
            schema: None,
            liveness_ref: None,
            readiness_ref: None,
            degraded_reasons: Vec::new(),
            failure_reasons: Vec::new(),
            last_reported_at: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricReference {
    pub metric_name: String,
    pub schema: Option<MetricSchema>,
    pub source_ref: Option<String>,
    pub privacy_class: PrivacyClass,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisualizationBinding {
    pub contribution_id: Option<UiContributionId>,
    pub slot: Option<UiContributionSlot>,
    pub renderer_type: RendererType,
    pub title: String,
    pub description: Option<String>,
    pub fallback_allowed: bool,
}

impl VisualizationBinding {
    pub fn fallback_allowed(renderer_type: RendererType, title: impl Into<String>) -> Self {
        Self {
            contribution_id: None,
            slot: None,
            renderer_type,
            title: title.into(),
            description: None,
            fallback_allowed: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComponentDefinition {
    pub component_id: ComponentId,
    pub component_type: ComponentType,
    pub metadata: ComponentMetadata,
    pub capability_bindings: Vec<CapabilityBinding>,
    pub contract_bindings: Vec<ContractBinding>,
    pub dependency_bindings: Vec<DependencyBinding>,
    pub permission_bindings: Vec<PermissionBinding>,
    pub health_reference: HealthReference,
    pub metric_references: Vec<MetricReference>,
    pub visualization_bindings: Vec<VisualizationBinding>,
    pub compatibility_reasons: Vec<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl ComponentDefinition {
    pub fn new(
        component_type: ComponentType,
        name: impl Into<String>,
        version: impl Into<String>,
        runtime_mode: RuntimeMode,
    ) -> Result<Self, ComponentLifecycleError> {
        let now = Timestamp::now();

        Ok(Self {
            component_id: ComponentId::new_v4(),
            component_type,
            metadata: ComponentMetadata::new(name, version, runtime_mode)?,
            capability_bindings: Vec::new(),
            contract_bindings: Vec::new(),
            dependency_bindings: Vec::new(),
            permission_bindings: Vec::new(),
            health_reference: HealthReference::default(),
            metric_references: Vec::new(),
            visualization_bindings: Vec::new(),
            compatibility_reasons: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn add_contract_binding(&mut self, binding: ContractBinding) {
        self.metadata
            .contract_refs
            .push(binding.contract.contract_id.clone());
        self.contract_bindings.push(binding);
        self.updated_at = Timestamp::now();
    }

    pub fn add_dependency_binding(&mut self, binding: DependencyBinding) {
        if let Some(name) = &binding.dependency_name {
            self.metadata.dependency_refs.push(name.clone());
        }
        self.dependency_bindings.push(binding);
        self.updated_at = Timestamp::now();
    }

    pub fn add_permission_binding(&mut self, binding: PermissionBinding) {
        self.metadata
            .permission_refs
            .push(binding.permission.permission.clone());
        self.permission_bindings.push(binding);
        self.updated_at = Timestamp::now();
    }

    pub fn add_metric_reference(&mut self, reference: MetricReference) {
        self.metadata
            .metric_refs
            .push(reference.metric_name.clone());
        self.metric_references.push(reference);
        self.updated_at = Timestamp::now();
    }

    pub fn set_health_reference(&mut self, reference: HealthReference) {
        if let Some(liveness_ref) = &reference.liveness_ref {
            self.metadata.health_refs.push(liveness_ref.clone());
        }
        if let Some(readiness_ref) = &reference.readiness_ref {
            self.metadata.health_refs.push(readiness_ref.clone());
        }
        self.health_reference = reference;
        self.updated_at = Timestamp::now();
    }

    pub fn add_visualization_binding(&mut self, binding: VisualizationBinding) {
        if let Some(contribution_id) = &binding.contribution_id {
            self.metadata
                .visualization_refs
                .push(contribution_id.clone());
        }
        self.visualization_bindings.push(binding);
        self.updated_at = Timestamp::now();
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComponentInstance {
    pub instance_id: ComponentId,
    pub component_id: ComponentId,
    pub component_type: ComponentType,
    pub state: ComponentState,
    pub health_status: HealthStatus,
    pub lifecycle_history: Vec<LifecycleTransition>,
    pub dependency_reasons: Vec<String>,
    pub permission_reasons: Vec<String>,
    pub compatibility_reasons: Vec<String>,
    pub last_error_redacted: Option<String>,
    pub started_at: Option<Timestamp>,
    pub stopped_at: Option<Timestamp>,
    pub updated_at: Timestamp,
}

impl ComponentInstance {
    pub fn from_definition(definition: &ComponentDefinition) -> Self {
        let now = Timestamp::now();

        Self {
            instance_id: ComponentId::new_v4(),
            component_id: definition.component_id.clone(),
            component_type: definition.component_type.clone(),
            state: ComponentState::Discovered,
            health_status: HealthStatus::Unknown,
            lifecycle_history: Vec::new(),
            dependency_reasons: Vec::new(),
            permission_reasons: Vec::new(),
            compatibility_reasons: definition.compatibility_reasons.clone(),
            last_error_redacted: None,
            started_at: None,
            stopped_at: None,
            updated_at: now,
        }
    }

    pub fn transition_to(
        &mut self,
        target: ComponentState,
        context: TransitionContext,
    ) -> Result<LifecycleTransition, ComponentLifecycleError> {
        let validation = validate_lifecycle_transition(&self.state, &target, &context);
        let transition = LifecycleTransition {
            from: self.state.clone(),
            to: target.clone(),
            requested_at: Timestamp::now(),
            reason: context.reason.clone(),
            validation: validation.clone(),
            health_status: next_health_status(&target, &context.health_status),
        };

        if !validation.allowed {
            return Err(ComponentLifecycleError::InvalidTransition {
                from: self.state.clone(),
                to: target,
                reasons: validation.denied_reasons,
            });
        }

        self.state = target.clone();
        self.health_status = transition.health_status.clone();
        self.dependency_reasons = context.dependency_reasons;
        self.permission_reasons = context.permission_reasons;
        self.compatibility_reasons = context.compatibility_reasons;
        self.updated_at = Timestamp::now();

        match target {
            ComponentState::Running => self.started_at = Some(self.updated_at.clone()),
            ComponentState::Stopped | ComponentState::Disabled | ComponentState::Failed => {
                self.stopped_at = Some(self.updated_at.clone())
            }
            _ => {}
        }

        self.lifecycle_history.push(transition.clone());
        Ok(transition)
    }

    pub fn record_failure(&mut self, error_redacted: impl Into<String>, reason: impl Into<String>) {
        let reason = reason.into();
        let transition = LifecycleTransition {
            from: self.state.clone(),
            to: ComponentState::Failed,
            requested_at: Timestamp::now(),
            reason: Some(reason.clone()),
            validation: TransitionValidation::allowed(),
            health_status: HealthStatus::Failed,
        };

        self.state = ComponentState::Failed;
        self.health_status = HealthStatus::Failed;
        self.last_error_redacted = Some(error_redacted.into());
        self.compatibility_reasons.clear();
        self.dependency_reasons.clear();
        self.permission_reasons.clear();
        self.updated_at = Timestamp::now();
        self.stopped_at = Some(self.updated_at.clone());
        self.lifecycle_history.push(transition);
    }

    pub fn mark_degraded(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<LifecycleTransition, ComponentLifecycleError> {
        let reason = reason.into();
        let context = TransitionContext {
            reason: Some(reason.clone()),
            health_status: HealthStatus::Degraded,
            dependency_reasons: vec![reason],
            ..TransitionContext::default()
        };

        self.transition_to(ComponentState::Degraded, context)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleTransition {
    pub from: ComponentState,
    pub to: ComponentState,
    pub requested_at: Timestamp,
    pub reason: Option<String>,
    pub validation: TransitionValidation,
    pub health_status: HealthStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionContext {
    pub reason: Option<String>,
    pub dependencies_satisfied: bool,
    pub permissions_granted: bool,
    pub compatible: bool,
    pub health_status: HealthStatus,
    pub dependency_reasons: Vec<String>,
    pub permission_reasons: Vec<String>,
    pub compatibility_reasons: Vec<String>,
}

impl TransitionContext {
    pub fn with_reason(reason: impl Into<String>) -> Self {
        Self {
            reason: Some(reason.into()),
            ..Self::default()
        }
    }
}

impl Default for TransitionContext {
    fn default() -> Self {
        Self {
            reason: None,
            dependencies_satisfied: true,
            permissions_granted: true,
            compatible: true,
            health_status: HealthStatus::Unknown,
            dependency_reasons: Vec::new(),
            permission_reasons: Vec::new(),
            compatibility_reasons: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionValidation {
    pub allowed: bool,
    pub denied_reasons: Vec<String>,
    pub dependency_reasons: Vec<String>,
    pub permission_reasons: Vec<String>,
    pub compatibility_reasons: Vec<String>,
}

impl TransitionValidation {
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            denied_reasons: Vec::new(),
            dependency_reasons: Vec::new(),
            permission_reasons: Vec::new(),
            compatibility_reasons: Vec::new(),
        }
    }
}

pub fn validate_lifecycle_transition(
    from: &ComponentState,
    to: &ComponentState,
    context: &TransitionContext,
) -> TransitionValidation {
    let mut denied_reasons = Vec::new();

    if !from.allows_direct_transition_to(to) {
        denied_reasons.push(format!("invalid transition from {from:?} to {to:?}"));
    }

    if !context.compatible && !allows_incompatible_target(to) {
        push_reasons_or_default(
            &mut denied_reasons,
            &context.compatibility_reasons,
            "component is incompatible",
        );
    }

    if !context.dependencies_satisfied && requires_dependencies(to) {
        push_reasons_or_default(
            &mut denied_reasons,
            &context.dependency_reasons,
            "component dependencies are not satisfied",
        );
    }

    if !context.permissions_granted && requires_permissions(to) {
        push_reasons_or_default(
            &mut denied_reasons,
            &context.permission_reasons,
            "component permissions are not granted",
        );
    }

    if matches!(to, ComponentState::Running)
        && matches!(context.health_status, HealthStatus::Failed)
    {
        denied_reasons.push("component health is failed".to_string());
    }

    TransitionValidation {
        allowed: denied_reasons.is_empty(),
        denied_reasons,
        dependency_reasons: context.dependency_reasons.clone(),
        permission_reasons: context.permission_reasons.clone(),
        compatibility_reasons: context.compatibility_reasons.clone(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComponentLifecycleError {
    InvalidDefinition {
        field: &'static str,
    },
    InvalidTransition {
        from: ComponentState,
        to: ComponentState,
        reasons: Vec<String>,
    },
}

impl fmt::Display for ComponentLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDefinition { field } => {
                write!(f, "invalid component definition field: {field}")
            }
            Self::InvalidTransition { from, to, reasons } => {
                write!(
                    f,
                    "invalid component transition from {from:?} to {to:?}: {}",
                    reasons.join("; ")
                )
            }
        }
    }
}

impl std::error::Error for ComponentLifecycleError {}

fn require_non_empty(
    field: &'static str,
    value: String,
) -> Result<String, ComponentLifecycleError> {
    if value.trim().is_empty() {
        Err(ComponentLifecycleError::InvalidDefinition { field })
    } else {
        Ok(value)
    }
}

fn requires_dependencies(state: &ComponentState) -> bool {
    matches!(
        state,
        ComponentState::Registered
            | ComponentState::Initialized
            | ComponentState::Enabled
            | ComponentState::Starting
            | ComponentState::Running
            | ComponentState::Degraded
            | ComponentState::Paused
            | ComponentState::Upgrading
    )
}

fn requires_permissions(state: &ComponentState) -> bool {
    matches!(
        state,
        ComponentState::Enabled
            | ComponentState::Starting
            | ComponentState::Running
            | ComponentState::Degraded
            | ComponentState::Paused
            | ComponentState::Upgrading
    )
}

fn allows_incompatible_target(state: &ComponentState) -> bool {
    matches!(
        state,
        ComponentState::Incompatible
            | ComponentState::Disabled
            | ComponentState::Failed
            | ComponentState::Stopped
    )
}

fn push_reasons_or_default(target: &mut Vec<String>, reasons: &[String], fallback: &str) {
    if reasons.is_empty() {
        target.push(fallback.to_string());
    } else {
        target.extend(reasons.iter().cloned());
    }
}

fn next_health_status(target: &ComponentState, requested: &HealthStatus) -> HealthStatus {
    if !matches!(requested, HealthStatus::Unknown) {
        return requested.clone();
    }

    match target {
        ComponentState::Running => HealthStatus::Healthy,
        ComponentState::Degraded => HealthStatus::Degraded,
        ComponentState::Failed => HealthStatus::Failed,
        _ => HealthStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        ContractDescriptor, MetricKind, PermissionCategory, PermissionRiskLevel,
    };

    #[test]
    fn component_id_serializes_as_json_string() {
        let component_id = ComponentId::new_v4();
        let json = serde_json::to_string(&component_id).expect("serialize component id");

        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
        assert_eq!(
            serde_json::from_str::<ComponentId>(&json).expect("deserialize component id"),
            component_id
        );
    }

    #[test]
    fn state_model_includes_required_states() {
        let states = [
            ComponentState::Discovered,
            ComponentState::Validated,
            ComponentState::Registered,
            ComponentState::Initialized,
            ComponentState::Enabled,
            ComponentState::Running,
            ComponentState::Degraded,
            ComponentState::Paused,
            ComponentState::Stopped,
            ComponentState::Disabled,
            ComponentState::Failed,
            ComponentState::Starting,
            ComponentState::Incompatible,
        ];

        assert!(states.contains(&ComponentState::Running));
        assert!(states.contains(&ComponentState::Incompatible));
    }

    #[test]
    fn valid_lifecycle_path_reaches_running() {
        let definition = ComponentDefinition::new(
            ComponentType::Plugin,
            "flow-observer",
            "0.1.0",
            RuntimeMode::Streaming,
        )
        .expect("valid definition");
        let mut instance = ComponentInstance::from_definition(&definition);

        for state in [
            ComponentState::Validated,
            ComponentState::Registered,
            ComponentState::Initialized,
            ComponentState::Enabled,
            ComponentState::Starting,
            ComponentState::Running,
        ] {
            instance
                .transition_to(state, TransitionContext::default())
                .expect("valid lifecycle transition");
        }

        assert_eq!(instance.state, ComponentState::Running);
        assert_eq!(instance.health_status, HealthStatus::Healthy);
        assert_eq!(instance.lifecycle_history.len(), 6);
    }

    #[test]
    fn invalid_transition_is_rejected() {
        let definition = ComponentDefinition::new(
            ComponentType::Plugin,
            "flow-observer",
            "0.1.0",
            RuntimeMode::Streaming,
        )
        .expect("valid definition");
        let mut instance = ComponentInstance::from_definition(&definition);

        let error = instance
            .transition_to(ComponentState::Running, TransitionContext::default())
            .expect_err("discovered cannot jump directly to running");

        match error {
            ComponentLifecycleError::InvalidTransition { from, to, reasons } => {
                assert_eq!(from, ComponentState::Discovered);
                assert_eq!(to, ComponentState::Running);
                assert!(!reasons.is_empty());
            }
            other => panic!("unexpected error: {other}"),
        }
        assert_eq!(instance.state, ComponentState::Discovered);
    }

    #[test]
    fn dependency_permission_and_compatibility_context_blocks_transition() {
        let context = TransitionContext {
            dependencies_satisfied: false,
            permissions_granted: false,
            compatible: false,
            dependency_reasons: vec!["missing dependency: network.source".to_string()],
            permission_reasons: vec!["missing permission: network.read".to_string()],
            compatibility_reasons: vec!["contract version unsupported".to_string()],
            ..TransitionContext::default()
        };

        let validation = validate_lifecycle_transition(
            &ComponentState::Enabled,
            &ComponentState::Starting,
            &context,
        );

        assert!(!validation.allowed);
        assert!(validation
            .denied_reasons
            .contains(&"missing dependency: network.source".to_string()));
        assert!(validation
            .denied_reasons
            .contains(&"missing permission: network.read".to_string()));
        assert!(validation
            .denied_reasons
            .contains(&"contract version unsupported".to_string()));
    }

    #[test]
    fn failure_marks_component_failed_without_panicking() {
        let definition = ComponentDefinition::new(
            ComponentType::ServiceAdapter,
            "elevated-service-adapter",
            "0.1.0",
            RuntimeMode::OnDemand,
        )
        .expect("valid definition");
        let mut instance = ComponentInstance::from_definition(&definition);

        instance.record_failure(
            "redacted service startup error",
            "startup health check failed",
        );

        assert_eq!(instance.state, ComponentState::Failed);
        assert_eq!(instance.health_status, HealthStatus::Failed);
        assert_eq!(
            instance.last_error_redacted.as_deref(),
            Some("redacted service startup error")
        );
        assert_eq!(instance.lifecycle_history.len(), 1);
    }

    #[test]
    fn metadata_references_contracts_permissions_dependencies_metrics_health_and_visualization() {
        let mut definition = ComponentDefinition::new(
            ComponentType::Plugin,
            "component-catalog",
            "0.1.0",
            RuntimeMode::OnDemand,
        )
        .expect("valid definition");

        let contract = ContractDescriptor::new("plugin.catalog", SchemaVersion::new(1, 0, 0))
            .expect("contract descriptor");
        let contract_id = contract.contract_id.clone();
        definition.add_contract_binding(ContractBinding {
            contract,
            required: true,
            compatibility_reason: None,
        });

        let permission_key = PermissionKey::new("plugin.catalog.read").expect("permission key");
        definition.add_permission_binding(PermissionBinding {
            permission: PermissionDescriptor::new(
                permission_key.clone(),
                PermissionCategory::DataAccess,
                PermissionRiskLevel::Low,
                "read plugin catalog metadata",
            )
            .expect("permission descriptor"),
            required: true,
            granted: true,
            grant_reason: Some("safe metadata-only read".to_string()),
            denial_reason: None,
        });

        definition.add_dependency_binding(DependencyBinding {
            dependency_type: PluginDependencyType::RequiredContract,
            dependency_component_id: None,
            dependency_plugin_id: None,
            dependency_capability_id: None,
            dependency_name: Some("contracts.plugin_manifest".to_string()),
            version_requirement: VersionRange::any(),
            required: true,
            resolved: true,
            resolution_reason: Some("contract available".to_string()),
            incompatibility_reason: None,
        });

        definition.add_metric_reference(MetricReference {
            metric_name: "component.catalog.count".to_string(),
            schema: Some(
                MetricSchema::new(
                    "component.catalog.count",
                    MetricKind::Gauge,
                    "number of visible components",
                )
                .expect("metric schema"),
            ),
            source_ref: Some("component-center".to_string()),
            privacy_class: PrivacyClass::Internal,
        });

        definition.set_health_reference(HealthReference {
            status: HealthStatus::Healthy,
            schema: Some(HealthSchema::default()),
            liveness_ref: Some("component-catalog.liveness".to_string()),
            readiness_ref: Some("component-catalog.readiness".to_string()),
            degraded_reasons: Vec::new(),
            failure_reasons: Vec::new(),
            last_reported_at: Some(Timestamp::now()),
        });

        definition.add_visualization_binding(VisualizationBinding {
            contribution_id: Some(UiContributionId::new_v4()),
            slot: Some(UiContributionSlot::ComponentCenterCard),
            renderer_type: RendererType::HealthBadge,
            title: "Component health".to_string(),
            description: None,
            fallback_allowed: true,
        });

        assert!(definition.metadata.contract_refs.contains(&contract_id));
        assert!(definition
            .metadata
            .permission_refs
            .contains(&permission_key));
        assert!(definition
            .metadata
            .dependency_refs
            .contains(&"contracts.plugin_manifest".to_string()));
        assert!(definition
            .metadata
            .metric_refs
            .contains(&"component.catalog.count".to_string()));
        assert!(definition
            .metadata
            .health_refs
            .contains(&"component-catalog.liveness".to_string()));
        assert_eq!(definition.metadata.visualization_refs.len(), 1);
    }
}
