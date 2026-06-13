use crate::component::{
    ComponentDefinition, ComponentId, ComponentInstance, ComponentState, DependencyBinding,
    HealthStatus,
};
use sentinel_contracts::{
    CapabilityId, CapabilityManifest, ContractDescriptor, ContractId, PermissionKey,
    PluginDependency, PluginId, PluginManifest, RuntimeMode, SchemaVersion, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    DuplicateRegistration {
        registry: &'static str,
        key: String,
    },
    MissingRegistration {
        registry: &'static str,
        key: String,
    },
    InvalidRegistration {
        registry: &'static str,
        reason: String,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateRegistration { registry, key } => {
                write!(f, "duplicate registration in {registry}: {key}")
            }
            Self::MissingRegistration { registry, key } => {
                write!(f, "missing registration in {registry}: {key}")
            }
            Self::InvalidRegistration { registry, reason } => {
                write!(f, "invalid registration in {registry}: {reason}")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryValidation {
    pub valid: bool,
    pub issues: Vec<String>,
}

impl RegistryValidation {
    pub fn valid() -> Self {
        Self {
            valid: true,
            issues: Vec::new(),
        }
    }

    pub fn from_issues(issues: Vec<String>) -> Self {
        Self {
            valid: issues.is_empty(),
            issues,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ComponentRegistry {
    components: HashMap<ComponentId, ComponentDefinition>,
    instances: HashMap<ComponentId, ComponentInstance>,
}

impl ComponentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, definition: ComponentDefinition) -> Result<(), RegistryError> {
        validate_component_definition(&definition)?;
        let component_id = definition.component_id.clone();

        if self.components.contains_key(&component_id) {
            return Err(RegistryError::DuplicateRegistration {
                registry: "component_registry",
                key: component_id.to_string(),
            });
        }

        self.components.insert(component_id, definition);
        Ok(())
    }

    pub fn register_instance(&mut self, instance: ComponentInstance) -> Result<(), RegistryError> {
        if !self.components.contains_key(&instance.component_id) {
            return Err(RegistryError::MissingRegistration {
                registry: "component_registry",
                key: instance.component_id.to_string(),
            });
        }

        if self.instances.contains_key(&instance.instance_id) {
            return Err(RegistryError::DuplicateRegistration {
                registry: "component_instance_registry",
                key: instance.instance_id.to_string(),
            });
        }

        self.instances
            .insert(instance.instance_id.clone(), instance);
        Ok(())
    }

    pub fn get(&self, component_id: &ComponentId) -> Option<&ComponentDefinition> {
        self.components.get(component_id)
    }

    pub fn get_instance(&self, instance_id: &ComponentId) -> Option<&ComponentInstance> {
        self.instances.get(instance_id)
    }

    pub fn contains(&self, component_id: &ComponentId) -> bool {
        self.components.contains_key(component_id)
    }

    pub fn list(&self) -> Vec<&ComponentDefinition> {
        let mut components = self.components.values().collect::<Vec<_>>();
        components.sort_by_key(|component| component.component_id.to_string());
        components
    }

    pub fn list_instances(&self) -> Vec<&ComponentInstance> {
        let mut instances = self.instances.values().collect::<Vec<_>>();
        instances.sort_by_key(|instance| instance.instance_id.to_string());
        instances
    }

    pub fn find_by_name(&self, name: &str) -> Vec<&ComponentDefinition> {
        let mut matches = self
            .components
            .values()
            .filter(|component| component.metadata.name == name)
            .collect::<Vec<_>>();
        matches.sort_by_key(|component| component.component_id.to_string());
        matches
    }

    pub fn validate(&self) -> RegistryValidation {
        let mut issues = Vec::new();

        for definition in self.components.values() {
            if let Err(error) = validate_component_definition(definition) {
                issues.push(error.to_string());
            }
        }

        for instance in self.instances.values() {
            if !self.components.contains_key(&instance.component_id) {
                issues.push(format!(
                    "instance {} references missing component {}",
                    instance.instance_id, instance.component_id
                ));
            }
        }

        RegistryValidation::from_issues(issues)
    }
}

#[derive(Clone, Debug, Default)]
pub struct PluginRegistry {
    plugins: HashMap<PluginId, PluginManifest>,
    component_by_plugin: HashMap<PluginId, ComponentId>,
    plugin_by_component: HashMap<ComponentId, PluginId>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        manifest: PluginManifest,
        component_id: Option<ComponentId>,
    ) -> Result<(), RegistryError> {
        manifest
            .validate()
            .map_err(|error| RegistryError::InvalidRegistration {
                registry: "plugin_registry",
                reason: error.to_string(),
            })?;

        let plugin_id = manifest.plugin_id.clone();
        if self.plugins.contains_key(&plugin_id) {
            return Err(RegistryError::DuplicateRegistration {
                registry: "plugin_registry",
                key: plugin_id.to_string(),
            });
        }

        if let Some(component_id) = component_id {
            if self.plugin_by_component.contains_key(&component_id) {
                return Err(RegistryError::DuplicateRegistration {
                    registry: "plugin_component_binding",
                    key: component_id.to_string(),
                });
            }
            self.component_by_plugin
                .insert(plugin_id.clone(), component_id.clone());
            self.plugin_by_component
                .insert(component_id, plugin_id.clone());
        }

        self.plugins.insert(plugin_id, manifest);
        Ok(())
    }

    pub fn get(&self, plugin_id: &PluginId) -> Option<&PluginManifest> {
        self.plugins.get(plugin_id)
    }

    pub fn contains(&self, plugin_id: &PluginId) -> bool {
        self.plugins.contains_key(plugin_id)
    }

    pub fn list(&self) -> Vec<&PluginManifest> {
        let mut plugins = self.plugins.values().collect::<Vec<_>>();
        plugins.sort_by_key(|plugin| plugin.plugin_id.to_string());
        plugins
    }

    pub fn component_id_for_plugin(&self, plugin_id: &PluginId) -> Option<&ComponentId> {
        self.component_by_plugin.get(plugin_id)
    }

    pub fn plugin_id_for_component(&self, component_id: &ComponentId) -> Option<&PluginId> {
        self.plugin_by_component.get(component_id)
    }

    pub fn find_by_name(&self, plugin_name: &str) -> Option<&PluginManifest> {
        self.plugins
            .values()
            .find(|plugin| plugin.plugin_name == plugin_name)
    }

    pub fn validate(&self) -> RegistryValidation {
        let mut issues = Vec::new();

        for plugin in self.plugins.values() {
            if let Err(error) = plugin.validate() {
                issues.push(format!("plugin {}: {error}", plugin.plugin_id));
            }
        }

        RegistryValidation::from_issues(issues)
    }
}

#[derive(Clone, Debug, Default)]
pub struct CapabilityRegistry {
    capabilities: HashMap<CapabilityId, CapabilityManifest>,
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, manifest: CapabilityManifest) -> Result<(), RegistryError> {
        validate_capability_manifest(&manifest)?;
        let capability_id = manifest.capability_id.clone();

        if self.capabilities.contains_key(&capability_id) {
            return Err(RegistryError::DuplicateRegistration {
                registry: "capability_registry",
                key: capability_id.to_string(),
            });
        }

        self.capabilities.insert(capability_id, manifest);
        Ok(())
    }

    pub fn get(&self, capability_id: &CapabilityId) -> Option<&CapabilityManifest> {
        self.capabilities.get(capability_id)
    }

    pub fn contains(&self, capability_id: &CapabilityId) -> bool {
        self.capabilities.contains_key(capability_id)
    }

    pub fn list(&self) -> Vec<&CapabilityManifest> {
        let mut capabilities = self.capabilities.values().collect::<Vec<_>>();
        capabilities.sort_by_key(|capability| capability.capability_id.to_string());
        capabilities
    }

    pub fn find_by_domain(&self, capability_domain: &str) -> Option<&CapabilityManifest> {
        self.capabilities
            .values()
            .find(|capability| capability.capability_domain == capability_domain)
    }

    pub fn validate(&self) -> RegistryValidation {
        let mut issues = Vec::new();

        for capability in self.capabilities.values() {
            if let Err(error) = validate_capability_manifest(capability) {
                issues.push(error.to_string());
            }
        }

        RegistryValidation::from_issues(issues)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ContractRegistry {
    contracts: HashMap<ContractId, ContractDescriptor>,
    contracts_by_name: HashMap<String, Vec<ContractId>>,
}

impl ContractRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, descriptor: ContractDescriptor) -> Result<(), RegistryError> {
        if descriptor.contract_name.trim().is_empty() {
            return Err(RegistryError::InvalidRegistration {
                registry: "contract_registry",
                reason: "contract_name must not be empty".to_string(),
            });
        }

        let contract_id = descriptor.contract_id.clone();
        if self.contracts.contains_key(&contract_id) {
            return Err(RegistryError::DuplicateRegistration {
                registry: "contract_registry",
                key: contract_id.to_string(),
            });
        }

        self.contracts_by_name
            .entry(descriptor.contract_name.clone())
            .or_default()
            .push(contract_id.clone());
        self.contracts.insert(contract_id, descriptor);
        Ok(())
    }

    pub fn get(&self, contract_id: &ContractId) -> Option<&ContractDescriptor> {
        self.contracts.get(contract_id)
    }

    pub fn contains(&self, contract_id: &ContractId) -> bool {
        self.contracts.contains_key(contract_id)
    }

    pub fn find_by_name(&self, contract_name: &str) -> Vec<&ContractDescriptor> {
        self.contracts_by_name
            .get(contract_name)
            .map(|ids| {
                let mut descriptors = ids
                    .iter()
                    .filter_map(|id| self.contracts.get(id))
                    .collect::<Vec<_>>();
                descriptors.sort_by_key(|descriptor| {
                    (
                        descriptor.schema_version.major,
                        descriptor.schema_version.minor,
                        descriptor.schema_version.patch,
                    )
                });
                descriptors
            })
            .unwrap_or_default()
    }

    pub fn list(&self) -> Vec<&ContractDescriptor> {
        let mut contracts = self.contracts.values().collect::<Vec<_>>();
        contracts.sort_by_key(|contract| {
            (
                contract.contract_name.clone(),
                contract.schema_version.major,
                contract.schema_version.minor,
                contract.schema_version.patch,
            )
        });
        contracts
    }
}

#[derive(Clone, Debug, Default)]
pub struct DependencyRegistry {
    component_dependencies: HashMap<ComponentId, Vec<DependencyBinding>>,
    plugin_dependencies: HashMap<PluginId, Vec<PluginDependency>>,
}

impl DependencyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_component_definition(&mut self, definition: &ComponentDefinition) {
        self.component_dependencies.insert(
            definition.component_id.clone(),
            definition.dependency_bindings.clone(),
        );
    }

    pub fn register_plugin_manifest(&mut self, manifest: &PluginManifest) {
        self.plugin_dependencies
            .insert(manifest.plugin_id.clone(), manifest.dependencies.clone());
    }

    pub fn dependencies_for_component(&self, component_id: &ComponentId) -> &[DependencyBinding] {
        self.component_dependencies
            .get(component_id)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn dependencies_for_plugin(&self, plugin_id: &PluginId) -> &[PluginDependency] {
        self.plugin_dependencies
            .get(plugin_id)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn component_entries(&self) -> Vec<(&ComponentId, &[DependencyBinding])> {
        let mut entries = self
            .component_dependencies
            .iter()
            .map(|(component_id, dependencies)| (component_id, dependencies.as_slice()))
            .collect::<Vec<_>>();
        entries.sort_by_key(|(component_id, _)| component_id.to_string());
        entries
    }

    pub fn plugin_entries(&self) -> Vec<(&PluginId, &[PluginDependency])> {
        let mut entries = self
            .plugin_dependencies
            .iter()
            .map(|(plugin_id, dependencies)| (plugin_id, dependencies.as_slice()))
            .collect::<Vec<_>>();
        entries.sort_by_key(|(plugin_id, _)| plugin_id.to_string());
        entries
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteBinding {
    pub route_key: String,
    pub source_component_id: ComponentId,
    pub target_component_id: Option<ComponentId>,
    pub topic: String,
    pub contract_id: Option<ContractId>,
    pub required_permissions: Vec<PermissionKey>,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default)]
pub struct RouteRegistry {
    routes: HashMap<String, RouteBinding>,
}

impl RouteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, binding: RouteBinding) -> Result<(), RegistryError> {
        if binding.route_key.trim().is_empty() || binding.topic.trim().is_empty() {
            return Err(RegistryError::InvalidRegistration {
                registry: "route_registry",
                reason: "route_key and topic must not be empty".to_string(),
            });
        }

        if self.routes.contains_key(&binding.route_key) {
            return Err(RegistryError::DuplicateRegistration {
                registry: "route_registry",
                key: binding.route_key,
            });
        }

        self.routes.insert(binding.route_key.clone(), binding);
        Ok(())
    }

    pub fn get(&self, route_key: &str) -> Option<&RouteBinding> {
        self.routes.get(route_key)
    }

    pub fn list(&self) -> Vec<&RouteBinding> {
        let mut routes = self.routes.values().collect::<Vec<_>>();
        routes.sort_by_key(|route| route.route_key.clone());
        routes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBinding {
    pub policy_key: String,
    pub component_id: Option<ComponentId>,
    pub plugin_id: Option<PluginId>,
    pub permission_refs: Vec<PermissionKey>,
    pub enabled: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyRegistry {
    policies: HashMap<String, PolicyBinding>,
}

impl PolicyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, binding: PolicyBinding) -> Result<(), RegistryError> {
        if binding.policy_key.trim().is_empty() {
            return Err(RegistryError::InvalidRegistration {
                registry: "policy_registry",
                reason: "policy_key must not be empty".to_string(),
            });
        }

        if self.policies.contains_key(&binding.policy_key) {
            return Err(RegistryError::DuplicateRegistration {
                registry: "policy_registry",
                key: binding.policy_key,
            });
        }

        self.policies.insert(binding.policy_key.clone(), binding);
        Ok(())
    }

    pub fn get(&self, policy_key: &str) -> Option<&PolicyBinding> {
        self.policies.get(policy_key)
    }

    pub fn list(&self) -> Vec<&PolicyBinding> {
        let mut policies = self.policies.values().collect::<Vec<_>>();
        policies.sort_by_key(|policy| policy.policy_key.clone());
        policies
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeMetadata {
    pub component_id: ComponentId,
    pub plugin_id: Option<PluginId>,
    pub runtime_mode: RuntimeMode,
    pub component_state: ComponentState,
    pub health_status: HealthStatus,
    pub metadata_version: SchemaVersion,
    pub last_resolved_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Default)]
pub struct RuntimeRegistry {
    runtimes: HashMap<ComponentId, RuntimeMetadata>,
}

impl RuntimeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, metadata: RuntimeMetadata) -> Result<(), RegistryError> {
        if self.runtimes.contains_key(&metadata.component_id) {
            return Err(RegistryError::DuplicateRegistration {
                registry: "runtime_registry",
                key: metadata.component_id.to_string(),
            });
        }

        self.runtimes
            .insert(metadata.component_id.clone(), metadata);
        Ok(())
    }

    pub fn get(&self, component_id: &ComponentId) -> Option<&RuntimeMetadata> {
        self.runtimes.get(component_id)
    }

    pub fn list(&self) -> Vec<&RuntimeMetadata> {
        let mut runtimes = self.runtimes.values().collect::<Vec<_>>();
        runtimes.sort_by_key(|runtime| runtime.component_id.to_string());
        runtimes
    }
}

fn validate_component_definition(definition: &ComponentDefinition) -> Result<(), RegistryError> {
    if definition.metadata.name.trim().is_empty() {
        return Err(RegistryError::InvalidRegistration {
            registry: "component_registry",
            reason: "component name must not be empty".to_string(),
        });
    }

    if definition.metadata.version.trim().is_empty() {
        return Err(RegistryError::InvalidRegistration {
            registry: "component_registry",
            reason: "component version must not be empty".to_string(),
        });
    }

    Ok(())
}

fn validate_capability_manifest(manifest: &CapabilityManifest) -> Result<(), RegistryError> {
    if manifest.capability_domain.trim().is_empty() {
        return Err(RegistryError::InvalidRegistration {
            registry: "capability_registry",
            reason: "capability_domain must not be empty".to_string(),
        });
    }

    if manifest.title.trim().is_empty() {
        return Err(RegistryError::InvalidRegistration {
            registry: "capability_registry",
            reason: "capability title must not be empty".to_string(),
        });
    }

    Ok(())
}
