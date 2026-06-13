use crate::component::{ComponentDefinition, ComponentId, DependencyBinding};
use crate::registry::{
    CapabilityRegistry, ComponentRegistry, ContractRegistry, DependencyRegistry, PluginRegistry,
};
use sentinel_contracts::{
    CapabilityId, ContractCompatibilityRequirement, ContractDescriptor, PluginDependency,
    PluginDependencyType, PluginId, PluginManifest, SchemaCompatibility, SchemaVersion,
    VersionRange,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionSeverity {
    Info,
    Warning,
    Blocker,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionIssueKind {
    MissingDependency,
    DependencyCycle,
    IncompatibleVersion,
    Conflict,
    MissingPermission,
    UnsupportedContract,
    CoreVersionMismatch,
    MissingCapability,
    MissingComponent,
    InvalidManifest,
    StartupOrdering,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResolutionIssue {
    pub severity: ResolutionSeverity,
    pub kind: ResolutionIssueKind,
    pub component_id: Option<ComponentId>,
    pub plugin_id: Option<PluginId>,
    pub capability_id: Option<CapabilityId>,
    pub contract_name: Option<String>,
    pub dependency_name: Option<String>,
    pub message: String,
}

impl ResolutionIssue {
    pub fn blocker(kind: ResolutionIssueKind, message: impl Into<String>) -> Self {
        Self::new(ResolutionSeverity::Blocker, kind, message)
    }

    pub fn warning(kind: ResolutionIssueKind, message: impl Into<String>) -> Self {
        Self::new(ResolutionSeverity::Warning, kind, message)
    }

    pub fn info(kind: ResolutionIssueKind, message: impl Into<String>) -> Self {
        Self::new(ResolutionSeverity::Info, kind, message)
    }

    pub fn for_component(mut self, component_id: ComponentId) -> Self {
        self.component_id = Some(component_id);
        self
    }

    pub fn for_plugin(mut self, plugin_id: PluginId) -> Self {
        self.plugin_id = Some(plugin_id);
        self
    }

    pub fn for_capability(mut self, capability_id: CapabilityId) -> Self {
        self.capability_id = Some(capability_id);
        self
    }

    pub fn for_contract(mut self, contract_name: impl Into<String>) -> Self {
        self.contract_name = Some(contract_name.into());
        self
    }

    pub fn for_dependency(mut self, dependency_name: impl Into<String>) -> Self {
        self.dependency_name = Some(dependency_name.into());
        self
    }

    fn new(
        severity: ResolutionSeverity,
        kind: ResolutionIssueKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            kind,
            component_id: None,
            plugin_id: None,
            capability_id: None,
            contract_name: None,
            dependency_name: None,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    Compatible,
    Degraded,
    Incompatible,
}

impl ResolutionStatus {
    pub fn from_issues(issues: &[ResolutionIssue]) -> Self {
        if issues
            .iter()
            .any(|issue| issue.severity == ResolutionSeverity::Blocker)
        {
            Self::Incompatible
        } else if issues
            .iter()
            .any(|issue| issue.severity == ResolutionSeverity::Warning)
        {
            Self::Degraded
        } else {
            Self::Compatible
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionReport {
    pub status: ResolutionStatus,
    pub issues: Vec<ResolutionIssue>,
}

impl ResolutionReport {
    pub fn from_issues(issues: Vec<ResolutionIssue>) -> Self {
        Self {
            status: ResolutionStatus::from_issues(&issues),
            issues,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedStartupItem {
    pub component_id: ComponentId,
    pub order_index: usize,
    pub explicit_startup_order: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyResolution {
    pub status: ResolutionStatus,
    pub issues: Vec<ResolutionIssue>,
    pub startup_order: Vec<ResolvedStartupItem>,
}

#[derive(Clone, Debug, Default)]
pub struct DependencyResolver;

impl DependencyResolver {
    pub fn new() -> Self {
        Self
    }

    pub fn resolve(
        &self,
        component_registry: &ComponentRegistry,
        plugin_registry: &PluginRegistry,
        capability_registry: &CapabilityRegistry,
        contract_registry: &ContractRegistry,
        dependency_registry: &DependencyRegistry,
        version_resolver: &VersionResolver,
    ) -> DependencyResolution {
        let mut issues = Vec::new();
        let mut edges: HashMap<ComponentId, HashSet<ComponentId>> = HashMap::new();
        let mut explicit_orders: HashMap<ComponentId, u32> = HashMap::new();

        for component in component_registry.list() {
            edges.entry(component.component_id.clone()).or_default();
            self.resolve_component_bindings(
                component,
                component_registry,
                plugin_registry,
                capability_registry,
                version_resolver,
                &mut edges,
                &mut issues,
            );
        }

        for (plugin_id, dependencies) in dependency_registry.plugin_entries() {
            let Some(component_id) = plugin_registry.component_id_for_plugin(plugin_id) else {
                continue;
            };

            for dependency in dependencies {
                if let Some(startup_order) = dependency.startup_order {
                    explicit_orders
                        .entry(component_id.clone())
                        .and_modify(|current| *current = (*current).min(startup_order))
                        .or_insert(startup_order);
                }

                self.resolve_plugin_dependency(
                    component_id,
                    plugin_id,
                    dependency,
                    component_registry,
                    plugin_registry,
                    capability_registry,
                    contract_registry,
                    version_resolver,
                    &mut edges,
                    &mut issues,
                );
            }
        }

        for cycle in detect_cycles(&edges) {
            let names = cycle
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" -> ");
            issues.push(ResolutionIssue::blocker(
                ResolutionIssueKind::DependencyCycle,
                format!("dependency cycle detected: {names}"),
            ));
        }

        let startup_order = compute_startup_order(&edges, &explicit_orders);

        DependencyResolution {
            status: ResolutionStatus::from_issues(&issues),
            issues,
            startup_order,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_component_bindings(
        &self,
        component: &ComponentDefinition,
        component_registry: &ComponentRegistry,
        plugin_registry: &PluginRegistry,
        capability_registry: &CapabilityRegistry,
        version_resolver: &VersionResolver,
        edges: &mut HashMap<ComponentId, HashSet<ComponentId>>,
        issues: &mut Vec<ResolutionIssue>,
    ) {
        for dependency in &component.dependency_bindings {
            let target = resolve_component_dependency_target(
                dependency,
                component_registry,
                plugin_registry,
                capability_registry,
            );

            if matches!(dependency.dependency_type, PluginDependencyType::Conflict) {
                if target.component_id.is_some() || target.capability_exists {
                    issues.push(
                        ResolutionIssue::blocker(
                            ResolutionIssueKind::Conflict,
                            "conflicting dependency is present",
                        )
                        .for_component(component.component_id.clone())
                        .for_dependency(dependency_label(dependency)),
                    );
                }
                continue;
            }

            if let Some(target_component_id) = target.component_id {
                edges
                    .entry(component.component_id.clone())
                    .or_default()
                    .insert(target_component_id.clone());

                if let Some(target_plugin) = target.plugin.as_ref() {
                    let version = version_resolver
                        .version_satisfies(&target_plugin.version, &dependency.version_requirement);
                    if !version.compatible && dependency.required {
                        issues.extend(version.issues.into_iter().map(|issue| {
                            issue
                                .for_component(component.component_id.clone())
                                .for_plugin(target_plugin.plugin_id.clone())
                        }));
                    }
                }
            } else if dependency.required && !target.capability_exists {
                issues.push(
                    ResolutionIssue::blocker(
                        ResolutionIssueKind::MissingDependency,
                        "required component dependency is missing",
                    )
                    .for_component(component.component_id.clone())
                    .for_dependency(dependency_label(dependency)),
                );
            } else if !dependency.required {
                issues.push(
                    ResolutionIssue::warning(
                        ResolutionIssueKind::MissingDependency,
                        "optional component dependency is missing",
                    )
                    .for_component(component.component_id.clone())
                    .for_dependency(dependency_label(dependency)),
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_plugin_dependency(
        &self,
        source_component_id: &ComponentId,
        source_plugin_id: &PluginId,
        dependency: &PluginDependency,
        component_registry: &ComponentRegistry,
        plugin_registry: &PluginRegistry,
        capability_registry: &CapabilityRegistry,
        contract_registry: &ContractRegistry,
        version_resolver: &VersionResolver,
        edges: &mut HashMap<ComponentId, HashSet<ComponentId>>,
        issues: &mut Vec<ResolutionIssue>,
    ) {
        match dependency.dependency_type {
            PluginDependencyType::RequiredPlugin | PluginDependencyType::OptionalPlugin => {
                let target_plugin = resolve_plugin_target(dependency, plugin_registry);
                if let Some(target_plugin) = target_plugin {
                    if let Some(target_component_id) =
                        plugin_registry.component_id_for_plugin(&target_plugin.plugin_id)
                    {
                        edges
                            .entry(source_component_id.clone())
                            .or_default()
                            .insert(target_component_id.clone());
                    }

                    let version = version_resolver
                        .version_satisfies(&target_plugin.version, &dependency.version_requirement);
                    if !version.compatible {
                        issues.extend(version.issues.into_iter().map(|issue| {
                            issue
                                .for_component(source_component_id.clone())
                                .for_plugin(target_plugin.plugin_id.clone())
                        }));
                    }
                } else {
                    push_missing_plugin_dependency(
                        issues,
                        dependency,
                        source_component_id,
                        source_plugin_id,
                    );
                }
            }
            PluginDependencyType::RequiredCapability | PluginDependencyType::OptionalCapability => {
                let target_capability = dependency
                    .capability_id
                    .as_ref()
                    .and_then(|capability_id| capability_registry.get(capability_id))
                    .or_else(|| {
                        dependency
                            .name
                            .as_deref()
                            .and_then(|name| capability_registry.find_by_domain(name))
                    });

                if let Some(capability) = target_capability {
                    for plugin_id in &capability.plugin_ids {
                        if let Some(target_component_id) =
                            plugin_registry.component_id_for_plugin(plugin_id)
                        {
                            edges
                                .entry(source_component_id.clone())
                                .or_default()
                                .insert(target_component_id.clone());
                        }
                    }
                } else {
                    push_missing_capability_dependency(
                        issues,
                        dependency,
                        source_component_id,
                        source_plugin_id,
                    );
                }
            }
            PluginDependencyType::RequiredContract => {
                if let Some(contract) = &dependency.contract {
                    if contract_registry
                        .find_by_name(&contract.contract_name)
                        .is_empty()
                    {
                        issues.push(
                            ResolutionIssue::blocker(
                                ResolutionIssueKind::UnsupportedContract,
                                "required contract dependency is missing",
                            )
                            .for_component(source_component_id.clone())
                            .for_plugin(source_plugin_id.clone())
                            .for_contract(contract.contract_name.clone()),
                        );
                    }
                }
            }
            PluginDependencyType::RequiredInfrastructure | PluginDependencyType::RequiredEngine => {
                let present = dependency
                    .name
                    .as_deref()
                    .is_some_and(|name| !component_registry.find_by_name(name).is_empty());
                if !present {
                    issues.push(
                        ResolutionIssue::blocker(
                            ResolutionIssueKind::MissingDependency,
                            "required platform component dependency is missing",
                        )
                        .for_component(source_component_id.clone())
                        .for_plugin(source_plugin_id.clone())
                        .for_dependency(plugin_dependency_label(dependency)),
                    );
                }
            }
            PluginDependencyType::Conflict => {
                let conflict_present = resolve_plugin_target(dependency, plugin_registry).is_some()
                    || dependency.name.as_deref().is_some_and(|name| {
                        !component_registry.find_by_name(name).is_empty()
                            || capability_registry.find_by_domain(name).is_some()
                    });
                if conflict_present {
                    issues.push(
                        ResolutionIssue::blocker(
                            ResolutionIssueKind::Conflict,
                            "conflicting plugin dependency is present",
                        )
                        .for_component(source_component_id.clone())
                        .for_plugin(source_plugin_id.clone())
                        .for_dependency(plugin_dependency_label(dependency)),
                    );
                }
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ContractResolver;

impl ContractResolver {
    pub fn new() -> Self {
        Self
    }

    pub fn resolve_plugin_manifest(
        &self,
        manifest: &PluginManifest,
        contract_registry: &ContractRegistry,
    ) -> ResolutionReport {
        let mut issues = Vec::new();

        for contract in manifest
            .input_contracts
            .iter()
            .chain(manifest.output_contracts.iter())
        {
            let candidates = contract_registry.find_by_name(&contract.contract_name);
            if candidates.is_empty() {
                if contract.required {
                    issues.push(
                        ResolutionIssue::blocker(
                            ResolutionIssueKind::UnsupportedContract,
                            "required contract is not registered",
                        )
                        .for_plugin(manifest.plugin_id.clone())
                        .for_contract(contract.contract_name.clone()),
                    );
                }
                continue;
            }

            if candidates
                .iter()
                .all(|candidate| !contract_is_compatible(candidate, contract))
            {
                issues.push(
                    ResolutionIssue::blocker(
                        ResolutionIssueKind::UnsupportedContract,
                        "registered contract schema is incompatible",
                    )
                    .for_plugin(manifest.plugin_id.clone())
                    .for_contract(contract.contract_name.clone()),
                );
            }
        }

        ResolutionReport::from_issues(issues)
    }

    pub fn resolve_descriptor(
        &self,
        registered: &ContractDescriptor,
        requested: &ContractDescriptor,
    ) -> ResolutionReport {
        if registered.contract_name != requested.contract_name {
            return ResolutionReport::from_issues(vec![ResolutionIssue::blocker(
                ResolutionIssueKind::UnsupportedContract,
                "contract names do not match",
            )
            .for_contract(requested.contract_name.clone())]);
        }

        if contract_is_compatible(registered, requested) {
            ResolutionReport::from_issues(Vec::new())
        } else {
            ResolutionReport::from_issues(vec![ResolutionIssue::blocker(
                ResolutionIssueKind::UnsupportedContract,
                "contract schema is incompatible",
            )
            .for_contract(requested.contract_name.clone())])
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct VersionResolver;

impl VersionResolver {
    pub fn new() -> Self {
        Self
    }

    pub fn version_satisfies(&self, version: &str, range: &VersionRange) -> VersionResolution {
        let mut issues = Vec::new();

        if let Some(exact) = &range.exact {
            if version != exact {
                issues.push(ResolutionIssue::blocker(
                    ResolutionIssueKind::IncompatibleVersion,
                    format!("version {version} does not match required exact version {exact}"),
                ));
            }
        }

        if let Some(min) = &range.min {
            if !version_at_least(version, min) {
                issues.push(ResolutionIssue::blocker(
                    ResolutionIssueKind::IncompatibleVersion,
                    format!("version {version} is lower than required minimum {min}"),
                ));
            }
        }

        if let Some(max) = &range.max {
            if !version_at_most(version, max) {
                issues.push(ResolutionIssue::blocker(
                    ResolutionIssueKind::IncompatibleVersion,
                    format!("version {version} is higher than supported maximum {max}"),
                ));
            }
        }

        VersionResolution {
            compatible: issues.is_empty(),
            status: ResolutionStatus::from_issues(&issues),
            issues,
        }
    }

    pub fn schema_compatibility(
        &self,
        registered: &SchemaVersion,
        requested: &SchemaVersion,
        requirement: &ContractCompatibilityRequirement,
    ) -> ResolutionStatus {
        if matches!(requirement, ContractCompatibilityRequirement::Strict)
            && registered != requested
        {
            return ResolutionStatus::Incompatible;
        }

        if matches!(
            requirement,
            ContractCompatibilityRequirement::MigrationRequired
        ) {
            return ResolutionStatus::Incompatible;
        }

        match registered.compatibility_with(requested) {
            SchemaCompatibility::Unsupported | SchemaCompatibility::MigrationRequired => {
                ResolutionStatus::Incompatible
            }
            SchemaCompatibility::Deprecated => ResolutionStatus::Degraded,
            SchemaCompatibility::Strict | SchemaCompatibility::BackwardCompatible => {
                ResolutionStatus::Compatible
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionResolution {
    pub compatible: bool,
    pub status: ResolutionStatus,
    pub issues: Vec<ResolutionIssue>,
}

#[derive(Clone, Debug, Default)]
pub struct ConflictResolver;

impl ConflictResolver {
    pub fn new() -> Self {
        Self
    }

    pub fn resolve(
        &self,
        component_registry: &ComponentRegistry,
        plugin_registry: &PluginRegistry,
        capability_registry: &CapabilityRegistry,
        dependency_registry: &DependencyRegistry,
    ) -> ResolutionReport {
        let version_resolver = VersionResolver::new();
        let contract_registry = ContractRegistry::new();
        let resolution = DependencyResolver::new().resolve(
            component_registry,
            plugin_registry,
            capability_registry,
            &contract_registry,
            dependency_registry,
            &version_resolver,
        );
        let conflicts = resolution
            .issues
            .into_iter()
            .filter(|issue| issue.kind == ResolutionIssueKind::Conflict)
            .collect::<Vec<_>>();

        ResolutionReport::from_issues(conflicts)
    }
}

#[derive(Clone, Debug, Default)]
pub struct CapabilityResolver;

impl CapabilityResolver {
    pub fn new() -> Self {
        Self
    }

    pub fn resolve_plugin_manifest(
        &self,
        manifest: &PluginManifest,
        capability_registry: &CapabilityRegistry,
    ) -> CapabilityResolution {
        let mut issues = Vec::new();

        for capability_id in &manifest.required_capabilities {
            if !capability_registry.contains(capability_id) {
                issues.push(
                    ResolutionIssue::blocker(
                        ResolutionIssueKind::MissingCapability,
                        "required capability is missing",
                    )
                    .for_plugin(manifest.plugin_id.clone())
                    .for_capability(capability_id.clone()),
                );
            }
        }

        for capability_id in &manifest.optional_capabilities {
            if !capability_registry.contains(capability_id) {
                issues.push(
                    ResolutionIssue::warning(
                        ResolutionIssueKind::MissingCapability,
                        "optional capability is missing",
                    )
                    .for_plugin(manifest.plugin_id.clone())
                    .for_capability(capability_id.clone()),
                );
            }
        }

        CapabilityResolution {
            status: ResolutionStatus::from_issues(&issues),
            issues,
            required_capabilities: manifest.required_capabilities.clone(),
            optional_capabilities: manifest.optional_capabilities.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityResolution {
    pub status: ResolutionStatus,
    pub issues: Vec<ResolutionIssue>,
    pub required_capabilities: Vec<CapabilityId>,
    pub optional_capabilities: Vec<CapabilityId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactLevel {
    None,
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactAnalysis {
    pub disabled_component_id: ComponentId,
    pub affected_components: Vec<ComponentId>,
    pub affected_plugins: Vec<PluginId>,
    pub affected_capabilities: Vec<CapabilityId>,
    pub issues: Vec<ResolutionIssue>,
    pub impact_level: ImpactLevel,
}

impl ImpactAnalysis {
    pub fn for_disable_component(
        disabled_component_id: ComponentId,
        component_registry: &ComponentRegistry,
        plugin_registry: &PluginRegistry,
        capability_registry: &CapabilityRegistry,
    ) -> Self {
        let mut affected_components = HashSet::new();
        let mut issues = Vec::new();
        let mut changed = true;

        while changed {
            changed = false;

            for component in component_registry.list() {
                if component.component_id == disabled_component_id
                    || affected_components.contains(&component.component_id)
                {
                    continue;
                }

                let depends_on_disabled = component.dependency_bindings.iter().any(|dependency| {
                    dependency_targets_component(
                        dependency,
                        &disabled_component_id,
                        component_registry,
                        plugin_registry,
                    ) || affected_components.iter().any(|affected| {
                        dependency_targets_component(
                            dependency,
                            affected,
                            component_registry,
                            plugin_registry,
                        )
                    })
                });

                if depends_on_disabled {
                    affected_components.insert(component.component_id.clone());
                    issues.push(
                        ResolutionIssue::warning(
                            ResolutionIssueKind::MissingDependency,
                            "component depends on disabled component",
                        )
                        .for_component(component.component_id.clone()),
                    );
                    changed = true;
                }
            }
        }

        let mut affected_components = affected_components.into_iter().collect::<Vec<_>>();
        affected_components.sort_by_key(ToString::to_string);

        let mut affected_plugins = affected_components
            .iter()
            .filter_map(|component_id| plugin_registry.plugin_id_for_component(component_id))
            .cloned()
            .collect::<Vec<_>>();
        affected_plugins.sort_by_key(ToString::to_string);
        affected_plugins.dedup_by_key(|plugin_id| plugin_id.to_string());

        let mut affected_capabilities = capability_registry
            .list()
            .into_iter()
            .filter(|capability| {
                capability
                    .plugin_ids
                    .iter()
                    .any(|plugin_id| affected_plugins.contains(plugin_id))
            })
            .map(|capability| capability.capability_id.clone())
            .collect::<Vec<_>>();
        affected_capabilities.sort_by_key(ToString::to_string);
        affected_capabilities.dedup_by_key(|capability_id| capability_id.to_string());

        let impact_level = match affected_components.len() {
            0 => ImpactLevel::None,
            1 => ImpactLevel::Low,
            2..=3 => ImpactLevel::Medium,
            _ => ImpactLevel::High,
        };

        Self {
            disabled_component_id,
            affected_components,
            affected_plugins,
            affected_capabilities,
            issues,
            impact_level,
        }
    }
}

#[derive(Default)]
struct DependencyTarget<'a> {
    component_id: Option<ComponentId>,
    plugin: Option<&'a PluginManifest>,
    capability_exists: bool,
}

fn resolve_component_dependency_target<'a>(
    dependency: &DependencyBinding,
    component_registry: &'a ComponentRegistry,
    plugin_registry: &'a PluginRegistry,
    capability_registry: &'a CapabilityRegistry,
) -> DependencyTarget<'a> {
    if let Some(component_id) = &dependency.dependency_component_id {
        return DependencyTarget {
            component_id: component_registry
                .contains(component_id)
                .then_some(component_id.clone()),
            plugin: plugin_registry
                .plugin_id_for_component(component_id)
                .and_then(|plugin_id| plugin_registry.get(plugin_id)),
            capability_exists: false,
        };
    }

    if let Some(plugin_id) = &dependency.dependency_plugin_id {
        let plugin = plugin_registry.get(plugin_id);
        return DependencyTarget {
            component_id: plugin_registry.component_id_for_plugin(plugin_id).cloned(),
            plugin,
            capability_exists: false,
        };
    }

    if let Some(capability_id) = &dependency.dependency_capability_id {
        return DependencyTarget {
            component_id: None,
            plugin: None,
            capability_exists: capability_registry.contains(capability_id),
        };
    }

    if let Some(name) = &dependency.dependency_name {
        let component = component_registry.find_by_name(name).into_iter().next();
        if let Some(component) = component {
            let plugin = plugin_registry
                .plugin_id_for_component(&component.component_id)
                .and_then(|plugin_id| plugin_registry.get(plugin_id));
            return DependencyTarget {
                component_id: Some(component.component_id.clone()),
                plugin,
                capability_exists: false,
            };
        }

        if let Some(plugin) = plugin_registry.find_by_name(name) {
            return DependencyTarget {
                component_id: plugin_registry
                    .component_id_for_plugin(&plugin.plugin_id)
                    .cloned(),
                plugin: Some(plugin),
                capability_exists: false,
            };
        }

        return DependencyTarget {
            component_id: None,
            plugin: None,
            capability_exists: capability_registry.find_by_domain(name).is_some(),
        };
    }

    DependencyTarget::default()
}

fn resolve_plugin_target<'a>(
    dependency: &PluginDependency,
    plugin_registry: &'a PluginRegistry,
) -> Option<&'a PluginManifest> {
    dependency
        .plugin_id
        .as_ref()
        .and_then(|plugin_id| plugin_registry.get(plugin_id))
        .or_else(|| {
            dependency
                .name
                .as_deref()
                .and_then(|name| plugin_registry.find_by_name(name))
        })
}

fn push_missing_plugin_dependency(
    issues: &mut Vec<ResolutionIssue>,
    dependency: &PluginDependency,
    source_component_id: &ComponentId,
    source_plugin_id: &PluginId,
) {
    let required = dependency.dependency_type == PluginDependencyType::RequiredPlugin;
    let issue = if required {
        ResolutionIssue::blocker(
            ResolutionIssueKind::MissingDependency,
            "required plugin dependency is missing",
        )
    } else {
        ResolutionIssue::warning(
            ResolutionIssueKind::MissingDependency,
            "optional plugin dependency is missing",
        )
    };

    issues.push(
        issue
            .for_component(source_component_id.clone())
            .for_plugin(source_plugin_id.clone())
            .for_dependency(plugin_dependency_label(dependency)),
    );
}

fn push_missing_capability_dependency(
    issues: &mut Vec<ResolutionIssue>,
    dependency: &PluginDependency,
    source_component_id: &ComponentId,
    source_plugin_id: &PluginId,
) {
    let required = dependency.dependency_type == PluginDependencyType::RequiredCapability;
    let issue = if required {
        ResolutionIssue::blocker(
            ResolutionIssueKind::MissingCapability,
            "required capability dependency is missing",
        )
    } else {
        ResolutionIssue::warning(
            ResolutionIssueKind::MissingCapability,
            "optional capability dependency is missing",
        )
    };

    issues.push(
        issue
            .for_component(source_component_id.clone())
            .for_plugin(source_plugin_id.clone())
            .for_dependency(plugin_dependency_label(dependency)),
    );
}

fn dependency_label(dependency: &DependencyBinding) -> String {
    dependency
        .dependency_name
        .clone()
        .or_else(|| {
            dependency
                .dependency_component_id
                .as_ref()
                .map(ToString::to_string)
        })
        .or_else(|| {
            dependency
                .dependency_plugin_id
                .as_ref()
                .map(ToString::to_string)
        })
        .or_else(|| {
            dependency
                .dependency_capability_id
                .as_ref()
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "unnamed dependency".to_string())
}

fn plugin_dependency_label(dependency: &PluginDependency) -> String {
    dependency
        .name
        .clone()
        .or_else(|| dependency.plugin_id.as_ref().map(ToString::to_string))
        .or_else(|| dependency.capability_id.as_ref().map(ToString::to_string))
        .or_else(|| {
            dependency
                .contract
                .as_ref()
                .map(|contract| contract.contract_name.clone())
        })
        .unwrap_or_else(|| "unnamed dependency".to_string())
}

fn detect_cycles(edges: &HashMap<ComponentId, HashSet<ComponentId>>) -> Vec<Vec<ComponentId>> {
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    let mut path = Vec::new();
    let mut cycles = Vec::new();

    let mut nodes = edges.keys().cloned().collect::<Vec<_>>();
    nodes.sort_by_key(ToString::to_string);

    for node in nodes {
        visit_for_cycles(
            &node,
            edges,
            &mut visiting,
            &mut visited,
            &mut path,
            &mut cycles,
        );
    }

    cycles
}

fn visit_for_cycles(
    node: &ComponentId,
    edges: &HashMap<ComponentId, HashSet<ComponentId>>,
    visiting: &mut HashSet<ComponentId>,
    visited: &mut HashSet<ComponentId>,
    path: &mut Vec<ComponentId>,
    cycles: &mut Vec<Vec<ComponentId>>,
) {
    if visited.contains(node) {
        return;
    }

    if visiting.contains(node) {
        if let Some(index) = path.iter().position(|existing| existing == node) {
            cycles.push(path[index..].to_vec());
        }
        return;
    }

    visiting.insert(node.clone());
    path.push(node.clone());

    let mut dependencies = edges
        .get(node)
        .map(|set| set.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    dependencies.sort_by_key(ToString::to_string);

    for dependency in dependencies {
        visit_for_cycles(&dependency, edges, visiting, visited, path, cycles);
    }

    visiting.remove(node);
    visited.insert(node.clone());
    path.pop();
}

fn compute_startup_order(
    edges: &HashMap<ComponentId, HashSet<ComponentId>>,
    explicit_orders: &HashMap<ComponentId, u32>,
) -> Vec<ResolvedStartupItem> {
    let mut indegree: HashMap<ComponentId, usize> = HashMap::new();
    let mut reverse: HashMap<ComponentId, HashSet<ComponentId>> = HashMap::new();

    for (component_id, dependencies) in edges {
        indegree.entry(component_id.clone()).or_insert(0);
        for dependency in dependencies {
            indegree.entry(dependency.clone()).or_insert(0);
            reverse
                .entry(dependency.clone())
                .or_default()
                .insert(component_id.clone());
            *indegree.entry(component_id.clone()).or_insert(0) += 1;
        }
    }

    let mut ready = indegree
        .iter()
        .filter_map(|(component_id, count)| (*count == 0).then_some(component_id.clone()))
        .collect::<Vec<_>>();
    sort_ready(&mut ready, explicit_orders);

    let mut queue = VecDeque::from(ready);
    let mut ordered = Vec::new();

    while let Some(component_id) = queue.pop_front() {
        ordered.push(component_id.clone());

        let mut dependents = reverse
            .get(&component_id)
            .map(|set| set.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        sort_ready(&mut dependents, explicit_orders);

        for dependent in dependents {
            if let Some(count) = indegree.get_mut(&dependent) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    queue.push_back(dependent);
                }
            }
        }

        let mut remaining = queue.drain(..).collect::<Vec<_>>();
        sort_ready(&mut remaining, explicit_orders);
        queue = VecDeque::from(remaining);
    }

    ordered
        .into_iter()
        .enumerate()
        .map(|(order_index, component_id)| ResolvedStartupItem {
            explicit_startup_order: explicit_orders.get(&component_id).copied(),
            component_id,
            order_index,
        })
        .collect()
}

fn sort_ready(values: &mut [ComponentId], explicit_orders: &HashMap<ComponentId, u32>) {
    values.sort_by_key(|component_id| {
        (
            explicit_orders
                .get(component_id)
                .copied()
                .unwrap_or(u32::MAX),
            component_id.to_string(),
        )
    });
}

fn dependency_targets_component(
    dependency: &DependencyBinding,
    target_component_id: &ComponentId,
    component_registry: &ComponentRegistry,
    plugin_registry: &PluginRegistry,
) -> bool {
    if dependency.dependency_component_id.as_ref() == Some(target_component_id) {
        return true;
    }

    if let Some(plugin_id) = &dependency.dependency_plugin_id {
        if plugin_registry.component_id_for_plugin(plugin_id) == Some(target_component_id) {
            return true;
        }
    }

    dependency.dependency_name.as_deref().is_some_and(|name| {
        component_registry
            .find_by_name(name)
            .iter()
            .any(|component| &component.component_id == target_component_id)
            || plugin_registry.find_by_name(name).is_some_and(|plugin| {
                plugin_registry.component_id_for_plugin(&plugin.plugin_id)
                    == Some(target_component_id)
            })
    })
}

fn contract_is_compatible(registered: &ContractDescriptor, requested: &ContractDescriptor) -> bool {
    if registered.contract_name != requested.contract_name {
        return false;
    }

    if matches!(
        requested.compatibility,
        ContractCompatibilityRequirement::MigrationRequired
    ) {
        return false;
    }

    if matches!(
        requested.compatibility,
        ContractCompatibilityRequirement::Strict
    ) && registered.schema_version != requested.schema_version
    {
        return false;
    }

    !matches!(
        registered
            .schema_version
            .compatibility_with(&requested.schema_version),
        SchemaCompatibility::Unsupported | SchemaCompatibility::MigrationRequired
    )
}

fn version_at_least(version: &str, min: &str) -> bool {
    compare_versions(version, min).is_some_and(|ordering| ordering >= std::cmp::Ordering::Equal)
}

fn version_at_most(version: &str, max: &str) -> bool {
    compare_versions(version, max).is_some_and(|ordering| ordering <= std::cmp::Ordering::Equal)
}

fn compare_versions(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    let left = parse_version(left)?;
    let right = parse_version(right)?;
    Some(left.cmp(&right))
}

fn parse_version(value: &str) -> Option<Vec<u64>> {
    value
        .split(['.', '-'])
        .take_while(|part| part.chars().all(|value| value.is_ascii_digit()))
        .map(|part| part.parse::<u64>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ComponentDefinition, ComponentRegistry, ComponentState, ComponentType, ContractRegistry,
        DependencyRegistry, PluginRegistry,
    };
    use sentinel_contracts::{
        CapabilityManifest, ContractDescriptor, PermissionKey, PluginDependency, PluginType,
        RuntimeMode,
    };

    fn component(name: &str) -> ComponentDefinition {
        ComponentDefinition::new(ComponentType::Plugin, name, "0.1.0", RuntimeMode::OnDemand)
            .expect("component definition")
    }

    fn contract(name: &str, version: SchemaVersion) -> ContractDescriptor {
        ContractDescriptor::new(name, version).expect("contract descriptor")
    }

    fn plugin(name: &str, output_contract: ContractDescriptor) -> PluginManifest {
        PluginManifest::new(
            PluginId::new_v4(),
            name,
            "0.1.0",
            "test.capability",
            PluginType::Utility,
            RuntimeMode::OnDemand,
        )
        .map(|mut manifest| {
            manifest.output_contracts.push(output_contract);
            manifest
        })
        .expect("plugin manifest")
    }

    #[test]
    fn registries_register_retrieve_list_and_validate_metadata() {
        let mut component_registry = ComponentRegistry::new();
        let definition = component("metadata-catalog");
        let component_id = definition.component_id.clone();
        component_registry
            .register(definition)
            .expect("register component");

        assert!(component_registry.get(&component_id).is_some());
        assert_eq!(component_registry.list().len(), 1);
        assert!(component_registry.validate().valid);

        let mut contract_registry = ContractRegistry::new();
        let descriptor = contract("plugin.catalog", SchemaVersion::new(1, 0, 0));
        contract_registry
            .register(descriptor.clone())
            .expect("register contract");
        assert_eq!(contract_registry.find_by_name("plugin.catalog").len(), 1);

        let mut plugin_registry = PluginRegistry::new();
        plugin_registry
            .register(plugin("catalog-plugin", descriptor), Some(component_id))
            .expect("register plugin");
        assert!(plugin_registry.validate().valid);

        let mut capability_registry = CapabilityRegistry::new();
        capability_registry
            .register(
                CapabilityManifest::new(
                    "test.capability",
                    "Test capability",
                    "Metadata-only capability for registry validation",
                )
                .expect("capability manifest"),
            )
            .expect("register capability");
        assert!(capability_registry.validate().valid);
    }

    #[test]
    fn dependency_resolver_detects_missing_dependency_and_startup_order() {
        let provider = component("provider");
        let mut consumer = component("consumer");
        consumer.dependency_bindings.push(DependencyBinding {
            dependency_type: PluginDependencyType::RequiredInfrastructure,
            dependency_component_id: Some(provider.component_id.clone()),
            dependency_plugin_id: None,
            dependency_capability_id: None,
            dependency_name: Some("provider".to_string()),
            version_requirement: VersionRange::any(),
            required: true,
            resolved: true,
            resolution_reason: None,
            incompatibility_reason: None,
        });

        let mut missing = component("missing-consumer");
        missing.dependency_bindings.push(DependencyBinding {
            dependency_type: PluginDependencyType::RequiredInfrastructure,
            dependency_component_id: Some(ComponentId::new_v4()),
            dependency_plugin_id: None,
            dependency_capability_id: None,
            dependency_name: Some("absent".to_string()),
            version_requirement: VersionRange::any(),
            required: true,
            resolved: false,
            resolution_reason: None,
            incompatibility_reason: None,
        });

        let mut components = ComponentRegistry::new();
        components.register(provider.clone()).expect("provider");
        components.register(consumer.clone()).expect("consumer");
        components.register(missing).expect("missing consumer");

        let mut dependencies = DependencyRegistry::new();
        for definition in components.list() {
            dependencies.register_component_definition(definition);
        }

        let resolution = DependencyResolver::new().resolve(
            &components,
            &PluginRegistry::new(),
            &CapabilityRegistry::new(),
            &ContractRegistry::new(),
            &dependencies,
            &VersionResolver::new(),
        );

        assert_eq!(resolution.status, ResolutionStatus::Incompatible);
        assert!(resolution
            .issues
            .iter()
            .any(|issue| issue.kind == ResolutionIssueKind::MissingDependency));

        let ordered_ids = resolution
            .startup_order
            .iter()
            .map(|item| item.component_id.clone())
            .collect::<Vec<_>>();
        let provider_index = ordered_ids
            .iter()
            .position(|component_id| component_id == &provider.component_id)
            .expect("provider in order");
        let consumer_index = ordered_ids
            .iter()
            .position(|component_id| component_id == &consumer.component_id)
            .expect("consumer in order");
        assert!(provider_index < consumer_index);
    }

    #[test]
    fn dependency_resolver_detects_cycles() {
        let mut a = component("a");
        let mut b = component("b");

        a.dependency_bindings.push(DependencyBinding {
            dependency_type: PluginDependencyType::RequiredInfrastructure,
            dependency_component_id: Some(b.component_id.clone()),
            dependency_plugin_id: None,
            dependency_capability_id: None,
            dependency_name: Some("b".to_string()),
            version_requirement: VersionRange::any(),
            required: true,
            resolved: true,
            resolution_reason: None,
            incompatibility_reason: None,
        });
        b.dependency_bindings.push(DependencyBinding {
            dependency_type: PluginDependencyType::RequiredInfrastructure,
            dependency_component_id: Some(a.component_id.clone()),
            dependency_plugin_id: None,
            dependency_capability_id: None,
            dependency_name: Some("a".to_string()),
            version_requirement: VersionRange::any(),
            required: true,
            resolved: true,
            resolution_reason: None,
            incompatibility_reason: None,
        });

        let mut components = ComponentRegistry::new();
        components.register(a).expect("a");
        components.register(b).expect("b");

        let mut dependencies = DependencyRegistry::new();
        for definition in components.list() {
            dependencies.register_component_definition(definition);
        }

        let resolution = DependencyResolver::new().resolve(
            &components,
            &PluginRegistry::new(),
            &CapabilityRegistry::new(),
            &ContractRegistry::new(),
            &dependencies,
            &VersionResolver::new(),
        );

        assert!(resolution
            .issues
            .iter()
            .any(|issue| issue.kind == ResolutionIssueKind::DependencyCycle));
    }

    #[test]
    fn contract_resolver_blocks_unsupported_contract_versions() {
        let mut contracts = ContractRegistry::new();
        contracts
            .register(contract("network.flow.record", SchemaVersion::new(1, 0, 0)))
            .expect("register contract");

        let mut requested = contract("network.flow.record", SchemaVersion::new(2, 0, 0));
        requested.required = true;
        let manifest = plugin("flow-consumer", requested);

        let report = ContractResolver::new().resolve_plugin_manifest(&manifest, &contracts);

        assert_eq!(report.status, ResolutionStatus::Incompatible);
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.kind == ResolutionIssueKind::UnsupportedContract));
    }

    #[test]
    fn capability_resolver_marks_missing_required_and_optional_capabilities() {
        let descriptor = contract("plugin.catalog", SchemaVersion::new(1, 0, 0));
        let mut manifest = plugin("capability-consumer", descriptor);
        manifest.required_capabilities.push(CapabilityId::new_v4());
        manifest.optional_capabilities.push(CapabilityId::new_v4());

        let resolution = CapabilityResolver::new()
            .resolve_plugin_manifest(&manifest, &CapabilityRegistry::new());

        assert_eq!(resolution.status, ResolutionStatus::Incompatible);
        assert!(resolution
            .issues
            .iter()
            .any(|issue| issue.severity == ResolutionSeverity::Blocker));
        assert!(resolution
            .issues
            .iter()
            .any(|issue| issue.severity == ResolutionSeverity::Warning));
    }

    #[test]
    fn version_resolver_checks_exact_min_and_max_ranges() {
        let resolver = VersionResolver::new();
        let exact = VersionRange::exact("1.2.3").expect("exact range");
        assert!(resolver.version_satisfies("1.2.3", &exact).compatible);
        assert!(!resolver.version_satisfies("1.2.4", &exact).compatible);

        let range = VersionRange {
            min: Some("1.2.0".to_string()),
            max: Some("1.3.0".to_string()),
            exact: None,
        };
        assert!(resolver.version_satisfies("1.2.5", &range).compatible);
        assert!(!resolver.version_satisfies("1.4.0", &range).compatible);
    }

    #[test]
    fn impact_analysis_identifies_dependents_when_disabling_dependency() {
        let provider = component("provider");
        let mut consumer = component("consumer");
        consumer.dependency_bindings.push(DependencyBinding {
            dependency_type: PluginDependencyType::RequiredInfrastructure,
            dependency_component_id: Some(provider.component_id.clone()),
            dependency_plugin_id: None,
            dependency_capability_id: None,
            dependency_name: Some("provider".to_string()),
            version_requirement: VersionRange::any(),
            required: true,
            resolved: true,
            resolution_reason: None,
            incompatibility_reason: None,
        });

        let mut components = ComponentRegistry::new();
        components.register(provider.clone()).expect("provider");
        components.register(consumer.clone()).expect("consumer");

        let analysis = ImpactAnalysis::for_disable_component(
            provider.component_id,
            &components,
            &PluginRegistry::new(),
            &CapabilityRegistry::new(),
        );

        assert_eq!(analysis.impact_level, ImpactLevel::Low);
        assert_eq!(analysis.affected_components, vec![consumer.component_id]);
    }

    #[test]
    fn plugin_dependency_registry_supports_missing_permissions_as_metadata_issue() {
        let descriptor = contract("plugin.catalog", SchemaVersion::new(1, 0, 0));
        let manifest = plugin("permission-consumer", descriptor);
        let mut dependency_registry = DependencyRegistry::new();
        dependency_registry.register_plugin_manifest(&manifest);

        let missing_permission = ResolutionIssue::blocker(
            ResolutionIssueKind::MissingPermission,
            "permission resolver must grant required permissions before startup",
        )
        .for_plugin(manifest.plugin_id.clone())
        .for_dependency(
            PermissionKey::new("read.event.flow")
                .expect("permission")
                .to_string(),
        );

        assert_eq!(
            missing_permission.kind,
            ResolutionIssueKind::MissingPermission
        );
        assert_eq!(
            dependency_registry.dependencies_for_plugin(&manifest.plugin_id),
            &[] as &[PluginDependency]
        );
    }

    #[test]
    fn runtime_related_components_are_metadata_only() {
        let definition = ComponentDefinition::new(
            ComponentType::ServiceAdapter,
            "service-adapter",
            "0.1.0",
            RuntimeMode::OnDemand,
        )
        .expect("component definition");

        assert_eq!(definition.component_type, ComponentType::ServiceAdapter);
        assert!(!ComponentState::Disabled.is_operational());
    }
}
