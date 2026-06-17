use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeConstructorClassification {
    ServiceProduction,
    PortableProduction,
    DesktopClientOnly,
    TestHarness,
    Fixture,
    Mock,
    Demo,
    DeadOrUnreachable,
    ArchitectureViolation,
}

impl RuntimeConstructorClassification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceProduction => "service_production",
            Self::PortableProduction => "portable_production",
            Self::DesktopClientOnly => "desktop_client_only",
            Self::TestHarness => "test_harness",
            Self::Fixture => "fixture",
            Self::Mock => "mock",
            Self::Demo => "demo",
            Self::DeadOrUnreachable => "dead_or_unreachable",
            Self::ArchitectureViolation => "architecture_violation",
        }
    }
}

impl fmt::Display for RuntimeConstructorClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeConstructorKind {
    EventBusWithCoreTopics,
    PipelineDagNew,
    PluginRuntimeNew,
    CapabilityRegistryNew,
    ReadOnlyCommandStateBootstrap,
    AuthorizedNativePermissionRuntimeFromReadState,
    NativeSchedulerControllerFromReadState,
    NativeSchedulerHostControllerFromReadState,
    NativeSamplerRuntimeFromReadState,
    SqliteStoreFactoryNew,
    SessionLifecycleStart,
    DatabaseRuntimeBootstrap,
    DatabaseRuntimeBootstrapWithSession,
}

impl RuntimeConstructorKind {
    pub const fn pattern(self) -> &'static str {
        match self {
            Self::EventBusWithCoreTopics => "EventBus::with_core_topics",
            Self::PipelineDagNew => "PipelineDag::new",
            Self::PluginRuntimeNew => "PluginRuntime::new",
            Self::CapabilityRegistryNew => "CapabilityRegistry::new",
            Self::ReadOnlyCommandStateBootstrap => "ReadOnlyCommandState::bootstrap",
            Self::AuthorizedNativePermissionRuntimeFromReadState => {
                "AuthorizedNativePermissionRuntime::from_read_state"
            }
            Self::NativeSchedulerControllerFromReadState => {
                "NativeSchedulerController::from_read_state"
            }
            Self::NativeSchedulerHostControllerFromReadState => {
                "NativeSchedulerHostController::from_read_state"
            }
            Self::NativeSamplerRuntimeFromReadState => "NativeSamplerRuntime::from_read_state",
            Self::SqliteStoreFactoryNew => "SqliteStoreFactory::new",
            Self::SessionLifecycleStart => "SessionLifecycle::start",
            Self::DatabaseRuntimeBootstrap => "DatabaseRuntime::bootstrap",
            Self::DatabaseRuntimeBootstrapWithSession => "DatabaseRuntime::bootstrap_with_session",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeConstructorInventoryEntry {
    pub file_module: &'static str,
    pub constructor: RuntimeConstructorKind,
    pub observed_occurrences: usize,
    pub reachable_caller: &'static str,
    pub current_classification: RuntimeConstructorClassification,
    pub required_classification: RuntimeConstructorClassification,
    pub migration_action: &'static str,
    pub blocking_dependency: &'static str,
    pub test_coverage: &'static str,
}

macro_rules! inv {
    ($file:expr, $kind:expr, $count:expr, $caller:expr, $class:expr, $action:expr, $coverage:expr) => {
        RuntimeConstructorInventoryEntry {
            file_module: $file,
            constructor: $kind,
            observed_occurrences: $count,
            reachable_caller: $caller,
            current_classification: $class,
            required_classification: $class,
            migration_action: $action,
            blocking_dependency: "none",
            test_coverage: $coverage,
        }
    };
}

// This is the bounded migration table exposed in ownership summaries. Source-boundary
// tests below lock every runtime-owner primitive to its approved construction module.
pub const LEGACY_RUNTIME_CONSTRUCTOR_INVENTORY: &[RuntimeConstructorInventoryEntry] = &[
    inv!(
        "crates/app_core/src/runtime_container.rs",
        RuntimeConstructorKind::EventBusWithCoreTopics,
        2,
        "RuntimeContainerBuilder service/portable/test assembly",
        RuntimeConstructorClassification::ServiceProduction,
        "retain only inside approved RuntimeContainerBuilder assembly",
        "runtime_architecture and runtime_container tests"
    ),
    inv!(
        "crates/app_core/src/runtime_container.rs",
        RuntimeConstructorKind::PipelineDagNew,
        1,
        "RuntimeContainerBuilder service/portable/test assembly",
        RuntimeConstructorClassification::ServiceProduction,
        "retain only inside approved RuntimeContainerBuilder assembly",
        "runtime_architecture and runtime_container tests"
    ),
    inv!(
        "crates/app_core/src/runtime_container.rs",
        RuntimeConstructorKind::PluginRuntimeNew,
        4,
        "RuntimeContainerBuilder service/portable/test assembly",
        RuntimeConstructorClassification::ServiceProduction,
        "retain only inside approved RuntimeContainerBuilder assembly",
        "runtime_architecture and runtime_container tests"
    ),
    inv!(
        "crates/app_core/src/runtime_container.rs",
        RuntimeConstructorKind::CapabilityRegistryNew,
        1,
        "RuntimeContainerBuilder read-model registry assembly",
        RuntimeConstructorClassification::ServiceProduction,
        "retain only inside approved RuntimeContainerBuilder assembly",
        "runtime_architecture and read_commands tests"
    ),
    inv!(
        "apps/desktop/src/lib.rs",
        RuntimeConstructorKind::SessionLifecycleStart,
        7,
        "explicit Portable Default storage plus desktop storage tests",
        RuntimeConstructorClassification::PortableProduction,
        "retain behind explicit portable fallback; service-owned mode rejects desktop writer",
        "desktop runtime_ownership and storage_gate tests"
    ),
    inv!(
        "apps/desktop/src/lib.rs",
        RuntimeConstructorKind::DatabaseRuntimeBootstrapWithSession,
        7,
        "explicit Portable Default storage plus desktop storage tests",
        RuntimeConstructorClassification::PortableProduction,
        "retain behind explicit portable fallback; service-owned mode rejects desktop writer",
        "desktop runtime_ownership and storage_gate tests"
    ),
    inv!(
        "apps/desktop/src/lib.rs",
        RuntimeConstructorKind::DatabaseRuntimeBootstrap,
        8,
        "explicit Portable Default storage plus desktop storage tests",
        RuntimeConstructorClassification::PortableProduction,
        "retain behind explicit portable fallback; service-owned mode rejects desktop writer",
        "desktop runtime_ownership and storage_gate tests"
    ),
    inv!(
        "crates/app_core/src/*",
        RuntimeConstructorKind::ReadOnlyCommandStateBootstrap,
        89,
        "cfg(test) read-model fixtures delegated to RuntimeContainerBuilder::for_test",
        RuntimeConstructorClassification::TestHarness,
        "retain test compatibility surface only",
        "workspace and runtime_architecture tests"
    ),
    inv!(
        "crates/app_core/src/{authorized_native_permissions,native_sampler_runtime,native_scheduler,native_scheduler_host,mutation_commands}.rs",
        RuntimeConstructorKind::NativeSamplerRuntimeFromReadState,
        25,
        "cfg(test) native runtime fixtures",
        RuntimeConstructorClassification::TestHarness,
        "retain cfg(test) compatibility constructors only",
        "runtime_ownership and native scheduler/sampler tests"
    ),
    inv!(
        "crates/capabilities/src/{mock_network_pipeline,runtime_test_support}.rs",
        RuntimeConstructorKind::PluginRuntimeNew,
        6,
        "test-support feature and cfg(test) capability fixtures",
        RuntimeConstructorClassification::TestHarness,
        "retain only behind explicit test-support ownership",
        "sentinel-capabilities runtime_boundary tests"
    ),
    inv!(
        "crates/platform/src/*",
        RuntimeConstructorKind::PluginRuntimeNew,
        9,
        "platform primitive tests and mock catalog",
        RuntimeConstructorClassification::TestHarness,
        "retain platform primitive/test ownership only",
        "sentinel-platform runtime_architecture tests"
    ),
    inv!(
        "crates/storage/src/*",
        RuntimeConstructorKind::SqliteStoreFactoryNew,
        17,
        "storage infrastructure and storage tests",
        RuntimeConstructorClassification::Fixture,
        "retain infrastructure adapter construction; production writer ownership remains gated",
        "sentinel-storage ownership and workspace tests"
    ),
];

pub fn legacy_runtime_constructor_inventory() -> &'static [RuntimeConstructorInventoryEntry] {
    LEGACY_RUNTIME_CONSTRUCTOR_INVENTORY
}

pub fn legacy_runtime_migration_table() -> &'static [RuntimeConstructorInventoryEntry] {
    LEGACY_RUNTIME_CONSTRUCTOR_INVENTORY
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};

    const OWNER_PATTERNS: &[RuntimeConstructorKind] = &[
        RuntimeConstructorKind::EventBusWithCoreTopics,
        RuntimeConstructorKind::PipelineDagNew,
        RuntimeConstructorKind::PluginRuntimeNew,
        RuntimeConstructorKind::CapabilityRegistryNew,
    ];

    const SOURCE_LOCK_EXCLUDES: &[&str] = &[
        "crates/app_core/src/runtime_architecture.rs",
        "crates/platform/src/runtime_architecture_tests.rs",
        "crates/capabilities/src/runtime_boundary_tests.rs",
    ];

    #[test]
    fn runtime_architecture_inventory_has_no_unclassified_or_violation_rows() {
        assert!(legacy_runtime_constructor_inventory().iter().all(|entry| {
            entry.current_classification == entry.required_classification
                && entry.current_classification
                    != RuntimeConstructorClassification::ArchitectureViolation
                && entry.current_classification
                    != RuntimeConstructorClassification::DeadOrUnreachable
                && !entry.reachable_caller.trim().is_empty()
                && !entry.migration_action.trim().is_empty()
                && !entry.test_coverage.trim().is_empty()
        }));
    }

    #[test]
    fn runtime_architecture_runtime_owner_constructor_counts_are_locked() {
        let expected = BTreeMap::from([
            (
                key(
                    "crates/app_core/src/runtime_container.rs",
                    RuntimeConstructorKind::EventBusWithCoreTopics,
                ),
                2,
            ),
            (
                key(
                    "crates/app_core/src/runtime_container.rs",
                    RuntimeConstructorKind::PipelineDagNew,
                ),
                1,
            ),
            (
                key(
                    "crates/app_core/src/runtime_container.rs",
                    RuntimeConstructorKind::PluginRuntimeNew,
                ),
                4,
            ),
            (
                key(
                    "crates/app_core/src/runtime_container.rs",
                    RuntimeConstructorKind::CapabilityRegistryNew,
                ),
                1,
            ),
            (
                key(
                    "crates/capabilities/src/mock_network_pipeline.rs",
                    RuntimeConstructorKind::EventBusWithCoreTopics,
                ),
                13,
            ),
            (
                key(
                    "crates/capabilities/src/mock_network_pipeline.rs",
                    RuntimeConstructorKind::PipelineDagNew,
                ),
                1,
            ),
            (
                key(
                    "crates/capabilities/src/mock_network_pipeline.rs",
                    RuntimeConstructorKind::PluginRuntimeNew,
                ),
                5,
            ),
            (
                key(
                    "crates/capabilities/src/runtime_test_support.rs",
                    RuntimeConstructorKind::EventBusWithCoreTopics,
                ),
                1,
            ),
            (
                key(
                    "crates/capabilities/src/runtime_test_support.rs",
                    RuntimeConstructorKind::PipelineDagNew,
                ),
                1,
            ),
            (
                key(
                    "crates/capabilities/src/runtime_test_support.rs",
                    RuntimeConstructorKind::PluginRuntimeNew,
                ),
                1,
            ),
            (
                key(
                    "crates/platform/src/event_bus/bus.rs",
                    RuntimeConstructorKind::EventBusWithCoreTopics,
                ),
                7,
            ),
            (
                key(
                    "crates/platform/src/pipeline/tests.rs",
                    RuntimeConstructorKind::PipelineDagNew,
                ),
                2,
            ),
            (
                key(
                    "crates/platform/src/plugin_runtime/mock_catalog.rs",
                    RuntimeConstructorKind::PluginRuntimeNew,
                ),
                8,
            ),
            (
                key(
                    "crates/platform/src/plugin_runtime/tests.rs",
                    RuntimeConstructorKind::PluginRuntimeNew,
                ),
                2,
            ),
            (
                key(
                    "crates/platform/src/resolver/mod.rs",
                    RuntimeConstructorKind::CapabilityRegistryNew,
                ),
                5,
            ),
        ]);
        assert_eq!(scan_runtime_owner_constructors(), expected);
    }

    #[test]
    fn runtime_architecture_production_runtime_owners_are_builder_owned() {
        for ((file, _), _) in scan_runtime_owner_constructors() {
            if file.starts_with("crates/capabilities/src/")
                || file.starts_with("crates/platform/src/")
            {
                continue;
            }
            assert_eq!(
                file, "crates/app_core/src/runtime_container.rs",
                "production runtime-owner primitive escaped RuntimeContainerBuilder"
            );
        }
    }

    #[test]
    fn runtime_architecture_capability_runtime_owners_are_test_support_only() {
        for ((file, _), _) in scan_runtime_owner_constructors() {
            if !file.starts_with("crates/capabilities/src/") {
                continue;
            }
            assert!(
                matches!(
                    file.as_str(),
                    "crates/capabilities/src/mock_network_pipeline.rs"
                        | "crates/capabilities/src/runtime_test_support.rs"
                ),
                "capability production module owns a runtime primitive: {file}"
            );
        }
    }

    #[test]
    fn runtime_architecture_desktop_has_no_runtime_owner_primitives() {
        assert!(scan_runtime_owner_constructors()
            .keys()
            .all(|(file, _)| !file.starts_with("apps/desktop/")));
    }

    #[test]
    fn runtime_architecture_no_ungated_provider_execution_is_reachable_from_container_or_servicehost(
    ) {
        let root = workspace_root();
        for relative in [
            "crates/app_core/src/runtime_container.rs",
            "service/elevated/src/service_host.rs",
        ] {
            let source = fs::read_to_string(root.join(relative)).expect("source");
            for forbidden in [
                "read_snapshot",
                "Npcap",
                "CaptureBroker",
                "read_packet_metadata_batch",
                "run_provider",
                "start_capture",
            ] {
                assert!(
                    !source.contains(forbidden),
                    "{relative} invokes {forbidden}"
                );
            }
        }
        let container_source =
            fs::read_to_string(root.join("crates/app_core/src/runtime_container.rs"))
                .expect("container source");
        assert!(container_source.contains("validate_ip_helper_execution_gate"));
        assert!(container_source.contains("IpHelperHandoffExecutionPolicy::ProductionIpc"));
        assert!(container_source.contains("ip_helper_not_active"));
        assert!(container_source.contains("activate_ip_helper_provider"));
        assert!(container_source.contains("stop_ip_helper_provider"));
        assert!(container_source.contains("validate_etw_lifecycle_gate"));
        assert!(container_source.contains("validate_etw_handoff_gate"));
        assert!(container_source.contains("execute_etw_network_handoff"));
        assert!(container_source.contains("pump_etw_live_batches"));
    }

    fn key(file: &str, kind: RuntimeConstructorKind) -> (String, RuntimeConstructorKind) {
        (file.to_string(), kind)
    }

    fn scan_runtime_owner_constructors() -> BTreeMap<(String, RuntimeConstructorKind), usize> {
        let root = workspace_root();
        let excludes = SOURCE_LOCK_EXCLUDES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut observed = BTreeMap::new();
        for scan_root in ["apps", "crates", "service"] {
            collect_rs_files(&root.join(scan_root), &mut |path| {
                let relative = normalize_path(path.strip_prefix(&root).expect("relative path"));
                if excludes.contains(relative.as_str()) {
                    return;
                }
                let source = fs::read_to_string(path).expect("source");
                for constructor in OWNER_PATTERNS {
                    let count = source.matches(constructor.pattern()).count();
                    if count > 0 {
                        observed.insert((relative.clone(), *constructor), count);
                    }
                }
            });
        }
        observed
    }

    fn collect_rs_files(path: &Path, visitor: &mut impl FnMut(&Path)) {
        for entry in fs::read_dir(path).expect("read source directory") {
            let entry = entry.expect("directory entry");
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, visitor);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                visitor(&path);
            }
        }
    }

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .to_path_buf()
    }

    fn normalize_path(path: &Path) -> String {
        path.components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    }
}
