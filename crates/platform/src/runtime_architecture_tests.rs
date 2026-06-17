use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const PATTERNS: &[&str] = &[
    "EventBus::with_core_topics",
    "PipelineDag::new",
    "PluginRuntime::new",
    "CapabilityRegistry::new",
];

#[test]
fn runtime_architecture_platform_runtime_constructors_are_test_only_or_primitives() {
    let observed = scan_platform_sources();
    let expected = BTreeMap::from([
        (
            (
                "src/event_bus/bus.rs".to_string(),
                "EventBus::with_core_topics".to_string(),
            ),
            7,
        ),
        (
            (
                "src/pipeline/tests.rs".to_string(),
                "PipelineDag::new".to_string(),
            ),
            2,
        ),
        (
            (
                "src/plugin_runtime/mock_catalog.rs".to_string(),
                "PluginRuntime::new".to_string(),
            ),
            8,
        ),
        (
            (
                "src/plugin_runtime/tests.rs".to_string(),
                "PluginRuntime::new".to_string(),
            ),
            2,
        ),
        (
            (
                "src/resolver/mod.rs".to_string(),
                "CapabilityRegistry::new".to_string(),
            ),
            5,
        ),
    ]);
    assert_eq!(
        observed, expected,
        "platform runtime primitive construction changed; classify before expanding production reachability"
    );
}

#[test]
fn runtime_architecture_platform_has_no_servicehost_or_app_core_dependency() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("platform manifest");
    assert!(!manifest.contains("sentinel-app-core"));
    assert!(!manifest.contains("sentinel-guard-elevated"));
}

fn scan_platform_sources() -> BTreeMap<(String, String), usize> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source_root = root.join("src");
    let mut observed = BTreeMap::new();
    collect_rs_files(&source_root, &mut |path| {
        let relative = normalize_path(path.strip_prefix(&root).expect("relative"));
        if relative == "src/runtime_architecture_tests.rs" {
            return;
        }
        let source = fs::read_to_string(path).expect("source");
        for pattern in PATTERNS {
            let count = source.matches(pattern).count();
            if count > 0 {
                observed.insert((relative.clone(), (*pattern).to_string()), count);
            }
        }
    });
    observed
}

fn collect_rs_files(path: &Path, visitor: &mut impl FnMut(&Path)) {
    for entry in fs::read_dir(path).expect("read directory") {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, visitor);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            visitor(&path);
        }
    }
}

fn normalize_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
