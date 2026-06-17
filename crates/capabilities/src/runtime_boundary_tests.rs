use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const RUNTIME_OWNER_PATTERNS: &[&str] = &[
    "EventBus::with_core_topics",
    "PipelineDag::new",
    "PluginRuntime::new",
    "CapabilityRegistry::new",
];

#[test]
fn runtime_boundary_capabilities_runtime_owners_are_explicit_test_only() {
    let observed = scan_capability_runtime_owners();
    let expected = BTreeMap::from([
        (
            (
                "src/mock_network_pipeline.rs".to_string(),
                "EventBus::with_core_topics".to_string(),
            ),
            13,
        ),
        (
            (
                "src/mock_network_pipeline.rs".to_string(),
                "PipelineDag::new".to_string(),
            ),
            1,
        ),
        (
            (
                "src/mock_network_pipeline.rs".to_string(),
                "PluginRuntime::new".to_string(),
            ),
            5,
        ),
        (
            (
                "src/runtime_test_support.rs".to_string(),
                "EventBus::with_core_topics".to_string(),
            ),
            1,
        ),
        (
            (
                "src/runtime_test_support.rs".to_string(),
                "PipelineDag::new".to_string(),
            ),
            1,
        ),
        (
            (
                "src/runtime_test_support.rs".to_string(),
                "PluginRuntime::new".to_string(),
            ),
            1,
        ),
    ]);
    assert_eq!(
        observed, expected,
        "capability runtime owner construction changed; only explicit test modules may own runtime fixtures"
    );
    assert!(observed.keys().all(|(path, _)| {
        matches!(
            path.as_str(),
            "src/mock_network_pipeline.rs" | "src/runtime_test_support.rs"
        )
    }));
}

#[test]
fn runtime_boundary_capabilities_do_not_construct_provider_or_scheduler_owners() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for relative in [
        "src/portable_capture_lite.rs",
        "src/mock_network_pipeline.rs",
        "src/static_plugin_runtime.rs",
    ] {
        let source = fs::read_to_string(root.join(relative)).expect("source");
        for forbidden in [
            "IpHelperSnapshotAdapter::new",
            "EtwControlSessionAdapter::new",
            "EnableTraceEx2",
            "OpenTraceW",
            "ProcessTrace",
            "Npcap",
            "CaptureBroker",
            "NativeSchedulerController::from_read_state",
            "NativeSchedulerHostController::from_read_state",
            "NativeSamplerRuntime::from_read_state",
            "read_packet_metadata_batch",
            "start_capture",
        ] {
            assert!(
                !source.contains(forbidden),
                "capability boundary must not construct provider/scheduler owner {forbidden}"
            );
        }
    }
}

fn scan_capability_runtime_owners() -> BTreeMap<(String, String), usize> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source_root = root.join("src");
    let mut observed = BTreeMap::new();
    collect_rs_files(&source_root, &mut |path| {
        let relative = normalize_path(path.strip_prefix(&root).expect("relative"));
        if relative == "src/runtime_boundary_tests.rs" {
            return;
        }
        let source = fs::read_to_string(path).expect("source");
        for pattern in RUNTIME_OWNER_PATTERNS {
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
