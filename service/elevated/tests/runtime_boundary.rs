use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn runtime_boundary_elevated_service_has_no_ip_helper_provider_implementation() {
    let root = workspace_root();
    let service_root = root.join("service/elevated");

    assert!(
        !service_root.join("src/ip_helper_provider.rs").exists(),
        "IP Helper implementation must live under crates/infrastructure, not service/elevated"
    );

    let lib_source = fs::read_to_string(service_root.join("src/lib.rs")).expect("service lib");
    for forbidden in [
        "pub mod ip_helper_provider",
        "pub use ip_helper_provider",
        "IpHelperSnapshotAdapter",
        "GetExtendedTcpTable",
        "GetExtendedUdpTable",
        "Win32_NetworkManagement_IpHelper",
    ] {
        assert!(
            !lib_source.contains(forbidden),
            "elevated service lib still exposes IP Helper provider boundary: {forbidden}"
        );
    }

    let cargo_toml = fs::read_to_string(service_root.join("Cargo.toml")).expect("service cargo");
    for forbidden in [
        "Win32_NetworkManagement_IpHelper",
        "Win32_Networking_WinSock",
    ] {
        assert!(
            !cargo_toml.contains(forbidden),
            "elevated service should not depend on IP Helper provider APIs: {forbidden}"
        );
    }
}

#[test]
fn runtime_boundary_ip_helper_adapter_resides_in_infrastructure_only() {
    let root = workspace_root();
    let infrastructure_adapter = root.join("crates/infrastructure/src/windows/ip_helper.rs");
    assert!(
        infrastructure_adapter.exists(),
        "IP Helper adapter must be owned by infrastructure"
    );

    let source = fs::read_to_string(infrastructure_adapter).expect("infrastructure adapter");
    for required in [
        "IpHelperSnapshotAdapter",
        "ProviderAdapterOwnership::infrastructure_adapter",
        "NetworkMetadataAdapter for IpHelperSnapshotAdapter",
    ] {
        assert!(
            source.contains(required),
            "infrastructure IP Helper adapter is missing boundary marker: {required}"
        );
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}
