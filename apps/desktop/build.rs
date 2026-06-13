use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    tauri_build::build();
    configure_windows_gnu_test_runtime();
}

fn configure_windows_gnu_test_runtime() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("gnu")
    {
        return;
    }

    let Some(out_dir) = env::var_os("OUT_DIR").map(PathBuf::from) else {
        return;
    };

    if let Some(manifest_object) = build_common_controls_manifest(&out_dir) {
        println!("cargo:rustc-link-arg={}", manifest_object.display());
    }

    copy_webview_loader_for_test_executables(&out_dir);
}

fn build_common_controls_manifest(out_dir: &Path) -> Option<PathBuf> {
    let manifest_path = out_dir.join("sentinel-guard-test.exe.manifest");
    let resource_path = out_dir.join("sentinel-guard-test-manifest.rc");
    let object_path = out_dir.join("sentinel-guard-test-manifest.o");
    let manifest = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*" />
    </dependentAssembly>
  </dependency>
</assembly>
"#;
    fs::write(&manifest_path, manifest).ok()?;

    let escaped_manifest_path = manifest_path
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    fs::write(
        &resource_path,
        format!("1 24 \"{escaped_manifest_path}\"\n"),
    )
    .ok()?;

    let windres = env::var_os("WINDRES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("windres"));
    let status = Command::new(windres)
        .arg("--target=pe-x86-64")
        .arg("-i")
        .arg(&resource_path)
        .arg("-o")
        .arg(&object_path)
        .status()
        .ok()?;
    if status.success() {
        Some(object_path)
    } else {
        println!("cargo:warning=windres failed to build Windows GNU test manifest resource");
        None
    }
}

fn copy_webview_loader_for_test_executables(out_dir: &Path) {
    let Some(profile_dir) = target_profile_dir(out_dir) else {
        return;
    };
    let source = profile_dir.join("WebView2Loader.dll");
    if !source.exists() {
        return;
    }
    let deps_dir = profile_dir.join("deps");
    if fs::create_dir_all(&deps_dir).is_err() {
        return;
    }
    let _ = fs::copy(source, deps_dir.join("WebView2Loader.dll"));
}

fn target_profile_dir(out_dir: &Path) -> Option<PathBuf> {
    out_dir.ancestors().nth(3).map(Path::to_path_buf)
}
