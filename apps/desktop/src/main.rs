// Prevents additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Some(arg) = std::env::args().nth(1) {
        match arg.as_str() {
            "--help" | "-h" => {
                println!(
                    "Sentinel Guard Desktop {}\n\nUsage: sentinel-guard-desktop [--profile <installed|portable>] [--help] [--version]",
                    env!("CARGO_PKG_VERSION")
                );
                return;
            }
            "--version" | "-V" => {
                println!("sentinel-guard-desktop {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            _ => {}
        }
    }

    sentinel_guard_desktop::run();
}
