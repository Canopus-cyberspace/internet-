use sentinel_elevated_service::{
    ServiceHostLifecycleState, ServiceHostRunMode, ServiceHostRuntime, ServiceHostRuntimeStatus,
    ServiceHostShutdown, SERVICE_DISPLAY_NAME, SERVICE_NAME, SERVICE_VERSION,
};
use std::env;
use std::error::Error;
use std::process;
use std::time::{Duration, Instant};

#[cfg(windows)]
static FOREGROUND_STOP_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn main() {
    if let Err(error) = run_cli() {
        eprintln!("SERVICE_FATAL {error}");
        process::exit(1);
    }
}

fn run_cli() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--service") | Some("--run") => run_as_windows_service(),
        Some("--foreground") | Some("--standalone") | None => run_foreground(),
        Some("--status") => print_status(),
        Some("--version") | Some("-V") => {
            println!("{SERVICE_VERSION}");
            Ok(())
        }
        Some("--install") | Some("--uninstall") => {
            Err("service registration is not implemented by this product ServiceHost phase".into())
        }
        Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!("unsupported argument: {other}").into()),
    }
}

fn print_help() {
    println!("{SERVICE_DISPLAY_NAME}");
    println!("  --foreground   Run the product ServiceHost in foreground mode");
    println!("  --service      Run through Windows Service Control Manager");
    println!("  --status       Print bounded local ServiceHost status metadata");
    println!("  --version      Print ServiceHost version");
}

fn print_status() -> Result<(), Box<dyn Error>> {
    let status = ServiceHostRuntimeStatus::new(
        ServiceHostRunMode::Foreground,
        ServiceHostLifecycleState::Stopped,
    );
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

fn run_foreground() -> Result<(), Box<dyn Error>> {
    let shutdown = ServiceHostShutdown::new();
    install_foreground_ctrl_c(shutdown.clone())?;
    install_foreground_smoke_shutdown(shutdown.clone());
    let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Foreground, shutdown);
    let final_status = runtime.run()?;
    println!("{}", serde_json::to_string(&final_status)?);
    Ok(())
}

fn install_foreground_smoke_shutdown(shutdown: ServiceHostShutdown) {
    let stop_file = env::var_os("SENTINEL_GUARD_FOREGROUND_SMOKE_STOP_FILE");
    let max_runtime = env::var("SENTINEL_GUARD_FOREGROUND_SMOKE_MAX_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|millis| Duration::from_millis(millis.clamp(1_000, 300_000)));
    if stop_file.is_none() && max_runtime.is_none() {
        return;
    }
    let stop_file = stop_file.map(std::path::PathBuf::from);
    std::thread::spawn(move || {
        let started = Instant::now();
        loop {
            if stop_file.as_ref().is_some_and(|path| path.exists())
                || max_runtime.is_some_and(|limit| started.elapsed() >= limit)
            {
                shutdown.request();
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
}

#[cfg(windows)]
fn run_as_windows_service() -> Result<(), Box<dyn Error>> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(not(windows))]
fn run_as_windows_service() -> Result<(), Box<dyn Error>> {
    let status = ServiceHostRuntimeStatus::unsupported_platform(ServiceHostRunMode::Service);
    println!("{}", serde_json::to_string(&status)?);
    Ok(())
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(error) = run_service_runtime() {
        eprintln!("SERVICE_RUNTIME_FATAL {error}");
    }
}

#[cfg(windows)]
fn run_service_runtime() -> Result<(), Box<dyn Error>> {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let shutdown = ServiceHostShutdown::new();
    let stop_handle = shutdown.clone();
    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop => {
                stop_handle.request();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: Some(process::id()),
    })?;

    let mut runtime = ServiceHostRuntime::new(ServiceHostRunMode::Service, shutdown);

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: Some(process::id()),
    })?;

    let result = runtime.run();

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: Some(process::id()),
    })?;

    result?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: Some(process::id()),
    })?;
    Ok(())
}

#[cfg(windows)]
fn install_foreground_ctrl_c(shutdown: ServiceHostShutdown) -> Result<(), Box<dyn Error>> {
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Console::{
        SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT,
    };

    unsafe extern "system" fn handler(control: u32) -> i32 {
        match control {
            CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT => {
                FOREGROUND_STOP_REQUESTED.store(true, Ordering::SeqCst);
                1
            }
            _ => 0,
        }
    }

    let installed = unsafe { SetConsoleCtrlHandler(Some(handler), 1) };
    if installed == 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    std::thread::spawn(move || loop {
        if FOREGROUND_STOP_REQUESTED.load(Ordering::SeqCst) {
            shutdown.request();
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    });
    Ok(())
}

#[cfg(not(windows))]
fn install_foreground_ctrl_c(_shutdown: ServiceHostShutdown) -> Result<(), Box<dyn Error>> {
    Ok(())
}
