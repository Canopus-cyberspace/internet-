use sentinel_elevated_service::{
    run_standalone_named_pipe_server, DEFAULT_PIPE_NAME, SERVICE_DISPLAY_NAME, SERVICE_NAME,
};
use std::env;
use std::error::Error;
use std::process;

fn main() {
    if let Err(error) = run_cli() {
        eprintln!("SERVICE_FATAL {error}");
        process::exit(1);
    }
}

fn run_cli() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--install") => install_service(),
        Some("--uninstall") => uninstall_service(),
        Some("--run") => run_as_windows_service(),
        Some("--standalone") | None => run_standalone(),
        Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!("unsupported argument: {other}").into()),
    }
}

fn print_help() {
    println!("{SERVICE_DISPLAY_NAME}");
    println!("  --standalone   Run foreground Named Pipe server for development");
    println!("  --run          Run through Windows Service Control Manager");
    println!("  --install      Install manual-start LocalSystem Windows service");
    println!("  --uninstall    Remove the Windows service registration");
}

fn run_standalone() -> Result<(), Box<dyn Error>> {
    println!(
        "SERVICE_START mode=standalone service={} pipe={}",
        SERVICE_NAME, DEFAULT_PIPE_NAME
    );
    run_standalone_named_pipe_server(DEFAULT_PIPE_NAME)?;
    Ok(())
}

#[cfg(windows)]
fn install_service() -> Result<(), Box<dyn Error>> {
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    let service_binary_path = env::current_exe()?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary_path,
        launch_arguments: vec![OsString::from("--run")],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    };

    let _service = service_manager.create_service(
        &service_info,
        ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP,
    )?;
    println!(
        "SERVICE_INSTALLED name={} display=\"{}\" startup=manual account=LocalSystem",
        SERVICE_NAME, SERVICE_DISPLAY_NAME
    );
    Ok(())
}

#[cfg(not(windows))]
fn install_service() -> Result<(), Box<dyn Error>> {
    Err("Windows service installation is only available on Windows".into())
}

#[cfg(windows)]
fn uninstall_service() -> Result<(), Box<dyn Error>> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    let _ = service.stop();
    service.delete()?;
    println!("SERVICE_UNINSTALLED name={}", SERVICE_NAME);
    Ok(())
}

#[cfg(not(windows))]
fn uninstall_service() -> Result<(), Box<dyn Error>> {
    Err("Windows service removal is only available on Windows".into())
}

#[cfg(windows)]
fn run_as_windows_service() -> Result<(), Box<dyn Error>> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(not(windows))]
fn run_as_windows_service() -> Result<(), Box<dyn Error>> {
    Err("Windows service mode is only available on Windows".into())
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
    use sentinel_elevated_service::{
        run_one_pipe_connection, ServiceAuditLogger, ServiceCommandDispatcher,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let should_stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&should_stop);
    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop => {
                stop_flag.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: Some(process::id()),
    })?;

    let audit_logger = ServiceAuditLogger::program_data_default();
    let _ = audit_logger.log("service_start", None, "started", Some("scm"));
    let mut dispatcher = ServiceCommandDispatcher::new(audit_logger.clone());

    while !should_stop.load(Ordering::SeqCst) {
        run_one_pipe_connection(DEFAULT_PIPE_NAME, &mut dispatcher)?;
    }

    let _ = audit_logger.log("service_stop", None, "stopped", Some("scm"));
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
