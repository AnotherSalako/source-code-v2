// Real Windows Service Control Manager integration. A plain exe pointed at
// by a registry key is NOT a working Windows Service — the SCM expects the
// process to call back with SERVICE_START_PENDING/SERVICE_RUNNING within a
// startup timeout and to respond to control codes (Stop, Shutdown); a
// process that never does either gets killed as "failed to start" the
// moment the SCM's patience runs out. `windows-service` handles that
// handshake correctly via `service_dispatcher`/`service_control_handler`.
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const SERVICE_NAME: &str = "JupiterAgent";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

// The argument `main.rs` looks for before clap ever runs — see its
// top-of-main() check. Not a real subcommand a person would type; this is
// only ever invoked by the SCM itself, using exactly this launch argument,
// because `install()` below registered it that way.
pub const SCM_LAUNCH_ARG: &str = "__winsvc-run";

define_windows_service!(ffi_service_main, service_main);

/// Called by main.rs when it detects it was launched by the SCM (not a
/// person at a terminal). Blocks until the service is told to stop.
pub fn run_as_service() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).context("service_dispatcher::start failed")?;
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        crate::log::log_line(&format!("Windows Service exited with an error: {e}"));
    }
}

fn run_service() -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_for_handler = shutdown.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown_for_handler.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("could not register the service control handler")?;

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // The interval lives in config.json (set by install(), below) rather
    // than being parsed from argv here — the SCM launches us with exactly
    // the launch_arguments registered at install time, and threading a
    // second value through that path is more moving parts than just
    // reading the one config file this process already reads for
    // everything else.
    let interval_hours = crate::config::load().ok().and_then(|c| c.checkin_interval_hours).unwrap_or(12);
    crate::scheduler::run_loop(Duration::from_secs(interval_hours * 3600), shutdown);

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

pub fn install(interval_hours: u64) -> Result<()> {
    // Persisted so run_service() (above) can read it back — see that
    // function's comment for why this goes through config.json instead of
    // argv.
    let mut cfg = crate::config::load().context("enroll this machine (`jupiter-agent enroll`) before installing the service")?;
    cfg.checkin_interval_hours = Some(interval_hours);
    crate::config::save(&cfg)?;

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
        .context("could not open the Windows Service Control Manager — run this from an elevated (Administrator) prompt")?;

    let exe_path = std::env::current_exe()?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Jupiter Endpoint Agent"),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![OsString::from(SCM_LAUNCH_ARG)],
        dependencies: vec![],
        // LocalSystem (the default when this is None) — the same account
        // that already has unprompted access to everything this agent's
        // inventory collection reads (installed-software registry keys,
        // process list, `netsh advfirewall`). No new privilege the agent
        // didn't already have when run interactively as an admin; running
        // as a dedicated least-privilege service account is real follow-up
        // work, not something to fake here with a config flag that doesn't
        // actually reduce what the process can touch.
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(&service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("could not create the service — is one already installed? (`jupiter-agent service uninstall` first)")?;
    service.set_description("Periodic read-only inventory check-in for Jupiter. No remote command execution.")?;

    println!("Installed as a Windows Service (Start type: Automatic).");
    println!("Starting it now...");
    service.start::<&str>(&[])?;
    println!("Started. Check status with: sc query {SERVICE_NAME}");
    println!("Logs: %APPDATA%\\jupiter-agent\\agent.log");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("could not open the Windows Service Control Manager — run this from an elevated (Administrator) prompt")?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)
        .context("service not found — was it installed?")?;

    // Best-effort stop before delete; Windows won't delete a running
    // service's registration until it's stopped, but a service that's
    // already stopped (or mid-stop) erroring here isn't a real failure.
    let _ = service.stop();
    service.delete().context("could not delete the service")?;

    println!("Uninstalled the Windows Service.");
    println!("Run `jupiter-agent uninstall` too if you want to fully remove local enrollment state.");
    Ok(())
}
