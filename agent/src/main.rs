mod checkin;
mod config;
mod crypto;
mod http;
mod inventory;
mod log;
mod scheduler;
mod service;
mod storage;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use crypto::DeviceKeypair;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "jupiter-agent",
    version,
    about = "Jupiter endpoint agent — enrollment, read-only inventory check-in, and an optional background schedule.",
    long_about = "Jupiter endpoint agent.\n\n\
                  Implemented: enrollment against a Jupiter org via a dashboard-issued \
                  token, a signed self-test, a one-shot read-only inventory check-in \
                  (OS info, installed software, process names, firewall state, network \
                  interfaces — no remediation, no remote command execution), an interval \
                  loop that repeats check-in on a schedule, and OS-service installation \
                  (Windows Service / launchd LaunchDaemon / systemd unit) so that loop \
                  survives a reboot without anyone staying logged in.\n\n\
                  NOT implemented: auto-update, and anything privileged beyond what \
                  `service install` itself needs (real Administrator/root, once, to \
                  register the service — the agent never elevates itself afterward). \
                  See README.md for what's deliberately out of scope and why."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll this machine against a Jupiter org using a token generated in the dashboard.
    Enroll {
        /// Jupiter server base URL, e.g. https://jupiter.example.com (no trailing slash).
        #[arg(long)]
        server: String,
        /// Single-use enrollment token from the dashboard. 30-minute TTL — generate it
        /// right before running this, not in advance.
        #[arg(long)]
        token: String,
    },
    /// Confirms this machine's stored credential still authenticates against the server.
    Whoami,
    /// Collects a read-only inventory snapshot and sends it once, then exits.
    ///
    /// Retries a few times on failure; never queues a failed snapshot for later — the
    /// next check-in (scheduled or manual) just collects a fresh one instead.
    Checkin,
    /// Runs check-in on a repeating interval until stopped (Ctrl-C, or SIGTERM/a service
    /// stop request). This is the foreground process an OS service wraps — `service
    /// install` registers this same loop to survive a reboot; running `run` directly is
    /// for testing the schedule itself without installing anything system-level.
    Run {
        /// Hours between check-ins.
        #[arg(long, default_value_t = 12)]
        interval_hours: u64,
    },
    /// Register or remove this agent as a background OS service (Windows Service /
    /// macOS LaunchDaemon / Linux systemd unit) so `run`'s check-in loop survives a
    /// reboot. Needs Administrator/root — real OS-level privilege that only the person
    /// running this command grants, once; the agent never elevates itself afterward.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Removes every local trace of enrollment (the stored private key and config).
    ///
    /// Deliberately simple in v1: this does NOT contact the server or revoke the device
    /// record there — it only makes this machine forget it was ever enrolled. If the
    /// device should stop being trusted immediately (lost laptop, compromised host),
    /// revoke it from the Jupiter dashboard; don't rely on uninstall alone for that.
    /// Does NOT remove an installed OS service either — run `service uninstall` first.
    Uninstall,
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Installs and starts the background service, running `run`'s check-in loop.
    Install {
        /// Hours between check-ins once installed.
        #[arg(long, default_value_t = 12)]
        interval_hours: u64,
    },
    /// Stops and unregisters the background service. Local enrollment state (the
    /// stored key/config) is untouched — run `jupiter-agent uninstall` separately to
    /// remove that too.
    Uninstall,
}

fn detected_platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

fn main() -> Result<()> {
    // Intercepted before clap ever sees argv: this exact argument is only
    // ever present because `service::windows::install()` registered it as
    // the Windows Service's launch argument — a real person never types
    // this. The Service Control Manager launches the exe this way and then
    // waits for the SCM handshake (service_dispatcher/service_main); running
    // that through the normal Cli::parse() → clap subcommand path would be
    // the wrong shape entirely (clap expects to print help/errors to a
    // console that, under the SCM, doesn't exist).
    #[cfg(windows)]
    {
        if std::env::args().nth(1).as_deref() == Some(service::windows::SCM_LAUNCH_ARG) {
            return service::windows::run_as_service();
        }
    }

    let cli = Cli::parse();

    match cli.command {
        Command::Enroll { server, token } => cmd_enroll(&server, &token),
        Command::Whoami => cmd_whoami(),
        Command::Checkin => checkin::perform_checkin(),
        Command::Run { interval_hours } => cmd_run(interval_hours),
        Command::Service { action } => match action {
            ServiceAction::Install { interval_hours } => service::install(interval_hours),
            ServiceAction::Uninstall => service::uninstall(),
        },
        Command::Uninstall => cmd_uninstall(),
    }
}

fn cmd_enroll(server: &str, token: &str) -> Result<()> {
    if config::exists() {
        bail!("this machine is already enrolled — run `jupiter-agent uninstall` first if you want to re-enroll");
    }

    let keypair = DeviceKeypair::generate();
    let hostname = hostname::get()?.to_string_lossy().into_owned();
    let os_version = {
        let snapshot = inventory::collect();
        format!("{} {}", snapshot.os.name, snapshot.os.version)
    };

    println!("Enrolling {hostname} ({}) against {server}...", detected_platform());
    let response = http::enroll(server, token, &keypair, &hostname, detected_platform(), Some(&os_version))?;

    // Order matters: only persist the config (which marks this machine as
    // "enrolled" for the `config::exists()` check above) after the private
    // key itself is safely stored — never leave a config pointing at a key
    // that was never actually written.
    storage::save_private_key(&keypair.seed())?;
    config::save(&config::AgentConfig {
        server_url: server.to_string(),
        device_id: response.device_id.clone(),
        client_id: response.client_id.clone(),
        checkin_interval_hours: None,
    })?;

    println!("Enrolled. Device ID: {}", response.device_id);
    println!("Verifying the credential actually authenticates a request...");
    let who = http::whoami(server, &response.device_id, &keypair)?;
    println!("Confirmed: server recognizes device {} under client {}.", who.device_id, who.client_id);
    Ok(())
}

fn cmd_whoami() -> Result<()> {
    let cfg = config::load()?;
    let seed = storage::load_private_key()?;
    let keypair = DeviceKeypair::from_seed(&seed);
    let who = http::whoami(&cfg.server_url, &cfg.device_id, &keypair)?;
    println!("Device {} recognized under client {}.", who.device_id, who.client_id);
    Ok(())
}

/// Runs check-in on a repeating interval in the foreground until Ctrl-C
/// (or SIGTERM/SIGHUP on Unix — the "termination" ctrlc feature covers
/// those too, which matters because that's what `systemctl stop` actually
/// sends, not SIGINT). This is exactly the loop an installed OS service
/// wraps (see service::windows::run_service and the macOS/Linux install()
/// functions, which point launchd/systemd at this same `run` command) —
/// running it directly is for testing the schedule itself without
/// installing anything system-level.
fn cmd_run(interval_hours: u64) -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let handler_flag = shutdown.clone();
    ctrlc::set_handler(move || {
        log::log_line("Stop requested — finishing the current cycle and exiting.");
        handler_flag.store(true, Ordering::SeqCst);
    })
    .context("could not install the Ctrl-C/SIGTERM handler")?;

    scheduler::run_loop(Duration::from_secs(interval_hours * 3600), shutdown);
    Ok(())
}

fn cmd_uninstall() -> Result<()> {
    config::clear()?;
    println!("Removed local enrollment state.");
    println!("This device's server-side record still exists — revoke it from the Jupiter");
    println!("dashboard if it should stop being trusted immediately, not just stop checking in.");
    Ok(())
}
