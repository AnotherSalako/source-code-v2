mod config;
mod crypto;
mod http;
mod inventory;
mod storage;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use crypto::DeviceKeypair;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "jupiter-agent",
    version,
    about = "Jupiter endpoint agent — v1: enrollment + read-only inventory check-in.",
    long_about = "Jupiter endpoint agent — v1 scope.\n\n\
                  Implemented: enrollment against a Jupiter org via a dashboard-issued \
                  token, a signed self-test, and a one-shot read-only inventory check-in \
                  (OS info, installed software, process names, firewall state, network \
                  interfaces — no remediation, no remote command execution).\n\n\
                  NOT yet implemented: a persistent scheduler (this binary collects and \
                  sends once per invocation; running it on an interval is an OS-scheduler \
                  or service-installation concern, not built yet), OS-service installation \
                  (Windows Service / launchd / systemd), auto-update, and anything \
                  privileged. See README.md for what's deliberately out of scope and why."
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
    /// Collects a read-only inventory snapshot and sends it — the "check in now" action,
    /// also what a scheduler (cron/Task Scheduler/systemd timer) would invoke periodically
    /// once one exists. Retries a few times on failure; never queues a failed snapshot for
    /// later — the next scheduled run just collects a fresh one instead.
    Checkin,
    /// Removes every local trace of enrollment (the stored private key and config).
    ///
    /// Deliberately simple in v1: this does NOT contact the server or revoke the device
    /// record there — it only makes this machine forget it was ever enrolled. If the
    /// device should stop being trusted immediately (lost laptop, compromised host),
    /// revoke it from the Jupiter dashboard; don't rely on uninstall alone for that.
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
    let cli = Cli::parse();

    match cli.command {
        Command::Enroll { server, token } => cmd_enroll(&server, &token),
        Command::Whoami => cmd_whoami(),
        Command::Checkin => cmd_checkin(),
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

// Retry-only, deliberately no offline queue: a snapshot that fails to send
// after these attempts is dropped, not persisted — the next scheduled
// check-in (once a scheduler exists) collects and sends a fresh one
// instead of retrying a stale one. Simpler, and avoids ever answering "which
// snapshot is this actually from" after a long outage.
const CHECKIN_RETRY_DELAYS_SECS: [u64; 3] = [5, 30, 120];

fn cmd_checkin() -> Result<()> {
    let cfg = config::load()?;
    let seed = storage::load_private_key()?;
    let keypair = DeviceKeypair::from_seed(&seed);

    println!("Collecting inventory...");
    let snapshot = inventory::collect();
    println!(
        "Collected: {} software entries, {} processes, {} network interfaces, firewall: {:?}.",
        snapshot.software.len(),
        snapshot.processes.len(),
        snapshot.interfaces.len(),
        snapshot.firewall
    );

    let mut last_err = None;
    for (attempt, delay) in CHECKIN_RETRY_DELAYS_SECS.iter().enumerate() {
        match http::checkin(&cfg.server_url, &cfg.device_id, &keypair, &snapshot) {
            Ok(()) => {
                println!("Check-in succeeded.");
                return Ok(());
            }
            Err(e) => {
                eprintln!("Check-in attempt {} failed: {e}", attempt + 1);
                last_err = Some(e);
                if attempt + 1 < CHECKIN_RETRY_DELAYS_SECS.len() {
                    std::thread::sleep(Duration::from_secs(*delay));
                }
            }
        }
    }

    Err(last_err.unwrap())
}

fn cmd_uninstall() -> Result<()> {
    config::clear()?;
    println!("Removed local enrollment state.");
    println!("This device's server-side record still exists — revoke it from the Jupiter");
    println!("dashboard if it should stop being trusted immediately, not just stop checking in.");
    Ok(())
}
