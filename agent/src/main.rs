mod config;
mod crypto;
mod http;
mod storage;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use crypto::DeviceKeypair;

#[derive(Parser)]
#[command(
    name = "jupiter-agent",
    version,
    about = "Jupiter endpoint agent — v1: enrollment + a signed self-test only.",
    long_about = "Jupiter endpoint agent — v1 scope.\n\n\
                  Implemented: enrollment against a Jupiter org via a dashboard-issued \
                  token, and a signed self-test that proves the resulting device \
                  credential authenticates real requests.\n\n\
                  NOT yet implemented: inventory collection, scheduled/on-demand \
                  check-in reporting, OS-service installation (Windows Service / \
                  launchd / systemd), auto-update, and anything privileged. See \
                  README.md for what's deliberately out of scope for v1 and why."
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
        Command::Uninstall => cmd_uninstall(),
    }
}

fn cmd_enroll(server: &str, token: &str) -> Result<()> {
    if config::exists() {
        bail!("this machine is already enrolled — run `jupiter-agent uninstall` first if you want to re-enroll");
    }

    let keypair = DeviceKeypair::generate();
    let hostname = hostname::get()?.to_string_lossy().into_owned();
    // Real OS name/version/patch-level detection is inventory-collection
    // scope (deliberately not built yet, per this project's phased scope —
    // see README.md) — this is a best-effort placeholder so the enrollment
    // record isn't blank, not the real thing.
    let os_version = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);

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

fn cmd_uninstall() -> Result<()> {
    config::clear()?;
    println!("Removed local enrollment state.");
    println!("This device's server-side record still exists — revoke it from the Jupiter");
    println!("dashboard if it should stop being trusted immediately, not just stop checking in.");
    Ok(())
}
