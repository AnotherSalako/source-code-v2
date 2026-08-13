// systemd unit — the standard for anything expected to run headless on
// Linux (this agent's most likely real-world Linux home, per storage.rs's
// same reasoning for why it doesn't use keyring's Secret Service backend
// there). Needs root to write into /etc/systemd/system and to enable it.
//
// UNVERIFIED LIVE: no Linux machine was available while writing this. The
// unit file shape and systemctl invocations follow systemd.service(5)'s
// documented format, but that's a different claim from "actually starts on
// a real system" — compile and test on real hardware before trusting it.
use anyhow::{bail, Context, Result};
use std::fs;
use std::process::Command;

const UNIT_PATH: &str = "/etc/systemd/system/jupiter-agent.service";
const UNIT_NAME: &str = "jupiter-agent";

pub fn install(interval_hours: u64) -> Result<()> {
    let exe_path = std::env::current_exe()?;
    let exe_path_str = exe_path.to_string_lossy();

    // Restart=on-failure is a crash safety net, not the scheduling
    // mechanism — `run` itself loops internally and never exits under
    // normal operation, the same shape as the Windows Service and the
    // macOS LaunchDaemon (KeepAlive). systemd restarting a *crashed*
    // process is a separate, complementary concern from who decides when
    // the next check-in happens.
    let unit = format!(
        r#"[Unit]
Description=Jupiter Endpoint Agent — periodic read-only inventory check-in
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe_path_str} run --interval-hours {interval_hours}
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
"#
    );

    fs::write(UNIT_PATH, unit)
        .context("could not write the systemd unit — this needs root (try: sudo jupiter-agent service install)")?;

    let reload = Command::new("systemctl").arg("daemon-reload").status().context("could not run systemctl")?;
    if !reload.success() {
        bail!("systemctl daemon-reload failed");
    }

    let enable = Command::new("systemctl")
        .args(["enable", "--now", UNIT_NAME])
        .status()
        .context("could not run systemctl")?;
    if !enable.success() {
        bail!("systemctl enable --now failed — check `systemctl status {UNIT_NAME}`");
    }

    println!("Installed and started as a systemd service.");
    println!("Logs: journalctl -u {UNIT_NAME}");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    // Best-effort; a unit that's already disabled/stopped erroring here
    // isn't a real failure.
    let _ = Command::new("systemctl").args(["disable", "--now", UNIT_NAME]).status();

    if std::path::Path::new(UNIT_PATH).exists() {
        fs::remove_file(UNIT_PATH).context("could not remove the unit file — this needs root")?;
    }
    let _ = Command::new("systemctl").arg("daemon-reload").status();

    println!("Uninstalled the systemd service.");
    Ok(())
}
