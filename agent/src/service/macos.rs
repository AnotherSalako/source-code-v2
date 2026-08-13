// launchd LaunchDaemon (not LaunchAgent) — this needs to run whether or not
// anyone is logged in, same reasoning as the Windows Service running under
// LocalSystem rather than a per-user Scheduled Task. Needs root to write
// into /Library/LaunchDaemons and to launchctl-load a daemon plist.
//
// UNVERIFIED LIVE: no macOS machine was available while writing this. The
// plist shape and launchctl invocations below follow Apple's own
// documented launchd.plist(5) format and haven't changed in years, but
// "matches the docs" and "actually loads on a real Mac" are different
// claims — treat this the way the rest of this project treats anything
// marked unverified: compile and test it on real hardware before trusting
// it in production.
use anyhow::{bail, Context, Result};
use std::fs;
use std::process::Command;

const LABEL: &str = "com.jupiter.agent";
const PLIST_PATH: &str = "/Library/LaunchDaemons/com.jupiter.agent.plist";
const LOG_PATH: &str = "/var/log/jupiter-agent.log";

pub fn install(interval_hours: u64) -> Result<()> {
    let exe_path = std::env::current_exe()?;
    let exe_path_str = exe_path.to_string_lossy();

    // KeepAlive (not StartInterval) — this keeps one persistent process
    // running our own interval loop, the same shape as the Windows Service
    // and the systemd unit, rather than launchd relaunching a one-shot
    // `checkin` every cycle. Keeps all three platforms behaviorally
    // identical instead of macOS being the odd one out.
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe_path_str}</string>
        <string>run</string>
        <string>--interval-hours</string>
        <string>{interval_hours}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{LOG_PATH}</string>
    <key>StandardErrorPath</key>
    <string>{LOG_PATH}</string>
</dict>
</plist>
"#
    );

    fs::write(PLIST_PATH, plist)
        .context("could not write the LaunchDaemon plist — this needs root (try: sudo jupiter-agent service install)")?;

    let status = Command::new("launchctl")
        .args(["load", "-w", PLIST_PATH])
        .status()
        .context("could not run launchctl")?;
    if !status.success() {
        bail!("launchctl load failed — check `launchctl list | grep jupiter` and {LOG_PATH}");
    }

    println!("Installed and started as a LaunchDaemon.");
    println!("Logs: {LOG_PATH}");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    // Best-effort unload; a plist that's already unloaded (or was never
    // loaded this boot) erroring here isn't a real failure.
    let _ = Command::new("launchctl").args(["unload", "-w", PLIST_PATH]).status();

    if std::path::Path::new(PLIST_PATH).exists() {
        fs::remove_file(PLIST_PATH).context("could not remove the plist — this needs root")?;
    }

    println!("Uninstalled the LaunchDaemon.");
    Ok(())
}
