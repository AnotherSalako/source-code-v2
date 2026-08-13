use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Minimal append-only file logger for the unattended run loop / OS
/// service, where stdout goes nowhere — a Windows Service has no console,
/// and even on Unix a systemd/launchd-managed process's stdout usually
/// isn't something anyone is watching live. Interactive commands (enroll,
/// whoami, service install/uninstall) keep using println!/eprintln!
/// directly; this is only for the path nobody has a terminal open for.
pub fn log_line(message: &str) {
    let line = format!("[{}] {}", unix_timestamp(), message);
    if let Ok(dir) = crate::config::config_dir() {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(dir.join("agent.log")) {
            let _ = writeln!(f, "{line}");
        }
    }
    // Harmless when there's no console attached (a Windows Service, a
    // detached systemd unit) — eprintln! to a closed/absent stderr is a
    // no-op, not an error.
    eprintln!("{line}");
}

fn unix_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
