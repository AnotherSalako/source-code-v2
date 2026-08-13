use super::FirewallStatus;
use std::process::Command;

/// Read-only, connect-only equivalent for firewall state: never attempts
/// to change it, only asks the OS's own tool what it currently reports.

#[cfg(target_os = "windows")]
pub fn collect() -> FirewallStatus {
    // Unprivileged read — no admin needed on Windows to query this.
    let output = Command::new("netsh").args(["advfirewall", "show", "currentprofile", "state"]).output();
    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout).to_lowercase();
            if text.contains("state") && text.contains("on") {
                FirewallStatus::Enabled
            } else if text.contains("off") {
                FirewallStatus::Disabled
            } else {
                FirewallStatus::Unavailable
            }
        }
        _ => FirewallStatus::Unavailable,
    }
}

#[cfg(target_os = "macos")]
pub fn collect() -> FirewallStatus {
    // Unprivileged read via Apple's own tool for exactly this query.
    let output = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw").arg("--getglobalstate").output();
    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout).to_lowercase();
            if text.contains("enabled") {
                FirewallStatus::Enabled
            } else if text.contains("disabled") {
                FirewallStatus::Disabled
            } else {
                FirewallStatus::Unavailable
            }
        }
        _ => FirewallStatus::Unavailable,
    }
}

#[cfg(target_os = "linux")]
pub fn collect() -> FirewallStatus {
    // Linux is the one platform where reading firewall state genuinely
    // needs root — this is expected to work ONLY because provisioning
    // (Terraform/Packer/cloud-init) added a narrowly-scoped sudoers rule
    // for exactly this one command (see README.md "Provisioning-time
    // privilege grant"). The agent itself never elevates, never prompts,
    // and never runs `sudo` for anything else. `-n` (non-interactive)
    // means a missing/misconfigured grant fails immediately rather than
    // hanging on a password prompt that will never be answered.
    let output = Command::new("sudo").args(["-n", "ufw", "status"]).output();
    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout).to_lowercase();
            if text.contains("status: active") {
                FirewallStatus::Enabled
            } else if text.contains("status: inactive") {
                FirewallStatus::Disabled
            } else {
                FirewallStatus::Unavailable
            }
        }
        // No sudo grant configured, ufw not installed, or some other
        // firewall tool in use (nftables/firewalld) — degrade, don't fail
        // the whole check-in over one field.
        _ => FirewallStatus::Unavailable,
    }
}
