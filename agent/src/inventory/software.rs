use super::SoftwareEntry;

#[cfg(target_os = "windows")]
pub fn collect() -> Vec<SoftwareEntry> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    // The standard place Windows itself records installed programs — same
    // location Add/Remove Programs reads from. Both paths are readable by
    // any user, no admin needed; the second covers 32-bit apps on a 64-bit
    // OS, which live under the Wow6432Node redirect.
    const UNINSTALL_PATHS: [&str; 2] = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut results = Vec::new();

    for path in UNINSTALL_PATHS {
        let Ok(uninstall_key) = hklm.open_subkey(path) else { continue };
        for subkey_name in uninstall_key.enum_keys().flatten() {
            let Ok(subkey) = uninstall_key.open_subkey(&subkey_name) else { continue };
            let Ok(name) = subkey.get_value::<String, _>("DisplayName") else { continue };
            let name = name.trim().to_string();
            if name.is_empty() {
                continue; // registry entries with no DisplayName are usually system components, not real "installed software"
            }
            let version = subkey.get_value::<String, _>("DisplayVersion").ok();
            results.push(SoftwareEntry { name, version });
        }
    }

    results
}

#[cfg(target_os = "macos")]
pub fn collect() -> Vec<SoftwareEntry> {
    use std::process::Command;

    // Apple's own tool for exactly this — reads Info.plist bundles across
    // /Applications so this doesn't need to hand-parse plists itself.
    let Ok(output) = Command::new("system_profiler").args(["SPApplicationsDataType", "-json"]).output() else {
        return Vec::new();
    };
    let Ok(json): Result<serde_json::Value, _> = serde_json::from_slice(&output.stdout) else {
        return Vec::new();
    };

    json.get("SPApplicationsDataType")
        .and_then(|v| v.as_array())
        .map(|apps| {
            apps.iter()
                .filter_map(|app| {
                    let name = app.get("_name")?.as_str()?.to_string();
                    let version = app.get("version").and_then(|v| v.as_str()).map(String::from);
                    Some(SoftwareEntry { name, version })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
pub fn collect() -> Vec<SoftwareEntry> {
    use std::process::Command;

    // Try dpkg (Debian/Ubuntu family) first, then rpm (RHEL/Fedora family)
    // — no single package manager is universal across Linux, so this tries
    // the two that cover the overwhelming majority of server deployments
    // and returns empty (not an error) if neither is present.
    if let Ok(output) = Command::new("dpkg-query").args(["-W", "-f=${Package}\t${Version}\n"]).output() {
        if output.status.success() {
            return parse_tab_separated(&output.stdout);
        }
    }
    if let Ok(output) = Command::new("rpm").args(["-qa", "--qf", "%{NAME}\t%{VERSION}\n"]).output() {
        if output.status.success() {
            return parse_tab_separated(&output.stdout);
        }
    }
    Vec::new()
}

#[cfg(target_os = "linux")]
fn parse_tab_separated(bytes: &[u8]) -> Vec<SoftwareEntry> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, '\t');
            let name = parts.next()?.trim().to_string();
            if name.is_empty() {
                return None;
            }
            let version = parts.next().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
            Some(SoftwareEntry { name, version })
        })
        .collect()
}
