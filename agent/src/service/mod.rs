#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

use anyhow::Result;

pub fn install(interval_hours: u64) -> Result<()> {
    #[cfg(windows)]
    return windows::install(interval_hours);
    #[cfg(target_os = "macos")]
    return macos::install(interval_hours);
    #[cfg(target_os = "linux")]
    return linux::install(interval_hours);
}

pub fn uninstall() -> Result<()> {
    #[cfg(windows)]
    return windows::uninstall();
    #[cfg(target_os = "macos")]
    return macos::uninstall();
    #[cfg(target_os = "linux")]
    return linux::uninstall();
}
