use super::OsInfo;

pub fn collect() -> OsInfo {
    OsInfo {
        name: sysinfo::System::name().unwrap_or_else(|| "unknown".to_string()),
        version: sysinfo::System::os_version().unwrap_or_else(|| "unknown".to_string()),
        build: sysinfo::System::kernel_version(),
    }
}
