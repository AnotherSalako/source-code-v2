use super::ProcessEntry;
use sysinfo::System;

/// Names only — no memory inspection, no command-line args, no environment.
pub fn collect() -> Vec<ProcessEntry> {
    let sys = System::new_all();
    sys.processes()
        .values()
        .map(|p| ProcessEntry { name: p.name().to_string_lossy().into_owned() })
        .collect()
}
