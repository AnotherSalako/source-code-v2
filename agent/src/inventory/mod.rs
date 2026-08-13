mod firewall;
mod network;
mod os_info;
mod processes;
mod software;

use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

// Field names/shapes here are the wire contract with the server's
// inventorySchema (src/modules/agents/agents.routes.ts) — keep them in
// sync deliberately, not by accident. `skip_serializing_if` on every
// Option matters: the server's zod schema uses `.optional()` (key may be
// *absent*), not `.nullable()` (key present, value null) — serializing
// `None` as an explicit `null` would fail validation there instead of
// just being omitted.

#[derive(Serialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
}

#[derive(Serialize)]
pub struct SoftwareEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Serialize)]
pub struct ProcessEntry {
    pub name: String,
}

#[derive(Serialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: String,
}

#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FirewallStatus {
    Enabled,
    Disabled,
    Unavailable,
}

#[derive(Serialize)]
pub struct InventorySnapshot {
    pub os: OsInfo,
    pub software: Vec<SoftwareEntry>,
    pub processes: Vec<ProcessEntry>,
    pub firewall: FirewallStatus,
    pub interfaces: Vec<NetworkInterface>,
    #[serde(rename = "collectedAt")]
    pub collected_at: i64,
}

/// Collects everything in one pass. Never panics — each sub-collector
/// degrades to an empty list / Unavailable on its own failure (missing
/// tool, permission denied, unrecognized platform variant) rather than
/// taking down the whole check-in over one field.
pub fn collect() -> InventorySnapshot {
    InventorySnapshot {
        os: os_info::collect(),
        software: software::collect(),
        processes: processes::collect(),
        firewall: firewall::collect(),
        interfaces: network::collect(),
        collected_at: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0),
    }
}
