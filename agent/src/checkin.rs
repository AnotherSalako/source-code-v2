use anyhow::Result;
use std::time::Duration;

use crate::crypto::DeviceKeypair;
use crate::{config, http, inventory, log, storage};

// Retry-only, deliberately no offline queue: a snapshot that fails to send
// after these attempts is dropped, not persisted — the next scheduled
// check-in collects and sends a fresh one instead of retrying a stale one.
// Simpler, and avoids ever answering "which snapshot is this actually
// from" after a long outage.
const CHECKIN_RETRY_DELAYS_SECS: [u64; 3] = [5, 30, 120];

/// Collects and sends one inventory snapshot, retrying on failure. Shared
/// by the one-shot `checkin` command, the `run` interval loop, and the OS
/// service entry point — identical behavior everywhere; only what calls it
/// and how often differs.
pub fn perform_checkin() -> Result<()> {
    let cfg = config::load()?;
    let seed = storage::load_private_key()?;
    let keypair = DeviceKeypair::from_seed(&seed);

    log::log_line("Collecting inventory...");
    let snapshot = inventory::collect();
    log::log_line(&format!(
        "Collected: {} software entries, {} processes, {} network interfaces, firewall: {:?}.",
        snapshot.software.len(),
        snapshot.processes.len(),
        snapshot.interfaces.len(),
        snapshot.firewall
    ));

    let mut last_err = None;
    for (attempt, delay) in CHECKIN_RETRY_DELAYS_SECS.iter().enumerate() {
        match http::checkin(&cfg.server_url, &cfg.device_id, &keypair, &snapshot) {
            Ok(()) => {
                log::log_line("Check-in succeeded.");
                return Ok(());
            }
            Err(e) => {
                log::log_line(&format!("Check-in attempt {} failed: {e}", attempt + 1));
                last_err = Some(e);
                if attempt + 1 < CHECKIN_RETRY_DELAYS_SECS.len() {
                    std::thread::sleep(Duration::from_secs(*delay));
                }
            }
        }
    }

    Err(last_err.unwrap())
}
