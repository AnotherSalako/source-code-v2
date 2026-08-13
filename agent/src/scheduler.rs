use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::{checkin, log};

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Runs check-in on a fixed interval until `shutdown` is set. Shared by the
/// plain `run` command and the Windows Service entry point — the service's
/// SCM control handler and `run`'s Ctrl-C/SIGTERM handler both just set the
/// same flag, so this loop doesn't need to know which one it's running
/// under.
///
/// Sleeps in 1-second increments rather than one long sleep so a stop
/// request is honored within about a second instead of waiting out
/// whatever's left of the current interval — matters most for `systemctl
/// stop`/SCM stop, which both expect a service to actually exit promptly,
/// not after several more hours.
pub fn run_loop(interval: Duration, shutdown: Arc<AtomicBool>) {
    log::log_line(&format!("Check-in loop starting, every {}s.", interval.as_secs()));
    while !shutdown.load(Ordering::SeqCst) {
        if let Err(e) = checkin::perform_checkin() {
            log::log_line(&format!("Scheduled check-in failed: {e}"));
        }

        let mut waited = Duration::ZERO;
        while waited < interval {
            if shutdown.load(Ordering::SeqCst) {
                log::log_line("Stop requested — exiting.");
                return;
            }
            std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
            waited += SHUTDOWN_POLL_INTERVAL;
        }
    }
    log::log_line("Stop requested — exiting.");
}
