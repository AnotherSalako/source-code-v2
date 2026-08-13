use super::NetworkInterface;
use sysinfo::Networks;

/// Interface names and IPs only — no traffic inspection, no packet capture.
pub fn collect() -> Vec<NetworkInterface> {
    let networks = Networks::new_with_refreshed_list();
    let mut results = Vec::new();
    for (name, data) in &networks {
        for ip_network in data.ip_networks() {
            results.push(NetworkInterface { name: name.clone(), ip: ip_network.addr.to_string() });
        }
    }
    results
}
