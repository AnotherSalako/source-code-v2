use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{signed_payload, DeviceKeypair};

#[derive(Serialize)]
struct EnrollRequest<'a> {
    token: &'a str,
    #[serde(rename = "publicKeyBase64")]
    public_key_base64: &'a str,
    hostname: &'a str,
    platform: &'a str,
    #[serde(rename = "osVersion", skip_serializing_if = "Option::is_none")]
    os_version: Option<&'a str>,
}

#[derive(Deserialize)]
pub struct EnrollResponse {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "clientId")]
    pub client_id: String,
    // credentialSignature and caPublicKeyBase64 are also returned but not
    // used client-side yet — the device's own stored keypair + deviceId is
    // what authenticates every future request, not this credential. Kept
    // out of this struct rather than added-and-ignored, so it's obvious
    // nothing here is silently dropping something that matters.
}

fn unix_timestamp() -> Result<i64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64)
}

/// Redeems a single-use enrollment token. Unauthenticated by a device
/// signature (there's no device identity yet) — the token itself, sent
/// once over TLS, is the only credential this call has.
pub fn enroll(
    server_url: &str,
    token: &str,
    keypair: &DeviceKeypair,
    hostname: &str,
    platform: &str,
    os_version: Option<&str>,
) -> Result<EnrollResponse> {
    let client = reqwest::blocking::Client::new();
    let body = EnrollRequest {
        token,
        public_key_base64: &keypair.public_key_base64(),
        hostname,
        platform,
        os_version,
    };

    let res = client
        .post(format!("{server_url}/internal/agents/enroll"))
        .json(&body)
        .send()
        .context("could not reach the Jupiter server")?;

    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().unwrap_or_default();
        bail!("enrollment rejected by server ({status}): {text}");
    }

    Ok(res.json()?)
}

#[derive(Deserialize)]
pub struct WhoamiResponse {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "clientId")]
    pub client_id: String,
}

/// Proves enrollment actually worked end to end: a signed GET that only
/// succeeds if the server's stored public key for this device, this
/// device's private key, and the timestamp/replay-window check all agree.
pub fn whoami(server_url: &str, device_id: &str, keypair: &DeviceKeypair) -> Result<WhoamiResponse> {
    let client = reqwest::blocking::Client::new();
    let timestamp = unix_timestamp()?;
    let payload = signed_payload("GET", "/internal/agents/whoami", timestamp, "");
    let signature = keypair.sign(payload.as_bytes());

    let res = client
        .get(format!("{server_url}/internal/agents/whoami"))
        .header("x-jupiter-device-id", device_id)
        .header("x-jupiter-timestamp", timestamp.to_string())
        .header("x-jupiter-signature", signature)
        .send()
        .context("could not reach the Jupiter server")?;

    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().unwrap_or_default();
        bail!("whoami check failed ({status}): {text}");
    }

    Ok(res.json()?)
}
