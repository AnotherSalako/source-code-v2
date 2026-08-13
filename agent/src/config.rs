use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct AgentConfig {
    pub server_url: String,
    pub device_id: String,
    pub client_id: String,
}

pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("could not resolve a platform config directory")?;
    let dir = base.join("jupiter-agent");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.json"))
}

pub fn save(config: &AgentConfig) -> Result<()> {
    fs::write(config_path()?, serde_json::to_string_pretty(config)?)?;
    Ok(())
}

pub fn load() -> Result<AgentConfig> {
    let raw = fs::read_to_string(config_path()?).context("not enrolled yet — run `jupiter-agent enroll` first")?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn exists() -> bool {
    config_path().map(|p| p.exists()).unwrap_or(false)
}

/// Deletes every trace this agent leaves on disk — the config file and the
/// stored private key (storage.rs). Uninstall must be trivially complete,
/// not a partial cleanup that leaves an orphaned credential behind; this is
/// a trust requirement for this project, not optional polish.
pub fn clear() -> Result<()> {
    let path = config_path()?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    crate::storage::delete_private_key()
}
