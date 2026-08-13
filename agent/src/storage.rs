use anyhow::{Context, Result};

const SERVICE_NAME: &str = "jupiter-agent";
const KEY_ENTRY: &str = "device-private-key";

/// Persists the device's Ed25519 private key seed (32 raw bytes) using
/// whatever secure-storage mechanism actually exists on this platform.
///
/// Windows/macOS: the real OS credential store (Credential Manager /
/// Keychain) via the `keyring` crate — the standard, audited way to do
/// this on both.
///
/// Linux: intentionally NOT `keyring`'s Secret Service backend — that
/// backend assumes a desktop session with gnome-keyring/kwallet running,
/// which a headless server (a very likely place to run this agent) simply
/// doesn't have. Falls back to a file with 0600 permissions in the config
/// directory instead. This is a documented v1 limitation, not an
/// oversight: anyone with read access to that file (root, or whatever
/// account this agent's service runs as) can read the key. Real
/// secret-store integration (systemd-creds, a TPM-backed store, etc.) is
/// honest follow-up work, not something to fake with a weaker mechanism
/// dressed up as equivalent.
pub fn save_private_key(seed: &[u8; 32]) -> Result<()> {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        let entry = keyring::Entry::new(SERVICE_NAME, KEY_ENTRY)?;
        entry.set_secret(seed)?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let path = crate::config::config_dir()?.join("device.key");
        fs::write(&path, seed)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}

pub fn load_private_key() -> Result<[u8; 32]> {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        let entry = keyring::Entry::new(SERVICE_NAME, KEY_ENTRY)?;
        let secret = entry.get_secret().context("no device key found — has this machine been enrolled?")?;
        secret.try_into().map_err(|_| anyhow::anyhow!("stored key has the wrong length"))
    }
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let path = crate::config::config_dir()?.join("device.key");
        let bytes = fs::read(&path).context("no device key found — has this machine been enrolled?")?;
        bytes.try_into().map_err(|_| anyhow::anyhow!("stored key has the wrong length"))
    }
}

/// Part of `jupiter-agent uninstall` — removing the key must be as
/// unconditional as writing it was. Missing-file is not an error here: the
/// end state ("no key on disk") is what matters, not whether there
/// happened to be one already.
pub fn delete_private_key() -> Result<()> {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        let entry = keyring::Entry::new(SERVICE_NAME, KEY_ENTRY)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let path = crate::config::config_dir()?.join("device.key");
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
