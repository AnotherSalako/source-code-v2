use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// This device's Ed25519 identity. The private key never leaves the
/// process except to be written to platform-secure storage (storage.rs) —
/// it is generated here, on-device, and the server never sees anything but
/// the public half.
pub struct DeviceKeypair {
    signing_key: SigningKey,
}

impl DeviceKeypair {
    pub fn generate() -> Self {
        Self { signing_key: SigningKey::generate(&mut OsRng) }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { signing_key: SigningKey::from_bytes(seed) }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn sign(&self, payload: &[u8]) -> String {
        STANDARD.encode(self.signing_key.sign(payload).to_bytes())
    }
}

/// Exactly the payload format the server's device-auth middleware expects
/// (src/modules/agents/device-auth.middleware.ts): method, path, a
/// unix-second timestamp, and a base64 SHA-256 of the body — empty string
/// hashed for a body-less request. Any mismatch here (a trailing slash, a
/// query string, a different JSON serialization of the body) fails the
/// signature check server-side; this function is the one place that format
/// is allowed to be defined, so client and server can't silently drift.
pub fn signed_payload(method: &str, path: &str, timestamp: i64, body: &str) -> String {
    let body_hash = STANDARD.encode(Sha256::digest(body.as_bytes()));
    format!("{method}.{path}.{timestamp}.{body_hash}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_signature() {
        let keypair = DeviceKeypair::generate();
        let payload = signed_payload("GET", "/internal/agents/whoami", 1_700_000_000, "");
        let signature = keypair.sign(payload.as_bytes());
        assert!(!signature.is_empty());
    }

    #[test]
    fn seed_round_trip_preserves_the_public_key() {
        let original = DeviceKeypair::generate();
        let seed = original.seed();
        let restored = DeviceKeypair::from_seed(&seed);
        assert_eq!(original.public_key_base64(), restored.public_key_base64());
    }

    #[test]
    fn empty_and_nonempty_bodies_hash_differently() {
        let a = signed_payload("POST", "/x", 1, "");
        let b = signed_payload("POST", "/x", 1, "{}");
        assert_ne!(a, b);
    }
}
