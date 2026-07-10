//! Ed25519 verification for the self-update path. The pinned publisher key(s)
//! live here (an array, so a rotation ships additively: a build pins both the
//! new and old key, the private key swaps a deploy later). The same key signs
//! release assets in CI; the public key is also served at
//! www.sevrahq.com/install/sevra.pub for out-of-band checks.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

/// SPKI PEMs of the accepted publisher keys. Same key the TS chain shipped.
const PUBKEYS_PEM: &[&str] = &[
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA+v5mafEPcIwKAU/DO/z8MM/cT9ndgE1saSUfvcrzLKA=\n-----END PUBLIC KEY-----",
];

/// Extract the raw 32-byte Ed25519 key from an SPKI PEM. Ed25519 SPKI is a
/// fixed 12-byte prefix + the 32-byte key, so the last 32 bytes of the decoded
/// body are the key.
fn spki_to_raw(pem: &str) -> Option<[u8; 32]> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>();
    let der = STANDARD.decode(b64.trim()).ok()?;
    if der.len() < 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&der[der.len() - 32..]);
    Some(key)
}

/// True if `sig_b64` (standard base64 of 64 raw bytes) is a valid signature of
/// `message` under ANY pinned key.
pub fn verify(message: &[u8], sig_b64: &str) -> bool {
    let sig_bytes = match STANDARD.decode(sig_b64.trim()) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    for pem in PUBKEYS_PEM {
        if let Some(raw) = spki_to_raw(pem) {
            if let Ok(vk) = VerifyingKey::from_bytes(&raw) {
                if vk.verify_strict(message, &signature).is_ok() {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(!verify(b"hello", "not-base64!!"));
        assert!(!verify(b"hello", &STANDARD.encode([0u8; 64])));
    }

    #[test]
    fn pinned_key_parses() {
        // The pinned SPKI must decode to a usable 32-byte key.
        let raw = spki_to_raw(PUBKEYS_PEM[0]).expect("pinned key parses");
        assert!(VerifyingKey::from_bytes(&raw).is_ok());
    }
}
