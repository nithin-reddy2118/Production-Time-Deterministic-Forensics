//! Encryption at rest (architecture §18: "segments and blobs encrypted at
//! rest with AES-256-GCM, per-session data-encryption-keys wrapped by a
//! KMS-held key"). This module implements the DEK (data-encryption-key)
//! generation and the actual AES-256-GCM encrypt/decrypt of arbitrary
//! byte payloads (segment bytes, blob-store contents). It deliberately
//! does **not** implement KMS wrapping of the DEK itself — that's
//! inherently specific to which KMS a deployment uses (AWS KMS, Azure Key
//! Vault, HashiCorp Vault, per architecture §18), and integrating any one
//! of them is a deployment-time choice, not something this crate should
//! hardcode. `DataEncryptionKey::as_bytes`/`from_bytes` is exactly the
//! seam a KMS integration wraps/unwraps at.
//!
//! Uses the `aes-gcm` crate (RustCrypto, widely audited) rather than a
//! hand-rolled implementation — cryptographic primitives are exactly the
//! kind of code where "we wrote it ourselves" is a liability, not a
//! feature, regardless of this workspace's general preference for
//! dependency-light crates elsewhere.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use std::fmt;
use thiserror::Error;

const NONCE_LEN: usize = 12;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncryptionError {
    #[error("encryption failed")]
    EncryptFailed,

    #[error("decryption failed: ciphertext is corrupt, truncated, or was encrypted under a different key")]
    DecryptFailed,

    #[error("ciphertext too short to contain a nonce: need at least {NONCE_LEN} bytes, got {0}")]
    TooShort(usize),
}

/// A 256-bit AES-GCM key. `Debug` is intentionally redacted — a key must
/// never end up in a log line via an accidental `{:?}` on a struct that
/// contains one.
pub struct DataEncryptionKey(Key<Aes256Gcm>);

impl fmt::Debug for DataEncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DataEncryptionKey(<redacted>)")
    }
}

impl DataEncryptionKey {
    /// Generate a new random key using the OS CSPRNG. This is the normal
    /// path for creating a fresh per-session DEK (architecture §18).
    pub fn generate() -> Self {
        Self(Aes256Gcm::generate_key(&mut OsRng))
    }

    /// Reconstruct a key from raw bytes — the seam a KMS-unwrap operation
    /// would call into after retrieving/decrypting the DEK.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(*Key::<Aes256Gcm>::from_slice(&bytes))
    }

    /// Export raw key bytes — the seam a KMS-wrap operation would call
    /// before persisting the (now-wrapped) DEK alongside the session.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Encrypt `plaintext` under `key`, returning `nonce || ciphertext`
/// (ciphertext includes the GCM authentication tag, per the `aes-gcm`
/// crate's standard output format). The nonce is generated fresh via the
/// OS CSPRNG for every call — reusing a nonce with the same key would
/// catastrophically break AES-GCM's confidentiality guarantee, so this
/// function never accepts a caller-supplied nonce.
pub fn encrypt(key: &DataEncryptionKey, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let cipher = Aes256Gcm::new(&key.0);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| EncryptionError::EncryptFailed)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data previously produced by `encrypt` under the same `key`.
pub fn decrypt(key: &DataEncryptionKey, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if data.len() < NONCE_LEN {
        return Err(EncryptionError::TooShort(data.len()));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(&key.0);
    cipher.decrypt(nonce, ciphertext).map_err(|_| EncryptionError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt_recovers_the_plaintext() {
        let key = DataEncryptionKey::generate();
        let plaintext = b"segment bytes go here, potentially containing sensitive syscall arguments";
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let recovered = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext_verbatim() {
        let key = DataEncryptionKey::generate();
        let plaintext = b"a very recognizable secret string marker";
        let ciphertext = encrypt(&key, plaintext).unwrap();
        assert!(
            !ciphertext.windows(plaintext.len()).any(|w| w == plaintext),
            "ciphertext must not contain the plaintext as a substring"
        );
    }

    #[test]
    fn decrypting_with_the_wrong_key_fails() {
        let key1 = DataEncryptionKey::generate();
        let key2 = DataEncryptionKey::generate();
        let ciphertext = encrypt(&key1, b"secret").unwrap();
        assert_eq!(decrypt(&key2, &ciphertext), Err(EncryptionError::DecryptFailed));
    }

    #[test]
    fn tampering_with_ciphertext_is_detected() {
        let key = DataEncryptionKey::generate();
        let mut ciphertext = encrypt(&key, b"authenticated data").unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        assert_eq!(decrypt(&key, &ciphertext), Err(EncryptionError::DecryptFailed), "GCM must detect tampering, not silently return corrupted plaintext");
    }

    #[test]
    fn truncated_ciphertext_is_rejected_before_attempting_decryption() {
        assert_eq!(decrypt(&DataEncryptionKey::generate(), &[0u8; 5]), Err(EncryptionError::TooShort(5)));
    }

    #[test]
    fn key_round_trips_through_bytes() {
        let key = DataEncryptionKey::generate();
        let bytes: [u8; 32] = key.as_bytes().try_into().unwrap();
        let reconstructed = DataEncryptionKey::from_bytes(bytes);

        let ciphertext = encrypt(&key, b"data").unwrap();
        let recovered = decrypt(&reconstructed, &ciphertext).unwrap();
        assert_eq!(recovered, b"data");
    }

    #[test]
    fn debug_output_never_reveals_key_material() {
        let key1 = DataEncryptionKey::generate();
        let key2 = DataEncryptionKey::generate();
        assert_ne!(key1.as_bytes(), key2.as_bytes(), "precondition: the two keys must actually differ");

        // The real, non-tautological property: Debug output is identical
        // regardless of the underlying key bytes — i.e. it structurally
        // cannot vary with (and so cannot leak) key material.
        let debug1 = format!("{key1:?}");
        let debug2 = format!("{key2:?}");
        assert_eq!(debug1, debug2);
        assert_eq!(debug1, "DataEncryptionKey(<redacted>)");
    }

    #[test]
    fn two_generated_keys_are_different() {
        let key1 = DataEncryptionKey::generate();
        let key2 = DataEncryptionKey::generate();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn two_encryptions_of_the_same_plaintext_produce_different_ciphertext() {
        // Because the nonce is fresh every call — proves nonce reuse
        // protection is actually working, not just present in the code.
        let key = DataEncryptionKey::generate();
        let c1 = encrypt(&key, b"same plaintext").unwrap();
        let c2 = encrypt(&key, b"same plaintext").unwrap();
        assert_ne!(c1, c2);
    }
}
