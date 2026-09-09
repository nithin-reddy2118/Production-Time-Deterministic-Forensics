//! Authentication (architecture §18): API-key based. Keys are hashed
//! (SHA-256) before being stored or compared — the raw key is never
//! retained in memory longer than the single `register_key`/`authenticate`
//! call that needs it, so a memory dump of a running server cannot recover
//! usable credentials, only their hashes (which is exactly the property
//! password/API-key hashing is supposed to give you).
//!
//! Scope: this is API-key auth, appropriate for service-to-service and
//! CLI/agent authentication. Interactive human-user auth (OIDC, per
//! architecture §18's "OIDC for human users of the Query API/CLI") is a
//! separate, larger integration (a real identity provider) and is not
//! implemented here — API-key auth is complete and independently useful
//! without it.

use crate::authz::Role;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("API key must not be empty")]
    EmptyKey,

    #[error("a principal is already registered under this key")]
    DuplicateKey,

    #[error("authentication failed: unknown or invalid API key")]
    InvalidCredentials,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub role: Role,
}

fn hash_key(raw_key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    hasher.finalize().into()
}

/// Generate a new cryptographically random API key, hex-encoded (64
/// characters = 256 bits of entropy). Callers are responsible for
/// displaying/transmitting it exactly once and then registering its hash
/// via `register_key` — this function never stores anything itself.
pub fn generate_random_api_key() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Default)]
pub struct ApiKeyAuthenticator {
    // Keyed by SHA-256 digest of the raw key, never the raw key itself.
    keys: HashMap<[u8; 32], Principal>,
}

impl ApiKeyAuthenticator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `raw_key` as authenticating `principal`. The raw key is
    /// hashed immediately and discarded from this call's perspective —
    /// only the digest is retained.
    pub fn register_key(&mut self, raw_key: &str, principal: Principal) -> Result<(), AuthError> {
        if raw_key.is_empty() {
            return Err(AuthError::EmptyKey);
        }
        let digest = hash_key(raw_key);
        if self.keys.contains_key(&digest) {
            return Err(AuthError::DuplicateKey);
        }
        self.keys.insert(digest, principal);
        Ok(())
    }

    /// Revoke a previously-registered key.
    pub fn revoke_key(&mut self, raw_key: &str) {
        let digest = hash_key(raw_key);
        self.keys.remove(&digest);
    }

    /// Authenticate a presented key, returning the `Principal` it maps to.
    pub fn authenticate(&self, raw_key: &str) -> Result<&Principal, AuthError> {
        if raw_key.is_empty() {
            return Err(AuthError::EmptyKey);
        }
        let digest = hash_key(raw_key);
        self.keys.get(&digest).ok_or(AuthError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(id: &str, role: Role) -> Principal {
        Principal {
            id: id.to_string(),
            role,
        }
    }

    #[test]
    fn register_then_authenticate_succeeds_with_the_correct_key() {
        let mut auth = ApiKeyAuthenticator::new();
        auth.register_key("secret-key-123", principal("svc-a", Role::Operator))
            .unwrap();

        let result = auth.authenticate("secret-key-123").unwrap();
        assert_eq!(result.id, "svc-a");
        assert_eq!(result.role, Role::Operator);
    }

    #[test]
    fn authenticate_with_wrong_key_fails() {
        let mut auth = ApiKeyAuthenticator::new();
        auth.register_key("correct-key", principal("svc-a", Role::Viewer))
            .unwrap();
        assert_eq!(
            auth.authenticate("wrong-key"),
            Err(AuthError::InvalidCredentials)
        );
    }

    #[test]
    fn empty_key_is_rejected_on_both_register_and_authenticate() {
        let mut auth = ApiKeyAuthenticator::new();
        assert_eq!(
            auth.register_key("", principal("x", Role::Viewer)),
            Err(AuthError::EmptyKey)
        );
        assert_eq!(auth.authenticate(""), Err(AuthError::EmptyKey));
    }

    #[test]
    fn duplicate_key_registration_is_rejected() {
        let mut auth = ApiKeyAuthenticator::new();
        auth.register_key("key1", principal("a", Role::Viewer))
            .unwrap();
        assert_eq!(
            auth.register_key("key1", principal("b", Role::Admin)),
            Err(AuthError::DuplicateKey)
        );
    }

    #[test]
    fn revoked_key_no_longer_authenticates() {
        let mut auth = ApiKeyAuthenticator::new();
        auth.register_key("key1", principal("a", Role::Viewer))
            .unwrap();
        assert!(auth.authenticate("key1").is_ok());

        auth.revoke_key("key1");
        assert_eq!(
            auth.authenticate("key1"),
            Err(AuthError::InvalidCredentials)
        );
    }

    #[test]
    fn raw_key_is_never_stored_verbatim() {
        let mut auth = ApiKeyAuthenticator::new();
        auth.register_key("super-secret", principal("a", Role::Viewer))
            .unwrap();
        // The only stored keys are 32-byte SHA-256 digests, structurally
        // incapable of containing the original ASCII string.
        for stored_digest in auth.keys.keys() {
            assert_eq!(stored_digest.len(), 32);
            assert_ne!(stored_digest.as_slice(), b"super-secret");
        }
    }

    #[test]
    fn generated_api_keys_are_64_hex_characters_and_unique() {
        let k1 = generate_random_api_key();
        let k2 = generate_random_api_key();
        assert_eq!(k1.len(), 64);
        assert!(k1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(k1, k2);
    }

    #[test]
    fn a_generated_key_can_be_registered_and_authenticated() {
        let key = generate_random_api_key();
        let mut auth = ApiKeyAuthenticator::new();
        auth.register_key(&key, principal("generated", Role::Admin))
            .unwrap();
        assert_eq!(auth.authenticate(&key).unwrap().id, "generated");
    }
}
