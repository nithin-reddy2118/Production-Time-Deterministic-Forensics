//! `ptdf-security` — Authentication, Authorization, Encryption, and Audit
//! Logging (architecture §18).

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod audit;
pub mod auth;
pub mod authz;
pub mod encryption;

pub use audit::{AuditError, AuditLogger, AuditOutcome, AuditRecord, AUDIT_SCHEMA_VERSION};
pub use auth::{generate_random_api_key, ApiKeyAuthenticator, AuthError, Principal};
pub use authz::{authorize, AuthzError, Permission, Role};
pub use encryption::{decrypt, encrypt, DataEncryptionKey, EncryptionError};
