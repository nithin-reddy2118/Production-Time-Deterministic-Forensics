//! `ptdf-pal` — the Platform Abstraction Layer trait boundary (architecture
//! §13). This crate defines *contracts only*: `PlatformInterceptor` for
//! recording and `ReplayDriver` for replay. It contains zero
//! platform-specific code — no `#[cfg(target_os = ...)]`, no FFI. Real
//! adapters (Linux/eBPF+ptrace, Windows/ETW+minifilter, macOS/EndpointSecurity)
//! live in their own downstream crates (`ptdf-pal-linux`, `ptdf-pal-windows`,
//! `ptdf-pal-macos` — introduced starting Module 4) and implement these
//! traits.
//!
//! Why a separate crate from `ptdf-recorder-core`: the core engine, the
//! replay engine, and every platform adapter all need this boundary without
//! needing each other — splitting it out is what makes "core only depends
//! on the trait, never on OS-specific types" actually enforceable by the
//! build graph rather than just a convention.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod interceptor;
pub mod replay;

pub use interceptor::{AttachTarget, InterceptorCapabilities, InterceptorError, PlatformInterceptor};
pub use replay::{Divergence, ReplayDriver, ReplayError, StepOutcome};
