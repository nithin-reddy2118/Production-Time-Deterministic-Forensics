//! `ptdf-pal-linux` — Linux `PlatformInterceptor` implementation
//! (architecture §13, Linux Adapter). See `interceptor.rs` for the
//! `ptrace`-based v1 scope and its documented limitations, and `raw.rs`
//! for the unsafe FFI boundary (kept isolated to that one module).

#![deny(missing_debug_implementations)]

pub mod interceptor;
pub mod raw;
pub mod replay_injector;
pub mod syscall_table;

pub use interceptor::LinuxPtraceInterceptor;
pub use replay_injector::{syscall_result_to_rax, InjectorError};
