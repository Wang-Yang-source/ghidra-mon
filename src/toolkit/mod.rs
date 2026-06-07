//! Native Rust reverse-engineering toolkit adapters.
//!
//! These adapters run entirely in-process (no external tool dependency)
//! and expose their results as structured `ToolEvent`s.
//!
//! | Module | Engine | Purpose |
//! |--------|--------|---------|
//! | [`binwalk`] | Built-in `binwalk` crate | Firmware signature scanning |
//! | [`checksec`] | `goblin` | ELF security hardening checks (PIE, NX, RELRO, canary) |
//! | [`rizin`] | External `rizin` binary | JSON-based static analysis |
//! | [`rop`] | `iced-x86` | ROP gadget discovery |

use crate::adapter::schema::{AdapterCapability, OutputFormat};

#[cfg(feature = "binwalk")]
pub mod binwalk;
pub mod checksec;
pub mod rizin;
pub mod rop;

/// Build a read-only [`AdapterCapability`] for a native Rust engine.
pub fn native_rust_capability(name: &str) -> AdapterCapability {
    AdapterCapability {
        name: name.to_string(),
        formats: vec![OutputFormat::NativeRust],
        read_only: true,
        parser_version: Some("native-rust-v1".to_string()),
    }
}
