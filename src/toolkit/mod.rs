//! Native Rust reverse-engineering toolkit adapters.
//!
//! These adapters run entirely in-process (no external tool dependency)
//! and expose their results as structured `ToolEvent`s.
//!
//! | Module | Engine | Purpose |
//! |--------|--------|---------|
//! | [`binwalk`] | Built-in `binwalk` crate | Firmware signature scanning |
//! | [`checksec`] | `goblin` | ELF security hardening checks (PIE, NX, RELRO, canary) |
//! | [`cwe`] | Native Rust triage | CWE-style findings from imports, hardening, strings |
//! | [`disasm`] | `iced-x86` + `goblin` | Native x86/x86-64 disassembly |
//! | [`entropy`] | Native Rust triage | Shannon entropy and packer/compression hints |
//! | [`gdb`] | External `gdb` batch / MI | Debugger metadata, symbols, and GDB/MI protocol lane |
//! | [`lief`] | `goblin` | LIEF-style object metadata, sections, imports, exports |
//! | [`rizin`] | External `rizin` binary | JSON-based static analysis |
//! | [`rop`] | `iced-x86` | ROP gadget discovery |
//! | [`strings`] | Native Rust scanner | ASCII/UTF-8 string extraction |
//! | [`volatility`] | Native Rust triage | Memory/blob markers and IOC scanning |

use crate::adapter::schema::{AdapterCapability, OutputFormat};

#[cfg(feature = "binwalk")]
pub mod binwalk;
pub mod checksec;
pub mod cwe;
pub mod disasm;
pub mod entropy;
pub mod gdb;
pub mod lief;
pub mod rizin;
pub mod rop;
pub mod strings;
pub mod volatility;

/// Build a read-only [`AdapterCapability`] for a native Rust engine.
pub fn native_rust_capability(name: &str) -> AdapterCapability {
    AdapterCapability {
        name: name.to_string(),
        formats: vec![OutputFormat::NativeRust],
        read_only: true,
        parser_version: Some("native-rust-v1".to_string()),
    }
}
