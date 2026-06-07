//! Backend abstraction layer for pluggable reverse-engineering tools.
//!
//! Every analysis engine — Ghidra, Rizin, binwalk, checksec, or a ROP
//! gadget finder — implements the [`ToolAdapter`] trait. The adapter
//! layer normalises tool output into structured [`schema::ToolEvent`]s
//! that the TUI and MCP server can consume uniformly.
//!
//! ## Submodules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`schema`] | Shared data types: events, commands, capabilities |
//! | [`process`] | External tool process runner with timeout/cancel support |
//! | [`ghidra`] | Ghidra bridge adapter (Java ↔ Rust TCP bridge) |

pub mod ghidra;
pub mod process;
pub mod schema;

use crate::error::Result;
use schema::{AdapterCapability, ToolCommand, ToolEvent};

/// Trait that every reverse-engineering backend must implement.
///
/// Implementors provide a human-readable [`name`](Self::name), a
/// [`parser_version`](Self::parser_version) for output format tracking,
/// a set of [`capabilities`](Self::capabilities), and a [`run`](Self::run)
/// method that executes the tool against a target binary.
pub trait ToolAdapter {
    fn name(&self) -> &'static str;
    fn parser_version(&self) -> &'static str;
    fn capabilities(&self) -> Vec<AdapterCapability>;
    fn command(&self, _target: &str) -> Option<ToolCommand> {
        None
    }
    fn run(&self, target: &str) -> Result<Vec<ToolEvent>>;
}
