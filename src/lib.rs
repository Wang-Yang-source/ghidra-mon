//! # Ghidrai — Terminal Reverse Engineering Toolkit Aggregator
//!
//! **Ghidrai** is an open-source terminal UI toolkit that unifies multiple
//! reverse-engineering backends (Ghidra, Rizin, binwalk, checksec, GDB,
//! native CWE triage, entropy triage, memory triage, ROP gadget finders) behind a single TUI workspace. It provides:
//!
//! - A **terminal UI** for interactive binary analysis
//! - A **CLI** for scripting and automation
//! - An **MCP server** for AI-assisted reverse engineering
//! - A **daemon mode** with a Unix socket for tool delegation
//! - Pluggable **toolkit adapters** (binwalk, checksec, CWE triage, entropy, GDB/GDB-MI, memory triage, rizin, ROP)
//!
//! ## Quick Start
//!
//! ```rust
//! use ghidrai::bridge::BridgeClient;
//!
//! # async fn example() -> ghidrai::error::Result<()> {
//! let client = BridgeClient::new(12345);
//! let functions = client.list_functions().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! The crate is organized into these top-level modules:
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`bridge`] | TCP client for the Ghidra Java bridge |
//! | [`cli`] | Command-line argument parsing and dispatch |
//! | [`tui`] | Terminal UI workspace (ratatui + crossterm) |
//! | [`daemon`] | Background daemon with Unix socket IPC |
//! | [`mcp`] | Model Context Protocol server (JSON-RPC 2.0) |
//! | [`toolkit`] | Native Rust RE tools and external adapters (binwalk, checksec, CWE triage, entropy, GDB/GDB-MI, memory triage, rizin, ROP) |
//! | [`adapter`] | Backend abstraction layer (schema, process runner) |
//! | [`types`] | Shared data types (CFG, call graph, symbols, etc.) |
//! | [`setup`] | Ghidra installation and auto-setup |
//! | [`handlers`] | Command dispatch glue between CLI and backends |
//! | [`error`] | Unified error types and `Result` alias |

pub mod adapter;
pub mod bridge;
pub mod cli;
pub mod daemon;
pub mod error;
pub mod handlers;
pub mod mcp;
pub mod setup;
pub mod toolkit;
pub mod tui;
pub mod types;
