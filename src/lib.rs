// Ghidrai terminal reverse engineering toolkit aggregator.
//
// This is the library entry point for the CLI, TUI workspace, optional
// compatibility adapters, and pluggable reverse-engineering backends.
//
// Example usage:
// ```rust
// use revisor::bridge::BridgeClient;
//
// let client = BridgeClient::new(12345);
// let functions = client.list_functions().await?;
// ```

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
