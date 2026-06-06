// revisor: Revisoritor & AI MCP Unified Binary
//
// This is the library entry point, allowing other Rust projects to use
// revisor as a dependency for programmatic Ghidra access.
//
// Example usage:
// ```rust
// use revisor::bridge::BridgeClient;
//
// let client = BridgeClient::new(12345);
// let functions = client.list_functions().await?;
// ```

pub mod bridge;
pub mod daemon;
pub mod error;
pub mod mcp;
pub mod setup;
pub mod tui;
pub mod types;
pub mod cli;
pub mod handlers;
