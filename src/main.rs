// ghidra-mon: Ghidra Monitor & AI MCP Unified Binary
// Slim CLI entry point – all logic lives in the library modules.

use clap::Parser;
use ghidra_mon::cli::Cli;
use ghidra_mon::handlers;

#[tokio::main]
async fn main() -> Result<(), ghidra_mon::error::GhidraMonError> {
    let cli = Cli::parse();
    handlers::handle_command(cli.command).await
}
