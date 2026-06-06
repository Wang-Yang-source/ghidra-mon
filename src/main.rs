// revisor: Ghidra Monitor & AI MCP Unified Binary
// Slim CLI entry point – all logic lives in the library modules.

use clap::Parser;
use revisor::cli::Cli;
use revisor::handlers;

#[tokio::main]
async fn main() -> Result<(), revisor::error::GhidraMonError> {
    let cli = Cli::parse();
    handlers::handle_command(cli.command).await
}
