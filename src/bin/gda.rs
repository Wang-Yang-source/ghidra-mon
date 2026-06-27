use clap::Parser;
use ghidrai::cli::Cli;
use ghidrai::handlers;

#[tokio::main]
async fn main() -> Result<(), ghidrai::error::RevisorError> {
    let cli = Cli::parse();
    handlers::handle_command(cli.command).await
}
