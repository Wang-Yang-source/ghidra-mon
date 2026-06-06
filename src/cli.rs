use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about = "Ghidra Monitor & AI MCP Unified Binary")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run the AI MCP Server over Stdio
    Mcp,
    /// Automatically download and set up Ghidra
    Setup,
    /// Start the daemon and TUI (Default if no command provided)
    Tui,
    /// Start a persistent Java Bridge Server on a project
    Bridge {
        /// Project path
        #[arg(short, long, default_value = "/tmp/ghidra_proj")]
        project_path: String,
        /// Project name
        #[arg(short = 'n', long, default_value = "test")]
        project_name: String,
    },
    /// Import a binary into a new Ghidra project and analyze it
    Analyze {
        /// Path to the binary to analyze
        binary_path: String,
        /// Project path (defaults to /tmp/ghidra_proj)
        #[arg(short, long, default_value = "/tmp/ghidra_proj")]
        project_path: String,
        /// Project name (defaults to test)
        #[arg(short = 'n', long, default_value = "test")]
        project_name: String,
    },
    /// Run a script on an existing Ghidra project
    RunScript {
        /// Name of the script to run
        script_name: String,
        /// Project path (defaults to /tmp/ghidra_proj)
        #[arg(short, long, default_value = "/tmp/ghidra_proj")]
        project_path: String,
        /// Project name (defaults to test)
        #[arg(short = 'n', long, default_value = "test")]
        project_name: String,
    },
    /// Query the running Bridge directly from CLI
    Query {
        /// Bridge command to execute
        command: String,
        /// Optional argument (function name, address, etc.)
        arg: Option<String>,
        /// Additional key=value arguments (e.g. new_name=foo comment="hello world")
        #[arg(trailing_var_arg = true)]
        extra_args: Vec<String>,
        /// Bridge TCP port (auto-discovered if not specified)
        #[arg(short, long)]
        port: Option<u16>,
        /// Pass raw JSON args string (e.g. --json '{"function":"main","new_name":"entry"}')
        #[arg(short, long)]
        json: Option<String>,
        /// Output format: json (default) or pretty
        #[arg(short, long, default_value = "pretty")]
        format: String,
    },
}
