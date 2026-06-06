use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "🚀 Revisor & AI MCP Unified Binary (Terminal IDE)",
    long_about = "Revisor (revisor) is an all-in-one headless reverse engineering toolkit.\n\n\
        It provides:\n\
        1. A Java Bridge to interact with Ghidra headlessly.\n\
        2. A JSON-RPC server (MCP) for AI integration.\n\
        3. A zero-config Terminal IDE for reverse engineering without the heavy Java GUI.\n\n\
        Examples:\n  \
        revisor tui\n  \
        revisor analyze /bin/ls -p /tmp/proj -n test_ls\n  \
        revisor bridge -p /tmp/proj -n test_ls\n  \
        revisor query decompile main"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// 🤖 Run the AI MCP Server over Stdio (for Claude/Cursor integration)
    #[command(long_about = "Starts the JSON-RPC 2.0 MCP server over stdin/stdout. This is primarily used by AI agents like Claude Desktop or Cursor to query the running Ghidra bridge automatically.")]
    Mcp,
    /// 📥 Automatically download and set up Ghidra
    #[command(long_about = "Downloads the latest version of Ghidra (approx 350MB) and unzips it into ~/.local/share/ghidra. It also creates a symlink so the internal headless analyzer can find it. You must have Java 17+ installed.")]
    Setup,
    /// 💻 Start the Terminal IDE dashboard (Default)
    #[command(long_about = "Launches the Cyberpunk-themed Terminal IDE. If a bridge is running, it will automatically connect and load functions, decompiled C code, X-Refs, and strings. You can also run CLI commands directly inside the TUI console.")]
    Tui,
    /// 🔌 Start a persistent Java Bridge Server on a project
    #[command(long_about = "Starts a headless Ghidra instance that opens a local TCP socket. This bridge acts as the backend for the TUI or the MCP server, executing scripts to query the Ghidra API without opening the GUI.")]
    Bridge {
        /// Path to the local directory where the Ghidra project will be stored
        #[arg(short, long, default_value = "/tmp/ghidra_proj", help = "Project storage directory")]
        project_path: String,
        /// Name of the Ghidra project (e.g. 'my_malware')
        #[arg(short = 'n', long, default_value = "test", help = "Project internal name")]
        project_name: String,
    },
    /// 🔍 Import a binary into a new Ghidra project and analyze it
    #[command(long_about = "Uses the Ghidra Headless Analyzer to import a raw binary executable (ELF, PE, Mach-O, etc.) into the specified project, runs auto-analysis on it, and saves the project. You must do this before running the bridge.")]
    Analyze {
        /// Absolute or relative path to the binary to analyze (e.g., /usr/bin/ls)
        #[arg(help = "Path to the binary file to analyze")]
        binary_path: String,
        /// Path to the local directory where the Ghidra project will be stored
        #[arg(short, long, default_value = "/tmp/ghidra_proj", help = "Project storage directory")]
        project_path: String,
        /// Name of the Ghidra project to create or append to
        #[arg(short = 'n', long, default_value = "test", help = "Project internal name")]
        project_name: String,
    },
    /// 📜 Run a standalone Ghidra script on an existing project
    #[command(long_about = "Spawns the Headless Analyzer just to run a single Java/Python Ghidra script and then exits. This does not start the persistent bridge.")]
    RunScript {
        /// Name of the script to run (e.g., 'FindInstructions.java')
        #[arg(help = "Name of the script (must be in the search path)")]
        script_name: String,
        /// Path to the local directory where the Ghidra project is stored
        #[arg(short, long, default_value = "/tmp/ghidra_proj")]
        project_path: String,
        /// Name of the Ghidra project
        #[arg(short = 'n', long, default_value = "test")]
        project_name: String,
    },
    /// ❓ Query the running Bridge directly from CLI
    #[command(long_about = "Sends an arbitrary JSON command to the running Ghidra bridge via TCP and prints the result. Useful for scripting or debugging.\n\nExamples:\n  revisor query decompile main\n  revisor query search_strings password\n  revisor query list_functions")]
    Query {
        /// Bridge command to execute (e.g., 'decompile', 'list_functions')
        #[arg(help = "The query action (ping, decompile, callers, search_strings, etc.)")]
        command: String,
        /// Optional main argument (e.g., the function name 'main' or address '0x401000')
        #[arg(help = "Main argument like function name or address")]
        arg: Option<String>,
        /// Additional key=value arguments (e.g. new_name=foo comment="hello")
        #[arg(trailing_var_arg = true, help = "Additional args formatted as key=value")]
        extra_args: Vec<String>,
        /// Override the bridge TCP port (auto-discovered from /tmp/ghidra-mon-bridge.port if not specified)
        #[arg(short, long, help = "Bridge TCP port (if auto-discovery fails)")]
        port: Option<u16>,
        /// Pass raw JSON args string instead of key=value (e.g. --json '{"function":"main"}')
        #[arg(short, long, help = "Raw JSON payload for complex arguments")]
        json: Option<String>,
        /// Output format: 'json' for raw API response or 'pretty' for human-readable output
        #[arg(short, long, default_value = "pretty", help = "Output format (json | pretty)")]
        format: String,
    },
}
