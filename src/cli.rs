use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Ghidrai terminal reverse engineering TUI toolkit aggregator",
    long_about = "Ghidrai is an open-source, terminal-first reverse engineering TUI toolkit aggregator.\n\n\
        Design philosophy:\n\
        1. The product center is the unified terminal workspace, not a single automation backend.\n\
        2. Ghidra, Rizin, Binwalk, ROPgadget, GDB, Frida, Volatility and similar tools are pluggable engines.\n\
        3. Structured output is preferred; text parsing is isolated inside versioned adapters.\n\n\
        Examples:\n  \
        gda tui\n  \
        gda toolkit binwalk ./firmware.bin\n  \
        gda toolkit checksec ./tests/crackme\n  \
        gda toolkit cwe ./tests/crackme\n  \
        gda toolkit lief ./tests/crackme\n  \
        gda toolkit strings ./tests/crackme\n  \
        gda toolkit disasm ./tests/crackme\n  \
        gda toolkit entropy ./tests/crackme\n  \
        gda toolkit gdb ./tests/crackme\n  \
        gda toolkit gdb-mi ./tests/crackme\n  \
        gda toolkit rop ./tests/crackme\n  \
        gda toolkit volatility ./tests/crackme\n  \
        gda catalog\n  \
        gda toolkit all ./tests/crackme --format json\n  \
        gda analyze /bin/ls -p /tmp/proj -n test_ls\n  \
        gda bridge -p /tmp/proj -n test_ls\n  \
        gda query decompile main"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run the optional MCP compatibility server over stdio
    #[command(
        long_about = "Starts the optional JSON-RPC 2.0 MCP compatibility server over stdin/stdout. This is not the product center; it is one adapter over the same reverse engineering backend model.\n\nUse `--backend external` with `GHIDRA_MCP_COMMAND` (and optional `GHIDRA_MCP_ARGS`) to proxy the full `bridge_mcp_ghidra.py` toolset."
    )]
    Mcp {
        /// MCP backend implementation: `legacy` (default) or `external` (`bridge_mcp_ghidra.py`).
        ///
        /// If omitted, `GHIDRA_MCP_BACKEND` is used; when unset, `legacy` is the fallback.
        #[arg(
            short = 'b',
            long = "backend",
            value_name = "legacy|external",
            value_parser = ["legacy", "external"],
            help = "Choose MCP backend implementation"
        )]
        backend: Option<String>,
    },
    /// Set up the optional Ghidra backend
    #[command(
        long_about = "Downloads and configures Ghidra as one optional static analysis/decompiler backend. Ghidrai should continue to support other CLI engines such as Rizin and Binwalk."
    )]
    Setup,
    /// Start the terminal reverse engineering workspace (default)
    #[command(
        long_about = "Launches the Ratatui workspace for the tool collection. The TUI should render unified events from multiple adapters and keep raw tool output available for inspection."
    )]
    Tui,
    /// Start the optional Ghidra bridge backend on a project
    #[command(
        long_about = "Starts a headless Ghidra instance that opens a local TCP socket. This is one backend engine for decompilation, symbols, xrefs and CFG data; it is not the whole product architecture."
    )]
    Bridge {
        /// Path to the local directory where the Ghidra project will be stored
        #[arg(
            short,
            long,
            default_value = "/tmp/ghidra_proj",
            help = "Project storage directory"
        )]
        project_path: String,
        /// Name of the Ghidra project (e.g. 'my_malware')
        #[arg(
            short = 'n',
            long,
            default_value = "test",
            help = "Project internal name"
        )]
        project_name: String,
    },
    /// Import a binary into a Ghidra backend project
    #[command(
        long_about = "Uses the Ghidra Headless Analyzer to import a binary into a backend project and run auto-analysis. This command exists for the Ghidra adapter path; other adapters should not depend on it."
    )]
    Analyze {
        /// Absolute or relative path to the binary to analyze (e.g., /usr/bin/ls)
        #[arg(help = "Path to the binary file to analyze")]
        binary_path: String,
        /// Path to the local directory where the Ghidra project will be stored
        #[arg(
            short,
            long,
            default_value = "/tmp/ghidra_proj",
            help = "Project storage directory"
        )]
        project_path: String,
        /// Name of the Ghidra project to create or append to
        #[arg(
            short = 'n',
            long,
            default_value = "test",
            help = "Project internal name"
        )]
        project_name: String,
    },
    /// Run a standalone Ghidra backend script on an existing project
    #[command(
        long_about = "Spawns the Ghidra Headless Analyzer to run a single Java/Python script. This is a backend maintenance command, not the primary Ghidrai workflow."
    )]
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
    /// Query the running Ghidra backend directly from CLI
    #[command(
        long_about = "Sends a JSON command to the running Ghidra bridge backend and prints the result. This remains useful for debugging the Ghidra adapter while the broader toolkit model is built.\n\nExamples:\n  gda query decompile main\n  gda query search_strings password\n  gda query list_functions"
    )]
    Query {
        /// Bridge command to execute (e.g., 'decompile', 'list_functions')
        #[arg(help = "The query action (ping, decompile, callers, search_strings, etc.)")]
        command: String,
        /// Optional main argument (e.g., the function name 'main' or address '0x401000')
        #[arg(help = "Main argument like function name or address")]
        arg: Option<String>,
        /// Additional key=value arguments (e.g. new_name=foo comment="hello")
        #[arg(
            trailing_var_arg = true,
            help = "Additional args formatted as key=value"
        )]
        extra_args: Vec<String>,
        /// Override the bridge TCP port (auto-discovered from ~/.ghidrai/bridge.pid if not specified)
        #[arg(short, long, help = "Bridge TCP port (if auto-discovery fails)")]
        port: Option<u16>,
        /// Pass raw JSON args string instead of key=value (e.g. --json '{"function":"main"}')
        #[arg(short, long, help = "Raw JSON payload for complex arguments")]
        json: Option<String>,
        /// Output format: 'json' for raw API response, 'events' for ToolEvent JSON lines, or 'pretty'
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (json | events | pretty)"
        )]
        format: String,
    },
    /// Run CLI/TUI integrated reverse engineering toolkit backends
    #[command(subcommand)]
    Toolkit(ToolkitCommands),
    /// Show the unified reverse-engineering tool catalog
    Catalog {
        /// Output format: pretty text or json
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
}

#[derive(Subcommand)]
pub enum ToolkitCommands {
    /// Scan firmware signatures and extracted structures
    #[cfg(feature = "binwalk")]
    Binwalk {
        /// Binary to scan
        #[arg(help = "Path to the binary file")]
        file_path: String,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
    /// Inspect ELF hardening features
    Checksec {
        /// Binary to inspect
        #[arg(help = "Path to the ELF/PE/Mach-O binary file")]
        file_path: String,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
    /// Run native CWE-style risk triage
    Cwe {
        /// Binary to inspect
        #[arg(help = "Path to the binary file")]
        file_path: String,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
    /// Inspect object metadata, sections, imports, exports, and symbols
    Lief {
        /// Binary/object to inspect
        #[arg(help = "Path to the ELF/PE/Mach-O file")]
        file_path: String,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
    /// Extract printable strings with the native Rust scanner
    Strings {
        /// Binary to scan
        #[arg(help = "Path to the binary file")]
        file_path: String,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
    /// Disassemble the executable text section with the native Rust disassembler
    Disasm {
        /// Binary to disassemble
        #[arg(help = "Path to the ELF/PE binary file")]
        file_path: String,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
    /// Measure entropy for packer/compression triage
    Entropy {
        /// Binary/blob to inspect
        #[arg(help = "Path to the binary or blob file")]
        file_path: String,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
    /// Query GDB batch metadata without launching an interactive debugger
    Gdb {
        /// Binary to inspect with GDB
        #[arg(help = "Path to the binary file")]
        file_path: String,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
    /// Query GDB/MI metadata through the machine interface
    GdbMi {
        /// Binary to inspect with GDB/MI
        #[arg(help = "Path to the binary file")]
        file_path: String,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
    /// Find ROP gadgets
    Rop {
        /// Binary to scan
        #[arg(help = "Path to the binary file")]
        file_path: String,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
    /// Run native Volatility-style memory/blob triage
    Volatility {
        /// Memory dump or binary blob to triage
        #[arg(help = "Path to the memory dump or blob")]
        file_path: String,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
    /// Run the currently integrated native toolkit passes in one shot
    All {
        /// Binary to inspect
        #[arg(help = "Path to the binary file")]
        file_path: String,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
    /// Run Rizin JSON static analysis views
    Rizin {
        /// Binary to inspect
        #[arg(help = "Path to the binary file")]
        file_path: String,
        /// Rizin view: info, functions, strings, sections, imports, disasm, xrefs
        #[arg(
            short,
            long,
            default_value = "functions",
            help = "Rizin action (info | functions | strings | sections | imports | disasm | xrefs)"
        )]
        action: String,
        /// Symbol or address for disasm/xrefs
        #[arg(short, long, help = "Symbol or address for action-specific queries")]
        query: Option<String>,
        /// Output format: pretty text or json event stream
        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format (pretty | json)"
        )]
        format: String,
    },
}
