# Ghidra Mon 👁️

A **blazing fast, unified Rust CLI and AI MCP Server** for automating Ghidra reverse engineering workflows. Single binary, zero-config, 10ms query response time.

> Designed for seamless AI agent integration (Cursor, Claude Desktop, Windsurf) and power-user CLI workflows.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔧 **Zero-Config Setup** | `ghidra-mon setup` downloads and installs Ghidra automatically |
| ⚡ **10ms Queries** | Persistent JVM Bridge keeps Ghidra in memory — no startup overhead |
| 🤖 **22 MCP Tools** | Full AI integration via Model Context Protocol (JSON-RPC 2.0) |
| 🔍 **CLI Query** | `ghidra-mon query` for direct command-line reverse engineering |
| 📦 **Single Binary** | Java Bridge embedded in the Rust executable, no extra scripts |
| 🖥️ **Cyberpunk TUI** | Ratatui-powered dashboard for monitoring headless tasks |
| 🔌 **Auto Port Discovery** | Bridge port saved to `~/.ghidra-mon/bridge.pid`, MCP auto-connects |
| 🦀 **Library API** | `use ghidra_mon::bridge::BridgeClient` for Rust integration |

## 🏗️ Architecture

```text
┌─────────────────────────┐         ┌──────────────────────────────────────┐
│  AI Agent (Cursor/MCP)  │──stdio─▶│  ghidra-mon mcp  (JSON-RPC 2.0)     │
│  Human CLI (query)      │──TCP───▶│  ghidra-mon query (direct CLI)       │
│  Rust App (BridgeClient)│──TCP───▶│  ghidra-mon bridge (TCP server)      │
└─────────────────────────┘         └──────────────────────────────────────┘
                                                       │
                                                 Local TCP Socket
                                                       ▼
                                    ┌──────────────────────────────────────┐
                                    │  GhidraMonBridge.java (917 lines)    │
                                    │  25+ commands, transaction-safe      │
                                    │  Running persistently inside JVM     │
                                    └──────────────────────────────────────┘
```

---

## 🚀 Installation

### From Source (recommended)
```bash
git clone https://github.com/Wang-Yang-source/ghidra-mon.git
cd ghidra-mon
cargo install --path .
```

### From Crates.io
```bash
cargo install ghidra-mon
```

### Prerequisites
- **Rust** 1.85+ (edition 2024)
- **Java** 17+ (JDK 21 recommended — Ghidra 11.2 requirement)

---

## 📖 Quick Start Tutorial

### Step 1: Install Ghidra (one-time)

```bash
ghidra-mon setup
```

This downloads Ghidra 11.2 to `~/.ghidra-mon/ghidra/`. You only need to run this once.

> Already have Ghidra? Set `GHIDRA_HEADLESS=/path/to/analyzeHeadless` instead.

### Step 2: Import and Analyze a Binary

```bash
ghidra-mon analyze /path/to/binary --project-path ./my_project -n my_binary
```

Example with a real binary:
```bash
# Analyze the system's ls command
ghidra-mon analyze /usr/bin/ls --project-path /tmp/ghidra_proj -n ls_analysis
```

Output:
```
🚀 Running Ghidra Headless Analysis on /usr/bin/ls...
INFO  Using Language/Compiler: x86:LE:64:default:gcc
INFO  REPORT: Analysis succeeded for file: /usr/bin/ls
✅ Analysis complete!
```

### Step 3: Start the Bridge Server

```bash
ghidra-mon bridge --project-path /tmp/ghidra_proj -n ls_analysis
```

Output:
```
🚀 Starting Ghidra Bridge Server...
🔌 Bridge is initializing...
✅ Bridge is now ONLINE and listening on TCP port 36881
   Port auto-saved to ~/.ghidra-mon/bridge.pid for MCP discovery
```

> The bridge runs persistently. All subsequent queries are **near-instant** (no JVM startup).

### Step 4: Query from CLI

The bridge port is auto-discovered — no need to specify `--port`:

```bash
# List all functions
ghidra-mon query list_functions

# Decompile a function
ghidra-mon query decompile main

# Get callers/callees
ghidra-mon query callers validate_password
ghidra-mon query callees main

# Search strings
ghidra-mon query search_strings password

# Get disassembly
ghidra-mon query instructions_for_function main

# Cross-references
ghidra-mon query references_to 0x00401000
```

### Step 5: Connect AI Agent via MCP

Add to your MCP config (Cursor, Claude Desktop, etc.):
```json
{
  "mcpServers": {
    "ghidra": {
      "command": "ghidra-mon",
      "args": ["mcp"]
    }
  }
}
```

That's it! The AI can now call any of the 22 Ghidra tools directly.

---

## 💻 CLI Reference

### `ghidra-mon setup`

Download and install Ghidra automatically.

```bash
ghidra-mon setup
```
- Installs to `~/.ghidra-mon/ghidra/`
- Sets execution permissions automatically
- Only needs to run once

### `ghidra-mon analyze`

Import a binary into a Ghidra project and run auto-analysis.

```bash
ghidra-mon analyze <BINARY_PATH> [OPTIONS]

Options:
  -p, --project-path <PATH>  Project directory [default: /tmp/ghidra_proj]
  -n, --project-name <NAME>  Project name       [default: test]
```

Examples:
```bash
# Basic analysis
ghidra-mon analyze ./malware.exe

# Custom project location
ghidra-mon analyze ./firmware.bin -p ~/ghidra_projects -n firmware_v2

# Analyze a CTF challenge
ghidra-mon analyze ./crackme -p /tmp/ctf -n crackme
```

### `ghidra-mon bridge`

Start the persistent Java Bridge TCP server on an analyzed project.

```bash
ghidra-mon bridge [OPTIONS]

Options:
  -p, --project-path <PATH>  Project directory [default: /tmp/ghidra_proj]
  -n, --project-name <NAME>  Project name       [default: test]
```

Example:
```bash
ghidra-mon bridge -p /tmp/ctf -n crackme
# Bridge starts on a random TCP port, auto-saved to ~/.ghidra-mon/bridge.pid
```

### `ghidra-mon query`

Query the running Bridge directly from the command line.

```bash
ghidra-mon query <COMMAND> [ARG] [EXTRA_ARGS...] [OPTIONS]

Options:
  -p, --port <PORT>      Bridge port (auto-discovered if omitted)
  -j, --json <JSON>      Raw JSON args (for complex commands)
  -f, --format <FORMAT>  Output: pretty (default) or json
```

#### Read Commands

```bash
# Program metadata
ghidra-mon query ping
ghidra-mon query program_info
ghidra-mon query list_functions
ghidra-mon query memory_blocks
ghidra-mon query symbols
ghidra-mon query list_imports
ghidra-mon query list_exports
ghidra-mon query list_data_types

# Decompilation (by function name)
ghidra-mon query decompile main
ghidra-mon query decompile validate_password

# Function lookup (by address)
ghidra-mon query function_at 0x00401000
ghidra-mon query function_containing 0x00401050

# Call graph
ghidra-mon query callers some_function
ghidra-mon query callees main
ghidra-mon query call_graph

# Disassembly
ghidra-mon query instructions_for_function main

# Cross-references
ghidra-mon query references_to 0x00401000
ghidra-mon query references_from 0x00401000

# Strings and symbols
ghidra-mon query search_strings "password"
ghidra-mon query find_symbols main

# Data
ghidra-mon query data_at 0x00402000

# Control flow graph
ghidra-mon query control_flow_graph main
```

#### Write Commands (use `--json` for multiple args)

```bash
# Rename a function
ghidra-mon query rename_function --json '{"function":"FUN_00401000","new_name":"decrypt_payload"}'

# Set inline comment at an address
ghidra-mon query set_comment --json '{"address":"0x00401000","comment":"XOR decrypt loop"}'

# Set plate comment on a function
ghidra-mon query set_plate_comment --json '{"function":"main","comment":"Entry point"}'
```

#### Output Formats

```bash
# Pretty-printed JSON (default)
ghidra-mon query decompile main

# Compact JSON (for scripting/piping)
ghidra-mon query decompile main -f json

# Pipe to jq
ghidra-mon query list_functions -f json | jq '.functions[].name'
```

### `ghidra-mon mcp`

Run the MCP (Model Context Protocol) server over stdio.

```bash
ghidra-mon mcp
```

This is normally called by the AI agent, not by the user directly. It reads JSON-RPC 2.0 requests from stdin and writes responses to stdout.

### `ghidra-mon run-script`

Run a Ghidra script on an existing project.

```bash
ghidra-mon run-script <SCRIPT_NAME> [OPTIONS]

Options:
  -p, --project-path <PATH>  Project directory [default: /tmp/ghidra_proj]
  -n, --project-name <NAME>  Project name       [default: test]
```

Example:
```bash
ghidra-mon run-script MyCustomScript.java -p /tmp/ctf -n crackme
```

### `ghidra-mon tui`

Launch the Cyberpunk TUI dashboard (also the default when no command is given).

```bash
ghidra-mon       # same as ghidra-mon tui
ghidra-mon tui
```

Press `q` to quit the TUI.

---

## 🤖 MCP Tools Reference (22 Tools)

All tools auto-discover the bridge port — the `port` parameter is optional.

### 📋 Query Tools (15)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `ghidra_program_info` | — | Program metadata (name, language, compiler, function count) |
| `ghidra_list_functions` | — | All functions with names, addresses, signatures, sizes |
| `ghidra_decompile` | `function` | Decompile to C pseudocode |
| `ghidra_function_at` | `address` | Find function at exact address |
| `ghidra_callers` | `function` | All callers of a function |
| `ghidra_callees` | `function` | All functions called by a function |
| `ghidra_instructions` | `function` | Disassembly (address, mnemonic, operands, bytes) |
| `ghidra_memory_blocks` | — | Memory sections with R/W/X permissions |
| `ghidra_symbols` | `query?`, `symbol_type?` | List/search symbols |
| `ghidra_references_to` | `address` | Cross-references TO an address |
| `ghidra_references_from` | `address` | Cross-references FROM an address |
| `ghidra_search_strings` | `query?` | Search strings in binary |
| `ghidra_imports` | — | Imported functions and libraries |
| `ghidra_exports` | — | Exported entry points |
| `ghidra_data_types` | — | All data types |

### 📊 Graph Tools (2)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `ghidra_call_graph` | `depth?` | Full program call graph (nodes + edges) |
| `ghidra_control_flow_graph` | `function` | CFG with basic blocks for a function |

### ✏️ Write Tools (2)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `ghidra_rename_function` | `function`, `new_name` | Rename a function (transaction-safe) |
| `ghidra_set_comment` | `address`, `comment` | Set inline comment at address |

### ⚙️ Headless Tools (3)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `ghidra_import_and_analyze` | `binary_path`, `project_path`, `project_name` | Import + auto-analyze |
| `ghidra_run_script` | `script_name`, `project_path`, `project_name` | Run Ghidra script |
| `ghidra_ask_bridge` | `command`, `args?` | Send raw JSON to bridge (advanced) |

---

## 🦀 Rust Library API

`ghidra-mon` can be used as a library in your own Rust projects:

```toml
[dependencies]
ghidra-mon = "0.3"
```

```rust
use ghidra_mon::bridge::BridgeClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Auto-discover bridge port, or specify manually
    let port = ghidra_mon::bridge::read_bridge_port()
        .expect("No running bridge found");
    let client = BridgeClient::new(port);

    // Query functions
    let info = client.program_info().await?;
    println!("Program: {:?}", info.name);

    let functions = client.list_functions().await?;
    for f in &functions {
        println!("{} @ {}", f.name, f.address);
    }

    // Decompile
    let result = client.decompile("main").await?;
    println!("{}", result.c_code.unwrap_or_default());

    // Call graph analysis
    let callers = client.callers("main").await?;
    let callees = client.callees("main").await?;

    // Cross-references
    let refs = client.references_to("0x00401000").await?;

    // Write operations
    client.rename_function("FUN_00401000", "decrypt_payload").await?;
    client.set_comment("0x00401000", "XOR decrypt loop").await?;

    Ok(())
}
```

Available methods on `BridgeClient`:

| Method | Return Type | Description |
|--------|------------|-------------|
| `ping()` | `()` | Verify connectivity |
| `program_info()` | `ProgramInfo` | Program metadata |
| `list_functions()` | `Vec<FunctionInfo>` | All functions |
| `decompile(name)` | `DecompileResult` | C pseudocode |
| `function_at(addr)` | `FunctionInfo` | Function at address |
| `function_containing(addr)` | `FunctionInfo` | Function containing address |
| `callers(name)` | `Vec<FunctionInfo>` | Callers |
| `callees(name)` | `Vec<FunctionInfo>` | Callees |
| `instructions_for_function(name)` | `Vec<InstructionInfo>` | Disassembly |
| `memory_blocks()` | `Vec<MemoryBlockInfo>` | Memory sections |
| `symbols(type?)` | `Vec<SymbolInfo>` | Symbols |
| `find_symbols(query)` | `Vec<SymbolInfo>` | Search symbols |
| `references_to(addr)` | `Vec<ReferenceInfo>` | Xrefs TO |
| `references_from(addr)` | `Vec<ReferenceInfo>` | Xrefs FROM |
| `search_strings(query)` | `Vec<StringResult>` | String search |
| `call_graph(depth?)` | `CallGraph` | Call graph |
| `control_flow_graph(name)` | `ControlFlowGraph` | CFG |
| `list_imports()` | `Vec<ImportInfo>` | Imports |
| `list_exports()` | `Vec<ExportInfo>` | Exports |
| `list_data_types()` | `Vec<DataTypeInfo>` | Data types |
| `data_at(addr)` | `DataInfo` | Data at address |
| `rename_function(old, new)` | `()` | Rename function |
| `set_comment(addr, text)` | `()` | Set EOL comment |
| `set_plate_comment(func, text)` | `()` | Set plate comment |

---

## 🔍 Reverse Engineering Walkthrough

Here's a complete example using the included [crackme](tests/crackme.c) test binary:

### 1. Analyze the binary
```bash
ghidra-mon analyze tests/crackme -p /tmp/ctf -n crackme
```

### 2. Start the bridge
```bash
ghidra-mon bridge -p /tmp/ctf -n crackme
# ✅ Bridge is now ONLINE on port 36881
```

### 3. Discover the password
```bash
$ ghidra-mon query decompile validate_password

# Output reveals:
# if (((sVar1 == 8) && (*param_1 == 'R')) && (param_1[1] == 'E'))
#     && (param_1[2] == 'V' && (param_1[3] == '3'))
#     && (param_1[4] == 'R' && (param_1[5] == 'S' && (param_1[6] == 'E')))
#     bVar2 = param_1[7] == '!';
#
# → Password: REV3RSE!
```

### 4. Find the XOR key
```bash
$ ghidra-mon query decompile xor_decrypt

# "GhidraMon2024"[(int)lVar1 % 0xd] ^ *(byte *)(param_1 + lVar1)
# → XOR Key: GhidraMon2024
```

### 5. Discover hidden functions
```bash
$ ghidra-mon query callees main

# → validate_password, print_banner, check_license, secret_function
# secret_function is only called when check_license passes!
```

### 6. Annotate your findings
```bash
ghidra-mon query rename_function --json '{"function":"secret_function","new_name":"decrypt_secret_message"}'
ghidra-mon query set_comment --json '{"address":"0x00400591","comment":"Password: REV3RSE!"}'
```

---

## 🗂️ Project Structure

```
ghidra-mon/
├── Cargo.toml                    # Dependencies & metadata
├── README.md                     # This file
├── src/
│   ├── main.rs                   # CLI entry point (7 subcommands)
│   ├── lib.rs                    # Library exports
│   ├── bridge.rs                 # BridgeClient + Bridge server + port discovery
│   ├── mcp.rs                    # MCP server (22 tools, JSON-RPC 2.0)
│   ├── tui.rs                    # Ratatui TUI dashboard
│   ├── daemon.rs                 # Background task daemon
│   ├── setup.rs                  # Ghidra download & install
│   ├── types.rs                  # Shared types (24 structs)
│   ├── error.rs                  # Typed errors (thiserror)
│   └── GhidraMonBridge.java      # Embedded Java bridge (917 lines)
└── tests/
    ├── crackme.c                 # Reverse engineering test target
    ├── crackme                   # Compiled test binary
    └── integration_test.sh       # Automated integration tests
```

---

## 🙏 Acknowledgments

This project was inspired by and references the work of:

- **[ghidra-cli](https://github.com/akiselev/ghidra-cli)** by [@akiselev](https://github.com/akiselev) — A Rust CLI for headless Ghidra automation. Its architectural approach and CLI design patterns provided valuable reference during the development of `ghidra-mon`. 🦀
- **[ghidra-rs](https://crates.io/crates/ghidra)** by [@ooojustin](https://github.com/ooojustin) — Typed Rust bindings for an embedded Ghidra JVM via JNI. Its elegant API design with Rust-native lifetime safety inspired the typed `BridgeClient` API.

## 📄 License

MIT OR Apache-2.0.
