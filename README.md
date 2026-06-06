# Revisor 👁️

A **blazing fast, unified Rust CLI and AI MCP Server** for automating Ghidra reverse engineering workflows. Single binary, zero-config, 10ms query response time.

> Designed for seamless AI agent integration (Cursor, Claude Desktop, Windsurf) and power-user CLI workflows.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔧 **Zero-Config Setup** | `revisor setup` downloads and installs Ghidra automatically |
| ⚡ **10ms Queries** | Persistent JVM Bridge keeps Ghidra in memory — no startup overhead |
| 🤖 **22 MCP Tools** | Full AI integration via Model Context Protocol (JSON-RPC 2.0) |
| 🔍 **CLI Query** | `revisor query` for direct command-line reverse engineering |
| 📦 **Single Binary** | Java Bridge embedded in the Rust executable, no extra scripts |
| 🖥️ **Cyberpunk TUI** | Ratatui-powered dashboard for monitoring headless tasks |
| 🔌 **Auto Port Discovery** | Bridge port saved to `~/.revisor/bridge.pid`, MCP auto-connects |
| 🦀 **Library API** | `use revisor::bridge::BridgeClient` for Rust integration |

## 🏗️ Architecture

```text
┌─────────────────────────┐         ┌──────────────────────────────────────┐
│  AI Agent (Cursor/MCP)  │──stdio─▶│  revisor mcp  (JSON-RPC 2.0)     │
│  Human CLI (query)      │──TCP───▶│  revisor query (direct CLI)       │
│  Rust App (BridgeClient)│──TCP───▶│  revisor bridge (TCP server)      │
└─────────────────────────┘         └──────────────────────────────────────┘
                                                       │
                                                 Local TCP Socket
                                                       ▼
                                    ┌──────────────────────────────────────┐
                                    │  RevisorBridge.java (917 lines)    │
                                    │  25+ commands, transaction-safe      │
                                    │  Running persistently inside JVM     │
                                    └──────────────────────────────────────┘
```

---

## 🚀 Installation

### From Source (recommended)
```bash
git clone https://github.com/Wang-Yang-source/revisor.git
cd revisor
cargo install --path .
```

### From Crates.io
```bash
cargo install revisor
```

### Prerequisites
- **Rust** 1.85+ (edition 2024)
- **Java** 17+ (JDK 21 recommended — Ghidra 11.2 requirement)

---

## 📖 Quick Start Tutorial

### Step 1: Install Ghidra (one-time)

```bash
revisor setup
```

This downloads Ghidra 11.2 to `~/.revisor/ghidra/`. You only need to run this once.

> Already have Ghidra? Set `GHIDRA_HEADLESS=/path/to/analyzeHeadless` instead.

### Step 2: Import and Analyze a Binary

```bash
revisor analyze /path/to/binary --project-path ./my_project -n my_binary
```

Example with a real binary:
```bash
# Analyze the system's ls command
revisor analyze /usr/bin/ls --project-path /tmp/ghidra_proj -n ls_analysis
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
revisor bridge --project-path /tmp/ghidra_proj -n ls_analysis
```

Output:
```
🚀 Starting Ghidra Bridge Server...
🔌 Bridge is initializing...
✅ Bridge is now ONLINE and listening on TCP port 36881
   Port auto-saved to ~/.revisor/bridge.pid for MCP discovery
```

> The bridge runs persistently. All subsequent queries are **near-instant** (no JVM startup).

### Step 4: Query from CLI

The bridge port is auto-discovered — no need to specify `--port`:

```bash
# List all functions
revisor query list_functions

# Decompile a function
revisor query decompile main

# Get callers/callees
revisor query callers validate_password
revisor query callees main

# Search strings
revisor query search_strings password

# Get disassembly
revisor query instructions_for_function main

# Cross-references
revisor query references_to 0x00401000
```

### Step 5: Connect AI Agent via MCP

Add to your MCP config (Cursor, Claude Desktop, etc.):
```json
{
  "mcpServers": {
    "ghidra": {
      "command": "revisor",
      "args": ["mcp"]
    }
  }
}
```

That's it! The AI can now call any of the 22 Ghidra tools directly.

---

## 💻 CLI Reference

### `revisor setup`

Download and install Ghidra automatically.

```bash
revisor setup
```
- Installs to `~/.revisor/ghidra/`
- Sets execution permissions automatically
- Only needs to run once

### `revisor analyze`

Import a binary into a Ghidra project and run auto-analysis.

```bash
revisor analyze <BINARY_PATH> [OPTIONS]

Options:
  -p, --project-path <PATH>  Project directory [default: /tmp/ghidra_proj]
  -n, --project-name <NAME>  Project name       [default: test]
```

Examples:
```bash
# Basic analysis
revisor analyze ./malware.exe

# Custom project location
revisor analyze ./firmware.bin -p ~/ghidra_projects -n firmware_v2

# Analyze a CTF challenge
revisor analyze ./crackme -p /tmp/ctf -n crackme
```

### `revisor bridge`

Start the persistent Java Bridge TCP server on an analyzed project.

```bash
revisor bridge [OPTIONS]

Options:
  -p, --project-path <PATH>  Project directory [default: /tmp/ghidra_proj]
  -n, --project-name <NAME>  Project name       [default: test]
```

Example:
```bash
revisor bridge -p /tmp/ctf -n crackme
# Bridge starts on a random TCP port, auto-saved to ~/.revisor/bridge.pid
```

### `revisor query`

Query the running Bridge directly from the command line.

```bash
revisor query <COMMAND> [ARG] [EXTRA_ARGS...] [OPTIONS]

Options:
  -p, --port <PORT>      Bridge port (auto-discovered if omitted)
  -j, --json <JSON>      Raw JSON args (for complex commands)
  -f, --format <FORMAT>  Output: pretty (default) or json
```

#### Read Commands

```bash
# Program metadata
revisor query ping
revisor query program_info
revisor query list_functions
revisor query memory_blocks
revisor query symbols
revisor query list_imports
revisor query list_exports
revisor query list_data_types

# Decompilation (by function name)
revisor query decompile main
revisor query decompile validate_password

# Function lookup (by address)
revisor query function_at 0x00401000
revisor query function_containing 0x00401050

# Call graph
revisor query callers some_function
revisor query callees main
revisor query call_graph

# Disassembly
revisor query instructions_for_function main

# Cross-references
revisor query references_to 0x00401000
revisor query references_from 0x00401000

# Strings and symbols
revisor query search_strings "password"
revisor query find_symbols main

# Data
revisor query data_at 0x00402000

# Control flow graph
revisor query control_flow_graph main
```

#### Write Commands (use `--json` for multiple args)

```bash
# Rename a function
revisor query rename_function --json '{"function":"FUN_00401000","new_name":"decrypt_payload"}'

# Set inline comment at an address
revisor query set_comment --json '{"address":"0x00401000","comment":"XOR decrypt loop"}'

# Set plate comment on a function
revisor query set_plate_comment --json '{"function":"main","comment":"Entry point"}'
```

#### Output Formats

```bash
# Pretty-printed JSON (default)
revisor query decompile main

# Compact JSON (for scripting/piping)
revisor query decompile main -f json

# Pipe to jq
revisor query list_functions -f json | jq '.functions[].name'
```

### `revisor mcp`

Run the MCP (Model Context Protocol) server over stdio.

```bash
revisor mcp
```

This is normally called by the AI agent, not by the user directly. It reads JSON-RPC 2.0 requests from stdin and writes responses to stdout.

### `revisor run-script`

Run a Ghidra script on an existing project.

```bash
revisor run-script <SCRIPT_NAME> [OPTIONS]

Options:
  -p, --project-path <PATH>  Project directory [default: /tmp/ghidra_proj]
  -n, --project-name <NAME>  Project name       [default: test]
```

Example:
```bash
revisor run-script MyCustomScript.java -p /tmp/ctf -n crackme
```

### `revisor tui`

Launch the Cyberpunk TUI dashboard (also the default when no command is given).

```bash
revisor       # same as revisor tui
revisor tui
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

`revisor` can be used as a library in your own Rust projects:

```toml
[dependencies]
revisor = "0.3"
```

```rust
use revisor::bridge::BridgeClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Auto-discover bridge port, or specify manually
    let port = revisor::bridge::read_bridge_port()
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
revisor analyze tests/crackme -p /tmp/ctf -n crackme
```

### 2. Start the bridge
```bash
revisor bridge -p /tmp/ctf -n crackme
# ✅ Bridge is now ONLINE on port 36881
```

### 3. Discover the password
```bash
$ revisor query decompile validate_password

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
$ revisor query decompile xor_decrypt

# "Revisor2024"[(int)lVar1 % 0xd] ^ *(byte *)(param_1 + lVar1)
# → XOR Key: Revisor2024
```

### 5. Discover hidden functions
```bash
$ revisor query callees main

# → validate_password, print_banner, check_license, secret_function
# secret_function is only called when check_license passes!
```

### 6. Annotate your findings
```bash
revisor query rename_function --json '{"function":"secret_function","new_name":"decrypt_secret_message"}'
revisor query set_comment --json '{"address":"0x00400591","comment":"Password: REV3RSE!"}'
```

---

## 🗂️ Project Structure

```
revisor/
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
│   └── RevisorBridge.java      # Embedded Java bridge (917 lines)
└── tests/
    ├── crackme.c                 # Reverse engineering test target
    ├── crackme                   # Compiled test binary
    └── integration_test.sh       # Automated integration tests
```

---

## 🙏 Acknowledgments

This project was inspired by and references the work of:

- **[ghidra-cli](https://github.com/akiselev/ghidra-cli)** by [@akiselev](https://github.com/akiselev) — A Rust CLI for headless Ghidra automation. Its architectural approach and CLI design patterns provided valuable reference during the development of `revisor`. 🦀
- **[ghidra-rs](https://crates.io/crates/ghidra)** by [@ooojustin](https://github.com/ooojustin) — Typed Rust bindings for an embedded Ghidra JVM via JNI. Its elegant API design with Rust-native lifetime safety inspired the typed `BridgeClient` API.

## 📄 License

GPL-3.0-or-later.
