# Ghidra Mon 👁️

A **blazing fast, unified Rust CLI and AI MCP Server** for automating Ghidra reverse engineering workflows. Designed for seamless AI agent integration (Cursor, Claude Desktop) and power users.

## ✨ Features

- **Single Binary Distribution**: The Java Bridge is embedded directly into the Rust executable. No separate scripts to manage or lose.
- **Persistent JVM Bridge Architecture**: Keeps Ghidra loaded in memory, enabling **10-millisecond response times** for complex decompilation and string searching queries.
- **Zero-Configuration Setup**: `ghidra-mon setup` automatically downloads, extracts, and configures the official Ghidra release for you in an isolated environment.
- **Cyberpunk TUI Dashboard**: Monitor long-running headless analysis tasks and live MCP server logs through a beautiful Ratatui-powered terminal interface.
- **Native MCP Server**: Exposes Ghidra's powerful reverse engineering capabilities directly to AI agents via the Model Context Protocol.

## 🏗️ Architecture

```text
┌─────────────────────────┐         ┌──────────────────────────────────────┐
│  AI Agent (Cursor/MCP)  │──TCP──▶ │  ghidra-mon (Rust MCP Server)        │
│  or Human CLI           │         │  (Parses commands, spawns Ghidra)    │
└─────────────────────────┘         └──────────────────────────────────────┘
                                                       │
                                                 Local TCP Socket
                                                       ▼
                                    ┌──────────────────────────────────────┐
                                    │  GhidraMonBridge.java                │
                                    │  (Running persistently in JVM)       │
                                    └──────────────────────────────────────┘
```

The CLI connects directly to a Java bridge running inside Ghidra's JVM. This provides:
- **Zero JVM Startup Overhead**: The JVM is started once. Subsequent queries (like decompiling a function) happen in milliseconds.
- **Single Source of Truth**: The Rust binary handles both the MCP Server routing and the embedding of the Java script.

## 🚀 Installation

From Crates.io:
```bash
cargo install ghidra-mon
```

From Source:
```bash
git clone https://github.com/Wang-Yang-source/ghidra-mon.git
cd ghidra-mon
cargo install --path .
```

## 🛠️ Zero-Config Setup

Don't have Ghidra installed? No problem.
```bash
ghidra-mon setup
```
*This downloads and configures Ghidra 11.2 locally into `~/.ghidra-mon/ghidra` without touching your system environment.*

## 💻 Usage

### 1. Import and Analyze
Import a binary into a Ghidra project and run the headless auto-analyzer.
```bash
ghidra-mon analyze /path/to/malware.bin --project-path ./my_project -n my_binary
```

### 2. Start the Persistent Bridge
Start the in-memory Java Bridge server for lightning-fast querying.
```bash
ghidra-mon bridge --project-path ./my_project -n my_binary
```
*You will see the bridge come online and bind to a TCP port.*

### 3. Start the MCP Server
Connect your AI Assistant (Cursor, Claude) to Ghidra by adding this to your MCP config:
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

### 4. TUI Monitoring Daemon
Run `ghidra-mon tui` (or just `ghidra-mon`) to open the Cyberpunk Dashboard and visually monitor all running tasks and MCP queries in real-time.

## 🤖 MCP Capabilities (AI Tools)

Once connected via MCP, your AI gets access to these tools:
- `ghidra_ask_bridge`: Send instant JSON queries to the persistent bridge.
  - `list_functions`: Get all functions in the binary.
  - `decompile`: Instantly grab the C source code of any function.
  - `get_function_signature`: Get the exact C prototype signature of a function.
  - `get_xrefs`: Find all cross-references calling a specific function.
  - `search_strings`: Globally search memory for string patterns.
- `ghidra_import_and_analyze`: Trigger long-running binary analysis.
- `ghidra_run_script`: Execute arbitrary custom Java/Python Ghidra scripts.

## License

GPL-3.0 License.
