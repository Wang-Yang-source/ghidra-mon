# ghidra-mon

`ghidra-mon` is a unified command-line utility and AI Model Context Protocol (MCP) server designed to streamline and monitor your Ghidra reverse engineering workflows. It offers a convenient out-of-the-box experience, wrapping Ghidra's powerful but verbose headless analyzer into simple, intuitive CLI commands.

## Features
- **Out-of-the-box CLI**: Quickly analyze binaries and run scripts without memorizing long `analyzeHeadless` incantations.
- **TUI Dashboard**: A built-in terminal UI (TUI) to monitor background Ghidra analysis tasks and logs.
- **AI MCP Integration**: Acts as a Model Context Protocol (MCP) server, allowing AI assistants to seamlessly interact with your Ghidra projects over standard I/O.

## Installation

You can install `ghidra-mon` directly from crates.io (once published):

```bash
cargo install ghidra-mon
```

Or build from source:

```bash
git clone https://github.com/Wang-Yang-source/ghidra-mon.git
cd ghidra-mon
cargo build --release
```

## 🚀 Setup (Zero-Configuration)

`ghidra-mon` supports an ultra-convenient auto-setup mechanism. You don't need to manually download Java or configure Ghidra paths! Simply run:

```bash
ghidra-mon setup
```

This command will automatically download the official Ghidra release and extract it securely into `~/.ghidra-mon/ghidra`. From that point on, `ghidra-mon` will seamlessly use this isolated instance.

*(Optional)* If you already have Ghidra installed and prefer to use your own instance, you can simply set the `GHIDRA_HEADLESS` environment variable:

```bash
export GHIDRA_HEADLESS=/path/to/your/ghidra/support/analyzeHeadless
```

## Usage

### 1. Simple Analysis
Import and analyze a binary in one simple command. By default, it uses a temporary project path.

```bash
ghidra-mon analyze /path/to/malware.bin
```
You can also specify the project path and name:
```bash
ghidra-mon analyze /path/to/malware.bin --project-path ./my_project -n my_binary
```

### 2. Run a Ghidra Script
Easily run a Ghidra script on an existing project.

```bash
ghidra-mon run-script MyCustomScript.java --project-path ./my_project -n my_binary
```

### 3. TUI Monitoring Daemon
Start the background daemon and Terminal UI to monitor tasks visually.

```bash
ghidra-mon tui
```
*(Note: Running `ghidra-mon` without arguments defaults to the TUI).*

### 4. MCP Server Mode
Start the tool as an MCP server. This mode reads from `stdin` and writes to `stdout`, and is typically invoked by an AI agent platform.

```bash
ghidra-mon mcp
```

## Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue on the repository.

## License
Licensed under either of MIT or Apache-2.0 at your option.
