// Bridge client for communicating with the Ghidra Java bridge TCP server.
// Wraps TCP send/receive with typed convenience methods for each command.
// Also handles bridge port auto-discovery via ~/.revisor/bridge.pid.

use crate::error::{GhidraMonError, Result};
use crate::types::*;

use serde_json::{json, Value};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Embedded Java bridge source – written to disk before launching Ghidra.
pub(crate) const GHIDRA_BRIDGE_CODE: &str = include_str!("GhidraMonBridge.java");

// ─── Bridge Port Auto-Discovery ──────────────────────────────────────────────

/// Path to the bridge port file.
fn bridge_pid_path() -> Option<std::path::PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(|h| std::path::PathBuf::from(h).join(".revisor/bridge.pid"))
}

/// Write the bridge port to the discovery file so MCP can find it automatically.
pub fn write_bridge_port(port: u16, project: &str) {
    if let Some(path) = bridge_pid_path() {
        let content = format!(
            "{}\n{}\n{}",
            port,
            std::process::id(),
            project
        );
        let _ = std::fs::write(&path, content);
    }
}

/// Read the bridge port from the discovery file.
/// Returns None if the file doesn't exist or can't be parsed.
pub fn read_bridge_port() -> Option<u16> {
    let path = bridge_pid_path()?;
    let content = std::fs::read_to_string(&path).ok()?;
    let first_line = content.lines().next()?;
    first_line.trim().parse::<u16>().ok()
}

/// Remove the bridge port file (called on shutdown).
pub fn remove_bridge_port_file() {
    if let Some(path) = bridge_pid_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// A client that talks to the Ghidra bridge TCP server.
pub struct BridgeClient {
    addr: String,
}

impl BridgeClient {
    /// Create a new client targeting the bridge on the given port.
    pub fn new(port: u16) -> Self {
        Self {
            addr: format!("127.0.0.1:{}", port),
        }
    }

    // ─── Low-level transport ──────────────────────────────────────────────

    /// Send a raw JSON command to the bridge and return the parsed response.
    /// Uses line-based reading (each bridge response is one JSON line) to avoid
    /// truncation issues with large responses like call graphs.
    pub async fn send_command(&self, command: &str, args: Option<Value>) -> Result<Value> {
        let mut stream = tokio::net::TcpStream::connect(&self.addr)
            .await
            .map_err(|e| GhidraMonError::Bridge {
                message: format!("Failed to connect to bridge at {}: {}", self.addr, e),
            })?;

        let payload = BridgeCommand {
            command: command.to_string(),
            args,
        };
        let payload_str = format!("{}\n", serde_json::to_string(&payload)?);
        stream
            .write_all(payload_str.as_bytes())
            .await
            .map_err(|e| GhidraMonError::Bridge {
                message: format!("Failed to write to bridge: {e}"),
            })?;

        // Read a single line response using BufReader (no fixed-size buffer limit)
        let reader = tokio::io::BufReader::new(&mut stream);
        let mut lines = reader.lines();
        let response_str = lines
            .next_line()
            .await
            .map_err(|e| GhidraMonError::Bridge {
                message: format!("Failed to read from bridge: {e}"),
            })?
            .ok_or_else(|| GhidraMonError::Bridge {
                message: "Bridge closed connection without response".to_string(),
            })?;

        let value: Value = serde_json::from_str(&response_str)?;

        // Check for bridge-level errors
        if let Some(err) = value.get("error").and_then(|e| e.as_str()) {
            return Err(GhidraMonError::Bridge {
                message: err.to_string(),
            });
        }

        Ok(value)
    }

    // ─── Typed convenience methods ────────────────────────────────────────

    /// Ping the bridge to verify connectivity.
    pub async fn ping(&self) -> Result<()> {
        self.send_command("ping", None).await?;
        Ok(())
    }

    /// Get program metadata.
    pub async fn program_info(&self) -> Result<ProgramInfo> {
        let val = self.send_command("program_info", None).await?;
        Ok(serde_json::from_value(val)?)
    }

    /// List all functions in the program (up to the bridge's limit).
    pub async fn list_functions(&self) -> Result<Vec<FunctionInfo>> {
        let val = self.send_command("list_functions", None).await?;
        let funcs = val
            .get("functions")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(funcs)?)
    }

    /// Decompile a function by name.
    pub async fn decompile(&self, function: &str) -> Result<DecompileResult> {
        let val = self
            .send_command("decompile", Some(json!({ "function": function })))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get the function at a specific address.
    pub async fn function_at(&self, address: &str) -> Result<FunctionInfo> {
        let val = self
            .send_command("function_at", Some(json!({ "address": address })))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get the function containing a specific address.
    pub async fn function_containing(&self, address: &str) -> Result<FunctionInfo> {
        let val = self
            .send_command(
                "function_containing",
                Some(json!({ "address": address })),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get callers of a function.
    pub async fn callers(&self, function: &str) -> Result<Vec<FunctionInfo>> {
        let val = self
            .send_command("callers", Some(json!({ "function": function })))
            .await?;
        let callers = val
            .get("callers")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(callers)?)
    }

    /// Get callees of a function.
    pub async fn callees(&self, function: &str) -> Result<Vec<FunctionInfo>> {
        let val = self
            .send_command("callees", Some(json!({ "function": function })))
            .await?;
        let callees = val
            .get("callees")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(callees)?)
    }

    /// Get disassembly for a function.
    pub async fn instructions_for_function(&self, function: &str) -> Result<Vec<InstructionInfo>> {
        let val = self
            .send_command("instructions", Some(json!({ "function": function })))
            .await?;
        let instrs = val
            .get("instructions")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(instrs)?)
    }

    /// List memory blocks.
    pub async fn memory_blocks(&self) -> Result<Vec<MemoryBlockInfo>> {
        let val = self.send_command("memory_blocks", None).await?;
        let blocks = val.get("blocks").cloned().unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(blocks)?)
    }

    /// List symbols, optionally filtered by type.
    pub async fn symbols(&self, symbol_type: Option<&str>) -> Result<Vec<SymbolInfo>> {
        let args = symbol_type.map(|t| json!({ "type": t }));
        let val = self.send_command("symbols", args).await?;
        let symbols = val
            .get("symbols")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(symbols)?)
    }

    /// Search for symbols by name pattern.
    pub async fn find_symbols(&self, query: &str) -> Result<Vec<SymbolInfo>> {
        let val = self
            .send_command("find_symbols", Some(json!({ "query": query })))
            .await?;
        let symbols = val
            .get("symbols")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(symbols)?)
    }

    /// Get cross-references TO an address.
    pub async fn references_to(&self, address: &str) -> Result<Vec<ReferenceInfo>> {
        let val = self
            .send_command("references_to", Some(json!({ "address": address })))
            .await?;
        let refs = val
            .get("references")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(refs)?)
    }

    /// Get cross-references FROM an address.
    pub async fn references_from(&self, address: &str) -> Result<Vec<ReferenceInfo>> {
        let val = self
            .send_command("references_from", Some(json!({ "address": address })))
            .await?;
        let refs = val
            .get("references")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(refs)?)
    }

    /// Search for strings in the binary.
    pub async fn search_strings(&self, query: &str) -> Result<Vec<StringResult>> {
        let val = self
            .send_command("search_strings", Some(json!({ "query": query })))
            .await?;
        let strings = val
            .get("strings")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(strings)?)
    }

    /// Get call graph for the program.
    pub async fn call_graph(&self, depth: Option<u32>) -> Result<CallGraph> {
        let args = depth.map(|d| json!({ "depth": d }));
        let val = self.send_command("call_graph", args).await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get control flow graph for a function.
    pub async fn control_flow_graph(&self, function: &str) -> Result<ControlFlowGraph> {
        let val = self
            .send_command(
                "control_flow_graph",
                Some(json!({ "function": function })),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// List imported symbols.
    pub async fn list_imports(&self) -> Result<Vec<ImportInfo>> {
        let val = self.send_command("list_imports", None).await?;
        let imports = val
            .get("imports")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(imports)?)
    }

    /// List exported symbols.
    pub async fn list_exports(&self) -> Result<Vec<ExportInfo>> {
        let val = self.send_command("list_exports", None).await?;
        let exports = val
            .get("exports")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(exports)?)
    }

    /// Rename a function.
    pub async fn rename_function(&self, function: &str, new_name: &str) -> Result<()> {
        self.send_command(
            "rename_function",
            Some(json!({ "function": function, "new_name": new_name })),
        )
        .await?;
        Ok(())
    }

    /// Set an inline comment at an address.
    pub async fn set_comment(&self, address: &str, comment: &str) -> Result<()> {
        self.send_command(
            "set_comment",
            Some(json!({ "address": address, "comment": comment })),
        )
        .await?;
        Ok(())
    }

    /// Set a plate (block) comment on a function.
    pub async fn set_plate_comment(&self, function: &str, comment: &str) -> Result<()> {
        self.send_command(
            "set_plate_comment",
            Some(json!({ "function": function, "comment": comment })),
        )
        .await?;
        Ok(())
    }

    /// Get data at an address.
    pub async fn data_at(&self, address: &str) -> Result<DataInfo> {
        let val = self
            .send_command("data_at", Some(json!({ "address": address })))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// List data types known to the program.
    pub async fn list_data_types(&self) -> Result<Vec<DataTypeInfo>> {
        let val = self.send_command("list_data_types", None).await?;
        let types = val
            .get("data_types")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(types)?)
    }
}

// ─── Bridge Server Launcher ──────────────────────────────────────────────────

/// Start the Ghidra headless process with the bridge script.
/// This is used by the `bridge` CLI subcommand.
pub async fn run_bridge_server(
    ghidra_bin: String,
    project_path: String,
    project_name: String,
) -> Result<()> {
    let script_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(|h| std::path::PathBuf::from(h).join(".revisor"))
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));

    std::fs::create_dir_all(&script_dir).map_err(|e| GhidraMonError::io("create script dir", e))?;
    let script_path = script_dir.join("GhidraMonBridge.java");
    std::fs::write(&script_path, GHIDRA_BRIDGE_CODE)
        .map_err(|e| GhidraMonError::io("write bridge script", e))?;

    println!("🚀 Starting Ghidra Bridge Server...");

    let mut child = Command::new(&ghidra_bin)
        .arg(&project_path)
        .arg(&project_name)
        .arg("-process")
        .arg("-postScript")
        .arg(script_path.to_string_lossy().to_string())
        .arg("-scriptPath")
        .arg(script_dir.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| GhidraMonError::io("spawn Ghidra headless", e))?;

    let stdout = child.stdout.take().expect("Failed to grab stdout");
    let mut reader = tokio::io::BufReader::new(stdout).lines();

    tokio::spawn(async move {
        while let Ok(Some(line)) = reader.next_line().await {
            if line.contains("---GHIDRA_MON_START---") {
                println!("🔌 Bridge is initializing...");
            } else if line.contains("{\"status\":\"ready\"") {
                if let Some(start) = line.find('{')
                    && let Some(end) = line.rfind('}')
                        && let Ok(val) = serde_json::from_str::<Value>(&line[start..=end])
                            && let Some(port) = val.get("port") {
                                let port_num = port.as_u64().unwrap_or(0) as u16;
                                // Write port to discovery file so MCP can find it
                                write_bridge_port(port_num, "bridge");
                                println!(
                                    "✅ Bridge is now ONLINE and listening on TCP port {}",
                                    port
                                );
                                println!(
                                    "   Port auto-saved to ~/.revisor/bridge.pid for MCP discovery"
                                );
                                println!(
                                    "   You can now send JSON commands like {{\"command\":\"ping\"}} to 127.0.0.1:{}",
                                    port
                                );
                            }
            } else {
                println!("[Ghidra] {}", line);
            }
        }
    });

    let status = child
        .wait()
        .await
        .map_err(|e| GhidraMonError::io("wait for Ghidra process", e))?;
    remove_bridge_port_file();
    println!("🛑 Bridge process exited with status: {}", status);
    Ok(())
}
