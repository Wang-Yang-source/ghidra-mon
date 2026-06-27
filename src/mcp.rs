// MCP (Model Context Protocol) server over stdio.
// Implements JSON-RPC 2.0 as an optional compatibility layer.
//
// The MCP server exposes adapter commands over the same backend model:
// 1. Bridge tools: query/mutate a running Ghidra bridge TCP server
// 2. Headless tools: spawn Ghidra headless processes (import, analyze, scripts)

mod tools;

use crate::bridge;
use crate::tui::SOCKET_PATH;
use crate::types::*;

use serde_json::{Value, json};
use std::env;
use std::io::{self, Write};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::Command;

const MCP_BACKEND_ENV: &str = "GHIDRA_MCP_BACKEND";
const MCP_EXT_CMD_ENV: &str = "GHIDRA_MCP_COMMAND";
const MCP_EXT_ARGS_ENV: &str = "GHIDRA_MCP_ARGS";
const DEFAULT_GHIDRA_MCP_COMMAND: &str = "bridge_mcp_ghidra.py";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpBackend {
    Legacy,
    External,
}

impl McpBackend {
    fn from_cli_or_env_strict(backend: Option<&str>) -> Result<Self, String> {
        let value = backend
            .map(|value| value.to_lowercase())
            .or_else(|| env::var(MCP_BACKEND_ENV).ok())
            .or_else(|| {
                env::var(MCP_EXT_CMD_ENV)
                    .ok()
                    .and_then(|_| Some("external".to_string()))
            })
            .unwrap_or_else(|| "legacy".to_string());

        match value.as_str() {
            "legacy" => Ok(Self::Legacy),
            "external" | "ghidra-mcp" | "ghidramcp" | "ghidra_mcp" => Ok(Self::External),
            other => Err(format!(
                "unsupported MCP backend '{other}'. Valid values are: legacy, external"
            )),
        }
    }
}

/// Run the MCP server, reading JSON-RPC 2.0 requests from stdin and writing responses to stdout.
/// Uses async tokio stdin to avoid blocking the runtime.
pub async fn run_mcp_server(backend: Option<&str>) -> bool {
    let backend = match McpBackend::from_cli_or_env_strict(backend) {
        Ok(backend) => backend,
        Err(err) => {
            eprintln!("{err}");
            return false;
        }
    };

    match backend {
        McpBackend::External => run_external_mcp_server().await,
        McpBackend::Legacy => {
            run_legacy_mcp_server().await;
            true
        }
    }
}

async fn run_external_mcp_server() -> bool {
    let command =
        env::var(MCP_EXT_CMD_ENV).unwrap_or_else(|_| DEFAULT_GHIDRA_MCP_COMMAND.to_string());
    let extra_args = env::var(MCP_EXT_ARGS_ENV).unwrap_or_default();
    let (exec, mut args) = resolve_external_command(&command);

    if !extra_args.trim().is_empty() {
        args.extend(split_external_args(&extra_args));
    }

    let status = Command::new(&exec)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await;

    match status {
        Ok(status) if status.success() => true,
        Ok(status) => {
            println!("external mcp backend exited with status: {status}");
            false
        }
        Err(err) => {
            println!(
                "failed to launch external MCP backend ({exec}): {err}; set GHIDRA_MCP_COMMAND and GHIDRA_MCP_ARGS"
            );
            false
        }
    }
}

fn resolve_external_command(raw: &str) -> (String, Vec<String>) {
    let parts = split_external_command(raw);
    if parts.len() > 1 {
        return (
            parts[0].clone(),
            parts[1..]
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        );
    }

    let exec = parts
        .first()
        .cloned()
        .unwrap_or_else(|| DEFAULT_GHIDRA_MCP_COMMAND.to_string());
    if exec.ends_with(".py") {
        let python = if cfg!(windows) { "python" } else { "python3" };
        return (python.to_string(), vec![exec]);
    }

    (exec, Vec::new())
}

fn split_external_command(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    if let Ok(Value::Array(parsed)) = serde_json::from_str::<Value>(trimmed)
        && parsed.iter().all(Value::is_string)
    {
        return parsed
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect();
    }

    trimmed.split_whitespace().map(str::to_string).collect()
}

fn split_external_args(raw: &str) -> Vec<String> {
    split_external_command(raw)
}

async fn run_legacy_mcp_server() {
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let req_val: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(err) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {}", err)
                    }
                });
                println!("{}", serde_json::to_string(&err_resp).unwrap());
                let _ = io::stdout().flush();
                continue;
            }
        };
        let method = req_val["method"].as_str().unwrap_or("");
        let id = req_val.get("id").cloned().unwrap_or(Value::Null);

        let mut response = json!({ "jsonrpc": "2.0", "id": id });

        match method {
            "initialize" => {
                response["result"] = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "ghidrai", "version": env!("CARGO_PKG_VERSION") }
                });
            }
            "tools/list" => {
                response["result"] = json!({ "tools": tools::build_legacy_tool_list() });
            }
            "tools/call" => {
                let name = req_val["params"]["name"].as_str().unwrap_or("");
                let args = req_val["params"]["arguments"].clone();
                response = handle_tool_call(name, args, id).await;
            }
            "notifications/initialized" => {
                continue;
            }
            _ => {
                response["error"] = json!({ "code": -32601, "message": "Method not found" });
            }
        }
        println!("{}", serde_json::to_string(&response).unwrap());
        io::stdout().flush().unwrap();
    }
}

// ─── Tool Call Dispatch ───────────────────────────────────────────────────────

/// Handle a tools/call request and return the JSON-RPC response.
async fn handle_tool_call(name: &str, args: Value, id: Value) -> Value {
    let mut response = json!({ "jsonrpc": "2.0", "id": id });

    match name {
        // ── Raw bridge ─────────────────────────────────────────────────
        "ghidra_ask_bridge" => {
            handle_bridge_raw(&args, &mut response).await;
        }
        "ghidra_check_connection" => {
            send_bridge_command(&args, "ping", None, &mut response).await;
        }
        "ghidra_get_metadata" => {
            send_bridge_command(&args, "program_info", None, &mut response).await;
        }
        "ghidra_get_version" => {
            set_result_text(
                &mut response,
                &json!({
                    "status": "ok",
                    "tool_version": env!("CARGO_PKG_VERSION"),
                })
                .to_string(),
            );
        }
        "ghidra_list_functions_enhanced" => {
            send_bridge_command(&args, "list_functions", None, &mut response).await;
        }
        "ghidra_decompile_function" => {
            let cmd_args = json!({ "function": args["function"] });
            send_bridge_command(&args, "decompile", Some(cmd_args), &mut response).await;
        }
        "ghidra_force_decompile" => {
            let cmd_args = json!({ "function": args["function"] });
            send_bridge_command(&args, "decompile", Some(cmd_args), &mut response).await;
        }

        // ── Typed bridge queries ───────────────────────────────────────
        "ghidra_program_info" => {
            send_bridge_command(&args, "program_info", None, &mut response).await;
        }
        "ghidra_list_functions" => {
            send_bridge_command(&args, "list_functions", None, &mut response).await;
        }
        "ghidra_decompile" => {
            let cmd_args = json!({ "function": args["function"] });
            send_bridge_command(&args, "decompile", Some(cmd_args), &mut response).await;
        }
        "ghidra_function_at" => {
            let cmd_args = json!({ "address": args["address"] });
            send_bridge_command(&args, "function_at", Some(cmd_args), &mut response).await;
        }
        "ghidra_function_containing" => {
            let cmd_args = json!({ "address": args["address"] });
            send_bridge_command(&args, "function_containing", Some(cmd_args), &mut response).await;
        }
        "ghidra_get_function_signature" => {
            let mut cmd_args = json!({});
            if args.get("function").is_some() {
                cmd_args["function"] = args["function"].clone();
            } else if args.get("address").is_some() {
                cmd_args["address"] = args["address"].clone();
            } else {
                cmd_args = json!({});
            }
            send_bridge_command(
                &args,
                "get_function_signature",
                Some(cmd_args),
                &mut response,
            )
            .await;
        }
        "ghidra_callers" => {
            let cmd_args = json!({ "function": args["function"] });
            send_bridge_command(&args, "callers", Some(cmd_args), &mut response).await;
        }
        "ghidra_callees" => {
            let cmd_args = json!({ "function": args["function"] });
            send_bridge_command(&args, "callees", Some(cmd_args), &mut response).await;
        }
        "ghidra_instructions" => {
            let cmd_args = json!({ "function": args["function"] });
            send_bridge_command(
                &args,
                "instructions_for_function",
                Some(cmd_args),
                &mut response,
            )
            .await;
        }
        "ghidra_instructions_for_function" => {
            let cmd_args = json!({ "function": args["function"] });
            send_bridge_command(
                &args,
                "instructions_for_function",
                Some(cmd_args),
                &mut response,
            )
            .await;
        }
        "ghidra_instruction_at" => {
            let cmd_args = json!({ "address": args["address"] });
            send_bridge_command(&args, "instruction_at", Some(cmd_args), &mut response).await;
        }
        "ghidra_memory_blocks" => {
            send_bridge_command(&args, "memory_blocks", None, &mut response).await;
        }
        "ghidra_find_symbols" => {
            let cmd_args = if args.is_object() && !args.as_object().unwrap().is_empty() {
                Some(json!({ "query": args["query"] }))
            } else {
                None
            };
            send_bridge_command(&args, "find_symbols", cmd_args, &mut response).await;
        }
        "ghidra_symbols" => {
            let mut cmd_args = json!({});
            if let Some(t) = args.get("symbol_type").and_then(|v| v.as_str()) {
                cmd_args["type"] = json!(t);
            }
            if let Some(q) = args.get("query").and_then(|v| v.as_str()) {
                cmd_args["query"] = json!(q);
            }
            let cmd_args_opt = if cmd_args.as_object().unwrap().is_empty() {
                None
            } else {
                Some(cmd_args)
            };
            // Use find_symbols if query is present, otherwise symbols
            if args.get("query").is_some() {
                send_bridge_command(&args, "find_symbols", cmd_args_opt, &mut response).await;
            } else {
                send_bridge_command(&args, "symbols", cmd_args_opt, &mut response).await;
            }
        }
        "ghidra_get_xrefs" => {
            let mut cmd_args = json!({});
            if args.get("function").is_some() {
                cmd_args["function"] = args["function"].clone();
            } else if args.get("address").is_some() {
                cmd_args["address"] = args["address"].clone();
            }
            let cmd_args = if cmd_args.as_object().unwrap().is_empty() {
                None
            } else {
                Some(cmd_args)
            };
            send_bridge_command(&args, "references_to", cmd_args, &mut response).await;
        }
        "ghidra_references_to" => {
            let cmd_args = json!({ "address": args["address"] });
            send_bridge_command(&args, "references_to", Some(cmd_args), &mut response).await;
        }
        "ghidra_references_from" => {
            let cmd_args = json!({ "address": args["address"] });
            send_bridge_command(&args, "references_from", Some(cmd_args), &mut response).await;
        }
        "ghidra_search_strings" => {
            let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let cmd_args = json!({ "query": query });
            send_bridge_command(&args, "search_strings", Some(cmd_args), &mut response).await;
        }
        "ghidra_call_graph" => {
            let cmd_args = args.get("depth").map(|d| json!({ "depth": d }));
            send_bridge_command(&args, "call_graph", cmd_args, &mut response).await;
        }
        "ghidra_control_flow_graph" => {
            let cmd_args = json!({ "function": args["function"] });
            send_bridge_command(&args, "control_flow_graph", Some(cmd_args), &mut response).await;
        }
        "ghidra_imports" => {
            send_bridge_command(&args, "list_imports", None, &mut response).await;
        }
        "ghidra_list_imports" => {
            send_bridge_command(&args, "list_imports", None, &mut response).await;
        }
        "ghidra_exports" => {
            send_bridge_command(&args, "list_exports", None, &mut response).await;
        }
        "ghidra_list_exports" => {
            send_bridge_command(&args, "list_exports", None, &mut response).await;
        }
        "ghidra_data_types" => {
            send_bridge_command(&args, "list_data_types", None, &mut response).await;
        }
        "ghidra_list_data_types" => {
            send_bridge_command(&args, "list_data_types", None, &mut response).await;
        }
        "ghidra_data_at" => {
            let cmd_args = json!({ "address": args["address"] });
            send_bridge_command(&args, "data_at", Some(cmd_args), &mut response).await;
        }
        "ghidra_set_plate_comment" => {
            let cmd_args = json!({
                "function": args["function"],
                "comment": args["comment"]
            });
            send_bridge_command(&args, "set_plate_comment", Some(cmd_args), &mut response).await;
        }
        "ghidra_ping" => {
            send_bridge_command(&args, "ping", None, &mut response).await;
        }
        "ghidra_shutdown" => {
            send_bridge_command(&args, "shutdown", None, &mut response).await;
        }
        "ghidra_rename_function" => {
            let cmd_args = json!({
                "function": args["function"],
                "new_name": args["new_name"]
            });
            send_bridge_command(&args, "rename_function", Some(cmd_args), &mut response).await;
        }
        "ghidra_set_comment" => {
            let cmd_args = json!({
                "address": args["address"],
                "comment": args["comment"]
            });
            send_bridge_command(&args, "set_comment", Some(cmd_args), &mut response).await;
        }

        // ── Headless tools (delegate to daemon) ────────────────────────
        "ghidra_import_and_analyze" | "ghidra_run_script" => {
            delegate_to_daemon(name, &args, &mut response).await;
        }

        _ => {
            if let Some(command) = bridge_alias_for_tool(name) {
                send_bridge_command(&args, command.as_str(), Some(args.clone()), &mut response)
                    .await;
            } else if let Some(command) = name.strip_prefix("ghidra_") {
                send_bridge_command(
                    &args,
                    command,
                    Some(strip_reserved_bridge_args(&args)),
                    &mut response,
                )
                .await;
            } else {
                response["error"] =
                    json!({ "code": -32601, "message": format!("Unknown tool: {}", name) });
            }
        }
    }

    response
}

// ─── Bridge Communication Helpers ─────────────────────────────────────────────

/// Resolve the bridge port: use explicit port if provided, otherwise read from bridge.pid file.
fn resolve_port(args: &Value) -> Option<u16> {
    // Explicit port takes priority
    if let Some(port) = args.get("port").and_then(|v| v.as_u64()) {
        if (1..=u16::MAX as u64).contains(&port) {
            return Some(port as u16);
        }
        return None;
    }
    // Fall back to auto-discovery from bridge.pid
    bridge::read_bridge_port()
}

fn bridge_alias_for_tool(name: &str) -> Option<String> {
    match name {
        "ghidra_check_connection" => Some("ping".to_string()),
        "ghidra_get_metadata" => Some("program_info".to_string()),
        "ghidra_list_functions_enhanced" => Some("list_functions".to_string()),
        "ghidra_decompile_function" => Some("decompile".to_string()),
        "ghidra_force_decompile" => Some("decompile".to_string()),
        _ => {
            let (_, base) = name.split_at(7);
            if name.starts_with("ghidra_") && is_supported_bridge_command(base) {
                Some(base.to_string())
            } else {
                None
            }
        }
    }
}

fn is_supported_bridge_command(command: &str) -> bool {
    matches!(
        command,
        "ping"
            | "shutdown"
            | "program_info"
            | "list_functions"
            | "function_at"
            | "function_containing"
            | "get_function_signature"
            | "callers"
            | "callees"
            | "decompile"
            | "instructions_for_function"
            | "instruction_at"
            | "memory_blocks"
            | "data_at"
            | "list_data_types"
            | "symbols"
            | "find_symbols"
            | "get_xrefs"
            | "references_to"
            | "references_from"
            | "search_strings"
            | "call_graph"
            | "control_flow_graph"
            | "list_imports"
            | "list_exports"
            | "rename_function"
            | "set_comment"
            | "set_plate_comment"
    )
}

fn set_result_text(response: &mut Value, text: &str) {
    response["result"] = json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ]
    });
}

fn strip_reserved_bridge_args(args: &Value) -> Value {
    let mut stripped = args.clone();
    if let Some(map) = stripped.as_object_mut() {
        map.remove("port");
    }
    stripped
}

/// Send a raw command to the bridge (the ghidra_ask_bridge tool).
async fn handle_bridge_raw(args: &Value, response: &mut Value) {
    let port = match resolve_port(args) {
        Some(p) => p,
        None => {
            response["error"] = json!({ "code": -32000, "message": "No bridge port specified and no running bridge found. Start a bridge first with 'gda bridge' or pass a 'port' parameter." });
            return;
        }
    };
    let cmd = args["command"].as_str().unwrap_or("");
    let cmd_args = args["args"].clone();

    if let Ok(mut stream) = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
        let payload = json!({ "command": cmd, "args": cmd_args });
        let payload_str = format!("{}\n", serde_json::to_string(&payload).unwrap());
        let _ = stream.write_all(payload_str.as_bytes()).await;

        // Read response line-by-line instead of fixed buffer to prevent truncation
        let reader = tokio::io::BufReader::new(&mut stream);
        let mut lines = reader.lines();
        if let Ok(Some(line)) = lines.next_line().await {
            if let Ok(parsed) = serde_json::from_str::<Value>(&line) {
                let status = parsed.get("status").and_then(Value::as_str);
                if status == Some("error") {
                    response["error"] = json!({
                        "code": -32000,
                        "message": parsed
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("bridge returned error status"),
                    });
                    return;
                }
                response["result"] = json!({
                    "content": [{ "type": "text", "text": line }]
                });
            } else {
                response["result"] = json!({
                    "content": [{ "type": "text", "text": line }]
                });
            }
        } else {
            response["error"] = json!({ "code": -32000, "message": "Failed to read from bridge" });
        }
    } else {
        response["error"] = json!({ "code": -32000, "message": format!("Failed to connect to bridge on port {}", port) });
    }
}

/// Send a typed command to the bridge and wrap the response for MCP.
async fn send_bridge_command(
    tool_args: &Value,
    command: &str,
    cmd_args: Option<Value>,
    response: &mut Value,
) {
    let port = match resolve_port(tool_args) {
        Some(p) => p,
        None => {
            response["error"] = json!({ "code": -32602, "message": "No bridge port available. Start a bridge with 'gda bridge' or pass 'port'." });
            return;
        }
    };

    if let Ok(mut stream) = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
        let payload = BridgeCommand {
            command: command.to_string(),
            args: cmd_args,
        };
        let payload_str = format!("{}\n", serde_json::to_string(&payload).unwrap());
        let _ = stream.write_all(payload_str.as_bytes()).await;

        // Read response line-by-line instead of fixed buffer to prevent truncation
        let reader = tokio::io::BufReader::new(&mut stream);
        let mut lines = reader.lines();
        if let Ok(Some(line)) = lines.next_line().await {
            if let Ok(parsed) = serde_json::from_str::<Value>(&line) {
                let status = parsed.get("status").and_then(Value::as_str);
                if status == Some("error") {
                    response["error"] = json!({
                        "code": -32000,
                        "message": parsed
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("bridge returned error status"),
                    });
                    return;
                }
                response["result"] = json!({
                    "content": [{ "type": "text", "text": line }]
                });
            } else {
                response["result"] = json!({
                    "content": [{ "type": "text", "text": line }]
                });
            }
        } else {
            response["error"] = json!({ "code": -32000, "message": "Failed to read from bridge" });
        }
    } else {
        response["error"] = json!({
            "code": -32000,
            "message": format!("Failed to connect to bridge on port {}", port)
        });
    }
}

/// Delegate a headless tool call to the daemon over the Unix socket.
async fn delegate_to_daemon(name: &str, args: &Value, response: &mut Value) {
    if let Ok(mut stream) = UnixStream::connect(SOCKET_PATH).await {
        let d_req = DaemonRequest::StartTask {
            name: name.to_string(),
            params: args.to_string(),
        };
        let req_str = format!("{}\n", serde_json::to_string(&d_req).unwrap());
        let _ = stream.write_all(req_str.as_bytes()).await;

        let mut buf = vec![0; 8192];
        if let Ok(n) = stream.read(&mut buf).await {
            let res_str = String::from_utf8_lossy(&buf[..n]);
            response["result"] = json!({
                "content": [{ "type": "text", "text": format!("Ghidra Task submitted. Daemon reply: {}", res_str.trim()) }]
            });
        }
    } else {
        response["error"] = json!({ "code": -32000, "message": "Failed to connect to daemon" });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, json};
    use std::collections::HashSet;

    #[test]
    fn split_external_args_supports_json_arrays() {
        assert_eq!(
            split_external_command(
                "[\"python3\", \"bridge_mcp_ghidra.py\", \"--transport\", \"stdio\"]"
            ),
            vec![
                "python3".to_string(),
                "bridge_mcp_ghidra.py".to_string(),
                "--transport".to_string(),
                "stdio".to_string()
            ]
        );
    }

    #[test]
    fn split_external_args_falls_back_to_whitespace() {
        assert_eq!(
            split_external_command("python3 bridge_mcp_ghidra.py --transport stdio"),
            vec![
                "python3".to_string(),
                "bridge_mcp_ghidra.py".to_string(),
                "--transport".to_string(),
                "stdio".to_string()
            ]
        );
    }

    #[test]
    fn resolve_external_command_supports_interpreter_and_script_modes() {
        assert_eq!(
            resolve_external_command("python3"),
            ("python3".to_string(), Vec::<String>::new())
        );
        assert_eq!(
            resolve_external_command("python3 -m tools.bridge"),
            (
                "python3".to_string(),
                vec!["-m".to_string(), "tools.bridge".to_string()],
            )
        );
        assert_eq!(
            resolve_external_command("bridge_mcp_ghidra.py"),
            (
                "python3".to_string(),
                vec!["bridge_mcp_ghidra.py".to_string()]
            )
        );
        assert_eq!(
            resolve_external_command("/usr/bin/python3"),
            ("/usr/bin/python3".to_string(), Vec::<String>::new())
        );
        assert_eq!(
            resolve_external_command("/tmp/tools/bridge.py"),
            (
                "python3".to_string(),
                vec!["/tmp/tools/bridge.py".to_string()]
            )
        );
    }

    #[test]
    fn external_and_legacy_backend_aliases_are_recognized() {
        assert_eq!(
            McpBackend::from_cli_or_env_strict(Some("external")),
            Ok(McpBackend::External)
        );
        assert_eq!(
            McpBackend::from_cli_or_env_strict(Some("ghidra-mcp")),
            Ok(McpBackend::External)
        );
        assert_eq!(
            McpBackend::from_cli_or_env_strict(Some("legacy")),
            Ok(McpBackend::Legacy)
        );
        assert!(McpBackend::from_cli_or_env_strict(Some("other")).is_err());
    }

    fn sample_args_for_tool(tool: &Value) -> Value {
        let properties = tool
            .get("inputSchema")
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut map = Map::new();

        for (name, definition) in properties.iter() {
            if name == "port" {
                continue;
            }

            let schema_type = definition
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("string");
            let value = match schema_type {
                "number" | "integer" => json!(1),
                "boolean" => json!(false),
                "array" => json!([]),
                "object" => json!({}),
                _ => match name.as_str() {
                    "command" => json!("ping"),
                    "function" => json!("main"),
                    "address" => json!("0x401000"),
                    "binary_path" => json!("./tests/guess_game"),
                    "project_path" => json!("./tests"),
                    "project_name" => json!("test"),
                    "script_name" => json!("noop"),
                    "new_name" => json!("renamed_main"),
                    "comment" => json!("integration comment"),
                    "query" => json!("main"),
                    "symbol_type" => json!("Function"),
                    _ => json!("main"),
                },
            };

            map.insert(name.clone(), value);
        }

        Value::Object(map)
    }

    #[tokio::test]
    async fn resolve_port_rejects_out_of_range_value() {
        let args = json!({ "port": 70000 });
        assert_eq!(resolve_port(&args), None);
    }

    #[test]
    fn resolves_ghidra_alias_tools() {
        let mappings = [
            ("ghidra_check_connection", "ping"),
            ("ghidra_get_metadata", "program_info"),
            ("ghidra_list_functions_enhanced", "list_functions"),
            ("ghidra_decompile_function", "decompile"),
            ("ghidra_force_decompile", "decompile"),
            ("ghidra_program_info", "program_info"),
            ("ghidra_list_functions", "list_functions"),
        ];

        for (tool_name, expected_command) in mappings {
            assert_eq!(
                bridge_alias_for_tool(tool_name).as_deref(),
                Some(expected_command),
                "tool {tool_name} should map to {expected_command}"
            );
        }
    }

    #[test]
    fn unknown_tool_has_no_alias() {
        assert!(bridge_alias_for_tool("not_ghidra_tool").is_none());
    }

    #[test]
    fn bridge_passthrough_strips_port_arg() {
        let args = json!({
            "port": 12799,
            "function": "main",
            "count": 3,
        });
        let stripped = strip_reserved_bridge_args(&args);
        assert!(!stripped.get("port").is_some());
        assert_eq!(stripped["function"], "main");
        assert_eq!(stripped["count"], 3);
    }

    #[tokio::test]
    async fn get_version_tool_is_local() {
        let resp = handle_tool_call("ghidra_get_version", json!({}), json!(42)).await;
        assert!(
            resp.get("result").is_some(),
            "expected result for ghidra_get_version"
        );
        assert!(resp.get("error").is_none());
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("tool_version"),
            "version response should include tool_version"
        );
    }

    #[tokio::test]
    async fn all_declared_tools_return_dispatch_results() {
        let tools_list = tools::build_tool_list();
        let tools_list = tools_list
            .as_array()
            .expect("tools list should be an array");

        let mut seen = HashSet::new();
        for (index, tool) in tools_list.iter().enumerate() {
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .expect("tool should have a name");
            assert!(
                seen.insert(name.to_string()),
                "duplicate tool name found in build_tool_list: {name}"
            );

            let args = sample_args_for_tool(tool);
            let response = handle_tool_call(name, args, json!(index as u64)).await;
            assert!(
                response.get("result").is_some() || response.get("error").is_some(),
                "tool '{name}' should return a valid MCP response"
            );
            assert_eq!(response.get("id"), Some(&json!(index as u64)));
            assert_eq!(response.get("jsonrpc").and_then(Value::as_str), Some("2.0"));
        }
    }
}
