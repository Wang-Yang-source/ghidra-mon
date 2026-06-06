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
use std::io::{self, Write};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Run the MCP server, reading JSON-RPC 2.0 requests from stdin and writing responses to stdout.
/// Uses async tokio stdin to avoid blocking the runtime.
pub async fn run_mcp_server() {
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let req_val: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let method = req_val["method"].as_str().unwrap_or("");
        let id = req_val["id"].clone();

        let mut response = json!({ "jsonrpc": "2.0", "id": id });

        match method {
            "initialize" => {
                response["result"] = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "revisor", "version": "0.5.0" }
                });
            }
            "tools/list" => {
                response["result"] = json!({ "tools": tools::build_tool_list() });
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
        "ghidra_memory_blocks" => {
            send_bridge_command(&args, "memory_blocks", None, &mut response).await;
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
        "ghidra_exports" => {
            send_bridge_command(&args, "list_exports", None, &mut response).await;
        }
        "ghidra_data_types" => {
            send_bridge_command(&args, "list_data_types", None, &mut response).await;
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
            response["error"] =
                json!({ "code": -32601, "message": format!("Unknown tool: {}", name) });
        }
    }

    response
}

// ─── Bridge Communication Helpers ─────────────────────────────────────────────

/// Resolve the bridge port: use explicit port if provided, otherwise read from bridge.pid file.
fn resolve_port(args: &Value) -> Option<u16> {
    // Explicit port takes priority
    if let Some(port) = args.get("port").and_then(|v| v.as_u64())
        && port > 0
    {
        return Some(port as u16);
    }
    // Fall back to auto-discovery from bridge.pid
    bridge::read_bridge_port()
}

/// Send a raw command to the bridge (the ghidra_ask_bridge tool).
async fn handle_bridge_raw(args: &Value, response: &mut Value) {
    let port = match resolve_port(args) {
        Some(p) => p,
        None => {
            response["error"] = json!({ "code": -32000, "message": "No bridge port specified and no running bridge found. Start a bridge first with 'revisor bridge' or pass a 'port' parameter." });
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
            response["result"] = json!({
                "content": [{ "type": "text", "text": line }]
            });
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
            response["error"] = json!({ "code": -32602, "message": "No bridge port available. Start a bridge with 'revisor bridge' or pass 'port'." });
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
            response["result"] = json!({
                "content": [{ "type": "text", "text": line }]
            });
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
