use serde_json::{Value, json};
use std::collections::HashSet;
use std::env;
use std::path::Path;

const MCP_ENDPOINTS_ENV: &str = "GHIDRA_MCP_ENDPOINTS_PATH";

const MCP_ENDPOINT_CANDIDATES: &[&str] = &[
    "/tmp/ghidra-mcp-remote/tests/endpoints.json",
    "tests/endpoints.json",
];

const MCP_LEGACY_SUPPORTED_COMMANDS: &[&str] = &[
    "ping",
    "program_info",
    "list_functions",
    "function_at",
    "function_containing",
    "get_function_signature",
    "callers",
    "callees",
    "decompile",
    "instructions_for_function",
    "instruction_at",
    "memory_blocks",
    "data_at",
    "list_data_types",
    "symbols",
    "find_symbols",
    "get_xrefs",
    "references_to",
    "references_from",
    "search_strings",
    "call_graph",
    "control_flow_graph",
    "list_imports",
    "list_exports",
    "rename_function",
    "set_comment",
    "set_plate_comment",
    "shutdown",
];

pub fn build_tool_list() -> Value {
    build_tool_list_internal(false)
}

pub fn build_legacy_tool_list() -> Value {
    build_tool_list_internal(true)
}

fn build_tool_list_internal(limit_to_supported_legacy: bool) -> Value {
    let mut tools: Vec<Value> = vec![
        tool(
            "ghidra_ask_bridge",
            "[Raw] Send a raw JSON command to a running Ghidra bridge adapter.",
            &[
                prop("port", "number", "Bridge TCP port"),
                prop("command", "string", "Bridge command name"),
                prop("args", "object", "JSON arguments"),
            ],
            &["command"],
        ),
        tool(
            "ghidra_check_connection",
            "[Query] Verify bridge connectivity.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_get_metadata",
            "[Query] Get metadata and program details.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_get_version",
            "[Query] Get MCP server version.",
            &[],
            &[],
        ),
        tool(
            "ghidra_list_functions_enhanced",
            "[Query] Enhanced function list endpoint alias.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_decompile_function",
            "[Query] Alias of ghidra_decompile.",
            &[port(), function()],
            &["function"],
        ),
        tool(
            "ghidra_force_decompile",
            "[Query] Alias of ghidra_decompile (fresh decode request).",
            &[port(), function()],
            &["function"],
        ),
        tool(
            "ghidra_program_info",
            "[Query] Get metadata about the loaded program.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_list_functions",
            "[Query] List functions with names and entry-point addresses.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_decompile",
            "[Query] Decompile a function by name.",
            &[port(), function()],
            &["function"],
        ),
        tool(
            "ghidra_function_at",
            "[Query] Find the function at a specific address.",
            &[port(), address()],
            &["address"],
        ),
        tool(
            "ghidra_function_containing",
            "[Query] Find the function containing an address.",
            &[port(), address()],
            &["address"],
        ),
        tool(
            "ghidra_get_function_signature",
            "[Query] Get a function signature and parameter list.",
            &[port(), function(), address()],
            &[],
        ),
        tool(
            "ghidra_instructions_for_function",
            "[Query] Alias of ghidra_instructions.",
            &[port(), function()],
            &["function"],
        ),
        tool(
            "ghidra_callers",
            "[Query] Get functions that call the specified function.",
            &[port(), function()],
            &["function"],
        ),
        tool(
            "ghidra_callees",
            "[Query] Get functions called by the specified function.",
            &[port(), function()],
            &["function"],
        ),
        tool(
            "ghidra_instructions",
            "[Query] Get disassembled instructions for a function.",
            &[port(), function()],
            &["function"],
        ),
        tool(
            "ghidra_instruction_at",
            "[Query] Decode one instruction at an address.",
            &[port(), address()],
            &["address"],
        ),
        tool(
            "ghidra_memory_blocks",
            "[Query] List memory blocks/sections.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_symbols",
            "[Query] List or search symbols.",
            &[
                port(),
                prop("symbol_type", "string", "Optional symbol type filter"),
                prop("query", "string", "Optional symbol search pattern"),
            ],
            &[],
        ),
        tool(
            "ghidra_find_symbols",
            "[Query] Search symbols by name.",
            &[port(), prop("query", "string", "Search query string")],
            &["query"],
        ),
        tool(
            "ghidra_get_xrefs",
            "[Query] Backward alias of references_to.",
            &[port(), function(), address()],
            &[],
        ),
        tool(
            "ghidra_references_to",
            "[Query] Get cross-references to an address.",
            &[port(), address()],
            &["address"],
        ),
        tool(
            "ghidra_references_from",
            "[Query] Get cross-references from an address.",
            &[port(), address()],
            &["address"],
        ),
        tool(
            "ghidra_search_strings",
            "[Query] Search strings in the binary.",
            &[
                port(),
                prop("query", "string", "Search string; empty lists all"),
            ],
            &[],
        ),
        tool(
            "ghidra_call_graph",
            "[Graph] Get the call graph.",
            &[port(), prop("depth", "number", "Optional maximum depth")],
            &[],
        ),
        tool(
            "ghidra_control_flow_graph",
            "[Graph] Get CFG for a function.",
            &[port(), function()],
            &["function"],
        ),
        tool(
            "ghidra_set_plate_comment",
            "[Write] Set a plate/function comment.",
            &[
                port(),
                function(),
                prop("comment", "string", "Plate comment text"),
            ],
            &["function", "comment"],
        ),
        tool(
            "ghidra_data_at",
            "[Query] Get defined data metadata at an address.",
            &[port(), address()],
            &["address"],
        ),
        tool(
            "ghidra_imports",
            "[Query] List imported symbols/functions.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_exports",
            "[Query] List exported symbols/functions.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_data_types",
            "[Query] List known data types.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_list_data_types",
            "[Query] Alias of ghidra_data_types.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_list_imports",
            "[Query] Alias of ghidra_imports.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_list_exports",
            "[Query] Alias of ghidra_exports.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_ping",
            "[Query] Verify bridge connectivity.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_shutdown",
            "[Write] Stop the connected Ghidra bridge.",
            &[port()],
            &[],
        ),
        tool(
            "ghidra_rename_function",
            "[Write] Rename a function.",
            &[
                port(),
                function(),
                prop("new_name", "string", "New function name"),
            ],
            &["function", "new_name"],
        ),
        tool(
            "ghidra_set_comment",
            "[Write] Set an inline comment at an address.",
            &[port(), address(), prop("comment", "string", "Comment text")],
            &["address", "comment"],
        ),
        tool(
            "ghidra_import_and_analyze",
            "[Headless] Import a binary into a Ghidra project and analyze it.",
            &[
                prop("binary_path", "string", "Path to the binary file"),
                prop("project_path", "string", "Ghidra project directory"),
                prop("project_name", "string", "Ghidra project name"),
            ],
            &["binary_path", "project_path", "project_name"],
        ),
        tool(
            "ghidra_run_script",
            "[Headless] Run a Ghidra script on an existing project.",
            &[
                prop("project_path", "string", "Ghidra project directory"),
                prop("project_name", "string", "Ghidra project name"),
                prop("script_name", "string", "Ghidra script name"),
            ],
            &["project_path", "project_name", "script_name"],
        ),
    ];

    let mut existing = HashSet::new();
    for tool in &tools {
        if let Some(name) = tool.get("name").and_then(|v| v.as_str()) {
            existing.insert(name.to_string());
        }
    }

    for upstream_tool in load_upstream_tools(limit_to_supported_legacy) {
        let tool_name = upstream_tool
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string);

        if let Some(name) = tool_name {
            if !existing.contains(&name) {
                existing.insert(name);
                tools.push(upstream_tool);
            }
        }
    }

    Value::Array(tools)
}

fn load_upstream_tools(limit_to_supported_legacy: bool) -> Vec<Value> {
    let mut loaded: Vec<Value> = Vec::new();
    let supported: HashSet<&str> = MCP_LEGACY_SUPPORTED_COMMANDS.iter().copied().collect();

    let candidates: Vec<String> = env::var(MCP_ENDPOINTS_ENV)
        .map(|env_value| vec![env_value])
        .unwrap_or_else(|_| {
            MCP_ENDPOINT_CANDIDATES
                .iter()
                .map(|path| (*path).to_string())
                .collect()
        });

    for candidate in candidates {
        let path = Path::new(&candidate);
        if !path.exists() {
            continue;
        }
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(_) => continue,
        };
        let value: Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(endpoints) = value.get("endpoints").and_then(Value::as_array) else {
            continue;
        };

        for entry in endpoints {
            let Some(raw_path) = entry.get("path").and_then(Value::as_str) else {
                continue;
            };
            if raw_path.is_empty() {
                continue;
            }
            let tool_name = format!("ghidra_{}", raw_path.trim_matches('/').replace('/', "_"));
            if tool_name == "ghidra_" {
                continue;
            }

            if limit_to_supported_legacy
                && !supported.contains(raw_path.trim_matches('/').replace('/', "_").as_str())
            {
                continue;
            }

            let mut required: Vec<&str> = Vec::new();
            let mut properties = Vec::new();
            if let Some(params) = entry.get("params").and_then(Value::as_array) {
                for param in params {
                    let Some(param_name) = param.as_str() else {
                        continue;
                    };
                    if required.is_empty() || !required.contains(&param_name) {
                        required.push(param_name);
                    }
                    properties.push(prop(
                        param_name,
                        if param_name == "port" {
                            "number"
                        } else {
                            "string"
                        },
                        if param_name == "port" {
                            "Bridge TCP port"
                        } else {
                            "Upstream ghidra-mcp argument"
                        },
                    ));
                }
            }
            let description = entry
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("");
            let description = if description.is_empty() {
                "Proxy to ghidra-mcp endpoint."
            } else {
                description
            };
            loaded.push(tool(&tool_name, description, &properties, &required));
        }

        if !loaded.is_empty() {
            return loaded;
        }
    }

    loaded
}

fn port() -> Value {
    prop("port", "number", "Bridge TCP port")
}

fn function() -> Value {
    prop("function", "string", "Function name")
}

fn address() -> Value {
    prop("address", "string", "Hex address")
}

fn prop(name: &str, kind: &str, description: &str) -> Value {
    json!({
        "name": name,
        "schema": {
            "type": kind,
            "description": description,
        }
    })
}

fn tool(name: &str, description: &str, properties: &[Value], required: &[&str]) -> Value {
    let mut props = serde_json::Map::new();
    for property in properties {
        if let Some(name) = property.get("name").and_then(|value| value.as_str()) {
            props.insert(
                name.to_string(),
                property
                    .get("schema")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            );
        }
    }

    json!({
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": props,
            "required": required,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_expected_core_tools() {
        let tools = build_tool_list();
        let legacy_tools = build_legacy_tool_list();
        let names: Vec<&str> = tools
            .as_array()
            .expect("tool list")
            .iter()
            .filter_map(|tool| tool.get("name").and_then(|name| name.as_str()))
            .collect();

        assert!(names.contains(&"ghidra_ask_bridge"));
        assert!(names.contains(&"ghidra_check_connection"));
        assert!(names.contains(&"ghidra_get_version"));
        assert!(names.contains(&"ghidra_get_metadata"));
        assert!(names.contains(&"ghidra_list_functions_enhanced"));
        assert!(names.contains(&"ghidra_decompile"));
        assert!(names.contains(&"ghidra_import_and_analyze"));
        assert!(names.contains(&"ghidra_function_containing"));
        assert!(names.contains(&"ghidra_get_function_signature"));
        assert!(names.contains(&"ghidra_data_at"));
        assert!(names.contains(&"ghidra_set_plate_comment"));
        assert!(names.contains(&"ghidra_ping"));
        assert!(names.contains(&"ghidra_find_symbols"));
        if std::path::Path::new(MCP_ENDPOINT_CANDIDATES[0]).exists()
            || std::env::var(MCP_ENDPOINTS_ENV).is_ok()
            || std::path::Path::new(MCP_ENDPOINT_CANDIDATES[1]).exists()
        {
            assert!(names.contains(&"ghidra_add_function_tag"));
            assert!(names.contains(&"ghidra_analyze_call_graph"));
        }

        let legacy_names: Vec<&str> = legacy_tools
            .as_array()
            .expect("legacy tool list")
            .iter()
            .filter_map(|tool| tool.get("name").and_then(|name| name.as_str()))
            .collect();
        assert!(legacy_names.len() < names.len());

        if std::path::Path::new(MCP_ENDPOINT_CANDIDATES[0]).exists()
            || std::env::var(MCP_ENDPOINTS_ENV).is_ok()
            || std::path::Path::new(MCP_ENDPOINT_CANDIDATES[1]).exists()
        {
            assert!(!legacy_names.contains(&"ghidra_add_function_tag"));
            assert!(!legacy_names.contains(&"ghidra_analyze_call_graph"));
        }
    }
}
