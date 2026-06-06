use serde_json::{Value, json};

pub fn build_tool_list() -> Value {
    json!([
        tool(
            "ghidra_ask_bridge",
            "[Raw] Send a raw JSON command to a running Ghidra bridge adapter.",
            &[
                prop("port", "number", "Bridge TCP port"),
                prop("command", "string", "Bridge command name"),
                prop("args", "object", "JSON arguments")
            ],
            &["command"],
        ),
        tool(
            "ghidra_program_info",
            "[Query] Get metadata about the loaded program.",
            &[port()],
            &[]
        ),
        tool(
            "ghidra_list_functions",
            "[Query] List functions with names and entry-point addresses.",
            &[port()],
            &[]
        ),
        tool(
            "ghidra_decompile",
            "[Query] Decompile a function by name.",
            &[port(), function()],
            &["function"]
        ),
        tool(
            "ghidra_function_at",
            "[Query] Find the function at a specific address.",
            &[port(), address()],
            &["address"]
        ),
        tool(
            "ghidra_callers",
            "[Query] Get functions that call the specified function.",
            &[port(), function()],
            &["function"]
        ),
        tool(
            "ghidra_callees",
            "[Query] Get functions called by the specified function.",
            &[port(), function()],
            &["function"]
        ),
        tool(
            "ghidra_instructions",
            "[Query] Get disassembled instructions for a function.",
            &[port(), function()],
            &["function"]
        ),
        tool(
            "ghidra_memory_blocks",
            "[Query] List memory blocks/sections.",
            &[port()],
            &[]
        ),
        tool(
            "ghidra_symbols",
            "[Query] List or search symbols.",
            &[
                port(),
                prop("symbol_type", "string", "Optional symbol type filter"),
                prop("query", "string", "Optional symbol search pattern")
            ],
            &[],
        ),
        tool(
            "ghidra_references_to",
            "[Query] Get cross-references to an address.",
            &[port(), address()],
            &["address"]
        ),
        tool(
            "ghidra_references_from",
            "[Query] Get cross-references from an address.",
            &[port(), address()],
            &["address"]
        ),
        tool(
            "ghidra_search_strings",
            "[Query] Search strings in the binary.",
            &[
                port(),
                prop("query", "string", "Search string; empty lists all")
            ],
            &[]
        ),
        tool(
            "ghidra_call_graph",
            "[Graph] Get the call graph.",
            &[port(), prop("depth", "number", "Optional maximum depth")],
            &[]
        ),
        tool(
            "ghidra_control_flow_graph",
            "[Graph] Get CFG for a function.",
            &[port(), function()],
            &["function"]
        ),
        tool(
            "ghidra_imports",
            "[Query] List imported symbols/functions.",
            &[port()],
            &[]
        ),
        tool(
            "ghidra_exports",
            "[Query] List exported symbols/functions.",
            &[port()],
            &[]
        ),
        tool(
            "ghidra_data_types",
            "[Query] List known data types.",
            &[port()],
            &[]
        ),
        tool(
            "ghidra_rename_function",
            "[Write] Rename a function.",
            &[
                port(),
                function(),
                prop("new_name", "string", "New function name")
            ],
            &["function", "new_name"]
        ),
        tool(
            "ghidra_set_comment",
            "[Write] Set an inline comment at an address.",
            &[port(), address(), prop("comment", "string", "Comment text")],
            &["address", "comment"]
        ),
        tool(
            "ghidra_import_and_analyze",
            "[Headless] Import a binary into a Ghidra project and analyze it.",
            &[
                prop("binary_path", "string", "Path to the binary file"),
                prop("project_path", "string", "Ghidra project directory"),
                prop("project_name", "string", "Ghidra project name")
            ],
            &["binary_path", "project_path", "project_name"],
        ),
        tool(
            "ghidra_run_script",
            "[Headless] Run a Ghidra script on an existing project.",
            &[
                prop("project_path", "string", "Ghidra project directory"),
                prop("project_name", "string", "Ghidra project name"),
                prop("script_name", "string", "Ghidra script name")
            ],
            &["project_path", "project_name", "script_name"],
        ),
    ])
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
        let names: Vec<&str> = tools
            .as_array()
            .expect("tool list")
            .iter()
            .filter_map(|tool| tool.get("name").and_then(|name| name.as_str()))
            .collect();

        assert!(names.contains(&"ghidra_ask_bridge"));
        assert!(names.contains(&"ghidra_decompile"));
        assert!(names.contains(&"ghidra_import_and_analyze"));
    }
}
