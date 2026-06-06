use crate::adapter::schema::{AdapterCapability, OutputFormat, ToolEvent, ToolEventKind};

pub const ADAPTER_NAME: &str = "ghidra";
pub const PARSER_VERSION: &str = "bridge-json-v1";

pub fn capabilities() -> Vec<AdapterCapability> {
    vec![
        AdapterCapability {
            name: "decompile".to_string(),
            formats: vec![OutputFormat::Json],
            read_only: true,
            parser_version: Some(PARSER_VERSION.to_string()),
        },
        AdapterCapability {
            name: "symbols_xrefs_strings".to_string(),
            formats: vec![OutputFormat::Json],
            read_only: true,
            parser_version: Some(PARSER_VERSION.to_string()),
        },
    ]
}

pub fn bridge_response_to_events(command: &str, value: &serde_json::Value) -> Vec<ToolEvent> {
    let mut events = Vec::new();
    collect_array(
        command,
        value,
        "functions",
        ToolEventKind::Function,
        &mut events,
    );
    collect_array(
        command,
        value,
        "instructions",
        ToolEventKind::Instruction,
        &mut events,
    );
    collect_array(
        command,
        value,
        "references",
        ToolEventKind::Xref,
        &mut events,
    );
    collect_array(
        command,
        value,
        "strings",
        ToolEventKind::StringHit,
        &mut events,
    );
    collect_array(
        command,
        value,
        "symbols",
        ToolEventKind::Symbol,
        &mut events,
    );
    collect_array(
        command,
        value,
        "blocks",
        ToolEventKind::Section,
        &mut events,
    );
    collect_array(
        command,
        value,
        "imports",
        ToolEventKind::Symbol,
        &mut events,
    );
    collect_array(
        command,
        value,
        "exports",
        ToolEventKind::Symbol,
        &mut events,
    );

    if let Some(c_code) = value.get("c_code").and_then(|v| v.as_str()) {
        events.push(ToolEvent {
            adapter: ADAPTER_NAME.to_string(),
            kind: ToolEventKind::Decompile,
            message: format!(
                "decompiled {} ({} bytes)",
                value
                    .get("function_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(command),
                c_code.len()
            ),
            address: value
                .get("address")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            raw: Some(c_code.to_string()),
            data: value.clone(),
        });
    }

    if command == "program_info" || value.get("language_id").is_some() {
        events.push(ToolEvent {
            adapter: ADAPTER_NAME.to_string(),
            kind: ToolEventKind::BinaryInfo,
            message: format_program_info(value),
            address: value
                .get("image_base")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            raw: Some(value.to_string()),
            data: value.clone(),
        });
    }

    if events.is_empty() {
        events.push(ToolEvent {
            adapter: ADAPTER_NAME.to_string(),
            kind: ToolEventKind::RawStdout,
            message: format!("{} returned JSON payload", command),
            address: None,
            raw: Some(value.to_string()),
            data: value.clone(),
        });
    }

    events
}

fn collect_array(
    command: &str,
    value: &serde_json::Value,
    field: &str,
    kind: ToolEventKind,
    events: &mut Vec<ToolEvent>,
) {
    let Some(items) = value.get(field).and_then(|v| v.as_array()) else {
        return;
    };

    for item in items {
        events.push(ToolEvent {
            adapter: ADAPTER_NAME.to_string(),
            kind: kind.clone(),
            message: summarize_item(command, field, item),
            address: item
                .get("address")
                .or_else(|| item.get("from_address"))
                .or_else(|| item.get("to_address"))
                .or_else(|| item.get("start"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            raw: Some(item.to_string()),
            data: item.clone(),
        });
    }
}

fn summarize_item(command: &str, field: &str, item: &serde_json::Value) -> String {
    if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
        return format!(
            "{} {} @ {}",
            field.trim_end_matches('s'),
            name,
            item.get("address")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
    }

    if let Some(value) = item.get("value").and_then(|v| v.as_str()) {
        return format!(
            "string @ {}: {}",
            item.get("address")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            value
        );
    }

    if let Some(mnemonic) = item.get("mnemonic").and_then(|v| v.as_str()) {
        return format!(
            "instruction @ {}: {} {}",
            item.get("address")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            mnemonic,
            item.get("operands").and_then(|v| v.as_str()).unwrap_or("")
        );
    }

    if let Some(from) = item.get("from_address").and_then(|v| v.as_str()) {
        return format!(
            "xref {} -> {}",
            from,
            item.get("to_address")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
    }

    format!("{} item from {}", field, command)
}

fn format_program_info(value: &serde_json::Value) -> String {
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("program");
    let lang = value
        .get("language_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown language");
    format!("program {} ({})", name, lang)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_functions_to_events() {
        let value = json!({
            "functions": [
                { "name": "main", "address": "0x1000" }
            ]
        });

        let events = bridge_response_to_events("list_functions", &value);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, ToolEventKind::Function);
        assert_eq!(events[0].address.as_deref(), Some("0x1000"));
    }

    #[test]
    fn maps_decompile_to_event_with_raw_code() {
        let value = json!({
            "function_name": "main",
            "address": "0x1000",
            "c_code": "int main() { return 0; }"
        });

        let events = bridge_response_to_events("decompile", &value);
        assert_eq!(events[0].kind, ToolEventKind::Decompile);
        assert!(events[0].raw.as_ref().unwrap().contains("return 0"));
    }

    #[test]
    fn falls_back_to_raw_event() {
        let value = json!({ "status": "ok" });
        let events = bridge_response_to_events("ping", &value);
        assert_eq!(events[0].kind, ToolEventKind::RawStdout);
    }
}
