//! GDB adapters for debugger-oriented metadata.
//!
//! These adapters keep GDB behind versioned parsers. `GdbAdapter` uses
//! non-interactive batch commands, while `GdbMiAdapter` drives GDB through
//! the MI interpreter so later breakpoint/register/stack workflows can use
//! the same protocol surface.

use crate::adapter::ToolAdapter;
use crate::adapter::process::{ToolProcessLimits, run_tool_process};
use crate::adapter::schema::{
    AdapterCapability, OutputFormat, Section, ToolCommand, ToolEvent, ToolEventKind,
};
use crate::error::{Result, RevisorError};
use serde::Serialize;
use std::time::Duration;

/// Parser version string emitted in capability metadata.
pub const PARSER_VERSION: &str = "gdb-batch-v1";
pub const MI_PARSER_VERSION: &str = "gdb-mi-v1";

#[derive(Debug, Clone, Serialize)]
struct GdbInfo {
    entry: Option<String>,
    file_type: Option<String>,
}

/// Read-only GDB adapter.
pub struct GdbAdapter;
pub struct GdbMiAdapter;

impl ToolAdapter for GdbAdapter {
    fn name(&self) -> &'static str {
        "gdb"
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn capabilities(&self) -> Vec<AdapterCapability> {
        vec![AdapterCapability {
            name: "debugger_metadata".to_string(),
            formats: vec![OutputFormat::VersionedText],
            read_only: true,
            parser_version: Some(PARSER_VERSION.to_string()),
        }]
    }

    fn command(&self, target: &str) -> Option<ToolCommand> {
        let program = std::env::var("GDB").unwrap_or_else(|_| "gdb".to_string());
        Some(ToolCommand {
            program,
            args: vec![
                "--batch".to_string(),
                "--nx".to_string(),
                "--quiet".to_string(),
                "-iex".to_string(),
                "set debuginfod enabled off".to_string(),
                "-ex".to_string(),
                format!("file {target}"),
                "-ex".to_string(),
                "info files".to_string(),
                "-ex".to_string(),
                "info functions".to_string(),
            ],
            working_dir: None,
            env: vec![("DEBUGINFOD_URLS".to_string(), "".to_string())],
            stdin: None,
        })
    }

    fn run(&self, target: &str) -> Result<Vec<ToolEvent>> {
        let command = self
            .command(target)
            .ok_or_else(|| RevisorError::Other("failed to build gdb command".to_string()))?;
        let process = run_tool_process(
            self.name(),
            &command,
            &ToolProcessLimits {
                timeout: Duration::from_secs(30),
                max_output_bytes: 2 * 1024 * 1024,
            },
        )?;

        let stdout = process
            .events
            .iter()
            .filter(|event| event.kind == ToolEventKind::RawStdout)
            .filter_map(|event| event.raw.as_deref())
            .collect::<Vec<_>>()
            .join("\n");

        let mut events = parse_gdb_batch(&stdout);
        if events.is_empty() {
            events.extend(process.events);
        }
        Ok(events)
    }
}

impl ToolAdapter for GdbMiAdapter {
    fn name(&self) -> &'static str {
        "gdb-mi"
    }

    fn parser_version(&self) -> &'static str {
        MI_PARSER_VERSION
    }

    fn capabilities(&self) -> Vec<AdapterCapability> {
        vec![AdapterCapability {
            name: "debugger_mi_metadata".to_string(),
            formats: vec![OutputFormat::VersionedText],
            read_only: true,
            parser_version: Some(MI_PARSER_VERSION.to_string()),
        }]
    }

    fn command(&self, target: &str) -> Option<ToolCommand> {
        let program = std::env::var("GDB").unwrap_or_else(|_| "gdb".to_string());
        Some(ToolCommand {
            program,
            args: vec![
                "--interpreter=mi3".to_string(),
                "--nx".to_string(),
                "--quiet".to_string(),
                "-iex".to_string(),
                "set debuginfod enabled off".to_string(),
            ],
            working_dir: None,
            env: vec![("DEBUGINFOD_URLS".to_string(), "".to_string())],
            stdin: Some(format!(
                "1-file-exec-and-symbols {target}\n2-interpreter-exec console \"info files\"\n3-interpreter-exec console \"info functions\"\n4-gdb-exit\n"
            )),
        })
    }

    fn run(&self, target: &str) -> Result<Vec<ToolEvent>> {
        let command = self
            .command(target)
            .ok_or_else(|| RevisorError::Other("failed to build gdb/mi command".to_string()))?;
        let process = run_tool_process(
            self.name(),
            &command,
            &ToolProcessLimits {
                timeout: Duration::from_secs(30),
                max_output_bytes: 2 * 1024 * 1024,
            },
        )?;

        let stdout = process
            .events
            .iter()
            .filter(|event| event.kind == ToolEventKind::RawStdout)
            .filter_map(|event| event.raw.as_deref())
            .collect::<Vec<_>>()
            .join("\n");

        let mut events = parse_gdb_mi(&stdout);
        if events.is_empty() {
            events.extend(process.events);
        }
        Ok(events)
    }
}

/// Parse `gdb --batch -ex "info files" -ex "info functions"` output.
pub fn parse_gdb_batch(text: &str) -> Vec<ToolEvent> {
    let mut events = Vec::new();
    let mut entry = None;
    let mut file_type = None;

    for line in text.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("Entry point: ") {
            entry = Some(value.trim().to_string());
            continue;
        }

        if let Some((_, rest)) = line.split_once("file type ") {
            file_type = Some(rest.trim_end_matches('.').to_string());
            continue;
        }

        if let Some(section) = parse_section_line(line) {
            events.push(section_event(section));
            continue;
        }

        if let Some(event) = parse_function_line(line) {
            events.push(event);
        }
    }

    if entry.is_some() || file_type.is_some() {
        events.insert(0, binary_info_event(GdbInfo { entry, file_type }));
    }

    events
}

pub fn parse_gdb_mi(text: &str) -> Vec<ToolEvent> {
    let console = extract_mi_console_stream(text);
    let mut events = parse_gdb_batch(&console)
        .into_iter()
        .map(|mut event| {
            event.adapter = "gdb-mi".to_string();
            if event.data.is_object()
                && let Some(object) = event.data.as_object_mut()
            {
                object.insert("protocol".to_string(), serde_json::json!("mi3"));
            }
            event
        })
        .collect::<Vec<_>>();

    for line in text.lines().map(str::trim) {
        if line.contains("^error") {
            events.push(ToolEvent::error("gdb-mi", line));
        } else if line.contains("^done") {
            events.push(ToolEvent::status("gdb-mi", line));
        }
    }

    events
}

fn extract_mi_console_stream(text: &str) -> String {
    let mut output = String::new();
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("~\"")
            && let Some(quoted) = rest.strip_suffix('"')
        {
            output.push_str(&decode_mi_c_string(quoted));
        }
    }
    output
}

fn decode_mi_c_string(value: &str) -> String {
    let mut decoded = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }

        match chars.next() {
            Some('n') => decoded.push('\n'),
            Some('t') => decoded.push('\t'),
            Some('r') => decoded.push('\r'),
            Some('"') => decoded.push('"'),
            Some('\\') => decoded.push('\\'),
            Some(other) => {
                decoded.push('\\');
                decoded.push(other);
            }
            None => decoded.push('\\'),
        }
    }
    decoded
}

fn parse_section_line(line: &str) -> Option<Section> {
    let (range, name) = line.split_once(" is ")?;
    let (start, end) = range.split_once(" - ")?;
    let start = start.trim();
    let end = end.trim();
    let start_num = parse_hex(start)?;
    let end_num = parse_hex(end)?;
    let size = end_num.checked_sub(start_num)?;

    Some(Section {
        name: name.trim().to_string(),
        address: Some(start.to_string()),
        size: Some(size),
        readable: None,
        writable: None,
        executable: None,
        extra: serde_json::json!({ "end": end }),
    })
}

fn parse_function_line(line: &str) -> Option<ToolEvent> {
    let mut parts = line.split_whitespace();
    let address = parts.next()?;
    if !address.starts_with("0x") || parse_hex(address).is_none() {
        return None;
    }
    let name = parts.next()?.to_string();

    Some(ToolEvent {
        adapter: "gdb".to_string(),
        kind: ToolEventKind::Function,
        message: format!("{address} {name}"),
        address: Some(address.to_string()),
        raw: None,
        data: serde_json::json!({
            "name": name,
            "address": address,
            "source": "gdb info functions",
        }),
    })
}

fn binary_info_event(info: GdbInfo) -> ToolEvent {
    let entry = info.entry.clone();
    ToolEvent {
        adapter: "gdb".to_string(),
        kind: ToolEventKind::BinaryInfo,
        message: format!(
            "gdb file type {} entry {}",
            info.file_type
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            entry.clone().unwrap_or_else(|| "unknown".to_string())
        ),
        address: entry,
        raw: None,
        data: serde_json::to_value(info).unwrap_or(serde_json::Value::Null),
    }
}

fn section_event(section: Section) -> ToolEvent {
    ToolEvent {
        adapter: "gdb".to_string(),
        kind: ToolEventKind::Section,
        message: format!(
            "{} {} size {}",
            section
                .address
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            section.name,
            section
                .size
                .map(|size| size.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        address: section.address.clone(),
        raw: None,
        data: serde_json::to_value(section).unwrap_or(serde_json::Value::Null),
    }
}

fn parse_hex(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::ToolAdapter;

    const SAMPLE: &str = r#"
Symbols from "/tmp/crackme".
Local exec file:
        `/tmp/crackme', file type elf64-x86-64.
        Entry point: 0x4003c0
        0x00000000004003c0 - 0x0000000000400701 is .text
All defined functions:

Non-debugging symbols:
0x00000000004003c0  _start
0x0000000000400664  main
"#;

    #[test]
    fn gdb_adapter_reports_capabilities() {
        let adapter = GdbAdapter;
        let capabilities = adapter.capabilities();

        assert_eq!(adapter.name(), "gdb");
        assert_eq!(adapter.parser_version(), PARSER_VERSION);
        assert_eq!(capabilities.len(), 1);
        assert!(capabilities[0].read_only);
        assert_eq!(capabilities[0].name, "debugger_metadata");
    }

    #[test]
    fn gdb_mi_adapter_reports_capabilities() {
        let adapter = GdbMiAdapter;
        let capabilities = adapter.capabilities();

        assert_eq!(adapter.name(), "gdb-mi");
        assert_eq!(adapter.parser_version(), MI_PARSER_VERSION);
        assert_eq!(capabilities.len(), 1);
        assert!(capabilities[0].read_only);
        assert_eq!(capabilities[0].name, "debugger_mi_metadata");
    }

    #[test]
    fn parses_gdb_batch_output() {
        let events = parse_gdb_batch(SAMPLE);

        assert!(
            events
                .iter()
                .any(|event| event.kind == ToolEventKind::BinaryInfo)
        );
        assert!(
            events
                .iter()
                .any(|event| event.kind == ToolEventKind::Section)
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == ToolEventKind::Function)
                .count(),
            2
        );
    }

    #[test]
    fn parses_gdb_mi_console_output() {
        let sample = r#"
=thread-group-added,id="i1"
1^done
~"Local exec file:\n"
~"\t`/tmp/crackme', file type elf64-x86-64.\n"
~"\tEntry point: 0x4003c0\n"
~"\t0x00000000004003c0 - 0x0000000000400701 is .text\n"
2^done
~"All defined functions:\n"
~"0x0000000000400664  main\n"
3^done
"#;
        let events = parse_gdb_mi(sample);

        assert!(
            events
                .iter()
                .any(|event| event.adapter == "gdb-mi" && event.kind == ToolEventKind::BinaryInfo)
        );
        assert!(
            events
                .iter()
                .any(|event| event.adapter == "gdb-mi" && event.kind == ToolEventKind::Function)
        );
        assert!(
            events
                .iter()
                .any(|event| event.adapter == "gdb-mi" && event.kind == ToolEventKind::Status)
        );
    }

    #[test]
    fn parses_section_line() {
        let section = parse_section_line("0x00000000004003c0 - 0x0000000000400701 is .text")
            .expect("section");

        assert_eq!(section.name, ".text");
        assert_eq!(section.address.as_deref(), Some("0x00000000004003c0"));
        assert_eq!(section.size, Some(0x341));
    }

    #[test]
    fn parses_function_line() {
        let event = parse_function_line("0x0000000000400664  main").expect("function");

        assert_eq!(event.kind, ToolEventKind::Function);
        assert_eq!(event.address.as_deref(), Some("0x0000000000400664"));
        assert_eq!(
            event.data.get("name").and_then(|value| value.as_str()),
            Some("main")
        );
    }
}
