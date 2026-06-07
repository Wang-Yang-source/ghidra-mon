use crate::adapter::ToolAdapter;
use crate::adapter::process::{ToolProcessLimits, run_tool_process};
use crate::adapter::schema::{
    AdapterCapability, OutputFormat, ToolCommand, ToolEvent, ToolEventKind,
};
use crate::error::{Result, RevisorError};
use std::time::Duration;

/// JSON parser version string emitted in capability metadata.
pub const PARSER_VERSION: &str = "rizin-json-v1";

/// Analysis action to perform via the external `rizin` binary.
///
/// Each variant maps to a Rizin JSON command (`ij`, `aflj`, `izzj`, etc.).
#[derive(Debug, Clone, Copy)]
pub enum RizinAction {
    Info,
    Functions,
    Strings,
    Sections,
    Imports,
    Disasm,
    Xrefs,
}

impl RizinAction {
    /// Parse a user-supplied action string (e.g. `"functions"`, `"disasm"`).
    ///
    /// Accepts abbreviations: `"funcs"` for functions, `"refs"` for xrefs.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "info" => Ok(Self::Info),
            "functions" | "funcs" => Ok(Self::Functions),
            "strings" => Ok(Self::Strings),
            "sections" => Ok(Self::Sections),
            "imports" => Ok(Self::Imports),
            "disasm" | "disassemble" => Ok(Self::Disasm),
            "xrefs" | "refs" => Ok(Self::Xrefs),
            other => Err(RevisorError::Other(format!(
                "unknown rizin action '{other}'. Use info, functions, strings, sections, imports, disasm, or xrefs"
            ))),
        }
    }

    fn command(self, query: Option<&str>) -> Result<String> {
        Ok(match self {
            Self::Info => "ij".to_string(),
            Self::Functions => "aaa;aflj".to_string(),
            Self::Strings => "izzj".to_string(),
            Self::Sections => "iSj".to_string(),
            Self::Imports => "iij".to_string(),
            Self::Disasm => {
                let target = query.ok_or_else(|| {
                    RevisorError::Other(
                        "rizin disasm requires --query <symbol|address>".to_string(),
                    )
                })?;
                format!("aaa;pdfj @ {target}")
            }
            Self::Xrefs => {
                let target = query.ok_or_else(|| {
                    RevisorError::Other("rizin xrefs requires --query <symbol|address>".to_string())
                })?;
                format!("aaa;axtj @ {target}")
            }
        })
    }
}

/// Rizin adapter that shells out to the `rizin` CLI.
///
/// Requires `rizin` on `$PATH` (or set the `RIZIN` env var).
/// Results are parsed from Rizin's JSON output and converted to
/// structured [`ToolEvent`]s.
pub struct RizinAdapter {
    pub action: RizinAction,
    pub query: Option<String>,
}

impl ToolAdapter for RizinAdapter {
    fn name(&self) -> &'static str {
        "rizin"
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn capabilities(&self) -> Vec<AdapterCapability> {
        vec![AdapterCapability {
            name: "static_analysis_json".to_string(),
            formats: vec![OutputFormat::Json],
            read_only: true,
            parser_version: Some(PARSER_VERSION.to_string()),
        }]
    }

    fn command(&self, target: &str) -> Option<ToolCommand> {
        let program = std::env::var("RIZIN").unwrap_or_else(|_| "rizin".to_string());
        let cmd = self.command_string().ok()?;
        Some(ToolCommand {
            program,
            args: vec!["-q0".to_string(), "-c".to_string(), cmd, target.to_string()],
            working_dir: None,
            env: Vec::new(),
            stdin: None,
        })
    }

    fn run(&self, target: &str) -> Result<Vec<ToolEvent>> {
        let command = self
            .command(target)
            .ok_or_else(|| RevisorError::Other("failed to build rizin command".to_string()))?;
        let process = run_tool_process(
            self.name(),
            &command,
            &ToolProcessLimits {
                timeout: Duration::from_secs(120),
                max_output_bytes: 8 * 1024 * 1024,
            },
        )?;

        let stdout = process
            .events
            .iter()
            .filter(|event| event.kind == ToolEventKind::RawStdout)
            .filter_map(|event| event.raw.as_deref())
            .collect::<Vec<_>>()
            .join("\n")
            .replace('\0', "");

        let mut events = parse_rizin_json(self.action, &stdout)?;
        if events.is_empty() {
            events.extend(process.events);
        }
        Ok(events)
    }
}

impl RizinAdapter {
    fn command_string(&self) -> Result<String> {
        self.action.command(self.query.as_deref())
    }
}

/// Parse raw Rizin JSON output into structured [`ToolEvent`]s.
///
/// The `action` determines the expected JSON shape (array of functions,
/// single info object, disassembly listing, etc.).
pub fn parse_rizin_json(action: RizinAction, text: &str) -> Result<Vec<ToolEvent>> {
    let cleaned = text.trim_matches(char::from(0)).trim();
    if cleaned.is_empty() {
        return Ok(vec![ToolEvent::status("rizin", "empty rizin JSON output")]);
    }

    let value: serde_json::Value = serde_json::from_str(cleaned)
        .map_err(|e| RevisorError::Other(format!("parse rizin JSON: {e}")))?;
    Ok(match action {
        RizinAction::Info => vec![event_from_info(value)],
        RizinAction::Functions => array_events(value, ToolEventKind::Function, summarize_function),
        RizinAction::Strings => array_events(value, ToolEventKind::StringHit, summarize_string),
        RizinAction::Sections => array_events(value, ToolEventKind::Section, summarize_section),
        RizinAction::Imports => array_events(value, ToolEventKind::Symbol, summarize_import),
        RizinAction::Disasm => instructions_from_pdfj(value),
        RizinAction::Xrefs => array_events(value, ToolEventKind::Xref, summarize_xref),
    })
}

fn array_events(
    value: serde_json::Value,
    kind: ToolEventKind,
    summarize: fn(&serde_json::Value) -> String,
) -> Vec<ToolEvent> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| event(kind.clone(), summarize(item), address(item), item.clone()))
                .collect()
        })
        .unwrap_or_else(|| {
            vec![ToolEvent::error(
                "rizin",
                "expected rizin JSON array for action",
            )]
        })
}

fn instructions_from_pdfj(value: serde_json::Value) -> Vec<ToolEvent> {
    let ops = value
        .get("ops")
        .and_then(|ops| ops.as_array())
        .cloned()
        .unwrap_or_default();
    ops.iter()
        .map(|op| {
            event(
                ToolEventKind::Instruction,
                format!(
                    "instruction @ {}: {}",
                    address(op).unwrap_or_else(|| "unknown".to_string()),
                    op.get("opcode").and_then(|v| v.as_str()).unwrap_or("")
                ),
                address(op),
                op.clone(),
            )
        })
        .collect()
}

fn event(
    kind: ToolEventKind,
    message: String,
    address: Option<String>,
    data: serde_json::Value,
) -> ToolEvent {
    ToolEvent {
        adapter: "rizin".to_string(),
        kind,
        message,
        address,
        raw: Some(data.to_string()),
        data,
    }
}

fn event_from_info(value: serde_json::Value) -> ToolEvent {
    let bin = value.get("bin").unwrap_or(&value);
    event(
        ToolEventKind::BinaryInfo,
        format!(
            "binary {} {}",
            bin.get("file")
                .or_else(|| bin.get("bintype"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            bin.get("arch").and_then(|v| v.as_str()).unwrap_or("")
        ),
        bin.get("baddr")
            .or_else(|| bin.get("binsz"))
            .map(value_to_address),
        value,
    )
}

fn summarize_function(item: &serde_json::Value) -> String {
    format!(
        "function {} @ {}",
        item.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown"),
        address(item).unwrap_or_else(|| "unknown".to_string())
    )
}

fn summarize_string(item: &serde_json::Value) -> String {
    format!(
        "string @ {}: {}",
        address(item).unwrap_or_else(|| "unknown".to_string()),
        item.get("string")
            .or_else(|| item.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    )
}

fn summarize_section(item: &serde_json::Value) -> String {
    format!(
        "section {} @ {}",
        item.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown"),
        address(item).unwrap_or_else(|| "unknown".to_string())
    )
}

fn summarize_import(item: &serde_json::Value) -> String {
    format!(
        "import {} @ {}",
        item.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown"),
        address(item).unwrap_or_else(|| "unknown".to_string())
    )
}

fn summarize_xref(item: &serde_json::Value) -> String {
    format!(
        "xref {} -> {}",
        item.get("from")
            .or_else(|| item.get("fromaddr"))
            .map(value_to_address)
            .unwrap_or_else(|| "unknown".to_string()),
        item.get("to")
            .or_else(|| item.get("addr"))
            .map(value_to_address)
            .unwrap_or_else(|| "unknown".to_string())
    )
}

fn address(item: &serde_json::Value) -> Option<String> {
    item.get("offset")
        .or_else(|| item.get("addr"))
        .or_else(|| item.get("vaddr"))
        .or_else(|| item.get("paddr"))
        .map(value_to_address)
}

fn value_to_address(value: &serde_json::Value) -> String {
    if let Some(n) = value.as_u64() {
        format!("0x{n:x}")
    } else if let Some(s) = value.as_str() {
        s.to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_function_list() {
        let events = parse_rizin_json(
            RizinAction::Functions,
            r#"[{"name":"main","offset":4198400}]"#,
        )
        .expect("parse");

        assert_eq!(events[0].kind, ToolEventKind::Function);
        assert_eq!(events[0].address.as_deref(), Some("0x401000"));
    }

    #[test]
    fn parses_strings() {
        let events = parse_rizin_json(
            RizinAction::Strings,
            r#"[{"vaddr":4199000,"string":"password"}]"#,
        )
        .expect("parse");

        assert_eq!(events[0].kind, ToolEventKind::StringHit);
        assert!(events[0].message.contains("password"));
    }

    #[test]
    fn builds_disasm_command_with_query() {
        let adapter = RizinAdapter {
            action: RizinAction::Disasm,
            query: Some("main".to_string()),
        };
        let command = adapter.command("tests/crackme").expect("command");

        assert_eq!(command.program, "rizin");
        assert!(command.args.contains(&"aaa;pdfj @ main".to_string()));
    }
}
