use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Ndjson,
    Xml,
    Sqlite,
    Protobuf,
    NativeRust,
    VersionedText,
    RawText,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterCapability {
    pub name: String,
    pub formats: Vec<OutputFormat>,
    pub read_only: bool,
    pub parser_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCommand {
    pub program: String,
    pub args: Vec<String>,
    pub working_dir: Option<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default)]
    pub stdin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolEventKind {
    RawStdout,
    RawStderr,
    Finding,
    Gadget,
    FirmwareEntry,
    BinaryInfo,
    Function,
    Instruction,
    Xref,
    StringHit,
    Symbol,
    Section,
    Decompile,
    Status,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolEvent {
    pub adapter: String,
    pub kind: ToolEventKind,
    pub message: String,
    pub address: Option<String>,
    pub raw: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl ToolEvent {
    pub fn status(adapter: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            adapter: adapter.into(),
            kind: ToolEventKind::Status,
            message: message.into(),
            address: None,
            raw: None,
            data: serde_json::Value::Null,
        }
    }

    pub fn raw_stdout(adapter: impl Into<String>, line: impl Into<String>) -> Self {
        let line = line.into();
        Self {
            adapter: adapter.into(),
            kind: ToolEventKind::RawStdout,
            message: line.clone(),
            address: None,
            raw: Some(line),
            data: serde_json::Value::Null,
        }
    }

    pub fn raw_stderr(adapter: impl Into<String>, line: impl Into<String>) -> Self {
        let line = line.into();
        Self {
            adapter: adapter.into(),
            kind: ToolEventKind::RawStderr,
            message: line.clone(),
            address: None,
            raw: Some(line),
            data: serde_json::Value::Null,
        }
    }

    pub fn error(adapter: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            adapter: adapter.into(),
            kind: ToolEventKind::Error,
            message: message.into(),
            address: None,
            raw: None,
            data: serde_json::Value::Null,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareEntry {
    pub offset: u64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gadget {
    pub address: u64,
    pub instructions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub address: Option<String>,
    pub size: Option<u64>,
    pub readable: Option<bool>,
    pub writable: Option<bool>,
    pub executable: Option<bool>,
    #[serde(default)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFeature {
    pub name: String,
    pub enabled: Option<bool>,
    pub value: Option<String>,
    #[serde(default)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProcess {
    pub pid: u32,
    pub name: String,
    pub parent_pid: Option<u32>,
    pub image_path: Option<String>,
    #[serde(default)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub severity: Option<String>,
    pub address: Option<String>,
    pub description: String,
    pub source: String,
    #[serde(default)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolLogEvent {
    pub adapter: String,
    pub stream: String,
    pub line: String,
    pub task_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringHit {
    pub address: String,
    pub value: String,
    pub encoding: Option<String>,
    #[serde(default)]
    pub extra: serde_json::Value,
}
