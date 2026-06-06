// Typed data structures for revisor
// All structs that cross module boundaries or represent wire formats live here.

use serde::{Deserialize, Serialize};

// ─── Program & Function Info ──────────────────────────────────────────────────

/// Top-level program metadata returned by the bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInfo {
    pub name: Option<String>,
    pub language_id: Option<String>,
    pub compiler_spec: Option<String>,
    pub executable_path: Option<String>,
    pub image_base: Option<String>,
    pub creation_date: Option<String>,
    pub function_count: Option<u64>,
    pub symbol_count: Option<u64>,
}

/// Summary information about a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub is_thunk: Option<bool>,
    #[serde(default)]
    pub calling_convention: Option<String>,
}

/// Extended function info with call-graph context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDetail {
    #[serde(flatten)]
    pub info: FunctionInfo,
    #[serde(default)]
    pub callers_count: Option<u64>,
    #[serde(default)]
    pub callees_count: Option<u64>,
}

// ─── Disassembly & Data ───────────────────────────────────────────────────────

/// A single disassembled instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionInfo {
    pub address: String,
    pub mnemonic: String,
    #[serde(default)]
    pub operands: Option<String>,
}

/// A defined data item at an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataInfo {
    pub address: String,
    pub data_type: Option<String>,
    pub value: Option<String>,
    pub size: Option<u64>,
}

// ─── Memory ───────────────────────────────────────────────────────────────────

/// A memory block in the program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBlockInfo {
    pub name: String,
    pub start: String,
    pub end: String,
    pub size: Option<u64>,
    #[serde(default)]
    pub readable: Option<bool>,
    #[serde(default)]
    pub writable: Option<bool>,
    #[serde(default)]
    pub executable: Option<bool>,
    #[serde(default)]
    pub initialized: Option<bool>,
}

// ─── Symbols & References ─────────────────────────────────────────────────────

/// A named symbol in the program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub symbol_type: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
}

/// A reference (cross-reference) between addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceInfo {
    pub from_address: String,
    pub to_address: String,
    #[serde(default)]
    pub ref_type: Option<String>,
}

/// Backwards-compatible cross-reference info (from the Java bridge's get_xrefs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRefInfo {
    #[serde(alias = "from")]
    pub from_address: String,
    #[serde(alias = "type")]
    pub ref_type: Option<String>,
}

// ─── Strings ──────────────────────────────────────────────────────────────────

/// A string found in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringResult {
    pub address: String,
    pub value: String,
}

// ─── Decompilation ────────────────────────────────────────────────────────────

/// Result of decompiling a function to C code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileResult {
    #[serde(default)]
    pub function_name: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    pub c_code: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

// ─── Graphs ───────────────────────────────────────────────────────────────────

/// A node in a call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    pub name: String,
    pub address: String,
}

/// An edge in a call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphEdge {
    pub from_name: String,
    pub from_address: String,
    pub to_name: String,
    pub to_address: String,
}

/// Complete call graph for the program (or a subset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub nodes: Vec<CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
}

/// A basic block in a control flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start_address: String,
    pub end_address: String,
    #[serde(default)]
    pub instructions: Vec<InstructionInfo>,
}

/// An edge in a control flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowEdge {
    pub from_block: String,
    pub to_block: String,
    #[serde(default)]
    pub edge_type: Option<String>,
}

/// Complete control flow graph for a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<ControlFlowEdge>,
}

// ─── Imports & Exports ────────────────────────────────────────────────────────

/// An imported function/symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub library: Option<String>,
}

/// An exported function/symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportInfo {
    pub name: String,
    pub address: String,
}

/// A data type known to the program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeInfo {
    pub name: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub description: Option<String>,
}

// ─── Bridge Wire Format ───────────────────────────────────────────────────────

/// A command sent to the Ghidra bridge TCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeCommand {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<serde_json::Value>,
}

/// Raw response from the Ghidra bridge TCP server.
/// Uses `#[serde(flatten)]` so unknown fields are captured in `extra`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeResponse {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

// ─── Daemon State ─────────────────────────────────────────────────────────────

/// Information about a running or completed task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub id: String,
    pub name: String,
    pub status: String,
    pub progress: String,
}

/// Snapshot of the daemon's current state, sent to the TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonState {
    pub tasks: Vec<TaskInfo>,
    pub logs: Vec<String>,
}

/// Requests that can be sent to the daemon over the Unix socket.
#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonRequest {
    StartTask { name: String, params: String },
    GetState,
}

/// Responses from the daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonResponse {
    TaskStarted { id: String },
    State(DaemonState),
    Error(String),
}
