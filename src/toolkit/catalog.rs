//! Reverse-engineering tool catalog.
//!
//! The catalog records the broader "toolbox" scope for Ghidrai. Some entries
//! are built into this crate today, while others are external adapters or
//! roadmap targets that belong in the unified workspace.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ToolCatalogEntry {
    pub name: &'static str,
    pub category: &'static str,
    pub status: ToolStatus,
    pub platforms: &'static [&'static str],
    pub purpose: &'static str,
    pub integration: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    BuiltIn,
    ExternalAdapter,
    BundledBackend,
    Planned,
}

impl ToolStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::BuiltIn => "built-in",
            Self::ExternalAdapter => "external",
            Self::BundledBackend => "bundled",
            Self::Planned => "planned",
        }
    }
}

pub const TOOL_CATALOG: &[ToolCatalogEntry] = &[
    ToolCatalogEntry {
        name: "Ghidra",
        category: "Decompiler / static analysis",
        status: ToolStatus::BundledBackend,
        platforms: &["linux", "windows", "macos"],
        purpose: "Headless import, decompilation, xrefs, call graphs, symbols, and program metadata.",
        integration: "bridge, analyze, run-script, query",
    },
    ToolCatalogEntry {
        name: "Rizin",
        category: "Static analysis",
        status: ToolStatus::ExternalAdapter,
        platforms: &["linux", "windows", "macos"],
        purpose: "Fast JSON views for functions, strings, sections, imports, disassembly, and xrefs.",
        integration: "toolkit rizin",
    },
    ToolCatalogEntry {
        name: "Binwalk",
        category: "Firmware analysis",
        status: ToolStatus::BuiltIn,
        platforms: &["linux", "windows", "macos"],
        purpose: "Firmware signatures, embedded payload discovery, compression and filesystem hints.",
        integration: "toolkit binwalk",
    },
    ToolCatalogEntry {
        name: "Checksec",
        category: "Binary hardening",
        status: ToolStatus::BuiltIn,
        platforms: &["linux", "windows", "macos"],
        purpose: "PIE, NX, RELRO, canary, and format-specific hardening triage.",
        integration: "toolkit checksec",
    },
    ToolCatalogEntry {
        name: "LIEF-style parser",
        category: "Object metadata",
        status: ToolStatus::BuiltIn,
        platforms: &["linux", "windows", "macos"],
        purpose: "ELF, PE, and Mach-O metadata, sections, imports, exports, and symbols.",
        integration: "toolkit lief",
    },
    ToolCatalogEntry {
        name: "Native strings",
        category: "String extraction",
        status: ToolStatus::BuiltIn,
        platforms: &["linux", "windows", "macos"],
        purpose: "Printable ASCII and UTF-8 string extraction without shelling out.",
        integration: "toolkit strings",
    },
    ToolCatalogEntry {
        name: "Native disasm",
        category: "Disassembly",
        status: ToolStatus::BuiltIn,
        platforms: &["linux", "windows", "macos"],
        purpose: "x86 and x86-64 executable-section disassembly through iced-x86.",
        integration: "toolkit disasm",
    },
    ToolCatalogEntry {
        name: "ROP finder",
        category: "Exploit development",
        status: ToolStatus::BuiltIn,
        platforms: &["linux", "windows", "macos"],
        purpose: "Ret-terminated gadget discovery and deduplication.",
        integration: "toolkit rop",
    },
    ToolCatalogEntry {
        name: "Entropy scanner",
        category: "Packer / crypto triage",
        status: ToolStatus::BuiltIn,
        platforms: &["linux", "windows", "macos"],
        purpose: "Shannon entropy scoring for packed, compressed, or encrypted regions.",
        integration: "toolkit entropy",
    },
    ToolCatalogEntry {
        name: "CWE triage",
        category: "Security review",
        status: ToolStatus::BuiltIn,
        platforms: &["linux", "windows", "macos"],
        purpose: "Static risk hints for unsafe APIs, command execution, credentials, and plaintext URLs.",
        integration: "toolkit cwe",
    },
    ToolCatalogEntry {
        name: "GDB / GDB-MI",
        category: "Debugging",
        status: ToolStatus::ExternalAdapter,
        platforms: &["linux", "windows", "macos"],
        purpose: "Batch debugger metadata, symbols, and machine-interface output.",
        integration: "toolkit gdb, toolkit gdb-mi",
    },
    ToolCatalogEntry {
        name: "Volatility-style triage",
        category: "Memory forensics",
        status: ToolStatus::BuiltIn,
        platforms: &["linux", "windows", "macos"],
        purpose: "Memory/blob marker detection and IOC-oriented triage.",
        integration: "toolkit volatility",
    },
    ToolCatalogEntry {
        name: "IDA Pro / IDA Free",
        category: "Decompiler / static analysis",
        status: ToolStatus::Planned,
        platforms: &["windows", "linux", "macos"],
        purpose: "IDA database import/export, script automation, symbols, xrefs, and decompiler output.",
        integration: "planned adapter",
    },
    ToolCatalogEntry {
        name: "x64dbg",
        category: "Windows debugging",
        status: ToolStatus::Planned,
        platforms: &["windows"],
        purpose: "User-mode dynamic debugging, breakpoints, memory views, traces, and patching workflows.",
        integration: "planned adapter",
    },
    ToolCatalogEntry {
        name: "WinDbg",
        category: "Windows debugging",
        status: ToolStatus::Planned,
        platforms: &["windows"],
        purpose: "Crash dump, kernel, driver, symbol-server, and low-level Windows debugging.",
        integration: "planned adapter",
    },
    ToolCatalogEntry {
        name: "Frida",
        category: "Dynamic instrumentation",
        status: ToolStatus::Planned,
        platforms: &["android", "ios", "linux", "windows", "macos"],
        purpose: "Runtime hooks, tracing, argument inspection, and mobile/desktop instrumentation.",
        integration: "planned adapter",
    },
    ToolCatalogEntry {
        name: "JADX",
        category: "Android reverse engineering",
        status: ToolStatus::Planned,
        platforms: &["android", "linux", "windows", "macos"],
        purpose: "APK and DEX Java/Kotlin decompilation.",
        integration: "planned adapter",
    },
    ToolCatalogEntry {
        name: "apktool",
        category: "Android reverse engineering",
        status: ToolStatus::Planned,
        platforms: &["android", "linux", "windows", "macos"],
        purpose: "APK resource decoding, smali editing, rebuild, and resign workflows.",
        integration: "planned adapter",
    },
    ToolCatalogEntry {
        name: "010 Editor / WinHex / HxD",
        category: "Hex editing",
        status: ToolStatus::Planned,
        platforms: &["windows", "linux", "macos"],
        purpose: "Binary inspection, structure templates, manual patching, and forensic review.",
        integration: "planned launcher / notes",
    },
    ToolCatalogEntry {
        name: "Detect It Easy / PEiD / Exeinfo PE",
        category: "Packer identification",
        status: ToolStatus::Planned,
        platforms: &["windows", "linux", "macos"],
        purpose: "Compiler, packer, protector, and file signature identification.",
        integration: "planned adapter",
    },
    ToolCatalogEntry {
        name: "CFF Explorer / PE-bear",
        category: "PE inspection",
        status: ToolStatus::Planned,
        platforms: &["windows", "linux", "macos"],
        purpose: "PE headers, directories, imports, exports, resources, and manual edits.",
        integration: "planned adapter",
    },
    ToolCatalogEntry {
        name: "radare2",
        category: "Static analysis",
        status: ToolStatus::Planned,
        platforms: &["linux", "windows", "macos"],
        purpose: "Alternative command-driven static analysis and scripting backend.",
        integration: "planned adapter",
    },
];

pub fn print_catalog_pretty() {
    let mut current_category = "";
    for entry in TOOL_CATALOG {
        if entry.category != current_category {
            current_category = entry.category;
            println!("\n{}", current_category);
        }
        println!(
            "  - {:36} {:10} {:24} {}",
            entry.name,
            entry.status.label(),
            entry.integration,
            entry.purpose
        );
    }
}
