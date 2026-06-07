//! LIEF-style object inspection backed by native Rust parsing.
//!
//! This adapter covers the read-only subset Ghidrai currently needs from
//! LIEF: binary metadata, sections, imports, exports, and symbols. It uses
//! [`goblin`] in-process so the toolkit has a working Rust-native object
//! inspector before any external LIEF binding is introduced.

use crate::adapter::ToolAdapter;
use crate::adapter::schema::{AdapterCapability, Section, ToolEvent, ToolEventKind};
use crate::error::{Result, RevisorError};
use crate::toolkit::native_rust_capability;
use goblin::Object;
use serde::Serialize;
use std::fs;

/// Parser version string emitted in capability metadata.
pub const PARSER_VERSION: &str = "native-lief-v1";

#[derive(Debug, Clone, Serialize)]
struct BinaryInfo {
    format: String,
    architecture: String,
    machine: String,
    entry: Option<String>,
    bits: Option<u8>,
    endian: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SymbolInfo {
    name: String,
    address: Option<String>,
    kind: String,
    source: String,
}

/// Rust-native read-only object inspection adapter.
pub struct LiefAdapter;

impl ToolAdapter for LiefAdapter {
    fn name(&self) -> &'static str {
        "lief"
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn capabilities(&self) -> Vec<AdapterCapability> {
        vec![native_rust_capability("object_inspection")]
    }

    fn run(&self, target: &str) -> Result<Vec<ToolEvent>> {
        inspect_object(target)
    }
}

/// Inspect ELF, PE, or Mach-O metadata and emit unified events.
pub fn inspect_object(path: &str) -> Result<Vec<ToolEvent>> {
    let buffer = fs::read(path).map_err(|e| RevisorError::io("read object target", e))?;

    match Object::parse(&buffer).map_err(|e| RevisorError::Other(format!("parse target: {e}")))? {
        Object::Elf(elf) => Ok(inspect_elf(&elf)),
        Object::PE(pe) => Ok(inspect_pe(&pe)),
        Object::Mach(mach) => inspect_mach(&mach),
        Object::Archive(_) => Err(RevisorError::Other(
            "lief adapter does not inspect archive members yet".to_string(),
        )),
        _ => Err(RevisorError::Other(
            "lief adapter target is not a supported executable/object".to_string(),
        )),
    }
}

fn inspect_elf(elf: &goblin::elf::Elf<'_>) -> Vec<ToolEvent> {
    let mut events = vec![binary_info_event(BinaryInfo {
        format: "ELF".to_string(),
        architecture: elf_machine_name(elf.header.e_machine).to_string(),
        machine: elf.header.e_machine.to_string(),
        entry: Some(format!("0x{:x}", elf.header.e_entry)),
        bits: Some(if elf.is_64 { 64 } else { 32 }),
        endian: Some(if elf.little_endian {
            "little".to_string()
        } else {
            "big".to_string()
        }),
    })];

    for section in &elf.section_headers {
        let name = elf
            .shdr_strtab
            .get_at(section.sh_name)
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }

        let data = Section {
            name: name.clone(),
            address: Some(format!("0x{:x}", section.sh_addr)),
            size: Some(section.sh_size),
            readable: Some(true),
            writable: Some(section.is_writable()),
            executable: Some(section.is_executable()),
            extra: serde_json::json!({
                "offset": section.sh_offset,
                "type": section.sh_type,
                "flags": section.sh_flags,
            }),
        };
        events.push(section_event(data));
    }

    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name)
            && !name.is_empty()
        {
            let kind = if sym.st_value == 0 {
                "import"
            } else {
                "dynamic_symbol"
            };
            events.push(symbol_event(SymbolInfo {
                name: name.to_string(),
                address: nonzero_hex(sym.st_value),
                kind: kind.to_string(),
                source: ".dynsym".to_string(),
            }));
        }
    }

    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get_at(sym.st_name)
            && !name.is_empty()
        {
            events.push(symbol_event(SymbolInfo {
                name: name.to_string(),
                address: nonzero_hex(sym.st_value),
                kind: "symbol".to_string(),
                source: ".symtab".to_string(),
            }));
        }
    }

    events
}

fn inspect_pe(pe: &goblin::pe::PE<'_>) -> Vec<ToolEvent> {
    let mut events = vec![binary_info_event(BinaryInfo {
        format: "PE".to_string(),
        architecture: pe_machine_name(pe.header.coff_header.machine).to_string(),
        machine: format!("0x{:04x}", pe.header.coff_header.machine),
        entry: Some(format!("0x{:x}", pe.image_base + pe.entry as u64)),
        bits: Some(if pe.is_64 { 64 } else { 32 }),
        endian: Some("little".to_string()),
    })];

    for section in &pe.sections {
        let name = section.name().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        let data = Section {
            name: name.clone(),
            address: Some(format!(
                "0x{:x}",
                pe.image_base + section.virtual_address as u64
            )),
            size: Some(section.virtual_size as u64),
            readable: Some(
                section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0,
            ),
            writable: Some(
                section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0,
            ),
            executable: Some(
                section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0,
            ),
            extra: serde_json::json!({
                "raw_size": section.size_of_raw_data,
                "raw_offset": section.pointer_to_raw_data,
                "characteristics": section.characteristics,
            }),
        };
        events.push(section_event(data));
    }

    for import in &pe.imports {
        events.push(symbol_event(SymbolInfo {
            name: import.name.to_string(),
            address: Some(format!("0x{:x}", import.rva)),
            kind: "import".to_string(),
            source: import.dll.to_string(),
        }));
    }

    for export in &pe.exports {
        if let Some(name) = export.name {
            events.push(symbol_event(SymbolInfo {
                name: name.to_string(),
                address: Some(format!("0x{:x}", pe.image_base + export.rva as u64)),
                kind: "export".to_string(),
                source: "export_table".to_string(),
            }));
        }
    }

    events
}

fn inspect_mach(mach: &goblin::mach::Mach) -> Result<Vec<ToolEvent>> {
    match mach {
        goblin::mach::Mach::Binary(macho) => Ok(inspect_single_macho(macho)),
        goblin::mach::Mach::Fat(fat) => {
            let first = fat.get(0).map_err(|e| {
                RevisorError::Other(format!("failed to read first fat architecture: {e}"))
            })?;
            match first {
                goblin::mach::SingleArch::MachO(macho) => Ok(inspect_single_macho(&macho)),
                goblin::mach::SingleArch::Archive(_) => Err(RevisorError::Other(
                    "lief adapter does not inspect archive entries in fat binaries yet".to_string(),
                )),
            }
        }
    }
}

fn inspect_single_macho(macho: &goblin::mach::MachO<'_>) -> Vec<ToolEvent> {
    let mut events = vec![binary_info_event(BinaryInfo {
        format: "Mach-O".to_string(),
        architecture: macho_cpu_name(macho.header.cputype()).to_string(),
        machine: macho.header.cputype().to_string(),
        entry: nonzero_hex(macho.entry),
        bits: Some(if macho.is_64 { 64 } else { 32 }),
        endian: Some(if macho.little_endian {
            "little".to_string()
        } else {
            "big".to_string()
        }),
    })];

    for segment in &macho.segments {
        if let Ok(sections) = segment.sections() {
            for (section, _data) in sections {
                let name = section.name().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                events.push(section_event(Section {
                    name,
                    address: Some(format!("0x{:x}", section.addr)),
                    size: Some(section.size),
                    readable: None,
                    writable: None,
                    executable: None,
                    extra: serde_json::json!({
                        "offset": section.offset,
                        "align": section.align,
                        "flags": section.flags,
                    }),
                }));
            }
        }
    }

    for sym in macho.symbols().filter_map(|sym| sym.ok()) {
        let (name, nlist) = sym;
        if name.is_empty() {
            continue;
        }
        events.push(symbol_event(SymbolInfo {
            name: name.to_string(),
            address: nonzero_hex(nlist.n_value),
            kind: "symbol".to_string(),
            source: "symtab".to_string(),
        }));
    }

    events
}

fn binary_info_event(info: BinaryInfo) -> ToolEvent {
    let entry = info.entry.clone().unwrap_or_else(|| "unknown".to_string());
    ToolEvent {
        adapter: "lief".to_string(),
        kind: ToolEventKind::BinaryInfo,
        message: format!(
            "{} {}-bit {} entry {}",
            info.format,
            info.bits
                .map(|bits| bits.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            info.architecture,
            entry
        ),
        address: info.entry.clone(),
        raw: None,
        data: serde_json::to_value(info).unwrap_or(serde_json::Value::Null),
    }
}

fn section_event(section: Section) -> ToolEvent {
    ToolEvent {
        adapter: "lief".to_string(),
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

fn symbol_event(symbol: SymbolInfo) -> ToolEvent {
    let address = symbol.address.clone();
    ToolEvent {
        adapter: "lief".to_string(),
        kind: ToolEventKind::Symbol,
        message: format!(
            "{} {} {} ({})",
            address.clone().unwrap_or_else(|| "unknown".to_string()),
            symbol.kind,
            symbol.name,
            symbol.source
        ),
        address,
        raw: None,
        data: serde_json::to_value(symbol).unwrap_or(serde_json::Value::Null),
    }
}

fn nonzero_hex(value: u64) -> Option<String> {
    if value == 0 {
        None
    } else {
        Some(format!("0x{value:x}"))
    }
}

fn elf_machine_name(machine: u16) -> &'static str {
    match machine {
        3 => "x86",
        8 => "mips",
        20 => "powerpc",
        21 => "powerpc64",
        40 => "arm",
        43 => "sparc",
        62 => "x86_64",
        183 => "aarch64",
        243 => "riscv",
        _ => "unknown",
    }
}

fn pe_machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86",
        0x01c0 | 0x01c2 | 0x01c4 => "arm",
        0x8664 => "x86_64",
        0xaa64 | 0xa641 | 0xa64e => "aarch64",
        0x5032 => "riscv32",
        0x5064 => "riscv64",
        0x5128 => "riscv128",
        _ => "unknown",
    }
}

fn macho_cpu_name(cpu_type: u32) -> &'static str {
    match cpu_type {
        7 => "x86",
        0x0100_0007 => "x86_64",
        8 => "mips",
        12 => "arm",
        0x0100_000c => "aarch64",
        18 => "powerpc",
        0x0100_0012 => "powerpc64",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::ToolAdapter;

    #[test]
    fn lief_adapter_reports_capabilities() {
        let adapter = LiefAdapter;
        let capabilities = adapter.capabilities();

        assert_eq!(adapter.name(), "lief");
        assert_eq!(adapter.parser_version(), PARSER_VERSION);
        assert_eq!(capabilities.len(), 1);
        assert!(capabilities[0].read_only);
        assert_eq!(capabilities[0].name, "object_inspection");
    }

    #[test]
    fn inspects_elf_fixture() {
        let events = inspect_object("tests/crackme").expect("inspect ELF fixture");

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
        assert!(
            events
                .iter()
                .any(|event| event.kind == ToolEventKind::Symbol)
        );
        assert!(events.iter().all(|event| event.adapter == "lief"));
    }

    #[test]
    fn emits_text_section_for_fixture() {
        let events = inspect_object("tests/crackme").expect("inspect ELF fixture");
        assert!(events.iter().any(|event| {
            event.kind == ToolEventKind::Section
                && event.data.get("name").and_then(|value| value.as_str()) == Some(".text")
        }));
    }

    #[test]
    fn maps_common_machine_names() {
        assert_eq!(elf_machine_name(62), "x86_64");
        assert_eq!(elf_machine_name(183), "aarch64");
        assert_eq!(pe_machine_name(0x8664), "x86_64");
        assert_eq!(pe_machine_name(0xaa64), "aarch64");
        assert_eq!(macho_cpu_name(0x0100_0007), "x86_64");
        assert_eq!(macho_cpu_name(0x0100_000c), "aarch64");
    }

    #[test]
    fn adapter_run_returns_events() {
        let adapter = LiefAdapter;
        let events = adapter.run("tests/crackme").expect("run on crackme");

        assert!(!events.is_empty());
        assert!(events.iter().all(|event| event.adapter == "lief"));
    }
}
