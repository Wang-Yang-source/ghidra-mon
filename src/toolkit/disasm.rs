//! x86 / x86-64 disassembly adapter backed by [`iced_x86`].
//!
//! Reads the target binary with [`goblin`], locates the `.text` section
//! (falling back to the entry-point region), and disassembles up to 500
//! instructions using NASM syntax.  Each instruction is returned as a
//! [`ToolEvent`] with kind [`ToolEventKind::Instruction`].

use crate::adapter::ToolAdapter;
use crate::adapter::schema::{AdapterCapability, ToolEvent, ToolEventKind};
use crate::error::{Result, RevisorError};
use crate::toolkit::native_rust_capability;
use goblin::Object;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
use serde::Serialize;
use std::fs;

/// Default maximum number of instructions the adapter will emit.
const DEFAULT_MAX_INSTRUCTIONS: usize = 500;

/// Structured data emitted in the `data` field of each [`ToolEvent`].
#[derive(Debug, Clone, Serialize)]
struct InstructionData {
    mnemonic: String,
    operands: String,
    bytes: String,
    length: usize,
}

/// x86 / x86-64 disassembly adapter.
///
/// Parses ELF and PE binaries via [`goblin`] to determine bitness and
/// locate the `.text` section, then disassembles with [`iced_x86`].
pub struct DisasmAdapter;

impl ToolAdapter for DisasmAdapter {
    fn name(&self) -> &'static str {
        "disasm"
    }

    fn parser_version(&self) -> &'static str {
        "native-rust-v1"
    }

    fn capabilities(&self) -> Vec<AdapterCapability> {
        vec![native_rust_capability("disassembly")]
    }

    fn run(&self, target: &str) -> Result<Vec<ToolEvent>> {
        disassemble(target, None, DEFAULT_MAX_INSTRUCTIONS)
    }
}

/// Disassemble the `.text` section (or entry-point region) of a binary.
///
/// # Arguments
/// * `path`  – Filesystem path to an ELF or PE binary.
/// * `start` – Optional virtual address to begin disassembly at.
///   When `None`, the start of the `.text` section is used.
/// * `count` – Maximum number of instructions to return.
///
/// # Returns
/// A vector of [`ToolEvent`]s with kind [`ToolEventKind::Instruction`].
pub fn disassemble(path: &str, start: Option<u64>, count: usize) -> Result<Vec<ToolEvent>> {
    let buffer = fs::read(path).map_err(|e| RevisorError::io("read disasm target", e))?;

    match Object::parse(&buffer).map_err(|e| RevisorError::Other(format!("parse target: {e}")))? {
        Object::Elf(elf) => {
            let bitness: u32 = if elf.is_64 { 64 } else { 32 };
            let (bytes, ip) = find_elf_text(&buffer, &elf, start)?;
            Ok(decode_instructions("disasm", bitness, bytes, ip, count))
        }
        Object::PE(pe) => {
            let bitness: u32 = if pe.is_64 { 64 } else { 32 };
            let (bytes, ip) = find_pe_text(&buffer, &pe, start)?;
            Ok(decode_instructions("disasm", bitness, bytes, ip, count))
        }
        _ => Err(RevisorError::Other(
            "disasm currently supports ELF and PE targets".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Binary format helpers
// ---------------------------------------------------------------------------

/// Locate the `.text` section bytes and virtual address for an ELF binary.
///
/// When `start` is `Some(addr)`, the returned slice begins at the file
/// offset corresponding to that virtual address (must fall within `.text`).
fn find_elf_text<'a>(
    buffer: &'a [u8],
    elf: &goblin::elf::Elf<'_>,
    start: Option<u64>,
) -> Result<(&'a [u8], u64)> {
    // Try to locate the .text section by name.
    for section in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
        if name == ".text" {
            let sec_offset = section.sh_offset as usize;
            let sec_size = section.sh_size as usize;
            let sec_addr = section.sh_addr;

            if sec_offset.saturating_add(sec_size) > buffer.len() {
                return Err(RevisorError::Other(
                    ".text section extends past end of file".to_string(),
                ));
            }

            return match start {
                Some(addr) if addr >= sec_addr && addr < sec_addr + section.sh_size => {
                    let delta = (addr - sec_addr) as usize;
                    Ok((&buffer[sec_offset + delta..sec_offset + sec_size], addr))
                }
                Some(addr) => Err(RevisorError::Other(format!(
                    "start address 0x{addr:x} is outside .text (0x{sec_addr:x}..0x{:x})",
                    sec_addr + section.sh_size
                ))),
                None => Ok((&buffer[sec_offset..sec_offset + sec_size], sec_addr)),
            };
        }
    }

    // Fallback: use the entry point to find a containing LOAD segment.
    let entry = elf.header.e_entry;
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD
            && entry >= ph.p_vaddr
            && entry < ph.p_vaddr + ph.p_memsz
        {
            let base_offset = ph.p_offset as usize;
            let seg_size = ph.p_filesz as usize;

            if base_offset + seg_size <= buffer.len() {
                let ip = start.unwrap_or(entry);
                if ip < ph.p_vaddr || ip >= ph.p_vaddr + ph.p_filesz {
                    return Err(RevisorError::Other(format!(
                        "start address 0x{ip:x} is outside entry LOAD segment (0x{:x}..0x{:x})",
                        ph.p_vaddr,
                        ph.p_vaddr + ph.p_filesz
                    )));
                }
                let skip = (ip - ph.p_vaddr) as usize;
                return Ok((&buffer[base_offset + skip..base_offset + seg_size], ip));
            }
        }
    }

    Err(RevisorError::Other(
        "could not locate .text section or entry-point segment".to_string(),
    ))
}

/// Locate the `.text` section bytes and virtual address for a PE binary.
fn find_pe_text<'a>(
    buffer: &'a [u8],
    pe: &goblin::pe::PE<'_>,
    start: Option<u64>,
) -> Result<(&'a [u8], u64)> {
    let image_base = pe.image_base;

    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name);
        let name = name.trim_end_matches('\0');
        if name == ".text" {
            let sec_offset = section.pointer_to_raw_data as usize;
            let sec_size = section.size_of_raw_data as usize;
            let sec_va = image_base + section.virtual_address as u64;

            if sec_offset.saturating_add(sec_size) > buffer.len() {
                return Err(RevisorError::Other(
                    ".text section extends past end of file".to_string(),
                ));
            }

            return match start {
                Some(addr) if addr >= sec_va && addr < sec_va + sec_size as u64 => {
                    let delta = (addr - sec_va) as usize;
                    Ok((&buffer[sec_offset + delta..sec_offset + sec_size], addr))
                }
                Some(addr) => Err(RevisorError::Other(format!(
                    "start address 0x{addr:x} is outside .text (0x{sec_va:x}..0x{:x})",
                    sec_va + sec_size as u64
                ))),
                None => Ok((&buffer[sec_offset..sec_offset + sec_size], sec_va)),
            };
        }
    }

    Err(RevisorError::Other(
        "could not locate .text section in PE".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Disassembly core
// ---------------------------------------------------------------------------

/// Decode up to `count` instructions from `bytes` starting at virtual
/// address `ip`, returning one [`ToolEvent`] per instruction.
fn decode_instructions(
    adapter: &str,
    bitness: u32,
    bytes: &[u8],
    ip: u64,
    count: usize,
) -> Vec<ToolEvent> {
    let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut instruction = Instruction::default();
    let mut events = Vec::with_capacity(count.min(bytes.len()));

    while decoder.can_decode() && events.len() < count {
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            continue;
        }

        let addr = instruction.ip();
        let len = instruction.len();
        let addr_hex = format!("0x{addr:x}");

        // Format the full instruction text (e.g. "mov rax,rbx").
        let mut full_text = String::new();
        formatter.format(&instruction, &mut full_text);

        // Split into mnemonic + operands.  The formatter produces
        // "mnemonic operands" with a single space separator.
        let (mnemonic, operands) = match full_text.find(' ') {
            Some(pos) => (
                full_text[..pos].to_string(),
                full_text[pos + 1..].to_string(),
            ),
            None => (full_text.clone(), String::new()),
        };

        // Hex-encoded instruction bytes.
        let byte_offset = (addr - ip) as usize;
        let hex_bytes: String = bytes[byte_offset..byte_offset + len]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let data = InstructionData {
            mnemonic,
            operands,
            bytes: hex_bytes,
            length: len,
        };

        events.push(ToolEvent {
            adapter: adapter.to_string(),
            kind: ToolEventKind::Instruction,
            message: format!("{addr_hex}  {full_text}"),
            address: Some(addr_hex),
            raw: None,
            data: serde_json::to_value(&data).unwrap_or(serde_json::Value::Null),
        });
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::ToolAdapter;

    #[test]
    fn disasm_adapter_reports_capabilities() {
        let adapter = DisasmAdapter;
        let capabilities = adapter.capabilities();

        assert_eq!(adapter.name(), "disasm");
        assert_eq!(adapter.parser_version(), "native-rust-v1");
        assert_eq!(capabilities.len(), 1);
        assert!(capabilities[0].read_only);
        assert_eq!(capabilities[0].name, "disassembly");
    }

    #[test]
    fn disassembles_crackme_fixture() {
        let events = disassemble("tests/crackme", None, 100).expect("crackme fixture");

        assert!(
            !events.is_empty(),
            "should produce at least one instruction"
        );
        assert!(
            events.len() <= 100,
            "should respect the instruction count limit"
        );

        for event in &events {
            assert_eq!(event.adapter, "disasm");
            assert_eq!(event.kind, ToolEventKind::Instruction);
            assert!(
                event.address.is_some(),
                "every instruction should have an address"
            );

            // Verify the data field has the expected structure.
            let data = &event.data;
            assert!(
                data.get("mnemonic").is_some(),
                "data should contain mnemonic"
            );
            assert!(
                data.get("operands").is_some(),
                "data should contain operands"
            );
            assert!(data.get("bytes").is_some(), "data should contain bytes");
            assert!(data.get("length").is_some(), "data should contain length");
        }
    }

    #[test]
    fn disasm_adapter_run_returns_instruction_events() {
        let adapter = DisasmAdapter;
        let events = adapter.run("tests/crackme").expect("crackme fixture");

        assert!(!events.is_empty());
        assert!(events.len() <= DEFAULT_MAX_INSTRUCTIONS);
        assert!(events.iter().all(|e| e.adapter == "disasm"));
        assert!(events.iter().all(|e| e.kind == ToolEventKind::Instruction));
    }

    #[test]
    fn instruction_message_format() {
        let events = disassemble("tests/crackme", None, 1).expect("crackme fixture");
        let first = &events[0];

        // Message should look like "0x<addr>  <instruction>"
        assert!(
            first.message.starts_with("0x"),
            "message should start with hex address prefix"
        );
        assert!(
            first.message.contains("  "),
            "message should have double-space between address and instruction"
        );
    }
}
