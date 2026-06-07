use crate::adapter::ToolAdapter;
use crate::adapter::schema::{AdapterCapability, Gadget, ToolEvent, ToolEventKind};
use crate::error::{Result, RevisorError};
use crate::toolkit::native_rust_capability;
use goblin::Object;
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use std::fs;

/// ROP gadget finder backed by `iced-x86`.
///
/// Memory-maps the target binary and scans for `ret`-terminated
/// instruction sequences. Gadgets are deduplicated by address and
/// sorted. Supports both 32-bit and 64-bit x86 via auto-detection
/// from ELF/PE headers.
///
/// NOTE: ARM support is planned but not yet implemented.
pub struct RopAdapter;

impl ToolAdapter for RopAdapter {
    fn name(&self) -> &'static str {
        "rop"
    }

    fn parser_version(&self) -> &'static str {
        "native-rust-v1"
    }

    fn capabilities(&self) -> Vec<AdapterCapability> {
        vec![native_rust_capability("rop_gadgets_x86_32_64")]
    }

    fn run(&self, target: &str) -> Result<Vec<ToolEvent>> {
        let gadgets = find_structured_gadgets(target)?;
        if gadgets.is_empty() {
            return Ok(vec![ToolEvent::status(
                self.name(),
                "No ROP gadgets found.",
            )]);
        }

        Ok(gadgets
            .into_iter()
            .map(|gadget| {
                let address = format!("0x{:x}", gadget.address);
                ToolEvent {
                    adapter: self.name().to_string(),
                    kind: ToolEventKind::Gadget,
                    message: format!("{}: {}", address, gadget.instructions.join(" ; ")),
                    address: Some(address),
                    raw: None,
                    data: serde_json::to_value(gadget).unwrap_or(serde_json::Value::Null),
                }
            })
            .collect())
    }
}

/// Detect the bitness (32 or 64) of an x86 binary from its ELF/PE header.
///
/// Falls back to 64-bit if the format is unrecognised (e.g. raw blobs).
/// ARM binaries will be parsed but currently fall through to the default;
/// ARM support is planned but not yet implemented.
fn detect_bitness(bytes: &[u8]) -> u32 {
    match Object::parse(bytes) {
        Ok(Object::Elf(elf)) => {
            if elf.is_64 {
                64
            } else {
                32
            }
        }
        Ok(Object::PE(pe)) => {
            if pe.is_64 {
                64
            } else {
                32
            }
        }
        _ => 64, // default fallback for raw blobs / unknown formats
    }
}

struct ExecutableRange<'a> {
    bytes: &'a [u8],
    virtual_address: u64,
}

/// Find ROP gadgets in a binary file.
///
/// Uses `iced-x86` to disassemble executable ELF LOAD segments or PE
/// executable sections, locating `ret`-terminated sequences (up to 15
/// bytes before each `ret`/`retn`). Automatically detects 32-bit vs
/// 64-bit from the binary header. Returns gadgets sorted and deduplicated
/// by virtual address.
pub fn find_structured_gadgets(file_path: &str) -> Result<Vec<Gadget>> {
    let bytes = fs::read(file_path).map_err(|e| RevisorError::io("read ROP target", e))?;

    let mut gadgets = Vec::new();
    let bitness = detect_bitness(&bytes);
    let ranges = executable_ranges(&bytes);

    for range in ranges {
        scan_range_for_gadgets(range, bitness, &mut gadgets);
    }

    gadgets.sort_by(|a, b| {
        a.address
            .cmp(&b.address)
            .then_with(|| a.instructions.cmp(&b.instructions))
    });
    gadgets.dedup_by(|a, b| a.address == b.address && a.instructions == b.instructions);

    Ok(gadgets)
}

fn executable_ranges(bytes: &[u8]) -> Vec<ExecutableRange<'_>> {
    match Object::parse(bytes) {
        Ok(Object::Elf(elf)) => {
            let mut ranges = Vec::new();
            for header in &elf.program_headers {
                if header.p_type != goblin::elf::program_header::PT_LOAD
                    || header.p_flags & goblin::elf::program_header::PF_X == 0
                {
                    continue;
                }

                let offset = header.p_offset as usize;
                let size = header.p_filesz as usize;
                if let Some(end) = offset.checked_add(size)
                    && end <= bytes.len()
                    && size > 0
                {
                    ranges.push(ExecutableRange {
                        bytes: &bytes[offset..end],
                        virtual_address: header.p_vaddr,
                    });
                }
            }
            if ranges.is_empty() {
                vec![ExecutableRange {
                    bytes,
                    virtual_address: 0,
                }]
            } else {
                ranges
            }
        }
        Ok(Object::PE(pe)) => {
            let image_base = pe.image_base;
            let mut ranges = Vec::new();
            for section in &pe.sections {
                const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
                if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                    continue;
                }

                let offset = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                if let Some(end) = offset.checked_add(size)
                    && end <= bytes.len()
                    && size > 0
                {
                    ranges.push(ExecutableRange {
                        bytes: &bytes[offset..end],
                        virtual_address: image_base + section.virtual_address as u64,
                    });
                }
            }
            if ranges.is_empty() {
                vec![ExecutableRange {
                    bytes,
                    virtual_address: 0,
                }]
            } else {
                ranges
            }
        }
        _ => vec![ExecutableRange {
            bytes,
            virtual_address: 0,
        }],
    }
}

fn scan_range_for_gadgets(range: ExecutableRange<'_>, bitness: u32, gadgets: &mut Vec<Gadget>) {
    for i in 0..range.bytes.len() {
        if range.bytes[i] == 0xC3 || range.bytes[i] == 0xC2 {
            let max_backward = std::cmp::min(i, 15);
            for back in 1..max_backward {
                let start_idx = i - back;
                let address = range.virtual_address + start_idx as u64;
                let mut decoder = Decoder::with_ip(
                    bitness,
                    &range.bytes[start_idx..=i],
                    address,
                    DecoderOptions::NONE,
                );

                let mut insts = Vec::new();
                let mut valid = true;
                let mut ends_in_ret = false;

                while decoder.can_decode() {
                    let instr = decoder.decode();
                    if instr.is_invalid() {
                        valid = false;
                        break;
                    }
                    insts.push(instr);
                    if instr.code() == iced_x86::Code::Retnq
                        || instr.code() == iced_x86::Code::Retnw
                        || instr.code() == iced_x86::Code::Retnd
                    {
                        ends_in_ret = true;
                        break;
                    }
                }

                if valid && ends_in_ret {
                    let mut instructions = Vec::new();
                    for inst in insts {
                        let mut formatter = NasmFormatter::new();
                        let mut output = String::new();
                        formatter.format(&inst, &mut output);
                        instructions.push(output);
                    }
                    gadgets.push(Gadget {
                        address,
                        instructions,
                    });
                }
            }
        }
    }
}

pub fn find_gadgets(
    file_path: &str,
) -> std::result::Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(find_structured_gadgets(file_path)?
        .into_iter()
        .map(|gadget| {
            format!(
                "0x{:x}: {}",
                gadget.address,
                gadget.instructions.join(" ; ")
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::ToolAdapter;

    #[test]
    fn rop_adapter_reports_capabilities() {
        let adapter = RopAdapter;
        let capabilities = adapter.capabilities();

        assert_eq!(adapter.name(), "rop");
        assert_eq!(adapter.parser_version(), "native-rust-v1");
        assert_eq!(capabilities.len(), 1);
        assert!(capabilities[0].read_only);
    }

    #[test]
    fn rop_adapter_returns_events_for_fixture() {
        let adapter = RopAdapter;
        let events = adapter.run("tests/crackme").expect("crackme should scan");

        assert!(!events.is_empty());
        assert!(events.iter().all(|event| event.adapter == "rop"));
    }

    #[test]
    fn detect_bitness_defaults_to_64_for_unknown() {
        // An empty buffer or non-ELF/PE blob should fall back to 64-bit.
        let empty: &[u8] = &[];
        assert_eq!(detect_bitness(empty), 64);

        let garbage: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(detect_bitness(garbage), 64);
    }

    #[test]
    fn detect_bitness_reads_elf64() {
        // Read the test fixture (known 64-bit ELF).
        let bytes = std::fs::read("tests/crackme").expect("test fixture should exist");
        assert_eq!(detect_bitness(&bytes), 64);
    }

    #[test]
    fn rop_gadgets_use_virtual_addresses_for_elf() {
        let gadgets = find_structured_gadgets("tests/crackme").expect("crackme should scan");

        assert!(!gadgets.is_empty());
        assert!(gadgets.iter().any(|gadget| gadget.address >= 0x400000));
        assert!(!gadgets.iter().any(|gadget| gadget.address < 0x1000));
    }
}
