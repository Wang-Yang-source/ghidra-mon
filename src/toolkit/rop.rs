use crate::adapter::ToolAdapter;
use crate::adapter::schema::{AdapterCapability, Gadget, ToolEvent, ToolEventKind};
use crate::error::{Result, RevisorError};
use crate::toolkit::native_rust_capability;
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use memmap2::Mmap;
use std::fs::File;

/// ROP gadget finder backed by `iced-x86`.
///
/// Memory-maps the target binary and scans for `ret`-terminated
/// instruction sequences. Gadgets are deduplicated by address and
/// sorted. Currently hard-coded to 64-bit x86.
pub struct RopAdapter;

impl ToolAdapter for RopAdapter {
    fn name(&self) -> &'static str {
        "rop"
    }

    fn parser_version(&self) -> &'static str {
        "native-rust-v1"
    }

    fn capabilities(&self) -> Vec<AdapterCapability> {
        vec![native_rust_capability("rop_gadgets")]
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

/// Find ROP gadgets in a binary file.
///
/// Uses `iced-x86` to disassemble the raw bytes, locating `ret`-
/// terminated sequences (up to 15 bytes before each `ret`/`retn`).
/// Returns gadgets sorted and deduplicated by address.
pub fn find_structured_gadgets(file_path: &str) -> Result<Vec<Gadget>> {
    let file = File::open(file_path).map_err(|e| RevisorError::io("open ROP target", e))?;
    let mmap = unsafe { Mmap::map(&file).map_err(|e| RevisorError::io("map ROP target", e))? };
    let bytes = &mmap[..];

    let mut gadgets = Vec::new();
    let bitness = 64; // Hardcode to 64 for simple implementation

    for i in 0..bytes.len() {
        if bytes[i] == 0xC3 || bytes[i] == 0xC2 {
            let max_backward = std::cmp::min(i, 15);
            for back in 1..max_backward {
                let start_idx = i - back;
                let mut decoder = Decoder::with_ip(
                    bitness,
                    &bytes[start_idx..=i],
                    start_idx as u64,
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
                        address: start_idx as u64,
                        instructions,
                    });
                }
            }
        }
    }

    gadgets.sort_by(|a, b| {
        a.address
            .cmp(&b.address)
            .then_with(|| a.instructions.cmp(&b.instructions))
    });
    gadgets.dedup_by(|a, b| a.address == b.address && a.instructions == b.instructions);

    Ok(gadgets)
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
}
