use goblin::Object;
use std::fs;

pub fn scan_binary_info(target: &str) -> Vec<String> {
    let mut lines = vec![format!("[adapter:local] binary info scan: {}", target)];

    match fs::read(target) {
        Ok(buffer) => match Object::parse(&buffer) {
            Ok(Object::Elf(elf)) => {
                lines.push("Format: ELF".to_string());
                lines.push(format!(
                    "Architecture: {}",
                    if elf.is_64 { "64-bit" } else { "32-bit" }
                ));
                lines.push(format!("Dynamic Symbols: {}", elf.dynsyms.len()));
                lines.push(format!("Sections: {}", elf.section_headers.len()));
                lines.push(format!("Entry Point: 0x{:x}", elf.header.e_entry));
            }
            Ok(Object::PE(pe)) => {
                lines.push("Format: PE (Windows)".to_string());
                lines.push(format!(
                    "Architecture: {}",
                    if pe.is_64 { "64-bit" } else { "32-bit" }
                ));
                lines.push(format!("Imports: {}", pe.imports.len()));
                lines.push(format!("Exports: {}", pe.exports.len()));
                lines.push(format!("Sections: {}", pe.sections.len()));
                lines.push(format!("Entry Point: 0x{:x}", pe.entry));
            }
            Ok(Object::Mach(_)) => lines.push("Format: Mach-O (macOS)".to_string()),
            Ok(_) => lines.push("Format: Unknown/Archive".to_string()),
            Err(e) => lines.push(format!("[error] parse failed: {}", e)),
        },
        Err(e) => lines.push(format!("[error] file read failed: {}", e)),
    }

    lines
}
