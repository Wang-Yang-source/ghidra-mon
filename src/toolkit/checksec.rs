use crate::adapter::ToolAdapter;
use crate::adapter::schema::{
    AdapterCapability, OutputFormat, SecurityFeature, ToolEvent, ToolEventKind,
};
use crate::error::{Result, RevisorError};
use goblin::Object;
use goblin::elf::dynamic::{DF_1_NOW, DT_BIND_NOW, DT_FLAGS_1};
use goblin::elf::header::{ET_DYN, ET_EXEC};
use goblin::elf::program_header::{PF_X, PT_GNU_RELRO, PT_GNU_STACK};
use std::fs;

/// Parser version string emitted in capability metadata.
pub const PARSER_VERSION: &str = "native-checksec-v2";

// ── PE DLL characteristics constants ────────────────────────────────────────
const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

// ── Mach-O flag constant ────────────────────────────────────────────────────
const MH_PIE: u32 = 0x0020_0000;

/// Binary security hardening checker backed by [`goblin`].
///
/// Checks security features across ELF, PE, and Mach-O binaries:
/// - **ELF**: PIE, NX, RELRO, stack canary, stripped symbols
/// - **PE**: ASLR/DynamicBase, DEP/NX, CFG, Integrity, SEH, High Entropy ASLR
/// - **Mach-O**: PIE, stack canary, ARC
pub struct ChecksecAdapter;

impl ToolAdapter for ChecksecAdapter {
    fn name(&self) -> &'static str {
        "checksec"
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn capabilities(&self) -> Vec<AdapterCapability> {
        vec![AdapterCapability {
            name: "security_features".to_string(),
            formats: vec![OutputFormat::NativeRust],
            read_only: true,
            parser_version: Some(PARSER_VERSION.to_string()),
        }]
    }

    fn run(&self, target: &str) -> Result<Vec<ToolEvent>> {
        let features = analyze_security_features(target)?;
        Ok(features
            .into_iter()
            .map(|feature| ToolEvent {
                adapter: self.name().to_string(),
                kind: ToolEventKind::Finding,
                message: format_feature(&feature),
                address: None,
                raw: None,
                data: serde_json::to_value(feature).unwrap_or(serde_json::Value::Null),
            })
            .collect())
    }
}

/// Analyze a binary and return its security hardening features.
///
/// Supports ELF, PE, and Mach-O executable formats.
pub fn analyze_security_features(file_path: &str) -> Result<Vec<SecurityFeature>> {
    let buffer = fs::read(file_path).map_err(|e| RevisorError::io("read checksec target", e))?;
    match Object::parse(&buffer).map_err(|e| RevisorError::Other(format!("parse target: {e}")))? {
        Object::Elf(elf) => Ok(analyze_elf(&elf)),
        Object::PE(pe) => Ok(analyze_pe(&pe)),
        Object::Mach(mach) => analyze_mach(&mach),
        _ => Err(RevisorError::Other(
            "checksec target is not a supported executable".to_string(),
        )),
    }
}

// ── ELF analysis ────────────────────────────────────────────────────────────

fn analyze_elf(elf: &goblin::elf::Elf<'_>) -> Vec<SecurityFeature> {
    vec![
        security_feature(
            "PIE",
            Some(elf.header.e_type == ET_DYN),
            Some(match elf.header.e_type {
                ET_DYN => "position-independent executable",
                ET_EXEC => "fixed executable",
                _ => "unknown executable type",
            }),
        ),
        security_feature("NX", nx_enabled(elf), Some("GNU_STACK executable flag")),
        security_feature("RELRO", relro_enabled(elf), Some(relro_status(elf))),
        security_feature(
            "Canary",
            Some(has_stack_canary(elf)),
            Some("__stack_chk_fail import/symbol"),
        ),
        security_feature(
            "Stripped",
            Some(is_stripped(elf)),
            Some("symbol table availability"),
        ),
    ]
}

fn nx_enabled(elf: &goblin::elf::Elf<'_>) -> Option<bool> {
    elf.program_headers
        .iter()
        .find(|ph| ph.p_type == PT_GNU_STACK)
        .map(|ph| ph.p_flags & PF_X == 0)
}

fn relro_enabled(elf: &goblin::elf::Elf<'_>) -> Option<bool> {
    Some(
        elf.program_headers
            .iter()
            .any(|ph| ph.p_type == PT_GNU_RELRO),
    )
}

fn relro_status(elf: &goblin::elf::Elf<'_>) -> &'static str {
    let has_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);
    if !has_relro {
        return "none";
    }

    if has_bind_now(elf) { "full" } else { "partial" }
}

fn has_bind_now(elf: &goblin::elf::Elf<'_>) -> bool {
    elf.dynamic
        .as_ref()
        .map(|dynamic| {
            dynamic.dyns.iter().any(|dyn_entry| {
                dyn_entry.d_tag == DT_BIND_NOW
                    || (dyn_entry.d_tag == DT_FLAGS_1 && dyn_entry.d_val & DF_1_NOW != 0)
            })
        })
        .unwrap_or(false)
}

fn has_stack_canary(elf: &goblin::elf::Elf<'_>) -> bool {
    elf.dynsyms.iter().any(|sym| {
        elf.dynstrtab
            .get_at(sym.st_name)
            .map(|name| name == "__stack_chk_fail")
            .unwrap_or(false)
    }) || elf.syms.iter().any(|sym| {
        elf.strtab
            .get_at(sym.st_name)
            .map(|name| name == "__stack_chk_fail")
            .unwrap_or(false)
    })
}

fn is_stripped(elf: &goblin::elf::Elf<'_>) -> bool {
    elf.syms.is_empty()
}

// ── PE analysis ─────────────────────────────────────────────────────────────

fn analyze_pe(pe: &goblin::pe::PE<'_>) -> Vec<SecurityFeature> {
    let dll_chars = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.dll_characteristics)
        .unwrap_or(0);

    vec![
        security_feature(
            "ASLR/DynamicBase",
            Some(dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0),
            Some("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"),
        ),
        security_feature(
            "DEP/NX",
            Some(dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0),
            Some("IMAGE_DLLCHARACTERISTICS_NX_COMPAT"),
        ),
        security_feature(
            "CFG",
            Some(dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0),
            Some("IMAGE_DLLCHARACTERISTICS_GUARD_CF"),
        ),
        security_feature(
            "Integrity",
            Some(dll_chars & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0),
            Some("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"),
        ),
        security_feature(
            "SEH",
            Some(dll_chars & IMAGE_DLLCHARACTERISTICS_NO_SEH == 0),
            Some(if dll_chars & IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 {
                "NO_SEH set — SEH disabled"
            } else {
                "SEH active"
            }),
        ),
        security_feature(
            "High Entropy ASLR",
            Some(dll_chars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0),
            Some("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"),
        ),
    ]
}

// ── Mach-O analysis ─────────────────────────────────────────────────────────

fn analyze_mach(mach: &goblin::mach::Mach) -> Result<Vec<SecurityFeature>> {
    match mach {
        goblin::mach::Mach::Binary(macho) => Ok(analyze_single_macho(macho)),
        goblin::mach::Mach::Fat(fat) => {
            let first = fat.get(0).map_err(|e| {
                RevisorError::Other(format!("failed to read first fat architecture: {e}"))
            })?;
            match first {
                goblin::mach::SingleArch::MachO(macho) => Ok(analyze_single_macho(&macho)),
                goblin::mach::SingleArch::Archive(_) => Err(RevisorError::Other(
                    "checksec does not support archive entries in fat binaries".to_string(),
                )),
            }
        }
    }
}

fn analyze_single_macho(macho: &goblin::mach::MachO<'_>) -> Vec<SecurityFeature> {
    let flags = macho.header.flags;

    let has_canary = macho_has_symbol(macho, "___stack_chk_fail")
        || macho_has_symbol(macho, "___stack_chk_guard");

    let has_arc = macho_has_symbol(macho, "_objc_release");

    vec![
        security_feature("PIE", Some(flags & MH_PIE != 0), Some("MH_PIE header flag")),
        security_feature(
            "Canary",
            Some(has_canary),
            Some("___stack_chk_fail/___stack_chk_guard symbol"),
        ),
        security_feature("ARC", Some(has_arc), Some("_objc_release symbol")),
    ]
}

fn macho_has_symbol(macho: &goblin::mach::MachO<'_>, target: &str) -> bool {
    macho
        .symbols()
        .filter_map(|sym| sym.ok())
        .any(|(name, _)| name == target)
}

// ── Shared helpers ──────────────────────────────────────────────────────────

fn security_feature(name: &str, enabled: Option<bool>, value: Option<&str>) -> SecurityFeature {
    SecurityFeature {
        name: name.to_string(),
        enabled,
        value: value.map(ToString::to_string),
        extra: serde_json::Value::Null,
    }
}

fn format_feature(feature: &SecurityFeature) -> String {
    let status = match feature.enabled {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "unknown",
    };
    match &feature.value {
        Some(value) => format!("{}: {} ({})", feature.name, status, value),
        None => format!("{}: {}", feature.name, status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::ToolAdapter;

    #[test]
    fn checksec_adapter_reports_capabilities() {
        let adapter = ChecksecAdapter;
        let capabilities = adapter.capabilities();

        assert_eq!(adapter.name(), "checksec");
        assert_eq!(adapter.parser_version(), PARSER_VERSION);
        assert_eq!(capabilities.len(), 1);
        assert!(capabilities[0].read_only);
    }

    #[test]
    fn analyzes_elf_fixture() {
        let features = analyze_security_features("tests/crackme").expect("ELF fixture");
        let names: Vec<&str> = features
            .iter()
            .map(|feature| feature.name.as_str())
            .collect();

        assert!(names.contains(&"PIE"));
        assert!(names.contains(&"NX"));
        assert!(names.contains(&"RELRO"));
        assert!(names.contains(&"Canary"));
    }

    #[test]
    fn checksec_adapter_returns_feature_events() {
        let adapter = ChecksecAdapter;
        let events = adapter.run("tests/crackme").expect("ELF fixture");

        assert!(events.iter().any(|event| event.message.starts_with("NX:")));
        assert!(events.iter().all(|event| event.adapter == "checksec"));
    }

    #[test]
    fn pe_dll_characteristics_flags_are_correct() {
        assert_eq!(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, 0x0020);
        assert_eq!(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, 0x0040);
        assert_eq!(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, 0x0080);
        assert_eq!(IMAGE_DLLCHARACTERISTICS_NX_COMPAT, 0x0100);
        assert_eq!(IMAGE_DLLCHARACTERISTICS_NO_SEH, 0x0400);
        assert_eq!(IMAGE_DLLCHARACTERISTICS_GUARD_CF, 0x4000);
    }

    #[test]
    fn macho_pie_flag_is_correct() {
        assert_eq!(MH_PIE, 0x0020_0000);
    }

    #[test]
    fn format_feature_output() {
        let feat = security_feature("TestFeat", Some(true), Some("details"));
        assert_eq!(format_feature(&feat), "TestFeat: enabled (details)");

        let feat_disabled = security_feature("TestFeat", Some(false), None);
        assert_eq!(format_feature(&feat_disabled), "TestFeat: disabled");

        let feat_unknown = security_feature("TestFeat", None, Some("info"));
        assert_eq!(format_feature(&feat_unknown), "TestFeat: unknown (info)");
    }
}
