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
pub const PARSER_VERSION: &str = "native-elf-checksec-v1";

/// ELF security hardening checker backed by [`goblin`].
///
/// Checks for PIE, NX (non-executable stack), RELRO (full/partial),
/// stack canaries, and symbol table stripping. Currently supports
/// ELF targets; PE and Mach-O support is planned.
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
            name: "elf_security_features".to_string(),
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

/// Analyze an ELF binary and return its security hardening features.
///
/// Returns PIE, NX, RELRO, Canary, and Stripped status. Currently
/// only ELF is supported; PE and Mach-O targets return an error.
pub fn analyze_security_features(file_path: &str) -> Result<Vec<SecurityFeature>> {
    let buffer = fs::read(file_path).map_err(|e| RevisorError::io("read checksec target", e))?;
    match Object::parse(&buffer).map_err(|e| RevisorError::Other(format!("parse target: {e}")))? {
        Object::Elf(elf) => Ok(analyze_elf(&elf)),
        Object::PE(_) => Err(RevisorError::Other(
            "checksec currently supports ELF targets; PE support is planned".to_string(),
        )),
        Object::Mach(_) => Err(RevisorError::Other(
            "checksec currently supports ELF targets; Mach-O support is planned".to_string(),
        )),
        _ => Err(RevisorError::Other(
            "checksec target is not a supported executable".to_string(),
        )),
    }
}

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
}
