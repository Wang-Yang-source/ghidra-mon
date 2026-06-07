//! Volatility-style memory/blob triage backed by native Rust scanning.
//!
//! This adapter is a first-pass, always-available memory forensics lane. It
//! does not replace Volatility 3 plugins; it provides quick dump metadata,
//! embedded executable markers, and IOC strings as structured events until a
//! full external `volatility3 --renderer json` adapter is added.

use crate::adapter::ToolAdapter;
use crate::adapter::schema::{AdapterCapability, Finding, MemoryRegion, ToolEvent, ToolEventKind};
use crate::error::{Result, RevisorError};
use crate::toolkit::native_rust_capability;
use crate::toolkit::strings::extract_strings;
use memmap2::Mmap;
use serde::Serialize;
use std::fs::File;

/// Parser version string emitted in capability metadata.
pub const PARSER_VERSION: &str = "native-volatility-v1";

const MAX_REGIONS: usize = 256;
const IOC_MIN_LEN: usize = 5;

#[derive(Debug, Clone, Serialize)]
struct DumpInfo {
    size: u64,
    scan: String,
}

/// Native memory/blob triage adapter.
pub struct VolatilityAdapter;

impl ToolAdapter for VolatilityAdapter {
    fn name(&self) -> &'static str {
        "volatility"
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn capabilities(&self) -> Vec<AdapterCapability> {
        vec![native_rust_capability("memory_dump_triage")]
    }

    fn run(&self, target: &str) -> Result<Vec<ToolEvent>> {
        triage_memory_dump(target)
    }
}

/// Triage a memory dump or arbitrary binary blob.
pub fn triage_memory_dump(path: &str) -> Result<Vec<ToolEvent>> {
    let file = File::open(path).map_err(|e| RevisorError::io("open memory dump", e))?;
    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| RevisorError::io("mmap memory dump", e))?;
    let bytes = &mmap[..];

    let mut events = vec![dump_info_event(bytes.len() as u64)];
    events.extend(scan_executable_regions(bytes));
    events.extend(scan_ioc_strings(path)?);

    Ok(events)
}

fn dump_info_event(size: u64) -> ToolEvent {
    let info = DumpInfo {
        size,
        scan: "native byte-pattern triage".to_string(),
    };

    ToolEvent {
        adapter: "volatility".to_string(),
        kind: ToolEventKind::BinaryInfo,
        message: format!("memory/blob size {} bytes", size),
        address: None,
        raw: None,
        data: serde_json::to_value(info).unwrap_or(serde_json::Value::Null),
    }
}

fn scan_executable_regions(bytes: &[u8]) -> Vec<ToolEvent> {
    let mut events = Vec::new();
    for offset in 0..bytes.len().saturating_sub(4) {
        if events.len() >= MAX_REGIONS {
            break;
        }

        let marker = if bytes[offset..].starts_with(b"\x7fELF") {
            Some(("ELF image marker", "elf"))
        } else if bytes[offset..].starts_with(b"MZ") {
            Some(("MZ/PE image marker", "pe"))
        } else {
            None
        };

        if let Some((label, format)) = marker {
            let region = MemoryRegion {
                address: None,
                offset: offset as u64,
                size: estimate_region_size(bytes, offset),
                label: label.to_string(),
                permissions: None,
                extra: serde_json::json!({ "format": format }),
            };
            events.push(memory_region_event(region));
        }
    }

    events
}

fn scan_ioc_strings(path: &str) -> Result<Vec<ToolEvent>> {
    let strings = extract_strings(path, IOC_MIN_LEN)?;
    let mut events = Vec::new();

    for hit in strings {
        let lower = hit.value.to_ascii_lowercase();
        let finding = if lower.contains("cmd.exe")
            || lower.contains("powershell")
            || lower.contains("/bin/sh")
        {
            Some(finding(
                "Shell artifact in memory/blob",
                "high",
                Some(hit.address.clone()),
                format!("Command shell string `{}` found.", hit.value),
                serde_json::json!({ "string": hit.value, "encoding": hit.encoding }),
            ))
        } else if lower.contains("http://") || lower.contains("https://") {
            Some(finding(
                "Network URL in memory/blob",
                "medium",
                Some(hit.address.clone()),
                format!("URL string `{}` found.", hit.value),
                serde_json::json!({ "string": hit.value, "encoding": hit.encoding }),
            ))
        } else if lower.contains("password")
            || lower.contains("passwd")
            || lower.contains("secret")
            || lower.contains("token")
        {
            Some(finding(
                "Credential-like string in memory/blob",
                "medium",
                Some(hit.address.clone()),
                format!("Credential-like string `{}` found.", hit.value),
                serde_json::json!({ "string": hit.value, "encoding": hit.encoding }),
            ))
        } else {
            None
        };

        if let Some(finding) = finding {
            events.push(finding_event(finding));
        }
    }

    Ok(events)
}

fn memory_region_event(region: MemoryRegion) -> ToolEvent {
    ToolEvent {
        adapter: "volatility".to_string(),
        kind: ToolEventKind::MemoryRegion,
        message: format!(
            "0x{:x}: {} size {}",
            region.offset, region.label, region.size
        ),
        address: region.address.clone(),
        raw: None,
        data: serde_json::to_value(region).unwrap_or(serde_json::Value::Null),
    }
}

fn finding(
    title: &str,
    severity: &str,
    address: Option<String>,
    description: String,
    evidence: serde_json::Value,
) -> Finding {
    Finding {
        title: title.to_string(),
        severity: Some(severity.to_string()),
        address,
        description,
        source: "volatility.native".to_string(),
        extra: serde_json::json!({ "evidence": evidence }),
    }
}

fn finding_event(finding: Finding) -> ToolEvent {
    let severity = finding
        .severity
        .clone()
        .unwrap_or_else(|| "info".to_string());
    ToolEvent {
        adapter: "volatility".to_string(),
        kind: ToolEventKind::Finding,
        message: format!("[{}] {}: {}", severity, finding.title, finding.description),
        address: finding.address.clone(),
        raw: None,
        data: serde_json::to_value(finding).unwrap_or(serde_json::Value::Null),
    }
}

fn estimate_region_size(bytes: &[u8], offset: usize) -> u64 {
    bytes
        .len()
        .saturating_sub(offset)
        .min(1024 * 1024)
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::ToolAdapter;

    #[test]
    fn volatility_adapter_reports_capabilities() {
        let adapter = VolatilityAdapter;
        let capabilities = adapter.capabilities();

        assert_eq!(adapter.name(), "volatility");
        assert_eq!(adapter.parser_version(), PARSER_VERSION);
        assert_eq!(capabilities.len(), 1);
        assert!(capabilities[0].read_only);
        assert_eq!(capabilities[0].name, "memory_dump_triage");
    }

    #[test]
    fn scans_crackme_as_blob() {
        let events = triage_memory_dump("tests/crackme").expect("scan blob");

        assert!(!events.is_empty());
        assert!(
            events
                .iter()
                .any(|event| event.kind == ToolEventKind::BinaryInfo)
        );
        assert!(
            events
                .iter()
                .any(|event| event.kind == ToolEventKind::MemoryRegion)
        );
    }

    #[test]
    fn finds_credential_like_blob_strings() {
        let events = triage_memory_dump("tests/crackme").expect("scan blob");

        assert!(events.iter().any(|event| {
            event.kind == ToolEventKind::Finding && event.message.contains("Credential-like string")
        }));
    }

    #[test]
    fn adapter_run_returns_events() {
        let adapter = VolatilityAdapter;
        let events = adapter.run("tests/crackme").expect("run adapter");

        assert!(!events.is_empty());
        assert!(events.iter().all(|event| event.adapter == "volatility"));
    }
}
