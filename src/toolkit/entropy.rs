//! Shannon entropy analysis for packer/compression triage.
//!
//! This native adapter gives Ghidrai an always-available first pass for
//! spotting packed, encrypted, compressed, or suspiciously uniform regions.

use crate::adapter::ToolAdapter;
use crate::adapter::schema::{AdapterCapability, Finding, ToolEvent, ToolEventKind};
use crate::error::{Result, RevisorError};
use crate::toolkit::native_rust_capability;
use goblin::Object;
use serde::Serialize;
use std::fs;

pub const PARSER_VERSION: &str = "native-entropy-v1";

const HIGH_ENTROPY_THRESHOLD: f64 = 7.20;
const VERY_HIGH_ENTROPY_THRESHOLD: f64 = 7.80;
const LOW_ENTROPY_THRESHOLD: f64 = 1.00;
const MAX_REGION_EVENTS: usize = 256;

#[derive(Debug, Clone, Serialize)]
struct EntropySummary {
    entropy: f64,
    size: usize,
    high_entropy_regions: usize,
    low_entropy_regions: usize,
}

#[derive(Debug, Clone, Serialize)]
struct EntropyRegion {
    name: String,
    offset: u64,
    address: Option<String>,
    size: usize,
    entropy: f64,
    executable: Option<bool>,
    writable: Option<bool>,
}

pub struct EntropyAdapter;

impl ToolAdapter for EntropyAdapter {
    fn name(&self) -> &'static str {
        "entropy"
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn capabilities(&self) -> Vec<AdapterCapability> {
        vec![native_rust_capability("entropy_packer_triage")]
    }

    fn run(&self, target: &str) -> Result<Vec<ToolEvent>> {
        analyze_entropy(target)
    }
}

pub fn analyze_entropy(path: &str) -> Result<Vec<ToolEvent>> {
    let bytes = fs::read(path).map_err(|e| RevisorError::io("read entropy target", e))?;
    let regions = entropy_regions(&bytes);
    let mut events = Vec::new();

    let high_count = regions
        .iter()
        .filter(|region| region.entropy >= HIGH_ENTROPY_THRESHOLD)
        .count();
    let low_count = regions
        .iter()
        .filter(|region| region.entropy <= LOW_ENTROPY_THRESHOLD && region.size > 0)
        .count();

    events.push(summary_event(EntropySummary {
        entropy: shannon_entropy(&bytes),
        size: bytes.len(),
        high_entropy_regions: high_count,
        low_entropy_regions: low_count,
    }));

    for region in regions.into_iter().take(MAX_REGION_EVENTS) {
        if let Some(finding) = region_finding(&region) {
            events.push(finding_event(finding));
        }
        events.push(region_event(region));
    }

    Ok(events)
}

fn entropy_regions(bytes: &[u8]) -> Vec<EntropyRegion> {
    match Object::parse(bytes) {
        Ok(Object::Elf(elf)) => {
            let mut regions = Vec::new();
            for section in &elf.section_headers {
                let size = section.sh_size as usize;
                let offset = section.sh_offset as usize;
                if size == 0 {
                    continue;
                }
                if let Some(end) = offset.checked_add(size) {
                    if end > bytes.len() {
                        continue;
                    }
                    let name = elf
                        .shdr_strtab
                        .get_at(section.sh_name)
                        .unwrap_or("")
                        .to_string();
                    regions.push(EntropyRegion {
                        name,
                        offset: offset as u64,
                        address: Some(format!("0x{:x}", section.sh_addr)),
                        size,
                        entropy: shannon_entropy(&bytes[offset..end]),
                        executable: Some(
                            section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64
                                != 0,
                        ),
                        writable: Some(
                            section.sh_flags & goblin::elf::section_header::SHF_WRITE as u64 != 0,
                        ),
                    });
                }
            }
            fallback_if_empty(regions, bytes)
        }
        Ok(Object::PE(pe)) => {
            const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
            const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
            let image_base = pe.image_base;
            let mut regions = Vec::new();
            for section in &pe.sections {
                let size = section.size_of_raw_data as usize;
                let offset = section.pointer_to_raw_data as usize;
                if size == 0 {
                    continue;
                }
                if let Some(end) = offset.checked_add(size) {
                    if end > bytes.len() {
                        continue;
                    }
                    let name = String::from_utf8_lossy(&section.name)
                        .trim_end_matches('\0')
                        .to_string();
                    regions.push(EntropyRegion {
                        name,
                        offset: offset as u64,
                        address: Some(format!(
                            "0x{:x}",
                            image_base + section.virtual_address as u64
                        )),
                        size,
                        entropy: shannon_entropy(&bytes[offset..end]),
                        executable: Some(section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0),
                        writable: Some(section.characteristics & IMAGE_SCN_MEM_WRITE != 0),
                    });
                }
            }
            fallback_if_empty(regions, bytes)
        }
        _ => vec![EntropyRegion {
            name: "file".to_string(),
            offset: 0,
            address: None,
            size: bytes.len(),
            entropy: shannon_entropy(bytes),
            executable: None,
            writable: None,
        }],
    }
}

fn fallback_if_empty(mut regions: Vec<EntropyRegion>, bytes: &[u8]) -> Vec<EntropyRegion> {
    if regions.is_empty() {
        regions.push(EntropyRegion {
            name: "file".to_string(),
            offset: 0,
            address: None,
            size: bytes.len(),
            entropy: shannon_entropy(bytes),
            executable: None,
            writable: None,
        });
    }
    regions
}

pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }

    let len = bytes.len() as f64;
    let entropy: f64 = counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum();

    if entropy == 0.0 { 0.0 } else { entropy }
}

fn summary_event(summary: EntropySummary) -> ToolEvent {
    ToolEvent {
        adapter: "entropy".to_string(),
        kind: ToolEventKind::BinaryInfo,
        message: format!(
            "entropy {:.2} over {} bytes ({} high, {} low regions)",
            summary.entropy,
            summary.size,
            summary.high_entropy_regions,
            summary.low_entropy_regions
        ),
        address: None,
        raw: None,
        data: serde_json::to_value(summary).unwrap_or(serde_json::Value::Null),
    }
}

fn region_event(region: EntropyRegion) -> ToolEvent {
    ToolEvent {
        adapter: "entropy".to_string(),
        kind: ToolEventKind::Section,
        message: format!(
            "{} entropy {:.2} size {}",
            region.name, region.entropy, region.size
        ),
        address: region.address.clone(),
        raw: None,
        data: serde_json::to_value(region).unwrap_or(serde_json::Value::Null),
    }
}

fn region_finding(region: &EntropyRegion) -> Option<Finding> {
    let executable = region.executable.unwrap_or(false);
    let writable = region.writable.unwrap_or(false);

    let (title, severity, description) = if region.entropy >= VERY_HIGH_ENTROPY_THRESHOLD {
        (
            "Very high entropy region",
            "high",
            format!(
                "{} has entropy {:.2}; this often indicates packing, encryption, or compression.",
                region.name, region.entropy
            ),
        )
    } else if region.entropy >= HIGH_ENTROPY_THRESHOLD && executable {
        (
            "High entropy executable region",
            "medium",
            format!(
                "{} is executable and has entropy {:.2}; packed code is possible.",
                region.name, region.entropy
            ),
        )
    } else if executable && writable {
        (
            "Writable executable region",
            "high",
            format!("{} is both writable and executable.", region.name),
        )
    } else {
        return None;
    };

    Some(Finding {
        title: title.to_string(),
        severity: Some(severity.to_string()),
        address: region.address.clone(),
        description,
        source: "entropy.native".to_string(),
        extra: serde_json::json!({
            "region": region.name,
            "offset": region.offset,
            "size": region.size,
            "entropy": region.entropy,
            "executable": region.executable,
            "writable": region.writable,
        }),
    })
}

fn finding_event(finding: Finding) -> ToolEvent {
    let severity = finding
        .severity
        .clone()
        .unwrap_or_else(|| "info".to_string());
    ToolEvent {
        adapter: "entropy".to_string(),
        kind: ToolEventKind::Finding,
        message: format!("[{}] {}: {}", severity, finding.title, finding.description),
        address: finding.address.clone(),
        raw: None,
        data: serde_json::to_value(finding).unwrap_or(serde_json::Value::Null),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::ToolAdapter;

    #[test]
    fn entropy_adapter_reports_capabilities() {
        let adapter = EntropyAdapter;
        let capabilities = adapter.capabilities();

        assert_eq!(adapter.name(), "entropy");
        assert_eq!(adapter.parser_version(), PARSER_VERSION);
        assert_eq!(capabilities.len(), 1);
        assert!(capabilities[0].read_only);
        assert_eq!(capabilities[0].name, "entropy_packer_triage");
    }

    #[test]
    fn shannon_entropy_handles_empty_and_uniform_data() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0; 32]), 0.0);
    }

    #[test]
    fn shannon_entropy_detects_high_entropy_distribution() {
        let bytes: Vec<u8> = (0..=255).collect();
        let entropy = shannon_entropy(&bytes);

        assert!((entropy - 8.0).abs() < 0.001);
    }

    #[test]
    fn scans_crackme_sections() {
        let events = analyze_entropy("tests/crackme").expect("entropy scan");

        assert!(
            events
                .iter()
                .any(|event| event.kind == ToolEventKind::BinaryInfo)
        );
        assert!(
            events.iter().any(
                |event| event.kind == ToolEventKind::Section && event.message.contains(".text")
            )
        );
    }

    #[test]
    fn high_entropy_region_produces_finding() {
        let region = EntropyRegion {
            name: ".packed".to_string(),
            offset: 0,
            address: Some("0x401000".to_string()),
            size: 256,
            entropy: 8.0,
            executable: Some(true),
            writable: Some(false),
        };

        assert!(region_finding(&region).is_some());
    }
}
