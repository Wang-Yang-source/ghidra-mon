use crate::adapter::ToolAdapter;
use crate::adapter::schema::{FirmwareEntry, ToolEvent, ToolEventKind};
use crate::error::{Result, RevisorError};
use crate::toolkit::native_rust_capability;
use std::fs;

pub struct BinwalkAdapter;

impl ToolAdapter for BinwalkAdapter {
    fn name(&self) -> &'static str {
        "binwalk"
    }

    fn parser_version(&self) -> &'static str {
        "native-rust-v1"
    }

    fn capabilities(&self) -> Vec<crate::adapter::schema::AdapterCapability> {
        vec![native_rust_capability("firmware_signatures")]
    }

    fn run(&self, target: &str) -> Result<Vec<ToolEvent>> {
        let entries = scan_entries(target).map_err(|e| RevisorError::Other(e.to_string()))?;
        if entries.is_empty() {
            return Ok(vec![ToolEvent::status(self.name(), "No signatures found.")]);
        }

        Ok(entries
            .into_iter()
            .map(|entry| ToolEvent {
                adapter: self.name().to_string(),
                kind: ToolEventKind::FirmwareEntry,
                message: format!("0x{:x}: {}", entry.offset, entry.description),
                address: Some(format!("0x{:x}", entry.offset)),
                raw: None,
                data: serde_json::to_value(entry).unwrap_or(serde_json::Value::Null),
            })
            .collect())
    }
}

pub fn scan_entries(file_path: &str) -> Result<Vec<FirmwareEntry>> {
    let file_data = fs::read(file_path).map_err(|e| RevisorError::io("read binwalk target", e))?;
    let binwalker = binwalk::Binwalk::new();

    Ok(binwalker
        .scan(&file_data)
        .into_iter()
        .map(|result| FirmwareEntry {
            offset: result.offset as u64,
            description: result.description,
        })
        .collect())
}

pub fn scan_signatures(
    file_path: &str,
) -> std::result::Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut results: Vec<String> = scan_entries(file_path)?
        .into_iter()
        .map(|entry| format!("0x{:x}: {}", entry.offset, entry.description))
        .collect();

    if results.is_empty() {
        results.push("No signatures found.".to_string());
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::ToolAdapter;

    #[test]
    fn binwalk_adapter_reports_capabilities() {
        let adapter = BinwalkAdapter;
        let capabilities = adapter.capabilities();

        assert_eq!(adapter.name(), "binwalk");
        assert_eq!(adapter.parser_version(), "native-rust-v1");
        assert_eq!(capabilities.len(), 1);
        assert!(capabilities[0].read_only);
    }

    #[test]
    fn binwalk_adapter_returns_events_for_fixture() {
        let adapter = BinwalkAdapter;
        let events = adapter
            .run("third_party/binwalk/tests/inputs/png_malformed.bin")
            .expect("binwalk fixture should scan");

        assert!(!events.is_empty());
        assert!(events.iter().all(|event| event.adapter == "binwalk"));
    }
}
