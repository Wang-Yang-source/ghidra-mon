//! Rust-native CWE-style risk scanner.
//!
//! This is not a full replacement for upstream CWE_Checker. It is a fast,
//! always-available first pass that combines native object inspection,
//! hardening checks, and string extraction into structured `Finding` events.
//! A future external CWE_Checker adapter can coexist behind the same event
//! model.

use crate::adapter::ToolAdapter;
use crate::adapter::schema::{AdapterCapability, Finding, ToolEvent, ToolEventKind};
use crate::error::Result;
use crate::toolkit::checksec::analyze_security_features;
use crate::toolkit::lief::inspect_object;
use crate::toolkit::native_rust_capability;
use crate::toolkit::strings::extract_strings;
use std::collections::HashSet;

/// Parser version string emitted in capability metadata.
pub const PARSER_VERSION: &str = "native-cwe-v1";

/// Native findings adapter for quick CWE-style triage.
pub struct CweAdapter;

impl ToolAdapter for CweAdapter {
    fn name(&self) -> &'static str {
        "cwe"
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn capabilities(&self) -> Vec<AdapterCapability> {
        vec![native_rust_capability("cwe_style_findings")]
    }

    fn run(&self, target: &str) -> Result<Vec<ToolEvent>> {
        scan_findings(target)
    }
}

/// Scan a binary for lightweight CWE-style findings.
pub fn scan_findings(target: &str) -> Result<Vec<ToolEvent>> {
    let mut findings = Vec::new();

    findings.extend(import_findings(target)?);
    findings.extend(hardening_findings(target));
    findings.extend(string_findings(target)?);

    if findings.is_empty() {
        return Ok(vec![ToolEvent::status(
            "cwe",
            "No CWE-style findings found.",
        )]);
    }

    Ok(dedup_findings(findings)
        .into_iter()
        .map(finding_event)
        .collect())
}

fn import_findings(target: &str) -> Result<Vec<Finding>> {
    let events = inspect_object(target)?;
    let mut findings = Vec::new();

    for event in events
        .into_iter()
        .filter(|event| event.kind == ToolEventKind::Symbol)
    {
        let name = event
            .data
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let kind = event
            .data
            .get("kind")
            .and_then(|value| value.as_str())
            .unwrap_or("");

        if name.is_empty() || !(kind == "import" || event.address.is_none()) {
            continue;
        }

        if matches_any(name, &["gets", "strcpy", "strcat", "sprintf", "vsprintf"]) {
            findings.push(finding(
                "CWE-120",
                "high",
                event.address.clone(),
                format!("Unsafe copy/format import `{name}` may allow buffer overflow."),
                "lief.imports",
                serde_json::json!({ "symbol": name, "kind": kind }),
            ));
        } else if matches_any(
            name,
            &[
                "system", "popen", "execl", "execle", "execlp", "execv", "execve", "execvp",
            ],
        ) {
            findings.push(finding(
                "CWE-78",
                "high",
                event.address.clone(),
                format!("Command execution import `{name}` requires input-flow review."),
                "lief.imports",
                serde_json::json!({ "symbol": name, "kind": kind }),
            ));
        } else if matches_any(
            name,
            &["printf", "fprintf", "snprintf", "vprintf", "vfprintf"],
        ) {
            findings.push(finding(
                "CWE-134",
                "medium",
                event.address.clone(),
                format!("Format function `{name}` is present; verify format strings are constant."),
                "lief.imports",
                serde_json::json!({ "symbol": name, "kind": kind }),
            ));
        } else if matches_any(name, &["scanf", "sscanf", "fscanf"]) {
            findings.push(finding(
                "CWE-20",
                "medium",
                event.address.clone(),
                format!("Input parsing import `{name}` needs bounds and validation review."),
                "lief.imports",
                serde_json::json!({ "symbol": name, "kind": kind }),
            ));
        }
    }

    Ok(findings)
}

fn hardening_findings(target: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(features) = analyze_security_features(target) else {
        return findings;
    };

    for feature in features {
        match (feature.name.as_str(), feature.enabled) {
            ("Canary", Some(false)) => findings.push(finding(
                "CWE-121",
                "medium",
                None,
                "Stack canary is disabled; stack-based overflow exploitation may be easier.",
                "checksec",
                serde_json::json!({ "feature": feature.name, "value": feature.value }),
            )),
            ("NX" | "DEP/NX", Some(false)) => findings.push(finding(
                "CWE-787",
                "high",
                None,
                "NX/DEP is disabled; injected code execution may be possible after memory corruption.",
                "checksec",
                serde_json::json!({ "feature": feature.name, "value": feature.value }),
            )),
            ("PIE" | "ASLR/DynamicBase", Some(false)) => findings.push(finding(
                "CWE-119",
                "low",
                None,
                "PIE/ASLR is disabled or unavailable; fixed code addresses simplify exploitation.",
                "checksec",
                serde_json::json!({ "feature": feature.name, "value": feature.value }),
            )),
            ("RELRO", Some(false)) => findings.push(finding(
                "CWE-123",
                "medium",
                None,
                "RELRO is disabled; GOT overwrite style attacks may be easier.",
                "checksec",
                serde_json::json!({ "feature": feature.name, "value": feature.value }),
            )),
            _ => {}
        }
    }

    findings
}

fn string_findings(target: &str) -> Result<Vec<Finding>> {
    let hits = extract_strings(target, 4)?;
    let mut findings = Vec::new();

    for hit in hits {
        let lower = hit.value.to_ascii_lowercase();
        if lower.contains("/bin/sh") || lower.contains("cmd.exe") || lower.contains("powershell") {
            findings.push(finding(
                "CWE-78",
                "high",
                Some(hit.address.clone()),
                format!("Command shell string `{}` found in binary.", hit.value),
                "strings",
                serde_json::json!({ "string": hit.value, "encoding": hit.encoding }),
            ));
        } else if lower.contains("password")
            || lower.contains("passwd")
            || lower.contains("secret")
            || lower.contains("token")
            || lower.contains("apikey")
        {
            findings.push(finding(
                "CWE-798",
                "medium",
                Some(hit.address.clone()),
                format!("Credential-like string `{}` found in binary.", hit.value),
                "strings",
                serde_json::json!({ "string": hit.value, "encoding": hit.encoding }),
            ));
        } else if lower.contains("http://") {
            findings.push(finding(
                "CWE-319",
                "low",
                Some(hit.address.clone()),
                format!("Plaintext URL `{}` found in binary.", hit.value),
                "strings",
                serde_json::json!({ "string": hit.value, "encoding": hit.encoding }),
            ));
        }
    }

    Ok(findings)
}

fn finding(
    cwe: &str,
    severity: &str,
    address: Option<String>,
    description: impl Into<String>,
    source: impl Into<String>,
    evidence: serde_json::Value,
) -> Finding {
    let description = description.into();
    Finding {
        title: cwe.to_string(),
        severity: Some(severity.to_string()),
        address,
        description,
        source: source.into(),
        extra: serde_json::json!({
            "cwe": cwe,
            "evidence": evidence,
        }),
    }
}

fn finding_event(finding: Finding) -> ToolEvent {
    let address = finding.address.clone();
    let severity = finding
        .severity
        .clone()
        .unwrap_or_else(|| "info".to_string());
    ToolEvent {
        adapter: "cwe".to_string(),
        kind: ToolEventKind::Finding,
        message: format!("[{}] {}: {}", severity, finding.title, finding.description),
        address,
        raw: None,
        data: serde_json::to_value(finding).unwrap_or(serde_json::Value::Null),
    }
}

fn dedup_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = HashSet::new();
    findings
        .into_iter()
        .filter(|finding| {
            seen.insert(format!(
                "{}|{}|{}",
                finding.title,
                finding.address.clone().unwrap_or_default(),
                finding.description
            ))
        })
        .collect()
}

fn matches_any(name: &str, candidates: &[&str]) -> bool {
    candidates.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::ToolAdapter;

    #[test]
    fn cwe_adapter_reports_capabilities() {
        let adapter = CweAdapter;
        let capabilities = adapter.capabilities();

        assert_eq!(adapter.name(), "cwe");
        assert_eq!(adapter.parser_version(), PARSER_VERSION);
        assert_eq!(capabilities.len(), 1);
        assert!(capabilities[0].read_only);
        assert_eq!(capabilities[0].name, "cwe_style_findings");
    }

    #[test]
    fn scans_crackme_for_findings() {
        let events = scan_findings("tests/crackme").expect("scan crackme");

        assert!(!events.is_empty());
        assert!(events.iter().all(|event| event.adapter == "cwe"));
        assert!(
            events
                .iter()
                .any(|event| event.kind == ToolEventKind::Finding)
        );
    }

    #[test]
    fn finds_credential_like_strings_in_fixture() {
        let events = scan_findings("tests/crackme").expect("scan crackme");

        assert!(events.iter().any(|event| {
            event.kind == ToolEventKind::Finding
                && event
                    .data
                    .get("extra")
                    .and_then(|extra| extra.get("cwe"))
                    .and_then(|cwe| cwe.as_str())
                    == Some("CWE-798")
        }));
    }

    #[test]
    fn finding_events_have_structured_data() {
        let event = finding_event(finding(
            "CWE-120",
            "high",
            Some("0x10".to_string()),
            "demo",
            "test",
            serde_json::json!({ "symbol": "gets" }),
        ));

        assert_eq!(event.kind, ToolEventKind::Finding);
        assert_eq!(event.address.as_deref(), Some("0x10"));
        assert_eq!(
            event.data.get("title").and_then(|value| value.as_str()),
            Some("CWE-120")
        );
    }
}
