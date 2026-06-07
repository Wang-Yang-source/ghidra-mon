//! Pure Rust string extraction adapter.
//!
//! Memory-maps a binary file and scans byte-by-byte for printable ASCII
//! and UTF-8 encoded strings of configurable minimum length. Results are
//! emitted as [`StringHit`] events.

use crate::adapter::ToolAdapter;
use crate::adapter::schema::{AdapterCapability, StringHit, ToolEvent, ToolEventKind};
use crate::error::{Result, RevisorError};
use crate::toolkit::native_rust_capability;
use memmap2::Mmap;
use std::fs::File;

/// Default minimum string length for extraction.
const DEFAULT_MIN_LEN: usize = 4;

/// Maximum number of strings returned to avoid unbounded output.
const MAX_STRINGS: usize = 2000;

/// Parser version string emitted in capability metadata.
pub const PARSER_VERSION: &str = "native-rust-strings-v1";

/// Native Rust string extraction adapter.
///
/// Scans a binary file for printable ASCII sequences (bytes `0x20..=0x7E`)
/// and valid UTF-8 multi-byte sequences, returning all strings that meet
/// the minimum length threshold (default 4).
pub struct StringsAdapter;

impl ToolAdapter for StringsAdapter {
    fn name(&self) -> &'static str {
        "strings"
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn capabilities(&self) -> Vec<AdapterCapability> {
        vec![native_rust_capability("string_extraction")]
    }

    fn run(&self, target: &str) -> Result<Vec<ToolEvent>> {
        let hits = extract_strings(target, DEFAULT_MIN_LEN)?;
        Ok(hits
            .into_iter()
            .map(|hit| ToolEvent {
                adapter: self.name().to_string(),
                kind: ToolEventKind::StringHit,
                message: format!("{}: {}", hit.address, hit.value),
                address: Some(hit.address.clone()),
                raw: None,
                data: serde_json::to_value(&hit).unwrap_or(serde_json::Value::Null),
            })
            .collect())
    }
}

/// Extract printable strings from a binary file.
///
/// Memory-maps `path` and scans through every byte looking for runs of
/// printable ASCII (`0x20..=0x7E`) or valid UTF-8 multi-byte characters.
/// Only strings whose decoded character count is at least `min_len` are
/// returned. Output is capped at [`MAX_STRINGS`] entries.
pub fn extract_strings(path: &str, min_len: usize) -> Result<Vec<StringHit>> {
    let file = File::open(path).map_err(|e| RevisorError::io("open binary", e))?;
    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| RevisorError::io("mmap binary", e))?;
    let data = &mmap[..];

    let mut hits = Vec::new();
    let mut i = 0;

    while i < data.len() {
        if hits.len() >= MAX_STRINGS {
            break;
        }

        // Try UTF-8 multi-byte sequence first (leading byte 0x80+).
        if data[i] & 0x80 != 0 {
            if let Some((s, consumed)) = try_utf8_string(data, i, min_len) {
                let addr = format!("0x{:x}", i);
                hits.push(StringHit {
                    address: addr,
                    value: s,
                    encoding: Some("utf-8".to_string()),
                    extra: serde_json::json!({}),
                });
                i += consumed;
                continue;
            }
            i += 1;
            continue;
        }

        // Printable ASCII range: 0x20..=0x7E
        if is_printable_ascii(data[i]) {
            let start = i;
            while i < data.len() && is_printable_ascii(data[i]) {
                i += 1;
            }
            let len = i - start;
            if len >= min_len {
                let value = String::from_utf8_lossy(&data[start..i]).into_owned();
                let addr = format!("0x{:x}", start);
                hits.push(StringHit {
                    address: addr,
                    value,
                    encoding: Some("ascii".to_string()),
                    extra: serde_json::json!({}),
                });
            }
            continue;
        }

        i += 1;
    }

    Ok(hits)
}

/// Returns `true` for printable ASCII bytes (space through tilde).
#[inline]
fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

/// Try to decode a UTF-8 string starting at `offset` that contains at
/// least one multi-byte character. Returns `(decoded_string, bytes_consumed)`
/// if the run is at least `min_len` characters long.
fn try_utf8_string(data: &[u8], offset: usize, min_len: usize) -> Option<(String, usize)> {
    let remaining = &data[offset..];

    // Find the longest prefix that decodes as valid UTF-8 consisting of
    // printable characters (ASCII printable or non-ASCII codepoints).
    let mut char_count = 0usize;
    let mut byte_len = 0usize;
    let mut has_multibyte = false;

    let mut iter = remaining.iter().copied().peekable();
    let mut pos = 0;

    while iter.peek().is_some() {
        // Try to decode one UTF-8 character from the remaining slice.
        let sub = &remaining[pos..];
        let ch = match std::str::from_utf8(sub) {
            Ok(s) => s.chars().next(),
            Err(e) => {
                let valid_up_to = e.valid_up_to();
                if valid_up_to > 0 {
                    // There is a valid prefix — grab the next char from it.
                    let valid = unsafe { std::str::from_utf8_unchecked(&sub[..valid_up_to]) };
                    valid.chars().next()
                } else {
                    None
                }
            }
        };

        match ch {
            Some(c) if c >= ' ' && !c.is_control() => {
                let clen = c.len_utf8();
                if clen > 1 {
                    has_multibyte = true;
                }
                char_count += 1;
                byte_len += clen;
                pos += clen;
                // Advance the byte iterator by clen.
                for _ in 0..clen {
                    iter.next();
                }
            }
            _ => break,
        }
    }

    // Only return if we found multi-byte chars (otherwise the ASCII scanner
    // handles pure ASCII) and the string is long enough.
    if has_multibyte && char_count >= min_len {
        let s = String::from_utf8_lossy(&remaining[..byte_len]).into_owned();
        Some((s, byte_len))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::ToolAdapter;

    #[test]
    fn strings_adapter_reports_capabilities() {
        let adapter = StringsAdapter;
        let capabilities = adapter.capabilities();

        assert_eq!(adapter.name(), "strings");
        assert_eq!(adapter.parser_version(), PARSER_VERSION);
        assert_eq!(capabilities.len(), 1);
        assert!(capabilities[0].read_only);
    }

    #[test]
    fn extracts_strings_from_crackme() {
        let hits = extract_strings("tests/crackme", DEFAULT_MIN_LEN).expect("extract strings");
        assert!(!hits.is_empty(), "should find at least one string");

        // Every hit must have a non-empty value.
        for hit in &hits {
            assert!(!hit.value.is_empty(), "string value must not be empty");
            assert!(
                hit.address.starts_with("0x"),
                "address should be hex: {}",
                hit.address
            );
            assert!(
                hit.encoding.is_some(),
                "encoding should be set for: {}",
                hit.value
            );
        }
    }

    #[test]
    fn adapter_run_returns_string_hit_events() {
        let adapter = StringsAdapter;
        let events = adapter.run("tests/crackme").expect("run on crackme");

        assert!(!events.is_empty());
        assert!(events.iter().all(|e| e.adapter == "strings"));
        assert!(events.iter().all(|e| e.kind == ToolEventKind::StringHit));

        // Events should have address set and a message like "0x...: value".
        for event in &events {
            assert!(event.address.is_some());
            assert!(event.message.contains(": "));
        }
    }

    #[test]
    fn respects_minimum_length() {
        let hits = extract_strings("tests/crackme", 8).expect("min_len 8");
        for hit in &hits {
            // Every returned string should have at least 8 printable characters.
            let char_count: usize = hit.value.chars().count();
            assert!(
                char_count >= 8,
                "expected >= 8 chars, got {} for '{}'",
                char_count,
                hit.value
            );
        }
    }

    #[test]
    fn output_capped_at_max() {
        let hits = extract_strings("tests/crackme", 1).expect("min_len 1");
        assert!(
            hits.len() <= MAX_STRINGS,
            "should not exceed {} strings, got {}",
            MAX_STRINGS,
            hits.len()
        );
    }

    #[test]
    fn data_field_has_string_hit_json() {
        let adapter = StringsAdapter;
        let events = adapter.run("tests/crackme").expect("run on crackme");
        let event = &events[0];

        // The data field should deserialise back to a StringHit.
        let hit: StringHit =
            serde_json::from_value(event.data.clone()).expect("data should be a valid StringHit");
        assert!(!hit.value.is_empty());
        assert!(hit.address.starts_with("0x"));
    }
}
