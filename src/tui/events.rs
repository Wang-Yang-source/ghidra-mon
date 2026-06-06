use super::model::EventView;
use crate::adapter::schema::ToolEvent;

pub fn event_line(event: ToolEvent) -> String {
    serde_json::to_string(&event)
        .unwrap_or_else(|_| "[error] failed to serialize ToolEvent".to_string())
}

pub fn visible_logs(logs: &[String], view: EventView, limit: usize) -> Vec<String> {
    logs.iter()
        .rev()
        .filter_map(|line| match view {
            EventView::Raw => Some(raw_line(line)),
            EventView::Structured => structured_line(line),
        })
        .take(limit)
        .collect()
}

fn structured_line(line: &str) -> Option<String> {
    if let Ok(event) = serde_json::from_str::<ToolEvent>(line) {
        return Some(format!(
            "[{}:{:?}] {}",
            event.adapter, event.kind, event.message
        ));
    }

    if is_structured_legacy_line(line) {
        Some(line.to_string())
    } else {
        None
    }
}

fn raw_line(line: &str) -> String {
    if let Ok(event) = serde_json::from_str::<ToolEvent>(line) {
        return event.raw.unwrap_or(event.message);
    }

    line.to_string()
}

fn is_structured_legacy_line(line: &str) -> bool {
    line.starts_with("[")
        || line.starts_with("Format:")
        || line.starts_with("Architecture:")
        || line.starts_with("Entry Point:")
        || line.starts_with("Sections:")
        || line.starts_with("Imports:")
        || line.starts_with("Exports:")
        || line.starts_with("Dynamic Symbols:")
        || line.starts_with("Commands:")
        || line.starts_with("$ ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_view_filters_plain_raw_lines() {
        let logs = vec![
            "plain stdout".to_string(),
            "[adapter:local] scan".to_string(),
            r#"{"adapter":"binwalk","kind":"Status","message":"ok","address":null,"raw":null,"data":null}"#.to_string(),
        ];
        let visible = visible_logs(&logs, EventView::Structured, 10);

        assert_eq!(visible.len(), 2);
        assert!(!visible.contains(&"plain stdout".to_string()));
    }

    #[test]
    fn raw_view_keeps_all_lines() {
        let logs = vec!["plain stdout".to_string(), "[event] structured".to_string()];
        assert_eq!(visible_logs(&logs, EventView::Raw, 10).len(), 2);
    }

    #[test]
    fn structured_view_formats_tool_event() {
        let logs = vec![
            r#"{"adapter":"tui","kind":"Status","message":"ready","address":null,"raw":null,"data":null}"#.to_string(),
        ];
        assert_eq!(
            visible_logs(&logs, EventView::Structured, 10),
            vec!["[tui:Status] ready".to_string()]
        );
    }

    #[test]
    fn raw_view_uses_tool_event_raw_payload() {
        let logs = vec![
            r#"{"adapter":"cli","kind":"RawStdout","message":"summary","address":null,"raw":"raw line","data":null}"#.to_string(),
        ];
        assert_eq!(
            visible_logs(&logs, EventView::Raw, 10),
            vec!["raw line".to_string()]
        );
    }
}
