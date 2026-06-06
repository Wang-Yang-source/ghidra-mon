pub const ROOT_COMMANDS: &[&str] = &[
    "info", "toolkit", "analyze", "bridge", "query", "clear", "quit", "help", "setup", "mcp",
];

pub const TOOLKIT_COMMANDS: &[&str] = &["binwalk", "checksec", "rizin", "rop"];

pub const QUERY_COMMANDS: &[&str] = &[
    "ping",
    "program_info",
    "list_functions",
    "memory_blocks",
    "symbols",
    "list_imports",
    "list_exports",
    "list_data_types",
    "decompile",
    "function_at",
    "function_containing",
    "callers",
    "callees",
    "call_graph",
    "control_flow_graph",
    "instructions_for_function",
    "references_to",
    "references_from",
    "search_strings",
    "find_symbols",
    "data_at",
    "rename_function",
    "set_comment",
    "set_plate_comment",
];

pub fn suggestions(input: &str) -> Vec<String> {
    if input.is_empty() {
        return Vec::new();
    }

    let parts: Vec<&str> = input.split_whitespace().collect();
    if input.ends_with(' ') || parts.len() > 1 {
        if let Some(&"toolkit") = parts.first() {
            let second = if parts.len() > 1 && !input.ends_with(' ') {
                parts[1]
            } else {
                ""
            };
            return filter_prefix(TOOLKIT_COMMANDS, second);
        }

        if let Some(&"query") = parts.first() {
            let second = if parts.len() > 1 && !input.ends_with(' ') {
                parts[1]
            } else {
                ""
            };
            return filter_prefix(QUERY_COMMANDS, second);
        }

        if input.ends_with('-') || parts.last().unwrap_or(&"").starts_with('-') {
            return filter_prefix(
                &["--help", "-p", "-n", "--json", "--port", "--version"],
                parts.last().unwrap_or(&""),
            );
        }
    }

    filter_prefix(ROOT_COMMANDS, parts.first().unwrap_or(&""))
}

pub fn ghost_text(input: &str, history: &[String], suggestions: &[String]) -> String {
    if input.is_empty() {
        return String::new();
    }

    if let Some(hist) = history
        .iter()
        .rev()
        .find(|entry| entry.starts_with(input) && *entry != input)
    {
        return hist[input.len()..].to_string();
    }

    let parts: Vec<&str> = input.split_whitespace().collect();
    if input.ends_with(' ') {
        return String::new();
    }

    parts
        .last()
        .and_then(|last| {
            suggestions
                .iter()
                .find(|suggestion| suggestion.starts_with(*last))
                .map(|suggestion| suggestion[last.len()..].to_string())
        })
        .unwrap_or_default()
}

pub fn accept_completion(input: &mut String, history: &[String], suggestions: &[String]) {
    let ghost = ghost_text(input, history, suggestions);
    if !ghost.is_empty() {
        input.push_str(&ghost);
        if !input.ends_with(' ') {
            input.push(' ');
        }
    }
}

fn filter_prefix(values: &[&str], prefix: &str) -> Vec<String> {
    values
        .iter()
        .filter(|value| value.starts_with(prefix))
        .map(|value| value.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggests_toolkit_subcommands() {
        assert_eq!(suggestions("toolkit b"), vec!["binwalk".to_string()]);
        assert_eq!(suggestions("toolkit c"), vec!["checksec".to_string()]);
        assert_eq!(
            suggestions("toolkit r"),
            vec!["rizin".to_string(), "rop".to_string()]
        );
    }

    #[test]
    fn suggests_query_commands() {
        assert!(suggestions("query de").contains(&"decompile".to_string()));
    }

    #[test]
    fn ghost_text_prefers_history() {
        let history = vec!["toolkit rop tests/crackme".to_string()];
        assert_eq!(ghost_text("tool", &history, &[]), "kit rop tests/crackme");
    }

    #[test]
    fn ghost_text_falls_back_to_suggestions() {
        assert_eq!(
            ghost_text("toolkit b", &[], &["binwalk".to_string()]),
            "inwalk"
        );
    }

    #[test]
    fn accept_completion_appends_space() {
        let mut input = "toolkit b".to_string();
        accept_completion(&mut input, &[], &["binwalk".to_string()]);
        assert_eq!(input, "toolkit binwalk ");
    }
}
