// TUI dashboard for revisor.
// Cyberpunk-themed ratatui interface acting as a Terminal IDE Artifact.

use crate::bridge::{read_bridge_port, BridgeClient};
use crate::error::Result;
use crate::types::*;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Terminal,
};
use goblin::Object;
use std::fs;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use syntect::easy::HighlightLines;
use syntect::highlighting::{ThemeSet, Style as SyntectStyle};
use syntect::parsing::SyntaxSet;
use std::{io, sync::Arc, time::Duration};
use tokio::sync::Mutex;

pub const SOCKET_PATH: &str = "/tmp/revisor.sock";

#[derive(PartialEq, Clone, Copy)]
enum AppTab {
    Decompiler,
    XRefs,
    Strings,
}

#[derive(PartialEq, Clone, Copy)]
enum ActivePane {
    Sidebar,
    Input,
}

/// Professional syntax highlighter using `syntect` for VSCode-level code coloring.
fn highlight_c_code_syntect<'a>(code: &'a str, ps: &SyntaxSet, ts: &ThemeSet) -> Vec<Line<'a>> {
    let syntax = ps.find_syntax_by_extension("c").unwrap_or_else(|| ps.find_syntax_plain_text());
    let mut h = HighlightLines::new(syntax, &ts.themes["base16-ocean.dark"]);

    code.lines()
        .map(|line| {
            let ranges: Vec<(SyntectStyle, &str)> = h.highlight_line(line, ps).unwrap_or_default();
            let spans: Vec<Span> = ranges
                .into_iter()
                .map(|(style, text)| {
                    Span::styled(
                        text.to_string(),
                        Style::default().fg(ratatui::style::Color::Rgb(
                            style.foreground.r,
                            style.foreground.g,
                            style.foreground.b,
                        )),
                    )
                })
                .collect();
            Line::from(spans)
        })
        .collect()
}

pub async fn run_tui(state: Arc<Mutex<DaemonState>>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut input = String::new();
    let mut active_pane = ActivePane::Input;
    let mut app_tab = AppTab::Decompiler;

    // Command History & Suggestions
    let mut command_history: Vec<String> = Vec::new();
    let mut history_index: Option<usize> = None;
    let mut history_search_prefix: String = String::new();
    let mut suggestions: Vec<String> = Vec::new();
    let mut suggestion_index: usize = 0;

    // Data State
    let mut functions: Vec<FunctionInfo> = Vec::new();
    let mut list_state = ListState::default();
    
    let mut strings: Vec<StringResult> = Vec::new();
    let mut strings_list_state = ListState::default();

    let mut decompiled_code = String::from("Press TAB to focus the Functions List.\nUse Up/Down to navigate, and Enter to Decompile.\nUse Mouse Scroll to scroll the list.\nPress 'x' to view X-Refs, 's' for Strings, 'd' for Decompiler.");
    let mut callers: Vec<FunctionInfo> = Vec::new();
    let mut callees: Vec<FunctionInfo> = Vec::new();

    // Syntect setup
    let ps = SyntaxSet::load_defaults_newlines();
    let ts = ThemeSet::load_defaults();

    // Check if bridge is available initially
    let mut bridge_port = read_bridge_port();

    {
        let mut st = state.lock().await;
        st.logs.push("🚀 Welcome to Revisor Terminal IDE!".into());
        if let Some(port) = bridge_port {
            st.logs.push(format!("🔗 Connected to Bridge on port {}", port));
            st.logs.push("💡 Hotkeys: [TAB] Focus | [d] Decompiler | [x] X-Refs | [s] Strings | [Ctrl+C] Quit".into());
        } else {
            st.logs.push("⚠️ No Bridge found. Press [ESC] to focus input, then type 'analyze <bin> -p <proj> -n <name>'".into());
            st.logs.push("   followed by 'bridge -p <proj> -n <name>' to start analyzing!".into());
        }
    }

    // Channels for async data fetching
    let (tx_funcs, mut rx_funcs) = tokio::sync::mpsc::channel(1);
    let (tx_decompile, mut rx_decompile) = tokio::sync::mpsc::channel(1);
    let (tx_xrefs, mut rx_xrefs) = tokio::sync::mpsc::channel(1);
    let (tx_strings, mut rx_strings) = tokio::sync::mpsc::channel(1);

    // If bridge is already online, fetch
    if let Some(port) = bridge_port {
        let client = BridgeClient::new(port);
        let tx_f = tx_funcs.clone();
        let tx_s = tx_strings.clone();
        tokio::spawn(async move {
            if let Ok(funcs) = client.list_functions().await {
                let _ = tx_f.send(funcs).await;
            }
            if let Ok(strs) = client.search_strings("").await {
                let _ = tx_s.send(strs).await;
            }
        });
    }

    let mut last_bridge_check = std::time::Instant::now();

    loop {
        // Dynamic Bridge Detection
        if bridge_port.is_none() && last_bridge_check.elapsed() > Duration::from_secs(1) {
            last_bridge_check = std::time::Instant::now();
            if let Some(port) = read_bridge_port() {
                bridge_port = Some(port);
                let mut st = state.lock().await;
                st.logs.push(format!("🔗 自动检测到 Bridge 上线 (Port {})! 正在拉取数据...", port));
                
                let client = BridgeClient::new(port);
                let tx_f = tx_funcs.clone();
                let tx_s = tx_strings.clone();
                tokio::spawn(async move {
                    if let Ok(funcs) = client.list_functions().await {
                        let _ = tx_f.send(funcs).await;
                    }
                    if let Ok(strs) = client.search_strings("").await {
                        let _ = tx_s.send(strs).await;
                    }
                });
            }
        }

        // Compute Suggestions
        suggestions.clear();
        if active_pane == ActivePane::Input && !input.is_empty() {
            let cmds = ["analyze", "bridge", "query", "clear", "quit", "help", "setup", "mcp", "info"];
            let queries = ["decompile", "list_functions", "ping", "search_strings", "callers", "callees", "program_info", "memory_blocks", "symbols"];
            
            let parts: Vec<&str> = input.split_whitespace().collect();
            if input.ends_with(' ') || parts.len() > 1 {
                if let Some(&"query") = parts.first() {
                    let second = if parts.len() > 1 && !input.ends_with(' ') { parts[1] } else { "" };
                    suggestions = queries.iter().filter(|q| q.starts_with(second)).map(|s| s.to_string()).collect();
                } else if input.ends_with("-") || parts.last().unwrap_or(&"").starts_with("-") {
                    let last = parts.last().unwrap_or(&"");
                    let flags = ["--help", "-p", "-n", "--json", "--port", "--version"];
                    suggestions = flags.iter().filter(|f| f.starts_with(last)).map(|s| s.to_string()).collect();
                }
            } else {
                let first = parts.first().unwrap_or(&"");
                suggestions = cmds.iter().filter(|c| c.starts_with(first)).map(|s| s.to_string()).collect();
            }
        }
        if suggestion_index >= suggestions.len() {
            suggestion_index = 0;
        }

        // Poll receivers
        if let Ok(funcs) = rx_funcs.try_recv() {
            functions = funcs;
            if !functions.is_empty() {
                list_state.select(Some(0));
            }
        }
        if let Ok(strs) = rx_strings.try_recv() {
            strings = strs;
            if !strings.is_empty() {
                strings_list_state.select(Some(0));
            }
        }
        if let Ok(code) = rx_decompile.try_recv() {
            decompiled_code = code;
        }
        if let Ok((callers_res, callees_res)) = rx_xrefs.try_recv() {
            callers = callers_res;
            callees = callees_res;
        }

        let st = state.lock().await.clone();

        terminal.draw(|f| {
            let main_chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),      // Tabs
                    Constraint::Percentage(60), // IDE area
                    Constraint::Percentage(25), // Logs area
                    Constraint::Length(3),      // Input area
                ])
                .split(f.area());

            // 1. Tabs
            let titles = vec![
                Line::from(" [d] 💻 Decompiler "),
                Line::from(" [x] 🕸️ Cross-References "),
                Line::from(" [s] 🔍 Strings "),
            ];
            let tab_index = match app_tab {
                AppTab::Decompiler => 0,
                AppTab::XRefs => 1,
                AppTab::Strings => 2,
            };
            let tabs = Tabs::new(titles)
                .block(Block::default().borders(Borders::ALL).title(" 🗂️ VIEWS "))
                .select(tab_index)
                .style(Style::default().fg(Color::DarkGray))
                .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
            f.render_widget(tabs, main_chunks[0]);

            // 2. IDE Area
            let ide_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(25), // Sidebar
                    Constraint::Percentage(75), // Main content
                ])
                .split(main_chunks[1]);

            // Sidebar rendering (Functions or Strings depending on tab)
            let sidebar_border = if active_pane == ActivePane::Sidebar { Color::Yellow } else { Color::DarkGray };
            
            if app_tab == AppTab::Strings {
                let str_items: Vec<ListItem> = strings
                    .iter()
                    .map(|s| ListItem::new(format!("{} | {}", s.address, s.value)))
                    .collect();
                let str_list = List::new(str_items)
                    .block(Block::default().title(" 📋 STRINGS (TAB focus) ").borders(Borders::ALL).border_style(Style::default().fg(sidebar_border)))
                    .highlight_style(Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD))
                    .highlight_symbol("▶ ");
                f.render_stateful_widget(str_list, main_chunks[1], &mut strings_list_state);
            } else {
                let func_items: Vec<ListItem> = functions
                    .iter()
                    .map(|func| ListItem::new(format!("{} @ {}", func.name, func.address)))
                    .collect();
                let func_list = List::new(func_items)
                    .block(Block::default().title(" 📋 FUNCTIONS (TAB focus) ").borders(Borders::ALL).border_style(Style::default().fg(sidebar_border)))
                    .highlight_style(Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD))
                    .highlight_symbol("▶ ");
                f.render_stateful_widget(func_list, ide_chunks[0], &mut list_state);

                // Main content rendering (Decompiler or XRefs)
                if app_tab == AppTab::Decompiler {
                    let highlighted_lines = highlight_c_code_syntect(&decompiled_code, &ps, &ts);
                    let code_block = Paragraph::new(highlighted_lines)
                        .block(Block::default().title(" 💻 DECOMPILED C SOURCE ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
                        .wrap(Wrap { trim: false });
                    f.render_widget(code_block, ide_chunks[1]);
                } else if app_tab == AppTab::XRefs {
                    let xrefs_chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(ide_chunks[1]);
                    
                    let callers_items: Vec<ListItem> = callers.iter().map(|f| ListItem::new(format!("{} @ {}", f.name, f.address))).collect();
                    let callers_list = List::new(callers_items)
                        .block(Block::default().title(" ⬆️ CALLERS ").borders(Borders::ALL).border_style(Style::default().fg(Color::LightMagenta)));
                    f.render_widget(callers_list, xrefs_chunks[0]);

                    let callees_items: Vec<ListItem> = callees.iter().map(|f| ListItem::new(format!("{} @ {}", f.name, f.address))).collect();
                    let callees_list = List::new(callees_items)
                        .block(Block::default().title(" ⬇️ CALLEES ").borders(Borders::ALL).border_style(Style::default().fg(Color::LightBlue)));
                    f.render_widget(callees_list, xrefs_chunks[1]);
                }
            }

            // 3. Logs Area
            let log_items: Vec<ListItem> = st.logs.iter().rev().take(15).map(|l| ListItem::new(l.clone())).collect();
            let logs_block = List::new(log_items).block(
                Block::default().title(" 📡 TERMINAL & EVENT LOGS ").borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(logs_block, main_chunks[2]);

            // Compute Ghost Text (Fish style)
            let mut ghost_text = String::new();
            if active_pane == ActivePane::Input && !input.is_empty() {
                if let Some(hist) = command_history.iter().rev().find(|h| h.starts_with(&input) && *h != &input) {
                    ghost_text = hist[input.len()..].to_string();
                } else {
                    let parts: Vec<&str> = input.split_whitespace().collect();
                    if !input.ends_with(' ') {
                        if let Some(last) = parts.last() {
                            if let Some(sugg) = suggestions.iter().find(|s| s.starts_with(*last)) {
                                ghost_text = sugg[last.len()..].to_string();
                            }
                        }
                    }
                }
            }

            let input_border = if active_pane == ActivePane::Input { Color::Green } else { Color::DarkGray };
            let title = if !suggestions.is_empty() && active_pane == ActivePane::Input {
                let mut sugg_str = String::from(" ⌨️ COMMAND CONSOLE | Suggestions: ");
                for (i, s) in suggestions.iter().enumerate() {
                    if i == suggestion_index {
                        sugg_str.push_str(&format!("[{}] ", s));
                    } else {
                        sugg_str.push_str(&format!("{} ", s));
                    }
                }
                sugg_str
            } else {
                String::from(" ⌨️ COMMAND CONSOLE (Fish-style: Right arrow to autocomplete) ")
            };

            let line = Line::from(vec![
                Span::styled("> ", Style::default().fg(Color::Yellow)),
                Span::styled(input.clone(), Style::default().fg(Color::Yellow)),
                Span::styled(ghost_text.clone(), Style::default().fg(Color::DarkGray)),
                Span::styled("_", Style::default().fg(Color::Yellow)),
            ]);

            let input_block = Paragraph::new(line)
                .block(Block::default().title(title).borders(Borders::ALL).border_style(Style::default().fg(input_border)));
            f.render_widget(input_block, main_chunks[3]);
        })?;

        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind != crossterm::event::KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Esc => { 
                            // Focus input instead of quitting
                            active_pane = ActivePane::Input; 
                        }
                        KeyCode::Char('c') | KeyCode::Char('q') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => { break; }
                        KeyCode::Tab => {
                            active_pane = if active_pane == ActivePane::Input { ActivePane::Sidebar } else { ActivePane::Input };
                        }
                        
                        // Global hotkeys to switch tabs
                        KeyCode::Char('d') if active_pane == ActivePane::Sidebar => { app_tab = AppTab::Decompiler; }
                        KeyCode::Char('x') if active_pane == ActivePane::Sidebar => { 
                            app_tab = AppTab::XRefs; 
                            // Trigger xrefs fetch for current selected function
                            if let Some(i) = list_state.selected() {
                                if let Some(f) = functions.get(i) {
                                    let func_name = f.name.clone();
                                    let tx = tx_xrefs.clone();
                                    let port = bridge_port;
                                    tokio::spawn(async move {
                                        if let Some(p) = port {
                                            let client = BridgeClient::new(p);
                                            let callers = client.callers(&func_name).await.unwrap_or_default();
                                            let callees = client.callees(&func_name).await.unwrap_or_default();
                                            let _ = tx.send((callers, callees)).await;
                                        }
                                    });
                                }
                            }
                        }
                        KeyCode::Char('s') if active_pane == ActivePane::Sidebar => { app_tab = AppTab::Strings; }

                        // Navigation in Sidebar
                        KeyCode::Up if active_pane == ActivePane::Sidebar => {
                            if app_tab == AppTab::Strings {
                                let i = match strings_list_state.selected() { Some(i) => if i == 0 { 0 } else { i - 1 }, None => 0 };
                                strings_list_state.select(Some(i));
                            } else {
                                let i = match list_state.selected() { Some(i) => if i == 0 { 0 } else { i - 1 }, None => 0 };
                                list_state.select(Some(i));
                            }
                        }
                        KeyCode::Down if active_pane == ActivePane::Sidebar => {
                            if app_tab == AppTab::Strings {
                                let i = match strings_list_state.selected() { Some(i) => if i >= strings.len().saturating_sub(1) { strings.len().saturating_sub(1) } else { i + 1 }, None => 0 };
                                strings_list_state.select(Some(i));
                            } else {
                                let i = match list_state.selected() { Some(i) => if i >= functions.len().saturating_sub(1) { functions.len().saturating_sub(1) } else { i + 1 }, None => 0 };
                                list_state.select(Some(i));
                            }
                        }
                        
                        // Execution
                        KeyCode::Enter if active_pane == ActivePane::Sidebar => {
                            if app_tab == AppTab::Decompiler || app_tab == AppTab::XRefs {
                                if let Some(i) = list_state.selected() {
                                    if let Some(f) = functions.get(i) {
                                        let func_name = f.name.clone();
                                        
                                        // Fetch Decompile
                                        let tx_dec = tx_decompile.clone();
                                        let port = bridge_port;
                                        decompiled_code = format!("⏳ Decompiling {}...", func_name);
                                        let func_name_dec = func_name.clone();
                                        tokio::spawn(async move {
                                            if let Some(p) = port {
                                                let client = BridgeClient::new(p);
                                                if let Ok(res) = client.decompile(&func_name_dec).await {
                                                    if let Some(c_code) = res.c_code {
                                                        let _ = tx_dec.send(c_code).await;
                                                    }
                                                }
                                            }
                                        });

                                        // Fetch XRefs
                                        let tx_x = tx_xrefs.clone();
                                        let func_name2 = func_name.clone();
                                        tokio::spawn(async move {
                                            if let Some(p) = port {
                                                let client = BridgeClient::new(p);
                                                let callers = client.callers(&func_name2).await.unwrap_or_default();
                                                let callees = client.callees(&func_name2).await.unwrap_or_default();
                                                let _ = tx_x.send((callers, callees)).await;
                                            }
                                        });
                                    }
                                }
                            }
                        }

                        // Input Mode Handling
                        KeyCode::Char(c) if active_pane == ActivePane::Input => { 
                            input.push(c); 
                            history_index = None;
                            history_search_prefix.clear();
                        }
                        KeyCode::Backspace if active_pane == ActivePane::Input => { 
                            input.pop(); 
                            history_index = None;
                            history_search_prefix.clear();
                        }
                        KeyCode::Up if active_pane == ActivePane::Input => {
                            if !command_history.is_empty() {
                                if history_index.is_none() {
                                    history_search_prefix = input.clone();
                                }
                                let mut start_idx = history_index.unwrap_or(command_history.len());
                                let mut found = false;
                                while start_idx > 0 {
                                    start_idx -= 1;
                                    if command_history[start_idx].starts_with(&history_search_prefix) {
                                        history_index = Some(start_idx);
                                        input = command_history[start_idx].clone();
                                        found = true;
                                        break;
                                    }
                                }
                                // If not found going up, we stay where we are.
                            }
                        }
                        KeyCode::Down if active_pane == ActivePane::Input => {
                            if let Some(mut curr_idx) = history_index {
                                let mut found = false;
                                while curr_idx + 1 < command_history.len() {
                                    curr_idx += 1;
                                    if command_history[curr_idx].starts_with(&history_search_prefix) {
                                        history_index = Some(curr_idx);
                                        input = command_history[curr_idx].clone();
                                        found = true;
                                        break;
                                    }
                                }
                                if !found {
                                    history_index = None;
                                    input = history_search_prefix.clone();
                                }
                            }
                        }
                        KeyCode::Right if active_pane == ActivePane::Input => {
                            // Fish-style: Autocomplete ghost text
                            let mut ghost_text = String::new();
                            if !input.is_empty() {
                                if let Some(hist) = command_history.iter().rev().find(|h| h.starts_with(&input) && *h != &input) {
                                    ghost_text = hist[input.len()..].to_string();
                                } else {
                                    let parts: Vec<&str> = input.split_whitespace().collect();
                                    if !input.ends_with(' ') {
                                        if let Some(last) = parts.last() {
                                            if let Some(sugg) = suggestions.iter().find(|s| s.starts_with(*last)) {
                                                ghost_text = sugg[last.len()..].to_string();
                                            }
                                        }
                                    }
                                }
                            }
                            if !ghost_text.is_empty() {
                                input.push_str(&ghost_text);
                                if !input.ends_with(' ') {
                                    input.push(' ');
                                }
                            }
                        }
                        KeyCode::Enter if active_pane == ActivePane::Input => {
                            let cmd = input.trim().to_string();
                            input.clear();
                            history_index = None;
                            history_search_prefix.clear();
                            if !cmd.is_empty() {
                                command_history.push(cmd.clone());
                                if cmd == "quit" || cmd == "exit" || cmd == "q" { break; }

                                let state_clone = Arc::clone(&state);
                                if cmd.starts_with("info ") {
                                    let target = cmd.trim_start_matches("info ").trim().to_string();
                                    tokio::spawn(async move {
                                        let mut st = state_clone.lock().await;
                                        st.logs.push(format!("⚡ Fast Static Analysis on: {}", target));
                                        match fs::read(&target) {
                                            Ok(buffer) => {
                                                match Object::parse(&buffer) {
                                                    Ok(Object::Elf(elf)) => {
                                                        st.logs.push(format!("🛡️ Format: ELF"));
                                                        st.logs.push(format!("📐 Architecture: {}", if elf.is_64 { "64-bit" } else { "32-bit" }));
                                                        st.logs.push(format!("📥 Dynamic Symbols: {}", elf.dynsyms.len()));
                                                        st.logs.push(format!("📚 Sections: {}", elf.section_headers.len()));
                                                        st.logs.push(format!("🚀 Entry Point: 0x{:x}", elf.header.e_entry));
                                                    }
                                                    Ok(Object::PE(pe)) => {
                                                        st.logs.push(format!("🛡️ Format: PE (Windows)"));
                                                        st.logs.push(format!("📐 Architecture: {}", if pe.is_64 { "64-bit" } else { "32-bit" }));
                                                        st.logs.push(format!("📥 Imports: {}", pe.imports.len()));
                                                        st.logs.push(format!("📤 Exports: {}", pe.exports.len()));
                                                        st.logs.push(format!("📚 Sections: {}", pe.sections.len()));
                                                        st.logs.push(format!("🚀 Entry Point: 0x{:x}", pe.entry));
                                                    }
                                                    Ok(Object::Mach(_mach)) => {
                                                        st.logs.push("🛡️ Format: Mach-O (macOS)".into());
                                                    }
                                                    Ok(_) => {
                                                        st.logs.push("🛡️ Format: Unknown/Archive".into());
                                                    }
                                                    Err(e) => st.logs.push(format!("❌ Parse Error: {}", e)),
                                                }
                                            }
                                            Err(e) => st.logs.push(format!("❌ File Error: {}", e)),
                                        }
                                    });
                                } else {
                                    tokio::spawn(async move {
                                        let mut args: Vec<String> = cmd.split_whitespace().map(|s| s.to_string()).collect();

                                        if args[0] == "clear" || args[0] == "cls" {
                                            let mut st = state_clone.lock().await;
                                            st.logs.clear();
                                            return;
                                        }

                                        if args[0] == "help" {
                                            let mut st = state_clone.lock().await;
                                            st.logs.push("📝 Commands: info <bin>, analyze, bridge, query <cmd>, clear, quit".into());
                                            return;
                                        }

                                        let query_cmds = [
                                            "ping", "program_info", "list_functions", "memory_blocks", "symbols", "list_imports", "list_exports", "list_data_types", "decompile", "function_at", "function_containing", "callers", "callees", "call_graph", "control_flow_graph", "instructions_for_function", "references_to", "references_from", "search_strings", "find_symbols", "data_at", "rename_function", "set_comment", "set_plate_comment",
                                        ];
                                        if query_cmds.contains(&args[0].as_str()) {
                                            args.insert(0, "query".to_string());
                                        }

                                        {
                                            let mut st = state_clone.lock().await;
                                            st.logs.push(format!("❯ revisor {}", args.join(" ")));
                                        }

                                        let exe = std::env::current_exe().unwrap_or_else(|_| "revisor".into());
                                        let mut command = tokio::process::Command::new(exe);
                                        command.args(&args);
                                        command.stdout(Stdio::piped());
                                        command.stderr(Stdio::piped());

                                        match command.spawn() {
                                            Ok(mut child) => {
                                                let stdout = child.stdout.take();
                                                let stderr = child.stderr.take();

                                                if let Some(stdout) = stdout {
                                                    let state_clone_out = state_clone.clone();
                                                    tokio::spawn(async move {
                                                        let mut reader = BufReader::new(stdout).lines();
                                                        while let Ok(Some(line)) = reader.next_line().await {
                                                            let mut st = state_clone_out.lock().await;
                                                            st.logs.push(line);
                                                        }
                                                    });
                                                }

                                                if let Some(stderr) = stderr {
                                                    let state_clone_err = state_clone.clone();
                                                    tokio::spawn(async move {
                                                        let mut reader = BufReader::new(stderr).lines();
                                                        while let Ok(Some(line)) = reader.next_line().await {
                                                            let mut st = state_clone_err.lock().await;
                                                            st.logs.push(line);
                                                        }
                                                    });
                                                }
                                            }
                                            Err(e) => {
                                                let mut st = state_clone.lock().await;
                                                st.logs.push(format!("❌ Failed to spawn: {}", e));
                                            }
                                        }
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Event::Mouse(mouse) => {
                    if active_pane == ActivePane::Sidebar || mouse.column < 30 {
                        match mouse.kind {
                            MouseEventKind::ScrollDown => {
                                if app_tab == AppTab::Strings {
                                    let i = match strings_list_state.selected() { Some(i) => if i >= strings.len().saturating_sub(1) { strings.len().saturating_sub(1) } else { i + 1 }, None => 0 };
                                    strings_list_state.select(Some(i));
                                } else {
                                    let i = match list_state.selected() { Some(i) => if i >= functions.len().saturating_sub(1) { functions.len().saturating_sub(1) } else { i + 1 }, None => 0 };
                                    list_state.select(Some(i));
                                }
                            }
                            MouseEventKind::ScrollUp => {
                                if app_tab == AppTab::Strings {
                                    let i = match strings_list_state.selected() { Some(i) => if i == 0 { 0 } else { i - 1 }, None => 0 };
                                    strings_list_state.select(Some(i));
                                } else {
                                    let i = match list_state.selected() { Some(i) => if i == 0 { 0 } else { i - 1 }, None => 0 };
                                    list_state.select(Some(i));
                                }
                            }
                            MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                                if app_tab == AppTab::Decompiler || app_tab == AppTab::XRefs {
                                    if let Some(i) = list_state.selected() {
                                        if let Some(f) = functions.get(i) {
                                            let func_name = f.name.clone();
                                            let tx_dec = tx_decompile.clone();
                                            let port = bridge_port;
                                            decompiled_code = format!("⏳ Decompiling {}...", func_name);
                                            let func_name_dec = func_name.clone();
                                            tokio::spawn(async move {
                                                if let Some(p) = port {
                                                    let client = BridgeClient::new(p);
                                                    if let Ok(res) = client.decompile(&func_name_dec).await {
                                                        if let Some(c_code) = res.c_code {
                                                            let _ = tx_dec.send(c_code).await;
                                                        }
                                                    }
                                                }
                                            });

                                            let tx_x = tx_xrefs.clone();
                                            let func_name2 = func_name.clone();
                                            tokio::spawn(async move {
                                                if let Some(p) = port {
                                                    let client = BridgeClient::new(p);
                                                    let callers = client.callers(&func_name2).await.unwrap_or_default();
                                                    let callees = client.callees(&func_name2).await.unwrap_or_default();
                                                    let _ = tx_x.send((callers, callees)).await;
                                                }
                                            });
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}
