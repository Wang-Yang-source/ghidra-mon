//! Terminal UI workspace built on [ratatui] and [crossterm].
//!
//! The TUI presents a unified surface over all pluggable backends:
//! function lists, decompiled C with syntax highlighting, cross-references,
//! string tables, and a command console with fish-style autocompletion.
//!
//! ## Theme
//!
//! Fire-gradient palette (orange-yellow + fire-red) with per-character
//! gradient rendering.  See [`theme`] for the colour engine.
//!
//! ## Key bindings
//!
//! | Key | Action |
//! |-----|--------|
//! | `Tab` | Cycle focus: Input → Sidebar → Main Content |
//! | `o/d/x/s/r/f/g/t` | Switch tabs |
//! | `v` | Toggle event log view (structured / raw) |
//! | `Enter` (sidebar) | Decompile / inspect selected item |
//! | `↑` / `↓` | Navigate lists or command history |
//! | `→` | Accept autocompletion suggestion |
//! | `Ctrl+C` / `Ctrl+Q` | Quit |

mod binary_info;
mod commands;
mod events;
mod highlight;
mod model;
mod runner;
mod theme;

use crate::adapter::schema::{Finding, FirmwareEntry, Gadget, ToolEvent, ToolEventKind};
use crate::bridge::{BridgeClient, read_bridge_port, remove_bridge_port_file};
use crate::error::Result;
use crate::types::*;
use model::{ActivePane, AppTab, EventView};

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, MouseButton, MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Position, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap},
};
use std::{io, sync::Arc, time::Duration};
use syntect::highlighting::ThemeSet;
use syntect::parsing::SyntaxSet;
use tokio::sync::Mutex;

pub const SOCKET_PATH: &str = "/tmp/ghidrai.sock";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Build a Block with gradient-coloured title and themed border.
fn themed_block(title: &str, focused: bool) -> Block<'_> {
    let border_style = if focused {
        theme::border_focused()
    } else {
        theme::border_dim()
    };
    Block::default()
        .title(Span::styled(format!(" {} ", title), theme::title()))
        .borders(Borders::ALL)
        .border_style(border_style)
}

/// Shorthand for the highlight symbol used in all lists.
const HIGHLIGHT_SYMBOL: &str = "▸ ";

fn is_left_click(kind: MouseEventKind) -> bool {
    matches!(
        kind,
        MouseEventKind::Down(MouseButton::Left)
            | MouseEventKind::Up(MouseButton::Left)
            | MouseEventKind::Drag(MouseButton::Left)
    )
}

fn click_in_content(area: Rect, pos: Position) -> bool {
    let max_x = area.x.saturating_add(area.width);
    let max_y = area.y.saturating_add(area.height);
    pos.x > area.x
        && pos.x.saturating_add(1) < max_x
        && pos.y > area.y
        && pos.y.saturating_add(1) < max_y
}

fn sidebar_index_from_click(area: Rect, pos: Position, offset: usize, len: usize) -> Option<usize> {
    if !click_in_content(area, pos) {
        return None;
    }

    let row_in_content = (pos.y - area.y - 1) as usize;
    let content_height = area.height.saturating_sub(2) as usize;
    if row_in_content >= content_height {
        return None;
    }

    let clicked = offset.saturating_add(row_in_content);
    (clicked < len).then_some(clicked)
}

fn tab_from_click(tab_area: Rect, pos: Position) -> Option<AppTab> {
    if pos.y != tab_area.y + 1 {
        return None;
    }
    let inner_x = pos.x.saturating_sub(tab_area.x + 1); // skip left border
    let content_width = tab_area.width.saturating_sub(2);
    if inner_x >= content_width {
        return None;
    }

    let mut current_x: u16 = 0;
    for (idx, tab) in AppTab::ALL.iter().enumerate() {
        let tab_width = tab.label().chars().count() as u16;
        let tab_end = current_x.saturating_add(tab_width);
        if inner_x < tab_end {
            return Some(*tab);
        }

        let is_last = idx + 1 >= AppTab::ALL.len();
        if is_last {
            break;
        }

        // skip divider position after each tab
        if inner_x == tab_end {
            return None;
        }
        current_x = current_x.saturating_add(tab_width + 1);
    }

    None
}

fn trigger_function_actions(
    func_name: String,
    bridge_port: Option<u16>,
    decompiled_code: &mut String,
    tx_decompile: &tokio::sync::mpsc::Sender<String>,
    tx_xrefs: &tokio::sync::mpsc::Sender<(Vec<FunctionInfo>, Vec<FunctionInfo>)>,
) {
    *decompiled_code = format!("Decompiling {}...", func_name);
    let port = bridge_port;
    let tx_dec = tx_decompile.clone();
    let tx_x = tx_xrefs.clone();
    tokio::spawn(async move {
        if let Some(p) = port {
            let client = BridgeClient::new(p);
            if let Ok(res) = client.decompile(&func_name).await
                && let Some(c_code) = res.c_code
            {
                let _ = tx_dec.send(c_code).await;
            }

            let callers = client.callers(&func_name).await.unwrap_or_default();
            let callees = client.callees(&func_name).await.unwrap_or_default();
            let _ = tx_x.send((callers, callees)).await;
        }
    });
}

async fn refresh_bridge_data(
    state: Arc<Mutex<DaemonState>>,
    port: u16,
    tx_funcs: tokio::sync::mpsc::Sender<Vec<FunctionInfo>>,
    tx_strings: tokio::sync::mpsc::Sender<Vec<StringResult>>,
) {
    let client = BridgeClient::new(port);
    if let Ok(funcs) = client.list_functions().await {
        let count = funcs.len();
        let mut st = state.lock().await;
        st.logs.push(events::event_line(ToolEvent::status(
            "ghidra",
            format!("loaded {} function(s) from bridge", count),
        )));
        drop(st);
        let _ = tx_funcs.send(funcs).await;
    } else {
        let mut st = state.lock().await;
        st.logs.push(events::event_line(ToolEvent::error(
            "ghidra",
            format!("bridge list_functions request failed for port {}", port),
        )));
    }

    if let Ok(strs) = client.search_strings("").await {
        let _ = tx_strings.send(strs).await;
    } else {
        let mut st = state.lock().await;
        st.logs.push(events::event_line(ToolEvent::error(
            "ghidra",
            format!("bridge search_strings request failed for port {}", port),
        )));
    }
}

// ─── Main Entry ───────────────────────────────────────────────────────────────

pub async fn run_tui(state: Arc<Mutex<DaemonState>>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut input = String::new();
    let mut active_pane = ActivePane::Input;
    let mut app_tab = AppTab::Overview;
    let mut event_view = EventView::Structured;

    // Command History & Suggestions
    let mut command_history: Vec<String> = Vec::new();
    let mut history_index: Option<usize> = None;
    let mut history_search_prefix: String = String::new();
    let mut suggestions: Vec<String>;
    let mut suggestion_index: usize = 0;

    // Data State
    let mut functions: Vec<FunctionInfo> = Vec::new();
    let mut list_state = ListState::default();

    let mut strings: Vec<StringResult> = Vec::new();
    let mut strings_list_state = ListState::default();

    let mut rop_gadgets: Vec<Gadget> = Vec::new();
    let mut rop_list_state = ListState::default();

    let mut firmware_entries: Vec<FirmwareEntry> = Vec::new();
    let mut firmware_list_state = ListState::default();

    let mut findings_list: Vec<Finding> = Vec::new();
    let mut findings_list_state = ListState::default();

    let mut decompiled_code = String::from(
        "No decompiler result loaded.\n\nUse the command console to run:\n  analyze <bin> -p <project_dir> -n <project_name>\n  bridge -p <project_dir> -n <project_name>\n\nThen focus the symbol list with TAB and press Enter to decompile.",
    );
    let mut callers: Vec<FunctionInfo> = Vec::new();
    let mut callees: Vec<FunctionInfo> = Vec::new();

    // Overview data (populated by `info <bin>`)
    let mut overview_lines: Vec<String> = Vec::new();

    // Syntect setup
    let ps = SyntaxSet::load_defaults_newlines();
    let ts = ThemeSet::load_defaults();

    // Check if bridge is available initially
    let mut bridge_port = read_bridge_port();

    // Animation tick counter for subtle pulsing effects
    let mut tick: u64 = 0;

    // Layout areas for mouse hit-testing (updated each frame)
    let mut tab_area = Rect::default();
    let mut sidebar_area = Rect::default();
    let mut main_content_area = Rect::default();
    let mut log_area = Rect::default();
    let mut input_area = Rect::default();

    {
        let mut st = state.lock().await;
        st.logs.push(events::event_line(ToolEvent::status(
            "tui",
            "Ghidrai toolkit workspace ready.",
        )));
        if let Some(port) = bridge_port {
            st.logs.push(events::event_line(ToolEvent::status(
                "ghidra",
                format!("bridge connected on port {}", port),
            )));
            st.logs.push(events::event_line(ToolEvent::status(
                "tui",
                "keys: TAB focus | o overview | d decompile | x xrefs | s strings | r rop | f firmware | g findings | t toolkit | v event view | Ctrl+C quit",
            )));
        } else {
            st.logs.push(events::event_line(ToolEvent::status(
                "tui",
                "no Ghidra bridge detected; local toolkit commands remain available.",
            )));
            st.logs.push(events::event_line(ToolEvent::status(
                "tui",
                "try: info <bin>, toolkit gdb <bin>, toolkit cwe <bin>, toolkit rop <bin>",
            )));
        }
    }

    // Channels for async data fetching
    let (tx_funcs, mut rx_funcs) = tokio::sync::mpsc::channel(1);
    let (tx_decompile, mut rx_decompile) = tokio::sync::mpsc::channel(1);
    let (tx_xrefs, mut rx_xrefs) = tokio::sync::mpsc::channel(1);
    let (tx_strings, mut rx_strings) = tokio::sync::mpsc::channel(1);

    // If bridge is already online, fetch data.
    if let Some(port) = bridge_port {
        let state_for_refresh = Arc::clone(&state);
        let tx_f = tx_funcs.clone();
        let tx_s = tx_strings.clone();
        tokio::spawn(refresh_bridge_data(state_for_refresh, port, tx_f, tx_s));
    }

    let mut last_bridge_check = std::time::Instant::now();
    let mut bridge_health_logged = false;

    loop {
        tick = tick.wrapping_add(1);

        // Dynamic Bridge Detection / Health Check
        if last_bridge_check.elapsed() > Duration::from_secs(1) {
            last_bridge_check = std::time::Instant::now();

            if let Some(port) = bridge_port {
                match BridgeClient::new(port).ping().await {
                    Ok(_) => {
                        if !bridge_health_logged {
                            let mut st = state.lock().await;
                            st.logs.push(events::event_line(ToolEvent::status(
                                "ghidra",
                                format!("bridge on port {} is alive", port),
                            )));
                            bridge_health_logged = true;
                        }
                    }
                    Err(err) => {
                        let mut st = state.lock().await;
                        st.logs.push(events::event_line(ToolEvent::error(
                            "ghidra",
                            format!("bridge lost on port {port}: {err}"),
                        )));
                        remove_bridge_port_file();
                        bridge_port = None;
                        functions.clear();
                        strings.clear();
                        callers.clear();
                        callees.clear();
                        list_state.select(None);
                        strings_list_state.select(None);
                        rop_list_state.select(None);
                        firmware_list_state.select(None);
                        findings_list_state.select(None);
                        decompiled_code = String::from(
                            "No decompiler result loaded.\n\nUse the command console to run:\n  analyze <bin> -p <project_dir> -n <project_name>\n  bridge -p <project_dir> -n <project_name>\n\nThen focus the symbol list with TAB and press Enter to decompile.",
                        );
                        bridge_health_logged = false;
                        st.logs.push(events::event_line(ToolEvent::status(
                            "tui",
                            "bridge disconnected, waiting for next bridge restart",
                        )));
                    }
                }
            }

            if bridge_port.is_none() {
                if let Some(port) = read_bridge_port() {
                    match BridgeClient::new(port).ping().await {
                        Ok(_) => {
                            bridge_port = Some(port);
                            bridge_health_logged = true;
                            let mut st = state.lock().await;
                            st.logs.push(events::event_line(ToolEvent::status(
                                "ghidra",
                                format!(
                                    "bridge detected on port {}; loading symbols and strings",
                                    port
                                ),
                            )));
                            let state_for_refresh = Arc::clone(&state);
                            let tx_f = tx_funcs.clone();
                            let tx_s = tx_strings.clone();
                            tokio::spawn(refresh_bridge_data(state_for_refresh, port, tx_f, tx_s));
                        }
                        Err(_) => {
                            bridge_health_logged = false;
                        }
                    }
                }
            }
        }

        suggestions = if active_pane == ActivePane::Input {
            commands::suggestions(&input)
        } else {
            Vec::new()
        };
        if suggestion_index >= suggestions.len() {
            suggestion_index = 0;
        }

        // Poll receivers
        if let Ok(funcs) = rx_funcs.try_recv() {
            functions = funcs;
            if !functions.is_empty() {
                list_state.select(Some(0));
            } else {
                list_state.select(None);
                callers.clear();
                callees.clear();
            }
        }
        if let Ok(strs) = rx_strings.try_recv() {
            strings = strs;
            if !strings.is_empty() {
                strings_list_state.select(Some(0));
            } else {
                strings_list_state.select(None);
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

        // Rebuild ROP, Firmware, and Findings from logs
        let mut new_rop_gadgets = Vec::new();
        let mut new_firmware_entries = Vec::new();
        let mut new_findings = Vec::new();
        for log in &st.logs {
            if let Ok(ev) = serde_json::from_str::<ToolEvent>(log) {
                match ev.kind {
                    ToolEventKind::Gadget => {
                        if let Ok(g) = serde_json::from_value::<Gadget>(ev.data.clone()) {
                            new_rop_gadgets.push(g);
                        } else {
                            let address = ev
                                .address
                                .as_deref()
                                .and_then(|a| {
                                    u64::from_str_radix(a.trim_start_matches("0x"), 16).ok()
                                })
                                .unwrap_or(0);
                            let insts = ev
                                .message
                                .split(':')
                                .last()
                                .unwrap_or(&ev.message)
                                .split(';')
                                .map(|s| s.trim().to_string())
                                .collect();
                            new_rop_gadgets.push(Gadget {
                                address,
                                instructions: insts,
                            });
                        }
                    }
                    ToolEventKind::FirmwareEntry => {
                        if let Ok(fe) = serde_json::from_value::<FirmwareEntry>(ev.data.clone()) {
                            new_firmware_entries.push(fe);
                        }
                    }
                    ToolEventKind::Finding => {
                        if let Ok(f) = serde_json::from_value::<Finding>(ev.data.clone()) {
                            new_findings.push(f);
                        }
                    }
                    _ => {}
                }
            }
        }

        if !new_rop_gadgets.is_empty() && rop_gadgets.is_empty() {
            rop_list_state.select(Some(0));
        }
        rop_gadgets = new_rop_gadgets;

        if !new_firmware_entries.is_empty() && firmware_entries.is_empty() {
            firmware_list_state.select(Some(0));
        }
        firmware_entries = new_firmware_entries;

        if !new_findings.is_empty() && findings_list.is_empty() {
            findings_list_state.select(Some(0));
        }
        findings_list = new_findings;

        // Collect overview data from recent info logs
        if app_tab == AppTab::Overview && overview_lines.is_empty() {
            for log in &st.logs {
                if let Ok(ev) = serde_json::from_str::<ToolEvent>(log)
                    && ev.adapter == "local"
                    && ev.message.contains(':')
                {
                    overview_lines.push(ev.message.clone());
                }
            }
        }

        terminal.draw(|f| {
            let main_chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(0)
                .constraints([
                    Constraint::Length(3),      // Tabs
                    Constraint::Min(10),        // IDE area (flexible)
                    Constraint::Length(8),       // Logs area
                    Constraint::Length(3),       // Input area
                ])
                .split(f.area());

            // Save layout areas for mouse hit-testing
            tab_area = main_chunks[0];
            log_area = main_chunks[2];
            input_area = main_chunks[3];

            // ── 1. Tab Bar with Gradient ──────────────────────────────────
            let titles: Vec<Line> = AppTab::ALL
                .iter()
                .enumerate()
                .map(|(i, tab)| {
                    let t = i as f32 / (AppTab::ALL.len() - 1).max(1) as f32;
                    let color = theme::gradient(theme::FIRE_GRADIENT, t);
                    Line::from(Span::styled(
                        tab.label(),
                        Style::default().fg(color),
                    ))
                })
                .collect();

            let tab_block = Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border_dim())
                .title(Span::styled(
                    " ◆ GHIDRAI ",
                    Style::default()
                        .fg(theme::AMBER)
                        .add_modifier(Modifier::BOLD),
                ));
            let tabs = Tabs::new(titles)
                .block(tab_block)
                .select(app_tab.index())
                .style(theme::tab_inactive())
                .highlight_style(theme::tab_active())
                .padding("", "")
                .divider(Span::styled("│", Style::default().fg(theme::SMOKE)));
            f.render_widget(tabs, main_chunks[0]);

            // ── 2. IDE Area ──────────────────────────────────────────────
            let ide_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(25), // Sidebar
                    Constraint::Percentage(75), // Main content
                ])
                .split(main_chunks[1]);

            sidebar_area = ide_chunks[0];
            main_content_area = ide_chunks[1];

            let sidebar_focused = active_pane == ActivePane::Sidebar;
            let main_focused = active_pane == ActivePane::MainContent;

            // ── Render per-tab content ────────────────────────────────────
            match app_tab {
                        AppTab::Overview => {
                    render_overview(
                        f,
                        ide_chunks[0],
                        ide_chunks[1],
                        sidebar_focused,
                        main_focused,
                        bridge_port.is_some(),
                        app_tab,
                        &functions,
                        &mut list_state,
                        &overview_lines,
                        tick,
                    );
                }
                AppTab::Decompiler => {
                    render_sidebar_functions(
                        f,
                        ide_chunks[0],
                        sidebar_focused,
                        bridge_port.is_some(),
                        app_tab,
                        &functions,
                        &mut list_state,
                    );
                    let highlighted_lines = highlight::c_code(&decompiled_code, &ps, &ts);
                    let code_block = Paragraph::new(highlighted_lines)
                        .block(themed_block("Decompiled C", main_focused))
                        .wrap(Wrap { trim: false });
                    f.render_widget(code_block, ide_chunks[1]);
                }
                AppTab::XRefs => {
                    render_sidebar_functions(
                        f,
                        ide_chunks[0],
                        sidebar_focused,
                        bridge_port.is_some(),
                        app_tab,
                        &functions,
                        &mut list_state,
                    );

                    let xrefs_chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                        .split(ide_chunks[1]);

                    if callers.is_empty() {
                        render_placeholder(
                            f,
                            xrefs_chunks[0],
                            main_focused,
                            "Callers (incoming)",
                            if bridge_port.is_some() {
                                &[
                                    "No callers loaded.",
                                    "",
                                    "Select a function and trigger XRefs:",
                                    "  [Enter] in sidebar (Decompiler/XRefs/Overview)",
                                    "  or switch to XRefs using [x]",
                                ]
                            } else {
                                &[
                                    "No bridge available.",
                                    "",
                                    "Run Ghidra backend first:",
                                    "  analyze <bin> -p <project_dir> -n <project_name>",
                                    "  bridge -p <project_dir> -n <project_name>",
                                ]
                            },
                        );
                    } else {
                        let callers_items: Vec<ListItem> = callers
                            .iter()
                            .map(|func| {
                                ListItem::new(Line::from(vec![
                                    Span::styled("← ", theme::xref_caller()),
                                    Span::styled(&func.name, Style::default().fg(theme::BONE)),
                                    Span::styled(format!(" @ {}", func.address), theme::address()),
                                ]))
                            })
                            .collect();
                        let callers_list = List::new(callers_items)
                            .block(themed_block("Callers (incoming)", main_focused))
                            .highlight_style(theme::list_highlight())
                            .highlight_symbol(HIGHLIGHT_SYMBOL);
                        f.render_widget(callers_list, xrefs_chunks[0]);
                    }

                    if callees.is_empty() {
                        render_placeholder(
                            f,
                            xrefs_chunks[1],
                            main_focused,
                            "Callees (outgoing)",
                            if bridge_port.is_some() {
                                &[
                                    "No callees loaded.",
                                    "",
                                    "Select a function and trigger XRefs:",
                                    "  [Enter] in sidebar (Decompiler/XRefs/Overview)",
                                    "  or switch to XRefs using [x]",
                                ]
                            } else {
                                &[
                                    "No bridge available.",
                                    "",
                                    "Run Ghidra backend first:",
                                    "  analyze <bin> -p <project_dir> -n <project_name>",
                                    "  bridge -p <project_dir> -n <project_name>",
                                ]
                            },
                        );
                    } else {
                        let callees_items: Vec<ListItem> = callees
                            .iter()
                            .map(|func| {
                                ListItem::new(Line::from(vec![
                                    Span::styled("→ ", theme::xref_callee()),
                                    Span::styled(&func.name, Style::default().fg(theme::BONE)),
                                    Span::styled(format!(" @ {}", func.address), theme::address()),
                                ]))
                            })
                            .collect();
                        let callees_list = List::new(callees_items)
                            .block(themed_block("Callees (outgoing)", main_focused))
                            .highlight_style(theme::list_highlight())
                            .highlight_symbol(HIGHLIGHT_SYMBOL);
                        f.render_widget(callees_list, xrefs_chunks[1]);
                    }
                }
                AppTab::Strings => {
                    if strings.is_empty() {
                        render_sidebar_command_list(
                            f,
                            ide_chunks[0],
                            sidebar_focused,
                            "Strings",
                            strings_sidebar_commands(),
                            &mut strings_list_state,
                        );
                    } else {
                        let str_items: Vec<ListItem> = strings
                            .iter()
                            .map(|s| {
                                ListItem::new(Line::from(vec![
                                    Span::styled(&s.address, theme::address()),
                                    Span::styled(" │ ", Style::default().fg(theme::SMOKE)),
                                    Span::styled(&s.value, Style::default().fg(theme::SAND)),
                                ]))
                            })
                            .collect();
                        let str_list = List::new(str_items)
                            .block(themed_block("Strings", sidebar_focused))
                            .highlight_style(theme::list_highlight())
                            .highlight_symbol(HIGHLIGHT_SYMBOL);
                        f.render_stateful_widget(str_list, ide_chunks[0], &mut strings_list_state);
                    }

                    let detail = if let Some(i) = strings_list_state.selected() {
                        strings
                            .get(i)
                            .map(|s| {
                                format!(
                                    "Address:  {}\nEncoding: UTF-8\nLength:   {} bytes\n\n{}",
                                    s.address,
                                    s.value.len(),
                                    s.value
                                )
                            })
                            .unwrap_or_else(|| "No string selected.".to_string())
                    } else {
                        "No strings loaded.\n\nRun a backend adapter or use:\n  toolkit rizin <bin>\n  query search_strings <pattern>".to_string()
                    };
                    let detail_block = Paragraph::new(detail)
                        .block(themed_block("String Detail", main_focused))
                        .style(Style::default().fg(theme::SAND))
                        .wrap(Wrap { trim: false });
                    f.render_widget(detail_block, ide_chunks[1]);
                }
                AppTab::ROP => {
                    if rop_gadgets.is_empty() {
                        render_placeholder(
                            f,
                            ide_chunks[0],
                            sidebar_focused,
                            "Gadget Discovery",
                            &[
                                "No ROP gadgets yet.",
                                "",
                                "Run in console:",
                                "  toolkit rop <binary>",
                                "  toolkit disasm <binary>",
                                "  toolkit strings <binary>",
                            ],
                        );
                        render_placeholder(f, ide_chunks[1], main_focused,
                            "ROP Gadgets",
                            &[
                                "ROP gadget discovery powered by iced-x86.",
                                "",
                                "Run from the console:",
                                "  toolkit rop <binary>",
                                "",
                                "Gadgets will appear here once a scan completes.",
                                "Current adapter: pure Rust (64-bit x86).",
                            ],
                        );
                    } else {
                        let rop_items: Vec<ListItem> = rop_gadgets
                            .iter()
                            .map(|g| {
                                ListItem::new(Line::from(vec![
                                    Span::styled(format!("0x{:x}", g.address), theme::address()),
                                ]))
                            })
                            .collect();
                        let rop_list = List::new(rop_items)
                            .block(themed_block("Gadgets", sidebar_focused))
                            .highlight_style(theme::list_highlight())
                            .highlight_symbol(HIGHLIGHT_SYMBOL);
                        f.render_stateful_widget(rop_list, ide_chunks[0], &mut rop_list_state);

                        let detail = if let Some(i) = rop_list_state.selected() {
                            if let Some(g) = rop_gadgets.get(i) {
                                let mut lines = vec![
                                    Line::from(""),
                                    theme::gradient_text("  ROP Gadget Details", theme::FIRE_GRADIENT, true),
                                    Line::from(""),
                                    Line::from(vec![
                                        Span::styled("  Address:      ", Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD)),
                                        Span::styled(format!("0x{:x}", g.address), Style::default().fg(theme::BONE)),
                                    ]),
                                    Line::from(vec![
                                        Span::styled("  Instructions: ", Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD)),
                                        Span::styled(g.instructions.join(" ; "), Style::default().fg(theme::SAND)),
                                    ]),
                                    Line::from(""),
                                    theme::gradient_rule(60, theme::EMBER, theme::SOLAR),
                                    Line::from(""),
                                ];
                                for inst in &g.instructions {
                                    lines.push(Line::from(vec![
                                        Span::styled("    ▸ ", Style::default().fg(theme::ORANGE)),
                                        Span::styled(inst.clone(), Style::default().fg(theme::BONE)),
                                    ]));
                                }
                                lines
                            } else {
                                vec![Line::from("  No gadget selected.")]
                            }
                        } else {
                            vec![Line::from("  No gadget selected.")]
                        };
                        let detail_block = Paragraph::new(detail)
                            .block(themed_block("Gadget View", main_focused))
                            .wrap(Wrap { trim: false });
                        f.render_widget(detail_block, ide_chunks[1]);
                    }
                }
                AppTab::Firmware => {
                    if firmware_entries.is_empty() {
                        render_placeholder(
                            f,
                            ide_chunks[0],
                            sidebar_focused,
                            "Firmware Scan",
                            &[
                                "No firmware results yet.",
                                "",
                                "Run in console:",
                                "  toolkit binwalk <firmware.bin>",
                                "  toolkit entropy <firmware.bin>",
                                "  toolkit lief <firmware.bin>",
                            ],
                        );
                        render_placeholder(f, ide_chunks[1], main_focused,
                            "Firmware Scan",
                            &[
                                "Binwalk firmware analysis results.",
                                "",
                                "Run from the console:",
                                "  toolkit binwalk <firmware.bin>",
                                "",
                                "Detected signatures, embedded filesystems,",
                                "and entropy analysis will appear here.",
                            ],
                        );
                    } else {
                        let fw_items: Vec<ListItem> = firmware_entries
                            .iter()
                            .map(|entry| {
                                ListItem::new(Line::from(vec![
                                    Span::styled(format!("0x{:x}", entry.offset), theme::address()),
                                ]))
                            })
                            .collect();
                        let fw_list = List::new(fw_items)
                            .block(themed_block("Offsets", sidebar_focused))
                            .highlight_style(theme::list_highlight())
                            .highlight_symbol(HIGHLIGHT_SYMBOL);
                        f.render_stateful_widget(fw_list, ide_chunks[0], &mut firmware_list_state);

                        let detail = if let Some(i) = firmware_list_state.selected() {
                            if let Some(entry) = firmware_entries.get(i) {
                                vec![
                                    Line::from(""),
                                    theme::gradient_text("  Firmware Signature Details", theme::FIRE_GRADIENT, true),
                                    Line::from(""),
                                    Line::from(vec![
                                        Span::styled("  Offset:      ", Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD)),
                                        Span::styled(format!("0x{:x} ({})", entry.offset, entry.offset), Style::default().fg(theme::BONE)),
                                    ]),
                                    Line::from(vec![
                                        Span::styled("  Description: ", Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD)),
                                        Span::styled(&entry.description, Style::default().fg(theme::SAND)),
                                    ]),
                                    Line::from(""),
                                    theme::gradient_rule(60, theme::EMBER, theme::SOLAR),
                                    Line::from(""),
                                    Line::from(Span::styled("  Extracted firmware magic signature hit.", Style::default().fg(theme::ASH))),
                                ]
                            } else {
                                vec![Line::from("  No entry selected.")]
                            }
                        } else {
                            vec![Line::from("  No entry selected.")]
                        };
                        let detail_block = Paragraph::new(detail)
                            .block(themed_block("Signature Detail", main_focused))
                            .wrap(Wrap { trim: false });
                        f.render_widget(detail_block, ide_chunks[1]);
                    }
                }
                AppTab::Findings => {
                    if findings_list.is_empty() {
                        render_placeholder(
                            f,
                            ide_chunks[0],
                            sidebar_focused,
                            "Findings",
                            &[
                                "No findings yet.",
                                "",
                                "Run in console:",
                                "  toolkit cwe <binary>",
                                "  toolkit checksec <binary>",
                                "  toolkit lief <binary>",
                                "",
                                "Severity tags: [Critical] [High] [Medium] [Low] [Info]",
                            ],
                        );
                        render_placeholder(f, ide_chunks[1], main_focused,
                            "Findings / Audit Log",
                            &[
                                "Security findings from all adapters.",
                                "",
                                "checksec, native CWE triage, CWE_Checker, and custom rules",
                                "will populate findings here.",
                                "",
                                "Run: toolkit cwe <binary>",
                            ],
                        );
                    } else {
                        let find_items: Vec<ListItem> = findings_list
                            .iter()
                            .map(|finding| {
                                let sev = finding.severity.as_deref().unwrap_or("info");
                                let sev_style = match sev.to_lowercase().as_str() {
                                    "high" | "critical" => theme::log_error(),
                                    "medium" => Style::default().fg(theme::ORANGE),
                                    _ => Style::default().fg(theme::AMBER),
                                };
                                ListItem::new(Line::from(vec![
                                    Span::styled(format!("[{}] ", sev), sev_style),
                                    Span::styled(&finding.title, Style::default().fg(theme::BONE)),
                                ]))
                            })
                            .collect();
                        let find_list = List::new(find_items)
                            .block(themed_block("Findings", sidebar_focused))
                            .highlight_style(theme::list_highlight())
                            .highlight_symbol(HIGHLIGHT_SYMBOL);
                        f.render_stateful_widget(find_list, ide_chunks[0], &mut findings_list_state);

                        let detail = if let Some(i) = findings_list_state.selected() {
                            if let Some(finding) = findings_list.get(i) {
                                let sev = finding.severity.as_deref().unwrap_or("info");
                                let sev_style = match sev.to_lowercase().as_str() {
                                    "high" | "critical" => theme::log_error(),
                                    "medium" => Style::default().fg(theme::ORANGE),
                                    _ => Style::default().fg(theme::AMBER),
                                };
                                vec![
                                    Line::from(""),
                                    theme::gradient_text("  Security Finding Details", theme::FIRE_GRADIENT, true),
                                    Line::from(""),
                                    Line::from(vec![
                                        Span::styled("  CWE / Title:  ", Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD)),
                                        Span::styled(&finding.title, Style::default().fg(theme::BONE)),
                                    ]),
                                    Line::from(vec![
                                        Span::styled("  Severity:     ", Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD)),
                                        Span::styled(sev, sev_style),
                                    ]),
                                    Line::from(vec![
                                        Span::styled("  Address:      ", Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD)),
                                        Span::styled(finding.address.as_deref().unwrap_or("N/A"), theme::address()),
                                    ]),
                                    Line::from(vec![
                                        Span::styled("  Source:       ", Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD)),
                                        Span::styled(&finding.source, Style::default().fg(theme::ASH)),
                                    ]),
                                    Line::from(""),
                                    Line::from(vec![
                                        Span::styled("  Description:  ", Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD)),
                                        Span::styled(&finding.description, Style::default().fg(theme::SAND)),
                                    ]),
                                    Line::from(""),
                                    theme::gradient_rule(60, theme::EMBER, theme::SOLAR),
                                    Line::from(""),
                                    Line::from(Span::styled("  Evidence Data:", Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD))),
                                    Line::from(Span::styled(
                                        format!("    {}", serde_json::to_string_pretty(&finding.extra).unwrap_or_default()),
                                        Style::default().fg(theme::SAND),
                                    )),
                                ]
                            } else {
                                vec![Line::from("  No finding selected.")]
                            }
                        } else {
                            vec![Line::from("  No finding selected.")]
                        };
                        let detail_block = Paragraph::new(detail)
                            .block(themed_block("Audit Log / Findings Details", main_focused))
                            .wrap(Wrap { trim: false });
                        f.render_widget(detail_block, ide_chunks[1]);
                    }
                }
                AppTab::Toolkit => {
                    let tools = [
                        ("info <bin>",              "binary format and section summary"),
                        ("toolkit all <bin>",        "run native toolkit passes together"),
                        ("toolkit binwalk <bin>",    "firmware signatures and embedded structures"),
                        ("toolkit checksec <bin>",   "ELF/PE/Mach-O hardening features"),
                        ("toolkit cwe <bin>",        "CWE-style risk findings"),
                        ("toolkit lief <bin>",       "object sections, symbols, imports, exports"),
                        ("toolkit strings <bin>",    "native ASCII/UTF-8 string extraction"),
                        ("toolkit disasm <bin>",     "native x86/x86-64 disassembly"),
                        ("toolkit entropy <bin>",    "entropy and packer/compression hints"),
                        ("toolkit gdb <bin>",        "GDB batch debugger metadata"),
                        ("toolkit gdb-mi <bin>",     "GDB/MI protocol metadata"),
                        ("toolkit rop <bin>",        "ROP gadget discovery"),
                        ("toolkit volatility <dump>", "memory/blob IOC triage"),
                        ("toolkit rizin <bin>",      "Rizin JSON static analysis"),
                        ("analyze <bin> ...",        "import into the Ghidra backend adapter"),
                        ("bridge ...",               "start the Ghidra backend adapter"),
                        ("query <cmd> ...",          "inspect a running backend adapter"),
                    ];
                    let tool_items: Vec<ListItem> = tools.iter().map(|(cmd, desc)| {
                        ListItem::new(Line::from(vec![
                            Span::styled(*cmd, Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD)),
                            Span::styled(format!("  {}", desc), Style::default().fg(theme::ASH)),
                        ]))
                    }).collect();
                    let tool_list = List::new(tool_items)
                        .block(themed_block("Tool Adapters", sidebar_focused))
                        .highlight_symbol(HIGHLIGHT_SYMBOL);
                    f.render_widget(tool_list, ide_chunks[0]);

                    let detail_lines: Vec<Line> = vec![
                        Line::from(""),
                        theme::gradient_text("  Ghidrai Adapter Architecture", theme::FIRE_GRADIENT, true),
                        Line::from(""),
                        Line::from(Span::styled(
                            "  Every reverse-engineering engine is an adapter.",
                            Style::default().fg(theme::SAND),
                        )),
                        Line::from(""),
                        Line::from(vec![
                            Span::styled("  Structured  ", Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD)),
                            Span::styled("JSON events from Rizin, Ghidra, Binwalk", Style::default().fg(theme::SAND)),
                        ]),
                        Line::from(vec![
                            Span::styled("  Native      ", Style::default().fg(theme::ORANGE).add_modifier(Modifier::BOLD)),
                            Span::styled("Pure Rust: checksec, ROP (iced-x86), binary info", Style::default().fg(theme::SAND)),
                        ]),
                        Line::from(vec![
                            Span::styled("  Raw         ", Style::default().fg(theme::FIRE).add_modifier(Modifier::BOLD)),
                            Span::styled("Fallback stdout/stderr capture with adapter isolation", Style::default().fg(theme::SAND)),
                        ]),
                        Line::from(""),
                        theme::gradient_rule(60, theme::EMBER, theme::SOLAR),
                        Line::from(""),
                        Line::from(Span::styled(
                            "  Press [v] to toggle structured / raw event view.",
                            Style::default().fg(theme::ASH),
                        )),
                    ];
                    let detail_block = Paragraph::new(detail_lines)
                        .block(themed_block("Adapter Model", main_focused))
                        .wrap(Wrap { trim: false });
                    f.render_widget(detail_block, ide_chunks[1]);
                }
            }

            // ── 3. Event Log ─────────────────────────────────────────────
            let log_items: Vec<ListItem> = events::visible_logs(&st.logs, event_view, 15)
                .into_iter()
                .map(|line| {
                    let style = if line.contains("Error") || line.contains("[error]") {
                        theme::log_error()
                    } else {
                        theme::log_status()
                    };
                    ListItem::new(Span::styled(line, style))
                })
                .collect();

            let log_title = event_view.title();
            let logs_block = List::new(log_items).block(
                Block::default()
                    .title(Span::styled(log_title, theme::title()))
                    .borders(Borders::ALL)
                    .border_style(theme::border_dim()),
            );
            f.render_widget(logs_block, main_chunks[2]);

            // ── 4. Command Console ───────────────────────────────────────
            let ghost_text = if active_pane == ActivePane::Input {
                if input.is_empty() {
                    if functions.is_empty() {
                        "analyze <binary> -p <project_dir> -n <project_name>".to_string()
                    } else {
                        String::new()
                    }
                } else {
                    commands::ghost_text(&input, &command_history, &suggestions)
                }
            } else {
                String::new()
            };

            let console_focused = active_pane == ActivePane::Input;
            let console_border = if console_focused { theme::AMBER } else { theme::SMOKE };

            let title = if !suggestions.is_empty() && console_focused {
                let mut sugg_str = String::from(" Console │ ");
                for (i, s) in suggestions.iter().enumerate() {
                    if i == suggestion_index {
                        sugg_str.push_str(&format!("[{}] ", s));
                    } else {
                        sugg_str.push_str(&format!("{} ", s));
                    }
                }
                sugg_str
            } else {
                if functions.is_empty() {
                    String::from(" Console │ 输入 analyze / toolkit，回车执行 ")
                } else {
                    String::from(" Console │ → accepts completion ")
                }
            };

            // Pulse the cursor color slightly
            let cursor_phase = ((tick % 20) as f32) / 20.0;
            let cursor_color = theme::lerp_color(theme::ORANGE, theme::SOLAR, cursor_phase);

            let prompt_str = if console_focused { ":" } else { "❯ " };
            let line = Line::from(vec![
                Span::styled(prompt_str, theme::prompt()),
                Span::styled(input.clone(), theme::input_text()),
                Span::styled(ghost_text.clone(), theme::ghost()),
                Span::styled("█", Style::default().fg(cursor_color)),
            ]);

            let input_block = Paragraph::new(line).block(
                Block::default()
                    .title(Span::styled(title, Style::default().fg(theme::MUTED_GOLD)))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(console_border)),
            );
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
                            if active_pane == ActivePane::Input {
                                active_pane = ActivePane::Sidebar;
                            }
                        }
                        KeyCode::Char(':') if active_pane != ActivePane::Input => {
                            active_pane = ActivePane::Input;
                        }
                        KeyCode::Char('c') | KeyCode::Char('q')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            break;
                        }
                        KeyCode::Tab => {
                            active_pane = match active_pane {
                                ActivePane::Input => ActivePane::Sidebar,
                                ActivePane::Sidebar => ActivePane::MainContent,
                                ActivePane::MainContent => ActivePane::Input,
                            };
                        }
                        KeyCode::BackTab => {
                            active_pane = match active_pane {
                                ActivePane::Input => ActivePane::MainContent,
                                ActivePane::Sidebar => ActivePane::Input,
                                ActivePane::MainContent => ActivePane::Sidebar,
                            };
                        }
                        KeyCode::Char('v') if active_pane != ActivePane::Input => {
                            event_view = event_view.toggle();
                            let mut st = state.lock().await;
                            st.logs.push(events::event_line(ToolEvent::status(
                                "tui",
                                format!("event log switched to {}", event_view.title().trim()),
                            )));
                        }

                        // ── Tab switching hotkeys ────────────────────
                        KeyCode::Char('o') if active_pane != ActivePane::Input => {
                            app_tab = AppTab::Overview;
                        }
                        KeyCode::Char('d') if active_pane != ActivePane::Input => {
                            app_tab = AppTab::Decompiler;
                        }
                        KeyCode::Char('x') if active_pane != ActivePane::Input => {
                            app_tab = AppTab::XRefs;
                            // Trigger xrefs fetch for current selected function
                            fetch_xrefs_for_selected_function(
                                &functions,
                                &list_state,
                                bridge_port,
                                &tx_xrefs,
                            );
                        }
                        KeyCode::Char('s') if active_pane != ActivePane::Input => {
                            app_tab = AppTab::Strings;
                        }
                        KeyCode::Char('r') if active_pane != ActivePane::Input => {
                            app_tab = AppTab::ROP;
                        }
                        KeyCode::Char('f') if active_pane != ActivePane::Input => {
                            app_tab = AppTab::Firmware;
                        }
                        KeyCode::Char('g') if active_pane != ActivePane::Input => {
                            app_tab = AppTab::Findings;
                        }
                        KeyCode::Char('t') if active_pane != ActivePane::Input => {
                            app_tab = AppTab::Toolkit;
                        }

                        // ── Sidebar navigation ──────────────────────
                        KeyCode::Up if active_pane == ActivePane::Sidebar => {
                            if app_tab == AppTab::Strings {
                                let i = match strings_list_state.selected() {
                                    Some(i) => {
                                        let max = if strings.is_empty() {
                                            strings_sidebar_commands().len()
                                        } else {
                                            strings.len()
                                        };
                                        if i == 0 {
                                            0
                                        } else if i >= max {
                                            max.saturating_sub(1)
                                        } else {
                                            i - 1
                                        }
                                    }
                                    None => 0,
                                };
                                strings_list_state.select(Some(i));
                            } else if app_tab == AppTab::ROP {
                                let i = match rop_list_state.selected() {
                                    Some(i) => {
                                        if i == 0 {
                                            0
                                        } else {
                                            i - 1
                                        }
                                    }
                                    None => 0,
                                };
                                rop_list_state.select(Some(i));
                            } else if app_tab == AppTab::Firmware {
                                let i = match firmware_list_state.selected() {
                                    Some(i) => {
                                        if i == 0 {
                                            0
                                        } else {
                                            i - 1
                                        }
                                    }
                                    None => 0,
                                };
                                firmware_list_state.select(Some(i));
                            } else if app_tab == AppTab::Findings {
                                let i = match findings_list_state.selected() {
                                    Some(i) => {
                                        if i == 0 {
                                            0
                                        } else {
                                            i - 1
                                        }
                                    }
                                    None => 0,
                                };
                                findings_list_state.select(Some(i));
                            } else {
                                let i = match list_state.selected() {
                                    Some(i) => {
                                        if matches!(
                                            app_tab,
                                            AppTab::Overview | AppTab::Decompiler | AppTab::XRefs
                                        ) {
                                            let max = if functions.is_empty() {
                                                sidebar_command_count(app_tab)
                                            } else {
                                                functions.len()
                                            };
                                            if i == 0 {
                                                0
                                            } else if i >= max {
                                                max.saturating_sub(1)
                                            } else {
                                                i - 1
                                            }
                                        } else if i == 0 {
                                            0
                                        } else {
                                            i - 1
                                        }
                                    }
                                    None => 0,
                                };
                                list_state.select(Some(i));
                            }
                        }
                        KeyCode::Down if active_pane == ActivePane::Sidebar => {
                            if app_tab == AppTab::Strings {
                                let max = if strings.is_empty() {
                                    strings_sidebar_commands().len().saturating_sub(1)
                                } else {
                                    strings.len().saturating_sub(1)
                                };
                                let i = match strings_list_state.selected() {
                                    Some(i) => {
                                        if i >= max {
                                            max
                                        } else {
                                            i + 1
                                        }
                                    }
                                    None => 0,
                                };
                                strings_list_state.select(Some(i));
                            } else if app_tab == AppTab::ROP {
                                let i = match rop_list_state.selected() {
                                    Some(i) => {
                                        if i >= rop_gadgets.len().saturating_sub(1) {
                                            rop_gadgets.len().saturating_sub(1)
                                        } else {
                                            i + 1
                                        }
                                    }
                                    None => 0,
                                };
                                rop_list_state.select(Some(i));
                            } else if app_tab == AppTab::Firmware {
                                let i = match firmware_list_state.selected() {
                                    Some(i) => {
                                        if i >= firmware_entries.len().saturating_sub(1) {
                                            firmware_entries.len().saturating_sub(1)
                                        } else {
                                            i + 1
                                        }
                                    }
                                    None => 0,
                                };
                                firmware_list_state.select(Some(i));
                            } else if app_tab == AppTab::Findings {
                                let i = match findings_list_state.selected() {
                                    Some(i) => {
                                        if i >= findings_list.len().saturating_sub(1) {
                                            findings_list.len().saturating_sub(1)
                                        } else {
                                            i + 1
                                        }
                                    }
                                    None => 0,
                                };
                                findings_list_state.select(Some(i));
                            } else {
                                let max = if matches!(
                                    app_tab,
                                    AppTab::Overview | AppTab::Decompiler | AppTab::XRefs
                                ) {
                                    if functions.is_empty() {
                                        sidebar_command_count(app_tab).saturating_sub(1)
                                    } else {
                                        functions.len().saturating_sub(1)
                                    }
                                } else {
                                    functions.len().saturating_sub(1)
                                };
                                let i = match list_state.selected() {
                                    Some(i) => {
                                        if i >= max {
                                            max
                                        } else {
                                            i + 1
                                        }
                                    }
                                    None => 0,
                                };
                                list_state.select(Some(i));
                            }
                        }

                        // ── Execution ───────────────────────────────
                        KeyCode::Enter if active_pane == ActivePane::Sidebar => {
                            if app_tab == AppTab::Strings {
                                if let Some(i) = strings_list_state.selected()
                                    && let Some(cmd) = strings_sidebar_command(i)
                                {
                                    input = cmd.to_string();
                                    active_pane = ActivePane::Input;
                                }
                            } else if app_tab == AppTab::Decompiler
                                || app_tab == AppTab::XRefs
                                || app_tab == AppTab::Overview
                            {
                                if let Some(i) = list_state.selected() {
                                    if functions.is_empty() {
                                        if let Some(cmd) = sidebar_command(app_tab, i) {
                                            input = cmd.to_string();
                                            active_pane = ActivePane::Input;
                                        }
                                    } else if let Some(func) = functions.get(i) {
                                        let func_name = func.name.clone();
                                        trigger_function_actions(
                                            func_name,
                                            bridge_port,
                                            &mut decompiled_code,
                                            &tx_decompile,
                                            &tx_xrefs,
                                        );
                                    }
                                }
                            }
                        }

                        // ── Input mode handling ─────────────────────
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
                        KeyCode::Up
                            if active_pane == ActivePane::Input && !command_history.is_empty() =>
                        {
                            if history_index.is_none() {
                                history_search_prefix = input.clone();
                            }
                            let mut start_idx = history_index.unwrap_or(command_history.len());
                            while start_idx > 0 {
                                start_idx -= 1;
                                if command_history[start_idx].starts_with(&history_search_prefix) {
                                    history_index = Some(start_idx);
                                    input = command_history[start_idx].clone();
                                    break;
                                }
                            }
                        }
                        KeyCode::Down if active_pane == ActivePane::Input => {
                            if let Some(mut curr_idx) = history_index {
                                let mut found = false;
                                while curr_idx + 1 < command_history.len() {
                                    curr_idx += 1;
                                    if command_history[curr_idx].starts_with(&history_search_prefix)
                                    {
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
                            commands::accept_completion(&mut input, &command_history, &suggestions);
                        }
                        KeyCode::Enter if active_pane == ActivePane::Input => {
                            let cmd = input.trim().to_string();
                            input.clear();
                            history_index = None;
                            history_search_prefix.clear();
                            if !cmd.is_empty() {
                                command_history.push(cmd.clone());
                                if cmd == "quit" || cmd == "exit" || cmd == "q" {
                                    break;
                                }

                                // If `info` command, also update overview
                                if cmd.starts_with("info ") {
                                    let target =
                                        cmd.strip_prefix("info ").unwrap_or("").trim().to_string();
                                    overview_lines = binary_info::scan_binary_info(&target);
                                }

                                let state_clone = Arc::clone(&state);
                                tokio::spawn(async move {
                                    runner::run_console_command(state_clone, cmd).await;
                                });
                            }
                        }
                        _ => {}
                    }
                }
                Event::Mouse(mouse) => {
                    let pos = Position::new(mouse.column, mouse.row);
                    let is_click = is_left_click(mouse.kind);

                    // ── Click on Tab Bar → switch tab ────────────────
                    if tab_area.contains(pos) {
                        if is_click {
                            if let Some(tab) = tab_from_click(tab_area, pos) {
                                app_tab = tab;
                                if matches!(tab, AppTab::XRefs) {
                                    fetch_xrefs_for_selected_function(
                                        &functions,
                                        &list_state,
                                        bridge_port,
                                        &tx_xrefs,
                                    );
                                }
                            }
                        }
                    }
                    // ── Click / scroll in Sidebar ────────────────────
                    else if sidebar_area.contains(pos) {
                        match mouse.kind {
                            _ if is_click => {
                                active_pane = ActivePane::Sidebar;
                                let clicked = match app_tab {
                                    AppTab::Overview | AppTab::Decompiler | AppTab::XRefs => {
                                        let len = if functions.is_empty() {
                                            sidebar_command_count(app_tab)
                                        } else {
                                            functions.len()
                                        };
                                        sidebar_index_from_click(
                                            sidebar_area,
                                            pos,
                                            list_state.offset(),
                                            len,
                                        )
                                    }
                                    AppTab::Strings => sidebar_index_from_click(
                                        sidebar_area,
                                        pos,
                                        strings_list_state.offset(),
                                        if strings.is_empty() {
                                            strings_sidebar_commands().len()
                                        } else {
                                            strings.len()
                                        },
                                    ),
                                    AppTab::ROP => sidebar_index_from_click(
                                        sidebar_area,
                                        pos,
                                        rop_list_state.offset(),
                                        rop_gadgets.len(),
                                    ),
                                    AppTab::Firmware => sidebar_index_from_click(
                                        sidebar_area,
                                        pos,
                                        firmware_list_state.offset(),
                                        firmware_entries.len(),
                                    ),
                                    AppTab::Findings => sidebar_index_from_click(
                                        sidebar_area,
                                        pos,
                                        findings_list_state.offset(),
                                        findings_list.len(),
                                    ),
                                    AppTab::Toolkit => None,
                                };

                                if let Some(clicked) = clicked {
                                    if app_tab == AppTab::Strings {
                                        strings_list_state.select(Some(clicked));
                                        if strings.is_empty() {
                                            if let Some(cmd) = strings_sidebar_command(clicked) {
                                                input = cmd.to_string();
                                                active_pane = ActivePane::Input;
                                            }
                                        }
                                    } else if app_tab == AppTab::ROP {
                                        rop_list_state.select(Some(clicked));
                                    } else if app_tab == AppTab::Firmware {
                                        firmware_list_state.select(Some(clicked));
                                    } else if app_tab == AppTab::Findings {
                                        findings_list_state.select(Some(clicked));
                                    } else if matches!(
                                        app_tab,
                                        AppTab::Overview | AppTab::Decompiler | AppTab::XRefs
                                    ) {
                                        list_state.select(Some(clicked));
                                        if functions.is_empty() {
                                            if let Some(cmd) = sidebar_command(app_tab, clicked) {
                                                input = cmd.to_string();
                                                active_pane = ActivePane::Input;
                                            }
                                        } else if let Some(func) = functions.get(clicked) {
                                            trigger_function_actions(
                                                func.name.clone(),
                                                bridge_port,
                                                &mut decompiled_code,
                                                &tx_decompile,
                                                &tx_xrefs,
                                            );
                                        }
                                    }
                                }
                            }
                            MouseEventKind::ScrollDown => {
                                active_pane = ActivePane::Sidebar;
                                match app_tab {
                                    AppTab::Overview | AppTab::Decompiler | AppTab::XRefs => {
                                        let last = if functions.is_empty() {
                                            sidebar_command_count(app_tab).saturating_sub(1)
                                        } else {
                                            functions.len().saturating_sub(1)
                                        };
                                        let i = list_state.selected().unwrap_or(0);
                                        let next = (i + 1).min(last);
                                        list_state.select(Some(next));
                                    }
                                    AppTab::Strings => {
                                        let last = if strings.is_empty() {
                                            strings_sidebar_commands().len().saturating_sub(1)
                                        } else {
                                            strings.len().saturating_sub(1)
                                        };
                                        let i = strings_list_state.selected().unwrap_or(0);
                                        let next = (i + 1).min(last);
                                        strings_list_state.select(Some(next));
                                    }
                                    AppTab::ROP => {
                                        let i = rop_list_state.selected().unwrap_or(0);
                                        let next = (i + 1).min(rop_gadgets.len().saturating_sub(1));
                                        rop_list_state.select(Some(next));
                                    }
                                    AppTab::Firmware => {
                                        let i = firmware_list_state.selected().unwrap_or(0);
                                        let next =
                                            (i + 1).min(firmware_entries.len().saturating_sub(1));
                                        firmware_list_state.select(Some(next));
                                    }
                                    AppTab::Findings => {
                                        let i = findings_list_state.selected().unwrap_or(0);
                                        let next =
                                            (i + 1).min(findings_list.len().saturating_sub(1));
                                        findings_list_state.select(Some(next));
                                    }
                                    AppTab::Toolkit => {}
                                }
                            }
                            MouseEventKind::ScrollUp => {
                                active_pane = ActivePane::Sidebar;
                                match app_tab {
                                    AppTab::Overview | AppTab::Decompiler | AppTab::XRefs => {
                                        let max = if functions.is_empty() {
                                            sidebar_command_count(app_tab).saturating_sub(1)
                                        } else {
                                            functions.len().saturating_sub(1)
                                        };
                                        let i = match list_state.selected() {
                                            Some(i) if i > max => max,
                                            Some(i) => i,
                                            None => 0,
                                        };
                                        list_state.select(Some(i.saturating_sub(1)));
                                    }
                                    AppTab::Strings => {
                                        let max = if strings.is_empty() {
                                            strings_sidebar_commands().len().saturating_sub(1)
                                        } else {
                                            strings.len().saturating_sub(1)
                                        };
                                        let i = match strings_list_state.selected() {
                                            Some(i) if i > max => max,
                                            Some(i) => i,
                                            None => 0,
                                        };
                                        strings_list_state.select(Some(i.saturating_sub(1)));
                                    }
                                    AppTab::ROP => {
                                        let i = rop_list_state.selected().unwrap_or(0);
                                        rop_list_state.select(Some(i.saturating_sub(1)));
                                    }
                                    AppTab::Firmware => {
                                        let i = firmware_list_state.selected().unwrap_or(0);
                                        firmware_list_state.select(Some(i.saturating_sub(1)));
                                    }
                                    AppTab::Findings => {
                                        let i = findings_list_state.selected().unwrap_or(0);
                                        findings_list_state.select(Some(i.saturating_sub(1)));
                                    }
                                    AppTab::Toolkit => {}
                                }
                            }
                            _ => {}
                        }
                    }
                    // ── Click / scroll in Main Content ──────────────
                    else if main_content_area.contains(pos) {
                        match mouse.kind {
                            kind if is_left_click(kind) => {
                                active_pane = ActivePane::MainContent;
                            }
                            MouseEventKind::ScrollDown => {
                                if matches!(app_tab, AppTab::Overview | AppTab::Toolkit) {
                                    // non-list detail regions currently do not support per-panel
                                    // item scrolling; keep behavior stable and avoid accidental
                                    // sidebar selection side effects.
                                }
                            }
                            MouseEventKind::ScrollUp => {
                                if matches!(app_tab, AppTab::Overview | AppTab::Toolkit) {
                                    // keep behavior stable
                                }
                            }
                            _ => {}
                        }
                    }
                    // ── Click on Input Console → focus it ────────────
                    else if input_area.contains(pos) {
                        if is_click {
                            active_pane = ActivePane::Input;
                        }
                    }
                    // ── Click on Log Area → toggle event view ────────
                    else if log_area.contains(pos) && is_click {
                        // Double-purpose: click log area to toggle view
                        event_view = event_view.toggle();
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

// ─── Reusable Widget Renderers ────────────────────────────────────────────────

type SidebarCommand<'a> = (&'a str, &'a str);

const OVERVIEW_QUICKSTART_COMMANDS: [SidebarCommand<'static>; 4] = [
    ("info <binary>", "show basic binary summary in Overview"),
    (
        "toolkit rizin <binary>",
        "fast local function scan (no Ghidra needed)",
    ),
    (
        "analyze <binary> -p <project_dir> -n <project_name>",
        "load into Ghidra bridge backend",
    ),
    (
        "bridge -p <project_dir> -n <project_name>",
        "start or restart bridge daemon",
    ),
];

const DECOMPILER_QUICKSTART_COMMANDS: [SidebarCommand<'static>; 4] = [
    (
        "toolkit rizin <binary>",
        "fast local scan, then choose a symbol",
    ),
    (
        "analyze <binary> -p <project_dir> -n <project_name>",
        "prepare Ghidra for decompile and xrefs",
    ),
    ("info <binary>", "load file metadata into Overview"),
    (
        "query search_strings <pattern>",
        "run backend query once bridge is ready",
    ),
];

const XREFS_QUICKSTART_COMMANDS: [SidebarCommand<'static>; 4] = [
    (
        "analyze <binary> -p <project_dir> -n <project_name>",
        "prepare Ghidra backend then switch to [x]",
    ),
    (
        "bridge -p <project_dir> -n <project_name>",
        "connect to existing bridge daemon",
    ),
    (
        "toolkit rizin <binary>",
        "populate local function list first",
    ),
    ("info <binary>", "inspect binary metadata before xrefs"),
];

const STRINGS_QUICKSTART_COMMANDS: [SidebarCommand<'static>; 3] = [
    ("toolkit strings <binary>", "extract ASCII/UTF-8 strings"),
    (
        "query search_strings <pattern>",
        "search in currently attached bridge",
    ),
    (
        "toolkit rizin <binary>",
        "offline scan and string discovery",
    ),
];

fn sidebar_commands_for_tab(tab: AppTab) -> &'static [SidebarCommand<'static>] {
    match tab {
        AppTab::Overview => &OVERVIEW_QUICKSTART_COMMANDS,
        AppTab::Decompiler => &DECOMPILER_QUICKSTART_COMMANDS,
        AppTab::XRefs => &XREFS_QUICKSTART_COMMANDS,
        _ => &[],
    }
}

fn sidebar_command(tab: AppTab, idx: usize) -> Option<&'static str> {
    sidebar_commands_for_tab(tab).get(idx).map(|(cmd, _)| *cmd)
}

fn sidebar_command_count(tab: AppTab) -> usize {
    sidebar_commands_for_tab(tab).len()
}

fn strings_sidebar_commands() -> &'static [SidebarCommand<'static>] {
    &STRINGS_QUICKSTART_COMMANDS
}

fn strings_sidebar_command(idx: usize) -> Option<&'static str> {
    strings_sidebar_commands().get(idx).map(|(cmd, _)| *cmd)
}

fn render_sidebar_command_list(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    focused: bool,
    title: &str,
    commands: &[SidebarCommand<'static>],
    list_state: &mut ListState,
) {
    if list_state.selected().is_none() && !commands.is_empty() {
        list_state.select(Some(0));
    }

    let sidebar_items: Vec<ListItem> = commands
        .iter()
        .map(|(cmd, desc)| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{HIGHLIGHT_SYMBOL}{cmd} "),
                    Style::default()
                        .fg(theme::AMBER)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(*desc, Style::default().fg(theme::SAND)),
            ]))
        })
        .collect();

    let list = List::new(sidebar_items)
        .block(themed_block(title, focused))
        .highlight_style(theme::list_highlight())
        .highlight_symbol(HIGHLIGHT_SYMBOL);
    f.render_stateful_widget(list, area, list_state);
}

/// Render the function sidebar (shared by Decompiler, XRefs, Overview).
fn render_sidebar_functions(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    focused: bool,
    bridge_connected: bool,
    tab: AppTab,
    functions: &[FunctionInfo],
    list_state: &mut ListState,
) {
    if functions.is_empty() {
        let fallback = sidebar_commands_for_tab(tab);
        if !fallback.is_empty() {
            render_sidebar_command_list(f, area, focused, "Functions", fallback, list_state);
        } else if bridge_connected {
            render_placeholder(
                f,
                area,
                focused,
                "Functions",
                &[
                    "No functions loaded.",
                    "",
                    "Start here in the console:",
                    "  toolkit rizin <binary> (fast local scan)",
                    "  analyze <bin> -p <project_dir> -n <project_name>",
                    "  bridge -p <project_dir> -n <project_name> (backend)",
                    "",
                    "After functions appear:",
                    "  Press Enter to decompile",
                    "  Press [x] to load callers/callees",
                ],
            );
        } else {
            render_placeholder(
                f,
                area,
                focused,
                "Functions",
                &[
                    "No bridge available.",
                    "",
                    "Start here in the console:",
                    "  toolkit rizin <binary> (fast local scan)",
                    "  analyze <bin> -p <project_dir> -n <project_name> (Ghidra)",
                    "  bridge -p <project_dir> -n <project_name> (start backend)",
                ],
            );
        }
        return;
    }

    let func_items: Vec<ListItem> = functions
        .iter()
        .map(|func| {
            ListItem::new(Line::from(vec![
                Span::styled(&func.name, Style::default().fg(theme::BONE)),
                Span::styled(format!(" @ {}", func.address), theme::address()),
            ]))
        })
        .collect();
    let func_list = List::new(func_items)
        .block(themed_block("Functions", focused))
        .highlight_style(theme::list_highlight())
        .highlight_symbol(HIGHLIGHT_SYMBOL);
    f.render_stateful_widget(func_list, area, list_state);
}

fn fetch_xrefs_for_selected_function(
    functions: &[FunctionInfo],
    list_state: &ListState,
    bridge_port: Option<u16>,
    tx_xrefs: &tokio::sync::mpsc::Sender<(Vec<FunctionInfo>, Vec<FunctionInfo>)>,
) {
    let Some(i) = list_state.selected() else {
        return;
    };

    let Some(func) = functions.get(i) else {
        return;
    };

    let func_name = func.name.clone();
    let tx = tx_xrefs.clone();
    tokio::spawn(async move {
        if let Some(p) = bridge_port {
            let client = BridgeClient::new(p);
            let callers = client.callers(&func_name).await.unwrap_or_default();
            let callees = client.callees(&func_name).await.unwrap_or_default();
            let _ = tx.send((callers, callees)).await;
        }
    });
}

/// Render the Overview tab — shows the ASCII banner + binary summary.
#[allow(clippy::too_many_arguments)]
fn render_overview(
    f: &mut ratatui::Frame,
    sidebar_area: ratatui::layout::Rect,
    main_area: ratatui::layout::Rect,
    sidebar_focused: bool,
    main_focused: bool,
    bridge_connected: bool,
    tab: AppTab,
    functions: &[FunctionInfo],
    list_state: &mut ListState,
    overview_lines: &[String],
    tick: u64,
) {
    render_sidebar_functions(
        f,
        sidebar_area,
        sidebar_focused,
        bridge_connected,
        tab,
        functions,
        list_state,
    );

    // Build main panel content: banner + overview info
    let mut lines: Vec<Line> = Vec::new();

    // ASCII banner with full fire gradient
    lines.push(Line::from(""));
    for banner_line in theme::gradient_banner() {
        lines.push(banner_line);
    }

    // Subtitle with shimmer
    lines.push(Line::from(""));
    let phase = ((tick % 40) as f32) / 40.0;
    let sub_color = theme::lerp_color(theme::ORANGE, theme::SOLAR, phase);
    lines.push(Line::from(Span::styled(
        format!("    {}", theme::BANNER_SUBTITLE),
        Style::default()
            .fg(sub_color)
            .add_modifier(Modifier::ITALIC),
    )));
    lines.push(Line::from(""));

    // Gradient rule
    let rule_width = main_area.width.saturating_sub(4) as usize;
    lines.push(theme::gradient_rule(rule_width, theme::EMBER, theme::SOLAR));
    lines.push(Line::from(""));

    if overview_lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Run  info <binary>  to display binary metadata here.",
            Style::default().fg(theme::ASH),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Adapters: Ghidra · Rizin · Binwalk · checksec · ROP",
            Style::default().fg(theme::SMOKE),
        )));
    } else {
        for (i, line) in overview_lines.iter().enumerate() {
            let t = i as f32 / (overview_lines.len()).max(1) as f32;
            let c = theme::gradient(theme::FIRE_GRADIENT, t);
            lines.push(Line::from(Span::styled(
                format!("  {}", line),
                Style::default().fg(c),
            )));
        }
    }

    // Status bar at bottom
    lines.push(Line::from(""));
    let bridge_status = if overview_lines.iter().any(|l| l.contains("Format:")) {
        "● binary loaded"
    } else {
        "○ no binary loaded"
    };
    lines.push(theme::gradient_status(&format!(
        "  {} │ v{} │ {}",
        bridge_status,
        env!("CARGO_PKG_VERSION"),
        "press TAB to navigate"
    )));

    let overview_block = Paragraph::new(lines)
        .block(themed_block("Overview", main_focused))
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: false });
    f.render_widget(overview_block, main_area);
}

/// Render a placeholder panel with themed text.
fn render_placeholder(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    focused: bool,
    title: &str,
    lines: &[&str],
) {
    let content: Vec<Line> = std::iter::once(Line::from(""))
        .chain(lines.iter().enumerate().map(|(i, line)| {
            if line.is_empty() {
                Line::from("")
            } else if line.starts_with("  ") {
                // Indented lines are commands — highlight them
                Line::from(Span::styled(
                    *line,
                    Style::default()
                        .fg(theme::AMBER)
                        .add_modifier(Modifier::BOLD),
                ))
            } else if line.starts_with('[') {
                // Severity tags
                let t = i as f32 / lines.len().max(1) as f32;
                let c = theme::gradient(theme::FIRE_GRADIENT, t);
                Line::from(Span::styled(*line, Style::default().fg(c)))
            } else {
                Line::from(Span::styled(*line, Style::default().fg(theme::SAND)))
            }
        }))
        .collect();

    let block = Paragraph::new(content)
        .block(themed_block(title, focused))
        .wrap(Wrap { trim: false });
    f.render_widget(block, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{MouseButton, MouseEventKind};

    #[test]
    fn recognizes_left_mouse_click_variants() {
        assert!(is_left_click(MouseEventKind::Down(MouseButton::Left)));
        assert!(is_left_click(MouseEventKind::Up(MouseButton::Left)));
        assert!(is_left_click(MouseEventKind::Drag(MouseButton::Left)));
        assert!(!is_left_click(MouseEventKind::Down(MouseButton::Right)));
    }

    #[test]
    fn sidebar_index_from_click_hits_scrolled_rows() {
        let area = Rect::new(2, 3, 20, 8);
        let pos = Position::new(5, 4); // content row 0

        assert_eq!(sidebar_index_from_click(area, pos, 3, 12), Some(3));
        assert_eq!(sidebar_index_from_click(area, pos, 3, 100), Some(3));
        assert_eq!(sidebar_index_from_click(area, pos, 3, 3), None);
        assert_eq!(
            sidebar_index_from_click(area, Position::new(2, 4), 3, 12),
            None
        );
        assert_eq!(
            sidebar_index_from_click(area, Position::new(21, 4), 3, 12),
            None
        );
    }

    #[test]
    fn sidebar_index_from_click_ignores_border_lines() {
        let area = Rect::new(0, 0, 12, 4); // content rows y=1..2
        assert_eq!(
            sidebar_index_from_click(area, Position::new(1, 0), 0, 10),
            None
        );
        assert_eq!(
            sidebar_index_from_click(area, Position::new(1, 3), 0, 10),
            None
        );
        assert_eq!(
            sidebar_index_from_click(area, Position::new(1, 1), 0, 1),
            Some(0)
        );
    }

    #[test]
    fn tab_from_click_matches_tab_positions() {
        let area = Rect::new(0, 0, 120, 3);
        let mut cursor: u16 = 0;
        for tab in AppTab::ALL {
            let x = area.x + 1 + cursor;
            let y = area.y + 1;
            assert!(matches!(tab_from_click(area, Position::new(x, y)), Some(v) if v == *tab));
            cursor = cursor.saturating_add(tab.label().chars().count() as u16 + 1);
        }

        // divider area should not resolve to a tab
        let first = AppTab::ALL[0];
        let divider_x = area.x + 1 + first.label().chars().count() as u16;
        assert!(tab_from_click(area, Position::new(divider_x, 1)).is_none());
    }
}
