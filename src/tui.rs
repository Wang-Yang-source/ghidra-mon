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

use crate::adapter::schema::ToolEvent;
use crate::bridge::{BridgeClient, read_bridge_port};
use crate::error::Result;
use crate::types::*;
use model::{ActivePane, AppTab, EventView};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, MouseEventKind},
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
        tick = tick.wrapping_add(1);

        // Dynamic Bridge Detection
        if bridge_port.is_none() && last_bridge_check.elapsed() > Duration::from_secs(1) {
            last_bridge_check = std::time::Instant::now();
            if let Some(port) = read_bridge_port() {
                bridge_port = Some(port);
                let mut st = state.lock().await;
                st.logs.push(events::event_line(ToolEvent::status(
                    "ghidra",
                    format!(
                        "bridge detected on port {}; loading symbols and strings",
                        port
                    ),
                )));

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
                    render_overview(f, ide_chunks[0], ide_chunks[1], sidebar_focused, main_focused, &functions, &mut list_state, &overview_lines, tick);
                }
                AppTab::Decompiler => {
                    render_sidebar_functions(f, ide_chunks[0], sidebar_focused, &functions, &mut list_state);
                    let highlighted_lines = highlight::c_code(&decompiled_code, &ps, &ts);
                    let code_block = Paragraph::new(highlighted_lines)
                        .block(themed_block("Decompiled C", main_focused))
                        .wrap(Wrap { trim: false });
                    f.render_widget(code_block, ide_chunks[1]);
                }
                AppTab::XRefs => {
                    render_sidebar_functions(f, ide_chunks[0], sidebar_focused, &functions, &mut list_state);

                    let xrefs_chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                        .split(ide_chunks[1]);

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
                AppTab::Strings => {
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
                    render_sidebar_functions(f, ide_chunks[0], sidebar_focused, &functions, &mut list_state);
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
                }
                AppTab::Firmware => {
                    let fw_sidebar_items: Vec<ListItem> = vec![
                        ListItem::new(Line::from(vec![
                            Span::styled("binwalk", Style::default().fg(theme::ORANGE).add_modifier(Modifier::BOLD)),
                            Span::styled("  firmware scanner", Style::default().fg(theme::ASH)),
                        ])),
                    ];
                    let fw_list = List::new(fw_sidebar_items)
                        .block(themed_block("Engines", sidebar_focused))
                        .highlight_style(theme::list_highlight())
                        .highlight_symbol(HIGHLIGHT_SYMBOL);
                    f.render_widget(fw_list, ide_chunks[0]);
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
                }
                AppTab::Findings => {
                    render_placeholder(f, ide_chunks[0], sidebar_focused,
                        "Severity",
                        &["[Critical]", "[High]", "[Medium]", "[Low]", "[Info]"],
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
                commands::ghost_text(&input, &command_history, &suggestions)
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
                String::from(" Console │ → accepts completion ")
            };

            // Pulse the cursor color slightly
            let cursor_phase = ((tick % 20) as f32) / 20.0;
            let cursor_color = theme::lerp_color(theme::ORANGE, theme::SOLAR, cursor_phase);

            let line = Line::from(vec![
                Span::styled("❯ ", theme::prompt()),
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
                            // Focus input instead of quitting
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
                            if let Some(i) = list_state.selected()
                                && let Some(func) = functions.get(i)
                            {
                                let func_name = func.name.clone();
                                let tx = tx_xrefs.clone();
                                let port = bridge_port;
                                tokio::spawn(async move {
                                    if let Some(p) = port {
                                        let client = BridgeClient::new(p);
                                        let callers =
                                            client.callers(&func_name).await.unwrap_or_default();
                                        let callees =
                                            client.callees(&func_name).await.unwrap_or_default();
                                        let _ = tx.send((callers, callees)).await;
                                    }
                                });
                            }
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
                                        if i == 0 {
                                            0
                                        } else {
                                            i - 1
                                        }
                                    }
                                    None => 0,
                                };
                                strings_list_state.select(Some(i));
                            } else {
                                let i = match list_state.selected() {
                                    Some(i) => {
                                        if i == 0 {
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
                                let i = match strings_list_state.selected() {
                                    Some(i) => {
                                        if i >= strings.len().saturating_sub(1) {
                                            strings.len().saturating_sub(1)
                                        } else {
                                            i + 1
                                        }
                                    }
                                    None => 0,
                                };
                                strings_list_state.select(Some(i));
                            } else {
                                let i = match list_state.selected() {
                                    Some(i) => {
                                        if i >= functions.len().saturating_sub(1) {
                                            functions.len().saturating_sub(1)
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
                            if (app_tab == AppTab::Decompiler
                                || app_tab == AppTab::XRefs
                                || app_tab == AppTab::Overview)
                                && let Some(i) = list_state.selected()
                                && let Some(func) = functions.get(i)
                            {
                                let func_name = func.name.clone();

                                // Fetch Decompile
                                let tx_dec = tx_decompile.clone();
                                let port = bridge_port;
                                decompiled_code = format!("Decompiling {}...", func_name);
                                let func_name_dec = func_name.clone();
                                tokio::spawn(async move {
                                    if let Some(p) = port {
                                        let client = BridgeClient::new(p);
                                        if let Ok(res) = client.decompile(&func_name_dec).await
                                            && let Some(c_code) = res.c_code
                                        {
                                            let _ = tx_dec.send(c_code).await;
                                        }
                                    }
                                });

                                // Fetch XRefs
                                let tx_x = tx_xrefs.clone();
                                let func_name2 = func_name.clone();
                                tokio::spawn(async move {
                                    if let Some(p) = port {
                                        let client = BridgeClient::new(p);
                                        let callers =
                                            client.callers(&func_name2).await.unwrap_or_default();
                                        let callees =
                                            client.callees(&func_name2).await.unwrap_or_default();
                                        let _ = tx_x.send((callers, callees)).await;
                                    }
                                });
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

                    // ── Click on Tab Bar → switch tab ────────────────
                    if tab_area.contains(pos) {
                        if let MouseEventKind::Down(crossterm::event::MouseButton::Left) =
                            mouse.kind
                        {
                            // Compute which tab was clicked based on horizontal position
                            let inner_x = mouse.column.saturating_sub(tab_area.x + 1); // skip border
                            let inner_w = tab_area.width.saturating_sub(2).max(1);
                            let tab_count = AppTab::ALL.len() as u16;
                            let tab_idx =
                                ((inner_x as u32 * tab_count as u32) / inner_w as u32) as usize;
                            if let Some(clicked_tab) =
                                AppTab::ALL.get(tab_idx.min(AppTab::ALL.len() - 1))
                            {
                                app_tab = *clicked_tab;
                            }
                        }
                    }
                    // ── Click / scroll in Sidebar ────────────────────
                    else if sidebar_area.contains(pos) {
                        match mouse.kind {
                            MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                                active_pane = ActivePane::Sidebar;
                                // Calculate which list item was clicked
                                let row_in_list =
                                    mouse.row.saturating_sub(sidebar_area.y + 1) as usize; // +1 for border
                                if app_tab == AppTab::Strings {
                                    let offset = strings_list_state.offset();
                                    let clicked = offset + row_in_list;
                                    if clicked < strings.len() {
                                        strings_list_state.select(Some(clicked));
                                    }
                                } else {
                                    let offset = list_state.offset();
                                    let clicked = offset + row_in_list;
                                    if clicked < functions.len() {
                                        list_state.select(Some(clicked));
                                        // Auto-trigger decompile + xrefs on click
                                        if let Some(func) = functions.get(clicked) {
                                            let func_name = func.name.clone();
                                            let tx_dec = tx_decompile.clone();
                                            let port = bridge_port;
                                            decompiled_code =
                                                format!("Decompiling {}...", func_name);
                                            let func_name_dec = func_name.clone();
                                            tokio::spawn(async move {
                                                if let Some(p) = port {
                                                    let client = BridgeClient::new(p);
                                                    if let Ok(res) =
                                                        client.decompile(&func_name_dec).await
                                                        && let Some(c_code) = res.c_code
                                                    {
                                                        let _ = tx_dec.send(c_code).await;
                                                    }
                                                }
                                            });
                                            let tx_x = tx_xrefs.clone();
                                            let func_name2 = func_name.clone();
                                            tokio::spawn(async move {
                                                if let Some(p) = port {
                                                    let client = BridgeClient::new(p);
                                                    let callers = client
                                                        .callers(&func_name2)
                                                        .await
                                                        .unwrap_or_default();
                                                    let callees = client
                                                        .callees(&func_name2)
                                                        .await
                                                        .unwrap_or_default();
                                                    let _ = tx_x.send((callers, callees)).await;
                                                }
                                            });
                                        }
                                    }
                                }
                            }
                            MouseEventKind::ScrollDown => {
                                active_pane = ActivePane::Sidebar;
                                if app_tab == AppTab::Strings {
                                    let i = strings_list_state.selected().unwrap_or(0);
                                    let next = (i + 1).min(strings.len().saturating_sub(1));
                                    strings_list_state.select(Some(next));
                                } else {
                                    let i = list_state.selected().unwrap_or(0);
                                    let next = (i + 1).min(functions.len().saturating_sub(1));
                                    list_state.select(Some(next));
                                }
                            }
                            MouseEventKind::ScrollUp => {
                                active_pane = ActivePane::Sidebar;
                                if app_tab == AppTab::Strings {
                                    let i = strings_list_state.selected().unwrap_or(0);
                                    strings_list_state.select(Some(i.saturating_sub(1)));
                                } else {
                                    let i = list_state.selected().unwrap_or(0);
                                    list_state.select(Some(i.saturating_sub(1)));
                                }
                            }
                            _ => {}
                        }
                    }
                    // ── Click / scroll in Main Content ──────────────
                    else if main_content_area.contains(pos) {
                        match mouse.kind {
                            MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                                active_pane = ActivePane::MainContent;
                            }
                            // Scroll in main content area also navigates sidebar list
                            // (content panels like Decompiler/Overview are not scrollable yet)
                            MouseEventKind::ScrollDown => {
                                if app_tab == AppTab::Strings {
                                    let i = strings_list_state.selected().unwrap_or(0);
                                    let next = (i + 1).min(strings.len().saturating_sub(1));
                                    strings_list_state.select(Some(next));
                                } else {
                                    let i = list_state.selected().unwrap_or(0);
                                    let next = (i + 1).min(functions.len().saturating_sub(1));
                                    list_state.select(Some(next));
                                }
                            }
                            MouseEventKind::ScrollUp => {
                                if app_tab == AppTab::Strings {
                                    let i = strings_list_state.selected().unwrap_or(0);
                                    strings_list_state.select(Some(i.saturating_sub(1)));
                                } else {
                                    let i = list_state.selected().unwrap_or(0);
                                    list_state.select(Some(i.saturating_sub(1)));
                                }
                            }
                            _ => {}
                        }
                    }
                    // ── Click on Input Console → focus it ────────────
                    else if input_area.contains(pos) {
                        if mouse.kind == MouseEventKind::Down(crossterm::event::MouseButton::Left) {
                            active_pane = ActivePane::Input;
                        }
                    }
                    // ── Click on Log Area → toggle event view ────────
                    else if log_area.contains(pos)
                        && let MouseEventKind::Down(crossterm::event::MouseButton::Left) =
                            mouse.kind
                    {
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

/// Render the function sidebar (shared by Decompiler, XRefs, ROP, Overview).
fn render_sidebar_functions(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    focused: bool,
    functions: &[FunctionInfo],
    list_state: &mut ListState,
) {
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

/// Render the Overview tab — shows the ASCII banner + binary summary.
#[allow(clippy::too_many_arguments)]
fn render_overview(
    f: &mut ratatui::Frame,
    sidebar_area: ratatui::layout::Rect,
    main_area: ratatui::layout::Rect,
    sidebar_focused: bool,
    main_focused: bool,
    functions: &[FunctionInfo],
    list_state: &mut ListState,
    overview_lines: &[String],
    tick: u64,
) {
    render_sidebar_functions(f, sidebar_area, sidebar_focused, functions, list_state);

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
