// Ghidrai terminal workspace.
// The TUI presents a unified toolkit surface over pluggable backends.

mod binary_info;
mod commands;
mod events;
mod highlight;
mod model;
mod runner;

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
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap},
};
use std::{io, sync::Arc, time::Duration};
use syntect::highlighting::ThemeSet;
use syntect::parsing::SyntaxSet;
use tokio::sync::Mutex;

pub const SOCKET_PATH: &str = "/tmp/ghidrai.sock";

pub async fn run_tui(state: Arc<Mutex<DaemonState>>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut input = String::new();
    let mut active_pane = ActivePane::Input;
    let mut app_tab = AppTab::Decompiler;
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

    // Syntect setup
    let ps = SyntaxSet::load_defaults_newlines();
    let ts = ThemeSet::load_defaults();

    // Check if bridge is available initially
    let mut bridge_port = read_bridge_port();

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
                "keys: TAB focus | d decompile | x xrefs | s strings | t toolkit | v event view | Ctrl+C quit",
            )));
        } else {
            st.logs.push(events::event_line(ToolEvent::status(
                "tui",
                "no Ghidra bridge detected; local toolkit commands remain available.",
            )));
            st.logs.push(events::event_line(ToolEvent::status(
                "tui",
                "try: info <bin>, toolkit binwalk <bin>, toolkit checksec <bin>, toolkit rop <bin>",
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
                Line::from(" [d] Decompile "),
                Line::from(" [x] Xrefs "),
                Line::from(" [s] Strings "),
                Line::from(" [t] Toolkit "),
            ];
            let tab_index = match app_tab {
                AppTab::Decompiler => 0,
                AppTab::XRefs => 1,
                AppTab::Strings => 2,
                AppTab::Toolkit => 3,
            };
            let tabs = Tabs::new(titles)
                .block(Block::default().borders(Borders::ALL).title(" Workspace "))
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
            let sidebar_border = if active_pane == ActivePane::Sidebar {
                Color::Yellow
            } else {
                Color::DarkGray
            };

            if app_tab == AppTab::Strings {
                let str_items: Vec<ListItem> = strings
                    .iter()
                    .map(|s| ListItem::new(format!("{} | {}", s.address, s.value)))
                    .collect();
                let str_list = List::new(str_items)
                    .block(Block::default().title(" Strings ").borders(Borders::ALL).border_style(Style::default().fg(sidebar_border)))
                    .highlight_style(Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD))
                    .highlight_symbol("> ");
                f.render_stateful_widget(str_list, ide_chunks[0], &mut strings_list_state);

                let detail = if let Some(i) = strings_list_state.selected() {
                    strings
                        .get(i)
                        .map(|s| {
                            format!(
                                "Adapter: Ghidra\nAddress: {}\nValue:\n{}",
                                s.address, s.value
                            )
                        })
                        .unwrap_or_else(|| "No string selected.".to_string())
                } else {
                    "No strings loaded. Start a backend adapter or run a toolkit command from the console.".to_string()
                };
                let detail_block = Paragraph::new(detail)
                    .block(Block::default().title(" String Detail ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
                    .wrap(Wrap { trim: false });
                f.render_widget(detail_block, ide_chunks[1]);
            } else if app_tab == AppTab::Toolkit {
                let tools = [
                    "info <bin>              binary format and section summary",
                    "toolkit binwalk <bin>   firmware signatures and embedded structures",
                    "toolkit checksec <bin>  ELF hardening features",
                    "toolkit rop <bin>       ROP gadget discovery",
                    "toolkit rizin <bin>     Rizin JSON static analysis",
                    "analyze <bin> ...       import into the Ghidra backend adapter",
                    "bridge ...              start the Ghidra backend adapter",
                    "query <cmd> ...         inspect a running backend adapter",
                ];
                let tool_items: Vec<ListItem> = tools.iter().map(|tool| ListItem::new(*tool)).collect();
                let tool_list = List::new(tool_items)
                    .block(Block::default().title(" Tool Adapters ").borders(Borders::ALL).border_style(Style::default().fg(sidebar_border)))
                    .highlight_symbol("> ");
                f.render_widget(tool_list, ide_chunks[0]);

                let detail = "Ghidrai treats every engine as an adapter.\n\nThe TUI shows structured events and keeps raw stdout/stderr in the event log. Ghidra and Rizin are static-analysis backends; Binwalk, checksec and ROP adapters are toolkit engines available from the command console.";
                let detail_block = Paragraph::new(detail)
                    .block(Block::default().title(" Adapter Model ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
                    .wrap(Wrap { trim: false });
                f.render_widget(detail_block, ide_chunks[1]);
            } else {
                let func_items: Vec<ListItem> = functions
                    .iter()
                    .map(|func| ListItem::new(format!("{} @ {}", func.name, func.address)))
                    .collect();
                let func_list = List::new(func_items)
                    .block(Block::default().title(" Functions ").borders(Borders::ALL).border_style(Style::default().fg(sidebar_border)))
                    .highlight_style(Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD))
                    .highlight_symbol("> ");
                f.render_stateful_widget(func_list, ide_chunks[0], &mut list_state);

                // Main content rendering (Decompiler or XRefs)
                if app_tab == AppTab::Decompiler {
                    let highlighted_lines = highlight::c_code(&decompiled_code, &ps, &ts);
                    let code_block = Paragraph::new(highlighted_lines)
                        .block(Block::default().title(" Decompiled C ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
                        .wrap(Wrap { trim: false });
                    f.render_widget(code_block, ide_chunks[1]);
                } else if app_tab == AppTab::XRefs {
                    let xrefs_chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                        .split(ide_chunks[1]);

                    let callers_items: Vec<ListItem> = callers.iter().map(|f| ListItem::new(format!("{} @ {}", f.name, f.address))).collect();
                    let callers_list = List::new(callers_items)
                        .block(Block::default().title(" Callers ").borders(Borders::ALL).border_style(Style::default().fg(Color::LightMagenta)));
                    f.render_widget(callers_list, xrefs_chunks[0]);

                    let callees_items: Vec<ListItem> = callees.iter().map(|f| ListItem::new(format!("{} @ {}", f.name, f.address))).collect();
                    let callees_list = List::new(callees_items)
                        .block(Block::default().title(" Callees ").borders(Borders::ALL).border_style(Style::default().fg(Color::LightBlue)));
                    f.render_widget(callees_list, xrefs_chunks[1]);
                }
            }

            // 3. Logs Area
            let log_items: Vec<ListItem> = events::visible_logs(&st.logs, event_view, 15)
                .into_iter()
                .map(ListItem::new)
                .collect();
            let logs_block = List::new(log_items).block(
                Block::default().title(event_view.title()).borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(logs_block, main_chunks[2]);

            // Compute Ghost Text (Fish style)
            let ghost_text = if active_pane == ActivePane::Input {
                commands::ghost_text(&input, &command_history, &suggestions)
            } else {
                String::new()
            };

            let input_border = if active_pane == ActivePane::Input { Color::Green } else { Color::DarkGray };
            let title = if !suggestions.is_empty() && active_pane == ActivePane::Input {
                let mut sugg_str = String::from(" Command Console | Suggestions: ");
                for (i, s) in suggestions.iter().enumerate() {
                    if i == suggestion_index {
                        sugg_str.push_str(&format!("[{}] ", s));
                    } else {
                        sugg_str.push_str(&format!("{} ", s));
                    }
                }
                sugg_str
            } else {
                String::from(" Command Console | Right arrow accepts completion ")
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
                        KeyCode::Char('c') | KeyCode::Char('q')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            break;
                        }
                        KeyCode::Tab => {
                            active_pane = if active_pane == ActivePane::Input {
                                ActivePane::Sidebar
                            } else {
                                ActivePane::Input
                            };
                        }
                        KeyCode::Char('v') => {
                            event_view = event_view.toggle();
                            let mut st = state.lock().await;
                            st.logs.push(events::event_line(ToolEvent::status(
                                "tui",
                                format!("event log switched to {}", event_view.title().trim()),
                            )));
                        }

                        // Global hotkeys to switch tabs
                        KeyCode::Char('d') if active_pane == ActivePane::Sidebar => {
                            app_tab = AppTab::Decompiler;
                        }
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
                                            let callers = client
                                                .callers(&func_name)
                                                .await
                                                .unwrap_or_default();
                                            let callees = client
                                                .callees(&func_name)
                                                .await
                                                .unwrap_or_default();
                                            let _ = tx.send((callers, callees)).await;
                                        }
                                    });
                                }
                            }
                        }
                        KeyCode::Char('s') if active_pane == ActivePane::Sidebar => {
                            app_tab = AppTab::Strings;
                        }
                        KeyCode::Char('t') if active_pane == ActivePane::Sidebar => {
                            app_tab = AppTab::Toolkit;
                        }

                        // Navigation in Sidebar
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

                        // Execution
                        KeyCode::Enter if active_pane == ActivePane::Sidebar => {
                            if app_tab == AppTab::Decompiler || app_tab == AppTab::XRefs {
                                if let Some(i) = list_state.selected() {
                                    if let Some(f) = functions.get(i) {
                                        let func_name = f.name.clone();

                                        // Fetch Decompile
                                        let tx_dec = tx_decompile.clone();
                                        let port = bridge_port;
                                        decompiled_code = format!("Decompiling {}...", func_name);
                                        let func_name_dec = func_name.clone();
                                        tokio::spawn(async move {
                                            if let Some(p) = port {
                                                let client = BridgeClient::new(p);
                                                if let Ok(res) =
                                                    client.decompile(&func_name_dec).await
                                                {
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
                                while start_idx > 0 {
                                    start_idx -= 1;
                                    if command_history[start_idx]
                                        .starts_with(&history_search_prefix)
                                    {
                                        history_index = Some(start_idx);
                                        input = command_history[start_idx].clone();
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
                    if active_pane == ActivePane::Sidebar || mouse.column < 30 {
                        match mouse.kind {
                            MouseEventKind::ScrollDown => {
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
                            MouseEventKind::ScrollUp => {
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
                            MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                                if app_tab == AppTab::Decompiler || app_tab == AppTab::XRefs {
                                    if let Some(i) = list_state.selected() {
                                        if let Some(f) = functions.get(i) {
                                            let func_name = f.name.clone();
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
                                                    {
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
