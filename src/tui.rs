// TUI dashboard for ghidra-mon.
// Cyberpunk-themed ratatui interface showing daemon status, tasks, and logs.

use crate::error::Result;
use crate::types::*;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table},
    Terminal,
};
use std::{io, sync::Arc, time::Duration};
use tokio::sync::Mutex;

/// Unix socket path used by the daemon.
pub const SOCKET_PATH: &str = "/tmp/ghidra-mon.sock";

/// Run the TUI dashboard.
/// Polls the shared daemon state and renders it in a btop-like layout.
/// Press 'q' to quit.
pub async fn run_tui(state: Arc<Mutex<DaemonState>>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        let st = state.lock().await.clone();

        terminal.draw(|f| {
            // btop-like layout
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                    [Constraint::Percentage(40), Constraint::Percentage(60)].as_ref(),
                )
                .split(f.area());

            let top_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [Constraint::Percentage(30), Constraint::Percentage(70)].as_ref(),
                )
                .split(chunks[0]);

            // Top-Left: System/Daemon Status
            let status_text = format!(
                "\n 🟢 Daemon: ONLINE\n 🔌 Socket: {}\n 📋 Total Tasks: {}\n\n 🖥️  Press 'q' to quit",
                SOCKET_PATH,
                st.tasks.len()
            );
            let status_block = Paragraph::new(status_text).block(
                Block::default()
                    .title(" ⚙️ SYSTEM STATUS ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Magenta))
                    .style(Style::default().fg(Color::White)),
            );
            f.render_widget(status_block, top_chunks[0]);

            // Top-Right: MCP Logs
            let log_items: Vec<ListItem> = st
                .logs
                .iter()
                .rev()
                .take(10)
                .map(|l| ListItem::new(l.clone()))
                .collect();
            let logs_block = List::new(log_items).block(
                Block::default()
                    .title(" 📡 MCP EVENT LOGS (Live) ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .style(Style::default().fg(Color::Green)),
            );
            f.render_widget(logs_block, top_chunks[1]);

            // Bottom: Ghidra Tasks
            let header = Row::new(vec!["Task ID", "Ghidra Action", "Status", "Live Progress"])
                .style(
                    Style::default()
                        .bg(Color::Blue)
                        .fg(Color::White)
                        .add_modifier(ratatui::style::Modifier::BOLD),
                )
                .height(1)
                .bottom_margin(1);
            let mut rows = Vec::new();
            for task in st.tasks.iter().rev() {
                let color = match task.status.as_str() {
                    "Running" => Color::Yellow,
                    "Completed" => Color::Green,
                    "Failed" | "Error" => Color::Red,
                    _ => Color::White,
                };
                rows.push(Row::new(vec![
                    Cell::from(task.id.clone()),
                    Cell::from(task.name.clone()),
                    Cell::from(task.status.clone()).style(
                        Style::default()
                            .fg(color)
                            .add_modifier(ratatui::style::Modifier::BOLD),
                    ),
                    Cell::from(task.progress.clone())
                        .style(Style::default().fg(Color::LightCyan)),
                ]));
            }
            if rows.is_empty() {
                rows.push(
                    Row::new(vec!["-", "No Active Ghidra Tasks", "-", "-"])
                        .style(Style::default().fg(Color::DarkGray)),
                );
            }

            let table = Table::new(
                rows,
                [
                    Constraint::Percentage(10),
                    Constraint::Percentage(25),
                    Constraint::Percentage(15),
                    Constraint::Percentage(50),
                ],
            )
            .header(header)
            .block(
                Block::default()
                    .title(" 🔍 GHIDRA HEADLESS TASKS ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            );
            f.render_widget(table, chunks[1]);
        })?;

        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
                && let KeyCode::Char('q') = key.code {
                    break;
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
