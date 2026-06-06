use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Cell, Row, Table, Paragraph, List, ListItem},
    Terminal,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{error::Error, io::{self, BufRead, Write}, sync::Arc, time::Duration};
use tokio::{net::{UnixListener, UnixStream}, io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt}, sync::Mutex, process::Command};
use std::process::Stdio;

#[derive(Parser)]
#[command(author, version, about = "Ghidra Monitor & AI MCP Unified Binary")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the AI MCP Server over Stdio
    Mcp,
    /// Automatically download and set up Ghidra
    Setup,
    /// Start the daemon and TUI (Default if no command provided)
    Tui,
    /// Import a binary into a new Ghidra project and analyze it
    Analyze {
        /// Path to the binary to analyze
        binary_path: String,
        /// Project path (defaults to /tmp/ghidra_proj)
        #[arg(short, long, default_value = "/tmp/ghidra_proj")]
        project_path: String,
        /// Project name (defaults to test)
        #[arg(short = 'n', long, default_value = "test")]
        project_name: String,
    },
    /// Run a script on an existing Ghidra project
    RunScript {
        /// Name of the script to run
        script_name: String,
        /// Project path (defaults to /tmp/ghidra_proj)
        #[arg(short, long, default_value = "/tmp/ghidra_proj")]
        project_path: String,
        /// Project name (defaults to test)
        #[arg(short = 'n', long, default_value = "test")]
        project_name: String,
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TaskInfo {
    pub id: String,
    pub name: String,
    pub status: String,
    pub progress: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonRequest {
    StartTask { name: String, params: String },
    GetState,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DaemonState {
    pub tasks: Vec<TaskInfo>,
    pub logs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonResponse {
    TaskStarted { id: String },
    State(DaemonState),
    Error(String),
}

const SOCKET_PATH: &str = "/tmp/ghidra_mon.sock";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Some(Commands::Mcp) => {
            // MCP Mode: reads stdin, writes stdout
            run_mcp_client().await;
            Ok(())
        }
        Some(Commands::Setup) => {
            setup_ghidra().await?;
            Ok(())
        }
        Some(Commands::Analyze { binary_path, project_path, project_name }) => {
            let ghidra_bin = match find_ghidra_headless() {
                Some(p) => p,
                None => {
                    eprintln!("❌ Could not find Ghidra. Please run 'ghidra-mon setup' first to automatically download it.");
                    return Ok(());
                }
            };
            let _ = std::fs::create_dir_all(&project_path);
            println!("🚀 Running Ghidra Headless Analysis on {}...", binary_path);
            let mut child = Command::new(&ghidra_bin)
                .arg(&project_path)
                .arg(&project_name)
                .arg("-import")
                .arg(&binary_path)
                .spawn()?;
            let status = child.wait().await?;
            if status.success() {
                println!("✅ Analysis complete!");
            } else {
                eprintln!("❌ Analysis failed. It is possible the binary could not be imported.");
            }
            Ok(())
        }
        Some(Commands::RunScript { script_name, project_path, project_name }) => {
            let ghidra_bin = match find_ghidra_headless() {
                Some(p) => p,
                None => {
                    eprintln!("❌ Could not find Ghidra. Please run 'ghidra-mon setup' first to automatically download it.");
                    return Ok(());
                }
            };
            println!("🚀 Running Ghidra Script {} on project {}...", script_name, project_name);
            let mut child = Command::new(&ghidra_bin)
                .arg(&project_path)
                .arg(&project_name)
                .arg("-process")
                .arg("-postScript")
                .arg(&script_name)
                .spawn()?;
            let status = child.wait().await?;
            if status.success() {
                println!("✅ Script execution complete!");
            } else {
                eprintln!("❌ Script execution failed.");
            }
            Ok(())
        }
        None | Some(Commands::Tui) => {
            // Daemon + UI Mode
            let state = Arc::new(Mutex::new(DaemonState {
                tasks: Vec::new(),
                logs: vec!["[INFO] Daemon initialized. Listening for MCP...".to_string()],
            }));
            
            // 1. Spawn Daemon
            let daemon_state = state.clone();
            tokio::spawn(async move {
                let _ = std::fs::remove_file(SOCKET_PATH);
                if let Ok(listener) = UnixListener::bind(SOCKET_PATH) {
                    loop {
                        if let Ok((mut stream, _)) = listener.accept().await {
                            let state_clone = daemon_state.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0; 8192];
                                if let Ok(n) = stream.read(&mut buf).await {
                                    if n == 0 { return; }
                                    let req_str = String::from_utf8_lossy(&buf[..n]);
                                    for line in req_str.lines() {
                                        if line.trim().is_empty() { continue; }
                                        if let Ok(req) = serde_json::from_str::<DaemonRequest>(line) {
                                            handle_daemon_request(req, state_clone.clone(), &mut stream).await;
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            });

            // 2. Run Ratatui TUI
            run_tui(state).await?;
            Ok(())
        }
    }
}

async fn handle_daemon_request(req: DaemonRequest, state: Arc<Mutex<DaemonState>>, stream: &mut UnixStream) {
    match req {
        DaemonRequest::GetState => {
            let st = state.lock().await;
            let res = DaemonResponse::State(st.clone());
            let mut res_str = serde_json::to_string(&res).unwrap();
            res_str.push('\n');
            let _ = stream.write_all(res_str.as_bytes()).await;
        }
        DaemonRequest::StartTask { name, params } => {
            let id = format!("{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() % 100000);
            {
                let mut st = state.lock().await;
                st.tasks.push(TaskInfo {
                    id: id.clone(),
                    name: name.clone(),
                    status: "Starting".to_string(),
                    progress: "0%".to_string(),
                });
                st.logs.push(format!("[MCP] Triggered tool '{}' with params: {}", name, params));
                if st.logs.len() > 50 { st.logs.remove(0); }
            }

            let state_bg = state.clone();
            let id_clone = id.clone();
            
            tokio::spawn(async move {
                let params_val: Value = serde_json::from_str(&params).unwrap_or(json!({}));
                let ghidra_bin = match find_ghidra_headless() {
                    Some(p) => p,
                    None => {
                        let mut st = state_bg.lock().await;
                        st.logs.push("[ERROR] Could not find Ghidra. Run 'ghidra-mon setup'".to_string());
                        if let Some(t) = st.tasks.iter_mut().find(|t| t.id == id_clone) {
                            t.status = "Error".to_string();
                            t.progress = "Ghidra not found".to_string();
                        }
                        return;
                    }
                };
                let mut cmd = Command::new(&ghidra_bin);
                
                if name == "ghidra_import_and_analyze" {
                    let proj_path = params_val["project_path"].as_str().unwrap_or("/tmp/ghidra_proj");
                    let proj_name = params_val["project_name"].as_str().unwrap_or("test");
                    let bin_path = params_val["binary_path"].as_str().unwrap_or("");
                    let _ = std::fs::create_dir_all(proj_path);
                    cmd.arg(proj_path).arg(proj_name).arg("-import").arg(bin_path);
                } else if name == "ghidra_run_script" {
                    let proj_path = params_val["project_path"].as_str().unwrap_or("/tmp/ghidra_proj");
                    let proj_name = params_val["project_name"].as_str().unwrap_or("test");
                    let script = params_val["script_name"].as_str().unwrap_or("");
                    cmd.arg(proj_path).arg(proj_name).arg("-process").arg("-postScript").arg(script);
                } else {
                    return; // Ignore unknown
                }

                cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
                
                {
                    let mut st = state_bg.lock().await;
                    if let Some(t) = st.tasks.iter_mut().find(|t| t.id == id_clone) {
                        t.status = "Running".to_string();
                    }
                }

                match cmd.spawn() {
                    Ok(mut child) => {
                        let stdout = child.stdout.take().unwrap();
                        let mut reader = tokio::io::BufReader::new(stdout).lines();
                        while let Ok(Some(line)) = reader.next_line().await {
                            if line.contains("INFO") {
                                let mut st = state_bg.lock().await;
                                if let Some(t) = st.tasks.iter_mut().find(|t| t.id == id_clone) {
                                    t.progress = line.chars().take(50).collect::<String>();
                                }
                            }
                        }
                        let status = child.wait().await;
                        let mut st = state_bg.lock().await;
                        if let Some(t) = st.tasks.iter_mut().find(|t| t.id == id_clone) {
                            if status.is_ok() && status.unwrap().success() {
                                t.status = "Completed".to_string();
                                t.progress = "Done".to_string();
                            } else {
                                t.status = "Failed".to_string();
                                t.progress = "Exited with error".to_string();
                            }
                        }
                    }
                    Err(e) => {
                        let mut st = state_bg.lock().await;
                        if let Some(t) = st.tasks.iter_mut().find(|t| t.id == id_clone) {
                            t.status = "Error".to_string();
                            t.progress = format!("Spawn failed: {}", e);
                        }
                        st.logs.push(format!("[ERROR] Spawn failed: {}", e));
                    }
                }
            });

            let res = DaemonResponse::TaskStarted { id };
            let mut res_str = serde_json::to_string(&res).unwrap();
            res_str.push('\n');
            let _ = stream.write_all(res_str.as_bytes()).await;
        }
    }
}

async fn run_mcp_client() {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    while let Some(Ok(line)) = lines.next() {
        if line.trim().is_empty() { continue; }
        let req_val: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let method = req_val["method"].as_str().unwrap_or("");
        let id = req_val["id"].clone();
        
        let mut response = json!({ "jsonrpc": "2.0", "id": id });

        match method {
            "initialize" => {
                response["result"] = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "ghidra-mon", "version": "1.0.0" }
                });
            }
            "tools/list" => {
                response["result"] = json!({
                    "tools": [
                        {
                            "name": "ghidra_import_and_analyze",
                            "description": "Imports binary and auto-analyzes",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "binary_path": { "type": "string" },
                                    "project_path": { "type": "string" },
                                    "project_name": { "type": "string" }
                                },
                                "required": ["binary_path", "project_path", "project_name"]
                            }
                        },
                        {
                            "name": "ghidra_run_script",
                            "description": "Runs a script on an imported project",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "project_path": { "type": "string" },
                                    "project_name": { "type": "string" },
                                    "script_name": { "type": "string" }
                                },
                                "required": ["project_path", "project_name", "script_name"]
                            }
                        }
                    ]
                });
            }
            "tools/call" => {
                let name = req_val["params"]["name"].as_str().unwrap_or("");
                let args = req_val["params"]["arguments"].clone();
                
                if let Ok(mut stream) = UnixStream::connect(SOCKET_PATH).await {
                    let d_req = DaemonRequest::StartTask {
                        name: name.to_string(),
                        params: args.to_string(),
                    };
                    let req_str = format!("{}\n", serde_json::to_string(&d_req).unwrap());
                    let _ = stream.write_all(req_str.as_bytes()).await;

                    let mut buf = vec![0; 8192];
                    if let Ok(n) = stream.read(&mut buf).await {
                        let res_str = String::from_utf8_lossy(&buf[..n]);
                        response["result"] = json!({
                            "content": [{ "type": "text", "text": format!("Ghidra Task submitted. Daemon reply: {}", res_str.trim()) }]
                        });
                    }
                } else {
                    response["error"] = json!({ "code": -32000, "message": "Failed to connect to daemon" });
                }
            }
            "notifications/initialized" => { continue; }
            _ => {
                response["error"] = json!({ "code": -32601, "message": "Method not found" });
            }
        }
        println!("{}", serde_json::to_string(&response).unwrap());
        io::stdout().flush().unwrap();
    }
}

async fn run_tui(state: Arc<Mutex<DaemonState>>) -> Result<(), Box<dyn Error>> {
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
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
                .split(f.area());

            let top_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(30), Constraint::Percentage(70)].as_ref())
                .split(chunks[0]);

            // Top-Left: System/Daemon Status
            let status_text = format!("\n 🟢 Daemon: ONLINE\n 🔌 Socket: {}\n 📋 Total Tasks: {}\n\n 🖥️  Press 'q' to quit", SOCKET_PATH, st.tasks.len());
            let status_block = Paragraph::new(status_text)
                .block(Block::default().title(" ⚙️ SYSTEM STATUS ").borders(Borders::ALL).style(Style::default().fg(Color::Cyan)));
            f.render_widget(status_block, top_chunks[0]);

            // Top-Right: MCP Logs
            let log_items: Vec<ListItem> = st.logs.iter().rev().take(10).map(|l| ListItem::new(l.clone())).collect();
            let logs_block = List::new(log_items)
                .block(Block::default().title(" 📡 MCP EVENT LOGS (Live) ").borders(Borders::ALL).style(Style::default().fg(Color::Green)));
            f.render_widget(logs_block, top_chunks[1]);

            // Bottom: Ghidra Tasks
            let header = Row::new(vec!["Task ID", "Ghidra Action", "Status", "Live Progress"])
                .style(Style::default().bg(Color::DarkGray)).height(1).bottom_margin(1);
            let mut rows = Vec::new();
            for task in st.tasks.iter().rev() {
                let color = match task.status.as_str() {
                    "Running" => Color::Yellow,
                    "Completed" => Color::LightBlue,
                    "Failed" | "Error" => Color::Red,
                    _ => Color::White,
                };
                rows.push(Row::new(vec![
                    Cell::from(task.id.clone()),
                    Cell::from(task.name.clone()),
                    Cell::from(task.status.clone()).style(Style::default().fg(color)),
                    Cell::from(task.progress.clone()),
                ]));
            }
            if rows.is_empty() { rows.push(Row::new(vec!["-", "No Active Ghidra Tasks", "-", "-"])); }
            
            let table = Table::new(rows, [Constraint::Percentage(10), Constraint::Percentage(25), Constraint::Percentage(15), Constraint::Percentage(50)])
                .header(header)
                .block(Block::default().title(" 🔍 GHIDRA HEADLESS TASKS ").borders(Borders::ALL));
            f.render_widget(table, chunks[1]);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}

fn find_ghidra_headless() -> Option<String> {
    if let Ok(val) = std::env::var("GHIDRA_HEADLESS") {
        if std::path::Path::new(&val).exists() {
            return Some(val);
        }
    }

    let script_name = if cfg!(windows) { "analyzeHeadless.bat" } else { "analyzeHeadless" };
    
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        let auto_path = std::path::PathBuf::from(home).join(".ghidra-mon/ghidra/support").join(script_name);
        if auto_path.exists() {
            return Some(auto_path.to_string_lossy().to_string());
        }
    }

    None
}

async fn setup_ghidra() -> Result<(), Box<dyn Error>> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
    let install_dir = std::path::PathBuf::from(home).join(".ghidra-mon");
    std::fs::create_dir_all(&install_dir)?;
    
    // We will use Ghidra 11.2_PUBLIC as an example
    let ghidra_url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20240926.zip";
    let zip_path = install_dir.join("ghidra.zip");
    
    println!("🚀 Downloading Ghidra 11.2 (this might take a while depending on your connection)...");
    let response = reqwest::get(ghidra_url).await?;
    let mut file = std::fs::File::create(&zip_path)?;
    
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk)?;
    }
    
    println!("📦 Extracting Ghidra...");
    let file = std::fs::File::open(&zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    archive.extract(&install_dir)?;
    
    // Rename extracted dir to "ghidra"
    for entry in std::fs::read_dir(&install_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("ghidra_") {
                let final_dir = install_dir.join("ghidra");
                if final_dir.exists() {
                    std::fs::remove_dir_all(&final_dir)?;
                }
                std::fs::rename(entry.path(), &final_dir)?;
                break;
            }
        }
    }
    
    println!("✅ Setup Complete! Ghidra is installed to ~/.ghidra-mon/ghidra");
    let _ = std::fs::remove_file(zip_path);
    
    // Set execution permissions on Linux/macOS
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let analyze_headless = install_dir.join("ghidra/support/analyzeHeadless");
        if analyze_headless.exists() {
            let mut perms = std::fs::metadata(&analyze_headless)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&analyze_headless, perms)?;
        }
    }
    
    Ok(())
}
