// ghidra-mon: Ghidra Monitor & AI MCP Unified Binary
// Slim CLI entry point – all logic lives in the library modules.

use clap::{Parser, Subcommand};
use ghidra_mon::bridge;
use ghidra_mon::daemon;
use ghidra_mon::error::GhidraMonError;
use ghidra_mon::mcp;
use ghidra_mon::setup;
use ghidra_mon::tui;
use ghidra_mon::types::*;

use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::sync::Mutex;

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
    /// Start a persistent Java Bridge Server on a project
    Bridge {
        /// Project path
        #[arg(short, long, default_value = "/tmp/ghidra_proj")]
        project_path: String,
        /// Project name
        #[arg(short = 'n', long, default_value = "test")]
        project_name: String,
    },
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
    },
    /// Query the running Bridge directly from CLI
    Query {
        /// Bridge command to execute
        command: String,
        /// Optional argument (function name, address, etc.)
        arg: Option<String>,
        /// Additional key=value arguments (e.g. new_name=foo comment="hello world")
        #[arg(trailing_var_arg = true)]
        extra_args: Vec<String>,
        /// Bridge TCP port (auto-discovered if not specified)
        #[arg(short, long)]
        port: Option<u16>,
        /// Pass raw JSON args string (e.g. --json '{"function":"main","new_name":"entry"}')
        #[arg(short, long)]
        json: Option<String>,
        /// Output format: json (default) or pretty
        #[arg(short, long, default_value = "pretty")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), GhidraMonError> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Mcp) => {
            // MCP Mode: reads stdin, writes stdout
            mcp::run_mcp_server().await;
            Ok(())
        }
        Some(Commands::Setup) => {
            setup::setup_ghidra().await?;
            Ok(())
        }
        Some(Commands::Bridge {
            project_path,
            project_name,
        }) => {
            let ghidra_bin = require_ghidra()?;
            bridge::run_bridge_server(ghidra_bin, project_path, project_name).await?;
            Ok(())
        }
        Some(Commands::Analyze {
            binary_path,
            project_path,
            project_name,
        }) => {
            let ghidra_bin = require_ghidra()?;
            let _ = std::fs::create_dir_all(&project_path);
            println!("🚀 Running Ghidra Headless Analysis on {}...", binary_path);
            let mut child = tokio::process::Command::new(&ghidra_bin)
                .arg(&project_path)
                .arg(&project_name)
                .arg("-import")
                .arg(&binary_path)
                .spawn()
                .map_err(|e| GhidraMonError::io("spawn Ghidra headless", e))?;
            let status = child
                .wait()
                .await
                .map_err(|e| GhidraMonError::io("wait for Ghidra", e))?;
            if status.success() {
                println!("✅ Analysis complete!");
            } else {
                eprintln!(
                    "❌ Analysis failed. It is possible the binary could not be imported."
                );
            }
            Ok(())
        }
        Some(Commands::RunScript {
            script_name,
            project_path,
            project_name,
        }) => {
            let ghidra_bin = require_ghidra()?;
            println!(
                "🚀 Running Ghidra Script {} on project {}...",
                script_name, project_name
            );
            let mut child = tokio::process::Command::new(&ghidra_bin)
                .arg(&project_path)
                .arg(&project_name)
                .arg("-process")
                .arg("-postScript")
                .arg(&script_name)
                .spawn()
                .map_err(|e| GhidraMonError::io("spawn Ghidra script", e))?;
            let status = child
                .wait()
                .await
                .map_err(|e| GhidraMonError::io("wait for Ghidra script", e))?;
            if status.success() {
                println!("✅ Script execution complete!");
            } else {
                eprintln!("❌ Script execution failed.");
            }
            Ok(())
        }
        Some(Commands::Query {
            command,
            arg,
            extra_args,
            port,
            json,
            format,
        }) => {
            // Resolve port: explicit > auto-discovery
            let bridge_port = port
                .or_else(bridge::read_bridge_port)
                .ok_or_else(|| {
                    eprintln!("❌ No running bridge found. Start one with 'ghidra-mon bridge' or specify --port.");
                    GhidraMonError::Bridge {
                        message: "No bridge port available".to_string(),
                    }
                })?;

            let client = bridge::BridgeClient::new(bridge_port);

            // Build args: --json takes priority, then positional arg + extra_args
            let args = if let Some(json_str) = json {
                // Raw JSON mode
                let parsed: serde_json::Value = serde_json::from_str(&json_str)
                    .map_err(|e| GhidraMonError::Other(format!("Invalid JSON: {e}")))?;
                Some(parsed)
            } else if arg.is_some() || !extra_args.is_empty() {
                // Build a JSON object from positional args
                let mut map = serde_json::Map::new();

                if let Some(ref a) = arg {
                    // Auto-detect if the arg is an address (starts with 0x) or a name
                    if a.starts_with("0x") || a.starts_with("0X") {
                        map.insert("address".to_string(), serde_json::json!(a));
                    } else {
                        map.insert("function".to_string(), serde_json::json!(a));
                    }
                }

                // Parse extra key=value args
                for extra in &extra_args {
                    if let Some((key, value)) = extra.split_once('=') {
                        map.insert(key.to_string(), serde_json::json!(value));
                    }
                }

                Some(serde_json::Value::Object(map))
            } else {
                None
            };

            match client.send_command(&command, args).await {
                Ok(result) => {
                    if format == "json" {
                        println!("{}", serde_json::to_string(&result).unwrap_or_default());
                    } else {
                        println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
                    }
                }
                Err(e) => {
                    eprintln!("❌ Bridge error: {}", e);
                    return Err(e);
                }
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
                let _ = std::fs::remove_file(tui::SOCKET_PATH);
                if let Ok(listener) = UnixListener::bind(tui::SOCKET_PATH) {
                    loop {
                        if let Ok((mut stream, _)) = listener.accept().await {
                            let state_clone = daemon_state.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0; 8192];
                                if let Ok(n) = stream.read(&mut buf).await {
                                    if n == 0 {
                                        return;
                                    }
                                    let req_str = String::from_utf8_lossy(&buf[..n]);
                                    for line in req_str.lines() {
                                        if line.trim().is_empty() {
                                            continue;
                                        }
                                        if let Ok(req) =
                                            serde_json::from_str::<DaemonRequest>(line)
                                        {
                                            daemon::handle_daemon_request(
                                                req,
                                                state_clone.clone(),
                                                &mut stream,
                                            )
                                            .await;
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            });

            // 2. Run Ratatui TUI
            tui::run_tui(state).await?;
            Ok(())
        }
    }
}

/// Find Ghidra or return a user-friendly error.
fn require_ghidra() -> Result<String, GhidraMonError> {
    setup::find_ghidra_headless().ok_or_else(|| {
        eprintln!(
            "❌ Could not find Ghidra. Please run 'ghidra-mon setup' first to automatically download it."
        );
        GhidraMonError::GhidraNotFound
    })
}
