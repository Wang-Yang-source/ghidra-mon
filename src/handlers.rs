use crate::cli::Commands;
use crate::error::{GhidraMonError, Result};
use crate::{bridge, daemon, mcp, setup, tui, types::*};

use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::sync::Mutex;

pub async fn handle_command(command: Option<Commands>) -> Result<()> {
    match command {
        Some(Commands::Mcp) => {
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
            let bridge_port = port
                .or_else(bridge::read_bridge_port)
                .ok_or_else(|| {
                    eprintln!("❌ No running bridge found. Start one with 'ghidra-mon bridge' or specify --port.");
                    GhidraMonError::Bridge {
                        message: "No bridge port available".to_string(),
                    }
                })?;

            let client = bridge::BridgeClient::new(bridge_port);

            let args = if let Some(json_str) = json {
                let parsed: serde_json::Value = serde_json::from_str(&json_str)
                    .map_err(|e| GhidraMonError::Other(format!("Invalid JSON: {e}")))?;
                Some(parsed)
            } else if arg.is_some() || !extra_args.is_empty() {
                let mut map = serde_json::Map::new();

                if let Some(ref a) = arg {
                    if a.starts_with("0x") || a.starts_with("0X") {
                        map.insert("address".to_string(), serde_json::json!(a));
                    } else {
                        map.insert("function".to_string(), serde_json::json!(a));
                    }
                }

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
            let state = Arc::new(Mutex::new(DaemonState {
                tasks: Vec::new(),
                logs: vec!["[INFO] Daemon initialized. Listening for MCP...".to_string()],
            }));

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

            tui::run_tui(state).await?;
            Ok(())
        }
    }
}

pub fn require_ghidra() -> Result<String> {
    setup::find_ghidra_headless().ok_or_else(|| {
        eprintln!(
            "❌ Could not find Ghidra. Please run 'ghidra-mon setup' first to automatically download it."
        );
        GhidraMonError::GhidraNotFound
    })
}
