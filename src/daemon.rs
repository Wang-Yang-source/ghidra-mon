// Daemon request handler for the Unix socket server.
// The daemon runs in the background while the TUI is displayed.

use crate::setup::find_ghidra_headless;
use crate::types::*;

use serde_json::{Value, json};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::Mutex;

/// Handle a single daemon request from the Unix socket.
pub async fn handle_daemon_request(
    req: DaemonRequest,
    state: Arc<Mutex<DaemonState>>,
    stream: &mut UnixStream,
) {
    match req {
        DaemonRequest::GetState => {
            let st = state.lock().await;
            let res = DaemonResponse::State(st.clone());
            let mut res_str = serde_json::to_string(&res).unwrap();
            res_str.push('\n');
            let _ = stream.write_all(res_str.as_bytes()).await;
        }
        DaemonRequest::StartTask { name, params } => {
            let id = format!(
                "{:x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
                    % 100000
            );
            {
                let mut st = state.lock().await;
                st.tasks.push(TaskInfo {
                    id: id.clone(),
                    name: name.clone(),
                    status: "Starting".to_string(),
                    progress: "0%".to_string(),
                });
                st.logs.push(format!(
                    "[MCP] Triggered tool '{}' with params: {}",
                    name, params
                ));
                if st.logs.len() > 50 {
                    st.logs.remove(0);
                }
            }

            let state_bg = state.clone();
            let id_clone = id.clone();

            tokio::spawn(async move {
                let params_val: Value = serde_json::from_str(&params).unwrap_or(json!({}));
                let ghidra_bin = match find_ghidra_headless() {
                    Some(p) => p,
                    None => {
                        let mut st = state_bg.lock().await;
                        st.logs
                            .push("[ERROR] Could not find Ghidra. Run 'ghidrai setup'".to_string());
                        if let Some(t) = st.tasks.iter_mut().find(|t| t.id == id_clone) {
                            t.status = "Error".to_string();
                            t.progress = "Ghidra not found".to_string();
                        }
                        return;
                    }
                };
                let mut cmd = Command::new(&ghidra_bin);

                if name == "ghidra_import_and_analyze" {
                    let proj_path = params_val["project_path"]
                        .as_str()
                        .unwrap_or("/tmp/ghidra_proj");
                    let proj_name = params_val["project_name"].as_str().unwrap_or("test");
                    let bin_path = params_val["binary_path"].as_str().unwrap_or("");
                    let _ = std::fs::create_dir_all(proj_path);
                    cmd.arg(proj_path)
                        .arg(proj_name)
                        .arg("-import")
                        .arg(bin_path);
                } else if name == "ghidra_run_script" {
                    let proj_path = params_val["project_path"]
                        .as_str()
                        .unwrap_or("/tmp/ghidra_proj");
                    let proj_name = params_val["project_name"].as_str().unwrap_or("test");
                    let script = params_val["script_name"].as_str().unwrap_or("");
                    cmd.arg(proj_path)
                        .arg(proj_name)
                        .arg("-process")
                        .arg("-postScript")
                        .arg(script);
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
