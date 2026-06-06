use super::{binary_info, commands};
use crate::adapter::schema::ToolEvent;
use crate::types::DaemonState;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

pub async fn run_console_command(state: Arc<Mutex<DaemonState>>, cmd: String) {
    let mut args: Vec<String> = cmd.split_whitespace().map(|s| s.to_string()).collect();
    if args.is_empty() {
        return;
    }

    if args[0] == "clear" || args[0] == "cls" {
        let mut st = state.lock().await;
        st.logs.clear();
        return;
    }

    if args[0] == "help" {
        push_event(
            &state,
            ToolEvent::status(
                "tui",
                "Commands: info <bin>, toolkit binwalk/checksec/rop/rizin <bin>, analyze, bridge, query <cmd>, clear, quit | keys: v toggles structured/raw events",
            ),
        )
        .await;
        return;
    }

    if args[0] == "info" && args.len() > 1 {
        for line in binary_info::scan_binary_info(&args[1]) {
            let event = if line.starts_with("[error]") {
                ToolEvent::error("local", line)
            } else {
                ToolEvent::status("local", line)
            };
            push_event(&state, event).await;
        }
        return;
    }

    if commands::QUERY_COMMANDS.contains(&args[0].as_str()) {
        args.insert(0, "query".to_string());
    }

    push_event(
        &state,
        ToolEvent::status("tui", format!("$ revisor {}", args.join(" "))),
    )
    .await;

    let exe = std::env::current_exe().unwrap_or_else(|_| "revisor".into());
    let mut command = tokio::process::Command::new(exe);
    command.args(&args);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    match command.spawn() {
        Ok(mut child) => {
            if let Some(stdout) = child.stdout.take() {
                spawn_stream_reader(state.clone(), stdout, false);
            }

            if let Some(stderr) = child.stderr.take() {
                spawn_stream_reader(state.clone(), stderr, true);
            }
        }
        Err(e) => {
            push_event(
                &state,
                ToolEvent::error("tui", format!("failed to spawn command: {}", e)),
            )
            .await;
        }
    }
}

fn spawn_stream_reader<R>(state: Arc<Mutex<DaemonState>>, stream: R, stderr: bool)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            let event = if let Ok(event) = serde_json::from_str::<ToolEvent>(&line) {
                event
            } else if stderr {
                ToolEvent::raw_stderr("cli", line)
            } else {
                ToolEvent::raw_stdout("cli", line)
            };
            push_event(&state, event).await;
        }
    });
}

async fn push_event(state: &Arc<Mutex<DaemonState>>, event: ToolEvent) {
    let line = serde_json::to_string(&event)
        .unwrap_or_else(|_| "{\"adapter\":\"tui\",\"kind\":\"Error\",\"message\":\"serialize event failed\",\"address\":null,\"raw\":null,\"data\":null}".to_string());
    let mut st = state.lock().await;
    st.logs.push(line);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn help_command_pushes_event_json() {
        let state = Arc::new(Mutex::new(DaemonState {
            tasks: Vec::new(),
            logs: Vec::new(),
        }));

        run_console_command(state.clone(), "help".to_string()).await;
        let st = state.lock().await;
        assert_eq!(st.logs.len(), 1);
        let event: ToolEvent = serde_json::from_str(&st.logs[0]).expect("event json");
        assert_eq!(event.adapter, "tui");
    }
}
