use crate::adapter::schema::{ToolCommand, ToolEvent};
use crate::error::{Result, RevisorError};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ToolProcessLimits {
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

impl Default for ToolProcessLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            max_output_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ToolProcessResult {
    pub status_code: Option<i32>,
    pub events: Vec<ToolEvent>,
    pub timed_out: bool,
    pub cancelled: bool,
}

pub fn run_tool_process(
    adapter: &str,
    command: &ToolCommand,
    limits: &ToolProcessLimits,
) -> Result<ToolProcessResult> {
    let cancel = AtomicBool::new(false);
    run_tool_process_with_cancel(adapter, command, limits, &cancel)
}

pub fn run_tool_process_with_cancel(
    adapter: &str,
    command: &ToolCommand,
    limits: &ToolProcessLimits,
    cancel: &AtomicBool,
) -> Result<ToolProcessResult> {
    let mut cmd = Command::new(&command.program);
    cmd.args(&command.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if command.stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }

    if let Some(dir) = &command.working_dir {
        cmd.current_dir(dir);
    }

    for (key, value) in &command.env {
        cmd.env(key, value);
    }

    let start = Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| RevisorError::io("spawn tool process", e))?;

    if let Some(stdin) = &command.stdin
        && let Some(mut child_stdin) = child.stdin.take()
    {
        child_stdin
            .write_all(stdin.as_bytes())
            .map_err(|e| RevisorError::io("write tool stdin", e))?;
    }

    let mut timed_out = false;
    let mut cancelled = false;
    loop {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            let _ = child.kill();
            break;
        }

        if start.elapsed() >= limits.timeout {
            timed_out = true;
            let _ = child.kill();
            break;
        }

        if child
            .try_wait()
            .map_err(|e| RevisorError::io("poll tool process", e))?
            .is_some()
        {
            break;
        }

        std::thread::sleep(Duration::from_millis(20));
    }

    let output = child
        .wait_with_output()
        .map_err(|e| RevisorError::io("collect tool output", e))?;

    let mut events = Vec::new();
    collect_lines(
        adapter,
        &String::from_utf8_lossy(&output.stdout),
        limits.max_output_bytes,
        &mut events,
        true,
    );
    collect_lines(
        adapter,
        &String::from_utf8_lossy(&output.stderr),
        limits.max_output_bytes,
        &mut events,
        false,
    );

    if timed_out {
        events.push(ToolEvent::error(
            adapter,
            format!("process exceeded timeout {:?}", limits.timeout),
        ));
    }
    if cancelled {
        events.push(ToolEvent::error(adapter, "process cancelled"));
    }

    Ok(ToolProcessResult {
        status_code: output.status.code(),
        events,
        timed_out,
        cancelled,
    })
}

fn collect_lines(
    adapter: &str,
    text: &str,
    max_output_bytes: usize,
    events: &mut Vec<ToolEvent>,
    stdout: bool,
) {
    let mut used = 0usize;
    for line in text.lines() {
        used += line.len() + 1;
        if used > max_output_bytes {
            events.push(ToolEvent::error(
                adapter,
                "raw output truncated by byte limit",
            ));
            break;
        }
        if stdout {
            events.push(ToolEvent::raw_stdout(adapter, line));
        } else {
            let mut event = ToolEvent::raw_stdout(adapter, line);
            event.kind = crate::adapter::schema::ToolEventKind::RawStderr;
            events.push(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::schema::ToolEventKind;

    fn shell_command(script: &str) -> ToolCommand {
        ToolCommand {
            program: "sh".to_string(),
            args: vec!["-c".to_string(), script.to_string()],
            working_dir: None,
            env: Vec::new(),
            stdin: None,
        }
    }

    #[test]
    fn captures_stdout_and_stderr() {
        let command = shell_command("echo out; echo err >&2");
        let result =
            run_tool_process("test", &command, &ToolProcessLimits::default()).expect("process");

        assert_eq!(result.status_code, Some(0));
        assert!(
            result
                .events
                .iter()
                .any(|event| event.kind == ToolEventKind::RawStdout && event.message == "out")
        );
        assert!(
            result
                .events
                .iter()
                .any(|event| event.kind == ToolEventKind::RawStderr && event.message == "err")
        );
    }

    #[test]
    fn kills_process_on_timeout() {
        let command = shell_command("sleep 1; echo late");
        let limits = ToolProcessLimits {
            timeout: Duration::from_millis(30),
            max_output_bytes: 1024,
        };
        let result = run_tool_process("test", &command, &limits).expect("process");

        assert!(result.timed_out);
        assert!(
            result
                .events
                .iter()
                .any(|event| event.kind == ToolEventKind::Error)
        );
    }

    #[test]
    fn kills_process_when_cancelled() {
        let command = shell_command("sleep 1; echo late");
        let limits = ToolProcessLimits {
            timeout: Duration::from_secs(5),
            max_output_bytes: 1024,
        };
        let cancel = AtomicBool::new(true);
        let result =
            run_tool_process_with_cancel("test", &command, &limits, &cancel).expect("process");

        assert!(result.cancelled);
        assert!(
            result
                .events
                .iter()
                .any(|event| event.message == "process cancelled")
        );
    }
}
