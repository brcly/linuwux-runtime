use crate::Result;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn kill_group(pid: u32) {
    unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
}

pub(crate) fn run(cmd: &mut Command, input: &[u8], limit: Duration) -> Result<Output> {
    let mut child = cmd
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("missing child stdin")?;
    let mut stdout = child.stdout.take().ok_or("missing child stdout")?;
    let mut stderr = child.stderr.take().ok_or("missing child stderr")?;
    let data = input.to_vec();
    let writer = thread::spawn(move || stdin.write_all(&data));
    let out = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let err = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let start = Instant::now();
    let mut expired = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= limit {
            expired = true;
            kill_group(child.id());
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(5));
    };
    kill_group(child.id());
    let stdout = out.join().map_err(|_| "stdout reader panicked")??;
    let stderr = err.join().map_err(|_| "stderr reader panicked")??;
    let write = writer.join().map_err(|_| "stdin writer panicked")?;
    if expired {
        return Err(format!(
            "timed out after {limit:?}: {cmd:?}\n{}",
            String::from_utf8_lossy(&stderr)
        )
        .into());
    }
    if status.success() {
        write?;
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

pub(crate) fn checked(cmd: &mut Command) -> Result<Output> {
    let output = run(cmd, &[], Duration::from_secs(180))?;
    if !output.status.success() {
        return Err(format!(
            "{cmd:?}: {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_kills_descendants_that_hold_output_open() {
        let started = Instant::now();
        let result = run(
            Command::new("sh").args(["-c", "sleep 30 & wait"]),
            &[],
            Duration::from_millis(100),
        );
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn exited_fixture_cannot_leave_a_child_holding_its_output_pipe() {
        let started = Instant::now();
        let result = run(
            Command::new("sh").args(["-c", "sleep 30 & exit 0"]),
            &[],
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(result.status.success());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
