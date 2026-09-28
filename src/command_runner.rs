use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};
use wait_timeout::ChildExt;

use crate::env_source;

const READ_ONLY_COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const CONTROLLED_COMMAND_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_CAPTURE_BYTES: u64 = 8 * 1024 * 1024;
const FIXED_SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug, Clone)]
pub struct CapturedCommand {
    pub status_code: Option<i32>,
    pub stdout: String,
}

#[derive(Debug, Clone)]
pub struct ControlledCommand {
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone)]
pub struct ControlledFileCommand {
    pub bytes_written: u64,
}

pub fn capture(program: &str, args: &[&str]) -> Result<CapturedCommand> {
    capture_with_dir_and_env(program, args, None, &[], false)
}

pub fn capture_in_dir(program: &str, args: &[&str], working_dir: &Path) -> Result<CapturedCommand> {
    capture_with_dir_and_env(program, args, Some(working_dir), &[], false)
}

pub fn capture_with_clean_env(
    program: &str,
    args: &[&str],
    envs: &[(String, OsString)],
) -> Result<CapturedCommand> {
    capture_with_dir_and_env(program, args, Some(Path::new("/")), envs, true)
}

fn capture_with_dir_and_env(
    program: &str,
    args: &[&str],
    working_dir: Option<&Path>,
    envs: &[(String, OsString)],
    clear_env: bool,
) -> Result<CapturedCommand> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(working_dir) = working_dir {
        command.current_dir(working_dir);
    }
    if clear_env {
        command.env_clear();
        command.env("PATH", FIXED_SYSTEM_PATH);
    }
    for (name, value) in envs {
        command.env(name, value);
    }

    let mut stdout = CaptureBuffer::default();
    let status = supervise(
        &mut command,
        None,
        READ_ONLY_COMMAND_TIMEOUT,
        |bytes| {
            stdout.push(bytes);
            Ok(())
        },
        |_| Ok(()),
    )?;
    Ok(CapturedCommand {
        status_code: status.code(),
        stdout: stdout.finish(),
    })
}

pub fn run_controlled(program: &str, args: &[String]) -> Result<ControlledCommand> {
    run_controlled_with_dir_and_env(program, args, None, &[], CONTROLLED_COMMAND_TIMEOUT)
}

pub fn run_controlled_timeout(
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Result<ControlledCommand> {
    if timeout.is_zero() || timeout > CONTROLLED_COMMAND_TIMEOUT {
        anyhow::bail!("controlled command timeout must be between 1s and 3600s");
    }
    run_controlled_with_dir_and_env(program, args, None, &[], timeout)
}

pub fn run_controlled_in_dir(
    program: &str,
    args: &[String],
    working_dir: &Path,
) -> Result<ControlledCommand> {
    run_controlled_with_dir_and_env(
        program,
        args,
        Some(working_dir),
        &[],
        CONTROLLED_COMMAND_TIMEOUT,
    )
}

pub fn run_controlled_with_env(
    program: &str,
    args: &[String],
    envs: &[(String, OsString)],
) -> Result<ControlledCommand> {
    run_controlled_with_dir_and_env(program, args, None, envs, CONTROLLED_COMMAND_TIMEOUT)
}

pub fn run_controlled_with_input(
    program: &str,
    args: &[String],
    input: &[u8],
) -> Result<ControlledCommand> {
    run_controlled_with_dir_env_and_input(
        program,
        args,
        None,
        &[],
        Some(input),
        CONTROLLED_COMMAND_TIMEOUT,
        false,
    )
}

pub fn run_controlled_with_env_in_dir(
    program: &str,
    args: &[String],
    envs: &[(String, OsString)],
    working_dir: &Path,
) -> Result<ControlledCommand> {
    run_controlled_with_dir_and_env(
        program,
        args,
        Some(working_dir),
        envs,
        CONTROLLED_COMMAND_TIMEOUT,
    )
}

pub fn run_controlled_with_clean_env_in_dir(
    program: &str,
    args: &[String],
    envs: &[(String, OsString)],
    working_dir: &Path,
) -> Result<ControlledCommand> {
    run_controlled_with_dir_env_and_input(
        program,
        args,
        Some(working_dir),
        envs,
        None,
        CONTROLLED_COMMAND_TIMEOUT,
        true,
    )
}

pub fn run_controlled_with_clean_env_timeout(
    program: &str,
    args: &[String],
    envs: &[(String, OsString)],
    timeout: Duration,
) -> Result<ControlledCommand> {
    if timeout.is_zero() || timeout > CONTROLLED_COMMAND_TIMEOUT {
        anyhow::bail!("controlled command timeout must be between 1s and 3600s");
    }
    run_controlled_with_dir_env_and_input(
        program,
        args,
        Some(Path::new("/")),
        envs,
        None,
        timeout,
        true,
    )
}

pub fn run_controlled_to_create_new_file_with_clean_env_timeout(
    program: &str,
    args: &[String],
    envs: &[(String, OsString)],
    destination: &Path,
    max_bytes: u64,
    timeout: Duration,
) -> Result<ControlledFileCommand> {
    if timeout.is_zero() || timeout > CONTROLLED_COMMAND_TIMEOUT {
        anyhow::bail!("controlled command timeout must be between 1s and 3600s");
    }
    if max_bytes == 0 || max_bytes > 512 * 1024 * 1024 {
        anyhow::bail!("controlled file capture limit must be between 1 byte and 512 MiB");
    }
    let mut destination_options = OpenOptions::new();
    destination_options.write(true).create_new(true);
    #[cfg(unix)]
    destination_options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let destination_file = destination_options.open(destination).with_context(|| {
        format!(
            "failed to create controlled command destination {}",
            destination.display()
        )
    })?;

    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir("/")
        .env_clear()
        .env("PATH", FIXED_SYSTEM_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in envs {
        command.env(name, value);
    }
    let result = (|| -> Result<ControlledFileCommand> {
        let mut output = destination_file;
        let mut bytes_written = 0_u64;
        let status = supervise(
            &mut command,
            None,
            timeout,
            |bytes| {
                bytes_written += bytes.len() as u64;
                if bytes_written > max_bytes {
                    anyhow::bail!("controlled file command exceeded its byte limit");
                }
                output
                    .write_all(bytes)
                    .context("failed to write controlled command destination")?;
                Ok(())
            },
            |_| Ok(()),
        )?;
        if !status.success() {
            anyhow::bail!("controlled file command returned a nonzero status");
        }
        output
            .sync_all()
            .context("failed to sync controlled command destination")?;
        Ok(ControlledFileCommand { bytes_written })
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

/// Stream trusted, planner-generated command output with one process/I/O deadline.
/// Diagnostics are discarded so database output cannot leak into reports.
pub fn run_controlled_stream_timeout(
    program: &str,
    args: &[String],
    max_bytes: u64,
    timeout: Duration,
    mut output: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    if max_bytes == 0 || timeout.is_zero() || timeout > CONTROLLED_COMMAND_TIMEOUT {
        anyhow::bail!("invalid controlled stream resource limits");
    }
    let mut command = Command::new(program);
    command.args(args);
    if let Some(path) = controlled_path() {
        command.env("PATH", path);
    }
    let mut bytes_read = 0_u64;
    let status = supervise(
        &mut command,
        None,
        timeout,
        |bytes| {
            bytes_read = bytes_read
                .checked_add(bytes.len() as u64)
                .context("stream byte count overflow")?;
            if bytes_read > max_bytes {
                anyhow::bail!("controlled stream exceeded its byte limit");
            }
            output(bytes)
        },
        |_| Ok(()),
    )?;
    if !status.success() {
        anyhow::bail!("controlled stream command returned a nonzero status");
    }
    Ok(())
}

fn run_controlled_with_dir_and_env(
    program: &str,
    args: &[String],
    working_dir: Option<&Path>,
    envs: &[(String, OsString)],
    timeout: Duration,
) -> Result<ControlledCommand> {
    run_controlled_with_dir_env_and_input(program, args, working_dir, envs, None, timeout, false)
}

fn run_controlled_with_dir_env_and_input(
    program: &str,
    args: &[String],
    working_dir: Option<&Path>,
    envs: &[(String, OsString)],
    input: Option<&[u8]>,
    timeout: Duration,
    clear_env: bool,
) -> Result<ControlledCommand> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(working_dir) = working_dir {
        command.current_dir(working_dir);
    }
    if clear_env {
        command.env_clear();
        command.env(
            "PATH",
            controlled_path().unwrap_or_else(|| {
                OsString::from("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            }),
        );
    } else if let Some(path) = controlled_path() {
        command.env("PATH", path);
    }
    for (name, value) in envs {
        command.env(name, value);
    }

    let mut stdout = CaptureBuffer::default();
    let mut stderr = CaptureBuffer::default();
    let status = supervise(
        &mut command,
        input,
        timeout,
        |bytes| {
            stdout.push(bytes);
            Ok(())
        },
        |bytes| {
            stderr.push(bytes);
            Ok(())
        },
    )?;
    Ok(ControlledCommand {
        status_code: status.code(),
        stdout: stdout.finish(),
        stderr: stderr.finish(),
    })
}

#[derive(Default)]
struct CaptureBuffer {
    bytes: Vec<u8>,
    truncated: bool,
}

impl CaptureBuffer {
    fn push(&mut self, bytes: &[u8]) {
        let remaining = (MAX_CAPTURE_BYTES as usize).saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        self.truncated |= bytes.len() > remaining;
    }

    fn finish(mut self) -> String {
        if self.truncated {
            self.bytes
                .extend_from_slice(b"\n[opsctl output truncated]\n");
        }
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

// Independent nonblocking pipes prevent descendants, blocked stdin and output
// backpressure from outliving the caller's deadline. No worker thread is joined.
#[cfg(unix)]
fn supervise(
    command: &mut Command,
    input: Option<&[u8]>,
    timeout: Duration,
    mut stdout_sink: impl FnMut(&[u8]) -> Result<()>,
    mut stderr_sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<ExitStatus> {
    use std::os::unix::process::CommandExt;
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("command deadline overflow")?;
    command
        .process_group(0)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut guard = ProcessGuard {
        child: command
            .spawn()
            .context("failed to start supervised command")?,
        complete: false,
    };
    let mut stdout = Some(
        guard
            .child
            .stdout
            .take()
            .context("missing command stdout")?,
    );
    let mut stderr = Some(
        guard
            .child
            .stderr
            .take()
            .context("missing command stderr")?,
    );
    let mut stdin = guard.child.stdin.take();
    nonblocking(stdout.as_ref().context("missing command stdout")?)?;
    nonblocking(stderr.as_ref().context("missing command stderr")?)?;
    if let Some(stdin) = &stdin {
        nonblocking(stdin)?;
    }
    let mut input = input.unwrap_or_default();
    let mut status = None;
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("controlled command timed out after {}s", timeout.as_secs());
        }
        let mut progressed = drain_pipe(&mut stdout, &mut stdout_sink)?;
        progressed |= drain_pipe(&mut stderr, &mut stderr_sink)?;
        // A synchronous sink can return after the deadline. Never report success
        // or send more input after an overrun, even if the child already exited.
        if Instant::now() >= deadline {
            anyhow::bail!("controlled command timed out after {}s", timeout.as_secs());
        }
        if input.is_empty() {
            stdin = None;
        }
        if let Some(pipe) = &mut stdin {
            match pipe.write(&input[..input.len().min(64 * 1024)]) {
                Ok(0) => anyhow::bail!("command stdin closed before input was written"),
                Ok(bytes) => {
                    input = &input[bytes..];
                    progressed = true;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error).context("failed to write command stdin"),
            }
        }
        if status.is_none() {
            status = guard
                .child
                .try_wait()
                .context("failed to wait for supervised command")?;
        }
        if let Some(status) = status
            && stdout.is_none()
            && stderr.is_none()
            && stdin.is_none()
        {
            guard.complete = true;
            return Ok(status);
        }
        if !progressed {
            thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(10)),
            );
        }
    }
}

#[cfg(not(unix))]
fn supervise(
    _command: &mut Command,
    _input: Option<&[u8]>,
    _timeout: Duration,
    _stdout_sink: impl FnMut(&[u8]) -> Result<()>,
    _stderr_sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<ExitStatus> {
    anyhow::bail!("bounded command supervision requires Unix")
}

#[cfg(unix)]
fn nonblocking(fd: &impl std::os::fd::AsFd) -> Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd)?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)?;
    Ok(())
}

#[cfg(unix)]
fn drain_pipe(
    pipe: &mut Option<impl Read>,
    sink: &mut impl FnMut(&[u8]) -> Result<()>,
) -> Result<bool> {
    let Some(reader) = pipe else {
        return Ok(false);
    };
    let mut bytes = [0_u8; 64 * 1024];
    match reader.read(&mut bytes) {
        Ok(0) => {
            *pipe = None;
            Ok(true)
        }
        Ok(count) => {
            sink(&bytes[..count])?;
            Ok(true)
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error).context("failed to read supervised command output"),
    }
}

#[cfg(unix)]
struct ProcessGuard {
    child: Child,
    complete: bool,
}

#[cfg(unix)]
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if !self.complete {
            if let Ok(raw_pid) = i32::try_from(self.child.id())
                && raw_pid > 1
                && let Some(pid) = rustix::process::Pid::from_raw(raw_pid)
            {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            }
            let _ = self.child.kill();
            // A bounded reap also covers errors during pipe setup and sink writes.
            let _ = self.child.wait_timeout(Duration::from_secs(1));
        }
    }
}

fn controlled_path() -> Option<OsString> {
    let extra = env_source::var_os("OPSCTL_EXTRA_PATHS")?;
    let mut paths = env::split_paths(&extra).collect::<Vec<_>>();
    if let Some(current) = env::var_os("PATH") {
        paths.extend(env::split_paths(&current));
    }
    env::join_paths(paths).ok()
}

impl CapturedCommand {
    pub fn success(&self) -> bool {
        self.status_code == Some(0)
    }
}

impl ControlledCommand {
    pub fn success(&self) -> bool {
        self.status_code == Some(0)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        ffi::OsString,
        time::{Duration, Instant},
    };

    use anyhow::Result;

    use super::{
        FIXED_SYSTEM_PATH, capture_with_clean_env, run_controlled_in_dir,
        run_controlled_to_create_new_file_with_clean_env_timeout,
        run_controlled_with_clean_env_in_dir,
    };

    #[cfg(unix)]
    #[test]
    fn timeout_covers_inherited_output_after_parent_exit() -> Result<()> {
        for script in ["sleep 10 & wait", "sleep 10 & exit 0"] {
            let started = Instant::now();
            let result = super::run_controlled_timeout(
                "/bin/sh",
                &["-c".into(), script.into()],
                Duration::from_millis(200),
            );
            assert!(result.is_err());
            assert!(started.elapsed() < Duration::from_secs(2));
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn slow_output_sink_cannot_report_success_after_deadline() -> Result<()> {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "printf output"]);
        let result = super::supervise(
            &mut command,
            None,
            Duration::from_millis(200),
            |_| {
                std::thread::sleep(Duration::from_millis(250));
                Ok(())
            },
            |_| Ok(()),
        );
        let error = result
            .err()
            .ok_or_else(|| anyhow::anyhow!("late sink succeeded"))?;
        assert!(error.to_string().contains("timed out"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn timeout_covers_blocked_stdin() -> Result<()> {
        let started = Instant::now();
        let result = super::run_controlled_with_dir_env_and_input(
            "/bin/sh",
            &["-c".into(), "sleep 10".into()],
            None,
            &[],
            Some(&vec![b'x'; 256 * 1024]),
            Duration::from_millis(200),
            false,
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn stdin_and_output_backpressure_are_drained_together() -> Result<()> {
        let input = vec![b'x'; 256 * 1024];
        let result = super::run_controlled_with_dir_env_and_input(
            "/bin/sh",
            &["-c".into(), "head -c 131072 /dev/zero; cat".into()],
            None,
            &[],
            Some(&input),
            Duration::from_secs(3),
            false,
        )?;
        assert!(result.success());
        assert_eq!(result.stdout.len(), 131072 + input.len());
        assert!(result.stdout.ends_with(&String::from_utf8(input)?));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn file_capture_timeout_removes_partial_output() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let destination = temp.path().join("timed-out.bin");
        let started = Instant::now();
        let result = super::run_controlled_to_create_new_file_with_clean_env_timeout(
            "/bin/sh",
            &["-c".into(), "printf partial; sleep 10 & wait".into()],
            &[],
            &destination,
            64,
            Duration::from_millis(200),
        );
        assert!(result.is_err());
        assert!(!destination.exists());
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn controlled_command_can_run_in_working_directory() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let captured = run_controlled_in_dir("pwd", &[], temp.path())?;

        assert!(captured.success());
        assert_eq!(captured.stdout.trim(), temp.path().display().to_string());
        Ok(())
    }

    #[test]
    fn controlled_clean_environment_contains_only_path_and_injected_keys() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let envs = vec![("DATABASE_URL".to_string(), OsString::from("test-value"))];
        let captured =
            run_controlled_with_clean_env_in_dir("/usr/bin/env", &[], &envs, temp.path())?;
        let names = captured
            .stdout
            .lines()
            .filter_map(|line| line.split_once('=').map(|(name, _)| name))
            .collect::<BTreeSet<_>>();

        assert!(captured.success());
        assert_eq!(names, BTreeSet::from(["DATABASE_URL", "PATH"]));
        Ok(())
    }

    #[test]
    fn read_only_clean_environment_uses_fixed_path_and_injected_keys_only() -> Result<()> {
        let envs = vec![("LC_ALL".to_string(), OsString::from("C"))];
        let captured = capture_with_clean_env("/usr/bin/env", &[], &envs)?;
        let values = captured
            .stdout
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<std::collections::BTreeMap<_, _>>();

        assert!(captured.success());
        assert_eq!(values.get("PATH"), Some(&FIXED_SYSTEM_PATH));
        assert_eq!(values.get("LC_ALL"), Some(&"C"));
        assert_eq!(values.len(), 2);
        Ok(())
    }

    #[test]
    fn controlled_file_capture_is_create_new_private_and_bounded() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::TempDir::new()?;
        let destination = temp.path().join("capture.bin");
        let report = run_controlled_to_create_new_file_with_clean_env_timeout(
            "/usr/bin/printf",
            &["exact-bytes".to_string()],
            &[],
            &destination,
            64,
            Duration::from_secs(2),
        )?;
        assert_eq!(report.bytes_written, 11);
        assert_eq!(std::fs::read(&destination)?, b"exact-bytes");
        assert_eq!(
            std::fs::metadata(&destination)?.permissions().mode() & 0o777,
            0o600
        );
        assert!(
            run_controlled_to_create_new_file_with_clean_env_timeout(
                "/usr/bin/printf",
                &["replacement".to_string()],
                &[],
                &destination,
                64,
                Duration::from_secs(2),
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&destination)?, b"exact-bytes");
        Ok(())
    }

    #[test]
    fn controlled_file_capture_removes_overflow_and_nonzero_outputs() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let overflow = temp.path().join("overflow.bin");
        assert!(
            run_controlled_to_create_new_file_with_clean_env_timeout(
                "/usr/bin/printf",
                &["too-long".to_string()],
                &[],
                &overflow,
                3,
                Duration::from_secs(2),
            )
            .is_err()
        );
        assert!(!overflow.exists());

        let failed = temp.path().join("failed.bin");
        assert!(
            run_controlled_to_create_new_file_with_clean_env_timeout(
                "/usr/bin/false",
                &[],
                &[],
                &failed,
                64,
                Duration::from_secs(2),
            )
            .is_err()
        );
        assert!(!failed.exists());
        Ok(())
    }
}
