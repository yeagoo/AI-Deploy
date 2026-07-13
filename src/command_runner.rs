use std::{
    env,
    ffi::OsString,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use wait_timeout::ChildExt;

use crate::env_source;

const READ_ONLY_COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const CONTROLLED_COMMAND_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_CAPTURE_BYTES: u64 = 8 * 1024 * 1024;

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

pub fn capture(program: &str, args: &[&str]) -> Result<CapturedCommand> {
    capture_with_dir(program, args, None)
}

pub fn capture_in_dir(program: &str, args: &[&str], working_dir: &Path) -> Result<CapturedCommand> {
    capture_with_dir(program, args, Some(working_dir))
}

fn capture_with_dir(
    program: &str,
    args: &[&str],
    working_dir: Option<&Path>,
) -> Result<CapturedCommand> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(working_dir) = working_dir {
        command.current_dir(working_dir);
    }

    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to run read-only command: {program}"))?;

    let stdout_pipe = child
        .stdout
        .take()
        .context("failed to capture command stdout")?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout_pipe));

    let Some(status) = child
        .wait_timeout(READ_ONLY_COMMAND_TIMEOUT)
        .with_context(|| format!("failed to wait for read-only command: {program}"))?
    else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = stdout_reader.join();
        anyhow::bail!(
            "read-only command timed out after {}s: {program}",
            READ_ONLY_COMMAND_TIMEOUT.as_secs()
        );
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow!("command stdout reader panicked: {program}"))?
        .with_context(|| format!("failed to read command stdout: {program}"))?;

    Ok(CapturedCommand {
        status_code: status.code(),
        stdout,
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

    let mut child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run controlled command: {program}"))?;

    if let Some(input) = input
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin
            .write_all(input)
            .with_context(|| format!("failed to write command stdin: {program}"))?;
    }

    let stdout_pipe = child
        .stdout
        .take()
        .context("failed to capture command stdout")?;
    let stderr_pipe = child
        .stderr
        .take()
        .context("failed to capture command stderr")?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout_pipe));
    let stderr_reader = thread::spawn(move || read_bounded(stderr_pipe));

    let Some(status) = child
        .wait_timeout(timeout)
        .with_context(|| format!("failed to wait for controlled command: {program}"))?
    else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = stdout_reader.join();
        let _ = stderr_reader.join();
        anyhow::bail!(
            "controlled command timed out after {}s: {program}",
            timeout.as_secs()
        );
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow!("command stdout reader panicked: {program}"))?
        .with_context(|| format!("failed to read command stdout: {program}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow!("command stderr reader panicked: {program}"))?
        .with_context(|| format!("failed to read command stderr: {program}"))?;

    Ok(ControlledCommand {
        status_code: status.code(),
        stdout,
        stderr,
    })
}

fn read_bounded(reader: impl Read) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    reader.take(MAX_CAPTURE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CAPTURE_BYTES {
        bytes.truncate(MAX_CAPTURE_BYTES as usize);
        bytes.extend_from_slice(b"\n[opsctl output truncated]\n");
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
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
    use std::{collections::BTreeSet, ffi::OsString};

    use anyhow::Result;

    use super::{run_controlled_in_dir, run_controlled_with_clean_env_in_dir};

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
}
