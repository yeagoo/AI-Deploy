use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result, anyhow};
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
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            drop(destination_file);
            let _ = fs::remove_file(destination);
            return Err(error)
                .with_context(|| format!("failed to run controlled command: {program}"));
        }
    };
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            drop(destination_file);
            let _ = fs::remove_file(destination);
            anyhow::bail!("failed to capture controlled file command stdout");
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            drop(stdout);
            drop(destination_file);
            let _ = fs::remove_file(destination);
            anyhow::bail!("failed to capture controlled file command stderr");
        }
    };
    let destination_path = destination.to_path_buf();
    let writer = thread::spawn(move || -> std::io::Result<u64> {
        let mut input = stdout.take(max_bytes + 1);
        let mut output = destination_file;
        let copied = std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        if copied > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "controlled file command exceeded its byte limit",
            ));
        }
        Ok(copied)
    });
    let stderr_reader = thread::spawn(move || read_bounded(stderr));

    let status = match child.wait_timeout(timeout) {
        Ok(Some(status)) => status,
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = writer.join();
            let _ = stderr_reader.join();
            let _ = fs::remove_file(&destination_path);
            anyhow::bail!(
                "controlled command timed out after {}s: {program}",
                timeout.as_secs()
            );
        }
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = writer.join();
            let _ = stderr_reader.join();
            let _ = fs::remove_file(&destination_path);
            return Err(error)
                .with_context(|| format!("failed to wait for controlled command: {program}"));
        }
    };
    let bytes_written = match writer.join() {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => {
            let _ = stderr_reader.join();
            let _ = fs::remove_file(&destination_path);
            return Err(error).context("failed to write controlled command destination");
        }
        Err(_) => {
            let _ = stderr_reader.join();
            let _ = fs::remove_file(&destination_path);
            anyhow::bail!("controlled file command writer panicked: {program}");
        }
    };
    match stderr_reader.join() {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            let _ = fs::remove_file(&destination_path);
            return Err(error).context("failed to read controlled file command stderr");
        }
        Err(_) => {
            let _ = fs::remove_file(&destination_path);
            anyhow::bail!("controlled file command stderr reader panicked: {program}");
        }
    }
    if !status.success() {
        let _ = fs::remove_file(&destination_path);
        anyhow::bail!("controlled file command returned a nonzero status");
    }
    Ok(ControlledFileCommand { bytes_written })
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
    use std::{collections::BTreeSet, ffi::OsString, time::Duration};

    use anyhow::Result;

    use super::{
        FIXED_SYSTEM_PATH, capture_with_clean_env, run_controlled_in_dir,
        run_controlled_to_create_new_file_with_clean_env_timeout,
        run_controlled_with_clean_env_in_dir,
    };

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
