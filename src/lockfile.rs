use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::Path,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use fs2::FileExt;
use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const LOCK_WAIT_ENV: &str = "OPSCTL_LOCK_WAIT_SECONDS";
const MAX_LOCK_WAIT_SECONDS: u64 = 6 * 60 * 60;
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const MAX_LOCK_METADATA_BYTES: u64 = 4096;

#[derive(Debug)]
pub struct GlobalLock {
    file: File,
}

#[derive(Debug, Clone, Serialize)]
struct LockMetadata<'a> {
    schema_version: &'static str,
    pid: u32,
    actor: &'a str,
    command: &'a str,
    target: &'a str,
    acquired_at: String,
}

impl GlobalLock {
    pub fn acquire(state_dir: &Path, actor: &str, command: &str, target: &str) -> Result<Self> {
        let wait = lock_wait_from_env()?;
        Self::acquire_with_wait(state_dir, actor, command, target, wait)
    }

    fn acquire_with_wait(
        state_dir: &Path,
        actor: &str,
        command: &str,
        target: &str,
        wait: Duration,
    ) -> Result<Self> {
        fs::create_dir_all(state_dir)
            .with_context(|| format!("failed to create state directory {}", state_dir.display()))?;
        let path = state_dir.join("opsctl.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);

        let mut file = options
            .open(&path)
            .with_context(|| format!("failed to open global lock {}", path.display()))?;
        set_private_permissions(&path)?;

        let started = Instant::now();
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => break,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    let elapsed = started.elapsed();
                    if elapsed >= wait {
                        return Err(lock_busy_error(&mut file, &path, wait));
                    }
                    thread::sleep(LOCK_RETRY_INTERVAL.min(wait.saturating_sub(elapsed)));
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to acquire global lock {}", path.display())
                    });
                }
            }
        }

        let acquired_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("failed to format lock timestamp")?;
        let metadata = LockMetadata {
            schema_version: "opsctl.lock.v1",
            pid: std::process::id(),
            actor,
            command,
            target,
            acquired_at,
        };
        let raw =
            serde_json::to_vec(&metadata).context("failed to serialize global lock metadata")?;
        file.set_len(0)
            .with_context(|| format!("failed to truncate global lock {}", path.display()))?;
        file.write_all(&raw)
            .with_context(|| format!("failed to write global lock {}", path.display()))?;
        file.write_all(b"\n")
            .with_context(|| format!("failed to write global lock newline {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync global lock {}", path.display()))?;

        Ok(Self { file })
    }
}

fn lock_wait_from_env() -> Result<Duration> {
    match env::var(LOCK_WAIT_ENV) {
        Ok(value) => parse_lock_wait(&value),
        Err(env::VarError::NotPresent) => Ok(Duration::ZERO),
        Err(env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{LOCK_WAIT_ENV} must be valid UTF-8")
        }
    }
}

fn parse_lock_wait(value: &str) -> Result<Duration> {
    let seconds = value
        .parse::<u64>()
        .with_context(|| format!("{LOCK_WAIT_ENV} must be an integer number of seconds"))?;
    if seconds > MAX_LOCK_WAIT_SECONDS {
        anyhow::bail!("{LOCK_WAIT_ENV} cannot exceed {MAX_LOCK_WAIT_SECONDS} seconds");
    }
    Ok(Duration::from_secs(seconds))
}

fn lock_busy_error(file: &mut File, path: &Path, wait: Duration) -> anyhow::Error {
    let holder = read_lock_holder(file);
    let waited = wait.as_secs();
    if holder.is_empty() {
        anyhow::anyhow!(
            "another opsctl mutating command is already running after waiting {waited}s; lock={}",
            path.display()
        )
    } else {
        anyhow::anyhow!(
            "another opsctl mutating command is already running after waiting {waited}s; lock={}; holder={holder}",
            path.display()
        )
    }
}

fn read_lock_holder(file: &mut File) -> String {
    if file.seek(SeekFrom::Start(0)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    if file
        .take(MAX_LOCK_METADATA_BYTES)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return String::new();
    }
    String::from_utf8(bytes)
        .unwrap_or_default()
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

impl Drop for GlobalLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{io::Write, thread, time::Duration};

    use anyhow::Result;
    use tempfile::TempDir;

    use super::{GlobalLock, parse_lock_wait, read_lock_holder};

    #[test]
    fn second_global_lock_fails_fast() -> Result<()> {
        let state = TempDir::new()?;
        let _first = GlobalLock::acquire(state.path(), "tester", "deploy", "plan.yml")?;
        let error = match GlobalLock::acquire(state.path(), "tester", "snapshot", "plan.yml") {
            Ok(_) => anyhow::bail!("second lock should fail while first is held"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("already running"));
        assert!(state.path().join("opsctl.lock").exists());
        Ok(())
    }

    #[test]
    fn global_lock_can_be_reacquired_after_drop() -> Result<()> {
        let state = TempDir::new()?;
        {
            let _first = GlobalLock::acquire(state.path(), "tester", "deploy", "plan.yml")?;
        }
        let _second = GlobalLock::acquire(state.path(), "tester", "snapshot", "plan.yml")?;

        let raw = std::fs::read_to_string(state.path().join("opsctl.lock"))?;
        assert!(raw.contains("\"command\":\"snapshot\""));
        Ok(())
    }

    #[test]
    fn bounded_wait_acquires_after_holder_exits() -> Result<()> {
        let state = TempDir::new()?;
        let first = GlobalLock::acquire(state.path(), "tester", "backup", "first")?;
        let release = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            drop(first);
        });
        let _second = GlobalLock::acquire_with_wait(
            state.path(),
            "tester",
            "backup",
            "second",
            Duration::from_secs(1),
        )?;
        release
            .join()
            .map_err(|_| anyhow::anyhow!("lock holder thread panicked"))?;
        Ok(())
    }

    #[test]
    fn bounded_wait_times_out_and_configuration_is_capped() -> Result<()> {
        let state = TempDir::new()?;
        let _first = GlobalLock::acquire(state.path(), "tester", "backup", "first")?;
        let error = match GlobalLock::acquire_with_wait(
            state.path(),
            "tester",
            "backup",
            "second",
            Duration::from_millis(25),
        ) {
            Ok(_) => anyhow::bail!("second lock should time out"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("after waiting 0s"));
        assert!(parse_lock_wait("21600").is_ok());
        assert!(parse_lock_wait("21601").is_err());
        assert!(parse_lock_wait("forever").is_err());
        Ok(())
    }

    #[test]
    fn lock_holder_diagnostic_is_bounded_and_single_line() -> Result<()> {
        let mut file = tempfile::tempfile()?;
        file.write_all(&vec![b'a'; 8192])?;
        file.write_all(b"\nsecret-looking-second-line")?;

        let holder = read_lock_holder(&mut file);
        assert_eq!(holder.len(), 4096);
        assert!(!holder.contains('\n'));
        assert!(!holder.contains("second-line"));
        Ok(())
    }
}
