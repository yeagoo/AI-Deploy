#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    collections::VecDeque,
    env,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const AUDIT_SCHEMA_VERSION: &str = "opsctl.audit.v1";

#[derive(Debug)]
pub struct AuditStore {
    connection: Connection,
    state_db_path: PathBuf,
    audit_log_path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct AuditEvent<'a> {
    pub schema_version: &'static str,
    pub ts: String,
    pub actor: &'a str,
    pub command: &'a str,
    pub target: Option<&'a str>,
    pub cwd: Option<String>,
    pub result: &'a str,
    pub decision: &'a str,
    pub reason: Option<&'a str>,
    pub risk: &'a str,
    pub dry_run: bool,
}

#[derive(Debug)]
pub struct AuditRecord<'a> {
    pub actor: &'a str,
    pub command: &'a str,
    pub target: Option<&'a str>,
    pub result: &'a str,
    pub decision: &'a str,
    pub reason: Option<&'a str>,
    pub risk: &'a str,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditIntegrityReport {
    pub path: String,
    pub exists: bool,
    pub total_lines: usize,
    pub invalid_lines: Vec<usize>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditQueryReport {
    pub path: String,
    pub limit: usize,
    pub integrity: AuditIntegrityReport,
    pub events: Vec<AuditQueryEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditQueryEvent {
    pub schema_version: Option<String>,
    pub ts: Option<String>,
    pub actor: Option<String>,
    pub command: Option<String>,
    pub target: Option<String>,
    pub cwd: Option<String>,
    pub result: Option<String>,
    pub decision: Option<String>,
    pub reason: Option<String>,
    pub risk: Option<String>,
    pub dry_run: Option<bool>,
}

impl AuditStore {
    pub fn open(state_dir: &Path, state_db_path: &Path, audit_log_path: &Path) -> Result<Self> {
        fs::create_dir_all(state_dir)
            .with_context(|| format!("failed to create state directory {}", state_dir.display()))?;
        set_secure_permissions(state_dir, 0o700)?;

        let connection = Connection::open(state_db_path).with_context(|| {
            format!("failed to open state database {}", state_db_path.display())
        })?;
        set_secure_permissions(state_db_path, 0o600)?;
        configure_sqlite(&connection).context("failed to configure sqlite pragmas")?;

        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    command TEXT NOT NULL,
                    target TEXT,
                    result TEXT NOT NULL,
                    message TEXT,
                    schema_version TEXT NOT NULL DEFAULT 'opsctl.audit.v1',
                    cwd TEXT,
                    decision TEXT NOT NULL DEFAULT 'allow',
                    reason TEXT,
                    risk TEXT NOT NULL DEFAULT 'low',
                    dry_run INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp
                    ON audit_events(timestamp);
                "#,
            )
            .context("failed to initialize audit_events table")?;
        ensure_audit_columns(&connection).context("failed to migrate audit_events table")?;
        secure_sqlite_files(state_db_path)?;

        Ok(Self {
            connection,
            state_db_path: state_db_path.to_path_buf(),
            audit_log_path: audit_log_path.to_path_buf(),
        })
    }

    pub fn record(&self, record: &AuditRecord<'_>) -> Result<()> {
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("failed to format audit timestamp")?;
        let cwd = env::current_dir()
            .ok()
            .map(|path| path.to_string_lossy().into_owned());

        self.connection
            .execute(
                "INSERT INTO audit_events (
                    timestamp, actor, command, target, result, message,
                    schema_version, cwd, decision, reason, risk, dry_run
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    timestamp,
                    record.actor,
                    record.command,
                    record.target,
                    record.result,
                    record.reason,
                    AUDIT_SCHEMA_VERSION,
                    cwd,
                    record.decision,
                    record.reason,
                    record.risk,
                    record.dry_run
                ],
            )
            .context("failed to write audit event to sqlite")?;
        secure_sqlite_files(&self.state_db_path)?;

        let event = AuditEvent {
            schema_version: AUDIT_SCHEMA_VERSION,
            ts: timestamp,
            actor: record.actor,
            command: record.command,
            target: record.target,
            cwd,
            result: record.result,
            decision: record.decision,
            reason: record.reason,
            risk: record.risk,
            dry_run: record.dry_run,
        };

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let mut file = options.open(&self.audit_log_path).with_context(|| {
            format!("failed to open audit log {}", self.audit_log_path.display())
        })?;
        set_secure_permissions(&self.audit_log_path, 0o600)?;

        let mut serialized =
            serde_json::to_string(&event).context("failed to serialize audit event")?;
        serialized.push('\n');
        file.write_all(serialized.as_bytes())
            .context("failed to append event to audit log")?;
        set_secure_permissions(&self.audit_log_path, 0o600)?;

        Ok(())
    }
}

const MAX_AUDIT_SCAN_BYTES: u64 = 256 * 1024 * 1024;
const MAX_AUDIT_LINE_BYTES: u64 = 128 * 1024;
const MAX_INVALID_AUDIT_LINES: usize = 1000;

pub fn inspect_audit_log(path: &Path) -> Result<AuditIntegrityReport> {
    Ok(scan_audit_log(path, None)?.integrity)
}

pub fn query_audit_log(path: &Path, limit: usize) -> Result<AuditQueryReport> {
    scan_audit_log(path, Some(limit.clamp(1, 1000)))
}

fn scan_audit_log(path: &Path, limit: Option<usize>) -> Result<AuditQueryReport> {
    let mut report = AuditQueryReport {
        path: path.to_string_lossy().into_owned(),
        limit: limit.unwrap_or(0),
        integrity: AuditIntegrityReport {
            path: path.to_string_lossy().into_owned(),
            exists: false,
            total_lines: 0,
            invalid_lines: Vec::new(),
            warnings: Vec::new(),
        },
        events: Vec::new(),
    };
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            report
                .integrity
                .warnings
                .push("audit log does not exist yet".to_string());
            return Ok(report);
        }
        Err(error) => return Err(error).context("failed to inspect audit log"),
    };
    report.integrity.exists = true;
    if metadata.file_type().is_symlink() && limit.is_none() {
        report
            .integrity
            .warnings
            .push("audit log path is a symlink; integrity was not scanned".to_string());
        return Ok(report);
    }
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to scan non-regular audit log or symlink");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path).context("failed to open audit log")?;
    let metadata = file
        .metadata()
        .context("failed to inspect opened audit log")?;
    if !metadata.is_file() || metadata.len() > MAX_AUDIT_SCAN_BYTES {
        anyhow::bail!(
            "audit log must be a regular file within the 256 MiB scan limit; archive the log before retrying"
        );
    }
    let mut reader = BufReader::new(file.take(MAX_AUDIT_SCAN_BYTES + 1));
    let mut events = VecDeque::with_capacity(limit.unwrap_or(0));
    let mut line = Vec::new();
    let mut bytes_read = 0_u64;
    let mut invalid_count = 0_usize;
    loop {
        line.clear();
        let bytes = reader
            .by_ref()
            .take(MAX_AUDIT_LINE_BYTES + 1)
            .read_until(b'\n', &mut line)
            .context("failed to read audit log")?;
        if bytes == 0 {
            break;
        }
        bytes_read += bytes as u64;
        if bytes_read > MAX_AUDIT_SCAN_BYTES || bytes as u64 > MAX_AUDIT_LINE_BYTES {
            anyhow::bail!("audit log exceeds its scan or line size limit");
        }
        report.integrity.total_lines += 1;
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<serde_json::Value>(&line) {
            Ok(value) => {
                if let Some(limit) = limit {
                    if events.len() == limit {
                        events.pop_front();
                    }
                    events.push_back(audit_query_event(&value));
                }
            }
            Err(_) => {
                invalid_count += 1;
                if report.integrity.invalid_lines.len() < MAX_INVALID_AUDIT_LINES {
                    report
                        .integrity
                        .invalid_lines
                        .push(report.integrity.total_lines);
                }
            }
        }
    }
    if invalid_count > 0 {
        report
            .integrity
            .warnings
            .push("audit log contains lines that are not valid JSON".to_string());
    }
    if invalid_count > MAX_INVALID_AUDIT_LINES {
        report.integrity.warnings.push(format!("invalid line list truncated to {MAX_INVALID_AUDIT_LINES} entries; {invalid_count} invalid lines detected"));
    }
    report.events = events.into_iter().collect();
    Ok(report)
}

fn audit_query_event(value: &serde_json::Value) -> AuditQueryEvent {
    AuditQueryEvent {
        schema_version: string_field(value, "schema_version"),
        ts: string_field(value, "ts"),
        actor: string_field(value, "actor"),
        command: string_field(value, "command"),
        target: string_field(value, "target"),
        cwd: string_field(value, "cwd"),
        result: string_field(value, "result"),
        decision: string_field(value, "decision"),
        reason: string_field(value, "reason"),
        risk: string_field(value, "risk"),
        dry_run: value.get("dry_run").and_then(serde_json::Value::as_bool),
    }
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn configure_sqlite(connection: &Connection) -> Result<()> {
    connection
        .execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;
            PRAGMA journal_mode = WAL;
            "#,
        )
        .context("failed to apply sqlite pragmas")
}

fn ensure_audit_columns(connection: &Connection) -> Result<()> {
    let existing_columns = audit_columns(connection)?;
    let migrations = [
        (
            "schema_version",
            "ALTER TABLE audit_events ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'opsctl.audit.v1'",
        ),
        ("cwd", "ALTER TABLE audit_events ADD COLUMN cwd TEXT"),
        (
            "decision",
            "ALTER TABLE audit_events ADD COLUMN decision TEXT NOT NULL DEFAULT 'allow'",
        ),
        ("reason", "ALTER TABLE audit_events ADD COLUMN reason TEXT"),
        (
            "risk",
            "ALTER TABLE audit_events ADD COLUMN risk TEXT NOT NULL DEFAULT 'low'",
        ),
        (
            "dry_run",
            "ALTER TABLE audit_events ADD COLUMN dry_run INTEGER NOT NULL DEFAULT 0",
        ),
    ];

    for (column, statement) in migrations {
        if !existing_columns.iter().any(|existing| existing == column) {
            connection
                .execute_batch(statement)
                .with_context(|| format!("failed to add audit_events.{column}"))?;
        }
    }

    Ok(())
}

fn audit_columns(connection: &Connection) -> Result<Vec<String>> {
    let mut statement = connection
        .prepare("PRAGMA table_info(audit_events)")
        .context("failed to inspect audit_events columns")?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(1))
        .context("failed to query audit_events columns")?;

    let mut columns = Vec::new();
    for row in rows {
        columns.push(row.context("failed to read audit_events column")?);
    }
    Ok(columns)
}

#[cfg(unix)]
fn set_secure_permissions(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_secure_permissions(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

fn secure_sqlite_files(path: &Path) -> Result<()> {
    set_secure_permissions(path, 0o600)?;

    for suffix in ["-wal", "-shm"] {
        let sidecar = sqlite_sidecar_path(path, suffix);
        if sidecar.exists() {
            set_secure_permissions(&sidecar, 0o600)?;
        }
    }

    Ok(())
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    sidecar.into()
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use tempfile::TempDir;

    use super::{AuditRecord, AuditStore, inspect_audit_log, query_audit_log};

    #[test]
    fn audit_scan_bounds_lines_and_invalid_line_output() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("audit.log");
        std::fs::write(&path, vec![b'x'; super::MAX_AUDIT_LINE_BYTES as usize + 1])?;
        assert!(query_audit_log(&path, 20).is_err());
        std::fs::write(
            &path,
            "invalid\n".repeat(super::MAX_INVALID_AUDIT_LINES + 10),
        )?;
        let report = query_audit_log(&path, 20)?;
        assert_eq!(
            report.integrity.total_lines,
            super::MAX_INVALID_AUDIT_LINES + 10
        );
        assert_eq!(
            report.integrity.invalid_lines.len(),
            super::MAX_INVALID_AUDIT_LINES
        );
        assert!(
            report
                .integrity
                .warnings
                .iter()
                .any(|warning| warning.contains("truncated"))
        );
        assert!(report.events.is_empty());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn audit_query_refuses_symlink_and_non_regular_file() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("audit.log");
        let target = temp.path().join("target.log");
        std::fs::write(&target, "{}\n")?;
        std::os::unix::fs::symlink(&target, &path)?;
        assert!(query_audit_log(&path, 20).is_err());
        assert!(query_audit_log(temp.path(), 20).is_err());
        Ok(())
    }

    #[test]
    fn writes_audit_event_to_jsonl() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state_dir = temp_dir.path();
        let db_path = state_dir.join("opsctl.db");
        let audit_log = state_dir.join("audit.log");
        let store = AuditStore::open(state_dir, &db_path, &audit_log)?;

        store.record(&AuditRecord {
            actor: "tester",
            command: "status",
            target: None,
            result: "success",
            decision: "allow",
            reason: None,
            risk: "low",
            dry_run: false,
        })?;

        let raw = std::fs::read_to_string(audit_log)?;
        assert!(raw.contains("\"command\":\"status\""));
        assert!(raw.contains("\"result\":\"success\""));
        assert!(raw.contains("\"schema_version\":\"opsctl.audit.v1\""));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn record_refuses_audit_log_symlink() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new()?;
        let state_dir = temp_dir.path();
        let db_path = state_dir.join("opsctl.db");
        let audit_log = state_dir.join("audit.log");
        let target = state_dir.join("target.log");
        std::fs::write(&target, "")?;
        symlink(&target, &audit_log)?;

        let store = AuditStore::open(state_dir, &db_path, &audit_log)?;
        let error = match store.record(&AuditRecord {
            actor: "tester",
            command: "status",
            target: None,
            result: "success",
            decision: "allow",
            reason: None,
            risk: "low",
            dry_run: false,
        }) {
            Ok(_) => anyhow::bail!("audit symlink should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("failed to open audit log"));
        Ok(())
    }

    #[test]
    fn audit_integrity_reports_invalid_jsonl_lines() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let audit_log = temp_dir.path().join("audit.log");
        std::fs::write(&audit_log, "{\"ok\":true}\nnot-json\n")?;

        let report = inspect_audit_log(&audit_log)?;

        assert_eq!(report.total_lines, 2);
        assert_eq!(report.invalid_lines, vec![2]);
        assert_eq!(report.warnings.len(), 1);
        Ok(())
    }

    #[test]
    fn query_audit_log_returns_recent_valid_events_only() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let audit_log = temp_dir.path().join("audit.log");
        std::fs::write(
            &audit_log,
            r#"{"schema_version":"opsctl.audit.v1","ts":"1","actor":"a","command":"status","result":"success","decision":"allow","risk":"low","dry_run":false}
not-json
{"schema_version":"opsctl.audit.v1","ts":"2","actor":"a","command":"doctor","result":"success","decision":"allow","risk":"medium","dry_run":false}
"#,
        )?;

        let report = query_audit_log(&audit_log, 1)?;

        assert_eq!(report.integrity.total_lines, 3);
        assert_eq!(report.integrity.invalid_lines, vec![2]);
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].command.as_deref(), Some("doctor"));
        Ok(())
    }
}
