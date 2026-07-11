#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    collections::VecDeque,
    env,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
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

pub fn inspect_audit_log(path: &Path) -> Result<AuditIntegrityReport> {
    if !path.exists() {
        return Ok(AuditIntegrityReport {
            path: path.to_string_lossy().into_owned(),
            exists: false,
            total_lines: 0,
            invalid_lines: Vec::new(),
            warnings: vec!["audit log does not exist yet".to_string()],
        });
    }

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(AuditIntegrityReport {
            path: path.to_string_lossy().into_owned(),
            exists: true,
            total_lines: 0,
            invalid_lines: Vec::new(),
            warnings: vec!["audit log path is a symlink; integrity was not scanned".to_string()],
        });
    }

    let file = fs::File::open(path)
        .with_context(|| format!("failed to open audit log {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut total_lines = 0_usize;
    let mut invalid_lines = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("failed to read audit log {}", path.display()))?;
        total_lines = index + 1;
        if line.trim().is_empty() {
            continue;
        }
        if serde_json::from_str::<serde_json::Value>(&line).is_err() {
            invalid_lines.push(index + 1);
        }
    }

    let mut warnings = Vec::new();
    if !invalid_lines.is_empty() {
        warnings.push("audit log contains lines that are not valid JSON".to_string());
    }

    Ok(AuditIntegrityReport {
        path: path.to_string_lossy().into_owned(),
        exists: true,
        total_lines,
        invalid_lines,
        warnings,
    })
}

pub fn query_audit_log(path: &Path, limit: usize) -> Result<AuditQueryReport> {
    let limit = limit.clamp(1, 1000);
    let integrity = inspect_audit_log(path)?;
    if !path.exists() {
        return Ok(AuditQueryReport {
            path: path.to_string_lossy().into_owned(),
            limit,
            integrity,
            events: Vec::new(),
        });
    }

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to query audit log symlink: {}", path.display());
    }

    let file = fs::File::open(path)
        .with_context(|| format!("failed to open audit log {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut events = VecDeque::with_capacity(limit);

    for line in reader.lines() {
        let line = line.with_context(|| format!("failed to read audit log {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if events.len() == limit {
            events.pop_front();
        }
        events.push_back(audit_query_event(&value));
    }

    Ok(AuditQueryReport {
        path: path.to_string_lossy().into_owned(),
        limit,
        integrity,
        events: events.into_iter().collect(),
    })
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
