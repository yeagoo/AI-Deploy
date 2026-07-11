use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{
    evidence_crypto,
    paths::display_path,
    registry::Registry,
    volume_protect::{VolumeProtectOptions, VolumeProtectReport, volume_protect},
};

const RUN_SCHEMA: &str = "opsctl.volume_protect_run.v1";
const MAX_RUN_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeProtectRunEvent {
    pub schema_version: String,
    pub run_id: String,
    pub ts: String,
    pub stage: String,
    pub actor: String,
    pub request_file: String,
    pub request_id: String,
    pub target: String,
    pub repository_id: String,
    pub restore_root: String,
    #[serde(default = "default_verification_strength")]
    pub min_verification_strength: String,
    pub repository_snapshot_id: Option<String>,
    pub restore_dir: Option<String>,
    pub files_checked: Option<usize>,
    pub bytes_checked: Option<u64>,
    pub duration_ms: Option<u64>,
    pub error_code: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct RunEventInput<'a> {
    pub run_id: &'a str,
    pub stage: &'a str,
    pub actor: &'a str,
    pub request_file: &'a Path,
    pub request_id: &'a str,
    pub target: &'a str,
    pub repository_id: &'a str,
    pub restore_root: &'a Path,
    pub min_verification_strength: &'a str,
    pub repository_snapshot_id: Option<&'a str>,
    pub restore_dir: Option<&'a Path>,
    pub files_checked: Option<usize>,
    pub bytes_checked: Option<u64>,
    pub duration_ms: Option<u64>,
    pub error_code: Option<&'a str>,
    pub detail: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectRunStatusReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub run_id: Option<String>,
    pub runs: Vec<VolumeProtectRunStatus>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectRunStatus {
    pub run_id: String,
    pub stage: String,
    pub resumable: bool,
    pub request_file: String,
    pub request_id: String,
    pub target: String,
    pub repository_id: String,
    pub restore_root: String,
    pub min_verification_strength: String,
    pub repository_snapshot_id: Option<String>,
    pub restore_dir: Option<String>,
    pub started_at: String,
    pub updated_at: String,
    pub files_checked: Option<usize>,
    pub bytes_checked: Option<u64>,
    pub duration_ms: Option<u64>,
    pub error_code: Option<String>,
    pub events: Vec<VolumeProtectRunEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectCleanupReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub restore_root: String,
    pub keep_days: u32,
    pub keep_count: usize,
    pub candidates: Vec<String>,
    pub removed: Vec<String>,
    pub retained: Vec<String>,
    pub limitations: Vec<String>,
}

pub fn append_run_event(state_dir: &Path, input: &RunEventInput<'_>) -> Result<()> {
    let path = run_journal_path(state_dir);
    evidence_crypto::verify_artifact_before_append(state_dir, &path)?;
    let event = VolumeProtectRunEvent {
        schema_version: RUN_SCHEMA.to_string(),
        run_id: input.run_id.to_string(),
        ts: timestamp(),
        stage: input.stage.to_string(),
        actor: input.actor.to_string(),
        request_file: display_path(input.request_file),
        request_id: input.request_id.to_string(),
        target: input.target.to_string(),
        repository_id: input.repository_id.to_string(),
        restore_root: display_path(input.restore_root),
        min_verification_strength: input.min_verification_strength.to_string(),
        repository_snapshot_id: input.repository_snapshot_id.map(str::to_string),
        restore_dir: input.restore_dir.map(display_path),
        files_checked: input.files_checked,
        bytes_checked: input.bytes_checked,
        duration_ms: input.duration_ms,
        error_code: input.error_code.map(str::to_string),
        detail: input.detail.to_string(),
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        anyhow::bail!(
            "refusing unsafe volume protect run journal: {}",
            path.display()
        );
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&path)?;
    writeln!(file, "{}", serde_json::to_string(&event)?)?;
    file.sync_data()?;
    evidence_crypto::append_audit_event(
        state_dir,
        "volume_protect_run",
        input.actor,
        input.run_id,
        &path,
    )?;
    Ok(())
}

pub fn volume_protect_run_status(
    state_dir: &Path,
    run_id: Option<&str>,
    limit: usize,
) -> VolumeProtectRunStatusReport {
    let (events, limitations) = read_run_events(state_dir);
    let mut grouped = BTreeMap::<String, Vec<VolumeProtectRunEvent>>::new();
    for event in events {
        if run_id.is_none_or(|expected| event.run_id == expected) {
            grouped.entry(event.run_id.clone()).or_default().push(event);
        }
    }
    let mut runs = grouped
        .into_values()
        .filter_map(run_status_from_events)
        .collect::<Vec<_>>();
    runs.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    runs.truncate(limit);
    let found = run_id.is_none() || !runs.is_empty();
    VolumeProtectRunStatusReport {
        ok: limitations.is_empty() && found,
        read_only: true,
        status: if !found {
            "not_found"
        } else if limitations.is_empty() {
            "ready"
        } else {
            "limited"
        }
        .to_string(),
        run_id: run_id.map(str::to_string),
        runs,
        limitations,
    }
}

pub fn resume_volume_protect(
    registry: &Registry,
    state_dir: &Path,
    actor: &str,
    run_id: &str,
    execute: bool,
    alert_on_failure: bool,
) -> Result<VolumeProtectReport> {
    let status = volume_protect_run_status(state_dir, Some(run_id), 1);
    let run = status
        .runs
        .first()
        .with_context(|| format!("volume protect run not found: {run_id}"))?;
    if run.stage == "evidence_written" {
        anyhow::bail!("volume protect run is already complete: {run_id}");
    }
    let request_file = PathBuf::from(&run.request_file);
    let restore_root = PathBuf::from(&run.restore_root);
    volume_protect(&VolumeProtectOptions {
        registry,
        request_file: &request_file,
        state_dir,
        actor,
        target: &run.target,
        repository_id: &run.repository_id,
        restore_root: &restore_root,
        run_id: Some(run_id),
        resume_snapshot_id: run.repository_snapshot_id.as_deref(),
        min_verification_strength: &run.min_verification_strength,
        alert_on_failure,
        execute,
    })
}

pub fn cleanup_volume_protect_staging(
    state_dir: &Path,
    restore_root: &Path,
    keep_days: u32,
    keep_count: usize,
    execute: bool,
) -> VolumeProtectCleanupReport {
    let mut limitations = Vec::new();
    if !restore_root.is_absolute() || restore_root == Path::new("/") {
        limitations.push("restore_root must be an absolute non-root directory".to_string());
    }
    let (events, event_limitations) = read_run_events(state_dir);
    limitations.extend(event_limitations);
    if let Ok(metadata) = fs::symlink_metadata(restore_root)
        && (metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        limitations.push("restore_root is a symlink or is not a directory".to_string());
    }
    let mut recorded_paths = events
        .iter()
        .filter_map(|event| event.restore_dir.as_deref())
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    recorded_paths.sort();
    recorded_paths.dedup();
    let mut recorded = Vec::new();
    for path in recorded_paths {
        if path.parent() != Some(restore_root) {
            limitations.push(format!(
                "recorded staging path is not a direct child of restore_root: {}",
                path.display()
            ));
            continue;
        }
        recorded.push(path);
    }
    recorded.sort();
    recorded.sort_by_key(|path| {
        fs::symlink_metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
    });
    recorded.reverse();
    let cutoff = OffsetDateTime::now_utc() - Duration::days(i64::from(keep_days));
    let mut candidates = Vec::new();
    let mut retained = Vec::new();
    for (index, path) in recorded.into_iter().enumerate() {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            limitations.push(format!("unsafe staging candidate: {}", path.display()));
            continue;
        }
        let old = metadata
            .modified()
            .ok()
            .map(OffsetDateTime::from)
            .is_some_and(|value| value < cutoff);
        if index >= keep_count && old {
            candidates.push(path);
        } else {
            retained.push(display_path(&path));
        }
    }
    let mut removed = Vec::new();
    if execute && limitations.is_empty() {
        for path in &candidates {
            match fs::remove_dir_all(path) {
                Ok(()) => removed.push(display_path(path)),
                Err(error) => {
                    limitations.push(format!("failed to remove {}: {error}", path.display()))
                }
            }
        }
    }
    VolumeProtectCleanupReport {
        ok: limitations.is_empty(),
        read_only: !execute,
        status: if !limitations.is_empty() {
            "blocked"
        } else if execute {
            "cleaned"
        } else {
            "planned"
        }
        .to_string(),
        restore_root: display_path(restore_root),
        keep_days,
        keep_count,
        candidates: candidates.iter().map(|path| display_path(path)).collect(),
        removed,
        retained,
        limitations,
    }
}

fn read_run_events(state_dir: &Path) -> (Vec<VolumeProtectRunEvent>, Vec<String>) {
    let path = run_journal_path(state_dir);
    if !path.exists() {
        return (Vec::new(), Vec::new());
    }
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => return (Vec::new(), vec![error.to_string()]),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_RUN_JOURNAL_BYTES
    {
        return (
            Vec::new(),
            vec!["volume protect run journal is unsafe or too large".to_string()],
        );
    }
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => return (Vec::new(), vec![error.to_string()]),
    };
    let mut events = Vec::new();
    let mut limitations = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        match serde_json::from_str::<VolumeProtectRunEvent>(line) {
            Ok(event) if event.schema_version == RUN_SCHEMA => events.push(event),
            Ok(_) => limitations.push(format!(
                "run journal line {} has unsupported schema",
                index + 1
            )),
            Err(error) => limitations.push(format!(
                "run journal line {} is invalid: {error}",
                index + 1
            )),
        }
    }
    (events, limitations)
}

fn run_status_from_events(
    mut events: Vec<VolumeProtectRunEvent>,
) -> Option<VolumeProtectRunStatus> {
    events.sort_by(|left, right| left.ts.cmp(&right.ts));
    let first = events.first()?;
    let last = events.last()?;
    let latest_snapshot = events
        .iter()
        .rev()
        .find_map(|event| event.repository_snapshot_id.clone());
    let latest_restore = events
        .iter()
        .rev()
        .find_map(|event| event.restore_dir.clone());
    let latest_files = events.iter().rev().find_map(|event| event.files_checked);
    let latest_bytes = events.iter().rev().find_map(|event| event.bytes_checked);
    let duration_ms = events.iter().rev().find_map(|event| event.duration_ms);
    Some(VolumeProtectRunStatus {
        run_id: last.run_id.clone(),
        stage: last.stage.clone(),
        resumable: last.stage != "evidence_written" && latest_snapshot.is_some(),
        request_file: first.request_file.clone(),
        request_id: first.request_id.clone(),
        target: first.target.clone(),
        repository_id: first.repository_id.clone(),
        restore_root: first.restore_root.clone(),
        min_verification_strength: first.min_verification_strength.clone(),
        repository_snapshot_id: latest_snapshot,
        restore_dir: latest_restore,
        started_at: first.ts.clone(),
        updated_at: last.ts.clone(),
        files_checked: latest_files,
        bytes_checked: latest_bytes,
        duration_ms,
        error_code: last.error_code.clone(),
        events,
    })
}

fn run_journal_path(state_dir: &Path) -> PathBuf {
    state_dir.join("volume-protect-runs.jsonl")
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string())
}

fn default_verification_strength() -> String {
    "feature".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_rejects_recorded_parent_traversal() -> Result<()> {
        let workspace = tempfile::TempDir::new()?;
        let state_dir = workspace.path().join("state");
        let restore_root = workspace.path().join("restores");
        let outside = workspace.path().join("outside");
        fs::create_dir_all(&restore_root)?;
        fs::create_dir_all(&outside)?;
        append_run_event(
            &state_dir,
            &RunEventInput {
                run_id: "vp-test",
                stage: "restore_succeeded",
                actor: "test",
                request_file: Path::new("/tmp/request.yml"),
                request_id: "cleanup-volume-test",
                target: "test",
                repository_id: "repository",
                restore_root: &restore_root,
                min_verification_strength: "feature",
                repository_snapshot_id: Some("abc12345"),
                restore_dir: Some(&restore_root.join("../outside")),
                files_checked: None,
                bytes_checked: None,
                duration_ms: None,
                error_code: None,
                detail: "test fixture",
            },
        )?;

        let report = cleanup_volume_protect_staging(&state_dir, &restore_root, 0, 0, true);

        assert!(!report.ok);
        assert_eq!(report.status, "blocked");
        assert!(outside.is_dir());
        assert!(report.removed.is_empty());
        assert!(
            report
                .limitations
                .iter()
                .any(|value| value.contains("not a direct child"))
        );
        Ok(())
    }
}
