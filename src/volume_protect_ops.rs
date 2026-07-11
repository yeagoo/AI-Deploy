use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const MAX_MAINTENANCE_JOURNAL_BYTES: u64 = 128 * 1024 * 1024;

use crate::{
    drift::read_drift_cleanup_request_document,
    paths::display_path,
    volume_protect_campaign::{campaign_journal_path, campaign_status},
    volume_protect_lifecycle::volume_protect_run_status,
};

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectMetricsReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub runs_total: usize,
    pub runs_failed: usize,
    pub runs_resumable: usize,
    pub campaigns_total: usize,
    pub campaigns_paused: usize,
    pub files_checked: usize,
    pub bytes_checked: u64,
    pub duration_ms: u64,
    pub evidence_gaps: Option<usize>,
    pub metrics: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectJournalMaintenanceReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub keep_lines: usize,
    pub archive_dir: String,
    pub files: Vec<VolumeProtectJournalMaintenanceFile>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectJournalMaintenanceFile {
    pub path: String,
    pub total_lines: usize,
    pub retained_lines: usize,
    pub archived_lines: usize,
    pub archive_path: Option<String>,
    pub archive_sha256: Option<String>,
}

pub fn volume_protect_metrics(
    state_dir: &Path,
    request_file: Option<&Path>,
) -> VolumeProtectMetricsReport {
    let runs = volume_protect_run_status(state_dir, None, usize::MAX);
    let campaigns = campaign_status(state_dir, None, usize::MAX);
    let mut limitations = runs.limitations.clone();
    limitations.extend(campaigns.limitations.clone());
    let evidence_gaps = request_file.map(|path| {
        read_drift_cleanup_request_document(path)
            .map(|request| {
                request
                    .items
                    .iter()
                    .filter(|item| {
                        item.kind == "docker-volume"
                            && (item.backup_snapshot_id.as_deref().is_none_or(str::is_empty)
                                || item.restore_drill_id.as_deref().is_none_or(str::is_empty))
                    })
                    .count()
            })
            .unwrap_or_else(|error| {
                limitations.push(error.to_string());
                0
            })
    });
    let runs_failed = runs.runs.iter().filter(|run| run.stage == "failed").count();
    let runs_resumable = runs.runs.iter().filter(|run| run.resumable).count();
    let campaigns_paused = campaigns
        .campaigns
        .iter()
        .filter(|campaign| campaign.stage == "paused")
        .count();
    let files_checked = runs.runs.iter().filter_map(|run| run.files_checked).sum();
    let bytes_checked = runs.runs.iter().filter_map(|run| run.bytes_checked).sum();
    let duration_ms = runs.runs.iter().filter_map(|run| run.duration_ms).sum();
    let mut metrics = format!(
        "# HELP opsctl_volume_protect_runs_total Recorded volume protection runs.\n# TYPE opsctl_volume_protect_runs_total gauge\nopsctl_volume_protect_runs_total {}\n# HELP opsctl_volume_protect_runs_failed Failed volume protection runs.\n# TYPE opsctl_volume_protect_runs_failed gauge\nopsctl_volume_protect_runs_failed {}\n# HELP opsctl_volume_protect_runs_resumable Resumable volume protection runs.\n# TYPE opsctl_volume_protect_runs_resumable gauge\nopsctl_volume_protect_runs_resumable {}\n# HELP opsctl_volume_protect_campaigns_total Recorded volume protection campaigns.\n# TYPE opsctl_volume_protect_campaigns_total gauge\nopsctl_volume_protect_campaigns_total {}\n# HELP opsctl_volume_protect_campaigns_paused Paused volume protection campaigns.\n# TYPE opsctl_volume_protect_campaigns_paused gauge\nopsctl_volume_protect_campaigns_paused {}\n# HELP opsctl_volume_protect_files_checked Files checked by latest run states.\n# TYPE opsctl_volume_protect_files_checked gauge\nopsctl_volume_protect_files_checked {}\n# HELP opsctl_volume_protect_bytes_checked Bytes checked by latest run states.\n# TYPE opsctl_volume_protect_bytes_checked gauge\nopsctl_volume_protect_bytes_checked {}\n# HELP opsctl_volume_protect_duration_milliseconds Total latest run duration.\n# TYPE opsctl_volume_protect_duration_milliseconds gauge\nopsctl_volume_protect_duration_milliseconds {}\n",
        runs.runs.len(),
        runs_failed,
        runs_resumable,
        campaigns.campaigns.len(),
        campaigns_paused,
        files_checked,
        bytes_checked,
        duration_ms,
    );
    if let Some(gaps) = evidence_gaps {
        metrics.push_str(&format!(
            "# HELP opsctl_volume_protect_evidence_gaps Docker volume cleanup items missing backup or restore evidence.\n# TYPE opsctl_volume_protect_evidence_gaps gauge\nopsctl_volume_protect_evidence_gaps {gaps}\n"
        ));
    }
    metrics.push_str("# EOF\n");
    VolumeProtectMetricsReport {
        ok: limitations.is_empty(),
        read_only: true,
        status: if limitations.is_empty() {
            "ready"
        } else {
            "limited"
        }
        .to_string(),
        runs_total: runs.runs.len(),
        runs_failed,
        runs_resumable,
        campaigns_total: campaigns.campaigns.len(),
        campaigns_paused,
        files_checked,
        bytes_checked,
        duration_ms,
        evidence_gaps,
        metrics,
        limitations,
    }
}

pub fn maintain_volume_protect_journals(
    state_dir: &Path,
    archive_dir: &Path,
    keep_lines: usize,
    execute: bool,
) -> VolumeProtectJournalMaintenanceReport {
    let mut limitations = Vec::new();
    if keep_lines < 100 {
        limitations.push("keep_lines must be at least 100".to_string());
    }
    if !archive_dir.is_absolute() || archive_dir == Path::new("/") {
        limitations.push("archive_dir must be an absolute non-root directory".to_string());
    }
    if let Ok(metadata) = fs::symlink_metadata(archive_dir)
        && (metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        limitations.push("archive_dir is a symlink or is not a directory".to_string());
    }
    if path_contains_symlink(archive_dir) {
        limitations.push("archive_dir contains a symlink ancestor".to_string());
    }
    let paths = [
        state_dir.join("volume-protect-runs.jsonl"),
        campaign_journal_path(state_dir),
        state_dir.join("volume-protect.jsonl"),
    ];
    let mut files = Vec::new();
    for path in paths {
        match maintain_one_journal(
            &path,
            archive_dir,
            keep_lines,
            execute && limitations.is_empty(),
        ) {
            Ok(file) => files.push(file),
            Err(error) => limitations.push(error.to_string()),
        }
    }
    VolumeProtectJournalMaintenanceReport {
        ok: limitations.is_empty(),
        read_only: !execute,
        status: if !limitations.is_empty() {
            "blocked"
        } else if execute {
            "maintained"
        } else {
            "planned"
        }
        .to_string(),
        keep_lines,
        archive_dir: display_path(archive_dir),
        files,
        limitations,
    }
}

fn maintain_one_journal(
    path: &Path,
    archive_dir: &Path,
    keep_lines: usize,
    execute: bool,
) -> Result<VolumeProtectJournalMaintenanceFile> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VolumeProtectJournalMaintenanceFile {
                path: display_path(path),
                total_lines: 0,
                retained_lines: 0,
                archived_lines: 0,
                archive_path: None,
                archive_sha256: None,
            });
        }
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_MAINTENANCE_JOURNAL_BYTES
    {
        anyhow::bail!("refusing unsafe journal: {}", path.display());
    }
    let raw = fs::read_to_string(path)?;
    let lines = raw.lines().collect::<Vec<_>>();
    let archived_lines = lines.len().saturating_sub(keep_lines);
    let mut result = VolumeProtectJournalMaintenanceFile {
        path: display_path(path),
        total_lines: lines.len(),
        retained_lines: lines.len().min(keep_lines),
        archived_lines,
        archive_path: None,
        archive_sha256: None,
    };
    if !execute || archived_lines == 0 {
        return Ok(result);
    }
    fs::create_dir_all(archive_dir)?;
    #[cfg(unix)]
    fs::set_permissions(archive_dir, fs::Permissions::from_mode(0o700))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("journal file name is invalid")?;
    let archive_path = archive_dir.join(format!(
        "{}-{}.jsonl",
        file_name.trim_end_matches(".jsonl"),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    let archive_content = format!("{}\n", lines[..archived_lines].join("\n"));
    write_new_file(&archive_path, archive_content.as_bytes())?;
    let archive_sha256 = format!("{:x}", Sha256::digest(archive_content.as_bytes()));
    write_new_file(
        &archive_path.with_extension("jsonl.sha256"),
        format!(
            "{archive_sha256}  {}\n",
            archive_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("archive.jsonl")
        )
        .as_bytes(),
    )?;
    let retained = format!("{}\n", lines[archived_lines..].join("\n"));
    replace_file(path, retained.as_bytes())?;
    result.archive_path = Some(display_path(&archive_path));
    result.archive_sha256 = Some(archive_sha256);
    Ok(result)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn replace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("journal path has no parent")?;
    let temporary = parent.join(format!(
        ".{}.maintain-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("journal"),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    write_new_file(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn path_contains_symlink(path: &Path) -> bool {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component.as_os_str());
        if fs::symlink_metadata(&cursor).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_maintenance_archives_before_retaining_tail() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let archives = state.path().join("archives");
        let journal = state.path().join("volume-protect-runs.jsonl");
        let content = (0..105)
            .map(|index| format!("{{\"line\":{index}}}"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&journal, format!("{content}\n"))?;

        let report = maintain_volume_protect_journals(state.path(), &archives, 100, true);

        assert!(report.ok);
        let maintained = report
            .files
            .iter()
            .find(|file| file.path.ends_with("volume-protect-runs.jsonl"))
            .context("run journal should be reported")?;
        assert_eq!(maintained.archived_lines, 5);
        assert_eq!(fs::read_to_string(&journal)?.lines().count(), 100);
        assert!(
            maintained
                .archive_path
                .as_ref()
                .is_some_and(|path| Path::new(path).is_file())
        );
        Ok(())
    }
}
