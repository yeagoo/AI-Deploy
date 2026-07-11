use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    backup::{parse_repository_snapshot_id, repository_command_env, restic_base_argv},
    command_runner, evidence_crypto,
    paths::display_path,
    registry::Registry,
};

const MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARCHIVE_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct EvidenceArchiveOptions<'a> {
    pub registry: &'a Registry,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub bundle_file: &'a Path,
    pub repository_id: &'a str,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceArchiveReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub bundle_file: String,
    pub signature_file: String,
    pub bundle_sha256: Option<String>,
    pub signature_valid: bool,
    pub repository_id: String,
    pub provider: Option<String>,
    pub snapshot_id: Option<String>,
    pub duration_ms: Option<u64>,
    pub immutability_externally_enforced: bool,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

pub fn archive_evidence_bundle(options: &EvidenceArchiveOptions<'_>) -> EvidenceArchiveReport {
    let mut limitations = Vec::new();
    let warnings = vec![
        "repository retention/Object Lock/WORM policy must be enforced and audited outside opsctl"
            .to_string(),
    ];
    let repository = options
        .registry
        .backups
        .repositories
        .iter()
        .find(|repository| repository.id == options.repository_id);
    if repository.is_none() {
        limitations.push("evidence archive repository is not registered".to_string());
    }
    if repository.is_some_and(|repository| repository.status != "active") {
        limitations.push("evidence archive repository is not active".to_string());
    }
    if repository
        .is_some_and(|repository| !matches!(repository.provider.as_str(), "restic" | "rustic"))
    {
        limitations.push("evidence archive supports Restic/rustic repositories only".to_string());
    }
    let bundle_bytes = read_bundle(options.bundle_file, &mut limitations);
    let bundle_sha256 = bundle_bytes
        .as_deref()
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)));
    let signature =
        evidence_crypto::verify_artifact_signature(options.state_dir, options.bundle_file);
    let signature_file = PathBuf::from(&signature.signature_path);
    if !signature.ok {
        limitations.push("audit bundle must have a valid trusted detached signature".to_string());
    }
    let audit = evidence_crypto::verify_audit_chain(options.state_dir);
    if !audit.ok {
        limitations.push("evidence audit chain must verify before archive execution".to_string());
    }
    if let Some(repository) = repository {
        for name in repository
            .repository_env
            .iter()
            .chain(repository.password_env.iter())
            .chain(repository.env.iter())
        {
            if std::env::var_os(name).is_none() {
                limitations.push(format!("missing repository environment: {name}"));
            }
        }
        if repository.repository_env.is_none() && repository.repository.is_none() {
            limitations.push("repository location is unavailable".to_string());
        }
    }
    limitations.sort();
    limitations.dedup();
    let mut report = EvidenceArchiveReport {
        ok: limitations.is_empty(),
        read_only: !options.execute,
        status: if limitations.is_empty() {
            "planned"
        } else {
            "blocked"
        }
        .to_string(),
        bundle_file: display_path(options.bundle_file),
        signature_file: display_path(&signature_file),
        bundle_sha256,
        signature_valid: signature.ok,
        repository_id: options.repository_id.to_string(),
        provider: repository.map(|repository| repository.provider.clone()),
        snapshot_id: None,
        duration_ms: None,
        immutability_externally_enforced: false,
        warnings,
        limitations,
    };
    if !options.execute || !report.limitations.is_empty() {
        return report;
    }
    let Some(repository) = repository else {
        return report;
    };
    let started = Instant::now();
    let mut args = restic_base_argv(repository);
    let program = args.remove(0);
    args.extend([
        "backup".to_string(),
        display_path(options.bundle_file),
        display_path(&signature_file),
        "--tag".to_string(),
        "opsctl-evidence-archive".to_string(),
        "--tag".to_string(),
        format!(
            "bundle-sha256:{}",
            report.bundle_sha256.as_deref().unwrap_or("unknown")
        ),
    ]);
    let output = command_runner::run_controlled_with_env(
        &program,
        &args,
        &repository_command_env(repository),
    );
    report.duration_ms = Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
    match output {
        Ok(output) if output.success() => {
            report.snapshot_id = parse_repository_snapshot_id(&output.stdout);
            if report.snapshot_id.is_none() {
                report
                    .limitations
                    .push("repository snapshot id was not present in trusted output".to_string());
            }
        }
        Ok(_) => report
            .limitations
            .push("evidence repository archive command failed".to_string()),
        Err(error) => report.limitations.push(error.to_string()),
    }
    report.ok = report.limitations.is_empty();
    report.status = if report.ok { "archived" } else { "blocked" }.to_string();
    if report.ok
        && let Err(error) = append_archive_report(options.state_dir, options.actor, &report)
    {
        report.ok = false;
        report.status = "blocked".to_string();
        report.limitations.push(error.to_string());
    }
    report
}

pub fn evidence_archive_history(state_dir: &Path, limit: usize) -> Vec<EvidenceArchiveReport> {
    let path = state_dir.join("evidence-archives.jsonl");
    let Ok(reports) = read_archive_reports(&path) else {
        return Vec::new();
    };
    reports.into_iter().rev().take(limit).collect()
}

fn read_bundle(path: &Path, limitations: &mut Vec<String>) -> Option<Vec<u8>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            limitations.push(error.to_string());
            return None;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_BUNDLE_BYTES
    {
        limitations.push("audit bundle is unsafe or too large".to_string());
        return None;
    }
    match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            limitations.push(error.to_string());
            None
        }
    }
}

fn append_archive_report(
    state_dir: &Path,
    actor: &str,
    report: &EvidenceArchiveReport,
) -> Result<()> {
    let path = state_dir.join("evidence-archives.jsonl");
    evidence_crypto::verify_artifact_before_append(state_dir, &path)?;
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_ARCHIVE_JOURNAL_BYTES)
    {
        anyhow::bail!("evidence archive journal is unsafe or oversized");
    }
    fs::create_dir_all(state_dir)?;
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&path)?;
    writeln!(file, "{}", serde_json::to_string(report)?)?;
    file.sync_data()?;
    evidence_crypto::append_audit_event(
        state_dir,
        "evidence_archive",
        actor,
        report.snapshot_id.as_deref().unwrap_or("unknown"),
        &path,
    )
}

fn read_archive_reports(path: &Path) -> Result<Vec<EvidenceArchiveReport>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_ARCHIVE_JOURNAL_BYTES
    {
        anyhow::bail!("evidence archive journal is unsafe or oversized");
    }
    fs::read_to_string(path)?
        .lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line)
                .with_context(|| format!("invalid evidence archive journal line {}", index + 1))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::read_bundle;

    #[cfg(unix)]
    #[test]
    fn archive_rejects_symlink_bundle() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let root = TempDir::new()?;
        let target = root.path().join("bundle.json");
        let link = root.path().join("bundle-link.json");
        fs::write(&target, b"{}")?;
        symlink(&target, &link)?;
        let mut limitations = Vec::new();

        assert!(read_bundle(&link, &mut limitations).is_none());
        assert!(limitations.iter().any(|item| item.contains("unsafe")));
        Ok(())
    }
}
