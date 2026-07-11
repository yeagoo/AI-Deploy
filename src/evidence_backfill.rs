use std::{fs, io::Write, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{
    evidence_crypto,
    paths::display_path,
    registry::Registry,
    volume_protect::{EvidenceResolveOptions, EvidenceResolveReport, resolve_cleanup_evidence},
};

const BACKFILL_SCHEMA: &str = "opsctl.evidence_backfill.v1";
const MAX_BACKFILL_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;

pub struct EvidenceBackfillOptions<'a> {
    pub registry: &'a Registry,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub request_file: &'a Path,
    pub repository_id: &'a str,
    pub restore_root: &'a Path,
    pub max_age_hours: u32,
    pub record: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBackfillReport {
    pub schema_version: String,
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub observed_at: String,
    pub request_file: String,
    pub repository_id: String,
    pub selected_items: usize,
    pub matched: usize,
    pub ambiguous: usize,
    pub missing: usize,
    pub stale: usize,
    pub exact_profile_matches: usize,
    pub actions: Vec<EvidenceBackfillAction>,
    pub historical_phase95_total_missing: usize,
    pub historical_phase95_database_like: usize,
    pub historical_baseline_only: bool,
    pub journal_path: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBackfillAction {
    pub request_id: String,
    pub target: String,
    pub evidence_status: String,
    pub profile_matches: usize,
    pub action: String,
    pub argv: Vec<String>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceBackfillStatusReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub journal_path: String,
    pub latest: Option<EvidenceBackfillReport>,
    pub history: Vec<EvidenceBackfillReport>,
    pub matched_delta: Option<i64>,
    pub evidence_gap_delta: Option<i64>,
    pub limitations: Vec<String>,
}

pub fn evidence_backfill(options: &EvidenceBackfillOptions<'_>) -> EvidenceBackfillReport {
    let resolved = resolve_cleanup_evidence(&EvidenceResolveOptions {
        registry: options.registry,
        request_file: options.request_file,
        state_dir: options.state_dir,
        request_ids: &[],
        targets: &[],
        all: true,
        max_age_hours: options.max_age_hours,
        verify_repository: false,
        execute: false,
    });
    let journal_path = options.state_dir.join("evidence-backfill.jsonl");
    let mut limitations = resolved.limitations.clone();
    if !options.restore_root.is_absolute() || options.restore_root == Path::new("/") {
        limitations.push("restore_root must be an absolute non-root directory".to_string());
    }
    let repository = options
        .registry
        .backups
        .repositories
        .iter()
        .find(|repository| repository.id == options.repository_id);
    if repository.is_none_or(|repository| repository.status != "active") {
        limitations.push("repository_id must identify an active repository".to_string());
    }
    let actions = backfill_actions(options, &resolved);
    let exact_profile_matches = actions
        .iter()
        .filter(|action| action.profile_matches == 1)
        .count();
    let mut report = EvidenceBackfillReport {
        schema_version: BACKFILL_SCHEMA.to_string(),
        ok: limitations.is_empty() && resolved.ambiguous == 0,
        read_only: !options.record,
        status: if !limitations.is_empty() {
            "blocked"
        } else if resolved.ambiguous > 0 {
            "review_required"
        } else if resolved.missing + resolved.stale == 0 {
            "closed"
        } else {
            "evidence_required"
        }
        .to_string(),
        observed_at: timestamp(),
        request_file: display_path(options.request_file),
        repository_id: options.repository_id.to_string(),
        selected_items: resolved.selected_items,
        matched: resolved.matched,
        ambiguous: resolved.ambiguous,
        missing: resolved.missing,
        stale: resolved.stale,
        exact_profile_matches,
        actions,
        historical_phase95_total_missing: 69,
        historical_phase95_database_like: 58,
        historical_baseline_only: true,
        journal_path: display_path(&journal_path),
        limitations,
    };
    if options.record && report.limitations.is_empty() {
        report.read_only = false;
        report.status = format!("{}_recorded", report.status);
        if let Err(error) = append_report(options.state_dir, options.actor, &report) {
            report.ok = false;
            report.status = "blocked".to_string();
            report.limitations.push(error.to_string());
        }
    }
    report
}

pub fn evidence_backfill_status(state_dir: &Path, limit: usize) -> EvidenceBackfillStatusReport {
    let journal_path = state_dir.join("evidence-backfill.jsonl");
    let (mut history, mut limitations) = match read_reports(&journal_path) {
        Ok(history) => (history, Vec::new()),
        Err(error) => (Vec::new(), vec![error.to_string()]),
    };
    history.sort_by(|left, right| right.observed_at.cmp(&left.observed_at));
    history.truncate(limit);
    let latest = history.first().cloned();
    let previous = history.get(1);
    let matched_delta = latest.as_ref().zip(previous).map(|(latest, previous)| {
        i64::try_from(latest.matched).unwrap_or(i64::MAX)
            - i64::try_from(previous.matched).unwrap_or(i64::MAX)
    });
    let evidence_gap_delta = latest.as_ref().zip(previous).map(|(latest, previous)| {
        let latest_gap = latest.missing.saturating_add(latest.stale);
        let previous_gap = previous.missing.saturating_add(previous.stale);
        i64::try_from(latest_gap).unwrap_or(i64::MAX)
            - i64::try_from(previous_gap).unwrap_or(i64::MAX)
    });
    if history.is_empty() && journal_path.exists() {
        limitations.push("backfill journal contains no readable reports".to_string());
    }
    EvidenceBackfillStatusReport {
        ok: limitations.is_empty(),
        read_only: true,
        status: if limitations.is_empty() {
            if history.is_empty() { "empty" } else { "ready" }
        } else {
            "limited"
        }
        .to_string(),
        journal_path: display_path(&journal_path),
        latest,
        history,
        matched_delta,
        evidence_gap_delta,
        limitations,
    }
}

fn backfill_actions(
    options: &EvidenceBackfillOptions<'_>,
    resolved: &EvidenceResolveReport,
) -> Vec<EvidenceBackfillAction> {
    resolved
        .entries
        .iter()
        .map(|entry| {
            let profile_matches = options
                .registry
                .backups
                .recovery_profiles
                .iter()
                .filter(|profile| profile.volume == entry.target)
                .count();
            let (action, argv) = if entry.status == "matched" {
                ("none", Vec::new())
            } else if entry.status == "ambiguous" || profile_matches > 1 {
                ("resolve_ambiguity", Vec::new())
            } else if profile_matches == 0 {
                (
                    "onboard_profile",
                    vec![
                        "opsctl".to_string(),
                        "backup".to_string(),
                        "volume-protect".to_string(),
                        "profile-detect".to_string(),
                        "--source-dir".to_string(),
                        format!("<mountpoint-for:{}>", entry.target),
                        "--volume".to_string(),
                        entry.target.clone(),
                    ],
                )
            } else {
                (
                    "protect_volume",
                    vec![
                        "opsctl".to_string(),
                        "backup".to_string(),
                        "volume-protect".to_string(),
                        "plan".to_string(),
                        display_path(options.request_file),
                        "--target".to_string(),
                        entry.target.clone(),
                        "--repository-id".to_string(),
                        options.repository_id.to_string(),
                        "--restore-root".to_string(),
                        display_path(options.restore_root),
                    ],
                )
            };
            EvidenceBackfillAction {
                request_id: entry.request_id.clone(),
                target: entry.target.clone(),
                evidence_status: entry.status.clone(),
                profile_matches,
                action: action.to_string(),
                argv,
                blockers: entry.blockers.clone(),
            }
        })
        .collect()
}

fn append_report(state_dir: &Path, actor: &str, report: &EvidenceBackfillReport) -> Result<()> {
    let path = state_dir.join("evidence-backfill.jsonl");
    evidence_crypto::verify_artifact_before_append(state_dir, &path)?;
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_BACKFILL_JOURNAL_BYTES)
    {
        anyhow::bail!("evidence backfill journal is unsafe or oversized");
    }
    fs::create_dir_all(state_dir)?;
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&path)?;
    writeln!(file, "{}", serde_json::to_string(report)?)?;
    file.sync_data()?;
    evidence_crypto::append_audit_event(
        state_dir,
        "evidence_backfill",
        actor,
        &report.request_file,
        &path,
    )
}

fn read_reports(path: &Path) -> Result<Vec<EvidenceBackfillReport>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_BACKFILL_JOURNAL_BYTES
    {
        anyhow::bail!("evidence backfill journal is unsafe or oversized");
    }
    fs::read_to_string(path)?
        .lines()
        .enumerate()
        .map(|(index, line)| {
            let report: EvidenceBackfillReport = serde_json::from_str(line)
                .with_context(|| format!("invalid evidence backfill line {}", index + 1))?;
            if report.schema_version != BACKFILL_SCHEMA {
                anyhow::bail!("unsupported evidence backfill schema on line {}", index + 1);
            }
            Ok(report)
        })
        .collect()
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_current_backfill_without_writing_cleanup_evidence() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let request_root = tempfile::TempDir::new()?;
        let restore = tempfile::TempDir::new()?;
        let request = request_root.path().join("cleanup.yml");
        fs::write(
            &request,
            r#"schema_version: opsctl.drift_cleanup_request.v1
generated_at: 2026-07-11T00:00:00Z
source_active_findings: 1
source_candidates: 1
items:
  - request_id: cleanup-0001-volume-orphan
    kind: docker-volume
    target: orphan-volume
    code: observed_unregistered_docker_volume
    risk: high
    running: false
    public_bind: false
    data_risk: docker_volume
    observed_status: null
    planned_action: collect evidence
    approval_status: needs_cleanup
    owner: null
    reason: null
    operator_note: null
    cleanup_strategy: null
    exact_resource_id: orphan-volume
    backup_snapshot_id: null
    restore_drill_id: null
    maintenance_window: null
    rollback_plan: null
    approval_expires_at: null
    destructive_command_generated: false
    rationale: backfill fixture
"#,
        )?;
        let registry = Registry::load("examples/server-registry")?;
        let original = fs::read_to_string(&request)?;

        let report = evidence_backfill(&EvidenceBackfillOptions {
            registry: &registry,
            state_dir: state.path(),
            actor: "test",
            request_file: &request,
            repository_id: "restic-r2-main",
            restore_root: restore.path(),
            max_age_hours: 168,
            record: true,
        });

        assert!(!report.read_only);
        assert!(report.status.ends_with("_recorded"));
        assert_eq!(fs::read_to_string(&request)?, original);
        let status = evidence_backfill_status(state.path(), 10);
        assert_eq!(
            status.latest.as_ref().map(|item| item.read_only),
            Some(false)
        );
        Ok(())
    }
}
