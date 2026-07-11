use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{
    drift::read_drift_cleanup_request_document,
    evidence_crypto,
    paths::display_path,
    registry::Registry,
    volume_protect::{
        VolumeProtectOptions, VolumeProtectReport, required_repository_env, volume_protect,
    },
    volume_protect_batch::{
        VolumeProtectBatchItem, VolumeProtectBatchOptions, volume_protect_batch,
    },
    volume_protect_lifecycle::{resume_volume_protect, volume_protect_run_status},
};

const CAMPAIGN_SCHEMA: &str = "opsctl.volume_protect_campaign.v1";
const MAX_CAMPAIGN_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct VolumeProtectCampaignOptions<'a> {
    pub registry: &'a Registry,
    pub request_file: &'a Path,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub repository_id: &'a str,
    pub restore_root: &'a Path,
    pub max_items: usize,
    pub max_total_bytes: u64,
    pub max_volume_bytes: u64,
    pub min_free_bytes: u64,
    pub max_failures: usize,
    pub max_duration_seconds: u64,
    pub min_verification_strength: &'a str,
    pub alert_on_failure: bool,
    pub campaign_id: Option<&'a str>,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectCampaignReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub campaign_id: String,
    pub request_file: String,
    pub repository_id: String,
    pub restore_root: String,
    pub serial_execution: bool,
    pub available_bytes: Option<u64>,
    pub min_free_bytes: u64,
    pub planned_bytes: u64,
    pub max_failures: usize,
    pub max_duration_seconds: u64,
    pub min_verification_strength: String,
    pub evidence_gaps_before: usize,
    pub evidence_gaps_after: usize,
    pub eligible: usize,
    pub skipped: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub remaining: usize,
    pub items: Vec<VolumeProtectBatchItem>,
    pub runs: Vec<VolumeProtectReport>,
    pub journal_path: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectCampaignStatusReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub campaign_id: Option<String>,
    pub campaigns: Vec<VolumeProtectCampaignStatus>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectCampaignAbortReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub campaign_id: String,
    pub prior_stage: Option<String>,
    pub reason: Option<String>,
    pub journal_written: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectCampaignStatus {
    pub campaign_id: String,
    pub stage: String,
    pub resumable: bool,
    pub request_file: String,
    pub repository_id: String,
    pub restore_root: String,
    pub started_at: String,
    pub updated_at: String,
    pub succeeded: usize,
    pub failed: usize,
    pub remaining: usize,
    pub completed_targets: Vec<String>,
    pub failed_runs: BTreeMap<String, String>,
    pub config: VolumeProtectCampaignConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeProtectCampaignConfig {
    #[serde(default)]
    pub planned_items: usize,
    pub max_items: usize,
    pub max_total_bytes: u64,
    pub max_volume_bytes: u64,
    pub min_free_bytes: u64,
    pub max_failures: usize,
    pub max_duration_seconds: u64,
    pub min_verification_strength: String,
    pub alert_on_failure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CampaignEvent {
    schema_version: String,
    campaign_id: String,
    ts: String,
    stage: String,
    actor: String,
    request_file: String,
    repository_id: String,
    restore_root: String,
    target: Option<String>,
    run_id: Option<String>,
    detail: String,
    config: VolumeProtectCampaignConfig,
}

pub fn volume_protect_campaign(
    options: &VolumeProtectCampaignOptions<'_>,
) -> Result<VolumeProtectCampaignReport> {
    let campaign_id = options
        .campaign_id
        .map(str::to_string)
        .unwrap_or_else(new_campaign_id);
    let journal_path = campaign_journal_path(options.state_dir);
    let prior = options.campaign_id.and_then(|id| {
        campaign_status(options.state_dir, Some(id), 1)
            .campaigns
            .into_iter()
            .next()
    });
    if prior
        .as_ref()
        .is_some_and(|status| status.stage == "completed")
    {
        return campaign_completed_report(options, &campaign_id, &journal_path, prior.as_ref());
    }
    let batch = volume_protect_batch(&VolumeProtectBatchOptions {
        registry: options.registry,
        request_file: options.request_file,
        state_dir: options.state_dir,
        actor: options.actor,
        repository_id: options.repository_id,
        restore_root: options.restore_root,
        max_items: options.max_items,
        max_total_bytes: options.max_total_bytes,
        max_volume_bytes: options.max_volume_bytes,
        min_verification_strength: options.min_verification_strength,
        alert_on_failure: options.alert_on_failure,
        execute: false,
    })?;
    let evidence_gaps_before = evidence_gap_count(options.request_file)?;
    let available_bytes =
        existing_ancestor(options.restore_root).and_then(|path| fs2::available_space(path).ok());
    let mut limitations = batch.limitations.clone();
    validate_campaign_inputs(options, &mut limitations);
    if !matches!(
        options.min_verification_strength,
        "feature" | "integrity" | "boot"
    ) {
        limitations
            .push("min_verification_strength must be feature, integrity, or boot".to_string());
    }
    if options.max_failures == 0 {
        limitations.push("max_failures must be at least 1".to_string());
    }
    if options.max_duration_seconds == 0 {
        limitations.push("max_duration_seconds must be at least 1".to_string());
    }
    if available_bytes.is_none() {
        limitations.push("restore root free space could not be determined".to_string());
    } else if available_bytes.is_some_and(|available| {
        available < options.min_free_bytes.saturating_add(batch.planned_bytes)
    }) {
        limitations.push(
            "restore root does not have planned bytes plus the configured free-space reserve"
                .to_string(),
        );
    }
    let completed_targets: BTreeSet<String> = prior
        .as_ref()
        .map(|status| status.completed_targets.iter().cloned().collect())
        .unwrap_or_default();
    let mut report = VolumeProtectCampaignReport {
        ok: limitations.is_empty(),
        read_only: !options.execute,
        status: if limitations.is_empty() {
            "planned"
        } else {
            "blocked"
        }
        .to_string(),
        campaign_id: campaign_id.clone(),
        request_file: display_path(options.request_file),
        repository_id: options.repository_id.to_string(),
        restore_root: display_path(options.restore_root),
        serial_execution: true,
        available_bytes,
        min_free_bytes: options.min_free_bytes,
        planned_bytes: batch.planned_bytes,
        max_failures: options.max_failures,
        max_duration_seconds: options.max_duration_seconds,
        min_verification_strength: options.min_verification_strength.to_string(),
        evidence_gaps_before,
        evidence_gaps_after: evidence_gaps_before,
        eligible: batch.eligible,
        skipped: batch.skipped,
        succeeded: 0,
        failed: 0,
        remaining: batch.eligible,
        items: batch.items,
        runs: Vec::new(),
        journal_path: display_path(&journal_path),
        limitations,
    };
    if !options.execute || !report.limitations.is_empty() {
        return Ok(report);
    }
    let config = campaign_config(options, report.eligible);
    append_campaign_event(
        options.state_dir,
        CampaignEventInput {
            campaign_id: &campaign_id,
            stage: "started",
            actor: options.actor,
            request_file: options.request_file,
            repository_id: options.repository_id,
            restore_root: options.restore_root,
            target: None,
            run_id: None,
            detail: "serial volume protection campaign started",
            config: &config,
        },
    )?;
    let started = Instant::now();
    let prior_failed = prior
        .as_ref()
        .map(|status| status.failed_runs.clone())
        .unwrap_or_default();
    for item in report.items.iter().filter(|item| item.status == "eligible") {
        if completed_targets.contains(&item.target) {
            report.succeeded += 1;
            continue;
        }
        if report.failed >= options.max_failures
            || started.elapsed().as_secs() >= options.max_duration_seconds
        {
            report.status = "paused".to_string();
            break;
        }
        let run = run_campaign_item(options, item, prior_failed.get(&item.target))?;
        let success = run.ok && run.status == "protected";
        append_campaign_event(
            options.state_dir,
            CampaignEventInput {
                campaign_id: &campaign_id,
                stage: if success {
                    "item_succeeded"
                } else {
                    "item_failed"
                },
                actor: options.actor,
                request_file: options.request_file,
                repository_id: options.repository_id,
                restore_root: options.restore_root,
                target: Some(&item.target),
                run_id: Some(&run.run_id),
                detail: if success {
                    "item protection and evidence registration succeeded"
                } else {
                    "item protection failed and remains resumable when a snapshot exists"
                },
                config: &config,
            },
        )?;
        if success {
            report.succeeded += 1;
        } else {
            report.failed += 1;
        }
        report.runs.push(run);
    }
    report.remaining = report
        .eligible
        .saturating_sub(report.succeeded.saturating_add(report.failed));
    report.evidence_gaps_after = evidence_gap_count(options.request_file)?;
    if report.status != "paused" {
        report.status = if report.failed == 0 && report.remaining == 0 {
            "completed"
        } else {
            "paused"
        }
        .to_string();
    }
    report.ok = report.status == "completed";
    append_campaign_event(
        options.state_dir,
        CampaignEventInput {
            campaign_id: &campaign_id,
            stage: &report.status,
            actor: options.actor,
            request_file: options.request_file,
            repository_id: options.repository_id,
            restore_root: options.restore_root,
            target: None,
            run_id: None,
            detail: if report.status == "completed" {
                "campaign completed"
            } else {
                "campaign paused at a configured safety bound"
            },
            config: &config,
        },
    )?;
    Ok(report)
}

pub fn resume_campaign(
    registry: &Registry,
    state_dir: &Path,
    actor: &str,
    campaign_id: &str,
    execute: bool,
) -> Result<VolumeProtectCampaignReport> {
    let status = campaign_status(state_dir, Some(campaign_id), 1);
    let campaign = status
        .campaigns
        .first()
        .with_context(|| format!("volume protect campaign not found: {campaign_id}"))?;
    if campaign.stage == "aborted" {
        anyhow::bail!("volume protect campaign is aborted and cannot be resumed: {campaign_id}");
    }
    let request_file = PathBuf::from(&campaign.request_file);
    let restore_root = PathBuf::from(&campaign.restore_root);
    volume_protect_campaign(&VolumeProtectCampaignOptions {
        registry,
        request_file: &request_file,
        state_dir,
        actor,
        repository_id: &campaign.repository_id,
        restore_root: &restore_root,
        max_items: campaign.config.max_items,
        max_total_bytes: campaign.config.max_total_bytes,
        max_volume_bytes: campaign.config.max_volume_bytes,
        min_free_bytes: campaign.config.min_free_bytes,
        max_failures: campaign.config.max_failures,
        max_duration_seconds: campaign.config.max_duration_seconds,
        min_verification_strength: &campaign.config.min_verification_strength,
        alert_on_failure: campaign.config.alert_on_failure,
        campaign_id: Some(campaign_id),
        execute,
    })
}

pub fn abort_campaign(
    state_dir: &Path,
    actor: &str,
    campaign_id: &str,
    reason: Option<&str>,
    execute: bool,
) -> VolumeProtectCampaignAbortReport {
    let status = campaign_status(state_dir, Some(campaign_id), 1);
    let campaign = status.campaigns.first();
    let mut limitations = status.limitations;
    if campaign.is_none() {
        limitations.push(format!("volume protect campaign not found: {campaign_id}"));
    }
    if campaign.is_some_and(|campaign| campaign.stage == "completed") {
        limitations.push("completed campaign cannot be aborted".to_string());
    }
    if execute && reason.is_none_or(str::is_empty) {
        limitations.push("reason is required when aborting a campaign".to_string());
    }
    if reason.is_some_and(|value| value.len() > 512 || value.contains(['\n', '\r'])) {
        limitations.push("abort reason must be at most 512 characters on one line".to_string());
    }
    let already_aborted = campaign.is_some_and(|campaign| campaign.stage == "aborted");
    let mut journal_written = false;
    if execute
        && limitations.is_empty()
        && !already_aborted
        && let Some(campaign) = campaign
    {
        let request_file = PathBuf::from(&campaign.request_file);
        let restore_root = PathBuf::from(&campaign.restore_root);
        match append_campaign_event(
            state_dir,
            CampaignEventInput {
                campaign_id,
                stage: "aborted",
                actor,
                request_file: &request_file,
                repository_id: &campaign.repository_id,
                restore_root: &restore_root,
                target: None,
                run_id: None,
                detail: reason.unwrap_or("campaign aborted by operator"),
                config: &campaign.config,
            },
        ) {
            Ok(()) => journal_written = true,
            Err(error) => limitations.push(error.to_string()),
        }
    }
    VolumeProtectCampaignAbortReport {
        ok: limitations.is_empty(),
        read_only: !execute,
        status: if !limitations.is_empty() {
            "blocked"
        } else if execute || already_aborted {
            "aborted"
        } else {
            "ready_to_abort"
        }
        .to_string(),
        campaign_id: campaign_id.to_string(),
        prior_stage: campaign.map(|campaign| campaign.stage.clone()),
        reason: reason.map(str::to_string),
        journal_written,
        limitations,
    }
}

pub fn campaign_status(
    state_dir: &Path,
    campaign_id: Option<&str>,
    limit: usize,
) -> VolumeProtectCampaignStatusReport {
    let (events, limitations) = read_campaign_events(state_dir);
    let mut grouped = BTreeMap::<String, Vec<CampaignEvent>>::new();
    for event in events {
        if campaign_id.is_none_or(|expected| event.campaign_id == expected) {
            grouped
                .entry(event.campaign_id.clone())
                .or_default()
                .push(event);
        }
    }
    let mut campaigns = grouped
        .into_values()
        .filter_map(campaign_status_from_events)
        .collect::<Vec<_>>();
    campaigns.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    campaigns.truncate(limit);
    let found = campaign_id.is_none() || !campaigns.is_empty();
    VolumeProtectCampaignStatusReport {
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
        campaign_id: campaign_id.map(str::to_string),
        campaigns,
        limitations,
    }
}

fn run_campaign_item(
    options: &VolumeProtectCampaignOptions<'_>,
    item: &VolumeProtectBatchItem,
    failed_run_id: Option<&String>,
) -> Result<VolumeProtectReport> {
    if let Some(run_id) = failed_run_id {
        let run_status = volume_protect_run_status(options.state_dir, Some(run_id), 1);
        if run_status
            .runs
            .first()
            .is_some_and(|status| status.resumable)
        {
            return resume_volume_protect(
                options.registry,
                options.state_dir,
                options.actor,
                run_id,
                true,
                options.alert_on_failure,
            );
        }
    }
    volume_protect(&VolumeProtectOptions {
        registry: options.registry,
        request_file: options.request_file,
        state_dir: options.state_dir,
        actor: options.actor,
        target: &item.target,
        repository_id: options.repository_id,
        restore_root: options.restore_root,
        run_id: None,
        resume_snapshot_id: None,
        min_verification_strength: options.min_verification_strength,
        alert_on_failure: options.alert_on_failure,
        execute: true,
    })
}

fn campaign_status_from_events(
    mut events: Vec<CampaignEvent>,
) -> Option<VolumeProtectCampaignStatus> {
    events.sort_by(|left, right| left.ts.cmp(&right.ts));
    let first = events.first()?;
    let last = events.last()?;
    let mut completed = BTreeSet::new();
    let mut failed_runs = BTreeMap::new();
    for event in &events {
        let Some(target) = event.target.as_ref() else {
            continue;
        };
        if event.stage == "item_succeeded" {
            completed.insert(target.clone());
            failed_runs.remove(target);
        } else if event.stage == "item_failed"
            && let Some(run_id) = &event.run_id
        {
            failed_runs.insert(target.clone(), run_id.clone());
        }
    }
    let eligible = if first.config.planned_items == 0 {
        first.config.max_items
    } else {
        first.config.planned_items
    };
    let succeeded = completed.len();
    let failed = failed_runs.len();
    Some(VolumeProtectCampaignStatus {
        campaign_id: last.campaign_id.clone(),
        stage: last.stage.clone(),
        resumable: !matches!(last.stage.as_str(), "completed" | "aborted"),
        request_file: first.request_file.clone(),
        repository_id: first.repository_id.clone(),
        restore_root: first.restore_root.clone(),
        started_at: first.ts.clone(),
        updated_at: last.ts.clone(),
        succeeded,
        failed,
        remaining: eligible.saturating_sub(succeeded.saturating_add(failed)),
        completed_targets: completed.into_iter().collect(),
        failed_runs,
        config: first.config.clone(),
    })
}

fn campaign_completed_report(
    options: &VolumeProtectCampaignOptions<'_>,
    campaign_id: &str,
    journal_path: &Path,
    prior: Option<&VolumeProtectCampaignStatus>,
) -> Result<VolumeProtectCampaignReport> {
    let gaps = evidence_gap_count(options.request_file)?;
    Ok(VolumeProtectCampaignReport {
        ok: true,
        read_only: !options.execute,
        status: "completed".to_string(),
        campaign_id: campaign_id.to_string(),
        request_file: display_path(options.request_file),
        repository_id: options.repository_id.to_string(),
        restore_root: display_path(options.restore_root),
        serial_execution: true,
        available_bytes: existing_ancestor(options.restore_root)
            .and_then(|path| fs2::available_space(path).ok()),
        min_free_bytes: options.min_free_bytes,
        planned_bytes: 0,
        max_failures: options.max_failures,
        max_duration_seconds: options.max_duration_seconds,
        min_verification_strength: options.min_verification_strength.to_string(),
        evidence_gaps_before: gaps,
        evidence_gaps_after: gaps,
        eligible: prior.map_or(0, |status| status.succeeded),
        skipped: 0,
        succeeded: prior.map_or(0, |status| status.succeeded),
        failed: 0,
        remaining: 0,
        items: Vec::new(),
        runs: Vec::new(),
        journal_path: display_path(journal_path),
        limitations: Vec::new(),
    })
}

fn evidence_gap_count(request_file: &Path) -> Result<usize> {
    Ok(read_drift_cleanup_request_document(request_file)?
        .items
        .iter()
        .filter(|item| {
            item.kind == "docker-volume"
                && (item.backup_snapshot_id.as_deref().is_none_or(str::is_empty)
                    || item.restore_drill_id.as_deref().is_none_or(str::is_empty))
        })
        .count())
}

fn validate_campaign_inputs(
    options: &VolumeProtectCampaignOptions<'_>,
    limitations: &mut Vec<String>,
) {
    if !options.restore_root.is_absolute() || options.restore_root == Path::new("/") {
        limitations.push("restore_root must be an absolute non-root directory".to_string());
    }
    let Some(repository) = options
        .registry
        .backups
        .repositories
        .iter()
        .find(|repository| repository.id == options.repository_id)
    else {
        limitations.push("campaign repository is not registered".to_string());
        return;
    };
    if repository.status != "active" {
        limitations.push("campaign repository is not active".to_string());
    }
    if !matches!(repository.provider.as_str(), "restic" | "rustic") {
        limitations.push("campaign repository must use Restic or rustic".to_string());
    }
    let missing_env = required_repository_env(repository)
        .into_iter()
        .filter(|name| std::env::var_os(name).is_none())
        .collect::<Vec<_>>();
    if !missing_env.is_empty() {
        limitations.push(format!(
            "campaign repository environment is missing: {}",
            missing_env.join(", ")
        ));
    }
}

fn existing_ancestor(path: &Path) -> Option<&Path> {
    path.ancestors().find(|candidate| candidate.exists())
}

fn campaign_config(
    options: &VolumeProtectCampaignOptions<'_>,
    planned_items: usize,
) -> VolumeProtectCampaignConfig {
    VolumeProtectCampaignConfig {
        planned_items,
        max_items: options.max_items,
        max_total_bytes: options.max_total_bytes,
        max_volume_bytes: options.max_volume_bytes,
        min_free_bytes: options.min_free_bytes,
        max_failures: options.max_failures,
        max_duration_seconds: options.max_duration_seconds,
        min_verification_strength: options.min_verification_strength.to_string(),
        alert_on_failure: options.alert_on_failure,
    }
}

struct CampaignEventInput<'a> {
    campaign_id: &'a str,
    stage: &'a str,
    actor: &'a str,
    request_file: &'a Path,
    repository_id: &'a str,
    restore_root: &'a Path,
    target: Option<&'a str>,
    run_id: Option<&'a str>,
    detail: &'a str,
    config: &'a VolumeProtectCampaignConfig,
}

fn append_campaign_event(state_dir: &Path, input: CampaignEventInput<'_>) -> Result<()> {
    let path = campaign_journal_path(state_dir);
    evidence_crypto::verify_artifact_before_append(state_dir, &path)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_CAMPAIGN_JOURNAL_BYTES)
    {
        anyhow::bail!(
            "refusing unsafe or oversized campaign journal: {}",
            path.display()
        );
    }
    let event = CampaignEvent {
        schema_version: CAMPAIGN_SCHEMA.to_string(),
        campaign_id: input.campaign_id.to_string(),
        ts: timestamp(),
        stage: input.stage.to_string(),
        actor: input.actor.to_string(),
        request_file: display_path(input.request_file),
        repository_id: input.repository_id.to_string(),
        restore_root: display_path(input.restore_root),
        target: input.target.map(str::to_string),
        run_id: input.run_id.map(str::to_string),
        detail: input.detail.to_string(),
        config: input.config.clone(),
    };
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&path)?;
    writeln!(file, "{}", serde_json::to_string(&event)?)?;
    file.sync_data()?;
    evidence_crypto::append_audit_event(
        state_dir,
        "volume_protect_campaign",
        input.actor,
        input.campaign_id,
        &path,
    )?;
    Ok(())
}

fn read_campaign_events(state_dir: &Path) -> (Vec<CampaignEvent>, Vec<String>) {
    let path = campaign_journal_path(state_dir);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (Vec::new(), Vec::new());
        }
        Err(error) => return (Vec::new(), vec![error.to_string()]),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_CAMPAIGN_JOURNAL_BYTES
    {
        return (
            Vec::new(),
            vec!["campaign journal is unsafe or too large".to_string()],
        );
    }
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => return (Vec::new(), vec![error.to_string()]),
    };
    let mut events = Vec::new();
    let mut limitations = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        match serde_json::from_str::<CampaignEvent>(line) {
            Ok(event) if event.schema_version == CAMPAIGN_SCHEMA => events.push(event),
            Ok(_) => limitations.push(format!(
                "campaign journal line {} has unsupported schema",
                index + 1
            )),
            Err(error) => limitations.push(format!(
                "campaign journal line {} is invalid: {error}",
                index + 1
            )),
        }
    }
    (events, limitations)
}

pub(crate) fn campaign_journal_path(state_dir: &Path) -> PathBuf {
    state_dir.join("volume-protect-campaigns.jsonl")
}

fn new_campaign_id() -> String {
    format!(
        "vpc-{}-{}",
        OffsetDateTime::now_utc().unix_timestamp(),
        std::process::id()
    )
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
    fn campaign_status_tracks_success_and_failed_run() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let config = VolumeProtectCampaignConfig {
            planned_items: 3,
            max_items: 3,
            max_total_bytes: 100,
            max_volume_bytes: 100,
            min_free_bytes: 0,
            max_failures: 1,
            max_duration_seconds: 60,
            min_verification_strength: "integrity".to_string(),
            alert_on_failure: false,
        };
        for (stage, target, run_id) in [
            ("started", None, None),
            ("item_succeeded", Some("one"), Some("run-one")),
            ("item_failed", Some("two"), Some("run-two")),
            ("paused", None, None),
        ] {
            append_campaign_event(
                state.path(),
                CampaignEventInput {
                    campaign_id: "campaign-test",
                    stage,
                    actor: "test",
                    request_file: Path::new("/tmp/request.yml"),
                    repository_id: "repository",
                    restore_root: Path::new("/tmp/restores"),
                    target,
                    run_id,
                    detail: "test",
                    config: &config,
                },
            )?;
        }

        let report = campaign_status(state.path(), Some("campaign-test"), 1);

        assert!(report.ok);
        assert_eq!(report.campaigns[0].stage, "paused");
        assert_eq!(report.campaigns[0].succeeded, 1);
        assert_eq!(report.campaigns[0].failed, 1);
        assert_eq!(report.campaigns[0].remaining, 1);
        assert_eq!(report.campaigns[0].failed_runs["two"], "run-two");
        let aborted = abort_campaign(
            state.path(),
            "test",
            "campaign-test",
            Some("operator stopped fixture campaign"),
            true,
        );
        assert!(aborted.ok);
        assert_eq!(aborted.status, "aborted");
        assert!(aborted.journal_written);
        let final_status = campaign_status(state.path(), Some("campaign-test"), 1);
        assert_eq!(final_status.campaigns[0].stage, "aborted");
        assert!(!final_status.campaigns[0].resumable);
        Ok(())
    }
}
