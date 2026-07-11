use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process,
    time::{Duration as StdDuration, SystemTime},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{
    backup::{BackupPlanOptions, plan_backup},
    command_runner, env_source,
    importer::{RegistryPromoteImportOptions, check_registry_import, promote_registry_import},
    paths::display_path,
    redact::redact_value,
    registry::{
        BackupRepository, BackupTarget, PoliciesRegistry, Registry, Service, TimerAlertPolicy,
    },
};

const DEFAULT_TRUST_MAX_AGE_HOURS: u32 = 168;
const DRILL_RUN_PREFIX: &str = "run-";
const RESTORE_DRILLS_DIR: &str = "restore-drills";
const ALERT_DELIVERY_MAX_ATTEMPTS: u32 = 3;
const OPERATIONAL_ALERT_COOLDOWN_SECONDS: i64 = 900;
const MAX_OPERATIONAL_ALERT_STATE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct DrillCleanupOptions<'a> {
    pub state_dir: &'a Path,
    pub keep_days: u32,
    pub keep_count: usize,
    pub execute: bool,
}

#[derive(Debug, Serialize)]
pub struct DrillCleanupReport {
    pub ok: bool,
    pub execute: bool,
    pub root: String,
    pub keep_days: u32,
    pub keep_count: usize,
    pub services: usize,
    pub retained: usize,
    pub candidates: usize,
    pub deleted: usize,
    pub failed: usize,
    pub entries: Vec<DrillCleanupEntry>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DrillCleanupEntry {
    pub service_id: String,
    pub path: String,
    pub modified_at_unix: Option<u64>,
    pub age_days: Option<u64>,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct BackupTimerOptions<'a> {
    pub registry: &'a Registry,
    pub service_id: Option<&'a str>,
    pub repository_id: Option<&'a str>,
    pub execute: bool,
    pub include_status: bool,
}

#[derive(Debug, Serialize)]
pub struct BackupTimerReport {
    pub ok: bool,
    pub execute: bool,
    pub read_only: bool,
    pub entries: Vec<BackupTimerEntry>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerEntry {
    pub kind: String,
    pub id: String,
    pub timer_unit: String,
    pub service_unit: String,
    pub command: String,
    pub schedule: String,
    pub enabled: Option<String>,
    pub active: Option<String>,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct BackupTimerMonitorOptions<'a> {
    pub registry: &'a Registry,
    pub service_id: Option<&'a str>,
    pub repository_id: Option<&'a str>,
    pub include_journal: bool,
}

#[derive(Debug, Clone)]
pub struct BackupTimerAlertOptions<'a> {
    pub registry: &'a Registry,
    pub service_id: Option<&'a str>,
    pub repository_id: Option<&'a str>,
    pub include_journal: bool,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct BackupTimerAlertTestOptions<'a> {
    pub registry: &'a Registry,
    pub sink_id: Option<&'a str>,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct BackupTimerAlertStatusOptions<'a> {
    pub registry: &'a Registry,
    pub sink_id: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct BackupTimerAlertEnablePlanOptions<'a> {
    pub registry: &'a Registry,
    pub id: Option<&'a str>,
    pub provider: Option<&'a str>,
    pub target_env: Option<&'a str>,
    pub owner: Option<&'a str>,
    pub min_severity: Option<&'a str>,
    pub topic: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct BackupTimerAlertConfigureOptions<'a> {
    pub registry_dir: &'a Path,
    pub id: &'a str,
    pub provider: &'a str,
    pub target_env: &'a str,
    pub owner: &'a str,
    pub status: &'a str,
    pub min_severity: Option<&'a str>,
    pub topic: Option<&'a str>,
    pub notes: Option<&'a str>,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct BackupTimerAlertEnvTemplateOptions<'a> {
    pub registry: &'a Registry,
    pub id: Option<&'a str>,
    pub provider: Option<&'a str>,
    pub target_env: Option<&'a str>,
    pub env_file: Option<&'a Path>,
}

#[derive(Debug, Serialize)]
pub struct BackupTimerMonitorReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub entries: Vec<BackupTimerMonitorEntry>,
    pub health: BackupTimerHealthReport,
    pub alert_candidates: Vec<BackupTimerAlertCandidate>,
    pub alert_sinks: Vec<BackupTimerAlertSink>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerMonitorEntry {
    pub kind: String,
    pub id: String,
    pub timer_unit: String,
    pub service_unit: String,
    pub timer_enabled: String,
    pub timer_active: String,
    pub service_active: String,
    pub service_result: String,
    pub exec_main_status: Option<i32>,
    pub active_enter_timestamp: Option<String>,
    pub inactive_exit_timestamp: Option<String>,
    pub recent_status: String,
    pub consecutive_failures: usize,
    pub journal_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerHealthReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub max_consecutive_failures: u32,
    pub block_deploy_on_failure: bool,
    pub services_checked: usize,
    pub services_ready: usize,
    pub services_blocked: usize,
    pub services: Vec<BackupTimerHealthService>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerHealthService {
    pub service_id: String,
    pub status: String,
    pub consecutive_failures: usize,
    pub backup_run_consecutive_failures: usize,
    pub repository_check_consecutive_failures: usize,
    pub restore_drill_consecutive_failures: usize,
    pub blocked_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerAlertCandidate {
    pub severity: String,
    pub kind: String,
    pub id: String,
    pub reason: String,
    pub configured_alerts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerAlertSink {
    pub id: String,
    pub provider: String,
    pub status: String,
    pub owner: String,
    pub configured: bool,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct BackupTimerAlertReport {
    pub ok: bool,
    pub execute: bool,
    pub read_only: bool,
    pub status: String,
    pub candidate_count: usize,
    pub delivery_count: usize,
    pub monitor: BackupTimerMonitorReport,
    pub deliveries: Vec<BackupTimerAlertDelivery>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BackupTimerAlertTestReport {
    pub ok: bool,
    pub execute: bool,
    pub read_only: bool,
    pub status: String,
    pub sink_filter: Option<String>,
    pub delivery_count: usize,
    pub deliveries: Vec<BackupTimerAlertDelivery>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BackupTimerAlertStatusReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub sink_filter: Option<String>,
    pub total_sinks: usize,
    pub active_sinks: usize,
    pub disabled_sinks: usize,
    pub configured_sinks: usize,
    pub missing_target_env: usize,
    pub missing_env_value: usize,
    pub sinks: Vec<BackupTimerAlertStatusSink>,
    pub activation_plan: Vec<BackupTimerAlertActivationStep>,
    pub next_actions: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BackupTimerAlertEnablePlanReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub existing_status: BackupTimerAlertStatusReport,
    pub requested_sink: TimerAlertPolicy,
    pub target_env_present: bool,
    pub target_env_source: Option<String>,
    pub secret_handling: String,
    pub steps: Vec<BackupTimerAlertEnableStep>,
    pub retry_policy: BackupTimerAlertRetryPolicy,
    pub escalation_policy: BackupTimerAlertEscalationPolicy,
    pub alert_template: BackupTimerAlertTemplate,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerAlertEnableStep {
    pub order: u32,
    pub action: String,
    pub command: Option<String>,
    pub required_env: Option<String>,
    pub env_present: Option<bool>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerAlertRetryPolicy {
    pub delivery_attempts: u32,
    pub retry_backoff_seconds: Vec<u32>,
    pub planned: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerAlertEscalationPolicy {
    pub consecutive_failures_before_deploy_block: u32,
    pub deploy_block_enabled: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerAlertTemplate {
    pub subject: String,
    pub body_fields: Vec<String>,
    pub json_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerAlertStatusSink {
    pub id: String,
    pub provider: String,
    pub status: String,
    pub owner: String,
    pub target_env: Option<String>,
    pub target_env_present: bool,
    pub target_env_source: Option<String>,
    pub configured: bool,
    pub min_severity: Option<String>,
    pub topic_configured: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerAlertActivationStep {
    pub sink_id: String,
    pub provider: String,
    pub status: String,
    pub required_env: Option<String>,
    pub env_present: bool,
    pub planned_command: String,
    pub test_command: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTimerAlertDelivery {
    pub sink_id: String,
    pub provider: String,
    pub status: String,
    pub detail: String,
    pub candidate_count: usize,
    pub attempts: u32,
}

#[derive(Debug, Serialize)]
pub struct BackupTimerAlertConfigureReport {
    pub ok: bool,
    pub execute: bool,
    pub read_only: bool,
    pub status: String,
    pub action: String,
    pub sink: TimerAlertPolicy,
    pub target_env_present: bool,
    pub target_env_source: Option<String>,
    pub changed_files: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BackupTimerAlertEnvTemplateReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub env_file: String,
    pub sink_id: String,
    pub provider: String,
    pub target_env: String,
    pub target_env_present: bool,
    pub target_env_source: Option<String>,
    pub template_lines: Vec<String>,
    pub install_commands: Vec<String>,
    pub next_commands: Vec<String>,
    pub secret_handling: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProductionOnboardingOptions<'a> {
    pub registry: &'a Registry,
    pub registry_dir: &'a Path,
    pub state_dir: &'a Path,
    pub import_dir: Option<&'a Path>,
}

#[derive(Debug, Serialize)]
pub struct ProductionOnboardingReport {
    pub ok: bool,
    pub read_only: bool,
    pub registry_dir: String,
    pub import_dir: Option<String>,
    pub services_checked: usize,
    pub services_ready: usize,
    pub services_blocked: usize,
    pub repositories_checked: usize,
    pub backup_history_status: String,
    pub import_check_status: Option<String>,
    pub promote_dry_run_status: Option<String>,
    pub services: Vec<ProductionOnboardingService>,
    pub repositories: Vec<ProductionOnboardingRepository>,
    pub planned_commands: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProductionOnboardingService {
    pub service_id: String,
    pub backup_plan_status: String,
    pub backup_history_status: String,
    pub missing_env: Vec<String>,
    pub commands: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProductionOnboardingRepository {
    pub repository_id: String,
    pub provider: String,
    pub command: String,
}

struct OnboardingHistoryStatus {
    status: String,
    service_status: BTreeMap<String, String>,
    service_limitations: BTreeMap<String, Vec<String>>,
}

pub fn cleanup_restore_drills(options: &DrillCleanupOptions<'_>) -> DrillCleanupReport {
    let root = options.state_dir.join(RESTORE_DRILLS_DIR);
    let mut limitations = Vec::new();
    let mut entries = Vec::new();
    if let Err(error) = validate_cleanup_root(&root) {
        limitations.push(error.to_string());
        return DrillCleanupReport {
            ok: false,
            execute: options.execute,
            root: display_path(&root),
            keep_days: options.keep_days,
            keep_count: options.keep_count,
            services: 0,
            retained: 0,
            candidates: 0,
            deleted: 0,
            failed: 0,
            entries,
            limitations,
        };
    }
    if !root.exists() {
        return DrillCleanupReport {
            ok: true,
            execute: options.execute,
            root: display_path(&root),
            keep_days: options.keep_days,
            keep_count: options.keep_count,
            services: 0,
            retained: 0,
            candidates: 0,
            deleted: 0,
            failed: 0,
            entries,
            limitations,
        };
    }

    let now = SystemTime::now();
    let cutoff = now
        .checked_sub(StdDuration::from_secs(
            u64::from(options.keep_days) * 24 * 60 * 60,
        ))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut services = 0usize;
    match fs::read_dir(&root) {
        Ok(service_dirs) => {
            for service_entry in service_dirs.flatten() {
                let service_path = service_entry.path();
                let service_id = service_entry.file_name().to_string_lossy().into_owned();
                let Ok(metadata) = fs::symlink_metadata(&service_path) else {
                    continue;
                };
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    continue;
                }
                services += 1;
                append_service_cleanup_entries(&mut CleanupAppendContext {
                    root: &root,
                    service_id: &service_id,
                    service_path: &service_path,
                    options,
                    cutoff,
                    now,
                    entries: &mut entries,
                    limitations: &mut limitations,
                });
            }
        }
        Err(error) => limitations.push(format!("failed to read {}: {error}", root.display())),
    }

    let retained = entries
        .iter()
        .filter(|entry| entry.status == "retained")
        .count();
    let candidates = entries
        .iter()
        .filter(|entry| entry.status == "delete_candidate")
        .count();
    let deleted = entries
        .iter()
        .filter(|entry| entry.status == "deleted")
        .count();
    let failed = entries
        .iter()
        .filter(|entry| entry.status == "failed")
        .count();

    DrillCleanupReport {
        ok: failed == 0 && limitations.is_empty(),
        execute: options.execute,
        root: display_path(&root),
        keep_days: options.keep_days,
        keep_count: options.keep_count,
        services,
        retained,
        candidates,
        deleted,
        failed,
        entries,
        limitations,
    }
}

struct CleanupAppendContext<'a> {
    root: &'a Path,
    service_id: &'a str,
    service_path: &'a Path,
    options: &'a DrillCleanupOptions<'a>,
    cutoff: SystemTime,
    now: SystemTime,
    entries: &'a mut Vec<DrillCleanupEntry>,
    limitations: &'a mut Vec<String>,
}

fn append_service_cleanup_entries(context: &mut CleanupAppendContext<'_>) {
    let mut runs = match restore_drill_runs(context.service_path) {
        Ok(runs) => runs,
        Err(error) => {
            context.limitations.push(error.to_string());
            return;
        }
    };
    runs.sort_by_key(|run| std::cmp::Reverse(run.modified));
    for (index, run) in runs.into_iter().enumerate() {
        let age_days = context
            .now
            .duration_since(run.modified)
            .ok()
            .map(|duration| duration.as_secs() / (24 * 60 * 60));
        let modified_at_unix = run
            .modified
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs());
        let protected_by_count = index < context.options.keep_count;
        let protected_by_age = context.options.keep_days > 0 && run.modified >= context.cutoff;
        if protected_by_count || protected_by_age {
            context.entries.push(DrillCleanupEntry {
                service_id: context.service_id.to_string(),
                path: display_path(&run.path),
                modified_at_unix,
                age_days,
                status: "retained".to_string(),
                reason: if protected_by_count {
                    "within keep_count newest runs".to_string()
                } else {
                    "within keep_days window".to_string()
                },
            });
            continue;
        }

        if context.options.execute {
            match safe_remove_run_dir(context.root, &run.path) {
                Ok(()) => context.entries.push(DrillCleanupEntry {
                    service_id: context.service_id.to_string(),
                    path: display_path(&run.path),
                    modified_at_unix,
                    age_days,
                    status: "deleted".to_string(),
                    reason: "older than keep_days and beyond keep_count".to_string(),
                }),
                Err(error) => context.entries.push(DrillCleanupEntry {
                    service_id: context.service_id.to_string(),
                    path: display_path(&run.path),
                    modified_at_unix,
                    age_days,
                    status: "failed".to_string(),
                    reason: error.to_string(),
                }),
            }
        } else {
            context.entries.push(DrillCleanupEntry {
                service_id: context.service_id.to_string(),
                path: display_path(&run.path),
                modified_at_unix,
                age_days,
                status: "delete_candidate".to_string(),
                reason: "older than keep_days and beyond keep_count".to_string(),
            });
        }
    }
}

#[derive(Debug)]
struct RunDir {
    path: PathBuf,
    modified: SystemTime,
}

fn restore_drill_runs(service_path: &Path) -> Result<Vec<RunDir>> {
    let mut runs = Vec::new();
    for entry in fs::read_dir(service_path)
        .with_context(|| format!("failed to read {}", service_path.display()))?
    {
        let entry = entry.context("failed to read restore drill run entry")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(DRILL_RUN_PREFIX) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        runs.push(RunDir { path, modified });
    }
    Ok(runs)
}

fn validate_cleanup_root(root: &Path) -> Result<()> {
    if !root.is_absolute() {
        anyhow::bail!(
            "restore drill cleanup root must be absolute: {}",
            root.display()
        );
    }
    if root.exists() {
        let metadata = fs::symlink_metadata(root)
            .with_context(|| format!("failed to inspect {}", root.display()))?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "refusing restore drill cleanup root symlink: {}",
                root.display()
            );
        }
        if !metadata.is_dir() {
            anyhow::bail!(
                "restore drill cleanup root is not a directory: {}",
                root.display()
            );
        }
    }
    Ok(())
}

fn safe_remove_run_dir(root: &Path, path: &Path) -> Result<()> {
    if !path.starts_with(root) {
        anyhow::bail!(
            "refusing to delete path outside cleanup root: {}",
            path.display()
        );
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !name.starts_with(DRILL_RUN_PREFIX) {
        anyhow::bail!(
            "refusing to delete non-run restore drill directory: {}",
            path.display()
        );
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "refusing to delete non-directory or symlink: {}",
            path.display()
        );
    }
    fs::remove_dir_all(path).with_context(|| format!("failed to delete {}", path.display()))?;
    Ok(())
}

pub fn backup_timer_plan(options: &BackupTimerOptions<'_>) -> BackupTimerReport {
    backup_timer_report(options, false, false)
}

pub fn backup_timer_install(options: &BackupTimerOptions<'_>) -> BackupTimerReport {
    backup_timer_report(options, options.execute, false)
}

pub fn backup_timer_status(options: &BackupTimerOptions<'_>) -> BackupTimerReport {
    backup_timer_report(options, false, true)
}

pub fn backup_timer_monitor(options: &BackupTimerMonitorOptions<'_>) -> BackupTimerMonitorReport {
    let planned =
        planned_timer_entries(options.registry, options.service_id, options.repository_id);
    let health = timer_health(options.registry);
    let health_by_service = health
        .services
        .iter()
        .map(|service| (service.service_id.as_str(), service))
        .collect::<BTreeMap<_, _>>();
    let mut limitations = Vec::new();
    if planned.is_empty() {
        limitations.push("no timer entries match the registry and filters".to_string());
    }
    let journal_lines = options.registry.policies.timer_health.journal_error_lines;
    let entries = planned
        .into_iter()
        .map(|entry| {
            monitor_timer_entry(
                options.registry,
                &health_by_service,
                entry,
                options.include_journal,
                journal_lines,
            )
        })
        .collect::<Vec<_>>();
    let alert_sinks = timer_alert_sinks(options.registry);
    let alert_candidates = timer_alert_candidates(&entries, &health, &alert_sinks);
    let failed_entries = entries
        .iter()
        .filter(|entry| entry.recent_status == "failed")
        .count();
    let status = if health.status == "blocked" || failed_entries > 0 {
        "blocked"
    } else if limitations.is_empty() {
        "ready"
    } else {
        "blocked"
    }
    .to_string();

    BackupTimerMonitorReport {
        ok: status == "ready",
        read_only: true,
        status,
        entries,
        health,
        alert_candidates,
        alert_sinks,
        limitations,
    }
}

pub fn backup_timer_alert(options: &BackupTimerAlertOptions<'_>) -> BackupTimerAlertReport {
    let monitor = backup_timer_monitor(&BackupTimerMonitorOptions {
        registry: options.registry,
        service_id: options.service_id,
        repository_id: options.repository_id,
        include_journal: options.include_journal,
    });
    let candidates = monitor.alert_candidates.clone();
    let candidate_count = candidates.len();
    let alert_body = timer_alert_text(&monitor);
    let alert_json = timer_alert_json(&monitor);
    let mut deliveries = Vec::new();
    let mut limitations = Vec::new();
    if candidate_count > 0 {
        let matching_policies = options
            .registry
            .policies
            .timer_alerts
            .iter()
            .filter(|policy| {
                policy.status == "active" && operational_policy_matches(policy, "error")
            })
            .filter(|policy| {
                candidates
                    .iter()
                    .any(|candidate| candidate_matches_policy(candidate, policy))
            })
            .collect::<Vec<_>>();
        if matching_policies.is_empty() {
            limitations.push(
                "alert candidates exist but no active configured alert sink matches their severity"
                    .to_string(),
            );
        }
        for policy in matching_policies {
            deliveries.push(timer_alert_delivery(
                policy,
                &alert_body,
                &alert_json,
                candidate_count,
                options.execute,
            ));
        }
    }
    for delivery in &deliveries {
        if matches!(delivery.status.as_str(), "failed" | "blocked") {
            limitations.push(format!(
                "alert sink {} delivery {}",
                delivery.sink_id, delivery.status
            ));
        }
    }
    limitations.sort();
    limitations.dedup();
    let failed = deliveries
        .iter()
        .any(|delivery| matches!(delivery.status.as_str(), "failed" | "blocked"));
    let status = if candidate_count == 0 {
        "no_candidates"
    } else if failed || !limitations.is_empty() {
        "blocked"
    } else if options.execute {
        "sent"
    } else {
        "planned"
    }
    .to_string();

    BackupTimerAlertReport {
        ok: status == "no_candidates" || status == "planned" || status == "sent",
        execute: options.execute,
        read_only: !options.execute,
        status,
        candidate_count,
        delivery_count: deliveries.len(),
        monitor,
        deliveries,
        limitations,
    }
}

pub fn backup_timer_alert_test(
    options: &BackupTimerAlertTestOptions<'_>,
) -> BackupTimerAlertTestReport {
    let mut limitations = Vec::new();
    let policies = options
        .registry
        .policies
        .timer_alerts
        .iter()
        .filter(|policy| policy.status == "active" && operational_policy_matches(policy, "error"))
        .filter(|policy| options.sink_id.is_none_or(|sink_id| policy.id == sink_id))
        .collect::<Vec<_>>();
    if policies.is_empty() {
        limitations.push(match options.sink_id {
            Some(sink_id) => format!("no active alert sink matches id {sink_id}"),
            None => "no active alert sinks are configured".to_string(),
        });
    }
    let body = timer_alert_test_text();
    let payload = timer_alert_test_json();
    let deliveries = policies
        .into_iter()
        .map(|policy| timer_alert_delivery(policy, &body, &payload, 1, options.execute))
        .collect::<Vec<_>>();
    for delivery in &deliveries {
        if matches!(delivery.status.as_str(), "failed" | "blocked") {
            limitations.push(format!(
                "alert sink {} delivery {}",
                delivery.sink_id, delivery.status
            ));
        }
    }
    limitations.sort();
    limitations.dedup();
    let failed = deliveries
        .iter()
        .any(|delivery| matches!(delivery.status.as_str(), "failed" | "blocked"));
    let status = if failed || !limitations.is_empty() {
        "blocked"
    } else if options.execute {
        "sent"
    } else {
        "planned"
    }
    .to_string();
    BackupTimerAlertTestReport {
        ok: status == "planned" || status == "sent",
        execute: options.execute,
        read_only: !options.execute,
        status,
        sink_filter: options.sink_id.map(str::to_string),
        delivery_count: deliveries.len(),
        deliveries,
        limitations,
    }
}

pub fn backup_timer_alert_status(
    options: &BackupTimerAlertStatusOptions<'_>,
) -> BackupTimerAlertStatusReport {
    let mut limitations = Vec::new();
    let sinks = options
        .registry
        .policies
        .timer_alerts
        .iter()
        .filter(|policy| options.sink_id.is_none_or(|sink_id| policy.id == sink_id))
        .map(timer_alert_status_sink)
        .collect::<Vec<_>>();

    if sinks.is_empty() {
        limitations.push(match options.sink_id {
            Some(sink_id) => format!("no alert sink matches id {sink_id}"),
            None => "no alert sinks are configured".to_string(),
        });
    }

    let total_sinks = sinks.len();
    let active_sinks = sinks.iter().filter(|sink| sink.status == "active").count();
    let disabled_sinks = sinks.iter().filter(|sink| sink.status != "active").count();
    let configured_sinks = sinks.iter().filter(|sink| sink.configured).count();
    let missing_target_env = sinks
        .iter()
        .filter(|sink| sink.status == "active" && sink.target_env.is_none())
        .count();
    let missing_env_value = sinks
        .iter()
        .filter(|sink| {
            sink.status == "active" && sink.target_env.is_some() && !sink.target_env_present
        })
        .count();

    let status = if !limitations.is_empty() {
        "not_configured"
    } else if missing_target_env > 0 || missing_env_value > 0 {
        "active_missing_env"
    } else if configured_sinks > 0 {
        "ready"
    } else if disabled_sinks > 0 {
        "disabled"
    } else {
        "not_configured"
    }
    .to_string();

    BackupTimerAlertStatusReport {
        ok: status != "active_missing_env" && limitations.is_empty(),
        read_only: true,
        status,
        sink_filter: options.sink_id.map(str::to_string),
        total_sinks,
        active_sinks,
        disabled_sinks,
        configured_sinks,
        missing_target_env,
        missing_env_value,
        activation_plan: timer_alert_activation_plan(&sinks),
        sinks,
        next_actions: timer_alert_status_next_actions(
            total_sinks,
            active_sinks,
            configured_sinks,
            missing_target_env,
            missing_env_value,
        ),
        limitations,
    }
}

pub fn backup_timer_alert_enable_plan(
    options: &BackupTimerAlertEnablePlanOptions<'_>,
) -> BackupTimerAlertEnablePlanReport {
    let default_owner = env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let requested_sink = TimerAlertPolicy {
        id: options
            .id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("ops-alert-webhook")
            .to_string(),
        provider: options
            .provider
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("webhook")
            .to_ascii_lowercase(),
        target_env: Some(
            options
                .target_env
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("OPSCTL_TIMER_ALERT_WEBHOOK_URL")
                .to_string(),
        ),
        topic: options
            .topic
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        owner: options
            .owner
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&default_owner)
            .to_string(),
        status: "active".to_string(),
        min_severity: Some(
            options
                .min_severity
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("error")
                .to_ascii_lowercase(),
        ),
        notes: Some(
            "managed by opsctl alert enable plan; target value stays in environment".to_string(),
        ),
    };

    let existing_status = backup_timer_alert_status(&BackupTimerAlertStatusOptions {
        registry: options.registry,
        sink_id: Some(requested_sink.id.as_str()),
    });
    let mut limitations = Vec::new();
    if let Err(error) = validate_alert_sink_for_registry(&requested_sink) {
        limitations.push(error.to_string());
    }
    let target_env = requested_sink.target_env.as_deref().unwrap_or_default();
    let target_env_source = (!target_env.is_empty())
        .then(|| env_source::var_source(target_env))
        .flatten();
    let target_env_present = target_env_source.is_some();
    let configure_command = format!(
        "opsctl backup timer alert-configure {} --provider {} --target-env {} --owner {} --status active --min-severity {}{} --execute",
        shell_hint(&requested_sink.id),
        shell_hint(&requested_sink.provider),
        shell_hint(target_env),
        shell_hint(&requested_sink.owner),
        shell_hint(requested_sink.min_severity.as_deref().unwrap_or("error")),
        requested_sink
            .topic
            .as_ref()
            .map(|topic| format!(" --topic {}", shell_hint(topic)))
            .unwrap_or_default()
    );
    let mut steps = vec![
        BackupTimerAlertEnableStep {
            order: 1,
            action: "set_target_env".to_string(),
            command: None,
            required_env: Some(target_env.to_string()),
            env_present: Some(target_env_present),
            detail: "store the real webhook URL, ntfy URL, Telegram bot token, or email target in /etc/opsctl/backup.env or the opsctl service environment; do not write it to policies.yml".to_string(),
        },
        BackupTimerAlertEnableStep {
            order: 2,
            action: "configure_active_sink".to_string(),
            command: Some(configure_command),
            required_env: Some(target_env.to_string()),
            env_present: Some(target_env_present),
            detail: "write only sink metadata and target_env name to policies.yml after review".to_string(),
        },
        BackupTimerAlertEnableStep {
            order: 3,
            action: "send_test_notification".to_string(),
            command: Some(format!(
                "opsctl backup timer alert-test --sink-id {} --execute",
                shell_hint(&requested_sink.id)
            )),
            required_env: Some(target_env.to_string()),
            env_present: Some(target_env_present),
            detail: "send one controlled test alert through the configured sink".to_string(),
        },
        BackupTimerAlertEnableStep {
            order: 4,
            action: "monitor_failures".to_string(),
            command: Some("opsctl backup timer monitor --journal".to_string()),
            required_env: None,
            env_present: None,
            detail: "review recent timer failures and journal excerpts before relying on alerts".to_string(),
        },
    ];
    if !target_env_present {
        steps.insert(
            1,
            BackupTimerAlertEnableStep {
                order: 2,
                action: "blocked_until_env_present".to_string(),
                command: None,
                required_env: Some(target_env.to_string()),
                env_present: Some(false),
                detail:
                    "alert delivery will be blocked until the target environment variable exists"
                        .to_string(),
            },
        );
        for (index, step) in steps.iter_mut().enumerate() {
            step.order = u32::try_from(index + 1).unwrap_or(u32::MAX);
        }
    }

    let status = if !limitations.is_empty() {
        "blocked"
    } else if target_env_present {
        "ready_to_configure"
    } else {
        "missing_target_env"
    }
    .to_string();

    BackupTimerAlertEnablePlanReport {
        ok: limitations.is_empty(),
        read_only: true,
        status,
        existing_status,
        requested_sink,
        target_env_present,
        target_env_source,
        secret_handling: "secret values are never printed or stored by this plan; only the target_env variable name is recorded".to_string(),
        steps,
        retry_policy: BackupTimerAlertRetryPolicy {
            delivery_attempts: ALERT_DELIVERY_MAX_ATTEMPTS,
            retry_backoff_seconds: Vec::new(),
            planned: true,
        },
        escalation_policy: BackupTimerAlertEscalationPolicy {
            consecutive_failures_before_deploy_block: options
                .registry
                .policies
                .timer_health
                .max_consecutive_failures,
            deploy_block_enabled: options
                .registry
                .policies
                .timer_health
                .block_deploy_on_failure,
            detail: "timer health already blocks deploy gates after configured consecutive failures; delivery retry is intentionally not automatic yet".to_string(),
        },
        alert_template: BackupTimerAlertTemplate {
            subject: "opsctl backup timer alert".to_string(),
            body_fields: vec![
                "status".to_string(),
                "candidate severity".to_string(),
                "timer or repository id".to_string(),
                "reason".to_string(),
                "recent journal errors when requested".to_string(),
            ],
            json_fields: vec![
                "status".to_string(),
                "candidate_count".to_string(),
                "alert_candidates".to_string(),
                "timer_health".to_string(),
                "entries".to_string(),
            ],
        },
        limitations,
    }
}

pub fn backup_timer_alert_env_template(
    options: &BackupTimerAlertEnvTemplateOptions<'_>,
) -> BackupTimerAlertEnvTemplateReport {
    let id = options
        .id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("ops-alert-webhook")
        .to_string();
    let provider = options
        .provider
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("webhook")
        .to_ascii_lowercase();
    let target_env = options
        .target_env
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("OPSCTL_TIMER_ALERT_WEBHOOK_URL")
        .to_string();
    let env_file = options
        .env_file
        .map(display_path)
        .unwrap_or_else(|| "/etc/opsctl/backup.env".to_string());
    let target_env_source = env_source::var_source(&target_env);
    let target_env_present = target_env_source.is_some();
    let mut limitations = Vec::new();
    if !matches!(provider.as_str(), "webhook" | "ntfy" | "telegram" | "email") {
        limitations.push("provider must be webhook, ntfy, telegram, or email".to_string());
    }
    if !target_env.chars().all(|character| {
        character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
    }) {
        limitations
            .push("target env name must use uppercase letters, digits, or underscore".to_string());
    }
    let placeholder = match provider.as_str() {
        "webhook" => "<REPLACE_WITH_HTTPS_WEBHOOK_URL>",
        "ntfy" => "<REPLACE_WITH_NTFY_TOPIC_URL>",
        "telegram" => "<REPLACE_WITH_TELEGRAM_BOT_TOKEN_OR_SENDMESSAGE_URL>",
        "email" => "<REPLACE_WITH_ALERT_EMAIL_RECIPIENT>",
        _ => "<REPLACE_WITH_ALERT_TARGET>",
    };
    let mut template_lines = vec![
        "# opsctl backup timer alert target; keep this file mode 0600".to_string(),
        format!("{target_env}={placeholder}"),
    ];
    if provider == "telegram" {
        template_lines
            .push("# Telegram also needs --topic <chat_id> on alert-configure.".to_string());
    }
    let install_commands = vec![
        "sudo install -d -m 0750 -o root -g opsctl /etc/opsctl".to_string(),
        format!("sudo editor {}", shell_hint(&env_file)),
        format!("sudo chown root:opsctl {}", shell_hint(&env_file)),
        format!("sudo chmod 0600 {}", shell_hint(&env_file)),
    ];
    let next_commands = vec![
        format!(
            "opsctl backup timer alert-enable-plan --id {} --provider {} --target-env {} --json",
            shell_hint(&id),
            shell_hint(&provider),
            shell_hint(&target_env)
        ),
        format!(
            "opsctl backup timer alert-configure {} --provider {} --target-env {} --status active --execute",
            shell_hint(&id),
            shell_hint(&provider),
            shell_hint(&target_env)
        ),
        format!(
            "opsctl backup timer alert-test --sink-id {} --execute",
            shell_hint(&id)
        ),
    ];
    let status = if !limitations.is_empty() {
        "blocked"
    } else if target_env_present {
        "env_present"
    } else {
        "template_ready"
    }
    .to_string();
    let existing_status = backup_timer_alert_status(&BackupTimerAlertStatusOptions {
        registry: options.registry,
        sink_id: Some(id.as_str()),
    });
    if existing_status.status == "ready" {
        limitations.push("requested sink is already configured and ready".to_string());
    }

    BackupTimerAlertEnvTemplateReport {
        ok: limitations.is_empty() || status == "env_present",
        read_only: true,
        status,
        env_file,
        sink_id: id,
        provider,
        target_env,
        target_env_present,
        target_env_source,
        template_lines,
        install_commands,
        next_commands,
        secret_handling:
            "template uses placeholders only; write the real value manually into the env file"
                .to_string(),
        limitations: unique_sorted(limitations),
    }
}

fn timer_alert_activation_plan(
    sinks: &[BackupTimerAlertStatusSink],
) -> Vec<BackupTimerAlertActivationStep> {
    sinks
        .iter()
        .map(|sink| {
            let mut notes = Vec::new();
            if sink.target_env.is_none() {
                notes.push("configure a target_env name before activation".to_string());
            } else if !sink.target_env_present {
                notes.push(
                    "put the target value in /etc/opsctl/backup.env or the service environment"
                        .to_string(),
                );
            }
            if sink.provider == "telegram" && !sink.topic_configured {
                notes.push("telegram sinks require topic/chat_id before delivery".to_string());
            }
            if sink.status == "active" && sink.configured {
                notes.push("sink is active and can be tested".to_string());
            } else {
                notes.push("review provider, owner, and target_env before activation".to_string());
            }
            BackupTimerAlertActivationStep {
                sink_id: sink.id.clone(),
                provider: sink.provider.clone(),
                status: sink.status.clone(),
                required_env: sink.target_env.clone(),
                env_present: sink.target_env_present,
                planned_command: format!(
                    "opsctl backup timer alert-configure --id {} --provider {} --target-env {} --owner {} --status active --execute",
                    shell_hint(&sink.id),
                    shell_hint(&sink.provider),
                    shell_hint(sink.target_env.as_deref().unwrap_or("<TARGET_ENV>")),
                    shell_hint(&sink.owner)
                ),
                test_command: sink.configured.then(|| {
                    format!(
                        "opsctl backup timer alert-test --sink-id {} --execute",
                        shell_hint(&sink.id)
                    )
                }),
                notes,
            }
        })
        .collect()
}

fn shell_hint(value: &str) -> String {
    if value.is_empty() {
        "''".to_string()
    } else if value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | ':' | '/' | '_' | '-')
    }) {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn unique_sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

pub fn backup_timer_alert_configure(
    options: &BackupTimerAlertConfigureOptions<'_>,
) -> BackupTimerAlertConfigureReport {
    let mut limitations = Vec::new();
    let sink = TimerAlertPolicy {
        id: options.id.trim().to_string(),
        provider: options.provider.trim().to_ascii_lowercase(),
        target_env: Some(options.target_env.trim().to_string()),
        topic: options
            .topic
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        owner: options.owner.trim().to_string(),
        status: options.status.trim().to_ascii_lowercase(),
        min_severity: options
            .min_severity
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase()),
        notes: options
            .notes
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
    };

    if let Err(error) = validate_alert_sink_for_registry(&sink) {
        limitations.push(error.to_string());
    }
    let target_env_source = sink
        .target_env
        .as_deref()
        .filter(|value| !value.is_empty())
        .and_then(env_source::var_source);
    let target_env_present = target_env_source.is_some();
    if options.execute && sink.status == "active" && !target_env_present {
        limitations.push(format!(
            "active alert sink {} requires target env {} to be configured before --execute",
            sink.id,
            sink.target_env.as_deref().unwrap_or("<missing>")
        ));
    }

    let path = options.registry_dir.join("policies.yml");
    let mut action = "unknown".to_string();
    let mut changed_files = Vec::new();
    if limitations.is_empty() {
        match read_yaml_registry::<PoliciesRegistry>(&path, "policies registry") {
            Ok(mut policies) => {
                action = planned_alert_sink_action(&policies.timer_alerts, &sink).to_string();
                if options.execute && action != "unchanged" {
                    if let Some(existing) = policies
                        .timer_alerts
                        .iter_mut()
                        .find(|existing| existing.id == sink.id)
                    {
                        *existing = sink.clone();
                    } else {
                        policies.timer_alerts.push(sink.clone());
                    }
                    policies
                        .timer_alerts
                        .sort_by(|left, right| left.id.cmp(&right.id));
                    match write_yaml_registry(&path, &policies, "policies registry") {
                        Ok(()) => changed_files.push(display_path(&path)),
                        Err(error) => limitations.push(error.to_string()),
                    }
                }
            }
            Err(error) => limitations.push(error.to_string()),
        }
    }

    let status = if !limitations.is_empty() {
        "blocked"
    } else if !options.execute {
        "planned"
    } else if action == "unchanged" {
        "unchanged"
    } else {
        "configured"
    }
    .to_string();
    let mut report_sink = sink;
    if status == "blocked" {
        report_sink.notes = None;
        report_sink.topic = None;
    }

    BackupTimerAlertConfigureReport {
        ok: matches!(status.as_str(), "planned" | "configured" | "unchanged"),
        execute: options.execute,
        read_only: !options.execute,
        status,
        action,
        sink: report_sink,
        target_env_present,
        target_env_source,
        changed_files,
        limitations,
    }
}

pub fn timer_health(registry: &Registry) -> BackupTimerHealthReport {
    let max_failures = registry.policies.timer_health.max_consecutive_failures;
    let block_deploy = registry.policies.timer_health.block_deploy_on_failure;
    let mut services = active_backup_target_services(registry)
        .into_iter()
        .map(|service| timer_health_for_service(registry, service, max_failures, block_deploy))
        .collect::<Vec<_>>();
    services.sort_by(|left, right| left.service_id.cmp(&right.service_id));

    let services_checked = services.len();
    let services_blocked = services
        .iter()
        .filter(|service| service.status == "blocked")
        .count();
    let services_ready = services_checked.saturating_sub(services_blocked);
    let status = if services_blocked == 0 {
        "ready"
    } else {
        "blocked"
    }
    .to_string();

    BackupTimerHealthReport {
        ok: status == "ready",
        read_only: true,
        status,
        max_consecutive_failures: max_failures,
        block_deploy_on_failure: block_deploy,
        services_checked,
        services_ready,
        services_blocked,
        services,
        limitations: Vec::new(),
    }
}

fn backup_timer_report(
    options: &BackupTimerOptions<'_>,
    install: bool,
    include_status: bool,
) -> BackupTimerReport {
    let mut entries =
        planned_timer_entries(options.registry, options.service_id, options.repository_id);
    let mut limitations = Vec::new();
    if entries.is_empty() {
        limitations.push("no timer entries match the registry and filters".to_string());
    }

    for entry in &mut entries {
        if install {
            let args = vec![
                "enable".to_string(),
                "--now".to_string(),
                entry.timer_unit.clone(),
            ];
            let systemctl = systemctl_bin();
            match command_runner::run_controlled(&systemctl, &args) {
                Ok(output) if output.success() => {
                    entry.status = "installed".to_string();
                    entry.detail = "systemctl enable --now completed".to_string();
                }
                Ok(output) => {
                    entry.status = "failed".to_string();
                    entry.detail = format!(
                        "systemctl enable --now exited {:?}; stdout/stderr were not persisted",
                        output.status_code
                    );
                }
                Err(error) => {
                    entry.status = "failed".to_string();
                    entry.detail = error.to_string();
                }
            }
        }
        if include_status || options.include_status || install {
            entry.enabled = Some(systemctl_state("is-enabled", &entry.timer_unit));
            entry.active = Some(systemctl_state("is-active", &entry.timer_unit));
            if !install {
                entry.status = "observed".to_string();
                entry.detail = "read timer state with systemctl".to_string();
            }
        }
    }

    let failed = entries.iter().any(|entry| entry.status == "failed");
    BackupTimerReport {
        ok: !failed && limitations.is_empty(),
        execute: install,
        read_only: !install,
        entries,
        limitations,
    }
}

fn planned_timer_entries(
    registry: &Registry,
    service_filter: Option<&str>,
    repository_filter: Option<&str>,
) -> Vec<BackupTimerEntry> {
    let services = registry
        .services
        .services
        .iter()
        .map(|service| (service.id.as_str(), service))
        .collect::<BTreeMap<_, _>>();
    let repositories = registry
        .backups
        .repositories
        .iter()
        .map(|repository| (repository.id.as_str(), repository))
        .collect::<BTreeMap<_, _>>();
    let mut entries = Vec::new();
    let mut backup_services = BTreeSet::new();
    let mut drill_services = BTreeSet::new();
    let mut repository_ids = BTreeSet::new();

    for target in registry
        .backups
        .targets
        .iter()
        .filter(|target| target.status == "active")
    {
        if service_filter.is_some_and(|service_id| service_id != target.service_id) {
            continue;
        }
        backup_services.insert(target.service_id.clone());
        if target.schedule == "before_deploy"
            || services
                .get(target.service_id.as_str())
                .and_then(|service| service.backup_policy.as_deref())
                == Some("before_deploy")
        {
            drill_services.insert(target.service_id.clone());
        }
        repository_ids.insert(target.repository_id.clone());
    }

    for service_id in backup_services {
        entries.push(timer_entry(
            "backup_run",
            &service_id,
            &format!("opsctl-backup-run@{service_id}.timer"),
            &format!("opsctl-backup-run@{service_id}.service"),
            &format!("opsctl backup run {service_id} --execute"),
            "daily",
        ));
    }
    for service_id in drill_services {
        entries.push(timer_entry(
            "restore_drill",
            &service_id,
            &format!("opsctl-restore-drill@{service_id}.timer"),
            &format!("opsctl-restore-drill@{service_id}.service"),
            &format!(
                "opsctl backup drill {service_id} --restore-dir /var/lib/opsctl/restore-drills/{service_id} --execute --scheduled"
            ),
            "weekly",
        ));
    }
    for repository_id in repository_ids {
        if repository_filter.is_some_and(|filter| filter != repository_id) {
            continue;
        }
        if repositories
            .get(repository_id.as_str())
            .is_some_and(|repository| repository.status == "active")
        {
            entries.push(timer_entry(
                "repository_check",
                &repository_id,
                &format!("opsctl-backup-check@{repository_id}.timer"),
                &format!("opsctl-backup-check@{repository_id}.service"),
                &format!("opsctl backup check {repository_id}"),
                "weekly",
            ));
        }
    }
    entries
}

fn timer_entry(
    kind: &str,
    id: &str,
    timer_unit: &str,
    service_unit: &str,
    command: &str,
    schedule: &str,
) -> BackupTimerEntry {
    BackupTimerEntry {
        kind: kind.to_string(),
        id: id.to_string(),
        timer_unit: timer_unit.to_string(),
        service_unit: service_unit.to_string(),
        command: command.to_string(),
        schedule: schedule.to_string(),
        enabled: None,
        active: None,
        status: "planned".to_string(),
        detail: "timer unit is planned; use install --execute to enable".to_string(),
    }
}

fn systemctl_state(action: &str, unit: &str) -> String {
    let systemctl = systemctl_bin();
    match command_runner::capture(&systemctl, &[action, unit]) {
        Ok(output) if output.success() => output.stdout.trim().to_string(),
        Ok(output) => {
            if output.stdout.trim().is_empty() {
                format!("exit:{:?}", output.status_code)
            } else {
                output.stdout.trim().to_string()
            }
        }
        Err(error) => format!("unavailable:{error}"),
    }
}

fn monitor_timer_entry(
    registry: &Registry,
    health_by_service: &BTreeMap<&str, &BackupTimerHealthService>,
    entry: BackupTimerEntry,
    include_journal: bool,
    journal_lines: u32,
) -> BackupTimerMonitorEntry {
    let show = systemctl_show(&entry.service_unit);
    let service_result = show_value(&show, "Result", "unknown");
    let service_active = systemctl_state("is-active", &entry.service_unit);
    let exec_main_status = show
        .get("ExecMainStatus")
        .and_then(|value| value.parse::<i32>().ok());
    let recent_status = recent_timer_status(&service_result, exec_main_status);
    let consecutive_failures =
        entry_consecutive_failures(registry, health_by_service, &entry.kind, &entry.id);
    let journal_errors = if include_journal && journal_lines > 0 {
        journal_error_lines(&entry.service_unit, journal_lines)
    } else {
        Vec::new()
    };

    BackupTimerMonitorEntry {
        kind: entry.kind,
        id: entry.id,
        timer_unit: entry.timer_unit.clone(),
        service_unit: entry.service_unit,
        timer_enabled: systemctl_state("is-enabled", &entry.timer_unit),
        timer_active: systemctl_state("is-active", &entry.timer_unit),
        service_active,
        service_result,
        exec_main_status,
        active_enter_timestamp: show_optional_value(&show, "ActiveEnterTimestamp"),
        inactive_exit_timestamp: show_optional_value(&show, "InactiveExitTimestamp"),
        recent_status,
        consecutive_failures,
        journal_errors,
    }
}

fn systemctl_show(unit: &str) -> BTreeMap<String, String> {
    let args = [
        "show",
        unit,
        "--property=Result",
        "--property=ExecMainStatus",
        "--property=ActiveEnterTimestamp",
        "--property=InactiveExitTimestamp",
    ];
    let systemctl = systemctl_bin();
    match command_runner::capture(&systemctl, &args) {
        Ok(output) if output.success() => output
            .stdout
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        _ => BTreeMap::new(),
    }
}

fn systemctl_bin() -> String {
    env_source::var_string("OPSCTL_SYSTEMCTL_BIN").unwrap_or_else(|| "systemctl".to_string())
}

fn show_value(values: &BTreeMap<String, String>, key: &str, default: &str) -> String {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn show_optional_value(values: &BTreeMap<String, String>, key: &str) -> Option<String> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty() && value.as_str() != "n/a")
        .cloned()
}

fn recent_timer_status(result: &str, exec_main_status: Option<i32>) -> String {
    if result == "success"
        || result == "unknown" && exec_main_status.is_none_or(|status| status == 0)
    {
        "ready".to_string()
    } else {
        "failed".to_string()
    }
}

fn journal_error_lines(unit: &str, lines: u32) -> Vec<String> {
    let lines_string = lines.to_string();
    let args = [
        "-u",
        unit,
        "-n",
        lines_string.as_str(),
        "--no-pager",
        "--output=short-iso",
        "--priority=warning..alert",
    ];
    match command_runner::capture("journalctl", &args) {
        Ok(output) => output
            .stdout
            .lines()
            .take(lines as usize)
            .map(redact_line)
            .collect(),
        Err(error) => vec![format!("journal unavailable: {error}")],
    }
}

fn redact_line(line: &str) -> String {
    match redact_value(&Value::String(line.to_string())) {
        Value::String(redacted) => redacted,
        _ => "[REDACTED]".to_string(),
    }
}

fn entry_consecutive_failures(
    registry: &Registry,
    health_by_service: &BTreeMap<&str, &BackupTimerHealthService>,
    kind: &str,
    id: &str,
) -> usize {
    match kind {
        "backup_run" => health_by_service
            .get(id)
            .map(|service| service.backup_run_consecutive_failures)
            .unwrap_or(0),
        "restore_drill" => health_by_service
            .get(id)
            .map(|service| service.restore_drill_consecutive_failures)
            .unwrap_or(0),
        "repository_check" => repository_consecutive_failures(registry, id),
        _ => 0,
    }
}

fn timer_health_for_service(
    registry: &Registry,
    service: &Service,
    max_failures: u32,
    block_deploy: bool,
) -> BackupTimerHealthService {
    let active_targets = registry
        .backups
        .targets
        .iter()
        .filter(|target| target.status == "active" && target.service_id == service.id)
        .collect::<Vec<_>>();
    let backup_failures = active_targets
        .iter()
        .map(|target| backup_consecutive_failures(registry, target))
        .max()
        .unwrap_or(0);
    let repository_failures = active_targets
        .iter()
        .map(|target| repository_consecutive_failures(registry, &target.repository_id))
        .max()
        .unwrap_or(0);
    let drill_failures = active_targets
        .iter()
        .map(|target| restore_drill_consecutive_failures(registry, target))
        .max()
        .unwrap_or(0);
    let consecutive_failures = backup_failures.max(repository_failures).max(drill_failures);
    let blocked = block_deploy && consecutive_failures >= max_failures as usize;
    BackupTimerHealthService {
        service_id: service.id.clone(),
        status: if blocked { "blocked" } else { "ready" }.to_string(),
        consecutive_failures,
        backup_run_consecutive_failures: backup_failures,
        repository_check_consecutive_failures: repository_failures,
        restore_drill_consecutive_failures: drill_failures,
        blocked_reason: blocked.then(|| {
            format!(
                "consecutive timer-related failures {} reached policy threshold {}",
                consecutive_failures, max_failures
            )
        }),
    }
}

fn backup_consecutive_failures(registry: &Registry, target: &BackupTarget) -> usize {
    let mut records = registry
        .backups
        .history
        .iter()
        .filter(|record| {
            record.service_id == target.service_id
                && record.target_id == target.id
                && record
                    .repository_id
                    .as_deref()
                    .is_none_or(|repository_id| repository_id == target.repository_id)
        })
        .filter_map(|record| {
            parse_rfc3339(&record.completed_at).map(|ts| (ts, record.status.as_str()))
        })
        .collect::<Vec<_>>();
    consecutive_failures_from_statuses(&mut records)
}

fn repository_consecutive_failures(registry: &Registry, repository_id: &str) -> usize {
    let mut records = registry
        .backups
        .repository_checks
        .iter()
        .filter(|record| record.repository_id == repository_id)
        .filter_map(|record| {
            parse_rfc3339(&record.completed_at).map(|ts| (ts, record.status.as_str()))
        })
        .collect::<Vec<_>>();
    consecutive_failures_from_statuses(&mut records)
}

fn restore_drill_consecutive_failures(registry: &Registry, target: &BackupTarget) -> usize {
    let mut records = registry
        .backups
        .restore_drills
        .iter()
        .filter(|record| record.service_id == target.service_id && record.target_id == target.id)
        .filter_map(|record| {
            parse_rfc3339(&record.completed_at).map(|ts| (ts, record.status.as_str()))
        })
        .collect::<Vec<_>>();
    consecutive_failures_from_statuses(&mut records)
}

fn consecutive_failures_from_statuses(records: &mut [(OffsetDateTime, &str)]) -> usize {
    records.sort_by_key(|(completed_at, _)| std::cmp::Reverse(*completed_at));
    records
        .iter()
        .take_while(|(_, status)| *status != "success")
        .count()
}

fn timer_alert_sinks(registry: &Registry) -> Vec<BackupTimerAlertSink> {
    registry
        .policies
        .timer_alerts
        .iter()
        .map(|alert| {
            let configured = alert
                .target_env
                .as_deref()
                .is_some_and(|name| env_source::var_os(name).is_some());
            let detail = if alert.status != "active" {
                "alert sink is disabled".to_string()
            } else if alert.target_env.is_none() {
                "target_env is required for real alert delivery".to_string()
            } else if !configured {
                "target_env is not present in the command environment".to_string()
            } else {
                "alert sink is configured for monitor reports".to_string()
            };
            BackupTimerAlertSink {
                id: alert.id.clone(),
                provider: alert.provider.clone(),
                status: alert.status.clone(),
                owner: alert.owner.clone(),
                configured: alert.status == "active" && configured,
                detail,
            }
        })
        .collect()
}

fn timer_alert_status_sink(policy: &TimerAlertPolicy) -> BackupTimerAlertStatusSink {
    let target_env_source = policy
        .target_env
        .as_deref()
        .and_then(env_source::var_source);
    let target_env_present = target_env_source.is_some();
    let configured = policy.status == "active" && policy.target_env.is_some() && target_env_present;
    let detail = if policy.status != "active" {
        "alert sink is disabled".to_string()
    } else if policy.target_env.is_none() {
        "target_env is required for real alert delivery".to_string()
    } else if !target_env_present {
        "target_env is not present in the command environment".to_string()
    } else {
        "alert sink can be tested with alert-test --execute".to_string()
    };
    BackupTimerAlertStatusSink {
        id: policy.id.clone(),
        provider: policy.provider.clone(),
        status: policy.status.clone(),
        owner: policy.owner.clone(),
        target_env: policy.target_env.clone(),
        target_env_present,
        target_env_source,
        configured,
        min_severity: policy.min_severity.clone(),
        topic_configured: policy
            .topic
            .as_deref()
            .is_some_and(|topic| !topic.is_empty()),
        detail,
    }
}

fn timer_alert_status_next_actions(
    total_sinks: usize,
    active_sinks: usize,
    configured_sinks: usize,
    missing_target_env: usize,
    missing_env_value: usize,
) -> Vec<String> {
    let mut actions = Vec::new();
    if total_sinks == 0 {
        actions.push(
            "configure a disabled sink first, then activate it after the target env var exists"
                .to_string(),
        );
    }
    if active_sinks == 0 && total_sinks > 0 {
        actions.push("activate one reviewed sink with alert-configure --status active".to_string());
    }
    if missing_target_env > 0 {
        actions.push("reconfigure active sinks with a target_env variable name".to_string());
    }
    if missing_env_value > 0 {
        actions.push(
            "add missing alert target variables to the opsctl environment file or service environment"
                .to_string(),
        );
    }
    if configured_sinks > 0 {
        actions.push(
            "run opsctl backup timer alert-test --execute for one configured sink".to_string(),
        );
    }
    if actions.is_empty() {
        actions.push("alert sink configuration is ready".to_string());
    }
    actions
}

fn timer_alert_candidates(
    entries: &[BackupTimerMonitorEntry],
    health: &BackupTimerHealthReport,
    sinks: &[BackupTimerAlertSink],
) -> Vec<BackupTimerAlertCandidate> {
    let configured_alerts = sinks
        .iter()
        .filter(|sink| sink.configured)
        .map(|sink| sink.id.clone())
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for entry in entries {
        if entry.recent_status == "failed" {
            candidates.push(BackupTimerAlertCandidate {
                severity: "error".to_string(),
                kind: entry.kind.clone(),
                id: entry.id.clone(),
                reason: format!(
                    "{} last result is {}",
                    entry.service_unit, entry.service_result
                ),
                configured_alerts: configured_alerts.clone(),
            });
        }
    }
    for service in &health.services {
        if service.status == "blocked" {
            candidates.push(BackupTimerAlertCandidate {
                severity: "error".to_string(),
                kind: "deploy_gate".to_string(),
                id: service.service_id.clone(),
                reason: service
                    .blocked_reason
                    .clone()
                    .unwrap_or_else(|| "timer health gate is blocked".to_string()),
                configured_alerts: configured_alerts.clone(),
            });
        }
    }
    candidates.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.id.cmp(&right.id))
    });
    candidates.dedup_by(|left, right| left.kind == right.kind && left.id == right.id);
    candidates
}

fn timer_alert_delivery(
    policy: &TimerAlertPolicy,
    body: &str,
    payload: &Value,
    candidate_count: usize,
    execute: bool,
) -> BackupTimerAlertDelivery {
    if !execute {
        return BackupTimerAlertDelivery {
            sink_id: policy.id.clone(),
            provider: policy.provider.clone(),
            status: "planned".to_string(),
            detail: "dry-run only; rerun with --execute to send".to_string(),
            candidate_count,
            attempts: 0,
        };
    }
    let Some(target_env) = policy.target_env.as_deref() else {
        return alert_delivery_status(policy, "blocked", "target_env is required", candidate_count);
    };
    let Some(target) = env_source::var_string(target_env) else {
        return alert_delivery_status(
            policy,
            "blocked",
            "target_env is not present in the command environment",
            candidate_count,
        );
    };
    let mut failed_details = Vec::new();
    for attempt in 1..=ALERT_DELIVERY_MAX_ATTEMPTS {
        let mut delivery = match policy.provider.as_str() {
            "webhook" => send_webhook_alert(policy, &target, payload, candidate_count),
            "ntfy" => send_ntfy_alert(policy, &target, body, candidate_count),
            "telegram" => send_telegram_alert(policy, &target, body, candidate_count),
            "email" => send_email_alert(policy, &target, body, candidate_count),
            provider => alert_delivery_status(
                policy,
                "blocked",
                &format!("unsupported alert provider: {provider}"),
                candidate_count,
            ),
        };
        delivery.attempts = attempt;
        if delivery.status != "failed" {
            if attempt > 1 {
                delivery.detail = format!(
                    "{} after {attempt} attempt(s); previous failures: {}",
                    delivery.detail,
                    failed_details.join(" | ")
                );
            }
            return delivery;
        }
        failed_details.push(format!("attempt {attempt}: {}", delivery.detail));
    }
    alert_delivery_status(
        policy,
        "failed",
        &format!(
            "failed after {} attempt(s): {}",
            ALERT_DELIVERY_MAX_ATTEMPTS,
            failed_details.join(" | ")
        ),
        candidate_count,
    )
}

pub fn send_operational_alert(
    registry: &Registry,
    state_dir: &Path,
    kind: &str,
    id: &str,
    reason: &str,
) -> Vec<BackupTimerAlertDelivery> {
    let key = format!("{kind}:{id}");
    let mut state = load_operational_alert_state(state_dir);
    let now = OffsetDateTime::now_utc();
    let reason_sha256 = format!("{:x}", Sha256::digest(reason.as_bytes()));
    if state.entries.get(&key).is_some_and(|entry| {
        entry.status == "failed"
            && entry.reason_sha256 == reason_sha256
            && OffsetDateTime::parse(&entry.updated_at, &Rfc3339)
                .map(|updated| {
                    now - updated < TimeDuration::seconds(OPERATIONAL_ALERT_COOLDOWN_SECONDS)
                })
                .unwrap_or(false)
    }) {
        return registry
            .policies
            .timer_alerts
            .iter()
            .filter(|policy| policy.status == "active")
            .map(|policy| BackupTimerAlertDelivery {
                sink_id: policy.id.clone(),
                provider: policy.provider.clone(),
                status: "suppressed".to_string(),
                detail: "duplicate operational failure is inside the alert cooldown".to_string(),
                candidate_count: 1,
                attempts: 0,
            })
            .collect();
    }
    let body = format!("opsctl {kind} failure\nid: {id}\nreason: {reason}");
    let payload = json!({
        "schema_version": "opsctl.operational_alert.v1",
        "severity": "error",
        "kind": kind,
        "id": id,
        "reason": reason,
    });
    let deliveries = registry
        .policies
        .timer_alerts
        .iter()
        .filter(|policy| policy.status == "active" && operational_policy_matches(policy, "info"))
        .map(|policy| timer_alert_delivery(policy, &body, &payload, 1, true))
        .collect::<Vec<_>>();
    state.entries.insert(
        key,
        OperationalAlertEntry {
            status: "failed".to_string(),
            reason_sha256,
            updated_at: operational_timestamp(now),
        },
    );
    let _ = write_operational_alert_state(state_dir, &state);
    deliveries
}

pub fn send_operational_recovery(
    registry: &Registry,
    state_dir: &Path,
    kind: &str,
    id: &str,
) -> Vec<BackupTimerAlertDelivery> {
    let key = format!("{kind}:{id}");
    let mut state = load_operational_alert_state(state_dir);
    if state
        .entries
        .get(&key)
        .is_none_or(|entry| entry.status != "failed")
    {
        return Vec::new();
    }
    let body = format!("opsctl {kind} recovered\nid: {id}");
    let payload = json!({
        "schema_version": "opsctl.operational_alert.v1",
        "severity": "info",
        "kind": kind,
        "id": id,
        "status": "recovered",
    });
    let deliveries = registry
        .policies
        .timer_alerts
        .iter()
        .filter(|policy| policy.status == "active")
        .map(|policy| timer_alert_delivery(policy, &body, &payload, 1, true))
        .collect::<Vec<_>>();
    state.entries.insert(
        key,
        OperationalAlertEntry {
            status: "recovered".to_string(),
            reason_sha256: String::new(),
            updated_at: operational_timestamp(OffsetDateTime::now_utc()),
        },
    );
    let _ = write_operational_alert_state(state_dir, &state);
    deliveries
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OperationalAlertState {
    #[serde(default)]
    entries: BTreeMap<String, OperationalAlertEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OperationalAlertEntry {
    status: String,
    reason_sha256: String,
    updated_at: String,
}

fn load_operational_alert_state(state_dir: &Path) -> OperationalAlertState {
    let path = state_dir.join("operational-alert-state.json");
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return OperationalAlertState::default();
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_OPERATIONAL_ALERT_STATE_BYTES
    {
        return OperationalAlertState::default();
    }
    fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_operational_alert_state(state_dir: &Path, state: &OperationalAlertState) -> Result<()> {
    fs::create_dir_all(state_dir)?;
    let path = state_dir.join("operational-alert-state.json");
    let temporary = state_dir.join(format!(
        ".operational-alert-state-{}-{}.tmp",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&temporary)?;
    serde_json::to_writer_pretty(&mut file, state)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn operational_timestamp(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .unwrap_or_else(|_| value.unix_timestamp().to_string())
}

fn operational_policy_matches(policy: &TimerAlertPolicy, severity: &str) -> bool {
    severity_rank(severity) >= severity_rank(policy.min_severity.as_deref().unwrap_or("warning"))
}

fn send_webhook_alert(
    policy: &TimerAlertPolicy,
    target: &str,
    payload: &Value,
    candidate_count: usize,
) -> BackupTimerAlertDelivery {
    let payload = match serde_json::to_vec(payload) {
        Ok(payload) => payload,
        Err(error) => {
            return alert_delivery_status(
                policy,
                "failed",
                &format!("failed to serialize alert payload: {error}"),
                candidate_count,
            );
        }
    };
    send_curl_alert(
        policy,
        target,
        &[("Content-Type", "application/json")],
        &payload,
        candidate_count,
    )
}

fn send_ntfy_alert(
    policy: &TimerAlertPolicy,
    target: &str,
    body: &str,
    candidate_count: usize,
) -> BackupTimerAlertDelivery {
    send_curl_alert(
        policy,
        target,
        &[
            ("Title", "opsctl backup timer alert"),
            ("Priority", "urgent"),
            ("Tags", "warning"),
        ],
        body.as_bytes(),
        candidate_count,
    )
}

fn send_telegram_alert(
    policy: &TimerAlertPolicy,
    target: &str,
    body: &str,
    candidate_count: usize,
) -> BackupTimerAlertDelivery {
    let Some(chat_id) = policy.topic.as_deref() else {
        return alert_delivery_status(
            policy,
            "blocked",
            "telegram alert sink requires topic as chat_id",
            candidate_count,
        );
    };
    if header_or_topic_has_control_chars(chat_id) {
        return alert_delivery_status(
            policy,
            "blocked",
            "telegram chat_id contains control characters",
            candidate_count,
        );
    }
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else if secret_token_is_safe(target) {
        format!("https://api.telegram.org/bot{target}/sendMessage")
    } else {
        return alert_delivery_status(
            policy,
            "blocked",
            "telegram target_env must be an HTTPS URL or a safe bot token",
            candidate_count,
        );
    };
    let payload = match serde_json::to_vec(&json!({
        "chat_id": chat_id,
        "text": body,
        "disable_web_page_preview": true
    })) {
        Ok(payload) => payload,
        Err(error) => {
            return alert_delivery_status(
                policy,
                "failed",
                &format!("failed to serialize telegram payload: {error}"),
                candidate_count,
            );
        }
    };
    send_curl_alert(
        policy,
        &url,
        &[("Content-Type", "application/json")],
        &payload,
        candidate_count,
    )
}

fn send_email_alert(
    policy: &TimerAlertPolicy,
    recipient: &str,
    body: &str,
    candidate_count: usize,
) -> BackupTimerAlertDelivery {
    if header_or_topic_has_control_chars(recipient) {
        return alert_delivery_status(
            policy,
            "blocked",
            "email recipient contains control characters",
            candidate_count,
        );
    }
    let message = format!(
        "To: {recipient}\nSubject: opsctl backup timer alert\nContent-Type: text/plain; charset=utf-8\n\n{body}\n"
    );
    let args = vec!["-t".to_string()];
    match command_runner::run_controlled_with_input("sendmail", &args, message.as_bytes()) {
        Ok(output) if output.success() => alert_delivery_status(
            policy,
            "sent",
            "sendmail accepted alert message",
            candidate_count,
        ),
        Ok(output) => alert_delivery_status(
            policy,
            "failed",
            &format!("sendmail exited {:?}", output.status_code),
            candidate_count,
        ),
        Err(error) => alert_delivery_status(
            policy,
            "failed",
            &format!("failed to run sendmail: {error}"),
            candidate_count,
        ),
    }
}

fn send_curl_alert(
    policy: &TimerAlertPolicy,
    target: &str,
    headers: &[(&str, &str)],
    payload: &[u8],
    candidate_count: usize,
) -> BackupTimerAlertDelivery {
    if let Err(error) = validate_alert_url(target) {
        return alert_delivery_status(policy, "blocked", &error.to_string(), candidate_count);
    }
    let config_path =
        match write_alert_temp_file("curl-config", curl_config(target, headers).as_bytes()) {
            Ok(path) => path,
            Err(error) => {
                return alert_delivery_status(
                    policy,
                    "failed",
                    &format!("failed to prepare curl config: {error}"),
                    candidate_count,
                );
            }
        };
    let payload_path = match write_alert_temp_file("curl-payload", payload) {
        Ok(path) => path,
        Err(error) => {
            remove_alert_temp_file(&config_path);
            return alert_delivery_status(
                policy,
                "failed",
                &format!("failed to prepare curl payload: {error}"),
                candidate_count,
            );
        }
    };
    if let Err(error) = append_curl_payload_path(&config_path, &payload_path) {
        remove_alert_temp_file(&config_path);
        remove_alert_temp_file(&payload_path);
        return alert_delivery_status(
            policy,
            "failed",
            &format!("failed to finalize curl config: {error}"),
            candidate_count,
        );
    }
    let args = vec!["--config".to_string(), display_path(&config_path)];
    let result = command_runner::run_controlled("curl", &args);
    remove_alert_temp_file(&config_path);
    remove_alert_temp_file(&payload_path);
    match result {
        Ok(output) if output.success() => {
            alert_delivery_status(policy, "sent", "curl POST completed", candidate_count)
        }
        Ok(output) => alert_delivery_status(
            policy,
            "failed",
            &format!("curl exited {:?}", output.status_code),
            candidate_count,
        ),
        Err(error) => alert_delivery_status(
            policy,
            "failed",
            &format!("failed to run curl: {error}"),
            candidate_count,
        ),
    }
}

fn alert_delivery_status(
    policy: &TimerAlertPolicy,
    status: &str,
    detail: &str,
    candidate_count: usize,
) -> BackupTimerAlertDelivery {
    BackupTimerAlertDelivery {
        sink_id: policy.id.clone(),
        provider: policy.provider.clone(),
        status: status.to_string(),
        detail: detail.to_string(),
        candidate_count,
        attempts: if status == "blocked" { 0 } else { 1 },
    }
}

fn candidate_matches_policy(
    candidate: &BackupTimerAlertCandidate,
    policy: &TimerAlertPolicy,
) -> bool {
    severity_rank(&candidate.severity)
        >= severity_rank(policy.min_severity.as_deref().unwrap_or("warning"))
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "error" => 3,
        "warning" | "warn" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn timer_alert_text(report: &BackupTimerMonitorReport) -> String {
    let mut lines = vec![
        "opsctl backup timer alert".to_string(),
        format!("status: {}", report.status),
        format!("timer_health: {}", report.health.status),
        format!("alert_candidates: {}", report.alert_candidates.len()),
    ];
    for candidate in &report.alert_candidates {
        lines.push(format!(
            "- [{}] {} {}: {}",
            candidate.severity, candidate.kind, candidate.id, candidate.reason
        ));
    }
    lines.join("\n")
}

fn timer_alert_json(report: &BackupTimerMonitorReport) -> Value {
    json!({
        "schema_version": "opsctl.backup_timer_alert.v1",
        "source": "opsctl",
        "status": report.status,
        "timer_health_status": report.health.status,
        "candidate_count": report.alert_candidates.len(),
        "candidates": report.alert_candidates,
    })
}

fn timer_alert_test_text() -> String {
    format!(
        "opsctl backup timer alert test\nstatus: test\nsent_at: {}",
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string())
    )
}

fn timer_alert_test_json() -> Value {
    json!({
        "schema_version": "opsctl.backup_timer_alert_test.v1",
        "source": "opsctl",
        "status": "test",
        "candidate_count": 1,
        "candidates": [
            {
                "severity": "info",
                "kind": "alert_test",
                "id": "manual",
                "reason": "operator requested alert sink test",
                "configured_alerts": []
            }
        ],
    })
}

fn validate_alert_url(target: &str) -> Result<()> {
    if target.chars().any(|character| character.is_control()) {
        anyhow::bail!("alert URL contains control characters");
    }
    let target = target.to_ascii_lowercase();
    if target.starts_with("https://") || is_loopback_http_url(&target) {
        return Ok(());
    }
    anyhow::bail!("alert URL must be https or loopback http")
}

fn validate_alert_sink_for_registry(policy: &TimerAlertPolicy) -> Result<()> {
    validate_alert_sink_id(&policy.id)?;
    match policy.provider.as_str() {
        "webhook" | "ntfy" | "telegram" | "email" => {}
        provider => anyhow::bail!("unsupported alert provider: {provider}"),
    }
    let target_env = policy
        .target_env
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("target_env is required"))?;
    validate_env_name(target_env)?;
    if policy.owner.trim().is_empty() {
        anyhow::bail!("owner is required");
    }
    match policy.status.as_str() {
        "active" | "disabled" => {}
        status => anyhow::bail!("alert sink status must be active or disabled, got {status}"),
    }
    if let Some(severity) = policy.min_severity.as_deref()
        && severity_rank(severity) == 0
    {
        anyhow::bail!("unsupported alert min_severity: {severity}");
    }
    if policy.provider == "telegram" {
        let Some(topic) = policy.topic.as_deref() else {
            anyhow::bail!("telegram alert sink requires --topic chat_id");
        };
        if header_or_topic_has_control_chars(topic) {
            anyhow::bail!("telegram topic contains control characters");
        }
    }
    if let Some(topic) = policy.topic.as_deref()
        && header_or_topic_has_control_chars(topic)
    {
        anyhow::bail!("alert topic contains control characters");
    }
    if let Some(notes) = policy.notes.as_deref() {
        if notes.chars().any(char::is_control) {
            anyhow::bail!("alert notes contain control characters");
        }
        if notes.contains("://") {
            anyhow::bail!("alert notes must not contain URLs; store secret targets in target_env");
        }
    }
    Ok(())
}

fn validate_alert_sink_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 80
        || id.contains("..")
        || id.chars().any(|character| {
            !(character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'
                || character == '_')
        })
    {
        anyhow::bail!("alert sink id must use lowercase letters, digits, '-' or '_'");
    }
    Ok(())
}

fn validate_env_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        anyhow::bail!("target_env is required");
    };
    if !(first.is_ascii_uppercase() || first == '_') {
        anyhow::bail!("target_env must start with an uppercase ASCII letter or underscore");
    }
    if chars.any(|character| {
        !(character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_')
    }) {
        anyhow::bail!(
            "target_env must contain only uppercase ASCII letters, digits, or underscore"
        );
    }
    Ok(())
}

fn planned_alert_sink_action<'a>(
    sinks: &'a [TimerAlertPolicy],
    sink: &TimerAlertPolicy,
) -> &'a str {
    let Some(existing) = sinks.iter().find(|existing| existing.id == sink.id) else {
        return "create";
    };
    if same_alert_sink(existing, sink) {
        "unchanged"
    } else {
        "update"
    }
}

fn same_alert_sink(left: &TimerAlertPolicy, right: &TimerAlertPolicy) -> bool {
    left.provider == right.provider
        && left.target_env == right.target_env
        && left.topic == right.topic
        && left.owner == right.owner
        && left.status == right.status
        && left.min_severity == right.min_severity
        && left.notes == right.notes
}

fn read_yaml_registry<T>(path: &Path, label: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    ensure_regular_file_or_missing_no_symlink(path, label)?;
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    serde_yaml::from_str::<T>(&raw)
        .with_context(|| format!("failed to parse {label} {}", path.display()))
}

fn write_yaml_registry<T>(path: &Path, value: &T, label: &str) -> Result<()>
where
    T: Serialize,
{
    let serialized =
        serde_yaml::to_string(value).with_context(|| format!("failed to serialize {label}"))?;
    write_registry_atomic(path, serialized.as_bytes(), label)
}

fn write_registry_atomic(path: &Path, contents: &[u8], label: &str) -> Result<()> {
    ensure_regular_file_or_missing_no_symlink(path, label)?;
    let temporary_path = registry_temporary_path(path);
    let mode = existing_file_mode(path);
    if let Err(error) = write_secure_file_with_mode(&temporary_path, contents, mode) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error).with_context(|| format!("failed to replace {label} {}", path.display()));
    }
    Ok(())
}

fn write_secure_file_with_mode(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(mode);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn existing_file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    fs::symlink_metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777)
        .unwrap_or(0o640)
}

#[cfg(not(unix))]
fn existing_file_mode(_path: &Path) -> u32 {
    0o640
}

fn ensure_regular_file_or_missing_no_symlink(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "refusing to read or write {label} symlink: {}",
                    path.display()
                );
            }
            if !metadata.is_file() {
                anyhow::bail!("{label} is not a regular file: {}", path.display());
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn registry_temporary_path(path: &Path) -> PathBuf {
    let timestamp = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("opsctl");
    path.with_file_name(format!(
        ".{file_name}.opsctl-{}-{timestamp}.tmp",
        process::id()
    ))
}

fn is_loopback_http_url(target: &str) -> bool {
    ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| {
            target == *prefix
                || target
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with('/') || suffix.starts_with(':'))
        })
}

fn secret_token_is_safe(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn header_or_topic_has_control_chars(value: &str) -> bool {
    value.chars().any(|character| character.is_control())
}

fn curl_config(target: &str, headers: &[(&str, &str)]) -> String {
    let mut config = vec![
        "fail".to_string(),
        "silent".to_string(),
        "show-error".to_string(),
        "request = \"POST\"".to_string(),
        format!("url = \"{}\"", curl_config_quote(target)),
    ];
    for (name, value) in headers {
        config.push(format!(
            "header = \"{}: {}\"",
            curl_config_quote(name),
            curl_config_quote(value)
        ));
    }
    config.join("\n")
}

fn append_curl_payload_path(config_path: &Path, payload_path: &Path) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(config_path)
        .with_context(|| format!("failed to open curl config {}", config_path.display()))?;
    writeln!(
        file,
        "\ndata-binary = \"@{}\"",
        curl_config_quote(&display_path(payload_path))
    )
    .with_context(|| format!("failed to update curl config {}", config_path.display()))?;
    Ok(())
}

fn curl_config_quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn write_alert_temp_file(prefix: &str, contents: &[u8]) -> Result<PathBuf> {
    let dir = env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..32 {
        let path = dir.join(format!(
            "opsctl-{prefix}-{}-{nanos}-{attempt}",
            process::id()
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(contents)
                    .with_context(|| format!("failed to write {}", path.display()))?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("failed to create {}", path.display()));
            }
        }
    }
    anyhow::bail!("failed to allocate alert temp file after repeated attempts")
}

fn remove_alert_temp_file(path: &Path) {
    let _ = fs::remove_file(path);
}

pub fn production_onboarding_check(
    options: &ProductionOnboardingOptions<'_>,
) -> ProductionOnboardingReport {
    let history = active_backup_target_history_status(options.registry);
    let mut services = Vec::new();
    let mut planned_commands = Vec::new();
    let onboarding_services = active_backup_target_services(options.registry);
    let onboarding_service_ids = onboarding_services
        .iter()
        .map(|service| service.id.clone())
        .collect::<Vec<_>>();
    let drill_suite_command = if onboarding_service_ids.is_empty() {
        None
    } else {
        Some(production_drill_suite_command(&onboarding_service_ids))
    };

    for service in onboarding_services {
        let run_command = format!("opsctl backup run {} --execute", service.id);
        planned_commands.push(run_command.clone());
        let mut commands = vec![run_command];
        if let Some(command) = &drill_suite_command {
            commands.push(command.clone());
        }
        match plan_backup(&BackupPlanOptions {
            registry: options.registry,
            service_id: &service.id,
            dry_run: true,
        }) {
            Ok(plan) => services.push(ProductionOnboardingService {
                service_id: service.id.clone(),
                backup_plan_status: plan.status,
                backup_history_status: history
                    .service_status
                    .get(&service.id)
                    .map(String::as_str)
                    .unwrap_or("missing")
                    .to_string(),
                missing_env: plan.missing_env,
                commands,
                limitations: combine_limitations(
                    plan.limitations,
                    history
                        .service_limitations
                        .get(&service.id)
                        .cloned()
                        .unwrap_or_default(),
                ),
            }),
            Err(error) => {
                commands.clear();
                services.push(ProductionOnboardingService {
                    service_id: service.id.clone(),
                    backup_plan_status: "blocked".to_string(),
                    backup_history_status: "missing".to_string(),
                    missing_env: Vec::new(),
                    commands,
                    limitations: vec![format!("backup plan failed: {error}")],
                });
            }
        }
    }
    if let Some(command) = &drill_suite_command {
        planned_commands.push(command.clone());
    }

    let repositories = referenced_active_repositories(options.registry)
        .into_iter()
        .map(|repository| {
            let command = format!("opsctl backup check {}", repository.id);
            planned_commands.push(command.clone());
            ProductionOnboardingRepository {
                repository_id: repository.id.clone(),
                provider: repository.provider.clone(),
                command,
            }
        })
        .collect::<Vec<_>>();

    let mut limitations = Vec::new();
    let import_check_status = options.import_dir.map(|import_dir| {
        let report = check_registry_import(import_dir, true);
        if !report.ok {
            limitations.push("registry import-check --scan-observed is not ready".to_string());
        }
        if report.ok {
            "ready".to_string()
        } else {
            "blocked".to_string()
        }
    });
    let promote_dry_run_status = options.import_dir.map(|import_dir| {
        planned_commands.push(format!(
            "opsctl registry import-check {} --scan-observed",
            display_path(import_dir)
        ));
        planned_commands.push(format!(
            "opsctl registry promote-import {} --dry-run --scan-observed",
            display_path(import_dir)
        ));
        match promote_registry_import(&RegistryPromoteImportOptions {
            import_dir,
            active_registry_dir: options.registry_dir,
            state_dir: options.state_dir,
            dry_run: true,
            scan_observed: true,
            allow_observed_drift: false,
            approval_token: None,
        }) {
            Ok(report) if report.ok => "ready_for_promotion".to_string(),
            Ok(_) => {
                limitations.push("registry promote-import --dry-run is blocked".to_string());
                "blocked".to_string()
            }
            Err(error) => {
                limitations.push(format!("registry promote-import --dry-run failed: {error}"));
                "error".to_string()
            }
        }
    });

    let services_ready = services
        .iter()
        .filter(|service| {
            service.backup_plan_status == "ready" && service.backup_history_status == "ready"
        })
        .count();
    let services_blocked = services.len().saturating_sub(services_ready);
    if services_blocked > 0 {
        limitations.push("one or more production backup service gates are blocked".to_string());
    }
    if history.status != "ready" {
        limitations.push("backup history gate is not ready".to_string());
    }

    ProductionOnboardingReport {
        ok: limitations.is_empty(),
        read_only: true,
        registry_dir: display_path(options.registry_dir),
        import_dir: options.import_dir.map(display_path),
        services_checked: services.len(),
        services_ready,
        services_blocked,
        repositories_checked: repositories.len(),
        backup_history_status: history.status,
        import_check_status,
        promote_dry_run_status,
        services,
        repositories,
        planned_commands,
        limitations,
    }
}

fn production_drill_suite_command(service_ids: &[String]) -> String {
    let mut command = "opsctl backup drill-suite".to_string();
    for service_id in service_ids {
        command.push_str(" --service ");
        command.push_str(service_id);
    }
    command.push_str(" --restore-root /var/lib/opsctl/restore-drills --execute");
    command
}

fn active_backup_target_services(registry: &Registry) -> Vec<&Service> {
    let service_ids = registry
        .backups
        .targets
        .iter()
        .filter(|target| target.status == "active")
        .map(|target| target.service_id.as_str())
        .collect::<BTreeSet<_>>();
    registry
        .services
        .services
        .iter()
        .filter(|service| service_ids.contains(service.id.as_str()))
        .collect()
}

fn active_backup_target_history_status(registry: &Registry) -> OnboardingHistoryStatus {
    let now = OffsetDateTime::now_utc();
    let mut service_limitations: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for target in registry
        .backups
        .targets
        .iter()
        .filter(|target| target.status == "active")
    {
        let mut limitations = Vec::new();
        check_latest_backup_record(registry, target, now, &mut limitations);
        check_latest_repository_check(registry, target, now, &mut limitations);
        check_latest_restore_drill(registry, target, now, &mut limitations);
        if !limitations.is_empty() {
            service_limitations
                .entry(target.service_id.clone())
                .or_default()
                .extend(limitations);
        } else {
            service_limitations
                .entry(target.service_id.clone())
                .or_default();
        }
    }

    let mut service_status = BTreeMap::new();
    for (service_id, limitations) in &mut service_limitations {
        limitations.sort();
        limitations.dedup();
        let status = if limitations.is_empty() {
            "ready"
        } else {
            "blocked"
        };
        service_status.insert(service_id.clone(), status.to_string());
    }

    let status =
        if !service_status.is_empty() && service_status.values().all(|status| status == "ready") {
            "ready"
        } else {
            "blocked"
        }
        .to_string();

    OnboardingHistoryStatus {
        status,
        service_status,
        service_limitations,
    }
}

fn check_latest_backup_record(
    registry: &Registry,
    target: &BackupTarget,
    now: OffsetDateTime,
    limitations: &mut Vec<String>,
) {
    let mut latest = None;
    for record in registry.backups.history.iter().filter(|record| {
        record.service_id == target.service_id
            && record.target_id == target.id
            && record
                .repository_id
                .as_deref()
                .is_none_or(|repository_id| repository_id == target.repository_id)
    }) {
        match parse_rfc3339(&record.completed_at) {
            Some(completed_at) => {
                if latest
                    .as_ref()
                    .is_none_or(|(_, latest_at)| completed_at > *latest_at)
                {
                    latest = Some((record, completed_at));
                }
            }
            None => limitations.push(format!(
                "backup history record {} has an invalid completed_at timestamp",
                record.id
            )),
        }
    }

    let Some((record, completed_at)) = latest else {
        limitations.push(format!("target {} has no backup history record", target.id));
        return;
    };
    if record.status != "success" {
        limitations.push(format!(
            "latest backup record {} for target {} finished with status {}",
            record.id, target.id, record.status
        ));
    }
    if record.repository_snapshot_id.is_none() {
        limitations.push(format!(
            "latest backup record {} for target {} has no repository snapshot id",
            record.id, target.id
        ));
    }
    push_time_limitations(
        "backup history record",
        &record.id,
        &target.id,
        completed_at,
        now,
        target.max_age_hours,
        limitations,
    );
}

fn check_latest_repository_check(
    registry: &Registry,
    target: &BackupTarget,
    now: OffsetDateTime,
    limitations: &mut Vec<String>,
) {
    let mut latest = None;
    for record in registry
        .backups
        .repository_checks
        .iter()
        .filter(|record| record.repository_id == target.repository_id)
    {
        match parse_rfc3339(&record.completed_at) {
            Some(completed_at) => {
                if latest
                    .as_ref()
                    .is_none_or(|(_, latest_at)| completed_at > *latest_at)
                {
                    latest = Some((record, completed_at));
                }
            }
            None => limitations.push(format!(
                "repository check record {} has an invalid completed_at timestamp",
                record.id
            )),
        }
    }

    let Some((record, completed_at)) = latest else {
        limitations.push(format!(
            "target {} repository {} has no repository check record",
            target.id, target.repository_id
        ));
        return;
    };
    if record.status != "success" {
        limitations.push(format!(
            "latest repository check {} for target {} finished with status {}",
            record.id, target.id, record.status
        ));
    }
    push_time_limitations(
        "repository check record",
        &record.id,
        &target.id,
        completed_at,
        now,
        Some(repository_check_max_age_hours(target)),
        limitations,
    );
}

fn check_latest_restore_drill(
    registry: &Registry,
    target: &BackupTarget,
    now: OffsetDateTime,
    limitations: &mut Vec<String>,
) {
    let mut latest = None;
    for record in
        registry.backups.restore_drills.iter().filter(|record| {
            record.service_id == target.service_id && record.target_id == target.id
        })
    {
        match parse_rfc3339(&record.completed_at) {
            Some(completed_at) => {
                if latest
                    .as_ref()
                    .is_none_or(|(_, latest_at)| completed_at > *latest_at)
                {
                    latest = Some((record, completed_at));
                }
            }
            None => limitations.push(format!(
                "restore drill record {} has an invalid completed_at timestamp",
                record.id
            )),
        }
    }

    let Some((record, completed_at)) = latest else {
        limitations.push(format!(
            "target {} has no registered restore drill",
            target.id
        ));
        return;
    };
    if record.status != "success" {
        limitations.push(format!(
            "latest restore drill {} for target {} finished with status {}",
            record.id, target.id, record.status
        ));
    }
    push_time_limitations(
        "restore drill record",
        &record.id,
        &target.id,
        completed_at,
        now,
        Some(restore_drill_max_age_hours(target)),
        limitations,
    );
}

fn push_time_limitations(
    record_kind: &str,
    record_id: &str,
    target_id: &str,
    completed_at: OffsetDateTime,
    now: OffsetDateTime,
    max_age_hours: Option<u32>,
    limitations: &mut Vec<String>,
) {
    if completed_at > now {
        limitations.push(format!(
            "{record_kind} {record_id} has a completed_at timestamp in the future"
        ));
    }
    if completed_at <= now
        && max_age_hours.is_some_and(|max_age_hours| {
            now - completed_at > TimeDuration::hours(i64::from(max_age_hours))
        })
    {
        limitations.push(format!(
            "{record_kind} {record_id} for target {target_id} is older than its max_age_hours policy"
        ));
    }
}

fn repository_check_max_age_hours(target: &BackupTarget) -> u32 {
    target
        .repository_check_max_age_hours
        .or(target.max_age_hours)
        .unwrap_or(DEFAULT_TRUST_MAX_AGE_HOURS)
}

fn restore_drill_max_age_hours(target: &BackupTarget) -> u32 {
    target
        .restore_drill_max_age_hours
        .or(target.max_age_hours)
        .unwrap_or(DEFAULT_TRUST_MAX_AGE_HOURS)
}

fn parse_rfc3339(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

fn combine_limitations(mut left: Vec<String>, right: Vec<String>) -> Vec<String> {
    left.extend(right);
    left.sort();
    left.dedup();
    left
}

fn referenced_active_repositories(registry: &Registry) -> Vec<&BackupRepository> {
    let repository_ids = registry
        .backups
        .targets
        .iter()
        .filter(|target| target.status == "active")
        .map(|target| target.repository_id.as_str())
        .collect::<BTreeSet<_>>();
    registry
        .backups
        .repositories
        .iter()
        .filter(|repository| repository.status == "active")
        .filter(|repository| repository_ids.contains(repository.id.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};

    use crate::{
        backup_schedule::{
            DrillCleanupOptions, backup_timer_plan, cleanup_restore_drills,
            production_onboarding_check, timer_health,
        },
        registry::Registry,
    };

    #[test]
    fn cleanup_restore_drills_dry_run_and_execute_are_scoped_to_run_dirs() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let service_dir = temp.path().join("restore-drills/pcafev2");
        std::fs::create_dir_all(service_dir.join("run-old"))?;
        std::fs::create_dir_all(service_dir.join("manual-note"))?;

        let dry_run = cleanup_restore_drills(&DrillCleanupOptions {
            state_dir: temp.path(),
            keep_days: 0,
            keep_count: 0,
            execute: false,
        });
        assert!(dry_run.ok);
        assert_eq!(dry_run.candidates, 1);
        assert!(service_dir.join("run-old").exists());

        let executed = cleanup_restore_drills(&DrillCleanupOptions {
            state_dir: temp.path(),
            keep_days: 0,
            keep_count: 0,
            execute: true,
        });
        assert!(executed.ok);
        assert_eq!(executed.deleted, 1);
        assert!(!service_dir.join("run-old").exists());
        assert!(service_dir.join("manual-note").exists());
        Ok(())
    }

    #[test]
    fn backup_timer_plan_reports_service_and_repository_units() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let report = backup_timer_plan(&crate::backup_schedule::BackupTimerOptions {
            registry: &registry,
            service_id: Some("pcafev2"),
            repository_id: None,
            execute: false,
            include_status: false,
        });

        assert!(report.ok);
        assert!(report.entries.iter().any(|entry| {
            entry.kind == "backup_run" && entry.timer_unit == "opsctl-backup-run@pcafev2.timer"
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.kind == "restore_drill"
                && entry.timer_unit == "opsctl-restore-drill@pcafev2.timer"
        }));
        Ok(())
    }

    #[test]
    fn timer_health_blocks_after_configured_consecutive_failures() -> Result<()> {
        let mut registry = Registry::load("examples/server-registry")?;
        let mut failed = registry
            .backups
            .history
            .iter()
            .find(|record| record.service_id == "rankfan-new" && record.status == "failed")
            .cloned()
            .context("example registry should include one failed rankfan backup")?;
        failed.id = "backup-rankfan-new-20260705".to_string();
        failed.completed_at = "2026-07-05T01:40:00Z".to_string();
        registry.backups.history.push(failed);

        let report = timer_health(&registry);
        let rankfan = report
            .services
            .iter()
            .find(|service| service.service_id == "rankfan-new")
            .context("rankfan timer health should be reported")?;

        assert_eq!(rankfan.backup_run_consecutive_failures, 2);
        assert_eq!(rankfan.status, "blocked");
        assert_eq!(report.status, "blocked");
        Ok(())
    }

    #[test]
    fn production_onboarding_check_is_read_only_and_reports_blocked_history() -> Result<()> {
        let mut registry = Registry::load("examples/server-registry")?;
        for target in &mut registry.backups.targets {
            if target.id == "mariadb-edu-rich-external" {
                target.status = "active".to_string();
            }
        }
        let temp = tempfile::TempDir::new()?;
        let report =
            production_onboarding_check(&crate::backup_schedule::ProductionOnboardingOptions {
                registry: &registry,
                registry_dir: "examples/server-registry".as_ref(),
                state_dir: temp.path(),
                import_dir: None,
            });

        assert!(report.read_only);
        assert!(!report.ok);
        assert_eq!(report.backup_history_status, "blocked");
        assert!(
            report
                .planned_commands
                .iter()
                .any(|command| command.contains("opsctl backup run pcafev2 --execute"))
        );
        assert!(
            report
                .planned_commands
                .iter()
                .any(|command| command.contains("opsctl backup run mariadb-edu-rich --execute"))
        );
        assert!(report.planned_commands.iter().any(|command| {
            command.contains("opsctl backup drill-suite")
                && command.contains("--service pcafev2")
                && command.contains("--service mariadb-edu-rich")
                && command.contains("--restore-root /var/lib/opsctl/restore-drills --execute")
        }));
        Ok(())
    }

    #[test]
    fn alert_url_validation_allows_https_and_exact_loopback_http_only() {
        assert!(super::validate_alert_url("https://alerts.example/hook").is_ok());
        assert!(super::validate_alert_url("http://127.0.0.1:8080/hook").is_ok());
        assert!(super::validate_alert_url("http://localhost/hook").is_ok());
        assert!(super::validate_alert_url("http://[::1]:8080/hook").is_ok());
        assert!(super::validate_alert_url("http://localhost.evil.example/hook").is_err());
        assert!(super::validate_alert_url("http://127.0.0.1.evil.example/hook").is_err());
        assert!(super::validate_alert_url("http://alerts.example/hook").is_err());
    }

    #[test]
    fn alert_activation_shell_hints_are_unambiguous_without_leaking_values() {
        assert_eq!(
            super::shell_hint("OPSCTL_TIMER_ALERT_WEBHOOK_URL"),
            "OPSCTL_TIMER_ALERT_WEBHOOK_URL"
        );
        assert_eq!(super::shell_hint(""), "''");
        assert_eq!(super::shell_hint("owner name"), "'owner name'");
        assert_eq!(super::shell_hint("owner's hook"), "'owner'\\''s hook'");
    }
}
