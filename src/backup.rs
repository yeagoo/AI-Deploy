use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::{
    command_runner, env_source,
    paths::display_path,
    registry::{
        BackupDatabaseDump, BackupHistoryRecord, BackupRepository, BackupRepositoryCheckRecord,
        BackupRestoreDatabaseDumpCheck, BackupRestoreDrillRecord, BackupRestoreHashSample,
        BackupRetention, BackupTarget, BackupsRegistry, Registry, Service,
    },
};

const RESTORE_VERIFY_MAX_FILES: usize = 50_000;
const RESTORE_VERIFY_HASH_SAMPLES: usize = 8;
const RESTORE_VERIFY_SQL_PREVIEW_BYTES: usize = 16 * 1024;
const DEFAULT_TRUST_MAX_AGE_HOURS: u32 = 168;

#[derive(Debug, Clone)]
pub struct BackupPlanOptions<'a> {
    pub registry: &'a Registry,
    pub service_id: &'a str,
    pub dry_run: bool,
}

#[derive(Debug, Clone)]
pub struct BackupRunOptions<'a> {
    pub registry: &'a Registry,
    pub registry_dir: &'a Path,
    pub service_id: &'a str,
    pub target_id: Option<&'a str>,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct BackupRepositoryActionOptions<'a> {
    pub registry: &'a Registry,
    pub registry_dir: Option<&'a Path>,
    pub repository_id: &'a str,
    pub service_id: Option<&'a str>,
    pub approval_token: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct BackupRepositoryInitOptions<'a> {
    pub registry: &'a Registry,
    pub repository_id: &'a str,
    pub execute: bool,
    pub approval_token: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct BackupRestoreOptions<'a> {
    pub registry: &'a Registry,
    pub registry_dir: Option<&'a Path>,
    pub service_id: &'a str,
    pub target_id: Option<&'a str>,
    pub repository_snapshot_id: &'a str,
    pub restore_dir: &'a Path,
    pub execute: bool,
    pub approval_token: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct BackupDrillOptions<'a> {
    pub registry: &'a Registry,
    pub registry_dir: Option<&'a Path>,
    pub service_id: &'a str,
    pub target_id: Option<&'a str>,
    pub repository_snapshot_id: Option<&'a str>,
    pub restore_dir: &'a Path,
    pub execute: bool,
    pub scheduled: bool,
    pub approval_token: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct BackupDrillSuiteOptions<'a> {
    pub registry: &'a Registry,
    pub registry_dir: Option<&'a Path>,
    pub service_ids: &'a [String],
    pub restore_root: &'a Path,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct BackupRefreshStaleOptions<'a> {
    pub registry: &'a Registry,
    pub registry_dir: &'a Path,
    pub service_ids: &'a [String],
    pub restore_root: &'a Path,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackupSeverity {
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupFinding {
    pub severity: BackupSeverity,
    pub code: String,
    pub message: String,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupDoctorReport {
    pub ok: bool,
    pub errors: usize,
    pub warnings: usize,
    pub repositories: usize,
    pub targets: usize,
    pub history: usize,
    pub findings: Vec<BackupFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupPlanReport {
    pub service_id: String,
    pub service_name: String,
    pub dry_run: bool,
    pub status: String,
    pub targets: Vec<BackupTargetPlan>,
    pub required_env: Vec<String>,
    pub missing_env: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupReadinessReport {
    pub ok: bool,
    pub status: String,
    pub dry_run: bool,
    pub services_checked: usize,
    pub ready: usize,
    pub blocked: usize,
    pub skipped: usize,
    pub required_env: Vec<String>,
    pub missing_env: Vec<String>,
    pub services: Vec<BackupServiceReadiness>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupHistoryReport {
    pub ok: bool,
    pub status: String,
    pub read_only: bool,
    pub services_checked: usize,
    pub services_ready: usize,
    pub services_blocked: usize,
    pub services_with_success: usize,
    pub services_missing_success: usize,
    pub skipped: usize,
    pub records: usize,
    pub freshness_policy_targets: usize,
    pub stale_targets: usize,
    pub future_records: usize,
    pub invalid_timestamps: usize,
    pub repository_checks: usize,
    pub repository_check_targets_blocked: usize,
    pub restore_drills: usize,
    pub restore_drill_targets_blocked: usize,
    pub services: Vec<BackupServiceHistory>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupServiceHistory {
    pub service_id: String,
    pub service_name: String,
    pub backup_policy: Option<String>,
    pub target_count: usize,
    pub latest_record_id: Option<String>,
    pub latest_status: Option<String>,
    pub latest_completed_at: Option<String>,
    pub successful_targets: usize,
    pub missing_success_targets: Vec<String>,
    pub freshness_policy_targets: usize,
    pub stale_targets: Vec<String>,
    pub future_record_ids: Vec<String>,
    pub invalid_record_ids: Vec<String>,
    pub repository_check_ready_targets: usize,
    pub repository_check_blocked_targets: Vec<String>,
    pub restore_drill_ready_targets: usize,
    pub restore_drill_blocked_targets: Vec<String>,
    pub status: String,
    pub records: usize,
    pub target_issues: Vec<BackupHistoryTargetIssue>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupHistoryTargetIssue {
    pub target_id: String,
    pub repository_id: String,
    pub issue: String,
    pub detail: String,
    pub max_age_hours: Option<u32>,
    pub latest_record_id: Option<String>,
    pub latest_status: Option<String>,
    pub latest_completed_at: Option<String>,
    pub remediation_commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupServiceReadiness {
    pub service_id: String,
    pub service_name: String,
    pub environment: String,
    pub backup_policy: Option<String>,
    pub status: String,
    pub target_count: usize,
    pub required_env: Vec<String>,
    pub missing_env: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupTargetPlan {
    pub target_id: String,
    pub repository_id: String,
    pub provider: String,
    pub status: String,
    pub repository_source: String,
    pub include_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub database_dump_outputs: Vec<String>,
    pub required_env: Vec<String>,
    pub missing_env: Vec<String>,
    pub operations: Vec<BackupOperation>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupOperation {
    pub order: u32,
    pub kind: String,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRunReport {
    pub service_id: String,
    pub execute: bool,
    pub status: String,
    pub targets: Vec<BackupRunTargetReport>,
    pub history_records: Vec<BackupHistoryRecord>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRunTargetReport {
    pub target_id: String,
    pub repository_id: String,
    pub status: String,
    pub operations: Vec<BackupRunOperationReport>,
    pub history_record_id: Option<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRunOperationReport {
    pub order: u32,
    pub kind: String,
    pub argv: Vec<String>,
    pub status: String,
    pub exit_code: Option<i32>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRepositoryActionReport {
    pub ok: bool,
    pub status: String,
    pub repository_id: String,
    pub provider: String,
    pub service_id: Option<String>,
    pub approval_required: bool,
    pub expected_approval_token: Option<String>,
    pub operations: Vec<BackupRunOperationReport>,
    pub repository_check_record: Option<BackupRepositoryCheckRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupDrillSuiteReport {
    pub ok: bool,
    pub execute: bool,
    pub restore_root: String,
    pub services_requested: Vec<String>,
    pub services_checked: usize,
    pub services_success: usize,
    pub services_blocked: usize,
    pub services_failed: usize,
    pub database_import_check_enabled: bool,
    pub reports: Vec<BackupRestoreReport>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRefreshStaleReport {
    pub ok: bool,
    pub execute: bool,
    pub read_only: bool,
    pub status: String,
    pub restore_root: String,
    pub services_checked: usize,
    pub services_blocked: usize,
    pub services_selected: usize,
    pub targets_planned: usize,
    pub repositories_planned: usize,
    pub backup_runs_success: usize,
    pub backup_runs_failed: usize,
    pub repository_checks_success: usize,
    pub repository_checks_failed: usize,
    pub drill_suite_status: Option<String>,
    pub planned_commands: Vec<String>,
    pub services: Vec<BackupRefreshStaleService>,
    pub repository_checks: Vec<BackupRefreshStaleRepositoryCheck>,
    pub drill_suite: Option<BackupDrillSuiteReport>,
    pub failure_summary: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRefreshStaleService {
    pub service_id: String,
    pub service_name: String,
    pub status: String,
    pub target_issues: Vec<BackupHistoryTargetIssue>,
    pub target_ids: Vec<String>,
    pub repository_ids: Vec<String>,
    pub planned_commands: Vec<String>,
    pub backup_runs: Vec<BackupRefreshStaleBackupRun>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRefreshStaleBackupRun {
    pub service_id: String,
    pub target_id: String,
    pub status: String,
    pub report: Option<BackupRunReport>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRefreshStaleRepositoryCheck {
    pub repository_id: String,
    pub status: String,
    pub command: String,
    pub report: Option<BackupRepositoryActionReport>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BackupS3SmokeOptions<'a> {
    pub endpoint: &'a str,
    pub region: &'a str,
    pub provider: &'a str,
    pub bucket: &'a str,
    pub prefix: Option<&'a str>,
    pub access_key_env: &'a str,
    pub secret_key_env: &'a str,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupS3SmokeReport {
    pub ok: bool,
    pub execute: bool,
    pub status: String,
    pub tool: String,
    pub endpoint: String,
    pub region: String,
    pub provider: String,
    pub bucket: String,
    pub prefix: String,
    pub object_key: String,
    pub required_env: Vec<String>,
    pub missing_env: Vec<String>,
    pub operations: Vec<BackupRunOperationReport>,
    pub payload_sha256: Option<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRestoreReport {
    pub ok: bool,
    pub service_id: String,
    pub target_id: String,
    pub repository_id: String,
    pub provider: String,
    pub repository_snapshot_id: String,
    pub restore_dir: String,
    pub execute: bool,
    pub status: String,
    pub approval_required: bool,
    pub expected_approval_token: Option<String>,
    pub required_env: Vec<String>,
    pub missing_env: Vec<String>,
    pub operations: Vec<BackupRunOperationReport>,
    pub verification: Option<BackupRestoreVerification>,
    pub restore_drill_record: Option<BackupRestoreDrillRecord>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRestoreVerification {
    pub files_checked: usize,
    pub bytes_checked: u64,
    pub sampled_hashes: Vec<BackupRestoreHashSample>,
    pub database_dump_checks: Vec<BackupRestoreDatabaseDumpCheck>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DatabaseDumpExecution {
    pub argv: Vec<String>,
    pub output_path: String,
    pub compressed: bool,
    pub duration_seconds: u64,
}

pub fn backup_doctor(registry: &Registry) -> BackupDoctorReport {
    let mut findings = Vec::new();

    check_unique_values(
        registry
            .backups
            .repositories
            .iter()
            .map(|repository| repository.id.as_str()),
        "duplicate_backup_repository_id",
        "duplicate backup repository id",
        &mut findings,
    );
    check_unique_values(
        registry
            .backups
            .targets
            .iter()
            .map(|target| target.id.as_str()),
        "duplicate_backup_target_id",
        "duplicate backup target id",
        &mut findings,
    );
    check_unique_values(
        registry
            .backups
            .history
            .iter()
            .map(|record| record.id.as_str()),
        "duplicate_backup_history_id",
        "duplicate backup history id",
        &mut findings,
    );

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
    let targets = registry
        .backups
        .targets
        .iter()
        .map(|target| (target.id.as_str(), target))
        .collect::<BTreeMap<_, _>>();

    for repository in &registry.backups.repositories {
        check_repository(repository, &mut findings);
    }

    for target in &registry.backups.targets {
        check_target(target, &services, &repositories, &mut findings);
    }

    for record in &registry.backups.history {
        check_history_record(record, &services, &targets, &repositories, &mut findings);
    }
    for record in &registry.backups.repository_checks {
        check_repository_check_record(record, &repositories, &mut findings);
    }
    for record in &registry.backups.restore_drills {
        check_restore_drill_record(record, &services, &targets, &repositories, &mut findings);
    }

    check_services_have_backup_targets(registry, &mut findings);

    let errors = findings
        .iter()
        .filter(|finding| finding.severity == BackupSeverity::Error)
        .count();
    let warnings = findings
        .iter()
        .filter(|finding| finding.severity == BackupSeverity::Warn)
        .count();

    BackupDoctorReport {
        ok: errors == 0,
        errors,
        warnings,
        repositories: registry.backups.repositories.len(),
        targets: registry.backups.targets.len(),
        history: registry.backups.history.len(),
        findings,
    }
}

pub fn plan_backup(options: &BackupPlanOptions<'_>) -> Result<BackupPlanReport> {
    if !options.dry_run {
        anyhow::bail!(
            "backup plan is dry-run only; use opsctl backup run {} to execute",
            options.service_id
        );
    }
    build_backup_plan(options.registry, options.service_id, options.dry_run)
}

fn build_backup_plan(
    registry: &Registry,
    service_id: &str,
    dry_run: bool,
) -> Result<BackupPlanReport> {
    let service = registry
        .services
        .services
        .iter()
        .find(|service| service.id == service_id)
        .with_context(|| format!("service not found: {service_id}"))?;
    let repositories = registry
        .backups
        .repositories
        .iter()
        .map(|repository| (repository.id.as_str(), repository))
        .collect::<BTreeMap<_, _>>();
    let active_targets = registry
        .backups
        .targets
        .iter()
        .filter(|target| target.service_id == service.id && target.status == "active")
        .collect::<Vec<_>>();

    let mut limitations = Vec::new();
    let mut target_plans = Vec::new();
    if active_targets.is_empty() {
        limitations.push(format!(
            "service {} has no active backup target",
            service_id
        ));
    }

    for target in active_targets {
        match repositories.get(target.repository_id.as_str()) {
            Some(repository) => target_plans.push(plan_target(service, target, repository)?),
            None => target_plans.push(missing_repository_plan(target)),
        }
    }

    let required_env = unique_sorted(
        target_plans
            .iter()
            .flat_map(|target| target.required_env.iter().cloned()),
    );
    let missing_env = unique_sorted(
        target_plans
            .iter()
            .flat_map(|target| target.missing_env.iter().cloned()),
    );
    let blocked =
        target_plans.is_empty() || target_plans.iter().any(|target| target.status == "blocked");
    let status = if blocked { "blocked" } else { "ready" }.to_string();

    Ok(BackupPlanReport {
        service_id: service.id.clone(),
        service_name: service.name.clone(),
        dry_run,
        status,
        targets: target_plans,
        required_env,
        missing_env,
        limitations,
    })
}

pub fn run_backup(options: &BackupRunOptions<'_>) -> Result<BackupRunReport> {
    let plan = build_backup_plan(options.registry, options.service_id, !options.execute)?;
    let service = service_by_id(options.registry, options.service_id)?;
    let selected_targets = plan
        .targets
        .iter()
        .filter(|target| {
            options
                .target_id
                .is_none_or(|target_id| target.target_id == target_id)
        })
        .collect::<Vec<_>>();
    if selected_targets.is_empty() {
        anyhow::bail!("backup target not found for service {}", options.service_id);
    }

    let mut target_reports = Vec::new();
    let mut history_records = Vec::new();
    let mut limitations = plan.limitations.clone();
    if plan.status != "ready" {
        limitations.push("backup plan is blocked; no command was executed".to_string());
    }

    for target in selected_targets {
        let report = if options.execute && target.status == "ready" && plan.status == "ready" {
            let source_target = options
                .registry
                .backups
                .targets
                .iter()
                .find(|candidate| candidate.id == target.target_id)
                .with_context(|| format!("backup target not found: {}", target.target_id))?;
            let repository = repository_by_id(options.registry, &source_target.repository_id)?;
            let (report, history_record) =
                execute_backup_target(&plan, target, source_target, repository, service)?;
            history_records.push(history_record);
            report
        } else {
            BackupRunTargetReport {
                target_id: target.target_id.clone(),
                repository_id: target.repository_id.clone(),
                status: if target.status == "ready" {
                    "dry_run".to_string()
                } else {
                    "blocked".to_string()
                },
                operations: target
                    .operations
                    .iter()
                    .map(|operation| BackupRunOperationReport {
                        order: operation.order,
                        kind: operation.kind.clone(),
                        argv: operation.argv.clone(),
                        status: "planned".to_string(),
                        exit_code: None,
                        detail: operation.detail.clone(),
                    })
                    .collect(),
                history_record_id: None,
                limitations: target.limitations.clone(),
            }
        };
        target_reports.push(report);
    }

    if options.execute && !history_records.is_empty() {
        append_backup_history(options.registry_dir, &history_records)?;
    }

    let status = if target_reports
        .iter()
        .any(|target| target.status == "failed")
    {
        "failed"
    } else if target_reports
        .iter()
        .any(|target| target.status == "blocked")
    {
        "blocked"
    } else if options.execute {
        "success"
    } else {
        "dry_run"
    }
    .to_string();

    Ok(BackupRunReport {
        service_id: plan.service_id,
        execute: options.execute,
        status,
        targets: target_reports,
        history_records,
        limitations,
    })
}

pub fn plan_backup_restore(options: &BackupRestoreOptions<'_>) -> Result<BackupRestoreReport> {
    let mut dry_run_options = options.clone();
    dry_run_options.execute = false;
    dry_run_options.approval_token = None;
    build_backup_restore_report(&dry_run_options)
}

pub fn backup_restore_drill(options: &BackupDrillOptions<'_>) -> Result<BackupRestoreReport> {
    let snapshot_id = resolve_drill_repository_snapshot_id(options)?;
    let scheduled_restore_dir;
    let restore_dir = if options.execute && options.scheduled {
        validate_scheduled_restore_drill_dir(options.restore_dir)?;
        scheduled_restore_dir = scheduled_restore_drill_run_dir(options.restore_dir);
        scheduled_restore_dir.as_path()
    } else {
        options.restore_dir
    };
    let scheduled_approval_token;
    let approval_token = if options.execute && options.scheduled {
        scheduled_approval_token = backup_restore_approval_token(
            options.service_id,
            restore_target(
                options.registry,
                service_by_id(options.registry, options.service_id)?,
                options.target_id,
            )?
            .id
            .as_str(),
            &snapshot_id,
        );
        Some(scheduled_approval_token.as_str())
    } else {
        options.approval_token
    };
    let restore_options = BackupRestoreOptions {
        registry: options.registry,
        registry_dir: options.registry_dir,
        service_id: options.service_id,
        target_id: options.target_id,
        repository_snapshot_id: &snapshot_id,
        restore_dir,
        execute: options.execute,
        approval_token,
    };
    if options.execute {
        restore_backup(&restore_options)
    } else {
        plan_backup_restore(&restore_options)
    }
}

pub fn backup_restore_drill_suite(options: &BackupDrillSuiteOptions<'_>) -> BackupDrillSuiteReport {
    let mut limitations = Vec::new();
    let service_ids = if options.service_ids.is_empty() {
        service_ids_with_active_backup_targets(options.registry)
    } else {
        unique_sorted(options.service_ids.iter().cloned())
    };
    if service_ids.is_empty() {
        limitations.push("no services selected for restore drill suite".to_string());
    }
    let mut reports = Vec::new();
    for service_id in &service_ids {
        let restore_dir = options.restore_root.join(service_id);
        match backup_restore_drill(&BackupDrillOptions {
            registry: options.registry,
            registry_dir: options.registry_dir,
            service_id,
            target_id: None,
            repository_snapshot_id: None,
            restore_dir: &restore_dir,
            execute: options.execute,
            scheduled: options.execute,
            approval_token: None,
        }) {
            Ok(report) => reports.push(report),
            Err(error) => reports.push(blocked_drill_suite_report(
                options.registry,
                service_id,
                &restore_dir,
                options.execute,
                error,
            )),
        }
    }

    let services_success = reports
        .iter()
        .filter(|report| {
            report.status == "success" || (!options.execute && report.status == "dry_run")
        })
        .count();
    let services_blocked = reports
        .iter()
        .filter(|report| report.status == "blocked")
        .count();
    let services_failed = reports
        .iter()
        .filter(|report| matches!(report.status.as_str(), "failed" | "partial"))
        .count();
    let ok = !service_ids.is_empty() && services_blocked == 0 && services_failed == 0;

    BackupDrillSuiteReport {
        ok,
        execute: options.execute,
        restore_root: display_path(options.restore_root),
        services_requested: service_ids,
        services_checked: reports.len(),
        services_success,
        services_blocked,
        services_failed,
        database_import_check_enabled: env_source::var_os("OPSCTL_RESTORE_DB_IMPORT_CHECK")
            .is_some(),
        reports,
        limitations,
    }
}

pub fn backup_refresh_stale(options: &BackupRefreshStaleOptions<'_>) -> BackupRefreshStaleReport {
    let history = backup_history(options.registry);
    let service_filter = options
        .service_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let known_services = options
        .registry
        .services
        .services
        .iter()
        .map(|service| service.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut limitations = options
        .service_ids
        .iter()
        .filter(|service_id| !known_services.contains(service_id.as_str()))
        .map(|service_id| format!("service {service_id} is not registered"))
        .collect::<Vec<_>>();

    let mut repository_ids = BTreeSet::new();
    let mut target_count = 0usize;
    let mut planned_commands = Vec::new();
    let mut selected_services = history
        .services
        .iter()
        .filter(|service| {
            service_filter.is_empty() || service_filter.contains(service.service_id.as_str())
        })
        .filter(|service| service.status == "blocked" && !service.target_issues.is_empty())
        .map(|service| {
            let target_ids = unique_sorted(
                service
                    .target_issues
                    .iter()
                    .map(|issue| issue.target_id.clone()),
            );
            let service_repository_ids = unique_sorted(
                service
                    .target_issues
                    .iter()
                    .map(|issue| issue.repository_id.clone()),
            );
            target_count += target_ids.len();
            repository_ids.extend(service_repository_ids.iter().cloned());
            let service_commands = backup_refresh_stale_commands(
                &service.service_id,
                &target_ids,
                &service_repository_ids,
                options.restore_root,
            );
            planned_commands.extend(service_commands.iter().cloned());
            BackupRefreshStaleService {
                service_id: service.service_id.clone(),
                service_name: service.service_name.clone(),
                status: "planned".to_string(),
                target_issues: service.target_issues.clone(),
                target_ids,
                repository_ids: service_repository_ids,
                planned_commands: service_commands,
                backup_runs: Vec::new(),
                limitations: service.limitations.clone(),
            }
        })
        .collect::<Vec<_>>();

    planned_commands = unique_sorted(planned_commands);
    let mut repository_checks = repository_ids
        .iter()
        .map(|repository_id| BackupRefreshStaleRepositoryCheck {
            repository_id: repository_id.clone(),
            status: "planned".to_string(),
            command: format!("opsctl backup check {}", command_hint_arg(repository_id)),
            report: None,
            error: None,
        })
        .collect::<Vec<_>>();
    let selected_service_ids = selected_services
        .iter()
        .map(|service| service.service_id.clone())
        .collect::<Vec<_>>();
    let mut drill_suite = if selected_service_ids.is_empty() {
        None
    } else {
        Some(backup_restore_drill_suite(&BackupDrillSuiteOptions {
            registry: options.registry,
            registry_dir: Some(options.registry_dir),
            service_ids: &selected_service_ids,
            restore_root: options.restore_root,
            execute: false,
        }))
    };
    let mut failure_summary = Vec::new();

    if options.execute {
        for service in &mut selected_services {
            let mut service_failed = false;
            for target_id in &service.target_ids {
                let run = match run_backup(&BackupRunOptions {
                    registry: options.registry,
                    registry_dir: options.registry_dir,
                    service_id: &service.service_id,
                    target_id: Some(target_id),
                    execute: true,
                }) {
                    Ok(report) => {
                        let status = report.status.clone();
                        if status != "success" {
                            service_failed = true;
                            failure_summary.push(format!(
                                "backup run {} target {} ended with status {}",
                                service.service_id, target_id, status
                            ));
                        }
                        BackupRefreshStaleBackupRun {
                            service_id: service.service_id.clone(),
                            target_id: target_id.clone(),
                            status,
                            report: Some(report),
                            error: None,
                        }
                    }
                    Err(error) => {
                        service_failed = true;
                        let message = error.to_string();
                        failure_summary.push(format!(
                            "backup run {} target {} failed: {}",
                            service.service_id, target_id, message
                        ));
                        BackupRefreshStaleBackupRun {
                            service_id: service.service_id.clone(),
                            target_id: target_id.clone(),
                            status: "failed".to_string(),
                            report: None,
                            error: Some(message),
                        }
                    }
                };
                service.backup_runs.push(run);
            }
            service.status = if service_failed {
                "failed".to_string()
            } else {
                "success".to_string()
            };
        }

        for repository_check in &mut repository_checks {
            match backup_repository_check(&BackupRepositoryActionOptions {
                registry: options.registry,
                registry_dir: Some(options.registry_dir),
                repository_id: &repository_check.repository_id,
                service_id: None,
                approval_token: None,
            }) {
                Ok(report) => {
                    repository_check.status = report.status.clone();
                    if !report.ok {
                        failure_summary.push(format!(
                            "repository check {} ended with status {}",
                            repository_check.repository_id, report.status
                        ));
                    }
                    repository_check.report = Some(report);
                }
                Err(error) => {
                    repository_check.status = "failed".to_string();
                    let message = error.to_string();
                    failure_summary.push(format!(
                        "repository check {} failed: {}",
                        repository_check.repository_id, message
                    ));
                    repository_check.error = Some(message);
                }
            }
        }

        if !selected_service_ids.is_empty() && failure_summary.is_empty() {
            match Registry::load(options.registry_dir) {
                Ok(refreshed_registry) => {
                    let report = backup_restore_drill_suite(&BackupDrillSuiteOptions {
                        registry: &refreshed_registry,
                        registry_dir: Some(options.registry_dir),
                        service_ids: &selected_service_ids,
                        restore_root: options.restore_root,
                        execute: true,
                    });
                    if !report.ok {
                        failure_summary.push(format!(
                            "restore drill suite ended with {} blocked and {} failed service(s)",
                            report.services_blocked, report.services_failed
                        ));
                    }
                    drill_suite = Some(report);
                }
                Err(error) => {
                    let message = format!(
                        "failed to reload registry before restore drill suite: {}",
                        error
                    );
                    failure_summary.push(message.clone());
                    limitations.push(message);
                    drill_suite = None;
                }
            }
        } else if !selected_service_ids.is_empty() {
            failure_summary.push(
                "restore drill suite skipped because an earlier backup refresh step failed"
                    .to_string(),
            );
            drill_suite = None;
        }
    }

    failure_summary = unique_sorted(failure_summary);
    limitations = unique_sorted(limitations);
    let backup_runs_success = selected_services
        .iter()
        .flat_map(|service| service.backup_runs.iter())
        .filter(|run| run.status == "success")
        .count();
    let backup_runs_failed = selected_services
        .iter()
        .flat_map(|service| service.backup_runs.iter())
        .filter(|run| matches!(run.status.as_str(), "failed" | "blocked"))
        .count();
    let repository_checks_success = repository_checks
        .iter()
        .filter(|check| check.status == "success")
        .count();
    let repository_checks_failed = repository_checks
        .iter()
        .filter(|check| matches!(check.status.as_str(), "failed" | "blocked"))
        .count();
    let drill_suite_status = drill_suite.as_ref().map(|report| {
        if report.ok {
            if report.execute { "success" } else { "planned" }
        } else {
            "blocked"
        }
        .to_string()
    });
    let status = if !limitations.is_empty() {
        "blocked"
    } else if selected_services.is_empty() {
        "ready"
    } else if !options.execute {
        "planned"
    } else if failure_summary.is_empty() {
        "success"
    } else {
        "failed"
    }
    .to_string();

    BackupRefreshStaleReport {
        ok: limitations.is_empty() && (!options.execute || failure_summary.is_empty()),
        execute: options.execute,
        read_only: !options.execute,
        status,
        restore_root: display_path(options.restore_root),
        services_checked: history.services_checked,
        services_blocked: history.services_blocked,
        services_selected: selected_services.len(),
        targets_planned: target_count,
        repositories_planned: repository_ids.len(),
        backup_runs_success,
        backup_runs_failed,
        repository_checks_success,
        repository_checks_failed,
        drill_suite_status,
        planned_commands,
        services: selected_services,
        repository_checks,
        drill_suite,
        failure_summary,
        limitations,
    }
}

pub fn restore_backup(options: &BackupRestoreOptions<'_>) -> Result<BackupRestoreReport> {
    let mut report = build_backup_restore_report(options)?;
    if !options.execute {
        return Ok(report);
    }

    let expected_token = report
        .expected_approval_token
        .clone()
        .context("backup restore approval token was not generated")?;
    if options.approval_token != Some(expected_token.as_str()) {
        anyhow::bail!("backup restore requires approval token: {expected_token}");
    }
    if report.status != "ready" {
        report.status = "blocked".to_string();
        report.ok = false;
        report.limitations.push(
            "backup restore is blocked; no repository restore command was executed".to_string(),
        );
        return Ok(report);
    }

    let Some(operation) = report.operations.first().cloned() else {
        anyhow::bail!("backup restore has no planned operation");
    };
    let service = service_by_id(options.registry, options.service_id)?;
    let target = restore_target(options.registry, service, options.target_id)?.clone();
    let repository = repository_by_id(options.registry, &target.repository_id)?.clone();
    let started_at = OffsetDateTime::now_utc();
    let executed = execute_restore_operation(operation, &repository)?;
    report.ok = executed.status == "success";
    report.status = if report.ok { "success" } else { "failed" }.to_string();
    report.operations = vec![executed];
    if report.ok {
        let verification = verify_restored_backup(options.restore_dir, &target)?;
        report.ok = verification.limitations.is_empty();
        if !report.ok {
            report.status = "partial".to_string();
            report.limitations.extend(verification.limitations.clone());
        }
        let drill_record = backup_restore_drill_record(BackupRestoreDrillInput {
            service,
            target: &target,
            repository: &repository,
            repository_snapshot_id: options.repository_snapshot_id,
            restore_dir: options.restore_dir,
            verification: &verification,
            started_at,
            status: &report.status,
        })?;
        if let Some(registry_dir) = options.registry_dir {
            append_restore_drill_history(registry_dir, &drill_record)?;
        }
        report.restore_drill_record = Some(drill_record);
        report.verification = Some(verification);
    }
    Ok(report)
}

fn build_backup_restore_report(options: &BackupRestoreOptions<'_>) -> Result<BackupRestoreReport> {
    let service = service_by_id(options.registry, options.service_id)?;
    validate_repository_snapshot_id(options.repository_snapshot_id)?;
    let target = restore_target(options.registry, service, options.target_id)?;
    let repository = repository_by_id(options.registry, &target.repository_id)?;
    let mut limitations = restore_limitations(options.registry, service, target, repository);
    limitations.extend(validate_restore_dir(
        options.registry,
        service,
        target,
        options.restore_dir,
    ));

    let required_env = required_env(repository);
    let missing_env = missing_env(repository);
    if !missing_env.is_empty() {
        limitations.push(format!(
            "backup repository {} is missing required environment variables: {}",
            repository.id,
            missing_env.join(", ")
        ));
    }

    let blocked = !limitations.is_empty();
    let status = if blocked {
        "blocked"
    } else if options.execute {
        "ready"
    } else {
        "dry_run"
    }
    .to_string();
    let provider = repository.provider.clone();
    let operation_status = if blocked { "blocked" } else { "planned" }.to_string();
    let operation = BackupRunOperationReport {
        order: 1,
        kind: format!("{provider}_restore"),
        argv: restic_restore_argv(
            repository,
            options.repository_snapshot_id,
            options.restore_dir,
        ),
        status: operation_status,
        exit_code: None,
        detail: format!(
            "Restore repository snapshot {} for target {} into staging directory {}.",
            options.repository_snapshot_id,
            target.id,
            display_path(options.restore_dir)
        ),
    };

    Ok(BackupRestoreReport {
        ok: !blocked,
        service_id: service.id.clone(),
        target_id: target.id.clone(),
        repository_id: repository.id.clone(),
        provider,
        repository_snapshot_id: options.repository_snapshot_id.to_string(),
        restore_dir: display_path(options.restore_dir),
        execute: options.execute,
        status,
        approval_required: true,
        expected_approval_token: Some(backup_restore_approval_token(
            &service.id,
            &target.id,
            options.repository_snapshot_id,
        )),
        required_env,
        missing_env,
        operations: vec![operation],
        verification: None,
        restore_drill_record: None,
        limitations,
    })
}

fn execute_backup_target(
    plan: &BackupPlanReport,
    target: &BackupTargetPlan,
    source_target: &BackupTarget,
    repository: &BackupRepository,
    service: &Service,
) -> Result<(BackupRunTargetReport, BackupHistoryRecord)> {
    let started_at = OffsetDateTime::now_utc();
    let mut operations = Vec::new();
    let mut limitations = Vec::new();
    let mut failed = false;
    let mut dump_index = 0usize;
    let mut repository_snapshot_id = None;

    for operation in &target.operations {
        if operation.kind == "check_env" {
            operations.push(BackupRunOperationReport {
                order: operation.order,
                kind: operation.kind.clone(),
                argv: operation.argv.clone(),
                status: "success".to_string(),
                exit_code: None,
                detail: operation.detail.clone(),
            });
            continue;
        }
        if operation.kind == "database_dump" {
            let Some(dump) = source_target.database_dumps.get(dump_index) else {
                failed = true;
                operations.push(BackupRunOperationReport {
                    order: operation.order,
                    kind: operation.kind.clone(),
                    argv: operation.argv.clone(),
                    status: "failed".to_string(),
                    exit_code: None,
                    detail: "database dump plan does not match target registry entry".to_string(),
                });
                break;
            };
            dump_index += 1;
            match execute_database_dump_for_service(service, dump, &dump.output_path) {
                Ok(execution) => operations.push(BackupRunOperationReport {
                    order: operation.order,
                    kind: operation.kind.clone(),
                    argv: execution.argv,
                    status: "success".to_string(),
                    exit_code: Some(0),
                    detail: format!(
                        "database dump written to {}",
                        display_path(&dump.output_path)
                    ),
                }),
                Err(error) => {
                    failed = true;
                    limitations.push(format!("database dump {} failed: {error}", dump.id));
                    operations.push(BackupRunOperationReport {
                        order: operation.order,
                        kind: operation.kind.clone(),
                        argv: operation.argv.clone(),
                        status: "failed".to_string(),
                        exit_code: None,
                        detail: format!("database dump {} failed", dump.id),
                    });
                    break;
                }
            }
            continue;
        }
        if !is_backup_execution_operation(&operation.kind) {
            operations.push(BackupRunOperationReport {
                order: operation.order,
                kind: operation.kind.clone(),
                argv: operation.argv.clone(),
                status: "skipped".to_string(),
                exit_code: None,
                detail: "operation is not executable by backup run".to_string(),
            });
            continue;
        }
        let Some((program, args)) = operation.argv.split_first() else {
            failed = true;
            operations.push(BackupRunOperationReport {
                order: operation.order,
                kind: operation.kind.clone(),
                argv: operation.argv.clone(),
                status: "failed".to_string(),
                exit_code: None,
                detail: "operation argv is empty".to_string(),
            });
            continue;
        };
        let captured = command_runner::run_controlled_with_env(
            program,
            args,
            &repository_command_env(repository),
        )?;
        if !captured.success() {
            failed = true;
            limitations.push(format!(
                "{} failed: {}",
                operation.kind,
                safe_repository_failure_reason(&captured.stdout, &captured.stderr)
            ));
        } else if operation.kind.ends_with("_backup") {
            repository_snapshot_id = parse_repository_snapshot_id(&captured.stdout);
        }
        operations.push(BackupRunOperationReport {
            order: operation.order,
            kind: operation.kind.clone(),
            argv: operation.argv.clone(),
            status: if captured.success() {
                "success"
            } else {
                "failed"
            }
            .to_string(),
            exit_code: captured.status_code,
            detail: operation.detail.clone(),
        });
        if failed {
            break;
        }
    }

    let status = if failed { "failed" } else { "success" }.to_string();
    let history_record_id = backup_history_id(&target.target_id, started_at)?;
    let history_record = BackupHistoryRecord {
        id: history_record_id.clone(),
        service_id: plan.service_id.clone(),
        target_id: target.target_id.clone(),
        repository_id: Some(target.repository_id.clone()),
        tool: target.provider.clone(),
        completed_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("failed to format backup completion timestamp")?,
        status: status.clone(),
        repository_snapshot_id,
        duration_seconds: Some(
            (OffsetDateTime::now_utc() - started_at)
                .whole_seconds()
                .max(0) as u64,
        ),
        bytes_processed: None,
        limitations: limitations.clone(),
        notes: Some("Recorded by opsctl backup run.".to_string()),
    };
    let mut report = BackupRunTargetReport {
        target_id: target.target_id.clone(),
        repository_id: target.repository_id.clone(),
        status,
        operations,
        history_record_id: Some(history_record_id),
        limitations,
    };
    if history_record.repository_snapshot_id.is_none() && history_record.status == "success" {
        report
            .limitations
            .push("restic snapshot id was not parsed from command output".to_string());
    }
    Ok((report, history_record))
}

pub(crate) fn parse_repository_snapshot_id(stdout: &str) -> Option<String> {
    let words = stdout.split_whitespace().collect::<Vec<_>>();
    for window in words.windows(3).rev() {
        if window[0] == "snapshot" && is_snapshot_like_token(window[1]) && window[2] == "saved" {
            return Some(window[1].to_string());
        }
    }
    for window in words.windows(2).rev() {
        if window[0] == "snapshot" && is_snapshot_like_token(window[1]) {
            return Some(window[1].to_string());
        }
    }
    None
}

fn is_snapshot_like_token(value: &str) -> bool {
    value.len() >= 6
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '_'
        })
}

fn append_backup_history(registry_dir: &Path, records: &[BackupHistoryRecord]) -> Result<()> {
    let path = registry_dir.join("backups.yml");
    ensure_regular_file_no_symlink(&path)?;
    let permissions = registry_file_permissions(&path)?;
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read backup registry {}", path.display()))?;
    let mut registry = serde_yaml::from_str::<BackupsRegistry>(&raw)
        .with_context(|| format!("failed to parse backup registry {}", path.display()))?;
    registry.history.extend(records.iter().cloned());
    let serialized =
        serde_yaml::to_string(&registry).context("failed to serialize backup registry")?;
    let temporary_path = backup_history_temp_path(&path);
    if let Err(error) = write_secure_file(&temporary_path, serialized.as_bytes()) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    fs::rename(&temporary_path, &path)
        .with_context(|| format!("failed to replace {}", path.display()))?;
    restore_registry_file_permissions(&path, permissions)?;
    Ok(())
}

fn ensure_regular_file_no_symlink(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to read backup registry symlink: {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        anyhow::bail!("backup registry is not a regular file: {}", path.display());
    }
    Ok(())
}

#[cfg(unix)]
fn registry_file_permissions(path: &Path) -> Result<u32> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to inspect {}", path.display()))?;
    Ok(metadata.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn registry_file_permissions(_path: &Path) -> Result<u32> {
    Ok(0)
}

#[cfg(unix)]
fn restore_registry_file_permissions(path: &Path, permissions: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(permissions))
        .with_context(|| format!("failed to restore permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restore_registry_file_permissions(_path: &Path, _permissions: u32) -> Result<()> {
    Ok(())
}

fn backup_history_temp_path(path: &Path) -> PathBuf {
    let timestamp = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("backups.yml");
    path.with_file_name(format!(
        ".{file_name}.opsctl-{}-{timestamp}.tmp",
        std::process::id()
    ))
}

fn write_secure_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = create_secure_file(path)?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn backup_history_id(target_id: &str, timestamp: OffsetDateTime) -> Result<String> {
    Ok(format!(
        "backup-{}-{}",
        sanitize_id_part(target_id),
        timestamp
            .format(&time::macros::format_description!(
                "[year][month][day][hour][minute][second]"
            ))
            .context("failed to format backup history id timestamp")?
    ))
}

fn sanitize_id_part(raw: &str) -> String {
    let mut sanitized = String::new();
    for character in raw.chars() {
        if character.is_ascii_alphanumeric() {
            sanitized.push(character.to_ascii_lowercase());
        } else if character == '-' || character == '_' {
            sanitized.push(character);
        } else {
            sanitized.push('_');
        }
    }
    let sanitized = sanitized.trim_matches(|character| character == '_' || character == '-');
    if sanitized.is_empty() {
        "backup".to_string()
    } else {
        sanitized.to_string()
    }
}

pub fn backup_readiness(registry: &Registry) -> BackupReadinessReport {
    let mut services = Vec::new();
    let mut skipped = 0usize;

    for service in &registry.services.services {
        if !requires_before_deploy_backup(service) {
            skipped += 1;
            continue;
        }

        match plan_backup(&BackupPlanOptions {
            registry,
            service_id: &service.id,
            dry_run: true,
        }) {
            Ok(plan) => {
                let limitations = unique_sorted(
                    plan.limitations.iter().cloned().chain(
                        plan.targets
                            .iter()
                            .flat_map(|target| target.limitations.iter().cloned()),
                    ),
                );
                services.push(BackupServiceReadiness {
                    service_id: service.id.clone(),
                    service_name: service.name.clone(),
                    environment: service.environment.clone(),
                    backup_policy: service.backup_policy.clone(),
                    status: plan.status,
                    target_count: plan.targets.len(),
                    required_env: plan.required_env,
                    missing_env: plan.missing_env,
                    limitations,
                });
            }
            Err(error) => services.push(BackupServiceReadiness {
                service_id: service.id.clone(),
                service_name: service.name.clone(),
                environment: service.environment.clone(),
                backup_policy: service.backup_policy.clone(),
                status: "blocked".to_string(),
                target_count: 0,
                required_env: Vec::new(),
                missing_env: Vec::new(),
                limitations: vec![format!("backup dry-run planning failed: {error}")],
            }),
        }
    }

    let ready = services
        .iter()
        .filter(|service| service.status == "ready")
        .count();
    let blocked = services
        .iter()
        .filter(|service| service.status != "ready")
        .count();
    let required_env = unique_sorted(
        services
            .iter()
            .flat_map(|service| service.required_env.iter().cloned()),
    );
    let missing_env = unique_sorted(
        services
            .iter()
            .flat_map(|service| service.missing_env.iter().cloned()),
    );
    let status = if blocked == 0 { "ready" } else { "blocked" }.to_string();

    BackupReadinessReport {
        ok: blocked == 0,
        status,
        dry_run: true,
        services_checked: services.len(),
        ready,
        blocked,
        skipped,
        required_env,
        missing_env,
        services,
    }
}

struct ParsedBackupRecord<'a> {
    record: &'a BackupHistoryRecord,
    completed_at: OffsetDateTime,
}

struct ParsedRepositoryCheck<'a> {
    record: &'a BackupRepositoryCheckRecord,
    completed_at: OffsetDateTime,
}

struct ParsedRestoreDrill<'a> {
    record: &'a BackupRestoreDrillRecord,
    completed_at: OffsetDateTime,
}

pub fn backup_history(registry: &Registry) -> BackupHistoryReport {
    backup_history_at(registry, OffsetDateTime::now_utc())
}

pub fn backup_history_at(registry: &Registry, now_utc: OffsetDateTime) -> BackupHistoryReport {
    let mut services = Vec::new();
    let mut skipped = 0usize;
    let (repository_checks, _) = parsed_repository_checks(&registry.backups.repository_checks);
    let (restore_drills, _) = parsed_restore_drills(&registry.backups.restore_drills);

    for service in &registry.services.services {
        if !requires_before_deploy_backup(service) {
            skipped += 1;
            continue;
        }

        let active_targets = registry
            .backups
            .targets
            .iter()
            .filter(|target| target.service_id == service.id && target.status == "active")
            .collect::<Vec<_>>();
        let service_records = registry
            .backups
            .history
            .iter()
            .filter(|record| record.service_id == service.id)
            .collect::<Vec<_>>();
        let mut valid_records = Vec::new();
        let mut invalid_record_ids = Vec::new();
        for record in &service_records {
            match parse_completed_at(record) {
                Ok(completed_at) => valid_records.push(ParsedBackupRecord {
                    record,
                    completed_at,
                }),
                Err(_) => invalid_record_ids.push(record.id.clone()),
            }
        }
        let latest = valid_records
            .iter()
            .max_by(|left, right| left.completed_at.cmp(&right.completed_at));
        let latest_record = latest.map(|record| record.record);

        let mut freshness_policy_targets = 0usize;
        let mut stale_targets = Vec::new();
        let mut future_record_ids = Vec::new();
        let mut missing_success_targets = Vec::new();
        let mut repository_check_ready_targets = 0usize;
        let mut repository_check_blocked_targets = Vec::new();
        let mut restore_drill_ready_targets = 0usize;
        let mut restore_drill_blocked_targets = Vec::new();
        let mut target_issues = Vec::new();
        let mut limitations = Vec::new();

        for target in &active_targets {
            let latest_target = latest_target_record(&valid_records, &target.id);
            let Some(latest_target) = latest_target else {
                missing_success_targets.push(target.id.clone());
                target_issues.push(backup_history_target_issue(
                    service.id.as_str(),
                    target,
                    "missing_success",
                    format!(
                        "target {} has no registered backup history record",
                        target.id
                    ),
                    None,
                    target.max_age_hours,
                ));
                continue;
            };

            if latest_target.record.status != "success" {
                missing_success_targets.push(target.id.clone());
                target_issues.push(backup_history_target_issue(
                    service.id.as_str(),
                    target,
                    "latest_backup_not_success",
                    format!(
                        "latest backup record {} for target {} finished with status {}",
                        latest_target.record.id, target.id, latest_target.record.status
                    ),
                    Some(latest_target),
                    target.max_age_hours,
                ));
            }

            if latest_target.completed_at > now_utc {
                future_record_ids.push(latest_target.record.id.clone());
                target_issues.push(backup_history_target_issue(
                    service.id.as_str(),
                    target,
                    "future_backup_timestamp",
                    format!(
                        "backup history record {} for target {} has a completed_at timestamp in the future",
                        latest_target.record.id, target.id
                    ),
                    Some(latest_target),
                    target.max_age_hours,
                ));
            }

            if let Some(max_age_hours) = target.max_age_hours {
                freshness_policy_targets += 1;
                if latest_target.completed_at <= now_utc {
                    let max_age = Duration::hours(i64::from(max_age_hours));
                    if now_utc - latest_target.completed_at > max_age {
                        stale_targets.push(target.id.clone());
                        target_issues.push(backup_history_target_issue(
                            service.id.as_str(),
                            target,
                            "stale_backup",
                            format!(
                                "target {} latest successful backup {} completed at {} is older than max_age_hours={}",
                                target.id,
                                latest_target.record.id,
                                latest_target.record.completed_at,
                                max_age_hours
                            ),
                            Some(latest_target),
                            Some(max_age_hours),
                        ));
                    }
                }
            }

            let check_age = repository_check_max_age_hours(target);
            match latest_repository_check(&repository_checks, &target.repository_id) {
                Some(check) if repository_check_record_ready(check, now_utc, check_age) => {
                    repository_check_ready_targets += 1;
                }
                Some(check) => {
                    repository_check_blocked_targets.push(target.id.clone());
                    target_issues.push(repository_check_target_issue(
                        service.id.as_str(),
                        target,
                        check,
                        now_utc,
                        check_age,
                    ));
                    push_repository_check_limitation(
                        check,
                        now_utc,
                        check_age,
                        &mut limitations,
                        &target.id,
                    );
                }
                None => {
                    repository_check_blocked_targets.push(target.id.clone());
                    target_issues.push(BackupHistoryTargetIssue {
                        target_id: target.id.clone(),
                        repository_id: target.repository_id.clone(),
                        issue: "missing_repository_check".to_string(),
                        detail: format!(
                            "target {} repository {} has no registered repository check record",
                            target.id, target.repository_id
                        ),
                        max_age_hours: Some(check_age),
                        latest_record_id: None,
                        latest_status: None,
                        latest_completed_at: None,
                        remediation_commands: backup_history_remediation_commands(
                            service.id.as_str(),
                            target,
                        ),
                    });
                    limitations.push(format!(
                        "target {} repository {} has no registered repository check record",
                        target.id, target.repository_id
                    ));
                }
            }
            for record_id in invalid_repository_check_ids_for_repository(
                &registry.backups.repository_checks,
                &target.repository_id,
            ) {
                repository_check_blocked_targets.push(target.id.clone());
                limitations.push(format!(
                    "repository check record {record_id} has an invalid completed_at timestamp"
                ));
            }

            let drill_age = restore_drill_max_age_hours(target);
            match latest_restore_drill(&restore_drills, service.id.as_str(), &target.id) {
                Some(drill) if restore_drill_record_ready(drill, now_utc, drill_age) => {
                    restore_drill_ready_targets += 1;
                }
                Some(drill) => {
                    restore_drill_blocked_targets.push(target.id.clone());
                    target_issues.push(restore_drill_target_issue(
                        service.id.as_str(),
                        target,
                        drill,
                        now_utc,
                        drill_age,
                    ));
                    push_restore_drill_limitation(
                        drill,
                        now_utc,
                        drill_age,
                        &mut limitations,
                        &target.id,
                    );
                }
                None => {
                    restore_drill_blocked_targets.push(target.id.clone());
                    target_issues.push(BackupHistoryTargetIssue {
                        target_id: target.id.clone(),
                        repository_id: target.repository_id.clone(),
                        issue: "missing_restore_drill".to_string(),
                        detail: format!(
                            "target {} has no registered successful restore drill",
                            target.id
                        ),
                        max_age_hours: Some(drill_age),
                        latest_record_id: None,
                        latest_status: None,
                        latest_completed_at: None,
                        remediation_commands: backup_history_remediation_commands(
                            service.id.as_str(),
                            target,
                        ),
                    });
                    limitations.push(format!(
                        "target {} has no registered successful restore drill",
                        target.id
                    ));
                }
            }
            for record_id in invalid_restore_drill_ids_for_target(
                &registry.backups.restore_drills,
                service.id.as_str(),
                &target.id,
            ) {
                restore_drill_blocked_targets.push(target.id.clone());
                limitations.push(format!(
                    "restore drill record {record_id} has an invalid completed_at timestamp"
                ));
            }
        }

        let missing_success_targets = unique_sorted(missing_success_targets);
        let stale_targets = unique_sorted(stale_targets);
        let future_record_ids = unique_sorted(future_record_ids);
        let invalid_record_ids = unique_sorted(invalid_record_ids);
        let repository_check_blocked_targets = unique_sorted(repository_check_blocked_targets);
        let restore_drill_blocked_targets = unique_sorted(restore_drill_blocked_targets);

        let latest = latest_record;
        if active_targets.is_empty() {
            limitations.push(format!(
                "service {} has no active backup target",
                service.id
            ));
        }
        for target in &active_targets {
            if let Some(record) = latest_target_record(&valid_records, &target.id)
                && record.record.status != "success"
            {
                limitations.push(format!(
                    "latest backup record {} for target {} finished with status {}",
                    record.record.id, target.id, record.record.status
                ));
                limitations.extend(record.record.limitations.iter().cloned());
            }
        }
        for target_id in &stale_targets {
            limitations.push(format!(
                "latest successful backup for target {target_id} is older than its max_age_hours policy"
            ));
        }
        for record_id in &future_record_ids {
            limitations.push(format!(
                "backup history record {record_id} has a completed_at timestamp in the future"
            ));
        }
        for record_id in &invalid_record_ids {
            limitations.push(format!(
                "backup history record {record_id} has an invalid completed_at timestamp"
            ));
        }
        limitations = unique_sorted(limitations);

        let successful_targets = active_targets.len() - missing_success_targets.len();
        let status = if active_targets.is_empty()
            || !missing_success_targets.is_empty()
            || !stale_targets.is_empty()
            || !future_record_ids.is_empty()
            || !invalid_record_ids.is_empty()
            || !repository_check_blocked_targets.is_empty()
            || !restore_drill_blocked_targets.is_empty()
        {
            "blocked"
        } else {
            "ready"
        }
        .to_string();

        services.push(BackupServiceHistory {
            service_id: service.id.clone(),
            service_name: service.name.clone(),
            backup_policy: service.backup_policy.clone(),
            target_count: active_targets.len(),
            latest_record_id: latest.map(|record| record.id.clone()),
            latest_status: latest.map(|record| record.status.clone()),
            latest_completed_at: latest.map(|record| record.completed_at.clone()),
            successful_targets,
            missing_success_targets,
            freshness_policy_targets,
            stale_targets,
            future_record_ids,
            invalid_record_ids,
            repository_check_ready_targets,
            repository_check_blocked_targets,
            restore_drill_ready_targets,
            restore_drill_blocked_targets,
            status,
            records: service_records.len(),
            target_issues: unique_backup_history_target_issues(target_issues),
            limitations,
        });
    }

    let services_ready = services
        .iter()
        .filter(|service| service.status == "ready")
        .count();
    let services_blocked = services.len() - services_ready;
    let services_with_success = services
        .iter()
        .filter(|service| service.target_count > 0 && service.missing_success_targets.is_empty())
        .count();
    let services_missing_success = services.len() - services_with_success;
    let freshness_policy_targets = services
        .iter()
        .map(|service| service.freshness_policy_targets)
        .sum();
    let stale_targets = services
        .iter()
        .map(|service| service.stale_targets.len())
        .sum();
    let future_records = services
        .iter()
        .map(|service| service.future_record_ids.len())
        .sum();
    let invalid_timestamps = services
        .iter()
        .map(|service| service.invalid_record_ids.len())
        .sum();
    let repository_check_targets_blocked = services
        .iter()
        .map(|service| service.repository_check_blocked_targets.len())
        .sum();
    let restore_drill_targets_blocked = services
        .iter()
        .map(|service| service.restore_drill_blocked_targets.len())
        .sum();
    let status = if services_blocked == 0 {
        "ready"
    } else {
        "blocked"
    }
    .to_string();

    BackupHistoryReport {
        ok: services_blocked == 0,
        status,
        read_only: true,
        services_checked: services.len(),
        services_ready,
        services_blocked,
        services_with_success,
        services_missing_success,
        skipped,
        records: registry.backups.history.len(),
        freshness_policy_targets,
        stale_targets,
        future_records,
        invalid_timestamps,
        repository_checks: registry.backups.repository_checks.len(),
        repository_check_targets_blocked,
        restore_drills: registry.backups.restore_drills.len(),
        restore_drill_targets_blocked,
        services,
    }
}

fn check_repository(repository: &BackupRepository, findings: &mut Vec<BackupFinding>) {
    if repository.status != "active" {
        return;
    }

    if !is_supported_backup_provider(&repository.provider) {
        findings.push(warn(
            "backup_provider_not_planned",
            format!(
                "provider {} is registered but the current release only plans restic/rustic commands",
                repository.provider
            ),
            Some(repository.id.clone()),
        ));
        return;
    }

    if repository.repository.is_none() && repository.repository_env.is_none() {
        findings.push(error(
            "restic_repository_missing",
            "restic repository must set repository or repository_env".to_string(),
            Some(repository.id.clone()),
        ));
    }
    if repository.password_env.is_none() {
        findings.push(error(
            "restic_password_env_missing",
            "restic repository must set password_env".to_string(),
            Some(repository.id.clone()),
        ));
    }
    for name in required_env(repository) {
        if env_source::var_os(&name).is_none() {
            findings.push(warn(
                "backup_env_missing",
                format!("environment variable {name} is not set for backup planning"),
                Some(repository.id.clone()),
            ));
        }
    }
}

fn check_target(
    target: &BackupTarget,
    services: &BTreeMap<&str, &Service>,
    repositories: &BTreeMap<&str, &BackupRepository>,
    findings: &mut Vec<BackupFinding>,
) {
    if !services.contains_key(target.service_id.as_str()) {
        findings.push(error(
            "backup_target_missing_service",
            format!(
                "backup target references unknown service {}",
                target.service_id
            ),
            Some(target.id.clone()),
        ));
    }
    if !repositories.contains_key(target.repository_id.as_str()) {
        findings.push(error(
            "backup_target_missing_repository",
            format!(
                "backup target references unknown repository {}",
                target.repository_id
            ),
            Some(target.id.clone()),
        ));
    }
    if target.status == "active" && target.include_paths.is_empty() {
        findings.push(error(
            "backup_target_empty_paths",
            "active backup target must include at least one path".to_string(),
            Some(target.id.clone()),
        ));
    }
    for path in target
        .include_paths
        .iter()
        .chain(target.exclude_paths.iter())
        .chain(target.database_dumps.iter().map(|dump| &dump.output_path))
    {
        if !path.is_absolute() || has_parent_component(path) {
            findings.push(error(
                "backup_target_unsafe_path",
                format!(
                    "backup target path must be absolute without parent traversal: {}",
                    display_path(path)
                ),
                Some(target.id.clone()),
            ));
        }
    }
    for dump in &target.database_dumps {
        match services.get(target.service_id.as_str()) {
            Some(service) => match validate_database_dump(service, dump) {
                Ok(()) => {
                    check_external_dump_package_script(service, dump, &target.id, findings);
                    check_database_engine_consistency(service, target, dump, findings);
                }
                Err(dump_error) => findings.push(error(
                    "backup_database_dump_invalid",
                    dump_error.to_string(),
                    Some(target.id.clone()),
                )),
            },
            None if !is_supported_database_dump_kind(&dump.kind) => findings.push(error(
                "backup_database_dump_invalid",
                format!(
                    "database dump kind {} is not executable; use mariadb, mysql, postgres, or external",
                    dump.kind
                ),
                Some(target.id.clone()),
            )),
            None => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DatabaseEngineFamily {
    Mysql,
    Postgres,
}

#[derive(Debug, Clone)]
struct DatabaseEngineHint {
    family: DatabaseEngineFamily,
    label: &'static str,
    source: String,
}

fn check_database_engine_consistency(
    service: &Service,
    target: &BackupTarget,
    dump: &BackupDatabaseDump,
    findings: &mut Vec<BackupFinding>,
) {
    let Some(declared) = database_dump_import_kind(dump).and_then(database_engine_family) else {
        return;
    };
    let hints = database_engine_hints(service, dump);
    let conflicts = hints
        .iter()
        .filter(|hint| hint.family != declared)
        .collect::<Vec<_>>();
    if conflicts.is_empty() {
        return;
    }

    let detail = conflicts
        .iter()
        .take(4)
        .map(|hint| format!("{} indicates {}", hint.source, hint.label))
        .collect::<Vec<_>>()
        .join("; ");
    findings.push(warn(
        "backup_database_engine_mismatch",
        format!(
            "database dump {} declares {}, but observed project hints disagree: {}",
            dump.id,
            database_engine_family_label(&declared),
            detail
        ),
        Some(target.id.clone()),
    ));
}

fn database_engine_hints(service: &Service, dump: &BackupDatabaseDump) -> Vec<DatabaseEngineHint> {
    let mut hints = Vec::new();
    if let Some(container) = dump.container.as_deref() {
        push_text_database_hint(
            &mut hints,
            &format!("database_dumps[].container={container}"),
            container,
        );
    }
    for container in &service.containers {
        push_text_database_hint(
            &mut hints,
            &format!("service container {container}"),
            container,
        );
    }
    hints.extend(env_file_database_hints(service));
    hints.extend(compose_database_hints(service));
    dedup_database_hints(hints)
}

fn env_file_database_hints(service: &Service) -> Vec<DatabaseEngineHint> {
    let mut paths = service
        .env_files
        .iter()
        .map(|env_file| resolve_service_path(service, &env_file.path))
        .collect::<Vec<_>>();
    if let Some(root) = service.root.as_deref() {
        paths.extend(
            [
                ".env",
                ".env.local",
                ".env.prod",
                ".env.production",
                ".env.example",
                "env.example.txt",
            ]
            .into_iter()
            .map(|name| root.join(name)),
        );
    }
    let mut hints = Vec::new();
    for path in unique_paths(paths) {
        hints.extend(read_env_file_database_hints(&path));
    }
    hints
}

fn read_env_file_database_hints(path: &Path) -> Vec<DatabaseEngineHint> {
    const MAX_ENV_HINT_BYTES: u64 = 64 * 1024;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return Vec::new(),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_ENV_HINT_BYTES
    {
        return Vec::new();
    }
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut hints = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = unquote_env_hint_value(value.trim());
        match key {
            "DATABASE_URL" => {
                if let Some(scheme) = value.split_once(':').map(|(scheme, _)| scheme) {
                    push_database_hint_from_token(
                        &mut hints,
                        &format!("{} DATABASE_URL scheme", display_path(path)),
                        scheme,
                    );
                }
            }
            "DB_CONNECTION" | "DATABASE_ENGINE" | "DATABASE_CLIENT" => {
                push_database_hint_from_token(
                    &mut hints,
                    &format!("{} {key}", display_path(path)),
                    &value,
                );
            }
            _ => {}
        }
    }
    hints
}

fn compose_database_hints(service: &Service) -> Vec<DatabaseEngineHint> {
    let Some(root) = service.root.as_deref() else {
        return Vec::new();
    };
    [
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
    ]
    .into_iter()
    .flat_map(|name| read_compose_database_hints(&root.join(name)))
    .collect()
}

fn read_compose_database_hints(path: &Path) -> Vec<DatabaseEngineHint> {
    const MAX_COMPOSE_HINT_BYTES: u64 = 512 * 1024;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return Vec::new(),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_COMPOSE_HINT_BYTES
    {
        return Vec::new();
    }
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&raw) else {
        return Vec::new();
    };
    let Some(services) = yaml_mapping_get(&value, "services").and_then(|value| value.as_mapping())
    else {
        return Vec::new();
    };
    let mut hints = Vec::new();
    for (service_name, service_value) in services {
        let service_label = service_name
            .as_str()
            .map_or_else(|| "service".to_string(), str::to_string);
        if let Some(image) =
            yaml_mapping_get(service_value, "image").and_then(|value| value.as_str())
        {
            push_text_database_hint(
                &mut hints,
                &format!(
                    "{} compose service {service_label} image",
                    display_path(path)
                ),
                image,
            );
        }
        if let Some(container_name) =
            yaml_mapping_get(service_value, "container_name").and_then(|value| value.as_str())
        {
            push_text_database_hint(
                &mut hints,
                &format!(
                    "{} compose service {service_label} container_name",
                    display_path(path)
                ),
                container_name,
            );
        }
    }
    hints
}

fn yaml_mapping_get<'a>(value: &'a serde_yaml::Value, key: &str) -> Option<&'a serde_yaml::Value> {
    value
        .as_mapping()?
        .get(serde_yaml::Value::String(key.to_string()))
}

fn resolve_service_path(service: &Service, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(root) = service.root.as_deref() {
        root.join(path)
    } else {
        path.to_path_buf()
    }
}

fn unique_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for path in paths {
        if seen.insert(path.clone()) {
            output.push(path);
        }
    }
    output
}

fn unquote_env_hint_value(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

fn push_text_database_hint(hints: &mut Vec<DatabaseEngineHint>, source: &str, text: &str) {
    push_database_hint_from_token(hints, source, text);
}

fn push_database_hint_from_token(hints: &mut Vec<DatabaseEngineHint>, source: &str, token: &str) {
    let token = token.to_ascii_lowercase();
    let Some((family, label)) = infer_database_engine(&token) else {
        return;
    };
    hints.push(DatabaseEngineHint {
        family,
        label,
        source: source.to_string(),
    });
}

fn infer_database_engine(token: &str) -> Option<(DatabaseEngineFamily, &'static str)> {
    if token.contains("postgresql") || token.contains("postgres") {
        Some((DatabaseEngineFamily::Postgres, "postgres"))
    } else if token.contains("mariadb") {
        Some((DatabaseEngineFamily::Mysql, "mariadb"))
    } else if token.contains("mysql") {
        Some((DatabaseEngineFamily::Mysql, "mysql"))
    } else {
        None
    }
}

fn database_engine_family(kind: &str) -> Option<DatabaseEngineFamily> {
    match kind {
        "mysql" | "mariadb" => Some(DatabaseEngineFamily::Mysql),
        "postgres" => Some(DatabaseEngineFamily::Postgres),
        _ => None,
    }
}

fn database_engine_family_label(family: &DatabaseEngineFamily) -> &'static str {
    match family {
        DatabaseEngineFamily::Mysql => "mysql/mariadb",
        DatabaseEngineFamily::Postgres => "postgres",
    }
}

fn dedup_database_hints(hints: Vec<DatabaseEngineHint>) -> Vec<DatabaseEngineHint> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for hint in hints {
        if seen.insert((hint.source.clone(), hint.label)) {
            output.push(hint);
        }
    }
    output
}

fn check_external_dump_package_script(
    service: &Service,
    dump: &BackupDatabaseDump,
    target_id: &str,
    findings: &mut Vec<BackupFinding>,
) {
    let Ok(Some(command)) = external_dump_command(service, dump) else {
        return;
    };
    let package_json = command.working_dir.join("package.json");
    let metadata = match fs::symlink_metadata(&package_json) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) => {
            findings.push(warn(
                "external_dump_package_unreadable",
                format!(
                    "external database dump package.json could not be inspected: {}: {}",
                    display_path(&package_json),
                    error
                ),
                Some(target_id.to_string()),
            ));
            return;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        findings.push(warn(
            "external_dump_package_unsafe",
            format!(
                "external database dump package.json is not a regular file: {}",
                display_path(&package_json)
            ),
            Some(target_id.to_string()),
        ));
        return;
    }
    let text = match fs::read_to_string(&package_json) {
        Ok(text) => text,
        Err(error) => {
            findings.push(warn(
                "external_dump_package_unreadable",
                format!(
                    "external database dump package.json could not be read: {}: {}",
                    display_path(&package_json),
                    error
                ),
                Some(target_id.to_string()),
            ));
            return;
        }
    };
    let value = match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(value) => value,
        Err(error) => {
            findings.push(warn(
                "external_dump_package_invalid",
                format!(
                    "external database dump package.json is not valid JSON: {}: {}",
                    display_path(&package_json),
                    error
                ),
                Some(target_id.to_string()),
            ));
            return;
        }
    };
    let has_script = value
        .get("scripts")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|scripts| scripts.contains_key(&command.script));
    if !has_script {
        findings.push(warn(
            "external_dump_package_script_missing",
            format!(
                "external database dump script {} run {} is declared in registry but missing from {}",
                command.adapter,
                command.script,
                display_path(&package_json)
            ),
            Some(target_id.to_string()),
        ));
    }
}

fn check_history_record(
    record: &BackupHistoryRecord,
    services: &BTreeMap<&str, &Service>,
    targets: &BTreeMap<&str, &BackupTarget>,
    repositories: &BTreeMap<&str, &BackupRepository>,
    findings: &mut Vec<BackupFinding>,
) {
    if parse_completed_at(record).is_err() {
        findings.push(error(
            "backup_history_invalid_completed_at",
            format!(
                "backup history record has invalid completed_at timestamp: {}",
                record.completed_at
            ),
            Some(record.id.clone()),
        ));
    }

    if !services.contains_key(record.service_id.as_str()) {
        findings.push(error(
            "backup_history_missing_service",
            format!(
                "backup history record references unknown service {}",
                record.service_id
            ),
            Some(record.id.clone()),
        ));
    }

    match targets.get(record.target_id.as_str()) {
        Some(target) if target.service_id != record.service_id => {
            findings.push(error(
                "backup_history_target_service_mismatch",
                format!(
                    "backup history target {} belongs to service {}, not {}",
                    target.id, target.service_id, record.service_id
                ),
                Some(record.id.clone()),
            ));
        }
        Some(target) => {
            if let Some(repository_id) = &record.repository_id
                && repository_id != &target.repository_id
            {
                findings.push(error(
                    "backup_history_repository_mismatch",
                    format!(
                        "backup history repository {} does not match target repository {}",
                        repository_id, target.repository_id
                    ),
                    Some(record.id.clone()),
                ));
            }
        }
        None => findings.push(error(
            "backup_history_missing_target",
            format!(
                "backup history record references unknown target {}",
                record.target_id
            ),
            Some(record.id.clone()),
        )),
    }

    if let Some(repository_id) = &record.repository_id
        && !repositories.contains_key(repository_id.as_str())
    {
        findings.push(error(
            "backup_history_missing_repository",
            format!("backup history record references unknown repository {repository_id}"),
            Some(record.id.clone()),
        ));
    }
}

fn check_repository_check_record(
    record: &BackupRepositoryCheckRecord,
    repositories: &BTreeMap<&str, &BackupRepository>,
    findings: &mut Vec<BackupFinding>,
) {
    if parse_repository_check_completed_at(record).is_err() {
        findings.push(error(
            "backup_repository_check_invalid_completed_at",
            format!(
                "repository check record has invalid completed_at timestamp: {}",
                record.completed_at
            ),
            Some(record.id.clone()),
        ));
    }
    match repositories.get(record.repository_id.as_str()) {
        Some(repository) if repository.provider != record.tool => findings.push(error(
            "backup_repository_check_tool_mismatch",
            format!(
                "repository check tool {} does not match repository provider {}",
                record.tool, repository.provider
            ),
            Some(record.id.clone()),
        )),
        Some(_) => {}
        None => findings.push(error(
            "backup_repository_check_missing_repository",
            format!(
                "repository check references unknown repository {}",
                record.repository_id
            ),
            Some(record.id.clone()),
        )),
    }
}

fn check_restore_drill_record(
    record: &BackupRestoreDrillRecord,
    services: &BTreeMap<&str, &Service>,
    targets: &BTreeMap<&str, &BackupTarget>,
    repositories: &BTreeMap<&str, &BackupRepository>,
    findings: &mut Vec<BackupFinding>,
) {
    if parse_restore_drill_completed_at(record).is_err() {
        findings.push(error(
            "backup_restore_drill_invalid_completed_at",
            format!(
                "restore drill record has invalid completed_at timestamp: {}",
                record.completed_at
            ),
            Some(record.id.clone()),
        ));
    }
    if !services.contains_key(record.service_id.as_str()) {
        findings.push(error(
            "backup_restore_drill_missing_service",
            format!(
                "restore drill references unknown service {}",
                record.service_id
            ),
            Some(record.id.clone()),
        ));
    }
    match targets.get(record.target_id.as_str()) {
        Some(target) if target.service_id != record.service_id => findings.push(error(
            "backup_restore_drill_target_service_mismatch",
            format!(
                "restore drill target {} belongs to service {}, not {}",
                target.id, target.service_id, record.service_id
            ),
            Some(record.id.clone()),
        )),
        Some(target) if target.repository_id != record.repository_id => findings.push(error(
            "backup_restore_drill_repository_mismatch",
            format!(
                "restore drill repository {} does not match target repository {}",
                record.repository_id, target.repository_id
            ),
            Some(record.id.clone()),
        )),
        Some(_) => {}
        None => findings.push(error(
            "backup_restore_drill_missing_target",
            format!(
                "restore drill references unknown target {}",
                record.target_id
            ),
            Some(record.id.clone()),
        )),
    }
    match repositories.get(record.repository_id.as_str()) {
        Some(repository) if repository.provider != record.tool => findings.push(error(
            "backup_restore_drill_tool_mismatch",
            format!(
                "restore drill tool {} does not match repository provider {}",
                record.tool, repository.provider
            ),
            Some(record.id.clone()),
        )),
        Some(_) => {}
        None => findings.push(error(
            "backup_restore_drill_missing_repository",
            format!(
                "restore drill references unknown repository {}",
                record.repository_id
            ),
            Some(record.id.clone()),
        )),
    }
}

fn requires_before_deploy_backup(service: &Service) -> bool {
    service.environment == "production"
        && matches!(service.backup_policy.as_deref(), Some("before_deploy"))
}

fn check_services_have_backup_targets(registry: &Registry, findings: &mut Vec<BackupFinding>) {
    let active_targets = registry
        .backups
        .targets
        .iter()
        .filter(|target| target.status == "active")
        .map(|target| target.service_id.as_str())
        .collect::<BTreeSet<_>>();

    for service in &registry.services.services {
        if requires_before_deploy_backup(service) && !active_targets.contains(service.id.as_str()) {
            findings.push(warn(
                "production_service_without_backup_target",
                "production service requires before-deploy backups but has no active backup target"
                    .to_string(),
                Some(service.id.clone()),
            ));
        }
    }
}

fn plan_target(
    service: &Service,
    target: &BackupTarget,
    repository: &BackupRepository,
) -> Result<BackupTargetPlan> {
    let mut limitations = Vec::new();
    let mut operations = Vec::new();
    let mut missing_env = missing_env(repository);
    let mut blocked = false;

    if repository.status != "active" {
        blocked = true;
        limitations.push(format!(
            "repository {} is not active: {}",
            repository.id, repository.status
        ));
    }
    if !is_supported_backup_provider(&repository.provider) {
        blocked = true;
        limitations.push(format!(
            "provider {} is not executable in current backup planning",
            repository.provider
        ));
    }
    if repository.repository.is_none() && repository.repository_env.is_none() {
        blocked = true;
        limitations.push("restic repository source is missing".to_string());
    }
    if repository.password_env.is_none() {
        blocked = true;
        limitations.push("restic password_env is missing".to_string());
    }
    if target.include_paths.is_empty() {
        blocked = true;
        limitations.push("backup target include_paths is empty".to_string());
    }
    for path in target
        .include_paths
        .iter()
        .chain(target.exclude_paths.iter())
        .chain(target.database_dumps.iter().map(|dump| &dump.output_path))
    {
        if !path.is_absolute() || has_parent_component(path) {
            blocked = true;
            limitations.push(format!(
                "unsafe backup path must be absolute without parent traversal: {}",
                display_path(path)
            ));
        }
    }
    for dump in &target.database_dumps {
        if let Err(error) = validate_database_dump(service, dump) {
            blocked = true;
            limitations.push(error.to_string());
        }
    }
    if repository.repository.is_some() && repository.repository_env.is_some() {
        limitations.push("repository and repository_env are both set; repository_env is preferred in generated environment requirements".to_string());
    }
    if !missing_env.is_empty() {
        blocked = true;
    }

    let required_env = required_env(repository);
    let operation_env = required_env.clone();
    operations.push(BackupOperation {
        order: 1,
        kind: "check_env".to_string(),
        argv: Vec::new(),
        env: operation_env.clone(),
        detail: "Verify required environment variable names are set; values are never printed or persisted by opsctl.".to_string(),
    });

    if repository.provider == "restic" {
        operations.push(BackupOperation {
            order: operations.len() as u32 + 1,
            kind: "restic_unlock".to_string(),
            argv: restic_unlock_argv(repository),
            env: operation_env.clone(),
            detail: format!(
                "Remove only stale Restic locks from repository {} before starting the controlled backup; active locks are preserved.",
                repository.id
            ),
        });
    }

    for dump in &target.database_dumps {
        operations.push(BackupOperation {
            order: operations.len() as u32 + 1,
            kind: "database_dump".to_string(),
            argv: database_dump_argv(dump),
            env: Vec::new(),
            detail: format!(
                "Create {} dump for service {} at {} before running the backup tool.",
                dump.kind,
                service.id,
                display_path(&dump.output_path)
            ),
        });
    }

    if is_supported_backup_provider(&repository.provider) {
        let provider = repository.provider.clone();
        operations.push(BackupOperation {
            order: operations.len() as u32 + 1,
            kind: format!("{provider}_backup"),
            argv: restic_backup_argv(service, target, repository),
            env: operation_env.clone(),
            detail: format!("Back up target {} with {}.", target.id, provider),
        });

        if let Some(retention) = &repository.retention {
            operations.push(BackupOperation {
                order: operations.len() as u32 + 1,
                kind: format!("{provider}_forget_prune"),
                argv: restic_forget_argv(service, repository, retention),
                env: operation_env.clone(),
                detail: format!("Apply the configured {provider} retention policy."),
            });
        }
        if repository.check_after_backup.unwrap_or(false) {
            operations.push(BackupOperation {
                order: operations.len() as u32 + 1,
                kind: format!("{provider}_check"),
                argv: restic_check_argv(repository),
                env: operation_env,
                detail: format!("Check the {provider} repository after backup."),
            });
        }
    }

    missing_env.sort();
    missing_env.dedup();

    Ok(BackupTargetPlan {
        target_id: target.id.clone(),
        repository_id: repository.id.clone(),
        provider: repository.provider.clone(),
        status: if blocked { "blocked" } else { "ready" }.to_string(),
        repository_source: repository_source(repository),
        include_paths: path_strings(&target.include_paths),
        exclude_paths: path_strings(&target.exclude_paths),
        database_dump_outputs: target
            .database_dumps
            .iter()
            .map(|dump| display_path(&dump.output_path))
            .collect(),
        required_env,
        missing_env,
        operations,
        limitations,
    })
}

fn missing_repository_plan(target: &BackupTarget) -> BackupTargetPlan {
    BackupTargetPlan {
        target_id: target.id.clone(),
        repository_id: target.repository_id.clone(),
        provider: "unknown".to_string(),
        status: "blocked".to_string(),
        repository_source: "missing".to_string(),
        include_paths: path_strings(&target.include_paths),
        exclude_paths: path_strings(&target.exclude_paths),
        database_dump_outputs: target
            .database_dumps
            .iter()
            .map(|dump| display_path(&dump.output_path))
            .collect(),
        required_env: Vec::new(),
        missing_env: Vec::new(),
        operations: Vec::new(),
        limitations: vec![format!(
            "repository {} is not registered",
            target.repository_id
        )],
    }
}

fn restic_backup_argv(
    service: &Service,
    target: &BackupTarget,
    repository: &BackupRepository,
) -> Vec<String> {
    let mut argv = restic_base_argv(repository);
    argv.push("backup".to_string());
    for path in target
        .include_paths
        .iter()
        .chain(target.database_dumps.iter().map(|dump| &dump.output_path))
    {
        argv.push(display_path(path));
    }
    for path in &target.exclude_paths {
        argv.push("--exclude".to_string());
        argv.push(display_path(path));
    }
    for tag in restic_tags(service, target) {
        argv.push("--tag".to_string());
        argv.push(tag);
    }
    argv
}

fn restic_forget_argv(
    service: &Service,
    repository: &BackupRepository,
    retention: &BackupRetention,
) -> Vec<String> {
    let mut argv = restic_base_argv(repository);
    argv.push("forget".to_string());
    argv.push("--prune".to_string());
    if let Some(value) = retention.keep_daily {
        argv.push("--keep-daily".to_string());
        argv.push(value.to_string());
    }
    if let Some(value) = retention.keep_weekly {
        argv.push("--keep-weekly".to_string());
        argv.push(value.to_string());
    }
    if let Some(value) = retention.keep_monthly {
        argv.push("--keep-monthly".to_string());
        argv.push(value.to_string());
    }
    if let Some(value) = retention.keep_yearly {
        argv.push("--keep-yearly".to_string());
        argv.push(value.to_string());
    }
    argv.push("--tag".to_string());
    argv.push(format!("service:{}", service.id));
    argv
}

fn restic_forget_all_argv(
    repository: &BackupRepository,
    retention: &BackupRetention,
) -> Vec<String> {
    let mut argv = restic_base_argv(repository);
    argv.push("forget".to_string());
    argv.push("--prune".to_string());
    if let Some(value) = retention.keep_daily {
        argv.push("--keep-daily".to_string());
        argv.push(value.to_string());
    }
    if let Some(value) = retention.keep_weekly {
        argv.push("--keep-weekly".to_string());
        argv.push(value.to_string());
    }
    if let Some(value) = retention.keep_monthly {
        argv.push("--keep-monthly".to_string());
        argv.push(value.to_string());
    }
    if let Some(value) = retention.keep_yearly {
        argv.push("--keep-yearly".to_string());
        argv.push(value.to_string());
    }
    argv
}

fn restic_check_argv(repository: &BackupRepository) -> Vec<String> {
    let mut argv = restic_base_argv(repository);
    argv.push("check".to_string());
    argv
}

fn restic_unlock_argv(repository: &BackupRepository) -> Vec<String> {
    let mut argv = restic_base_argv(repository);
    argv.push("unlock".to_string());
    argv
}

fn restic_init_argv(repository: &BackupRepository) -> Vec<String> {
    let mut argv = restic_base_argv(repository);
    argv.push("init".to_string());
    argv
}

fn restic_restore_argv(
    repository: &BackupRepository,
    repository_snapshot_id: &str,
    restore_dir: &Path,
) -> Vec<String> {
    let mut argv = restic_base_argv(repository);
    argv.push("restore".to_string());
    argv.push(repository_snapshot_id.to_string());
    argv.push("--target".to_string());
    argv.push(display_path(restore_dir));
    argv
}

pub(crate) fn restic_base_argv(repository: &BackupRepository) -> Vec<String> {
    let mut argv = vec![backup_tool_binary(repository)];
    if repository.repository_env.is_none()
        && let Some(repository) = &repository.repository
    {
        argv.push("-r".to_string());
        argv.push(repository.clone());
    }
    argv
}

pub(crate) fn backup_tool_binary(repository: &BackupRepository) -> String {
    match repository.provider.as_str() {
        "rustic" => {
            env_source::var_string("OPSCTL_RUSTIC_BIN").unwrap_or_else(|| "rustic".to_string())
        }
        _ => env_source::var_string("OPSCTL_RESTIC_BIN").unwrap_or_else(|| "restic".to_string()),
    }
}

pub(crate) fn repository_command_env(repository: &BackupRepository) -> Vec<(String, OsString)> {
    let mut envs = Vec::new();
    if let Some(name) = &repository.repository_env
        && let Some(value) = env_source::var_os(name)
    {
        envs.push(("RESTIC_REPOSITORY".to_string(), value.clone()));
        envs.push(("RUSTIC_REPOSITORY".to_string(), value));
    }
    if let Some(name) = &repository.password_env
        && let Some(value) = env_source::var_os(name)
    {
        envs.push(("RESTIC_PASSWORD".to_string(), value.clone()));
        envs.push(("RUSTIC_PASSWORD".to_string(), value));
    }
    for name in &repository.env {
        if let Some(value) = env_source::var_os(name) {
            envs.push((name.clone(), value));
        }
    }
    envs
}

fn restic_tags(service: &Service, target: &BackupTarget) -> Vec<String> {
    let mut tags = vec![
        "opsctl".to_string(),
        format!("service:{}", service.id),
        format!("target:{}", target.id),
    ];
    tags.extend(target.tags.iter().cloned());
    unique_sorted(tags)
}

pub fn backup_repository_check(
    options: &BackupRepositoryActionOptions<'_>,
) -> Result<BackupRepositoryActionReport> {
    let repository = repository_by_id(options.registry, options.repository_id)?;
    ensure_repository_executable(repository)?;
    let started_at = OffsetDateTime::now_utc();
    let operation = run_repository_operation(
        1,
        "repository_check",
        repository,
        restic_check_argv(repository),
    )?;
    let completed_at = OffsetDateTime::now_utc();
    let ok = operation.status == "success";
    let record = backup_repository_check_record(
        repository,
        started_at,
        completed_at,
        if ok { "success" } else { "failed" },
    )?;
    if let Some(registry_dir) = options.registry_dir {
        append_repository_check_history(registry_dir, &record)?;
    }
    Ok(BackupRepositoryActionReport {
        ok,
        status: if ok { "success" } else { "failed" }.to_string(),
        repository_id: repository.id.clone(),
        provider: repository.provider.clone(),
        service_id: options.service_id.map(str::to_string),
        approval_required: false,
        expected_approval_token: None,
        operations: vec![operation],
        repository_check_record: Some(record),
    })
}

pub fn backup_repository_init(
    options: &BackupRepositoryInitOptions<'_>,
) -> Result<BackupRepositoryActionReport> {
    let repository = repository_by_id(options.registry, options.repository_id)?;
    ensure_repository_executable(repository)?;
    let token = backup_repo_init_approval_token(&repository.id);
    let operation = BackupRunOperationReport {
        order: 1,
        kind: format!("{}_init", repository.provider),
        argv: restic_init_argv(repository),
        status: if options.execute {
            "planned".to_string()
        } else {
            "dry_run".to_string()
        },
        exit_code: None,
        detail: format!(
            "Initialize {} repository {}. This writes repository metadata to the configured backend.",
            repository.provider, repository.id
        ),
    };
    if !options.execute {
        return Ok(BackupRepositoryActionReport {
            ok: true,
            status: "dry_run".to_string(),
            repository_id: repository.id.clone(),
            provider: repository.provider.clone(),
            service_id: None,
            approval_required: true,
            expected_approval_token: Some(token),
            operations: vec![operation],
            repository_check_record: None,
        });
    }
    if options.approval_token != Some(token.as_str()) {
        anyhow::bail!("backup repository init requires approval token: {token}");
    }
    let operation_kind = format!("{}_init", repository.provider);
    let executed = run_repository_operation(1, &operation_kind, repository, operation.argv)?;
    let ok = executed.status == "success";
    Ok(BackupRepositoryActionReport {
        ok,
        status: if ok { "success" } else { "failed" }.to_string(),
        repository_id: repository.id.clone(),
        provider: repository.provider.clone(),
        service_id: None,
        approval_required: true,
        expected_approval_token: Some(token),
        operations: vec![executed],
        repository_check_record: None,
    })
}

pub fn backup_repository_prune(
    options: &BackupRepositoryActionOptions<'_>,
) -> Result<BackupRepositoryActionReport> {
    let repository = repository_by_id(options.registry, options.repository_id)?;
    ensure_repository_executable(repository)?;
    let Some(retention) = repository.retention.as_ref() else {
        anyhow::bail!(
            "backup repository {} has no retention policy",
            repository.id
        );
    };
    let service = match options.service_id {
        Some(service_id) => Some(service_by_id(options.registry, service_id)?),
        None => None,
    };
    let token =
        backup_prune_approval_token(&repository.id, service.map(|service| service.id.as_str()));
    if options.approval_token != Some(token.as_str()) {
        anyhow::bail!("backup prune requires approval token: {token}");
    }
    let argv = match service {
        Some(service) => restic_forget_argv(service, repository, retention),
        None => restic_forget_all_argv(repository, retention),
    };
    let operation = run_repository_operation(1, "repository_prune", repository, argv)?;
    let ok = operation.status == "success";
    Ok(BackupRepositoryActionReport {
        ok,
        status: if ok { "success" } else { "failed" }.to_string(),
        repository_id: repository.id.clone(),
        provider: repository.provider.clone(),
        service_id: service.map(|service| service.id.clone()),
        approval_required: true,
        expected_approval_token: Some(token),
        operations: vec![operation],
        repository_check_record: None,
    })
}

pub fn backup_repo_init_approval_token(repository_id: &str) -> String {
    format!("repo-init:{repository_id}")
}

pub fn backup_prune_approval_token(repository_id: &str, service_id: Option<&str>) -> String {
    match service_id {
        Some(service_id) => format!("prune:{repository_id}:{service_id}"),
        None => format!("prune:{repository_id}"),
    }
}

pub fn backup_restore_approval_token(
    service_id: &str,
    target_id: &str,
    repository_snapshot_id: &str,
) -> String {
    format!("restore:{service_id}:{target_id}:{repository_snapshot_id}")
}

pub fn backup_s3_smoke(options: &BackupS3SmokeOptions<'_>) -> Result<BackupS3SmokeReport> {
    let endpoint = normalize_s3_endpoint(options.endpoint)?;
    let region = validate_s3_region(options.region)?;
    let provider = validate_s3_provider(options.provider)?;
    let bucket = validate_s3_bucket(options.bucket)?;
    let prefix = match options.prefix {
        Some(prefix) => validate_s3_prefix(prefix)?,
        None => default_s3_smoke_prefix()?,
    };
    let object_key = format!("{prefix}/payload.txt");
    let required_env = unique_sorted(vec![
        options.access_key_env.to_string(),
        options.secret_key_env.to_string(),
    ]);
    let missing_env = required_env
        .iter()
        .filter(|name| env_source::var_os(name.as_str()).is_none())
        .cloned()
        .collect::<Vec<_>>();
    let mut limitations = Vec::new();
    if !missing_env.is_empty() {
        limitations.push(format!(
            "S3 smoke test is missing required environment variables: {}",
            missing_env.join(", ")
        ));
    }

    let tool = env_source::var_string("OPSCTL_RCLONE_BIN").unwrap_or_else(|| "rclone".to_string());
    let remote = "opsctls3smoke";
    let remote_prefix = format!("{remote}:{bucket}/{prefix}");
    let remote_object = format!("{remote}:{bucket}/{object_key}");
    let payload_sha256 =
        planned_s3_smoke_payload_sha256(&endpoint, &region, &provider, &bucket, &prefix);
    let planned_operations = s3_smoke_planned_operations(&tool, &remote_object, &remote_prefix);

    if !options.execute {
        let blocked = !missing_env.is_empty();
        return Ok(BackupS3SmokeReport {
            ok: !blocked,
            execute: false,
            status: if blocked { "blocked" } else { "dry_run" }.to_string(),
            tool,
            endpoint,
            region,
            provider,
            bucket,
            prefix,
            object_key,
            required_env,
            missing_env,
            operations: planned_operations,
            payload_sha256: Some(payload_sha256),
            limitations,
        });
    }

    if !missing_env.is_empty() {
        return Ok(BackupS3SmokeReport {
            ok: false,
            execute: true,
            status: "blocked".to_string(),
            tool,
            endpoint,
            region,
            provider,
            bucket,
            prefix,
            object_key,
            required_env,
            missing_env,
            operations: planned_operations
                .into_iter()
                .map(|mut operation| {
                    operation.status = "blocked".to_string();
                    operation
                })
                .collect(),
            payload_sha256: Some(payload_sha256),
            limitations,
        });
    }

    execute_s3_smoke(ExecuteS3SmokeInput {
        tool,
        endpoint,
        region,
        provider,
        bucket,
        prefix,
        object_key,
        remote,
        remote_prefix,
        remote_object,
        access_key_env: options.access_key_env,
        secret_key_env: options.secret_key_env,
        required_env,
        missing_env,
        payload_sha256,
        limitations,
    })
}

struct ExecuteS3SmokeInput<'a> {
    tool: String,
    endpoint: String,
    region: String,
    provider: String,
    bucket: String,
    prefix: String,
    object_key: String,
    remote: &'a str,
    remote_prefix: String,
    remote_object: String,
    access_key_env: &'a str,
    secret_key_env: &'a str,
    required_env: Vec<String>,
    missing_env: Vec<String>,
    payload_sha256: String,
    limitations: Vec<String>,
}

fn execute_s3_smoke(input: ExecuteS3SmokeInput<'_>) -> Result<BackupS3SmokeReport> {
    let temp_dir = s3_smoke_temp_dir()?;
    let payload_path = temp_dir.join("payload.txt");
    let payload = s3_smoke_payload(
        &input.endpoint,
        &input.region,
        &input.provider,
        &input.bucket,
        &input.prefix,
    );
    fs::write(&payload_path, payload.as_bytes()).with_context(|| {
        format!(
            "failed to write S3 smoke payload {}",
            payload_path.display()
        )
    })?;

    let command_env = s3_smoke_rclone_env(
        input.remote,
        &input.endpoint,
        &input.region,
        &input.provider,
        input.access_key_env,
        input.secret_key_env,
    )?;
    let mut operations = Vec::new();
    let mut limitations = input.limitations;
    let mut ok = true;

    let copy_args = vec![
        "copyto".to_string(),
        display_path(&payload_path),
        input.remote_object.clone(),
        "--s3-no-check-bucket".to_string(),
        "--s3-no-head".to_string(),
        "--no-check-dest".to_string(),
    ];
    let (copy_operation, copy_capture) = run_s3_smoke_rclone(
        1,
        "s3_upload",
        &input.tool,
        copy_args,
        &command_env,
        "uploaded S3 smoke payload",
    );
    let copied = copy_capture
        .as_ref()
        .is_some_and(|capture| capture.success());
    ok &= copied;
    if !copied {
        limitations.push("failed to upload S3 smoke payload".to_string());
    }
    operations.push(copy_operation);

    if copied {
        let download_args = vec!["cat".to_string(), input.remote_object.clone()];
        let (mut download_operation, download_capture) = run_s3_smoke_rclone(
            2,
            "s3_download",
            &input.tool,
            download_args,
            &command_env,
            "downloaded S3 smoke payload",
        );
        match download_capture {
            Some(capture)
                if capture.success() && capture.stdout.as_bytes() == payload.as_bytes() => {}
            Some(capture) if capture.success() => {
                ok = false;
                download_operation.status = "failed".to_string();
                download_operation.detail = format!(
                    "downloaded S3 smoke payload hash mismatch: expected {} bytes sha256 {}, got {} bytes sha256 {}",
                    payload.len(),
                    sha256_hex(payload.as_bytes()),
                    capture.stdout.len(),
                    sha256_hex(capture.stdout.as_bytes())
                );
                limitations.push("S3 smoke payload verification failed".to_string());
            }
            Some(_) => {
                ok = false;
                limitations.push("failed to download S3 smoke payload".to_string());
            }
            None => {
                ok = false;
                limitations.push("failed to run S3 smoke download command".to_string());
            }
        }
        operations.push(download_operation);

        let list_args = vec![
            "lsjson".to_string(),
            input.remote_prefix.clone(),
            "--files-only".to_string(),
            "--s3-no-check-bucket".to_string(),
        ];
        let (mut list_operation, list_capture) = run_s3_smoke_rclone(
            3,
            "s3_list",
            &input.tool,
            list_args,
            &command_env,
            "listed S3 smoke prefix",
        );
        match list_capture {
            Some(capture)
                if capture.success() && s3_smoke_list_contains_payload(&capture.stdout) => {}
            Some(capture) if capture.success() => {
                ok = false;
                list_operation.status = "failed".to_string();
                list_operation.detail =
                    "S3 smoke prefix listing did not include payload.txt".to_string();
                limitations.push("S3 smoke prefix listing did not include payload.txt".to_string());
            }
            Some(_) => {
                ok = false;
                limitations.push("failed to list S3 smoke prefix".to_string());
            }
            None => {
                ok = false;
                limitations.push("failed to run S3 smoke list command".to_string());
            }
        }
        operations.push(list_operation);

        let delete_args = vec![
            "deletefile".to_string(),
            input.remote_object.clone(),
            "--s3-no-check-bucket".to_string(),
        ];
        let (delete_operation, delete_capture) = run_s3_smoke_rclone(
            4,
            "s3_delete",
            &input.tool,
            delete_args,
            &command_env,
            "deleted S3 smoke payload",
        );
        if !delete_capture
            .as_ref()
            .is_some_and(|capture| capture.success())
        {
            ok = false;
            limitations.push(format!(
                "failed to delete S3 smoke object {}; manual cleanup may be required",
                input.object_key
            ));
        }
        operations.push(delete_operation);

        let rmdirs_args = vec![
            "rmdirs".to_string(),
            input.remote_prefix.clone(),
            "--leave-root".to_string(),
        ];
        let (rmdirs_operation, rmdirs_capture) = run_s3_smoke_rclone(
            5,
            "s3_cleanup_prefix",
            &input.tool,
            rmdirs_args,
            &command_env,
            "removed empty S3 smoke prefix markers when present",
        );
        if !rmdirs_capture
            .as_ref()
            .is_some_and(|capture| capture.success())
        {
            ok = false;
            limitations.push(
                "failed to remove empty S3 smoke prefix markers; object deletion already ran"
                    .to_string(),
            );
        }
        operations.push(rmdirs_operation);
    }

    if let Err(error) = fs::remove_dir_all(&temp_dir) {
        ok = false;
        limitations.push(format!(
            "failed to remove local S3 smoke temp directory {}: {error}",
            temp_dir.display()
        ));
    }

    Ok(BackupS3SmokeReport {
        ok,
        execute: true,
        status: if ok { "success" } else { "failed" }.to_string(),
        tool: input.tool,
        endpoint: input.endpoint,
        region: input.region,
        provider: input.provider,
        bucket: input.bucket,
        prefix: input.prefix,
        object_key: input.object_key,
        required_env: input.required_env,
        missing_env: input.missing_env,
        operations,
        payload_sha256: Some(input.payload_sha256),
        limitations,
    })
}

fn s3_smoke_planned_operations(
    tool: &str,
    remote_object: &str,
    remote_prefix: &str,
) -> Vec<BackupRunOperationReport> {
    vec![
        planned_s3_smoke_operation(
            1,
            "s3_upload",
            vec![
                tool.to_string(),
                "copyto".to_string(),
                "<temp-payload>".to_string(),
                remote_object.to_string(),
                "--s3-no-check-bucket".to_string(),
                "--s3-no-head".to_string(),
                "--no-check-dest".to_string(),
            ],
            "Upload one generated smoke payload object.",
        ),
        planned_s3_smoke_operation(
            2,
            "s3_download",
            vec![
                tool.to_string(),
                "cat".to_string(),
                remote_object.to_string(),
            ],
            "Download the smoke payload object and compare its content hash.",
        ),
        planned_s3_smoke_operation(
            3,
            "s3_list",
            vec![
                tool.to_string(),
                "lsjson".to_string(),
                remote_prefix.to_string(),
                "--files-only".to_string(),
                "--s3-no-check-bucket".to_string(),
            ],
            "List the smoke prefix and confirm payload.txt is visible.",
        ),
        planned_s3_smoke_operation(
            4,
            "s3_delete",
            vec![
                tool.to_string(),
                "deletefile".to_string(),
                remote_object.to_string(),
                "--s3-no-check-bucket".to_string(),
            ],
            "Delete the smoke payload object.",
        ),
        planned_s3_smoke_operation(
            5,
            "s3_cleanup_prefix",
            vec![
                tool.to_string(),
                "rmdirs".to_string(),
                remote_prefix.to_string(),
                "--leave-root".to_string(),
            ],
            "Remove empty prefix markers if the S3-compatible backend created any.",
        ),
    ]
}

fn planned_s3_smoke_operation(
    order: u32,
    kind: &str,
    argv: Vec<String>,
    detail: &str,
) -> BackupRunOperationReport {
    BackupRunOperationReport {
        order,
        kind: kind.to_string(),
        argv,
        status: "planned".to_string(),
        exit_code: None,
        detail: detail.to_string(),
    }
}

fn run_s3_smoke_rclone(
    order: u32,
    kind: &str,
    tool: &str,
    args: Vec<String>,
    envs: &[(String, OsString)],
    success_detail: &str,
) -> (
    BackupRunOperationReport,
    Option<command_runner::ControlledCommand>,
) {
    let mut argv = vec![tool.to_string()];
    argv.extend(args.iter().cloned());
    match command_runner::run_controlled_with_env(tool, &args, envs) {
        Ok(captured) => {
            let success = captured.success();
            (
                BackupRunOperationReport {
                    order,
                    kind: kind.to_string(),
                    argv,
                    status: if success { "success" } else { "failed" }.to_string(),
                    exit_code: captured.status_code,
                    detail: if success {
                        success_detail.to_string()
                    } else {
                        s3_smoke_failure_detail(&captured, envs)
                    },
                },
                Some(captured),
            )
        }
        Err(error) => (
            BackupRunOperationReport {
                order,
                kind: kind.to_string(),
                argv,
                status: "failed".to_string(),
                exit_code: None,
                detail: format!("failed to run S3 smoke command: {error}"),
            },
            None,
        ),
    }
}

fn s3_smoke_failure_detail(
    captured: &command_runner::ControlledCommand,
    envs: &[(String, OsString)],
) -> String {
    let diagnostic = captured
        .stderr
        .lines()
        .rev()
        .chain(captured.stdout.lines().rev())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| redact_s3_smoke_diagnostic(line, envs))
        .unwrap_or_else(|| "no command output was captured".to_string());
    format!("S3 smoke command failed: {diagnostic}")
}

fn redact_s3_smoke_diagnostic(raw: &str, envs: &[(String, OsString)]) -> String {
    let mut redacted = raw.to_string();
    for (name, value) in envs {
        if !is_sensitive_env_name(name) {
            continue;
        }
        let Some(value) = value.to_str() else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        redacted = redacted.replace(value, "[REDACTED]");
    }
    const MAX_DIAGNOSTIC_CHARS: usize = 240;
    if redacted.chars().count() > MAX_DIAGNOSTIC_CHARS {
        let mut truncated = redacted
            .chars()
            .take(MAX_DIAGNOSTIC_CHARS)
            .collect::<String>();
        truncated.push_str("...");
        truncated
    } else {
        redacted
    }
}

fn is_sensitive_env_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("token")
        || normalized.contains("access_key")
}

fn s3_smoke_rclone_env(
    remote: &str,
    endpoint: &str,
    region: &str,
    provider: &str,
    access_key_env: &str,
    secret_key_env: &str,
) -> Result<Vec<(String, OsString)>> {
    let remote = remote.to_ascii_uppercase();
    let access_key = env_source::var_os(access_key_env)
        .with_context(|| format!("environment variable {access_key_env} is not set"))?;
    let secret_key = env_source::var_os(secret_key_env)
        .with_context(|| format!("environment variable {secret_key_env} is not set"))?;
    Ok(vec![
        (format!("RCLONE_CONFIG_{remote}_TYPE"), OsString::from("s3")),
        (
            format!("RCLONE_CONFIG_{remote}_PROVIDER"),
            OsString::from(provider),
        ),
        (
            format!("RCLONE_CONFIG_{remote}_ENDPOINT"),
            OsString::from(endpoint),
        ),
        (
            format!("RCLONE_CONFIG_{remote}_REGION"),
            OsString::from(region),
        ),
        (format!("RCLONE_CONFIG_{remote}_ACCESS_KEY_ID"), access_key),
        (
            format!("RCLONE_CONFIG_{remote}_SECRET_ACCESS_KEY"),
            secret_key,
        ),
        (
            format!("RCLONE_CONFIG_{remote}_FORCE_PATH_STYLE"),
            OsString::from("true"),
        ),
    ])
}

fn s3_smoke_payload(
    endpoint: &str,
    region: &str,
    provider: &str,
    bucket: &str,
    prefix: &str,
) -> String {
    format!(
        "opsctl s3 smoke\nendpoint={endpoint}\nregion={region}\nprovider={provider}\nbucket={bucket}\nprefix={prefix}\n"
    )
}

fn planned_s3_smoke_payload_sha256(
    endpoint: &str,
    region: &str,
    provider: &str,
    bucket: &str,
    prefix: &str,
) -> String {
    sha256_hex(s3_smoke_payload(endpoint, region, provider, bucket, prefix).as_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn s3_smoke_list_contains_payload(stdout: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout) else {
        return false;
    };
    value.as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry.get("Name").and_then(serde_json::Value::as_str) == Some("payload.txt")
        })
    })
}

fn s3_smoke_temp_dir() -> Result<PathBuf> {
    let timestamp = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let path = env::temp_dir().join(format!(
        "opsctl-s3-smoke-{}-{timestamp}",
        std::process::id()
    ));
    fs::create_dir(&path).with_context(|| {
        format!(
            "failed to create S3 smoke temp directory {}",
            path.display()
        )
    })?;
    Ok(path)
}

fn default_s3_smoke_prefix() -> Result<String> {
    let timestamp = OffsetDateTime::now_utc()
        .format(&time::macros::format_description!(
            "[year][month][day]T[hour][minute][second]"
        ))
        .context("failed to format S3 smoke prefix timestamp")?;
    Ok(format!("opsctl-smoke/{timestamp}-{}", std::process::id()))
}

fn normalize_s3_endpoint(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("S3 endpoint cannot be empty");
    }
    if trimmed
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        anyhow::bail!("S3 endpoint cannot contain whitespace or control characters");
    }
    let endpoint = if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    if endpoint.ends_with('/') {
        anyhow::bail!("S3 endpoint must not end with a slash");
    }
    Ok(endpoint)
}

fn validate_s3_region(raw: &str) -> Result<String> {
    let region = raw.trim();
    if region.is_empty() || region.len() > 64 {
        anyhow::bail!("S3 region must be 1-64 characters");
    }
    if !region
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        anyhow::bail!("S3 region contains unsupported characters");
    }
    Ok(region.to_string())
}

fn validate_s3_provider(raw: &str) -> Result<String> {
    let provider = raw.trim();
    if provider.is_empty() || provider.len() > 64 {
        anyhow::bail!("S3 provider must be 1-64 characters");
    }
    if !provider
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        anyhow::bail!("S3 provider contains unsupported characters");
    }
    Ok(provider.to_string())
}

fn validate_s3_bucket(raw: &str) -> Result<String> {
    let bucket = raw.trim();
    if !(3..=63).contains(&bucket.len()) {
        anyhow::bail!("S3 bucket name must be 3-63 characters");
    }
    if bucket.starts_with(['.', '-']) || bucket.ends_with(['.', '-']) {
        anyhow::bail!("S3 bucket name must not start or end with dot or dash");
    }
    if !bucket.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '.' | '-')
    }) {
        anyhow::bail!("S3 bucket name contains unsupported characters");
    }
    Ok(bucket.to_string())
}

fn validate_s3_prefix(raw: &str) -> Result<String> {
    let prefix = raw.trim().trim_matches('/');
    if prefix.is_empty() {
        anyhow::bail!("S3 smoke prefix cannot be empty");
    }
    if prefix.len() > 256 {
        anyhow::bail!("S3 smoke prefix must be at most 256 characters");
    }
    if prefix.contains("..") || prefix.contains("//") || prefix.contains('\\') {
        anyhow::bail!("S3 smoke prefix cannot contain traversal-like segments");
    }
    if !prefix.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '/' | '-' | '_' | '.' | '=')
    }) {
        anyhow::bail!("S3 smoke prefix contains unsupported characters");
    }
    Ok(prefix.to_string())
}

fn run_repository_operation(
    order: u32,
    kind: &str,
    repository: &BackupRepository,
    argv: Vec<String>,
) -> Result<BackupRunOperationReport> {
    let Some((program, args)) = argv.split_first() else {
        anyhow::bail!("repository operation argv is empty");
    };
    let captured = command_runner::run_controlled_with_env(
        program,
        args,
        &repository_command_env(repository),
    )?;
    Ok(BackupRunOperationReport {
        order,
        kind: kind.to_string(),
        argv,
        status: if captured.success() {
            "success"
        } else {
            "failed"
        }
        .to_string(),
        exit_code: captured.status_code,
        detail: if captured.success() {
            "repository command completed successfully".to_string()
        } else {
            format!(
                "repository command failed: {}",
                safe_repository_failure_reason(&captured.stdout, &captured.stderr)
            )
        },
    })
}

fn execute_restore_operation(
    operation: BackupRunOperationReport,
    repository: &BackupRepository,
) -> Result<BackupRunOperationReport> {
    let Some((program, args)) = operation.argv.split_first() else {
        anyhow::bail!("backup restore operation argv is empty");
    };
    if !is_backup_execution_operation(&operation.kind) {
        anyhow::bail!(
            "backup restore operation is not executable: {}",
            operation.kind
        );
    }
    let captured = command_runner::run_controlled_with_env(
        program,
        args,
        &repository_command_env(repository),
    )?;
    Ok(BackupRunOperationReport {
        status: if captured.success() {
            "success"
        } else {
            "failed"
        }
        .to_string(),
        exit_code: captured.status_code,
        detail: if captured.success() {
            operation.detail
        } else {
            format!(
                "restore command failed: {}",
                safe_repository_failure_reason(&captured.stdout, &captured.stderr)
            )
        },
        ..operation
    })
}

fn safe_repository_failure_reason(stdout: &str, stderr: &str) -> &'static str {
    let output = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    if output.trim().is_empty() {
        return "no output was captured";
    }
    if output.contains("access denied")
        || output.contains("accessdenied")
        || output.contains("status code: 403")
        || output.contains("403 forbidden")
    {
        return "repository access was denied; refresh repository credentials or bucket permissions";
    }
    if output.contains("wrong password")
        || output.contains("no key found")
        || output.contains("password is incorrect")
    {
        return "repository password or encryption key was rejected";
    }
    if output.contains("already locked")
        || output.contains("unable to create lock")
        || output.contains("repository is locked")
    {
        return "repository is locked; verify no backup is running and clear stale locks if needed";
    }
    if output.contains("unable to open config file")
        || output.contains("is there a repository")
        || output.contains("repository does not exist")
    {
        return "repository is unavailable or not initialized";
    }
    if output.contains("temporary failure in name resolution")
        || output.contains("no such host")
        || output.contains("connection refused")
        || output.contains("connection reset")
        || output.contains("i/o timeout")
    {
        return "repository network connection failed";
    }
    "command output was captured but not persisted to avoid leaking secrets"
}

fn verify_restored_backup(
    restore_dir: &Path,
    target: &BackupTarget,
) -> Result<BackupRestoreVerification> {
    let metadata = fs::symlink_metadata(restore_dir).with_context(|| {
        format!(
            "failed to inspect restore directory {}",
            restore_dir.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing restore verification on symlink directory: {}",
            restore_dir.display()
        );
    }
    if !metadata.is_dir() {
        anyhow::bail!(
            "restore verification path is not a directory: {}",
            restore_dir.display()
        );
    }

    let mut files_checked = 0usize;
    let mut bytes_checked = 0u64;
    let mut sampled_hashes = Vec::new();
    let mut limitations = Vec::new();
    let mut stack = vec![restore_dir.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("failed to read {}", directory.display()))?
        {
            let entry = entry.context("failed to read restore directory entry")?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("failed to inspect {}", path.display()))?;
            if metadata.file_type().is_symlink() {
                if is_safe_restore_symlink(restore_dir, &path) {
                    continue;
                }
                limitations.push(format!(
                    "restore output contains symlink and was not followed: {}",
                    display_path(&path)
                ));
                continue;
            }
            if metadata.is_dir() {
                stack.push(path);
                continue;
            }
            if !metadata.is_file() {
                limitations.push(format!(
                    "restore output contains non-regular file: {}",
                    display_path(&path)
                ));
                continue;
            }
            files_checked += 1;
            bytes_checked = bytes_checked.saturating_add(metadata.len());
            if files_checked > RESTORE_VERIFY_MAX_FILES {
                limitations.push(format!(
                    "restore verification stopped after {RESTORE_VERIFY_MAX_FILES} files"
                ));
                break;
            }
            if sampled_hashes.len() < RESTORE_VERIFY_HASH_SAMPLES {
                sampled_hashes.push(BackupRestoreHashSample {
                    path: display_restore_relative_path(restore_dir, &path),
                    sha256: sha256_file(&path)?,
                    bytes: metadata.len(),
                });
            }
        }
        if files_checked > RESTORE_VERIFY_MAX_FILES {
            break;
        }
    }
    if files_checked == 0 {
        limitations.push("restore output directory contains no regular files".to_string());
    }

    let database_dump_checks = target
        .database_dumps
        .iter()
        .map(|dump| verify_restored_database_dump(restore_dir, dump))
        .collect::<Result<Vec<_>>>()?;
    for check in &database_dump_checks {
        if matches!(
            check.status.as_str(),
            "missing" | "unrecognized" | "import_failed"
        ) {
            limitations.push(format!(
                "database dump {} restore check status is {}",
                check.dump_id, check.status
            ));
        }
    }

    Ok(BackupRestoreVerification {
        files_checked,
        bytes_checked,
        sampled_hashes,
        database_dump_checks,
        limitations,
    })
}

fn is_safe_restore_symlink(restore_dir: &Path, path: &Path) -> bool {
    let Ok(target) = fs::read_link(path) else {
        return false;
    };
    if target.is_absolute() || has_parent_component(&target) {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let resolved = parent.join(target);
    if !resolved.starts_with(restore_dir) {
        return false;
    }
    fs::symlink_metadata(&resolved)
        .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn verify_restored_database_dump(
    restore_dir: &Path,
    dump: &BackupDatabaseDump,
) -> Result<BackupRestoreDatabaseDumpCheck> {
    let restored_path = restored_dump_path(restore_dir, &dump.output_path)?;
    if !restored_path.exists() {
        return Ok(BackupRestoreDatabaseDumpCheck {
            dump_id: dump.id.clone(),
            restored_path: display_path(&restored_path),
            status: "missing".to_string(),
            detail: "database dump output was not found in restored staging tree".to_string(),
        });
    }
    let metadata = fs::symlink_metadata(&restored_path)
        .with_context(|| format!("failed to inspect {}", restored_path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(BackupRestoreDatabaseDumpCheck {
            dump_id: dump.id.clone(),
            restored_path: display_path(&restored_path),
            status: "unrecognized".to_string(),
            detail: "restored database dump path is a symlink".to_string(),
        });
    }
    if !metadata.is_file() {
        return Ok(BackupRestoreDatabaseDumpCheck {
            dump_id: dump.id.clone(),
            restored_path: display_path(&restored_path),
            status: "unrecognized".to_string(),
            detail: "restored database dump path is not a regular file".to_string(),
        });
    }
    if dump_is_zstd_compressed(&restored_path)
        && restore_db_import_check_enabled()
        && database_dump_kind_importable(dump)
    {
        return Ok(verify_zstd_database_dump_import(&restored_path, dump));
    }
    if dump_is_compressed(&restored_path) {
        return Ok(BackupRestoreDatabaseDumpCheck {
            dump_id: dump.id.clone(),
            restored_path: display_path(&restored_path),
            status: "present_compressed".to_string(),
            detail: "compressed database dump is present; import was not attempted".to_string(),
        });
    }
    let preview = read_text_preview(&restored_path, RESTORE_VERIFY_SQL_PREVIEW_BYTES)?;
    let plausible = preview_contains_sql(&preview);
    if plausible && restore_db_import_check_enabled() && database_dump_kind_importable(dump) {
        return Ok(verify_database_dump_import(&restored_path, dump));
    }
    Ok(BackupRestoreDatabaseDumpCheck {
        dump_id: dump.id.clone(),
        restored_path: display_path(&restored_path),
        status: if plausible {
            "plausible_sql"
        } else {
            "unrecognized"
        }
        .to_string(),
        detail: if plausible {
            "database dump exists and has SQL-like content; import was not attempted".to_string()
        } else {
            "database dump exists but does not look like a plain SQL dump".to_string()
        },
    })
}

fn restore_db_import_check_enabled() -> bool {
    env_source::var_string("OPSCTL_RESTORE_DB_IMPORT_CHECK")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn database_dump_kind_importable(dump: &BackupDatabaseDump) -> bool {
    database_dump_import_kind(dump).is_some()
}

fn verify_database_dump_import(
    restored_path: &Path,
    dump: &BackupDatabaseDump,
) -> BackupRestoreDatabaseDumpCheck {
    let import_path = temporary_import_check_dump_path(restored_path);
    let prepared = copy_dump_for_import_check(restored_path, &import_path);
    let import_path = match prepared {
        Ok(()) => import_path,
        Err(error) => {
            return BackupRestoreDatabaseDumpCheck {
                dump_id: dump.id.clone(),
                restored_path: display_path(restored_path),
                status: "import_failed".to_string(),
                detail: format!("failed to prepare database dump for import check: {error}"),
            };
        }
    };
    let argv = database_dump_import_argv(&import_path, dump);
    let Some((program, args)) = argv.split_first() else {
        let _ = fs::remove_file(&import_path);
        return BackupRestoreDatabaseDumpCheck {
            dump_id: dump.id.clone(),
            restored_path: display_path(restored_path),
            status: "unrecognized".to_string(),
            detail: "database dump kind is not import-checkable".to_string(),
        };
    };
    let result = match command_runner::run_controlled(program, args) {
        Ok(output) if output.success() => BackupRestoreDatabaseDumpCheck {
            dump_id: dump.id.clone(),
            restored_path: display_path(restored_path),
            status: "import_verified".to_string(),
            detail: "database dump imported successfully into an isolated temporary container"
                .to_string(),
        },
        Ok(output) => BackupRestoreDatabaseDumpCheck {
            dump_id: dump.id.clone(),
            restored_path: display_path(restored_path),
            status: "import_failed".to_string(),
            detail: format!(
                "temporary database import container exited non-zero: {}",
                output
                    .status_code
                    .map_or_else(|| "-".to_string(), |code| code.to_string())
            ),
        },
        Err(error) => BackupRestoreDatabaseDumpCheck {
            dump_id: dump.id.clone(),
            restored_path: display_path(restored_path),
            status: "import_failed".to_string(),
            detail: format!("temporary database import container failed: {error}"),
        },
    };
    let _ = fs::remove_file(&import_path);
    result
}

fn verify_zstd_database_dump_import(
    restored_path: &Path,
    dump: &BackupDatabaseDump,
) -> BackupRestoreDatabaseDumpCheck {
    let temporary_path = temporary_decompressed_dump_path(restored_path);
    let result = decompress_zstd_dump(restored_path, &temporary_path)
        .map(|()| verify_database_dump_import(&temporary_path, dump));
    let _ = fs::remove_file(&temporary_path);
    match result {
        Ok(mut check) => {
            check.restored_path = display_path(restored_path);
            if check.status == "import_verified" {
                check.detail =
                    "zstd database dump decompressed and imported successfully into an isolated temporary container"
                        .to_string();
            }
            check
        }
        Err(error) => BackupRestoreDatabaseDumpCheck {
            dump_id: dump.id.clone(),
            restored_path: display_path(restored_path),
            status: "import_failed".to_string(),
            detail: format!("zstd database dump import check failed: {error}"),
        },
    }
}

fn decompress_zstd_dump(source: &Path, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let input =
        fs::File::open(source).with_context(|| format!("failed to open {}", source.display()))?;
    let mut decoder = zstd::Decoder::new(input).context("failed to initialize zstd decoder")?;
    let mut output = create_secure_file(destination)?;
    io::copy(&mut decoder, &mut output).context("failed to decompress database dump")?;
    Ok(())
}

fn temporary_decompressed_dump_path(path: &Path) -> PathBuf {
    let timestamp = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("dump.sql.zst");
    path.with_file_name(format!(
        ".{file_name}.opsctl-restore-{}-{timestamp}.sql",
        std::process::id()
    ))
}

fn temporary_import_check_dump_path(path: &Path) -> PathBuf {
    let timestamp = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("dump.sql");
    path.with_file_name(format!(
        ".{file_name}.opsctl-import-{}-{timestamp}.sql",
        std::process::id()
    ))
}

fn copy_dump_for_import_check(source: &Path, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut input =
        fs::File::open(source).with_context(|| format!("failed to open {}", source.display()))?;
    let mut output = create_readable_temp_file(destination)?;
    io::copy(&mut input, &mut output).context("failed to copy database dump for import check")?;
    Ok(())
}

fn create_readable_temp_file(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o644).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to make {} container-readable", path.display()))?;
    Ok(file)
}

fn database_dump_import_argv(restored_path: &Path, dump: &BackupDatabaseDump) -> Vec<String> {
    let mount = format!("{}:/tmp/opsctl-restore.sql:ro", display_path(restored_path));
    let container_name = format!(
        "opsctl-restore-check-{}-{}",
        sanitize_id_part(&dump.id),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    let mut argv = vec![
        env_source::var_string("OPSCTL_DOCKER_BIN").unwrap_or_else(|| "docker".to_string()),
        "run".to_string(),
        "--rm".to_string(),
        "--network=none".to_string(),
        "--name".to_string(),
        container_name,
        "-v".to_string(),
        mount,
    ];
    match database_dump_import_kind(dump) {
        Some("postgres") => {
            argv.push("--user".to_string());
            argv.push("postgres".to_string());
            argv.push(restore_import_image(
                dump,
                "OPSCTL_RESTORE_POSTGRES_IMAGE",
                "postgres:18-alpine",
            ));
            argv.push("sh".to_string());
            argv.push("-ec".to_string());
            argv.push(postgres_restore_import_script(dump));
        }
        Some("mysql") => {
            argv.push(restore_import_image(
                dump,
                "OPSCTL_RESTORE_MYSQL_IMAGE",
                "mysql:8.0",
            ));
            argv.push("sh".to_string());
            argv.push("-ec".to_string());
            argv.push(mysql_restore_import_script());
        }
        Some("mariadb") => {
            let image = dump.restore_image.clone().unwrap_or_else(|| {
                env_source::var_string("OPSCTL_RESTORE_MARIADB_IMAGE")
                    .or_else(|| env_source::var_string("OPSCTL_RESTORE_MYSQL_IMAGE"))
                    .unwrap_or_else(|| "mariadb:11".to_string())
            });
            argv.push(image);
            argv.push("sh".to_string());
            argv.push("-ec".to_string());
            argv.push(mariadb_restore_import_script());
        }
        _ => {}
    }
    argv
}

fn restore_import_image(dump: &BackupDatabaseDump, env_name: &str, default_image: &str) -> String {
    dump.restore_image
        .clone()
        .or_else(|| env_source::var_string(env_name))
        .unwrap_or_else(|| default_image.to_string())
}

fn postgres_restore_import_script(dump: &BackupDatabaseDump) -> String {
    let server_options = shell_single_quote(&postgres_restore_server_options(dump));
    format!(
        "initdb -D /tmp/pgdata >/dev/null && pg_ctl -D /tmp/pgdata -o {server_options} -w start >/dev/null && createdb -h /tmp restorecheck && psql -h /tmp -d restorecheck -v ON_ERROR_STOP=1 -f /tmp/opsctl-restore.sql >/dev/null"
    )
}

fn postgres_restore_server_options(dump: &BackupDatabaseDump) -> String {
    let mut options = vec!["-k /tmp".to_string()];
    for setting in &dump.restore_postgres_settings {
        options.push(format!("-c {setting}"));
    }
    options.join(" ")
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn mysql_restore_import_script() -> String {
    "mkdir -p /tmp/mysql && chown -R mysql:mysql /tmp/mysql && mysqld --initialize-insecure --datadir=/tmp/mysql --user=mysql >/tmp/mysql-init.log 2>&1 && mysqld --datadir=/tmp/mysql --socket=/tmp/mysql.sock --skip-networking --user=mysql >/tmp/mysql.log 2>&1 & ready=0; for i in $(seq 1 90); do if mysqladmin --socket=/tmp/mysql.sock -uroot ping >/dev/null 2>&1; then ready=1; break; fi; sleep 1; done; test \"$ready\" = 1 && mysql --socket=/tmp/mysql.sock -uroot < /tmp/opsctl-restore.sql >/dev/null".to_string()
}

fn mariadb_restore_import_script() -> String {
    "mariadb-install-db --datadir=/tmp/mysql >/dev/null && mariadbd --datadir=/tmp/mysql --socket=/tmp/mysql.sock --skip-networking --user=root >/tmp/mariadb.log 2>&1 & ready=0; for i in $(seq 1 60); do if mariadb-admin --socket=/tmp/mysql.sock ping >/dev/null 2>&1; then ready=1; break; fi; sleep 1; done; test \"$ready\" = 1 && mariadb --socket=/tmp/mysql.sock -uroot -e 'CREATE DATABASE restorecheck;' && mariadb --socket=/tmp/mysql.sock -uroot restorecheck < /tmp/opsctl-restore.sql >/dev/null".to_string()
}

fn database_dump_import_kind(dump: &BackupDatabaseDump) -> Option<&str> {
    match dump.kind.as_str() {
        "mariadb" | "mysql" | "postgres" => Some(dump.kind.as_str()),
        "external" => dump.verify_kind.as_deref(),
        _ => None,
    }
}

fn restored_dump_path(restore_dir: &Path, output_path: &Path) -> Result<PathBuf> {
    if has_parent_component(output_path) {
        anyhow::bail!("database dump output path contains parent traversal");
    }
    if output_path.is_absolute() {
        Ok(restore_dir.join(output_path.strip_prefix("/")?))
    } else {
        Ok(restore_dir.join(output_path))
    }
}

fn dump_is_compressed(path: &Path) -> bool {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("zst") => dump_is_zstd_compressed(path),
        Some("gz" | "xz" | "bz2") => true,
        _ => false,
    }
}

fn dump_is_zstd_compressed(path: &Path) -> bool {
    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut magic = [0_u8; 4];
    matches!(file.read_exact(&mut magic), Ok(())) && magic == ZSTD_MAGIC
}

fn read_text_preview(path: &Path, max_bytes: usize) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut buffer = vec![0; max_bytes];
    let bytes = file
        .read(&mut buffer)
        .with_context(|| format!("failed to read {}", path.display()))?;
    buffer.truncate(bytes);
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

fn preview_contains_sql(preview: &str) -> bool {
    let upper = preview.to_ascii_uppercase();
    upper.contains("CREATE ")
        || upper.contains("INSERT ")
        || upper.contains("SET ")
        || upper.contains("COPY ")
        || upper.contains("POSTGRESQL")
        || upper.contains("MARIADB")
        || upper.contains("MYSQL")
        || preview.contains("\\connect")
        || preview.trim_start().starts_with("--")
}

struct BackupRestoreDrillInput<'a> {
    service: &'a Service,
    target: &'a BackupTarget,
    repository: &'a BackupRepository,
    repository_snapshot_id: &'a str,
    restore_dir: &'a Path,
    verification: &'a BackupRestoreVerification,
    started_at: OffsetDateTime,
    status: &'a str,
}

fn backup_restore_drill_record(
    input: BackupRestoreDrillInput<'_>,
) -> Result<BackupRestoreDrillRecord> {
    Ok(BackupRestoreDrillRecord {
        id: backup_restore_drill_id(&input.target.id, input.started_at)?,
        service_id: input.service.id.clone(),
        target_id: input.target.id.clone(),
        repository_id: input.repository.id.clone(),
        tool: input.repository.provider.clone(),
        completed_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("failed to format restore drill completion timestamp")?,
        status: input.status.to_string(),
        repository_snapshot_id: input.repository_snapshot_id.to_string(),
        restore_dir: input.restore_dir.to_path_buf(),
        files_checked: input.verification.files_checked,
        bytes_checked: input.verification.bytes_checked,
        sampled_hashes: input.verification.sampled_hashes.clone(),
        database_dump_checks: input.verification.database_dump_checks.clone(),
        limitations: input.verification.limitations.clone(),
        notes: Some("Recorded by opsctl backup restore drill.".to_string()),
    })
}

fn backup_restore_drill_id(target_id: &str, timestamp: OffsetDateTime) -> Result<String> {
    Ok(format!(
        "restore-{}-{}",
        sanitize_id_part(target_id),
        timestamp
            .format(&time::macros::format_description!(
                "[year][month][day][hour][minute][second]"
            ))
            .context("failed to format restore drill id timestamp")?
    ))
}

fn backup_repository_check_record(
    repository: &BackupRepository,
    started_at: OffsetDateTime,
    completed_at: OffsetDateTime,
    status: &str,
) -> Result<BackupRepositoryCheckRecord> {
    let duration_seconds = (completed_at - started_at).whole_seconds().max(0) as u64;
    Ok(BackupRepositoryCheckRecord {
        id: backup_repository_check_id(&repository.id, started_at)?,
        repository_id: repository.id.clone(),
        tool: repository.provider.clone(),
        completed_at: completed_at
            .format(&Rfc3339)
            .context("failed to format repository check completion timestamp")?,
        status: status.to_string(),
        duration_seconds: Some(duration_seconds),
        limitations: Vec::new(),
        notes: Some("Recorded by opsctl backup check.".to_string()),
    })
}

fn backup_repository_check_id(repository_id: &str, timestamp: OffsetDateTime) -> Result<String> {
    Ok(format!(
        "check-{}-{}",
        sanitize_id_part(repository_id),
        timestamp
            .format(&time::macros::format_description!(
                "[year][month][day][hour][minute][second]"
            ))
            .context("failed to format repository check id timestamp")?
    ))
}

fn append_repository_check_history(
    registry_dir: &Path,
    record: &BackupRepositoryCheckRecord,
) -> Result<()> {
    let path = registry_dir.join("backups.yml");
    ensure_regular_file_no_symlink(&path)?;
    let permissions = registry_file_permissions(&path)?;
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read backup registry {}", path.display()))?;
    let mut registry = serde_yaml::from_str::<BackupsRegistry>(&raw)
        .with_context(|| format!("failed to parse backup registry {}", path.display()))?;
    registry.repository_checks.push(record.clone());
    let serialized =
        serde_yaml::to_string(&registry).context("failed to serialize backup registry")?;
    let temporary_path = backup_history_temp_path(&path);
    if let Err(error) = write_secure_file(&temporary_path, serialized.as_bytes()) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    fs::rename(&temporary_path, &path)
        .with_context(|| format!("failed to replace backup registry {}", path.display()))?;
    restore_registry_file_permissions(&path, permissions)?;
    Ok(())
}

fn append_restore_drill_history(
    registry_dir: &Path,
    record: &BackupRestoreDrillRecord,
) -> Result<()> {
    let path = registry_dir.join("backups.yml");
    ensure_regular_file_no_symlink(&path)?;
    let permissions = registry_file_permissions(&path)?;
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read backup registry {}", path.display()))?;
    let mut registry = serde_yaml::from_str::<BackupsRegistry>(&raw)
        .with_context(|| format!("failed to parse backup registry {}", path.display()))?;
    registry.restore_drills.push(record.clone());
    let serialized =
        serde_yaml::to_string(&registry).context("failed to serialize backup registry")?;
    let temporary_path = backup_history_temp_path(&path);
    if let Err(error) = write_secure_file(&temporary_path, serialized.as_bytes()) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    fs::rename(&temporary_path, &path)
        .with_context(|| format!("failed to replace {}", path.display()))?;
    restore_registry_file_permissions(&path, permissions)?;
    Ok(())
}

fn resolve_drill_repository_snapshot_id(options: &BackupDrillOptions<'_>) -> Result<String> {
    if let Some(repository_snapshot_id) = options.repository_snapshot_id {
        validate_repository_snapshot_id(repository_snapshot_id)?;
        return Ok(repository_snapshot_id.to_string());
    }

    let service = service_by_id(options.registry, options.service_id)?;
    let target = restore_target(options.registry, service, options.target_id)?;
    let mut candidates = Vec::new();
    for record in &options.registry.backups.history {
        if record.service_id != service.id
            || record.target_id != target.id
            || record.status != "success"
        {
            continue;
        }
        let Some(repository_snapshot_id) = record.repository_snapshot_id.as_deref() else {
            continue;
        };
        if validate_repository_snapshot_id(repository_snapshot_id).is_err() {
            continue;
        }
        let Ok(completed_at) = parse_completed_at(record) else {
            continue;
        };
        candidates.push((record, completed_at, repository_snapshot_id));
    }
    candidates
        .into_iter()
        .max_by(|left, right| left.1.cmp(&right.1))
        .map(|(_, _, repository_snapshot_id)| repository_snapshot_id.to_string())
        .with_context(|| {
            format!(
                "no successful backup history with repository_snapshot_id found for service {} target {}",
                service.id, target.id
            )
        })
}

fn display_restore_relative_path(restore_dir: &Path, path: &Path) -> String {
    path.strip_prefix(restore_dir)
        .ok()
        .map(display_path)
        .unwrap_or_else(|| display_path(path))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if bytes == 0 {
            break;
        }
        hasher.update(&buffer[..bytes]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn repository_by_id<'a>(
    registry: &'a Registry,
    repository_id: &str,
) -> Result<&'a BackupRepository> {
    registry
        .backups
        .repositories
        .iter()
        .find(|repository| repository.id == repository_id)
        .with_context(|| format!("backup repository not found: {repository_id}"))
}

fn service_by_id<'a>(registry: &'a Registry, service_id: &str) -> Result<&'a Service> {
    registry
        .services
        .services
        .iter()
        .find(|service| service.id == service_id)
        .with_context(|| format!("service not found: {service_id}"))
}

fn service_ids_with_active_backup_targets(registry: &Registry) -> Vec<String> {
    let active_service_ids = registry
        .backups
        .targets
        .iter()
        .filter(|target| target.status == "active")
        .map(|target| target.service_id.clone())
        .collect::<BTreeSet<_>>();
    registry
        .services
        .services
        .iter()
        .filter(|service| active_service_ids.contains(service.id.as_str()))
        .map(|service| service.id.clone())
        .collect()
}

fn blocked_drill_suite_report(
    registry: &Registry,
    service_id: &str,
    restore_dir: &Path,
    execute: bool,
    error: anyhow::Error,
) -> BackupRestoreReport {
    let (service_name, target_id, repository_id, provider) = registry
        .services
        .services
        .iter()
        .find(|service| service.id == service_id)
        .map(|service| {
            let target = registry
                .backups
                .targets
                .iter()
                .find(|target| target.service_id == service.id && target.status == "active");
            let repository =
                target.and_then(|target| repository_by_id(registry, &target.repository_id).ok());
            (
                service.name.clone(),
                target
                    .map(|target| target.id.clone())
                    .unwrap_or_else(|| "-".to_string()),
                target
                    .map(|target| target.repository_id.clone())
                    .unwrap_or_else(|| "-".to_string()),
                repository
                    .map(|repository| repository.provider.clone())
                    .unwrap_or_else(|| "-".to_string()),
            )
        })
        .unwrap_or_else(|| {
            (
                service_id.to_string(),
                "-".to_string(),
                "-".to_string(),
                "-".to_string(),
            )
        });
    BackupRestoreReport {
        ok: false,
        service_id: service_id.to_string(),
        target_id,
        repository_id,
        provider,
        repository_snapshot_id: "-".to_string(),
        restore_dir: display_path(restore_dir),
        execute,
        status: "blocked".to_string(),
        approval_required: false,
        expected_approval_token: None,
        required_env: Vec::new(),
        missing_env: Vec::new(),
        operations: Vec::new(),
        verification: None,
        restore_drill_record: None,
        limitations: vec![format!(
            "restore drill planning failed for {service_name}: {error}"
        )],
    }
}

fn restore_target<'a>(
    registry: &'a Registry,
    service: &Service,
    target_id: Option<&str>,
) -> Result<&'a BackupTarget> {
    let active_targets = registry
        .backups
        .targets
        .iter()
        .filter(|target| target.service_id == service.id && target.status == "active")
        .collect::<Vec<_>>();
    if let Some(target_id) = target_id {
        return active_targets
            .into_iter()
            .find(|target| target.id == target_id)
            .with_context(|| format!("active backup target not found: {target_id}"));
    }
    match active_targets.as_slice() {
        [target] => Ok(*target),
        [] => anyhow::bail!("service {} has no active backup target", service.id),
        _ => anyhow::bail!(
            "service {} has multiple active backup targets; pass --target",
            service.id
        ),
    }
}

fn restore_limitations(
    registry: &Registry,
    service: &Service,
    target: &BackupTarget,
    repository: &BackupRepository,
) -> Vec<String> {
    let mut limitations = Vec::new();
    if repository.status != "active" {
        limitations.push(format!(
            "repository {} is not active: {}",
            repository.id, repository.status
        ));
    }
    if !is_supported_backup_provider(&repository.provider) {
        limitations.push(format!(
            "provider {} is not executable in current backup restore planning",
            repository.provider
        ));
    }
    if repository.repository.is_none() && repository.repository_env.is_none() {
        limitations.push("restic repository source is missing".to_string());
    }
    if repository.password_env.is_none() {
        limitations.push("restic password_env is missing".to_string());
    }
    if !registry
        .services
        .services
        .iter()
        .any(|candidate| candidate.id == service.id)
    {
        limitations.push(format!("service {} is not registered", service.id));
    }
    if target.include_paths.is_empty() {
        limitations.push("backup target include_paths is empty".to_string());
    }
    limitations
}

fn validate_repository_snapshot_id(repository_snapshot_id: &str) -> Result<()> {
    if repository_snapshot_id.is_empty()
        || repository_snapshot_id.len() > 128
        || repository_snapshot_id == "."
        || repository_snapshot_id == ".."
        || repository_snapshot_id.contains("..")
        || !repository_snapshot_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
    {
        anyhow::bail!("invalid repository snapshot id");
    }
    Ok(())
}

fn validate_restore_dir(
    registry: &Registry,
    service: &Service,
    target: &BackupTarget,
    restore_dir: &Path,
) -> Vec<String> {
    let mut limitations = Vec::new();
    if !restore_dir.is_absolute() {
        limitations.push(format!(
            "restore_dir must be absolute: {}",
            display_path(restore_dir)
        ));
    }
    if has_parent_component(restore_dir) {
        limitations.push("restore_dir must not contain parent traversal".to_string());
    }
    if is_protected_restore_root(restore_dir) {
        limitations.push(format!(
            "restore_dir is a protected production root: {}",
            display_path(restore_dir)
        ));
    }
    if restore_dir_conflicts_with_registered_paths(registry, service, target, restore_dir) {
        limitations.push(
            "restore_dir overlaps a registered service root, data path, backup include path, or dump output"
                .to_string(),
        );
    }
    if let Some(ancestor) = symlink_ancestor(restore_dir) {
        limitations.push(format!(
            "restore_dir ancestor must not be a symlink: {}",
            display_path(&ancestor)
        ));
    }

    match fs::symlink_metadata(restore_dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                limitations.push(format!(
                    "restore_dir must not be a symlink: {}",
                    display_path(restore_dir)
                ));
            } else if !metadata.is_dir() {
                limitations.push(format!(
                    "restore_dir must be a directory when it already exists: {}",
                    display_path(restore_dir)
                ));
            } else if !directory_is_empty(restore_dir) {
                limitations.push(format!(
                    "restore_dir must be empty when it already exists: {}",
                    display_path(restore_dir)
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => match restore_dir.parent() {
            Some(parent) => match fs::symlink_metadata(parent) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        limitations.push(format!(
                            "restore_dir parent must not be a symlink: {}",
                            display_path(parent)
                        ));
                    } else if !metadata.is_dir() {
                        limitations.push(format!(
                            "restore_dir parent must be a directory: {}",
                            display_path(parent)
                        ));
                    }
                }
                Err(parent_error) => limitations.push(format!(
                    "restore_dir parent could not be inspected: {parent_error}"
                )),
            },
            None => limitations.push("restore_dir has no parent directory".to_string()),
        },
        Err(error) => limitations.push(format!("restore_dir could not be inspected: {error}")),
    }
    limitations
}

fn validate_scheduled_restore_drill_dir(restore_dir: &Path) -> Result<()> {
    let allowed_root = Path::new("/var/lib/opsctl/restore-drills");
    if !restore_dir.is_absolute()
        || has_parent_component(restore_dir)
        || !restore_dir.starts_with(allowed_root)
        || restore_dir == allowed_root
    {
        anyhow::bail!(
            "scheduled restore drill must use a service staging directory under {}",
            allowed_root.display()
        );
    }
    Ok(())
}

fn scheduled_restore_drill_run_dir(base_dir: &Path) -> PathBuf {
    base_dir.join(format!(
        "run-{}-{}",
        OffsetDateTime::now_utc().unix_timestamp_nanos(),
        std::process::id()
    ))
}

fn directory_is_empty(path: &Path) -> bool {
    match fs::read_dir(path) {
        Ok(mut entries) => entries.next().is_none(),
        Err(_) => false,
    }
}

fn is_protected_restore_root(path: &Path) -> bool {
    let protected_paths = [
        Path::new("/"),
        Path::new("/etc"),
        Path::new("/srv"),
        Path::new("/var"),
        Path::new("/var/lib"),
        Path::new("/home"),
        Path::new("/root"),
    ];
    protected_paths.contains(&path)
}

fn symlink_ancestor(path: &Path) -> Option<PathBuf> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir | Component::Prefix(_) => return None,
        }
        if current == path {
            break;
        }
        if fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Some(current);
        }
    }
    None
}

fn restore_dir_conflicts_with_registered_paths(
    registry: &Registry,
    service: &Service,
    target: &BackupTarget,
    restore_dir: &Path,
) -> bool {
    service
        .root
        .iter()
        .chain(service.data_paths.iter())
        .chain(target.include_paths.iter())
        .chain(target.database_dumps.iter().map(|dump| &dump.output_path))
        .any(|path| paths_overlap(restore_dir, path))
        || registry
            .services
            .services
            .iter()
            .flat_map(|registered| registered.data_paths.iter().chain(registered.root.iter()))
            .any(|path| paths_overlap(restore_dir, path))
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn ensure_repository_executable(repository: &BackupRepository) -> Result<()> {
    if repository.status != "active" {
        anyhow::bail!(
            "backup repository {} is not active: {}",
            repository.id,
            repository.status
        );
    }
    if !is_supported_backup_provider(&repository.provider) {
        anyhow::bail!(
            "backup repository {} uses unsupported provider {}",
            repository.id,
            repository.provider
        );
    }
    let missing = missing_env(repository);
    if !missing.is_empty() {
        anyhow::bail!(
            "backup repository {} is missing required environment variables: {}",
            repository.id,
            missing.join(", ")
        );
    }
    Ok(())
}

fn is_supported_backup_provider(provider: &str) -> bool {
    matches!(provider, "restic" | "rustic")
}

fn is_backup_execution_operation(kind: &str) -> bool {
    matches!(
        kind,
        "restic_unlock"
            | "restic_backup"
            | "restic_forget_prune"
            | "restic_check"
            | "restic_restore"
            | "rustic_backup"
            | "rustic_forget_prune"
            | "rustic_check"
            | "rustic_restore"
    )
}

#[derive(Debug, Clone)]
struct ExternalDumpCommand {
    adapter: String,
    script: String,
    working_dir: PathBuf,
}

fn validate_database_dump(service: &Service, dump: &BackupDatabaseDump) -> Result<()> {
    if !is_supported_database_dump_kind(&dump.kind) {
        anyhow::bail!(
            "database dump kind {} is not executable; use mariadb, mysql, postgres, or external",
            dump.kind
        );
    }
    if let Some(image) = dump.restore_image.as_deref() {
        validate_restore_image(image)?;
    }
    if let Some(verify_kind) = dump.verify_kind.as_deref()
        && !matches!(verify_kind, "mariadb" | "mysql" | "postgres")
    {
        anyhow::bail!(
            "database dump verify_kind {} is not supported; use mariadb, mysql, or postgres",
            verify_kind
        );
    }
    validate_restore_postgres_settings(dump)?;
    let _ = external_dump_command(service, dump)?;
    Ok(())
}

fn validate_restore_image(image: &str) -> Result<()> {
    if image.is_empty() || image.len() > 256 {
        anyhow::bail!("database dump restore_image must be 1-256 characters");
    }
    if image.starts_with('-') || image.chars().any(|character| character.is_whitespace()) {
        anyhow::bail!("database dump restore_image must not start with '-' or contain whitespace");
    }
    if !image
        .chars()
        .all(|character| character.is_ascii_graphic() && character != '\'' && character != '"')
    {
        anyhow::bail!("database dump restore_image contains unsupported characters");
    }
    Ok(())
}

fn validate_restore_postgres_settings(dump: &BackupDatabaseDump) -> Result<()> {
    if dump.restore_postgres_settings.is_empty() {
        return Ok(());
    }
    if database_dump_import_kind(dump) != Some("postgres") {
        anyhow::bail!(
            "database dump restore_postgres_settings can only be used for postgres import checks"
        );
    }
    for setting in &dump.restore_postgres_settings {
        if setting.is_empty() || setting.len() > 160 || !setting.contains('=') {
            anyhow::bail!("postgres restore setting must be key=value and 1-160 characters");
        }
        if !setting.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ',' | '=')
        }) {
            anyhow::bail!("postgres restore setting contains unsupported characters: {setting}");
        }
    }
    Ok(())
}

fn external_dump_command(
    service: &Service,
    dump: &BackupDatabaseDump,
) -> Result<Option<ExternalDumpCommand>> {
    if dump.kind != "external" {
        if dump.adapter.is_some() || dump.script.is_some() || dump.working_dir.is_some() {
            anyhow::bail!(
                "database dump {} can only declare adapter/script/working_dir when kind is external",
                dump.id
            );
        }
        return Ok(None);
    }
    match (dump.adapter.as_deref(), dump.script.as_deref()) {
        (None, None) => {
            if dump.working_dir.is_some() {
                anyhow::bail!(
                    "external database dump {} sets working_dir but no adapter/script",
                    dump.id
                );
            }
            Ok(None)
        }
        (Some(adapter), Some(script)) => {
            validate_external_dump_adapter(adapter)?;
            validate_external_dump_script_name(script)?;
            ensure_external_dump_script_declared(service, adapter, script)?;
            let working_dir = resolve_external_dump_working_dir(service, dump)?;
            Ok(Some(ExternalDumpCommand {
                adapter: adapter.to_string(),
                script: script.to_string(),
                working_dir,
            }))
        }
        _ => {
            anyhow::bail!(
                "external database dump {} must set adapter and script together",
                dump.id
            );
        }
    }
}

fn validate_external_dump_adapter(adapter: &str) -> Result<()> {
    if matches!(adapter, "npm" | "pnpm" | "bun") {
        Ok(())
    } else {
        anyhow::bail!("external database dump adapter must be npm, pnpm, or bun");
    }
}

fn validate_external_dump_script_name(script: &str) -> Result<()> {
    if script.is_empty() || script.len() > 64 {
        anyhow::bail!("external database dump script name must be 1-64 characters");
    }
    if !script
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, ':' | '_' | '-'))
    {
        anyhow::bail!(
            "external database dump script name contains unsupported characters: {script}"
        );
    }
    Ok(())
}

fn ensure_external_dump_script_declared(
    service: &Service,
    adapter: &str,
    script: &str,
) -> Result<()> {
    let declared = service.deployment.as_ref().is_some_and(|deployment| {
        deployment.build.iter().any(|build| {
            build.adapter == adapter && build.scripts.iter().any(|item| item == script)
        })
    });
    if declared {
        Ok(())
    } else {
        anyhow::bail!(
            "external database dump script {adapter} run {script} is not declared in services.yml deployment.build for service {}",
            service.id
        );
    }
}

fn resolve_external_dump_working_dir(
    service: &Service,
    dump: &BackupDatabaseDump,
) -> Result<PathBuf> {
    let working_dir = match dump.working_dir.as_ref() {
        Some(working_dir) => working_dir.clone(),
        None => match service.root.as_slice() {
            [root] => root.clone(),
            [] => anyhow::bail!(
                "external database dump {} must set working_dir because service {} has no root",
                dump.id,
                service.id
            ),
            _ => anyhow::bail!(
                "external database dump {} must set working_dir because service {} has multiple roots",
                dump.id,
                service.id
            ),
        },
    };
    if !working_dir.is_absolute() || has_parent_component(&working_dir) {
        anyhow::bail!(
            "external database dump working_dir is unsafe: {}",
            display_path(&working_dir)
        );
    }
    if !service
        .root
        .iter()
        .any(|root| working_dir == *root || working_dir.starts_with(root))
    {
        anyhow::bail!(
            "external database dump working_dir {} is outside registered service root(s) for {}",
            display_path(&working_dir),
            service.id
        );
    }
    Ok(working_dir)
}

#[cfg(test)]
pub fn execute_database_dump_to_path(
    dump: &BackupDatabaseDump,
    output_path: &Path,
) -> Result<DatabaseDumpExecution> {
    if dump.kind == "external" && (dump.adapter.is_some() || dump.script.is_some()) {
        anyhow::bail!(
            "scripted external database dump {} requires service deployment contract validation",
            dump.id
        );
    }
    execute_database_dump(dump, output_path, None)
}

pub fn execute_database_dump_for_service(
    service: &Service,
    dump: &BackupDatabaseDump,
    output_path: &Path,
) -> Result<DatabaseDumpExecution> {
    execute_database_dump(dump, output_path, Some(service))
}

fn execute_database_dump(
    dump: &BackupDatabaseDump,
    output_path: &Path,
    service: Option<&Service>,
) -> Result<DatabaseDumpExecution> {
    let argv = database_dump_argv(dump);
    if argv.is_empty() {
        copy_external_database_dump(dump, output_path)?;
        return Ok(DatabaseDumpExecution {
            argv,
            output_path: display_path(output_path),
            compressed: false,
            duration_seconds: 0,
        });
    }
    if dump.kind == "external" {
        let Some(service) = service else {
            anyhow::bail!(
                "scripted external database dump {} requires service deployment contract validation",
                dump.id
            );
        };
        return execute_external_database_dump_script(service, dump, output_path, argv);
    }

    let started = OffsetDateTime::now_utc();
    let compressed = output_path.extension().and_then(|value| value.to_str()) == Some("zst");
    let temporary_path = temporary_dump_path(output_path);
    let Some((program, args)) = argv.split_first() else {
        anyhow::bail!("database dump argv is empty");
    };
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to start database dump command: {program}"))?;
    let stdout = child
        .stdout
        .take()
        .context("failed to capture database dump stdout")?;
    if let Err(error) = write_database_dump_output(stdout, &temporary_path, compressed) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    let status = child
        .wait()
        .with_context(|| format!("failed to wait for database dump command: {program}"))?;
    if !status.success() {
        let _ = fs::remove_file(&temporary_path);
        anyhow::bail!(
            "database dump command {} failed with exit code {:?}",
            program,
            status.code()
        );
    }
    if let Ok(metadata) = fs::symlink_metadata(output_path) {
        if metadata.file_type().is_symlink() {
            let _ = fs::remove_file(&temporary_path);
            anyhow::bail!(
                "refusing to overwrite database dump symlink {}",
                display_path(output_path)
            );
        }
        if !metadata.is_file() {
            let _ = fs::remove_file(&temporary_path);
            anyhow::bail!(
                "database dump output path is not a regular file: {}",
                display_path(output_path)
            );
        }
    }
    fs::rename(&temporary_path, output_path).with_context(|| {
        format!(
            "failed to move temporary database dump {} to {}",
            temporary_path.display(),
            output_path.display()
        )
    })?;
    Ok(DatabaseDumpExecution {
        argv,
        output_path: display_path(output_path),
        compressed,
        duration_seconds: (OffsetDateTime::now_utc() - started).whole_seconds().max(0) as u64,
    })
}

fn temporary_dump_path(output_path: &Path) -> PathBuf {
    let timestamp = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let file_name = output_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("dump");
    output_path.with_file_name(format!(
        ".{file_name}.opsctl-{}-{timestamp}.tmp",
        std::process::id()
    ))
}

fn write_database_dump_output(
    stdout: impl io::Read,
    output_path: &Path,
    compressed: bool,
) -> Result<()> {
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut output_options = fs::OpenOptions::new();
    output_options.write(true).create_new(true);
    #[cfg(unix)]
    output_options.mode(0o600);
    let output = output_options
        .open(output_path)
        .with_context(|| format!("failed to create {}", output_path.display()))?;
    if compressed {
        let mut encoder = zstd::Encoder::new(output, 3)
            .context("failed to initialize zstd database dump encoder")?;
        let mut input = stdout;
        io::copy(&mut input, &mut encoder).context("failed to write compressed database dump")?;
        encoder
            .finish()
            .context("failed to finish compressed database dump")?;
    } else {
        let mut input = stdout;
        let mut output = output;
        io::copy(&mut input, &mut output).context("failed to write database dump")?;
    }
    Ok(())
}

fn execute_external_database_dump_script(
    service: &Service,
    dump: &BackupDatabaseDump,
    output_path: &Path,
    argv: Vec<String>,
) -> Result<DatabaseDumpExecution> {
    let Some(command) = external_dump_command(service, dump)? else {
        anyhow::bail!(
            "external database dump {} has no configured script",
            dump.id
        );
    };
    if !output_path.is_absolute() || has_parent_component(output_path) {
        anyhow::bail!(
            "external database dump output path is unsafe: {}",
            display_path(output_path)
        );
    }
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if let Some(symlink) = symlink_ancestor(&command.working_dir) {
        anyhow::bail!(
            "external database dump working_dir has symlink ancestor: {}",
            display_path(&symlink)
        );
    }
    if !command.working_dir.is_dir() {
        anyhow::bail!(
            "external database dump working_dir is not a directory: {}",
            display_path(&command.working_dir)
        );
    }

    let started = OffsetDateTime::now_utc();
    let temporary_path = temporary_dump_path(output_path);
    let args = vec!["run".to_string(), command.script.clone()];
    let mut envs = vec![
        (
            "OPSCTL_BACKUP_DUMP_OUTPUT".to_string(),
            temporary_path.as_os_str().to_os_string(),
        ),
        (
            "OPSCTL_BACKUP_DUMP_FINAL_OUTPUT".to_string(),
            output_path.as_os_str().to_os_string(),
        ),
        (
            "OPSCTL_BACKUP_DUMP_ID".to_string(),
            OsString::from(&dump.id),
        ),
    ];
    if let Some(database) = &dump.database {
        envs.push((
            "OPSCTL_BACKUP_DATABASE".to_string(),
            OsString::from(database),
        ));
    }

    let captured = command_runner::run_controlled_with_env_in_dir(
        &command.adapter,
        &args,
        &envs,
        &command.working_dir,
    );
    let captured = match captured {
        Ok(captured) => captured,
        Err(error) => {
            let _ = fs::remove_file(&temporary_path);
            return Err(error);
        }
    };
    if !captured.success() {
        let _ = fs::remove_file(&temporary_path);
        anyhow::bail!(
            "external database dump script {} run {} failed with exit code {:?}; stdout/stderr were not persisted",
            command.adapter,
            command.script,
            captured.status_code
        );
    }

    let metadata = match fs::symlink_metadata(&temporary_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            anyhow::bail!(
                "external database dump script did not write OPSCTL_BACKUP_DUMP_OUTPUT {}: {}",
                display_path(&temporary_path),
                error
            );
        }
    };
    if metadata.file_type().is_symlink() {
        let _ = fs::remove_file(&temporary_path);
        anyhow::bail!(
            "external database dump script wrote a symlink: {}",
            display_path(&temporary_path)
        );
    }
    if !metadata.is_file() || metadata.len() == 0 {
        let _ = fs::remove_file(&temporary_path);
        anyhow::bail!(
            "external database dump script output is not a non-empty regular file: {}",
            display_path(&temporary_path)
        );
    }
    if let Ok(metadata) = fs::symlink_metadata(output_path) {
        if metadata.file_type().is_symlink() {
            let _ = fs::remove_file(&temporary_path);
            anyhow::bail!(
                "refusing to overwrite database dump symlink {}",
                display_path(output_path)
            );
        }
        if !metadata.is_file() {
            let _ = fs::remove_file(&temporary_path);
            anyhow::bail!(
                "database dump output path is not a regular file: {}",
                display_path(output_path)
            );
        }
    }
    fs::rename(&temporary_path, output_path).with_context(|| {
        format!(
            "failed to move external database dump {} to {}",
            temporary_path.display(),
            output_path.display()
        )
    })?;

    Ok(DatabaseDumpExecution {
        argv,
        output_path: display_path(output_path),
        compressed: output_path.extension().and_then(|value| value.to_str()) == Some("zst"),
        duration_seconds: (OffsetDateTime::now_utc() - started).whole_seconds().max(0) as u64,
    })
}

fn copy_external_database_dump(dump: &BackupDatabaseDump, output_path: &Path) -> Result<()> {
    if dump.kind != "external" {
        anyhow::bail!("database dump kind {} is not executable", dump.kind);
    }
    if !dump.output_path.is_absolute() || has_parent_component(&dump.output_path) {
        anyhow::bail!(
            "external database dump path is unsafe: {}",
            display_path(&dump.output_path)
        );
    }
    if dump.output_path == output_path {
        let _ = open_regular_file_no_follow(output_path)?;
        return Ok(());
    }
    copy_regular_file_no_follow(&dump.output_path, output_path)?;
    Ok(())
}

fn database_dump_argv(dump: &BackupDatabaseDump) -> Vec<String> {
    match dump.kind.as_str() {
        "mariadb" | "mysql" => mysql_dump_argv(dump),
        "postgres" => postgres_dump_argv(dump),
        "external" => match (dump.adapter.as_ref(), dump.script.as_ref()) {
            (Some(adapter), Some(script)) => {
                vec![adapter.clone(), "run".to_string(), script.clone()]
            }
            _ => Vec::new(),
        },
        "sqlite" => Vec::new(),
        _ => Vec::new(),
    }
}

fn is_supported_database_dump_kind(kind: &str) -> bool {
    matches!(kind, "mariadb" | "mysql" | "postgres" | "external")
}

fn copy_regular_file_no_follow(source: &Path, destination: &Path) -> Result<()> {
    let mut input = open_regular_file_no_follow(source)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut output = create_secure_file(destination)?;
    if let Err(error) = io::copy(&mut input, &mut output) {
        let _ = fs::remove_file(destination);
        anyhow::bail!(
            "failed to copy external database dump {} to {}: {}",
            source.display(),
            destination.display(),
            error
        );
    }
    Ok(())
}

fn open_regular_file_no_follow(path: &Path) -> Result<fs::File> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to open external database dump symlink: {}",
            path.display()
        );
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!(
            "external database dump path is not a regular file: {}",
            display_path(path)
        );
    }
    Ok(file)
}

fn create_secure_file(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))
}

fn mysql_dump_argv(dump: &BackupDatabaseDump) -> Vec<String> {
    let binary = if dump.kind == "mysql" {
        env_source::var_string("OPSCTL_MYSQL_DUMP_BIN").unwrap_or_else(|| "mysqldump".to_string())
    } else {
        env_source::var_string("OPSCTL_MARIADB_DUMP_BIN")
            .unwrap_or_else(|| "mariadb-dump".to_string())
    };
    if dump
        .container
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && dump.database.as_deref() == Some("configured-by-env")
    {
        let mut argv = container_prefix(dump);
        argv.push("sh".to_string());
        argv.push("-lc".to_string());
        argv.push(mysql_container_env_dump_script(&binary));
        return argv;
    }
    let mut argv = container_prefix(dump);
    argv.push(binary);
    argv.push("--single-transaction".to_string());
    match dump
        .database
        .as_deref()
        .filter(|database| !database.trim().is_empty() && *database != "configured-by-env")
    {
        Some(database) => {
            argv.push("--databases".to_string());
            argv.push(database.to_string());
        }
        None => argv.push("--all-databases".to_string()),
    }
    argv
}

fn mysql_container_env_dump_script(binary: &str) -> String {
    let binary = if safe_shell_word(binary) {
        binary
    } else {
        "mysqldump"
    };
    format!(
        r#"set -eu
if [ -n "${{MYSQL_ROOT_PASSWORD:-}}" ]; then
  export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
  if [ -n "${{MYSQL_DATABASE:-}}" ]; then
    exec {binary} -uroot --single-transaction --databases "$MYSQL_DATABASE"
  fi
  echo "MYSQL_DATABASE is required for configured-by-env root dump" >&2
  exit 2
fi
if [ -n "${{MYSQL_USER:-}}" ] && [ -n "${{MYSQL_PASSWORD:-}}" ]; then
  export MYSQL_PWD="$MYSQL_PASSWORD"
  if [ -n "${{MYSQL_DATABASE:-}}" ]; then
    exec {binary} -u"$MYSQL_USER" --single-transaction --databases "$MYSQL_DATABASE"
  fi
  echo "MYSQL_DATABASE is required for configured-by-env user dump" >&2
  exit 2
fi
if [ -n "${{MARIADB_ROOT_PASSWORD:-}}" ]; then
  export MYSQL_PWD="$MARIADB_ROOT_PASSWORD"
  if [ -n "${{MARIADB_DATABASE:-}}" ]; then
    exec {binary} -uroot --single-transaction --databases "$MARIADB_DATABASE"
  fi
  echo "MARIADB_DATABASE is required for configured-by-env root dump" >&2
  exit 2
fi
if [ -n "${{MARIADB_USER:-}}" ] && [ -n "${{MARIADB_PASSWORD:-}}" ]; then
  export MYSQL_PWD="$MARIADB_PASSWORD"
  if [ -n "${{MARIADB_DATABASE:-}}" ]; then
    exec {binary} -u"$MARIADB_USER" --single-transaction --databases "$MARIADB_DATABASE"
  fi
  echo "MARIADB_DATABASE is required for configured-by-env user dump" >&2
  exit 2
fi
echo "MYSQL_* or MARIADB_* credentials are required for configured-by-env dump" >&2
exit 2"#
    )
}

fn safe_shell_word(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
}

fn postgres_dump_argv(dump: &BackupDatabaseDump) -> Vec<String> {
    if dump
        .container
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && dump.database.as_deref() == Some("configured-by-env")
    {
        let mut argv = container_prefix(dump);
        argv.push("sh".to_string());
        argv.push("-lc".to_string());
        argv.push(postgres_container_env_dump_script());
        return argv;
    }
    let mut argv = container_prefix(dump);
    match dump
        .database
        .as_deref()
        .filter(|database| !database.trim().is_empty() && *database != "configured-by-env")
    {
        Some(database) => {
            argv.push(
                env_source::var_string("OPSCTL_PG_DUMP_BIN")
                    .unwrap_or_else(|| "pg_dump".to_string()),
            );
            argv.push("--format=plain".to_string());
            argv.push("--no-owner".to_string());
            argv.push("--no-privileges".to_string());
            argv.push(database.to_string());
        }
        None => argv.push(
            env_source::var_string("OPSCTL_PG_DUMPALL_BIN")
                .unwrap_or_else(|| "pg_dumpall".to_string()),
        ),
    }
    argv
}

fn postgres_container_env_dump_script() -> String {
    r#"set -eu
if [ -z "${POSTGRES_USER:-}" ]; then
  echo "POSTGRES_USER is required for configured-by-env dump" >&2
  exit 2
fi
if [ -n "${POSTGRES_PASSWORD:-}" ]; then
  export PGPASSWORD="$POSTGRES_PASSWORD"
fi
if [ -n "${POSTGRES_DB:-}" ]; then
  exec pg_dump --format=plain --no-owner --no-privileges -U "$POSTGRES_USER" "$POSTGRES_DB"
fi
echo "POSTGRES_DB is required for configured-by-env dump" >&2
exit 2"#
        .to_string()
}

fn container_prefix(dump: &BackupDatabaseDump) -> Vec<String> {
    match dump
        .container
        .as_deref()
        .filter(|container| !container.trim().is_empty())
    {
        Some(container) => vec![
            "docker".to_string(),
            "exec".to_string(),
            container.to_string(),
        ],
        None => Vec::new(),
    }
}

fn repository_source(repository: &BackupRepository) -> String {
    if let Some(name) = &repository.repository_env {
        format!("env:{name}")
    } else if repository.repository.is_some() {
        "inline".to_string()
    } else {
        "missing".to_string()
    }
}

fn required_env(repository: &BackupRepository) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(name) = &repository.repository_env {
        names.push(name.clone());
    }
    if let Some(name) = &repository.password_env {
        names.push(name.clone());
    }
    names.extend(repository.env.iter().cloned());
    unique_sorted(names)
}

fn missing_env(repository: &BackupRepository) -> Vec<String> {
    required_env(repository)
        .into_iter()
        .filter(|name| env_source::var_os(name).is_none())
        .collect()
}

fn check_unique_values<'a>(
    values: impl Iterator<Item = &'a str>,
    code: &str,
    message: &str,
    findings: &mut Vec<BackupFinding>,
) {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            findings.push(error(
                code,
                format!("{message}: {value}"),
                Some(value.to_string()),
            ));
        }
    }
}

fn unique_sorted(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn path_strings(paths: &[std::path::PathBuf]) -> Vec<String> {
    paths.iter().map(|path| display_path(path)).collect()
}

fn latest_target_record<'a>(
    records: &'a [ParsedBackupRecord<'a>],
    target_id: &str,
) -> Option<&'a ParsedBackupRecord<'a>> {
    records
        .iter()
        .filter(|record| record.record.target_id == target_id)
        .max_by(|left, right| left.completed_at.cmp(&right.completed_at))
}

fn backup_history_target_issue(
    service_id: &str,
    target: &BackupTarget,
    issue: &str,
    detail: String,
    latest: Option<&ParsedBackupRecord<'_>>,
    max_age_hours: Option<u32>,
) -> BackupHistoryTargetIssue {
    BackupHistoryTargetIssue {
        target_id: target.id.clone(),
        repository_id: target.repository_id.clone(),
        issue: issue.to_string(),
        detail,
        max_age_hours,
        latest_record_id: latest.map(|record| record.record.id.clone()),
        latest_status: latest.map(|record| record.record.status.clone()),
        latest_completed_at: latest.map(|record| record.record.completed_at.clone()),
        remediation_commands: backup_history_remediation_commands(service_id, target),
    }
}

fn repository_check_target_issue(
    service_id: &str,
    target: &BackupTarget,
    check: &ParsedRepositoryCheck<'_>,
    now_utc: OffsetDateTime,
    max_age_hours: u32,
) -> BackupHistoryTargetIssue {
    let issue = if check.record.status != "success" {
        "repository_check_not_success"
    } else if check.completed_at > now_utc {
        "future_repository_check_timestamp"
    } else if now_utc - check.completed_at > Duration::hours(i64::from(max_age_hours)) {
        "stale_repository_check"
    } else {
        "repository_check_limited"
    };
    let detail = match issue {
        "repository_check_not_success" => format!(
            "latest repository check {} for target {} finished with status {}",
            check.record.id, target.id, check.record.status
        ),
        "future_repository_check_timestamp" => format!(
            "repository check record {} for target {} has a completed_at timestamp in the future",
            check.record.id, target.id
        ),
        "stale_repository_check" => format!(
            "latest repository check {} for target {} completed at {} is older than {} hour(s)",
            check.record.id, target.id, check.record.completed_at, max_age_hours
        ),
        _ => format!(
            "latest repository check {} for target {} has limitation(s)",
            check.record.id, target.id
        ),
    };
    BackupHistoryTargetIssue {
        target_id: target.id.clone(),
        repository_id: target.repository_id.clone(),
        issue: issue.to_string(),
        detail,
        max_age_hours: Some(max_age_hours),
        latest_record_id: Some(check.record.id.clone()),
        latest_status: Some(check.record.status.clone()),
        latest_completed_at: Some(check.record.completed_at.clone()),
        remediation_commands: backup_history_remediation_commands(service_id, target),
    }
}

fn restore_drill_target_issue(
    service_id: &str,
    target: &BackupTarget,
    drill: &ParsedRestoreDrill<'_>,
    now_utc: OffsetDateTime,
    max_age_hours: u32,
) -> BackupHistoryTargetIssue {
    let issue = if drill.record.status != "success" {
        "restore_drill_not_success"
    } else if drill.completed_at > now_utc {
        "future_restore_drill_timestamp"
    } else if now_utc - drill.completed_at > Duration::hours(i64::from(max_age_hours)) {
        "stale_restore_drill"
    } else {
        "restore_drill_limited"
    };
    let detail = match issue {
        "restore_drill_not_success" => format!(
            "latest restore drill {} for target {} finished with status {}",
            drill.record.id, target.id, drill.record.status
        ),
        "future_restore_drill_timestamp" => format!(
            "restore drill record {} for target {} has a completed_at timestamp in the future",
            drill.record.id, target.id
        ),
        "stale_restore_drill" => format!(
            "latest restore drill {} for target {} completed at {} is older than {} hour(s)",
            drill.record.id, target.id, drill.record.completed_at, max_age_hours
        ),
        _ => format!(
            "latest restore drill {} for target {} has limitation(s)",
            drill.record.id, target.id
        ),
    };
    BackupHistoryTargetIssue {
        target_id: target.id.clone(),
        repository_id: target.repository_id.clone(),
        issue: issue.to_string(),
        detail,
        max_age_hours: Some(max_age_hours),
        latest_record_id: Some(drill.record.id.clone()),
        latest_status: Some(drill.record.status.clone()),
        latest_completed_at: Some(drill.record.completed_at.clone()),
        remediation_commands: backup_history_remediation_commands(service_id, target),
    }
}

fn backup_history_remediation_commands(service_id: &str, target: &BackupTarget) -> Vec<String> {
    vec![
        format!(
            "opsctl backup run {} --target {} --execute",
            service_id, target.id
        ),
        format!("opsctl backup check {}", target.repository_id),
        format!(
            "opsctl backup drill-suite --service {} --restore-root /var/lib/opsctl/restore-drills --execute",
            service_id
        ),
    ]
}

fn backup_refresh_stale_commands(
    service_id: &str,
    target_ids: &[String],
    repository_ids: &[String],
    restore_root: &Path,
) -> Vec<String> {
    let mut commands = target_ids
        .iter()
        .map(|target_id| {
            format!(
                "opsctl backup run {} --target {} --execute",
                command_hint_arg(service_id),
                command_hint_arg(target_id)
            )
        })
        .collect::<Vec<_>>();
    commands.extend(
        repository_ids.iter().map(|repository_id| {
            format!("opsctl backup check {}", command_hint_arg(repository_id))
        }),
    );
    commands.push(format!(
        "opsctl backup drill-suite --service {} --restore-root {} --execute",
        command_hint_arg(service_id),
        command_hint_arg(&display_path(restore_root))
    ));
    unique_sorted(commands)
}

fn command_hint_arg(value: &str) -> String {
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

fn unique_backup_history_target_issues(
    issues: Vec<BackupHistoryTargetIssue>,
) -> Vec<BackupHistoryTargetIssue> {
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();
    for issue in issues {
        let key = (
            issue.target_id.clone(),
            issue.issue.clone(),
            issue.latest_record_id.clone(),
        );
        if seen.insert(key) {
            unique.push(issue);
        }
    }
    unique
}

fn parsed_repository_checks(
    records: &[BackupRepositoryCheckRecord],
) -> (Vec<ParsedRepositoryCheck<'_>>, Vec<String>) {
    let mut parsed = Vec::new();
    let mut invalid = Vec::new();
    for record in records {
        match parse_repository_check_completed_at(record) {
            Ok(completed_at) => parsed.push(ParsedRepositoryCheck {
                record,
                completed_at,
            }),
            Err(_) => invalid.push(record.id.clone()),
        }
    }
    (parsed, invalid)
}

fn parsed_restore_drills(
    records: &[BackupRestoreDrillRecord],
) -> (Vec<ParsedRestoreDrill<'_>>, Vec<String>) {
    let mut parsed = Vec::new();
    let mut invalid = Vec::new();
    for record in records {
        match parse_restore_drill_completed_at(record) {
            Ok(completed_at) => parsed.push(ParsedRestoreDrill {
                record,
                completed_at,
            }),
            Err(_) => invalid.push(record.id.clone()),
        }
    }
    (parsed, invalid)
}

fn latest_repository_check<'a>(
    records: &'a [ParsedRepositoryCheck<'a>],
    repository_id: &str,
) -> Option<&'a ParsedRepositoryCheck<'a>> {
    records
        .iter()
        .filter(|record| record.record.repository_id == repository_id)
        .max_by(|left, right| left.completed_at.cmp(&right.completed_at))
}

fn latest_restore_drill<'a>(
    records: &'a [ParsedRestoreDrill<'a>],
    service_id: &str,
    target_id: &str,
) -> Option<&'a ParsedRestoreDrill<'a>> {
    records
        .iter()
        .filter(|record| {
            record.record.service_id == service_id && record.record.target_id == target_id
        })
        .max_by(|left, right| left.completed_at.cmp(&right.completed_at))
}

fn repository_check_record_ready(
    record: &ParsedRepositoryCheck<'_>,
    now_utc: OffsetDateTime,
    max_age_hours: u32,
) -> bool {
    record.record.status == "success"
        && record.completed_at <= now_utc
        && now_utc - record.completed_at <= Duration::hours(i64::from(max_age_hours))
        && record.record.limitations.is_empty()
}

fn restore_drill_record_ready(
    record: &ParsedRestoreDrill<'_>,
    now_utc: OffsetDateTime,
    max_age_hours: u32,
) -> bool {
    record.record.status == "success"
        && record.completed_at <= now_utc
        && now_utc - record.completed_at <= Duration::hours(i64::from(max_age_hours))
        && record.record.limitations.is_empty()
}

fn push_repository_check_limitation(
    record: &ParsedRepositoryCheck<'_>,
    now_utc: OffsetDateTime,
    max_age_hours: u32,
    limitations: &mut Vec<String>,
    target_id: &str,
) {
    if record.record.status != "success" {
        limitations.push(format!(
            "latest repository check {} for target {} finished with status {}",
            record.record.id, target_id, record.record.status
        ));
    }
    if record.completed_at > now_utc {
        limitations.push(format!(
            "repository check record {} has a completed_at timestamp in the future",
            record.record.id
        ));
    } else if now_utc - record.completed_at > Duration::hours(i64::from(max_age_hours)) {
        limitations.push(format!(
            "latest repository check {} for target {} is older than {} hour(s)",
            record.record.id, target_id, max_age_hours
        ));
    }
    limitations.extend(record.record.limitations.iter().cloned());
}

fn push_restore_drill_limitation(
    record: &ParsedRestoreDrill<'_>,
    now_utc: OffsetDateTime,
    max_age_hours: u32,
    limitations: &mut Vec<String>,
    target_id: &str,
) {
    if record.record.status != "success" {
        limitations.push(format!(
            "latest restore drill {} for target {} finished with status {}",
            record.record.id, target_id, record.record.status
        ));
    }
    if record.completed_at > now_utc {
        limitations.push(format!(
            "restore drill record {} has a completed_at timestamp in the future",
            record.record.id
        ));
    } else if now_utc - record.completed_at > Duration::hours(i64::from(max_age_hours)) {
        limitations.push(format!(
            "latest restore drill {} for target {} is older than {} hour(s)",
            record.record.id, target_id, max_age_hours
        ));
    }
    limitations.extend(record.record.limitations.iter().cloned());
}

fn invalid_repository_check_ids_for_repository(
    records: &[BackupRepositoryCheckRecord],
    repository_id: &str,
) -> Vec<String> {
    records
        .iter()
        .filter(|record| {
            record.repository_id == repository_id
                && parse_repository_check_completed_at(record).is_err()
        })
        .map(|record| record.id.clone())
        .collect()
}

fn invalid_restore_drill_ids_for_target(
    records: &[BackupRestoreDrillRecord],
    service_id: &str,
    target_id: &str,
) -> Vec<String> {
    records
        .iter()
        .filter(|record| {
            record.service_id == service_id
                && record.target_id == target_id
                && parse_restore_drill_completed_at(record).is_err()
        })
        .map(|record| record.id.clone())
        .collect()
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

fn parse_completed_at(record: &BackupHistoryRecord) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(&record.completed_at, &Rfc3339)
        .with_context(|| format!("invalid backup completed_at for {}", record.id))
}

fn parse_repository_check_completed_at(
    record: &BackupRepositoryCheckRecord,
) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(&record.completed_at, &Rfc3339)
        .with_context(|| format!("invalid repository check completed_at for {}", record.id))
}

fn parse_restore_drill_completed_at(record: &BackupRestoreDrillRecord) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(&record.completed_at, &Rfc3339)
        .with_context(|| format!("invalid restore drill completed_at for {}", record.id))
}

fn error(code: &str, message: String, target: Option<String>) -> BackupFinding {
    BackupFinding {
        severity: BackupSeverity::Error,
        code: code.to_string(),
        message,
        target,
    }
}

fn warn(code: &str, message: String, target: Option<String>) -> BackupFinding {
    BackupFinding {
        severity: BackupSeverity::Warn,
        code: code.to_string(),
        message,
        target,
    }
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::Path};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use anyhow::{Context, Result};
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    use crate::{
        backup::{
            BackupPlanOptions, BackupRunOptions, backup_doctor, backup_history_at,
            backup_readiness, copy_dump_for_import_check, database_dump_argv,
            database_dump_import_argv, dump_is_compressed, dump_is_zstd_compressed,
            execute_database_dump_to_path, is_safe_restore_symlink, mariadb_restore_import_script,
            mysql_restore_import_script, parse_repository_snapshot_id, plan_backup, run_backup,
            safe_repository_failure_reason,
        },
        registry::{BackupDatabaseDump, BackupHistoryRecord, Registry},
    };

    #[test]
    fn backup_doctor_loads_example_registry() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let report = backup_doctor(&registry);

        assert_eq!(report.errors, 0);
        assert_eq!(report.repositories, 1);
        assert!(report.targets >= 3);
        assert_eq!(report.history, 3);
        Ok(())
    }

    #[test]
    fn s3_smoke_diagnostic_redacts_sensitive_env_values() {
        let envs = vec![
            (
                "RCLONE_CONFIG_TEST_ACCESS_KEY_ID".to_string(),
                OsString::from("visible-access-key"),
            ),
            (
                "RCLONE_CONFIG_TEST_SECRET_ACCESS_KEY".to_string(),
                OsString::from("visible-secret-key"),
            ),
            (
                "RCLONE_CONFIG_TEST_ENDPOINT".to_string(),
                OsString::from("https://example.invalid"),
            ),
        ];

        let diagnostic = super::redact_s3_smoke_diagnostic(
            "setting visible-access-key and visible-secret-key failed against https://example.invalid",
            &envs,
        );

        assert!(!diagnostic.contains("visible-access-key"));
        assert!(!diagnostic.contains("visible-secret-key"));
        assert!(diagnostic.contains("[REDACTED]"));
        assert!(diagnostic.contains("https://example.invalid"));
    }

    #[test]
    fn restic_plan_is_dry_run_only_and_reports_missing_env() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;

        let report = plan_backup(&BackupPlanOptions {
            registry: &registry,
            service_id: "pcafev2",
            dry_run: true,
        })?;

        assert!(report.dry_run);
        assert_eq!(report.status, "blocked");
        assert!(
            report
                .required_env
                .iter()
                .any(|name| name == "RESTIC_PASSWORD")
        );
        assert!(
            report.targets[0]
                .operations
                .iter()
                .any(|operation| operation.kind == "restic_backup")
        );
        Ok(())
    }

    #[test]
    fn backup_readiness_checks_production_before_deploy_services() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;

        let report = backup_readiness(&registry);

        assert!(report.dry_run);
        assert_eq!(report.status, "blocked");
        assert_eq!(report.services_checked, 3);
        assert_eq!(report.blocked, 3);
        assert!(
            report
                .services
                .iter()
                .any(|service| service.service_id == "pcafev2")
        );
        assert!(
            report
                .missing_env
                .iter()
                .any(|name| name == "RESTIC_PASSWORD")
        );
        assert!(report.services.iter().any(|service| {
            service.service_id == "pcafev2"
                && service
                    .required_env
                    .iter()
                    .any(|name| name == "RESTIC_PASSWORD")
        }));
        Ok(())
    }

    #[test]
    fn backup_history_checks_registered_success_records() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let now = OffsetDateTime::parse("2026-07-04T03:00:00Z", &Rfc3339)?;

        let report = backup_history_at(&registry, now);

        assert!(report.read_only);
        assert_eq!(report.status, "blocked");
        assert_eq!(report.services_checked, 3);
        assert_eq!(report.records, 3);
        assert_eq!(report.freshness_policy_targets, 0);
        assert_eq!(report.stale_targets, 0);
        assert_eq!(report.future_records, 0);
        assert_eq!(report.invalid_timestamps, 0);
        assert_eq!(report.services_with_success, 2);
        assert_eq!(report.services_missing_success, 1);
        assert_eq!(report.services_ready, 2);
        assert_eq!(report.services_blocked, 1);
        assert!(report.services.iter().any(|service| {
            service.service_id == "rankfan-new"
                && service.status == "blocked"
                && service
                    .missing_success_targets
                    .iter()
                    .any(|target| target == "rankfan-new-restic")
        }));
        Ok(())
    }

    #[test]
    fn backup_history_blocks_stale_success_records() -> Result<()> {
        let mut registry = Registry::load("examples/server-registry")?;
        let target = registry
            .backups
            .targets
            .iter_mut()
            .find(|target| target.id == "caddy-restic")
            .context("caddy target should exist")?;
        target.max_age_hours = Some(24);
        let record = registry
            .backups
            .history
            .iter_mut()
            .find(|record| record.id == "backup-caddy-20260704")
            .context("caddy history should exist")?;
        record.completed_at = "2026-07-01T01:30:00Z".to_string();
        let now = OffsetDateTime::parse("2026-07-04T01:30:00Z", &Rfc3339)?;

        let report = backup_history_at(&registry, now);

        assert_eq!(report.status, "blocked");
        assert_eq!(report.freshness_policy_targets, 1);
        assert_eq!(report.stale_targets, 1);
        assert!(report.services.iter().any(|service| {
            service.service_id == "caddy"
                && service.status == "blocked"
                && service
                    .stale_targets
                    .iter()
                    .any(|target| target == "caddy-restic")
        }));
        Ok(())
    }

    #[test]
    fn backup_doctor_reports_invalid_history_timestamps() -> Result<()> {
        let mut registry = Registry::load("examples/server-registry")?;
        let record = registry
            .backups
            .history
            .iter_mut()
            .find(|record| record.id == "backup-caddy-20260704")
            .context("caddy history should exist")?;
        record.completed_at = "not-a-timestamp".to_string();

        let report = backup_doctor(&registry);

        assert!(!report.ok);
        assert!(report.findings.iter().any(|finding| {
            finding.code == "backup_history_invalid_completed_at"
                && finding.target.as_deref() == Some("backup-caddy-20260704")
        }));
        Ok(())
    }

    #[test]
    fn backup_plan_refuses_execution() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let error = match plan_backup(&BackupPlanOptions {
            registry: &registry,
            service_id: "pcafev2",
            dry_run: false,
        }) {
            Ok(_) => anyhow::bail!("backup execution should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("backup plan is dry-run only"));
        Ok(())
    }

    #[test]
    fn restic_backup_plan_recovers_only_stale_locks_before_writes() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let report = plan_backup(&BackupPlanOptions {
            registry: &registry,
            service_id: "caddy",
            dry_run: true,
        })?;
        let target = report
            .targets
            .first()
            .context("caddy backup target should be planned")?;
        let unlock = target
            .operations
            .iter()
            .find(|operation| operation.kind == "restic_unlock")
            .context("Restic backup should plan stale-lock recovery")?;
        let backup = target
            .operations
            .iter()
            .find(|operation| operation.kind == "restic_backup")
            .context("Restic backup operation should be planned")?;

        assert!(unlock.order < backup.order);
        assert_eq!(unlock.argv.last().map(String::as_str), Some("unlock"));
        assert!(
            !unlock
                .argv
                .iter()
                .any(|argument| argument == "--remove-all")
        );
        Ok(())
    }

    #[test]
    fn rustic_backup_plan_does_not_invent_restic_unlock_semantics() -> Result<()> {
        let mut registry = Registry::load("examples/server-registry")?;
        let repository_id = registry
            .backups
            .targets
            .iter()
            .find(|target| target.service_id == "caddy")
            .map(|target| target.repository_id.clone())
            .context("caddy backup target should exist")?;
        registry
            .backups
            .repositories
            .iter_mut()
            .find(|repository| repository.id == repository_id)
            .context("caddy backup repository should exist")?
            .provider = "rustic".to_string();

        let report = plan_backup(&BackupPlanOptions {
            registry: &registry,
            service_id: "caddy",
            dry_run: true,
        })?;
        let target = report
            .targets
            .first()
            .context("caddy backup target should be planned")?;

        assert!(
            target
                .operations
                .iter()
                .all(|operation| operation.kind != "restic_unlock")
        );
        assert!(
            target
                .operations
                .iter()
                .any(|operation| operation.kind == "rustic_backup")
        );
        Ok(())
    }

    #[test]
    fn backup_plan_blocks_unsupported_database_dump_kind() -> Result<()> {
        let mut registry = Registry::load("examples/server-registry")?;
        let target = registry
            .backups
            .targets
            .iter_mut()
            .find(|target| target.id == "caddy-restic")
            .context("caddy target should exist")?;
        target.database_dumps.push(BackupDatabaseDump {
            id: "sqlite-main".to_string(),
            kind: "sqlite".to_string(),
            adapter: None,
            script: None,
            working_dir: None,
            container: None,
            database: None,
            verify_kind: None,
            restore_image: None,
            restore_postgres_settings: Vec::new(),
            output_path: "/var/lib/opsctl/backup-dumps/caddy/sqlite.db".into(),
            notes: None,
        });

        let report = plan_backup(&BackupPlanOptions {
            registry: &registry,
            service_id: "caddy",
            dry_run: true,
        })?;

        assert_eq!(report.status, "blocked");
        assert!(report.targets.iter().any(|target| {
            target.limitations.iter().any(|limitation| {
                limitation.contains("database dump kind sqlite is not executable")
            })
        }));
        Ok(())
    }

    #[test]
    fn backup_run_without_execute_is_non_mutating() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;

        let report = run_backup(&BackupRunOptions {
            registry: &registry,
            registry_dir: "examples/server-registry".as_ref(),
            service_id: "caddy",
            target_id: None,
            execute: false,
        })?;

        assert!(!report.execute);
        assert_eq!(report.status, "blocked");
        assert!(report.history_records.is_empty());
        assert!(report.targets.iter().any(|target| {
            target
                .operations
                .iter()
                .any(|operation| operation.status == "planned")
        }));
        Ok(())
    }

    #[test]
    fn mysql_container_configured_by_env_uses_container_env_password() {
        let dump = BackupDatabaseDump {
            id: "mysql-main".to_string(),
            kind: "mysql".to_string(),
            adapter: None,
            script: None,
            working_dir: None,
            container: Some("mysql-container".to_string()),
            database: Some("configured-by-env".to_string()),
            verify_kind: None,
            restore_image: None,
            restore_postgres_settings: Vec::new(),
            output_path: "/var/lib/opsctl/backup-dumps/mysql.sql.zst".into(),
            notes: None,
        };

        let argv = database_dump_argv(&dump);

        assert_eq!(argv[0], "docker");
        assert_eq!(argv[1], "exec");
        assert_eq!(argv[2], "mysql-container");
        assert_eq!(argv[3], "sh");
        assert_eq!(argv[4], "-lc");
        assert!(argv[5].contains("MYSQL_ROOT_PASSWORD"));
        assert!(argv[5].contains("MYSQL_PWD"));
        assert!(argv[5].contains("MYSQL_DATABASE"));
        assert!(argv[5].contains("MYSQL_DATABASE is required"));
        assert!(!argv[5].contains("--all-databases"));
        assert!(!argv[5].contains("super-secret"));
    }

    #[test]
    fn mariadb_container_configured_by_env_uses_mariadb_env_password() {
        let dump = BackupDatabaseDump {
            id: "mariadb-main".to_string(),
            kind: "mariadb".to_string(),
            adapter: None,
            script: None,
            working_dir: None,
            container: Some("mariadb-container".to_string()),
            database: Some("configured-by-env".to_string()),
            verify_kind: None,
            restore_image: None,
            restore_postgres_settings: Vec::new(),
            output_path: "/var/lib/opsctl/backup-dumps/mariadb.sql.zst".into(),
            notes: None,
        };

        let argv = database_dump_argv(&dump);

        assert_eq!(argv[0], "docker");
        assert_eq!(argv[1], "exec");
        assert_eq!(argv[2], "mariadb-container");
        assert_eq!(argv[3], "sh");
        assert_eq!(argv[4], "-lc");
        assert!(argv[5].contains("mariadb-dump"));
        assert!(argv[5].contains("MARIADB_ROOT_PASSWORD"));
        assert!(argv[5].contains("MARIADB_PASSWORD"));
        assert!(argv[5].contains("MARIADB_DATABASE"));
        assert!(argv[5].contains("MYSQL_PWD"));
        assert!(!argv[5].contains("--all-databases"));
        assert!(!argv[5].contains("super-secret"));
    }

    #[test]
    fn repository_failure_reason_classifies_common_restic_errors_without_raw_output() {
        assert_eq!(
            safe_repository_failure_reason(
                "",
                "Stat(<config/>) failed: Stat: Access Denied.\nIs there a repository at s3:https://secret.example/bucket?"
            ),
            "repository access was denied; refresh repository credentials or bucket permissions"
        );
        assert_eq!(
            safe_repository_failure_reason("", "Fatal: repository is already locked by PID 123"),
            "repository is locked; verify no backup is running and clear stale locks if needed"
        );
        assert_eq!(
            safe_repository_failure_reason("", "wrong password or no key found"),
            "repository password or encryption key was rejected"
        );
        assert_eq!(
            safe_repository_failure_reason("", ""),
            "no output was captured"
        );
    }

    #[test]
    fn postgres_container_configured_by_env_uses_container_env_password() {
        let dump = BackupDatabaseDump {
            id: "postgres-main".to_string(),
            kind: "postgres".to_string(),
            adapter: None,
            script: None,
            working_dir: None,
            container: Some("postgres-container".to_string()),
            database: Some("configured-by-env".to_string()),
            verify_kind: None,
            restore_image: None,
            restore_postgres_settings: Vec::new(),
            output_path: "/var/lib/opsctl/backup-dumps/postgres.sql.zst".into(),
            notes: None,
        };

        let argv = database_dump_argv(&dump);

        assert_eq!(argv[0], "docker");
        assert_eq!(argv[1], "exec");
        assert_eq!(argv[2], "postgres-container");
        assert_eq!(argv[3], "sh");
        assert_eq!(argv[4], "-lc");
        assert!(argv[5].contains("POSTGRES_USER"));
        assert!(argv[5].contains("POSTGRES_PASSWORD"));
        assert!(argv[5].contains("PGPASSWORD"));
        assert!(argv[5].contains("POSTGRES_DB"));
        assert!(argv[5].contains("POSTGRES_DB is required"));
        assert!(!argv[5].contains("pg_dumpall"));
        assert!(!argv[5].contains("super-secret"));
    }

    #[test]
    fn restore_import_scripts_match_database_family() {
        let mysql_script = mysql_restore_import_script();
        assert!(mysql_script.contains("mysqld --initialize-insecure"));
        assert!(mysql_script.contains("mysqladmin"));
        assert!(mysql_script.contains("mysql --socket"));
        assert!(!mysql_script.contains("mariadb-install-db"));

        let mariadb_script = mariadb_restore_import_script();
        assert!(mariadb_script.contains("mariadb-install-db"));
        assert!(mariadb_script.contains("mariadb-admin"));
        assert!(mariadb_script.contains("mariadb --socket"));
        assert!(!mariadb_script.contains("mysqld --initialize-insecure"));
    }

    #[test]
    fn postgres_restore_import_uses_dump_specific_image_and_settings() -> Result<()> {
        let dump = BackupDatabaseDump {
            id: "postgres-main".to_string(),
            kind: "postgres".to_string(),
            adapter: None,
            script: None,
            working_dir: None,
            container: None,
            database: None,
            verify_kind: None,
            restore_image: Some("ghcr.io/example/postgres:15".to_string()),
            restore_postgres_settings: vec![
                "shared_preload_libraries=pg_cron,pg_net".to_string(),
                "cron.database_name=restorecheck".to_string(),
            ],
            output_path: "/var/lib/opsctl/backup-dumps/postgres.sql.zst".into(),
            notes: None,
        };

        let argv = database_dump_import_argv(Path::new("/tmp/restore.sql"), &dump);

        assert!(argv.contains(&"ghcr.io/example/postgres:15".to_string()));
        let script = argv
            .last()
            .context("postgres import script should be present")?;
        assert!(script.contains(
            "shared_preload_libraries=pg_cron,pg_net -c cron.database_name=restorecheck"
        ));
        assert!(script.contains("pg_ctl -D /tmp/pgdata -o '"));
        Ok(())
    }

    #[test]
    fn restic_snapshot_parser_prefers_saved_snapshot_over_parent() {
        let output = "\
repository 123 opened (version 2)
using parent snapshot d27ee3ad
Files: 1 new, 2 changed, 3 unmodified
snapshot abc12345 saved
";

        assert_eq!(
            parse_repository_snapshot_id(output),
            Some("abc12345".to_string())
        );
    }

    #[test]
    fn zstd_detection_uses_magic_bytes_not_extension() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let plain_zst_name = temp.path().join("plain.sql.zst");
        std::fs::write(&plain_zst_name, b"CREATE TABLE example(id int);\n")?;

        assert!(!dump_is_zstd_compressed(&plain_zst_name));
        assert!(!dump_is_compressed(&plain_zst_name));
        Ok(())
    }

    #[test]
    fn zstd_detection_accepts_real_zstd_payload() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let compressed_path = temp.path().join("dump.sql.zst");
        let output = std::fs::File::create(&compressed_path)?;
        let mut encoder = zstd::Encoder::new(output, 3)?;
        std::io::Write::write_all(&mut encoder, b"CREATE TABLE example(id int);\n")?;
        encoder.finish()?;

        assert!(dump_is_zstd_compressed(&compressed_path));
        assert!(dump_is_compressed(&compressed_path));
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn import_check_copy_is_readable_by_non_root_container_user() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::TempDir::new()?;
        let source = temp.path().join("source.sql");
        let destination = temp.path().join("import.sql");
        std::fs::write(&source, b"CREATE TABLE example(id int);\n")?;
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600))?;

        copy_dump_for_import_check(&source, &destination)?;

        let mode = std::fs::metadata(&destination)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        assert_eq!(
            std::fs::read(&destination)?,
            b"CREATE TABLE example(id int);\n"
        );
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn restore_verification_accepts_relative_file_symlink_inside_restore_dir() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let restore_dir = temp.path().join("restore");
        std::fs::create_dir(&restore_dir)?;
        let target = restore_dir.join(".env.local");
        let link = restore_dir.join(".env");
        std::fs::write(&target, b"KEY=value\n")?;
        std::os::unix::fs::symlink(".env.local", &link)?;

        assert!(is_safe_restore_symlink(&restore_dir, &link));
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn restore_verification_rejects_parent_traversal_symlink() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let restore_dir = temp.path().join("restore");
        std::fs::create_dir(&restore_dir)?;
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"secret\n")?;
        let link = restore_dir.join("escape");
        std::os::unix::fs::symlink("../outside", &link)?;

        assert!(!is_safe_restore_symlink(&restore_dir, &link));
        Ok(())
    }

    #[test]
    fn external_database_dump_is_copied_to_requested_output() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let source = temp.path().join("source.sql");
        let destination = temp.path().join("captured.sql");
        std::fs::write(&source, b"select 1;\n")?;
        let dump = BackupDatabaseDump {
            id: "external-sql".to_string(),
            kind: "external".to_string(),
            adapter: None,
            script: None,
            working_dir: None,
            container: None,
            database: None,
            verify_kind: None,
            restore_image: None,
            restore_postgres_settings: Vec::new(),
            output_path: source,
            notes: None,
        };

        let execution = execute_database_dump_to_path(&dump, &destination)?;

        assert!(execution.argv.is_empty());
        assert_eq!(std::fs::read(&destination)?, b"select 1;\n");
        Ok(())
    }

    #[test]
    fn external_database_dump_accepts_existing_same_output_path() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let output = temp.path().join("source.sql");
        std::fs::write(&output, b"select 2;\n")?;
        let dump = BackupDatabaseDump {
            id: "external-sql".to_string(),
            kind: "external".to_string(),
            adapter: None,
            script: None,
            working_dir: None,
            container: None,
            database: None,
            verify_kind: None,
            restore_image: None,
            restore_postgres_settings: Vec::new(),
            output_path: output.clone(),
            notes: None,
        };

        let execution = execute_database_dump_to_path(&dump, &output)?;

        assert!(execution.argv.is_empty());
        assert_eq!(std::fs::read(&output)?, b"select 2;\n");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn external_database_dump_refuses_symlink_source() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let real = temp.path().join("source.sql");
        let symlink = temp.path().join("source-link.sql");
        let destination = temp.path().join("captured.sql");
        std::fs::write(&real, b"select 3;\n")?;
        std::os::unix::fs::symlink(&real, &symlink)?;
        let dump = BackupDatabaseDump {
            id: "external-sql".to_string(),
            kind: "external".to_string(),
            adapter: None,
            script: None,
            working_dir: None,
            container: None,
            database: None,
            verify_kind: None,
            restore_image: None,
            restore_postgres_settings: Vec::new(),
            output_path: symlink,
            notes: None,
        };

        let error = match execute_database_dump_to_path(&dump, &destination) {
            Ok(_) => anyhow::bail!("external dump symlink source should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("symlink"));
        assert!(!destination.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn backup_restore_refuses_symlink_ancestor() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let real_parent = temp.path().join("real-parent");
        let link_parent = temp.path().join("link-parent");
        std::fs::create_dir_all(real_parent.join("restore"))?;
        std::os::unix::fs::symlink(&real_parent, &link_parent)?;
        let registry = Registry::load("examples/server-registry")?;
        let service = registry
            .services
            .services
            .iter()
            .find(|service| service.id == "pcafev2")
            .context("pcafev2 service should exist")?;
        let target = registry
            .backups
            .targets
            .iter()
            .find(|target| target.id == "pcafev2-restic")
            .context("pcafev2 backup target should exist")?;

        let limitations =
            super::validate_restore_dir(&registry, service, target, &link_parent.join("restore"));

        assert!(
            limitations
                .iter()
                .any(|limitation| limitation.contains("ancestor must not be a symlink")),
            "{limitations:?}"
        );
        Ok(())
    }

    #[test]
    fn scheduled_restore_drill_uses_child_under_allowed_root() -> Result<()> {
        let base = Path::new("/var/lib/opsctl/restore-drills/pcafev2");

        super::validate_scheduled_restore_drill_dir(base)?;
        assert!(super::validate_scheduled_restore_drill_dir(Path::new("/tmp/pcafev2")).is_err());

        let run_dir = super::scheduled_restore_drill_run_dir(base);
        assert!(run_dir.starts_with(base));
        assert!(
            run_dir
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("run-"))
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn append_backup_history_preserves_registry_file_mode() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let path = temp.path().join("backups.yml");
        std::fs::write(
            &path,
            "version: 1\nrepositories: []\ntargets: []\nhistory: []\nrepository_checks: []\nrestore_drills: []\n",
        )?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;
        let record = BackupHistoryRecord {
            id: "backup-mode-test".to_string(),
            service_id: "service".to_string(),
            target_id: "target".to_string(),
            repository_id: Some("repo".to_string()),
            tool: "restic".to_string(),
            completed_at: "2026-07-05T00:00:00Z".to_string(),
            status: "success".to_string(),
            repository_snapshot_id: Some("abcdef123456".to_string()),
            duration_seconds: Some(1),
            bytes_processed: None,
            limitations: Vec::new(),
            notes: None,
        };

        super::append_backup_history(temp.path(), &[record])?;

        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert!(std::fs::read_to_string(&path)?.contains("backup-mode-test"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn append_backup_history_refuses_backups_registry_symlink() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let real = temp.path().join("real-backups.yml");
        let symlink = temp.path().join("backups.yml");
        std::fs::write(&real, "repositories: []\ntargets: []\nhistory: []\n")?;
        std::os::unix::fs::symlink(&real, &symlink)?;
        let record = BackupHistoryRecord {
            id: "backup-test".to_string(),
            service_id: "service".to_string(),
            target_id: "target".to_string(),
            repository_id: Some("repo".to_string()),
            tool: "restic".to_string(),
            completed_at: "2026-07-05T00:00:00Z".to_string(),
            status: "success".to_string(),
            repository_snapshot_id: Some("abcdef123456".to_string()),
            duration_seconds: Some(1),
            bytes_processed: None,
            limitations: Vec::new(),
            notes: None,
        };

        let error = match super::append_backup_history(temp.path(), &[record]) {
            Ok(()) => anyhow::bail!("symlinked backup registry should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("symlink"));
        assert!(!std::fs::read_to_string(&real)?.contains("backup-test"));
        Ok(())
    }
}
