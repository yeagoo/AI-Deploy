mod analyze;
mod approvals;
mod audit;
mod backup;
mod backup_schedule;
mod cleanup_evidence;
mod cli;
mod command_runner;
mod deploy;
mod doctor;
mod drift;
mod env_source;
mod evidence_archive;
mod evidence_backfill;
mod evidence_crypto;
mod evidence_retention;
mod gates;
mod importer;
mod install_check;
mod lockfile;
mod mcp;
mod paths;
mod plan;
mod policy;
mod recovery_governance;
mod recovery_lab;
mod recovery_onboarding;
mod redact;
mod registry;
mod registry_schema;
mod release_matrix;
mod scan;
mod snapshot;
mod sudoers;
mod tui;
mod volume_protect;
mod volume_protect_batch;
mod volume_protect_campaign;
mod volume_protect_lifecycle;
mod volume_protect_ops;
mod volume_recovery;

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use serde_json::{Value, json};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{
    analyze::analyze_project,
    approvals::{
        ApprovalRequestOptions, approve, approved_scope_for_plan, list_approvals, reject,
        request_approval,
    },
    audit::{AuditRecord, AuditStore, query_audit_log},
    backup::{
        BackupDrillOptions, BackupDrillSuiteOptions, BackupPlanOptions, BackupRefreshStaleOptions,
        BackupRepositoryActionOptions, BackupRepositoryInitOptions, BackupRestoreOptions,
        BackupRunOptions, BackupS3SmokeOptions, backup_doctor, backup_history, backup_readiness,
        backup_refresh_stale, backup_repository_check, backup_repository_init,
        backup_repository_prune, backup_restore_drill, backup_restore_drill_suite, backup_s3_smoke,
        plan_backup, plan_backup_restore, restore_backup, run_backup,
    },
    backup_schedule::{
        BackupTimerAlertConfigureOptions, BackupTimerAlertEnablePlanOptions,
        BackupTimerAlertEnvTemplateOptions, BackupTimerAlertOptions, BackupTimerAlertStatusOptions,
        BackupTimerAlertTestOptions, BackupTimerMonitorOptions, BackupTimerOptions,
        DrillCleanupOptions, ProductionOnboardingOptions, backup_timer_alert,
        backup_timer_alert_configure, backup_timer_alert_enable_plan,
        backup_timer_alert_env_template, backup_timer_alert_status, backup_timer_alert_test,
        backup_timer_install, backup_timer_monitor, backup_timer_plan, backup_timer_status,
        cleanup_restore_drills, production_onboarding_check, timer_health,
    },
    cleanup_evidence::{
        CleanupEvidenceReconcileOptions, CleanupEvidenceSealOptions, cleanup_manifest_status,
        reconcile_cleanup_evidence, seal_cleanup_evidence,
    },
    cli::{
        BackupCommand, BackupTimerCommand, BackupVolumeProtectCommand, Cli, Command, HelperCommand,
        RegistryCommand, RegistryDriftCleanupRequestCommand, RegistryDriftCommand,
        RegistryDriftReviewCommand, RegistryPublicDataExceptionCommand,
    },
    deploy::{
        DeployExecutionOptions, DeployOptions, DeployResumeExecutionOptions, deploy_decision,
        deploy_exit_code, ensure_dry_run, execute_deploy, execute_deploy_resume,
        expected_deploy_approval_token, expected_deploy_resume_approval_scope,
        expected_deploy_resume_approval_token, inspect_caddy_routes, inspect_deploy_journal,
        list_deploy_journals, plan_deploy, report_text, resume_deploy_journal, serialize_report,
    },
    doctor::DoctorReport,
    drift::{
        DRIFT_CLEANUP_EXECUTION_PLAN_ID, DRIFT_CLEANUP_EXECUTION_SCOPE, DriftAdoptOptions,
        DriftAdoptReviewOptions, DriftCleanupEvidenceOptions, DriftCleanupExecuteOptions,
        DriftCleanupFinalizeOptions, DriftCleanupMarkOptions, DriftCleanupSyncOptions, DriftFilter,
        DriftIgnoreOptions, DriftReviewApplyOptions, DriftServiceAddOptions, drift_adopt,
        drift_adopt_review, drift_cleanup_approval_pack, drift_cleanup_approval_summary,
        drift_cleanup_dashboard, drift_cleanup_evidence_plan, drift_cleanup_execute_handoff,
        drift_cleanup_execution_gate, drift_cleanup_execution_plan, drift_cleanup_finalize,
        drift_cleanup_plan, drift_cleanup_request_evidence, drift_cleanup_request_export,
        drift_cleanup_request_mark, drift_cleanup_request_progress, drift_cleanup_request_sync,
        drift_cleanup_request_triage, drift_cleanup_request_verify, drift_cleanup_runbook,
        drift_cleanup_volume_ownership, drift_cleanup_worklist, drift_explain, drift_governance,
        drift_groups, drift_ignore, drift_list, drift_ownership, drift_review_apply,
        drift_review_export, drift_service_add, drift_suggest,
    },
    gates::{deploy_gates, deploy_gates_from_reports},
    importer::{
        RegistryImportBuildOptions, RegistryImportWriteOptions, RegistryPromoteImportOptions,
        check_registry_import, promote_registry_import, write_registry_import,
    },
    install_check::check_install,
    lockfile::GlobalLock,
    paths::{RuntimePaths, display_path},
    plan::{DraftPlanOptions, draft_deploy_plan, load_deploy_plan, plan_as_yaml},
    policy::{decision_for_status, evaluate_preflight, preflight_exit_code},
    registry::{BackupDatabaseDump, BackupTarget, PublicDataPortException, Registry},
    registry_schema::{list_schemas, schema_as_json, schema_by_name, validate_registry_schemas},
    scan::scan_server,
    snapshot::{
        SnapshotBaselineOptions, SnapshotOptions, create_snapshot, inspect_snapshot_archive_report,
        inspect_snapshot_report, inspect_snapshot_volume_archives_report, list_snapshots,
        register_snapshot_baseline, rollback_dry_run_with_registry, rollback_restore,
        rollback_stage, snapshot_coverage, verify_snapshot_report,
    },
    sudoers::check_sudoers_file,
    tui::{dump_tui, run_tui},
    volume_protect::{
        EvidenceResolveOptions, VolumeProtectOptions, resolve_cleanup_evidence, volume_protect,
        volume_protect_history,
    },
    volume_protect_batch::{VolumeProtectBatchOptions, volume_protect_batch},
    volume_protect_campaign::{
        VolumeProtectCampaignOptions, abort_campaign, campaign_status, resume_campaign,
        volume_protect_campaign,
    },
    volume_protect_lifecycle::{
        cleanup_volume_protect_staging, resume_volume_protect, volume_protect_run_status,
    },
    volume_protect_ops::{maintain_volume_protect_journals, volume_protect_metrics},
};

const OUTPUT_SCHEMA_VERSION: &str = "opsctl.v1";

#[derive(Debug)]
struct CommandOutput {
    json: Value,
    text: String,
    exit_code: i32,
    audit_decision: &'static str,
    dry_run: bool,
}

#[derive(Debug, Serialize)]
struct StatusSummary {
    registry_dir: String,
    state_db: String,
    audit_log: String,
    services: usize,
    ports: usize,
    domains: usize,
    volumes: usize,
    snapshots: usize,
    doctor_errors: usize,
    doctor_warnings: usize,
    deploy_gates_status: String,
    deploy_gates_read_only: bool,
    deploy_gates_dry_run: bool,
    deploy_gates_services_checked: usize,
    deploy_gates_services_ready: usize,
    deploy_gates_services_blocked: usize,
    backup_readiness_status: String,
    backup_readiness_dry_run: bool,
    backup_services_checked: usize,
    backup_ready: usize,
    backup_blocked: usize,
    backup_missing_env: usize,
    backup_history_status: String,
    backup_history_read_only: bool,
    backup_history_records: usize,
    backup_history_services_missing_success: usize,
    backup_history_stale_targets: usize,
    backup_history_future_records: usize,
    backup_history_invalid_timestamps: usize,
    snapshot_coverage_status: String,
    snapshot_coverage_read_only: bool,
    snapshot_coverage_services_checked: usize,
    snapshot_coverage_services_blocked: usize,
    snapshot_coverage_missing_snapshot: usize,
    snapshot_coverage_missing_required_scope: usize,
    snapshot_coverage_with_limitations: usize,
}

struct BackupTargetAddInput<'a> {
    service_id: &'a str,
    repository_id: &'a str,
    target_id: Option<&'a str>,
    include_paths: &'a [PathBuf],
    exclude_paths: &'a [PathBuf],
    tags: &'a [String],
    postgres_containers: &'a [String],
    mysql_containers: &'a [String],
    mariadb_containers: &'a [String],
    max_age_hours: u32,
    schedule: &'a str,
    status: &'a str,
    notes: Option<&'a str>,
    execute: bool,
}

#[derive(Debug, Serialize)]
struct BackupTargetAddReport {
    ok: bool,
    execute: bool,
    status: String,
    service_id: String,
    target_id: String,
    target: Option<BackupTarget>,
    warnings: Vec<String>,
    limitations: Vec<String>,
    changed_files: Vec<String>,
}

struct PublicDataExceptionAddInput<'a> {
    port_id: &'a str,
    owner: Option<&'a str>,
    reason: &'a str,
    expires_at: &'a str,
    mitigation: Option<&'a str>,
    status: &'a str,
    execute: bool,
}

#[derive(Debug, Serialize)]
struct PublicDataExceptionAddReport {
    ok: bool,
    execute: bool,
    status: String,
    exception: Option<PublicDataPortException>,
    warnings: Vec<String>,
    limitations: Vec<String>,
    changed_files: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json_output = cli.json;
    let actor = resolve_actor(cli.actor.as_deref());
    let command_name = cli.command.name();

    if matches!(cli.command, Command::Mcp) {
        return run_mcp_command(&cli, &actor);
    }

    let result = run(&cli, &actor);

    match result {
        Ok((audit, output, audit_target)) => {
            let result = if output.exit_code == 0 {
                "success"
            } else {
                "completed"
            };
            if let Err(error) = audit.record(&AuditRecord {
                actor: &actor,
                command: command_name,
                target: Some(&audit_target),
                result,
                decision: output.audit_decision,
                reason: None,
                risk: command_risk_for(&cli.command),
                dry_run: output.dry_run,
            }) {
                print_audit_error(json_output, error);
                return ExitCode::from(1);
            }
            print_output(json_output, output)
        }
        Err(error) => {
            let exit_code = if is_nonfatal_status_missing_registry(&cli.command, &error) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            };
            print_error_with_ok(
                json_output,
                &error,
                matches!(cli.command, Command::Rollback { .. }),
            );
            exit_code
        }
    }
}

#[allow(clippy::print_stderr)]
fn run_mcp_command(cli: &Cli, actor: &str) -> ExitCode {
    match RuntimePaths::resolve(cli.registry.clone(), cli.state_dir.clone()).and_then(|paths| {
        mcp::run_stdio(&mcp::McpOptions {
            paths: &paths,
            actor,
        })
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn is_nonfatal_status_missing_registry(command: &Command, error: &anyhow::Error) -> bool {
    matches!(command, Command::Status)
        && error
            .to_string()
            .contains("registry directory does not exist")
}

fn run(cli: &Cli, actor: &str) -> Result<(AuditStore, CommandOutput, String)> {
    let paths = RuntimePaths::resolve(cli.registry.clone(), cli.state_dir.clone())?;
    let audit = AuditStore::open(&paths.state_dir, &paths.state_db, &paths.audit_log)?;
    let audit_target = command_audit_target(&cli.command, &paths);

    let output = match execute_command(&cli.command, &paths, actor, &audit_target) {
        Ok(output) => output,
        Err(error) => {
            let message = error.to_string();
            if let Err(audit_error) = audit.record(&AuditRecord {
                actor,
                command: cli.command.name(),
                target: Some(&audit_target),
                result: "error",
                decision: "deny",
                reason: Some(&message),
                risk: command_risk_for(&cli.command),
                dry_run: command_is_dry_run(&cli.command),
            }) {
                return Err(error)
                    .with_context(|| format!("also failed to write audit record: {audit_error}"));
            }
            return Err(error);
        }
    };

    Ok((audit, output, audit_target))
}

fn execute_command(
    command: &Command,
    paths: &RuntimePaths,
    actor: &str,
    audit_target: &str,
) -> Result<CommandOutput> {
    let _global_lock = acquire_global_lock_for_command(command, paths, actor, audit_target)?;
    match command {
        Command::Status => status_command(paths),
        Command::Services => services_command(paths),
        Command::Ports => ports_command(paths),
        Command::Registry { command } => registry_command(paths, command, actor),
        Command::Backup { command } => backup_command(paths, command, actor),
        Command::DeployGates => deploy_gates_command(paths),
        Command::Doctor => doctor_command(paths),
        Command::Scan => scan_command(paths),
        Command::CaddyRoutes { adapt, admin } => caddy_routes_command(*adapt, *admin),
        Command::Analyze { project } => analyze_command(project),
        Command::Plan {
            project,
            domain,
            port,
            environment,
            id,
        } => plan_command(
            project,
            domain.as_deref(),
            port,
            environment,
            id.as_deref(),
            actor,
        ),
        Command::Preflight { plan } => preflight_command(paths, plan, false),
        Command::ExplainRisk { plan } => preflight_command(paths, plan, true),
        Command::Snapshot { plan, dry_run } => snapshot_command(paths, plan, *dry_run),
        Command::Snapshots => snapshots_command(paths),
        Command::SnapshotInspect { snapshot_id } => snapshot_inspect_command(paths, snapshot_id),
        Command::SnapshotVerify { snapshot_id } => snapshot_verify_command(paths, snapshot_id),
        Command::SnapshotArchiveInspect { snapshot_id } => {
            snapshot_archive_inspect_command(paths, snapshot_id)
        }
        Command::SnapshotVolumeArchiveInspect { snapshot_id } => {
            snapshot_volume_archive_inspect_command(paths, snapshot_id)
        }
        Command::SnapshotCoverage {
            register_baseline,
            service,
            reason,
            execute,
        } => snapshot_coverage_command(
            paths,
            *register_baseline,
            service,
            reason.as_deref(),
            *execute,
        ),
        Command::Rollback {
            snapshot_id,
            dry_run,
            stage_dir,
            restore,
            restore_config,
            restore_data,
            approval_token,
        } => rollback_command(
            paths,
            RollbackCommandOptions {
                snapshot_id,
                dry_run: *dry_run,
                stage_dir: stage_dir.as_deref(),
                restore: *restore,
                restore_config: *restore_config,
                restore_data: *restore_data,
                approval_token: approval_token.as_deref(),
            },
        ),
        Command::Deploy {
            plan,
            dry_run,
            execute,
            snapshot,
            approval_token,
        } => deploy_command(
            paths,
            plan,
            *dry_run,
            *execute,
            snapshot.as_deref(),
            approval_token.as_deref(),
        ),
        Command::RequestDeployExecution {
            plan,
            snapshot,
            reason,
            expires_at,
        } => request_deploy_execution_command(
            paths,
            plan,
            snapshot.as_deref(),
            reason,
            expires_at.as_deref(),
            actor,
        ),
        Command::RequestDeployResume {
            plan,
            journal,
            reason,
            expires_at,
        } => request_deploy_resume_command(
            paths,
            plan,
            journal,
            reason,
            expires_at.as_deref(),
            actor,
        ),
        Command::DeployJournals => deploy_journals_command(paths),
        Command::DeployJournalInspect { journal_id } => {
            deploy_journal_inspect_command(paths, journal_id)
        }
        Command::DeployResume {
            plan,
            journal,
            dry_run,
            execute,
            approval_token,
        } => deploy_resume_command(
            paths,
            plan,
            journal,
            *dry_run,
            *execute,
            approval_token.as_deref(),
        ),
        Command::InstallCheck => install_check_command(paths),
        Command::Helper { command } => helper_command(paths, command),
        Command::Tui { dump } => tui_command(paths, *dump, actor),
        Command::Approvals => approvals_command(paths),
        Command::Audit { limit } => audit_command(paths, *limit),
        Command::Approve { approval_id } => approve_command(paths, approval_id, actor),
        Command::Reject {
            approval_id,
            reason,
        } => reject_command(paths, approval_id, actor, reason.as_deref()),
        Command::Mcp => anyhow::bail!("mcp must be run as a dedicated stdio command"),
    }
}

fn acquire_global_lock_for_command(
    command: &Command,
    paths: &RuntimePaths,
    actor: &str,
    audit_target: &str,
) -> Result<Option<GlobalLock>> {
    if command_requires_global_lock(command) {
        return GlobalLock::acquire(&paths.state_dir, actor, command.name(), audit_target)
            .map(Some);
    }
    Ok(None)
}

fn command_requires_global_lock(command: &Command) -> bool {
    matches!(
        command,
        Command::Snapshot { dry_run: false, .. }
            | Command::SnapshotCoverage {
                register_baseline: true,
                execute: true,
                ..
            }
            | Command::Rollback { dry_run: false, .. }
            | Command::Deploy { execute: true, .. }
            | Command::RequestDeployExecution { .. }
            | Command::RequestDeployResume { .. }
            | Command::DeployResume { execute: true, .. }
            | Command::Helper {
                command: HelperCommand::RunDeployOperation { .. },
            }
            | Command::Backup {
                command: BackupCommand::Run { execute: true, .. }
                    | BackupCommand::Check { .. }
                    | BackupCommand::Restore { execute: true, .. }
                    | BackupCommand::Drill { execute: true, .. }
                    | BackupCommand::DrillSuite { execute: true, .. }
                    | BackupCommand::DrillCleanup { execute: true, .. }
                    | BackupCommand::RefreshStale { execute: true, .. }
                    | BackupCommand::TargetAdd { execute: true, .. }
                    | BackupCommand::RepoInit { execute: true, .. }
                    | BackupCommand::S3Smoke { execute: true, .. }
                    | BackupCommand::VolumeProtect {
                        command: BackupVolumeProtectCommand::Run { execute: true, .. }
                            | BackupVolumeProtectCommand::Resume { execute: true, .. }
                            | BackupVolumeProtectCommand::Cleanup { execute: true, .. }
                            | BackupVolumeProtectCommand::BatchRun { execute: true, .. }
                            | BackupVolumeProtectCommand::CampaignRun { execute: true, .. }
                            | BackupVolumeProtectCommand::CampaignResume { execute: true, .. }
                            | BackupVolumeProtectCommand::CampaignAbort { execute: true, .. }
                            | BackupVolumeProtectCommand::LabRun { execute: true, .. }
                            | BackupVolumeProtectCommand::BackfillRecord { execute: true, .. }
                            | BackupVolumeProtectCommand::RetentionImport { execute: true, .. }
                            | BackupVolumeProtectCommand::ArchiveDrill { execute: true, .. }
                            | BackupVolumeProtectCommand::GovernanceInstall { execute: true, .. }
                            | BackupVolumeProtectCommand::ProfileDraft { execute: true, .. }
                            | BackupVolumeProtectCommand::JournalMaintain { execute: true, .. },
                    }
                    | BackupCommand::Timer {
                        command: BackupTimerCommand::Install { execute: true, .. }
                            | BackupTimerCommand::Alert { execute: true, .. }
                            | BackupTimerCommand::AlertTest { execute: true, .. }
                            | BackupTimerCommand::AlertConfigure { execute: true, .. },
                    }
                    | BackupCommand::Prune { .. },
            }
            | Command::Registry {
                command: RegistryCommand::ImportProjects { .. },
            }
            | Command::Registry {
                command: RegistryCommand::Normalize { execute: true },
            }
            | Command::Registry {
                command: RegistryCommand::PublicDataException {
                    command: RegistryPublicDataExceptionCommand::Add { execute: true, .. },
                },
            }
            | Command::Registry {
                command: RegistryCommand::PromoteImport { dry_run: false, .. },
            }
            | Command::Registry {
                command: RegistryCommand::Drift {
                    command: RegistryDriftCommand::ServiceAdd { execute: true, .. }
                        | RegistryDriftCommand::Adopt { execute: true, .. }
                        | RegistryDriftCommand::AdoptReview { execute: true, .. }
                        | RegistryDriftCommand::Ignore { execute: true, .. }
                        | RegistryDriftCommand::Review {
                            command: RegistryDriftReviewCommand::Apply { execute: true, .. },
                        }
                        | RegistryDriftCommand::CleanupRequest {
                            command: RegistryDriftCleanupRequestCommand::RequestExecution { .. }
                                | RegistryDriftCleanupRequestCommand::Sync { execute: true, .. }
                                | RegistryDriftCleanupRequestCommand::Mark { execute: true, .. }
                                | RegistryDriftCleanupRequestCommand::Evidence {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceResolve {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::Execute { execute: true, .. }
                                | RegistryDriftCleanupRequestCommand::Finalize {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::HandoffPack {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceKeygen {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::ManifestSign {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::AuditBundle {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceKeyTrust {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceKeyRevoke {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::AuditCheckpoint {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceWormExport {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::Reconcile {
                                    execute: true,
                                    ..
                                },
                        },
                },
            }
            | Command::Approve { .. }
            | Command::Reject { .. }
    )
}

fn registry_command(
    paths: &RuntimePaths,
    command: &RegistryCommand,
    actor: &str,
) -> Result<CommandOutput> {
    match command {
        RegistryCommand::Validate => registry_validate_command(paths),
        RegistryCommand::Normalize { execute } => registry_normalize_command(paths, *execute),
        RegistryCommand::Schemas => registry_schemas_command(),
        RegistryCommand::ExportSchema { name } => registry_export_schema_command(name),
        RegistryCommand::ImportProjects { .. } => registry_import_projects_command(paths, command),
        RegistryCommand::ImportCheck {
            import_dir,
            scan_observed,
        } => registry_import_check_command(import_dir, *scan_observed),
        RegistryCommand::PromoteImport {
            import_dir,
            dry_run,
            scan_observed,
            allow_observed_drift,
            approval_token,
        } => registry_promote_import_command(
            paths,
            import_dir,
            *dry_run,
            *scan_observed,
            *allow_observed_drift,
            approval_token.as_deref(),
        ),
        RegistryCommand::Drift { command } => registry_drift_command(paths, command, actor),
        RegistryCommand::PublicDataException { command } => {
            registry_public_data_exception_command(paths, command)
        }
    }
}

fn registry_validate_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let schema_report = validate_registry_schemas(&paths.registry_dir);
    let doctor_report = if schema_report.ok {
        let registry = Registry::load(&paths.registry_dir)?;
        Some(DoctorReport::from_registry(&registry))
    } else {
        None
    };
    let doctor_errors = doctor_report.as_ref().map_or(0, |report| report.errors);
    let warnings = doctor_report.as_ref().map_or(0, |report| report.warnings);
    let errors = schema_report.errors + doctor_errors;
    let ok = errors == 0;

    let mut lines = vec![format!(
        "registry: {}\nstatus: {}\nschema errors: {}\ndoctor errors: {}\nwarnings: {}",
        display_path(&paths.registry_dir),
        if ok { "ok" } else { "error" },
        schema_report.errors,
        doctor_errors,
        warnings
    )];
    for finding in &schema_report.findings {
        lines.push(format!(
            "schema\t{}\t{}\t{}\t{}",
            finding.file, finding.instance_path, finding.schema_path, finding.message
        ));
    }
    if let Some(report) = &doctor_report {
        for finding in &report.findings {
            lines.push(format!(
                "{:?}\t{}\t{}\t{}",
                finding.severity,
                finding.code,
                finding.target.as_deref().unwrap_or("-"),
                finding.message
            ));
        }
    }

    Ok(CommandOutput {
        json: json!({
            "ok": ok,
            "errors": errors,
            "warnings": warnings,
            "schema_errors": schema_report.errors,
            "doctor_errors": doctor_errors,
            "schema_validation": schema_report,
            "doctor": doctor_report,
        }),
        text: lines.join("\n"),
        exit_code: if ok { 0 } else { 1 },
        audit_decision: if ok { "allow" } else { "warn" },
        dry_run: false,
    })
}

fn registry_normalize_command(paths: &RuntimePaths, execute: bool) -> Result<CommandOutput> {
    let mut registry = Registry::load(&paths.registry_dir)?;
    let legacy_port_sources = registry
        .ports
        .ports
        .iter()
        .filter(|port| port.source == "observed_adopted")
        .count();
    for port in &mut registry.ports.ports {
        if port.source == "observed_adopted" {
            port.source = "observed".to_string();
        }
        if port.exposure == "local" {
            port.exposure = "localhost".to_string();
        } else if port.exposure == "private" {
            port.exposure = "private_network".to_string();
        }
    }

    let mut changed_files = Vec::new();
    normalize_registry_file(
        &paths.registry_dir,
        "services.yml",
        &registry.services,
        execute,
        &mut changed_files,
    )?;
    normalize_registry_file(
        &paths.registry_dir,
        "ports.yml",
        &registry.ports,
        execute,
        &mut changed_files,
    )?;
    normalize_registry_file(
        &paths.registry_dir,
        "domains.yml",
        &registry.domains,
        execute,
        &mut changed_files,
    )?;
    normalize_registry_file(
        &paths.registry_dir,
        "volumes.yml",
        &registry.volumes,
        execute,
        &mut changed_files,
    )?;
    normalize_registry_file(
        &paths.registry_dir,
        "snapshots.yml",
        &registry.snapshots,
        execute,
        &mut changed_files,
    )?;
    normalize_registry_file(
        &paths.registry_dir,
        "backups.yml",
        &registry.backups,
        execute,
        &mut changed_files,
    )?;
    normalize_registry_file(
        &paths.registry_dir,
        "policies.yml",
        &registry.policies,
        execute,
        &mut changed_files,
    )?;

    let status = if changed_files.is_empty() {
        "unchanged"
    } else if execute {
        "normalized"
    } else {
        "dry_run"
    };
    let text = format!(
        "registry normalize: {status}\nchanged_files: {}\nlegacy_port_sources: {}",
        changed_files.len(),
        legacy_port_sources
    );

    Ok(CommandOutput {
        json: json!({
            "ok": true,
            "execute": execute,
            "status": status,
            "changed_files": changed_files,
            "legacy_port_sources": legacy_port_sources,
        }),
        text,
        exit_code: 0,
        audit_decision: "allow",
        dry_run: !execute,
    })
}

fn registry_public_data_exception_command(
    paths: &RuntimePaths,
    command: &RegistryPublicDataExceptionCommand,
) -> Result<CommandOutput> {
    match command {
        RegistryPublicDataExceptionCommand::Add {
            port_id,
            owner,
            reason,
            expires_at,
            mitigation,
            status,
            execute,
        } => registry_public_data_exception_add_command(
            paths,
            PublicDataExceptionAddInput {
                port_id,
                owner: owner.as_deref(),
                reason,
                expires_at,
                mitigation: mitigation.as_deref(),
                status,
                execute: *execute,
            },
        ),
    }
}

fn registry_public_data_exception_add_command(
    paths: &RuntimePaths,
    input: PublicDataExceptionAddInput<'_>,
) -> Result<CommandOutput> {
    let mut registry = Registry::load(&paths.registry_dir)?;
    let owner_value = input
        .owner
        .map(str::to_string)
        .unwrap_or_else(|| env::var("USER").unwrap_or_else(|_| "unknown".to_string()));
    let mut limitations = Vec::new();
    let mut warnings = Vec::new();

    validate_registry_record_id("port_id", input.port_id, &mut limitations);
    validate_registry_record_id("status", input.status, &mut limitations);
    validate_short_registry_text("owner", &owner_value, &mut limitations);
    validate_short_registry_text("reason", input.reason, &mut limitations);
    validate_optional_registry_text("mitigation", input.mitigation, &mut limitations);

    let expires_at_parsed = time::OffsetDateTime::parse(
        input.expires_at,
        &time::format_description::well_known::Rfc3339,
    );
    match expires_at_parsed {
        Ok(ts) if ts <= time::OffsetDateTime::now_utc() => {
            limitations.push("expires_at must be in the future".to_string());
        }
        Ok(_) => {}
        Err(_) => limitations.push("expires_at must be an RFC3339 timestamp".to_string()),
    }

    let Some(port) = registry
        .ports
        .ports
        .iter()
        .find(|port| port.id == input.port_id)
    else {
        limitations.push(format!("port_id is not registered: {}", input.port_id));
        return public_data_exception_add_output(PublicDataExceptionAddReport {
            ok: false,
            execute: input.execute,
            status: "blocked".to_string(),
            exception: None,
            warnings,
            limitations,
            changed_files: Vec::new(),
        });
    };
    if !is_public_data_port_record(port) {
        warnings.push(format!(
            "port {} is not classified as a public database/cache port",
            port.id
        ));
    }

    let exception = PublicDataPortException {
        id: existing_public_exception_id(&registry, input.port_id)
            .unwrap_or_else(|| format!("{}-public-temporary", input.port_id)),
        port_id: input.port_id.to_string(),
        owner: owner_value,
        reason: input.reason.to_string(),
        expires_at: input.expires_at.to_string(),
        status: input.status.to_string(),
        mitigation: input.mitigation.map(str::to_string),
    };
    validate_registry_record_id("exception_id", &exception.id, &mut limitations);

    if !limitations.is_empty() {
        return public_data_exception_add_output(PublicDataExceptionAddReport {
            ok: false,
            execute: input.execute,
            status: "blocked".to_string(),
            exception: Some(exception),
            warnings,
            limitations,
            changed_files: Vec::new(),
        });
    }

    upsert_public_data_exception(&mut registry, exception.clone());
    let mut changed_files = Vec::new();
    normalize_registry_file(
        &paths.registry_dir,
        "policies.yml",
        &registry.policies,
        input.execute,
        &mut changed_files,
    )?;

    public_data_exception_add_output(PublicDataExceptionAddReport {
        ok: true,
        execute: input.execute,
        status: if input.execute {
            "configured"
        } else {
            "dry_run"
        }
        .to_string(),
        exception: Some(exception),
        warnings,
        limitations,
        changed_files,
    })
}

fn public_data_exception_add_output(report: PublicDataExceptionAddReport) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
    ];
    if let Some(exception) = &report.exception {
        lines.push(format!("port_id: {}", exception.port_id));
        lines.push(format!("exception_id: {}", exception.id));
    }
    for warning in &report.warnings {
        lines.push(format!("warning: {warning}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize public data exception add report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok {
            if report.execute {
                "allow"
            } else {
                "require_approval"
            }
        } else {
            "deny"
        },
        dry_run: !report.execute,
    })
}

fn normalize_registry_file<T>(
    registry_dir: &Path,
    file_name: &str,
    value: &T,
    execute: bool,
    changed_files: &mut Vec<String>,
) -> Result<()>
where
    T: Serialize,
{
    let path = registry_dir.join(file_name);
    ensure_normalize_target(&path)?;
    let current = fs::read_to_string(&path)
        .with_context(|| format!("failed to read registry file {}", path.display()))?;
    let desired = serde_yaml::to_string(value)
        .with_context(|| format!("failed to serialize registry file {}", path.display()))?;
    if current == desired {
        return Ok(());
    }
    changed_files.push(display_path(&path));
    if execute {
        write_normalized_registry_file(&path, desired.as_bytes())?;
    }
    Ok(())
}

fn ensure_normalize_target(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect registry file {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to normalize registry symlink: {}", path.display());
    }
    if !metadata.is_file() {
        anyhow::bail!("registry path is not a regular file: {}", path.display());
    }
    Ok(())
}

fn write_normalized_registry_file(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary_path = path.with_file_name(format!(
        ".{}.opsctl-normalize-{}-{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("registry.yml"),
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o640).custom_flags(libc::O_NOFOLLOW);
    let write_result = (|| -> Result<()> {
        let mut file = options
            .open(&temporary_path)
            .with_context(|| format!("failed to create {}", temporary_path.display()))?;
        file.write_all(contents)
            .with_context(|| format!("failed to write {}", temporary_path.display()))?;
        fs::rename(&temporary_path, path)
            .with_context(|| format!("failed to replace {}", path.display()))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    write_result
}

fn validate_registry_record_id(label: &str, value: &str, limitations: &mut Vec<String>) {
    let valid = !value.is_empty()
        && value.len() <= 120
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        });
    if !valid {
        limitations.push(format!(
            "{label} must contain only lowercase letters, digits, '-' or '_'"
        ));
    }
}

fn validate_short_registry_text(label: &str, value: &str, limitations: &mut Vec<String>) {
    if value.trim().is_empty() {
        limitations.push(format!("{label} must not be empty"));
    }
    if value.len() > 512 {
        limitations.push(format!("{label} is too long"));
    }
    if value.contains('\n') || value.contains('\r') {
        limitations.push(format!("{label} must be a single line"));
    }
}

fn validate_optional_registry_text(
    label: &str,
    value: Option<&str>,
    limitations: &mut Vec<String>,
) {
    if let Some(value) = value {
        validate_short_registry_text(label, value, limitations);
    }
}

fn validate_registry_absolute_path(
    label: &str,
    path: &Path,
    limitations: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    if !path.is_absolute() {
        limitations.push(format!("{label} must be absolute: {}", display_path(path)));
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        limitations.push(format!(
            "{label} must not contain parent traversal: {}",
            display_path(path)
        ));
    }
    if !path.exists() {
        warnings.push(format!(
            "{label} does not currently exist: {}",
            display_path(path)
        ));
    }
}

fn generated_database_dump(service_id: &str, container: &str, kind: &str) -> BackupDatabaseDump {
    BackupDatabaseDump {
        id: format!("{service_id}-{container}-{kind}-dump"),
        kind: kind.to_string(),
        adapter: None,
        script: None,
        working_dir: None,
        container: Some(container.to_string()),
        database: Some("configured-by-env".to_string()),
        verify_kind: None,
        restore_image: None,
        restore_postgres_settings: Vec::new(),
        output_path: PathBuf::from(format!(
            "/var/lib/opsctl/backup-dumps/{service_id}/{container}-{kind}.sql.zst"
        )),
        notes: Some("Generated by controlled backup target onboarding.".to_string()),
    }
}

fn existing_public_exception_id(registry: &Registry, port_id: &str) -> Option<String> {
    registry
        .policies
        .public_data_port_exceptions
        .iter()
        .find(|exception| exception.port_id == port_id)
        .map(|exception| exception.id.clone())
}

fn upsert_public_data_exception(registry: &mut Registry, exception: PublicDataPortException) {
    if let Some(existing) = registry
        .policies
        .public_data_port_exceptions
        .iter_mut()
        .find(|existing| existing.port_id == exception.port_id)
    {
        *existing = exception;
    } else {
        registry
            .policies
            .public_data_port_exceptions
            .push(exception);
        registry
            .policies
            .public_data_port_exceptions
            .sort_by(|left, right| left.id.cmp(&right.id));
    }
}

fn is_public_data_port_record(port: &crate::registry::PortRecord) -> bool {
    if port.exposure != "public" {
        return false;
    }
    let haystack = format!(
        "{} {} {}",
        port.id,
        port.purpose.as_deref().unwrap_or_default(),
        port.notes.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase();
    [
        "postgres", "mysql", "mariadb", "redis", "valkey", "database", "cache",
    ]
    .iter()
    .any(|needle| haystack.contains(needle))
}

fn registry_import_projects_command(
    paths: &RuntimePaths,
    command: &RegistryCommand,
) -> Result<CommandOutput> {
    let RegistryCommand::ImportProjects {
        output,
        force,
        include_caddy,
        domain_from_docs,
        reserve_likely_ports,
        scan_observed,
        environment,
        backup_repository_id,
        projects,
    } = command
    else {
        anyhow::bail!("invalid registry import command");
    };
    let report = write_registry_import(&RegistryImportWriteOptions {
        build: RegistryImportBuildOptions {
            projects,
            include_caddy: *include_caddy,
            domain_from_docs: *domain_from_docs,
            reserve_likely_ports: *reserve_likely_ports,
            scan_observed: *scan_observed,
            default_environment: environment,
            backup_repository_id,
        },
        output_dir: output,
        active_registry_dir: &paths.registry_dir,
        force: *force,
    })?;

    let text = format!(
        "registry import: {}\nprojects: {} requested, {} imported\nfiles_written: {}\nservices: {}\nports: {}\ndomains: {}\nvolumes: {}",
        if report.ok { "ok" } else { "warn" },
        report.projects_requested,
        report.projects_imported,
        report.files_written.len(),
        report.counts.services,
        report.counts.ports,
        report.counts.domains,
        report.counts.volumes
    );

    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize registry import report")?,
        text,
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "warn" },
        dry_run: false,
    })
}

fn registry_import_check_command(
    import_dir: &std::path::Path,
    scan_observed: bool,
) -> Result<CommandOutput> {
    let report = check_registry_import(import_dir, scan_observed);
    let doctor_errors = report.doctor.as_ref().map_or(0, |doctor| doctor.errors);
    let backup_errors = report
        .backup_doctor
        .as_ref()
        .map_or(0, |backup| backup.errors);
    let observed_findings = report
        .observed
        .as_ref()
        .map_or(0, |observed| observed.findings.len());
    let production_gate_status = report
        .production_gates
        .as_ref()
        .map(|gates| gates.backup_history_status.as_str())
        .unwrap_or("unavailable");
    let production_gate_blocked = report
        .production_gates
        .as_ref()
        .map_or(0, |gates| gates.services_blocked);
    let text = format!(
        "registry import check: {}\nimport_dir: {}\nread_only: {}\nschema_errors: {}\ndoctor_errors: {}\nbackup_errors: {}\nproduction_backup_history: {} ({} blocked)\nobserved_findings: {}",
        if report.ok { "ok" } else { "warn" },
        report.import_dir,
        report.read_only,
        report.schema_validation.errors,
        doctor_errors,
        backup_errors,
        production_gate_status,
        production_gate_blocked,
        observed_findings
    );

    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize registry import check report")?,
        text,
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "warn" },
        dry_run: true,
    })
}

fn registry_promote_import_command(
    paths: &RuntimePaths,
    import_dir: &std::path::Path,
    dry_run: bool,
    scan_observed: bool,
    allow_observed_drift: bool,
    approval_token: Option<&str>,
) -> Result<CommandOutput> {
    let report = promote_registry_import(&RegistryPromoteImportOptions {
        import_dir,
        active_registry_dir: &paths.registry_dir,
        state_dir: &paths.state_dir,
        dry_run,
        scan_observed,
        allow_observed_drift,
        approval_token,
    })?;
    let changed = report
        .diff
        .iter()
        .filter(|entry| entry.status != "unchanged")
        .count();
    let mut lines = vec![
        format!("registry promote import: {}", report.status),
        format!("dry_run: {}", report.dry_run),
        format!("import_dir: {}", report.import_dir),
        format!("active_registry_dir: {}", report.active_registry_dir),
        format!("files_checked: {}", report.files_checked),
        format!("files_promoted: {}", report.files_promoted),
        format!("files_backed_up: {}", report.files_backed_up),
        format!("changed_files: {changed}"),
    ];
    if let Some(backup_dir) = &report.backup_dir {
        lines.push(format!("backup_dir: {backup_dir}"));
    }
    if let Some(token) = &report.approval_token {
        lines.push(format!("approval_token: {token}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    for accepted_risk in &report.accepted_risks {
        lines.push(format!("accepted_risk: {accepted_risk}"));
    }

    let audit_decision = if report.status == "promoted" {
        "allow"
    } else if report.status == "ready_for_promotion" {
        "require_approval"
    } else {
        "deny"
    };

    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize registry import promotion report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision,
        dry_run: report.dry_run,
    })
}

fn registry_drift_command(
    paths: &RuntimePaths,
    command: &RegistryDriftCommand,
    actor: &str,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    match command {
        RegistryDriftCommand::List => {
            let report = drift_list(&registry);
            drift_report_output(report)
        }
        RegistryDriftCommand::Groups => drift_groups_report_output(drift_groups(&registry)),
        RegistryDriftCommand::Suggest => drift_suggest_report_output(drift_suggest(&registry)),
        RegistryDriftCommand::Ownership { code, target } => {
            drift_ownership_report_output(drift_ownership(
                &registry,
                &DriftFilter {
                    code: code.as_deref(),
                    target: target.as_deref(),
                },
            ))
        }
        RegistryDriftCommand::Governance => {
            drift_governance_report_output(drift_governance(&registry))
        }
        RegistryDriftCommand::Review { command } => match command {
            RegistryDriftReviewCommand::Export => {
                drift_review_export_report_output(drift_review_export(&registry))
            }
            RegistryDriftReviewCommand::Apply {
                review_file,
                execute,
            } => drift_review_apply_report_output(drift_review_apply(&DriftReviewApplyOptions {
                registry_dir: &paths.registry_dir,
                state_dir: &paths.state_dir,
                review_file,
                actor,
                execute: *execute,
            })),
        },
        RegistryDriftCommand::CleanupPlan => {
            drift_cleanup_plan_report_output(drift_cleanup_plan(&registry))
        }
        RegistryDriftCommand::CleanupRequest { command } => match command {
            RegistryDriftCleanupRequestCommand::Export => {
                drift_cleanup_request_export_report_output(drift_cleanup_request_export(&registry))
            }
            RegistryDriftCleanupRequestCommand::Verify { request_file } => {
                drift_cleanup_request_verify_report_output(drift_cleanup_request_verify(
                    request_file,
                ))
            }
            RegistryDriftCleanupRequestCommand::Progress { request_file } => {
                drift_cleanup_progress_report_output(drift_cleanup_request_progress(
                    &registry,
                    request_file,
                ))
            }
            RegistryDriftCleanupRequestCommand::Triage { request_file } => {
                drift_cleanup_triage_report_output(drift_cleanup_request_triage(
                    &registry,
                    request_file,
                ))
            }
            RegistryDriftCleanupRequestCommand::Dashboard { request_file } => {
                drift_cleanup_dashboard_report_output(drift_cleanup_dashboard(
                    &registry,
                    request_file,
                ))
            }
            RegistryDriftCleanupRequestCommand::Worklist {
                request_file,
                kind,
                status,
                limit,
            } => drift_cleanup_worklist_report_output(drift_cleanup_worklist(
                &registry,
                request_file,
                kind.as_deref(),
                Some(status),
                *limit,
            )),
            RegistryDriftCleanupRequestCommand::Sync {
                request_file,
                execute,
            } => drift_cleanup_sync_report_output(drift_cleanup_request_sync(
                &DriftCleanupSyncOptions {
                    registry: &registry,
                    request_file,
                    execute: *execute,
                },
            )),
            RegistryDriftCleanupRequestCommand::ExecutionPlan { request_file } => {
                drift_cleanup_execution_plan_report_output(drift_cleanup_execution_plan(
                    request_file,
                ))
            }
            RegistryDriftCleanupRequestCommand::ExecutionGate { request_file } => {
                drift_cleanup_execution_gate_report_output(drift_cleanup_execution_gate(
                    &registry,
                    request_file,
                ))
            }
            RegistryDriftCleanupRequestCommand::ApprovalSummary { request_file } => {
                drift_cleanup_approval_summary_report_output(drift_cleanup_approval_summary(
                    request_file,
                ))
            }
            RegistryDriftCleanupRequestCommand::ApprovalPack {
                request_file,
                kind,
                status,
                limit,
            } => drift_cleanup_approval_pack_report_output(drift_cleanup_approval_pack(
                &registry,
                request_file,
                kind.as_deref(),
                Some(status),
                *limit,
            )),
            RegistryDriftCleanupRequestCommand::EvidencePlan {
                request_file,
                kind,
                status,
                limit,
            } => drift_cleanup_evidence_plan_report_output(drift_cleanup_evidence_plan(
                &registry,
                request_file,
                kind.as_deref(),
                Some(status),
                *limit,
            )),
            RegistryDriftCleanupRequestCommand::EvidenceResolve {
                request_file,
                request_id,
                target,
                all,
                max_age_hours,
                verify_repository,
                execute,
            } => {
                evidence_resolve_report_output(resolve_cleanup_evidence(&EvidenceResolveOptions {
                    registry: &registry,
                    request_file,
                    state_dir: &paths.state_dir,
                    request_ids: request_id,
                    targets: target,
                    all: *all,
                    max_age_hours: *max_age_hours,
                    verify_repository: *verify_repository,
                    execute: *execute,
                }))
            }
            RegistryDriftCleanupRequestCommand::VolumeOwnership {
                request_file,
                status,
                limit,
            } => drift_cleanup_volume_ownership_report_output(drift_cleanup_volume_ownership(
                &registry,
                request_file,
                Some(status),
                *limit,
            )),
            RegistryDriftCleanupRequestCommand::Runbook { request_file } => {
                drift_cleanup_runbook_report_output(drift_cleanup_runbook(request_file))
            }
            RegistryDriftCleanupRequestCommand::Mark {
                request_file,
                request_id,
                target,
                kind,
                target_prefix,
                target_contains,
                target_suffix,
                approval_status,
                owner,
                reason,
                operator_note,
                cleanup_strategy,
                exact_resource_id,
                backup_snapshot_id,
                restore_drill_id,
                maintenance_window,
                rollback_plan,
                approval_expires_at,
                execute,
            } => drift_cleanup_mark_report_output(drift_cleanup_request_mark(
                &DriftCleanupMarkOptions {
                    request_file,
                    request_ids: request_id,
                    targets: target,
                    kind: kind.as_deref(),
                    target_prefix: target_prefix.as_deref(),
                    target_contains: target_contains.as_deref(),
                    target_suffix: target_suffix.as_deref(),
                    approval_status,
                    owner: owner.as_deref(),
                    reason: reason.as_deref(),
                    operator_note: operator_note.as_deref(),
                    cleanup_strategy: cleanup_strategy.as_deref(),
                    exact_resource_id: exact_resource_id.as_deref(),
                    backup_snapshot_id: backup_snapshot_id.as_deref(),
                    restore_drill_id: restore_drill_id.as_deref(),
                    maintenance_window: maintenance_window.as_deref(),
                    rollback_plan: rollback_plan.as_deref(),
                    approval_expires_at: approval_expires_at.as_deref(),
                    execute: *execute,
                },
            )),
            RegistryDriftCleanupRequestCommand::Evidence {
                request_file,
                request_id,
                target,
                kind,
                target_prefix,
                target_contains,
                target_suffix,
                all,
                execute,
            } => drift_cleanup_evidence_report_output(drift_cleanup_request_evidence(
                &DriftCleanupEvidenceOptions {
                    registry: &registry,
                    request_file,
                    request_ids: request_id,
                    targets: target,
                    kind: kind.as_deref(),
                    target_prefix: target_prefix.as_deref(),
                    target_contains: target_contains.as_deref(),
                    target_suffix: target_suffix.as_deref(),
                    all: *all,
                    execute: *execute,
                },
            )),
            RegistryDriftCleanupRequestCommand::RequestExecution {
                request_file,
                reason,
                expires_at,
            } => drift_cleanup_request_execution_command(
                paths,
                request_file,
                reason,
                expires_at.as_deref(),
                actor,
            ),
            RegistryDriftCleanupRequestCommand::Execute {
                request_file,
                approval_token,
                reason,
                execute,
            } => drift_cleanup_execute_command(
                paths,
                &registry,
                request_file,
                approval_token.as_deref(),
                reason.as_deref(),
                actor,
                *execute,
            ),
            RegistryDriftCleanupRequestCommand::Finalize {
                request_file,
                request_id,
                outcome,
                reason,
                evidence,
                execute,
            } => drift_cleanup_finalize_report_output(drift_cleanup_finalize(
                &DriftCleanupFinalizeOptions {
                    request_file,
                    state_dir: &paths.state_dir,
                    actor,
                    request_id,
                    outcome,
                    reason: reason.as_deref(),
                    evidence: evidence.clone(),
                    execute: *execute,
                },
            )),
            RegistryDriftCleanupRequestCommand::HandoffPack {
                request_file,
                expires_at,
                ticket,
                require_signature,
                execute,
            } => cleanup_evidence_seal_output(seal_cleanup_evidence(&CleanupEvidenceSealOptions {
                request_file,
                state_dir: &paths.state_dir,
                actor,
                expires_at,
                ticket: ticket.as_deref(),
                require_signature: *require_signature,
                execute: *execute,
            })),
            RegistryDriftCleanupRequestCommand::ManifestStatus { manifest_file } => {
                cleanup_evidence_manifest_status_output(cleanup_manifest_status(
                    &paths.state_dir,
                    manifest_file,
                ))
            }
            RegistryDriftCleanupRequestCommand::EvidenceKeygen { key_id, execute } => {
                evidence_crypto_output(
                    evidence_crypto::evidence_key_generate(&paths.state_dir, key_id, *execute),
                    *execute,
                )
            }
            RegistryDriftCleanupRequestCommand::ManifestSign {
                manifest_file,
                key_id,
                credential_name,
                execute,
            } => evidence_crypto_output(
                evidence_crypto::sign_artifact_with_credential(
                    &paths.state_dir,
                    manifest_file,
                    key_id,
                    credential_name.as_deref(),
                    *execute,
                ),
                *execute,
            ),
            RegistryDriftCleanupRequestCommand::ManifestVerify { manifest_file } => {
                evidence_crypto_output(
                    evidence_crypto::verify_artifact_signature(&paths.state_dir, manifest_file),
                    false,
                )
            }
            RegistryDriftCleanupRequestCommand::AuditVerify => {
                evidence_crypto_output(evidence_crypto::verify_audit_chain(&paths.state_dir), false)
            }
            RegistryDriftCleanupRequestCommand::EvidenceKeyTrust {
                key_id,
                expires_at,
                execute,
            } => evidence_crypto_output(
                evidence_crypto::trust_evidence_key(
                    &paths.state_dir,
                    actor,
                    key_id,
                    expires_at,
                    *execute,
                ),
                *execute,
            ),
            RegistryDriftCleanupRequestCommand::EvidenceKeyRevoke {
                key_id,
                reason,
                execute,
            } => evidence_crypto_output(
                evidence_crypto::revoke_evidence_key(
                    &paths.state_dir,
                    actor,
                    key_id,
                    reason.as_deref(),
                    *execute,
                ),
                *execute,
            ),
            RegistryDriftCleanupRequestCommand::EvidenceKeyStatus { key_id } => {
                evidence_crypto_output(
                    evidence_crypto::evidence_key_status(&paths.state_dir, key_id.as_deref()),
                    false,
                )
            }
            RegistryDriftCleanupRequestCommand::AuditCheckpoint {
                key_id,
                credential_name,
                execute,
            } => evidence_crypto_output(
                evidence_crypto::create_audit_checkpoint(
                    &paths.state_dir,
                    actor,
                    key_id,
                    credential_name.as_deref(),
                    *execute,
                ),
                *execute,
            ),
            RegistryDriftCleanupRequestCommand::EvidenceVerifyAll => evidence_crypto_output(
                evidence_crypto::verify_all_evidence(&paths.state_dir),
                false,
            ),
            RegistryDriftCleanupRequestCommand::AuditBundle {
                manifest_file,
                output_file,
                execute,
            } => evidence_crypto_output(
                evidence_crypto::export_audit_bundle(
                    &paths.state_dir,
                    manifest_file,
                    output_file,
                    *execute,
                ),
                *execute,
            ),
            RegistryDriftCleanupRequestCommand::EvidenceWormExport {
                bundle_file,
                repository_id,
                execute,
            } => evidence_crypto_output(
                evidence_archive::archive_evidence_bundle(
                    &evidence_archive::EvidenceArchiveOptions {
                        registry: &registry,
                        state_dir: &paths.state_dir,
                        actor,
                        bundle_file,
                        repository_id,
                        execute: *execute,
                    },
                ),
                *execute,
            ),
            RegistryDriftCleanupRequestCommand::Reconcile {
                manifest_file,
                reason,
                execute,
            } => cleanup_evidence_reconcile_output(reconcile_cleanup_evidence(
                &CleanupEvidenceReconcileOptions {
                    registry: &registry,
                    state_dir: &paths.state_dir,
                    actor,
                    manifest_file,
                    reason: reason.as_deref(),
                    execute: *execute,
                },
            )),
        },
        RegistryDriftCommand::Explain { code, target } => {
            let report = drift_explain(
                &registry,
                &DriftFilter {
                    code: code.as_deref(),
                    target: target.as_deref(),
                },
            );
            drift_report_output(report)
        }
        RegistryDriftCommand::ServiceAdd {
            id,
            name,
            root,
            kind,
            environment,
            deploy_method,
            owner,
            status,
            backup_policy,
            reason,
            notes,
            execute,
        } => drift_service_add_report_output(drift_service_add(&DriftServiceAddOptions {
            registry: &registry,
            registry_dir: &paths.registry_dir,
            id,
            name: name.as_deref(),
            root: root.as_deref(),
            kind,
            environment,
            deploy_method: deploy_method.as_deref(),
            owner: owner.as_deref(),
            status,
            backup_policy: backup_policy.as_deref(),
            reason: reason.as_deref(),
            notes: notes.as_deref(),
            execute: *execute,
        })),
        RegistryDriftCommand::Adopt {
            kind,
            target,
            service_id,
            exposure,
            purpose,
            reason,
            operator_note,
            review_status,
            execute,
        } => {
            let report = drift_adopt(&DriftAdoptOptions {
                registry: &registry,
                registry_dir: &paths.registry_dir,
                state_dir: &paths.state_dir,
                actor,
                kind,
                target,
                service_id,
                exposure,
                purpose: purpose.as_deref(),
                reason: reason.as_deref(),
                operator_note: operator_note.as_deref(),
                review_status,
                execute: *execute,
            });
            let mut lines = vec![
                format!("status: {}", report.status),
                format!("kind: {}", report.kind),
                format!("target: {}", report.target),
                format!("service_id: {}", report.service_id),
                format!("execute: {}", report.execute),
                format!("review_status: {}", report.review_status),
            ];
            if let Some(reason) = &report.reason {
                lines.push(format!("reason: {reason}"));
            }
            if let Some(operator_note) = &report.operator_note {
                lines.push(format!("operator_note: {operator_note}"));
            }
            if let Some(record) = &report.record {
                lines.push(format!("record\t{}", serde_json::to_string(record)?));
            }
            for warning in &report.warnings {
                lines.push(format!("warning: {warning}"));
            }
            for limitation in &report.limitations {
                lines.push(format!("limitation: {limitation}"));
            }
            for changed_file in &report.changed_files {
                lines.push(format!("changed_file: {changed_file}"));
            }
            if let Some(journal_path) = &report.journal_path {
                lines.push(format!("journal: {journal_path}"));
            }
            Ok(CommandOutput {
                json: serde_json::to_value(&report)
                    .context("failed to serialize drift adopt report")?,
                text: lines.join("\n"),
                exit_code: if report.ok { 0 } else { 1 },
                audit_decision: if report.status == "adopted" {
                    "allow"
                } else if report.status == "dry_run" {
                    "require_approval"
                } else {
                    "deny"
                },
                dry_run: !execute,
            })
        }
        RegistryDriftCommand::AdoptReview {
            target,
            service_id,
            status,
            reason,
            execute,
        } => drift_adopt_review_report_output(drift_adopt_review(&DriftAdoptReviewOptions {
            registry: &registry,
            state_dir: &paths.state_dir,
            actor,
            target,
            service_id: service_id.as_deref(),
            status,
            reason: reason.as_deref(),
            execute: *execute,
        })),
        RegistryDriftCommand::Ignore {
            kind,
            code,
            target,
            target_prefix,
            target_suffix,
            target_contains,
            owner,
            reason,
            expires_at,
            execute,
        } => {
            let report = drift_ignore(&DriftIgnoreOptions {
                registry: &registry,
                registry_dir: &paths.registry_dir,
                state_dir: &paths.state_dir,
                actor,
                kind,
                code: code.as_deref(),
                target: target.as_deref(),
                target_prefix: target_prefix.as_deref(),
                target_suffix: target_suffix.as_deref(),
                target_contains: target_contains.as_deref(),
                owner: owner.as_deref(),
                reason: reason.as_deref(),
                expires_at: expires_at.as_deref(),
                execute: *execute,
            });
            drift_ignore_report_output(report)
        }
    }
}

fn drift_report_output(report: drift::DriftReport) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("active_findings: {}", report.active_findings),
        format!("ignored_findings: {}", report.ignored_findings),
        format!("adoption_candidates: {}", report.adoption_candidates.len()),
    ];
    for entry in &report.summary {
        lines.push(format!(
            "summary\t{}\t{}\tactive={}\tignored={}",
            entry.code,
            entry.kind.as_deref().unwrap_or("-"),
            entry.active,
            entry.ignored
        ));
    }
    for finding in &report.findings {
        lines.push(format!(
            "{}\t{}\t{}\t{}",
            finding.severity,
            finding.code,
            finding.target.as_deref().unwrap_or("-"),
            finding.message
        ));
    }
    for ignored in &report.ignored {
        lines.push(format!(
            "ignored\t{}\t{}\t{}\t{}",
            ignored.code,
            ignored.target.as_deref().unwrap_or("-"),
            ignored.ignore_id,
            ignored.reason
        ));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize drift report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "warn" },
        dry_run: true,
    })
}

fn drift_groups_report_output(report: drift::DriftGroupsReport) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("active_findings: {}", report.active_findings),
        format!("ignored_findings: {}", report.ignored_findings),
        format!("groups: {}", report.groups.len()),
    ];
    for group in &report.groups {
        lines.push(format!(
            "{}\t{}\tactive={}\tignored={}\t{}",
            group.kind, group.group, group.active, group.ignored, group.suggested_next_step
        ));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize drift groups report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn drift_suggest_report_output(report: drift::DriftSuggestReport) -> Result<CommandOutput> {
    let mut lines = vec![format!("suggestions: {}", report.suggestions.len())];
    for suggestion in &report.suggestions {
        lines.push(format!(
            "{}\t{}\t{}\t{}",
            suggestion.kind, suggestion.target, suggestion.action, suggestion.reason
        ));
        if let Some(command) = &suggestion.command {
            lines.push(format!("command: {command}"));
        }
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize drift suggest report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn drift_ownership_report_output(report: drift::DriftOwnershipReport) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("active_findings: {}", report.active_findings),
        format!("findings: {}", report.findings.len()),
    ];
    for finding in &report.findings {
        lines.push(format!(
            "finding\t{}\t{}\tconfidence={}\trisk={}",
            finding.kind, finding.target, finding.confidence, finding.cleanup_risk
        ));
        if !finding.service_candidates.is_empty() {
            lines.push(format!(
                "service_candidates: {}",
                finding.service_candidates.join(",")
            ));
        }
        for evidence in &finding.evidence {
            lines.push(format!("evidence: {evidence}"));
        }
        lines.push(format!("next: {}", finding.suggested_action));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift ownership report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "warn" },
        dry_run: true,
    })
}

fn drift_governance_report_output(report: drift::DriftGovernanceReport) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!(
            "human_decision_required: {}",
            report.human_decision_required
        ),
        format!("active_findings: {}", report.active_findings),
        format!("ignored_findings: {}", report.ignored_findings),
        format!("groups: {}", report.groups),
        format!("cleanup_candidates: {}", report.cleanup_candidates),
        format!(
            "suggestions: adopt={}, ignore={}, cleanup={}, unknown={}",
            report.adopt_suggestions,
            report.ignore_suggestions,
            report.cleanup_suggestions,
            report.unknown_suggestions
        ),
        format!(
            "cleanup_risk: public={}, data_risk={}, high_risk={}",
            report.public_cleanup_candidates,
            report.data_risk_cleanup_candidates,
            report.high_risk_cleanup_candidates
        ),
    ];
    for group in &report.priority_groups {
        lines.push(format!(
            "priority_group\t{}\t{}\tactive={}\t{}",
            group.kind, group.group, group.active, group.risk_hint
        ));
    }
    for step in &report.review_workflow {
        lines.push(format!(
            "workflow\t{}\t{}\twrites_registry={}\trequires_execute={}\t{}",
            step.order, step.name, step.writes_registry, step.requires_execute, step.command
        ));
    }
    for command in &report.safe_commands {
        lines.push(format!("safe_command: {command}"));
    }
    for action in &report.suggested_next_actions {
        lines.push(format!("next: {action}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift governance report")?,
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: if report.status == "blocked" {
            "warn"
        } else {
            "allow"
        },
        dry_run: true,
    })
}

fn drift_review_export_report_output(
    report: drift::DriftReviewExportReport,
) -> Result<CommandOutput> {
    let text = serde_yaml::to_string(&report.review)
        .context("failed to serialize drift review export YAML")?;
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift review export report")?,
        text,
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "warn" },
        dry_run: true,
    })
}

fn drift_review_apply_report_output(
    report: drift::DriftReviewApplyReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("review_file: {}", report.review_file),
        format!("total_items: {}", report.total_items),
        format!("planned: {}", report.planned),
        format!("applied: {}", report.applied),
        format!("skipped: {}", report.skipped),
        format!("blocked: {}", report.blocked),
        format!("cleanup_candidates: {}", report.cleanup_candidates),
    ];
    for entry in &report.entries {
        lines.push(format!(
            "entry\t{}\t{}\t{}\t{}\t{}",
            entry.group, entry.kind, entry.target, entry.action, entry.status
        ));
        for diff in &entry.diff {
            lines.push(format!("diff: {diff}"));
        }
        for warning in &entry.warnings {
            lines.push(format!("warning: {warning}"));
        }
        for limitation in &entry.limitations {
            lines.push(format!("limitation: {limitation}"));
        }
    }
    for changed_file in &report.changed_files {
        lines.push(format!("changed_file: {changed_file}"));
    }
    for journal_path in &report.journal_paths {
        lines.push(format!("journal: {journal_path}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift review apply report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.status == "applied" {
            "allow"
        } else if report.status == "dry_run" {
            "require_approval"
        } else {
            "deny"
        },
        dry_run: !report.execute,
    })
}

fn drift_cleanup_plan_report_output(
    report: drift::DriftCleanupPlanReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!("candidates: {}", report.candidates.len()),
    ];
    for candidate in &report.candidates {
        lines.push(format!(
            "{}\t{}\trisk={}\t{}",
            candidate.kind, candidate.target, candidate.risk, candidate.suggested_action
        ));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup plan report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: "warn",
        dry_run: true,
    })
}

fn drift_cleanup_request_export_report_output(
    report: drift::DriftCleanupRequestExportReport,
) -> Result<CommandOutput> {
    let text = serde_yaml::to_string(&report.request)
        .context("failed to serialize drift cleanup request YAML")?;
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup request export report")?,
        text,
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "warn" },
        dry_run: true,
    })
}

fn drift_cleanup_request_verify_report_output(
    report: drift::DriftCleanupRequestVerifyReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("request_file: {}", report.request_file),
        format!("total_items: {}", report.total_items),
        format!("approved: {}", report.approved),
        format!("rejected: {}", report.rejected),
        format!("needs_cleanup: {}", report.needs_cleanup),
        format!("unknown: {}", report.unknown),
        format!("high_risk: {}", report.high_risk),
        format!("public_bind: {}", report.public_bind),
        format!("data_risk: {}", report.data_risk),
        format!(
            "destructive_command_generated: {}",
            report.destructive_command_generated
        ),
    ];
    for entry in &report.entries {
        lines.push(format!(
            "entry\t{}\t{}\t{}\t{}\t{}",
            entry.request_id, entry.kind, entry.target, entry.approval_status, entry.status
        ));
        for warning in &entry.warnings {
            lines.push(format!("warning: {warning}"));
        }
        for limitation in &entry.limitations {
            lines.push(format!("limitation: {limitation}"));
        }
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup request verify report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn drift_cleanup_progress_report_output(
    report: drift::DriftCleanupProgressReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("request_file: {}", report.request_file),
        format!("current_candidates: {}", report.current_candidates),
        format!("request_items: {}", report.request_items),
        format!("matched_current: {}", report.matched_current),
        format!("missing_current: {}", report.missing_current),
        format!("stale_items: {}", report.stale_items),
        format!("approved: {}", report.approved),
        format!("needs_cleanup: {}", report.needs_cleanup),
        format!("rejected: {}", report.rejected),
        format!("unknown: {}", report.unknown),
    ];
    for kind in &report.by_kind {
        lines.push(format!(
            "kind\t{}\tcurrent={}\trequest={}\tmissing={}\tstale={}\tapproved={}\tneeds_cleanup={}\tunknown={}",
            kind.kind,
            kind.current_candidates,
            kind.request_items,
            kind.missing_current,
            kind.stale_items,
            kind.approved,
            kind.needs_cleanup,
            kind.unknown
        ));
    }
    for item in &report.missing {
        lines.push(format!(
            "missing\t{}\t{}\t{}",
            item.kind, item.target, item.risk
        ));
    }
    for item in &report.stale {
        lines.push(format!(
            "stale\t{}\t{}\t{}",
            item.kind,
            item.target,
            item.approval_status.as_deref().unwrap_or("-")
        ));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup progress report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn drift_cleanup_triage_report_output(
    report: drift::DriftCleanupTriageReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!("request_file: {}", report.request_file),
        format!("current_candidates: {}", report.current_candidates),
        format!("request_items: {}", report.request_items),
        format!("matched_current: {}", report.matched_current),
        format!("missing_current: {}", report.missing_current),
        format!("stale_items: {}", report.stale_items),
        format!("approved: {}", report.approved),
        format!("needs_cleanup: {}", report.needs_cleanup),
        format!("rejected: {}", report.rejected),
        format!("unknown: {}", report.unknown),
        format!("ready: {}", report.ready),
        format!("needs_approval: {}", report.needs_approval),
        format!("blocked: {}", report.blocked),
        format!("skipped: {}", report.skipped),
    ];
    for bucket in &report.by_status_kind {
        lines.push(format!(
            "bucket\t{}\t{}\t{}",
            bucket.approval_status, bucket.kind, bucket.items
        ));
    }
    for action in &report.next_actions {
        lines.push(format!("next_action: {action}"));
    }
    for item in &report.unknown_items {
        lines.push(format!(
            "unknown\t{}\t{}\t{}\trisk={}",
            item.request_id, item.kind, item.target, item.risk
        ));
        lines.push(format!("suggested_next_step: {}", item.suggested_next_step));
        for evidence in &item.evidence {
            lines.push(format!("evidence: {evidence}"));
        }
    }
    for item in &report.needs_cleanup_items {
        lines.push(format!(
            "needs_cleanup\t{}\t{}\t{}\trisk={}",
            item.request_id, item.kind, item.target, item.risk
        ));
        lines.push(format!("suggested_next_step: {}", item.suggested_next_step));
        for evidence in &item.required_evidence {
            lines.push(format!("required_evidence: {evidence}"));
        }
        for blocker in &item.blockers {
            lines.push(format!("blocker: {blocker}"));
        }
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup triage report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn drift_cleanup_dashboard_report_output(
    report: drift::DriftCleanupDashboardReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!("request_file: {}", report.request_file),
        format!("current_candidates: {}", report.progress.current_candidates),
        format!("request_items: {}", report.progress.request_items),
        format!("missing_current: {}", report.progress.missing_current),
        format!("stale_items: {}", report.progress.stale_items),
        format!("unknown: {}", report.approval_summary.unknown),
        format!("needs_cleanup: {}", report.approval_summary.needs_cleanup),
        format!("approved: {}", report.approval_summary.approved),
        format!("ready: {}", report.execution_plan.ready),
        format!("needs_approval: {}", report.execution_plan.needs_approval),
        format!("blocked: {}", report.execution_plan.blocked),
        format!("runbook_status: {}", report.runbook_status),
        format!("runbook_ready_steps: {}", report.runbook_ready_steps),
    ];
    for bucket in &report.approval_summary.by_status_kind {
        lines.push(format!(
            "bucket\t{}\t{}\t{}",
            bucket.approval_status, bucket.kind, bucket.items
        ));
    }
    for action in &report.next_actions {
        lines.push(format!("next_action: {action}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup dashboard report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn drift_cleanup_worklist_report_output(
    report: drift::DriftCleanupWorklistReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!("request_file: {}", report.request_file),
        format!(
            "filter: kind={} status={} limit={}",
            report.filter_kind.as_deref().unwrap_or("-"),
            report.filter_status,
            report.limit
        ),
        format!("total_matching_items: {}", report.total_matching_items),
        format!("returned_items: {}", report.returned_items),
    ];
    for item in &report.items {
        lines.push(format!(
            "item\t{}\t{}\t{}\tstatus={}\trisk={}",
            item.request_id, item.kind, item.target, item.approval_status, item.risk
        ));
        lines.push(format!("suggested_next_step: {}", item.suggested_next_step));
        for option in &item.decision_options {
            lines.push(format!(
                "decision\t{}\twrites_registry={}\trequires_execute={}\t{}",
                option.action, option.writes_registry, option.requires_execute, option.command
            ));
        }
    }
    for action in &report.next_actions {
        lines.push(format!("next_action: {action}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup worklist report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn drift_cleanup_sync_report_output(
    report: drift::DriftCleanupSyncReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("request_file: {}", report.request_file),
        format!("current_candidates: {}", report.current_candidates),
        format!("previous_items: {}", report.previous_items),
        format!("written_items: {}", report.written_items),
        format!("matched_current: {}", report.matched_current),
        format!("added: {}", report.added),
        format!("removed_stale: {}", report.removed_stale),
        format!("preserved_reviewed: {}", report.preserved_reviewed),
        format!("changed: {}", report.changed),
    ];
    if let Some(backup_file) = report.backup_file.as_deref() {
        lines.push(format!("backup_file: {backup_file}"));
    }
    for kind in &report.diff_summary {
        lines.push(format!(
            "diff_kind\t{}\tadded={}\tremoved_stale={}\tpreserved_current={}",
            kind.kind, kind.added, kind.removed_stale, kind.preserved_current
        ));
    }
    for item in &report.added_items {
        lines.push(format!(
            "added\t{}\t{}\trisk={}",
            item.kind, item.target, item.risk
        ));
    }
    for item in &report.removed_stale_items {
        lines.push(format!(
            "removed_stale\t{}\t{}\tstatus={}",
            item.kind,
            item.target,
            item.approval_status.as_deref().unwrap_or("-")
        ));
    }
    for entry in &report.entries {
        lines.push(format!(
            "entry\t{}\t{}\t{}\t{}",
            entry.action, entry.kind, entry.target, entry.approval_status
        ));
    }
    for action in &report.next_actions {
        lines.push(format!("next_action: {action}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup sync report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: !report.execute,
    })
}

fn drift_cleanup_mark_report_output(
    report: drift::DriftCleanupMarkReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("request_file: {}", report.request_file),
        format!("matched: {}", report.matched),
        format!("updated: {}", report.updated),
        format!("unchanged: {}", report.unchanged),
    ];
    if let Some(backup_file) = report.backup_file.as_deref() {
        lines.push(format!("backup_file: {backup_file}"));
    }
    for entry in &report.entries {
        lines.push(format!(
            "entry\t{}\t{}\t{}\t{} -> {}\tchanged={}",
            entry.request_id,
            entry.kind,
            entry.target,
            entry.previous_approval_status,
            entry.new_approval_status,
            entry.changed
        ));
        for diff in &entry.diff {
            lines.push(format!("diff: {diff}"));
        }
        for limitation in &entry.limitations {
            lines.push(format!("limitation: {limitation}"));
        }
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup mark report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: !report.execute,
    })
}

fn drift_cleanup_evidence_report_output(
    report: drift::DriftCleanupEvidenceReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("read_only: {}", report.read_only),
        format!("request_file: {}", report.request_file),
        format!("matched: {}", report.matched),
        format!("updated: {}", report.updated),
        format!("unchanged: {}", report.unchanged),
    ];
    if let Some(backup_file) = report.backup_file.as_deref() {
        lines.push(format!("backup_file: {backup_file}"));
    }
    for entry in &report.entries {
        lines.push(format!(
            "entry\t{}\t{}\t{}\tcurrent={}\tconfidence={}\tchanged={}",
            entry.request_id,
            entry.kind,
            entry.target,
            entry.current_candidate,
            entry.confidence.as_deref().unwrap_or("-"),
            entry.changed
        ));
        for candidate in &entry.service_candidates {
            lines.push(format!("service_candidate: {candidate}"));
        }
        for evidence in &entry.evidence {
            lines.push(format!("evidence: {evidence}"));
        }
        for limitation in &entry.limitations {
            lines.push(format!("limitation: {limitation}"));
        }
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup evidence report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: !report.execute,
    })
}

fn drift_cleanup_execution_plan_report_output(
    report: drift::DriftCleanupExecutionPlanReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("request_file: {}", report.request_file),
        format!("total_items: {}", report.total_items),
        format!("approved: {}", report.approved),
        format!("ready: {}", report.ready),
        format!("needs_approval: {}", report.needs_approval),
        format!("blocked: {}", report.blocked),
        format!("skipped: {}", report.skipped),
    ];
    for entry in &report.entries {
        lines.push(format!(
            "entry\t{}\t{}\t{}\t{}\t{}",
            entry.request_id, entry.kind, entry.target, entry.approval_status, entry.status
        ));
        for evidence in &entry.required_evidence {
            lines.push(format!("required_evidence: {evidence}"));
        }
        for blocker in &entry.blockers {
            lines.push(format!("blocker: {blocker}"));
        }
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup execution plan report")?,
        text: lines.join("\n"),
        exit_code: if report.status == "blocked" { 1 } else { 0 },
        audit_decision: if report.status == "ready_for_human_execution_request" {
            "require_approval"
        } else if report.status == "blocked" {
            "deny"
        } else {
            "allow"
        },
        dry_run: true,
    })
}

fn drift_cleanup_execution_gate_report_output(
    report: drift::DriftCleanupExecutionGateReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!("request_file: {}", report.request_file),
        format!("auto_cleanup_supported: {}", report.auto_cleanup_supported),
        format!(
            "destructive_executor_status: {}",
            report.destructive_executor_status
        ),
        format!("manual_handoff_status: {}", report.manual_handoff_status),
        format!("unknown: {}", report.unknown),
        format!("needs_cleanup: {}", report.needs_cleanup),
        format!("approved: {}", report.approved),
        format!("ready: {}", report.ready),
        format!("blocked: {}", report.blocked),
        format!("stale_items: {}", report.stale_items),
        format!("missing_current: {}", report.missing_current),
    ];
    for step in &report.required_steps {
        lines.push(format!("required_step: {step}"));
    }
    for command in &report.commands {
        lines.push(format!("command: {command}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup execution gate report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.status == "ready_for_manual_handoff" {
            "require_approval"
        } else if report.ok {
            "allow"
        } else {
            "deny"
        },
        dry_run: true,
    })
}

fn drift_cleanup_approval_summary_report_output(
    report: drift::DriftCleanupApprovalSummaryReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!("request_file: {}", report.request_file),
        format!("total_items: {}", report.total_items),
        format!("unknown: {}", report.unknown),
        format!("needs_cleanup: {}", report.needs_cleanup),
        format!("approved: {}", report.approved),
        format!("ready: {}", report.ready),
        format!("needs_approval: {}", report.needs_approval),
        format!("blocked: {}", report.blocked),
        format!("skipped: {}", report.skipped),
    ];
    for bucket in &report.by_status_kind {
        lines.push(format!(
            "bucket\t{}\t{}\t{}",
            bucket.approval_status, bucket.kind, bucket.items
        ));
    }
    for missing in &report.missing_evidence {
        lines.push(format!(
            "missing_evidence\t{}\titems={}\tkinds={}",
            missing.evidence,
            missing.items,
            missing.kinds.join(",")
        ));
        if !missing.sample_request_ids.is_empty() {
            lines.push(format!(
                "sample_request_ids: {}",
                missing.sample_request_ids.join(",")
            ));
        }
    }
    for action in &report.next_actions {
        lines.push(format!("next_action: {action}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup approval summary report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.status == "ready_for_human_execution_request" {
            "require_approval"
        } else if report.status == "blocked" {
            "deny"
        } else {
            "allow"
        },
        dry_run: true,
    })
}

fn drift_cleanup_approval_pack_report_output(
    report: drift::DriftCleanupApprovalPackReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!("request_file: {}", report.request_file),
        format!(
            "filter: kind={} status={} limit={}",
            report.filter_kind.as_deref().unwrap_or("-"),
            report.filter_status,
            report.limit
        ),
        format!("total_matching_items: {}", report.total_matching_items),
        format!("returned_items: {}", report.returned_items),
        format!(
            "human_approval_required: {}",
            report.human_approval_required
        ),
        format!(
            "destructive_execution_supported: {}",
            report.destructive_execution_supported
        ),
        format!("missing_current: {}", report.missing_current),
        format!("stale_items: {}", report.stale_items),
        format!("needs_approval: {}", report.needs_approval),
        format!("ready: {}", report.ready),
        format!("data_bearing_items: {}", report.data_bearing_items),
        format!("running_items: {}", report.running_items),
        format!("public_bind_items: {}", report.public_bind_items),
    ];
    lines.push(format!(
        "destructive_execution_reason: {}",
        report.destructive_execution_reason
    ));
    for checklist_item in &report.checklist {
        lines.push(format!("checklist: {checklist_item}"));
    }
    for entry in &report.entries {
        lines.push(format!(
            "entry\t{}\t{}\t{}\tstatus={}\trisk={}\tcurrent={}",
            entry.request_id,
            entry.kind,
            entry.target,
            entry.approval_status,
            entry.risk,
            entry.current_candidate
        ));
        for required in &entry.required_evidence {
            lines.push(format!("required_evidence: {required}"));
        }
        for note in &entry.review_notes {
            lines.push(format!("review_note: {note}"));
        }
        lines.push(format!(
            "approval_command_template: {}",
            entry.approval_command_template
        ));
    }
    for command in &report.safe_next_commands {
        lines.push(format!("safe_next_command: {command}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup approval pack report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ready > 0 {
            "require_approval"
        } else if report.status == "blocked" {
            "deny"
        } else {
            "allow"
        },
        dry_run: true,
    })
}

fn drift_cleanup_evidence_plan_report_output(
    report: drift::DriftCleanupEvidencePlanReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!("request_file: {}", report.request_file),
        format!(
            "filter: kind={} status={} limit={}",
            report.filter_kind.as_deref().unwrap_or("-"),
            report.filter_status,
            report.limit
        ),
        format!("total_items: {}", report.total_items),
        format!("returned_items: {}", report.returned_items),
        format!("docker_volume_items: {}", report.docker_volume_items),
        format!(
            "database_like_volume_items: {}",
            report.database_like_volume_items
        ),
        format!(
            "attached_or_running_items: {}",
            report.attached_or_running_items
        ),
        format!("truncated_volume_items: {}", report.truncated_volume_items),
        format!(
            "missing_backup_snapshot: {}",
            report.missing_backup_snapshot
        ),
        format!("missing_restore_drill: {}", report.missing_restore_drill),
    ];
    for group in &report.volume_groups {
        lines.push(format!(
            "volume_group\t{}\titems={}\tdatabase_like={}\tattached={}\ttruncated={}",
            group.group,
            group.items,
            group.database_like,
            group.attached_or_running_items,
            group.truncated_items
        ));
        for action in &group.required_actions {
            lines.push(format!("volume_group_action: {action}"));
        }
        for command in &group.command_templates {
            lines.push(format!("volume_group_command: {command}"));
        }
    }
    for step in &report.batch_plan {
        lines.push(format!(
            "batch_stage\t{}\titems={}\twrites_review_file={}\tdestructive={}\trequires_human_input={}",
            step.stage,
            step.item_count,
            step.writes_review_file,
            step.destructive,
            step.requires_human_input
        ));
        lines.push(format!("batch_command: {}", step.command_template));
        for note in &step.notes {
            lines.push(format!("batch_note: {note}"));
        }
    }
    for entry in &report.entries {
        lines.push(format!(
            "entry\t{}\t{}\t{}\tstage={}\tstatus={}",
            entry.request_id, entry.kind, entry.target, entry.evidence_stage, entry.approval_status
        ));
        for hint in &entry.volume_content_hints {
            lines.push(format!("volume_content_hint: {hint}"));
        }
        for required in &entry.required_evidence {
            lines.push(format!("required_evidence: {required}"));
        }
        for note in &entry.review_notes {
            lines.push(format!("review_note: {note}"));
        }
        for command in &entry.evidence_commands {
            lines.push(format!("evidence_command: {command}"));
        }
        for command in &entry.backup_restore_commands {
            lines.push(format!("backup_restore_command: {command}"));
        }
        for command in &entry.approval_commands {
            lines.push(format!("approval_command: {command}"));
        }
    }
    for command in &report.safe_next_commands {
        lines.push(format!("safe_next_command: {command}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup evidence plan report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.status == "blocked" {
            "deny"
        } else {
            "allow"
        },
        dry_run: true,
    })
}

fn drift_cleanup_volume_ownership_report_output(
    report: drift::DriftCleanupVolumeOwnershipReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!("request_file: {}", report.request_file),
        format!(
            "filter: status={} limit={}",
            report.filter_status, report.limit
        ),
        format!("total_volume_items: {}", report.total_volume_items),
        format!("returned_items: {}", report.returned_items),
        format!("current_candidates: {}", report.current_candidates),
        format!("anonymous_hash_volumes: {}", report.anonymous_hash_volumes),
        format!("named_volumes: {}", report.named_volumes),
        format!("attached_volumes: {}", report.attached_volumes),
        format!("unattached_volumes: {}", report.unattached_volumes),
        format!(
            "service_candidate_volumes: {}",
            report.service_candidate_volumes
        ),
        format!(
            "backup_evidence_missing: {}",
            report.backup_evidence_missing
        ),
        format!("restore_drill_missing: {}", report.restore_drill_missing),
    ];
    for bucket in &report.buckets {
        lines.push(format!(
            "bucket\t{}\titems={}\t{}",
            bucket.category, bucket.items, bucket.recommended_next_step
        ));
        if !bucket.sample_targets.is_empty() {
            lines.push(format!(
                "bucket_samples: {}",
                bucket.sample_targets.join(",")
            ));
        }
    }
    for entry in &report.entries {
        lines.push(format!(
            "volume\t{}\t{}\tcategory={}\tconfidence={}\tstatus={}",
            entry.request_id, entry.target, entry.category, entry.confidence, entry.approval_status
        ));
        if !entry.service_candidates.is_empty() {
            lines.push(format!(
                "service_candidates: {}",
                entry.service_candidates.join(",")
            ));
        }
        if !entry.mounted_by_containers.is_empty() {
            lines.push(format!(
                "mounted_by: {}",
                entry.mounted_by_containers.join(",")
            ));
        }
        for missing in &entry.missing_evidence {
            lines.push(format!("missing_evidence: {missing}"));
        }
        lines.push(format!("next: {}", entry.recommended_next_step));
    }
    for command in &report.safe_next_commands {
        lines.push(format!("safe_next_command: {command}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup volume ownership report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "warn" },
        dry_run: true,
    })
}

fn drift_cleanup_runbook_report_output(
    report: drift::DriftCleanupRunbookReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("request_file: {}", report.request_file),
        format!("total_items: {}", report.total_items),
        format!("ready: {}", report.ready),
        format!("blocked: {}", report.blocked),
    ];
    for safeguard in &report.global_safeguards {
        lines.push(format!("safeguard: {safeguard}"));
    }
    for step in &report.steps {
        lines.push(format!(
            "step\t{}\t{}\t{}\t{}",
            step.step_id, step.kind, step.target, step.request_id
        ));
        for check in &step.verify_before {
            lines.push(format!("verify_before: {check}"));
        }
        for action in &step.execute_manually {
            lines.push(format!("manual_action: {action}"));
        }
        for check in &step.verify_after {
            lines.push(format!("verify_after: {check}"));
        }
        for action in &step.forbidden_actions {
            lines.push(format!("forbidden: {action}"));
        }
        if let Some(rollback_plan) = &step.rollback_plan {
            lines.push(format!("rollback_plan: {rollback_plan}"));
        }
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup runbook report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn drift_cleanup_finalize_report_output(
    report: drift::DriftCleanupFinalizeReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("request_file: {}", report.request_file),
        format!("request_id: {}", report.request_id),
        format!("outcome: {}", report.outcome),
    ];
    if let Some(reason) = &report.reason {
        lines.push(format!("reason: {reason}"));
    }
    for evidence in &report.evidence {
        lines.push(format!("evidence: {evidence}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    if let Some(journal_path) = &report.journal_path {
        lines.push(format!("journal: {journal_path}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup finalize report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.status == "recorded" {
            "allow"
        } else if report.status == "dry_run" {
            "require_approval"
        } else {
            "deny"
        },
        dry_run: !report.execute,
    })
}

fn cleanup_evidence_seal_output(
    report: cleanup_evidence::CleanupEvidenceSealReport,
) -> Result<CommandOutput> {
    let text = format!(
        "cleanup evidence pack: {}\nhandoff recorded: {}\nmanifest: {}\nitems: {}\nlimitations: {}",
        report.status,
        report.handoff_recorded,
        report.manifest_path.as_deref().unwrap_or("-"),
        report
            .manifest
            .as_ref()
            .map_or(0, |value| value.items.len()),
        report.limitations.len()
    );
    Ok(CommandOutput {
        json: serde_json::to_value(&report)?,
        text,
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok {
            if report.read_only { "allow" } else { "execute" }
        } else {
            "deny"
        },
        dry_run: report.read_only,
    })
}

fn evidence_crypto_output(report: impl Serialize, execute: bool) -> Result<CommandOutput> {
    let json = serde_json::to_value(report)?;
    let ok = json
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let status = json
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("blocked")
        .to_string();
    Ok(CommandOutput {
        json,
        text: format!("evidence security: {status}"),
        exit_code: if ok { 0 } else { 1 },
        audit_decision: if ok {
            if execute { "execute" } else { "allow" }
        } else {
            "deny"
        },
        dry_run: !execute,
    })
}

fn cleanup_evidence_manifest_status_output(
    report: cleanup_evidence::CleanupEvidenceManifestStatusReport,
) -> Result<CommandOutput> {
    let text = format!(
        "cleanup manifest: {}\nseal valid: {}\nexpired: {}\nrequest unchanged: {}\nhandoff recorded: {}",
        report.status,
        report.seal_valid,
        report.expired,
        report.request_unchanged,
        report.handoff_recorded
    );
    Ok(CommandOutput {
        json: serde_json::to_value(&report)?,
        text,
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "warn" },
        dry_run: true,
    })
}

fn cleanup_evidence_reconcile_output(
    report: cleanup_evidence::CleanupEvidenceReconcileReport,
) -> Result<CommandOutput> {
    let text = format!(
        "cleanup reconciliation: {}\nabsent: {}\nstill present: {}\nfinalized: {}\nlimitations: {}",
        report.status,
        report.absent,
        report.still_present,
        report.finalized,
        report.limitations.len()
    );
    Ok(CommandOutput {
        json: serde_json::to_value(&report)?,
        text,
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok {
            if report.read_only { "allow" } else { "execute" }
        } else {
            "deny"
        },
        dry_run: report.read_only,
    })
}

fn drift_cleanup_execute_report_output(
    report: drift::DriftCleanupExecuteReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("decision: {}", report.decision),
        format!("execute: {}", report.execute),
        format!("request_file: {}", report.request_file),
        format!("ready: {}", report.ready),
        format!("total_items: {}", report.total_items),
        format!("manual_execution_only: {}", report.manual_execution_only),
    ];
    if let Some(token) = &report.approval_token {
        lines.push(format!("approval_token: {token}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    if let Some(journal_path) = &report.journal_path {
        lines.push(format!("journal: {journal_path}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift cleanup execute report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.status == "manual_handoff_recorded" {
            "allow"
        } else if report.status == "ready_for_approval" {
            "require_approval"
        } else {
            "deny"
        },
        dry_run: !report.execute,
    })
}

fn drift_cleanup_request_execution_command(
    paths: &RuntimePaths,
    request_file: &Path,
    reason: &str,
    expires_at: Option<&str>,
    actor: &str,
) -> Result<CommandOutput> {
    let plan = drift_cleanup_execution_plan(request_file);
    if plan.status != "ready_for_human_execution_request" {
        anyhow::bail!(
            "cleanup execution approval requires a ready execution plan; current status is {}",
            plan.status
        );
    }
    if plan.ready == 0 {
        anyhow::bail!("cleanup execution approval requires at least one ready item");
    }

    let scope = vec!["drift_cleanup_execution_request".to_string()];
    let mut constraints = vec![
        format!("request_file={}", display_path(request_file)),
        format!("ready_items={}", plan.ready),
        "approval does not authorize automatic deletion by opsctl".to_string(),
        "execution must be performed manually or by a separate approved service-owned runbook"
            .to_string(),
        "every resource must be re-matched exactly before cleanup".to_string(),
    ];
    for entry in plan
        .entries
        .iter()
        .filter(|entry| entry.status == "ready_for_human_execution_request")
        .take(20)
    {
        constraints.push(format!(
            "ready:{}:{}:{}",
            entry.request_id, entry.kind, entry.target
        ));
    }
    if plan.ready > 20 {
        constraints.push(format!("ready_items_truncated={}", plan.ready - 20));
    }

    let approval = request_approval(&ApprovalRequestOptions {
        registry_root: &paths.registry_dir,
        plan_id: "deploy_drift_cleanup_request",
        requested_by: actor,
        reason,
        scope: &scope,
        constraints: &constraints,
        expires_at,
    })?;

    let payload = json!({
        "decision": "require_approval",
        "approval": approval,
        "execution_approval_token": drift::expected_drift_cleanup_approval_token(&plan),
        "execution_plan": plan,
        "next_step": "Approve only after owner review, then execute cleanup manually or through a separate service-owned runbook. opsctl does not delete drift resources from this command."
    });
    Ok(CommandOutput {
        json: payload,
        text: "decision: require_approval\nscope: drift_cleanup_execution_request\nnext: approve only after owner review; opsctl does not execute cleanup deletion"
            .to_string(),
        exit_code: 0,
        audit_decision: "require_approval",
        dry_run: false,
    })
}

fn drift_cleanup_execute_command(
    paths: &RuntimePaths,
    registry: &Registry,
    request_file: &Path,
    approval_token: Option<&str>,
    reason: Option<&str>,
    actor: &str,
    execute: bool,
) -> Result<CommandOutput> {
    let approvals = list_approvals(&paths.registry_dir)?.approvals;
    let approval_satisfied = approved_scope_for_plan(&approvals, DRIFT_CLEANUP_EXECUTION_PLAN_ID)
        .iter()
        .any(|scope| scope == DRIFT_CLEANUP_EXECUTION_SCOPE);
    drift_cleanup_execute_report_output(drift_cleanup_execute_handoff(
        &DriftCleanupExecuteOptions {
            registry,
            request_file,
            state_dir: &paths.state_dir,
            actor,
            reason,
            approval_satisfied,
            approval_token,
            execute,
        },
    ))
}

fn drift_adopt_review_report_output(
    report: drift::DriftAdoptReviewReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("target: {}", report.target),
        format!("review_status: {}", report.review_status),
        format!(
            "matched_registry_records: {}",
            report.matched_registry_records.len()
        ),
    ];
    if let Some(service_id) = &report.service_id {
        lines.push(format!("service_id: {service_id}"));
    }
    if let Some(reason) = &report.reason {
        lines.push(format!("reason: {reason}"));
    }
    for record in &report.matched_registry_records {
        lines.push(format!("record: {record}"));
    }
    for warning in &report.warnings {
        lines.push(format!("warning: {warning}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    if let Some(journal_path) = &report.journal_path {
        lines.push(format!("journal: {journal_path}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift adopt review report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.status == "recorded" {
            "allow"
        } else if report.status == "dry_run" {
            "require_approval"
        } else {
            "deny"
        },
        dry_run: !report.execute,
    })
}

fn drift_ignore_report_output(report: drift::DriftIgnoreReport) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("matched_findings: {}", report.matched_findings.len()),
    ];
    if let Some(rule) = &report.rule {
        lines.push(format!(
            "rule\t{}\tkind={}\ttarget={}",
            rule.id,
            rule.kind.as_deref().unwrap_or("-"),
            rule.target
                .as_deref()
                .or(rule.target_prefix.as_deref())
                .or(rule.target_suffix.as_deref())
                .or(rule.target_contains.as_deref())
                .unwrap_or("-")
        ));
    }
    for warning in &report.warnings {
        lines.push(format!("warning: {warning}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    for changed_file in &report.changed_files {
        lines.push(format!("changed_file: {changed_file}"));
    }
    if let Some(journal_path) = &report.journal_path {
        lines.push(format!("journal: {journal_path}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize drift ignore report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.status == "ignored" {
            "allow"
        } else if report.status == "dry_run" {
            "require_approval"
        } else {
            "deny"
        },
        dry_run: !report.execute,
    })
}

fn drift_service_add_report_output(report: drift::DriftServiceAddReport) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("service_id: {}", report.service_id),
        format!("execute: {}", report.execute),
    ];
    if let Some(reason) = &report.reason {
        lines.push(format!("reason: {reason}"));
    }
    if let Some(service) = &report.service {
        lines.push(format!(
            "service\t{}\t{}\t{}\troot={}",
            service.id,
            service.kind,
            service.environment,
            service
                .root
                .as_ref()
                .map_or_else(|| "-".to_string(), |path| display_path(path))
        ));
    }
    for warning in &report.warnings {
        lines.push(format!("warning: {warning}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    for changed_file in &report.changed_files {
        lines.push(format!("changed_file: {changed_file}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize drift service-add report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.status == "added" {
            "allow"
        } else if report.status == "dry_run" {
            "require_approval"
        } else {
            "deny"
        },
        dry_run: !report.execute,
    })
}

fn backup_command(
    paths: &RuntimePaths,
    command: &BackupCommand,
    actor: &str,
) -> Result<CommandOutput> {
    match command {
        BackupCommand::Doctor => backup_doctor_command(paths),
        BackupCommand::Readiness => backup_readiness_command(paths),
        BackupCommand::History => backup_history_command(paths),
        BackupCommand::VolumeProtect { command } => volume_protect_command(paths, command, actor),
        BackupCommand::Plan {
            service_id,
            dry_run,
        } => backup_plan_command(paths, service_id, *dry_run),
        BackupCommand::Run {
            service_id,
            target,
            execute,
        } => backup_run_command(paths, service_id, target.as_deref(), *execute),
        BackupCommand::RefreshStale {
            service,
            restore_root,
            execute,
        } => backup_refresh_stale_command(paths, service, restore_root, *execute),
        BackupCommand::TargetAdd {
            service_id,
            repository_id,
            target_id,
            include_path,
            exclude_path,
            tag,
            postgres_container,
            mysql_container,
            mariadb_container,
            max_age_hours,
            schedule,
            status,
            notes,
            execute,
        } => backup_target_add_command(
            paths,
            BackupTargetAddInput {
                service_id,
                repository_id,
                target_id: target_id.as_deref(),
                include_paths: include_path,
                exclude_paths: exclude_path,
                tags: tag,
                postgres_containers: postgres_container,
                mysql_containers: mysql_container,
                mariadb_containers: mariadb_container,
                max_age_hours: *max_age_hours,
                schedule,
                status,
                notes: notes.as_deref(),
                execute: *execute,
            },
        ),
        BackupCommand::RestorePlan {
            service_id,
            target,
            repository_snapshot,
            restore_dir,
        } => backup_restore_command(
            paths,
            service_id,
            target.as_deref(),
            repository_snapshot,
            restore_dir,
            false,
            None,
        ),
        BackupCommand::Restore {
            service_id,
            target,
            repository_snapshot,
            restore_dir,
            execute,
            approval_token,
        } => backup_restore_command(
            paths,
            service_id,
            target.as_deref(),
            repository_snapshot,
            restore_dir,
            *execute,
            approval_token.as_deref(),
        ),
        BackupCommand::Drill {
            service_id,
            target,
            repository_snapshot,
            restore_dir,
            execute,
            scheduled,
            approval_token,
        } => backup_drill_command(
            paths,
            BackupDrillCommandInput {
                service_id,
                target_id: target.as_deref(),
                repository_snapshot: repository_snapshot.as_deref(),
                restore_dir,
                execute: *execute,
                scheduled: *scheduled,
                approval_token: approval_token.as_deref(),
            },
        ),
        BackupCommand::DrillCleanup {
            keep_days,
            keep_count,
            execute,
        } => backup_drill_cleanup_command(paths, *keep_days, *keep_count, *execute),
        BackupCommand::Timer { command } => backup_timer_command(paths, command),
        BackupCommand::OnboardingCheck { import_dir } => {
            backup_onboarding_check_command(paths, import_dir.as_deref())
        }
        BackupCommand::RepoInit {
            repository_id,
            execute,
            approval_token,
        } => backup_repository_init_command(
            paths,
            repository_id,
            *execute,
            approval_token.as_deref(),
        ),
        BackupCommand::DrillSuite {
            service,
            restore_root,
            execute,
        } => backup_drill_suite_command(paths, service, restore_root, *execute),
        BackupCommand::S3Smoke {
            endpoint,
            region,
            provider,
            bucket,
            prefix,
            access_key_env,
            secret_key_env,
            execute,
        } => backup_s3_smoke_command(BackupS3SmokeCommandInput {
            endpoint,
            region,
            provider,
            bucket,
            prefix: prefix.as_deref(),
            access_key_env,
            secret_key_env,
            execute: *execute,
        }),
        BackupCommand::Check { repository_id } => {
            backup_repository_check_command(paths, repository_id)
        }
        BackupCommand::Prune {
            repository_id,
            service_id,
            approval_token,
        } => backup_repository_prune_command(
            paths,
            repository_id,
            service_id.as_deref(),
            approval_token.as_deref(),
        ),
    }
}

fn volume_protect_command(
    paths: &RuntimePaths,
    command: &BackupVolumeProtectCommand,
    actor: &str,
) -> Result<CommandOutput> {
    match command {
        BackupVolumeProtectCommand::Plan {
            request_file,
            target,
            repository_id,
            restore_root,
            min_verification_strength,
        } => volume_protect_report_output(volume_protect(&VolumeProtectOptions {
            registry: &Registry::load(&paths.registry_dir)?,
            request_file,
            state_dir: &paths.state_dir,
            actor,
            target,
            repository_id,
            restore_root,
            run_id: None,
            resume_snapshot_id: None,
            min_verification_strength,
            alert_on_failure: false,
            execute: false,
        })?),
        BackupVolumeProtectCommand::Run {
            request_file,
            target,
            repository_id,
            restore_root,
            min_verification_strength,
            execute,
            alert_on_failure,
        } => volume_protect_report_output(volume_protect(&VolumeProtectOptions {
            registry: &Registry::load(&paths.registry_dir)?,
            request_file,
            state_dir: &paths.state_dir,
            actor,
            target,
            repository_id,
            restore_root,
            run_id: None,
            resume_snapshot_id: None,
            min_verification_strength,
            alert_on_failure: *alert_on_failure,
            execute: *execute,
        })?),
        BackupVolumeProtectCommand::History { limit } => {
            let report = volume_protect_history(&paths.state_dir, *limit);
            let text = format!(
                "volume protect history: {}\nrecords: {}\nlimitations: {}",
                report.status,
                report.entries.len(),
                report.limitations.len()
            );
            Ok(CommandOutput {
                json: serde_json::to_value(&report)?,
                text,
                exit_code: if report.ok { 0 } else { 1 },
                audit_decision: if report.ok { "allow" } else { "warn" },
                dry_run: true,
            })
        }
        BackupVolumeProtectCommand::Status { run_id, limit } => {
            let report = volume_protect_run_status(&paths.state_dir, run_id.as_deref(), *limit);
            let text = format!(
                "volume protect run status: {}\nruns: {}\nlimitations: {}",
                report.status,
                report.runs.len(),
                report.limitations.len()
            );
            Ok(CommandOutput {
                json: serde_json::to_value(&report)?,
                text,
                exit_code: if report.ok { 0 } else { 1 },
                audit_decision: if report.ok { "allow" } else { "warn" },
                dry_run: true,
            })
        }
        BackupVolumeProtectCommand::Resume {
            run_id,
            execute,
            alert_on_failure,
        } => volume_protect_report_output(resume_volume_protect(
            &Registry::load(&paths.registry_dir)?,
            &paths.state_dir,
            actor,
            run_id,
            *execute,
            *alert_on_failure,
        )?),
        BackupVolumeProtectCommand::Cleanup {
            restore_root,
            keep_days,
            keep_count,
            execute,
        } => {
            let report = cleanup_volume_protect_staging(
                &paths.state_dir,
                restore_root,
                *keep_days,
                *keep_count,
                *execute,
            );
            let text = format!(
                "volume protect staging cleanup: {}\ncandidates: {}\nremoved: {}\nlimitations: {}",
                report.status,
                report.candidates.len(),
                report.removed.len(),
                report.limitations.len()
            );
            Ok(CommandOutput {
                json: serde_json::to_value(&report)?,
                text,
                exit_code: if report.ok { 0 } else { 1 },
                audit_decision: if report.ok {
                    if *execute { "execute" } else { "allow" }
                } else {
                    "deny"
                },
                dry_run: !execute,
            })
        }
        BackupVolumeProtectCommand::BatchPlan {
            request_file,
            repository_id,
            restore_root,
            max_items,
            max_total_bytes,
            max_volume_bytes,
            min_verification_strength,
        } => volume_protect_batch_output(volume_protect_batch(&VolumeProtectBatchOptions {
            registry: &Registry::load(&paths.registry_dir)?,
            request_file,
            state_dir: &paths.state_dir,
            actor,
            repository_id,
            restore_root,
            max_items: *max_items,
            max_total_bytes: *max_total_bytes,
            max_volume_bytes: *max_volume_bytes,
            min_verification_strength,
            alert_on_failure: false,
            execute: false,
        })?),
        BackupVolumeProtectCommand::BatchRun {
            request_file,
            repository_id,
            restore_root,
            max_items,
            max_total_bytes,
            max_volume_bytes,
            min_verification_strength,
            execute,
            alert_on_failure,
        } => volume_protect_batch_output(volume_protect_batch(&VolumeProtectBatchOptions {
            registry: &Registry::load(&paths.registry_dir)?,
            request_file,
            state_dir: &paths.state_dir,
            actor,
            repository_id,
            restore_root,
            max_items: *max_items,
            max_total_bytes: *max_total_bytes,
            max_volume_bytes: *max_volume_bytes,
            min_verification_strength,
            alert_on_failure: *alert_on_failure,
            execute: *execute,
        })?),
        BackupVolumeProtectCommand::CampaignPlan {
            request_file,
            repository_id,
            restore_root,
            max_items,
            max_total_bytes,
            max_volume_bytes,
            min_free_bytes,
            max_failures,
            max_duration_seconds,
            min_verification_strength,
        } => volume_protect_campaign_output(volume_protect_campaign(
            &VolumeProtectCampaignOptions {
                registry: &Registry::load(&paths.registry_dir)?,
                request_file,
                state_dir: &paths.state_dir,
                actor,
                repository_id,
                restore_root,
                max_items: *max_items,
                max_total_bytes: *max_total_bytes,
                max_volume_bytes: *max_volume_bytes,
                min_free_bytes: *min_free_bytes,
                max_failures: *max_failures,
                max_duration_seconds: *max_duration_seconds,
                min_verification_strength,
                alert_on_failure: false,
                campaign_id: None,
                execute: false,
            },
        )?),
        BackupVolumeProtectCommand::CampaignRun {
            request_file,
            repository_id,
            restore_root,
            max_items,
            max_total_bytes,
            max_volume_bytes,
            min_free_bytes,
            max_failures,
            max_duration_seconds,
            min_verification_strength,
            alert_on_failure,
            execute,
        } => volume_protect_campaign_output(volume_protect_campaign(
            &VolumeProtectCampaignOptions {
                registry: &Registry::load(&paths.registry_dir)?,
                request_file,
                state_dir: &paths.state_dir,
                actor,
                repository_id,
                restore_root,
                max_items: *max_items,
                max_total_bytes: *max_total_bytes,
                max_volume_bytes: *max_volume_bytes,
                min_free_bytes: *min_free_bytes,
                max_failures: *max_failures,
                max_duration_seconds: *max_duration_seconds,
                min_verification_strength,
                alert_on_failure: *alert_on_failure,
                campaign_id: None,
                execute: *execute,
            },
        )?),
        BackupVolumeProtectCommand::CampaignStatus { campaign_id, limit } => {
            let report = campaign_status(&paths.state_dir, campaign_id.as_deref(), *limit);
            Ok(CommandOutput {
                text: format!(
                    "volume protect campaigns: {}\ncampaigns: {}\nlimitations: {}",
                    report.status,
                    report.campaigns.len(),
                    report.limitations.len()
                ),
                json: serde_json::to_value(&report)?,
                exit_code: if report.ok { 0 } else { 1 },
                audit_decision: if report.ok { "allow" } else { "warn" },
                dry_run: true,
            })
        }
        BackupVolumeProtectCommand::CampaignResume {
            campaign_id,
            execute,
        } => volume_protect_campaign_output(resume_campaign(
            &Registry::load(&paths.registry_dir)?,
            &paths.state_dir,
            actor,
            campaign_id,
            *execute,
        )?),
        BackupVolumeProtectCommand::CampaignAbort {
            campaign_id,
            reason,
            execute,
        } => {
            let report = abort_campaign(
                &paths.state_dir,
                actor,
                campaign_id,
                reason.as_deref(),
                *execute,
            );
            Ok(CommandOutput {
                text: format!(
                    "volume protect campaign abort: {}\nid: {}\njournal written: {}\nlimitations: {}",
                    report.status,
                    report.campaign_id,
                    report.journal_written,
                    report.limitations.len()
                ),
                json: serde_json::to_value(&report)?,
                exit_code: if report.ok { 0 } else { 1 },
                audit_decision: if report.ok {
                    if *execute {
                        "execute"
                    } else {
                        "require_approval"
                    }
                } else {
                    "deny"
                },
                dry_run: !execute,
            })
        }
        BackupVolumeProtectCommand::Metrics { request_file } => {
            let report = volume_protect_metrics(&paths.state_dir, request_file.as_deref());
            Ok(CommandOutput {
                text: report.metrics.clone(),
                json: serde_json::to_value(&report)?,
                exit_code: if report.ok { 0 } else { 1 },
                audit_decision: if report.ok { "allow" } else { "warn" },
                dry_run: true,
            })
        }
        BackupVolumeProtectCommand::FailureMatrix => evidence_crypto_output(
            release_matrix::production_failure_matrix(
                &Registry::load(&paths.registry_dir)?,
                &paths.state_dir,
            ),
            false,
        ),
        BackupVolumeProtectCommand::GapRescan { request_file } => evidence_crypto_output(
            release_matrix::evidence_gap_rescan(
                &Registry::load(&paths.registry_dir)?,
                &paths.state_dir,
                request_file,
            ),
            false,
        ),
        BackupVolumeProtectCommand::LabPlan {
            fixture_root,
            profile_id,
        } => evidence_crypto_output(
            recovery_lab::recovery_lab(&recovery_lab::RecoveryLabOptions {
                registry: &Registry::load(&paths.registry_dir)?,
                state_dir: &paths.state_dir,
                actor,
                fixture_root,
                profile_id: profile_id.as_deref(),
                execute: false,
            }),
            false,
        ),
        BackupVolumeProtectCommand::LabRun {
            fixture_root,
            profile_id,
            execute,
        } => evidence_crypto_output(
            recovery_lab::recovery_lab(&recovery_lab::RecoveryLabOptions {
                registry: &Registry::load(&paths.registry_dir)?,
                state_dir: &paths.state_dir,
                actor,
                fixture_root,
                profile_id: profile_id.as_deref(),
                execute: *execute,
            }),
            *execute,
        ),
        BackupVolumeProtectCommand::LabStatus { limit } => evidence_crypto_output(
            recovery_lab::recovery_lab_status(&paths.state_dir, *limit),
            false,
        ),
        BackupVolumeProtectCommand::LabQualify {
            fixture_root,
            max_age_hours,
        } => evidence_crypto_output(
            recovery_lab::recovery_qualification(
                &Registry::load(&paths.registry_dir)?,
                &paths.state_dir,
                fixture_root,
                *max_age_hours,
            ),
            false,
        ),
        BackupVolumeProtectCommand::BackfillPlan {
            request_file,
            repository_id,
            restore_root,
            max_age_hours,
        } => evidence_crypto_output(
            evidence_backfill::evidence_backfill(&evidence_backfill::EvidenceBackfillOptions {
                registry: &Registry::load(&paths.registry_dir)?,
                state_dir: &paths.state_dir,
                actor,
                request_file,
                repository_id,
                restore_root,
                max_age_hours: *max_age_hours,
                record: false,
            }),
            false,
        ),
        BackupVolumeProtectCommand::BackfillRecord {
            request_file,
            repository_id,
            restore_root,
            max_age_hours,
            execute,
        } => evidence_crypto_output(
            evidence_backfill::evidence_backfill(&evidence_backfill::EvidenceBackfillOptions {
                registry: &Registry::load(&paths.registry_dir)?,
                state_dir: &paths.state_dir,
                actor,
                request_file,
                repository_id,
                restore_root,
                max_age_hours: *max_age_hours,
                record: *execute,
            }),
            *execute,
        ),
        BackupVolumeProtectCommand::BackfillStatus { limit } => evidence_crypto_output(
            evidence_backfill::evidence_backfill_status(&paths.state_dir, *limit),
            false,
        ),
        BackupVolumeProtectCommand::RetentionStatus {
            attestation_file,
            max_age_hours,
        } => evidence_crypto_output(
            evidence_retention::retention_attestation_status(
                &Registry::load(&paths.registry_dir)?,
                &paths.state_dir,
                attestation_file.as_deref(),
                *max_age_hours,
            ),
            false,
        ),
        BackupVolumeProtectCommand::RetentionImport {
            attestation_file,
            max_age_hours,
            execute,
        } => evidence_crypto_output(
            evidence_retention::import_retention_attestation(
                &evidence_retention::RetentionImportOptions {
                    registry: &Registry::load(&paths.registry_dir)?,
                    state_dir: &paths.state_dir,
                    actor,
                    attestation_file,
                    max_age_hours: *max_age_hours,
                    execute: *execute,
                },
            ),
            *execute,
        ),
        BackupVolumeProtectCommand::ArchiveDrill {
            repository_id,
            repository_snapshot,
            bundle_name,
            restore_root,
            execute,
        } => evidence_crypto_output(
            evidence_retention::evidence_archive_drill(
                &evidence_retention::EvidenceArchiveDrillOptions {
                    registry: &Registry::load(&paths.registry_dir)?,
                    state_dir: &paths.state_dir,
                    actor,
                    repository_id,
                    repository_snapshot,
                    bundle_name,
                    restore_root,
                    execute: *execute,
                },
            ),
            *execute,
        ),
        BackupVolumeProtectCommand::ArchiveDrillStatus { limit } => evidence_crypto_output(
            evidence_retention::archive_drill_status(&paths.state_dir, *limit),
            false,
        ),
        BackupVolumeProtectCommand::KeyDrStatus {
            retention_max_age_hours,
        } => evidence_crypto_output(
            evidence_retention::key_disaster_recovery_status(
                &Registry::load(&paths.registry_dir)?,
                &paths.state_dir,
                *retention_max_age_hours,
            ),
            false,
        ),
        BackupVolumeProtectCommand::GovernancePlan { key_id, profile_id } => {
            evidence_crypto_output(
                recovery_governance::governance_timers(
                    &recovery_governance::GovernanceTimerOptions {
                        registry: &Registry::load(&paths.registry_dir)?,
                        state_dir: &paths.state_dir,
                        key_id: key_id.as_deref(),
                        profile_id: profile_id.as_deref(),
                        execute: false,
                        include_status: false,
                    },
                ),
                false,
            )
        }
        BackupVolumeProtectCommand::GovernanceInstall {
            key_id,
            profile_id,
            execute,
        } => evidence_crypto_output(
            recovery_governance::governance_timers(&recovery_governance::GovernanceTimerOptions {
                registry: &Registry::load(&paths.registry_dir)?,
                state_dir: &paths.state_dir,
                key_id: key_id.as_deref(),
                profile_id: profile_id.as_deref(),
                execute: *execute,
                include_status: true,
            }),
            *execute,
        ),
        BackupVolumeProtectCommand::GovernanceStatus { key_id, profile_id } => {
            evidence_crypto_output(
                recovery_governance::governance_timers(
                    &recovery_governance::GovernanceTimerOptions {
                        registry: &Registry::load(&paths.registry_dir)?,
                        state_dir: &paths.state_dir,
                        key_id: key_id.as_deref(),
                        profile_id: profile_id.as_deref(),
                        execute: false,
                        include_status: true,
                    },
                ),
                false,
            )
        }
        BackupVolumeProtectCommand::Slo {
            request_file,
            fixture_root,
            lab_max_age_hours,
            backfill_max_age_hours,
            retention_max_age_hours,
            archive_drill_max_age_hours,
        } => {
            let report =
                recovery_governance::recovery_slo(&recovery_governance::RecoverySloOptions {
                    registry: &Registry::load(&paths.registry_dir)?,
                    state_dir: &paths.state_dir,
                    request_file: request_file.as_deref(),
                    fixture_root,
                    lab_max_age_hours: *lab_max_age_hours,
                    backfill_max_age_hours: *backfill_max_age_hours,
                    retention_max_age_hours: *retention_max_age_hours,
                    archive_drill_max_age_hours: *archive_drill_max_age_hours,
                });
            Ok(CommandOutput {
                text: report.metrics.clone(),
                json: serde_json::to_value(&report)?,
                exit_code: if report.ok { 0 } else { 1 },
                audit_decision: if report.ok { "allow" } else { "warn" },
                dry_run: true,
            })
        }
        BackupVolumeProtectCommand::ProfileDetect { source_dir, volume } => evidence_crypto_output(
            recovery_onboarding::detect_recovery_profile(source_dir, volume),
            false,
        ),
        BackupVolumeProtectCommand::ProfilePlan {
            source_dir,
            volume,
            engine,
            engine_version,
            image,
        } => evidence_crypto_output(
            recovery_onboarding::plan_recovery_profile(
                &Registry::load(&paths.registry_dir)?,
                source_dir,
                volume,
                engine.as_deref(),
                engine_version.as_deref(),
                image.as_deref(),
            ),
            false,
        ),
        BackupVolumeProtectCommand::ProfileDraft {
            source_dir,
            volume,
            engine,
            engine_version,
            image,
            output_file,
            execute,
        } => evidence_crypto_output(
            recovery_onboarding::write_recovery_profile_draft(
                &Registry::load(&paths.registry_dir)?,
                source_dir,
                volume,
                engine.as_deref(),
                engine_version.as_deref(),
                image.as_deref(),
                output_file,
                *execute,
            ),
            *execute,
        ),
        BackupVolumeProtectCommand::ProfileValidate { profile_file } => evidence_crypto_output(
            recovery_onboarding::validate_recovery_profile_file(
                &Registry::load(&paths.registry_dir)?,
                profile_file,
            ),
            false,
        ),
        BackupVolumeProtectCommand::JournalMaintain {
            archive_dir,
            keep_lines,
            execute,
        } => {
            let default_archive = paths.state_dir.join("volume-protect-archives");
            let archive_dir = archive_dir.as_deref().unwrap_or(&default_archive);
            let report = maintain_volume_protect_journals(
                &paths.state_dir,
                archive_dir,
                *keep_lines,
                *execute,
            );
            Ok(CommandOutput {
                text: format!(
                    "volume protect journal maintenance: {}\nfiles: {}\nlimitations: {}",
                    report.status,
                    report.files.len(),
                    report.limitations.len()
                ),
                json: serde_json::to_value(&report)?,
                exit_code: if report.ok { 0 } else { 1 },
                audit_decision: if report.ok {
                    if *execute { "execute" } else { "allow" }
                } else {
                    "deny"
                },
                dry_run: !execute,
            })
        }
    }
}

fn volume_protect_campaign_output(
    report: volume_protect_campaign::VolumeProtectCampaignReport,
) -> Result<CommandOutput> {
    let text = format!(
        "volume protect campaign: {}\nid: {}\neligible: {}\nsucceeded: {}\nfailed: {}\nremaining: {}\nevidence gaps: {} -> {}",
        report.status,
        report.campaign_id,
        report.eligible,
        report.succeeded,
        report.failed,
        report.remaining,
        report.evidence_gaps_before,
        report.evidence_gaps_after
    );
    let dry_run = report.read_only;
    Ok(CommandOutput {
        json: serde_json::to_value(&report)?,
        text,
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok {
            if dry_run { "allow" } else { "execute" }
        } else if report.status == "paused" {
            "warn"
        } else {
            "deny"
        },
        dry_run,
    })
}

fn volume_protect_batch_output(
    report: volume_protect_batch::VolumeProtectBatchReport,
) -> Result<CommandOutput> {
    let text = format!(
        "volume protect batch: {}\neligible: {}\nskipped: {}\nsucceeded: {}\nfailed: {}\nplanned bytes: {}",
        report.status,
        report.eligible,
        report.skipped,
        report.succeeded,
        report.failed,
        report.planned_bytes
    );
    let dry_run = report.read_only;
    Ok(CommandOutput {
        json: serde_json::to_value(&report)?,
        text,
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok {
            if dry_run { "allow" } else { "execute" }
        } else {
            "deny"
        },
        dry_run,
    })
}

fn volume_protect_report_output(
    report: volume_protect::VolumeProtectReport,
) -> Result<CommandOutput> {
    let text = format!(
        "volume protect: {}\ntarget: {}\nrepository: {}\nsnapshot: {}\nrestore drill: {}\ncleanup evidence updated: {}\nlimitations: {}",
        report.status,
        report.target,
        report.repository_id,
        report.repository_snapshot_id.as_deref().unwrap_or("-"),
        report.restore_drill_id.as_deref().unwrap_or("-"),
        report.cleanup_request_updated,
        report.limitations.len()
    );
    let dry_run = report.read_only;
    let ok = report.ok;
    Ok(CommandOutput {
        json: serde_json::to_value(&report)?,
        text,
        exit_code: if ok { 0 } else { 1 },
        audit_decision: if ok {
            if dry_run { "allow" } else { "execute" }
        } else {
            "deny"
        },
        dry_run,
    })
}

fn evidence_resolve_report_output(
    report: volume_protect::EvidenceResolveReport,
) -> Result<CommandOutput> {
    let text = format!(
        "cleanup evidence resolve: {}\nselected: {}\nmatched: {}\nambiguous: {}\nmissing: {}\nstale: {}\nupdated: {}\nlimitations: {}",
        report.status,
        report.selected_items,
        report.matched,
        report.ambiguous,
        report.missing,
        report.stale,
        report.updated,
        report.limitations.len()
    );
    let dry_run = report.read_only;
    let ok = report.ok;
    Ok(CommandOutput {
        json: serde_json::to_value(&report)?,
        text,
        exit_code: if ok { 0 } else { 1 },
        audit_decision: if ok {
            if dry_run { "allow" } else { "execute" }
        } else {
            "warn"
        },
        dry_run,
    })
}

fn backup_doctor_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = backup_doctor(&registry);
    let mut lines = vec![format!(
        "backup: {} error(s), {} warning(s), {} repository(ies), {} target(s), {} history record(s)",
        report.errors, report.warnings, report.repositories, report.targets, report.history
    )];
    for finding in &report.findings {
        lines.push(format!(
            "{:?}\t{}\t{}\t{}",
            finding.severity,
            finding.code,
            finding.target.as_deref().unwrap_or("-"),
            finding.message
        ));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize backup doctor report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: false,
    })
}

fn backup_readiness_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = backup_readiness(&registry);
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("dry_run: {}", report.dry_run),
        format!("services_checked: {}", report.services_checked),
        format!("ready: {}", report.ready),
        format!("blocked: {}", report.blocked),
        format!("skipped: {}", report.skipped),
    ];
    for name in &report.missing_env {
        lines.push(format!("missing_env: {name}"));
    }
    for service in &report.services {
        lines.push(format!(
            "service\t{}\t{}\t{} target(s)",
            service.service_id, service.status, service.target_count
        ));
        for limitation in &service.limitations {
            lines.push(format!(
                "limitation\t{}\t{}",
                service.service_id, limitation
            ));
        }
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize backup readiness report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn backup_history_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = backup_history(&registry);
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("services_checked: {}", report.services_checked),
        format!("services_ready: {}", report.services_ready),
        format!("services_blocked: {}", report.services_blocked),
        format!("services_with_success: {}", report.services_with_success),
        format!(
            "services_missing_success: {}",
            report.services_missing_success
        ),
        format!("records: {}", report.records),
        format!(
            "freshness_policy_targets: {}",
            report.freshness_policy_targets
        ),
        format!("stale_targets: {}", report.stale_targets),
        format!("future_records: {}", report.future_records),
        format!("invalid_timestamps: {}", report.invalid_timestamps),
        format!("repository_checks: {}", report.repository_checks),
        format!(
            "repository_check_targets_blocked: {}",
            report.repository_check_targets_blocked
        ),
        format!("restore_drills: {}", report.restore_drills),
        format!(
            "restore_drill_targets_blocked: {}",
            report.restore_drill_targets_blocked
        ),
    ];
    for service in &report.services {
        lines.push(format!(
            "service\t{}\t{}\t{} successful / {} target(s)",
            service.service_id, service.status, service.successful_targets, service.target_count
        ));
        for target_id in &service.missing_success_targets {
            lines.push(format!(
                "missing_success\t{}\t{}",
                service.service_id, target_id
            ));
        }
        for target_id in &service.stale_targets {
            lines.push(format!("stale\t{}\t{}", service.service_id, target_id));
        }
        for record_id in &service.future_record_ids {
            lines.push(format!(
                "future_record\t{}\t{}",
                service.service_id, record_id
            ));
        }
        for record_id in &service.invalid_record_ids {
            lines.push(format!(
                "invalid_timestamp\t{}\t{}",
                service.service_id, record_id
            ));
        }
        for target_id in &service.repository_check_blocked_targets {
            lines.push(format!(
                "repository_check_blocked\t{}\t{}",
                service.service_id, target_id
            ));
        }
        for target_id in &service.restore_drill_blocked_targets {
            lines.push(format!(
                "restore_drill_blocked\t{}\t{}",
                service.service_id, target_id
            ));
        }
        for limitation in &service.limitations {
            lines.push(format!(
                "limitation\t{}\t{}",
                service.service_id, limitation
            ));
        }
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize backup history report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: false,
    })
}

fn backup_plan_command(
    paths: &RuntimePaths,
    service_id: &str,
    dry_run: bool,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = plan_backup(&BackupPlanOptions {
        registry: &registry,
        service_id,
        dry_run,
    })?;
    let mut lines = vec![
        format!("service: {}", report.service_id),
        format!("status: {}", report.status),
        format!("dry_run: {}", report.dry_run),
        format!("targets: {}", report.targets.len()),
    ];
    for name in &report.missing_env {
        lines.push(format!("missing_env: {name}"));
    }
    for target in &report.targets {
        lines.push(format!(
            "target\t{}\t{}\t{}",
            target.target_id, target.repository_id, target.status
        ));
        for operation in &target.operations {
            lines.push(format!(
                "{}\t{}\t{}",
                operation.order, operation.kind, operation.detail
            ));
        }
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize backup plan report")?,
        text: lines.join("\n"),
        exit_code: if report.status == "ready" { 0 } else { 1 },
        audit_decision: if report.status == "ready" {
            "allow"
        } else {
            "deny"
        },
        dry_run,
    })
}

fn backup_target_add_command(
    paths: &RuntimePaths,
    input: BackupTargetAddInput<'_>,
) -> Result<CommandOutput> {
    let mut registry = Registry::load(&paths.registry_dir)?;
    let mut limitations = Vec::new();
    let mut warnings = Vec::new();
    let target_id = input
        .target_id
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}-restic", input.service_id));

    validate_registry_record_id("service_id", input.service_id, &mut limitations);
    validate_registry_record_id("repository_id", input.repository_id, &mut limitations);
    validate_registry_record_id("target_id", &target_id, &mut limitations);
    validate_registry_record_id("status", input.status, &mut limitations);
    validate_short_registry_text("schedule", input.schedule, &mut limitations);
    validate_optional_registry_text("notes", input.notes, &mut limitations);

    let service = registry
        .services
        .services
        .iter()
        .find(|service| service.id == input.service_id);
    if service.is_none() {
        limitations.push(format!(
            "service_id is not registered: {}",
            input.service_id
        ));
    }
    if !registry
        .backups
        .repositories
        .iter()
        .any(|repository| repository.id == input.repository_id)
    {
        limitations.push(format!(
            "repository_id is not registered: {}",
            input.repository_id
        ));
    }
    if registry
        .backups
        .targets
        .iter()
        .any(|target| target.id == target_id)
    {
        limitations.push(format!("backup target id already exists: {target_id}"));
    }
    if registry
        .backups
        .targets
        .iter()
        .any(|target| target.service_id == input.service_id && target.status == "active")
    {
        warnings.push(format!(
            "service {} already has at least one active backup target",
            input.service_id
        ));
    }
    if input.max_age_hours == 0 {
        limitations.push("max_age_hours must be greater than zero".to_string());
    }

    let include_paths = if input.include_paths.is_empty() {
        service
            .map(|service| service.data_paths.clone())
            .unwrap_or_default()
    } else {
        input.include_paths.to_vec()
    };
    if include_paths.is_empty() {
        limitations.push("backup target must include at least one path".to_string());
    }
    for path in &include_paths {
        validate_registry_absolute_path("include_path", path, &mut limitations, &mut warnings);
    }
    for path in input.exclude_paths {
        validate_registry_absolute_path("exclude_path", path, &mut limitations, &mut warnings);
    }

    for container in input
        .postgres_containers
        .iter()
        .chain(input.mysql_containers.iter())
        .chain(input.mariadb_containers.iter())
    {
        validate_registry_record_id("container", container, &mut limitations);
    }

    let mut database_dumps = Vec::new();
    for container in input.postgres_containers {
        database_dumps.push(generated_database_dump(
            input.service_id,
            container,
            "postgres",
        ));
    }
    for container in input.mysql_containers {
        database_dumps.push(generated_database_dump(
            input.service_id,
            container,
            "mysql",
        ));
    }
    for container in input.mariadb_containers {
        database_dumps.push(generated_database_dump(
            input.service_id,
            container,
            "mariadb",
        ));
    }

    let mut final_include_paths = include_paths;
    if !database_dumps.is_empty() {
        let dump_dir = PathBuf::from(format!("/var/lib/opsctl/backup-dumps/{}", input.service_id));
        if !final_include_paths.iter().any(|path| path == &dump_dir) {
            final_include_paths.push(dump_dir);
        }
    }

    let mut tags = vec!["production".to_string(), "before-deploy".to_string()];
    for tag in input.tags {
        validate_short_registry_text("tag", tag, &mut limitations);
        if !tags.iter().any(|existing| existing == tag) {
            tags.push(tag.clone());
        }
    }

    let target = BackupTarget {
        id: target_id.clone(),
        service_id: input.service_id.to_string(),
        repository_id: input.repository_id.to_string(),
        max_age_hours: Some(input.max_age_hours),
        repository_check_max_age_hours: None,
        restore_drill_max_age_hours: None,
        include_paths: final_include_paths,
        exclude_paths: input.exclude_paths.to_vec(),
        tags,
        database_dumps,
        schedule: input.schedule.to_string(),
        status: input.status.to_string(),
        notes: input
            .notes
            .map(str::to_string)
            .or_else(|| Some("Added by controlled backup target onboarding.".to_string())),
    };

    if !limitations.is_empty() {
        return backup_target_add_output(BackupTargetAddReport {
            ok: false,
            execute: input.execute,
            status: "blocked".to_string(),
            service_id: input.service_id.to_string(),
            target_id,
            target: Some(target),
            warnings,
            limitations,
            changed_files: Vec::new(),
        });
    }

    let mut changed_files = Vec::new();
    if input.execute {
        registry.backups.targets.push(target.clone());
        registry
            .backups
            .targets
            .sort_by(|left, right| left.id.cmp(&right.id));
        normalize_registry_file(
            &paths.registry_dir,
            "backups.yml",
            &registry.backups,
            true,
            &mut changed_files,
        )?;
    } else {
        let mut preview = registry.backups.clone();
        preview.targets.push(target.clone());
        preview
            .targets
            .sort_by(|left, right| left.id.cmp(&right.id));
        normalize_registry_file(
            &paths.registry_dir,
            "backups.yml",
            &preview,
            false,
            &mut changed_files,
        )?;
    }

    backup_target_add_output(BackupTargetAddReport {
        ok: true,
        execute: input.execute,
        status: if input.execute { "added" } else { "dry_run" }.to_string(),
        service_id: input.service_id.to_string(),
        target_id,
        target: Some(target),
        warnings,
        limitations,
        changed_files,
    })
}

fn backup_target_add_output(report: BackupTargetAddReport) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("service: {}", report.service_id),
        format!("target: {}", report.target_id),
    ];
    for warning in &report.warnings {
        lines.push(format!("warning: {warning}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize backup target add report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok {
            if report.execute {
                "allow"
            } else {
                "require_approval"
            }
        } else {
            "deny"
        },
        dry_run: !report.execute,
    })
}

fn backup_run_command(
    paths: &RuntimePaths,
    service_id: &str,
    target_id: Option<&str>,
    execute: bool,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = run_backup(&BackupRunOptions {
        registry: &registry,
        registry_dir: &paths.registry_dir,
        service_id,
        target_id,
        execute,
    })?;
    let mut lines = vec![
        format!("service: {}", report.service_id),
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("targets: {}", report.targets.len()),
    ];
    for target in &report.targets {
        lines.push(format!(
            "target\t{}\t{}\t{}",
            target.target_id, target.repository_id, target.status
        ));
        for operation in &target.operations {
            lines.push(format!(
                "{}\t{}\t{}",
                operation.order, operation.kind, operation.status
            ));
        }
        for limitation in &target.limitations {
            lines.push(format!("limitation\t{}\t{}", target.target_id, limitation));
        }
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize backup run report")?,
        text: lines.join("\n"),
        exit_code: if matches!(report.status.as_str(), "success" | "dry_run") {
            0
        } else {
            1
        },
        audit_decision: if matches!(report.status.as_str(), "success" | "dry_run") {
            "allow"
        } else {
            "deny"
        },
        dry_run: !execute,
    })
}

fn backup_refresh_stale_command(
    paths: &RuntimePaths,
    service_ids: &[String],
    restore_root: &Path,
    execute: bool,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = backup_refresh_stale(&BackupRefreshStaleOptions {
        registry: &registry,
        registry_dir: &paths.registry_dir,
        service_ids,
        restore_root,
        execute,
    });
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("read_only: {}", report.read_only),
        format!("restore_root: {}", report.restore_root),
        format!("services_checked: {}", report.services_checked),
        format!("services_blocked: {}", report.services_blocked),
        format!("services_selected: {}", report.services_selected),
        format!("targets_planned: {}", report.targets_planned),
        format!("repositories_planned: {}", report.repositories_planned),
    ];
    if let Some(status) = &report.drill_suite_status {
        lines.push(format!("drill_suite_status: {status}"));
    }
    for service in &report.services {
        lines.push(format!(
            "service\t{}\t{}\ttargets={}\trepositories={}",
            service.service_id,
            service.status,
            service.target_ids.len(),
            service.repository_ids.len()
        ));
        for issue in &service.target_issues {
            lines.push(format!(
                "issue\t{}\t{}\t{}\t{}",
                service.service_id, issue.target_id, issue.issue, issue.detail
            ));
        }
        for run in &service.backup_runs {
            lines.push(format!(
                "backup_run\t{}\t{}\t{}",
                run.service_id, run.target_id, run.status
            ));
        }
    }
    for repository_check in &report.repository_checks {
        lines.push(format!(
            "repository_check\t{}\t{}",
            repository_check.repository_id, repository_check.status
        ));
    }
    for command in &report.planned_commands {
        lines.push(format!("planned_command: {command}"));
    }
    for failure in &report.failure_summary {
        lines.push(format!("failure: {failure}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize backup refresh stale report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok {
            if execute { "allow" } else { "require_approval" }
        } else {
            "deny"
        },
        dry_run: !execute,
    })
}

fn backup_restore_command(
    paths: &RuntimePaths,
    service_id: &str,
    target_id: Option<&str>,
    repository_snapshot: &str,
    restore_dir: &Path,
    execute: bool,
    approval_token: Option<&str>,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let options = BackupRestoreOptions {
        registry: &registry,
        registry_dir: Some(&paths.registry_dir),
        service_id,
        target_id,
        repository_snapshot_id: repository_snapshot,
        restore_dir,
        execute,
        approval_token,
    };
    let report = if execute {
        restore_backup(&options)?
    } else {
        plan_backup_restore(&options)?
    };
    backup_restore_report_output(report, !execute)
}

struct BackupDrillCommandInput<'a> {
    service_id: &'a str,
    target_id: Option<&'a str>,
    repository_snapshot: Option<&'a str>,
    restore_dir: &'a Path,
    execute: bool,
    scheduled: bool,
    approval_token: Option<&'a str>,
}

fn backup_drill_command(
    paths: &RuntimePaths,
    input: BackupDrillCommandInput<'_>,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = backup_restore_drill(&BackupDrillOptions {
        registry: &registry,
        registry_dir: Some(&paths.registry_dir),
        service_id: input.service_id,
        target_id: input.target_id,
        repository_snapshot_id: input.repository_snapshot,
        restore_dir: input.restore_dir,
        execute: input.execute,
        scheduled: input.scheduled,
        approval_token: input.approval_token,
    })?;
    backup_restore_report_output(report, !input.execute)
}

fn backup_drill_suite_command(
    paths: &RuntimePaths,
    service_ids: &[String],
    restore_root: &Path,
    execute: bool,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = backup_restore_drill_suite(&BackupDrillSuiteOptions {
        registry: &registry,
        registry_dir: Some(&paths.registry_dir),
        service_ids,
        restore_root,
        execute,
    });
    let mut lines = vec![
        format!("status: {}", if report.ok { "ready" } else { "blocked" }),
        format!("execute: {}", report.execute),
        format!("restore_root: {}", report.restore_root),
        format!("services_checked: {}", report.services_checked),
        format!("services_success: {}", report.services_success),
        format!("services_blocked: {}", report.services_blocked),
        format!("services_failed: {}", report.services_failed),
        format!(
            "database_import_check_enabled: {}",
            report.database_import_check_enabled
        ),
    ];
    for service in &report.reports {
        lines.push(format!(
            "service\t{}\t{}\t{}\t{}",
            service.service_id, service.target_id, service.repository_id, service.status
        ));
        for limitation in &service.limitations {
            lines.push(format!(
                "limitation\t{}\t{}",
                service.service_id, limitation
            ));
        }
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize backup drill suite report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: !execute,
    })
}

fn backup_drill_cleanup_command(
    paths: &RuntimePaths,
    keep_days: u32,
    keep_count: usize,
    execute: bool,
) -> Result<CommandOutput> {
    let report = cleanup_restore_drills(&DrillCleanupOptions {
        state_dir: &paths.state_dir,
        keep_days,
        keep_count,
        execute,
    });
    let mut lines = vec![
        format!("root: {}", report.root),
        format!("execute: {}", report.execute),
        format!("services: {}", report.services),
        format!("retained: {}", report.retained),
        format!("candidates: {}", report.candidates),
        format!("deleted: {}", report.deleted),
        format!("failed: {}", report.failed),
    ];
    for entry in &report.entries {
        lines.push(format!(
            "{}\t{}\t{}\t{}",
            entry.service_id, entry.status, entry.path, entry.reason
        ));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize restore drill cleanup report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok {
            if execute { "allow" } else { "require_approval" }
        } else {
            "deny"
        },
        dry_run: !execute,
    })
}

fn backup_timer_command(
    paths: &RuntimePaths,
    command: &BackupTimerCommand,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    match command {
        BackupTimerCommand::Plan {
            service_id,
            repository_id,
        } => backup_timer_report_output(backup_timer_plan(&BackupTimerOptions {
            registry: &registry,
            service_id: service_id.as_deref(),
            repository_id: repository_id.as_deref(),
            execute: false,
            include_status: false,
        })),
        BackupTimerCommand::Install {
            service_id,
            repository_id,
            execute,
        } => backup_timer_report_output(backup_timer_install(&BackupTimerOptions {
            registry: &registry,
            service_id: service_id.as_deref(),
            repository_id: repository_id.as_deref(),
            execute: *execute,
            include_status: *execute,
        })),
        BackupTimerCommand::Status {
            service_id,
            repository_id,
        } => backup_timer_report_output(backup_timer_status(&BackupTimerOptions {
            registry: &registry,
            service_id: service_id.as_deref(),
            repository_id: repository_id.as_deref(),
            execute: false,
            include_status: true,
        })),
        BackupTimerCommand::Monitor {
            service_id,
            repository_id,
            journal,
        } => backup_timer_monitor_report_output(backup_timer_monitor(&BackupTimerMonitorOptions {
            registry: &registry,
            service_id: service_id.as_deref(),
            repository_id: repository_id.as_deref(),
            include_journal: *journal,
        })),
        BackupTimerCommand::Alert {
            service_id,
            repository_id,
            journal,
            execute,
        } => backup_timer_alert_report_output(backup_timer_alert(&BackupTimerAlertOptions {
            registry: &registry,
            service_id: service_id.as_deref(),
            repository_id: repository_id.as_deref(),
            include_journal: *journal,
            execute: *execute,
        })),
        BackupTimerCommand::AlertTest { sink_id, execute } => {
            backup_timer_alert_test_report_output(backup_timer_alert_test(
                &BackupTimerAlertTestOptions {
                    registry: &registry,
                    sink_id: sink_id.as_deref(),
                    execute: *execute,
                },
            ))
        }
        BackupTimerCommand::AlertStatus { sink_id } => backup_timer_alert_status_report_output(
            backup_timer_alert_status(&BackupTimerAlertStatusOptions {
                registry: &registry,
                sink_id: sink_id.as_deref(),
            }),
        ),
        BackupTimerCommand::AlertEnablePlan {
            id,
            provider,
            target_env,
            owner,
            min_severity,
            topic,
        } => backup_timer_alert_enable_plan_report_output(backup_timer_alert_enable_plan(
            &BackupTimerAlertEnablePlanOptions {
                registry: &registry,
                id: id.as_deref(),
                provider: provider.as_deref(),
                target_env: target_env.as_deref(),
                owner: owner.as_deref(),
                min_severity: min_severity.as_deref(),
                topic: topic.as_deref(),
            },
        )),
        BackupTimerCommand::AlertEnvTemplate {
            id,
            provider,
            target_env,
            env_file,
        } => backup_timer_alert_env_template_report_output(backup_timer_alert_env_template(
            &BackupTimerAlertEnvTemplateOptions {
                registry: &registry,
                id: id.as_deref(),
                provider: provider.as_deref(),
                target_env: target_env.as_deref(),
                env_file: env_file.as_deref(),
            },
        )),
        BackupTimerCommand::AlertConfigure {
            id,
            provider,
            target_env,
            owner,
            status,
            min_severity,
            topic,
            notes,
            execute,
        } => {
            let owner_value = owner
                .clone()
                .unwrap_or_else(|| env::var("USER").unwrap_or_else(|_| "unknown".to_string()));
            backup_timer_alert_configure_report_output(backup_timer_alert_configure(
                &BackupTimerAlertConfigureOptions {
                    registry_dir: &paths.registry_dir,
                    id,
                    provider,
                    target_env,
                    owner: &owner_value,
                    status,
                    min_severity: Some(min_severity),
                    topic: topic.as_deref(),
                    notes: notes.as_deref(),
                    execute: *execute,
                },
            ))
        }
    }
}

fn backup_timer_report_output(report: backup_schedule::BackupTimerReport) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("execute: {}", report.execute),
        format!("read_only: {}", report.read_only),
        format!("entries: {}", report.entries.len()),
    ];
    for entry in &report.entries {
        lines.push(format!(
            "{}\t{}\t{}\t{}",
            entry.kind, entry.id, entry.timer_unit, entry.status
        ));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize backup timer report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: !report.execute,
    })
}

fn backup_timer_monitor_report_output(
    report: backup_schedule::BackupTimerMonitorReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!("entries: {}", report.entries.len()),
        format!(
            "timer_health: {} ({} checked, {} ready, {} blocked, max_consecutive_failures={})",
            report.health.status,
            report.health.services_checked,
            report.health.services_ready,
            report.health.services_blocked,
            report.health.max_consecutive_failures
        ),
        format!("alert_candidates: {}", report.alert_candidates.len()),
    ];
    for entry in &report.entries {
        lines.push(format!(
            "{}\t{}\t{}\tresult={}\tconsecutive_failures={}",
            entry.kind,
            entry.id,
            entry.recent_status,
            entry.service_result,
            entry.consecutive_failures
        ));
    }
    for candidate in &report.alert_candidates {
        lines.push(format!(
            "alert\t{}\t{}\t{}\t{}",
            candidate.severity, candidate.kind, candidate.id, candidate.reason
        ));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize backup timer monitor report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn backup_timer_alert_report_output(
    report: backup_schedule::BackupTimerAlertReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("read_only: {}", report.read_only),
        format!("alert_candidates: {}", report.candidate_count),
        format!("deliveries: {}", report.delivery_count),
    ];
    for delivery in &report.deliveries {
        lines.push(format!(
            "delivery\t{}\t{}\t{}\tcandidates={}\tattempts={}",
            delivery.sink_id,
            delivery.provider,
            delivery.status,
            delivery.candidate_count,
            delivery.attempts
        ));
        lines.push(format!("detail: {}", delivery.detail));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize backup timer alert report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.status == "sent" || report.status == "no_candidates" {
            "allow"
        } else if report.status == "planned" {
            "require_approval"
        } else {
            "deny"
        },
        dry_run: !report.execute,
    })
}

fn backup_timer_alert_test_report_output(
    report: backup_schedule::BackupTimerAlertTestReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("read_only: {}", report.read_only),
        format!(
            "sink_filter: {}",
            report.sink_filter.as_deref().unwrap_or("-")
        ),
        format!("deliveries: {}", report.delivery_count),
    ];
    for delivery in &report.deliveries {
        lines.push(format!(
            "delivery\t{}\t{}\t{}\tcandidates={}\tattempts={}",
            delivery.sink_id,
            delivery.provider,
            delivery.status,
            delivery.candidate_count,
            delivery.attempts
        ));
        lines.push(format!("detail: {}", delivery.detail));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize backup timer alert test report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.status == "sent" {
            "allow"
        } else if report.status == "planned" {
            "require_approval"
        } else {
            "deny"
        },
        dry_run: !report.execute,
    })
}

fn backup_timer_alert_status_report_output(
    report: backup_schedule::BackupTimerAlertStatusReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!(
            "sink_filter: {}",
            report.sink_filter.as_deref().unwrap_or("-")
        ),
        format!("total_sinks: {}", report.total_sinks),
        format!("active_sinks: {}", report.active_sinks),
        format!("disabled_sinks: {}", report.disabled_sinks),
        format!("configured_sinks: {}", report.configured_sinks),
        format!("missing_target_env: {}", report.missing_target_env),
        format!("missing_env_value: {}", report.missing_env_value),
    ];
    for sink in &report.sinks {
        lines.push(format!(
            "sink\t{}\t{}\t{}\tconfigured={}\ttarget_env={}",
            sink.id,
            sink.provider,
            sink.status,
            sink.configured,
            sink.target_env.as_deref().unwrap_or("-")
        ));
        lines.push(format!(
            "target_env_source: {}",
            sink.target_env_source.as_deref().unwrap_or("-")
        ));
        lines.push(format!("detail: {}", sink.detail));
    }
    for step in &report.activation_plan {
        lines.push(format!(
            "activation\t{}\t{}\tenv_present={}\t{}",
            step.sink_id, step.status, step.env_present, step.planned_command
        ));
        if let Some(test_command) = &step.test_command {
            lines.push(format!("test_command: {test_command}"));
        }
        for note in &step.notes {
            lines.push(format!("activation_note: {note}"));
        }
    }
    for action in &report.next_actions {
        lines.push(format!("next_action: {action}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize backup timer alert status report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn backup_timer_alert_enable_plan_report_output(
    report: backup_schedule::BackupTimerAlertEnablePlanReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!(
            "sink\t{}\t{}\t{}\ttarget_env={}",
            report.requested_sink.id,
            report.requested_sink.provider,
            report.requested_sink.status,
            report.requested_sink.target_env.as_deref().unwrap_or("-")
        ),
        format!("target_env_present: {}", report.target_env_present),
        format!(
            "target_env_source: {}",
            report.target_env_source.as_deref().unwrap_or("-")
        ),
        format!("secret_handling: {}", report.secret_handling),
        format!(
            "retry_policy: attempts={} planned={}",
            report.retry_policy.delivery_attempts, report.retry_policy.planned
        ),
        format!(
            "escalation: failures_before_block={} deploy_block_enabled={}",
            report
                .escalation_policy
                .consecutive_failures_before_deploy_block,
            report.escalation_policy.deploy_block_enabled
        ),
    ];
    for step in &report.steps {
        lines.push(format!(
            "step\t{}\t{}\tenv={}\tpresent={}",
            step.order,
            step.action,
            step.required_env.as_deref().unwrap_or("-"),
            step.env_present
                .map_or_else(|| "-".to_string(), |present| present.to_string())
        ));
        if let Some(command) = &step.command {
            lines.push(format!("command: {command}"));
        }
        lines.push(format!("detail: {}", step.detail));
    }
    for field in &report.alert_template.body_fields {
        lines.push(format!("template_body_field: {field}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize backup timer alert enable plan report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn backup_timer_alert_env_template_report_output(
    report: backup_schedule::BackupTimerAlertEnvTemplateReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!("env_file: {}", report.env_file),
        format!("sink_id: {}", report.sink_id),
        format!("provider: {}", report.provider),
        format!("target_env: {}", report.target_env),
        format!("target_env_present: {}", report.target_env_present),
        format!(
            "target_env_source: {}",
            report.target_env_source.as_deref().unwrap_or("-")
        ),
        format!("secret_handling: {}", report.secret_handling),
    ];
    for line in &report.template_lines {
        lines.push(format!("template: {line}"));
    }
    for command in &report.install_commands {
        lines.push(format!("install_command: {command}"));
    }
    for command in &report.next_commands {
        lines.push(format!("next_command: {command}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize backup timer alert env template report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn backup_timer_alert_configure_report_output(
    report: backup_schedule::BackupTimerAlertConfigureReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("read_only: {}", report.read_only),
        format!("action: {}", report.action),
        format!("target_env_present: {}", report.target_env_present),
        format!(
            "target_env_source: {}",
            report.target_env_source.as_deref().unwrap_or("-")
        ),
        format!(
            "sink\t{}\t{}\t{}\ttarget_env={}",
            report.sink.id,
            report.sink.provider,
            report.sink.status,
            report.sink.target_env.as_deref().unwrap_or("-")
        ),
    ];
    for file in &report.changed_files {
        lines.push(format!("changed_file: {file}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize backup timer alert configure report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.status == "configured" || report.status == "unchanged" {
            "allow"
        } else if report.status == "planned" {
            "require_approval"
        } else {
            "deny"
        },
        dry_run: !report.execute,
    })
}

fn backup_onboarding_check_command(
    paths: &RuntimePaths,
    import_dir: Option<&Path>,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = production_onboarding_check(&ProductionOnboardingOptions {
        registry: &registry,
        registry_dir: &paths.registry_dir,
        state_dir: &paths.state_dir,
        import_dir,
    });
    let mut lines = vec![
        format!("status: {}", if report.ok { "ready" } else { "blocked" }),
        format!("read_only: {}", report.read_only),
        format!("services_checked: {}", report.services_checked),
        format!("services_blocked: {}", report.services_blocked),
        format!("repositories_checked: {}", report.repositories_checked),
        format!("backup_history_status: {}", report.backup_history_status),
    ];
    if let Some(status) = &report.import_check_status {
        lines.push(format!("import_check_status: {status}"));
    }
    if let Some(status) = &report.promote_dry_run_status {
        lines.push(format!("promote_dry_run_status: {status}"));
    }
    for command in &report.planned_commands {
        lines.push(format!("planned_command: {command}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize production onboarding report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn backup_repository_init_command(
    paths: &RuntimePaths,
    repository_id: &str,
    execute: bool,
    approval_token: Option<&str>,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = backup_repository_init(&BackupRepositoryInitOptions {
        registry: &registry,
        repository_id,
        execute,
        approval_token,
    })?;
    repository_action_output(report, !execute)
}

struct BackupS3SmokeCommandInput<'a> {
    endpoint: &'a str,
    region: &'a str,
    provider: &'a str,
    bucket: &'a str,
    prefix: Option<&'a str>,
    access_key_env: &'a str,
    secret_key_env: &'a str,
    execute: bool,
}

fn backup_s3_smoke_command(input: BackupS3SmokeCommandInput<'_>) -> Result<CommandOutput> {
    let report = backup_s3_smoke(&BackupS3SmokeOptions {
        endpoint: input.endpoint,
        region: input.region,
        provider: input.provider,
        bucket: input.bucket,
        prefix: input.prefix,
        access_key_env: input.access_key_env,
        secret_key_env: input.secret_key_env,
        execute: input.execute,
    })?;
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("tool: {}", report.tool),
        format!("endpoint: {}", report.endpoint),
        format!("region: {}", report.region),
        format!("provider: {}", report.provider),
        format!("bucket: {}", report.bucket),
        format!("prefix: {}", report.prefix),
        format!("object_key: {}", report.object_key),
    ];
    if let Some(hash) = &report.payload_sha256 {
        lines.push(format!("payload_sha256: {hash}"));
    }
    if !report.required_env.is_empty() {
        lines.push(format!("required_env: {}", report.required_env.join(", ")));
    }
    if !report.missing_env.is_empty() {
        lines.push(format!("missing_env: {}", report.missing_env.join(", ")));
    }
    for operation in &report.operations {
        lines.push(format!(
            "{}\t{}\t{}",
            operation.order, operation.kind, operation.status
        ));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize S3 smoke report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: !input.execute,
    })
}

fn backup_restore_report_output(
    report: backup::BackupRestoreReport,
    dry_run: bool,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("service: {}", report.service_id),
        format!("target: {}", report.target_id),
        format!("repository: {}", report.repository_id),
        format!("provider: {}", report.provider),
        format!("snapshot: {}", report.repository_snapshot_id),
        format!("restore_dir: {}", report.restore_dir),
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
    ];
    if let Some(token) = &report.expected_approval_token {
        lines.push(format!("approval_token: {token}"));
    }
    if let Some(verification) = &report.verification {
        lines.push(format!("files_checked: {}", verification.files_checked));
        lines.push(format!("bytes_checked: {}", verification.bytes_checked));
        lines.push(format!(
            "database_dump_checks: {}",
            verification.database_dump_checks.len()
        ));
    }
    if let Some(record) = &report.restore_drill_record {
        lines.push(format!("restore_drill: {}", record.id));
    }
    for operation in &report.operations {
        lines.push(format!(
            "{}\t{}\t{}",
            operation.order, operation.kind, operation.status
        ));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize backup restore report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run,
    })
}

fn backup_repository_check_command(
    paths: &RuntimePaths,
    repository_id: &str,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = backup_repository_check(&BackupRepositoryActionOptions {
        registry: &registry,
        registry_dir: Some(&paths.registry_dir),
        repository_id,
        service_id: None,
        approval_token: None,
    })?;
    repository_action_output(report, false)
}

fn backup_repository_prune_command(
    paths: &RuntimePaths,
    repository_id: &str,
    service_id: Option<&str>,
    approval_token: Option<&str>,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = backup_repository_prune(&BackupRepositoryActionOptions {
        registry: &registry,
        registry_dir: None,
        repository_id,
        service_id,
        approval_token,
    })?;
    repository_action_output(report, false)
}

fn repository_action_output(
    report: backup::BackupRepositoryActionReport,
    dry_run: bool,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("repository: {}", report.repository_id),
        format!("provider: {}", report.provider),
        format!("status: {}", report.status),
    ];
    if let Some(service_id) = &report.service_id {
        lines.push(format!("service: {service_id}"));
    }
    if let Some(token) = &report.expected_approval_token {
        lines.push(format!("approval_token: {token}"));
    }
    if let Some(record) = &report.repository_check_record {
        lines.push(format!("repository_check: {}", record.id));
    }
    for operation in &report.operations {
        lines.push(format!(
            "{}\t{}\t{}",
            operation.order, operation.kind, operation.status
        ));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize backup repository action report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run,
    })
}

fn deploy_gates_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = deploy_gates(&registry, &paths.state_dir)?;
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("read_only: {}", report.read_only),
        format!("dry_run: {}", report.dry_run),
        format!("services_checked: {}", report.services_checked),
        format!("services_ready: {}", report.services_ready),
        format!("services_blocked: {}", report.services_blocked),
        format!(
            "backup_readiness: {} ({} blocked)",
            report.backup_readiness_status, report.backup_readiness_blocked
        ),
        format!(
            "backup_history: {} ({} blocked)",
            report.backup_history_status, report.backup_history_blocked
        ),
        format!(
            "snapshot_coverage: {} ({} blocked)",
            report.snapshot_coverage_status, report.snapshot_coverage_blocked
        ),
    ];
    for service in &report.services {
        lines.push(format!(
            "service\t{}\t{}\tgates=[{}]",
            service.service_id,
            service.status,
            service.blocked_gates.join(",")
        ));
        if let Some(reason) = service.blocked_reason.as_deref() {
            lines.push(format!(
                "blocked_reason\t{}\t{}",
                service.service_id, reason
            ));
        }
        for detail in &service.blocked_details {
            lines.push(format!(
                "blocked_detail\t{}\t{}",
                service.service_id, detail
            ));
        }
        for command in &service.remediation_commands {
            lines.push(format!("remediation\t{}\t{}", service.service_id, command));
        }
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize deploy gates report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn registry_schemas_command() -> Result<CommandOutput> {
    let schemas = list_schemas()?;
    let mut lines = vec!["NAME\tFILE\tTITLE".to_string()];
    for schema in &schemas {
        lines.push(format!(
            "{}\t{}\t{}",
            schema.name,
            schema.file_name,
            schema.title.as_deref().unwrap_or("-")
        ));
    }

    Ok(CommandOutput {
        json: json!({ "schemas": schemas }),
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: "allow",
        dry_run: false,
    })
}

fn registry_export_schema_command(name: &str) -> Result<CommandOutput> {
    let schema = schema_by_name(name)?;
    let schema_json = schema_as_json(name)?;

    Ok(CommandOutput {
        json: json!({
            "name": schema.name,
            "file_name": schema.file_name,
            "schema": schema_json,
        }),
        text: schema.raw_yaml.to_string(),
        exit_code: 0,
        audit_decision: "allow",
        dry_run: false,
    })
}

fn status_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let doctor_report = DoctorReport::from_registry(&registry);
    let backup = backup_readiness(&registry);
    let backup_history_report = backup_history(&registry);
    let snapshot_coverage_report = snapshot_coverage(&registry, &paths.state_dir)?;
    let timer_health_report = timer_health(&registry);
    let deploy_gate_report = deploy_gates_from_reports(
        &backup,
        &backup_history_report,
        &snapshot_coverage_report,
        &timer_health_report,
    );

    let summary = StatusSummary {
        registry_dir: display_path(&paths.registry_dir),
        state_db: display_path(&paths.state_db),
        audit_log: display_path(&paths.audit_log),
        services: registry.services.services.len(),
        ports: registry.ports.ports.len(),
        domains: registry.domains.domains.len(),
        volumes: registry.volumes.volumes.len(),
        snapshots: registry.snapshots.snapshots.len(),
        doctor_errors: doctor_report.errors,
        doctor_warnings: doctor_report.warnings,
        deploy_gates_status: deploy_gate_report.status,
        deploy_gates_read_only: deploy_gate_report.read_only,
        deploy_gates_dry_run: deploy_gate_report.dry_run,
        deploy_gates_services_checked: deploy_gate_report.services_checked,
        deploy_gates_services_ready: deploy_gate_report.services_ready,
        deploy_gates_services_blocked: deploy_gate_report.services_blocked,
        backup_readiness_status: backup.status,
        backup_readiness_dry_run: backup.dry_run,
        backup_services_checked: backup.services_checked,
        backup_ready: backup.ready,
        backup_blocked: backup.blocked,
        backup_missing_env: backup.missing_env.len(),
        backup_history_status: backup_history_report.status,
        backup_history_read_only: backup_history_report.read_only,
        backup_history_records: backup_history_report.records,
        backup_history_services_missing_success: backup_history_report.services_missing_success,
        backup_history_stale_targets: backup_history_report.stale_targets,
        backup_history_future_records: backup_history_report.future_records,
        backup_history_invalid_timestamps: backup_history_report.invalid_timestamps,
        snapshot_coverage_status: snapshot_coverage_report.status,
        snapshot_coverage_read_only: snapshot_coverage_report.read_only,
        snapshot_coverage_services_checked: snapshot_coverage_report.services_checked,
        snapshot_coverage_services_blocked: snapshot_coverage_report.services_blocked,
        snapshot_coverage_missing_snapshot: snapshot_coverage_report.services_missing_snapshot,
        snapshot_coverage_missing_required_scope: snapshot_coverage_report
            .services_missing_required_scope,
        snapshot_coverage_with_limitations: snapshot_coverage_report.services_with_limitations,
    };

    let text = format!(
        "registry: {}\nstate db: {}\naudit log: {}\nservices: {}\nports: {}\ndomains: {}\nvolumes: {}\nsnapshots: {}\ndoctor: {} error(s), {} warning(s)\ndeploy_gates: {} ({} checked, {} ready, {} blocked, dry_run={})\nbackup_readiness: {} ({} checked, {} ready, {} blocked, {} missing env)\nbackup_history: {} ({} record(s), {} service(s) missing success, {} stale target(s), {} future record(s), {} invalid timestamp(s))\nsnapshot_coverage: {} ({} checked, {} blocked, {} missing snapshot, {} missing scope, {} with limitations)",
        summary.registry_dir,
        summary.state_db,
        summary.audit_log,
        summary.services,
        summary.ports,
        summary.domains,
        summary.volumes,
        summary.snapshots,
        summary.doctor_errors,
        summary.doctor_warnings,
        summary.deploy_gates_status,
        summary.deploy_gates_services_checked,
        summary.deploy_gates_services_ready,
        summary.deploy_gates_services_blocked,
        summary.deploy_gates_dry_run,
        summary.backup_readiness_status,
        summary.backup_services_checked,
        summary.backup_ready,
        summary.backup_blocked,
        summary.backup_missing_env,
        summary.backup_history_status,
        summary.backup_history_records,
        summary.backup_history_services_missing_success,
        summary.backup_history_stale_targets,
        summary.backup_history_future_records,
        summary.backup_history_invalid_timestamps,
        summary.snapshot_coverage_status,
        summary.snapshot_coverage_services_checked,
        summary.snapshot_coverage_services_blocked,
        summary.snapshot_coverage_missing_snapshot,
        summary.snapshot_coverage_missing_required_scope,
        summary.snapshot_coverage_with_limitations,
    );

    let gates_ok = summary.deploy_gates_status == "ready"
        && summary.backup_readiness_status == "ready"
        && summary.backup_history_status == "ready"
        && summary.snapshot_coverage_status == "ready";

    Ok(CommandOutput {
        json: serde_json::to_value(summary).context("failed to serialize status summary")?,
        text,
        exit_code: if doctor_report.errors > 0 { 1 } else { 0 },
        audit_decision: if doctor_report.errors > 0 || !gates_ok {
            "deny"
        } else {
            "allow"
        },
        dry_run: false,
    })
}

fn services_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let services = registry.services.services;
    let mut lines = Vec::with_capacity(services.len() + 1);
    lines.push("ID\tENV\tSTATUS\tKIND\tNAME".to_string());
    for service in &services {
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}",
            service.id, service.environment, service.status, service.kind, service.name
        ));
    }

    Ok(CommandOutput {
        json: json!({ "services": services }),
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: "allow",
        dry_run: false,
    })
}

fn ports_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let ports = registry.ports.ports;
    let mut lines = Vec::with_capacity(ports.len() + 1);
    lines.push("PORT\tPROTO\tBIND\tEXPOSURE\tSERVICE\tPURPOSE".to_string());
    for port in &ports {
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            port.port,
            port.protocol,
            port.bind,
            port.exposure,
            port.service_id,
            port.purpose.as_deref().unwrap_or("")
        ));
    }

    Ok(CommandOutput {
        json: json!({ "ports": ports }),
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: "allow",
        dry_run: false,
    })
}

fn doctor_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = DoctorReport::from_registry(&registry);
    let mut lines = Vec::new();

    if report.findings.is_empty() {
        lines.push("doctor: ok".to_string());
    } else {
        lines.push(format!(
            "doctor: {} error(s), {} warning(s)",
            report.errors, report.warnings
        ));
        for finding in &report.findings {
            let target = finding.target.as_deref().unwrap_or("-");
            lines.push(format!(
                "{:?}\t{}\t{}\t{}",
                finding.severity, finding.code, target, finding.message
            ));
        }
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize doctor report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: false,
    })
}

fn scan_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let report = scan_server(&registry);
    let mut lines = vec![
        format!("scan: {}", report.registry_dir),
        format!("observed ports: {}", report.detected.ports.len()),
        format!("registered ports: {}", report.registered.ports.len()),
        format!(
            "docker: {} container(s), {} volume(s), {} compose project(s)",
            report.detected.docker.containers.len(),
            report.detected.docker.volumes.len(),
            report.detected.docker.compose_projects.len()
        ),
        format!("caddy labels: {}", report.detected.caddy.site_labels.len()),
        format!(
            "systemd running units: {}",
            report.detected.systemd.running_units.len()
        ),
        format!("findings: {}", report.findings.len()),
    ];

    for finding in &report.findings {
        lines.push(format!(
            "{}\t{}\t{}",
            finding.severity, finding.code, finding.message
        ));
    }
    for note in &report.visibility {
        lines.push(format!(
            "visibility\t{}\t{}\t{}",
            note.source, note.status, note.message
        ));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize scan report")?,
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: "allow",
        dry_run: false,
    })
}

fn caddy_routes_command(adapt: bool, admin: bool) -> Result<CommandOutput> {
    let report = inspect_caddy_routes(adapt, admin)?;
    let mut lines = vec![
        format!("caddyfile: {}", report.caddyfile),
        format!("exists: {}", report.exists),
        format!("managed_routes: {}", report.managed_routes.len()),
        format!("unmanaged_hosts: {}", report.unmanaged_hosts.len()),
        format!("management_status: {}", report.management.status),
        format!(
            "admin_api_write_supported: {}",
            report.management.admin_api_write_supported
        ),
    ];
    if let Some(adapt) = &report.adapt {
        lines.push(format!("adapt_ok: {}", adapt.ok));
        lines.push(format!("adapt_routes: {}", adapt.route_count));
        lines.push(format!(
            "adapt_hosts: {}",
            if adapt.normalized_hosts.is_empty() {
                "-".to_string()
            } else {
                adapt.normalized_hosts.join(",")
            }
        ));
    }
    if let Some(admin) = &report.admin {
        lines.push(format!("admin_ok: {}", admin.ok));
        lines.push(format!("admin_routes: {}", admin.route_count));
    }
    for route in &report.managed_routes {
        lines.push(format!(
            "managed\t{}\t{}",
            route.host,
            route.upstream.as_deref().unwrap_or("-")
        ));
    }
    for host in &report.unmanaged_hosts {
        lines.push(format!("unmanaged\t{host}"));
    }
    for finding in &report.findings {
        lines.push(format!("finding\t{finding}"));
    }
    for action in &report.management.recommended_next_actions {
        lines.push(format!("management_next: {action}"));
    }
    let has_issues = !report.findings.is_empty()
        || report.adapt.as_ref().is_some_and(|adapt| !adapt.ok)
        || report.admin.as_ref().is_some_and(|admin| !admin.ok);

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize Caddy routes report")?,
        text: lines.join("\n"),
        exit_code: if has_issues { 1 } else { 0 },
        audit_decision: if has_issues { "warn" } else { "allow" },
        dry_run: false,
    })
}

fn analyze_command(project: &std::path::Path) -> Result<CommandOutput> {
    let report = analyze_project(project)?;
    let high_risk = report.risk_hints.iter().any(|hint| hint.severity == "high");
    let mut lines = vec![
        format!("project: {}", report.project_root),
        format!("types: {}", join_or_dash(&report.detected.project_types)),
        format!(
            "package managers: {}",
            join_or_dash(&report.detected.package_managers)
        ),
        format!(
            "likely ports: {}",
            join_ports_or_dash(&report.detected.likely_ports)
        ),
        format!("compose files: {}", report.detected.compose_files.len()),
        format!("dockerfiles: {}", report.detected.dockerfiles.len()),
        format!("env files: {}", report.detected.env_files.len()),
        format!("risk hints: {}", report.risk_hints.len()),
    ];

    for hint in &report.risk_hints {
        lines.push(format!(
            "{}\t{}\t{}",
            hint.severity, hint.code, hint.message
        ));
    }
    for note in &report.visibility {
        lines.push(format!(
            "visibility\t{}\t{}\t{}",
            note.source, note.status, note.message
        ));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize analyze report")?,
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: if high_risk { "deny" } else { "allow" },
        dry_run: false,
    })
}

fn plan_command(
    project: &Path,
    domain: Option<&str>,
    ports: &[u16],
    environment: &str,
    id: Option<&str>,
    actor: &str,
) -> Result<CommandOutput> {
    let plan = draft_deploy_plan(&DraftPlanOptions {
        actor,
        project,
        domain,
        ports,
        environment,
        id,
    })?;
    let text = plan_as_yaml(&plan)?;

    Ok(CommandOutput {
        json: serde_json::to_value(&plan).context("failed to serialize draft deploy plan")?,
        text,
        exit_code: 0,
        audit_decision: "allow",
        dry_run: true,
    })
}

fn preflight_command(
    paths: &RuntimePaths,
    plan_path: &Path,
    explain_only: bool,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let plan = load_deploy_plan(plan_path)?;
    let report = evaluate_preflight(&plan, &registry);
    let status = report.status;
    let mut lines = vec![
        format!("plan: {}", report.plan_id),
        format!("status: {:?}", report.status),
        format!(
            "summary: {} blocked, {} needs approval, {} warning(s), {} info",
            report.summary.blocked,
            report.summary.needs_approval,
            report.summary.warnings,
            report.summary.info
        ),
    ];
    for finding in &report.findings {
        let target = finding.target.as_deref().unwrap_or("-");
        lines.push(format!(
            "{:?}\t{}\t{}\t{}",
            finding.severity, finding.code, target, finding.message
        ));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize preflight report")?,
        text: lines.join("\n"),
        exit_code: if explain_only {
            0
        } else {
            preflight_exit_code(status)
        },
        audit_decision: if explain_only {
            "allow"
        } else {
            decision_for_status(status)
        },
        dry_run: true,
    })
}

fn snapshot_command(
    paths: &RuntimePaths,
    plan_path: &Path,
    dry_run: bool,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let plan = load_deploy_plan(plan_path)?;
    let report = create_snapshot(&SnapshotOptions {
        state_dir: &paths.state_dir,
        registry: &registry,
        plan: &plan,
        dry_run,
    })?;
    let mut lines = vec![
        format!("snapshot: {}", report.id),
        format!("status: {}", report.status),
        format!("root: {}", report.root),
        format!("manifest: {}", report.manifest_path),
        format!("rollback: {}", report.rollback_plan_path),
    ];
    for limitation in &report.manifest.limitations {
        lines.push(format!("limitation: {limitation}"));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize snapshot report")?,
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: if dry_run { "deny" } else { "allow" },
        dry_run,
    })
}

fn snapshots_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let report = list_snapshots(&paths.state_dir)?;
    let mut lines = vec![format!("snapshots: {}", report.snapshots.len())];
    for snapshot in &report.snapshots {
        lines.push(format!(
            "{}\t{}\t{}\t{}",
            snapshot.id, snapshot.status, snapshot.created_at, snapshot.plan_id
        ));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize snapshot list")?,
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: "allow",
        dry_run: false,
    })
}

fn snapshot_inspect_command(paths: &RuntimePaths, snapshot_id: &str) -> Result<CommandOutput> {
    let report = inspect_snapshot_report(&paths.state_dir, snapshot_id)?;
    let mut lines = vec![
        format!("snapshot: {}", report.snapshot_id),
        format!("status: {}", report.status),
        format!("manifest_status: {}", report.manifest.status),
        format!("root: {}", report.snapshot_root),
        format!("manifest: {}", report.manifest_path),
        format!("rollback: {}", report.rollback_plan_path),
        format!(
            "rollback_plan_available: {}",
            report.rollback_plan_available
        ),
        format!("scope: {}", join_or_dash(&report.manifest.scope)),
        format!("limitations: {}", report.manifest.limitations.len()),
    ];
    for limitation in &report.manifest.limitations {
        lines.push(format!("limitation: {limitation}"));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize snapshot inspect report")?,
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: "allow",
        dry_run: false,
    })
}

fn snapshot_verify_command(paths: &RuntimePaths, snapshot_id: &str) -> Result<CommandOutput> {
    let report = verify_snapshot_report(&paths.state_dir, snapshot_id)?;
    let mut lines = vec![
        format!("snapshot: {}", report.snapshot_id),
        format!("status: {}", report.status),
        format!("artifacts_checked: {}", report.artifacts_checked),
        format!("artifacts_verified: {}", report.artifacts_verified),
        format!("artifacts_failed: {}", report.artifacts_failed),
        format!(
            "artifacts_missing_checksum: {}",
            report.artifacts_missing_checksum
        ),
        format!("root: {}", report.snapshot_root),
        format!("manifest: {}", report.manifest_path),
    ];
    for finding in &report.findings {
        lines.push(format!(
            "finding\t{}\t{}\t{}",
            finding.artifact, finding.status, finding.message
        ));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize snapshot verify report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: false,
    })
}

fn snapshot_archive_inspect_command(
    paths: &RuntimePaths,
    snapshot_id: &str,
) -> Result<CommandOutput> {
    let report = inspect_snapshot_archive_report(&paths.state_dir, snapshot_id)?;
    let mut lines = vec![
        format!("snapshot: {}", report.snapshot_id),
        format!("status: {}", report.status),
        format!("artifact: {}", report.artifact),
        format!("checksum_status: {}", report.checksum_status),
        format!("entries_checked: {}", report.entries_checked),
        format!("regular_files: {}", report.regular_files),
        format!("directories: {}", report.directories),
        format!("unsupported_entries: {}", report.unsupported_entries),
        format!("total_unpacked_bytes: {}", report.total_unpacked_bytes),
    ];
    if let Some(archive_path) = &report.archive_path {
        lines.push(format!("archive: {archive_path}"));
    }
    for finding in &report.findings {
        lines.push(format!(
            "finding\t{}\t{}\t{}",
            finding.path.as_deref().unwrap_or("-"),
            finding.status,
            finding.message
        ));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize snapshot archive inspect report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: false,
    })
}

fn snapshot_volume_archive_inspect_command(
    paths: &RuntimePaths,
    snapshot_id: &str,
) -> Result<CommandOutput> {
    let report = inspect_snapshot_volume_archives_report(&paths.state_dir, snapshot_id)?;
    let mut lines = vec![
        format!("snapshot: {}", report.snapshot_id),
        format!("status: {}", report.status),
        format!("archives_checked: {}", report.archives_checked),
    ];
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }
    for archive in &report.archives {
        lines.push(format!(
            "archive\t{}\t{}\t{} entries",
            archive.artifact, archive.status, archive.entries_checked
        ));
        for finding in &archive.findings {
            lines.push(format!(
                "finding\t{}\t{}\t{}",
                finding.path.as_deref().unwrap_or("-"),
                finding.status,
                finding.message
            ));
        }
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize snapshot volume archive inspect report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: false,
    })
}

fn snapshot_coverage_command(
    paths: &RuntimePaths,
    register_baseline: bool,
    service_ids: &[String],
    reason: Option<&str>,
    execute: bool,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    if !register_baseline {
        if !service_ids.is_empty() || reason.is_some() || execute {
            anyhow::bail!("snapshot-coverage baseline flags require --register-baseline");
        }
        return snapshot_coverage_report_output(snapshot_coverage(&registry, &paths.state_dir)?);
    }
    let report = register_snapshot_baseline(&SnapshotBaselineOptions {
        registry: &registry,
        registry_dir: &paths.registry_dir,
        state_dir: &paths.state_dir,
        service_ids,
        reason,
        execute,
    })?;
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("execute: {}", report.execute),
        format!("services_checked: {}", report.services_checked),
        format!("planned: {}", report.planned),
        format!("registered: {}", report.registered),
        format!("skipped: {}", report.skipped),
        format!("blocked: {}", report.blocked),
    ];
    for record in &report.records {
        lines.push(format!(
            "service\t{}\t{}\tsnapshot={}",
            record.service_id,
            record.status,
            record.snapshot_id.as_deref().unwrap_or("-")
        ));
        for evidence in &record.evidence {
            lines.push(format!("evidence: {evidence}"));
        }
        for limitation in &record.limitations {
            lines.push(format!("limitation: {limitation}"));
        }
    }
    for changed_file in &report.changed_files {
        lines.push(format!("changed_file: {changed_file}"));
    }
    for limitation in &report.limitations {
        lines.push(format!("limitation: {limitation}"));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize snapshot baseline report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok {
            if report.execute {
                "allow"
            } else {
                "require_approval"
            }
        } else {
            "deny"
        },
        dry_run: !report.execute,
    })
}

fn snapshot_coverage_report_output(
    report: snapshot::SnapshotCoverageReport,
) -> Result<CommandOutput> {
    let mut lines = vec![
        format!("status: {}", report.status),
        format!("services_checked: {}", report.services_checked),
        format!("services_ready: {}", report.services_ready),
        format!("services_blocked: {}", report.services_blocked),
        format!("registered_snapshots: {}", report.registered_snapshots),
        format!("local_snapshots: {}", report.local_snapshots),
    ];
    for service in &report.services {
        lines.push(format!(
            "service\t{}\t{}\t{} snapshot(s)",
            service.service_id, service.status, service.snapshot_count
        ));
        if let Some(snapshot_id) = &service.latest_snapshot_id {
            lines.push(format!(
                "latest\t{}\t{}\t{}",
                service.service_id,
                snapshot_id,
                service.latest_status.as_deref().unwrap_or("-")
            ));
        }
        for scope in &service.missing_scope {
            lines.push(format!("missing_scope\t{}\t{}", service.service_id, scope));
        }
        for limitation in &service.limitations {
            lines.push(format!(
                "limitation\t{}\t{}",
                service.service_id, limitation
            ));
        }
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize snapshot coverage report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: false,
    })
}

struct RollbackCommandOptions<'a> {
    snapshot_id: &'a str,
    dry_run: bool,
    stage_dir: Option<&'a Path>,
    restore: bool,
    restore_config: bool,
    restore_data: bool,
    approval_token: Option<&'a str>,
}

fn rollback_command(
    paths: &RuntimePaths,
    options: RollbackCommandOptions<'_>,
) -> Result<CommandOutput> {
    if let Some(stage_dir) = options.stage_dir {
        if options.dry_run || options.restore || options.restore_config || options.restore_data {
            anyhow::bail!(
                "--stage-dir cannot be combined with --dry-run, --restore, --restore-config, or --restore-data"
            );
        }
        let report = rollback_stage(&paths.state_dir, options.snapshot_id, stage_dir)?;
        let mut lines = vec![
            format!("snapshot: {}", report.snapshot_id),
            format!("status: {}", report.status),
            format!("stage_dir: {}", report.stage_dir),
            format!("registry_stage_dir: {}", report.registry_stage_dir),
            format!("files_staged: {}", report.files_staged),
            format!("directories_staged: {}", report.directories_staged),
        ];
        for limitation in &report.limitations {
            lines.push(format!("limitation: {limitation}"));
        }
        return Ok(CommandOutput {
            json: serde_json::to_value(&report)
                .context("failed to serialize rollback stage report")?,
            text: lines.join("\n"),
            exit_code: 0,
            audit_decision: "require_approval",
            dry_run: false,
        });
    }
    if (options.restore_config || options.restore_data) && !options.restore {
        anyhow::bail!("--restore-config and --restore-data require --restore");
    }
    if options.restore {
        if options.dry_run {
            anyhow::bail!("--restore cannot be combined with --dry-run");
        }
        let Some(approval_token) = options.approval_token else {
            anyhow::bail!("--restore requires --approval-token from rollback --dry-run");
        };
        let report = rollback_restore(
            &paths.state_dir,
            &paths.registry_dir,
            options.snapshot_id,
            approval_token,
            options.restore_config,
            options.restore_data,
        )?;
        let mut lines = vec![
            format!("snapshot: {}", report.snapshot_id),
            format!("status: {}", report.status),
            format!("staging_dir: {}", report.staging_dir),
            format!("backup_dir: {}", report.backup_dir),
            format!("registry_restored: {}", report.registry_restored),
            format!("caddy_config_restored: {}", report.caddy_config_restored),
            format!(
                "volume_archives_restored: {}",
                report.volume_archives_restored
            ),
        ];
        for limitation in &report.limitations {
            lines.push(format!("limitation: {limitation}"));
        }
        return Ok(CommandOutput {
            json: serde_json::to_value(&report)
                .context("failed to serialize rollback restore report")?,
            text: lines.join("\n"),
            exit_code: if report.registry_restored { 0 } else { 1 },
            audit_decision: if report.ok { "allow" } else { "warn" },
            dry_run: false,
        });
    }
    if !options.dry_run {
        anyhow::bail!("rollback requires --dry-run, --stage-dir, or --restore --approval-token");
    }
    let report = rollback_dry_run_with_registry(
        &paths.state_dir,
        options.snapshot_id,
        Some(&paths.registry_dir),
    )?;
    let mut lines = vec![
        format!("snapshot: {}", report.snapshot_id),
        format!("status: {}", report.status),
        format!("can_restore: {}", report.can_restore),
        format!("approval_token: {}", report.approval_token),
        format!("manifest: {}", report.manifest_path),
        format!("rollback: {}", report.rollback_plan_path),
    ];
    for conflict in &report.conflicts {
        lines.push(format!("conflict\t{}\t{}", conflict.path, conflict.message));
    }
    for step in &report.rollback_plan.steps {
        lines.push(format!("{}\t{}\t{}", step.order, step.action, step.detail));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize rollback dry-run report")?,
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: "allow",
        dry_run: true,
    })
}

fn deploy_command(
    paths: &RuntimePaths,
    plan_path: &Path,
    dry_run: bool,
    execute: bool,
    snapshot_id: Option<&str>,
    approval_token: Option<&str>,
) -> Result<CommandOutput> {
    if dry_run && execute {
        anyhow::bail!("deploy --dry-run cannot be combined with --execute");
    }
    if !dry_run && !execute {
        ensure_dry_run(dry_run)?;
    }
    let registry = Registry::load(&paths.registry_dir)?;
    let approvals = list_approvals(&paths.registry_dir)?.approvals;
    let plan = load_deploy_plan(plan_path)?;
    let report = if execute {
        let Some(approval_token) = approval_token else {
            anyhow::bail!("deploy --execute requires --approval-token from deploy --dry-run");
        };
        execute_deploy(&DeployExecutionOptions {
            state_dir: &paths.state_dir,
            registry_dir: &paths.registry_dir,
            registry: &registry,
            plan: &plan,
            snapshot_id,
            approvals: &approvals,
            approval_token,
            operation_order: None,
        })?
    } else {
        plan_deploy(&DeployOptions {
            state_dir: &paths.state_dir,
            registry: &registry,
            plan: &plan,
            dry_run,
            snapshot_id,
            approvals: &approvals,
        })?
    };
    let status = report.status;

    Ok(CommandOutput {
        json: serialize_report(&report)?,
        text: report_text(&report),
        exit_code: deploy_exit_code(status),
        audit_decision: deploy_decision(status),
        dry_run: !execute,
    })
}

fn request_deploy_execution_command(
    paths: &RuntimePaths,
    plan_path: &Path,
    snapshot_id: Option<&str>,
    reason: &str,
    expires_at: Option<&str>,
    actor: &str,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let approvals = list_approvals(&paths.registry_dir)?.approvals;
    let plan = load_deploy_plan(plan_path)?;
    let report = plan_deploy(&DeployOptions {
        state_dir: &paths.state_dir,
        registry: &registry,
        plan: &plan,
        dry_run: true,
        snapshot_id,
        approvals: &approvals,
    })?;
    if report.status != deploy::DeployStatus::Ready {
        anyhow::bail!(
            "deploy execution approval can only be requested after deploy dry-run is ready"
        );
    }

    let execution_token = expected_deploy_approval_token(&plan, snapshot_id);
    let scope = vec!["deploy_execution".to_string()];
    let constraints = vec![
        format!("plan_id={}", plan.id),
        format!("execution_approval_token={execution_token}"),
        "execution must use opsctl deploy --execute or opsctl helper run-deploy-operation"
            .to_string(),
    ];
    let approval = request_approval(&ApprovalRequestOptions {
        registry_root: &paths.registry_dir,
        plan_id: &plan.id,
        requested_by: actor,
        reason,
        scope: &scope,
        constraints: &constraints,
        expires_at,
    })?;

    let payload = json!({
        "decision": "require_approval",
        "approval": approval.clone(),
        "deploy": report,
        "execution_approval_token": execution_token,
        "next_step": "Review the request, approve it with opsctl approve or TUI, then run opsctl deploy --execute."
    });
    Ok(CommandOutput {
        json: payload,
        text: format!(
            "approval: {}\nplan: {}\nstatus: {}\nexecution_approval_token: {}\nnext: approve the request, then run deploy --execute",
            approval.id, approval.plan_id, approval.status, execution_token
        ),
        exit_code: 0,
        audit_decision: "require_approval",
        dry_run: false,
    })
}

fn request_deploy_resume_command(
    paths: &RuntimePaths,
    plan_path: &Path,
    journal_id: &str,
    reason: &str,
    expires_at: Option<&str>,
    actor: &str,
) -> Result<CommandOutput> {
    let plan = load_deploy_plan(plan_path)?;
    let report = resume_deploy_journal(&paths.state_dir, journal_id, &plan)?;
    if !report.can_resume {
        anyhow::bail!("deploy resume approval can only be requested for a resumable journal");
    }

    let resume_token = expected_deploy_resume_approval_token(&plan, journal_id);
    let scope = vec![expected_deploy_resume_approval_scope(journal_id)];
    let constraints = vec![
        format!("plan_id={}", plan.id),
        format!("journal_id={journal_id}"),
        format!("resume_approval_token={resume_token}"),
        "execution must use opsctl deploy-resume --execute".to_string(),
    ];
    let approval = request_approval(&ApprovalRequestOptions {
        registry_root: &paths.registry_dir,
        plan_id: &plan.id,
        requested_by: actor,
        reason,
        scope: &scope,
        constraints: &constraints,
        expires_at,
    })?;

    let payload = json!({
        "decision": "require_approval",
        "approval": approval.clone(),
        "resume": report,
        "resume_approval_token": resume_token,
        "next_step": "Review the failed journal, approve this request, then run opsctl deploy-resume --execute."
    });
    Ok(CommandOutput {
        json: payload,
        text: format!(
            "approval: {}\nplan: {}\nstatus: {}\nresume_approval_token: {}\nnext: approve the request, then run deploy-resume --execute",
            approval.id, approval.plan_id, approval.status, resume_token
        ),
        exit_code: 0,
        audit_decision: "require_approval",
        dry_run: false,
    })
}

fn deploy_journals_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let report = list_deploy_journals(&paths.state_dir)?;
    let mut lines = vec![
        format!("journals_dir: {}", report.journals_dir),
        format!("journals: {}", report.journals.len()),
    ];
    for journal in &report.journals {
        lines.push(format!(
            "{}\t{}\t{}\t{} ok / {} failed",
            journal.journal_id,
            journal.plan_id,
            journal.status,
            journal.operations_succeeded,
            journal.operations_failed
        ));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize deploy journal list")?,
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: "allow",
        dry_run: false,
    })
}

fn deploy_journal_inspect_command(paths: &RuntimePaths, journal_id: &str) -> Result<CommandOutput> {
    let report = inspect_deploy_journal(&paths.state_dir, journal_id)?;
    let mut lines = vec![
        format!("journal: {}", report.journal_id),
        format!("status: {}", report.journal.status),
        format!("plan: {}", report.journal.plan_id),
        format!("path: {}", report.path),
        format!("operations: {}", report.journal.operations_total),
        format!("succeeded: {}", report.journal.operations_succeeded),
        format!("failed: {}", report.journal.operations_failed),
        format!("registry_updated: {}", report.journal.registry_updated),
    ];
    for result in &report.journal.results {
        lines.push(format!(
            "{}\t{}\t{}\t{}",
            result.order, result.kind, result.target, result.status
        ));
    }
    Ok(CommandOutput {
        json: serde_json::to_value(&report)
            .context("failed to serialize deploy journal inspect report")?,
        text: lines.join("\n"),
        exit_code: if report.journal.status == "failed" {
            1
        } else {
            0
        },
        audit_decision: if report.journal.status == "failed" {
            "warn"
        } else {
            "allow"
        },
        dry_run: false,
    })
}

fn deploy_resume_command(
    paths: &RuntimePaths,
    plan_path: &Path,
    journal_id: &str,
    dry_run: bool,
    execute: bool,
    approval_token: Option<&str>,
) -> Result<CommandOutput> {
    if dry_run && execute {
        anyhow::bail!("deploy-resume --dry-run cannot be combined with --execute");
    }
    if !dry_run && !execute {
        anyhow::bail!("deploy-resume requires --dry-run or --execute");
    }
    let plan = load_deploy_plan(plan_path)?;
    let report = if execute {
        let Some(approval_token) = approval_token else {
            anyhow::bail!(
                "deploy-resume --execute requires --approval-token from deploy-resume --dry-run"
            );
        };
        let registry = Registry::load(&paths.registry_dir)?;
        let approvals = list_approvals(&paths.registry_dir)?.approvals;
        execute_deploy_resume(&DeployResumeExecutionOptions {
            state_dir: &paths.state_dir,
            registry_dir: &paths.registry_dir,
            registry: &registry,
            plan: &plan,
            journal_id,
            approvals: &approvals,
            approval_token,
        })?
    } else {
        resume_deploy_journal(&paths.state_dir, journal_id, &plan)?
    };
    let mut lines = vec![
        format!("journal: {}", report.journal_id),
        format!("plan: {}", report.plan_id),
        format!("journal_status: {}", report.journal_status),
        format!("can_resume: {}", report.can_resume),
        format!(
            "executed_orders: {}",
            join_u32_or_dash(&report.executed_orders)
        ),
        format!("next_operations: {}", report.next_operations.len()),
    ];
    if let Some(token) = &report.resume_approval_token {
        lines.push(format!("resume_approval_token: {token}"));
    }
    if let Some(failed_operation) = &report.failed_operation {
        lines.push(format!(
            "failed_operation: {}\t{}\t{}\t{}",
            failed_operation.order,
            failed_operation.kind,
            failed_operation.target,
            failed_operation.status
        ));
    }
    for blocker in &report.blockers {
        lines.push(format!("blocker: {blocker}"));
    }
    for operation in &report.next_operations {
        lines.push(format!(
            "{}\t{}\t{}",
            operation.order, operation.kind, operation.target
        ));
    }
    if let Some(execution) = &report.execution {
        lines.push(format!("execution: {}", execution.status));
        lines.push(format!("new_journal: {}", execution.journal_id));
    }
    let execution_failed = report
        .execution
        .as_ref()
        .is_some_and(|execution| execution.status != "success");

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize deploy resume report")?,
        text: lines.join("\n"),
        exit_code: if report.can_resume && !execution_failed {
            0
        } else {
            2
        },
        audit_decision: if report.can_resume && !execution_failed {
            "allow"
        } else {
            "deny"
        },
        dry_run: !execute,
    })
}

fn install_check_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let report = check_install(paths);
    let mut lines = vec![
        format!("registry: {}", report.registry_dir),
        format!("state: {}", report.state_dir),
        format!("status: {}", if report.ok { "ok" } else { "error" }),
        format!("errors: {}", report.errors),
        format!("warnings: {}", report.warnings),
    ];
    for finding in &report.findings {
        lines.push(format!(
            "{}\t{}\t{}\t{}",
            finding.severity, finding.code, finding.target, finding.message
        ));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize install check report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: false,
    })
}

fn helper_command(paths: &RuntimePaths, command: &HelperCommand) -> Result<CommandOutput> {
    match command {
        HelperCommand::RunDeployOperation {
            plan,
            operation,
            snapshot,
            approval_token,
        } => helper_run_deploy_operation_command(
            paths,
            plan,
            *operation,
            snapshot.as_deref(),
            approval_token,
        ),
        HelperCommand::SudoersCheck { path } => helper_sudoers_check_command(path.as_deref()),
    }
}

fn helper_sudoers_check_command(path: Option<&Path>) -> Result<CommandOutput> {
    let default_path = Path::new("/etc/sudoers.d/opsctl-helper");
    let path = path.unwrap_or(default_path);
    let report = check_sudoers_file(path);
    let mut lines = vec![
        format!("path: {}", report.path),
        format!("status: {}", if report.ok { "ok" } else { "error" }),
        format!("exists: {}", report.exists),
        format!("syntax_checked: {}", report.syntax_checked),
        format!(
            "syntax_ok: {}",
            report
                .syntax_ok
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string())
        ),
        format!("errors: {}", report.errors),
        format!("warnings: {}", report.warnings),
    ];
    for finding in &report.findings {
        lines.push(format!(
            "{}\t{}\t{}",
            finding.severity, finding.code, finding.message
        ));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize sudoers check report")?,
        text: lines.join("\n"),
        exit_code: if report.ok { 0 } else { 1 },
        audit_decision: if report.ok { "allow" } else { "deny" },
        dry_run: true,
    })
}

fn helper_run_deploy_operation_command(
    paths: &RuntimePaths,
    plan_path: &Path,
    operation: u32,
    snapshot_id: Option<&str>,
    approval_token: &str,
) -> Result<CommandOutput> {
    let registry = Registry::load(&paths.registry_dir)?;
    let approvals = list_approvals(&paths.registry_dir)?.approvals;
    let plan = load_deploy_plan(plan_path)?;
    let report = execute_deploy(&DeployExecutionOptions {
        state_dir: &paths.state_dir,
        registry_dir: &paths.registry_dir,
        registry: &registry,
        plan: &plan,
        snapshot_id,
        approvals: &approvals,
        approval_token,
        operation_order: Some(operation),
    })?;
    let status = report.status;

    Ok(CommandOutput {
        json: serialize_report(&report)?,
        text: report_text(&report),
        exit_code: deploy_exit_code(status),
        audit_decision: deploy_decision(status),
        dry_run: false,
    })
}

fn tui_command(paths: &RuntimePaths, dump: bool, actor: &str) -> Result<CommandOutput> {
    if dump {
        let report = dump_tui(paths)?;
        return Ok(CommandOutput {
            json: serde_json::to_value(&report).context("failed to serialize tui dump")?,
            text: tui_dump_text(&report.summary),
            exit_code: 0,
            audit_decision: "allow",
            dry_run: false,
        });
    }

    run_tui(paths, actor)?;
    Ok(CommandOutput {
        json: json!({ "status": "closed" }),
        text: "tui closed".to_string(),
        exit_code: 0,
        audit_decision: "allow",
        dry_run: false,
    })
}

fn approvals_command(paths: &RuntimePaths) -> Result<CommandOutput> {
    let report = list_approvals(&paths.registry_dir)?;
    let mut lines = vec![format!("approvals: {}", report.approvals.len())];
    for approval in &report.approvals {
        lines.push(format!(
            "{}\t{}\t{:?}\t{}",
            approval.record.id,
            approval.record.plan_id,
            approval.effective_status,
            approval.record.scope.join(",")
        ));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize approval list")?,
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: "allow",
        dry_run: false,
    })
}

fn audit_command(paths: &RuntimePaths, limit: usize) -> Result<CommandOutput> {
    let report = query_audit_log(&paths.audit_log, limit)?;
    let mut lines = vec![
        format!("audit_log: {}", report.path),
        format!("events: {}", report.events.len()),
        format!("total_lines: {}", report.integrity.total_lines),
        format!("invalid_lines: {}", report.integrity.invalid_lines.len()),
    ];
    for warning in &report.integrity.warnings {
        lines.push(format!("warning: {warning}"));
    }
    for event in &report.events {
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}",
            event.ts.as_deref().unwrap_or("-"),
            event.actor.as_deref().unwrap_or("-"),
            event.command.as_deref().unwrap_or("-"),
            event.decision.as_deref().unwrap_or("-"),
            event.target.as_deref().unwrap_or("-"),
        ));
    }

    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize audit query")?,
        text: lines.join("\n"),
        exit_code: 0,
        audit_decision: if report.integrity.invalid_lines.is_empty() {
            "allow"
        } else {
            "warn"
        },
        dry_run: false,
    })
}

fn approve_command(paths: &RuntimePaths, approval_id: &str, actor: &str) -> Result<CommandOutput> {
    let report = approve(&paths.registry_dir, approval_id, actor)?;
    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize approval decision")?,
        text: format!(
            "approval: {}\nplan: {}\nstatus: {}\npath: {}",
            report.id, report.plan_id, report.status, report.path
        ),
        exit_code: 0,
        audit_decision: "allow",
        dry_run: false,
    })
}

fn reject_command(
    paths: &RuntimePaths,
    approval_id: &str,
    actor: &str,
    reason: Option<&str>,
) -> Result<CommandOutput> {
    let report = reject(&paths.registry_dir, approval_id, actor, reason)?;
    Ok(CommandOutput {
        json: serde_json::to_value(&report).context("failed to serialize approval rejection")?,
        text: format!(
            "approval: {}\nplan: {}\nstatus: {}\npath: {}",
            report.id, report.plan_id, report.status, report.path
        ),
        exit_code: 0,
        audit_decision: "deny",
        dry_run: false,
    })
}

#[allow(clippy::print_stdout)]
fn print_output(json_output: bool, output: CommandOutput) -> ExitCode {
    if json_output {
        println!(
            "{}",
            json!({
                "schema_version": OUTPUT_SCHEMA_VERSION,
                "ok": command_output_ok(&output),
                "data": output.json,
            })
        );
    } else {
        println!("{}", output.text);
    }

    if output.exit_code == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(u8::try_from(output.exit_code).unwrap_or(1))
    }
}

fn command_output_ok(output: &CommandOutput) -> bool {
    if output.json.get("schema_validation").is_some() {
        return true;
    }
    if output.json.get("deploy_gates_status").is_some() {
        return output.audit_decision != "deny";
    }
    if output.json.get("plan_id").is_some() && output.json.get("summary").is_some() {
        return true;
    }
    output.exit_code == 0 && output.audit_decision != "deny"
}

#[allow(clippy::print_stderr, clippy::print_stdout)]
fn print_audit_error(json_output: bool, error: anyhow::Error) {
    if json_output {
        println!(
            "{}",
            json!({
                "schema_version": OUTPUT_SCHEMA_VERSION,
                "ok": false,
                "error": {
                    "message": format!("failed to write audit record: {error}")
                }
            })
        );
    } else {
        eprintln!("error: failed to write audit record: {error:#}");
    }
}

#[allow(clippy::print_stderr, clippy::print_stdout)]
fn print_error_with_ok(json_output: bool, error: &anyhow::Error, ok: bool) {
    if json_output {
        println!(
            "{}",
            json!({
                "schema_version": OUTPUT_SCHEMA_VERSION,
                "ok": ok,
                "error": {
                    "message": error.to_string()
                }
            })
        );
    } else {
        eprintln!("error: {error:#}");
    }
}

fn resolve_actor(cli_actor: Option<&str>) -> String {
    if let Some(actor) = cli_actor
        && !actor.trim().is_empty()
    {
        return actor.to_string();
    }

    env::var("USER").unwrap_or_else(|_| "unknown".to_string())
}

fn command_risk(command_name: &str) -> &'static str {
    match command_name {
        "preflight" | "deploy-gates" => "high",
        "snapshot"
        | "rollback"
        | "deploy"
        | "deploy-resume"
        | "request-deploy-execution"
        | "request-deploy-resume"
        | "helper"
        | "approve"
        | "reject"
        | "backup" => "high",
        "registry"
        | "doctor"
        | "scan"
        | "caddy-routes"
        | "explain-risk"
        | "snapshots"
        | "snapshot-inspect"
        | "snapshot-verify"
        | "snapshot-archive-inspect"
        | "snapshot-volume-archive-inspect"
        | "deploy-journals"
        | "deploy-journal-inspect"
        | "install-check"
        | "approvals"
        | "audit"
        | "snapshot-coverage"
        | "tui"
        | "mcp" => "medium",
        "status" | "services" | "ports" | "analyze" | "plan" => "low",
        _ => "unknown",
    }
}

fn command_risk_for(command: &Command) -> &'static str {
    match command {
        Command::Registry {
            command:
                RegistryCommand::ImportProjects { .. }
                | RegistryCommand::Normalize { execute: true }
                | RegistryCommand::PromoteImport { dry_run: false, .. },
        } => "high",
        Command::Registry {
            command:
                RegistryCommand::PublicDataException {
                    command: RegistryPublicDataExceptionCommand::Add { execute: true, .. },
                },
        } => "high",
        Command::Registry {
            command:
                RegistryCommand::Drift {
                    command:
                        RegistryDriftCommand::ServiceAdd { execute: true, .. }
                        | RegistryDriftCommand::Adopt { execute: true, .. }
                        | RegistryDriftCommand::AdoptReview { execute: true, .. }
                        | RegistryDriftCommand::Ignore { execute: true, .. }
                        | RegistryDriftCommand::Review {
                            command: RegistryDriftReviewCommand::Apply { execute: true, .. },
                        }
                        | RegistryDriftCommand::CleanupRequest {
                            command:
                                RegistryDriftCleanupRequestCommand::RequestExecution { .. }
                                | RegistryDriftCleanupRequestCommand::Sync { execute: true, .. }
                                | RegistryDriftCleanupRequestCommand::Mark { execute: true, .. }
                                | RegistryDriftCleanupRequestCommand::Evidence { execute: true, .. }
                                | RegistryDriftCleanupRequestCommand::EvidenceResolve {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::Execute { execute: true, .. }
                                | RegistryDriftCleanupRequestCommand::Finalize { execute: true, .. }
                                | RegistryDriftCleanupRequestCommand::HandoffPack {
                                    execute: true, ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceKeygen {
                                    execute: true, ..
                                }
                                | RegistryDriftCleanupRequestCommand::ManifestSign {
                                    execute: true, ..
                                }
                                | RegistryDriftCleanupRequestCommand::AuditBundle {
                                    execute: true, ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceKeyTrust {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceKeyRevoke {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::AuditCheckpoint {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceWormExport {
                                    execute: true,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::Reconcile { execute: true, .. },
                        },
                },
        } => "high",
        Command::SnapshotCoverage {
            register_baseline: true,
            execute: true,
            ..
        } => "high",
        Command::SnapshotCoverage {
            register_baseline: true,
            ..
        } => "medium",
        Command::Backup {
            command:
                BackupCommand::DrillCleanup { execute: true, .. }
                | BackupCommand::DrillSuite { execute: true, .. }
                | BackupCommand::RefreshStale { execute: true, .. }
                | BackupCommand::TargetAdd { execute: true, .. }
                | BackupCommand::RepoInit { execute: true, .. }
                | BackupCommand::S3Smoke { execute: true, .. }
                | BackupCommand::VolumeProtect {
                    command:
                        BackupVolumeProtectCommand::Run { execute: true, .. }
                        | BackupVolumeProtectCommand::Resume { execute: true, .. }
                        | BackupVolumeProtectCommand::Cleanup { execute: true, .. }
                        | BackupVolumeProtectCommand::BatchRun { execute: true, .. }
                        | BackupVolumeProtectCommand::CampaignRun { execute: true, .. }
                        | BackupVolumeProtectCommand::CampaignResume { execute: true, .. }
                        | BackupVolumeProtectCommand::CampaignAbort { execute: true, .. }
                        | BackupVolumeProtectCommand::LabRun { execute: true, .. }
                        | BackupVolumeProtectCommand::BackfillRecord { execute: true, .. }
                        | BackupVolumeProtectCommand::RetentionImport { execute: true, .. }
                        | BackupVolumeProtectCommand::ArchiveDrill { execute: true, .. }
                        | BackupVolumeProtectCommand::GovernanceInstall { execute: true, .. }
                        | BackupVolumeProtectCommand::ProfileDraft { execute: true, .. }
                        | BackupVolumeProtectCommand::JournalMaintain { execute: true, .. },
                }
                | BackupCommand::Timer {
                    command:
                        BackupTimerCommand::Install { execute: true, .. }
                        | BackupTimerCommand::AlertTest { execute: true, .. }
                        | BackupTimerCommand::AlertConfigure { execute: true, .. },
                },
        } => "high",
        Command::Backup {
            command:
                BackupCommand::Timer {
                    command: BackupTimerCommand::Alert { execute: true, .. },
                },
        } => "medium",
        Command::Registry {
            command: RegistryCommand::PromoteImport { dry_run: true, .. },
        } => "medium",
        _ => command_risk(command.name()),
    }
}

fn command_audit_target(command: &Command, paths: &RuntimePaths) -> String {
    match command {
        Command::Analyze { project } | Command::Plan { project, .. } => display_path(project),
        Command::Backup {
            command:
                BackupCommand::Plan { service_id, .. }
                | BackupCommand::Run { service_id, .. }
                | BackupCommand::RestorePlan { service_id, .. }
                | BackupCommand::Restore { service_id, .. }
                | BackupCommand::Drill { service_id, .. },
        } => service_id.clone(),
        Command::Backup {
            command:
                BackupCommand::TargetAdd {
                    service_id,
                    target_id,
                    ..
                },
        } => target_id.as_ref().map_or_else(
            || format!("{service_id}=>{service_id}-restic"),
            |target_id| format!("{service_id}=>{target_id}"),
        ),
        Command::Backup {
            command: BackupCommand::DrillSuite { service, .. },
        } => {
            if service.is_empty() {
                "drill-suite:all-active-targets".to_string()
            } else {
                format!("drill-suite:{}", service.join(","))
            }
        }
        Command::Backup {
            command: BackupCommand::RefreshStale { service, .. },
        } => {
            if service.is_empty() {
                "refresh-stale:all-blocked-services".to_string()
            } else {
                format!("refresh-stale:{}", service.join(","))
            }
        }
        Command::Backup {
            command: BackupCommand::S3Smoke { bucket, prefix, .. },
        } => prefix.as_ref().map_or_else(
            || format!("s3:{bucket}/<generated>"),
            |prefix| format!("s3:{bucket}/{prefix}"),
        ),
        Command::Backup {
            command: BackupCommand::VolumeProtect { command },
        } => match command {
            BackupVolumeProtectCommand::Plan { target, .. }
            | BackupVolumeProtectCommand::Run { target, .. } => target.clone(),
            BackupVolumeProtectCommand::Resume { run_id, .. } => run_id.clone(),
            BackupVolumeProtectCommand::Cleanup { restore_root, .. } => display_path(restore_root),
            BackupVolumeProtectCommand::BatchPlan { request_file, .. }
            | BackupVolumeProtectCommand::BatchRun { request_file, .. }
            | BackupVolumeProtectCommand::CampaignPlan { request_file, .. }
            | BackupVolumeProtectCommand::CampaignRun { request_file, .. } => {
                display_path(request_file)
            }
            BackupVolumeProtectCommand::CampaignResume { campaign_id, .. } => campaign_id.clone(),
            BackupVolumeProtectCommand::CampaignAbort { campaign_id, .. } => campaign_id.clone(),
            BackupVolumeProtectCommand::Metrics {
                request_file: Some(request_file),
            } => display_path(request_file),
            BackupVolumeProtectCommand::Metrics { request_file: None } => {
                display_path(&paths.state_dir)
            }
            BackupVolumeProtectCommand::GapRescan { request_file } => display_path(request_file),
            BackupVolumeProtectCommand::FailureMatrix => display_path(&paths.state_dir),
            BackupVolumeProtectCommand::LabPlan { fixture_root, .. }
            | BackupVolumeProtectCommand::LabRun { fixture_root, .. } => display_path(fixture_root),
            BackupVolumeProtectCommand::LabStatus { .. } => {
                display_path(&paths.state_dir.join("recovery-lab.jsonl"))
            }
            BackupVolumeProtectCommand::LabQualify { fixture_root, .. } => {
                display_path(fixture_root)
            }
            BackupVolumeProtectCommand::BackfillPlan { request_file, .. }
            | BackupVolumeProtectCommand::BackfillRecord { request_file, .. } => {
                display_path(request_file)
            }
            BackupVolumeProtectCommand::BackfillStatus { .. } => {
                display_path(&paths.state_dir.join("evidence-backfill.jsonl"))
            }
            BackupVolumeProtectCommand::RetentionStatus {
                attestation_file: Some(path),
                ..
            }
            | BackupVolumeProtectCommand::RetentionImport {
                attestation_file: path,
                ..
            } => display_path(path),
            BackupVolumeProtectCommand::RetentionStatus {
                attestation_file: None,
                ..
            }
            | BackupVolumeProtectCommand::KeyDrStatus { .. } => display_path(&paths.state_dir),
            BackupVolumeProtectCommand::ArchiveDrill {
                repository_snapshot,
                ..
            } => repository_snapshot.clone(),
            BackupVolumeProtectCommand::ArchiveDrillStatus { .. } => {
                display_path(&paths.state_dir.join("evidence-archive-drills.jsonl"))
            }
            BackupVolumeProtectCommand::GovernancePlan { .. }
            | BackupVolumeProtectCommand::GovernanceInstall { .. }
            | BackupVolumeProtectCommand::GovernanceStatus { .. } => display_path(&paths.state_dir),
            BackupVolumeProtectCommand::Slo {
                request_file: Some(request_file),
                ..
            } => display_path(request_file),
            BackupVolumeProtectCommand::Slo {
                request_file: None, ..
            } => display_path(&paths.state_dir),
            BackupVolumeProtectCommand::ProfileDetect { source_dir, .. }
            | BackupVolumeProtectCommand::ProfilePlan { source_dir, .. } => {
                display_path(source_dir)
            }
            BackupVolumeProtectCommand::ProfileDraft { output_file, .. } => {
                display_path(output_file)
            }
            BackupVolumeProtectCommand::ProfileValidate { profile_file } => {
                display_path(profile_file)
            }
            BackupVolumeProtectCommand::JournalMaintain { archive_dir, .. } => archive_dir
                .as_ref()
                .map_or_else(|| display_path(&paths.state_dir), |path| display_path(path)),
            BackupVolumeProtectCommand::History { .. }
            | BackupVolumeProtectCommand::Status { .. }
            | BackupVolumeProtectCommand::CampaignStatus { .. } => {
                display_path(&paths.state_dir.join("volume-protect.jsonl"))
            }
        },
        Command::Backup {
            command:
                BackupCommand::DrillCleanup { .. }
                | BackupCommand::Timer { .. }
                | BackupCommand::OnboardingCheck { .. },
        } => display_path(&paths.registry_dir),
        Command::Backup {
            command:
                BackupCommand::Check { repository_id }
                | BackupCommand::Prune { repository_id, .. }
                | BackupCommand::RepoInit { repository_id, .. },
        } => repository_id.clone(),
        Command::Preflight { plan }
        | Command::ExplainRisk { plan }
        | Command::Snapshot { plan, .. }
        | Command::Deploy { plan, .. }
        | Command::RequestDeployExecution { plan, .. } => display_path(plan),
        Command::RequestDeployResume { plan, journal, .. } => {
            format!("{}#{journal}", display_path(plan))
        }
        Command::DeployResume { plan, journal, .. } => {
            format!("{}#{journal}", display_path(plan))
        }
        Command::Helper {
            command:
                HelperCommand::RunDeployOperation {
                    plan, operation, ..
                },
        } => format!("{}#{operation}", display_path(plan)),
        Command::Helper {
            command: HelperCommand::SudoersCheck { path },
        } => path.as_ref().map_or_else(
            || "/etc/sudoers.d/opsctl-helper".to_string(),
            |path| display_path(path),
        ),
        Command::SnapshotInspect { snapshot_id }
        | Command::SnapshotVerify { snapshot_id }
        | Command::SnapshotArchiveInspect { snapshot_id }
        | Command::SnapshotVolumeArchiveInspect { snapshot_id }
        | Command::Rollback { snapshot_id, .. } => snapshot_id.clone(),
        Command::DeployJournalInspect { journal_id } => journal_id.clone(),
        Command::Registry {
            command: RegistryCommand::ImportProjects { output, .. },
        } => display_path(output),
        Command::Registry {
            command: RegistryCommand::ImportCheck { import_dir, .. },
        } => display_path(import_dir),
        Command::Registry {
            command: RegistryCommand::Normalize { .. },
        } => display_path(&paths.registry_dir),
        Command::Registry {
            command:
                RegistryCommand::PublicDataException {
                    command: RegistryPublicDataExceptionCommand::Add { port_id, .. },
                },
        } => port_id.clone(),
        Command::Registry {
            command: RegistryCommand::PromoteImport { import_dir, .. },
        } => format!(
            "{}=>{}",
            display_path(import_dir),
            display_path(&paths.registry_dir)
        ),
        Command::Registry {
            command: RegistryCommand::Drift { command },
        } => match command {
            RegistryDriftCommand::ServiceAdd { id, .. } => id.clone(),
            RegistryDriftCommand::Adopt {
                target, service_id, ..
            } => {
                format!("{target}=>{service_id}")
            }
            RegistryDriftCommand::AdoptReview {
                target, service_id, ..
            } => service_id.as_ref().map_or_else(
                || target.clone(),
                |service_id| format!("{target}=>{service_id}"),
            ),
            RegistryDriftCommand::Ignore {
                target: Some(target),
                ..
            } => target.clone(),
            RegistryDriftCommand::Ignore {
                code: Some(code), ..
            } => code.clone(),
            RegistryDriftCommand::Explain {
                target: Some(target),
                ..
            } => target.clone(),
            RegistryDriftCommand::Explain {
                code: Some(code), ..
            } => code.clone(),
            RegistryDriftCommand::Review {
                command: RegistryDriftReviewCommand::Apply { review_file, .. },
            } => display_path(review_file),
            RegistryDriftCommand::CleanupRequest {
                command:
                    RegistryDriftCleanupRequestCommand::Verify { request_file }
                    | RegistryDriftCleanupRequestCommand::Progress { request_file }
                    | RegistryDriftCleanupRequestCommand::Triage { request_file }
                    | RegistryDriftCleanupRequestCommand::Dashboard { request_file }
                    | RegistryDriftCleanupRequestCommand::Worklist { request_file, .. }
                    | RegistryDriftCleanupRequestCommand::Sync { request_file, .. }
                    | RegistryDriftCleanupRequestCommand::ExecutionPlan { request_file }
                    | RegistryDriftCleanupRequestCommand::ExecutionGate { request_file }
                    | RegistryDriftCleanupRequestCommand::ApprovalSummary { request_file }
                    | RegistryDriftCleanupRequestCommand::ApprovalPack { request_file, .. }
                    | RegistryDriftCleanupRequestCommand::EvidencePlan { request_file, .. }
                    | RegistryDriftCleanupRequestCommand::EvidenceResolve { request_file, .. }
                    | RegistryDriftCleanupRequestCommand::VolumeOwnership { request_file, .. }
                    | RegistryDriftCleanupRequestCommand::Runbook { request_file }
                    | RegistryDriftCleanupRequestCommand::Mark { request_file, .. }
                    | RegistryDriftCleanupRequestCommand::Evidence { request_file, .. }
                    | RegistryDriftCleanupRequestCommand::RequestExecution { request_file, .. }
                    | RegistryDriftCleanupRequestCommand::Execute { request_file, .. }
                    | RegistryDriftCleanupRequestCommand::Finalize { request_file, .. }
                    | RegistryDriftCleanupRequestCommand::HandoffPack { request_file, .. },
            } => display_path(request_file),
            RegistryDriftCommand::CleanupRequest {
                command:
                    RegistryDriftCleanupRequestCommand::ManifestStatus { manifest_file }
                    | RegistryDriftCleanupRequestCommand::ManifestSign { manifest_file, .. }
                    | RegistryDriftCleanupRequestCommand::ManifestVerify { manifest_file }
                    | RegistryDriftCleanupRequestCommand::AuditBundle { manifest_file, .. }
                    | RegistryDriftCleanupRequestCommand::Reconcile { manifest_file, .. },
            } => display_path(manifest_file),
            RegistryDriftCommand::CleanupRequest {
                command: RegistryDriftCleanupRequestCommand::EvidenceKeygen { key_id, .. },
            } => key_id.clone(),
            RegistryDriftCommand::CleanupRequest {
                command:
                    RegistryDriftCleanupRequestCommand::EvidenceKeyTrust { key_id, .. }
                    | RegistryDriftCleanupRequestCommand::EvidenceKeyRevoke { key_id, .. }
                    | RegistryDriftCleanupRequestCommand::EvidenceKeyStatus {
                        key_id: Some(key_id),
                    }
                    | RegistryDriftCleanupRequestCommand::AuditCheckpoint { key_id, .. },
            } => key_id.clone(),
            RegistryDriftCommand::CleanupRequest {
                command: RegistryDriftCleanupRequestCommand::EvidenceWormExport { bundle_file, .. },
            } => display_path(bundle_file),
            RegistryDriftCommand::CleanupRequest {
                command:
                    RegistryDriftCleanupRequestCommand::AuditVerify
                    | RegistryDriftCleanupRequestCommand::EvidenceVerifyAll
                    | RegistryDriftCleanupRequestCommand::EvidenceKeyStatus { key_id: None },
            } => display_path(&paths.state_dir),
            RegistryDriftCommand::Explain { .. }
            | RegistryDriftCommand::List
            | RegistryDriftCommand::Groups
            | RegistryDriftCommand::Suggest
            | RegistryDriftCommand::Ownership { .. }
            | RegistryDriftCommand::Governance
            | RegistryDriftCommand::CleanupPlan
            | RegistryDriftCommand::CleanupRequest {
                command: RegistryDriftCleanupRequestCommand::Export,
            }
            | RegistryDriftCommand::Review {
                command: RegistryDriftReviewCommand::Export,
            }
            | RegistryDriftCommand::Ignore { .. } => display_path(&paths.registry_dir),
        },
        Command::Registry { .. } => display_path(&paths.registry_dir),
        Command::Backup {
            command: BackupCommand::Doctor | BackupCommand::Readiness | BackupCommand::History,
        } => display_path(&paths.registry_dir),
        Command::Approve { approval_id } | Command::Reject { approval_id, .. } => {
            approval_id.clone()
        }
        Command::Mcp => display_path(&paths.registry_dir),
        Command::Audit { .. } => display_path(&paths.audit_log),
        Command::Status
        | Command::Services
        | Command::Ports
        | Command::DeployGates
        | Command::Doctor
        | Command::Scan
        | Command::CaddyRoutes { .. }
        | Command::Snapshots
        | Command::SnapshotCoverage { .. }
        | Command::DeployJournals
        | Command::InstallCheck
        | Command::Approvals
        | Command::Tui { .. } => display_path(&paths.registry_dir),
    }
}

fn command_is_dry_run(command: &Command) -> bool {
    matches!(
        command,
        Command::Plan { .. }
            | Command::Preflight { .. }
            | Command::ExplainRisk { .. }
            | Command::DeployGates
            | Command::Backup {
                command: BackupCommand::Readiness
                    | BackupCommand::Plan { dry_run: true, .. }
                    | BackupCommand::Run { execute: false, .. }
                    | BackupCommand::RestorePlan { .. }
                    | BackupCommand::Restore { execute: false, .. }
                    | BackupCommand::Drill { execute: false, .. }
                    | BackupCommand::DrillSuite { execute: false, .. }
                    | BackupCommand::DrillCleanup { execute: false, .. }
                    | BackupCommand::RefreshStale { execute: false, .. }
                    | BackupCommand::TargetAdd { execute: false, .. }
                    | BackupCommand::RepoInit { execute: false, .. }
                    | BackupCommand::S3Smoke { execute: false, .. }
                    | BackupCommand::VolumeProtect {
                        command: BackupVolumeProtectCommand::Plan { .. }
                            | BackupVolumeProtectCommand::Run { execute: false, .. }
                            | BackupVolumeProtectCommand::History { .. }
                            | BackupVolumeProtectCommand::Status { .. }
                            | BackupVolumeProtectCommand::Resume { execute: false, .. }
                            | BackupVolumeProtectCommand::Cleanup { execute: false, .. }
                            | BackupVolumeProtectCommand::BatchPlan { .. }
                            | BackupVolumeProtectCommand::BatchRun { execute: false, .. }
                            | BackupVolumeProtectCommand::CampaignPlan { .. }
                            | BackupVolumeProtectCommand::CampaignRun { execute: false, .. }
                            | BackupVolumeProtectCommand::CampaignStatus { .. }
                            | BackupVolumeProtectCommand::CampaignResume { execute: false, .. }
                            | BackupVolumeProtectCommand::CampaignAbort { execute: false, .. }
                            | BackupVolumeProtectCommand::Metrics { .. }
                            | BackupVolumeProtectCommand::FailureMatrix
                            | BackupVolumeProtectCommand::GapRescan { .. }
                            | BackupVolumeProtectCommand::LabPlan { .. }
                            | BackupVolumeProtectCommand::LabRun { execute: false, .. }
                            | BackupVolumeProtectCommand::LabStatus { .. }
                            | BackupVolumeProtectCommand::LabQualify { .. }
                            | BackupVolumeProtectCommand::BackfillPlan { .. }
                            | BackupVolumeProtectCommand::BackfillRecord { execute: false, .. }
                            | BackupVolumeProtectCommand::BackfillStatus { .. }
                            | BackupVolumeProtectCommand::RetentionStatus { .. }
                            | BackupVolumeProtectCommand::RetentionImport { execute: false, .. }
                            | BackupVolumeProtectCommand::ArchiveDrill { execute: false, .. }
                            | BackupVolumeProtectCommand::ArchiveDrillStatus { .. }
                            | BackupVolumeProtectCommand::KeyDrStatus { .. }
                            | BackupVolumeProtectCommand::GovernancePlan { .. }
                            | BackupVolumeProtectCommand::GovernanceInstall { execute: false, .. }
                            | BackupVolumeProtectCommand::GovernanceStatus { .. }
                            | BackupVolumeProtectCommand::Slo { .. }
                            | BackupVolumeProtectCommand::ProfileDetect { .. }
                            | BackupVolumeProtectCommand::ProfilePlan { .. }
                            | BackupVolumeProtectCommand::ProfileDraft { execute: false, .. }
                            | BackupVolumeProtectCommand::ProfileValidate { .. }
                            | BackupVolumeProtectCommand::JournalMaintain { execute: false, .. },
                    }
                    | BackupCommand::Timer {
                        command: BackupTimerCommand::Plan { .. }
                            | BackupTimerCommand::Status { .. }
                            | BackupTimerCommand::Monitor { .. }
                            | BackupTimerCommand::AlertStatus { .. }
                            | BackupTimerCommand::AlertEnablePlan { .. }
                            | BackupTimerCommand::Alert { execute: false, .. }
                            | BackupTimerCommand::AlertTest { execute: false, .. }
                            | BackupTimerCommand::AlertConfigure { execute: false, .. }
                            | BackupTimerCommand::Install { execute: false, .. },
                    }
                    | BackupCommand::OnboardingCheck { .. },
            }
            | Command::Snapshot { dry_run: true, .. }
            | Command::SnapshotCoverage {
                register_baseline: true,
                execute: false,
                ..
            }
            | Command::Rollback { dry_run: true, .. }
            | Command::Deploy { dry_run: true, .. }
            | Command::DeployResume { dry_run: true, .. }
            | Command::Helper {
                command: HelperCommand::SudoersCheck { .. },
            }
            | Command::Registry {
                command: RegistryCommand::ImportCheck { .. },
            }
            | Command::Registry {
                command: RegistryCommand::Normalize { execute: false },
            }
            | Command::Registry {
                command: RegistryCommand::PublicDataException {
                    command: RegistryPublicDataExceptionCommand::Add { execute: false, .. },
                },
            }
            | Command::Registry {
                command: RegistryCommand::PromoteImport { dry_run: true, .. },
            }
            | Command::Registry {
                command: RegistryCommand::Drift {
                    command: RegistryDriftCommand::List
                        | RegistryDriftCommand::Groups
                        | RegistryDriftCommand::Suggest
                        | RegistryDriftCommand::Ownership { .. }
                        | RegistryDriftCommand::Governance
                        | RegistryDriftCommand::CleanupPlan
                        | RegistryDriftCommand::CleanupRequest {
                            command: RegistryDriftCleanupRequestCommand::Export
                                | RegistryDriftCleanupRequestCommand::Verify { .. }
                                | RegistryDriftCleanupRequestCommand::Progress { .. }
                                | RegistryDriftCleanupRequestCommand::Triage { .. }
                                | RegistryDriftCleanupRequestCommand::Dashboard { .. }
                                | RegistryDriftCleanupRequestCommand::Worklist { .. }
                                | RegistryDriftCleanupRequestCommand::Sync { execute: false, .. }
                                | RegistryDriftCleanupRequestCommand::ExecutionPlan { .. }
                                | RegistryDriftCleanupRequestCommand::ExecutionGate { .. }
                                | RegistryDriftCleanupRequestCommand::ApprovalSummary { .. }
                                | RegistryDriftCleanupRequestCommand::ApprovalPack { .. }
                                | RegistryDriftCleanupRequestCommand::EvidencePlan { .. }
                                | RegistryDriftCleanupRequestCommand::VolumeOwnership { .. }
                                | RegistryDriftCleanupRequestCommand::Runbook { .. }
                                | RegistryDriftCleanupRequestCommand::Mark { execute: false, .. }
                                | RegistryDriftCleanupRequestCommand::Evidence {
                                    execute: false,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceResolve {
                                    execute: false,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::Execute {
                                    execute: false,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::Finalize {
                                    execute: false,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::HandoffPack {
                                    execute: false,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::ManifestStatus { .. }
                                | RegistryDriftCleanupRequestCommand::EvidenceKeygen {
                                    execute: false,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::ManifestSign {
                                    execute: false,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::ManifestVerify { .. }
                                | RegistryDriftCleanupRequestCommand::AuditVerify
                                | RegistryDriftCleanupRequestCommand::AuditBundle {
                                    execute: false,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceKeyTrust {
                                    execute: false,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceKeyRevoke {
                                    execute: false,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceKeyStatus { .. }
                                | RegistryDriftCleanupRequestCommand::AuditCheckpoint {
                                    execute: false,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::EvidenceVerifyAll
                                | RegistryDriftCleanupRequestCommand::EvidenceWormExport {
                                    execute: false,
                                    ..
                                }
                                | RegistryDriftCleanupRequestCommand::Reconcile {
                                    execute: false,
                                    ..
                                },
                        }
                        | RegistryDriftCommand::Explain { .. }
                        | RegistryDriftCommand::ServiceAdd { execute: false, .. }
                        | RegistryDriftCommand::Adopt { execute: false, .. }
                        | RegistryDriftCommand::AdoptReview { execute: false, .. }
                        | RegistryDriftCommand::Ignore { execute: false, .. }
                        | RegistryDriftCommand::Review {
                            command: RegistryDriftReviewCommand::Export
                                | RegistryDriftReviewCommand::Apply { execute: false, .. },
                        },
                },
            }
            | Command::Tui { dump: true }
    )
}

fn tui_dump_text(summary: &tui::TuiSummary) -> String {
    format!(
        "services: {}\nports: {}\ndomains: {}\napprovals: {} pending, {} approved, {} expired\nsnapshots: {}\ndoctor: {} error(s), {} warning(s)\ndeploy_gates: {} ({} checked, {} ready, {} blocked, dry_run={})\nbackup_readiness: {} ({} checked, {} blocked)\nbackup_restore: {} service(s), {} target(s), {} successful snapshot id(s)\nbackup_history: {} ({} record(s), {} service(s) missing success, {} stale target(s))\ndrift: {} active, {} ignored, {} group(s), {} cleanup candidate(s)\ndeploy_adapters: {} supported\nregistry_promotion_backups: {}",
        summary.services,
        summary.ports,
        summary.domains,
        summary.pending_approvals,
        summary.approved_approvals,
        summary.expired_approvals,
        summary.local_snapshots,
        summary.doctor_errors,
        summary.doctor_warnings,
        summary.deploy_gates_status,
        summary.deploy_gates_services_checked,
        summary.deploy_gates_services_ready,
        summary.deploy_gates_services_blocked,
        summary.deploy_gates_dry_run,
        summary.backup_status,
        summary.backup_services_checked,
        summary.backup_blocked,
        summary.backup_restore_capable_services,
        summary.backup_restore_capable_targets,
        summary.backup_restore_successful_snapshots,
        summary.backup_history_status,
        summary.backup_history_records,
        summary.backup_history_services_missing_success,
        summary.backup_history_stale_targets,
        summary.drift_active_findings,
        summary.drift_ignored_findings,
        summary.drift_groups,
        summary.drift_cleanup_candidates,
        summary.deploy_adapters_supported.len(),
        summary.registry_promotion_backups
    )
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

fn join_ports_or_dash(values: &[u16]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn join_u32_or_dash(values: &[u32]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}
