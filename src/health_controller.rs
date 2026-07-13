use std::{fs, io::Write, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::{
    approvals::{ApprovalFile, approved_scope_for_plan},
    deploy::{deploy_plan_sha256, inspect_deploy_journal},
    paths::display_path,
    plan::DeployPlan,
    snapshot::{inspect_snapshot, rollback_dry_run_with_registry, rollback_restore_scoped},
};

const CONTROLLER_SCHEMA: &str = "opsctl.health_rollback_controller.v1";

#[derive(Debug, Clone)]
pub struct HealthControllerOptions<'a> {
    pub state_dir: &'a Path,
    pub registry_dir: &'a Path,
    pub plan: &'a DeployPlan,
    pub journal_id: &'a str,
    pub execute: bool,
    pub approval_token: Option<&'a str>,
    pub approvals: &'a [ApprovalFile],
    pub caddyfile_path: Option<&'a Path>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthControllerReport {
    pub read_only: bool,
    pub execute: bool,
    pub status: String,
    pub eligible: bool,
    pub plan_id: String,
    pub plan_sha256: String,
    pub journal_id: String,
    pub snapshot_id: Option<String>,
    pub failed_health_checks: usize,
    pub automatic_scopes: Vec<String>,
    pub blockers: Vec<String>,
    pub approval_scope: Option<String>,
    pub approval_token: Option<String>,
    pub controller_record: Option<String>,
    pub rollback_status: Option<String>,
    pub rollback_limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerClaim {
    schema_version: String,
    controller_id: String,
    plan_id: String,
    plan_sha256: String,
    journal_id: String,
    snapshot_id: String,
    created_at: String,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerResult {
    schema_version: String,
    controller_id: String,
    plan_sha256: String,
    journal_id: String,
    snapshot_id: String,
    completed_at: String,
    status: String,
    rollback_status: String,
    limitations: Vec<String>,
}

pub fn expected_health_rollback_scope(journal_id: &str) -> String {
    format!("health_rollback.{journal_id}")
}

pub fn evaluate_health_controller(
    options: &HealthControllerOptions<'_>,
) -> Result<HealthControllerReport> {
    let inspected = inspect_deploy_journal(options.state_dir, options.journal_id)?;
    let journal = inspected.journal;
    let plan_sha256 = deploy_plan_sha256(options.plan)?;
    let mut blockers = Vec::new();
    if !options.plan.changes.health.controller
        || options.plan.changes.health.max_rollback_attempts != 1
    {
        blockers
            .push("deploy plan does not enable the bounded health rollback controller".to_string());
    }
    if journal.plan_id != options.plan.id {
        blockers.push("deploy journal belongs to a different plan".to_string());
    }
    if journal.plan_sha256.as_deref() != Some(plan_sha256.as_str()) {
        blockers.push("deploy journal plan digest is missing or changed".to_string());
    }
    if journal.status != "failed" {
        blockers.push("controller requires a failed deploy journal".to_string());
    }
    if journal.registry_updated {
        blockers
            .push("automatic rollback refuses a journal that already changed Registry".to_string());
    }
    let failed = journal.results.last();
    if !failed
        .is_some_and(|result| result.kind == "PostDeployHealthCheck" && result.status == "failed")
    {
        blockers.push("last failed operation is not the post-deploy health gate".to_string());
    }
    let failed_health_checks = failed
        .map(|result| {
            result
                .health_checks
                .iter()
                .filter(|check| check.status == "failed")
                .count()
        })
        .unwrap_or(0);
    if failed_health_checks == 0 {
        blockers.push("journal contains no failed health-check evidence".to_string());
    }
    let snapshot_id = journal.snapshot_id.clone();
    let mut automatic_scopes = Vec::new();
    if let Some(snapshot_id) = snapshot_id.as_deref() {
        let snapshot = inspect_snapshot(options.state_dir, snapshot_id)?;
        if snapshot.plan_id != options.plan.id {
            blockers.push("snapshot belongs to a different deploy plan".to_string());
        }
        let rollback = rollback_dry_run_with_registry(
            options.state_dir,
            snapshot_id,
            Some(options.registry_dir),
        )?;
        if !rollback.can_restore {
            blockers.push("verified rollback dry-run contains conflicts".to_string());
        }
        if plan_changes_caddy(options.plan) {
            if snapshot.artifacts.contains_key("caddy_config") {
                automatic_scopes.push("caddy_config".to_string());
            } else {
                blockers
                    .push("Caddy changed but snapshot has no Caddy config artifact".to_string());
            }
        }
    } else {
        blockers.push("failed deploy journal has no bound snapshot".to_string());
    }
    if plan_has_uncovered_application_changes(options.plan) {
        blockers.push(
            "application code, image, static output, migration, data, or service-unit changes are not fully covered by automatic rollback"
                .to_string(),
        );
    }
    if automatic_scopes.is_empty() {
        blockers.push("plan has no changed scope covered by automatic rollback".to_string());
    }

    let eligible = blockers.is_empty();
    let scope = eligible.then(|| expected_health_rollback_scope(options.journal_id));
    let token = snapshot_id
        .as_deref()
        .filter(|_| eligible)
        .map(|snapshot_id| controller_token(&plan_sha256, options.journal_id, snapshot_id));
    let controller_dir = options.state_dir.join("health-controllers");
    let claim_path = controller_dir.join(format!("{}.claim.json", options.journal_id));
    let result_path = controller_dir.join(format!("{}.result.json", options.journal_id));
    let mut report = HealthControllerReport {
        read_only: !options.execute,
        execute: options.execute,
        status: if eligible { "ready" } else { "manual_required" }.to_string(),
        eligible,
        plan_id: options.plan.id.clone(),
        plan_sha256,
        journal_id: options.journal_id.to_string(),
        snapshot_id,
        failed_health_checks,
        automatic_scopes,
        blockers,
        approval_scope: scope,
        approval_token: token,
        controller_record: None,
        rollback_status: None,
        rollback_limitations: Vec::new(),
    };
    if options.execute {
        execute_controller(options, &claim_path, &result_path, &mut report)?;
    }
    Ok(report)
}

fn execute_controller(
    options: &HealthControllerOptions<'_>,
    claim_path: &Path,
    result_path: &Path,
    report: &mut HealthControllerReport,
) -> Result<()> {
    if !report.eligible {
        anyhow::bail!(
            "health rollback is not eligible: {}",
            report.blockers.join("; ")
        );
    }
    let scope = report
        .approval_scope
        .as_deref()
        .context("missing approval scope")?;
    if !approved_scope_for_plan(options.approvals, &options.plan.id)
        .iter()
        .any(|approved| approved == scope)
    {
        anyhow::bail!("health rollback requires an approved record with scope {scope}");
    }
    let token = report
        .approval_token
        .as_deref()
        .context("missing controller token")?;
    if options.approval_token != Some(token) {
        anyhow::bail!("invalid health rollback approval token");
    }
    ensure_controller_dir(claim_path.parent().context("claim has no parent")?)?;
    if result_path.exists() {
        let result: ControllerResult = read_json(result_path)?;
        if result.controller_id != format!("health-{}", report.journal_id)
            || result.plan_sha256 != report.plan_sha256
            || result.journal_id != report.journal_id
            || Some(result.snapshot_id.as_str()) != report.snapshot_id.as_deref()
        {
            anyhow::bail!("existing health controller result does not match this request");
        }
        report.status = "already_completed".to_string();
        report.controller_record = Some(display_path(result_path));
        report.rollback_status = Some(result.rollback_status);
        report.rollback_limitations = result.limitations;
        return Ok(());
    }
    let snapshot_id = report
        .snapshot_id
        .as_deref()
        .context("missing snapshot id")?;
    let controller_id = format!("health-{}", options.journal_id);
    let claim = ControllerClaim {
        schema_version: CONTROLLER_SCHEMA.to_string(),
        controller_id: controller_id.clone(),
        plan_id: report.plan_id.clone(),
        plan_sha256: report.plan_sha256.clone(),
        journal_id: report.journal_id.clone(),
        snapshot_id: snapshot_id.to_string(),
        created_at: now()?,
        status: "executing".to_string(),
    };
    write_create_new_json(claim_path, &claim)?;
    let dry_run =
        rollback_dry_run_with_registry(options.state_dir, snapshot_id, Some(options.registry_dir))?;
    let restore_config = report
        .automatic_scopes
        .iter()
        .any(|scope| scope == "caddy_config");
    let default_caddyfile = Path::new("/etc/caddy/Caddyfile");
    let rollback = rollback_restore_scoped(
        options.state_dir,
        options.registry_dir,
        snapshot_id,
        &dry_run.approval_token,
        false,
        restore_config,
        false,
        options.caddyfile_path.unwrap_or(default_caddyfile),
    )?;
    let limitations = rollback
        .limitations
        .iter()
        .filter(|limitation| {
            (restore_config || !limitation.starts_with("Caddyfile artifact is available"))
                && !limitation.contains("Docker volume archive(s) are available")
        })
        .cloned()
        .collect::<Vec<_>>();
    let covered = !rollback.registry_restored
        && (!restore_config || rollback.caddy_config_restored)
        && limitations.is_empty();
    let result = ControllerResult {
        schema_version: CONTROLLER_SCHEMA.to_string(),
        controller_id,
        plan_sha256: report.plan_sha256.clone(),
        journal_id: report.journal_id.clone(),
        snapshot_id: snapshot_id.to_string(),
        completed_at: now()?,
        status: if covered { "completed" } else { "partial" }.to_string(),
        rollback_status: if covered {
            "covered_scopes_restored".to_string()
        } else {
            rollback.status.clone()
        },
        limitations,
    };
    write_create_new_json(result_path, &result)?;
    report.status = result.status;
    report.controller_record = Some(display_path(result_path));
    report.rollback_status = Some(result.rollback_status);
    report.rollback_limitations = result.limitations;
    Ok(())
}

fn plan_changes_caddy(plan: &DeployPlan) -> bool {
    !plan.changes.caddy.routes.is_empty()
        || plan
            .changes
            .files
            .typed
            .iter()
            .any(|write| write.kind == "caddy_route_snippet")
}

fn plan_has_uncovered_application_changes(plan: &DeployPlan) -> bool {
    !plan.changes.build.steps.is_empty()
        || plan.changes.docker.compose_project.is_some()
        || !plan.changes.static_site.sync.is_empty()
        || !plan.changes.systemd.units.is_empty()
        || plan.changes.migrations.required
        || plan.changes.laravel.optimize
        || plan.changes.laravel.config_cache
        || plan.changes.laravel.route_cache
        || plan.changes.laravel.view_cache
        || !plan.changes.docker.volumes.is_empty()
        || plan
            .changes
            .files
            .typed
            .iter()
            .any(|write| write.kind == "systemd_service")
}

fn controller_token(plan_sha256: &str, journal_id: &str, snapshot_id: &str) -> String {
    let value = format!("{plan_sha256}\0{journal_id}\0{snapshot_id}");
    format!("health-rollback:{:x}", Sha256::digest(value.as_bytes()))
}

fn ensure_controller_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            anyhow::bail!("health controller directory is unsafe")
        }
        Ok(metadata) =>
        {
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o022 != 0 {
                anyhow::bail!("health controller directory must not be group/other writable");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            #[cfg(unix)]
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn write_create_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 1024 * 1024 {
        anyhow::bail!("health controller record is unsafe");
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn now() -> Result<String> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use anyhow::Result;
    use tempfile::TempDir;

    use crate::{
        approvals::{ApprovalFile, ApprovalRecord, EffectiveApprovalStatus},
        deploy::{
            DeployExecutionReport, DeployHealthCheckResult, DeployOperationResult,
            deploy_plan_sha256,
        },
        plan::{DraftPlanOptions, PlanBuildStep, PlanCaddyRoute, draft_deploy_plan},
        registry::Registry,
        snapshot::{SnapshotOptions, create_snapshot_with_caddyfile},
    };

    use super::{
        HealthControllerOptions, evaluate_health_controller, expected_health_rollback_scope,
    };

    #[test]
    fn exact_failed_health_journal_executes_one_idempotent_covered_rollback() -> Result<()> {
        let project = TempDir::new()?;
        let state = TempDir::new()?;
        let registry_dir = TempDir::new()?;
        copy_registry(Path::new("examples/server-registry"), registry_dir.path())?;
        let registry = Registry::load(registry_dir.path())?;
        let mut plan = draft_deploy_plan(&DraftPlanOptions {
            actor: "tester",
            project: project.path(),
            domain: None,
            ports: &[],
            environment: "production",
            id: Some("deploy_health_controller_test"),
        })?;
        plan.changes.health.enabled = true;
        plan.changes.health.controller = true;
        plan.changes.health.max_rollback_attempts = 1;
        plan.changes.caddy.routes.push(PlanCaddyRoute {
            host: "health-controller.example.com".to_string(),
            upstream: "127.0.0.1:3000".to_string(),
            handler: "reverse_proxy".to_string(),
            tls: "automatic".to_string(),
        });
        let caddyfile = project.path().join("Caddyfile");
        fs::write(&caddyfile, "before-health-deploy\n")?;
        let snapshot = create_snapshot_with_caddyfile(
            &SnapshotOptions {
                state_dir: state.path(),
                registry: &registry,
                plan: &plan,
                dry_run: false,
            },
            &caddyfile,
        )?;
        fs::write(&caddyfile, "failed-health-deploy\n")?;
        let journal_id = "deploy-health-controller-test-20260712150000";
        let journal_dir = state.path().join("deploy-journals");
        fs::create_dir(&journal_dir)?;
        let journal = DeployExecutionReport {
            schema_version: "opsctl.deploy_journal.v1".to_string(),
            journal_id: journal_id.to_string(),
            journal_path: journal_dir
                .join(format!("{journal_id}.json"))
                .display()
                .to_string(),
            plan_id: plan.id.clone(),
            plan_sha256: Some(deploy_plan_sha256(&plan)?),
            snapshot_id: Some(snapshot.id.clone()),
            status: "failed".to_string(),
            started_at: "2026-07-12T15:00:00Z".to_string(),
            completed_at: Some("2026-07-12T15:00:01Z".to_string()),
            operations_total: 1,
            operations_executed: 1,
            operations_succeeded: 0,
            operations_failed: 1,
            operations_skipped: 0,
            registry_updated: false,
            results: vec![DeployOperationResult {
                order: 1,
                kind: "PostDeployHealthCheck".to_string(),
                target: plan.id.clone(),
                status: "failed".to_string(),
                status_code: None,
                stdout_preview: None,
                stderr_preview: None,
                message: Some("bounded health failure".to_string()),
                health_checks: vec![DeployHealthCheckResult {
                    kind: "port_listening".to_string(),
                    target: "127.0.0.1:3000".to_string(),
                    status: "failed".to_string(),
                    detail: "connection refused".to_string(),
                }],
                rollback_suggestion: Some("run controller".to_string()),
            }],
            limitations: Vec::new(),
            rollback_suggestions: vec!["run controller".to_string()],
        };
        fs::write(
            journal_dir.join(format!("{journal_id}.json")),
            serde_json::to_vec_pretty(&journal)?,
        )?;

        let dry_run = evaluate_health_controller(&HealthControllerOptions {
            state_dir: state.path(),
            registry_dir: registry_dir.path(),
            plan: &plan,
            journal_id,
            execute: false,
            approval_token: None,
            approvals: &[],
            caddyfile_path: Some(&caddyfile),
        })?;
        assert!(
            dry_run.eligible,
            "unexpected blockers: {:?}",
            dry_run.blockers
        );
        assert_eq!(dry_run.automatic_scopes, ["caddy_config"]);
        assert!(!state.path().join("health-controllers").exists());
        let token = dry_run.approval_token.as_deref().unwrap_or_default();
        let missing_approval = evaluate_health_controller(&HealthControllerOptions {
            state_dir: state.path(),
            registry_dir: registry_dir.path(),
            plan: &plan,
            journal_id,
            execute: true,
            approval_token: Some(token),
            approvals: &[],
            caddyfile_path: Some(&caddyfile),
        });
        assert!(missing_approval.is_err());
        assert!(!state.path().join("health-controllers").exists());

        let mut changed_plan = plan.clone();
        changed_plan.changes.build.steps.push(PlanBuildStep {
            adapter: "pnpm".to_string(),
            script: Some("build".to_string()),
        });
        let changed = evaluate_health_controller(&HealthControllerOptions {
            state_dir: state.path(),
            registry_dir: registry_dir.path(),
            plan: &changed_plan,
            journal_id,
            execute: false,
            approval_token: None,
            approvals: &[],
            caddyfile_path: Some(&caddyfile),
        })?;
        assert!(!changed.eligible);
        assert_eq!(changed.status, "manual_required");
        assert!(
            changed
                .blockers
                .iter()
                .any(|blocker| blocker.contains("digest"))
        );
        assert!(
            changed
                .blockers
                .iter()
                .any(|blocker| blocker.contains("application code"))
        );

        let approval = approved_health_rollback(&plan.id, journal_id);
        let executed = evaluate_health_controller(&HealthControllerOptions {
            state_dir: state.path(),
            registry_dir: registry_dir.path(),
            plan: &plan,
            journal_id,
            execute: true,
            approval_token: Some(token),
            approvals: std::slice::from_ref(&approval),
            caddyfile_path: Some(&caddyfile),
        })?;
        assert_eq!(executed.status, "completed");
        assert_eq!(fs::read_to_string(&caddyfile)?, "before-health-deploy\n");
        let repeated = evaluate_health_controller(&HealthControllerOptions {
            state_dir: state.path(),
            registry_dir: registry_dir.path(),
            plan: &plan,
            journal_id,
            execute: true,
            approval_token: Some(token),
            approvals: &[approval],
            caddyfile_path: Some(&caddyfile),
        })?;
        assert_eq!(repeated.status, "already_completed");
        Ok(())
    }

    fn approved_health_rollback(plan_id: &str, journal_id: &str) -> ApprovalFile {
        ApprovalFile {
            path: "test-approval.yml".to_string(),
            effective_status: EffectiveApprovalStatus::Approved,
            record: ApprovalRecord {
                id: "appr_health_controller_test".to_string(),
                plan_id: plan_id.to_string(),
                status: "approved".to_string(),
                requested_by: "tester".to_string(),
                approved_by: Some("reviewer".to_string()),
                requested_at: Some("2026-07-12T14:00:00Z".to_string()),
                expires_at: Some("2099-07-12T16:00:00Z".to_string()),
                reason: "test covered rollback".to_string(),
                scope: vec![expected_health_rollback_scope(journal_id)],
                constraints: Vec::new(),
                notes: None,
                decided_by: Some("reviewer".to_string()),
                decided_at: Some("2026-07-12T14:01:00Z".to_string()),
                decision_reason: Some("approved for test".to_string()),
            },
        }
    }

    fn copy_registry(source: &Path, destination: &Path) -> Result<()> {
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                fs::copy(entry.path(), destination.join(entry.file_name()))?;
            }
        }
        let approvals = destination.join("approvals");
        fs::create_dir(&approvals)?;
        for entry in fs::read_dir(source.join("approvals"))? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                fs::copy(entry.path(), approvals.join(entry.file_name()))?;
            }
        }
        Ok(())
    }
}
